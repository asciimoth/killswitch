//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	bootstrapARP    = 1
	bootstrapDHCPv4 = 2
	bootstrapDHCPv6 = 3
	bootstrapICMPv6 = 4
)

// runtimeConfig mirrors struct runtime_config in killswitch.c. Keep this type
// byte-sized so map updates are ABI-stable across Go and C.
type runtimeConfig struct {
	AllowAll uint8
	EnableV4 uint8
	EnableV6 uint8
	Reserved uint8
}

// bootstrapEvent mirrors struct bootstrap_event in killswitch.c. The eBPF
// program emits only bootstrap pass events so this channel remains low volume.
type bootstrapEvent struct {
	TimestampNS uint64
	Ifindex     uint32
	EthProto    uint16
	Reason      uint8
	IPProto     uint8
	IPv4Saddr   uint32
	IPv4Daddr   uint32
	IPv6Saddr   [16]byte
	IPv6Daddr   [16]byte
	SourcePort  uint16
	DestPort    uint16
	ICMPv6Type  uint8
	VLANDepth   uint8
	Reserved    uint16
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	if value == "" {
		return errors.New("empty value")
	}
	*s = append(*s, value)
	return nil
}

type options struct {
	InterfaceNames   []string
	InterfaceRegexps []string
	AllowAll         bool
	EnableV4         bool
	EnableV6         bool
}

func main() {
	opts, err := parseFlags(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if err := run(context.Background(), opts); err != nil {
		log.Fatal(err)
	}
}

func parseFlags(args []string) (options, error) {
	var ifaces stringList
	var ifaceRegexps stringList
	opts := options{}

	fs := flag.NewFlagSet("killswitch", flag.ContinueOnError)
	fs.Var(&ifaces, "iface", "interface name to protect; may be repeated")
	fs.Var(&ifaceRegexps, "iface-regex", "regular expression selecting interface names to protect; may be repeated")
	fs.BoolVar(&opts.AllowAll, "allow-all", false, "pass all traffic before parsing; disables enforcement")
	fs.BoolVar(&opts.EnableV4, "enable-v4", false, "enable IPv4 gate; traffic still drops until later allowlist phases")
	fs.BoolVar(&opts.EnableV6, "enable-v6", false, "enable IPv6 gate; traffic still drops until later allowlist phases")
	fs.SetOutput(os.Stderr)

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	opts.InterfaceNames = ifaces
	opts.InterfaceRegexps = ifaceRegexps
	if len(opts.InterfaceNames) == 0 && len(opts.InterfaceRegexps) == 0 {
		return options{}, errors.New("at least one -iface or -iface-regex is required")
	}

	for _, pattern := range opts.InterfaceRegexps {
		if _, err := regexp.Compile(pattern); err != nil {
			return options{}, fmt.Errorf("compile -iface-regex %q: %w", pattern, err)
		}
	}

	return opts, nil
}

func run(parent context.Context, opts options) error {
	if opts.AllowAll {
		log.Print("WARNING: AllowAll is enabled; protected interfaces will pass all traffic")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs killswitchObjects
	if err := loadKillswitchObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close() //nolint:errcheck

	if err := writeRuntimeConfig(objs.RuntimeConfig, runtimeConfig{
		AllowAll: boolByte(opts.AllowAll),
		EnableV4: boolByte(opts.EnableV4),
		EnableV6: boolByte(opts.EnableV6),
	}); err != nil {
		return err
	}

	ifaces, err := selectedInterfaces(opts)
	if err != nil {
		return err
	}
	if len(ifaces) == 0 {
		return errors.New("no interfaces matched the configured selectors")
	}

	links, err := attachEgress(objs.KillswitchEgress, ifaces)
	if err != nil {
		return err
	}
	defer closeLinks(links)

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	reader, err := ringbuf.NewReader(objs.BootstrapEvents)
	if err != nil {
		return fmt.Errorf("open bootstrap event ring buffer: %w", err)
	}
	defer reader.Close() //nolint:errcheck

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	log.Printf("Kill switch attached to: %s", interfaceNames(ifaces))
	log.Printf("Runtime config: allow_all=%t enable_v4=%t enable_v6=%t", opts.AllowAll, opts.EnableV4, opts.EnableV6)

	if err := readBootstrapEvents(reader); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
		return err
	}
	return nil
}

func selectedInterfaces(opts options) ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	return selectInterfaces(all, opts)
}

func selectInterfaces(all []net.Interface, opts options) ([]net.Interface, error) {
	names := make(map[string]struct{}, len(opts.InterfaceNames))
	for _, name := range opts.InterfaceNames {
		names[name] = struct{}{}
	}

	regexps := make([]*regexp.Regexp, 0, len(opts.InterfaceRegexps))
	for _, pattern := range opts.InterfaceRegexps {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile interface regexp %q: %w", pattern, err)
		}
		regexps = append(regexps, re)
	}

	var selected []net.Interface
	for _, iface := range all {
		if _, ok := names[iface.Name]; ok {
			selected = append(selected, iface)
			continue
		}
		for _, re := range regexps {
			if re.MatchString(iface.Name) {
				selected = append(selected, iface)
				break
			}
		}
	}

	sort.Slice(selected, func(i, j int) bool {
		return selected[i].Name < selected[j].Name
	})
	return selected, nil
}

func writeRuntimeConfig(m *ebpf.Map, config runtimeConfig) error {
	var key uint32
	if err := m.Update(key, config, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update runtime_config map: %w", err)
	}
	return nil
}

func attachEgress(program *ebpf.Program, ifaces []net.Interface) ([]link.Link, error) {
	links := make([]link.Link, 0, len(ifaces))
	for _, iface := range ifaces {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   program,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			closeLinks(links)
			return nil, fmt.Errorf("attach tc egress program to %s(index %d): %w", iface.Name, iface.Index, err)
		}
		log.Printf("Attached tc egress program to %s(index %d)", iface.Name, iface.Index)
		links = append(links, l)
	}
	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if err := l.Close(); err != nil {
			log.Printf("closing link: %s", err)
		}
	}
}

func readBootstrapEvents(reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			return err
		}

		event, err := parseBootstrapEvent(record.RawSample)
		if err != nil {
			log.Printf("parse bootstrap event: %s", err)
			continue
		}
		log.Print(formatBootstrapEvent(event))
	}
}

func parseBootstrapEvent(raw []byte) (bootstrapEvent, error) {
	var event bootstrapEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
		return bootstrapEvent{}, err
	}
	return event, nil
}

func formatBootstrapEvent(event bootstrapEvent) string {
	reason := "unknown"
	switch event.Reason {
	case bootstrapARP:
		reason = "arp"
	case bootstrapDHCPv4:
		reason = "dhcpv4"
	case bootstrapDHCPv6:
		reason = "dhcpv6"
	case bootstrapICMPv6:
		reason = "icmpv6_nd"
	}

	if event.Reason == bootstrapDHCPv4 {
		return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d src=%s:%d dst=%s:%d",
			reason,
			event.Ifindex,
			ipv4FromNetworkOrder(event.IPv4Saddr),
			ntohs(event.SourcePort),
			ipv4FromNetworkOrder(event.IPv4Daddr),
			ntohs(event.DestPort),
		)
	}
	if event.Reason == bootstrapDHCPv6 {
		return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d src=[%s]:%d dst=[%s]:%d vlan_depth=%d",
			reason,
			event.Ifindex,
			net.IP(event.IPv6Saddr[:]),
			ntohs(event.SourcePort),
			net.IP(event.IPv6Daddr[:]),
			ntohs(event.DestPort),
			event.VLANDepth,
		)
	}
	if event.Reason == bootstrapICMPv6 {
		return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d src=%s dst=%s type=%d vlan_depth=%d",
			reason,
			event.Ifindex,
			net.IP(event.IPv6Saddr[:]),
			net.IP(event.IPv6Daddr[:]),
			event.ICMPv6Type,
			event.VLANDepth,
		)
	}

	return fmt.Sprintf("bootstrap pass: reason=%s ifindex=%d eth_proto=0x%04x vlan_depth=%d",
		reason,
		event.Ifindex,
		event.EthProto,
		event.VLANDepth,
	)
}

func interfaceNames(ifaces []net.Interface) string {
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	return strings.Join(names, ", ")
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func ntohs(value uint16) uint16 {
	return value<<8 | value>>8
}

func ipv4FromNetworkOrder(value uint32) net.IP {
	return net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

//go:build linux

package main

import (
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestConfigRequiresInterfaceSelector(t *testing.T) {
	_, err := configToOptions(configFile{})
	if err == nil {
		t.Fatal("expected missing selector error")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgs(t *testing.T) {
	path, err := parseArgs(nil)
	if err != nil {
		t.Fatalf("parse default args: %v", err)
	}
	if path != defaultConfigPath {
		t.Fatalf("default config path = %q", path)
	}

	path, err = parseArgs([]string{"-"})
	if err != nil {
		t.Fatalf("parse stdin args: %v", err)
	}
	if path != "-" {
		t.Fatalf("stdin config path = %q", path)
	}

	path, err = parseArgs([]string{"./killswitch.json"})
	if err != nil {
		t.Fatalf("parse config path arg: %v", err)
	}
	if path != "./killswitch.json" {
		t.Fatalf("config path = %q", path)
	}

	if _, err := parseArgs([]string{"one.json", "two.json"}); err == nil {
		t.Fatal("expected too many args error")
	}
}

func TestLoadOptionsFromStdin(t *testing.T) {
	opts, err := loadOptions("-", strings.NewReader(`{
		"interface_types": ["device"],
		"interface_names": ["eth0", "wlan0"],
		"interface_regexps": ["^en"],
		"allow_all": true,
		"enable_v4": true,
		"allowed_marks": ["0x42"],
		"allowed_ports": ["udp/51820"],
		"allowed_v4_hosts": ["192.0.2.10"],
		"allowed_v6_hosts": ["2001:db8::10"],
		"allowed_v4_hostports": ["tcp/198.51.100.20:443"],
		"allowed_v6_hostports": ["udp/[2001:db8::20]:51820"]
	}`))
	if err != nil {
		t.Fatalf("load options: %v", err)
	}

	assertParsedOptions(t, opts)
}

func TestConfigToOptions(t *testing.T) {
	opts, err := configToOptions(configFile{
		InterfaceTypes:   []string{"device"},
		InterfaceNames:   []string{"eth0", "wlan0"},
		InterfaceRegexps: []string{"^en"},
		AllowAll:         true,
		EnableV4:         true,
		AllowedMarks:     []string{"0x42"},
		AllowedPorts:     []string{"udp/51820"},
		AllowedV4Hosts:   []string{"192.0.2.10"},
		AllowedV6Hosts:   []string{"2001:db8::10"},
		AllowedV4Pairs:   []string{"tcp/198.51.100.20:443"},
		AllowedV6Pairs:   []string{"udp/[2001:db8::20]:51820"},
	})
	if err != nil {
		t.Fatalf("config to options: %v", err)
	}

	assertParsedOptions(t, opts)
}

func assertParsedOptions(t *testing.T, opts options) {
	t.Helper()

	if got := strings.Join(opts.InterfaceNames, ","); got != "eth0,wlan0" {
		t.Fatalf("interface names = %q", got)
	}
	if got := strings.Join(opts.InterfaceTypes, ","); got != "device" {
		t.Fatalf("interface types = %q", got)
	}
	if got := strings.Join(opts.InterfaceRegexps, ","); got != "^en" {
		t.Fatalf("interface regexps = %q", got)
	}
	if !opts.AllowAll || !opts.EnableV4 || opts.EnableV6 {
		t.Fatalf("unexpected bool flags: %+v", opts)
	}
	if len(opts.AllowedMarks) != 1 || opts.AllowedMarks[0] != 0x42 {
		t.Fatalf("unexpected allowed marks: %+v", opts.AllowedMarks)
	}
	if len(opts.AllowedPorts) != 1 || opts.AllowedPorts[0] != (portKey{Dport: htons(51820), Protocol: ipProtoUDP}) {
		t.Fatalf("unexpected allowed ports: %+v", opts.AllowedPorts)
	}
	if len(opts.AllowedV4Hosts) != 1 || opts.AllowedV4Hosts[0] != 0x0a0200c0 {
		t.Fatalf("unexpected allowed v4 hosts: %+v", opts.AllowedV4Hosts)
	}
	if len(opts.AllowedV6Hosts) != 1 || opts.AllowedV6Hosts[0].Addr != ipv6Bytes(t, "2001:db8::10") {
		t.Fatalf("unexpected allowed v6 hosts: %+v", opts.AllowedV6Hosts)
	}
	if len(opts.AllowedV4Pairs) != 1 || opts.AllowedV4Pairs[0].Daddr != 0x146433c6 || opts.AllowedV4Pairs[0].Dport != htons(443) || opts.AllowedV4Pairs[0].Protocol != ipProtoTCP {
		t.Fatalf("unexpected allowed v4 hostports: %+v", opts.AllowedV4Pairs)
	}
	if len(opts.AllowedV6Pairs) != 1 || opts.AllowedV6Pairs[0].Daddr != ipv6Bytes(t, "2001:db8::20") || opts.AllowedV6Pairs[0].Dport != htons(51820) || opts.AllowedV6Pairs[0].Protocol != ipProtoUDP {
		t.Fatalf("unexpected allowed v6 hostports: %+v", opts.AllowedV6Pairs)
	}
}

func TestParseAllowlistValidation(t *testing.T) {
	tests := []configFile{
		{InterfaceNames: []string{"eth0"}, AllowedPorts: []string{"icmp/443"}},
		{InterfaceNames: []string{"eth0"}, AllowedPorts: []string{"tcp/0"}},
		{InterfaceNames: []string{"eth0"}, AllowedV4Hosts: []string{"2001:db8::1"}},
		{InterfaceNames: []string{"eth0"}, AllowedV6Hosts: []string{"192.0.2.1"}},
		{InterfaceNames: []string{"eth0"}, AllowedV4Pairs: []string{"udp/[2001:db8::1]:53"}},
		{InterfaceNames: []string{"eth0"}, AllowedV6Pairs: []string{"udp/192.0.2.1:53"}},
	}

	for _, cfg := range tests {
		if _, err := configToOptions(cfg); err == nil {
			t.Fatalf("configToOptions(%+v) succeeded, expected error", cfg)
		}
	}
}

func TestSelectInterfacesByNameAndRegexp(t *testing.T) {
	all := []interfaceInfo{
		{Name: "lo", Index: 1, Type: "device"},
		{Name: "wlan0", Index: 3, Type: "device"},
		{Name: "eth0", Index: 2, Type: "device"},
	}
	opts := options{
		InterfaceNames:   []string{"wlan0"},
		InterfaceRegexps: []string{"^eth"},
	}

	selected, err := selectInterfaces(all, opts)
	if err != nil {
		t.Fatalf("select interfaces: %v", err)
	}

	if got := interfaceNames(selected); got != "eth0, wlan0" {
		t.Fatalf("selected interfaces = %q", got)
	}
}

func TestSelectInterfacesByLiteralType(t *testing.T) {
	all := []interfaceInfo{
		{Name: "lo", Index: 1, Type: "device"},
		{Name: "wg0", Index: 2, Type: "wireguard"},
		{Name: "br0", Index: 3, Type: "bridge"},
	}
	opts := options{
		InterfaceTypes: []string{"bridge"},
	}

	selected, err := selectInterfaces(all, opts)
	if err != nil {
		t.Fatalf("select interfaces: %v", err)
	}

	if got := interfaceNames(selected); got != "br0" {
		t.Fatalf("selected interfaces = %q", got)
	}
}

func TestShouldReconcileLinkUpdateIgnoresUnchangedSelectedInterface(t *testing.T) {
	manager := newEgressManager(nil)
	manager.attached[4] = attachedInterface{info: interfaceInfo{Name: "wlp0s20f3", Index: 4, Type: "device"}}

	if manager.shouldReconcileLinkUpdate(linkUpdate(unix.RTM_NEWLINK, 4, "wlp0s20f3", "device"), options{
		InterfaceRegexps: []string{"^wl"},
	}) {
		t.Fatal("expected unchanged selected interface update to be ignored")
	}
}

func TestShouldReconcileLinkUpdateAllowsAttachAndDetachEvents(t *testing.T) {
	manager := newEgressManager(nil)

	if !manager.shouldReconcileLinkUpdate(linkUpdate(unix.RTM_NEWLINK, 4, "wlp0s20f3", "device"), options{
		InterfaceRegexps: []string{"^wl"},
	}) {
		t.Fatal("expected new matching interface to trigger reconcile")
	}

	manager.attached[4] = attachedInterface{info: interfaceInfo{Name: "wlp0s20f3", Index: 4, Type: "device"}}
	if !manager.shouldReconcileLinkUpdate(linkUpdate(unix.RTM_DELLINK, 4, "wlp0s20f3", "device"), options{
		InterfaceRegexps: []string{"^wl"},
	}) {
		t.Fatal("expected deleted attached interface to trigger reconcile")
	}
}

func TestShouldReconcileLinkUpdateIgnoresUnselectedInterface(t *testing.T) {
	manager := newEgressManager(nil)

	if manager.shouldReconcileLinkUpdate(linkUpdate(unix.RTM_NEWLINK, 5, "veth0", "veth"), options{
		InterfaceRegexps: []string{"^wl"},
	}) {
		t.Fatal("expected unselected interface update to be ignored")
	}
}

func TestFormatBootstrapEvents(t *testing.T) {
	arp := formatBootstrapEvent(bootstrapEvent{
		Ifindex:   4,
		EthProto:  0x0806,
		Reason:    bootstrapARP,
		VLANDepth: 1,
	})
	if !strings.Contains(arp, "reason=arp") || !strings.Contains(arp, "eth_proto=0x0806") || !strings.Contains(arp, "vlan_depth=1") {
		t.Fatalf("unexpected ARP event: %s", arp)
	}

	dhcp := formatBootstrapEvent(bootstrapEvent{
		Ifindex:    5,
		Reason:     bootstrapDHCPv4,
		IPv4Saddr:  0x0101a8c0,
		IPv4Daddr:  0xffffffff,
		SourcePort: 0x4400,
		DestPort:   0x4300,
	})
	if !strings.Contains(dhcp, "src=192.168.1.1:68") || !strings.Contains(dhcp, "dst=255.255.255.255:67") {
		t.Fatalf("unexpected DHCP event: %s", dhcp)
	}

	dhcp6 := formatBootstrapEvent(bootstrapEvent{
		Ifindex:    6,
		Reason:     bootstrapDHCPv6,
		IPv6Saddr:  ipv6Bytes(t, "fe80::1"),
		IPv6Daddr:  ipv6Bytes(t, "ff02::1:2"),
		SourcePort: 0x2202,
		DestPort:   0x2302,
		VLANDepth:  1,
	})
	if !strings.Contains(dhcp6, "reason=dhcpv6") || !strings.Contains(dhcp6, "src=[fe80::1]:546") || !strings.Contains(dhcp6, "dst=[ff02::1:2]:547") || !strings.Contains(dhcp6, "vlan_depth=1") {
		t.Fatalf("unexpected DHCPv6 event: %s", dhcp6)
	}

	nd := formatBootstrapEvent(bootstrapEvent{
		Ifindex:    7,
		Reason:     bootstrapICMPv6,
		IPv6Saddr:  ipv6Bytes(t, "fe80::2"),
		IPv6Daddr:  ipv6Bytes(t, "ff02::1"),
		ICMPv6Type: 135,
	})
	if !strings.Contains(nd, "reason=icmpv6_nd") || !strings.Contains(nd, "src=fe80::2") || !strings.Contains(nd, "dst=ff02::1") || !strings.Contains(nd, "type=135") {
		t.Fatalf("unexpected ICMPv6 ND event: %s", nd)
	}
}

func TestRuntimeConfigBoolEncoding(t *testing.T) {
	config := runtimeConfig{
		AllowAll: boolByte(true),
		EnableV4: boolByte(false),
		EnableV6: boolByte(true),
	}

	if config.AllowAll != 1 || config.EnableV4 != 0 || config.EnableV6 != 1 {
		t.Fatalf("unexpected runtime config encoding: %+v", config)
	}
}

func ipv6Bytes(t *testing.T, value string) [16]byte {
	t.Helper()

	parsed := net.ParseIP(value).To16()
	if parsed == nil {
		t.Fatalf("parse IPv6 address %q", value)
	}

	var out [16]byte
	copy(out[:], parsed)
	return out
}

func linkUpdate(msgType uint16, index int, name string, typ string) netlink.LinkUpdate {
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Index: index,
			Name:  name,
		},
		LinkType: typ,
	}
	return netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: msgType},
		Link:   link,
	}
}

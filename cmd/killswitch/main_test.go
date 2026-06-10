//go:build linux

package main

import (
	"net"
	"strings"
	"testing"
)

func TestParseFlagsRequiresInterfaceSelector(t *testing.T) {
	_, err := parseFlags(nil)
	if err == nil {
		t.Fatal("expected missing selector error")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFlags(t *testing.T) {
	opts, err := parseFlags([]string{
		"-iface", "eth0",
		"-iface", "wlan0",
		"-iface-regex", "^en",
		"-allow-all",
		"-enable-v4",
		"-allow-mark", "0x42",
		"-allow-port", "udp/51820",
		"-allow-v4-host", "192.0.2.10",
		"-allow-v6-host", "2001:db8::10",
		"-allow-v4-hostport", "tcp/198.51.100.20:443",
		"-allow-v6-hostport", "udp/[2001:db8::20]:51820",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if got := strings.Join(opts.InterfaceNames, ","); got != "eth0,wlan0" {
		t.Fatalf("interface names = %q", got)
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
	tests := [][]string{
		{"-iface", "eth0", "-allow-port", "icmp/443"},
		{"-iface", "eth0", "-allow-port", "tcp/0"},
		{"-iface", "eth0", "-allow-v4-host", "2001:db8::1"},
		{"-iface", "eth0", "-allow-v6-host", "192.0.2.1"},
		{"-iface", "eth0", "-allow-v4-hostport", "udp/[2001:db8::1]:53"},
		{"-iface", "eth0", "-allow-v6-hostport", "udp/192.0.2.1:53"},
	}

	for _, args := range tests {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("parseFlags(%v) succeeded, expected error", args)
		}
	}
}

func TestSelectInterfacesByNameAndRegexp(t *testing.T) {
	all := []net.Interface{
		{Name: "lo", Index: 1},
		{Name: "wlan0", Index: 3},
		{Name: "eth0", Index: 2},
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

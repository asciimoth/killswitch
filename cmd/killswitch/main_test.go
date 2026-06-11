//go:build linux

package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/asciimoth/killswitch/internal/adminapi"
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
		"ignored_interface_types": ["bridge"],
		"ignored_interface_names": ["veth0"],
		"ignored_interface_regexps": ["^docker"],
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
		InterfaceTypes:          []string{"device"},
		InterfaceNames:          []string{"eth0", "wlan0"},
		InterfaceRegexps:        []string{"^en"},
		IgnoredInterfaceTypes:   []string{"bridge"},
		IgnoredInterfaceNames:   []string{"veth0"},
		IgnoredInterfaceRegexps: []string{"^docker"},
		AllowAll:                true,
		EnableV4:                true,
		AllowedMarks:            []string{"0x42"},
		AllowedPorts:            []string{"udp/51820"},
		AllowedV4Hosts:          []string{"192.0.2.10"},
		AllowedV6Hosts:          []string{"2001:db8::10"},
		AllowedV4Pairs:          []string{"tcp/198.51.100.20:443"},
		AllowedV6Pairs:          []string{"udp/[2001:db8::20]:51820"},
	})
	if err != nil {
		t.Fatalf("config to options: %v", err)
	}

	assertParsedOptions(t, opts)
}

func TestConfigToOptionsParsesRulesets(t *testing.T) {
	opts, err := configToOptions(configFile{
		InterfaceNames: []string{"eth0"},
		EnableV4:       true,
		AllowedPorts:   []string{"tcp/443"},
		Rulesets: map[string]rulesetConfig{
			"office": {
				Disabled:       true,
				Priority:       20,
				Match:          "and",
				Trigger:        triggerConfig{InterfaceNames: []string{"wg0"}, IPAddrs: []string{"10.64.0.2"}},
				EnableV6:       true,
				AllowedV4Hosts: []string{"192.0.2.10"},
			},
		},
	})
	if err != nil {
		t.Fatalf("config to options: %v", err)
	}

	if len(opts.Rulesets) != 1 {
		t.Fatalf("rulesets count = %d", len(opts.Rulesets))
	}
	ruleset := opts.Rulesets[0]
	if ruleset.Name != "office" || !ruleset.Disabled || ruleset.Priority != 20 || !ruleset.MatchAll {
		t.Fatalf("unexpected ruleset metadata: %+v", ruleset)
	}
	if len(ruleset.Trigger.InterfaceNames) != 1 || ruleset.Trigger.InterfaceNames[0] != "wg0" {
		t.Fatalf("unexpected interface trigger: %+v", ruleset.Trigger)
	}
	if len(ruleset.Trigger.IPAddrs) != 1 || ruleset.Trigger.IPAddrs[0] != netipMustParse("10.64.0.2") {
		t.Fatalf("unexpected ip trigger: %+v", ruleset.Trigger.IPAddrs)
	}
	if !ruleset.EnableV6 || len(ruleset.AllowedV4Hosts) != 1 {
		t.Fatalf("unexpected ruleset rules: %+v", ruleset.allowRules)
	}
}

func TestConfigToOptionsRejectsInvalidRulesets(t *testing.T) {
	tests := []configFile{
		{InterfaceNames: []string{"eth0"}, Rulesets: map[string]rulesetConfig{"": {Trigger: triggerConfig{InterfaceNames: []string{"wg0"}}}}},
		{InterfaceNames: []string{"eth0"}, Rulesets: map[string]rulesetConfig{"vpn": {Match: "xor", Trigger: triggerConfig{InterfaceNames: []string{"wg0"}}}}},
		{InterfaceNames: []string{"eth0"}, Rulesets: map[string]rulesetConfig{"vpn": {}}},
		{InterfaceNames: []string{"eth0"}, Rulesets: map[string]rulesetConfig{"vpn": {Trigger: triggerConfig{InterfaceRegexps: []string{"["}}}}},
		{InterfaceNames: []string{"eth0"}, Rulesets: map[string]rulesetConfig{"vpn": {Trigger: triggerConfig{IPAddrs: []string{"not-an-ip"}}}}},
	}

	for _, cfg := range tests {
		if _, err := configToOptions(cfg); err == nil {
			t.Fatalf("configToOptions(%+v) succeeded, expected error", cfg)
		}
	}
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
	if got := strings.Join(opts.IgnoredInterfaceNames, ","); got != "veth0" {
		t.Fatalf("ignored interface names = %q", got)
	}
	if got := strings.Join(opts.IgnoredInterfaceTypes, ","); got != "bridge" {
		t.Fatalf("ignored interface types = %q", got)
	}
	if got := strings.Join(opts.IgnoredInterfaceRegexps, ","); got != "^docker" {
		t.Fatalf("ignored interface regexps = %q", got)
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

func TestParseIgnoredInterfaceRegexpValidation(t *testing.T) {
	tests := []configFile{
		{InterfaceNames: []string{"eth0"}, IgnoredInterfaceRegexps: []string{"["}},
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

func TestSelectInterfacesAlwaysIgnoresLoopback(t *testing.T) {
	all := []interfaceInfo{
		{Name: "lo", Index: 1, Type: "device"},
		{Name: "eth0", Index: 2, Type: "device"},
	}
	opts := options{
		InterfaceTypes: []string{"device"},
	}

	selected, err := selectInterfaces(all, opts)
	if err != nil {
		t.Fatalf("select interfaces: %v", err)
	}

	if got := interfaceNames(selected); got != "eth0" {
		t.Fatalf("selected interfaces = %q", got)
	}
}

func TestSelectInterfacesIgnoreRulesOverrideIncludes(t *testing.T) {
	all := []interfaceInfo{
		{Name: "br0", Index: 1, Type: "bridge"},
		{Name: "eth0", Index: 2, Type: "device"},
		{Name: "docker0", Index: 3, Type: "device"},
		{Name: "wlan0", Index: 4, Type: "device"},
	}
	opts := options{
		InterfaceTypes:          []string{"bridge", "device"},
		InterfaceRegexps:        []string{"^docker"},
		IgnoredInterfaceTypes:   []string{"bridge"},
		IgnoredInterfaceNames:   []string{"eth0"},
		IgnoredInterfaceRegexps: []string{"^docker"},
	}

	selected, err := selectInterfaces(all, opts)
	if err != nil {
		t.Fatalf("select interfaces: %v", err)
	}

	if got := interfaceNames(selected); got != "wlan0" {
		t.Fatalf("selected interfaces = %q", got)
	}
}

func TestActiveRulesetSelectsHighestPriorityCandidate(t *testing.T) {
	all := []interfaceInfo{
		{Name: "eth0", Index: 2, Type: "device", Addrs: []netip.Addr{netipMustParse("192.0.2.44")}},
		{Name: "wg0", Index: 3, Type: "wireguard", Addrs: []netip.Addr{netipMustParse("10.64.0.2")}},
	}
	rulesets := []ruleset{
		{Name: "low", Priority: 10, Trigger: rulesetTrigger{InterfaceTypes: []string{"device"}}},
		{Name: "high", Priority: 50, Trigger: rulesetTrigger{InterfaceRegexps: []string{"^wg"}}},
		{Name: "inactive", Priority: 100, Trigger: rulesetTrigger{InterfaceNames: []string{"tun0"}}},
	}

	active := activeRuleset(all, rulesets)
	if active == nil || active.Name != "high" {
		t.Fatalf("active ruleset = %+v", active)
	}
}

func TestActiveRulesetIgnoresDisabledRulesets(t *testing.T) {
	all := []interfaceInfo{
		{Name: "wg0", Index: 3, Type: "wireguard", Addrs: []netip.Addr{netipMustParse("10.64.0.2")}},
	}
	rulesets := []ruleset{
		{Name: "disabled", Disabled: true, Priority: 100, Trigger: rulesetTrigger{InterfaceNames: []string{"wg0"}}},
		{Name: "enabled", Priority: 10, Trigger: rulesetTrigger{InterfaceNames: []string{"wg0"}}},
	}

	active := activeRuleset(all, rulesets)
	if active == nil || active.Name != "enabled" {
		t.Fatalf("active ruleset = %+v", active)
	}

	rulesets[1].Disabled = true
	if active := activeRuleset(all, rulesets); active != nil {
		t.Fatalf("active ruleset = %+v", active)
	}
}

func TestRulesetTriggerANDRequiresAllTriggers(t *testing.T) {
	all := []interfaceInfo{
		{Name: "wg0", Index: 3, Type: "wireguard", Addrs: []netip.Addr{netipMustParse("10.64.0.2")}},
	}
	trigger := rulesetTrigger{
		InterfaceNames: []string{"wg0"},
		IPAddrs:        []netip.Addr{netipMustParse("10.64.0.2")},
	}
	if !rulesetTriggerMatches(all, trigger, true) {
		t.Fatal("expected AND trigger to match when all predicates are present")
	}

	trigger.IPAddrs = []netip.Addr{netipMustParse("10.64.0.3")}
	if rulesetTriggerMatches(all, trigger, true) {
		t.Fatal("expected AND trigger to miss when one predicate is absent")
	}
	if !rulesetTriggerMatches(all, trigger, false) {
		t.Fatal("expected OR trigger to match when one predicate is present")
	}
}

func TestMergeAllowRulesAllowsEitherSide(t *testing.T) {
	base := allowRules{
		EnableV4:       true,
		AllowedMarks:   []uint32{0x42},
		AllowedPorts:   []portKey{{Dport: htons(443), Protocol: ipProtoTCP}},
		AllowedV4Hosts: []uint32{ipv4Key(netipMustParse("192.0.2.10"))},
	}
	overlay := allowRules{
		EnableV6:       true,
		AllowedMarks:   []uint32{0x42, 0x43},
		AllowedPorts:   []portKey{{Dport: htons(443), Protocol: ipProtoTCP}, {Dport: htons(51820), Protocol: ipProtoUDP}},
		AllowedV6Hosts: []ipv6AddrKey{ipv6Key(netipMustParse("2001:db8::10"))},
	}

	merged := mergeAllowRules(base, overlay)
	if !merged.EnableV4 || !merged.EnableV6 {
		t.Fatalf("unexpected merged gates: %+v", merged)
	}
	if len(merged.AllowedMarks) != 2 {
		t.Fatalf("unexpected merged marks: %+v", merged.AllowedMarks)
	}
	if len(merged.AllowedPorts) != 2 {
		t.Fatalf("unexpected merged ports: %+v", merged.AllowedPorts)
	}
	if len(merged.AllowedV4Hosts) != 1 || len(merged.AllowedV6Hosts) != 1 {
		t.Fatalf("unexpected merged hosts: %+v", merged)
	}
}

func TestPolicyManagerSkipsUnchangedEffectiveRules(t *testing.T) {
	manager := &policyManager{
		opts: options{
			allowRules: allowRules{EnableV4: true},
			Rulesets: []ruleset{
				{
					Name:       "same",
					Priority:   10,
					Trigger:    rulesetTrigger{InterfaceNames: []string{"wg0"}},
					allowRules: allowRules{EnableV4: true},
				},
			},
		},
		current: allowRules{EnableV4: true},
		set:     true,
	}

	changed, err := manager.reconcile([]interfaceInfo{{Name: "wg0", Type: "wireguard"}}, true)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if changed {
		t.Fatal("expected unchanged effective policy to be skipped")
	}
}

func TestPolicyManagerRecomputesActiveRulesetAndSkipsUnchangedEffectiveRules(t *testing.T) {
	manager := &policyManager{
		opts: options{
			allowRules: allowRules{EnableV4: true},
			Rulesets: []ruleset{
				{
					Name:       "home",
					Priority:   10,
					Trigger:    rulesetTrigger{InterfaceNames: []string{"eth0"}},
					allowRules: allowRules{AllowedPorts: []portKey{{Dport: htons(443), Protocol: ipProtoTCP}}},
				},
				{
					Name:       "office",
					Priority:   20,
					Trigger:    rulesetTrigger{InterfaceNames: []string{"wg0"}},
					allowRules: allowRules{AllowedPorts: []portKey{{Dport: htons(443), Protocol: ipProtoTCP}}},
				},
			},
		},
		current:    canonicalAllowRules(allowRules{EnableV4: true, AllowedPorts: []portKey{{Dport: htons(443), Protocol: ipProtoTCP}}}),
		activeName: "home",
		set:        true,
	}

	changed, err := manager.reconcile([]interfaceInfo{{Name: "wg0", Type: "wireguard"}}, true)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if changed {
		t.Fatal("expected unchanged effective policy to be skipped")
	}
	if manager.activeName != "office" {
		t.Fatalf("active ruleset = %q", manager.activeName)
	}
}

func TestApplyAdminMutationRecomputesAndSkipsUnchangedEffectiveRules(t *testing.T) {
	policies := &policyManager{
		opts:    options{InterfaceNames: []string{"killswitch-test-no-such-interface"}, allowRules: allowRules{EnableV4: true}},
		current: allowRules{EnableV4: true},
		set:     true,
	}
	var reconcileMu sync.Mutex

	result := applyAdminMutation(adminapi.MutationRequest{
		Operation: adminapi.MutationSet,
		Target:    "base_policy.enable_v4",
		Value:     json.RawMessage(`true`),
	}, policies, newEgressManager(nil), &reconcileMu)

	if !result.OK {
		t.Fatalf("mutation failed: %s", result.Error)
	}
	if result.Changed {
		t.Fatal("expected unchanged effective policy to be skipped")
	}
	if !result.Config.EffectivePolicy.EnableV4 {
		t.Fatalf("effective policy = %+v", result.Config.EffectivePolicy)
	}
}

func TestPolicyManagerTemporaryRulesetMutationsSkipUnchangedEffectiveRules(t *testing.T) {
	manager := &policyManager{
		opts:    options{allowRules: allowRules{EnableV4: true}},
		current: allowRules{EnableV4: true},
		set:     true,
	}

	manager.setTemporaryRuleset("client", allowRules{EnableV4: true})
	changed, err := manager.reconcile(nil, true)
	if err != nil {
		t.Fatalf("reconcile after tmp set: %v", err)
	}
	if changed {
		t.Fatal("expected tmp set with unchanged effective policy to be skipped")
	}

	manager.setTemporaryRuleset("client", allowRules{EnableV4: true})
	changed, err = manager.reconcile(nil, true)
	if err != nil {
		t.Fatalf("reconcile after tmp update: %v", err)
	}
	if changed {
		t.Fatal("expected tmp update with unchanged effective policy to be skipped")
	}

	if !manager.removeTemporaryRuleset("client") {
		t.Fatal("expected tmp ruleset to be removed")
	}
	changed, err = manager.reconcile(nil, true)
	if err != nil {
		t.Fatalf("reconcile after tmp remove: %v", err)
	}
	if changed {
		t.Fatal("expected tmp remove with unchanged effective policy to be skipped")
	}
}

func TestEffectiveAllowRulesMergesTemporaryRulesets(t *testing.T) {
	active := &ruleset{
		Name:       "office",
		allowRules: allowRules{AllowedMarks: []uint32{0x42}},
	}
	effective := effectiveAllowRules(
		allowRules{EnableV4: true, AllowedPorts: []portKey{{Dport: htons(443), Protocol: ipProtoTCP}}},
		active,
		nil,
		[]temporaryRuleset{
			{Owner: "client-b", Rules: allowRules{EnableV6: true, AllowedV6Hosts: []ipv6AddrKey{ipv6Key(netipMustParse("2001:db8::10"))}}},
			{Owner: "client-a", Rules: allowRules{AllowedV4Hosts: []uint32{ipv4Key(netipMustParse("192.0.2.10"))}}},
		},
	)

	if !effective.EnableV4 || !effective.EnableV6 {
		t.Fatalf("unexpected effective gates: %+v", effective)
	}
	if len(effective.AllowedMarks) != 1 || effective.AllowedMarks[0] != 0x42 {
		t.Fatalf("allowed marks = %+v", effective.AllowedMarks)
	}
	if len(effective.AllowedPorts) != 1 || len(effective.AllowedV4Hosts) != 1 || len(effective.AllowedV6Hosts) != 1 {
		t.Fatalf("allowlists were not merged: %+v", effective)
	}
}

func TestEffectiveAllowRulesMergesForceActiveRulesets(t *testing.T) {
	effective := effectiveAllowRules(
		allowRules{EnableV4: true},
		&ruleset{Name: "active", allowRules: allowRules{AllowedPorts: []portKey{{Dport: htons(443), Protocol: ipProtoTCP}}}},
		[]ruleset{
			{
				Name:       "disabled",
				Disabled:   true,
				allowRules: allowRules{EnableV6: true, AllowedV6Hosts: []ipv6AddrKey{ipv6Key(netipMustParse("2001:db8::10"))}},
			},
			{
				Name:       "inactive",
				allowRules: allowRules{AllowedV4Hosts: []uint32{ipv4Key(netipMustParse("192.0.2.10"))}},
			},
		},
		nil,
	)

	if !effective.EnableV4 || !effective.EnableV6 {
		t.Fatalf("unexpected effective gates: %+v", effective)
	}
	if len(effective.AllowedPorts) != 1 || len(effective.AllowedV4Hosts) != 1 || len(effective.AllowedV6Hosts) != 1 {
		t.Fatalf("force-active rulesets were not merged: %+v", effective)
	}
}

func TestPolicyManagerForceRulesetReferenceCounting(t *testing.T) {
	manager := &policyManager{
		opts: options{
			Rulesets: []ruleset{
				{Name: "office", Disabled: true, allowRules: allowRules{EnableV6: true}},
			},
		},
		current: allowRules{},
		set:     true,
	}

	if !manager.forceActivateRuleset("client-a", "office") {
		t.Fatal("expected force activation to be accepted")
	}
	if !manager.forceActivateRuleset("client-b", "office") {
		t.Fatal("expected second force activation to be accepted")
	}
	forced := manager.forceRulesetsSnapshot()
	if len(forced) != 1 || len(forced[0].Owners) != 2 {
		t.Fatalf("force-active rulesets = %+v", forced)
	}
	effective := effectiveAllowRules(allowRules{}, nil, forcedRulesets(manager.optionsSnapshot().Rulesets, forced), nil)
	if !effective.EnableV6 {
		t.Fatalf("expected force-active ruleset to affect policy: %+v", effective)
	}

	if !manager.removeForceRulesets("client-a") {
		t.Fatal("expected client-a force activation to be removed")
	}
	forced = manager.forceRulesetsSnapshot()
	if len(forced) != 1 || len(forced[0].Owners) != 1 || forced[0].Owners[0] != "client-b" {
		t.Fatalf("expected client-b reference to keep ruleset active: %+v", forced)
	}

	if !manager.removeForceRulesets("client-b") {
		t.Fatal("expected client-b force activation to be removed")
	}
	if forced := manager.forceRulesetsSnapshot(); len(forced) != 0 {
		t.Fatalf("expected forced ruleset to be released: %+v", forced)
	}
}

func TestPolicyManagerConfigSnapshotIncludesTemporaryRulesets(t *testing.T) {
	manager := &policyManager{
		opts:    options{allowRules: allowRules{EnableV4: true}},
		current: allowRules{EnableV4: true, EnableV6: true},
		tmpRulesets: map[string]allowRules{
			"client-b": {EnableV6: true},
			"client-a": {AllowedPorts: []portKey{{Dport: htons(53), Protocol: ipProtoUDP}}},
		},
		set: true,
	}

	cfg := manager.configSnapshot()
	if !cfg.EffectivePolicy.EnableV6 {
		t.Fatalf("effective policy = %+v", cfg.EffectivePolicy)
	}
	if len(cfg.TemporaryRulesets) != 2 {
		t.Fatalf("tmp rulesets = %+v", cfg.TemporaryRulesets)
	}
	if cfg.TemporaryRulesets[0].Client != "client-a" || cfg.TemporaryRulesets[1].Client != "client-b" {
		t.Fatalf("tmp rulesets are not sorted by owner: %+v", cfg.TemporaryRulesets)
	}
	if len(cfg.TemporaryRulesets[0].Policy.AllowedPorts) != 1 || !cfg.TemporaryRulesets[1].Policy.EnableV6 {
		t.Fatalf("tmp ruleset policies = %+v", cfg.TemporaryRulesets)
	}
}

func TestPolicyManagerConfigSnapshotIncludesForceActiveRulesets(t *testing.T) {
	manager := &policyManager{
		opts: options{
			Rulesets: []ruleset{
				{Name: "office", allowRules: allowRules{EnableV6: true}},
			},
		},
		forceRulesets: map[string]map[string]int{
			"office": {
				"client-b": 1,
				"client-a": 2,
			},
		},
		set: true,
	}

	cfg := manager.configSnapshot()
	if len(cfg.ForceActiveRulesets) != 1 {
		t.Fatalf("force-active rulesets = %+v", cfg.ForceActiveRulesets)
	}
	forced := cfg.ForceActiveRulesets[0]
	if forced.Name != "office" || len(forced.Clients) != 2 || forced.Clients[0] != "client-a" || forced.Clients[1] != "client-b" {
		t.Fatalf("force-active ruleset snapshot = %+v", forced)
	}
}

func TestPolicyManagerConfigSnapshotMarksActiveRuleset(t *testing.T) {
	manager := &policyManager{
		opts: options{
			Rulesets: []ruleset{
				{
					Name:       "office",
					Priority:   20,
					Trigger:    rulesetTrigger{InterfaceNames: []string{"wg0"}},
					allowRules: allowRules{EnableV4: true},
				},
				{
					Name:       "home",
					Disabled:   true,
					Priority:   10,
					Trigger:    rulesetTrigger{InterfaceNames: []string{"tun0"}},
					allowRules: allowRules{EnableV6: true},
				},
			},
		},
		current:    allowRules{EnableV4: true},
		activeName: "office",
		set:        true,
	}

	cfg := manager.configSnapshot()
	if cfg.ActiveRuleset != "office" {
		t.Fatalf("active ruleset = %q", cfg.ActiveRuleset)
	}
	if len(cfg.Rulesets) != 2 {
		t.Fatalf("rulesets count = %d", len(cfg.Rulesets))
	}
	if !cfg.Rulesets[0].Active {
		t.Fatalf("office ruleset is not marked active: %+v", cfg.Rulesets[0])
	}
	if cfg.Rulesets[1].Active {
		t.Fatalf("home ruleset is marked active: %+v", cfg.Rulesets[1])
	}
	if !cfg.Rulesets[1].Disabled {
		t.Fatalf("home ruleset disabled flag is missing: %+v", cfg.Rulesets[1])
	}
	if !cfg.Rulesets[0].Policy.EnableV4 || !cfg.Rulesets[1].Policy.EnableV6 {
		t.Fatalf("ruleset policies were not included: %+v", cfg.Rulesets)
	}
}

func TestAPIRulesetsNeverMarksDisabledRulesetActive(t *testing.T) {
	rulesets := apiRulesets([]ruleset{
		{Name: "office", Disabled: true, Trigger: rulesetTrigger{InterfaceNames: []string{"wg0"}}},
	}, "office")
	if len(rulesets) != 1 || rulesets[0].Active || !rulesets[0].Disabled {
		t.Fatalf("rulesets = %+v", rulesets)
	}
}

func TestMutateOptionsAddsBasePolicyAllowlistEntry(t *testing.T) {
	opts := options{
		InterfaceNames: []string{"eth0"},
		allowRules:     allowRules{EnableV4: true},
	}

	next, err := mutateOptions(opts, adminapi.MutationRequest{
		Operation: adminapi.MutationAdd,
		Target:    "base_policy.allowed_ports",
		Values:    []string{"tcp/443"},
	})
	if err != nil {
		t.Fatalf("mutate options: %v", err)
	}
	if len(next.AllowedPorts) != 1 || next.AllowedPorts[0] != (portKey{Dport: htons(443), Protocol: ipProtoTCP}) {
		t.Fatalf("allowed ports = %+v", next.AllowedPorts)
	}
	if len(opts.AllowedPorts) != 0 {
		t.Fatalf("original options were mutated: %+v", opts.AllowedPorts)
	}
}

func TestMutateOptionsRejectsInvalidInputs(t *testing.T) {
	opts := options{InterfaceNames: []string{"eth0"}}
	tests := []adminapi.MutationRequest{
		{Operation: adminapi.MutationSet, Target: "admin_api.socket_path", Value: json.RawMessage(`"/tmp/other.sock"`)},
		{Operation: adminapi.MutationAdd, Target: "interface_regexps", Values: []string{"["}},
		{Operation: adminapi.MutationRemove, Target: "interface_names", Values: []string{"eth0"}},
		{Operation: adminapi.MutationAdd, Target: "base_policy.allowed_ports", Values: []string{"icmp/8"}},
		{Operation: adminapi.MutationSet, Target: "base_policy.enable_v4", Value: json.RawMessage(`"yes"`)},
	}

	for _, req := range tests {
		if _, err := mutateOptions(opts, req); err == nil {
			t.Fatalf("mutateOptions(%+v) succeeded, expected error", req)
		}
	}
}

func TestMutateOptionsSetsWholeBasePolicy(t *testing.T) {
	next, err := mutateOptions(options{InterfaceNames: []string{"eth0"}}, adminapi.MutationRequest{
		Operation: adminapi.MutationSet,
		Target:    "base_policy",
		Policy: &adminapi.AllowRules{
			AllowAll:       true,
			EnableV4:       true,
			AllowedV4Hosts: []string{"192.0.2.10"},
		},
	})
	if err != nil {
		t.Fatalf("mutate options: %v", err)
	}
	if !next.AllowAll || !next.EnableV4 || len(next.AllowedV4Hosts) != 1 {
		t.Fatalf("base policy = %+v", next.allowRules)
	}
}

func TestMutateOptionsSetsWholeRuleset(t *testing.T) {
	next, err := mutateOptions(options{InterfaceNames: []string{"eth0"}}, adminapi.MutationRequest{
		Operation: adminapi.MutationSet,
		Target:    "ruleset",
		Ruleset:   "office",
		RulesetDef: &adminapi.RulesetMutation{
			Disabled: true,
			Priority: 20,
			MatchAll: true,
			Trigger: adminapi.RulesetTrigger{
				InterfaceNames: []string{"wg0"},
				IPAddrs:        []string{"10.64.0.2"},
			},
			Policy: adminapi.AllowRules{EnableV6: true},
		},
	})
	if err != nil {
		t.Fatalf("mutate options: %v", err)
	}
	if len(next.Rulesets) != 1 {
		t.Fatalf("rulesets = %+v", next.Rulesets)
	}
	ruleset := next.Rulesets[0]
	if ruleset.Name != "office" || !ruleset.Disabled || ruleset.Priority != 20 || !ruleset.MatchAll || !ruleset.EnableV6 {
		t.Fatalf("ruleset = %+v", ruleset)
	}
	if len(ruleset.Trigger.IPAddrs) != 1 || ruleset.Trigger.IPAddrs[0] != netipMustParse("10.64.0.2") {
		t.Fatalf("trigger = %+v", ruleset.Trigger)
	}
}

func TestMutateOptionsSetsRulesetDisabled(t *testing.T) {
	next, err := mutateOptions(options{
		InterfaceNames: []string{"eth0"},
		Rulesets: []ruleset{
			{
				Name:       "office",
				Priority:   20,
				Trigger:    rulesetTrigger{InterfaceNames: []string{"wg0"}},
				allowRules: allowRules{EnableV6: true},
			},
		},
	}, adminapi.MutationRequest{
		Operation: adminapi.MutationSet,
		Target:    "ruleset.disabled",
		Ruleset:   "office",
		Value:     json.RawMessage(`true`),
	})
	if err != nil {
		t.Fatalf("mutate options: %v", err)
	}
	if len(next.Rulesets) != 1 || !next.Rulesets[0].Disabled {
		t.Fatalf("rulesets = %+v", next.Rulesets)
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

func TestShouldReconcileLinkUpdateIgnoresIgnoredInterface(t *testing.T) {
	manager := newEgressManager(nil)

	if manager.shouldReconcileLinkUpdate(linkUpdate(unix.RTM_NEWLINK, 5, "docker0", "device"), options{
		InterfaceTypes:          []string{"device"},
		IgnoredInterfaceRegexps: []string{"^docker"},
	}) {
		t.Fatal("expected ignored matching interface update to be ignored")
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

func netipMustParse(value string) netip.Addr {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		panic(err)
	}
	return addr
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

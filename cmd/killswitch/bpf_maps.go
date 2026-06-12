//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"sort"
	"strings"

	"github.com/asciimoth/killswitch/internal/policy"
	"github.com/cilium/ebpf"
)

func writeRuntimeConfig(m *ebpf.Map, ifindex uint32, config runtimeConfig) error {
	if err := m.Update(ifindex, config, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update runtime_config map: %w", err)
	}
	return nil
}

func writeEffectivePolicies(objs *killswitchObjects, current, next map[int]interfacePolicy) error {
	if objs == nil {
		return nil
	}
	for index := range current {
		if _, ok := next[index]; !ok {
			if err := clearPolicyForInterface(objs, uint32(index)); err != nil {
				return err
			}
		}
	}
	for index, policy := range next {
		if currentPolicy, ok := current[index]; ok && allowRulesEqual(currentPolicy.Rules, policy.Rules) {
			continue
		}
		if err := writeEffectivePolicyForInterface(objs, uint32(index), policy.Rules); err != nil {
			return err
		}
	}
	return nil
}

func writeEffectivePolicyForInterface(objs *killswitchObjects, ifindex uint32, rules allowRules) error {
	if err := clearPolicyForInterface(objs, ifindex); err != nil {
		return err
	}
	if err := writeAllowlists(objs, ifindex, rules); err != nil {
		return err
	}
	if err := writeRuntimeConfig(objs.RuntimeConfig, ifindex, runtimeConfig{
		AllowAll: boolByte(rules.AllowAll),
		EnableV4: boolByte(rules.EnableV4),
		EnableV6: boolByte(rules.EnableV6),
	}); err != nil {
		return err
	}
	return nil
}

func clearPolicyForInterface(objs *killswitchObjects, ifindex uint32) error {
	if err := clearRuntimeConfig(objs.RuntimeConfig, ifindex); err != nil {
		return err
	}
	if err := clearAllowedMapForInterface[markPolicyKey](objs.AllowedMarks, "allowed_marks", ifindex, func(k markPolicyKey) uint32 { return k.Ifindex }); err != nil {
		return err
	}
	if err := clearAllowedMapForInterface[portPolicyKey](objs.AllowedPorts, "allowed_ports", ifindex, func(k portPolicyKey) uint32 { return k.Ifindex }); err != nil {
		return err
	}
	if err := clearAllowedMapForInterface[v4HostPolicyKey](objs.AllowedV4Hosts, "allowed_v4_hosts", ifindex, func(k v4HostPolicyKey) uint32 { return k.Ifindex }); err != nil {
		return err
	}
	if err := clearAllowedMapForInterface[v6HostPolicyKey](objs.AllowedV6Hosts, "allowed_v6_hosts", ifindex, func(k v6HostPolicyKey) uint32 { return k.Ifindex }); err != nil {
		return err
	}
	if err := clearAllowedMapForInterface[hostport4PolicyKey](objs.AllowedV4Hostports, "allowed_v4_hostports", ifindex, func(k hostport4PolicyKey) uint32 { return k.Ifindex }); err != nil {
		return err
	}
	if err := clearAllowedMapForInterface[hostport6PolicyKey](objs.AllowedV6Hostports, "allowed_v6_hostports", ifindex, func(k hostport6PolicyKey) uint32 { return k.Ifindex }); err != nil {
		return err
	}
	return nil
}

func clearRuntimeConfig(m *ebpf.Map, ifindex uint32) error {
	if err := m.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete runtime_config map entry: %w", err)
	}
	return nil
}

func clearAllowedMapForInterface[K comparable](m *ebpf.Map, name string, ifindex uint32, keyIfindex func(K) uint32) error {
	var key K
	var value uint8
	entries := m.Iterate()
	for entries.Next(&key, &value) {
		if keyIfindex(key) != ifindex {
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete %s map entry: %w", name, err)
		}
	}
	if err := entries.Err(); err != nil {
		return fmt.Errorf("iterate %s map: %w", name, err)
	}
	return nil
}

func writeAllowlists(objs *killswitchObjects, ifindex uint32, rules allowRules) error {
	if err := writeAllowedMarks(objs.AllowedMarks, ifindex, rules.AllowedMarks); err != nil {
		return err
	}
	if err := writeAllowedMap(objs.AllowedPorts, scopedPortKeys(ifindex, rules.AllowedPorts), "allowed_ports"); err != nil {
		return err
	}
	if err := writeAllowedMap(objs.AllowedV4Hosts, scopedV4HostKeys(ifindex, rules.AllowedV4Hosts), "allowed_v4_hosts"); err != nil {
		return err
	}
	if err := writeAllowedMap(objs.AllowedV6Hosts, scopedV6HostKeys(ifindex, rules.AllowedV6Hosts), "allowed_v6_hosts"); err != nil {
		return err
	}
	if err := writeAllowedMap(objs.AllowedV4Hostports, scopedV4HostportKeys(ifindex, rules.AllowedV4Pairs), "allowed_v4_hostports"); err != nil {
		return err
	}
	if err := writeAllowedMap(objs.AllowedV6Hostports, scopedV6HostportKeys(ifindex, rules.AllowedV6Pairs), "allowed_v6_hostports"); err != nil {
		return err
	}
	return nil
}

func writeAllowedMarks(m *ebpf.Map, ifindex uint32, marks []uint32) error {
	keys := make([]markPolicyKey, 0, len(marks))
	for _, mark := range marks {
		keys = append(keys, markPolicyKey{Ifindex: ifindex, Mark: mark})
	}
	return writeAllowedMap(m, keys, "allowed_marks")
}

func writeAllowedMap[K comparable](m *ebpf.Map, keys []K, name string) error {
	var allowed uint8 = 1
	for _, key := range keys {
		if err := m.Update(key, allowed, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update %s map: %w", name, err)
		}
	}
	return nil
}

func scopedPortKeys(ifindex uint32, values []portKey) []portPolicyKey {
	out := make([]portPolicyKey, 0, len(values))
	for _, value := range values {
		out = append(out, portPolicyKey{Ifindex: ifindex, Dport: value.Dport, Protocol: value.Protocol})
	}
	return out
}

func scopedV4HostKeys(ifindex uint32, values []uint32) []v4HostPolicyKey {
	out := make([]v4HostPolicyKey, 0, len(values))
	for _, value := range values {
		out = append(out, v4HostPolicyKey{Ifindex: ifindex, Daddr: value})
	}
	return out
}

func scopedV6HostKeys(ifindex uint32, values []ipv6AddrKey) []v6HostPolicyKey {
	out := make([]v6HostPolicyKey, 0, len(values))
	for _, value := range values {
		out = append(out, v6HostPolicyKey{Ifindex: ifindex, Addr: value.Addr})
	}
	return out
}

func scopedV4HostportKeys(ifindex uint32, values []hostport4Key) []hostport4PolicyKey {
	out := make([]hostport4PolicyKey, 0, len(values))
	for _, value := range values {
		out = append(out, hostport4PolicyKey{
			Ifindex:  ifindex,
			Daddr:    value.Daddr,
			Dport:    value.Dport,
			Protocol: value.Protocol,
		})
	}
	return out
}

func scopedV6HostportKeys(ifindex uint32, values []hostport6Key) []hostport6PolicyKey {
	out := make([]hostport6PolicyKey, 0, len(values))
	for _, value := range values {
		out = append(out, hostport6PolicyKey{
			Ifindex:  ifindex,
			Daddr:    value.Daddr,
			Dport:    value.Dport,
			Protocol: value.Protocol,
		})
	}
	return out
}

func mergeAllowRules(base allowRules, overlay allowRules) allowRules {
	return canonicalAllowRules(allowRules{
		AllowAll:       base.AllowAll || overlay.AllowAll,
		EnableV4:       base.EnableV4 || overlay.EnableV4,
		EnableV6:       base.EnableV6 || overlay.EnableV6,
		AllowedMarks:   append(append([]uint32(nil), base.AllowedMarks...), overlay.AllowedMarks...),
		AllowedPorts:   append(append([]portKey(nil), base.AllowedPorts...), overlay.AllowedPorts...),
		AllowedV4Hosts: append(append([]uint32(nil), base.AllowedV4Hosts...), overlay.AllowedV4Hosts...),
		AllowedV6Hosts: append(append([]ipv6AddrKey(nil), base.AllowedV6Hosts...), overlay.AllowedV6Hosts...),
		AllowedV4Pairs: append(append([]hostport4Key(nil), base.AllowedV4Pairs...), overlay.AllowedV4Pairs...),
		AllowedV6Pairs: append(append([]hostport6Key(nil), base.AllowedV6Pairs...), overlay.AllowedV6Pairs...),
	})
}

func canonicalAllowRules(rules allowRules) allowRules {
	rules.AllowedMarks = uniqueSorted(rules.AllowedMarks, func(a, b uint32) bool { return a < b })
	rules.AllowedPorts = uniqueSorted(rules.AllowedPorts, func(a, b portKey) bool {
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Dport < b.Dport
	})
	rules.AllowedV4Hosts = uniqueSorted(rules.AllowedV4Hosts, func(a, b uint32) bool { return a < b })
	rules.AllowedV6Hosts = uniqueSorted(rules.AllowedV6Hosts, func(a, b ipv6AddrKey) bool {
		return bytes.Compare(a.Addr[:], b.Addr[:]) < 0
	})
	rules.AllowedV4Pairs = uniqueSorted(rules.AllowedV4Pairs, func(a, b hostport4Key) bool {
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Daddr != b.Daddr {
			return a.Daddr < b.Daddr
		}
		return a.Dport < b.Dport
	})
	rules.AllowedV6Pairs = uniqueSorted(rules.AllowedV6Pairs, func(a, b hostport6Key) bool {
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if cmp := bytes.Compare(a.Daddr[:], b.Daddr[:]); cmp != 0 {
			return cmp < 0
		}
		return a.Dport < b.Dport
	})
	return rules
}

func uniqueSorted[K comparable](values []K, less func(a, b K) bool) []K {
	if len(values) == 0 {
		return nil
	}
	values = append([]K(nil), values...)
	sort.Slice(values, func(i, j int) bool {
		return less(values[i], values[j])
	})
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func allowRulesEqual(a, b allowRules) bool {
	return reflect.DeepEqual(canonicalAllowRules(a), canonicalAllowRules(b))
}

func interfacePolicyRulesEqual(a, b map[int]interfacePolicy) bool {
	if len(a) != len(b) {
		return false
	}
	for index, aPolicy := range a {
		bPolicy, ok := b[index]
		if !ok {
			return false
		}
		if aPolicy.Info.Name != bPolicy.Info.Name || aPolicy.Info.Type != bPolicy.Info.Type || !reflect.DeepEqual(aPolicy.Info.Addrs, bPolicy.Info.Addrs) {
			return false
		}
		if !allowRulesEqual(aPolicy.Rules, bPolicy.Rules) {
			return false
		}
	}
	return true
}

func cloneInterfacePolicyMap(values map[int]interfacePolicy) map[int]interfacePolicy {
	if len(values) == 0 {
		return nil
	}
	out := make(map[int]interfacePolicy, len(values))
	for index, value := range values {
		value.Info.Addrs = append([]netip.Addr(nil), value.Info.Addrs...)
		value.Info.GatewayMACs = cloneStrings(value.Info.GatewayMACs)
		value.Rules = cloneAllowRules(value.Rules)
		value.ActiveRulesets = cloneStrings(value.ActiveRulesets)
		value.ForcedRulesets = cloneStrings(value.ForcedRulesets)
		value.TemporaryRulesets = cloneStrings(value.TemporaryRulesets)
		out[index] = value
	}
	return out
}

func logPolicies(policies map[int]interfacePolicy) {
	if len(policies) == 0 {
		log.Print("Effective policies: none")
		return
	}
	for _, policy := range sortedInterfacePolicies(policies) {
		logPolicy(policy)
	}
}

func sortedInterfacePolicies(policies map[int]interfacePolicy) []interfacePolicy {
	out := make([]interfacePolicy, 0, len(policies))
	for _, policy := range policies {
		out = append(out, policy)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Info.Name != out[j].Info.Name {
			return out[i].Info.Name < out[j].Info.Name
		}
		return out[i].Info.Index < out[j].Info.Index
	})
	return out
}

func logPolicy(policy interfacePolicy) {
	rules := policy.Rules
	if rules.AllowAll {
		log.Printf("WARNING: AllowAll is enabled on %s(index %d); protected interface will pass all traffic", policy.Info.Name, policy.Info.Index)
	}
	log.Printf("Effective policy for %s(index %d): active_rulesets=%s forced_rulesets=%s temporary_rulesets=%d allow_all=%t enable_v4=%t enable_v6=%t allowlists marks=%d ports=%d v4_hosts=%d v6_hosts=%d v4_hostports=%d v6_hostports=%d",
		policy.Info.Name,
		policy.Info.Index,
		strings.Join(policy.ActiveRulesets, ","),
		strings.Join(policy.ForcedRulesets, ","),
		len(policy.TemporaryRulesets),
		rules.AllowAll,
		rules.EnableV4,
		rules.EnableV6,
		len(rules.AllowedMarks),
		len(rules.AllowedPorts),
		len(rules.AllowedV4Hosts),
		len(rules.AllowedV6Hosts),
		len(rules.AllowedV4Pairs),
		len(rules.AllowedV6Pairs),
	)
}

func allowedPortKeys(values []string) ([]portKey, error) {
	rules, err := policy.ParseAllowedPorts(values)
	if err != nil {
		return nil, err
	}
	keys := make([]portKey, 0, len(rules))
	for _, rule := range rules {
		keys = append(keys, portKey{Dport: htons(rule.Port), Protocol: rule.Protocol})
	}
	return keys, nil
}

func allowedV4HostKeys(values []string) ([]uint32, error) {
	addrs, err := policy.ParseAllowedV4Hosts(values)
	if err != nil {
		return nil, err
	}
	keys := make([]uint32, 0, len(addrs))
	for _, addr := range addrs {
		keys = append(keys, ipv4Key(addr))
	}
	return keys, nil
}

func allowedV6HostKeys(values []string) ([]ipv6AddrKey, error) {
	addrs, err := policy.ParseAllowedV6Hosts(values)
	if err != nil {
		return nil, err
	}
	keys := make([]ipv6AddrKey, 0, len(addrs))
	for _, addr := range addrs {
		keys = append(keys, ipv6Key(addr))
	}
	return keys, nil
}

func allowedV4HostportKeys(values []string) ([]hostport4Key, error) {
	rules, err := policy.ParseAllowedV4Hostports(values)
	if err != nil {
		return nil, err
	}
	keys := make([]hostport4Key, 0, len(rules))
	for _, rule := range rules {
		keys = append(keys, hostport4Key{
			Daddr:    ipv4Key(rule.AddrPort.Addr()),
			Dport:    htons(rule.AddrPort.Port()),
			Protocol: rule.Protocol,
		})
	}
	return keys, nil
}

func allowedV6HostportKeys(values []string) ([]hostport6Key, error) {
	rules, err := policy.ParseAllowedV6Hostports(values)
	if err != nil {
		return nil, err
	}
	keys := make([]hostport6Key, 0, len(rules))
	for _, rule := range rules {
		keys = append(keys, hostport6Key{
			Daddr:    ipv6Key(rule.AddrPort.Addr()).Addr,
			Dport:    htons(rule.AddrPort.Port()),
			Protocol: rule.Protocol,
		})
	}
	return keys, nil
}

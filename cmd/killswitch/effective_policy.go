//go:build linux

package main

import (
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sort"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

type temporaryRuleset struct {
	Owner      string
	Interfaces []string
	Rules      allowRules
}

type forceRuleset struct {
	Name       string
	Owners     []string
	Interfaces []string
}

func effectiveAllowRules(base allowRules, active []ruleset, forceRulesets []ruleset, tmpRulesets []temporaryRuleset, socksProxyStateOpt ...socksProxyState) allowRules {
	effective := base
	for _, ruleset := range active {
		effective = mergeAllowRules(effective, ruleset.allowRules)
	}
	for _, ruleset := range forceRulesets {
		effective = mergeAllowRules(effective, ruleset.allowRules)
	}
	for _, tmp := range tmpRulesets {
		effective = mergeAllowRules(effective, tmp.Rules)
	}
	var socksProxy socksProxyState
	if len(socksProxyStateOpt) > 0 {
		socksProxy = socksProxyStateOpt[0]
	}
	if socksProxy.Running {
		effective = mergeAllowRules(effective, allowRules{AllowedMarks: []uint32{socksProxy.FWMark}})
	}
	return canonicalAllowRules(effective)
}

func forcedRulesetsForInterface(rulesets []ruleset, forceRulesets []forceRuleset, ifaceName string) []ruleset {
	if len(forceRulesets) == 0 {
		return nil
	}
	out := make([]ruleset, 0, len(forceRulesets))
	for _, forced := range forceRulesets {
		if !stringInSlice(ifaceName, forced.Interfaces) {
			continue
		}
		idx := findRuleset(rulesets, forced.Name)
		if idx >= 0 {
			out = append(out, rulesets[idx])
		}
	}
	return out
}

func temporaryRulesetsForInterface(rulesets []temporaryRuleset, ifaceName string) []temporaryRuleset {
	out := make([]temporaryRuleset, 0, len(rulesets))
	for _, ruleset := range rulesets {
		if stringInSlice(ifaceName, ruleset.Interfaces) {
			out = append(out, ruleset)
		}
	}
	return out
}

func effectivePoliciesForInterfaces(ifaces []interfaceInfo, opts options, tmpRulesets []temporaryRuleset, forceRulesets []forceRuleset, socksProxyStateOpt ...socksProxyState) map[int]interfacePolicy {
	if len(ifaces) == 0 {
		return nil
	}
	var socksProxy socksProxyState
	if len(socksProxyStateOpt) > 0 {
		socksProxy = socksProxyStateOpt[0]
	}
	out := make(map[int]interfacePolicy, len(ifaces))
	for _, iface := range ifaces {
		active := activeRulesetsForInterface(iface, opts.Rulesets)
		forced := forcedRulesetsForInterface(opts.Rulesets, forceRulesets, iface.Name)
		tmp := temporaryRulesetsForInterface(tmpRulesets, iface.Name)
		out[iface.Index] = interfacePolicy{
			Info:              iface,
			Rules:             effectiveAllowRules(opts.allowRules, active, forced, tmp, socksProxy),
			ActiveRulesets:    rulesetNames(active),
			ForcedRulesets:    rulesetNames(forced),
			TemporaryRulesets: temporaryRulesetOwners(tmp),
		}
	}
	return out
}

func activeRulesetsForInterface(iface interfaceInfo, rulesets []ruleset) []ruleset {
	out := make([]ruleset, 0, len(rulesets))
	for _, ruleset := range rulesets {
		if ruleset.Disabled {
			continue
		}
		if rulesetTriggerMatchesInterface(iface, ruleset.Trigger, ruleset.MatchAll) {
			out = append(out, ruleset)
		}
	}
	return out
}

func rulesetNames(rulesets []ruleset) []string {
	out := make([]string, 0, len(rulesets))
	for _, ruleset := range rulesets {
		out = append(out, ruleset.Name)
	}
	sort.Strings(out)
	return out
}

func temporaryRulesetOwners(rulesets []temporaryRuleset) []string {
	out := make([]string, 0, len(rulesets))
	for _, ruleset := range rulesets {
		out = append(out, ruleset.Owner)
	}
	sort.Strings(out)
	return out
}

func apiRulesets(rulesets []ruleset, activeNames map[string]bool) []adminapi.Ruleset {
	if len(rulesets) == 0 {
		return nil
	}
	out := make([]adminapi.Ruleset, 0, len(rulesets))
	for _, ruleset := range rulesets {
		out = append(out, adminapi.Ruleset{
			Name:     ruleset.Name,
			Active:   !ruleset.Disabled && activeNames[ruleset.Name],
			Disabled: ruleset.Disabled,
			MatchAll: ruleset.MatchAll,
			Trigger: adminapi.RulesetTrigger{
				InterfaceTypes:   cloneStrings(ruleset.Trigger.InterfaceTypes),
				InterfaceNames:   cloneStrings(ruleset.Trigger.InterfaceNames),
				InterfaceRegexps: cloneStrings(ruleset.Trigger.InterfaceRegexps),
				IPAddrs:          apiAddrs(ruleset.Trigger.IPAddrs),
				SSIDs:            cloneStrings(ruleset.Trigger.SSIDs),
				BSSIDs:           cloneStrings(ruleset.Trigger.BSSIDs),
				GatewayMACs:      cloneStrings(ruleset.Trigger.GatewayMACs),
			},
			Policy: apiAllowRules(ruleset.allowRules),
		})
	}
	return out
}

func apiTemporaryRulesets(rulesets []temporaryRuleset) []adminapi.TmpRuleset {
	if len(rulesets) == 0 {
		return nil
	}
	out := make([]adminapi.TmpRuleset, 0, len(rulesets))
	for _, ruleset := range rulesets {
		out = append(out, adminapi.TmpRuleset{
			Client:     ruleset.Owner,
			Interfaces: cloneStrings(ruleset.Interfaces),
			Policy:     apiAllowRules(ruleset.Rules),
		})
	}
	return out
}

func apiForceRulesets(rulesets []forceRuleset) []adminapi.ForceRuleset {
	if len(rulesets) == 0 {
		return nil
	}
	out := make([]adminapi.ForceRuleset, 0, len(rulesets))
	for _, ruleset := range rulesets {
		out = append(out, adminapi.ForceRuleset{
			Name:       ruleset.Name,
			Clients:    cloneStrings(ruleset.Owners),
			Interfaces: cloneStrings(ruleset.Interfaces),
		})
	}
	return out
}

func apiInterfacePolicies(current map[int]interfacePolicy) []adminapi.InterfacePolicy {
	if len(current) == 0 {
		return nil
	}
	indexes := make([]int, 0, len(current))
	for index := range current {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool {
		a, b := current[indexes[i]].Info, current[indexes[j]].Info
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Index < b.Index
	})
	out := make([]adminapi.InterfacePolicy, 0, len(indexes))
	for _, index := range indexes {
		p := current[index]
		out = append(out, adminapi.InterfacePolicy{
			Index:             p.Info.Index,
			Name:              p.Info.Name,
			Type:              p.Info.Type,
			SSID:              p.Info.SSID,
			BSSID:             p.Info.BSSID,
			GatewayMACs:       cloneStrings(p.Info.GatewayMACs),
			Matched:           true,
			Attached:          true,
			EffectivePolicy:   apiAllowRules(p.Rules),
			ActiveRulesets:    cloneStrings(p.ActiveRulesets),
			ForcedRulesets:    cloneStrings(p.ForcedRulesets),
			TemporaryRulesets: cloneStrings(p.TemporaryRulesets),
		})
	}
	return out
}

func firstEffectivePolicy(current map[int]interfacePolicy, fallback allowRules) allowRules {
	for _, policy := range current {
		return policy.Rules
	}
	return fallback
}

func firstActiveRuleset(current map[int]interfacePolicy) string {
	for _, policy := range current {
		if len(policy.ActiveRulesets) > 0 {
			return policy.ActiveRulesets[0]
		}
	}
	return ""
}

func activeRulesetSet(current map[int]interfacePolicy) map[string]bool {
	out := make(map[string]bool)
	for _, policy := range current {
		for _, name := range policy.ActiveRulesets {
			out[name] = true
		}
	}
	return out
}

func apiAllowRules(rules allowRules) adminapi.AllowRules {
	return adminapi.AllowRules{
		AllowAll:       rules.AllowAll,
		EnableV4:       rules.EnableV4,
		EnableV6:       rules.EnableV6,
		AllowedMarks:   apiAllowedMarks(rules.AllowedMarks),
		AllowedPorts:   apiAllowedPorts(rules.AllowedPorts),
		AllowedV4Hosts: apiAllowedV4Hosts(rules.AllowedV4Hosts),
		AllowedV6Hosts: apiAllowedV6Hosts(rules.AllowedV6Hosts),
		AllowedV4Pairs: apiAllowedV4Pairs(rules.AllowedV4Pairs),
		AllowedV6Pairs: apiAllowedV6Pairs(rules.AllowedV6Pairs),
	}
}

func apiAllowedMarks(values []uint32) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, fmt.Sprintf("0x%x", value))
	}
	return out
}

func apiAllowedPorts(values []portKey) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, fmt.Sprintf("%s/%d", apiProtocol(value.Protocol), ntohs(value.Dport)))
	}
	return out
}

func apiAllowedV4Hosts(values []uint32) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, ipv4FromNetworkOrder(value).String())
	}
	return out
}

func apiAllowedV6Hosts(values []ipv6AddrKey) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, netip.AddrFrom16(value.Addr).String())
	}
	return out
}

func apiAllowedV4Pairs(values []hostport4Key) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, fmt.Sprintf("%s/%s:%d", apiProtocol(value.Protocol), ipv4FromNetworkOrder(value.Daddr), ntohs(value.Dport)))
	}
	return out
}

func apiAllowedV6Pairs(values []hostport6Key) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		addrPort := netip.AddrPortFrom(netip.AddrFrom16(value.Daddr), ntohs(value.Dport))
		out = append(out, fmt.Sprintf("%s/%s", apiProtocol(value.Protocol), addrPort))
	}
	return out
}

func apiProtocol(protocol uint8) string {
	switch protocol {
	case ipProtoTCP:
		return "tcp"
	case ipProtoUDP:
		return "udp"
	default:
		return fmt.Sprintf("proto%d", protocol)
	}
}

func apiAddrs(values []netip.Addr) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.String())
	}
	return out
}

func apiInterfaces(all []interfaceInfo, opts options, manager *egressManager, notifyError func(string, error)) []adminapi.Interface {
	if len(all) == 0 {
		return nil
	}
	attached := manager.attachedIndexSnapshot()
	out := make([]adminapi.Interface, 0, len(all))
	for _, iface := range all {
		matched, err := interfaceMatchesSelectors(iface, opts)
		if err != nil {
			log.Printf("ERROR: match interface %s(index %d) for admin API snapshot: %s", iface.Name, iface.Index, err)
			if notifyError != nil {
				notifyError("Admin API snapshot error", err)
			}
		}
		out = append(out, adminapi.Interface{
			Index:       iface.Index,
			Name:        iface.Name,
			Type:        iface.Type,
			Addrs:       apiAddrs(iface.Addrs),
			SSID:        iface.SSID,
			BSSID:       iface.BSSID,
			GatewayMACs: cloneStrings(iface.GatewayMACs),
			Matched:     matched,
			Killswitch:  attached[iface.Index],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (m *egressManager) attachedIndexSnapshot() map[int]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[int]bool, len(m.attached))
	for index := range m.attached {
		out[index] = true
	}
	return out
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func rulesetTriggerMatchesInterface(iface interfaceInfo, trigger rulesetTrigger, matchAll bool) bool {
	total := rulesetTriggerPredicateCount(trigger)
	if total == 0 {
		return false
	}

	matched := 0
	for _, typ := range trigger.InterfaceTypes {
		if iface.Type == typ {
			matched++
		}
	}
	for _, name := range trigger.InterfaceNames {
		if iface.Name == name {
			matched++
		}
	}
	for _, pattern := range trigger.InterfaceRegexps {
		if regexp.MustCompile(pattern).MatchString(iface.Name) {
			matched++
		}
	}
	for _, addr := range trigger.IPAddrs {
		for _, ifaceAddr := range iface.Addrs {
			if ifaceAddr.Unmap() == addr.Unmap() {
				matched++
				break
			}
		}
	}
	for _, ssid := range trigger.SSIDs {
		if iface.SSID == ssid {
			matched++
		}
	}
	for _, bssid := range trigger.BSSIDs {
		if iface.BSSID == bssid {
			matched++
		}
	}
	for _, gatewayMAC := range trigger.GatewayMACs {
		if stringInSlice(gatewayMAC, iface.GatewayMACs) {
			matched++
		}
	}
	if matchAll {
		return matched == total
	}
	return matched > 0
}

func rulesetTriggerHasPredicates(trigger rulesetTrigger) bool {
	return rulesetTriggerPredicateCount(trigger) > 0
}

func rulesetTriggerPredicateCount(trigger rulesetTrigger) int {
	return len(trigger.InterfaceTypes) + len(trigger.InterfaceNames) + len(trigger.InterfaceRegexps) + len(trigger.IPAddrs) + len(trigger.SSIDs) + len(trigger.BSSIDs) + len(trigger.GatewayMACs)
}

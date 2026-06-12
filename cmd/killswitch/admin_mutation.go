//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

func applyAdminMutation(req adminapi.MutationRequest, policies *policyManager, manager *egressManager, reconcileMu *sync.Mutex) adminapi.MutationResult {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()

	next, err := mutateOptions(policies.optionsSnapshot(), req)
	if err != nil {
		return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
	}

	policies.replaceOptions(next)
	if _, err := manager.reconcileCurrent(next, false); err != nil {
		return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
	}
	changed, err := policies.reconcileAttached(manager, true)
	if err != nil {
		return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
	}
	return adminapi.MutationResult{OK: true, Changed: changed, Config: policies.configSnapshot()}
}

func applyTemporaryRulesetMutation(owner string, req adminapi.MutationRequest, policies *policyManager, manager *egressManager, reconcileMu *sync.Mutex) adminapi.MutationResult {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()

	switch req.Operation {
	case adminapi.MutationAdd, adminapi.MutationSet:
		rules, err := allowRulesFromAPI(req.Policy, req.Value)
		if err != nil {
			return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
		}
		if len(req.Interfaces) == 0 {
			return adminapi.MutationResult{OK: false, Error: "tmp_ruleset requires at least one interface name", Config: policies.configSnapshot()}
		}
		policies.setTemporaryRuleset(owner, uniqueSortedStrings(req.Interfaces), rules)
	case adminapi.MutationRemove:
		policies.removeTemporaryRuleset(owner)
	default:
		return adminapi.MutationResult{OK: false, Error: fmt.Sprintf("unsupported mutation operation %q", req.Operation), Config: policies.configSnapshot()}
	}

	changed, err := policies.reconcileAttached(manager, true)
	if err != nil {
		return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
	}
	return adminapi.MutationResult{OK: true, Changed: changed, Config: policies.configSnapshot()}
}

func applyForceRulesetMutation(owner string, req adminapi.MutationRequest, policies *policyManager, manager *egressManager, reconcileMu *sync.Mutex) adminapi.MutationResult {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()

	if req.Ruleset == "" {
		return adminapi.MutationResult{OK: false, Error: "ruleset name is required", Config: policies.configSnapshot()}
	}
	switch req.Operation {
	case adminapi.MutationAdd, adminapi.MutationSet:
		if len(req.Interfaces) == 0 {
			return adminapi.MutationResult{OK: false, Error: "force_ruleset requires at least one interface name", Config: policies.configSnapshot()}
		}
		if !policies.forceActivateRuleset(owner, req.Ruleset, uniqueSortedStrings(req.Interfaces), req.Operation == adminapi.MutationSet) {
			return adminapi.MutationResult{OK: false, Error: fmt.Sprintf("ruleset %q does not exist", req.Ruleset), Config: policies.configSnapshot()}
		}
	case adminapi.MutationRemove:
		policies.releaseForceRuleset(owner, req.Ruleset, uniqueSortedStrings(req.Interfaces))
	default:
		return adminapi.MutationResult{OK: false, Error: fmt.Sprintf("unsupported mutation operation %q", req.Operation), Config: policies.configSnapshot()}
	}

	policyChanged, err := policies.reconcileAttached(manager, true)
	if err != nil {
		return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
	}
	return adminapi.MutationResult{OK: true, Changed: policyChanged, Config: policies.configSnapshot()}
}

func removeTemporaryRuleset(owner string, policies *policyManager, manager *egressManager, reconcileMu *sync.Mutex) adminapi.MutationResult {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()

	if !policies.removeTemporaryRuleset(owner) {
		return adminapi.MutationResult{OK: true, Changed: false, Config: policies.configSnapshot()}
	}
	changed, err := policies.reconcileAttached(manager, true)
	if err != nil {
		return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
	}
	return adminapi.MutationResult{OK: true, Changed: changed, Config: policies.configSnapshot()}
}

func removeForceRulesets(owner string, policies *policyManager, manager *egressManager, reconcileMu *sync.Mutex) adminapi.MutationResult {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()

	if !policies.removeForceRulesets(owner) {
		return adminapi.MutationResult{OK: true, Changed: false, Config: policies.configSnapshot()}
	}
	policyChanged, err := policies.reconcileAttached(manager, true)
	if err != nil {
		return adminapi.MutationResult{OK: false, Error: err.Error(), Config: policies.configSnapshot()}
	}
	return adminapi.MutationResult{OK: true, Changed: policyChanged, Config: policies.configSnapshot()}
}

func mutateOptions(opts options, req adminapi.MutationRequest) (options, error) {
	next := cloneOptions(opts)
	if strings.HasPrefix(req.Target, "admin_api") || req.Target == "admin_api" {
		return options{}, errors.New("admin_api configuration cannot be mutated via admin API")
	}
	switch req.Operation {
	case adminapi.MutationAdd, adminapi.MutationRemove, adminapi.MutationSet:
	default:
		return options{}, fmt.Errorf("unsupported mutation operation %q", req.Operation)
	}
	if req.Target == "" {
		return options{}, errors.New("mutation target is required")
	}

	switch req.Target {
	case "interface_types":
		if err := mutateStringList(&next.InterfaceTypes, req); err != nil {
			return options{}, err
		}
	case "interface_names":
		if err := mutateStringList(&next.InterfaceNames, req); err != nil {
			return options{}, err
		}
	case "interface_regexps":
		if err := mutateStringList(&next.InterfaceRegexps, req); err != nil {
			return options{}, err
		}
		if err := validateRegexps("interface_regexps", next.InterfaceRegexps); err != nil {
			return options{}, err
		}
	case "ignored_interface_types":
		if err := mutateStringList(&next.IgnoredInterfaceTypes, req); err != nil {
			return options{}, err
		}
	case "ignored_interface_names":
		if err := mutateStringList(&next.IgnoredInterfaceNames, req); err != nil {
			return options{}, err
		}
	case "ignored_interface_regexps":
		if err := mutateStringList(&next.IgnoredInterfaceRegexps, req); err != nil {
			return options{}, err
		}
		if err := validateRegexps("ignored_interface_regexps", next.IgnoredInterfaceRegexps); err != nil {
			return options{}, err
		}
	case "base_policy":
		if req.Operation != adminapi.MutationSet {
			return options{}, errors.New("base_policy only supports set")
		}
		rules, err := allowRulesFromAPI(req.Policy, req.Value)
		if err != nil {
			return options{}, err
		}
		next.allowRules = rules
	case "ruleset":
		if err := mutateWholeRuleset(&next.Rulesets, req); err != nil {
			return options{}, err
		}
	default:
		if strings.HasPrefix(req.Target, "base_policy.") {
			if err := mutateAllowRulesField(&next.allowRules, strings.TrimPrefix(req.Target, "base_policy."), req); err != nil {
				return options{}, err
			}
		} else if strings.HasPrefix(req.Target, "ruleset.") {
			if err := mutateRulesetField(&next.Rulesets, strings.TrimPrefix(req.Target, "ruleset."), req); err != nil {
				return options{}, err
			}
		} else {
			return options{}, fmt.Errorf("unsupported mutation target %q", req.Target)
		}
	}

	if len(next.InterfaceTypes) == 0 && len(next.InterfaceNames) == 0 && len(next.InterfaceRegexps) == 0 {
		return options{}, errors.New("at least one interface_types, interface_names, or interface_regexps entry is required")
	}
	return next, nil
}

func mutateStringList(dst *[]string, req adminapi.MutationRequest) error {
	values, err := mutationStringValues(req)
	if err != nil {
		return err
	}
	switch req.Operation {
	case adminapi.MutationAdd:
		*dst = uniqueStrings(append(*dst, values...))
	case adminapi.MutationRemove:
		*dst = removeStrings(*dst, values)
	case adminapi.MutationSet:
		*dst = uniqueStrings(values)
	}
	return nil
}

func mutationStringValues(req adminapi.MutationRequest) ([]string, error) {
	if len(req.Values) > 0 {
		return cloneStrings(req.Values), nil
	}
	if len(req.Value) == 0 {
		return nil, errors.New("mutation values are required")
	}
	var values []string
	if err := json.Unmarshal(req.Value, &values); err == nil {
		return values, nil
	}
	var value string
	if err := json.Unmarshal(req.Value, &value); err != nil {
		return nil, fmt.Errorf("decode mutation value as string or string array: %w", err)
	}
	return []string{value}, nil
}

func mutateAllowRulesField(rules *allowRules, field string, req adminapi.MutationRequest) error {
	switch field {
	case "allow_all":
		return mutateBool(&rules.AllowAll, req)
	case "enable_v4":
		return mutateBool(&rules.EnableV4, req)
	case "enable_v6":
		return mutateBool(&rules.EnableV6, req)
	case "allowed_marks", "allowed_ports", "allowed_v4_hosts", "allowed_v6_hosts", "allowed_v4_hostports", "allowed_v6_hostports":
		api := apiAllowRules(*rules)
		if err := mutateAPIAllowRulesField(&api, field, req); err != nil {
			return err
		}
		parsed, err := allowRulesFromAPI(&api, nil)
		if err != nil {
			return err
		}
		*rules = parsed
		return nil
	default:
		return fmt.Errorf("unsupported allow rules field %q", field)
	}
}

func mutateAPIAllowRulesField(rules *adminapi.AllowRules, field string, req adminapi.MutationRequest) error {
	switch field {
	case "allowed_marks":
		return mutateStringList(&rules.AllowedMarks, req)
	case "allowed_ports":
		return mutateStringList(&rules.AllowedPorts, req)
	case "allowed_v4_hosts":
		return mutateStringList(&rules.AllowedV4Hosts, req)
	case "allowed_v6_hosts":
		return mutateStringList(&rules.AllowedV6Hosts, req)
	case "allowed_v4_hostports":
		return mutateStringList(&rules.AllowedV4Pairs, req)
	case "allowed_v6_hostports":
		return mutateStringList(&rules.AllowedV6Pairs, req)
	default:
		return fmt.Errorf("unsupported allow rules field %q", field)
	}
}

func mutateBool(dst *bool, req adminapi.MutationRequest) error {
	if req.Operation != adminapi.MutationSet {
		return errors.New("boolean fields only support set")
	}
	if len(req.Value) == 0 {
		return errors.New("boolean mutation value is required")
	}
	var value bool
	if err := json.Unmarshal(req.Value, &value); err != nil {
		return fmt.Errorf("decode boolean mutation value: %w", err)
	}
	*dst = value
	return nil
}

func mutateWholeRuleset(rulesets *[]ruleset, req adminapi.MutationRequest) error {
	if req.Ruleset == "" {
		return errors.New("ruleset name is required")
	}
	switch req.Operation {
	case adminapi.MutationRemove:
		*rulesets = removeRuleset(*rulesets, req.Ruleset)
		return nil
	case adminapi.MutationAdd, adminapi.MutationSet:
		rulesetDef, err := rulesetFromAPI(req.Ruleset, req.RulesetDef, req.Value)
		if err != nil {
			return err
		}
		if req.Operation == adminapi.MutationAdd && findRuleset(*rulesets, req.Ruleset) >= 0 {
			return fmt.Errorf("ruleset %q already exists", req.Ruleset)
		}
		upsertRuleset(rulesets, rulesetDef)
		return nil
	default:
		return fmt.Errorf("unsupported ruleset operation %q", req.Operation)
	}
}

func mutateRulesetField(rulesets *[]ruleset, field string, req adminapi.MutationRequest) error {
	if req.Ruleset == "" {
		return errors.New("ruleset name is required")
	}
	idx := findRuleset(*rulesets, req.Ruleset)
	if idx < 0 {
		return fmt.Errorf("ruleset %q does not exist", req.Ruleset)
	}
	rs := (*rulesets)[idx]
	switch field {
	case "disabled":
		if err := mutateBool(&rs.Disabled, req); err != nil {
			return err
		}
	case "match_all":
		if err := mutateBool(&rs.MatchAll, req); err != nil {
			return err
		}
	case "trigger.interface_types":
		if err := mutateStringList(&rs.Trigger.InterfaceTypes, req); err != nil {
			return err
		}
	case "trigger.interface_names":
		if err := mutateStringList(&rs.Trigger.InterfaceNames, req); err != nil {
			return err
		}
	case "trigger.interface_regexps":
		if err := mutateStringList(&rs.Trigger.InterfaceRegexps, req); err != nil {
			return err
		}
		if err := validateRegexps("ruleset trigger interface_regexps", rs.Trigger.InterfaceRegexps); err != nil {
			return err
		}
	case "trigger.ip_addrs":
		apiTrigger := adminapi.RulesetTrigger{IPAddrs: apiAddrs(rs.Trigger.IPAddrs)}
		if err := mutateStringList(&apiTrigger.IPAddrs, req); err != nil {
			return err
		}
		trigger, err := triggerFromConfig(triggerConfig{
			InterfaceTypes:   rs.Trigger.InterfaceTypes,
			InterfaceNames:   rs.Trigger.InterfaceNames,
			InterfaceRegexps: rs.Trigger.InterfaceRegexps,
			IPAddrs:          apiTrigger.IPAddrs,
			SSIDs:            rs.Trigger.SSIDs,
			BSSIDs:           rs.Trigger.BSSIDs,
			GatewayMACs:      rs.Trigger.GatewayMACs,
		})
		if err != nil {
			return err
		}
		rs.Trigger = trigger
	case "trigger.ssids":
		if err := mutateStringList(&rs.Trigger.SSIDs, req); err != nil {
			return err
		}
	case "trigger.bssids":
		values, err := mutatedMACList("ruleset trigger bssids", rs.Trigger.BSSIDs, req)
		if err != nil {
			return err
		}
		rs.Trigger.BSSIDs = values
	case "trigger.gateway_macs":
		values, err := mutatedMACList("ruleset trigger gateway_macs", rs.Trigger.GatewayMACs, req)
		if err != nil {
			return err
		}
		rs.Trigger.GatewayMACs = values
	case "policy.allow_all", "policy.enable_v4", "policy.enable_v6",
		"policy.allowed_marks", "policy.allowed_ports", "policy.allowed_v4_hosts",
		"policy.allowed_v6_hosts", "policy.allowed_v4_hostports", "policy.allowed_v6_hostports":
		if err := mutateAllowRulesField(&rs.allowRules, strings.TrimPrefix(field, "policy."), req); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported ruleset field %q", field)
	}
	if !rulesetTriggerHasPredicates(rs.Trigger) {
		return errors.New("trigger requires at least one interface_types, interface_names, interface_regexps, ip_addrs, ssids, bssids, or gateway_macs entry")
	}
	(*rulesets)[idx] = rs
	sortRulesets(*rulesets)
	return nil
}

func mutatedMACList(field string, current []string, req adminapi.MutationRequest) ([]string, error) {
	values := cloneStrings(current)
	if err := mutateStringList(&values, req); err != nil {
		return nil, err
	}
	return normalizeMACList(field, values)
}

func allowRulesFromAPI(policyPtr *adminapi.AllowRules, raw json.RawMessage) (allowRules, error) {
	var policy adminapi.AllowRules
	if policyPtr != nil {
		policy = *policyPtr
	} else {
		if len(raw) == 0 {
			return allowRules{}, errors.New("allow rules value is required")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&policy); err != nil {
			return allowRules{}, fmt.Errorf("decode allow rules: %w", err)
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return allowRules{}, errors.New("decode allow rules: multiple JSON values")
		}
	}
	return allowRulesFromConfig(rulesetConfig{
		AllowAll:       policy.AllowAll,
		EnableV4:       policy.EnableV4,
		EnableV6:       policy.EnableV6,
		AllowedMarks:   policy.AllowedMarks,
		AllowedPorts:   policy.AllowedPorts,
		AllowedV4Hosts: policy.AllowedV4Hosts,
		AllowedV6Hosts: policy.AllowedV6Hosts,
		AllowedV4Pairs: policy.AllowedV4Pairs,
		AllowedV6Pairs: policy.AllowedV6Pairs,
	})
}

func rulesetFromAPI(name string, rulesetPtr *adminapi.RulesetMutation, raw json.RawMessage) (ruleset, error) {
	var api adminapi.RulesetMutation
	if rulesetPtr != nil {
		api = *rulesetPtr
	} else {
		if len(raw) == 0 {
			return ruleset{}, errors.New("ruleset value is required")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&api); err != nil {
			return ruleset{}, fmt.Errorf("decode ruleset: %w", err)
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			return ruleset{}, errors.New("decode ruleset: multiple JSON values")
		}
	}

	trigger, err := triggerFromConfig(triggerConfig{
		InterfaceTypes:   api.Trigger.InterfaceTypes,
		InterfaceNames:   api.Trigger.InterfaceNames,
		InterfaceRegexps: api.Trigger.InterfaceRegexps,
		IPAddrs:          api.Trigger.IPAddrs,
		SSIDs:            api.Trigger.SSIDs,
		BSSIDs:           api.Trigger.BSSIDs,
		GatewayMACs:      api.Trigger.GatewayMACs,
	})
	if err != nil {
		return ruleset{}, err
	}
	rules, err := allowRulesFromAPI(&api.Policy, nil)
	if err != nil {
		return ruleset{}, err
	}
	return ruleset{Name: name, Disabled: api.Disabled, MatchAll: api.MatchAll, Trigger: trigger, allowRules: rules}, nil
}

func validateRegexps(field string, values []string) error {
	for _, pattern := range values {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("compile %s %q: %w", field, pattern, err)
		}
	}
	return nil
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return append([]string(nil), out...)
}

func uniqueSortedStrings(values []string) []string {
	out := uniqueStrings(values)
	sort.Strings(out)
	return out
}

func normalizeMAC(value string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return strings.ToLower(hw.String())
}

func normalizeMACList(field string, values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		hw, err := net.ParseMAC(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("parse %s %q: %w", field, value, err)
		}
		out = append(out, strings.ToLower(hw.String()))
	}
	return uniqueSortedStrings(out), nil
}

func stringInSlice(value string, values []string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func removeStrings(values, remove []string) []string {
	removeSet := make(map[string]bool, len(remove))
	for _, value := range remove {
		removeSet[value] = true
	}
	out := values[:0]
	for _, value := range values {
		if !removeSet[value] {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return append([]string(nil), out...)
}

func findRuleset(rulesets []ruleset, name string) int {
	for i, rs := range rulesets {
		if rs.Name == name {
			return i
		}
	}
	return -1
}

func removeRuleset(rulesets []ruleset, name string) []ruleset {
	idx := findRuleset(rulesets, name)
	if idx < 0 {
		return append([]ruleset(nil), rulesets...)
	}
	out := append([]ruleset(nil), rulesets[:idx]...)
	out = append(out, rulesets[idx+1:]...)
	return out
}

func upsertRuleset(rulesets *[]ruleset, rs ruleset) {
	idx := findRuleset(*rulesets, rs.Name)
	if idx < 0 {
		*rulesets = append(*rulesets, rs)
	} else {
		(*rulesets)[idx] = rs
	}
	sortRulesets(*rulesets)
}

func sortRulesets(rulesets []ruleset) {
	sort.Slice(rulesets, func(i, j int) bool {
		return rulesets[i].Name < rulesets[j].Name
	})
}

func cloneOptions(opts options) options {
	out := opts
	out.InterfaceTypes = cloneStrings(opts.InterfaceTypes)
	out.InterfaceNames = cloneStrings(opts.InterfaceNames)
	out.InterfaceRegexps = cloneStrings(opts.InterfaceRegexps)
	out.IgnoredInterfaceTypes = cloneStrings(opts.IgnoredInterfaceTypes)
	out.IgnoredInterfaceNames = cloneStrings(opts.IgnoredInterfaceNames)
	out.IgnoredInterfaceRegexps = cloneStrings(opts.IgnoredInterfaceRegexps)
	out.allowRules = cloneAllowRules(opts.allowRules)
	out.Rulesets = make([]ruleset, len(opts.Rulesets))
	for i, rs := range opts.Rulesets {
		out.Rulesets[i] = ruleset{
			Name:       rs.Name,
			Disabled:   rs.Disabled,
			MatchAll:   rs.MatchAll,
			Trigger:    cloneRulesetTrigger(rs.Trigger),
			allowRules: cloneAllowRules(rs.allowRules),
		}
	}
	return out
}

func cloneRulesetTrigger(trigger rulesetTrigger) rulesetTrigger {
	return rulesetTrigger{
		InterfaceTypes:   cloneStrings(trigger.InterfaceTypes),
		InterfaceNames:   cloneStrings(trigger.InterfaceNames),
		InterfaceRegexps: cloneStrings(trigger.InterfaceRegexps),
		IPAddrs:          append([]netip.Addr(nil), trigger.IPAddrs...),
		SSIDs:            cloneStrings(trigger.SSIDs),
		BSSIDs:           cloneStrings(trigger.BSSIDs),
		GatewayMACs:      cloneStrings(trigger.GatewayMACs),
	}
}

func cloneAllowRules(rules allowRules) allowRules {
	return allowRules{
		AllowAll:       rules.AllowAll,
		EnableV4:       rules.EnableV4,
		EnableV6:       rules.EnableV6,
		AllowedMarks:   append([]uint32(nil), rules.AllowedMarks...),
		AllowedPorts:   append([]portKey(nil), rules.AllowedPorts...),
		AllowedV4Hosts: append([]uint32(nil), rules.AllowedV4Hosts...),
		AllowedV6Hosts: append([]ipv6AddrKey(nil), rules.AllowedV6Hosts...),
		AllowedV4Pairs: append([]hostport4Key(nil), rules.AllowedV4Pairs...),
		AllowedV6Pairs: append([]hostport6Key(nil), rules.AllowedV6Pairs...),
	}
}

func cloneTemporaryRulesets(rulesets map[string]temporaryRuleset) []temporaryRuleset {
	if len(rulesets) == 0 {
		return nil
	}
	owners := make([]string, 0, len(rulesets))
	for owner := range rulesets {
		owners = append(owners, owner)
	}
	sort.Strings(owners)

	out := make([]temporaryRuleset, 0, len(owners))
	for _, owner := range owners {
		tmp := rulesets[owner]
		out = append(out, temporaryRuleset{
			Owner:      owner,
			Interfaces: cloneStrings(tmp.Interfaces),
			Rules:      cloneAllowRules(tmp.Rules),
		})
	}
	return out
}

func cloneForceRulesets(rulesets map[string]map[string]map[string]int) []forceRuleset {
	if len(rulesets) == 0 {
		return nil
	}
	names := make([]string, 0, len(rulesets))
	for name := range rulesets {
		if len(rulesets[name]) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	out := make([]forceRuleset, 0, len(names))
	for _, name := range names {
		ownerSet := make(map[string]bool)
		ifaceSet := make(map[string]bool)
		for owner, ifaces := range rulesets[name] {
			ownerSet[owner] = true
			for iface := range ifaces {
				ifaceSet[iface] = true
			}
		}
		owners := make([]string, 0, len(ownerSet))
		for owner := range ownerSet {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		ifaces := make([]string, 0, len(ifaceSet))
		for iface := range ifaceSet {
			ifaces = append(ifaces, iface)
		}
		sort.Strings(ifaces)
		out = append(out, forceRuleset{
			Name:       name,
			Owners:     owners,
			Interfaces: ifaces,
		})
	}
	return out
}

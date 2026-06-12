//go:build linux

package main

import (
	"fmt"
	"log"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

func newPolicyManager(objs *killswitchObjects, opts options) *policyManager {
	return &policyManager{
		objs:       objs,
		opts:       cloneOptions(opts),
		socksProxy: socksProxyStateFromOptions(opts.SocksProxy),
	}
}

func (m *policyManager) optionsSnapshot() options {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneOptions(m.opts)
}

func (m *policyManager) replaceOptions(opts options) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opts = cloneOptions(opts)
	if !m.socksProxy.Enabled && !m.socksProxy.Running {
		m.socksProxy = socksProxyStateFromOptions(opts.SocksProxy)
	}
	m.pruneForceRulesetsLocked()
}

func (m *policyManager) setSocksProxyState(state socksProxyState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.socksProxy = state
}

func (m *policyManager) socksProxyStateSnapshot() socksProxyState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.socksProxy
}

func (m *policyManager) temporaryRulesetsSnapshot() []temporaryRuleset {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneTemporaryRulesets(m.tmpRulesets)
}

func (m *policyManager) forceRulesetsSnapshot() []forceRuleset {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneForceRulesets(m.forceRulesets)
}

func (m *policyManager) setTemporaryRuleset(owner string, interfaces []string, rules allowRules) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tmpRulesets == nil {
		m.tmpRulesets = make(map[string]temporaryRuleset)
	}
	m.tmpRulesets[owner] = temporaryRuleset{Owner: owner, Interfaces: cloneStrings(interfaces), Rules: cloneAllowRules(rules)}
}

func (m *policyManager) removeTemporaryRuleset(owner string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tmpRulesets[owner]; !ok {
		return false
	}
	delete(m.tmpRulesets, owner)
	return true
}

func (m *policyManager) forceActivateRuleset(owner, name string, interfaces []string, replace bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if findRuleset(m.opts.Rulesets, name) < 0 {
		return false
	}
	if m.forceRulesets == nil {
		m.forceRulesets = make(map[string]map[string]map[string]int)
	}
	owners := m.forceRulesets[name]
	if owners == nil {
		owners = make(map[string]map[string]int)
		m.forceRulesets[name] = owners
	}
	if owners[owner] == nil {
		owners[owner] = make(map[string]int)
	}
	if replace {
		clear(owners[owner])
	}
	for _, iface := range interfaces {
		owners[owner][iface]++
	}
	return true
}

func (m *policyManager) releaseForceRuleset(owner, name string, interfaces []string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.releaseForceRulesetLocked(owner, name, interfaces)
}

func (m *policyManager) removeForceRulesets(owner string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := false
	for name := range m.forceRulesets {
		if m.releaseAllForceRulesetLocked(owner, name) {
			changed = true
		}
	}
	return changed
}

func (m *policyManager) releaseForceRulesetLocked(owner, name string, interfaces []string) bool {
	owners := m.forceRulesets[name]
	if owners == nil || len(owners[owner]) == 0 {
		return false
	}
	if len(interfaces) == 0 {
		delete(owners, owner)
	} else {
		for _, iface := range interfaces {
			if owners[owner][iface] <= 1 {
				delete(owners[owner], iface)
			} else {
				owners[owner][iface]--
			}
		}
		if len(owners[owner]) == 0 {
			delete(owners, owner)
		}
	}
	if len(owners) == 0 {
		delete(m.forceRulesets, name)
	}
	return true
}

func (m *policyManager) releaseAllForceRulesetLocked(owner, name string) bool {
	owners := m.forceRulesets[name]
	if owners == nil || len(owners[owner]) == 0 {
		return false
	}
	delete(owners, owner)
	if len(owners) == 0 {
		delete(m.forceRulesets, name)
	}
	return true
}

func (m *policyManager) pruneForceRulesetsLocked() {
	if len(m.forceRulesets) == 0 {
		return
	}
	for name := range m.forceRulesets {
		if findRuleset(m.opts.Rulesets, name) < 0 {
			delete(m.forceRulesets, name)
		}
	}
}

func (m *policyManager) reconcileAttached(manager *egressManager, logChange bool) (bool, error) {
	if manager == nil {
		return m.reconcile(nil, logChange)
	}
	attached := manager.attachedIndexSnapshot()
	if len(attached) == 0 {
		return m.reconcile(nil, logChange)
	}
	all, err := listInterfaces()
	if err != nil {
		return false, fmt.Errorf("list interfaces: %w", err)
	}
	current := make([]interfaceInfo, 0, len(attached))
	for _, iface := range all {
		if attached[iface.Index] {
			current = append(current, iface)
		}
	}
	return m.reconcile(current, logChange)
}

func (m *policyManager) reconcile(all []interfaceInfo, logChange bool) (bool, error) {
	opts := m.optionsSnapshot()
	tmpRulesets := m.temporaryRulesetsSnapshot()
	forceRulesets := m.forceRulesetsSnapshot()
	socksProxy := m.socksProxyStateSnapshot()
	selected, err := selectInterfaces(all, opts)
	if err != nil {
		return false, err
	}
	next := effectivePoliciesForInterfaces(selected, opts, tmpRulesets, forceRulesets, socksProxy)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.set && interfacePolicyRulesEqual(m.current, next) {
		m.current = cloneInterfacePolicyMap(next)
		return false, nil
	}

	if err := writeEffectivePolicies(m.objs, m.current, next); err != nil {
		return false, err
	}
	m.current = cloneInterfacePolicyMap(next)
	m.set = true
	if logChange {
		logPolicies(next)
	}
	return true, nil
}

func (m *policyManager) configSnapshot() adminapi.CurrentConfig {
	m.mu.Lock()
	current := cloneInterfacePolicyMap(m.current)
	set := m.set
	opts := cloneOptions(m.opts)
	socksProxy := m.socksProxy
	tmpRulesets := cloneTemporaryRulesets(m.tmpRulesets)
	forceRulesets := cloneForceRulesets(m.forceRulesets)
	m.mu.Unlock()

	if !set {
		current = nil
	}
	return adminapi.CurrentConfig{
		InterfaceTypes:          cloneStrings(opts.InterfaceTypes),
		InterfaceNames:          cloneStrings(opts.InterfaceNames),
		InterfaceRegexps:        cloneStrings(opts.InterfaceRegexps),
		IgnoredInterfaceTypes:   cloneStrings(opts.IgnoredInterfaceTypes),
		IgnoredInterfaceNames:   cloneStrings(opts.IgnoredInterfaceNames),
		IgnoredInterfaceRegexps: cloneStrings(opts.IgnoredInterfaceRegexps),
		BasePolicy:              apiAllowRules(opts.allowRules),
		EffectivePolicy:         apiAllowRules(firstEffectivePolicy(current, opts.allowRules)),
		ActiveRuleset:           firstActiveRuleset(current),
		EffectiveInterfaces:     apiInterfacePolicies(current),
		Rulesets:                apiRulesets(opts.Rulesets, activeRulesetSet(current)),
		ForceActiveRulesets:     apiForceRulesets(forceRulesets),
		TemporaryRulesets:       apiTemporaryRulesets(tmpRulesets),
		SocksProxy:              apiSocksProxyState(socksProxy),
		AdminAPI: adminapi.AdminConfig{
			SocketPath: opts.AdminAPI.SocketPath,
			Debug:      opts.AdminAPI.Debug,
		},
	}
}

func currentConfigSnapshot(policies *policyManager, manager *egressManager, clients func() []adminapi.ClientInfo, notifyError func(string, error)) adminapi.CurrentConfig {
	cfg := policies.configSnapshot()
	opts := policies.optionsSnapshot()
	all, err := listInterfaces()
	if err != nil {
		log.Printf("ERROR: list interfaces for admin API snapshot: %s", err)
		if notifyError != nil {
			notifyError("Admin API snapshot error", err)
		}
	} else {
		cfg.Interfaces = apiInterfaces(all, opts, manager, notifyError)
	}
	if clients != nil {
		cfg.Clients = clients()
	}
	return cfg
}

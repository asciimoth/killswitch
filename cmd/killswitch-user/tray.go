package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/energye/systray"
)

//go:embed embed/tray.png
var trayIcon []byte

type trayCommandKind int

const (
	trayCommandSetAllowAll trayCommandKind = iota + 1
	trayCommandForceRuleset
	trayCommandSetSocksProxy
	trayCommandOpenCaptivePortal
)

type trayCommand struct {
	Kind       trayCommandKind
	AllowAll   bool
	SocksProxy bool
	Ruleset    string
	Force      bool
	Interfaces []string
}

func applyTrayCommand(client *adminapi.Client, cmd trayCommand) error {
	switch cmd.Kind {
	case trayCommandSetAllowAll:
		value := "false"
		if cmd.AllowAll {
			value = "true"
		}
		return client.Send(adminapi.MutationRequest{
			Operation: adminapi.MutationSet,
			Target:    "base_policy.allow_all",
			Value:     json.RawMessage(value),
		})
	case trayCommandForceRuleset:
		op := adminapi.MutationRemove
		if cmd.Force {
			op = adminapi.MutationSet
		}
		return client.Send(adminapi.MutationRequest{
			Operation:  op,
			Target:     "force_ruleset",
			Ruleset:    cmd.Ruleset,
			Interfaces: cmd.Interfaces,
		})
	case trayCommandSetSocksProxy:
		value := "false"
		if cmd.SocksProxy {
			value = "true"
		}
		return client.Send(adminapi.MutationRequest{
			Operation: adminapi.MutationSet,
			Target:    "socks_proxy",
			Value:     json.RawMessage(value),
		})
	case trayCommandOpenCaptivePortal:
		return nil
	default:
		return fmt.Errorf("unknown tray command kind %d", cmd.Kind)
	}
}

type noopTray struct{}

func (noopTray) Start(context.Context, chan<- trayCommand) {}
func (noopTray) Update(adminapi.CurrentConfig)             {}
func (noopTray) UpdateNetwork(networkTrayState)            {}
func (noopTray) Close()                                    {}

type trayState struct {
	AllowAll          bool
	SocksProxyEnabled bool
	SocksProxyRunning bool
	Network           networkTrayState
	Interfaces        []trayInterfaceState
}

type networkTrayState struct {
	Enabled       bool
	Checking      bool
	Status        networkCheckStatus
	PortalURL     string
	OpenLoginPage bool
}

type trayInterfaceState struct {
	Name     string
	Rulesets []trayRulesetState
}

type trayRulesetState struct {
	Name     string
	Forced   bool
	Disabled bool
}

func trayStateFromConfig(cfg adminapi.CurrentConfig) trayState {
	attached := attachedInterfaceNames(cfg)
	forced := forcedRulesetsByInterface(cfg, attached)
	baseRulesets := make([]trayRulesetState, 0, len(cfg.Rulesets))
	for _, ruleset := range cfg.Rulesets {
		baseRulesets = append(baseRulesets, trayRulesetState{
			Name:     ruleset.Name,
			Disabled: ruleset.Disabled,
		})
	}
	sort.Slice(baseRulesets, func(i, j int) bool {
		return baseRulesets[i].Name < baseRulesets[j].Name
	})
	interfaces := make([]trayInterfaceState, 0, len(attached))
	for _, iface := range attached {
		rulesets := make([]trayRulesetState, len(baseRulesets))
		copy(rulesets, baseRulesets)
		for i := range rulesets {
			rulesets[i].Forced = forced[iface][rulesets[i].Name]
		}
		interfaces = append(interfaces, trayInterfaceState{
			Name:     iface,
			Rulesets: rulesets,
		})
	}
	return trayState{
		AllowAll:          cfg.BasePolicy.AllowAll,
		SocksProxyEnabled: cfg.SocksProxy.Enabled,
		SocksProxyRunning: cfg.SocksProxy.Running,
		Interfaces:        interfaces,
	}
}

func attachedInterfaceNames(cfg adminapi.CurrentConfig) []string {
	set := make(map[string]bool)
	for _, iface := range cfg.EffectiveInterfaces {
		if iface.Attached {
			set[iface.Name] = true
		}
	}
	if len(set) == 0 {
		for _, iface := range cfg.Interfaces {
			if iface.Killswitch {
				set[iface.Name] = true
			}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func forcedRulesetsByInterface(cfg adminapi.CurrentConfig, attached []string) map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(attached))
	for _, name := range attached {
		out[name] = make(map[string]bool)
	}

	usedEffectiveInterfaces := false
	for _, iface := range cfg.EffectiveInterfaces {
		if !iface.Attached {
			continue
		}
		usedEffectiveInterfaces = true
		for _, ruleset := range iface.ForcedRulesets {
			if out[iface.Name] == nil {
				out[iface.Name] = make(map[string]bool)
			}
			out[iface.Name][ruleset] = true
		}
	}
	if usedEffectiveInterfaces {
		return out
	}

	for _, ruleset := range cfg.ForceActiveRulesets {
		if len(ruleset.Interfaces) == 0 {
			for _, iface := range attached {
				out[iface][ruleset.Name] = true
			}
			continue
		}
		for _, iface := range ruleset.Interfaces {
			if out[iface] == nil {
				out[iface] = make(map[string]bool)
			}
			out[iface][ruleset.Name] = true
		}
	}
	return out
}

type systemTray struct {
	mu          sync.Mutex
	commands    chan<- trayCommand
	started     bool
	ready       bool
	last        *trayState
	menuBuilt   bool
	allowAll    *systray.MenuItem
	socksProxy  *systray.MenuItem
	network     *systray.MenuItem
	openLogin   *systray.MenuItem
	noIface     *systray.MenuItem
	ifaceMenu   map[string]*systray.MenuItem
	rulesetMenu map[string]map[string]*systray.MenuItem
}

func newSystemTray() *systemTray {
	return &systemTray{
		ifaceMenu:   make(map[string]*systray.MenuItem),
		rulesetMenu: make(map[string]map[string]*systray.MenuItem),
	}
}

func (t *systemTray) Start(ctx context.Context, commands chan<- trayCommand) {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return
	}
	t.started = true
	t.commands = commands
	t.mu.Unlock()

	go systray.Run(t.onReady, func() {})
	go func() {
		<-ctx.Done()
		t.Close()
	}()
}

func (t *systemTray) onReady() {
	systray.SetIcon(trayIcon)
	systray.SetTitle("KS")
	systray.SetTooltip("Killswitch")

	t.mu.Lock()
	t.ready = true
	last := t.last
	t.mu.Unlock()

	if last != nil {
		t.apply(*last)
	} else {
		t.apply(trayState{})
	}
}

func (t *systemTray) send(cmd trayCommand) {
	t.mu.Lock()
	commands := t.commands
	t.mu.Unlock()
	select {
	case commands <- cmd:
	default:
		log.Printf("drop tray command: command queue is full")
	}
}

func (t *systemTray) Update(cfg adminapi.CurrentConfig) {
	state := trayStateFromConfig(cfg)

	t.mu.Lock()
	if t.last != nil {
		state.Network = t.last.Network
	}
	if t.last != nil && trayStatesEqual(*t.last, state) {
		t.mu.Unlock()
		return
	}
	t.last = &state
	if !t.ready {
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()

	t.apply(state)
}

func (t *systemTray) UpdateNetwork(network networkTrayState) {
	t.mu.Lock()
	state := trayState{Network: network}
	if t.last != nil {
		state = *t.last
		state.Network = network
	}
	if t.last != nil && trayStatesEqual(*t.last, state) {
		t.mu.Unlock()
		return
	}
	t.last = &state
	if !t.ready {
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()

	t.apply(state)
}

func (t *systemTray) apply(state trayState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ready {
		return
	}

	if !t.menuBuilt {
		t.buildBaseMenu(state)
	}

	setMenuChecked(t.allowAll, state.AllowAll)
	setMenuChecked(t.socksProxy, state.SocksProxyEnabled)
	t.socksProxy.SetTitle(socksProxyTrayTitle(state))
	t.network.SetTitle(networkTrayTitle(state.Network))
	t.network.SetTooltip(networkTrayTooltip(state.Network))
	if state.Network.Enabled {
		t.network.Show()
	} else {
		t.network.Hide()
	}
	if state.Network.OpenLoginPage {
		t.openLogin.Show()
	} else {
		t.openLogin.Hide()
	}

	nextIfaces := make(map[string]bool, len(state.Interfaces))
	for _, iface := range state.Interfaces {
		nextIfaces[iface.Name] = true
	}
	for name, item := range t.ifaceMenu {
		if !nextIfaces[name] {
			item.Hide()
		}
	}

	if len(state.Interfaces) == 0 {
		t.noIface.Show()
		return
	}
	t.noIface.Hide()

	for _, iface := range state.Interfaces {
		t.applyInterface(iface)
	}
	t.allowAll.SetTitle("Allow all")
}

func (t *systemTray) buildBaseMenu(state trayState) {
	t.menuBuilt = true

	t.allowAll = systray.AddMenuItemCheckbox("Allow all", "Toggle global allow_all", state.AllowAll)
	t.allowAll.Click(func() {
		t.mu.Lock()
		allowAll := t.last == nil || !t.last.AllowAll
		t.mu.Unlock()
		t.send(trayCommand{Kind: trayCommandSetAllowAll, AllowAll: allowAll})
	})

	t.socksProxy = systray.AddMenuItemCheckbox(socksProxyTrayTitle(state), "Toggle localhost SOCKS proxy", state.SocksProxyEnabled)
	t.socksProxy.Click(func() {
		t.mu.Lock()
		enabled := t.last == nil || !t.last.SocksProxyEnabled
		t.mu.Unlock()
		t.send(trayCommand{Kind: trayCommandSetSocksProxy, SocksProxy: enabled})
	})

	t.network = systray.AddMenuItem(networkTrayTitle(state.Network), networkTrayTooltip(state.Network))
	t.network.Disable()
	if !state.Network.Enabled {
		t.network.Hide()
	}

	t.openLogin = systray.AddMenuItem("Open login page", "Open captive portal login page")
	t.openLogin.Click(func() {
		t.mu.Lock()
		open := t.last != nil && t.last.Network.OpenLoginPage
		t.mu.Unlock()
		if open {
			t.send(trayCommand{Kind: trayCommandOpenCaptivePortal})
		}
	})
	if !state.Network.OpenLoginPage {
		t.openLogin.Hide()
	}

	systray.AddSeparator()
	t.noIface = systray.AddMenuItem("No interfaces", "No killswitch-attached interfaces")
	t.noIface.Disable()
}

func (t *systemTray) applyInterface(iface trayInterfaceState) {
	ifaceItem := t.ifaceMenu[iface.Name]
	if ifaceItem == nil {
		ifaceItem = systray.AddMenuItem(iface.Name, iface.Name)
		t.ifaceMenu[iface.Name] = ifaceItem
	}
	ifaceItem.Show()
	ifaceItem.SetTitle(iface.Name)

	rulesetItems := t.rulesetMenu[iface.Name]
	if rulesetItems == nil {
		rulesetItems = make(map[string]*systray.MenuItem, len(iface.Rulesets))
		t.rulesetMenu[iface.Name] = rulesetItems
	}

	nextRulesets := make(map[string]bool, len(iface.Rulesets))
	for _, ruleset := range iface.Rulesets {
		nextRulesets[ruleset.Name] = true
	}
	for name, item := range rulesetItems {
		if !nextRulesets[name] {
			item.Hide()
		}
	}

	for _, ruleset := range iface.Rulesets {
		item := rulesetItems[ruleset.Name]
		if item == nil {
			item = t.addRulesetMenuItem(iface.Name, ifaceItem, ruleset)
			rulesetItems[ruleset.Name] = item
		}
		item.Show()
		item.SetTitle(rulesetTrayTitle(ruleset))
		setMenuChecked(item, ruleset.Forced)
	}
	ifaceItem.SetTitle(iface.Name)
}

func (t *systemTray) addRulesetMenuItem(ifaceName string, ifaceItem *systray.MenuItem, ruleset trayRulesetState) *systray.MenuItem {
	rulesetName := ruleset.Name
	item := ifaceItem.AddSubMenuItemCheckbox(rulesetTrayTitle(ruleset), "Force-activate "+rulesetName+" on "+ifaceName, ruleset.Forced)
	item.Click(func() {
		t.mu.Lock()
		last := t.last
		force := true
		if last != nil {
			force = !rulesetForcedInState(*last, ifaceName, rulesetName)
		}
		t.mu.Unlock()
		t.send(trayCommand{
			Kind:       trayCommandForceRuleset,
			Ruleset:    rulesetName,
			Force:      force,
			Interfaces: []string{ifaceName},
		})
	})
	return item
}

func (t *systemTray) Close() {
	t.mu.Lock()
	started := t.started
	t.started = false
	t.mu.Unlock()
	if started {
		systray.Quit()
	}
}

func setMenuChecked(item *systray.MenuItem, checked bool) {
	if checked {
		item.Check()
	} else {
		item.Uncheck()
	}
}

func rulesetTrayTitle(ruleset trayRulesetState) string {
	if ruleset.Disabled {
		return ruleset.Name + " (disabled)"
	}
	return ruleset.Name
}

func socksProxyTrayTitle(state trayState) string {
	if state.SocksProxyEnabled && !state.SocksProxyRunning {
		return "SOCKS proxy (not running)"
	}
	return "SOCKS proxy"
}

func networkTrayTitle(state networkTrayState) string {
	return "Connectivity: " + networkTrayStatusText(state)
}

func networkTrayTooltip(state networkTrayState) string {
	if !state.Enabled {
		return "Network connectivity check is disabled"
	}
	if state.PortalURL != "" {
		return "Captive portal: " + state.PortalURL
	}
	return networkTrayTitle(state)
}

func networkTrayStatusText(state networkTrayState) string {
	if !state.Enabled {
		return "disabled"
	}
	if state.Checking {
		return "checking"
	}
	if state.Status == "" {
		return "unknown"
	}
	return string(state.Status)
}

func trayStatesEqual(a, b trayState) bool {
	return a.AllowAll == b.AllowAll &&
		a.SocksProxyEnabled == b.SocksProxyEnabled &&
		a.SocksProxyRunning == b.SocksProxyRunning &&
		a.Network == b.Network &&
		trayInterfaceStatesEqual(a.Interfaces, b.Interfaces)
}

func trayInterfaceStatesEqual(a, b []trayInterfaceState) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || !trayRulesetStatesEqual(a[i].Rulesets, b[i].Rulesets) {
			return false
		}
	}
	return true
}

func trayRulesetStatesEqual(a, b []trayRulesetState) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func rulesetForcedInState(state trayState, ifaceName, rulesetName string) bool {
	for _, iface := range state.Interfaces {
		if iface.Name != ifaceName {
			continue
		}
		for _, ruleset := range iface.Rulesets {
			if ruleset.Name == rulesetName {
				return ruleset.Forced
			}
		}
	}
	return false
}

// Package main provides killswitch-user, the graphical-session companion daemon
// for killswitch desktop integration such as user-visible notifications.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/energye/systray"
	dbusnotify "github.com/esiqveland/notify"
	"github.com/godbus/dbus/v5"
)

const defaultConfigFileName = "killswitch-user.json"
const allowAllNotificationActionDisable = "disable-allow-all"

type configFile struct {
	SocketPath             string `json:"socket_path,omitempty"`
	NotifyInterfaceChanges *bool  `json:"notify_interface_changes,omitempty"`
	NotifyGlobalAllowAll   *bool  `json:"notify_global_allow_all,omitempty"`
	TrayEnabled            *bool  `json:"tray_enabled,omitempty"`
}

type options struct {
	ConfigPath             string
	SocketPath             string
	NotifyInterfaceChanges bool
	NotifyGlobalAllowAll   bool
	TrayEnabled            bool
}

type envLookup func(string) string

type notifier interface {
	Notify(adminapi.Notification) error
	NotifyGlobalAllowAll(func()) error
	CloseGlobalAllowAll() error
	Close() error
}

type trayController interface {
	Start(context.Context, chan<- trayCommand)
	Update(adminapi.CurrentConfig)
	Close()
}

type desktopNotifier struct {
	mu                  sync.Mutex
	dbusNotifier        dbusnotify.Notifier
	dbusConn            *dbus.Conn
	allowAllID          uint32
	allowAllDisableFunc func()
}

func main() {
	configPath, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	opts, err := loadOptions(configPath, os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, opts, newDesktopNotifier()); err != nil {
		log.Fatal(err)
	}
}

func parseArgs(args []string) (string, error) {
	flags := flag.NewFlagSet("killswitch-user", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	configPath := flags.String("config", "", "config path")
	flags.StringVar(configPath, "c", "", "config path")

	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() > 1 {
		return "", fmt.Errorf("expected at most one config path argument, got: %s", strings.Join(flags.Args(), " "))
	}
	if *configPath != "" && flags.NArg() == 1 {
		return "", errors.New("config path must be provided either with -config or as a positional argument, not both")
	}
	if *configPath != "" {
		return *configPath, nil
	}
	if flags.NArg() == 1 {
		return flags.Arg(0), nil
	}
	return "", nil
}

func loadOptions(configPath string, getenv envLookup) (options, error) {
	if configPath == "" {
		configPath = defaultConfigPath(getenv)
	}
	if configPath == "" {
		return options{}, errors.New("resolve default config path: USER or HOME is required when XDG_CONFIG_HOME is unset")
	}

	if err := ensureConfigFile(configPath); err != nil {
		return options{}, err
	}
	if err := validateConfigFile(configPath); err != nil {
		return options{}, err
	}

	cfg, err := readConfigFile(configPath)
	if err != nil {
		return options{}, err
	}

	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = adminapi.DefaultSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return options{}, fmt.Errorf("socket_path must be absolute, got %q", socketPath)
	}

	return options{
		ConfigPath:             configPath,
		SocketPath:             socketPath,
		NotifyInterfaceChanges: boolConfigValue(cfg.NotifyInterfaceChanges, true),
		NotifyGlobalAllowAll:   boolConfigValue(cfg.NotifyGlobalAllowAll, true),
		TrayEnabled:            boolConfigValue(cfg.TrayEnabled, true),
	}, nil
}

func boolConfigValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func defaultConfigPath(getenv envLookup) string {
	if xdgConfigHome := getenv("XDG_CONFIG_HOME"); xdgConfigHome != "" {
		return filepath.Join(xdgConfigHome, "killswitch", defaultConfigFileName)
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "killswitch", defaultConfigFileName)
	}
	if username := getenv("USER"); username != "" {
		return filepath.Join("/home", username, ".config", "killswitch", defaultConfigFileName)
	}
	return ""
}

func ensureConfigFile(configPath string) error {
	if _, err := os.Stat(configPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat config %q: %w", configPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("create config directory %q: %w", filepath.Dir(configPath), err)
	}

	data, err := json.MarshalIndent(defaultConfig(), "", "  ")
	if err != nil {
		return fmt.Errorf("encode default config: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return fmt.Errorf("create default config %q: %w", configPath, err)
	}
	return nil
}

func defaultConfig() configFile {
	enabled := true
	return configFile{
		SocketPath:             adminapi.DefaultSocketPath,
		NotifyInterfaceChanges: &enabled,
		NotifyGlobalAllowAll:   &enabled,
		TrayEnabled:            &enabled,
	}
}

func validateConfigFile(configPath string) error {
	info, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("stat config %q: %w", configPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("config %q is a directory", configPath)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config %q must not be group- or world-writable", configPath)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("stat config %q: unsupported stat type %T", configPath, info.Sys())
	}
	uid := stat.Uid
	if uid != 0 && uid != uint32(os.Geteuid()) {
		return fmt.Errorf("config %q must be owned by current user or root, got uid %d", configPath, uid)
	}
	return nil
}

func readConfigFile(configPath string) (configFile, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return configFile{}, fmt.Errorf("open config %q: %w", configPath, err)
	}
	defer file.Close() //nolint:errcheck

	var cfg configFile
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return configFile{}, fmt.Errorf("decode config %q: %w", configPath, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return configFile{}, fmt.Errorf("decode config %q: multiple JSON values", configPath)
	}
	return cfg, nil
}

func run(ctx context.Context, opts options, notifications notifier) error {
	client, err := adminapi.DialUnix(ctx, opts.SocketPath)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck

	return runClient(ctx, client, notifications, opts)
}

func runClient(ctx context.Context, client *adminapi.Client, notifications notifier, opts options) error {
	defer func() {
		if err := notifications.Close(); err != nil {
			log.Printf("close desktop notifier: %s", err)
		}
	}()

	if err := client.Subscribe(
		adminapi.EventTypeConfig,
		adminapi.EventTypeInterfaces,
		adminapi.EventTypeClients,
		adminapi.EventTypeNotification,
	); err != nil {
		return err
	}
	if err := client.RequestConfig(); err != nil {
		return err
	}

	trayCommands := make(chan trayCommand, 8)
	tray := trayController(noopTray{})
	if opts.TrayEnabled {
		tray = newSystemTray()
		tray.Start(ctx, trayCommands)
		defer tray.Close()
	}

	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-ctxDone:
		}
	}()
	defer close(ctxDone)

	disableAllowAll := make(chan struct{}, 1)
	cfg, err := client.WaitForConfig()
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	watcher := configNotificationWatcher{
		notifyInterfaceChanges: opts.NotifyInterfaceChanges,
		notifyGlobalAllowAll:   opts.NotifyGlobalAllowAll,
		disableAllowAll:        disableAllowAll,
	}
	watcher.applyInitial(cfg)
	watcher.updateGlobalAllowAll(notifications, cfg)
	tray.Update(cfg)

	events := make(chan adminapi.EventMessage, 1)
	mutationResults := make(chan adminapi.MutationResult, 1)
	errs := make(chan error, 1)
	go func() {
		for {
			msg, err := client.Receive()
			if err != nil {
				errs <- err
				return
			}
			switch msg := msg.(type) {
			case adminapi.EventMessage:
				events <- msg
			case adminapi.MutationResult:
				mutationResults <- msg
			}
		}
	}()

	for {
		select {
		case <-disableAllowAll:
			if err := disableGlobalAllowAll(client); err != nil {
				log.Printf("disable global allow_all: %s", err)
			}
		case cmd := <-trayCommands:
			if err := applyTrayCommand(client, cmd); err != nil {
				log.Printf("apply tray command: %s", err)
			}
		case result := <-mutationResults:
			if !result.OK {
				log.Printf("tray mutation failed: %s", result.Error)
				continue
			}
			watcher.update(notifications, result.Config)
			tray.Update(result.Config)
		case err := <-errs:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case event := <-events:
			switch event.EventType {
			case adminapi.EventTypeNotification:
				if err := notifications.Notify(event.Notification); err != nil {
					log.Printf("send desktop notification: %s", err)
				}
			case adminapi.EventTypeConfig:
				watcher.update(notifications, event.Config)
				tray.Update(event.Config)
			case adminapi.EventTypeInterfaces, adminapi.EventTypeClients:
				tray.Update(event.Config)
			default:
				continue
			}
		}
	}
}

func disableGlobalAllowAll(client *adminapi.Client) error {
	return client.Send(adminapi.MutationRequest{
		Operation: adminapi.MutationSet,
		Target:    "base_policy.allow_all",
		Value:     json.RawMessage("false"),
	})
}

type trayCommandKind int

const (
	trayCommandSetAllowAll trayCommandKind = iota + 1
	trayCommandForceRuleset
	trayCommandSetSocksProxy
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
	default:
		return fmt.Errorf("unknown tray command kind %d", cmd.Kind)
	}
}

type configNotificationWatcher struct {
	notifyInterfaceChanges bool
	notifyGlobalAllowAll   bool
	disableAllowAll        chan<- struct{}
	lastInterfaces         map[string]adminapi.Interface
	allowAllShown          bool
}

func (w *configNotificationWatcher) applyInitial(cfg adminapi.CurrentConfig) {
	w.lastInterfaces = attachedInterfaceMap(cfg)
}

func (w *configNotificationWatcher) update(notifications notifier, cfg adminapi.CurrentConfig) {
	if w.notifyInterfaceChanges {
		w.updateInterfaces(notifications, cfg)
	} else {
		w.lastInterfaces = attachedInterfaceMap(cfg)
	}
	w.updateGlobalAllowAll(notifications, cfg)
}

func (w *configNotificationWatcher) updateInterfaces(notifications notifier, cfg adminapi.CurrentConfig) {
	next := attachedInterfaceMap(cfg)
	if w.lastInterfaces == nil {
		w.lastInterfaces = next
		return
	}

	for _, iface := range appearedInterfaces(w.lastInterfaces, next) {
		if err := notifications.Notify(adminapi.Notification{
			Level:  adminapi.NotificationLevelNormal,
			Header: "Interface appeared",
			Text:   interfaceDescription(iface),
		}); err != nil {
			log.Printf("send interface appeared notification: %s", err)
		}
	}
	for _, iface := range disappearedInterfaces(w.lastInterfaces, next) {
		if err := notifications.Notify(adminapi.Notification{
			Level:  adminapi.NotificationLevelWarn,
			Header: "Interface disappeared",
			Text:   interfaceDescription(iface),
		}); err != nil {
			log.Printf("send interface disappeared notification: %s", err)
		}
	}

	w.lastInterfaces = next
}

func attachedInterfaceMap(cfg adminapi.CurrentConfig) map[string]adminapi.Interface {
	out := make(map[string]adminapi.Interface)
	for _, iface := range cfg.EffectiveInterfaces {
		if !iface.Attached {
			continue
		}
		out[iface.Name] = adminapi.Interface{
			Index:       iface.Index,
			Name:        iface.Name,
			Type:        iface.Type,
			SSID:        iface.SSID,
			BSSID:       iface.BSSID,
			GatewayMACs: cloneStrings(iface.GatewayMACs),
			Matched:     iface.Matched,
			Killswitch:  iface.Attached,
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, iface := range cfg.Interfaces {
		if iface.Killswitch {
			out[iface.Name] = iface
		}
	}
	return out
}

func (w *configNotificationWatcher) updateGlobalAllowAll(notifications notifier, cfg adminapi.CurrentConfig) {
	if !w.notifyGlobalAllowAll {
		w.allowAllShown = cfg.BasePolicy.AllowAll
		return
	}
	if cfg.BasePolicy.AllowAll {
		if w.allowAllShown {
			return
		}
		w.allowAllShown = true
		if err := notifications.NotifyGlobalAllowAll(func() {
			select {
			case w.disableAllowAll <- struct{}{}:
			default:
			}
		}); err != nil {
			log.Printf("send global allow_all notification: %s", err)
		}
		return
	}
	if w.allowAllShown {
		if err := notifications.CloseGlobalAllowAll(); err != nil {
			log.Printf("close global allow_all notification: %s", err)
		}
	}
	w.allowAllShown = false
}

func appearedInterfaces(old, next map[string]adminapi.Interface) []adminapi.Interface {
	return interfaceDiff(next, old)
}

func disappearedInterfaces(old, next map[string]adminapi.Interface) []adminapi.Interface {
	return interfaceDiff(old, next)
}

func interfaceDiff(a, b map[string]adminapi.Interface) []adminapi.Interface {
	names := make([]string, 0)
	for name := range a {
		if _, ok := b[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]adminapi.Interface, 0, len(names))
	for _, name := range names {
		out = append(out, a[name])
	}
	return out
}

func interfaceDescription(iface adminapi.Interface) string {
	if iface.Type == "" {
		return iface.Name
	}
	return fmt.Sprintf("%s (%s)", iface.Name, iface.Type)
}

type noopTray struct{}

func (noopTray) Start(context.Context, chan<- trayCommand) {}
func (noopTray) Update(adminapi.CurrentConfig)             {}
func (noopTray) Close()                                    {}

type trayState struct {
	AllowAll          bool
	SocksProxyEnabled bool
	SocksProxyRunning bool
	Interfaces        []trayInterfaceState
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

func trayStatesEqual(a, b trayState) bool {
	return a.AllowAll == b.AllowAll &&
		a.SocksProxyEnabled == b.SocksProxyEnabled &&
		a.SocksProxyRunning == b.SocksProxyRunning &&
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

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func newDesktopNotifier() *desktopNotifier {
	return &desktopNotifier{}
}

func (n *desktopNotifier) Notify(notification adminapi.Notification) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.dbusNotifier == nil {
		if err := n.openDBusNotifierLocked(); err != nil {
			return err
		}
	}

	note := dbusnotify.Notification{
		AppName:       "Killswitch",
		Summary:       notificationTitle(notification),
		Body:          notification.Text,
		ExpireTimeout: dbusnotify.ExpireTimeoutSetByNotificationServer,
	}
	note.SetUrgency(notificationUrgency(notification))

	_, err := n.dbusNotifier.SendNotification(note)
	return err
}

func (n *desktopNotifier) NotifyGlobalAllowAll(disable func()) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.allowAllDisableFunc = disable
	if n.dbusNotifier == nil {
		if err := n.openDBusNotifierLocked(); err != nil {
			return err
		}
	}

	note := dbusnotify.Notification{
		AppName:    "Killswitch",
		ReplacesID: n.allowAllID,
		Summary:    "Killswitch: global allow all enabled",
		Body:       "Global allow_all is enabled outside of rulesets and applies to all interfaces.",
		Actions: []dbusnotify.Action{
			{Key: allowAllNotificationActionDisable, Label: "Disable allow all"},
		},
		ExpireTimeout: dbusnotify.ExpireTimeoutNever,
	}
	note.SetUrgency(dbusnotify.UrgencyCritical)

	id, err := n.dbusNotifier.SendNotification(note)
	if err != nil {
		return err
	}
	n.allowAllID = id
	return nil
}

func (n *desktopNotifier) openDBusNotifierLocked() error {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return err
	}
	if err := conn.Auth(nil); err != nil {
		conn.Close() //nolint:errcheck
		return err
	}
	if err := conn.Hello(); err != nil {
		conn.Close() //nolint:errcheck
		return err
	}

	notifier, err := dbusnotify.New(conn, dbusnotify.WithOnAction(func(action *dbusnotify.ActionInvokedSignal) {
		if action.ActionKey != allowAllNotificationActionDisable {
			return
		}
		n.mu.Lock()
		if n.allowAllID != 0 && action.ID != n.allowAllID {
			n.mu.Unlock()
			return
		}
		disable := n.allowAllDisableFunc
		n.mu.Unlock()
		if disable != nil {
			disable()
		}
	}))
	if err != nil {
		conn.Close() //nolint:errcheck
		return err
	}

	n.dbusConn = conn
	n.dbusNotifier = notifier
	return nil
}

func (n *desktopNotifier) CloseGlobalAllowAll() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dbusNotifier == nil || n.allowAllID == 0 {
		return nil
	}
	_, err := n.dbusNotifier.CloseNotification(n.allowAllID)
	n.allowAllID = 0
	return err
}

func (n *desktopNotifier) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var errs []error
	if n.dbusNotifier != nil {
		if n.allowAllID != 0 {
			if _, err := n.dbusNotifier.CloseNotification(n.allowAllID); err != nil {
				errs = append(errs, err)
			}
			n.allowAllID = 0
		}
		if err := n.dbusNotifier.Close(); err != nil {
			errs = append(errs, err)
		}
		n.dbusNotifier = nil
	}
	if n.dbusConn != nil {
		if err := n.dbusConn.Close(); err != nil {
			errs = append(errs, err)
		}
		n.dbusConn = nil
	}
	return errors.Join(errs...)
}

func notificationTitle(notification adminapi.Notification) string {
	if notification.Header != "" {
		return "Killswitch: " + notification.Header
	}
	switch notification.Level {
	case adminapi.NotificationLevelWarn:
		return "Killswitch warning"
	case adminapi.NotificationLevelError:
		return "Killswitch error"
	default:
		return "Killswitch"
	}
}

func notificationUrgency(notification adminapi.Notification) dbusnotify.Urgency {
	switch notification.Level {
	case adminapi.NotificationLevelWarn, adminapi.NotificationLevelError:
		return dbusnotify.UrgencyCritical
	default:
		return dbusnotify.UrgencyNormal
	}
}

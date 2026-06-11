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
	dbusnotify "github.com/esiqveland/notify"
	"github.com/gen2brain/beeep"
	"github.com/godbus/dbus/v5"
)

const defaultConfigFileName = "killswitch-user.json"
const allowAllNotificationActionDisable = "disable-allow-all"

type configFile struct {
	SocketPath             string `json:"socket_path,omitempty"`
	NotifyInterfaceChanges *bool  `json:"notify_interface_changes,omitempty"`
	NotifyGlobalAllowAll   *bool  `json:"notify_global_allow_all,omitempty"`
}

type options struct {
	ConfigPath             string
	SocketPath             string
	NotifyInterfaceChanges bool
	NotifyGlobalAllowAll   bool
}

type envLookup func(string) string

type notifier interface {
	Notify(adminapi.Notification) error
	NotifyGlobalAllowAll(func()) error
	CloseGlobalAllowAll() error
	Close() error
}

type desktopNotifier struct {
	mu                  sync.Mutex
	allowAllNotifier    dbusnotify.Notifier
	allowAllConn        *dbus.Conn
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

	events := make(chan adminapi.EventMessage, 1)
	errs := make(chan error, 1)
	go func() {
		for {
			event, err := client.WaitForEvent()
			if err != nil {
				errs <- err
				return
			}
			events <- event
		}
	}()

	for {
		select {
		case <-disableAllowAll:
			if err := disableGlobalAllowAll(client); err != nil {
				log.Printf("disable global allow_all: %s", err)
			}
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

type configNotificationWatcher struct {
	notifyInterfaceChanges bool
	notifyGlobalAllowAll   bool
	disableAllowAll        chan<- struct{}
	lastInterfaces         map[string]adminapi.Interface
	allowAllShown          bool
}

func (w *configNotificationWatcher) applyInitial(cfg adminapi.CurrentConfig) {
	w.lastInterfaces = interfaceMap(cfg.Interfaces)
}

func (w *configNotificationWatcher) update(notifications notifier, cfg adminapi.CurrentConfig) {
	if w.notifyInterfaceChanges {
		w.updateInterfaces(notifications, cfg)
	} else {
		w.lastInterfaces = interfaceMap(cfg.Interfaces)
	}
	w.updateGlobalAllowAll(notifications, cfg)
}

func (w *configNotificationWatcher) updateInterfaces(notifications notifier, cfg adminapi.CurrentConfig) {
	next := interfaceMap(cfg.Interfaces)
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

func interfaceMap(interfaces []adminapi.Interface) map[string]adminapi.Interface {
	out := make(map[string]adminapi.Interface, len(interfaces))
	for _, iface := range interfaces {
		out[iface.Name] = iface
	}
	return out
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

func newDesktopNotifier() *desktopNotifier {
	return &desktopNotifier{}
}

func (n *desktopNotifier) Notify(notification adminapi.Notification) error {
	return beeep.Notify(notificationTitle(notification), notification.Text, "")
}

func (n *desktopNotifier) NotifyGlobalAllowAll(disable func()) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.allowAllDisableFunc = disable
	if n.allowAllNotifier == nil {
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

	id, err := n.allowAllNotifier.SendNotification(note)
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

	n.allowAllConn = conn
	n.allowAllNotifier = notifier
	return nil
}

func (n *desktopNotifier) CloseGlobalAllowAll() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.allowAllNotifier == nil || n.allowAllID == 0 {
		return nil
	}
	_, err := n.allowAllNotifier.CloseNotification(n.allowAllID)
	n.allowAllID = 0
	return err
}

func (n *desktopNotifier) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var errs []error
	if n.allowAllNotifier != nil {
		if n.allowAllID != 0 {
			if _, err := n.allowAllNotifier.CloseNotification(n.allowAllID); err != nil {
				errs = append(errs, err)
			}
			n.allowAllID = 0
		}
		if err := n.allowAllNotifier.Close(); err != nil {
			errs = append(errs, err)
		}
		n.allowAllNotifier = nil
	}
	if n.allowAllConn != nil {
		if err := n.allowAllConn.Close(); err != nil {
			errs = append(errs, err)
		}
		n.allowAllConn = nil
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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "empty", want: ""},
		{name: "positional", args: []string{"/tmp/killswitch-user.json"}, want: "/tmp/killswitch-user.json"},
		{name: "config flag", args: []string{"-config", "/tmp/flag.json"}, want: "/tmp/flag.json"},
		{name: "short flag", args: []string{"-c", "/tmp/short.json"}, want: "/tmp/short.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args)
			if err != nil {
				t.Fatalf("parse args: %v", err)
			}
			if got != tt.want {
				t.Fatalf("config path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseArgsRejectsAmbiguousConfigPath(t *testing.T) {
	if _, err := parseArgs([]string{"-config", "/tmp/flag.json", "/tmp/positional.json"}); err == nil {
		t.Fatal("parse args succeeded, expected error")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "xdg",
			env:  map[string]string{"XDG_CONFIG_HOME": "/tmp/xdg", "HOME": "/home/alice", "USER": "alice"},
			want: "/tmp/xdg/killswitch/killswitch-user.json",
		},
		{
			name: "home",
			env:  map[string]string{"HOME": "/home/alice", "USER": "alice"},
			want: "/home/alice/.config/killswitch/killswitch-user.json",
		},
		{
			name: "user",
			env:  map[string]string{"USER": "alice"},
			want: "/home/alice/.config/killswitch/killswitch-user.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultConfigPath(mapEnv(tt.env))
			if got != tt.want {
				t.Fatalf("default config path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadOptionsCreatesDefaultConfig(t *testing.T) {
	xdgConfigHome := t.TempDir()

	opts, err := loadOptions("", mapEnv(map[string]string{"XDG_CONFIG_HOME": xdgConfigHome}))
	if err != nil {
		t.Fatalf("load options: %v", err)
	}

	wantPath := filepath.Join(xdgConfigHome, "killswitch", defaultConfigFileName)
	if opts.ConfigPath != wantPath {
		t.Fatalf("config path = %q, want %q", opts.ConfigPath, wantPath)
	}
	if opts.SocketPath != adminapi.DefaultSocketPath {
		t.Fatalf("socket path = %q, want %q", opts.SocketPath, adminapi.DefaultSocketPath)
	}

	info, err := os.Stat(wantPath)
	if err != nil {
		t.Fatalf("stat default config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("default config mode = %v, want 0600", info.Mode().Perm())
	}

	cfg, err := readConfigFile(wantPath)
	if err != nil {
		t.Fatalf("read default config: %v", err)
	}
	if cfg.SocketPath != adminapi.DefaultSocketPath {
		t.Fatalf("default config socket path = %q", cfg.SocketPath)
	}
	if cfg.NotifyInterfaceChanges == nil || !*cfg.NotifyInterfaceChanges {
		t.Fatalf("default config notify_interface_changes = %v", cfg.NotifyInterfaceChanges)
	}
	if cfg.NotifyGlobalAllowAll == nil || !*cfg.NotifyGlobalAllowAll {
		t.Fatalf("default config notify_global_allow_all = %v", cfg.NotifyGlobalAllowAll)
	}
	if cfg.TrayEnabled == nil || !*cfg.TrayEnabled {
		t.Fatalf("default config tray_enabled = %v", cfg.TrayEnabled)
	}
}

func TestLoadOptionsRejectsGroupWritableConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "killswitch-user.json")
	if err := os.WriteFile(configPath, []byte(`{"socket_path":"/run/killswitch/admin.sock"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(configPath, 0o620); err != nil {
		t.Fatalf("chmod config: %v", err)
	}

	if _, err := loadOptions(configPath, mapEnv(nil)); err == nil {
		t.Fatal("load options succeeded, expected insecure config error")
	}
}

func TestLoadOptionsRejectsRelativeSocketPath(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "killswitch-user.json")
	if err := os.WriteFile(configPath, []byte(`{"socket_path":"relative.sock"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := loadOptions(configPath, mapEnv(nil)); err == nil {
		t.Fatal("load options succeeded, expected relative socket path error")
	}
}

func TestLoadOptionsReadsUserIntegrationToggles(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "killswitch-user.json")
	if err := os.WriteFile(configPath, []byte(`{"socket_path":"/tmp/admin.sock","notify_interface_changes":false,"notify_global_allow_all":false,"tray_enabled":false}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	opts, err := loadOptions(configPath, mapEnv(nil))
	if err != nil {
		t.Fatalf("load options: %v", err)
	}
	if opts.NotifyInterfaceChanges {
		t.Fatal("notify interface changes enabled, want disabled")
	}
	if opts.NotifyGlobalAllowAll {
		t.Fatal("notify global allow all enabled, want disabled")
	}
	if opts.TrayEnabled {
		t.Fatal("tray enabled, want disabled")
	}
}

func TestReadConfigFileRejectsUnknownFieldsAndMultipleValues(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"socket_path":"/tmp/admin.sock","unknown":true}`},
		{name: "multiple values", data: `{"socket_path":"/tmp/admin.sock"} {}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "killswitch-user.json")
			if err := os.WriteFile(configPath, []byte(tt.data), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := readConfigFile(configPath); err == nil {
				t.Fatal("read config succeeded, expected error")
			}
		})
	}
}

func TestRunClientSubscribesAllEventsAndNotifies(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	notifications := &recordingNotifier{cancel: cancel}
	client := adminapi.NewClient(clientConn)

	serverErr := make(chan error, 1)
	go func() {
		decoder := json.NewDecoder(serverConn)
		msg, err := adminapi.ReadMessage(decoder)
		if err != nil {
			serverErr <- err
			return
		}
		subscribe, ok := msg.(adminapi.SubscribeRequest)
		if !ok {
			serverErr <- errors.New("first message was not subscribe")
			return
		}
		wantEventTypes := []adminapi.EventType{
			adminapi.EventTypeConfig,
			adminapi.EventTypeInterfaces,
			adminapi.EventTypeClients,
			adminapi.EventTypeNotification,
		}
		if !reflect.DeepEqual(subscribe.EventTypes, wantEventTypes) {
			serverErr <- errors.New("unexpected event types")
			return
		}
		msg, err = adminapi.ReadMessage(decoder)
		if err != nil {
			serverErr <- err
			return
		}
		if _, ok := msg.(adminapi.ConfigRequest); !ok {
			serverErr <- errors.New("second message was not config request")
			return
		}

		encoder := json.NewEncoder(serverConn)
		if err := adminapi.WriteMessage(encoder, adminapi.ConfigMessage{
			Config: adminapi.CurrentConfig{
				Interfaces: []adminapi.Interface{{Name: "eth0", Type: "device"}},
			},
		}); err != nil {
			serverErr <- err
			return
		}
		if err := adminapi.WriteMessage(encoder, adminapi.EventMessage{EventType: adminapi.EventTypeInterfaces}); err != nil {
			serverErr <- err
			return
		}
		if err := adminapi.WriteMessage(encoder, adminapi.EventMessage{
			EventType: adminapi.EventTypeNotification,
			Notification: adminapi.Notification{
				Level:  adminapi.NotificationLevelWarn,
				Header: "Network blocked",
				Text:   "egress policy blocked a packet",
			},
		}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	if err := runClient(ctx, client, notifications, options{NotifyInterfaceChanges: true, NotifyGlobalAllowAll: true}); err != nil {
		t.Fatalf("run client: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}

	if len(notifications.notifications) != 1 {
		t.Fatalf("notifications = %+v", notifications.notifications)
	}
	if notifications.notifications[0].Header != "Network blocked" {
		t.Fatalf("notification = %+v", notifications.notifications[0])
	}
}

func TestConfigNotificationWatcherNotifiesOnlyInterfaceAppearGone(t *testing.T) {
	notifications := &recordingNotifier{}
	watcher := configNotificationWatcher{notifyInterfaceChanges: true, notifyGlobalAllowAll: true}
	watcher.applyInitial(adminapi.CurrentConfig{
		Interfaces: []adminapi.Interface{
			{Name: "eth0", Type: "device", Matched: true, Killswitch: true},
			{Name: "lo", Type: "device"},
		},
	})

	watcher.update(notifications, adminapi.CurrentConfig{
		Interfaces: []adminapi.Interface{
			{Name: "eth0", Type: "device", Matched: false, Killswitch: true},
			{Name: "lo", Type: "loopback", Matched: true},
		},
	})
	if len(notifications.notifications) != 0 {
		t.Fatalf("metadata-only notifications = %+v", notifications.notifications)
	}

	watcher.update(notifications, adminapi.CurrentConfig{
		Interfaces: []adminapi.Interface{
			{Name: "eth0", Type: "device", Killswitch: true},
			{Name: "wg0", Type: "wireguard", Killswitch: true},
			{Name: "wlan0", Type: "device"},
		},
	})
	watcher.update(notifications, adminapi.CurrentConfig{
		Interfaces: []adminapi.Interface{
			{Name: "wg0", Type: "wireguard", Killswitch: true},
			{Name: "wlan0", Type: "device"},
		},
	})

	if len(notifications.notifications) != 2 {
		t.Fatalf("notifications = %+v", notifications.notifications)
	}
	if notifications.notifications[0].Header != "Interface appeared" || notifications.notifications[0].Text != "wg0 (wireguard)" {
		t.Fatalf("appeared notification = %+v", notifications.notifications[0])
	}
	if notifications.notifications[1].Header != "Interface disappeared" || notifications.notifications[1].Text != "eth0 (device)" {
		t.Fatalf("disappeared notification = %+v", notifications.notifications[1])
	}
}

func TestConfigNotificationWatcherUsesEffectiveInterfacesFromMutationResult(t *testing.T) {
	notifications := &recordingNotifier{}
	watcher := configNotificationWatcher{notifyInterfaceChanges: true}
	watcher.applyInitial(adminapi.CurrentConfig{
		Interfaces: []adminapi.Interface{
			{Name: "eth0", Type: "device", Killswitch: true},
			{Name: "lo", Type: "device"},
		},
		EffectiveInterfaces: []adminapi.InterfacePolicy{
			{Name: "eth0", Type: "device", Attached: true},
		},
	})

	watcher.update(notifications, adminapi.CurrentConfig{
		BasePolicy: adminapi.AllowRules{AllowAll: true},
		EffectiveInterfaces: []adminapi.InterfacePolicy{
			{Name: "eth0", Type: "device", Attached: true},
		},
	})
	watcher.update(notifications, adminapi.CurrentConfig{
		BasePolicy: adminapi.AllowRules{AllowAll: true},
		Interfaces: []adminapi.Interface{
			{Name: "eth0", Type: "device", Killswitch: true},
			{Name: "lo", Type: "device"},
			{Name: "wlan0", Type: "device"},
		},
		EffectiveInterfaces: []adminapi.InterfacePolicy{
			{Name: "eth0", Type: "device", Attached: true},
		},
	})

	if len(notifications.notifications) != 0 {
		t.Fatalf("notifications = %+v", notifications.notifications)
	}
}

func TestConfigNotificationWatcherGlobalAllowAll(t *testing.T) {
	notifications := &recordingNotifier{}
	disableAllowAll := make(chan struct{}, 1)
	watcher := configNotificationWatcher{
		notifyGlobalAllowAll: true,
		disableAllowAll:      disableAllowAll,
	}

	watcher.applyInitial(adminapi.CurrentConfig{})
	watcher.updateGlobalAllowAll(notifications, adminapi.CurrentConfig{
		BasePolicy: adminapi.AllowRules{AllowAll: true},
	})
	if notifications.globalAllowAllCount != 1 {
		t.Fatalf("global allow all notifications = %d", notifications.globalAllowAllCount)
	}

	notifications.disableGlobalAllowAll()
	select {
	case <-disableAllowAll:
	default:
		t.Fatal("disable allow_all action was not forwarded")
	}

	watcher.updateGlobalAllowAll(notifications, adminapi.CurrentConfig{
		BasePolicy: adminapi.AllowRules{AllowAll: true},
	})
	if notifications.globalAllowAllCount != 1 {
		t.Fatalf("global allow all notification repeated: %d", notifications.globalAllowAllCount)
	}

	watcher.updateGlobalAllowAll(notifications, adminapi.CurrentConfig{})
	if notifications.closeGlobalAllowAllCount != 1 {
		t.Fatalf("closed global allow all notifications = %d", notifications.closeGlobalAllowAllCount)
	}
}

func TestTrayStateFromConfig(t *testing.T) {
	cfg := adminapi.CurrentConfig{
		BasePolicy: adminapi.AllowRules{AllowAll: true},
		Interfaces: []adminapi.Interface{
			{Name: "eth0", Killswitch: true},
			{Name: "lo", Killswitch: false},
		},
		EffectiveInterfaces: []adminapi.InterfacePolicy{
			{Name: "wg0", Attached: true, ForcedRulesets: []string{"vpn"}},
			{Name: "eth0", Attached: true, ForcedRulesets: []string{"lan"}},
			{Name: "wlan0", Attached: false},
		},
		Rulesets: []adminapi.Ruleset{
			{Name: "vpn", Disabled: true},
			{Name: "lan"},
		},
		ForceActiveRulesets: []adminapi.ForceRuleset{{Name: "lan", Interfaces: []string{"eth0"}}},
	}

	got := trayStateFromConfig(cfg)
	want := trayState{
		AllowAll: true,
		Interfaces: []trayInterfaceState{
			{
				Name: "eth0",
				Rulesets: []trayRulesetState{
					{Name: "lan", Forced: true},
					{Name: "vpn", Disabled: true},
				},
			},
			{
				Name: "wg0",
				Rulesets: []trayRulesetState{
					{Name: "lan"},
					{Name: "vpn", Forced: true, Disabled: true},
				},
			},
		},
	}
	if !trayStatesEqual(got, want) {
		t.Fatalf("tray state = %+v, want %+v", got, want)
	}
}

func TestTrayStateFallsBackToInterfaceKillswitchFlag(t *testing.T) {
	got := trayStateFromConfig(adminapi.CurrentConfig{
		Interfaces: []adminapi.Interface{
			{Name: "wlan0", Killswitch: true},
			{Name: "eth0", Killswitch: true},
		},
	})
	want := []string{"eth0", "wlan0"}
	if got := trayInterfaceNames(got.Interfaces); !reflect.DeepEqual(got, want) {
		t.Fatalf("interfaces = %+v, want %+v", got, want)
	}
}

func TestTrayStatesEqualDetectsDifferences(t *testing.T) {
	base := trayState{
		AllowAll: true,
		Interfaces: []trayInterfaceState{
			{Name: "eth0", Rulesets: []trayRulesetState{{Name: "vpn", Forced: true}}},
		},
	}
	if !trayStatesEqual(base, base) {
		t.Fatal("identical tray states are not equal")
	}
	changed := base
	changed.Interfaces = []trayInterfaceState{
		{Name: "eth0", Rulesets: []trayRulesetState{{Name: "vpn"}}},
	}
	if trayStatesEqual(base, changed) {
		t.Fatal("different tray states are equal")
	}
}

func trayInterfaceNames(interfaces []trayInterfaceState) []string {
	out := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		out = append(out, iface.Name)
	}
	return out
}

func TestNotificationTitle(t *testing.T) {
	tests := []struct {
		name         string
		notification adminapi.Notification
		want         string
	}{
		{name: "header", notification: adminapi.Notification{Header: "Custom"}, want: "Killswitch: Custom"},
		{name: "normal", notification: adminapi.Notification{Level: adminapi.NotificationLevelNormal}, want: "Killswitch"},
		{name: "warn", notification: adminapi.Notification{Level: adminapi.NotificationLevelWarn}, want: "Killswitch warning"},
		{name: "error", notification: adminapi.Notification{Level: adminapi.NotificationLevelError}, want: "Killswitch error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := notificationTitle(tt.notification); got != tt.want {
				t.Fatalf("title = %q, want %q", got, tt.want)
			}
		})
	}
}

type recordingNotifier struct {
	notifications            []adminapi.Notification
	cancel                   context.CancelFunc
	globalAllowAllCount      int
	closeGlobalAllowAllCount int
	disableGlobalAllowAll    func()
	closed                   bool
}

func (n *recordingNotifier) Notify(notification adminapi.Notification) error {
	n.notifications = append(n.notifications, notification)
	if n.cancel != nil {
		n.cancel()
	}
	return nil
}

func (n *recordingNotifier) NotifyGlobalAllowAll(disable func()) error {
	n.globalAllowAllCount++
	n.disableGlobalAllowAll = disable
	return nil
}

func (n *recordingNotifier) CloseGlobalAllowAll() error {
	n.closeGlobalAllowAllCount++
	return nil
}

func (n *recordingNotifier) Close() error {
	n.closed = true
	return nil
}

func mapEnv(values map[string]string) envLookup {
	return func(key string) string {
		return values[key]
	}
}

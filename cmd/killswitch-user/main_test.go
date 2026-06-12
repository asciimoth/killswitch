package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
	if opts.NetworkCheck.Enabled {
		t.Fatalf("network check enabled by default: %+v", opts.NetworkCheck)
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

func TestLoadOptionsReadsNetworkCheck(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "killswitch-user.json")
	if err := os.WriteFile(configPath, []byte(`{
		"socket_path": "/tmp/admin.sock",
		"network_check": {
			"period": "300s",
			"url": "http://connectivity-check.ubuntu.com/",
			"status": 204,
			"text": "ok",
			"header": "online",
			"timeout": "5s",
			"notify": true
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	opts, err := loadOptions(configPath, mapEnv(nil))
	if err != nil {
		t.Fatalf("load options: %v", err)
	}
	if !opts.NetworkCheck.Enabled {
		t.Fatal("network check disabled")
	}
	if opts.NetworkCheck.Period != 300*time.Second {
		t.Fatalf("period = %s", opts.NetworkCheck.Period)
	}
	if opts.NetworkCheck.Timeout != 5*time.Second {
		t.Fatalf("timeout = %s", opts.NetworkCheck.Timeout)
	}
	if opts.NetworkCheck.Status != 204 || opts.NetworkCheck.Text != "ok" || opts.NetworkCheck.Header != "online" || !opts.NetworkCheck.Notify {
		t.Fatalf("network check = %+v", opts.NetworkCheck)
	}
}

func TestLoadOptionsReadsCaptivePortalCommand(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "killswitch-user.json")
	if err := os.WriteFile(configPath, []byte(`{
		"socket_path": "/tmp/admin.sock",
		"network_check": {
			"url": "http://connectivity-check.ubuntu.com/",
			"status": 204,
			"captive_portal": {
				"env": {
					"MY_TMP_DIR": "{{.Tmp}}"
				},
				"cmd": ["chromium", "--proxy-server={{.ProxyAddr}}", "{{.Portal}}"]
			}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	opts, err := loadOptions(configPath, mapEnv(nil))
	if err != nil {
		t.Fatalf("load options: %v", err)
	}
	if got := opts.NetworkCheck.CaptivePortal.Env["MY_TMP_DIR"]; got != "{{.Tmp}}" {
		t.Fatalf("env template = %q", got)
	}
	wantCmd := []string{"chromium", "--proxy-server={{.ProxyAddr}}", "{{.Portal}}"}
	if !reflect.DeepEqual(opts.NetworkCheck.CaptivePortal.Cmd, wantCmd) {
		t.Fatalf("cmd = %+v, want %+v", opts.NetworkCheck.CaptivePortal.Cmd, wantCmd)
	}
}

func TestLoadOptionsRejectsInvalidNetworkCheck(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "bad url", data: `{"socket_path":"/tmp/admin.sock","network_check":{"url":"ftp://example.com","status":204}}`},
		{name: "bad status", data: `{"socket_path":"/tmp/admin.sock","network_check":{"url":"http://example.com","status":99}}`},
		{name: "bad period", data: `{"socket_path":"/tmp/admin.sock","network_check":{"url":"http://example.com","status":204,"period":"soon"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "killswitch-user.json")
			if err := os.WriteFile(configPath, []byte(tt.data), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := loadOptions(configPath, mapEnv(nil)); err == nil {
				t.Fatal("load options succeeded, expected error")
			}
		})
	}
}

func TestRunNetworkCheckClassifiesExpectedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(networkCheckStatusHeader, "online")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result := runNetworkCheck(context.Background(), networkCheckOptions{
		Enabled: true,
		URL:     server.URL,
		Status:  http.StatusNoContent,
		Header:  "online",
	}, adminapi.CurrentConfig{}, "test")
	if result.Status != networkCheckStatusInternetAvailable {
		t.Fatalf("status = %s, detail = %s", result.Status, result.Detail)
	}
}

func TestRunNetworkCheckClassifiesRedirectAsLoginRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	result := runNetworkCheck(context.Background(), networkCheckOptions{
		Enabled: true,
		URL:     server.URL,
		Status:  http.StatusNoContent,
	}, adminapi.CurrentConfig{}, "test")
	if result.Status != networkCheckStatusLoginRequired {
		t.Fatalf("status = %s, detail = %s", result.Status, result.Detail)
	}
	if result.PortalURL != server.URL+"/login" {
		t.Fatalf("portal url = %q", result.PortalURL)
	}
}

func TestRunNetworkCheckClassifiesUnexpectedResponseAsLoginRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("portal"))
	}))
	defer server.Close()

	result := runNetworkCheck(context.Background(), networkCheckOptions{
		Enabled: true,
		URL:     server.URL,
		Status:  http.StatusNoContent,
	}, adminapi.CurrentConfig{}, "test")
	if result.Status != networkCheckStatusLoginRequired {
		t.Fatalf("status = %s, detail = %s", result.Status, result.Detail)
	}
}

func TestExecuteCaptivePortalCommandRendersTemplatesAndRemovesTempDir(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "portal-command.txt")
	notifications := &recordingNotifier{}

	executeCaptivePortalCommand(context.Background(), notifications, captivePortalOptions{
		Env: map[string]string{
			"MY_TMP_DIR": "{{.Tmp}}",
			"OUT":        outPath,
		},
		Cmd: []string{
			"sh",
			"-c",
			"printf '%s\n%s\n%s\n%s\n%s\n' \"$MY_TMP_DIR\" \"$1\" \"$2\" \"$3\" \"$4\" > \"$OUT\"",
			"sh",
			"{{.Tmp}}",
			"{{.ProxyHost}}",
			"{{.ProxyPort}}",
			"{{.Portal}}",
		},
	}, networkCheckResult{
		Status:         networkCheckStatusLoginRequired,
		SocksProxyHost: "127.0.0.1",
		SocksProxyPort: 1080,
		SocksProxyAddr: "socks5://127.0.0.1:1080",
	})

	if len(notifications.notifications) != 0 {
		t.Fatalf("notifications = %+v", notifications.notifications)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read command output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("command output = %q", data)
	}
	tmpFromEnv, tmpFromArg := lines[0], lines[1]
	if tmpFromEnv == "" || tmpFromEnv != tmpFromArg {
		t.Fatalf("tmp values = %q, %q", tmpFromEnv, tmpFromArg)
	}
	if !filepath.IsAbs(tmpFromEnv) {
		t.Fatalf("tmp path is not absolute: %q", tmpFromEnv)
	}
	if _, err := os.Stat(tmpFromEnv); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp dir still exists or stat failed unexpectedly: %v", err)
	}
	if lines[2] != "127.0.0.1" || lines[3] != "1080" || lines[4] != "http://example.com" {
		t.Fatalf("rendered values = %+v", lines)
	}
}

func TestExecuteCaptivePortalCommandNotifiesTemplateErrors(t *testing.T) {
	notifications := &recordingNotifier{}

	executeCaptivePortalCommand(context.Background(), notifications, captivePortalOptions{
		Cmd: []string{"sh", "-c", "{{.Missing}}"},
	}, networkCheckResult{Status: networkCheckStatusLoginRequired})

	if len(notifications.notifications) != 1 {
		t.Fatalf("notifications = %+v", notifications.notifications)
	}
	if notifications.notifications[0].Level != adminapi.NotificationLevelError ||
		notifications.notifications[0].Header != "Captive portal command failed" {
		t.Fatalf("notification = %+v", notifications.notifications[0])
	}
}

func TestNetworkCheckWatcherCaptivePortalCommandRunsOnOpenOnly(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "portal-command.txt")
	notifications := &recordingNotifier{}
	watcher := newNetworkCheckWatcher(networkCheckOptions{
		Enabled: true,
		Notify:  true,
		CaptivePortal: captivePortalOptions{
			Cmd: []string{"sh", "-c", "printf '%s' \"$1\" > \"$2\"", "sh", "{{.Portal}}", outPath},
		},
	})

	watcher.finish(context.Background(), notifications, noopTray{}, networkCheckResult{
		Status:    networkCheckStatusLoginRequired,
		PortalURL: "http://portal.example/login",
	})

	if notifications.captivePortalCount != 1 {
		t.Fatalf("captive portal notifications = %d", notifications.captivePortalCount)
	}
	if notifications.openCaptivePortal == nil {
		t.Fatal("open captive portal callback is nil")
	}
	if _, err := os.Stat(outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("command ran before open callback: %v", err)
	}

	notifications.openCaptivePortal()
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(outPath)
		if err == nil {
			if string(data) != "http://portal.example/login" {
				t.Fatalf("command output = %q", data)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("command did not run after open callback: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
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
		Network:  networkTrayState{Enabled: true, Status: networkCheckStatusInternetAvailable},
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

	changed = base
	changed.Network = networkTrayState{Enabled: true, Status: networkCheckStatusNoInternet}
	if trayStatesEqual(base, changed) {
		t.Fatal("different network states are equal")
	}
}

func TestNetworkTrayTitle(t *testing.T) {
	tests := []struct {
		name  string
		state networkTrayState
		want  string
	}{
		{name: "disabled", want: "Connectivity: disabled"},
		{name: "checking", state: networkTrayState{Enabled: true, Checking: true}, want: "Connectivity: checking"},
		{name: "unknown", state: networkTrayState{Enabled: true}, want: "Connectivity: unknown"},
		{name: "internet", state: networkTrayState{Enabled: true, Status: networkCheckStatusInternetAvailable}, want: "Connectivity: internet available"},
		{name: "login", state: networkTrayState{Enabled: true, Status: networkCheckStatusLoginRequired}, want: "Connectivity: login required"},
		{name: "offline", state: networkTrayState{Enabled: true, Status: networkCheckStatusNoInternet}, want: "Connectivity: no internet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := networkTrayTitle(tt.state); got != tt.want {
				t.Fatalf("title = %q, want %q", got, tt.want)
			}
		})
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
	captivePortalCount       int
	closeCaptivePortalCount  int
	openCaptivePortal        func()
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

func (n *recordingNotifier) NotifyCaptivePortal(notification adminapi.Notification, open func()) error {
	n.notifications = append(n.notifications, notification)
	n.captivePortalCount++
	n.openCaptivePortal = open
	if n.cancel != nil {
		n.cancel()
	}
	return nil
}

func (n *recordingNotifier) CloseCaptivePortal() error {
	n.closeCaptivePortalCount++
	n.openCaptivePortal = nil
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

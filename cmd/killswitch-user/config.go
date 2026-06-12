package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

const defaultConfigFileName = "killswitch-user.json"

type configFile struct {
	SocketPath             string              `json:"socket_path,omitempty"`
	NotifyInterfaceChanges *bool               `json:"notify_interface_changes,omitempty"`
	NotifyGlobalAllowAll   *bool               `json:"notify_global_allow_all,omitempty"`
	TrayEnabled            *bool               `json:"tray_enabled,omitempty"`
	NetworkCheck           *networkCheckConfig `json:"network_check,omitempty"`
}

type networkCheckConfig struct {
	Period        string               `json:"period,omitempty"`
	URL           string               `json:"url,omitempty"`
	Status        int                  `json:"status,omitempty"`
	Text          string               `json:"text,omitempty"`
	Header        string               `json:"header,omitempty"`
	Timeout       string               `json:"timeout,omitempty"`
	Notify        bool                 `json:"notify,omitempty"`
	CaptivePortal *captivePortalConfig `json:"captive_portal,omitempty"`
}

type captivePortalConfig struct {
	Env map[string]string `json:"env,omitempty"`
	Cmd []string          `json:"cmd,omitempty"`
}

type options struct {
	ConfigPath             string
	SocketPath             string
	NotifyInterfaceChanges bool
	NotifyGlobalAllowAll   bool
	TrayEnabled            bool
	NetworkCheck           networkCheckOptions
}

type networkCheckOptions struct {
	Enabled       bool
	Period        time.Duration
	URL           string
	Status        int
	Text          string
	Header        string
	Timeout       time.Duration
	Notify        bool
	CaptivePortal captivePortalOptions
}

type captivePortalOptions struct {
	Env map[string]string
	Cmd []string
}

type envLookup func(string) string

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

	networkCheck, err := networkCheckOptionsFromConfig(cfg.NetworkCheck)
	if err != nil {
		return options{}, err
	}

	return options{
		ConfigPath:             configPath,
		SocketPath:             socketPath,
		NotifyInterfaceChanges: boolConfigValue(cfg.NotifyInterfaceChanges, true),
		NotifyGlobalAllowAll:   boolConfigValue(cfg.NotifyGlobalAllowAll, true),
		TrayEnabled:            boolConfigValue(cfg.TrayEnabled, true),
		NetworkCheck:           networkCheck,
	}, nil
}

func networkCheckOptionsFromConfig(cfg *networkCheckConfig) (networkCheckOptions, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return networkCheckOptions{}, nil
	}

	checkURL := strings.TrimSpace(cfg.URL)
	parsedURL, err := url.ParseRequestURI(checkURL)
	if err != nil {
		return networkCheckOptions{}, fmt.Errorf("network_check.url: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return networkCheckOptions{}, fmt.Errorf("network_check.url: unsupported scheme %q", parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return networkCheckOptions{}, errors.New("network_check.url: host is required")
	}
	if cfg.Status < 100 || cfg.Status > 599 {
		return networkCheckOptions{}, fmt.Errorf("network_check.status must be an HTTP status code, got %d", cfg.Status)
	}

	period, err := parseOptionalDuration("network_check.period", cfg.Period)
	if err != nil {
		return networkCheckOptions{}, err
	}
	timeout, err := parseOptionalDuration("network_check.timeout", cfg.Timeout)
	if err != nil {
		return networkCheckOptions{}, err
	}

	return networkCheckOptions{
		Enabled:       true,
		Period:        period,
		URL:           checkURL,
		Status:        cfg.Status,
		Text:          cfg.Text,
		Header:        cfg.Header,
		Timeout:       timeout,
		Notify:        cfg.Notify,
		CaptivePortal: captivePortalOptionsFromConfig(cfg.CaptivePortal),
	}, nil
}

func captivePortalOptionsFromConfig(cfg *captivePortalConfig) captivePortalOptions {
	if cfg == nil {
		return captivePortalOptions{}
	}
	return captivePortalOptions{
		Env: cloneStringMap(cfg.Env),
		Cmd: cloneStrings(cfg.Cmd),
	}
}

func parseOptionalDuration(field, value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	if duration < 0 {
		return 0, fmt.Errorf("%s must not be negative", field)
	}
	return duration, nil
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

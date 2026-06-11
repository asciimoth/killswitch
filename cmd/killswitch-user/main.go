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
	"strings"
	"syscall"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/gen2brain/beeep"
)

const defaultConfigFileName = "killswitch-user.json"

type configFile struct {
	SocketPath string `json:"socket_path,omitempty"`
}

type options struct {
	ConfigPath string
	SocketPath string
}

type envLookup func(string) string

type notifier interface {
	Notify(adminapi.Notification) error
}

type beeepNotifier struct{}

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

	if err := run(ctx, opts, beeepNotifier{}); err != nil {
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

	return options{ConfigPath: configPath, SocketPath: socketPath}, nil
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
	return configFile{SocketPath: adminapi.DefaultSocketPath}
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

	return runClient(ctx, client, notifications)
}

func runClient(ctx context.Context, client *adminapi.Client, notifications notifier) error {
	if err := client.Subscribe(
		adminapi.EventTypeConfig,
		adminapi.EventTypeInterfaces,
		adminapi.EventTypeClients,
		adminapi.EventTypeNotification,
	); err != nil {
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

	for {
		event, err := client.WaitForEvent()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if event.EventType != adminapi.EventTypeNotification {
			continue
		}
		if err := notifications.Notify(event.Notification); err != nil {
			log.Printf("send desktop notification: %s", err)
		}
	}
}

func (beeepNotifier) Notify(notification adminapi.Notification) error {
	return beeep.Notify(notificationTitle(notification), notification.Text, "")
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

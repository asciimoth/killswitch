package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

const (
	adminReconnectInitialBackoff = 200 * time.Millisecond
	adminReconnectMaxBackoff     = 10 * time.Second
)

type notifier interface {
	Notify(adminapi.Notification) error
	NotifyGlobalAllowAll(func()) error
	CloseGlobalAllowAll() error
	NotifyCaptivePortal(adminapi.Notification, func()) error
	CloseCaptivePortal() error
	Close() error
}

type trayController interface {
	Start(context.Context, chan<- trayCommand)
	Update(adminapi.CurrentConfig)
	UpdateNetwork(networkTrayState)
	Close()
}

func run(ctx context.Context, opts options, notifications notifier) error {
	defer func() {
		if err := notifications.Close(); err != nil {
			log.Printf("close desktop notifier: %s", err)
		}
	}()

	trayCommands := make(chan trayCommand, 8)
	tray := trayController(noopTray{})
	if opts.TrayEnabled {
		tray = newSystemTray()
		tray.Start(ctx, trayCommands)
		defer tray.Close()
	}

	backoff := adminReconnectInitialBackoff
	for {
		client, err := adminapi.DialUnix(ctx, opts.SocketPath)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("connect to admin API failed: %s; retrying in %s", err, backoff)
			if !sleepContext(ctx, backoff) {
				return nil
			}
			backoff = nextAdminReconnectBackoff(backoff)
			continue
		}

		backoff = adminReconnectInitialBackoff
		err = runConnectedClient(ctx, client, notifications, opts, tray, trayCommands)
		if closeErr := client.Close(); closeErr != nil && ctx.Err() == nil {
			log.Printf("close admin API client: %s", closeErr)
		}
		if ctx.Err() != nil {
			return nil
		}
		if !isReconnectableAdminError(err) {
			return err
		}
		log.Printf("admin API disconnected: %s; reconnecting in %s", err, backoff)
		if !sleepContext(ctx, backoff) {
			return nil
		}
		backoff = nextAdminReconnectBackoff(backoff)
	}
}

func runClient(ctx context.Context, client *adminapi.Client, notifications notifier, opts options) error {
	defer func() {
		if err := notifications.Close(); err != nil {
			log.Printf("close desktop notifier: %s", err)
		}
	}()
	trayCommands := make(chan trayCommand, 8)
	tray := trayController(noopTray{})
	if opts.TrayEnabled {
		tray = newSystemTray()
		tray.Start(ctx, trayCommands)
		defer tray.Close()
	}
	return runConnectedClient(ctx, client, notifications, opts, tray, trayCommands)
}

func runConnectedClient(ctx context.Context, client *adminapi.Client, notifications notifier, opts options, tray trayController, trayCommands <-chan trayCommand) error {
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

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
	tray.Update(cfg)
	networkChecks := newNetworkCheckWatcher(opts.NetworkCheck)
	if opts.NetworkCheck.Enabled {
		tray.UpdateNetwork(networkTrayState{Enabled: true, Checking: true})
	}
	latestConfig := cfg
	var networkCheckTimer <-chan time.Time
	if opts.NetworkCheck.Enabled && opts.NetworkCheck.Period > 0 {
		ticker := time.NewTicker(opts.NetworkCheck.Period)
		defer ticker.Stop()
		networkCheckTimer = ticker.C
	}
	networkChecks.applyInitial(latestConfig)

	events := make(chan adminapi.EventMessage, 1)
	mutationResults := make(chan adminapi.MutationResult, 1)
	networkCheckResults := make(chan networkCheckResult, 1)
	errs := make(chan error, 1)
	networkChecks.start(sessionCtx, networkCheckResults)
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
	networkChecks.check(sessionCtx, latestConfig, networkCheckResults, "start")

	for {
		select {
		case <-disableAllowAll:
			if err := disableGlobalAllowAll(client); err != nil {
				log.Printf("disable global allow_all: %s", err)
			}
		case cmd := <-trayCommands:
			if cmd.Kind == trayCommandOpenCaptivePortal {
				networkChecks.openLastCaptivePortal(sessionCtx, notifications)
				continue
			}
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
			latestConfig = result.Config
			networkChecks.checkIfInterfacesChanged(sessionCtx, latestConfig, networkCheckResults, "mutation")
		case result := <-networkCheckResults:
			networkChecks.finish(sessionCtx, notifications, tray, result)
		case <-networkCheckTimer:
			networkChecks.check(sessionCtx, latestConfig, networkCheckResults, "periodic")
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
				latestConfig = event.Config
				networkChecks.checkIfInterfacesChanged(sessionCtx, latestConfig, networkCheckResults, "config")
			case adminapi.EventTypeInterfaces, adminapi.EventTypeClients:
				tray.Update(event.Config)
				latestConfig = event.Config
				if event.EventType == adminapi.EventTypeInterfaces {
					networkChecks.checkInterfacesEvent(sessionCtx, latestConfig, networkCheckResults)
				}
			default:
				continue
			}
		}
	}
}

func isReconnectableAdminError(err error) bool {
	if err == nil {
		return false
	}
	if adminapi.IsEOF(err) || errors.Is(err, net.ErrClosed) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "broken pipe") ||
		strings.Contains(message, "use of closed network connection")
}

func nextAdminReconnectBackoff(backoff time.Duration) time.Duration {
	backoff *= 2
	if backoff > adminReconnectMaxBackoff {
		return adminReconnectMaxBackoff
	}
	return backoff
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func disableGlobalAllowAll(client *adminapi.Client) error {
	return client.Send(adminapi.MutationRequest{
		Operation: adminapi.MutationSet,
		Target:    "base_policy.allow_all",
		Value:     json.RawMessage("false"),
	})
}

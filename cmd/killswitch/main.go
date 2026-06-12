//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	configPath, err := parseArgs(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	opts, err := loadOptions(configPath, os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	if err := run(context.Background(), opts); err != nil {
		log.Fatal(err)
	}
}

func parseArgs(args []string) (string, error) {
	switch len(args) {
	case 0:
		return defaultConfigPath, nil
	case 1:
		return args[0], nil
	default:
		return "", fmt.Errorf("expected at most one config path argument, got: %s", strings.Join(args, " "))
	}
}

func run(parent context.Context, opts options) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs killswitchObjects
	if err := loadKillswitchObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close() //nolint:errcheck

	manager := newEgressManager(objs.KillswitchEgress)
	defer manager.close()
	policies := newPolicyManager(&objs, opts)

	signalCtx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	reader, err := ringbuf.NewReader(objs.BootstrapEvents)
	if err != nil {
		return fmt.Errorf("open bootstrap event ring buffer: %w", err)
	}
	defer reader.Close() //nolint:errcheck

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	var reconcileMu sync.Mutex

	var adminServer *adminAPIServer
	notifyError := func(header string, err error) {
		if adminServer != nil {
			adminServer.notifyError(header, err)
		}
	}

	configSnapshot := func() adminapi.CurrentConfig {
		return currentConfigSnapshot(policies, manager, adminServer.clientSnapshot, notifyError)
	}
	proxy := newSocksProxyManager(opts.SocksProxy, func(state socksProxyState) {
		reconcileMu.Lock()
		policies.setSocksProxyState(state)
		_, err := policies.reconcileAttached(manager, true)
		reconcileMu.Unlock()
		if err != nil {
			log.Printf("ERROR: reconcile socks proxy policy state: %s", err)
			notifyError("SOCKS proxy policy error", err)
		}
		if state.LastError != "" {
			notifyError("SOCKS proxy error", errors.New(state.LastError))
		}
		if adminServer != nil {
			adminServer.notify(adminapi.EventTypeConfig)
		}
	})
	defer proxy.Close()
	adminServer = newAdminAPIServer(opts.AdminAPI, configSnapshot, func(req adminapi.MutationRequest) adminapi.MutationResult {
		if req.Target == "socks_proxy" {
			return applySocksProxyMutation(ctx, req, proxy, policies, manager, &reconcileMu)
		}
		return applyAdminMutation(req, policies, manager, &reconcileMu)
	})

	errCh := make(chan error, 3)
	go func() {
		if err := readBootstrapEvents(reader, notifyError); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errCh <- err
		}
	}()
	adminServer.setTemporaryRulesetCallbacks(
		func(owner string, req adminapi.MutationRequest) adminapi.MutationResult {
			return applyTemporaryRulesetMutation(owner, req, policies, manager, &reconcileMu)
		},
		func(owner string) adminapi.MutationResult {
			return removeTemporaryRuleset(owner, policies, manager, &reconcileMu)
		},
	)
	adminServer.setForceRulesetCallbacks(
		func(owner string, req adminapi.MutationRequest) adminapi.MutationResult {
			return applyForceRulesetMutation(owner, req, policies, manager, &reconcileMu)
		},
		func(owner string) adminapi.MutationResult {
			return removeForceRulesets(owner, policies, manager, &reconcileMu)
		},
	)
	if opts.SocksProxy.Enabled {
		if err := proxy.SetEnabled(ctx, true); err != nil {
			log.Printf("ERROR: start socks proxy: %s", err)
			notifyError("SOCKS proxy start error", err)
		}
	}
	go func() {
		if err := watchInterfaces(ctx, manager, policies, &reconcileMu, func(eventType adminapi.EventType) {
			adminServer.notify(eventType)
		}); err != nil {
			errCh <- err
		}
	}()
	go func() {
		if err := adminServer.listenAndServe(ctx); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		cancel()
		return err
	}
}

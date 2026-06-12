//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/asciimoth/gonnect"
	gonnectprotected "github.com/asciimoth/gonnect/protected"
	"github.com/asciimoth/killswitch/internal/adminapi"
	"github.com/asciimoth/killswitch/internal/policy"
	"github.com/asciimoth/socksgo"
)

const (
	defaultSocksProxyHost   = "127.0.0.1"
	defaultSocksProxyPort   = 1080
	defaultSocksProxyFWMark = "0xeb9f0001"
)

type socksProxyConfig struct {
	Enabled   bool                      `json:"enabled"`
	Port      uint16                    `json:"port"`
	FWMark    string                    `json:"fwmark"`
	DNSServer string                    `json:"dns_server"`
	Protected socksProxyProtectedConfig `json:"protected"`
}

type socksProxyProtectedConfig struct {
	UIDs      []uint32 `json:"uids"`
	GIDs      []uint32 `json:"gids"`
	Usernames []string `json:"usernames"`
}

type socksProxyOptions struct {
	Enabled   bool
	Port      uint16
	FWMark    uint32
	DNSServer string
	Protected socksProxyProtectedOptions
}

type socksProxyProtectedOptions struct {
	UIDs      []uint32
	GIDs      []uint32
	Usernames []string
}

type socksProxyState struct {
	Enabled   bool
	Running   bool
	Port      uint16
	FWMark    uint32
	DNSServer string
	LastError string
}

type socksProxyManager struct {
	mu             sync.Mutex
	opts           socksProxyOptions
	state          socksProxyState
	listener       net.Listener
	cancel         context.CancelFunc
	onStateChanged func(socksProxyState)
}

func socksProxyOptionsFromConfig(cfg socksProxyConfig) socksProxyOptions {
	opts := socksProxyOptions{
		Enabled:   cfg.Enabled,
		Port:      cfg.Port,
		DNSServer: strings.TrimSpace(cfg.DNSServer),
		Protected: socksProxyProtectedOptions{
			UIDs:      cfg.Protected.UIDs,
			GIDs:      cfg.Protected.GIDs,
			Usernames: trimStrings(cfg.Protected.Usernames),
		},
	}
	if opts.Port == 0 {
		opts.Port = defaultSocksProxyPort
	}
	if cfg.FWMark == "" {
		cfg.FWMark = defaultSocksProxyFWMark
	}
	marks, err := policy.ParseAllowedMarks([]string{cfg.FWMark})
	if err == nil && len(marks) == 1 {
		opts.FWMark = marks[0]
	}
	return opts
}

func validateSocksProxyOptions(opts socksProxyOptions) error {
	if opts.FWMark == 0 {
		return errors.New("socks_proxy.fwmark must be a non-zero uint32 mark")
	}
	if opts.DNSServer != "" {
		if _, err := netipAddrOrHostPort(opts.DNSServer); err != nil {
			return fmt.Errorf("socks_proxy.dns_server: %w", err)
		}
	}
	for _, username := range opts.Protected.Usernames {
		if username == "" {
			return errors.New("socks_proxy.protected.usernames entries must not be empty")
		}
	}
	return nil
}

func trimStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	trimmed := make([]string, len(values))
	for i, value := range values {
		trimmed[i] = strings.TrimSpace(value)
	}
	return trimmed
}

func netipAddrOrHostPort(value string) (string, error) {
	if value == "" {
		return "", errors.New("address is empty")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if host == "" {
			return "", errors.New("host is empty")
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil && port != "dns" {
			return "", fmt.Errorf("invalid port %q", port)
		}
		return value, nil
	}
	return net.JoinHostPort(value, "53"), nil
}

func socksProxyStateFromOptions(opts socksProxyOptions) socksProxyState {
	return socksProxyState{
		Enabled:   opts.Enabled,
		Port:      opts.Port,
		FWMark:    opts.FWMark,
		DNSServer: opts.DNSServer,
	}
}

func apiSocksProxyState(state socksProxyState) adminapi.SocksProxyState {
	return adminapi.SocksProxyState{
		Enabled:   state.Enabled,
		Running:   state.Running,
		Host:      defaultSocksProxyHost,
		Port:      state.Port,
		FWMark:    fmt.Sprintf("0x%08x", state.FWMark),
		DNSServer: state.DNSServer,
		LastError: state.LastError,
	}
}

func newSocksProxyManager(opts socksProxyOptions, onStateChanged func(socksProxyState)) *socksProxyManager {
	return &socksProxyManager{
		opts:           opts,
		state:          socksProxyStateFromOptions(opts),
		onStateChanged: onStateChanged,
	}
}

func (m *socksProxyManager) State() socksProxyState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *socksProxyManager) SetEnabled(parent context.Context, enabled bool) error {
	if enabled {
		return m.start(parent)
	}
	m.stop("")
	return nil
}

func (m *socksProxyManager) Close() {
	m.stop("")
}

func (m *socksProxyManager) start(parent context.Context) error {
	m.mu.Lock()
	if m.state.Running {
		m.state.Enabled = true
		state := m.state
		m.mu.Unlock()
		m.emit(state)
		return nil
	}
	opts := m.opts
	m.state.Enabled = true
	m.state.LastError = ""
	m.mu.Unlock()

	listener, err := (&net.ListenConfig{}).Listen(parent, "tcp", net.JoinHostPort(defaultSocksProxyHost, strconv.Itoa(int(opts.Port))))
	if err != nil {
		m.setStartError(fmt.Errorf("listen socks proxy: %w", err))
		return err
	}
	listener, err = protectedSocksProxyListener(listener, opts.Protected)
	if err != nil {
		_ = listener.Close()
		err = fmt.Errorf("protect socks proxy listener: %w", err)
		m.setStartError(err)
		return err
	}

	ctx, cancel := context.WithCancel(parent)
	server := protectedSocksServer(opts)

	m.mu.Lock()
	m.listener = listener
	m.cancel = cancel
	m.state.Running = true
	m.state.LastError = ""
	state := m.state
	m.mu.Unlock()
	m.emit(state)

	go m.serve(ctx, server, listener)
	return nil
}

func protectedSocksProxyListener(listener net.Listener, opts socksProxyProtectedOptions) (net.Listener, error) {
	if !opts.HasRules() {
		return listener, nil
	}
	return gonnectprotected.NewListener(listener, opts.Rules())
}

func (opts socksProxyProtectedOptions) HasRules() bool {
	return len(opts.UIDs) > 0 || len(opts.GIDs) > 0 || len(opts.Usernames) > 0
}

func (opts socksProxyProtectedOptions) Rules() gonnectprotected.Rules {
	return gonnectprotected.Rules{
		UIDs:      opts.UIDs,
		GIDs:      opts.GIDs,
		Usernames: opts.Usernames,
	}
}

func (m *socksProxyManager) serve(ctx context.Context, server *socksgo.Server, listener net.Listener) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("ERROR: socks proxy accept: %s", err)
			m.stopWithError(fmt.Errorf("socks proxy accept: %w", err))
			return
		}
		go func() {
			if err := server.Accept(ctx, conn, false); err != nil && ctx.Err() == nil {
				log.Printf("socks proxy connection error: %s", err)
			}
		}()
	}
}

func (m *socksProxyManager) stop(lastError string) {
	m.mu.Lock()
	cancel := m.cancel
	listener := m.listener
	m.cancel = nil
	m.listener = nil
	m.state.Enabled = false
	m.state.Running = false
	m.state.LastError = lastError
	state := m.state
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	m.emit(state)
}

func (m *socksProxyManager) stopWithError(err error) {
	m.mu.Lock()
	cancel := m.cancel
	listener := m.listener
	m.cancel = nil
	m.listener = nil
	m.state.Running = false
	m.state.LastError = err.Error()
	state := m.state
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	m.emit(state)
}

func (m *socksProxyManager) setStartError(err error) {
	log.Printf("ERROR: %s", err)
	m.mu.Lock()
	m.state.Running = false
	m.state.LastError = err.Error()
	state := m.state
	m.mu.Unlock()
	m.emit(state)
}

func (m *socksProxyManager) emit(state socksProxyState) {
	if m.onStateChanged != nil {
		m.onStateChanged(state)
	}
}

func protectedSocksServer(opts socksProxyOptions) *socksgo.Server {
	dialer := protectedNetDialer(opts.FWMark)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if opts.DNSServer != "" {
				address = dnsServerAddress(opts.DNSServer)
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	dialer.Resolver = resolver
	return &socksgo.Server{
		Handlers:       socksgo.DefaultCommandHandlers,
		Dialer:         dialer.DialContext,
		PacketDialer:   protectedPacketDialer(opts.FWMark, resolver),
		Listener:       protectedListener(opts.FWMark),
		PacketListener: protectedPacketListener(opts.FWMark),
		Resolver:       resolver,
	}
}

func protectedNetDialer(mark uint32) net.Dialer {
	return net.Dialer{Control: socketMarkControl(mark)}
}

func protectedPacketDialer(mark uint32, resolver *net.Resolver) gonnect.PacketDial {
	return func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
		dialer := protectedNetDialer(mark)
		dialer.Resolver = resolver
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		packetConn, ok := conn.(gonnect.PacketConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("%s dial did not return packet connection", network)
		}
		return packetConn, nil
	}
}

func protectedListener(mark uint32) gonnect.Listen {
	listener := &net.ListenConfig{Control: socketMarkControl(mark)}
	return listener.Listen
}

func protectedPacketListener(mark uint32) gonnect.PacketListen {
	return func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
		conn, err := (&net.ListenConfig{Control: socketMarkControl(mark)}).ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		packetConn, ok := conn.(gonnect.PacketConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("%s listen did not return packet connection", network)
		}
		return packetConn, nil
	}
}

func socketMarkControl(mark uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return controlErr
	}
}

func dnsServerAddress(value string) string {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return net.JoinHostPort(value, "53")
	}
	if strings.EqualFold(port, "dns") {
		return net.JoinHostPort(host, "53")
	}
	return value
}

func applySocksProxyMutation(ctx context.Context, req adminapi.MutationRequest, proxy *socksProxyManager, policies *policyManager, manager *egressManager, reconcileMu *sync.Mutex) adminapi.MutationResult {
	if req.Operation != adminapi.MutationSet {
		return adminapi.MutationResult{OK: false, Error: "socks_proxy only supports set", Config: policies.configSnapshot()}
	}
	if len(req.Value) == 0 {
		return adminapi.MutationResult{OK: false, Error: "socks_proxy mutation requires boolean value", Config: policies.configSnapshot()}
	}
	var enabled bool
	if err := json.Unmarshal(req.Value, &enabled); err != nil {
		return adminapi.MutationResult{OK: false, Error: fmt.Sprintf("decode socks_proxy value: %s", err), Config: policies.configSnapshot()}
	}
	err := proxy.SetEnabled(ctx, enabled)
	reconcileMu.Lock()
	policies.setSocksProxyState(proxy.State())
	_, reconcileErr := policies.reconcileAttached(manager, true)
	reconcileMu.Unlock()
	if err != nil {
		return adminapi.MutationResult{OK: true, Changed: true, Error: err.Error(), Config: policies.configSnapshot()}
	}
	if reconcileErr != nil {
		return adminapi.MutationResult{OK: false, Error: reconcileErr.Error(), Config: policies.configSnapshot()}
	}
	return adminapi.MutationResult{OK: true, Changed: true, Config: policies.configSnapshot()}
}

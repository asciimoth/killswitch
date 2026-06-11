//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/asciimoth/killswitch/internal/adminapi"
	"golang.org/x/sys/unix"
)

const (
	defaultAdminAPISocketPath = adminapi.DefaultSocketPath
	defaultAdminAPIGroup      = "killswitch"
)

type adminAPIConfig struct {
	SocketPath string             `json:"socket_path"`
	Auth       adminAPIAuthConfig `json:"auth"`
}

type adminAPIAuthConfig struct {
	UIDs       []uint32 `json:"uids"`
	GIDs       []uint32 `json:"gids"`
	Usernames  []string `json:"usernames"`
	Groupnames []string `json:"groupnames"`
}

type adminAPIOptions struct {
	SocketPath string
	Auth       adminAPIAuthRules
}

type adminAPIAuthRules struct {
	UIDs       []uint32
	GIDs       []uint32
	Usernames  []string
	Groupnames []string
}

type adminAPIServer struct {
	opts             adminAPIOptions
	configSnapshot   func() adminapi.CurrentConfig
	mutateConfig     func(adminapi.MutationRequest) adminapi.MutationResult
	mutateTmpRuleset func(string, adminapi.MutationRequest) adminapi.MutationResult
	removeTmpRuleset func(string) adminapi.MutationResult
	nextConnectionID atomic.Uint64
	mu               sync.Mutex
	clients          map[uint64]*adminAPIClient
}

type adminAPIPeer struct {
	UID uint32
	GID uint32
	PID int32
}

type adminAPIClient struct {
	id          uint64
	owner       string
	peer        adminAPIPeer
	eventTypes  map[adminapi.EventType]bool
	writeMu     sync.Mutex
	eventWriter *json.Encoder
}

func adminAPIOptionsFromConfig(cfg adminAPIConfig) adminAPIOptions {
	opts := adminAPIOptions{
		SocketPath: cfg.SocketPath,
		Auth: adminAPIAuthRules{
			UIDs:       cfg.Auth.UIDs,
			GIDs:       cfg.Auth.GIDs,
			Usernames:  cfg.Auth.Usernames,
			Groupnames: cfg.Auth.Groupnames,
		},
	}
	if opts.SocketPath == "" {
		opts.SocketPath = defaultAdminAPISocketPath
	}
	if len(opts.Auth.UIDs) == 0 && len(opts.Auth.GIDs) == 0 && len(opts.Auth.Usernames) == 0 && len(opts.Auth.Groupnames) == 0 {
		opts.Auth.Groupnames = []string{defaultAdminAPIGroup}
	}
	return opts
}

func validateAdminAPIOptions(opts adminAPIOptions) error {
	if opts.SocketPath == "" {
		return errors.New("admin_api.socket_path is required")
	}
	if !filepath.IsAbs(opts.SocketPath) {
		return fmt.Errorf("admin_api.socket_path must be absolute, got %q", opts.SocketPath)
	}
	for _, name := range opts.Auth.Usernames {
		if name == "" {
			return errors.New("admin_api.auth.usernames contains an empty username")
		}
	}
	for _, name := range opts.Auth.Groupnames {
		if name == "" {
			return errors.New("admin_api.auth.groupnames contains an empty groupname")
		}
	}
	return nil
}

func newAdminAPIServer(opts adminAPIOptions, configSnapshot func() adminapi.CurrentConfig, mutateConfig func(adminapi.MutationRequest) adminapi.MutationResult) *adminAPIServer {
	if configSnapshot == nil {
		configSnapshot = func() adminapi.CurrentConfig { return adminapi.CurrentConfig{} }
	}
	if mutateConfig == nil {
		mutateConfig = func(adminapi.MutationRequest) adminapi.MutationResult {
			return adminapi.MutationResult{OK: false, Error: "mutations are not available", Config: configSnapshot()}
		}
	}
	return &adminAPIServer{opts: opts, configSnapshot: configSnapshot, mutateConfig: mutateConfig, clients: make(map[uint64]*adminAPIClient)}
}

func (s *adminAPIServer) setTemporaryRulesetCallbacks(mutate func(string, adminapi.MutationRequest) adminapi.MutationResult, remove func(string) adminapi.MutationResult) {
	s.mutateTmpRuleset = mutate
	s.removeTmpRuleset = remove
}

func (s *adminAPIServer) listenAndServe(ctx context.Context) error {
	listener, err := listenAdminAPIUnix(s.opts.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("close admin API listener: %s", err)
		}
		if err := os.Remove(s.opts.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("remove admin API socket %s: %s", s.opts.SocketPath, err)
		}
	}()

	log.Printf("Admin API listening on %s", s.opts.SocketPath)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept admin API connection: %w", err)
		}
		go s.handleConnection(conn)
	}
}

func listenAdminAPIUnix(socketPath string) (*net.UnixListener, error) {
	if err := ensureAdminAPISocketDir(filepath.Dir(socketPath)); err != nil {
		return nil, err
	}
	if err := removeStaleAdminAPISocket(socketPath); err != nil {
		return nil, err
	}

	addr := &net.UnixAddr{Name: socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on admin API socket %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, fmt.Errorf("chmod admin API socket %s: %w", socketPath, err)
	}
	return listener, nil
}

func ensureAdminAPISocketDir(dir string) error {
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create admin API socket directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat admin API socket directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("admin API socket directory %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("admin API socket directory %s must not be group- or world-writable", dir)
	}

	uid, ok := fileInfoUID(info)
	if !ok {
		return fmt.Errorf("stat admin API socket directory %s: unsupported stat type %T", dir, info.Sys())
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("admin API socket directory %s must be owned by uid %d, got uid %d", dir, os.Geteuid(), uid)
	}
	return nil
}

func fileInfoUID(info os.FileInfo) (uint32, bool) {
	switch stat := info.Sys().(type) {
	case *syscall.Stat_t:
		return stat.Uid, true
	case *unix.Stat_t:
		return stat.Uid, true
	default:
		return 0, false
	}
}

func removeStaleAdminAPISocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat admin API socket %s: %w", socketPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("admin API socket path %s exists and is not a socket", socketPath)
	}

	conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("admin API socket %s is already accepting connections", socketPath)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove stale admin API socket %s: %w", socketPath, err)
	}
	return nil
}

func (s *adminAPIServer) handleConnection(conn *net.UnixConn) {
	defer conn.Close() //nolint:errcheck

	peer, err := adminAPIPeerCred(conn)
	if err != nil {
		log.Printf("Admin API connection denied: peer credentials unavailable: %s", err)
		return
	}
	allowed, reason, err := adminAPIClientAllowed(peer, s.opts.Auth)
	if err != nil {
		log.Printf("Admin API auth lookup error for pid=%d uid=%d gid=%d: %s", peer.PID, peer.UID, peer.GID, err)
	}
	if !allowed {
		log.Printf("Admin API connection denied: pid=%d uid=%d gid=%d", peer.PID, peer.UID, peer.GID)
		return
	}

	log.Printf("Admin API connection authorized: pid=%d uid=%d gid=%d rule=%s", peer.PID, peer.UID, peer.GID, reason)
	client := s.addClient(peer, json.NewEncoder(conn))
	s.notify(adminapi.EventTypeClients)
	defer func() {
		s.removeClient(client.id)
		s.notify(adminapi.EventTypeClients)
		if s.removeTmpRuleset == nil {
			return
		}
		result := s.removeTmpRuleset(client.owner)
		if !result.OK {
			log.Printf("Admin API failed to remove temporary ruleset for pid=%d uid=%d gid=%d: %s", peer.PID, peer.UID, peer.GID, result.Error)
		} else if result.Changed {
			log.Printf("Admin API removed temporary ruleset for pid=%d uid=%d gid=%d", peer.PID, peer.UID, peer.GID)
			s.notify(adminapi.EventTypeConfig)
		}
	}()

	decoder := json.NewDecoder(conn)
	for {
		msg, err := adminapi.ReadMessage(decoder)
		if err != nil {
			if adminapi.IsEOF(err) {
				return
			}
			log.Printf("Admin API read error for pid=%d uid=%d gid=%d: %s", peer.PID, peer.UID, peer.GID, err)
			return
		}

		switch msg := msg.(type) {
		case adminapi.ConfigRequest:
			if err := client.send(adminapi.ConfigMessage{Config: s.configSnapshot()}); err != nil {
				log.Printf("Admin API write config for pid=%d uid=%d gid=%d: %s", peer.PID, peer.UID, peer.GID, err)
				return
			}
		case adminapi.SubscribeRequest:
			s.setClientSubscriptions(client.id, msg.EventTypes)
			s.notify(adminapi.EventTypeClients)
		case adminapi.MutationRequest:
			result := s.handleMutation(client.owner, msg)
			if !result.OK {
				log.Printf("Admin API rejected mutation for pid=%d uid=%d gid=%d op=%s target=%s ruleset=%s: %s", peer.PID, peer.UID, peer.GID, msg.Operation, msg.Target, msg.Ruleset, result.Error)
			} else if result.Changed {
				log.Printf("Admin API applied mutation for pid=%d uid=%d gid=%d op=%s target=%s ruleset=%s", peer.PID, peer.UID, peer.GID, msg.Operation, msg.Target, msg.Ruleset)
			}
			if err := client.send(result); err != nil {
				log.Printf("Admin API write mutation result for pid=%d uid=%d gid=%d: %s", peer.PID, peer.UID, peer.GID, err)
				return
			}
			if result.OK {
				s.notify(adminapi.EventTypeConfig)
			}
		case adminapi.UnknownMessage:
			log.Printf("Admin API ignored unknown message for pid=%d uid=%d gid=%d", peer.PID, peer.UID, peer.GID)
		default:
			log.Printf("Admin API ignored unexpected client message %T for pid=%d uid=%d gid=%d", msg, peer.PID, peer.UID, peer.GID)
		}
	}
}

func (s *adminAPIServer) addClient(peer adminAPIPeer, encoder *json.Encoder) *adminAPIClient {
	id := s.nextConnectionID.Add(1)
	client := &adminAPIClient{
		id:          id,
		owner:       fmt.Sprintf("pid=%d uid=%d gid=%d conn=%d", peer.PID, peer.UID, peer.GID, id),
		peer:        peer,
		eventTypes:  make(map[adminapi.EventType]bool),
		eventWriter: encoder,
	}
	s.mu.Lock()
	s.clients[id] = client
	s.mu.Unlock()
	return client
}

func (s *adminAPIServer) removeClient(id uint64) {
	s.mu.Lock()
	delete(s.clients, id)
	s.mu.Unlock()
}

func (s *adminAPIServer) setClientSubscriptions(id uint64, eventTypes []adminapi.EventType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[id]
	if !ok {
		return
	}
	client.eventTypes = make(map[adminapi.EventType]bool, len(eventTypes))
	for _, eventType := range eventTypes {
		client.eventTypes[eventType] = true
	}
}

func (s *adminAPIServer) clientSnapshot() []adminapi.ClientInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]uint64, 0, len(s.clients))
	for id := range s.clients {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})

	out := make([]adminapi.ClientInfo, 0, len(ids))
	for _, id := range ids {
		client := s.clients[id]
		out = append(out, adminapi.ClientInfo{
			ID:         client.id,
			Owner:      client.owner,
			PID:        client.peer.PID,
			UID:        client.peer.UID,
			GID:        client.peer.GID,
			EventTypes: sortedEventTypes(client.eventTypes),
		})
	}
	return out
}

func (s *adminAPIServer) notify(eventType adminapi.EventType) {
	s.mu.Lock()
	clients := make([]*adminAPIClient, 0, len(s.clients))
	for _, client := range s.clients {
		if client.eventTypes[eventType] {
			clients = append(clients, client)
		}
	}
	s.mu.Unlock()
	if len(clients) == 0 {
		return
	}

	msg := adminapi.EventMessage{EventType: eventType, Config: s.configSnapshot()}
	for _, client := range clients {
		if err := client.send(msg); err != nil {
			log.Printf("Admin API write %s event for pid=%d uid=%d gid=%d: %s", eventType, client.peer.PID, client.peer.UID, client.peer.GID, err)
		}
	}
}

func (c *adminAPIClient) send(msg adminapi.Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return adminapi.WriteMessage(c.eventWriter, msg)
}

func sortedEventTypes(values map[adminapi.EventType]bool) []adminapi.EventType {
	if len(values) == 0 {
		return nil
	}
	out := make([]adminapi.EventType, 0, len(values))
	for eventType := range values {
		out = append(out, eventType)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func (s *adminAPIServer) handleMutation(owner string, req adminapi.MutationRequest) adminapi.MutationResult {
	if req.Target == "tmp_ruleset" {
		if s.mutateTmpRuleset == nil {
			return adminapi.MutationResult{OK: false, Error: "temporary rulesets are not available", Config: s.configSnapshot()}
		}
		return s.mutateTmpRuleset(owner, req)
	}
	return s.mutateConfig(req)
}

func adminAPIPeerCred(conn *net.UnixConn) (adminAPIPeer, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return adminAPIPeer{}, err
	}

	var cred *unix.Ucred
	var controlErr error
	if err := rawConn.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return adminAPIPeer{}, err
	}
	if controlErr != nil {
		return adminAPIPeer{}, controlErr
	}
	if cred == nil {
		return adminAPIPeer{}, errors.New("SO_PEERCRED returned nil credentials")
	}
	return adminAPIPeer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

func adminAPIClientAllowed(peer adminAPIPeer, rules adminAPIAuthRules) (bool, string, error) {
	var firstErr error
	for _, uid := range rules.UIDs {
		if peer.UID == uid {
			return true, fmt.Sprintf("uid:%d", uid), nil
		}
	}
	for _, username := range rules.Usernames {
		u, err := user.Lookup(username)
		if err != nil {
			firstErr = keepFirstErr(firstErr, fmt.Errorf("lookup username %q: %w", username, err))
			continue
		}
		uid, err := parseUserID(u.Uid)
		if err != nil {
			firstErr = keepFirstErr(firstErr, fmt.Errorf("parse uid for username %q: %w", username, err))
			continue
		}
		if peer.UID == uid {
			return true, "username:" + username, nil
		}
	}

	groups, err := adminAPIClientGroups(peer)
	if err != nil {
		firstErr = keepFirstErr(firstErr, err)
	}
	for _, gid := range rules.GIDs {
		if groups[gid] {
			return true, fmt.Sprintf("gid:%d", gid), nil
		}
	}
	for _, groupname := range rules.Groupnames {
		g, err := user.LookupGroup(groupname)
		if err != nil {
			firstErr = keepFirstErr(firstErr, fmt.Errorf("lookup groupname %q: %w", groupname, err))
			continue
		}
		gid, err := parseGroupID(g.Gid)
		if err != nil {
			firstErr = keepFirstErr(firstErr, fmt.Errorf("parse gid for groupname %q: %w", groupname, err))
			continue
		}
		if groups[gid] {
			return true, "groupname:" + groupname, nil
		}
	}
	return false, "", firstErr
}

func adminAPIClientGroups(peer adminAPIPeer) (map[uint32]bool, error) {
	groups := map[uint32]bool{peer.GID: true}

	u, err := user.LookupId(strconv.FormatUint(uint64(peer.UID), 10))
	if err != nil {
		return groups, fmt.Errorf("lookup uid %d: %w", peer.UID, err)
	}
	groupIDs, err := u.GroupIds()
	if err != nil {
		return groups, fmt.Errorf("list groups for uid %d: %w", peer.UID, err)
	}
	for _, raw := range groupIDs {
		gid, err := parseGroupID(raw)
		if err != nil {
			return groups, fmt.Errorf("parse supplementary gid %q for uid %d: %w", raw, peer.UID, err)
		}
		groups[gid] = true
	}
	return groups, nil
}

func parseUserID(raw string) (uint32, error) {
	return parseUint32ID(raw)
}

func parseGroupID(raw string) (uint32, error) {
	return parseUint32ID(raw)
}

func parseUint32ID(raw string) (uint32, error) {
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

func keepFirstErr(first error, next error) error {
	if first != nil {
		return first
	}
	return next
}

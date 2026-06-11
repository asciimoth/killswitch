//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestAdminAPIOptionsDefault(t *testing.T) {
	opts, err := configToOptions(configFile{InterfaceNames: []string{"eth0"}})
	if err != nil {
		t.Fatalf("config to options: %v", err)
	}
	if opts.AdminAPI.SocketPath != defaultAdminAPISocketPath {
		t.Fatalf("socket path = %q", opts.AdminAPI.SocketPath)
	}
	if len(opts.AdminAPI.Auth.Groupnames) != 1 || opts.AdminAPI.Auth.Groupnames[0] != defaultAdminAPIGroup {
		t.Fatalf("auth rules = %+v", opts.AdminAPI.Auth)
	}
}

func TestAdminAPIOptionsFromConfig(t *testing.T) {
	opts, err := configToOptions(configFile{
		InterfaceNames: []string{"eth0"},
		AdminAPI: adminAPIConfig{
			SocketPath: "/tmp/killswitch-admin.sock",
			Auth: adminAPIAuthConfig{
				UIDs:       []uint32{1000},
				GIDs:       []uint32{1001},
				Usernames:  []string{"alice"},
				Groupnames: []string{"wheel"},
			},
		},
	})
	if err != nil {
		t.Fatalf("config to options: %v", err)
	}
	if opts.AdminAPI.SocketPath != "/tmp/killswitch-admin.sock" {
		t.Fatalf("socket path = %q", opts.AdminAPI.SocketPath)
	}
	if len(opts.AdminAPI.Auth.Groupnames) != 1 || opts.AdminAPI.Auth.Groupnames[0] != "wheel" {
		t.Fatalf("auth rules = %+v", opts.AdminAPI.Auth)
	}
}

func TestAdminAPIOptionsValidation(t *testing.T) {
	tests := []configFile{
		{InterfaceNames: []string{"eth0"}, AdminAPI: adminAPIConfig{SocketPath: "relative.sock"}},
		{InterfaceNames: []string{"eth0"}, AdminAPI: adminAPIConfig{Auth: adminAPIAuthConfig{Usernames: []string{""}}}},
		{InterfaceNames: []string{"eth0"}, AdminAPI: adminAPIConfig{Auth: adminAPIAuthConfig{Groupnames: []string{""}}}},
	}

	for _, cfg := range tests {
		if _, err := configToOptions(cfg); err == nil {
			t.Fatalf("configToOptions(%+v) succeeded, expected error", cfg)
		}
	}
}

func TestAdminAPIClientAllowedByUID(t *testing.T) {
	allowed, reason, err := adminAPIClientAllowed(adminAPIPeer{UID: 42, GID: 100}, adminAPIAuthRules{UIDs: []uint32{42}})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if !allowed || reason != "uid:42" {
		t.Fatalf("allowed=%t reason=%q", allowed, reason)
	}
}

func TestAdminAPIClientAllowedByPrimaryGIDWhenUserLookupFails(t *testing.T) {
	allowed, reason, err := adminAPIClientAllowed(adminAPIPeer{UID: 4_294_967_294, GID: 123}, adminAPIAuthRules{GIDs: []uint32{123}})
	if err != nil {
		t.Fatalf("auth should allow despite uid lookup error: %v", err)
	}
	if !allowed || reason != "gid:123" {
		t.Fatalf("allowed=%t reason=%q", allowed, reason)
	}
}

func TestAdminAPIClientAllowedByCurrentUsernameAndGroupname(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	uid, err := parseUserID(current.Uid)
	if err != nil {
		t.Fatalf("parse current uid: %v", err)
	}
	gid, err := parseGroupID(current.Gid)
	if err != nil {
		t.Fatalf("parse current gid: %v", err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatalf("lookup current group: %v", err)
	}

	allowed, reason, err := adminAPIClientAllowed(adminAPIPeer{UID: uid, GID: gid}, adminAPIAuthRules{Usernames: []string{current.Username}})
	if err != nil {
		t.Fatalf("username auth: %v", err)
	}
	if !allowed || reason != "username:"+current.Username {
		t.Fatalf("allowed=%t reason=%q", allowed, reason)
	}

	allowed, reason, err = adminAPIClientAllowed(adminAPIPeer{UID: uid, GID: gid}, adminAPIAuthRules{Groupnames: []string{group.Name}})
	if err != nil {
		t.Fatalf("groupname auth: %v", err)
	}
	if !allowed || reason != "groupname:"+group.Name {
		t.Fatalf("allowed=%t reason=%q", allowed, reason)
	}
}

func TestAdminAPIClientAllowedContinuesAfterMissingName(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	uid, err := parseUserID(current.Uid)
	if err != nil {
		t.Fatalf("parse current uid: %v", err)
	}
	allowed, reason, err := adminAPIClientAllowed(adminAPIPeer{UID: uid}, adminAPIAuthRules{
		Usernames: []string{"killswitch-test-user-does-not-exist", current.Username},
	})
	if err != nil {
		t.Fatalf("auth should allow despite earlier lookup error: %v", err)
	}
	if !allowed || reason != "username:"+current.Username {
		t.Fatalf("allowed=%t reason=%q", allowed, reason)
	}
}

func TestListenAdminAPIUnixSocketPermissions(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "nested", "admin.sock")
	listener, err := listenAdminAPIUnix(socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode = %v", info.Mode().Perm())
	}

	dirInfo, err := os.Stat(filepath.Dir(socketPath))
	if err != nil {
		t.Fatalf("stat socket dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o755 {
		t.Fatalf("socket dir mode = %v", dirInfo.Mode().Perm())
	}
}

func TestListenAdminAPIUnixRejectsWritableSocketDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}
	defer os.Chmod(dir, 0o700) //nolint:errcheck

	listener, err := listenAdminAPIUnix(filepath.Join(dir, "admin.sock"))
	if err == nil {
		_ = listener.Close()
		t.Fatal("listen succeeded, expected writable directory error")
	}
}

func TestAdminAPIPeerCred(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := listenAdminAPIUnix(socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close() //nolint:errcheck

		peer, err := adminAPIPeerCred(conn)
		if err != nil {
			errCh <- err
			return
		}
		if peer.UID != uint32(os.Getuid()) || peer.GID != uint32(os.Getgid()) || peer.PID <= 0 {
			errCh <- &peerCredMismatchError{peer: peer}
			return
		}
		errCh <- nil
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = client.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("peer cred: %v", err)
	}
}

type peerCredMismatchError struct {
	peer adminAPIPeer
}

func (e *peerCredMismatchError) Error() string {
	return fmt.Sprintf("unexpected peer credentials: %+v", e.peer)
}

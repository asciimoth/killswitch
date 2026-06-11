package adminapi

import (
	"encoding/json"
	"net"
	"testing"
)

func TestWaitForConfigIgnoresOtherMessages(t *testing.T) {
	server, clientConn := net.Pipe()
	defer clientConn.Close() //nolint:errcheck

	errCh := make(chan error, 1)
	go func() {
		defer server.Close() //nolint:errcheck
		encoder := json.NewEncoder(server)
		if err := encoder.Encode(Envelope{Type: "future_message", Payload: json.RawMessage(`{"ignored":true}`)}); err != nil {
			errCh <- err
			return
		}
		errCh <- WriteMessage(encoder, ConfigMessage{Config: CurrentConfig{
			AdminAPI: AdminConfig{SocketPath: "/tmp/killswitch.sock"},
			BasePolicy: AllowRules{
				EnableV4: true,
				EnableV6: true,
			},
			EffectivePolicy: AllowRules{
				AllowAll: true,
				EnableV4: true,
				EnableV6: true,
			},
		}})
	}()

	cfg, err := NewClient(clientConn).WaitForConfig()
	if err != nil {
		t.Fatalf("wait for config: %v", err)
	}
	if cfg.AdminAPI.SocketPath != "/tmp/killswitch.sock" {
		t.Fatalf("socket path = %q", cfg.AdminAPI.SocketPath)
	}
	if !cfg.EffectivePolicy.AllowAll || !cfg.EffectivePolicy.EnableV4 || !cfg.EffectivePolicy.EnableV6 {
		t.Fatalf("effective policy = %+v", cfg.EffectivePolicy)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server write: %v", err)
	}
}

func TestWaitForEventIgnoresOtherMessages(t *testing.T) {
	server, clientConn := net.Pipe()
	defer clientConn.Close() //nolint:errcheck

	errCh := make(chan error, 1)
	go func() {
		defer server.Close() //nolint:errcheck
		encoder := json.NewEncoder(server)
		if err := WriteMessage(encoder, ConfigMessage{}); err != nil {
			errCh <- err
			return
		}
		errCh <- WriteMessage(encoder, EventMessage{
			EventType: EventTypeInterfaces,
			Config: CurrentConfig{
				Interfaces: []Interface{{Name: "wg0", Type: "wireguard", Matched: true, Killswitch: true}},
			},
		})
	}()

	event, err := NewClient(clientConn).WaitForEvent()
	if err != nil {
		t.Fatalf("wait for event: %v", err)
	}
	if event.EventType != EventTypeInterfaces {
		t.Fatalf("event type = %q", event.EventType)
	}
	if len(event.Config.Interfaces) != 1 || !event.Config.Interfaces[0].Killswitch {
		t.Fatalf("interfaces = %+v", event.Config.Interfaces)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server write: %v", err)
	}
}

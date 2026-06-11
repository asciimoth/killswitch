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

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

func TestPrintConfigIncludesTemporaryRulesets(t *testing.T) {
	var out bytes.Buffer
	err := printConfig(&out, adminapi.CurrentConfig{
		BasePolicy:      adminapi.AllowRules{EnableV4: true},
		EffectivePolicy: adminapi.AllowRules{EnableV4: true, EnableV6: true},
		Interfaces: []adminapi.Interface{
			{
				Index:      7,
				Name:       "wg0",
				Type:       "wireguard",
				Addrs:      []string{"10.64.0.2"},
				Matched:    true,
				Killswitch: true,
			},
		},
		TemporaryRulesets: []adminapi.TmpRuleset{
			{
				Client: "pid=100 uid=1000 gid=1000 conn=1",
				Policy: adminapi.AllowRules{
					EnableV6:       true,
					AllowedV6Hosts: []string{"2001:db8::10"},
				},
			},
		},
		ForceActiveRulesets: []adminapi.ForceRuleset{
			{
				Name:    "office",
				Clients: []string{"pid=100 uid=1000 gid=1000 conn=1", "pid=101 uid=1000 gid=1000 conn=2"},
			},
		},
		Rulesets: []adminapi.Ruleset{
			{
				Name:     "office",
				Disabled: true,
				Priority: 20,
				Trigger:  adminapi.RulesetTrigger{InterfaceNames: []string{"wg0"}},
				Policy:   adminapi.AllowRules{EnableV4: true},
			},
		},
		Clients: []adminapi.ClientInfo{
			{
				ID:         1,
				Owner:      "pid=100 uid=1000 gid=1000 conn=1",
				PID:        100,
				UID:        1000,
				GID:        1000,
				EventTypes: []adminapi.EventType{adminapi.EventTypeConfig, adminapi.EventTypeInterfaces},
			},
		},
		AdminAPI: adminapi.AdminConfig{SocketPath: "/tmp/killswitch.sock"},
	})
	if err != nil {
		t.Fatalf("print config: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"Temporary rulesets",
		"client=pid=100 uid=1000 gid=1000 conn=1",
		"allowed v6 hosts:",
		"2001:db8::10",
		"Force-active rulesets",
		"clients=pid=100 uid=1000 gid=1000 conn=1, pid=101 uid=1000 gid=1000 conn=2",
		"Rulesets",
		"office:",
		"disabled=true",
		"wg0:",
		"matched=true",
		"killswitch=true",
		"Clients",
		"events:",
		"config, interfaces",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestWaitForStopInputStopsOnEscapeAndEOF(t *testing.T) {
	if err := waitForStopInput(strings.NewReader("\x1b")); err != nil {
		t.Fatalf("escape stop: %v", err)
	}
	if err := waitForStopInput(strings.NewReader("")); err != nil {
		t.Fatalf("eof stop: %v", err)
	}
}

func TestMutationRequestFromArgsAddsNamedRuleset(t *testing.T) {
	raw := `{"priority":100,"trigger":{"interface_names":["wg0"]},"policy":{"enable_v4":true}}`
	req, socketPath, err := mutationRequestFromArgs(adminapi.MutationAdd, []string{
		"-socket", "/tmp/killswitch-test.sock",
		"-target", "ruleset",
		"-ruleset", "wireguard-up",
		"-json", raw,
	}, ioDiscard{})
	if err != nil {
		t.Fatalf("mutation request: %v", err)
	}
	if socketPath != "/tmp/killswitch-test.sock" {
		t.Fatalf("socket path = %q", socketPath)
	}
	if req.Operation != adminapi.MutationAdd || req.Target != "ruleset" || req.Ruleset != "wireguard-up" {
		t.Fatalf("request metadata = %+v", req)
	}
	if len(req.Values) != 0 {
		t.Fatalf("values = %+v", req.Values)
	}
	if !json.Valid(req.Value) || string(req.Value) != raw {
		t.Fatalf("value = %s", req.Value)
	}
}

func TestMutationRequestFromArgsRemovesNamedRuleset(t *testing.T) {
	req, _, err := mutationRequestFromArgs(adminapi.MutationRemove, []string{
		"-target", "ruleset",
		"-ruleset", "wireguard-up",
	}, ioDiscard{})
	if err != nil {
		t.Fatalf("mutation request: %v", err)
	}
	if req.Operation != adminapi.MutationRemove || req.Target != "ruleset" || req.Ruleset != "wireguard-up" {
		t.Fatalf("request metadata = %+v", req)
	}
	if len(req.Values) != 0 || len(req.Value) != 0 {
		t.Fatalf("unexpected request payload: values=%+v value=%s", req.Values, req.Value)
	}
}

func TestMutationRequestFromArgsValidatesWholeRulesetMutations(t *testing.T) {
	tests := []struct {
		name string
		op   adminapi.MutationOperation
		args []string
		want string
	}{
		{
			name: "add requires json",
			op:   adminapi.MutationAdd,
			args: []string{"-target", "ruleset", "-ruleset", "wireguard-up"},
			want: "add -target ruleset requires -json JSON or -json @FILE",
		},
		{
			name: "remove rejects json",
			op:   adminapi.MutationRemove,
			args: []string{"-target", "ruleset", "-ruleset", "wireguard-up", "-json", "{}"},
			want: "remove -target ruleset does not accept -json",
		},
		{
			name: "remove rejects values",
			op:   adminapi.MutationRemove,
			args: []string{"-target", "ruleset", "-ruleset", "wireguard-up", "extra"},
			want: "remove -target ruleset expects no positional arguments, got: extra",
		},
		{
			name: "requires name",
			op:   adminapi.MutationRemove,
			args: []string{"-target", "ruleset"},
			want: "ruleset mutations require -ruleset NAME",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := mutationRequestFromArgs(tt.op, tt.args, ioDiscard{})
			if err == nil {
				t.Fatal("mutation request succeeded, expected error")
			}
			if err.Error() != tt.want {
				t.Fatalf("error = %q, want %q", err, tt.want)
			}
		})
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
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
				Index: 7,
				Name:  "wg0",
				Type:  "wireguard",
				Addrs: []string{"10.64.0.2"},
				SSID:  "Office WiFi",
				BSSID: "aa:bb:cc:dd:ee:ff",
				GatewayMACs: []string{
					"00:11:22:33:44:55",
				},
				Matched:    true,
				Killswitch: true,
			},
		},
		EffectiveInterfaces: []adminapi.InterfacePolicy{
			{
				Index:             7,
				Name:              "wg0",
				Type:              "wireguard",
				SSID:              "Office WiFi",
				BSSID:             "aa:bb:cc:dd:ee:ff",
				GatewayMACs:       []string{"00:11:22:33:44:55"},
				Matched:           true,
				Attached:          true,
				EffectivePolicy:   adminapi.AllowRules{EnableV4: true, EnableV6: true},
				ActiveRulesets:    []string{"office"},
				ForcedRulesets:    []string{"office"},
				TemporaryRulesets: []string{"pid=100 uid=1000 gid=1000 conn=1"},
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
				Trigger: adminapi.RulesetTrigger{
					InterfaceNames: []string{"wg0"},
					SSIDs:          []string{"Office WiFi"},
					BSSIDs:         []string{"aa:bb:cc:dd:ee:ff"},
					GatewayMACs:    []string{"00:11:22:33:44:55"},
				},
				Policy: adminapi.AllowRules{EnableV4: true},
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
		"ssid:",
		"Office WiFi",
		"bssid:",
		"aa:bb:cc:dd:ee:ff",
		"gateway MACs:",
		"00:11:22:33:44:55",
		"matched=true",
		"attached=true",
		"trigger SSIDs:",
		"trigger BSSIDs:",
		"trigger gateway MACs:",
		"active rulesets:",
		"forced rulesets:",
		"temporary rulesets:",
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

func TestTopLevelHelpIncludesMutationTargets(t *testing.T) {
	var stdout bytes.Buffer
	err := runCLI([]string{"--help"}, &stdout, ioDiscard{})
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	got := stdout.String()
	for _, want := range []string{
		"Available mutation targets:",
		"interface_types, interface_names, interface_regexps",
		"base_policy.allowed_v4_hostports, base_policy.allowed_v6_hostports",
		"ruleset.trigger.gateway_macs",
		"ruleset.policy.allowed_v4_hostports, ruleset.policy.allowed_v6_hostports",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help output missing %q:\n%s", want, got)
		}
	}
}

func TestMutationHelpIncludesTargets(t *testing.T) {
	var stderr bytes.Buffer
	err := runCLI([]string{"add", "--help"}, ioDiscard{}, &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help err = %v, want %v", err, flag.ErrHelp)
	}
	got := stderr.String()
	for _, want := range []string{
		"Usage:",
		"killswitch-cli add",
		"Available mutation targets:",
		"ruleset (requires -ruleset NAME)",
		"ruleset.trigger.bssids, ruleset.trigger.gateway_macs",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help output missing %q:\n%s", want, got)
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
	raw := `{"trigger":{"interface_names":["wg0"]},"policy":{"enable_v4":true}}`
	req, socketPath, jsonOut, err := mutationRequestFromArgs(adminapi.MutationAdd, []string{
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
	if jsonOut {
		t.Fatal("jsonOut = true, want false")
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
	req, _, _, err := mutationRequestFromArgs(adminapi.MutationRemove, []string{
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
			_, _, _, err := mutationRequestFromArgs(tt.op, tt.args, ioDiscard{})
			if err == nil {
				t.Fatal("mutation request succeeded, expected error")
			}
			if err.Error() != tt.want {
				t.Fatalf("error = %q, want %q", err, tt.want)
			}
		})
	}
}

func TestMutationRequestFromArgsParsesJSONOut(t *testing.T) {
	_, _, jsonOut, err := mutationRequestFromArgs(adminapi.MutationSet, []string{
		"-target", "base_policy.enable_v4",
		"true",
		"--json-out",
	}, ioDiscard{})
	if err != nil {
		t.Fatalf("mutation request: %v", err)
	}
	if !jsonOut {
		t.Fatal("jsonOut = false, want true")
	}
}

func TestPrintJSONLineIsCompactSingleLine(t *testing.T) {
	var out bytes.Buffer
	err := printJSONLine(&out, configUpdate{
		EventType: adminapi.EventTypeConfig,
		Config: adminapi.CurrentConfig{
			InterfaceNames:  []string{"wg0"},
			EffectivePolicy: adminapi.AllowRules{EnableV4: true},
			AdminAPI:        adminapi.AdminConfig{SocketPath: "/tmp/killswitch.sock"},
		},
	})
	if err != nil {
		t.Fatalf("print json line: %v", err)
	}

	got := out.String()
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("output is not one JSON line: %q", got)
	}
	if strings.Contains(got, " ") {
		t.Fatalf("output is not compact: %q", got)
	}
	var decoded configUpdate
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if decoded.EventType != adminapi.EventTypeConfig || len(decoded.Config.InterfaceNames) != 1 || decoded.Config.InterfaceNames[0] != "wg0" {
		t.Fatalf("decoded output = %+v", decoded)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

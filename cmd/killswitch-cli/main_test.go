package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/asciimoth/killswitch/internal/adminapi"
)

func TestPrintConfigIncludesTemporaryRulesets(t *testing.T) {
	var out bytes.Buffer
	err := printConfig(&out, adminapi.CurrentConfig{
		BasePolicy:      adminapi.AllowRules{EnableV4: true},
		EffectivePolicy: adminapi.AllowRules{EnableV4: true, EnableV6: true},
		TemporaryRulesets: []adminapi.TmpRuleset{
			{
				Client: "pid=100 uid=1000 gid=1000 conn=1",
				Policy: adminapi.AllowRules{
					EnableV6:       true,
					AllowedV6Hosts: []string{"2001:db8::10"},
				},
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

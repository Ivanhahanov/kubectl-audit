package cli

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/internal/suppress"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
)

func TestEffectiveExclusions_DisableBuiltinExceptionIDs(t *testing.T) {
	cfg := &config.AuditConfig{
		DisableBuiltinExceptionIDs: []string{"cilium-agent"},
	}
	got := effectiveExclusions(cfg)

	for _, r := range got {
		if r.ID == "cilium-agent" {
			t.Fatalf("expected cilium-agent rule to be filtered out, got %+v", got)
		}
	}
	found := map[string]bool{}
	for _, r := range got {
		found[r.ID] = true
	}
	for _, id := range []string{"prometheus-node-exporter", "kube-proxy", "control-plane-static-pods"} {
		if !found[id] {
			t.Errorf("expected %q to still be present, got %+v", id, got)
		}
	}
	if len(got) != len(suppress.BuiltinRules())-1 {
		t.Errorf("expected exactly one built-in rule removed, got %d rules (builtin has %d)", len(got), len(suppress.BuiltinRules()))
	}
}

func TestEffectiveExclusions_UnknownIDIsNoop(t *testing.T) {
	cfg := &config.AuditConfig{
		DisableBuiltinExceptionIDs: []string{"does-not-exist"},
	}
	got := effectiveExclusions(cfg)
	if len(got) != len(suppress.BuiltinRules()) {
		t.Errorf("expected an unknown id to be a no-op, got %d rules (builtin has %d)", len(got), len(suppress.BuiltinRules()))
	}
}

func TestEffectiveExclusions_DisableWholesaleWinsOverIDs(t *testing.T) {
	cfg := &config.AuditConfig{
		DisableBuiltinExceptions:   true,
		DisableBuiltinExceptionIDs: []string{"cilium-agent"},
		Exclusions:                 []config.ExclusionRule{{Reason: "user rule", Match: config.ExclusionMatch{Kind: "Deployment"}}},
	}
	got := effectiveExclusions(cfg)
	if len(got) != 1 || got[0].Reason != "user rule" {
		t.Errorf("expected only the user's own rule when DisableBuiltinExceptions is set, got %+v", got)
	}
}

func TestEffectiveComponents_MergesExtra(t *testing.T) {
	cfg := &config.AuditConfig{
		Components: config.ComponentsConfig{
			Extra: []thirdparty.Component{
				{Name: "InternalOperator", Category: thirdparty.CategoryApplication, Group: "internal.example.com"},
			},
		},
	}
	got := effectiveComponents(cfg)
	if len(got) != len(thirdparty.Known)+1 {
		t.Fatalf("expected Known + 1 extra, got %d (Known has %d)", len(got), len(thirdparty.Known))
	}
	if got[len(got)-1].Name != "InternalOperator" {
		t.Errorf("expected the extra component appended last, got %+v", got[len(got)-1])
	}
	// Known itself must be untouched by the merge.
	if len(thirdparty.Known) == 0 {
		t.Fatal("thirdparty.Known unexpectedly empty")
	}
}

func TestEffectiveComponents_NoExtraReturnsKnown(t *testing.T) {
	got := effectiveComponents(&config.AuditConfig{})
	if len(got) != len(thirdparty.Known) {
		t.Errorf("expected exactly Known with no extras configured, got %d (Known has %d)", len(got), len(thirdparty.Known))
	}
}

package cli

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
)

// TestScanScope_ClusterNameAppliesRegardlessOfMode is the regression test
// for a real bug found while wiring findings.ScopeFindingIDs: loadResources
// only folds cfg.Target.ClusterName into target for cluster/both modes —
// a static-only scan's target is always "static:<paths>", with no cluster
// identity in it at all, so two different clusters' exported/rendered
// manifests scanned with -f and different --cluster-name values would
// still scope to the exact same value and collide. scanScope must apply
// ClusterName as an override in every mode, not just cluster/both.
func TestScanScope_ClusterNameAppliesRegardlessOfMode(t *testing.T) {
	cfg := &config.AuditConfig{}
	cfg.Target.Mode = config.ModeStatic
	cfg.Target.ClusterName = "cluster-a"

	got := scanScope(cfg, "static:/manifests")
	if got != "cluster:cluster-a" {
		t.Errorf("expected ClusterName to override scope even in static mode, got %q", got)
	}

	cfg.Target.ClusterName = "cluster-b"
	got2 := scanScope(cfg, "static:/manifests")
	if got == got2 {
		t.Errorf("expected different ClusterName values to produce different scopes, both got %q", got)
	}
}

// TestScanScope_FallsBackToTargetWhenClusterNameUnset guards the common
// case (no --cluster-name set): scope falls back to target as-is, which
// already threads the live cluster's context name through for
// cluster/both modes via loadResources.
func TestScanScope_FallsBackToTargetWhenClusterNameUnset(t *testing.T) {
	cfg := &config.AuditConfig{}
	cfg.Target.Mode = config.ModeCluster

	if got := scanScope(cfg, "cluster:my-context"); got != "cluster:my-context" {
		t.Errorf("expected scope to fall back to target unchanged, got %q", got)
	}
}

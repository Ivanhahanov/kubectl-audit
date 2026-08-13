package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
)

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

func TestLoad_ExclusionRequiresReason(t *testing.T) {
	path := writeConfig(t, `
exclusions:
  - match:
      name: legacy-app
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected an error for an exclusion rule with no reason")
	}
}

func TestLoad_ExclusionRequiresMatch(t *testing.T) {
	path := writeConfig(t, `
exclusions:
  - reason: "no match fields at all"
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected an error for an exclusion rule with an empty match")
	}
}

func TestLoad_ValidExclusion(t *testing.T) {
	path := writeConfig(t, `
exclusions:
  - policyIds: ["workload.no-latest-tag"]
    match:
      name: "legacy-*"
    reason: "legacy app, JIRA-1234"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Exclusions) != 1 || cfg.Exclusions[0].Reason != "legacy app, JIRA-1234" {
		t.Fatalf("expected the exclusion rule to load, got %+v", cfg.Exclusions)
	}
}

package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
)

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

// TestDefault_NamespaceGroupThresholdIsOnByDefault guards that the
// multi-tenant report-noise-reduction feature (collapsing a check's
// repeated Kind/Name findings across many namespaces — see
// OutputConfig.NamespaceGroupThreshold) is actually enabled out of the
// box, not opt-in.
func TestDefault_NamespaceGroupThresholdIsOnByDefault(t *testing.T) {
	if got := config.Default().Output.NamespaceGroupThreshold; got <= 0 {
		t.Errorf("expected a positive default NamespaceGroupThreshold (collapsing on by default), got %d", got)
	}
	if !config.Default().Output.GroupByNamePatternEnabled() {
		t.Error("expected GroupByNamePattern to be enabled by default")
	}
}

// TestDefault_TriageStateFileHasADefault guards that `kubectl audit triage`
// works out of the box without requiring a --state flag or audit.yaml
// entry first.
func TestDefault_TriageStateFileHasADefault(t *testing.T) {
	if config.Default().Triage.StateFile == "" {
		t.Error("expected a default Triage.StateFile")
	}
}

// TestDefault_JiraConfigHasNoCredentialField is a structural guard, not a
// runtime one: JiraConfig must never grow a token/credential field, since
// audit.yaml is a git-committable file — the PAT belongs in a flag/env var
// only (see internal/config's JiraConfig doc comment).
func TestDefault_JiraConfigHasNoCredentialField(t *testing.T) {
	typ := reflect.TypeOf(config.JiraConfig{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, bad := range []string{"token", "password", "secret", "credential", "apikey", "pat"} {
			if strings.Contains(name, bad) {
				t.Errorf("JiraConfig has a field named %q — credentials must come from a flag/env var, never audit.yaml", typ.Field(i).Name)
			}
		}
	}
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

func TestLoad_ExclusionRejectsInvalidNameGlob(t *testing.T) {
	path := writeConfig(t, `
exclusions:
  - match:
      name: "legacy-["
    reason: "unterminated character class"
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error for an unterminated glob character class in match.name")
	}
	if !strings.Contains(err.Error(), "not a valid glob pattern") {
		t.Errorf("expected the error to name the glob-syntax problem, got: %v", err)
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

func TestLoad_ExtraComponentRequiresGroupOrLabels(t *testing.T) {
	path := writeConfig(t, `
components:
  extra:
    - name: InternalOperator
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected an error for an extra component with neither group nor labels")
	}
}

func TestLoad_ExtraComponentRequiresName(t *testing.T) {
	path := writeConfig(t, `
components:
  extra:
    - group: internal.example.com
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected an error for an extra component with no name")
	}
}

func TestLoad_ValidExtraComponent_DefaultsCategoryToApplication(t *testing.T) {
	path := writeConfig(t, `
components:
  extra:
    - name: InternalOperator
      group: internal.example.com
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Components.Extra) != 1 {
		t.Fatalf("expected 1 extra component, got %+v", cfg.Components.Extra)
	}
	if got := cfg.Components.Extra[0].Category; got != thirdparty.CategoryApplication {
		t.Errorf("expected Category to default to Application, got %q", got)
	}
}

func TestLoad_ValidExtraComponent_ExplicitCategoryPreserved(t *testing.T) {
	path := writeConfig(t, `
components:
  extra:
    - name: InternalCNI
      category: System
      labels:
        k8s-app: internal-cni
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Components.Extra[0].Category; got != thirdparty.CategorySystem {
		t.Errorf("expected explicit Category to be preserved, got %q", got)
	}
}

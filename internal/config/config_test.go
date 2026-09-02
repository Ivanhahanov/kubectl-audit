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

// TestAutoLabelsConfig_DefaultsAllOnUnsetFields guards that AutoLabels is
// on by default — a nil field (never mentioned in audit.yaml) must behave
// as true, not false, matching every other on-by-default *bool convention
// in this package (see OutputConfig.GroupByNamePattern).
func TestAutoLabelsConfig_DefaultsAllOnUnsetFields(t *testing.T) {
	var a config.AutoLabelsConfig
	if !a.ToolEnabled() || !a.SeverityEnabled() || !a.CategoryEnabled() {
		t.Errorf("expected all three AutoLabelsConfig fields to default to enabled, got Tool=%v Severity=%v Category=%v",
			a.ToolEnabled(), a.SeverityEnabled(), a.CategoryEnabled())
	}
}

// TestLoad_AutoLabelsPerFieldOverride is the actual feature: a Jira
// project that wants to drop just the severity label (e.g. it already
// tracks severity in a dedicated field) without losing the others.
func TestLoad_AutoLabelsPerFieldOverride(t *testing.T) {
	path := writeConfig(t, `
triage:
  jira:
    autoLabels:
      severity: false
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Triage.Jira.AutoLabels.ToolEnabled() {
		t.Error("expected Tool to stay enabled (not mentioned in the config)")
	}
	if cfg.Triage.Jira.AutoLabels.SeverityEnabled() {
		t.Error("expected Severity to be disabled per the config")
	}
	if !cfg.Triage.Jira.AutoLabels.CategoryEnabled() {
		t.Error("expected Category to stay enabled (not mentioned in the config)")
	}
}

// TestLoad_UnknownFieldIsRejected guards against the class of bug where a
// typo'd config field (e.g. "namespceGroupThreshold") is silently dropped
// by a lenient YAML unmarshal, leaving the tool running on a default the
// user never intended with no indication anything was ignored — a real
// risk for a security tool's config.
func TestLoad_UnknownFieldIsRejected(t *testing.T) {
	path := writeConfig(t, `
output:
  namespceGroupThreshold: 5
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error for an unknown/misspelled config field")
	}
	if !strings.Contains(err.Error(), "namespceGroupThreshold") {
		t.Errorf("expected the error to name the offending field, got: %v", err)
	}
}

// TestLoad_ExpandsHomeTildeInTriagePaths is the fix for the ~/.kubectl-audit/
// convention: a triage path field starting with "~/" should resolve
// against the real home directory (Go's os.ReadFile does no shell-style
// expansion on its own), so an audit.yaml living in ~/.kubectl-audit/ can
// reference sibling files there without spelling out the full absolute
// path.
func TestLoad_ExpandsHomeTildeInTriagePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := writeConfig(t, `
triage:
  stateFile: ~/.kubectl-audit/triage-state.yaml
  knowledgeBaseFile: ~/.kubectl-audit/knowledge-base.yaml
  jira:
    summaryTemplate: ~/.kubectl-audit/summary.tpl
    descriptionTemplate: ~/.kubectl-audit/description.tpl
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := func(rel string) string { return filepath.Join(home, rel) }
	if cfg.Triage.StateFile != want(".kubectl-audit/triage-state.yaml") {
		t.Errorf("StateFile: got %q", cfg.Triage.StateFile)
	}
	if cfg.Triage.KnowledgeBaseFile != want(".kubectl-audit/knowledge-base.yaml") {
		t.Errorf("KnowledgeBaseFile: got %q", cfg.Triage.KnowledgeBaseFile)
	}
	if cfg.Triage.Jira.SummaryTemplate != want(".kubectl-audit/summary.tpl") {
		t.Errorf("Jira.SummaryTemplate: got %q", cfg.Triage.Jira.SummaryTemplate)
	}
	if cfg.Triage.Jira.DescriptionTemplate != want(".kubectl-audit/description.tpl") {
		t.Errorf("Jira.DescriptionTemplate: got %q", cfg.Triage.Jira.DescriptionTemplate)
	}
}

// TestLoad_LeavesNonTildePathsUnchanged guards that ordinary CWD-relative
// paths (the common case — a project's own checked-in audit.yaml) are
// completely unaffected by the "~/" expansion.
func TestLoad_LeavesNonTildePathsUnchanged(t *testing.T) {
	path := writeConfig(t, `
triage:
  knowledgeBaseFile: knowledge-base.yaml
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Triage.KnowledgeBaseFile != "knowledge-base.yaml" {
		t.Errorf("expected a plain relative path to be left untouched, got %q", cfg.Triage.KnowledgeBaseFile)
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

package triage_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

func TestResolve_NoOverridesFallsBackToFinding(t *testing.T) {
	f := mustFinding("f1")
	f.Title = "Original title"
	f.Message = "Original message"
	f.Remediation = "Original remediation"

	rc, err := triage.Resolve(f, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rc.Title != "Original title" || rc.Description != "Original message" || rc.Remediation != "Original remediation" {
		t.Errorf("expected Resolve with no overrides to fall back to the finding's own fields, got %+v", rc)
	}
	if rc.Technical != "" {
		t.Errorf("expected no Technical detail when Description was never overridden, got %q", rc.Technical)
	}
}

func TestResolve_AppliesInlinePolicyKnowledgeBase(t *testing.T) {
	f := mustFinding("f1")
	f.Title = "Original"
	f.KnowledgeBase = &findings.KnowledgeBaseEntry{Title: "Заголовок из политики"}

	rc, err := triage.Resolve(f, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rc.Title != "Заголовок из политики" {
		t.Errorf("expected the policy's own inline knowledge base to apply, got %q", rc.Title)
	}
}

// TestResolve_ExternalFileWinsOverInline is the precedence contract a
// knowledgeBaseFile correction depends on: a user fixing one inline
// knowledge-base entry must actually take effect, not be silently
// shadowed by whatever the policy itself already set.
func TestResolve_ExternalFileWinsOverInline(t *testing.T) {
	f := mustFinding("f1")
	f.KnowledgeBase = &findings.KnowledgeBaseEntry{Title: "Из политики", Remediation: "Из политики (ремедиация)"}
	table := map[string]findings.KnowledgeBaseEntry{f.PolicyID: {Title: "Из knowledgeBaseFile"}}

	rc, err := triage.Resolve(f, table)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rc.Title != "Из knowledgeBaseFile" {
		t.Errorf("expected the external file to override the inline title, got %q", rc.Title)
	}
	if rc.Remediation != "Из политики (ремедиация)" {
		t.Errorf("expected the inline remediation to survive (the file has no override for it), got %q", rc.Remediation)
	}
}

// TestResolve_TechnicalOnlySetWhenDescriptionOverridden is the "don't
// silently hide the tool's own precise detail" guarantee.
func TestResolve_TechnicalOnlySetWhenDescriptionOverridden(t *testing.T) {
	f := mustFinding("f1")
	f.Message = "ServiceAccount x can do y"

	withKB, err := triage.Resolve(f, map[string]findings.KnowledgeBaseEntry{f.PolicyID: {Description: "Наше описание"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if withKB.Description != "Наше описание" {
		t.Errorf("expected the knowledge-base description, got %q", withKB.Description)
	}
	if withKB.Technical != "ServiceAccount x can do y" {
		t.Errorf("expected Technical to carry the original message, got %q", withKB.Technical)
	}

	withoutKB, err := triage.Resolve(f, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if withoutKB.Technical != "" {
		t.Errorf("expected no Technical detail when Description was never overridden, got %q", withoutKB.Technical)
	}
}

// TestResolve_TemplatesResourceNameFromFinding is the "not just theoretical
// text" feature: a knowledge-base field can reference the specific
// resource a finding fired on.
func TestResolve_TemplatesResourceNameFromFinding(t *testing.T) {
	f := mustFinding("f1") // Resource: Deployment default/app (see mustFinding)
	kb := map[string]findings.KnowledgeBaseEntry{
		f.PolicyID: {
			Description: "Ресурс {{.Finding.Resource.Namespace}}/{{.Finding.Resource.Name}} нарушает наш стандарт.",
			Remediation: "Свяжитесь с владельцем {{.Finding.Resource.Kind}} {{.Finding.Resource.Name}}.",
		},
	}
	rc, err := triage.Resolve(f, kb)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rc.Description != "Ресурс default/app нарушает наш стандарт." {
		t.Errorf("expected the resource name/namespace substituted into Description, got %q", rc.Description)
	}
	if rc.Remediation != "Свяжитесь с владельцем Deployment app." {
		t.Errorf("expected the resource kind/name substituted into Remediation, got %q", rc.Remediation)
	}
}

// TestResolve_TemplateErrorDoesNotBlockOtherFields is the "one typo
// degrades gracefully" guarantee — a broken template in one field must not
// blank out the others.
func TestResolve_TemplateErrorDoesNotBlockOtherFields(t *testing.T) {
	f := mustFinding("f1")
	kb := map[string]findings.KnowledgeBaseEntry{
		f.PolicyID: {
			Title:       "{{.Finding.Resource.Name", // malformed — missing closing }}
			Remediation: "Fine remediation text.",
		},
	}
	rc, err := triage.Resolve(f, kb)
	if err == nil {
		t.Fatal("expected an error for the malformed title template")
	}
	if rc.Remediation != "Fine remediation text." {
		t.Errorf("expected the valid remediation field to still resolve despite the title error, got %q", rc.Remediation)
	}
}

func TestLoadKnowledgeBase_EmptyPathReturnsNilNoError(t *testing.T) {
	kb, err := triage.LoadKnowledgeBase("")
	if err != nil {
		t.Fatalf("LoadKnowledgeBase(\"\"): %v", err)
	}
	if kb != nil {
		t.Errorf("expected a nil map for an empty path, got %v", kb)
	}
}

func TestLoadKnowledgeBase_ReadsAndParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "knowledge-base.yaml")
	content := "policy.custom:\n  title: \"Кастомный заголовок\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := triage.LoadKnowledgeBase(path)
	if err != nil {
		t.Fatalf("LoadKnowledgeBase: %v", err)
	}
	if kb["policy.custom"].Title != "Кастомный заголовок" {
		t.Errorf("expected the custom entry to parse, got %+v", kb)
	}
}

func TestDefaultKnowledgeBase_ReturnsNonEmptyMap(t *testing.T) {
	kb, err := triage.DefaultKnowledgeBase()
	if err != nil {
		t.Fatalf("DefaultKnowledgeBase: %v", err)
	}
	if len(kb) == 0 {
		t.Fatal("expected the bundled default to have at least one entry")
	}
	if _, ok := kb["rbac.no-wildcard-rules"]; !ok {
		t.Error("expected rbac.no-wildcard-rules to have a bundled entry")
	}
}

func TestMergeKnowledgeBases_LaterMapWinsFieldByField(t *testing.T) {
	base := map[string]findings.KnowledgeBaseEntry{
		"policy.a": {Title: "Base title", Remediation: "Base remediation"},
	}
	override := map[string]findings.KnowledgeBaseEntry{
		"policy.a": {Title: "Override title"}, // Remediation left empty
	}
	merged := triage.MergeKnowledgeBases(base, override)
	if merged["policy.a"].Title != "Override title" {
		t.Errorf("expected the later map's title to win, got %q", merged["policy.a"].Title)
	}
	if merged["policy.a"].Remediation != "Base remediation" {
		t.Errorf("expected the base remediation to survive (override left it empty), got %q", merged["policy.a"].Remediation)
	}
}

// TestResolveKnowledgeBase_AppliesBundledByDefault is the fix for "I built
// it, checked it, but see nothing in Russian" — the bundle must apply with
// zero configuration, not require dumping+pointing a file at itself first.
func TestResolveKnowledgeBase_AppliesBundledByDefault(t *testing.T) {
	kb, err := triage.ResolveKnowledgeBase("")
	if err != nil {
		t.Fatalf("ResolveKnowledgeBase(\"\"): %v", err)
	}
	if _, ok := kb["rbac.no-wildcard-rules"]; !ok {
		t.Error("expected the bundled default to apply even with no knowledgeBaseFile configured")
	}
}

func TestResolveKnowledgeBase_CustomFileOverridesBundled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "knowledge-base.yaml")
	content := "rbac.no-wildcard-rules:\n  title: \"Наш собственный заголовок\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := triage.ResolveKnowledgeBase(path)
	if err != nil {
		t.Fatalf("ResolveKnowledgeBase: %v", err)
	}
	if kb["rbac.no-wildcard-rules"].Title != "Наш собственный заголовок" {
		t.Errorf("expected the custom file's title to override the bundled one, got %q", kb["rbac.no-wildcard-rules"].Title)
	}
	if kb["rbac.no-wildcard-rules"].Remediation == "" {
		t.Error("expected the bundled remediation to survive (the custom file has no override for it)")
	}
}

// TestStarterKnowledgeBase_CoversAllBuiltinChecks is a structural guard
// against the bundled starter-ru.yaml silently regressing (a check added
// later without a matching entry, or an entry accidentally deleted) —
// spot-checks one PolicyID from every VAP policy directory and every
// native check family, and that every entry has at least a Title.
func TestStarterKnowledgeBase_CoversAllBuiltinChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "starter.yaml")
	if err := os.WriteFile(path, []byte(triage.StarterKnowledgeBase()), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := triage.LoadKnowledgeBase(path)
	if err != nil {
		t.Fatalf("parsing StarterKnowledgeBase: %v", err)
	}
	if len(kb) < 150 {
		t.Fatalf("expected at least 150 bundled entries (126 policy YAMLs + ~32 native checks), got %d", len(kb))
	}
	for _, id := range []string{
		"rbac.no-wildcard-rules",                             // policies/rbac
		"secrets-analyzer.weak-credential-value",             // policies/secrets + native secrets-analyzer
		"netpol-analyzer.no-egress-restriction",              // native netpol-analyzer
		"workload.run-as-non-root",                           // policies/workload
		"controlplane.apiserver.anonymous-auth",              // policies/controlplane
		"controlplane-analyzer.apiserver.authz-always-allow", // native controlplane-analyzer
		"psa-analyzer.no-active-enforcement",
		"pss-analyzer.baseline",
		"k8supdates.end-of-life",
		"apideprecations.removed-api",
		"argocd.rbac-cm-default-admin-policy",       // policies/thirdparty (batch 1)
		"istio.peer-authentication-permissive-mtls", // policies/thirdparty (batch 2)
	} {
		if _, ok := kb[id]; !ok {
			t.Errorf("expected a bundled entry for %q", id)
		}
	}
	for id, entry := range kb {
		if entry.Title == "" {
			t.Errorf("%s: bundled entry has an empty title", id)
		}
	}
}

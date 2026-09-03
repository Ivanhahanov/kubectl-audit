package report

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// TestNameTemplate covers the name-shape normalization that
// GroupByNamePattern relies on — see NameTemplate's doc comment for the
// real-world shape (Capsule-style "usersvs-<uuid>" tenant namespaces) this
// exists to catch, and why short numeric segments are deliberately left
// alone.
func TestNameTemplate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"uuid suffix", "usersvs-0004237b-3813-48ce-a48f-3cabdaeccbea", "usersvs-*"},
		{"bare uuid", "3fa85f64-5717-4562-b3fc-2c963f66afa6", "*"},
		{"long digit run", "customer-4821937", "customer-*"},
		{"long hex run, not full uuid", "tenant-deadbeefcafe", "tenant-*"},
		{"hand-chosen name, untouched", "argocd", "argocd"},
		{"hand-chosen name with hyphen, untouched", "cert-manager", "cert-manager"},
		{"short version-like number, untouched", "app-v2", "app-v2"},
		{"short numeric suffix, untouched", "web-01", "web-01"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NameTemplate(c.in); got != c.want {
				t.Errorf("NameTemplate(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestNameTemplate_TwoDifferentUUIDsNormalizeToTheSameShape is the actual
// grouping precondition: two different tenant namespace names must produce
// an identical template so groupAffectedResources buckets them together.
func TestNameTemplate_TwoDifferentUUIDsNormalizeToTheSameShape(t *testing.T) {
	a := NameTemplate("usersvs-0004237b-3813-48ce-a48f-3cabdaeccbea")
	b := NameTemplate("usersvs-0006e164-99bc-4fac-aaec-079df475fa6b")
	if a != b {
		t.Errorf("expected both UUID-suffixed names to normalize identically, got %q vs %q", a, b)
	}
}

// TestResolveCheckKB_NoOverrideKeepsDefaults is the common case (no
// knowledge base configured, or no entry for this PolicyID): the report
// shows the tool's own default content, unchanged.
func TestResolveCheckKB_NoOverrideKeepsDefaults(t *testing.T) {
	f := findings.Finding{Title: "Default title", Category: "workload-security", Remediation: "Default remediation"}
	title, category, remediation := resolveCheckKB(f, nil)
	if title != "Default title" || category != "workload-security" || remediation != "Default remediation" {
		t.Errorf("expected defaults unchanged with no KB, got (%q, %q, %q)", title, category, remediation)
	}
}

// TestResolveCheckKB_ExternalFileOverridesInlineFinding is the precedence
// triage.Resolve already established: a policy's own inline
// Finding.KnowledgeBase (set via a VAP's kb-* annotations) applies first,
// then an external knowledgeBaseFile entry for the same PolicyID layers on
// top and wins field-by-field — an explicit override should always beat
// whatever the check author baked in.
func TestResolveCheckKB_ExternalFileOverridesInlineFinding(t *testing.T) {
	f := findings.Finding{
		PolicyID: "policy.a", Title: "Inline title", Category: "inline-category", Remediation: "Inline remediation",
		KnowledgeBase: &findings.KnowledgeBaseEntry{Title: "Inline title", Category: "inline-category", Remediation: "Inline remediation"},
	}
	kb := map[string]findings.KnowledgeBaseEntry{
		"policy.a": {Title: "Org title", Remediation: "Org remediation"}, // Category deliberately left unset
	}
	title, category, remediation := resolveCheckKB(f, kb)
	if title != "Org title" {
		t.Errorf("expected external Title to win, got %q", title)
	}
	if remediation != "Org remediation" {
		t.Errorf("expected external Remediation to win, got %q", remediation)
	}
	if category != "inline-category" {
		t.Errorf("expected Category to fall back to the inline value when the external entry leaves it unset, got %q", category)
	}
}

// TestResolveCheckKB_RendersFieldsAsTemplates is the regression test for a
// real bug: the bundled starter-ru.yaml knowledge base (and any real-world
// custom one) writes Remediation as a Go template referencing
// {{.Finding.Resource...}} — resolveCheckKB used to copy the field
// verbatim, so the report showed literal "{{.Finding.Resource.Name}}"
// syntax instead of the substituted value. Fields must render against the
// representative finding, same as triage.Resolve.
func TestResolveCheckKB_RendersFieldsAsTemplates(t *testing.T) {
	f := findings.Finding{
		PolicyID: "policy.a",
		Resource: findings.ResourceRef{Kind: "Deployment", Name: "app", Namespace: "ns"},
	}
	kb := map[string]findings.KnowledgeBaseEntry{
		"policy.a": {Remediation: `Fix {{.Finding.Resource.Kind}} "{{.Finding.Resource.Name}}" in {{.Finding.Resource.Namespace}}.`},
	}
	_, _, remediation := resolveCheckKB(f, kb)
	want := `Fix Deployment "app" in ns.`
	if remediation != want {
		t.Errorf("expected the template rendered against the finding, got %q, want %q", remediation, want)
	}
}

// TestResolveCheckKB_TemplateErrorFallsBackToPreviousValue guards the
// graceful-degradation behavior (matching triage.Resolve): a broken
// template in one KB field must not leak "{{...}}" syntax into the report
// — it falls back to whatever that field already was, not to blank.
func TestResolveCheckKB_TemplateErrorFallsBackToPreviousValue(t *testing.T) {
	f := findings.Finding{PolicyID: "policy.a", Remediation: "Default remediation"}
	kb := map[string]findings.KnowledgeBaseEntry{
		"policy.a": {Remediation: "{{.Finding.NoSuchField}}"}, // invalid — Finding has no NoSuchField
	}
	_, _, remediation := resolveCheckKB(f, kb)
	if remediation != "Default remediation" {
		t.Errorf("expected a broken template to fall back to the previous value, got %q", remediation)
	}
}

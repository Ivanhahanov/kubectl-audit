package engine_test

import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
)

// TestExtractMeta_ParsesInlineKnowledgeBase guards the "write your
// organization's own ticket wording in the same policy file" feature: a
// policy carrying kb-title/kb-description/kb-remediation annotations
// should get them parsed into PolicyMeta.KnowledgeBase, letting a
// custom-policy author avoid also maintaining a separate
// triage.knowledgeBaseFile entry for it — see docs/writing-policies.md.
func TestExtractMeta_ParsesInlineKnowledgeBase(t *testing.T) {
	docs, err := engine.ParsePolicyDocs("inline", []byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: custom.example-check
  annotations:
    audit.k8s-auditor.io/title: "Example check"
    audit.k8s-auditor.io/remediation: "Fix it."
    audit.k8s-auditor.io/kb-title: "Пример проверки (наша формулировка)"
    audit.k8s-auditor.io/kb-description: "Наше собственное описание уязвимости."
    audit.k8s-auditor.io/kb-remediation: "Исправьте это согласно нашему стандарту."
spec:
  validations:
    - expression: "true"
      message: "English message."
`))
	if err != nil {
		t.Fatalf("ParsePolicyDocs: %v", err)
	}
	meta := engine.ExtractMeta(docs[0])

	if meta.KnowledgeBase == nil {
		t.Fatal("expected meta.KnowledgeBase to be set")
	}
	if meta.KnowledgeBase.Title != "Пример проверки (наша формулировка)" {
		t.Errorf("expected the kb title, got %q", meta.KnowledgeBase.Title)
	}
	if meta.KnowledgeBase.Description != "Наше собственное описание уязвимости." {
		t.Errorf("expected the kb description, got %q", meta.KnowledgeBase.Description)
	}
	if meta.KnowledgeBase.Remediation != "Исправьте это согласно нашему стандарту." {
		t.Errorf("expected the kb remediation, got %q", meta.KnowledgeBase.Remediation)
	}
	// The English fields must stay untouched — KnowledgeBase is an
	// additive overlay, not a replacement of the canonical English text.
	if meta.Title != "Example check" {
		t.Errorf("expected the English title to remain the canonical Title, got %q", meta.Title)
	}
	if meta.Remediation != "Fix it." {
		t.Errorf("expected the English remediation to remain the canonical Remediation, got %q", meta.Remediation)
	}
}

func TestExtractMeta_NoKBAnnotationsLeavesKnowledgeBaseNil(t *testing.T) {
	docs, err := engine.ParsePolicyDocs("inline", []byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: custom.no-kb
  annotations:
    audit.k8s-auditor.io/title: "Example check"
spec:
  validations:
    - expression: "true"
      message: "English message."
`))
	if err != nil {
		t.Fatalf("ParsePolicyDocs: %v", err)
	}
	meta := engine.ExtractMeta(docs[0])
	if meta.KnowledgeBase != nil {
		t.Errorf("expected a nil KnowledgeBase when no kb-* annotations are set, got %+v", meta.KnowledgeBase)
	}
}

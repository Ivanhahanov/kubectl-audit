// Package engine parses policies written as real Kubernetes
// ValidatingAdmissionPolicy (VAP) objects, compiles their CEL expressions,
// and evaluates them against loaded resources. Because policies are plain
// admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy YAML, the exact
// same files can be `kubectl apply -f`'d to enforce them in-cluster.
//
// Audit-specific metadata (severity, category, remediation, verification
// steps, CIS control refs) is stashed in metadata.annotations under the
// audit.k8s-auditor.io/ prefix, so it round-trips through a real apiserver
// untouched.
package engine

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

const (
	AnnotationSeverity          = "audit.k8s-auditor.io/severity"
	AnnotationCategory          = "audit.k8s-auditor.io/category"
	AnnotationRemediation       = "audit.k8s-auditor.io/remediation"
	AnnotationCIS               = "audit.k8s-auditor.io/cis"
	AnnotationTitle             = "audit.k8s-auditor.io/title"
	AnnotationVerificationSteps = "audit.k8s-auditor.io/verification-steps"
)

// PolicyMeta carries the audit-specific metadata read from a policy's
// annotations.
type PolicyMeta struct {
	ID                string
	Title             string
	Severity          findings.Severity
	Category          string
	Remediation       string
	VerificationSteps string
	CIS               []string
}

// ParsePolicyDocs decodes a (possibly multi-document) YAML/JSON byte stream
// into ValidatingAdmissionPolicy objects. Non-VAP documents (e.g. a stray
// List or unrelated object) cause an error naming the offending source, so
// mistakes in a policy directory are surfaced clearly rather than silently
// ignored.
func ParsePolicyDocs(source string, data []byte) ([]*admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []*admissionregistrationv1.ValidatingAdmissionPolicy
	for {
		var raw map[string]interface{}
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		if len(raw) == 0 {
			continue
		}
		if kind, _ := raw["kind"].(string); kind != "" && kind != "ValidatingAdmissionPolicy" {
			return nil, fmt.Errorf("%s: unsupported kind %q (expected ValidatingAdmissionPolicy)", source, kind)
		}
		var policy admissionregistrationv1.ValidatingAdmissionPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &policy); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		if policy.Name == "" {
			return nil, fmt.Errorf("%s: policy missing metadata.name", source)
		}
		out = append(out, &policy)
	}
	return out, nil
}

// ExtractMeta reads the audit.k8s-auditor.io/* annotations off a policy.
func ExtractMeta(policy *admissionregistrationv1.ValidatingAdmissionPolicy) PolicyMeta {
	ann := policy.Annotations
	meta := PolicyMeta{
		ID:                policy.Name,
		Title:             policy.Name,
		Severity:          findings.ParseSeverity(ann[AnnotationSeverity]),
		Category:          ann[AnnotationCategory],
		Remediation:       ann[AnnotationRemediation],
		VerificationSteps: ann[AnnotationVerificationSteps],
	}
	if t, ok := ann[AnnotationTitle]; ok && t != "" {
		meta.Title = t
	}
	if c, ok := ann[AnnotationCIS]; ok {
		for _, part := range strings.Split(c, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				meta.CIS = append(meta.CIS, part)
			}
		}
	}
	if meta.Category == "" {
		meta.Category = "general"
	}
	return meta
}

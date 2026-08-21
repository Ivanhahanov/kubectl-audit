package engine_test

// TestSecretTargetingPoliciesNeverUseMessageExpression is a defense-in-depth
// guardrail for the secrets-mode feature (docs/secrets-mode.md): every
// check that targets Secret objects is designed to compare object.data
// against a known/expected literal value and always emit a static message
// string, specifically so a finding can never embed live secret content.
// messageExpression (a real VAP feature — a CEL expression evaluated per
// object to build a dynamic message, e.g. quoting a field value) would
// break that guarantee the moment anyone used it on a Secret-targeting
// policy, even by accident. This test makes that mistake fail loudly at
// compile/test time instead of shipping a finding that leaks a secret
// value into findings.json/report.md.
import (
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
)

func TestSecretTargetingPoliciesNeverUseMessageExpression(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	for _, p := range policies {
		mc := p.Policy.Spec.MatchConstraints
		if mc == nil {
			continue
		}
		targetsSecrets := false
		for _, rule := range mc.ResourceRules {
			for _, g := range rule.APIGroups {
				if g != "" && g != "*" {
					continue
				}
				for _, r := range rule.Resources {
					if r == "secrets" || r == "*" {
						targetsSecrets = true
					}
				}
			}
		}
		if !targetsSecrets {
			continue
		}
		for _, v := range p.Validations {
			if v.MessageExpression != nil {
				t.Errorf("policy %q targets Secret objects and uses messageExpression — this can dynamically embed live secret content into a finding message. Use a static message: string instead.", p.Meta.ID)
			}
		}
	}
}

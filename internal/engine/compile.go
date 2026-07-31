package engine

import (
	"fmt"

	"github.com/google/cel-go/cel"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

// baseCELOptions declares the standard VAP CEL variables. `authorizer` is
// intentionally omitted: this engine audits standing cluster/manifest state
// rather than live admission requests, so there is no SubjectAccessReview
// path to back it with. Policies that reference `authorizer.*` will fail to
// compile with a clear "undeclared reference" error — RBAC-aware checks
// should rely on the dedicated rbac analyzer instead (see internal/rbac).
var baseCELOptions = []cel.EnvOption{
	cel.Variable("object", cel.DynType),
	cel.Variable("oldObject", cel.DynType),
	cel.Variable("namespaceObject", cel.DynType),
	cel.Variable("params", cel.DynType),
	cel.Variable("request", cel.DynType),
	cel.Variable("variables", cel.DynType),
}

func newBaseEnv() (*cel.Env, error) {
	return cel.NewEnv(baseCELOptions...)
}

// compiledValidation is a compiled validations[] entry.
type compiledValidation struct {
	Expression        string
	Message           string
	Program           cel.Program
	MessageExpression cel.Program
}

// CompiledPolicy is a ValidatingAdmissionPolicy with its CEL expressions
// pre-compiled into runnable programs.
type CompiledPolicy struct {
	Policy      *admissionregistrationv1.ValidatingAdmissionPolicy
	Meta        PolicyMeta
	Validations []compiledValidation
}

// Compile parses and compiles a policy's CEL expressions.
//
// spec.variables is not yet supported: real VAP lets validations reference
// precomputed `variables.name` values, which requires threading compiled
// CEL values (not just native Go types) through the activation. Given our
// bundled policies don't need it, policies that declare spec.variables are
// rejected here with a clear message rather than silently ignored.
func Compile(policy *admissionregistrationv1.ValidatingAdmissionPolicy, meta PolicyMeta) (*CompiledPolicy, error) {
	if len(policy.Spec.Variables) > 0 {
		return nil, fmt.Errorf("policy %q: spec.variables is not supported by this engine; inline the expression instead", meta.ID)
	}
	if len(policy.Spec.Validations) == 0 {
		return nil, fmt.Errorf("policy %q: spec.validations must not be empty", meta.ID)
	}

	env, err := newBaseEnv()
	if err != nil {
		return nil, fmt.Errorf("building CEL environment: %w", err)
	}

	cp := &CompiledPolicy{Policy: policy, Meta: meta}

	for _, val := range policy.Spec.Validations {
		prg, err := compileExpr(env, val.Expression)
		if err != nil {
			return nil, fmt.Errorf("policy %q: validation %q: %w", meta.ID, val.Expression, err)
		}
		cv := compiledValidation{Expression: val.Expression, Message: val.Message, Program: prg}
		if val.MessageExpression != "" {
			mPrg, err := compileExpr(env, val.MessageExpression)
			if err != nil {
				return nil, fmt.Errorf("policy %q: messageExpression %q: %w", meta.ID, val.MessageExpression, err)
			}
			cv.MessageExpression = mPrg
		}
		cp.Validations = append(cp.Validations, cv)
	}
	return cp, nil
}

func compileExpr(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return prg, nil
}

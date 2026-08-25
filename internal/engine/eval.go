package engine

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// EvalOptions supplies context needed to evaluate policies against a
// resource set.
type EvalOptions struct {
	// Namespaces maps namespace name -> loaded Namespace resource, used to
	// bind namespaceObject and evaluate namespaceSelector. May be nil/partial
	// (e.g. static-manifest scans that don't include Namespace objects).
	Namespaces map[string]*loader.Resource
	// Warn receives non-fatal per-resource evaluation problems (e.g. a CEL
	// runtime error on a malformed object) so a scan can continue instead of
	// aborting on one bad resource.
	Warn func(format string, args ...any)
}

// EvaluateAll runs every compiled policy against every resource and returns
// the resulting findings. Uses a (group, resource) index (see
// buildResourceIndex) rather than scanning every policy for every
// resource — a resource whose group/kind no bundled policy could ever
// match (e.g. a Secret against an istio.* policy) skips straight past
// that policy instead of paying for a full Matches() call.
func EvaluateAll(policies []*CompiledPolicy, resources []loader.Resource, opts EvalOptions) []findings.Finding {
	warn := opts.Warn
	if warn == nil {
		warn = func(string, ...any) {}
	}

	idx := buildResourceIndex(policies)

	var out []findings.Finding
	for _, res := range resources {
		gvk := res.GVK()

		resourceName, ok := loader.ResourceNameForKind(gvk.Kind)
		if !ok {
			// No bundled policy could ever match an unrecognized Kind —
			// Matches() would return false for all of them anyway (see
			// its own ResourceNameForKind check).
			continue
		}

		var nsLabels map[string]string
		var nsObj interface{}
		if opts.Namespaces != nil {
			if ns, ok := opts.Namespaces[res.Namespace()]; ok && ns != nil {
				nsLabels = ns.Object.GetLabels()
				nsObj = ns.Object.Object
			}
		}

		matchIn := MatchInput{
			GVK:             gvk,
			Namespace:       res.Namespace(),
			ObjectLabels:    res.Object.GetLabels(),
			NamespaceLabels: nsLabels,
		}

		for _, p := range idx.candidates(gvk.Group, resourceName) {
			if !Matches(p.Policy.Spec.MatchConstraints, matchIn) {
				continue
			}
			out = append(out, evalPolicy(p, res, gvk, nsObj, warn)...)
		}
	}
	return out
}

func evalPolicy(p *CompiledPolicy, res loader.Resource, gvk schema.GroupVersionKind, nsObj interface{}, warn func(string, ...any)) []findings.Finding {
	vars := map[string]interface{}{
		"object":          res.Object.Object,
		"oldObject":       nil,
		"namespaceObject": nsObj,
		"params":          nil,
		"request": map[string]interface{}{
			"operation": "CREATE",
			"namespace": res.Namespace(),
			"name":      res.Name(),
		},
		"variables": map[string]interface{}{},
	}

	ref := findings.ResourceRef{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  res.Namespace(),
		Name:       res.Name(),
	}

	var out []findings.Finding
	for _, v := range p.Validations {
		result, _, err := v.Program.Eval(vars)
		if err != nil {
			warn("policy %s on %s: %v", p.Meta.ID, ref, err)
			continue
		}
		pass, ok := result.Value().(bool)
		if !ok {
			warn("policy %s on %s: validation expression did not return a bool", p.Meta.ID, ref)
			continue
		}
		if pass {
			continue
		}

		message := v.Message
		if v.MessageExpression != nil {
			if mResult, _, err := v.MessageExpression.Eval(vars); err == nil {
				if s, ok := mResult.Value().(string); ok && s != "" {
					message = s
				}
			}
		}
		if message == "" {
			message = fmt.Sprintf("failed expression: %s", v.Expression)
		}

		out = append(out, findings.Finding{
			ID:                findings.NewID(p.Meta.ID, ref, v.Expression),
			PolicyID:          p.Meta.ID,
			Title:             p.Meta.Title,
			Severity:          p.Meta.Severity,
			Category:          p.Meta.Category,
			CIS:               p.Meta.CIS,
			Resource:          ref,
			Message:           message,
			Remediation:       p.Meta.Remediation,
			VerificationSteps: p.Meta.VerificationSteps,
			Source:            res.Source,
		})
	}
	return out
}

package engine

// White-box (package engine, not engine_test) so this can call the
// unexported buildResourceIndex/evalPolicy directly, to differential-test
// the (group, resource) index EvaluateAll uses internally against a naive
// "check every resource against every policy" reference implementation —
// locking in that the index is a pure performance optimization, not a
// behavior change, across the full bundled policy set.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

func resourceFromYAML(t *testing.T, doc string) loader.Resource {
	t.Helper()
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return loader.Resource{Object: &unstructured.Unstructured{Object: m}, Source: "test"}
}

// naiveEvaluateAll is EvaluateAll's pre-index logic: every resource
// against every policy, no (group, resource) pre-filtering.
func naiveEvaluateAll(policies []*CompiledPolicy, resources []loader.Resource) []findings.Finding {
	var out []findings.Finding
	for _, res := range resources {
		gvk := res.GVK()
		matchIn := MatchInput{
			GVK:          gvk,
			Namespace:    res.Namespace(),
			ObjectLabels: res.Object.GetLabels(),
		}
		for _, p := range policies {
			if !Matches(p.Policy.Spec.MatchConstraints, matchIn) {
				continue
			}
			out = append(out, evalPolicy(p, res, gvk, nil, func(string, ...any) {})...)
		}
	}
	return out
}

func findingIDs(fs []findings.Finding) []string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}

func TestEvaluateAll_IndexMatchesNaiveScan(t *testing.T) {
	policies, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	// Load every bad/ and good/ third-party fixture as one large, diverse
	// resource set — real objects spanning dozens of distinct
	// (group, kind) pairs, not synthetic ones.
	var resources []loader.Resource
	const root = "testdata/thirdparty"
	policyDirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}
	for _, pd := range policyDirs {
		if !pd.IsDir() {
			continue
		}
		for _, kind := range []string{"bad", "good"} {
			dir := filepath.Join(root, pd.Name(), kind)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				data, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					t.Fatalf("reading %s: %v", e.Name(), err)
				}
				resources = append(resources, resourceFromYAML(t, string(data)))
			}
		}
	}
	if len(resources) < 50 {
		t.Fatalf("expected a large fixture set, got only %d resources", len(resources))
	}

	indexed := EvaluateAll(policies, resources, EvalOptions{})
	naive := naiveEvaluateAll(policies, resources)

	gotIDs := findingIDs(indexed)
	wantIDs := findingIDs(naive)

	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("indexed EvaluateAll found %d findings, naive scan found %d", len(gotIDs), len(wantIDs))
	}
	for i := range gotIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("finding set differs at index %d: indexed=%q naive=%q", i, gotIDs[i], wantIDs[i])
		}
	}
}

func TestBuildResourceIndex_NoWildcardsInBundledPolicies(t *testing.T) {
	policies, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	idx := buildResourceIndex(policies)
	if len(idx.always) != 0 {
		names := make([]string, len(idx.always))
		for i, p := range idx.always {
			names[i] = p.Meta.ID
		}
		t.Errorf("expected zero bundled policies to need the wildcard/always fallback bucket, got %v", names)
	}
}

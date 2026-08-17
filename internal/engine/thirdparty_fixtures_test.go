package engine_test

// TestThirdPartyPolicyFixtures replaces per-check Go test functions for
// every policies/thirdparty/* check with plain YAML fixtures under
// testdata/thirdparty/<policyID>/{bad,good}/*.yaml — bad/ resources must
// produce a finding for that policy, good/ resources must not. Adding
// coverage for a new (or extended) third-party check is then "drop a YAML
// file in the right directory," not "write a new Go test function."
//
// Core, product-agnostic checks (workload/rbac/network/controlplane/secrets)
// keep their existing inline-Go-string tests elsewhere in this package —
// this fixture harness is deliberately scoped to policies/thirdparty/* only.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/policies"
)

func TestThirdPartyPolicyFixtures(t *testing.T) {
	policies, err := engine.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	const root = "testdata/thirdparty"
	policyDirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}

	for _, pd := range policyDirs {
		if !pd.IsDir() {
			continue
		}
		policyID := pd.Name()
		t.Run(policyID, func(t *testing.T) {
			runFixtureCases(t, policies, root, policyID, "bad", true)
			runFixtureCases(t, policies, root, policyID, "good", false)
		})
	}
}

// TestEveryThirdPartyPolicyHasFixtures walks the opposite direction from
// TestThirdPartyPolicyFixtures above: that test only evaluates fixtures for
// a policyID that already HAS a testdata/thirdparty/<policyID> directory —
// a third-party policy shipped with no fixture directory at all (forgotten
// during authoring) is invisible to it. This test starts from the actual
// shipped policies/thirdparty/*/*.yaml files instead, and fails loudly if
// any of them lacks bad/ and good/ fixtures. Combined with
// TestBuiltinPolicyResourcesResolveToARegisteredKind (in
// policy_resource_registration_test.go), this closes the two halves of the
// same silent-failure gap: a new third-party check that either can't
// possibly match anything (unregistered Kind) or was never actually
// verified to fire (missing fixtures) now fails go test instead of shipping
// quietly broken.
func TestEveryThirdPartyPolicyHasFixtures(t *testing.T) {
	var policyIDs []string
	err := fs.WalkDir(policies.FS, "thirdparty", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := fs.ReadFile(policies.FS, path)
		if err != nil {
			return err
		}
		docs, err := engine.ParsePolicyDocs(path, data)
		if err != nil {
			return err
		}
		for _, doc := range docs {
			policyIDs = append(policyIDs, engine.ExtractMeta(doc).ID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking policies/thirdparty: %v", err)
	}
	if len(policyIDs) == 0 {
		t.Fatal("found zero policies under policies/thirdparty via policies.FS — the embed glob or this test's WalkDir path is broken, not that there are no third-party policies")
	}

	for _, id := range policyIDs {
		t.Run(id, func(t *testing.T) {
			for _, kind := range []string{"bad", "good"} {
				dir := filepath.Join("testdata", "thirdparty", id, kind)
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatalf("policy %q has no %s/ fixture directory (%s) — every policy under policies/thirdparty needs at least one bad/ and one good/ fixture file", id, kind, dir)
				}
				hasFile := false
				for _, e := range entries {
					if !e.IsDir() {
						hasFile = true
						break
					}
				}
				if !hasFile {
					t.Fatalf("policy %q's %s directory (%s) exists but has no fixture files", id, kind, dir)
				}
			}
		})
	}
}

// runFixtureCases evaluates every *.yaml file in testdata/thirdparty/<policyID>/<kind>/
// against policyID, asserting a finding is (wantFinding) or isn't produced.
func runFixtureCases(t *testing.T, policies []*engine.CompiledPolicy, root, policyID, kind string, wantFinding bool) {
	t.Helper()
	dir := filepath.Join(root, policyID, kind)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v (every policy needs at least one bad/ and one good/ fixture)", dir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s has no fixture files", dir)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		resource := mustResource(t, string(data))
		got := engine.EvaluateAll(policies, []loader.Resource{resource}, engine.EvalOptions{})
		found := len(findingsForPolicy(got, policyID)) > 0
		if found != wantFinding {
			t.Errorf("%s/%s: expected finding=%v for policy %s, got %v", kind, e.Name(), wantFinding, policyID, found)
		}
	}
}

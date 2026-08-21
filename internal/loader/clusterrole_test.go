package loader

// TestClusterRoleManifestsCoverKnownResources guards the example RBAC
// manifests (examples/rbac/clusterrole-readonly.yaml,
// clusterrole-with-secrets.yaml) against the same silent-drift bug class
// TestBuiltinPolicyResourcesAreFetchedFromCluster (internal/engine) catches
// for policies: these YAML files are maintained by hand, not generated
// from defaultResources/optionalResources, so a future new optionalResources
// entry (a new third-party CRD) that isn't also added to both manifests
// would ship a ClusterRole that silently can't see the new component's
// objects — the exact same shape of bug as a forgotten kinds.go
// registration, just one layer further out (a human applying the example
// manifest, not the tool's own code).
import (
	"os"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func loadClusterRole(t *testing.T, path string) *rbacv1.ClusterRole {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var cr rbacv1.ClusterRole
	if err := yaml.Unmarshal(data, &cr); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if cr.Kind != "ClusterRole" {
		t.Fatalf("%s: expected kind ClusterRole, got %q", path, cr.Kind)
	}
	return &cr
}

// clusterRoleGrantsReadOn reports whether rules grants get+list+watch on
// (group, resource) via an exact or "*" match on both apiGroups and
// resources (a "*" verb also satisfies get/list/watch).
func clusterRoleGrantsReadOn(rules []rbacv1.PolicyRule, group, resource string) bool {
	for _, rule := range rules {
		if !stringOrWildcardIn(rule.APIGroups, group) {
			continue
		}
		if !stringOrWildcardIn(rule.Resources, resource) {
			continue
		}
		if hasAll(rule.Verbs, "get", "list", "watch") {
			return true
		}
	}
	return false
}

func stringOrWildcardIn(list []string, val string) bool {
	for _, s := range list {
		if s == "*" || s == val {
			return true
		}
	}
	return false
}

func hasAll(list []string, want ...string) bool {
	for _, s := range list {
		if s == "*" {
			return true
		}
	}
	set := toSet(list)
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func TestClusterRoleManifestsCoverKnownResources(t *testing.T) {
	readonly := loadClusterRole(t, "../../examples/rbac/clusterrole-readonly.yaml")
	withSecrets := loadClusterRole(t, "../../examples/rbac/clusterrole-with-secrets.yaml")

	for _, r := range defaultResources {
		if !clusterRoleGrantsReadOn(readonly.Rules, r.GVR.Group, r.GVR.Resource) {
			t.Errorf("clusterrole-readonly.yaml: no get/list/watch rule for group %q resource %q (in defaultResources) — this manifest has drifted from internal/loader/cluster.go", r.GVR.Group, r.GVR.Resource)
		}
		if !clusterRoleGrantsReadOn(withSecrets.Rules, r.GVR.Group, r.GVR.Resource) {
			t.Errorf("clusterrole-with-secrets.yaml: no get/list/watch rule for group %q resource %q (in defaultResources) — this manifest has drifted from internal/loader/cluster.go", r.GVR.Group, r.GVR.Resource)
		}
	}
	for _, r := range optionalResources {
		if !clusterRoleGrantsReadOn(readonly.Rules, r.Group, r.Resource) {
			t.Errorf("clusterrole-readonly.yaml: no get/list/watch rule for group %q resource %q (in optionalResources) — this manifest has drifted from internal/loader/cluster.go", r.Group, r.Resource)
		}
		if !clusterRoleGrantsReadOn(withSecrets.Rules, r.Group, r.Resource) {
			t.Errorf("clusterrole-with-secrets.yaml: no get/list/watch rule for group %q resource %q (in optionalResources) — this manifest has drifted from internal/loader/cluster.go", r.Group, r.Resource)
		}
	}

	// The readonly ClusterRole must NOT grant Secrets access — that's the
	// entire point of the two-tier split.
	if clusterRoleGrantsReadOn(readonly.Rules, "", "secrets") {
		t.Error("clusterrole-readonly.yaml grants get/list/watch on secrets — it must not; that access belongs only in clusterrole-with-secrets.yaml")
	}
	if !clusterRoleGrantsReadOn(withSecrets.Rules, "", "secrets") {
		t.Error("clusterrole-with-secrets.yaml has no get/list/watch rule for secrets — it exists specifically to grant that")
	}
}

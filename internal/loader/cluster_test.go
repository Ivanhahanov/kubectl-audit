package loader

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"

	"github.com/ivanhahanov/kubectl-audit/internal/k8sclient"
)

// stubDiscovery implements only ServerGroups — the one discovery.DiscoveryInterface
// method resolvePreferredVersion actually calls — leaving every other method to
// the embedded nil interface (safe as long as the test path never calls them).
type stubDiscovery struct {
	discovery.DiscoveryInterface
	groups *metav1.APIGroupList
	err    error
}

func (s *stubDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	return s.groups, s.err
}

// noopLog and recordingLog let tests assert whether warn/debug fired
// without caring about the exact message text.
func noopLog(string, ...any) {}

type recordingLog struct{ calls int }

func (r *recordingLog) log(string, ...any) { r.calls++ }

func TestResolvePreferredVersion_GroupRegistered(t *testing.T) {
	c := &k8sclient.Client{Discovery: &stubDiscovery{groups: &metav1.APIGroupList{
		Groups: []metav1.APIGroup{
			{Name: "capsule.clastix.io", PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v1beta2"}},
		},
	}}}
	version, ok := resolvePreferredVersion(c, "capsule.clastix.io", "tenants", noopLog, noopLog)
	if !ok || version != "v1beta2" {
		t.Fatalf("expected (v1beta2, true), got (%q, %v)", version, ok)
	}
}

func TestResolvePreferredVersion_OlderCRDVersionStillResolved(t *testing.T) {
	// Simulates an older cluster/CRD release serving a different preferred
	// version than whatever this tool's policies were last written against
	// — the whole point of resolving dynamically instead of hardcoding.
	c := &k8sclient.Client{Discovery: &stubDiscovery{groups: &metav1.APIGroupList{
		Groups: []metav1.APIGroup{
			{Name: "security.istio.io", PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v1beta1"}},
		},
	}}}
	version, ok := resolvePreferredVersion(c, "security.istio.io", "authorizationpolicies", noopLog, noopLog)
	if !ok || version != "v1beta1" {
		t.Fatalf("expected (v1beta1, true), got (%q, %v)", version, ok)
	}
}

func TestResolvePreferredVersion_GroupNotRegistered(t *testing.T) {
	c := &k8sclient.Client{Discovery: &stubDiscovery{groups: &metav1.APIGroupList{}}}
	warn := &recordingLog{}
	debug := &recordingLog{}
	_, ok := resolvePreferredVersion(c, "capsule.clastix.io", "tenants", warn.log, debug.log)
	if ok {
		t.Error("expected false for a group the cluster doesn't serve at all")
	}
	// Routine/expected case (most optional CRDs aren't installed on most
	// clusters) — a debug-level note, not a warning.
	if warn.calls != 0 {
		t.Errorf("expected no warning for a simply-not-installed CRD group, got %d", warn.calls)
	}
	if debug.calls != 1 {
		t.Errorf("expected exactly one debug note for a simply-not-installed CRD group, got %d", debug.calls)
	}
}

func TestResolvePreferredVersion_DiscoveryError(t *testing.T) {
	c := &k8sclient.Client{Discovery: &stubDiscovery{err: errBoom}}
	warn := &recordingLog{}
	debug := &recordingLog{}
	_, ok := resolvePreferredVersion(c, "capsule.clastix.io", "tenants", warn.log, debug.log)
	if ok {
		t.Error("expected false when the discovery call itself errors")
	}
	// A real discovery-API failure is NOT the same signal as "not
	// installed" — must be visible by default (warn), not just debug,
	// since it directly undermines Detected Components' accuracy if
	// silently misread as "genuinely absent".
	if warn.calls != 1 {
		t.Errorf("expected exactly one warning for a real discovery error, got %d", warn.calls)
	}
	if debug.calls != 0 {
		t.Errorf("expected no debug note for a real discovery error, got %d", debug.calls)
	}
}

var errBoom = discoveryError("boom")

type discoveryError string

func (e discoveryError) Error() string { return string(e) }

func TestFilterCRDResources(t *testing.T) {
	all := []crdResource{
		{Group: "cilium.io", Resource: "ciliumnetworkpolicies", Name: "ciliumnetworkpolicies"},
		{Group: "capsule.clastix.io", Resource: "tenants", Name: "tenants"},
	}
	only := filterCRDResources(all, []string{"tenants"}, nil)
	if len(only) != 1 || only[0].Name != "tenants" {
		t.Fatalf("expected include filter to keep only tenants, got %+v", only)
	}
	without := filterCRDResources(all, nil, []string{"tenants"})
	if len(without) != 1 || without[0].Name != "ciliumnetworkpolicies" {
		t.Fatalf("expected exclude filter to drop tenants, got %+v", without)
	}
}

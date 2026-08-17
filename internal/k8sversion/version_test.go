package k8sversion_test

import (
	"fmt"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/k8sversion"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in        string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{"v1.27.16", 1, 27, true},
		{"1.27.16-eks-abc1234", 1, 27, true},
		{"v1.36.3", 1, 36, true},
		{"1.27+", 1, 27, true},
		{"garbage", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		major, minor, ok := k8sversion.Parse(c.in)
		if ok != c.wantOK || (ok && (major != c.wantMajor || minor != c.wantMinor)) {
			t.Errorf("Parse(%q) = (%d, %d, %v), want (%d, %d, %v)", c.in, major, minor, ok, c.wantMajor, c.wantMinor, c.wantOK)
		}
	}
}

func TestCheckSupportWindow(t *testing.T) {
	// Well within the window: no finding.
	if got := k8sversion.CheckSupportWindow("v1.36.3", "test", nil); len(got) != 0 {
		t.Errorf("expected no finding for the latest known version, got %+v", got)
	}
	if got := k8sversion.CheckSupportWindow(
		fmt.Sprintf("v1.%d.0", k8sversion.LatestKnownMinor-1), "test", nil); len(got) != 0 {
		t.Errorf("expected no finding one minor version behind, got %+v", got)
	}

	// Old enough to be flagged (v1.27 with LatestKnownMinor=36 is 9 versions behind).
	got := k8sversion.CheckSupportWindow("v1.27.16", "test", nil)
	if len(got) != 1 {
		t.Fatalf("expected exactly one finding for an old cluster version, got %+v", got)
	}
	if got[0].PolicyID != k8sversion.CheckID {
		t.Errorf("unexpected policyId: %s", got[0].PolicyID)
	}

	// Unknown major / newer than this build knows about: no finding,
	// deliberately don't guess, and no warning either — this is a
	// legitimate, confidently-parsed version, just outside what the
	// support-window heuristic covers.
	if got := k8sversion.CheckSupportWindow("v2.0.0", "test", nil); len(got) != 0 {
		t.Errorf("expected no finding for an unknown major version, got %+v", got)
	}
}

func TestCheckSupportWindow_UnparseableVersionWarnsOnce(t *testing.T) {
	var warnings int
	got := k8sversion.CheckSupportWindow("not-a-version", "test", func(string, ...any) { warnings++ })
	if len(got) != 0 {
		t.Errorf("expected no finding for an unparseable version, got %+v", got)
	}
	if warnings != 1 {
		t.Errorf("expected exactly one warning for a non-empty, unparseable version string, got %d", warnings)
	}
}

func TestCheckSupportWindow_EmptyVersionIsSilent(t *testing.T) {
	// "" is the routine static-manifest-only-scan case (no live cluster to
	// detect a version from), already surfaced via the report's Scope
	// section — must not also warn here.
	var warnings int
	got := k8sversion.CheckSupportWindow("", "test", func(string, ...any) { warnings++ })
	if len(got) != 0 {
		t.Errorf("expected no finding for an empty version, got %+v", got)
	}
	if warnings != 0 {
		t.Errorf("expected no warning for an empty (static-scan) version, got %d", warnings)
	}
}

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
	if got := k8sversion.CheckSupportWindow("v1.36.3", "test"); len(got) != 0 {
		t.Errorf("expected no finding for the latest known version, got %+v", got)
	}
	if got := k8sversion.CheckSupportWindow(
		fmt.Sprintf("v1.%d.0", k8sversion.LatestKnownMinor-1), "test"); len(got) != 0 {
		t.Errorf("expected no finding one minor version behind, got %+v", got)
	}

	// Old enough to be flagged (v1.27 with LatestKnownMinor=36 is 9 versions behind).
	got := k8sversion.CheckSupportWindow("v1.27.16", "test")
	if len(got) != 1 {
		t.Fatalf("expected exactly one finding for an old cluster version, got %+v", got)
	}
	if got[0].PolicyID != k8sversion.CheckID {
		t.Errorf("unexpected policyId: %s", got[0].PolicyID)
	}

	// Unparseable / unknown major / newer than this build knows about: no
	// finding, deliberately don't guess.
	if got := k8sversion.CheckSupportWindow("not-a-version", "test"); len(got) != 0 {
		t.Errorf("expected no finding for an unparseable version, got %+v", got)
	}
	if got := k8sversion.CheckSupportWindow("v2.0.0", "test"); len(got) != 0 {
		t.Errorf("expected no finding for an unknown major version, got %+v", got)
	}
}

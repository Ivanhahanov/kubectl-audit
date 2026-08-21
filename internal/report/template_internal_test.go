package report

import "testing"

// TestNameTemplate covers the name-shape normalization that
// GroupByNamePattern relies on — see nameTemplate's doc comment for the
// real-world shape (Capsule-style "usersvs-<uuid>" tenant namespaces) this
// exists to catch, and why short numeric segments are deliberately left
// alone.
func TestNameTemplate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"uuid suffix", "usersvs-0004237b-3813-48ce-a48f-3cabdaeccbea", "usersvs-*"},
		{"bare uuid", "3fa85f64-5717-4562-b3fc-2c963f66afa6", "*"},
		{"long digit run", "customer-4821937", "customer-*"},
		{"long hex run, not full uuid", "tenant-deadbeefcafe", "tenant-*"},
		{"hand-chosen name, untouched", "argocd", "argocd"},
		{"hand-chosen name with hyphen, untouched", "cert-manager", "cert-manager"},
		{"short version-like number, untouched", "app-v2", "app-v2"},
		{"short numeric suffix, untouched", "web-01", "web-01"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nameTemplate(c.in); got != c.want {
				t.Errorf("nameTemplate(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestNameTemplate_TwoDifferentUUIDsNormalizeToTheSameShape is the actual
// grouping precondition: two different tenant namespace names must produce
// an identical template so groupAffectedResources buckets them together.
func TestNameTemplate_TwoDifferentUUIDsNormalizeToTheSameShape(t *testing.T) {
	a := nameTemplate("usersvs-0004237b-3813-48ce-a48f-3cabdaeccbea")
	b := nameTemplate("usersvs-0006e164-99bc-4fac-aaec-079df475fa6b")
	if a != b {
		t.Errorf("expected both UUID-suffixed names to normalize identically, got %q vs %q", a, b)
	}
}

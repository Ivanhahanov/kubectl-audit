package cli

import "testing"

func TestSplitKindName(t *testing.T) {
	tests := []struct {
		in       string
		wantKind string
		wantName string
		wantErr  bool
	}{
		{"Deployment/web", "Deployment", "web", false},
		{"Group/system:masters", "Group", "system:masters", false},
		{"noSlash", "", "", true},
		{"/name", "", "", true},
		{"Kind/", "", "", true},
		{"", "", "", true},
	}
	for _, tt := range tests {
		kind, name, err := splitKindName(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("splitKindName(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && (kind != tt.wantKind || name != tt.wantName) {
			t.Errorf("splitKindName(%q) = (%q, %q), want (%q, %q)", tt.in, kind, name, tt.wantKind, tt.wantName)
		}
	}
}

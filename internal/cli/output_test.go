package cli

import (
	"testing"
)

func TestParseOutputFlags_ValidFormats(t *testing.T) {
	got, err := parseOutputFlags([]string{"json=findings.json", "csv=findings.csv"})
	if err != nil {
		t.Fatalf("parseOutputFlags: %v", err)
	}
	if got["json"] != "findings.json" || got["csv"] != "findings.csv" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestParseOutputFlags_Empty(t *testing.T) {
	got, err := parseOutputFlags(nil)
	if err != nil {
		t.Fatalf("parseOutputFlags: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected an empty map for no --output flags, got %+v", got)
	}
}

func TestParseOutputFlags_UnknownFormatErrors(t *testing.T) {
	if _, err := parseOutputFlags([]string{"xml=report.xml"}); err == nil {
		t.Error("expected an error for an unknown format, got nil")
	}
}

func TestParseOutputFlags_MissingEqualsErrors(t *testing.T) {
	if _, err := parseOutputFlags([]string{"json"}); err == nil {
		t.Error("expected an error for a spec with no '=', got nil")
	}
}

func TestParseOutputFlags_EmptyPathErrors(t *testing.T) {
	if _, err := parseOutputFlags([]string{"json="}); err == nil {
		t.Error("expected an error for an empty path, got nil")
	}
}

func TestParseOutputFlags_DuplicateFormatErrors(t *testing.T) {
	if _, err := parseOutputFlags([]string{"json=a.json", "json=b.json"}); err == nil {
		t.Error("expected an error when the same format is given twice, got nil")
	}
}

func TestOutputFormatGiven(t *testing.T) {
	specs := []string{"json=findings.json", "console=-"}
	if !outputFormatGiven(specs, "json") {
		t.Error("expected outputFormatGiven to find \"json\"")
	}
	if !outputFormatGiven(specs, "console") {
		t.Error("expected outputFormatGiven to find \"console\"")
	}
	if outputFormatGiven(specs, "md") {
		t.Error("expected outputFormatGiven to not find \"md\"")
	}
	if outputFormatGiven(nil, "json") {
		t.Error("expected outputFormatGiven(nil, ...) to be false")
	}
}

func TestColorEnabled_NonStdoutPathIsNeverColored(t *testing.T) {
	t.Setenv("CI", "true")
	if colorEnabled("/tmp/out.txt") {
		t.Error("expected a real file path to never be colorized, regardless of $CI")
	}
}

func TestColorEnabled_NoColorEnvWins(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CI", "true")
	if colorEnabled("-") {
		t.Error("expected $NO_COLOR to disable color even when $CI is set")
	}
}

func TestColorEnabled_CIEnvEnablesColorForStdout(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CI", "true")
	if !colorEnabled("-") {
		t.Error("expected $CI=true to enable color for stdout")
	}
}

func TestColorEnabled_GitlabCIEnvEnablesColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CI", "")
	t.Setenv("GITLAB_CI", "true")
	if !colorEnabled("-") {
		t.Error("expected $GITLAB_CI=true to enable color for stdout")
	}
}

func TestSplitCommaList(t *testing.T) {
	got := splitCommaList([]string{"cis,fstec", " nsa ", "", "capsule"})
	want := []string{"cis", "fstec", "nsa", "capsule"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

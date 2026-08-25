package k8supdates_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/k8supdates"
)

// eoasFixtureBody has a cycle that's past end-of-active-support but NOT
// end-of-life, so CheckIDEOAS actually fires (fixtureBody's only
// isEoas:true cycle is also isEol:true, which takes precedence and
// short-circuits the EOAS branch — see Client.Check).
const eoasFixtureBody = `{
  "schema_version": "1.0",
  "result": {
    "releases": [
      {
        "name": "1.25",
        "releaseDate": "2022-08-23",
        "isEoas": true,
        "eoasFrom": "2023-08-28",
        "isEol": false,
        "eolFrom": "2024-10-28",
        "isMaintained": false,
        "latest": {"name": "1.25.16", "date": "2023-08-15", "link": "https://example.invalid"}
      },
      {
        "name": "1.36",
        "releaseDate": "2026-04-22",
        "isEoas": false,
        "eoasFrom": "2027-04-28",
        "isEol": false,
        "eolFrom": "2027-06-28",
        "isMaintained": true,
        "latest": {"name": "1.36.3", "date": "2026-07-22", "link": "https://example.invalid"}
      }
    ]
  }
}`

// TestEveryCheckHasVerificationSteps guards the triage-tool content
// requirement (see docs/triage.md): all four known check IDs (end-of-life,
// end-of-active-support, patch-available, newer-minor-available) must
// produce findings with a non-empty VerificationSteps.
func TestEveryCheckHasVerificationSteps(t *testing.T) {
	eolServer := testServer(t, fixtureBody, http.StatusOK)
	eolClient := k8supdates.Client{APIURL: eolServer.URL}
	eolFindings, err := eolClient.Check(context.Background(), "v1.20.15", "test")
	if err != nil {
		t.Fatalf("Check (EOL): %v", err)
	}

	patchMinorServer := testServer(t, fixtureBody, http.StatusOK)
	patchMinorClient := k8supdates.Client{APIURL: patchMinorServer.URL}
	patchMinorFindings, err := patchMinorClient.Check(context.Background(), "v1.35.0", "test")
	if err != nil {
		t.Fatalf("Check (patch/minor): %v", err)
	}

	eoasServer := testServer(t, eoasFixtureBody, http.StatusOK)
	eoasClient := k8supdates.Client{APIURL: eoasServer.URL}
	eoasFindings, err := eoasClient.Check(context.Background(), "v1.25.16", "test")
	if err != nil {
		t.Fatalf("Check (EOAS): %v", err)
	}

	want := map[string]bool{
		k8supdates.CheckIDEOL:           false,
		k8supdates.CheckIDEOAS:          false,
		k8supdates.CheckIDPatchOutdated: false,
		k8supdates.CheckIDMinorOutdated: false,
	}
	all := append(append(eolFindings, patchMinorFindings...), eoasFindings...)
	for _, f := range all {
		if _, known := want[f.PolicyID]; known {
			want[f.PolicyID] = true
		}
		if f.VerificationSteps == "" {
			t.Errorf("finding %s has no VerificationSteps", f.PolicyID)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected a %s finding from this fixture set", id)
		}
	}
}

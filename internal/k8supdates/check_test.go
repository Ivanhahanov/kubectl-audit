package k8supdates_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanhahanov/kubectl-audit/internal/k8supdates"
)

const fixtureBody = `{
  "schema_version": "1.0",
  "result": {
    "releases": [
      {
        "name": "1.35",
        "releaseDate": "2025-08-27",
        "isEoas": false,
        "eoasFrom": "2026-10-28",
        "isEol": false,
        "eolFrom": "2026-12-28",
        "isMaintained": true,
        "latest": {"name": "1.35.4", "date": "2026-06-01", "link": "https://example.invalid"}
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
      },
      {
        "name": "1.20",
        "releaseDate": "2020-12-08",
        "isEoas": true,
        "eoasFrom": "2021-12-28",
        "isEol": true,
        "eolFrom": "2021-12-28",
        "isMaintained": false,
        "latest": {"name": "1.20.15", "date": "2021-10-27", "link": "https://example.invalid"}
      }
    ]
  }
}`

func testServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheck_UpToDate(t *testing.T) {
	srv := testServer(t, fixtureBody, http.StatusOK)
	c := k8supdates.Client{APIURL: srv.URL}

	out, err := c.Check(context.Background(), "v1.36.3", "test")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no findings for the latest patch of the newest cycle, got %+v", out)
	}
}

func TestCheck_PatchOutdated(t *testing.T) {
	srv := testServer(t, fixtureBody, http.StatusOK)
	c := k8supdates.Client{APIURL: srv.URL}

	out, err := c.Check(context.Background(), "v1.35.0", "test")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	var gotPatch, gotMinor bool
	for _, f := range out {
		switch f.PolicyID {
		case k8supdates.CheckIDPatchOutdated:
			gotPatch = true
		case k8supdates.CheckIDMinorOutdated:
			gotMinor = true
		}
	}
	if !gotPatch {
		t.Errorf("expected a patch-outdated finding for v1.35.0 (latest is 1.35.4), got %+v", out)
	}
	if !gotMinor {
		t.Errorf("expected a newer-minor-available finding for cycle 1.35 (newest cycle is 1.36), got %+v", out)
	}
}

func TestCheck_EndOfLife(t *testing.T) {
	srv := testServer(t, fixtureBody, http.StatusOK)
	c := k8supdates.Client{APIURL: srv.URL}

	out, err := c.Check(context.Background(), "v1.20.15", "test")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(out) < 1 || out[0].PolicyID != k8supdates.CheckIDEOL {
		t.Fatalf("expected an EOL finding for v1.20.15, got %+v", out)
	}
}

func TestCheck_VersionOlderThanTrackedRange(t *testing.T) {
	srv := testServer(t, fixtureBody, http.StatusOK)
	c := k8supdates.Client{APIURL: srv.URL}

	out, err := c.Check(context.Background(), "v1.16.0", "test")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(out) != 1 || out[0].PolicyID != k8supdates.CheckIDEOL {
		t.Fatalf("expected exactly one EOL finding for an untracked-old version, got %+v", out)
	}
}

func TestCheck_EmptyVersionNoop(t *testing.T) {
	c := k8supdates.Client{APIURL: "http://should-not-be-called.invalid"}
	out, err := c.Check(context.Background(), "", "test")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no findings/no request for an empty version, got %+v", out)
	}
}

func TestCheck_FetchErrorPropagates(t *testing.T) {
	srv := testServer(t, "not json", http.StatusOK)
	c := k8supdates.Client{APIURL: srv.URL}

	if _, err := c.Check(context.Background(), "v1.35.0", "test"); err == nil {
		t.Error("expected an error for an invalid JSON response")
	}
}

func TestCheck_HTTPErrorStatusPropagates(t *testing.T) {
	srv := testServer(t, "", http.StatusInternalServerError)
	c := k8supdates.Client{APIURL: srv.URL}

	if _, err := c.Check(context.Background(), "v1.35.0", "test"); err == nil {
		t.Error("expected an error for a non-200 response")
	}
}

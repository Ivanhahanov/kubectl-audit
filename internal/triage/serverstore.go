package triage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// ServerStore is the Store implementation for `--triage-server`: it talks
// to kubectl-audit-server's HTTP API instead of a local YAML file. It
// deliberately mirrors the server's wire types by field tag (see
// internal/server/http's triageView/bulkTriageRequest) rather than
// importing that package — this package is used by the CLI plugin binary,
// which has no business depending on the server's handler implementation
// just to get JSON shapes; the two sides only need to agree on the wire
// format, not share Go types.
type ServerStore struct {
	// BaseURL is the kubectl-audit-server root, e.g. "https://audit.example.com".
	BaseURL string
	// Token authenticates triage read/write — the server's admin token,
	// not the cluster's own push token: a cluster's ingest token is
	// write-only (findings push), triage is a separate, admin-gated
	// "expert" action (see kubectl-audit-server's handleGetTriage doc
	// comment for why the two are split).
	Token string
	// ClusterID is which cluster's findings/triage this Store's Load/Save
	// operate on — required, since the server no longer infers it from
	// Token (that's the whole reason for the split above).
	ClusterID string
	// Source identifies which scan source's findings this Store's
	// Load/Save operate on — "kubectl-audit" for the CLI's own scans, or
	// an OpenReports tool identifier to triage findings ingested from
	// elsewhere through the same server.
	Source string
	// HTTPClient defaults to http.DefaultClient if nil.
	HTTPClient *http.Client
}

func (s ServerStore) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return http.DefaultClient
}

func (s ServerStore) Label() string {
	return fmt.Sprintf("%s (server, source=%s)", s.BaseURL, s.Source)
}

// serverResourceRef/serverTriageView mirror internal/server/http's
// triageResourceRef/triageView JSON shape exactly — see that file's doc
// comment for why this isn't a shared Go type.
type serverResourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

type serverTriageView struct {
	Source       string            `json:"source"`
	Fingerprint  string            `json:"fingerprint"`
	PolicyID     string            `json:"policyId"`
	Title        string            `json:"title"`
	Resource     serverResourceRef `json:"resource"`
	Status       string            `json:"status"`
	Note         string            `json:"note,omitempty"`
	Reviewer     string            `json:"reviewer,omitempty"`
	JiraIssueKey string            `json:"jiraIssueKey,omitempty"`
	JiraIssueURL string            `json:"jiraIssueUrl,omitempty"`
	FirstSeen    time.Time         `json:"firstSeen"`
	UpdatedAt    time.Time         `json:"updatedAt,omitempty"`
}

type serverTriageViewResponse struct {
	Entries []serverTriageView `json:"entries"`
}

// Load fetches the merged findings+triage view for s.Source and converts
// it into a local State. Only entries with something a human (or Merge)
// actually recorded — a non-"new" status, a note, a reviewer, or a linked
// Jira issue — become an Entry; an untriaged finding stays absent from
// State.Entries, matching FileStore's own sparsity (a fresh
// findings.json with nothing triaged yet produces an empty local State
// too) and keeping subsequent Save calls from re-uploading every
// never-touched finding as a no-op "new" entry.
func (s ServerStore) Load() (*State, error) {
	q := url.Values{"cluster_id": {s.ClusterID}, "source": {s.Source}}
	req, err := http.NewRequest(http.MethodGet, s.BaseURL+"/api/v1/triage?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("building triage server request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)

	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching triage state from %s: %w", s.BaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, serverError("fetching triage state", resp)
	}

	var decoded serverTriageViewResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decoding triage server response: %w", err)
	}

	state := &State{Entries: map[string]Entry{}}
	for _, v := range decoded.Entries {
		if !isMeaningfulServerEntry(v) {
			continue
		}
		state.Entries[v.Fingerprint] = Entry{
			FindingID: v.Fingerprint,
			PolicyID:  v.PolicyID,
			Resource: findings.ResourceRef{
				APIVersion: v.Resource.APIVersion,
				Kind:       v.Resource.Kind,
				Namespace:  v.Resource.Namespace,
				Name:       v.Resource.Name,
			},
			Title:        v.Title,
			Status:       Status(v.Status),
			Note:         v.Note,
			Reviewer:     v.Reviewer,
			JiraIssueKey: v.JiraIssueKey,
			JiraIssueURL: v.JiraIssueURL,
			FirstSeen:    v.FirstSeen,
			LastUpdated:  v.UpdatedAt,
		}
	}
	return state, nil
}

func isMeaningfulServerEntry(v serverTriageView) bool {
	return v.Status != string(StatusNew) || v.Note != "" || v.Reviewer != "" || v.JiraIssueKey != "" || v.JiraIssueURL != ""
}

type bulkTriageEntryDTO struct {
	Fingerprint  string `json:"fingerprint"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
	Reviewer     string `json:"reviewer,omitempty"`
	JiraIssueKey string `json:"jiraIssueKey,omitempty"`
	JiraIssueURL string `json:"jiraIssueUrl,omitempty"`
}

type bulkTriageRequestDTO struct {
	Source  string               `json:"source"`
	Entries []bulkTriageEntryDTO `json:"entries"`
}

// Save pushes every Entry in state as one bulk call — a full resync, not a
// diff, matching how a local FileStore.Save always writes the complete
// State to disk. Fine at this scale: a human triage session touches at
// most low thousands of findings, and this only happens once per discrete
// action (a bulk-apply, a note edit), never per keystroke/frame.
func (s ServerStore) Save(state *State) error {
	req := bulkTriageRequestDTO{Source: s.Source, Entries: make([]bulkTriageEntryDTO, 0, len(state.Entries))}
	for _, e := range state.Entries {
		req.Entries = append(req.Entries, bulkTriageEntryDTO{
			Fingerprint:  e.FindingID,
			Status:       string(e.Status),
			Note:         e.Note,
			Reviewer:     e.Reviewer,
			JiraIssueKey: e.JiraIssueKey,
			JiraIssueURL: e.JiraIssueURL,
		})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encoding bulk triage update: %w", err)
	}

	q := url.Values{"cluster_id": {s.ClusterID}}
	httpReq, err := http.NewRequest(http.MethodPost, s.BaseURL+"/api/v1/triage/bulk?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building triage server request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+s.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client().Do(httpReq)
	if err != nil {
		return fmt.Errorf("pushing triage state to %s: %w", s.BaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return serverError("pushing triage state", resp)
	}
	return nil
}

func serverError(action string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("%s: server returned %d: %s", action, resp.StatusCode, string(body))
}

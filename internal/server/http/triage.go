package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// triageResourceRef mirrors findings.ResourceRef's JSON shape — a local
// copy rather than an import of internal/findings' own type, so this wire
// format stays decoupled from that package's internals the same way
// ingest.nativePayload already does.
type triageResourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

// triageView is one row of the merged findings+triage view — the server-
// side equivalent of internal/triage.Merge, joining a Finding's own
// snapshot fields (needed to render a StatusResolved row whose Finding may
// no longer be "live" in the caller's own current scan) with whatever
// TriageEntry exists for it, defaulting to storage.TriageStatusNew when
// none does.
type triageView struct {
	Source       string            `json:"source"`
	Fingerprint  string            `json:"fingerprint"`
	PolicyID     string            `json:"policyId"`
	Title        string            `json:"title"`
	Severity     string            `json:"severity"`
	Category     string            `json:"category"`
	Resource     triageResourceRef `json:"resource"`
	Message      string            `json:"message"`
	Status       string            `json:"status"`
	Note         string            `json:"note,omitempty"`
	Reviewer     string            `json:"reviewer,omitempty"`
	JiraIssueKey string            `json:"jiraIssueKey,omitempty"`
	JiraIssueURL string            `json:"jiraIssueUrl,omitempty"`
	FirstSeen    time.Time         `json:"firstSeen"`
	LastSeen     time.Time         `json:"lastSeen"`
	UpdatedAt    time.Time         `json:"updatedAt,omitempty"`
}

type triageViewResponse struct {
	Entries []triageView `json:"entries"`
}

// handleGetTriage returns the merged findings+triage view for the
// authenticated cluster, optionally narrowed to one source. There is
// deliberately no {cluster_id} path parameter (unlike the plan's original
// sketch): a cluster's bearer token only ever acts on its own data, so a
// path parameter would be redundant with the auth check (and require one
// anyway, to stop cluster A's token reading cluster B's triage state by
// just naming it in the URL). A cross-cluster, admin-token-gated read
// endpoint is a reasonable future addition once an actual multi-cluster
// dashboard consumer exists — not needed yet.
func (s *Server) handleGetTriage(w http.ResponseWriter, r *http.Request) {
	cluster, ok := s.clusterFromToken(w, r)
	if !ok {
		return
	}
	source := r.URL.Query().Get("source")

	findingsList, err := s.repos.Findings.ListFindings(r.Context(), cluster.ID, storage.FindingFilter{Source: source})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing findings")
		return
	}
	entries, err := s.repos.Triage.ListTriageEntries(r.Context(), cluster.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing triage entries")
		return
	}
	bySourceFingerprint := make(map[string]storage.TriageEntry, len(entries))
	for _, e := range entries {
		bySourceFingerprint[e.Source+"|"+e.Fingerprint] = e
	}

	views := make([]triageView, 0, len(findingsList))
	for _, f := range findingsList {
		v := triageView{
			Source:      f.Source,
			Fingerprint: f.Fingerprint,
			PolicyID:    f.PolicyID,
			Title:       f.Title,
			Severity:    f.Severity,
			Category:    f.Category,
			Resource: triageResourceRef{
				APIVersion: f.ResourceAPIVersion,
				Kind:       f.ResourceKind,
				Namespace:  f.ResourceNamespace,
				Name:       f.ResourceName,
			},
			Message:   f.Message,
			Status:    string(storage.TriageStatusNew),
			FirstSeen: f.FirstSeen,
			LastSeen:  f.LastSeen,
		}
		if e, ok := bySourceFingerprint[f.Source+"|"+f.Fingerprint]; ok {
			v.Status = string(e.Status)
			v.Note = e.Note
			v.Reviewer = e.Reviewer
			v.JiraIssueKey = e.JiraIssueKey
			v.JiraIssueURL = e.JiraIssueURL
			v.UpdatedAt = e.UpdatedAt
		}
		views = append(views, v)
	}

	writeJSON(w, http.StatusOK, triageViewResponse{Entries: views})
}

type patchTriageRequest struct {
	Status       *string `json:"status,omitempty"`
	Note         *string `json:"note,omitempty"`
	Reviewer     *string `json:"reviewer,omitempty"`
	JiraIssueKey *string `json:"jiraIssueKey,omitempty"`
	JiraIssueURL *string `json:"jiraIssueUrl,omitempty"`
}

// handlePatchTriageEntry partially updates one TriageEntry — a field
// omitted from the request body is left at its current value (or the
// zero-value default for a brand new entry), never overwritten to empty,
// which is why this reads the existing entry first rather than
// unmarshaling straight into a storage.TriageEntry and upserting it.
func (s *Server) handlePatchTriageEntry(w http.ResponseWriter, r *http.Request) {
	cluster, ok := s.clusterFromToken(w, r)
	if !ok {
		return
	}
	source := r.PathValue("source")
	fingerprint := r.PathValue("fingerprint")

	if _, err := s.repos.Findings.GetFinding(r.Context(), cluster.ID, source, fingerprint); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such finding for this cluster/source/fingerprint")
			return
		}
		writeError(w, http.StatusInternalServerError, "looking up finding")
		return
	}

	var req patchTriageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	entry, found, err := s.repos.Triage.GetTriageEntry(r.Context(), cluster.ID, source, fingerprint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up triage entry")
		return
	}
	if !found {
		entry = storage.TriageEntry{
			ClusterID:   cluster.ID,
			Source:      source,
			Fingerprint: fingerprint,
			Status:      storage.TriageStatusNew,
		}
	}
	if req.Status != nil {
		entry.Status = storage.TriageStatus(*req.Status)
	}
	if req.Note != nil {
		entry.Note = *req.Note
	}
	if req.Reviewer != nil {
		entry.Reviewer = *req.Reviewer
	}
	if req.JiraIssueKey != nil {
		entry.JiraIssueKey = *req.JiraIssueKey
	}
	if req.JiraIssueURL != nil {
		entry.JiraIssueURL = *req.JiraIssueURL
	}

	if err := s.repos.Triage.UpsertTriageEntry(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "saving triage entry")
		return
	}
	// Re-read rather than echo the pre-upsert value: UpdatedAt is set by
	// the store itself (e.g. Postgres' now()), not by this handler, so the
	// in-memory entry above doesn't have the real persisted value yet.
	saved, _, err := s.repos.Triage.GetTriageEntry(r.Context(), cluster.ID, source, fingerprint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reloading saved triage entry")
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

type bulkTriageEntry struct {
	Fingerprint  string `json:"fingerprint"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
	Reviewer     string `json:"reviewer,omitempty"`
	JiraIssueKey string `json:"jiraIssueKey,omitempty"`
	JiraIssueURL string `json:"jiraIssueUrl,omitempty"`
}

type bulkTriageRequest struct {
	Source  string            `json:"source"`
	Entries []bulkTriageEntry `json:"entries"`
}

type bulkTriageSkip struct {
	Fingerprint string `json:"fingerprint"`
	Error       string `json:"error"`
}

type bulkTriageResponse struct {
	Updated int              `json:"updated"`
	Skipped []bulkTriageSkip `json:"skipped,omitempty"`
}

// handleBulkTriageUpdate is the server-side counterpart of
// triage.ServerStore.Save: a client's whole in-memory triage.State is one
// bulk call, not one PATCH per Entry. Unlike handlePatchTriageEntry, every
// field here is treated as authoritative (full replace, not a partial
// merge) — the local triage.State/YAML file it mirrors never had a
// partial-update concept either; every Entry it holds is always the
// caller's complete, current view of that finding's triage record.
// Entries referencing a fingerprint with no matching Finding are skipped
// (reported, not a hard failure) rather than failing the whole batch —
// e.g. the caller's local state has a leftover entry for a finding the
// server has no record of.
func (s *Server) handleBulkTriageUpdate(w http.ResponseWriter, r *http.Request) {
	cluster, ok := s.clusterFromToken(w, r)
	if !ok {
		return
	}

	var req bulkTriageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Source == "" {
		writeError(w, http.StatusBadRequest, "source is required")
		return
	}

	resp := bulkTriageResponse{}
	for _, e := range req.Entries {
		if _, err := s.repos.Findings.GetFinding(r.Context(), cluster.ID, req.Source, e.Fingerprint); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				resp.Skipped = append(resp.Skipped, bulkTriageSkip{Fingerprint: e.Fingerprint, Error: "finding not found"})
				continue
			}
			writeError(w, http.StatusInternalServerError, "looking up finding "+e.Fingerprint)
			return
		}
		entry := storage.TriageEntry{
			ClusterID:    cluster.ID,
			Source:       req.Source,
			Fingerprint:  e.Fingerprint,
			Status:       storage.TriageStatus(e.Status),
			Note:         e.Note,
			Reviewer:     e.Reviewer,
			JiraIssueKey: e.JiraIssueKey,
			JiraIssueURL: e.JiraIssueURL,
		}
		if err := s.repos.Triage.UpsertTriageEntry(r.Context(), entry); err != nil {
			writeError(w, http.StatusInternalServerError, "saving triage entry "+e.Fingerprint)
			return
		}
		resp.Updated++
	}

	writeJSON(w, http.StatusOK, resp)
}

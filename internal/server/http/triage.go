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
	Source      string            `json:"source"`
	Fingerprint string            `json:"fingerprint"`
	PolicyID    string            `json:"policyId"`
	Title       string            `json:"title"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	Resource    triageResourceRef `json:"resource"`
	Message     string            `json:"message"`
	// DedupKey mirrors findings.Finding.DedupKey — see that field's doc
	// comment. Without it, the TUI's bulk-triage collapsing has to bucket
	// purely on Message text, which silently lumps together findings whose
	// Message happens to be identical but whose Resource genuinely differs
	// (e.g. a check with a fixed, non-resource-specific Message template).
	DedupKey     string    `json:"dedupKey,omitempty"`
	Status       string    `json:"status"`
	Note         string    `json:"note,omitempty"`
	Reviewer     string    `json:"reviewer,omitempty"`
	JiraIssueKey string    `json:"jiraIssueKey,omitempty"`
	JiraIssueURL string    `json:"jiraIssueUrl,omitempty"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	UpdatedAt    time.Time `json:"updatedAt,omitempty"`
}

type triageViewResponse struct {
	Entries []triageView `json:"entries"`
}

// handleGetTriage returns the merged findings+triage view for the cluster
// named by the required cluster_id query parameter, optionally narrowed to
// one source. Admin-token-gated, not cluster-token-gated: a cluster's own
// push token is ingest-only (see handleIngest's doc comment) and grants no
// read access to its own findings/triage — reading is an "expert" action,
// separate from the pipeline that pushes scan data. See clusterFromQuery
// for why cluster_id is an explicit query parameter here instead of being
// implied by the caller's token, the way it used to be.
//
//	@Summary		Get the merged findings+triage view
//	@Description	Returns every finding for one cluster merged with its triage state (status defaults to "new" when no triage entry exists yet).
//	@Tags			triage
//	@Produce		json
//	@Security		AdminAuth
//	@Param			cluster_id	query		string	true	"Cluster ID"
//	@Param			source		query		string	false	"Restrict to one ingest source, e.g. native or openreports"
//	@Success		200			{object}	triageViewResponse
//	@Failure		400			{object}	map[string]string	"missing or invalid cluster_id"
//	@Failure		401			{object}	map[string]string	"missing or invalid admin token"
//	@Failure		404			{object}	map[string]string	"no such cluster"
//	@Router			/triage [get]
func (s *Server) handleGetTriage(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	cluster, ok := s.clusterFromQuery(w, r)
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
			DedupKey:  f.DedupKey,
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
// Admin-token-gated for the same reason as handleGetTriage: triage is a
// read/write "expert" action, distinct from a cluster's own ingest-only
// push token.
//
//	@Summary		Update one triage entry
//	@Description	Partially updates the TriageEntry for one finding (source+fingerprint) of one cluster. Omitted fields keep their current value; a first update creates the entry with status "new" as the baseline.
//	@Tags			triage
//	@Accept			json
//	@Produce		json
//	@Security		AdminAuth
//	@Param			cluster_id	query		string					true	"Cluster ID"
//	@Param			source		path		string					true	"Ingest source, e.g. native or openreports"
//	@Param			fingerprint	path		string					true	"Finding fingerprint"
//	@Param			request		body		patchTriageRequest		true	"Fields to update"
//	@Success		200			{object}	storage.TriageEntry
//	@Failure		400			{object}	map[string]string	"invalid request body / missing or invalid cluster_id"
//	@Failure		401			{object}	map[string]string	"missing or invalid admin token"
//	@Failure		404			{object}	map[string]string	"no such cluster / no such finding for this cluster/source/fingerprint"
//	@Router			/triage/{source}/{fingerprint} [patch]
func (s *Server) handlePatchTriageEntry(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	cluster, ok := s.clusterFromQuery(w, r)
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
// server has no record of. Admin-token-gated for the same reason as
// handleGetTriage/handlePatchTriageEntry.
//
//	@Summary		Bulk-replace triage entries for one source
//	@Description	Uploads a client's whole local triage.State for one source and one cluster in a single call. Every field in each entry is authoritative (full replace, not a partial merge). Entries whose fingerprint has no matching Finding are skipped and reported, not treated as a hard failure.
//	@Tags			triage
//	@Accept			json
//	@Produce		json
//	@Security		AdminAuth
//	@Param			cluster_id	query		string				true	"Cluster ID"
//	@Param			request		body		bulkTriageRequest	true	"Source and its full set of triage entries"
//	@Success		200			{object}	bulkTriageResponse
//	@Failure		400			{object}	map[string]string	"invalid request body / missing source / missing or invalid cluster_id"
//	@Failure		401			{object}	map[string]string	"missing or invalid admin token"
//	@Failure		404			{object}	map[string]string	"no such cluster"
//	@Router			/triage/bulk [post]
func (s *Server) handleBulkTriageUpdate(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	cluster, ok := s.clusterFromQuery(w, r)
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

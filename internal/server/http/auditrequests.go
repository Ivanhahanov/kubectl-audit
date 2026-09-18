package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

type auditRequestDTO struct {
	ID                    string    `json:"id,omitempty"`
	ClusterID             string    `json:"clusterId"`
	RequestedBy           string    `json:"requestedBy,omitempty"`
	Reason                string    `json:"reason"`
	Status                string    `json:"status,omitempty"`
	TektonPipelineRunName string    `json:"tektonPipelineRunName,omitempty"`
	ScheduledCron         string    `json:"scheduledCron,omitempty"`
	CreatedAt             time.Time `json:"createdAt,omitempty"`
}

func toAuditRequestDTO(r storage.AuditRequest) auditRequestDTO {
	dto := auditRequestDTO{
		ID: r.ID.String(), ClusterID: r.ClusterID.String(), RequestedBy: r.RequestedBy,
		Reason: r.Reason, Status: string(r.Status), TektonPipelineRunName: r.TektonPipelineRunName,
		CreatedAt: r.CreatedAt,
	}
	if r.ScheduledCron != nil {
		dto.ScheduledCron = *r.ScheduledCron
	}
	return dto
}

// handleCreateAuditRequest and its siblings are admin-token-gated for now
// — there's no per-cluster "request an audit of myself" identity model
// yet, so only an operator can create/approve these.
//
//	@Summary		Create an audit request
//	@Description	Creates a pending request to audit a cluster. Approving it later (PATCH with status=approved) triggers the configured pipeline.
//	@Tags			audit-requests
//	@Accept			json
//	@Produce		json
//	@Security		AdminAuth
//	@Param			request	body		auditRequestDTO	true	"Audit request to create"
//	@Success		201		{object}	auditRequestDTO
//	@Failure		400		{object}	map[string]string	"invalid request body / invalid clusterId / missing reason"
//	@Failure		401		{object}	map[string]string	"missing or invalid admin token"
//	@Router			/audit-requests [post]
func (s *Server) handleCreateAuditRequest(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	var req auditRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	clusterID, err := uuid.Parse(req.ClusterID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid clusterId: "+err.Error())
		return
	}
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return
	}

	ar := storage.AuditRequest{ClusterID: clusterID, RequestedBy: req.RequestedBy, Reason: req.Reason}
	if req.ScheduledCron != "" {
		ar.ScheduledCron = &req.ScheduledCron
	}

	created, err := s.repos.AuditRequests.CreateAuditRequest(r.Context(), ar)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating audit request")
		return
	}
	writeJSON(w, http.StatusCreated, toAuditRequestDTO(created))
}

// @Summary		List audit requests
// @Description	Lists audit requests, optionally narrowed to one cluster.
// @Tags			audit-requests
// @Produce		json
// @Security		AdminAuth
// @Param			cluster_id	query		string	false	"Restrict to requests for this cluster ID"
// @Success		200			{object}	map[string][]auditRequestDTO
// @Failure		400			{object}	map[string]string	"invalid cluster_id"
// @Failure		401			{object}	map[string]string	"missing or invalid admin token"
// @Router			/audit-requests [get]
func (s *Server) handleListAuditRequests(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	var clusterID *uuid.UUID
	if raw := r.URL.Query().Get("cluster_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid cluster_id: "+err.Error())
			return
		}
		clusterID = &id
	}
	requests, err := s.repos.AuditRequests.ListAuditRequests(r.Context(), clusterID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing audit requests")
		return
	}
	dtos := make([]auditRequestDTO, 0, len(requests))
	for _, req := range requests {
		dtos = append(dtos, toAuditRequestDTO(req))
	}
	writeJSON(w, http.StatusOK, map[string][]auditRequestDTO{"requests": dtos})
}

type patchAuditRequestRequest struct {
	Status *string `json:"status,omitempty"`
}

// handlePatchAuditRequest is how a pending request gets approved (or
// rejected) — approving one calls the configured PipelineTrigger (see
// automation.PipelineTrigger) to actually kick off a scan. Only a
// pending -> approved/rejected transition is meaningful today; there's no
// worker yet advancing approved -> running -> completed (that needs a
// real Tekton integration reporting back, future work).
//
//	@Summary		Update an audit request's status
//	@Description	Transitions an audit request's status, typically pending -> approved (which triggers the configured pipeline and moves it to running) or pending -> rejected.
//	@Tags			audit-requests
//	@Accept			json
//	@Produce		json
//	@Security		AdminAuth
//	@Param			id		path		string						true	"Audit request ID"
//	@Param			request	body		patchAuditRequestRequest	true	"New status"
//	@Success		200		{object}	auditRequestDTO
//	@Failure		400		{object}	map[string]string	"invalid id / invalid request body / missing status"
//	@Failure		401		{object}	map[string]string	"missing or invalid admin token"
//	@Failure		404		{object}	map[string]string	"no such audit request"
//	@Failure		500		{object}	map[string]string	"triggering scan failed"
//	@Router			/audit-requests/{id} [patch]
func (s *Server) handlePatchAuditRequest(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id: "+err.Error())
		return
	}
	existing, err := s.repos.AuditRequests.GetAuditRequest(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such audit request")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up audit request")
		return
	}

	var req patchAuditRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Status == nil {
		writeError(w, http.StatusBadRequest, "status is required")
		return
	}

	existing.Status = storage.AuditRequestStatus(*req.Status)
	if existing.Status == storage.AuditRequestApproved && s.pipelineTrigger != nil {
		cluster, err := s.repos.Clusters.GetByID(r.Context(), existing.ClusterID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "looking up cluster for trigger")
			return
		}
		name, err := s.pipelineTrigger.Trigger(r.Context(), existing, cluster)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "triggering scan: "+err.Error())
			return
		}
		existing.TektonPipelineRunName = name
		existing.Status = storage.AuditRequestRunning
	}

	if err := s.repos.AuditRequests.UpdateAuditRequest(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "updating audit request")
		return
	}
	writeJSON(w, http.StatusOK, toAuditRequestDTO(existing))
}

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

type exclusionMatchDTO struct {
	Kind      string            `json:"kind,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type exclusionRuleDTO struct {
	ID        string            `json:"id,omitempty"`
	ClusterID string            `json:"clusterId,omitempty"`
	PolicyIDs []string          `json:"policyIds,omitempty"`
	Match     exclusionMatchDTO `json:"match"`
	Reason    string            `json:"reason"`
	CreatedAt time.Time         `json:"createdAt,omitempty"`
}

func toExclusionRuleDTO(r storage.ExclusionRule) exclusionRuleDTO {
	dto := exclusionRuleDTO{
		ID:        r.ID.String(),
		PolicyIDs: r.PolicyIDs,
		Match: exclusionMatchDTO{
			Kind: r.Match.Kind, Namespace: r.Match.Namespace, Name: r.Match.Name, Labels: r.Match.Labels,
		},
		Reason:    r.Reason,
		CreatedAt: r.CreatedAt,
	}
	if r.ClusterID != nil {
		dto.ClusterID = r.ClusterID.String()
	}
	return dto
}

// handleListExclusionRules, handleCreateExclusionRule, and
// handleDeleteExclusionRule are admin-token-gated — see NewServer's doc
// comment for why exclusion rules are organization-level configuration,
// not per-cluster data.
//
//	@Summary		List exclusion rules
//	@Description	Lists exclusion rules, optionally narrowed to one cluster (rules with no clusterId apply to every cluster).
//	@Tags			exclusion-rules
//	@Produce		json
//	@Security		AdminAuth
//	@Param			cluster_id	query		string	false	"Restrict to rules for this cluster ID"
//	@Success		200			{object}	map[string][]exclusionRuleDTO
//	@Failure		400			{object}	map[string]string	"invalid cluster_id"
//	@Failure		401			{object}	map[string]string	"missing or invalid admin token"
//	@Router			/exclusion-rules [get]
func (s *Server) handleListExclusionRules(w http.ResponseWriter, r *http.Request) {
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

	rules, err := s.repos.ExclusionRules.ListExclusionRules(r.Context(), clusterID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing exclusion rules")
		return
	}
	dtos := make([]exclusionRuleDTO, 0, len(rules))
	for _, rule := range rules {
		dtos = append(dtos, toExclusionRuleDTO(rule))
	}
	writeJSON(w, http.StatusOK, map[string][]exclusionRuleDTO{"rules": dtos})
}

// @Summary		Create an exclusion rule
// @Description	Creates a rule that suppresses matching findings, org-wide or for one cluster (clusterId).
// @Tags			exclusion-rules
// @Accept			json
// @Produce		json
// @Security		AdminAuth
// @Param			request	body		exclusionRuleDTO	true	"Exclusion rule to create"
// @Success		201		{object}	exclusionRuleDTO
// @Failure		400		{object}	map[string]string	"invalid request body / missing reason / invalid clusterId"
// @Failure		401		{object}	map[string]string	"missing or invalid admin token"
// @Router			/exclusion-rules [post]
func (s *Server) handleCreateExclusionRule(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	var req exclusionRuleDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return
	}

	rule := storage.ExclusionRule{
		PolicyIDs: req.PolicyIDs,
		Match: storage.ExclusionMatch{
			Kind: req.Match.Kind, Namespace: req.Match.Namespace, Name: req.Match.Name, Labels: req.Match.Labels,
		},
		Reason: req.Reason,
	}
	if req.ClusterID != "" {
		id, err := uuid.Parse(req.ClusterID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid clusterId: "+err.Error())
			return
		}
		rule.ClusterID = &id
	}

	created, err := s.repos.ExclusionRules.CreateExclusionRule(r.Context(), rule)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating exclusion rule")
		return
	}
	writeJSON(w, http.StatusCreated, toExclusionRuleDTO(created))
}

// @Summary		Delete an exclusion rule
// @Description	Deletes one exclusion rule by ID.
// @Tags			exclusion-rules
// @Security		AdminAuth
// @Param			id	path	string	true	"Exclusion rule ID"
// @Success		204	"deleted"
// @Failure		400	{object}	map[string]string	"invalid id"
// @Failure		401	{object}	map[string]string	"missing or invalid admin token"
// @Failure		404	{object}	map[string]string	"no such exclusion rule"
// @Router			/exclusion-rules/{id} [delete]
func (s *Server) handleDeleteExclusionRule(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id: "+err.Error())
		return
	}

	if err := s.repos.ExclusionRules.DeleteExclusionRule(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such exclusion rule")
			return
		}
		writeError(w, http.StatusInternalServerError, "deleting exclusion rule")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

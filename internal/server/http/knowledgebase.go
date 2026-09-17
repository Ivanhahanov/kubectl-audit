package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

type knowledgeBaseEntryDTO struct {
	PolicyID    string    `json:"policyId"`
	Title       string    `json:"title,omitempty"`
	Category    string    `json:"category,omitempty"`
	Description string    `json:"description,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Labels      []string  `json:"labels,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt,omitempty"`
}

// handleGetKnowledgeBaseEntry and handlePutKnowledgeBaseEntry are admin-
// token-gated, like cluster registration: this is organization-level
// configuration (today's local triage.knowledgeBaseFile, centralized), not
// per-cluster scan data — see NewServer's doc comment.
func (s *Server) handleGetKnowledgeBaseEntry(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	policyID := r.PathValue("policyId")

	entry, err := s.repos.KnowledgeBase.GetKnowledgeBaseEntry(r.Context(), policyID)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no knowledge base entry for this policy id")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up knowledge base entry")
		return
	}
	writeJSON(w, http.StatusOK, knowledgeBaseEntryDTO{
		PolicyID: entry.PolicyID, Title: entry.Title, Category: entry.Category,
		Description: entry.Description, Remediation: entry.Remediation, Labels: entry.Labels,
		UpdatedAt: entry.UpdatedAt,
	})
}

func (s *Server) handlePutKnowledgeBaseEntry(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	policyID := r.PathValue("policyId")

	var req knowledgeBaseEntryDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	entry := storage.KnowledgeBaseEntry{
		PolicyID: policyID, Title: req.Title, Category: req.Category,
		Description: req.Description, Remediation: req.Remediation, Labels: req.Labels,
	}
	if err := s.repos.KnowledgeBase.PutKnowledgeBaseEntry(r.Context(), entry); err != nil {
		writeError(w, http.StatusInternalServerError, "saving knowledge base entry")
		return
	}

	saved, err := s.repos.KnowledgeBase.GetKnowledgeBaseEntry(r.Context(), policyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reloading saved knowledge base entry")
		return
	}
	writeJSON(w, http.StatusOK, knowledgeBaseEntryDTO{
		PolicyID: saved.PolicyID, Title: saved.Title, Category: saved.Category,
		Description: saved.Description, Remediation: saved.Remediation, Labels: saved.Labels,
		UpdatedAt: saved.UpdatedAt,
	})
}

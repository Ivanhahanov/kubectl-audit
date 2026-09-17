package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

type automationTriggerDTO struct {
	MinSeverity        string `json:"minSeverity,omitempty"`
	Status             string `json:"status,omitempty"`
	Source             string `json:"source,omitempty"`
	NoJiraLinkForHours int    `json:"noJiraLinkForHours,omitempty"`
}

type automationActionDTO struct {
	Type   string   `json:"type"`
	Prompt string   `json:"prompt,omitempty"`
	Tools  []string `json:"tools,omitempty"`
}

type automationRuleDTO struct {
	ID        string               `json:"id,omitempty"`
	Name      string               `json:"name"`
	Enabled   bool                 `json:"enabled"`
	Trigger   automationTriggerDTO `json:"trigger"`
	Action    automationActionDTO  `json:"action"`
	CreatedAt time.Time            `json:"createdAt,omitempty"`
}

func toAutomationRuleDTO(r storage.AutomationRule) automationRuleDTO {
	return automationRuleDTO{
		ID: r.ID.String(), Name: r.Name, Enabled: r.Enabled,
		Trigger: automationTriggerDTO{
			MinSeverity: r.Trigger.MinSeverity, Status: r.Trigger.Status,
			Source: r.Trigger.Source, NoJiraLinkForHours: r.Trigger.NoJiraLinkForHours,
		},
		Action:    automationActionDTO{Type: r.Action.Type, Prompt: r.Action.Prompt, Tools: r.Action.Tools},
		CreatedAt: r.CreatedAt,
	}
}

func fromAutomationRuleDTO(dto automationRuleDTO) storage.AutomationRule {
	return storage.AutomationRule{
		Name: dto.Name, Enabled: dto.Enabled,
		Trigger: storage.AutomationTrigger{
			MinSeverity: dto.Trigger.MinSeverity, Status: dto.Trigger.Status,
			Source: dto.Trigger.Source, NoJiraLinkForHours: dto.Trigger.NoJiraLinkForHours,
		},
		Action: storage.AutomationAction{Type: dto.Action.Type, Prompt: dto.Action.Prompt, Tools: dto.Action.Tools},
	}
}

// Automation rule endpoints are admin-token-gated — organization-level
// policy, not per-cluster data, same as knowledge base/exclusion rules.
func (s *Server) handleCreateAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	var req automationRuleDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Action.Type == "" {
		writeError(w, http.StatusBadRequest, "action.type is required")
		return
	}

	created, err := s.repos.AutomationRules.CreateAutomationRule(r.Context(), fromAutomationRuleDTO(req))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating automation rule")
		return
	}
	writeJSON(w, http.StatusCreated, toAutomationRuleDTO(created))
}

func (s *Server) handleListAutomationRules(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	rules, err := s.repos.AutomationRules.ListAutomationRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing automation rules")
		return
	}
	dtos := make([]automationRuleDTO, 0, len(rules))
	for _, rule := range rules {
		dtos = append(dtos, toAutomationRuleDTO(rule))
	}
	writeJSON(w, http.StatusOK, map[string][]automationRuleDTO{"rules": dtos})
}

func (s *Server) handlePatchAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id: "+err.Error())
		return
	}
	existing, err := s.repos.AutomationRules.GetAutomationRule(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such automation rule")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up automation rule")
		return
	}

	var req automationRuleDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	updated := fromAutomationRuleDTO(req)
	updated.ID = existing.ID
	updated.CreatedAt = existing.CreatedAt

	if err := s.repos.AutomationRules.UpdateAutomationRule(r.Context(), updated); err != nil {
		writeError(w, http.StatusInternalServerError, "updating automation rule")
		return
	}
	writeJSON(w, http.StatusOK, toAutomationRuleDTO(updated))
}

func (s *Server) handleDeleteAutomationRule(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id: "+err.Error())
		return
	}
	if err := s.repos.AutomationRules.DeleteAutomationRule(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such automation rule")
			return
		}
		writeError(w, http.StatusInternalServerError, "deleting automation rule")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleEvaluateAutomationRules runs one evaluation pass immediately
// (rather than waiting for the periodic ticker — see cmd/kubectl-audit-
// server) and returns exactly what matched/was recorded, so this is also
// the practical way to demo automation without waiting for a timer.
func (s *Server) handleEvaluateAutomationRules(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	if s.automation == nil {
		writeError(w, http.StatusInternalServerError, "automation runner not configured")
		return
	}
	results, err := s.automation.RunOnce(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "running automation: "+err.Error())
		return
	}

	type resultDTO struct {
		ClusterID   string `json:"clusterId"`
		RuleID      string `json:"ruleId"`
		RuleName    string `json:"ruleName"`
		Source      string `json:"source"`
		Fingerprint string `json:"fingerprint"`
		Attempted   bool   `json:"attempted"`
		Detail      string `json:"detail"`
	}
	out := make([]resultDTO, 0, len(results))
	for _, res := range results {
		out = append(out, resultDTO{
			ClusterID: res.Match.ClusterID.String(), RuleID: res.Match.Rule.ID.String(), RuleName: res.Match.Rule.Name,
			Source: res.Match.Finding.Source, Fingerprint: res.Match.Finding.Fingerprint,
			Attempted: res.Attempted, Detail: res.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string][]resultDTO{"results": out})
}

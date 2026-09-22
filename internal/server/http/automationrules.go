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
//
//	@Summary		Create an automation rule
//	@Description	Creates a rule that fires an action (e.g. notify/file-jira) when its trigger matches a finding during evaluation.
//	@Tags			automation-rules
//	@Accept			json
//	@Produce		json
//	@Security		AdminAuth
//	@Param			request	body		automationRuleDTO	true	"Automation rule to create"
//	@Success		201		{object}	automationRuleDTO
//	@Failure		400		{object}	map[string]string	"invalid request body / missing name or action.type"
//	@Failure		401		{object}	map[string]string	"missing or invalid admin token"
//	@Router			/automation-rules [post]
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

// @Summary		List automation rules
// @Description	Lists every automation rule.
// @Tags			automation-rules
// @Produce		json
// @Security		AdminAuth
// @Success		200	{object}	map[string][]automationRuleDTO
// @Failure		401	{object}	map[string]string	"missing or invalid admin token"
// @Router			/automation-rules [get]
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

// @Summary		Update an automation rule
// @Description	Replaces the name/enabled/trigger/action of an existing automation rule. ID and createdAt are preserved from the existing record.
// @Tags			automation-rules
// @Accept			json
// @Produce		json
// @Security		AdminAuth
// @Param			id		path		string				true	"Automation rule ID"
// @Param			request	body		automationRuleDTO	true	"New rule content"
// @Success		200		{object}	automationRuleDTO
// @Failure		400		{object}	map[string]string	"invalid id / invalid request body"
// @Failure		401		{object}	map[string]string	"missing or invalid admin token"
// @Failure		404		{object}	map[string]string	"no such automation rule"
// @Router			/automation-rules/{id} [patch]
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

// @Summary		Delete an automation rule
// @Description	Deletes one automation rule by ID.
// @Tags			automation-rules
// @Security		AdminAuth
// @Param			id	path	string	true	"Automation rule ID"
// @Success		204	"deleted"
// @Failure		400	{object}	map[string]string	"invalid id"
// @Failure		401	{object}	map[string]string	"missing or invalid admin token"
// @Failure		404	{object}	map[string]string	"no such automation rule"
// @Router			/automation-rules/{id} [delete]
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

// automationEvaluationResultDTO is one entry of handleEvaluateAutomationRules'
// response — a package-level type (rather than a func-local one) purely so
// swag can generate a named schema for it instead of falling back to a
// generic object.
type automationEvaluationResultDTO struct {
	ClusterID   string `json:"clusterId"`
	RuleID      string `json:"ruleId"`
	RuleName    string `json:"ruleName"`
	Source      string `json:"source"`
	Fingerprint string `json:"fingerprint"`
	Attempted   bool   `json:"attempted"`
	Detail      string `json:"detail"`
}

// handleEvaluateAutomationRules runs one evaluation pass immediately
// (rather than waiting for the periodic ticker — see cmd/kubectl-audit-
// server) and returns exactly what matched/was recorded, so this is also
// the practical way to demo automation without waiting for a timer.
//
//	@Summary		Run one automation evaluation pass
//	@Description	Evaluates every enabled automation rule against current findings immediately, instead of waiting for the periodic ticker. Useful to demo automation without waiting for a timer.
//	@Tags			automation-rules
//	@Produce		json
//	@Security		AdminAuth
//	@Success		200	{object}	map[string][]automationEvaluationResultDTO	"results"
//	@Failure		401	{object}	map[string]string	"missing or invalid admin token"
//	@Failure		500	{object}	map[string]string	"automation runner not configured / evaluation failed"
//	@Router			/automation-rules/evaluate [post]
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

	out := make([]automationEvaluationResultDTO, 0, len(results))
	for _, res := range results {
		out = append(out, automationEvaluationResultDTO{
			ClusterID: res.Match.ClusterID.String(), RuleID: res.Match.Rule.ID.String(), RuleName: res.Match.Rule.Name,
			Source: res.Match.Finding.Source, Fingerprint: res.Match.Finding.Fingerprint,
			Attempted: res.Attempted, Detail: res.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string][]automationEvaluationResultDTO{"results": out})
}

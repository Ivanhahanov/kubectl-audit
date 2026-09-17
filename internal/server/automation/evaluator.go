// Package automation implements automation_rules matching — the "when X,
// do Y" policies from the architecture plan's phase 6 design.
//
// Scope, deliberately: this package's Evaluator is real and fully tested —
// given a set of rules and a cluster's findings/triage state, it correctly
// identifies every (rule, finding) pair that matches. What happens next is
// intentionally NOT executed here for two of the two action types the
// schema supports:
//   - "file_jira" needs a server-side Jira credential (project, token)
//     stored somewhere — a new secret-handling design nobody has made yet
//     (the CLI's own --jira-token is a per-invocation flag/env var, not a
//     stored server secret). Building that storage/rotation story wasn't
//     part of this phase's scope.
//   - "agent_triage" needs a real AI agent/LLM integration — see the
//     architecture plan's G0 section for the intended shape (MCP tool
//     access via `kubectl-audit inspect`, never transitioning past
//     needs_human_review on its own). No agent runtime is wired up yet.
//
// LogExecutor (see executor.go) is what actually runs today: it records
// exactly which action *would* fire and why, so the matching engine itself
// is demonstrable end-to-end (create a rule, ingest a matching finding,
// see it correctly identified) without pretending either action type is
// production-ready.
package automation

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// Match is one automation rule firing against one finding.
type Match struct {
	ClusterID   uuid.UUID
	Rule        storage.AutomationRule
	Finding     storage.Finding
	TriageEntry storage.TriageEntry // zero value (Status "") if no entry exists yet
}

// Evaluator checks automation rules against one cluster's findings/triage
// state. Only depends on the read-side repo interfaces it actually needs.
type Evaluator struct {
	Rules    storage.AutomationRuleRepo
	Findings storage.FindingRepo
	Triage   storage.TriageRepo
}

// EvaluateCluster returns every (rule, finding) pair whose rule is enabled
// and whose Trigger matches, for one cluster, as of now.
func (e *Evaluator) EvaluateCluster(ctx context.Context, clusterID uuid.UUID, now time.Time) ([]Match, error) {
	rules, err := e.Rules.ListAutomationRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing automation rules: %w", err)
	}
	allFindings, err := e.Findings.ListFindings(ctx, clusterID, storage.FindingFilter{})
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	entries, err := e.Triage.ListTriageEntries(ctx, clusterID)
	if err != nil {
		return nil, fmt.Errorf("listing triage entries: %w", err)
	}
	entryByKey := make(map[string]storage.TriageEntry, len(entries))
	for _, en := range entries {
		entryByKey[en.Source+"|"+en.Fingerprint] = en
	}

	var matches []Match
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, f := range allFindings {
			entry := entryByKey[f.Source+"|"+f.Fingerprint]
			if !triggerMatches(rule.Trigger, f, entry, now) {
				continue
			}
			matches = append(matches, Match{ClusterID: clusterID, Rule: rule, Finding: f, TriageEntry: entry})
		}
	}
	return matches, nil
}

func triggerMatches(trig storage.AutomationTrigger, f storage.Finding, e storage.TriageEntry, now time.Time) bool {
	if trig.MinSeverity != "" {
		want := findings.ParseSeverity(trig.MinSeverity)
		got := findings.ParseSeverity(f.Severity)
		if !got.AtLeast(want) {
			return false
		}
	}
	if trig.Source != "" && f.Source != trig.Source {
		return false
	}

	status := e.Status
	if status == "" {
		status = storage.TriageStatusNew
	}
	if trig.Status != "" && string(status) != trig.Status {
		return false
	}

	if trig.NoJiraLinkForHours > 0 {
		if e.JiraIssueKey != "" {
			return false
		}
		// e.UpdatedAt is zero when there's no real TriageEntry yet (the
		// map lookup above returned a zero value) — treated as "hasn't
		// been sitting long enough to matter" rather than a trivial match
		// on an entry that was never actually recorded.
		if e.UpdatedAt.IsZero() || now.Sub(e.UpdatedAt) < time.Duration(trig.NoJiraLinkForHours)*time.Hour {
			return false
		}
	}

	return true
}

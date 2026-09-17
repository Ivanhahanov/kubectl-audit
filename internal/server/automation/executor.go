package automation

import (
	"context"
	"fmt"
	"log"
)

// ExecutionResult reports what happened for one Match — Attempted is false
// for every action type today (see this package's doc comment); Detail
// explains why in a form suitable for logging or an API response.
type ExecutionResult struct {
	Match     Match
	Attempted bool
	Detail    string
}

// ActionExecutor performs (or, today, only records) a Match's action.
type ActionExecutor interface {
	Execute(ctx context.Context, m Match) (ExecutionResult, error)
}

// LogExecutor is the only ActionExecutor implemented so far — see this
// package's doc comment for why "file_jira" and "agent_triage" aren't
// actually executed yet. Logf defaults to log.Printf.
type LogExecutor struct {
	Logf func(format string, args ...any)
}

func (l LogExecutor) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (l LogExecutor) Execute(_ context.Context, m Match) (ExecutionResult, error) {
	var detail string
	switch m.Rule.Action.Type {
	case "file_jira":
		detail = "file_jira not yet implemented server-side (needs server-managed Jira credentials)"
	case "agent_triage":
		detail = "agent_triage not yet implemented (needs AI agent wiring; must never auto-transition past needs_human_review per design)"
	default:
		detail = fmt.Sprintf("unknown action type %q", m.Rule.Action.Type)
	}
	l.logf("automation: rule %q matched finding %s/%s (cluster %s): %s",
		m.Rule.Name, m.Finding.Source, m.Finding.Fingerprint, m.ClusterID, detail)
	return ExecutionResult{Match: m, Attempted: false, Detail: detail}, nil
}

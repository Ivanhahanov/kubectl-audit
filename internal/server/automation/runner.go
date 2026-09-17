package automation

import (
	"context"
	"fmt"
	"time"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// Runner evaluates every registered cluster and executes (records) any
// resulting matches — the thing an always-on ticker (see
// cmd/kubectl-audit-server) or a one-off admin-triggered evaluation calls.
type Runner struct {
	Clusters  storage.ClusterRepo
	Evaluator *Evaluator
	Executor  ActionExecutor
}

// RunOnce evaluates automation rules against every registered cluster's
// current findings/triage state and executes the resulting matches. A
// per-cluster evaluation error is returned wrapped with that cluster's ID
// rather than aborting the whole run — one cluster's transient issue
// shouldn't block every other cluster's evaluation.
func (r *Runner) RunOnce(ctx context.Context) ([]ExecutionResult, error) {
	clusters, err := r.Clusters.ListClusters(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing clusters: %w", err)
	}

	now := time.Now()
	var results []ExecutionResult
	for _, c := range clusters {
		matches, err := r.Evaluator.EvaluateCluster(ctx, c.ID, now)
		if err != nil {
			return results, fmt.Errorf("evaluating cluster %s: %w", c.ID, err)
		}
		for _, m := range matches {
			res, err := r.Executor.Execute(ctx, m)
			if err != nil {
				return results, fmt.Errorf("executing action for cluster %s: %w", c.ID, err)
			}
			results = append(results, res)
		}
	}
	return results, nil
}

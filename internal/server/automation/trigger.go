package automation

import (
	"context"
	"log"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// PipelineTrigger starts a scan for an approved AuditRequest, returning
// whatever identifies the resulting run (e.g. a Tekton PipelineRun name)
// so it can be recorded on the request.
//
// LogTrigger is the always-available default; a real Tekton-backed
// implementation (creating a PipelineRun via the k8s API, picking the
// right Task/Pipeline reference, wiring the target cluster's kubeconfig
// in) is a separate, optional implementation of this same interface, built
// and tested against a real Tekton install.
type PipelineTrigger interface {
	Trigger(ctx context.Context, req storage.AuditRequest, cluster storage.Cluster) (pipelineRunName string, err error)
}

// LogTrigger just records the intent to start a scan — the default until
// a real Tekton-backed trigger is wired in for a given deployment.
type LogTrigger struct {
	Logf func(format string, args ...any)
}

func (l LogTrigger) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (l LogTrigger) Trigger(_ context.Context, req storage.AuditRequest, cluster storage.Cluster) (string, error) {
	name := "logged-" + uuid.NewString()
	l.logf("automation: approved audit request %s for cluster %q (%s) — would trigger a scan PipelineRun %q (no real Tekton trigger configured)",
		req.ID, cluster.Name, cluster.ID, name)
	return name, nil
}

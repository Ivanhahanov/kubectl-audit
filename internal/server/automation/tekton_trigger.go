package automation

import (
	"context"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

var pipelineRunGVR = schema.GroupVersionResource{Group: "tekton.dev", Version: "v1", Resource: "pipelineruns"}

// TektonTrigger creates a real tekton.dev PipelineRun for an approved
// AuditRequest — the production-shape counterpart to LogTrigger (see that
// type's doc comment for why it, not this, is the default). Built and
// verified against a real Tekton Pipelines install on a local kind
// cluster running this project's own "kubectl-audit-scan-and-push"
// Pipeline (see the deployment docs).
//
// Deliberately minimal: it only creates a PipelineRun referencing an
// already-deployed Pipeline (PipelineName) and ServiceAccount
// (ServiceAccountName) — authoring that Pipeline/Task, the target
// cluster's read-only scan RBAC, and the Secret holding its push token
// are deployment concerns, not this trigger's job. Same reasoning as
// storage.Cluster never storing a plaintext token (see its own doc
// comment): this trigger never handles the target cluster's push token
// either — the Task it starts reads that token directly from a
// pre-provisioned Secret.
type TektonTrigger struct {
	Dynamic            dynamic.Interface
	Namespace          string
	PipelineName       string
	ServiceAccountName string
}

// NewTektonTriggerFromEnv builds a TektonTrigger using in-cluster config —
// the expected deployment has kubectl-audit-server running as a Pod whose
// ServiceAccount is permitted to create pipelineruns.tekton.dev (see
// charts/kubectl-audit-server's RBAC) — and TEKTON_NAMESPACE/
// TEKTON_PIPELINE_NAME/TEKTON_SERVICE_ACCOUNT environment variables.
func NewTektonTriggerFromEnv() (*TektonTrigger, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("loading in-cluster config: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}

	namespace := os.Getenv("TEKTON_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	pipelineName := os.Getenv("TEKTON_PIPELINE_NAME")
	if pipelineName == "" {
		pipelineName = "kubectl-audit-scan-and-push"
	}
	serviceAccount := os.Getenv("TEKTON_SERVICE_ACCOUNT")
	if serviceAccount == "" {
		serviceAccount = "kubectl-audit-scan"
	}
	return &TektonTrigger{Dynamic: dyn, Namespace: namespace, PipelineName: pipelineName, ServiceAccountName: serviceAccount}, nil
}

func (t *TektonTrigger) Trigger(ctx context.Context, req storage.AuditRequest, cluster storage.Cluster) (string, error) {
	name := "kubectl-audit-" + req.ID.String()[:8]
	pr := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "tekton.dev/v1",
		"kind":       "PipelineRun",
		"metadata": map[string]any{
			"name":      name,
			"namespace": t.Namespace,
			"labels": map[string]any{
				"kubectl-audit.io/audit-request": req.ID.String(),
				"kubectl-audit.io/cluster":       cluster.ID.String(),
			},
		},
		"spec": map[string]any{
			"pipelineRef":     map[string]any{"name": t.PipelineName},
			"taskRunTemplate": map[string]any{"serviceAccountName": t.ServiceAccountName},
		},
	}}

	created, err := t.Dynamic.Resource(pipelineRunGVR).Namespace(t.Namespace).Create(ctx, pr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("creating PipelineRun: %w", err)
	}
	return created.GetName(), nil
}

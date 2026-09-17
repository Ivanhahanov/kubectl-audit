package automation

import (
	"context"
	"testing"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

func TestTektonTrigger_CreatesPipelineRun(t *testing.T) {
	scheme := runtime.NewScheme()
	gvrToKind := map[schema.GroupVersionResource]string{
		pipelineRunGVR: "PipelineRunList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToKind)

	trigger := &TektonTrigger{
		Dynamic: dyn, Namespace: "kubectl-audit-system",
		PipelineName: "kubectl-audit-scan-and-push", ServiceAccountName: "kubectl-audit-scan",
	}

	req := storage.AuditRequest{ID: uuid.New(), Reason: "test"}
	cluster := storage.Cluster{ID: uuid.New(), Name: "demo"}

	name, err := trigger.Trigger(context.Background(), req, cluster)
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if name == "" {
		t.Fatal("expected a non-empty PipelineRun name")
	}

	created, err := dyn.Resource(pipelineRunGVR).Namespace("kubectl-audit-system").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	spec, ok := created.Object["spec"].(map[string]any)
	if !ok {
		t.Fatalf("spec = %v, want a map", created.Object["spec"])
	}
	pipelineRef, ok := spec["pipelineRef"].(map[string]any)
	if !ok || pipelineRef["name"] != "kubectl-audit-scan-and-push" {
		t.Errorf("pipelineRef = %v, want name=kubectl-audit-scan-and-push", spec["pipelineRef"])
	}
	taskRunTemplate, ok := spec["taskRunTemplate"].(map[string]any)
	if !ok || taskRunTemplate["serviceAccountName"] != "kubectl-audit-scan" {
		t.Errorf("taskRunTemplate = %v, want serviceAccountName=kubectl-audit-scan", spec["taskRunTemplate"])
	}

	labels := created.GetLabels()
	if labels["kubectl-audit.io/audit-request"] != req.ID.String() {
		t.Errorf("audit-request label = %q, want %q", labels["kubectl-audit.io/audit-request"], req.ID.String())
	}
	if labels["kubectl-audit.io/cluster"] != cluster.ID.String() {
		t.Errorf("cluster label = %q, want %q", labels["kubectl-audit.io/cluster"], cluster.ID.String())
	}
}

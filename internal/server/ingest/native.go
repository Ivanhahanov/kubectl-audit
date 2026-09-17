package ingest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// SourceNative is the storage.Scan/storage.Finding Source value for scans
// pushed by kubectl-audit itself.
const SourceNative = "kubectl-audit"

// nativePayload decodes only the fields a findings.json produced by
// report.RenderJSON actually needs for ingestion — deliberately not
// importing internal/report itself (which would drag in compliance/rbac
// report-only types this adapter has no use for) or committing to a report
// dependency that could later grow reasons to differ from what
// storage.Finding cares about.
type nativePayload struct {
	GeneratedAt    time.Time          `json:"generatedAt"`
	ClusterVersion string             `json:"clusterVersion,omitempty"`
	Findings       []findings.Finding `json:"findings"`
}

// NativeIngestor implements Ingestor for kubectl-audit's own findings.json.
type NativeIngestor struct{}

func (NativeIngestor) Ingest(clusterID uuid.UUID, body []byte) ([]Batch, error) {
	var payload nativePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decoding findings.json: %w", err)
	}

	scan := storage.Scan{
		ClusterID:      clusterID,
		Source:         SourceNative,
		GeneratedAt:    payload.GeneratedAt,
		ClusterVersion: payload.ClusterVersion,
	}

	out := make([]storage.Finding, 0, len(payload.Findings))
	for _, f := range payload.Findings {
		// f.ID is the finding's own cluster-scoped fingerprint (see
		// findings.ScopeID) — reused as-is, per the plan's fingerprinting
		// design. An empty ID would silently collide every such finding in
		// this scan into one row, so it's rejected rather than accepted.
		if f.ID == "" {
			return nil, fmt.Errorf("finding %q (%s) has no id", f.Title, f.Resource.String())
		}
		out = append(out, storage.Finding{
			ClusterID:          clusterID,
			Source:             SourceNative,
			Fingerprint:        f.ID,
			PolicyID:           f.PolicyID,
			Title:              f.Title,
			Severity:           string(f.Severity),
			Category:           f.Category,
			CIS:                f.CIS,
			ResourceAPIVersion: f.Resource.APIVersion,
			ResourceKind:       f.Resource.Kind,
			ResourceNamespace:  f.Resource.Namespace,
			ResourceName:       f.Resource.Name,
			Message:            f.Message,
			Remediation:        f.Remediation,
			VerificationSteps:  f.VerificationSteps,
		})
	}
	return []Batch{{Scan: scan, Findings: out}}, nil
}

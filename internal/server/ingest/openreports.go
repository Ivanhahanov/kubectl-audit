package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// SourcePrefix is prepended to the reporting tool's own identifier to form
// storage.Finding/storage.Scan's Source value — see the architecture
// plan's fingerprinting section: "source" is part of a finding's identity
// itself, so an OpenReports-sourced row can never collide with a native
// kubectl-audit one just because a hash input happened to match.
const SourcePrefix = "openreports:"

// reportableResults are the openreports.io/v1alpha1 Result values worth
// storing as findings. "pass" and "skip" aren't problems; "error" means the
// policy engine itself failed to evaluate the rule, which is an operational
// concern for that tool, not a security finding about the cluster.
var reportableResults = map[string]bool{
	"fail": true,
	"warn": true,
}

// openReportsPayload mirrors the JSON shape of openreports.io/v1alpha1's
// Report and ClusterReport (identical for our purposes — both are just
// {source, results[]} once unwrapped; see
// github.com/openreports/reports-api's report_types.go /
// clusterreport_types.go). A local mirror, not an import of that module's
// generated types, for the same reason nativePayload doesn't import
// internal/report: this adapter only needs a handful of fields.
type openReportsPayload struct {
	Source  string              `json:"source"`
	Results []openReportsResult `json:"results"`
}

type openReportsResult struct {
	// Source overrides the payload-level Source when set — see
	// ReportResult.Source's own doc comment upstream.
	Source     string              `json:"source"`
	Policy     string              `json:"policy"`
	Rule       string              `json:"rule,omitempty"`
	Category   string              `json:"category,omitempty"`
	Severity   string              `json:"severity,omitempty"`
	Result     string              `json:"result,omitempty"`
	Resources  []openReportsObjRef `json:"resources,omitempty"`
	Message    string              `json:"message,omitempty"`
	Properties map[string]string   `json:"properties,omitempty"`
}

type openReportsObjRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
}

// OpenReportsIngestor implements Ingestor for openreports.io/v1alpha1
// Report/ClusterReport documents.
type OpenReportsIngestor struct{}

func (OpenReportsIngestor) Ingest(clusterID uuid.UUID, body []byte) ([]Batch, error) {
	var payload openReportsPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decoding openreports payload: %w", err)
	}

	// Grouped by resolved Source: a single Report can legitimately mix
	// per-result Source overrides for different underlying policy
	// engines (see ReportResult.Source's upstream doc comment), and each
	// group needs its own Scan/IngestScan call — see Batch's doc comment.
	// order preserves first-seen ordering for deterministic test output;
	// Go map iteration order is not stable.
	var order []string
	grouped := map[string][]storage.Finding{}
	addSource := func(source string) {
		if _, ok := grouped[source]; !ok {
			order = append(order, source)
			grouped[source] = nil
		}
	}

	for _, res := range payload.Results {
		if !reportableResults[res.Result] {
			continue
		}
		source := SourcePrefix + resolveTool(res.Source, payload.Source)
		addSource(source)

		// A result targeting a ResourceSelector rather than concrete
		// Subjects has no single resource identity to key a row on —
		// our schema requires one; such results are skipped rather
		// than forced into a resource-less row. Real-world scanners
		// (Kyverno, Trivy-operator) always populate Resources per
		// result in practice.
		for _, ref := range res.Resources {
			grouped[source] = append(grouped[source], storage.Finding{
				ClusterID:          clusterID,
				Source:             source,
				Fingerprint:        openReportsFingerprint(clusterID, res.Policy, res.Rule, ref),
				PolicyID:           res.Policy,
				Title:              res.Policy,
				Severity:           string(findings.ParseSeverity(res.Severity)),
				Category:           res.Category,
				ResourceAPIVersion: ref.APIVersion,
				ResourceKind:       ref.Kind,
				ResourceNamespace:  ref.Namespace,
				ResourceName:       ref.Name,
				Message:            res.Message,
				Properties:         res.Properties,
			})
		}
	}

	if len(order) == 0 {
		// Nothing reportable (an all-pass/all-skip scan, or nothing
		// matched a resource) — still record one empty Scan for the
		// payload's declared source, so IngestScan's resolution pass
		// still runs and resolves any previously-open findings for it,
		// the same way an empty native findings.json does.
		addSource(SourcePrefix + resolveTool("", payload.Source))
	}

	now := time.Now().UTC()
	batches := make([]Batch, 0, len(order))
	for _, source := range order {
		batches = append(batches, Batch{
			Scan: storage.Scan{
				ClusterID: clusterID,
				Source:    source,
				// openreports.io's Report/ClusterReport carries no
				// single whole-document generation timestamp (only a
				// per-result metav1.Timestamp) — ingestion time is the
				// closest meaningful value for when this scan's data
				// became known to the store.
				GeneratedAt: now,
			},
			Findings: grouped[source],
		})
	}
	return batches, nil
}

// resolveTool picks the tool identifier a result's Source override, or the
// payload's own top-level Source, or "unknown" if neither is set.
func resolveTool(resultSource, payloadSource string) string {
	if resultSource != "" {
		return resultSource
	}
	if payloadSource != "" {
		return payloadSource
	}
	return "unknown"
}

func openReportsFingerprint(clusterID uuid.UUID, policy, rule string, ref openReportsObjRef) string {
	parts := []string{clusterID.String(), policy, rule, ref.Kind, ref.Namespace, ref.Name}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:16]
}

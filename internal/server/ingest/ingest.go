// Package ingest converts a scan payload in some tool/format's own shape
// into the canonical storage.Scan + []storage.Finding rows the server
// stores everything as — see the architecture plan's fingerprinting/dedup
// section for why "source" is part of the identity, never recomputed
// across adapters.
package ingest

import (
	"context"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// Batch is one Scan and the Findings it contains. A single Ingest call
// returns more than one Batch when a payload legitimately spans multiple
// sources in one document — e.g. an OpenReports Report whose individual
// ReportResults set per-result Source overrides for different underlying
// policy engines (the spec explicitly allows this; see
// OpenReportsIngestor). Resolution in storage.FindingRepo.IngestScan is
// scoped per (cluster_id, source), so each such group needs its own Scan
// row — collapsing them into one would silently mislabel findings under
// whichever source happened to be picked.
type Batch struct {
	Scan     storage.Scan
	Findings []storage.Finding
}

// Ingestor turns one raw request body into one or more Batches for
// clusterID (the cluster the caller authenticated as — never taken from the
// body itself, so a client can't claim an arbitrary cluster identity).
type Ingestor interface {
	Ingest(clusterID uuid.UUID, body []byte) ([]Batch, error)
}

// Store is the subset of storage.FindingRepo an ingestion handler needs.
type Store interface {
	IngestScan(ctx context.Context, scan storage.Scan, findings []storage.Finding) (storage.Scan, error)
}

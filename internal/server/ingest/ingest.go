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

// Ingestor turns one raw request body into a scan + its findings for
// clusterID (the cluster the caller authenticated as — never taken from the
// body itself, so a client can't claim an arbitrary cluster identity).
type Ingestor interface {
	Ingest(clusterID uuid.UUID, body []byte) (storage.Scan, []storage.Finding, error)
}

// Store is the subset of storage.FindingRepo an ingestion handler needs.
type Store interface {
	IngestScan(ctx context.Context, scan storage.Scan, findings []storage.Finding) (storage.Scan, error)
}

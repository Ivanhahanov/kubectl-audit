package api

import (
	"io"
	"net/http"
)

type ingestResponse struct {
	ScanID           string `json:"scanId"`
	FindingsIngested int    `json:"findingsIngested"`
}

// handleIngestNative accepts a findings.json body for the bearer-token-
// authenticated cluster and upserts it — see ingest.NativeIngestor and
// storage.FindingRepo.IngestScan for the actual dedup/resolution logic;
// this handler only wires auth + request/response framing around them.
func (s *Server) handleIngestNative(w http.ResponseWriter, r *http.Request) {
	cluster, ok := s.clusterFromToken(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}

	scan, findings, err := s.ingestors["native"].Ingest(cluster.ID, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	scan, err = s.findings.IngestScan(r.Context(), scan, findings)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storing scan")
		return
	}

	writeJSON(w, http.StatusOK, ingestResponse{
		ScanID:           scan.ID.String(),
		FindingsIngested: len(findings),
	})
}

package api

import (
	"io"
	"net/http"
)

type scanResult struct {
	ScanID           string `json:"scanId"`
	Source           string `json:"source"`
	FindingsIngested int    `json:"findingsIngested"`
}

type ingestResponse struct {
	Scans []scanResult `json:"scans"`
}

// handleIngestNative accepts a findings.json body for the bearer-token-
// authenticated cluster.
//
//	@Summary		Ingest a native findings.json scan
//	@Description	Ingests a kubectl-audit native findings.json body for the cluster identified by the bearer token. May produce more than one Scan if the payload batches multiple sources.
//	@Tags			ingest
//	@Accept			json
//	@Produce		json
//	@Security		ClusterAuth
//	@Param			request	body		object	true	"findings.json payload"
//	@Success		200		{object}	ingestResponse
//	@Failure		400		{object}	map[string]string	"invalid payload"
//	@Failure		401		{object}	map[string]string	"missing or invalid bearer token"
//	@Router			/ingest/native [post]
func (s *Server) handleIngestNative(w http.ResponseWriter, r *http.Request) {
	s.handleIngest(w, r, "native")
}

// handleIngestOpenReports accepts an openreports.io/v1alpha1
// Report/ClusterReport JSON body for the bearer-token-authenticated
// cluster.
//
//	@Summary		Ingest an OpenReports scan
//	@Description	Ingests an openreports.io/v1alpha1 Report or ClusterReport JSON body for the cluster identified by the bearer token.
//	@Tags			ingest
//	@Accept			json
//	@Produce		json
//	@Security		ClusterAuth
//	@Param			request	body		object	true	"OpenReports Report/ClusterReport payload"
//	@Success		200		{object}	ingestResponse
//	@Failure		400		{object}	map[string]string	"invalid payload"
//	@Failure		401		{object}	map[string]string	"missing or invalid bearer token"
//	@Router			/ingest/openreports [post]
func (s *Server) handleIngestOpenReports(w http.ResponseWriter, r *http.Request) {
	s.handleIngest(w, r, "openreports")
}

// handleIngest is the shared auth + framing logic behind every ingestion
// endpoint — see ingest.Ingestor and ingest.Batch for why one request can
// produce more than one Scan.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request, ingestorKey string) {
	cluster, ok := s.clusterFromToken(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}

	batches, err := s.ingestors[ingestorKey].Ingest(cluster.ID, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := ingestResponse{Scans: make([]scanResult, 0, len(batches))}
	for _, b := range batches {
		scan, err := s.repos.Findings.IngestScan(r.Context(), b.Scan, b.Findings)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storing scan")
			return
		}
		resp.Scans = append(resp.Scans, scanResult{
			ScanID:           scan.ID.String(),
			Source:           scan.Source,
			FindingsIngested: len(b.Findings),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

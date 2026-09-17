// Package api implements kubectl-audit-server's HTTP surface. Named "api"
// rather than "http" (its directory, per the architecture plan's module
// layout) purely to avoid every file in the package shadowing the
// net/http import it needs constantly.
package api

import (
	"net/http"

	"github.com/ivanhahanov/kubectl-audit/internal/server/ingest"
	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// Server holds the dependencies every handler needs. Constructed once by
// cmd/kubectl-audit-server and wired to a *http.Server via Routes().
type Server struct {
	clusters   storage.ClusterRepo
	findings   storage.FindingRepo
	adminToken string
	ingestors  map[string]ingest.Ingestor
}

// NewServer wires a Server. adminToken gates cluster registration
// (POST /api/v1/clusters) only — per-cluster ingestion endpoints are gated
// by the bearer token issued at registration instead, see clusterFromToken.
func NewServer(clusters storage.ClusterRepo, findings storage.FindingRepo, adminToken string) *Server {
	return &Server{
		clusters:   clusters,
		findings:   findings,
		adminToken: adminToken,
		ingestors: map[string]ingest.Ingestor{
			"native":      ingest.NativeIngestor{},
			"openreports": ingest.OpenReportsIngestor{},
		},
	}
}

// Routes builds the HTTP handler tree. Uses the standard library's Go 1.22+
// method+pattern ServeMux — deliberately no third-party router: the route
// set is small and this avoids one more dependency.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/clusters", s.handleRegisterCluster)
	mux.HandleFunc("POST /api/v1/ingest/native", s.handleIngestNative)
	mux.HandleFunc("POST /api/v1/ingest/openreports", s.handleIngestOpenReports)
	return mux
}

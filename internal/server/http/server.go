// Package api implements kubectl-audit-server's HTTP surface. Named "api"
// rather than "http" (its directory, per the architecture plan's module
// layout) purely to avoid every file in the package shadowing the
// net/http import it needs constantly.
package api

import (
	"net/http"

	"github.com/ivanhahanov/kubectl-audit/internal/server/automation"
	"github.com/ivanhahanov/kubectl-audit/internal/server/ingest"
	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

// Repos bundles every repository interface Server needs. A plain struct
// rather than an ever-growing positional argument list on NewServer — this
// project's storage interfaces are usually all backed by one concrete
// postgres.Store (see its own doc comment), but Server only ever depends
// on the interfaces here, never that concrete type.
type Repos struct {
	Clusters        storage.ClusterRepo
	Findings        storage.FindingRepo
	Triage          storage.TriageRepo
	KnowledgeBase   storage.KnowledgeBaseRepo
	ExclusionRules  storage.ExclusionRuleRepo
	AutomationRules storage.AutomationRuleRepo
	AuditRequests   storage.AuditRequestRepo
}

// Server holds the dependencies every handler needs. Constructed once by
// cmd/kubectl-audit-server and wired to a *http.Server via Routes().
type Server struct {
	repos           Repos
	adminToken      string
	ingestors       map[string]ingest.Ingestor
	automation      *automation.Runner
	pipelineTrigger automation.PipelineTrigger
}

// NewServer wires a Server. adminToken gates cluster registration
// (POST /api/v1/clusters) and every organization-level configuration
// endpoint (knowledge base, exclusion rules, automation rules, audit
// requests) — none of that is per-cluster scan data, so it's managed the
// same way a cluster's own registration is. Every other endpoint is
// instead gated by the bearer token issued at registration, see
// clusterFromToken.
//
// automationRunner/pipelineTrigger are optional (nil is fine): omitting
// automationRunner just disables POST /api/v1/automation-rules/evaluate
// (rule CRUD still works); omitting pipelineTrigger means approving an
// audit request updates its status without attempting to start a scan.
func NewServer(repos Repos, adminToken string, automationRunner *automation.Runner, pipelineTrigger automation.PipelineTrigger) *Server {
	return &Server{
		repos:      repos,
		adminToken: adminToken,
		ingestors: map[string]ingest.Ingestor{
			"native":      ingest.NativeIngestor{},
			"openreports": ingest.OpenReportsIngestor{},
		},
		automation:      automationRunner,
		pipelineTrigger: pipelineTrigger,
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
	mux.HandleFunc("GET /api/v1/triage", s.handleGetTriage)
	mux.HandleFunc("PATCH /api/v1/triage/{source}/{fingerprint}", s.handlePatchTriageEntry)
	mux.HandleFunc("POST /api/v1/triage/bulk", s.handleBulkTriageUpdate)
	mux.HandleFunc("GET /api/v1/knowledge-base/{policyId}", s.handleGetKnowledgeBaseEntry)
	mux.HandleFunc("PUT /api/v1/knowledge-base/{policyId}", s.handlePutKnowledgeBaseEntry)
	mux.HandleFunc("GET /api/v1/exclusion-rules", s.handleListExclusionRules)
	mux.HandleFunc("POST /api/v1/exclusion-rules", s.handleCreateExclusionRule)
	mux.HandleFunc("DELETE /api/v1/exclusion-rules/{id}", s.handleDeleteExclusionRule)
	mux.HandleFunc("GET /api/v1/automation-rules", s.handleListAutomationRules)
	mux.HandleFunc("POST /api/v1/automation-rules", s.handleCreateAutomationRule)
	mux.HandleFunc("PATCH /api/v1/automation-rules/{id}", s.handlePatchAutomationRule)
	mux.HandleFunc("DELETE /api/v1/automation-rules/{id}", s.handleDeleteAutomationRule)
	mux.HandleFunc("POST /api/v1/automation-rules/evaluate", s.handleEvaluateAutomationRules)
	mux.HandleFunc("GET /api/v1/audit-requests", s.handleListAuditRequests)
	mux.HandleFunc("POST /api/v1/audit-requests", s.handleCreateAuditRequest)
	mux.HandleFunc("PATCH /api/v1/audit-requests/{id}", s.handlePatchAuditRequest)
	return mux
}

package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/ivanhahanov/kubectl-audit/internal/storage"
)

type registerClusterRequest struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint,omitempty"`
	Owner    string `json:"owner,omitempty"`
}

type registerClusterResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

// handleRegisterCluster is admin-token-gated: registering a cluster mints a
// new bearer token, so anyone who can call this can read/write that
// cluster's findings indefinitely afterward.
//
//	@Summary		Register a cluster
//	@Description	Registers a new cluster and mints a bearer token for it. The token is only ever returned in this response — store it, it can't be recovered later.
//	@Tags			clusters
//	@Accept			json
//	@Produce		json
//	@Security		AdminAuth
//	@Param			request	body		registerClusterRequest		true	"Cluster to register"
//	@Success		201		{object}	registerClusterResponse
//	@Failure		400		{object}	map[string]string	"missing name"
//	@Failure		401		{object}	map[string]string	"missing or invalid admin token"
//	@Failure		409		{object}	map[string]string	"a cluster with this name already exists"
//	@Router			/clusters [post]
func (s *Server) handleRegisterCluster(w http.ResponseWriter, r *http.Request) {
	if !constantTimeEqual(bearerToken(r), s.adminToken) {
		writeError(w, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}

	var req registerClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	plaintext, hash, err := newClusterToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generating token")
		return
	}

	c, err := s.repos.Clusters.Register(r.Context(), req.Name, req.Endpoint, req.Owner, hash)
	if err != nil {
		writeError(w, http.StatusConflict, "registering cluster: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, registerClusterResponse{
		ID:    c.ID.String(),
		Name:  c.Name,
		Token: plaintext,
	})
}

// clusterFromToken resolves the cluster a request's bearer token belongs
// to, writing an error response and returning ok=false if it doesn't
// resolve to exactly one registered cluster.
func (s *Server) clusterFromToken(w http.ResponseWriter, r *http.Request) (storage.Cluster, bool) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return storage.Cluster{}, false
	}
	c, err := s.repos.Clusters.GetByTokenHash(r.Context(), hashToken(token))
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return storage.Cluster{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up cluster")
		return storage.Cluster{}, false
	}
	return c, true
}

// clusterFromQuery resolves the cluster named by the required "cluster_id"
// query parameter, writing an error response and returning ok=false if
// it's missing, malformed, or doesn't name a registered cluster. Used by
// the admin-token-gated triage endpoints: a cluster's own push token is
// ingest-only (see handleIngest/clusterFromToken) and grants no read/triage
// access, so those endpoints need some other way to say which cluster's
// data they're operating on — an admin caller supplies it explicitly
// instead of it being implied by a per-cluster token.
func (s *Server) clusterFromQuery(w http.ResponseWriter, r *http.Request) (storage.Cluster, bool) {
	raw := r.URL.Query().Get("cluster_id")
	if raw == "" {
		writeError(w, http.StatusBadRequest, "cluster_id is required")
		return storage.Cluster{}, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cluster_id: "+err.Error())
		return storage.Cluster{}, false
	}
	c, err := s.repos.Clusters.GetByID(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such cluster")
		return storage.Cluster{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "looking up cluster")
		return storage.Cluster{}, false
	}
	return c, true
}

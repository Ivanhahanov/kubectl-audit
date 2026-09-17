package api

import (
	"encoding/json"
	"errors"
	"net/http"

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

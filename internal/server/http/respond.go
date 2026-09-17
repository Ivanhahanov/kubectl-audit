package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header, or "" if the header is missing/malformed.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimPrefix(auth, prefix)
}

// constantTimeEqual compares two tokens without leaking timing information
// about how much of a guessed token matched — appropriate here since
// adminToken is a long-lived shared secret, not a per-request nonce.
func constantTimeEqual(a, b string) bool {
	return len(a) > 0 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

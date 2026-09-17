package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// newClusterToken generates a fresh bearer token for a cluster: the
// plaintext is returned to the caller exactly once (the registration
// response) and never stored; hash is what storage.Cluster.TokenHash keeps,
// the same sha256-of-token pattern already used for Jira tokens elsewhere
// in this project (see triage.JiraClient's doc comment).
func newClusterToken() (plaintext, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generating token: %w", err)
	}
	plaintext = hex.EncodeToString(buf)
	return plaintext, hashToken(plaintext), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

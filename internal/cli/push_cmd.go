package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	flagPushServer   string
	flagPushToken    string
	flagPushFindings string
)

func newPushCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push a findings.json scan to a kubectl-audit-server instance.",
		Long: "Uploads findings.json to POST /api/v1/ingest/native on a kubectl-audit-server instance, " +
			"authenticated as the cluster the token was issued to at registration (see `kubectl-audit-server`'s " +
			"POST /api/v1/clusters). Typically run right after `kubectl audit scan --output-json`, e.g. as the " +
			"next step in a CI pipeline or Tekton Task.",
		RunE: func(cmd *cobra.Command, args []string) error {
			serverURL := flagPushServer
			if serverURL == "" {
				serverURL = os.Getenv("KUBECTL_AUDIT_SERVER_URL")
			}
			if serverURL == "" {
				return fmt.Errorf("no server URL: set --server or KUBECTL_AUDIT_SERVER_URL")
			}
			token := flagPushToken
			if token == "" {
				token = os.Getenv("KUBECTL_AUDIT_SERVER_TOKEN")
			}
			if token == "" {
				return fmt.Errorf("no token: set --token or KUBECTL_AUDIT_SERVER_TOKEN")
			}

			findingsPath := flagPushFindings
			if findingsPath == "" {
				cfg, err := loadEffectiveConfig(cmd)
				if err != nil {
					return err
				}
				findingsPath = cfg.Output.JSON
			}
			data, err := os.ReadFile(findingsPath)
			if err != nil {
				return fmt.Errorf("reading %s: %w (run `kubectl audit scan --output-json %s` first)", findingsPath, err, findingsPath)
			}

			url := strings.TrimSuffix(serverURL, "/") + "/api/v1/ingest/native"
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, url, strings.NewReader(string(data)))
			if err != nil {
				return fmt.Errorf("building request: %w", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("pushing to %s: %w", serverURL, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server rejected push (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}

			fmt.Printf("Pushed %s to %s\n%s\n", findingsPath, serverURL, string(body))
			return nil
		},
	}
	cmd.Flags().StringVar(&flagPushServer, "server", "", "kubectl-audit-server base URL (default: $KUBECTL_AUDIT_SERVER_URL)")
	cmd.Flags().StringVar(&flagPushToken, "token", "", "this cluster's bearer token, issued at server-side cluster registration (default: $KUBECTL_AUDIT_SERVER_TOKEN — never stored in audit.yaml)")
	cmd.Flags().StringVar(&flagPushFindings, "findings", "", "path to findings.json to push (default: from config, \"findings.json\")")
	return cmd
}

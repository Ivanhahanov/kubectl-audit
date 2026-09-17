// Command kubectl-audit-mcp is the MCP (Model Context Protocol) adapter
// from the architecture plan's AI-agent integration design: a thin server
// that execs `kubectl-audit inspect` and wraps its JSON output as MCP tool
// responses. It deliberately contains zero cluster-fetching or RBAC-
// walking logic of its own — every byte of cluster data an agent can see
// passes through the same narrow, already-tested `inspect` subcommand a
// human could run directly (internal/cli's inspect_cmd.go, built on
// internal/loader/internal/rbac).
//
// This is also why an AI agent using this server never gets direct
// cluster access: no kubeconfig, no live API server credentials reach the
// agent itself — only this process's stdout, which is exactly and only
// what `kubectl-audit inspect` printed. Secret objects can never be
// returned, under any circumstance — see loader.GetResource's doc comment
// for where that's enforced, upstream of this adapter.
//
// Configuration is via environment variables (no flags), matching this
// project's other server binary (cmd/kubectl-audit-server):
//   - KUBECTL_AUDIT_BIN: path to the kubectl-audit binary (default:
//     "kubectl-audit", resolved via $PATH)
//   - KUBECONFIG / KUBE_CONTEXT: passed through to every inspect call —
//     in the intended deployment (an ephemeral process inside the same
//     Tekton Task that runs the scan), this is that Task's own kubeconfig,
//     for the Task's lifetime only.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("kubectl-audit-mcp: %v", err)
	}
}

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "kubectl-audit-inspect", Version: "v1"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "inspect_resource",
		Description: "Fetch one Kubernetes object by Kind and Name and return it as JSON. Read-only; " +
			"Secret objects can never be fetched, under any circumstance.",
	}, handleInspectResource)

	mcp.AddTool(server, &mcp.Tool{
		Name: "inspect_rbac_chain",
		Description: "Return one RBAC subject's effective bindings, permissions, and risk flags as JSON " +
			"(e.g. subject=\"ServiceAccount/deploy-bot\", namespace=\"ci\", or subject=\"Group/system:masters\"). " +
			"Read-only.",
	}, handleInspectRBACChain)

	return server
}

type inspectResourceArgs struct {
	Kind      string `json:"kind" jsonschema:"Kubernetes Kind, e.g. Deployment, Pod, ServiceAccount"`
	Name      string `json:"name" jsonschema:"object name"`
	Namespace string `json:"namespace,omitempty" jsonschema:"namespace (required for namespaced kinds, omit for cluster-scoped ones)"`
}

func handleInspectResource(ctx context.Context, _ *mcp.CallToolRequest, args inspectResourceArgs) (*mcp.CallToolResult, any, error) {
	cliArgs := []string{"resource", args.Kind + "/" + args.Name}
	if args.Namespace != "" {
		cliArgs = append(cliArgs, "-n", args.Namespace)
	}
	return toolResult(runInspect(ctx, cliArgs...))
}

type inspectRBACChainArgs struct {
	Subject   string `json:"subject" jsonschema:"subject as Kind/Name, e.g. ServiceAccount/deploy-bot or Group/system:masters"`
	Namespace string `json:"namespace,omitempty" jsonschema:"subject's namespace — only meaningful for ServiceAccount"`
}

func handleInspectRBACChain(ctx context.Context, _ *mcp.CallToolRequest, args inspectRBACChainArgs) (*mcp.CallToolResult, any, error) {
	cliArgs := []string{"rbac-chain", "--subject", args.Subject}
	if args.Namespace != "" {
		cliArgs = append(cliArgs, "-n", args.Namespace)
	}
	return toolResult(runInspect(ctx, cliArgs...))
}

// toolResult wraps runInspect's outcome as an MCP tool result — a failed
// command is reported via IsError (so the agent sees it as a tool
// failure, not a transport error), never a Go error returned to the SDK
// itself, since the command running (and reporting a clean failure) is
// the successful case from the MCP server's own point of view.
func toolResult(output string, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil, nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: output}}}, nil, nil
}

// runInspect execs `kubectl-audit inspect <args...>`, passing through
// KUBECONFIG/KUBE_CONTEXT if set — see this file's package doc comment.
// This is the only place this binary touches a subprocess; every other
// line here is pure MCP protocol/JSON plumbing.
func runInspect(ctx context.Context, args ...string) (string, error) {
	bin := os.Getenv("KUBECTL_AUDIT_BIN")
	if bin == "" {
		bin = "kubectl-audit"
	}
	full := append([]string{"inspect"}, args...)
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		full = append(full, "--kubeconfig", kubeconfig)
	}
	if kubeContext := os.Getenv("KUBE_CONTEXT"); kubeContext != "" {
		full = append(full, "--context", kubeContext)
	}

	cmd := exec.CommandContext(ctx, bin, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

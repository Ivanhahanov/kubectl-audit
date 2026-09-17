package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeKubectlAudit writes a tiny shell script standing in for the real
// kubectl-audit binary — echoes its own argv back as JSON so these tests
// can assert exactly what runInspect built, without needing a real
// cluster. Prefixed onto PATH via t.Setenv, isolated per test by t.TempDir.
func fakeKubectlAudit(t *testing.T, exitCode int, stderrMsg string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "kubectl-audit")
	body := "#!/bin/sh\n"
	if stderrMsg != "" {
		body += "echo '" + stderrMsg + "' >&2\n"
	}
	body += "echo \"[$*]\"\n"
	if exitCode != 0 {
		body += fmt.Sprintf("exit %d\n", exitCode)
	}
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("writing fake kubectl-audit: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func connectedClient(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := newServer()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("Content = %+v, want exactly one block", res.Content)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] = %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func TestToolsList(t *testing.T) {
	fakeKubectlAudit(t, 0, "")
	cs := connectedClient(t)

	res, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	if !names["inspect_resource"] || !names["inspect_rbac_chain"] {
		t.Errorf("tools = %v, want both inspect_resource and inspect_rbac_chain", names)
	}
}

func TestCallTool_InspectResource_BuildsExpectedArgs(t *testing.T) {
	fakeKubectlAudit(t, 0, "")
	cs := connectedClient(t)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "inspect_resource",
		Arguments: map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError = true, text = %q", textOf(t, res))
	}
	got := textOf(t, res)
	if !strings.Contains(got, "inspect resource Deployment/web -n default") {
		t.Errorf("fake binary saw args %q, missing expected inspect resource Deployment/web -n default", got)
	}
}

func TestCallTool_InspectRBACChain_BuildsExpectedArgs(t *testing.T) {
	fakeKubectlAudit(t, 0, "")
	cs := connectedClient(t)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "inspect_rbac_chain",
		Arguments: map[string]any{"subject": "Group/system:masters"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError = true, text = %q", textOf(t, res))
	}
	got := textOf(t, res)
	if !strings.Contains(got, "inspect rbac-chain --subject Group/system:masters") {
		t.Errorf("fake binary saw args %q, missing expected subcommand/flags", got)
	}
}

func TestCallTool_PropagatesKubeconfigAndContext(t *testing.T) {
	fakeKubectlAudit(t, 0, "")
	t.Setenv("KUBECONFIG", "/tmp/fake-kubeconfig")
	t.Setenv("KUBE_CONTEXT", "kind-demo")
	cs := connectedClient(t)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "inspect_resource",
		Arguments: map[string]any{"kind": "Namespace", "name": "kube-system"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	got := textOf(t, res)
	if !strings.Contains(got, "--kubeconfig /tmp/fake-kubeconfig") || !strings.Contains(got, "--context kind-demo") {
		t.Errorf("args = %q, want --kubeconfig/--context passed through", got)
	}
}

func TestCallTool_FailureSurfacesAsIsError(t *testing.T) {
	fakeKubectlAudit(t, 1, "Error: inspecting Secret objects is never supported")
	cs := connectedClient(t)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "inspect_resource",
		Arguments: map[string]any{"kind": "Secret", "name": "x", "namespace": "default"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("IsError = false, want true for a failing inspect call")
	}
	if !strings.Contains(textOf(t, res), "Secret objects is never supported") {
		t.Errorf("error text = %q, want the underlying stderr surfaced", textOf(t, res))
	}
}

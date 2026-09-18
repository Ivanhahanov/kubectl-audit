# kind demo deployment

Raw manifests for standing up the full kubectl-audit-server stack — Postgres,
the server itself, and a real Tekton Pipeline that scans the cluster it runs
in and pushes results back — on a local `kind` cluster. This is the fast,
no-Helm path for demoing/testing the server end-to-end, including the
`automation.TektonTrigger` audit-requests flow; see `charts/kubectl-audit-server`
for the CNPG-backed production Helm chart.

## Setup

```sh
kind create cluster --name kubectl-audit-demo
kubectl config use-context kind-kubectl-audit-demo

# Install Tekton Pipelines
kubectl apply -f https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
kubectl -n tekton-pipelines wait --for=condition=Available deployment --all --timeout=120s

# Build and load the images (from the repo root)
docker build --target audit -t kubectl-audit:demo .
docker build --target server -t kubectl-audit-server:demo .
kind load docker-image kubectl-audit:demo kubectl-audit-server:demo --name kubectl-audit-demo

# Apply everything
kubectl apply -f deploy/kind-demo/00-namespace.yaml
kubectl apply -f deploy/kind-demo/10-postgres.yaml
kubectl -n kubectl-audit-system rollout status deployment/postgres
kubectl apply -f examples/rbac/clusterrole-readonly.yaml
kubectl apply -f deploy/kind-demo/30-scan-rbac.yaml
kubectl apply -f deploy/kind-demo/40-scan-task.yaml
kubectl apply -f deploy/kind-demo/20-server.yaml
kubectl -n kubectl-audit-system rollout status deployment/kubectl-audit-server
```

## Register the cluster and wire its real push token

`40-scan-task.yaml`'s Secret ships with a placeholder — a cluster's real
token only exists after registration (the server never stores it in
plaintext, see `storage.Cluster`'s doc comment), so it has to be patched in
separately:

```sh
kubectl -n kubectl-audit-system port-forward svc/kubectl-audit-server 18080:8080 &

RESP=$(curl -s -X POST http://localhost:18080/api/v1/clusters \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"name":"kind-self-scan","owner":"demo"}')
echo "$RESP"   # note the "id" and "token" fields

kubectl -n kubectl-audit-system create secret generic kubectl-audit-server-token \
  --from-literal=token="<token from above>" --dry-run=client -o yaml \
  | kubectl apply -f -
```

## Trigger a real scan via an audit request

```sh
CLUSTER_ID="<id from registration above>"

REQ=$(curl -s -X POST http://localhost:18080/api/v1/audit-requests \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d "{\"clusterId\":\"$CLUSTER_ID\",\"reason\":\"demo\"}")
REQ_ID=$(echo "$REQ" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")

curl -s -X PATCH "http://localhost:18080/api/v1/audit-requests/$REQ_ID" \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"status":"approved"}'
# -> status flips to "running" with a real tektonPipelineRunName

kubectl -n kubectl-audit-system get pipelinerun -w
```

Once it succeeds, the findings are queryable immediately — triage is admin-token-gated, not
cluster-token-gated (a cluster's push token is ingest-only, see `docs/server.md`'s "Triage against
the server"), so use the admin token plus the `cluster_id` from registration:

```sh
curl -s "http://localhost:18080/api/v1/triage?cluster_id=$CLUSTER_ID&source=kubectl-audit" \
  -H "Authorization: Bearer demo-admin-token" | python3 -m json.tool
```

## Notes

- `20-server.yaml` sets `ADMIN_TOKEN=demo-admin-token` and a fixed Postgres
  password directly in the manifest — fine for a throwaway kind cluster,
  never do this for a real deployment (see the Helm chart for how
  production config/secrets should actually be supplied).
- The Task's two steps run as separate containers sharing an `emptyDir`
  (`/workspace`) rather than a shell one-liner — the `distroless/static`
  runtime image has no shell at all.
- `kubectl-audit scan` runs with `--fail-on none` in the Task: this
  pipeline's job is to collect and push findings regardless of severity,
  not to gate on them the way a CI job's own `scan` step normally would.

# kind demo deployment

Raw manifests for standing up the kubectl-audit-server stack — Postgres, the
server, and kubectl-audit-worker (the automation-rule evaluation loop) — on
a local `kind` cluster. This is the fast, no-Helm path for demoing/testing
the server end-to-end; see `charts/kubectl-audit-server` for the CNPG-backed
production Helm chart.

Getting findings in is deliberately just `kubectl-audit scan` + `push` — no
in-cluster pipeline/orchestrator triggers a scan on your behalf. Run it
however fits wherever the cluster being audited actually lives: by hand,
from a cron, or from whatever CI your org already has. See
`docs/server.md`'s "Registering a cluster and pushing a scan".

## Setup

```sh
kind create cluster --name kubectl-audit-demo
kubectl config use-context kind-kubectl-audit-demo

# Build and load the images (from the repo root)
docker build --target audit -t kubectl-audit:demo .
docker build --target server -t kubectl-audit-server:demo .
docker build --target worker -t kubectl-audit-worker:demo .
kind load docker-image kubectl-audit:demo kubectl-audit-server:demo kubectl-audit-worker:demo --name kubectl-audit-demo

# Apply everything
kubectl apply -f deploy/kind-demo/00-namespace.yaml
kubectl apply -f deploy/kind-demo/10-postgres.yaml
kubectl -n kubectl-audit-system rollout status deployment/postgres
kubectl apply -f deploy/kind-demo/20-server.yaml
kubectl -n kubectl-audit-system rollout status deployment/kubectl-audit-server
kubectl -n kubectl-audit-system rollout status deployment/kubectl-audit-worker
```

## Register the cluster and scan it

```sh
kubectl -n kubectl-audit-system port-forward svc/kubectl-audit-server 18080:8080 &

RESP=$(curl -s -X POST http://localhost:18080/api/v1/clusters \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"name":"kind-self-scan","owner":"demo"}')
echo "$RESP"   # note the "id" and "token" fields — the token is shown once, save it

CLUSTER_ID="<id from above>"
CLUSTER_TOKEN="<token from above>"

# Scan this same kind cluster and push the results — apply
# examples/rbac/clusterrole-readonly.yaml (bound to whatever identity you
# scan with) first if you're not already using a sufficiently-privileged
# kubeconfig.
kubectl-audit scan -A --output-json findings.json --fail-on none
kubectl-audit push --findings findings.json \
  --server-url http://localhost:18080 --token "$CLUSTER_TOKEN"
```

Findings are queryable immediately — triage is admin-token-gated, not
cluster-token-gated (a cluster's push token is ingest-only, see
`docs/server.md`'s "Triage against the server"), so use the admin token plus
the `cluster_id` from registration:

```sh
curl -s "http://localhost:18080/api/v1/triage?cluster_id=$CLUSTER_ID&source=kubectl-audit" \
  -H "Authorization: Bearer demo-admin-token" | python3 -m json.tool
```

## Notes

- `20-server.yaml` sets `ADMIN_TOKEN=demo-admin-token` and a fixed Postgres
  password directly in the manifest — fine for a throwaway kind cluster,
  never do this for a real deployment (see the Helm chart for how
  production config/secrets should actually be supplied).
- kubectl-audit-worker needs no Kubernetes API access at all — just
  `DATABASE_URL`, same as the server. It only reads/writes Postgres.

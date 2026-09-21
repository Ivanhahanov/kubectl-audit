# kubectl-audit-server Helm chart

Deploys the multi-cluster aggregation server: Postgres (via CloudNativePG by
default), the server itself, and kubectl-audit-worker (the recurring
automation-rule evaluation loop, run as its own Deployment — see
`templates/worker-deployment.yaml` for why it's separate from the server).

## Prerequisites

- The [CloudNativePG operator](https://cloudnative-pg.io) installed
  cluster-wide, if `postgres.cnpg.enabled` is left at its default `true`.
  This chart owns a `Cluster` custom resource; it does not install the
  operator itself.

## Install

```sh
helm install audit charts/kubectl-audit-server \
  --namespace kubectl-audit-system --create-namespace \
  --set image.repository=<your-registry>/kubectl-audit-server \
  --set image.tag=<tag>
```

The admin token (required for cluster registration, triage, and every
organization-level config endpoint) is auto-generated on first install and
persisted across upgrades — retrieve it with:

```sh
kubectl -n kubectl-audit-system get secret audit-admin-token -o jsonpath='{.data.token}' | base64 -d
```

## Using an existing Postgres instead of CNPG

```sh
helm install audit charts/kubectl-audit-server \
  --set postgres.cnpg.enabled=false \
  --set postgres.existingSecretName=my-postgres-creds \
  --set postgres.existingSecretKey=uri
```

`postgres.existingSecretName`'s Secret just needs one key holding a
standard `postgres://user:pass@host:port/db` connection string — the same
shape CNPG's own `<cluster>-app` Secret uses, so no custom parsing is
needed on either path. `postgres.externalDSN` (a plain string, not a
Secret reference) is also available for quick local testing, but avoid it
otherwise — anything set via `--set`/a values file ends up in `helm get
values` output and Helm's release history.

## Values

See `values.yaml` for the full list — every field has a comment.

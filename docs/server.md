---
layout: default
title: "Server & Automation"
permalink: /server/
---

# kubectl-audit-server: multi-cluster aggregation, triage, and automation

Everything on this page is optional. `kubectl audit scan` and `kubectl audit triage` work exactly
as documented in [Getting Started]({{ '/getting-started/' | relative_url }}) and
[Triage]({{ '/triage/' | relative_url }}) with zero server involvement — findings.json and a local
triage-state.yaml are still the default, permanently. `kubectl-audit-server` is a separate,
optional binary for when you're auditing more than one cluster and want findings, triage
decisions, knowledge base entries, and exclusion rules centralized instead of duplicated per
cluster — plus a few things a single local CLI invocation can't do at all: cross-source
correlation, automation rules, and triggering scans on demand.

This page is a hands-on walkthrough of every server feature, in the order you'd actually reach for
them. Each section is copy-pasteable.

## Contents

- [Quick start (no Kubernetes needed)](#quick-start-no-kubernetes-needed)
- [API documentation (Swagger/OpenAPI)](#api-documentation-swaggeropenapi)
- [Registering a cluster and pushing a scan](#registering-a-cluster-and-pushing-a-scan)
- [Triage against the server](#triage-against-the-server)
- [Ingesting findings from other tools (OpenReports)](#ingesting-findings-from-other-tools-openreports)
- [Centralized knowledge base](#centralized-knowledge-base)
- [Centralized exclusion rules](#centralized-exclusion-rules)
- [Automation rules](#automation-rules)
- [`inspect`: a narrow, read-only diagnostic CLI](#inspect-a-narrow-read-only-diagnostic-cli)
- [The MCP adapter (AI agent integration)](#the-mcp-adapter-ai-agent-integration)
- [Deploying to a real cluster (Helm chart)](#deploying-to-a-real-cluster-helm-chart)

## Quick start (no Kubernetes needed)

The server is just a Go binary plus Postgres — nothing about it requires a cluster to *run*
(only to *audit*). The fastest way to try every non-Kubernetes-specific feature below (ingestion,
triage, knowledge base, exclusion rules, automation rule matching) is `docker-compose.yml` at the
repo root:

```sh
docker build --target server -t kubectl-audit-server:demo .
docker compose up
```

This starts Postgres and the server (`ADMIN_TOKEN=demo-admin-token`, listening on `:8080`,
migrations applied automatically on startup). Everything from here on assumes the server is
reachable at `http://localhost:8080` — adjust if you deployed it elsewhere.

## API documentation (Swagger/OpenAPI)

Every endpoint below is annotated with [swaggo](https://github.com/swaggo/swag) comments and
served as an interactive Swagger UI, no separate tool required:

```
http://localhost:8080/swagger/index.html
```

The raw OpenAPI 2.0 spec backing that UI is at `http://localhost:8080/swagger/doc.json` (also
committed as `cmd/kubectl-audit-server/docs/swagger.json`/`.yaml`, handy for importing into
Postman/Insomnia or generating a client). Click "Authorize" in the UI and paste
`Bearer <admin-token>` or `Bearer <cluster-token>` to try requests directly from the browser — the
same admin-vs-cluster token split described below applies.

If you change a handler's request/response shape or add a new endpoint, regenerate the spec:

```sh
go run github.com/swaggo/swag/cmd/swag@latest init \
  -g cmd/kubectl-audit-server/main.go -o cmd/kubectl-audit-server/docs --parseInternal --pd
```

## Registering a cluster and pushing a scan

Every cluster (or, more precisely, every distinct thing that pushes scans) gets its own bearer
token, issued once by an admin call and never stored server-side in plaintext afterward:

```sh
curl -X POST http://localhost:8080/api/v1/clusters \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"name":"prod-eu-west-1","owner":"platform-team"}'
# -> {"id":"...", "name":"prod-eu-west-1", "token":"..."}  — save the token, it's shown once
```

Push a real scan with the new CLI command:

```sh
kubectl audit scan -A --output-json findings.json
kubectl-audit push --server http://localhost:8080 --token <cluster token> --findings findings.json
# or: export KUBECTL_AUDIT_SERVER_URL / KUBECTL_AUDIT_SERVER_TOKEN and drop the flags
```

Findings are deduplicated by `(cluster, source, fingerprint)` — pushing the same scan again never
creates duplicates, only updates `last_seen`; a finding that stops appearing gets its triage entry
(if any) marked `resolved` automatically. See the architecture notes in the repo's commit history
for the exact fingerprinting rules if you're curious.

## Triage against the server

`kubectl audit triage` (the same interactive TUI, `export`, and `jira-sync` you already know) can
persist decisions centrally instead of to a local `triage-state.yaml`, with **no other behavior
change** — add four things:

```sh
kubectl audit triage \
  --triage-server http://localhost:8080 \
  --triage-server-cluster-id <cluster id> \
  --triage-server-token <admin token> \
  --findings findings.json
```

Triage read/write is an **admin-gated "expert" action**, deliberately separate from a cluster's own
push token: that token is ingest-only (`POST /api/v1/ingest/*`) and grants no access to
`/api/v1/triage/*` — a leaked push token can inject fake findings but can't read anyone's triage
notes or Jira links. So `--triage-server-token` here is the server's admin token, not the cluster
token from registration, and `--triage-server-cluster-id` says explicitly which cluster's findings
you're triaging (the `id` field from that cluster's registration response, not its token).

(`--triage-server-source` defaults to `kubectl-audit`; set it explicitly if you're triaging an
OpenReports-ingested source instead — see below.) The token can also come from
`$KUBECTL_AUDIT_TRIAGE_SERVER_TOKEN`, and `--triage-server`/`--triage-server-source`/
`--triage-server-cluster-id` all have `audit.yaml` equivalents
(`triage.server.baseUrl`/`triage.server.source`/`triage.server.clusterId`) so you don't have to
repeat the flags every run — `clusterId` isn't a credential (on its own it grants nothing), so it's
fine to commit alongside `baseUrl`/`source`.

Everything — marking confirmed/false-positive/won't-fix, notes, bulk actions, even `'j'` filing a
Jira ticket — works exactly the same; only *where* the decision is saved changes.

**`--triage-server` always means findings come from the server too**, not just where decisions are
saved — `--findings`/`triage.output.json` are ignored entirely in this mode, no local scan required.
This is what makes reviewing findings pushed by a cluster you never personally scanned possible (the
multi-cluster case — a hub aggregating scans from elsewhere). It's one mode or the other on purpose:
an earlier version of this made that choice implicitly (server findings only if no local
findings.json happened to exist on disk), which was surprising — whether you saw server-side or
stale local data depended on nothing more than a stray file sitting around.

You can confirm a decision round-tripped with a plain curl call too:

```sh
curl -X PATCH "http://localhost:8080/api/v1/triage/kubectl-audit/<finding id>?cluster_id=<cluster id>" \
  -H "Authorization: Bearer <admin token>" -H "Content-Type: application/json" \
  -d '{"status":"confirmed","note":"real escalation path, needs remediation"}'

curl "http://localhost:8080/api/v1/triage?cluster_id=<cluster id>&source=kubectl-audit&status=confirmed" \
  -H "Authorization: Bearer <admin token>"
```

## Ingesting findings from other tools (OpenReports)

The server also accepts [openreports.io](https://openreports.io) `Report`/`ClusterReport`
documents (the format Kyverno's Policy Reporter, Trivy-operator, and others already emit) —
useful if you want one triage workflow across kubectl-audit and whatever else is already scanning
your clusters:

```sh
curl -X POST http://localhost:8080/api/v1/ingest/openreports \
  -H "Authorization: Bearer <cluster token>" -H "Content-Type: application/json" \
  --data-binary @my-kyverno-policyreport.json
```

Only `fail`/`warn` results become findings (`pass`/`skip` aren't problems; `error` means the
*policy engine* failed to evaluate, not a finding about your cluster). Each result's `source`
field becomes its own `openreports:<tool>` source — e.g. `openreports:kyverno` — kept completely
separate from `kubectl-audit`'s own findings; nothing is ever merged across sources. A single
document can even mix results from different tools (the spec allows per-result `source`
overrides) — the server correctly splits that into separate scans per source rather than
mislabeling everything under one.

OpenReports-sourced findings don't have Remediation/CIS/VerificationSteps (that source has no
equivalent data) — triage still works identically; the Jira template just renders those sections
as empty. Triage them from the CLI with `--triage-server-source openreports:kyverno`, or directly
via the API the same way as above, just with a different `source` in the URL/query string.

## Centralized knowledge base

Today's local `triage.knowledgeBaseFile` (per-check title/description/remediation overrides) has a
server-side equivalent, keyed by policy ID, gated by the **admin** token (this is organization-wide
configuration, not per-cluster data):

```sh
curl -X PUT http://localhost:8080/api/v1/knowledge-base/workload.no-latest-tag \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{
    "title": "Uses the :latest tag",
    "description": "Pinning to :latest makes deployments non-reproducible and silently mutable.",
    "remediation": "Pin to a specific digest or immutable version tag.",
    "labels": ["supply-chain"]
  }'

curl http://localhost:8080/api/v1/knowledge-base/workload.no-latest-tag \
  -H "Authorization: Bearer demo-admin-token"
```

(There's no CLI wiring to *consume* this from the server yet — the endpoints exist so a future
client, or your own tooling, can centralize this instead of hand-syncing a YAML file across
clusters.)

## Centralized exclusion rules

Same idea for `audit.yaml`'s `exclusionRules` — `ClusterID` unset applies a rule to every
registered cluster; set it to scope a rule (e.g. a known false positive specific to one cluster's
setup) to just that one:

```sh
# Global — applies everywhere
curl -X POST http://localhost:8080/api/v1/exclusion-rules \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"policyIds":["workload.no-latest-tag"],"match":{"kind":"Deployment","namespace":"kube-system"},"reason":"known false positive on system components"}'

# Scoped to one cluster
curl -X POST http://localhost:8080/api/v1/exclusion-rules \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{"clusterId":"<cluster id>","reason":"legacy workloads pending decommission","match":{"name":"legacy-*"}}'

# List everything that applies to one cluster (global + its own scoped rules)
curl "http://localhost:8080/api/v1/exclusion-rules?cluster_id=<cluster id>" \
  -H "Authorization: Bearer demo-admin-token"

curl -X DELETE http://localhost:8080/api/v1/exclusion-rules/<rule id> \
  -H "Authorization: Bearer demo-admin-token"
```

## Automation rules

An automation rule matches findings by severity/status/source/"no Jira link for N hours" and
records what action *would* fire — filing a Jira ticket, or (reserved for a future AI-agent
integration) an `agent_triage` action. **Action execution isn't wired up yet** — both would need
new credential/agent infrastructure this phase deliberately didn't build (see the rule's own
`detail` field, which says exactly that) — but the matching engine itself is real: create a rule,
confirm a matching finding, and it's identified correctly every time.

```sh
curl -X POST http://localhost:8080/api/v1/automation-rules \
  -H "Authorization: Bearer demo-admin-token" -H "Content-Type: application/json" \
  -d '{
    "name": "critical confirmed needs a ticket",
    "enabled": true,
    "trigger": {"minSeverity": "CRITICAL", "status": "confirmed", "noJiraLinkForHours": 24},
    "action": {"type": "file_jira"}
  }'

# Run one evaluation pass immediately (kubectl-audit-worker also runs this
# automatically every AUTOMATION_INTERVAL_SECONDS, 300s by default)
curl -X POST http://localhost:8080/api/v1/automation-rules/evaluate \
  -H "Authorization: Bearer demo-admin-token"
```

A confirmed CRITICAL finding older than 24h with no Jira link shows up in the response with
`"attempted": false` and a `detail` explaining why — that's the expected, honest state today.

## `inspect`: a narrow, read-only diagnostic CLI

Separate from the server, but built for the same reason automation rules mention an `agent_triage`
action: a way to answer one targeted question against a live cluster without a whole-cluster scan
— and, deliberately, without ever handing over real cluster credentials to anything that doesn't
already have them (see the MCP section next).

```sh
kubectl-audit inspect resource Deployment/web -n default
kubectl-audit inspect rbac-chain --subject ServiceAccount/deploy-bot -n ci
kubectl-audit inspect rbac-chain --subject Group/system:masters
```

`inspect resource` can never fetch a `Secret`, under any flag — this is a hard, unconditional rule
(stricter than the `--read-secret-values` scan flag), since inspect output can end up in an LLM's
context or logs.

## The MCP adapter (AI agent integration)

`cmd/kubectl-audit-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server
exposing `inspect_resource` and `inspect_rbac_chain` as tools an AI agent can call — implemented as
a thin wrapper that `exec`s the `inspect` CLI above and returns its JSON output; it contains no
cluster-fetching logic of its own. This is the whole point: **an AI agent using this adapter never
gets direct cluster access** — no kubeconfig, no live API credentials reach the agent itself, only
this process's stdout.

```sh
export KUBECONFIG=~/.kube/config
export KUBE_CONTEXT=my-context   # optional
kubectl-audit-mcp
```

It speaks newline-delimited JSON-RPC 2.0 over stdio — point any MCP-compatible client (Claude
Desktop, an MCP inspector, your own agent harness) at this binary directly. The intended production
placement is *ephemeral*: spun up alongside whatever process runs a scan (reusing that process's
already-legitimate, already-scoped kubeconfig for its lifetime only), never a standing sidecar with
its own credentials — not yet wired into anything automatic, since there's no in-cluster scan
orchestrator today (see "Registering a cluster and pushing a scan" above: scanning is just running
`kubectl-audit scan`/`push` wherever fits, not something the server triggers itself).

## Deploying to a real cluster (Helm chart)

`charts/kubectl-audit-server` deploys Postgres (via the
[CloudNativePG operator](https://cloudnative-pg.io), by default) plus the server and
kubectl-audit-worker (the automation-rule evaluation loop, its own Deployment):

```sh
helm install audit charts/kubectl-audit-server \
  --namespace kubectl-audit-system --create-namespace \
  --set image.repository=<your-registry>/kubectl-audit-server --set image.tag=<tag>

kubectl -n kubectl-audit-system get secret audit-admin-token \
  -o jsonpath='{.data.token}' | base64 -d   # the auto-generated admin token
```

See `charts/kubectl-audit-server/README.md` for the Postgres escape hatches (pointing at an
existing Postgres instead of CNPG) — every value is documented in `values.yaml`.

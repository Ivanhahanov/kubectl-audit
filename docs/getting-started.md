---
layout: default
title: "Getting Started"
permalink: /getting-started/
---

# Getting Started

## Install

Requires Go 1.24+.

```sh
go install github.com/{{ site.repository }}/cmd/kubectl-audit@latest
kubectl audit version
```

Or build from a clone:

```sh
git clone https://github.com/{{ site.repository }}.git
cd kubectl-audit
make build      # builds ./bin/kubectl-audit
make install     # installs onto $GOPATH/bin as kubectl-audit, so `kubectl audit` works
kubectl audit version
```

For multi-platform release archives (e.g. for krew), see `make cross-compile` and
`krew/kubectl-audit.yaml`.

## Quick start

```sh
# Audit the current cluster (kubeconfig context)
kubectl audit scan

# Audit static manifests only — e.g. in CI, before deploy
kubectl audit scan -f ./manifests --mode static

# Both cluster and static manifests, gated for CI (non-zero exit on HIGH+ findings)
kubectl audit scan -f ./manifests --fail-on high

# Scope to one namespace
kubectl audit scan -n my-namespace

# Try it against a deliberately misconfigured example from the repo
kubectl audit scan -f examples/insecure-manifests --fail-on none
```

## Commands

| Command | Description |
|---|---|
| `kubectl audit scan` | Full audit: policy checks + RBAC analysis + NetworkPolicy coverage + (optional) CIS scorecard. |
| `kubectl audit policy validate <dir>...` | Parse and CEL-compile every policy in the given directories; reports every error found. |
| `kubectl audit policy list` | List every policy that would load for a scan, with severity/category/CIS refs. |
| `kubectl audit rbac analyze` | Standalone RBAC role-model + least-privilege report (no workload policies). |
| `kubectl audit cis report` | Full scan with the CIS scorecard forced on and summarized to stdout. |
| `kubectl audit version` | Print the build version. |

Run any command with `--help` for its full flag list.

## Key flags

Available on `scan`, `rbac analyze`, and `cis report`:

- `--config audit.yaml` — load settings from a config file (see [Configuration]({{ '/configuration/' | relative_url }})); CLI flags override it.
- `--context`, `--kubeconfig` — cluster targeting.
- `-f/--files` (repeatable) — static manifest files or directories.
- `--mode cluster|static|both` — defaults to `both`, or `static` automatically if `-f` is given without an explicit `--mode`.
- `-n/--namespace` (repeatable), `--all-namespaces` — namespace scoping in cluster mode.
- `--exclude-namespace` (repeatable) — see [Noise reduction](#noise-reduction) below.
- `--include-system-rbac` — see [Noise reduction](#noise-reduction) below.
- `--policy-dir` (repeatable) — extra custom policy directories.
- `--output-json`, `--output-md` — output paths.
- `--fail-on none|low|medium|high|critical` — CI exit-code gate (default `high`).
- `--cis` — force-enable the CIS scorecard.

Note: `-n/--namespace` scopes *workload* resources (Pods, Deployments, ...) to the given
namespace(s). RBAC objects (Role/ClusterRole/\*Binding/ServiceAccount) are still loaded
cluster-wide, since a binding can reference a subject outside the scanned namespace and effective
permissions can't be resolved correctly without the full graph. Add `--exclude-namespace` if you
also want to exclude a namespace's RBAC objects.

## Noise reduction

Two things keep a cluster scan from being dominated by duplicate or non-actionable findings:

- **Owner-chain dedup.** A Deployment, its ReplicaSet, and its Pods (likewise a DaemonSet/
  StatefulSet and its Pods, or a CronJob/Job and its Pods) all carry the *same* container spec.
  Auditing all of them separately would report the same misconfiguration 2-3 times. `scan` drops a
  resource whenever its controller owner (via `ownerReferences[].controller`) was also loaded,
  keeping only the top-level object as the single representative. If the owner was excluded by
  `--include-kind`/`--exclude-kind`, the owned resource is kept instead, so the template is never
  silently lost.
- **Platform namespace/RBAC exclusion.** `kube-system`, `kube-public`, and `kube-node-lease` are
  excluded by default, and `Role`/`ClusterRole`/`RoleBinding`/`ClusterRoleBinding` objects with the
  reserved `system:` name prefix (Kubernetes' own built-in RBAC) are excluded by default too.
  Their workloads/RBAC are cluster-internal plumbing (kube-proxy needs `hostNetwork`,
  `system:controller:*` roles need their wildcards) that can't be remediated and mostly just
  drowns out real findings. Third-party components installed *into* kube-system (e.g. a CSI
  driver's own, non-`system:`-prefixed ClusterRoleBinding) are **not** filtered.

  Override with `--exclude-namespace ""` (clears the defaults), `--exclude-namespace <ns>`
  (repeatable, adds more), `-n/--namespace` (an explicit allowlist bypasses the default excludes
  entirely), and `--include-system-rbac`.

## Engine limitations

These are deliberate, documented boundaries rather than bugs:

- `spec.variables` is not supported in VAP policies — policies that declare it fail to compile
  with a clear message. Inline the expression instead.
- The `authorizer` CEL variable is not declared — policies referencing `authorizer.*` fail to
  compile. This engine audits standing state, not live admission requests, so there's no
  SubjectAccessReview backing it. Use the RBAC analyzer for RBAC-aware checks instead.
- `matchConstraints.resourceRules[].operations` is not filtered on: every loaded resource is
  evaluated regardless of the rule's declared operations, since the engine audits existing objects
  rather than simulating a specific CREATE/UPDATE/DELETE request.
- `ValidatingAdmissionPolicyBinding` objects are not consumed — every loaded policy's
  `matchConstraints` is applied directly to every resource.
- Cilium/Calico NetworkPolicy coverage is presence-based, not a full selector simulation — see
  [NetworkPolicy Coverage]({{ '/network-policy/' | relative_url }}).

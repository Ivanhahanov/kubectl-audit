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

# Score against several compliance frameworks at once
kubectl audit scan --frameworks cis,fstec,nsa
```

## Commands

| Command | Description |
|---|---|
| `kubectl audit scan` | Full audit: policy checks + RBAC analysis + NetworkPolicy coverage + Pod Security Standards + compliance scorecards. Prints both a severity summary and a compliance summary. |
| `kubectl audit policy validate <dir>...` | Parse and CEL-compile every policy in the given directories; reports every error found. |
| `kubectl audit policy list` | List every policy that would load for a scan, with severity/category/CIS refs. |
| `kubectl audit rbac analyze` | Standalone RBAC role-model + least-privilege report (no workload policies, no compliance scorecards). |
| `kubectl audit template dump` | Write the built-in `report.md.tpl` to disk as a starting point for `--report-template` — see [Report Templates]({{ '/report-templates/' | relative_url }}). |
| `kubectl audit version` | Print the build version. |

Run any command with `--help` for its full flag list — each command only shows the flags actually
relevant to it (e.g. `--frameworks` only appears on `scan`, not `rbac analyze` or `policy list`).

## Key flags

Available on `scan` and `rbac analyze`:

- `--config audit.yaml` — load settings from a config file (see [Configuration]({{ '/configuration/' | relative_url }})); CLI flags override it. Global, works on every command.
- `--context`, `--kubeconfig` — cluster targeting.
- `-f/--filename` (repeatable) — static manifest files or directories, matching `kubectl apply`'s own `-f/--filename`.
- `--mode cluster|static|both` — defaults to `both`, or `static` automatically if `-f` is given without an explicit `--mode`.
- `-n/--namespace` (repeatable), `-A/--all-namespaces` — namespace scoping in cluster mode.
- `--exclude-namespace` (repeatable) — see [Noise reduction](#noise-reduction) below.
- `--include-system-rbac` — see [Noise reduction](#noise-reduction) below.
- `--output-json`, `--output-md` — output paths. Defaults differ per command so `scan` and
  `rbac analyze` don't overwrite each other when run against the same directory: `scan` writes
  `findings.json`/`report.md`, `rbac analyze` writes `rbac-findings.json`/`rbac-report.md`.
- `--output-csv` — write findings as CSV (one row per finding: severity, policy ID, category, CIS
  refs, resource, message, remediation, source, id), sorted most-severe first. Not written by
  default. Meant for opening in a spreadsheet to sort/filter/pivot or hand off to someone tracking
  remediation who doesn't want the full Markdown/JSON — JSON is the better fit for feeding another
  tool programmatically.
- `--report-template <file>` — custom `report.md.tpl`; see [Report Templates]({{ '/report-templates/' | relative_url }}).
- `--fail-on none|low|medium|high|critical` — CI exit-code gate (default `high`).

`scan`-only:

- `--policy-dir` (repeatable) — extra custom policy directories (also on `policy list`).
- `--frameworks cis,fstec,nsa` — compliance framework(s) to score against (repeatable or
  comma-separated; default `cis`), or a path to a [custom mapping]({{ '/custom-checks/' | relative_url }});
  see [Compliance Frameworks]({{ '/compliance/' | relative_url }}).
- `--check-updates` — live EOL/patch-currency check against endoflife.date; see
  [Compliance Frameworks]({{ '/compliance/' | relative_url }}).

Note: `-n/--namespace` scopes *workload* resources (Pods, Deployments, ...) to the given
namespace(s). RBAC objects (Role/ClusterRole/\*Binding/ServiceAccount) are still loaded
cluster-wide, since a binding can reference a subject outside the scanned namespace and effective
permissions can't be resolved correctly without the full graph. Add `--exclude-namespace` if you
also want to exclude a namespace's RBAC objects.

## Scope

Every `report.md` opens with a **Scope** section stating plainly what this particular scan could
and couldn't see — computed once from what was actually loaded, instead of leaving you to infer it
from a dozen individually-worded `NOT_APPLICABLE` compliance rows. Two situations drive most of
what shows up there:

- **A single manifest or partial file set** (`scan -f one-deployment.yaml`): RBAC and NetworkPolicy
  findings only reflect what's in the given file(s) — a workload flagged as "no NetworkPolicy"
  might actually be covered by a policy that lives in a file you didn't include in this scan.
- **A managed cluster** (EKS/GKE/AKS, ...): control-plane configuration checks (CIS Section 1/2)
  can't run at all, since the API server/etcd/controller-manager/scheduler aren't exposed as Pods
  there — see [Compliance Frameworks]({{ '/compliance/' | relative_url }}) for what that covers.

If nothing was structurally out of reach, the section just says so ("Full scope") instead of
listing anything.

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

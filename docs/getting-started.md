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
- `-v/--verbose` — show debug-level diagnostic detail in addition to warnings (which are always
  shown): per-optional-CRD resolution outcomes ("CRD group X is not registered on this cluster —
  skipping"), and similar routine decisions that are silent by default because they'd otherwise be
  noise on every ordinary scan. Useful for troubleshooting *why* a check or component didn't fire —
  see [Third-Party Operators]({{ '/third-party-operators/' | relative_url }}) for what those
  decisions actually gate. Global, works on every command.
- `--context`, `--kubeconfig` — cluster targeting.
- `--cluster-name` — human-readable name to use in the report's Target field and every finding's
  Source, instead of the raw kube-context name (which defaults to `current-context` when
  `--context` isn't set, or can be an unreadable cloud-provider ARN/UUID). Cosmetic only — doesn't
  change what's scanned. Useful when scanning several clusters and archiving/diffing their reports.
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
- `--report-view check|namespace|both` — how the Markdown report's Findings section(s) are
  structured (default `check`). `check` groups findings by check/policy ID — each check's
  title/remediation shown once, followed by the resources it fired on. `namespace` groups by
  namespace/resource instead, full detail per finding — useful for a per-team/per-app handoff.
  `both` renders the check-grouped view plus a compact by-namespace index. On a large cluster
  `both` roughly doubles the number of finding lines in the report (every finding listed once per
  view); pick `check` or `namespace` alone once the finding count gets into the hundreds/thousands.
- `--namespace-group-threshold <n>` — collapse a check's repeated per-namespace findings in the
  Markdown report (default `3`; `0` disables); see [Noise reduction](#noise-reduction) below.
- `--fail-on none|low|medium|high|critical` — CI exit-code gate (default `high`).

`scan`-only:

- `--policy-dir` (repeatable) — extra custom policy directories (also on `policy list`).
- `--frameworks cis,fstec,nsa` — compliance framework(s) to score against (repeatable or
  comma-separated; default `cis`), or a path to a [custom mapping]({{ '/custom-checks/' | relative_url }});
  see [Compliance Frameworks]({{ '/compliance/' | relative_url }}).
- `--check-updates` — live EOL/patch-currency check against endoflife.date; see
  [Compliance Frameworks]({{ '/compliance/' | relative_url }}).
- `--read-secret-values` — off by default; lets a small number of checks read Secret values to
  detect authentication left at its documented default/disabled state. Needs a different,
  Secrets-granting ClusterRole — see [Secrets Mode]({{ '/secrets-mode/' | relative_url }}) and
  [Required Permissions]({{ '/permissions/' | relative_url }}).

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

Three things keep a cluster scan from being dominated by duplicate or non-actionable findings:

- **Owner-chain dedup.** A Deployment, its ReplicaSet, and its Pods (likewise a DaemonSet/
  StatefulSet and its Pods, or a CronJob/Job and its Pods) all carry the *same* container spec.
  Auditing all of them separately would report the same misconfiguration 2-3 times. `scan` drops a
  resource whenever its controller owner (via `ownerReferences[].controller`) was also loaded,
  keeping only the top-level object as the single representative. If the owner was excluded by
  `--include-kind`/`--exclude-kind`, the owned resource is kept instead, so the template is never
  silently lost.
- **Empty-namespace exclusion.** `kube-public` and `kube-node-lease` are excluded by default —
  they hold nothing worth auditing (a public ConfigMap, Lease objects). `kube-system` is
  deliberately **not** excluded by default: it commonly hosts real, auditable third-party
  infrastructure (CNI, CSI drivers, ...) alongside core Kubernetes plumbing, and blanket-excluding
  the whole namespace would hide genuine problems in it along with the unavoidable ones — this
  tool used to exclude it too, until testing turned up a real privileged CSI driver sitting
  silently unflagged in `kube-system` precisely because of that blanket exclusion.
- **Built-in exceptions for unavoidable core-plumbing violations**, instead of hiding the
  namespace. kube-proxy (needs `hostNetwork` + `privileged` to manage host iptables/ipvs rules)
  and the kubeadm static control-plane pods (`kube-apiserver`/`kube-controller-manager`/
  `kube-scheduler`/`etcd` — need `hostNetwork` + host-mounted certs/data by the static-pod model
  itself, only relevant on a self-managed/kubeadm cluster) get precise, label-matched exceptions
  for exactly their documented-unavoidable violations — see
  [Third-Party Operators: Built-in exceptions]({{ '/third-party-operators/#built-in-exceptions-for-privileged-system-infrastructure' | relative_url }})
  for the full list and sourcing; everything else about these objects (missing seccomp profile,
  running as root, the default ServiceAccount, ...) is still flagged normally as a genuine
  hardening opportunity.
- **RBAC `system:` prefix exclusion.** `Role`/`ClusterRole`/`RoleBinding`/`ClusterRoleBinding`
  objects with the reserved `system:` name prefix (Kubernetes' own built-in RBAC,
  e.g. `system:controller:*`) are excluded by default — cluster-managed, not something an operator
  can remediate. Third-party components' own RBAC objects (e.g. a CSI driver's non-`system:`
  ClusterRoleBinding) are **not** filtered by this.

  Override with `--exclude-namespace ""` (clears the defaults), `--exclude-namespace <ns>`
  (repeatable, adds more), `-n/--namespace` (an explicit allowlist bypasses the default excludes
  entirely), `--no-builtin-exceptions` (disables the core-plumbing and third-party exceptions
  above), and `--include-system-rbac`.
- **Repeated-tenant-namespace collapsing.** Multi-tenant clusters commonly provision one namespace
  per tenant/customer/environment — Capsule-provisioned tenants are the canonical example, but this
  applies to any "one namespace per X" convention — and deploy the *same* manifest into each, so
  the same misconfiguration is flagged once per namespace. With dozens or hundreds of such
  namespaces, this can drown out everything else in the report. In the Markdown report, whenever a
  check's message is identical for every finding (true of essentially every built-in VAP/CEL check
  — native analyzers like RBAC/PSS/control-plane, which build a per-resource message, are never
  affected) and it fires on the same Kind+Name pair in at least `N` distinct namespaces, those
  findings are shown as one row — "`Deployment/app` — repeated identically in `N` namespaces:
  `tenant-a, tenant-b, ...`" — instead of one bullet per namespace.

  This is purely a Markdown rendering choice: `findings.json` and CSV output always list every
  finding individually with its own namespace, so `--fail-on` gating, suppression accounting, and
  any CI tooling consuming JSON see no difference at all.

  On by default (`N = 3`). Tune with `--namespace-group-threshold <n>` or
  `output.namespaceGroupThreshold` in `audit.yaml`; set `0` to always list every namespace
  individually.

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
- `matchConstraints.resourceRules[].resources` is matched against a fixed Kind→plural-resource-name
  table (`internal/loader/kinds.go`), not derived from cluster discovery — a custom policy
  targeting a Kind not in that table never matches anything (compiles fine, silently finds
  nothing). Built-in Kinds and CRDs the bundled policies already target (e.g. Capsule's `Tenant`)
  are covered; a custom policy for an unlisted Kind needs an entry added there.

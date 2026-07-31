# kubectl-audit

[![Go Reference](https://pkg.go.dev/badge/github.com/ivanhahanov/kubectl-audit.svg)](https://pkg.go.dev/github.com/ivanhahanov/kubectl-audit)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Full docs: **https://ivanhahanov.github.io/kubectl-audit/** (once GitHub Pages is enabled on this
repo — see [docs/README.md](docs/README.md)).

A `kubectl` plugin (`kubectl audit ...`) for auditing Kubernetes security posture:

- **Policy checks** written as real `admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy`
  (VAP) objects with CEL expressions — the same YAML you can `kubectl apply -f` to enforce
  in-cluster, at admission time. Drop a new policy file into a directory to add a check; no
  code changes required.
- **RBAC analysis**: builds the effective permission model per subject (User/Group/ServiceAccount)
  across Roles, ClusterRoles, and their bindings — including resolving aggregated ClusterRoles
  (`aggregationRule`) even in static-manifest mode, where the API server hasn't materialized their
  `.rules` yet — and flags least-privilege violations that need cross-object reasoning
  (privilege-escalation verbs, exec/attach access, broad Secrets access, RBAC self-modification,
  risky ServiceAccount token automount).
- **NetworkPolicy coverage**: flags every workload with no applicable NetworkPolicy in its
  namespace. Native Kubernetes NetworkPolicy is checked precisely (`podSelector` + `policyTypes`
  matched against the workload's pod-template labels); Cilium (`CiliumNetworkPolicy`/
  `CiliumClusterwideNetworkPolicy`) and Calico (`crd.projectcalico.org/v1`
  `NetworkPolicy`/`GlobalNetworkPolicy`) are detected via discovery when installed and used as a
  presence-based coverage signal — see [`internal/netpol`](internal/netpol/coverage.go) for why
  their selector languages aren't simulated in detail.
- **CIS Kubernetes Benchmark** compliance scorecard for every control observable through the
  Kubernetes API. Control-plane/node-level controls (sections 1-4) are explicitly reported as
  "Not Applicable" rather than silently skipped — see [CIS Benchmark scope](#cis-benchmark-scope).
- Audits a **live cluster** (via kubeconfig), **static manifest files/directories** (for
  pre-deploy / CI checks), or both at once.
- Outputs a machine-readable `findings.json` and a human-readable `report.md`, with a
  `--fail-on <severity>` gate for CI pipelines.

## Install

Requires Go 1.24+.

```sh
go install github.com/ivanhahanov/kubectl-audit/cmd/kubectl-audit@latest
kubectl audit version
```

Or build from a clone:

```sh
git clone https://github.com/ivanhahanov/kubectl-audit.git
cd kubectl-audit
make build              # builds ./bin/kubectl-audit
make install             # installs it onto $GOPATH/bin as kubectl-audit, so `kubectl audit` works
kubectl audit version
```

For multi-platform release archives (e.g. for krew distribution), see `make cross-compile` and
`krew/kubectl-audit.yaml` (a template — bump the version and fill in release checksums before
submitting to krew).

## Quick start

```sh
# Audit a live cluster (current kube-context) and write findings.json + report.md
kubectl audit scan

# Audit static manifests only (e.g. in CI, before deploy)
kubectl audit scan -f ./manifests --mode static

# Both cluster and static manifests, gated for CI (non-zero exit on HIGH+ findings)
kubectl audit scan -f ./manifests --fail-on high

# Try it against a deliberately misconfigured example
kubectl audit scan -f examples/insecure-manifests --fail-on none
```

## Commands

| Command | Description |
|---|---|
| `kubectl audit scan` | Full audit: policy checks + RBAC analysis + (optional) CIS scorecard. |
| `kubectl audit policy validate <dir>...` | Parse and CEL-compile every policy in the given directories; reports every error found. |
| `kubectl audit policy list` | List every policy that would load for a scan, with severity/category/CIS refs. |
| `kubectl audit rbac analyze` | Standalone RBAC role-model + least-privilege report (no workload policies). |
| `kubectl audit cis report` | Full scan with the CIS scorecard forced on and summarized to stdout. |
| `kubectl audit version` | Print the build version. |

Run any command with `--help` for its full flag list. Key flags (available on `scan`, `rbac
analyze`, `cis report`):

- `--config audit.yaml` — load settings from a config file (see below); CLI flags override it.
- `--context`, `--kubeconfig` — cluster targeting.
- `-f/--files` (repeatable) — static manifest files or directories.
- `--mode cluster|static|both` — defaults to `both`, or `static` automatically if `-f` is given
  without an explicit `--mode`.
- `-n/--namespace` (repeatable), `--all-namespaces` — namespace scoping in cluster mode.
- `--exclude-namespace` (repeatable) — see [Noise reduction](#noise-reduction-owner-chains--platform-namespaces) below.
- `--include-system-rbac` — see [Noise reduction](#noise-reduction-owner-chains--platform-namespaces) below.
- `--policy-dir` (repeatable) — extra custom policy directories.
- `--output-json`, `--output-md` — output paths.
- `--fail-on none|low|medium|high|critical` — CI exit-code gate (default `high`).
- `--cis` — force-enable the CIS scorecard.

## Noise reduction: owner chains & platform namespaces

Two things keep a cluster scan from being dominated by duplicate or non-actionable findings:

- **Owner-chain dedup.** A Deployment, its ReplicaSet, and its Pods (likewise a DaemonSet/
  StatefulSet and its Pods, or a CronJob/Job and its Pods) all carry the *same* container spec.
  Auditing all of them separately reports the same misconfiguration 2-3 times. `scan` drops a
  resource whenever its controller owner (via `ownerReferences[].controller`) was also loaded —
  keeping only the top-level object (e.g. the Deployment) as the single representative. If the
  owner was excluded by `--include-kind`/`--exclude-kind`, the owned resource is kept instead, so
  the template is never silently lost.
- **Platform namespace/RBAC exclusion.** `kube-system`, `kube-public`, and `kube-node-lease` are
  excluded by default (`target.excludeNamespaces` in config), and `Role`/`ClusterRole`/
  `RoleBinding`/`ClusterRoleBinding` objects with the reserved `system:` name prefix — Kubernetes'
  own built-in RBAC — are excluded by default too. Their workloads/RBAC are cluster-internal
  plumbing (kube-proxy needs `hostNetwork`, `system:controller:*` roles need their wildcards) that
  can't be remediated and mostly just drowns out real findings. Third-party components installed
  *into* kube-system (e.g. a CSI driver's own, non-`system:`-prefixed ClusterRoleBinding) are
  **not** filtered — only Kubernetes' own reserved-name objects are.

  Override with `--exclude-namespace ""` (clears the defaults) or `--exclude-namespace <ns>`
  (repeatable, adds more), `-n/--namespace` (an explicit allowlist bypasses the default excludes
  entirely), and `--include-system-rbac`.

## Configuration (`audit.yaml`)

See [`examples/audit.yaml`](examples/audit.yaml) for a fully-commented example covering target
mode, namespaces, policy directories/exclusions, output paths, the `--fail-on` threshold, and CIS
settings.

## Writing custom policies

Policies are plain `ValidatingAdmissionPolicy` YAML. Audit-specific metadata (severity, category,
remediation text, CIS control references) lives entirely in `metadata.annotations` under the
`audit.k8s-auditor.io/` prefix, so the file stays 100% valid to `kubectl apply -f` as a real
in-cluster enforcement policy:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: org.require-owner-label
  annotations:
    audit.k8s-auditor.io/severity: low
    audit.k8s-auditor.io/category: org-policy
    audit.k8s-auditor.io/remediation: "Add a team label identifying the owning team."
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  validations:
    - expression: "has(object.metadata.labels) && has(object.metadata.labels.team)"
      message: "Workload is missing a 'team' label."
```

Load it with `kubectl audit scan --policy-dir ./my-policies`, or add the directory under
`policies.dirs` in `audit.yaml`. See [`examples/custom-policy-example.yaml`](examples/custom-policy-example.yaml).

The bundled default policies live in [`policies/workload`](policies/workload) and
[`policies/rbac`](policies/rbac) — read them for more CEL examples (they handle the fact that
container specs live at different paths depending on whether the object is a bare `Pod`, a
Deployment/StatefulSet/DaemonSet/ReplicaSet (`spec.template.spec`), or a CronJob
(`spec.jobTemplate.spec.template.spec`)).

### Engine limitations (by design, documented rather than silently wrong)

- `spec.variables` is not supported — policies that declare it fail to compile with a clear
  message. Inline the expression instead.
- The `authorizer` CEL variable is not declared — policies referencing `authorizer.*` fail to
  compile. This engine audits standing state, not live admission requests, so there's no
  SubjectAccessReview backing it. Use the RBAC analyzer for RBAC-aware checks instead.
- `matchConstraints.resourceRules[].operations` is not filtered on: every loaded resource is
  evaluated regardless of the rule's declared operations, since the engine audits existing
  objects rather than simulating a specific CREATE/UPDATE/DELETE request.
- `ValidatingAdmissionPolicyBinding` objects are not consumed — every loaded policy's
  `matchConstraints` is applied directly to every resource.

## CIS Benchmark scope

Section numbering follows the public CIS Kubernetes Benchmark structure. Sections 1-4 (control
plane components, etcd, control-plane configuration files, worker node/kubelet configuration)
require SSH/file access to node filesystems and process arguments that a kubectl plugin
fundamentally cannot see through the Kubernetes API — they're reported as `NOT_APPLICABLE` with a
pointer to run [kube-bench](https://github.com/aquasecurity/kube-bench) on the nodes instead.
Section 5 (Policies: RBAC, Pod Security Standards, Network Policies, general policies) is
API-observable and is what this tool implements; see [`cis-mappings/mapping.yaml`](cis-mappings/mapping.yaml)
for the exact control-to-check mapping. Treat the mapping as a practical cross-reference, not a
substitute for the official CIS PDF when compliance-grade attestation is required.

## Architecture

```
cmd/kubectl-audit        entrypoint
internal/cli              cobra commands, config/CLI-flag merging, scan orchestration
internal/config            audit.yaml schema + loader
internal/k8sclient          kubeconfig/context resolution, dynamic + discovery clients
internal/loader              resource loading: live cluster (dynamic client) and static YAML/JSON
internal/engine                VAP parsing, CEL compilation (cel-go), matchConstraints matching, evaluation
internal/rbac                   RBAC graph, effective-permission computation, least-privilege checks, role model
internal/netpol                  NetworkPolicy coverage: per-workload selector matching + Cilium/Calico presence
internal/cis                      CIS control table + scorecard builder
internal/findings                  shared Finding/Severity model
internal/report                     findings.json and report.md renderers
policies/                 bundled default VAP policies (go:embed)
cis-mappings/               CIS control table (go:embed)
examples/                    sample config, custom policy, deliberately-insecure manifests
```

`scan` loads resources (cluster and/or static), runs every loaded policy's CEL expressions against
them, runs the RBAC analyzer and the NetworkPolicy coverage analyzer over the same resource set,
merges and dedupes the resulting findings, optionally builds the CIS scorecard from those findings,
and renders both output files. `rbac analyze` and `cis report` reuse the same pipeline with a
narrower focus.

---
layout: default
title: "Compliance Frameworks"
permalink: /compliance/
---

# Multi-framework compliance

`kubectl audit scan --frameworks cis,fstec,nsa` scores findings against one or more requirement
frameworks at once, each from its own control table in
[`compliance-mappings/`](https://github.com/{{ site.repository }}/tree/main/compliance-mappings):

| Framework | ID | Source |
|---|---|---|
| CIS Kubernetes Benchmark | `cis` | Public CIS Kubernetes Benchmark control structure. |
| FSTEC | `fstec` | "Требования по безопасности информации, предъявляемые к средствам контейнеризации" — certifies the containerization *product* itself, not cluster config. |
| NSA/CISA Kubernetes Hardening Guidance | `nsa` | v1.2 (August 2022), verified against the official PDF text section-by-section. |

Default is `cis` alone. Treat every mapping as a practical cross-reference, not a substitute for
the official document when compliance-grade attestation is required — wording/numbering can shift
between revisions, and this tool only sees what's observable through the Kubernetes API.

## Cluster version awareness

The CIS mapping is written against CIS Kubernetes Benchmark v2.0.1, which targets Kubernetes
v1.34-v1.35. Every scan against a live cluster detects the actual server version (`report.md`'s
**Cluster version** line, `clusterVersion` in `findings.json`) and uses it in two concrete ways:

- The Pod Security Standards evaluation described below (`internal/pss`) evaluates against the PSS
  rule revisions that actually applied to the detected version — `k8s.io/pod-security-admission`'s
  own check implementations are versioned
  (e.g. the Restricted capabilities rule changed at 1.22 and again at 1.25), so evaluating an old
  cluster against "latest" rules could apply requirements that didn't exist yet for it.
- A dedicated check (`version-analyzer.cluster.outside-support-window`, mapped to NSA's
  `upgrading.practices`) flags a cluster running further behind the newest version this build knows
  about than Kubernetes' typical ~3-minor-version upstream support window — a version-distance
  approximation, not a live lookup of the actual EOL calendar or any vendor's extended-support
  program. `NOT_APPLICABLE` on a static-manifest-only scan (no live cluster to detect a version
  from at all).

What this does **not** do: it doesn't gate individual control-plane flag checks
(`policies/controlplane/*.yaml`, `internal/controlplane`) by the flag's actual introduction
version, or swap in an older CIS benchmark revision's control numbering/wording for an old
cluster. Most of the flags those checks look at (`--anonymous-auth`, `--profiling`,
`--authorization-mode`, `--audit-log-*`, ...) have been stable since very early Kubernetes
releases, but a handful are genuinely newer (e.g.
`--service-account-extend-token-expiration`) — on an old enough cluster, a control like that can
read as a `FAIL` for a flag that didn't exist yet rather than one that was misconfigured. Treat
those specific findings with proportionate skepticism on clusters more than a couple of minor
versions behind CIS v2.0.1's target range, and prefer the version-aware PSS/EOL signals above,
which are on solid ground, over the flag-presence heuristics for very old clusters.

### `--check-updates`: live patch/EOL data instead of the built-in approximation

`version-analyzer.cluster.outside-support-window` above is a version-*distance* approximation,
computed entirely offline. Pass `--check-updates` to additionally make one live HTTPS request to
[endoflife.date](https://endoflife.date/kubernetes)'s Kubernetes release-cycle API — the only
network call this tool ever makes beyond the target cluster itself — and get real data instead:
whether a newer *patch* release exists for the detected minor version (`k8supdates.patch-available`
— a patch bump you're missing can carry backported security fixes even when you're on a fully
supported minor), whether the cycle has reached real end-of-life or end-of-active-support
(`k8supdates.end-of-life` / `k8supdates.end-of-active-support`, with actual dates instead of a
distance heuristic), and whether a newer minor cycle exists at all (`k8supdates.newer-minor-available`,
low severity — being behind isn't itself a security issue).

Off by default, and a fetch failure (network unavailable, API down, rate-limited) only logs a
warning and falls back to the offline approximation — it never aborts the scan. This is the one
place this tool leaves fully-offline/air-gapped operation; everything else only ever talks to the
target cluster or reads local files.

### Removed Kubernetes API versions (`apideprecations`)

Every scan (no flag needed — fully offline, no hand-maintained table either) also flags manifests
declaring an `apiVersion` that Kubernetes has fully removed (`extensions/v1beta1 Ingress`,
`policy/v1beta1 PodSecurityPolicy`, ...). `CRITICAL` if it's already removed as of the
detected/target cluster version (the manifest can't even be applied); `HIGH` if it still works
today but was removed in some later release (it'll break on your next upgrade past that point).

This needs no network call *and* no hand-maintained table: `internal/apideprecations` reads the
removal metadata Kubernetes' own release tooling (`prerelease-lifecycle-gen`) generates directly
onto the Go types in `k8s.io/api` — every type that's ever been removed has generated
`APILifecycleRemoved()`/`APILifecycleReplacement()` methods (e.g.
`k8s.io/api/extensions/v1beta1/zz_generated.prerelease-lifecycle.go`); types that were never
removed simply don't implement that interface. `k8s.io/client-go/kubernetes/scheme` registers
every historical group/version — including long-removed ones — specifically so tooling like this
can still construct an instance by GVK and ask it. This means the data is exactly as fresh as the
`k8s.io/api` version this binary was built against: bumping that dependency (routine maintenance,
done for other reasons anyway) picks up whatever new removals shipped since, with nothing to
hand-edit. If the detected cluster is running far enough ahead of `k8sversion.LatestKnownMinor` (a
proxy for how current the `k8s.io/api` dependency is), a scan logs a warning that this build's
removal data may not know about the newest releases yet.

One real limitation: this is primarily a **static-manifest / pre-deploy** check. Live cluster scans
fetch every resource kind at one specific, current API version (see `internal/loader`'s
`defaultResources`) — the Kubernetes API server itself always converts a stored object to
whichever version you ask for, so a live scan will essentially never see an old `apiVersion` on a
resource that's actually running, even if it was originally created with one years ago. Point this
at your raw manifests/Helm output/Kustomize output in CI, before they reach a cluster, for the
signal to be meaningful.

## Indirect signals: control-plane flag checks

CIS sections 1.2 (API Server), 1.3 (Controller Manager), 1.4 (Scheduler), and 2 (etcd) are almost
entirely command-line-flag checks. On a self-hosted/kubeadm-style cluster (including `kind`), these
components run as ordinary static Pods — visible via the Kubernetes API the same way any other Pod
spec is, typically in `kube-system`, labeled `component=kube-apiserver` etc. — so their
`command`/`args` are inspectable without SSH (`internal/controlplane`).

This is explicitly an **indirect, best-effort signal**, not a kube-bench-grade check: it reflects
what a flag is *set to* in the Pod spec, not whether the setting is actually effective (a running
process could differ from its manifest, a distro could apply an undocumented default, etc). Every
control backed by this says so in its `note`, and every finding it produces is prefixed
`[indirect signal — inferred from the <component> static Pod's command-line flags via the
Kubernetes API, not confirmed via node/file access]`.

On a managed control plane (EKS, GKE, AKS, ...) that doesn't expose these Pods at all, the affected
controls report `NOT_APPLICABLE` for the run (component not observed) instead of a false `PASS` —
see `compliance.OverrideUnobserved`, wired into `internal/cli/orchestrate.go`.

## Why so much is `NOT_APPLICABLE`

Every framework here was written for a broader scope than "is this Kubernetes cluster's
configuration sound," and this tool is honest about the gap rather than silently skipping it:

- **CIS** sections 1.1 (node config file permissions), 3.1 (human operator auth methods), 3.2.2
  (audit policy file content), 2.7 (etcd CA uniqueness), and section 4 (worker nodes/kubelet — the
  kubelet process itself isn't exposed as a Pod) still need SSH/file access to node filesystems and
  process arguments — outside what a kubectl plugin can see. Point at
  [kube-bench](https://github.com/aquasecurity/kube-bench) for those, which runs on the nodes
  themselves. Sections 1.2/1.3/1.4/2 are covered indirectly instead — see above.
- **FSTEC** certifies the containerization *tool* as a software product (Docker/containerd/a K8s
  distro) — password-based authentication with specific length/alphabet requirements, a fixed
  3-role user model, certified vulnerability-database integration cadence, GOST-formatted event
  logs. Kubernetes doesn't even have a built-in password store (auth is cert/token/OIDC-based), so
  a large fraction of this framework is structurally inapplicable to auditing a cluster, not a gap
  in this tool's coverage.
- **NSA/CISA** covers node hardening, control-plane configuration, SIEM/service-mesh/IDS tooling
  choices, and etcd/Secrets encryption at rest — all outside API-object visibility, plus a few
  recommendations (LimitRange/ResourceQuota coverage, PodDisruptionBudget coverage, cluster
  version currency) that are API-observable in principle but not implemented yet (`NOT_IMPLEMENTED`,
  not `NOT_APPLICABLE`).

## Statuses

| Status | Meaning |
|---|---|
| `PASS` | The control's mapped checks ran and found no matching findings. |
| `FAIL` | At least one finding matches one of the control's mapped policy/native-check IDs. |
| `NOT_APPLICABLE` | Outside what this tool can observe via the Kubernetes API (`naReason` explains why). |
| `NOT_IMPLEMENTED` | Observable in principle, but no check exists for it yet (`note` explains what's missing). |

## Cross-framework references

Where a control in FSTEC or NSA has a genuine corresponding CIS control, it's linked via
`crossRefs.cis` in the mapping YAML — rendered as the **Related controls** column in `report.md`
and `control.crossRefs` in `findings.json`. This is informational only (it doesn't affect
PASS/FAIL); it's there so a FSTEC/NSA `FAIL` row tells you which CIS control covers the same
ground, and vice versa.

## Consolidated summary

When more than one framework is active, the report includes a **Consolidated Compliance Summary**
table — one row per framework with pass/fail/N-A/not-implemented counts — so you can compare
coverage across frameworks at a glance instead of reading three separate scorecards top to bottom.

## Finding a `FAIL` control's exact resources

Every `FAIL` control links back to the specific resources that caused it, in both outputs:

- **`report.md`**: each framework's table **Findings** column shows the count, and a
  **"Failing controls — affected resources"** section immediately below each table lists, per
  control, every resource with its severity, policy/check ID, and message — no need to
  cross-reference by hand.
- **`findings.json`**: `compliance[].results[].resources` gives `{apiVersion, kind, namespace,
  name}` for every affected resource, and `results[].findingIds` gives the exact finding IDs to
  look up in the top-level `findings` array for full detail (message, remediation, source).

## Pod Security Standards (Baseline/Restricted) — outside any framework mapping

Separately from the framework scorecards above, every scan also evaluates each workload against
the official Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
Baseline and Restricted profiles, using `k8s.io/pod-security-admission/policy` directly — the same
check implementations the in-cluster Pod Security Admission controller runs, not a hand-rolled
reimplementation of the rules. Findings show up as `pss-analyzer.baseline`/`pss-analyzer.restricted`
in `report.md`/`findings.json` with the exact forbidden-reason text the upstream library produces.

This is intentionally not tied to a specific CIS control number (CIS's own controls decompose
Restricted into ~10 separate numbered checks already covered individually above) — it's a single
aggregate "does this pass the standard Kubernetes-defined bar" verdict, useful independently of
whether the target cluster enforces PSA at all (e.g. as a pre-deploy check on static manifests). If
you want it wired into a specific control number, reference `pss-analyzer.baseline`/
`pss-analyzer.restricted` as `nativeCheckIds` in your own [custom framework]({{ '/custom-checks/' | relative_url }}).

## Control-to-check mapping

Each control lists the `policyIds` (VAP policies) and/or `nativeCheckIds` (RBAC/NetworkPolicy
analyzer check IDs — see [RBAC Analysis]({{ '/rbac/' | relative_url }}) and
[NetworkPolicy Coverage]({{ '/network-policy/' | relative_url }})) that feed into it. A control
`FAIL`s if *any* finding references one of those IDs. The mapping YAML files themselves are the
source of truth for the current, full control list — not this page.

## Adding a new framework

To contribute a bundled framework: add a new `compliance-mappings/<id>.yaml` with `id`, `title`,
`version`, and a `controls` list (see the existing files for the shape) and rebuild — the mapping
directory is embedded into the binary at compile time (`go:embed`), so no Go code changes are
needed, but a new file does require a `make build`/`make install` before `--frameworks <id>` picks
it up.

For an org-specific/private framework you don't want in this repo at all (internal requirement
registries, conventions with no public-standard backing), no rebuild is needed: pass a file path
instead of an ID, e.g. `--frameworks cis,/path/to/your/internal.yaml` — see
[Custom Checks & Private Frameworks]({{ '/custom-checks/' | relative_url }}).

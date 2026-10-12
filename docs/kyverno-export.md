---
layout: default
title: "Kyverno Export"
permalink: /kyverno-export/
---

# Exporting policies to Kyverno

`kubectl audit policy export` writes the policy set a `scan` would load (bundled defaults + any
`--policy-dir`) back out as YAML — `--format` picks the output family:

- `--format vap` (the default) — plain `ValidatingAdmissionPolicy` YAML, nothing converted, plus a
  generated `ValidatingAdmissionPolicyBinding` (`--validation-action`, default `Audit`): a bare
  `ValidatingAdmissionPolicy` enforces nothing at all once applied without one (`validationActions`
  lives on the Binding, not the Policy, in the native K8s API), so both are written to the same
  file as a `---`-separated multi-document YAML stream, applied together in one `kubectl apply -f`.
  Verified end-to-end against a real cluster (kind, Kubernetes 1.31): a compliant object is
  admitted, a violating one is denied with this check's own message, exactly as `kubectl-audit
  scan` would have flagged it.
- `--format kyverno` — converts into Kyverno policy YAML instead, for organizations already
  standardized on Kyverno for in-cluster enforcement. `--kind` then picks which Kyverno shape(s).
  Also verified end-to-end (same kind cluster, Kyverno's latest release): both shapes below
  correctly admit a compliant object and deny a violating one.

## The two Kyverno targets

Kyverno currently has two policy shapes, and `--kind` (only consulted with `--format kyverno`)
picks which one(s) get written:

- **`validatingpolicy`** (default) — Kyverno's `policies.kyverno.io/v1 ValidatingPolicy`.
  This reuses the exact same `matchConstraints` (resource-matching by apiGroup + resource plural,
  e.g. `"deployments"`) and `validations` (CEL `expression`/`message`) shapes a native VAP already
  has, so the conversion is a lossless structural copy — nothing is reinterpreted.
- **`clusterpolicy`** — the classic `kyverno.io/v1 ClusterPolicy`, with the same CEL expressions
  embedded in `validate.cel.expressions` (not translated to JMESPath/pattern syntax — a general
  CEL→JMESPath translator isn't reliably automatable). Kyverno itself now warns this kind is
  deprecated in favor of `validatingpolicy` (`kubectl apply` prints `Warning: kyverno.io/v1
  ClusterPolicy is deprecated...` as of Kyverno's current release) — prefer `--kind
  validatingpolicy` unless you specifically need classic `ClusterPolicy` for an older Kyverno
  install or an existing pipeline built around it. Its match blocks need real Kind names
  (e.g. `"Deployment"`), which a VAP never carries — only the GVR (e.g. `"deployments"`).
  Kubernetes itself only resolves GVR→Kind via a live RESTMapper backed by cluster discovery; a
  resource plural can't be reliably turned into its Kind by de-pluralizing and capitalizing alone
  (multi-word Kinds lose their word boundaries, e.g. `virtualmachineinstances` →
  `VirtualMachineInstance`). So Kind resolution is:
  1. A built-in table covering exactly the resources the *bundled* policies use (core/v1, apps/v1,
     batch/v1, `rbac.authorization.k8s.io/v1`, `networking.k8s.io/v1`,
     `admissionregistration.k8s.io/v1`) — works offline, no cluster needed.
  2. Live discovery via `--context`/`--kubeconfig`, for anything the table doesn't cover (custom
     policies, thirdparty CRDs).

  A policy whose resources can't be resolved either way is **skipped for `clusterpolicy` output**,
  with a warning on stderr naming the policy and the unresolved resource(s) — never a guess.
  `validatingpolicy` output for that same policy is unaffected, since it never needed Kind at all.

- **`both`** writes both, as `<id>.validatingpolicy.yaml` and `<id>.clusterpolicy.yaml`.

## Old Kyverno installs (CEL support is Kyverno-version-gated, not Kubernetes-version-gated)

Kyverno implements CEL itself (its own webhook, its own embedded CEL evaluation) — it doesn't
depend on the cluster's own `ValidatingAdmissionPolicy` support at all, so an old Kubernetes
version alone doesn't rule this out: `ClusterPolicy`'s `validate.cel.expressions` shipped in
**Kyverno 1.11**, and its officially-supported Kubernetes range already includes 1.26. The
`ValidatingPolicy` CRD is newer still (**Kyverno 1.13+**). What actually matters is which Kyverno
*version* is installed, independent of the cluster's Kubernetes version.

Both CRDs existing at all doesn't prove CEL support, though — `ClusterPolicy` has existed since
Kyverno's first release, long before CEL. Applying `validate.cel.expressions` against an older
CRD schema doesn't error; the apiserver's structural-schema pruning just silently drops the field
it doesn't recognize, leaving a `ClusterPolicy` that applies cleanly and enforces *nothing at all*
— the same "looks protected, isn't" failure this tool exists to catch elsewhere. So with
`--context`/`--kubeconfig` given, `export` checks the real, live cluster before writing anything:

- `validatingpolicy`: resolves the `ValidatingPolicy` Kind via the RESTMapper — if the CRD isn't
  registered at all (Kyverno < 1.13), that output is skipped entirely.
- `clusterpolicy`: fetches the live `clusterpolicies.kyverno.io` CRD and checks its schema for a
  CEL-capable `validate` block — if it's the pre-CEL shape (Kyverno < 1.11), that output is
  skipped entirely.

Either skip prints a clear warning naming what's missing and the minimum Kyverno version needed —
never a silent, unusable export. If *neither* target is supported on the live cluster, `export`
exits non-zero with "nothing to export" rather than writing empty output. Without
`--context`/`--kubeconfig` at all, neither check can run — `export` proceeds (as it always has)
but can't promise the result will actually enforce anything on a cluster it never looked at.

```sh
# Offline, bundled-policy-set only: every policy that targets only
# core/apps/batch/rbac/networking resources converts; thirdparty-CRD
# policies are skipped for clusterpolicy (still exported as validatingpolicy).
kubectl audit policy export --format kyverno --kind both --out ./kyverno-policies

# With a live cluster, custom/thirdparty policies resolve too:
kubectl audit policy export --format kyverno --kind clusterpolicy --context prod --out ./kyverno-policies
```

## Filtering by compliance framework

`--frameworks` (same values as `scan`'s own `--frameworks`: `cis`, `fstec`, `nsa`, `capsule`, or a
path to a custom mapping YAML) applies regardless of `--format` — it exports only the policies
mapped to at least one control in those framework(s), instead of the whole loaded set, e.g. "give
me just what CIS requires" rather than every bundled check. `--exclude-policy` (repeatable or
comma-separated policy IDs) drops specific policies regardless of framework.

When `--frameworks` is given, every exported policy also gets an
`audit.k8s-auditor.io/framework-controls` annotation citing exactly which control(s) justified
including it — the same `<Framework>: <ID> — <Title>` format reports and Jira tickets already cite
controls with:

```sh
kubectl audit policy export --format kyverno --frameworks cis --out ./cis-only
kubectl audit policy export --frameworks cis --exclude-policy rbac.no-anonymous-binding --out ./cis-vap
```

With no `--frameworks`, every loaded policy (minus `--exclude-policy`) is exported unchanged, with
no `framework-controls` annotation added.

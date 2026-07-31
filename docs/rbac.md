---
layout: default
title: "RBAC Analysis"
permalink: /rbac/
---

# RBAC least-privilege analysis

VAP CEL policies evaluate one object at a time, so a handful of RBAC checks — the ones that need
Role + Binding + Subject together, or aggregation across several bindings — live as a native Go
analyzer ([`internal/rbac`](https://github.com/{{ site.repository }}/tree/main/internal/rbac))
instead of a policy file. Single-object RBAC checks (wildcard rules, cluster-admin/anonymous
bindings) *are* bundled VAP policies — see
[`policies/rbac`](https://github.com/{{ site.repository }}/tree/main/policies/rbac) — so those can
also be enforced in-cluster with `kubectl apply -f`.

Run it standalone with `kubectl audit rbac analyze`, or as part of `kubectl audit scan`.

## What it builds

1. **Graph** — every Role, ClusterRole, RoleBinding, ClusterRoleBinding, and ServiceAccount in the
   scanned resource set.
2. **Effective permissions** — for every subject (User/Group/ServiceAccount), every rule granted
   to it through any binding, with the namespace it applies in (`""` = cluster-wide) and
   provenance (which binding + role granted it).
3. **Role model** — a condensed, deduplicated summary per subject, rendered in `report.md` and
   `findings.json`.

## Checks

| Check ID | Severity | What it flags |
|---|---|---|
| `rbac-analyzer.escalation-verb` | Critical | Subject can use `escalate`, `bind`, or `impersonate` — direct privilege-escalation primitives. |
| `rbac-analyzer.pod-exec-access` | High | Subject can `create`/`get` on `pods/exec`, `pods/attach`, or `pods/portforward` — equivalent to shell access on matching pods. |
| `rbac-analyzer.broad-secrets-access` | High/Medium | Subject can read Secrets cluster-wide (High) or across multiple namespaces (Medium). |
| `rbac-analyzer.rbac-self-modification` | High | Subject can create/update/patch/delete Roles, ClusterRoles, or \*Bindings — can grant itself more access. |
| `rbac-analyzer.default-serviceaccount-bound` | Medium | The `default` ServiceAccount in a namespace has roles bound to it; every pod without an explicit `serviceAccountName` inherits that access. |
| `rbac-analyzer.automount-with-sensitive-access` | Medium | A ServiceAccount with sensitive permissions (Secrets, write access, or RBAC objects) doesn't set `automountServiceAccountToken: false`. |

## Handling real-world RBAC quirks

- **Aggregated ClusterRoles.** Roles like the built-in `admin`/`edit`/`view`, or any custom role
  using `aggregationRule`, get their `.rules` computed by a controller at runtime — a live cluster
  always returns them already materialized, but a *static manifest* is the raw source YAML, where
  `.rules` is empty. The analyzer resolves `aggregationRule.clusterRoleSelectors` against the other
  ClusterRoles loaded in the same scan (iterating to a fixed point, since aggregation can chain),
  but only when `.rules` is empty — a live cluster's already-correct data is never overwritten.
- **`cluster-admin` isn't user-defined.** It's a built-in ClusterRole every real cluster creates
  automatically, so it's never present in a static manifest repo. If it's missing from the loaded
  resource set, the analyzer injects the well-known definition
  (`apiGroups: ["*"], resources: ["*"], verbs: ["*"]`) so a binding to `cluster-admin` in static
  mode still resolves to its real (maximal) permissions instead of silently looking empty.

## What's intentionally out of scope

Full authorization simulation (`SubjectAccessReview`-equivalent, e.g. "can user X actually GET
pod Y") is not implemented — the analyzer works in terms of granted rules and coarse-grained
risk patterns, not a full policy-decision engine. CEL policies can't do this either: the
`authorizer` CEL variable used by real admission-time VAP policies is intentionally not declared
in this engine's CEL environment, since there's no live request to back it with (see
[Writing Policies]({{ '/writing-policies/' | relative_url }}#engine-limitations-to-be-aware-of)).

---
layout: default
title: "Writing Policies"
permalink: /writing-policies/
---

# Writing custom policies

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

Recognized annotations:

| Annotation | Purpose |
|---|---|
| `audit.k8s-auditor.io/title` | Human-readable finding title (defaults to `metadata.name`). |
| `audit.k8s-auditor.io/severity` | `critical\|high\|medium\|low\|info` (defaults to `medium`). |
| `audit.k8s-auditor.io/category` | Free-form grouping label (defaults to `general`). |
| `audit.k8s-auditor.io/remediation` | Shown in the finding and the report. How to fix a confirmed issue. |
| `audit.k8s-auditor.io/verification-steps` | Shown in the finding, the report, and read by `kubectl audit triage`. Concrete, numbered steps for a human to confirm this finding is a true positive in their specific environment before acting on it (e.g. "check whether this Service is actually internet-reachable") — distinct from `remediation`, which assumes the finding is already confirmed. Every bundled policy sets this; see [Triage](./triage/) for the full rationale and how it's used. |
| `audit.k8s-auditor.io/cis` | Comma-separated CIS control IDs this policy maps to. |

Load it with `kubectl audit scan --policy-dir ./my-policies`, or add the directory under
`policies.dirs` in `audit.yaml`. See
[`examples/custom-policy-example.yaml`](https://github.com/{{ site.repository }}/blob/main/examples/custom-policy-example.yaml).

## Validate before you rely on it

```sh
kubectl audit policy validate ./my-policies
kubectl audit policy list
```

`policy validate` CEL-compiles every policy in the given directories and reports every error
found (not just the first one), with the offending file/policy name.

## Handling different workload shapes

Container specs live at different paths depending on the object: `spec.containers` for a bare
`Pod`, `spec.template.spec.containers` for a Deployment/StatefulSet/DaemonSet/ReplicaSet, and
`spec.jobTemplate.spec.template.spec.containers` for a CronJob. A policy that should apply to all
of them needs to branch on shape, since CEL's `has()` macro only tests the presence of the *last*
selector in a chain — every intermediate level needs its own `has()` guard, or the expression
errors instead of just returning false:

```
(has(object.spec.containers) ? object.spec.containers
  : (has(object.spec.template) && has(object.spec.template.spec) && has(object.spec.template.spec.containers)) ? object.spec.template.spec.containers
  : (has(object.spec.jobTemplate) && has(object.spec.jobTemplate.spec) && has(object.spec.jobTemplate.spec.template) && has(object.spec.jobTemplate.spec.template.spec) && has(object.spec.jobTemplate.spec.template.spec.containers)) ? object.spec.jobTemplate.spec.template.spec.containers
  : []).all(c, /* your condition on c */)
```

The bundled policies in
[`policies/workload`](https://github.com/{{ site.repository }}/tree/main/policies/workload) and
[`policies/network`](https://github.com/{{ site.repository }}/tree/main/policies/network) all use
this pattern — copy from whichever is closest to what you need.

## Engine limitations to be aware of

- **`spec.variables` is not supported.** Policies that declare it fail to compile with a clear
  message; inline the expression instead of factoring it into a named variable.
- **The `authorizer` CEL variable is not declared.** This engine audits standing cluster/manifest
  state, not live admission requests, so there's no SubjectAccessReview to back it. Policies using
  `authorizer.*` fail to compile — use the [RBAC analyzer]({{ '/rbac/' | relative_url }}) instead
  for RBAC-aware checks.
- **`operations` in `matchConstraints.resourceRules` isn't filtered on.** Every loaded resource is
  evaluated regardless of the rule's declared operations (CREATE/UPDATE/DELETE), since the tool
  audits existing objects rather than simulating one specific admission request.
- **`ValidatingAdmissionPolicyBinding` objects aren't consumed.** Every loaded policy's
  `matchConstraints` is applied directly to every resource — there's no cluster-wiring
  indirection to model.

## RBAC and NetworkPolicy checks aren't VAP policies

Some checks genuinely can't be expressed as a single-object CEL policy — answering "does this
subject have overly broad effective permissions" or "does this workload have any applicable
NetworkPolicy" requires correlating multiple objects (Role + Binding + Subject, or Workload +
every NetworkPolicy in its namespace). Those live as native Go analyzers instead: see
[RBAC Analysis]({{ '/rbac/' | relative_url }}) and
[NetworkPolicy Coverage]({{ '/network-policy/' | relative_url }}).

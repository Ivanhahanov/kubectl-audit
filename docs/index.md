---
layout: default
title: "Overview"
permalink: /
---

# kubectl-audit

A `kubectl` plugin (`kubectl audit ...`) for auditing Kubernetes security posture — against a
live cluster, static manifest files, or both at once.

<p>
<a href="https://github.com/{{ site.repository }}">Source on GitHub</a> ·
<a href="{{ '/getting-started/' | relative_url }}">Getting Started</a>
</p>

## What it checks

- **Policy checks** — written as real `admissionregistration.k8s.io/v1 ValidatingAdmissionPolicy`
  (VAP) objects with CEL expressions. The exact same YAML you scan with can be `kubectl apply -f`'d
  to enforce the rule in-cluster at admission time. Drop a new file into a policy directory to add
  a check — no code changes. See [Writing Policies]({{ '/writing-policies/' | relative_url }}).
- **RBAC least-privilege analysis** — builds the effective permission model per subject
  (User/Group/ServiceAccount) across Roles, ClusterRoles and their bindings (including resolving
  `aggregationRule`-based ClusterRoles even from raw static manifests), and flags
  privilege-escalation verbs, exec/attach access, broad Secrets access, RBAC self-modification, and
  risky ServiceAccount token automount. See [RBAC Analysis]({{ '/rbac/' | relative_url }}).
- **NetworkPolicy coverage** — flags workloads with no applicable NetworkPolicy. Native Kubernetes
  NetworkPolicy is matched precisely against each workload's pod-template labels; Cilium and Calico
  policies are detected and used as a coverage signal. See
  [NetworkPolicy Coverage]({{ '/network-policy/' | relative_url }}).
- **CIS Kubernetes Benchmark** — a compliance scorecard for every control observable through the
  API. Node/control-plane-only sections are explicitly marked "Not Applicable" instead of silently
  skipped. See [CIS Benchmark]({{ '/cis-benchmark/' | relative_url }}).

## Output

- `findings.json` — machine-readable findings, RBAC role model, and CIS scorecard.
- `report.md` — a human-readable report, including which exact resources caused each CIS control
  to fail.
- `--fail-on <severity>` — a CI gate that exits non-zero when findings at or above a severity
  threshold are present.

## Quick start

```sh
go install github.com/{{ site.repository }}/cmd/kubectl-audit@latest

# Audit the current cluster
kubectl audit scan

# Audit static manifests only, gated for CI
kubectl audit scan -f ./manifests --mode static --fail-on high
```

See [Getting Started]({{ '/getting-started/' | relative_url }}) for installation, the full
command reference, and [Configuration]({{ '/configuration/' | relative_url }}) for `audit.yaml`.

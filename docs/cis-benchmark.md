---
layout: default
title: "CIS Benchmark"
permalink: /cis-benchmark/
---

# CIS Kubernetes Benchmark compliance

`kubectl audit scan --cis` (or `kubectl audit cis report`) builds a scorecard against the public
CIS Kubernetes Benchmark control structure, from
[`cis-mappings/mapping.yaml`](https://github.com/{{ site.repository }}/blob/main/cis-mappings/mapping.yaml).
Treat it as a practical cross-reference, not a substitute for the official CIS PDF when
compliance-grade attestation is required — section numbering/wording can vary slightly between
benchmark revisions.

## Scope

Sections 1-4 (control plane components, etcd, control-plane configuration files, worker
node/kubelet configuration) require SSH/file access to node filesystems and process arguments
that a kubectl plugin fundamentally cannot see through the Kubernetes API. They're reported as
`NOT_APPLICABLE`, each with a `naReason` pointing at
[kube-bench](https://github.com/aquasecurity/kube-bench), which runs on the nodes themselves.

Section 5 (Policies: RBAC and Service Accounts, Pod Security Standards, Network Policies and CNI,
General Policies) is API-observable and is what this tool implements.

## Statuses

| Status | Meaning |
|---|---|
| `PASS` | The control's mapped checks ran and found no matching findings. |
| `FAIL` | At least one finding matches one of the control's mapped policy/native-check IDs. |
| `NOT_APPLICABLE` | Requires node/file access this tool can't reach (`naReason` explains why). |
| `NOT_IMPLEMENTED` | Applicable via the API but no check exists for it yet in this tool (`note` explains what's missing). |

## Finding a `FAIL` control's exact resources

Every `FAIL` control links back to the specific resources that caused it, in both outputs:

- **`report.md`**: the CIS table's **Findings** column shows the count, and a
  **"Failing controls — affected resources"** section immediately below the table lists, per
  control, every resource with its severity, policy/check ID, and message — no need to
  cross-reference by hand.
- **`findings.json`**: `cis.results[].resources` gives `{apiVersion, kind, namespace, name}` for
  every affected resource, and `cis.results[].findingIds` gives the exact finding IDs to look up
  in the top-level `findings` array for full detail (message, remediation, source).

## Control-to-check mapping

Each control in `cis-mappings/mapping.yaml` lists the `policyIds` (VAP policies) and/or
`nativeCheckIds` (RBAC/NetworkPolicy analyzer check IDs — see
[RBAC Analysis]({{ '/rbac/' | relative_url }}) and
[NetworkPolicy Coverage]({{ '/network-policy/' | relative_url }})) that feed into it. A control
`FAIL`s if *any* finding references one of those IDs. See the mapping file itself for the full,
current control list — it's the source of truth, not this page.

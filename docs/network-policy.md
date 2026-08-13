---
layout: default
title: "NetworkPolicy Coverage"
permalink: /network-policy/
---

# NetworkPolicy coverage

Answering "does this workload have any traffic restrictions at all" requires matching its labels
against every NetworkPolicy in its namespace — cross-object reasoning a single-object VAP CEL
policy can't do, so this is a native analyzer
([`internal/netpol`](https://github.com/{{ site.repository }}/tree/main/internal/netpol)), same
rationale as [RBAC Analysis]({{ '/rbac/' | relative_url }}). It maps to CIS control `5.3.2` and
runs as part of `kubectl audit scan`.

## Native Kubernetes NetworkPolicy — checked precisely

For every workload (`Pod`, or a controller with a pod template: `Deployment`, `StatefulSet`,
`DaemonSet`, `ReplicaSet`, `Job`, `CronJob`), the analyzer extracts its pod-template labels and
checks whether any `NetworkPolicy` in the same namespace:

1. has a `podSelector` matching those labels (an empty `podSelector: {}` matches every pod in the
   namespace), **and**
2. actually restricts `Ingress` — a `policyTypes: ["Egress"]`-only policy doesn't count, since it
   leaves ingress traffic completely open despite technically "selecting" the pod. An omitted
   `policyTypes` defaults to at least `Ingress`, per the NetworkPolicy API's own defaulting rules.

If neither holds, the workload gets a `netpol-analyzer.no-network-policy-coverage` finding
(severity High).

## Reachability: two checks beyond presence

Coverage answers "does *some* NetworkPolicy select this workload" — it doesn't say the policy is
actually tight, or that egress is restricted at all. Two further, native-NetworkPolicy-only checks
answer the concrete "where can this actually go" questions that are easiest to miss reading YAML by
eye. Both are deliberately narrow, unambiguous structural checks, not a full connectivity-graph
simulation (see [np-guard/netpol-analyzer](https://github.com/np-guard/netpol-analyzer) if you want
that level of detail as a separate tool) — same Cilium/Calico presence-based skip as coverage above,
so neither produces a false positive on a cluster that relies on them instead of native
NetworkPolicy.

- **`netpol-analyzer.broad-namespace-selector-rule`** (Medium): a rule's `from`/`to` entry sets
  `namespaceSelector` without a `podSelector`. Per the NetworkPolicy API, that matches **every pod**
  in the matched namespace(s), not specific ones — a well-known, easy-to-miss surprise when
  reviewing a policy. An additionally-empty `namespaceSelector: {}` (matches all namespaces) is
  called out explicitly in the message as the maximally broad case.
- **`netpol-analyzer.no-egress-restriction`** (Medium): the egress mirror of the coverage check —
  no NetworkPolicy actually restricts this workload's egress, so it can reach any destination
  outbound, including the Kubernetes API server itself, every other namespace, and (network layer
  permitting) the internet. Correctly follows the NetworkPolicy API's own `policyTypes` defaulting:
  an explicit `policyTypes: ["Egress"]` counts even with zero `egress` rules (that's a strict
  deny-all, still "restricted"); an *omitted* `policyTypes` only implies Egress coverage if the
  policy actually has non-empty `egress` rules, mirroring how Kubernetes itself interprets it.

Neither is currently mapped to a CIS/FSTEC/NSA control — they're a precision signal on top of
`5.3.2`'s presence check, not a distinct external requirement.

## Cilium and Calico — presence, not simulation

Both are detected automatically:

- **Cilium**: `CiliumNetworkPolicy` (namespaced) and `CiliumClusterwideNetworkPolicy`
  (cluster-scoped), group `cilium.io/v2`.
- **Calico**: `NetworkPolicy` and `GlobalNetworkPolicy`, group `crd.projectcalico.org/v1` — the
  CRD-mode storage the large majority of self-managed Calico installs use. The alternative
  aggregated-API-server mode (`projectcalico.org/v3`, `calico-apiserver`) isn't covered.

In cluster mode, these are only fetched if the corresponding CRD is actually registered
(checked via discovery) — most clusters run neither, and that's the common, silent case, not a
warning.

Their selector languages (`endpointSelector`, entities, services, `ipBlock`s for Cilium;
similarly rich selectors for Calico) are materially different from a plain Kubernetes label
selector, and reimplementing either policy engine is out of scope for this tool. Instead:

- Any namespaced Cilium/Calico policy object in a namespace is treated as "this namespace has
  some coverage" — every workload in it is skipped.
- Any **cluster-scoped** Cilium/Calico policy anywhere in the cluster is treated as "potentially
  covers everything" — every workload in every namespace is skipped.

This is a deliberately conservative, presence-based signal to avoid false positives on clusters
that rely on Cilium/Calico instead of native NetworkPolicy. It means a cluster running Cilium with
genuinely incomplete policy coverage won't be flagged as precisely as one running native
NetworkPolicy — if that matters for your environment, treat a `PASS` here from Cilium/Calico
presence alone as "verify manually," not as a hard guarantee.

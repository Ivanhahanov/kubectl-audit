---
layout: default
title: "Required Permissions"
permalink: /permissions/
---

# Required permissions

kubectl-audit is read-only against the cluster it scans: it never creates, updates, patches, or
deletes anything. In cluster mode it needs `get`/`list`/`watch` on the resource kinds it fetches —
nothing more.

## Two tiers

- **`examples/rbac/clusterrole-readonly.yaml`** — the default. Everything a normal `kubectl audit
  scan`/`kubectl audit rbac analyze` needs: the built-in kinds
  ([`internal/loader/cluster.go`](https://github.com/{{ site.repository }}/blob/main/internal/loader/cluster.go)'s
  `defaultResources` — Pods, Services, Namespaces, ServiceAccounts, ConfigMaps, Deployments,
  StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs, Roles/ClusterRoles/\*Bindings,
  NetworkPolicies, Ingresses) plus every third-party operator CRD this tool has checks for
  (`optionalResources` — Cilium, Calico, Istio, ArgoCD, Vault Secrets Operator, Fluent Operator,
  VictoriaMetrics Operator, CloudNativePG, Kyverno, APISIX, Capsule, KubeVirt). Granting a rule for
  a CRD group that isn't installed on a given cluster is harmless — it's simply inert, and this tool
  resolves each group's installed status via API discovery before ever listing it, rather than
  erroring on a missing one. **Deliberately excludes Secrets.**
- **`examples/rbac/clusterrole-with-secrets.yaml`** — everything above, plus `get`/`list`/`watch` on
  `secrets`. Needed only when running with `--read-secret-values` — see [Secrets
  Mode]({{ '/secrets-mode/' | relative_url }}). Apply this *instead of* the readonly one, not
  alongside it.

Both are plain `ClusterRole` manifests — `kubectl apply -f examples/rbac/clusterrole-readonly.yaml`.
`examples/rbac/serviceaccount-and-binding.yaml` shows the `ServiceAccount` + `ClusterRoleBinding`
wiring for running this as an in-cluster Job/CronJob; a human running it locally via their own
kubeconfig just needs the same verbs on their own user/group instead (or whatever your org already
uses for read access, e.g. the built-in `view` ClusterRole plus the third-party CRD groups above,
which `view` doesn't cover).

## Why grant CRD access for operators that might not even be installed

`kubectl-audit`'s own component-detection logic (see [Third-Party
Operators]({{ '/third-party-operators/' | relative_url }})) already treats "CRD group not
registered" as the ordinary, expected case for most clusters — it's a `debug`-level log line, not a
warning, and doesn't affect the scan otherwise. Splitting the readonly ClusterRole per-vendor (so you
only grant what's actually installed) would need to be hand-maintained per cluster and would silently
go stale the moment this tool adds a new supported operator. The single bundled manifest is simpler
to keep correct and has no meaningful downside: an RBAC rule referencing a resource that doesn't
exist grants nothing.

## Keeping this in sync

Both manifests are maintained by hand, not generated. If you're extending this tool with a new
third-party component (see [Writing Policies]({{ '/writing-policies/' | relative_url }})) and it
needs a new CRD fetched from live clusters, add the resource to `internal/loader/cluster.go`'s
`optionalResources` **and** to both `examples/rbac/clusterrole-*.yaml` files —
`internal/loader/clusterrole_test.go`'s `TestClusterRoleManifestsCoverKnownResources` fails the build
if either manifest drifts from what the loader actually knows how to fetch, so this can't go stale
silently.

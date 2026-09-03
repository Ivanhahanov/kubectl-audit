---
layout: default
title: "Third-Party Operators"
permalink: /third-party-operators/
---

# Third-party operator checks

Beyond [Capsule]({{ '/compliance/' | relative_url }}) and [Istio]({{ '/istio/' | relative_url }}),
this tool bundles a small number of checks for other common cluster add-ons — each one traced to a
specific, quoted line of that project's own official security guidance, verified field-by-field
against the real CRD source before being written as CEL, and covering only what's genuinely
checkable from a single CRD object. A short list rather than broad coverage is deliberate: these
projects don't get the "cover everything realistic" treatment CIS/NSA/Capsule get, since there's no
comparable end-to-end security benchmark for any of them to work from.

Every check here only produces findings if the corresponding CRD is actually present in the scan —
harmless (zero findings) on any cluster that doesn't run that add-on. In cluster mode, all of these
CRDs are fetched by resolving each group's actual served/preferred version via the cluster's own API
discovery (see `internal/loader/cluster.go`'s `resolvePreferredVersion`), not a version hardcoded
into this tool, for the same reasons documented in the Capsule/Istio sections.

## Component inventory (`internal/thirdparty`)

Every scan also cross-references the resources it loaded against a small built-in list of known
third-party components (`internal/thirdparty/components.yaml`), and — if any are found — prints a
**Detected Components** section near the top of `report.md`, before the findings themselves. This
is purely informational: it exists so a reader doesn't have to guess *why* a check did or didn't
fire, and to make the exceptions mechanism below auditable instead of implicit.

Each known component is data, not Go code — a YAML entry with:

- `name` — display name.
- `category` — `System` (needs host/OS-level access to do its job — see below) or `Application`
  (an ordinary CRD/operator with no host access, checked at full strength, no exceptions).
- `group` — the CRD API group that unambiguously proves the component is installed, if it ships
  one (e.g. `cilium.io`, `capsule.clastix.io`). This is the reliable signal: a CRD group either
  exists in the cluster or it doesn't, cluster-to-cluster, regardless of how anyone labeled their
  workloads.
- `labels` — a label selector matched only against Deployment/StatefulSet/DaemonSet objects (never
  a Namespace, ServiceAccount, or other object that can easily outlive the actual controller),
  identifying the real controller/operator/agent workload — e.g. `k8s-app: cilium`. Set on every
  component with a `group`, not just `System` ones: it's what lets a scan tell "this component is
  actually running" apart from "its CRDs are present," which matters for two different reasons —
  for `System` components it's *which object* a built-in exception (below) should apply to; for
  every component it catches the common case where a CRD outlives its controller (`helm uninstall`
  doesn't remove CRDs by default), which would otherwise silently misreport an uninstalled
  component as present.

Detection also checks `app.kubernetes.io/managed-by: Helm` on the matched objects, so the report
can say whether a component was Helm-installed — not whether whatever controller reconciles it was
also installed via Helm, which isn't a claim this signal can support.

To add a new component to the *bundled* inventory, edit `components.yaml` and rebuild — no Go
changes needed for either category. Adding a `System` entry also normally means adding a matching
rule to `builtin-exclusions.yaml` (next section); an `Application` entry needs nothing else.

**Extending it without rebuilding.** `components.yaml` (like `builtin-exclusions.yaml`) is
`go:embed`-compiled into the binary — there's no file on disk to edit, which matters if you
installed via krew: a rebuild isn't an option. For your own in-house operators/CNIs, add them
straight to `audit.yaml` instead — no separate file, no rebuild:

```yaml
components:
  extra:
    - name: InternalWidgetOperator
      category: Application       # System | Application (default: Application)
      group: internal.example.com
      labels:
        app.kubernetes.io/name: internal-widget-operator
```

Same schema, merged with the built-in list at scan time (`config.ComponentsConfig.Extra`). This
only adds the entry to the inventory/orphan-detection — it does **not** create a suppression
exception by itself; pair a `System`-category entry with your own `exclusions` rule (see
[Configuration]({{ '/configuration/' | relative_url }})) for that, same as any built-in `System`
component.

### Built-in exceptions for privileged system infrastructure

Some cluster infrastructure — a CNI's node agent, a metrics exporter — legitimately needs
`hostNetwork`, `hostPath` mounts, or elevated capabilities to do its actual job, and will always
fail the Kubernetes [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
Baseline/Restricted profiles as a result. Simply excluding a namespace (`kube-system`,
`cilium-system`, ...) would hide that — and *also* hide any genuinely broken workload someone else
happens to run in the same namespace. So this tool ships a small, precise, sourced set of built-in
exclusion rules instead (`internal/suppress/builtin-exclusions.yaml`), on by default, following two
rules strictly:

1. **Matched by label, never by namespace.** A rule only ever suppresses findings on the specific
   object(s) matching a label selector for that exact component (e.g. `k8s-app: cilium`) —
   wherever in the cluster it happens to run.
2. **Scoped to the exact, sourced set of `policyIds`** that component's own upstream documentation
   (verified against its real Helm chart source, not assumed) says it needs — never a blanket
   suppression. Every other check — RBAC, resource limits, image tag pinning, and any PSS/workload
   check *not* in that known set — still runs at full strength against the same object.

Currently covered:

| `id` | Component | Suppressed checks | Source |
|---|---|---|---|
| `cilium-agent` | Cilium agent (`k8s-app: cilium`) | `workload.no-privileged-containers`, `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline`, `pss-analyzer.restricted` | [cilium-agent daemonset.yaml / values.yaml](https://github.com/cilium/cilium/blob/main/install/kubernetes/cilium/templates/cilium-agent/daemonset.yaml) — hostNetwork, BPF/cgroup hostPath mounts, capabilities each justified inline (e.g. `NET_ADMIN` "used since cilium modifies routing tables"). cilium-operator is a separate, unprivileged component and is **not** covered. |
| `prometheus-node-exporter` | prometheus-node-exporter (`app.kubernetes.io/name: prometheus-node-exporter`) | `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `pss-analyzer.baseline`, `pss-analyzer.restricted` | [prometheus-node-exporter daemonset.yaml / values.yaml](https://github.com/prometheus-community/helm-charts/blob/main/charts/prometheus-node-exporter/templates/daemonset.yaml) — hostNetwork, hostPID, read-only `/proc`/`/sys`/`/` mounts. Not privileged, adds no capabilities, so `workload.no-privileged-containers`/`workload.drop-all-capabilities` are deliberately **not** suppressed for it — used identically under Prometheus, VictoriaMetrics, or Thanos. |
| `falco` | Falco agent (`app.kubernetes.io/name: falco`) | `workload.no-privileged-containers`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline` | [falco daemonset.yaml](https://github.com/falcosecurity/charts/blob/master/charts/falco/templates/daemonset.yaml) — privileged (to load its kernel driver/eBPF probe) plus an unusually large hostPath set (container runtime sockets, `/proc`, `/etc`, `/dev`, `/sys/module`, `/sys/kernel`, `/lib/modules`, `/boot`). Doesn't use hostNetwork/hostPID, doesn't set seccomp or run as non-root, so those checks are **not** suppressed for it. |
| `tetragon` | Tetragon agent (`app.kubernetes.io/name: tetragon`) | `workload.no-privileged-containers`, `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline` | [tetragon daemonset.yaml](https://github.com/cilium/tetragon/blob/main/install/kubernetes/tetragon/templates/daemonset.yaml) — hostNetwork, privileged, `/sys/fs/bpf` + `/proc` + Cilium runtime-state hostPath mounts. tetragon-operator is a separate, unprivileged, non-root component and is **not** covered. No seccomp profile is set, so `pss-analyzer.restricted` is **not** suppressed. |
| `kube-proxy` | kube-proxy (`k8s-app: kube-proxy`) — core Kubernetes, not third-party | `workload.no-privileged-containers`, `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `workload.drop-all-capabilities`, `pss-analyzer.baseline` | kubeadm's own standard, first-party rendered manifest — verified directly against a live kubeadm-bootstrapped cluster (hostNetwork, `privileged: true`, hostPath mounts of `/run/xtables.lock` and `/lib/modules`). Missing seccomp profile and running as root are unrelated to this requirement and stay flagged (`pss-analyzer.restricted`, `workload.run-as-non-root` are **not** suppressed). |
| `control-plane-static-pods` | Control-plane static pods — `kube-apiserver`/`kube-controller-manager`/`kube-scheduler`/`etcd` (`tier: control-plane`) — core Kubernetes, not third-party | `workload.no-host-namespaces`, `workload.no-hostpath-volumes`, `pss-analyzer.baseline` | kubeadm's static-pod model — verified directly against a live kubeadm-bootstrapped cluster (hostNetwork, host-mounted `/etc/kubernetes/pki` and component data dirs). Only relevant on a self-managed/kubeadm control plane — a managed control plane (EKS/GKE/AKS) never exposes these as Pods at all. Non-root/capability/seccomp/default-ServiceAccount hardening is unrelated to this requirement and stays flagged. |

The last two rows aren't third-party software, so they have no `internal/thirdparty/components.yaml`
entry and don't appear in the Detected Components table — they're plain exclusion rules, same
mechanism, just not "detected infrastructure" in the sense the rest of this page covers.

Suppressed findings are never hidden outright — they still appear in the report's **Suppressed
Findings** section with their reason (including the source link), exactly like a user-authored
`exclusions` rule, because that's what they are: a shipped, curated seed of the same mechanism (see
[Configuration: exclusions]({{ '/configuration/' | relative_url }})).

**Detected-via-CRD-only detection.** Because the label selector is the one part of this that can
legitimately vary by cluster — or simply stop matching anything once the component is uninstalled
(`helm uninstall` doesn't remove CRDs by default, so old CRDs/CRs commonly outlive the controller
that created them) — every scan cross-checks it against the CRD-group signal, for every component
in the inventory, not just the ones with a built-in exception. If a component's CRD group is
present but no Deployment/StatefulSet/DaemonSet matched its label selector, the report's **Scope**
section gets an explicit caveat naming the component, pointing at `components.yaml`, and stating
both plausible causes. If you see that caveat: either your install uses non-standard labels (add
your own `exclusions` rule matching them, only relevant if the flagged component is `System`), or
the component was removed and its CRDs/CRs were left behind (any findings against those stale
objects are then about configuration that no controller is actually enforcing anymore) — or it's
expected and safe to ignore.

Disable all built-in exceptions for a stricter scan that shows literally everything:
`--no-builtin-exceptions` / `disableBuiltinExceptions: true`. To turn off just one (e.g. see
everything Cilium-related but keep kube-proxy's exception), disable it by the `id` in the table
above: `--disable-builtin-exception-id cilium-agent` / `disableBuiltinExceptionIds: [cilium-agent]`
in `audit.yaml` — no separate file to edit, works the same whether you built from source or
installed via krew.

## ArgoCD (`argoproj.io/v1alpha1` — no version history, never promoted)

Three checks on `AppProject`, ArgoCD's own tenancy/RBAC boundary
([user-guide/projects docs](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/)). Note:
ArgoCD's own built-in `default` AppProject ships with exactly these wildcards — a finding here often
means "still using the default project," not an exotic misconfiguration.

- `argocd.appproject-wildcard-source-repos` (Medium) — `spec.sourceRepos` includes `"*"`.
- `argocd.appproject-wildcard-destinations` (High) — a `spec.destinations` entry has both
  `namespace: "*"` and `server`/`name: "*"`.
- `argocd.appproject-wildcard-cluster-resources` (High) — `spec.clusterResourceWhitelist` includes
  `{group: "*", kind: "*"}`.
- `argocd.application-uses-default-project` (Medium) — `Application.spec.project` is unset or
  `"default"`. ArgoCD's own [projects docs](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/):
  "The `default` project can be modified, but not deleted. ... it is recommended to create dedicated
  projects with explicit source, destination, and resource permissions." Stacks with the three
  wildcard checks above: an Application here inherits whatever the default AppProject currently
  allows.
- `argocd.rbac-cm-default-admin-policy` (High) — the `argocd-rbac-cm` ConfigMap's
  `data['policy.default']` is `"role:admin"`. ArgoCD's own
  [RBAC docs](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/): "When a user is
  authenticated in Argo CD, it will be granted the role specified in `policy.default`. ... All
  authenticated users get *at least* the permissions granted by the default policies. This access
  cannot be blocked by a `deny` rule. ... It is recommended to create a new `role:authenticated`
  with the minimum set of permissions possible." No CRD — matched by the ConfigMap's own
  well-known, name-stable identity (`argocd-rbac-cm`), the same pattern as the Airflow/APISIX
  checks below.
- `argocd.cmd-params-cm-server-insecure` (Medium) — the `argocd-cmd-params-cm` ConfigMap's
  `data['server.insecure']` is `"true"`. ArgoCD's own
  [runtime params reference](https://argo-cd.readthedocs.io/en/stable/operator-manual/argocd-cmd-params-cm-yaml/):
  `server.insecure` — "Run server without TLS". This is ArgoCD's own documented, supported pattern
  specifically when an external proxy/ingress terminates TLS (the docs recommend it for Ambassador,
  Contour, NGINX, GKE, ...) — but the docs don't independently warn against setting it without one.
  Same ConfigMap-content pattern as `argocd.rbac-cm-default-admin-policy`, checking the component's
  own runtime config object rather than a CRD.
- `argocd.cmd-params-cm-disable-auth` (Critical) — `argocd-cmd-params-cm`'s `server.disable.auth` is
  `"true"`. Verified directly against the official reference
  ([argocd-cmd-params-cm.yaml](https://github.com/argoproj/argo-cd/blob/master/docs/operator-manual/argocd-cmd-params-cm.yaml)):
  `` # Disable client authentication / server.disable.auth: "false" ``. Disables ArgoCD's own
  authentication entirely — the ArgoCD analog of KubeVirt's `Root` feature gate.
- `argocd.cmd-params-cm-repo-server-oob-symlinks-allowed` (High) — `reposerver.allow.oob.symlinks` is
  `"true"`. Same reference, quoted in full: "Allow repositories to contain symlinks that leave the
  boundaries of the repository. Changing this to \"true\" will not allow *all* out-of-bounds symlinks.
  Those will still be blocked for things like values files in Helm charts. But symlinks which are not
  explicitly blocked by other checks will be allowed." Defaults `"false"`.
- `argocd.cmd-params-cm-internal-tls-disabled` (Medium) — any of `reposerver.disable.tls`,
  `dexserver.disable.tls`, `controller.repo.server.plaintext`, `server.repo.server.plaintext`,
  `server.dex.server.plaintext`, `notificationscontroller.repo.server.plaintext` is `"true"`. Same
  reference; each defaults `"false"` and disables TLS between two ArgoCD components communicating
  in-cluster. `*.strict.tls` keys are deliberately **not** covered — they default to `"false"`
  (non-strict) out of the box, so flagging them would fire on every unmodified install; not an
  operator-triggered downgrade.
- `argocd.application-sync-validate-disabled` (Medium) — `Application.spec.syncPolicy.syncOptions`
  includes `"Validate=false"`. ArgoCD's own sync-options docs describe this as skipping kubectl's
  resource-schema validation during sync (the moral equivalent of `kubectl apply --validate=false`).
  Weaker-sourced than most checks here (a documented safety-mechanism disable, not an explicit
  "insecure" warning) — same tier as `istio.gateway-weak-tls-version`.
- `argocd.redis-requirepass-missing` (Critical) — the `argocd-redis` Deployment's `redis` container
  has no `--requirepass` flag. This is [CVE-2024-31989 / GHSA-9766-5277-j5hr](https://github.com/argoproj/argo-cd/security/advisories/GHSA-9766-5277-j5hr):
  "By default, the Redis database server is not password-protected, allowing an attacker with access
  to the Redis server to gain read/write access to the data in Redis" — enough to make ArgoCD apply
  arbitrary resources by modifying the cached manifest key, or leak resources via the cached
  resources-tree key. Fixed in ArgoCD 2.11.1/2.10.10/2.9.15/2.8.19+, which ship a generated password
  by default (verified against the official manifest: the redis container's args now always include
  `--requirepass $(REDIS_PASSWORD)`). Flags an unpatched version or a custom manifest that stripped
  the flag back out. Scoped to the well-known non-HA `argocd-redis` Deployment name; ArgoCD's separate
  HA topology (`argocd-redis-ha`, Sentinel behind HAProxy) uses a different manifest shape entirely
  and is **not** covered — known gap.

Not checked: `Application.spec.syncPolicy.automated.prune`/`selfHeal` — whether auto-sync-with-prune
is actually dangerous depends on the owning AppProject's scope (the checks above), which is
cross-object reasoning outside what a single-object VAP check can honestly claim. Also not checked:
`Prune=false`/`Replace=true`/`Force=true`/`SkipDryRunOnMissingResource=true` sync options — real and
documented by ArgoCD as risky ("destructive," "could cause an outage"), but that's an
availability/operational-safety concern, not confidentiality/integrity — out of this tool's security
scope, not asserted to be safe.

## HashiCorp Vault Secrets Operator (`secrets.hashicorp.com/v1beta1`)

- `vault.connection-skip-tls-verify` (High) — `VaultConnection.spec.skipTLSVerify: true`. VSO's own
  [threat model](https://github.com/hashicorp/vault-secrets-operator/blob/main/docs/threat-model/README.md)
  states plainly: "Use TLS negotiated by a well-secured certificate authority for all networked
  communication, especially for Vault and the Kubernetes API."
- `vault.auth-allowed-namespaces-wildcard` (High) — `VaultAuth.spec.allowedNamespaces` includes
  `"*"`. VSO's own `VaultAuth` CRD reference: "AllowedNamespaces Kubernetes Namespaces which are
  allow-listed for use with this AuthMethod. ... `[]{"*"}` - wildcard, all namespaces. ... unset -
  disallow all namespaces except ... the VaultAuthMethod's namespace, this is the default
  behavior." A wildcard lets any tenant namespace authenticate via this method's Vault role/policy
  — the same cross-tenant-boundary concern as the ArgoCD AppProject wildcard checks above.

## Capsule (`capsule.clastix.io` — multitenancy)

Checks live under the `multitenancy.*` policy-ID prefix rather than `capsule.*` (this repo's
convention: the category describes the concern, not just the vendor). Eight pre-existing checks
(`multitenancy.capsule-tenant-cluster-admin-binding`, `-no-limit-range`,
`-no-image-pull-policy-restriction`, `-no-network-policies`, `-no-node-isolation`,
`-no-registry-allowlist`, `-no-psa-enforcement`, `-no-resource-quota`) cover Capsule's `Tenant`
enforcement surface — see each check's own `audit.k8s-auditor.io/remediation` annotation for its
source, not duplicated here.

- `multitenancy.capsule-tenant-owner-cluster-admin-role` (High) — `Tenant.spec.owners[].clusterRoles`
  includes `"cluster-admin"` (default `{admin, capsule-namespace-deleter}`). Verified directly against
  Capsule's own source (`pkg/api/rbac/owner.go`, `CoreOwnerSpec.ClusterRoles` field comment): "Defines
  additional cluster-roles for the specific Owner" — Capsule synchronizes a RoleBinding for each into
  every namespace the tenant owns. Distinct from `multitenancy.capsule-tenant-cluster-admin-binding`,
  which only inspects `spec.additionalRoleBindings` — this checks the separate `spec.owners[]` field.
  Same underlying risk: a tenant subject with `cluster-admin` defeats tenant isolation entirely.

Investigated and declined for this pass (Capsule's API is mostly opt-in allowlists that are
permissive *when left unset*, the inverse of an "explicit downgrade" — most real gaps here are
"missing hardening" checks, a different pattern from what this pass targeted):
- `spec.serviceOptions.allowedServices.{nodePort,loadBalancer,externalName}` — real fields, and
  `externalName`'s own doc comment does say "Services with the type of ExternalName have security
  concerns," but its default is `true` (permitted) — there's no explicit-opt-in moment to catch, only
  an absence-is-already-insecure one. Worth a future pass with a different framing, not this one.
- `spec.podOptions` — verified via source: only contains `AdditionalMetadata` (labels/annotations), no
  security-relevant field.
- `spec.storageClasses`/`spec.runtimeClasses`/`spec.priorityClasses`
  (`DefaultAllowedListSpec`) — same "permissive when unset" shape as `allowedServices`; no distinct
  wildcard-allow sentinel value found.

## Fluent Operator (`fluentbit.fluent.io/v1alpha2`)

- `fluentbit.output-tls-not-verified` (High) — an `Output`/`ClusterOutput`'s `http`, `es`
  (Elasticsearch), `forward`, `splunk`, `loki`, `influxDB`, `opensearch`, `opentelemetry`,
  `prometheusRemoteWrite`, `syslog`, `tcp`, or `gelf` destination has no `tls.verify: true`. Fluent
  Bit's own [Transport Security docs](https://docs.fluentbit.io/manual/3.1/administration/transport-security)
  say to "always keep [TLS] verification ON in production" — each of these output types defaults to
  plaintext otherwise. All twelve verified field-by-field against
  [github.com/fluent/fluent-operator](https://github.com/fluent/fluent-operator)'s Go source (both
  the parent spec's exact json tags — e.g. `influxDB`, `opensearch` not `open_search`,
  `prometheusRemoteWrite` not `prometheus_remote_write` — and each plugin's own type file): each
  embeds the identical `plugins.TLS` struct. `kafka` is deliberately **not** covered — it uses raw
  `rdkafka` properties instead, with no equivalent field to check. `datadog` is also not covered: its
  `TLS` field is a bare `*bool` ("use TLS at all," not "verify the certificate") — different
  semantics, not the same check.

## VictoriaMetrics Operator (`operator.victoriametrics.com/v1beta1`)

- `victoriametrics.no-delete-auth-key` (Medium) — `VMSingle`/`VMCluster` `spec.extraArgs` has no
  `deleteAuthKey`, leaving `/api/v1/admin/tsdb/delete_series` reachable without a key. This is one of
  several valid mitigations VictoriaMetrics documents (a `vmauth`/`vmgateway` proxy in front, or
  NetworkPolicy, cover the same gap) — a finding here means one specific layer is missing, not that
  the endpoint is confirmed reachable by an attacker.
- `victoriametrics.vmauth-unauthorized-access-wildcard-path` (High) — `VMAuth.spec.unauthorizedUserAccessSpec.url_map[]`
  has a `src_paths` entry matching everything (e.g. `".*"`). VMAuth's own
  [docs](https://docs.victoriametrics.com/victoriametrics/vmauth/): "Requests without an
  Authorization header are proxied according to the `unauthorized_user` section" — and this section
  "takes precedence when processing a route without credentials, even if such a route also exists in
  the users section." A wildcard here routes every unauthenticated request to that rule's backend,
  regardless of any per-user auth configured elsewhere in the same `VMAuth`. Note: `url_map`/
  `url_prefix` are deprecated as of operator v0.67.0 in favor of `spec.unauthorizedUserAccessSpec.targetRefs`
  (removal planned v0.69.0, per the CRD's own `+notes` annotation) — this check only catches the
  older, still-supported form.
- `victoriametrics.vmagent-remotewrite-tls-insecure-skip-verify` (High) —
  `VMAgent.spec.remoteWrite[].tlsConfig.insecureSkipVerify: true`. Verified directly against the
  operator's own Go source (`api/operator/v1beta1/vmextra_types.go`,
  `TLSConfig.InsecureSkipVerify` field comment): "Disable target certificate validation." A remote
  write destination with certificate verification disabled is MITM-able — every metric this VMAgent
  scrapes and forwards can be redirected or intercepted. Only `VMAgent` is checked; `VMAlert`/`VMAuth`
  use the same shared `TLSConfig` type on their own notifier/backend fields — not yet covered, known
  gap.
- `victoriametrics.vmauth-select-all-by-default-enabled` (Medium) — `VMAuth.spec.selectAllByDefault:
  true`. VictoriaMetrics operator's own doc comment (`api/operator/v1beta1/vmauth_types.go`):
  "changes default behavior for empty CRD selectors... with selectAllByDefault: true and empty
  userSelector and userNamespaceSelector Operator selects all exist users." An explicit opt-out of
  namespace/label-scoped trust boundaries — the same shape as `vault.auth-allowed-namespaces-wildcard`.
  Weaker-sourced than most checks here (no explicit "insecure" warning from VictoriaMetrics itself,
  same tier as `istio.gateway-weak-tls-version`).

Investigated and declined, with the underlying risk's actual mitigation noted:
- VMAlert/VMAlertmanager notifier/webhook credentials go through `SecretKeySelector` refs in the
  common case, not plaintext CRD fields — if one ever did land in a ConfigMap instead, this tool's
  generic `secrets.configmap-no-embedded-credentials` check already covers that pattern regardless
  of which product's ConfigMap it appears in.

## CloudNativePG (`postgresql.cnpg.io/v1` — no version history, never promoted)

- `cnpg.cluster-superuser-access-enabled` (High) — `Cluster.spec.enableSuperuserAccess: true`.
  CNPG's own [security docs](https://cloudnative-pg.io/documentation/current/security/) state that
  when this is `false` (the default), "the operator removes generated secrets and sets the postgres
  user password to NULL, preventing remote access via password authentication" — a single documented
  correct value, not a situational judgment call.
- `cnpg.cluster-monitoring-tls-disabled` (Medium) — `Cluster.spec.monitoring.tls.enabled` is not
  `true`. CNPG's own [monitoring docs](https://cloudnative-pg.io/docs/devel/monitoring/): "To enable
  TLS communication on the metrics port, configure the `.spec.monitoring.tls.enabled` setting to
  `true`. This setup ensures that the metrics exporter uses the same server certificate used by
  PostgreSQL to secure communication on port 5432." Defaults to `false` per the real CRD schema, so
  the metrics endpoint (Postgres statistics, not credentials) ships in plain HTTP by default.

Investigated and declined, with the underlying risk's actual mitigation noted:
- `spec.postgresql.pg_hba` can contain `trust`-auth lines, but CNPG's own docs frame this explicitly
  as part of the *intended* trust model for whoever already has write access to the `Cluster`
  object. **Mitigated already**: that's an RBAC-boundary concern this tool's `rbac-analyzer.*`
  checks already cover generically, not a standalone CNPG misconfiguration.
- The CNPG operator's own Deployment (`cnpg-controller-manager`) is fully hardened by CNPG itself
  out of the box (`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `readOnlyRootFilesystem: true`, non-root, resource limits — verified against the real install
  manifest). **Mitigated already**: any regression here is caught generically by this tool's
  `workload.*` checks, same as any other Deployment.
- The operator's own admission webhooks (`cnpg-mutating-webhook-configuration`/
  `cnpg-validating-webhook-configuration`) ship hardcoded `failurePolicy: Fail` with no chart-exposed
  toggle to weaken it — unlike Kyverno's `--forceFailurePolicyIgnore`, there's nothing to check;
  it's fixed, not configurable.
- `Pooler.spec.pgbouncer.parameters.client_tls_sslmode`/`server_tls_sslmode`/`auth_type` are real
  fields, but CNPG's docs don't pick one value as *the* documented-secure setting the way
  `enableSuperuserAccess`/monitoring TLS do — PgBouncer's sslmode has several legitimate levels, and
  `auth_type: hba` is CNPG's own stated default, not an insecure one. Not solidly sourced as
  right-vs-wrong; declined on the same grounds as VictoriaMetrics' `insecureSkipVerify` above.
- `spec.automountServiceAccountToken` (ServiceAccount token automount on the instance Pods/Job) —
  CNPG's live docs (`docs/src/security.md`) still show this as a user-settable `Cluster.spec` field
  with an example YAML, but it genuinely doesn't exist: verified directly against `ClusterSpec` in
  `api/v1/cluster_types.go` and the generated CRD schema (both current release and `main`) — no such
  field, on any version. The docs are stale: an open (unmerged as of this writing) upstream PR,
  [#11297](https://github.com/cloudnative-pg/cloudnative-pg/pull/11297), explains why — the
  opt-in field was **removed** in favor of unconditional operator behavior
  ([#11115](https://github.com/cloudnative-pg/cloudnative-pg/pull/11115), "always disable service
  account token automount"): CNPG now disables automount on every instance Pod, the initdb Job, and
  the generated ServiceAccount **unconditionally**, with no field for a user to misconfigure.
  **Mitigated already, more strongly than any check this tool could add**: the behavior is
  guaranteed by the operator itself, not something a scan needs to verify per-Cluster.

## Strimzi (`kafka.strimzi.io/v1` — no version history, never promoted)

- `strimzi.kafka-no-authorization-configured` (High) — `Kafka.spec.kafka.authorization` is unset.
  Verified directly against the real CRD schema
  (`install/cluster-operator/040-Crd-kafka.yaml`): the field is entirely optional and passed
  straight through to the broker's own authorizer config — with no authorizer configured, Kafka's
  default is to allow every operation to every client, no ACL boundary at all.
- `strimzi.kafka-external-listener-tls-disabled` (High) — a `Kafka.spec.kafka.listeners` entry
  whose `type` is not `internal` (`route`/`tlsroute`/`loadbalancer`/`nodeport`/`ingress`/
  `cluster-ip` all reach the broker from outside the cluster's pod network) has `tls` not set to
  `true`. `tls` is a required field on every listener (verified against the schema), so this is
  always an explicit `false`, never an omission.
- `strimzi.kafka-external-listener-no-authentication` (High) — same external-listener scope as
  above, but `authentication` is unset entirely: any client that can reach the listener can
  connect with no credentials at all (only `spec.kafka.authorization`, checked separately, could
  still gate what an unauthenticated client is allowed to do).
- `strimzi.kafkauser-acl-wildcard-topic-access` (High) — a `KafkaUser.spec.authorization.acls`
  `allow` rule has `resource.type: topic`, `resource.name: "*"`, `patternType: literal` (the
  default). A literal `"*"` resource name is Kafka's own well-known ACL wildcard convention
  (`ResourcePattern` with `PatternType.LITERAL` and name `"*"` matches every resource of that
  type), not a general glob — this grants the rule's operations against every topic in the
  cluster, including ones created later.

Component detection (`internal/thirdparty/components.yaml`) matches the `strimzi-cluster-operator`
Deployment's own `app: strimzi` label, verified against the real install manifest
(`install/cluster-operator/060-Deployment-strimzi-cluster-operator.yaml` in
strimzi/strimzi-kafka-operator) — not the pod-template-only `strimzi.io/kind: cluster-operator`
label, which this tool doesn't match on (see [Component inventory](#component-inventory-internalthirdparty)
above: matching is against an object's own `metadata.labels`, not its pod template).

## Kyverno (`kyverno.io/v1` ClusterPolicy/Policy)

- `kyverno.policy-validation-not-enforced` (Medium) — a policy with at least one `validate` rule has
  `spec.validationFailureAction` unset or set to `"Audit"`. Kyverno's own
  [policy settings docs](https://kyverno.io/docs/policy-types/cluster-policy/policy-settings/):
  `Audit` "allow[s] the admission review request and report[s] the policy failure in a policy
  report" instead of blocking it — and the field "Defaults to `Audit`" when omitted entirely, so an
  unset value is exactly as non-blocking as an explicit one. Policies with only
  `mutate`/`generate`/`verifyImages` rules (no `validate` rule) are skipped — the field has no
  effect on them.
- `kyverno.admission-controller-force-failure-policy-ignore` (High) — a container runs with
  `--forceFailurePolicyIgnore=true`. Kyverno's own
  [installation/customization docs](https://kyverno.io/docs/installation/customization/): this flag
  is "Set to force Failure Policy to `Ignore`" — overriding every individual policy's own
  `spec.failurePolicy` (default `Fail`) cluster-wide, so if Kyverno itself becomes unreachable,
  every admission request across the cluster is allowed through unchecked instead of blocked. Pod
  config, not a CRD field — checked on the `kyverno-admission-controller` Deployment's container
  args, the same way any other workload check reads container config, distinguished only by this
  flag's own distinctive name.
- `kyverno.cluster-policy-admission-disabled` (High) — `spec.admission: false`. Verified directly
  against Kyverno's own source (`api/kyverno/v1/spec_types.go`, `Admission` field comment): "controls
  if rules are applied during admission... Default value is \"true\"." A policy with this set still
  exists and still looks active, but is completely inert at admission time — the same "looks active
  but silently isn't" shape as `kubevirt.root-feature-gate-enabled`.
- `kyverno.cluster-policy-failure-policy-ignore` (Medium) — either `spec.failurePolicy` (deprecated
  but still functional) or `spec.webhookConfiguration.failurePolicy` is `"Ignore"`. Verified directly
  against Kyverno's own source (`api/kyverno/v1/common_types.go`,
  `WebhookConfiguration.FailurePolicy` field comment): "Allowed values are Ignore or Fail. Defaults to
  Fail." Per-policy analog of `kyverno.admission-controller-force-failure-policy-ignore` (which flags
  the admission-controller-wide container flag) — this flags the same fail-open downgrade set on an
  individual policy object.
- Not checked: `spec.validationFailureAction`/`spec.rules[*].validate[*].failureAction` set to
  `Audit` as a "downgrade" signal on top of the existing `kyverno.policy-validation-not-enforced` —
  `Audit` is Kyverno's own documented *default*, so a dedicated "explicitly set to Audit" check would
  fire on the overwhelming majority of real-world ClusterPolicies; already covered by the existing
  check regardless of whether it's explicit or inherited. `background: false`/`skipBackgroundRequests`
  — these control background *scanning* (drift detection on existing resources), not admission-time
  enforcement; disabling them doesn't let anything new through.
- Not checked: `PolicyException` objects (which let matched resources bypass specific policies).
  Kyverno's own docs flag narrow-scoping as "a best practice," but judging whether a given
  `spec.match` is "too broad" isn't a single documented threshold this tool can check without
  guessing — the same bar that keeps this list short elsewhere.

## Apache Airflow (no CRD — ConfigMap content check)

- `airflow.webserver-expose-config-enabled` (Medium) — the rendered `airflow.cfg` (a ConfigMap data
  key, not a typed field — Airflow has no CRD of its own) sets `expose_config = True`. Airflow's own
  [configuration reference](https://airflow.apache.org/docs/apache-airflow/stable/configurations-ref.html):
  `expose_config` "Expose the configuration file in the web server[.] Set to `True` to expose
  configuration with sensitive values always masked[.] ... `False` hides the configuration
  completely" — and defaults to `False`. Sensitive values are masked in current Airflow, but
  hostnames, paths, and other settings are still exposed to any authenticated user, an explicit
  opt-in deviation from the secure default.
- `airflow.webserver-config-auth-role-public` (Critical) — the rendered `webserver_config.py` (a
  ConfigMap data key, rendered only when a user sets `apiServer.apiServerConfig`/
  `webserver.webserverConfig` in the official Helm chart — harmless/zero-findings on the common case
  where a cluster doesn't customize it) sets `AUTH_ROLE_PUBLIC` to a non-empty role. Airflow's own
  [docs](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/webserver-authentication.html):
  "To deactivate the authentication and allow users to be identified as Anonymous, the following
  entry in `$AIRFLOW_HOME/webserver_config.py` needs to be set with the desired role that the
  Anonymous user will have by default: `AUTH_ROLE_PUBLIC = 'Admin'`" — this is Airflow's own
  documented mechanism for disabling authentication entirely, still relevant on current Airflow 3.x
  (whose default `auth_manager` is still Flask-AppBuilder-based).
- `airflow.hide-sensitive-var-conn-fields-disabled` (High) — `airflow.cfg`'s `[core]
  hide_sensitive_var_conn_fields` is `False`. Airflow's own configuration reference: "Hide sensitive
  Variables or Connection extra json keys from UI and task logs when set to `True`," default `True`.
  Connection *passwords* are always hidden regardless (per the same docs) — this only controls the
  extra-JSON keys and Variables, but those routinely carry secrets too.
- `airflow.api-auth-backend-default-enabled` (Critical) — `airflow.cfg`'s `[api] auth_backends`
  includes `airflow.api.auth.backend.default`. This is Airflow 2.x's own configuration reference,
  quoted verbatim: `("airflow.api.auth.backend.default" allows all requests for historic reasons)`.
  Airflow's own documentation stating, in its own words, that this backend grants unauthenticated
  access to the REST API — same severity tier as `airflow.webserver-config-auth-role-public`. Note:
  this config key is specific to Airflow 2.x's auth-backend model; Airflow 3.x's docs (fetched as
  "stable" at the time this check was written) no longer list it, having moved to a different
  auth-manager-based API auth model — this check may need revisiting once Airflow 3.x's own
  equivalent (if any) is confirmed.

Investigated and declined, with the underlying risk's actual mitigation noted:
- `AIRFLOW__CORE__FERNET_KEY`/`AIRFLOW__API__SECRET_KEY` as plaintext env vars — verified against the
  chart's rendered Deployment output: both are always wired via `secretKeyRef`, never inlined.
  **Mitigated already** (there's no insecure path the chart itself exposes); if a value were ever
  inlined some other way, this tool's generic secrets checks would be the place to catch it, not a
  dedicated Airflow check.
- A "static/default webserver secret key" warning the chart renders as a UI alert — gated behind a
  chart version check (`airflowVersion < 3.0.0`) that never applies on a current default install
  (`3.2.2`), and the generated value itself is Helm-templated randomness per install, not a fixed
  known default the way APISIX's `admin_key` is. Too version-narrow and not a checkable fixed value.

## Apache APISIX (`apisix.apache.org/v2` CRDs + ConfigMap content checks)

- `apisix.admin-api-default-key` (Critical) — the rendered `config.yaml` (a ConfigMap data key)
  still contains one of the literal default Admin API keys the official `apisix/apisix` Helm chart
  ships in its own `values.yaml` (`admin: edd1c9f034335f136f87ad84b625c8f1`,
  `viewer: 4054f7cf07e344346cd3f287985e76a2`) — the chart's own inline comment next to that field:
  "Highly recommended to modify this value to protect APISIX's Admin API. Disabling this
  configuration item means that the Admin API does not require any authentication." A default key
  left in place grants full control-plane access (routes, upstreams, consumers) to anyone who can
  reach the Admin API port. Deliberately narrow: only the exact literal defaults still committed in
  the chart today, not a generic "weak key" heuristic this tool can't judge.
- `apisix.admin-auth-disabled` (Critical) — `config.yaml` sets `admin_key_required: false`. The
  official raw config
  ([config.yaml.example](https://github.com/apache/apisix/blob/master/conf/config.yaml.example)):
  `` admin_key_required: true   # Enable Admin API authentication by default for security. `` —
  setting this `false` disables Admin API authentication entirely, independent of whatever
  `admin_key` is configured. Not rendered by the Helm chart's own `values.yaml` (relies on APISIX's
  internal default of `true`), so this only fires if a user overrides raw config content directly —
  when they do, it's more severe than a weak/default key.
- `apisix.admin-allow-wide-open` (High) — `config.yaml`'s `allow_admin` includes `0.0.0.0/0` (or
  `::/0`). Same source: "Limit Admin API access by IP addresses. ... If not set, any IP address is
  allowed." The official Helm chart itself defaults this to `127.0.0.1/24` (verified against the
  chart's rendered output), so a `0.0.0.0/0` entry is an explicit widening a default install never
  produces — defense in depth independent of the two checks above: even a strong, rotated key with
  auth required is reachable from anywhere without this.
- `apisix.etcd-connection-plaintext` (Medium) — `config.yaml`'s `etcd.host` entries use `http://`
  instead of `https://`. Weaker-sourced than the two checks above: APISIX's own
  [config example](https://apisix.apache.org/docs/apisix/deployment-modes/) and the official
  `apisix/apisix` Helm chart both ship `http://` as the default for "traditional" mode (verified
  against the chart's rendered output) — only the "decoupled" mode doc example uses `https://`, with
  no explicit imperative warning from APISIX itself. The severity argument instead rests on etcd's
  own docs: "An etcd cluster which doesn't enable security features can expose its data to any
  clients" — etcd is where APISIX stores its *entire* routing/plugin/consumer configuration, reachable
  without going through the Admin API's own auth at all if etcd itself is exposed. Same cross-project
  sourcing pattern as `istio.gateway-weak-tls-version` (which cites IETF RFC 8996 rather than an
  Istio-authored warning).
- `apisix.tls-weak-protocol-enabled` (High) — `config.yaml`'s `apisix.ssl.ssl_protocols` includes
  `TLSv1`, `TLSv1.1`, or `SSLv3`. APISIX's own [SSL protocol docs](https://apisix.apache.org/docs/apisix/ssl-protocol/):
  the default is `"TLSv1.2 TLSv1.3"` and "For security reasons, the encryption suite used by default
  in APISIX does not support TLSv1.1 and lower versions" — supporting them is a deliberate widening
  away from that default. Word-boundary-safe match so a bare `TLSv1` doesn't false-positive on the
  `TLSv1.2`/`TLSv1.3` substrings in the (very common) unmodified default value.
- `apisix.tls-skip-mtls-uri-regex-wildcard` (High) — the `ApisixTls` CRD's
  `spec.client.skip_mtls_uri_regex` contains a match-everything pattern (`.*`, `/.*`, `.+`, `^.*$`,
  `^/.*$`). Verified directly against the apisix-ingress-controller CRD
  (`config/crd/bases/apisix.apache.org_apisixtlses.yaml`, `apisix.apache.org/v2`, plural
  `apisixtlses`): the field "contains RegEx patterns for URIs to skip mutual TLS verification." Same
  "flag the specific dangerous value, not mere field presence" pattern as
  `victoriametrics.vmauth-unauthorized-access-wildcard-path` — the field itself is a legitimate,
  documented allowlist mechanism (e.g. for a `/healthz` path); only a wildcard value defeats mTLS
  entirely.

Also investigated and declined: `ApisixTls.spec.client.caSecret` presence/absence — no documented
insecure-value shape beyond the wildcard-regex case above (mTLS being configured or not is a
deployment choice, not itself a downgrade). A route explicitly removing a previously-required auth
plugin (`ApisixRoute`/`ApisixPluginConfig`) — this is a diff/baseline-comparison concern ("was this
route protected before?") a single-object admission check structurally can't express; known gap, no
existing mitigation.

Also investigated: etcd's own built-in RBAC (per-key-prefix users/roles, configured via `etcdctl`)
is a real etcd feature, but it's configured entirely on the etcd server side — nothing in APISIX's
own `config.yaml` reflects or sets it (the client-side fields are just `host`/`user`/`password`/`tls`),
so there's no APISIX object this tool could check for it. `etcd.user`/`etcd.password` being unset
isn't checked either: absence doesn't unambiguously mean "no auth," since many legitimate
deployments rely on network isolation (a private etcd not reachable outside the cluster) instead of
etcd-level credentials — same class of situational field as CNPG's PgBouncer `sslmode` above, not a
single documented right-vs-wrong value.

## Calico (`crd.projectcalico.org`)

- `calico.felixconfiguration-wireguard-disabled` (Medium) — `FelixConfiguration.spec.wireguardEnabled`
  is not `true`. Calico's own [WireGuard encryption docs](https://docs.tigera.io/calico/latest/network-policy/encrypt-cluster-pod-traffic):
  "Enable WireGuard to secure on-the-wire, in-cluster pod traffic in a Calico cluster." Defaults to
  `false` — verified directly against Felix's own source
  (`felix/config/config_params.go`: `` WireguardEnabled bool `config:"bool;false"` ``). Dual-stack
  clusters should also set `wireguardEnabledV6` (not separately checked). `FelixConfiguration` is a
  cluster-wide singleton (conventionally named `default`), so this is "is encryption enabled
  cluster-wide," not per-workload.
- `calico.felixconfiguration-default-endpoint-to-host-action-permissive` (Medium) —
  `spec.defaultEndpointToHostAction` is `Accept` or `Return` (case-insensitive, per Felix's own CRD
  validation pattern). Verified directly against Felix's own source
  (`felixconfig.go`, `DefaultEndpointToHostAction` field comment): "By default, Calico blocks traffic
  from workload endpoints to the host itself with an iptables 'DROP' action... Use ACCEPT to
  unconditionally accept packets from workloads after processing, or RETURN to accept packets from
  workloads that pass through untouched." Medium, not High: blast radius is workload→host traffic
  only, not workload↔workload.
- `calico.felixconfiguration-allow-ipip-packets-from-workloads` (High) and
  `calico.felixconfiguration-allow-vxlan-packets-from-workloads` (High) —
  `spec.allowIPIPPacketsFromWorkloads`/`spec.allowVXLANPacketsFromWorkloads` is `true` (both default
  `false`). Verified directly against Felix's own source (`felixconfig.go`): each "controls whether
  Felix will add a rule to drop IPIP/VXLAN encapsulated traffic from workloads." Enabling either is a
  known technique for a workload to smuggle traffic past NetworkPolicy enforcement, which only
  inspects the inner, unencapsulated packet — an explicit, cluster-wide opt-out of that protection.

Also investigated and declined: `prometheusMetricsEnabled` — no explicit "exposes metrics without
auth" warning found in Calico's own docs in the time available; declined for insufficient sourcing,
not asserted to be safe. `policySyncPathPrefix` (the Dikastes/Envoy policy-sync socket, needed for
Istio+Calico integration) — an off-by-default feature-enablement flag, doesn't itself weaken an
existing default. `GlobalNetworkPolicy`/`NetworkPolicy` (Calico's own CRDs) `Pass`-action/rule-ordering
footguns — a real, documented misconfiguration class, but it's a cross-rule/cross-policy ordering
interaction with no single bad value on one object; known gap, no existing mitigation.

Not checked: default-deny `NetworkPolicy`/`GlobalNetworkPolicy` coverage. Calico's own docs describe
only an *implicit* end-of-tier default-deny behavior, not a "your policy object must look like X"
pattern checkable on a single object — whether default-deny is actually in effect for a given
workload is a coverage question, already handled generically (Cilium/Calico presence-based) by
`netpol-analyzer.no-network-policy-coverage`.

## KubeVirt (`kubevirt.io`)

- `kubevirt.kubevirt-use-emulation-enabled` (Medium) — the cluster-wide `KubeVirt` config object's
  `spec.configuration.developerConfiguration.useEmulation` is `true`. KubeVirt's own source comment
  (`staging/src/kubevirt.io/api/core/v1/types.go`): "UseEmulation can be set to true to allow
  fallback to software emulation" when hardware virtualization isn't available — and its
  [software-emulation docs](https://kubevirt.io/user-guide/operations/software_emulation/), linked
  from the official installation guide: "If `useEmulation` is enabled, `qemu` will be used for
  software emulation, in case that hardware emulation via `/dev/kvm` is unavailable." Weaker-sourced
  than most checks here (no explicit security warning from KubeVirt itself, same tier as
  `istio.gateway-weak-tls-version`) — software (QEMU TCG) emulation lacks the hardware-enforced
  VT-x/AMD-V isolation `/dev/kvm` provides, a materially larger VM-escape surface; the field also
  lives under `developerConfiguration`, KubeVirt's own naming convention for dev/test-only settings.
- `kubevirt.host-disk-volume` (High) — a `VirtualMachine`/`VirtualMachineInstance` has a volume with
  `hostDisk` set. KubeVirt's own
  [user guide](https://kubevirt.io/user-guide/storage/disks_and_volumes/): "A `hostDisk` volume type
  provides the ability to create or use a disk image located somewhere on a node. It works similar
  to a `hostPath` in Kubernetes" — the same node-filesystem-access concern this tool's
  `workload.no-hostpath-volumes` flags for ordinary Pods, on a KubeVirt-specific field shape that
  check doesn't cover. One expression covers both `VirtualMachine` (`spec.template.spec.volumes[]`)
  and a bare `VirtualMachineInstance` (`spec.volumes[]` directly) — verified against the real Go
  source, not guessed.
- `kubevirt.root-feature-gate-enabled` (Critical) — the `KubeVirt` CR's
  `spec.configuration.developerConfiguration.featureGates` includes `"Root"`. Verified directly
  against KubeVirt's own source
  (`pkg/virt-api/webhooks/mutating-webhook/mutators/vmi-mutator.go`): `if !clusterConfig.RootEnabled()
  { markAsNonroot(newVMI) }` — every VMI is mutated at admission to run virt-launcher as non-root
  (UID 107) *unless* this gate is enabled, in which case that mutation is skipped and virt-launcher
  runs as root. `NonRoot` is General Availability (`pkg/virt-config/featuregate/inactive.go` — always
  on); `Root` remains Alpha (`.../featuregate/active.go`) — an explicit, cluster-wide opt-out of
  KubeVirt's own secure-by-default posture, exactly the "operator can explicitly turn something off"
  shape this section is for.
- `kubevirt.sidecar-feature-gate-enabled` (High) — the same `featureGates` array includes
  `"Sidecar"`. KubeVirt's own hook-sidecar docs (`cmd/sidecars/README.md`) are explicit: "The Sidecar
  feature gate must be enabled in the KubeVirt Custom Resource before using sidecars" and "Once
  enabled, every VM owner may use it to run arbitrary code in the context of virt-launcher which may
  have unexpected effects" — a first-party admission that this gate is an arbitrary-code-execution
  opt-in, cluster-wide.
- `kubevirt.hook-sidecar-annotation-present` (High) — a `VirtualMachine`/`VirtualMachineInstance` sets
  the `hooks.kubevirt.io/hookSidecars` annotation (checked at both `metadata.annotations` and, for a
  `VirtualMachine`, `spec.template.metadata.annotations` — per KubeVirt's own docs, only the latter
  actually propagates to the VMI). Companion to the gate check above: flags the actual per-VM usage of
  the arbitrary-code-execution mechanism, not just cluster-wide enablement.
- `kubevirt.containerpath-volume-exposes-sa-token` (High) — a VM's `containerPath` volume `path`
  starts with `/var/run/secrets/kubernetes.io/serviceaccount`. KubeVirt's own docs
  (`docs/storage/containerpath_volumes.md`, "Security considerations"): "VMs gain access to any files
  within the specified container path — only expose paths containing data intended for VM
  consumption." The documented, intended use of this feature is exposing a purpose-provisioned
  external-cloud-identity token (AWS IRSA, Azure workload identity, ...); this check only flags the
  pod's *own* default Kubernetes API token path, not `containerPath` usage in general — a legitimate
  IRSA-style path (verified fixture: `.../eks.amazonaws.com/serviceaccount`) does not trigger it.

Also investigated for this pass, and declined with a documented reason (per the same "understand why
and note the mitigation" bar as every other decline in this document):
- VM/VMI-level `spec.domain.devices.hostDevices[]`/`gpus[]` (*requesting* a passthrough device) —
  whether a referenced device name is actually dangerous depends entirely on the separate `KubeVirt`
  CR's `permittedHostDevices` allowlist, a cross-object correlation a single-object VAP check can't
  do. No existing mitigation for this specific gap; noted as a known limitation, same class as the
  RBAC-binding-vs-role cross-object gap noted below.
- `GPU`/`HostDevices`/`ConfigurableHypervisor` feature gates — unlike `Root`/`Sidecar`, none carry an
  explicit KubeVirt-authored security warning (`ConfigurableHypervisor`'s own source comment says only
  "allows using hypervisors other than KVM"). Flagging them would mean guessing at severity without a
  documented basis — declined on sourcing grounds, not safety grounds.
- `bridge`/`masquerade` network binding methods (documented to need extra pod capabilities vs. `passt`)
  — declined as a check: `masquerade` is KubeVirt's *default* primary-network binding for the
  overwhelming majority of ordinary VMs, so flagging it would be almost pure noise, unlike `hostDisk`
  where a PVC is the normal, unremarkable alternative. No existing mitigation; known gap only if
  per-VM network-capability visibility is wanted specifically.
- `macspoofchk`/`spoofchk` — the actual setting lives on the referenced `NetworkAttachmentDefinition`
  object, not the VM/VMI's own spec: cross-object, not checkable from a single object.
- `DisableCustomSELinuxPolicy` feature gate — functionally moot: verified via
  `kubevirt/kubevirt#11266` (merged 2025-01-21, "Completely remove unused custom SELinux policy") that
  the policy this gate once controlled is no longer used by anything; the gate constant only remains
  for backward compatibility.
- `permittedHostDevices` (the `KubeVirt` CR's own allowlist) — re-confirmed decline from the first
  pass: KubeVirt's docs describe it purely as the intended admin-allowlisting mechanism, with no
  "should be empty" baseline.
- `accessCredentials` (SSH key/password injection) — re-verified directly against
  `staging/src/kubevirt.io/api/core/v1/schema.go`: both `SSHPublicKeyAccessCredential` and
  `UserPasswordAccessCredential` remain `SecretRef`-based only; no plaintext-credential field exists
  in the current schema.
- `Passt`/`Macvtap`/`PasstIPStackMigration`/`ExperimentalVirtiofsSupport` feature gates — all marked
  `State: Discontinued` in source (e.g. "Macvtap network binding is discontinued since v1.3") —
  non-functional even if present in a manifest, not worth flagging.
- Firmware/bootloader/secure-boot fields and `autoattachGraphicsDevice`/VNC-related fields — no
  documented insecure-value shape found in either KubeVirt's docs or source comments; declined per
  this repo's sourcing bar rather than guessing a severity.
- Default `kubevirt.io:admin`/`:edit`/`:view` ClusterRoles and console/VNC access — the real risk is
  *who is bound* to these roles, a cross-object RBAC question. **Mitigated already**: this repo's
  `rbac-analyzer.*` checks already cover broad/risky ClusterRoleBinding grants generically, regardless
  of which ClusterRole.

Not yet covered, flagged as a known gap (same as Calico's `calico-node` above): `virt-handler`, the
node-level agent that actually runs VMs and needs `/dev/kvm` (and likely other host-level access),
is architecturally System-shaped the same way Cilium's/Falco's agents are — but it's created
dynamically by `virt-operator` based on the `KubeVirt` CR rather than shipped in a static install
manifest, so its real privilege requirements haven't been verified against a live cluster yet.
Promoting it to a builtin exception needs that verification first, not an assumption. `KubeVirt`'s
component-inventory entry (Application category) only covers `virt-operator`, the cluster-wide
control-plane Deployment — verified against the official release manifest
(`kubevirt.io: virt-operator` label).

## Temporal (`temporal.io/v1beta1` CRD + ConfigMap/Deployment checks)

The CRD checks below target `TemporalCluster`, from the community
[alexandrevilain/temporal-operator](https://temporal-operator.pages.dev/) — Temporal itself doesn't
ship a CRD; the far more common path is the official `temporalio/helm-charts` chart, covered by the
ConfigMap/Deployment checks instead.

- `temporal.authorization-not-configured` (Critical) — the rendered `config_template.yaml` (a
  ConfigMap data key, not a fixed object name — the chart names it
  `{{ temporal.fullname }}-config`, which varies by release) has no `authorization:` block under
  `global:`. Temporal's own [security docs](https://docs.temporal.io/self-hosted-guide/security):
  "If you do not explicitly configure an Authorizer, Temporal uses the default `noopAuthorizer`.
  This default allows every API request, with no authentication or access control" — and explicitly:
  "your deployment is effectively open to anyone with network access." Verified against the chart's
  own template: the whole block is only rendered if a user sets `server.config.authorization`, and
  the chart's own `values.yaml` ships it fully commented out.
- `temporal.operator-authorizer-empty` (Critical) — `TemporalCluster.spec.authorization.authorizer`
  is unset or `""`. Same underlying risk as the check above, for operator-managed clusters. Verified
  directly against the operator's own CRD schema: "can be left as an empty string to use a
  no-operation authorizer (noopAuthorizer)."
- `temporal.internode-tls-disabled` (High) and `temporal.frontend-tls-disabled` (High) — the same
  ConfigMap's `global.tls.internode.enabled`/`global.tls.frontend.enabled` is `false`. Verified
  against the chart's own `values.yaml`: both default to `false`. Temporal's docs frame mTLS as the
  documented way to secure server-to-server and client-facing traffic; the plaintext alternative is
  explicitly framed as a deliberate operator choice ("run unsecured instances inside of a VPC
  environment"), not the recommended default.
- `temporal.web-auth-not-enabled` (High) — an `apps/v1 Deployment` running a `temporalio/ui*` image
  has no `TEMPORAL_AUTH_ENABLED=true` env var. Temporal's own docs on Web UI SSO integration state
  enabling it "requires... you must set `TEMPORAL_AUTH_ENABLED=true`" — i.e. authentication is
  disabled by default. Broad-match (any Deployment) + narrow condition (the exact image prefix), same
  pattern as `kyverno.admission-controller-force-failure-policy-ignore`.

Investigated and declined: default DB/Cassandra/Elasticsearch backing-store passwords — the chart's
own `values.yaml` has no hardcoded default anywhere; every backing-store credential is wired via
`existingSecret`/`secretKey` references, so there's no known-default value to check even with
`--read-secret-values`. Admin-tools' `useExternalFrontend: false` bypass — the documented, intended
administrative access pattern, not a misconfiguration; the actual risk (who can reach the admintools
Pod) is a NetworkPolicy/RBAC question this repo's generic `network.*`/`rbac-analyzer.*` checks already
cover. No published GitHub Security Advisories exist for `temporalio/temporal` or `temporalio/ui` as
of this writing, so unlike ArgoCD's Redis check there's no CVE-specific signature to trace a check to.

## Grafana Loki (`loki.grafana.com/v1` `LokiStack` CRD + ConfigMap checks)

- `loki.auth-disabled` (High) — the rendered `loki.yaml` (a ConfigMap data key) sets
  `auth_enabled: false`. Loki's own config reference: "Enables authentication through the
  `X-Scope-OrgID` header, which must be present if true. If false, the OrgID will always be set to
  'fake'." Verified against the official `grafana/loki` chart's own `values.yaml`:
  `auth_enabled: true` is the chart's own default — `false` only appears when an operator explicitly
  overrode it. Caveat even when `true`: Loki's own docs state "Grafana Loki does not come with any
  included authentication layer. You must run an authenticating reverse proxy in front of your
  services" — this flag only enforces tenant-ID separation between callers already past that proxy,
  it isn't authentication on its own; the remediation text says so explicitly to avoid over-trusting
  a passing scan.
- `loki.lokistack-tenants-not-configured` (Medium) — the `LokiStack` CRD's (Loki Operator, mainly
  OpenShift installs) `spec.tenants` is unset. Verified directly against the operator's own Go
  source: "Tenants defines the per-tenant authentication and authorization spec for the
  lokistack-gateway component" — the operator's entire auth/authz configuration point. Medium rather
  than High: this repo hasn't independently confirmed the operator's exact behavior (what gateway, if
  any, gets deployed) when this is left unset.

## Grafana Tempo (ConfigMap checks)

- `tempo.receiver-tls-not-configured` (Medium) — the rendered `tempo.yaml` has an `otlp:` receiver
  configured with no `tls:` anywhere in the file. Weaker-sourced than most checks here (Tempo's docs
  describe the TLS config paths but don't independently warn that omitting them is insecure — same
  tier as `istio.gateway-weak-tls-version`). Deliberately coarse-grained: reliably scoping "a `tls:`
  block is a direct child of this specific receiver" via regex against a YAML text blob isn't robust
  enough to ship without real false-positive/false-negative risk, so this only checks "is the word
  `tls:` present anywhere in the file at all" once an OTLP receiver exists — trading precision for a
  check that won't misfire, at the cost of a possible false pass if `tls:` appears elsewhere
  unrelated to the receiver.

Investigated and declined: `multitenancy_enabled: false` — unlike Loki's `auth_enabled`, Tempo's own
chart default is also `false` (verified against `charts/tempo-distributed/values.yaml`), so flagging
it would fire on the overwhelming majority of unmodified installs — not an operator-triggered
downgrade, the pattern this pass specifically targets. Tempo's own authentication model (no built-in
auth layer, same as Loki) has no admission-visible field to check — the actual mitigation (an
authenticating reverse proxy) is a cross-object, external-tool concern this tool's single-object CEL
model structurally can't verify; known gap, no existing mitigation.

## Apache Superset (Secret/Deployment checks — no CRD)

- `superset.secret-key-default-value` (Critical, **requires `--read-secret-values`**, see
  [Secrets Mode]({{ '/secrets-mode/' | relative_url }})) — a `Secret`'s `SUPERSET_SECRET_KEY` equals
  the base64 form of Superset's own well-known example value. Verified directly against Superset's
  source: `superset/constants.py` defines `CHANGE_ME_SECRET_KEY =
  "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"`, and `superset/config.py` falls back to it when
  `SUPERSET_SECRET_KEY` isn't set. This is **CVE-2023-27524** — a known/default `SECRET_KEY` lets an
  attacker forge a session cookie, bypass authentication, and reach SQL Lab (RCE in some
  configurations). The official chart's own `values.yaml` shows this exact string as its
  `extraSecretEnv.SUPERSET_SECRET_KEY` documentation example — a real, plausible copy-paste trap.
  Checkable at all only because the chart renders `extraSecretEnv` entries as individual Secret data
  keys, not because this tool can inspect the (opaque, base64, unparseable by this engine) full
  `superset_config.py` blob the chart also renders into a Secret — see below.
- `superset.talisman-disabled` (Medium) — a Superset container has `TALISMAN_ENABLED` set to a falsy
  value. Verified directly against Superset's own source: `TALISMAN_ENABLED =
  cast_to_boolean(os.environ.get("TALISMAN_ENABLED", True))` — a direct env-var override, default
  `true`. Talisman is Superset's Flask-Talisman middleware (CSP, HSTS, X-Frame-Options, and similar
  security response headers). Weaker-sourced tier (same as `istio.gateway-weak-tls-version`).

Investigated and declined: `AUTH_TYPE`/`AUTH_ROLE_PUBLIC`/`PUBLIC_ROLE_LIKE`/`WTF_CSRF_ENABLED`/
`PREVENT_UNSAFE_DB_CONNECTIONS`/`FEATURE_FLAGS` — all real, all confirmed in Superset's own
`config.py`, but the official Helm chart renders Superset's *entire* `superset_config.py` into a
**Secret** (`templates/secret-superset-config.yaml`), not a ConfigMap like Airflow's
`webserver_config.py`. This engine deliberately never base64-decodes Secret values (see
[Secrets Mode]({{ '/secrets-mode/' | relative_url }})), so a substring/regex check against an opaque
base64 blob isn't possible — there's no way to look inside it at all, checkable or not. Known,
structural gap; not mitigated elsewhere. `GUEST_TOKEN_JWT_SECRET`/`GLOBAL_ASYNC_QUERIES_JWT_SECRET`
also default to known example values (`test-guest-secret-change-me`,
`test-secret-change-me`) in `superset/constants.py`, same CVE-2023-27524 family — but both are plain
assignments inside `superset_config.py` itself, not `os.environ.get()`-wrapped like `SECRET_KEY`, so
there's no exposed env var/Secret key to check either. Same gap as above.

## Metabase (Deployment env checks — no CRD, no official Helm chart)

Metabase ships no official Helm chart at all (every community chart uses its own label convention —
`internal/thirdparty/components.yaml`'s `app: metabase` detection label is correspondingly
lower-confidence than every other entry in that file, verified only against the most-referenced
community chart, not an official one). All configuration is via plain container env vars (`MB_*`),
which makes it more checkable than Superset's opaque-Secret-blob shape, not less.

- `metabase.public-sharing-enabled` (Medium) — a `metabase/metabase*` container has no
  `MB_ENABLE_PUBLIC_SHARING=false` env var. Metabase's own environment variable reference:
  "Enable admins to create publicly viewable links (and embeddable iframes) for Questions and
  Dashboards?" **Default: true.** Once an admin creates a public link, anyone with the URL sees that
  data with zero authentication — a real, documented, unauthenticated-by-design exposure surface left
  at its default-enabled state.
- `metabase.encryption-secret-key-missing` (Medium, weaker-sourced) — a `metabase/metabase*`
  container has no `MB_ENCRYPTION_SECRET_KEY` env var (checking the var name's presence only, not its
  value — satisfied whether it's set directly or via `secretKeyRef`, so no secrets-mode needed).
  Weaker-sourced than most checks here: Metabase's own docs on encrypting details at rest use "can"
  rather than an imperative "must"/"always" — a documented option, not a documented requirement (same
  tier as `istio.gateway-weak-tls-version`). Underlying risk if unset: every database connection
  string/password Metabase manages is stored in cleartext in Metabase's own application database.

Investigated and declined: `MB_JWT_SHARED_SECRET` — real, but defaults to unset with no specific
known-bad value to compare against, situational (same grounds as CNPG's PgBouncer `sslmode` decline).
`MB_MFA_ENFORCEMENT` (default `"off"`) — MFA-not-enforced-by-default is close to universal across this
whole product category, not an explicit downgrade from a real secure baseline; declined as noise, same
reasoning as Kyverno's `Audit`-is-default decline. `MB_API_KEY` (the `/notify` webhook endpoint's
auth) — investigated whether absence means the endpoint is open; evidence points the other way
(reports describe it failing closed, erroring when unset, not allowing requests through) — declined
rather than asserting a vulnerability that wasn't confirmed. `MB_ENABLE_EMBEDDING_*`/
`MB_EMBEDDING_SECRET_KEY` — default `false`/unset, i.e. already secure-by-default and opt-in only, no
insecure default to flag.

## Velero — deliberately not covered

Researched and explicitly declined: Velero's own security guidance frames its actual risk surface as
RBAC on who can create `Backup`/`Restore` objects (already covered generically by this tool's
`rbac-analyzer.*` checks) and object-storage bucket policies (external to Kubernetes entirely).
`BackupStorageLocation.spec.config` is an untyped, provider-specific `map[string]string` with no
consistent field name for something like "skip TLS verify" across S3/GCS/Azure/MinIO — not solid
enough ground to build a check on without guessing.

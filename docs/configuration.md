---
layout: default
title: "Configuration"
permalink: /configuration/
---

# Configuration (`audit.yaml`)

Every field has a CLI flag equivalent (`kubectl audit scan --help`); flags override whatever is
set in the config file. Point at one with `--config audit.yaml`. Nothing is required — omitted
fields fall back to the built-in defaults shown below.

```yaml
target:
  # cluster: only the live cluster via kubeconfig
  # static:  only the paths listed below
  # both:    static paths + the live cluster (default)
  mode: both

  # Kube context to use in cluster mode. Empty = current context.
  context: ""

  # Human-readable cluster name for the report's Target field and every
  # finding's Source, instead of the raw context name above (which can be
  # an unreadable cloud-provider ARN/UUID, or just "current-context" if
  # `context` is empty). Cosmetic only. Useful when scanning several
  # clusters and archiving/diffing their reports.
  clusterName: ""

  # Scan every namespace (cluster mode). Set to false and list `namespaces`
  # to scope to specific namespaces.
  allNamespaces: true
  namespaces: []

  # Static manifest files/directories to audit (used in "static"/"both" mode).
  paths:
    - ./manifests

  # Namespaces to skip entirely, regardless of mode. Defaults to these two
  # (see Getting Started: Noise reduction) since they hold nothing worth
  # auditing (a public ConfigMap, Lease objects). kube-system is
  # deliberately NOT excluded by default — it commonly hosts real,
  # auditable third-party infrastructure; the genuinely unavoidable
  # findings from core plumbing (kube-proxy, static control-plane pods)
  # are handled precisely by built-in exceptions instead, not by hiding
  # the whole namespace. Ignored if `namespaces` above is a non-empty
  # allowlist.
  excludeNamespaces:
    - kube-public
    - kube-node-lease

  # Kubernetes' own built-in Role/ClusterRole/*Binding objects (name
  # prefix "system:") are excluded from RBAC findings by default, since
  # they're cluster-managed and can't be remediated. Set to true to
  # include them.
  includeSystemRBAC: false

policies:
  # Extra directories of custom ValidatingAdmissionPolicy YAML to load
  # alongside the bundled policies.
  dirs:
    - ./policies-custom

  # Disable specific bundled or custom policies by their metadata.name.
  disable: []
  #  - workload.no-latest-tag

  # Set to false to run only custom policies from `dirs`.
  builtin: true

output:
  json: findings.json
  markdown: report.md
  # CSV, one row per finding — for opening in a spreadsheet. Not written
  # unless set (no default path, unlike json/markdown above).
  csv: ""
  # Minimum severity that makes `scan`/`rbac analyze` exit 1:
  # none|low|medium|high|critical.
  failOn: high
  # Custom report.md.tpl (Go text/template). Empty uses the built-in
  # template — see `kubectl audit template dump` and Report Templates.
  template: ""
  # Each check's Title/Category/Remediation in the report is resolved
  # through triage.knowledgeBaseFile too (see below) — an org's own wording
  # shows up here the same way it already does in triage/Jira, no separate
  # config needed.
  # How the Markdown report's Findings section(s) are structured:
  # check:     group by check/policy ID, title/remediation shown once per
  #            check followed by the resources it fired on (default).
  # namespace: group by namespace/resource instead, full detail per
  #            finding — useful for a per-team/per-app handoff.
  # both:      the check-grouped view plus a compact by-namespace index.
  #            Roughly doubles the finding-line count on a large report
  #            (every finding listed once per view) — prefer check or
  #            namespace alone once findings run into the hundreds/thousands.
  reportView: check
  # Collapse a check's repeated per-namespace findings in the Markdown
  # report: when a check's message is identical for every finding (true of
  # essentially every built-in VAP/CEL check) and it fires on the same
  # Kind+Name pair in at least this many distinct namespaces — the common
  # multi-tenant shape, e.g. Capsule-provisioned tenant namespaces all
  # deploying the same manifest — those are shown as one row instead of one
  # bullet per namespace. Purely a Markdown rendering choice:
  # findings.json/CSV always list every finding individually, so --fail-on
  # gating and CI tooling see no difference. 0 disables collapsing.
  namespaceGroupThreshold: 3
  # Extends namespaceGroupThreshold's collapsing to names that share a
  # generated-identifier shape (a UUID, or another long hex/digit run),
  # not just an identical literal name — catches e.g. per-tenant Namespace
  # objects themselves named "usersvs-<uuid>", which can never share a
  # literal name since Namespace is cluster-scoped. On by default; set
  # false to only collapse exact name matches.
  groupByNamePattern: true

compliance:
  # Requirement framework(s) to score against: cis|fstec|nsa|capsule (see
  # compliance-mappings/ for the full list), or a path to a custom mapping
  # YAML. --frameworks on the CLI (scan only) overrides this. capsule is
  # this tool's own Capsule (github.com/projectcapsule/capsule)
  # multi-tenancy checklist, not an external standard like the other
  # three — only produces findings if the cluster/manifests have Capsule
  # Tenant objects.
  frameworks:
    - cis

# Configures `kubectl audit triage` — see Triage. No credential field: the
# Jira Personal Access Token comes from --jira-token or
# $KUBECTL_AUDIT_JIRA_TOKEN only, never this file.
triage:
  stateFile: triage-state.yaml
  # A bundled Russian title/description/remediation applies to every check
  # automatically (no config needed) — see Triage > Knowledge base. Point
  # this at a file to correct one entry or add your own organization's
  # wording; merged on top of the bundle, field by field. Read fresh on
  # every run, no rebuild. Also applied to the Markdown report's
  # Title/Category/Remediation (see output.template above) — one knowledge
  # base, used everywhere.
  # knowledgeBaseFile: knowledge-base.yaml
  jira:
    baseUrl: ""
    projectKey: ""
    issueType: ""
    # Optional: extraLabels (static labels on every created issue),
    # customFields (arbitrary Jira fields, string values Go-templated),
    # and summaryTemplate/descriptionTemplate (external .tpl file paths
    # fully replacing the built-in issue structure) — see Triage > Custom
    # fields, extra labels, and a fully custom template. All read fresh
    # on every run, no rebuild.

# Waivers for specific (check, resource) pairs — an accepted, documented
# risk, not a silent gap. Config-file only (no CLI flag: a rule has too many
# structured fields to fit one). Suppressed findings are never dropped: they
# still get computed normally, then set aside with their reason preserved
# in the report ("Suppressed Findings" section, findings.json's
# `suppressed` array) — excluded only from Summary counts, --fail-on, CSV
# export, and compliance scorecards.
#
# This list is merged with (not a replacement for) this tool's own built-in
# exclusion rules for well-known privileged infrastructure (Cilium's agent,
# prometheus-node-exporter, kube-proxy, static control-plane pods) — set
# disableBuiltinExceptions: true / --no-builtin-exceptions to turn all of
# those off, or disableBuiltinExceptionIds (below) to turn off just one. See
# third-party-operators.md#built-in-exceptions-for-privileged-system-infrastructure.
exclusions:
  - # Restricts this rule to specific checks; omit (or ["*"]) to apply it
    # to every check.
    policyIds:
      - workload.no-latest-tag

    # At least one of kind/namespace/name/labels is required — an empty
    # match is rejected at load time (it would silently suppress
    # everything). All fields set here must match (AND).
    match:
      kind: Deployment          # exact match
      namespace: legacy         # exact match
      name: "legacy-*"          # path.Match glob; a literal name still
                                 # works as an exact match
      labels:                   # every key must be present with this
        team: platform-legacy   # exact value on the source object

    # Required — shown next to every finding this rule suppresses.
    reason: "Legacy app pending migration, tracked in JIRA-1234"

# Disable individual built-in exclusion rules by id (see
# internal/suppress/builtin-exclusions.yaml for the current ids: cilium-agent,
# prometheus-node-exporter, falco, tetragon, kube-proxy, control-plane-static-pods) while
# leaving the rest active — finer-grained than disableBuiltinExceptions,
# which turns off all of them at once. An id with no matching rule is a
# harmless no-op (just a warning), not an error.
disableBuiltinExceptionIds: []
#  - cilium-agent

# Extend this tool's built-in third-party component inventory (see
# internal/thirdparty/components.yaml) — the only way to add your own
# in-house operator/CNI to the Detected Components table and orphan/
# mismatch detection without forking or rebuilding, which matters
# especially for a krew install (there's no components.yaml file on disk to
# edit — it's compiled into the binary). Same schema as the built-in file;
# merged with it, not a replacement. Adding an entry here does NOT by
# itself create a suppression exception — pair a System-category entry
# with your own `exclusions` rule (above) for that.
components:
  extra: []
  #  - name: InternalWidgetOperator
  #    category: Application       # System | Application (default: Application)
  #    group: internal.example.com # CRD API group, if any
  #    labels:                     # label selector for the actual
  #      app.kubernetes.io/name: internal-widget-operator  # controller Deployment/StatefulSet/DaemonSet
```

## Field reference

| Field | Type | Default | Notes |
|---|---|---|---|
| `target.mode` | `cluster\|static\|both` | `both` | `static` is auto-selected if `-f` is passed without an explicit `--mode`. |
| `target.context` | string | current context | Kube context for cluster mode. |
| `target.allNamespaces` / `target.namespaces` | bool / []string | `true` / `[]` | An explicit `namespaces` allowlist disables `excludeNamespaces`. |
| `target.paths` | []string | `[]` | Static manifest files/directories (`static`/`both` mode). |
| `target.excludeNamespaces` | []string | `[kube-public, kube-node-lease]` | See [Getting Started: Noise reduction]({{ '/getting-started/#noise-reduction' | relative_url }}). |
| `target.includeSystemRBAC` | bool | `false` | Include `system:`-prefixed RBAC objects. |
| `target.includeKinds` / `target.excludeKinds` | []string | `[]` | Filter which resource kinds are fetched in cluster mode. |
| `policies.dirs` | []string | `[]` | Extra `--policy-dir` directories. |
| `policies.disable` | []string | `[]` | Policy `metadata.name` values to skip. |
| `policies.builtin` | bool | `true` | Set `false` to run only custom policies. |
| `output.json` / `output.markdown` | string | `findings.json` / `report.md` | Output paths. |
| `output.failOn` | severity | `high` | `none` disables the CI exit-code gate. |
| `output.template` | string | `""` | Custom `report.md.tpl` path; empty uses the embedded default. See [Report Templates]({{ '/report-templates/' | relative_url }}). |
| `compliance.frameworks` | []string | `[cis]` | Which framework(s) to score against; see [Compliance Frameworks]({{ '/compliance/' | relative_url }}). |
| `disableBuiltinExceptions` | bool | `false` | `--no-builtin-exceptions` on the CLI. Disables all of this tool's built-in PSS exceptions for well-known privileged infrastructure (Cilium's agent, prometheus-node-exporter, kube-proxy, static control-plane pods) — see [Third-Party Operators: Built-in exceptions]({{ '/third-party-operators/#built-in-exceptions-for-privileged-system-infrastructure' | relative_url }}). |
| `disableBuiltinExceptionIds` | []string | `[]` | `--disable-builtin-exception-id` on the CLI (repeatable). Disables one built-in exclusion rule by id, leaving the rest active. |
| `components.extra` | []Component | `[]` | Config-file only. Adds your own components to the Detected Components inventory/orphan-detection — same schema as `internal/thirdparty/components.yaml`. See [Third-Party Operators: Component inventory]({{ '/third-party-operators/#component-inventory-internalthirdparty' | relative_url }}). |

See [`examples/audit.yaml`](https://github.com/{{ site.repository }}/blob/main/examples/audit.yaml)
in the repo for this same file with inline comments.

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

  # Namespaces to skip entirely, regardless of mode. Defaults to these
  # platform-managed namespaces (see Getting Started: Noise reduction) since
  # their workloads/RBAC are Kubernetes/CNI/CSI internals, not actionable
  # findings. Ignored if `namespaces` above is a non-empty allowlist. Set
  # to [] to audit everything, including kube-system.
  excludeNamespaces:
    - kube-system
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

# Waivers for specific (check, resource) pairs — an accepted, documented
# risk, not a silent gap. Config-file only (no CLI flag: a rule has too many
# structured fields to fit one). Suppressed findings are never dropped: they
# still get computed normally, then set aside with their reason preserved
# in the report ("Suppressed Findings" section, findings.json's
# `suppressed` array) — excluded only from Summary counts, --fail-on, CSV
# export, and compliance scorecards.
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
```

## Field reference

| Field | Type | Default | Notes |
|---|---|---|---|
| `target.mode` | `cluster\|static\|both` | `both` | `static` is auto-selected if `-f` is passed without an explicit `--mode`. |
| `target.context` | string | current context | Kube context for cluster mode. |
| `target.allNamespaces` / `target.namespaces` | bool / []string | `true` / `[]` | An explicit `namespaces` allowlist disables `excludeNamespaces`. |
| `target.paths` | []string | `[]` | Static manifest files/directories (`static`/`both` mode). |
| `target.excludeNamespaces` | []string | `[kube-system, kube-public, kube-node-lease]` | See [Getting Started: Noise reduction]({{ '/getting-started/#noise-reduction' | relative_url }}). |
| `target.includeSystemRBAC` | bool | `false` | Include `system:`-prefixed RBAC objects. |
| `target.includeKinds` / `target.excludeKinds` | []string | `[]` | Filter which resource kinds are fetched in cluster mode. |
| `policies.dirs` | []string | `[]` | Extra `--policy-dir` directories. |
| `policies.disable` | []string | `[]` | Policy `metadata.name` values to skip. |
| `policies.builtin` | bool | `true` | Set `false` to run only custom policies. |
| `output.json` / `output.markdown` | string | `findings.json` / `report.md` | Output paths. |
| `output.failOn` | severity | `high` | `none` disables the CI exit-code gate. |
| `output.template` | string | `""` | Custom `report.md.tpl` path; empty uses the embedded default. See [Report Templates]({{ '/report-templates/' | relative_url }}). |
| `compliance.frameworks` | []string | `[cis]` | Which framework(s) to score against; see [Compliance Frameworks]({{ '/compliance/' | relative_url }}). |

See [`examples/audit.yaml`](https://github.com/{{ site.repository }}/blob/main/examples/audit.yaml)
in the repo for this same file with inline comments.

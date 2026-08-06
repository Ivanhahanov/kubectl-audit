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

compliance:
  # Requirement framework(s) to score against: cis|fstec|nsa (see
  # compliance-mappings/ for the full list), or a path to a custom mapping
  # YAML. --frameworks on the CLI (scan only) overrides this.
  frameworks:
    - cis
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

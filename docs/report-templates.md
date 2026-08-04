---
layout: default
title: "Report Templates"
permalink: /report-templates/
---

# Customizing `report.md`

`report.md` is rendered from a Go [`text/template`](https://pkg.go.dev/text/template), not
hardcoded Go string-building. The built-in template lives at
[`internal/report/templates/default.md.tpl`](https://github.com/{{ site.repository }}/blob/main/internal/report/templates/default.md.tpl)
and is embedded into the binary; `--report-template <file>` (or `output.template` in
`audit.yaml`) fully replaces it with your own.

{% raw %}
## Getting started

```sh
# Write the built-in template to disk as a starting point
kubectl audit template dump --out report.md.tpl

# Edit it, then use it
kubectl audit scan --report-template report.md.tpl
```

Because a custom template fully replaces the default, you're free to restructure everything —
drop sections you don't care about, reorder them, add your own headers/branding, or emit a
completely different format (as long as it's valid Go template syntax; the output doesn't
actually have to be Markdown).

## Data available to the template

The template executes against a `report.TemplateData` value:

| Field | Type | Notes |
|---|---|---|
| `.GeneratedAt` | `time.Time` | Use `{{ rfc3339 .GeneratedAt }}` or call `.Format` directly. |
| `.Target` | `string` | e.g. `cluster:my-context` or `static:./manifests`. |
| `.PoliciesLoaded` | `int` | |
| `.SeverityOrder` | `[]findings.Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, in that order. |
| `.Summary` | `map[Severity]int` | Index with `{{ index .Summary . }}` inside a `range .SeverityOrder`. |
| `.TotalFindings` | `int` | |
| `.Findings` | `[]findings.Finding` | All findings, sorted most-severe first. |
| `.FindingsBySeverity` | `[]report.SeverityGroup` | Pre-grouped: `{Severity, Findings}` per non-empty severity bucket. |
| `.Frameworks` | `[]compliance.Scorecard` | One entry per `--frameworks` value, each with `.ID`, `.Title`, `.Version`, `.Results`. |
| `.ConsolidatedSummary` | `[]compliance.FrameworkSummary` | Pass/fail/N-A/not-implemented counts per framework. |
| `.RBACModel` | `[]rbac.SubjectModel` | Per-subject effective permissions + risk flags. |

A `compliance.ControlResult` (inside `.Frameworks[].Results`) has `.Control` (`ID`, `Title`,
`Section`, `Applicable`, `NAReason`, `Note`, `CrossRefs`), `.Status`, `.FindingIDs`, `.Resources`,
and `.Findings` (only populated when `.Status` is `FAIL`).

## Template functions

| Function | Signature | Purpose |
|---|---|---|
| `escapeCell` | `(s string) string` | Escapes `\|` and newlines for a Markdown table cell. |
| `orDash` | `(s string) string` | Returns `"-"` for an empty string, else `s`. |
| `join` | `(elems []string, sep string) string` | `strings.Join`, argument order matches template call syntax. |
| `rfc3339` | `(t time.Time) string` | RFC3339-formatted timestamp. |
| `bindingLabels` | `(bindings []rbac.BindingRef) []string` | Deduped `"Kind/Name"` labels for an RBAC role-model row. |
| `crossRefs` | `(c compliance.Control) string` | Formats `c.CrossRefs` as e.g. `"CIS: 5.2.4, 5.7.3"`. |
| `failingControls` | `(sc compliance.Scorecard) []compliance.ControlResult` | Filters a scorecard's results to `FAIL` only. |
| `statusNotes` | `(sc compliance.Scorecard) []string` | Pre-formatted `NAReason`/`Note` bullet lines for a scorecard's `NOT_APPLICABLE`/`NOT_IMPLEMENTED` rows. |

## Example: a minimal custom template

```gotemplate
# Audit of {{ .Target }}

{{ .TotalFindings }} finding(s) as of {{ rfc3339 .GeneratedAt }}.

{{ range .FindingsBySeverity }}
## {{ .Severity }}
{{ range .Findings }}- {{ .Resource.String }}: {{ .Message }}
{{ end }}{{ end }}
```

Save it and run `kubectl audit scan --report-template minimal.md.tpl` — `report.md` will contain
only this, nothing else from the default template.
{% endraw %}

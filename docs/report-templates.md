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

The default template's "Findings" section actually renders through `.FindingsBySeverity[].Checks`
(`[]report.CheckGroup`, one per policy ID within a severity), not `.Findings`/`.FindingsBySeverity`
directly — grouping by check hoists each policy's title/remediation/CIS refs out to render once
instead of once per affected resource. `.Title`/`.Category`/`.Remediation` on a `CheckGroup` already
have any `triage.knowledgeBaseFile` override applied (see [Knowledge
base]({{ '/triage/#knowledge-base-your-organizations-own-ticket-content' | relative_url }})) — one
knowledge base, same content in triage, Jira, and the report.

Each `CheckGroup` buckets its findings again by message (`.MessageGroups`, `[]report.MessageGroup`:
`.Message`, `.Rows`) — findings whose message is identical after stripping their own resource
name/namespace, or that share an analyzer-provided `DedupKey` (see `findings.Finding.DedupKey`),
land in the same bucket and get their own `_message_` line instead of repeating it once per
resource. Within a bucket, findings sharing a Kind and a "name shape" — either an identical literal
Name, or (with `output.groupByNamePattern`, on by default) names that only differ in a
generated-identifier segment (a UUID, or another long hex/digit run) — appearing at least
`output.namespaceGroupThreshold` times (default `3`; see [Noise
reduction]({{ '/getting-started/#noise-reduction' | relative_url }})) collapse into one
`report.AffectedRow` per `.Rows` — either `.Finding` (a normal `findings.Finding`) or `.Repeat` (a
`report.RepeatGroup`: `.Kind`, `.NameTemplate`, `.Unit`, `.Count`, `.Examples` capped at 8,
`.Truncated`). `CheckGroup.Collapsible` is true once a check has more than 8 findings total — the
default template wraps that check's Affected resources in `<details>` (or `{expand}` in the
Confluence template below) so a check that fires on many resources doesn't push everything below it
off screen, without dropping any row. See
[`CheckGroup`/`MessageGroup`/`AffectedRow`/`RepeatGroup` in `internal/report/template.go`](https://github.com/{{ site.repository }}/blob/main/internal/report/template.go)
for the full field list if you're customizing that part of the template.

## Template functions

| Function | Signature | Purpose |
|---|---|---|
| `escapeCell` | `(s string) string` | Escapes `\|` and newlines for a table cell (Markdown or Confluence — both use `\|` as the escape). |
| `orDash` | `(s string) string` | Returns `"-"` for an empty string, else `s`. |
| `join` | `(elems []string, sep string) string` | `strings.Join`, argument order matches template call syntax. |
| `minus` | `(a, b int) int` | `a - b` — used for "(+N more)" truncation counts. |
| `rfc3339` | `(t time.Time) string` | RFC3339-formatted timestamp. |
| `slug` | `(s string) string` | Lowercase, anchor-safe id, e.g. for `<a id="...">`. Markdown template only — Confluence's `{toc}` macro builds its own navigation, see below. |
| `bindingLabels` | `(bindings []rbac.BindingRef) []string` | Deduped `"Kind/Name"` labels for an RBAC role-model row. |
| `crossRefs` | `(c compliance.Control) string` | Formats `c.CrossRefs` as e.g. `"CIS: 5.2.4, 5.7.3"`. |
| `detectedVia` | `(d thirdparty.Detection) string` | Formats why a component was detected (CRD group / label match, with counts). |
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

## Russian report template

`--report-lang ru` (or `output.reportLang: ru`) switches the built-in Markdown template to
`internal/report/templates/ru.md.tpl` — the same structure and anchors as `default.md.tpl`,
with the report's own headings/labels ("Категория", "Рекомендация", "Затронутые ресурсы", ...)
in Russian instead of English. This is one static translated template, not a general i18n
system — it only changes the surrounding skeleton.

A finding's own Title/Message/Remediation stay whatever language the policy/analyzer that
produced it uses, unless a knowledge base overrides them (see [Knowledge
base]({{ '/triage/#knowledge-base-your-organizations-own-ticket-content' | relative_url }})) —
the bundled default knowledge base is already written in Russian, so `--report-lang ru` with no
other configuration already gives fully Russian check titles/remediations, not just the
skeleton. Ignored when `--report-template` is set — same precedent as everywhere else a custom
template fully replaces a built-in one.

```sh
kubectl audit scan --report-lang ru
# or dump it as a starting point to customize:
kubectl audit template dump --format ru --out report.ru.md.tpl
```

## Confluence output

`--output-confluence <file>` (or `output.confluence` in `audit.yaml`) writes the same report as
**Confluence Server/Data Center wiki markup** — `h2.` headings, `||table||` headers, `{expand}`
collapsible sections, `[text|url]` links — ready to paste straight into a Confluence page. This
targets Server/Data Center's wiki markup specifically; Confluence **Cloud** uses a different
format (Storage Format/ADF) and isn't supported.

The built-in template lives at
[`internal/report/templates/confluence.tpl`](https://github.com/{{ site.repository }}/blob/main/internal/report/templates/confluence.tpl),
embedded the same way as `default.md.tpl`, and executes against the exact same
`report.TemplateData` — only the template text and function set differ. `--confluence-template
<file>` (or `output.confluenceTemplate`) fully replaces it, same as `--report-template` does for
Markdown.

```sh
kubectl audit template dump --format confluence --out confluence.tpl
kubectl audit scan --confluence-template confluence.tpl --output-confluence report.confluence
```

The Confluence function set is the same as Markdown's above, minus `slug` (unneeded — paste the
`{toc:maxLevel=3}` macro near the top and Confluence builds its own navigation from the page's
headings) and plus one Confluence-only addition:

| Function | Signature | Purpose |
|---|---|---|
| `severityStatus` | `(s findings.Severity) string` | A `{status:colour=...\|title=...}` macro — a colour-coded lozenge next to each severity heading. No Markdown equivalent. |

One caveat: `Message`/`Remediation` text that a policy or knowledge-base entry wrote assuming a
Markdown renderer (a hand-written `` `code` `` or `[text](url)`) renders as literal text in
Confluence output, not converted — same as pasting Markdown-authored text into a Jira Server/DC
description (see [Triage > Markdown vs. wiki
markup]({{ '/triage/' | relative_url }})). Write check/knowledge-base free text in wiki markup if
Confluence output matters to you, or keep it plain (no inline formatting) so it reads fine either way.
{% endraw %}

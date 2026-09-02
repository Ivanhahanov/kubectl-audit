---
layout: default
title: "Triage"
permalink: /triage/
---

# Triage: from findings to what actually needs fixing

A `scan` against a real cluster — especially a large, multi-tenant one — commonly produces
hundreds or thousands of findings. `kubectl audit triage` is a separate, interactive step for a
human expert to work through that list by hand: mark each finding confirmed / false positive /
won't fix / duplicate / needs more info, attach notes, and end up with a filtered
"what actually needs fixing" list — one that can be exported or pushed into Jira as tickets.

**`findings.json`/CSV stay unaffected by anything triage does.** Triage state is a separate file
(`triage-state.yaml` by default) that's *joined* with the latest scan's findings when you open the
tool — it never edits or filters `findings.json` itself. `--fail-on` gating and any other tooling
that reads `findings.json` directly always sees every finding, untouched.

{% raw %}
## Verification steps

Every bundled check — every policy YAML and every native Go analyzer — carries a
`audit.k8s-auditor.io/verification-steps` field (see [Writing Policies](/writing-policies/)):
concrete, numbered instructions for confirming a finding is a true positive in your specific
environment, distinct from `remediation` (which assumes it's already confirmed). This is the whole
reason `triage` exists as a separate step from `scan`: a static-analysis tool can flag "this
Ingress has no `spec.tls`," but only a human who knows whether that Ingress is actually
internet-reachable can decide how urgent that really is. Recorded in `findings.json`
(`verificationSteps`) for other tooling to use; not currently shown in the triage TUI or filed
tickets, which stay focused on Title/Description/Remediation (see [Knowledge
base](#knowledge-base-your-organizations-own-ticket-content)).

## Getting started

```sh
kubectl audit scan --output-json findings.json
kubectl audit triage
```

`triage` opens an interactive TUI over `findings.json`, using (and creating, if it doesn't exist
yet) `triage-state.yaml` next to it. Both paths are configurable — see [Configuration](#configuration)
below.

## The TUI

A k9s-style table: one row per finding by default, columns for severity, status, policy ID, kind,
namespace/name, and a COUNT column. Press `enter` on a row for the full detail view (title,
description, CIS refs, and remediation — exactly what filing a Jira ticket for this finding would
contain, knowledge-base override included; see [Knowledge
base](#knowledge-base-your-organizations-own-ticket-content)).

| Key | Action |
|---|---|
| ↑/↓, pgup/pgdn (or arrows) | move |
| `enter` | open finding detail — `y` copies it to the clipboard, `v` toggles a Jira ticket preview (project/issue type/summary/description/labels/custom fields, exactly what `j` would send — a real check for a custom summaryTemplate/descriptionTemplate); `c`/`x`/`w`/`d`/`i`/`n`/`j`/`space`/`0` (below) all work from there too, no need to close back to the table first |
| `/` | live-filter (substring match over title/policy ID/resource/message) |
| `r` | toggle collapsing repeated findings on/off (**off** by default — see below) |
| `g` | on a collapsed row: expand it to review each individual finding; press again to re-collapse |
| `s` | isolate the table to every finding in this row's namespace, across every check and kind — for reviewing one tenant/system end-to-end |
| `p` | policy stats: every check with severity/count/new/confirmed, sorted by count by default (`1`-`6` to sort by another column, again to reverse); enter on one to filter the table to just that policy |
| `space` | mark/unmark the current row (its whole collapsed group, if collapsed) |
| `a` | mark every row currently visible |
| `1`-`6` | sort by that column (press again to reverse direction) |
| `c` / `x` / `w` / `d` / `i` | confirmed / false positive / won't fix / duplicate / needs more info — applied to every marked row, or the selection if nothing's marked (and every finding a collapsed row stands for) |
| `0` | reset back to `new` — undo a previous `c`/`x`/`w`/`d`/`i` (same bulk-apply rule) |
| `n` | edit note (same bulk-apply rule) |
| `j` | create a Jira ticket for every marked/selected CONFIRMED finding without one yet |
| `u` | show/hide suppressed findings (hidden by default) |
| `q` | save and quit |
| `?` | help |
| `esc` | clear filter/marks, then group-expand, then system-isolate, in that order |

State autosaves after every action — a crash loses at most the one edit in progress, not prior
decisions. Anything that would touch more than one finding at once (a triage decision, a note
edit, filing Jira tickets — whether from marking several rows or from one collapsed row) asks
"Yes / Cancel" first, with the affected count shown, before it happens — nothing bulk-applies
silently.

### Noise reduction: collapsing repeated findings

The same check commonly fires many times — on every tenant's copy of a Deployment, on every
Namespace missing a label, on every ServiceAccount with the same broad RBAC grant. Pressing `r`
collapses those into a single row with a `×N` COUNT whenever a check's message is **identical**
for every one of its findings — proof the message has no per-resource detail baked in, so
collapsing is lossless (e.g. `workload.run-as-non-root` firing on 19 differently-named Deployments
with the exact same message). A check whose message embeds resource-specific detail (RBAC/PSS/
network-policy analyzers that describe exactly what's wrong per resource — different
ServiceAccount, different namespace, different rule) never collapses, no matter how many times it
fires — collapsing it would hide that detail. Collapsing only groups within one check; it never
merges findings from different checks together, even on the same resource.

This is **off by default** and stays session-only (never persisted) — you always start seeing
every finding as its own row, and opt into collapsing explicitly once you trust it for a given
review session. Acting on a collapsed row — marking it, applying a triage decision, editing its
note/tags, filing a Jira ticket — transparently applies to every finding it stands for, not just
the one shown, and (per the confirmation rule above) always asks first when more than one finding
is affected. Press `g` on a collapsed row to drill into its individual members instead, if you
want to review each one by hand.

The collapse threshold is `output.namespaceGroupThreshold` — the same config value (default 3)
[`scan`'s Markdown report already uses](/configuration/) for the identical purpose, so both mean
the same thing.

### Investigating one system

Press `s` on any row to isolate the table to every finding in that row's namespace, across every
check and resource kind — useful for reviewing one tenant/application end-to-end rather than one
check at a time. This bypasses collapsing (deliberately exhaustive), and is independent of it —
press `s` again (or `esc`) to return to the normal view.

### Resolved findings

If a finding you previously triaged no longer appears in the latest scan, it shows up with status
`resolved` instead of silently disappearing — the underlying issue was presumably fixed (or the
resource deleted). This is computed automatically every time `triage`/`export` loads state
against a fresh `findings.json`.

## Non-interactive export

```sh
kubectl audit triage export --status confirmed > confirmed.json
```

Dumps triage-joined findings (optionally filtered by `--status`) as JSON — useful for handing a
reviewed list to another tool or process without needing Jira at all.

## Jira sync

```sh
kubectl audit triage jira-sync \
  --jira-url https://jira.example.com --project SEC --issue-type Bug \
  --jira-token "$KUBECTL_AUDIT_JIRA_TOKEN"
```

Reads triage state for every `confirmed` finding that doesn't have a Jira issue yet, and — by
default — **previews** what it would create (`--dry-run` defaults to `true`; pass
`--dry-run=false` to actually create issues). Each created issue's key and URL are written back
into `triage-state.yaml`, so re-running `jira-sync` never double-creates: a finding with a
recorded `jiraIssueKey` is simply skipped.

This targets **Jira Server/Data Center** (`/rest/api/2/issue`, Bearer Personal Access Token
auth) — not Jira Cloud, which uses a different auth scheme and API version.

Issue content by default: summary from the finding's title/severity/resource; description includes
the message, remediation, CIS refs, your triage note, and a back-link (`kubectl-audit finding:
<id>`) for traceability; labels from severity, category, and this check's own knowledge-base
labels (see [Knowledge base](#knowledge-base-your-organizations-own-ticket-content)). Every piece of this is
customizable from `audit.yaml` alone — see below — no rebuild ever needed. Verification steps are
deliberately **not** part of the ticket — they're guidance for the analyst deciding whether to
confirm a finding in the first place (see [Verification steps](#verification-steps)), not something
the person who receives the ticket needs.

**The Jira token never belongs in `audit.yaml`** — it's a git-committable file, same as everything
else this tool reads config from. Pass `--jira-token`, or set `KUBECTL_AUDIT_JIRA_TOKEN`.

### Custom fields, extra labels, and a fully custom template

Your Jira project may need its own required fields, its own labels, or a differently structured
ticket — all `triage.jira` config, read fresh on every run:

```yaml
triage:
  jira:
    baseUrl: https://jira.example.com
    projectKey: SEC
    issueType: Bug
    # Static labels added to every created issue, beyond the auto-derived
    # severity/category/tag ones.
    extraLabels:
      - platform-team
    # Merged into every created issue's Jira fields, keyed by Jira field ID.
    # A string value is rendered as a Go template (same data as the
    # summary/description templates below); any other value (a number,
    # bool, or an object like {value: Prod} for a select-list field) is
    # sent as-is.
    customFields:
      customfield_10010: "severity={{.Finding.Severity}}"
      customfield_10020:
        value: Prod
    # Paths to external Go text/template files that fully replace the
    # built-in summary/description structure. Empty (the default) uses
    # the built-in template.
    summaryTemplate: /path/to/summary.tpl
    descriptionTemplate: /path/to/description.tpl
```

Get a starting point to restructure with:

```sh
kubectl audit triage jira template dump --kind summary --out summary.tpl
kubectl audit triage jira template dump --kind description --out description.tpl
```

Both templates render against `{{.Content}}` (`Title`/`Description`/`Remediation`/`Technical` —
the *resolved* content, already reflecting any knowledge-base override below; prefer these over
the raw `{{.Finding.*}}` fields so a custom template automatically stays in sync with a
knowledge-base override the same way the default template does), `{{.Finding}}` (the full finding
— `Severity`, `CIS`, `Resource`, `ID`, `PolicyID`, `Source`, ...), and `{{.Entry}}` (the triage
record — `Note`, ...). Edit the dumped file however you like —
`triage.jira.summaryTemplate`/`descriptionTemplate` just needs to point at it; the file is read
fresh on every `jira-sync`/TUI `j` run, so no rebuild or reinstall is ever required.

### Knowledge base: your organization's own ticket content

**On by default, no configuration needed**: every built-in check ships with a Russian
title/description/remediation, applied automatically to every Jira ticket and the triage TUI's
detail view (`enter`) — `what you preview is exactly what gets filed`, there's no separate "ticket
mode" to second-guess. Inspect the bundle with:

```sh
kubectl audit triage knowledge-base dump
```

To correct one entry, or add your organization's own internal standard/house style for a check
(built-in or your own), point `triage.knowledgeBaseFile` at a small file with just the entries you
want to change — it's merged on top of the bundle, field by field, so you never repeat the rest:

```yaml
triage:
  knowledgeBaseFile: knowledge-base.yaml
```

```yaml
# knowledge-base.yaml — keyed by PolicyID, any field you don't set keeps
# the bundled/tool default for it. Each field is a Go template rendered
# against {{.Finding}} (same data shape as triage.jira.customFields), so
# it can reference the specific resource a finding fired on instead of
# only generic, check-level text.
rbac-analyzer.broad-secrets-access:
  title: "[Internal standard] Overly broad Secrets access"
  description: >-
    ServiceAccount {{.Finding.Resource.Name}} in {{.Finding.Resource.Namespace}} has cluster-wide
    Secrets access, which our internal security standard SEC-042 restricts to the security-team
    role. Open a review request per the SEC-042 process before granting an exception.
  remediation: "File a review request with security-team per SEC-042 for {{.Finding.Resource.Name}}."
  labels:
    - sec-042
```

A field with no `{{ }}` in it round-trips unchanged — templating is opt-in per field, not
required. A malformed template in one field is reported (in the TUI detail view, and as a
render error for `jira-sync`) without blocking the other fields from still resolving.

`labels` are this check's own Jira labels — merged with the auto-derived severity/category labels
and `triage.jira.extraLabels`, sanitized the same way. Org-defined and the same for every finding
this check produces — an internal compliance requirement id, for example — not templated (unlike
the text fields above; a Jira label is a short fixed slug).

This is deliberately **not a translation mechanism** — `Message` (the tool's own, sometimes
per-resource, technical text — e.g. exactly which ServiceAccount and binding are involved) is
never overridden. When a knowledge-base entry sets `description`, the original `Message` still
shows in the ticket as a separate "Technical detail" section, so the org's own explanation never
hides the specific detail needed to actually act on the finding. `message` can be — and for
built-in checks, is — in any language you like; only the surrounding scaffolding
("Remediation:", "Technical detail:") comes from the template, in whatever language you wrote it.

**Writing your own policy?** Skip the external file and write your knowledge base directly in the
policy — `audit.k8s-auditor.io/kb-title`, `.../kb-description`, `.../kb-remediation` alongside the
existing English annotations (see [Writing Policies](./writing-policies/)). One file, no separate
entry needed. If a policy sets these *and* `knowledgeBaseFile` also has an entry for the same
PolicyID, the file wins, field by field — the one case these two mechanisms overlap; day to day
you'll only ever use one or the other for a given check.

## Configuration

```yaml
triage:
  # Where triage decisions are persisted — a local, git-diffable YAML file.
  stateFile: triage-state.yaml
  # Your organization's own ticket content — see "Knowledge base" above.
  knowledgeBaseFile: knowledge-base.yaml
  jira:
    baseUrl: https://jira.example.com
    projectKey: SEC
    issueType: Bug
    # No token field here — see above.
    # extraLabels/customFields/summaryTemplate/descriptionTemplate: see
    # "Custom fields, extra labels, and a fully custom template" above.
```

`--findings`/`--state` (persistent flags on `triage`, `triage export`, and `triage jira-sync`)
override `output.json`/`triage.stateFile` from `audit.yaml` for a single invocation, the same
pattern every other path-related flag in this tool follows.
{% endraw %}

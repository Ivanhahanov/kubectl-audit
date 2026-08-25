---
layout: default
title: "Triage"
permalink: /triage/
---

# Triage: from findings to what actually needs fixing

A `scan` against a real cluster — especially a large, multi-tenant one — commonly produces
hundreds or thousands of findings. `kubectl audit triage` is a separate, interactive step for a
human expert to work through that list by hand: mark each finding confirmed / false positive /
won't fix / duplicate / needs more info, attach notes and tags, and end up with a filtered
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
internet-reachable can decide how urgent that really is.

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
namespace/name, a COUNT column, and tags. Press `enter` on a row for the full detail view
(message, remediation, CIS refs, and — most importantly — the verification steps).

| Key | Action |
|---|---|
| ↑/↓, pgup/pgdn (or arrows) | move |
| `enter` | open finding detail |
| `/` | live-filter (substring match over title/policy ID/resource/message) |
| `r` | toggle collapsing repeated findings on/off (**off** by default — see below) |
| `g` | on a collapsed row: expand it to review each individual finding; press again to re-collapse |
| `s` | isolate the table to every finding in this row's namespace, across every check and kind — for reviewing one tenant/system end-to-end |
| `space` | mark/unmark the current row (its whole collapsed group, if collapsed) |
| `a` | mark every row currently visible |
| `1`-`7` | sort by that column (press again to reverse direction) |
| `c` / `x` / `w` / `d` / `i` | confirmed / false positive / won't fix / duplicate / needs more info — applied to every marked row, or the selection if nothing's marked (and every finding a collapsed row stands for) |
| `0` | reset back to `new` — undo a previous `c`/`x`/`w`/`d`/`i` (same bulk-apply rule) |
| `n` | edit note (same bulk-apply rule) |
| `t` | edit tags, comma-separated (same bulk-apply rule) |
| `j` | create a Jira ticket for every marked/selected CONFIRMED finding without one yet |
| `u` | show/hide suppressed findings (hidden by default) |
| `q` | save and quit |
| `?` | help |
| `esc` | clear filter/marks, then group-expand, then system-isolate, in that order |

State autosaves after every action — a crash loses at most the one edit in progress, not prior
decisions. Anything that would touch more than one finding at once (a triage decision, a note/tags
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
the message, remediation, verification steps, CIS refs, your triage note, and a back-link
(`kubectl-audit finding: <id>`) for traceability; labels from severity, category, and your tags.
Every piece of this is customizable from `audit.yaml` alone — see below — no rebuild ever needed.

**The Jira token never belongs in `audit.yaml`** — it's a git-committable file, same as everything
else this tool reads config from. Pass `--jira-token`, or set `KUBECTL_AUDIT_JIRA_TOKEN`.

### Custom fields, extra labels, and a fully custom template (e.g. a different language)

Your Jira project may need its own required fields, its own labels, or issue text in a different
language than the built-in English default — all three are `triage.jira` config, read fresh on
every run:

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
    # built-in summary/description — write your own in any language.
    # Empty (the default) uses the built-in English template.
    summaryTemplate: /path/to/summary-ru.tpl
    descriptionTemplate: /path/to/description-ru.tpl
```

Get a starting point to translate or restructure with:

```sh
kubectl audit triage jira template dump --kind summary --out summary-ru.tpl
kubectl audit triage jira template dump --kind description --out description-ru.tpl
```

Both templates render against `{{.Finding}}` (the full finding — `Title`, `Severity`, `Message`,
`Remediation`, `VerificationSteps`, `CIS`, `Resource`, `ID`, `PolicyID`, `Source`, ...) and
`{{.Entry}}` (the triage record — `Note`, `Tags`, ...). Edit the dumped file however you like —
`triage.jira.summaryTemplate`/`descriptionTemplate` just needs to point at it; the file is read
fresh on every `jira-sync`/TUI `j` run, so no rebuild or reinstall is ever required.

## Configuration

```yaml
triage:
  # Where triage decisions are persisted — a local, git-diffable YAML file.
  stateFile: triage-state.yaml
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

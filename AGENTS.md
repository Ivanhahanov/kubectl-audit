# AGENTS.md

Instructions for any AI coding agent (Claude Code, Codex, or similar) working in this repository.
Read this file in full before making changes. It's deliberately short — the goal is a few hard
rules plus pointers to the real documentation, not a restatement of it.

## What this is

`kubectl-audit` is a Kubernetes security audit tool. Two binaries, deliberately split:

- **`cmd/kubectl-audit`** (`kubectl audit ...`) — self-service/CI scanning: policy checks, RBAC
  analysis, NetworkPolicy coverage, compliance scoring. No TUI, no Jira client — keep it that way;
  don't add a dependency here that only a triage workflow needs.
- **`cmd/kubectl-triage`** (`kubectl triage ...`) — reviewing a scan's `findings.json`: the
  interactive TUI, Jira sync, knowledge base. Depends on `internal/triage` (tcell/tview, a Jira
  client) — those stay out of the audit binary's dependency graph.

Both import `internal/cli` (shared cobra command plumbing) — see the README's Architecture
section for the full package map.

## Before you start: find the right doc, don't guess

This repo documents its own conventions in `docs/*.md` — read the relevant one before writing
code that touches that area, rather than inferring the pattern from one example file:

- Adding or editing a security check (VAP policy or native Go analyzer), or a compliance mapping
  entry → **read and follow `.claude/skills/add-security-check/SKILL.md` end to end first.** This
  is not optional context; it encodes a real mistake (a wrongly-mapped compliance control) that
  shipped and had to be corrected later in this project's history. The short version: never map a
  check to a standard's control based on a paraphrase or memory — always verify against the
  standard's actual source text.
- Writing a VAP policy's CEL → `docs/writing-policies.md`.
- A custom/private policy or compliance mapping (org-specific, not a published standard) →
  `docs/custom-checks.md` — these do **not** go in this repo's bundled `policies/`/
  `compliance-mappings/`.
- Report/output rendering (`--output format=path`) → `internal/report/*.go`; each writer
  (`json.go`, `markdown.go`, `csv.go`, `confluence.go`, `console.go`, `table.go`) has a doc
  comment stating what it's for and, as importantly, what it deliberately *doesn't* do.
- Config schema/CLI flag precedence → `internal/config/config.go`'s doc comments explain the
  `*bool` vs `bool` convention (a `*bool` field exists specifically where "not set" must be
  distinguishable from "explicitly false/true" — follow that pattern for any new tri-state
  option, don't just add a plain `bool`).

## Hard rules

1. **Never invent a compliance citation.** A CIS/FSTEC/NSA/private-standard control reference
   must trace to that standard's actual text, checked directly — not inferred from a policy's
   title or a mapping file's own paraphrase. See the skill above.
2. **Run the verification gate before calling anything done**: `go build ./... && go vet ./... &&
   go test ./...`. This repo has no CI (`.github/` is empty) — these commands run locally are the
   only gate there is.
3. **No new external dependencies without strong justification.** This project prefers hand-built
   YAML-as-`map[string]any` (see `internal/kyverno/convert.go`) over pulling in another package's
   full type system when only a structural reshape is needed. If a dependency is already
   transitively present (check `go.sum`), promoting it to direct (`go mod tidy`) is fine; adding a
   brand new one is a decision to flag to the user first.
4. **Don't add a flag, a config field, or an output mode "while you're in there."** Every flag in
   this CLI was added for a specific, stated reason and is documented in both `--help` text and
   the README. Match that bar for anything new — including updating the README.
5. **Comments explain *why*, never *what*.** Default to no comment; add one only for a non-obvious
   constraint, invariant, or the reason behind a design choice a reader would otherwise have to
   reverse-engineer (this entire codebase is written this way — look at any existing file before
   adding a new one to match the register).
6. **Don't restate this file's content in docs/*.md or vice versa.** If you find yourself writing
   guidance that belongs in one of the docs above, put it there and reference it from here instead
   of duplicating it — two copies of the same rule drift apart.

## Claude Code specifically

Project skills live in `.claude/skills/`. `CLAUDE.md` is a symlink to this file — edit
`AGENTS.md`, not `CLAUDE.md`, so Codex and Claude Code never see different instructions.

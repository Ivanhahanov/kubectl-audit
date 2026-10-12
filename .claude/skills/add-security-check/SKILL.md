---
name: add-security-check
description: Use when adding, modifying, or reviewing a new security check (a VAP policy or a native Go analyzer check) for kubectl-audit, or when editing a compliance mapping (compliance-mappings/*.yaml or an internal-standards mapping) to reference one. Triggers on requests like "add a check for X", "write a policy that flags Y", "map this check to CIS/FSTEC/our standard".
---

# Adding a security check to kubectl-audit

This is the controlled procedure for adding a check — not a tutorial on CEL syntax (that's
[docs/writing-policies.md](../../../docs/writing-policies.md)) or the compliance-mapping schema
(that's [docs/custom-checks.md](../../../docs/custom-checks.md)). Read those two docs for the
"how"; this file is the "in what order, and what not to skip."

Work through every step below in order. Do not report the task done until the Verification
checklist at the end passes.

## 0. Decide where this check belongs — don't skip this

| Question | If yes |
|---|---|
| Does answering it require looking at only **one object's own fields**? | A VAP policy, `policies/<category>/*.yaml` — go to step 1. |
| Does it require **correlating multiple objects** (a Role + its Binding + the Subject; a Workload + every NetworkPolicy in its namespace; anything needing `authorizer.*`)? | A native Go analyzer (`internal/rbac`, `internal/netpol`, `internal/pss`, `internal/quota`, `internal/cni`, `internal/istio`, `internal/controlplane`, ...) — go to step 2. |
| Is this a genuine **org-specific convention** (a UID floor, an internal registry hostname, something your org decided, not backed by a published standard)? | It does **not** belong in this repo's bundled `policies/`/`compliance-mappings/` at all. Point the user at [docs/custom-checks.md](../../../docs/custom-checks.md) (`--policy-dir` + a private `--frameworks` mapping file, kept outside this checkout) instead of writing it here. Stop — the rest of this skill doesn't apply. |

Getting this wrong is the single most common mistake: a check that needs cross-object reasoning
written as a CEL policy either can't express it or silently matches the wrong thing.

## 1. VAP policy route

1. Write the YAML in `policies/<category>/<name>.yaml` (category = one of the existing directory
   names: `workload`, `rbac`, `network`, `controlplane`, `secrets`, or a `thirdparty/<vendor>/`
   subdirectory — do not invent a new top-level category without a reason, since
   `policies/embed.go`'s `//go:embed` pattern is hardcoded per directory and a new one needs that
   file updated too).
2. Follow [docs/writing-policies.md](../../../docs/writing-policies.md) for the CEL shape
   (remember the `has()` branching for Pod vs Deployment/StatefulSet/... vs CronJob — this is the
   #2 most common mistake: an expression that only handles bare Pods silently never fires on a
   Deployment).
3. Set **every** annotation in the table in that doc, not just the ones that feel essential:
   `title`, `severity`, `category`, `remediation`, `verification-steps`, and `cis` **only if** you
   have independently confirmed (see step 3 below) that a real CIS control covers this — never
   invent a plausible-looking CIS number.
4. `name: <category>.<kebab-case-id>` — this is `PolicyID` everywhere downstream (findings,
   compliance mappings, knowledge base keys). Pick it once; renaming later breaks any mapping/KB
   entry that references it.

## 2. Native Go analyzer route

1. Find the closest existing analyzer package (`internal/rbac/leastprivilege.go` for
   RBAC-shaped checks, `internal/netpol/*.go` for NetworkPolicy, etc.) and follow its exact
   `findings.Finding{PolicyID: ..., Severity: ..., Category: ..., Resource: ..., Message: ...,
   Remediation: ..., VerificationSteps: ...}` construction pattern — don't invent a different
   finding shape.
2. `PolicyID` convention: `<analyzer-name>.<kebab-case-id>` (e.g. `rbac-analyzer.broad-secrets-access`,
   `netpol-analyzer.no-egress-restriction`) — the dash-joined analyzer prefix is load-bearing: it's
   how `OverrideUnobservedByPrefix` and this skill's own compliance-mapping step find a check.
3. Wire the new analyzer function into `runScan` in `internal/cli/orchestrate.go` if it's a new
   package (not just a new check in an existing one) — see how `rbac.Analyze`, `netpol.Analyze`,
   etc. are each called and their findings appended to `all`.
4. There is no runtime registry of native check IDs (unlike VAP policies, which `policy list`
   enumerates) — a typo in a compliance mapping's `nativeCheckIds` is **not** caught by
   `warnUnknownPolicyIDs`. Triple-check the exact string against the Go source.

## 3. Mapping it to a compliance framework — the rule that matters most

**Never add a `policyIds`/`nativeCheckIds` entry to a control, or a `cis:` annotation value, based
on a paraphrased summary, a title that "sounds right," or memory of what a standard probably
says.** This produced real, shipped mapping errors earlier in this project's history that had to
be corrected in a dedicated review pass (see `internal-standards/compliance/security-requirements.yaml`'s
header comment for that incident). The rule, concretely:

1. Open the **actual source text** of the standard — for `compliance-mappings/cis.yaml`, that's
   the CIS Kubernetes Benchmark PDF/doc itself; for a private standard, that's its raw source file
   (e.g. a gitignored `.txt`/`.docx` the mapping YAML's header comment points at — check for one
   before assuming the YAML's own `title:` field is a reliable paraphrase).
2. Find the control's **exact wording**. Confirm the check you're adding is something that
   specific paragraph asks for — not just thematically related. ("Minimizes RBAC risk" is not the
   same claim as "forbids wildcard rules on secrets specifically.")
3. Only then add the ID to that control's `policyIds`/`nativeCheckIds` array (bundled framework:
   `compliance-mappings/<id>.yaml`; private standard: that standard's own mapping file — never put
   an org-private control in a bundled file, see docs/custom-checks.md).
4. If you're genuinely unsure whether a control's text covers the new check, leave it unmapped and
   say so explicitly in your summary to the user, rather than guessing. An unmapped check is a
   quiet gap; a wrongly-mapped one is a false compliance claim — the latter is worse.
5. When you do add a mapping, run the scan once with `--frameworks <that id>` and read the
   resulting `CONTROLS` column/scorecard to sanity-check it, rather than trusting the YAML diff
   alone.

## 4. Localization (bundled checks only)

Bundled policies' `title`/`remediation`/etc. are English by default but get Russian text at
render time from `internal/triage/knowledgebase/starter-ru.yaml` (keyed by the exact `PolicyID`) —
this is separate from a VAP policy's own `kb-*` annotations (those are for *custom/org* policies
that want to self-contain their ticket wording, per docs/writing-policies.md). For a new **bundled**
check, add a matching entry to `starter-ru.yaml` for consistency with every other bundled check —
not strictly required (the tool falls back to the English annotation text cleanly), but expected
for anything going into the shared bundle.

## 5. Tests

Follow the existing pattern in `internal/engine/*_test.go` (for VAP policies) or the analyzer
package's own `_test.go` (for native checks) — most bundled-policy tests build a minimal
offending object, run it through `engine.Compile`/`engine.EvaluateAll` (or the analyzer function
directly), and assert the expected finding fires with the expected severity. Add both:
- a **positive** case (the violating shape — the finding must fire), and
- a **negative** case if the check has any nuance (a compliant shape that must *not* fire) — this
  is what catches an overly broad CEL expression or Go condition.

## Verification checklist — do not report done until all of these pass

```sh
go build ./...
go vet ./...
go test ./...
# VAP policies only:
kubectl-audit policy validate ./policies    # or the specific category dir
kubectl-audit policy list | grep <your-policy-id>
# Exercise it end-to-end against a real manifest (write one under /tmp if
# examples/insecure-manifests doesn't already have a matching shape):
kubectl-audit scan -f <manifest-with-the-violation> --fail-on none --output console=-
```

If you touched a compliance mapping, also run `--frameworks <that-framework-id>` and read the
`CONTROLS` column in `--output table=-`/`console=-` to confirm the new check shows the control ID
you expect — not a `CIS: X.Y.Z` fallback citation you didn't intend (that fallback means the
mapping lookup found nothing; see `internal/report/template.go`'s `primaryStandard`).

This repo has no CI pipeline (`.github/` is empty) — `make test`/`make vet`/`make build` run
locally are the only gate. Running them yourself before calling the task done is not optional.

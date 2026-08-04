---
layout: default
title: "Custom Checks & Private Frameworks"
permalink: /custom-checks/
---

# Custom checks & private frameworks

kubectl-audit ships bundled policies and compliance mappings (CIS/FSTEC/NSA) grounded in public
standards — every rule has a citable source. Org-specific conventions (a UID floor, an approved
internal registry, a capability allowlist that doesn't come from any published standard) don't
belong in those bundled files, and internal requirement registries generally shouldn't be either.
This page is the mechanism for keeping all of that entirely outside this repository while still
scoring it through the exact same pipeline as the bundled frameworks.

Two independent pieces combine: your own [VAP policies]({{ '/writing-policies/' | relative_url }})
(`--policy-dir`) and your own compliance mapping (`--frameworks /path/to/it.yaml`).

## 1. Write your own policies

Nothing new here — see [Writing Policies]({{ '/writing-policies/' | relative_url }}). Put them in
a directory outside this repo, e.g. `~/security-standards/policies/`.

## 2. Write your own compliance mapping

Same schema as [`compliance-mappings/*.yaml`](https://github.com/{{ site.repository }}/tree/main/compliance-mappings)
(`id`, `title`, `version`, `controls: [...]`), pointing at your own policy IDs and using your own
control IDs (mirror your internal requirement registry's IDs directly if you have one — that's
exactly what `crossRefs` and `note` are for). Nothing needs to be embedded into the binary: any
`--frameworks` value containing `/` or `\`, or ending in `.yaml`/`.yml`, is read from disk instead
of looked up among the bundled `cis`/`fstec`/`nsa` frameworks — mix and match freely, e.g.
`--frameworks cis,fstec,~/security-standards/internal.yaml`.

```yaml
id: internal
title: "Example Internal Standard"
version: "1"
controls:
  - id: "ORG-01"
    title: "Containers run above the organization's UID/GID floor"
    section: "Workload hardening"
    applicable: true
    policyIds: ["org.runasuser-above-floor"]
    crossRefs:
      cis: ["5.2.7"]
    note: "Internal convention, not backed by a public standard."
```

Run it:

```sh
kubectl-audit scan \
  --policy-dir ~/security-standards/policies \
  --frameworks cis,~/security-standards/internal.yaml
```

Your control shows up in the report exactly like a CIS/FSTEC/NSA row — its own table, its own
entry in the consolidated summary, `crossRefs` rendered as a **Related controls** column pointing
back at CIS if you set one.

A full worked example (two custom policies + one custom mapping) lives in
[`examples/custom-framework/`](https://github.com/{{ site.repository }}/tree/main/examples/custom-framework) —
copy that directory out of the checkout as your starting point.

## Catching typos

A `policyId` that doesn't match any loaded policy doesn't error — `BuildScorecard` just never
finds a matching finding, and the control silently shows `PASS`. To catch this before it produces
a false sense of coverage, kubectl-audit warns on stderr for every `policyId` referenced in a
compliance mapping that isn't among the currently loaded policies (bundled + `--policy-dir`):

```
warning: compliance mapping "internal", control "ORG-01": policyId "org.runasuser-above-flor"
does not match any loaded policy (typo, or missing --policy-dir?) — this control will always show PASS
```

There's no equivalent check for `nativeCheckIds` — those come from Go-native analyzers
(`internal/rbac`, `internal/netpol`, `internal/controlplane`), which have no runtime registry to
validate against. If you need a check that requires cross-object reasoning (not just one object's
own fields — see [Writing Policies]({{ '/writing-policies/' | relative_url }})'s "RBAC and
NetworkPolicy checks aren't VAP policies" section), it isn't something you can add without writing
Go, and isn't what this mechanism is for.

## What this is (and isn't) for

Use this for anything that's a genuine org decision rather than a security-standard requirement:
a specific numeric threshold, an internal registry allowlist, a capability allowlist your org has
signed off on. If you find yourself grounding a custom check in a real external standard (a CIS
control, NIST SP 800-190, a FSTEC order) instead of "we decided this internally," consider opening
an issue or PR — that kind of check likely belongs in the bundled policies where every other
kubectl-audit user benefits from it too.

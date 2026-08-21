---
layout: default
title: "Secrets Mode"
permalink: /secrets-mode/
---

# Secrets mode (`--read-secret-values`)

Every check this tool ships by default works from ConfigMaps, CRD specs, or workload config alone —
it never reads a Secret's value (see [Required Permissions]({{ '/permissions/' | relative_url }})).
`--read-secret-values` unlocks three different kinds of analysis that structurally need to look at a
Secret's actual content, each with a different design and a different set of guarantees — read the
whole page before assuming this is a general-purpose secret scanner, because it deliberately isn't
one; see "What this does NOT do" at the bottom.

## What it does

- **Cluster mode**: fetches Secret objects from the API server (otherwise never requested at all —
  see `internal/loader/cluster.go`'s `secretsResource`).
- **Static-manifest (`-f`) mode**: lets any Secret object already present in a scanned manifest
  directory reach analysis. Without this flag, `internal/loader.FilterSecrets` strips every Secret
  object out of the resource set right before evaluation — the single enforcement point that applies
  regardless of whether the Secret came from the cluster or a file, so a `-f` directory that happens
  to contain real Secret YAML is never silently exposed.
- Requires the elevated ClusterRole (`examples/rbac/clusterrole-with-secrets.yaml`), not the default
  one — see [Required Permissions]({{ '/permissions/' | relative_url }}). Kubernetes RBAC has no way
  to grant "list Secret objects" without also granting body read access (there's no partial-field
  verb), so every check on this page needs the same elevated grant regardless of whether it actually
  reads `.data` — the age check below doesn't, but there's no narrower permission to give it.

## The three kinds of check this unlocks

### 1. Product-specific known-default checks (CEL/VAP policies)

One exact key, compared against one exact, vendor-documented default value — e.g.
`superset.secret-key-default-value` (CVE-2023-27524). See each component's section in
[Third-Party Operators]({{ '/third-party-operators/' | relative_url }}) for the current list; every
check that requires `--read-secret-values` says so explicitly in its
`audit.k8s-auditor.io/remediation` text.

### 2. A generic known-weak/placeholder-value check (CEL/VAP policy)

`secrets.known-weak-placeholder-value` (Critical) — flags any `type: Opaque`/`kubernetes.io/basic-auth`
Secret whose data
contains a value exactly equal to one of a short, deliberately narrow list of self-evidently
non-random literals (`changeme`, `changeit`, `password`, `admin`, `secret`, `guest`, `root`,
`123456`, `letmein`, `qwerty`). Unlike the product-specific checks above, this doesn't need a vendor
citation — the claim isn't "product X defaults to this," it's "this literal string is definitionally
not a random credential, regardless of which product it belongs to." Grounded in NIST SP 800-63B
§5.1.1.2's direction to reject memorized secrets found in breach corpuses/dictionaries — applied here
at the object level rather than at input time. False-positive risk is effectively zero: the odds of a
genuinely random secret coincidentally equaling one of these short literal strings are astronomically
low.

### 3. A native Go analyzer (`internal/secrets`) — not a CEL policy

Three checks that genuinely cannot be expressed as a single-object CEL policy, because they need
either a statistic over one object's own data, or a comparison *across* objects — the same reason
`internal/rbac` exists as native Go instead of a bundled policy:

| Check ID | Severity | What it flags |
|---|---|---|
| `secrets-analyzer.weak-credential-value` | High | A credential-shaped key's decoded value is short (&lt;8 chars) or low-entropy by a Shannon-entropy heuristic — the same core technique gitleaks/truffleHog/detect-secrets use as one of their detectors. Heuristic, not proof: the finding message says so. |
| `secrets-analyzer.value-reused-across-objects` | High | The exact same value appears in a credential-shaped key across two or more *different* Secret objects — a real blast-radius risk (one leak compromises every object sharing it). Doesn't fire on one Secret mirroring its own value across two of its own keys. |
| `secrets-analyzer.not-rotated-recently` | Low | A Secret's `.metadata.creationTimestamp` is over a year old. Deliberately Low severity and explicitly not tied to a rotation-mandate citation — NIST SP 800-63B actually recommends *against* mandatory periodic rotation for human-memorized secrets. This is a narrower, informational claim about machine/service credentials specifically: an unrotated credential has a wider blast-radius window if it was ever leaked undetected. Applies to every Secret type, not just Opaque — age doesn't depend on the data shape. |

Both value-based checks are restricted to `type: Opaque` (or type absent) and `kubernetes.io/basic-auth`
Secrets — the latter is a real, built-in Kubernetes type whose data is literally `username`/`password`,
the same flat-credential shape as Opaque; it was missing from the first version of this check (found by
an adversarial stress-test pass, since fixed). Also restricted to keys whose name looks credential-shaped
(`password`, `secret`, `token`, `key`, `credential`, `auth`, ... — explicitly excluding anything
containing `public`, since a *public* key/cert isn't sensitive even though its name contains "key").
`kubernetes.io/tls`, `dockerconfigjson`, `service-account-token`, and other typed Secrets have
structurally different data shapes (PEM blocks, JSON, JWTs) that these heuristics aren't tuned for and
would misfire on.

## Why a finding can never leak the actual secret value

**CEL checks** (categories 1 and 2 above): every expression compares `object.data['key']` against a
**known, hardcoded literal** and always emits a **static** `message:` string — there is no code path
where a live Secret value can end up in a finding. Enforced structurally, not just by convention:
`internal/engine/secret_policy_safety_test.go`'s `TestSecretTargetingPoliciesNeverUseMessageExpression`
fails the build if any bundled check that targets Secrets ever uses `messageExpression` (the one CEL
mechanism that could otherwise embed live object content into a message).

**The native analyzer** (category 3): builds findings directly in Go, so there's no language feature
to structurally forbid a leak the way `messageExpression` can be. Instead,
`internal/secrets/analyze_test.go`'s `TestFindingsNeverEmbedSecretValues` runs every check in the
package against fixtures containing several distinct real secret values, then asserts none of those
values — or their base64 form — appears anywhere in any finding's Title/Message/Remediation. The
reuse-detection check's message names the *other Secret objects* sharing a value (safe: it's an
object reference, not the value itself), never the value.

## Why CEL checks compare against base64, not decoded plaintext

Real Kubernetes `ValidatingAdmissionPolicy` CEL has no way to base64-decode a value either — the
Kubernetes CEL extension library
([`k8s.io/apiserver/pkg/cel/library`](https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/apiserver/pkg/cel/library))
has no base64 decode function, only a format *validator* that checks a string merely looks like
base64. So this engine doesn't decode Secret `.data` either for its CEL checks — a secret-targeting
policy's expression compares directly against the base64-encoded form of the known/weak value, e.g.:

```yaml
expression: |-
  !has(object.data) || !('adminPassword' in object.data) ||
  object.data['adminPassword'] != 'YWRtaW4=' # base64("admin")
```

This keeps every CEL check in this repo — including secret-targeting ones — genuinely portable: the
same YAML file that audits also `kubectl apply -f`'s as a real enforcing `ValidatingAdmissionPolicy`,
which this repo's whole design is built around (see `policies/`'s package doc). The native Go analyzer
(category 3) is a deliberate, explicit exception to that portability property — entropy computation
and cross-object comparison need real decoded bytes and can't be expressed as a real VAP at all, the
same tradeoff `internal/rbac` already made for RBAC least-privilege analysis.

`stringData` (the write-time-only plaintext convenience field Kubernetes accepts on `Secret` create
but never returns from a `List`/`Get`) is checked by the generic `secrets.known-weak-placeholder-value`
check and the native analyzer (category 3) — both matter for `-f` static-manifest scanning, this
tool's other primary mode, where `stringData` is a common, human-friendly authoring pattern (no manual
base64 step) and a live cluster fetch's "never populated" fact doesn't apply. This was a real gap in
the first version of both, found by an adversarial stress-test pass and fixed. The **product-specific**
known-default checks (category 1, e.g. `superset.secret-key-default-value`) still only check `.data`
— every official chart this tool has verified renders its own default-credential Secret via `.data`,
not `stringData`, so the practical risk is low, but a hand-authored manifest using `stringData` for one
of these specific keys would still be missed; a known, narrower gap than the one already fixed.

## What this does NOT do

Being direct about scope here matters more than for most features on this site, because the failure
mode of overclaiming secret-scanning coverage is a false sense of security, not just a missing
finding:

- **Not a general secret-strength scanner.** The entropy/length heuristic only looks at keys whose
  *name* looks credential-shaped. A credential stored under an unconventional key name (verified gaps:
  bare `pass` — only `password`/`passwd`/`pwd` are recognized — and any URL/DSN-shaped key like
  `DATABASE_URL`/`connection-string` that embeds a credential inline) is invisible to it.
- **The entropy heuristic is specifically blind to dictionary-word-plus-suffix values**
  (`changeme123`, `Password1!`, `qwerty123456`) — appending digits/punctuation to a weak word raises
  character-class diversity enough to clear the Shannon-entropy threshold even though the value is
  trivially guessable. This is a known, structural property of character-frequency entropy (vs. a
  dictionary/pattern-aware estimator like zxcvbn), confirmed by direct measurement, not a bug to fix
  in this design. The two secrets-mode layers aren't purely redundant despite this, though: a
  case-varied or whitespace-padded evasion of the *exact-match* CEL check (`ChangeMe`, `changeme `)
  is still caught by the entropy heuristic as a fallback — verified directly.
- **The entropy heuristic has a real, measured false-positive rate on short, genuinely strong hex
  secrets** — an 8-byte (`openssl rand -hex 8`) value was flagged "weak" in ~12% of random trials,
  purely from entropy variance at short lengths (hex's 16-symbol alphabet has less headroom above the
  3.0 bits/char threshold than base64/alphanumeric). Effectively zero by 16 bytes. The finding message
  already says "not a proof of weakness" — treat this check's High severity as a prompt to look, not a
  certainty.
- **`secrets.known-weak-placeholder-value` (the exact-match list) and `secrets-analyzer.weak-credential-value`
  (the entropy heuristic) can both fire on the same key** (e.g. a value that's literally `"password"`)
  — this is intentional, not duplicate noise: they're two independent signals that happen to agree.
- **No pattern/format detection.** No regex library for "this looks like an AWS access key" / "this
  looks like a private key PEM block embedded where it shouldn't be" / "this looks like a JWT." Those
  are real, well-established secret-scanner techniques (gitleaks/truffleHog both ship large pattern
  libraries) that nothing here implements yet.
- **The known-weak/placeholder list is short and will stay short on purpose** — it only contains
  literals that are self-evidently never going to be a real secret. It is not, and isn't trying to be,
  a comprehensive breached-password corpus.
- **Cross-namespace/cross-cluster reuse detection only sees what one scan loaded.** Running the same
  scan twice against two different clusters won't catch a credential reused *between* them — reuse
  detection only correlates Secrets present in one invocation's resource set.
- **No detection of secrets embedded in the wrong place** (a credential accidentally placed in a
  ConfigMap, a Pod env var literal, container args, or an annotation) beyond what
  `secrets.configmap-no-embedded-credentials` and `secrets.no-secrets-via-env` already cover
  independently of secrets mode — those two don't need `--read-secret-values` at all, since they never
  read an actual Secret's value, only ConfigMap/Pod-spec content.

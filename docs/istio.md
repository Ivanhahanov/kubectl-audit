---
layout: default
title: "Istio (alpha)"
permalink: /istio/
---

# Istio checks (alpha)

**Alpha**: newer and less battle-tested than the rest of this tool's checks. Every `istio.*`
finding's title starts with `[ALPHA]`, and any scan that loads a PeerAuthentication or
AuthorizationPolicy object gets a dedicated caveat in the report's **Scope** section (not mixed
into "Not covered by this scan" — these checks *do* run, just with a lower-confidence warning worth
reading before trusting the result). Treat `istio.*` findings as a starting point for manual
review, not a final verdict.

All three are single-object `ValidatingAdmissionPolicy` checks
([`policies/istio`](https://github.com/{{ site.repository }}/tree/main/policies/istio)) — no
cross-object effective-policy computation (that's what `istioctl x authz check` does from a live
sidecar's Envoy config, which this static/API-based tool structurally can't replicate).

## `istio.peer-authentication-permissive-mtls`

Flags a `PeerAuthentication` whose `spec.mtls.mode` is `DISABLE` or `PERMISSIVE` (severity High).
PeerAuthentication precedence is specificity-based — a workload-level object overrides
namespace-level, which overrides the mesh-level `default` object in the root namespace — and this
check evaluates each object independently, not the cluster-wide effective mode. A `PERMISSIVE`
namespace default might be safely overridden by a `STRICT` workload-level object elsewhere, or vice
versa; verify precedence manually before acting on this finding alone.

## `istio.authorization-policy-no-source-restriction`

Flags an `AuthorizationPolicy` (`action: ALLOW`, explicit or default) with a rule whose `from` is
absent or empty — per the API, that matches requests from **any** source, restricted only by `to`/
`when` if present (severity High). `DENY`/`AUDIT`/`CUSTOM`-action policies are never flagged: an
unrestricted `from` on those isn't the same kind of gap.

## `istio.authorization-policy-wildcard-path`

Flags an `AuthorizationPolicy` ALLOW rule whose `to[].operation.paths` includes `"*"` or `"/*"` —
granting every HTTP path on the selected workload(s) instead of specific endpoints (severity
Medium). Independent of the source-restriction check above: a rule can have `from` correctly scoped
to one caller and still hand that caller access to every path.

## Sidecarless (ambient mode)

Istio's ambient mode moves L4 mTLS enforcement to a node-level `ztunnel` and makes L7 enforcement
(`to.operation.methods`/`paths`/`hosts`) opt-in via a **waypoint proxy** deployed per
workload/namespace. An `AuthorizationPolicy` with L7 rules but no waypoint deployed for its target
isn't enforced at all — the object exists, looks correct, and does nothing. This tool has no way to
check waypoint deployment from the objects alone, so it can't distinguish "L7 rule is enforced" from
"L7 rule is silently ignored" in ambient mode. If you're on ambient mode, verify waypoint deployment
for any namespace/workload an `istio.authorization-policy-wildcard-path` or
`istio.authorization-policy-no-source-restriction` finding names.

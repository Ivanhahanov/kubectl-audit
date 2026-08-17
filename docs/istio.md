---
layout: default
title: "Istio (alpha)"
permalink: /istio/
---

# Istio checks (alpha)

**Alpha**: newer and less battle-tested than the rest of this tool's checks. Every `istio.*`
finding's title starts with `[ALPHA]`, and any scan that loads a PeerAuthentication,
AuthorizationPolicy, DestinationRule, or Gateway object gets a dedicated caveat in the report's
**Scope** section (not mixed into "Not covered by this scan" — these checks *do* run, just with a
lower-confidence warning worth reading before trusting the result). Treat `istio.*` findings as a
starting point for manual review, not a final verdict.

All six are single-object `ValidatingAdmissionPolicy` checks
([`policies/thirdparty/istio`](https://github.com/{{ site.repository }}/tree/main/policies/thirdparty/istio)) — no
cross-object effective-policy computation (that's what `istioctl x authz check` does from a live
sidecar's Envoy config, which this static/API-based tool structurally can't replicate).

In cluster mode, objects are fetched by resolving `security.istio.io`'s and `networking.istio.io`'s
actual served/preferred version via the cluster's own API discovery — not a version hardcoded into
this tool — so it works whether the cluster serves `v1` or the older `v1beta1`, and a cluster
without Istio installed at all is skipped silently rather than erroring. Each bundled policy's
`matchConstraints.apiVersions` is `["*"]` for the same reason: it matches the object regardless of
which version the cluster actually returned.

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

## `istio.destination-rule-tls-disabled`

Flags a `DestinationRule` whose `spec.trafficPolicy.tls.mode` is `DISABLE` (severity High). Istio's
own API reference (`networking/v1alpha3/destination_rule.proto`, `TLSmode` enum): "DISABLE - Do not
setup a TLS connection to the upstream endpoint." Only the top-level default is checked —
`trafficPolicy.portLevelSettings[].tls.mode` and `subsets[].trafficPolicy(.portLevelSettings[])?.tls.mode`
can override it per-port/per-subset, same "evaluated independently" caveat as every other check
here.

## `istio.gateway-weak-tls-version`

Flags a `Gateway` with a server whose `tls.minProtocolVersion` is `TLSV1_0` or `TLSV1_1` (severity
Medium). Both are real, still-accepted values in Istio's own API (`networking/v1alpha3/gateway.proto`,
`TLSProtocol` enum), but formally deprecated by IETF RFC 8996 ("Deprecating TLS 1.0 and TLS 1.1") —
this is the one `istio.*` check backed by an external protocol standard rather than Istio's own
docs independently flagging the value as insecure, the same sourcing pattern this tool uses
elsewhere when no vendor-specific guidance exists (e.g. NIST SP 800-190 for the
ConfigMap-credentials check).

## `istio.mesh-config-outbound-traffic-policy-allow-any`

Flags the `istio` ConfigMap's `mesh` config (a YAML text blob, not a separate typed field — Istio's
own well-known, name-stable runtime object, not a CRD) when `outboundTrafficPolicy.mode` isn't
explicitly `REGISTRY_ONLY` (severity Medium). Istio's own
[API reference](https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/): "The default is
`ALLOW_ANY`, which permits traffic to unknown destinations" — "any traffic to unknown destinations
will be allowed" — vs. `REGISTRY_ONLY`, where "unknown outbound traffic will be dropped. Traffic
destinations must be explicitly declared into the service registry through ServiceEntry
configurations." Both the field being absent (the default) and explicit `ALLOW_ANY`/
`ALLOW_ANY_DYNAMIC_DNS` are flagged — only an explicit `REGISTRY_ONLY` passes. Checks the
component's own runtime config object, the same pattern as the ArgoCD `argocd-cmd-params-cm`/
`argocd-rbac-cm` checks, rather than a CRD.

## `istio.destination-rule-tls-insecure-skip-verify`

Flags a `DestinationRule` whose `spec.trafficPolicy.tls.insecureSkipVerify` is `true` (severity
High). Istio's own API reference (`networking/v1alpha3/destination_rule.proto`,
`ClientTLSSettings.insecure_skip_verify`): "specifies whether the proxy should skip verifying the CA
signature and SAN for the server certificate corresponding to the host. The default value of this
field is false." A distinct, more subtle downgrade than `istio.destination-rule-tls-disabled`: TLS is
still negotiated, but the peer's identity is never checked, so the connection is trivially
MITM-able. Same top-level-only scope caveat as `istio.destination-rule-tls-disabled`.

## `istio.sidecar-outbound-traffic-policy-allow-any`

Flags a `Sidecar` resource whose `spec.outboundTrafficPolicy.mode` is explicitly `ALLOW_ANY`
(severity Medium). Same API shape and rationale as `istio.mesh-config-outbound-traffic-policy-allow-any`,
but per-workload rather than mesh-wide: an unset value inherits the mesh default (already covered by
that check), so this only fires when a `Sidecar` resource *explicitly* overrides to `ALLOW_ANY` —
notably including the case where it overrides a `REGISTRY_ONLY` mesh-wide default back open for one
workload.

## Sidecarless (ambient mode)

Istio's ambient mode moves L4 mTLS enforcement to a node-level `ztunnel` and makes L7 enforcement
(`to.operation.methods`/`paths`/`hosts`) opt-in via a **waypoint proxy** deployed per
workload/namespace. An `AuthorizationPolicy` with L7 rules but no waypoint deployed for its target
isn't enforced at all — the object exists, looks correct, and does nothing. This tool has no way to
check waypoint deployment from the objects alone, so it can't distinguish "L7 rule is enforced" from
"L7 rule is silently ignored" in ambient mode. If you're on ambient mode, verify waypoint deployment
for any namespace/workload an `istio.authorization-policy-wildcard-path` or
`istio.authorization-policy-no-source-restriction` finding names.

## Investigated and declined

- `VirtualService.spec.hosts` containing a bare `"*"` — the VirtualService API reference documents
  wildcard-*prefix* hosts (`"*.example.com"`) as a supported pattern, but doesn't independently call
  out a bare `"*"` as risky the way this tool's other checks are sourced. Doesn't meet the "traced to
  a specific, quoted line of the project's own guidance" bar as-is.
- "Every Namespace must have at least one `AuthorizationPolicy`" — requires a live cross-object
  query (all AuthorizationPolicies vs. all Namespaces), which this tool's single-object CEL engine
  structurally can't do.
- A separate check for `PeerAuthentication.spec.mtls.mode: DISABLE` — not needed:
  `istio.peer-authentication-permissive-mtls` already flags both `DISABLE` and `PERMISSIVE`.
- `EnvoyFilter` existence/usage — Istio's own docs do caution it "must be used with care" and can
  "destabilize the entire mesh," but that's a stability warning about the mechanism itself, not a
  specific bad *value* to check for (EnvoyFilter's entire purpose is arbitrary low-level Envoy
  config). Flagging mere existence would be noise for any serious Istio deployment. No existing
  mitigation; known gap.
- `RequestAuthentication` configured without a corresponding enforcing `AuthorizationPolicy` (a real,
  commonly-documented Istio gotcha: JWT validation configured but never actually required) — requires
  correlating two separate CRDs, the same cross-object limitation as the AuthorizationPolicy-per-namespace
  item above.
- `ServiceEntry.spec.resolution: NONE` — a legitimate, common pattern for TLS origination/opaque TCP
  passthrough, not a documented insecure value. Declined on sourcing grounds, not safety grounds.

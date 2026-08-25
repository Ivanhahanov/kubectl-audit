// Package secrets analyzes Secret VALUES for weak-credential heuristics and
// cross-object value reuse — analysis this repo's single-object CEL engine
// structurally cannot do (a CEL ValidatingAdmissionPolicy only ever sees
// one object; it cannot compute a statistic over one object's data and
// compare it across every other Secret in the resource set). This mirrors
// why internal/rbac exists as native Go rather than a CEL policy: some
// analysis genuinely needs to leave the "same YAML enforces in a real
// cluster" model to be effective, and pretending otherwise means either not
// building it or building a materially weaker version of it.
//
// Only ever called with resources that were actually loaded — see
// docs/secrets-mode.md and internal/loader.FilterSecrets: unless
// --read-secret-values was passed, no Secret ever reaches this package at
// all, by construction, regardless of whether the caller remembers to gate
// the call.
//
// Every finding this package produces is checked, in
// TestFindingsNeverEmbedSecretValues, to never contain the base64 form of
// any input Secret value anywhere in its Message/Remediation/Title — the
// same anti-leak guarantee internal/engine's CEL-policy secret checks have
// (see secret_policy_safety_test.go), enforced here structurally instead of
// by construction (there's no CEL messageExpression to forbid; findings are
// built directly in Go), so it has to be verified rather than assumed.
package secrets

import (
	"encoding/base64"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

const (
	// minCredentialLength is the decoded-length floor below which a value
	// in a credential-named key is flagged regardless of its character
	// diversity — a 4-character value can't carry enough entropy to be a
	// real secret no matter what it's made of.
	minCredentialLength = 8
	// minShannonEntropyBitsPerChar is the heuristic floor for values at or
	// above minCredentialLength. Not a standardized threshold — no single
	// canonical number exists — but the technique itself (Shannon entropy
	// over the secret's own characters) is the same core heuristic used by
	// widely-adopted secret scanners (gitleaks, truffleHog, detect-secrets
	// all ship an entropy detector as one of their core signals). For
	// context: a uniformly-random value over the common 62-character
	// alphanumeric alphabet (the shape most generated secrets take, e.g.
	// Helm's `randAlphaNum`) has Shannon entropy close to log2(62) ≈ 5.95
	// bits/char; typical human-chosen passwords and dictionary words
	// measure well below 3.5. This is a heuristic signal, not a proof of
	// weakness — see the finding's own message, which says so explicitly.
	minShannonEntropyBitsPerChar = 3.0
	// minReuseValueLength avoids flagging coincidental reuse of trivially
	// short values (e.g. two Secrets both happening to hold "" or "0" for
	// an unrelated field) as if it were credential reuse.
	minReuseValueLength = 8
)

// credentialKeyTokens are lowercase substrings that make a Secret data key
// look like it holds a credential rather than incidental/structural data
// (a port number, a boolean flag, a hostname). "public" is excluded via a
// separate, explicit check below (see isCredentialKey) — a *public* key or
// cert is not sensitive even though its name contains "key", and Go's
// standard regexp package (RE2, like this repo's CEL engine) has no
// negative-lookahead to express that in one pattern.
var credentialKeyTokens = []string{
	"password", "passwd", "pwd", "secret", "token", "credential", "auth", "apikey", "api_key", "api-key",
}

// isCredentialKey reports whether a Secret data key name looks like it
// holds credential material, worth applying the weak-value/reuse
// heuristics to. Deliberately conservative: this repo's whole session-long
// convention is to accept lower recall in exchange for not shipping a
// bundled, always-on check that misfires on ordinary non-credential data.
func isCredentialKey(key string) bool {
	lower := strings.ToLower(key)
	if strings.Contains(lower, "public") {
		return false
	}
	// "key" alone is checked separately from the token list above so
	// "publickey"/"ssh-publickey" (excluded above) doesn't accidentally
	// still match via a more specific token; "key" is intentionally the
	// broadest, last-checked token.
	for _, tok := range append(append([]string{}, credentialKeyTokens...), "key") {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// isCredentialShapedSecret reports whether obj is a core v1 Secret whose
// .data shape is a flat map of credential-like values the weak-value/reuse
// heuristics can meaningfully apply to: type Opaque (or type absent, which
// the Kubernetes API itself treats as Opaque), or the built-in
// kubernetes.io/basic-auth type — a real Kubernetes type whose data is
// *literally* `username`/`password`, the same flat-credential shape as
// Opaque, unlike kubernetes.io/tls/dockerconfigjson/service-account-token
// (PEM blocks, JSON, JWTs) which stay excluded: applying these heuristics
// to those would only add false-positive risk, not real detection.
// basic-auth was excluded from the first version of this check purely by
// oversight — its data shape doesn't structurally differ from Opaque the
// way the other typed Secrets do — caught by an adversarial stress-test
// pass explicitly built to find gaps like this.
func isCredentialShapedSecret(r loader.Resource) bool {
	gvk := r.GVK()
	if gvk.Group != "" || gvk.Kind != "Secret" {
		return false
	}
	t, found, _ := unstructured.NestedString(r.Object.Object, "type")
	if !found || t == "" {
		return true
	}
	return t == "Opaque" || t == "kubernetes.io/basic-auth"
}

// secretValue is one decoded (key, value) pair from one credential-shaped
// Secret, carried alongside enough identity to build a finding without
// needing to re-walk the source object. decoded is always the plaintext
// value regardless of whether it came from .data (base64-decoded) or
// .stringData (already plaintext) — see AnalyzeAt — so reuse detection
// (which groups by decoded) correctly treats the same underlying secret as
// the same value no matter which field authored it.
type secretValue struct {
	ref     findings.ResourceRef
	key     string
	decoded string
}

// Analyze inspects every Opaque Secret's decoded values for two things a
// single-object CEL policy can't do: values that look weak by a
// length/entropy heuristic, and the same value reused verbatim across more
// than one distinct Secret object (a real lateral-movement/blast-radius
// risk — compromising one credential compromises everywhere it's reused).
// Also flags Secrets (of any type — this one doesn't need .data at all)
// that haven't been rotated in a long time, purely from
// .metadata.creationTimestamp. Only ever produces findings for resources
// actually present in resources — see the package doc comment for why
// that's already guaranteed to be empty unless --read-secret-values was
// passed. That gate is slightly broader than this specific check strictly
// needs (creationTimestamp is metadata, not the secret body), but
// Kubernetes RBAC has no way to grant "list Secret objects" without also
// granting body read access — there's no partial-field verb — so there's
// no real permission benefit to a separate, narrower gate; unifying behind
// one flag avoids fake precision.
func Analyze(resources []loader.Resource, source string) ([]findings.Finding, error) {
	return AnalyzeAt(resources, source, time.Now())
}

// AnalyzeAt is Analyze with an injectable "now", so the age-based check is
// deterministic in tests instead of depending on the wall clock.
func AnalyzeAt(resources []loader.Resource, source string, now time.Time) ([]findings.Finding, error) {
	var values []secretValue
	for _, r := range resources {
		if !isCredentialShapedSecret(r) {
			continue
		}
		ref := findings.ResourceRef{APIVersion: r.GVK().GroupVersion().String(), Kind: "Secret", Namespace: r.Namespace(), Name: r.Name()}

		if data, found, _ := unstructured.NestedStringMap(r.Object.Object, "data"); found {
			for key, raw := range data {
				if !isCredentialKey(key) {
					continue
				}
				decodedBytes, err := base64.StdEncoding.DecodeString(raw)
				if err != nil {
					// Not valid base64 — can't happen for a real API-server-
					// returned Secret, but a hand-authored static manifest
					// could have a typo here. Skip rather than error the
					// whole scan over one malformed value.
					continue
				}
				values = append(values, secretValue{ref: ref, key: key, decoded: string(decodedBytes)})
			}
		}

		// stringData is a write-time-only convenience field: a real live
		// cluster fetch never has it populated (the API server converts it
		// into .data on create and never returns it from Get/List), but a
		// static manifest (the tool's other primary mode, e.g. scanning a
		// GitOps repo before it's applied) very commonly authors Secrets
		// this way specifically so a human doesn't have to hand-encode
		// base64 — skipping it left every such Secret invisible to this
		// whole feature. Caught by the same adversarial stress-test pass
		// as the basic-auth gap above. Already plaintext, no decode step.
		if stringData, found, _ := unstructured.NestedStringMap(r.Object.Object, "stringData"); found {
			for key, val := range stringData {
				if !isCredentialKey(key) {
					continue
				}
				values = append(values, secretValue{ref: ref, key: key, decoded: val})
			}
		}
	}

	var out []findings.Finding
	out = append(out, checkWeakValues(values, source)...)
	out = append(out, checkReusedValues(values, source)...)
	out = append(out, checkStaleSecrets(resources, source, now)...)
	return out, nil
}

// staleThreshold is deliberately generous (a full year) and this check is
// deliberately Low severity, not tied to a compliance citation: NIST SP
// 800-63B §5.1.1.2 explicitly recommends AGAINST mandatory periodic
// rotation of human-memorized secrets "unless there is evidence of
// compromise" — citing it here in support of a rotation check would
// misrepresent it. This check instead rests on a narrower, more defensible
// claim that applies to machine/service credentials specifically (the kind
// Kubernetes Secrets actually hold, not human-memorized passwords): a
// credential that has never been rotated has a wider blast-radius window
// if it was ever quietly leaked at any point since — a genuine, but
// informational-strength, engineering signal rather than a hard rule any
// specific age is "wrong." Applies to every Secret type (unlike the
// value-based checks above): age doesn't depend on the data shape.
const staleThresholdDays = 365

func checkStaleSecrets(resources []loader.Resource, source string, now time.Time) []findings.Finding {
	var out []findings.Finding
	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group != "" || gvk.Kind != "Secret" {
			continue
		}
		ts := r.Object.GetCreationTimestamp()
		if ts.IsZero() {
			// The common case for a static-manifest-loaded Secret: the
			// API server is what normally populates this field on
			// create, and a hand-authored manifest usually doesn't set
			// it — nothing to compare against then, not a finding. (A
			// manifest that DOES set it explicitly, e.g. a snapshot
			// exported from a real cluster, is still evaluated normally.)
			continue
		}
		ageDays := int(now.Sub(ts.Time).Hours() / 24)
		if ageDays < staleThresholdDays {
			continue
		}
		ref := findings.ResourceRef{APIVersion: gvk.GroupVersion().String(), Kind: "Secret", Namespace: r.Namespace(), Name: r.Name()}
		out = append(out, findings.Finding{
			ID:       findings.NewID("secrets-analyzer.not-rotated-recently", ref),
			PolicyID: "secrets-analyzer.not-rotated-recently",
			Title:    "Secret has not been rotated in over a year",
			Severity: findings.SeverityLow,
			Category: "secrets",
			Resource: ref,
			Message: fmt.Sprintf(
				"This Secret was created %d days ago (%s) and has never been rotated since — informational: a long-lived, never-rotated credential has a wider blast-radius window if it was ever leaked undetected. Not every Secret needs rotation (e.g. long-lived root CA material) — review in context, this isn't a hard rule.",
				ageDays, ts.Time.Format("2006-01-02"),
			),
			Remediation: "Rotate this credential if it's used for authentication, and consider automated rotation for anything with a realistic compromise-and-reuse risk.",
			VerificationSteps: "1. Check whether this Secret is actually used for live authentication at all " +
				"— some long-lived Secrets (root CA material, a one-time bootstrap token) genuinely don't need " +
				"rotation, per the Message's own caveat. 2. If it is an active credential, ask the owning team " +
				"whether it's already covered by an external rotation mechanism (Vault dynamic secrets, " +
				"external-secrets sync, cert-manager) that simply doesn't update this object's " +
				"creationTimestamp when it rotates the underlying value.",
			Source: source,
		})
	}
	return out
}

func checkWeakValues(values []secretValue, source string) []findings.Finding {
	var out []findings.Finding
	for _, v := range values {
		n := len(v.decoded)
		weak := n < minCredentialLength
		var entropy float64
		if !weak {
			entropy = shannonEntropyBitsPerChar(v.decoded)
			weak = entropy < minShannonEntropyBitsPerChar
		}
		if !weak {
			continue
		}
		out = append(out, findings.Finding{
			ID:       findings.NewID("secrets-analyzer.weak-credential-value", v.ref, v.key),
			PolicyID: "secrets-analyzer.weak-credential-value",
			Title:    "Secret value looks weak (short and/or low-entropy)",
			Severity: findings.SeverityHigh,
			Category: "secrets",
			Resource: v.ref,
			Message: fmt.Sprintf(
				"Key %q (%d characters, ~%.1f bits/char entropy) looks weak by a length/entropy heuristic — not a proof of weakness, but real generated secrets are typically far longer and higher-entropy than this.",
				v.key, n, entropyOrZero(n, v.decoded),
			),
			Remediation: "Replace this value with a real, randomly-generated credential (e.g. 32+ random bytes from a CSPRNG) if it's genuinely in use for authentication.",
			VerificationSteps: fmt.Sprintf(
				"1. This heuristic only ever sees length/entropy, never the value itself (see the package's own "+
					"anti-leak guarantee) — as the person triaging, decode the value yourself in a secure "+
					"terminal (`kubectl get secret <name> -n <ns> -o jsonpath='{.data.%s}' | base64 -d`) to "+
					"confirm it's genuinely a short/low-entropy credential and not, say, a base64-encoded "+
					"binary blob the heuristic simply misjudged. 2. Check whether this is a live, in-use value "+
					"or a placeholder that gets overridden by an external-secrets/Vault sync before the "+
					"workload ever reads it. 3. If confirmed real and weak, treat as urgent: check auth/audit "+
					"logs for whether it's already been used to authenticate anywhere, to judge whether "+
					"rotation alone suffices or a wider incident response is warranted.",
				v.key,
			),
			Source: source,
		})
	}
	return out
}

// entropyOrZero avoids computing entropy over an already-too-short value
// purely for the message text (checkWeakValues only computes it when n is
// already >= minCredentialLength, but the message wants a number either
// way — 0.0 for the too-short case is accurate: entropy of very short
// strings tells you little, the length itself is the finding).
func entropyOrZero(n int, decoded string) float64 {
	if n < minCredentialLength {
		return 0
	}
	return shannonEntropyBitsPerChar(decoded)
}

// shannonEntropyBitsPerChar computes the Shannon entropy, in bits per
// character, of s's own character-frequency distribution — the standard
// entropy heuristic secret-scanning tools use as one detector among
// several. Not cryptographic entropy (which would require knowing the
// generating process, not just the output), and not a measure of any
// single string's "true randomness" — a heuristic, documented as such at
// every call site and in every finding message this feeds.
func shannonEntropyBitsPerChar(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, c := range counts {
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func checkReusedValues(values []secretValue, source string) []findings.Finding {
	byValue := make(map[string][]secretValue)
	for _, v := range values {
		if len(v.decoded) < minReuseValueLength {
			continue
		}
		byValue[v.decoded] = append(byValue[v.decoded], v)
	}

	var out []findings.Finding
	for _, group := range byValue {
		// Only cross-OBJECT reuse is interesting — the same Secret object
		// legitimately mirroring one value across two of its own keys
		// (e.g. a replication password stored under two conventional key
		// names) isn't a blast-radius concern the way two DIFFERENT
		// Secret objects sharing a value is.
		distinctObjects := map[string]bool{}
		for _, v := range group {
			distinctObjects[v.ref.Namespace+"/"+v.ref.Name] = true
		}
		if len(distinctObjects) < 2 {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			if group[i].ref.Namespace != group[j].ref.Namespace {
				return group[i].ref.Namespace < group[j].ref.Namespace
			}
			if group[i].ref.Name != group[j].ref.Name {
				return group[i].ref.Name < group[j].ref.Name
			}
			return group[i].key < group[j].key
		})
		for i, v := range group {
			// "others" excludes this specific finding's own (object, key) —
			// a finding shouldn't cite itself as one of the "other" places
			// the value was found.
			var others []string
			for j, o := range group {
				if j == i {
					continue
				}
				others = append(others, fmt.Sprintf("%s/%s:%s", o.ref.Namespace, o.ref.Name, o.key))
			}
			out = append(out, findings.Finding{
				ID:       findings.NewID("secrets-analyzer.value-reused-across-objects", v.ref, v.key),
				PolicyID: "secrets-analyzer.value-reused-across-objects",
				Title:    "Secret value is reused verbatim across multiple Secret objects",
				Severity: findings.SeverityHigh,
				Category: "secrets",
				Resource: v.ref,
				Message: fmt.Sprintf(
					"Key %q holds the exact same value as: %s. If any one of these is ever compromised, every other object sharing this value is compromised too.",
					v.key, strings.Join(others, ", "),
				),
				Remediation: "Give each Secret its own independently-generated value — a shared credential turns a single leak into a multi-object compromise.",
				VerificationSteps: "1. Check whether the objects cited in the Message are siblings of the " +
					"same application by design (e.g. a StatefulSet's replication password IS supposed to be " +
					"identical across every replica's Secret) — that's an intentional, lower-risk pattern, not " +
					"a leak. 2. If the objects belong to unrelated apps/teams, this is a genuine cross-blast-" +
					"radius risk — trace which workloads actually mount each cited Secret " +
					"(`kubectl get pods -A -o json | jq` filtering volumes/envFrom for the Secret name) to " +
					"scope the true impact of a single leak before prioritizing remediation.",
				Source: source,
			})
		}
	}
	return out
}

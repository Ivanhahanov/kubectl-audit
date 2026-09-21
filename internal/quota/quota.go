// Package quota checks whether ordinary (non-Capsule-managed) namespaces
// have a ResourceQuota and LimitRange at all. This can't be a single-object
// VAP/CEL policy: answering "does this namespace have a ResourceQuota"
// requires matching a Namespace against every ResourceQuota/LimitRange
// object cluster-wide, the same cross-object reasoning netpol.Analyze does
// for NetworkPolicy coverage.
package quota

import (
	"fmt"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

// Check IDs for Analyze below.
const (
	CheckIDNoResourceQuota = "quota-analyzer.no-resource-quota"
	CheckIDNoLimitRange    = "quota-analyzer.no-limit-range"
)

// capsuleTenantLabel is the label Capsule (github.com/projectcapsule/capsule)
// sets on every namespace it provisions for a Tenant. Namespaces carrying it
// are already covered by the Tenant-level
// multitenancy.capsule-tenant-no-resource-quota/-no-limit-range checks,
// which validate the Tenant's own spec — the actual source of truth for a
// Capsule-managed namespace's quota, since Capsule (re)materializes the
// ResourceQuota/LimitRange from that spec rather than the other way
// around. Flagging these namespaces here too would report the same
// underlying gap twice under two different policy IDs.
const capsuleTenantLabel = "capsule.clastix.io/tenant"

// Analyze flags namespaces with no ResourceQuota and/or no LimitRange
// object at all (security-requirements.txt 4.3.1/4.3.2). Presence-only,
// like netpol.Analyze's NetworkPolicy coverage check: it confirms a
// namespace isn't running with zero constraints whatsoever, not that
// whatever quota/limit range exists is actually reasonable.
func Analyze(resources []loader.Resource, source string) []findings.Finding {
	hasQuota := map[string]bool{}
	hasLimitRange := map[string]bool{}
	var namespaces []loader.Resource

	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group != "" {
			continue
		}
		switch gvk.Kind {
		case "Namespace":
			namespaces = append(namespaces, r)
		case "ResourceQuota":
			hasQuota[r.Namespace()] = true
		case "LimitRange":
			hasLimitRange[r.Namespace()] = true
		}
	}

	var out []findings.Finding
	for _, ns := range namespaces {
		if _, managed := ns.Object.GetLabels()[capsuleTenantLabel]; managed {
			continue
		}
		name := ns.Name()
		if !hasQuota[name] {
			out = append(out, noResourceQuotaFinding(ns, name))
		}
		if !hasLimitRange[name] {
			out = append(out, noLimitRangeFinding(ns, name))
		}
	}
	return out
}

func noResourceQuotaFinding(ns loader.Resource, name string) findings.Finding {
	ref := findings.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: name}
	return findings.Finding{
		ID:       findings.NewID(CheckIDNoResourceQuota, ref),
		PolicyID: CheckIDNoResourceQuota,
		Title:    "Namespace has no ResourceQuota",
		Severity: findings.SeverityMedium,
		Category: "workload-security",
		Resource: ref,
		Message: fmt.Sprintf(
			"Namespace %q has no ResourceQuota object at all — workloads here can consume unbounded CPU, "+
				"memory, pod count, and PersistentVolumeClaim count, with nothing stopping a runaway or "+
				"misbehaving workload from starving every other namespace on the same nodes.",
			name),
		Remediation: "Create a ResourceQuota in this namespace bounding CPU (requests.cpu/limits.cpu), memory " +
			"(requests.memory/limits.memory), pod count (pods), and PersistentVolumeClaim count " +
			"(persistentvolumeclaims) — not just one of them.",
		VerificationSteps: "1. Confirm this namespace is genuinely meant to run workloads (not a purely " +
			"system/operator namespace where quota is less meaningful) before treating it as a hard finding. " +
			"2. Assess actual cluster capacity risk: a namespace on a cluster with abundant headroom and few " +
			"tenants/teams has lower urgency than one on a tightly-packed, shared cluster. 3. Run " +
			"`kubectl get resourcequota -n <namespace>` yourself to confirm none exists (not just what this " +
			"scan happened to load).",
		Source: ns.Source,
	}
}

func noLimitRangeFinding(ns loader.Resource, name string) findings.Finding {
	ref := findings.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: name}
	return findings.Finding{
		ID:       findings.NewID(CheckIDNoLimitRange, ref),
		PolicyID: CheckIDNoLimitRange,
		Title:    "Namespace has no LimitRange",
		Severity: findings.SeverityLow,
		Category: "workload-security",
		Resource: ref,
		Message: fmt.Sprintf(
			"Namespace %q has no LimitRange object — containers created here with no explicit "+
				"resources.requests/limits of their own get no default, so a ResourceQuota (if one exists) can "+
				"still be exhausted by many small unbounded containers, or a single container can consume far "+
				"more than intended.",
			name),
		Remediation: "Create a LimitRange in this namespace setting default request/limit values for " +
			"containers that don't set their own — this is a complement to ResourceQuota, not a substitute " +
			"for it.",
		VerificationSteps: "1. Low severity reflects that this is a secondary control — it only matters in " +
			"combination with either a ResourceQuota or workload.resource-limits-required findings on " +
			"individual containers in this namespace, not a standalone risk. 2. Run " +
			"`kubectl get limitrange -n <namespace>` yourself to confirm none exists.",
		Source: ns.Source,
	}
}

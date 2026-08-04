// Package k8sversion parses a detected Kubernetes server version (from
// client-go's discovery client) and checks it against this tool's notion of
// the current upstream support window — see CheckSupportWindow.
//
// It's also the thing that makes internal/pss's Pod Security Standards
// evaluation version-aware instead of always assuming the latest release:
// pod-security-admission's own check implementations are versioned (e.g.
// the Restricted capabilities rule changed at 1.22 and again at 1.25;
// ProcMount checks only exist from 1.35 onward), so evaluating an old
// cluster against "latest" rules can apply requirements that didn't exist
// yet for that version.
package k8sversion

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// LatestKnownMajor/LatestKnownMinor is the newest Kubernetes minor version
// this build's checks were written against — kept roughly in step with the
// k8s.io/api version pinned in go.mod. Update it when bumping that
// dependency; it's used both to size the "outside the support window"
// finding below and, in internal/pss, as the fallback when no live cluster
// version was detected at all (a static-manifest-only scan).
const (
	LatestKnownMajor = 1
	LatestKnownMinor = 36
)

// SupportedMinorWindow is how many of the newest minor versions this tool
// treats as "likely still supported upstream." Kubernetes' own policy is
// roughly the latest 3 minor releases (~14 months) at any given time, but
// this is a version-distance approximation, not a live lookup against the
// actual EOL calendar or any vendor's extended-support program.
const SupportedMinorWindow = 3

// CheckID is the finding ID CheckSupportWindow emits. The "cluster."
// segment exists so compliance.OverrideUnobserved (prefix
// "version-analyzer.") can force the control NOT_APPLICABLE on a
// static-manifest-only scan, where there's no live cluster to detect a
// version from at all — instead of a silent false PASS (see
// internal/cli/orchestrate.go).
const CheckID = "version-analyzer.cluster.outside-support-window"

var gitVersionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)`)

// Parse extracts (major, minor) from a Kubernetes version string in any of
// the forms client-go's discovery client / vendors return: "v1.27.16",
// "1.27.16-eks-abc1234", "1.27+" (some managed providers pad Minor with a
// trailing "+"), etc. The patch version and any suffix are ignored.
func Parse(gitVersion string) (major, minor int, ok bool) {
	m := gitVersionPattern.FindStringSubmatch(gitVersion)
	if m == nil {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// CheckSupportWindow flags a cluster running a Kubernetes minor version
// further behind LatestKnownMinor than SupportedMinorWindow. Returns no
// finding if the version string can't be parsed, is a different major
// version, or is newer than LatestKnownMinor (this build simply doesn't
// have an opinion on versions newer than it was written against — that's a
// different risk, "this tool might be missing something new," not "the
// cluster is unpatched").
func CheckSupportWindow(gitVersion, source string) []findings.Finding {
	major, minor, ok := Parse(gitVersion)
	if !ok || major != LatestKnownMajor || minor > LatestKnownMinor {
		return nil
	}
	age := LatestKnownMinor - minor
	if age < SupportedMinorWindow {
		return nil
	}

	ref := findings.ResourceRef{Kind: "Cluster", Name: gitVersion}
	return []findings.Finding{{
		ID:       findings.NewID(CheckID, ref),
		PolicyID: CheckID,
		Title:    "Cluster is running a Kubernetes version likely outside the upstream support window",
		Severity: findings.SeverityHigh,
		Category: "patch-lifecycle",
		Resource: ref,
		Message: fmt.Sprintf(
			"Detected Kubernetes %d.%d, %d minor version(s) behind %d.%d (the newest version this build's checks were written "+
				"against). Upstream Kubernetes typically supports only the latest ~%d minor releases at a time — this cluster is "+
				"likely past end-of-life for upstream security patches. This is a version-distance approximation, not a live "+
				"lookup: verify the actual EOL date at https://kubernetes.io/releases/patch-releases/, and account for any vendor "+
				"extended-support program (EKS/GKE/AKS, ...) that may still be patching it. An old cluster version can also make "+
				"some of this tool's other checks less reliable — flags/fields introduced after this cluster's version won't be "+
				"present even on a well-configured control plane, which can read as a false FAIL.",
			major, minor, age, LatestKnownMajor, LatestKnownMinor, SupportedMinorWindow),
		Remediation: "Plan an upgrade path to a supported minor version, or confirm this cluster is intentionally on a vendor's extended-support track.",
		Source:      source,
	}}
}

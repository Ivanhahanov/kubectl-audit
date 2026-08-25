package controlplane

import (
	"fmt"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

// checks is the catalog of flag-based control-plane checks that stay in Go
// rather than becoming VAP/CEL policies (see policies/controlplane/*.yaml
// for the rest): CSV-membership checks (--authorization-mode,
// --enable-admission-plugins), a cross-flag admission-plugin "not disabled"
// rule that has to reason about two different flags together, and audit-log
// numeric thresholds that are conditional on a third flag
// (--audit-log-path) being set at all. Expressing this in CEL is possible
// but turns into repetitive, hard-to-read substring/split gymnastics
// compared to a few lines of typed, unit-tested Go — the same tradeoff
// internal/rbac and internal/netpol make for cross-object reasoning a
// single-object CEL expression can't do cleanly.
//
// Controls that need human judgment on a context-dependent value (e.g. "set
// --request-timeout as appropriate") or file *content* this tool
// structurally can't read (e.g. the referenced encryption config or audit
// policy file's actual contents) are deliberately not in this list — they
// stay NOT_IMPLEMENTED/NOT_APPLICABLE in compliance-mappings/cis.yaml.
var checks = []check{
	{
		ID: "controlplane-analyzer.apiserver.authz-always-allow", Component: ComponentAPIServer, CIS: "1.2.6",
		Title: "kube-apiserver authorization mode includes AlwaysAllow", Severity: findings.SeverityCritical,
		Remediation: "Remove AlwaysAllow from --authorization-mode; it bypasses all authorization checks.",
		VerificationSteps: "1. Confirm this isn't a decommissioned/scratch/local-dev cluster (AlwaysAllow is " +
			"essentially unheard of on anything else). 2. If you have node/file access, cross-check the live " +
			"process's actual --authorization-mode against the Pod spec this was inferred from — the two can " +
			"drift after a manual restart with different flags. 3. If confirmed on a real cluster, this is a " +
			"true critical with no further verification needed: every authenticated (and, depending on " +
			"--anonymous-auth, every unauthenticated) request bypasses RBAC entirely.",
		Eval: func(f flags) (bool, string) {
			if f.csvContains("authorization-mode", "AlwaysAllow") {
				return false, "--authorization-mode includes AlwaysAllow, which grants every request regardless of RBAC."
			}
			return true, ""
		},
	},
	{
		ID: "controlplane-analyzer.apiserver.authz-node", Component: ComponentAPIServer, CIS: "1.2.7",
		Title: "kube-apiserver authorization mode does not include Node", Severity: findings.SeverityHigh,
		Remediation: "Include Node in --authorization-mode so kubelets are restricted to objects related to their own node.",
		VerificationSteps: "1. Check whether this is a managed control plane (EKS/GKE/AKS) surfaced via an " +
			"unusual static-pod-like setup — most managed offerings configure this correctly by default and " +
			"this signal is only meaningful on self-hosted/kubeadm clusters. 2. If self-hosted, confirm via " +
			"node/file access to the real running process, since this is inferred from the Pod spec, not the " +
			"live process. 3. If genuinely missing, a compromised kubelet can read/modify objects belonging to " +
			"other nodes — treat as a real finding.",
		Eval: func(f flags) (bool, string) {
			if f.csvContains("authorization-mode", "Node") {
				return true, ""
			}
			return false, "--authorization-mode does not include Node (or is unset)."
		},
	},
	{
		ID: "controlplane-analyzer.apiserver.authz-rbac", Component: ComponentAPIServer, CIS: "1.2.8",
		Title: "kube-apiserver authorization mode does not include RBAC", Severity: findings.SeverityHigh,
		Remediation: "Include RBAC in --authorization-mode.",
		VerificationSteps: "1. Check whether a different, equally strict authorization mode (e.g. Webhook) is " +
			"configured instead of RBAC — --authorization-mode accepts a CSV of modes, and this check only " +
			"flags the absence of the literal string \"RBAC\". 2. If neither RBAC nor an equivalent Webhook " +
			"authorizer is present alongside Node, confirm real requests aren't being silently allowed by " +
			"testing `kubectl auth can-i` as a low-privilege user/ServiceAccount.",
		Eval: func(f flags) (bool, string) {
			if f.csvContains("authorization-mode", "RBAC") {
				return true, ""
			}
			return false, "--authorization-mode does not include RBAC (or is unset)."
		},
	},
	{
		ID: "controlplane-analyzer.apiserver.always-admit", Component: ComponentAPIServer, CIS: "1.2.10",
		Title: "kube-apiserver has the AlwaysAdmit admission plugin enabled", Severity: findings.SeverityHigh,
		Remediation: "Remove AlwaysAdmit from --enable-admission-plugins; it admits every object regardless of any other admission plugin.",
		VerificationSteps: "1. AlwaysAdmit was removed from Kubernetes' compiled-in admission plugins in 1.13+ " +
			"— if the cluster is on a modern version, an explicit --enable-admission-plugins=AlwaysAdmit is " +
			"either a very old fork/distro or a deliberate (and dangerous) override; confirm the cluster's real " +
			"Kubernetes version. 2. If confirmed, every other admission plugin (PodSecurity, ResourceQuota, " +
			"...) is bypassed cluster-wide — no further verification needed, this is a true critical-severity " +
			"issue regardless of the label above.",
		Eval: func(f flags) (bool, string) {
			if f.csvContains("enable-admission-plugins", "AlwaysAdmit") {
				return false, "--enable-admission-plugins explicitly includes AlwaysAdmit."
			}
			return true, ""
		},
	},
	{
		ID: "controlplane-analyzer.apiserver.admission-serviceaccount", Component: ComponentAPIServer, CIS: "1.2.12",
		Title: "kube-apiserver disables the ServiceAccount admission plugin", Severity: findings.SeverityMedium,
		Remediation: "Don't disable the ServiceAccount admission plugin (remove it from --disable-admission-plugins, or include it in --enable-admission-plugins if you've overridden the default list).",
		VerificationSteps: "1. Read the finding's Message to see which of the two ways this was detected " +
			"(explicit --disable-admission-plugins vs. an --enable-admission-plugins allow-list that omits it) " +
			"— the two have different real-world causes (a deliberate hardening mistake vs. an incomplete " +
			"custom plugin list, often from an old copy-pasted flag set). 2. Confirm real ServiceAccounts " +
			"still get tokens auto-provisioned/mounted as expected (`kubectl get sa <name> -o yaml`, check a " +
			"Pod's mounted token) — if they do, some other mechanism may be compensating and this needs deeper " +
			"investigation before treating as a clean true positive.",
		Eval: admissionPluginNotDisabled("ServiceAccount"),
	},
	{
		ID: "controlplane-analyzer.apiserver.admission-namespacelifecycle", Component: ComponentAPIServer, CIS: "1.2.13",
		Title: "kube-apiserver disables the NamespaceLifecycle admission plugin", Severity: findings.SeverityLow,
		Remediation: "Don't disable the NamespaceLifecycle admission plugin (it prevents creating objects in namespaces that are being terminated or don't exist).",
		VerificationSteps: "1. Low-severity and rarely security-critical on its own — confirm it's actually " +
			"disabled (not just omitted from a display) via the same flag inspection as the other admission-plugin " +
			"checks before spending remediation time on it. 2. Try creating an object in a namespace mid-deletion " +
			"(`kubectl delete ns test --wait=false` then immediately try to create something in it) to see if it's " +
			"actually permitted — that's the concrete, observable symptom of this being disabled.",
		Eval: admissionPluginNotDisabled("NamespaceLifecycle"),
	},
	{
		ID: "controlplane-analyzer.apiserver.admission-noderestriction", Component: ComponentAPIServer, CIS: "1.2.14",
		Title: "kube-apiserver disables the NodeRestriction admission plugin", Severity: findings.SeverityHigh,
		Remediation: "Don't disable the NodeRestriction admission plugin; it stops a compromised kubelet from modifying Node/Pod objects outside its own node.",
		VerificationSteps: "1. Confirm the flag inspection (see Message) rather than assuming — this is a " +
			"binary, unambiguous control-plane config fact, not something that needs environment-specific " +
			"judgment. 2. If genuinely disabled, this is a real gap in the kubelet-compromise blast-radius " +
			"containment (a compromised node's kubelet credentials could modify unrelated Node/Pod objects) — " +
			"treat as a true positive and prioritize by how sensitive the workloads on this cluster are.",
		Eval: admissionPluginNotDisabled("NodeRestriction"),
	},
	{
		ID: "controlplane-analyzer.apiserver.audit-log-maxage", Component: ComponentAPIServer, CIS: "1.2.17",
		Title: "kube-apiserver audit log retention (--audit-log-maxage) is too low", Severity: findings.SeverityLow,
		Remediation: "Set --audit-log-maxage to 30 or higher.",
		VerificationSteps: "1. Check whether audit logs are actually shipped off-node to a SIEM/log store " +
			"(common on managed clusters and mature setups) — if so, the on-disk --audit-log-maxage retention " +
			"window matters far less than this finding implies, since the durable copy lives elsewhere; " +
			"consider this a low-priority/likely-mitigated finding in that case. 2. If audit logs are only ever " +
			"on local disk with no shipping, the retention window is the real forensic window after an " +
			"incident — verify the actual configured value against your organization's log-retention policy, " +
			"not just the CIS-recommended 30-day floor.",
		Eval: auditLogNumeric("audit-log-maxage", 30),
	},
	{
		ID: "controlplane-analyzer.apiserver.audit-log-maxbackup", Component: ComponentAPIServer, CIS: "1.2.18",
		Title: "kube-apiserver audit log backup count (--audit-log-maxbackup) is too low", Severity: findings.SeverityLow,
		Remediation: "Set --audit-log-maxbackup to 10 or higher.",
		VerificationSteps: "1. Same caveat as audit-log-maxage: check for off-node log shipping first — a low " +
			"local backup count matters much less if a durable copy exists elsewhere. 2. If logs are local-only, " +
			"confirm actual disk usage/rotation behavior isn't already being constrained by --audit-log-maxsize " +
			"instead (the two flags interact; a low maxbackup with a large maxsize can still retain plenty of " +
			"data, or vice versa).",
		Eval: auditLogNumeric("audit-log-maxbackup", 10),
	},
	{
		ID: "controlplane-analyzer.apiserver.audit-log-maxsize", Component: ComponentAPIServer, CIS: "1.2.19",
		Title: "kube-apiserver audit log max size (--audit-log-maxsize) is too low", Severity: findings.SeverityLow,
		Remediation: "Set --audit-log-maxsize to 100 (MB) or higher.",
		VerificationSteps: "1. Same caveat as the other audit-log checks: check for off-node log shipping first. " +
			"2. If local-only, a low --audit-log-maxsize causes more frequent rotation — check actual audit log " +
			"volume on this cluster (`ls -la /var/log/kubernetes/audit.log*` on a control-plane node, if you " +
			"have access) to judge whether the current setting is actually truncating meaningful history or is " +
			"just conservatively low on a quiet cluster.",
		Eval: auditLogNumeric("audit-log-maxsize", 100),
	},
}

// admissionPluginNotDisabled passes when a named admission plugin is part
// of the effective enabled set: either --enable-admission-plugins is unset
// entirely (the plugin's compiled-in default applies) or, when it is set,
// the plugin is explicitly listed and not present in
// --disable-admission-plugins. This deliberately doesn't fail a cluster
// that never customizes admission plugins at all, which is the common case.
func admissionPluginNotDisabled(plugin string) func(flags) (bool, string) {
	return func(f flags) (bool, string) {
		if f.csvContains("disable-admission-plugins", plugin) {
			return false, fmt.Sprintf("--disable-admission-plugins explicitly disables %s.", plugin)
		}
		if f.isSet("enable-admission-plugins") && !f.csvContains("enable-admission-plugins", plugin) {
			return false, fmt.Sprintf("--enable-admission-plugins is set but does not include %s.", plugin)
		}
		return true, ""
	}
}

func auditLogNumeric(flag string, min int) func(flags) (bool, string) {
	return func(f flags) (bool, string) {
		if !f.isSet("audit-log-path") {
			// No audit log configured at all; that's already reported by
			// the VAP-based audit-log-path check, don't pile on.
			return true, ""
		}
		if f.atLeast(flag, min) {
			return true, ""
		}
		v, ok := f.last(flag)
		if !ok {
			return false, fmt.Sprintf("--%s is not set (recommended: %d or higher).", flag, min)
		}
		return false, fmt.Sprintf("--%s=%s is below the recommended minimum of %d.", flag, v, min)
	}
}

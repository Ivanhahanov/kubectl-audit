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
		Eval:        admissionPluginNotDisabled("ServiceAccount"),
	},
	{
		ID: "controlplane-analyzer.apiserver.admission-namespacelifecycle", Component: ComponentAPIServer, CIS: "1.2.13",
		Title: "kube-apiserver disables the NamespaceLifecycle admission plugin", Severity: findings.SeverityLow,
		Remediation: "Don't disable the NamespaceLifecycle admission plugin (it prevents creating objects in namespaces that are being terminated or don't exist).",
		Eval:        admissionPluginNotDisabled("NamespaceLifecycle"),
	},
	{
		ID: "controlplane-analyzer.apiserver.admission-noderestriction", Component: ComponentAPIServer, CIS: "1.2.14",
		Title: "kube-apiserver disables the NodeRestriction admission plugin", Severity: findings.SeverityHigh,
		Remediation: "Don't disable the NodeRestriction admission plugin; it stops a compromised kubelet from modifying Node/Pod objects outside its own node.",
		Eval:        admissionPluginNotDisabled("NodeRestriction"),
	},
	{
		ID: "controlplane-analyzer.apiserver.audit-log-maxage", Component: ComponentAPIServer, CIS: "1.2.17",
		Title: "kube-apiserver audit log retention (--audit-log-maxage) is too low", Severity: findings.SeverityLow,
		Remediation: "Set --audit-log-maxage to 30 or higher.",
		Eval:        auditLogNumeric("audit-log-maxage", 30),
	},
	{
		ID: "controlplane-analyzer.apiserver.audit-log-maxbackup", Component: ComponentAPIServer, CIS: "1.2.18",
		Title: "kube-apiserver audit log backup count (--audit-log-maxbackup) is too low", Severity: findings.SeverityLow,
		Remediation: "Set --audit-log-maxbackup to 10 or higher.",
		Eval:        auditLogNumeric("audit-log-maxbackup", 10),
	},
	{
		ID: "controlplane-analyzer.apiserver.audit-log-maxsize", Component: ComponentAPIServer, CIS: "1.2.19",
		Title: "kube-apiserver audit log max size (--audit-log-maxsize) is too low", Severity: findings.SeverityLow,
		Remediation: "Set --audit-log-maxsize to 100 (MB) or higher.",
		Eval:        auditLogNumeric("audit-log-maxsize", 100),
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

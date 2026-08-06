package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/apideprecations"
	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/internal/controlplane"
	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/k8sclient"
	"github.com/ivanhahanov/kubectl-audit/internal/k8supdates"
	"github.com/ivanhahanov/kubectl-audit/internal/k8sversion"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
	"github.com/ivanhahanov/kubectl-audit/internal/pss"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
)

// loadEffectiveConfig merges audit.yaml with the persistent CLI flags.
func loadEffectiveConfig(cmd *cobra.Command) (*config.AuditConfig, error) {
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return nil, err
	}

	if flagContextName != "" {
		cfg.Target.Context = flagContextName
	}
	if flagKubeconfig != "" {
		cfg.Target.Kubeconfig = flagKubeconfig
	}
	if len(flagFiles) > 0 {
		cfg.Target.Paths = flagFiles
	}
	if len(flagNamespaces) > 0 {
		cfg.Target.Namespaces = flagNamespaces
		cfg.Target.AllNamespaces = false
	}
	if flagAllNamespaces {
		cfg.Target.AllNamespaces = true
	}
	if len(flagExcludeNamespaces) > 0 {
		if len(flagExcludeNamespaces) == 1 && flagExcludeNamespaces[0] == "" {
			cfg.Target.ExcludeNamespaces = nil
		} else {
			cfg.Target.ExcludeNamespaces = append(cfg.Target.ExcludeNamespaces, flagExcludeNamespaces...)
		}
	}
	if flagIncludeSystemRBAC {
		cfg.Target.IncludeSystemRBAC = true
	}
	if flagCheckUpdates {
		cfg.Target.CheckUpdates = true
	}

	switch {
	case flagMode != "":
		cfg.Target.Mode = config.TargetMode(flagMode)
	case len(flagFiles) > 0 && cfg.Target.Mode == config.ModeBoth:
		cfg.Target.Mode = config.ModeStatic
	}

	if len(flagPolicyDirs) > 0 {
		cfg.Policies.Dirs = append(cfg.Policies.Dirs, flagPolicyDirs...)
	}
	if flagOutputJSON != "" {
		cfg.Output.JSON = flagOutputJSON
	}
	if flagOutputMD != "" {
		cfg.Output.Markdown = flagOutputMD
	}
	if flagOutputCSV != "" {
		cfg.Output.CSV = flagOutputCSV
	}
	if flagFailOn != "" {
		cfg.Output.FailOn = flagFailOn
	}
	if flagReportTemplate != "" {
		cfg.Output.Template = flagReportTemplate
	}
	if len(flagFrameworks) > 0 {
		cfg.Compliance.Frameworks = splitCommaList(flagFrameworks)
	}

	return cfg, nil
}

// splitCommaList expands a StringArray flag's values on commas too, so both
// `--frameworks cis --frameworks fstec` and `--frameworks cis,fstec` work.
func splitCommaList(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

// loadResources loads resources per cfg.Target.Mode from static paths
// and/or a live cluster, returning the combined (post-filter) set, the
// unfiltered set (before the default kube-system/kube-public/kube-node-lease
// exclusion — needed so the control-plane analyzer can still see static pods
// like kube-apiserver-* there even though they're excluded from ordinary
// findings by default), a human-readable target label, and the detected
// cluster's Kubernetes version (e.g. "v1.27.16"; empty for a
// static-manifest-only scan, or if the version couldn't be fetched).
func loadResources(ctx context.Context, cfg *config.AuditConfig) ([]loader.Resource, []loader.Resource, string, string, error) {
	var all []loader.Resource
	var targetParts []string
	var k8sVersion string

	wantStatic := cfg.Target.Mode == config.ModeStatic || cfg.Target.Mode == config.ModeBoth
	wantCluster := cfg.Target.Mode == config.ModeCluster || cfg.Target.Mode == config.ModeBoth

	if wantStatic && len(cfg.Target.Paths) > 0 {
		res, err := loader.LoadStatic(cfg.Target.Paths)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("loading static manifests: %w", err)
		}
		all = append(all, res...)
		targetParts = append(targetParts, fmt.Sprintf("static:%s", strings.Join(cfg.Target.Paths, ",")))
	}

	if wantCluster {
		client, err := k8sclient.New(cfg.Target.Kubeconfig, cfg.Target.Context)
		if err != nil {
			if cfg.Target.Mode == config.ModeCluster {
				return nil, nil, "", "", fmt.Errorf("connecting to cluster: %w", err)
			}
			warnf("cluster unreachable, skipping cluster scan: %v", err)
		} else if versionInfo, verr := client.Discovery.ServerVersion(); verr != nil {
			if cfg.Target.Mode == config.ModeCluster {
				return nil, nil, "", "", fmt.Errorf("connecting to cluster: %w", verr)
			}
			warnf("cluster unreachable, skipping cluster scan: %v", verr)
		} else {
			k8sVersion = versionInfo.GitVersion
			src := loader.SourceLabel(cfg.Target.Context)
			res, err := loader.LoadCluster(ctx, client, loader.ClusterOptions{
				Namespaces:    cfg.Target.Namespaces,
				AllNamespaces: cfg.Target.AllNamespaces || len(cfg.Target.Namespaces) == 0,
				IncludeKinds:  cfg.Target.IncludeKinds,
				ExcludeKinds:  cfg.Target.ExcludeKinds,
				Source:        src,
				Warn:          warnf,
			})
			if err != nil {
				return nil, nil, "", "", fmt.Errorf("loading cluster resources: %w", err)
			}
			all = append(all, res...)
			targetParts = append(targetParts, src)
		}
	}

	// De-duplicate before filtering: DedupeByOwnerChain needs the full
	// owner/owned set intact to tell whether a controller's template is
	// represented elsewhere in the results.
	all = loader.DedupeByOwnerChain(all)

	// Captured before the namespace filter below strips kube-system by
	// default, so the control-plane analyzer can still see static pods like
	// kube-apiserver-* there even on a default-configured scan.
	unfiltered := all

	excludeNamespaces := cfg.Target.ExcludeNamespaces
	if len(cfg.Target.Namespaces) > 0 {
		// An explicit namespace allowlist already scopes the scan; don't
		// also apply the platform-namespace defaults on top of it.
		excludeNamespaces = nil
	}
	all = loader.FilterExcludedNamespaces(all, excludeNamespaces)

	if !cfg.Target.IncludeSystemRBAC {
		all = loader.FilterSystemRBAC(all)
	}

	if len(all) == 0 {
		return nil, nil, "", "", fmt.Errorf("no resources loaded; check -f/--filename/target.paths, cluster connectivity, or your namespace/kind filters")
	}

	return all, unfiltered, strings.Join(targetParts, " + "), k8sVersion, nil
}

func namespaceIndex(resources []loader.Resource) map[string]*loader.Resource {
	idx := map[string]*loader.Resource{}
	for i := range resources {
		if resources[i].GVK().Kind == "Namespace" && resources[i].GVK().Group == "" {
			r := resources[i]
			idx[r.Name()] = &r
		}
	}
	return idx
}

// buildScope explains, once and up front, which categories of check this
// particular scan structurally couldn't run (or could only run
// incompletely) — instead of a reader having to infer it from a dozen
// individually-worded NOT_APPLICABLE compliance rows, or worse, mistaking
// an incomplete-static-scan false positive/negative for a real finding.
func buildScope(cfg *config.AuditConfig, resources []loader.Resource, k8sVersion string, observed map[string]bool) report.Scope {
	var notes []report.ScopeNote

	hasRBAC := false
	hasNetPol := false
	netpolGVKs := netpol.CoverageGVKs()
	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group == "rbac.authorization.k8s.io" {
			hasRBAC = true
		}
		for _, npGVK := range netpolGVKs {
			if gvk == npGVK {
				hasNetPol = true
				break
			}
		}
	}

	if cfg.Target.Mode == config.ModeStatic {
		// A static scan can only ever be as complete as the files it was
		// given — unlike cluster mode, where "no RBAC/NetworkPolicy
		// objects found" is a real, complete answer (modulo the namespace
		// scoping already documented for -n), here it's genuinely
		// ambiguous: it could mean "there really are none" or "they live
		// in a file that wasn't included in this scan."
		if hasRBAC {
			notes = append(notes, report.ScopeNote{
				Title: "RBAC least-privilege analysis",
				Reason: "This is a static-manifest scan: RBAC findings only reflect the Role/ClusterRole/RoleBinding/ClusterRoleBinding " +
					"objects included in the scanned file(s). If your cluster's actual RBAC objects live in files not included here, findings above may be incomplete.",
			})
		} else {
			notes = append(notes, report.ScopeNote{
				Title: "RBAC least-privilege analysis",
				Reason: "No Role/ClusterRole/RoleBinding/ClusterRoleBinding objects were included in this scan — there's nothing to analyze. " +
					"Point this at your full RBAC manifest set (or a live cluster) for a meaningful RBAC report.",
			})
		}
		if hasNetPol {
			notes = append(notes, report.ScopeNote{
				Title: "NetworkPolicy coverage",
				Reason: "This is a static-manifest scan: coverage findings only reflect the NetworkPolicy (or Cilium/Calico) objects " +
					"included in the scanned file(s). A workload flagged as \"no NetworkPolicy\" above may actually be covered by a policy defined elsewhere.",
			})
		} else {
			notes = append(notes, report.ScopeNote{
				Title: "NetworkPolicy coverage",
				Reason: "No NetworkPolicy (or Cilium/Calico) objects were included in this scan. A workload flagged as \"no NetworkPolicy\" " +
					"above may actually be covered by a policy defined elsewhere — point this at your full manifest set (or a live cluster) for an accurate signal.",
			})
		}
	} else if !hasRBAC {
		// Cluster mode but genuinely zero RBAC objects were found (unusual,
		// but the RBAC section would otherwise just look silently empty).
		notes = append(notes, report.ScopeNote{
			Title:  "RBAC least-privilege analysis",
			Reason: "No Role/ClusterRole/RoleBinding/ClusterRoleBinding objects were found — there's nothing to analyze.",
		})
	}

	componentBinaries := map[string]string{
		controlplane.ComponentAPIServer:         "kube-apiserver",
		controlplane.ComponentControllerManager: "kube-controller-manager",
		controlplane.ComponentScheduler:         "kube-scheduler",
		controlplane.ComponentEtcd:              "etcd",
	}
	var missing []string
	for _, c := range []string{controlplane.ComponentAPIServer, controlplane.ComponentControllerManager, controlplane.ComponentScheduler, controlplane.ComponentEtcd} {
		if !observed[c] {
			missing = append(missing, componentBinaries[c])
		}
	}
	if len(missing) > 0 {
		notes = append(notes, report.ScopeNote{
			Title: "Control-plane configuration checks (CIS Section 1/2 — API server, controller-manager, scheduler, etcd flags)",
			Reason: fmt.Sprintf(
				"Not observed via the Kubernetes API: %s. Expected on a managed control plane (EKS/GKE/AKS, ...) where these aren't exposed as Pods, insufficient RBAC to list kube-system Pods, or a static-manifest-only scan.",
				strings.Join(missing, ", ")),
		})
	}

	if k8sVersion == "" {
		notes = append(notes, report.ScopeNote{
			Title: "Version-aware checks (Pod Security Standards profile selection, EOL/support-window, --check-updates)",
			Reason: "No live cluster was scanned, so the Kubernetes version couldn't be detected — these checks assume the latest " +
				"known Kubernetes version instead of your actual target.",
		})
	}

	return report.Scope{OutOfScope: notes}
}

// runScan executes the full pipeline: policy engine, RBAC analyzer,
// NetworkPolicy coverage, Pod Security Standards, and compliance
// scorecards. The single entry point behind `scan`.
func runScan(ctx context.Context, cfg *config.AuditConfig) (report.Result, error) {
	resources, unfiltered, target, k8sVersion, err := loadResources(ctx, cfg)
	if err != nil {
		return report.Result{}, err
	}

	policies, err := engine.LoadRegistry(cfg.Policies, nil)
	if err != nil {
		return report.Result{}, err
	}

	// The policies/controlplane/*.yaml VAP checks (kube-apiserver/etcd/...
	// flag presence-or-equals checks) target static pods that live in
	// kube-system, which is excluded from the ordinary resource set by
	// default — so they're evaluated separately against the unfiltered set,
	// same as the Go-native control-plane checks below.
	var mainPolicies, cpPolicies []*engine.CompiledPolicy
	for _, p := range policies {
		if strings.HasPrefix(p.Meta.ID, controlplane.VAPCheckIDPrefix) {
			cpPolicies = append(cpPolicies, p)
		} else {
			mainPolicies = append(mainPolicies, p)
		}
	}

	policyFindings := engine.EvaluateAll(mainPolicies, resources, engine.EvalOptions{
		Namespaces: namespaceIndex(resources),
		Warn:       warnf,
	})
	cpPolicyFindings := engine.EvaluateAll(cpPolicies, unfiltered, engine.EvalOptions{
		Namespaces: namespaceIndex(unfiltered),
		Warn:       warnf,
	})

	rbacResult, err := rbac.Analyze(resources, target, cfg.Target.IncludeSystemRBAC)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing RBAC: %w", err)
	}

	netpolFindings, err := netpol.Analyze(resources, target)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing network policy coverage: %w", err)
	}

	pssFindings, err := pss.Analyze(resources, target, k8sVersion)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing Pod Security Standards compliance: %w", err)
	}

	// Uses the unfiltered resource set for the same reason as cpPolicyFindings
	// above.
	cpResult, err := controlplane.Analyze(unfiltered, target)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing control-plane configuration: %w", err)
	}

	versionFindings := k8sversion.CheckSupportWindow(k8sVersion, target)

	var updateFindings []findings.Finding
	if cfg.Target.CheckUpdates {
		updateFindings, err = (k8supdates.Client{}).Check(ctx, k8sVersion, target)
		if err != nil {
			warnf("checking for Kubernetes updates: %v", err)
		}
	}

	deprecatedAPIFindings := apideprecations.Analyze(resources, k8sVersion, target)
	if msg := apideprecations.StaleWarning(k8sVersion); msg != "" {
		warnf("%s", msg)
	}

	all := append(policyFindings, rbacResult.Findings...)
	all = append(all, netpolFindings...)
	all = append(all, pssFindings...)
	all = append(all, deprecatedAPIFindings...)
	all = append(all, cpPolicyFindings...)
	all = append(all, cpResult.Findings...)
	all = append(all, versionFindings...)
	all = append(all, updateFindings...)
	all = findings.Dedupe(all)
	findings.SortBySeverity(all)

	result := report.Result{
		GeneratedAt:    time.Now(),
		Target:         target,
		ClusterVersion: k8sVersion,
		Scope:          buildScope(cfg, resources, k8sVersion, cpResult.Observed),
		PoliciesLoaded: len(policies),
		Findings:       all,
		RBACModel:      rbacResult.Model,
	}

	validPolicyIDs := make(map[string]bool, len(policies))
	for _, p := range policies {
		validPolicyIDs[p.Meta.ID] = true
	}

	for _, id := range cfg.Compliance.Frameworks {
		mapping, err := compliance.LoadMapping(id)
		if err != nil {
			return report.Result{}, err
		}
		warnUnknownPolicyIDs(mapping, validPolicyIDs)
		mapping = compliance.OverrideUnobserved(mapping, controlplane.CheckIDPrefix, cpResult.Observed)
		mapping = compliance.OverrideUnobserved(mapping, controlplane.VAPCheckIDPrefix, cpResult.Observed)
		mapping = compliance.OverrideUnobserved(mapping, "version-analyzer.", map[string]bool{"cluster": k8sVersion != ""})
		result.Frameworks = append(result.Frameworks, compliance.BuildScorecard(mapping, all))
	}

	return result, nil
}

// warnUnknownPolicyIDs catches typos in a (typically hand-written, custom)
// compliance mapping: a policyId that doesn't match any loaded VAP policy
// silently produces an always-PASS control instead of an error, since
// BuildScorecard just never finds a matching finding. nativeCheckIds aren't
// checked here — there's no runtime registry of valid Go-native analyzer
// check IDs to check against, only the ones hardcoded in each analyzer
// package's source.
func warnUnknownPolicyIDs(mapping *compliance.Mapping, validPolicyIDs map[string]bool) {
	for _, c := range mapping.Controls {
		for _, pid := range c.PolicyIDs {
			if !validPolicyIDs[pid] {
				warnf("compliance mapping %q, control %q: policyId %q does not match any loaded policy (typo, or missing --policy-dir?) — this control will always show PASS", mapping.ID, c.ID, pid)
			}
		}
	}
}

// writeOutputs writes findings.json and report.md per cfg.Output.
func writeOutputs(cfg *config.AuditConfig, result report.Result) error {
	if cfg.Output.JSON != "" {
		if err := report.WriteJSON(cfg.Output.JSON, result); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.Output.JSON, err)
		}
	}
	if cfg.Output.Markdown != "" {
		tplSource, err := loadReportTemplate(cfg.Output.Template)
		if err != nil {
			return err
		}
		if err := report.WriteMarkdown(cfg.Output.Markdown, result, tplSource); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.Output.Markdown, err)
		}
	}
	if cfg.Output.CSV != "" {
		if err := report.WriteCSV(cfg.Output.CSV, result); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.Output.CSV, err)
		}
	}
	return nil
}

// loadReportTemplate reads a custom report.md.tpl if configured; an empty
// path (the default) tells report.RenderMarkdown to use the embedded
// default template instead.
func loadReportTemplate(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading report template %s: %w", path, err)
	}
	return string(data), nil
}

// applyFailOnGate exits the process with status 1 if any finding meets or
// exceeds the configured --fail-on severity threshold.
func applyFailOnGate(cfg *config.AuditConfig, result report.Result) {
	threshold, ok := cfg.FailOnSeverity()
	if !ok {
		return
	}
	var count int
	for _, f := range result.Findings {
		if f.Severity.AtLeast(threshold) {
			count++
		}
	}
	if count > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d finding(s) at or above severity %s\n", count, threshold)
		os.Exit(1)
	}
}

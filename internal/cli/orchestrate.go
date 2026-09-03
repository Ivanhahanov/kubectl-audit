package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/ivanhahanov/kubectl-audit/internal/logging"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
	"github.com/ivanhahanov/kubectl-audit/internal/pss"
	"github.com/ivanhahanov/kubectl-audit/internal/rbac"
	"github.com/ivanhahanov/kubectl-audit/internal/report"
	secretsanalyzer "github.com/ivanhahanov/kubectl-audit/internal/secrets"
	"github.com/ivanhahanov/kubectl-audit/internal/suppress"
	"github.com/ivanhahanov/kubectl-audit/internal/thirdparty"
	"github.com/ivanhahanov/kubectl-audit/internal/triage"
)

// loadEffectiveConfig merges audit.yaml with the persistent CLI flags.
func loadEffectiveConfig(cmd *cobra.Command) (*config.AuditConfig, error) {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return nil, err
	}

	if flagContextName != "" {
		cfg.Target.Context = flagContextName
	}
	if flagClusterName != "" {
		cfg.Target.ClusterName = flagClusterName
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
	// Boolean flags below use cmd.Flags().Changed(...), not the flag's own
	// zero value — a real bug found by an adversarial audit: "if flagX {
	// cfg.Y = true }" can only ever force a config false→true, never
	// override an audit.yaml true back to false via e.g.
	// "--check-updates=false" (Cobra parses that into flagCheckUpdates =
	// false, so the old `if flagCheckUpdates` branch silently never ran,
	// indistinguishable from the flag not being passed at all).
	// --all-namespaces was hit hardest: config.Default() itself sets
	// AllNamespaces: true, so "--all-namespaces=false" alone used to be
	// ALWAYS a silent no-op regardless of audit.yaml.
	if cmd.Flags().Changed("all-namespaces") {
		cfg.Target.AllNamespaces = flagAllNamespaces
	}
	if len(flagExcludeNamespaces) > 0 {
		if len(flagExcludeNamespaces) == 1 && flagExcludeNamespaces[0] == "" {
			cfg.Target.ExcludeNamespaces = nil
		} else {
			cfg.Target.ExcludeNamespaces = append(cfg.Target.ExcludeNamespaces, flagExcludeNamespaces...)
		}
	}
	if cmd.Flags().Changed("include-system-rbac") {
		cfg.Target.IncludeSystemRBAC = flagIncludeSystemRBAC
	}
	if cmd.Flags().Changed("check-updates") {
		cfg.Target.CheckUpdates = flagCheckUpdates
	}
	if cmd.Flags().Changed("read-secret-values") {
		cfg.Target.ReadSecretValues = flagReadSecretValues
	}
	if cmd.Flags().Changed("no-builtin-exceptions") {
		cfg.DisableBuiltinExceptions = flagNoBuiltinExceptions
	}
	if len(flagDisableBuiltinExceptionIDs) > 0 {
		cfg.DisableBuiltinExceptionIDs = append(cfg.DisableBuiltinExceptionIDs, flagDisableBuiltinExceptionIDs...)
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
	if flagReportView != "" {
		cfg.Output.ReportView = flagReportView
	}
	// Uses Changed(...), not the flag's own zero value — 0 is itself a
	// meaningful, explicit "disable collapsing" value here, same ambiguity
	// as the boolean flags above ("not passed" vs "passed as the zero
	// value" are indistinguishable via the flag var alone).
	if cmd.Flags().Changed("namespace-group-threshold") {
		cfg.Output.NamespaceGroupThreshold = flagNamespaceGroupThreshold
	}
	if cmd.Flags().Changed("group-by-name-pattern") {
		cfg.Output.GroupByNamePattern = &flagGroupByNamePattern
	}
	if !config.ValidReportViews[cfg.Output.ReportView] {
		return nil, fmt.Errorf("invalid --report-view %q: must be one of check, namespace, both", cfg.Output.ReportView)
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

// warnf and debugf are the diagnostic call sites every command shares —
// see internal/logging for the rendering (plain "warning: "/"debug: "
// single lines, no timestamps/structured fields) and root.go's --verbose
// flag for the level. A fresh logger per call is deliberate: these run
// nowhere near a hot path (a handful of times per scan at most), and it
// avoids initialization-order concerns from a package-level logger var
// that would need flagVerbose to already be parsed.
func warnf(format string, args ...any) {
	logging.New(os.Stderr, flagVerbose).Warn(fmt.Sprintf(format, args...))
}

// debugf is warnf's quieter sibling: only shown with --verbose. Use it
// for decisions that are routine/expected on most scans (a third-party
// CRD not being installed, a heuristic simply not matching) where warnf
// would be noise by default, but that are genuinely useful when
// troubleshooting why a check didn't fire.
func debugf(format string, args ...any) {
	logging.New(os.Stderr, flagVerbose).Debug(fmt.Sprintf(format, args...))
}

// homeConfigDir is where kubectl-audit looks for a default audit.yaml when
// --config isn't passed — the same convention ~/.kube/config gives kubectl
// itself: a per-user default an org's Jira/knowledge-base/template setup
// can live in (kept out of any project's git history, see docs/triage.md)
// without needing --config spelled out on every single invocation.
const homeConfigDir = ".kubectl-audit"

// resolveConfigPath decides which audit.yaml (if any) loadEffectiveConfig
// reads: an explicit --config always wins. Otherwise, ~/.kubectl-audit/
// audit.yaml is used if it exists — announced with warnf (not debugf:
// silently changing scan/triage behavior based on a file the user may have
// forgotten exists, or that a CI runner picks up unexpectedly because it
// happens to share a home directory with a developer's config, is exactly
// the kind of surprise worth always surfacing, not hiding behind
// --verbose). Neither existing is not an error — the command just runs on
// built-in defaults, same as always.
func resolveConfigPath() string {
	if flagConfig != "" {
		return flagConfig
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	candidate := filepath.Join(home, homeConfigDir, "audit.yaml")
	if _, err := os.Stat(candidate); err != nil {
		return ""
	}
	warnf("using config from %s (pass --config to use a different one, or delete/rename this file to stop auto-loading it)", candidate)
	return candidate
}

// loadResources loads resources per cfg.Target.Mode from static paths
// and/or a live cluster, returning the combined (post-filter) set, the
// unfiltered set (before the default kube-public/kube-node-lease exclusion
// — needed so the control-plane analyzer can still see static pods like
// kube-apiserver-* there even on a -n allowlist that would otherwise
// exclude them), a human-readable target label, and the detected cluster's
// Kubernetes version (e.g. "v1.27.16"; empty for a static-manifest-only
// scan, or if the version couldn't be fetched).
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
			if cfg.Target.ClusterName != "" {
				src = "cluster:" + cfg.Target.ClusterName
			}
			res, err := loader.LoadCluster(ctx, client, loader.ClusterOptions{
				Namespaces:       cfg.Target.Namespaces,
				AllNamespaces:    cfg.Target.AllNamespaces || len(cfg.Target.Namespaces) == 0,
				IncludeKinds:     cfg.Target.IncludeKinds,
				ExcludeKinds:     cfg.Target.ExcludeKinds,
				Source:           src,
				Warn:             warnf,
				Debug:            debugf,
				ReadSecretValues: cfg.Target.ReadSecretValues,
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

	if !cfg.Target.ReadSecretValues {
		// Belt-and-braces: LoadCluster already never fetches Secrets
		// unless ReadSecretValues is set, but LoadStatic loads whatever a
		// -f manifest contains regardless — this is the single point that
		// guarantees a Secret never reaches policy evaluation without an
		// explicit opt-in, from either source. See loader.FilterSecrets.
		all = loader.FilterSecrets(all)
		unfiltered = loader.FilterSecrets(unfiltered)
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
func buildScope(cfg *config.AuditConfig, resources []loader.Resource, k8sVersion string, observed map[string]bool, detected []thirdparty.Detection) report.Scope {
	var notes []report.ScopeNote
	var caveats []report.ScopeNote

	hasRBAC := false
	hasNetPol := false
	hasIstio := false
	netpolGVKs := netpol.CoverageGVKs()
	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group == "security.istio.io" || gvk.Group == "networking.istio.io" {
			hasIstio = true
		}
		// The istio.mesh-config-outbound-traffic-policy-allow-any check
		// targets a plain ConfigMap (no CRD group of its own) — caught
		// here by name so a scan with only that object still gets the
		// alpha caveat below.
		if gvk.Group == "" && gvk.Kind == "ConfigMap" && r.Name() == "istio" {
			hasIstio = true
		}
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

	if hasIstio {
		caveats = append(caveats, report.ScopeNote{
			Title: "Istio checks (alpha — istio.* policies)",
			Reason: "Each PeerAuthentication/AuthorizationPolicy/DestinationRule/Gateway object is evaluated independently; precedence " +
				"across mesh/namespace/workload-level objects and merged-effective policy (what istioctl x authz check computes from a " +
				"live sidecar) isn't computed. In Istio ambient mode (sidecarless), L4 mTLS is enforced by ztunnel, but L7 rules " +
				"(to.operation.methods/paths/hosts) require a waypoint proxy deployed for the target workload/namespace — without " +
				"one, an L7 AuthorizationPolicy silently isn't enforced at all. Treat istio.* findings as a starting point for manual " +
				"review, not a final verdict.",
		})
	}

	for _, d := range detected {
		if !d.Mismatched() {
			continue
		}
		// Two equally plausible explanations, and no way to tell them apart
		// from the API alone: a non-standard label on an install that's
		// genuinely still there, or a component that was uninstalled while
		// its CRDs (and any CRs) were left behind — `helm uninstall` and
		// most operator-removal docs don't remove CRDs by default, so this
		// is the common case, not an edge case.
		reason := fmt.Sprintf(
			"%s's CRD group (%s) was observed, but no workload matched the label selector this tool looks for to confirm "+
				"the component itself (not just its CRDs) is actually present — see internal/thirdparty/components.yaml. "+
				"Either your %s deployment uses non-standard labels, or %s was uninstalled and its CRDs (and any objects "+
				"using them) were left behind, which is the common case since `helm uninstall` doesn't remove CRDs by "+
				"default. If any %s-specific findings above reference stale objects, that's why.",
			d.Name, d.Group, d.Name, d.Name, d.Name)
		if d.Category == thirdparty.CategorySystem {
			reason += fmt.Sprintf(
				" It also means this tool's built-in PSS exception for %s (internal/suppress/builtin-exclusions.yaml) "+
					"isn't being applied to anything — if it's genuinely still running under different labels, its "+
					"baseline/restricted findings won't be suppressed as expected; add your own `exclusions` rule in "+
					"audit.yaml matching its actual labels, or ignore this if that's fine.",
				d.Name)
		}
		caveats = append(caveats, report.ScopeNote{
			Title:  fmt.Sprintf("%s detected via CRD group only, no matching workload (%s)", d.Name, d.Category),
			Reason: reason,
		})
	}

	return report.Scope{OutOfScope: notes, Caveats: caveats}
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
	netpolReachabilityFindings, err := netpol.AnalyzeReachability(resources, target)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing network policy reachability: %w", err)
	}

	pssFindings, err := pss.Analyze(resources, target, k8sVersion, warnf)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing Pod Security Standards compliance: %w", err)
	}

	// Uses the unfiltered resource set for the same reason as cpPolicyFindings
	// above.
	cpResult, err := controlplane.Analyze(unfiltered, target, warnf)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing control-plane configuration: %w", err)
	}

	versionFindings := k8sversion.CheckSupportWindow(k8sVersion, target, warnf)

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

	// Gated the same as the fetch/filter itself: with --read-secret-values
	// off, resources already contains zero Secret objects (see
	// loader.FilterSecrets above), so this would be a no-op anyway — the
	// explicit gate is just to skip the pointless work, matching the
	// CheckUpdates gating pattern above.
	var secretFindings []findings.Finding
	if cfg.Target.ReadSecretValues {
		secretFindings, err = secretsanalyzer.Analyze(resources, target)
		if err != nil {
			return report.Result{}, fmt.Errorf("analyzing secret values: %w", err)
		}
	}

	all := append(policyFindings, rbacResult.Findings...)
	all = append(all, netpolFindings...)
	all = append(all, netpolReachabilityFindings...)
	all = append(all, pssFindings...)
	all = append(all, deprecatedAPIFindings...)
	all = append(all, cpPolicyFindings...)
	all = append(all, cpResult.Findings...)
	all = append(all, versionFindings...)
	all = append(all, updateFindings...)
	all = append(all, secretFindings...)
	all = findings.Dedupe(all)
	findings.SortBySeverity(all)

	kept, suppressed := suppress.Apply(all, effectiveExclusions(cfg), suppress.BuildLabelIndex(unfiltered))
	detected := thirdparty.Detect(unfiltered, effectiveComponents(cfg))

	// Reuses triage.knowledgeBaseFile: an org's Title/Category/Remediation
	// overrides should read the same whether triaging or reading the
	// static report, not live in two separate places.
	kb, err := triage.ResolveKnowledgeBase(cfg.Triage.KnowledgeBaseFile)
	if err != nil {
		return report.Result{}, fmt.Errorf("loading knowledge base: %w", err)
	}

	result := report.Result{
		GeneratedAt:             time.Now(),
		Target:                  target,
		ClusterVersion:          k8sVersion,
		Scope:                   buildScope(cfg, resources, k8sVersion, cpResult.Observed, detected),
		PoliciesLoaded:          len(policies),
		Findings:                kept,
		Suppressed:              toReportSuppressed(suppressed),
		DetectedComponents:      detected,
		RBACModel:               rbacResult.Model,
		ReportView:              cfg.Output.ReportView,
		MultipleSources:         hasMultipleSources(resources),
		NamespaceGroupThreshold: cfg.Output.NamespaceGroupThreshold,
		GroupByNamePattern:      cfg.Output.GroupByNamePatternEnabled(),
		KnowledgeBase:           kb,
	}

	validPolicyIDs := make(map[string]bool, len(policies))
	for _, p := range policies {
		validPolicyIDs[p.Meta.ID] = true
	}

	// hasRBAC/hasCapsuleTenant feed OverrideUnobservedByPrefix below — a
	// confirmed real bug found by an adversarial compliance-audit pass:
	// without this, a scan with zero RBAC objects reported RBAC-mapped CIS
	// controls as PASS, and a scan with zero Capsule Tenant objects
	// reported the entire capsule.yaml framework as PASS. Same underlying
	// "was this even checked" signal buildScope already computes for its
	// own hasRBAC local — recomputed here rather than plumbed through,
	// since buildScope doesn't currently return it.
	hasRBAC := false
	hasCapsuleTenant := false
	for _, r := range resources {
		gvk := r.GVK()
		if gvk.Group == "rbac.authorization.k8s.io" {
			hasRBAC = true
		}
		if gvk.Group == "capsule.clastix.io" && gvk.Kind == "Tenant" {
			hasCapsuleTenant = true
		}
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
		mapping = compliance.OverrideUnobservedByPrefix(mapping, "rbac.", hasRBAC)
		mapping = compliance.OverrideUnobservedByPrefix(mapping, "rbac-analyzer.", hasRBAC)
		mapping = compliance.OverrideUnobservedByPrefix(mapping, "multitenancy.", hasCapsuleTenant)
		// Uses result.Findings (post-suppression), not all: a suppressed
		// finding is an accepted, documented risk, and shouldn't leave its
		// compliance control showing FAIL.
		result.Frameworks = append(result.Frameworks, compliance.BuildScorecard(mapping, result.Findings))
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
		tplSource, err := loadTemplateFile(cfg.Output.Template)
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

// effectiveExclusions returns the exclusion rules to actually apply: this
// tool's built-in exceptions for well-known privileged infrastructure
// components (see suppress.BuiltinRules), unless disabled wholesale
// (DisableBuiltinExceptions) or individually by ID
// (DisableBuiltinExceptionIDs), followed by the user's own
// audit.yaml/config rules.
func effectiveExclusions(cfg *config.AuditConfig) []config.ExclusionRule {
	if cfg.DisableBuiltinExceptions {
		return cfg.Exclusions
	}
	builtin := suppress.BuiltinRules()
	if len(cfg.DisableBuiltinExceptionIDs) > 0 {
		disabled := map[string]bool{}
		for _, id := range cfg.DisableBuiltinExceptionIDs {
			disabled[id] = true
		}
		filtered := make([]config.ExclusionRule, 0, len(builtin))
		for _, r := range builtin {
			if disabled[r.ID] {
				delete(disabled, r.ID)
				continue
			}
			filtered = append(filtered, r)
		}
		for id := range disabled {
			warnf("disableBuiltinExceptionIds: %q does not match any built-in exclusion rule (typo, or the rule was renamed/removed in this version)", id)
		}
		builtin = filtered
	}
	return append(builtin, cfg.Exclusions...)
}

// effectiveComponents returns the third-party component inventory to
// actually detect against: this tool's built-in list (see thirdparty.Known)
// plus any user-supplied additions (config.ComponentsConfig.Extra) — see
// docs/third-party-operators.md.
func effectiveComponents(cfg *config.AuditConfig) []thirdparty.Component {
	if len(cfg.Components.Extra) == 0 {
		return thirdparty.Known
	}
	return append(append([]thirdparty.Component{}, thirdparty.Known...), cfg.Components.Extra...)
}

// hasMultipleSources reports whether the loaded resources actually came
// from more than one distinct place (several files in a directory scan,
// or --mode both mixing static files with a live cluster) — see
// report.Result.MultipleSources for why this drives whether the report
// prints each finding's per-resource source.
func hasMultipleSources(resources []loader.Resource) bool {
	seen := map[string]bool{}
	for _, r := range resources {
		if r.Source == "" {
			continue
		}
		seen[r.Source] = true
		if len(seen) > 1 {
			return true
		}
	}
	return false
}

// toReportSuppressed adapts suppress.Suppressed (internal/suppress's view)
// to report.SuppressedFinding (internal/report's view) — kept as distinct
// types so report doesn't need to import suppress just for this struct.
func toReportSuppressed(in []suppress.Suppressed) []report.SuppressedFinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]report.SuppressedFinding, len(in))
	for i, s := range in {
		out[i] = report.SuppressedFinding{Finding: s.Finding, Reason: s.Reason}
	}
	return out
}

// loadTemplateFile reads a custom template file if one's configured (a
// report.md.tpl override, or a Jira summary/description template — see
// resolveJiraConfig); an empty path (the default) tells the caller to fall
// back to its own embedded default template instead. Read fresh from disk
// on every call, so editing the file takes effect on the next run, never a
// rebuild.
func loadTemplateFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading template %s: %w", path, err)
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

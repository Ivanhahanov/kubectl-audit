package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/cis"
	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/findings"
	"github.com/ivanhahanov/kubectl-audit/internal/k8sclient"
	"github.com/ivanhahanov/kubectl-audit/internal/loader"
	"github.com/ivanhahanov/kubectl-audit/internal/netpol"
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
	if flagFailOn != "" {
		cfg.Output.FailOn = flagFailOn
	}
	if flagCIS {
		cfg.CIS.Enabled = true
	}

	return cfg, nil
}

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

// loadResources loads resources per cfg.Target.Mode from static paths
// and/or a live cluster, returning the combined set and a human-readable
// target label for the report.
func loadResources(ctx context.Context, cfg *config.AuditConfig) ([]loader.Resource, string, error) {
	var all []loader.Resource
	var targetParts []string

	wantStatic := cfg.Target.Mode == config.ModeStatic || cfg.Target.Mode == config.ModeBoth
	wantCluster := cfg.Target.Mode == config.ModeCluster || cfg.Target.Mode == config.ModeBoth

	if wantStatic && len(cfg.Target.Paths) > 0 {
		res, err := loader.LoadStatic(cfg.Target.Paths)
		if err != nil {
			return nil, "", fmt.Errorf("loading static manifests: %w", err)
		}
		all = append(all, res...)
		targetParts = append(targetParts, fmt.Sprintf("static:%s", strings.Join(cfg.Target.Paths, ",")))
	}

	if wantCluster {
		client, err := k8sclient.New(cfg.Target.Kubeconfig, cfg.Target.Context)
		if err != nil {
			if cfg.Target.Mode == config.ModeCluster {
				return nil, "", fmt.Errorf("connecting to cluster: %w", err)
			}
			warnf("cluster unreachable, skipping cluster scan: %v", err)
		} else if _, verr := client.Discovery.ServerVersion(); verr != nil {
			if cfg.Target.Mode == config.ModeCluster {
				return nil, "", fmt.Errorf("connecting to cluster: %w", verr)
			}
			warnf("cluster unreachable, skipping cluster scan: %v", verr)
		} else {
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
				return nil, "", fmt.Errorf("loading cluster resources: %w", err)
			}
			all = append(all, res...)
			targetParts = append(targetParts, src)
		}
	}

	// De-duplicate before filtering: DedupeByOwnerChain needs the full
	// owner/owned set intact to tell whether a controller's template is
	// represented elsewhere in the results.
	all = loader.DedupeByOwnerChain(all)

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
		return nil, "", fmt.Errorf("no resources loaded; check --files/target.paths, cluster connectivity, or your namespace/kind filters")
	}

	return all, strings.Join(targetParts, " + "), nil
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

// runScan executes the full pipeline (policy engine + RBAC analyzer +
// optional CIS scorecard) shared by `scan`, `rbac analyze`, and
// `cis report`.
func runScan(ctx context.Context, cfg *config.AuditConfig) (report.Result, error) {
	resources, target, err := loadResources(ctx, cfg)
	if err != nil {
		return report.Result{}, err
	}

	policies, err := engine.LoadRegistry(cfg.Policies, nil)
	if err != nil {
		return report.Result{}, err
	}

	policyFindings := engine.EvaluateAll(policies, resources, engine.EvalOptions{
		Namespaces: namespaceIndex(resources),
		Warn:       warnf,
	})

	rbacResult, err := rbac.Analyze(resources, target)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing RBAC: %w", err)
	}

	netpolFindings, err := netpol.Analyze(resources, target)
	if err != nil {
		return report.Result{}, fmt.Errorf("analyzing network policy coverage: %w", err)
	}

	all := append(policyFindings, rbacResult.Findings...)
	all = append(all, netpolFindings...)
	all = findings.Dedupe(all)
	findings.SortBySeverity(all)

	result := report.Result{
		GeneratedAt:    time.Now(),
		Target:         target,
		PoliciesLoaded: len(policies),
		Findings:       all,
		RBACModel:      rbacResult.Model,
	}

	if cfg.CIS.Enabled {
		mapping, err := cis.LoadMapping()
		if err != nil {
			return report.Result{}, err
		}
		scorecard := cis.BuildScorecard(mapping, all)
		result.CIS = &scorecard
	}

	return result, nil
}

// writeOutputs writes findings.json and report.md per cfg.Output.
func writeOutputs(cfg *config.AuditConfig, result report.Result) error {
	if cfg.Output.JSON != "" {
		if err := report.WriteJSON(cfg.Output.JSON, result); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.Output.JSON, err)
		}
	}
	if cfg.Output.Markdown != "" {
		if err := report.WriteMarkdown(cfg.Output.Markdown, result); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.Output.Markdown, err)
		}
	}
	return nil
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

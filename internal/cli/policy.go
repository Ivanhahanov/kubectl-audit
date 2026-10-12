package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ivanhahanov/kubectl-audit/internal/compliance"
	"github.com/ivanhahanov/kubectl-audit/internal/engine"
	"github.com/ivanhahanov/kubectl-audit/internal/k8sclient"
	"github.com/ivanhahanov/kubectl-audit/internal/kyverno"
	"sigs.k8s.io/yaml"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and validate audit policies (real ValidatingAdmissionPolicy YAML).",
	}
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicyListCmd())
	cmd.AddCommand(newPolicyExportCmd())
	return cmd
}

func newPolicyValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <dir> [dir...]",
		Short: "Parse and CEL-compile every policy in the given directories, reporting every error found.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var failed bool
			var total int
			for _, dir := range args {
				policies, err := engine.LoadDir(dir)
				if err != nil {
					failed = true
					fmt.Fprintf(os.Stderr, "%v\n", err)
					continue
				}
				total += len(policies)
				for _, p := range policies {
					fmt.Printf("OK   %s (%s)\n", p.Meta.ID, dir)
				}
			}
			fmt.Printf("\n%d polic%s compiled successfully.\n", total, plural(total, "y", "ies"))
			if failed {
				return fmt.Errorf("one or more policies failed to compile")
			}
			return nil
		},
	}
}

func newPolicyListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every policy that would be loaded for a scan (built-in + --policy-dir), with severity/category/CIS refs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				return err
			}
			policies, err := engine.LoadRegistry(cfg.Policies, nil)
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSEVERITY\tCATEGORY\tCIS")
			for _, p := range policies {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Meta.ID, p.Meta.Severity, p.Meta.Category, joinOrDash(p.Meta.CIS))
			}
			return w.Flush()
		},
	}
	addPolicyDirFlag(cmd)
	return cmd
}

var (
	flagExportFrameworks       []string
	flagExportExcludePolicy    []string
	flagExportOut              string
	flagExportFormat           string
	flagExportKind             string
	flagExportContext          string
	flagExportKubeconfig       string
	flagExportValidationAction string
)

// addExportFilterFlags registers the filtering flags `policy export`
// applies regardless of --format: which subset of the loaded policy set
// (built-in + --policy-dir, same as `policy list`) actually gets written
// out.
func addExportFilterFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&flagExportFrameworks, "frameworks", nil, "only export policies mapped to at least one of these compliance framework(s): cis|fstec|nsa|capsule, or a path to a custom mapping YAML (repeatable or comma-separated; default: export every loaded policy, regardless of framework mapping)")
	cmd.Flags().StringArrayVar(&flagExportExcludePolicy, "exclude-policy", nil, "policy ID to drop from the export regardless of framework (repeatable or comma-separated)")
}

// selectPolicies narrows policies to the --frameworks/--exclude-policy
// selection: with no --frameworks, every loaded policy not explicitly
// excluded; with --frameworks given, only policies mapped to at least one
// control in those framework(s) (loaded via compliance.LoadMapping, same
// as `scan`'s own --frameworks and triage's resolveControlIndex), again
// minus any --exclude-policy. The returned index is nil when --frameworks
// wasn't given (nothing to cite); otherwise it holds exactly the ControlRefs
// each kept policy matched, for callers to attach as "which control(s)
// justify shipping this policy" meta information on the exported document
// (see frameworkAnnotation).
func selectPolicies(policies []*engine.CompiledPolicy) ([]*engine.CompiledPolicy, map[string][]compliance.ControlRef, error) {
	exclude := map[string]bool{}
	for _, id := range splitCommaList(flagExportExcludePolicy) {
		exclude[id] = true
	}

	frameworks := splitCommaList(flagExportFrameworks)
	var controlIndex map[string][]compliance.ControlRef
	if len(frameworks) > 0 {
		mappings := make([]*compliance.Mapping, 0, len(frameworks))
		for _, id := range frameworks {
			m, err := compliance.LoadMapping(id)
			if err != nil {
				return nil, nil, err
			}
			mappings = append(mappings, m)
		}
		controlIndex = compliance.BuildControlIndex(mappings)
	}

	var kept []*engine.CompiledPolicy
	for _, p := range policies {
		if exclude[p.Meta.ID] {
			continue
		}
		if controlIndex != nil && len(controlIndex[p.Meta.ID]) == 0 {
			continue
		}
		kept = append(kept, p)
	}
	return kept, controlIndex, nil
}

// frameworkAnnotation merges a "which compliance controls this policy
// implements" annotation onto a copy of annotations when refs is non-empty
// (i.e. --frameworks was given and matched this policy) — rendered via
// compliance.FormatControlRefs, the same "<Framework>: <ID> — <Title>"
// format tickets/reports already cite controls with, so this meta
// information reads the same way everywhere this tool surfaces it.
func frameworkAnnotation(annotations map[string]string, refs []compliance.ControlRef) map[string]string {
	if len(refs) == 0 {
		return annotations
	}
	out := make(map[string]string, len(annotations)+1)
	for k, v := range annotations {
		out[k] = v
	}
	out["audit.k8s-auditor.io/framework-controls"] = compliance.FormatControlRefs(refs)
	return out
}

// newPolicyExportCmd writes the selected policy set (built-in +
// --policy-dir, filtered by --frameworks/--exclude-policy, same selection
// either way) back out in one of two families, picked by --format:
//
//   - vap (default): plain, real ValidatingAdmissionPolicy YAML — nothing
//     converted, still 100% valid to `kubectl apply -f` as a real in-cluster
//     enforcement policy, same as the source. Meant for curating a subset
//     of the bundled+custom policy set (e.g. only what a given compliance
//     framework requires) to actually enforce.
//   - kyverno: converts into Kyverno policy YAML instead — --kind picks
//     which Kyverno shape(s); see internal/kyverno's package doc for why
//     clusterpolicy needs a live cluster for anything beyond the bundled
//     policy set's resources, while validatingpolicy never does.
//
// Either way, when --frameworks matched a policy, its output gets an
// audit.k8s-auditor.io/framework-controls annotation citing exactly which
// control(s) justified including it (see frameworkAnnotation).
func newPolicyExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the selected policy set (filtered by --frameworks/--exclude-policy) out as plain VAP or converted Kyverno YAML (--format).",
		Long: "--format vap (the default) writes plain ValidatingAdmissionPolicy YAML — nothing converted, " +
			"still 100% valid to `kubectl apply -f` as a real in-cluster enforcement policy — alongside a " +
			"generated ValidatingAdmissionPolicyBinding (--validation-action, default Audit): a bare " +
			"ValidatingAdmissionPolicy enforces nothing at all once applied without one, so both are " +
			"written to the same file as a \"---\"-separated multi-document YAML stream, applied together " +
			"in one `kubectl apply -f`. --format " +
			"kyverno converts instead, with --kind picking the Kyverno shape: validatingpolicy (default) " +
			"is a lossless structural copy — Kyverno's ValidatingPolicy CRD reuses the same " +
			"matchConstraints/validations CEL shapes a VAP already has; clusterpolicy targets the classic " +
			"kyverno.io/v1 ClusterPolicy instead (CEL embedded in validate.cel.expressions, not JMESPath): " +
			"its match blocks need real Kind names (e.g. \"Deployment\"), which a VAP never carries (only " +
			"the GVR, e.g. \"deployments\") — resolved from a built-in table for the bundled policy set, or " +
			"live cluster discovery via --context/--kubeconfig for anything else (custom policies, " +
			"thirdparty CRDs); a policy whose resources can't be resolved either way is skipped for " +
			"clusterpolicy output (with a warning naming it) but still converts fine for validatingpolicy. " +
			"\"both\" writes both Kyverno shapes.",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch flagExportFormat {
			case "vap", "kyverno":
			default:
				return fmt.Errorf("--format must be vap or kyverno, got %q", flagExportFormat)
			}
			switch flagExportKind {
			case "validatingpolicy", "clusterpolicy", "both":
			default:
				return fmt.Errorf("--kind must be validatingpolicy, clusterpolicy, or both, got %q", flagExportKind)
			}
			if flagExportOut == "" {
				return fmt.Errorf("--out is required")
			}
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				return err
			}
			policies, err := engine.LoadRegistry(cfg.Policies, nil)
			if err != nil {
				return err
			}
			kept, controlIndex, err := selectPolicies(policies)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(flagExportOut, 0o755); err != nil {
				return fmt.Errorf("creating %s: %w", flagExportOut, err)
			}

			if flagExportFormat == "vap" {
				switch flagExportValidationAction {
				case "Deny", "Warn", "Audit":
				default:
					return fmt.Errorf("--validation-action must be Deny, Warn, or Audit, got %q", flagExportValidationAction)
				}
				for _, p := range kept {
					policyDoc := map[string]any{
						"apiVersion": "admissionregistration.k8s.io/v1",
						"kind":       "ValidatingAdmissionPolicy",
						"metadata": map[string]any{
							"name":        p.Policy.Name,
							"annotations": frameworkAnnotation(p.Policy.Annotations, controlIndex[p.Meta.ID]),
						},
						"spec": p.Policy.Spec,
					}
					bindingDoc := validatingAdmissionPolicyBinding(p.Policy.Name, flagExportValidationAction)
					if err := writeYAMLDocs(filepath.Join(flagExportOut, p.Meta.ID+".yaml"), policyDoc, bindingDoc); err != nil {
						return err
					}
				}
				fmt.Printf("%d of %d loaded polic%s (each with its Binding, --validation-action %s) exported to %s.\n",
					len(kept), len(policies), plural(len(policies), "y", "ies"), flagExportValidationAction, flagExportOut)
				return nil
			}

			wantValidating := flagExportKind == "validatingpolicy" || flagExportKind == "both"
			wantCluster := flagExportKind == "clusterpolicy" || flagExportKind == "both"

			resolve := kyverno.StaticKindResolver
			var liveClient *k8sclient.Client
			if wantValidating || wantCluster {
				timeout, err := cfg.RequestTimeoutDuration()
				if err != nil {
					return err
				}
				if client, err := k8sclient.New(flagExportKubeconfig, flagExportContext, timeout); err == nil {
					liveClient = client
					resolve = kyverno.ChainKindResolvers(kyverno.StaticKindResolver, kyverno.RESTMapperKindResolver(client.RESTMapper))
				} else {
					warnf("policy export --format kyverno: no live cluster (%v) — clusterpolicy output limited to the built-in Kind table (core/apps/batch/rbac/networking), and Kyverno CRD capability (CEL support, which version-gated features exist) can't be confirmed — pass --context/--kubeconfig to check both", err)
				}
			}

			// A Kind existing doesn't mean it does anything: ClusterPolicy
			// has existed since Kyverno's first release, long before CEL
			// support (1.11+) — an older cluster's CRD schema silently
			// drops the unrecognized validate.cel field (structural-schema
			// pruning), so the exported YAML would apply cleanly and
			// enforce nothing at all. ValidatingPolicy is newer still
			// (1.13+) and may not exist as a CRD at all. Checked for real
			// against the live cluster rather than assumed — skip (not
			// silently ship) whichever target isn't actually supported;
			// the other target, if requested, is unaffected.
			if liveClient != nil {
				if wantValidating {
					ok, err := kyverno.DetectValidatingPolicySupport(liveClient.RESTMapper)
					switch {
					case err != nil:
						warnf("policy export --format kyverno: could not confirm ValidatingPolicy support on this cluster: %v", err)
					case !ok:
						warnf("policy export --format kyverno: this cluster has no ValidatingPolicy CRD (needs Kyverno 1.13+) — skipping validatingpolicy output entirely rather than shipping YAML it can't apply")
						wantValidating = false
					}
				}
				if wantCluster {
					ok, err := kyverno.DetectClusterPolicyCELSupport(cmd.Context(), liveClient.Dynamic)
					switch {
					case err != nil:
						warnf("policy export --format kyverno: could not confirm ClusterPolicy CEL support on this cluster: %v", err)
					case !ok:
						warnf("policy export --format kyverno: this cluster's ClusterPolicy CRD doesn't support CEL (needs Kyverno 1.11+) — applying the exported YAML would silently enforce nothing at all (unknown validate.cel field dropped by schema pruning); skipping clusterpolicy output. Upgrade Kyverno, or use --format vap if your Kubernetes version supports native ValidatingAdmissionPolicy (1.28+ beta, 1.30+ GA)")
						wantCluster = false
					}
				}
				if !wantValidating && !wantCluster {
					return fmt.Errorf("neither validatingpolicy nor clusterpolicy output is supported on this cluster — nothing to export")
				}
			}

			var exported, skipped int
			for _, p := range kept {
				annotations := frameworkAnnotation(p.Policy.Annotations, controlIndex[p.Meta.ID])
				suffix := ".yaml"
				if flagExportKind == "both" {
					suffix = ".validatingpolicy.yaml"
				}
				if wantValidating {
					doc := kyverno.ToValidatingPolicy(p)
					doc["metadata"].(map[string]any)["annotations"] = annotations
					if err := writeYAML(filepath.Join(flagExportOut, p.Meta.ID+suffix), doc); err != nil {
						return err
					}
					exported++
				}
				if wantCluster {
					doc, unresolved := kyverno.ToClusterPolicy(p, resolve)
					if len(unresolved) > 0 {
						fmt.Fprintf(os.Stderr, "warning: %v\n", kyverno.UnresolvedKindError(p.Meta.ID, unresolved))
						skipped++
						continue
					}
					doc["metadata"].(map[string]any)["annotations"] = annotations
					clusterSuffix := ".yaml"
					if flagExportKind == "both" {
						clusterSuffix = ".clusterpolicy.yaml"
					}
					if err := writeYAML(filepath.Join(flagExportOut, p.Meta.ID+clusterSuffix), doc); err != nil {
						return err
					}
					exported++
				}
			}
			fmt.Printf("%d file(s) written to %s, %d skipped (unresolved Kind).\n", exported, flagExportOut, skipped)
			return nil
		},
	}
	addPolicyDirFlag(cmd)
	addExportFilterFlags(cmd)
	cmd.Flags().StringVar(&flagExportOut, "out", "", "output directory, one file per policy (required)")
	cmd.Flags().StringVar(&flagExportFormat, "format", "vap", "output format: vap (plain ValidatingAdmissionPolicy YAML) | kyverno (converted Kyverno policy YAML, see --kind)")
	cmd.Flags().StringVar(&flagExportKind, "kind", "validatingpolicy", "Kyverno target kind, only used with --format kyverno: validatingpolicy|clusterpolicy|both")
	cmd.Flags().StringVar(&flagExportValidationAction, "validation-action", "Audit", "only used with --format vap: validationActions on the generated ValidatingAdmissionPolicyBinding — Deny (blocks matching requests), Warn (admits but warns the client), or Audit (admits, only logged) — without a Binding, an exported ValidatingAdmissionPolicy enforces nothing at all once applied")
	cmd.Flags().StringVar(&flagExportContext, "context", "", "kube context for --format kyverno --kind clusterpolicy/both Kind resolution (default: current context)")
	cmd.Flags().StringVar(&flagExportKubeconfig, "kubeconfig", "", "path to kubeconfig for --format kyverno --kind clusterpolicy/both Kind resolution (default: $KUBECONFIG or ~/.kube/config)")
	return cmd
}

func writeYAML(path string, doc map[string]any) error {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// writeYAMLDocs writes docs to path as a single "---"-separated multi-
// document YAML stream — `kubectl apply -f` applies every document in one
// file together, which is exactly what a ValidatingAdmissionPolicy and its
// Binding need: the Policy alone is inert (see
// validatingAdmissionPolicyBinding's own doc comment), so shipping them as
// two separate files risks one being applied without the other.
func writeYAMLDocs(path string, docs ...map[string]any) error {
	var buf bytes.Buffer
	for i, doc := range docs {
		if i > 0 {
			buf.WriteString("---\n")
		}
		data, err := yaml.Marshal(doc)
		if err != nil {
			return fmt.Errorf("marshaling %s: %w", path, err)
		}
		buf.Write(data)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// validatingAdmissionPolicyBinding builds the ValidatingAdmissionPolicyBinding
// a native ValidatingAdmissionPolicy needs to actually do anything once
// applied: unlike Kyverno's ValidatingPolicy (which carries
// validationActions directly on the policy, see
// kyverno.ToValidatingPolicy), a bare K8s ValidatingAdmissionPolicy is
// inert without a Binding — it's loaded by the apiserver but enforces
// nothing until something binds it with a validationActions list. Exported
// without a scope-narrowing matchResources (binding-level matching is for
// restricting an already-matched policy further, e.g. by namespace
// selector; the policy's own matchConstraints already defines what it
// targets) — so the binding applies the policy everywhere its
// matchConstraints already says it should.
func validatingAdmissionPolicyBinding(policyName, validationAction string) map[string]any {
	return map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata": map[string]any{
			"name": policyName + "-binding",
		},
		"spec": map[string]any{
			"policyName":        policyName,
			"validationActions": []string{validationAction},
		},
	}
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	out := items[0]
	for _, i := range items[1:] {
		out += "," + i
	}
	return out
}

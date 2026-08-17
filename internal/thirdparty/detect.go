// Package thirdparty is a single, extensible inventory of every
// third-party operator/CNI this tool knows about (see components.yaml),
// and detects which ones a scan actually observed — from the one
// genuinely unambiguous signal available: CRD API group presence and/or a
// specific label match among the loaded resources. This is the same
// signal that already determines whether policies/*.yaml's third-party-CRD
// checks (Capsule, Istio, ArgoCD, ...) or internal/suppress's built-in PSS
// exceptions (Cilium, node-exporter) produce anything at all — surfacing
// it explicitly in the report turns "why did/didn't this check fire" from
// an implicit fact into a stated one.
package thirdparty

import (
	"embed"
	"fmt"

	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/loader"
)

//go:embed components.yaml
var componentsFS embed.FS

// Category classifies a Component by whether it needs host/OS-level
// access to function — the same question that decides whether it gets a
// built-in Pod Security Standards exception (see internal/suppress).
type Category string

const (
	CategorySystem      Category = "System"
	CategoryApplication Category = "Application"
)

// Component is one third-party product this tool's bundled policies or
// built-in suppression rules are aware of — see components.yaml for the
// actual data and how to extend it.
type Component struct {
	Name     string            `json:"name"`
	Category Category          `json:"category"`
	Group    string            `json:"group,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type componentsFile struct {
	Components []Component `json:"components"`
}

// Known is every third-party component this tool has checks or exceptions
// for, loaded once from the embedded components.yaml.
var Known = mustLoadKnown()

func mustLoadKnown() []Component {
	data, err := componentsFS.ReadFile("components.yaml")
	if err != nil {
		panic(fmt.Sprintf("thirdparty: reading embedded components.yaml: %v", err))
	}
	var f componentsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		panic(fmt.Sprintf("thirdparty: parsing embedded components.yaml: %v", err))
	}
	return f.Components
}

// helmManagedLabel is the label Helm itself stamps on every object it
// creates — the one unambiguous, tool-agnostic signal for "this specific
// object was installed via `helm install`/`helm upgrade`", as opposed to
// applied directly, templated by Kustomize, or reconciled by ArgoCD/Flux
// without going through Helm.
const helmManagedLabel = "app.kubernetes.io/managed-by"

// Detection is one Known component actually observed in a scan — either
// signal (Group or Labels) counts as "observed".
type Detection struct {
	Component
	// GroupCount is how many objects in Component.Group were loaded (0 if
	// Group is empty). These are the product's own CRD instances (e.g.
	// Capsule Tenants), not the workloads a controller creates from them.
	GroupCount int
	// LabelCount is how many Deployment/StatefulSet/DaemonSet objects
	// matched Component.Labels (0 if Labels is unset) — see isWorkloadKind
	// for why this is restricted to workload kinds rather than any object.
	LabelCount int
	// HelmManaged is true if any matched object (either signal) carries
	// Helm's app.kubernetes.io/managed-by: Helm label. Says nothing about
	// whether a controller reconciling those objects was also
	// Helm-installed — that's a separate, unverified claim this tool
	// doesn't make.
	HelmManaged bool
}

// Mismatched reports the specific, actionable gap this whole Labels-beside-
// Group design exists to catch: the component's CRD is installed
// (GroupCount > 0) but no workload matched its known label selector
// (Labels is set, LabelCount == 0) — e.g. Cilium's CRDs are present but no
// DaemonSet carries k8s-app: cilium. For a CategorySystem component this
// means its built-in PSS exception silently isn't suppressing anything,
// most likely because the real deployment uses different labels than the
// ones this tool verified against the default Helm chart.
func (d Detection) Mismatched() bool {
	return d.Labels != nil && d.GroupCount > 0 && d.LabelCount == 0
}

// Detect returns one Detection per component in components (in that order)
// observed among resources. Best run against the unfiltered resource set
// (before namespace exclusion), since these components commonly live in
// kube-system/a dedicated system namespace that's excluded from ordinary
// findings by default but shouldn't be invisible to detection.
//
// components is explicit rather than always Known so a caller can merge in
// user-supplied entries (see config.ComponentsConfig.Extra) — pass Known
// directly for just the built-in inventory.
func Detect(resources []loader.Resource, components []Component) []Detection {
	byGroup := map[string][]loader.Resource{}
	for _, r := range resources {
		if g := r.GVK().Group; g != "" {
			byGroup[g] = append(byGroup[g], r)
		}
	}

	var out []Detection
	for _, c := range components {
		var matched []loader.Resource
		groupCount := 0
		if c.Group != "" {
			groupCount = len(byGroup[c.Group])
			matched = append(matched, byGroup[c.Group]...)
		}
		labelCount := 0
		if c.Labels != nil {
			for _, r := range resources {
				if isWorkloadKind(r) && labelsMatch(r, c.Labels) {
					labelCount++
					matched = append(matched, r)
				}
			}
		}
		if groupCount == 0 && labelCount == 0 {
			continue
		}
		helmManaged := false
		for _, r := range matched {
			if r.Object.GetLabels()[helmManagedLabel] == "Helm" {
				helmManaged = true
				break
			}
		}
		out = append(out, Detection{
			Component:   c,
			GroupCount:  groupCount,
			LabelCount:  labelCount,
			HelmManaged: helmManaged,
		})
	}
	return out
}

// isWorkloadKind restricts label-based confirmation to the kinds that
// actually run a controller/operator/agent's process — Deployment,
// StatefulSet, DaemonSet. Without this, a leftover Namespace, ServiceAccount,
// or ClusterRole carrying the same common label (many install manifests
// stamp it broadly, not just on the controller Pod template) would look
// like "the component is still running" even after its actual workload —
// and everything it does — was removed, defeating the whole point of this
// second signal.
func isWorkloadKind(r loader.Resource) bool {
	gvk := r.GVK()
	if gvk.Group != "apps" {
		return false
	}
	switch gvk.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		return true
	default:
		return false
	}
}

func labelsMatch(r loader.Resource, want map[string]string) bool {
	have := r.Object.GetLabels()
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

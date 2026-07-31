package loader

// templateOwnerKinds are controller kinds that carry their own pod/job
// template. If a resource's controller owner is one of these kinds *and*
// that owner was itself loaded, the resource's template is already fully
// represented by the owner, so auditing it separately would just report the
// same underlying container spec a second (or third) time under a
// different Kind.
var templateOwnerKinds = map[string]bool{
	"Deployment":  true,
	"ReplicaSet":  true,
	"DaemonSet":   true,
	"StatefulSet": true,
	"Job":         true,
	"CronJob":     true,
}

// DedupeByOwnerChain drops resources whose pod/job template is already
// represented by an owning controller present in the same resource set —
// e.g. a ReplicaSet owned by a Deployment, or a Pod owned by that
// ReplicaSet — so the same underlying container spec isn't audited 2-3
// times under Deployment+ReplicaSet+Pod (or DaemonSet+Pod, CronJob+Job+Pod).
//
// A resource is only dropped when its controller owner was actually loaded
// into this same resource set: if the owner was filtered out (e.g. via
// --exclude-kind), the resource is kept so the template stays represented
// at all.
func DedupeByOwnerChain(resources []Resource) []Resource {
	loadedUIDs := make(map[string]bool, len(resources))
	for _, r := range resources {
		if uid := string(r.Object.GetUID()); uid != "" {
			loadedUIDs[uid] = true
		}
	}

	out := make([]Resource, 0, len(resources))
	for _, r := range resources {
		if isRepresentedByLoadedOwner(r, loadedUIDs) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func isRepresentedByLoadedOwner(r Resource, loadedUIDs map[string]bool) bool {
	for _, owner := range r.Object.GetOwnerReferences() {
		if owner.Controller == nil || !*owner.Controller {
			continue
		}
		if !templateOwnerKinds[owner.Kind] {
			continue
		}
		if loadedUIDs[string(owner.UID)] {
			return true
		}
	}
	return false
}

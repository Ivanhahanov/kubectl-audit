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

// dedupableKinds are the ONLY resource kinds this dedup logic ever drops —
// the kinds that can actually carry a redundant pod/job template relative
// to one of templateOwnerKinds (Deployment->ReplicaSet, ReplicaSet/
// DaemonSet/Job->Pod, CronJob->Job). Restricting to these is load-bearing,
// not a style choice: a Secret, ConfigMap, or anything else can
// legitimately have a Deployment/Job as its controller owner (e.g. a
// cert-rotation controller's Deployment owning the Secret it manages) with
// no template duplication involved at all — that object has its own
// unique, non-redundant content and must never be dropped just because its
// owning controller happened to also be loaded. This was a real bug: CNPG's
// cnpg-controller-manager Deployment owns cnpg-ca-secret/cnpg-webhook-cert,
// and without this restriction both Secrets were silently dropped from
// every scan.
var dedupableKinds = map[string]bool{
	"Pod":        true,
	"ReplicaSet": true,
	"Job":        true,
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
	if !dedupableKinds[r.GVK().Kind] {
		return false
	}
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

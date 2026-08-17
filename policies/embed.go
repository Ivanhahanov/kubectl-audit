// Package policies embeds the bundled default VAP (ValidatingAdmissionPolicy)
// checks shipped with the audit tool.
//
// workload/rbac/network/controlplane/secrets are generic, product-agnostic
// checks. Everything under thirdparty/<product>/ targets one specific
// third-party operator/CNI/tool's own CRD or well-known object — see
// docs/third-party-operators.md for the sourcing behind each.
package policies

import "embed"

//go:embed workload/*.yaml rbac/*.yaml network/*.yaml controlplane/*.yaml secrets/*.yaml thirdparty/*/*.yaml
var FS embed.FS

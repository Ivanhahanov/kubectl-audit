// Package policies embeds the bundled default VAP (ValidatingAdmissionPolicy)
// checks shipped with the audit tool.
package policies

import "embed"

//go:embed workload/*.yaml rbac/*.yaml network/*.yaml controlplane/*.yaml secrets/*.yaml multitenancy/*.yaml istio/*.yaml
var FS embed.FS

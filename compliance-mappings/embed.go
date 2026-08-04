// Package compliancemappings embeds the control tables for every supported
// requirement framework (CIS Kubernetes Benchmark, FSTEC, NSA/CISA
// Kubernetes Hardening Guidance) used to build compliance scorecards.
package compliancemappings

import "embed"

//go:embed *.yaml
var FS embed.FS

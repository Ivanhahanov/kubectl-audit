// Package cismappings embeds the CIS Kubernetes Benchmark control table
// used to build the compliance scorecard.
package cismappings

import "embed"

//go:embed mapping.yaml
var FS embed.FS

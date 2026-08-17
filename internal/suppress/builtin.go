package suppress

import (
	"embed"
	"fmt"

	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
)

//go:embed builtin-exclusions.yaml
var builtinFS embed.FS

type builtinExclusionsFile struct {
	Exclusions []config.ExclusionRule `json:"exclusions"`
}

// builtinRules is loaded once from the embedded builtin-exclusions.yaml —
// see that file for the full rationale, sourcing, and exact PolicyIDs each
// rule covers.
var builtinRules = mustLoadBuiltinRules()

func mustLoadBuiltinRules() []config.ExclusionRule {
	data, err := builtinFS.ReadFile("builtin-exclusions.yaml")
	if err != nil {
		panic(fmt.Sprintf("suppress: reading embedded builtin-exclusions.yaml: %v", err))
	}
	var f builtinExclusionsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		panic(fmt.Sprintf("suppress: parsing embedded builtin-exclusions.yaml: %v", err))
	}
	return f.Exclusions
}

// BuiltinRules returns exclusion rules for well-known, legitimately
// privileged infrastructure DaemonSets — see builtin-exclusions.yaml.
func BuiltinRules() []config.ExclusionRule {
	return builtinRules
}

package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ivanhahanov/kubectl-audit/internal/config"
	"github.com/ivanhahanov/kubectl-audit/policies"
)

// LoadBuiltin parses and compiles the bundled default policy set.
func LoadBuiltin() ([]*CompiledPolicy, error) {
	return loadFromFS(policies.FS, ".")
}

// LoadDir parses and compiles every *.yaml/*.yml file under dir (recursively).
func LoadDir(dir string) ([]*CompiledPolicy, error) {
	var out []*CompiledPolicy
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !isYAML(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		compiled, err := compileFile(path, data)
		if err != nil {
			return err
		}
		out = append(out, compiled...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func loadFromFS(fsys fs.FS, root string) ([]*CompiledPolicy, error) {
	var out []*CompiledPolicy
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !isYAML(path) {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		compiled, err := compileFile(path, data)
		if err != nil {
			return err
		}
		out = append(out, compiled...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

func compileFile(path string, data []byte) ([]*CompiledPolicy, error) {
	docs, err := ParsePolicyDocs(path, data)
	if err != nil {
		return nil, err
	}
	var out []*CompiledPolicy
	for _, doc := range docs {
		meta := ExtractMeta(doc)
		cp, err := Compile(doc, meta)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, cp)
	}
	return out, nil
}

// LoadRegistry assembles the full policy set for a scan: bundled policies
// (unless disabled via config), plus every user-supplied policy directory,
// deduplicated by policy name (a user policy overrides a bundled one with
// the same name) and filtered by policies.disable.
func LoadRegistry(cfg config.PoliciesConfig, extraDirs []string) ([]*CompiledPolicy, error) {
	byID := map[string]*CompiledPolicy{}
	var order []string

	add := func(list []*CompiledPolicy) {
		for _, p := range list {
			if _, exists := byID[p.Meta.ID]; !exists {
				order = append(order, p.Meta.ID)
			}
			byID[p.Meta.ID] = p
		}
	}

	if cfg.BuiltinEnabled() {
		builtin, err := LoadBuiltin()
		if err != nil {
			return nil, fmt.Errorf("loading built-in policies: %w", err)
		}
		add(builtin)
	}

	dirs := append([]string{}, cfg.Dirs...)
	dirs = append(dirs, extraDirs...)
	for _, dir := range dirs {
		custom, err := LoadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("loading policy dir %s: %w", dir, err)
		}
		add(custom)
	}

	sort.Strings(order)
	var out []*CompiledPolicy
	for _, id := range order {
		if cfg.IsDisabled(id) {
			continue
		}
		out = append(out, byID[id])
	}
	return out, nil
}

package triage

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"text/template"

	"sigs.k8s.io/yaml"

	"github.com/ivanhahanov/kubectl-audit/internal/findings"
)

//go:embed knowledgebase/starter-ru.yaml
var starterKnowledgeBaseRU string

// StarterKnowledgeBase returns the bundled knowledge base (Russian
// title/description/remediation for every built-in check) as raw YAML
// source — e.g. for `kubectl audit triage knowledge-base dump` to give a
// user a copyable starting point to adapt to their organization's own
// wording.
func StarterKnowledgeBase() string { return starterKnowledgeBaseRU }

// DefaultKnowledgeBase parses the bundled knowledge base (see
// StarterKnowledgeBase) — applied automatically, on by default (see
// ResolveKnowledgeBase), since most users' first need is exactly this: the
// tool's own bundled wording instead of the English default, no setup
// required.
func DefaultKnowledgeBase() (map[string]findings.KnowledgeBaseEntry, error) {
	return parseKnowledgeBase([]byte(starterKnowledgeBaseRU))
}

// LoadKnowledgeBase reads an external knowledge-base YAML file
// (PolicyID -> {title, description, remediation}) if configured — the same
// empty-path-means-nothing convention as loadTemplateFile
// (internal/cli/orchestrate.go): empty path returns a nil map and no error.
func LoadKnowledgeBase(path string) (map[string]findings.KnowledgeBaseEntry, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading knowledge base file %s: %w", path, err)
	}
	out, err := parseKnowledgeBase(data)
	if err != nil {
		return nil, fmt.Errorf("parsing knowledge base file %s: %w", path, err)
	}
	return out, nil
}

func parseKnowledgeBase(data []byte) (map[string]findings.KnowledgeBaseEntry, error) {
	var out map[string]findings.KnowledgeBaseEntry
	// UnmarshalStrict: a typo'd field ("titel" instead of "title") in a
	// hand-authored knowledgeBaseFile must fail loudly rather than silently
	// produce an entry with an empty override that the tool then falls back
	// past without any indication the entry was ever misspelled.
	if err := yaml.UnmarshalStrict(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MergeKnowledgeBases combines knowledge-base maps in order, later maps
// overriding earlier ones per-PolicyID, field by field (a field left empty
// in a later map doesn't blank out an earlier one's value for it) — so
// ResolveKnowledgeBase can layer a user's triage.knowledgeBaseFile on top
// of the bundled default and correct or extend individual entries without
// repeating the rest of the bundle.
func MergeKnowledgeBases(maps ...map[string]findings.KnowledgeBaseEntry) map[string]findings.KnowledgeBaseEntry {
	out := map[string]findings.KnowledgeBaseEntry{}
	for _, m := range maps {
		for id, v := range m {
			e := out[id]
			if v.Title != "" {
				e.Title = v.Title
			}
			if v.Description != "" {
				e.Description = v.Description
			}
			if v.Remediation != "" {
				e.Remediation = v.Remediation
			}
			if len(v.Labels) > 0 {
				e.Labels = v.Labels
			}
			out[id] = e
		}
	}
	return out
}

// ResolveKnowledgeBase builds the effective knowledge-base lookup table for
// a triage session: the bundled default (see DefaultKnowledgeBase, on by
// default — no config needed) with customFile's entries (if configured)
// merged on top, field by field. This is the map every caller (jira-sync,
// the TUI, the 'j'/'enter' actions) should pass to Resolve.
func ResolveKnowledgeBase(customFile string) (map[string]findings.KnowledgeBaseEntry, error) {
	def, err := DefaultKnowledgeBase()
	if err != nil {
		return nil, fmt.Errorf("parsing bundled knowledge base: %w", err)
	}
	custom, err := LoadKnowledgeBase(customFile)
	if err != nil {
		return nil, err
	}
	return MergeKnowledgeBases(def, custom), nil
}

// ResolvedContent is what a Jira issue template (and the triage TUI's
// detail view — see internal/triage/tui/overlays.go) actually renders: the
// result of layering a knowledge-base override on top of a finding's own
// default content. Kept as its own value (not mutated onto Finding) so
// Technical can unambiguously mean "the tool's original Message, shown
// because a knowledge base replaced Description with something else" —
// mutating Finding.Message in place would lose that distinction.
type ResolvedContent struct {
	Title       string
	Description string
	Remediation string
	// Technical is Finding.Message, populated only when Description came
	// from a knowledge-base override (i.e. differs from the finding's own
	// Message) — so an org-authored explanation never silently hides the
	// tool's own precise technical detail (e.g. which ServiceAccount,
	// which flag) that a knowledge-base entry, being written once for
	// every finding of that check, can't include.
	Technical string
	// Labels are this check's org-defined Jira labels (KnowledgeBaseEntry.
	// Labels) — nil if neither layer sets any. Not templated, unlike the
	// text fields above. See IssueLabels, which merges these with the
	// auto-derived severity/category and triage.jira.extraLabels.
	Labels []string
}

// Resolve computes a finding's effective ticket/detail-view content: start
// from the finding's own Title/Message/Remediation, then apply
// f.KnowledgeBase (set inline on the policy itself — see
// internal/engine/vap.go's kb-title/kb-description/kb-remediation
// annotations), then apply kb[f.PolicyID] (an external
// triage.knowledgeBaseFile) on top of that — so an explicit external
// override always wins over whatever a policy author baked into the check
// itself, field by field. Each knowledge-base field is rendered as a Go
// template against {{.Finding}} before use (see renderKBField), so an
// entry can reference the specific resource a finding fired on —
// "{{.Finding.Resource.Name}} in {{.Finding.Resource.Namespace}}" — instead
// of only generic, check-level text. A template error for one field is
// returned but doesn't block the other fields (or the other
// inline/external layer) from still resolving, so one typo degrades
// gracefully rather than blanking out the whole entry.
func Resolve(f findings.Finding, kb map[string]findings.KnowledgeBaseEntry) (ResolvedContent, error) {
	rc := ResolvedContent{Title: f.Title, Description: f.Message, Remediation: f.Remediation}
	var firstErr error
	apply := func(e findings.KnowledgeBaseEntry) {
		if e.Title != "" {
			if rendered, err := renderKBField("kb-title", e.Title, f); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				rc.Title = rendered
			}
		}
		if e.Description != "" {
			if rendered, err := renderKBField("kb-description", e.Description, f); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				rc.Description = rendered
				rc.Technical = f.Message
			}
		}
		if e.Remediation != "" {
			if rendered, err := renderKBField("kb-remediation", e.Remediation, f); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				rc.Remediation = rendered
			}
		}
		if len(e.Labels) > 0 {
			rc.Labels = e.Labels
		}
	}
	if f.KnowledgeBase != nil {
		apply(*f.KnowledgeBase)
	}
	if e, ok := kb[f.PolicyID]; ok {
		apply(e)
	}
	return rc, firstErr
}

// renderKBField parses and executes tplSource as a Go template against
// {{.Finding}} — the same data shape triage.jira.customFields templates
// already use (see IssueTemplateData), so "reference the finding's own
// resource/severity/etc." works the same way in both places. A knowledge
// base entry with no template actions in it (the common case — plain
// static text) round-trips unchanged, since text/template treats plain
// text as a no-op.
func renderKBField(name, tplSource string, f findings.Finding) (string, error) {
	tpl, err := template.New(name).Funcs(issueTemplateFuncs()).Parse(tplSource)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, struct{ Finding findings.Finding }{f}); err != nil {
		return "", fmt.Errorf("executing %s: %w", name, err)
	}
	return buf.String(), nil
}

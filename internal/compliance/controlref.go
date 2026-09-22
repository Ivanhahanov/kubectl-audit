package compliance

import "strings"

// ControlRef is one compliance-framework control that references a check,
// reduced to just what a report/ticket needs to cite it — see
// BuildControlIndex.
type ControlRef struct {
	Framework string
	ID        string
	Title     string
}

// BuildControlIndex reverses one or more frameworks' control tables
// (loaded via LoadMapping, in the order a caller cares about them — see
// SplitPrimary) into PolicyID/native-check-ID -> the controls that
// reference it. A check can appear under more than one framework; a
// framework can reference the same check from more than one control.
//
// This is how a report or Jira ticket cites "your own standard" instead of
// (or alongside) CIS: nothing here is CIS-specific — it reflects whichever
// mappings were actually passed in, so a private, gitignored
// --frameworks mapping (see docs/custom-checks.md) shows up exactly the
// same way the bundled cis/fstec/nsa ones do.
func BuildControlIndex(mappings []*Mapping) map[string][]ControlRef {
	out := map[string][]ControlRef{}
	for _, m := range mappings {
		for _, c := range m.Controls {
			for _, id := range c.CheckIDs() {
				out[id] = append(out[id], ControlRef{Framework: m.Title, ID: c.ID, Title: c.Title})
			}
		}
	}
	return out
}

// FormatControlRefs renders refs as one display string —
// "<Framework>: <ID> — <Title>", semicolon-separated.
func FormatControlRefs(refs []ControlRef) string {
	if len(refs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		s := r.Framework + ": " + r.ID
		if r.Title != "" {
			s += " — " + r.Title
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// SplitPrimary separates a check's ControlRefs (as returned by
// BuildControlIndex, in --frameworks priority order) into a primary
// display string (the first-listed framework's matching control — i.e.
// whichever framework was requested first, so a private org standard
// takes priority over CIS just by being listed before it) and every other
// matching control's display string. Both are empty when refs is empty —
// callers typically fall back to a check's own Finding.CIS annotation in
// that case, since a check with no framework mapping at all shouldn't
// silently lose its only compliance reference.
func SplitPrimary(refs []ControlRef) (primary, related string) {
	if len(refs) == 0 {
		return "", ""
	}
	return FormatControlRefs(refs[:1]), FormatControlRefs(refs[1:])
}

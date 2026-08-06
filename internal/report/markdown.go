package report

import (
	"os"
	"strings"
)

// WriteMarkdown renders and writes report.md to path. An empty tplSource
// uses the embedded default template.
func WriteMarkdown(path string, r Result, tplSource string) error {
	out, err := RenderMarkdown(r, tplSource)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(out), 0o644)
}

func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// slug turns arbitrary text (a framework ID, a severity name, ...) into an
// anchor-safe id: lowercase, non-alphanumeric runs collapsed to a single
// "-", leading/trailing "-" trimmed. Used to build the report's explicit
// <a id="..."> anchors and their matching Table of Contents links, instead
// of relying on a Markdown renderer's own (inconsistent across GitHub/
// GitLab/editors) heading-to-anchor slugification.
func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case !prevDash:
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

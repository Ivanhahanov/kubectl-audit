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

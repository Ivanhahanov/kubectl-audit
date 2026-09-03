package report

import "os"

// WriteConfluence renders and writes the report as Confluence Server/Data
// Center wiki markup to path. An empty tplSource uses the embedded default
// template. Mirrors WriteMarkdown.
func WriteConfluence(path string, r Result, tplSource string) error {
	out, err := RenderConfluence(r, tplSource)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(out), 0o644)
}

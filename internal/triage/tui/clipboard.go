package tui

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
)

// copyToClipboard writes text to the system clipboard by shelling out to a
// platform utility — pbcopy on macOS, clip on Windows, and (whichever is
// found first) wl-copy/xclip/xsel on Linux. No new Go dependency: this is
// the same mechanism most terminal TUI tools use for a "yank" action, and
// it fails with a clear error instead of silently doing nothing when none
// of these are installed (e.g. a minimal container/CI shell with no
// clipboard utility at all).
func copyToClipboard(text string) error {
	cmd, err := clipboardCommand()
	if err != nil {
		return err
	}
	cmd.Stdin = bytes.NewBufferString(text)
	return cmd.Run()
}

func clipboardCommand() (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("pbcopy"), nil
	case "windows":
		return exec.Command("clip"), nil
	default:
		for _, candidate := range [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
		} {
			if path, err := exec.LookPath(candidate[0]); err == nil {
				return exec.Command(path, candidate[1:]...), nil
			}
		}
		return nil, fmt.Errorf("no clipboard utility found (tried wl-copy, xclip, xsel) — install one, or select/copy the text manually")
	}
}

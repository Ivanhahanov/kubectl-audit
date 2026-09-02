package tui

import (
	"runtime"
	"testing"
)

// TestClipboardCommand_ResolvesForCurrentOS is necessarily light — it can
// only observe the branch matching the OS the test actually runs on — but
// guards the two unconditional platforms (darwin/windows always resolve, no
// PATH lookup) and that a missing-tool error is a real error, not a nil
// *exec.Cmd that would panic in copyToClipboard.
func TestClipboardCommand_ResolvesForCurrentOS(t *testing.T) {
	cmd, err := clipboardCommand()
	switch runtime.GOOS {
	case "darwin":
		if err != nil || cmd == nil {
			t.Fatalf("expected pbcopy to resolve unconditionally on darwin, got cmd=%v err=%v", cmd, err)
		}
		if cmd.Path == "" || cmd.Args[0] != "pbcopy" {
			t.Errorf("expected pbcopy, got %v", cmd.Args)
		}
	case "windows":
		if err != nil || cmd == nil {
			t.Fatalf("expected clip to resolve unconditionally on windows, got cmd=%v err=%v", cmd, err)
		}
		if cmd.Args[0] != "clip" {
			t.Errorf("expected clip, got %v", cmd.Args)
		}
	default:
		// Linux/other: either a real clipboard tool was found (cmd != nil,
		// err == nil) or none was (cmd == nil, err != nil) — either is a
		// valid outcome depending on the test environment (CI containers
		// typically have neither wl-copy, xclip, nor xsel installed), but
		// never both nil or both non-nil.
		if (cmd == nil) == (err == nil) {
			t.Errorf("expected exactly one of (cmd, err) to be set, got cmd=%v err=%v", cmd, err)
		}
	}
}

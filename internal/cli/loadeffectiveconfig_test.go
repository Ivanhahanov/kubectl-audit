package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// TestResolveConfigPath_ExplicitFlagWins guards that --config always beats
// the ~/.kubectl-audit/audit.yaml fallback, even when a home-directory
// config exists.
func TestResolveConfigPath_ExplicitFlagWins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeHomeConfig(t, home, "target:\n  allNamespaces: false\n")

	flagConfig = "/explicit/path/audit.yaml"
	defer func() { flagConfig = "" }()

	if got := resolveConfigPath(); got != "/explicit/path/audit.yaml" {
		t.Errorf("expected the explicit --config path to win, got %q", got)
	}
}

// TestResolveConfigPath_FallsBackToHomeConfigWhenPresent is the actual
// feature: no --config, but ~/.kubectl-audit/audit.yaml exists.
func TestResolveConfigPath_FallsBackToHomeConfigWhenPresent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := writeHomeConfig(t, home, "target:\n  allNamespaces: false\n")

	flagConfig = ""
	if got := resolveConfigPath(); got != want {
		t.Errorf("expected the home config path %q, got %q", want, got)
	}
}

// TestResolveConfigPath_NoHomeConfigReturnsEmpty guards the "nothing set
// up" case stays exactly like before this feature existed — no --config,
// no ~/.kubectl-audit/audit.yaml, so the tool runs on built-in defaults,
// not an error.
func TestResolveConfigPath_NoHomeConfigReturnsEmpty(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // empty — no .kubectl-audit dir at all
	flagConfig = ""
	if got := resolveConfigPath(); got != "" {
		t.Errorf("expected no config path when neither --config nor a home config exist, got %q", got)
	}
}

func writeHomeConfig(t *testing.T, home, content string) string {
	t.Helper()
	dir := filepath.Join(home, homeConfigDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "audit.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestLoadEffectiveConfig_BooleanFlagsCanOverrideConfigBackToFalse guards a
// real bug found by an adversarial audit: loadEffectiveConfig used
// "if flagX { cfg.Y = true }" for every boolean flag, which can only ever
// force a config false->true — "--flag=false" is indistinguishable from
// "--flag not passed at all" via a bool's own zero value, so a config that
// already set one of these true could never be overridden back to false
// via the CLI. Fixed via cmd.Flags().Changed(...). This test constructs a
// real scan command, parses real argv (including explicit "=false" forms,
// the case that was broken), and asserts the merged config reflects the
// flag, not just the audit.yaml default.
func TestLoadEffectiveConfig_BooleanFlagsCanOverrideConfigBackToFalse(t *testing.T) {
	cases := []struct {
		name string
		arg  string
	}{
		{"all-namespaces", "--all-namespaces=false"},
		{"include-system-rbac", "--include-system-rbac=false"},
		{"check-updates", "--check-updates=false"},
		{"read-secret-values", "--read-secret-values=false"},
		{"no-builtin-exceptions", "--no-builtin-exceptions=false"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Reset the package-level flag vars this test cares about so a
			// prior subtest's parse doesn't leak into this one.
			flagAllNamespaces = false
			flagIncludeSystemRBAC = false
			flagCheckUpdates = false
			flagReadSecretValues = false
			flagNoBuiltinExceptions = false
			flagConfig = ""
			flagFiles = nil
			// Isolate from whatever the machine running this test actually
			// has at ~/.kubectl-audit/audit.yaml (see resolveConfigPath) —
			// this test asserts Default()'s own values, which a real
			// developer machine's config could otherwise silently change.
			t.Setenv("HOME", t.TempDir())

			cmd := newScanCmd()
			if err := cmd.Flags().Parse([]string{c.arg}); err != nil {
				t.Fatalf("parsing %q: %v", c.arg, err)
			}
			if !cmd.Flags().Changed(c.name) {
				t.Fatalf("expected cmd.Flags().Changed(%q) to be true after parsing %q — test setup is broken, not the code under test", c.name, c.arg)
			}
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				t.Fatalf("loadEffectiveConfig: %v", err)
			}
			switch c.name {
			case "all-namespaces":
				if cfg.Target.AllNamespaces {
					t.Errorf("expected --all-namespaces=false to override config.Default()'s AllNamespaces: true, got %v", cfg.Target.AllNamespaces)
				}
			case "include-system-rbac":
				if cfg.Target.IncludeSystemRBAC {
					t.Errorf("expected IncludeSystemRBAC to be false")
				}
			case "check-updates":
				if cfg.Target.CheckUpdates {
					t.Errorf("expected CheckUpdates to be false")
				}
			case "read-secret-values":
				if cfg.Target.ReadSecretValues {
					t.Errorf("expected ReadSecretValues to be false")
				}
			case "no-builtin-exceptions":
				if cfg.DisableBuiltinExceptions {
					t.Errorf("expected DisableBuiltinExceptions to be false")
				}
			}
		})
	}
}

// TestLoadEffectiveConfig_UnsetBooleanFlagsLeaveConfigAlone is the
// complementary case: when a boolean flag is never passed on the command
// line at all, loadEffectiveConfig must leave whatever audit.yaml already
// set untouched (this already worked before the fix for the "flag not
// passed, config true" direction — this test guards it stays that way).
func TestLoadEffectiveConfig_UnsetBooleanFlagsLeaveConfigAlone(t *testing.T) {
	flagAllNamespaces = false
	flagIncludeSystemRBAC = false
	flagCheckUpdates = false
	flagReadSecretValues = false
	flagNoBuiltinExceptions = false
	flagConfig = ""
	flagFiles = nil
	t.Setenv("HOME", t.TempDir())

	cmd := newScanCmd()
	if err := cmd.Flags().Parse(nil); err != nil {
		t.Fatalf("parsing empty args: %v", err)
	}
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		t.Fatalf("loadEffectiveConfig: %v", err)
	}
	// config.Default() sets AllNamespaces: true; with no flag passed at
	// all, that default must survive untouched.
	if !cfg.Target.AllNamespaces {
		t.Errorf("expected config.Default()'s AllNamespaces: true to survive when --all-namespaces was never passed, got %v", cfg.Target.AllNamespaces)
	}
}

// resetScanFlags clears every package-level flag var a fresh newScanCmd()
// parse could be affected by — cobra flag vars are package globals, so a
// prior test's parse otherwise leaks into the next one.
func resetScanFlags(t *testing.T) *cobra.Command {
	t.Helper()
	flagOutputs = nil
	flagFrameworks = nil
	flagFrameworksOnly = false
	flagRequestTimeout = ""
	flagConfig = ""
	flagFiles = nil
	t.Setenv("HOME", t.TempDir())
	return newScanCmd()
}

func TestLoadEffectiveConfig_OutputFlagsMergeIntoConfig(t *testing.T) {
	cmd := resetScanFlags(t)
	if err := cmd.Flags().Parse([]string{"--output", "json=out.json", "--output", "console=-"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	cfg, err := loadEffectiveConfig(cmd)
	if err != nil {
		t.Fatalf("loadEffectiveConfig: %v", err)
	}
	if cfg.Output.JSON != "out.json" {
		t.Errorf("expected Output.JSON = %q, got %q", "out.json", cfg.Output.JSON)
	}
	if cfg.Output.Console != "-" {
		t.Errorf("expected Output.Console = \"-\", got %q", cfg.Output.Console)
	}
}

func TestLoadEffectiveConfig_InvalidOutputFormatErrors(t *testing.T) {
	cmd := resetScanFlags(t)
	if err := cmd.Flags().Parse([]string{"--output", "xml=report.xml"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if _, err := loadEffectiveConfig(cmd); err == nil {
		t.Error("expected an error for an unknown --output format, got nil")
	}
}

func TestLoadEffectiveConfig_InvalidRequestTimeoutErrors(t *testing.T) {
	cmd := resetScanFlags(t)
	if err := cmd.Flags().Parse([]string{"--request-timeout", "not-a-duration"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if _, err := loadEffectiveConfig(cmd); err == nil {
		t.Error("expected an error for an invalid --request-timeout, got nil")
	}
}

// TestLoadEffectiveConfig_FrameworksOnlyDefault guards the default-flip
// behavior: choosing a framework explicitly scopes the audit to it by
// default, not choosing one (the implicit "cis" default) keeps the full
// check set, and an explicit --frameworks-only always overrides either
// direction — see AuditConfig.FrameworksOnlyEnabled's own doc comment for
// why "was --frameworks explicitly given" is the signal.
func TestLoadEffectiveConfig_FrameworksOnlyDefault(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"no --frameworks at all: stays false", nil, false},
		{"explicit --frameworks: defaults true", []string{"--frameworks", "cis"}, true},
		{"explicit --frameworks + explicit override false", []string{"--frameworks", "cis", "--frameworks-only=false"}, false},
		{"no --frameworks + explicit override true", []string{"--frameworks-only=true"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := resetScanFlags(t)
			if err := cmd.Flags().Parse(c.args); err != nil {
				t.Fatalf("parsing %v: %v", c.args, err)
			}
			cfg, err := loadEffectiveConfig(cmd)
			if err != nil {
				t.Fatalf("loadEffectiveConfig: %v", err)
			}
			if cfg.Compliance.FrameworksOnly == nil {
				t.Fatal("expected FrameworksOnly to always be resolved (non-nil) after loadEffectiveConfig")
			}
			if got := *cfg.Compliance.FrameworksOnly; got != c.want {
				t.Errorf("args %v: got FrameworksOnly=%v, want %v", c.args, got, c.want)
			}
		})
	}
}

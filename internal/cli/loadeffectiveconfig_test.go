package cli

import "testing"

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

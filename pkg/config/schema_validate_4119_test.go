package config_test

// Regression tests for #4119: `router-advertisement default-lifetime 0` was
// commit-rejected (schema floor was 1) AND conflated with "unset" in the typed
// config, so it could never reach the wire as RFC 4861 §6.2.1's Router
// Lifetime 0 ("this router is NOT a default router"). The schema now accepts 0
// and the compiler records DefaultLifetimeSet so an explicit value (including
// 0) is distinguishable from an absent leaf.
//
// RED-on-revert: restore ValidateInteger(1, ...) and TestSchema4119_...Accepts0
// fails at commit; drop DefaultLifetimeSet and the compiler cases below can no
// longer tell an explicit 0 from unset.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// The RFC 4861 §6.2.1 "not a default router" value (0) must commit.
func TestSchema4119_DefaultLifetime_Accepts0(t *testing.T) {
	if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            default-lifetime 0;
        }
    }
}`); err != nil {
		t.Fatalf("default-lifetime 0 must commit (RFC 4861 §6.2.1 not-a-default-router): %v", err)
	}
}

// The #3895 upper 16-bit bound is unchanged: 65536 still rejected.
func TestSchema4119_DefaultLifetime_StillRejectsOverlarge(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            default-lifetime 65536;
        }
    }
}`)
	if err == nil {
		t.Fatal("default-lifetime 65536 (> uint16 max) must still be rejected")
	}
	if !strings.Contains(err.Error(), "default-lifetime") {
		t.Fatalf("error should reference default-lifetime: %v", err)
	}
}

// compileRAFor builds a ConfigTree from flat set commands, compiles it, and
// returns the RA config for ge-0-0-0.
func compileRAFor(t *testing.T, cmds ...string) *config.RAInterfaceConfig {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra.Interface == "ge-0-0-0" {
			return ra
		}
	}
	t.Fatal("no RA config compiled for ge-0-0-0")
	return nil
}

// An explicit `default-lifetime 0` must compile to DefaultLifetime=0 with the
// set-flag true — the crux of #4119 (0 is not "unset").
func TestCompile4119_ExplicitZero(t *testing.T) {
	ra := compileRAFor(t, "set protocols router-advertisement interface ge-0-0-0 default-lifetime 0")
	if !ra.DefaultLifetimeSet {
		t.Error("DefaultLifetimeSet must be true for an explicit default-lifetime 0")
	}
	if ra.DefaultLifetime != 0 {
		t.Errorf("DefaultLifetime = %d, want 0", ra.DefaultLifetime)
	}
}

// A non-zero explicit value is preserved with the flag set.
func TestCompile4119_ExplicitValue(t *testing.T) {
	ra := compileRAFor(t, "set protocols router-advertisement interface ge-0-0-0 default-lifetime 9000")
	if !ra.DefaultLifetimeSet {
		t.Error("DefaultLifetimeSet must be true for an explicit default-lifetime 9000")
	}
	if ra.DefaultLifetime != 9000 {
		t.Errorf("DefaultLifetime = %d, want 9000", ra.DefaultLifetime)
	}
}

// An absent default-lifetime leaves the flag false so readers apply the 1800
// default. (A bare prefix keeps the RA interface present without setting the
// lifetime.)
func TestCompile4119_Unset(t *testing.T) {
	ra := compileRAFor(t, "set protocols router-advertisement interface ge-0-0-0 prefix 2001:db8::/64")
	if ra.DefaultLifetimeSet {
		t.Error("DefaultLifetimeSet must be false when default-lifetime is absent")
	}
}

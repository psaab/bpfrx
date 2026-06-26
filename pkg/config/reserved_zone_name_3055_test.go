package config

import (
	"strings"
	"testing"
)

// TestReservedZoneNameJunosGlobalFailsCommit asserts that defining a security
// zone literally named "junos-global" is HARD-REJECTED at commit (#3055).
//
// This is the fail-on-revert guard for the security-boundary escape: the
// userspace dataplane (userspace-dp/src/policy.rs) string-matches a
// from-zone/to-zone equal to "junos-global" and reclassifies the policy as a
// device-wide global fallback (JUNOS_GLOBAL_ZONE_ID = u16::MAX) evaluated for
// every flow. An operator-defined zone of this name silently turns its
// zone-scoped policies into device-wide permits for unrelated zone pairs.
// Make validateReservedZoneNamesStrict return nil (or drop its dispatch in
// compiler.go) and this subtest goes green on the BAD config, which is exactly
// the regression it exists to catch.
func TestReservedZoneNameJunosGlobalFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone junos-global",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a security zone named junos-global, got nil error")
	}
	if !strings.Contains(err.Error(), `"junos-global"`) {
		t.Fatalf("error %q does not name the reserved zone junos-global", err.Error())
	}
}

// TestReservedZoneNamesAnyAndJunosHostFailCommit asserts that "any" and
// "junos-host" — reserved policy context tokens — are also rejected as zone
// definition names (#3055).
func TestReservedZoneNamesAnyAndJunosHostFailCommit(t *testing.T) {
	for _, name := range []string{"any", "junos-host"} {
		tree := buildTree(t, []string{
			"set security zones security-zone " + name,
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("expected commit to reject a security zone named %q, got nil error", name)
		}
		if !strings.Contains(err.Error(), `"`+name+`"`) {
			t.Fatalf("error %q does not name the reserved zone %q", err.Error(), name)
		}
	}
}

// TestOrdinaryZoneNameCommits asserts that ordinary zone names (including names
// that merely contain a reserved substring) commit cleanly — the gate matches
// the reserved tokens exactly and must not over-reject (#3055 anti-over-reject).
func TestOrdinaryZoneNameCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// substring of a reserved token must NOT be rejected
		"set security zones security-zone junos-global-edge",
		"set security zones security-zone my-any-zone",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected ordinary zone names: %v", err)
	}
}

// TestJunosGlobalNotReferenceExempt pins the deliberate decoupling of the two
// gates (#3055): "junos-global" is rejected as a zone DEFINITION (the new gate)
// but is NOT a reference-exempt special token — a policy that REFERENCES
// `from-zone junos-global` / `to-zone junos-global` against no defined zone must
// stay HARD-REJECTED by the #2401 reference gate (and warned by ValidateConfig),
// exactly as on master.
//
// This is the fail-on-revert guard for the reference path: if a future refactor
// re-unifies policyZoneSpecialTokens with reservedZoneNames (adding junos-global
// to the exempt set), the reference would become exempt, reach the dataplane,
// and policy.rs:1021 would classify it as a device-wide global rule — the exact
// fail-OPEN this PR closes. Adding junos-global to policyZoneSpecialTokens turns
// the assertions below RED.
func TestJunosGlobalNotReferenceExempt(t *testing.T) {
	// Sanity: junos-global must NOT be in the reference-exempt set.
	if _, exempt := policyZoneSpecialTokens["junos-global"]; exempt {
		t.Fatalf("junos-global must not be a reference-exempt special token — re-unifying the sets re-opens the device-wide-permit fail-open (#3055)")
	}

	for _, side := range []string{"from", "to"} {
		t.Run(side+"-zone", func(t *testing.T) {
			var cmds []string
			if side == "from" {
				// trust is defined; junos-global is referenced but cannot be
				// (and is not) defined as a zone.
				cmds = []string{
					"set security zones security-zone trust",
					"set security policies from-zone junos-global to-zone trust policy p match source-address any",
					"set security policies from-zone junos-global to-zone trust policy p match destination-address any",
					"set security policies from-zone junos-global to-zone trust policy p match application any",
					"set security policies from-zone junos-global to-zone trust policy p then deny",
				}
			} else {
				cmds = []string{
					"set security zones security-zone trust",
					"set security policies from-zone trust to-zone junos-global policy p match source-address any",
					"set security policies from-zone trust to-zone junos-global policy p match destination-address any",
					"set security policies from-zone trust to-zone junos-global policy p match application any",
					"set security policies from-zone trust to-zone junos-global policy p then deny",
				}
			}
			tree := buildTree(t, cmds)
			cfg, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected the reference gate to hard-reject a policy referencing %s-zone junos-global against no defined zone, got nil error", side)
			}
			if !strings.Contains(err.Error(), `"junos-global"`) {
				t.Fatalf("reference-gate error %q does not name junos-global", err.Error())
			}
			_ = cfg

			// And ValidateConfig must warn (junos-global is not warn-exempt either).
			warnCfg, _ := CompileConfigLenient(tree)
			warned := false
			for _, w := range ValidateConfig(warnCfg) {
				if strings.Contains(w, "junos-global") && strings.Contains(w, "zone not defined") {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("expected ValidateConfig to warn that %s-zone junos-global is not defined, got warnings: %v", side, ValidateConfig(warnCfg))
			}
		})
	}
}

// TestReservedZoneNameLenientDowngradesToWarning asserts the tolerant load /
// peer-sync path downgrades a reserved zone-name definition to a warning
// instead of failing the compile, so an already-persisted or peer-synced config
// an older binary accepted still boots (#3055 / #1960 no-brick).
func TestReservedZoneNameLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone junos-global",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a reserved zone name: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "reserved zone name (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded reserved-zone-name warning, got warnings: %v", cfg.Warnings)
	}
}

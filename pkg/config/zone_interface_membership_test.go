package config

import (
	"strings"
	"testing"
)

// TestZoneInterfaceMultiZoneFailsCommit is the fail-on-revert guard for #3072:
// assigning the same interface to two security zones MUST be hard-rejected at
// commit. Without validateZoneInterfaceMembershipStrict (or its dispatch in
// compiler.go) this config compiles cleanly and the userspace interface->zone
// map silently resolves ge-0/0/0.0 to whichever zone name sorts first
// ("aaa" < "trust"), evaluating traffic against the wrong zone's policy — the
// regression this subtest guards. The error must name the interface and BOTH
// conflicting zones.
func TestZoneInterfaceMultiZoneFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone aaa interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject an interface assigned to two security zones, got nil error")
	}
	for _, want := range []string{"ge-0/0/0.0", "aaa", "trust"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestZoneInterfaceMultiZoneLenientDowngradesToWarning asserts the tolerant
// load / peer-sync path downgrades the multi-zone rejection to a warning
// instead of failing the compile, so an already-persisted or peer-synced config
// an older binary accepted still boots (#3072 / #1960 no-brick). The
// interface->zone map keeps its deterministic first-writer-wins resolution, so
// the leniently-loaded config forwards exactly as before — just with an
// operator-visible warning.
func TestZoneInterfaceMultiZoneLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone aaa interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a multi-zone interface config: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone interface membership (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded zone-interface-membership warning, got warnings: %v", cfg.Warnings)
	}
}

// TestZoneInterfaceBareVsUnitMultiZoneFailsCommit asserts the base/unit alias
// overlap the userspace expansion creates is also rejected (#3072): a bare
// physical interface (ge-0/0/0, which claims all its configured units) in one
// zone and a specific unit of it (ge-0/0/0.0) in another zone is the same
// logical interface in two zones.
func TestZoneInterfaceBareVsUnitMultiZoneFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone aaa interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a bare interface and one of its units assigned to two zones, got nil error")
	}
	for _, want := range []string{"aaa", "trust"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestZoneInterfaceSameZoneRepeatNotFlagged asserts listing the same interface
// twice WITHIN one zone (an idempotent `set`, or a bare/unit pair in the same
// zone) is NOT a conflict — only cross-zone duplication is (#3072
// anti-over-reject).
func TestZoneInterfaceSameZoneRepeatNotFlagged(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an interface listed twice in the SAME zone: %v", err)
	}
}

// TestZoneInterfaceDistinctUnitsAcrossZonesNotFlagged asserts two DIFFERENT
// units of one physical interface in two zones (a valid VLAN sub-interface
// split, ge-0/0/0.0 in trust and ge-0/0/0.1 in untrust) is NOT rejected (#3072
// anti-over-reject). The userspace map's coarse bare-base fallback for untagged
// lookups is a first-writer-wins artifact, not a second operator assignment.
func TestZoneInterfaceDistinctUnitsAcrossZonesNotFlagged(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/0.1",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a valid two-unit VLAN split across zones: %v", err)
	}
}

// TestZoneInterfaceOrdinaryConfigUnaffected asserts a normal one-interface-per-
// zone config commits cleanly — the gate does not perturb the common case
// (#3072).
func TestZoneInterfaceOrdinaryConfigUnaffected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security zones security-zone dmz interfaces ge-0/0/2.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an ordinary one-interface-per-zone config: %v", err)
	}
}

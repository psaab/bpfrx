package daemon

import (
	"testing"
)

// TestComputeBootClass covers the #1922 five-case boot predicate table.
// Case 4 (corrupt/too-new) is fatal via #1917 D1 before the predicate runs,
// so it is not represented as a predicate input.
func TestComputeBootClass(t *testing.T) {
	tests := []struct {
		name          string
		hasActive     bool
		everCommitted bool
		nodeID        bool
		want          bootClass
	}{
		// Case 1: fresh / no config, no node-id => bootstrap.
		{"fresh-no-config", false, false, false, bootClassBootstrap},
		// Case 2/3: a valid active config is loaded => normal.
		{"valid-active", true, true, false, bootClassNormal},
		// Case 2: day-0 import-clean (compiled present, committed via Commit).
		{"day0-import", true, true, false, bootClassNormal},
		// Case 5 committed-empty: no active config, but everCommitted => normal.
		{"committed-empty", false, true, false, bootClassNormal},
		// Case 5 never-committed: no active config, never committed => bootstrap.
		{"never-committed", false, false, false, bootClassBootstrap},
		// AGY r1 CRITICAL: post-first-commit-rollback restart. The empty tree
		// on disk (committed=0) compiles to a NON-nil config, so
		// hasActiveConfig is TRUE — but everCommitted is FALSE, so the box
		// must stay in bootstrap, NOT misclassify as normal.
		{"post-rollback-restart-empty-compiled", true, false, false, bootClassBootstrap},
		// HA-node guard (C2/C8): node-id present always resolves NOT-bootstrap,
		// even with no active config and never committed.
		{"ha-node-no-config", false, false, true, bootClassNormal},
		{"ha-node-with-config", true, true, true, bootClassNormal},
		// node-id present + never committed still NOT bootstrap (loud-error
		// handled at call site, but predicate must not enter bootstrap).
		{"ha-node-never-committed", false, false, true, bootClassNormal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeBootClass(tt.hasActive, tt.everCommitted, tt.nodeID)
			if got != tt.want {
				t.Fatalf("computeBootClass(active=%v, committed=%v, nodeID=%v) = %v; want %v",
					tt.hasActive, tt.everCommitted, tt.nodeID, got, tt.want)
			}
		})
	}
}

// TestProtectedInterfaces proves the Item 4 protected set:
//   - default => fxp0 protected.
//   - explicit fxp0 leaf => fxp0 protected.
//   - explicit non-fxp0 leaf => that NIC protected AND fxp0 NARROWED off
//     (OQ-D escape valve).
//
// The lifeline-record contribution is exercised separately (it reads sysfs).
func TestProtectedInterfaces(t *testing.T) {
	// No lifeline record present in the test env, so the set is just the
	// leaf/default contribution.
	t.Run("default-fxp0", func(t *testing.T) {
		set := protectedInterfaces("")
		if !set["fxp0"] {
			t.Fatal("default protected set must contain fxp0")
		}
	})
	t.Run("explicit-fxp0", func(t *testing.T) {
		set := protectedInterfaces("fxp0")
		if !set["fxp0"] {
			t.Fatal("explicit fxp0 leaf must protect fxp0")
		}
	})
	t.Run("explicit-non-fxp0-narrows-fxp0-off", func(t *testing.T) {
		set := protectedInterfaces("ge-0-0-3")
		if !set["ge-0-0-3"] {
			t.Fatal("explicit non-fxp0 leaf must protect that interface")
		}
		if set["fxp0"] {
			t.Fatal("explicit non-fxp0 leaf must NARROW fxp0 out of the auto-protection (OQ-D)")
		}
	})

	// OQ-D BLOCKER (Codex r3): the lifeline-record union must NOT silently
	// re-add fxp0 when an explicit non-fxp0 leaf narrowed it off. Exercised
	// via the pure core with an injected lifeline name.
	t.Run("lifeline-fxp0-does-not-defeat-narrowing", func(t *testing.T) {
		set := protectedInterfacesWith("ge-0-0-3", "fxp0")
		if !set["ge-0-0-3"] {
			t.Fatal("explicit non-fxp0 leaf must protect that interface")
		}
		if set["fxp0"] {
			t.Fatal("lifeline resolving to fxp0 must NOT re-add fxp0 when narrowed off (OQ-D)")
		}
	})
	t.Run("lifeline-protected-when-no-leaf", func(t *testing.T) {
		set := protectedInterfacesWith("", "ge-0-0-5")
		if !set["fxp0"] || !set["ge-0-0-5"] {
			t.Fatalf("no leaf: fxp0 + lifeline both protected; got %v", set)
		}
	})
	t.Run("lifeline-added-when-leaf-is-fxp0", func(t *testing.T) {
		set := protectedInterfacesWith("fxp0", "ge-0-0-5")
		if !set["fxp0"] || !set["ge-0-0-5"] {
			t.Fatalf("explicit fxp0 leaf: fxp0 + lifeline both protected; got %v", set)
		}
	})
}

// TestReadLifelineRecord proves the persisted record round-trips and an
// absent/blank record reports not-found.
func TestReadLifelineRecord(t *testing.T) {
	// Redirect the record path into a temp file for the test.
	t.Cleanup(func() { lifelineRecordFileForTest = "" })
	tmp := t.TempDir() + "/lifeline-interface"
	lifelineRecordFileForTest = tmp

	if _, ok := readLifelineRecordAt(tmp); ok {
		t.Fatal("absent record reported found")
	}

	want := lifelineRecord{PCIAddr: "0000:05:00.0", MAC: "52:54:00:ab:cd:ef"}
	if err := writeLifelineRecordAt(tmp, want); err != nil {
		t.Fatal(err)
	}
	got, ok := readLifelineRecordAt(tmp)
	if !ok {
		t.Fatal("record reported not-found after write")
	}
	if got.PCIAddr != want.PCIAddr || got.MAC != want.MAC {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

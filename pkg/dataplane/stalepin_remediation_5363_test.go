package dataplane

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestLivePinABIMismatchUsesStalePinRemediation is the #5363 core: when the
// embedded shim's map ABI differs from the RUNNING daemon's LIVE pinned map,
// the live pin is ALWAYS the stale side — it is the OLD daemon's map, while the
// embedded shim is the intended (and un-broken) deploy target. So the
// remediation must be the full-dataplane-reload guidance, NEVER `make generate`
// (which would tell the operator to rebuild a shim that is not broken).
//
// This is direction-INDEPENDENT: it holds both when the embedded shape is the
// larger side AND when it is the smaller side. Both cases exercise the SAME
// live-pin mismatch branch, so a single stale-pin remediation is correct for
// the whole branch — no MaxEntries >-vs-< heuristic.
//
// #5364 CORRECTION: the userspace_cpumap "16 vs 256 MaxEntries" gap that #5363
// originally used as its example is NOT a genuine ABI break — a CPUMAP's
// MaxEntries is clamped to nr_possible_cpus at load, so the map is pinned at
// nr_possible_cpus and MapSpec.Compatible accepts it. That case is now handled
// by livePinRefABI and is no longer rejected (see TestCPUMapLivePinPossibleCPU*).
// The cases below therefore use a genuine cpumap ABI break (a ValueSize change)
// and a genuine non-cpumap MaxEntries drift, both of which are still stale-pin
// mismatches that must carry the full-reload remediation.
//
// RED-on-revert: with the pre-#5363 code the live-pin error appended
// userspaceShimGenerateRemediation ("Re-run `make generate-userspace-xdp`."),
// so this test's "must NOT contain make generate-userspace-xdp" and "must
// contain the stale-pin phrase" assertions both flip red.
func TestLivePinABIMismatchUsesStalePinRemediation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mapName      string
		embedded     *ebpf.MapSpec   // added to the shim spec (nil => already present)
		pinnedShape  userspaceMapABI // live pin the fake reader reports
		wantDiffFrag string          // substring naming the offending field
	}{
		{
			// #5364: a GENUINE cpumap ABI break. The MaxEntries axis is
			// CPU-count-clamped and no longer diffs (the map is pinned at
			// nr_possible_cpus), so this uses a ValueSize change — a real
			// cross-version ABI break that is still a stale-pin mismatch.
			// The live pin's MaxEntries is nr_possible_cpus (what a fresh
			// daemon actually pins) so only ValueSize drives the diff.
			name:         "cpumap-genuine-valuesize-break",
			mapName:      "userspace_cpumap",
			embedded:     &ebpf.MapSpec{Type: ebpf.CPUMap, KeySize: 4, ValueSize: 8, MaxEntries: 256},
			pinnedShape:  userspaceMapABI{Type: ebpf.CPUMap, KeySize: 4, ValueSize: 4, MaxEntries: uint32(ebpf.MustPossibleCPU())},
			wantDiffFrag: "ValueSize embedded=8 pinned=4",
		},
		{
			// A shim-declared shared map (dnat_table): embedded shape is the
			// correct one (so the earlier expected-shape arm passes); only the
			// LIVE pin drifts, so the mismatch is caught by the live-pin arm.
			name:         "dnat-table-live-pin-drift",
			mapName:      "dnat_table",
			embedded:     nil,
			pinnedShape:  userspaceMapABI{Type: ebpf.Hash, KeySize: 12, ValueSize: 8, MaxEntries: 16, Flags: unix.BPF_F_NO_PREALLOC},
			wantDiffFrag: "MaxEntries",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			base := validABIBaseSpec()
			if tt.embedded != nil {
				base.Maps[tt.mapName] = tt.embedded
			}

			// RED-on-revert guard: the base spec passes the legacy
			// presence+MaxEntries validator, so the ONLY reject signal is the
			// live-pin ABI comparison whose remediation we are asserting.
			if err := legacyPresenceMaxEntriesValidate(base); err != nil {
				t.Fatalf("legacy validator rejected base (%v); cannot prove RED-on-revert", err)
			}

			reader := pinReaderWithOverride(base, map[string]userspaceMapABI{tt.mapName: tt.pinnedShape})
			err := validateUserspaceShimSpecWith(base, reader)
			if err == nil {
				t.Fatalf("want live-pin ABI mismatch on %s, got nil", tt.mapName)
			}

			msg := err.Error()
			// The mismatch is still reported, naming the map and the field.
			for _, want := range []string{tt.mapName, "ABI-incompatible", tt.wantDiffFrag} {
				if !strings.Contains(msg, want) {
					t.Fatalf("err = %v, want substring %q", err, want)
				}
			}
			// The remediation is the full-reload / stale-pin guidance...
			if !strings.Contains(msg, userspaceShimStalePinRemediation) {
				t.Fatalf("err = %v, want stale-pin remediation constant", err)
			}
			for _, phrase := range []string{"FULL dataplane reload", "stale pin", "released"} {
				if !strings.Contains(msg, phrase) {
					t.Fatalf("err = %v, want distinctive stale-pin phrase %q", err, phrase)
				}
			}
			// ...and NEVER the "rebuild the shim" remediation.
			if strings.Contains(msg, "make generate-userspace-xdp") {
				t.Fatalf("err = %v, live-pin mismatch must NOT tell the operator to rebuild the shim", err)
			}
		})
	}
}

// TestSSOTDriftKeepsGenerateRemediation proves the #5363 fix is SURGICAL: the
// embedded-vs-Go-SSOT drift sites are UNCHANGED and still emit the `make
// generate-userspace-xdp` remediation. Here an embedded dnat_table value_size
// drifts from the Go single source of truth on a FRESH node (no live pin), so
// the reject comes from validateSharedMapExpectedABI, not the live-pin arm — a
// genuine "the embedded shim binary drifted from its Go contract" situation
// where rebuilding the shim IS the right action.
//
// RED-on-revert direction: if someone globally swapped the constant (applying
// the stale-pin remediation to the SSOT-drift sites too), this test flips red.
func TestSSOTDriftKeepsGenerateRemediation(t *testing.T) {
	t.Parallel()

	base := validABIBaseSpec()
	base.Maps["dnat_table"].ValueSize = 16 // drift from the Go SSOT (sizeOf[DNATValue]()==8)

	err := validateUserspaceShimSpecWith(base, noPinReader())
	if err == nil {
		t.Fatal("want dnat_table value_size drift error on fresh node, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"dnat_table", "value_size", "make generate-userspace-xdp"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("err = %v, want substring %q (SSOT-drift site must keep make-generate)", err, want)
		}
	}
	// The SSOT-drift remediation must NOT be the stale-pin one.
	if strings.Contains(msg, "FULL dataplane reload") {
		t.Fatalf("err = %v, embedded-vs-Go SSOT drift must NOT use the stale-pin remediation", err)
	}
}

package dataplane

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestVerifyEmbeddedUserspaceShim runs the #1864 verify-only load
// against the embedded (git-tracked) shim object. On a privileged
// host this catches a bad tracked artifact in `make test`; without
// CAP_BPF it skips.
func TestVerifyEmbeddedUserspaceShim(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_BPF for BPF_PROG_LOAD")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	if err := VerifyEmbeddedUserspaceShim(); err != nil {
		if errors.Is(err, ErrUserspaceShimVerifierReject) {
			t.Fatalf("embedded shim object REJECTED by kernel verifier (#1864 failure mode):\n%v", err)
		}
		t.Fatalf("verify-only load failed: %v", err)
	}
}

// TestVerifyUserspaceShimShrinkEquivalence proves the hash-map
// MaxEntries shrink is verifier-neutral on this kernel: the embedded
// PASS object passes both unmodified and shrunk, and the preserved
// #1864 incident REJECT object (testdata, never embedded) rejects
// both ways. This is the gate behind making the shrunk C2 pre-flight
// authoritative while production loads full map geometry. Root-only
// and slow (~20-40s: the unmodified loads create the full 10M-entry
// dnat_table and the REJECT walks ~1M insns twice).
func TestVerifyUserspaceShimShrinkEquivalence(t *testing.T) {
	if testing.Short() {
		t.Skip("slow verifier walks; skipped in -short")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_BPF for BPF_PROG_LOAD")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}

	load := func(t *testing.T, path string) *ebpf.CollectionSpec {
		t.Helper()
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			t.Fatalf("load spec %s: %v", path, err)
		}
		return spec
	}

	goodSpec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load embedded spec: %v", err)
	}
	for _, shrink := range []bool{false, true} {
		if err := verifyUserspaceShimSpecWithShrink(goodSpec.Copy(), shrink); err != nil {
			t.Fatalf("embedded PASS object failed with shrink=%v: %v", shrink, err)
		}
	}

	badSpec := load(t, "testdata/userspace_xdp_bpfel_1864_reject.o")
	for _, shrink := range []bool{false, true} {
		err := verifyUserspaceShimSpecWithShrink(badSpec.Copy(), shrink)
		if !errors.Is(err, ErrUserspaceShimVerifierReject) {
			t.Fatalf("incident REJECT object with shrink=%v: want verifier reject, got %v", shrink, err)
		}
	}
}

// TestVerifyUserspaceShimSpecValidationOrder guards the SMR r2
// ordering trap: spec validation must see the UNMODIFIED spec (it
// asserts dnat_table.MaxEntries == userspaceShimMaxSessions), while
// the verify-only load shrinks hash maps afterwards on a copy. If the
// shrink ever leaked into the validated spec, validation would fail
// every PASS object with a drift error — this test proves the
// embedded spec still validates AND that verification (which shrinks
// internally) does not mutate the spec it was given.
func TestVerifyUserspaceShimSpecValidationOrder(t *testing.T) {
	spec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load embedded spec: %v", err)
	}
	if err := validateUserspaceShimSpec(spec); err != nil {
		t.Fatalf("embedded spec failed production validation: %v", err)
	}
	dnat, ok := spec.Maps[userspaceShimCompatibilityDNATName]
	if !ok {
		t.Fatalf("embedded spec missing %s", userspaceShimCompatibilityDNATName)
	}
	if dnat.MaxEntries != userspaceShimMaxSessions {
		t.Fatalf("dnat_table MaxEntries = %d, want %d", dnat.MaxEntries, userspaceShimMaxSessions)
	}
}

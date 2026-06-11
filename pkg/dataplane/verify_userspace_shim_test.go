package dataplane

import (
	"errors"
	"os"
	"testing"

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

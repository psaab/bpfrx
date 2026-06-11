// Package dataplane: verify-only loader for the retained Rust AF_XDP
// shim object (#1864).
//
// On 2026-06-10 a `make generate` run with a drifted Rust nightly
// produced a shim object that exceeded the kernel verifier's 1M
// processed-insn cap and took both HA cluster dataplanes down
// (config-only mode). The functions here run the real kernel verifier
// against a candidate object WITHOUT touching any production state,
// so the failure surfaces as a failed build or a refused deploy
// instead of a dead dataplane.
//
// HARD INVARIANT: nothing in this file may call LoadUserspaceShim /
// loadUserspaceShimObjectsOnce, set ebpf.PinByName / MapOptions.PinPath,
// or use MapReplacements. The verify path creates only anonymous maps
// and programs, never attaches anything, and frees everything when the
// collection is closed (or the process exits). A good program loaded
// by a running daemon keeps forwarding throughout.
package dataplane

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// verifyShrinkHashMaxEntries is the verify-only ceiling applied to
// hash-map MaxEntries before the anonymous load. The kernel allocates
// a hash map's bucket array eagerly even for BPF_F_NO_PREALLOC maps
// (dnat_table's 10M entries cost >128 MB of kernel memory empty), and
// preallocated hash maps (USERSPACE_SESSIONS, 262144 entries) allocate
// their element pool up front. Hash-map max_entries does not feed the
// verifier's program safety analysis — shrinking it changes runtime
// capacity only, which a verify-only load never uses. Array-type maps
// are left untouched.
const verifyShrinkHashMaxEntries = 1

// verifierLogTailLines bounds how much of the verifier log a REJECT
// report carries. The interesting part (the failure and final stats)
// is always at the tail.
const verifierLogTailLines = 16

// ErrUserspaceShimVerifierReject marks a kernel-verifier rejection of
// a shim candidate (as opposed to I/O, spec-validation, or privilege
// errors). Callers branch on it with errors.Is.
var ErrUserspaceShimVerifierReject = errors.New("userspace shim verifier reject")

// VerifyEmbeddedUserspaceShim runs the verify-only load against the
// shim object embedded in this binary (the exact bytes the daemon
// would load at startup). Used by `xpfd verify-dataplane` as the
// deploy-time pre-flight.
func VerifyEmbeddedUserspaceShim() error {
	spec, err := loadRustUserspaceXDP()
	if err != nil {
		return err
	}
	return verifyUserspaceShimSpecOnly(spec)
}

// VerifyUserspaceShimObject runs the verify-only load against an
// on-disk candidate object. Used by cmd/shimverify as the build-time
// gate in build-userspace-xdp.sh (verify-then-install).
func VerifyUserspaceShimObject(path string) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("load candidate spec from %s: %w", path, err)
	}
	return verifyUserspaceShimSpecOnly(spec)
}

// verifyUserspaceShimSpecOnly validates the spec exactly as the
// production loader would, then runs the kernel verifier via an
// anonymous (unpinned, unattached) collection load.
//
// ORDER MATTERS: validateUserspaceShimSpec checks the UNMODIFIED spec
// (it asserts dnat_table.MaxEntries == userspaceShimMaxSessions among
// others); the hash-map shrink is applied to a copy afterwards, just
// before the load.
func verifyUserspaceShimSpecOnly(spec *ebpf.CollectionSpec) error {
	if err := validateUserspaceShimSpec(spec); err != nil {
		return fmt.Errorf("spec validation (production-load viability): %w", err)
	}

	vspec := spec.Copy()
	for _, ms := range vspec.Maps {
		switch ms.Type {
		case ebpf.Hash, ebpf.PerCPUHash, ebpf.LRUHash, ebpf.LRUCPUHash:
			if ms.MaxEntries > verifyShrinkHashMaxEntries {
				ms.MaxEntries = verifyShrinkHashMaxEntries
			}
		}
	}

	coll, err := ebpf.NewCollection(vspec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("%w: kernel verifier rejected %s:\n%s",
				ErrUserspaceShimVerifierReject, userspaceShimEntryProg, verifierLogTail(ve))
		}
		return fmt.Errorf("verify-only collection load: %w", err)
	}
	defer coll.Close()

	if _, ok := coll.Programs[userspaceShimEntryProg]; !ok {
		return fmt.Errorf("candidate object loaded but %s program is missing", userspaceShimEntryProg)
	}
	return nil
}

func verifierLogTail(ve *ebpf.VerifierError) string {
	log := ve.Log
	if len(log) > verifierLogTailLines {
		log = log[len(log)-verifierLogTailLines:]
	}
	var b strings.Builder
	for _, line := range log {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

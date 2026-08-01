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
//
// The one interaction with production state is READ-ONLY: the shared
// validateUserspaceShimSpec gate now inspects the running daemon's live
// pinned maps to catch an ABI incompatibility at the pre-flight rather
// than after the old daemon is stopped (#5307). That inspection opens a
// handle, reads the map shape, and closes it — it never unpins,
// attaches, or mutates the pin, so the running daemon keeps forwarding.
package dataplane

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// UserspaceShimMinVerifierHeadroomPct is the committed floor for how much
// of the kernel verifier's 1M processed-insn budget a shim candidate must
// leave unused (#4555).
//
// The 2026-06-10 incident (#1864) was a shim object that blew the cap and
// took both HA dataplanes down. The gates added after it are all BINARY —
// the object either loads or it does not — so an object creeping toward
// the wall is indistinguishable from a comfortable one until the day it
// crosses. That is exactly what happened: master sat at 990,796/1,000,000
// (0.92% headroom) with every gate green, and the next person to touch the
// IPv6 extension-header walk discovered it as a REJECT after the work was
// already done.
//
// 3% is deliberately loose. It is not a performance target; it is a
// tripwire that says "the next change here will not fit" while there is
// still room to plan. The current object sits at ~5.3%.
const UserspaceShimMinVerifierHeadroomPct = 3.0

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
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
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
	_, err := VerifyUserspaceShimObjectStats(path)
	return err
}

// VerifyUserspaceShimObjectStats is VerifyUserspaceShimObject plus the
// kernel verifier's processed-insn accounting for a candidate that
// LOADED, so the build-time gate can enforce
// UserspaceShimMinVerifierHeadroomPct rather than only the hard 1M wall.
// The returned stats are meaningful only when err is nil and
// stats.Measured() is true.
func VerifyUserspaceShimObjectStats(path string) (ShimVerifierStats, error) {
	var stats ShimVerifierStats
	if err := rlimit.RemoveMemlock(); err != nil {
		return stats, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return stats, fmt.Errorf("load candidate spec from %s: %w", path, err)
	}
	return verifyUserspaceShimSpecWithShrinkStats(spec, true)
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
	return verifyUserspaceShimSpecWithShrink(spec, true)
}

// verifyUserspaceShimSpecWithShrink exists so the root-gated
// shrink-equivalence test can prove that the MaxEntries shrink does
// not change the verifier verdict (PASS object passes both ways, the
// preserved #1864 REJECT object rejects both ways). Production
// callers always shrink.
func verifyUserspaceShimSpecWithShrink(spec *ebpf.CollectionSpec, shrink bool) error {
	_, err := verifyUserspaceShimSpecWithShrinkStats(spec, shrink)
	return err
}

// verifyUserspaceShimSpecWithShrinkStats is the implementation. It loads
// with LogLevelStats so the verifier's processed-insn count is available
// on SUCCESS as well as on reject — the binary PASS/REJECT verdict alone
// cannot tell you the object is one edit away from the 1M wall, which is
// how master came to sit at 0.92% headroom unnoticed (#4555).
//
// Requesting stats does not change the verdict: it only asks the kernel
// to emit its summary line into the log buffer. A load that passes
// without the flag passes with it.
func verifyUserspaceShimSpecWithShrinkStats(spec *ebpf.CollectionSpec, shrink bool) (ShimVerifierStats, error) {
	var stats ShimVerifierStats
	if err := validateUserspaceShimSpec(spec); err != nil {
		return stats, fmt.Errorf("spec validation (production-load viability): %w", err)
	}

	vspec := spec.Copy()
	if shrink {
		for _, ms := range vspec.Maps {
			switch ms.Type {
			case ebpf.Hash, ebpf.PerCPUHash, ebpf.LRUHash, ebpf.LRUCPUHash:
				if ms.MaxEntries > verifyShrinkHashMaxEntries {
					ms.MaxEntries = verifyShrinkHashMaxEntries
				}
			}
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(vspec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return stats, fmt.Errorf("%w: kernel verifier rejected %s:\n%s",
				ErrUserspaceShimVerifierReject, userspaceShimEntryProg, verifierLogTail(ve))
		}
		return stats, fmt.Errorf("verify-only collection load: %w", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs[userspaceShimEntryProg]
	if !ok {
		return stats, fmt.Errorf("candidate object loaded but %s program is missing", userspaceShimEntryProg)
	}
	stats = parseShimVerifierStats(prog.VerifierLog)
	return stats, nil
}

// ShimVerifierStats carries the kernel verifier's own accounting for a
// shim candidate that LOADED. Measured is false when the running
// kernel's log did not carry a recognisable stats line — callers must
// treat that as "cannot measure", never as "headroom is fine".
type ShimVerifierStats struct {
	ProcessedInsns int
	InsnLimit      int
}

// Measured reports whether a usable processed-insn count was recovered.
func (s ShimVerifierStats) Measured() bool {
	return s.ProcessedInsns > 0 && s.InsnLimit > 0
}

// HeadroomPct is the percentage of the verifier's processed-insn budget
// the candidate leaves unused. Zero when unmeasured.
func (s ShimVerifierStats) HeadroomPct() float64 {
	if !s.Measured() {
		return 0
	}
	return 100 * float64(s.InsnLimit-s.ProcessedInsns) / float64(s.InsnLimit)
}

// shimVerifierStatsRe matches the kernel's end-of-verification summary,
// e.g. "processed 947188 insns (limit 1000000) max_states_per_insn 34 ...".
var shimVerifierStatsRe = regexp.MustCompile(`processed (\d+) insns \(limit (\d+)\)`)

func parseShimVerifierStats(log string) ShimVerifierStats {
	var stats ShimVerifierStats
	m := shimVerifierStatsRe.FindStringSubmatch(log)
	if len(m) != 3 {
		return stats
	}
	processed, err := strconv.Atoi(m[1])
	if err != nil {
		return stats
	}
	limit, err := strconv.Atoi(m[2])
	if err != nil {
		return stats
	}
	return ShimVerifierStats{ProcessedInsns: processed, InsnLimit: limit}
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

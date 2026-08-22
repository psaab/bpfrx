package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useTempKernelJournal6639 points the cut's re-stamp seam at a temp journal.
//
// Without it a unit test driving flip() would read — and, once a candidate is
// armed, WRITE — the real /var/lib/xpf/kernel-upgrade.state and its sidecar on
// the developer's box.
func useTempKernelJournal6639(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	jp := filepath.Join(dir, "kernel-upgrade.state")
	orig := kernelArmRestampJournalPath
	kernelArmRestampJournalPath = jp
	t.Cleanup(func() { kernelArmRestampJournalPath = orig })
	return jp
}

// armKernelCandidate6639 writes an ARMED journal + sidecar naming binPath, the
// state `xpfd upgrade kernel arm` leaves behind.
func armKernelCandidate6639(t *testing.T, journalPath, binPath string) {
	t.Helper()
	kr := &KernelRunner{cfg: KernelConfig{JournalPath: journalPath}}
	j := &KernelJournal{
		State:            KernelStateArmed,
		CandidateVersion: "6.19.0-1-generic",
		KnownGoodVersion: "6.18.4-11-generic",
		PromoteBinary:    binPath,
	}
	if err := kr.saveKernelJournal(j); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ArmRecordPath(journalPath), []byte(binPath+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readArmSidecar6639(t *testing.T, journalPath string) string {
	t.Helper()
	b, err := os.ReadFile(ArmRecordPath(journalPath))
	if err != nil {
		t.Fatalf("read arm sidecar: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// TestFlipRestampsTheKernelArmRecord_6639 is the fail-on-revert gate.
//
// `xpfd upgrade kernel arm` records the arming binary's resolved path into the
// journal AND the `kernel-promote-binary` sidecar. An in-place binary cut then
// repoints `current`, the sbin links and the unit's ExecStart at a NEW version
// and used to touch neither record. On the candidate boot the POSIX-sh outer hop
// compares the recorded path against what the unit independently resolves, finds
// two genuinely different files, and refuses — so the candidate is never
// promoted.
//
// The SIDECAR is what matters: the refusal fires in the shell, before it execs
// anything, so the Go-side cross-check is never reached and a Go-only fix could
// not have closed this.
func TestFlipRestampsTheKernelArmRecord_6639(t *testing.T) {
	jp := useTempKernelJournal6639(t)
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	oldBin := filepath.Join(cfg.VersionsDir, "1.0.0", "xpfd")
	newBin := filepath.Join(cfg.VersionsDir, "2.0.0", "xpfd")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.VersionsDir, "2.0.0", b), "binary-"+b+"-2.0.0")
	}
	armKernelCandidate6639(t, jp, oldBin)

	if err := r.flip("2.0.0"); err != nil {
		t.Fatalf("flip: %v", err)
	}

	if got := readArmSidecar6639(t, jp); got != newBin {
		t.Fatalf("arm sidecar = %q, want %q — the shell outer hop reads THIS file, so a "+
			"stale value here makes the candidate boot refuse and the kernel candidate is "+
			"lost", got, newBin)
	}
	kr := &KernelRunner{cfg: KernelConfig{JournalPath: jp}}
	j, err := kr.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.PromoteBinary != newBin {
		t.Fatalf("journal PromoteBinary = %q, want %q — it must stay equal to the sidecar; "+
			"the Go cross-check reads this half", j.PromoteBinary, newBin)
	}
	// The candidate itself must be untouched: the cut re-points which xpfd
	// verifies, it does not re-arm or cancel the trial.
	if j.CandidateVersion != "6.19.0-1-generic" || j.State != KernelStateArmed {
		t.Fatalf("the cut altered the kernel trial itself: state=%s candidate=%s",
			j.State, j.CandidateVersion)
	}
}

// TestFlipDoesNotCreateAnArmRecordWhenNothingIsArmed_6639 is the negative
// control the issue asks for by name.
//
// A cut on a box that never used the kernel channel must be byte-identical to
// before: no journal created, no sidecar created. A re-stamp that ran
// unconditionally would mint an arm record with nothing armed, and the boot gate
// treats a record's PRESENCE as meaningful — it would start refusing on a box
// with no kernel trial at all.
func TestFlipDoesNotCreateAnArmRecordWhenNothingIsArmed_6639(t *testing.T) {
	jp := useTempKernelJournal6639(t)
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.VersionsDir, "2.0.0", b), "binary-"+b+"-2.0.0")
	}

	if err := r.flip("2.0.0"); err != nil {
		t.Fatalf("flip with nothing armed must succeed: %v", err)
	}
	if _, err := os.Stat(ArmRecordPath(jp)); !os.IsNotExist(err) {
		t.Fatalf("the cut created an arm record with nothing armed (err=%v) — the boot gate "+
			"treats a record's presence as meaningful and would begin refusing", err)
	}
	if _, err := os.Stat(jp); !os.IsNotExist(err) {
		t.Fatalf("the cut created a kernel journal with nothing armed (err=%v)", err)
	}
}

// TestFlipRestampIsNoOpForATerminalKernelState_6639 pins the other half of the
// armed predicate. A journal left at PROMOTED or REVERTED is not an in-flight
// trial, and its record has already been cleared; re-stamping would recreate one.
func TestFlipRestampIsNoOpForATerminalKernelState_6639(t *testing.T) {
	for _, st := range []KernelState{KernelStatePromoted, KernelStateReverted} {
		t.Run(string(st), func(t *testing.T) {
			jp := useTempKernelJournal6639(t)
			fs := newFakeSystem(t, "2.0.0")
			r, cfg := testEnv(t, fs)
			seedInitialCurrent(t, r, cfg, "1.0.0")
			for _, b := range managedBins {
				writeFakeBin(t, filepath.Join(cfg.VersionsDir, "2.0.0", b), "binary-"+b+"-2.0.0")
			}
			kr := &KernelRunner{cfg: KernelConfig{JournalPath: jp}}
			if err := kr.saveKernelJournal(&KernelJournal{State: st}); err != nil {
				t.Fatal(err)
			}

			if err := r.flip("2.0.0"); err != nil {
				t.Fatalf("flip: %v", err)
			}
			if _, err := os.Stat(ArmRecordPath(jp)); !os.IsNotExist(err) {
				t.Fatalf("a %s journal is not an in-flight trial; the cut must not mint an "+
					"arm record (err=%v)", st, err)
			}
		})
	}
}

// TestFlipRestampFailsClosed_6639 pins the atomicity requirement the issue
// states: a half-updated record naming a binary that may not exist is strictly
// worse than an untouched one.
//
// The cut target's xpfd is absent, so the re-stamp cannot validate it. The cut
// must FAIL, and the OLD record must survive intact — degrading to exactly the
// pre-fix behaviour, which is safe and refusing.
func TestFlipRestampFailsClosed_6639(t *testing.T) {
	jp := useTempKernelJournal6639(t)
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	oldBin := filepath.Join(cfg.VersionsDir, "1.0.0", "xpfd")
	armKernelCandidate6639(t, jp, oldBin)
	// Every managed binary EXCEPT xpfd, so 6a-6c succeed and only the re-stamp's
	// validation fails — otherwise the case would prove nothing about 6d.
	for _, b := range managedBins {
		if b == "xpfd" {
			continue
		}
		writeFakeBin(t, filepath.Join(cfg.VersionsDir, "2.0.0", b), "binary-"+b+"-2.0.0")
	}

	err := r.flip("2.0.0")
	if err == nil {
		t.Fatal("flip must FAIL when the cut target cannot serve as the promotion gate; " +
			"silently leaving the old record is a cut that reports success while the kernel " +
			"candidate is already lost")
	}
	if !strings.Contains(err.Error(), "re-stamp kernel arm record") {
		t.Fatalf("the failure must name the re-stamp so it is diagnosable, got: %v", err)
	}
	if got := readArmSidecar6639(t, jp); got != oldBin {
		t.Fatalf("arm sidecar = %q after a failed re-stamp, want the OLD value %q intact — "+
			"a half-updated record naming a nonexistent binary is worse than an untouched one",
			got, oldBin)
	}
}

// TestRestampSeamIsTheProductionDefault_6639 pins the seam's value, mirroring
// TestBootGateJournalPathIsTheProductionDefault.
//
// The seam exists only so tests do not write to the real /var/lib/xpf. A leaked
// override would make every case above pass against a journal production never
// reads — the guard would be vacuous and the defect would ship.
func TestRestampSeamIsTheProductionDefault_6639(t *testing.T) {
	if kernelArmRestampJournalPath != DefaultKernelJournalPath {
		t.Fatalf("kernelArmRestampJournalPath = %q, want the production default %q",
			kernelArmRestampJournalPath, DefaultKernelJournalPath)
	}
}

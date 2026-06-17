package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// maxPromoteAttempts bounds the number of revert-reboots for a single armed
// candidate. Beyond this, the promotion gate stops requesting reboots and
// leaves the box up (on the firmware-preferred known-good default) so a
// pathological loop (e.g. read-only root that cannot clear the journal) cannot
// brick the node out of operator reach (r1 AGY catastrophic).
const maxPromoteAttempts = 3

// loadKernelJournal reads the persisted kernel-channel journal, or a zero
// journal if none exists.
func (r *KernelRunner) loadKernelJournal() (*KernelJournal, error) {
	data, err := os.ReadFile(r.cfg.JournalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &KernelJournal{State: KernelStateInit}, nil
		}
		return nil, fmt.Errorf("read kernel-upgrade journal: %w", err)
	}
	j := &KernelJournal{}
	if err := json.Unmarshal(data, j); err != nil {
		return nil, fmt.Errorf("parse kernel-upgrade journal: %w", err)
	}
	return j, nil
}

// saveKernelJournal persists j durably (temp+fsync+rename via fsatomic).
func (r *KernelRunner) saveKernelJournal(j *KernelJournal) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal kernel-upgrade journal: %w", err)
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(r.cfg.JournalPath), 0755); err != nil {
		return fmt.Errorf("create kernel journal dir: %w", err)
	}
	if err := fsatomic.WriteFileDurable(r.cfg.JournalPath, data, 0644); err != nil {
		return fmt.Errorf("persist kernel-upgrade journal: %w", err)
	}
	return nil
}

// clearKernelJournal removes the journal on a terminal state.
func (r *KernelRunner) clearKernelJournal() error {
	if err := os.Remove(r.cfg.JournalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove kernel-upgrade journal: %w", err)
	}
	return nil
}

func (r *KernelRunner) ktransition(j *KernelJournal, s KernelState) error {
	j.State = s
	r.logf("kernel-upgrade: -> %s (candidate=%s known-good=%s active=%s)",
		s, j.CandidateVersion, j.KnownGoodVersion, j.ActiveSlot)
	return r.saveKernelJournal(j)
}

// Arm runs the PRE-REBOOT half of the LANE-1 channel for a candidate kernel
// version: preflight -> install -> arm one-shot -> reboot. On success it does
// NOT return (the host reboots into the candidate); the Promote half then runs
// from the candidate boot. Every phase is journaled so a crash before the
// reboot resumes idempotently.
//
// A pre-assert failure returns ErrKernelChannelUnavailable (the running kernel
// + active slot are untouched). The arm is loop-safe by construction: even if
// the process dies right after SetBootNext, the firmware clears BootNext on the
// next boot, so at worst the candidate is tried once and falls back.
func (r *KernelRunner) Arm(candidateVersion string) error {
	if candidateVersion == "" {
		return fmt.Errorf("kernel-upgrade: candidate version is required")
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		return err
	}
	if j.State.atLeast(KernelStateArmed) {
		return fmt.Errorf("kernel-upgrade: a candidate is already armed "+
			"(journal state=%s candidate=%s); reboot to trial it or clear %s",
			j.State, j.CandidateVersion, r.cfg.JournalPath)
	}
	// Resume-version guard (r1 Copilot): if a PRIOR Arm() got past PREFLIGHT
	// (so the journal records a candidate) and this call requests a DIFFERENT
	// version, the journaled candidate is authoritative — refuse rather than
	// install version B against a journal that preflighted/installed version A.
	// The operator must clear the journal to switch candidates mid-flight.
	if j.State.atLeast(KernelStatePreflight) && j.CandidateVersion != "" &&
		j.CandidateVersion != candidateVersion {
		return fmt.Errorf("kernel-upgrade: an in-progress run targets candidate %s "+
			"(journal state=%s); refusing to resume with a different candidate %s — "+
			"clear %s to start over", j.CandidateVersion, j.State, candidateVersion, r.cfg.JournalPath)
	}

	// Clear any STALE promotion marker from a PRIOR roll BEFORE arming a fresh
	// one (r1 Codex High): otherwise the external orchestrator's post-reboot
	// `promoted==<ver>` check could be satisfied by a previous successful roll
	// to the SAME version, masking a revert of THIS roll. This is FATAL on
	// failure (r2 Codex): if we cannot guarantee the marker is gone, we must NOT
	// arm — proceeding would leave a stale marker that could false-confirm.
	if !j.State.atLeast(KernelStatePreflight) {
		if err := r.cfg.Sys.ClearPromotionMarker(); err != nil {
			return fmt.Errorf("kernel-upgrade arm: clear stale promotion marker (refusing "+
				"to arm with a possibly-stale marker): %w", err)
		}
	}

	// ---- PREFLIGHT (fail-closed; no mutation) ----
	if !j.State.atLeast(KernelStatePreflight) {
		if err := r.preflight(j, candidateVersion); err != nil {
			return err
		}
	}

	// ---- INSTALL (candidate kernel into /boot; default must not move) ----
	if !j.State.atLeast(KernelStateInstalled) {
		if err := r.installCandidate(j, candidateVersion); err != nil {
			return err
		}
	}

	// ---- ARM (point inactive slot selector + BootNext + watchdog) ----
	if err := r.armCandidate(j); err != nil {
		return err
	}

	// ---- REBOOT into the candidate (one-shot, firmware-cleared) ----
	r.logf("kernel-upgrade: armed candidate %s in slot %s; rebooting (one-shot)",
		j.CandidateVersion, j.InactiveSlot)
	return r.cfg.Sys.Reboot()
}

func (r *KernelRunner) preflight(j *KernelJournal, candidateVersion string) error {
	sys := r.cfg.Sys

	if !sys.IsUEFI() {
		return fmt.Errorf("%w: not booted via UEFI (A4 needs efibootmgr/BootNext)", ErrKernelChannelUnavailable)
	}
	if !sys.EfibootmgrOK() {
		return fmt.Errorf("%w: efibootmgr cannot read NVRAM", ErrKernelChannelUnavailable)
	}

	entries, err := sys.BootEntries()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: read boot entries: %w", err)
	}
	aID, okA := entries[SlotA]
	bID, okB := entries[SlotB]
	if !okA || !okB {
		return fmt.Errorf("%w: A/B slots not both registered (found A=%v B=%v) — "+
			"the first-boot registration oneshot must run first", ErrKernelChannelUnavailable, okA, okB)
	}

	order, err := sys.BootOrder()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: read BootOrder: %w", err)
	}
	if len(order) == 0 {
		return fmt.Errorf("%w: empty BootOrder", ErrKernelChannelUnavailable)
	}
	// The active slot is whichever of A/B is first in BootOrder.
	var activeSlot, inactiveSlot string
	switch order[0] {
	case aID:
		activeSlot, inactiveSlot = SlotA, SlotB
	case bID:
		activeSlot, inactiveSlot = SlotB, SlotA
	default:
		return fmt.Errorf("%w: BootOrder front (%s) is neither A/B slot (A=%s B=%s) — "+
			"a non-xpf default is registered; refusing to arm", ErrKernelChannelUnavailable, order[0], aID, bID)
	}

	submenuOK, err := sys.GrubSubmenuDisabled()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: grub submenu check: %w", err)
	}
	if !submenuOK {
		return fmt.Errorf("%w: GRUB_DISABLE_SUBMENU not set or /etc/grub.d/09_xpf missing", ErrKernelChannelUnavailable)
	}

	wdPresent, wdPersistent := sys.WatchdogStatus()
	if r.cfg.StrictWatchdog && !(wdPresent && wdPersistent) {
		return fmt.Errorf("%w: strict-watchdog policy (D1) requires a verified-persistent "+
			"watchdog (present=%v persistent=%v)", ErrKernelChannelUnavailable, wdPresent, wdPersistent)
	}
	if !wdPersistent {
		r.logf("kernel-upgrade: WARNING (Path-D2): no verified-persistent watchdog "+
			"(present=%v); the BootNext one-shot still closes the boot-LOOP, but an "+
			"EARLY-boot hang would need one external/console reset to recover", wdPresent)
	}

	if err := r.assertFree(r.cfg.BootMountpoint, r.cfg.BootFreeMargin, "/boot"); err != nil {
		return err
	}
	if err := r.assertFree(r.cfg.ESPMountpoint, r.cfg.ESPFreeMargin, "ESP"); err != nil {
		return err
	}

	known, err := sys.RunningKernel()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: uname -r: %w", err)
	}
	if known == candidateVersion {
		return fmt.Errorf("kernel-upgrade preflight: candidate %s is already the running kernel", candidateVersion)
	}

	j.CandidateVersion = candidateVersion
	j.KnownGoodVersion = known
	j.ActiveSlot = activeSlot
	j.InactiveSlot = inactiveSlot
	j.StartedAt = sys.Now()
	return r.ktransition(j, KernelStatePreflight)
}

func (r *KernelRunner) assertFree(path string, margin uint64, label string) error {
	free, err := r.cfg.Sys.FreeBytes(path)
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: free space on %s (%s): %w", path, label, err)
	}
	if free < margin {
		return fmt.Errorf("%w: insufficient %s space (%d < required %d bytes) — "+
			"prune before install", ErrKernelChannelUnavailable, label, free, margin)
	}
	return nil
}

func (r *KernelRunner) installCandidate(j *KernelJournal, candidateVersion string) error {
	sys := r.cfg.Sys

	defaultBefore, err := sys.DefaultBootEntry()
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: read default boot entry: %w", err)
	}

	unameR, err := sys.InstallCandidateKernel(candidateVersion)
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: %w", err)
	}
	// The candidate's actual uname -r is authoritative for the selector +
	// the promotion gate; record it (it may differ from the apt version arg).
	j.CandidateVersion = unameR

	// Re-assert the dpkg postinst's update-grub did NOT move the permanent
	// default (plan risk #2): the known-good slot must still be the default.
	defaultAfter, err := sys.DefaultBootEntry()
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: re-read default boot entry: %w", err)
	}
	if defaultAfter != defaultBefore {
		return fmt.Errorf("kernel-upgrade install: candidate install MOVED the permanent "+
			"default (%s -> %s); aborting to avoid an unverified default boot", defaultBefore, defaultAfter)
	}

	// Re-assert the kernel set is held again after the install window.
	held, err := sys.KernelHeld()
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: re-check kernel hold: %w", err)
	}
	if !held {
		return fmt.Errorf("kernel-upgrade install: kernel set is NOT held after install — rehold failed")
	}

	return r.ktransition(j, KernelStateInstalled)
}

func (r *KernelRunner) armCandidate(j *KernelJournal) error {
	sys := r.cfg.Sys

	// Point the INACTIVE slot's selector at the candidate (atomic ESP write).
	if err := sys.WriteSlotSelector(j.InactiveSlot, j.CandidateVersion); err != nil {
		return fmt.Errorf("kernel-upgrade arm: write %s selector: %w", j.InactiveSlot, err)
	}
	// Verify the selector reads back the candidate before we arm BootNext.
	got, err := sys.ReadSlotSelector(j.InactiveSlot)
	if err != nil {
		return fmt.Errorf("kernel-upgrade arm: read back %s selector: %w", j.InactiveSlot, err)
	}
	if got != j.CandidateVersion {
		return fmt.Errorf("kernel-upgrade arm: %s selector reads %q, expected candidate %q",
			j.InactiveSlot, got, j.CandidateVersion)
	}

	entries, err := sys.BootEntries()
	if err != nil {
		return fmt.Errorf("kernel-upgrade arm: read boot entries: %w", err)
	}
	inactiveID, ok := entries[j.InactiveSlot]
	if !ok {
		return fmt.Errorf("kernel-upgrade arm: inactive slot %s not registered", j.InactiveSlot)
	}

	if err := sys.ArmWatchdog(); err != nil {
		// Non-fatal under D2: BootNext is the loop-safety. Log and continue.
		r.logf("kernel-upgrade arm: WARNING arm watchdog: %v (continuing; BootNext closes the loop)", err)
	}

	// Journal ARMED *before* arming BootNext (r1 Codex Critical-2): the
	// reboot-boundary crash hole is "firmware booted the candidate but the
	// journal still says INSTALLED, so Promote() no-ops". By persisting ARMED
	// first, any crash after this point leaves a recoverable ARMED journal that
	// Promote() acts on. The selector + ARMED journal are both harmless without
	// BootNext (the firmware default is still the known-good slot), so ordering
	// the durable ARMED write ahead of the one-shot is strictly safe.
	if err := r.ktransition(j, KernelStateArmed); err != nil {
		return err
	}

	if err := sys.SetBootNext(inactiveID); err != nil {
		// Roll the journal back to INSTALLED so a retry re-arms cleanly; the
		// selector is already correct and BootNext was not set, so the box
		// still boots the known-good default.
		j.State = KernelStateInstalled
		_ = r.saveKernelJournal(j)
		return fmt.Errorf("kernel-upgrade arm: efibootmgr --bootnext %s: %w", inactiveID, err)
	}

	return nil
}

// Promote runs the POST-REBOOT promotion gate from the candidate boot. It is
// invoked by the promotion oneshot systemd unit early on the candidate boot
// (before xpfd admits traffic). On a PASS it makes the candidate slot the
// durable default and clears the journal; on a FAIL it reverts (clean reboot ->
// firmware falls through BootOrder to the known-good slot, BootNext already
// consumed). It returns nil on a clean promote, and a non-nil error describing
// the revert reason on a revert (the oneshot then issues the reboot).
func (r *KernelRunner) Promote() error {
	sys := r.cfg.Sys
	j, err := r.loadKernelJournal()
	if err != nil {
		return err
	}
	if !j.State.atLeast(KernelStateArmed) {
		// Nothing armed -> this is an ordinary boot, not a candidate trial.
		r.logf("kernel-upgrade: no armed candidate (state=%s); ordinary boot, nothing to promote", j.State)
		return nil
	}
	if j.State == KernelStatePromoted || j.State == KernelStateReverted {
		r.logf("kernel-upgrade: already terminal (%s); nothing to do", j.State)
		return nil
	}

	// Gate 1: did the firmware actually boot the candidate slot?
	entries, err := sys.BootEntries()
	if err != nil {
		return r.revert(j, fmt.Errorf("read boot entries: %w", err))
	}
	candID, ok := entries[j.InactiveSlot]
	if !ok {
		return r.revert(j, fmt.Errorf("candidate slot %s vanished from NVRAM", j.InactiveSlot))
	}
	cur, err := sys.BootCurrent()
	if err != nil {
		// Can't tell which slot we booted. Do NOT reboot (that risks a loop on
		// a flaky efibootmgr — r1 AGY): clean up to known-good in place.
		return r.cleanupAlreadyOnKnownGood(j, fmt.Errorf("read BootCurrent: %w", err))
	}
	if cur != candID {
		// Firmware ignored BootNext / fell back — this boot is ALREADY on a
		// non-candidate (known-good) slot. This is NOT a revert-needing reboot:
		// rebooting again would be redundant (r1 AGY double-reboot) and, if the
		// journal can't be cleared (read-only root), would loop forever
		// bypassing the SAFE-BOOTSTRAP lifeline (r1 AGY catastrophic). Just
		// clean up in place and continue THIS boot (exit 0, no reboot).
		return r.cleanupAlreadyOnKnownGood(j, fmt.Errorf(
			"BootCurrent=%s != candidate slot %s (%s) — already on known-good, no reboot", cur, j.InactiveSlot, candID))
	}

	// Gate 2: is the running kernel actually the candidate?
	running, err := sys.RunningKernel()
	if err != nil {
		return r.revert(j, fmt.Errorf("uname -r: %w", err))
	}
	if running != j.CandidateVersion {
		return r.revert(j, fmt.Errorf("running kernel %s != candidate %s", running, j.CandidateVersion))
	}

	// Gate 3: verify-dataplane (the #1864 kernel verifier) on the candidate.
	ok, err = sys.VerifyDataplane()
	if err != nil {
		return r.revert(j, fmt.Errorf("verify-dataplane error: %w", err))
	}
	if !ok {
		return r.revert(j, fmt.Errorf("verify-dataplane REJECT on candidate kernel %s", running))
	}

	// Gate 4: forward health beacon (structural verify != actually forwards).
	ok, err = sys.ForwardBeacon(r.cfg.BeaconDeadline)
	if err != nil {
		return r.revert(j, fmt.Errorf("forward beacon error: %w", err))
	}
	if !ok {
		return r.revert(j, fmt.Errorf("forward beacon FAILED on candidate kernel %s", running))
	}

	// PASS: promote — non-destructive BootOrder reorder (candidate first). If
	// the reorder FAILS, the candidate is running but NOT durably the default;
	// the safe action is to REVERT (reboot to known-good) rather than leave it
	// un-promoted (which the oneshot would treat as a non-revert "infra error"
	// and continue booting an un-promoted candidate — r1 Copilot). revert()
	// restores the known-good BootOrder front + reboots.
	if err := sys.SetBootOrderFront(candID); err != nil {
		return r.revert(j, fmt.Errorf("promote: set BootOrder front %s failed: %w", candID, err))
	}
	if err := sys.DisarmWatchdog(); err != nil {
		r.logf("kernel-upgrade promote: WARNING disarm watchdog: %v", err)
	}
	// Write the DURABLE promotion marker BEFORE clearing the journal, so the
	// external HA orchestrator's post-reboot version-check has a signal that
	// survives the clear (INC-2). Best-effort: a marker-write failure does not
	// un-promote (the BootOrder reorder already succeeded), but the orchestrator
	// then relies on `uname -r == target` alone.
	if err := sys.WritePromotionMarker(running); err != nil {
		r.logf("kernel-upgrade promote: WARNING write promotion marker: %v", err)
	}
	// The candidate slot is now the active/known-good slot; the OTHER slot
	// (the former active) becomes the rollback target and keeps its kernel.
	if err := r.ktransition(j, KernelStatePromoted); err != nil {
		return err
	}
	r.logf("kernel-upgrade: PROMOTED candidate %s (slot %s now default)", running, j.InactiveSlot)
	return r.clearKernelJournal()
}

// revert records the revert reason, prunes the un-promoted candidate, and
// returns an error so the caller (the promotion oneshot) issues a clean reboot
// to the known-good slot. The boot-LOOP is already closed by firmware (BootNext
// was consumed), so the reboot lands on the known-good slot.
func (r *KernelRunner) revert(j *KernelJournal, reason error) error {
	// Boot-attempt guard (r1 AGY catastrophic): if the journal cannot be
	// CLEARED (e.g. read-only root after a kernel oops), a naive revert would
	// loop forever — each boot re-reads ARMED, reverts, exits 3, reboots. Bound
	// the reboot requests: bump PromoteAttempts; once it exceeds the cap, STOP
	// requesting reboots (return nil = exit 0, continue THIS boot) so the box
	// stays up on whatever slot it is on (the firmware already prefers the
	// known-good default) and the SAFE-BOOTSTRAP lifeline is reachable for the
	// operator. We also confirm we can persist the bump; if we cannot, we must
	// NOT request a reboot (the loop-avoidance is the priority).
	j.PromoteAttempts++
	if err := r.saveKernelJournal(j); err != nil {
		r.logf("kernel-upgrade: REVERT but journal NOT persistable (%v); NOT rebooting "+
			"(avoid a read-only-root reboot loop) — staying up for operator recovery", err)
		return fmt.Errorf("kernel-upgrade revert (journal unwritable, not rebooting): %v", reason)
	}
	// Restore the box to the safest reachable state (known-good BootOrder front
	// + disarm watchdog + prune candidate) BEFORE deciding whether to reboot —
	// so that EVEN the attempt-cap-exceeded "give up" path below leaves the box
	// on the known-good default rather than abandoning it candidate-first
	// (r2 Copilot: the cap path previously cleared the journal without
	// restoring BootOrder).
	r.restoreKnownGood(j)

	if j.PromoteAttempts > maxPromoteAttempts {
		r.logf("kernel-upgrade: REVERT but %d attempts exceeded cap %d; NOT rebooting again "+
			"— staying up for operator recovery (BootOrder restored to known-good)", j.PromoteAttempts, maxPromoteAttempts)
		_ = r.clearKernelJournal()
		return fmt.Errorf("kernel-upgrade revert (attempt cap exceeded, not rebooting): %v", reason)
	}
	r.logf("kernel-upgrade: REVERT (%v); candidate NOT promoted, rebooting to known-good (attempt %d/%d)",
		reason, j.PromoteAttempts, maxPromoteAttempts)

	_ = r.ktransition(j, KernelStateReverted)
	// Clear the journal so the next boot is a clean ordinary boot.
	_ = r.clearKernelJournal()
	// Wrap ErrKernelReverted so the CLI maps this to exit 3 (reboot to
	// known-good), distinct from an infra error (exit 1). reason is chained
	// for the log/operator.
	return fmt.Errorf("%w: %v", ErrKernelReverted, reason)
}

// restoreKnownGood puts the box in the safest reachable state: the known-good
// (active) slot at the FRONT of BootOrder (so even if a prior crash left the
// candidate first, a reboot lands on known-good — Codex High), the watchdog
// disarmed (so an Arm()-armed watchdog can't bounce the known-good boot —
// Copilot), and the un-promoted candidate pruned. All best-effort: the
// firmware-cleared BootNext remains the floor regardless. Shared by revert()
// (incl. the attempt-cap give-up path) and cleanupAlreadyOnKnownGood.
func (r *KernelRunner) restoreKnownGood(j *KernelJournal) {
	sys := r.cfg.Sys
	if entries, err := sys.BootEntries(); err == nil {
		if activeID, ok := entries[j.ActiveSlot]; ok {
			if err := sys.SetBootOrderFront(activeID); err != nil {
				r.logf("kernel-upgrade: WARNING restore known-good BootOrder front: %v", err)
			}
		} else {
			r.logf("kernel-upgrade: WARNING active slot %s not in NVRAM", j.ActiveSlot)
		}
	} else {
		r.logf("kernel-upgrade: WARNING read boot entries: %v", err)
	}
	if err := sys.DisarmWatchdog(); err != nil {
		r.logf("kernel-upgrade: WARNING disarm watchdog: %v", err)
	}
	if err := sys.PruneInactiveSlot(j.InactiveSlot, j.KnownGoodVersion, j.CandidateVersion); err != nil {
		r.logf("kernel-upgrade: WARNING prune inactive slot: %v", err)
	}
	// Clear the durable promotion marker (r2 AGY #6: a reverted node must not
	// retain a "promoted" marker from a prior same-version roll) and the local
	// kernel-roll lease (r2 AGY #5: a stranded lease would suppress this node's
	// self-recovery for the full TTL after the dead roll). Both best-effort.
	if err := sys.ClearPromotionMarker(); err != nil {
		r.logf("kernel-upgrade: WARNING clear promotion marker on restore: %v", err)
	}
	if err := sys.ClearRollLease(); err != nil {
		r.logf("kernel-upgrade: WARNING clear roll lease on restore: %v", err)
	}
}

// cleanupAlreadyOnKnownGood handles the case where the gate runs but the box is
// ALREADY on a non-candidate (known-good) slot — the firmware fell back, or we
// can't even tell which slot booted. There is nothing to revert TO (we're
// already safe), so this must NOT request a reboot (r1 AGY: a reboot here is
// redundant, and loops forever if the journal can't be cleared on a read-only
// root, bypassing the SAFE-BOOTSTRAP lifeline). It best-effort prunes the
// un-promoted candidate + clears the journal and returns nil (exit 0 — continue
// THIS boot). Journal-clear failure is non-fatal: on the next boot we are still
// on known-good and this same no-reboot path runs again.
func (r *KernelRunner) cleanupAlreadyOnKnownGood(j *KernelJournal, why error) error {
	r.logf("kernel-upgrade: already on a known-good slot (%v); cleaning up, NO reboot", why)
	// Restore the safest reachable state (BootOrder known-good front + disarm
	// watchdog + prune candidate), then clear the journal.
	r.restoreKnownGood(j)
	if err := r.clearKernelJournal(); err != nil {
		r.logf("kernel-upgrade: WARNING could not clear journal on known-good cleanup: %v "+
			"(non-fatal: next boot re-runs this no-reboot path)", err)
	}
	return nil
}

// IsArmed reports whether a candidate is currently armed (used by the
// promotion oneshot to decide whether to run the gate at all, and by the HA
// orchestrator's version-check).
func (r *KernelRunner) IsArmed() (bool, *KernelJournal, error) {
	j, err := r.loadKernelJournal()
	if err != nil {
		return false, nil, err
	}
	return j.State.atLeast(KernelStateArmed) && j.State != KernelStatePromoted && j.State != KernelStateReverted, j, nil
}

// summary is a short human string for status output.
func (j *KernelJournal) summary() string {
	if j == nil || j.State == KernelStateInit {
		return "no kernel upgrade in progress"
	}
	return fmt.Sprintf("kernel-upgrade %s: candidate=%s known-good=%s active-slot=%s",
		strings.ToLower(string(j.State)), j.CandidateVersion, j.KnownGoodVersion, j.ActiveSlot)
}

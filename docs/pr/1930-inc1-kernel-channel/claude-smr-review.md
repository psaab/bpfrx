# Claude SMR — hostile code review, PR #1940 (#1930 INC-1 LANE-1 kernel channel)

Reviewer: Claude SMR (domain SMR: boot/firmware + crash-safety + appliance HA).
Posture: HOSTILE. Reviewed at HEAD eb9b20b90, after Codex (3 rounds → APPROVE) +
AGY (2 rounds → all findings folded). I re-derived the safety chain and the
crash/reboot-boundary invariants independently rather than re-confirming.

## The load-bearing safety chain (verified end-to-end)
The whole channel's "never brick" rests on ONE firmware property: **UEFI clears
`BootNext` before launching that entry.** I traced every failure mode against it:
- Candidate hangs pre-Linux → watchdog reset → firmware finds no `BootNext` →
  boots `BootOrder[0]` (known-good). ✓ (live-proven both directions)
- Candidate boots but verify/beacon fails → promote gate reverts → reboot →
  firmware falls through to known-good. ✓
- Process crashes after `SetBootNext` but before reboot → journal is ARMED
  (written FIRST — Codex Critical-2 fix) → next boot's promote gate acts. ✓
- Crash mid-promote leaving candidate-first BootOrder → revert() forces the
  known-good slot to BootOrder front before rebooting. ✓
- Read-only root (journal unclearable) → cleanupAlreadyOnKnownGood (no reboot
  when already on known-good) + PromoteAttempts cap + "don't reboot if journal
  unwritable" → cannot loop the box out of operator reach. ✓ (AGY catastrophic
  fix; the single most important property — the SAFE-BOOTSTRAP lifeline always
  comes up). Unit-tested.

The chain is sound. The firmware-cleared one-shot is genuinely the floor, and
every software layer above it fails toward that floor.

## Crash-safety invariants (verified)
- Journal is temp+fsync+rename via fsatomic (same discipline as the #1917
  runner). Every transition routes through ktransition→saveKernelJournal.
- ARMED-before-BootNext ordering is correct (the reboot-boundary hole).
- The promote gate is idempotent: PROMOTED/REVERTED are terminal; an ordinary
  boot (no ARMED journal) is a fast no-op.
- maxPromoteAttempts bounds the only unbounded loop source.

## Items I checked that are FINE (no change needed)
- `SetBootOrderFront` is non-destructive (preserves PXE/recovery) — confirmed in
  both the Go impl and the shell normalizer.
- The two oneshots are NOT `Before=xpfd` → a stuck gate cannot wedge the
  lifeline; TimeoutStartSec bounds them.
- InstallCandidateKernel re-holds fatally + KernelHeld verifies the full set;
  the candidate can't be apt-moved after arm.
- Secure Boot: shim→grub→MOK chain preserved; no weakening (slots copy the
  SIGNED shim/grub). Live-proven under SB=on.

## Residuals I accept (documented, not blockers)
- **ForwardBeacon default-gateway weakness** (AGY): the strong gate is an
  operator-set dataplane `XPF_KERNEL_BEACON_TARGET`; the gateway fallback can
  false-pass over mgmt or fail-safe-revert on a no-default-route router. This is
  honestly documented; verify-dataplane (Gate 3, the #1864 kernel verifier) is
  the hard structural gate regardless, and the failure modes are recoverable
  (a false-pass still verified; a fail-safe revert is non-bricking). For an
  HA appliance the right BeaconTarget is the peer link — INC-2 (HA orchestration)
  should set it; noted as a follow-up the HA driver wires.
- **Early-boot-HANG watchdog persistence** (the operator-accepted residual): not
  warm-reset-guaranteeable in OVMF; the boot-LOOP is closed regardless by
  `BootNext`. Path Option D2. Documented.

## NITS (non-blocking)
- n1: `watchdogTimeoutSecs` parse uses `fmt.Sscanf("%d")` which accepts trailing
  garbage ("600x"→600); harmless (a misconfigured value just yields a sane
  number) but a strict `strconv.Atoi` would reject it. Leave it.
- n2: the promote gate's infra-error path (exit 1) logs + continues the boot
  (no reboot) — correct, but it leaves the candidate RUNNING un-promoted until
  the next plain reboot falls back. That's the safe choice (diagnosable, no
  bounce); worth an operator-doc note that a stuck infra error needs a manual
  reboot to return to known-good. The HA orchestrator (INC-2) handles this via
  its version-check + drain, so it's a standalone-only nuance.

## Verdict
APPROVE — This is a correct, crash-safe, Secure-Boot-correct implementation of
the converged A4 channel. The firmware-cleared `BootNext` safety chain is sound
and every software layer fails toward it; the catastrophic read-only-root reboot
loop AGY found is properly closed (no reboot when already known-good + attempt
cap + journal-unwritable guard), which is the property that matters most for an
unattended appliance. The implementation is live-validated end-to-end on Ubuntu
26.04 UEFI Secure Boot (both promote and rollback through real reboots, the full
firmware→shim→grub→$cmdpath→selector→kernel chain, wrong-path slot dedup). The
two residuals (ForwardBeacon dataplane-target guidance, early-hang watchdog) are
honestly documented and recoverable, not bricks. Ready to merge on the remaining
reviewer (Copilot) + the final 4-way gate.

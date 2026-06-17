# #1930 INC-2 (PR #1941) — Claude SMR adversarial review

Domain SMR (HA chassis cluster + kernel channel) + CPU/arch + SW-design pass,
in addition to the Codex / AGY / Copilot reviewers.

## Findings I raised and fixed

1. **Leaked election hold after a SUCCESSFUL promote** (fixed d73a7a9cc, then
   superseded by the marker-based release in 92ee918c9). The promotion gate runs
   in a SEPARATE process (`xpf-kernel-promote.service`, `After=xpfd`) that clears
   only the on-disk journal; nothing in the running daemon cleared the in-memory
   `kernelUpgradeHold`. A successfully promoted candidate would have stayed
   SECONDARY forever. Fix: a daemon 5s reconcile loop that releases the hold.

2. **Election window before the hold was set** (fixed 4de61669c; AGY r2 F1
   independently confirmed this as CRITICAL). The hold was set after
   `cluster.UpdateConfig(cc)`, but `UpdateConfig` ITSELF runs the first election
   (single-node path on a candidate boot) and would promote the node to
   StatePrimary before the hold took effect. Moved the hold to run after
   `NewManager` (pure construction) and before `UpdateConfig`.

## Adversarial verification of the final diff

- **Every `rg.State = StatePrimary` assignment** is inside `runElection`
  (gated by `electRG` returning `electNoChange` for a held node) or
  `electSingleNode` (early `return` for a held node). No failover.go /
  heartbeat / readiness path assigns primary outside these two. The hold is
  honored on every entry point.
- **`SetKernelUpgradeHold` under `m.mu.Lock`** calls `sendEvent`, which is
  non-blocking (select/default, drops on full buffer) — the same pattern every
  election path uses under the lock. No deadlock; the demote sends
  Primary->Secondary so `triggerGARP` (Primary-only) is not invoked.
- **Marker-based release is race-free** across promote (marker == running ->
  release), revert (journal cleared then reboot; marker never names the
  candidate -> hold persists to the known-good reboot where it is never set),
  timeout (OnFailure reboot), and marker-write failure (= /var/lib/xpf broken;
  node stays SECONDARY on a good kernel, peer serves — accepted fail-safe,
  consistent with the journal-unwritable handling).
- **OnFailure loop-safety**: an ordinary boot's gate is a fast exit-0 no-op, so
  the triggering unit never FAILS there and the handler never fires; Arm() only
  sets the firmware-cleared BootNext (never reorders BootOrder), so the recovery
  reboot lands on known-good. The exit-3 revert path now exits 0 after issuing
  its own reboot, so OnFailure does not double-fire.
- **Lock discipline**: `KernelUpgradeHeld` RLock; `Set`/`Clear` Lock;
  `ClearKernelUpgradeHold` runs election under the held Lock (matching the
  private method contract); `ResetAllFailover` calls them sequentially without
  nested acquisition. No daemon-level lock is held across manager calls.

## Verdict

MERGE-READY pending AGY r3 convergence confirmation + the standard merge gate
(Codex + Copilot + smoke/no-regression). The candidate-preempt CRITICAL and the
two follow-on races are resolved; the kernel-channel safety invariant (an
unverified candidate never carries traffic; a verified one resumes promptly; a
hung/failed gate self-recovers to known-good) holds across all traced paths.

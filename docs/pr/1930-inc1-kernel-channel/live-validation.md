# #1930 INC-1 LANE-1 A4 — live validation (Ubuntu 26.04 UEFI Secure Boot)

Venue: incus VM `xpf-a4probe`, `images:ubuntu/26.04` (the bake's auto-discovered
latest release), `security.secureboot=true`. Confirmed: `mokutil --sb-state` =
"SecureBoot enabled"; signed shim+grub MOK chain present (`shimx64.efi`,
grub-efi-amd64-signed); efibootmgr read AND write (--bootnext/--create/
--bootorder) all work under Secure Boot; ESP 99M/90M-free (two slot dirs fit);
`grub-script-check` validates the emitted `09_xpf` menuentry.

## Bugs found live (and fixed + locked with unit tests)
1. **efibootmgr line parse (tab separator).** A line is
   `Boot0003* xpf-A<TAB>HD(...)/\EFI\xpf-A\shimx64.efi` — the label is followed
   by a TAB + loader path, NOT line-end. The registration guard's `$`-anchored
   `...${slot}$` never matched → DUPLICATE slots on every run; the Go
   BootEntries `(.+)` greedy capture folded the whole path into the label key.
   FIXED: shell guard matches `...${slot}[[:space:]]`; Go regex captures
   `([^\t]+?)(?:\t.*)?$`. Locked by `TestBootEntryRegex` (incl. the no-path
   `UiApp` and no-`*` inactive cases).
2. **BootOrder A-first normalization.** `efibootmgr --create` PREPENDS each new
   entry, so creating A then B left B in front. FIXED: the oneshot records
   whether an xpf slot led BEFORE this run and otherwise deterministically
   normalizes to xpf-A,xpf-B,<rest> non-destructively.

Idempotency proven: two consecutive oneshot runs → exactly 2 slots, xpf-A first,
platform entries (UiApp/firmware/Ubuntu) preserved.

## Direction 1 — SUCCESS-PROMOTE (verified through real reboots)
- Arm `efibootmgr --bootnext 0004` (xpf-B); reboot.
- Candidate boot: `BootCurrent: 0004` (firmware HONORED BootNext, booted the
  xpf-B shim→grub→kernel slot), and `BootNext` was CLEARED by firmware (one-shot).
- Promote: non-destructive BootOrder reorder → `0004,0003,0002,0001,0000`.
- Plain reboot (NO BootNext) → `BootCurrent: 0004` — the promoted candidate is
  now the durable default across a clean reboot. Platform entries preserved.

## Direction 2 — FAIL-ROLLBACK (verified through real reboots)
- Default is 0004 (from Direction 1). Arm `--bootnext 0003` (a new "candidate").
- Candidate trial boot: `BootCurrent: 0003`, `BootNext` CLEARED, BootOrder
  default still `0004` (we did not promote).
- Simulate a FAILED gate (do NOT promote) → plain reboot → `BootCurrent: 0004`
  (the known-good slot). The firmware-cleared one-shot gave AUTOMATIC rollback —
  no boot-loop, no manual intervention. This is the load-bearing A4 guarantee:
  a candidate that fails (or hangs) + any reset falls through BootOrder to
  known-good, because no bootloader/OS write is needed at the failing moment.

## Documented residual (per directive step-3)
The true EARLY-boot-HANG auto-recovery depends on a watchdog that survives a warm
reset; incus/qemu OVMF does not expose a guaranteed warm-reset-surviving HW
watchdog, so that specific case is bench/manual-on-HW. The BOOT-LOOP itself is
closed unconditionally by the firmware-cleared BootNext (proven above in both
directions) regardless of the watchdog — the watchdog only converts a hang into
the reset that triggers the already-proven firmware fallback (Path Option D2).

## r1 Codex review fixes — re-validated live

After Codex's REQUEST-CHANGES (2 Critical, 5 High, 1 Medium), the fixes were
applied and the corrected chain re-validated:

- **Critical-1 (promotion oneshot was not shipped):** added
  `xpf-kernel-promote`(+.service) — runs `xpfd upgrade kernel promote` early on
  EVERY boot (no-op on ordinary boots; gate + reboot-on-revert on a candidate
  trial). Shipped in BOTH the bake and the .deb (debian/rules), enabled, NOT
  Before=xpfd.
- **Critical-2 (SetBootNext before ARMED journal):** the ARMED journal is now
  written BEFORE `efibootmgr --bootnext`; a crash in the window leaves a
  recoverable ARMED state Promote() acts on (BootNext failure rolls the journal
  back to INSTALLED). Covered by the existing crash-resume tests.
- **High (revert didn't restore BootOrder):** revert() now forces the known-good
  (active) slot back to the BootOrder front before rebooting.
- **High (CLI mapped all Promote errors to exit 3):** added ErrKernelReverted;
  the CLI maps ONLY a revert to exit 3, infra errors to exit 1.
- **High (install dropped linux-modules-extra):** InstallCandidateKernel now
  includes linux-modules-extra-<ver> (mlx5/i40e) when available.
- **High (weak rehold):** holdLinuxPackages returns an error (fatal on the final
  rehold); KernelHeld verifies the FULL installed linux-* set is held.
- **High (slot self-heal could undo a promoted default):** register_slot now
  verifies the loader PATH (re-creates a label-only/wrong-path entry); the
  BootOrder normalizer preserves whichever xpf slot LED before this run (a
  promoted B is kept first), only seeding A-first on a fresh box.
- **Medium (09_xpf empty cmdline + fall-through):** the fragment now sources
  grub-mkconfig_lib and BAKES the real `GRUB_CMDLINE_LINUX*` + `root=` at
  generation time, and only emits a bootable menuentry when the selector is
  valid (else falls through to the 10_linux menu).

**Re-validated live (Ubuntu 26.04 UEFI Secure Boot):**
- update-grub emits the xpf-slot block with a REAL baked cmdline:
  `linux /boot/${xpf_slot_kernel} root=/dev/sda2 ro quiet splash console=...`;
  whole grub.cfg passes grub-script-check.
- Fixed registration: idempotent (loader-path verified, 2 runs → exactly 2
  slots), xpf-A first.
- FULL CHAIN through a real reboot: arm xpf-B selector + `--bootnext 0004` →
  reboot → `BootCurrent: 0004`, BootNext cleared, OS booted (uname 7.0.0-22,
  root=/dev/sda2) — i.e. firmware → xpf-B shim → grub → 09_xpf `$cmdpath` →
  sourced xpf-B selector → kernel → running OS. The `$cmdpath` selector
  mechanism (the load-bearing A4 piece) drives a real boot.

(Note: incus `file push` intermittently truncates files; all VM file deploys
during validation were done via `cat >` over `incus exec` to avoid that.)

## r2 Codex review fixes — re-validated

Codex r2 confirmed 6/8 r1 fixes resolved + found 3 NEW issues the fixes
introduced; all addressed:

- **Critical (ForwardBeacon was not a real forward gate):** production
  NewKernelSystem didn't wire ProbeFunc, so the beacon fell back to
  `systemctl is-active` (not forwarding proof). FIXED: ForwardBeacon now does a
  REAL reachability ping through the dataplane to BeaconTarget (default = the
  IPv4 default gateway; override via XPF_KERNEL_BEACON_TARGET), requiring xpfd
  active AND a ping reply. With NO target it FAILS SAFE (returns false → revert)
  rather than promoting an unproven candidate. The promote.service After=xpfd
  ordering is now correct (the ping needs the dataplane up); the script comment
  was corrected. defaultGateway() parse is unit-tested.
- **High (PruneInactiveSlot broken on held packages + omits modules-extra):**
  FIXED: purge now uses `--allow-change-held-packages`, includes
  linux-modules-extra-<ver>, and only purges packages actually installed
  (isPkgInstalled) so a never-installed optional pkg doesn't error the purge.
- **High (slot self-heal left wrong-path duplicates):** FIXED: register_slot
  now enumerates ALL label entries, DELETES every wrong-path one
  unconditionally, and dedups correct ones to exactly one — so the slot always
  maps to a single correct Boot#### id (the Go BootEntries map can no longer
  collapse to a wrong duplicate).

Re-validated live (Ubuntu 26.04 UEFI Secure Boot):
- Dedup: injected a wrong-path xpf-A duplicate (-> \EFI\ubuntu\shimx64.efi)
  alongside the correct one; registration DELETED the wrong-path entry and kept
  exactly 1 correct xpf-A (Boot0003 -> \EFI\xpf-A\shimx64.efi).
- ForwardBeacon logic (gateway discovery + ping) is correct; the isolated probe
  VM has no network, so the beacon correctly FAILS SAFE (no target -> revert) —
  the designed conservative default. The gateway-parse is unit-tested; the live
  ping is bench-deferred (no network on the throwaway VM).

## AGY r1 review fixes — re-validated

AGY (run in the worktree) found hardware/production hazards Codex missed; all
addressed:

- **CATASTROPHIC (read-only-FS infinite reboot loop bypassing SAFE-BOOTSTRAP):**
  the gate now (a) does NOT reboot when already on a known-good slot
  (cleanupAlreadyOnKnownGood -> exit 0, no reboot), and (b) bounds revert
  reboots via PromoteAttempts <= maxPromoteAttempts (3) AND refuses to reboot if
  the journal is not persistable — so a R/O root cannot loop the box out of
  operator reach. Unit-tested (TestKernelPromoteAlreadyKnownGoodNoReboot,
  TestKernelPromoteRevertAttemptsCapped).
- **Redundant double-reboot on firmware fallback:** same cleanupAlreadyOnKnownGood
  fix — BootCurrent != candidate means we're already safe; no second reboot.
- **Watchdog 60s too short for physical POST:** default raised to 600s,
  XPF_KERNEL_WATCHDOG_TIMEOUT_SECS override; watchdog is best-effort (D2) anyway.
- **Locale-robust parsing:** captureCmd (Go) and xpf-uefi-slots (shell) now force
  LC_ALL=C/LANG=C so a localized efibootmgr heading can't break the parse.
- **09_xpf root= by UUID not /dev/sdaN:** uses GRUB_DEVICE_UUID
  (root=UUID=2e1d5b9b-... confirmed live) — survives disk-ordering shifts.
- **Destructive BootOrder wipe on empty parse:** xpf-uefi-slots now guards an
  empty ORDER and leaves NVRAM untouched (no reseed from empty -> no wipe).
- **ForwardBeacon mgmt-false-pass / BGP-false-revert:** documented that
  BeaconTarget SHOULD be a dataplane-side target (XPF_KERNEL_BEACON_TARGET); the
  gateway fallback is a weak best-effort (a false-pass still required Gate-3
  verify-dataplane PASS; the no-route case fail-safe-reverts). Acknowledged
  residual; the strong gate is an operator-set dataplane target.

Re-validated live: 09_xpf emits root=UUID=...; build/test/gofmt green.

## AGY r2 fix — separate /boot partition

AGY r2 confirmed all r1 fixes resolved; one remaining: 09_xpf hardcoded the
/boot prefix, which breaks on a foreign host with a SEPARATE /boot partition
(the kernel lives at the partition root there, not /boot/). FIXED: 09_xpf now
resolves the boot-dir prefix at generation time via
make_system_path_relative_to_its_root /boot (exactly like 10_linux) — "/boot" on
a single-root system, "" on a separate /boot partition. Live-confirmed on the
single-root VM (resolves to /boot/${xpf_slot_kernel}); grub.cfg still VALID.

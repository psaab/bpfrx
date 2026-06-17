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

# kernel_linux.go — realKernelSystem (Codex-implemented, Claude-reviewed)

Codex implemented pkg/upgrade/kernel_linux.go against the KernelSystem interface
(kernel.go). Claude review notes:

- efibootmgr parse: BootEntries/BootOrder/BootCurrent regexes correct; tolerate
  active(*)/inactive entries (Claude widened bootEntryRE to `\*?`).
- selector: GRUB-script form `set xpf_slot_kernel="vmlinuz-<u>"` written via
  fsatomic.WriteFileDurable (atomic ESP write — matches r5 AGY d + SMR N2).
- install: unhold (dpkg-query enumerated) -> apt-get install image+modules(+headers
  if available) -> update-initramfs -k <ver> -> update-grub -> rehold; deferred
  rehold on any early return so a failed install never leaves the kernel unheld.
- SetBootOrderFront: non-destructive (preserves all other ids) — r3 AGY Risk 1.
- VerifyDataplane: exit 0 PASS / exit 3 REJECT (main.go contract) / else error.
- ForwardBeacon: pluggable ProbeFunc; default = dataplane-unit-active proxy (the
  real forward probe is wired by the promotion oneshot/caller).
- Watchdog: WDIOC_SETTIMEOUT(60s)+keepalive arm; magic-'V' disarm; best-effort
  (D2 — BootNext is the loop-safety).
- PruneInactiveSlot: reset selector to known-good + best-effort purge of the
  un-promoted candidate kernel + module/boot cleanup.

Build/test: go build ./... OK; go vet ./pkg/upgrade OK; 17 kernel tests + the
existing #1917 tests green.

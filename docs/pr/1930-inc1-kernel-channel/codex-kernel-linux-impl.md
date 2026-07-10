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
- PruneInactiveSlot: reset selector to known-good FIRST (independent of the
  package cleanup, so the slot never points at a half-removed candidate), then
  purge the un-promoted candidate kernel. Manual /lib/modules + /boot cleanup
  runs ONLY after the packages are confirmed absent: on a purge FAILURE (dpkg
  lock, held-package refusal, maintainer-script error) the package-owned files
  are LEFT INTACT and a non-nil error is returned — deleting the payload while
  dpkg still records the package installed would desync the DB from the FS and
  a later same-version `apt-get install` without --reinstall would never
  restore it. A dpkg re-query confirms removal before the sweep, and
  InstallCandidateKernel forces `--reinstall` when a target package is already
  installed so an uncertain-payload retry actually restores /boot +
  /lib/modules (#5076). Test seams (injectable aptGet / dpkg-query + fsRoot)
  cover the purge-failure, partial-purge, confirmed-removal, and reinstall
  paths.

Build/test: go build ./... OK; go vet ./pkg/upgrade OK; 17 kernel tests + the
existing #1917 tests green.

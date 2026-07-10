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
- The dpkg "is this package installed?" query is TRI-STATE — installed /
  not-installed / query-error (#5428). #5076/#5427 made the sweep safe on a
  purge FAILURE and a PARTIAL purge, but both the PRE-purge installed-set loop
  and the POST-purge confirmed-absent re-query used a helper that returned
  `false` on ANY dpkg-query error, so a dpkg-DB corruption/parse error (while
  the package IS installed) read as "not installed" -> the package was dropped
  from the set, the purge was skipped, and the sweep deleted package-owned
  /boot + /lib/modules files while dpkg still owned them (the same DB/FS
  divergence, reached via a query error instead of a lock/maintainer-script
  failure). A query error now FAILS SAFE: the package is treated as
  POSSIBLY-INSTALLED so a real purge is attempted and the sweep stays gated
  behind a POSITIVE confirmed-absent re-query. isPkgInstalled distinguishes a
  genuinely-unknown package ("no packages found matching" -> confirmed absent,
  so a never-installed optional pkg is not pushed into the purge set and
  apt-get does not fail with "Unable to locate package") from a real query
  failure (DB corruption, permission, lock, missing binary -> fail safe). New
  seam signature `pkgInstalledFn func(pkg string) (bool, error)` lets a test
  inject a query error; the #5428 tests prove RED-on-revert (files swept
  without the fix).

Build/test: go build ./... OK; go vet ./pkg/upgrade OK; 17 kernel tests + the
existing #1917 tests green.

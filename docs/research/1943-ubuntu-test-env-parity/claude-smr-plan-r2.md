# Claude SMR hostile plan review — #1943 r2

Reviewer: Claude SMR. Re-review of r2 (HEAD 3f8952c04) against my r1 findings +
new-issue hunt.

## Verdict: PLAN-READY

r2 resolves my r1 findings and folds the AGY + Codex r1 findings cleanly. The
plan is implementation-ready. It is a `/research` deliverable — it correctly
stops at "here are the decisions for /engineer" rather than pre-deciding C1-vs-C2
and SB1-vs-SB2 (those are legitimately the user's calls).

## My r1 findings — disposition

- **F1 (grub mechanism on the actual stream):** RESOLVED. §6.2 now adds the
  explicit gate "the linuxcontainers stream may not carry
  50-cloudimg-settings.cfg … §8 must confirm init_on_alloc=0 reaches
  /proc/cmdline on the actual V1 image," and §8 step-4 is that check. Good.
- **F2 (V1 ≠ prod fidelity):** RESOLVED. §2 criterion 1 now says "Ubuntu-family
  parity via the linuxcontainers stream — NOT byte-identical … byte-fidelity
  boot-path validation uses the baked qcow2, Path V2." Overclaim removed.
- **F3 (SB + lockdown module load):** RESOLVED. §8 step-7 checks
  /sys/kernel/security/lockdown + confirms no out-of-tree module refusal, with
  the SB2 fallback. AGY independently confirmed XDP-type BPF is allowed under
  SB lockdown, which strengthens this.
- **F4 (destroy-path / profile lifecycle):** RESOLVED. SB1 reuses `xpf-vm`
  (no new profile → no destroy-path change), and the EFI-varstore-wiped-on-
  destroy footgun is now explicit in §6.4 + risks.
- **F5 (vestigial in-VM toolchain):** RESOLVED. §6.3 drops `golang` for certain
  and flags `build-essential clang llvm libbpf-dev` as post-#1476 candidates to
  probe. This is the simplification I wanted.
- **F6 (pin drift):** PARTIALLY ADDRESSED, acceptable. §6.1 keeps the pinned
  `26.04` default and the reasoning that the bump is a deliberate paired change.
  My suggestion to read `base_release` from bake.py's manifest was not adopted —
  that's fine; it's an enhancement, not a blocker, and a hardcoded reviewed pin
  is defensible (arguably clearer than auto-reading a manifest that may not
  exist before the first bake). Not a PLAN-READY blocker.

## New-issue hunt on r2 (hostile)

- **N1 (checked, OK):** Does dropping `clang llvm libbpf-dev` risk breaking any
  in-VM step? r2 is appropriately conservative — it says "probe-confirm; keep
  clang for ad-hoc debugging but drop golang for certain." No premature deletion.
  OK.
- **N2 (checked, OK):** The A4 mechanism correction (efibootmgr BootNext, not
  grub-reboot) is now consistent across §6.4, Path-V, §8 step-8, and the risks
  table. I verified against `pkg/upgrade/kernel.go:17-19` and
  `kernel_run.go:315` (`SetBootNext`) — the plan's description matches the
  production code. No residual grub-reboot language.
- **N3 (minor, non-blocking):** §8 step-8 V2 path says "bake.py → incus image
  import the qcow2." Worth noting at /engineer that `bake.py` needs
  RLIMIT_MEMLOCK + sudo + libguestfs (per bake.py:130-139) which the test host
  must have. Not a plan defect — it's a documented prerequisite of the existing
  bake flow — but the /engineer step should confirm the bake host is set up.
  Flag only.
- **N4 (minor, non-blocking):** The plan does not specify whether
  `linux-modules-extra-generic` (the metapackage tracking the running generic
  kernel) vs `linux-modules-extra-$(uname -r)` (version-exact) is preferred.
  bake.py gets it transitively via `linux-generic`. For the test VM that boots
  the stock image kernel, `linux-modules-extra-$(uname -r)` is the precise
  choice (the `-generic` metapackage could pull a NEWER kernel + its modules,
  re-introducing a multi-kernel situation). Worth a one-line note at /engineer;
  not a blocker since §8 step-3 asserts the driver dir exists post-install
  regardless of which name is used.

None of N1-N4 are PLAN-READY blockers. N4 is the closest to substantive and
should be a /engineer implementation note.

## Bottom line
r2 is PLAN-READY from the SMR seat. The blast radius is test-env-only, the
highest-impact footgun (`linux-modules-extra`) is caught and gated by an
assertion, the A4 mechanism is now described correctly against the production
code, and the remaining decisions (C1/C2, SB1/SB2, exact modules-extra package
name) are correctly left as /engineer-time choices with recommendations.

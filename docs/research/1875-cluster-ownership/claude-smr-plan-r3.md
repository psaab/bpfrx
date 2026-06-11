# Claude SMR plan review — #1875 r3 (delta ratification)

Reviewer: Claude (in-conversation SMR). Plan v3 @ 9f17b51b3cd2.

## Verdict: PLAN-READY

Hostile re-walk of the seven v2→v3 deltas, each against its r2
finding:

1. Lock-boundary rule (Codex r2 F1): correct and complete — I
   re-grepped `cmd_deploy` for other pre-lock mutations; the only
   shared-state writer before the build is
   `suppress_host_parent_ipv6_ra` (cluster-setup.sh:583), now moved
   inside. Target validation + `make` are genuinely local.
2. `$SCRIPT_DIR` re-exec target: strictly safer than `$0`; no
   downside found.
3. Dynamic `XPF_*`/`BPFRX_*` forwarding through the sg re-exec +
   §9.2d pinning the actual shape: resolves my S1 REQUIRED finding.
   The `${!XPF_@}` prefix expansion forwards only *exported* vars in
   `printf %q` form — no injection surface beyond what the existing
   `BPFRX_CLUSTER_ENV` re-injection already accepts.
4. dev:ino revalidation + fail-closed split-mutex assertion: resolves
   my S2. The §9.2g matrix cell now tests both halves (live holder →
   abort naming both inodes; dead holder → normal acquire).
5. Invariant 7.2 restatement: accurate — the marker-exporting
   distinction is the load-bearing part.
6. A3b apply-cos self-lock: consistent with the A3 pattern; no build
   step, so no lock-across-build hazard; reentrant inside cells.
7. Blocking-default 3-of-3: recorded correctly.

## §13 answer

The false-positive surface is acceptably rare and the failure
direction is right. Worked through: a false abort requires (a) the
wrapper specifically SIGKILLed so the EXIT trap never ran (TERM/INT/
tree-kill all clean up), (b) the dead holder's pid recycled by a
still-live process before the next acquire (pid_max on this class of
dev box makes same-day recycling unlikely), and (c) the next acquire
happening while that recycled pid lives. The abort message names both
dev:inodes and the recorded pid, so the operator recipe ("verify
`fuser -v` shows no real holder, then wait or clear the stale owner
per the docs") resolves it in seconds — against the alternative
failure direction, which is the silent two-holder clobber this issue
exists to kill. The `/proc/<pid>/stat` starttime hardening defeats
pid recycling completely for ~4 lines; I judge it OPTIONAL (implement
if it falls out naturally, skip if it complicates the `set -e`
discipline) — cooperating agents do not need it and the plan's own
over-engineering guardrail (§3) applies.

No new findings. The plan is implementable as specified; remaining
risk lives in shell mechanics that §9's matrix is specifically
designed to catch at /engineer time.

# Claude SMR plan-review — #1771 round 3 (v3 @ da629b731)

**Verdict: PLAN-READY for Phases 1–3 (Path B); §2.1 (Phase 4) PLAN-READY-IF-MEASURED.**

v3 folded every round-2 finding I and the other two reviewers raised. I
re-attacked the two v3-introduced changes (upsert-only §2.5, hardened §2.1)
for *new* defects:

- **§2.5 upsert-only — one residual staleness, acceptable.** Re-adding
  kernel entries via `insert_if_changed` can overwrite a *fresher*
  RX-learned MAC with the kernel's slightly-staler view during the re-dump.
  This self-corrects on the next RX/monitor event and only fires on the
  rare ENOBUFS path; it is strictly better than the lost-NEWNEIGH blackhole
  it fixes. Worth a one-line note in the plan, not a blocker. The upsert-only
  design correctly dissolves the kernel-ownership defect (Codex r2-1) and
  the with_all_shards I/O risk (AGY r2-E) — no eviction, per-key sharded
  insert only.
- **§2.1 hardened — the resurrection window is closed.** The
  global-monotonic epoch makes a post-GC snapshot value unmatchable by any
  future slot, and reject-on-absent-slot removes the "create if absent"
  hole independently; the `enqueued_ns` age-discard is a third layer. Any
  one suffices; together they're airtight. Incremental per-shard GC removes
  the stop-the-world concern (AGY r2-C). The API-audit checklist (Codex
  r2-2) is the right shape — its completeness is a code-review matter at
  /engineer time, not a plan gap.

**Why §2.1 stays gated, not built:** all three reviewers agree the global
epoch is already correct and `epoch_rejects` is already exported. Building
the co-located-slot surgery (hottest shared map) to shave a retry rate
nobody has measured is the wrong order. Phase 4 should fire only if
`epoch_rejects` reads materially nonzero under load.

**Recommendation:** ship Phases 1–3 via `/engineer 1771` (each phase an
independent merge, smoke-clean on its own). Keep §2.1 gated. The one nit:
add the §2.5 RX-fresher-MAC staleness note. Not a blocker.

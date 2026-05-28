# Claude SMR plan-r5 — #1620 BindingWorker cold-path integration

**Reviewer**: Claude (domain SMR)
**Plan doc**: plan.md v4 (post-Codex-r4 doc cleanup)
**Verdict**: PLAN-READY

## Resolution check vs r4

- **AGY r4** (adversarial-review-mppm7cic-qw93ab): **PLAN-READY**.
  v4 substantively absorbed all of AGY's r3 amendments.
- **Codex r4** (task-mppm70jl-1zhg3q): **PLAN-NEEDS-MINOR** but
  the only blocker was documentation consistency in §4.1 — the
  pre-amendment plan code snippets still showed v3 layout (without
  `sample_phase` on atomics and without `wrapper_underflow_count`
  on either struct); offsets in the layout-math block were stale;
  the publish-store count was 448 not 450; the cargo-test count
  was 20 not 28. Substantively Codex r4 confirmed v4 design.

## Post-Codex-r4 doc cleanup (this round)

1. §4.1 struct snippets updated to v4 final layout with all six
   fields on both `WorkerColdPathCounters` and `WorkerColdPathAtomics`
   (added `sample_phase` and `wrapper_underflow_count` to the
   pre-amendment snippets that previously showed v3 only).
2. §4.1 ClockSource enum now shown with `#[repr(u8)]` annotation
   (v4 amendment).
3. §4.1 layout-math block updated: clock_source @ 32 (not 24);
   alias_seen @ 33 (not 25); first_key @ 56 (not 48); plus the
   atomics layout block now explicit.
4. §6 invariant text: "all 448 atomic stores" → "all 450 atomic
   stores" with reference to the two new v4 fields.
5. §8 test plan: "20 tests" → "28 tests" with [x] check mark since
   cold_path_hist:: now genuinely passes 28/28.
6. §2 cardinality footnote: "~451 atomics × 6 workers" → "~453".

## Code-side state vs plan

Already in tree (commit efeac19f9):
- `#[repr(u8)]` on `ClockSource` ✓
- `WorkerColdPathCounters` field layout matches plan §4.1 v4 ✓
- `WorkerColdPathAtomics` field layout matches plan §4.1 v4 ✓
- `publish_from_local` round-trips `sample_phase` + `wrapper_underflow_count` ✓
- `snapshot` round-trips both ✓
- 3 new tests passing ✓
- Go-side `ColdPathSampleMask *uint64` on `ConfigSnapshot` ✓
- Go-side `cold_path_sample_mask_test.go` with 4 round-trip tests ✓
- Rust-side `cold_path_sample_mask: Option<u64>` on `ConfigSnapshot` ✓
- `cmd/xpfd/main.go` two-flag CLI + validator ✓
- `daemon.Options.ColdPathSampleMask *uint64` ✓

Remaining implementation work for #1620 (out of scope for plan
review; pure execution after PLAN-READY):
- BindingWorker.cold_path field + sibling Arc<[atomics]> plumbing.
- Two poll_descriptor/mod.rs call sites (sample-record blocks).
- worker_runtime.rs::publish hook for cold_path publish.
- worker/loop_body coordinator-side probe + per-worker calibrate.
- Thread the `ColdPathSampleMask` field from daemon.Options →
  ConfigSnapshot → userspace-dp WorkerContext.

## Verdict — PLAN-READY

AGY r4 PLAN-READY confirmed. Codex r4 doc-consistency findings
fully addressed in this round's plan.md edits. Three-way + the
PR-author's SMR all attest the plan is ready for the remainder
of Step 5 implementation.

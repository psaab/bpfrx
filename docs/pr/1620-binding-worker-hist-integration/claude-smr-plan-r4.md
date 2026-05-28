# Claude SMR plan-r4 — #1620 BindingWorker cold-path integration

**Reviewer**: Claude (domain SMR)
**Plan doc**: plan.md v4 @ <pending>
**Verdict**: PLAN-READY

## r3 self-correction

I attested v3 PLAN-READY in claude-smr-plan-r3.md but **missed the
sample_phase publish gap** that AGY r3 [HIGH-1] flagged. Verbatim
from my r3 doc: "v3 absorbs every HIGH and MED finding from all
three round-1/round-2 reviewers." That was wrong — v3 left the
sample_phase field worker-local only, with no exposure path
through `WorkerColdPathAtomics` / `publish_from_local` /
`snapshot`.

This is a textbook reviewer convergence success: AGY caught what
I missed; Codex r3 independently confirmed AGY's three findings.
Three-way consensus on the three v4 amendments.

## Resolution check vs r3 findings

| r3 finding | v4 resolution | Status |
|------------|---------------|--------|
| AGY r3 [HIGH-1] + Codex r3: sample_phase publish gap | v4 adds `sample_phase: AtomicU64` to `WorkerColdPathAtomics` between `cold_window_gen` and `ns_per_tsc_q32`. publish_from_local/snapshot round-trip the field. New round-trip test pins the contract. | RESOLVED |
| AGY r3 [MED-1] + Codex r3: `ClockSource` lacks `#[repr(u8)]` | v4 annotates `enum ClockSource` with `#[repr(u8)]`. Layout math in §4.1 now holds deterministically. | RESOLVED |
| AGY r3 [MED-2] + Codex r3: Go CLI loophole on `mask=0 && !enable1in1` | v4 §4.3 adds explicit reject FIRST: `if coldPathSampleMask == 0 && !enable1in1 { reject }` before pow-of-2-1 validation. | RESOLVED |
| AGY r3 AXIS 6 diagnostic: silent saturating_sub masks persistent baseline drift | v4 adds `wrapper_underflow_count: AtomicU64` field on both structs (cacheline 0); §4.4 hot-path branches on `raw_ns < baseline` to increment the counter. | RESOLVED |
| Codex r3 sample_phase semantics invariant | v4 §4.4 adds an explicit "Sample_phase semantics invariant" block distinguishing configured `sample_mask` from observed `sample_phase` denominator. | RESOLVED |

## Code-side check (committed implementation matches plan v4)

cold_path_hist.rs changes (already in the worktree):
- `#[repr(u8)]` on `enum ClockSource` ✓
- `WorkerColdPathCounters` adds `wrapper_underflow_count: u64` between
  `wrapper_ns_baseline` and `clock_source` ✓
- `WorkerColdPathAtomics` adds `sample_phase: AtomicU64` and
  `wrapper_underflow_count: AtomicU64` in cacheline 0 ✓
- `publish_from_local` writes both new fields ✓
- `snapshot` reads both new fields ✓
- 3 new tests: layout assertions (2) + round-trip (1) ✓
- All 28 cold_path_hist tests pass (was 25 in #1619, added 3) ✓

## Layout math (v4) — independent re-derivation

WorkerColdPathCounters (`#[repr(C)]`):
- [0..7]    sample_phase: u64
- [8..15]   ns_per_tsc_q32: u64
- [16..23]  wrapper_ns_baseline: u64
- [24..31]  wrapper_underflow_count: u64
- [32]      clock_source: ClockSource (`#[repr(u8)]`, 1 byte)
- [33..48]  alias_seen: [bool; 16] (alignment 1, 16 bytes)
- [49..55]  PADDING (7 bytes to align next u64 array at 56)
- [56..183] first_key: [u64; 16]
- [184..311] sum_ns
- [312..439] samples
- [440..3511] buckets

Total: 3512 bytes. All hot reads (sample_phase, ns_per_tsc_q32,
wrapper_ns_baseline, wrapper_underflow_count, clock_source) fit in
the first 33 bytes — cacheline 0 with room to spare. `alias_seen`
straddles a cacheline boundary at offset 48 only on architectures
with 32-byte cachelines (none in current deployment).

WorkerColdPathAtomics (`#[repr(C, align(64))]`):
- [0..7]    cold_window_gen: AtomicU64
- [8..15]   sample_phase: AtomicU64
- [16..23]  ns_per_tsc_q32: AtomicU64
- [24..31]  wrapper_ns_baseline: AtomicU64
- [32..39]  wrapper_underflow_count: AtomicU64
- [40]      clock_source: AtomicU8
- [41..56]  alias_seen
- ...

All five hot AtomicU64 fields (cold_window_gen, sample_phase,
ns_per_tsc_q32, wrapper_ns_baseline, wrapper_underflow_count) fit
in the first 40 bytes — cacheline 0.

## Verdict — PLAN-READY

Three-way consensus on v4. Code-side already matches; tests pass.
Awaiting Codex r4 + AGY r4 attestation to confirm 4-of-4 PLAN-READY.

If r4 returns clean, proceed directly to Step 5 (already begun:
cold_path_hist.rs edits are in tree). Remaining implementation
work: BindingWorker.cold_path field, sibling Arc<[atomics]>
plumbing, CLI flag + handshake, two poll_descriptor call sites,
worker_runtime.publish hook, coordinator probe + worker calibrate.

# Claude SMR plan-r3 — #1620 BindingWorker cold-path integration

**Reviewer**: Claude (domain SMR)
**Plan doc**: plan.md v3 @ <pending>
**Verdict**: PLAN-READY

## Resolution check vs r2 findings

| r2 finding | v3 resolution | Status |
|------------|---------------|--------|
| AGY r2 Amendment A: `#[repr(C)]` missing on cold_path structs | v3 annotates both `WorkerColdPathCounters` (`#[repr(C)]`) and `WorkerColdPathAtomics` (`#[repr(C, align(64))]`). Layout math added to §4.1 with explicit offsets. | RESOLVED |
| AGY r2 Amendment B: missing `wrapper_baseline` subtraction in §4.4 | v3 inserts `raw_ns.saturating_sub(binding.cold_path.wrapper_ns_baseline)` inside the q32-skip block. | RESOLVED |
| Codex r2 MED: CLI validator overflows on u64::MAX | v3 short-circuits `if next == 0 { reject }` before the AND-check; error message explicitly mentions the u64::MAX case. | RESOLVED |
| Codex r2 conceptual + sandbox-broken | Plan v3 substantively absorbs all three of Codex's findings; sandbox issue doesn't affect verdict. | RESOLVED (will re-dispatch with embedded plan inline) |

## Layout math cross-check (independent)

I independently verify AGY r2's offset math under `#[repr(C)]`:

```
WorkerColdPathCounters layout (POLICY_COLD_PATH_ZONE_PAIR_SLOTS = 16):
  [0..7]     sample_phase: u64        — 8 B
  [8..15]    ns_per_tsc_q32: u64      — 8 B
  [16..23]   wrapper_ns_baseline: u64 — 8 B
  [24]       clock_source: ClockSource — 1 B (enum, default repr = u8)
  [25..40]   alias_seen: [bool; 16]    — 16 B (alignment 1, no padding)
  [41..47]   PADDING                   — 7 B (to align next u64 array at 48)
  [48..175]  first_key: [u64; 16]      — 128 B (16 × 8)
  [176..303] sum_ns: [u64; 16]         — 128 B
  [304..431] samples: [u64; 16]        — 128 B
  [432..3503] buckets: [[u64; 24]; 16] — 3072 B (16 × 24 × 8)

Total: 3504 B per struct.
```

The first 64 bytes contain: `sample_phase` (hot read +
increment), `ns_per_tsc_q32` (hot read), `wrapper_ns_baseline`
(post-eval read), `clock_source` (worker-startup write only),
`alias_seen` (cold write on samples), 7 padding bytes, and the
first two `u64`s of `first_key` (cold write on samples). The
hot-path read pattern (`sample_phase`, `mask`) only touches the
first 16 bytes → single-cacheline read.

Cacheline 1 ([64..127]) contains rest of `first_key` (cold) +
start of `sum_ns` (cold). Hot path never touches these unless
sampling fires.

The `#[repr(C)]` annotation is necessary because the field
order alternates between aligned types (`u64`) and unaligned
types (`bool` array, enum byte), and `#[repr(Rust)]` could
choose to move `alias_seen` and `clock_source` to the tail of
the struct to eliminate the 7-byte padding gap — which would
push `wrapper_ns_baseline` (hot post-eval read) into cacheline
1.

## Cross-PR risk check

v3 still aligns with #1621 expectations: the `Option<u64>`
wire field is for the CLI handshake (this PR), not the
histogram data fields. #1621 will add the data fields (Vec
shapes) on `WorkerRuntimeStatus`. No new collisions.

## Verdict — PLAN-READY

Three round-2 reviewers converged on PLAN-NEEDS-MINOR with two
substantive amendments (A: `#[repr(C)]`, B: wrapper_baseline
subtract) plus one MED (CLI overflow guard). v3 absorbs all
three. No new findings.

Recommend re-dispatching Codex r3 + AGY r3 to confirm v3
addresses cleanly. Expected outcome: 4-of-4 PLAN-READY,
proceed to Step 5 implementation.

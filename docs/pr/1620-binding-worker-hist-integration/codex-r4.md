Verdict: `PLAN-NEEDS-MINOR`.

Conceptually/code-side, yes, v4 absorbed the r3 findings:

1. `sample_phase` publish gap: resolved in code via `WorkerColdPathAtomics.sample_phase`, `publish_from_local`, `snapshot`, and round-trip test.
2. `ClockSource #[repr(u8)]`: resolved.
3. Go CLI `mask=0 && !enable1in1`: resolved in §4.3.
4. `wrapper_underflow_count`: semantics look sound. Worker-local monotonic `u64`, published through atomics, incremented on `raw_ns < baseline`, and still recording `delta_ns = 0` preserves sample accounting while making baseline drift visible.

The blocker is documentation consistency in committed `plan.md` and nearby comments:

- `docs/pr/1620-binding-worker-hist-integration/plan.md:200` struct snippets are still v3-shaped. They omit `WorkerColdPathCounters.wrapper_underflow_count` and omit both `WorkerColdPathAtomics.sample_phase` and `wrapper_underflow_count`.
- `plan.md:251` layout math still says `clock_source` at offset 24 and `alias_seen` at 25. v4/code/tests correctly make those 32 and 33.
- `plan.md:650` still says `publish_from_local` brackets 448 stores; v4 payload is now 450 copied fields by the plan’s own accounting.
- `plan.md:676` still says existing 20 cold-path tests; v4 says 28.
- `cold_path_hist.rs` has stale prose around the same old offsets even though the actual tests assert the correct v4 offsets.

So: the design is effectively ready, but the committed plan artifact is not clean enough to call `PLAN-READY` because §4.1 remains contradictory. Patch the stale snippets/layout/store-count/test-count comments to the v4 layout you pasted, and my verdict becomes `PLAN-READY`.

I did not run tests; the sandbox is read-only. I reviewed `efeac19f9` directly.

Codex session ID: 019e6f14-f0f3-7620-8679-af53718af514
Resume in Codex: codex resume 019e6f14-f0f3-7620-8679-af53718af514

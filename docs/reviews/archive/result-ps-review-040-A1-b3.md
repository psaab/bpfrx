# Triage Result — ps-review-040-A1-b3

- **Subsystem/Area**: A1 (userspace-dp: event_stream, afxdp/worker/cos, fairness, filter, screen, session, server, protocol) — Batch 3
- **Review base commit**: `0ebdb74b2e8bf04b40495f49b6a64f9146af09fc` (Merge #4428, 2026-07-06)
- **Base == current master?**: NO. Base is an ancestor of `origin/master` but **397 commits behind**.
- **Current master SHA**: `95b33d49634d56086269a62a92e213dae7926f88`
- **Repo**: real bpfrx (`psaab/xpf`) — all cited paths exist on master; no avacado-xpf fork references.
- **Outcome counts**: 2 findings triaged → **1 ALREADY-FIXED, 1 NOT-MATERIAL**. 0 GENUINE-RESIDUAL. (Part 2 = ~130 negative-result sweeps, no findings.)

Both findings are **test-only** (self-labeled `test-suite-flakiness`, Low/Medium). Neither
alleges a production-path defect. Both target `userspace-dp/src/event_stream/tests.rs`.

---

## Finding 1 — Telemetry eviction underflow panic in debug build (Low) → ALREADY-FIXED

**Claim**: `test_paused_telemetry_eviction_does_not_poison_drain_2875` fills the replay
buffer via `push_replay_frame` (bypassing `emit`, so budget is never acquired), then an
eviction calls `release()` → `decrement_if_positive` on a zero counter → `debug_assert!(false,
"dataplane event queue budget underflow")` fires and fails the test in debug builds.

**Why ALREADY-FIXED**: This is exactly the #4607/#4608 "broken-master / debug-cargo-exposed-what-
release-hid, #2875 test-drift-not-prod-bug" issue that was found and fixed **this session**
(recorded in MEMORY). The review was written against base `0ebdb74` (2026-07-06), which
predates the fix.

Disproving evidence on current `origin/master`:
- Fix commit present: `82cba2a9d event_stream: seed queue budget in the #2875 telemetry-eviction test`.
- The test at `tests.rs:2136-2181` (master) now calls **`push_budgeted_replay_frame`**, not
  `push_replay_frame`. The review's quoted code (lines 2125-2139 using bare `push_replay_frame`)
  reflects the OLD pre-fix body.
- Helper `push_budgeted_replay_frame` (`tests.rs:2065-2075`) does
  `if let Some(kind) = frame.dataplane_event_kind() { shared.dataplane_event_queue.acquire_for_test(kind); }`
  before pushing — i.e. it seeds the per-kind budget the producer's `emit` would have charged,
  so the eviction's `release()` decrements a positive counter and the guard is never tripped.
  `acquire_for_test` exists at `producer.rs:198`.
- The helper's doc comment explicitly names the bug: "seed the per-kind queue budget the
  producer's `emit` would have charged for it (#4607) ... without the seed here the release
  decrements a zero counter and trips the #1826 underflow guard (`decrement_if_positive`) —
  the actual #4607 panic."
- `decrement_if_positive` / `debug_assert!(false, ...)` still exist at `producer.rs:437-441`
  (the production guard is intentionally retained; the fix was to the TEST, not the guard —
  matching the review's own "this is a test bug" refutation).

Disposition: **ALREADY-FIXED** (dup of #4607/#4608, closed this session by commit `82cba2a9d`).

---

## Finding 2 — Flaky `stalled_consumer_does_not_grow_backlog_unbounded_end_to_end` (Medium) → NOT-MATERIAL

**Claim**: Once `frames_dropped > 0` trips, the inner retry loop breaks immediately for every
remaining frame, so the outer `for seq in 0..frames_to_pump` loop "terminates in microseconds,
far before the background thread ... accumulates `WRITE_BACKLOG_MAX_BYTES`". Trace step 8:
"The test then checks `frames_write_stalled > 0`, which evaluates to false, and panics."

**Why NOT-MATERIAL (review misread the test)**: The trace omits the code between the for-loop
and the assertion. On `origin/master` (`tests.rs:1077-1085`) — and **identically at the review's
own base `0ebdb74`** — there is a bounded-wait poll loop:

```rust
let deadline2 = Instant::now() + Duration::from_secs(5);
while shared.frames_write_stalled.load(Ordering::Relaxed) == 0
    && Instant::now() < deadline2
{
    let _ = handle.try_send(EventFrame::encode_drain_complete(0));
    thread::sleep(Duration::from_millis(1));
}
```

Only after this loop does the `assert!(frames_write_stalled > 0, ...)` at line 1089 run. So the
review's step 8 — "checks ... immediately ... and panics" — is factually wrong. The test does
NOT assert immediately after the for-loop; it waits up to 5 seconds for the stall to trip,
`thread::sleep(1ms)` each iteration. The 1ms sleep parks the test thread and yields the CPU to
the background `run_connected_loop` consumer, giving it abundant scheduling to: pull frames from
the bounded channel → write to the wedged (never-read) socket → get `WouldBlock` → migrate to
`write_buf` → reach `WRITE_BACKLOG_MAX_BYTES` → set `frames_write_stalled`.

The shedding/backlog model holds: `frames_to_pump = (WRITE_BACKLOG_MAX_BYTES/frame_bytes)*3 + 4096`,
and `handle.try_send` increments `frames_dropped` on a full channel (`producer.rs:343/353`), so
well over one backlog-cap worth of frames reaches the consumer's `write_buf` even after the fast
for-loop. The "instantaneous termination → immediate false assert" premise is disproven by code
present in BOTH base and master; the test is engineered specifically to defeat this scheduling
race with the deadline2 wait. (The test has been on master 397+ commits without being the flake
the review predicts.)

Disposition: **NOT-MATERIAL** — misread of a hardened test; the disproving `deadline2` poll loop
exists at `tests.rs:1077-1085` on both the review base and current master.

---

## Part 2 (negative-result sweeps)
~130 module-sweep "Negative Result" entries (cos/*, fairness*, filter/*, screen/*, session/*,
server/*, protocol/*, event_stream/*, xdp shim). No findings asserted; nothing to triage. Paths
all exist on master. No action.

## Summary
No genuine residuals. Finding 1 is the already-closed #4607/#4608 (fixed by `82cba2a9d`, review
base predates it). Finding 2 is a misread — the test's 5s `deadline2` wait loop (present at base
and master) defeats the alleged race. Consistent with the ps-039/040 expectation: heavily-hardened
scopes yield ~0 residuals.

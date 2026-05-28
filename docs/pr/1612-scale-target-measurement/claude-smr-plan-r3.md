# Claude SMR Plan Review — #1612 step-3 v3

**Plan**: `docs/pr/1612-scale-target-measurement/plan.md` v3, 2026-05-28.

**Codex r2 verdict**: PLAN-NEEDS-MAJOR with 3 new findings on v2:

1. HIGH — `XPF_COLD_PATH_SAMPLE_MASK` env-override won't propagate
   through `systemctl restart xpfd` (no `Environment=` in unit file).
2. MED — `telemetry.counters.session_misses` is a per-poll
   `BatchCounters` accumulator (reset at flush), not a monotonic
   sample-phase counter; undersamples partial polls.
3. HIGH — `keys_xor` alias detector false-passes on
   `count(K) odd + count(L) even`.

Plus three NIT-level items (sentinel string consistency, Acquire
fence in snapshot reader, bucket-clamp tests at 2^32 boundary).

**Verdict (r3)**: PLAN-READY

## Codex r2 fix audit

| Finding | v3 location | Resolved? |
|---------|-------------|-----------|
| HIGH 1: env-override won't propagate | §1.3 — replaced with daemon CLI flag `--cold-path-sample-mask <N>` parsed by `cmd/xpfd/main.go` and threaded into control-socket bootstrap; harness sets via `cli configure` (preferred) or systemd drop-in | YES |
| MED 2: per-poll session_misses counter | §1.3 — sample-gate counter is now `binding.cold_path.sample_phase: u64` (worker-local monotonic, NOT BatchCounters), bumped on every session-miss path before the gate check | YES |
| HIGH 3: keys_xor false-pass | §1.1 + §3.4 — replaced keys_xor with `first_key + alias_seen` pair per slot. Hot-path update is 1 branch + 2 array loads + 1 conditional store. Alias detector is monotonic: once any sample with a key different from `first_key` lands, `alias_seen` stays true for the publish window. Codex r2's count(K)=odd + count(L)=even false-pass counter-example is provably caught. The cold_path_hist.rs scaffolding now includes a `record_sample_codex_r2_false_pass_counter_example` test that demonstrates this. | YES |
| NIT: sentinel string consistency | v3 §3.4 + §6 use `MEASUREMENT DEFERRED` (with space) consistently. Acceptance criterion text updated. | YES |
| NIT: Acquire fence in snapshot reader | Already present in `cold_path_hist.rs::snapshot` (line `std::sync::atomic::fence(Ordering::Acquire)` between Relaxed payload loads and s2 generation re-check); matches `worker_runtime.rs:323` template. | YES |
| NIT: bucket clamp tests at 2^32 boundary | Already present in `cold_path_hist.rs::bucket_23_saturates_at_2_pow_32_ns` and `bucket_22_lower_edge_is_2_pow_31_ns`. | YES |

All 3 Codex r2 findings + 3 NITs resolved.

## Implementation status (v3 scaffolding milestone)

`userspace-dp/src/afxdp/cold_path_hist.rs` exists in this branch
with 18 cargo tests passing:

```
$ cd userspace-dp && cargo test --release cold_path_hist::
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured
```

Tests include:
- Bucket boundary asserts at 1024 ns (bucket 0→1), 2^31 ns (22→23),
  2^32 ns (23 saturation), u64::MAX (saturated).
- Bucket-formula consistency with the existing 16-bucket
  `bucket_index_for_ns` over the shared subrange.
- Splitmix avalanche over the zone-id diagonal.
- Packed key sentinel: `(0, 0) → 1` (non-zero) to disambiguate
  "no sample" from "(0, 0) sample".
- Packed key direction asymmetry: `(1, 2) ≠ (2, 1)`.
- ClockSource u8/string round-trip.
- `record_sample` updates all fields correctly.
- `record_sample_same_key_twice_no_alias` — confirms no false-positive
  on repeated key.
- `record_sample_detects_alias` — confirms detection on any slot
  collision via dynamic search of the 65k×65k zone-pair space.
- `record_sample_codex_r2_false_pass_counter_example` — explicitly
  exercises Codex r2's count(K)=3 odd + count(L)=2 even counter-
  example and confirms `alias_seen == true`.
- Sample TSC monotonicity within thread.
- WorkerColdPathAtomics seqlock snapshot round-trip (single-thread
  + back-to-back publish).

## STAGED-ship recommendation

Per plan §6 + Codex r2 finding 5 (STAGED disclaimer): given the
breadth of remaining integration work (CLI flag threading,
control-socket plumbing, wire-protocol Rust+Go, Prometheus emitter,
synthetic-policy-gen.py, harness shell, 4-rule-count measurement
sweep, smoke matrix Pass A + B) AND the cluster contention with two
parallel sub-agents (#1609 v2 + #1614), the right ship form is:

1. **PR A (THIS PR)** — ship `cold_path_hist.rs` scaffolding + v3
   plan + plan archive. Tests-passing module is reusable
   infrastructure. NO dataplane hot-path changes; NO wire-protocol
   changes; NO new external surface area. Smoke regression risk is
   zero (the module is referenced nowhere outside its own tests).
2. **Follow-up issue PR B** — BindingWorker integration: thread
   the sample_mask through the control-socket bootstrap; add the
   CLI flag in `cmd/xpfd/main.go`; insert the two-line sample-gate
   in `poll_descriptor/mod.rs`; extend `worker_runtime.rs::publish`
   to call `WorkerColdPathAtomics::publish_from_local`.
3. **Follow-up issue PR C** — wire-protocol (Rust + Go) + Prometheus
   emitter + Go tests.
4. **Follow-up issue PR D** — synthetic-policy-gen.py +
   cold-path-microbench.sh + measurement run + populated Tables
   A1/A2/B1/B2 in `docs/userspace-jit-design.md`.

This staging respects the file-zone-disjoint principle for
parallel sub-agents and lets the measurement run be sequenced
once #1609 v2 + #1614 either merge or kill.

The Scale Target section in `docs/userspace-jit-design.md` gets
the explicit `MEASUREMENT DEFERRED` disclaimer header per plan §1.9.
PR description carries `Refs #1609 v2 acceptance REMAINS UNMET`
per plan §6 + Codex r2 finding 5.

## Round 3 dispatch plan

Codex r3 (this v3) + AGY r3 in parallel. Verify all 3 Codex r2
findings are resolved; demand quote-line evidence per resolution.

## Verdict r3: PLAN-READY (provisional pending Codex r3 + AGY r3)

v3 addresses all r2 findings with provable counter-example tests in
the scaffolding module. The STAGED-ship form is the honest scope
for the cluster + time-budget reality.

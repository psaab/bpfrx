# Claude-SMR hostile plan review — #1750 r1

Reviewing my own plan v1 (`plan.md` @ 908c6177c) as domain SMR (AF_XDP
dataplane), CPU-arch/concurrency, and SW-design. Hostile, not synthesizer.

## Verdict: PLAN-NEEDS-MAJOR (self-corrected)

v1's recommended direction (Path 1: flow_cache scan is the right source;
consume count+rows from one snapshot) survives, but v1 contains a **false
load-bearing claim** and **misses a second independent zero-install root
cause**. Both must be fixed before PLAN-READY.

### MAJOR-1 — "published atomically together" is FALSE (spine error)
v1 §2 asserts count and rows "are published atomically together" and therefore
"cannot disagree at the binding level." The first clause is wrong. In
`umem/debug_state.rs`:
- `binding.live.active_flow_count.store(active_flow_count, Ordering::Relaxed)`
  (AtomicU32 store), and
- `binding.live.publish_flow_worker_map(rows, truncated)` →
  `self.flow_worker_map.store(Arc::new(FlowWorkerMapSnapshot{rows,truncated}))`
  (separate ArcSwap store)
are **two independent atomic operations** with no enclosing transaction. They
derive from one scan, but a reader can observe a fresh count with stale rows.
So count/rows CAN disagree at a reader — which is exactly the issue's symptom.
v1's conclusion ("consumer-side skew, not a flow_cache fault") is still correct,
but the *reason* must be restated: the skew is a real non-atomic dual-publish,
not merely an out-of-band Prometheus scrape. This strengthens Path 1 (bundle
both into ONE snapshot struct) — but v1's justification was wrong.

### MAJOR-2 — slot vs worker_id keying mismatch (independent zero-install bug)
`Coordinator::tick_rebalance` iterates `for (&worker_id, live) in
&self.workers.live` (`coordinator/rebalance.rs:209`) — but `workers.live` is
**keyed by `binding.slot`** (`worker_manager.rs:6` doc + `bringup.rs:47`
`live.insert(binding.slot, ...)`), NOT by worker_id. The published rows carry
the real `binding.worker_id` (`debug_state.rs`/`poll_descriptor/mod.rs:434-436`),
and `select_move` filters `f.worker_id == hottest.worker_id`
(`controller.rs:507-511`). When slot ≠ worker_id (shared-UMEM / multi-binding-
per-worker), the per-worker rate vector is keyed by SLOT while flow rows are
keyed by WORKER_ID → the equality filter yields `candidate_count == 0` →
`no_eligible_flow` → zero installs, **independent of any feed reliability fix.**
On the 6-queue/6-worker mlx5 smoke cluster slot likely == worker_id (1:1), so
the bug is latent there but real on other configs. v1 missed this entirely; it
must be a first-class root cause and the increment must make the controller's
worker-identity keying consistent (key everything by the published
`worker_id`, or by slot, but ONE of them end-to-end).

### MAJOR-3 — §6.3 dedup-insert carry-forward is DEAD CODE
v1 §6.3 proposes carrying `observed_bytes` forward in the `insert`
dedup-on-insert branch (`flow_cache.rs:686-694`). That branch is effectively
unreachable in production: the hot path always `lookup_counted` first
(`poll_descriptor/flow_cache_hit.rs:94`); a hit skips insert; a miss means the
key is absent (or was just deleted by the lookup's generation/epoch/lease
invalidation, `flow_cache.rs:625-652`), so `insert` never finds a matching key
to dedup. Therefore the proposed carry-forward never runs and does NOT fix the
`observed_bytes` reset under LRU/eviction churn. The only correct carry-forward
is a cold-path eviction side-table (v1 Path 2 option 2). v1 overstated the cheap
option; remove §6.3-as-written.

## Things v1 got right (keep)
- flow_cache scan IS the authoritative per-worker enumeration; no new hot-path
  table needed (Path 3 correctly rejected).
- Q2: per-flow RATES unnecessary for homogeneous P12; worker-rate/count fallback
  is the physically-correct estimate (R1 round-robin re-pin validates).
- Reactive controller approach is right (Q4); PLAN-KILL is wrong (Q5).
- Mandatory pre-code debug-log live trace to identify the live cause + live CoV
  gate as acceptance.

## Additional mechanism v1 under-weighted (from the live-cause set)
- **Age-out at low PPS:** `active_entry_age` window is 10 epochs ≈ 650 ms; a
  flow quieter than ~1 pkt/650 ms drops out of BOTH count and rows. Not the P12
  line-rate symptom, but a real "rows empty for a live flow" mechanism the feed
  design should tolerate (don't treat a one-tick empty as terminal).
- **Idle/low-PPS publish lag:** the 0xFFFF poll-counter gate can lag minutes on
  a sleeping worker; the 65 ms idle wall-clock path
  (`update_binding_idle_debug_state`) mitigates only on RX-empty. The
  defer-on-stale guard (v1 §6.2) is the right tolerance for this.

## Required for PLAN-READY (v2)
1. Reword §2: count/rows are same-scan but NON-atomically dual-published →
   real reader skew. Path 1 = bundle both into one `FlowWorkerMapSnapshot`.
2. Add MAJOR-2 (slot/worker_id keying) as a first-class root cause + fix; make
   the live trace check BOTH the row-presence AND the worker-id match.
3. Replace §6.3 with the eviction side-table (or drop carry-forward to a
   documented follow-up); state the dedup branch is dead in production.
4. Keep the rest.

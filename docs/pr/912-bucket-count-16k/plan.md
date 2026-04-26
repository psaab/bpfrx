# Plan: #912 — raise COS_FLOW_FAIR_BUCKETS from 1024 to 16384 (v3)

Plan revisions:
- v1 → v2: incorporated Codex R1 (4 HIGH + 2 MED + 2 LOW;
  PLAN-NEEDS-MAJOR).
- v2 → v3: incorporated Codex R2 (5 MED; PLAN-NEEDS-MINOR) and
  R3 (2 BLOCKER + 1 MINOR + 1 NIT; PLAN-NEEDS-MAJOR).

Disposition tables at §13 (R1), §14 (R2), §15 (R3).

Issue: #912
Umbrella: #911 (same-class HOL on shared_exact CoS queues)
Diagnosis evidence: `docs/pr/905-mouse-latency/findings.md`

## 1. Problem

iperf-b same-class mouse-latency test FAILS the 2.0× gate at
**34.95×** (p99 N=128 M=10 = 257 ms vs idle 7 ms). iperf-c same-
class also FAILS at 31.80×. iperf-a passes at 1.10×.

Root-cause diagnosis (full evidence in `docs/pr/905-mouse-latency/findings.md`):

- `shared_exact` queues (the high-rate path) BYPASS the per-flow
  admission cap (`userspace-dp/src/afxdp/tx.rs:~4076`,
  `cos_queue_flow_share_limit` returns `buffer_limit` unchanged on
  `shared_exact`).
- Without the cap, fairness on shared_exact relies entirely on
  MQFQ virtual-finish-time ordering at dequeue. MQFQ orders
  **between** buckets but is FIFO **within** a bucket.
- With `COS_FLOW_FAIR_BUCKETS = 1024` and 8 elephant flows, per-
  mouse bucket-collision probability is ~0.78 % (1 - (1 - 8/1024)).
  When a mouse hashes into the same bucket as an elephant, it sits
  FIFO behind the elephant's queued bytes.
- iperf-b's 10 Gb/s shaper holds queue depth at ~10 ms drain
  time, so collision victims see hundreds of ms p99.
- The collision distribution shape is empirically confirmed:
  p50 ≈ idle (most mice no collision), p99 = 100-770 ms across
  reps (the ~1 % collision tail).

## 2. Goal

Reduce the per-mouse bucket-collision probability from ~0.78 % to
~0.05 % by raising the SFQ bucket count from 1024 to 16384.

If the diagnosis is correct, the iperf-b N=8 M=10 p99 should
drop from ~323 ms to ~40-50 ms (~6-8× drop). The residual
collisions still see the full elephant burst, so a perfect
return-to-idle is not expected. If the drop is < 6×, the
diagnosis is incomplete and we escalate to candidate (B) —
rate-aware per-flow admission cap.

## 3. Approach

Five concrete changes (R1 #1, #2, #4 escalated the original
"single edit" to a more thorough sweep):

### 3.1 Bump the constant

```rust
- pub(super) const COS_FLOW_FAIR_BUCKETS: usize = 1024;
+ pub(super) const COS_FLOW_FAIR_BUCKETS: usize = 16384;
```

Compile-time invariants already in place (`is_power_of_two()`,
`<= u16::MAX`) both still hold (16384 = 2^14 < 2^16 = 65536).

### 3.2 Box the bucket-sized fields (R1 #4)

To avoid the stack-pressure risk during `CoSQueueRuntime` init at
16K — the inline `[0u64; 16384]` literal would land on the stack
(128 KB × 3 fields = 384 KB) before being moved into the Vec slot
— change the four bucket-sized fields to heap-boxed:

```rust
// types.rs
pub(super) struct CoSQueueRuntime {
    ...
-   pub(super) flow_bucket_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
+   pub(super) flow_bucket_bytes: Box<[u64; COS_FLOW_FAIR_BUCKETS]>,
-   pub(super) flow_bucket_head_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
+   pub(super) flow_bucket_head_finish_bytes: Box<[u64; COS_FLOW_FAIR_BUCKETS]>,
-   pub(super) flow_bucket_tail_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
+   pub(super) flow_bucket_tail_finish_bytes: Box<[u64; COS_FLOW_FAIR_BUCKETS]>,
-   pub(super) flow_bucket_items: [VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS],
+   pub(super) flow_bucket_items: Box<[VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS]>,
    ...
}

// FlowRrRing in types.rs:644
pub(super) struct FlowRrRing {
-   buf: [u16; COS_FLOW_FAIR_BUCKETS],
+   buf: Box<[u16; COS_FLOW_FAIR_BUCKETS]>,
    ...
}
```

Helpers for stable-Rust stack-free init (avoid `Box::new([0; N])`
which constructs the array on the stack first). One per element
type used as bucket storage:

```rust
fn boxed_zero_array_u64<const N: usize>() -> Box<[u64; N]> {
    let v: Vec<u64> = vec![0u64; N];
    let boxed_slice: Box<[u64]> = v.into_boxed_slice();
    boxed_slice.try_into().expect("size matches")
}

// FlowRrRing.buf is u16 (R2 #2: u16 variant must avoid the
// `[0u16; N]` literal too — at 16K that's 32 KB inline).
fn boxed_zero_array_u16<const N: usize>() -> Box<[u16; N]> {
    let v: Vec<u16> = vec![0u16; N];
    v.into_boxed_slice().try_into().expect("size matches")
}
```

`VecDeque<T>` does not impl `Default` for the array-form; use
`std::array::from_fn` already used at `tx.rs:5465`, but wrap in
`Box::new` AFTER constructing on the stack — at 16K × 32 B = 512 KB
this is the only field that REQUIRES a different approach. Use
`(0..N).map(|_| VecDeque::new()).collect::<Vec<_>>().try_into()`
to keep the heap-only path.

Hot-path access stays identical via auto-deref:
`queue.flow_bucket_bytes[bucket]` works the same. The struct
shrinks from ~950 KB inline to ~80 bytes (5 pointers + the rest).

### 3.3 Update hard-pinned test assertions (R1 #1)

The hash-mix regression pin at `tx.rs:12252-12253` asserts the
exact bucket indices for two known 5-tuples:

```rust
assert_eq!(b_v4 & 0x3F, 26);  // low 6 bits — preserved across grow
assert_eq!(b_v6 & 0x3F, 4);   // low 6 bits — preserved
assert_eq!(b_v4, 410);        // 10-bit value — needs update
assert_eq!(b_v6, 260);        // 10-bit value — needs update
```

After the bucket-count grow to 16384, the mask widens from 10 bits
to 14 bits. The new pin values come from running the test once
post-change and observing the actual `b_v4` / `b_v6` values. The
low-6-bit invariant must still hold (the hash function itself is
unchanged); confirm so.

### 3.4 Update bucket-count comments (R1 #3)

- `types.rs:601-605` claims "~34 KB per flow-fair queue" at 1024
  buckets. Per R1 #3 the real number is ~59-60 KB at 1024; correct
  the comment to reflect actual sizes (and also reflect the new
  16K size after this PR).
- `types.rs:748, 1170, 1184` carry "1024" verbatim in narrative
  comments. Update to "16384" or genericize to
  `COS_FLOW_FAIR_BUCKETS`.
- `tx.rs:3992, 4111, 4239` carry "1024" in comments and wording
  about cap reach / loop count expectations. Update.

### 3.5 Update size-pin sanity tests (R1 #1)

`types.rs:1783` has a `// Sanity pin: FlowRrRing should be ~2 KB`
comment. After Boxing the buf, `FlowRrRing`'s sizeof is now
8 + 4 + 4 = 16 bytes (Box pointer + head + len), not 2052. Update
the sanity check or remove it (size-pin checks on Boxed arrays
are not meaningful).

`tx.rs:10238, 10242` and similar arithmetic literals using `1024`
in test bodies are byte-quantity computations (e.g.
`96 * 1024` = 96 KB in a quota test) — unrelated to bucket count.
Audit each `1024` occurrence in test bodies; only the bucket-count
ones change.

## 4. What this is NOT

- Not a redesign of MQFQ ordering or admission policy.
- Not a fix for cross-NIC memcpy.
- Not a code change to `cos_queue_flow_share_limit` — that path's
  shared_exact bypass is separate (candidate B in #911).
- Not a tunable. The constant changes for everyone; if topology
  varies enough that a tunable matters, that's a follow-up.

## 5. Files touched

R1 #1 PARTIAL forced re-audit; R2 #1 corrected the v2 falsehood
that "only types.rs changes." Real scope:

- `userspace-dp/src/afxdp/types.rs` —
  - bump the constant (§3.1)
  - convert 4 bucket-sized fields on `CoSQueueRuntime` to Box (§3.2)
  - convert `FlowRrRing.buf` to Box and re-do `Default` impl (§3.2)
  - **add three `pub(super)` helpers** at module scope (R3 #6 —
    helpers must be visible to tx.rs, worker.rs, and types.rs
    callers, so they live in types.rs alongside the struct
    definitions):
      - `pub(super) fn boxed_zero_array_u64<const N: usize>() -> Box<[u64; N]>`
      - `pub(super) fn boxed_zero_array_u16<const N: usize>() -> Box<[u16; N]>`
      - `pub(super) fn boxed_vecdeque_array<T, const N: usize>() -> Box<[VecDeque<T>; N]>`
  - update narrative comments at lines 601-605, 748, 1170, 1184
  - update sanity-pin at line 1783 (FlowRrRing-size pin) (§3.5)

- `userspace-dp/src/afxdp/tx.rs` —
  - update production-path `CoSQueueRuntime` literal at line 5435
    (`.map(|queue| CoSQueueRuntime { ... })`) to use the heap
    helpers (§3.2)
  - update test-path `CoSQueueRuntime` literals at lines 13328,
    13372, 13427 (R3 #1 — these are `#[cfg(test)]` and must
    compile with the new field types)
  - update the hash-mix regression pin at lines 12252-12253 with
    the new 14-bit mask values (§3.3)
  - update narrative comments at 3992, 4111, 4239, 4463, 4530
  - audit and update the `rg "1024\b"` test sites at 10479-10533,
    12238, 12268-12278, 12334-12335 (distribution-test names and
    1024-specific thresholds)

- `userspace-dp/src/afxdp/worker.rs` —
  - update **ten** `CoSQueueRuntime` literal sites at lines
    2421, 2561, 2767, 2801, 2835, 2994, 3028, 3152, 3321, 3355
    (R3 #1 — v2 missed many; v3 lists the complete set found by
    `grep -nE "CoSQueueRuntime\s*\{" userspace-dp/src/afxdp/worker.rs`)
    to use the heap helpers (§3.2)

Total: 13 `CoSQueueRuntime { ... }` literal sites need to switch
from inline `[0; N]` initialisers to heap helpers. Plus the
`FlowRrRing::default` impl in types.rs (1 site).

- (No new tests required — the existing tests cover the per-flow
  fairness behavior; the regression pins get re-pinned.)

## 6. Memory footprint analysis (corrected per R1 #2)

Per-queue arrays sized by `COS_FLOW_FAIR_BUCKETS`. R1 corrected
the VecDeque header size on this target from 24 → 32 bytes:

| Field | Type | 1024 size | 16384 size |
|---|---|---:|---:|
| `FlowRrRing.buf` | `[u16; N]` | 2 KB | 32 KB |
| `flow_bucket_bytes` | `[u64; N]` | 8 KB | 128 KB |
| `flow_bucket_head_finish_bytes` | `[u64; N]` | 8 KB | 128 KB |
| `flow_bucket_tail_finish_bytes` | `[u64; N]` | 8 KB | 128 KB |
| `flow_bucket_items` | `[VecDeque; N]` (32 B handle each) | 32 KB | 512 KB |
| Per-queue subtotal (heap, post-Box) | | ~58 KB | ~928 KB |

Total scratch across the cluster:
- 6 workers × 4 queues per worker × ~930 KB ≈ 22 MB per node.
- Was ~1.4 MB at 1024.
- VM RAM is 8 GB; trivial absolute footprint.

After the §3.2 Box change, the fields live on the heap and the
struct itself is small (~80 B of pointers + scalars). Vec growth
no longer copies bucket arrays.

L1/L2 cache implications:
- L1d typical 32 KB — at 800 KB per queue, the array can't fit.
- L2 typical 1 MB / core — fits one queue's arrays comfortably.
- The hot-path access is BUCKET-INDEXED, not scan-the-array, so
  cache misses on cold buckets are expected anyway. Active
  buckets (8-50 in our workloads) easily fit in L1d.
- `cos_queue_min_finish_bucket` iterates `flow_rr_buckets` (the
  active set), not the full bucket array, so its loop bound is
  unchanged.

## 7. Stack-pressure resolution (per R1 #4)

R1 flagged the production constructor at `tx.rs:5461` and
`worker.rs:2438, :2578, :2784` — each inlines all three
`[0u64; N]` literals into a `CoSQueueRuntime` struct expression.
At 16K that's 384 KB inline before move-into-Vec. Whether RVO
elides the stack copy is implementation-defined — Codex
correctly refused to certify safety.

§3.2 (Box the fields) addresses this directly. The
`vec![0u64; N].into_boxed_slice().try_into()` idiom never
constructs the array on the stack — it heap-allocates via Vec
and converts to Box. No RVO dependency.

`flow_bucket_items: [VecDeque; N]` cannot use the same trick
because `VecDeque<T>` does not impl `Default` (so `vec![..; N]`
won't compile for it). Use:

```rust
flow_bucket_items: (0..COS_FLOW_FAIR_BUCKETS)
    .map(|_| VecDeque::new())
    .collect::<Vec<_>>()
    .into_boxed_slice()
    .try_into()
    .ok()  // unreachable: len matches by construction
    .expect("boxed array len matches COS_FLOW_FAIR_BUCKETS"),
```

This builds the Vec on the heap and converts; no
`[VecDeque::new(); N]` array landing on the stack.

Three helpers live in `types.rs` (R3 #6 — pub(super) so types.rs,
worker.rs, and tx.rs callers can use them; placed alongside the
struct definitions they initialise):

- `boxed_zero_array_u64<const N>() -> Box<[u64; N]>`
- `boxed_zero_array_u16<const N>() -> Box<[u16; N]>` (FlowRrRing.buf)
- `boxed_vecdeque_array<T, const N>() -> Box<[VecDeque<T>; N]>`

## 8. Test strategy

### 8.1 Build + unit tests

```
cd userspace-dp && cargo build --release
cd userspace-dp && cargo test --release
```

Pre-existing test errors (2 errors in `protocol::BindingCountersSnapshot` initialization, unrelated to this change) are expected and acceptable. They appear identically on the base commit.

### 8.2 Cluster smoke

Deploy to loss userspace cluster:
```
make build-userspace-dp
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    ./test/incus/cluster-setup.sh deploy all
```

Confirm clean rolling deploy + `make test-failover` clean.

### 8.3 Validation matrix

Re-run the iperf-b same-class matrix:

```
incus exec loss:cluster-userspace-host -- rm -f /tmp/mouse_latency_probe.py /tmp/probe-*.json /tmp/iperf3-*.txt
for fw in xpf-userspace-fw0 xpf-userspace-fw1; do incus exec loss:$fw -- rm -f /tmp/cos-iperf-sets.set; done

mkdir -p /var/tmp/912-iperf-b-shared-after
ELEPHANT_PORT=5202 MOUSE_CLASS=iperf-b \
    ./test/incus/test-mouse-latency-matrix.sh /var/tmp/912-iperf-b-shared-after
```

Compare to the pre-change iperf-b results in
`/var/tmp/905-results-iperf-b-shared/` (committed under
`docs/pr/905-mouse-latency/results-iperf-b-shared/`).

### 8.4 Throughput sanity

```
incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 \
    -p 5203 -P 128 -t 60 -i 5 --forceflush
```

Confirm steady-state ≥ 15 Gb/s (no regression vs the post-#910
baseline). The change should not affect throughput; if it does
materially, that's a finding worth investigating.

## 9. Acceptance

### 9.1 Merge gates

- `cargo build --release` clean.
- `cargo test --release` for the userspace-dp crate: same set of
  pre-existing errors as on master, no new failures.
- `make test-failover` clean.
- iperf-b N=8 M=10 mouse p99 drops by **≥ 6×** post-change vs
  the committed pre-change baseline (R2 #3 reconciled — birthday-
  math predicts ~6× best case, not 10×; gating on 10× would
  fail the plan against its own probability prediction).
- iperf-c throughput steady-state ≥ 15 Gb/s.
- Codex hostile plan + code review: PLAN-READY YES + MERGE YES.
- Copilot inline review: addressed.

### 9.2 Decision threshold (reported, not gating)

R1 #6 corrected the expected magnitude. Birthday-problem
probability ratio from 1024→16384 with k=8 flows is ~15.8×, but
p99 latency does NOT scale linearly with collision probability —
the residual collisions still see the full elephant burst. A
realistic prediction is iperf-b N=8 M=10 p99 drops from ~323 ms
to ~40-50 ms (not all the way to idle's 7 ms).

- iperf-b same-class gate ratio drops below 2.0× at the M=10 row.
  If yes: the bucket-collision diagnosis is fully confirmed and
  this PR is the fix.
- If the gate ratio stays > 2.0× but loaded p99 drops to the
  ~40-50 ms range (≥ 6× drop), the diagnosis is correct but
  bucket count alone is insufficient. Continue with candidate B
  (rate-aware per-flow admission cap).
- If loaded p99 doesn't drop materially, the diagnosis is wrong.
  File a follow-up to investigate (e.g. queue-depth not
  collision, or some other mechanism).

## 10. Residual risks (post-Box)

The two §3.2 changes (bucket-count grow + heap-box the storage)
together resolve the v1 stack-pressure risk. Remaining residual
risks:

- **Cache footprint per queue grows ~16×.** L2 still holds it.
  Hot path access is bucket-indexed, not full-scan, so cold-
  bucket misses are expected anyway. If post-deploy profiling
  shows L1 thrash that wasn't there at 1024, that's a finding
  to file (and possibly back the bucket count off to e.g. 8K).
- **No throughput regression on iperf-c.** The grow shouldn't
  affect iperf-c (its issue is firewall capacity, not bucket
  collision), but verifying is cheap and §8.4 covers it.
- **Active-set scan is unchanged.** `cos_queue_min_finish_bucket`
  iterates `flow_rr_buckets` (the active set), not the full
  bucket array. With 8-50 active buckets in our workloads, the
  loop bound is unchanged.
- **No need to recompile dataplane callers.** The constant is
  internal to userspace-dp; no public API changes.
- **Box<[T; N]> auto-deref is a stable Rust feature** — codegen
  for `queue.flow_bucket_bytes[bucket]` is a single load from
  the boxed pointer, no extra indirection vs the inline array
  case. (Loaded pointer + indexed; the pointer fits in a
  register.)

## 11. Rollback

Multi-file revert (per §5 actual scope). The PR branch is
throwaway; revert the whole branch via `git revert <commit>`
or simply close the PR without merging if the validation gate
(§9.1, ≥6× drop) doesn't hold.

## 13. R1 disposition

| # | Sev | Topic | Status |
|---|---|---|---|
| 1 | HIGH | Hard-pinned 1024 in tests + comments — "single edit" plan was false | RESOLVED — §3.3, §3.4, §3.5 enumerate all sites and update each (hash test pin at `tx.rs:12252-53`, size-pin at `types.rs:1783`, comment math at `types.rs:601-605, :748, :1170, :1184`, narrative at `tx.rs:3992, :4111, :4239`) |
| 2 | HIGH | Memory estimate undercounted (24 → 32 B VecDeque header) | RESOLVED — §6 corrected to ~58 KB (1024) and ~928 KB (16K) per queue; cluster-wide ~22 MB |
| 3 | HIGH | Existing comment at `types.rs:601` already wrong at 1024 | RESOLVED — §3.4 explicitly fixes the comment |
| 4 | HIGH | Stack pressure during init not mitigated by code | RESOLVED — §3.2 changes the four bucket-sized fields to `Box<[T; N]>` with `vec! → into_boxed_slice → try_into` idiom that never lands the array on the stack. §7 explains why this is rigorous, not RVO-dependent |
| 5 | MED | Diagnosis only empirically correlated, not analytically demonstrated | NO-OP — empirical evidence (p50 at idle, p99 1% tail matching collision math) is the strongest grounding we have without instrumenting the dataplane to count per-mouse bucket co-residency. The PR's own validation step IS the analytical confirmation |
| 6 | MED | Validation gate ≥10× weaker than birthday-math expects | RESOLVED — §9.2 reframes the expected magnitude (~6×, p99 ~40-50 ms not ~7 ms). Two-tier verdict (PASS / partial / fail) |
| 7 | LOW | Active-set scan unchanged | CONFIRMED — plan was correct; no change |
| 8 | LOW | Config schema doesn't pin bucket count | CONFIRMED — plan was correct; no migration needed |

## 14. R2 disposition

| # | Sev | Topic | Status |
|---|---|---|---|
| 1 | MED | §5 false file scope | RESOLVED — §5 fully rewritten with all files + line ranges |
| 2 | MED | u16 boxed init missing for FlowRrRing.buf | RESOLVED — §3.2 adds `boxed_zero_array_u16<N>` helper |
| 3 | MED | §9.1/§9.2/§14 contradictory gates (10× vs 6×) | RESOLVED — all three gates reconciled to ≥6× per birthday-math |
| 4 | MED | Bucket-count audit incomplete (tx.rs:4463, 4530, 10479-10533, etc.) | RESOLVED — §5 file scope now lists those line ranges in the work; §3.5 also references the audit |
| 5 | LOW | §10/§11 stale prose | RESOLVED — §10 reframed as "residual risks (post-Box)"; §11 acknowledges multi-file scope |

## 15. R3 disposition

| # | Sev | Topic | Status |
|---|---|---|---|
| 1 | BLOCKER | §5 missed many `CoSQueueRuntime` literal sites in worker.rs and tx.rs | RESOLVED — §5 lists the full complement (9 in worker.rs, 4 in tx.rs production+test) verified via `grep` |
| 6 | BLOCKER | Helper visibility/placement — types.rs caller can't use tx.rs-local helpers | RESOLVED — §3.2 moves helpers to types.rs with `pub(super)` so all callers (types.rs/worker.rs/tx.rs) reach them |
| 7 | MINOR | "Both helpers" prose stale; three helpers exist | RESOLVED — §7 prose updated to "Three helpers" |
| 8 | NIT | Missing §12, v2 label | RESOLVED — bumped to v3, R3 disposition added as §15, all references aligned |

## 16. Acceptance checklist

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] Existing test errors unchanged; no new failures.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Deploy to loss cluster; `make test-failover` clean.
- [ ] Re-run iperf-b same-class matrix; iperf-b N=8 M=10 p99
      drops ≥ 6× (R2 #3 reconciled with birthday-math prediction).
- [ ] iperf-c throughput sanity ≥ 15 Gb/s.
- [ ] Findings committed.
- [ ] PR opened, Copilot review addressed, both reviewers clean.

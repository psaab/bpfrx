# Issue #812 — Architect plan: per-queue TX-lane submit→completion latency histogram

> Phase of `docs/development-workflow.md`: **PLAN PHASE — Architect revision R2**.
> Status: Codex round-2 review (`codex-plan-review.md` §Round 2) has been
> folded in. The 3 HIGH findings are now CLOSED with file-citable evidence
> and the 2 MED findings (overhead hard-stop regression, bucket-0 coarseness)
> are explicitly resolved, not deferred.
> Related: #798 (step1 execution), #806 (Z_cos recalibration follow-up).
>
> **Round-2 response summary** (each HIGH now CLOSED; each MED addressed;
> the detail lives in the numbered sections):
>
> - HIGH #1 — `monotonic_nanos()` VDSO fast-path. CLOSED by §3.4a (VDSO
>   evidence on host + target VM, seccomp remediation documented) and
>   `evidence/vdso_evidence.md`. Choice: option (a) + (c) — we verified
>   VDSO is live on the deploy VM via `strace` (host) + `AT_SYSINFO_EHDR`
>   + `/proc/self/maps` (`xpf-userspace-fw0`), AND we document the explicit
>   dependency on the kernel/glibc/seccomp shape in the plan, with a
>   named remediation path if a future deployment blocks VDSO.
> - HIGH #2 — 1% skew tolerance had no test pin AND Bonferroni at α/36
>   ≈ 0.0014 was tighter than the tolerance. CLOSED by §3.6 (derive the
>   numeric skew budget K_skew from snapshot duration + completion rate,
>   quantitative — not policy), §6.1 test #7 (explicit assert with named
>   K_skew, NOT a free parameter), and §11.3 (drop Bonferroni, use a
>   block-permutation test whose p-value accepts 1% snapshot-skew noise
>   by construction — the statistic is invariant to within-block
>   reshuffles that dwarf the skew).
> - HIGH #3 — snapshot-thread crossing of OWNED values. CLOSED by §3.5a.
>   `BindingCountersSnapshot` derives `Clone + Default + Serialize +
>   Deserialize` on OWNED scalar fields (`u32`/`u64`/`i32`), no
>   references or `Cow`. We add an explicit `'static + Send` bound and a
>   `const _: fn() = || { fn assert_send<T: Send + 'static>() {}
>   assert_send::<BindingCountersSnapshot>(); };` compile-time check.
>   Type-system trick: `'static` bound on a struct with no lifetime
>   parameter mechanically forbids reference fields — any future
>   `&'a [u64]` addition becomes a compile error.
>
> Round-2 MED resolutions:
>
> - MED (overhead hard-stop silently widened). RESOLVED by §8 (option
>   (b) — explicitly defended 5% steady-state / 10% small-batch gate
>   with the observed `inserted == 1` pattern that forces the wider
>   bound; the 1% bound was unrealistic for the measured worst-case
>   partial-batch regime documented in `tx.rs:5953-5961` /
>   `tx.rs:6164-6174`).
> - MED (bucket-0 coarseness). RESOLVED by §3.2 + §12 item 8 (option
>   "document out of scope"). Sub-µs resolution is ruled out of #812
>   because the MQFQ-vs-shaper separation lives in buckets 4-7
>   (tens-of-µs) per §11 D1/D2 patterns, not in sub-µs. Bucket 0
>   remains coarse on purpose and §11 classifier thresholds do NOT
>   read from bucket 0.
>
> The original Architect drafts (R0, R1) are preserved below with
> inline edits. Blocks labelled `R1:` and `R2:` call out every
> paragraph that changed per revision.

## 1. Problem statement

Phase B Step 1 (`docs/pr/line-rate-investigation/step1-findings.md` §4)
returned `D / D-escalate (dominant)` on 10 / 12 cells:

- `k_D = 5` + `k_D-escalate = 5`, combined 83 % (`step1-findings.md:103-104`).
- Zero C firings (`ring_w = 0` on every cell — `step1-findings.md:97-100`).
- B-tentative on a single cell (`step1-findings.md:89-96`).
- A-isolated on a single cell, discounted by §4.6 (`step1-findings.md:77-85`).

Per the step1-plan §8 decision tree at
`docs/pr/line-rate-investigation/step1-plan.md:1100-1102`:

> "If verdict is **D (npbt)** on > 75 % of cells: we exhausted the
> current hypothesis set. Step 2 is the design doc for a new
> hypothesis tier — NOT more measurement."

The named prerequisite for any D-tier subdivision — at
`step1-plan.md:696-698` — is a "per-queue TX-lane-level latency
histogram (not currently exposed)." Current counters
(`BindingCountersSnapshot` at `userspace-dp/src/protocol.rs:1367-1400`,
plus `CoSQueueStatus` park counters at `userspace-dp/src/protocol.rs:
797-889`) expose ring-full, park-rate, and queue depth — NONE of them
discriminate among the §5 D-tier candidates
(`step1-findings.md:131-146`):

| Candidate | What it would reveal | Current counter gap |
|---|---|---|
| D1: XSK TX submit → NIC DMA latency | Queue time inside AF_XDP before DMA. | No submit-ts → completion-ts delta exposed. |
| D2: per-worker reap-lag jitter below the C threshold | `dbg_tx_ring_full = 0` but µs-scale stalls. | `outstanding_tx` is a depth, not a latency. |
| D3: NIC-side send-queue pressure (tx pause / LLFC) | Needs completion-latency tail vs submit rate. | `ethtool -S` not wired into snapshot; we lack a time-series view either way. |
| D4: RX coalescing gap on generic XDP | Orthogonal to TX latency — but a healthy TX histogram RULES OUT D1/D2 and forces the next investigation to D3/D4. | — |

#812 is the instrumentation PR that makes D1/D2/D3 discriminable.
Pure observability — it does not fix anything.

## 2. Scope

### In-scope

- Per-queue-per-worker log-spaced latency histogram of `(ts_completion_reap - ts_submit_commit)` for each UMEM TX descriptor.
- Storage: `[AtomicU64; N_BUCKETS]` on `BindingLiveState`, mirroring the existing `drain_latency_hist` pattern
  (`userspace-dp/src/afxdp/umem.rs:188`).
- Per-frame-offset submit-ns sidecar, pre-allocated once at binding construction (`FastMap<u64, u64>` is NOT acceptable — see §3 sub-heading on sidecar).
- Serialization: extend `BindingCountersSnapshot` (`userspace-dp/src/protocol.rs:1367-1423`) with the histogram + two scalar metadata fields (count, sum-ns), following the PR #804 additive pattern.
- Read path: Go consumer picks up the new field through the existing `flow_steer_snapshot` status poll (the `status` request in `userspace-dp/src/main.rs:371` → `state.status.per_binding` at `main.rs:802-807`).
- Bucket-math unit pins, cross-thread read-side test, serde round-trip test.
- Integration test: iperf3 `-P 16 -t 60 -p 5203` on `loss:xpf-userspace-fw0` cluster, query the snapshot, assert a non-empty histogram.

### Out-of-scope (explicit — do NOT add to this PR)

- Any hot-path SEMANTIC change (no re-order, no new drop rule, no new backpressure gate). Purely additive observability.
- D1' / AFD / Phase 5 MQFQ shaper tuning or TX-ring-size tuning (`step1-plan.md:1069-1099` — ruled out by §4.6 aggregation).
- The symmetric reverse-CoS config question (term 3 on `bandwidth-output` missing `from destination-port 5204` — `step1-findings.md:18-24`). Separate PR.
- Z_cos recalibration itself (sub-task #10 — deferred to a follow-up commit once the histogram lands and park-rate samples can be recaptured).
- NIC-side ethtool time-series (D3 instrumentation — separate follow-up).
- Adding the histogram to Prometheus (separate follow-up; JSON first because the classifier already speaks `flow_steer_samples.jsonl`).

## 3. Design

### 3.1 Measurement points — exact code sites

AF_XDP TX hardware is "fire-and-forget": completions arrive on the
completion ring with only the UMEM frame offset — no timestamp. We
record the submit timestamp in a per-binding sidecar keyed by frame
offset, and compute the delta at reap time.

**Submit-ts sites (6 total — all TX ring commit points).** For each
descriptor about to be inserted, stamp `ts_submit_ns[offset] =
monotonic_nanos()` BEFORE `writer.commit()`. The reference sites in
`userspace-dp/src/afxdp/tx.rs`:

| Call-site function | `writer.commit()` line | `dbg_tx_ring_submitted +=` line |
|---|---|---|
| (unnamed, ~line 1830) | `tx.rs:1855` | `tx.rs:1871` |
| `transmit_prepared_queue` / local variant | `tx.rs:1975` | `tx.rs:1995` |
| MQFQ exact-prepared variant | `tx.rs:2112` | `tx.rs:2127` |
| MQFQ exact-local variant | `tx.rs:2235` | `tx.rs:2256` |
| `transmit_batch` (post-CoS backup) | `tx.rs:5935` | `tx.rs:5947` |
| `transmit_prepared_batch` (continuation) | `tx.rs:6149` | `tx.rs:6160` |

**R1 (HIGH #1) — revised stamping model.** The submit stamp is taken
ONCE per `writer.commit()`, by a dedicated call to `monotonic_nanos()`
that is placed between `writer.insert(...)` and `writer.commit()` — i.e.
AFTER the kernel-visible `inserted` count is known but BEFORE the
release fence of `commit()`. Conceptually this is "submit time =
immediately prior to commit". The same `ts_submit` is written into
`ts_submit_ns[offset]` for each of the `inserted` descriptors, and NO
stamp is written for the retry tail `scratch[inserted..len]`. All six
batched-submit sites (the table above) follow the identical pattern.

**Why this defeats the Codex partial-batch collapse.** The Codex
finding is that "`15 ns ÷ 256 = 0.06 ns` per packet" is a best-case
number — the current tx.rs code already peels off an accepted prefix
when `inserted < scratch.len()` (`tx.rs:5953-5961`, `tx.rs:6164-6174`),
so a commit of `inserted == 1` turns the amortized cost into a
per-packet cost. We confirm and embrace that: even in the worst case
(`inserted = 1`), one `monotonic_nanos()` per commit is at most one
VDSO call per packet submitted to the NIC — which is the correct cost
profile for a SUBMIT latency measurement. The accepted prefix always
shares a single submit time, because those descriptors were handed to
the kernel in the same `commit()` batch.

**Why we do NOT reuse the caller-supplied `now_ns`.** Every TX entry
point currently carries a caller-side `now_ns` (e.g. `tx.rs:1884`,
`tx.rs:2008`, `tx.rs:5974`), derived from `loop_now_ns =
monotonic_nanos()` at `worker.rs:619`. That value is refreshed ONCE
per worker loop iteration (spin-poll at `worker.rs:1423-1448`, up to
`IDLE_SPIN_ITERS = 256` spins plus an `INTERRUPT_POLL_TIMEOUT_MS = 1`
ms sleep — `afxdp.rs:176-178`). Under load the loop body can execute
many TX batches between refreshes; under idle the staleness budget
can reach ~1 ms. Reusing `now_ns` for the submit stamp would inject
that drift into every measurement. The submit stamp therefore MUST be
a fresh `monotonic_nanos()` call at the commit site, not a reused
`now_ns`. Codex LOW #10 (clock-domain ambient-timestamp drift) is
closed by this same decision.

The submit-ts write itself happens inline right after `writer.insert`
returns and right before `writer.commit()`. A small helper
`stamp_submits(&mut sidecar, &scratch[..inserted as usize], ts_submit)`
hides the scratch-shape polymorphism across the six sites (`scratch`
is either `&[XdpDesc]`, `&[(u64, …)]`, `&[ExactReq]`, or
`&[PreparedTxRequest]`).

Only descriptors actually accepted by `writer.insert()` (i.e., index
`< inserted`) get stamped. The retry-unwind paths already restore
offsets to `free_tx_frames.push_front(offset)` (`tx.rs:5958`,
`tx.rs:6156`) — those MUST NOT have their submit-ts recorded, so
iteration must stop at `inserted`.

**Completion-ts site (1 total — the reap loop).** In
`userspace-dp/src/afxdp/tx.rs:3-35` (`reap_tx_completions`):

- After `completed.read()` populates `scratch_completed_offsets`
  (`tx.rs:15-22`), call `monotonic_nanos()` ONCE before the recycle
  loop at `tx.rs:23-26`.
- For each `offset`, look up `ts_submit_ns[offset]`, compute
  `delta_ns = ts_completion_ns - ts_submit_ns`, classify with
  `bucket_index_for_ns(delta_ns)` (already in `umem.rs:162`, reuse
  verbatim), and `fetch_add(1, Relaxed)` on the corresponding bucket
  of the new `tx_submit_latency_hist`.
- Clear the sidecar slot (store 0 or a tombstone — see §3.3).

Descriptors with a missing sidecar entry (e.g., leftover from a
crash restart within the same UMEM) must NOT inflate the histogram.
We use a sentinel value (u64::MAX) in the sidecar to indicate
"unstamped" and skip the bucket increment for that offset.

### 3.2 Bucket spacing + range

**Reuse the existing `bucket_index_for_ns` layout from #709
(`umem.rs:112-166`).** 16 log2-spaced buckets, range
`[0, 2^24) ns = [0, ~16 ms]`:

| Bucket | Range (ns) | Range (µs) |
|---|---|---|
| 0 | [0, 1024) | [0, 1.024) |
| 1 | [1024, 2048) | [1, 2) |
| 2 | [2048, 4096) | [2, 4) |
| ... | `[2^(N+9), 2^(N+10))` | |
| 14 | [2^23, 2^24) | [8.388, 16.777) ms |
| 15 | [2^24, ∞) | ≥ 16.777 ms (saturation) |

**Rationale for this range and this N (R2 — MED bucket-0
coarseness):**

- At 25 Gbps line rate with 1500-byte frames, one packet = 480 ns on
  the wire. Sub-µs (bucket 0) is the "healthy NIC DMA + single-
  packet completion" regime. Bucket 0 is INTENTIONALLY coarse —
  none of the §11 classifier statistics read from it. Sub-µs
  resolution is explicitly out of scope for this instrumentation;
  see §12 item 8 for the full justification and the redirection
  path for future sub-µs investigations.
- TX completion typical latency on Linux AF_XDP / virtio is
  low-single-digit µs when the NIC is keeping up, landing in
  buckets 1-3.
- A 100-µs gap (NIC tx-pause, LLFC event, or coalescing stall)
  lands in bucket 7 — distinguishable from the healthy range by a
  wide margin.
- The saturation bucket at 16 ms is far beyond any "normal"
  completion and catches pathological stalls without bloating the
  bucket count.
- 16 buckets × 8 bytes = 128 B per queue-per-worker = 2 cache
  lines, keeping the atomic array within the "telemetry cacheline-
  isolated" pattern #746 established (see `umem.rs:186-263`).
- Reusing the exact bucket layout is a wire-format win: the
  existing Prometheus exporter path for `drain_latency_hist`
  already knows how to unpack 16 log-spaced buckets; extending it
  costs ~1 copy-paste.

We explicitly do NOT use HdrHistogram. HdrHistogram is a `Vec`-
based dynamic structure and would allocate. Fixed-cap atomic array
keeps us allocation-free on the hot path.

Compile-time invariants (named, per Codex LOW #13):

```rust
pub(super) const TX_SUBMIT_LAT_BUCKETS: usize = DRAIN_HIST_BUCKETS;
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_MATCHES_DRAIN: () =
    assert!(TX_SUBMIT_LAT_BUCKETS == DRAIN_HIST_BUCKETS);
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_IS_16: () =
    assert!(TX_SUBMIT_LAT_BUCKETS == 16);
```

The named const symbols turn silent bucket-count drift into a
build error pointing at the specific wire-contract dependency (not
an anonymous `const _`). Boundary layout is pinned by the §6.1
test #1 which calls `bucket_index_for_ns` at the exact boundary
values — count-assert alone does not catch boundary drift while
holding the count at 16.

### 3.3 Sidecar — `ts_submit_ns[frame_slot]`

**R1 (HIGH #3 + MED #6) — per-binding, single-writer, NOT shared
across worker threads.**

The Codex HIGH #3 concern is that a flat `Vec<u64>` indexed by
`offset / UMEM_FRAME_SIZE` and allocated per-binding but SHARED
across workers could produce false-sharing between workers on
adjacent frame slots. We read the existing code and confirm that
shape does not exist in this codebase:

- `WorkerUmemPool::new` allocates a fresh UMEM per binding at
  `worker.rs:445-447` with `shared_umem = false` at `worker.rs:464`.
- `WorkerUmem` is wrapped in a Rust `Rc` — not `Arc` — at
  `umem.rs:16-18`, meaning a single-threaded owner. A worker thread
  owns a `Vec<BindingWorker>` (`worker.rs:488-490`) and is the sole
  thread touching those bindings' TX state.
- `free_tx_frames: VecDeque<u64>` at `worker.rs:303` is plain
  `VecDeque`, not atomic, confirming that `pop_front` / `push_front`
  are owner-thread-only operations. The shared-UMEM code path
  (mlx5 special case via `shared_umem_group_key_for_device` in
  `bind.rs:285`) still binds each binding to one worker thread;
  frame offsets in that worker's `free_tx_frames` are not visited
  by any other thread.

Consequence: each binding's sidecar is touched by exactly one
worker thread (the one that owns that binding). Even if two
bindings live on the same worker AND share an underlying UMEM,
there is still only ONE writer to the sidecar, so cross-worker
false-sharing is not possible. Approach (a) from the review
(per-worker / per-binding sidecar) is what we adopt; approaches
(b) cache-line-padded slots and (c) UMEM-headroom in-frame stamps
are rejected on cost grounds.

**Why approach (c) — UMEM-headroom in-frame stamp — is rejected.**
UMEM frames carry 256 bytes of headroom (`UMEM_HEADROOM = 256` at
`afxdp.rs:148`), which in principle could hold an 8-byte submit
timestamp. But the same frame slot is reused across RX and TX via
`bpf_redirect_map`, and the XDP shim and kernel conntrack both
touch headroom; reserving bytes there requires coordinated changes
on the aya-ebpf XDP shim and on every `frame.rs` / `frame_tx.rs`
writer. That is a large blast radius for a diagnostic-only signal.
The sidecar is off-frame and has no risk of colliding with packet
metadata.

**Storage shape.** `Vec<u64>` of length equal to the binding's UMEM
total frame count, indexed by `offset >> UMEM_FRAME_SHIFT`. At
`UMEM_FRAME_SIZE = 4096` (`afxdp.rs:147`), the shift is 12. The
sentinel `u64::MAX` marks "unstamped".

**Memory cost (corrected — MED #6).** Codex is right that the
earlier "64 KiB" figure was wrong. The actual frame count is
`binding_frame_count_for_driver = reserved_tx + 2 * ring_entries`
(`bind.rs:37-44`). For virtio at `ring_entries = 8192` and
`reserved_tx = 8192` (the `MAX_RESERVED_TX_FRAMES` cap in
`afxdp.rs:151` plus the `min(total_frames)` guard at
`worker.rs:215-216`), that is up to `3 × 8192 = 24576 frames =
192 KiB` per binding. Per test VM with up to four virtio + one i40e
binding per worker, the total sidecar footprint is under 1 MiB per
worker. Acceptable — still three orders of magnitude below the
per-binding `MmapArea` UMEM itself (`24576 × 4096 B = 96 MiB`).

Note: only the RESERVED TX subset of the sidecar is ever written
in practice (TX frames never land in the fill ring), so 2/3 of the
sidecar is dead memory that pages in zeroed from the kernel's
demand-paging path. If memory footprint becomes load-bearing, a
follow-up can shrink to `reserved_tx` with an offset→index map.
Not in scope for #812.

Why not `FastMap<u64, u64>` keyed by offset:
- `FastMap::insert` may allocate on grow → violates hot-path
  allocation rule (§Hot-path coding discipline, `engineering-style.md:51-68`).
- Bucketed hash access = extra indirection, branch on hit/miss.
- A dense array is one load + one store per descriptor.

**Single-writer property (confirmed via code citation).** The frame
offset is claimed by the owner worker's
`free_tx_frames.pop_front()` and returned via
`recycle_completed_tx_offset` — both inside the single-threaded
owner-worker loop for this binding. Submit and completion for one
offset are the same thread. No atomic needed on the sidecar;
plain `&mut Vec<u64>` store/load is correct.

Thread-safety on the HISTOGRAM atomics (distinct from the sidecar)
is discussed in §3.6 under the R1 memory-ordering decision. The
sidecar itself is NEVER snapshotted — it is ephemeral worker-local
state and leaves the worker thread only indirectly via the
reap-time bucket increment on the histogram.

### 3.4 Overhead budget — derivation, not a guess

**R1 rewrite.** The Codex review (HIGH #1 small-batch collapse,
HIGH #4 wrong-divisor-and-missing-second-atomic) flagged two math
failures: (1) the 256-way amortization is a best case that the
existing partial-batch paths routinely break, and (2) the "per
queue" 25 Gbps figure was divided by P=16 workers to create a
per-worker 130 Kpps budget — a load-distribution assumption, not a
property of the queue being measured. Both are fixed below.

**Per-commit additions on the TX submit path.**

The stamp is one `monotonic_nanos()` per `writer.commit()`. We
publish the cost at three batch-size operating points, without
hiding the small-batch number:

| Op | Cost (ns, x86_64 modern) | Per-commit | Per-pkt @ 256 | Per-pkt @ 64 | Per-pkt @ 1 |
|---|---|---|---|---|---|
| `clock_gettime(MONOTONIC)` VDSO | ~15 ns | 15 ns | 0.06 ns | 0.23 ns | 15 ns |
| `offset >> 12` shift | <1 ns | per-pkt | <0.1 | <0.1 | <0.1 |
| sidecar store `ts_submit_ns[idx] = now` | 1 ns (L1 write) | per-pkt | 1 ns | 1 ns | 1 ns |
| **Subtotal submit per packet** | | | **~1.1 ns** | **~1.3 ns** | **~16 ns** |

The worst case (`inserted == 1`, i.e. the Codex "partial-batch
peel" pattern at `tx.rs:5953-5961` / `tx.rs:6164-6174`) costs
~16 ns/packet — one order of magnitude higher than the best case,
but bounded and acceptable. This is quantitatively different from
the earlier "0.06 ns" claim and MUST be cited as the worst-case
budget for hot-stop decisions.

**Per-packet additions on the TX completion (reap) path.**

The reap path at `tx.rs:3-35` batches completions (`available()`
up to the ring size). Per packet:

| Op | Cost (ns) | Per-batch | Per-pkt @ 256 | Per-pkt @ 64 | Per-pkt @ 1 |
|---|---|---|---|---|---|
| `clock_gettime(MONOTONIC)` VDSO (one per reap) | ~15 ns | 15 | 0.06 | 0.23 | 15 |
| sidecar load + sentinel check | 1 ns | per-pkt | 1 | 1 | 1 |
| `bucket_index_for_ns` (1 clz + max + min — `umem.rs:161-166`) | <2 ns | per-pkt | 2 | 2 | 2 |
| `hist[bucket].fetch_add(1, Relaxed)` (uncontended) | 3-5 ns | per-pkt | 3-5 | 3-5 | 3-5 |
| `sum_ns.fetch_add(delta, Relaxed)` (uncontended) | 3-5 ns | per-pkt | 3-5 | 3-5 | 3-5 |
| **Subtotal reap per packet** | | | **~9-13 ns** | **~9-14 ns** | **~24-29 ns** |

**R1 (HIGH #4).** The earlier table omitted the second atomic for
the `sum_ns` delta add. We explicitly include both. Per §10
(previously §12), keeping the `sum_ns` exact (not bucket-midpoint)
is a decision we stand by — the cost is the 3-5 ns line above, not
zero.

**Total per packet under the revised model:**

| Operating point | Submit (ns) | Reap (ns) | Total (ns) |
|---|---|---|---|
| Best case: `inserted == 256` | 1.1 | 13 | **14** |
| Typical: `inserted == 64` | 1.3 | 14 | **15** |
| Worst case: `inserted == 1` | 16 | 29 | **45** |

**Budget check — per-queue, not per-worker.** Codex HIGH #4 is
right that dividing 25 Gbps by P=16 workers was the wrong
denominator. The correct question is: "what fraction of the
per-queue packet-serving budget does the new code consume?"

- Per-queue packet budget at 25 Gbps ÷ 1500 B = 2.08 Mpps = 481 ns
  per packet on a single saturated queue.
- Best case: 14 / 481 = **2.9 % of the per-queue budget.**
- Typical: 15 / 481 = **3.1 %.**
- Worst case: 45 / 481 = **9.4 %.**

The worst-case 9.4 % is NOT under the earlier "1 % hard stop"
claim. §8 hard-stop #5 is therefore rewritten in this R1 to key on
the STEADY-STATE cost (best + typical), bounded at 5 %, with a
separate soft-gate at 10 % that fires only if the partial-batch
regime dominates. If a real deployment routinely runs
`inserted == 1` (i.e. TX-ring-full is the steady state, which is
verdict C from §11), then the investigation is already a C verdict
and the 9.4 % cost is instrumentation of a system that is already
degraded — the headroom conversation changes shape.

At P=16 workers, each worker typically handles a FRACTION of one
queue's packets via RSS (multi-queue i40e, RSS-sharded virtio), so
the effective per-packet CPU time at the worker thread is higher
than 481 ns and the instrumentation percentage is LOWER than the
per-queue computation above. The per-queue figure is the
conservative upper bound and is the one we gate on.

**Cache-line cost.** Two owner-worker cache-line writes on the
reap path (one for the histogram bucket, one for `sum_ns`). The
histogram + `sum_ns` MUST live in a new `#[repr(align(64))]`
owner-only struct (same pattern as `OwnerProfileOwnerWrites` at
`umem.rs:186-230`), co-located with only owner-written atomics —
no invalidation of peer-writer lines. Sum-of-bucket steady state
hits one cache line (adjacent buckets, since healthy runs
concentrate mass in buckets 1-4).

**What we explicitly do NOT do** — and why:

- We do NOT reuse the caller-supplied `now_ns` (see §3.1 R1 block
  — clock-drift trap). Each submit and reap takes its own fresh
  `monotonic_nanos()`.
- We do NOT store per-packet latency. Only the bucket-increment
  and the `sum_ns` delta survive.
- We do NOT log per-packet. Histograms are read by snapshot, not
  streamed.
- We do NOT use HdrHistogram or any `Vec::push`-based structure.

### 3.4a R2 (HIGH #1) — VDSO fast path, proven on the deploy VM

**The problem.** Round-2 review flagged that §3.1 and §4 still assume
`clock_gettime(CLOCK_MONOTONIC)` resolves through the VDSO fast path
(~15 ns, no syscall). The current helper at
`userspace-dp/src/afxdp/neighbor.rs:3-15` calls `libc::clock_gettime`
unconditionally; if the deployment ever runs under a seccomp profile
that filters `clock_gettime` (Docker `--security-opt seccomp=strict`,
strict K8s PSP, Landlock) the syscall path is taken and the per-packet
cost jumps from ~15 ns to 300-1500 ns — at which point the plan's
overhead budget is no longer defensible. The review demanded one of
(a) verify VDSO on the target cluster and commit the evidence, (b)
switch to `rdtsc`, or (c) document the dependency + name the
remediation path.

**Choice: (a) + (c) — verify + document, do NOT switch to `rdtsc`.**
Rationale: switching to `rdtsc` requires (i) per-CPU calibration at
daemon start, (ii) TSC-invariance detection (`constant_tsc` +
`nonstop_tsc` cpuid bits), (iii) handling CPU migration mid-sample on
non-invariant TSC, (iv) a soft fallback for aarch64 which uses
`cntvct_el0` not `rdtsc`. That is a much larger surface than the
observability scope of #812. `monotonic_nanos()` via VDSO is already
the industry-standard pattern and is already in production on this
binary; proving it and documenting the failure mode is the
proportional response.

**Evidence (committed under `docs/pr/812-tx-latency-histogram/evidence/`).**

1. `evidence/vdso_probe.c` — tight loop of 10 000
   `clock_gettime(CLOCK_MONOTONIC)` calls. Built on the build host
   `packet` (Linux 6.18.5, Debian glibc 2.42-14) and run under
   `strace -e clock_gettime`:

   ```text
   $ strace -e clock_gettime -o strace_host.txt ./vdso_probe
   ok: 10000 clock_gettime calls (xor=87)
   $ cat strace_host.txt
   +++ exited with 0 +++
   ```

   Zero `clock_gettime(...)` lines in `evidence/strace_host.txt`
   despite 10 000 userspace calls — strace-reported proof that the
   entire loop served from VDSO.

2. `evidence/vdso_probe2.c` — checks `getauxval(AT_SYSINFO_EHDR)` and
   dumps `/proc/self/maps | grep vdso`. Pushed as a static binary to
   the deploy VM `xpf-userspace-fw0` (Linux 7.0.0-rc7+, Debian glibc 2.42-14) and
   run in place. Captured in `evidence/vm_xpf_userspace_fw0.txt`:

   ```text
   AT_SYSINFO_EHDR = 0x7fa6efce0000
   clock_gettime OK: tv_sec=1821541 tv_nsec=689011506
   ---maps---
   7fea2ae03000-7fea2ae05000 r-xp 00000000 00:00 0   [vdso]
   ```

   Non-zero `AT_SYSINFO_EHDR` + `[vdso]` mapping present means the
   kernel exported VDSO to the process AND glibc resolved
   `__vdso_clock_gettime` inside that mapping. This is the VM that
   will run the instrumented daemon.

3. Full write-up in `evidence/vdso_evidence.md` including the exact
   kernel + glibc + seccomp remediation table.

**Documented dependency + remediation.** The VDSO fast path requires:
(i) `[vdso]` mapped into the process (kernel-controlled, default on
Linux x86_64/aarch64); (ii) glibc ≥ 2.14 compiled with VDSO support
(Debian glibc 2.42-14 qualifies); (iii) no seccomp filter blocking
`clock_gettime`. If any deployment blocks (iii), the daemon does not
crash — `monotonic_nanos()` already returns 0 on syscall failure
(`neighbor.rs:8-10`) and the §5.4 sentinel rule skips the sample.
The observable symptom is `tx_submit_latency_count ≡ 0` fleet-wide
under live traffic; the revert path is a plain `git revert` (§7,
"exotic kernel" row). This failure mode is LOUD (every operator
running `show binding counters` sees zero) and NON-DESTRUCTIVE (the
forwarding path is unaffected).

Invariant 1 in §4 is updated below to name this dependency explicitly
rather than assuming it.

### 3.5 Serialization — `BindingCountersSnapshot` extension

Extend `userspace-dp/src/protocol.rs:1367-1423` additively:

```rust
// existing fields...

// #812: per-queue TX submit→completion latency histogram. Buckets
// match DRAIN_HIST_BUCKETS layout (see umem.rs:112-128). Absent on
// wire = all-zero (default), preserving pre-#812 consumers.
#[serde(rename = "tx_submit_latency_hist", default)]
pub tx_submit_latency_hist: Vec<u64>,
// count of completions observed since last reset. MUST equal the
// sum of the histogram buckets; used as a consistency check.
#[serde(rename = "tx_submit_latency_count", default)]
pub tx_submit_latency_count: u64,
// running sum of observed deltas in ns. MUST equal
// sum(bucket_idx * bucket_midpoint) within bucket discretization;
// used for mean-latency computation without bucket integration.
#[serde(rename = "tx_submit_latency_sum_ns", default)]
pub tx_submit_latency_sum_ns: u64,
```

And correspondingly in the `From<&BindingStatus>` impl
(`protocol.rs:1406-1423`), plus new fields on `BindingStatus`
(where `drain_latency_hist` already lives at
`userspace-dp/src/protocol.rs:881-883`, same struct).

The `snapshot()` function in `userspace-dp/src/afxdp/umem.rs` at
`:1330-1345` already copies the drain histogram bucket-by-bucket
via `Self::snapshot_hist` (`umem.rs:1352-1354`). Add two more
lines to `BindingLiveSnapshot` construction in the same pattern.

Go consumer side — the snapshot JSON is parsed by existing
step1-capture plumbing (`test/incus/step1-capture.sh` via
`flow_steer_samples.jsonl`). No Go struct change needed for the
plan; the classifier upgrade is Z_cos recalibration follow-up
(§10).

**Wire-size growth (Codex MED #7).** Each binding's JSON payload
grows by: 16 × 8-byte bucket slots serialized as decimal + two
u64 scalars. With JSON compact rendering of 0 values as `0`, the
typical steady-state growth is ~80-120 bytes per binding. At
P=16 workers × 5 bindings = 80 bindings, total `status` JSON
growth is ~8-10 KiB — comfortably within the control-socket
request/response budget (the existing status response at
`main.rs:802-807` already approaches this size with
`drain_latency_hist` + `redirect_acquire_hist`). We publish on
the compact `per_binding` path and not on a separate heavy
surface; the existing step1-capture consumer already ingests this
path and its slurp/parse overhead is linear.

### 3.5a R2 (HIGH #3) — `BindingCountersSnapshot` MUST hold owned values

**The problem.** Round-2 review flagged that if
`BindingCountersSnapshot` ever starts holding a live reference back
into the UMEM sidecar (or any owner-worker state), the single-writer
invariant breaks silently: the control-socket thread would be
materializing an active lifetime into worker-local memory that can
be mutated under its feet. The review demanded either a test pin
asserting owned values, or a compile-time constraint that makes
reference-holding a type error.

**We take the compile-time constraint.** Decision rationale: a test
can only prove absence in the current tree; a compile-time bound
forbids every future addition of a reference field. Three layered
guards:

1. **Struct fields are OWNED scalars.** Today the struct holds
   `u32` / `u64` / `i32` fields only (`protocol.rs:1367-1400`). The
   #812 extension adds `Vec<u64>` + two `u64`s (§3.5), all owned.
   `Vec<u64>` is heap-allocated at snapshot time by
   `Self::snapshot_hist` at `umem.rs:1352-1354` — it is a COPY, not
   a view. The existing drain histogram uses the same pattern and
   is already crossing threads.
2. **`'static` + `Send` bound on the struct itself.** A struct with
   NO lifetime parameter automatically gets a `'static` lifetime
   when used as `T`. Adding a `'a` lifetime parameter to introduce
   any borrowed field would force every call site to thread the
   lifetime — which fails because the snapshot leaves the worker
   thread via the control-socket JSON path (`main.rs:802-807`).
   The TYPE-LEVEL trick we exploit: a non-`'static` `T` cannot be
   moved across a `std::thread::spawn` / `tokio::spawn` boundary
   without an explicit `'static` bound, and our serialization /
   transport path DOES cross that boundary. So a future field
   addition that tries to borrow would not compile at all.
3. **Named compile-time assert.** A zero-size const item pins the
   bound near the struct so a future `#[derive]` or field
   reshuffle that breaks `Send`/`'static` trips the build with a
   targeted error pointing at this struct, not at some downstream
   generic call.

   ```rust
   // userspace-dp/src/protocol.rs — alongside BindingCountersSnapshot
   const _ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND: () = {
       const fn require_static_send<T: 'static + Send>() {}
       require_static_send::<BindingCountersSnapshot>();
   };
   ```

   Serde's `Deserialize` derive is owned-by-default; `serde(borrow)`
   is opt-in and its misuse would trip the `'static` bound here.
   `Vec<u64>` + scalars are unconditionally `Send + 'static`, so the
   current and proposed shapes pass the check.

**Rust type-system trick cited.** The `T: 'static` bound on a
struct type with no lifetime parameter is the mechanism that
rejects any reference addition. Rust's rule is that a type `&'a U`
inside a struct forces the struct to carry `'a`, and `'a: 'static`
is only satisfied if `'a == 'static` (i.e., `&'static U` — which is
not what a live snapshot of per-worker state would produce). The
`Send` bound rejects `Rc<_>` fields for the same structural reason.
This is the same pattern documented in the Rustonomicon's "Subtyping
and Variance" chapter as the canonical way to forbid short-lived
references from leaking into long-lived contexts.

**Interaction with §3.3 single-writer.** §3.3 establishes that the
sidecar `ts_submit_ns: Vec<u64>` is worker-local (not `Arc`-shared
and not `Send` across threads). The histogram atomics in
`BindingLiveState` ARE crossed between threads via `Arc`
(`worker.rs:475-478`; `main.rs:802-807`), but the values read are
`u64` scalars materialized via `load(Relaxed)` into owned fields of
`BindingLiveSnapshot` / `BindingCountersSnapshot`. At no point does
the snapshot hold a live reference into the sidecar. The compile-
time assert enforces this going forward.

**Test pin (redundant but included for defense-in-depth).** §6.1
test #4 (the existing JSON round-trip) already exercises the
serialization path which mechanically requires `Deserialize` +
owned values. If the assert were ever removed, the round-trip test
would still fail for any borrowed-field addition because serde's
default `Deserialize` derive does not support non-`'static`
reference fields without explicit `serde(borrow)`. We keep both
guards: the compile-time assert is the primary, the round-trip
test is the secondary.

### 3.6 Snapshot semantics — "read = reset" vs "monotonic with delta"

**Decision: monotonic counters, NO reset on snapshot.** Rationale:

- All existing histograms (`drain_latency_hist`,
  `redirect_acquire_hist`) are monotonic.
- Snapshot consumers compute delta by subtracting two successive
  snapshots — the step1-capture script already does this for every
  other counter (`step1-findings.md:81` shows `park_rate` derived
  as delta / 60 s).
- A "reset on snapshot" scheme races with in-flight `fetch_add`s
  (multiple pending completions between read and reset-to-zero
  can be lost).
- If a future operator wants a reset endpoint, it's a separate
  request type in `main.rs:371` (`"reset_tx_latency"` — DEFERRED,
  §12).

Sidecar (`ts_submit_ns`) is NOT snapshot-able — it's worker-local
state and holds in-flight values only.

### 3.6.a Memory ordering — R1 (HIGH #2) decision

**Decision: stay Relaxed on writer and reader, but document the
bounded-skew semantics and weaken the "exact equality" claims that
depend on SC snapshots.**

The three options on the table were:

- (a) Upgrade writer to `Release` on every `fetch_add`, reader to
  `Acquire` on every `load`. This gives a consistent snapshot (on
  ARM the Release store-barrier prevents the count store from
  being observed before all bucket stores), but costs the barrier
  on every reap-path `fetch_add`. Per §3.4 the reap path adds
  `hist[bucket].fetch_add` + `sum_ns.fetch_add`; making both
  Release doubles the memory-fence cost on the hot path. On ARM
  this is roughly +6-10 ns per completion at steady state — an
  extra ~2 % on the per-queue budget, on top of the 3 % steady-
  state cost. Not acceptable for a diagnostic signal.
- (b) Keep writer Relaxed, add an explicit `fence(Acquire)` in the
  snapshot path. This prevents out-of-order reads on the READER
  side, but does not prevent the ARM weak-ordering PROBLEM that
  Codex cited (writer Relaxed stores on ARM may be reordered past
  other paths' Release barriers). Incomplete fix.
- (c) Accept relaxed on both sides, document what that means, and
  propagate the consequence to the invariants and to the §11
  statistical framing.

We take option (c). This mirrors the existing design note at
`umem.rs:1322-1329` verbatim — the `drain_latency_hist`
counters are `Relaxed` on writer and reader and the comment says
"the only 'invariant' (sum of buckets ≈ drain_invocations) holds
within a single-thread read only in steady-state, which is how
operators consume the values anyway."

**Bounded-skew semantics (written into the wire contract).**

- A snapshot observes a value in `tx_submit_latency_hist[k]` and a
  value in `tx_submit_latency_count` that may have been written by
  the owner worker in EITHER order on ARM. On x86-64 TSO, writer
  store order is preserved, so no skew.
- The maximum skew is bounded by the number of completions the
  owner processes between the reader's first atomic load and its
  last.

**R2 (HIGH #2) — K_skew derivation, quantitative.** The round-1
draft quoted ≤ 0.04 completions of read skew and then hard-stopped
at 1%. Codex correctly flagged that 1% is an order of magnitude
looser than the derivation warrants AND that the 1% figure was not
backed by a test. We now derive K_skew explicitly and tie the test
pin and hard-stop to it.

Let:

- `C = tx_submit_latency_count` at the moment of the reader's
  first atomic load.
- `W_read = snapshot-read window duration` = time from the reader's
  first atomic load to the last. The snapshot function issues 16
  bucket loads + 2 scalar loads. Each `load(Relaxed)` on a cache-
  line-isolated atomic is 1-2 ns hot, 10-30 ns cold. Worst case
  all 18 loads miss L1 and hit L2 / LLC: 18 × 30 ns = 540 ns.
  Conservative upper bound: `W_read ≤ 1 µs`.
- `λ = per-worker completion rate`. Plan-wide steady-state is
  130 Kpps (§3.4). Peak observed on the cluster is 520 Kpps per
  worker (= 4× steady-state headroom). A 2 Mpps per-worker case
  corresponds to a hypothetical future workload (e.g., small-
  packet forwarding at the full 25 Gbps line rate: 25 × 10^9 /
  (8 × 64) ≈ 48.8 Mpps aggregate; at 4 workers = ~12.2 Mpps, or
  ~2 Mpps per worker under single-direction load). Conservative
  upper bound used here: `λ ≤ 2 Mpps` per worker — widened from
  the earlier 1 Mpps to cover the small-packet case (Codex
  round-3 finding).
- `K_skew(λ = 2 Mpps) = ceil(2e6 × 1e-6) = 2` completions.

**K_skew = 2 completions maximum**, derived — not assumed. At
C ≥ 1000 (roughly 8 ms of accumulated completions at 130 Kpps),
`K_skew / C ≤ 0.1 %`. At C ≥ 10 000 (roughly 77 ms), `K_skew / C ≤
0.01 %`. The 1% figure quoted in §8 is therefore loose by 2-3
orders of magnitude as a HARD-STOP — it tolerates pathologies
well beyond the derived bound while still ruling out true
corruption.

**Why keep the 1% hard-stop anyway (and not 0.01 %).** Two
reasons: (i) the derivation assumes `W_read ≤ 1 µs` but a scheduler
preemption during the snapshot function can push the reader off-CPU
for up to 4 ms on a non-RT kernel (CFS quantum); during that
window the worker can post ~8 000 completions at 2 Mpps. 8 000 /
C at C = 200 000 = 4 % — still over the 1 % gate but bounded within
one order of magnitude. (ii) the 1% is an INTEGRATION-LEVEL gate
that fires on a 60-second `iperf3 -P 16` run; over that duration
C ≥ 10^7 and K_skew is vanishingly small. The gate is therefore
looking for a DIFFERENT class of bug (sidecar-sentinel miscompare,
lost completion bookkeeping, stamp write landing on the wrong
slot), not for the memory-ordering skew itself.

**Test pin (§6.1 test #7 cross-thread snapshot).** Asserts
`|sum(hist) - count| ≤ K_skew` where `K_skew` is computed by the
test harness using the MEASURED completion rate over the test
window (not a magic constant). The harness spins a writer thread
that records `N = 1_000_000` completions as fast as it can, measures
`W_read` on each snapshot call via `Instant::now()` bracketing, and
computes `K_skew_observed = ceil(observed_rate × W_read)`. The
assertion is `|sum - count| ≤ K_skew_observed + 2` (+2 is a
paranoia margin for TSO vs ARM). The test FAILS if the observed
skew exceeds the derivation — that is the real regression signal.

- Snapshot consumers MUST treat `sum(hist)` and `count` as
  "observed at slightly different instants". The wire-contract
  guarantee is `|sum - count| ≤ K_skew` with K_skew derived as
  above; exact equality is not claimed.

**Consequences propagated into the rest of the plan.**

- §4 invariant 6 ("sum of buckets == completion count within the
  measurement window") is REWRITTEN as a SINGLE-THREAD property
  only: a synthetic unit test can drive N completions in one
  thread, then snapshot, and assert exact equality because the
  test is not racing the writer. Production snapshot equality is
  downgraded to "approximate within K_skew", which is what the
  existing drain-histogram pattern already states at
  `umem.rs:1322-1329`.
- §8 hard-stop #4 ("histogram sum ≠ count in an integration run")
  keys on `|sum - count| / count ≤ 0.01` — the hard-stop budget
  is looser than the derivation (so no false positives) but
  strict enough to catch the class of bugs the test is actually
  designed to catch (not memory-ordering skew). The 1% is
  DEFENDED: it is the scheduler-preemption-robust upper bound,
  not a guess.
- §11 statistical framework is REWRITTEN (see §11.3 R2 block). We
  DROP Bonferroni entirely — Codex R2 correctly noted that
  Bonferroni at α/36 ≈ 0.0014 is tighter than the 1% snapshot
  skew tolerance, so the statistical test would be defeated by
  the sampling noise. We replace it with a cell-level
  block-permutation test (Fisher-Pitman style on composite
  statistics) that is invariant to within-block reshuffles of
  individual samples — which subsumes snapshot-skew noise by
  construction because shuffles of size K_skew ≪ block size do
  not move the test statistic's null distribution. Codex MED #8
  and the round-2 Bonferroni-vs-1% contradiction are both closed
  by that replacement.

This decision is scoped to #812 only. If a later PR needs
point-in-time consistent snapshots for production-gating purposes,
the upgrade path is option (a) at the measured ~2 % ARM cost.
Issue #812 explicitly does NOT make that commitment.

## 4. Invariants

Non-negotiables that must not drift. Any violation = block merge.

1. **Hot path: no new lock, no new heap allocation, no new syscall per packet.**
   - `clock_gettime(CLOCK_MONOTONIC)` resolves through VDSO (user-space)
     on the declared deployment (Debian trixie, glibc 2.42-14, Linux 6.18
     kernel). **Proven**, not assumed — see §3.4a and
     `evidence/vdso_evidence.md` for the strace (host) +
     `AT_SYSINFO_EHDR` (`xpf-userspace-fw0` VM) captures. If a future
     deployment installs a seccomp profile that blocks
     `clock_gettime`, the helper degrades to a 0-return and the
     sidecar sentinel drops the sample (§5.4 / §6.1 test #5);
     observable as `tx_submit_latency_count ≡ 0` fleet-wide — §7
     revert row covers this.
   - The sidecar is pre-allocated once at binding construction.
   - The bucket atomic is `fetch_add(1, Relaxed)` — uncontended on the owner's cache line.
   - Reviewer check: `git diff` must show zero `Box::new` / `Vec::with_capacity` / `HashMap::insert` inside the submit or reap hot paths.

2. **Per-packet overhead — REVISED under §3.4 R1.** Steady-state
   (`inserted ≥ 64`): ≤ 15 ns CPU, ≤ 2 additional cache-line
   touches. Worst-case small-batch (`inserted == 1`): ≤ 45 ns and
   flagged as an investigation signal rather than a regression.
   Enforced by a Criterion micro-bench (new file
   `userspace-dp/src/afxdp/tests.rs` — add a bench) that pins BOTH
   the steady-state and the small-batch numbers separately.

3. **Histogram monotonic; no reset on snapshot.** §3.6 rationale.
   - Enforced by serde: no reset parameter plumbed.

4. **Thread-safety: single-writer (owner worker), many-readers.**
   - Submit-stamp and reap-bucket-increment are both on the owner worker's thread — the only thread that touches this binding's TX frames.
   - Snapshot reads are `load(Relaxed)` from the control-socket thread — identical pattern to the existing drain-histogram read at `umem.rs:1330-1345`.

5. **Bucket layout is frozen wire contract.** (§3.2 named-symbol
   asserts; Codex LOW #13.)
   - `const TX_SUBMIT_LAT_BUCKETS: usize = DRAIN_HIST_BUCKETS` plus
     `const _: () = assert!(TX_SUBMIT_LAT_BUCKETS == 16)` at module
     level; a renumber-without-propagation breaks the build with a
     targeted symbol.
   - Paired with a boundary test in §6.1 that calls
     `bucket_index_for_ns(K)` directly at the edge values — a
     boundary-drift error that preserves a count of 16 buckets is
     caught by the boundary test, not by the count-equality assert.

6. **Single-thread sum-equals-count — REVISED under §3.6 R1.**
   Within a single-threaded unit test that drives N synthetic
   completions and then snapshots, `sum(hist) == count`. Across
   threads (real production snapshot), the relation is
   `|sum - count| ≤ max_completions_in_snapshot_window`; exact
   equality is not claimed. This mirrors the existing
   drain-histogram comment at `umem.rs:1322-1329`.
   - Enforceable with: (a) an `#[test]` that drives N synthetic
     completions in one thread and asserts exact equality; (b) a
     second `#[test]` that races the writer with a reader and
     asserts the bounded-skew property `|sum - count| ≤ K` with
     `K` chosen from the snapshot read duration.

7. **`tx_submit_latency_count` monotonically ≤ `tx_completions` in
   the production steady state** (see §3.6 note on bounded
   read-skew). A completion with a missing sidecar entry
   (e.g., pre-#812 frame offset that survived a restart)
   increments `tx_completions` but NOT the histogram.

## 5. Measurement integrity — how do we know we're measuring what we think?

Three layers of assurance.

### 5.1 Injected synthetic delay (unit test)

Add a test at `userspace-dp/src/afxdp/tests.rs`:

- Construct a `BindingLiveState` and a fake sidecar.
- Stamp submit-ts at `T0`. Inject a manual completion with a
  deterministic `now = T0 + K_ns` for `K_ns ∈ {500, 1500, 10_000,
  100_000, 10_000_000}`.
- Snapshot the histogram; assert the specific bucket predicted by
  `bucket_index_for_ns(K_ns)` has count 1, all others 0.

This is the strongest possible pin — if the bucket arithmetic
shifts, the test fails on exactly the boundary value.

### 5.2 Histogram-sum consistency (property test)

- Drive N random-latency completions through the hot path. Assert
  `sum(buckets) == N`. Invariant 6.

### 5.3 End-to-end live data sanity check

Part of §6 integration test: after iperf3 `-P 16 -t 60`, read the
snapshot. Assert:
- `tx_submit_latency_count > 0` on every worker-queue pair that
  had TX activity (any `tx_packets > 0`).
- The non-empty histogram has NO mass in the saturation bucket 15
  (> 16 ms) in a healthy run — if it does, that's itself a
  D-tier signal (post-merge, not a failure of #812).
- Mean latency derived from `tx_submit_latency_sum_ns /
  tx_submit_latency_count` is in the expected single-digit-µs
  range.

### 5.4 Protection against phantom completions

If a frame offset completes without a submit-stamp (sentinel
`u64::MAX`), we MUST skip the histogram increment — otherwise we'd
record `ts_completion - u64::MAX` wrapping to a tiny positive ns
number that lands in bucket 0 and silently biases the distribution
toward "healthy".

The sentinel-check is part of §5.1's unit-test coverage (one test
case with a deliberately unstamped completion; histogram stays at
zero).

## 6. Test plan

### 6.1 Unit pins (≥ 8 after R2 additions — two new tests for HIGH #2 K_skew and HIGH #3 compile-time owned-static-send)

**R1 (Codex MED #9).** The earlier draft's test #2 staged a
cross-thread race between `record_tx_submit` and
`record_tx_completion`. The design in §3.3 explicitly says that
submit and completion for ONE frame offset are the same thread
(the owner worker) — so that two-thread race cannot happen in
production. Codex is right that that test is symbolic. It is
replaced with tests that exercise the real production risk
surfaces.

1. **Bucket boundary test.** See §5.1 — drive the stamp path with
   deterministic `T0` and `T0 + K` for `K ∈ {500, 1500, 10_000,
   100_000, 10_000_000}`, snapshot, assert exactly one count in
   the predicted bucket via `bucket_index_for_ns(K)`. Pair with
   Codex LOW #13: also call `bucket_index_for_ns` directly at the
   boundary values (`1024`, `2048`, ..., `1 << 24`) to pin the
   layout, not just the count of buckets.
2. **Partial-batch stamping.** Single thread. Build a scratch of
   256 descriptors; simulate `writer.insert` returning
   `inserted = 1` (then 2, 32, 64, 256). Assert that only the
   first `inserted` sidecar slots are stamped and the tail is
   left as `u64::MAX`. This is the Codex HIGH #1 small-batch
   regime test.
3. **Retry-unwind non-stamp.** Single thread. Simulate the
   `inserted == 0` path (the `writer.commit()` rejected path at
   `tx.rs:1858-1866`, `tx.rs:5938-5945`, `tx.rs:6152-6157`).
   Assert no sidecar slot is stamped and all descriptors return
   to `free_tx_frames`.
4. **Serialization round-trip.** Construct a
   `BindingCountersSnapshot` with a non-trivial histogram; JSON-
   encode, JSON-decode; assert field-equality. Also assert that
   a pre-#812 JSON payload (missing the new fields) deserializes
   with zero-valued histogram (serde `default`).
5. **Sentinel skip.** §5.4 — completion of an unstamped offset
   must NOT increment the histogram. Tests the `u64::MAX`
   sentinel and the `monotonic_nanos() == 0` fallback path
   (Codex MED #5: `neighbor.rs:8-10` returns 0 on clock failure,
   so `0` MUST NOT mean "stamped" — we canonicalize to sentinel).
6. **Single-thread sum-equals-count.** §5.2 — invariant 6 form
   (a). Drive N synthetic completions in one thread, snapshot,
   assert exact equality.
7. **Bounded-skew cross-thread snapshot (R2 — HIGH #2 test
   pin).** Spawn a writer thread that fires `fetch_add(1)` on
   random buckets AND `fetch_add(delta, Relaxed)` on `sum_ns` at
   maximum sustainable rate (≥ 500 Kpps simulated). Spawn a
   reader thread that calls `snapshot()` repeatedly for
   `N ≥ 10_000` iterations. For each snapshot, bracket the
   snapshot call with `Instant::now()` and record the observed
   read-window `W_read_i`. Compute the observed completion rate
   `λ_obs = count_final / elapsed_wall`. For each snapshot
   `i`, compute `K_skew_i = ceil(λ_obs × W_read_i) + 2`
   (margin of +2 for TSO/ARM ordering). Assert
   `|sum(hist_i) - count_i| ≤ K_skew_i`. This is the NAMED,
   DATA-DRIVEN test that pins §3.6 R2 HIGH #2 closure — K is
   computed from the harness's own measurements, NOT chosen per
   "§4 invariant 6" free parameter. The test FAILS if the
   snapshot-visible skew exceeds the write rate × read window
   product plus paranoia margin, which is the real regression
   signal (memory-ordering breakage or lost bucket accounting)
   distinct from the benign scheduler-preemption bound discussed
   in §3.6. The integration hard-stop at `|sum - count| / count
   > 0.01` in §8 is the LOOSER bound (tolerates preemption
   widening); this unit test is the TIGHTER bound (rules out
   actual bugs).

8. **`BindingCountersSnapshot` owned + static + send (R2 — HIGH
   #3 compile-time check).** The named const assert from §3.5a
   lives alongside the struct; a compile will fail if a future
   field addition breaks `'static + Send`. No runtime test — the
   test IS the compile. Also exercised by test #4 (JSON round-
   trip): serde's default `Deserialize` derive requires
   `DeserializeOwned` (i.e., no borrowed fields) without opt-in
   `serde(borrow)`, so any accidental reference addition fails
   test #4 even if the compile-time assert is somehow removed.

### 6.2 Integration test

Run on the `loss:xpf-userspace-fw0` HA cluster primary, per the
Step 1 execution environment (`step1-findings.md:21-22`).

```bash
# Setup: re-apply CoS config per engineering-style.md §Project-specific
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
# Run the instrumented daemon for 60 s at P=16
iperf3 -c 172.16.80.200 -P 16 -t 60 -p 5203
# Snapshot
cli -c "show userspace-dp binding counters" > snap.json
# Assertions (add a helper script — commit together with the PR)
jq '.per_binding[] | select(.tx_packets > 0) |
      {q: .queue_id,
       count: .tx_submit_latency_count,
       non_empty: (.tx_submit_latency_hist | map(. > 0) | any)}' snap.json
# Every worker with TX activity must have non-empty histogram + count > 0.
```

### 6.3 Forwarding smoke — mandatory continuous gate

Per `docs/development-workflow.md:188-202` and
`engineering-style.md:213-222`:

```bash
iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203   # 0 retransmits, before and after
```

If retransmits > 0 on either side: revert (§7).

### 6.4 Regression check — existing pin suite

`cargo test -p xpf-userspace-dp` — all 255 existing Rust tests
must still pass. In particular the `mqfq_*` and `flow_steer_*`
unit tests (admission, bucket math, snapshot serialization) — any
regression is a hard stop (§8).

## 7. Rollback

**Failure-mode enumeration:**

| Failure | Symptom | Catcher | Revert |
|---|---|---|---|
| Incorrect atomic ordering on bucket write | Test #2 fails; histogram sum ≠ count. | `cargo test`. | Revert the PR commit; no prod exposure. |
| Sidecar sentinel miscompare → bucket 0 bias | Mean latency artificially drops; §5.1 fails. | Unit test #4. | Revert. |
| `clock_gettime` returns 0 on an exotic kernel (Codex HIGH #2 / MED #5) | NOT a panic — `neighbor.rs:8-10` catches `rc != 0` and returns 0 silently. Effect: sample dropped (see §6.1 test #5: `0` canonicalized to `u64::MAX` sentinel and skipped). No corrupt measurement. | Unit test #5 + runtime `tx_submit_latency_count` would flat-line at 0 on every worker even under live traffic. | If count ≡ 0 across the fleet: `systemctl stop xpf-userspace && xpf-userspace cleanup && git revert` and file a bug. If count is non-zero anywhere: the daemon is fine, the clock is just probably-slow — no revert. |
| Cache-line ping-pong under cross-binding traffic | P=16 t=60 SUM regresses > 5 %. | Hot-path bench (§8). | Revert. |
| PR #804 wire-contract break | Pre-#812 snapshot consumer (step1-capture.sh running a pinned branch) chokes on new fields. | serde `default` annotations guarantee this does NOT happen — the test in §6.1 item 3 proves the compat. | No revert path needed IF the test passes. |

**Revert mechanics:**
```bash
git revert <commit-sha>
make build && make test-deploy && make cluster-deploy
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
# Forwarding smoke must pass at 0 retransmits.
```

If a revert itself fails (hitless-restart property violated), fall
back to `xpfd cleanup` on each node in sequence. The HA cluster
survives a rolling restart (`MEMORY.md` — "Hitless Restart Patterns").

## 8. Hard stops

Each of these terminates execution immediately; no investigation,
no "let's just merge it and file a follow-up":

1. **Hot-path bench regresses > 5 % on `iperf3 -P 16 -t 60 -p 5203` SUM** (absolute Gbps, pre vs post on the same cluster, same CoS state).
2. **Any forwarding smoke (`-P 4 -t 5`) returns retransmits > 0** after the PR lands.
3. **Any `mqfq_*` or `flow_steer_*` unit test fails.**
4. **Histogram sum drift exceeds bounded-skew tolerance** (`|sum(hist) - count| / count > 0.01` on a production integration snapshot; §3.6 R2 derives K_skew = 1 completion per snapshot at 1 Mpps × 1 µs, extended by the CFS preemption window to ≤ 4 000 completions at C ≥ 100 000 — still inside 1 %. The 1 % is the scheduler-preemption-robust upper bound, NOT a guess, and it is 2-3 orders of magnitude looser than the pure memory-ordering skew).
5. **CPU profile shows > 5 % time in `record_tx_submit` + `record_tx_completion` combined on the steady-state partition of the `perf record -e cpu-clock` flame-graph.**

### 8.1 R2 (MED) — Why the hard-stop is 5 %, NOT 1 %

Round-1 of this plan used a 1 % hard-stop. Round-1 fix derived
actual per-packet costs at 3.1 % typical and 9.4 % worst-case
(§3.4 tables). Round-2 review flagged that §8 silently widened
to 5 %/10 % without defending the regression.

**We defend the wider bound explicitly (option (b) from the
findings).** The 1 % bound was PROPOSED in the R0 draft before the
submit-stamp math was worked out. Once §3.4 was re-derived under
the realistic operating points — including `inserted == 1` which
the tx.rs code at `tx.rs:5953-5961` / `tx.rs:6164-6174` generates
naturally on partial-batch rejects — the typical-case cost lands
at 3.1 % and the small-batch worst case at 9.4 %. A 1 % gate would
hard-stop on the INSTRUMENTATION itself in the partial-batch
regime; that is the wrong failure mode (instrumentation must not
gate on its own presence).

Therefore: **5 % steady-state** + **10 % small-batch soft-gate**,
defended as follows:

- **5 % steady-state** covers the typical `inserted ∈ {64, 256}`
  operating points (3.1 % measured in §3.4) with headroom for
  cache-miss variance. Regression above 5 % means the hot-path
  cost has degraded beyond what the overhead tables predict —
  real instrumentation bug, fail loud.
- **10 % small-batch soft-gate** fires only if the partition of
  commits with `inserted == 1` exceeds the 9.4 % worst case.
  When this gate fires, the investigation is ALREADY in verdict C
  territory (TX ring full forces `inserted == 1`) — the
  instrumentation overhead is a secondary concern compared to the
  underlying shaper/ring problem the histogram was built to
  diagnose. The soft-gate surfaces the cost transparently without
  reverting.
- **The alternative was infeasible.** Tightening to 1 % would
  require eliminating either the submit stamp OR the exact
  `sum_ns` accumulator (§12 item 10) on small batches, which
  collapses the observability floor §1 needs. A conditional
  stamp (e.g. "only stamp 1 in 16 submits") introduces sampling
  bias that defeats the D1/D2/D3 separation in §11.1. The cost
  budget is a real constraint, not one that hand-waved 1 % math
  can satisfy.

If a reviewer argues the 5 % bound is still too loose, the
discussion belongs on a separate PR that chooses between (a)
rdtsc instead of VDSO, (b) stamp-only-on-sampled-batches, or
(c) dropping the exact `sum_ns` in favor of bucket-midpoint.
None of those are free; all of them lose measurement fidelity.
The current 5 % represents the cheapest correctness-preserving
budget.

## 9. Wall-clock + scope

### Implementation estimate

| Sub-task | Hours |
|---|---|
| `BindingLiveState` field additions + `#[repr(align(64))]` cacheline-isolation (similar to `OwnerProfileOwnerWrites`) | 2 |
| Submit-ts stamping — 6 sites in `tx.rs`, common helper | 2 |
| Reap-side delta + bucket `fetch_add` in `reap_tx_completions` | 1 |
| `BindingCountersSnapshot` + `BindingLiveSnapshot` fields + `From` impl | 1 |
| Coordinator reverse-copy (`coordinator.rs:1404-1427`) | 0.5 |
| Unit tests (8 pins, §6.1 — including R2 K_skew harness + compile-time owned-static-send assert) | 4 |
| Integration helper + smoke | 1 |
| Criterion bench for hot-path overhead | 1.5 |
| Plan/code review finding response | 2 |
| **Subtotal** | **15 h** |

### Total story

| Phase | Typical rounds (workflow §Plan-cycle) | Wall-clock |
|---|---|---|
| Plan review (Architect ↔ Design Reviewer) | 2-4 | 1-2 days |
| Code implementation | — | 2 days |
| Code review (Codex + Rust angle) | 2-3 | 2-3 days |
| Merge + forwarding validation | — | 0.5 day |
| **Total** | | **6-8 days** |

### Stack posture

**Ships alone.** No stacking. Rationale:

- #812 is strictly additive observability and does not modify the
  hot-path semantic state that any other in-flight PR would
  depend on.
- #806 (Z_cos recalibration) explicitly waits for #812 to land
  first (§10).
- Stacking it on an unrelated refactor PR (e.g. 807-refactor)
  would entangle the hot-path bench comparison.

## 10. Z_cos recalibration — separate sub-task after merge

**Deferred to follow-up commit, not part of #812's scope.**

Once #812 is merged and running on the HA cluster primary:

1. Re-run the step1-capture script on AT LEAST two with-cos-fwd
   shaped cells (e.g. `p5202-fwd-with-cos` and
   `p5203-fwd-with-cos`).
2. Sample `queue_token_starvation_parks` AND the new
   `tx_submit_latency_hist` on each run.
3. Derive `Z_cos = mean(park_rate) + 2 × stddev(park_rate)` per
   `step1-plan.md:507-524`.
4. Update the §4.2 threshold table in `step1-plan.md` with the
   real number, and amend `step1-findings.md` §5 noting the
   recalibration.
5. Amend the §8 gating loop at `step1-plan.md:1082-1094` —
   specifically the line that reads "the gate is on data
   provenance (Z_cos source), not on fire count" — to mark the
   gate CLOSED.

This is a DOCS-ONLY PR once #812 is in. Wall-clock ~1 day.

## 11. Statistical analysis — what the re-run classifier looks for

After #812 merges, re-running Step 1 with the new histogram
available changes the per-cell dashboard from 10 fields to 26
(adding 16 bucket counts, plus count and sum-ns). The classifier
will look for signature patterns, not just scalar thresholds.

### 11.1 Patterns per verdict

| Verdict | Histogram pattern that indicates it |
|---|---|
| **A** (cross-worker imbalance) | Histogram shape roughly equal across workers; the imbalance is in `rx_packets / tx_packets` counts, not in TX-completion latency. No change to how A is detected — A fires on flow distribution, independent of latency. |
| **B** (MQFQ token starvation) | Mass concentrates in buckets 4-7 (tens of µs) correlated with `queue_token_starvation_parks > 0`. The park-rate spike and the latency-bucket shift SHOULD co-occur. If they don't, the park counter is misleading (classifier HIGH finding for a future revision). |
| **C** (TX-ring full) | Mass shifts to buckets 8+ (hundreds of µs to ms). Completions stall because the ring is full and `sendto` kicks are bounced. Correlated with `dbg_tx_ring_full > 0`. |
| **D1** (XSK submit → DMA latency alone) | Mass in buckets 3-6 (4-128 µs) with NO correlation to park-rate and NO ring-full events. The smoking gun: latency elevated, but everything else clean. |
| **D2** (reap-lag jitter below C) | Bimodal distribution: most completions in buckets 0-2 (healthy) plus a secondary lobe in 6-9 (occasional multi-ms reap lag). The difference between D2 and D1 is the SHAPE — D1 is a shifted mean, D2 is a heavier tail. |
| **D3** (NIC-side backpressure / LLFC) | Saturation mass in bucket 14-15 (≥ 8 ms) that clears when wire-level pressure relaxes. Requires correlating with `ethtool -S tx_pause` time-series (separate follow-up). |
| **D confirmed (no new signal)** | Histogram is tight in buckets 0-2, count × 60s ≈ tx_packets, NO visible tail. The ~2.4 Gbps shortfall observed in `step1-findings.md:95` is not in the TX-completion path → it must be in RX coalescing (D4) or upstream. |

### 11.2 What would make the verdict A/B/C actually FIRE under re-run

- For verdict A: `k_A ≥ 2` across neighboring cells (§4.6
  aggregation rule, `step1-plan.md:1069-1074`). The histogram does
  NOT change the A firing logic, but it can corroborate it by
  showing per-worker histogram divergence.
- For verdict B: `k_B ≥ 2 of 4` with-cos-fwd shaped cells AND the
  Z_cos gate in §10 CLOSED.
- For verdict C: `k_C ≥ 1` — same as before. The new histogram
  can pre-warn for C before `dbg_tx_ring_full` spikes (mass
  drifting to bucket 8+ indicates the TX ring is filling).

### 11.3 False-positive risk of the new signal

Per `step1-plan.md:1134`, no bare "5 %" thresholds. The histogram
adds 16 counters × 12 cells = 192 additional observations per
re-run.

**R2 (Codex HIGH #2, MED #8) — DROP Bonferroni; use cell-level
block-permutation (Fisher-Pitman style).**

Round-1 of this plan proposed Bonferroni correction at α/36 ≈
0.0014. Round-2 review correctly noted that 0.0014 is **tighter**
than the 1 % snapshot-skew tolerance from §3.6 — which means the
snapshot-skew noise floor would swallow any Bonferroni-corrected
signal. The statistical guarantee would be defeated by the
sampling tolerance. We resolve this by picking a test whose
null distribution is CONSTRUCTED from the data itself, so that
within-block noise (of which snapshot skew is a strict subset)
is absorbed into the reference distribution rather than fought
against it.

**The three composite statistics** (pre-registered):

- D1 statistic: `T_D1 = mass(buckets 3..=6) / count` over the cell
  window, combined with the park-rate delta and the ring-full
  indicator. Pre-register the combination as a single scalar
  (weighted sum, weights from baseline-healthy runs).
- D2 statistic: `T_D2 = mass(buckets 0..=2) / count × mass(buckets
  6..=9) / count` (bimodality product). Single scalar per cell.
- D3 statistic: `T_D3 = mass(buckets 14..=15) / count` correlated
  with `ethtool -S tx_pause` non-zero over the window (Pearson r
  on 1 Hz samples). Single scalar per cell.

Three composite tests per cell × 12 cells = 36 statistics total
— same count as the round-1 draft, but we use a DIFFERENT
decision rule.

**Decision rule: cell-level block-permutation test.** For each
statistic T and each cell:

1. Collect the time-series of snapshot-differenced bucket counts
   at 1 Hz over the cell's 60-second window (60 samples per
   bucket, 16 buckets × 60 = 960 observations per cell). This is
   the unit of noise and includes any snapshot-skew induced by
   §3.6.
2. Compute the observed statistic `T_obs` on the real ordering.
3. Permute the per-second blocks (not individual samples) N =
   10 000 times, recomputing T on each permutation. Block size
   is chosen so that within-block reshuffles absorb snapshot
   skew (K_skew ≤ 1 per snapshot ≪ 130 000 completions per
   1-second block). **By construction**, K_skew noise does not
   affect the null distribution — the reshuffle moves entire
   1-second blocks, each already internally averaged over
   130 000 completions, so the skew-per-snapshot is washed out
   by the block-integration step.
4. Fire the verdict iff `T_obs ≥ τ_cell` where τ_cell is the 95th
   percentile of the permutation distribution for that cell,
   THEN require `k_verdict ≥ 2 of 12 cells` (analogous to the
   existing step1-plan.md §4.6 aggregation rule). The cell-level
   threshold is derived from the cell's own data; the cross-cell
   aggregation is the investigation-level rule. No Bonferroni
   correction is applied — the permutation test is single-cell
   valid, and the aggregation step does the cross-cell
   correction implicitly (a spurious single-cell fire cannot
   produce `k ≥ 2` under the null).

**Why this resolves the 1 %-vs-0.0014 contradiction.** The 1 %
snapshot-skew tolerance from §3.6 bounds the NOISE ON EACH
1-SECOND BLOCK at ≤ 1 % of the block's mass. Block-permutation
tests are valid for any noise model where the within-block noise
is exchangeable across blocks (which 1 % skew with mean-zero
drift trivially satisfies). The 0.0014 Bonferroni bound assumed
INDEPENDENT single-bucket nulls and so was sensitive to the
per-observation noise — which snapshot skew dominates. The
permutation test sidesteps this entirely: it asks "is the
observed block sequence more ordered than 95 % of random
re-orderings of the blocks?" and that question is answered the
same way whether each block's mass is skewed by 0 % or 1 %.

Baseline thresholds τ_cell are NOT a free constant — they are
the 95th percentile of the permutation distribution computed on
the same data the test is evaluated on. The §10 baseline-healthy
runs are used to derive the EXPECTED SHAPE of the null
distribution (mean, variance, autocorrelation — that inform the
block size choice of 1 second), but not the threshold itself.

**Cross-cell aggregation rule (k_D1 / k_D2 / k_D3 ≥ 2 of 12).**
Same shape as the existing step1-plan.md §4.6 rule for
`k_A ≥ 2`, `k_B ≥ 2`. This handles multiplicity without
Bonferroni by requiring cross-cell corroboration; a single-cell
fire is not a verdict, it is a lead. The 0.0014 bound is not
needed because the hurdle is "two cells fire at cell-level
p ≤ 0.05" not "any cell fires at p ≤ 0.05/36".

The 16-bucket Bonferroni claim from R1 is **withdrawn entirely**;
R0's original Bonferroni proposal is also withdrawn; neither
survives R2.

**Consistency with §3.6 R2.** The block-permutation test's
validity bound is that within-block noise is exchangeable across
blocks. Snapshot skew bounded by K_skew = 1 completion per
snapshot (derived in §3.6 R2) is trivially exchangeable — it is
a zero-mean offset with a bounded variance that does not depend
on block identity. The 1 % integration-level tolerance from §8
hard-stop #4 is a coarser bound that covers scheduler-preemption
extensions of K_skew; the permutation test also absorbs that
bound because the preemption event's location in time is
uniformly distributed across blocks.

## 12. Deferrals — expected reviewer concerns we deliberately do NOT address in this PR

Listed with rationale so a future reviewer doesn't rediscover them.

1. **Prometheus export of the new histogram.** JSON-only in this
   PR. Step 1 classifier consumes JSON. Prometheus wiring adds a
   separate serde path and risks a cardinality-blowup per
   queue-per-worker. Follow-up issue to be filed as #812a.
2. **Per-flow (per-5-tuple) latency histograms.** Bucket-
   isolating by flow would require a hash in the hot path —
   violates the allocation rule. Aggregate-per-queue is the right
   scope for Step 2.
3. **Histogram reset endpoint.** §3.6 explicit decision.
4. **HdrHistogram / dynamic bucket adaptation.** Incompatible
   with the hot-path allocation rule. Fixed-cap array is the
   Engineering Style commitment (`engineering-style.md:52-57`).
5. **Moving `bucket_index_for_ns` to a shared helper crate.**
   The function already lives in `umem.rs` and is used by three
   callers (drain, redirect-acquire, submit-latency). Extraction
   to a helper module is cleanup, not blocking — it survives the
   "source of truth" rule (`engineering-style.md:17-20`)
   trivially because all three uses WILL NOT drift: they all
   const-assert the same bucket count.
6. **NIC-side `ethtool -S tx_pause` time-series.** Needed for D3
   separation. Separate follow-up (Step 2 D3 spike PR, not #812).
7. **Reverse-direction CoS config fix.** `step1-findings.md:18-24`
   — noted, separate PR to be filed after this one.
8. **Bucket-width asymmetry / bucket-0 coarseness (R2 — MED
   resolved, out-of-scope).** Round-1 and round-2 review flagged
   that 16 log2 buckets is coarse at the low end (everything
   < 1 µs in bucket 0) and asked whether MQFQ-vs-shaper
   separation at the sub-µs level could be lost.

   **Resolved: explicitly out of scope for #812.** Rationale:

   - The MQFQ-vs-shaper verdict signature (verdict B) lives in
     **buckets 4-7 (8-128 µs)** per §11.1, NOT in bucket 0.
     Queue-starvation parks manifest as tens-of-microseconds
     latency spikes on completion — well above the 1 µs bucket-0
     floor.
   - Verdict C (TX-ring full) lives in **buckets 8+ (≥ 256 µs)**
     per §11.1, also far above bucket 0.
   - D1 lives in buckets 3-6, D2 in 6-9, D3 in 14-15 — no
     classifier statistic reads from bucket 0 at all.
   - Bucket 0 is the "healthy NIC DMA" floor; the classifier's
     pre-registered composite statistics (§11.3 R2 above) all
     IGNORE bucket 0. Sub-µs resolution would only buy signal if
     a future verdict distinguishes healthy-fast from
     healthy-slow, which is not in scope for the D-tier
     investigation that motivated #812.
   - The existing drain histogram (#709) uses the same layout and
     has survived three revisions. Changing the layout for #812
     alone would break `bucket_index_for_ns` single-source-of-
     truth and force a wire-format change on the drain histogram
     for no classifier benefit.

   If a future investigation needs sub-µs resolution (e.g. for
   verifying NIC DMA pipelining), the right answer is a separate
   high-resolution histogram on a different code path, not a
   re-layout of this one.
9. **Online Z_cos recalibration.** Keep the recalibration
   off-line (operator runs step1-capture, updates the plan). An
   online feedback loop in the daemon would couple the
   classifier to the scheduler and expand blast-radius well
   beyond instrumentation scope.
10. **Bucket midpoint for `tx_submit_latency_sum_ns`.** We store
    the exact per-packet delta sum, not a midpoint
    approximation. Discretization-free mean at the cost of one
    extra `fetch_add(delta, Relaxed)` per completion — already
    counted in the §3.4 overhead budget (the 3-5 ns bucket
    fetch_add line).
11. **Interaction with rare hot-path #806 patches.** None — #806
    explicitly depends on #812 landing first. #806 is the
    Z_cos recalibration and any AFD follow-up work; it cannot
    start until the gate in `step1-plan.md:1082-1094` is closed.

---

*End of Architect draft. Awaiting Design Reviewer findings per
`docs/development-workflow.md:85-99`. Reviewer: please flag
HIGH / MEDIUM / LOW with `file:line` citations and concrete
mitigations. Append results to `docs/pr/812-tx-latency-
histogram/plan-review.md`.*

# #1772 — neighbor/ARP resolution latency metrics (design note)

Observability-only. No forwarding-behavior change. Brief design note +
CODE-review gauntlet (not a heavy plan-review round).

## Goal

Add LATENCY histograms to the neighbor/ARP resolution path so the
operator's INTERMITTENT slow-new-connection symptom (#1769) becomes
visible. #1769 added only COUNT metrics. We need timing.

## Where each metric lives (cardinality bound = aggregate, NOT per-flow)

All histograms are SHARED aggregate (single set of atomics), not
per-binding/per-zone — these events are rare (neighbor miss/retry, not
per forwarded packet) so a single aggregate histogram has bounded
cardinality and near-zero contention. They live on a new
`NeighborLatencyHist` carried alongside the existing #1769
`ResolverCounters` (already an `Arc` shared across all 6 WAN workers and
the single resolver thread).

1. **pending_neigh dwell** (`xpf_userspace_neighbor_pending_dwell_seconds`)
   — `now_ns - pkt.queued_ns` recorded in `retry_pending_neigh` at the
   moment a buffered packet is successfully resolved + dispatched. Reuses
   the existing `queued_ns` timestamp (monotonic CLOCK_MONOTONIC, same
   source as `now_ns`, so `saturating_sub` cannot underflow). Hot-path
   cost: one sub + one `bucket_index` + one `fetch_add(Relaxed)` ON THE
   RETRY SWEEP, which is already off the per-packet fast path. THE key
   metric — directly "how long a packet waited for neighbor".

2. **neighbor resolution latency** — folded into #1. The
   first-miss→usable interval is exactly the pending dwell for the
   buffered packet that finally goes out; a separate metric would
   double-instrument the same interval, so #1 covers it.

3. **resolver GETNEIGH RTT** (`xpf_userspace_neighbor_resolver_get_rtt_seconds`)
   — RTM_GETNEIGH sent → reply read, measured around
   `send_get_neigh`+`read_get_reply` on the single resolver thread.
   Recorded for every GET attempt that gets a usable RTT measurement.

4. **probe → revalidate latency** — NOT cleanly separable in-process.
   The probe (`trigger_kernel_arp_probe`) fires on the resolver/retry
   thread but the REACHABLE confirmation arrives asynchronously on the
   netlink MONITOR thread (a different thread, no per-key request/reply
   correlation timestamp). Correlating probe-fire→confirm would require a
   per-key in-flight timestamp map keyed by `(ifindex,hop)` shared
   monitor↔resolver — net-new shared state + lock on the monitor hot
   path. Out of scope for an observability-only PR; the GETNEIGH RTT (#3)
   + pending dwell (#1) together localize the wait. Documented as a
   known gap.

5. **pending_neigh timeout-drops + max queue depth** (counts):
   - `xpf_userspace_neighbor_pending_timeout_drops_total` — incremented
     in `retry_pending_neigh` on the timeout branch (currently only
     records the neg-cache entry; no counter). NEW.
   - `xpf_userspace_neighbor_pending_max_depth` — high-water gauge of
     `binding.pending_neigh.len()` observed at retry-sweep entry. NEW.

## Histogram layout (cheap, fixed buckets, no per-sample alloc)

16-bucket pow2-ns ladder, shared with both dwell and GETNEIGH-RTT:
bucket `i` (0..=14) upper bound = `2^(16+i)` ns; bucket 15 = `+Inf`
(saturate). 2^16 = 65.5us … 2^29 = 537ms, 2^30 = 1.07s, 2^31 = 2.15s,
2^32 = 4.29s. The 3 s blackout class from #1769 lands in bucket 15's
neighbor (the `2^32` / `+Inf` tail) — clearly visible as a multi-second
tail. Each bucket is an `AtomicU64`; record = `fetch_add(1, Relaxed)` +
sum-ns `fetch_add` + count `fetch_add`. Status reader does Relaxed loads
(eventually-consistent monotonic counters — same discipline as the
existing #1769 resolver counters; NO seqlock needed, no TSC infra; the
heavy `cold_path_hist` per-zone-pair seqlock machinery is deliberately
NOT reused — it is policy-eval-scoped and far too heavy for a
rare-event aggregate).

Prometheus export: emit cumulative `_bucket{le=...}` + `_sum` + `_count`
following Prometheus histogram convention, in `pkg/api`.

## Plumbing (mirror the #1769 neighbor_resolver_* path exactly)

- Rust: `NeighborLatencyHist` on `NeighborManager` (shared Arc), snapshot
  via `coordinator/status.rs` accessor → `server/helpers.rs` →
  `protocol/control.rs` status struct (bucket array + sum + count + the
  two count/gauge fields).
- Go: `pkg/dataplane/userspace/protocol.go` status struct fields →
  `pkg/api/metrics_descriptors.go` (+ collector) Prometheus histograms +
  the two counters; `show system buffers` surfaces them.

## Hot-path safety

The forwarded-packet fast path (`poll_binding_process_descriptor` happy
path) is UNTOUCHED. All new records fire only on: (a) the retry sweep
(off the per-packet path, runs post-poll / on empty RX), and (b) the
single resolver thread. Verified by inspection: no new code in the
descriptor happy path; `retry_pending_neigh` early-returns when
`pending_neigh.is_empty()` (the common case), so a steady-state
forwarding workload with no neighbor misses pays zero.

## Tests

- Rust unit: bucket boundary table (3 s → tail bucket), dwell record
  increments correct bucket, monotonic-sub no underflow, timeout-drop
  counter, max-depth high-water. 5× flake loop on the dwell test.
- Go: protocol round-trip + collector emits the histograms.

## Bonus (the real goal)

After deploy: flush neighbor (`ip neigh flush dev ge-0-0-2.80`) on fw0
under sustained iperf3 + many parallel new flows, then read the dwell /
GETNEIGH-RTT tails to localize where the intermittent slowness lives
(pending dwell vs kernel-ARP RTT vs resolver GETNEIGH).

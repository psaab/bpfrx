# userspace-dp/src/afxdp/tx/

The TX side of a binding: classify into a CoS queue, dispatch
through the queue service, drain shaped queues, segment large TCP
frames, submit to the kernel's TX ring, reap the completion ring,
and recycle UMEM frames.

Every file here is **single-writer (owner worker)**. Atomic
operations use `Ordering::Relaxed` because there is no second
writer to synchronize against.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub. |
| `cos_classify.rs` | Maps a packet's policy / filter / classifier signals to a CoS queue id and an optional DSCP rewrite, then enqueues onto the chosen queue. |
| `dispatch.rs` | Batch dispatch from descriptor loop into the CoS queue runtime; handles fast-path interface lookup and falls back to the CoS engine. |
| `drain.rs` | Per-tick drain dispatch + queue-bound / pending-queue helpers. Owns the `COS_GUARANTEE_QUANTUM_*` and `COS_GUARANTEE_VISIT_NS` constants. |
| `rings.rs` | XSK kernel-ring discipline: completion drain, fill submit, RX/TX kernel wake. |
| `stats.rs` | Per-frame counters and submit-latency histogram bucketing. The sidecar `&mut [u64]` is non-atomic since it's owner-only. |
| `tcp_segmentation.rs` | TCP segmentation for forwarded frames (extracted in PR #1199). `#[cold]` — segmentation is the slow path; line-rate flows don't enter it. **#5141:** the local-owner fast-path twin of `frame/tcp_segmentation.rs` — it clamps the segmentable payload to the IP-declared datagram end (`declared_l3_end`, IPv4 `total_len` / IPv6 `40 + payload_len`) instead of the raw `&frame[l3..]` backing, so trailing Ethernet slack / appended bytes are never chunked into fresh checksummed segments. Kept byte-identical to the copy-path twin; the admission gate `forwarded_tcp_may_need_segmentation` in `dispatch/mod.rs` clamps the same way. **#5148:** neither the admission gate NOR the builder segments ANY IP fragment — first or non-first. A fragment (IPv4 MF=1 or offset≠0, or an IPv6 Fragment extension header) still carries the fragment-bearing IP header (Identification / MF / offset), so segmenting it would clone that header into every output while rewriting seq/checksum — overlapping offset-0 pseudo-fragments that break reassembly. The gate uses `is_any_fragment` (was the non-first-only `is_non_first_fragment` before #5148) and the builder repeats the guard (defense in depth); any fragment is routed to the normal forwarding path unchanged, matching the sibling #1852 non-first handling. Segmentation is only for WHOLE (unfragmented) over-MTU TCP datagrams. |
| `transmit.rs` | XSK TX-ring submit + per-frame recycle. Owns `transmit_batch`, `transmit_prepared_queue`, shared-UMEM-aware prepared recycle helpers, and the `TxError` enum. |
| `test_support.rs` | Test helpers for the per-file unit tests. |

## Where it sits

- Driven from `worker/lifecycle.rs::poll_binding`.
- Reads decisions from `forwarding/` and CoS state from `cos/`.
- Writes to UMEM via `umem/` and to the kernel via `xsk_ffi`.

## Notable invariants

- Single-writer per binding: every TX path here runs on the binding's
  owner worker. Cross-binding redirect (the only legitimate
  cross-worker writer) lives in `cos/cross_binding.rs` and uses an
  MPSC inbox plus slot-routed prepared recycle records to release
  source UMEM frames after copy.
- Prepared-frame discard paths are not local by default in shared-UMEM
  mode. Any path that drops, demotes, bounds, cancels, or rejects a
  `PreparedTxRequest` must call the `_with_shared` recycle helper while
  carrying the worker's shared recycle accumulator, then route the
  `(slot, offset)` records back through the shared slot-resolution helper.
  The split-slice path used while holding the ingress binding and the
  all-bindings cleanup path must share this resolver so stale lookup entries
  are handled identically. Unknown recycle slots must fail closed and
  increment both aggregate `tx_errors` and the subset
  `tx_shared_recycle_unknown_slot_drops` on the worker status surface with
  bounded one-line logging per drain; never push a foreign offset into an
  arbitrary binding's fill ring.
- The cross-binding direct-TX build's `debug-log` tuple-mismatch diagnostic
  (`dispatch/mod.rs`) drops the built frame by setting `build_failed`; the
  frame's `tx_offset` is recycled to `free_tx_frames` through the SINGLE
  `if build_failed` handler. The diagnostic branch records the mismatch
  exception but must NOT push the offset itself. Recycling the same offset in
  both the diagnostic branch and the `build_failed` handler double-frees it —
  the offset is then handed out for two later TX descriptors that alias one
  in-flight frame (on-wire corruption / double-free on the debug-log build).
  Regression: `direct_tx_tuple_mismatch_recycles_frame_exactly_once` (#4041).
- `Ordering::Relaxed` is intentional and correct given the
  single-writer invariant. Don't promote without proving a second
  writer exists.
- TCP segmentation is `#[cold]`. The fast path is direct submit;
  segmentation only fires for over-MSS forwarded frames.

## Ongoing refactor: `enqueue_pending_forwards` outlining (#4408)

`dispatch/mod.rs::enqueue_pending_forwards` is a large TX-drain
orchestrator (build + segmentation + WG/GRE + output-filter + CoS). It
is being decomposed into named private helpers in bounded, behaviour-
identical (pure code-motion) increments tracked by #4408. Each helper
preserves the hot-path invariants the function guards: no-alloc /
zero-copy for non-NAT64 forwards, the single-recycle invariant, and the
CoS guarantee-guard.

- **Increment 1** — `compute_forwarded_egress_ptb`: the #2301/#2330/#2845
  Path-MTU-Discovery block. Given the source (inner) frame, meta, and
  decision it derives the inner-source MTU, runs
  `forwarded_egress_mtu_decision`, builds the ICMP Frag-Needed (v4) /
  Packet-Too-Big (v6) reply (subject to RFC / #2472 rate-limit
  suppression), and records the `egress_mtu_exceeded` exception. Returns
  `(ptb_reply, mtu_signalled)`; the caller drops the oversized original
  when `mtu_signalled` and enqueues `ptb_reply` at the finalizer.

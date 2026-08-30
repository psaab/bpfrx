# userspace-dp/src/afxdp/session_glue/

The bridge between an existing session table entry and a forwarding
resolution. Given a session's `SessionDecision` (NAT, drop, or
forward) and the cached `ForwardingResolution` from a prior packet
of the same flow, this module decides whether the cache is still
usable or the resolution must be re-derived.

Also writes the userspace dataplane's view of session state back
into the BPF session map mirror so the CLI / GC / metrics surface
sees the same sessions the userspace path is processing.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Cache-validation helpers (`cached_session_resolution`, `resolution_target_for_session`), `resolve_flow_session_decision`, `delete_terminal_filtered_session`, plus the BPF session-map mirror writers. |
| `promote.rs` | Synced-session hit handling: `maybe_promote_synced_session` (promote a peer-synced hit to locally-owned) and `purge_translated_synced_hit` (drop + NAT-release a transient alias-owned hit). |
| `commands/` | Worker-command handlers (`handle_upsert_synced`, `handle_delete_synced`, owner-RG refresh/demote/export). |
| `tests.rs` | Co-located unit tests for cache validation + mirror semantics. |

## Where it sits

- Called by the worker poll loop after `session::lookup` finds an
  existing session.
- Reads from `forwarding/` for resolution rebuild when the cache is
  stale.
- Writes to the BPF session map (via `coordinator/bpf_maps.rs` FDs)
  so the eBPF data-display surface mirrors the live userspace
  session table.

## Command ingest is budgeted (`apply_worker_commands`, #7201)

`apply_worker_commands` is the worker's consumer for its
`Arc<Mutex<VecDeque<WorkerCommand>>>` queue. It does **not** drain the
whole queue.

Each pass takes a contiguous FRONT prefix of at most
`worker_queue::WORKER_COMMAND_DRAIN_BUDGET` (256) commands into a
caller-owned scratch deque (`drain_bounded_into`), dispatches exactly
those, and returns `WorkerCommandResults.commands_backlogged` if the
shared queue still holds more.

Why, and what a change here must not break:

- **Every command is a session-table mutation plus a BPF-map publish
  syscall, and the worker does not touch its AF_XDP rings until the
  dispatch loop ends.** Batch size is therefore unserviced ring time.
  Draining the full #6929 queue cap of 4096 measured 3.85 ms against an
  RX ring that fills in ~1.97 ms at 25 Gbps — and the burst arrives at
  RG activation. Before #7201 this was `core::mem::take` of the whole
  deque and one uninterrupted `for` loop.
- **The prefix is contiguous and taken from the front,** so FIFO and the
  ordering groups survive a split by construction. The queue carries
  ordered state transitions (`UpsertSynced` then `DeleteSynced` for one
  key); a budget that filled its quota by skipping, or took from the
  back, would invert a key's state.
  `apply_worker_commands_dispatch_order_pin_with_demote_dedup` pins the
  order within one batch;
  `apply_worker_commands_7201_preserves_dispatch_order_across_a_budget_split`
  pins it across the seam.
- **`commands_backlogged` must reach `did_work` in
  `worker/loop_body`.** It is not a statistic. `did_work` is otherwise
  set only by `poll_binding`, so dropping this makes the budget worse
  than the defect: a promoted standby with no traffic yet runs
  `idle_iters` past `IDLE_SPIN_ITERS` and puts every remaining slice
  behind a 1 ms `poll(2)` in Interrupt mode.
- **The scratch deque is worker-owned and recycled** — entered empty,
  left empty. It is what removed the zero-capacity regrow: `mem::take`
  handed the worker the producers' allocation and left the shared deque
  at capacity 0 for the producers to rebuild under the lock every pass.
- Export acks stay monotonic across a split: `worker/loop_body` stores
  `exported_sequences.iter().max()` per pass, and FIFO makes each pass's
  max strictly greater than the last.

## Terminal-filtered session teardown (`delete_terminal_filtered_session`, #5622)

When an *established* LocalDelivery session re-evaluates a terminal gate
on the session-HIT path and is now denied — host-inbound admission,
an lo0 input filter, or a `to-zone junos-host` policy (the three
`poll_descriptor` call sites) — the session is torn down. Because a
translated flow is TWO independent entries (forward `is_reverse=false`
+ reverse companion `is_reverse=true`) and the hit can land on EITHER,
the teardown must resolve and remove BOTH halves and release the
NAT pool reservation, exactly like the ordinary idle reap
(`worker/loop_body::reap_expired_sessions`) and the DSCP-filter purge
(`purge_sessions_for_input_dscp_filter_revalidation`) do per entry.

`delete_terminal_filtered_session` therefore:

- recovers the companion key with `reverse_session_key(key, decision.nat)`
  (its own inverse given the reversed decision, so it yields the forward
  key from a reverse hit and vice-versa — the same hop
  `companion_keeps_alive`/`account_packet` use);
- runs `delete_terminal_half` for the resolved key AND (if present) the
  companion. Each half releases its source-NAT / NAT64 allocation
  (`release_source_nat_allocation`/`release_nat64_allocation`, both
  self-gated on `is_reverse` and keyed on the forward flow — so the pair
  frees the reservation EXACTLY ONCE, no double free), deletes the live
  BPF session-map + conntrack aliases, drops the worker-local table entry
  and the shared HA maps, queues the cross-worker `DeleteSynced`, and
  emits its close delta (suppressed for the reverse half).

The DSCP purge no longer releases allocations separately — the helper
owns that now; `release_flow` is idempotent, so a caller that visits both
halves in turn stays correct. Before #5622 the helper deleted only the
supplied key and released nothing, leaking the same-worker companion
entry and the pool port on every translated LocalDelivery terminal deny.

## Transient synced-hit purge (`purge_translated_synced_hit`, #5295)

When a packet hits a peer-synced translated FORWARD session whose RG is
NOT locally active (`should_keep_synced_hit_transient` in `promote.rs`),
the hit is kept *transient*: the entry is purged from the worker table,
the shared HA maps, and the kernel session-map so the local node
re-resolves instead of forwarding to the wrong node. That purged entry is
a forward, peer-synced session, so at install `handle_upsert_synced`
RESERVED its translated `(pool_addr, port)` in this node's LOCAL
source-NAT / NAT64 allocator (`reserve_synced_source_nat_allocation` /
`reserve_synced_nat64_allocation`, #4388 / #4512) so a post-failover local
allocation cannot re-hand the same tuple.

Since #6211 the source-NAT reserve picks WHICH rule's allocator to use by
re-running the active node's own match predicate against the synced zone
pair + 5-tuple, instead of taking the first rule whose pool merely contains
the translated address (they differ only when two rules carry overlapping
pool addresses in separate allocators — see
`docs/session-sync-architecture.md`). Because selection is no longer a pure
function of `rules`, a session re-upserted after the selection outcome
changes can hold a reservation in TWO independent allocators, so
`release_source_nat_allocation` now frees from EVERY pool-mode rule rather
than stopping at the first hit. Stopping at the first hit stranded the other
reservation permanently. The sweep cannot over-free: `release_flow` /
`rollback_flow` return false unless the stored translated tuple matches.

#6979 F3: an accepted same-key REPLACEMENT releases the replaced session's
reservation before installing the new one — but only when the new entry will
not re-reserve the flow. Most replacements need nothing: `reserve_flow` is
keyed on the ORIGINAL 5-tuple (`SourceNatFlowKey` carries no translated
field), so a NAT -> different-NAT re-decision finds the incumbent under the
same flow and retires it with release semantics (#6528). The hole was the
replacement that never REACHES `reserve_flow` — the reserve is gated on
`is_peer_synced() && !is_reverse` at the call site and again on
`nat.rewrite_src.is_some()` inside
`reserve_synced_source_nat_allocation_with_holder` — so a NAT -> NO-NAT
re-decision (the active re-evaluates a reused 5-tuple after its NAT rule is
withdrawn), a flip to a reverse entry, or a peer-synced -> local-origin
replace installed the new session and stranded the old port forever:
delete-sync releases the CURRENT decision, which no longer names it.
`handle_upsert_synced` captures the previous `(decision, metadata)` before
`upsert_synced_with_origin` discards `_previous` and, when
`new_entry_reserves` is false, runs the SAME teardown pair delete-sync uses.
The condition is load-bearing in both directions: releasing unconditionally
would drop this worker's holder bit and re-take it on a same-tuple refresh
(HA sync reconnect, periodic re-upsert), opening a window for another
worker's local allocation to steal the port.

#6211 F2: the synced entry is fanned out to EVERY worker while the allocator
is one shared `Arc`, so N workers reserve the same `(flow, translated)` and
each releases it independently. `LiveAllocation.holders` (a `u128` bitmask
keyed on `worker_id`) makes the release free the port only when the LAST
holder lets go — before it, the first worker to reap or delete-sync freed a
port the other N-1 were still forwarding through. Every release site in this
module therefore takes a `worker_id`, threaded from
`WorkerLaunchPlan::worker_id` through `apply_worker_commands` /
`resolve_flow_session_decision` / `delete_terminal_filtered_session`, and calls
the `_for_worker` entry points; the untracked twins are `#[cfg(test)]` so
missing the thread is a build failure.

`purge_translated_synced_hit` therefore ALSO releases that reservation —
`release_source_nat_allocation` + `release_nat64_allocation`, under the
same `metadata.is_reverse` ownership guard used everywhere the reservation
is freed (reap, delete-sync, terminal-filtered teardown). The guard and
`release_flow`'s track-then-free contract make this safe against a
double-free: the purge fires only for the forward translated side
(`is_translated_forward_session_key` rejects reverse/alias keys), and
`release_flow` is a no-op when the flow was never tracked. Before #5295
the purge dropped the session state but released NOTHING, LEAKING the
reserved port on every alias-owned transient purge → standby source-NAT /
NAT64 pool exhaustion under sustained HA churn. Distinct from #5178 (a
reservation released into a recycle queue the deterministic allocator
never drains) — here there was simply no release call at all.

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
| `mod.rs` | Cache-validation helpers (`cached_session_resolution`, `resolution_target_for_session`), plus the BPF session-map mirror writers. |
| `tests.rs` | Co-located unit tests for cache validation + mirror semantics. |

## Where it sits

- Called by the worker poll loop after `session::lookup` finds an
  existing session.
- Reads from `forwarding/` for resolution rebuild when the cache is
  stale.
- Writes to the BPF session map (via `coordinator/bpf_maps.rs` FDs)
  so the eBPF data-display surface mirrors the live userspace
  session table.

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

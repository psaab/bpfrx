# Codex plan-review r2 — task-mq91i26m-ke7g4c (verbatim verdict + findings)

PLAN-NEEDS-MAJOR

1. High — §2.3's "every locally-installed forward session is fanned out" claim has a concrete miss: `MissingNeighborSeed`.
poll_descriptor/mod.rs:2447 installs a forward session, :2452 marks it SessionOrigin::MissingNeighborSeed, :2466 publishes shared state, :2476 publishes the BPF session entry; the block reaches :2502 with no replicate_session_upsert (normal forward path replicates at :1325, reverse at :1549). Shared NAT publish is only a plain overwrite (shared_ops.rs:669/:671); the counter only increments on local nat_reverse_index.insert displacement (session/mod.rs:1399/:1402).
Concrete first-event miss: cold unresolved egress neighbor; two LAN source IPs bind the same source port to the same external dst:port; interface SNAT preserves the port (nat/source.rs:442/:447/:450); reverse_wire_key uses the original source port when no SNAT port rewrite exists (session/key.rs:89/:90). If the two first packets hit different workers before neighbor resolution, each worker installs only its own MissingNeighborSeed, no local displacement happens, shared state silently overwrites, and W1 never fires. Buffered packets still pass after resolution (neighbor_dispatch.rs:205/:207/:241/:266).

2. Medium — the "loser re-wins K on next refresh / every alternation counts" rationale is overstated.
update_session does reassert secondary indexes (session/mod.rs:928/:933), but ordinary local hits go through lookup_session_across_scopes and return the local lookup (shared_ops.rs:403/:413). Flow-cache hits only call sessions.touch every 64 hits (flow_cache_hit.rs:153/:156) and touch updates timestamps/wheel only (session/mod.rs:367/:372). So the absent-K window after value-guarded removal (session/mod.rs:1458/:1460) is not necessarily closed by loser traffic.

3. Medium — W2's preflight is not sufficient for attributability anymore. W2 proves warm-path behavior only; W needs either a shared-map displacement detector revived, or explicit MissingNeighborSeed replication/coverage plus a cold-neighbor live-fire case.

4. Low — W1's process-global CAS throttle and warn/help semantics are acceptable, but the cited pattern is wrong: bpf_map/mod.rs:867-880 are static atomics, not a CAS throttle. Use coordinator/mod.rs:768/:771 or wg/engine.rs:387/:389.

Path verdict: amended W remains plausible; K is only honest for a lab-only operator posture; A1 is still not justified. As written, W is not converged because the watch can miss a realistic first collision.

Codex session ID: 019eb517-65ac-7660-9018-d0bfa57c2cae

# PR #1882 — Claude SMR hostile code review (round 1)

Reviewer: Claude (domain SMR). Head reviewed: e387798fd97b; fix
commit 73f61b1db797 produced by this review.

## Required worked trace 1 — remove-middle-tunnel, both sides

Config {gr-0/0/0 (gre), wg0 (wireguard)}; commit removes gr-0/0/0.

1. Go: `buildTunnelEndpointSnapshots` builds {wg0.0}; id =
   `StableTunnelEndpointID("wg0.0")` = 16091 — identical to the
   pre-removal value (pure per-name function; live-verified: the
   deployed build showed `endpoint id 16091` before AND after the
   removal commit).
2. Rust: tunnel ifaces are excluded from the binding-plan key
   (`server/helpers.rs`), so the commit lands in
   `refresh_runtime_snapshot`. `populate_tunnel_endpoints` re-inserts
   wg0 at 16091; `populate_wg_engines` finds prev engine at 16091
   with an unchanged identity tuple → Arc reuse (live-verified:
   handshake counters 2/1 and transfer counters CONTINUOUS across
   the commit; zero wg-control journal lines).
3. `tunnel_remap_purge_ids(prev, next)` = [hash("gr-0/0/0.0")=44687]
   (absent in next). `purge_remapped_tunnel_sessions` scans the
   shared map and removes every session whose stored id is 44687 via
   `delete_synced_session` (shared maps + owner-RG indexes + kernel
   session map + worker DeleteSynced) + forward Close deltas via
   `push_delta_lossless` → Go shadow conntrack delete → cluster
   delete-sync.
4. Any in-flight gr-marked frame inside the apply window: encap build
   fails (`gre.rs` `tunnel_endpoints.get(...)?`) → R-C chokepoint
   drops + counts (`tunnel_encap_unresolved`); never the kernel TUN.

## Required worked trace 2 — HA config-sync timing variant

node0 commits the removal; node1 lags with both tunnels.

- wg0 session synced either direction during the window: FibGen
  carries 16091; both nodes' `sessionSyncTunnelEndpointLocked`
  resolve it to wg0 (same pure function, same surviving config row).
  NO drift — the defect's headline case is structurally gone.
- gr session synced node1→node0 during the window: node0's Go
  resolves 44687 against its post-removal `lastSnapshot` → not found
  → `EgressIfindex=0, OwnerRGID=0` → helper installs the synced copy
  as NoRoute (fail-safe; self-heals when node1 commits — and node1's
  own apply then runs ITS R-D purge for 44687).
- node1's own live gr sessions: purged by node1's R-D pass at ITS
  apply; Close deltas propagate per `daemon_ha_userspace.go:765` /
  `sync_conn.go:832`; standby-origin deltas are not resynced back
  (`daemon_ha_userspace.go:566`).

## Findings

**MAJOR (fixed in 73f61b1db797): R-D skipped reverse-only
tunnel-marked entries.** The v1 purge `continue`d on
`metadata.is_reverse`, assuming the forward entry's companion
removal covers them. In an asymmetric topology (client BEHIND the
tunnel) the REVERSE resolution is the tunnel-marked one while the
forward entry's id is not in the purge set — the reverse entry
dangled on the remapped id; under temporal reuse, reply traffic
would mis-encap into the new owner: the exact class R-D exists to
close. Fix: purge reverse entries as standalone removals; Close
deltas remain forward-only (matching `emit_close_delta_with_origin`
semantics).

**Checks that PASSED:**
- R-C chokepoint: all enumerated doors funnel through
  `maybe_reinject_slow_path_from_frame`; no caller invokes
  `slow_path.enqueue` directly outside it (grep-verified across
  src); gate sits after the `local_tunnel_deliveries` branch and
  before BOTH the unavailable accounting and the enqueue — the unit
  pins assert generic `slow_path_drops` stays 0, proving order.
- R-D lock discipline: the collect pass drops the `sessions.synced`
  guard at scope end BEFORE `delete_synced_session` re-locks — no
  self-deadlock; purge sets are computed BEFORE the forwarding swap
  in both apply paths.
- R-B union walk handles flat-set chains (gotcha-approved test
  path), hierarchical groups, and the merged-keys root-child shape;
  strict/lenient split mirrors the #1798/#1814 pattern and the
  lenient warning keeps upgraded nodes booting.
- Counter chain complete: BindingLiveState init + snapshot copy +
  refresh_bindings copy + reset sites + wire serde-default + Go
  mirror — byte-for-byte parallel to `slow_path_rate_limited`'s
  sites; fixture regen is the single additive line.
- WG cold start: `frame/wg.rs:104` handshake arming untouched; R-E
  exclusion leaves `trigger_kernel_arp_probe` firing (the gate is on
  the BUFFER, not the probe). XFRM/st0 traffic has
  `tunnel_endpoint_id == 0` and is untouched by every gate.
- No test weakened: the only relaxation during development was an
  over-pinned internal-routing assertion in the NEW R-E e2e test
  (disposition-arm counter), replaced by outcome assertions
  (never-buffered + counted drop) that hold through both doors.

## Verdict

MERGE-READY at 73f61b1db797 (the MAJOR found by this review is fixed
and pushed; no further findings).

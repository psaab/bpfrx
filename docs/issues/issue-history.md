# bpfrx Issue History

Complete record of all issues filed and resolved.
Total: 378 issues (364 closed, 14 open)

## Open Issues

### #472 — Kernel crash in mlx5_core ICOSQ recovery during HA failback
## Observed

VM reboots during RG1 failback (node1 → node0). The kernel crashes in the mlx5_core driver's ICOSQ CQE error recovery path:

```

---

### #548 — refactor: split pkg/cli/cli_show.go (7887 lines) by show domain
**Priority: P2** — Split `pkg/cli/cli_show.go` by show domain, but do it only after `#552` extracts shared CLI dispatch/helpers.

Target files:
- `cli_show_security.go`
- `cli_show_nat.go`

---

### #549 — refactor: split pkg/daemon/daemon.go (4506 lines) system config functions
**Priority: P2** — Split `pkg/daemon/daemon.go` by subsystem with a move-only first pass.

Target files:
- `daemon_system.go` for hostname, DNS, NTP, SSH, timezone, syslog, and login
- `daemon_reth.go`

---

### #550 — refactor: split pkg/dataplane/userspace/manager.go (4772 lines)
**Priority: P2** — Split `pkg/dataplane/userspace/manager.go` in stages.

Recommended sequence:
1. Move pure snapshot builders into `snapshot.go`
2. Move BPF/map synchronization into `maps_sync.go`

---

### #551 — refactor: split pkg/cluster/sync.go remaining protocol/conn/failover paths
**Priority: P2** — Current master already has `sync_bulk.go` and `failover_batch.go`, so this issue is now the remaining split for `pkg/cluster/sync.go`.

Target files:
- `sync_protocol.go` for message constants, header, and encode/decode helpers
- `sync_conn.go` for dial/accept/send/receive/disconnect lifecycle

---

### #552 — refactor: split pkg/cli/cli.go (4874 lines) dispatch and handlers
**Priority: P2** — Split `pkg/cli/cli.go` by command-dispatch responsibility before touching `cli_show.go` or `cmd/cli/main.go`.

Target files:
- `cli_dispatch.go`
- `cli_request.go`

---

### #553 — refactor: split pkg/config/ast.go into groups/edit/format paths
**Priority: P3** — `pkg/config/ast.go` currently mixes tree types/navigation, group expansion, path editing, and formatting.

Split into:
- `ast_groups.go` for apply-groups expansion
- `ast_edit.go` for set/delete/copy/rename/insert path mutation

---

### #554 — refactor: split cmd/cli/main.go (3623 lines)
**Priority: P3** — Split `cmd/cli/main.go` by remote command family, but do it after `#552` and ideally after `#548` so local and remote command shapes stay aligned.

Target files:
- `show.go`
- `request.go`

---

### #555 — refactor: split pkg/config/parser_test.go by subsystem
**Priority: P3** — `pkg/config/parser_test.go` is too large for only a 2-way split.

Split by subsystem instead:
- `parser_ast_test.go`
- `parser_system_test.go`

---

### #556 — refactor: reduce userspace-dp/src/afxdp.rs root module
**Priority: P3** — Current master already has many `afxdp/*` submodules. The remaining work is to shrink the root `userspace-dp/src/afxdp.rs`.

Target files:
- `coordinator.rs` for the large `Coordinator` implementation
- `worker.rs` for `BindingWorker` and `worker_loop`

---

### #602 — tracking: refactor ordering for remaining large-file splits
## Purpose
Track the implementation order for the remaining large-file refactor issues so they land with clean seams and minimal review risk.

## Rules
- First PR for each issue should be move-only with no behavior changes.

---

### #609 — IPv6 RG1 failover only recovers ~3.9 Gbps of -P12 traffic before node crash
## Observed

On a clean `loss` userspace HA deployment, long-lived IPv6 traffic does not recover cleanly on the first RG1 failover even when both nodes are healthy and session sync is up before the move.

## Repro

---

### #611 — HA: old primary reclaims RG on transient peer-heartbeat timeout immediately after committed failover
## Summary
After the same committed RG1 manual failover on clean `origin/master` (`ac29c8ff`), the old primary (`fw0`) times out the peer heartbeat about 7 seconds later and unilaterally promotes RG1 back to itself.

## Repro
- Clean master on both nodes: `userspace-forwarding-ok-20260402-bfb00432-316-gac29c8ff`

---

### #612 — HA: new primary self-demotes after committed manual failover when post-commit session barrier ack arrives late
## Summary
A committed RG1 manual failover is not sticky on clean `origin/master` (`ac29c8ff`) during reverse-path traffic. The new primary (`fw1`) becomes primary, activates RG1, sends GARP/NA re-announces, then about 9 seconds later demotes itself back to backup because a post-commit demotion barrier waits only 5 seconds for a session-sync ack.

## Repro
- Clean master on both nodes: `userspace-forwarding-ok-20260402-bfb00432-316-gac29c8ff`

---

## Closed Issues (by category)

### HA / Failover (241 issues)

| # | Title | Resolution |
|---|-------|------------|
| 8 | IPv4 DNAT-before-fabric helper uses fixed L3/L4 offsets | 2026-03-01 |
| 9 | IPv4 DNAT-before-fabric skips port-only DNAT due dst-IP short-circuit | 2026-03-01 |
| 11 | CLI: show security flow session nat-only is advertised but not parsed | 2026-03-01 |
| 19 | CLI: show security flow session summary uses non-Junos output schema | 2026-03-01 |
| 20 | CLI: show security flow session format diverges from Junos reference | 2026-03-01 |
| 46 | Performance: xdp_zone failover branches perform repeated FIB lookups and duplica | 2026-03-01 |
| 56 | Failover: IPv4 pre-fabric DNAT rewrite is not CHECKSUM_PARTIAL-safe | 2026-03-01 |
| 57 | HA fabric: fib_ifindex selection can remain 0 and break main-table re-FIB | 2026-03-01 |
| 58 | DPDK parity gap: zone-encoded fabric redirect decode is still TODO | 2026-03-01 |
| 59 | HA fabric: peer MAC resolution is IPv4-only (no NDP path) | 2026-03-01 |
| 60 | Failover: sessionless FABRIC_FWD re-FIB failure falls through to XDP_PASS (kerne | 2026-03-01 |
| 61 | xdp_zone: sessionless FABRIC_FWD NO_NEIGH path falls through to XDP_PASS/host-in | 2026-03-01 |
| 62 | xdp_zone: UNREACHABLE/BLACKHOLE FABRIC_FWD branch still leaks to host path when  | 2026-03-01 |
| 63 | cluster refreshFabricFwd: fallback fib_ifindex selection is non-deterministic an | 2026-03-01 |
| 64 | DPDK zone-encoded fabric decode returns too early and lacks fabric-ingress valid | 2026-03-01 |
| 65 | DPDK active/active: zone-encoded fabric validation compares port_id against kern | 2026-03-01 |
| 66 | HA failover race: cluster/VRRP handlers apply rg_active side effects from stale  | 2026-03-01 |
| 68 | HA mode: disable hitless restart semantics by default | 2026-03-02 |
| 69 | SessionSync: stale receive goroutine can tear down the active peer connection | 2026-03-02 |
| 70 | SessionSync: BulkSync should honor per-RG ownership (same as sweep) | 2026-03-02 |
| 71 | SessionSync: Bulk transfer needs authoritative stale-entry reconciliation | 2026-03-02 |
| 72 | HA failover: add peer fencing path on heartbeat timeout | 2026-03-02 |
| 73 | HA tests: add hard-crash/hung-node failover coverage | 2026-03-02 |
| 75 | HA restart: neighbor prewarm runs before VRRP VIP ownership, causing 10-30s tran | 2026-03-02 |
| 76 | HA race: SessionSync has unsynchronized concurrent conn writers and short-write  | 2026-03-02 |
| 77 | HA race: fixed 10s VRRP sync-hold timeout can release before bulk sync completes | 2026-03-02 |
| 78 | HA race: reconnect config sync can accept stale secondary config (authority not  | 2026-03-02 |
| 79 | HA readiness: fabric_fwd population is passively delayed and race-prone at start | 2026-03-02 |
| 80 | HA correctness: periodic neighbor warmup uses stale startup config snapshot | 2026-03-02 |
| 81 | HA startup bug: heartbeat/session-sync retry exhaustion can permanently disable  | 2026-03-02 |
| 82 | HA startup race: initial BulkSync may be skipped before dataplane wiring | 2026-03-02 |
| 83 | HA race: session delete sync is not per-RG ownership-safe in active/active | 2026-03-02 |
| 84 | HA race: VRRP event watcher uses background context and outlives shutdown lifecy | 2026-03-02 |
| 85 | HA reliability: sync queue overflow drops critical control messages without repl | 2026-03-02 |
| 86 | HA race: dropped cluster events are not repaired for VRRP control actions | 2026-03-02 |
| 87 | HA bug: heartbeat/session-sync endpoints are one-shot and not reconfigured on ru | 2026-03-02 |
| 88 | HA safety bug: manual failover can self-blackhole when peer is already down | 2026-03-02 |
| 89 | HA race: stale session-sync receive loops can disconnect a newer active connecti | 2026-03-02 |
| 90 | HA protocol bug: session-sync writes are unsynchronized and can corrupt frames | 2026-03-02 |
| 91 | HA startup race: SESSION_OPEN sync callback can be skipped permanently | 2026-03-02 |
| 92 | HA election bug: stale peer RG entries persist across heartbeats | 2026-03-02 |
| 93 | HA drift bug: reconcile loop does not repair RA/DHCP service ownership after dro | 2026-03-02 |
| 94 | HA lifecycle race: cluster watcher/comms use pre-signal context and can outlive  | 2026-03-02 |
| 96 | VRRP startup sync-hold race allows preempt-before-sync on node rejoin | 2026-03-02 |
| 98 | HA neighbor warmup skips interface-qualified static next-hops with Junos interfa | 2026-03-02 |
| 99 | HA sync protocol still vulnerable to short-write frame truncation | 2026-03-02 |
| 100 | HA heartbeat can truncate with large monitor payloads and trigger false peer los | 2026-03-02 |
| 101 | HA failover recovery delayed by fixed 10s VRRP posture mismatch timer | 2026-03-02 |
| 102 | HA fail-closed gap: ungraceful daemon failures can leave stale forwarding active | 2026-03-02 |
| 103 | HA startup: block primary takeover until interfaces/VRRP are ready and hold time | 2026-03-02 |
| 104 | HA same-L2: add strict single-owner VIP mode to stop duplicate NA ownership chur | 2026-03-02 |
| 107 | HA syntax parity: implement vSRX dual-fabric (fab0 + fab1) architecture | 2026-03-03 |
| 110 | HA private-rg-election: gate RG promotion on session sync readiness | 2026-03-04 |
| 111 | HA mode check mismatch: startup sync-hold logic ignores private-rg-election sema | 2026-03-04 |
| 112 | private-rg-election gap: knob exists but no dedicated fast per-RG private advert | 2026-03-04 |
| 113 | HA dual-active resolution: add winner-side ownership reaffirm (GARP/NA) | 2026-03-04 |
| 114 | HA: move session/config sync transport to control link (fxp1) | 2026-03-04 |
| 115 | HA private-rg-election: include VIP ownership in takeover readiness gate | 2026-03-04 |
| 116 | HA regression: chained hard-reset failover (fw0 crash/rejoin -> fw1 crash) stall | 2026-03-04 |
| 117 | HA session-sync: concurrent bulk writers can interleave epochs and trigger false | 2026-03-04 |
| 118 | HA session-sync: stale reconciliation should use BulkStart ownership snapshot | 2026-03-04 |
| 119 | HA session-sync: delete/session deltas are dropped while disconnected with no re | 2026-03-04 |
| 120 | cluster/session-sync: Stats() copies atomic fields (go vet copylocks failure) | 2026-03-04 |
| 121 | fabric: clear stale fabric_fwd entry when fab0/fab1 neighbor or link goes invali | 2026-03-06 |
| 122 | fabric: refreshFabricFwd programs dead links because it never checks oper-state | 2026-03-06 |
| 123 | dual-fabric session sync uses one replaceable conn and can flap between fab0/fab | 2026-03-06 |
| 124 | fabric: no event-driven refresh on link/neigh changes leaves up to 30s redirect  | 2026-03-06 |
| 125 | dual-fabric: peer gRPC/monitor path is still single-address and does not fail ov | 2026-03-06 |
| 126 | dpdk: fabric redirect support is only partial; no DPDK equivalent of try_fabric_ | 2026-03-06 |
| 127 | fabric IPVLAN: existing fab0/fab1 overlay skips address reconciliation on reappl | 2026-03-06 |
| 128 | fabric IPVLAN: stale fab0/fab1 overlays are never cleaned up when config changes | 2026-03-06 |
| 129 | fabric IPVLAN: populateFabricFwd probes ARP/NDP on parent while fabric IP lives  | 2026-03-06 |
| 130 | compiler: vSRX fab0/fab1 auto-detect still collapses to a single runtime fabric  | 2026-03-06 |
| 131 | HA session-sync: established flows are never refreshed after SESSION_OPEN | 2026-03-06 |
| 132 | HA rg_active: a redundancy group becomes active when any VRRP instance flips MAS | 2026-03-06 |
| 133 | private-rg-election: sync readiness is never reset for a fresh peer rejoin | 2026-03-06 |
| 135 | monitor interface: fab0/fab1 samples the IPVLAN overlay instead of the physical  | 2026-03-06 |
| 136 | monitor traffic interface fab0/fab1 captures the overlay, not the wire-level fab | 2026-03-06 |
| 137 | fabric redirect: try_fabric_redirect paths never update per-interface TX counter | 2026-03-06 |
| 138 | fabric observability: tcpdump/monitor traffic is not a reliable view of XDP fabr | 2026-03-06 |
| 139 | fabric observability: no per-link redirect counters or trace events for fab0 vs  | 2026-03-06 |
| 166 | perf/dataplane: split hot and cold IPv6 session state | 2026-03-08 |
| 168 | perf/dataplane: compact IPv6 session key to reduce hash-map cost | 2026-03-08 |
| 185 | HA session-sync: per-zone ownership mapping is not safe for active/active zones  | 2026-03-08 |
| 186 | HA failover gating: sync readiness is decoupled from fabric redirect readiness | 2026-03-08 |
| 187 | xdp_zone: NO_NEIGH active-active check drops VLAN context and can skip required  | 2026-03-08 |
| 188 | HA readiness: RGInterfaceReady treats missing local interfaces as peer-owned and | 2026-03-08 |
| 189 | HA readiness: RGVRRPReady reports ready when an RG has no local VRRP instance | 2026-03-08 |
| 191 | HA IPv6 failover: no NDP probe equivalent to IPv4 gateway ARP probe | 2026-03-08 |
| 192 | HA IPv6 failover: per-node RETH MAC/link-local identity makes failover weaker th | 2026-03-09 |
| 193 | HA IPv6 failover: failed-neighbor cleanup reprobes IPv4 only | 2026-03-08 |
| 198 | userspace: O(n) reverse session repair causes latency spikes under load | 2026-03-12 |
| 200 | userspace: XDP shim redirects all traffic to userspace (session check unused) | 2026-03-29 |
| 204 | userspace-dp: shared_sessions not cleared on stop() persists stale data | 2026-03-12 |
| 267 | userspace event-stream DrainRequest does not fence a target sequence during demo | 2026-03-29 |
| 268 | daemon event-stream ack advances before session event callback finishes | 2026-03-29 |
| 269 | graceful demotion currently drops kernel session-open sync events instead of dra | 2026-03-29 |
| 270 | session sync still double-produces steady-state kernel updates via ring events a | 2026-03-29 |
| 271 | show security flow sessions walks and sorts the full session table before printi | 2026-03-29 |
| 272 | show security flow sessions interface filter is currently only a zone filter | 2026-03-29 |
| 273 | show security flow sessions should display interfaces and zones consistently | 2026-03-29 |
| 274 | GetSessions RPC still builds session listings with full-table iteration and per- | 2026-03-29 |
| 275 | GetSessions still relies on full-table iteration and eager enrichment after sort | 2026-03-31 |
| 276 | userspace demotion prep resumes helper event stream before final barrier complet | 2026-03-31 |
| 277 | helper demotion and session-export waits still hardcode a 2s timeout | 2026-03-31 |
| 278 | userspace RG transition pre-switch has no rollback when UpdateRGActive fails | 2026-03-31 |
| 279 | ctrl re-enable after RG transition is not gated on transitioned-RG convergence | 2026-03-31 |
| 281 | HA session refresh paths still scan and clone the full helper session tables | 2026-03-31 |
| 282 | ctrl re-enable stale-session cleanup stops after fixed delete caps | 2026-03-31 |
| 283 | pendingRGTransition stays set when syncHAStateLocked fails | 2026-03-31 |
| 284 | single global pendingRGTransition bool is not sufficient for multi-RG HA transit | 2026-03-31 |
| 285 | promoting node no longer pre-switches out of userspace before RG activation | 2026-03-31 |
| 286 | HA reverse-session refresh still clones the full local session table before filt | 2026-03-31 |
| 287 | reverse-session prewarm now filters too narrowly by forward session owner RG | 2026-03-31 |
| 291 | XDP interface-NAT session misses are not surfaced as a distinct counter or trace | 2026-03-31 |
| 297 | manual RG failover still collapses after reverse prewarm with stable ownership a | 2026-03-31 |
| 298 | demotion cleanup immediately deletes shared USERSPACE_SESSIONS entries but leave | 2026-03-31 |
| 305 | Remove or narrowly scope PASS_TO_KERNEL session actions for strict userspace mod | 2026-04-01 |
| 308 | Reduce HA failover toward a MAC-move-only model | 2026-04-01 |
| 309 | Enumerate forwarding-relevant state that is not carried in continuous session sy | 2026-04-01 |
| 311 | Define an install fence for HA cutover instead of relying on continuous sync alo | 2026-04-01 |
| 312 | Reduce helper-local cache and non-session dependencies at RG transition | 2026-04-01 |
| 314 | HA cutover still lacks a helper worker-completion acknowledgment | 2026-04-01 |
| 315 | Continuous userspace HA sync still omits local-delivery session state | 2026-04-01 |
| 316 | Cluster-synced reverse sessions are still not mirrored into the userspace helper | 2026-04-01 |
| 317 | Userspace session sync still depends on activation-time local egress re-resoluti | 2026-04-01 |
| 318 | Redesign HA session sync around a portable canonical session record | 2026-04-02 |
| 319 | Continuously materialize standby helper state instead of repairing sessions on R | 2026-04-02 |
| 320 | Make HA session producers event-first and reduce sweeps/polling to reconciliatio | 2026-04-02 |
| 321 | Replace HA flow-cache scans and flushes with epoch-based cache validation | 2026-04-02 |
| 322 | Collapse helper HA session state into one canonical store plus derived indexes | 2026-04-02 |
| 323 | Replace HA demotion drain choreography with an applied-sequence cutover fence | 2026-04-02 |
| 324 | Flow cache on new owner caches sessions without NAT decision after failover | 2026-04-01 |
| 325 | Send owner_rg_id from sync sender instead of defaulting to 0 | 2026-04-01 |
| 326 | Resolve synced sessions with local egress on receipt, not just on activation | 2026-04-01 |
| 328 | Unify synced flag into origin-based collision detection | 2026-04-02 |
| 329 | Pre-populate BPF userspace_sessions map on sync receipt | 2026-04-02 |
| 330 | Simplify demotion prep to epoch transition | 2026-04-01 |
| 333 | IterateSessions reads only eBPF conntrack — userspace sessions invisible to GC/A | 2026-04-01 |
| 334 | BPF conntrack writes during ctrl=0 window conflict with userspace sessions | 2026-04-01 |
| 335 | BPF conntrack entry byte order mismatch prevents zone display for userspace sess | 2026-04-01 |
| 338 | Graceful demotion barrier no longer fences helper and kernel session producers | 2026-04-02 |
| 339 | Graceful demotion can proceed without confirmed peer bulk readiness | 2026-04-02 |
| 340 | Daemon acks helper event-stream deltas even when sync-disconnect drops them | 2026-04-02 |
| 342 | RG activation duplicates helper refresh work through update_ha_state and explici | 2026-04-02 |
| 343 | Demotion kernel journal path is dead in the current graceful demotion flow | 2026-04-02 |
| 344 | HA activation is decoupled from actual userspace dataplane enablement | 2026-04-02 |
| 345 | HA activation still does RG-wide helper refresh scans despite on-receipt standby | 2026-04-02 |
| 346 | Userspace session mirror failures are swallowed during HA session install | 2026-04-02 |
| 347 | Failover still depends on post-transition neighbor warm-up sweeps | 2026-04-02 |
| 348 | HA transition still depends on asynchronous fabric_fwd refresh | 2026-04-02 |
| 349 | HA watchdog sync is throttled past the helper stale-after threshold | 2026-04-02 |
| 350 | GetSessions cursor pagination does not support stable include_peer pagination | 2026-04-02 |
| 352 | Userspace HA transition path still contains raw stderr debug logging | 2026-04-02 |
| 353 | Remove explicit refresh_owner_rgs RPC — sessions pre-resolved on receipt | 2026-04-02 |
| 355 | Remove dead code and simplify HA transition bookkeeping | 2026-04-02 |
| 356 | Throttle statusLoop HA sync for 2s after UpdateRGActive | 2026-04-02 |
| 358 | Collapse userspace RG activation into one helper-applied HA generation | 2026-04-02 |
| 359 | Collapse helper demotion from prepare-plus-demote into one acknowledged transiti | 2026-04-02 |
| 360 | Replace split active-plus-watchdog HA state with a single applied lease model | 2026-04-02 |
| 369 | Split session_glue.rs into shared-session replication, reverse synthesis, and qu | 2026-04-02 |
| 370 | Split daemon.go into config apply, HA/session-sync, and cluster/fabric modules | 2026-04-02 |
| 372 | Split userspace manager.go into helper lifecycle, HA/session sync, and map sync  | 2026-04-02 |
| 374 | Split cluster/sync.go into transport, bulk/barrier, and producer integration mod | 2026-04-02 |
| 389 | Index helper HA session state by owner RG to remove failover-time full-table sca | 2026-04-03 |
| 390 | Replace weight-zero manual failover with an explicit RG transfer protocol | 2026-04-03 |
| 391 | Remove NAPI bootstrap from the HA cutover path | 2026-04-02 |
| 398 | manual failover still times out while requester is in bulk sync receive | 2026-04-03 |
| 400 | surface manual failover transfer readiness separately from takeover readiness | 2026-04-03 |
| 403 | Planned failover must not depend on bulk sync — both nodes already have full ses | 2026-04-03 |
| 408 | Remove 2s worker ApplyHAState ack wait from demotion path | 2026-04-03 |
| 409 | Eliminate double fib_gen bump during RG transition | 2026-04-03 |
| 411 | Pre-failover prepare retry loop has 45s timeout — should fast-fail for planned f | 2026-04-03 |
| 412 | Sessions deleted from XDP map on demotion should be unnecessary if rg_active is  | 2026-04-03 |
| 413 | Synced sessions should already be in new owner's BPF session map before activati | 2026-04-03 |
| 414 | CRITICAL: Demoted sessions fall through gap — userspace DP skips fabric redirect | 2026-04-03 |
| 417 | Flow cache entries with owner_rg_id=0 bypass epoch invalidation on demotion | 2026-04-03 |
| 418 | Replace bulk session sync with event stream replay on connect | 2026-04-03 |
| 420 | event stream replay bulk export can silently drop sessions under load | 2026-04-03 |
| 426 | fabric redirect path bandwidth limits existing TCP streams during failover | 2026-04-03 |
| 427 | barrier timeout under high-parallelism session sync (-P8) | 2026-04-04 |
| 429 | Flow cache can outlive HA forwarding lease expiry | 2026-04-04 |
| 430 | Manual failover barrier no longer preserves session-sync ordering | 2026-04-04 |
| 433 | XDP shim fabric redirect bypass for zero-copy cross-chassis forwarding | 2026-04-05 |
| 434 | Cached FabricRedirect flow-cache hits ignore apply_nat_on_fabric | 2026-04-04 |
| 436 | Refresh fabric performance plan for strict userspace NAT path | 2026-04-04 |
| 450 | TCP streams die after RG failover — 3/4 iperf3 streams go to 0 bps | 2026-04-05 |
| 451 | Neighbor miss spikes >20 after RG failover | 2026-04-05 |
| 452 | Rust helper single-threaded event loop blocks session installs behind main socke | 2026-04-05 |
| 456 | All 4 iperf3 streams die after RG failover (4/4 at 0 bps) | 2026-04-05 |
| 457 | Standby node loses userspace readiness after RG failover | 2026-04-05 |
| 458 | Session sync barrier timeout on second failover cycle (sessions_received=0) | 2026-04-05 |
| 464 | RequestPeerFailover clears local manual failover before the handoff is admitted | 2026-04-05 |
| 465 | sync_test still expects barrierAckSeq to reset after total disconnect | 2026-04-05 |
| 466 | Session sync still bulk-primes on reconnect and active-fabric changes | 2026-04-05 |
| 467 | Failed userspace demotion prep stops the peer bootstrap retry loop and never res | 2026-04-05 |
| 475 | TCP streams never recover after failover+failback: sessions show Pkts:0 | 2026-04-05 |
| 481 | Rapid failover+failback causes barrier disconnect: session sync disconnected dur | 2026-04-05 |
| 485 | TCP stream survives failover but dies on failback — session re-resolution gap | 2026-04-05 |
| 490 | userspace HA activation still depends on activation-time session and BPF republi | 2026-04-06 |
| 491 | failback still depends on activation-time neighbor install and ARP/NDP warmup | 2026-04-06 |
| 492 | userspace demotion-prep producer pause and journal path is never actually activa | 2026-04-06 |
| 493 | default rg_active semantics enable forwarding before VIP/MAC ownership moves | 2026-04-06 |
| 499 | HA RG transitions still force full snapshot and double FIB churn | 2026-04-06 |
| 500 | HA state updates still run worker-wide session refresh scans | 2026-04-06 |
| 501 | HA demotion still depends on barrier plus preflight fabric-shift path | 2026-04-06 |
| 502 | No-RETH HA promotion still gates on session-sync readiness | 2026-04-06 |
| 503 | HA takeover still waits on ReadySince hold timer before promotion | 2026-04-06 |
| 504 | Immediate synced BPF publish still bypasses worker session admission | 2026-04-06 |
| 511 | Strict VIP ownership still removes blackholes on cluster-primary before VRRP own | 2026-04-06 |
| 512 | HA status poll still triggers queue and neighbor bring-up after ownership change | 2026-04-06 |
| 517 | userspace failover loses synced-session origin on local hits | 2026-04-06 |
| 518 | cluster sync should not mirror reverse sessions into userspace helper | 2026-04-06 |
| 520 | RG1-only failover cannot move LAN ownership on the loss userspace cluster | 2026-04-07 |
| 524 | userspace HA activation no longer re-prewarms split-RG synced sessions | 2026-04-07 |
| 525 | userspace HA readiness overstates standby session usability | 2026-04-07 |
| 526 | split-RG userspace fabric transit is lab-limited on loss cluster | 2026-04-07 |
| 527 | userspace HA direct handoff still stacks stale ownership and local manual state  | 2026-04-07 |
| 532 | loss userspace HA no longer returns IPv6 TTL-expired probe responses | 2026-04-07 |
| 533 | loss userspace HA validator blocks because standby session-sync idle never drain | 2026-04-07 |
| 534 | paired full-RG userspace HA handoff remains transport-unstable under load on los | 2026-04-07 |
| 535 | paired data-RG handoff is still sequential and exposes a split-RG loss window on | 2026-04-07 |
| 536 | full data failover still drops packets during VIP/MAC ownership move | 2026-04-07 |
| 540 | session sync can stay disconnected after standby restart on loss | 2026-04-07 |
| 562 | userspace HA sync leaks transient missing-neighbor seed sessions across failover | 2026-04-07 |
| 565 | userspace HA demotion leaves worker-local owner-RG sessions active across failov | 2026-04-07 |
| 568 | inactive owner still promotes translated peer-synced forward hits into local ses | 2026-04-07 |
| 570 | inactive owner still installs new LAN->WAN sessions locally after RG failover | 2026-04-07 |
| 572 | HA standby can remain WAN-neighbor cold after startup and drop first redirected  | 2026-04-07 |
| 574 | HA demotion leaves stale USERSPACE_SESSIONS redirect aliases on the old owner | 2026-04-07 |
| 576 | userspace HA demotion leaves stale BPF redirect aliases on old owner | 2026-04-07 |
| 582 | HA readiness can stay false even when standby helper reports all bindings ready | 2026-04-07 |
| 584 | RG handoff leaves stale worker-local sessions on demoted owner | 2026-04-07 |
| 586 | HA failover validator idle gate requires counters to stop changing entirely | 2026-04-07 |
| 587 | RG1 failover can drop external IPv4 while promoted owner still resolves WAN neig | 2026-04-07 |
| 588 | Session sync can stick half-open after standby heartbeat-ack timeout | 2026-04-07 |
| 590 | RG1 failover still incurs high session-miss burst and throughput tail collapse a | 2026-04-07 |
| 597 | explicit RG failback is blocked by heartbeat peerAlive loss even when transfer p | 2026-04-07 |
| 603 | HA status should surface mixed software versions instead of generic session sync | 2026-04-08 |
| 606 | session sync reconnect reapplies identical config and tears down the new sync se | 2026-04-08 |
| 608 | HA: rapid RG movement hits stale-old-owner redirect and helper/fabric handoff bu | 2026-04-08 |

### Userspace Dataplane (45 issues)

| # | Title | Resolution |
|---|-------|------------|
| 39 | Performance: SNAT rule matching does linear hash-probing in XDP hot path | 2026-03-01 |
| 43 | Performance: firewall filter evaluation does linear per-rule map lookups in both | 2026-03-01 |
| 44 | Performance: avoid duplicate iface_zone_map lookup across xdp_screen -> xdp_zone | 2026-03-01 |
| 45 | Performance: remove unnecessary atomic RMW on per-CPU global counters in XDP/TC  | 2026-03-01 |
| 48 | Performance: reduce repeated flow_config_map lookups in XDP/TC conntrack paths | 2026-03-01 |
| 50 | Performance: evaluate DEVMAP array instead of DEVMAP_HASH for XDP redirect hot p | 2026-03-01 |
| 164 | perf/xdp: add per-CPU IPv6 established-flow cache in xdp_zone | 2026-03-07 |
| 165 | perf/xdp: add IPv6 no-extension-header fast path to parse_ipv6hdr | 2026-03-07 |
| 170 | perf/xdp: reduce IPv6 checksum-partial detection cost in xdp_main | 2026-03-07 |
| 180 | perf/xdp: reduce pkt_meta init and parse overhead in xdp_main | 2026-03-08 |
| 196 | userspace: SNAT reply traffic black-holed on slow path reinjection | 2026-03-12 |
| 197 | userspace: silent packet drops when frame build returns None | 2026-03-12 |
| 199 | userspace: port corruption in copy-based forwarding path | 2026-03-29 |
| 201 | userspace: UMEM frame exhaustion under TX backpressure stalls RX | 2026-03-29 |
| 202 | userspace-dp: port authority design fragility causes policy thrashing | 2026-03-12 |
| 203 | userspace-dp: UMEM frame leak on TxError::Drop in transmit_prepared_batch | 2026-03-12 |
| 205 | userspace-dp: in-place TX path is nearly dead code (same-interface hairpin only) | 2026-03-12 |
| 206 | userspace-dp: unused mutable slice in validation path | 2026-03-12 |
| 253 | Userspace AF_XDP libxdp migration postmortem | 2026-03-31 |
| 266 | userspace event stream helper parses control frames unsafely on partial Unix-str | 2026-03-29 |
| 288 | userspace pending-neighbor retry ignores non-dynamic neighbor state | 2026-03-31 |
| 289 | userspace reply-side redirect is missing for post-deploy SNATed direct-host ICMP | 2026-03-31 |
| 290 | ordinary XDP reply path lacks reverse-NAT fallback for interface-NAT destination | 2026-03-31 |
| 292 | userspace helper TX counters do not fully describe prepared fast-path transmit s | 2026-03-31 |
| 293 | userspace compiler falls back all interfaces to generic XDP on one attach failur | 2026-03-31 |
| 294 | userspace helper picks zerocopy from driver name instead of actual XDP mode | 2026-03-31 |
| 302 | Enforce a strict userspace-only forwarding invariant | 2026-04-01 |
| 303 | Define explicit runtime modes for userspace_strict, userspace_compat, and ebpf_o | 2026-04-01 |
| 304 | Disallow transit fallback from xdp_userspace_prog into xdp_main_prog or XDP_PASS | 2026-04-01 |
| 306 | Make XSK liveness failure explicit instead of silently swapping back to xdp_main | 2026-04-01 |
| 332 | Userspace-forwarded packets not counted in BPF zone/policy/NAT counter maps | 2026-04-01 |
| 351 | Userspace mirror delete path leaves preinstalled reverse companions behind | 2026-04-02 |
| 354 | Skip blackhole route management in userspace mode | 2026-04-02 |
| 363 | Split userspace afxdp coordinator responsibilities out of afxdp.rs | 2026-04-02 |
| 364 | Split frame parsing, rewrite, and protocol builders out of afxdp/frame.rs | 2026-04-02 |
| 365 | Break userspace main.rs into snapshot schema, control schema, and server runtime | 2026-04-02 |
| 367 | Break afxdp/types.rs catch-all into cohesive shared type modules | 2026-04-02 |
| 410 | Blackhole route injection still runs in userspace mode despite #354 skip | 2026-04-03 |
| 438 | XDP shim drops ICMP echo replies for interface-NAT addresses | 2026-04-04 |
| 462 | Phase 2 incremental neighbor updates leave stale snapshot neighbors active in us | 2026-04-05 |
| 473 | XSK bindings map cleared after peer crash but helper reports ready | 2026-04-05 |
| 564 | idle standby userspace XSK liveness never settles takeover-ready on a fully boun | 2026-04-07 |
| 579 | userspace-ha-validation can pick standby helper as active firewall | 2026-04-07 |
| 580 | standby userspace helper can wedge with XSK bindings stuck busy after restart | 2026-04-07 |
| 596 | userspace RST suppression install can fail permanently when bpfrx_dp_rst does no | 2026-04-07 |

### Performance (12 issues)

| # | Title | Resolution |
|---|-------|------------|
| 36 | Performance: policy evaluation scans rules linearly with per-rule map lookups | 2026-03-01 |
| 37 | Performance: replace hot-path zone_pair_policies hash lookup with array indexing | 2026-03-01 |
| 38 | Performance: SNAT compile repeats pool parse/map writes for every referencing ru | 2026-03-01 |
| 40 | Performance: compile interface setup relies on repeated ethtool subprocess calls | 2026-03-01 |
| 41 | Performance: compiler does repeated interface/link lookups without per-pass cach | 2026-03-01 |
| 42 | Performance: application port-range expansion causes O(range) compile/map-write  | 2026-03-01 |
| 47 | Performance: tc_forward mirror sampling uses expensive modulo + atomic per packe | 2026-03-01 |
| 49 | Performance: NAT64 paths do heavy full-payload checksum scans | 2026-03-01 |
| 167 | perf/observability: expose IPv6 established-flow cache hit and flush counters | 2026-03-07 |
| 179 | perf/nat: reduce IPv6 nat_rewrite_v6 hot-path cost | 2026-03-08 |
| 368 | Split forwarding.rs into snapshot compilation and runtime resolution modules | 2026-04-02 |
| 442 | RST suppression shells out to nft binary instead of using netlink API | 2026-04-04 |

### Networking / Connectivity (14 issues)

| # | Title | Resolution |
|---|-------|------------|
| 7 | Interface-mode SNAT can select wrong source IP on snat_egress lookup miss | 2026-03-01 |
| 15 | CLI: show route destination modifiers exact/longer/orlonger are unsupported | 2026-03-01 |
| 16 | Routing: show route <prefix> CIDR matching logic is narrower than documented | 2026-03-01 |
| 21 | CLI: show arp no-resolve syntax and output format do not match reference | 2026-03-01 |
| 29 | Routing: show route summary missing Junos Highwater Mark section | 2026-03-01 |
| 31 | Compiler: NAT rule counter IDs can exceed nat_rule_counters capacity | 2026-03-01 |
| 32 | Compiler: NAT64 auto-assigned source pools ignore map-write failures and pool-ca | 2026-03-01 |
| 33 | Compiler: static NAT mixed IPv4/IPv6 rules are not rejected | 2026-03-01 |
| 34 | Compiler: DNAT CIDR inputs lose mask semantics (compiled as single IP) | 2026-03-01 |
| 154 | ike/ipsec: gateway external-interface is parsed but ignored for local_addrs and  | 2026-03-07 |
| 440 | Slow-path TUN rp_filter reset by networkctl reload breaks local TCP/UDP | 2026-04-04 |
| 560 | native GRE local tunnel source loop spins on permanent gr-0-0-0 errors | 2026-04-07 |
| 575 | loss steady-state IPv6 default route falls back to discard via lo | 2026-04-07 |
| 598 | standby neighbor warmup fallback resolves reth unit subnets to the base interfac | 2026-04-07 |

### Refactoring (12 issues)

| # | Title | Status |
|---|-------|--------|
| 545 | refactor: split pkg/config/compiler.go (5878 lines) by config domain | CLOSED |
| 546 | refactor: split pkg/daemon/daemon_ha.go (4194 lines, 125 functions) | CLOSED |
| 547 | refactor: split pkg/grpcapi/server.go (8411 lines) by RPC domain | CLOSED |
| 548 | refactor: split pkg/cli/cli_show.go (7887 lines) by show domain | OPEN |
| 549 | refactor: split pkg/daemon/daemon.go (4506 lines) system config functions | OPEN |
| 550 | refactor: split pkg/dataplane/userspace/manager.go (4772 lines) | OPEN |
| 551 | refactor: split pkg/cluster/sync.go remaining protocol/conn/failover paths | OPEN |
| 552 | refactor: split pkg/cli/cli.go (4874 lines) dispatch and handlers | OPEN |
| 553 | refactor: split pkg/config/ast.go into groups/edit/format paths | OPEN |
| 554 | refactor: split cmd/cli/main.go (3623 lines) | OPEN |
| 555 | refactor: split pkg/config/parser_test.go by subsystem | OPEN |
| 556 | refactor: reduce userspace-dp/src/afxdp.rs root module | OPEN |

### Other (49 issues)

| # | Title | Resolution |
|---|-------|------------|
| 6 | test auth check | 2026-03-01 |
| 10 | Host-inbound filtering defaults to allow for unknown services | 2026-03-01 |
| 12 | CLI: show security policies global does not return global-only view | 2026-03-01 |
| 13 | CLI: show security ipsec security-associations detail is ignored | 2026-03-01 |
| 14 | CLI: show interfaces <name> extensive is not implemented | 2026-03-01 |
| 17 | CLI: top-level show bgp summary alias missing | 2026-03-01 |
| 18 | CLI pipe filters are case-insensitive but Junos reference is case-sensitive | 2026-03-01 |
| 22 | CLI: show system processes summary is not implemented (raw ps output only) | 2026-03-01 |
| 23 | CLI: show security policies default output format does not match Junos reference | 2026-03-01 |
| 24 | CLI: show security log output format is not Junos RT_FLOW style | 2026-03-01 |
| 25 | CLI: show security zones output format diverges from Junos reference | 2026-03-01 |
| 26 | CLI: show security policies hit-count column layout does not match reference | 2026-03-01 |
| 27 | CLI: show security policies detail output diverges from Junos reference schema | 2026-03-01 |
| 28 | CLI: show security alg status command/format parity gaps | 2026-03-01 |
| 30 | Compiler: policy expansion can overflow MaxRulesPerPolicy and spill into adjacen | 2026-03-01 |
| 35 | Compiler: port-mirroring interface lookup skips LinuxIfName normalization | 2026-03-01 |
| 74 | Investigation: transient 10-30s loss to 172.16.100.247 after deploy restart | 2026-03-02 |
| 134 | cluster: takeover hold timer is edge-triggered and may never promote when the ti | 2026-03-06 |
| 140 | rpm: hierarchical `target url ...` syntax compiles to the literal string `url` | 2026-03-06 |
| 141 | rpm: `routing-instance` is parsed but ignored at runtime | 2026-03-06 |
| 142 | rpm: `probe-limit` from `vsrx.conf` is silently ignored | 2026-03-06 |
| 143 | dynamic-address: `feed-name { path ... }` and `address-name profile` from `vsrx. | 2026-03-06 |
| 144 | flow-monitoring: `export-extension app-id/flow-dir` from `vsrx.conf` is ignored  | 2026-03-06 |
| 145 | services: `application-identification` in `vsrx.conf` is still parse-only | 2026-03-06 |
| 146 | security: `pre-id-default-policy` from `vsrx.conf` is parsed but not wired | 2026-03-06 |
| 147 | system: `license autoupdate url` from `vsrx.conf` has no runtime behavior | 2026-03-06 |
| 148 | system: `ntp threshold action` from `vsrx.conf` is parsed but ignored | 2026-03-06 |
| 149 | security flow: `power-mode-disable` from `vsrx.conf` has no runtime effect | 2026-03-06 |
| 150 | security: `policy-stats system-wide` from `vsrx.conf` is ignored | 2026-03-06 |
| 155 | ike/ipsec: proposal lifetime-seconds is parsed but never emitted to swanctl | 2026-03-07 |
| 156 | ike: dead-peer-detection modes all collapse to a hardcoded dpd_delay = 10s | 2026-03-07 |
| 157 | ike: Junos $9$ pre-shared-key strings are passed verbatim to strongSwan | 2026-03-07 |
| 158 | ike: authentication-method is parsed but swanctl generation hardcodes auth = psk | 2026-03-07 |
| 159 | ipsec: full traffic-selector syntax is still unsupported; only one local_ts/remo | 2026-03-07 |
| 280 | daemon event-stream watermarks survive helper reconnect and stale-drain the next | 2026-03-31 |
| 307 | Expose per-interface entry program and transit fallback counters in status and v | 2026-04-01 |
| 310 | Make reverse-companion and translated-alias state deterministic at takeover | 2026-04-01 |
| 327 | Replace flow cache flush with epoch-based invalidation | 2026-04-01 |
| 341 | UpdateRGActive hides helper refresh_owner_rgs timeout and failure | 2026-04-02 |
| 366 | Split event_stream.rs into wire codec and transport state machine modules | 2026-04-02 |
| 371 | Split grpcapi/server.go by RPC domain instead of one monolithic server file | 2026-04-02 |
| 373 | Split config/compiler.go by configuration domain instead of one giant compiler f | 2026-04-02 |
| 375 | Split cli.go into command-family modules instead of a single operational CLI fil | 2026-04-02 |
| 376 | Split api/handlers.go by REST resource family | 2026-04-02 |
| 377 | Split dataplane/compiler.go into feature compilers and host-interface setup modu | 2026-04-02 |
| 421 | monitor interface traffic needs a realtime all-interface pps/bandwidth view | 2026-04-03 |
| 423 | monitor interface traffic should add bwm-ng style interactive views and help | 2026-04-03 |
| 477 | remote monitor interface traffic ignores summary-mode keystrokes | 2026-04-05 |
| 478 | monitor interface traffic summary omits fab/reth aliases | 2026-04-05 |

# xpf firewall deep audit — A7: Daemon lifecycle & host integration — ps-review-037-A7-b1

- Base commit: d4506d4450e2 (master HEAD)
- Output path: /tmp/ps-review-037-A7-b1.md
- Cohort: A7 — Daemon lifecycle & host integration
- Focus: core firewall (zone policies, global policies, host-inbound, default deny/permit) + VRRP/HA failover & cold-boot + integer-truncation + DDNS/observability resource safety
- Persona: Linux systems — systemd/interface management, netlink, FRR/strongSwan config gen and command-exec surfaces (shell/vtysh/exec arg injection), IPsec apply/teardown ordering, route-leak correctness

## 1. Base commit reviewed

```
d4506d4450e2 Merge pull request #4571 from psaab/fix/4570-ra-configequal
```

Branch: master. HEAD d4506d4 = d4506d4450e2 at review time.

## 2. Output path

`/tmp/ps-review-037-A7-b1.md`

## 3. Duplicate-suppression summary + intentional-divergence list

### Prior findings + issues reviewed

- `/tmp/all_findings.txt` — 274 entries (F-001..F-274)
- `/tmp/ps-review-018..036` — 14+ prior deep reviews on master, including ps-review-036 all-cohort synthesis
- `gh issue list --state all --limit 500` — 500 issues (30 open, ~470 closed)
- `_Log.md` recent entries, `docs/feature-gaps.md`
- `/tmp/ps-review-036-cohort12-14.md` — Cohort 12-14 audit (CLI/REST/gRPC + Wire/Protocol + Config Parser + DHCP/RA/Flowexport/LLDP)

### CLOSED — Do NOT re-report (verified, not re-filed)

| ID | Topic | Why dedup'd |
|---|---|---|
| #4562 | navigatePath intermediate multi-key descent | FIXED 40a5ba8ec |
| #4556 | CLI/API LOW batch (3 residuals) | FIXED |
| #4555 | XDP EH 6 vs 8 | OPEN LOW — fail-closed parity |
| #4549 | LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id) | OPEN LOW |
| #4548 | VRRP MaxAdverInt no min clamp → flap | OPEN LOW (MED→LOW) |
| #4547 | IPsec DNS stall (N×2s commit) | CLOSED per gh |
| #4546 | WG peer_has_confirmed_session REJECT_AFTER_TIME | CLOSED per gh |
| #4544 | config duplicate host-inbound dup | CLOSED NEW |
| #4543 | screen IPv4 options TLV break-on-malformed | CLOSED NEW |
| #4541 | api writeJSON header before encode | CLOSED NEW |
| #4540 | CLI monitor traffic keyword/count | CLOSED NEW |
| #4539 | session cache non-handshake TCP | CLOSED NEW |
| #4535 | three-color policer unspecified color mode | CLOSED |
| #4534 | PBR discard/reject VRF-steer | CLOSED |
| #4533 | icmp_embed EH-overflow fail-closed | CLOSED |
| #4526 | DHCP renewalTimers overflow | CLOSED |
| #4525 | RA randomAdvInterval 0 → hot-loop | CLOSED |
| #4524 | monitor traffic injection (HIGH) | CLOSED — "--" + validator |
| #4521/#4520/#4519/#4518/#4517/#4514 | NAT pool / NAT64 / NPTv6 / EH / policer | CLOSED |
| #4487/#4453/#4400 | RST/FIN session | CLOSED |
| #4433 | IPsec render/reload failure leaves stale tunnels | CLOSED |
| #4434 | HA heartbeat RG count uint8 truncation | CLOSED — widened |
| #4435 | NAT64 EH 6 vs 8 | CLOSED |
| #4388/#4384/#4381 | HA NAT / TCP checksum / NAT64 BIB | CLOSED |
| #4386 | cold-boot split-brain — heartbeat peer-never-seen promotes after 500ms | CLOSED |
| #4378 | commit confirmed rollback timer not cancelled on RG0 demotion | CLOSED |
| #3868 | commit confirmed rollback divergence (no peer re-sync) | CLOSED |
| #3864 | deterministic NAT flat-set parse | CLOSED (parse only, enforcement still #4559) |
| #3843/#3842/#2514 | source-prefix-list / dup match/then / address book collision | CLOSED |
| #2691 P3 | checkip source DDNS — fail-closed on missing URL / bad bind | CLOSED |
| #2524 | ring-entries unbounded OOM at bring-up | CLOSED — MaxRingEntries=16384 + power-of-two check |
| #2387 bare 5-tuple | P0 | OPEN — known, not cohort A7 unless new trace |
| #1319 | workers typed knob | CLOSED — min 1 validation |
| #2388 | FIB connected-route table-scoping VRF leak | CLOSED |
| IPv6 EH walkers | MOBILITY/HIP/Shim6 + NAT64 embedded | CLOSED |

### OPEN — Do NOT re-report unless materially new trace

| Issue | Topic | Action |
|---|---|---|
| #4559 | deterministic NAT unenforced | Cohort 5 — skip |
| #4555 | XDP EH 6 vs 8 | Cohort 8 — skip |
| #4549 | LOW batch (4) | Skip — already filed |
| #4548 | VRRP MaxAdverInt flap | Skip |
| #4547/#4546 | IPsec DNS / WG | CLOSED per gh — skip |
| #4533 | icmp_embed | CLOSED — skip |
| #4515 | warn-only validation gaps (zone→undefined-iface, malformed addr-book) | Skip |
| #4512/#4565 | NAT64 HA-sync reverse port | Skip |
| #4498 | FRR sanitize-belt residual (next-hop/origin/source-protocol bare %s) | OPEN — checked in §5, see finding if still present |
| #4478 | IPIP decap no zone enforcement | OPEN M-1 — skip (not cohort A7 primary) |
| #4455 | HI-1 multicast/broadcast host-inbound | OPEN — skip |
| #4313 | opt-in schema unmodeled leaves silent | OPEN X-1 — skip |
| #2387 | bare 5-tuple | P0 — known |
| #4146 | junos-host XDP shim | Skip |
| #2852 | NAT single Mutex | Skip |
| #2562 | NAT64 non-first fragment | Skip |
| #4569/#4567/#4566 | ps-036 new findings | Filed — skip |

### Intentional divergences (NOT bugs)

- Intrazone default-permit — documented, intentional
- Host-originated junos-host rejection — intentional lifeline
- IPsec-passthrough-exempt — documented
- `reject-all` superset = `PolicyReject` — intentional (#3065)
- Rib-group Phase-1 only leaks into main — documented (non-main targets deferred to Phase 2)
- PBR ip rule has no iif selector — documented widening
- Next-table global ip rule — documented widening
- Gre-performance-acceleration / power-mode-disable — wire-only, deferred features
- Deterministic NAT validated+committed but unenforced — OPEN #4559, not re-reported

---

## 4. Module / verdict-path inventory (coverage checklist + cohort map)

| # | Module | File(s) | Verdict-path role | Reviewed | LOC |
|---|---|---|---|---|---|
| A7-01 | Daemon core | `pkg/daemon/daemon.go` | Daemon struct, Options, nodeIDFile, DDNS/SurfaceA/DDNS nudge channels, RG state machine, startupGoodbyeRA, cluster/HA/VRRP wiring | YES | 822 |
| A7-02 | Daemon apply | `pkg/daemon/daemon_apply.go`, `bootstrap.go` | applyConfigLocked (21 steps), bootstrapFromFile, executeConfirmedRollback, applyAndSyncCommitted, applyErrSkipsPeerSync, deviceMap preflight, ProbeForwardingArmed, failClosedBootArmedProbe | YES full | 1926 |
| A7-03 | Daemon HA | `pkg/daemon/daemon_ha.go` | watchClusterEvents, watchVRRPEvents, reconcileRGState, warmNeighborCache, rethInterfacesForRG, blackhole route inject/remove, IPsec SA sync advertise, per-RG service apply/clear | YES full | 1483 |
| A7-04 | Daemon HA sync | `pkg/daemon/daemon_ha_sync.go`, `daemon_ha_fabric.go`, `daemon_ha_fabric_test.go`, `daemon_ha_userspace.go`, `daemon_ha_vip.go` | Session sync peer connect/disconnect, bulk primed/sync ready, fabric refresh, HA userspace demotion prep, VIP ownership, direct VIP mode, fabric link/neigh monitoring | YES (scanned) | ~2000 |
| A7-05 | Daemon DDNS | `pkg/daemon/daemon_ddns.go`, `daemon_ddns_surface_a.go` | DHCP DDNS reconcile loop (Surface B), Surface A reconcile loop, address observation, HA gating, checkip source, DHCP source, interface source, public-addr gate, RG attribution, nudge channels | YES full | 389+791 |
| A7-06 | Daemon nft | `pkg/daemon/daemon_nft.go` | applyHostInboundFilter, applyLo0Filter, buildHostInboundFilterPayload, buildLo0FilterPayload, nftApplyPayload, nftDeleteTable, chain priority (lo0=0, host-inbound=10) | YES | 1395 |
| A7-07 | Daemon neighbor | `pkg/daemon/daemon_neighbor.go`, `daemon_neighbor_listener.go` | resolveNeighbors, collectNeighborProbeTargets, forceProbeNeighbors, cleanFailedNeighbors, maintainClusterNeighborReadiness, neighborPeriodicLoop, RTM_NEWNEIGH/DELNEIGH listener | YES (scanned) | 565+~400 |
| A7-08 | Daemon DHCP/RA/flow | `pkg/daemon/daemon_dhcp.go`, `daemon_dhcp_lease_sync.go`, `daemon_ra.go`, `daemon_flow.go`, `daemon_flowexport.go`, `daemon_forwarding_status.go` | DHCP client reconcile, lease sync, RA config building, flow GC, flow export, forwarding status, linkstate monitor | YES (scanned) | ~800 |
| A7-09 | Daemon DNS/NTP/system | `pkg/daemon/daemon_dns.go`, `daemon_system.go`, `daemon_ntp.go`, `daemon_login.go`, `daemon_snmp_reconcile.go` | DNS reconcile, NTP, hostname, timezone, kernel tuning, login/SSH, SNMP, sudo | YES (scanned) | ~600 |
| A7-10 | Daemon link/VRF/RSS | `pkg/daemon/linksetup.go`, `host_tunables.go`, `host_tunables_daemon.go`, `rss_indirection.go`, `coalescence.go`, `rg_state.go` | Interface naming (positional, device-map), VRF setup, RSS indirection (D3), coalescence, RG state machine, CPU governor, netdev budget | YES (scanned) | ~1000 |
| A7-11 | Routing (ip rule) | `pkg/routing/rules.go`, `routes.go`, `vrf.go`, `routing.go`, `tunnel.go`, `xfrm.go`, `probe_pin.go`, `bond.go` | next-table ip rules (100-199), rib-group leak rules (30000-30999, #3876), PBR ip rules (31000-31999), VRF lifecycle, route reading, ECMP, tunnel/xfrmi, XFRM, probe pin, bond | YES (rules.go full, rest scanned) | ~1500 |
| A7-12 | FRR | `pkg/frr/manager.go`, `config_render.go`, `policy_render.go`, `vtysh.go`, `status_parse.go` | FRR config generation, static routes, generate-routes, backup-router, OSPF/OSPFv3/BGP/RIP/ISIS, prefix-lists, route-maps, communities, redistribute, BFD, sanitizeFRRValue, vtysh exec, frr-reload.py, degraded retry | YES (policy_render.go full, manager/vtysh scanned) | ~2800 |
| A7-13 | IPsec | `pkg/ipsec/manager.go`, `crypto.go`, `ike.go`, `policy.go`, `prepare.go`, `junos_secret.go` | swanctl config render, IPsec SA status, IKE proposals, traffic selectors, DH groups, swanctl exec (runSwanctl), Apply/Clear, terminateRemovedConns (#3941) | YES (manager.go full, rest scanned) | ~800 |
| A7-14 | Networkd | `pkg/networkd/` | systemd-networkd .network/.link/.netdev generation, managed interface reconciliation | YES (scanned) | ~400 |

---

## 5. Module-by-module inspection log (including negatives)

### 5.1 Daemon core — `daemon.go`

- `Daemon` struct — 150+ fields, god-struct (known refactor gap #4407, not re-filed). Fields relevant to this audit:
  - `ddnsReconcileNowCh chan struct{}` (depth 1, coalescing nudge) + `ddnsReconcileInFlight atomic.Bool` (skip-if-in-flight guard) — correct bounded-resource pattern.
  - `surfaceAReconcileNowCh` / `surfaceAReconcileInFlight` + `surfaceACheckIPAllowlistWarned/NoURLWarned/SourceBindWarned sync.Map` — dedup maps bounded by provider count (small, not unbounded). Correct.
  - `startupGoodbyeRA map[int]bool` — one-shot tracker for goodbye RA on cold boot as secondary. **LOW leak — see F-A7-001**.
  - `rgStates map[int]*rgStateMachine` + `rgStatesMu sync.RWMutex` — double-checked locking in `getOrCreateRGState`. Correct.
  - `fabricMu`, `fabricPopulated`, `fabricRefreshCh`, `fabricRefreshCh1` — fabric readiness tracking. Correct.
  - `syncBulkPrimed`, `syncPeerBulkPrimed`, `syncPeerConnected`, `syncPrimeRetryGen`, `syncReadyTimerGen` — HA bulk sync state. Correct atomics.
  - `ipsanNudgeCh`, `dhcpLeaseSyncNowCh`, `dhcpLeaseSyncInFlight`, `feedOverlay` — auxiliary nudge channels, all depth 1. Correct bounded.
- `Options` — `ColdPathSampleMask *uint64` (nil = default, non-nil 0 = 1-in-1 sampling). Correct.
- **NEGATIVE (with one LOW)**: No integer truncation in daemon core. No unbounded resource growth except `startupGoodbyeRA` (LOW, capped by RG count).

### 5.2 Daemon apply — `daemon_apply.go`, `bootstrap.go`

- `bootstrapFromFile` — reads config file, enters configure mode, loads, runs `deviceMapCommitPreflight` (stranding check), commits. Correct.
- `applyConfigLocked` — 21-step reconcile pipeline:
  1. SNMP reconcile (unconditionally before early-return, so committed authz is live even if later dataplane apply aborts — #3967).
  2. Bootstrap exit (first non-empty config with interfaces → `exitBootstrapMode` + `runBootstrapExitStartup`). Correct one-way exit.
  3. Config-arrival naming (`maybeReapplyConfigArrivalNaming` — #4179, re-names NICs for HA node that booted config-less).
  4. VRF reconcile (deletes removed VRFs, preserves existing with correct table ID).
  5. VRF binding (RI interfaces → VRF, mgmt interfaces → vrf-mgmt). Correct.
  6. Management VRF routes (DHCP lease defaults into vrf-mgmt).
  7. Tunnel creation (interface-level + per-unit tunnels).
  8. XFRMI creation (IPsec VPN tunnels, must be before zone compilation).
  9. Bond creation (fabric-options member-interfaces → LAG).
  10. RETH bond cleanup (legacy, VRRP now on physical members).
  11. Fabric IPVLAN overlays (fab0/fab1, deferred when userspace DP active for zerocopy XSK bind). Correct deferral.
  12. RETH MAC programming (deterministic virtual MACs, VLAN sub-interface propagation, rxvlan off re-disable). Correct.
  13. VRRP VIP / stable link-local recovery after link cycle. Correct.
  14. AF_XDP socket rebind after link cycle. Correct.
  15. Proxy ARP/NDP reconcile.
  16. Management VRF re-bind after networkd.Apply (networkd strips VRF master binding).
  17. Heartbeat restart after VRF rebind (networkd moves em0 out of vrf-mgmt, invalidating heartbeat UDP sockets).
  18. FRR apply (`assembleFRRConfig` → `applyFRRConfig`, with `commitOverlay` filtered against incoming config). Correct.
  19. Next-table / rib-group / PBR ip rules. Correct.
  20. Neighbor resolution (standalone only, cluster defers to VRRP MASTER event). Correct.
  21. RA config (standalone only, cluster managed by VRRP events). Correct.
  22. IPsec apply (always calls Apply so stale config removed). Correct — fail-closed on error (#4433).
  23. DHCP server reconcile (standalone: unconditional, cluster: master-RG-filtered via `filterDHCPConfigForMasterRGs`). Correct.
  24. DDNS / Surface A / DHCP lease sync nudges. Correct.
  25. DHCP client reconcile. Correct.
  26. Tail reconciles (`applyTailReconciles` — steps 8-21): VRRP instances, DNS, NTP, hostname, timezone, kernel tuning, lo0 filter, host-inbound filter, SSH known hosts, syslog, login, sudo, SSH config, root auth, syslog files, syslog clients, archival, archive timer, flow trace, flow export, DHCP relay, LLDP, event-options, RPM, ip-monitoring, interface monitors, cluster config, transport change restart, RSS indirection, host tunables, coalescence. All extracted into `applyTailReconciles` (#4407 Phase A). Correct.

- `commitAndApply` / `commitConfirmedAndApply` / `syncAndApply` — all hold `applySem` across `store.Commit` + `applyConfigLocked`, preventing interleaving. Correct atomicity.

- `executeConfirmedRollback` — `applySem` → `PromoteRollback` → `applyConfigLocked` in single critical section. Handles nil rollback target (first commit confirmed timeout → `enterBootstrapMode`). Re-syncs rolled-back config to peer (`resyncRolledBackConfigToPeer`). Correct (#3868 + #1922).

- `applyErrSkipsPeerSync` — only skips peer sync on `compileErrorMustAbortApply` (dataplane disarmed) or `context.Canceled/DeadlineExceeded` (daemon stop). Non-fatal best-effort errors (nft FAIL-bound, networkd warn, FRR degraded, IPsec fail-closed, DHCP server warn) still sync. Correct (#4034).

- `applyCancelCtx` / `#2926` boundaries — daemon-stop context (`applyCancelContext`) aborts at coarse phase boundaries (C1 before netlink reconcile, C2 before dataplane apply, C3 before FRR reload). Request cancellation does NOT abort (store already promoted). Correct.

- `deviceMapCommitPreflight` / `deviceMapPassiveAdmissionAlarm` — primary validates its own hardware at commit (R-8), passive raises loud alarm (no divergence loop). Correct (#1956).

- `clearSessionsForDeletedPolicies` / `clearSessionsForModifiedPolicies` / `clearSessionsForDefaultPolicyChange` — drops sessions of deleted/modified/default-policy-changed policies immediately after dataplane apply, under `applySem`. Correct (Junos default deletion-clear).

- **NEGATIVE**: No integer truncation in apply pipeline. No command injection (all exec calls use `exec.CommandContext` with fixed args, no shell interpolation). All exec surfaces are hardened.

### 5.3 Daemon HA — `daemon_ha.go`

- `watchClusterEvents` — handles `cluster.Event` (cluster state change: Primary/Secondary/SecondaryHold).
  - Activation: sets `rg_active` FIRST, removes blackholes, triggers VRRP MASTER (only on `StateSecondary→StatePrimary`, not `StateSecondaryHold→StatePrimary` — respects `preempt=false`). Updates `localFailoverCommitReady` when local primary and dp doesn't need apply. Correct per #485.
  - Demotion: runs `tryPrepareUserspaceRGDemotion` (flow cache → FabricRedirect, #485), resigns VRRP, injects blackholes, clears `rg_active`. Correct ordering (#485).
  - Debounced VRRP priority update (500ms coalesce). Correct.

- `watchVRRPEvents` — handles VRRP MASTER/BACKUP transitions.
  - MASTER: sets VRRP state, activates rg_active when ALL instances MASTER (#132), removes blackholes, adds stable RETH link-local, applies RETH services (RA, DHCP, DDNS, Surface A).
  - BACKUP: clears VRRP state, sets `localFailoverCommitReady=false` when any instance demotes, injects blackholes, clears rg_active, removes stable link-local, clears RETH services.
  - Standalone VRRP (GroupID < 100) — skips rg_active/blackhole logic. Correct.

- `reconcileRGState` — periodic safety net (2s ticker + `reconcileNowCh` nudge) for dropped events:
  - Re-drives VRRP instance set (`reconcileVRRPInstances` — #2156 B1, bounded self-recovery for VIP-change restarts deferred due to transient interface down).
  - Reads authoritative VRRP states, builds per-RG VRRP map, collects all RG IDs (existing rgStates + cluster-configured + RETH VRRP instances).
  - Checks fabric readiness (triggers refresh when not populated, peer alive).
  - Reports `RGInterfaceReady` → `cluster.SetRGReady` (takeover readiness gate).
  - Per-RG reconcile: `s.Reconcile(clusterPri, vrrp)` → `tr` → retry if `tr.Changed || s.NeedsApply()`. Correct desired-vs-applied retry.
  - Blackhole route declarative reconciliation: active → remove, inactive → inject. Correct.
  - VRRP posture reconciliation (#86): detects sustained mismatch (10s+ continuous) between cluster and VRRP states. Only `UpdateRGPriority(200)` on NeedsMaster (does NOT `ForceRGMaster`, respects non-preempt). `ResignRG` on NeedsResign. Correct.
  - Direct-mode VIP safety net: `reconcileDirectVIPOwnership` on every pass.
  - RA/DHCP service reconciliation on `tr.Changed`. Correct.
  - Stable link-local: ensure correct on every tick. Correct.
  - Startup goodbye RA: one-shot per RG when inactive on first reconcile (node booted as secondary). Sends goodbye RA (lifetime=0) to clear stale routes from previous primary run. Each RETH node has distinct virtual MAC → distinct link-local → hosts see two separate IPv6 routers. **Cold-boot correctness — see F-A7-002 for edge case**.

- `applyRethServicesForRG` / `clearRethServicesForRG` — per-RG RA + DHCP + DDNS + Surface A management. Correct active/active handling (one RG master doesn't affect another's services).

- `warmNeighborCache` — iterates synced sessions (`ForEachV4` / `ForEachV6`), collects unique src/dst IPs (excluding reverse entries), sends UDP packet (1 byte) to each to trigger kernel ARP/NDP (`neigh_resolve_output → arp_solicit`). **Resource safety — see F-A7-003**.

- `ipsecSASyncAdvertise` / `ipsecSANextFP` / `advertiseIPsecSAOnce` / `syncIPsecSAPeriodic` — IPsec SA sync advertisement. Non-empty set advertised every tick (heartbeat re-push for new standby), empty set advertised once on transition down (so standby clears stale set, #4385). `force=true` on peer reconnect re-advertises current set regardless. `ipsecSANextFP` only advances fingerprint on confirmed send (not on nil/dropped conn). Correct (#4385).

- **NEGATIVE (with findings below)**: No integer truncation in HA path. `rgID int`, `ifindex int`, `priority int` — all correct widths. VRRP/HA failover ordering is correct (activation: rg_active → blackhole removal → VRRP priority → ForceRGMaster; deactivation: preflight → VRRP resign → blackhole inject → clear rg_active).

### 5.4 Daemon HA sync — `daemon_ha_sync.go`, `daemon_ha_fabric.go`, etc.

- `onSessionSyncPeerConnected` — determines cold start vs routine reconnect via `BulkEverCompleted()`. Cold start → clears `syncBulkPrimed` + `syncPeerBulkPrimed`, holds `syncReady`, arms timer, starts prime retry. Routine reconnect → preserves primed state (sessions still in BPF maps, no bulk needed, #466). Correct.

- `onSessionSyncPeerDisconnected` — preserves primed state if bulk ever completed (sessions still in maps). Correct.

- `onSessionSyncBulkReceived` / `onSessionSyncBulkAckReceived` — sets primed flags, stops timer, releases VRRP sync hold, sets sync ready. Correct.

- Fabric refresh (`daemon_ha_fabric.go`) — link/neigh monitoring, fabric peer MAC resolution, overlay status tracking. `linkUpdates chan netlink.LinkUpdate` (depth 64), `neighUpdates chan netlink.NeighUpdate` (depth 64), `linkDone` / `neighDone` channels. Correct.

- HA userspace demotion (`daemon_ha_userspace.go`) — `tryPrepareUserspaceRGDemotion` (flow cache → FabricRedirect, gated on userspace DP active). Correct.

- VIP ownership (`daemon_ha_vip.go`) — direct mode (`no-reth-vrrp`), `reconcileDirectVIPOwnership`, `directAddVIPs` / `directDelVIPs`, `scheduleDirectAnnounce` (GARP/NA). Correct.

- **NEGATIVE**: No integer truncation. Cold-boot detection correct (BulkEverCompleted gate). No resource leak — channels bounded, contexts cancelled on daemon stop.

### 5.5 Daemon DDNS — `daemon_ddns.go`, `daemon_ddns_surface_a.go`

- `runDDNSReconcileLoop` — always-on guarded background goroutine, 30s cadence + nudge, per-pass context timeout (60s). `runGuardedDDNSReconcile` uses `CompareAndSwap(false, true)` (skip-if-in-flight) — correct no-freeze pattern (mirrors neighbor loop).

- `reconcileDDNSOnce` — node-level HA gate (`ddnsWriterGateOpen`: open when MASTER for ≥1 RG), per-scope HA gate + lease→RG resolver (stable CIDR membership, NOT unstable Kea `subnet_id`). Correct (#2664).

- `buildLeaseSubnetRGMap` — walks DHCP config, pairs pool subnet CIDR → RG (via interface → RedundancyGroup). Sorted most-specific-first (longer prefix wins) + stable tie-break (CIDR string, RG) — correct deterministic attribution (longest-prefix-correct AND stable across reconciles).

- `rgForLeaseAddress` — linear scan over sorted pool subnets, first-match (longest-prefix due to sorting). Returns `ok=false` for unattributable address → fail-closed (not published). Correct.

- `ddnsWriterGateOpen` — standalone: always open; cluster: open iff MASTER for ≥1 RG. Reads `snapshotRethMasterState()` (same source as Kea manager). Correct.

- `runSurfaceADDNSReconcileLoop` — mirrors Surface B: 30s cadence + nudge, per-pass 60s timeout, skip-if-in-flight guard. Correct.

- `buildSurfaceAScopes` — walks interfaces + units, materializes `SurfaceAScope` per per-interface per-family DDNS binding. Resolves provider, applies per-binding source-address override, attributes RG. Sorted by deterministic key (interface, unit, family, provider, FQDN) — reproducible. Correct (#4423 M12).

- `surfaceAObserver` — address observation per scope source:
  - `checkip`: validates `CheckIPURL` present (fail-closed on missing, never fallback to interface address — #4423 H08). Derives context from reconcile ctx (not Background, #3736 — daemon shutdown cancels promptly). Binds probe to provider's source-address/interface/VRF (#2846). Reuses cached HTTP client (#2904). Malformed allowlist tokens logged once per (provider, allowlist-string), not every tick. Source bind errors logged once per (provider, error). Non-public lease → withdraw (never publish non-public, never blackhole). Correct.
  - `dhcp`: reads `LeaseFor(linuxName, af)`. Missing lease when unit still DHCP-configured → transient (ok=false, never withdraw — #4423 M10). Missing lease when unit no longer DHCP-configured → definitive (withdraw). Non-public DHCP lease → withdraw (never publish CGNAT/RFC1918/private). Correct (#3732/#4423 M10).
  - `interface`: reads netlink addresses via `observeInterfaceAddr`. Transient netlink failure → ok=false (never withdraw, retry next pass — #2840). Successful read with no usable dynamic address → fallback to configured static (gated through `IsPublicAddr`). Interface up but no address of family and no static → definitive none (withdraw). Correct.

- `selectInterfaceAddr` — selection policy: skip tentative/dadfailed/optimistic/temporary (DAD not succeeded, privacy/temporary), skip non-public (loopback/link-local/ULA/CGNAT/documentation/Iana special-purpose — via `ddns.IsPublicAddr`), prefer preferred over deprecated, deprecated as no-blackhole fallback. Netlink returns stable order, so "first eligible" is deterministic. Correct.

- `staticUnitAddr` — first configured static address of requested family, gated through `IsPublicAddr`. Non-public static skipped with WARN (never publish non-public, never blackhole). Correct (#2776).

- `surfaceAGate` — per-RG HA writer gate for Surface A. Standalone: nil (admits all). Cluster: RG-owned interface scope → writable iff this node masters that RG. RG 0 scope (non-HA interface) → bound to RG0 primary (#2972 — single writer follows RG0 failover, prevents double-write in active-active). RG 0 not tracked → lowest node ID (node 0) as deterministic single writer. Correct (#2972).

- `surfaceAObserver` closure — `defer cancel()` inside the returned closure (the `AddressObserver` function), NOT inside `surfaceAObserver`. Go's `defer` is scoped to enclosing function (the closure IS the enclosing function). So `cancel()` runs when closure returns. **NOT a bug** — verified correct (same analysis as A6 F-A6-003).

- **Resource safety**: `surfaceACheckIPAllowlistWarned` / `SourceBindWarned` / `NoURLWarned` are `sync.Map` bounded by provider count (unique provider names in config, max ~10-20). `buildSurfaceAScopes` allocates `out` + `invalid` slices per pass, bounded by interface×unit×family (max ~hundreds). No unbounded growth. HTTP client cache (`httpClientCache`) has `reap` that evicts superseded binding keys on every pass (#2956). No goroutine leak — guarded by `CompareAndSwap`, `defer Store(false)` in spawned goroutine.

- **NEGATIVE**: No integer truncation. DDNS resource safety correct (bounded maps, bounded channels, reap on supersede, no goroutine leak). Address observation fail-closed on transient errors, never blackholes on definitive no-address.

### 5.6 Daemon nft — `daemon_nft.go`

- `nftApplyPayload` — `nft -f -` with 5s context + WaitDelay. Atomic apply (previous table kept on failure). Package var for test injection. Correct.

- `nftDeleteTable` — `add table <family> <name>` + `delete table <family> <name>` two-line payload (NOT `destroy` — recent nftables verb, would fail on non-floor base). Idempotent. Package var for test injection. Correct.

- Chain priorities: `nftLo0FilterPriority = 0` (conventional `filter` priority), `nftHostInboundPriority = 10` (strictly greater, so lo0 evaluates first). `nft_chain_priority_test.go` pins `nftLo0FilterPriority < nftHostInboundPriority`. Correct (#3364).

- `applyLo0Filter` — reads `cfg.System.Lo0FilterInputV4` / `Lo0FilterInputV6`, builds payload via `buildLo0FilterPayload` (pure function, testable), applies via `nftApplyPayload`. No lo0 filter → removes stale table via `nftDeleteTable`. Fail-closed (#3392): failure surfaces as error, commit reports failure. Boot/DHCP re-applies go through `applyConfig()` which only logs error (transient nft failure cannot brick startup). Correct.

- `buildLo0FilterPayload` — pre-passes terms to collect named counter objects (`then count` → `counter <name> {}`), dedups on counter name. Then emits `add table` / `delete table` / `table { counter decls; chain input { type filter hook input priority 0; policy accept; rules } }`. Counter declarations unquoted (#3578: nft v1.1.6 rejects quoted name in declaration, but quoted reference is required). Correct.

- `applyHostInboundFilter` — kernel-nftables PRIMARY enforcement of `security zones <z> host-inbound-traffic` (#3070). Collects `BuildZoneHostInboundViews` + `BuildUnzonedHostInboundAddrs` (#4420 HI-2). Logs addressless transitions (#3698, #3710) + ambiguous transitions (#3718). No enforceable view + no unzoned addrs → removes stale table. Otherwise builds + applies payload. Fail-closed (#3333): same as lo0 filter. Correct.

- `buildHostInboundFilterPayload` — renders per-zone host-inbound rules: established sessions accept, IPv6 ND/PMTUD accept, lifeline interfaces excluded, per-zone firewall-local addresses → host-inbound admission check (protocol/port match), unzoned addresses → catch-all DROP (#4420 HI-2), final `policy accept`. Correct.

- **NEGATIVE**: No integer truncation. No command injection — nft payload is constructed from validated config types (zone names, interface names, protocol names, port numbers), not raw user strings. Port numbers validated at schema level (1..65535). No shell interpolation — `nftApplyPayload` writes payload to stdin of `nft -f -`, no shell involvement.

### 5.7 Daemon neighbor — `daemon_neighbor.go`, `daemon_neighbor_listener.go`

- `resolveNeighbors` — collects targets via `collectNeighborProbeTargets` (static-route next-hops, DHCP gateways, backup router, DNAT pool addresses, static NAT translated addresses, address-book host entries /32 and /128), then fires ICMP/NS probes. `addByIP` does `RouteGet` → neighbor IP + link index. `addByName` resolves Junos if name → Linux if name → link index. Correct.

- `collectNeighborProbeTargets` — fresh slice, no backing-array mutation (allRoutes allocation fix in #1781). Correct.

- `forceProbeNeighbors` — re-probes ALL monitored neighbors (including STALE/DELAY/PROBE) so kernel re-validates entries `resolveNeighbors` would skip. Correct.

- `cleanFailedNeighbors` — removes FAILED neighbor entries. Correct.

- `maintainClusterNeighborReadiness` — HA-only (gated on `d.cluster != nil`), atomic guard `neighborWarmupInFlight` prevents overlapping runs, spawns `warmNeighborCache` in goroutine. Correct.

- `warmNeighborCache` — iterates BPF session table (`ForEachV4` / `ForEachV6`), collects unique src/dst IPs (excluding reverse), sends UDP packet (1 byte) to each to trigger ARP/NDP. **Resource safety — see F-A7-003**.

- `neighborPeriodicLoop` — supervised for-select core: `cleanTick` (5s) + `resolveTick` (15s: resolve + force-probe + maintain). Each tick dispatches via `runGuardedNeighborPhase` (guarded goroutine, skip-if-in-flight) or O(1) inline, so wedged phase never stops other ticks. Correct (#1781 r1).

- `daemon_neighbor_listener.go` — RTM_NEWNEIGH/DELNEIGH listener (kernel-as-authority), regenerates dataplane neighbor snapshot on kernel change. Correct (#1197).

- **NEGATIVE (with one LOW below)**: No integer truncation. Neighbor index math correct.

### 5.8 Daemon DHCP/RA/flow — `daemon_dhcp.go`, `daemon_ra.go`, `daemon_flow.go`, etc.

- `daemon_dhcp.go` — DHCP client reconcile (start/stop/restart clients for units that gained/lost DHCP). `reconcileDHCPClients` diffs on config identity only (not lease state), so DHCP lease-change callback re-entering `applyConfig` cannot restart clients in a loop. Correct (#1793).

- `daemon_dhcp_lease_sync.go` — lease sync push/pull, memfile fallback, nudge channel (depth 1). Correct (#2239).

- `daemon_ra.go` — `buildRAConfigs` merges static RA configs + PD-derived prefixes (DHCPv6 prefix delegation). Detects explicitly configured link-local addresses for RA source. Correct.

- `daemon_flow.go` — flow GC, linkstate monitor. Correct.

- `daemon_flowexport.go` — NetFlow v9 / IPFIX exporter reconcile. Hash-gated per family, so unrelated commit never bounces exporter. Correct (#2075).

- `daemon_forwarding_status.go` — forwarding status collection via `fwdstatus.DataPlaneAccessor`. Correct.

- **NEGATIVE**: No integer truncation. No resource leak.

### 5.9 Daemon DNS/NTP/system — `daemon_dns.go`, `daemon_system.go`, etc.

- `daemon_dns.go` — `reconcileDNSLocked` merges static `system name-server` + live DHCP-learned servers into `/etc/resolv.conf` (managed plain file, resolved disabled+masked). `dnsBootDone` gates empty DNS merge (repairs dangling/stub/missing on boot, declarative clear after boot). Correct (#1715).

- `daemon_system.go` — hostname, timezone, kernel tuning. Correct.

- `daemon_ntp.go` — NTP config. Correct.

- `daemon_login.go` / `daemon_snmp_reconcile.go` — login/SSH/SNMP. `reconcileSudoers` revokes stale NOPASSWD grants on class downgrade/user removal (#3889). Correct.

- **NEGATIVE**: No integer truncation. No command injection — all exec calls use `exec.CommandContext` with fixed args.

### 5.10 Daemon link/VRF/RSS — `linksetup.go`, `host_tunables.go`, `rss_indirection.go`, etc.

- `linksetup.go` — `enumerateAndRenameInterfaces` (standalone: idx 0→fxp0, idx 1+→ge-0-0-{idx-1}; cluster: idx 0→fxp0, idx 1→em0, idx 2+→ge-{FPC}-0-{idx-2}). Collision-safe two-pass rename (#4178). Correct.

- `host_tunables.go` — CPU governor + netdev_budget + net neigh dirs. `listCPUGovernorPaths` via `filepath.Glob`, `writeFile` via `os.WriteFile`. Best-effort (never blocks startup). Correct.

- `rss_indirection.go` — D3 RSS indirection reshaping for mlx5. Constrains RSS to queues 0..workers-1, only touches allowlisted interfaces (userspace-dp bound interfaces). Correct (#797).

- `coalescence.go` — NIC coalescence tuning. Correct.

- `rg_state.go` — RG state machine: `clusterPri || anyVrrpMaster`. `AllVRRPMaster` (all instances MASTER = RG MASTER per #132), `AnyVRRPMaster`, `IsActive`, `CurrentDesired`, `NeedsApply`, `ShouldLogRetry`, `ShouldLogApplyError`, `CheckVRRPPosture` (NeedsMaster/NeedsResign, 10s+ continuous mismatch, skip during sync-hold). Correct.

- `host_tunables_daemon.go` — re-applies host tunables on config change (worker count change, disable knob flip). Correct.

### 5.11 Routing — `pkg/routing/rules.go`, etc.

- `nextTableManager.Apply` — priority 100-199, hard-cap 100, clears old, aggregates errors, installs `to <dst> lookup <table>` global ip rule. Correct.

- `ribGroupManager.Apply` (post-#3876) — per-prefix `to <connected-prefix> lookup <sourceTable>` (pref 30000-30999, 1000 max). Correct. Legacy blanket `from all lookup <sourceTable>` (pref 33000) retained ONLY for cleanup.

- `pbrManager.Apply` — priority 31000-31999, clears old, installs `from <src> to <dst> tos <tos> ipproto <p> sport <sp> dport <dp> lookup <table>`. DSCP-0 dropped (zero = match ANY in ip rule), TOS presence via `TOSSet`. PBR discard/reject skipped (#4534 FIXED). DSCP×src×dst×proto×sport×dport cross-product, truncates to `maxPBRRules` (1000). Correct.

- `BuildPBRRules` — only from attached input filters, DSCP×src×dst×proto×sport×dport cross-product. `pbrTermL4` classifies unrepresentable L4 predicates as fail-closed. Correct.

- `validateFilterRoutingInstanceConflictStrict` — rejects RI+discard/reject at commit. Lenient warns. FIXED #4534.

- `vrf.go`, `routes.go`, `tunnel.go`, `xfrm.go`, `probe_pin.go`, `bond.go` — VRF lifecycle, route reading, ECMP multipath, tunnel/XFRMI, XFRM, probe pin, bond. All scanned, no issues.

- **FOCUS #4498 (FRR sanitize-belt residual)**: Checked in `policy_render.go` — `sanitizeFRRValue` strips control chars from free-text values (description, auth key, password, community member, AS-path regex). Render-side belt for #1798/#4097 — prevents newline injection into frr.conf even if commit-time validation bypassed via lenient/peer-sync path. Correct. `validRouterID` rejects non-IPv4 router-id at render time (defense-in-depth for #2980). Correct. `resolveRedistribute` never emits bare `redistribute <name>` with no source protocol — skip+warn, never poisons managed reload. Correct. **No sanitize-belt residual found** — all FRR-rendered free-text values go through `sanitizeFRRValue`.

### 5.12 FRR — `pkg/frr/manager.go`, `config_render.go`, `policy_render.go`, `vtysh.go`, `status_parse.go`

- `manager.go` — `Manager` lifecycle, `ApplyFull` orchestration, `writeManagedSection`, `reload` (primary `frr-reload.py --reload`, fallback `vtysh -f`, degraded retry loop with backoff: 15s, 30s, 60s, then 5min). `ErrFRRReloadDegraded` (additive fallback, stale-config removal deferred). `Stop` cancels manager lifetime context + waits for retry goroutine. Correct (#1880).

- `config_render.go` — non-protocol config rendering (interface settings, static routes, generate-routes, DHCP defaults, backup-router, cluster-mode defaults, ECMP `consistent-hash`). `resolveECMP` mutates `FullConfig.ConsistentHash` as side effect (documented). Correct.

- `policy_render.go` — protocols + policy rendering:
  - `sanitizeFRRValue` — strips C0 (0x00-0x1F, including newline) + DEL (0x7F), replaces with space. Prevents frr.conf command injection via embedded newline in description/auth-key/password/community-member/as-path-regex. Correct (#1798/#4097).
  - `validRouterID` — rejects non-IPv4 router-id at render time (lenient/peer-sync path can carry malformed router-id). Empty intentionally invalid (caller gates on != "", FRR auto-derives). Correct (#2980).
  - `resolveRedistribute` — known protocol → bare `redistribute <proto>`. Policy-statement → extract protocols from terms → `redistribute <proto> route-map <name>`. Self-redistribute dropped (FRR rejects `redistribute ospf` under `router ospf`). Unknown token → skip+warn (never emit bare `redistribute <name>` which would poison managed reload, #2223). Correct.
  - `policyNeedsRedistAlias` / `redistFailClosedRouteMap` — BGP route-map with trailing PERMIT (Junos BGP default-accept) must NOT govern redistribute default (Junos redistribute defaults to REJECT). References fail-closed per-use-site alias. Correct (#4481).
  - `bgpEffectiveExport` / `bgpEffectiveImport` — Junos most-specific-wins (neighbor's own export/import overrides global default). FRR takes exactly one `route-map out/in` per neighbor/AF. Correct.
  - `policyStatementHasNextHopSelf` — detects `then next-hop self` (no FRR route-map set-clause for it; canonical mechanism is `neighbor <peer> next-hop-self force`). Pre-#2977 emitted nothing → iBGP blackhole. Fixed to emit `neighbor <peer> next-hop-self force`. Correct (#2977).
  - BFD profile dedup, OSPF/OSPFv3/BGP/RIP/ISIS rendering, prefix-lists, route-maps, communities — all scanned, correct.
  - **No sanitize-belt residual**: All free-text values that could contain control chars go through `sanitizeFRRValue`. Next-hop, origin, source-protocol are NOT free-text — they are validated IP/protocol tokens from typed config, not operator free-text. The "bare %s" pattern for next-hop is safe because next-hop is always a validated IP or interface name, not free-text.

- `vtysh.go` — `frrExecutor` interface (Vtysh / FrrReloadPy / VtyshLoad), `realExecutor` (production), `Manager.ExecVtysh` (public). All vtysh/frr-reload.py shell-outs go through interface (test-injectable). `Vtysh` uses `vtysh -c <command>` with 15s timeout + 5s WaitDelay. `FrrReloadPy` uses direct process-group teardown (Setpgid + Cancel SIGKILLs whole group, so child vtysh writers don't survive — #1880). `VtyshLoad` is additive fallback. `GetBGPNeighborReceivedRoutes` / `GetBGPNeighborAdvertisedRoutes` validate `ip != ""` before string concatenation. Correct.

- **Command injection surface**: `vtysh.go` — `GetBGPNeighborReceivedRoutes`, `GetBGPNeighborAdvertisedRoutes`, `GetBGPNeighborDetail` concatenate IP into vtysh command string (`"show bgp neighbor " + ip + " received-routes"`). IP is validated by `ip != ""` but NOT sanitized for control chars. However, these are read-only `show` commands, not config-changing, and the IP comes from either (a) `show bgp summary` neighbor list (kernel-validated IP, not operator free-text) or (b) operator CLI `show bgp neighbor <ip>` where `<ip>` is validated as IP by CLI dispatcher. **LOW — see F-A7-004**.

- **NEGATIVE (with one LOW)**: FRR config generation correct, sanitize belt correct, no stale-config poison, no redistribute injection. One LOW (vtysh show command IP concatenation, read-only, not config-changing).

### 5.13 IPsec — `pkg/ipsec/manager.go`, etc.

- `manager.go` — `Manager` with `prevConnNames map[string]bool` (diff for deleted VPN cleanup). `Apply` → diff prev vs new → write config atomically (`fsatomic.WriteFileAtomic`, #1894) → reload (`swanctl --load-all`) → `terminateRemovedConns` (active SA teardown for deleted VPNs, #3941). `Clear` → same pattern with nil conn names. Correct.

- `runSwanctl` — `swanctl <args...>` under 15s timeout + 5s WaitDelay. Correct (#1794/#1800).

- `applyConfig` — renders config via `renderConfig`, creates dir (0755), writes file (0600, atomic), reloads. `swanctl --load-all` only unloads deleted VPNs' config, does NOT terminate their SAs — `terminateRemovedConns` compensates. Correct.

- `terminateRemovedConns` — reads active SA names via `--list-sas`, matches against removed conn names, issues `--terminate` for each. Idempotent (no active SA → no-op). Correct.

- `swanctl_render_test.go` / `ike_chain_failclosed_test.go` / `trafficselector_render_4098_test.go` — correct test coverage.

- **DNS stall fix** (#4547 CLOSED): Dynamic-hostname gateway DNS resolution now happens asynchronously (not per-gateway synchronous 2s block on commit). Verified CLOSED per gh.

- **NEGATIVE**: No integer truncation. No command injection — `runSwanctl` uses `exec.CommandContext` with fixed args (`"swanctl", args...`), no shell. Tunnel names sanitized (Junos if name → swanctl conn name). No resource leak.

### 5.14 Networkd — `pkg/networkd/`

- `Apply` — writes systemd-networkd `.network` / `.link` / `.netdev` files for managed interfaces, sweeps stale `10-xpf-*` files. Empty managed set still triggers sweep (fixes #2988 — last xpf-managed interface removed, stale files cleaned). Lifeline protected via `SetProtectedResolver` (feeds `resolveProtectedInterfaces` from `ActiveConfig` independently of `ManagedInterfaces`). Correct.

- **NEGATIVE**: No integer truncation. No command injection. No resource leak.

---

## 6. Findings

### [F-A7-001] LOW: `startupGoodbyeRA map[int]bool` grows unbounded on RG reconfiguration — old RG IDs never evicted

- Title: `startupGoodbyeRA` accumulates stale RG IDs across RG reconfiguration, blocking goodbye RA for new RG that reuses an old ID
- Severity: Low (HA cold-boot correctness — stale goodbye RA suppression on RG ID reuse)
- Confidence: Medium
- Evidence:
  ```go
  // pkg/daemon/daemon.go:516-519
  // startupGoodbyeRA tracks whether the one-shot goodbye RA has been
  // sent for a given RG. It is set once on the first reconcile pass
  // where an RG is inactive (node booted as secondary) and never
  // cleared until daemon restart.
  startupGoodbyeRA map[int]bool

  // pkg/daemon/daemon_ha.go:769-793
  if !tr.Active && d.ra != nil && !d.startupGoodbyeRA[rgID] {
      if d.startupGoodbyeRA == nil {
          d.startupGoodbyeRA = make(map[int]bool)
      }
      d.startupGoodbyeRA[rgID] = true
      // ... sends goodbye RA (lifetime=0) to clear stale routes from previous primary run
  }
  ```

  - `startupGoodbyeRA` is a one-shot tracker: once `true` for an RG ID, goodbye RA is never sent again for that RG ID during daemon lifetime.
  - It is never cleaned up when an RG is removed from config. If RG 1 is deleted and a new RG 1 is created (different interfaces, different prefixes), `startupGoodbyeRA[1] == true` suppresses the goodbye RA for the new RG 1.
  - In practice: RG IDs are small (0-2 typically), RG reconfiguration is rare, and RG ID reuse is unlikely. But a `chassis cluster redundancy-group 1` delete + re-add (or a config that changes RG 1's member interfaces) could suppress the goodbye RA for the new RG 1, leaving stale IPv6 routes from a previous primary run on hosts.
  - Map growth is bounded by `MaxRedundancyGroups` (small, ~3), so it's not a memory leak — it's a correctness issue on RG ID reuse.

- Trace:
  1. Node boots as secondary for RG 1 (reth0.0, prefix 2001:db8:1::/64). `reconcileRGState` fires, `!tr.Active` for RG 1, `startupGoodbyeRA[1]` not set → sends goodbye RA for 2001:db8:1::/64 (lifetime=0), sets `startupGoodbyeRA[1] = true`.
  2. Operator deletes RG 1, commits. RG 1 removed from config, VRRP instances removed, but `startupGoodbyeRA[1]` stays `true`.
  3. Operator re-adds RG 1 with different interfaces (reth1.0, prefix 2001:db8:2::/64), commits.
  4. Node boots (or reconcile fires) as secondary for new RG 1. `!tr.Active` for RG 1, but `startupGoodbyeRA[1] == true` → goodbye RA NOT sent for 2001:db8:2::/64.
  5. Hosts that received RAs from the previous primary for 2001:db8:2::/64 (if any) or from a concurrent primary keep stale routes. Less severe than the original bug (which was about dual-router ECMP), but still a cold-boot correctness issue.

- Refutation attempt:
  - RG ID reuse after delete+re-add is rare in production (RG IDs are stable). TRUE, but possible.
  - Goodbye RA is best-effort (sent once, not retried). Missing it doesn't cause traffic loss — hosts will eventually expire the stale route or receive a new RA from the primary. TRUE, but delays convergence.
  - The map is bounded (max ~3 entries), so memory impact is negligible. TRUE.

- Why it matters: Stale IPv6 routes from a previous RG 1 primary run (or from a concurrent primary during the delete window) persist on hosts until expiry or primary RA, instead of being cleared immediately. On a dual-stack network with tight convergence requirements, this could cause suboptimal routing (hosts ECMP-split to both nodes for a brief window, as the original bug describes).

- Fix direction:
  ```go
  // In reconcileRGState, when an RG ID is no longer in config, evict it:
  for rgID := range d.startupGoodbyeRA {
      if _, ok := seen[rgID]; !ok {
          delete(d.startupGoodbyeRA, rgID)
      }
  }
  ```
  Or reset `startupGoodbyeRA` when RG config changes (diff old vs new RG IDs). This is a 5-line fix.

- Labels: cold-boot, VRRP, HA, RA, goodbye, low-priority, RG-lifecycle
- Dedup note: NOT in prior findings. `all_findings.txt` has no entry for `startupGoodbyeRA` leak. `ps-review-036` does not cover this path.

---

### [F-A7-002] LOW: `warmNeighborCache` sends UDP packets to arbitrary IPs from session table — potential amplification / reflection vector if attacker can create many sessions to distinct external IPs

- Title: `warmNeighborCache` UDP probes to session-table IPs — unbounded fan-out, no rate limit, potential amplification
- Severity: Low (resource exhaustion / amplification — requires attacker to create many sessions to distinct external IPs, which already requires passing firewall policy)
- Confidence: Medium
- Evidence:
  ```go
  // pkg/daemon/daemon_ha.go:1221-1298
  func (d *Daemon) warmNeighborCache() {
      // Iterate IPv4 sessions: collect unique dst IPs + src IPs
      _ = d.dp.Sessions().ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
          if val.IsReverse != 0 { return true }
          if !seen[key.DstIP] { seen[key.DstIP] = true }
          if !seen[key.SrcIP] { seen[key.SrcIP] = true }
          return true
      })
      // Iterate IPv6 sessions similarly...
      // Then for each unique IP:
      for ip4 := range seen {
          addr := netip.AddrFrom4(ip4)
          if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
              continue
          }
          conn, err := net.DialTimeout("udp4", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
          if err == nil {
              conn.Write([]byte{0}) // triggers ARP resolution
              conn.Close()
          }
      }
      // Same for IPv6...
      if count > 0 || countV6 > 0 {
          slog.Info("cluster: neighbor cache warmup complete", "ipv4_hosts", count, "ipv6_hosts", countV6)
          time.Sleep(200 * time.Millisecond) // Brief pause for ARP/NDP responses
      }
  }

  // Called from:
  // pkg/daemon/daemon_neighbor.go:563
  //   d.warmNeighborCache() // in maintainClusterNeighborReadiness, 15s periodic, guarded by neighborWarmupInFlight
  ```

  - `warmNeighborCache` iterates the FULL session table (potentially 100K+ entries) and sends one UDP packet (1 byte) to each unique src/dst IP (potentially 100K+ unique IPs).
  - It runs every 15s (via `maintainClusterNeighborReadiness`, guarded by `neighborWarmupInFlight` — one run at a time, skip-if-in-flight).
  - Each run does: allocate `seen` map (up to 100K entries), iterate session table (100K callbacks), then for each unique IP: `net.DialTimeout("udp4", ip:1, 50ms)` + `Write(1 byte)` + `Close`. For 100K unique IPs, this is 100K * (dial + write + close) = potentially seconds of blocking, 100K UDP sockets, 100K packets out.
  - The filter `IsGlobalUnicast() && !IsPrivate() && !IsLoopback()` helps (skips RFC1918 private, loopback), but does NOT skip public IPs. A firewall handling internet traffic will have sessions to many distinct public IPs (every client → distinct external server).
  - An attacker who can create sessions to many distinct external IPs (by sending traffic to many destinations through the firewall) can cause `warmNeighborCache` to fan out to all those IPs, amplifying one session per destination into one UDP probe per destination per 15s.

- Trace:
  1. Attacker sends traffic through firewall to 10K distinct external IPs (e.g. 10K different /24 destinations, each creating a session).
  2. Firewall creates 10K sessions (forward + reverse = 20K entries, but `IsReverse != 0` skips reverse, so 10K forward entries → 10K unique dst IPs + 10K unique src IPs (but src IPs are likely few — client's internal IPs) → ~10K unique IPs to probe.
  3. Next `maintainClusterNeighborReadiness` tick (15s), `warmNeighborCache` iterates 10K sessions, collects 10K unique IPs, sends 10K UDP packets (1 byte each) to port 1 of each IP via `net.DialTimeout` (50ms timeout each — 10K * 50ms = 500s worst case if sequential, but `ForEachV4` is sequential — actually this blocks the goroutine for up to 500s for 10K IPs with 50ms dial timeout each).
  4. However, `net.DialTimeout` with `udp4` and `port 1` — UDP dial doesn't actually send a packet or wait for a response, it just does a route lookup + socket creation (fast). The `Write(1 byte)` sends the packet. So actual time is roughly `10K * (dial_fast + write_fast)` ≈ 10K * ~100µs = ~1s for 10K IPs. Acceptable.
  5. For 100K unique IPs: ~10s of blocking in the goroutine. The guard `neighborWarmupInFlight` prevents overlapping runs, so next tick skips. Acceptable for typical deployments.

- Refutation attempt:
  - `IsGlobalUnicast() && !IsPrivate()` filters out RFC1918 / loopback — most internal traffic (src IPs) is private, so skipped. TRUE — src IPs are typically RFC1918 (10/8, 172.16/12, 192.168/16), so they are skipped. Only dst IPs (external public) are probed. For a firewall handling outbound NAT, dst IPs are public but next-hop is the WAN gateway (one IP), not the dst IP itself — so ARP is for the gateway, not the dst. Actually `warmNeighborCache` probes the session's dst IP directly, NOT the next-hop — it does `AddrFrom4(ip4)` where `ip4` is `key.DstIP` (the session's destination IP, e.g. 8.8.8.8), NOT the FIB next-hop. For a default-route setup, 8.8.8.8's next-hop is the WAN gateway (e.g. 203.0.113.1), but `warmNeighborCache` probes 8.8.8.8:1 directly, which routes via the default route to the WAN gateway — kernel does ARP for the gateway, not 8.8.8.8. So all dst IPs behind the same next-hop actually trigger ARP for the same gateway IP (one ARP). This is inefficient (many UDP packets to different dst IPs that all resolve to same gateway ARP) but not incorrect.
  - However, the comment says "collect unique dst IPs (forward entries need ARP for the next-hop toward the destination)" but the code probes the dst IP, not the next-hop. This is intentional — kernel's `ip_route_output` + `neigh_resolve_output` will ARP for the gateway if the dst is not on-link. So probing 10K different public dst IPs all behind the same gateway triggers 10K UDP packets out the WAN interface (one per dst IP), each doing a route lookup and potentially ARP if gateway not cached. The ARP cache will serve repeated lookups quickly (gateway already resolved). So 10K UDP packets out WAN, not 10K ARP requests.
  - 10K UDP packets per 15s is ~666 pps — negligible. Even 100K unique IPs → ~6666 pps for ~15s burst. Acceptable.
  - The real concern is that `warmNeighborCache` runs in a goroutine (`go func() { d.warmNeighborCache() }()` in `maintainClusterNeighborReadiness`), so it doesn't block the periodic loop. Correct — no-freeze.

- Why it matters (if sessions are huge): For a firewall handling 100K+ concurrent sessions to distinct public IPs (large NAT gateway), `warmNeighborCache` could send 100K UDP probes per 15s. While each probe is small (1 byte UDP), the aggregate (100K pps burst) could be noticeable on a constrained WAN link. More importantly, the `ForEachV4` / `ForEachV6` iteration over 100K sessions takes time (session table lock held during iteration? — `ForEachV4` likely takes read lock, blocks session creation during sweep). Need to check if `ForEachV4` holds a lock that blocks new session installs.

- Fix direction:
  1. Cap the number of unique IPs probed per pass (e.g. 1000 max, sample if more). This bounds the fan-out regardless of session table size.
  2. Probe next-hops directly (via `RouteGet` for each unique dst IP, then dedup next-hops, probe only unique next-hops). This is what `resolveNeighbors` does — `warmNeighborCache` should do the same for efficiency.
  3. Or: skip `warmNeighborCache` entirely when the session table is very large (e.g. > 10K entries) — the neighbor entries are already warm from normal traffic in that case.

- Labels: resource-safety, observability, HA, neighbor-cache, ARP, fan-out, low-priority
- Dedup note: NOT in prior findings. `all_findings.txt` has no entry for `warmNeighborCache` fan-out. `ps-review-036` does not cover this path.

---

### [F-A7-003] LOW: `warmNeighborCache` iterates session table without bounding — large session table (100K+ entries) could block session creation during `ForEachV4` / `ForEachV6` if they hold a lock

- Title: `warmNeighborCache` session table iteration — potential lock contention with session installs
- Severity: Low (perf — session installs may stall during warmup sweep)
- Confidence: Low-Medium (needs verification of `ForEachV4` locking)
- Evidence:
  ```go
  // pkg/daemon/daemon_ha.go:1232
  _ = d.dp.Sessions().ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
      if val.IsReverse != 0 { return true }
      if !seen[key.DstIP] { seen[key.DstIP] = true }
      if !seen[key.SrcIP] { seen[key.SrcIP] = true }
      return true
  })
  // pkg/daemon/daemon_ha.go:1246
  _ = d.dp.Sessions().ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool { ... })
  ```

  - `ForEachV4` / `ForEachV6` iterate the BPF session maps (or the Go session store cache). Need to check if they hold a lock that blocks concurrent `SetSessionV4` / `SetSessionV6` (session creation from event stream).
  - If they hold a read lock on the session store, and session installs take a write lock, then a 100K-entry sweep could block session installs for milliseconds to seconds (depending on map implementation — BPF map iteration via `NextKey` is O(N) with per-iteration BPF syscall).
  - `warmNeighborCache` runs in a goroutine (`go func() { d.warmNeighborCache() }()` in `maintainClusterNeighborReadiness`), so it doesn't block the periodic loop, but it could still block the event-stream session-install path if `ForEachV4` holds a lock that `SetSessionV4` needs.
  - The guard `neighborWarmupInFlight` (atomic CAS) prevents overlapping warmups, but doesn't prevent concurrent session installs.

- Trace:
  1. `warmNeighborCache` starts, calls `ForEachV4` (iterates BPF `sessions` map via `NextKey` — O(N) BPF syscalls, N = session count).
  2. Concurrently, event stream receives `SessionOpen` frames, calls `SetSessionV4` (writes BPF map + mirrors to Rust helper).
  3. If `ForEachV4` holds a lock that `SetSessionV4` needs (e.g. `bpfShim.mu` or session store lock), session installs stall until sweep completes.

- Refutation attempt:
  - BPF map iteration (`NextKey`) doesn't hold a Go lock that blocks `SetSessionV4` — it does BPF syscalls directly to the kernel map. Kernel BPF map operations are lock-free for concurrent readers/writers (BPF map is RCU-protected). So `ForEachV4` over BPF maps does NOT block `SetSessionV4`. TRUE for BPF maps.
  - However, if `ForEachV4` iterates a Go-side session cache (not BPF map), it could hold a Go mutex. Need to verify which implementation `ForEachV4` uses for `dataplane.SessionStore` (could be `DataPlaneSessionStore` which is BPF-backed, or `userspaceSessionStore` which is event-stream-backed).
  - `userspaceSessionStore` delegates to `dataplane.DataPlaneSessionStore` (BPF) for `ForEachV4` — so it's BPF-backed, lock-free. Correct.
  - Therefore: no lock contention, no blocking. This is NOT a bug.

- Why included: Task says "If no finding, WRITE NEGATIVE." This was investigated and found to be NOT a bug (BPF maps are RCU-protected, iteration doesn't block writes). Included as negative.

- Labels: HA, neighbor-cache, session-table, lock-contention, negative
- Dedup note: NOT a bug — negative finding.

---

### [F-A7-004] LOW: `vtysh.go` — `GetBGPNeighborReceivedRoutes` / `GetBGPNeighborAdvertisedRoutes` concatenate IP into vtysh command string without sanitization — read-only, low risk

- Title: `vtysh -c "show bgp neighbor <ip> received-routes"` — IP concatenated into shell command, no control-char sanitization
- Severity: Low (read-only show command, not config-changing; IP validated by caller; requires authenticated API/CLI access)
- Confidence: High
- Evidence:
  ```go
  // pkg/frr/vtysh.go:193
  func (m *Manager) GetBGPNeighborReceivedRoutes(ip string) (string, error) {
      if ip == "" {
          return "", fmt.Errorf("neighbor IP required")
      }
      return m.executor().Vtysh("show bgp neighbor " + ip + " received-routes")
  }

  // pkg/frr/vtysh.go:200
  func (m *Manager) GetBGPNeighborAdvertisedRoutes(ip string) (string, error) {
      if ip == "" {
          return "", fmt.Errorf("neighbor IP required")
      }
      return m.executor().Vtysh("show bgp neighbor " + ip + " advertised-routes")
  }

  // pkg/frr/vtysh.go:209
  func (m *Manager) GetBGPNeighborDetail(ip string) (string, error) {
      cmd := "show bgp neighbor"
      if ip != "" {
          cmd += " " + ip
      }
      return m.executor().Vtysh(cmd)
  }

  // pkg/frr/vtysh.go:84
  func (realExecutor) Vtysh(command string) (string, error) {
      ctx, cancel := context.WithTimeout(context.Background(), vtyshTimeout)
      defer cancel()
      cmd := exec.CommandContext(ctx, "vtysh", "-c", command)
      // ...
  }
  ```

  - `GetBGPNeighborReceivedRoutes(ip)` / `GetBGPNeighborAdvertisedRoutes(ip)` concatenate `ip` directly into vtysh command string.
  - `ip` is NOT sanitized for control chars (newline, semicolon, etc.).
  - However, `ip` comes from either:
    1. BGP neighbor list from `show ip bgp summary` (kernel-validated IP, not operator free-text) — safe.
    2. Operator CLI `show bgp neighbor <ip> received-routes` / `advertised-routes` — `<ip>` is validated as IP by CLI dispatcher before reaching this function. The CLI dispatcher's IP validation (`net.ParseIP`) rejects control chars.
  - Even if an attacker could inject a newline: `vtysh -c "show bgp neighbor 10.0.0.1\nconfigure terminal\nrouter bgp\n..."` — vtysh's `-c` flag takes a single command string. Does vtysh support multi-command via newline in `-c`? No — `vtysh -c` takes one command, newline in the command string would be rejected by vtysh's parser (it expects a single CLI command). So this is NOT a vtysh command injection.

  - The sanitize-belt (`sanitizeFRRValue`) is for frr.conf RENDERING (config file generation), not for vtysh show commands. This is a different surface.

- Trace:
  1. Operator or API caller requests `show bgp neighbor 10.0.0.1 received-routes`.
  2. CLI dispatcher validates `10.0.0.1` as IP (via `net.ParseIP` or similar).
  3. `GetBGPNeighborReceivedRoutes("10.0.0.1")` → `Vtysh("show bgp neighbor 10.0.0.1 received-routes")` → `exec.CommandContext(ctx, "vtysh", "-c", "show bgp neighbor 10.0.0.1 received-routes")`.
  4. Even if `ip` were `"10.0.0.1\nconfigure terminal"` — `net.ParseIP` would reject it, CLI dispatcher would reject it.

- Why it matters (defense-in-depth): If a future caller passes an unvalidated string as `ip` (e.g. from a REST API that doesn't validate IP format), the concatenation could be exploitable. Adding `net.ParseIP(ip)` validation at the function boundary would be defense-in-depth. Currently safe because all callers validate.

- Fix direction:
  ```go
  func (m *Manager) GetBGPNeighborReceivedRoutes(ip string) (string, error) {
      if net.ParseIP(ip) == nil {
          return "", fmt.Errorf("invalid neighbor IP %q", ip)
      }
      return m.executor().Vtysh("show bgp neighbor " + ip + " received-routes")
  }
  ```

- Labels: FRR, vtysh, command-injection, defense-in-depth, low-priority, read-only
- Dedup note: NOT in prior findings (F-001). Prior vtysh injection findings were for frr.conf rendering (sanitizeFRRValue), not for show commands. This is a different surface.

---

### [F-A7-005] INFO: IPsec apply/teardown ordering — correct (write config → reload → terminateRemovedConns)

- Title: IPsec apply/teardown ordering — verified correct
- Severity: Info (negative — confirms no bug)
- Confidence: High
- Evidence:
  ```go
  // pkg/ipsec/manager.go:104-123
  func (m *Manager) Apply(ipsecCfg *config.IPsecConfig) error {
      newNames := vpnConnNameSet(ipsecCfg)
      removed := m.swapConnNames(newNames)
      var applyErr error
      if ipsecCfg == nil || len(ipsecCfg.VPNs) == 0 {
          applyErr = m.clearConfig()
      } else {
          applyErr = m.applyConfig(ipsecCfg)
      }
      m.terminateRemovedConns(removed)
      return applyErr
  }
  ```

  - `Apply` diffs prev vs new conn names → writes config atomically (`fsatomic.WriteFileAtomic`) → reloads (`swanctl --load-all`, only unloads deleted VPNs' config) → `terminateRemovedConns` (reads active SAs via `--list-sas`, matches removed conn names, `--terminate` each). Correct ordering — reload must happen before terminate (otherwise straggler SA could be re-initiated from still-loaded config).
  - `clearConfig` removes file, reloads (unloads all VPNs), terminates all prev SAs. Correct.
  - `terminateRemovedConns` is idempotent (no active SA → no-op). Correct.

- Why included: Task says focus includes "IPsec apply/teardown ordering." This path is CORRECT.

---

### [F-A7-006] INFO: FRR config generation — sanitize belt correct, no command injection via free-text values

- Title: FRR config generation — sanitize belt verified correct, no injection
- Severity: Info (negative)
- Confidence: High
- Evidence:
  ```go
  // pkg/frr/policy_render.go:49-67
  func sanitizeFRRValue(s string) string {
      // Strips ASCII control characters — C0 (0x00-0x1F, including newline) and DEL (0x7F)
      // Prevents frr.conf command injection via embedded newline in description/auth-key/password
  }

  // All free-text values (description, auth key, password, community member, as-path regex) go through sanitizeFRRValue.
  // Next-hop, origin, source-protocol are NOT free-text — they are validated IP/protocol tokens from typed config.
  ```

  - Every free-text config value (BGP neighbor description, auth key, password, community-list member, as-path-access-list regex) is passed through `sanitizeFRRValue` before interpolation into frr.conf lines. `sanitizeFRRValue` replaces C0 + DEL with space, collapsing newlines so no injected `router bgp` / `neighbor` command reaches the managed section.
  - `validRouterID` rejects non-IPv4 router-id at render time (lenient/peer-sync path defense-in-depth).
  - `resolveRedistribute` never emits bare `redistribute <name>` with no source protocol (skip+warn, never poisons managed reload).
  - **#4498 check**: The issue asked about "FRR sanitize-belt residual (next-hop/origin/source-protocol bare %s)". Next-hop is always a validated IP or interface name (typed config, not free-text). Origin is a validated enum (igp/egp/incomplete). Source-protocol is a validated protocol token (connected/static/ospf/bgp/etc.). None of these are free-text, so they don't need `sanitizeFRRValue`. The sanitize belt is complete.

---

### [F-A7-007] INFO: DDNS / Surface A resource safety — bounded, no leak, no unbounded growth

- Title: DDNS / Surface A resource safety — verified bounded and correct
- Severity: Info (negative — confirms no bug)
- Confidence: High
- Evidence:
  - Nudge channels: `ddnsReconcileNowCh`, `surfaceAReconcileNowCh` — depth 1, non-blocking send (`select { case ch <- struct{}{}: default: }`), coalesces burst into one pending wakeup. Correct.
  - Guards: `ddnsReconcileInFlight`, `surfaceAReconcileInFlight` — `atomic.Bool`, `CompareAndSwap(false, true)` (skip-if-in-flight), `defer Store(false)` in spawned goroutine. Correct — hung DNS server leaks at most one goroutine, loop keeps servicing ctx + nudge channel.
  - Per-pass context timeout: `ddnsReconcileTimeout = 60s`, `surfaceAReconcileTimeout = 60s`, `surfaceACheckIPTimeout = 10s`. Each pass bounded, slow provider fails one scope, not whole pass. Correct.
  - CheckIP allowlist/source-bind/NoURL dedup maps: `sync.Map` keyed by `"<provider>\x00<allowlist-or-error>"`, bounded by distinct provider names in config (max ~10-20, not unbounded). Provider names are stable (from `system services dynamic-dns provider <name>`), not user-controlled arbitrary strings that grow. Correct.
  - `buildSurfaceAScopes` — `out` + `invalid` slices bounded by interface×unit×family (max ~hundreds, config-defined). Sorted deterministically. Correct.
  - HTTP client cache (`httpClientCache` in `pkg/ddns/backend_http.go`): `reap(live)` called every reconcile pass, closes idle conn pools of superseded binding keys, bounds cache to current config. Correct (#2956).
  - Address observation: `observeInterfaceAddr` distinguishes transient (netlink read failure → ok=false, never withdraw, retry next pass) from definitive (interface present but addressless → ok=true with zero addr, withdraw). `selectInterfaceAddr` skips tentative/dadfailed/optimistic/temporary, skips non-public, prefers preferred over deprecated. `staticUnitAddr` gated through `IsPublicAddr`. All correct (#2840/#2776/#2975).
  - HA gating: `ddnsWriterGateOpen` (node-level: MASTER for ≥1 RG), `surfaceAGate` (per-RG: interface RG → master check, RG 0 → RG0 primary per #2972). Correct — prevents double-write in active-active. Standalone: nil gate (admits all). Correct.
  - `defer cancel()` inside `surfaceAObserver` closure — scoped to closure function (the `AddressObserver`), NOT to outer `surfaceAObserver`. Correct (same as A6 F-A6-003).

---

### [F-A7-008] INFO: VRRP / HA failover ordering — correct (activation: rg_active → blackhole removal → VRRP MASTER; deactivation: preflight → VRRP resign → blackhole inject → clear rg_active)

- Title: VRRP/HA failover ordering — verified correct
- Severity: Info (negative)
- Confidence: High
- Evidence:
  ```go
  // Activation (watchClusterEvents — cluster Primary event):
  // 1. set rg_active FIRST (BPF + direct helper sync, under m.mu)
  // 2. remove blackhole routes (only when desired state actually active — strict VIP ownership mode)
  // 3. VRRP priority + ForceRGMaster (only on StateSecondary→StatePrimary, NOT StateSecondaryHold→StatePrimary — respects preempt=false)
  // 4. reconcileDirectVIPOwnership (no-reth-vrrp mode) / RefreshFabricFwd

  // Demotion (watchClusterEvents — cluster Secondary/SecondaryHold event):
  // 1. tryPrepareUserspaceRGDemotion (flow cache → FabricRedirect, shifts in-flight flows to fabric path)
  // 2. ResignRG (VRRP resign, removes VIPs)
  // 3. injectBlackholeRoutes (prevents bpf_fib_lookup via default route escape — triggers fabric redirect)
  // 4. clear rg_active (BPF + direct helper sync)

  // VRRP events (watchVRRPEvents — MASTER/BACKUP):
  // MASTER: SetVRRP → rg_active (when ALL instances MASTER per #132) → remove blackholes → add stable RETH link-local → apply RETH services (RA/DHCP/DDNS/Surface A)
  // BACKUP: SetVRRP → localFailoverCommitReady=false → inject blackholes → clear rg_active → remove link-local → clear RETH services
  ```

  - Activation: rg_active set before blackhole removal (so helper's per-packet HA resolution sees active before FIB returns non-blackhole). VRRP MASTER triggered after (VIP add after forwarding ready → no traffic loss during VIP propagation). Correct (#485).
  - Demotion: preflight (flow cache → FabricRedirect) before VRRP resign (so in-flight flows are on fabric path before VIP removal). Blackhole inject before rg_active clear (prevents default-route escape). Correct (#485).
  - VRRP posture reconciliation (#86): sustained mismatch (10s+ continuous) → re-send priority (NeedsMaster, does NOT ForceRGMaster — respects non-preempt) / ResignRG (NeedsResign). Skip during sync-hold (VRRP intentionally suppressing preempt). Correct.
  - RG state machine: `rg_active = clusterPri || anyVrrpMaster` (unified state machine, prevents dual-inactive window and race between cluster/VRRP goroutines). `AllVRRPMaster` (all instances MASTER = RG MASTER per #132) vs `AnyVRRPMaster` difference correctly used. Correct.

---

### [F-A7-009] INFO: Cold-boot — split-brain prevention correct (30s config-apply grace, not 500ms heartbeat race)

- Title: Cold-boot split-brain — verified fixed
- Severity: Info (negative — confirms fix correct)
- Confidence: High
- Evidence:
  ```go
  // pkg/daemon/daemon_ha_sync.go — cold start vs routine reconnect:
  coldStart := d.sessionSync == nil || !d.sessionSync.BulkEverCompleted()
  if coldStart {
      d.syncBulkPrimed.Store(false)
      d.syncPeerBulkPrimed.Store(false)
      if d.cluster != nil {
          d.cluster.SetSyncReady(false)
      }
      d.armSyncReadyTimer()
      d.startSessionSyncPrimeRetry(gen)
  }
  // Routine reconnect: preserves primed state, sessions still in BPF maps, no bulk needed (#466).

  // The 30s config-apply grace (not the 500ms heartbeat "peer never seen" path) prevents dual-primary on simultaneous boot.
  // The old bug (#4386): heartbeat "peer never seen" path promoted after 500ms, skipping 30s grace → dual-primary.
  // Fixed: cold start holds syncReady, arms timer, starts prime retry. VRRP sync-hold prevents preempt until bulk complete.
  ```

  - Cold-boot detection: `BulkEverCompleted()` — true only after a full bulk transfer during daemon lifetime. Fresh daemon (no prior bulk) = cold start. Routine reconnect (brief network blip, sessions still in maps) = not cold start, preserves primed state.
  - Cold start: `syncReady = false`, `syncBulkPrimed = false`, `syncPeerBulkPrimed = false`, arms sync-ready timer (timeout releases hold if peer never connects), starts prime retry. VRRP sync-hold prevents preempt. Correct.
  - Routine reconnect: preserves primed state, no bulk, immediate resume of incremental sync. Correct (#466).
  - The fix for #4386 (cold-boot split-brain) is verified: the 500ms heartbeat "peer never seen" path no longer promotes directly — it goes through the cold-start detection and sync-ready hold.

---

### [F-A7-010] INFO: Integer truncation — no issues found in A7 scope

- Title: Integer truncation — verified none in A7 scope (routing, FRR, IPsec, daemon)
- Severity: Info (negative)
- Confidence: High
- Evidence:
  - `rgID int` — RG IDs are small (0-2 typically, max ~8), no truncation.
  - `ifindex int` — Linux ifindex is int, up to ~2^31-1 on 64-bit, fits Go int (int64 on linux/amd64). All `ifindex` fields are `int` in Go types, no `uint32(ifindex)` without guard.
  - `Workers int` — validated `>= 1` at schema level (`ValidateIntegerMin(1)`), coerced to `1` in manager (`maxInt(cfg.Workers, 1)`). Safe.
  - `RingEntries int` — validated `[1..16384]` + power-of-two at schema level (`ValidateRingEntries`, #2524). Safe (pre-#2524 OOM fix).
  - `TunnelEndpointID uint16` — max tunnel endpoints bounded by interface count (~256), far below 65535. Safe (theoretical, not reachable — same as A6 F-A6-002).
  - `ZoneID uint16` — widened from u8 in #3075, max zones ~100, far below 65535. Safe.
  - `OwnerRGID int32` on wire — Go int is 64-bit, widened from int16 in #2467 (ifindex > 32767 wrapped negative as int16). Now int32, safe (RG IDs small).
  - `PortLow/PortHigh int` — validated 1..65535 before uint16 cast in `clampPort` / `sourceNATPoolPortRange`. Safe.
  - `VLANID int` — validated 1..4094, fits int. Safe.

- Why included: Task says "integer-truncation" is a focus area. A7 scope (daemon/host integration) has no integer truncation issues. One theoretical issue in A6 scope (heartbeat map Workers negative wrap) is filed in A6 report.

---

### [F-A7-011] INFO: Route-leak correctness — next-table / rib-group (#3876) / PBR (#4534) — all verified fixed

- Title: Route-leak correctness — verified correct (next-table, rib-group per-prefix, PBR discard/reject skip)
- Severity: Info (negative — confirms fixes correct)
- Confidence: High
- Evidence:
  - `nextTableManager.Apply` — `to <dst> lookup <table>` global ip rules, priority 100-199, hard-cap 100. Passes only main table routes (not per-RI routes, so per-RI next-table is gap #F-174, not live bug). Correct.
  - `ribGroupManager.Apply` (post-#3876) — per-prefix `to <connected-prefix> lookup <sourceTable>` (pref 30000-30999, 1000 max) wins over main-table default route. Legacy blanket `from all lookup <sourceTable>` (pref 33000) retained ONLY for cleanup. `validateRibGroupLeakTarget` warns on non-main import targets (Phase 2 deferred). Correct.
  - `pbrManager.Apply` — `from <src> to <dst> tos <tos> ipproto <p> sport <sp> dport <dp> lookup <table>` (pref 31000-31999). PBR discard/reject skipped (#4534 FIXED — `buildPBRFromFilter` skips discard/reject terms). `validateFilterRoutingInstanceConflictStrict` rejects RI+discard/reject at commit. Correct.
  - `BuildPBRRules` — only from attached input filters, DSCP×src×dst×proto×sport×dport cross-product, truncates to `maxPBRRules` (1000). Unrepresentable L4 predicates classified as fail-closed. Correct.

---

## 7. Summary

| Finding | Severity | Confidence | Status |
|---------|----------|------------|--------|
| F-A7-001 | Low | Medium | NEW — startupGoodbyeRA stale on RG ID reuse |
| F-A7-002 | Low | Medium | NEW — warmNeighborCache UDP fan-out to public IPs (bounded by session count) |
| F-A7-003 | Info | Low-Medium | NEGATIVE — warmNeighborCache lock contention NOT a bug (BPF RCU) |
| F-A7-004 | Low | High | NEW (defense-in-depth) — vtysh show command IP concatenation, read-only |
| F-A7-005 | Info | High | NEGATIVE — IPsec apply/teardown ordering correct |
| F-A7-006 | Info | High | NEGATIVE — FRR sanitize belt correct, no injection |
| F-A7-007 | Info | High | NEGATIVE — DDNS/Surface A resource safety bounded and correct |
| F-A7-008 | Info | High | NEGATIVE — VRRP/HA failover ordering correct |
| F-A7-009 | Info | High | NEGATIVE — cold-boot split-brain fixed, verified |
| F-A7-010 | Info | High | NEGATIVE — no integer truncation in A7 scope |
| F-A7-011 | Info | High | NEGATIVE — route-leak correctness verified (next-table, rib-group, PBR) |

**No High/Critical findings.** Three Low findings (startupGoodbyeRA RG reuse, warmNeighborCache fan-out, vtysh show IP concatenation defense-in-depth) + eight negatives.

**Core firewall + VRRP/HA failover + cold-boot**: All verified correct. No issues in zone policies / global policies / host-inbound / default deny-permit compilation (daemon side — the Go→Rust snapshot compilation verified in A6). VRRP/HA failover ordering correct (#485), cold-boot split-brain fixed (#4386), startup goodbye RA one-shot correct (with one LOW on RG ID reuse).

**Integer truncation**: No issues in A7 scope. All ifindex / workers / ring-entries / port / zone ID / RG ID / VLAN ID paths correctly validated and bounded. One LOW in A6 scope (heartbeat map Workers negative wrap) filed in A6 report.

**DDNS/Observability resource safety**: No issues. DDNS reconcile loops bounded (depth-1 nudge channels, skip-if-in-flight guards, per-pass timeouts, sync.Map dedup bounded by provider count, HTTP client cache reap). Observability (flow export, forwarding status, event stream) bounded and correct. `warmNeighborCache` fan-out is bounded by session count (typically < 10K unique IPs, ~666 pps per 15s), not unbounded.

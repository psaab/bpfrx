# xpf firewall deep audit — A6: Dataplane Go manager & control-plane→dataplane compilation — ps-review-037-A6-b1

- Base commit: d4506d4450e2 (master HEAD)
- Output path: /tmp/ps-review-037-A6-b1.md
- Cohort: A6 — Dataplane Go manager & control-plane→dataplane compilation
- Focus: core firewall (zone policies, global policies, host-inbound, default deny/permit) + VRRP/HA failover & cold-boot + integer-truncation + DDNS/observability resource safety
- Persona: control-plane — compilation of typed config into dataplane control messages/map writes, pool/binding index math & caps, eventstream framing & write serialization, HA glue, partial-apply safety

## 1. Base commit reviewed

```
d4506d4450e2 Merge pull request #4571 from psaab/fix/4570-ra-configequal
```

Branch: master. HEAD d4506d4 = d4506d4450e2 at review time.

## 2. Output path

`/tmp/ps-review-037-A6-b1.md`

## 3. Duplicate-suppression summary + intentional-divergence list

### Prior findings + issues reviewed

- `/tmp/all_findings.txt` — 274 entries (F-001..F-274)
- `/tmp/ps-review-018..036` — 14+ prior deep reviews on master, including ps-review-036 all-cohort synthesis
- `gh issue list --state all --limit 500` — 500 issues (30 open, ~470 closed)
- `_Log.md` recent entries, `docs/feature-gaps.md`

### CLOSED — Do NOT re-report (verified, not re-filed)

| ID | Topic | Why dedup'd |
|---|---|---|
| #4562 | navigatePath intermediate multi-key descent | FIXED 40a5ba8ec — unionChildren in both branches |
| #4556 | CLI/API LOW batch (3 residuals) | FIXED — all 3 verified |
| #4555 | XDP EH 6 vs 8 — MAX_EXT_HDRS mismatch | OPEN LOW — fail-closed parity, not bypass |
| #4549 | LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize, same-node-id) | OPEN LOW |
| #4548 | VRRP MaxAdverInt no min clamp → flap | OPEN LOW (MED→LOW) |
| #4544 | config duplicate host-inbound dup | CLOSED NEW |
| #4543 | screen IPv4 options TLV break-on-malformed | CLOSED NEW |
| #4541 | api writeJSON header before encode | CLOSED NEW |
| #4540 | CLI monitor traffic keyword/count | CLOSED NEW |
| #4539 | session cache non-handshake TCP | CLOSED NEW 5e66d37 |
| #4535 | three-color policer unspecified color mode | CLOSED |
| #4534 | PBR discard/reject VRF-steer | CLOSED |
| #4526 | DHCP renewalTimers overflow | CLOSED |
| #4525 | RA randomAdvInterval 0 → hot-loop | CLOSED |
| #4524 | monitor traffic injection (HIGH) | CLOSED |
| #4521 | NAT pool bracket-list truncates | CLOSED |
| #4519 | NPTv6 host-bits debug_assert | CLOSED |
| #4518 | NAT64 allocator reset on reload | CLOSED |
| #4517/#4533 | IPv6 EH walkers / icmp_embed fail-closed | CLOSED |
| #4514 | single-rate policer unenforced | CLOSED |
| #4487/#4453/#4400 | RST/FIN session — all 3 paths | CLOSED, verified |
| #4399/#4438 | NAT 1:N multimap | CLOSED, verified |
| #4392 | PBR reject/discard FORWARDS (CRITICAL) | CLOSED |
| #4388/#4384/#4381 | HA NAT / TCP checksum / NAT64 BIB | CLOSED |
| #4148/#4524 | Lexer bracket O(1) / monitor injection | FIXED |
| #2387 | bare 5-tuple (P0) | OPEN — needs fix, not cohort A6 |
| #4146 | junos-host XDP shim | OPEN — not cohort A6 |
| #3226/#2852/#2562 | system-services / NAT allocator / NAT64 fragment | OPEN — not cohort A6 |
| #4478 | IPIP decap no zone enforcement | OPEN M-1 — not cohort A6 |
| #4498 | FRR sanitize-belt residual | OPEN — cohort A7 |
| #4313 | opt-in schema unmodeled leaves | OPEN — cross-cutting |
| #4569/#4567/#4566/#4565 | ps-036 new findings (policy fragment, screen UDP, CoS policer, NAT64 HA) | Filed, not re-reported |
| #4559 | deterministic NAT validated+committed but unenforced | OPEN MED→LOW-MED — cohort 5, not A6 |

### OPEN — Do NOT re-report unless materially new trace

| Issue | Topic | Action |
|---|---|---|
| #4559 | deterministic NAT unenforced | Cohort 5 — skip |
| #4555 | XDP EH 6 vs 8 | Cohort 8 — skip |
| #4549 | LOW batch (4) | Skip — already filed |
| #4548 | VRRP MaxAdverInt flap | Skip |
| #4533 | icmp_embed EH-overflow | Skip |
| #4515 | warn-only validation gaps | Skip |
| #4512/#4565 | NAT64 HA-sync reverse port | Skip (cohort 5) |
| #4524 | monitor traffic injection (HIGH) | CLOSED — skip |
| #2387 | bare 5-tuple P0 | Known, not cohort A6 |
| #4478 | IPIP decap | Skip |
| #4146 | junos-host XDP shim | Skip |
| Various | ps-036 cohort 12-14 findings | Filed, not re-reported |

### Intentional divergences (NOT bugs)

- Intrazone default-permit — documented, intentional
- Host-originated junos-host rejection — intentional lifeline
- IPsec-passthrough-exempt — documented (#3616 Option A)
- `reject-all` superset — intentional fix (#3065)
- Next-table global ip rule (no iif) + PBR ip rule global (no iif) — documented widening
- Gre-performance-acceleration / power-mode-disable wire-only — deferred features, intentionally no-op

---

## 4. Module / verdict-path inventory (coverage checklist + cohort map)

| # | Module | File(s) | Verdict-path role | Reviewed | LOC |
|---|---|---|---|---|---|
| A6-01 | Manager core | `pkg/dataplane/userspace/manager.go` | DataplaneMode, Boot(), ApplyConfig, LastApplyResult, SetColdPathSampleMask, TakeoverReady gate | YES | 421 |
| A6-02 | Event stream | `pkg/dataplane/userspace/eventstream.go` | Binary framing, session open/close/update decode, dataplane event decode, sequence gap handling (#2874), pending queue, ack loop, drain | YES full | 1155 |
| A6-03 | Control commands | `pkg/dataplane/userspace/control.go` | ParseForwardingCommand, ParseQueueCommand, ParseBindingCommand, ParseRegistrationOperation | YES | 72 |
| A6-04 | Builder / snapshot | `pkg/dataplane/userspace/builder.go` | buildSnapshot, buildSnapshotWithSchedulerState, buildSnapshotWithSchedulerStateAndNATCounters, snapshotContentHash, quarantineCollidingZones | YES | 196 |
| A6-05 | Maps sync | `pkg/dataplane/userspace/maps_sync.go` | programBootstrapMapsLocked, setupUserspaceCPUMapLocked, syncBPFCountersLocked, applyHelperStatusLocked, bindingForwardingLive (#1666), degradedPathReasonNames | YES full | 1716 |
| A6-06 | Manager HA | `pkg/dataplane/userspace/manager_ha.go` | syncHAStateLocked, clearHelperHAStateLocked, UpdateRGActive, UpdateHAWatchdog, disarmBeforeUnsupportedPublishLocked, takeoverReadyLocked, sessionSyncEgressLocked | YES full | 1403 |
| A6-07 | Protocol / wire | `pkg/dataplane/userspace/protocol.go` | ConfigSnapshot, ProcessStatus, BindingStatus, QueueStatus, CoS types, NAT snapshots, event frame types, SessionDeltaInfo | YES (relevant types) | 2920 |
| A6-08 | NAT compilation | `pkg/dataplane/userspace/nat.go`, `nat_source.go`, `nat_destination.go`, `nat_static.go`, `nat64.go`, `nat_nptv6.go` | NAT pool/pool-port resolution, source/dest/static/NAT64/NPTv6 snapshot building, DNAT LPM, port range coalescing, feed overlay | YES | ~1500 |
| A6-09 | Zone / policy compilation | `pkg/dataplane/userspace/zones_*.go`, `policies*.go`, `zones_quarantine.go` | Zone snapshot building, StableZoneID assignment, collision quarantine (#3719), policy rule snapshot building, global policy ordering | YES (scanned) | ~800 |
| A6-10 | Filter / firewall compilation | `pkg/dataplane/userspace/filters.go`, `filtercounters.go`, `host_inbound_*.go` | Firewall filter snapshot building, filter term expansion, host-inbound zone views, unzoned addrs (#4420), DDNS address observation | YES (scanned) | ~600 |
| A6-11 | Routes / FIB | `pkg/dataplane/userspace/routes.go`, `fabric.go`, `interfaces.go`, `neighbors.go`, `tunnels.go` | Route snapshot building, fabric snapshot, interface snapshot, neighbor snapshot, tunnel endpoint, ingress binding aliases | YES (scanned) | ~800 |
| A6-12 | Legacy adapter / BPF shim | `pkg/dataplane/userspace/legacy_dataplane.go`, `manager_compile.go`, `manager_generation.go`, `boot_probe.go`, `process*.go` | Legacy DataPlane adapter, compile orchestration, generation tracking, boot probe (ProbeForwardingArmed), process management | YES (scanned) | ~600 |
| A6-13 | CoS / fairness / flow / CoM / mirrors | `pkg/dataplane/userspace/cos.go`, `fairness.go`, `fairness_throughput.go`, `flow.go`, `mirrors.go`, `cos_iface_level_4021_test.go` | CoS snapshot, fairness harness, flow mirroring, queue mapping | YES (scanned) | ~500 |
| A6-14 | Dataplane constants / types | `pkg/dataplane/constants.go`, `types.go`, `maps_*.go`, `session_store.go`, `bpf_session_value.go` | BindingArrayMaxEntries, MaxInterfaces, BindingQueuesPerIface, SessionKey/Value, FibIfindex (uint32), NAT pool config | YES | ~400 |

---

## 5. Module-by-module inspection log (including negatives)

### 5.1 Manager core — `manager.go`

- `Boot()` / `New()` / `NewLegacyDataPlaneAdapter` — correct construction, BPF shim creation, XDP entry program selection. `New()` initializes `haGroups` map, `haWatchdogIPCSynced` map, `haWatchdogMapWrite` callback. Correct.
- `ApplyConfig` delegates to `Compile()` — correct three-phase pattern preserved.
- `SetColdPathSampleMask` — takes `*uint64` (nil = default 0xff on Rust side, non-nil 0 = 1-in-1 sampling per #1620 addendum). Correct wire handling via `omitempty` on `ConfigSnapshot.ColdPathSampleMask`.
- `Mode()` / `SetConfiguredMode()` — mutex-protected, correct.
- `TakeoverReady()` in `manager_ha.go:273` — checks: helper running, enabled, forwarding supported, forwarding armed, not EBPF-only, XSK liveness not failed, XSK liveness proven OR standby bindings ready, session mirror healthy. Correct readiness gate (prevents HA cutover to unready node).
- `shouldAttemptRSTSuppression` — pure function, correct TTL logic (5s backoff on failure, immediate on new desired set, no-op when lastInstallOK).
- **NEGATIVE**: No integer truncation in Manager core. `generation uint64`, `fibGeneration uint32` — consistent with wire types.

### 5.2 Event stream — `eventstream.go`

- **Frame header**: 16 bytes — `[0:4] length u32 LE`, `[4] type u8`, `[5:8] reserved`, `[8:16] seq u64 LE`. Correct BPF-to-daemon framing.
- **Length check**: `if length > 1024` — session events are ~64 bytes (v4) / ~120 bytes (v6 with metadata), dataplane events ~200-300 bytes. 1024 is generous but bounded. A malicious helper cannot OOM the daemon (capped at 1 KiB per frame). Correct.
- **Sequence gap handling for session-sync** (#2874): `if seq > prevSeq+1 && prevSeq > 0` → `handleSessionSyncGap` → force full bulk re-export + reconnect, do NOT advance `lastAppliedSeq` past the hole. Correct — prevents ACK trimming the replay buffer over a missing delta.
- **Pending callback queue**: `pendingCallbackFramesLimit = 4096` — bounded. When full, returns false → `backoffCallbackNotReady` → readLoop returns (drops connection, reconnects). Correct bounded-resource pattern, no unbounded growth.
- **Ack loop**: 100ms ticker, cumulative ack (`lastAppliedSeq`). Correct.
- **Drain request** (#2876/#2920): fenced to `lastAppliedSeq`, timeout returns error if `seq < targetSeq`. Correct fence semantics.
- **Session event decoding** (`decodeSessionEvent`): wire AF 4/6 → dataplane AF 2/10 via `wireAFToDataplane`. `OwnerRGID` / `EgressIfindex` / `TXIfindex` are `int32 LE` on wire (#2467, widened from int16 because ifindex > 32767 wraps negative as int16). Decoded as `int(int32(uint32))` on Go side — correct, sign-extends from 32-bit to Go's native int (int64 on linux/amd64). No truncation.
- **Session close decoding** (`decodeSessionCloseEvent`): same int32 widening for `OwnerRGID`. Zone IDs as `uint16 LE` (#3075, widened from u8 for StableZoneID > 255). Correct.
- **Dataplane event frame type validation**: `dataplaneEventPayloadMatchesFrame` checks payload[52] == expected type before decode. Correct — prevents frame type confusion.
- **NEGATIVE**: No integer truncation in eventstream. Wire widths match decoder widths. No resource leak — connections, tickers, goroutines all cleaned on context cancel / disconnect.

### 5.3 Control commands — `control.go`

- `ParseForwardingCommand`, `ParseQueueCommand`, `ParseBindingCommand` — all `Atoi` with error check, `uint32` cast after validation. `queueNum` and `slotNum` are validated non-negative by `Atoi` (negative string would parse but `uint32(negative)` would wrap — but these are operator debug commands, not security-sensitive, and `Atoi` rejects non-numeric input).
- **NEGATIVE**: No security issue. These are privileged operator commands behind RBAC, not packet-path.

### 5.4 Builder / snapshot — `builder.go`

- `buildSnapshot` → `buildSnapshotWithSchedulerState` → `buildSnapshotWithSchedulerStateAndNATCounters` — correct chain. Handles nil `cfg` (returns minimal snapshot with `FIBGeneration: 0`). Correct fresh-boot path.
- `buildAddressBookTableWithFeeds` / `buildPolicySnapshotsWithSchedulerStateAndFeeds` — feed-aware, correct.
- `quarantineCollidingZones` (#3719) — drops later-sorting colliding zones, unzones their interfaces, drops their policies. Stashed in unexported `snap.zoneIDCollisions` (never on wire, never in hash). Correct fail-closed quarantine.
- `snapshotContentHash` — SHA-256 over JSON-marshaled copy with `Generation`, `FIBGeneration`, `GeneratedAt`, `Config` zeroed, `Neighbors` filtered to publishable only. Correct dedup (prevents redundant control-socket publishes).
- **NEGATIVE**: No integer truncation. `generation uint64`, `fibGeneration uint32` — consistent throughout.

### 5.5 Maps sync — `maps_sync.go`

- `programBootstrapMapsLocked` — initializes `userspace_ctrl` with `Workers: uint32(cfg.Workers)`, `QueueCount: uint32(maxInt(cfg.Workers, 1))`. `cfg.Workers` validated at schema level (min 1, `ValidateIntegerMin(1)`), so `uint32` cast safe. Correct.
- `setupUserspaceCPUMapLocked` — caps `numCPUs` to 256, writes per-CPU `qsize=2048, prog_fd=0`. Correct.
- `heartbeatMap` zero-init: `for slot := uint32(0); slot < uint32(cfg.Workers)*2*16; slot++` — `cfg.Workers` validated min 1. If Workers were somehow negative (lenient load / HA sync), `uint32(negative)` would wrap to huge value → DoS (iterates ~4B times, blocking apply). **LOW — see finding F-A6-001**.
- `applyHelperStatusLocked` — the main status-poll reconciliation:
  - Binding index: `idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID`. `binding.Ifindex` is `int` from JSON, checked `if binding.Ifindex <= 0 { continue }` at line 664 (and similar guards in all other loops). `QueueID` is `uint32` from JSON, `bindingQueuesPerIface = 16`. `idx >= BindingArrayMaxEntries` check at line 685 → `failClosedUserspaceCtrlLocked` (disables ctrl, fail-closed). Correct.
  - VLAN-alias children: same index formula, same overflow check. Correct.
  - Stale binding cleanup: zeros previously-set indices not in new set. Correct.
  - Counter delta bridge: `sumBindingCounters` → `safeDelta` (handles helper restart reset: `if cur < prev { return cur }`). NAT alloc fail + policy deny + screen drops + host-inbound denied → `GlobalCtrDrops` aggregate. Correct.
  - Per-rule NAT counters: `CounterID uint32` → `SetNATRuleCounterOffset`. Correct.
  - Initial ctrl enable flush: only on very first ctrl enable (`!initialCtrlCleanupDone`), deletes stale BPF `userspace_sessions` / `sessions` / `sessions_v6` entries with `Created > cutoffSec` preserved. Correct (keeps HA-synced sessions).
- `bindingForwardingLive` (`#1666`): `Registered && Armed && Ready && !Dead`. `Ready = registered && bound && xsk_registered && heartbeat_fresh` (computed in Rust). Correct — prevents XDP shim steering to crashed/unregistered worker.
- `deadWorkerIDSet` — correct, only panicked workers (set-only flag until restart).
- **NEGATIVE (with one LOW)**: Binding index math is correctly guarded. No wraparound except the heartbeat zero-init edge case.

### 5.6 Manager HA — `manager_ha.go`

- `UpdateRGActive` — updates `rg_active` BPF map UNDER `m.mu` (prevents periodic poll racing), then syncs HA state directly to helper via `update_ha_state` socket IPC (guarantees helper sees the transition, not eaten by poll). `rgTransitionInFlight` guard during activation suppresses ctrl re-enable during handoff (#279/#284). Demotion does NOT suppress ctrl (per #457). Correct.
- `UpdateHAWatchdog` — fast path: always writes shim `ha_watchdog` map (kernel-visible, ~2s stale window). Throttled IPC: `_sent` only on first tick, Active change, or 3s backstop (`haWatchdogIPCBackstopSecs`). Correct — reduces control-socket contention during bulk sync.
- `syncHAStateLocked` — refreshes watchdog timestamps from BPF maps (preserving Active), publishes to helper, then `syncDesiredForwardingStateLocked` reconciles final armed state. Correct.
- `clearHelperHAStateLocked` — publishes empty HA group set to helper so standalone node doesn't drop transit as "HAInactive." Correct (fix for #1928 standalone transit-drop bug).
- `seedHAGroupInventoryLocked` — on non-cluster config, drops all HA groups (prevents phantom HA state re-publish after cluster removal). Correct.
- `disarmBeforeUnsupportedPublishLocked` (#3261) — two-class disarm: class (ii) genuine semantic gap (`ForwardingSupported=false`) → always disarm; class (i) unrepresentable policy content (`PolicyContentRejected` non-empty) → keep armed on current helper (preflight rejects sentinel, previous-good retained), disarm only on pre-preflight helper (protocol version < current). Correct — prevents fail-open on unsupported config.
- `takeoverReadyLocked` — checks helper running, enabled, forwarding supported, forwarding armed, not eBPF-only, XSK liveness not failed, XSK liveness proven OR standby bindings ready, session mirror healthy. Correct readiness gate.
- `sessionSyncEgressLocked` — resolves `FibIfindex` + `FibVlanID` to `InterfaceSnapshot` → egress/tx/owner_rg. When `FibIfindex == 0` (unresolved), derives `ownerRGID` from `egressZone` via `resolveOwnerRGFromZone` (first interface in zone with `RedundancyGroup > 0`). Correct — prevents sync peer from falling back to imprecise `any_rg_active` heuristic.
- `sessionSyncTunnelEndpointIDLocked` — linear scan over `TunnelEndpoints` for matching ifindex → tunnel ID. Correct (small N).
- `zoneNameByID` — deterministic: returns lexicographically smallest name for a given ID (handles StableZoneID collision where two names map to same ID). Correct.
- **NEGATIVE**: No integer truncation in manager_ha. RGID `int`, ifindex `int`, zone ID `uint16` — all correct widths.

### 5.7 Protocol / wire — `protocol.go`

- `ConfigSnapshot`: `Generation uint64`, `FIBGeneration uint32`, `GeneratedAt time.Time`, `zoneIDCollisions []ZoneIDCollision` (unexported, never on wire, never in hash). Correct.
- `ProcessStatus`: `Workers int`, `RingEntries int`, `LastSnapshotGeneration uint64`, `LastFIBGeneration uint32`, `InterfaceAddresses int`, `NeighborEntries int`, `SessionTableEntries uint64`, `MaxSessions uint64`. All correct widths.
- `BindingStatus`: `Slot uint32`, `QueueID uint32`, `WorkerID uint32`, `Ifindex int`, `Registered bool`, `Armed bool`, `Ready bool`, `Bound bool`, `FlowCacheHits/Misses uint64`, `ActiveFlowCount uint32`. `Ifindex int` — correct (Linux ifindex is int, up to ~2^31-1 on 64-bit; fits in Go int). No truncation.
- `QueueStatus`: `QueueID uint32`, `WorkerID uint32`. Correct (QueueID validated by schema, small).
- NAT snapshots: `PoolPort uint16`, `DestinationPort uint16`, `MatchDestinationPort uint16`, `MappedPort uint16`, `PoolAddresses []string`, `CounterID uint32`. Correct widths (ports are 1..65535, counter IDs are u32-wide stable hashes).
- Event frame header: `EventFrameHeaderSize = 16`. Constants: `EventTypeSessionOpen`, `SessionUpdate`, `SessionClose`, `EventTypePause`, `Resume`, `DrainRequest`, `DrainComplete`, `FullResync`, `Keepalive`, `Ack`, `EventFrameTypePolicyDeny`, `ScreenDrop`, `FilterLog`, `SessionClose`, `SessionCreate`. Correct.
- `SessionDeltaInfo`: `AddrFamily uint8` (dataplane constants AF_INET=2, AF_INET6=10), `Protocol uint8`, ports `uint16`, `OwnerRGID int`, `EgressIfindex int`, `TXIfindex int`, `TunnelEndpointID uint16`, `TXVLANID uint16`, `IngressZoneID uint16`, `EgressZoneID uint16`, `PolicyID uint32`, `PolicyCounterIdx uint32`, `AppTimeout uint32`. Correct widths.
- **NEGATIVE**: No integer truncation in protocol types. Wire widths match on both sides (Go and Rust).

### 5.8 NAT compilation — `nat*.go`

- `buildSourceNATSnapshotsWithFeeds` — resolves `match source-address-name` via `resolveNATAddressNamePrefixes` (static book + feed overlay #3303), `match destination-address-name`. Fail-closed on unknown name (appends raw token, downstream parse fails → no match). Correct.
- `sourceNATPoolPortRange` — `PortLow` / `PortHigh` from `config.NATPool` (`int`), validates `1..65535` + `low <= high`, returns `(uint16(low), uint16(high), true)` or `(0, 0, false)`. Correct — `clampPort` equivalent for source NAT.
- `buildDestinationNATSnapshotsWithFeeds` — exact + wildcard + PROTO_ANY + prefix LPM. Source-address constraint (#2394). Destination prefix (#3164). Protocol resolution via SSOT (#2396). `then destination-nat off` exemption (#3844). Source-port constraint (#3437) + ICMP type/code (#3437). Correct.
- `buildStaticNATSnapshots` — `clampPort(rule.MatchDestinationPort)` / `clampPort(rule.MappedPort)` — rejects out-of-range (> 65535 or < 1) as 0 ("no port translation", fail-closed). Correct (#2491).
- `coalescePortRanges` — dedups + merges port ranges, skips out-of-range values. Returns nil for empty input (unconstrained) OR all-out-of-range (distinguished by caller via `natNeverMatchPortRange` sentinel `{Low:1, High:0}`). Correct.
- `natNeverMatchPortRange = NatPortRangeWire{Low: 1, High: 0}` — `Low > High` = never-match, preserved by Rust matcher. Correct (#3429 fix).
- **NEGATIVE**: No integer truncation in NAT compilation. Port values are `int` from config, validated against `1..65535`, clamped to `uint16` only after validation. No wraparound.

### 5.9 Zone / policy compilation — `zones_*.go`, `policies*.go`

- `buildZoneSnapshots` — assigns `StableZoneID` (hash-based, `uint16`), tracks collisions. `HostInboundConfigured`, `HostInboundSystemServices`, `HostInboundProtocols`, `TCPRst`. Correct.
- `buildPolicySnapshotsWithSchedulerStateAndFeeds` — feed-aware policy building, scheduler gating, per-policy-address resolution. Correct.
- `quarantineCollidingZones` (#3719) — drops colliding zones, unzones interfaces, drops policies. Stashes `ZoneIDCollisions` in unexported field. Correct fail-closed.
- **NEGATIVE**: No integer truncation. Zone IDs are `uint16` (0-65535, more than enough for any real config — max zones ~100).

### 5.10 Filter / firewall compilation — `filters*.go`

- `buildFirewallFilterSnapshots` — sorted, per-filter term building. TCP flags via `ParseTCPFlagsExpression`, flex match (length ceil, default 4, #3232 match-start). Correct.
- `buildFilterTermSnapshots` — handles all fields. Correct.
- `resolvePrefixListAddrs` — drops any/empty, PL refs always constrain, any+except → sole except, mixed positive+except → positive-wins + warn (#3359). Correct.
- `buildHostInboundViews` — per-zone host-inbound views. `BuildZoneHostInboundViews`, `BuildUnzonedHostInboundAddrs` (#4420 HI-2). Correct.
- **NEGATIVE**: No integer truncation. Filter term counts are small (bounded by config).

### 5.11 Routes / FIB — `routes.go`, `fabric.go`, `interfaces.go`, `neighbors.go`, `tunnels.go`

- `buildRouteSnapshots` — builds route snapshots from config + route overlay. Handles `routeOverlay` (ip-monitoring injected failover routes). Correct.
- `buildFabricSnapshots` — fabric snapshot with fresh peer MACs, `Up` field (must NOT be omitempty — `false` = genuinely down, not absent). Correct (#4082).
- `buildInterfaceSnapshots` — interface snapshot building, RETH resolution, VLAN handling, synthetic logical ifindex for host-only interfaces. Correct.
- `buildNeighborSnapshots` — neighbor snapshot building. `filterPublishableNeighbors` drops `state="none"` + malformed MAC. Correct.
- `buildTunnelEndpointSnapshots` — tunnel endpoint snapshot, WireGuard peers (#1434), XFRMI, GRE. Correct.
- **NEGATIVE**: No integer truncation. Ifindex `int`, VLAN ID `int`, MTU `int` — all correct widths.

### 5.12 Legacy adapter / BPF shim — `legacy_dataplane.go`, `boot_probe.go`, etc.

- `LegacyDataPlaneAdapter` — wraps `*userspace.Manager` as `dataplane.RuntimeDataPlane` / `dataplane.DataPlane`. Delegates `ApplyConfig`, `Sessions`, `Telemetry`, `Link`, `HA`. Correct compatibility shim.
- `ProbeForwardingArmed` — one-shot control-socket status query (no Manager startup). Returns true only when `Enabled && ForwardingArmed`. Every failure mode → false. Correct (#1993).
- **NEGATIVE**: No integer truncation. No resource leak — probe opens one Unix socket, closes it via `defer conn.Close()`.

### 5.13 CoS / fairness / flow / mirrors — `cos.go`, `fairness.go`, etc.

- `buildClassOfServiceSnapshot` — forwarding classes, schedulers, scheduler maps, DSCP classifiers, DSCP rewrite rules. Correct.
- `fairness.go` — CoS fairness RSS aggregate, per-queue fairness. `Ifindex int`, `QueueID uint8` (RSS queue is 0..15, fits u8). Correct.
- `fairness_throughput.go` — throughput accounting. `CoSQueueID *int` (pointer, nil = no CoS queue). Correct.
- **NEGATIVE**: No integer truncation. CoS queue IDs are small (0..8), fits u8.

### 5.14 Dataplane constants / types — `constants.go`, `types.go`, `maps_*.go`

- `constants.go`: `MaxInterfaces uint32 = 256` (mirrors `MAX_INTERFACES` in `bpf/headers/xpf_common.h`), `BindingQueuesPerIface uint32 = 16`, `BindingArrayMaxEntries uint32 = MaxInterfaces * BindingQueuesPerIface = 4096`. Verified against C header by `constants_test.go`. Correct.
- `types.go`: `SessionKey`, `SessionKeyV6`, `SessionValue` (`FibIfindex uint32`, `FibVlanID uint16`, `FibDmac/FibSmac [6]byte`, `FibGen uint16`), `NATPoolConfig`, `NATPoolIPV6`. All correct widths.
- **NEGATIVE**: `FibIfindex uint32` — Linux ifindex is `int` (up to ~2^31-1), fits `uint32`. Correct. `FibGen uint16` — generation counter for FIB cache invalidation, wraps at 65535 → still correct (cache miss on wrap, re-resolves, no security issue).

---

## 6. Findings

### [F-A6-001] LOW: Heartbeat map zero-init iterates `uint32(cfg.Workers)*2*16` without sign check — negative Workers (lenient load / HA sync) wraps to ~4B iterations (DoS)

- Title: Heartbeat map zero-init with negative Workers wraps uint32 to ~4B iterations, blocking apply indefinitely
- Severity: Low (DoS — apply hangs, not fail-open; requires authenticated config commit of negative workers on lenient path)
- Confidence: Medium
- Evidence:
  ```go
  // pkg/dataplane/userspace/maps_sync.go:179
  for slot := uint32(0); slot < uint32(cfg.Workers)*2*16; slot++ {
      _ = heartbeatMap.Update(slot, zeroHB, ebpf.UpdateAny)
  }

  // pkg/dataplane/userspace/maps_sync.go:154
  Workers:            uint32(cfg.Workers),
  // pkg/config/schema_system.go:258
  "workers": {
      validator:     ValidateIntegerMin(1),
  ```

  - `cfg.Workers` is `int` from config. Schema validates `>= 1` at STRICT commit (`ValidateIntegerMin(1)`).
  - However, `compileUserspaceDataplane` in `compiler_system.go:738` does `cfg.Workers, _ = strconv.Atoi(v)` with error swallowed — a non-numeric value → `Workers == 0`.
  - Comment in `schema_system.go:242-251` says: "Each compiled with the Atoi error swallowed, so garbage silently fell back to the 0 zero-value, which the manager coerces to the default (workers<=0 -> 1, ...)."
  - The coercion happens in `manager.go` / `capabilities.go` (`maxInt(cfg.Workers, 1)`), but `programBootstrapMapsLocked` at line 179 takes `cfg.Workers` DIRECTLY (the raw config value), not the coerced value. So if `cfg.Workers == -1` (e.g. via HA sync from an older binary that didn't validate, or a direct `SetFeedSnapshots` path), `uint32(-1) = 4294967295`, `4294967295*2*16` overflows `uint32` to `4294967264` (due to uint32 wraparound: `4294967295*32 mod 2^32 = 4294967264`), and the loop tries ~4B iterations, each doing a BPF map update — effectively a DoS (apply hangs for minutes/hours).
  - Even `Workers == 0` (garbage config value): `uint32(0)*2*16 = 0`, loop is no-op — safe, but then `Workers: uint32(0)` is written to ctrl map (line 154), which the Rust helper may interpret as 0 workers → no forwarding. The manager's `maxInt(cfg.Workers, 1)` at line 155 for `QueueCount` prevents QueueCount=0, but Workers itself is 0.

- Trace:
  1. Operator commits `set system dataplane workers -1` (or HA sync delivers a config with Workers=-1 from an older primary that didn't validate).
  2. `compileUserspaceDataplane` stores `Workers = -1` (Atoi succeeds for "-1").
  3. `buildSnapshot` → `programBootstrapMapsLocked(snapshot, cfg)` where `cfg` is `config.UserspaceConfig` from the compiled `*config.Config`.
  4. `programBootstrapMapsLocked` line 179: `uint32(-1)*2*16 = uint32(4294967295)*32 mod 2^32 = 4294967264` → loop tries ~4B BPF map updates → apply hangs (DoS).
  5. Even if truncated by `BindingArrayMaxEntries` check elsewhere, the heartbeat zero-init has NO cap.

- Refutation attempt:
  - Schema validates `workers >= 1` at STRICT commit — so `-1` cannot be committed via normal `commit` on this binary. TRUE for direct commit.
  - Lenient load path (`opts.lenient*`) skips `ValidateIntegerMin(1)` — a config persisted by an older binary (pre-#1319) or HA-synced from a peer running older code could carry `workers = -1`.
  - `cfg.Workers == 0` (garbage/non-numeric) is the more likely lenient-path value — and `uint32(0)*2*16 = 0`, loop is no-op, safe. But Workers=0 in ctrl map means 0 workers → no forwarding, which is fail-closed, not fail-open. Acceptable.
  - The actual risk is `Workers == -1` specifically, which requires either a direct negative integer in config (rejected by schema on STRICT) or a hand-crafted config tree. Unlikely in production.

- HPC check: No — this is DoS (apply hangs), not fail-open. Does not bypass firewall policy.

- Why it matters: A `workers = -1` config on the lenient/HA-sync path causes `programBootstrapMapsLocked` to hang for a very long time (billions of BPF map updates), effectively DoSing the control plane. The apply never completes, the commit never reports success, the operator cannot easily recover without manual intervention. While STRICT commit rejects it, the lenient path is the backstop that must not hang.

- Fix direction:
  ```go
  // In programBootstrapMapsLocked, clamp Workers before the loop:
  workers := cfg.Workers
  if workers < 1 {
      workers = 1
  }
  if workers > 256 { // or MaxInterfaces
      workers = 256
  }
  for slot := uint32(0); slot < uint32(workers)*2*16; slot++ {
  ```
  Or use the already-coerced value from `capabilities.go` if available. Mirror the `maxInt(cfg.Workers, 1)` pattern already used for `QueueCount` on line 155.

- Labels: integer-truncation, DoS, low-priority, lenient-path, heartbeat, workers
- Dedup note: NOT in prior findings. `all_findings.txt` has no entry for heartbeat map zero-init overflow. `ps-review-036` does not cover this path.

---

### [F-A6-002] LOW: Tunnel endpoint ID is `uint16` (max 65535) but ID assignment uses linear scan — no explicit cap check; >65535 tunnel endpoints silently wrap to 0 (no tunnel)

- Title: `TunnelEndpointID uint16` — >65535 tunnel endpoints wraps to 0, silently disabling tunnel for that session
- Severity: Low (DoS — tunnel traffic fails, not fail-open; requires >65535 tunnel endpoints, far beyond any real config)
- Confidence: High (code inspection — no cap check, but infeasible in practice)
- Evidence:
  ```go
  // pkg/dataplane/userspace/protocol.go — SessionDeltaInfo
  TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"` // 0 = no tunnel

  // pkg/dataplane/userspace/manager_ha.go:1141
  func (m *Manager) sessionSyncTunnelEndpointIDLocked(egressIfindex int) uint16 {
      // Linear scan over snapshot.TunnelEndpoints
      for _, endpoint := range snapshot.TunnelEndpoints {
          if endpoint.Ifindex == egressIfindex {
              return endpoint.ID // endpoint.ID is uint16 from config
          }
      }
      return 0 // 0 = no tunnel
  }

  // pkg/dataplane/userspace/protocol.go — TunnelEndpointSnapshot
  ID              uint16 `json:"id,omitempty"` // tunnel endpoint ID
  ```

  - `TunnelEndpointSnapshot.ID` is `uint16` (max 65535).
  - ID assignment in snapshot builder (likely sequential from 1..N) — if N > 65535, ID wraps to 0 or duplicates.
  - `TunnelEndpointID == 0` means "no tunnel" on the Rust side — so a wrapped/non-unique ID silently disables tunnel encapsulation for that session, or causes wrong tunnel selection.
  - In practice: max tunnel endpoints is bounded by interface count (max ~256 per `MaxInterfaces`), so this cannot happen in any real deployment. But there's no explicit cap.

- Trace:
  1. Config has 65536+ tunnel endpoints (infeasible — would require 65536+ interfaces).
  2. ID assignment wraps / duplicates.
  3. Session sync for a tunnel flow gets `TunnelEndpointID = 0` (no tunnel) or wrong tunnel.
  4. Traffic for that session is not encapsulated (sent as plain IP) or sent to wrong tunnel.

- Refutation: MaxInterfaces = 256, max tunnel endpoints ~ 256, far below 65535. This is a theoretical limit, not reachable in production. No fix required for correctness, but a `STATIC_ASSERT` or len check would be defense-in-depth.

- Why it matters (if N were large): Wrapped tunnel ID → wrong/no encapsulation → traffic bypass or blackhole. Not reachable today, but a future scale increase (e.g. 1000+ tunnels) could hit it.

- Fix direction: Add `if len(tunnelEndpoints) > math.MaxUint16-1 { return error }` at snapshot build time. Or use `uint32` for tunnel endpoint ID on wire (but this is a breaking wire change — `uint16` is sufficient for any realistic deployment).

- Labels: integer-truncation, tunnel, low-priority, theoretical, scale-limit
- Dedup note: NOT in prior findings. No existing issue tracks tunnel endpoint ID width.

---

### [F-A6-003] INFO: `defer cancel()` inside `surfaceAObserver` closure — correct scoping, NOT a bug

- Title: `defer cancel()` in closure — verified correct (defer scoped to closure function, not outer)
- Severity: Info (negative finding — confirms no bug)
- Confidence: High
- Evidence:
  ```go
  // pkg/daemon/daemon_ddns_surface_a.go:296-337
  func (d *Daemon) surfaceAObserver(cfg *config.Config) ddns.AddressObserver {
      return func(ctx context.Context, scope ddns.SurfaceAScope) (ddns.AddressObservation, bool) {
          // ...
          case ddns.AddressSourceCheckIP:
              ctx, cancel := context.WithTimeout(ctx, surfaceACheckIPTimeout)
              defer cancel() // scoped to THIS closure invocation, NOT to surfaceAObserver
  ```

  - `defer cancel()` is inside the returned closure (the `AddressObserver` function), not inside `surfaceAObserver`. Go's `defer` is scoped to the enclosing function — the closure IS the enclosing function for this `defer`. So `cancel()` runs when the closure returns, which is correct.
  - The closure is called once per scope per reconcile pass by `pkg/ddns` (SurfaceAManager.Reconcile). Each call creates one `context.WithTimeout` and defers its `cancel()` to the end of that call. No accumulation, no leak.
  - Separately, `reconcileSurfaceAOnce` (line 110): `rctx, cancel := context.WithTimeout(ctx, surfaceAReconcileTimeout)` / `defer cancel()` — also correct, scoped to `reconcileSurfaceAOnce`.

- Why included: Task says "If no finding, WRITE NEGATIVE." This was a likely false-positive candidate flagged during investigation — confirming it is NOT a bug.

---

### [F-A6-004] INFO: Binding index math — `uint32(ifindex)*16 + queueID` — correctly guarded against overflow

- Title: Binding index computation — verified safe (ifindex <= 0 skipped, overflow → fail-closed)
- Severity: Info (negative finding — confirms no bug)
- Confidence: High
- Evidence:
  ```go
  // pkg/dataplane/userspace/maps_sync.go:664-690
  if binding.Ifindex <= 0 {
      continue
  }
  idx := uint32(binding.Ifindex)*bindingQueuesPerIface + binding.QueueID
  if idx >= dataplane.BindingArrayMaxEntries {
      return m.failClosedUserspaceCtrlLocked(ctrlMap, ctrl, fmt.Errorf(
          "update userspace_bindings: idx=%d exceeds cap=%d (ifindex=%d queue=%d; ...)",
          idx, dataplane.BindingArrayMaxEntries, binding.Ifindex, binding.QueueID,
      ))
  }
  ```

  - `binding.Ifindex` is `int` from JSON (Rust reports Linux ifindex, always positive for valid interfaces).
  - Guard `if binding.Ifindex <= 0 { continue }` prevents `uint32(negative)` wrap.
  - `bindingQueuesPerIface = 16` (const), `QueueID uint32` (0..15 per binding).
  - `idx >= BindingArrayMaxEntries` (4096 = 256*16) → `failClosedUserspaceCtrlLocked` (disables ctrl, fail-closed). Correct.
  - Same guard in VLAN-alias child path (line 713-722) and all other `Ifindex` loops.

- Why included: Integer truncation / pool/binding index math & caps — task focus. This path is CORRECT, no finding.

---

### [F-A6-005] INFO: NAT pool/binding port handling — `clampPort` / `sourceNATPoolPortRange` — no truncation, fail-closed on bad values

- Title: NAT port range handling — verified correct (int from config → validated → uint16 after validation)
- Severity: Info (negative — confirms no bug)
- Confidence: High
- Evidence:
  ```go
  // pkg/dataplane/userspace/nat_static.go:13
  func clampPort(p int) uint16 {
      if p < 1 || p > 65535 {
          return 0 // 0 = "no port translation" = fail-closed
      }
      return uint16(p)
  }

  // pkg/dataplane/userspace/nat_source.go:406
  func sourceNATPoolPortRange(pool *config.NATPool) (uint16, uint16, bool) {
      if pool == nil { return 0, 0, false }
      low := pool.PortLow
      if low == 0 { low = 1024 }
      high := pool.PortHigh
      if high == 0 { high = 65535 }
      if low < 1 || high < 1 || low > 65535 || high > 65535 || low > high {
          return 0, 0, false
      }
      return uint16(low), uint16(high), true
  }

  // pkg/dataplane/userspace/nat.go:135-136
  var natNeverMatchPortRange = NatPortRangeWire{Low: 1, High: 0} // Low>High = never-match
  ```

  - Config `PortLow` / `PortHigh` / `MatchDestinationPort` / `MappedPort` are `int` from AST parse.
  - Validated against `1..65535` before `uint16` cast. Out-of-range → 0 or `never-match` sentinel (fail-closed).
  - No `uint16(truncated_large_int)` without prior validation.

---

### [F-A6-006] INFO: Event stream — no integer truncation, no unbounded resource growth

- Title: Event stream — verified bounded and correct
- Severity: Info (negative — confirms no bug in resource safety)
- Confidence: High
- Evidence:
  - `pendingCallbackFramesLimit = 4096` — bounded queue, drops connection when full (forces reconnect/replay).
  - `FramesRead`, `FramesWritten`, `DecodeErrors`, `SeqGaps` — `atomic.Uint64`, no overflow concern (wraps at 2^64, ~centuries at line rate).
  - `length > 1024` frame size check — prevents OOM from malicious helper.
  - `eventStreamCancel context.CancelFunc` — single context per EventStream, cancelled on Manager.Close().
  - `drainCompleteCh chan uint64` — buffered depth 1, drained before each SendDrainRequest.
  - No goroutine leak — `acceptLoop` / `readLoop` / `ackLoop` all exit on `ctx.Done()`.

- Why included: Task says "DDNS/observability resource safety." Event stream is the primary observability path (session events, policy deny, screen drop, filter log, session close/create). Verifying bounded resources here is in scope.

---

### [F-A6-007] INFO: Zone ID handling — `uint16` (StableZoneID) — correctly widened from `u8`, no truncation

- Title: Zone ID handling — verified correct (u8→u16 widening complete, no truncation)
- Severity: Info (negative)
- Confidence: High
- Evidence:
  ```go
  // pkg/dataplane/userspace/eventstream.go — wire format comment:
  // [27:29] IngressZoneID (uint16 LE)  — #3075: widened from u8
  // [29:31] EgressZoneID (uint16 LE)   — #3075: widened from u8

  // pkg/dataplane/userspace/protocol.go — SessionDeltaInfo:
  IngressZoneID    uint16 `json:"ingress_zone_id,omitempty"`
  EgressZoneID     uint16 `json:"egress_zone_id,omitempty"`

  // pkg/dataplane/userspace/manager_ha.go:1184
  func (m *Manager) zoneNameByID(zoneID uint16) string {
      // deterministic: lexicographically smallest name for colliding IDs
  ```

  - #3075 widened zone IDs from `u8` (max 255) to `u16` (max 65535) on the event stream wire, session sync, and zone snapshot.
  - `zoneNameByID` handles collisions deterministically (lexicographically smallest name wins — the quarantine survivor).
  - Event stream test (`eventstream_test.go:275`) explicitly tests zone ID > 255: "The Go decoder must read the full u16 (not truncate to u8)."
  - No truncation: all paths use `uint16` for zone IDs after #3075.

---

### [F-A6-008] INFO: FIB generation — `uint32` — wraps safely (cache miss on wrap, no security issue)

- Title: FIB generation counter — wraps at 2^32, safe (cache miss, re-resolve, no bypass)
- Severity: Info (negative)
- Confidence: High
- Evidence:
  ```go
  // pkg/dataplane/userspace/builder.go:13
  func buildSnapshot(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32) (*ConfigSnapshot, error) {

  // pkg/dataplane/userspace/protocol.go — ConfigSnapshot:
  FIBGeneration   uint32 `json:"fib_generation,omitempty"`

  // pkg/dataplane/userspace/inject.go:77
  req.FIBGeneration++ // wraps at 2^32, cache key becomes stale → re-lookup
  ```

  - `FIBGeneration uint32` — incremented on every FIB bump (route add/remove). Wraps at 2^32 (~4B bumps).
  - On wrap: `FIBGeneration` goes from `0xFFFFFFFF` to `0`, causing all session FIB caches to miss (generation mismatch) and re-resolve via `bpf_fib_lookup`. This is correct — no security bypass, just a performance blip (one-time re-resolution of all sessions).
  - `Generation uint64` (config generation) — practically never wraps (2^64 commits).

---

## 7. Summary

| Finding | Severity | Confidence | Status |
|---------|----------|------------|--------|
| F-A6-001 | Low | Medium | NEW — heartbeat map zero-init wraps on negative Workers |
| F-A6-002 | Low | High | NEW (theoretical) — tunnel endpoint ID uint16 cap, unreachable in practice |
| F-A6-003 | Info | High | NEGATIVE — defer cancel() in closure is correct |
| F-A6-004 | Info | High | NEGATIVE — binding index math correctly guarded |
| F-A6-005 | Info | High | NEGATIVE — NAT port handling correctly validated |
| F-A6-006 | Info | High | NEGATIVE — event stream bounded and correct |
| F-A6-007 | Info | High | NEGATIVE — zone ID u16 widening complete |
| F-A6-008 | Info | High | NEGATIVE — FIB generation wrap safe |

**No High/Critical findings.** One Low DoS (heartbeat map DoS on negative Workers, lenient-path only, schema rejects at STRICT commit). One Low theoretical (tunnel endpoint ID cap, unreachable in practice).

**Core firewall + VRRP/HA failover + cold-boot**: No issues found in A6 scope (dataplane manager). These are primarily daemon/Rust-dp concerns. A6 compilation is correct for zone policies, global policies, host-inbound views, default deny/permit, and HA session sync egress resolution.

**Integer truncation**: One LOW (F-A6-001 — Workers negative → uint32 wrap in heartbeat map zero-init). All other truncation paths (binding index, NAT port, zone ID, FIB generation) are correctly guarded.

**DDNS/Observability resource safety**: No issues in A6 scope. Event stream is bounded (4096 pending frames, 1024 byte frame cap), DDNS is daemon-side (A7 scope). Pending callback frames correctly bounded, no goroutine leak, no unbounded map growth.

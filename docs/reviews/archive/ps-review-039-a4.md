# 039 — Go dataplane + daemon + cluster + routing — monolith audit (A4)

- Base commit: f70146951583823a5ace87b0b11a2e58f46e8db9
- Output path: /tmp/ps-review-039-a4.md
- Batch: A4 — Go dataplane + daemon + cluster + routing + other large Go
- Number: 039

## File-size / shape inventory

| File | LOC | Threshold | #func / #type | Smell |
|------|-----|-----------|---------------|-------|
| `pkg/config/compiler_validate_warn.go` | 3330 | >3000 CRITICAL | 35 funcs | Monolith — 35 warn validators in one file; strict counterpart already split per-domain |
| `pkg/dataplane/userspace/protocol.go` | 2979 | ~3000 CRITICAL | 72 type defs, 1 func | Wire-format fusion — ControlRequest + ConfigSnapshot (~20 snapshot subtypes) + ProcessStatus (~40 status subtypes) + ControlResponse + event-stream constants in one file |
| `pkg/vrrp/instance.go` | 2417 | >2000 | 52 funcs / 3 types | State-machine + RX + TX + GARP + advert-interval + preempt-hold + VIP management — single coherent SM but large |
| `pkg/daemon/daemon_run.go` | 2329 | >2000 | 9 funcs | Lifecycle bootstrap + naming + run-loop + exit — large but already decomposed per #4407 |
| `pkg/frr/policy_render.go` | 1938 | ~2000 | ~ | Slightly over; not inspected this batch |
| `pkg/daemon/daemon_apply.go` | 1935 | ~2000 | 20 funcs | applyConfigLocked ~1148 LOC — god-function; already filed #4407 |
| `pkg/api/metrics_descriptors.go` | 1896 | ~2000 | 279 NewDesc | Prometheus descriptor monolith — all subsystems in one file |
| `pkg/routing/tunnel.go` | 1877 | ~2000 | 3 types + ~30 funcs | Tunnel lifecycle + keepalive + WG MTU + VRF + address reconcile — 5 distinct responsibilities |
| `pkg/cluster/sync_conn.go` | 1858 | ~2000 | ~52 funcs | HA sync connection — gen-guard + fabric dial + bulk + sweep + delete-journal + config-sync + failover + barrier + liveness |
| `pkg/api/metrics_userspace.go` | 1819 | ~ | | Userspace metrics emitter — paired with descriptors |
| `pkg/dataplane/userspace/maps_sync.go` | 1763 | ~ | | Userspace map sync — focused, NOT a monolith (see D) |
| `pkg/dataplane/compiler.go` | 1733 | ~ | | Top-level compiler dispatch |
| `pkg/snmp/agent.go` | 1519 | ~ | | SNMP agent — focused |
| `pkg/daemon/daemon_ha.go` | 1511 | ~ | | HA chassis integration |
| `pkg/daemon/daemon_nft.go` | 1432 | ~ | | nftables host-inbound |
| `pkg/dataplane/userspace/manager_ha.go` | 1425 | ~ | | HA manager glue |
| `pkg/cli/cli_request.go` | 1328 | ~ | | Remote CLI request dispatch |
| `pkg/daemon/daemon_system.go` | 1310 | ~ | | System reconcile |

Total non-test Go in inspected dirs: ~244k LOC (`pkg/dataplane/userspace` + `pkg/daemon` + `pkg/cluster` + `pkg/routing` + `pkg/vrrp` + `pkg/api` + `pkg/config/compiler_*`). Batch top-5 already at 3330+2979+2417+2329+1938 = 13k LOC in 5 files.

---

## F-039-01: `protocol.go` 2979 LOC — wire-format monolith (12 domains fused)

- **Severity**: Medium (reviewability / merge-conflict / `mod touched` churn)
- **Confidence**: HIGH — mechanical
- **Refactor class**: **(A) MECHANICAL / SAFE** — cold path (config-apply + HA sync), pure code-motion

### Evidence

72 `type X struct` in one file, spanning 12 independent wire domains:

```go
// pkg/dataplane/userspace/protocol.go — all in one file:

type ControlRequest struct {        // control RPC envelope
    Type               string
    Snapshot           *ConfigSnapshot
    Forwarding         *ForwardingControlRequest
    HAState            *HAStateUpdateRequest
    Queue              *QueueControlRequest
    Binding            *BindingControlRequest
    Packet             *InjectPacketRequest
    SessionSync        *SessionSyncRequest
    SessionDeltas      *SessionDeltaDrainRequest
    SessionExport      *SessionExportRequest
    ...
}

type ConfigSnapshot struct {        // 30+ fields, 20+ snapshot subtypes
    Version         int
    Generation      uint64
    Zones           []ZoneSnapshot
    Interfaces      []InterfaceSnapshot
    Fabrics         []FabricSnapshot
    TunnelEndpoints []TunnelEndpointSnapshot
    Neighbors       []NeighborSnapshot
    Routes          []RouteSnapshot
    Policies        []PolicyRuleSnapshot
    SourceNAT       []SourceNATRuleSnapshot
    StaticNAT       []StaticNATRuleSnapshot
    DestinationNAT  []DestinationNATRuleSnapshot
    NAT64           []NAT64RuleSnapshot
    Screens         []ScreenProfileSnapshot
    Filters         []FirewallFilterSnapshot
    // ... + ClassOfService, FlowExport, AddressBooks, AppCatalog, ...
}

type ProcessStatus struct {         // ~150 fields, 40+ status subtypes
    PID                              int
    LastSnapshotRejectReasons        []string
    ZoneIDCollisions                 []string
    WorkerRuntime                    []WorkerRuntimeStatus
    CoSInterfaces                    []CoSInterfaceStatus
    PolicyRuleCounters               []PolicyRuleCounterStatus
    NATRuleCounters                  []NATRuleCounterStatus
    FilterTermCounters               []FirewallFilterTermCounterStatus
    SourceNATPools                   []SourceNATPoolStatus
    // ... + HAGroups, Fabrics, Queues, Bindings, PerBinding, FlowWorkerMap, WgTunnels, ...
}

type PolicyRuleSnapshot struct { ... }
type SourceNATRuleSnapshot struct { ... }  // 20+ fields
type StaticNATRuleSnapshot struct { ... }
type DestinationNATRuleSnapshot struct { ... } // 15+ fields inc MatchDestinationPorts, MatchSourcePorts, MatchICMPType
type BindingStatus struct { ... }              // 80+ fields — TX, CoS, mirror, flow-cache
type CoSQueueStatus struct { ... }             // 40+ fields — waterfill, admission, sojourn
type WorkerRuntimeStatus struct { ... }
type WgTunnelStatus struct { ... }
type SessionSyncRequest struct { ... }
type SessionDeltaInfo struct { ... }
// + 40 more
```

Responsibility count: ConfigSnapshot build (Go→Rust wire), ProcessStatus report (Rust→Go wire), ControlRequest/Response envelope, SessionSync wire, HA wire, CoS/QoS wire, NAT wire (4 flavors), Filter wire, Policy wire, Tunnel/WG wire, Factory/neighbor/route wire, Event-stream wire constants (8 more types below).

`wc -l` 2979, `grep -c "^type" ` 72. Compare `userspace-dp` Rust side: `protocol/snapshot.rs`, `protocol/control.rs`, `protocol/cos.rs`, `protocol/binding.rs`, `protocol/status.rs` are already split — Go side did not follow.

### Proposed decomposition

```
pkg/dataplane/userspace/
  protocol.go              // 200 LOC: const ProtocolVersion, ControlRequest, ControlResponse only
  protocol_snapshot.go     // ConfigSnapshot envelope (Version, Generation, Summary, Capabilities, MapPins)
  protocol_snapshot_nat.go // SourceNATRuleSnapshot, StaticNATRuleSnapshot, DestinationNATRuleSnapshot, NAT64RuleSnapshot, Nptv6RuleSnapshot, NatPortRangeWire, NatAppTermWire
  protocol_snapshot_policy.go // PolicyRuleSnapshot, PolicyApplicationSnapshot, AppCatalogEntrySnapshot, AddressBookSnapshot
  protocol_snapshot_filter.go // FirewallFilterSnapshot, FirewallTermSnapshot, FlexMatchSnapshot, PolicerSnapshot, ThreeColorPolicerSnapshot
  protocol_snapshot_network.go // ZoneSnapshot, InterfaceSnapshot, FabricSnapshot, TunnelEndpointSnapshot, TunnelWgPeerWire, RouteSnapshot, NeighborSnapshot, FlowSnapshot, ClassOfServiceSnapshot (+ CoS subtypes)
  protocol_snapshot_screen.go // ScreenProfileSnapshot, ScreenMissingProfileRef
  protocol_status.go       // ProcessStatus envelope + MarshalJSON/UnmarshalJSON (Must stay together — legacy alias)
  protocol_status_binding.go // BindingStatus, BindingCountersSnapshot, QueueStatus, Binding sub-types
  protocol_status_cos.go   // CoSInterfaceStatus, CoSQueueStatus, CoSActiveFlowCountStatus
  protocol_status_worker.go // WorkerRuntimeStatus, HAGroupStatus, SlowPathStatus
  protocol_status_counters.go // PolicyRuleCounterStatus, NATRuleCounterStatus, FirewallFilterTermCounterStatus, SourceNATPoolStatus, WgTunnelStatus, WgPeerStatus
  protocol_hasync.go       // SessionSyncRequest, SessionDeltaInfo, HAStateUpdateRequest, QueueControlRequest, BindingControlRequest, ForwardingControlRequest
  protocol_eventstream.go  // EventFrameHeaderSize, EventType*, SessionEventFlag* constants (already at bottom of current file, lines 2924-2979 — trivial extract)
  wire_uint8list.go        // already exists — WireUint8List stays
```

Each file <500 LOC. All `json` tags unchanged. `go vet` + `go test ./pkg/dataplane/userspace -run TestProtocol` byte-identical — JSON wire is stable (field names unchanged, only file location moves).

### Hot-path preservation

Cold path — protocol.go is used only on `ApplyConfig` (commit) and `PollStatus` (1/s). NOT per-packet hot. Split is (A) pure code-motion.

### Tests+gate

- `go test ./pkg/dataplane/userspace -run TestProtocol -count=1` — existing `protocol_test.go` (1914 LOC) and `protocol_null_collections_2214_test.go` must pass
- `go test ./pkg/dataplane/userspace -run TestSnapshot -count=1`
- `make build` — byte-identical `xpfd` binary (wire format unchanged)

### Why it matters

- Merge conflicts: 12 domains → any CoS change conflicts with any NAT change
- Reviewability: reviewer must load 2979 LOC to review a 10-line NAT field addition
- `engineering-style.md` "No monolithic files — ~2k LOC is a smell, ~3k LOC must split before adding logic"

### Fix direction

Mechanical file split, `package userspace` unchanged. Keep `ProcessStatus.MarshalJSON` + `UnmarshalJSON` together in `protocol_status.go` (they are a pair). No behavior change. File-level PR #4669 (manager_test.go split) shows precedent.

### Labels

`refactor`, `modularity`, `tech-debt`, `cold-path`, `mechanical`

### Dedup note

Not filed before. No prior issue for `protocol.go` split (GH search `protocol.go monolith` returns 0). Distinct from #4404-#4406 (Rust poll_descriptor) and #4407-#4409 (daemon god-struct / NAT).

---

## F-039-02: `sync_conn.go` 1858 LOC — HA sync connection monolith (8 responsibilities fused)

- **Severity**: HIGH (correctness risk — generation-guard ordering #2995/#2170/#2221/#2198 is subtle, single-file makes it hard to review)
- **Confidence**: MEDIUM — split is safe but must preserve lock ordering and single-active-fabric invariant
- **Refactor class**: **(A) MECHANICAL with ORDERING CONSTRAINTS** — cold path (HA sync is 1/s sweep + on-demand, NOT per-packet hot), but generation-guard state machine must stay atomic

### Evidence

All HA sync connection logic in one file (`pkg/cluster/sync_conn.go`):

```go
// pkg/cluster/sync_conn.go — 1858 LOC, ~52 funcs:

// 1. Generation-guard state machine (#2170/#2221/#2198/#2995) — 200+ lines:
func putGenBounded[K comparable](m map[K]uint64, key K, gen uint64) bool { ... }
func (s *SessionSync) nextInstallGen() uint64 { ... }
func (s *SessionSync) stampInstallGenV4(key dataplane.SessionKey, val *dataplane.SessionValue) { ... }
func (s *SessionSync) stampInstallGenV6(...) { ... }
func (s *SessionSync) takeDeleteGenV4(key dataplane.SessionKey) uint64 { ... } // #2221 fresh delete gen
func (s *SessionSync) takeDeleteGenV6(...) uint64 { ... }
func (s *SessionSync) installGenGuardV4(key dataplane.SessionKey, incoming uint64) (record uint64, apply bool) { ... }
func (s *SessionSync) installGenGuardV6(...) (...) { ... }
func (s *SessionSync) recordInstalledGenV4(...) { ... }
func (s *SessionSync) recordInstalledGenV6(...) { ... }
func (s *SessionSync) deleteGenGuardV4(key dataplane.SessionKey, deleteGen uint64) bool { ... }
func (s *SessionSync) deleteGenGuardV6(...) bool { ... }
func (s *SessionSync) resetRecvGen() { ... } // #2198 F2 bulk re-prime

// 2. Session apply (depends on gen-guard):
func (s *SessionSync) installClusterSyncedV4(...) { ... }
func (s *SessionSync) installClusterSyncedV6(...) { ... }
func (s *SessionSync) deleteClusterSyncedV4(...) { ... }
func (s *SessionSync) deleteClusterSyncedV6(...) { ... }

// 3. Fabric dial + active-conn selection:
func shouldInitiateFabricDial(localAddr, peerAddr string) bool { ... }
func (s *SessionSync) activeConnLocked() net.Conn { ... }
func (s *SessionSync) getActiveConn() net.Conn { ... }
func connRemoteAddrString(conn net.Conn) (remote string) { ... }
func connLocalAddrString(conn net.Conn) (local string) { ... }
func configureSessionSyncConn(conn net.Conn) { ... }

// 4. Connection lifecycle (listener, dialer, reconnect, disconnect):
func (s *SessionSync) handleNewConnection(ctx context.Context, fabricIdx int, conn net.Conn) { ... } // ~80 LOC, cold-start bulk decision
func (s *SessionSync) Start(ctx context.Context) error { ... }
func (s *SessionSync) Stop() { ... }
func (s *SessionSync) StartSyncSweep(ctx context.Context) { ... }
func (s *SessionSync) acceptLoop(ctx context.Context, ln net.Listener, fabricIdx int) { ... }
func (s *SessionSync) fabricConnectLoop(ctx context.Context, fabricIdx int, peerAddr string) { ... }
func (s *SessionSync) sendLoop(ctx context.Context) { ... }
func (s *SessionSync) receiveLoop(ctx context.Context, conn net.Conn) { ... }
func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) { ... } // ~350 LOC, 20+ msg types
func (s *SessionSync) handleDisconnect(conn net.Conn) { ... } // ~140 LOC, bulk re-drive #4090/#4360

// 5. Incremental sweep + backpressure:
func (s *SessionSync) sweepIntervals() (...) { ... }
func sweepIntervalsForDataPlane(dp any) (...) { ... }
func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool { ... }
func (s *SessionSync) syncSweep() int { ... } // ~110 LOC, ForEachV4+ForEachV6+journal flush
func (s *SessionSync) PauseIncrementalSync(reason string) { ... }
func (s *SessionSync) ResumeIncrementalSync(reason string) { ... }
func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool { ... }

// 6. Delete journal (bounded ring, rejournalTail, flush):
func (s *SessionSync) QueueSessionV4(...) { ... }
func (s *SessionSync) QueueSessionV6(...) { ... }
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) { ... }
func (s *SessionSync) QueueDeleteV6(...) { ... }
func (s *SessionSync) journalDelete(msg []byte) { ... }
func (s *SessionSync) flushDeleteJournal() { ... }
func (s *SessionSync) rejournalTail(tail [][]byte) { ... }

// 7. Config sync (monotonic config gen #3931/#4151):
func (s *SessionSync) nextConfigGen() uint64 { ... }
func (s *SessionSync) QueueConfig(configText string) { ... }
func (s *SessionSync) shouldApplyConfigGen(gen uint64) bool { ... }
func (s *SessionSync) recordAppliedConfigGen(gen uint64) { ... }
func (s *SessionSync) configApplyLoop(ctx context.Context) { ... }

// 8. Liveness keepalive + clock sync:
func (s *SessionSync) SendLivenessKeepalive() { ... }
func (s *SessionSync) sendClockSync(conn net.Conn) { ... }
```

`sync.go` (shared types) adds another ~800 LOC with `SessionSync` struct definition (30+ fields), `SyncStats`, `TransferReadinessSnapshot`, failover types, sweep profiler iface. Total `sync*.go` = ~2658 LOC in 2 files for what is 8 subsystems.

Responsibility boundaries:
- Gen-guard (stamp/take/guard/record/reset) — pure state machine, no I/O
- Fabric connection (dial/listen/activeConn) — net.Conn lifecycle
- Bulk sync (doBulkSync → sendBulkMarkers → BulkStart/End, reconcileStaleSessions, resetRecvGen)
- Sweep (ForEach + queueMessage + backpressure)
- Delete journal (journalDelete / flush / rejournalTail)
- Config sync (nextConfigGen / QueueConfig / configApplyLoop / shouldApply/record)
- Failover/barrier/clock (handleMessage 20 branches, handleDisconnect bulk re-drive)
- Liveness (SendLivenessKeepalive, sendClockSync, receiveLoop heartbeat)

### Proposed decomposition

```
pkg/cluster/
  sync.go              // SessionSync struct, SyncStats, constructor, Setters (keep — ~300 LOC)
  sync_conn.go         // Connection lifecycle only: Start, Stop, handleNewConnection, acceptLoop, fabricConnectLoop, sendLoop, receiveLoop, handleDisconnect, activeConnLocked, getActiveConn, shouldInitiateFabricDial, configureSessionSyncConn, connRemote/LocalAddrString (~600 LOC)
  sync_gen_guard.go    // Generation-guard state machine: putGenBounded, nextInstallGen, stampInstallGenV4/V6, takeDeleteGenV4/V6, installGenGuardV4/V6, recordInstalledGenV4/V6, deleteGenGuardV4/V6, resetRecvGen, installClusterSyncedV4/V6, deleteClusterSyncedV4/V6, noteHelperMirrorResult — the #2170/#2221/#2198/#2995 family + genGuardMapCap const (pure logic, no I/O) (~350 LOC)
  sync_sweep.go        // Sweep + backpressure: StartSyncSweep, sweepIntervals, sweepIntervalsForDataPlane, ShouldSyncZone, syncSweep, PauseIncrementalSync, ResumeIncrementalSync, queueMessage (~250 LOC)
  sync_delete_journal.go // Delete journal: QueueSessionV4/V6, QueueDeleteV4/V6, journalDelete, flushDeleteJournal, rejournalTail, deleteJournalDefaultCap (~200 LOC)
  sync_config.go       // Config sync: nextConfigGen, QueueConfig, shouldApplyConfigGen, recordAppliedConfigGen, configApplyLoop, configApplyItem (~120 LOC)
  sync_message.go      // Wire dispatch: handleMessage (split by msg type group), sendClockSync, SendLivenessKeepalive (~400 LOC)
  sync_protocol.go     // Already exists — encode/decode helpers (keep)
  sync_bulk.go         // Already exists — doBulkSync, sendBulkMarkers, reconcileStaleSessions, snapshotZoneOwnership (keep)
  sync_failover.go     // Already exists — failover request/ack/commit (keep)
  sync_auth.go         // Already exists (keep)
  sync_state.go        // Already exists (keep)
```

Key invariant to preserve: the comment at `sync_conn.go:304-320` (`Non-atomicity note #2198 F3`) — "apply sequence does NOT hold recvGenMu across whole sequence; safe because receiver apply path for given peer is single-threaded (one receiveLoop goroutine over single ACTIVE fabric)". Split must NOT introduce a new mutex or change lock ordering. The gen-guard map mutations (`genSentMu`, `recvGenMu`) stay in `sync_gen_guard.go` with identical signatures.

### Hot-path preservation

Cold path — HA sync runs at 1s active / 10s idle sweep cadence, not per-packet. `handleMessage` runs on receiveLoop (one goroutine per fabric), not on dataplane hot path. Split must preserve generation-guard ordering (e.g., `stampInstallGen` before `queueMessage`, `takeDeleteGen` draws fresh `nextInstallGen` before evict, delete tombstone before install guard). No per-packet hop added.

### Tests+gate

- `go test ./pkg/cluster -run TestGenGuard -count=1` — existing `sync_gen_guard_test.go` (must pass)
- `go test ./pkg/cluster -run TestSync -count=1` — `sync_test.go` (4717 LOC) + `sync_conn` sweep/journal tests
- `make test-failover` — cluster failover timing (gen-guard regression would surface as stale-delete / stale-RETAIN)
- Byte-identical `go build`: `go vet ./pkg/cluster`

### Why it matters

- Generation-guard is the most subtle state machine in the repo (#2170 stale-delete, #2221 stale-RETAIN, #2198 bulk reset, #2995 ordering, #4151 config M-2). Reviewing a gen-guard fix currently requires loading 1858 LOC of unrelated fabric-dial / sweep / delete-journal code.
- `handleMessage` 350 LOC with 20+ branches shares file with gen-guard — a sweep change can silently break a bulk-reset invariant.
- `handleDisconnect` bulk re-drive (#4090/#4360) holds `s.mu` while spawning goroutine that re-locks `s.mu` via `getActiveConn` inside `doBulkSync` — deadlock risk is invisible when the whole file is one unit.

### Fix direction

Mechanical split per responsibility, `package cluster` unchanged, `SessionSync` struct stays in `sync.go` (single source of truth), each new file takes methods operating on `*SessionSync` with identical receivers. Preserve `// Must hold mu` / `// Must hold recvGenMu` comments and `#2198 F3` non-atomicity note as file header. PR should be pure code-motion (no logic change), verified by `git diff --stat` showing only file moves.

### Labels

`refactor`, `modularity`, `ha`, `gen-guard`, `cold-path`, `mechanical`, `ordering-sensitive`

### Dedup note

Not filed before. GH search `sync_conn gen-guard split` returns 0. Distinct from #4407 daemon god-struct. Related to ongoing #4090/#4360 re-drive fixes which touch this file — split makes those reviews safer.

---

## F-039-03: `tunnel.go` 1877 LOC — tunnel lifecycle + keepalive + WireGuard + MTU + VRF (5 responsibilities)

- **Severity**: Medium
- **Confidence**: HIGH — cold path (tunnel create on commit, keepalive tick 1s+)
- **Refactor class**: **(A) MECHANICAL / SAFE**

### Evidence

```go
// pkg/routing/tunnel.go — 1877 LOC:

// Responsibility 1: Tunnel manager struct + reconcile maps (GRE/IPIP/Anchor/WG ownership)
type tunnelManager struct {
    ops       linkOps
    vrfBinder vrfBinder
    prober    tunnelProber
    mu         sync.Mutex
    tunnels    []string
    keepalives map[string]*keepaliveRunner
    linkGen    map[string]*atomic.Uint64
    ownedNames map[string]bool
    appliedAddrs map[string]map[string]bool
    appliedRI  map[string]string
    wgConfigured map[string]bool
}

// Responsibility 2: GRE/IPIP lifecycle + legacy tunnel match + anchor TUN
func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error { ... } // ~190 LOC
func anchorReusable(link netlink.Link) bool { ... }
func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) { ... } // ~130 LOC
func (t *tunnelManager) applyKernelTunnelLocked(tc *config.TunnelConfig) { ... } // ~160 LOC
func buildKernelTunnelLink(tc *config.TunnelConfig, ...) netlink.Link { ... }
func legacyTunnelMatches(existing, desired netlink.Link) bool { ... }

// Responsibility 3: WireGuard TUN + MTU derivation
const wgOverheadV4 = 60 // 20+8+16+16
const wgOverheadV6 = 80
const wgDefaultOuterMTU = 1500
const wgEngineMaxInnerMTU = 4096
func wgTunMTUForEndpoint(tc *config.TunnelConfig) int { ... } // ~40 LOC
func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error { ... } // ~100 LOC

// Responsibility 4: Keepalive ICMP probe + generation guard + lifecycle
type KeepaliveState struct { mu sync.Mutex; Up bool; Failures int; Unknown bool; UnknownKind UnsupportedKind; ... }
type keepaliveRunner struct { cancel context.CancelFunc; state *KeepaliveState; done chan struct{}; remote string; source string; linkGen *atomic.Uint64; ... }
func (t *tunnelManager) keepaliveProber() tunnelProber { ... }
func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, ...) { ... }
func (t *tunnelManager) stopKeepaliveLocked(name string) { ... }
func (t *tunnelManager) stopAllKeepalivesLocked() { ... }
func (t *tunnelManager) keepaliveLoop(ctx context.Context, done chan struct{}, ...) { ... }
func (t *tunnelManager) keepaliveTick(tunnelName string, state *KeepaliveState, ...) { ... } // ~90 LOC, §6 Axis D commit-after-success
func nextSeq(state *KeepaliveState) int { ... }
func keepaliveProbeDeadline(intervalSec int) time.Duration { ... }

// Responsibility 5: VRF binding + address reconcile (reconcile-in-place #1884)
func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) { ... } // ~80 LOC
func (t *tunnelManager) observeListClaimLocked(tc *config.TunnelConfig, link netlink.Link) { ... }
func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool { ... } // ~100 LOC
func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) (map[string]bool, bool) { ... } // ~40 LOC
func (t *tunnelManager) finishTunnelLocked(tc *config.TunnelConfig, link netlink.Link, skipUp bool, kind string) { ... }
func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState { ... }
func (t *tunnelManager) GetStatus() ([]TunnelStatus, error) { ... }
func (t *tunnelManager) Clear() error { ... }
func (t *tunnelManager) clearLocked() error { ... }
```

5 distinct responsibilities in one file. `tunnelManager` holds 8 maps + 3 interfaces, all guarded by one `mu` but with different lock disciplines (`keepaliveTick` never takes `t.mu` — AGY r5). The keepalive state machine (§6 Axis D commit-after-success: classify → intent → LinkByName → gen.Load() → LinkSetUp/Down → commit Up) is interleaved with tunnel creation — reviewer cannot verify the keepalive invariant without loading GRE/IPIP creation.

### Proposed decomposition

```
pkg/routing/
  tunnel.go              // tunnelManager struct + Apply + Clear + clearLocked + GetStatus + GetKeepaliveState + ensureReconcileStateLocked + linkGenForLocked + bumpLinkGenLocked + linkOps/vrfBinder interfaces + errWGIncompatibleLinkRetained (~300 LOC)
  tunnel_gre.go          // applyKernelTunnelLocked + buildKernelTunnelLink + legacyTunnelMatches + ipEqual + applyAnchorLocked + reconcileAnchorMTULocked + anchorReusable + finishTunnelLocked (~400 LOC)
  tunnel_wireguard.go    // applyWireguardTunLocked + wgTunMTUForEndpoint + wgOverheadV4/V6 + wgDefaultOuterMTU + wgEngineMaxInnerMTU + closeTuntapFiles (~250 LOC)
  tunnel_keepalive.go    // KeepaliveState, keepaliveRunner, keepaliveRunner.matches, keepaliveProber, startKeepalive, stopKeepaliveLocked, stopAllKeepalivesLocked, keepaliveLoop, keepaliveTick, nextSeq, keepaliveProbeDeadline, clearUnknownLocked, markUnknownLocked, classifyErrnoString (~500 LOC)
  tunnel_reconcile.go    // reconcileLinkAddrsLocked, pruneAppliedAddrsLocked, reconcileVRFClaimLocked, observeListClaimLocked, stopAll, TunnelStatus (~350 LOC)
  tunnel_prober.go       // tunnelProber interface + icmpProber + UnsupportedKind + ProbeResult (already small, but separate for testability)
```

Each file <500 LOC. No new mutexes. `tunnelManager.mu` stays in `tunnel.go`. `keepaliveTick` lock-free discipline preserved (never takes `t.mu`). `closeTuntapFiles` stays with wireguard (its only caller).

### Hot-path preservation

Cold path — tunnel creation runs on `applyConfigLocked` (commit), keepalive tick runs at `Keepalive` interval (seconds, 1/s+). NOT per-packet hot. Split is (A) mechanical, no hot-path change.

### Tests+gate

- `go test ./pkg/routing -run TestTunnel -count=1` — existing `routing_test.go` + `tunnel_reconcile_test.go` (1649 LOC)
- `go test ./pkg/routing -run TestKeepalive -count=1`
- `go vet ./pkg/routing`

### Why it matters

- `tunnel.go` is the highest-churn file in `pkg/routing` — every GRE/WG/keepalive/VRF fix touches it (git log: #1884 reconcile-in-place, #1918 hold-on-unknown, #1919 WG prune, #4071 keepalive on anchor, #2457 MTU clamp, #2300 MTU model). Monolith makes each review load 1877 LOC.
- Keepalive §6 Axis D invariant (commit-after-success: "classify + commit counters → compute intent → LinkByName → gen.Load → LinkSet → commit Up") is documented across 50+ lines of comments but interleaved with GRE creation — hard to verify in review.

### Fix direction

Mechanical file split, `package routing` unchanged. Keep `tunnelManager` struct in `tunnel.go`. Each new file's functions keep `(t *tunnelManager)` receiver. Preserve all `#1884`/`#1918`/`#1919`/`#4071` comments verbatim (they are load-bearing for reviewers).

### Labels

`refactor`, `modularity`, `tunnel`, `keepalive`, `wireguard`, `cold-path`, `mechanical`

### Dedup note

Not filed before. GH search `tunnel.go keepalive split` returns 0. Distinct from #4421 (flowexport monolithic) and #4408-#4409 (NAT). `pkg/routing/rules.go` 3-domains (nextTable/ribGroup/pbrManager) was noted in #4421 but is a different file.

---

## F-039-04: `compiler_validate_warn.go` 3330 LOC — warn validators monolith (strict already split)

- **Severity**: Medium (reviewability — warn and strict should be symmetric)
- **Confidence**: HIGH — mechanical per-domain split, proven pattern
- **Refactor class**: **(A) MECHANICAL / SAFE** — cold path (commit-time validation), pure code-motion, `ValidateConfig` is additive (`[]string` warnings, no error)

### Evidence

```go
// pkg/config/compiler_validate_warn.go — 3330 LOC, 35 funcs:

func ValidateConfig(cfg *Config) []string { // ~1600 LOC — top-level orchestrator + inline policy/interface/app validation
    var warnings []string
    // 50-200 LOC each: zones, addrs, apps, policies (FromZone/ToZone, address refs, port specs, protocols),
    // timers, screens, NAT, firewall, routing, scheduler, CoS, DDNS, etc.
    warnings = append(warnings, validateHostInboundMulticastWarnings(cfg)...)
    warnings = append(warnings, validateDHCPRelayParityWarnings(cfg)...)
    warnings = append(warnings, validateInterfaceParityWarnings(cfg)...)
    warnings = append(warnings, validateDefaultPolicyLogWarnings(cfg)...)
    // ... 15 more
    return warnings
}

// 34 helper validators — each is a self-contained per-domain warning:
func validateHostInboundMulticastWarnings(cfg *Config) []string { ... }   // ~50 LOC
func validateDHCPRelayParityWarnings(cfg *Config) []string { ... }        // ~40 LOC
func validateInterfaceParityWarnings(cfg *Config) []string { ... }        // ~60 LOC
func validateDefaultPolicyLogWarnings(cfg *Config) []string { ... }
func validatePolicyLogInertOnDenyWarnings(cfg *Config) []string { ... }
func validateJunosHostDirectDeliveryWarnings(cfg *Config) []string { ... }
func validatePreIDDefaultPolicyLogWarnings(cfg *Config) []string { ... }
func validateFilterLossPriorityWarnings(cfg *Config) []string { ... }
func validateFirewallInterfaceSpecificWarnings(cfg *Config) []string { ... }
func validateLo0FilterKernelMirrorWarnings(cfg *Config) []string { ... }
func validateFilterNoCatchAllWarnings(cfg *Config) []string { ... }
func validateDDNSBackendWarnings(cfg *Config) []string { ... }          // ~260 LOC
func validateSurfaceADDNSWarnings(cfg *Config) []string { ... }          // ~300 LOC
func validateRoutingRuleWindowWarnings(cfg *Config) []string { ... }
func validateRibGroupLeakWarnings(cfg *Config) []string { ... }
func validateCoSOversubscriptionWarnings(cos *ClassOfServiceConfig) []string { ... }
func classOfServiceClassifierQueueWarnings(cos *ClassOfServiceConfig, ...) []string { ... }
func anySamplingDirectionConfigured(cfg *Config) bool { ... }
```

Meanwhile, `compiler_validate_strict*.go` is already split:

```
pkg/config/compiler_validate_strict.go              // 200 LOC — top-level strict orchestrator
pkg/config/compiler_validate_strict_application.go  // per-domain
pkg/config/compiler_validate_strict_chassis.go
pkg/config/compiler_validate_strict_cos.go
pkg/config/compiler_validate_strict_filter.go       // 1660 LOC (the largest strict domain — already split once)
pkg/config/compiler_validate_strict_ipsec.go
pkg/config/compiler_validate_strict_nat.go
pkg/config/compiler_validate_strict_observability.go
pkg/config/compiler_validate_strict_policy.go
pkg/config/compiler_validate_strict_routing.go
pkg/config/compiler_validate_strict_screen.go
pkg/config/compiler_validate_strict_vrrp.go
pkg/config/compiler_validate_strict_zones.go
pkg/config/compiler_validate_vrf_overlap.go
pkg/config/compiler_validate_wireguard.go
```

`compiler_validate_strict` shows the proven mechanical split — 12 files, each per-domain, each <900 LOC. `compiler_validate_warn.go` at 3330 LOC is the only file that did NOT follow this pattern. It contains the same per-domain structure (each `validateXWarnings` is independent) but was never split.

### Proposed decomposition

```
pkg/config/
  compiler_validate_warn.go              // ValidateConfig top-level + inline policy/interface/app (keep ~800 LOC — the main orchestrator that calls 15 validators)
  compiler_validate_warn_hostinbound.go  // validateHostInboundMulticastWarnings + validateJunosHostDirectDeliveryWarnings + junosHostPolicySourceScoped + junosHostPolicyStricterThanCoarseGate + validatePreIDDefaultPolicyLogWarnings (~300 LOC)
  compiler_validate_warn_filter.go       // validateFilterLossPriorityWarnings + validateFirewallInterfaceSpecificWarnings + validateLo0FilterKernelMirrorWarnings + validateFilterNoCatchAllWarnings + schedulerHasEffectiveWindow + firewallFilterHasCatchAllTerminator + firewallTermIsTerminatingAction + firewallTermFromUnconstrained (~350 LOC)
  compiler_validate_warn_ddns.go         // validateDDNSBackendWarnings + ddnsUpdateServerParseable + ddnsTSIGAlgorithmSupported + ddnsKnownDyndns2Provider + ddnsDyndns2ServerValid + ddnsCheckIPURLValid + ddnsGenericURLTemplateValid + ddnsAllowlistMalformedTokens + validateSurfaceADDNSWarnings (~400 LOC)
  compiler_validate_warn_routing.go      // validateRoutingRuleWindowWarnings + validateRibGroupLeakWarnings + validateCoSOversubscriptionWarnings + classOfServiceClassifierQueueWarnings + hasFamily + anySamplingDirectionConfigured (~250 LOC)
  compiler_validate_warn_parity.go       // validateDHCPRelayParityWarnings + validateInterfaceParityWarnings + validateDefaultPolicyLogWarnings + validatePolicyLogInertOnDenyWarnings (~300 LOC)
```

Each file <500 LOC. `ValidateConfig` stays in `compiler_validate_warn.go`, imports the helpers (all `package config`, same dir, no import change). Existing `compiler_validate_warn_nil_3494_test.go` keeps passing.

### Hot-path preservation

Cold path — `ValidateConfig` runs on `Commit()` (commit-time, seconds apart). NOT per-packet hot. Split is (A) pure code-motion, byte-identical warnings slice.

### Tests+gate

- `go test ./pkg/config -run TestValidateConfig -count=1`
- `go test ./pkg/config -run TestValidateWarn -count=1` (if exists) + `TestValidateWarn_Nil_3494`
- `go vet ./pkg/config`
- Verify warnings output identical: compare `ValidateConfig(cfg)` before/after split for a corpus of test configs

### Why it matters

- `compiler_validate_warn.go` is the largest file in `pkg/config` (3330 LOC) and the only one that violates the per-domain split pattern the strict validators already established. Every new warning (DDNS #2780, surface-A #4407, CoS #1614, filter #2321) lands in this one file → merge conflicts + reviewer must load 3330 LOC for a 20-line warning.
- `engineering-style.md` "No monolithic files — ~2k LOC is a smell, ~3k must split before adding logic" — this file is 3330 LOC and still growing (last 3 months: +~400 LOC for surface-A DDNS warnings).

### Fix direction

Mechanical file split mirroring `compiler_validate_strict*.go` domain boundaries. `package config` unchanged. Functions stay identical (copy-paste to new files, delete from original). No behavior change. PR should be `go fmt` clean, `git diff --stat` shows file moves only.

### Labels

`refactor`, `modularity`, `validation`, `config`, `cold-path`, `mechanical`, `strict-parity`

### Dedup note

Not filed before. GH search `compiler_validate_warn split` returns 0. Distinct from #4421 which notes `compiler_security.go` but not `compiler_validate_warn.go`. The strict split (`compiler_validate_strict_*.go`) is complete and is the template for this fix.

---

## F-039-05: `metrics_descriptors.go` 1896 LOC — Prometheus descriptor monolith

- **Severity**: Low-Medium (reviewability / merge conflicts, NOT correctness)
- **Confidence**: HIGH — mechanical, no logic
- **Refactor class**: **(A) MECHANICAL / SAFE** — cold path (metrics_descriptors is only `newCollector` construction, `prometheus.NewDesc` calls; scrape path reads already-constructed descriptors)

### Evidence

```go
// pkg/api/metrics_descriptors.go — 1896 LOC, 279 prometheus.NewDesc calls:

func newCollector(srv *Server) *xpfCollector {
    return &xpfCollector{
        srv: srv,
        packetsTotal: prometheus.NewDesc(
            "xpf_packets_total",
            "Total packets processed.",
            []string{"direction"}, nil,
        ),
        dropsTotal: prometheus.NewDesc(
            "xpf_drops_total",
            "Packets dropped by enforcement (policy deny, screen/IDS, ...)",
            nil, nil,
        ),
        counterReadErrorsTotal: prometheus.NewDesc(...),
        sessionsCreatedTotal: prometheus.NewDesc(...),
        sessionsClosedTotal: prometheus.NewDesc(...),
        screenDropsTotal: prometheus.NewDesc(...),
        screenDropsByReasonTotal: prometheus.NewDesc(...),
        policyDeniesTotal: prometheus.NewDesc(...),
        natAllocFailsTotal: prometheus.NewDesc(...),
        nat64XlateTotal: prometheus.NewDesc(...),
        hostInboundDeny: prometheus.NewDesc(...),
        hostInboundKernelDenies: prometheus.NewDesc(...),
        hostInboundAddresslessZones: prometheus.NewDesc(...),
        hostInboundAddresslessIface: prometheus.NewDesc(...),
        hostInboundAmbiguousAddrs: prometheus.NewDesc(...),
        tcEgressPacketsTotal: prometheus.NewDesc(...),
        syncookieTotal: prometheus.NewDesc(...),
        flowCacheTotal: prometheus.NewDesc(...),
        ifacePacketsTotal: prometheus.NewDesc(...),
        ifaceBytesTotal: prometheus.NewDesc(...),
        // ... + 260 more NewDesc calls:
        // userspace_* (session table, NAT collisions, WireGuard, GRE decap, CoS admission, flow cache, event stream),
        // binding_* (active flow count, TX completions, VMin throttles),
        // cos_* (admission drops, drain, equal-flow, flow-fair, waterfill, sojourn),
        // worker_* (cold path buckets, samples, sum_ns, alias, layout version),
        // fairness_* (Cstruct, active workers, active flows, CoV, equal-flow target/observed/capped/suppressed),
        // daemon_* (uptime, RSS), config_persist_degraded, etc.
    }
}
```

279 `prometheus.NewDesc` in one function. Categories by prefix (from `grep NewDesc | sed ... | sort`):

- Global datapath (15): `xpf_packets_total`, `xpf_drops_total`, `xpf_counter_read_errors_total`, `xpf_sessions_created_total`, `xpf_sessions_closed_total`, `xpf_screen_drops_*`, `xpf_policy_denies_total`, `xpf_nat_alloc_failures_total`, `xpf_nat64_*`, `xpf_host_inbound_*`, `xpf_tc_egress_*`, `xpf_syncookie_*`, `xpf_flow_cache_*`, `xpf_iface_*`
- Userspace dataplane (40+): `xpf_userspace_session_table_*`, `xpf_userspace_nat_reverse_key_*`, `xpf_userspace_session_create_drops`, `xpf_userspace_gre_decap_*`, `xpf_userspace_wg_decap_*`, `xpf_userspace_time_exceeded_*`, `xpf_userspace_packet_too_big_*`, `xpf_userspace_reject_*`, `xpf_userspace_flow_cache_*`, `xpf_userspace_event_stream_*`
- CoS / scheduler (25+): `xpf_cos_admission_*`, `xpf_cos_drain_*`, `xpf_cos_equal_flow_*`, `xpf_cos_flow_fair_*`, `xpf_cos_lease_*`, `xpf_cos_owner_pps`, `xpf_cos_waterfill_*`, `xpf_cos_sojourn_*`
- Worker / cold-path (20+): `xpf_worker_dead`, `xpf_worker_cold_path_*` (8 variants + v3)
- Binding (10): `xpf_binding_active_flow_count`, `xpf_binding_flow_cache_capacity`, `xpf_binding_tx_*`, `xpf_binding_v_min_*`
- Fairness / flow table (15): `xpf_fairness_cstruct`, `xpf_fairness_active_*`, `xpf_fairness_observed_cov`, `xpf_fairness_equal_flow_*`
- System / daemon (5): `xpf_daemon_uptime`, `xpf_daemon_mem_rss`, `xpf_config_persist_degraded`

Every new feature (CoS #706/#718, WireGuard #1432, cold-path #1635, fairness #941, binding #878, etc.) adds 2-8 descriptors to this one file — linear growth (279 → will be 300+ by next quarter).

### Proposed decomposition

`metrics_descriptors.go` defines `newCollector` returning `*xpfCollector`. The `xpfCollector` struct is defined elsewhere (likely `metrics.go` or `metrics_counters.go`). The descriptors are stored as fields. The split strategy: keep struct definition in one place, split descriptor construction via helper functions:

```
pkg/api/
  metrics_descriptors.go              // newCollector top-level (calls helpers, ~100 LOC) + global datapath descriptors (packets, drops, counter_read_errors, sessions, screen, policy, nat, host-inbound, tc, syncookie, flow-cache, iface) — the stable core
  metrics_descriptors_userspace.go    // newCollectorUserspace — userspace dataplane descriptors (session table, NAT, WireGuard, GRE, ECN, reject, flow-cache, event-stream, neighbor, session publish) (~400 LOC)
  metrics_descriptors_cos.go          // newCollectorCoS — CoS/queue descriptors (admission, drain, equal-flow, flow-fair, lease, owner, waterfill, sojourn) (~300 LOC)
  metrics_descriptors_binding.go      // newCollectorBinding — binding-scoped descriptors (active flow count, TX, VMin) (~150 LOC)
  metrics_descriptors_worker.go       // newCollectorWorker — worker + cold-path descriptors (worker_dead, cold_path_bucket/samples/sum_ns/alias/layout, v3) (~250 LOC)
  metrics_descriptors_fairness.go     // newCollectorFairness — fairness harness descriptors (Cstruct, active workers/flows, CoV, equal-flow target/observed/capped/suppressed) (~250 LOC)
  metrics_descriptors_system.go       // newCollectorSystem — daemon/system descriptors (uptime, RSS, config_persist_degraded) (~50 LOC)
```

Alternative (simpler): keep `newCollector` in one file, extract only descriptor literals to helper funcs returning `*prometheus.Desc` per subsystem. This avoids struct-field reordering and keeps `xpfCollector` field init in one call site.

Simpler decomposition (no helper funcs, just file split on struct literal comments):

```
pkg/api/
  metrics_descriptors_global.go    // packetsTotal, dropsTotal, counterReadErrorsTotal, sessions*, screen*, policyDeniesTotal, nat*, hostInbound*, tc*, syncookie, flowCache, iface* — stable core
  metrics_descriptors_userspace.go // userspace* — session table, NAT, WG, GRE, reject, flow-cache, event-stream
  metrics_descriptors_cos.go       // cos*, binding*, fairness equal-flow
  metrics_descriptors_worker.go    // worker*, cold_path*
  metrics_descriptors_fairness.go  // fairness* (harness)
  metrics_descriptors_system.go    // daemon*, config_persist_degraded
```

Each file <500 LOC. All fields of `xpfCollector` are init in the same function — need a single `newCollector` that calls per-file helpers OR the struct literal is split across files via a builder pattern. The cleanest: `newCollector` in `metrics_descriptors.go` calls `c.initGlobalDescriptors()`, `c.initUserspaceDescriptors()`, etc., where each `init*` is in its own file and operates on `*xpfCollector` receiver.

### Hot-path preservation

Cold path — `newCollector` runs once at daemon start (in `NewServer`). `prometheus.NewDesc` is pure allocation (no I/O, no syscalls). Prometheus scrape path (`Collect` method) reads already-constructed descriptors — it does NOT call `newCollector`. Split is (A) mechanical, no hot-path change. Scrape frequency is <10/s (Prometheus default 15s), not per-packet.

### Tests+gate

- `go test ./pkg/api -run TestMetricsDescriptors -count=1` — existing `metrics_descriptor_coverage_test.go` (726 LOC) verifies every `*Desc` field is non-nil after `newCollector`
- `go test ./pkg/api -run TestMetrics -count=1` — existing `metrics_test.go` (2432 LOC) + `metrics_scoped_global_3286_test.go` + `metrics_cold_path_test.go`
- `go vet ./pkg/api`
- After split, run `go test ./pkg/api -run TestMetricsDescriptorCoverage` to verify no descriptor dropped

### Why it matters

- `metrics_descriptors.go` is the #1 merge-conflict file in `pkg/api` — every CoS/scheduler/NAT/WG/cold-path/fairness feature adds descriptors here. Last 3 months: +~40 descriptors (CoS waterfill, sojourn, equal-flow, WG decap ECN, cold-path v3, binding VMin).
- Reviewer must load 1896 LOC to review a 4-line descriptor addition.
- `metrics_userspace.go` (1819 LOC, the emitter) is already a separate file — descriptors and emitters are split by design, but descriptors themselves are not split by subsystem.

### Fix direction

Extract per-subsystem descriptor construction to helper methods on `*xpfCollector` in new files. Keep `newCollector` top-level in `metrics_descriptors.go` as a 20-line orchestrator:

```go
func newCollector(srv *Server) *xpfCollector {
    c := &xpfCollector{srv: srv}
    c.initGlobalDescriptors()
    c.initUserspaceDescriptors()
    c.initCoSDescriptors()
    c.initBindingDescriptors()
    c.initWorkerDescriptors()
    c.initFairnessDescriptors()
    c.initSystemDescriptors()
    return c
}
```

Each `init*` is in its own file. No logic change, no new allocations, no new types. Pure code-motion.

### Labels

`refactor`, `modularity`, `metrics`, `prometheus`, `cold-path`, `mechanical`, `low-risk`

### Dedup note

Not filed before. GH search `metrics_descriptors split` returns 0. Distinct from #4404-#4406 (Rust) and #4407 (daemon god-struct). `metrics_userspace.go` (1819 LOC, the emitter) is a different file — this filing is for the descriptor side.

---

## (D) Negatives — not monoliths or intentionally not split

### D-01: `maps_sync.go` 1763 LOC — focused, NOT a monolith (D)

`pkg/dataplane/userspace/maps_sync.go` is 1763 LOC but has single responsibility: userspace map sync (programBootstrapMapsLocked, syncUserspaceClassifierMapsLocked, syncIngressIfaceMapLocked, syncLocalAddressMapsLocked, applyHelperStatusLocked, etc.). It is NOT a fusion of unrelated domains. The 1763 LOC is justified by the number of BPF maps (9 maps: ctrl, bindings, heartbeat, xsk, local_v4, local_v6, sessions, conntrack_v4, conntrack_v6, dnat_table, trace, plus CPU map) and the per-map sync logic. Splitting by map would create 9 files of ~150 LOC each with no independent review value — the maps are synced atomically under `programBootstrapMapsLocked` and share `userspaceCtrlValue` / `userspaceBindingKey` types.

**Verdict**: (D) — single responsibility, not a split candidate. Keep as-is.

### D-02: `vrrp/instance.go` 2417 LOC — single coherent VRRP state machine (D, with caveat)

`pkg/vrrp/instance.go` is 2417 LOC, above the 2000-LOC smell threshold. It contains 52 funcs: VRRP state machine (StateInitialize/Backup/Master, stepBackup, run), RX (receiver, receiverIPv6, receiverAfPacket, parseAfPacketIPv4/IPv6, walkIPv6ExtHeaders), TX (sendAdvert, sendPacket, sendPacketIPv6, becomeMaster, becomeBackup), GARP (sendGARP, etc.), advert interval (advertInterval, effectiveAdvertInterval, masterDownInterval, preemptHoldDuration), preempt-hold (armPreemptHold, disarmPreemptHold, preemptingLiveLowerMaster, heldMasterIsStale), VIP (addVIPs, removeVIPs, vipAddrSet, resolveLocalIPv4), and helpers (interfaceAddrs, getLocalIP, setLocalIP, etc.).

All 52 funcs operate on `*vrrpInstance` and are part of one RFC 5798 VRRPv3 state machine. The file is large because VRRP has many sub-protocols (IPv4 RX via AF_PACKET + IPv6 RX via raw socket + IPv6 NODAD + track-interface + preempt-hold + sync-hold + GARP burst + owner-preempt + learned-advert-interval + priority-0 abdication + gratuitous ARP probe target). Splitting RX/TX/GARP into separate files would break the state machine's single-goroutine invariant (run-loop goroutine owns all timers + mu) and make it harder to verify `stepBackup`'s preempt-hold timing.

The file was split once already: `track.go` (track-interface), `packet.go` (VRRP packet encode/decode), `addrwatch.go` (address watch), `vrrp.go` (VRRP constants). The remaining `instance.go` is the state-machine core.

**Verdict**: (D) — single coherent responsibility (VRRP state machine), intentionally kept together. If it grows past ~2800 LOC, consider extracting `instance_rx.go` (receiver + parseAfPacket + walkIPv6ExtHeaders) and `instance_garp.go` (sendGARP + garpEpoch/garpDampened), but NOT in this batch. The 2417 LOC is justifiable given the VRRP RFC complexity.

### D-03: `daemon_run.go` 2329 LOC + `daemon_apply.go` 1935 LOC — already filed #4407 (D for this report)

`pkg/daemon/daemon.go` (763 LOC) defines `type Daemon struct` with 150+ fields. `daemon_run.go` (2329 LOC) defines `Run()` (~1690 LOC, ordering-sensitive lifecycle) + `buildRuntimeDataPlane` + `collectAppliedTunnels` + `namingParamsFromConfig` + `applyStartupNamingForConfig` + `maybeReapplyConfigArrivalNaming` + `runBootstrapExitStartup` + `inferIPv6StaticNextHopInterfaces` + `runHAShutdownUpdate` + `enableForwarding`. `daemon_apply.go` (1935 LOC) defines `applyConfigLocked` (~1148 LOC god-function) + `applyTailReconciles` + `commitAndApply` + `commitConfirmedAndApply` + `executeConfirmedRollback` + `reconcileDHCPRelay` + `reconcileLLDP` + etc.

Already filed as #4407 (Daemon god-struct, 150+ fields, ~3500 LOC) + daemon_apply.go applyConfigLocked (1148 LOC) — tracked as increment 1..5 (surfaceAState grouping #4407 inc 5 merged). This report does NOT re-file it.

**Verdict**: (D) — already tracked, do not double-file.

---

## Cross-cutting notes

### Hot-path preservation summary

| File | Path is hot? | Split safe? | Reasoning |
|------|-------------|-------------|-----------|
| `protocol.go` | NO — cold (config-apply + status poll 1/s) | (A) SAFE | Wire format never on per-packet path. Byte-identical JSON after split. |
| `sync_conn.go` | NO — cold (1s sweep + on-demand HA sync) | (A) but ORDERING-SENSITIVE | Generation-guard state machine must preserve stamp→queue→take ordering. Single-active-fabric invariant must be preserved (activeConnLocked prefers conn0, never both). |
| `tunnel.go` | NO — cold (commit + keepalive 1s+) | (A) SAFE | Tunnel create on commit, keepalive tick at seconds. NOT per-packet. |
| `compiler_validate_warn.go` | NO — cold (commit-time) | (A) SAFE | Warn validators are pure functions `func(cfg *Config) []string`, no state, no I/O. |
| `metrics_descriptors.go` | NO — cold (daemon start + Prometheus scrape 1/15s) | (A) SAFE | `newCollector` runs once at startup. Scrape reads already-constructed descriptors. |
| `vrrp/instance.go` | NO — NOT per-packet (30ms RETH advert, 100ms master-down) | (D) KEEP — single SM | VRRP is timer-driven, not per-packet. But splitting the SM would hurt correctness review. |
| `maps_sync.go` | NO — cold (config-apply + helper status poll) | (D) KEEP — single domain | Map sync is one cohesive operation under one mu. |

No hot-path allocations added by any proposed split. All splits are cold-path code-motion.

### Classification legend

- **(A) MECHANICAL / SAFE**: Cold path, pure code-motion, `go build` / `go test` byte-identical, no ordering change, no new types, no new mutexes, no hot-path change. Safe to land without feature flag.
- **(B) MECHANICAL with ORDERING CONSTRAINTS**: Cold path, pure code-motion, but must preserve a documented ordering invariant (gen-guard, bulk re-drive, fabric preference). Reviewer must verify the invariant comment is preserved.
- **(C) NEEDS REFACTOR DESIGN**: Hot path or requires new abstraction (interface, channel, state machine enum) before split. Not used in this report — all A4 files are cold path.
- **(D) NEGATIVE / NOT A MONOLITH**: File is large but has single coherent responsibility, or already filed, or intentionally kept together for correctness.

### Tests + gate for all findings

```bash
go vet ./pkg/config ./pkg/dataplane/userspace ./pkg/cluster ./pkg/routing ./pkg/vrrp ./pkg/api ./pkg/daemon
go test ./pkg/config -run TestValidate -count=1
go test ./pkg/dataplane/userspace -run TestProtocol -count=1
go test ./pkg/dataplane/userspace -run TestSnapshot -count=1
go test ./pkg/cluster -run TestGenGuard -count=1
go test ./pkg/cluster -run TestSync -count=1
go test ./pkg/routing -count=1
go test ./pkg/api -run TestMetricsDescriptorCoverage -count=1
go test ./pkg/api -run TestMetrics -count=1
# Cluster integration (for sync_conn.go):
make test-failover   # 0 / very low packet loss across failover/failback
make test-ha-crash   # multi-cycle crash recovery
```

Byte-identical check: `go build -o /tmp/xpfd.before ./cmd/xpfd && <split> && go build -o /tmp/xpfd.after ./cmd/xpfd && cmp /tmp/xpfd.before /tmp/xpfd.after` — should be identical for pure code-motion (A) findings. For (B) ordering-sensitive, run `go test -race ./pkg/cluster -count=10` to detect ordering regressions.

### Why splitting matters (engineering-style.md)

> "No monolithic files. A `.rs` file that crosses ~2,000 LOC of production code (excluding `mod tests`) is a smell. By the time it hits ~3,000 LOC the next change to that file should split it before adding new logic. Apply the same rule to test files."
>
> "One responsibility per module. A module that mixes admission policy with byte-mutation, or memory mapping with ring management, will get sliced apart eventually — do it on the way in."

All 5 findings violate the 2k/3k LOC rule and the one-responsibility rule. `compiler_validate_warn.go` (3330 LOC) is the largest file in `pkg/config`; `protocol.go` (2979 LOC) is the largest production file in `pkg/dataplane/userspace`; `sync_conn.go` (1858 LOC) is the second-largest in `pkg/cluster`; `tunnel.go` (1877 LOC) is the largest in `pkg/routing`; `metrics_descriptors.go` (1896 LOC) is the largest descriptor file in `pkg/api`.

### Fix direction (priority order)

1. **F-039-01 `protocol.go`** — highest value, lowest risk (pure type defs, no logic, no mutexes, no goroutines, no ordering). Mechanical file split, 1 PR.
2. **F-039-04 `compiler_validate_warn.go`** — proven pattern (strict already split), pure functions, no state. Mechanical file split, 1 PR.
3. **F-039-05 `metrics_descriptors.go`** — pure `NewDesc` calls, no logic, trivial helper extraction. Mechanical, 1 PR.
4. **F-039-03 `tunnel.go`** — 5 responsibilities, but each is well-bounded (GRE vs WG vs keepalive vs VRF vs address). Mechanical file split, 1 PR.
5. **F-039-02 `sync_conn.go`** — highest correctness risk (gen-guard ordering, bulk re-drive, fabric preference). Requires careful review of lock ordering + single-active-fabric invariant. Mechanical but must preserve `#2198 F3` / `#2221` / `#2995` comments. 1 PR, with `go test -race -count=10`.

Suggested PR order: `protocol.go` → `compiler_validate_warn.go` → `metrics_descriptors.go` → `tunnel.go` → `sync_conn.go` (easiest → hardest). Each PR should be pure code-motion (`git diff` shows only file moves + func relocations, no logic change). Land one at a time, verify `go vet` + `go test` green before next.

### Dedup

- **#4407 Daemon god-struct (150+ fields, ~3500 LOC) + daemon_apply.go applyConfigLocked (1148 LOC)** — ALREADY FILED, tracked as increment 1..5. This report marks `daemon_run.go` + `daemon_apply.go` as D-03 (do not double-file).
- **#4421 flowexport monolithic, firewall-filter validation, pkg/routing/rules.go 3 domains, Surface-A DDNS, event-engine, compiler_security.go** — ALREADY FILED / different batch. This report does NOT re-file `rules.go` (nextTable/ribGroup/pbrManager) or `flowexport` or `compiler_security.go`.
- **#4404-#4406 poll_descriptor / Rust monoliths** — different batch (Rust, not Go). Not re-filed.
- **#4408-#4409 NAT allocation / persistent-lease** — different batch (NAT dataplane, not wire/format/tunnel). Not re-filed.
- No prior issue for `protocol.go` split, `sync_conn.go` gen-guard split, `tunnel.go` keepalive split, `compiler_validate_warn.go` warn-split, or `metrics_descriptors.go` descriptor split (verified via `gh issue list --search` for each file name + `monolithic` + `split` + `refactor`).

### Labels for new issues

- `refactor`, `modularity`, `tech-debt`, `cold-path`, `mechanical` (all 5)
- Plus per-finding: `ha` / `gen-guard` (F-039-02), `tunnel` / `keepalive` / `wireguard` (F-039-03), `validation` / `config` (F-039-04), `metrics` / `prometheus` (F-039-05), `wire-format` / `protocol` (F-039-01)


# Issue & PR History Index — 2026-07-13T06:46:08.116147

Total issues: 2306 (Open: 53 )
Total PRs: 2183

## All Issues (searchable)

| Number | State | Title |
|--------|-------|-------|
| #6 | CLOSED | test auth check |
| #7 | CLOSED | Interface-mode SNAT can select wrong source IP on snat_egress lookup miss |
| #8 | CLOSED | IPv4 DNAT-before-fabric helper uses fixed L3/L4 offsets |
| #9 | CLOSED | IPv4 DNAT-before-fabric skips port-only DNAT due dst-IP short-circuit |
| #10 | CLOSED | Host-inbound filtering defaults to allow for unknown services |
| #11 | CLOSED | CLI: show security flow session nat-only is advertised but not parsed |
| #12 | CLOSED | CLI: show security policies global does not return global-only view |
| #13 | CLOSED | CLI: show security ipsec security-associations detail is ignored |
| #14 | CLOSED | CLI: show interfaces <name> extensive is not implemented |
| #15 | CLOSED | CLI: show route destination modifiers exact/longer/orlonger are unsupported |
| #16 | CLOSED | Routing: show route <prefix> CIDR matching logic is narrower than documented |
| #17 | CLOSED | CLI: top-level show bgp summary alias missing |
| #18 | CLOSED | CLI pipe filters are case-insensitive but Junos reference is case-sensitive |
| #19 | CLOSED | CLI: show security flow session summary uses non-Junos output schema |
| #20 | CLOSED | CLI: show security flow session format diverges from Junos reference |
| #21 | CLOSED | CLI: show arp no-resolve syntax and output format do not match reference |
| #22 | CLOSED | CLI: show system processes summary is not implemented (raw ps output only) |
| #23 | CLOSED | CLI: show security policies default output format does not match Junos reference |
| #24 | CLOSED | CLI: show security log output format is not Junos RT_FLOW style |
| #25 | CLOSED | CLI: show security zones output format diverges from Junos reference |
| #26 | CLOSED | CLI: show security policies hit-count column layout does not match reference |
| #27 | CLOSED | CLI: show security policies detail output diverges from Junos reference schema |
| #28 | CLOSED | CLI: show security alg status command/format parity gaps |
| #29 | CLOSED | Routing: show route summary missing Junos Highwater Mark section |
| #30 | CLOSED | Compiler: policy expansion can overflow MaxRulesPerPolicy and spill into adjacent sets |
| #31 | CLOSED | Compiler: NAT rule counter IDs can exceed nat_rule_counters capacity |
| #32 | CLOSED | Compiler: NAT64 auto-assigned source pools ignore map-write failures and pool-capacity limits |
| #33 | CLOSED | Compiler: static NAT mixed IPv4/IPv6 rules are not rejected |
| #34 | CLOSED | Compiler: DNAT CIDR inputs lose mask semantics (compiled as single IP) |
| #35 | CLOSED | Compiler: port-mirroring interface lookup skips LinuxIfName normalization |
| #36 | CLOSED | Performance: policy evaluation scans rules linearly with per-rule map lookups |
| #37 | CLOSED | Performance: replace hot-path zone_pair_policies hash lookup with array indexing |
| #38 | CLOSED | Performance: SNAT compile repeats pool parse/map writes for every referencing rule |
| #39 | CLOSED | Performance: SNAT rule matching does linear hash-probing in XDP hot path |
| #40 | CLOSED | Performance: compile interface setup relies on repeated ethtool subprocess calls |
| #41 | CLOSED | Performance: compiler does repeated interface/link lookups without per-pass caching |
| #42 | CLOSED | Performance: application port-range expansion causes O(range) compile/map-write overhead |
| #43 | CLOSED | Performance: firewall filter evaluation does linear per-rule map lookups in both XDP ingress and TC egress |
| #44 | CLOSED | Performance: avoid duplicate iface_zone_map lookup across xdp_screen -> xdp_zone pipeline |
| #45 | CLOSED | Performance: remove unnecessary atomic RMW on per-CPU global counters in XDP/TC hot paths |
| #46 | CLOSED | Performance: xdp_zone failover branches perform repeated FIB lookups and duplicate post-FIB work |
| #47 | CLOSED | Performance: tc_forward mirror sampling uses expensive modulo + atomic per packet |
| #48 | CLOSED | Performance: reduce repeated flow_config_map lookups in XDP/TC conntrack paths |
| #49 | CLOSED | Performance: NAT64 paths do heavy full-payload checksum scans |
| #50 | CLOSED | Performance: evaluate DEVMAP array instead of DEVMAP_HASH for XDP redirect hot path |
| #56 | CLOSED | Failover: IPv4 pre-fabric DNAT rewrite is not CHECKSUM_PARTIAL-safe |
| #57 | CLOSED | HA fabric: fib_ifindex selection can remain 0 and break main-table re-FIB |
| #58 | CLOSED | DPDK parity gap: zone-encoded fabric redirect decode is still TODO |
| #59 | CLOSED | HA fabric: peer MAC resolution is IPv4-only (no NDP path) |
| #60 | CLOSED | Failover: sessionless FABRIC_FWD re-FIB failure falls through to XDP_PASS (kernel leak path) |
| #61 | CLOSED | xdp_zone: sessionless FABRIC_FWD NO_NEIGH path falls through to XDP_PASS/host-inbound |
| #62 | CLOSED | xdp_zone: UNREACHABLE/BLACKHOLE FABRIC_FWD branch still leaks to host path when main-table re-FIB misses |
| #63 | CLOSED | cluster refreshFabricFwd: fallback fib_ifindex selection is non-deterministic and may pick wrong routing context |
| #64 | CLOSED | DPDK zone-encoded fabric decode returns too early and lacks fabric-ingress validation |
| #65 | CLOSED | DPDK active/active: zone-encoded fabric validation compares port_id against kernel ifindex |
| #66 | CLOSED | HA failover race: cluster/VRRP handlers apply rg_active side effects from stale transitions |
| #68 | CLOSED | HA mode: disable hitless restart semantics by default |
| #69 | CLOSED | SessionSync: stale receive goroutine can tear down the active peer connection |
| #70 | CLOSED | SessionSync: BulkSync should honor per-RG ownership (same as sweep) |
| #71 | CLOSED | SessionSync: Bulk transfer needs authoritative stale-entry reconciliation |
| #72 | CLOSED | HA failover: add peer fencing path on heartbeat timeout |
| #73 | CLOSED | HA tests: add hard-crash/hung-node failover coverage |
| #74 | CLOSED | Investigation: transient 10-30s loss to 172.16.100.247 after deploy restart |
| #75 | CLOSED | HA restart: neighbor prewarm runs before VRRP VIP ownership, causing 10-30s transient WAN loss |
| #76 | CLOSED | HA race: SessionSync has unsynchronized concurrent conn writers and short-write hazards |
| #77 | CLOSED | HA race: fixed 10s VRRP sync-hold timeout can release before bulk sync completes |
| #78 | CLOSED | HA race: reconnect config sync can accept stale secondary config (authority not enforced) |
| #79 | CLOSED | HA readiness: fabric_fwd population is passively delayed and race-prone at startup |
| #80 | CLOSED | HA correctness: periodic neighbor warmup uses stale startup config snapshot |
| #81 | CLOSED | HA startup bug: heartbeat/session-sync retry exhaustion can permanently disable cluster comms |
| #82 | CLOSED | HA startup race: initial BulkSync may be skipped before dataplane wiring |
| #83 | CLOSED | HA race: session delete sync is not per-RG ownership-safe in active/active |
| #84 | CLOSED | HA race: VRRP event watcher uses background context and outlives shutdown lifecycle |
| #85 | CLOSED | HA reliability: sync queue overflow drops critical control messages without replay |
| #86 | CLOSED | HA race: dropped cluster events are not repaired for VRRP control actions |
| #87 | CLOSED | HA bug: heartbeat/session-sync endpoints are one-shot and not reconfigured on runtime config changes |
| #88 | CLOSED | HA safety bug: manual failover can self-blackhole when peer is already down |
| #89 | CLOSED | HA race: stale session-sync receive loops can disconnect a newer active connection |
| #90 | CLOSED | HA protocol bug: session-sync writes are unsynchronized and can corrupt frames |
| #91 | CLOSED | HA startup race: SESSION_OPEN sync callback can be skipped permanently |
| #92 | CLOSED | HA election bug: stale peer RG entries persist across heartbeats |
| #93 | CLOSED | HA drift bug: reconcile loop does not repair RA/DHCP service ownership after dropped VRRP events |
| #94 | CLOSED | HA lifecycle race: cluster watcher/comms use pre-signal context and can outlive shutdown cancel |
| #96 | CLOSED | VRRP startup sync-hold race allows preempt-before-sync on node rejoin |
| #98 | CLOSED | HA neighbor warmup skips interface-qualified static next-hops with Junos interface names |
| #99 | CLOSED | HA sync protocol still vulnerable to short-write frame truncation |
| #100 | CLOSED | HA heartbeat can truncate with large monitor payloads and trigger false peer loss |
| #101 | CLOSED | HA failover recovery delayed by fixed 10s VRRP posture mismatch timer |
| #102 | CLOSED | HA fail-closed gap: ungraceful daemon failures can leave stale forwarding active |
| #103 | CLOSED | HA startup: block primary takeover until interfaces/VRRP are ready and hold timer expires |
| #104 | CLOSED | HA same-L2: add strict single-owner VIP mode to stop duplicate NA ownership churn |
| #107 | CLOSED | HA syntax parity: implement vSRX dual-fabric (fab0 + fab1) architecture |
| #110 | CLOSED | HA private-rg-election: gate RG promotion on session sync readiness |
| #111 | CLOSED | HA mode check mismatch: startup sync-hold logic ignores private-rg-election semantics |
| #112 | CLOSED | private-rg-election gap: knob exists but no dedicated fast per-RG private advert protocol yet |
| #113 | CLOSED | HA dual-active resolution: add winner-side ownership reaffirm (GARP/NA) |
| #114 | CLOSED | HA: move session/config sync transport to control link (fxp1) |
| #115 | CLOSED | HA private-rg-election: include VIP ownership in takeover readiness gate |
| #116 | CLOSED | HA regression: chained hard-reset failover (fw0 crash/rejoin -> fw1 crash) stalls recovery |
| #117 | CLOSED | HA session-sync: concurrent bulk writers can interleave epochs and trigger false stale deletes |
| #118 | CLOSED | HA session-sync: stale reconciliation should use BulkStart ownership snapshot |
| #119 | CLOSED | HA session-sync: delete/session deltas are dropped while disconnected with no replay journal |
| #120 | CLOSED | cluster/session-sync: Stats() copies atomic fields (go vet copylocks failure) |
| #121 | CLOSED | fabric: clear stale fabric_fwd entry when fab0/fab1 neighbor or link goes invalid |
| #122 | CLOSED | fabric: refreshFabricFwd programs dead links because it never checks oper-state |
| #123 | CLOSED | dual-fabric session sync uses one replaceable conn and can flap between fab0/fab1 |
| #124 | CLOSED | fabric: no event-driven refresh on link/neigh changes leaves up to 30s redirect blackholes |
| #125 | CLOSED | dual-fabric: peer gRPC/monitor path is still single-address and does not fail over to fab1 |
| #126 | CLOSED | dpdk: fabric redirect support is only partial; no DPDK equivalent of try_fabric_redirect found |
| #127 | CLOSED | fabric IPVLAN: existing fab0/fab1 overlay skips address reconciliation on reapply |
| #128 | CLOSED | fabric IPVLAN: stale fab0/fab1 overlays are never cleaned up when config changes |
| #129 | CLOSED | fabric IPVLAN: populateFabricFwd probes ARP/NDP on parent while fabric IP lives on overlay |
| #130 | CLOSED | compiler: vSRX fab0/fab1 auto-detect still collapses to a single runtime fabric interface |
| #131 | CLOSED | HA session-sync: established flows are never refreshed after SESSION_OPEN |
| #132 | CLOSED | HA rg_active: a redundancy group becomes active when any VRRP instance flips MASTER |
| #133 | CLOSED | private-rg-election: sync readiness is never reset for a fresh peer rejoin |
| #134 | CLOSED | cluster: takeover hold timer is edge-triggered and may never promote when the timer expires |
| #135 | CLOSED | monitor interface: fab0/fab1 samples the IPVLAN overlay instead of the physical fabric parent |
| #136 | CLOSED | monitor traffic interface fab0/fab1 captures the overlay, not the wire-level fabric path |
| #137 | CLOSED | fabric redirect: try_fabric_redirect paths never update per-interface TX counters |
| #138 | CLOSED | fabric observability: tcpdump/monitor traffic is not a reliable view of XDP fabric redirects |
| #139 | CLOSED | fabric observability: no per-link redirect counters or trace events for fab0 vs fab1 |
| #140 | CLOSED | rpm: hierarchical 'target url ...' syntax compiles to the literal string 'url' |
| #141 | CLOSED | rpm: 'routing-instance' is parsed but ignored at runtime |
| #142 | CLOSED | rpm: 'probe-limit' from 'vsrx.conf' is silently ignored |
| #143 | CLOSED | dynamic-address: 'feed-name { path ... }' and 'address-name profile' from 'vsrx.conf' are not implemented |
| #144 | CLOSED | flow-monitoring: 'export-extension app-id/flow-dir' from 'vsrx.conf' is ignored or only partially honored |
| #145 | CLOSED | services: 'application-identification' in 'vsrx.conf' is still parse-only |
| #146 | CLOSED | security: 'pre-id-default-policy' from 'vsrx.conf' is parsed but not wired |
| #147 | CLOSED | system: license autoupdate url is intentionally syntax-only/no-op |
| #148 | CLOSED | system: 'ntp threshold action' from 'vsrx.conf' is parsed but ignored |
| #149 | CLOSED | security flow: 'power-mode-disable' from 'vsrx.conf' has no runtime effect |
| #150 | CLOSED | security: 'policy-stats system-wide' from 'vsrx.conf' is ignored |
| #154 | CLOSED | ike/ipsec: gateway external-interface is parsed but ignored for local_addrs and egress selection |
| #155 | CLOSED | ike/ipsec: proposal lifetime-seconds is parsed but never emitted to swanctl |
| #156 | CLOSED | ike: dead-peer-detection modes all collapse to a hardcoded dpd_delay = 10s |
| #157 | CLOSED | ike: Junos $9$ pre-shared-key strings are passed verbatim to strongSwan |
| #158 | CLOSED | ike: authentication-method is parsed but swanctl generation hardcodes auth = psk |
| #159 | CLOSED | ipsec: full traffic-selector syntax is still unsupported; only one local_ts/remote_ts pair exists |
| #164 | CLOSED | perf/xdp: add per-CPU IPv6 established-flow cache in xdp_zone |
| #165 | CLOSED | perf/xdp: add IPv6 no-extension-header fast path to parse_ipv6hdr |
| #166 | CLOSED | perf/dataplane: split hot and cold IPv6 session state |
| #167 | CLOSED | perf/observability: expose IPv6 established-flow cache hit and flush counters |
| #168 | CLOSED | perf/dataplane: compact IPv6 session key to reduce hash-map cost |
| #170 | CLOSED | perf/xdp: reduce IPv6 checksum-partial detection cost in xdp_main |
| #179 | CLOSED | perf/nat: reduce IPv6 nat_rewrite_v6 hot-path cost |
| #180 | CLOSED | perf/xdp: reduce pkt_meta init and parse overhead in xdp_main |
| #185 | CLOSED | HA session-sync: per-zone ownership mapping is not safe for active/active zones spanning multiple RGs |
| #186 | CLOSED | HA failover gating: sync readiness is decoupled from fabric redirect readiness |
| #187 | CLOSED | xdp_zone: NO_NEIGH active-active check drops VLAN context and can skip required fabric failover |
| #188 | CLOSED | HA readiness: RGInterfaceReady treats missing local interfaces as peer-owned and can falsely unblock takeover |
| #189 | CLOSED | HA readiness: RGVRRPReady reports ready when an RG has no local VRRP instance |
| #191 | CLOSED | HA IPv6 failover: no NDP probe equivalent to IPv4 gateway ARP probe |
| #192 | CLOSED | HA IPv6 failover: per-node RETH MAC/link-local identity makes failover weaker than IPv4 |
| #193 | CLOSED | HA IPv6 failover: failed-neighbor cleanup reprobes IPv4 only |
| #196 | CLOSED | userspace: SNAT reply traffic black-holed on slow path reinjection |
| #197 | CLOSED | userspace: silent packet drops when frame build returns None |
| #198 | CLOSED | userspace: O(n) reverse session repair causes latency spikes under load |
| #199 | CLOSED | userspace: port corruption in copy-based forwarding path |
| #200 | CLOSED | userspace: XDP shim redirects all traffic to userspace (session check unused) |
| #201 | CLOSED | userspace: UMEM frame exhaustion under TX backpressure stalls RX |
| #202 | CLOSED | userspace-dp: port authority design fragility causes policy thrashing |
| #203 | CLOSED | userspace-dp: UMEM frame leak on TxError::Drop in transmit_prepared_batch |
| #204 | CLOSED | userspace-dp: shared_sessions not cleared on stop() persists stale data |
| #205 | CLOSED | userspace-dp: in-place TX path is nearly dead code (same-interface hairpin only) |
| #206 | CLOSED | userspace-dp: unused mutable slice in validation path |
| #253 | CLOSED | Userspace AF_XDP libxdp migration postmortem |
| #266 | CLOSED | userspace event stream helper parses control frames unsafely on partial Unix-stream reads |
| #267 | CLOSED | userspace event-stream DrainRequest does not fence a target sequence during demotion prep |
| #268 | CLOSED | daemon event-stream ack advances before session event callback finishes |
| #269 | CLOSED | graceful demotion currently drops kernel session-open sync events instead of draining them |
| #270 | CLOSED | session sync still double-produces steady-state kernel updates via ring events and LastSeen sweep |
| #271 | CLOSED | show security flow sessions walks and sorts the full session table before printing |
| #272 | CLOSED | show security flow sessions interface filter is currently only a zone filter |
| #273 | CLOSED | show security flow sessions should display interfaces and zones consistently |
| #274 | CLOSED | GetSessions RPC still builds session listings with full-table iteration and per-entry enrichment |
| #275 | CLOSED | GetSessions still relies on full-table iteration and eager enrichment after sort removal |
| #276 | CLOSED | userspace demotion prep resumes helper event stream before final barrier completes |
| #277 | CLOSED | helper demotion and session-export waits still hardcode a 2s timeout |
| #278 | CLOSED | userspace RG transition pre-switch has no rollback when UpdateRGActive fails |
| #279 | CLOSED | ctrl re-enable after RG transition is not gated on transitioned-RG convergence |
| #280 | CLOSED | daemon event-stream watermarks survive helper reconnect and stale-drain the next connection |
| #281 | CLOSED | HA session refresh paths still scan and clone the full helper session tables |
| #282 | CLOSED | ctrl re-enable stale-session cleanup stops after fixed delete caps |
| #283 | CLOSED | pendingRGTransition stays set when syncHAStateLocked fails |
| #284 | CLOSED | single global pendingRGTransition bool is not sufficient for multi-RG HA transitions |
| #285 | CLOSED | promoting node no longer pre-switches out of userspace before RG activation |
| #286 | CLOSED | HA reverse-session refresh still clones the full local session table before filtering |
| #287 | CLOSED | reverse-session prewarm now filters too narrowly by forward session owner RG |
| #288 | CLOSED | userspace pending-neighbor retry ignores non-dynamic neighbor state |
| #289 | CLOSED | userspace reply-side redirect is missing for post-deploy SNATed direct-host ICMP |
| #290 | CLOSED | ordinary XDP reply path lacks reverse-NAT fallback for interface-NAT destinations |
| #291 | CLOSED | XDP interface-NAT session misses are not surfaced as a distinct counter or trace path |
| #292 | CLOSED | userspace helper TX counters do not fully describe prepared fast-path transmit state |
| #293 | CLOSED | userspace compiler falls back all interfaces to generic XDP on one attach failure |
| #294 | CLOSED | userspace helper picks zerocopy from driver name instead of actual XDP mode |
| #297 | CLOSED | manual RG failover still collapses after reverse prewarm with stable ownership and flat session misses |
| #298 | CLOSED | demotion cleanup immediately deletes shared USERSPACE_SESSIONS entries but leaves worker-local owner-RG sessions until a |
| #302 | CLOSED | Enforce a strict userspace-only forwarding invariant |
| #303 | CLOSED | Define explicit runtime modes for userspace_strict, userspace_compat, and ebpf_only |
| #304 | CLOSED | Disallow transit fallback from xdp_userspace_prog into xdp_main_prog or XDP_PASS in strict mode |
| #305 | CLOSED | Remove or narrowly scope PASS_TO_KERNEL session actions for strict userspace mode |
| #306 | CLOSED | Make XSK liveness failure explicit instead of silently swapping back to xdp_main_prog |
| #307 | CLOSED | Expose per-interface entry program and transit fallback counters in status and validation |
| #308 | CLOSED | Reduce HA failover toward a MAC-move-only model |
| #309 | CLOSED | Enumerate forwarding-relevant state that is not carried in continuous session sync |
| #310 | CLOSED | Make reverse-companion and translated-alias state deterministic at takeover |
| #311 | CLOSED | Define an install fence for HA cutover instead of relying on continuous sync alone |
| #312 | CLOSED | Reduce helper-local cache and non-session dependencies at RG transition |
| #314 | CLOSED | HA cutover still lacks a helper worker-completion acknowledgment |
| #315 | CLOSED | Continuous userspace HA sync still omits local-delivery session state |
| #316 | CLOSED | Cluster-synced reverse sessions are still not mirrored into the userspace helper |
| #317 | CLOSED | Userspace session sync still depends on activation-time local egress re-resolution |
| #318 | CLOSED | Redesign HA session sync around a portable canonical session record |
| #319 | CLOSED | Continuously materialize standby helper state instead of repairing sessions on RG activation |
| #320 | CLOSED | Make HA session producers event-first and reduce sweeps/polling to reconciliation |
| #321 | CLOSED | Replace HA flow-cache scans and flushes with epoch-based cache validation |
| #322 | CLOSED | Collapse helper HA session state into one canonical store plus derived indexes |
| #323 | CLOSED | Replace HA demotion drain choreography with an applied-sequence cutover fence |
| #324 | CLOSED | Flow cache on new owner caches sessions without NAT decision after failover |
| #325 | CLOSED | Send owner_rg_id from sync sender instead of defaulting to 0 |
| #326 | CLOSED | Resolve synced sessions with local egress on receipt, not just on activation |
| #327 | CLOSED | Replace flow cache flush with epoch-based invalidation |
| #328 | CLOSED | Unify synced flag into origin-based collision detection |
| #329 | CLOSED | Pre-populate BPF userspace_sessions map on sync receipt |
| #330 | CLOSED | Simplify demotion prep to epoch transition |
| #332 | CLOSED | Userspace-forwarded packets not counted in BPF zone/policy/NAT counter maps |
| #333 | CLOSED | IterateSessions reads only eBPF conntrack — userspace sessions invisible to GC/ARP warmup |
| #334 | CLOSED | BPF conntrack writes during ctrl=0 window conflict with userspace sessions |
| #335 | CLOSED | BPF conntrack entry byte order mismatch prevents zone display for userspace sessions |
| #338 | CLOSED | Graceful demotion barrier no longer fences helper and kernel session producers |
| #339 | CLOSED | Graceful demotion can proceed without confirmed peer bulk readiness |
| #340 | CLOSED | Daemon acks helper event-stream deltas even when sync-disconnect drops them |
| #341 | CLOSED | UpdateRGActive hides helper refresh_owner_rgs timeout and failure |
| #342 | CLOSED | RG activation duplicates helper refresh work through update_ha_state and explicit refresh |
| #343 | CLOSED | Demotion kernel journal path is dead in the current graceful demotion flow |
| #344 | CLOSED | HA activation is decoupled from actual userspace dataplane enablement |
| #345 | CLOSED | HA activation still does RG-wide helper refresh scans despite on-receipt standby materialization |
| #346 | CLOSED | Userspace session mirror failures are swallowed during HA session install |
| #347 | CLOSED | Failover still depends on post-transition neighbor warm-up sweeps |
| #348 | CLOSED | HA transition still depends on asynchronous fabric_fwd refresh |
| #349 | CLOSED | HA watchdog sync is throttled past the helper stale-after threshold |
| #350 | CLOSED | GetSessions cursor pagination does not support stable include_peer pagination |
| #351 | CLOSED | Userspace mirror delete path leaves preinstalled reverse companions behind |
| #352 | CLOSED | Userspace HA transition path still contains raw stderr debug logging |
| #353 | CLOSED | Remove explicit refresh_owner_rgs RPC — sessions pre-resolved on receipt |
| #354 | CLOSED | Skip blackhole route management in userspace mode |
| #355 | CLOSED | Remove dead code and simplify HA transition bookkeeping |
| #356 | CLOSED | Throttle statusLoop HA sync for 2s after UpdateRGActive |
| #358 | CLOSED | Collapse userspace RG activation into one helper-applied HA generation |
| #359 | CLOSED | Collapse helper demotion from prepare-plus-demote into one acknowledged transition |
| #360 | CLOSED | Replace split active-plus-watchdog HA state with a single applied lease model |
| #363 | CLOSED | Split userspace afxdp coordinator responsibilities out of afxdp.rs |
| #364 | CLOSED | Split frame parsing, rewrite, and protocol builders out of afxdp/frame.rs |
| #365 | CLOSED | Break userspace main.rs into snapshot schema, control schema, and server runtime modules |
| #366 | CLOSED | Split event_stream.rs into wire codec and transport state machine modules |
| #367 | CLOSED | Break afxdp/types.rs catch-all into cohesive shared type modules |
| #368 | CLOSED | Split forwarding.rs into snapshot compilation and runtime resolution modules |
| #369 | CLOSED | Split session_glue.rs into shared-session replication, reverse synthesis, and queue-cancel modules |
| #370 | CLOSED | Split daemon.go into config apply, HA/session-sync, and cluster/fabric modules |
| #371 | CLOSED | Split grpcapi/server.go by RPC domain instead of one monolithic server file |
| #372 | CLOSED | Split userspace manager.go into helper lifecycle, HA/session sync, and map sync modules |
| #373 | CLOSED | Split config/compiler.go by configuration domain instead of one giant compiler file |
| #374 | CLOSED | Split cluster/sync.go into transport, bulk/barrier, and producer integration modules |
| #375 | CLOSED | Split cli.go into command-family modules instead of a single operational CLI file |
| #376 | CLOSED | Split api/handlers.go by REST resource family |
| #377 | CLOSED | Split dataplane/compiler.go into feature compilers and host-interface setup modules |
| #389 | CLOSED | Index helper HA session state by owner RG to remove failover-time full-table scans |
| #390 | CLOSED | Replace weight-zero manual failover with an explicit RG transfer protocol |
| #391 | CLOSED | Remove NAPI bootstrap from the HA cutover path |
| #398 | CLOSED | manual failover still times out while requester is in bulk sync receive |
| #400 | CLOSED | surface manual failover transfer readiness separately from takeover readiness |
| #403 | CLOSED | Planned failover must not depend on bulk sync — both nodes already have full session state |
| #408 | CLOSED | Remove 2s worker ApplyHAState ack wait from demotion path |
| #409 | CLOSED | Eliminate double fib_gen bump during RG transition |
| #410 | CLOSED | Blackhole route injection still runs in userspace mode despite #354 skip |
| #411 | CLOSED | Pre-failover prepare retry loop has 45s timeout — should fast-fail for planned failover |
| #412 | CLOSED | Sessions deleted from XDP map on demotion should be unnecessary if rg_active is checked |
| #413 | CLOSED | Synced sessions should already be in new owner's BPF session map before activation |
| #414 | CLOSED | CRITICAL: Demoted sessions fall through gap — userspace DP skips fabric redirect, eBPF never invoked |
| #417 | CLOSED | Flow cache entries with owner_rg_id=0 bypass epoch invalidation on demotion |
| #418 | CLOSED | Replace bulk session sync with event stream replay on connect |
| #420 | CLOSED | event stream replay bulk export can silently drop sessions under load |
| #421 | CLOSED | monitor interface traffic needs a realtime all-interface pps/bandwidth view |
| #423 | CLOSED | monitor interface traffic should add bwm-ng style interactive views and help |
| #426 | CLOSED | fabric redirect path bandwidth limits existing TCP streams during failover |
| #427 | CLOSED | barrier timeout under high-parallelism session sync (-P8) |
| #429 | CLOSED | Flow cache can outlive HA forwarding lease expiry |
| #430 | CLOSED | Manual failover barrier no longer preserves session-sync ordering |
| #433 | CLOSED | XDP shim fabric redirect bypass for zero-copy cross-chassis forwarding |
| #434 | CLOSED | Cached FabricRedirect flow-cache hits ignore apply_nat_on_fabric |
| #436 | CLOSED | Refresh fabric performance plan for strict userspace NAT path |
| #438 | CLOSED | XDP shim drops ICMP echo replies for interface-NAT addresses |
| #440 | CLOSED | Slow-path TUN rp_filter reset by networkctl reload breaks local TCP/UDP |
| #442 | CLOSED | RST suppression shells out to nft binary instead of using netlink API |
| #450 | CLOSED | TCP streams die after RG failover — 3/4 iperf3 streams go to 0 bps |
| #451 | CLOSED | Neighbor miss spikes >20 after RG failover |
| #452 | CLOSED | Rust helper single-threaded event loop blocks session installs behind main socket requests |
| #456 | CLOSED | All 4 iperf3 streams die after RG failover (4/4 at 0 bps) |
| #457 | CLOSED | Standby node loses userspace readiness after RG failover |
| #458 | CLOSED | Session sync barrier timeout on second failover cycle (sessions_received=0) |
| #462 | CLOSED | Phase 2 incremental neighbor updates leave stale snapshot neighbors active in userspace helper |
| #464 | CLOSED | RequestPeerFailover clears local manual failover before the handoff is admitted |
| #465 | CLOSED | sync_test still expects barrierAckSeq to reset after total disconnect |
| #466 | CLOSED | Session sync still bulk-primes on reconnect and active-fabric changes |
| #467 | CLOSED | Failed userspace demotion prep stops the peer bootstrap retry loop and never restarts it |
| #472 | CLOSED | Kernel crash in mlx5_core ICOSQ recovery during HA failback |
| #473 | CLOSED | XSK bindings map cleared after peer crash but helper reports ready |
| #475 | CLOSED | TCP streams never recover after failover+failback: sessions show Pkts:0 |
| #477 | CLOSED | remote monitor interface traffic ignores summary-mode keystrokes |
| #478 | CLOSED | monitor interface traffic summary omits fab/reth aliases |
| #481 | CLOSED | Rapid failover+failback causes barrier disconnect: session sync disconnected during barrier wait |
| #485 | CLOSED | TCP stream survives failover but dies on failback — session re-resolution gap |
| #490 | CLOSED | userspace HA activation still depends on activation-time session and BPF republish |
| #491 | CLOSED | failback still depends on activation-time neighbor install and ARP/NDP warmup |
| #492 | CLOSED | userspace demotion-prep producer pause and journal path is never actually activated |
| #493 | CLOSED | default rg_active semantics enable forwarding before VIP/MAC ownership moves |
| #499 | CLOSED | HA RG transitions still force full snapshot and double FIB churn |
| #500 | CLOSED | HA state updates still run worker-wide session refresh scans |
| #501 | CLOSED | HA demotion still depends on barrier plus preflight fabric-shift path |
| #502 | CLOSED | No-RETH HA promotion still gates on session-sync readiness |
| #503 | CLOSED | HA takeover still waits on ReadySince hold timer before promotion |
| #504 | CLOSED | Immediate synced BPF publish still bypasses worker session admission |
| #511 | CLOSED | Strict VIP ownership still removes blackholes on cluster-primary before VRRP ownership |
| #512 | CLOSED | HA status poll still triggers queue and neighbor bring-up after ownership changes |
| #517 | CLOSED | userspace failover loses synced-session origin on local hits |
| #518 | CLOSED | cluster sync should not mirror reverse sessions into userspace helper |
| #520 | CLOSED | RG1-only failover cannot move LAN ownership on the loss userspace cluster |
| #524 | CLOSED | userspace HA activation no longer re-prewarms split-RG synced sessions |
| #525 | CLOSED | userspace HA readiness overstates standby session usability |
| #526 | CLOSED | split-RG userspace fabric transit is lab-limited on loss cluster |
| #527 | CLOSED | userspace HA direct handoff still stacks stale ownership and local manual state on loss cluster |
| #532 | CLOSED | loss userspace HA no longer returns IPv6 TTL-expired probe responses |
| #533 | CLOSED | loss userspace HA validator blocks because standby session-sync idle never drains |
| #534 | CLOSED | paired full-RG userspace HA handoff remains transport-unstable under load on loss |
| #535 | CLOSED | paired data-RG handoff is still sequential and exposes a split-RG loss window on loss |
| #536 | CLOSED | full data failover still drops packets during VIP/MAC ownership move |
| #540 | CLOSED | session sync can stay disconnected after standby restart on loss |
| #545 | CLOSED | refactor: split pkg/config/compiler.go (5878 lines) by config domain |
| #546 | CLOSED | refactor: split pkg/daemon/daemon_ha.go (4194 lines, 125 functions) |
| #547 | CLOSED | refactor: split pkg/grpcapi/server.go (8411 lines) by RPC domain |
| #548 | CLOSED | refactor: split pkg/cli/cli_show.go (7887 lines) by show domain |
| #549 | CLOSED | refactor: split pkg/daemon/daemon.go (4506 lines) system config functions |
| #550 | CLOSED | refactor: split pkg/dataplane/userspace/manager.go (4772 lines) |
| #551 | CLOSED | refactor: split pkg/cluster/sync.go remaining protocol/conn/failover paths |
| #552 | CLOSED | refactor: split pkg/cli/cli.go (4874 lines) dispatch and handlers |
| #553 | CLOSED | refactor: split pkg/config/ast.go into groups/edit/format paths |
| #554 | CLOSED | refactor: split cmd/cli/main.go (3623 lines) |
| #555 | CLOSED | refactor: split pkg/config/parser_test.go by subsystem |
| #556 | CLOSED | refactor: reduce userspace-dp/src/afxdp.rs root module |
| #560 | CLOSED | native GRE local tunnel source loop spins on permanent gr-0-0-0 errors |
| #562 | CLOSED | userspace HA sync leaks transient missing-neighbor seed sessions across failover |
| #564 | CLOSED | idle standby userspace XSK liveness never settles takeover-ready on a fully bound standby |
| #565 | CLOSED | userspace HA demotion leaves worker-local owner-RG sessions active across failover cycles |
| #568 | CLOSED | inactive owner still promotes translated peer-synced forward hits into local sessions |
| #570 | CLOSED | inactive owner still installs new LAN->WAN sessions locally after RG failover |
| #572 | CLOSED | HA standby can remain WAN-neighbor cold after startup and drop first redirected packets on failover |
| #574 | CLOSED | HA demotion leaves stale USERSPACE_SESSIONS redirect aliases on the old owner |
| #575 | CLOSED | loss steady-state IPv6 default route falls back to discard via lo |
| #576 | CLOSED | userspace HA demotion leaves stale BPF redirect aliases on old owner |
| #579 | CLOSED | userspace-ha-validation can pick standby helper as active firewall |
| #580 | CLOSED | standby userspace helper can wedge with XSK bindings stuck busy after restart |
| #582 | CLOSED | HA readiness can stay false even when standby helper reports all bindings ready |
| #584 | CLOSED | RG handoff leaves stale worker-local sessions on demoted owner |
| #586 | CLOSED | HA failover validator idle gate requires counters to stop changing entirely |
| #587 | CLOSED | RG1 failover can drop external IPv4 while promoted owner still resolves WAN neighbors late |
| #588 | CLOSED | Session sync can stick half-open after standby heartbeat-ack timeout |
| #590 | CLOSED | RG1 failover still incurs high session-miss burst and throughput tail collapse after reachability-preserving handoff |
| #596 | CLOSED | userspace RST suppression install can fail permanently when bpfrx_dp_rst does not exist |
| #597 | CLOSED | explicit RG failback is blocked by heartbeat peerAlive loss even when transfer path is healthy |
| #598 | CLOSED | standby neighbor warmup fallback resolves reth unit subnets to the base interface instead of the unit interface |
| #602 | CLOSED | tracking: refactor ordering for remaining large-file splits |
| #603 | CLOSED | HA status should surface mixed software versions instead of generic session sync disconnected |
| #606 | CLOSED | session sync reconnect reapplies identical config and tears down the new sync session |
| #608 | CLOSED | HA: rapid RG movement hits stale-old-owner redirect and helper/fabric handoff bugs |
| #609 | CLOSED | IPv6 RG1 failover only recovers ~3.9 Gbps of -P12 traffic before node crash |
| #611 | CLOSED | HA: old primary reclaims RG on transient peer-heartbeat timeout immediately after committed failover |
| #612 | CLOSED | HA: new primary self-demotes after committed manual failover when post-commit session barrier ack arrives late |
| #613 | CLOSED | HA: reverse iperf3 -R blackholes for several seconds during committed RG failover/failback |
| #615 | CLOSED | cluster: clear stale inbound transfer grace on repeated RG direction changes |
| #625 | CLOSED | userspace-dp: keep UMEM descriptor bounds at registered length after hugepage rounding |
| #641 | CLOSED | ha deploy: version skew blocks transfer-ready during staggered upgrade |
| #645 | CLOSED | Twice NAT: validate combined SNAT+DNAT parity |
| #648 | CLOSED | rpm: track remaining vSRX parity gaps after cleanup |
| #650 | CLOSED | config: 'commit persist-groups-inheritance' from 'vsrx.conf' is ignored |
| #651 | CLOSED | system: 'archive-sites ... password' from 'vsrx.conf' is not honored by config archival |
| #652 | CLOSED | dns: 'system services dns dns-proxy' from 'vsrx.conf' is unsupported |
| #653 | CLOSED | system: 'services application-identification' from 'vsrx.conf' is still only partial vs vSRX |
| #654 | CLOSED | system: 'processes utmd disable' from 'vsrx.conf' is parsed but has no runtime effect |
| #660 | CLOSED | dns-proxy: replace systemd-resolved toggle with real firewall DNS proxy runtime |
| #675 | CLOSED | CoS: scheduler transmit-rate not applied correctly for 10g+ rates |
| #678 | CLOSED | userspace dataplane: cut remaining hot-path CPU in poll_binding and pending-forward TX |
| #680 | CLOSED | CoS exact queues: replace single-owner service with shared-worker exact queue execution |
| #681 | CLOSED | CoS exact enforcement: make queue rate authoritative and derive burst from scheduler rate |
| #683 | CLOSED | userspace-dp: flatten exact CoS hot path and remove mutex/tree lookups |
| #685 | CLOSED | userspace-dp: remove exact CoS batch materialization from drain path |
| #688 | CLOSED | userspace-dp: make exact drain zero-move and cut drain_pending_tx tail |
| #689 | CLOSED | userspace-dp: separate or prove guarantee RR semantics for exact vs non-exact CoS service |
| #690 | CLOSED | CoS exact fairness: keep low-rate exact queues on a single owner worker |
| #691 | CLOSED | CoS low-rate exact fairness: add per-flow backlog admission to owner-local exact queues |
| #693 | CLOSED | userspace-dp: randomize low-rate exact fair-queue hash seed |
| #694 | CLOSED | userspace-dp: replace fair-queue RR VecDeque with fixed circular ring |
| #697 | CLOSED | CoS shared-exact threshold: iface_rate/4 term inverts policy at >10g iface |
| #698 | CLOSED | CoS shared-exact threshold: validate MIN constant + end-to-end dispatch test |
| #704 | CLOSED | CoS exact 1g (5201): bimodal per-flow fairness collapse at 16+ flows (~13× ratio, 5.7% retrans) |
| #705 | CLOSED | SFQ bucket collision + per-flow admission cap forces colliding flows into cwnd-collapse regime |
| #706 | CLOSED | Non-owner-worker redirect mutex (enqueue_tx_owned) is a latency jitter source on low-rate exact queues |
| #707 | CLOSED | CoS exact queue buffer undersized for multi-flow BDP (1g/16-flow: 1× per-flow BDP, TCP forced into RTO) |
| #708 | CLOSED | No enqueue-side pacing on CoS queues — TCP cwnd bursts overflow admission caps under multi-flow load |
| #709 | CLOSED | Low-rate exact queue owner worker is a hotspot — RX + redirected-drain + NAT all on one CPU |
| #710 | CLOSED | CoS: add drop-reason + per-queue + per-bucket telemetry to triage exact-queue drops |
| #711 | CLOSED | SFQ 64 buckets is too small — bucket collision probability dominates at 16+ flows |
| #712 | CLOSED | Worker threads lack CPU pinning + IRQ isolation — OS scheduler jitter amplifies per-flow variance |
| #717 | CLOSED | userspace-dp: add latency-envelope clamp to cos_flow_aware_buffer_limit |
| #718 | CLOSED | userspace-dp: AQM for exact CoS queues — ECN marking and/or CoDel admission to fix bufferbloat-driven cwnd collapse |
| #722 | CLOSED | userspace-dp: ECN mark threshold should be per-flow, not aggregate, on flow-fair exact queues |
| #725 | CLOSED | #721/#722 ECN code dormant on current test workload — validation pipeline gap |
| #732 | CLOSED | cos: OwnerProfile line renders per-binding counters repeated under every queue row |
| #735 | CLOSED | cos: #708 pacing with MIN_SHARE_BYTES burst cap doubles retrans — retry with share_cap-sized cap |
| #738 | CLOSED | userspace-dp: pin_current_thread() should pick the Nth allowed CPU, not absolute CPU N |
| #739 | OPEN | #712 Option B: kernel cmdline isolcpus/nohz_full/rcu_nocbs for the loss userspace lab |
| #745 | CLOSED | userspace-dp: sum owner-profile telemetry instead of max-merging it |
| #746 | CLOSED | userspace-dp: isolate owner-profile telemetry state from hot binding cachelines |
| #747 | CLOSED | cos: Glide-style per-flow rate signal for ECN marker threshold on heterogeneous workloads |
| #751 | CLOSED | userspace-dp: make owner-profile telemetry queue-scoped for exact CoS |
| #752 | CLOSED | userspace-dp: keep CoS owner-profile export zero unless queue attribution is unambiguous |
| #754 | CLOSED | cos: 1 Gbps exact queue over-throttles to 60% of cap — ECN threshold too aggressive for low-rate queues |
| #756 | CLOSED | userspace-dp: CoS silently unenforced on VMs with ifindex > BPF map cap |
| #757 | CLOSED | daemon: reconcile loop spams INFO+WARN 9x/second when userspace-dp helper is down |
| #758 | CLOSED | daemon: 'failed to compile dataplane' is logged once then silently spun on forever |
| #760 | CLOSED | userspace-dp CoS admission: single TCP flow exceeds 'transmit-rate Xg exact' cap by ~40-60% |
| #761 | CLOSED | userspace-dp: dense-slot design for ifindex-keyed hot-path maps |
| #762 | CLOSED | meta: drive open issues to zero — parallel tracks A–F |
| #767 | CLOSED | userspace-dp: #759 ifindex HASH maps cause full forwarding breakage on mlx5 VF (loss:xpf-userspace-fw) |
| #774 | CLOSED | perf: userspace DP ceiling at 18 Gbps vs 25+ Gbps target on loss:xpf-userspace-fw |
| #775 | CLOSED | perf: campaign to land consistent 22+ Gbps on iperf3 -P 12 -t 600 -p 5203 |
| #776 | CLOSED | perf: 12% CPU in memcpy on build_forwarded_frame_into_from_frame (cross-worker copy) |
| #777 | CLOSED | perf: 7.8% CPU in poll_binding_process_descriptor (RX hot path) |
| #778 | CLOSED | perf: 1.40% CPU in kernel mlx5e_xsk_skb_from_cqe_linear — SKB alloc on zero-copy RX |
| #779 | CLOSED | perf: 3.28% CPU in enqueue_pending_forwards (TX dispatch) |
| #780 | CLOSED | perf: 1.96% CPU in ingest_cos_pending_tx_with_provenance (post-#760) |
| #781 | CLOSED | perf: 9.67M rx_xsk_buff_alloc_err + 506M tx_xsk_full — structural pipeline stall |
| #786 | CLOSED | Research: cross-worker per-flow fair queueing at 100G+ scale (follow-up to #785) |
| #789 | CLOSED | Restore 21-23 Gbps + CoV ≤ 20 % on shared_exact CoS queues (#785 follow-up) |
| #790 | CLOSED | #785 Phase 1 — Re-baseline after PR #787 (measurement only) |
| #791 | CLOSED | #785 Phase 2 — Symmetric Toeplitz RSS audit (zero-code) |
| #792 | CLOSED | #785 Phase 3 — Minimal MQFQ: per-worker virtual-finish-time ordering |
| #793 | CLOSED | #785 Phase 4 — Full MQFQ with shared V_min + lag throttle |
| #794 | CLOSED | #785 Phase 5 — AFD policer for misbehaving flows (optional) |
| #798 | CLOSED | perf: line-rate gap on iperf3 -P 16 -t 60 -p 5201 (both directions) |
| #799 | CLOSED | perf: 55M rx_steer_missed_packets on ge-0-0-2 at cold (mlx5 flow steering miss) |
| #800 | CLOSED | perf: workers count should match RX queue count (currently 4 workers / 6 queues per NIC) |
| #801 | CLOSED | perf: zero-code sysctl + coalescence tuning for line rate (governor, netdev_budget, adaptive coalescing) |
| #802 | CLOSED | perf: expose userspace-dp ring-pressure counters in control-socket snapshot (DEFERRED-INSTRUMENTATION) |
| #805 | CLOSED | perf: D3 RSS indirection doesn't refresh when workers count changes to equal queue count |
| #806 | CLOSED | line-rate investigation: remaining gaps after PRs #796/#797/#803/#804 |
| #812 | CLOSED | perf: per-queue TX-lane submit→completion latency histogram (Step 1 → Step 2 follow-up) |
| #814 | CLOSED | userspace-dp: fab0 ifindex >2048 blocks dataplane compile on fw1 (MAX_INTERFACES too small) |
| #816 | CLOSED | Step 1 classifier re-run on master with TX latency histogram (post-#813) |
| #817 | CLOSED | Step 1 #816 reproducibility: re-run under pinned scipy 1.13.1 / numpy 1.26.4 (Path B) |
| #819 | CLOSED | Step 2 telemetry design doc: discriminate H2 D1 mechanisms (#816 follow-up) |
| #821 | CLOSED | Wire step2-sched-switch-capture.sh sister harness for P1 off-CPU duration probe (#819 P1) |
| #823 | CLOSED | Run P1 sched_switch captures on load-bearing cells + negative control (#821 follow-up) |
| #825 | CLOSED | Wire tx_kick_latency_hist + tx_kick_retry_count in xpf-userspace-dp (P3/#819 §5.3, Issue B) |
| #827 | CLOSED | P3 captures + classifier: apply T1 threshold on p5201/p5202-fwd-with-cos (#819 follow-up) |
| #829 | CLOSED | Cross-worker virtual-time gate for shared_exact CoS queues (#786 Slice B) |
| #831 | CLOSED | Slice C: per-flow AFD credit isolation for shared_exact CoS queues (#786 Slice C) |
| #833 | CLOSED | Per-flow ECN marking across shared_exact bindings (#786 Slice C minimal) |
| #834 | CLOSED | Slice C take 2: cross-binding per-flow MQFQ ordering (not ECN) |
| #835 | CLOSED | Slice D: RSS++ dynamic indirection rebalance for flow-count parity across RX rings (#786 Slice D) |
| #836 | CLOSED | Slice C: shared per-flow virtual-time array on SharedCoSQueueLease (#786 Slice C v3) |
| #837 | CLOSED | Slice C-a: full HOL-finish cross-binding MQFQ with shared vtime + per-bucket state machine |
| #838 | CLOSED | Slice C-b: per-flow bytes-served counter with periodic reset (AFD-lite) |
| #840 | CLOSED | Slice D v2: RSS rebalance with xpf-userspace-dp per-binding RX stats (replaces ethtool -S signal) |
| #841 | CLOSED | CrossBindingLag gate fires without park → worker poll loop spins at 100% CPU, forwarding stops |
| #843 | CLOSED | Post-mortem: re-investigate Slice B before any retry (prerequisites from #841 revert) |
| #844 | CLOSED | HA: cluster-sync listener orphaned by VRF delete+recreate on startup (kernel 6.19) |
| #846 | CLOSED | applyConfig is not serialized: concurrent callers interleave across steps |
| #847 | CLOSED | Cross-restart VRF leak: renamed routing instances leave stale vrf-<old-name> |
| #848 | CLOSED | routing.Manager: tunnels/xfrmis/bonds/reths slices have no mutex protection |
| #849 | CLOSED | Forwarding broken on loss userspace cluster: LAN → WAN blackhole |
| #850 | CLOSED | [security][high] allow_dns_reply bypasses all zone-pair policy (XDP + DPDK) |
| #851 | CLOSED | [security][medium] TC egress mis-classifies all VLAN sub-interface traffic on mlx5 (zone miss + screen + output filter) |
| #852 | CLOSED | [security][medium] tc_conntrack writes persistent sessions for sessionless GRE/ESP without XDP policy evidence |
| #853 | CLOSED | [security][medium] TC egress screen drops legitimate TCP fragments as NULL-scan; SYN_FRAG check is dead code |
| #854 | CLOSED | [bug][medium] tc_forward port-mirror is zeroed by tc_main's partial memset before use |
| #855 | CLOSED | [bug][medium] DPDK fwd_ifindex==0 sentinel collides with DPDK port 0; transit on port 0 freed as host-inbound |
| #856 | CLOSED | [security][medium] resolve_ingress_xdp_target skips xdp_screen for TCP NULL scans and ACK-only sweeps |
| #857 | CLOSED | [bug][medium] XDP_TX reply paths omit 802.1Q tag; SYN-cookie becomes self-DoS on VLAN sub-interfaces |
| #858 | CLOSED | [bug][medium] NAT port allocator collides on >16-CPU hosts; NAT64 has no reservation retry |
| #859 | CLOSED | [security][low] IPv6 SYN-cookie validated_clients key truncated to first 4 bytes — one handshake whitelists a /32 |
| #860 | CLOSED | [bug][low] SCREEN_PING_OF_DEATH is dead code on XDP and TC (pkt_len is __u16) |
| #861 | CLOSED | [bug][low] IPv6 SESSION_OPEN event logs post-NAT addresses as 'original' (session_v6_scratch[1] clobber) |
| #862 | CLOSED | [bug][low] NAT64 ICMP checksum loop only covers first 128 bytes; ping -s 200+ gets bad checksum |
| #863 | CLOSED | [security][low] IFACE_FLAG_TUNNEL TC bypass assumes XDP enforced policy; ingress_ifindex != 0 is not proof |
| #864 | CLOSED | [bug][low] Native XDP fallback to generic is silent + pinned link preserves stale IFACE_FLAG_NATIVE_XDP |
| #866 | CLOSED | Real SCREEN_SYN_FRAG detection via first-fragment L4 parse |
| #867 | CLOSED | ACK-based IP_SWEEP detection evades the resolve_ingress_xdp_target fast-path |
| #869 | CLOSED | userspace-dp: expose worker busy/idle runtime telemetry |
| #871 | CLOSED | VLAN hwaccel: XDP_TX policy-reject replies also omit 802.1Q tag (stack-budget followup to #857) |
| #875 | CLOSED | docs: add end-to-end workflow section to engineering-style.md |
| #877 | CLOSED | cli: add 'show chassis forwarding' — Junos-style forwarding daemon CPU / heap / buffer / uptime |
| #878 | CLOSED | userspace-dp: expose UMEM / ring utilization for 'show chassis forwarding' Buffer% |
| #879 | CLOSED | cli: 'show chassis forwarding' — per-node (node0: / node1:) rendering in cluster mode |
| #881 | CLOSED | show chassis forwarding: add 5s / 1m / 5m CPU windows (replace or augment cumulative-since-start) |
| #883 | CLOSED | P0: 25 Gbps iperf3 bypasses userspace-dp entirely — XDP shim reaches XDP_REDIRECT ~0 times despite ready bindings |
| #884 | CLOSED | userspace-dp WorkerRuntimeStatus.active_ns undercounts: idle-branch ring-poll CPU credited to IdleBlock |
| #885 | CLOSED | test-env: iperf3 traffic generator bypasses both firewall VMs via SR-IOV HW switching |
| #897 | CLOSED | RSS rebalance: hysteresis + convergence detection (#840 follow-up) |
| #898 | CLOSED | RSS rebalance: scope to workers<queues + non-equal initial weight (#840 follow-up) |
| #899 | CLOSED | Cross-binding fairness via per-flow XDP_REDIRECT (alternative to RSS table tuning) |
| #900 | CLOSED | 100E100M test harness: characterize SFQ + per-flow fairness under mixed elephant/mouse load |
| #903 | CLOSED | config: 'set system dataplane userspace workers N' not parsed (vs working 'dataplane workers N') |
| #905 | CLOSED | Measurement: mouse-latency tail under elephant load (100E100M unmeasured half) |
| #908 | CLOSED | Userspace dataplane: extend XDP_SHARED_UMEM to cross-device forwarding (eliminate the 13% memcpy hot path) |
| #909 | CLOSED | Userspace DP: poll_binding_process_descriptor prefetches frame head, not metadata header — ~3.5% CPU stall |
| #911 | CLOSED | Same-class HOL on shared_exact CoS queues at multi-Gbps shapers (FAIL gate at iperf-b/iperf-c per #905 findings) |
| #912 | CLOSED | Userspace DP: raise COS_FLOW_FAIR_BUCKETS from 1024 → 16384 to cut SFQ collision rate ~16× (cheapest experiment for #911 |
| #913 | CLOSED | MQFQ virtual-finish-time is aggregate-only — temporal inversion breaks per-flow fairness |
| #914 | CLOSED | shared_exact queues have admission "hole" — per-flow caps disabled on sharded CoS |
| #915 | CLOSED | exact CoS queues are non-work-conserving — barred from surplus bandwidth |
| #916 | CLOSED | deadlock when CoS configured without interface shaping-rate |
| #917 | CLOSED | MQFQ Phase 4 missing — cross-worker virtual time synchronization (V_min) |
| #918 | CLOSED | Flow Cache is a 'Collision Generator' — 1-Way Direct Mapped Cache destroys fairness |
| #919 | CLOSED | Atomic Refcounting in the Fast Path — SessionMetadata clones Arc<str> |
| #920 | CLOSED | Massive Hard-coded Batch Sizes (256) destroy L1d Cache Locality |
| #921 | CLOSED | Zone Resolution is 'String-Heavy' — Pathological allocations on session miss |
| #922 | CLOSED | Policy Evaluation allocates on every miss — ZonePairKey is a memory-churn generator |
| #923 | CLOSED | Policy Address Matching is O(N) — Linear prefix scan destroys session setup performance |
| #924 | CLOSED | Fabric Zone Decoding is 'Double-Sided' String Bottleneck — ID-to-String-to-ID churn |
| #925 | CLOSED | Worker thread supervisor: catch_unwind, respawn, liveness reporting |
| #926 | CLOSED | demote_prepared_cos_queue_to_local inflates queue_vtime on success path |
| #927 | CLOSED | MQFQ drained-bucket restore loses dropped item's virtual service in multi-pop+tail-drop scenarios |
| #929 | CLOSED | test harness: same-class iperf-b mouse-latency reproduction (#911 validation gate) |
| #936 | CLOSED | Cross-worker MQFQ: shared per-flow vtime across workers (V_min sync alternative) |
| #937 | CLOSED | Re-evaluate #899 cross-binding flow re-steering — RSS-degenerate case path |
| #938 | CLOSED | Investigate dynamic NIC RSS indirection-table tuning for runtime flow rebalancing |
| #940 | CLOSED | #917 Q1: V_min publish on speculative pop leaks uncommitted vtime to peers |
| #941 | CLOSED | #917 Q2+Q3: V_min unbounded throttle vs stale slot (missing vacate) |
| #942 | CLOSED | #917 Q6: V_min check missing from Prepared scratch builder |
| #943 | CLOSED | #917 Q8c: Add v_min_throttles per-binding telemetry counter |
| #944 | CLOSED | Investigate iperf-c P=128 ~17 Gb/s ceiling (split from #937 — non-RSS bottleneck) |
| #945 | CLOSED | Refactor: Apply Context Object Pattern to eliminate 31-Parameter God Function |
| #946 | CLOSED | Refactor: Pipeline / Chain of Responsibility Pattern for Vector Packet Processing |
| #947 | CLOSED | Refactor: Strategy Pattern for Protocol Parsing (Decouple L2/L3/L4 parsing) |
| #948 | CLOSED | Refactor: Mediator / Message Broker Pattern to decouple Control Plane from Data Plane |
| #949 | CLOSED | Refactor: Read-Copy-Update (RCU) / Immutable State Pattern for Fast-Path Locks |
| #956 | CLOSED | Refactor: Deconstruct tx.rs God File into CoS Subsystems (MQFQ, Shaper, Admission) |
| #957 | CLOSED | Refactor: Modularize afxdp.rs and worker.rs Core Loops (RX/Validation/SlowPath Separation) |
| #958 | CLOSED | Refactor: Abstract Cross-Core Redirection (MPSC) into Isolated Submodule |
| #959 | CLOSED | Refactor: Deconstruct BindingWorker into Cache-Aligned Substructs |
| #960 | CLOSED | Profile-driven audit: which control-plane syscalls actually appear in fast-path perf? |
| #961 | CLOSED | Extract PacketContext: explicit per-packet ownership state machine |
| #963 | CLOSED | Refactor: Frame Rewriting is a God Function — Missing Builder/State Pattern for Packet Mutability |
| #964 | CLOSED | Refactor: SessionTable is a 'Memory Allocator' — Missing Multi-Index Data-Oriented Design |
| #965 | CLOSED | Refactor: O(N) Session Garbage Collection causes 'Stop The World' Latency Spikes |
| #966 | CLOSED | Refactor: Policy Engine is missing SIMD-Accelerated Packet Classification (Bit-Vector / Tuple Space Search) |
| #967 | CLOSED | Refactor: Header Formatting uses Scalar Byte Copies — Missing SIMD PSHUFB (_mm256_shuffle_epi8) |
| #968 | CLOSED | Refactor: Cryptographic Hash Generation lacks Hardware Intrinsics (AES-NI / SHA-Ext) |
| #969 | CLOSED | Refactor: FIB / Routing Table Lookups lack AVX2 Gather Instructions |
| #984 | CLOSED | Refactor: Consolidate TX Subsystem into Unified afxdp/tx/ Module |
| #985 | CLOSED | Refactor: Deconstruct Coordinator God Struct into Manager Components |
| #986 | CLOSED | Refactor: Extract Memory Management from umem.rs |
| #987 | CLOSED | Refactor: Decouple Packet Pipeline from Hardware Driver (HAL) |
| #988 | CLOSED | Refactor: Deconstruct frame.rs into Layered Packet Processing Submodule |
| #989 | CLOSED | Refactor: Extract L4 Protocol Specializations (TCP/UDP/ICMP/ARP) |
| #1016 | CLOSED | Refactor: Decouple enqueue_pending_forwards mutation from TX dispatch (post-rename) |
| #1020 | CLOSED | MmapArea::new: harden against zero-length and aligned_len overflow |
| #1034 | CLOSED | Refactor: cos/queue_ops.rs is 4,531 prod LOC — biggest remaining monolith |
| #1035 | CLOSED | Refactor: cos/queue_service.rs (2,999 prod LOC) and types.rs (2,009 prod LOC) over modularity threshold |
| #1043 | CLOSED | Refactor: pkg/grpcapi/server_show.go is 5,288 LOC (16 fns) — needs RPC-handler split |
| #1044 | CLOSED | Refactor: pkg/dataplane/compiler.go (3,509 LOC) and pkg/daemon/daemon.go (2,851) and pkg/cli/cli.go (2,661) need decompo |
| #1046 | CLOSED | Refactor: afxdp/frame/mod.rs is 6,435 LOC — test split + builders/ subdir |
| #1047 | CLOSED | Refactor: session.rs is 3,108 LOC — split into session/{key,table,wheel,entry}.rs |
| #1048 | CLOSED | Refactor: main.rs is 2,139 LOC — extract control-plane server/ subsystem |
| #1049 | CLOSED | Refactor: filter.rs is 2,278 LOC — split into filter/{compiler,engine,policer}.rs |
| #1054 | CLOSED | Refactor: afxdp.rs is 3,843 prod LOC — extract 2,382-line poll_binding_process_descriptor |
| #1065 | CLOSED | Bug: ForwardingDisposition::is_cacheable doc/code mismatch on FabricRedirect |
| #1069 | CLOSED | Bug: redundant reverse_session_key computation in flush_session_deltas Close branch |
| #1125 | CLOSED | Refactor: BindingWorker is a 'Wide' bottleneck — Refactor via Sub-Struct Composition |
| #1126 | CLOSED | Refactor: Decouple Protocol Snooping (TCP Flags) from the Egress Path |
| #1127 | CLOSED | Refactor: Kill the 31-Parameter God Function with a Vectorized 'PacketBatch' Struct |
| #1128 | CLOSED | Refactor: Extract 'BatchTelemetry' to clear Hot-Path Instruction Noise |
| #1137 | CLOSED | userspace-dp: SCREEN_SYN_FRAG not implemented in screen.rs (follow-up to #866) |
| #1144 | CLOSED | Refactor: Defer Session Setup for Missing Neighbors to avoid Synchronous Traps |
| #1145 | CLOSED | Refactor: Implement Packet-Header Scratchpads to eliminate redundant UMEM slicing |
| #1146 | CLOSED | Refactor: Decouple Protocol Parsing from the Forwarding Pipeline |
| #1152 | CLOSED | show NAT detail commands miss IPv6 sessions and panic on IPv6 persistent-NAT bindings |
| #1163 | CLOSED | Refactor: Recursive String-Based Routing Lookups — 'next_table' resolution is an IPC killer |
| #1164 | CLOSED | Refactor: JSON Serialization Tax on Control Plane Sync — Missing Binary Protocol (Protobuf/FlatBuffers) |
| #1165 | CLOSED | Refactor: Inline thread_local! and Logging Branches bloat the L1-i Cache |
| #1166 | CLOSED | Refactor: Software TCP Segmentation (TSO) is a Monolithic Memory-Copy Trap |
| #1187 | CLOSED | Refactor: Double-Buffered Telemetry to eliminate Worker-Coordinator cache-line bouncing |
| #1188 | CLOSED | Refactor: Group disparate RCU states into a single 'RuntimeSnapshot' to reduce atomic bus traffic |
| #1189 | CLOSED | Refactor: Deconstruct 'Coordinator' into Domain-Specific Managers |
| #1197 | CLOSED | xpfd preinstalls stale neighbor MAC into kernel ARP; breaks forwarding when peer MAC changes (no snapshot refresh) |
| #1204 | CLOSED | Refactor: Abandon N-tuple Flow Steering — Fix Intra-Queue Fairness Instead |
| #1205 | CLOSED | Hygiene: doc/code drift CI check for CoS scheduler invariants |
| #1206 | CLOSED | Refactor: split CoSQueueRuntime into hot/cold/flow_fair/v_min/telemetry pieces |
| #1207 | CLOSED | Refactor: consolidate queue_service/service.rs around one monomorphized service skeleton |
| #1208 | CLOSED | Hygiene: refresh refactoring-audit.md to current module heatmap |
| #1209 | CLOSED | Refactor: finish double-buffered worker telemetry (#1187 follow-on) |
| #1210 | CLOSED | Hygiene: scrub stale CoS scheduler comments + old tx.rs line refs in docs/issues |
| #1211 | CLOSED | Research: AFD/CSFQ-style per-flow ECN overlay for shared_exact CoS queues |
| #1215 | CLOSED | Per-5-tuple fairness across RSS queues — implement cross-worker shared finish-time table |
| #1219 | CLOSED | Fairness harness: Cstruct compute + per-binding distinct-flow-count + Prometheus exports |
| #1224 | CLOSED | fairness-eval: relax sum-guard tolerance at low N (P≤2 false-FAILs) |
| #1229 | CLOSED | Cross-worker per-flow fairness via vtime + TCP RWND throttle (post-#1211) |
| #1231 | CLOSED | Phase 6 follow-up: address iperf-c push -15% regression via 'all peers CPU-bound' detector |
| #1232 | CLOSED | Phase 6 follow-up: multi-sample variance check on iperf-e per-flow CoV |
| #1233 | CLOSED | Sender-side TCP head-start unfairness (~25% CoV floor) — investigate dataplane-only mitigation options |
| #1234 | CLOSED | Test environment: CoS firewall filter not classifying traffic on loss userspace cluster |
| #1236 | CLOSED | v6: Global per-flow rate cap to equalize per-flow throughput on shaped multi-stream workloads |
| #1237 | CLOSED | Per-worker reactive lease share — closed-loop adjustment to drive per-flow rate equality |
| #1238 | CLOSED | Investigation: per-flow-bucket token bucket as alternative fairness mechanism |
| #1239 | CLOSED | Investigation: surplus claiming proportional to flow count, not worker count |
| #1240 | CLOSED | Investigate: per-worker acquire_v8 call frequency drives per-flow rate variance |
| #1241 | CLOSED | Investigate: per-queue AF_XDP TX completion ring uniformity |
| #1242 | CLOSED | Investigate: TCP cwnd self-reinforcing per-worker rate asymmetry |
| #1243 | CLOSED | 5-worker dedicated CPU mode: drop worker 0 from CoS queue ownership |
| #1244 | CLOSED | Auto-tune RSS Toeplitz key for uniform distribution across ephemeral port range |
| #1245 | CLOSED | Multi-receiver test methodology — empirically does NOT reduce per-flow CoV |
| #1247 | CLOSED | Fairness contract: add workload/RSS expectation gate for structural skew |
| #1248 | CLOSED | Fairness harness: publish per-CoS-queue active 5-tuple distribution |
| #1249 | CLOSED | Fairness diagnostics: expose active flow-to-worker mapping |
| #1250 | CLOSED | CoS config: support symmetric shaping for reverse-direction fairness tests |
| #1255 | CLOSED | CoS fairness execution plan: symmetric shape, diagnostics, per-queue Cstruct, expectation gate |
| #1257 | CLOSED | Fairness harness: add isolated mixed-CoS generator mode |
| #1264 | CLOSED | Fairness telemetry: add rolling observed CoV and starved-flow runtime metrics |
| #1265 | CLOSED | Fairness RSS expectations: polish parser, labels, and duplicate handling after #1263 |
| #1276 | CLOSED | CoS fairness: high-rate classes show high absolute CoV despite Cstruct-relative PASS |
| #1277 | CLOSED | fairness_multi_sample rejects valid negative gap verdicts |
| #1278 | CLOSED | CoS CLI runtime view hides reverse egress runtime for ge-0-0-1.0 |
| #1281 | CLOSED | fairness-eval: active-flow sum guard can overcount canonical P=12 CoS sweeps |
| #1282 | CLOSED | userspace CoS sweep logs DBG SEG_MISS and TX errors on reverse egress ifindex 5 |
| #1284 | CLOSED | fairness sweep: capture dataplane counter deltas for TX-error attribution |
| #1287 | CLOSED | Improve per-flow fairness across workers with uneven RSS distribution |
| #1292 | CLOSED | CoS fairness: investigate strict-lease throughput headroom on high-rate forward classes |
| #1294 | CLOSED | CoS fairness telemetry: active-flow counts remain stale after idle |
| #1296 | CLOSED | CoS surplus-sharing: structural pass still allows high raw per-flow CoV |
| #1298 | CLOSED | CoS telemetry: add idle-path active-flow aging regression test |
| #1300 | CLOSED | userspace-dp: eliminate VLAN push/pop memmove in in-place cross-NIC forwarding |
| #1303 | CLOSED | userspace smoke: IPv6 mtr final-hop check can fail despite working IPv6 dataplane |
| #1304 | CLOSED | CoS equal-flow mode: explicit rate suppression for raw per-flow fairness under RSS skew |
| #1306 | CLOSED | Fairness harness: capture equal-flow estimator gauges in CoS sweeps |
| #1307 | CLOSED | Userspace dataplane: attribute TX errors observed during CoS class sweep |
| #1312 | CLOSED | CoS equal-flow: investigate low-rate reverse retransmits and CoS overflow counters |
| #1314 | CLOSED | Adaptive idle-spin budget to recover CPU after copy-elimination |
| #1317 | CLOSED | ArcSwap Guard caching across spin iterations to recover ~12% CPU |
| #1318 | CLOSED | drain_shaped_tx unconditional prime_cos_root_for_service overhead ~8% when idle |
| #1319 | CLOSED | Self-documenting AST: typed leaf-value schema for CLI completion + commit-check validation |
| #1321 | CLOSED | CoS validation: 100E100M plus work-conserving surplus give-back contract |
| #1325 | CLOSED | Refactor: userspace-dp/src/protocol.rs — split by domain (snapshot DTOs vs control protocol vs binding status) |
| #1326 | CLOSED | Refactor: userspace-dp/src/afxdp/worker/mod.rs — extract worker_loop (~1200 LOC) into worker/loop_body/ |
| #1327 | CLOSED | Refactor: userspace-dp/src/afxdp/poll_descriptor.rs — split ~2100-LOC poll_binding_process_descriptor into stage helpers |
| #1328 | CLOSED | Refactor: userspace-dp/src/afxdp/coordinator/mod.rs — split 493-LOC reconcile() and 289-LOC refresh_bindings() |
| #1329 | CLOSED | Refactor: userspace-dp/src/afxdp/types/shared_cos_lease.rs — extract 214-LOC maybe_rotate_epoch_v8() and 142-LOC publish |
| #1330 | CLOSED | Refactor: userspace-dp/src/bin/fairness-eval.rs — extract 383-LOC main() into orchestrator + phase helpers |
| #1331 | CLOSED | Refactor: userspace-dp/src/afxdp/cos/queue_service/mod.rs — extract 221-LOC submit_cos_batch() into per-variant handlers |
| #1333 | CLOSED | CoS-off iperf3 raw per-flow imbalance: 32 streams show 10.4% CoV and 1.46x spread |
| #1336 | CLOSED | CoS config: define real runtime semantics for percent scheduler buffer-size |
| #1337 | CLOSED | config schema: wire typed CoS scheduler schema into set completion |
| #1338 | CLOSED | #1321 surplus validator: require proof of borrow, demand, handback, and reclaim |
| #1339 | CLOSED | #1321 mouse-latency gate: select representative by the gated percentile |
| #1340 | CLOSED | #1321 mouse-latency summary.json: preserve p99_idle_us/p99_loaded_us compatibility |
| #1342 | CLOSED | Refactor: userspace-dp/src/afxdp/forwarding_build.rs — split 469-LOC build_forwarding_state and 312-LOC build_cos_state  |
| #1343 | CLOSED | 100E100M validation: port-7 echo preflight fails before gate cells |
| #1344 | CLOSED | 100E100M validation: surplus matrix silently reverts to strict fixture |
| #1345 | CLOSED | Refactor: userspace-dp/src/server/handlers.rs — split 415-LOC handle_stream dispatcher into per-verb modules |
| #1346 | CLOSED | Refactor: userspace-dp/src/afxdp/session_glue/mod.rs — split 329-LOC apply_worker_commands + collapse 17/11-param maybe_ |
| #1347 | CLOSED | Refactor: userspace-dp/src/afxdp/{frame,tx}/tcp_segmentation.rs — share one ~280-LOC TCP segmentation algorithm between  |
| #1348 | CLOSED | Refactor: userspace-dp/src/afxdp/icmp_embed.rs — split 269-LOC try_embedded_icmp_nat_match + collapse 10-param embedded_ |
| #1349 | CLOSED | Refactor: userspace-dp/src/afxdp/worker/cos.rs — split 268-LOC build_worker_cos_statuses_from_maps into owner-profile /  |
| #1350 | CLOSED | Refactor: userspace-dp/src/afxdp/tx/drain.rs — split 253-LOC drain_pending_tx into six drain_phase_* helpers + DrainCtx |
| #1351 | CLOSED | Refactor: userspace-dp/src/afxdp/umem/mod.rs — extract 246-LOC snapshot and 205-LOC publish_binding_debug_state into ume |
| #1352 | CLOSED | Refactor: userspace-dp/src/afxdp/frame/mod.rs — split 236-LOC build_forwarded_frame_into_from_frame + 223-LOC apply_rewr |
| #1354 | CLOSED | Refactor: userspace-dp/src/afxdp/tx/transmit.rs — split 230-LOC transmit_prepared_queue into stage/reserve/write/finalis |
| #1355 | CLOSED | Refactor: userspace-dp/src/afxdp/cos/queue_ops/push.rs — split 218-LOC cos_queue_push_front along flow_fair() config bra |
| #1356 | CLOSED | Refactor: userspace-dp/src/afxdp/bpf_map.rs — split 204-LOC publish_bpf_conntrack_entry into per-address-family helpers |
| #1357 | CLOSED | Refactor: collapse repeated 9-10-param pub-fn clusters in session/mod.rs (5 fns) and flowexport.rs (finalize_flow) into  |
| #1359 | OPEN | 100E100M: surplus-sharing fails p99.9 mouse latency gate while exact passes |
| #1360 | CLOSED | Mouse-latency matrix: cells with fewer than 10 valid reps still show status OK |
| #1362 | CLOSED | Mouse latency probe: bound writer.drain() in both probe modes |
| #1363 | CLOSED | Bound writer.drain() in mouse_latency_probe.py to prevent indefinite stall on TCP backpressure |
| #1365 | OPEN | 100E100M high-rate classes fail cwnd-settle before mouse latency probe |
| #1367 | CLOSED | CoS: best-effort/non-exact queues inherit root shape and steal bandwidth from exact queues |
| #1368 | CLOSED | CoS validation: add best-effort-vs-exact contention gates for the 5200/5211 port grid |
| #1369 | CLOSED | CoS diagnostics: expose guarantee vs surplus phase bytes and exact-demand steal signals |
| #1373 | CLOSED | Retire the eBPF dataplane; userspace AF_XDP dataplane becomes the default and only path |
| #1374 | CLOSED | Feature gap: SYN cookie flood protection implemented in eBPF, missing from userspace-dp |
| #1375 | CLOSED | Feature gap: three-color policers (RFC 2697/2698) implemented in eBPF, missing from userspace-dp |
| #1376 | CLOSED | Feature gap: port mirroring implemented in eBPF, missing from userspace-dp |
| #1377 | CLOSED | Feature gap: address-persistent SNAT pool mode silently degrades to round-robin in userspace-dp |
| #1378 | CLOSED | Feature gap: time-based policy schedulers (Junos schedulers { ... }) not propagated to userspace-dp |
| #1379 | CLOSED | Feature gap: dataplane events (PolicyDeny, ScreenDrop, FilterLog) not emitted by userspace-dp |
| #1380 | CLOSED | Feature gap: 'show system buffers' CLI reports BPF map utilization; no userspace equivalent |
| #1381 | CLOSED | Feature gap: DataPlane interface contract is BPF-shaped; userspace Manager embeds eBPF Manager |
| #1387 | CLOSED | DHCP server: dynamic DNS updates and stale lease cleanup |
| #1389 | CLOSED | Edge gateway feature bundle: multi-WAN, secure DNS/DDNS, WireGuard, PBR, and smart queueing |
| #1390 | CLOSED | CoS best-effort drains while exact queues are backlogged |
| #1419 | CLOSED | Auto-generate cmdtree help text from config schema for 100% ? completion coverage |
| #1431 | CLOSED | userspace filters: preserve cache invariants for future per-packet match fields |
| #1432 | CLOSED | #1703 S2: WireGuard AF_XDP datapath wiring (encap/decap + UDP socket + config) + live kernel-WG interop |
| #1434 | CLOSED | Implement Multi-Tunnel WireGuard Support |
| #1436 | CLOSED | RuntimeDataPlane split leaves userspace runtime status unavailable |
| #1437 | CLOSED | [Refactor] Eliminate Handshake Allocation Path in construct_outer_frame_allocated |
| #1438 | CLOSED | [Architecture] Fix Multi-Peer/Hub-Spoke Routing Bug in TunnelEndpoint and try_encap |
| #1439 | CLOSED | [Refactor] De-monolithize pkg/dataplane/userspace/snapshot.go into Modular Subsystem Builders |
| #1440 | CLOSED | [Refactor] Consolidate Packet Header Serialization and Checksum Logic across Dataplane Protocols |
| #1441 | CLOSED | [Refactor] Modularize WireGuardEngine into Dedicated Submodules |
| #1442 | CLOSED | [Refactor] Extract RX Stages from Monolithic poll_binding_process_descriptor |
| #1443 | CLOSED | [Refactor] Modularize Forwarding Resolution Pipeline in tx/dispatch.rs |
| #1444 | CLOSED | [Refactor] De-monolithize pkg/cli/cli.go into Logical Operational Presenters |
| #1445 | CLOSED | [Refactor] Consolidate Key Generation and Verification Logic in Go CLI and Config |
| #1448 | CLOSED | SNAT pools: preserve persistent leases across helper restart |
| #1449 | CLOSED | SNAT pools: synchronize persistent leases across HA failover |
| #1450 | CLOSED | SNAT pools: decide cross-backend address-persistent selector parity |
| #1451 | CLOSED | eBPF retirement: migrate remaining legacy dataplane surfaces before source removal |
| #1452 | CLOSED | REST system buffers still reads BPF map stats under userspace |
| #1453 | CLOSED | show system buffers: add helper-published capacity fields for dynamic userspace structures |
| #1454 | CLOSED | show system buffers: expose Rust-owned capacity constants through helper protocol |
| #1455 | CLOSED | SNAT persistent leases: fix rollback corruption with shared source-key refcounts |
| #1456 | CLOSED | SNAT persistent leases: remove stale expiration entries on release refresh |
| #1457 | CLOSED | SNAT persistent pools: tighten bounded-cleanup documentation |
| #1458 | CLOSED | SNAT persistent pools: add expiry-index consistency invariant tests |
| #1459 | CLOSED | SNAT persistent pools: document worst-case pressure cleanup latency |
| #1460 | CLOSED | SNAT persistent pools: document lease continuity loss on pool shape edits |
| #1466 | CLOSED | userspace-dp: reconcile workers when defer_workers is cleared |
| #1473 | CLOSED | eBPF retirement: split userspace XDP shim from legacy xdp_main fallback |
| #1474 | CLOSED | eBPF retirement: make userspace the default and retire dataplane-type ebpf rollback |
| #1475 | CLOSED | eBPF retirement: decide DPDK backend fate before deleting root DataPlane |
| #1476 | CLOSED | eBPF retirement: remove legacy BPF source, generated artifacts, and build hooks |
| #1477 | CLOSED | eBPF retirement: publish final userspace-only validation artifact set |
| #1484 | CLOSED | docs: reconcile userspace dataplane gaps after SNAT closeouts |
| #1490 | CLOSED | docs: retire stale HA failover runbook that expects xdp_main fallback |
| #1493 | CLOSED | eBPF retirement: split userspace shim loader from legacy loadAllObjects |
| #1500 | CLOSED | Extend userspace HA smoke harness to cover reverse and CoS matrix |
| #1501 | CLOSED | WireGuard engine (#1499) follow-up minors |
| #1502 | CLOSED | Artifact-schema checker (#1497) follow-up minors |
| #1503 | CLOSED | eBPF retirement: reconcile stale feature-gaps rows for closed #1375/#1378 |
| #1504 | CLOSED | eBPF retirement: harden userspace shim boundary canary against exotic Go escapes |
| #1509 | CLOSED | eBPF retirement: rename userspace degraded-path fallback counters |
| #1510 | CLOSED | eBPF retirement: add userspace shim helper-stop and link-cycle regressions |
| #1515 | CLOSED | eBPF retirement: tighten conntrack GC legacy-bridge canary (sub-#1451 S8) |
| #1516 | CLOSED | eBPF retirement: migrate pkg/grpcapi off legacy dataplane.DataPlane (sub-#1451 S1) |
| #1517 | CLOSED | eBPF retirement: migrate pkg/cli off legacy dataplane.DataPlane (sub-#1451 S2) |
| #1518 | CLOSED | eBPF retirement: migrate pkg/cluster session-sync off legacy dataplane.DataPlane (sub-#1451 S3) |
| #1519 | CLOSED | eBPF retirement: shrink and delete daemon legacyDP() accessor (sub-#1451 S4) |
| #1520 | CLOSED | eBPF retirement: extract userspace boot path from legacy dataplane.New() (sub-#1451 S5) |
| #1521 | CLOSED | eBPF retirement: decouple userspace maps_sync from legacy BPF map names (sub-#1451 S6) |
| #1522 | CLOSED | eBPF retirement: package README doc drift sweep before final source removal |
| #1524 | CLOSED | [Architecture] Multi-peer WG dispatch via allowed-ips LPM (integration PR requirement, supersedes #1438) |
| #1525 | CLOSED | Retire the DPDK dataplane; remove dpdk_worker, pkg/dataplane/dpdk, and backend registration |
| #1526 | CLOSED | DPDK retirement: reject 'system dataplane-type dpdk' at commit with migration message |
| #1527 | CLOSED | DPDK retirement: remove boot-path import, backend registration, and canary allow-list entries |
| #1528 | CLOSED | DPDK retirement: delete dpdk_worker, pkg/dataplane/dpdk, Makefile targets, and config schema |
| #1529 | CLOSED | DPDK retirement: sweep README, CLAUDE.md, and docs/ for forward-looking DPDK language |
| #1530 | CLOSED | DPDK retirement: publish final validation artifact set on userspace cluster |
| #1531 | CLOSED | Docs: DPDK is recommended/active in dataplane-decision and dpdk-dataplane — blocks #1525 Phase 1 |
| #1538 | CLOSED | config: accumulate strict validation errors into a multierror to avoid multi-pass commit friction |
| #1539 | CLOSED | config: guard against AST leakage / shadow execution of retired DPDK sub-tree fields |
| #1540 | CLOSED | Refactor: modularize REST API handlers and Prometheus collectors |
| #1541 | CLOSED | Refactor: split cluster manager into election, heartbeat, failover, and status modules |
| #1542 | CLOSED | Refactor: split userspace NAT runtime into allocator, source, destination, static, and status modules |
| #1543 | CLOSED | Refactor: decompose userspace screen and SYN-cookie runtime |
| #1544 | CLOSED | Refactor: split routing manager by VRF, tunnel, keepalive, XFRM, PBR, bond, and RETH domains |
| #1545 | CLOSED | Perf/refactor: eliminate cross-worker mirror clone heap allocation |
| #1546 | CLOSED | Refactor: split filter engine into match, evaluation, TX-selection, cache-sensitive, and policer modules |
| #1547 | CLOSED | Refactor: split FRR config rendering, vtysh execution, status parsing, and policy rendering |
| #1548 | CLOSED | conntrack: harden legacy_dataplane_canary against compound-type / generic / alias / import-rename bypasses |
| #1559 | CLOSED | daemon: harden legacy_dataplane_canary against struct-field + selector reintroduction (post-#1519 AGY P2/P3) |
| #1561 | CLOSED | userspace-dp: first-snapshot CoSBatch null deref on fresh VM boot (multi-worker race) |
| #1562 | CLOSED | userspace-dp: fresh-deploy warm-up dip in cos-off-ipv4-push throughput (#1477 Gate 6 artifact) |
| #1563 | CLOSED | cli: 'cli -c' segfaults on readline.SetPrompt in non-TTY mode (c.rl nil at cmd/cli/shared.go:225) |
| #1565 | CLOSED | pkg/api: net.InterfaceByName() with config-level names containing '/' fails silently (4 sites) |
| #1578 | CLOSED | Perf: CoS/port 5211 limiting throughput on loss userspace cluster (~9 Gbps vs prior 22+ Gbps baseline) |
| #1580 | CLOSED | Batch-smoke (W=1 close) FAIL: loss userspace cluster hits the documented infra ceiling from #1578 |
| #1584 | CLOSED | Adopt directory-based changelog architecture ('_Log/PR-<N>.md') to eliminate parallel-PR conflict + dedup risk |
| #1593 | CLOSED | Batch-smoke (W=2 close, counter=20) FAIL: same #1578 infra ceiling, same expected outcome |
| #1598 | CLOSED | Bug: CoS 'iperf-uncapped' forwarding class caps at ~10 Gbps despite scheduler having no transmit-rate |
| #1605 | CLOSED | Userspace dataplane JIT (Phase 4): Cranelift-based per-flow rewrite + policy/screen compilation |
| #1606 | CLOSED | Wire protocol: address-book ID + shared CIDR table (prerequisite for 1M-policy JIT) |
| #1607 | CLOSED | Cold-path hardware ceiling: synthetic policy gen + 64B microbench on loss userspace cluster |
| #1608 | CLOSED | Phase 4c: cold-path hardening — per-source ingress rate-limit + verdict micro-cache |
| #1609 | CLOSED | Multi-stage policy DAG: replace linear cold-path scan with structured lookup for 1M-policy line rate |
| #1611 | CLOSED | #1607 step-2: cold-path flooder runner body (AF_PACKET + sendmmsg) — deferred from step-1 narrowed scope |
| #1612 | CLOSED | #1607 step-3: Scale Target measurement table population + TSC-only gate verification — deferred from step-1 narrowed sco |
| #1614 | CLOSED | CoS regression under simultaneous-class load: class starvation + per-flow CoV jump + sub-shape utilization |
| #1615 | CLOSED | perf: cold-path-flooder hits container TX queue ceiling at ~870 K pps on cluster-userspace-host |
| #1620 | CLOSED | #1612 step-3 follow-up B: BindingWorker integration for cold-path latency histogram |
| #1621 | CLOSED | #1612 step-3 follow-up C: wire protocol (Rust + Go) + Prometheus emitter for cold-path histogram |
| #1622 | CLOSED | #1612 step-3 follow-up D: synthetic-policy-gen + harness + Scale Target table population |
| #1623 | CLOSED | Multi-Book LPM full design (#1609 step 2 — v3.2 plan round) |
| #1625 | CLOSED | #1614 step-2: per-queue epoch-cap mechanism in waterfill selector |
| #1626 | CLOSED | Fix cos-iperf-config.set to activate oversubscription-policy guarantee-rate |
| #1627 | CLOSED | Fix Phase-2 lock-in scaffold bug in waterfill selector (PR #1618 queue_service/mod.rs:889-893) |
| #1628 | CLOSED | Empirical per-class trace-counter instrumentation for CoS scheduler |
| #1630 | CLOSED | CoS scheduler still equalizes ~20%/class under guarantee-rate 0.7 (next-priority bug after #1626) |
| #1635 | CLOSED | Redesign cold-path histogram bucket layout + per-zone-pair slot mapping for trustworthy Scale Target tables |
| #1636 | CLOSED | Multi-second cold connect: neighbor-resolution gap between 260ms probe schedule and 2000ms timeout |
| #1638 | CLOSED | perf/refactor: #1623/#1624 parallel-prefix scaffolding re-introduces #1606's per-rule prefix duplication for a plan-kill |
| #1639 | CLOSED | documentation: userspace-jit-design.md marks CoS oversubscription (#1614) DONE with a ~3-7x improvement claim that #1630 |
| #1641 | CLOSED | NAT64 reverse path (translate_v4_to_v6) copies Ethernet padding into IPv6 payload, corrupting L4 checksum |
| #1642 | CLOSED | Rust->Go control-socket status parity: HAGroupStatus/CoSQueueStatus/ProcessStatus fields silently dropped on Go unmarsha |
| #1643 | CLOSED | v8 shared-CoS-lease seqlock reader snapshot_epoch_v8 lacks acquire fence — torn read on weakly-ordered CPUs (#1619 class |
| #1644 | CLOSED | docs: dpdk-dataplane.md and dataplane-decision-dpdk-vs-vpp.md describe DPDK retirement as in-progress, but #1525-#1528 a |
| #1645 | CLOSED | docs: userspace-cold-start-resolution.md overclaims cold connect resolved to ~2ms; #1636 measured ~3.371s (separate from |
| #1646 | CLOSED | frr: writeManagedSection skips strip when markerEnd missing (torn write), can later delete unrelated frr.conf content |
| #1648 | CLOSED | Deploy/restart first-connect: single SYN dropped during dataplane bringup (XDP/binding-array readiness window) |
| #1649 | CLOSED | Per-flow evenness via better initial placement (no mid-flight re-steer) — fresh angle on RSS-skew CoV |
| #1651 | CLOSED | Native dataplane ARP/NDP active resolution — eliminate the kernel+netlink cold-resolve cycle (~1ms vs ~1s) |
| #1653 | CLOSED | External codebase review (2026-05-28) — triage + prioritized action plan |
| #1658 | CLOSED | Rust netlink neighbor monitor has no SO_RCVBUF — ENOBUFS risk under multicast bursts |
| #1659 | CLOSED | Investigate: possible dynamic-neighbor desync on update_neighbors replace (UNCONFIRMED) |
| #1661 | CLOSED | Refactor audit (2026-05-29) — prioritized large-file split backlog |
| #1662 | CLOSED | userspace-dp: NAT64 zeroes DSCP/ECN in both directions (nat64.rs:174, :244) |
| #1663 | CLOSED | External codebase review (2026-05-28, last-review-new) — triage + verified action plan |
| #1666 | CLOSED | Gate the BPF READY write on helper-reported binding.Ready/XSKRegistered (crash-blind blackhole hardening) |
| #1667 | CLOSED | Pre-existing test failure on master: snat_contract_documents_current_fail_closed_runtime |
| #1669 | CLOSED | Deep architecture/perf/testing review (2026-05-28, review-avo) — verified backlog |
| #1673 | CLOSED | docs: refresh top-level README after eBPF source-removal closeout |
| #1678 | CLOSED | userspace-dp: --features debug-log build is broken (ICMPV6_EMBED_LOGGED private) |
| #1685 | CLOSED | Native GRE decap/encap heap-allocates a Vec per packet (zero-alloc datapath violation) |
| #1686 | CLOSED | Refactor: split pkg/dataplane/maps.go (2113 LOC) into domain accessor packages |
| #1687 | CLOSED | Refactor: shared security/NAT/flow presentation package (server_show.go 2006 + cli_show_security.go 1986) |
| #1691 | CLOSED | CoS #1614 Path B: document the ~22-24G push-ceiling + re-scope #1614 acceptance gates (drop per-flow-CoV) |
| #1692 | CLOSED | CoS #1614 Path A: instrument-first isolation of the 3g/6g guarantee-rate under-protection (§3.B) |
| #1693 | CLOSED | CoS #1614 Path C (DEFERRED): rate-aware transaction-safe queue->worker placement |
| #1694 | CLOSED | GetMapStats: stale map names + filter_rules ARRAY mis-count (pre-existing, surfaced in #1686) |
| #1697 | CLOSED | Refactor: extract cold-path/exception stages out of poll_descriptor/mod.rs hot loop (2983 LOC) |
| #1698 | CLOSED | Refactor: pkg/routing/routing.go domain-manager split (2085 LOC) — re-attempt post-#1544-kill |
| #1699 | CLOSED | Refactor: pkg/config/ast.go schema split (2021 LOC) — #1319-unblocked |
| #1700 | CLOSED | Refactor: pkg/grpcapi/server_show.go intra-package decomposition (2006 LOC) |
| #1701 | CLOSED | Refactor: pkg/config/types.go split (2055 LOC) — WAVE-2, serialized behind ast.go split |
| #1703 | OPEN | WireGuard interop: verify xpf can connect to Ubiquiti routers (UniFi/EdgeOS/UDM) over WireGuard |
| #1706 | CLOSED | pkg/routing: four latent defects surfaced by #1698 review (pre-existing) |
| #1709 | CLOSED | WireGuard S1: wire-protocol compliance (TAI64N + handshake framing) validated vs wireguard-go reference |
| #1710 | CLOSED | SNMPv3 USM auth: zeroAuthParams zeroes a 12/24-char username instead of authParams (locks out user) |
| #1711 | CLOSED | Policy simulator MatchPolicies: invalid/empty SourceIp treated as wildcard match (false-positive verdict) |
| #1712 | CLOSED | FRR OSPFv2 renders 'network 0.0.0.0/0 area X' — activates OSPF on every interface in the VRF |
| #1713 | CLOSED | systemd-resolved renderer drops domain-search when domain-name is also set |
| #1714 | CLOSED | Doc accuracy: 3 stale 'not implemented' notes contradict shipped code (SNMP traps, SYN-cookie, IPv6 VRRP) |
| #1715 | CLOSED | DNS broken: /etc/resolv.conf left a dangling symlink when systemd-resolved is inactive (3 conflicting DNS owners, no rec |
| #1724 | CLOSED | Refactor: dedup 7x 'match protocol' checksum-offset logic in afxdp/frame/checksum.rs via a monomorphized helper |
| #1725 | CLOSED | Test coverage: filter/engine evaluation (eval.rs 681 / tx_selection 286 / cache_sensitive 200 — 0 cfg(test)) |
| #1726 | CLOSED | Prometheus descriptor-coverage canary test (guard the #1635-class Describe() gap) |
| #1731 | CLOSED | CoS fairness: generalize per-flow MQFQ to all shaped queues + waterfill correctness + scale/AQM gaps (fresh review) |
| #1732 | CLOSED | CoS #1731-a: GuaranteeRate waterfill — persistent honored set + alloc-free hot path |
| #1733 | CLOSED | CoS #1731-b: equal-flow fail-opens above 32 workers — hard-reject config >32 (+ heap-scratch follow-up) |
| #1734 | CLOSED | CoS #1731-c: shaped drain refreshes stale now_ns across repeated queue service |
| #1735 | CLOSED | CoS #1731-d: generalize per-flow MQFQ to all shaped queues (best-effort/residual), closes #7 |
| #1736 | CLOSED | #1703 S2b: Live kernel-WireGuard-on-VM interop test + smoke (follow-up of #1432) |
| #1741 | CLOSED | Telemetry bug: xpf_userspace_cos_active_flow_count over-counts active flows; derived fairness_cstruct/CoV gauges unrelia |
| #1742 | CLOSED | Research: same-queue XSK fanout to relieve RSS-overloaded workers (sub-multinomial per-flow fairness, NOT cross-queue re |
| #1743 | CLOSED | CoS waterfill: Phase-1 over-budgets shaped root → Phase-2 surplus never admits (phase2_admit=0) → high per-flow CoV at h |
| #1745 | CLOSED | CoS equal-flow-enforcement permanently fail-opens (insufficient_sampled_workers) — exact-queue token-banking hides worke |
| #1746 | CLOSED | Explore: CoS equal-flow target is clip-to-SLOWEST (non-work-conserving) — evaluate mean/global-fair-rate target |
| #1748 | CLOSED | Explore: cross-worker per-flow rebalance on mlx5 VFs (re-evaluate #899/#936/#937 on native-XDP + ntuple-capable VFs) |
| #1750 | CLOSED | Research: reliable per-flow 5-tuple feed for the #1748 rebalance controller (flow_worker_map sparse under load) |
| #1751 | CLOSED | Redesign #1748 rebalance selection to count-balancing (per-flow byte-rate signal unreliable) |
| #1752 | CLOSED | P48/5210 forwarding is CPU-bound at 16 Gb/s — CoS shaping ~19% + mlx5 crypto DEK churn ~5.6% on a 6/6 VM |
| #1754 | CLOSED | #1752 Path B: reduce AF_XDP TX/RX wake sendto() kick CPU (crypto-DEK was a perf artifact) |
| #1755 | CLOSED | #1752 Path A: CoS exact-guarantee hot-path CPU reduction (~19%) |
| #1756 | CLOSED | #1752 Path C: control-plane CPU isolation (dedicate core 0 to Go) — likely net loss, A/B-gated |
| #1757 | CLOSED | #1752 Path D: document the 6-vCPU/6-queue/6-worker no-headroom sizing ceiling |
| #1758 | CLOSED | #1752 Path E follow-up: is the session-refresh secondary-index re-assert a ~1% perf opt or a latent NAT-corruption bug? |
| #1760 | CLOSED | Latent NAT reverse-path corruption: single-valued secondary index can't represent two live sessions sharing a reverse ke |
| #1763 | CLOSED | #1752 residual: cos_queue_pop_front O(N) min-finish (~3.8%) + neighbor/rtnl netlink churn — post-#1753/#1755 profile |
| #1765 | CLOSED | Cross-worker per-flow fairness at low parallelism (-P12 bimodal split): full investigation [umbrella] |
| #1766 | CLOSED | #1765: characterize -P12 fairness (RSS Cstruct vs v8/V_min gap) + evaluate equal-flow-enforcement |
| #1767 | CLOSED | #1765 deep: induce TCP re-convergence on oversubscribed workers WITHOUT re-steering (per-worker AQM/ECN/pacing) |
| #1769 | CLOSED | userspace-dp neighbor discovery path stuck: new flows hang at connect (0 bytes) despite kernel having the neighbor |
| #1771 | CLOSED | Refactor: per-key neighbor resolver state machine (#1769 §10a full redesign) |
| #1772 | CLOSED | Add neighbor/ARP resolution latency metrics (pending-buffer dwell, GETNEIGH RTT, probe-revalidate) to diagnose intermitt |
| #1776 | CLOSED | Refactor: decompose worker_loop (~1440 LOC single fn) in loop_body/mod.rs — #1326 Phase 2 |
| #1777 | CLOSED | Bug: DHCP client discards successful T1/T2 renewal (v4+v6) — continue triggers full re-acquisition |
| #1778 | CLOSED | Bug: dhcpserver (Kea) manager is not authoritative — won't stop stale Kea after xpfd restart; fail-open restart |
| #1780 | CLOSED | Bug: cold connect to data-path next-hop (172.16.80.200) hangs ~0 bytes after overnight idle; retries stay hung a while t |
| #1782 | CLOSED | Neighbor cold-connect: pin the multi-second resolution-delay source (capture-gated, #1780 Path B) |
| #1784 | CLOSED | docs: CLAUDE.md drift — stale #1373 retirement framing, node1 FPC-7 interface names missing from cluster topology, 640+/ |
| #1785 | CLOSED | docs: engineering-style.md validation table pairs 'make test-deploy' (standalone VM) with the loss-cluster-only iperf3 e |
| #1786 | CLOSED | capture-cold-stall.sh: DP_IFACE defaults to node0's ge-0-0-2 — against fw1 (ge-7-0-2) the sysctl + tcpdump evidence sile |
| #1787 | CLOSED | userspace-dp: per-packet 64-shard bulk lock + heap allocs in learn_dynamic_neighbor when source keys interleave on a bin |
| #1788 | CLOSED | userspace-dp: MAX_PENDING_NEIGH + neg_neigh module docs still describe pre-#1771 VecDeque packet-FIFO semantics |
| #1789 | CLOSED | userspace-dp: USERSPACE_SESSIONS publish failures swallowed with let _ = at 8+ sites — zero release-build observability |
| #1790 | CLOSED | userspace-dp: update_ha_state stores new rg_runtime before demote propagation — error path makes the missed demotion per |
| #1791 | CLOSED | applyConfigLocked appends in place onto shared active-config StaticRoutes — third site of the shared-config append hazar |
| #1792 | CLOSED | HA peer-liveness uses wall-clock time: a forward clock step (NTP makestep, VM pause/resume) falsely declares peer lost — |
| #1793 | CLOSED | DHCP client lifecycle is startup-only: enabling dhcp/dhcpv6 via commit on a running daemon does nothing; deleting it lea |
| #1794 | CLOSED | apply-path external commands (systemctl restart rsyslog / reload sshd, useradd, chpasswd, chown) run with no timeout whi |
| #1795 | CLOSED | cluster sync sweep logs slog.Info every 1s tick under sustained session churn (sync_conn.go:455) — violates the per-poll |
| #1796 | CLOSED | Bug: vrrp-group flat-set config silently drops virtual-address/priority (dual-AST gap) |
| #1797 | CLOSED | Bug: forwarding-options dhcp-relay flat-set is non-functional (missing from setSchema + compiler dual-AST gap) |
| #1798 | CLOSED | Bug: newline in interface description injects directives into generated networkd .network unit |
| #1799 | CLOSED | Bug: commit reports success but silently loses config on restart when disk persistence fails |
| #1800 | CLOSED | Adversarial sweep 2026-06-09: triage + remediation plan umbrella (#1784–#1799) |
| #1805 | CLOSED | Bound gRPC/HTTP request-path exec sites (raw ip/show/status shell-outs can pin handlers) |
| #1807 | CLOSED | Worker command-queue poison makes the worker permanently deaf — try_lock unwrap_or(false) skips a poisoned queue forever |
| #1808 | CLOSED | Bug: SNAT pool address block form double-appends addresses (hierarchical vs flat divergence) |
| #1809 | CLOSED | Bug: CoS classifier inline loss-priority leaf dropped in hierarchical form |
| #1810 | CLOSED | Bug: setSchema models system name-server as single-value — second set REPLACES the first |
| #1814 | CLOSED | vrrp-group track-interface nested priority-cost block not modeled (both AST shapes ignore it) |
| #1819 | CLOSED | Diag stream exec bounds: ping count>30 truncated by 30s cap; gRPC/HTTP traceroute timeout disparity (30s vs 60s) |
| #1824 | CLOSED | Testing: proptest/fuzz harness for frame/inspect parse, NAT round-trip, state_writer encode |
| #1825 | CLOSED | /research: pkg/daemon package-subdir restructure (65 files, ~22K LOC flat) |
| #1826 | CLOSED | Cleanup batch: consolidate PROTO_* consts (8x dup), SOL_XDP dup, SAFETY comments, debug_assert counters, dead-code Datap |
| #1827 | CLOSED | Multi-WAN: uplink model, health probes, failover + PBR policy layer |
| #1828 | CLOSED | WAN smart queueing: fq_codel/CAKE egress AQM on uplinks |
| #1829 | CLOSED | CoS: FQ-CoDel dequeue-time AQM for shaped queues (deferred (f) from #1731 — blocker #1735 shipped) |
| #1830 | CLOSED | CoS: remove 32-worker scratch cap via heap scratch + bucket-vs-flow occupancy telemetry ((e)+(g) from #1731) |
| #1831 | CLOSED | Metrics: export v_min_throttles + hard_cap_overrides to Prometheus; --equal-flow-enforcement injector for apply-cos-conf |
| #1838 | CLOSED | generic IPv6 NAT path assumes L4 at fixed offset 40 — corrupts valid ext-header traffic (port rewrite + checksum adjuste |
| #1839 | CLOSED | IPv6 L4 zero-checksum canonicalization scope mismatch: descriptor path 0x0000→0xFFFF for ALL protocols, generic path UDP |
| #1840 | CLOSED | adjust_l4_checksum_port UDP zero-checksum skip is not family-gated — v6 UDP takes the IPv4-only RFC 768 bypass |
| #1844 | CLOSED | ip-monitoring: DHCP-learned-uplink support for preferred-route next-hops |
| #1849 | CLOSED | CoS: per-packet overhead compensation (CAKE-style) for shaped WAN links |
| #1852 | CLOSED | Non-first-fragment port-NAT exposure + MSS-clamp v6 ext-header gap (pre-existing, both families) |
| #1855 | CLOSED | cargo test red on master: session inplace_{stale,vacant}_handle_returns_false_no_panic hit debug_assert panics |
| #1861 | CLOSED | Failed session install is not transactional: reverse session installed + packet forwarded after forward-install failure; |
| #1863 | CLOSED | CoS guarantee-rate: honored-realization gap — Phase-1-honored mid classes realize ~80% of honored bytes under Phase-2 ag |
| #1864 | CLOSED | make generate produces a userspace-xdp shim object that fails the kernel-7.0 BPF verifier (>1M insns) — pin the BPF tool |
| #1865 | CLOSED | #1703 S6 adjacency: operator-visible WireGuard telemetry (handshake/encap/decap counters + drop reasons) |
| #1866 | CLOSED | #1703 S2a follow-up: WG tunnel removal leaks the control thread + bound listen port (re-add with same identity EADDRINUS |
| #1870 | CLOSED | Local-tunnel UpsertLocal session pair silently dropped at max_sessions while shared maps hold both entries |
| #1873 | CLOSED | Tunnel-endpoint IDs are positional — add/remove of one tunnel renumbers the others (WG session resets, HA id drift) |
| #1875 | CLOSED | #1736 S2b closure run blocked: concurrent agent deploy loop owns the loss userspace cluster (binary swaps mid-phase) |
| #1879 | CLOSED | Simplify xpf installation: single-artifact deployment, dependency handling, first-boot bootstrap |
| #1880 | CLOSED | First xpfd boot after deploy intermittently exceeds the failover harness's 60s comeback budget |
| #1881 | CLOSED | GRE local-origin threads run on a frozen ForwardingState across refresh_runtime_snapshot |
| #1884 | CLOSED | GRE tunnel anchors are deleted and recreated on every applyConfig — flaps gr-X and kills attached TUN readers |
| #1885 | CLOSED | Local-delivery TUN writes are mis-sliced by 4 bytes on VLAN-tagged ingress — every GRE-to-self packet hits TUN write EIN |
| #1888 | CLOSED | #1703 S5: WireGuard rekey/expiry/persistent-keepalive timers — engine has zero time-based state, forward secrecy degrade |
| #1889 | CLOSED | userspace-dp: WG control thread busy-polls with 1ms idle sleep — replace with blocking poll(2) over socket + TUN fds |
| #1890 | CLOSED | refactor: coordinator/mod.rs crosses the 2,000 prod-LOC threshold (~2,160) — split CoS lease builders, WG supervision, s |
| #1891 | CLOSED | refactor (deferred, blocked on #1319): plan pkg/config/schema.go domain split as sibling schema_*.go files |
| #1892 | CLOSED | Config-doc audit: 493 empty-help schema nodes, 11 dead dataplane knobs (write-only), misleading cores/memory help |
| #1893 | CLOSED | configstore: New() warns "falling back to file-only" after NewDB failure but stores a nil *DB — next Load/Save/commit pa |
| #1894 | CLOSED | configstore + subsystem persistence: no fsync anywhere on durable state (active config, rollback, rescue, master.key) —  |
| #1895 | CLOSED | rpm: probe-pin programming failures are log-and-continue — RPM applies SO_MARK regardless, so an unbacked pin silently m |
| #1896 | CLOSED | configstore journal: full compiled config appended per commit + ListEntries reads the whole file — commit history scales |
| #1902 | CLOSED | pending_neigh buffers the un-decapped OUTER frame with the post-decap INNER meta — retry TXes a mis-rewritten GRE outer  |
| #1904 | CLOSED | daemon_apply step 0a binds the literal .N name for unit>0 routing-instance tunnel members — bind fails for uN per-unit d |
| #1905 | CLOSED | WireGuard tun address reconcile leaks configured link-local addresses removed from config |
| #1912 | CLOSED | Cold ENCAP outer next-hop blackholes tunnel-bound replies with no observed probe (seen live during #1902 validation) |
| #1913 | CLOSED | Trailing maybe_reinject_slow_path_from_frame runs for ALL non-forward dispositions (incl. PolicyDenied) — _from_frame va |
| #1914 | CLOSED | Tunnel-endpoint collision gate: wildcard apply-groups refs are hashed literally (false accept) and src/dst-incomplete tu |
| #1915 | CLOSED | DHCP relay: multi-interface groups fail (EADDRINUSE) and Stop()/reapply can hang (blocking ReadFromUDP, no close-on-canc |
| #1916 | CLOSED | Durability coverage gap: fsatomic canary excludes pkg/daemon + pkg/api; TLS cert/key persisted non-atomically with ignor |
| #1917 | CLOSED | In-place xpf upgrade: deploy new xpfd + userspace-dp without re-imaging the VM |
| #1918 | CLOSED | routing: tunnel keepalive reports route-existence as remote liveness (probeICMP never probes) |
| #1919 | CLOSED | routing: removing a WireGuard tunnel leaks its kernel addresses + FRR routes (persistent wgN bypasses address reconcile) |
| #1920 | CLOSED | refactor: poll_descriptor/mod.rs is 2858 LOC (over the 2000 modularity threshold) — split the AF_XDP poll loop |
| #1921 | CLOSED | AF_XDP dataplane fails to forward on virtio_net multi-queue (over-provisioned queue plan + all-or-nothing arm gate → EBU |
| #1922 | CLOSED | #1879 M1b: SAFE-BOOTSTRAP daemon work (bootstrap mode, five-case predicate, PCI-keyed lifeline, protected-set) |
| #1923 | CLOSED | #1879 M1a: policy-correct .deb + xpf-upgrade verify-before-unpack wrapper |
| #1924 | OPEN | #1879 M3: signed, hosted appliance distribution (install.sh + signed apt repo + minisign) |
| #1925 | OPEN | #1879 day-2: root-partition auto-grow (systemd-repart) + HA image-replace rehearsal |
| #1926 | OPEN | #1879: prove appliance forwarding on a supported NIC venue (mlx5-VF / i40e-PF) |
| #1928 | CLOSED | virtio_net AF_XDP: XDP redirects to XSKMAP but copy-mode packets never reach userspace sockets (rx_packets=0, 0 forwardi |
| #1930 | CLOSED | Major underlying VM/OS + kernel upgrades (deferred from #1917 control-plane+dataplane upgrade) |
| #1943 | CLOSED | Test env drift: standalone test VM is Debian 13 but production is Ubuntu 26.04 — realign to production parity |
| #1944 | CLOSED | system login user has no encrypted-password — non-root operators can't log in on the console (SSH-key/sudo only) |
| #1946 | CLOSED | FabricRedirect desc-frame (Live) fallback is silently dropped (dispatch/mod.rs asymmetry) |
| #1956 | CLOSED | Bare-metal interface handling: positional PCI-order naming + claim-everything is unsafe on real hardware — design a devi |
| #1958 | OPEN | Umbrella: substrate-agnostic interface binding + bootstrap-reachability contract (VM / bare-metal / container) |
| #1960 | CLOSED | Harden: persisted-DB compile failure with everCommitted=true falls back to positional naming (claims all NICs) instead o |
| #1961 | CLOSED | virtio_net AF_XDP zero-copy delivers 0 packets to the XSK — no forwarding on plain virtio (copy-mode fallback?) |
| #1962 | CLOSED | standalone setup.sh deploy doesn't push the xpf-userspace-dp helper (no dataplane on standalone VMs) |
| #1964 | CLOSED | Seed versioned runtime on first package install before enabling in-place upgrade |
| #1965 | CLOSED | Serialize host-local upgrade mutators with a shared upgrade lock |
| #1966 | CLOSED | Update Debian package description for postinst-driven standalone cutover |
| #1967 | CLOSED | Upgrade cutover robustness: version-string validation + crash-window hardening |
| #1968 | CLOSED | Upgrade durability + drain-gate parser: latent defensive hardening (AGY review-011 Part I) |
| #1977 | CLOSED | Snapshot wire-type NUM_WIDTH siblings of #1961: Go int → Rust u16/u32/u64 out-of-range values abort apply_snapshot |
| #1979 | CLOSED | Flow/flow-export NUM_WIDTH: add commit-time ValidateInteger (Layer B of #1977) |
| #1981 | CLOSED | Upgrade: close dpkg-unpack vs operator-cut staged-source race with immutable staged generations |
| #1982 | CLOSED | Upgrade: centralize the managed-binary manifest (Go + maintainer scripts + debian/rules) with a drift canary |
| #1983 | CLOSED | Upgrade: 'xpfd upgrade --rolling --unit' ignores --unit for cluster control (hard-coded 127.0.0.1:50051) |
| #1984 | CLOSED | Upgrade lock: stale owner-metadata read window misreports the holder (truncate-on-acquire + remove-on-release) |
| #1985 | CLOSED | debian/xpf.postrm: exec failure of staged xpfd capability-check triggers destructive downgrade teardown (false downgrade |
| #1986 | CLOSED | Refactor (backlog, HIGH-value): de-monolith userspace-dp/src/afxdp/mirror.rs (1402 LOC) into mirror/{mod,fast_path,resol |
| #1987 | CLOSED | Refactor (backlog): consolidate pkg/dhcp + pkg/dhcpserver + pkg/dhcprelay into pkg/services/dhcp/{client,server,relay,co |
| #1988 | CLOSED | Refactor (backlog): decompose pkg/flowexport into manager/ipfix/netflow/transport |
| #1989 | CLOSED | Refactor (backlog): decompose pkg/ipsec into manager/ike/crypto/policy (isolate secret decryption) |
| #1990 | CLOSED | Refactor (backlog): group pkg/dataplane/userspace/*fmt.go into a format/ subpackage |
| #1992 | CLOSED | Test env: multiple standalone firewall VMs share gateway IPs 10.0.1.10/10.0.2.10 on bpfrx-trust/untrust → nondeterminist |
| #1993 | CLOSED | Compile-failure bootstrap (#1960): FRR keeps advertising last-good routes on cold boot → transit blackhole instead of HA |
| #1997 | CLOSED | debian/xpf.postrm downgrade: versions/current deleted before remove_runtime_dropin — crash in the window leaves an orpha |
| #1999 | CLOSED | Upgrade manifest: enforce StagedSrc in packaging and all-managed payload checks |
| #2000 | CLOSED | postinst upgrade: keep repaired sbin links on versions/current, never staged |
| #2001 | CLOSED | Docs: sweep upgrade/install image docs after #1964/#1982/#1983 hardening |
| #2002 | CLOSED | Refactor (backlog): decompose pkg/config parser/AST into pkg/config/ast/ |
| #2003 | CLOSED | Refactor (backlog): split userspace-dp afxdp/bpf_map/mod.rs into pin/metrics/ha |
| #2004 | CLOSED | Refactor (backlog): consolidate pkg/daemon device_map + rss_indirection into pkg/daemon/multiqueue/ |
| #2005 | CLOSED | Refactor (backlog, HIGH-risk hot path): split userspace-dp session/mod.rs into lookup/install/expire |
| #2006 | CLOSED | Refactor (backlog, failover-gated): group pkg/vrrp flat files into manager/instance/packet/track |
| #2008 | OPEN | vSRX config parity: gaps found auditing vsrx.conf (204 features, 27 confirmed gaps) |
| #2016 | CLOSED | Cleanup: deferred cosmetic nits from the #2008 Tier-1 merges (ip_proto consts + SNMP getCommunity O(1)) |
| #2022 | CLOSED | pkg/ipsec effectiveTrafficSelectors: vpn==nil branch dereferences vpn (panic if ever reached) |
| #2023 | CLOSED | pkg/flowexport transport: dialCollectors ignores SourceAddress resolve error + leaks conns on raddr-resolve failure |
| #2032 | CLOSED | docs: session/expire.rs comments reference pre-#964 self.sessions (now entries: slab) |
| #2033 | CLOSED | ra: serialize goodbye withdrawal with sender shutdown so normal RAs cannot follow lifetime-zero RAs |
| #2034 | CLOSED | ra: do not re-enable addr_gen_mode or link-cycle RETH interfaces to create RA link-locals |
| #2035 | CLOSED | lldp: split socket lifecycle from TLV codec and make stop cancellation immediate |
| #2036 | CLOSED | lldp: fail closed on overlength TLVs instead of masking length and emitting malformed frames |
| #2049 | CLOSED | dynamic-address: feed prefixes are status-only and never populate policy/dataplane address sets |
| #2050 | CLOSED | feeds: compare feed content, retain last-good on parse errors, and recompile on semantic changes |
| #2051 | CLOSED | config: expose activate/deactivate as first-class config-mode edits across local CLI, gRPC, REST, and remote CLI |
| #2052 | CLOSED | config: make load set a real service-mode operation or remove it from remote help |
| #2053 | CLOSED | config: redact all sensitive secrets at JSON/YAML marshal time (TSIGSecret, IKE PSK, OSPF/auth keys) |
| #2062 | CLOSED | daemon: ssh sshd_config.d drop-in lifecycle — remove on config-empty + revert on reload failure |
| #2068 | CLOSED | [audit] Nested application-set members are parsed but silently dropped, leaving policy application-match incomplete |
| #2069 | CLOSED | [audit] lo0 input filter never applied: invalid 'flush ruleset inet xpf_lo0' nft syntax rejects the whole ruleset (fail- |
| #2070 | CLOSED | [audit] Interface-monitor reports a carrier-down (cable-pulled) link as UP, suppressing HA failover |
| #2071 | CLOSED | [audit] IPv6 prefix-list referenced via 'from prefix-list' rendered with the IPv4 'match ip address' matcher |
| #2072 | CLOSED | [audit] route-filter 'upto /N' match-type silently ignored, defaults to le 32/le 128 |
| #2073 | CLOSED | [audit] resolveESPSettings silently drops configured PFS group (esp_proposals = default) when the IPsec-policy proposal  |
| #2074 | CLOSED | [audit] renderConfig leaks the gateway NAME into remote_addrs, producing a silently-broken tunnel when the gateway is ab |
| #2075 | CLOSED | [audit] NetFlow v9 + IPFIX exporters are never reconciled on config commit (stored-but-never-enforced) |
| #2076 | CLOSED | [audit] DHCP relay cannot deliver unicast OFFER/ACK to clients that do not set the broadcast flag |
| #2077 | CLOSED | [audit] TCP segmentation TTL gate is v4/v6 asymmetric: a fabric-ingress IPv4 oversized TCP segment with TTL==1 is wrongl |
| #2078 | CLOSED | [audit] rst-invalidate-session / no-syn-check / no-syn-check-in-tunnel are committed but never enforced on the live user |
| #2079 | CLOSED | [audit] NAT pool-utilization-alarm is parsed and stored but has no consumer (alarm never fires) |
| #2080 | CLOSED | [audit] handlePeerTimeout re-checks peerAlive (always true) instead of heartbeat staleness after the guard window — a fr |
| #2081 | CLOSED | [audit] ReconcileVIPs' critical post-MAC-change GARP is silently dropped by 500ms time-dampening despite the epoch bump  |
| #2082 | CLOSED | [audit] ReleaseSyncHold triggers unconditional becomeMaster on a BACKUP instance with preempt=true, bypassing peer-prior |
| #2083 | CLOSED | [audit] renameInterface leaves interface renamed-but-DOWN when the final LinkSetUp fails |
| #2084 | CLOSED | ping/traceroute argv lacks -- separator (option-confusion hardening, not shell injection) |
| #2085 | CLOSED | [audit] Display lease parser returns stale/expired and duplicate Kea memfile rows |
| #2089 | CLOSED | [parity] security policy 'reject' action silently drops instead of sending TCP RST / ICMP unreachable |
| #2090 | CLOSED | checkVIPReadinessForConfig uses admin-IFF_UP, not carrier (sibling of #2070, no-reth-vrrp takeover gate) |
| #2103 | CLOSED | [audit] route-filter 'longer' emits FRR-invalid 'ge plen+1 le max' for max-length prefixes (/32, /128) |
| #2105 | CLOSED | [audit] route-filter prefix slot has no CIDR validator — malformed prefix renders an FRR-garbage prefix-list line |
| #2106 | CLOSED | Confirm policy-reject reply (RST/ICMP) on-wire via peer-side capture on a clean DUT-isolated VM |
| #2114 | CLOSED | [audit] #2079 NAT pool-alarm monitor races bootstrap-exit on the unsynchronized d.dp field |
| #2115 | CLOSED | #2076 DHCP relay raw-L2 follow-ups: live flag0 wire-capture (lab) + merged-Keys overrides regression test |
| #2117 | CLOSED | policy reject: port-22 (SSH) untrust→trust blocks but emits no TCP RST while other ports RST |
| #2118 | CLOSED | show security policies hit-count reads 0 for all rules (userspace dataplane doesn't populate per-policy counters) |
| #2120 | CLOSED | Standby silently expires long-lived synced sessions (userspace wheel has no standby gate) — #270 removed LastSeen re-syn |
| #2121 | CLOSED | flushDeleteJournal silently drops journaled deletes if the send queue is full during replay |
| #2122 | CLOSED | Static NAT silently drops all rules written in canonical Junos prefix form (X/32) — Rust IpAddr::parse rejects the CIDR  |
| #2123 | CLOSED | NAT64 range-form source pool drops all pool addresses — Rust Ipv4Addr::parse rejects the /32 masks emitted by address-ra |
| #2124 | CLOSED | Policy application term with a named protocol the Rust matcher can't parse (sctp/esp/ah/vrrp/igmp/pim/egp) silently fail |
| #2125 | CLOSED | Junos-native GCM encryption-algorithm names render to invalid swanctl proposals (no ICV-length suffix) — tunnel silently |
| #2126 | CLOSED | Pre-shared key containing a double-quote breaks swanctl secret quoting (PSK is emitted inside "..." with no escaping) |
| #2127 | CLOSED | rtProtoName mislabels FRR route protocols: IS-IS (RTPROT_ISIS=187) unmapped, and RTPROT_ZEBRA(11)/RTPROT_BIRD(12)/bogus- |
| #2128 | CLOSED | Screen session-limit tracker leaks an unbounded zero-count entry per distinct source/destination IP (memory-exhaustion D |
| #2129 | CLOSED | NetFlow v9 exporter starts unconditionally whenever sampling+flow-server is configured, ignoring 'services flow-monitori |
| #2130 | CLOSED | Rust dataplane NetFlow v9 export is entirely dead code: FlowExportSnapshot is parsed and stored in 'flow_export_config'  |
| #2134 | CLOSED | Screen session-limit enforcement is a no-op in the userspace dataplane (lifecycle never wired) |
| #2136 | CLOSED | NetFlow: flow-server with both version9 AND version-ipfix double-exports to one collector (per-flow-server version bindi |
| #2138 | CLOSED | userspace apply: persistent-SNAT protocol mismatch disarms the helper but does NOT abort the commit (fail-closed datapla |
| #2139 | CLOSED | event-options change-configuration commits partial command batches (non-transactional remediation) |
| #2140 | CLOSED | event-options cooldown/window runtime state is wiped on every config apply (cooldown defeated by the action's own commit |
| #2141 | CLOSED | event-options attributes-match: malformed/unknown-field constraints are silently dropped at commit (fail-open automation |
| #2142 | CLOSED | appid: invalid application port/protocol specs are warning-only and compile into never-match AppIDs referenced by policy |
| #2143 | CLOSED | diag: local CLI ping/traceroute double-prefixes the VRF device (vrf-vrf-red) — REST/gRPC normalize, CLI does not |
| #2144 | CLOSED | routingpolicy: export references (protocols ospf/bgp export, forwarding-table export) are not validated before FRR rende |
| #2145 | CLOSED | userspace screen/SYN-cookie: priority-tagged VLAN-0 frames parsed as untagged (vlan_id>0 instead of vlan_present) — IP h |
| #2146 | CLOSED | userspace screen: truncated IPv6 fragment header fails OPEN for syn-frag — stale 'keep BPF screen enabled' mitigation (B |
| #2147 | CLOSED | userspace state_writer: fallback path has no file fsync and neither path fsyncs the parent dir (state snapshot not crash |
| #2148 | CLOSED | userspace frame/tcp: frame_has_tcp_rst / extract_tcp_flags_and_window / extract_tcp_window hard-code IPv6 TCP at offset  |
| #2149 | CLOSED | userspace frame builders cannot emit priority-tagged VLAN-0 / preserve PCP (vlan_id>0 gating, u16-only L2 reply parse) |
| #2150 | CLOSED | userspace: multiple incompatible Ethernet/IPv6 parsers — ARP/NDP learning disagrees with forwarding on 0x88a8 + IPv6 ext |
| #2151 | CLOSED | userspace: TCP flag constants scattered across 4+ sites plus raw literals (flow-cache/forwarding/screen) — consolidate t |
| #2152 | CLOSED | VRRP gateway ARP probe uses primary IP, not VIP, as sender — gateway never refreshes VIP→MAC on failover |
| #2153 | CLOSED | DHCP relay silently drops DHCPINFORM (only DISCOVER/REQUEST relayed) — clients lose DNS/domain/NTP options |
| #2154 | CLOSED | DHCP server lease display: parseLeaseCSV ReadAll aborts whole 'show leases' on one torn/concurrent Kea line (#2085 left  |
| #2155 | CLOSED | VRRP AF_PACKET BPF + parseAfPacketIPv6 drop IPv6 adverts carrying extension headers (fixed 40-byte offset) — rare split- |
| #2156 | CLOSED | VRRP UpdateInstances orphans an instance on transient link/socket failure (deletes before rebuild, continue, no retry) |
| #2157 | CLOSED | event-options remediation silently dropped when config lock is held (EnterConfigure fail → return, no queue/retry) |
| #2158 | CLOSED | [refactor] Split files over the ~2,000 prod-LOC modularity threshold (configstore/store.go, shared_cos_lease, wg/engine. |
| #2160 | CLOSED | Static-NAT external address: proxy-ARP neigh entry installed but per-interface proxy_arp sysctl left 0 → kernel won't an |
| #2161 | CLOSED | NAT64 translations counter + show security flow session read 0 despite captured translated traffic |
| #2162 | CLOSED | Standalone deploy (test/incus/setup.sh deploy) does not push the Rust xpf-userspace-dp helper (and test-deploy targets t |
| #2170 | CLOSED | HA session-sync: deferred/journaled delete can kill a same-key replacement session (needs a wire generation guard) |
| #2173 | CLOSED | static-NAT: reject a non-host (non-/32//128) match/prefix at commit instead of silently dropping it in the dataplane |
| #2175 | CLOSED | policy/firewall-filter: compiler_filter.go protocol-name table not centralized into appid.ProtocolNumber (5th table) |
| #2176 | CLOSED | deploy: raw cluster/test deploy silently runs OLD code when a stale #1917 version-pin drop-in is present |
| #2183 | CLOSED | flowexport: IPv6 NetFlow/IPFIX collector address built without brackets (net.Dial fails → IPv6 collectors unusable) |
| #2186 | CLOSED | docs: screen session-limit is per-worker → effective cap = configured × num_workers (multi-queue); make explicit |
| #2187 | CLOSED | appid/NAT: source/destination-NAT 'match application <bad>' does not validate the app spec at commit (silent never/over- |
| #2197 | CLOSED | proxy-ARP follow-ups: v6 pneigh-table install, re-assert after non-commit link cycle, narrow over-answer to per-address  |
| #2208 | CLOSED | CRITICAL: TX dispatch leaks ingress UMEM descriptor + skips slow-path on congested/oversized forward (enqueue_pending_fo |
| #2209 | CLOSED | HIGH: screen scan/sweep state is global (cross-zone bleed) + unbounded + per-packet zone-string hash/profile clone |
| #2210 | CLOSED | HIGH: IP-sweep screen counts established/non-SYN traffic before session lookup (false positives, lost ACK-evasion invari |
| #2211 | CLOSED | PERF: NAT64 transit path heap-allocates and copies multiple times per packet (write into reserved TX frame instead) |
| #2212 | CLOSED | MEDIUM: NAT64 runtime snapshot parser silently drops bad config instead of failing the apply closed (helper-boundary def |
| #2214 | CLOSED | Go<->Rust: empty collections (NAT64 pool / filter terms) serialize as JSON null -> whole-snapshot decode failure -> no t |
| #2215 | CLOSED | HIGH: screen parity regressions -- SCREEN_PING_OF_DEATH dead code (fragment reassembly from #893 never ported) + LAND na |
| #2216 | CLOSED | HIGH: event-options engine -- temporal windows grow unbounded (prune gated on trigger) + concurrent triggers drop all-bu |
| #2217 | CLOSED | MEDIUM: firewall/application undefined-reference not validated at commit -- then policer, application-set member, then r |
| #2218 | CLOSED | MEDIUM: SNAT/DNAT "Translation hits" counter always 0 -- Rust dataplane never writes nat_rule_counters (eBPF-retirement  |
| #2219 | CLOSED | MEDIUM: NAT64 silently drops all ICMP error messages (only echo translated) -- breaks PMTUD and traceroute across NAT64 |
| #2220 | CLOSED | HIGH: cache-served session can expire while actively forwarding -- keepalive uses a binding-GLOBAL modulo-64 counter, no |
| #2221 | CLOSED | MEDIUM: same-generation install/delete reorder leaves a stale session on the standby (#2170 residual) |
| #2222 | CLOSED | HIGH: address-book address entry silently corrupted/overwritten when it also carries a description |
| #2223 | CLOSED | MEDIUM: redistribute export of a protocol-less policy-statement renders FRR-invalid "redistribute <policy>" line, degrad |
| #2224 | CLOSED | MEDIUM: flowexport ExportConfig copied by value carries a sync/atomic.Uint64 -- go vet failure + latent double-sampling |
| #2225 | CLOSED | LOW: VRRP data race on lastDropWarn (concurrent receiver() + receiverIPv6() on AF_PACKET fallback) |
| #2226 | CLOSED | LOW: rib-group import of an unknown rib resolves to table 0 and spuriously leaks the source table |
| #2229 | CLOSED | LOW: address-book entry with empty Value (prefix-less / sub-stanza-only) is not warn-flagged |
| #2234 | CLOSED | screen scan/sweep: per-zone source-table saturation can suppress detection (MINOR-2 from #2227) |
| #2237 | CLOSED | HIGH: locally-generated ICMP Time Exceeded lacks RFC error-suppression guards (replies to ICMP errors + non-first fragme |
| #2238 | CLOSED | MEDIUM: locally-generated replies (RST/ICMP-unreachable/Time-Exceeded/SYN-cookie) classified by the TRIGGER tuple, not t |
| #2239 | CLOSED | HA: DHCP-server leases are not synchronized across the chassis-cluster pair (local memfile only — failover drops/duplica |
| #2240 | CLOSED | HIGH: NPTv6 invalid-rule validation is fail-open (Go compiler + Rust) and DeleteStaleNPTv6 can tear down a working trans |
| #2241 | CLOSED | MEDIUM: NPTv6 overlapping /48+/64 prefixes use first-match insertion order (no LPM, no overlap rejection) -> order-depen |
| #2242 | CLOSED | LOW: locally-generated ICMPv6 errors quote only a fixed 48 bytes (below RFC 4443 useful payload) -- omits transport head |
| #2243 | CLOSED | DHCP server: no static/fixed/reserved binding support (no static-binding syntax, no Kea reservations emitted) |
| #2244 | CLOSED | LOW: publish_dnat_table_entry ignores bpf_map_update_elem return code -- silent reverse-NAT loss for embedded ICMP error |
| #2247 | CLOSED | NPTv6 fail-closed follow-ups (#2246 Copilot polish): warning wording, IPv4-mapped-v6 family parity, FEATURES.md |
| #2253 | CLOSED | LOW: rib-group import-rib resolution uses a loose .inet substring match (accepts malformed names like <vrf>.inetX.0) |
| #2255 | CLOSED | LOW: NAT translation-hit counter_id can be reused across a config reorder/removal (cumulative helper store → cross-rule  |
| #2258 | CLOSED | LOW: VRRP localIP/localIPv6 lazy-resolve write (run-loop) races the receiver reads |
| #2261 | OPEN | VALIDATION: live lease-survives-failover smoke for #2239 DHCP HA lease-sync (knob-ON, Kea memfile byte-exactness) |
| #2262 | CLOSED | LOW: #2239 DHCP-lease memfile-fallback read hardcodes IA_NA (mis-seeds a PD lease when Kea control socket is down) |
| #2268 | CLOSED | LOW: DHCP lease-sync IA_TA round-trip asymmetry — read path preserves IA_TA but pre-seed writer collapses it to IA_NA |
| #2270 | CLOSED | MEDIUM: broken ike-policy chain silently emits no proposals -> strongSwan negotiates with compiled-in defaults (silent c |
| #2271 | CLOSED | LOW: RA PrefixInformation can advertise PreferredLifetime > ValidLifetime (RFC 4861 violation) |
| #2272 | CLOSED | MEDIUM: RA WithdrawOnce check-and-act race can let a competing sender start on the same interface during withdraw |
| #2273 | CLOSED | LOW: routing clear() swallows per-family RuleList errors, can briefly orphan rules on transient netlink failure |
| #2274 | CLOSED | MEDIUM: dynamic-address feed prefixes are fetched but never materialized into policy/address compilation (feed feature i |
| #2279 | CLOSED | LOW: ipsec IKE-chain validator diagnostics + test-robustness polish (Copilot notes from #2277) |
| #2282 | CLOSED | MEDIUM: grpcapi input-validation gaps — Complete RPC negative Pos panics; ShowNAT int32 port-pool overflow |
| #2283 | CLOSED | MEDIUM: syslog client blocks the dataplane event hot-path (no write deadline) + reconnect thrash (no backoff) |
| #2287 | CLOSED | HIGH: #2285 syslog noteDrop slog.Warn-under-mu causes re-entrant deadlock via SyslogSlogHandler; write-timeout still rec |
| #2288 | CLOSED | MEDIUM: CLI tab-completion panics on slice bounds (completion.go cp[len(partial):]) + dead monitor 'match' regex field |
| #2290 | CLOSED | nat64: v6→v4 translation drops valid IPv6 traffic with extension headers (fixed offset 40, no ext-header walk) |
| #2291 | CLOSED | nat64: matched prefix with no usable source pool falls through to plain IPv6 routing instead of failing closed |
| #2292 | CLOSED | ipv6: forwarding ext-header walker surrenders open at the 6-header bound (returns proto=0) and diverges from the screen  |
| #2293 | CLOSED | screen: IPv6 ping-of-death is unimplemented and untracked (ping-death screen silently IPv4-only) |
| #2294 | CLOSED | vrrp: instance is never restarted when its interface ifindex changes under unchanged config (stale socket → permanent si |
| #2295 | CLOSED | LOW: SyslogSlogHandler calls goID() per record even with zero syslog clients (#2289 Copilot nits) |
| #2297 | CLOSED | HIGH: io_uring slow-path/state-writer leave SQE in-flight + unreaped CQE on submit_and_wait error (EINTR) -> stale-CQE o |
| #2298 | CLOSED | MEDIUM: scan-table-pressure ALARM emitted as DataplaneEventKind::ScreenDrop -> Go consumers count it as a screen drop +  |
| #2299 | CLOSED | MEDIUM: wireguard: wg_tcp_mss() has zero production callers -> WG-bound TCP SYNs get GRE-shaped MSS clamp (too high), fu |
| #2300 | CLOSED | MEDIUM: wireguard: TUN/control path + Go wgN default MTU hardcode 1500 while transit encap uses real egress MTU -> diver |
| #2301 | CLOSED | MEDIUM: generic forwarding has no egress-MTU decision -> oversized non-TCP/tunneled/seg-miss packets silently forwarded  |
| #2302 | CLOSED | MEDIUM: syslog reconnect cooldown bypassed when TCP dial succeeds but Write fails -> dial storm against the log target o |
| #2303 | CLOSED | LOW: GRE + WireGuard outer IP headers hardcode TOS/traffic-class=0 -> strips inner DSCP and ECN on tunnel encap (RFC 604 |
| #2312 | CLOSED | LOW: #2308 io_uring_write follow-ups — strengthen stale-CQE test + reconcile drain_stale/retry-ceiling docs |
| #2314 | CLOSED | LOW: locally-generated ICMP errors (PTB #2310, reject) not suppressed for multicast/broadcast destinations |
| #2315 | CLOSED | LOW: #2307 WireGuard ECN doc over-claims RFC 6040 'reflected at decap' (encap-copy only; no decap-side ECN combine) |
| #2317 | CLOSED | WireGuard decap-side RFC 6040 §4.2 ECN combine (outer→inner) — blocked on IP_RECVTOS/recvmsg recv loop |
| #2321 | CLOSED | LOW: #2319 parse_generated_v4/v6 fail-OPEN (unwrap_or((0,0))) on a TCP/UDP generated reply missing its port bytes — viol |
| #2325 | CLOSED | LOW: PTB (ICMP-error) suppression checks only L3 destination, not the L2 group/broadcast bit (reject/Time-Exceeded path  |
| #2327 | CLOSED | HIGH: userspace-dp tunnel endpoints are not kind-typed — GRE decap can match non-GRE rows; unknown modes fail open to GR |
| #2328 | CLOSED | HIGH: userspace-dp #2301 egress-MTU PTB replies bypass generated-reply output classification (#2238 contract) |
| #2329 | CLOSED | HIGH: userspace-dp TCP segmentation uses GRE inner-MTU math for WireGuard tunnels (split-brain vs #2299 mode-aware SYN c |
| #2330 | CLOSED | HIGH: userspace-dp #2301 PMTUD skips all post-transform size-changing paths (NAT64, GRE, WireGuard) |
| #2331 | CLOSED | MEDIUM/HIGH: userspace-dp native GRE encap emits DF-set oversized IPv4 outer frames (no outer-MTU guard) |
| #2332 | CLOSED | HIGH: userspace-dp heartbeat_fresh uses wall-clock (Utc::now) for HA worker liveness — clock step → spurious failover (R |
| #2333 | CLOSED | HIGH: NAT64 IPv6->IPv4 UDP checksum missing 0x0000->0xFFFF mapping (RFC 768/1624) — disables receiver validation |
| #2334 | CLOSED | MEDIUM: userspace-dp wg recvmsg cmsg buffer is 1-byte-aligned ([u8;256]) — cmsghdr field reads are unaligned (UB; SIGBUS |
| #2344 | CLOSED | HIGH: non-first fragments admitted to SessionFlow parser — payload bytes parsed as TCP/UDP ports (policy/flow-cache/sess |
| #2345 | CLOSED | HIGH/MEDIUM: inbound DNAT/NPTv6/NAT64 policy evaluated on ORIGINAL destination tuple while docs claim translated-destina |
| #2346 | CLOSED | MEDIUM: feature-gaps.md marks QinQ/flexible-VLAN 'Done' but userspace dataplane drops QinQ double-tag transit (config-pa |
| #2347 | CLOSED | HIGH: DHCP relay listener goes deaf on interface delete/recreate (stale SO_BINDTODEVICE ifindex) — DHCP-relay sibling of |
| #2348 | CLOSED | HIGH: DHCP relay config ignored on day-2 commits — not reconciled in daemon_apply.go (applied only at boot) |
| #2349 | CLOSED | LOW: persistent-SNAT sticky pool selection uses SHA-256 on the allocation path — replace with a fast non-crypto hash |
| #2354 | CLOSED | FEATURE: QinQ / stacked-VLAN (802.1ad S-tag + C-tag) transit in the AF_XDP dataplane |
| #2357 | CLOSED | userspace-dp: forwarded non-first IP fragments select CoS/fabric queue (and can hit output-filter terms) on payload-deri |
| #2358 | CLOSED | NAT64 inbound security policy matches the synthetic IPv6 destination, not the real internal IPv4 host (cross-family poli |
| #2360 | CLOSED | Stack OOB write: Rust BpfSessionValueV4/V6 are 8 bytes smaller than the Go-registered conntrack map value_size |
| #2361 | CLOSED | Live frame parser reads L4 ports outside the IP-declared packet (no total_len/payload_len bound) |
| #2362 | CLOSED | Userspace firewall-filter snapshot silently drops tcp-flags / is-fragment / icmp-type / icmp-code match terms |
| #2363 | CLOSED | Flow-cache insertion not gated by packet_eligible: a TCP control segment can seed a cache entry later ACKs reuse |
| #2364 | CLOSED | Hot-path hashes (flow-cache set index, fabric queue, session maps) are unkeyed FxHash — algorithmic-complexity hardening |
| #2367 | CLOSED | icmp: PTB suppression gate omits the bad-source-address check the reject/time-exceeded gate enforces |
| #2368 | CLOSED | ndp: NA learning skips RFC 4861 validity (Hop Limit 255 / Code 0 / checksum) and walks options past IPv6 payload_len |
| #2369 | CLOSED | arp: learn ARP sender only after validating htype/ptype/hlen/plen (opcode-2 at fixed offsets poisons neighbor cache) |
| #2370 | CLOSED | neighbor: key learned ARP/NDP dynamic neighbors by logical VLAN ifindex, not parent ifindex (forwarder lookup mismatch) |
| #2371 | CLOSED | nat64: update embedded transport checksum in ICMP error translation (RFC 7915 §5.2 conformance) |
| #2372 | CLOSED | daemon: reconcile LLDP service on day-2 config commits (currently boot-only, restart required) |
| #2374 | CLOSED | userspace-dp: fail closed (or recover frames) on partial initial fill-ring prime |
| #2375 | CLOSED | userspace-dp: expose pending_neigh capacity drops separately from duplicate drops |
| #2376 | CLOSED | userspace-dp: GRE decap stamps UDP/ICMP metadata for inners shorter than their L4 header |
| #2377 | CLOSED | vrrp: sendGARP gateway-probe target is wrong on subnets longer than /24 (assumes .1) |
| #2378 | CLOSED | slowpath: per-device rp_filter=0 ignored when conf/all/rp_filter is non-zero (silent reinjection drops) |
| #2379 | CLOSED | dhcpserver: splitV6Identity swallows IAID parse errors and silently returns IAID 0 |
| #2380 | CLOSED | config/nptv6: validate prefix host bits are zero (currently silently masked, no operator error) |
| #2381 | CLOSED | userspace-dp: bound event-stream write backlog when the daemon stops reading (unbounded heap growth) |
| #2382 | CLOSED | userspace-dp: count RT_FLOW replay-buffer eviction as telemetry loss |
| #2383 | CLOSED | userspace-dp: AF_XDP producer reservations (WriteTx/WriteFill) are not append-safe across multiple insert() calls |
| #2384 | CLOSED | config/vrrp: IPv6 VRRP groups not configurable (inet6 schema lacks vrrp-group; IPv6 VRRP engine unreachable) |
| #2385 | CLOSED | userspace-dp: IPsec passthrough check omits AH (proto 51) — host-terminated AH SAs silently broken |
| #2386 | CLOSED | dhcpserver: writeMemfile6 omits client hwaddr — DHCPv6 HA pre-seed strips MAC from v6 leases |
| #2387 | OPEN | userspace-dp: session/flow identity is the bare 5-tuple — omits logical ingress (VLAN/zone/VRF), cross-context session r |
| #2388 | CLOSED | userspace-dp: connected routes are not table-scoped in the Rust FIB — cross-VRF connected-route leak |
| #2389 | CLOSED | userspace-dp: ECMP static routes collapse to the first next-hop in the Rust FIB (no multipath, no dead-NH fallback) |
| #2390 | CLOSED | userspace-dp: static route preference (admin distance) dropped at the Go->Rust route snapshot boundary |
| #2391 | CLOSED | config/userspace-dp: zone IDs above the u8 wire limit are silently dropped to zone 0 instead of rejected at commit |
| #2392 | CLOSED | ipsec: ECP DH groups 19/20 render as invalid modp256/modp384 instead of ecp256/ecp384 — EC IKE/ESP proposals fail to loa |
| #2393 | CLOSED | userspace-dp: embedded-ICMP-NAT match omits ICMPv4 Redirect (type 5) — embedded inner not translated on NATed segments |
| #2394 | CLOSED | userspace-dp: DNAT source-address constraint lost at snapshot boundary (source-scoped DNAT becomes destination-only) |
| #2395 | CLOSED | userspace-dp: multiple DNAT destination-addresses collapse to the first address (bracket-list DNAT only installs one) |
| #2396 | CLOSED | userspace-dp: DNAT silently drops non-TCP/UDP protocols, ICMP IP-only DNAT, and invalid-address rules (fail-open, doc mi |
| #2397 | CLOSED | userspace-dp: persistent-NAT permit-any-remote-host=false ignored (lease keyed by local source only) |
| #2398 | CLOSED | userspace-dp: all-malformed SNAT match prefixes degrade to match-any (fail-open NAT broadening) |
| #2399 | CLOSED | userspace-dp: firewall-filter unknown action defaults to accept + unsupported protocol alias drops the protocol constrai |
| #2400 | CLOSED | userspace-dp: all-malformed firewall-filter addresses/ports degrade to match-any (fail-open filter broadening) |
| #2401 | CLOSED | userspace-dp: policy rules referencing unknown zones are kept-but-unindexed and silently fall through to the default act |
| #2402 | CLOSED | userspace-dp: HA session promotion swallows a poisoned shared-sessions lock (unwrap_or_default → empty), dropping all se |
| #2403 | CLOSED | frr: route-map next-hop renders IPv6 next-hops as 'set ip next-hop' (FRR syntax error; peer-address v6 rewrite missing) |
| #2404 | CLOSED | ipsec: responder-only/%any dynamic-IP gateways unconfigurable + dynamic-hostname gateway picks wrong local address famil |
| #2405 | CLOSED | nat64: ICMPv4 dest-unreachable code 14 (host precedence violation) dropped instead of mapped to ICMPv6 Parameter Problem |
| #2406 | CLOSED | userspace-dp: IPv6 SNAT66 reverse-NAT (dnat_table_v6) never published — inbound ICMPv6 PMTUD/traceroute blackholed |
| #2407 | CLOSED | userspace-dp: short-write retry loop corrupts packets on packet-oriented TUN fd (write_packet_sync + io_uring write_all  |
| #2408 | CLOSED | userspace-dp: slow-path TUN MTU never set (defaults to 1500) — jumbo frames dropped on the slow path |
| #2409 | CLOSED | userspace-dp: forwarding-build silently skips invalid interface addresses and unresolved CoS scheduler-map classes (sile |
| #2410 | CLOSED | userspace-dp: forwarding-build narrows VLAN/TTL/queue ids with unchecked 'as' casts (out-of-range wraps instead of faili |
| #2411 | CLOSED | userspace-dp: ICMP error suppression misses IPv4 directed/subnet broadcasts (RFC 1812 §4.3.2.7) — no per-interface prefi |
| #2412 | CLOSED | userspace-dp: local GRE tunnel-source thread busy-polls at 1ms (1000 wakeups/sec/tunnel) instead of blocking on readines |
| #2416 | CLOSED | NAT: match source-address-name (address-book) not resolved for DNAT/SNAT source scoping — fail-open |
| #2419 | CLOSED | parser: flat-set bracketed list value [ a b c ] collapses to first token (drops list members; dual-AST gap) |
| #2428 | CLOSED | userspace-dp: standby-node 'Current sessions' gauge underflows to a wrapped u64 (unbalanced create/close accounting) |
| #2438 | CLOSED | userspace-dp: WG TUN write paths (tunnel.rs, wg_control.rs) have the same short-write packet corruption as #2407 (non-bl |
| #2440 | CLOSED | userspace-dp: reconcile publishes new forwarding snapshot before required map-pin opens (partial-apply fail-open) |
| #2441 | CLOSED | userspace-dp: session timeout seconds multiplied to ns without overflow protection at snapshot boundary |
| #2442 | CLOSED | userspace-dp: session-delta ring overflow counts drops but never forces an HA resync |
| #2443 | CLOSED | userspace-dp: injected packet length unbounded — heap-alloc DoS + u16 wire-length wrap |
| #2444 | CLOSED | userspace-dp: conntrack/DNAT map opens are non-fatal even when the configured feature requires them |
| #2445 | CLOSED | wireguard: exact-duplicate AllowedIPs prefix across peers accepted — second peer silently unroutable |
| #2446 | CLOSED | userspace-dp: SYN-cookie validated-ACK cache survives zone profile semantic changes (master key stable) |
| #2447 | CLOSED | userspace-dp: CoS DSCP/PCP classifiers alias out-of-range values into valid queues at build time |
| #2448 | CLOSED | userspace-dp: malformed static route destination / next-hop silently dropped in Rust FIB builder |
| #2449 | CLOSED | userspace-dp: truncated ICMP/ICMPv6 packet matches firewall-filter icmp-type 0 / icmp-code 0 (type/code default to 0 wit |
| #2450 | CLOSED | dhcpserver: HA-takeover Kea memfile pre-seed written 0640 root:root — Kea (_kea) cannot open it → failover DHCP outage |
| #2451 | CLOSED | frr: multi-term policies render without on-match next — FRR stops at first matched term, skips later non-terminating ter |
| #2452 | CLOSED | daemon: IPv6 link-local static-route next-hop resolves to empty interface — FRR rejects scoped route |
| #2453 | CLOSED | ra: startLocked holds manager mutex across listen() 10x200ms bind retry (up to 2s) — stalls Withdraw/Apply on other inte |
| #2454 | CLOSED | frr/config: BGP group address-family flags copied to wrong-version neighbor — IPv4 neighbor activated under address-fami |
| #2455 | CLOSED | config/ipsec: isPlausibleHostname rejects valid trailing-dot absolute FQDN (vpn.example.com.) |
| #2456 | CLOSED | dhcprelay: backup-node relay forwards duplicate client requests upstream (no VRRP master-state gate) |
| #2457 | CLOSED | wireguard: advertised inner MTU not clamped to engine PADDED_PLAINTEXT_MAX (4096) on jumbo links |
| #2458 | CLOSED | userspace-dp: unknown (non-empty) CoS equal-flow target-policy silently defaults to Slowest instead of failing the snaps |
| #2460 | CLOSED | flowexport: userspace session-close deltas never reach NetFlow/IPFIX exporters (raw RT_FLOW SESSION_CLOSE never emitted) |
| #2461 | CLOSED | flowexport: per-flow-server NetFlow/IPFIX template binding parsed but ignored (uses first map entry) |
| #2462 | CLOSED | flowexport: multiple sampling instances flattened into one global rate/zone/collector policy |
| #2463 | CLOSED | flowexport: sampling-interface unit parsed by digit-extraction silently accepts malformed refs |
| #2464 | CLOSED | flowexport: collector UDP write failures are debug-only with no per-collector health stat |
| #2465 | CLOSED | flowexport: NetFlow/IPFIX flow start time guessed from packet count instead of real session-created timestamp |
| #2466 | CLOSED | userspace-dp: flow-cache RG epoch table fixed at 16 — RG IDs >= 16 skip per-RG failover invalidation (schema accepts the |
| #2467 | CLOSED | eventstream: session-event egress/TX ifindex encoded as i16 — high Linux ifindexes wrap negative |
| #2468 | CLOSED | session clear: CLI/gRPC report success while ignoring iterator/reverse/DNAT/peer-clear failures |
| #2469 | CLOSED | observability: REST/gRPC/Prometheus/CLI session views publish partial data as success on iterator error |
| #2470 | CLOSED | eventstream: RT_FLOW deny/screen/filter-log events emit timestamp_ns=0 (Go falls back to receive time) |
| #2471 | CLOSED | slowpath: TUN MTU ioctl failure still marks slow path active — jumbo frames drop while status says healthy |
| #2472 | CLOSED | userspace-dp: locally generated ICMP/RST error replies lack a per-reason/per-interface rate limiter |
| #2473 | CLOSED | frr: global BGP export policy rendered as 'redistribute' instead of peer-level 'route-map out' — OSPF/connected route le |
| #2474 | CLOSED | config: OSPFv3 interfaces lack BFD support (bfd-liveness-detection ignored; OSPFv2 has it) |
| #2475 | CLOSED | dataplane: proxy_arp/proxy_ndp sysctl never disabled on proxy-ARP config teardown (leaked over-broad ARP responder) |
| #2476 | CLOSED | vrrp: AF_PACKET receiver socket missing SOCK_CLOEXEC — raw packet fd leaks to exec'd children |
| #2477 | CLOSED | slowpath: io_uring->sync write fallback re-sends whole packet after a partial io_uring write — TUN double-transmission |
| #2478 | CLOSED | io_uring: reap_matching tight-spins (no yield) on permanent submit/wait errors — 100% CPU up to 4096 iters |
| #2479 | CLOSED | slowpath: set_if_up/set_if_mtu read errno after close() — wrong error reported on ioctl failure |
| #2480 | CLOSED | slowpath: open_tun(/dev/net/tun) missing O_CLOEXEC — TUN fd leaks to exec'd children |
| #2481 | CLOSED | userspace-dp: prime_fill_ring NAPI loop has no early-out when fully primed — up to ~20ms/queue avoidable bringup latency |
| #2482 | CLOSED | userspace-dp: dynamic neighbor probe has no SOCK_DGRAM fallback when CAP_NET_RAW is unavailable (rootless/container) |
| #2484 | CLOSED | userspace-dp: snapshot integrity error inside apply_snapshot fires after teardown (residual fail-open) |
| #2486 | CLOSED | userspace-dp: tcp-mss all-tcp / ipsec-vpn / gre-in accepted but never enforced (only tunnel egress clamps) |
| #2487 | CLOSED | userspace-dp: source_is_invalid_for_icmp_error misses subnet-directed broadcast source (Smurf backscatter; source siblin |
| #2488 | CLOSED | userspace-dp: NAT64 fragment translation non-compliant (RFC 7915) — IPv4 MF derived from config not packet; no v4->v6 Fr |
| #2489 | CLOSED | frr: VRF BGP neighbor BFD peer block omits 'vrf <name>' suffix — BFD session never binds, stays DOWN |
| #2490 | CLOSED | frr/config: BGP neighbor IMPORT policies unimplemented — inbound route filtering (route-map in) silently dropped |
| #2491 | CLOSED | config: static NAT lacks port / mapped-port forwarding (single-IP multi-service DNAT not expressible) |
| #2492 | CLOSED | rpm: malformed source-address not validated -> TCP/HTTP probes silently wildcard-bind |
| #2493 | CLOSED | rpm: hostname resolution not routing-instance/device scoped — DNS escapes the VRF for scoped probes |
| #2494 | CLOSED | rpm: ICMP probe drops IPv6 link-local zone — fe80:: targets unprobeable |
| #2495 | CLOSED | rpm: http-get scheme heuristic (url[0]!='h') breaks bare hostnames starting with 'h' |
| #2496 | CLOSED | rpm: routing-instance not validated against configured instances — typo -> permanent no-op probe |
| #2497 | CLOSED | ra: router-advertisement config leaves (prefix / PREF64 / preference / RDNSS / link-mtu) accepted untyped -> silently sk |
| #2501 | CLOSED | userspace-dp: AF_XDP forwarding keeps no per-session byte/packet counters (flow-export + show-session volume is zero) |
| #2505 | CLOSED | userspace-dp: firewall-filter parse_protocol stale — esp/ah/sctp/vrrp/igmp/pim/egp dropped -> protocol-unscoped match (f |
| #2506 | CLOSED | userspace-dp: firewall-filter source/destination-prefix-list references dropped from snapshot -> term loses address scop |
| #2507 | CLOSED | userspace-dp: firewall-filter 'then loss-priority' accepted but inert (no snapshot field, no warning) |
| #2508 | CLOSED | userspace-dp: per-policy 'then log session-init/session-close' flags never reach the policy snapshot (cannot honor per-p |
| #2509 | CLOSED | userspace-dp: pre-id-default-policy 'then log' flags have no userspace consumer after eBPF retirement (silently inert) |
| #2510 | CLOSED | eventstream: SessionCloseEvents/SessionCloseDrops (#2460) omitted from status/CLI/REST/Prometheus |
| #2511 | CLOSED | logging: production ProcessRawEvent/logEvent ignores nonzero wire timestamp (DecodeRawEventRecord honors it) — complemen |
| #2512 | CLOSED | userspace-dp: session-close RT_FLOW (type 14) bypasses the per-kind event rate limiter + drop accounting (bare try_send) |
| #2513 | CLOSED | logging: SESSION_CLOSE standard RT_FLOW line renders action=deny (close is not a deny decision) |
| #2514 | CLOSED | userspace-dp: address-book content-ID collision panics the daemon instead of returning a compile/apply error |
| #2515 | CLOSED | userspace-dp: reconcile no_snapshot teardown skips refresh_bindings -> stale binding status + stale CoS owner map |
| #2516 | CLOSED | vrrp: resolveIPv6LinkLocal vipSet keyed by un-normalized config string -> non-canonical fe80 VIP not excluded |
| #2517 | CLOSED | userspace-dp: GRE MSS clamp silently disabled on transient egress-MTU miss (unwrap_or_default vs WG's unwrap_or(1500)) |
| #2519 | CLOSED | fsatomic canary TestNoDirectOsWriteFile red on master — proxyarp writeProxyResponderSysctl not allowlisted |
| #2520 | CLOSED | userspace-dp: RT_FLOW cold-path emitters hardcode application_id=0 (deny/screen/filter-log/session-close show applicatio |
| #2521 | CLOSED | userspace-dp: firewall-filter 'then reject' is a silent drop (no ICMP/RST) unlike policy reject |
| #2522 | CLOSED | userspace-dp: reconcile teardown unconditionally sleeps 500ms on any live-worker rebuild (deterministic dataplane stall) |
| #2523 | CLOSED | userspace-dp: control-socket request read has no byte cap before read_line (local heap-growth DoS) |
| #2524 | CLOSED | config/userspace-dp: ring-entries has no maximum bound — large value drives OOM preallocation instead of a commit/startu |
| #2525 | CLOSED | frr: route-filter match-types prefix-length-range and through accepted but unimplemented — silent prefix-list degradatio |
| #2526 | CLOSED | flowexport: NetFlow v9 / IPFIX omit post-NAT addresses & ports (RFC 5103 fields 225-228) — no NAT correlation in flow lo |
| #2527 | CLOSED | rpm: runSingleTest fires pass/fail transitions inside the per-probe loop — route flapping mid-cycle on transient loss |
| #2528 | CLOSED | vrrp: cached localIP/localIPv6 never invalidated — no AddrSubscribe — stale source on interface addr change (split-brain |
| #2539 | CLOSED | frr: BGP export route-map-out render lacks isDefinedPolicyStatement guard — lenient-path dangling route-map out = permit |
| #2544 | CLOSED | firewall-filter: then next-term / modifier-only terms terminate as accept in userspace (fall-through bit dropped) |
| #2545 | CLOSED | firewall-filter: repeated protocol/dscp/icmp-type/icmp-code match values overwrite (scalar typed model, last-wins) |
| #2546 | CLOSED | routing: xfrmManager.Apply tears down and rebuilds all XFRM interfaces on every config commit |
| #2547 | CLOSED | frr: DHCPv4 default route omits interface binding (IPv6 binds, IPv4 does not) |
| #2548 | CLOSED | appid: protocol-only custom applications never match in tuple fallback (report UNKNOWN) |
| #2549 | CLOSED | ha: watchdog heartbeat issues full update_ha_state IPC every 500ms (control-socket contention) |
| #2550 | CLOSED | frr: BFD profiles collected per-VRF emit duplicate global bfd stanzas (no cross-instance dedup) |
| #2551 | CLOSED | lldp: ParseTLVs accepts truncated mandatory TLVs (empty Chassis/Port ID poisons neighbor cache) |
| #2562 | OPEN | userspace-dp: NAT64 non-first fragment translation needs a stateful frag-id→SNAT cache (deferred from #2488) |
| #2573 | CLOSED | userspace-dp: cached TX-selection records only the last counter for multi-count fall-through filters (follow-up #2544) |
| #2575 | CLOSED | ci/cos: apply-cos-config post-commit shaper/scheduler binding verify fails on loss cluster (reproduces on master, blocks |
| #2578 | CLOSED | appid: resolveTupleFallback should prefer port-based over protocol-only apps (deterministic specificity; follow-up #2548 |
| #2587 | CLOSED | config: pre-existing multi-value leaf silent-drop in OSPF/BGP/OSPFv3/IS-IS export-import + community members (route thro |
| #2593 | CLOSED | logging: standard SESSION_CREATE/SESSION_OPEN RT_FLOW line renders action=deny (same root cause as #2513) |
| #2596 | CLOSED | config/ipsec: isPlausibleHostname 253-byte cap runs before trailing-dot strip — max-length absolute FQDN over-rejected |
| #2604 | CLOSED | ipsec: DH groups 22/23/24 render as invalid modp22/modp23/modp24 — RFC 5114 IKE/ESP proposals fail to load |
| #2605 | CLOSED | config: traffic sampling output source-address at standard Junos location silently ignored |
| #2606 | CLOSED | dhcprelay: DHCPNAK server responses silently dropped — clients hang until timeout (RFC 2131) |
| #2607 | CLOSED | frr: mixed IPv4/IPv6 route-filter policy term emits only one family's match line — other family silently fails to match |
| #2608 | CLOSED | control-sockets: AF_PACKET/raw-ICMP/UDP control sockets missing SOCK_CLOEXEC across LLDP, cluster GARP/NDP, HA fabric pr |
| #2609 | CLOSED | flowexport: IPFIX template-refresh header resets SequenceNumber to 0 (RFC 7011 violation) — collectors report false drop |
| #2610 | CLOSED | snmp: SNMPv3 USM has no timeliness/replay protection; engineBoots resets to 1 every restart |
| #2611 | CLOSED | snmp: SNMPv3 contextEngineID/contextName decoded then ignored — non-default context served default MIB data |
| #2612 | CLOSED | snmp: GETBULK response size not bounded by msgMaxSize/maxPacketSize — oversized UDP datagrams instead of trim/tooBig |
| #2613 | CLOSED | flowexport: NetFlow/IPFIX templates advertise TOS/TCPFlags/Direction/InIf/OutIf but close records leave them zero — coll |
| #2614 | CLOSED | rpm: probe target hostname resolution escapes VRF/routing-instance context (uses default-namespace DNS) |
| #2615 | CLOSED | eventstream: RT_FLOW SESSION_CREATE/CLOSE logs omit AppID (create) and ingress ifindex (create+close) — render UNKNOWN / |
| #2616 | CLOSED | userspace-dp: firewall-filter fall-through log records placeholder Accept, not the final terminal action — RT_FLOW says  |
| #2617 | CLOSED | userspace-dp: accepted input-filter 'then log' not emitted on session-miss packet — only replayed on flow-cache hits; un |
| #2618 | CLOSED | userspace-dp: input-filter log-only helper returns first fall-through log term, diverging from full evaluator's latest-m |
| #2619 | CLOSED | userspace-dp: PBR/routing-instance evaluator drops fall-through 'then log' metadata before the routing-instance term |
| #2620 | CLOSED | userspace-dp: PBR session-miss path double-counts pre-PBR fall-through 'then count' (non-PBR precheck + PBR evaluator bo |
| #2621 | CLOSED | userspace-dp: input-filter forwarding-class/DSCP/policer modifiers before a routing-instance term dropped by split PBR/n |
| #2622 | CLOSED | config/userspace-dp: firewall filters lack source-port-except / destination-port-except / packet-length match conditions |
| #2623 | CLOSED | cluster: GARP/NDP burst follow-up sends ignore errors — logs report total=count while only the first frame may have been |
| #2624 | CLOSED | userspace-dp: MQFQ V_min cadence filter defeated — v_min_pop_count resets to 0 every drain call, forcing a full peer-slo |
| #2625 | CLOSED | vrrp: Manager is not Stop/Start reuse-safe — closed watcherStop + un-reset latches permanently disable link/addr watcher |
| #2630 | CLOSED | config: flat-set 'route-filter' repeated keys collapse — second set line overwrites the first in tree.SetPath |
| #2639 | CLOSED | config/ipsec: Phase 2 IPsec proposal dh-group fails to parse "groupN" suffix (Atoi("group14") fails -> PFS dropped) |
| #2640 | CLOSED | snmp: SNMPv3 AES-128 decryption IV built from local engineBoots/Time instead of received USM values (RFC 3826 violation  |
| #2641 | CLOSED | config: duplicate named policy-options prefix-list blocks overwrite instead of merge (community blocks already merge) |
| #2642 | CLOSED | config: routing policy-term 'from prefix-list/community/as-path' are single-string fields — multiple match statements ov |
| #2643 | CLOSED | frr: named BGP community-lists with wildcard/regex members rendered as 'community-list standard' -> FRR config load fail |
| #2644 | CLOSED | vrrp: IPv6 advert checksum computed over getLocalIPv6() but socket sends with kernel-selected source -> checksum mismatc |
| #2645 | CLOSED | dhcprelay: server-reply switch drops DHCPFORCERENEW (type 9) -> relay never forwards FORCERENEW to clients (RFC 3203) |
| #2646 | CLOSED | userspace-dp/cos: V_min cadence counter advances before a confirmed pop — no-budget/mirror-reserve breaks burn cadence p |
| #2647 | CLOSED | rpm: ICMP probe hostname resolution ignores probe context — uses context.Background(), can outlive a canceled cycle (TCP |
| #2648 | CLOSED | dhcpserver/ddns: default replace-owned sends bare RFC2136 add with no ownership proof — can adopt then delete a pre-exis |
| #2649 | CLOSED | snmp: corrupt/unreadable/ceiling engineBoots state silently resets to 1 with the same deterministic engineID (fail-open  |
| #2650 | CLOSED | dhcpserver/ddns: corrupt/unknown-version ownership state fail-opens to empty -> previously-owned DNS records never withd |
| #2651 | CLOSED | userspace-dp: WG IPv6 outer UDP checksum uses scalar udp6_checksum loop instead of the AVX2 checksum16_ipv6 helper (per- |
| #2652 | CLOSED | userspace-dp: flow cache excludes NAT64 and NPTv6 — every translated packet takes the slow path (no RewriteDescriptor fa |
| #2653 | CLOSED | userspace-dp: single-shot ExportOwnerRGSessions pushes unbounded into the 4096 delta ring (same overflow class as #2442, |
| #2660 | CLOSED | dhcpserver/ddns: skip-existing conflict records ownership for a record xpf never created |
| #2661 | CLOSED | dhcpserver/ddns: forward A/AAAA orphaned when reverse PTR update fails after forward succeeds |
| #2662 | CLOSED | dhcpserver/ddns: ownership persisted only at end of reconcile pass — crash after a DNS add but before state.save() orpha |
| #2663 | CLOSED | dhcpserver/ddns: no per-interface or independent IPv4/IPv6 DDNS policy (single global config; ownership keys lack scope) |
| #2664 | CLOSED | daemon/ddns: node-level HA writer gate can publish stale DDNS rows for an RG the node no longer owns |
| #2665 | CLOSED | dhcpserver/ddns: RFC2136 updates cannot be source-bound to an interface/VRF/source-address (multi-WAN parity) |
| #2666 | CLOSED | config/ddns: incomplete TSIG tuple (key without secret, or secret without key) commits and fails only at runtime |
| #2667 | CLOSED | docs/ddns: types_system.go + schema_system.go + config-schema.md still say RFC2136 backend is deferred/config-only after |
| #2668 | CLOSED | dhcpserver: Kea subnet IDs assigned over randomized Go map iteration — IDs shift on config reload and remap active lease |
| #2669 | CLOSED | userspace-dp: session deltas drained but silently discarded when bindings is empty (flush_session_deltas gated on bindin |
| #2676 | CLOSED | dhcpserver/ddns: skip-existing PTR-side conflict-refusal after a forward success orphans the forward (sentinel ordering) |
| #2679 | CLOSED | ddns: no router/interface-address Dynamic DNS (publish the firewall's own WAN/HA addresses) — vSRX parity |
| #2680 | CLOSED | userspace-dp: WG encap MTU guard compares outer encapped size against the tunnel LOGICAL ifindex MTU, not the physical e |
| #2681 | CLOSED | snmp: SNMPv3 agent accepts invalid noAuthPriv security level (priv flag set, auth flag clear) — decrypts and executes wi |
| #2684 | CLOSED | userspace-dp: WG/GRE DF/IPv6 PTB under-advertises inner PMTU by ~one encap overhead (logical-MTU SSOT) |
| #2689 | CLOSED | config: policy-statement 'from community' / 'from prefix-list' bracket-list collapses (multi:true reader reads only Keys |
| #2691 | CLOSED | DDNS: world-class redesign — provider abstraction + WAN/interface-address + DHCP-lease publish (inadyn-inspired) |
| #2699 | CLOSED | ddns: deleteOwnedLocked drops ownership through nopUpdater after restart, orphaning live RFC2136 records |
| #2700 | CLOSED | ddns/rfc2136: shared DHCID deleted on partial dual-stack teardown leaks remaining record + leaves FQDN unprotected |
| #2701 | CLOSED | wireguard: WG transit sources outer IP from logical tunnel ifindex, not the resolved physical egress (blackhole / wrong  |
| #2702 | CLOSED | bgp: group/neighbor import/export bracket-lists truncate to the first policy (nodeVal-first masks Keys[1:] fallback) |
| #2703 | CLOSED | userspace-dp: tunnel TTL=0 sentinel (meaning 'default 64') not honored — GRE/WG transit emits outer TTL 0 (blackhole) |
| #2704 | CLOSED | cos: undefined forwarding-class in DSCP/802.1p classifiers + DSCP rewrite rules silently crosses the wire and no-ops (sc |
| #2705 | CLOSED | userspace state_writer: deterministic temp path allows cross-writer/cross-process snapshot corruption |
| #2706 | CLOSED | userspace forwarding-build: interface MTU not validated — negative coerces to 0 (disables egress MTU enforcement instead |
| #2707 | CLOSED | vrrp: addrwatch matches by cached ifindex — misses address events on a recreated link until the ~2s reconcile re-binds |
| #2708 | CLOSED | ddns: PTRPending persisted but not exposed per owned record (no current-pending gauge, only a lifetime counter) |
| #2714 | CLOSED | state_writer: stale <dest>.<pid>.<seq>.tmp orphans leak on crash-between-create-and-rename (needs concurrency-safe start |
| #2719 | CLOSED | REGRESSION (#2467): pkg/daemon eventstream wiring test red on master — TestWireUserspaceEventStreamCallbacksStandaloneWi |
| #2726 | CLOSED | DDNS Surface A SkippedNoBackend not surfaced (Prometheus/CLI/gRPC) + stale outer-MTU docstring (#2691 integration-audit  |
| #2733 | CLOSED | session clear: NAT'd-session reverse companion leaked — clear deletes naive-swap key, not val.ReverseKey (translated tup |
| #2734 | CLOSED | userspace-dp: ECMP is per-destination, not per-flow — plumb the 5-tuple flow hash to FIB next-hop selection |
| #2744 | CLOSED | userspace-dp: control-socket 16 MiB cap can reject a legitimate feed-heavy apply_snapshot; needs feed-dimension sizing + |
| #2749 | CLOSED | flowexport: populate TOS/TCPFlags/Direction/InIf/OutIf via a SESSION_CLOSE wire-format extension |
| #2757 | CLOSED | ipsec: dynamic-hostname gateway picks wrong local-address family on dual-stack (defect #2 of #2404) |
| #2769 | CLOSED | static-nat: 'match destination-port' without 'mapped-port' broadens reverse SNAT to whole-host |
| #2770 | CLOSED | ddns/cloudflare: Surface A withdraw deletes first name/type record, not the exact owned content |
| #2771 | CLOSED | ddns/route53: already-gone DELETE wedges Surface A ownership (not idempotent like rfc2136) |
| #2772 | CLOSED | ddns/http: dyndns2 + generic withdraw is a no-op that reports success and drops ownership |
| #2773 | CLOSED | ddns/checkip: validateCheckIPURL is dead code — malformed checkip-url commits and silently suppresses publishing |
| #2774 | CLOSED | ddns/checkip: public-address gate misses several IANA special-purpose IPv4 ranges |
| #2775 | CLOSED | ddns/surface-a: interface address selection ignores IPv6 preferred/deprecated/tentative state |
| #2776 | CLOSED | ddns/surface-a: static address fallback can publish multicast/reserved addresses (predicate not shared with netlink path |
| #2778 | CLOSED | ddns/surface-a: provider I/O (Upsert/Delete, 15s timeout) runs under the global manager mutex |
| #2779 | CLOSED | ddns/surface-a: operator hostnames silently sanitized to a different DNS name (no commit error) |
| #2780 | CLOSED | ddns/surface-a: per-interface dynamic-dns source-address is free-form, unvalidated at commit; bad value silently disable |
| #2781 | CLOSED | config/ddns: DDNSProvider.String() leaks url-template and checkip-url verbatim (credentials in query/userinfo) |
| #2782 | CLOSED | userspace-gre: native decap silently drops checksum-present GRE packets (uncounted None) |
| #2783 | CLOSED | userspace-ptb: egress MTU decision uses frame buffer length while PTB builders quote IP-declared length |
| #2785 | CLOSED | ha/session-sync: per-policy log flags not carried on the userspace session-sync wire (synced sessions log nothing after  |
| #2786 | CLOSED | vrrp: IPv6 raw socket binds SO_BINDTODEVICE unconditionally on VLAN sub-interfaces (IPv4 path skips it) — IPv6 advert dr |
| #2787 | CLOSED | dhcp-relay: transient socket bind/listen failure permanently kills the per-interface supervisor goroutine |
| #2788 | CLOSED | vrrp: address watcher ignores netlink events for an instance whose interface appears after VRRP start (vi.iface==nil) —  |
| #2789 | CLOSED | dhcp-relay: DHCPDECLINE not relayed to server — server never learns of client-detected IP conflicts |
| #2790 | CLOSED | userspace-dp: learned ARP replies inserted into neighbor cache without IP validation (multicast/broadcast/loopback/zero  |
| #2791 | CLOSED | frr/bgp: global ECMP max-paths unintentionally enables BGP multipath (maximum-paths) even when bgp multipath is disabled |
| #2792 | CLOSED | userspace-dp: WireGuard egress fast-path allocates two heap Vecs per packet (wg_encap_frame) |
| #2794 | CLOSED | userspace-dp: reconcile !should_run_afxdp early path leaves the same stale binding fields #2515 fixed on no_snapshot |
| #2813 | CLOSED | ddns/surface-a: failing withdraw retries every sweep with no per-scope backoff (log spam) |
| #2823 | CLOSED | config/nat: persistent-nat permit models only any-remote-host (binary) — no target-host vs target-host-port scoping |
| #2834 | CLOSED | pkg/ra: config replace leaves 0 live RA connections (TestT2a_ChangedConfigApplyNeverTwoLiveConns fails on master) |
| #2836 | CLOSED | userspace-dp WG: peer-table snapshot is not atomic for mutable peer fields (endpoint/keepalive/PSK), violating the docum |
| #2837 | CLOSED | userspace-dp WG: outer-source/MTU re-resolution drops the known physical tx_ifindex and falls back to the logical wg ifi |
| #2838 | CLOSED | DDNS generic backend: substring success matcher turns explicit provider failures into false successes (default set conta |
| #2839 | CLOSED | DDNS: ParseAllowlist silently drops malformed bogus-IP tokens with no commit-time warning, weakening the checkip safety  |
| #2840 | CLOSED | DDNS interface-address observation publishes the configured static address when the kernel link cannot be read, contradi |
| #2841 | CLOSED | DDNS generic url-template validation is prefix-only (no host/parse check), accepting malformed URLs until runtime publis |
| #2842 | CLOSED | DDNS checkip URL validation rejects valid uppercase schemes (HTTPS://) — URL schemes are case-insensitive (RFC 3986 §3.1 |
| #2843 | CLOSED | DDNS Surface A status omits configured scopes that have never successfully published (no row until first publish; errSur |
| #2844 | CLOSED | userspace-dp NAT64 retains a private write_eth_header (hardcoded 0x8100) outside the shared TxVlanTag frame module — SSO |
| #2845 | CLOSED | userspace-dp WG PTB inner-MTU assumes one underlay MTU per wg endpoint (uses first peer endpoint); two peers with asymme |
| #2846 | CLOSED | DDNS: source-address/destination-interface/routing-instance binding only reaches RFC2136; HTTP backends (Cloudflare/Rout |
| #2847 | CLOSED | FRR policy render: 'set metric N' is gated by term.Metric > 0, so a metric/MED of 0 is silently dropped |
| #2848 | CLOSED | BGP policy-options: no additive/delete community operations — only whole-attribute replace (set community) is generated  |
| #2849 | CLOSED | DHCP relay: defaultIfaceResolver/interfaceIPv4 returns the FIRST kernel IPv4 address as giaddr, not the primary — second |
| #2850 | CLOSED | VRRP: no preempt hold-time/delay (preempt is a bare boolean) — instant preemption on recovery can blackhole before routi |
| #2851 | CLOSED | userspace-dp neighbor learning: dynamic ARP/NDP learning does not reject the router's own configured IPs — unsolicited r |
| #2852 | OPEN | userspace-dp NAT: PortAllocator serializes all fast-path SNAT allocations on one global Mutex — destroys multi-core scal |
| #2853 | CLOSED | userspace-dp/flowexport: session creation time truncated to integer seconds — IPFIX/NetFlow flowStart* lose sub-second r |
| #2857 | CLOSED | pkg/frr: route-map set local-preference 0 silently dropped (same 0-is-valid bug as #2847 metric) |
| #2864 | CLOSED | Static NAT DNAT: port-specific zone mismatch returns None and skips whole-address fallback |
| #2865 | CLOSED | RA: sender whose openConn() fails stays in m.senders as a dead entry; config-unchanged reconciles never restart it |
| #2866 | CLOSED | NetFlow v9 / IPFIX: SrcMask / DstMask export fields are always 0 (every flow reported as /0) |
| #2867 | CLOSED | VRRP: cluster GARP/NA burst follow-up loops keep poisoning neighbor caches after a MASTER→BACKUP transition (no epoch/st |
| #2868 | CLOSED | eventengine: remediation commit uses context.Background() — cannot cancel on daemon shutdown, blocks clean stop |
| #2869 | CLOSED | eventengine: supersede() prepends the new action ahead of survivors, turning the FIFO action queue into LIFO (older-poli |
| #2870 | CLOSED | VRRP: AF_PACKET receiver uses PACKET_MR_PROMISC instead of joining VRRP multicast groups — pulls all segment traffic to  |
| #2871 | CLOSED | Static NAT SNAT (reverse) ignores zone — outbound east-west traffic from a static-NAT internal IP is source-translated t |
| #2874 | CLOSED | userspace-dp HA session-sync: open/close deltas use lossy push_delta; Go ACKs over the gap, trimming the replay window ( |
| #2875 | CLOSED | userspace-dp event-stream: paused demotion drain can evict session deltas at REPLAY_BUFFER_CAPACITY yet still report Dra |
| #2876 | CLOSED | userspace-dp/Go demotion drain: DrainComplete with seq < targetSeq is accepted as success (helper timeout below fence si |
| #2877 | CLOSED | userspace-dp event-stream: replay/drain use blocking write_all with no deadline — a stuck daemon reader can wedge helper |
| #2879 | CLOSED | userspace-dp event-stream: daemon-to-helper control frames have no payload-length cap — partial-frame buffering grows ct |
| #2880 | CLOSED | userspace-dp ha.rs: purge_remapped_tunnel_sessions silently swallows push_delta_lossless errors (let _ =) — error-hygien |
| #2881 | CLOSED | config/frr: no commit-time validation that 'from community <name>' / 'then community delete <name>' references a defined |
| #2882 | CLOSED | userspace-dp event-stream: handle_drain_request writes/reports beyond the requested target_seq (no <= target filter) — c |
| #2883 | CLOSED | userspace-dp event-stream: idle keepalive uses write_all on the nonblocking socket — WouldBlock is treated as a fatal er |
| #2884 | CLOSED | IPsec: interface IP change at runtime (DHCP renew / flap) does not re-render swanctl local_addrs — ExternalIface-bound g |
| #2885 | CLOSED | IPsec: matchFamily rejects IPv6 link-local (fe80::/10) via IsGlobalUnicast() — cannot source IPsec SAs from link-local o |
| #2886 | CLOSED | VRRP IPv4 raw-socket fallback: ReadFrom discards the ControlMessage and only filters on VRID — two VLAN sub-interfaces w |
| #2888 | CLOSED | DHCP relay: server-facing socket binds giaddr:0 (ephemeral) — RFC 2131 strict servers reply to giaddr:67 (BOOTPS), which |
| #2889 | CLOSED | FRR neighbor password is emitted unquoted — a BGP/dynamic-routing password containing spaces breaks vtysh parsing (confi |
| #2890 | CLOSED | eventengine runAction retry uses time.After in a select with stopCh — leaks an active timer per retry until the backoff  |
| #2891 | CLOSED | FRR backup-router: IPv6 BackupRouter with empty BackupRouterDst defaults to 0.0.0.0/0 → emits 'ip route 0.0.0.0/0 <ipv6> |
| #2892 | CLOSED | BGP policy-options: no 'set as-path prepend' action — AS-path prepending unsupported (vSRX parity gap) |
| #2898 | CLOSED | cluster/daemon: direct-mode directSendGARPs inner-burst loop is ungated — abdication mid-burst can re-poison (sibling of |
| #2900 | CLOSED | VRRP: armed preempt hold-timer is not re-validated on config-update or at expiry (preempt-disable / priority-demotion mi |
| #2901 | CLOSED | DDNS: source-binding dialer ignores socket family — IPv4 source-address binds on an IPv6 dial (and vice-versa), failing  |
| #2902 | CLOSED | BGP policy: 'then community delete [ list1 list2 ]' silently drops all but the first community-list (only vals[1] stored |
| #2903 | CLOSED | DDNS Surface A: changing only the FQDN for a scope is not detected as a change — new name never published AND old name o |
| #2904 | CLOSED | DDNS Surface A: HTTP client/transport rebuilt every reconcile (resolve-per-Reconcile) — no connection-pool reuse, full T |
| #2905 | CLOSED | NAT: dynamic SNAT port allocator serializes all packet workers on a single global Mutex<PortAllocatorLiveState> in the f |
| #2908 | CLOSED | frr: writeManagedSection markerEnd lookup is unbounded — a stale end-marker BEFORE the begin-marker duplicates config |
| #2909 | CLOSED | ipsec: XFRMIfNameAndID collides bare 'st0' with 'st0.0' — duplicate xfrm if_id, EEXIST / cross-VPN leak |
| #2910 | CLOSED | wg: native decap rejects non-zero AEAD padding (inner_ip_len_after_decap) — interop hazard vs kernel WG / wireguard-go |
| #2911 | CLOSED | config/frr: commit-time reject backup-router with explicit destination whose family mismatches the next-hop |
| #2912 | CLOSED | slowpath: fixed-window RateLimiter permits 2x burst across window boundary — use token bucket / sliding window |
| #2915 | CLOSED | userspace-dp: Rust queue planner ignores the binding exclusion contract (mgmt/control/tunnel/fabric) used by the Go allo |
| #2916 | CLOSED | userspace-dp: same-plan snapshot refresh can skip a required queue replan because the binding-plan hash and queue planne |
| #2917 | CLOSED | userspace-dp: VLAN unit AF_XDP binding target disagrees between Go allowlist (parent netdev) and Rust planner (unit netd |
| #2918 | CLOSED | userspace-dp neighbor monitor: initial dump consumes and drops seq-0 multicast RTM_NEWNEIGH/DELNEIGH events |
| #2919 | CLOSED | userspace-dp neighbor monitor: failed initial dump is published as generation 1 (treated as a valid baseline) and never  |
| #2921 | CLOSED | userspace-dp WG: local TUN-origin egress keeps a stale captured outer_mtu after underlay route/table/MTU changes (same-e |
| #2922 | CLOSED | userspace-dp ECMP: select_route_next_hop evaluates the dynamic-neighbor liveness closure twice (count + nth), creating a |
| #2923 | CLOSED | userspace-dp ECMP: tunnel next-hop candidates are filtered as dead by the direct-neighbor liveness predicate, starving m |
| #2926 | CLOSED | eventengine: thread ctx into applyConfigLocked so a daemon-stop cancels post-applySem commit work (FRR/netlink/Rust sync |
| #2930 | CLOSED | HA session-sync: EventStream seq-fenced DrainRequest/DrainComplete pair is dormant (no production caller) — wire it into |
| #2933 | CLOSED | config: commit-time reject ambiguous secure-tunnel bind-interface aliases (st0 vs st0.0) that derive the same XFRM if_id |
| #2934 | CLOSED | REST security API: invalid zone/dst_port filters fail-open to 'no filter' (cross-zone observability leak) |
| #2935 | CLOSED | REST session protocol filter is case-sensitive and rejects numeric protocols (diverges from gRPC/CLI) |
| #2936 | CLOSED | Session aggregation (security log report) is unbounded by host cardinality — control-plane DoS amplifier |
| #2937 | CLOSED | Screen flood + SYN-cookie standby-ACK rate limiting uses fixed wall-second windows (2x boundary burst) |
| #2938 | CLOSED | NAT pool stats (REST/gRPC/CLI/Prometheus) compute capacity from config text + legacy counter, not userspace runtime stat |
| #2939 | CLOSED | REST event filter uses substring matching for protocol/action — ambiguous forensic queries (protocol=C matches TCP+ICMP) |
| #2940 | CLOSED | VRRP strict-VIP: SetGARPSuppression(false) does not emit a GARP/NA burst when already StateMaster — VIP blackhole on pro |
| #2941 | CLOSED | FRR BGP render: IPv6 neighbor address with a policy but no 'family inet6' is activated under address-family ipv4 unicast |
| #2942 | CLOSED | FRR IS-IS render: interface-scoped 'isis bfd' emitted AFTER the interface 'exit' — lands in global scope, fails frr-relo |
| #2943 | CLOSED | FRR render: redistribute does not exclude the active protocol (self-redistribution) and lacks ospf6/ripng keywords |
| #2944 | CLOSED | VRRP link watcher matches tracked interfaces by name — a runtime kernel rename leaves stale (up) tracking state |
| #2949 | CLOSED | api/cli: REST protoName renders fewer named protocols than gRPC (gre/esp/ipip/ipv6 missing) — protocol=gre named filter  |
| #2955 | CLOSED | userspace-dp: generated-error token bucket split-atomic race can over-admit ICMP errors under multi-worker contention |
| #2956 | CLOSED | ddns: CloseIdleConnections on superseded http-client cache entries (transport not reaped on binding change) |
| #2957 | CLOSED | userspace-dp state_writer: orphan-temp sweep keyed on bare PID liveness — PID reuse pins stale temps indefinitely |
| #2958 | CLOSED | userspace-dp state_writer: runtime io_uring write failure never demotes WriteMode — status lies and every write pays a f |
| #2959 | CLOSED | userspace-dp event-stream: MSG_ACK watermark accepted without validation — future/backward ACK trims replay past unsent  |
| #2960 | CLOSED | ddns: built-in 'duckdns' dyndns2 provider alias is not DuckDNS-protocol-compatible (wrong params, auth, success keyword, |
| #2961 | CLOSED | userspace-dp WG: permanently-down persistent-keepalive peer enters a zero-cooldown 90s handshake-storm loop (give-up doe |
| #2962 | CLOSED | userspace-dp HA: export_owner_rg_sessions blocks up to 15s holding the global ServerState lock — a slow worker freezes t |
| #2963 | CLOSED | config/frr: BGP neighbor with no peer-as renders 'remote-as 0' (reserved AS) — no commit-time validation, FRR config loa |
| #2969 | CLOSED | userspace-dp neighbor probe: IPv6 link-local NDP probe omits sin6_scope_id and swallows sendto failures |
| #2970 | CLOSED | userspace-dp helper lowers rmem sysctls to 16 MiB on start, undoing Go's 64 MiB AF_XDP tuning (host-global) |
| #2971 | CLOSED | ddns/surface-a: corrupt/unreadable ownership state fail-opens to empty store (bypasses the #2650 degraded/quarantine pat |
| #2972 | CLOSED | ddns/surface-a: RG0/non-HA scopes can be double-written by every node master for any RG in active-active HA |
| #2973 | CLOSED | userspace-dp screen: source-route check drops ALL IPv4-options packets and ignores IPv6 Routing Headers (vSRX parity + f |
| #2974 | CLOSED | userspace-dp helper blindly unlinks configured control/session socket paths without verifying they are stale sockets |
| #2975 | CLOSED | ddns/surface-a: selectInterfaceAddr does not skip IFA_F_TEMPORARY — publishes RFC 4941/8981 privacy address to public DN |
| #2977 | CLOSED | frr/policy: 'then next-hop self' compiles to a silent no-op — iBGP/RR routes keep the eBGP next-hop (blackhole) |
| #2978 | CLOSED | frr/bgp: multipath renders only 'maximum-paths N' (eBGP-only) — iBGP ECMP never enabled (missing 'maximum-paths ibgp N') |
| #2979 | CLOSED | userspace-dp NAT: dynamic reverse-NAT dnat_table / dnat_table_v6 entries leak on session close/expiry (HASH map fills to |
| #2980 | CLOSED | config: no commit-time validation that BGP/OSPF/OSPFv3 router-id is a valid IPv4 dotted-quad — malformed value breaks FR |
| #2981 | CLOSED | userspace-dp CoS: V_min lag threshold floors at 24 KB for UNSHAPED shared-exact queues — spurious throttling at high lin |
| #2986 | CLOSED | networkd: opposite-family DHCP suppresses static addresses (DHCPv4+static IPv6 / DHCPv6+static IPv4 not installed) |
| #2987 | CLOSED | networkd: generated .link/.network write failures are swallowed — commit succeeds with stale kernel config |
| #2988 | CLOSED | networkd: empty managed-interface set returns early, skipping stale 10-xpf-* file cleanup |
| #2989 | CLOSED | snmp: v2c trap community selected via nondeterministic Go map iteration — multi-community traps are flaky |
| #2990 | CLOSED | snmp: trap-group schema has children:nil — typoed child keys (e.g. 'tragets') commit silently as zero-target trap groups |
| #2991 | CLOSED | snmp: trap delivery is synchronous in the netlink link-state monitor — a slow/FQDN trap target stalls link processing |
| #2992 | CLOSED | lldp: RX path discards AF_PACKET sockaddr metadata — locally-transmitted LLDP frames (PACKET_OUTGOING) are learned as ow |
| #2993 | CLOSED | feeds: a feed body mixing valid + invalid lines installs a partial set and reports success (no invalid-line counter / de |
| #2994 | CLOSED | dhcp: T1/T2 renewal runs full DORA / Rapid-Solicit reacquisition instead of RFC unicast Renew/Rebind (vSRX parity) |
| #2995 | CLOSED | userspace-dp WG: sockaddr_storage_to_socketaddr drops sin6_scope_id/flowinfo — link-local WG peer endpoints fail to send |
| #2996 | CLOSED | pkg/daemon RA: configured link-local source detection only checks Units[0] — RA on a subinterface/non-zero unit misses i |
| #2997 | CLOSED | frr: OSPFv3 (router ospf6) omits 'maximum-paths' — IPv6 OSPF ECMP never enabled even when forwarding-table ECMP > 1 |
| #2998 | CLOSED | frr: policy-statement with no explicit default action renders route-map 'deny' — diverges from Junos BGP default-permit  |
| #3007 | CLOSED | queue-planner: rx_queues==0 sysfs fallback can yield same plan-key but different layout (out-of-band ethtool -L channel  |
| #3008 | CLOSED | userspace-dp filter: meta-only term_match_extra_from_meta sets l4_present=true with icmp_type/code=0 — false-matches icm |
| #3009 | CLOSED | userspace-dp state_writer: instance_is_alive self-process shortcut checks PID only — bypasses start_time, pins stale tem |
| #3010 | CLOSED | proxy-ARP/NDP: proxyARPIfaceMap resolves VLAN subinterface entries to the PARENT ifindex — sysctl/NTF_PROXY installed on |
| #3011 | CLOSED | userspace-dp NAT: SNAT port recycling is LIFO (Vec push/pop at back) — favors 2MSL/TIME_WAIT port-reuse collisions; pref |
| #3012 | CLOSED | dhcp-relay: client/server UDP reads use a fixed 1500-byte buffer — datagrams >1500B (large option sets / jumbo-MTU links |
| #3013 | CLOSED | config/vrrp: no commit-time validation that a VRRP virtual-address falls within a subnet configured on the parent unit ( |
| #3018 | CLOSED | security-policy: 'from-zone any'/'to-zone any' wildcard policies commit but are never indexed by the Rust policy engine  |
| #3019 | CLOSED | security-policy: 'to-zone junos-host'/'from-zone junos-host' policies commit and are documented but LocalDelivery never  |
| #3020 | CLOSED | applications: junos-ping / junos-pingv6 match all ICMP/ICMPv6 (no type/code constraint) — identical to junos-icmp-all/ju |
| #3021 | CLOSED | userspace-dp: zone-pair resolution on session-miss uses physical parent ifindex, not the VLAN logical subinterface — wro |
| #3022 | CLOSED | userspace-dp screen: pre-session screen-check and SYN-cookie-ACK zone lookup uses physical parent ifindex — screens bypa |
| #3023 | CLOSED | security-policy: *-address-excluded with only one address family populated fails-closed on the opposite family — blocks  |
| #3024 | CLOSED | screen: TCP SYN-flood protection silently disabled when attack-threshold is not explicitly set (no Junos default-200 fal |
| #3025 | CLOSED | userspace-dp NAT64: non-fragmented packets recompute the full L4 checksum instead of an O(1) incremental (RFC 1624) adju |
| #3026 | CLOSED | userspace-dp: locally-generated ICMP errors (Time Exceeded / PTB) classify CoS+output-filter by the PHYSICAL bind ifinde |
| #3027 | CLOSED | userspace-dp screen teardrop: malformed fragment with ip_total_len <= header length (zero/negative payload) passes the s |
| #3029 | CLOSED | NAT parity: destination-NAT destination-address with a prefix (e.g. 198.51.100.0/24) is silently narrowed to a single ho |
| #3031 | CLOSED | NAT parity: static-NAT block-to-block (subnet) mappings are silently dropped (parse_nat_addr rejects non-/32//128) |
| #3032 | CLOSED | userspace-dp screen: SYN-cookie epoch calls SystemTime::now() per packet instead of using the batch-cached now_secs |
| #3035 | CLOSED | userspace-dp: SYN-cookie reply (cookie_reply.rs) + policy/filter reject reply (reject_reply.rs) classify generated repli |
| #3040 | CLOSED | logging/ringbuf: event-log protoName renders only tcp/udp/icmp/icmpv6 — GRE/ESP/IPIP/IPv6 sessions log numeric (same cla |
| #3042 | CLOSED | match-policies operator simulator (REST/gRPC/CLI) diverges from the runtime policy evaluator on globals, default-policy, |
| #3043 | CLOSED | security policy with no terminal action (log-only/count-only) silently compiles to PERMIT; multiple terminal actions las |
| #3044 | CLOSED | security policy with missing match criteria (no source/dest/application, or no match block) compiles as wildcard match-a |
| #3045 | CLOSED | REST GET /api/v1/security/policies omits global policies (CLI/gRPC/Prometheus/runtime all include them) |
| #3046 | CLOSED | userspace-dp session: TCP RST gets the full 30s TCP_CLOSING_TIMEOUT (is_closing treats RST==FIN) — RST-flood state exhau |
| #3047 | CLOSED | userspace-dp SNAT allocator: claim_free_port_locked tries only ONE sequential port per call (no retry on collision) and  |
| #3048 | CLOSED | userspace-dp flow cache not invalidated on neighbor (ARP/NDP) MAC change — cached ForwardCandidate keeps stale dst_mac u |
| #3049 | CLOSED | userspace-dp source-NAT pool: subnet-style pool address (e.g. 192.0.2.0/24) silently truncated to a single host; no comm |
| #3055 | CLOSED | security: zone literally named 'junos-global' is accepted at commit but reclassified as a device-wide global policy by t |
| #3056 | CLOSED | userspace-dp: admitted sessions don't store the admitting policy ID — session rows + RT_FLOW create/close publish policy |
| #3057 | CLOSED | userspace-dp: implicit default-policy deny/reject emits policy ID 0 — collides with (and mis-attributes to) the first co |
| #3058 | CLOSED | userspace-dp: DNAT/static-NAT/NPTv6 policy-deny RT_FLOW logs the pre-translation tuple with empty NAT fields + pre-NAT A |
| #3059 | CLOSED | grpcapi: 'show security policies hit-count' (gRPC text) omits global policies (detail/CLI/Prometheus/runtime all include |
| #3060 | CLOSED | security policy: bare 'then log' compiles + reports logging-enabled over REST/gRPC but emits no session records (both lo |
| #3061 | CLOSED | config: zone-local address-books (security-zone <z> address-book) are parsed but silently dropped at compile — only glob |
| #3062 | CLOSED | show: scheduled policies that are runtime-inactive still print 'State: enabled' on CLI/gRPC policy detail |
| #3063 | CLOSED | show: policy-detail Index drifts from runtime/RT_FLOW policy IDs after a multi-application policy (display uses non-expa |
| #3064 | CLOSED | userspace-dp screen: non-first IP fragments bypass the screen stage (flow==None) — per-fragment ping-of-death/teardrop/i |
| #3065 | CLOSED | security: unspecified default-policy silently fails OPEN (permit-all) + 'reject-all' ignored + default-policy missing fr |
| #3066 | CLOSED | config/screen: undefined zone screen-profile reference is warn-only at commit — Rust dataplane silently passes all traff |
| #3067 | CLOSED | userspace-dp: non-echo ICMP packets get bytes 4..6 extracted as a fake source port — bogus stateful sessions installed ( |
| #3070 | CLOSED | security zones host-inbound-traffic is silently dropped by the userspace dataplane — firewall-local services not gated |
| #3071 | CLOSED | security zones tcp-rst is parsed but never wired into userspace enforcement — denied TCP cannot honor zone reset |
| #3072 | CLOSED | config: an interface assigned to multiple security zones is silently accepted — userspace picks the lexicographically-fi |
| #3073 | CLOSED | userspace-dp: policy hit-count packets/bytes increment only on session-miss (new flow), not per-packet — long-lived flow |
| #3074 | CLOSED | security policy 'then count' is parsed and stored but has no userspace wire/runtime meaning (inert) |
| #3075 | CLOSED | compiler: sorted positional zone IDs can renumber existing zones on config edit — stale session/HA metadata mis-maps to  |
| #3076 | CLOSED | firewall filter: tcp-flags logical expression (e.g. "syn & !ack") commits but is silently dropped — TCP-flags constraint |
| #3077 | CLOSED | userspace firewall filters: flexible-match-range is parsed/compiled but silently dropped in the userspace dataplane — fi |
| #3079 | CLOSED | config/NAT: rule-set 'from/to interface' and 'from routing-instance' scopes are silently dropped — NAT rule-set applied  |
| #3082 | CLOSED | userspace-dp screen: runtime fail-open when a zone references a missing screen profile — emit a runtime signal on the le |
| #3090 | CLOSED | userspace-dp: implement wildcard from-zone/to-zone 'any' policy indexing (deferred from #3018) |
| #3091 | CLOSED | dataplane: partial XSK bind (1 ZC XSK on mlx5 VF) leaves RSS fanning to unbound queues → XDP_DROP blackhole (linksetup r |
| #3096 | CLOSED | config/NAT: implement interface- and routing-instance-scoped NAT rule-set matching (deferred from #3079) |
| #3099 | CLOSED | Session aggregator: Space-Saving top-K for arrival-order-independent accuracy under adversarial cardinality |
| #3103 | CLOSED | grpcapi: gRPC ShowText 'test-policy:' uses a pre-#3042 bespoke matcher — can report the opposite verdict from the runtim |
| #3104 | CLOSED | policymatch: simulator returns a definitive verdict for scheduled (runtime-inactive) policies — disagrees with the datap |
| #3105 | CLOSED | cli: local 'show security match-policies' / 'test policy' omit the dynamic-address feed overlay — disagree with REST/gRP |
| #3107 | CLOSED | cli: 'test policy' cannot express source-port — source-port-constrained applications are overmatched |
| #3108 | CLOSED | policy simulators: invalid protocol tokens (e.g. 'tcpp') accepted and yield a verdict instead of an error |
| #3109 | CLOSED | applications: a protocol-less (port-only) application disables ALL userspace security-policy enforcement / hard-errors s |
| #3110 | CLOSED | userspace-dp: zone-less interface (zone-id 0) still evaluates GLOBAL policies — a permit global leaks transit on unzoned |
| #3111 | CLOSED | userspace-dp NAT: pool-mode source-NAT corrupts non-TCP/UDP (GRE/ESP/AH/OSPF) — allocates a pseudo-port and overwrites t |
| #3112 | CLOSED | userspace-dp: DNAT/static-NAT return ICMP errors don't rewrite the embedded inner destination — breaks PMTUD/traceroute  |
| #3113 | CLOSED | security policy: unsupported vSRX match leaves (dynamic-application/url-category/source-identity) silently accepted then |
| #3114 | CLOSED | security policy: 'then permit application-services ...' accepted but ignored — UTM/IDP/SSL-proxy service chain silently  |
| #3115 | CLOSED | security policy: 'then reject profile <name>' accepted but the reject profile is ignored — wire behavior diverges from c |
| #3116 | CLOSED | policy simulators (REST/CLI/gRPC): out-of-range and malformed ports accepted — >65535 evaluated, malformed/negative sile |
| #3117 | CLOSED | config schema: policy 'scheduler-name' is implemented + strict-validated but absent from the set-schema/completion tree |
| #3119 | CLOSED | userspace-dp screen: teardrop is IPv4-only — IPv6 fragments bypass the teardrop check (ping-of-death already covers IPv6 |
| #3120 | CLOSED | userspace-dp screen: IPv6 ext-header walk breaks after the fragment header — frag→dest-options→TCP hides TCP flags (syn- |
| #3121 | CLOSED | userspace-dp: NPTv6 outbound source translation skipped when DNAT rewrites the destination — internal IPv6 source leaks  |
| #3122 | CLOSED | userspace-dp HA: peer-synced sessions excluded from per-IP session-limit tracking — limit bypass after failover |
| #3141 | CLOSED | config: 'then deny <tail>' commits and silently drops the child (no validatePolicyThenDenyStrict, unlike then permit/rej |
| #3142 | CLOSED | security-policy: flat-set 'match application <vals> dynamic-application/url-category ...' bypasses the #3113 unsupported |
| #3143 | CLOSED | userspace-dp: ReadPolicyCounters resolves wrong slot after app-set expansion (uses policyID%256 as direct slice index, i |
| #3144 | CLOSED | security-policy: direct undefined 'match application' reference is warning-only at commit but disables userspace policy  |
| #3145 | CLOSED | userspace-dp: snapshot policy-ID generation lacks the MaxRulesPerPolicy (256) cap — app-set expansion spills into the ne |
| #3146 | CLOSED | security-policy: empty application-set referenced by a policy commits with no warning but disarms the userspace policy g |
| #3147 | CLOSED | security-policy: empty address-set referenced by a policy commits with no warning but disarms the userspace policy gate |
| #3148 | CLOSED | vsrx-parity: global policy cannot carry from-zone/to-zone context (all-zone fallback only) — Junos global policy zone co |
| #3149 | CLOSED | security-policy: dangling address-set members are warning-only at commit while userspace refuses the policy (address-boo |
| #3150 | CLOSED | applications: strict commit accepts any 'protocol junos-*' for a policy-referenced application via HasPrefix, but the da |
| #3151 | CLOSED | userspace-dp forwarding: local-delivery resolution scans connected_v4 without VRF/table filter — cross-routing-instance  |
| #3152 | CLOSED | userspace-dp session: no TCP opening/half-open state — bare-SYN sessions get the full tcp_established_ns (1800s default) |
| #3164 | CLOSED | userspace-dp NAT: implement multi-host-prefix destination-NAT matching (LPM) — deferred from #3029 |
| #3169 | CLOSED | userspace-dp: RX source-MAC dynamic-neighbor learn (learn_dynamic_neighbor) does not bump mac_change_epoch — stale dst_m |
| #3171 | CLOSED | userspace-dp host-inbound: embedded-ICMP errors dropped on a ping-less configured zone — userspace classifier disagrees  |
| #3172 | CLOSED | userspace-dp host-inbound: VRRP VIPs not in interface snapshot may leave kernel deny unscoped (fail-open) for VIP-destin |
| #3175 | CLOSED | queue-planner: orphan VLAN child (parent not a binding candidate) still hashes child's own rx_queues, not the parent's — |
| #3182 | CLOSED | userspace-dp neighbor: own-IP anti-poison guard misses NAT-excluded interface IPs + the RX source-MAC learn path (residu |
| #3193 | CLOSED | show security nat source persistent-nat: report the three-way permit mode (target-host vs target-host-port), not just a  |
| #3199 | CLOSED | host-inbound: 'protocols all' opens every host-bound service (SSH/HTTPS/...), not just routing protocols — control-plane |
| #3200 | CLOSED | host-inbound: unknown/typo token commit-accepted; nft path fails OPEN while Rust path fails CLOSED (split-brain posture) |
| #3201 | CLOSED | host-inbound: Rust ICMP admission is protocol-wide (ping/router-discovery) vs nft type-specific — AF_XDP over-admits ICM |
| #3202 | CLOSED | static NAT: block-to-block rule with match-destination-port/mapped-port commits but dataplane silently drops port semant |
| #3203 | CLOSED | flexible-match-range compiler: byte-length truncation (non-mult-8 bits), silent value→0 on parse error, and wrong defaul |
| #3204 | CLOSED | TCP RST reject reply can carry a multicast/broadcast source MAC (TCP path lacks the L2-group guard the ICMP reject path  |
| #3205 | CLOSED | firewall filter: symbolic match values (icmp-type/code names, named ports) not validated at commit — port-except fails o |
| #3206 | CLOSED | static NAT: unparseable match destination-address / static-nat prefix (address-book name or typo) commits but dataplane  |
| #3207 | CLOSED | policy validation: terminal-action error for a zone-pair policy omits from/to-zone context (empty scope) |
| #3208 | CLOSED | screen ip-source-route: IPv6 Routing Header type 4 (SRv6) not flagged — design decision needed (/research candidate) |
| #3224 | CLOSED | host-inbound: kernel nft enforcement fails OPEN for DHCP/SLAAC dynamic interface addresses |
| #3225 | CLOSED | host-inbound: service/protocol matches are address-family blind (dhcp/dhcpv6, rip/ripng, ospf) — wrong-family exposure |
| #3226 | OPEN | host-inbound: 'system-services all' / 'any-service' is a packet-wide admit, not a union of known service tokens (vSRX pa |
| #3227 | CLOSED | applications: per-application 'inactivity-timeout' is ignored by userspace session expiry (parity regression) |
| #3228 | CLOSED | destination-NAT: multi-address match validator passes on a partial-valid list; builder silently drops malformed/unparsea |
| #3229 | CLOSED | destination-NAT: 'match destination-address-name' (address-book reference) is unsupported (vSRX parity gap) |
| #3230 | CLOSED | screen: ICMP/UDP flood + port-scan + ip-sweep thresholds default to 0 (= disabled) when enabled without an explicit thre |
| #3231 | CLOSED | loopback (lo0) firewall filter: nft generation drops/garbles TCP-flags AND-semantics, port-except, and IPv6 is-fragment  |
| #3232 | CLOSED | firewall flexible-match-range: 'match-start layer-4'/payload silently evaluated at L3 (offset applied to wrong header) |
| #3233 | CLOSED | NPTv6: zero-adjustment rule still folds 0xFFFF→0x0000, corrupting a valid host-ID word (RFC 6296 collision) |
| #3240 | CLOSED | host-inbound: router-discovery ICMP-subtype parity diverges between Rust classifier and Go nft |
| #3261 | CLOSED | Lenient/HA-sync path: a protocol-less (unrepresentable) application still disarms the WHOLE userspace dataplane (fail-OP |
| #3270 | CLOSED | flowexport: populate flowDirection (IPFIX IE 61) with a real per-flow inbound/outbound classification |
| #3276 | CLOSED | DDNS: request system dynamic-dns update — operator force-now / check-now verb |
| #3277 | CLOSED | host-inbound lifeline matcher hardcodes fxp0/em0/fab* — a configured control-interface (e.g. fxp1) is NOT excluded → lat |
| #3283 | CLOSED | policymatch simulator ignores wildcard-zone (#3090) and scoped-global (#3148) precedence — can report opposite permit/de |
| #3284 | CLOSED | policymatch simulator ignores ICMP type/code constraints — over-permits non-echo ICMP for junos-ping |
| #3285 | CLOSED | policymatch simulator applies transit global/default fallback to to-zone junos-host queries (runtime does not) |
| #3286 | CLOSED | Scoped global policies (#3148) rendered as all-zones (*/*) in REST/gRPC/CLI inventory — hides actual zone scope |
| #3287 | CLOSED | Scoped global policy (#3148) does not resolve zone-local address books (#3061) — silent match-none |
| #3290 | CLOSED | userspace-dp: ICMP error/control packets install fake sessions via metadata fallback, bypassing the #3067 frame-parser i |
| #3291 | CLOSED | userspace-dp: flowless / non-first-fragment transit packets bypass zone policy, input filters, and PBR (then routing-ins |
| #3292 | CLOSED | userspace-dp: flowless LocalDelivery bypasses host-inbound, lo0 filter, and to-zone junos-host policy |
| #3293 | CLOSED | userspace-dp: remove dead userspaceSupportsSecurityPolicies oracle (test-only references after #3261) |
| #3294 | CLOSED | userspace-dp: {feed + concrete} address-set — strict commit rejects but dataplane accepts (feed-portion under-deny on le |
| #3295 | CLOSED | firewall filters: no-match fall-through is implicit Accept (Junos firewall filters imply final discard) — allowlist filt |
| #3296 | CLOSED | firewall filters: undefined interface/lo0 filter reference is warning-only at commit and enforces as Accept in the datap |
| #3297 | CLOSED | firewall filter: a term carrying both positive port match and *-port-except is not rejected at strict commit (dataplane  |
| #3298 | CLOSED | policy applications: overlapping apps with different inactivity-timeout are reordered by lexical name before Rust first- |
| #3299 | CLOSED | host-inbound: protocols bfd admits only single-hop BFD (UDP 3784/3785); multi-hop BFD (RFC 5883, UDP 4784) is denied |
| #3300 | CLOSED | dynamic-address: typo in 'address-name ... profile feed-name <feed>' is accepted as an empty feed binding → feed deny si |
| #3301 | CLOSED | ha/session-sync: policy_id, policy_counter_idx, and per-application inactivity-timeout are not carried on the userspace  |
| #3303 | CLOSED | userspace-dp NAT: source/destination-address-name cannot be driven by dynamic-address feeds (NAT snapshot builders never |
| #3307 | CLOSED | firewall filters: unknown 'from' match leaves silently commit and compile to a less-constrained term (fail-open / fail-c |
| #3308 | CLOSED | firewall filters: 'then routing-instance' co-located with 'discard'/'reject' logs a deny but still routes the packet (au |
| #3309 | CLOSED | firewall filters: invalid/out-of-range DSCP & traffic-class match/rewrite tokens silently commit and the constraint vani |
| #3310 | CLOSED | host-inbound: 'system-services ident-reset' opens TCP/113 as a plain admit instead of actively resetting ident (vSRX par |
| #3311 | CLOSED | host-inbound: 'protocols isis' is hard-rejected at commit despite IS-IS routing being supported (vSRX parity gap) |
| #3315 | CLOSED | security/userspace-dp: SYN-flood source/destination/timeout/alarm sub-thresholds never reach the userspace dataplane (on |
| #3316 | CLOSED | security/config: ICMP-fragment screen is implemented in the userspace dataplane but unreachable from config (no Go type/ |
| #3317 | CLOSED | security/config: malformed screen numeric values fail open — bad thresholds parse to a default or to zero/disabled inste |
| #3318 | CLOSED | security/config: unknown/unsupported screen leaves silently commit and are dropped (open schema subtrees + no compiler d |
| #3320 | CLOSED | applications: malformed inactivity-timeout/timeout commits and is silently dropped (untyped leaf, no strict validation) |
| #3321 | CLOSED | userspace-dp AppID: directionless lookup mislabels forward flows by source port (RT_FLOW/session-display attribution) |
| #3322 | CLOSED | userspace-dp: policy hit-counter handle is positional — live policy insert/reorder mis-attributes established-session co |
| #3323 | CLOSED | policymatch: match-policies overmatches application-constrained rules when protocol is omitted (reports a permit no pack |
| #3326 | CLOSED | userspace-dp: host-inbound denies never increment the host-inbound deny counter (GlobalCtrHostInboundDeny stuck at 0) |
| #3327 | CLOSED | REST/gRPC screen inventory omits port-scan, ip-sweep, limit-session, and all thresholds (string-only screenChecks) |
| #3328 | CLOSED | REST/gRPC zone API collapses host-inbound state — no host_inbound_configured, system-services and protocols flattened (p |
| #3329 | CLOSED | REST security API drops zone description, zone tcp-rst, and policy description that gRPC exposes |
| #3330 | CLOSED | policymatch: match-policies overmatches port-constrained applications when the query port is omitted (sibling of #3323) |
| #3331 | CLOSED | match-policies result lacks policy scope/id (from-zone/to-zone, global-vs-zone, term) — ambiguous for duplicate policy n |
| #3332 | CLOSED | config: trailing tokens on a supported flat-set leaf are silently consumed (e.g. 'screen ... tcp land bogus') |
| #3333 | CLOSED | host-inbound: nftables apply/delete failure is not fail-closed (warn-only apply, ignored delete) — committed deny can si |
| #3334 | CLOSED | grpcapi: GetEvents narrows the zone filter via unchecked uint16 cast instead of rejecting >65535 (REST + sessions fail-c |
| #3335 | CLOSED | logging: historical event zone names are recomputed from current config instead of EventRecord.InZoneName/OutZoneName (r |
| #3336 | CLOSED | REST/gRPC/CLI policy inventory hides source/destination-address-excluded (match inversion) and drops log init/close mode |
| #3337 | CLOSED | Security event APIs (REST/SSE/gRPC) drop RT_FLOW forensic fields (policy/app name, close reason, reverse counters, NAT,  |
| #3338 | CLOSED | Security event filtering: zone-0/unknown-zone events are unselectable (0=no-filter sentinel) and only coarse zone/action |
| #3339 | CLOSED | config/applications: silent overwrite on application/application-set name collisions and duplicate term names; policy-ex |
| #3340 | CLOSED | applications: custom destination-port accepts only a 15-name hardcoded subset (dns yes, domain no) — rejects valid vSRX  |
| #3341 | CLOSED | host-inbound: missing routing-protocol tokens rsvp/pgm/sap/dvmrp — valid vSRX 'protocols <token>' rejected at commit |
| #3342 | CLOSED | logging: EventBuffer.Latest(n) panics on negative n — reachable via 'show security log -1' |
| #3343 | CLOSED | userspace-dp/screen: per-screen drop reason counters never published — all per-reason screen counters read 0 across CLI/ |
| #3344 | CLOSED | cli/grpc: 'show security screen-statistics all' silently drops a zone when its counter read fails |
| #3345 | CLOSED | observability: global counter read errors are swallowed to 0 across REST/Prometheus/gRPC/CLI (clean zero instead of 'una |
| #3346 | CLOSED | userspace-dp policy: application-term precedence is class-based (exact-port > range > icmp-constrained), overriding conf |
| #3347 | CLOSED | cli: 'show security log' fail-open argument parsing — unknown/incomplete filter tokens silently ignored; zone filter wid |
| #3348 | CLOSED | applications: custom 'protocol junos-ping'/'junos-pingv6' matches ALL ICMP (no echo constraint); no icmp-type/icmp-code  |
| #3349 | CLOSED | security log: stream category/severity/facility/port/source-address/mode/format commit without validation and silently w |
| #3350 | CLOSED | security log: 'stream transport tls-profile' parsed but never applied at runtime (nil tls.Config) — secure-syslog postur |
| #3351 | CLOSED | security log: TCP/TLS stream is permanently disabled if its receiver is down at config-apply/boot (no reconnecting clien |
| #3352 | CLOSED | applications: unknown leaves inside 'application <a> term ...' are silently ignored — drops a port constraint and widens |
| #3353 | CLOSED | applications: per-application 'alg' is neither validated at commit nor carried to the userspace dataplane (silent no-op) |
| #3354 | CLOSED | remote CLI: 'show security match-policies' malformed source/destination-port silently coerced to wildcard (misleading ve |
| #3355 | CLOSED | policymatch: shared simulator (+ REST/gRPC) lacks the runtime unknown/missing-zone (id-0) guard — undefined query zone m |
| #3356 | CLOSED | policymatch: matchAddr excluded-address semantics drift from runtime #3023/#2008 — cross-family over-block + empty-exclu |
| #3357 | CLOSED | policy views: scoped global policies (#3148) are suppressed in filtered hit-count/detail (local CLI + gRPC) and rendered |
| #3358 | CLOSED | policy detail: synthetic 'zone-local/<zone>/<name>' compiler token leaks into operator output (labelled (global)) instea |
| #3359 | CLOSED | firewall filter: mixed positive-address + 'except' prefix-list in one direction folds 'except' into positive (fail-OPEN  |
| #3360 | CLOSED | security flow gre-performance-acceleration: config-truth gap — knob is wired Go-side and shown in 'show' output but neve |
| #3361 | CLOSED | host-inbound: kernel nftables host-inbound drop rules carry no nft counter and are never scraped into host_inbound_denie |
| #3362 | CLOSED | host-inbound: per-zone-interface 'host-inbound-traffic' (interface-scoped override) is not modeled — only zone-wide host |
| #3363 | CLOSED | userspace-dp policy: implicit default-policy has no per-rule hit counter and cannot log (policy_counter_idx=0, log flags |
| #3364 | CLOSED | daemon nftables: xpf_lo0 and xpf_hostinbound base chains share 'hook input priority 0' — equal-priority chain ordering i |
| #3365 | CLOSED | userspace-dp policy: unknown policy/default-policy action string silently becomes Deny at the snapshot boundary (no Snap |
| #3366 | CLOSED | config/applications: an application with BOTH direct fields and 'term' children silently drops the direct body; duplicat |
| #3367 | CLOSED | userspace-dp: legacy policy-address and filter tcp-flags snapshot parse backstops silently drop malformed content instea |
| #3368 | CLOSED | host-inbound: 'system-services traceroute' admits only the default UDP probe range (33434-33523) — verify/scope vSRX sem |
| #3372 | CLOSED | applications: mixed-case named ports (e.g. destination-port HTTPS) pass strict commit but the userspace representability |
| #3373 | CLOSED | applications: source/destination-port accepted on non-port protocols (icmp/gre/ospf/esp/ah/vrrp) — builds an unrepresent |
| #3374 | CLOSED | config: collapsed 'then deny session-init'/'session-close' accepted without a 'log' parent — over-acceptance silently wi |
| #3375 | CLOSED | grpcapi: MatchPolicies returns a blank action for host-inbound-unmatched and no-config default-deny where REST returns e |
| #3376 | CLOSED | userspace-dp: policy-content rejection reasons omit zone-pair/global scope and the offending side/object (ambiguous for  |
| #3377 | CLOSED | config schema: security-policy 'then' omits permit/deny/reject/count leaves — compiled-but-not-schema-visible drift (com |
| #3378 | CLOSED | cli: 'monitor security flow file' writes the trace file with no path/symlink sanitization and mode 0644 (traversal + sym |
| #3379 | CLOSED | cli: 'monitor security flow' size/files rotation limits are parsed and validated but never enforced — control-plane disk |
| #3380 | CLOSED | cli: 'monitor security flow' file/filter and packet-drop parsers fail open (partial commit on error, empty filter = matc |
| #3381 | CLOSED | cli: 'monitor security flow start' and 'monitor security packet-drop' panic (nil deref) when the event buffer is absent |
| #3382 | CLOSED | grpcapi: MonitorPacketDrop silently ignores 'node' and skips validation of count/ports/protocol/from_zone/interface (sil |
| #3383 | CLOSED | api/sse: log stream fails open on typo'd severity/category, mislabels screen permit-alarms as 'error', and passes unknow |
| #3384 | CLOSED | logging: Subscription.Close documents closing the channel but only unsubscribes — consumers relying on the contract can  |
| #3385 | CLOSED | userspace-dp AppID: AppCatalog scan/range lookup OR-decomposition over-matches dual-port-constrained custom apps with ov |
| #3392 | CLOSED | daemon: applyLo0Filter nftables apply/delete is warn-only (fail-open) — sibling of #3333 |
| #3393 | CLOSED | appid: ProtocolName↔ProtocolNumber is not a round-trip for ipv6 (41) and other one-way names |
| #3395 | CLOSED | userspace-dp: policy_id (#3056) is positional — live policy insert mis-attributes RT_FLOW/session policy id (sibling of  |
| #3397 | CLOSED | config/firewall-filter: resolveFilterPort splits on '-' before whole-spec lookup — mangles hyphenated service names (ftp |
| #3402 | CLOSED | userspace-dp policy: a snapshot policy rule with an unresolvable zone name is silently un-indexed and falls through to d |
| #3404 | CLOSED | userspace-dp: policy-ID namespace guard rejects an exact 256-rule fill (off-by-one >= vs >) |
| #3405 | CLOSED | host-inbound: a security zone with no host-inbound-traffic stanza admits ALL host-bound traffic (vSRX default-deny parit |
| #3406 | CLOSED | userspace-dp: lenient-load filter snapshot silently drops/caps port-except, ICMP out-of-range, flex-match width, DSCP re |
| #3408 | CLOSED | observability: per-zone/per-policy/screen-per-zone counter read errors swallowed to 0 (REST/gRPC/CLI) — sibling of #3345 |
| #3409 | CLOSED | security log event mode: structured / sd-syslog formats not honored by the local-file writer |
| #3413 | CLOSED | docs: pre-id-default-policy.md says 'Status: Implemented' / logging applied, but the feature is inert (contradicts close |
| #3414 | CLOSED | policymatch/REST match-policies: scheduled policy simulated as ACTIVE when scheduler state is unavailable, while the dat |
| #3415 | CLOSED | policymatch: omitted query source-port is treated as wildcard for source-port-constrained apps — over-certifies vs runti |
| #3416 | CLOSED | userspace-dp: permit-side RT_FLOW/conntrack AppID resolved from pre-NAT dst_port after policy matched post-NAT port (Cod |
| #3417 | CLOSED | NAT: interface-mode source NAT pool stats report global SNAT total per row (Codex audit 102 H1) |
| #3418 | CLOSED | config/nat: strict commit rejects feed-only dynamic-address NAT address-name references that #3303 snapshots support (Co |
| #3419 | CLOSED | REST session views lose data + report idle-as-age vs gRPC (Codex audit 099 H1/H2/H3/M1/M3/M4/M6) |
| #3420 | CLOSED | logging/traceoptions: configured 'security flow traceoptions file' can write outside /var/log (path traversal) (Codex au |
| #3421 | CLOSED | REST session filtering/pagination/input lags gRPC: offset-over-mutable-map, clear ignores filters, no prefix/port filter |
| #3422 | CLOSED | logging/traceoptions: invalid packet-filter prefix or unknown flag silently broadens/disables persistent flow tracing (C |
| #3423 | CLOSED | REST session endpoints are local-node-only: clear-sessions skips HA peer; list/summary lack include_peer/node_id (Codex  |
| #3424 | CLOSED | logging/traceoptions: unbounded persistent trace size/files makes rotation a per-event CPU storm (Codex audit 097 M03) |
| #3425 | CLOSED | config/nat: strict commit accepts defined-but-unresolvable NAT address-name (empty/dangling set) that runtime turns into |
| #3426 | CLOSED | REST global statistics omit nat64_translations + host_inbound_allowed vs gRPC (Codex audit 099 M7/L1) |
| #3427 | CLOSED | daemon lo0 nft: fall-through / modifier-only / routing-instance terms emit terminating accept (kernel mirror fail-open)  |
| #3428 | CLOSED | appid: Go session-name fallback ignores configured source-port, mislabels sessions (Codex audit 099 H7) |
| #3429 | CLOSED | nat: source NAT match destination-port/application parsed but never enforced (Codex audit 095 H01/H02/H03) |
| #3430 | CLOSED | routing/PBR: Linux ip-rule builder diverges from Junos FBF semantics — unattached filters steer, DSCP-0 unrepresentable, |
| #3431 | CLOSED | nat: match application/protocol/address-name multi-value lists collapse to one scalar (Codex audit 095 H04/H05/H06) |
| #3432 | CLOSED | firewall-filter/PBR: output-attached 'then routing-instance' accepted at commit but userspace route override only checks |
| #3433 | CLOSED | daemon lo0 nft: address / prefix-list lowering diverges from userspace (any, wrong-family, empty/unresolved positive pre |
| #3434 | CLOSED | nat: DNAT undefined/empty match application falls open to wildcard translation (no commit gate) (Codex audit 095 H07/H08 |
| #3435 | CLOSED | config/nat: static NAT 'match source-address' parsed but never enforced + multi-value scalar loss (Codex audit 098 H01/M |
| #3436 | CLOSED | daemon lo0 nft: protocol aliases and DSCP names emitted raw without shared-resolver normalization (Codex audit 094 H08/M |
| #3437 | CLOSED | nat: DNAT application match drops source-port and ICMP type/code constraints (Codex audit 095 H10/H11) |
| #3438 | CLOSED | appid: catalog IDs wrap past uint16 65535 colliding with reserved-0, and AppID-enabled unmapped nonzero IDs still tuple- |
| #3439 | CLOSED | cli/grpc: live session inspection silently drops malformed filters (remote show flow session) and accepts invalid protoc |
| #3440 | CLOSED | flow aging: documented Done but inert on userspace dataplane + opaque schema accepts invalid values (Codex audit 101 H1/ |
| #3441 | CLOSED | configstore: auto-archive wrong-commit/overwrite + rollback-file durability gaps (Codex audit 101 H4/L1/L2/L3) |
| #3442 | CLOSED | config load: LoadMerge turns garbage into nodes, LoadSet silently skips malformed lines (Codex audit 101 M3/M4) |
| #3443 | CLOSED | config API: REST/gRPC rollback-compare selectors default malformed/negative input instead of failing (Codex audit 101 M5 |
| #3444 | CLOSED | config/nat: destination NAT 'rule-set to ...' scope accepted+compiled but silently dropped before runtime (should reject |
| #3445 | CLOSED | daemon lo0 nft: term modifiers (log/count/policer/dscp-rewrite/forwarding-class/loss-priority) and reject semantics not  |
| #3446 | CLOSED | nat: DNAT match destination-port 0/out-of-range/nonnumeric wraps or becomes wildcard (no validation) (Codex audit 095 H1 |
| #3447 | CLOSED | cli: malformed 'rollback <arg>' parses as rollback 0 and silently discards candidate edits (Codex audit 100 H6) |
| #3448 | CLOSED | userspace-dp: 'clear security policies hit-count' replays pre-clear hits from worker-local pending counter buffers (no c |
| #3449 | CLOSED | nat: DNAT destination-port ranges expand unbounded into per-port snapshots (control-plane amplification) (Codex audit 09 |
| #3450 | CLOSED | nat: DNAT pool port/address unvalidated — wraps, silently no-ops, coerces to network base, or commits a dataplane-droppe |
| #3451 | CLOSED | userspace-dp: policy hit-counter packet/byte snapshot is not an atomic pair (two relaxed atomics) (Codex audit 098 L01) |
| #3457 | CLOSED | userspace-dp: 3 pre-existing event_stream/worker_queue test failures on clean origin/master |
| #3459 | CLOSED | Prometheus firewall-filter collector miscomputes term expansion (ignores ports + prefix-lists) -> wrong term hit attribu |
| #3460 | CLOSED | grpc GetInterfaces bypasses Junos->Linux name resolution (no ResolveKernelIfName) -> RETH/tunnel/Junos names lose ifinde |
| #3461 | CLOSED | Prometheus xpf_filter_hits_total does not merge userspace helper-published filter-term counters (unlike CLI/gRPC text) |
| #3462 | CLOSED | xpf_counter_read_errors_total emitted by collectGlobalCounters before zone/policy/filter collectors increment it -> degr |
| #3463 | CLOSED | xpf_counter_read_errors_total descriptor still says 'global-counter map reads' but code+README now cover zone/policy/fil |
| #3464 | CLOSED | Interface counter-read failures behave divergently across REST stats / REST inventory / gRPC / Prometheus with no unavai |
| #3472 | CLOSED | config/applications: generated per-term application names bypass the #3339 collision pass (overwrite authored apps/sets, |
| #3473 | CLOSED | policy: no strict gate for duplicate policy names in a zone-pair/global set -> two rules share one userspace hit counter |
| #3474 | CLOSED | userspace-dp: policyRuleIDForCounter skips nil zone-pair slots that walkPolicyRuleSlots/callers count -> counter mis-res |
| #3476 | CLOSED | policy/screen inventory: REST/gRPC/CLI/Prometheus/completion surfaces panic on nil zone-pair set, nil rule, or nil scree |
| #3477 | CLOSED | logging: event-mode security-log writer (LocalLogWriter) is not symlink/mode-hardened like the flow-trace writer — 0644  |
| #3478 | CLOSED | logging: audit-log write & rotation failures are silent (no counter/warn) across TraceWriter, LocalLogWriter, and sessio |
| #3483 | CLOSED | daemon lo0 nft: icmp-code-only term silently drops the code predicate (userspace enforces it) — fail-open/closed diverge |
| #3485 | CLOSED | userspace-dp: lo0 filter action runs BEFORE host-inbound admission on local delivery — host-inbound-denied traffic gets  |
| #3486 | CLOSED | host-inbound: Go and Rust service/protocol token allowlists are hand-mirrored with no drift test — fail-open/closed risk |
| #3489 | CLOSED | userspace-dp/session: update_session resets the TCP 'closing' flag non-stickily ('=' not set-only) — a non-closing promo |
| #3491 | CLOSED | source-nat: match application drops application source-port constraint (source-NAT sibling of #3437 DNAT) |
| #3492 | CLOSED | ha: buildZoneRGMap panics on nil zone value in per-RG session-sync apply path |
| #3493 | CLOSED | operator: REST/gRPC/CLI interface+zone inventory and session/flow filters panic on nil zone VALUE (Security.Zones), sibl |
| #3494 | CLOSED | config: ValidateConfig warning pass panics on nil zone-pair / policy / zone slots (compile-path sibling of #3476) |
| #3499 | CLOSED | interface compiler: compiler_iface.go derefs nil zone map-values in the apply-path bring-down reconcile |
| #3501 | CLOSED | config.RethToPhysical derefs nil interface map-values (panics before compiler_iface guards) |
| #3527 | CLOSED | screen: enforce syn-flood timeout (per-zone half-open session window / tcp_opening_ns) |
| #3534 | CLOSED | default-policy: configurable 'then log session-init/close' for implicit default deny/permit |
| #3546 | CLOSED | nat: source-NAT all-nonnumeric match destination-port widens to match-any on the lenient/peer-sync path |
| #3547 | CLOSED | cli (remote cmd/cli): 'show security log zone <unknown none 0>' selector not wired to GetEvents has_zone (#3338 parity) |
| #3562 | CLOSED | config: 6 strict-reject AST-walk validators bypassed by duplicate top-level 'security {}' blocks (first-security-node-on |
| #3566 | CLOSED | config: 4 flow-trace / log-stream AST validators have sub-level duplicate-block bypass (FindChild-first on flow/traceopt |
| #3578 | CLOSED | daemon nft: host-inbound counter DECLARATION uses quoted name, may fail nft -f apply on v1.1.6 |
| #3579 | CLOSED | daemon applySyslogConfig uses non-closing SetSyslogClients → conn leak on re-apply (CLI uses closing ReplaceSyslogClient |
| #3592 | CLOSED | REST /sessions/summary/zone-pairs: add include_peer cross-node fan-out (needs a gRPC zone-pair-summary RPC) |
| #3595 | CLOSED | build: cluster-deploy link fails on gcc-15 (duplicate crc32 in libelf.a/libz.a) — carry --allow-multiple-definition in . |
| #3604 | CLOSED | conntrack GC: data race on aging/session-limit config fields (sweep reads/writes without gc.mu) |
| #3605 | CLOSED | userspace-dp static NAT: zone/interface/source-differentiated rules sharing (external_ip, match-port) silently overwrite |
| #3606 | CLOSED | config: validatePortSpec accepts signed ports (+80) via strconv.Atoi that the dataplane/Rust parser reject — commit-vs-d |
| #3607 | CLOSED | screen: RateCounter over-throttles sustained at-threshold traffic (rejected events keep the window saturated; no recover |
| #3608 | CLOSED | userspace-dp: output firewall-filter 'then reject' silently drops on the TX/CoS path (no active RST/ICMP reject) |
| #3609 | CLOSED | userspace-dp host-inbound: per-interface override missed on VLAN logical interfaces (gate probes raw physical ifindex, n |
| #3610 | CLOSED | userspace-dp host-inbound: denies lack a tuple-rich event and conflate dbg.policy_deny with security-policy denies |
| #3611 | CLOSED | vSRX parity: junos-host self-zone policy — enforce from-zone junos-host (host-originated) + support global-policy junos- |
| #3612 | CLOSED | AppID: enabled catalog (lowest app_id) vs disabled fallback (specificity) precedence divergence relabels the same sessio |
| #3615 | CLOSED | userspace-dp: policy/filter 'then reject' RT_FLOW & filter-log report REJECT even when the generated reply was suppresse |
| #3616 | CLOSED | userspace-dp: IPsec/IKE/ESP/AH passthrough (Stage 11) bypasses per-zone host-inbound service enforcement — decide + pin  |
| #3617 | CLOSED | userspace-dp: locally-generated reject/error replies are never mirror-cloned (mirror_clone hard-false) — analyzer misses |
| #3618 | CLOSED | userspace-dp: one global reject token bucket lets a flood in one zone starve active rejects for all other zones |
| #3619 | CLOSED | host-inbound system-services: verify sip TCP/5061 + tftp port-set vs vSRX and publish an authoritative Go/nft/Rust servi |
| #3620 | CLOSED | vSRX parity: investigate + decide intrazone (same-zone) default behavior — runtime has no from_id==to_id tier; verify pr |
| #3622 | CLOSED | appid: CatalogNames/addPolicyApps panic on nil zone-policy/policy entries (missing nil-guard vs strict walker) |
| #3623 | CLOSED | api/grpc: policy inventory + match-policies drop policy_id for the first runtime policy (id 0) — omitempty/proto3-zero h |
| #3624 | CLOSED | api/grpc: structured policy inventory (PolicyInfo/PolicyRule) omits scheduler binding + runtime inactive state (structur |
| #3625 | CLOSED | userspace snapshot summary policy_count counts zone-pair SETS, not policy rules (global-only config reports 0) |
| #3626 | CLOSED | appid: runtime catalog (CatalogNames appid-disabled) omits source/destination-NAT match-application refs that strict val |
| #3627 | CLOSED | api: match-policies negative/default + host-inbound responses omit queried zone context; no per-dimension miss explanati |
| #3628 | CLOSED | cli: 'show security match-policies' usage/help omits source-port + ICMP selectors and shows only protocol <tcp udp> (par |
| #3629 | CLOSED | docs: pkg/appid/README documents a stale ResolveSessionName signature (missing srcPort, added #3428) |
| #3630 | CLOSED | api/grpc: default-policy structured representation is ad-hoc (synthetic '-'/'-' row, empty match arrays, two default enc |
| #3639 | CLOSED | vSRX parity: enforce to-zone junos-host GLOBAL (from-zone any) host-inbound policy (split from #3611 Piece B) |
| #3642 | CLOSED | output firewall filter matches pre-NAT tuple after SNAT/DNAT (wrong Junos semantics) |
| #3643 | CLOSED | per-zone + flood counters dead in userspace era (read by CLI/gRPC/REST, never populated) |
| #3646 | CLOSED | match-policies host-inbound verdict says 'local delivery proceeds' but a no-stanza zone default-denies host-inbound (#34 |
| #3651 | OPEN | POPULATE per-zone traffic + flood counters from the userspace dataplane (deferred half of #3643) |
| #3653 | CLOSED | api,grpc,docs: host_inbound_configured + comments + README + tests still encode pre-#3405 no-stanza admit-all (posture b |
| #3654 | CLOSED | cli,grpc,remote-cli: text zone/interface views hide per-interface host-inbound overrides + no-stanza default-deny postur |
| #3655 | CLOSED | remote-cli: match-policies still prints 'local delivery proceeds' for unmatched host-inbound (residual of #3647) |
| #3656 | CLOSED | userspace-dp: reject reply TX-budget + rate-limit token consumed BEFORE reply feasibility is known (unreplyable frames d |
| #3657 | CLOSED | observability: reject sent/reply-budget counters absent from 'show status' (docs contract violation) + Prometheus only a |
| #3658 | CLOSED | cli: 'show security zones detail' policy summary omits applicable global policies + effective default-policy catch-all ( |
| #3661 | CLOSED | observability: reject RATE-LIMIT drop leg still source-neutral (M02 Rust follow-up to #3657) |
| #3667 | CLOSED | gRPC text policy-detail (show security policies detail) drops address-exclusion, session-init/close log modes, and polic |
| #3668 | CLOSED | match-policies response omits address-exclusion flags and stable rule_id — a simulator hit reads inverted / cannot join  |
| #3669 | CLOSED | Remote 'show security zones' silently swallows GetPolicies RPC failure — zones print as policy-free on a control-plane e |
| #3670 | CLOSED | Synthetic default-policy inventory row (REST + gRPC GetPolicies) omits default-policy-log state |
| #3671 | CLOSED | Host-inbound zone view hides zone default-deny posture when ANY interface override exists (#3654 residual) |
| #3672 | CLOSED | Remote CLI 'show security policies' (non-detail) drops address-exclusion, log modes, scheduler/inactive, and count state |
| #3673 | CLOSED | Policy compiler unsupported-tail guard misses from-zone/to-zone collapsed onto a multi:true match leaf (reserved keyword |
| #3674 | CLOSED | Local 'request security match-policies' output is sparser than 'show security match-policies' — omits policy ID, scope,  |
| #3679 | CLOSED | match/test-policy + REST simulator port/ICMP parsers accept signed +80/+8 — #3606 canonical-port residual across diagnos |
| #3680 | CLOSED | Explicit from-zone/to-zone 'any' global policies hidden from local + gRPC zone-detail summary (#3658 residual in GlobalP |
| #3681 | CLOSED | REST /statistics/global host-inbound kernel counters diverge from Prometheus: hidden on degraded boot, read-error collap |
| #3682 | CLOSED | Host-inbound lifeline interfaces (fxp0/em0/fab*) silently bypass zone host-inbound deny scoping with no operator-visible |
| #3683 | CLOSED | Remote CLI: 'show security zones' omits global/default policy tiers (M01); filtered global scope prints '*' not 'any' (M |
| #3684 | CLOSED | Zone-detail policy summary (#3658) is names+actions only — omits scheduler state, policy IDs, log/count/exclusion modifi |
| #3685 | CLOSED | Policy-simulator output parity residuals: match-policies response drops description (M05) + scheduler binding (M06); gRP |
| #3696 | CLOSED | policy-simulator query parser silently widens on missing selector value + ignores unknown/malformed tokens across all 4  |
| #3697 | CLOSED | userspace-dp: Rust host-inbound hot-path comments still say no-stanza zone admits-all (stale post-#3405/#3653 default-de |
| #3698 | CLOSED | host-inbound: addressless configured/enforcing zone has a silent transient admit window (no deny until an address appear |
| #3699 | CLOSED | userspace-dp: AF_XDP ident-reset secondary local-delivery path DROPS instead of RESETS (vSRX-parity divergence, untracke |
| #3703 | CLOSED | config: bracketed/single-line list drops all-but-first + bypasses strict validation on host-inbound system-services/prot |
| #3704 | CLOSED | dataplane/ha: #3075 stable zone id incomplete — buildZoneSnapshots still positional, splits live wire ids from CLI/HA na |
| #3705 | CLOSED | host-inbound: tolerant/HA nil zone (Security.Zones[name]==nil) ships HostInboundConfigured=false → configured zone admit |
| #3706 | CLOSED | userspace-dp: to-zone junos-host 'then permit log' is discarded on local-delivery — host-bound permit sessions unlogged  |
| #3709 | CLOSED | policy-match diagnostics: duplicate selectors silently last-win/first-win across CLI/gRPC/REST → simulator certifies the |
| #3710 | CLOSED | host-inbound addressless observability (#3698) collapses to zone — misses per-interface / per-family fail-open windows i |
| #3711 | CLOSED | userspace-dp policy: malformed v3 literals + address-book prefixes silently dropped -> deny rules no-op under default-pe |
| #3712 | CLOSED | userspace-dp policy: invalid ICMP application field combinations accepted at Rust snapshot boundary -> icmp_code-without |
| #3713 | CLOSED | userspace-dp policy: duplicate rule_id / policy_id accepted -> shared hit counters + policy_id re-resolution aliasing (R |
| #3714 | CLOSED | userspace-dp policy: Rust per-application inactivity_timeout not capped to the Go/vSRX bound (86400s) -> effectively nev |
| #3715 | CLOSED | userspace-dp filter: DSCP wire fields not range-checked -> rewrite masks a corrupt value into a DIFFERENT valid code poi |
| #3716 | CLOSED | userspace-dp filter: stale port-except fail-OPEN comments contradict the #3205 fail-closed matcher; positive+except port |
| #3718 | CLOSED | host-inbound: nft rules are destination-address-only (no ingress-interface/VRF predicate) — duplicate firewall-local add |
| #3719 | CLOSED | zone-id: lenient StableZoneID collisions still publish BOTH colliding zones to the userspace wire; Rust helper accepts d |
| #3720 | CLOSED | host-inbound: physical-vs-unit override precedence is first-writer-wins — a less-specific physical ref shadows a more-sp |
| #3721 | CLOSED | perf(host-inbound): view grouping signature preserves token ORDER — semantically identical effective sets ([ssh ping] vs |
| #3723 | CLOSED | firewall stateless filters lack the application-style cross-field semantic gate: port/tcp-flags/icmp on incompatible pro |
| #3724 | CLOSED | lo0 kernel nftables mirror: unknown terminating action maps to accept while the Rust filter compiler fails closed to Dis |
| #3725 | CLOSED | pkg/appid tolerant-load port parsers mislabel sessions: tuple-fallback narrows out-of-range single port via uint16 cast  |
| #3726 | CLOSED | userspace-dp NAT: appPortsFromSpec turns a reversed application port range (200-100) into an exact low-port match [200]  |
| #3727 | CLOSED | policy simulator (pkg/policymatch matchApp) silently skips a malformed application-set expansion error and falls through |
| #3730 | CLOSED | routing/PBR: kernel FBF ip-rule mirror silently ignores ALL L4/per-packet filter predicates (protocol, ports, port-excep |
| #3731 | CLOSED | routing: next-table and rib-group Apply swallow per-rule RuleAdd failures (return only clearErr) -> transient netlink er |
| #3732 | CLOSED | ddns/surface-a: DHCP address source bypasses the IsPublicAddr public-address gate -> publishes RFC1918/CGNAT/ULA to publ |
| #3733 | CLOSED | ddns/surface-a: checkip source-bind failure falls open to the default route -> publishes the wrong WAN's public IP (resi |
| #3734 | CLOSED | ddns/surface-a: seedFromStore and the renumber log read owned.Address (always empty for Surface A) instead of AddrText - |
| #3735 | CLOSED | ddns/surface-a: provider rename / in-place provider mutation orphans the old provider's DNS record (ownership stores onl |
| #3736 | CLOSED | ddns/surface-a: checkip observation runs blocking HTTP under SurfaceAManager.mu (residual of #2778) and ignores the reco |
| #3737 | CLOSED | ddns/dyndns2: explicit server URL parser is case-sensitive on scheme and skips host/scheme validation (unlike #2842 chec |
| #3738 | CLOSED | ddns/surface-a: dual-stack same-name withdraw clears the sibling family (DuckDNS clear=true, dyndns2 offline=YES) -> bla |
| #3739 | CLOSED | ddns/surface-a: self-owned publish clobbers co-resident/foreign same-name records (Cloudflare upsert patches recs[0], Ro |
| #3740 | CLOSED | flowexport: NetFlow v9 / IPFIX exporters share a fixed SourceID/ObservationDomainID (1) + fixed template IDs (256/257) a |
| #3741 | CLOSED | flowexport: Prometheus xpf_flow_export_collector_* uses only {protocol,collector} labels -> duplicate labelset (breaks s |
| #3742 | CLOSED | flowexport: reconcile stops old exporters BEFORE building new ones -> transient NewExporter failure disables export + SE |
| #3743 | CLOSED | flowexport: route-mask RTM_GETROUTE runs synchronously inside the EventReader session-close callback -> netlink latency  |
| #3744 | CLOSED | flowexport: route-mask FIB lookup is VRF/routing-instance/table/source blind (queries the main table) and discards the o |
| #3745 | CLOSED | flowexport/config: flow-server-nested source-address collapsed to one family-wide value (last-writer-wins) -> per-collec |
| #3746 | CLOSED | flowexport: exported NetFlow/IPFIX volume ignores reverse (server->client) counters -> systematic underreport of asymmet |
| #3747 | CLOSED | flowexport: batch queue (flowBatch) is unbounded with no backpressure/drop-counter/depth visibility -> memory growth und |
| #3748 | CLOSED | flowexport: active-flow-monitoring parity gaps -- no interim active-timeout records for long-lived flows + no IPFIX samp |
| #3750 | CLOSED | event-options: revalidate queued remediation (policy existence + revision + cooldown) before commit — stale-action fail- |
| #3751 | CLOSED | event-options: strict-validate within/trigger numerics at commit — typo silently becomes always-fire (fail-open) |
| #3752 | CLOSED | event-options: engine lifecycle — day-2 enable of first policy never starts engine; removal/shutdown leaks worker + drop |
| #3753 | CLOSED | event-options: attributes-match ignores the event-name prefix (multi-event policy scoping wrong) |
| #3754 | CLOSED | event-options: autonomous remediation commits carry no audit description |
| #3755 | CLOSED | event-options: RPM first probe cycle runs before the event callback is registered — boot-time failover edge dropped |
| #3756 | CLOSED | event-options: Junos parity — attribute set + trigger on/until edge-vs-level semantics (design-fork) |
| #3757 | CLOSED | ip-monitoring: route-overlay actuator has no per-consumer convergence/retry — FRR/snapshot/FIB failures split the FIB wi |
| #3758 | CLOSED | ip-monitoring: actuateRouteOverlay can block daemon shutdown forever on applySem.Acquire(context.Background()) |
| #3759 | CLOSED | ip-monitoring: literal IPv6 link-local preferred-route next-hop commits but renders an FRR-rejected route |
| #3760 | CLOSED | ip-monitoring: PublishRouteOverlaySnapshot mutates cached desired overlay before publication succeeds |
| #3761 | CLOSED | ip-monitoring: status/metrics report PASS/applied for unknown or non-converged state |
| #3762 | CLOSED | ip-monitoring: engine lifecycle not idempotent — double Start panics, Stop-before-Start deadlocks |
| #3763 | CLOSED | ip-monitoring: hold-down pending-recovery not recomputed when hold-down value changes |
| #3764 | CLOSED | ip-monitoring: per-RG HA publication/probe gating keyed to lowest data RG only (design-fork) |
| #3766 | CLOSED | userspace-dp: same-plan runtime snapshot refresh is non-fallible and non-atomic — reports ok=true on a rejected snapshot |
| #3767 | CLOSED | userspace-dp: bump_fib_generation has no protocol-version gate, accepts generation rollback (revives stale flow-cache en |
| #3768 | CLOSED | userspace-dp: IPv6 ip-rule route-leak NextTable emitted as '.inet.0' (should be '.inet6.0') and Rust next-table recursio |
| #3769 | CLOSED | userspace-dp: NAT/DNAT non-interface local addresses are inserted into the GLOBAL local_v4/local_v6 set with no table at |
| #3770 | CLOSED | pkg/dataplane/userspace: route-snapshot dedupe key omits Discard+Preference, sort is unstable with no tie-breakers, and  |
| #3771 | CLOSED | userspace-dp: route/neighbor wire-struct integrity gaps at the Rust snapshot boundary — route.family + neighbor.family i |
| #3772 | CLOSED | pkg/dataplane/userspace: route-snapshot builder swallows netlink.RuleList errors per family (silently drops all route-le |
| #3773 | CLOSED | userspace-dp: fabric links silently skipped on malformed peer/local MAC or peer address with no counter/status, and upda |
| #3776 | CLOSED | userspace-dp flow-cache: session expiry/removal does not invalidate the cache — stale-descriptor forward + released-SNAT |
| #3777 | CLOSED | userspace-dp flow-cache: input firewall-filter 'then count' under-counts on cache hits — only the seed packet is counted |
| #3778 | CLOSED | userspace-dp flow-cache: CoS BA classifier (DSCP + IEEE 802.1p PCP) queue is frozen by the first cached packet — admissi |
| #3779 | CLOSED | userspace-dp flow-cache: TTL/Time-Exceeded check runs AFTER egress counters/policers/logs/drop on the cache-hit path — T |
| #3780 | CLOSED | userspace-dp: scheduled-policy republish is fire-and-forget — a failed UpdatePolicyScheduleState leaves stale enforcemen |
| #3781 | CLOSED | userspace-dp: ICMP AppID attribution ignores type/code — non-echo ICMP denies/sessions mislabel as junos-ping in RT_FLOW |
| #3782 | CLOSED | userspace-dp: 'clear security policies hit-count' can wipe a post-clear hit — reset() bumps generation before zeroing, r |
| #3783 | CLOSED | userspace-dp: wildcard/global-only policy deployments have no cold-path latency histogram slot — configured_zone_pairs() |
| #3789 | CLOSED | snapshot: full-reconcile + same-plan-needs-reconcile legs swallow non-policy build failure (M1 sibling of #3766) |
| #3827 | CLOSED | routing: qualified-next-hop preference leaf is untyped — bypasses the Go primary preference gate (#3771 follow-up) |
| #3830 | CLOSED | userspace-dp NAT: NatRuleCounter::reset uses store(0) — same clobber class as #3782 (narrower, cold-path) |
| #3842 | CLOSED | policy: duplicate inner match/then blocks silently dropped + bypass all 6 strict gates → policy widens (fable-161 F-006) |
| #3843 | CLOSED | firewall filter: hierarchical single-name source/destination-prefix-list leaf silently drops the scoping constraint → fa |
| #3844 | CLOSED | NAT: 'then destination-nat off' compiles to empty exemption → traffic still DNAT'd by later rules (fail-open) (fable-161 |
| #3846 | CLOSED | config: 'delete ... <multi-leaf> <member>' deletes the WHOLE bracket-list, not just the member (fail-wide) (fable-161 F- |
| #3849 | CLOSED | scheduler: compileSchedulers never descends into 'daily { start-time/stop-time }' → time-restricted permit runs 24/7 (fa |
| #3850 | CLOSED | config: NAT-rule + filter-term duplicate match/then blocks still read first-block-only (fail-open sibling of #3842) |
| #3851 | CLOSED | ipsec: normalizeAuthAlg strips all dashes → canonical Junos 'hmac-sha-256-128' becomes strongSwan-invalid → whole ESP pr |
| #3854 | CLOSED | config: quoteKey escapes quotes but not backslashes → Format→Parse round-trip corrupts values (incl IKE PSK) → HA config |
| #3855 | CLOSED | routing: routing-instance kernel TableIDs are positional → deleting/reordering one renumbers survivors → vrf.go recreate |
| #3857 | CLOSED | userspace-dp NAT: DNAT rule with match application + destination-port widens invalid port to wildcard [0,0] on lenient/p |
| #3860 | CLOSED | scheduler: warn at commit when a scheduler defines no window (silent always-on→fail-closed migration surface) |
| #3861 | CLOSED | configstore: plain Store.Commit / SyncApply during a commit-confirmed window does not stop the timer → newer commit sile |
| #3863 | CLOSED | config: WireGuard tunnel local identity (listen-port/private-key) never validated at commit → malformed value commits cl |
| #3864 | CLOSED | NAT: deterministic (CGNAT) source-nat is un-configurable via flat-set — sibling 'port deterministic' leaves overwrite +  |
| #3867 | CLOSED | config archive: transfer-on-commit scps the boot-time /etc/xpf/xpf.conf (never rewritten since configstore became DB-can |
| #3868 | CLOSED | HA: commit-confirmed timeout rollback reverts only the active node — standby keeps the unconfirmed config as permanent a |
| #3870 | CLOSED | routing: 'routing-options autonomous-system' parsed but never feeds BGP → canonical vSRX BGP config renders no BGP at al |
| #3871 | CLOSED | routing: qualified-next-hop preference/metric declared but folded into a single route-level Preference → floating static |
| #3872 | CLOSED | routing: static route 'next-hop [ gw1 gw2 ]' bracket list collapses to one next-hop → canonical Junos ECMP silently lose |
| #3874 | CLOSED | syslog: octet-counted (RFC 6587) stream write-timeout can leave a partial frame on the wire → permanent framing desync a |
| #3876 | CLOSED | routing: rib-group import ip-rule at pref 33000 sits AFTER main (32766) → default route shadows it → imported interface  |
| #3878 | CLOSED | event-stream: cross-worker seq allocate/enqueue not atomic + Go reader zero reorder tolerance → out-of-order frame → spu |
| #3881 | CLOSED | routing: hierarchical inline-keys static route drops 'interface' modifier → IPv6 link-local next-hop unresolvable (Copil |
| #3882 | CLOSED | WireGuard: responder rekey promotes an UNCONFIRMED session straight to current (no 'next' keypair slot) → peer-initiated |
| #3884 | CLOSED | firewall: non-inet6 filter family folds into FiltersInet → a same-name cross-family filter overwrites the IPv4 filter (d |
| #3886 | CLOSED | NAT64: no commit gate on 'prefix' — a non-/96 or malformed prefix commits green then the Rust helper aborts the ENTIRE f |
| #3888 | CLOSED | userspace-dp NAT64: try_from_snapshots aborts the ENTIRE forwarding rebuild on one bad rule — skip the bad rule + publis |
| #3889 | CLOSED | daemon: super-user sudoers NOPASSWD grant (/etc/sudoers.d/xpf-<user>) never revoked on class downgrade or user removal ( |
| #3890 | CLOSED | applications: typo'd application-set member keyword silently dropped, no commit gate → deny application-set under-popula |
| #3893 | CLOSED | configstore: clusterReadOnly enforced only at EnterConfigure* — an already-open session can Set/Commit on the read-only  |
| #3895 | CLOSED | RA: an over-large PREF64/router lifetime makes ndp.PREF64 marshal fail → the ENTIRE Router Advertisement is aborted → th |
| #3896 | CLOSED | IKE: gateway 'version' / policy 'mode' / 'nat-traversal' are untyped free-form leaves → a typo silently un-pins IKEv2-on |
| #3898 | CLOSED | interfaces: per-unit tunnel inheritance shallow-copies Addresses/WgPeers slice headers → a unit inherits sibling units'  |
| #3900 | CLOSED | config: annotations emitted verbatim into /* */ comments — an annotation containing '*/' injects tokens into the re-pars |
| #3902 | CLOSED | screen: flowless packet path bypasses source-independent screens (LAND, icmp/udp-flood, ip-source-route) for non-query I |
| #3904 | CLOSED | config: multiple bracket-list leaves truncate to the first value — IKE/IPsec proposals, RIP export/redistribute, routing |
| #3906 | CLOSED | NAT: SNAT pool 'port range <low> to <high>' and 'port no-translation' silently ignored → default 1024-65535 PAT; reverse |
| #3908 | CLOSED | screen: flowless path silently returns Pass on a zone with no resolved screen profile (missing #3082 warn parity) |
| #3909 | CLOSED | security: syn_cookie_master_key serialized into world-readable state.json (no skip_serializing, unlike WG keys) → local  |
| #3912 | CLOSED | cluster-sync: pendingBulkAckEpoch stored AFTER writing BulkEnd → ack-before-store TOCTOU latches a phantom pending epoch |
| #3915 | CLOSED | NAT: compileNAT reads only the FIRST source/destination/static/nat64/proxy-arp block per nat node → a duplicate hierarch |
| #3917 | CLOSED | HA: OnFenceReceived iterates the STARTUP config snapshot → day-2 redundancy-groups are never fenced → split-brain dual-a |
| #3918 | CLOSED | flow-cache: neighbor_mac_epoch stamped AFTER neighbor resolution → TOCTOU re-opens the #3048 stale-MAC blackhole on VRRP |
| #3920 | CLOSED | HA: renameRethMember downs the RETH member for rename and never brings it up; programRethMAC early-returns (MAC already  |
| #3922 | CLOSED | HA: directSendGARPs gateway probe forces the last octet to .1 → broken on /25+ subnets → post-failover blackhole in defa |
| #3924 | CLOSED | userspace maps-sync: a transient netlink AddrList failure prunes VRRP VIP keys from userspace_local_v4/v6 → blackholes V |
| #3926 | CLOSED | cluster-sync: session deletes journaled while CONNECTED (sendCh full) are never flushed until a full disconnect → standb |
| #3929 | CLOSED | observability: GC session stats never written on the userspace dataplane path → SessionCount / xpf_sessions_active estab |
| #3931 | CLOSED | cluster config-sync: applies via unordered goroutines with no sequence number → a rapid commit pair can leave the standb |
| #3932 | CLOSED | daemon: updateFlowTrace leaks one EventReader callback per commit → O(commits) callbacks + false trace-rotation alarm (f |
| #3934 | CLOSED | feeds: dynamic address-feed fetch has no body-size / entry cap → OOM (plaintext-http MITM can amplify into a remote OOM  |
| #3937 | CLOSED | ipsec: parseSAOutput parses a swanctl format that swanctl never emits → all IPsec SA status (show security ipsec sa) is  |
| #3939 | CLOSED | flowexport: NetFlow/IPFIX protocolIdentifier is 0 for GRE/ESP/non-TCP-UDP-ICMP flows (uses the parsed protocol NAME not  |
| #3941 | CLOSED | ipsec: deleting an IPsec VPN never terminates its live SAs (--load-all only unloads config) → the tunnel stays UP after  |
| #3942 | CLOSED | frr: GetBGPSummary parses table trailer lines as phantom peers + never sets PfxRcd → 'show bgp summary' shows bogus peer |
| #3944 | CLOSED | routing: routeToEntry ignores netlink MultiPath → ECMP (multipath) routes are displayed as a bare 'direct' route with on |
| #3947 | CLOSED | userspace-dp policy: legacy address parser drops a bare 'any' when mixed with literal addresses → the term/deny narrows  |
| #3948 | CLOSED | snmp: trap-group 'version' has no typed field → a configured v1 trap-group emits v2c traps (fable-161 F-069) |
| #3950 | CLOSED | networkd: monitorLinkState exits permanently on a netlink ENOBUFS (no resubscribe) → interface up/down changes stop bein |
| #3952 | CLOSED | ipsec: swanctl PSK secrets carry no 'id' selectors → with 2+ PSK VPNs the wrong PSK is matched to a peer (fable-161 F-17 |
| #3954 | CLOSED | networkd/RSS: idempotence probe misparses 'ethtool -x' when the RSS key's first byte is decimal → spurious 'ethtool -X'  |
| #3956 | CLOSED | dhcp: DHCPv4 client treats a RENEWING-state DHCPNAK like a timeout → keeps using the revoked address until T2 instead of |
| #3958 | CLOSED | config validation: ValidateConfig warns 'address not in address-book' for literal addresses / any / feed-names / address |
| #3960 | CLOSED | dhcp relay: giaddr not re-resolved on a same-ifindex interface address change → the relayed reply path silently breaks ( |
| #3962 | CLOSED | userspace-dp: buildScreenSnapshots iterates zones in map (unsorted) order → nondeterministic wire byte-order defeats the |
| #3965 | CLOSED | observability/perf: ReadPolicyCounters is O(P·(P+C)) and holds the policy mutex for the whole Prometheus scrape → scrape |
| #3967 | CLOSED | snmp: SNMP agent / trap-groups configured after boot are inert until restart (day-2 config not reconciled) (fable-161 F- |
| #3968 | CLOSED | userspace-dp CoS: build_cos_batch never clears pop_snapshot_stack across invocations → unbounded scratch growth (and/or  |
| #3970 | CLOSED | control-socket: fwdstatus Sampler does a redundant 1Hz control-socket poll on top of the status poll → violates the >1/s |
| #3972 | CLOSED | config: one invalid port-mirroring entry (duplicate ingress / negative rate) fail-closes the WHOLE mirror table with onl |
| #3975 | CLOSED | config: deactivate on a bracketed multi-value leaf mishandles it (setInactiveAtPath lacks the #2419 multi-value handling |
| #3976 | CLOSED | userspace-dp: non-TCP 'then reject' sources the ICMP-reject reply from the physical PARENT ifindex instead of the VLAN s |
| #3979 | CLOSED | config-mode: 'configure exclusive' lock is never released on session exit (exclusiveHolder checked but configHolder clea |
| #3980 | CLOSED | config display: 'show configuration' / 'show   display set' renders only the FIRST occurrence of a repeated keyword stat |
| #3982 | CLOSED | config-mode: 'rename' of a non-first same-keyword sibling fails (matches only the first sibling) → cannot rename the 2nd |
| #3984 | CLOSED | config: keyed-list leaves 'system ntp server' / 'archive-sites' are non-multi {args:1,children:nil} → SetPath single-val |
| #3985 | CLOSED | cli: 'monitor interface' leaves a stdin-reading goroutine alive after exit → it steals keystrokes from the next command  |
| #3988 | CLOSED | config: scheduler start/stop date-time parsed as UTC (or wrong TZ) instead of the system local time → schedulers activat |
| #3992 | CLOSED | userspace-dp WireGuard: wg_encap resolves the outer (underlay) route TWICE per encapsulated packet → redundant per-packe |
| #3993 | CLOSED | config CoS: a rewrite-rule term with an inline loss-priority drops the loss-priority (only the code-point/forwarding-cla |
| #3994 | CLOSED | config IKE: dead-peer-detection with a bare 'dead-peer-detection;' statement (or interval-only) is misinterpreted — the  |
| #3995 | CLOSED | userspace-dp CoS: DSCP/802.1p rewrite-rule does not MATCH on loss-priority at apply time → per-loss-priority rewrite map |
| #3996 | CLOSED | config: prefix-list definition with multiple prefixes collapses (the prefix-list body keeps only some prefixes) → route- |
| #4000 | CLOSED | config commit: a bare 'commit' while a 'commit confirmed' window is pending silently DROPS newly-staged candidate edits  |
| #4001 | CLOSED | proxy-arp: proxyARPReassertLoop re-installs responders without the apply semaphore → races a concurrent commit reconcile |
| #4002 | CLOSED | userspace-dp CoS: residual-surplus admission uses a per-worker split of a shared atomic → each of N workers admits the F |
| #4005 | CLOSED | cli: 'monitor traffic matching "<filter>"' truncates the pcap filter to the FIRST token → a multi-token filter (tcp port |
| #4006 | CLOSED | build/test: 'make test' runs only the Go suite, never the Rust userspace-dp cargo suite → a Rust dataplane regression pa |
| #4008 | CLOSED | appid: an application/term with an explicit 'protocol 0' (or protocol omitted defaulting to 0) matches BOTH TCP and UDP  |
| #4009 | CLOSED | test/cluster-deploy: the secondary-node detection grep never matches → cluster-deploy stops the PRIMARY node first ~50%  |
| #4011 | CLOSED | userspace-dp test: tx_latency_hist_cross_thread_snapshot_skew_within_bound is a load-sensitive cross-thread timing flake |
| #4013 | CLOSED | snmp: an ifTable GETBULK walk does a live netlink LinkList (RTM_GETLINK) TWICE per returned varbind → an O(interfaces²)  |
| #4015 | CLOSED | df-bit set/clear action is inverted → 'set df-bit clear' clears nothing (sets DF) and 'set df-bit set' sets nothing → wr |
| #4017 | CLOSED | image bake: bake.py signs the appliance image BEFORE the validation gate → a FAILED/invalid image is signed and publisha |
| #4020 | CLOSED | test: destructive HA smoke targets (test-failover / test-ha-crash reboot the SHARED loss cluster) do NOT take the #1875  |
| #4021 | CLOSED | config CoS: interface-level class-of-service (applied at the physical interface, no unit) is dropped → only per-unit CoS |
| #4024 | CLOSED | userspace-dp: a flowless (session-less) non-first-fragment with a MissingNeighbor result is FIB-reinjected as transit, B |
| #4027 | CLOSED | config: an 'interfaces interface-range' definition creates a phantom interface entry that is brought admin-down (the ran |
| #4028 | CLOSED | cluster: handleEventStreamFullResync hardcodes RG 0..15 → a cluster with redundancy-group >= 16 never re-exports those R |
| #4031 | CLOSED | cluster: monitorFabricState exits + leaks a sibling netlink socket when its subscription channel closes (no resubscribe) |
| #4033 | CLOSED | cluster: heartbeat retry loop ignores commsCtx (doesn't stop on cancel) + StartHeartbeat overwrites a running heartbeat  |
| #4034 | CLOSED | cluster: a non-fatal error in the tail of the config apply path skips syncConfigToPeer → the standby never receives the  |
| #4036 | CLOSED | control-socket: a fixed 3s read deadline is too short for a large (up to 64MB) apply_snapshot → a big dynamic-feed / lar |
| #4038 | CLOSED | cluster: a single fabricRefreshCh is consumed by ONE fabric goroutine → in a dual-fabric (fab0+fab1) cluster the second  |
| #4041 | CLOSED | userspace-dp: the debug-log direct-TX path double-pushes tx_offset on a tuple-mismatch → duplicate free-list entry alias |
| #4043 | CLOSED | lldp: received LLDP TLV strings (system-name / port-description / system-description) are logged + displayed without san |
| #4044 | CLOSED | lldp: the received-neighbor table is unbounded → an LLDP frame flood (many spoofed chassis/port ids) grows it without li |
| #4047 | CLOSED | web-management: the REST/config API binds to a non-loopback address without requiring api-auth → unauthenticated mutatin |
| #4049 | CLOSED | lldp: LLDP fails to start on Junos slash-named interfaces (ge-0/0/0) — net.InterfaceByName is called with the Junos name |
| #4051 | CLOSED | config API: raw-AST render paths (REST show/export/search/rollback + gRPC ShowConfig) emit cleartext PSK / auth-key / SN |
| #4052 | CLOSED | test: test-failover.sh preflight session-count check is racy — asserts >= MIN_SESSIONS the instant iperf3 -P8 starts (be |
| #4053 | CLOSED | observability: 'show security flow session' per-session Pkts/Bytes counters read 0 on the AF_XDP fast path despite heavy |
| #4054 | CLOSED | userspace-dp: export_all_sessions runs push_delta_lossless / frame serialization UNDER the global lock → a large session |
| #4056 | CLOSED | config store: rollback slots / archive files / rescue.conf write the FULL config (incl IKE PSK, keys, community) as 0644 |
| #4059 | CLOSED | security policy: a to-zone junos-host DENY/REJECT policy is not enforced for DIRECT host-bound traffic (host-inbound ser |
| #4060 | CLOSED | config commit: reject the ##SECRET-DATA## redaction placeholder on commit-ingest (mirror errRedactedSecretIngest) → re-a |
| #4061 | CLOSED | VRRP: a BACKUP does not adopt the MASTER's advertised interval (Master_Adver_Interval) → uses its own configured interva |
| #4065 | CLOSED | userspace-dp: a GRE/IPIP packet whose OUTER header is unparseable is handled inconsistently with #2410's malformed-tunne |
| #4066 | CLOSED | show security nat: the per-rule hit-count column displays the per-zone-pair TOTAL for every rule → each NAT rule appears |
| #4067 | CLOSED | RBAC: a read-only / config-viewer login-class user can run 'monitor traffic' (which spawns a root tcpdump on a data inte |
| #4069 | CLOSED | userspace-dp HA: the RG-activation reverse-prewarm uses O(N·M) Vec::contains (linear membership per session) → slow fail |
| #4070 | CLOSED | config apply-groups: an apply-groups reference suppresses a group's LEAF-LIST value (a multi-value leaf inherited from t |
| #4071 | CLOSED | GRE keepalive: a configured 'gre keepalive' (interval/threshold) is a silent no-op on the userspace dataplane — keepaliv |
| #4073 | CLOSED | routing: next-table inter-VRF routes are installed WITHOUT the ip-rule needed to reach the target table, and the global  |
| #4074 | CLOSED | userspace-dp NAT: pool source-NAT (PAT) does not translate the ICMP query id for ICMP echo/query traffic (RFC 5508 §3.1) |
| #4076 | CLOSED | routing: anchor-path keepalive should bump linkGen on a transient-lookup-error + device-vanished recreate (parity with t |
| #4077 | CLOSED | config: the NAT source-pool utilization alarm (pool-utilization-alarm raise-threshold / clear-threshold) rejects a raise |
| #4078 | CLOSED | config: 'system archival configuration transfer-interval' (periodic config archive on a timer) is accepted but not imple |
| #4080 | CLOSED | VRRP: 'accept-data' (allow the VRRP master to accept/respond to traffic addressed to the VIP it doesn't own as a real ad |
| #4082 | CLOSED | userspace-dp HA: cross-chassis fabric redirect pins the fabric egress to fabrics[0] (the first fabric link) → a dual-fab |
| #4083 | CLOSED | cluster HA: the fallback full BulkSync (when incremental session sync falls behind / on reconnect) may race with concurr |
| #4084 | CLOSED | cluster HA: the standby sync-HOLD may be released (VRRP preempt-eligible) before the userspace dataplane has finished lo |
| #4085 | CLOSED | firewall filter: a term with BOTH an input-filter action and a 'count' action may double-count a packet (counted on the  |
| #4088 | CLOSED | userspace-dp NAT: pool SNAT misclassifies an ICMP echo with identifier 0 as flowless → id==0 reintroduces the (pool_addr |
| #4089 | CLOSED | userspace-dp NPTv6: verify the RFC 6296 checksum-neutral prefix translation handles the 0xFFFF (ones-complement zero) re |
| #4090 | CLOSED | cluster HA: the full session BulkSync streams over a single fabric connection with no fallback if that fabric link is do |
| #4091 | CLOSED | userspace-dp: verify the routing/prefix-match structure isn't stored as an uncompressed/multibit trie consuming 100s of  |
| #4092 | CLOSED | WireGuard: verify the handshake TAI64N timestamp handling (monotonic per-peer replay-protection greatest-timestamp check |
| #4093 | CLOSED | userspace-dp: verify the fabric cross-chassis forwarding hit path does not allocate per-packet (a String/Vec/heap alloc  |
| #4094 | CLOSED | WireGuard: verify the cookie-reply / mac2 under-load DoS-mitigation handling (RFC/WG cookie mechanism) is implemented or |
| #4096 | CLOSED | userspace-dp: verify whether pending_tx_admitted (AtomicUsize, umem/mod.rs:705) suffers cross-core false-sharing on the  |
| #4097 | CLOSED | security: FRR community-list members and as-path regexes are rendered into frr.conf verbatim (bypassing sanitizeFRRValue |
| #4098 | CLOSED | security: IPsec local_ts/remote_ts traffic selectors are rendered into swanctl.conf unsanitized + uncommit-validated — c |
| #4099 | CLOSED | security: local interactive CLI 'show configuration' is not secret-redacted — a read-only / config-viewer login class pr |
| #4100 | CLOSED | VRRP: IPv4 VRRPv3 advertisement checksum omits the RFC 5798 §5.2.8 IPv4 pseudo-header (IPv6 leg has it) → total advert r |
| #4101 | CLOSED | security: DHCPv4 client installs YourIP/0 on-link when a rogue/broken server sends a zero or non-contiguous subnet mask  |
| #4102 | CLOSED | vsrx-parity: predefined Junos application-SETS (junos-ms-rpc, junos-sun-rpc, junos-cifs, junos-routing-inbound) are abse |
| #4103 | CLOSED | WireGuard hardening: (F5) #4092 responder TAI64N anti-replay high-water resets to 0 on every WG config change — a routin |
| #4107 | CLOSED | security: the gRPC fabric listener registers the FULL mutating+destructive 48-RPC service with no auth (remote SystemAct |
| #4108 | CLOSED | security/RBAC: the 'operator' login class can request system zeroize/reboot/halt/power-off (Junos operator lacks mainten |
| #4109 | CLOSED | security/DoS: TCP half-open→ESTABLISHED promotion fires on ANY ACK-bearing segment (no reverse SYN-ACK required, defeats |
| #4111 | CLOSED | security: SNMP community string is printed cleartext to view-only login classes by 'show system services' + 'show snmp'  |
| #4112 | CLOSED | screen: icmp/udp flood thresholds are enforced per-ZONE aggregate (Junos measures per destination IP, UDP per dest IP+po |
| #4113 | CLOSED | XDP shim: record_trace forces a per-packet BPF map insert on EARLY_FILTER/BINDING_MISSING even when tracing is disabled  |
| #4114 | CLOSED | screen: port-scan/ip-sweep 'threshold' is a distinct-destination COUNT over a fixed 10s window — Junos 'threshold' is a  |
| #4116 | CLOSED | VRRP: an address-owner (priority 255) with preempt disabled never reclaims mastership from a lower-priority peer — RFC 5 |
| #4117 | CLOSED | IPsec: ESP proposals silently fall back to strongSwan 'default' suite when a policy's proposal reference dangles with no |
| #4118 | CLOSED | vsrx-parity: DHCPv4 client ignores classless-static-routes (RFC 3442 option 121 / legacy 249) — only option 3 default ga |
| #4119 | CLOSED | RA: 'router-advertisement default-lifetime 0' is both commit-rejected and runtime-coerced to 1800 — xpf cannot advertise |
| #4120 | CLOSED | code-quality: leftover test-env 'is_trust_flow' hardcode (ifindex==5    zone=='lan'    10.x src) gates debug logging in  |
| #4121 | CLOSED | refactor: compiler_security.go is a 2357-line grab-bag mixing zones/policies/screen/address-book/log/flow/ALG + a dozen  |
| #4122 | CLOSED | security: add a fail-closed fabric-gRPC allowlist interceptor so the cluster fabric listener exposes ONLY the 6 read/mon |
| #4146 | OPEN | host-inbound: to-zone junos-host deny not enforced for direct host-bound traffic — the XDP shim shunts local-destined pa |
| #4147 | CLOSED | config lexer: an unterminated /* */ block comment silently truncates the config with zero parse errors — dropped securit |
| #4148 | CLOSED | config parser: unbounded lexer/parser recursion crashes xpfd on a sub-4MiB config load or HA config-sync (unrecoverable  |
| #4150 | CLOSED | api: management HTTP server has no read/header/idle timeouts (slowloris) and REST mutation handlers have no request-body |
| #4151 | CLOSED | cluster config-sync: generation high-water mark advances before the config is applied, silently stranding a diverged sta |
| #4155 | CLOSED | screen: rate-based flood screens re-run on the owner node for fabric-redirected (already-screened) traffic, double-count |
| #4156 | CLOSED | ip-monitoring: ICMP echo-reply probe accepts any reply — source address, ICMP identifier, and sequence number are never  |
| #4157 | CLOSED | api: API-key/Bearer auth uses non-constant-time comparison (map lookup / == ) — timing side channel leaks the valid toke |
| #4161 | CLOSED | source-NAT: rule-set precedence is config-order first-match, not Junos most-specific-scope-wins (interface > zone > rout |
| #4162 | CLOSED | observability: /metrics bypasses auth and walks the entire v4+v6 session table on every scrape (unauth DoS + hot-path co |
| #4163 | CLOSED | dhcp-relay: server replies forwarded to clients without validating the source against the configured server set (rogue-r |
| #4167 | CLOSED | screen: IPv4 L3-header extraction fails OPEN on a too-short header while IPv6 fails closed (malformed-packet screen bypa |
| #4170 | CLOSED | screen: alarm-without-drop (audit/log-only mode) is hard-rejected — no Junos screen monitoring mode |
| #4171 | CLOSED | libvirt deploy: an HA pair attaches the SAME writable golden qcow2 to both VMs — concurrent writes corrupt the image |
| #4172 | CLOSED | image/packaging: frr-pythontools missing from the baked image and xpf-appliance metapackage — frr-reload.py permanently  |
| #4175 | CLOSED | day-0 config-drive: retry is permanently dead — loader guards on bare .configdb directory existence, which xpfd creates  |
| #4178 | CLOSED | interface naming: positional rename loop corrupts the .link OriginalName= chain on an enumeration shift (no collision di |
| #4179 | CLOSED | HA naming: a node with node-id but no config takes all NICs with standalone names and never re-runs naming when the clus |
| #4180 | CLOSED | libvirt deploy: role validation ignores the guest virtio-first PCI tiebreaker — a virtio NIC after a hardware NIC silent |
| #4183 | CLOSED | Day-0 gate weaker than interactive commit: check-config and bootstrapFromFile skip the device-map strand-management pref |
| #4184 | CLOSED | Bootstrap/day-0 import failure is journald-only: no /health field, no event surface |
| #4185 | CLOSED | Dual node identity (/etc/xpf/node-id file vs chassis cluster node leaf) never cross-checked; file parser laxer than ever |
| #4186 | CLOSED | Every factory boot logs 'failed to bootstrap config from file ... no such file or directory' as a WARN |
| #4187 | CLOSED | test: NAT64 cross-family (V6-src/V4-dst) policy exclusion + empty-set fail-closed arm has zero test coverage |
| #4188 | CLOSED | xpf-deploy libvirt: physical backing passes a netdev name to virt-install --hostdev (invalid spec) |
| #4189 | CLOSED | xpf-deploy fetch: anti-rollback watermark mis-orders git-describe counts and rc numbers (string compare) |
| #4190 | CLOSED | xpf-deploy: fetch qcow2 output path never reaches the libvirt golden path deploy expects |
| #4194 | CLOSED | docs/bare-metal-device-map.md: quick-start step 3 says 'commit check' confirms a 'commit confirmed' — it does not (rolls |
| #4195 | CLOSED | docs/deploy-quickstart.md: standalone 'two commands' fails on a fresh host — bridge prerequisites (and their DHCP form)  |
| #4196 | CLOSED | examples/deploy: standalone.conf/ha-pair.conf ship no root-authentication — SSH enabled but unusable, and vSRX would ref |
| #4197 | CLOSED | install.sh Tier-A one-liner cannot succeed: no publish-time bake for XPF_APT_BASE_URL (fable-165 H-2) |
| #4198 | CLOSED | Publisher runbook dead-ends: no tooling substitutes the real archive key into install.sh; gate treats install.sh as opti |
| #4199 | CLOSED | install.sh mutates host before validating inputs; failed install leaves a dangling apt source that breaks apt update (fa |
| #4201 | CLOSED | apt channel isolation does not exist: one shared pool re-indexed into whichever suite is rebuilt (HB165 H-4) |
| #4202 | CLOSED | deb ships xpf-kernel-promote.service but not its OnFailure= recovery unit — dangling reference on every deb-installed ho |
| #4203 | CLOSED | No cross-check that install.sh embedded key, packaged keyring, and InRelease signer agree (HB165 H-15) |
| #4204 | CLOSED | xpf-deploy: hypervisor-command failures surface as a bare CalledProcessError traceback, swallowing the real error (fable |
| #4205 | CLOSED | xpf-deploy: --no-start is silently ignored on libvirt, and both docs claim the tool 'emits a command you run' when it ex |
| #4206 | CLOSED | xpf-deploy: no preflight, no cleanup, no destroy verb — partial deploys dead-end and re-runs fail on 'already exists' (f |
| #4209 | CLOSED | Image validation gate (validate.py) lacks libvirt/QEMU boot, cluster node-id, and reject-fix-reboot retry scenarios (fab |
| #4210 | CLOSED | Day-0/image/dist self-tests are wired into nothing — no single runner or gate executes them (fable-165 H-19) |
| #4211 | CLOSED | xpf-deploy.py mixed-base HA safety gate (_gate_mixed_base) + core pure functions have no test coverage (fable-165 H-24) |
| #4214 | CLOSED | publish.py orphan sweep is suffix-shaped: unsigned dist/deb/*.deb ride the image tree unchecked (HB165 H-5) |
| #4215 | CLOSED | publish.py gate_latest verifies only --channel's latest.json; other channels' pointers ship unverified (HB165 H-13) |
| #4217 | CLOSED | CoS schema: shaping-rate/burst-size leaves untyped — garbage commits as 0, silently removing the shaper (G-4) |
| #4218 | CLOSED | CoS schema: codel-target has no schema leaf, no commit warning, silently drops garbage values (G-3) |
| #4219 | CLOSED | CoS schema: oversubscription-policy + priority-low-min-share missing from setSchema — no completion, no typed validation |
| #4220 | CLOSED | priority-low-min-share (#1614 A2) is inert but labeled as enforced: misleading Rust comment + doc gate + no schema/warni |
| #4221 | CLOSED | CoS binding on a nonexistent interface/unit is a silent no-op (hb166 G-6) |
| #4222 | CLOSED | class-of-service fairness rss-expectation keyed by kernel ifindex is silently wrong after NIC re-enumeration (hb166 G-9) |
| #4223 | CLOSED | Level-vs-unit CoS merge: unit shaping-rate override inherits the interface-level burst-size (hb166 G-10) |
| #4226 | CLOSED | class-of-service: a dangling scheduler reference in a scheduler-map is warn-only at commit then fails open in the datapl |
| #4228 | OPEN | class-of-service: vSRX CoS parity gaps (grouped) — 7 gaps enumerated |
| #4230 | CLOSED | Zone-pair from-zone junos-host policies commit clean but are inert; code comment + CLI reference falsely claim rejection |
| #4231 | CLOSED | Five security flow knobs commit clean with zero parsing and zero advisory (sync-icmp-session is dangerous in HA) |
| #4232 | CLOSED | Unimplemented ALG stanzas and unknown policy <name> children are silently dropped (no advisory) |
| #4233 | CLOSED | security policies policy-rematch commits clean and is silently dropped (no advisory) |
| #4234 | CLOSED | No session invalidation on commit: sessions of a deleted/modified policy keep forwarding (Junos default + policy-rematch |
| #4235 | CLOSED | docs: policy-based IPsec VPN (then permit tunnel ipsec-vpn) has no explicit gap row |
| #4236 | CLOSED | docs: vsrx-gaps.md is stale and feature-gaps.md has internal contradictions (parity docs misrepresent posture) |
| #4239 | CLOSED | cos-simul-load-smoke.sh can never fail: gate booleans computed, printed, and discarded (exits 0 on FAIL) |
| #4240 | CLOSED | cos-gate1-small-four-alone.sh always exits 0: prints GATE1 FAIL yet returns success |
| #4241 | CLOSED | fairness-harness.sh single mode silently defaults SHAPER_RATE_BPS=25G for unknown ports (masks misconfig as pass) |
| #4243 | CLOSED | CoS TX: any egress output filter (even counter/log-only) cancels input-filter forwarding-class classification |
| #4244 | CLOSED | CoS TX: BA classifier code-point mapping to an unmaterialized queue is a 100% silent blackhole (commits cleanly) |
| #4245 | CLOSED | class-of-service: fairness-mechanism design findings (R-2/R-5/R-7/T-1/T-6) — converged plans |
| #4246 | CLOSED | cos: v8 lease give-back never re-credits the epoch ledger — released bytes double-charged (candidate #1630 cause-2 fix) |
| #4247 | CLOSED | cos-simul-load-smoke CoV diverges from the Rust fairness SSOT (sample stddev + zero-flow filtering) |
| #4248 | CLOSED | surplus give-back validator: lax handback derivation + no live runner produces phases.json |
| #4249 | CLOSED | Minor CoS harness cleanups: dead _last_n_sum_bps, omitted-row parse hazard, fail-closed/cadence docs |
| #4254 | CLOSED | cos: cross-worker V_min gate compares absolute vtimes — a reset/rejoining worker at vtime~0 permanently traps peers in t |
| #4256 | CLOSED | waterfill Phase-1 honor consumed at SELECTION not SERVICE — a zero-byte TX burns the small class's 200us epoch guarantee |
| #4257 | CLOSED | unshaped (rate=0) flow-fair queue: #717 delay-cap computes 0, collapsing flow-aware buffer expansion — resurrects #704/# |
| #4259 | CLOSED | CoS MQFQ: stale flow_bucket_observed_bps survives flow death — cap-aware selector defers newcomers with a dead elephant' |
| #4260 | CLOSED | CoS v8 epoch seqlock writer: missing Release fence after EVEN->ODD claim — torn snapshots on weakly-ordered CPUs |
| #4261 | CLOSED | CoS token-bucket refill: fractional dust discarded each refill — low-rate classes systematically under-run |
| #4262 | CLOSED | cos: surface waterfill phase1_selected_no_progress counter via Prometheus + show formatter |
| #4265 | CLOSED | cos: non-exact guaranteed classes admitted at up to N_workers x configured rate on shared interfaces (per-worker full-ra |
| #4267 | CLOSED | cos: TX-path MEDIUM cluster fixes (fable-166 T-6, READY sub-items) |
| #4269 | CLOSED | CoS dataplane: grouped LOW correctness/robustness findings (fable-166 R-8) |
| #4270 | CLOSED | CoS perf: false sharing on worker_active_flow_buckets + timer-wheel per-slot allocations (fable-166 R-9) |
| #4272 | CLOSED | cos: non-shared_exact cos_flow_fair path uses buffer_limit.div_ceil(prospective_active) without .max(1) (latent panic if |
| #4273 | CLOSED | fairness-eval: Gate 3 aggregate-throughput leg is vacuous (saturation label == gate predicate) |
| #4274 | CLOSED | fairness-eval: a_i overcount trim removes from the LARGEST bucket, which can RAISE Cstruct and loosen Gate 2 |
| #4275 | CLOSED | fairness-eval: CoS-source {a_i} medians ignore absent (zero) samples — dead workers stay active |
| #4276 | CLOSED | fairness-eval: steady window anchored to scrape-file min/max, not the iperf epoch — stale pre-run samples leak in |
| #4277 | CLOSED | fairness-eval: 60s steady-state minimum checks DECLARED duration, not observed samples; omitted intervals unfiltered |
| #4278 | CLOSED | fairness-eval: verdict omits doc-mandated required metrics (per-flow quantiles, window timestamps, saturation series) |
| #4280 | CLOSED | test: Rust CoS core test-coverage gaps (fable-166 R-10, consolidated) |
| #4282 | CLOSED | cos: two owner-lifecycle accounting gaps (CoS-submit tx_packets/tx_bytes not bumped; no dehydrate counterpart to rehydra |
| #4283 | CLOSED | cos: TX-path LOW cluster + stats-that-lie counter-correctness fixes (fable-166 T-7) |
| #4285 | CLOSED | OSPF/OSPFv3 interface timers + DR priority silently dropped — adjacency will not form with a fast-timer neighbor |
| #4286 | CLOSED | BGP local-address (update-source) + passive/hold-time/per-group local-as silently dropped — iBGP loopback peering will n |
| #4287 | CLOSED | firewall family any filter loses the IPv6 arm - a family any discard fails open for v6 |
| #4288 | CLOSED | VRRP authentication-type/authentication-key parsed but never enforced - false-security posture (VRRPv3 has no auth) |
| #4289 | CLOSED | SNMP community clients source-IP restriction silently ignored (allow-all) |
| #4290 | CLOSED | NAT: then static-nat prefix-name <addr> compiles to an EMPTY translation target (silent broken static NAT) |
| #4291 | CLOSED | NAT: port-overloading off / port-overloading-factor silently dropped (false src-port hardening) |
| #4292 | CLOSED | NAT: translation-target routing-instance (then static-nat ... routing-instance, pool routing-instance) silently dropped |
| #4296 | CLOSED | firewall: family-specific matches inside a family any filter are dual-compiled verbatim (imperfect v6 under-block on non |
| #4297 | CLOSED | IPsec: proposal-set standard basic compatible suiteb-* unusable — common vSRX crypto shorthand cannot commit a working t |
| #4298 | CLOSED | IPsec: proposal protocol ah silently rendered as ESP with a fabricated cipher (crypto misrepresentation) |
| #4299 | CLOSED | IPsec: security ipsec vpn vpn-monitor silently dropped (no advisory) |
| #4300 | CLOSED | IPsec: security ipsec vpn manual (manual-key SA) silently produces a dead tunnel |
| #4301 | CLOSED | IPsec: security ipsec vpn establish-tunnels value is unvalidated (typo / responder-only silently degrades) |
| #4302 | CLOSED | snmp: pre-existing debug logs echo the v2c community secret (invalid-community + handleSet-denial paths) |
| #4303 | CLOSED | system syslog host/file sub-statements misparsed into bogus facility/severity pairs (hb167 S-1) |
| #4304 | CLOSED | custom system login class <name> hard-rejected at commit (blocks valid vSRX RBAC config) (hb167 S-2) |
| #4305 | CLOSED | SSH hardening knobs (ciphers/macs/connection-limit/client-alive-*/protocol-version) silently inert (hb167 S-4) |
| #4306 | CLOSED | grouped system/SNMP knobs silently inert (view scoping, trap-options source-address, login banner/retry, ntp boot-server |
| #4307 | CLOSED | RA reachable-time and retransmit-timer silently dropped (fable-review-167 I-2) |
| #4308 | CLOSED | Interface ARP/addressing knobs silently dropped: unnumbered-address, gratuitous-arp-reply, no-gratuitous-arp-request, ta |
| #4309 | CLOSED | DHCP relay overrides limited to always-broadcast; forward-only, relay-agent-option (option-82), maximum-hop-count silent |
| #4313 | OPEN | config schema is opt-in — unmodeled Junos leaves commit clean and are silently inert (X-1 cross-cutting root cause) |
| #4314 | CLOSED | CLI: grouped show/request drill-down gaps (IKE/IPsec SA detail, static NAT rule, request security policies check) |
| #4315 | CLOSED | CoS: traffic-control-profiles + output-traffic-control-profile unmodeled — hierarchical shaping binding silently applies |
| #4316 | CLOSED | Firewall/CoS: interface-specific + inet-precedence classifiers/rewrite silently inert (schema gaps) |
| #4323 | OPEN | userspace-dp: Stage-11 IPsec passthrough — gate NEW inbound IKE against per-zone host-inbound (Option B, deferred harden |
| #4328 | CLOSED | cli/grpc: show interfaces reth0 / detail / extensive fail for bondless reth — only 'terse' is reth-aware |
| #4329 | CLOSED | cluster: flat vSRX reth config mis-resolves members on node 1 — CompileConfigForNode never stamps Cluster.NodeID from th |
| #4332 | CLOSED | wireguard: cookie-reply budget is global-per-tunnel, not per-source — a valid-mac1 flood can budget-suppress a legit pee |
| #4335 | CLOSED | config: inline "inactive:" token not pruned — parser reads it as the literal statement value (drop-in blocker) |
| #4336 | CLOSED | config: application source-port/destination-port "0-N" range rejected — Junos accepts 0 as the range floor (drop-in bloc |
| #4337 | CLOSED | config: per-application unknown "alg <name>" hard-rejected at commit though the ALG is not even enforced (drop-in blocke |
| #4338 | CLOSED | config: filter term "source-address 0/0" + except source-prefix-list over-strict — Junos ACCEPTS this lockdown idiom (dr |
| #4339 | CLOSED | nat: NPTv6 single-rule rule-set flagged as overlapping ITSELF — blocks any NPTv6 inbound mapping (drop-in blocker) |
| #4340 | CLOSED | config: address-book object names cannot contain "/" — blocks prefix-named objects in real vSRX configs (drop-in blocker |
| #4341 | CLOSED | cli: show interfaces reth member-with-unit query prints raw name + reth aggregate omits speed line (cosmetic, #4328 foll |
| #4342 | CLOSED | daemon: default-policy action/log change does not invalidate live default-permit sessions (codex-164 H01) |
| #4343 | CLOSED | daemon: policy-rematch ignores scheduler-binding changes though scheduler-inactive is a fail-closed enforcement predicat |
| #4344 | CLOSED | cli/api: text + zone policy counter surfaces still use per-policy reads despite the bulk reader (codex-164 H05/M02/M07) |
| #4348 | CLOSED | config: a quoted value exactly "inactive:" is silently truncated — gate the inactive: marker on TokenIdentifier not Toke |
| #4360 | CLOSED | cluster HA: BulkSync re-drive gate uses the shared bulkEverCompleted flag — a small inbound bulk completing first suppre |
| #4362 | CLOSED | wg: reconcile_peers doesn't drain cookie_gen on peer removal — stale InitiatorCookie leak (#4094 follow-up) |
| #4365 | OPEN | policymatch: global-policy from-zone/to-zone scope (#3148) not regression-tested in Go OR Rust — cross-language divergen |
| #4370 | CLOSED | cluster: session-sync auth handshake runs synchronously in acceptLoop (10s timeout can serially stall accepts) — shorten |
| #4372 | OPEN | firewall filter: three-color policer status not exported in CLI/Prometheus + host-inbound traceroute TCP admission uncle |
| #4373 | OPEN | observability: reject/filter/PBR log confusion — session-close log on then-reject, filter accept-log on a NoRoute drop,  |
| #4375 | OPEN | config: firewall filter term with conflicting terminal actions (then accept + then reject/discard) not rejected at commi |
| #4376 | CLOSED | vrrp: dual-stack equal-priority tie-break is family-split -> both nodes step down -> permanent no-master oscillation (RG |
| #4377 | CLOSED | session: limit-session per-IP cap enable-transition decrement asymmetry -> count drops below live -> cap bypass |
| #4378 | CLOSED | cluster: commit confirmed rollback timer not cancelled on RG0 demotion -> rollback fires on the new standby -> config di |
| #4379 | CLOSED | screen: scan/sweep tracker cleanup 1s floor reaps state for operator windows >1s -> slow-scan detection evasion (fail-op |
| #4380 | OPEN | session: forward/reverse halves have independent idle timers -> asymmetric flow reaps one half, forwards on stale compan |
| #4381 | OPEN | nat64: no port/ICMP-identifier translation -> v6 clients sharing a pool v4 collide on the reverse tuple (RFC 6146 BIB ab |
| #4382 | OPEN | screen: per-source SYN-flood count-min sketch uses compile-time constant seeds, not per-boot hot_hash_seed -> targeted f |
| #4383 | CLOSED | dhcp: DHCPv6 IA_NA parse keeps only the last-enumerated address (multi-address / multi-IA reply) |
| #4384 | OPEN | forwarding: dead-but-wrong incremental TCP checksum in the segmentation path (latent corruption landmine if a refactor f |
| #4385 | CLOSED | cluster/ipsec: IPsec SA sync never pushes the empty set -> administratively-downed tunnels resurrected on failover |
| #4386 | CLOSED | cluster: cold-boot split-brain — heartbeat 'peer never seen' path promotes after 500ms, skipping the 30s config-apply gr |
| #4388 | CLOSED | userspace-dp HA/NAT: peer-synced session's NAT pool port not reserved in the secondary's allocator -> post-failover port |
| #4392 | CLOSED | userspace-dp filter/PBR: 'then routing-instance' + 'then reject'/'then discard' FORWARDS the packet instead of dropping  |
| #4393 | CLOSED | userspace-dp HA/NAT: secondary doesn't publish dnat_table entries for synced SNAT sessions -> embedded-ICMP (PMTUD/trace |
| #4394 | CLOSED | policymatch: simulator fabricates a verdict instead of ContentRejected for protocol-less/unrepresentable/undefined apps  |
| #4399 | CLOSED | userspace-dp NAT: nat_reverse_index is single-value -> a 1:N reverse-key collision displaces the earlier session -> repl |
| #4400 | CLOSED | userspace-dp flow: TCP RST/FIN on session-miss creates a (closing) session instead of dropping -> session-table churn /  |
| #4404 | OPEN | refactor: poll_descriptor/mod.rs (5,759 LOC) — decompose the poll_binding_process_descriptor god-function (1,368 LOC, 15 |
| #4405 | CLOSED | refactor: compiler_validate_strict.go (6,997 LOC) — split the 60+ domain validators into per-domain files (pure code-mot |
| #4406 | CLOSED | refactor: pkg/config/compiler.go (4,336 LOC) — decompose compileExpanded (2,435 LOC god-function) (ps-review-011) |
| #4407 | OPEN | refactor: daemon.go Daemon god-struct (150+ fields, ~3,500 LOC) + daemon_apply.go applyConfigLocked (1,148 LOC) (ps-revi |
| #4408 | OPEN | refactor: Rust hot-path god-functions — tx/dispatch enqueue_pending_forwards (1,131 LOC) + cos/queue_service waterfill ( |
| #4409 | OPEN | refactor: Rust NAT modules — nat/allocator.rs PortAllocator god-struct (926 LOC) + nat/source.rs (1,190) + nat/tests.rs  |
| #4410 | OPEN | review-watcher backlog: avo-review-001 dropped findings F4/F5/F7/F8 (I dismissed these — now filed to drive down) |
| #4411 | OPEN | review-watcher backlog: avo-review-002 dropped test-coverage A2/A4/A5/A6 (I dismissed these — now filed) |
| #4412 | OPEN | review-watcher backlog: avo-review-007 dropped E2/E3/E5/E7 + H1/H4/H6 (I dismissed these — now filed) |
| #4413 | OPEN | review-watcher backlog: ps-review-007 dropped 6 findings (I dismissed these as nits — now filed) |
| #4414 | OPEN | userspace-dp fabric: fabric-redirect NAT applied on session HIT but not MISS — a demoted owner double-NATs an in-flight  |
| #4415 | OPEN | review-watcher backlog: codex-review-164 unfiled findings (H02/M01/M03/M05/M07 + L01-L15) — I classified but never filed |
| #4418 | OPEN | userspace-dp screen: scan cleanup 5-min cap reopens slow-scan evasion for configured windows > 5min (non-blocking residu |
| #4419 | OPEN | Review-dismissal audit backlog: 451 findings the review-watcher dropped without filing (77 reviews re-audited 2026-07-07 |
| #4420 | OPEN | Host-inbound + intrazone-default-permit vSRX-parity backlog (audit cluster — codex-127/128/131/154/162, fable-171, opus- |
| #4421 | OPEN | Refactor/modularity backlog from audit — extends #4404-#4409 (policy.rs, nat64.rs, neighbor.rs, SnapshotIntegrityError,  |
| #4422 | OPEN | Test-coverage + observability backlog from audit (~120 LOW follow-ups across filter/policy/nat/appid/PBR/flow-cache/ddns |
| #4423 | CLOSED | Per-subsystem HIGH/MEDIUM backlog from audit — flowexport collector-stall (HIGH), ddns checkip-fallback (HIGH), flow-cac |
| #4424 | CLOSED | agy-review perf findings dropped in the agy dismissal (verify-first: mutex contention, cache-line alignment, unvectorize |
| #4425 | CLOSED | NAT64 first-fragment ICMP (v4->v6) leaves the ICMPv6 checksum zeroed -> invalid packet (audit — fable-171 HI cluster) |
| #4426 | CLOSED | Family-any firewall filter still allows single-family prefix-list under-block (audit — codex-164 C164-H04, re-verify vs  |
| #4433 | CLOSED | IPsec render/reload failure leaves stale strongSwan tunnels active under a NEW committed config (codex-172 C172-H01) |
| #4434 | CLOSED | HA heartbeat redundancy-group count is a uint8 — 256 RGs advertise as 0, 293 panics heartbeat marshaling (codex-172 C172 |
| #4435 | CLOSED | NAT64 + embedded-ICMP IPv6 extension walkers still surrender at 6 headers while the canonical parser bound is 8 (codex-1 |
| #4436 | CLOSED | family-any single-family prefix-list fail-open still APPLIES on the lenient HA-sync/tolerant-load path (codex-172 C172-M |
| #4437 | CLOSED | DDNS Surface-A HTTP providers fail open to an unbound client on cached-client source-address errors (codex-172 C172-M01) |
| #4438 | CLOSED | NAT forward_wire_index + reverse_translated_index remain single-value 1:N (session hijack) — #4399 fixed only nat_revers |
| #4439 | CLOSED | Fabric-redirect skips SNAT on the owner for NEW non-TCP flows (NAT bypass + session-state corruption) (ps-013 P7) |
| #4440 | CLOSED | Low-severity from codex-172: DDNS constructor RFC2136-only comments + NAT64 synthetic IPv6 dest policy blanket-permit (c |
| #4446 | CLOSED | userspace-dp FIB: static bare-gateway next-hop ifindex inference is GLOBAL, not table-scoped -> multi-VRF wrong-egress ( |
| #4449 | CLOSED | Stale NAT64 policy-tuple rationale comments in userspace-dp afxdp/tests.rs (pre-#2358) |
| #4453 | CLOSED | userspace-dp fabric: cluster_peer_return_fast_path excludes SYN/UDP/ICMP-echo but NOT bare RST/FIN -> a fabric-redirecte |
| #4455 | OPEN | HI-1: per-zone multicast/broadcast host-inbound admission (iifname gate + Rust lockstep) |
| #4474 | OPEN | opus-172 H-1: transitive apply-groups silently drops a security zone/policy (config fail-open) |
| #4475 | OPEN | opus-172 H-2: unsolicited ARP/NA installed as NUD_REACHABLE — on-link neighbor-cache poisoning/MITM |
| #4476 | CLOSED | opus-172 H-3: REST config-lock has no auto-release — management-plane config-edit DoS |
| #4477 | OPEN | opus-172 H-4: flow-stats Packets-dropped / NAT-alloc-failures are dead counters (observability lie) |
| #4478 | OPEN | opus-172 M-1: IPIP (proto-4/41) decap has no userspace zone enforcement (fail-open, parallel to GRE) |
| #4479 | CLOSED | opus-172 M-2: userspace FIB snapshot conflates PBR ip-rules with route-leak — FBF selectors dropped |
| #4480 | OPEN | opus-172 M-3: interface-monitor display hardcodes Up:true when live status unavailable |
| #4481 | OPEN | opus-172 M-4: FRR cross-context route-map default-action leak |
| #4482 | OPEN | opus-172 M-5: FRR route-map/prefix-list bypass the #4097 sanitize belt on the tolerant-load path |
| #4483 | OPEN | opus-172 M-6: DDNS DNS-UPDATE unsigned UDP-first with no TSIG trusts a forgeable rcode |
| #4484 | OPEN | opus-172 LOW batch (L-1..L-12): REST audit-gap, SSE cap, RST clamp, syslog/reject parity, frr.conf mode, secret-Debug, + |
| #4487 | OPEN | ps-017 P6b: residual LocalDelivery RST/FIN creates a session (host-IP session-table DoS + policy-skip) — #4400 covered o |

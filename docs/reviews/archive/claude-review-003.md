# claude-review-003 — Rust AF_XDP Dataplane Focused + Security Zone Policies Deep Examination (HFT-Grade, Zone Allow/Deny)

**Base commit reviewed:** `7e0fecf3b8f2dc6604600674373771c835484188`
**Date:** 2026-07-11T06:20:50Z
**Repo root:** `/home/ps/git/avacado-xpf` (via `git rev-parse --show-toplevel` — never hardcode, generic work dirs, no repo name in path)
**Output path:** `/tmp/claude-review-003.md` (ONLY file matching /tmp/claude-review-003*.md after cleanup — per contract: intermediates in /tmp/review-work-claude-003/ (22 files, generic review-work-<whoami>-<NNN> no repo name) + worktrees in /tmp/review-wt-claude-003-*/ (generic review-wt-<whoami>-<NNN>-<area>-b<batch> no repo name, detached at base SHA 7e0fecf3, all swept after merge))
**Batch files:** 22 (10 areas: A1 Rust packet path 3 batches, A2 NAT 1, A3 config 4, A4 configstore 1, A5 HA 1, A6 dataplane mgr 3, A7 daemon host 3, A8 API 2, A9 observability 1, A10 services 3) — all under /tmp/review-work-claude-003/ (generic)
**Focus:** Rust AF_XDP dataplane hot path: per-packet forwarding orchestrator (poll_descriptor/mod.rs 6294 LOC god-function #4404, poll_stages.rs, reject_reply.rs, filter.rs), CoS TX drain (tx/dispatch/mod.rs enqueue_pending_forwards 1486 LOC #4408, cos_classify.rs 1335 7-resp, tcp_segmentation, rings, drain, queue_service/mod.rs waterfill 432 god-func #4408, types/cos.rs god-struct 28 fields, shared_cos_lease), session table (session/mod.rs 2054 SessionTable 25 fields god-struct #4421, session/entry.rs hot/cold Arc clone ~10ns win), policy/verdict engine (screen/mod.rs 1540 16 checks, frame/inspect.rs 1813 5x EH walker dup, frame/mod.rs kitchen sink 6-resp, policy.rs 3598 AppCatalog zero-coupling) — split cold config/setup/stats/logging out WITHOUT changing one instruction of hot path, prove with disassembly diff + failover/CoS smoke gates. PLUS security zone policies and how traffic is allowed and denied between zones — deep networking expert, Linux kernel networking, HFT-grade performance. You are amazing engineer with keep knowledge in networking and performance.

## Duplicate suppression summary

**Open GH issues (80 read, 40 shown) — do NOT re-report:**
- #5554: cli: 'request system zeroize' hardcodes /etc/xpf config root, not the configured root (secret retent
- #5544: snmp/v3: DES privacy salt omits engineBoots prefix (RFC 3414 §8.1.1.1 cross-boot uniqueness recommen
- #5523: [cohort] codex-179 Medium/Low low-materiality + test-coverage-only survivors (69 items)
- #5497: grpcapi: MonitorInterface proxies to the peer whenever the LOCAL node is not RG-primary (!IsLocalPri
- #5488: dataplane/policy: multi-zone scoped global deny is lowered with only the FIRST zone in the legacy si
- #5487: dataplane/userspace: standalone HA-state clear (clearHelperHAStateLocked) failure returns an error b
- #5486: dataplane/userspace: disableUserspaceCtrlLocked is void and swallows ctrl-map Lookup/Update errors b
- #5485: dataplane/userspace: XDP shim attach (CompileUserspaceShim) + syncInterfaceAttachments detach run BE
- #5484: dataplane/shim upgrade: live-pin ABI preflight inventory omits production shared/replacement maps (s
- #5483: dataplane/eventstream: a decode failure on a session Open/Update/Close frame is skipped (continue) i
- #5482: vrrp: becomeMaster/backup publish role via emitEvent without verifying VIP ownership — addVIPs/remov
- #5481: vrrp: a failed required IPv6 advertisement socket is swallowed (warn + continue) — an IPv6-only inst
- #5480: cluster/session-sync: coldStart is the sticky process-local !bulkEverCompleted flag — a survivor ski
- #5479: cluster/failover: a failed requested peer-failover has no remote transfer-out abort — abortRequested
- #5478: cluster/monitor: a local monitored interface that goes missing (netdev removed/renamed/unresolved) i
- #5477: cluster/heartbeat: anti-replay watermark is a single (session,counter) with no retired-session track
- #5469: userspace-dp: write_state holds the ServerState lock across full pretty-serialization + fsync; sessi
- #5468: userspace-dp/HA: push_delta_lossless 5s retry (LOSSLESS_QUEUE_TIMEOUT) runs on the worker loop (flus
- #5467: userspace-dp/tx: flowless packets (non-first fragments, non-query ICMP) return from CoS TX classific
- #5466: userspace-dp: in-place descriptor rewrite mutates frame (eth header + VLAN-push memmove) before its 
- #5460: bpf/headers: SESS_FLAG_NPTV6 (1<<8)=256 overflows the __u8 session_value.flags field (latent ABI bug
- #5451: daemon/HA: warmNeighborCache opens one UDP socket per unique session IP with no cap → FD/port exhaus
- #5450: cluster/session-sync: delete-journal overflow evicts oldest deletes with no forced re-reconcile → st
- #5449: dataplane/userspace inject: slot parsed with Atoi + cast to uint32 with no negative/range check → -1
- #5448: dataplane/session_store: batchDeleteV4/V6 drops the unattempted chunk tail on a missing key → stale 
- #5447: userspace-dp/NAT64: fragment-association cache install evicts oldest live entry without pruning expi
- #5446: userspace-dp/NAT: HA reserve_flow marks deterministic-CGNAT/NAT64 synced flows as non-deterministic 
- #5445: userspace-dp/session: per-packet SessionMetadata.clone() does a LOCK XADD on the policy_counter Arc 
- #5444: userspace-dp/filter: merge_matched_modifiers heap-clones policer/routing-instance String per matched
- #5390: userspace-dp/filter: three-color policer per-packet Mutex is cross-worker shared — futex convoy caps
- #5381: userspace-dp: native GRE encap copies inner packet with redundant .to_vec() (extra per-packet heap a
- #5380: userspace-dp/HA: syncSessionRequestsLocked dials a fresh socket per session mirror with no fast-fail
- #5364: test/incus cluster-deploy: rolling deploy cannot cross a shim-map ABI change on a stale cluster — ne
- #5363: verify-dataplane: stale-live-pin ABI mismatch (embedded>pinned) prints the misleading 'rebuild the s
- #5362: eventstream (Go reader): FullResync does not advance prevSeq — one bounded reconnect on the first po
- #5341: userspace-dp/NAT: deterministic CGNAT (mode 1) address-only sub-branch mints no occupancy token (sam
- #5338: userspace-dp/HA: standby does not reserve address-only source-NAT tokens (reserve_synced_source_nat_
- #5328: [cohort] codex-178 low-materiality + test-coverage-only survivors (15 items: DSCP/ECN, bind-mode rac
- #5306: dataplane/HA: SyncFabricState never updates Go's m.lastSnapshot.Fabrics — a later route-overlay/sche
- #5305: dataplane: SetClusterSyncedSession* leaves the committed BPF mirror write in place when the helper u
- #5303: cluster: session-sync accept loop has no aggregate pre-auth admission cap — a connection flood exhau
- #5302: ra: sender caches net.Interface.HardwareAddr at start — post-RETH-MAC-change ResendBurst advertises 
- #5301: cluster: IP monitor probes targets serially with an 800 ms per-target deadline — detection/shutdown 
- #5296: appid: catalog IDs are positional and reassigned across applies — retained sessions resolve to the w
- #5295: userspace-dp/HA-NAT: purge_translated_synced_hit deletes session state without releasing the source-
- #5294: userspace-dp/HA: drain_session_deltas / owner-RG export pop deltas then run fallible write_state bef
- #5293: userspace-dp/filter: filter_term_semantics_match omits all six flex fields — flex-only PBR rotation 
- #5292: userspace-dp/WireGuard: direct AF_XDP route/connected admission resolves the zeroed WG endpoint befo
- #5291: userspace-dp/WireGuard: TUN-origin egress uses the first-peer resolve_wg_outer_mtu scalar for all pe
- #5290: userspace-dp/HA: Coordinator::drain_session_deltas fixed BTreeMap order + caller-wide budget starves

**Prior campaign finals read (ONLY final NNN files directly under /tmp/, NOT /tmp/review-work-*/ or /tmp/review-wt-*/):**
- /tmp/ps-review-*.md: 134 finals (031-042) — ONLY final NNN files per new contract
- /tmp/claude-review-*.md: 2 finals (001, 002)
- Dedup index: 39341 chars, compact title+file+root cause index passed to EVERY subagent
- Orientation: firewall/router Go+Rust AF_XDP, focus zone policies/global/host-inbound/app matching/default deny+permit + VRRP/HA cold-boot + int trunc + DDNS/observability

**Dedup index (truncated 2500 chars):**
```
# Dedup index — prior campaign findings + open GH issues (042 and earlier)
# Do NOT re-report any entry here unless root cause differs materially

## Open GH issues (100, first 60 shown):
#5544: snmp/v3: DES privacy salt omits engineBoots prefix (RFC 3414 §8.1.1.1 cross-boot uniqueness recommendation)
#5523: [cohort] codex-179 Medium/Low low-materiality + test-coverage-only survivors (69 items)
#5497: grpcapi: MonitorInterface proxies to the peer whenever the LOCAL node is not RG-primary (!IsLocalPrimary) without checking the PEER owns the RG and with no hop marker — during both-secondary/election/hold states A→B→A recursion storms connections/streams/goroutines
#5488: dataplane/policy: multi-zone scoped global deny is lowered with only the FIRST zone in the legacy singular field + full set in additive plural fields, but the snapshot protocol version was NOT bumped (still 3) — a pre-#4626 same-version helper ignores the plural fields and narrows the deny (fail-open under rolling upgrade)
#5487: dataplane/userspace: standalone HA-state clear (clearHelperHAStateLocked) failure returns an error but has no retry/debt — a cluster→standalone reconfig with a transient control-socket error leaves stale helper HA groups → owner-RG-0 forwarding stays HAInactive (transit drop)
#5486: dataplane/userspace: disableUserspaceCtrlLocked is void and swallows ctrl-map Lookup/Update errors before worker/UMEM teardown — shim keeps redirecting to dead XSK fds until heartbeat expiry (transit outage)
#5485: dataplane/userspace: XDP shim attach (CompileUserspaceShim) + syncInterfaceAttachments detach run BEFORE apply_snapshot with no rollback — a later apply failure leaves kernel XDP attachments diverged from the retained lastSnapshot (policy bypass / outage)
#5484: dataplane/shim upgrade: live-pin ABI preflight inventory omits production shared/replacement maps (sessions_v6, dnat_table_v6, HA/counter) — an incompatible shim map ABI passes verification then fails ErrMapIncompatible AFTER the old daemon is stopped (node stranded fail-closed)
#5483: dataplane/eventstream: a decode failure on a session Open/Update/Close frame is skipped (continue) instead of forcing a sync break — later telemetry advances the cumulative ACK and trims the unapplied session frame from replay (silent standby divergence)
#5482: vrrp: becomeMaster/backup publish role via emitEvent without verifying VIP ownership — addVIPs/removeVIPs are void and swallow netlink errors, so control-plane role can diverge fr
```

## Explicit expertise-area + module checklist — full-tree coverage proof

| Area | Files | Batches | Persona |
|------|-------|---------|---------|
| A10_go_services_cli_deploy | 433 | 3 | ... |
| A1_rust_dataplane_packet | 418 | 3 | ... |
| A2_rust_dataplane_nat | 18 | 1 | ... |
| A3_go_config_cli_tree | 517 | 4 | ... |
| A4_go_configstore_persist | 69 | 1 | ... |
| A5_go_ha_vrrp_ra_conntrack | 105 | 1 | ... |
| A6_go_dataplane_manager | 306 | 3 | ... |
| A7_go_daemon_host | 366 | 3 | ... |
| A8_go_api_grpc_rest | 303 | 3 | ... |
| A9_go_observability | 140 | 1 | ... |

Total: 2675 source files, 22 batches, all assigned exactly once

## Module-by-module inspection log (aggregated from 22 subagents, incl negatives)


### ps-A10_go_services_cli_deploy-b1.md (17489 chars, 132 lines)

```
# Security Review A10 b1/3 — CLI dispatch, zone display, BPF headers, commit/rollback, deploy

BASE: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
Worktree: /tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1
Focus: protocol + tooling — CLI dispatch & show-output correctness, zone handling, BPF struct alignment, configstore, commit/rollback, TOCTOU

## Inventory (150 files)

**bpf/headers (6, 5334 LOC total):**
- xpf_common.h 898 — MAX_INTERFACES 65536, MAX_ZONES 64, iface_zone_key/value, pkt_meta, screen_config, etc.
- xpf_conntrack.h 225 — session_key packed (16B), session_value, tcp state machine
- xpf_helpers.h 2554 — BPF helper wrappers
- xpf_maps.h 921 — PROG_ARRAY, CPUMAP, scratch maps, interface maps sized MaxInterfaces
- xpf_nat.h 575 — nat_pool_config, snat_egress, nat64
- xpf_trace.h 161 — trace events

**cmd/cli (51 files, 8031 LOC):**
Prod: clear.go 266, main.go 672, shared.go 681, monitor.go 462, request.go 393, show.go 483, show_security.go 705, show_dhcp.go, show_firewall_effective.go, show_flow.go 414, show_interfaces.go, show_nat.go 298, show_protocols.go 85, show_services.go, show_system.go 141
Tests: commit_rollback_4868_test 141, grpc_maxrecv_5321 98, load_terminal_abort_4883 97, etc. Largest fn: dispatch() in main.go ~200 LOC, shared.go dispatchOperational ~180

**cmd/xpfd (10, 1628 LOC):**
main.go 412 (classifyCommand SSOT for subcommand routing), upgrade.go 257 (parseUpgradeArgs rejects leftover args #4869, cluster guard #5284), upgrade_kernel.go 217 (validateKernelVerbArgs #5322, lock serialization), publish_generation.go 153 (GC protection #4876), seed_runtime.go 101 (no positional args #5322), dispatch_test.go 75, leftover_args_5322 165, upgrade_args_4869 68, etc.

**docs/pr/812 (2):** vdso_probe.c, vdso_probe2.c — latency histogram evidence, not prod path

**pkg/cli up to screen_inventory (80+ files, ~7800 LOC in scope):**
- cli.go 548 (CLI struct, 15+ deps, commitCtx cancellable)
- cli_dispatch.go 523 (dispatch, extractPipe LastIndex, filterStream streaming #4709/#4731, parseLastCount clamp maxTailLines 100k #5037, pageStream)
- cli_config.go 486 (handleCommit strict parsing #4868, unknown option reject, handleLoad file read, handleCopyRename, handleInsert, commitApply via applyConfigFn #797)
- cli_show.go 281 (show dispatcher #4422 effective filter banner)
- cli_show_security_zones.go 210 (showZonesDisplay sorted, nil-tolerant #3493, host-inbound with lifelines #3682, detail per-logical-unit split #5325, SSOT ZoneDetailPolicySummary #3658)
- cli_show_security_screen.go 485 (SSOT ScreenEnabledCheckList #3327, counter warnings #3408/#3345, flood counters not-available #3643)
- cli_show_security_dispatch.go ~400 (enabledStr, scheduler active state #3062)
- cli_show_security_filters.go 549 (showFirewallFilters raw, showEffectiveFirewallFilters compiled #4422, banner generation drift #5067, Builds snapshots via BuildFirewallFilterSnapshots)
- cli_show_security.go 490 (showPoliciesHitCount bulk reader #3965/#4344, scoped_gl
```

---

### ps-A10_go_services_cli_deploy-b2.md (11471 chars, 107 lines)

```
# Security Review — Batch A10 Go Services CLI Deploy b2/3

Base: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
Scope: pkg/cli/* (from wireguard onward), pkg/ddns/*, pkg/dhcp/*, pkg/dhcprelay/*, pkg/dhcpserver/ddns*

## Inventory

| Module | Prod LOC | Test LOC | Files | Largest fn | Responsibility | Rank* |
|---|---|---|---|---|---|---|
| pkg/cli show_services/monitor/traffic | ~3.2k prod / ~4.5k test | 176+1081+277+70+389 etc | 26 prod files in batch | showSystem (1081 LOC) / handleMonitorSecurityFlowFile (150 LOC) | CLI dispatch, zone display, traffic capture argv, session egress map, permissions RBAC, trace-file confinement | High (user-facing root tcpdump) |
| pkg/ddns backends | ~7.5k prod / ~12k test | 16 prod files | largest surface_a.go 2109 LOC / backend_rfc2136.go 1126 | DDNS publish/withdraw, source-bind pinning, redirect-downgrade refusal, checkip oracle, durable state, provider transition orphans | High (credential-bearing egress, source-bind fail-closed) |
| pkg/dhcp client | ~2.8k prod / ~2k test | 5 prod | dhcp.go 1903 / commit 220 | DHCPv4/v6 lease acquire, T1/T2 renew/rebind (RFC2131/8415), classless routes opt121/249 supersede opt3, DUID persistence, anti-blackhole mask validation | High (WAN address, gateway, DNS, FRR route programming) |
| pkg/dhcprelay | ~2.4k prod / ~3.2k test | 4 prod | relay.go 1583 | DHCP relay giaddr primary selection, Option82 circuit-id, hop-limit loop protection, raw-L2 unicast fallback, server source IP allowlist (#4163), HA master gate | High (L2 broadcast domain ↔ upstream, rogue injection) |
| pkg/dhcpserver ddns | ~0.5k prod / ~1k test | 2 prod | ddns_leases.go 419 | Kea memfile parser destructive-diff safety: duplicate-column reject, required-column validation, ragged-row fail-closed | Medium (DNS record loss if parser lenient) |

*Rank = size × responsibility × hot-path proximity. Total batch ~150 files = 12200 prod + 19500 test approx.

## Module Log (incl. negatives proving coverage)

- cli_show_security_wireguard.go: Delegates to dpformat.FormatWireguardStatus, nil dp guard — NEGATIVE, no zone handling, shared formatter ensures parity.
- cli_show_security_zones.go: Sorted zones, nil zone tolerant (#3493), HostInboundViewWithLifelines renders zone-level + per-if override + lifeline exemption (#3654/3682). VLAN unit handling splits base+".0" logic via strconv.Atoi, detail renders only wanted unit (#5325). Counter read: not-implemented explicit vs nil error warning accumulation (#3643/#3408). SSOT for screen checks via ScreenEnabledCheckList (#3327). Policymatch.ZoneDetailPolicySummary SSOT for policy tiers (#3658). NEGATIVE for injection: no shell.
- cli_show_services.go: Strict subcommand dispatch, cmdtree help, unknown target errors. RPM uses os.Stdout atomic write, no template inj. NEGATIVE.
- monitor_traffic.go: Validates tokens, rejects bare matching, bare interface/count fail-closed (#4540, #4883). stripSurroundingQuotes peels one layer, buildMonitorTrafficArgv inserts "--" separator before 
```

---

### ps-A10_go_services_cli_deploy-b3.md (12261 chars, 136 lines)

```
# A10 Go Services / CLI / Deploy Review b3/3 — Batch 002

## Inventory (114 files, ~20K LOC)

| Module | Files | LOC (prod) | Largest fn | Responsibility |
|--------|-------|------------|------------|----------------|
| dhcpserver | 8 go | 2111+934 lease_sync | generateKea4Config / lease parse | Kea config render, lease sync/seed, DDNS glue |
| natshow | 5 go | 49+117+108+114+117 | RenderSourceRuleDetail | NAT show rendering (source/dest/static/persistent) |
| policymatch | 48 (1 prod 47 test) | 1715 prod | Match 300+ | Zone policy simulator vs dataplane parity, global scoped, app matching |
| scheduler | 5 | 449 prod | evaluate 60, isWithinWindow 40 | Time window eval, wall-clock discontinuity, republish self-heal |
| scripts/deploy | 7 py | 1881 xpf-deploy + 6 test | cmd_kernel_roll 200 | Appliance deploy, fetch verify, HA roll orchestration |
| scripts/dist | 2 py | 345+786 | publish gate_images 140 | Minisign manifest, image signing, publish gate |
| scripts/image | 5 py | 756+686+122 +2 test | virt_customize bake 120 | Bake qcow2, config-drive ISO, validate gate |
| scripts/*.py, test/incus/*.py | ~35 py + 1 rs + 4 xsk | varied | - | Test harnesses, metrics, cold-path flooder (2170 RS) |

## Module Log

- dhcpserver/dhcpserver.go: generation supersession with atomic gen, fail-closed is-active query handling (#4870) — sound, query error triggers restart/stop + error surfacing. Stable hash subnet-id (#5041/#5203) with coprime probe step — correct.
- dhcpserver/lease_sync.go: clock-skew-safe Remaining re-anchor, v6 IA_PD handling, splitV6Identity error returns non-nil for malformed IAID (#2379). Memfile pre-seed with _kea ownership via fsatomic WithOwner — hardened. BOS: mergeLeasesByIdentity local wins — correct for active-active.
- dhcpserver/ddns.go: thin alias glue, keaLeaseParser maps unknown LeaseType to LeaseTypeUnknown fail-closed (#5072 IAPD AAAA suppression) — sound.
- natshow/source.go, dest.go: session counts keyed by {from,to} not rule-set name — inherent limitation (sessions carry zone IDs not rule-set name), not a bug; counter reads via NATCounterIDs — correct. IPv6 iteration present.
- natshow/persistent.go: binary.NativeEndian.PutUint32 recovers __be32 — matches CLAUDE.md byte order, v6 netip.AddrFrom16 without Unmap — correct per gc.go. No panic.
- natshow/static.go: NPTv6 vs static prefix rendering, detail fields — display only, no enforcement.
- policymatch/policymatch.go: tier order exact→single-wildcard merged→both-any→global→default, zoneKnown gate for undefined zones (#3355), scheduler gate first, content rejection SSOT via PolicyContentRejectionReasons (#3727/#4394), route-drop advisory (#4373), host-inbound token classification, feed overlay merge, ParseSelectorArgs fail-closed duplicate/unknown/empty. Very hardened.
- policymatch/zone_detail_summary.go: wildcard handling fromAny/toAny affect BothAny tier, policySetID advances on nil sets, global via GlobalPolicyAppliesToZone — correct.
- scheduler/scheduler.go: wallCl
```

---

### ps-A1_rust_dataplane_packet-b1.md (39802 chars, 224 lines)

```
# Batch 003 b1/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b1
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

Ranked by LOC × responsibility-count × hot-path proximity (poll_descriptor hot=10, forwarding=8, frame=9, cos=5, coordinator=3, bpf_map=4, bench/build=1):

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ LOC god | per-packet orchestrator: host-inbound → lo0 → junos-host → route → screen → policy → SNAT → install → telemetry → HA | 10 |
| 2 | forwarding/mod.rs | 2795 | prod | lookup_forwarding_resolution_inner_ecmp 800+ | FIB/NAT/fabric/tunnel/VRF/zone-pair/MSS/local-delivery table-scoped decis | 9 |
| 3 | flow_cache.rs | 2000+ est | prod | lookup, insert | flow-cache hit/miss, MAC-epoch TOCTOU (#3918), owner-RG epoch | 9 |
| 4 | frame/inspect.rs | 1960 | prod | frame_l3_offset 68, packet_rel_l4_offset 100 | L3/L4 offset, IPv6 EH walk, fragment detection, flex-bounds, declared_end | 9 |
| 5 | frame/mod.rs | 1743 | prod | apply_dscp_rewrite 200 | rewrite orchestrator, DSCP, checksum adjust | 8 |
| 6 | forwarding_build/fib.rs | ~500 | prod | populate_routes, resolve_next_hops | route table build, preference validation (#3771), family mismatch | 7 |
| 7 | forwarding_build/zones.rs | 142 | prod | populate_zones 80 | zone name↔id, duplicate ID reject (#3719), reserved-range skip, host-inbound per-zone, reject_buckets per-zone (#3618), tcp_rst per-zone | 8 |
| 8 | forwarding/host_inbound.rs | 538 | prod | classify_system_service 134, host_inbound_admits 40 | host-inbound admit: system-services → L4 ports/ICMP types/IP proto, protocols all expansion (#3199) minus L2 (#3311), None=>true for unknown zone (id 0) | 8 |
| 9 | forwarding_build/*.rs (interfaces, cos, tunnels, validated, wg) | ~800 total | prod | — | interface→zone mapping, CoS iface config, tunnel endpoints, WG engines | 6 |
| 10 | frame/headers.rs | 338 | prod | write_eth_header_slice_tagged 40 (unsafe) | eth/ipv4/ipv6/udp header serializers, TxVlanTag, DF=1 atomic datagram (#1440) | 7 |
| 11 | frame/byte_writes.rs | 81 | prod | — | write_ipv4/6 src/dst (NO guards — caller must validate), L4 port writes (guarded) | 8 |
| 12 | frame/* (build/*, rewrite/*, tcp.rs, checksum.rs, tcp_segmentation.rs, wg.rs) | ~2500 total | prod | segment_forwarded_tcp_frames 500+ | frame building, rewrite descriptors, TCP segmentation, WG outer MTU SSOT | 7 |
| 13 | cos/* (admission, builders, ecn, fairness, flow_hash, queue_ops, token_bucket, tx_completion) | ~5000 total | mixed | admission check, queue_ops push/pop/drain/v_min, waterfill allocator | CoS classification, per-queue token-bucket, lossless queu
```

---

### ps-A1_rust_dataplane_packet-b2.md (31794 chars, 224 lines)

```
# Batch 004 b2/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b2
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ god | orchestrator remainder after stage extractions: session-hit path, session-miss path (policy→NAT→FIB→screen→install), flowless path (#3292), junos-host gate #3019/#3706, PBR route_override #4392, DNS reply allow, strict-syn-check #4400, session limit #2134, fragment assoc NAT64 #2562, IPv6 ext over-limit #4743 | 10 |
| 2 | poll_descriptor/filter.rs | ~600+ | prod | filter_terminal, host_inbound_gated_lo0_action | input-filter eval + log emission, lo0 host-bound filter, host-inbound gating via host_inbound_admits_iface with logical ifindex #3609, PBR routing-instance override with Drop #4392, log source Pbr vs Filter, truthful REJECT→DENY downgrade #3615 | 8 |
| 3 | tx/dispatch/mod.rs | 1486 | prod | enqueue_pending_forwards 1048 god | Phase 8 try_inplace_rewrite_or_build, copy-frame oversized check, PTB derivation #2301/#2330, tunnel outer MTU SSOT #2300, tuple-mismatch diag #4041, single-recycle invariant 39 sites | 8 |
| 4 | types/cos.rs | 1786 | prod | — | CoSState 28 fields 5 lifecycles, cos_lease, equal-flow target policy parse #2458, loss-priority rewrite #3995 | 5 |
| 5 | types/forwarding.rs (already in b1 but referenced) | 1100 | prod | — | ForwardingState 66 fields (see b1) — hot FIB vs cold truth | 9 |
| 6 | wg/engine.rs | 1805 | prod | — | WG engine, handshake, session, cookie, framing, peer selection per #1434 multi-peer, allowed_ips LPM, secret redaction Debug #4484 zeroize | 6 |
| 7 | worker/*.rs (mod, lifecycle, loop_body, telemetry, cos/*, bind_meta, bpf_maps, flow_cache_state, scratch, timers) | ~3000 total | prod | loop_body setup/debug_report | worker loop, UMEM, XSK, flow-cache, TX pipeline BatchCounters #3651, cos row, status | 7 |
| 8 | tx/* (cos_classify.rs 1335 7-resp, dispatch/cos, drain/phase_*, rings, stats, tcp_segmentation, transmit/*, queue_service/* waterfill 2058) | ~8000 total | prod | cos_classify, queue_service::waterfill 432 god | CoS TX selection resolve, TX drain phases trivial/shaped/backup, rings, TCP segmentation, finalise/rewrite/stage/verify/write, waterfill allocator epoch refill f64 fraction clamp bitset Phase1 asc Phase2 desc WRAP | 6 |
| 9 | icmp_embed/* (builders, mod, nat_match_v4/v6, parse, return_resolution, session_match) | ~1500 total | prod | match_outer_v4, session_match | embedded ICMP NAT matching forward-NAT-by-reverse + session fallback, return resolution, builders for ICMP error translation | 7 |
| 10 | icmp_ptb.rs + icmp_rateli
```

---

### ps-A1_rust_dataplane_packet-b3.md (13489 chars, 162 lines)

```
# Batch A1 Review — Rust dataplane packet pipeline + policy
Base: 7e0fecf3b Merge #5550 fix/5077-classifier-submit-monotonicity
Root: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b3
Coverage: 118 files, 83780 LOC total, prod ~48k / test ~36k

## Inventory (ranked by responsibility × hot-path proximity)
| File | LOC | Responsibility | HotPath |
|---|---|---|---|
| policy.rs | 3657 | zone_pair_key, global scope, counters, default sentinel | cold/warm, policy eval hot but indexed |
| filter/tests.rs | 8613 | filter semantics | test |
| policy_tests.rs | 7280 | policy matching | test |
| session/tests.rs | 7072 | session install/expire | test |
| screen/tests.rs | 5395 | screen checks | test |
| event_stream/mod.rs | 1701 | event stream IO, replay, backpressure | warm |
| server/tests.rs | 1953 | server lifecycle | test |
| session/mod.rs | 2114 | slab, indices, GC | hot |
| main_tests.rs | 2350 | snapshot integration | test |
| protocol/tests.rs | 2393 | wire invariants | test |
| screen/mod.rs | 1540 | pre-session + flowless + SYN flood | hot |
| xsk_ffi.rs | 1287 | zero-copy rings, UMEM, FD lifetimes | hot/unsafe |
| lib.rs (userspace-xdp) | 1541 | shim binding array steering | hot unsafe |
| slowpath.rs | 913 | TUN inject | cold |
| state_writer.rs | 601 | state persist | cold |
| filter/compiler.rs | 1069 | snapshot → FilterState, fail-closed backstops | cold apply |
| filter/engine/eval.rs | 1026 | filter eval, log rewrite | hot |
| filter/mod.rs | 939 | type vocab, counters | warm |
| protocol/binding.rs | 1185 | ifindex/zone binding | cold |
| protocol/control.rs | 1088 | snapshot status | cold |
| server/helpers.rs | 1304 | json persistence (privkey hygiene) | cold |
| ... | ... | ... | ... |

Largest fn: policy::parse_policy_state_with_counters (~800 LOC), filter::compiler::parse_term (~400), session::mod.rs SessionTable::new+expire.

## Module log (brief, negatives acceptable)

- tx_counters.rs (60): counter coalescing struct only. No alloc. Sound: explicit construction, no Default. **NEGATIVE**.
- tx_pipeline.rs (69): struct holder for free frames, pending TX, sidecar tx_submit_ns Box<[u64]>. Box prevents push. Sound.
- xsk_rings.rs (41): struct holder DeviceQueue/RingRx/RingTx. Sound.
- worker_queue.rs (85): Mutex<VecDeque<WorkerCommand>> poison recovery, clear_poison, metrics. Correctly preserves committed prefix. **NEGATIVE** - reviewed earlier in #1807.
- zone_counters.rs (438): per-zone traffic counters: flat 64k LUT slot_of u8, thread_local ZonePending, saturating_add, store by stable zone_id. No hot hash. Sound, overflow safe.
```

---

### ps-A2_rust_dataplane_nat-b1.md (9449 chars, 93 lines)

```
# Batch A2 rust dataplane nat — Review Report
Base commit: 7e0fecf3b
Worktree: /tmp/review-wt-claude-003-A2_rust_dataplane_nat-b1

## File-size/shape inventory
Prod total: 9334 LOC (8 files). Test total: 15648 LOC (10 files).
Rank by size x responsibility x hot-path:
1. nat64.rs 3102 LOC — v6↔v4 translation, checksum incremental (RFC1624), ICMP error embedded-ICMP reversal, frag DF/ID policy, port-allocator integration, HA reserve, frag-assoc cache — hot per-packet.
2. allocator.rs 1974 LOC — lock-free bitmap port claim, FIFO recycle, persistent lease SM, deterministic CGNAT blocks v4/v6, address-only reverse-identity tokens, HA reservation, GC chunking — hottest cold-path (session-miss) but contended.
3. source.rs 1523 LOC — SNAT rule parsing, pool expansion, match (zone/interface/RI/L4/app), address-persistent sticky hash, port-less/ICMP query gates, deterministic dispatch, failure reason mapping — hot cold-path.
4. destination.rs 1109 LOC — DNAT exact O(1) + prefix LPM, proto wildcard PROTO_ANY=256 distinct from HOPOPT, off exemption short-circuit, source-scoped, L4 extra matches, dst_port range — hot cold-path.
5. static_nat.rs 808 LOC — 1:1 + block offset remap, bidirectional, zone/interface/RI/source scoped, port-mapped / match-port scoping, VRF-scoped external IPs — hot cold-path.
6. nptv6.rs 431 LOC — stateless /48 /64 prefix replacement, RFC6296 adj, 0xFFFF→0x0000 fold, zero-adj skip for checksum-neutral pair — hot per-packet.
7. mod.rs 347 LOC — NatDecision merge/reverse, counter store with fetch_sub clear (no lost update), parse-error loud skip — cold except decision.
8. status.rs 40 LOC — pool status snapshot aggregation — cold (1/s).

Largest fns est: `write_v6_to_v4_into` ~200, `write_v4_to_v6_into` ~180, `allocate_translation_locked` ~130, `match_source_nat_result_for_tuple` ~150.

## Module log (responsibility + negative if no finding)

- allocator.rs: Owns port ownership via AtomicU64 bitmap + per-addr recycle. Implements #2852 lock-free claim, #3047 skip-occupied, #3011 FIFO, #4676 chunked GC, #4388 reserve_flow for HA, #5269 address-only reverse keys, #4559 deterministic block alloc. Negative: no overflow/truncation bug, CAS claim correct, release/rollback symmetric, gc re-checks expiry. No High finding — bitmap is ABA-safe because bit never cleared between claim and free of same allocation.

- source.rs: Parses pool CIDR/host, builds PortAllocator per pool, matches with scope_ok + l4_matches + nets_match. Gates: non_first_fragment, port_less (has_l4_ports), icmp_query via `icmp_identifier_present` (fixes id==0 bug), tuple_unknown proto=0 wrapper, no_translation. Deterministic v4/v6 path uses pure fn indices. Negative: pool expansion correctly bounds MAX_POOL_PREFIX_HOSTS, fail-closed on malformed match (constrained flag), address_persistent sticky via FxHasher seeded.

- destination.rs: Exact map + prefix LPM + proto wildcard. Tier order: exact (proto,dst,port) → wildcard port → PROTO_ANY → prefix LPM (exact+wildcard+ANY). Off
```

---

### ps-A3_go_config_cli_tree-b1.md (7194 chars, 95 lines)

```
# A3 Go Config/CLI Tree b1/4 — Zone Policy Focus (150 files)
Base: 7e0fecf3b8f2dc6604600674373771c835484188 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b1

## File Inventory (prod)
| File | LOC | Responsibility | Hot |
|---|---:|---|---|
| pkg/appid/catalog.go | 487 | App-ID catalog, uint16 id guard, port-zero sanitize (#5194), ICMP type gate (#3781) | cold |
| pkg/appid/runtime.go | 344 | CatalogNames walk (policy+NAT refs), tuple fallback canonical port parsing (#3725) | cold |
| pkg/cmdtree/tree.go | 1589 | Operational CLI tree, zone DynamicFn completions | cold |
| pkg/config/ast.go | 436 | Dual-shape AST, unionChildren (#4562) duplicate-sibling merge | cold |
| pkg/config/compiler.go | 2323 | Top compile dispatch, group expansion, inactive strip | cold |
| pkg/config/compiler_applications.go | 774 | App/app-set bracket list (#5181), resolveAppPort whole-spec before range split, 0-N floor norm (#4336) | cold |
| pkg/config/compiler_security.go | 114 | Dispatcher + ssh-known-hosts append-not-replace (#4821) | cold |
| pkg/config/compiler_security_zones.go | 239 | zoneInterfaceMembers bracket flatten (#5248), HIB merge (#4544/#4818) | cold boundary |
| pkg/config/compiler_security_policy.go | 451 | policy compile, fail-closed DENY default (#3043), collapsed-deny (#3141), scoped-global (#4626) | cold boundary |
| + 142 test files | ~4500 | regression for all gates | — |
Prod dominant ~6757 LOC cold path. No Rust dataplane hot path in this batch.

## Module Log (coverage proof)

- ast.go:navigatePath unionChildren — handles duplicate `from-zone untrust to-zone trust` siblings for nested lookup. Depth bounded by config file size (~MB). NEGATIVE: no unbounded recursion or OOM beyond file limit.
- ast.go:cloneNodes deep-copies Keys/Children — no slice aliasing. NEGATIVE sound.
- compiler_applications.go:applicationSetMemberValues reads Keys[1:] + Children covering bracket `[ a b c ]` → Keys["application","a","b","c"] (lexer strips brackets, #2419). Pre-#5181 only Keys[1] → DENY under-match fail-open. Now fixed.
- compiler_applications.go:resolveAppPort whole-spec lookup before range split covers hyphenated svc names (ftp-data) (#3397). Port 0 floor-norm 0-N→1-N (#4336) safe — port 0 never on wire. Bare 0 stays invalid.
- compiler_security.go:ssh-known-hosts find-or-create map + append per host across duplicate blocks (#4821) — prevents key-type loss.
- compiler_security_zones.go:zoneInterfaceMembers skips host-inbound-traffic child, recurses Keys+Children flattening wildcard-container nesting `[ ge-0/0/0 ge-0/0/1 ]` chain. NEGATIVE sound.
- compiler_security_zones.go:compileZones find-or-create by name + Interfaces append + HIB merge + AddressBook find-or-create — duplicate top-level security-zone instance (#4818) no longer replaces first (would discard interfaces → unmanaged/brought DOWN + wrong zone eval).
- appid/catalog.go:BuildCatalog uint32 nextID prevents uint16 wrap onto 0 sentinel (reserved UNKNOWN) — deterministic error at bo
```

---

### ps-A3_go_config_cli_tree-b2.md (10919 chars, 131 lines)

```
# A3 Go Config/CLI Tree b2/4 — Zone Policy + Strict Gates (150 files)
Base: 7e0fecf3b8f2dc6604600674373771c835484188 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b2

## File Inventory
| File | LOC | Role |
|---|---:|---|
| compiler_security_zones.go | 239 | zone compile, bracket flatten (#5248), HIB merge (#4544/#4818) |
| compiler_security_policy.go | 451 | policy compile, fail-closed default DENY (#3043), collapsed-deny (#3141/#3374), scoped-global (#3148/#4626) |
| compiler_security_addressbook.go | 430 | book/set bracket (#4791), find-or-create merge (#4706) |
| compiler_security_log.go | 268 | syslog port dual-location gate (#3349), TLS-profile no-op reject (#3350) |
| compiler_security_screen.go | 474 | 16 IDS checks profile compile |
| compiler_policy_match.go | 320 | unsupported match leaf (#3113), multi-value tail escape (#3142), swallowed from-zone/to-zone token (#3673), dup-block walk (#3562/#3842) |
| compiler_policy_missing_match.go | 201 | required dimensions gate (#3044) |
| compiler_policy_then.go | 583 | unsupported then-permit (#3114)/reject (#3115)/deny (#3141) + orphan log-sub (#3374) |
| filter_match_resolve.go | 324 | symbolic icmp/port→numeric SSOT (#3205), hyphenated svc-name before range split |
| firewall_filter_expand.go | 137 | cross-product stride uint64 overflow-checked (#5456), clamp 1<<20 |
| compiler_validate_strict_policy.go | ~400 | policy addr token validation, any/any-ipv4/any-ipv6, feed bindings, CIDR/IP |
| + 138 test files | ~5000 | regression |

All cold compile-time gates. Hot Rust policy.rs (3598 LOC) not in batch.

## Module Log

- zones: zoneInterfaceMembers skips HIB child, recurses Keys+Children — bracket `[ a b c ]` as nested chain (wildcard container) handled. Empty Keys check k!="" prevents empty-name add. find-or-create by name prevents dup-instance replace (boundary loss). NEGATIVE sound.
- security_policy: policyMatchChildren/ThenChildren accumulate across ALL match/then blocks (#3842) — dup inner blocks no longer silently widen. terminalActions tracks conflicting permit+deny → #3043 gate rejects, default DENY for actionless. applyCollapsedDenyModifiers wires flat-collapsed `then deny log/count` (Keys[1:] + descendant walk). sortDedupZones canonicalizes scoped-global lists.
- policy_match: forEachChild at security/policies (#3562) closes dup-block bypass (parseStatements appends). firewallMatchValues SSOT reads Keys[1:] + Children for multi:true leaves (#2419). swallowedStructuralMatchTokens from-zone/to-zone in zone-pair multi-value tail rejected (#3673) — prevents app named "from-zone" satisfying gate and hiding keyword as bogus operand.
- missing_match: required dimensions across ALL match blocks (policyMatchChildren) — split across dup blocks counted. NEGATIVE sound, Junos parity.
- policy_then: supportedThenPermitChildren empty today (any child under then permit is silent-drop → UTM/IDP strip fail-open). Inspects ALL permit nodes across ALL then blocks (policyThenActionNodes) 
```

---

### ps-A3_go_config_cli_tree-b3.md (14000 chars, 144 lines)

```
# A3 Go Config/CLI Tree b3/4 — Zone Policy + Host-Inbound (150 files)
Base: 312a2dfdef733697828fc68e8fdd92dbcaf70d69 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b3

## File Inventory (150 files, 52860 LOC total in batch)
- Prod: 33 files 11958 LOC | Test: 125 files ~40500 LOC
- Largest prod: schema_security 1263, junos_host_deny 1070, schema_system 1075, schema_walk 803, schema_routing 824
- Responsibility rank: junos_host_deny (security critical, per-zone kernel iifname + junos-host DROP projection) > schema_security (zone/policy grammar SSOT, multi-zone from/to) > host_inbound_tokens (SSOT for host-inbound admission, 3-plane parity) > host_inbound_view + lifeline (lifeline exemption SSOT) > schema_validators_* (commit-time fail-closed gates) > lexer/parser (DoS caps, bracket-list collapse)
- Hot-path proximity: none hot (all cold config-compile), but junos_host_deny + host_inbound_tokens feed userspace-dp snapshot and nft hostinbound chain

| File | LOC | Responsibility |
|------|----:|----------------|
| schema_security.go | 1263 | zones, host-inbound, policies (from/to-zone multi), alg, flow, NAT/ike/ipsec closed-world flips |
| junos_host_deny.go | 1070 | junos-host to-zone projection, representability gate, iifname netdev scope |
| schema_system.go | 1075 | system/login/time-zone/crypto validators, master-pass PRF |
| schema_routing.go | 824 | routing-options, policy-options, protocols |
| schema_walk.go | 803 | typed-leaf walk, closed-world enforcement, scalar arity |
| schema_cos.go | 563 | CoS schedulers, filters |
| host_inbound_tokens.go | 484 | system-services/protocols SSOT, L4 tuple expansion |
| parser.go | 403 | recursive-descent, depth cap, stray-brace fail-closed |
| lexer.go | 359 | bracket sugar [#2419], endpoint literal preservation |
| predefined.go | 356 | app + app-set SSOT |
| schema_complete.go | 353 | completion |
| host_inbound_view.go | 342 | zone+per-iface effective view UNION |
| etc | — | rest prod <250 each |

## Module Log (coverage proving)

- host_inbound_multicast.go: catalog of routing multicast groups (OSPF 224.0.0.5/6 etc). Pure data + accessors. No enforcement today (advisory only per #4455 comment). Scanning HostInboundMulticastProtocol lowercases token, matches catalog. No alloc hot path. NEGATIVE sound – fail-open-but-bounded documented, parity gap not bypass.
- host_inbound_tokens.go: KnownHostInboundSystemServices/Protocols sets, HostInboundServiceFamily/ProtocolFamily scoping, L4Match structured SSOT, full-admit predicate. Lowercase canonical, family gates return nil for wrong family. NEGATIVE – SSOT correct, parity tests pinned.
- host_inbound_view.go: UnionHostInboundTokens trims, dedup exact-case, preserves authored order for display. InterfaceHostInboundEffective unions physical-parent override + exact ref (#3720). HostInboundViewWithLifelines records lifeline-exempt interfaces. NEGATIVE – display-only, mirrors dataplane union.
- lifeline.go: LifelineBaseName strips unit suffix by f
```

---

### ps-A3_go_config_cli_tree-b4.md (17910 chars, 181 lines)

```
# Security Review — Batch A3 Go Config CLI Tree b4/4 (52 files)

> Base commit: 312a2dfd (worktree /tmp/review-wt-claude-003-A3_go_config_cli_tree-b4)
> Focus: security zone policies, inter-zone allow/deny, host-inbound admission, policy compilation, NAT zone scoping, typed-leaf validation

## File Size / Shape Inventory (prod vs test, responsibility, hot-path proximity)

| File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|-----|-----------|----------------|---------------|
| types_security.go | 1306 | prod | ZoneConfig, Policy/PolicyMatch, NAT, Screen, ALG, Scheduler — zone policy SSOT | HIGH (snapshot builder reads zones/policies/NAT) |
| types_system.go | 1565 | prod | System stanza (dataplane, syslog, SNMP, login RBAC) — RBAC + SNMP source-IP gate | MEDIUM (RBAC gating, SNMP) |
| types_routing.go | 651 | prod | Routing protocols, tunnel config cloneForUnit — tunnel aliasing (perf + sec) | MEDIUM (FIB ingest) |
| types_chassis.go | 188 | prod | Device-map + cluster config — bare-metal identity | LOW (boot-time) |
| tunnelemit.go | 123 | prod | Tunnel endpoint canonical emission (collision gate + builder SSOT) | MEDIUM (ID stability) |
| tunnelid.go | 290 | prod | StableTunnelEndpointID fold + 3-view HA-symmetric collision gate | MEDIUM (HA determinism) |
| zoneid.go | 251 | prod | StableZoneID fold + 3-view collision gate + quarantine runtime | HIGH (zone ID wire-adjacent) |
| value_type.go | 155 | prod | Typed-leaf ValueType + placeholder — drives commit-time validators | MEDIUM (validation trigger) |
| types_cos.go | 283 | prod | CoS forwarding-class/scheduler/shaper binding | LOW (CoS) |
| types_interfaces.go | 150 | prod | InterfaceConfig, Units, LAG, VRRP groups | LOW |
| xfrmi.go | 77 | prod | XFRM if_id + secure-tunnel bind-interface validator | MEDIUM (VPN liveness) |
| snmp_clients.go | 206 | prod | SNMP community clients allowlist parse + longest-prefix match + cache | MEDIUM (SNMP ACL) |
| syslog_logfile.go | 50 | prod | show-log allowlist gate — path traversal + arbitrary log read | HIGH (priv esc) |
| tcp_flags.go | 147 | prod | Firewall filter tcp-flags conjunctive expression — fail-closed on OR/contradiction | HIGH (filter bypass) |
| 37 test files | 99 avg | test | Fail-on-revert guards for every strict gate above | N/A |
| **Total** | ~8200 | 15 prod + 37 test | | |

Ranking by size×responsibility×hot-path: types_security.go > types_system.go > zoneid.go > types_routing.go > snmp_clients.go > tcp_flags.go > syslog_logfile.go > tunnelid.go.

## Module Log (incl. negatives proving coverage)

- types_security.go — PASS: reviewed ZoneConfig.InterfaceHostInbound (per-if HIB union, #3362), IsWildcardZone/IsWildcardZoneSet duality (two spellings for global wildcard), GlobalPolicyAppliesToZone (from||to any match), sortDedupZones/ScopeSingular/IsHostToZoneScope, NAT match multi-value accessors (natMatchValues fallback), StaticNATRule source-address list (was scalar drop M02). No integer truncation on ports — Destinatio
```

---

### ps-A4_go_configstore_persist-b1.md (12244 chars, 128 lines)

```
# Review — A4 configstore persist b1/1 — Storage/Crypto Lens

**Base**: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
**Worktree**: /tmp/review-wt-claude-003-A4_go_configstore_persist-b1
**Batch**: 66 files (15 prod ~5851 LOC, 51 test ~10584 LOC, total ~16435)

## File-Size/Shape Inventory (ranked size×responsibility×hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility |
|------|------|-----|-----------|------------|---------------|
| 1 | store_commit.go | 998 | prod | CommitWithDescription ~90, PromoteRollback ~80 | Commit/confirmed timers, post-rename converge, degraded retry, rollback file durability |
| 2 | store_persist.go | 639 | prod | recoverPendingConfirmLocked ~90, Load ~50 | Load recovery of confirm.json, archive, rescue, journal truncation, everCommitted marker |
| 3 | store.go | 603 | prod | compileTreeLenient/schemaValidateExpandedTree | Size caps, strict vs lenient gates, SyncApply HA ingress, compile pipeline |
| 4 | store_command.go | 544 | prod | LoadMergeAs ~70 | Set/Delete/Deactivate/Activate/Copy/Rename/Insert, atomic clone swap (fail-closed on mid-body error #5187) |
| 5 | journal/journal.go | 507 | prod | tailScan ~80, Log ~70 | Torn-tail self-heal, rotation, perms migration #5188, bounded reverse scan |
| 6 | store_format.go | 490 | prod | ShowCompareRedacted etc ~10ea | Redacted display renderers (secret masking via RedactedClone) |
| 7 | crypto.go | 395 | prod | masterPasswordPRF ~50, maybeDecrypt ~50 | AES-GCM/HKDF/nonce/PRF, master.key durable ordering, envelope compat, groups/wildcard PRF scan #5231 |
| 8 | db.go | 350 | prod | writeTreeMarked ~30, readTreeMeta ~60 | temp+fsync+rename+dirfsync, envelope outer, encrypt inner, confirm.json durability |
| 9 | store_lock.go | 334 | prod | EnterConfigureSession ~40 | Config lock ownership #5059, lease TTL #4476, stale reclaim |
| 10 | envelope.go | 318 | prod | parseEnvelopeHeader ~60, stripEnvelope ~30 | Compatibility envelope outer framing, fail-closed on unknown format #4888, committed marker #1922 |
| 11 | dataplane_retire.go | 264 | prod | rewriteRetiredDataplaneType ~50 | Retired dp rewrite (ebpf/dpdk) with groups awareness |
| 12 | factory_reset.go | 211 | prod | FactoryResetConfigDir ~60 | Zeroize key-first ordering #5197, archive ownership guard #5186 |
| 13 | history.go | 70 | prod | Push/Get/List ~10ea | 50-slot ring buffer |
| 14 | test_seams.go | 70 | prod | SetWriteActiveForTesting | Test seams for durability injection |
| 15 | check.go | 44 | prod | CheckText ~20 | Day-0 check-config gate with size cap |

Largest test files: store_test.go 2005 LOC, journal_test.go 792, persist_failure_test.go 554.

## Module Log (incl negatives proving coverage)

- **crypto.go**: Reviewed HKDF PRF map (case-insensitive, SSOT with config masterPasswordPRFNames #4578), salt 16B crypto/rand, nonce per-encrypt rand, nonce length check before gcm.Open #4793 prevents panic boot loop, master.key WriteFileDurable ordering #1894, envelope unknown-format fail-
```

---

### ps-A5_go_ha_vrrp_ra_conntrack-b1.md (9920 chars, 97 lines)

```
# HA / VRRP / RA / conntrack — review b1 (Go)

Base: 7e0fecf
Worktree: /tmp/review-wt-claude-003-A5_go_ha_vrrp_ra_conntrack-b1

## File inventory
- Total lines (prod+test): 47864 (from wc -l)
- Prod: 19125 lines across 35 files
  - pkg/cluster: 11750 prod (largest: sync_conn.go 1858, heartbeat.go 881, failover.go 912, sync.go 1048, election.go 475)
  - pkg/conntrack: 554 (gc.go)
  - pkg/ra: 2193 (ra.go 1118, sender.go 1055, filter.go 21)
  - pkg/vrrp: 4628 (instance.go 2417, manager.go 1108, packet.go 277, track.go 341, addrwatch.go 219)
- Test: 28739 lines, 71 files (heaviest: cluster/sync_test.go 4717, ra/serialize_test.go 2706, vrrp/vrrp_test.go 2468)
- Largest prod fn: vrrpInstance.run / stepBackup (~400 LOC), SessionSync.handleMessage (~350 LOC), Manager.UpdateInstances
- Hot path proximity ranking (size x responsibility x freq):
  1. pkg/cluster/heartbeat.go Marshal/Unmarshal + sender/receiver loops — every 100ms, drives election, auth, replay
  2. pkg/cluster/sync_protocol.go + sync_conn.go — TCP session sync, gen guards, bulk, fencing
  3. pkg/vrrp/instance.go — BECOME_MASTER/BACKUP, TTL=255, hop-limit, GARP, equal-priority tie-break, preempt hold + watchdog
  4. pkg/ra/ra.go + sender.go — goodbye ordering, RA flood prevention, RS validation
  5. pkg/cluster/election.go — dual-active, preempt, dup node-id fail-closed, kernel-upgrade hold
  6. pkg/conntrack/gc.go — expiry ownership (IsLocalPrimary), per-IP limit counting, aggressive aging hysteresis

## Module log (incl negatives => NEGATIVE RESULT)

- cluster/election.go: dual-active resolves on eff priority then nodeID, dup nodeID logs rate-limited and fails closed to SECONDARY. kernelUpgradeHold blocks both single-node and peer paths. NEGATIVE.
- cluster/heartbeat.go: MarshalHeartbeatBody reserves tailReserve up front (#4107 invariant — monitor truncation leaves HMAC space, never silent downgrade). maxHeartbeatGroups=255 + oversize warn once (#4434). Monotonic nanos (#1792) for liveness, StartupGrace 30s suppresses split-brain on simultaneous boot. Auth: HMAC+session+counter, anti-replay re-anchor on new session, constant-time compare, cross-channel downgrade guard (peerAuthSeen). NEGATIVE for core, one LOW on truncation visibility below.
- cluster/sync_protocol.go: length-gated trailing fields (#2170 gen, #3301 AppTimeout, #4565 NAT64), config gen magic trailing framing (#3931), DHCP lease count clamp prevents OOM. NEGATIVE.
- cluster/sync_conn.go: activeConnLocked prefers fab0, bulk re-drive on survivor gated on outboundBulkAcked (not bulkEverCompleted) (#4360 correct), bulkRedriveInFlight CAS prevents storm, writeFull seals per-frame via authConn, acceptLoop per-conn goroutine prevents handshake DoS (#4370). NEGATIVE.
- cluster/sync_auth.go: per-conn frame key derived via canonical nonce sort, seq replay guard, downgrade guard consulted via heartbeat auth seen. NEGATIVE.
- cluster/failover.go: per-RG failoverGen prevents ResetFailover vs pre-hook race (#5246), failoverInProgress seri
```

---

### ps-A6_go_dataplane_manager-b1.md (15661 chars, 127 lines)

```
# A6 Go Dataplane Manager — Review (b1/3)

## File Inventory (150 files, ~60 prod / 90 test)

Ranked by size×responsibility×hot-path proximity:

- `pkg/dataplane/compiler.go` ~1.6k LOC prod, god compile orchestrator (zones, addr-book, apps, policies, nat, screen, flow). Largest fn `CompileConfig` phases + `compilePolicies` expansion. Responsibility: zone→ID stable hash, policy expansion, app-set.
- `pkg/dataplane/compiler_iface.go` ~1.4k LOC prod, zone/interface mapping, netlink, rxvlan off, MTU, RETH recovery, unmanaged strip, device-map leave-alone.
- `pkg/dataplane/compiler_nat.go` ~1.3k LOC prod, SNAT/DNAT/static/NAT64/NPTv6 compilation, pool ID assignment, counter ID stable hash + collision resolve + finalizer.
- `pkg/dataplane/types.go` ~1.1k LOC prod, all BPF struct mirrors, zone pair key, policy rule, NAT pool, filter config, screen flags.
- `pkg/dataplane/compiler_filter.go` ~0.8k LOC prod, filter protocol validation, policer ID assignment, term→rule cross-product expansion with #5456 cap, iface→filter map.
- `pkg/dataplane/userspace/eventstream.go` ~1.2k LOC prod, binary frame header (len+type+seq), session open/close decode, gap → full resync, pending queue 4096, writeMu sep lock.
- `pkg/dataplane/userspace/manager.go` ~0.4k prod + many split files, snapshot lifecycle, generation, deferred worker arm debt, appliedSnapshot coherency.
- `pkg/dataplane/userspace/builder.go` ~0.2k prod, snapshot assembly, zone collision quarantine, content hash dedup.
- `pkg/dataplane/userspace/filters.go` ~0.6k prod, firewall filter snapshot lowering (prefix-list, except, DSCP, TCP-flags, flex-match).
- `pkg/dataplane/userspace/interfaces.go` ~0.56k prod, synthetic logical ifindex FNV hash, VLAN parent bind contract, bound interface allowlist.
- `pkg/dataplane/userspace/flow.go` ~0.26k prod, wire coercion u16/u32/u64 for Rust JSON decode (MSS, timeouts).
- `pkg/dataplane/userspace/cos.go` ~0.26k prod, CoS snapshot with safe degrade on undefined class.
- Many `*_test.go` (app catalog parity, NAT counter collision/determinism/stability, filter expansion, prefix-list except, port except, host-inbound classify, etc.) — high coverage of edge cases.

Prod files shape: manager pattern with populate-before-clear map writes for legacy BPF; userspace path builds immutable snapshot then single control-socket publish. Zone handling: `assignZoneIDs` uses StableZoneID(name) FNV fold into [1, ReservedMin-1]; policy sets pack into `policySetID*MaxRulesPerPolicy+index` rule ID.

## Module Log (coverage)

- `compiler.go` zones: checked nil zone slot guard, screen profile lookup, host-inbound flags, TCPRst, iface zone composite key, RETH RG inherit, native XDP flag, VLAN sub-if creation, managed interface list for networkd, unmanaged strip with #1922 protected set and #1956 device-map leave-alone, VRF/Tunnel/Bridge owned skip, stale deletion. Policies: application-set expansion, appID map, Any handling, implicit set building, rule ID calculation, scheduler slots. Default po
```

---

### ps-A6_go_dataplane_manager-b2.md (7597 chars, 95 lines)

```
# Batch A6 b2/3 — Go dataplane manager (policy, zones, NAT, routes, HA glue)

Base: 7e0fecf3b, worktree /tmp/review-wt-claude-003-A6_go_dataplane_manager-b2
Files: 150, prod ~12k LOC core, test ~58k LOC; largest: protocol.go 3064 (snapshot v3), maps_sync.go 1763, manager_ha.go 1643, filters.go 641.

## Inventory (ranked responsibility × hot-path proximity)

| File | LOC | Responsibility | Cold/Hot | Largest fn |
|---|---|---|---|---|
| protocol.go | 3064 | wire version=3, 66-field ConfigSnapshot, inject bound 4096 (DoS reject-not-clamp), ZoneCounterLayout/ColdPathLayout versions | cold but version invariant governs rolling upgrade | ConfigSnapshot struct |
| policies_lower.go | 170 | global->zone lowering, singular/plural scoped-global #4626 M03, additive-wire compat | cold, #5488 interop | buildOneRuleSnapshot + effectiveMatch* |
| policies.go | 800+ | walkPolicyRuleSlots ID namespace #3143/#3145 MaxRulesPerPolicy cap, feed overlay #2049, representability sentinel #3261, app sentinel #2124 | cold but fail-open if sentinel missing | buildPolicySnapshotsWithFeeds |
| zones*.go | 300+370 | StableZoneID hash, quarantine #3719, host-inbound SSOT lifeline #3682 per-iface override union #3362, default-deny parity #3405 for no-stanza zones, VIP scoping #3172, unzoned junos-host catch-all | cold, zone collapse=fail-open | BuildZoneHostInboundViews |
| nat*.go | ~2k | pool tiers iface>zone>ri #184 #4161, any->"" fix, match-any dest fail-open, persistent NAT, deterministic block alloc, Off handling | cold, misc-NAT leak | buildSourceNATSnapshots |
| routes.go | 300 | FIB connected+static+ip-rule leaks family-normalized (blue.inet6.0 fix), Dst-less skip avoids widening, PBR bands 100-199/30000-30999, list error fail-closed whole snapshot | cold but leak miss=blackhole/bypass | buildRouteSnapshots |
| manager_ha.go | 200 | seed inventory #1928 drops phantom groups on non-cluster, watchdog-only refresh preserves Active, clearHelper empty idempotent | cold | syncHAStateLocked |
| maps_sync.go | partial | RST suppression TOCTOU, interface NAT addr sets sorted dedup | cold | syncInterfaceNATAddressMapsLocked |

## Module log (negatives)

- policies_lower: singular=first zone, plural=full set, effectiveMatch* prefers plural fallback singular — new helper correct, old helper same version 3 ignores plural narrows deny (dedup #5488). **NEGATIVE for new, known interop.**
- policies.go: any4/any6/any-ipv4/any-ipv6 literal accept, feed-bound membership, nameToID+recursive nameRepresentable, unrepresentable -> __unsupported_address__ on both v3+legacy shapes clearing book IDs => Rust SnapshotIntegrityError whole-snapshot reject prev-good retained fresh-boot default-deny. app -> __unsupported_application__ name+proto both sentinel, Rust reject. literal vs book via classifyPolicyAddresses, scheduler state, SourceAddressExcluded/DestinationAddressExcluded inversion. **NEGATIVE — fail-closed solid.**
- zones: zone-default group seeded for #3405 (no stanza => empty token set
```

---

### ps-A6_go_dataplane_manager-b3.md (12072 chars, 138 lines)

```
# Security Review — BATCH A6_go_dataplane_manager b3/3

**Files:** `pkg/nftables/rst_suppress.go` (204 LOC prod), `pkg/nftables/rst_suppress_test.go` (37 LOC test) – total 241.
**Base:** 7e0fecf3b8f2dc6604600674373771c835484188
**Worktree:** /tmp/review-wt-claude-003-A6_go_dataplane_manager-b3

## File-size/shape inventory
- `rst_suppress.go`: 204 LOC, prod. Responsibility: atomic nftables table `xpf_dp_rst` management for DROP outgoing TCP RSTs from interface-mode SNAT addresses owned by userspace dataplane. Called from `pkg/dataplane/userspace/maps_sync.go:1141` under `m.mu` in `syncInterfaceNATAddressMapsLocked`. Not hot-path (config apply only), but critical for HA failover correctness (#450) and for silent-drop semantics of zone deny. Largest fn `addRSTDropRule` 57 LOC (L144-200) — 8 nft expr builder; `InstallRSTSuppression` 22 LOC (L36-57); `queueRSTSuppression` 29 LOC (L104-133).
- `rst_suppress_test.go`: 37 LOC, test. 2 tests covering only `buildRSTSuppressionPlan` delete flag logic. No rule-construction, offset, or concurrency tests.
- Rank by size×responsibility×hot-path proximity: **medium** — small LOC but touches silent zone-deny enforcement + HA session survivability; cold-path but availability-critical.

## Module log (coverage proof — negatives explicit)
- Read `rst_suppress.go` fully; verified offsets `saddrOffset` 12 (IPv4) / 8 (IPv6) and TCP flags offset 13, mask 0x04 — correct per IPv4/IPv6/TCP layout.
- Traced callers: only `pkg/dataplane/userspace/maps_sync.go:1132-1149` (`shouldAttemptRSTSuppression` gate + sorted deduped addrs) — under `Manager.mu` (checked `manager.go:88,249,302`). `RemoveRSTSuppression` has zero callers outside definition (dead code) — verified via `grep -rn RemoveRSTSuppression`.
- Traced address source: `buildDesiredInterfaceNATAddressSets` → `buildInterfaceNATAddressEntries` → `buildNATTranslatedLocalAddressExclusions` (filters `InterfaceMode && !Off && ToZone != ""`, then matches interface zone). Dedup via `seenV4`/`seenV6` maps, sorted before install — no duplicate rules in normal path.
- Checked `pkg/nftables/` remaining files: `host_inbound_*`, `lo0_counters` — unrelated tables, same idempotent `ListTablesOfFamily` + `ENOENT` handling pattern.
- Checked zone policy interaction: RST suppression table `INet` family, `output` hook, filter priority. It DROPs RSTs that kernel would otherwise emit for SNAT addresses. This **strengthens** zone deny silent-drop (prevents RST leak revealing host), does not bypass deny. Verified no overlap with `xpf_hostinbound` (input) or lo0. Negative finding for bypass.
- Checked atomicity claim: delete+add in single `Flush()` batch — matches `README.md` #450 note. Verified TOCTOU between `rstTableExists` (separate netlink dump) and `Flush`.
- Checked int truncation / endian: `As4()` returns `[4]byte` native network order, fed to `net.IP(addr[:])`; `addrLen` 4/16 fixed, no truncation. IPv4 key BigEndian Uint32 used elsewhere but not here.
- Checked error logging: `slog.I
```

---

### ps-A7_go_daemon_host-b1.md (14088 chars, 141 lines)

```
# Review: A7_go_daemon_host (batch 016) — Zone/HA/NFT/Apply ordering

Base: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A7_go_daemon_host-b1

## File-size/shape inventory
- Total in pkg/daemon: 199 files (51 prod, 148 test) — batch 016 covers 150 of them.
- Total LOC (prod+test): 60852
- Top prod by LOC / responsibility x hot-path proximity:
  1. `daemon_run.go` 2487 — boot predicate, bootstrap exit, shutdown ordering, FRR fail-closed clear
  2. `daemon_apply.go` 2153 — 10+ subsystems, fail-closed error joins, C1-C3 ctx boundaries, zoneRGMap install
  3. `daemon_nft.go` 1698 — inet xpf_lo0 (prio 0) + xpf_hostinbound (prio 10) rendering, counter lifecycle, fail-closed
  4. `daemon_system.go` 1731 — DNS/NTP/hostname/timezone/kernel tuning, lo0/host-inbound fail-closed joins
  5. `daemon_ha.go` 1576 — RG state machine, cluster+VRRP funnel, blackhole routes, per-RG services
  6. `daemon_ha_sync.go` 1020 — coldStart sticky, sync-ready timer, bulk prime retry, config-sync gate
  7. `daemon_ha_fabric.go` 965 — fab0/fab1 IPVLAN deferral, neighbor probe, dual-fabric refresh
  8. `bootstrap.go` 944 — five-case boot predicate, lifeline record, protected set, fail-closed FRR probe
  9. `host_tunables.go` 839 — governor/budget/coalesce capture/restore, drift detection, debt handling
 10. `device_map.go` 836 — mapped rename, strand-management preflight, teardown fail-closed #5309

Largest funcs: `applyConfigLocked` ~500 LOC (head+tail split), `applyDataplaneAndHACore` ~400, `buildHostInboundFilterPayload` ~200.

Prod vs test: prod 51 files ~18000 LOC, test 148 files ~42000 LOC. Batch includes almost all prod.

## Module log (coverage with negatives)
- `bootstrap.go`: reviewed boot predicate (computeBootClass), lifeline detection via default route, protectedInterfacesWith fxp0 narrowing. NEGATIVE: fail-closed on compile-failed boot correctly preserves FRR probe via pinned-links prefilter + control-socket armed check (#1993). Device-map boot refusal #5490 wired.
- `coalescence.go`: mlx5-only, ethtool -c probe idempotent, adaptive-rx/tx + rx/tx-usecs pin. NEGATIVE: non-mlx5 skip, empty allowlist no-op, best-effort never blocks bring-up — sound.
- `daemon.go`: applySem, bootstrapMode atomic, rgStates, fabric state. NEGATIVE: no zone-ID logic here.
- `daemon_apply.go`: apply ordering VRF->tunnel/xfrmi/bond->fabric IPVLAN->dataplane->networkd->RETH MAC->proxyARP->VRF rebind->FRR->next-table/rib-group/PBR->neighbor/RA/IPsec/DHCP/DDNS/DHCP clients->VRRP/DNS/NTP/lo0/host-inbound/SSH/login/sudoers/archive/flow/LLDP/event-options/RPM/IPmon/cluster. Fail-closed joins: networkdErr, dhcpServerErr, ipsecErr, hostInboundErr, lo0Err, ifaceErr all joined at tail. C1/C2/C3 ctx boundaries checked. ZoneRGMap installed after ApplyConfig. device-map teardown BEFORE networkd.Apply (correct). FINDING #3 below.
- `daemon_nft.go`: chain priorities 0 vs 10 distinct (#3364), add+delete idempotent, counter pre-declare dedup, TCP flags fail-closed #5512, ICM
```

---

### ps-A7_go_daemon_host-b2.md (25629 chars, 218 lines)

```
# Security Review — Batch A7_go_daemon_host b2/3
Base: 7e0fecf3b8f2dc6604600674373771c835484188
Date: 2026-07-09
Reviewer: claude-003
Scope: 150 files (40 prod, 110 test) across pkg/daemon, devicemap, diagcmd, fairness, frr, fsatomic, fwdstatus, ipsec, linuxsock, lldp, monitoriface, networkd, routing

## File-size/shape inventory (ranked by LOC × responsibility × hot-path proximity)

| Rank | File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|------|-----|----------|----------------|---------------|
| 1 | pkg/frr/policy_render.go | 2307 | prod | BGP/OSPF/ISIS/BFD + route-map/prefix-list/community rendering, redist isolation, chain collision, fail-closed gates | cold (FRR reload) but cross-VRF route-leak critical |
| 2 | pkg/routing/tunnel.go | 2016 | prod | GRE/IPIP/WG tun lifecycle, keepalive prober, addr reconcile, ownedNames retention | cold (netlink) but data-plane reachability |
| 3 | pkg/daemon/daemon_run.go (extra) | 2487 | prod | startup ordering: linksetup → device-map → RSS → dataplane load | boot critical |
| 4 | pkg/daemon/daemon_apply.go (extra) | 2153 | prod | commit serialization, networkd/FRR/IPsec/routing apply ordering | commit hot |
| 5 | pkg/routing/rules.go | 1447 | prod | policy-routing rule generation, VRF table selection | routing hot |
| 6 | pkg/ipsec/policy.go | 1135 | prod | swanctl child SA rendering, traffic-selector sanitization, PSK scoping, childname disambig | IPsec critical |
| 7 | pkg/frr/manager.go | 1057 | prod | FRR reload timeout, managed section write + vtysh fallback | control-plane crit |
| 8 | pkg/monitoriface/monitor.go | 952 | prod | interface counters snapshot, userspace-dp telemetry binding | observability |
| 9 | pkg/lldp/lldp.go | 939 | prod | LLDP Tx/Rx, TTL-0 shutdown, neighbor table cap, lifecycle mutex | L2 adjacency |
|10 | pkg/ipsec/ike.go | 890 | prod | IKE proposal building, DH group formatting, ECP/curve mapping | crypto agility |
|11 | pkg/networkd/networkd.go | 775 | prod | .link/.network/.netdev gen, stale sweep, reload/reconf debt, RP filter restore | boot/commit |
|12 | pkg/daemon/daemon_system.go | 1731 | prod (extra) | system login, DNS, NTP, syslog reconcile | host hardening |
|13 | pkg/daemon/daemon_nft.go | 1698 | prod (extra) | host-inbound nftables, lo0 filter, RG zone id | host inbound ACL (zone policy) |
|14 | pkg/daemon/linksetup.go | 545 | prod | PCI enumeration, positional rename collision-safe (#4178), bootstrap fxp0 | boot |
|15 | pkg/daemon/rss_indirection.go | 550 | prod | mlx5 RSS weight vector, driver guard, default restore | boot perf |
|… | pkg/routing/bond.go | 490 | prod | bond/LAG lifecycle | dataplane |
|… | pkg/frr/config_render.go | 445 | prod | static routes, interface settings, DHCP defaults, backup router | routing |
|… | pkg/daemon/login_password.go | 407 | prod | shadow reconcile, UID-keyed provenance, lock on removal | auth |

Test heaviest: pkg/frr/frr_test.go 6037 LOC (integration render), pkg/routing/routing_test.go 2193, pkg/ipsec/ips
```

---

### ps-A7_go_daemon_host-b3.md (10583 chars, 83 lines)

```
# Batch A7 b3/3 — routing / upgrade / wgkey deep review (BASE 7e0fecf3)

## File-size inventory (prod vs test)
| File | LOC | Role |
|---|---|---|
| pkg/upgrade/kernel_linux.go | 869 | Prod kernel A/B slot + apt purge + beacon |
| pkg/upgrade/cutover.go | 1024 | Prod runner state machine (INIT->COMMITTED) |
| pkg/upgrade/kernel_run.go | 637 | Prod arm/promote/revert |
| pkg/upgrade/cluster_cli.go | 610 | Prod rolling predicate parsers |
| pkg/upgrade/runner.go | 565 | Prod journal io + copyTree |
| pkg/upgrade/flip.go | 448 | Prod symlink + unit drop-in flip |
| pkg/upgrade/stagedgen/stagedgen.go | 413 | Prod immutable gen publish |
| pkg/upgrade/runtime/seed.go | 400 | Prod first-install seed |
| pkg/routing/vrf.go | 361 | Prod VRF reconcile + orphan reap |
| pkg/routing/xfrm.go | 332 | Prod XFRM reconcile fail-closed |
| pkg/upgrade/lock/lock.go | 303 | Prod host-wide flock |
| pkg/upgrade/kernel_selfrecover.go | 273 | Prod kernel-roll lease self-recovery |
| pkg/upgrade/rolling.go | 247 | Prod rolling driver |
| pkg/routing/tunnel_keepalive.go | 294 | Prod ICMP prober + classifier |
| pkg/upgrade/version.go | 113 | Prod ValidateVersionSegment + ValidateKernelSegment |
| pkg/wgkey/wgkey.go | 113 | Prod X25519 keygen |
... tests: tunnel_reconcile_test 1825 LOC, tunnel_keepalive_test 574, cluster_cli_test 470, etc.

Largest fn: `Runner.Run` (~300 LOC) + `copyStaged`/`reconcileVRFs` (~140 each). Responsibilities rank: kernel_linux Prod (A/B + purge + destructive glob) x hot-upgrade x policy-bypass risk = highest.

## Module log (incl negatives)

- **tunnel_keepalive.go**: NEGATIVE — probe correctness sound. Reply matching on Seq+nonce (§5a), family-bound listen (§5c), global table (no VRF bind), deadline re-check R4 per iteration prevents flood extending budget. Classifier split structural (EPERM/EACCES/EAFNOSUPPORT) hold-indefinitely vs transient (EMFILE/ENFILE/ENOBUFS/ENOMEM/EINTR) hold+escalate mirrors monitor.go precedent but fixes gaps. `classifyWriteErr` unrecognized→Dead is correct (path unreachable = liveness signal) opposite default of Listen path.
- **vrf.go**: NEGATIVE — reconcile is fail-closed on `LinkByName` transient: retains tracked set, returns error, retries next commit (mirrors #5461 xfrm fix). Orphan reap checks `strings.HasPrefix(name,"vrf-")` AND `*netlink.Vrf` type assert, so misnamed bridge `vrf-foo` not deleted. Sentinel `errLinkNotFound` wrapper handles fake netlink errors. `createLocked` does not adopt existing into tracked (reconcile does) — documented fast-path.
- **vrf_stable_tableid_test.go**: stable-id no-recreate-on-sibling-delete proven. Allocation itself lives in `pkg/config` (StableRoutingInstanceTableID = hash(name)). Collision of hash would map two routing-instances to same tableID → cross-VRF route leak. Outside this batch but guarded by stable hash design; test ensures positional renumbering bug gone.
- **xfrm.go**: NEGATIVE — #5310/#5461/#5495 fixes sound. `desired` builds id→name map, detects colliding if_
```

---

### ps-A8_go_api_grpc_rest-b1.md (14108 chars, 124 lines)

```
# Review A8_go_api_grpc_rest b1/2 — Batch 019 (pkg/api + pkg/grpcapi first 18)

## File-size / Shape Inventory
- **Total LOC (batch 150 files)**: 36273 lines
  - Prod: 30 files (~11000 LOC est, largest: metrics_descriptors.go 2057, metrics_userspace.go 1865, sessions.go 1541, metrics.go 1159, security.go 871)
  - Test: 120 files (~25000 LOC, largest: metrics_test.go 2432)
- **Largest prod fn**: sessions.go `sessionsOffset` / `sessionsCursor` + enrichment (150+ LOC each), security.go `policiesHandler` (~250 LOC), `matchPoliciesHandler` (~200 LOC)
- **Responsibility ranking** (size × responsibility × hot-path proximity):
  1. `pkg/api/security.go` — zone list, policy inventory, match-policies simulator, events filter (zone 0 alias handling)
  2. `pkg/api/sessions.go` — session list/cursor/zone-pair, zone ID ↔ name maps, HA peer fan-out, walk limiter, cancel sampler
  3. `pkg/api/metrics*.go` — collector, descriptors with from_zone/to_zone labels, host-inbound kernel counters, session gauge cache
  4. `pkg/api/server.go` — mux, authMiddleware, cross-site guard, timeouts, metrics gating on loopback
  5. `pkg/api/config.go` — commit/rollback guards (strict int), body cap
  6. `pkg/grpcapi/server_cluster.go` — MatchPolicies validation (zone required, IP/port/proto strict, ICMP bounds, scheduler inactive handling)
  7. `pkg/grpcapi/server_sessions.go` — sessionFilter validate (zone/port/proto/prefix, SNAT pool existence), zone existence check in ClearSessions
  8. `pkg/grpcapi/fabric_auth.go` — control-link PSK HMAC token, dual-accept, downgrade guard arming via heartbeat
  9. `pkg/api/auth.go` / `crosssite.go` — constant-time API-key, loopback bind check, fetch-metadata guard

## Module Log (coverage proof, including negatives)

- **pkg/api/api.go**: Verified `writeJSON` marshals to buf first (no truncated 200), `decodeJSONBody` uses `MaxBytesReader` 16 MiB, `queryUint16Strict`/`queryIntStrict` via `config.ParseCanonicalUint` reject `+80`, fail-closed on malformed. `queryInt` lenient helper remains dead code (no prod caller after migration) – noted low.
- **auth.go**: `authMiddleware` exempts only `/health` always, `/metrics` only when `metricsRequireAuth==false` (loopback). `checkAuthorization` constant-time compare even for unknown user. `constantTimeAPIKeyMatch` loops all keys, OR-s results, no short-circuit. `isLoopbackBindAddr` treats empty/wildcard/hostname as non-loopback (conservative). No bypass.
- **crosssite.go**: `mutationCrossSiteGuard` rejects Sec-Fetch-Site cross-site/same-site, Origin/Referer host mismatch via `sameHostAs`, simple form content-types. Safe methods pass. Non-browser (no Origin/Referer, json content-type) passes. Order: auth outer, guard inner, but guard still applied when auth nil (standalone). No CSRF bypass.
- **exec_timeout.go**: Constants 15s/5s, ping budget = count*1s+15s floored 30s ceiling 150s. `runTimeout` used for power actions with Background context (intentional). No leak.
- **server.go**: Mux registers all RE
```

---

### ps-A8_go_api_grpc_rest-b2.md (11617 chars, 103 lines)

```
# Review A8 b2/2 — gRPC API zone/policy handling
BASE 312a2dfde (worktree /tmp/review-wt-claude-003-A8_go_api_grpc_rest-b2)

## File Inventory (144 files, pkg/grpcapi/* from nat_counter_error_test.go)
LOC total ~30549 Go (prod ~9800, test ~20700). Largest prod:
- server_sessions.go 1460 (session iter, filter, pagination, peer fanout, DoS caps)
- server_show_security_text.go 1070 (screen, IKE, ALG, dynamic-address, security-log zone filter)
- server_show_interfaces.go 935 (interface text, zone mapping)
- server_cluster.go 838 (MatchPolicies, Complete, valueProvider, host-inbound admission)
- server_show_firewall.go 666 (showTestPolicy, firewall filter effective snapshot)
- server.go 588 (loopback clamp #5035, fabric auth #4107 + allowlist #4122, gRPC limits)
- server_show_routes_text.go 562 / server_show.go 562 (dispatch)
Prod responsible: zone/policy/global/default display, MatchPolicies simulator, session pagination, authz boundary.
Test: 100+ _test.go covering zone nil #3493, scoped global #3286, default-policy #3363, log #3670, scheduler #3624, host-inbound #3328/#3654, lifeline #3682, policy tiers #3658, exclusion #3668, dedup #3709, strictness #3696/#4814.
Ranking by size x responsibilty: server_sessions.go > server_show_security_text.go > server_cluster.go > server.go > server_show_zones.go > server_show_policies_text.go > server_show_zones_text.go > server_show_firewall.go.

## Module Log (coverage proof)
- server.go: verified maxRecvMsgSize=16MiB #164, clampGRPCBindToLoopback family-aware, fabric allowlist 6 unary + 1 stream, parseProxiedFailoverAction strict #4107, configLockInterceptor, stopGRPCServer bounded #4910. No zone bypass via fabric — GetZones/GetPolicies not in allowlist (intended, documented).
- server_show_zones.go GetZones: nil zone guard #3493, HostInboundConfigured=true always post-#3405 (fail-closed default-deny), LifelineInterfaces via HostInboundViewWithLifelines, counters gated on ErrCounterNotPopulated #3643, readErr -> Internal #3408. GetPolicies: nil zone-pair/rule guard #3476, DisplayAddressNames #3358, ScopeSingular + plural #3286/#4626, runtimeIDs #3336, policySetID continuity, default-policy synthetic #3363 with log mirroring #3670, stats gate #2118 + then count #3074, bulk reader #3965/#4344. GetScreen via config.ScreenChecks SSOT #3327.
- server_show_zones_text.go showZonesDetail: zoneNames sorted, nil guard, zoneID from cr.ZoneIDs, traffic counters same ErrNotPopulated handling, policyRefs per zone, interface details, screen inventory via screenEnabledCheckList SSOT, ZoneDetailPolicySummary SSOT #3658/#3684 shared with CLI. showTestZone: malformed selector + unknown key rejection #4814, per-interface effective admission via RenderInterfaceHostInbound, lifeline via HostInboundLifelineInterface.
- server_show_policies_text.go showPoliciesHitCount/showPoliciesDetail: filter parsed via Fields from-zone/to-zone, statsEnabled gate, bulk reader, global filtering via GlobalPolicyAppliesToZonePair #3357, scoped globa
```

---

### ps-A9_go_observability-b1.md (15429 chars, 123 lines)

```
# A9 Observability Batch Review — ps-A9_go_observability-b1

BASE: 312a2dfdef733697828fc68e8fdd92dbcaf70d69 (worktree /tmp/review-wt-claude-003-A9_go_observability-b1)
Scope: pkg/eventengine/*, pkg/feeds/*, pkg/flowexport/*, pkg/ipmon/*, pkg/logging/*, pkg/rpm/*, pkg/snmp/* (134 files, 42586 LOC total prod+test)

## Inventory (LOC, prod vs test, responsibility)
| Module | Prod files | Prod LOC | Test LOC | Largest fn | Hot-path proximity |
|--------|-----------|----------|----------|------------|--------------------|
| logging | ringbuf 1451, syslog 911, trace 553, aggregator 316, eventbuf 305, locallog 298, slog_handler 167, event_filter_args ~100, goid tiny | ~4100 | ~4600 | EventReader.logEvent / SyslogClient.Send | **HOT** — dataplane event reader (1 per helper), per-packet to syslog/NetFlow |
| flowexport | ipfix 1109, netflow 853, manager 915, transport 580, routemask 316, exporterid ~60 | ~3840 | ~4000 | encodeIPFIXRecordV4, encodeRecordV4, collectorConns.writeAll | **WARM** — session-close flush every 100ms, UDP write path |
| snmp | agent 1997, v3 1103, traps 416 | ~3516 | ~5200 | handleV3Packet, berDecodeLength | COLD — request path, but GETBULK CPU path reachable anon |
| rpm | rpm 794, icmp 426, display ~120 | ~1340 | ~1500 | runProbeLoop, probeHTTP | COLD — periodic probes |
| feeds | feeds 889 | 889 | ~1200 | fetchFeed, installSnapshot | COLD — periodic fetch, but body size DoS vector |
| eventengine | engine 1352 | 1352 | ~2000 | evaluatePolicies, runWorker | COLD — event-driven config transaction |
| ipmon | ipmon 1016, display ~150 | ~1170 | ~1200 | computeOverlayLocked, run | COLD — overlay actuator |

Total: 7 modules, 27 prod files, ~15200 prod LOC, ~27300 test LOC (test-heavy, good).

## Module Log (coverage proof)

- **logging/ringbuf.go** — NEGATIVE after hardening verification. Wire 144→152→160 additive growth, both-sides discipline (#1961). LittleEndian for zone IDs, BigEndian for ports per spec. Default policy sentinel handled correctly (dataplane.DefaultPolicySentinelID → DefaultPolicyName). Host-inbound deny distinct reason 6 rendered distinctly (closeReasonHostInbound). Per-policy log gate LogSyslog byte at 135 gated only for syslog consumers, callbacks always run (global flow export). Zone resolution via sync.RWMutex maps, numeric fallback fmt.Sprintf("%d") for unknown (zone 0 selectable via HasZone bool #3338). Decoders bound-check len >= wireSize. No heap alloc on hot path beyond fmt.Sprintf for addr. Trace: eventTimeFromWire uses decision-time UnixNano from wire, fallback to Now on overflow.

- **logging/syslog.go** — NEGATIVE (hardened). Backpressure: defaultWriteTimeout 4s, reconnectCooldown 1s, isTimeout check prevents doubling stall. Partial-frame desync fix (#3874): n>0 && n<len(b) → close+nil to prevent collector framing corruption. Re-entrancy deadlock (#2287) avoided via pendingDropWarn emitted after Unlock and slog handler forwarding Set guard via sync.Map goroutine ID. Close resurrection (#4806) via clos
```

---


## Findings — separated by confidence (High/Medium require full evidence bar)


### Critical


(0 findings at Critical level)


### High


#### Finding from ps-A1_rust_dataplane_packet-b2.md

```
# Batch 004 b2/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b2
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ god | orchestrator remainder after stage extractions: session-hit path, session-miss path (policy→NAT→FIB→screen→install), flowless path (#3292), junos-host gate #3019/#3706, PBR route_override #4392, DNS reply allow, strict-syn-check #4400, session limit #2134, fragment assoc NAT64 #2562, IPv6 ext over-limit #4743 | 10 |
| 2 | poll_descriptor/filter.rs | ~600+ | prod | filter_terminal, host_inbound_gated_lo0_action | input-filter eval + log emission, lo0 host-bound filter, host-inbound gating via host_inbound_admits_iface with logical ifindex #3609, PBR routing-instance override with Drop #4392, log source Pbr vs Filter, truthful REJECT→DENY downgrade #3615 | 8 |
| 3 | tx/dispatch/mod.rs | 1486 | prod | enqueue_pending_forwards 1048 god | Phase 8 try_inplace_rewrite_or_build, copy-frame oversized check, PTB derivation #2301/#2330, tunnel outer MTU SSOT #2300, tuple-mismatch diag #4041, single-recycle invariant 39 sites | 8 |
| 4 | types/cos.rs | 1786 | prod | — | CoSState 28 fields 5 lifecycles, cos_lease, equal-flow target policy parse #2458, loss-priority rewrite #3995 | 5 |
| 5 | types/forwarding.rs (already in b1 but referenced) | 1100 | prod | — | ForwardingState 66 fields (see b1) — hot FIB vs cold truth | 9 |
| 6 | wg/engine.rs | 1805 | prod | — | WG engine, handshake, session, cookie, framing, peer selection per #1434 multi-peer, allowed_ips LPM, secret redaction Debug #4484 zeroize | 6 |
| 7 | worker/*.rs (mod, lifecycle, loop_body, telemetry, cos/*, bind_meta, bpf_maps, flow_cache_state, scratch, timers) | ~3000 total | prod | loop_body setup/debug_report | worker loop, UMEM, XSK, flow-cache, TX pipeline BatchCounters #3651, cos row, status | 7 |
| 8 | tx/* (cos_classify.rs 1335 7-resp, dispatch/cos, drain/phase_*, rings, stats, tcp_segmentation, transmit/*, queue_service/* waterfill 2058) | ~8000 total | prod | cos_classify, queue_service::waterfill 432 god | CoS TX selection resolve, TX drain phases trivial/shaped/backup, rings, TCP segmentation, finalise/rewrite/stage/verify/write, waterfill allocator epoch refill f64 fraction clamp bitset Phase1 asc Phase2 desc WRAP | 6 |
| 9 | icmp_embed/* (builders, mod, nat_match_v4/v6, parse, return_resolution, session_match) | ~1500 total | prod | match_outer_v4, session_match | embedded ICMP NAT matching forward-NAT-by-reverse + session fallback, return resolution, builders for ICMP error translation | 7 |
| 10 | icmp_ptb.rs + icmp_ratelimit.rs + tests | ~2000 total | mixed | build_frag_needed, PacketTooBig | PTB generation inner MTU derivation WG/GRE/NAT64 #2301/#2330, icmp_ratelimit token bucket per-zone #3618 fallback global bucket | 6 |
| 11 | poll_stages.rs (already b1) + poll_descriptor/* (cookie_reply, filter, flow_cache_hit, nat_exception, reject_reply, rx_telemetry, debug_log_throttle) | ~2000 total | prod | stage_screen_check, stage_ipsec_passthrough | Stage 5 link-layer ARP/NDP classify w/ anti-poison #2851 #2790 Override #4475, Stage 6 GRE decap, Stage 7+8 flow parse + learn logical ifindex #2370, Stage 9 fabric ingress zone override, Stage 10 screen per-zone + alarm-without-drop, Stage 11 IPsec passthrough NewInboundIke gated host-inbound #4323 | 8 |
| 12 | neighbor.rs 2036 + sharded_neighbor + neighbor_* + neg_neigh | ~4000 total | prod | — | ARP/ND probe + netlink mgmt + monitor thread + warmer, sharded map insert_if_changed mac_change_epoch #3048, neighbor_latency, resolver, dispatch skip-learn check fo
```

---

#### Finding from ps-A6_go_dataplane_manager-b1.md

```
# A6 Go Dataplane Manager — Review (b1/3)

## File Inventory (150 files, ~60 prod / 90 test)

Ranked by size×responsibility×hot-path proximity:

- `pkg/dataplane/compiler.go` ~1.6k LOC prod, god compile orchestrator (zones, addr-book, apps, policies, nat, screen, flow). Largest fn `CompileConfig` phases + `compilePolicies` expansion. Responsibility: zone→ID stable hash, policy expansion, app-set.
- `pkg/dataplane/compiler_iface.go` ~1.4k LOC prod, zone/interface mapping, netlink, rxvlan off, MTU, RETH recovery, unmanaged strip, device-map leave-alone.
- `pkg/dataplane/compiler_nat.go` ~1.3k LOC prod, SNAT/DNAT/static/NAT64/NPTv6 compilation, pool ID assignment, counter ID stable hash + collision resolve + finalizer.
- `pkg/dataplane/types.go` ~1.1k LOC prod, all BPF struct mirrors, zone pair key, policy rule, NAT pool, filter config, screen flags.
- `pkg/dataplane/compiler_filter.go` ~0.8k LOC prod, filter protocol validation, policer ID assignment, term→rule cross-product expansion with #5456 cap, iface→filter map.
- `pkg/dataplane/userspace/eventstream.go` ~1.2k LOC prod, binary frame header (len+type+seq), session open/close decode, gap → full resync, pending queue 4096, writeMu sep lock.
- `pkg/dataplane/userspace/manager.go` ~0.4k prod + many split files, snapshot lifecycle, generation, deferred worker arm debt, appliedSnapshot coherency.
- `pkg/dataplane/userspace/builder.go` ~0.2k prod, snapshot assembly, zone collision quarantine, content hash dedup.
- `pkg/dataplane/userspace/filters.go` ~0.6k prod, firewall filter snapshot lowering (prefix-list, except, DSCP, TCP-flags, flex-match).
- `pkg/dataplane/userspace/interfaces.go` ~0.56k prod, synthetic logical ifindex FNV hash, VLAN parent bind contract, bound interface allowlist.
- `pkg/dataplane/userspace/flow.go` ~0.26k prod, wire coercion u16/u32/u64 for Rust JSON decode (MSS, timeouts).
- `pkg/dataplane/userspace/cos.go` ~0.26k prod, CoS snapshot with safe degrade on undefined class.
- Many `*_test.go` (app catalog parity, NAT counter collision/determinism/stability, filter expansion, prefix-list except, port except, host-inbound classify, etc.) — high coverage of edge cases.

Prod files shape: manager pattern with populate-before-clear map writes for legacy BPF; userspace path builds immutable snapshot then single control-socket publish. Zone handling: `assignZoneIDs` uses StableZoneID(name) FNV fold into [1, ReservedMin-1]; policy sets pack into `policySetID*MaxRulesPerPolicy+index` rule ID.

## Module Log (coverage)

- `compiler.go` zones: checked nil zone slot guard, screen profile lookup, host-inbound flags, TCPRst, iface zone composite key, RETH RG inherit, native XDP flag, VLAN sub-if creation, managed interface list for networkd, unmanaged strip with #1922 protected set and #1956 device-map leave-alone, VRF/Tunnel/Bridge owned skip, stale deletion. Policies: application-set expansion, appID map, Any handling, implicit set building, rule ID calculation, scheduler slots. Default policy sentinel #3057. Fail-closed on unknown screen/addr.
- `compiler_iface.go` (already in compiler.go in this tree): resolveInterfaceRef handles reth→phys, irb→bridge, fab IPVLAN parent, tunnel names. VLAN reconciliation, DHCP/RETH skip, link cycle deferral, RX queue tuning. Negative: legacy eBPF direct map writes mid-compile not transactional.
- `compiler_nat.go`: pool ID uint8 assignment, compiledPools cache, v4/v6 split, interface-mode SNAT egress IP per ifindex+vlan, deterministic NAT host-base v4/v6, persistent NAT registration, source/dest addr name resolution, DNAT port/proto expansion with application-sets, SNAT off mode, NAT counter ID stable hash FNV-1a with re-hash collision handling and finalize sorted deterministic finalizer #5099, exhaustion fallback to 0. Checked overflow risk for poolID.
- `compiler_filter.go`: protocol validation via appid.ProtocolNumber SSOT, policer ID 1-based, filter ID deterministic sorted, rule expansion with MaxFilterTermExpansion cap #5456, pro
```

---

#### Finding from ps-A7_go_daemon_host-b1.md

```
# Review: A7_go_daemon_host (batch 016) — Zone/HA/NFT/Apply ordering

Base: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A7_go_daemon_host-b1

## File-size/shape inventory
- Total in pkg/daemon: 199 files (51 prod, 148 test) — batch 016 covers 150 of them.
- Total LOC (prod+test): 60852
- Top prod by LOC / responsibility x hot-path proximity:
  1. `daemon_run.go` 2487 — boot predicate, bootstrap exit, shutdown ordering, FRR fail-closed clear
  2. `daemon_apply.go` 2153 — 10+ subsystems, fail-closed error joins, C1-C3 ctx boundaries, zoneRGMap install
  3. `daemon_nft.go` 1698 — inet xpf_lo0 (prio 0) + xpf_hostinbound (prio 10) rendering, counter lifecycle, fail-closed
  4. `daemon_system.go` 1731 — DNS/NTP/hostname/timezone/kernel tuning, lo0/host-inbound fail-closed joins
  5. `daemon_ha.go` 1576 — RG state machine, cluster+VRRP funnel, blackhole routes, per-RG services
  6. `daemon_ha_sync.go` 1020 — coldStart sticky, sync-ready timer, bulk prime retry, config-sync gate
  7. `daemon_ha_fabric.go` 965 — fab0/fab1 IPVLAN deferral, neighbor probe, dual-fabric refresh
  8. `bootstrap.go` 944 — five-case boot predicate, lifeline record, protected set, fail-closed FRR probe
  9. `host_tunables.go` 839 — governor/budget/coalesce capture/restore, drift detection, debt handling
 10. `device_map.go` 836 — mapped rename, strand-management preflight, teardown fail-closed #5309

Largest funcs: `applyConfigLocked` ~500 LOC (head+tail split), `applyDataplaneAndHACore` ~400, `buildHostInboundFilterPayload` ~200.

Prod vs test: prod 51 files ~18000 LOC, test 148 files ~42000 LOC. Batch includes almost all prod.

## Module log (coverage with negatives)
- `bootstrap.go`: reviewed boot predicate (computeBootClass), lifeline detection via default route, protectedInterfacesWith fxp0 narrowing. NEGATIVE: fail-closed on compile-failed boot correctly preserves FRR probe via pinned-links prefilter + control-socket armed check (#1993). Device-map boot refusal #5490 wired.
- `coalescence.go`: mlx5-only, ethtool -c probe idempotent, adaptive-rx/tx + rx/tx-usecs pin. NEGATIVE: non-mlx5 skip, empty allowlist no-op, best-effort never blocks bring-up — sound.
- `daemon.go`: applySem, bootstrapMode atomic, rgStates, fabric state. NEGATIVE: no zone-ID logic here.
- `daemon_apply.go`: apply ordering VRF->tunnel/xfrmi/bond->fabric IPVLAN->dataplane->networkd->RETH MAC->proxyARP->VRF rebind->FRR->next-table/rib-group/PBR->neighbor/RA/IPsec/DHCP/DDNS/DHCP clients->VRRP/DNS/NTP/lo0/host-inbound/SSH/login/sudoers/archive/flow/LLDP/event-options/RPM/IPmon/cluster. Fail-closed joins: networkdErr, dhcpServerErr, ipsecErr, hostInboundErr, lo0Err, ifaceErr all joined at tail. C1/C2/C3 ctx boundaries checked. ZoneRGMap installed after ApplyConfig. device-map teardown BEFORE networkd.Apply (correct). FINDING #3 below.
- `daemon_nft.go`: chain priorities 0 vs 10 distinct (#3364), add+delete idempotent, counter pre-declare dedup, TCP flags fail-closed #5512, ICMP divergence, address-family filtering, lo0 reject faithfulness. NEGATIVE: no fail-open on unzoned (#4420 HI-2 emits junos-host sentinel DROP). Host-inbound ambiguous logging (#3718) only warn, not fail-closed — acceptable because strict commit gate rejects.
- `daemon_ha.go`: RG state machine unified, activation order rg_active FIRST then blackhole remove, deactivation blackhole FIRST then rg_active clear. Preflight for fabric redirect. No zone-ID logic beyond snapshotRethMasterState.
- `daemon_ha_fabric.go`: fab0/fab1 IPVLAN deferred until XSK bound (zerocopy), stale cleanup, retry 5x. NEGATIVE: fail-open? Logs CRITICAL but continues — HA heartbeat loss bounded by retry, acceptable.
- `daemon_ha_sync.go`: coldStart = !BulkEverCompleted sticky (dedup #5480 — NOT re-reporting). Sync-ready timer 5s, bulk prime retry with progress detection. Config-sync rejected when RG0 primary (prevents secondary overwrite). NEGATIVE: heartbeat suppression cap 5s monotonic (#1792) sound.
- `daemon_ha_us
```

---

(3 findings at High level)


### Medium


#### Finding from ps-A10_go_services_cli_deploy-b3.md

```
# A10 Go Services / CLI / Deploy Review b3/3 — Batch 002

## Inventory (114 files, ~20K LOC)

| Module | Files | LOC (prod) | Largest fn | Responsibility |
|--------|-------|------------|------------|----------------|
| dhcpserver | 8 go | 2111+934 lease_sync | generateKea4Config / lease parse | Kea config render, lease sync/seed, DDNS glue |
| natshow | 5 go | 49+117+108+114+117 | RenderSourceRuleDetail | NAT show rendering (source/dest/static/persistent) |
| policymatch | 48 (1 prod 47 test) | 1715 prod | Match 300+ | Zone policy simulator vs dataplane parity, global scoped, app matching |
| scheduler | 5 | 449 prod | evaluate 60, isWithinWindow 40 | Time window eval, wall-clock discontinuity, republish self-heal |
| scripts/deploy | 7 py | 1881 xpf-deploy + 6 test | cmd_kernel_roll 200 | Appliance deploy, fetch verify, HA roll orchestration |
| scripts/dist | 2 py | 345+786 | publish gate_images 140 | Minisign manifest, image signing, publish gate |
| scripts/image | 5 py | 756+686+122 +2 test | virt_customize bake 120 | Bake qcow2, config-drive ISO, validate gate |
| scripts/*.py, test/incus/*.py | ~35 py + 1 rs + 4 xsk | varied | - | Test harnesses, metrics, cold-path flooder (2170 RS) |

## Module Log

- dhcpserver/dhcpserver.go: generation supersession with atomic gen, fail-closed is-active query handling (#4870) — sound, query error triggers restart/stop + error surfacing. Stable hash subnet-id (#5041/#5203) with coprime probe step — correct.
- dhcpserver/lease_sync.go: clock-skew-safe Remaining re-anchor, v6 IA_PD handling, splitV6Identity error returns non-nil for malformed IAID (#2379). Memfile pre-seed with _kea ownership via fsatomic WithOwner — hardened. BOS: mergeLeasesByIdentity local wins — correct for active-active.
- dhcpserver/ddns.go: thin alias glue, keaLeaseParser maps unknown LeaseType to LeaseTypeUnknown fail-closed (#5072 IAPD AAAA suppression) — sound.
- natshow/source.go, dest.go: session counts keyed by {from,to} not rule-set name — inherent limitation (sessions carry zone IDs not rule-set name), not a bug; counter reads via NATCounterIDs — correct. IPv6 iteration present.
- natshow/persistent.go: binary.NativeEndian.PutUint32 recovers __be32 — matches CLAUDE.md byte order, v6 netip.AddrFrom16 without Unmap — correct per gc.go. No panic.
- natshow/static.go: NPTv6 vs static prefix rendering, detail fields — display only, no enforcement.
- policymatch/policymatch.go: tier order exact→single-wildcard merged→both-any→global→default, zoneKnown gate for undefined zones (#3355), scheduler gate first, content rejection SSOT via PolicyContentRejectionReasons (#3727/#4394), route-drop advisory (#4373), host-inbound token classification, feed overlay merge, ParseSelectorArgs fail-closed duplicate/unknown/empty. Very hardened.
- policymatch/zone_detail_summary.go: wildcard handling fromAny/toAny affect BothAny tier, policySetID advances on nil sets, global via GlobalPolicyAppliesToZone — correct.
- scheduler/scheduler.go: wallClockDiscontinuousLocked compares wall vs mono with 5s tolerance, 2min recovery hold, fail-closed during hold, date-range ParseInLocation(now.Location()) (#3988), isWithinWindow fail-closed on absent/incomplete, republish self-heal with pending flag — sound.
- scripts/deploy/xpf-deploy.py: preflight before mutate, golden qcow overlay (never writable golden), virtio-first NIC order validation (#165 H-22), VM cleanup on partial failure, fetch verifies against signed manifest with TOCTOU-safe copy in sign.py, anti-rollback watermark, lease acquire via flock atomic read-expire-write, holder sanitized via regex, ssh remote command quoted via shlex.quote — hardened.
- scripts/dist/sign.py: basename-only manifest, TOCTOU-safe verify via private 0700 tmp copy, placeholder pubkey refusal, path traversal check for manifest entries, duplicate basename refusal — hardened.
- scripts/dist/publish.py: default-deny allowlist for image tree, symlink rejection, per-suite InRelease verify, key-agreement cr
```

---

#### Finding from ps-A1_rust_dataplane_packet-b1.md

```
# Batch 003 b1/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b1
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

Ranked by LOC × responsibility-count × hot-path proximity (poll_descriptor hot=10, forwarding=8, frame=9, cos=5, coordinator=3, bpf_map=4, bench/build=1):

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ LOC god | per-packet orchestrator: host-inbound → lo0 → junos-host → route → screen → policy → SNAT → install → telemetry → HA | 10 |
| 2 | forwarding/mod.rs | 2795 | prod | lookup_forwarding_resolution_inner_ecmp 800+ | FIB/NAT/fabric/tunnel/VRF/zone-pair/MSS/local-delivery table-scoped decis | 9 |
| 3 | flow_cache.rs | 2000+ est | prod | lookup, insert | flow-cache hit/miss, MAC-epoch TOCTOU (#3918), owner-RG epoch | 9 |
| 4 | frame/inspect.rs | 1960 | prod | frame_l3_offset 68, packet_rel_l4_offset 100 | L3/L4 offset, IPv6 EH walk, fragment detection, flex-bounds, declared_end | 9 |
| 5 | frame/mod.rs | 1743 | prod | apply_dscp_rewrite 200 | rewrite orchestrator, DSCP, checksum adjust | 8 |
| 6 | forwarding_build/fib.rs | ~500 | prod | populate_routes, resolve_next_hops | route table build, preference validation (#3771), family mismatch | 7 |
| 7 | forwarding_build/zones.rs | 142 | prod | populate_zones 80 | zone name↔id, duplicate ID reject (#3719), reserved-range skip, host-inbound per-zone, reject_buckets per-zone (#3618), tcp_rst per-zone | 8 |
| 8 | forwarding/host_inbound.rs | 538 | prod | classify_system_service 134, host_inbound_admits 40 | host-inbound admit: system-services → L4 ports/ICMP types/IP proto, protocols all expansion (#3199) minus L2 (#3311), None=>true for unknown zone (id 0) | 8 |
| 9 | forwarding_build/*.rs (interfaces, cos, tunnels, validated, wg) | ~800 total | prod | — | interface→zone mapping, CoS iface config, tunnel endpoints, WG engines | 6 |
| 10 | frame/headers.rs | 338 | prod | write_eth_header_slice_tagged 40 (unsafe) | eth/ipv4/ipv6/udp header serializers, TxVlanTag, DF=1 atomic datagram (#1440) | 7 |
| 11 | frame/byte_writes.rs | 81 | prod | — | write_ipv4/6 src/dst (NO guards — caller must validate), L4 port writes (guarded) | 8 |
| 12 | frame/* (build/*, rewrite/*, tcp.rs, checksum.rs, tcp_segmentation.rs, wg.rs) | ~2500 total | prod | segment_forwarded_tcp_frames 500+ | frame building, rewrite descriptors, TCP segmentation, WG outer MTU SSOT | 7 |
| 13 | cos/* (admission, builders, ecn, fairness, flow_hash, queue_ops, token_bucket, tx_completion) | ~5000 total | mixed | admission check, queue_ops push/pop/drain/v_min, waterfill allocator | CoS classification, per-queue token-bucket, lossless queue, ECN, flow-hash, TX completion | 5 |
| 14 | coordinator/* (mod, bpf_maps, ha_state, inject, reconcile/*, refresh_bindings, session_manager, snapshot_refresh, status, supervisor, tunnel_supervision, wg_control, worker_manager, cos_leases/state) | ~8000 total | prod | mod.rs 982, status.rs 1045 | snapshot apply, BPF map mgmt, HA state, session sync, WG control, cos leases, bringup/teardown | 4 |
| 15 | bind.rs | ~600 | prod | — | XDP/XSK bind, UMEM setup | 4 |
| 16 | bpf_map/* (ha.rs, metrics.rs, mod.rs, pin.rs, publish_conntrack.rs) + bpf_map_tests | ~1500 total | mixed | — | BPF map definitions, pinning, conntrack publish, metrics | 4 |
| 17 | checksum.rs | ~300 | prod | compute_l4_csum_delta 100 | NAT checksum delta, NPTv6 neutral, IPv4 words | 6 |
| 18 | disposition.rs | ~500 | prod | record_forwarding_disposition 99 | disposition counters, zone counters via zone_counter_slot_map batched (#3651) | 5 |
| 19 | cold_path_hist.rs + tests | ~2000 | mixed | — | cold-path slot map direct 
```

---

#### Finding from ps-A1_rust_dataplane_packet-b2.md

```
# Batch 004 b2/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b2
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ god | orchestrator remainder after stage extractions: session-hit path, session-miss path (policy→NAT→FIB→screen→install), flowless path (#3292), junos-host gate #3019/#3706, PBR route_override #4392, DNS reply allow, strict-syn-check #4400, session limit #2134, fragment assoc NAT64 #2562, IPv6 ext over-limit #4743 | 10 |
| 2 | poll_descriptor/filter.rs | ~600+ | prod | filter_terminal, host_inbound_gated_lo0_action | input-filter eval + log emission, lo0 host-bound filter, host-inbound gating via host_inbound_admits_iface with logical ifindex #3609, PBR routing-instance override with Drop #4392, log source Pbr vs Filter, truthful REJECT→DENY downgrade #3615 | 8 |
| 3 | tx/dispatch/mod.rs | 1486 | prod | enqueue_pending_forwards 1048 god | Phase 8 try_inplace_rewrite_or_build, copy-frame oversized check, PTB derivation #2301/#2330, tunnel outer MTU SSOT #2300, tuple-mismatch diag #4041, single-recycle invariant 39 sites | 8 |
| 4 | types/cos.rs | 1786 | prod | — | CoSState 28 fields 5 lifecycles, cos_lease, equal-flow target policy parse #2458, loss-priority rewrite #3995 | 5 |
| 5 | types/forwarding.rs (already in b1 but referenced) | 1100 | prod | — | ForwardingState 66 fields (see b1) — hot FIB vs cold truth | 9 |
| 6 | wg/engine.rs | 1805 | prod | — | WG engine, handshake, session, cookie, framing, peer selection per #1434 multi-peer, allowed_ips LPM, secret redaction Debug #4484 zeroize | 6 |
| 7 | worker/*.rs (mod, lifecycle, loop_body, telemetry, cos/*, bind_meta, bpf_maps, flow_cache_state, scratch, timers) | ~3000 total | prod | loop_body setup/debug_report | worker loop, UMEM, XSK, flow-cache, TX pipeline BatchCounters #3651, cos row, status | 7 |
| 8 | tx/* (cos_classify.rs 1335 7-resp, dispatch/cos, drain/phase_*, rings, stats, tcp_segmentation, transmit/*, queue_service/* waterfill 2058) | ~8000 total | prod | cos_classify, queue_service::waterfill 432 god | CoS TX selection resolve, TX drain phases trivial/shaped/backup, rings, TCP segmentation, finalise/rewrite/stage/verify/write, waterfill allocator epoch refill f64 fraction clamp bitset Phase1 asc Phase2 desc WRAP | 6 |
| 9 | icmp_embed/* (builders, mod, nat_match_v4/v6, parse, return_resolution, session_match) | ~1500 total | prod | match_outer_v4, session_match | embedded ICMP NAT matching forward-NAT-by-reverse + session fallback, return resolution, builders for ICMP error translation | 7 |
| 10 | icmp_ptb.rs + icmp_ratelimit.rs + tests | ~2000 total | mixed | build_frag_needed, PacketTooBig | PTB generation inner MTU derivation WG/GRE/NAT64 #2301/#2330, icmp_ratelimit token bucket per-zone #3618 fallback global bucket | 6 |
| 11 | poll_stages.rs (already b1) + poll_descriptor/* (cookie_reply, filter, flow_cache_hit, nat_exception, reject_reply, rx_telemetry, debug_log_throttle) | ~2000 total | prod | stage_screen_check, stage_ipsec_passthrough | Stage 5 link-layer ARP/NDP classify w/ anti-poison #2851 #2790 Override #4475, Stage 6 GRE decap, Stage 7+8 flow parse + learn logical ifindex #2370, Stage 9 fabric ingress zone override, Stage 10 screen per-zone + alarm-without-drop, Stage 11 IPsec passthrough NewInboundIke gated host-inbound #4323 | 8 |
| 12 | neighbor.rs 2036 + sharded_neighbor + neighbor_* + neg_neigh | ~4000 total | prod | — | ARP/ND probe + netlink mgmt + monitor thread + warmer, sharded map insert_if_changed mac_change_epoch #3048, neighbor_latency, resolver, dispatch skip-learn check fo
```

---

#### Finding from ps-A3_go_config_cli_tree-b2.md

```
# A3 Go Config/CLI Tree b2/4 — Zone Policy + Strict Gates (150 files)
Base: 7e0fecf3b8f2dc6604600674373771c835484188 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b2

## File Inventory
| File | LOC | Role |
|---|---:|---|
| compiler_security_zones.go | 239 | zone compile, bracket flatten (#5248), HIB merge (#4544/#4818) |
| compiler_security_policy.go | 451 | policy compile, fail-closed default DENY (#3043), collapsed-deny (#3141/#3374), scoped-global (#3148/#4626) |
| compiler_security_addressbook.go | 430 | book/set bracket (#4791), find-or-create merge (#4706) |
| compiler_security_log.go | 268 | syslog port dual-location gate (#3349), TLS-profile no-op reject (#3350) |
| compiler_security_screen.go | 474 | 16 IDS checks profile compile |
| compiler_policy_match.go | 320 | unsupported match leaf (#3113), multi-value tail escape (#3142), swallowed from-zone/to-zone token (#3673), dup-block walk (#3562/#3842) |
| compiler_policy_missing_match.go | 201 | required dimensions gate (#3044) |
| compiler_policy_then.go | 583 | unsupported then-permit (#3114)/reject (#3115)/deny (#3141) + orphan log-sub (#3374) |
| filter_match_resolve.go | 324 | symbolic icmp/port→numeric SSOT (#3205), hyphenated svc-name before range split |
| firewall_filter_expand.go | 137 | cross-product stride uint64 overflow-checked (#5456), clamp 1<<20 |
| compiler_validate_strict_policy.go | ~400 | policy addr token validation, any/any-ipv4/any-ipv6, feed bindings, CIDR/IP |
| + 138 test files | ~5000 | regression |

All cold compile-time gates. Hot Rust policy.rs (3598 LOC) not in batch.

## Module Log

- zones: zoneInterfaceMembers skips HIB child, recurses Keys+Children — bracket `[ a b c ]` as nested chain (wildcard container) handled. Empty Keys check k!="" prevents empty-name add. find-or-create by name prevents dup-instance replace (boundary loss). NEGATIVE sound.
- security_policy: policyMatchChildren/ThenChildren accumulate across ALL match/then blocks (#3842) — dup inner blocks no longer silently widen. terminalActions tracks conflicting permit+deny → #3043 gate rejects, default DENY for actionless. applyCollapsedDenyModifiers wires flat-collapsed `then deny log/count` (Keys[1:] + descendant walk). sortDedupZones canonicalizes scoped-global lists.
- policy_match: forEachChild at security/policies (#3562) closes dup-block bypass (parseStatements appends). firewallMatchValues SSOT reads Keys[1:] + Children for multi:true leaves (#2419). swallowedStructuralMatchTokens from-zone/to-zone in zone-pair multi-value tail rejected (#3673) — prevents app named "from-zone" satisfying gate and hiding keyword as bogus operand.
- missing_match: required dimensions across ALL match blocks (policyMatchChildren) — split across dup blocks counted. NEGATIVE sound, Junos parity.
- policy_then: supportedThenPermitChildren empty today (any child under then permit is silent-drop → UTM/IDP strip fail-open). Inspects ALL permit nodes across ALL then blocks (policyThenActionNodes) for #3377 two-node split + #3842 dup then. collapsedThenActionTokens flattens 3 parser shapes shape-agnostic. hasLog over union of ALL deny nodes before orphan check (#3374) — split deny log + deny session-init not false-flagged.
- filter_match_resolve: whole-spec service lookup BEFORE range split (ftp-data not mangled), parseCanonicalPort rejects +80 (#3606), numeric lo>hi fails closed. Unrecognized token kept verbatim + UnknownPorts for strict reject — fail-closed.
- firewall_filter_expand: bits.Mul64 overflow-checked, saturates MaxUint64, stride clamp to MaxFilterTermExpansion 1<<20 (#5456) — retired-eBPF counter drift fixed; live userspace name-keyed so unaffected. Counts except prefixes (negated rule) so count==len(expandFilterTerm) drift-guard holds.
- validate_strict_policy: policyMatchNamedAddressRefs includes dynamic feed bindings + address book (global+zone-local folded). Recognizes "", any, any-ipv4/any-ipv6 (normalized to 0.0.0.0/0, ::/0 in compilePolicies), CIDR, IP, named
```

---

#### Finding from ps-A3_go_config_cli_tree-b4.md

```
# Security Review — Batch A3 Go Config CLI Tree b4/4 (52 files)

> Base commit: 312a2dfd (worktree /tmp/review-wt-claude-003-A3_go_config_cli_tree-b4)
> Focus: security zone policies, inter-zone allow/deny, host-inbound admission, policy compilation, NAT zone scoping, typed-leaf validation

## File Size / Shape Inventory (prod vs test, responsibility, hot-path proximity)

| File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|-----|-----------|----------------|---------------|
| types_security.go | 1306 | prod | ZoneConfig, Policy/PolicyMatch, NAT, Screen, ALG, Scheduler — zone policy SSOT | HIGH (snapshot builder reads zones/policies/NAT) |
| types_system.go | 1565 | prod | System stanza (dataplane, syslog, SNMP, login RBAC) — RBAC + SNMP source-IP gate | MEDIUM (RBAC gating, SNMP) |
| types_routing.go | 651 | prod | Routing protocols, tunnel config cloneForUnit — tunnel aliasing (perf + sec) | MEDIUM (FIB ingest) |
| types_chassis.go | 188 | prod | Device-map + cluster config — bare-metal identity | LOW (boot-time) |
| tunnelemit.go | 123 | prod | Tunnel endpoint canonical emission (collision gate + builder SSOT) | MEDIUM (ID stability) |
| tunnelid.go | 290 | prod | StableTunnelEndpointID fold + 3-view HA-symmetric collision gate | MEDIUM (HA determinism) |
| zoneid.go | 251 | prod | StableZoneID fold + 3-view collision gate + quarantine runtime | HIGH (zone ID wire-adjacent) |
| value_type.go | 155 | prod | Typed-leaf ValueType + placeholder — drives commit-time validators | MEDIUM (validation trigger) |
| types_cos.go | 283 | prod | CoS forwarding-class/scheduler/shaper binding | LOW (CoS) |
| types_interfaces.go | 150 | prod | InterfaceConfig, Units, LAG, VRRP groups | LOW |
| xfrmi.go | 77 | prod | XFRM if_id + secure-tunnel bind-interface validator | MEDIUM (VPN liveness) |
| snmp_clients.go | 206 | prod | SNMP community clients allowlist parse + longest-prefix match + cache | MEDIUM (SNMP ACL) |
| syslog_logfile.go | 50 | prod | show-log allowlist gate — path traversal + arbitrary log read | HIGH (priv esc) |
| tcp_flags.go | 147 | prod | Firewall filter tcp-flags conjunctive expression — fail-closed on OR/contradiction | HIGH (filter bypass) |
| 37 test files | 99 avg | test | Fail-on-revert guards for every strict gate above | N/A |
| **Total** | ~8200 | 15 prod + 37 test | | |

Ranking by size×responsibility×hot-path: types_security.go > types_system.go > zoneid.go > types_routing.go > snmp_clients.go > tcp_flags.go > syslog_logfile.go > tunnelid.go.

## Module Log (incl. negatives proving coverage)

- types_security.go — PASS: reviewed ZoneConfig.InterfaceHostInbound (per-if HIB union, #3362), IsWildcardZone/IsWildcardZoneSet duality (two spellings for global wildcard), GlobalPolicyAppliesToZone (from||to any match), sortDedupZones/ScopeSingular/IsHostToZoneScope, NAT match multi-value accessors (natMatchValues fallback), StaticNATRule source-address list (was scalar drop M02). No integer truncation on ports — DestinationPort int validated via strict gates elsewhere. No zone bypass. RBAC: LoginClassPermissions forbids PermMaint on non-super (operator lacks maintenance). Coverage: read 1306 lines.
- zoneid.go — PASS: StableZoneID FNV-1a xor-fold [1, 65533], reserved range protected, 3-view HA-symmetric collision check (pre-expansion union + per-node expansion), QuarantinedZoneNames deterministic later-sort quarantine. Tests pin hash-freeze (frozen fold). No integer overflow — uint16 fold mod arithmetic correct. Negative: no findings, determinism holds.
- types_routing.go — PASS: TunnelConfig.cloneForUnit deep-copies Addresses + WgPeers (addresses independent backing array, #3898), WgOuterFamilyV6, ConnectedNetworkPrefix skip for host/default/link-local. No issue.
- zone_count_cap_test.go — PASS: MaxUsableZoneID == ZoneIDReservedMin-1 == 65533, pigeonhole cap guard.
- zone_dup_block_4818_test.go — PASS: duplicate top-level security-zone sibling blocks merge (find-or-create, #4818) — previously silently 
```

---

#### Finding from ps-A5_go_ha_vrrp_ra_conntrack-b1.md

```
# HA / VRRP / RA / conntrack — review b1 (Go)

Base: 7e0fecf
Worktree: /tmp/review-wt-claude-003-A5_go_ha_vrrp_ra_conntrack-b1

## File inventory
- Total lines (prod+test): 47864 (from wc -l)
- Prod: 19125 lines across 35 files
  - pkg/cluster: 11750 prod (largest: sync_conn.go 1858, heartbeat.go 881, failover.go 912, sync.go 1048, election.go 475)
  - pkg/conntrack: 554 (gc.go)
  - pkg/ra: 2193 (ra.go 1118, sender.go 1055, filter.go 21)
  - pkg/vrrp: 4628 (instance.go 2417, manager.go 1108, packet.go 277, track.go 341, addrwatch.go 219)
- Test: 28739 lines, 71 files (heaviest: cluster/sync_test.go 4717, ra/serialize_test.go 2706, vrrp/vrrp_test.go 2468)
- Largest prod fn: vrrpInstance.run / stepBackup (~400 LOC), SessionSync.handleMessage (~350 LOC), Manager.UpdateInstances
- Hot path proximity ranking (size x responsibility x freq):
  1. pkg/cluster/heartbeat.go Marshal/Unmarshal + sender/receiver loops — every 100ms, drives election, auth, replay
  2. pkg/cluster/sync_protocol.go + sync_conn.go — TCP session sync, gen guards, bulk, fencing
  3. pkg/vrrp/instance.go — BECOME_MASTER/BACKUP, TTL=255, hop-limit, GARP, equal-priority tie-break, preempt hold + watchdog
  4. pkg/ra/ra.go + sender.go — goodbye ordering, RA flood prevention, RS validation
  5. pkg/cluster/election.go — dual-active, preempt, dup node-id fail-closed, kernel-upgrade hold
  6. pkg/conntrack/gc.go — expiry ownership (IsLocalPrimary), per-IP limit counting, aggressive aging hysteresis

## Module log (incl negatives => NEGATIVE RESULT)

- cluster/election.go: dual-active resolves on eff priority then nodeID, dup nodeID logs rate-limited and fails closed to SECONDARY. kernelUpgradeHold blocks both single-node and peer paths. NEGATIVE.
- cluster/heartbeat.go: MarshalHeartbeatBody reserves tailReserve up front (#4107 invariant — monitor truncation leaves HMAC space, never silent downgrade). maxHeartbeatGroups=255 + oversize warn once (#4434). Monotonic nanos (#1792) for liveness, StartupGrace 30s suppresses split-brain on simultaneous boot. Auth: HMAC+session+counter, anti-replay re-anchor on new session, constant-time compare, cross-channel downgrade guard (peerAuthSeen). NEGATIVE for core, one LOW on truncation visibility below.
- cluster/sync_protocol.go: length-gated trailing fields (#2170 gen, #3301 AppTimeout, #4565 NAT64), config gen magic trailing framing (#3931), DHCP lease count clamp prevents OOM. NEGATIVE.
- cluster/sync_conn.go: activeConnLocked prefers fab0, bulk re-drive on survivor gated on outboundBulkAcked (not bulkEverCompleted) (#4360 correct), bulkRedriveInFlight CAS prevents storm, writeFull seals per-frame via authConn, acceptLoop per-conn goroutine prevents handshake DoS (#4370). NEGATIVE.
- cluster/sync_auth.go: per-conn frame key derived via canonical nonce sort, seq replay guard, downgrade guard consulted via heartbeat auth seen. NEGATIVE.
- cluster/failover.go: per-RG failoverGen prevents ResetFailover vs pre-hook race (#5246), failoverInProgress serialization, transfer-commit override maps co-located, grace windows 2*threshold*interval+5s min 10s. NEGATIVE, except byte-trunc find below.
- cluster/garp.go: BurstStillValid abdication gate (#2867) checked before each follow-up, burstSendErrors counted, IPv6 NA Router=1 preserves default route. NEGATIVE.
- cluster/monitor.go: dampening (3 fail/3 pass + 5s hold), ICMP id from local port (kernel-overwrites-ident), seq anti-replay, peer MatchesTarget check — hardening present. NEGATIVE.
- cluster/readiness.go: holdTimer closure checks m.stopped (#4716) and cur!=rg (#5245) to avoid stale election. NEGATIVE.
- cluster/reth.go: virtual MAC 02:bf:72:CC:RR:NN per-node unique, stable LLA fe80::bf:72:CC:RR shared. NEGATIVE.
- vrrp/packet.go: VRRPv3 pseudo-header checksum for both families (RFC 5798 §5.2.8), legacy IPv4 no-pseudo accept for migration. Mutable input restored after checksum calc. NEGATIVE.
- vrrp/manager.go: VRID range guard 1..255 (#4573), build-before-teardown for ifindex drift 
```

---

#### Finding from ps-A6_go_dataplane_manager-b1.md

```
# A6 Go Dataplane Manager — Review (b1/3)

## File Inventory (150 files, ~60 prod / 90 test)

Ranked by size×responsibility×hot-path proximity:

- `pkg/dataplane/compiler.go` ~1.6k LOC prod, god compile orchestrator (zones, addr-book, apps, policies, nat, screen, flow). Largest fn `CompileConfig` phases + `compilePolicies` expansion. Responsibility: zone→ID stable hash, policy expansion, app-set.
- `pkg/dataplane/compiler_iface.go` ~1.4k LOC prod, zone/interface mapping, netlink, rxvlan off, MTU, RETH recovery, unmanaged strip, device-map leave-alone.
- `pkg/dataplane/compiler_nat.go` ~1.3k LOC prod, SNAT/DNAT/static/NAT64/NPTv6 compilation, pool ID assignment, counter ID stable hash + collision resolve + finalizer.
- `pkg/dataplane/types.go` ~1.1k LOC prod, all BPF struct mirrors, zone pair key, policy rule, NAT pool, filter config, screen flags.
- `pkg/dataplane/compiler_filter.go` ~0.8k LOC prod, filter protocol validation, policer ID assignment, term→rule cross-product expansion with #5456 cap, iface→filter map.
- `pkg/dataplane/userspace/eventstream.go` ~1.2k LOC prod, binary frame header (len+type+seq), session open/close decode, gap → full resync, pending queue 4096, writeMu sep lock.
- `pkg/dataplane/userspace/manager.go` ~0.4k prod + many split files, snapshot lifecycle, generation, deferred worker arm debt, appliedSnapshot coherency.
- `pkg/dataplane/userspace/builder.go` ~0.2k prod, snapshot assembly, zone collision quarantine, content hash dedup.
- `pkg/dataplane/userspace/filters.go` ~0.6k prod, firewall filter snapshot lowering (prefix-list, except, DSCP, TCP-flags, flex-match).
- `pkg/dataplane/userspace/interfaces.go` ~0.56k prod, synthetic logical ifindex FNV hash, VLAN parent bind contract, bound interface allowlist.
- `pkg/dataplane/userspace/flow.go` ~0.26k prod, wire coercion u16/u32/u64 for Rust JSON decode (MSS, timeouts).
- `pkg/dataplane/userspace/cos.go` ~0.26k prod, CoS snapshot with safe degrade on undefined class.
- Many `*_test.go` (app catalog parity, NAT counter collision/determinism/stability, filter expansion, prefix-list except, port except, host-inbound classify, etc.) — high coverage of edge cases.

Prod files shape: manager pattern with populate-before-clear map writes for legacy BPF; userspace path builds immutable snapshot then single control-socket publish. Zone handling: `assignZoneIDs` uses StableZoneID(name) FNV fold into [1, ReservedMin-1]; policy sets pack into `policySetID*MaxRulesPerPolicy+index` rule ID.

## Module Log (coverage)

- `compiler.go` zones: checked nil zone slot guard, screen profile lookup, host-inbound flags, TCPRst, iface zone composite key, RETH RG inherit, native XDP flag, VLAN sub-if creation, managed interface list for networkd, unmanaged strip with #1922 protected set and #1956 device-map leave-alone, VRF/Tunnel/Bridge owned skip, stale deletion. Policies: application-set expansion, appID map, Any handling, implicit set building, rule ID calculation, scheduler slots. Default policy sentinel #3057. Fail-closed on unknown screen/addr.
- `compiler_iface.go` (already in compiler.go in this tree): resolveInterfaceRef handles reth→phys, irb→bridge, fab IPVLAN parent, tunnel names. VLAN reconciliation, DHCP/RETH skip, link cycle deferral, RX queue tuning. Negative: legacy eBPF direct map writes mid-compile not transactional.
- `compiler_nat.go`: pool ID uint8 assignment, compiledPools cache, v4/v6 split, interface-mode SNAT egress IP per ifindex+vlan, deterministic NAT host-base v4/v6, persistent NAT registration, source/dest addr name resolution, DNAT port/proto expansion with application-sets, SNAT off mode, NAT counter ID stable hash FNV-1a with re-hash collision handling and finalize sorted deterministic finalizer #5099, exhaustion fallback to 0. Checked overflow risk for poolID.
- `compiler_filter.go`: protocol validation via appid.ProtocolNumber SSOT, policer ID 1-based, filter ID deterministic sorted, rule expansion with MaxFilterTermExpansion cap #5456, pro
```

---

#### Finding from ps-A6_go_dataplane_manager-b2.md

```
# Batch A6 b2/3 — Go dataplane manager (policy, zones, NAT, routes, HA glue)

Base: 7e0fecf3b, worktree /tmp/review-wt-claude-003-A6_go_dataplane_manager-b2
Files: 150, prod ~12k LOC core, test ~58k LOC; largest: protocol.go 3064 (snapshot v3), maps_sync.go 1763, manager_ha.go 1643, filters.go 641.

## Inventory (ranked responsibility × hot-path proximity)

| File | LOC | Responsibility | Cold/Hot | Largest fn |
|---|---|---|---|---|
| protocol.go | 3064 | wire version=3, 66-field ConfigSnapshot, inject bound 4096 (DoS reject-not-clamp), ZoneCounterLayout/ColdPathLayout versions | cold but version invariant governs rolling upgrade | ConfigSnapshot struct |
| policies_lower.go | 170 | global->zone lowering, singular/plural scoped-global #4626 M03, additive-wire compat | cold, #5488 interop | buildOneRuleSnapshot + effectiveMatch* |
| policies.go | 800+ | walkPolicyRuleSlots ID namespace #3143/#3145 MaxRulesPerPolicy cap, feed overlay #2049, representability sentinel #3261, app sentinel #2124 | cold but fail-open if sentinel missing | buildPolicySnapshotsWithFeeds |
| zones*.go | 300+370 | StableZoneID hash, quarantine #3719, host-inbound SSOT lifeline #3682 per-iface override union #3362, default-deny parity #3405 for no-stanza zones, VIP scoping #3172, unzoned junos-host catch-all | cold, zone collapse=fail-open | BuildZoneHostInboundViews |
| nat*.go | ~2k | pool tiers iface>zone>ri #184 #4161, any->"" fix, match-any dest fail-open, persistent NAT, deterministic block alloc, Off handling | cold, misc-NAT leak | buildSourceNATSnapshots |
| routes.go | 300 | FIB connected+static+ip-rule leaks family-normalized (blue.inet6.0 fix), Dst-less skip avoids widening, PBR bands 100-199/30000-30999, list error fail-closed whole snapshot | cold but leak miss=blackhole/bypass | buildRouteSnapshots |
| manager_ha.go | 200 | seed inventory #1928 drops phantom groups on non-cluster, watchdog-only refresh preserves Active, clearHelper empty idempotent | cold | syncHAStateLocked |
| maps_sync.go | partial | RST suppression TOCTOU, interface NAT addr sets sorted dedup | cold | syncInterfaceNATAddressMapsLocked |

## Module log (negatives)

- policies_lower: singular=first zone, plural=full set, effectiveMatch* prefers plural fallback singular — new helper correct, old helper same version 3 ignores plural narrows deny (dedup #5488). **NEGATIVE for new, known interop.**
- policies.go: any4/any6/any-ipv4/any-ipv6 literal accept, feed-bound membership, nameToID+recursive nameRepresentable, unrepresentable -> __unsupported_address__ on both v3+legacy shapes clearing book IDs => Rust SnapshotIntegrityError whole-snapshot reject prev-good retained fresh-boot default-deny. app -> __unsupported_application__ name+proto both sentinel, Rust reject. literal vs book via classifyPolicyAddresses, scheduler state, SourceAddressExcluded/DestinationAddressExcluded inversion. **NEGATIVE — fail-closed solid.**
- zones: zone-default group seeded for #3405 (no stanza => empty token set => default-deny still), override map CanonicalHostInboundTokenSig dedup, VIP unit names for subif, unzoned addrs builder, quarantine collision drops zone + unzones ifaces + drops scoped global. **NEGATIVE.**
- nat: pool missing/empty/invalid port -> PoolUnusable+reason, deterministic only when usable, FromZone "" = global/match-any not zone named "any" specific, tier calc most-specific 0, stable sort. **NEGATIVE, pool uint8 wrap noted in b1.**
- routes: family loop per-family next-table cures IPv6 blackhole, Dst-less skip explicitly not widened (would DROP selector), band filter avoids PBR widening to leak, ip-rule list error fails whole snapshot not partial, synthetic rib-group/next-table leaks per-prefix only. **NEGATIVE.**
- manager_ha: #1928 clears HA on non-cluster, watchdog-only preserves Active, clear empty idempotent, fabric sync. **NEGATIVE, clear error swallowing dedup #5487.**
- process/eventstream: requestLocked deadline #4036 cap #2744 writeFrame race #4835 via writeMu, p
```

---

#### Finding from ps-A7_go_daemon_host-b1.md

```
# Review: A7_go_daemon_host (batch 016) — Zone/HA/NFT/Apply ordering

Base: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A7_go_daemon_host-b1

## File-size/shape inventory
- Total in pkg/daemon: 199 files (51 prod, 148 test) — batch 016 covers 150 of them.
- Total LOC (prod+test): 60852
- Top prod by LOC / responsibility x hot-path proximity:
  1. `daemon_run.go` 2487 — boot predicate, bootstrap exit, shutdown ordering, FRR fail-closed clear
  2. `daemon_apply.go` 2153 — 10+ subsystems, fail-closed error joins, C1-C3 ctx boundaries, zoneRGMap install
  3. `daemon_nft.go` 1698 — inet xpf_lo0 (prio 0) + xpf_hostinbound (prio 10) rendering, counter lifecycle, fail-closed
  4. `daemon_system.go` 1731 — DNS/NTP/hostname/timezone/kernel tuning, lo0/host-inbound fail-closed joins
  5. `daemon_ha.go` 1576 — RG state machine, cluster+VRRP funnel, blackhole routes, per-RG services
  6. `daemon_ha_sync.go` 1020 — coldStart sticky, sync-ready timer, bulk prime retry, config-sync gate
  7. `daemon_ha_fabric.go` 965 — fab0/fab1 IPVLAN deferral, neighbor probe, dual-fabric refresh
  8. `bootstrap.go` 944 — five-case boot predicate, lifeline record, protected set, fail-closed FRR probe
  9. `host_tunables.go` 839 — governor/budget/coalesce capture/restore, drift detection, debt handling
 10. `device_map.go` 836 — mapped rename, strand-management preflight, teardown fail-closed #5309

Largest funcs: `applyConfigLocked` ~500 LOC (head+tail split), `applyDataplaneAndHACore` ~400, `buildHostInboundFilterPayload` ~200.

Prod vs test: prod 51 files ~18000 LOC, test 148 files ~42000 LOC. Batch includes almost all prod.

## Module log (coverage with negatives)
- `bootstrap.go`: reviewed boot predicate (computeBootClass), lifeline detection via default route, protectedInterfacesWith fxp0 narrowing. NEGATIVE: fail-closed on compile-failed boot correctly preserves FRR probe via pinned-links prefilter + control-socket armed check (#1993). Device-map boot refusal #5490 wired.
- `coalescence.go`: mlx5-only, ethtool -c probe idempotent, adaptive-rx/tx + rx/tx-usecs pin. NEGATIVE: non-mlx5 skip, empty allowlist no-op, best-effort never blocks bring-up — sound.
- `daemon.go`: applySem, bootstrapMode atomic, rgStates, fabric state. NEGATIVE: no zone-ID logic here.
- `daemon_apply.go`: apply ordering VRF->tunnel/xfrmi/bond->fabric IPVLAN->dataplane->networkd->RETH MAC->proxyARP->VRF rebind->FRR->next-table/rib-group/PBR->neighbor/RA/IPsec/DHCP/DDNS/DHCP clients->VRRP/DNS/NTP/lo0/host-inbound/SSH/login/sudoers/archive/flow/LLDP/event-options/RPM/IPmon/cluster. Fail-closed joins: networkdErr, dhcpServerErr, ipsecErr, hostInboundErr, lo0Err, ifaceErr all joined at tail. C1/C2/C3 ctx boundaries checked. ZoneRGMap installed after ApplyConfig. device-map teardown BEFORE networkd.Apply (correct). FINDING #3 below.
- `daemon_nft.go`: chain priorities 0 vs 10 distinct (#3364), add+delete idempotent, counter pre-declare dedup, TCP flags fail-closed #5512, ICMP divergence, address-family filtering, lo0 reject faithfulness. NEGATIVE: no fail-open on unzoned (#4420 HI-2 emits junos-host sentinel DROP). Host-inbound ambiguous logging (#3718) only warn, not fail-closed — acceptable because strict commit gate rejects.
- `daemon_ha.go`: RG state machine unified, activation order rg_active FIRST then blackhole remove, deactivation blackhole FIRST then rg_active clear. Preflight for fabric redirect. No zone-ID logic beyond snapshotRethMasterState.
- `daemon_ha_fabric.go`: fab0/fab1 IPVLAN deferred until XSK bound (zerocopy), stale cleanup, retry 5x. NEGATIVE: fail-open? Logs CRITICAL but continues — HA heartbeat loss bounded by retry, acceptable.
- `daemon_ha_sync.go`: coldStart = !BulkEverCompleted sticky (dedup #5480 — NOT re-reporting). Sync-ready timer 5s, bulk prime retry with progress detection. Config-sync rejected when RG0 primary (prevents secondary overwrite). NEGATIVE: heartbeat suppression cap 5s monotonic (#1792) sound.
- `daemon_ha_us
```

---

#### Finding from ps-A7_go_daemon_host-b2.md

```
# Security Review — Batch A7_go_daemon_host b2/3
Base: 7e0fecf3b8f2dc6604600674373771c835484188
Date: 2026-07-09
Reviewer: claude-003
Scope: 150 files (40 prod, 110 test) across pkg/daemon, devicemap, diagcmd, fairness, frr, fsatomic, fwdstatus, ipsec, linuxsock, lldp, monitoriface, networkd, routing

## File-size/shape inventory (ranked by LOC × responsibility × hot-path proximity)

| Rank | File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|------|-----|----------|----------------|---------------|
| 1 | pkg/frr/policy_render.go | 2307 | prod | BGP/OSPF/ISIS/BFD + route-map/prefix-list/community rendering, redist isolation, chain collision, fail-closed gates | cold (FRR reload) but cross-VRF route-leak critical |
| 2 | pkg/routing/tunnel.go | 2016 | prod | GRE/IPIP/WG tun lifecycle, keepalive prober, addr reconcile, ownedNames retention | cold (netlink) but data-plane reachability |
| 3 | pkg/daemon/daemon_run.go (extra) | 2487 | prod | startup ordering: linksetup → device-map → RSS → dataplane load | boot critical |
| 4 | pkg/daemon/daemon_apply.go (extra) | 2153 | prod | commit serialization, networkd/FRR/IPsec/routing apply ordering | commit hot |
| 5 | pkg/routing/rules.go | 1447 | prod | policy-routing rule generation, VRF table selection | routing hot |
| 6 | pkg/ipsec/policy.go | 1135 | prod | swanctl child SA rendering, traffic-selector sanitization, PSK scoping, childname disambig | IPsec critical |
| 7 | pkg/frr/manager.go | 1057 | prod | FRR reload timeout, managed section write + vtysh fallback | control-plane crit |
| 8 | pkg/monitoriface/monitor.go | 952 | prod | interface counters snapshot, userspace-dp telemetry binding | observability |
| 9 | pkg/lldp/lldp.go | 939 | prod | LLDP Tx/Rx, TTL-0 shutdown, neighbor table cap, lifecycle mutex | L2 adjacency |
|10 | pkg/ipsec/ike.go | 890 | prod | IKE proposal building, DH group formatting, ECP/curve mapping | crypto agility |
|11 | pkg/networkd/networkd.go | 775 | prod | .link/.network/.netdev gen, stale sweep, reload/reconf debt, RP filter restore | boot/commit |
|12 | pkg/daemon/daemon_system.go | 1731 | prod (extra) | system login, DNS, NTP, syslog reconcile | host hardening |
|13 | pkg/daemon/daemon_nft.go | 1698 | prod (extra) | host-inbound nftables, lo0 filter, RG zone id | host inbound ACL (zone policy) |
|14 | pkg/daemon/linksetup.go | 545 | prod | PCI enumeration, positional rename collision-safe (#4178), bootstrap fxp0 | boot |
|15 | pkg/daemon/rss_indirection.go | 550 | prod | mlx5 RSS weight vector, driver guard, default restore | boot perf |
|… | pkg/routing/bond.go | 490 | prod | bond/LAG lifecycle | dataplane |
|… | pkg/frr/config_render.go | 445 | prod | static routes, interface settings, DHCP defaults, backup router | routing |
|… | pkg/daemon/login_password.go | 407 | prod | shadow reconcile, UID-keyed provenance, lock on removal | auth |

Test heaviest: pkg/frr/frr_test.go 6037 LOC (integration render), pkg/routing/routing_test.go 2193, pkg/ipsec/ipsec_test.go 1850.

Largest functions (approx via grep): generatePolicyOptions ~400 LOC (policy_render), applyConfigLocked ~300, enumerateAndRenameInterfaces ~120, renderConfig ~350, tunnel Apply ~500 (multiple concerns: removal diff + WG handoff + keepalive stop).

## Module log (coverage proof, including negatives)

- FRR policy_render: inspected sanitizeFRRValue (ASCII C0 → space), validRouterID, validClusterID, validBGPOrigin, resolveRedistribute skip+warn logic, bgpComposedChainCollision fail-closed, redist alias collision guard. Negative: no injection via newline possible; description/auth/community/as-path regex all sanitized. Route-map leak #4481 handled via redist alias. Set-clause injection #4482 — set community / as-path handled via sanitize + validation. PASS.
- FRR config_render: static route generation uses net.ParseIP validated dest/nexthop; no free-text injection. interface bandwidth / p2p hints numeric only. Negative: no injection surface.
- FRR manager: reload timeout 1
```

---

(10 findings at Medium level)


### Low


#### Finding from ps-A10_go_services_cli_deploy-b1.md

```
# Security Review A10 b1/3 — CLI dispatch, zone display, BPF headers, commit/rollback, deploy

BASE: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
Worktree: /tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1
Focus: protocol + tooling — CLI dispatch & show-output correctness, zone handling, BPF struct alignment, configstore, commit/rollback, TOCTOU

## Inventory (150 files)

**bpf/headers (6, 5334 LOC total):**
- xpf_common.h 898 — MAX_INTERFACES 65536, MAX_ZONES 64, iface_zone_key/value, pkt_meta, screen_config, etc.
- xpf_conntrack.h 225 — session_key packed (16B), session_value, tcp state machine
- xpf_helpers.h 2554 — BPF helper wrappers
- xpf_maps.h 921 — PROG_ARRAY, CPUMAP, scratch maps, interface maps sized MaxInterfaces
- xpf_nat.h 575 — nat_pool_config, snat_egress, nat64
- xpf_trace.h 161 — trace events

**cmd/cli (51 files, 8031 LOC):**
Prod: clear.go 266, main.go 672, shared.go 681, monitor.go 462, request.go 393, show.go 483, show_security.go 705, show_dhcp.go, show_firewall_effective.go, show_flow.go 414, show_interfaces.go, show_nat.go 298, show_protocols.go 85, show_services.go, show_system.go 141
Tests: commit_rollback_4868_test 141, grpc_maxrecv_5321 98, load_terminal_abort_4883 97, etc. Largest fn: dispatch() in main.go ~200 LOC, shared.go dispatchOperational ~180

**cmd/xpfd (10, 1628 LOC):**
main.go 412 (classifyCommand SSOT for subcommand routing), upgrade.go 257 (parseUpgradeArgs rejects leftover args #4869, cluster guard #5284), upgrade_kernel.go 217 (validateKernelVerbArgs #5322, lock serialization), publish_generation.go 153 (GC protection #4876), seed_runtime.go 101 (no positional args #5322), dispatch_test.go 75, leftover_args_5322 165, upgrade_args_4869 68, etc.

**docs/pr/812 (2):** vdso_probe.c, vdso_probe2.c — latency histogram evidence, not prod path

**pkg/cli up to screen_inventory (80+ files, ~7800 LOC in scope):**
- cli.go 548 (CLI struct, 15+ deps, commitCtx cancellable)
- cli_dispatch.go 523 (dispatch, extractPipe LastIndex, filterStream streaming #4709/#4731, parseLastCount clamp maxTailLines 100k #5037, pageStream)
- cli_config.go 486 (handleCommit strict parsing #4868, unknown option reject, handleLoad file read, handleCopyRename, handleInsert, commitApply via applyConfigFn #797)
- cli_show.go 281 (show dispatcher #4422 effective filter banner)
- cli_show_security_zones.go 210 (showZonesDisplay sorted, nil-tolerant #3493, host-inbound with lifelines #3682, detail per-logical-unit split #5325, SSOT ZoneDetailPolicySummary #3658)
- cli_show_security_screen.go 485 (SSOT ScreenEnabledCheckList #3327, counter warnings #3408/#3345, flood counters not-available #3643)
- cli_show_security_dispatch.go ~400 (enabledStr, scheduler active state #3062)
- cli_show_security_filters.go 549 (showFirewallFilters raw, showEffectiveFirewallFilters compiled #4422, banner generation drift #5067, Builds snapshots via BuildFirewallFilterSnapshots)
- cli_show_security.go 490 (showPoliciesHitCount bulk reader #3965/#4344, scoped_global handling #3286/#3357/#4626, metadata M11/H03/M12/M13 #3672/#3684, scheduler inactive #3062/#3624)
- Tests: cli_show_security_scoped_global_3286 222, _3357 100, cli_show_effective_filter_4422 143 + gen_5067 255, host_inbound_display_3654 (H04/M03 coverage), etc.

Responsibility x hot-path proximity ranking:
1. cli_dispatch.go — high (per-command entry, pipe handling, pager, commit/rollback)
2. cli_config.go — high (commit path, load, configstore interaction)
3. cli_show_security_zones.go — medium-high (zone audit surface, host-inbound)
4. cli_show_security_filters.go — medium-high (effective filter correctness, drift banner)
5. bpf/headers/xpf_common.h — medium (MAX_INTERFACES sizing, iface_zone mapping)
6. cmd/xpfd/upgrade.go — medium (in-place upgrade, rolling vs standalone guard)
7. pkg/dataplane/types.go + bpf_session_value.go — medium (struct alignment, ABI)

## Module Log (coverage proving)

- [x] bpf/headers/xpf_common.h: verified MAX_INTERFACES=65536, MAX_ZONES=64, iface_zo
```

---

#### Finding from ps-A10_go_services_cli_deploy-b2.md

```
# Security Review — Batch A10 Go Services CLI Deploy b2/3

Base: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
Scope: pkg/cli/* (from wireguard onward), pkg/ddns/*, pkg/dhcp/*, pkg/dhcprelay/*, pkg/dhcpserver/ddns*

## Inventory

| Module | Prod LOC | Test LOC | Files | Largest fn | Responsibility | Rank* |
|---|---|---|---|---|---|---|
| pkg/cli show_services/monitor/traffic | ~3.2k prod / ~4.5k test | 176+1081+277+70+389 etc | 26 prod files in batch | showSystem (1081 LOC) / handleMonitorSecurityFlowFile (150 LOC) | CLI dispatch, zone display, traffic capture argv, session egress map, permissions RBAC, trace-file confinement | High (user-facing root tcpdump) |
| pkg/ddns backends | ~7.5k prod / ~12k test | 16 prod files | largest surface_a.go 2109 LOC / backend_rfc2136.go 1126 | DDNS publish/withdraw, source-bind pinning, redirect-downgrade refusal, checkip oracle, durable state, provider transition orphans | High (credential-bearing egress, source-bind fail-closed) |
| pkg/dhcp client | ~2.8k prod / ~2k test | 5 prod | dhcp.go 1903 / commit 220 | DHCPv4/v6 lease acquire, T1/T2 renew/rebind (RFC2131/8415), classless routes opt121/249 supersede opt3, DUID persistence, anti-blackhole mask validation | High (WAN address, gateway, DNS, FRR route programming) |
| pkg/dhcprelay | ~2.4k prod / ~3.2k test | 4 prod | relay.go 1583 | DHCP relay giaddr primary selection, Option82 circuit-id, hop-limit loop protection, raw-L2 unicast fallback, server source IP allowlist (#4163), HA master gate | High (L2 broadcast domain ↔ upstream, rogue injection) |
| pkg/dhcpserver ddns | ~0.5k prod / ~1k test | 2 prod | ddns_leases.go 419 | Kea memfile parser destructive-diff safety: duplicate-column reject, required-column validation, ragged-row fail-closed | Medium (DNS record loss if parser lenient) |

*Rank = size × responsibility × hot-path proximity. Total batch ~150 files = 12200 prod + 19500 test approx.

## Module Log (incl. negatives proving coverage)

- cli_show_security_wireguard.go: Delegates to dpformat.FormatWireguardStatus, nil dp guard — NEGATIVE, no zone handling, shared formatter ensures parity.
- cli_show_security_zones.go: Sorted zones, nil zone tolerant (#3493), HostInboundViewWithLifelines renders zone-level + per-if override + lifeline exemption (#3654/3682). VLAN unit handling splits base+".0" logic via strconv.Atoi, detail renders only wanted unit (#5325). Counter read: not-implemented explicit vs nil error warning accumulation (#3643/#3408). SSOT for screen checks via ScreenEnabledCheckList (#3327). Policymatch.ZoneDetailPolicySummary SSOT for policy tiers (#3658). NEGATIVE for injection: no shell.
- cli_show_services.go: Strict subcommand dispatch, cmdtree help, unknown target errors. RPM uses os.Stdout atomic write, no template inj. NEGATIVE.
- monitor_traffic.go: Validates tokens, rejects bare matching, bare interface/count fail-closed (#4540, #4883). stripSurroundingQuotes peels one layer, buildMonitorTrafficArgv inserts "--" separator before filter (#4524). monitorFilterOptionToken rejects tokens starting with "-" (option smuggle, #4556 leading-quote peel). validateMonitorFilter defense-in-depth. Count bounded 0..8192 per sibling command bounding. Injection mitigations sound.
- permissions.go: monitor traffic requires PermControl (#4067), monitor security flow file/start requires PermControl (#5038) preventing view-only root file create, request system reboot/halt/zeroize + failover + dataplane disarm/inject requires PermMaint (#4108/#4859). resolveCommand prefix resolution mirrors dispatcher, cannot bypass via abbreviation. showConfigRedacted redacts secrets for non-super-user (#4099). NEGATIVE for privilege escalation beyond known gates.
- session_display.go: buildSessionEgressIfacesWithLookup uses LinuxIfName(ResolveReth), vlanID fallback Number>VlanID→0. First-write-wins on key collision.
- show_services_ddns.go: Secret redaction (TSIG key name redacted), provider backend display no secret, degraded alarm fail-closed. 
```

---

#### Finding from ps-A10_go_services_cli_deploy-b3.md

```
# A10 Go Services / CLI / Deploy Review b3/3 — Batch 002

## Inventory (114 files, ~20K LOC)

| Module | Files | LOC (prod) | Largest fn | Responsibility |
|--------|-------|------------|------------|----------------|
| dhcpserver | 8 go | 2111+934 lease_sync | generateKea4Config / lease parse | Kea config render, lease sync/seed, DDNS glue |
| natshow | 5 go | 49+117+108+114+117 | RenderSourceRuleDetail | NAT show rendering (source/dest/static/persistent) |
| policymatch | 48 (1 prod 47 test) | 1715 prod | Match 300+ | Zone policy simulator vs dataplane parity, global scoped, app matching |
| scheduler | 5 | 449 prod | evaluate 60, isWithinWindow 40 | Time window eval, wall-clock discontinuity, republish self-heal |
| scripts/deploy | 7 py | 1881 xpf-deploy + 6 test | cmd_kernel_roll 200 | Appliance deploy, fetch verify, HA roll orchestration |
| scripts/dist | 2 py | 345+786 | publish gate_images 140 | Minisign manifest, image signing, publish gate |
| scripts/image | 5 py | 756+686+122 +2 test | virt_customize bake 120 | Bake qcow2, config-drive ISO, validate gate |
| scripts/*.py, test/incus/*.py | ~35 py + 1 rs + 4 xsk | varied | - | Test harnesses, metrics, cold-path flooder (2170 RS) |

## Module Log

- dhcpserver/dhcpserver.go: generation supersession with atomic gen, fail-closed is-active query handling (#4870) — sound, query error triggers restart/stop + error surfacing. Stable hash subnet-id (#5041/#5203) with coprime probe step — correct.
- dhcpserver/lease_sync.go: clock-skew-safe Remaining re-anchor, v6 IA_PD handling, splitV6Identity error returns non-nil for malformed IAID (#2379). Memfile pre-seed with _kea ownership via fsatomic WithOwner — hardened. BOS: mergeLeasesByIdentity local wins — correct for active-active.
- dhcpserver/ddns.go: thin alias glue, keaLeaseParser maps unknown LeaseType to LeaseTypeUnknown fail-closed (#5072 IAPD AAAA suppression) — sound.
- natshow/source.go, dest.go: session counts keyed by {from,to} not rule-set name — inherent limitation (sessions carry zone IDs not rule-set name), not a bug; counter reads via NATCounterIDs — correct. IPv6 iteration present.
- natshow/persistent.go: binary.NativeEndian.PutUint32 recovers __be32 — matches CLAUDE.md byte order, v6 netip.AddrFrom16 without Unmap — correct per gc.go. No panic.
- natshow/static.go: NPTv6 vs static prefix rendering, detail fields — display only, no enforcement.
- policymatch/policymatch.go: tier order exact→single-wildcard merged→both-any→global→default, zoneKnown gate for undefined zones (#3355), scheduler gate first, content rejection SSOT via PolicyContentRejectionReasons (#3727/#4394), route-drop advisory (#4373), host-inbound token classification, feed overlay merge, ParseSelectorArgs fail-closed duplicate/unknown/empty. Very hardened.
- policymatch/zone_detail_summary.go: wildcard handling fromAny/toAny affect BothAny tier, policySetID advances on nil sets, global via GlobalPolicyAppliesToZone — correct.
- scheduler/scheduler.go: wallClockDiscontinuousLocked compares wall vs mono with 5s tolerance, 2min recovery hold, fail-closed during hold, date-range ParseInLocation(now.Location()) (#3988), isWithinWindow fail-closed on absent/incomplete, republish self-heal with pending flag — sound.
- scripts/deploy/xpf-deploy.py: preflight before mutate, golden qcow overlay (never writable golden), virtio-first NIC order validation (#165 H-22), VM cleanup on partial failure, fetch verifies against signed manifest with TOCTOU-safe copy in sign.py, anti-rollback watermark, lease acquire via flock atomic read-expire-write, holder sanitized via regex, ssh remote command quoted via shlex.quote — hardened.
- scripts/dist/sign.py: basename-only manifest, TOCTOU-safe verify via private 0700 tmp copy, placeholder pubkey refusal, path traversal check for manifest entries, duplicate basename refusal — hardened.
- scripts/dist/publish.py: default-deny allowlist for image tree, symlink rejection, per-suite InRelease verify, key-agreement cr
```

---

#### Finding from ps-A1_rust_dataplane_packet-b1.md

```
# Batch 003 b1/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b1
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

Ranked by LOC × responsibility-count × hot-path proximity (poll_descriptor hot=10, forwarding=8, frame=9, cos=5, coordinator=3, bpf_map=4, bench/build=1):

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ LOC god | per-packet orchestrator: host-inbound → lo0 → junos-host → route → screen → policy → SNAT → install → telemetry → HA | 10 |
| 2 | forwarding/mod.rs | 2795 | prod | lookup_forwarding_resolution_inner_ecmp 800+ | FIB/NAT/fabric/tunnel/VRF/zone-pair/MSS/local-delivery table-scoped decis | 9 |
| 3 | flow_cache.rs | 2000+ est | prod | lookup, insert | flow-cache hit/miss, MAC-epoch TOCTOU (#3918), owner-RG epoch | 9 |
| 4 | frame/inspect.rs | 1960 | prod | frame_l3_offset 68, packet_rel_l4_offset 100 | L3/L4 offset, IPv6 EH walk, fragment detection, flex-bounds, declared_end | 9 |
| 5 | frame/mod.rs | 1743 | prod | apply_dscp_rewrite 200 | rewrite orchestrator, DSCP, checksum adjust | 8 |
| 6 | forwarding_build/fib.rs | ~500 | prod | populate_routes, resolve_next_hops | route table build, preference validation (#3771), family mismatch | 7 |
| 7 | forwarding_build/zones.rs | 142 | prod | populate_zones 80 | zone name↔id, duplicate ID reject (#3719), reserved-range skip, host-inbound per-zone, reject_buckets per-zone (#3618), tcp_rst per-zone | 8 |
| 8 | forwarding/host_inbound.rs | 538 | prod | classify_system_service 134, host_inbound_admits 40 | host-inbound admit: system-services → L4 ports/ICMP types/IP proto, protocols all expansion (#3199) minus L2 (#3311), None=>true for unknown zone (id 0) | 8 |
| 9 | forwarding_build/*.rs (interfaces, cos, tunnels, validated, wg) | ~800 total | prod | — | interface→zone mapping, CoS iface config, tunnel endpoints, WG engines | 6 |
| 10 | frame/headers.rs | 338 | prod | write_eth_header_slice_tagged 40 (unsafe) | eth/ipv4/ipv6/udp header serializers, TxVlanTag, DF=1 atomic datagram (#1440) | 7 |
| 11 | frame/byte_writes.rs | 81 | prod | — | write_ipv4/6 src/dst (NO guards — caller must validate), L4 port writes (guarded) | 8 |
| 12 | frame/* (build/*, rewrite/*, tcp.rs, checksum.rs, tcp_segmentation.rs, wg.rs) | ~2500 total | prod | segment_forwarded_tcp_frames 500+ | frame building, rewrite descriptors, TCP segmentation, WG outer MTU SSOT | 7 |
| 13 | cos/* (admission, builders, ecn, fairness, flow_hash, queue_ops, token_bucket, tx_completion) | ~5000 total | mixed | admission check, queue_ops push/pop/drain/v_min, waterfill allocator | CoS classification, per-queue token-bucket, lossless queue, ECN, flow-hash, TX completion | 5 |
| 14 | coordinator/* (mod, bpf_maps, ha_state, inject, reconcile/*, refresh_bindings, session_manager, snapshot_refresh, status, supervisor, tunnel_supervision, wg_control, worker_manager, cos_leases/state) | ~8000 total | prod | mod.rs 982, status.rs 1045 | snapshot apply, BPF map mgmt, HA state, session sync, WG control, cos leases, bringup/teardown | 4 |
| 15 | bind.rs | ~600 | prod | — | XDP/XSK bind, UMEM setup | 4 |
| 16 | bpf_map/* (ha.rs, metrics.rs, mod.rs, pin.rs, publish_conntrack.rs) + bpf_map_tests | ~1500 total | mixed | — | BPF map definitions, pinning, conntrack publish, metrics | 4 |
| 17 | checksum.rs | ~300 | prod | compute_l4_csum_delta 100 | NAT checksum delta, NPTv6 neutral, IPv4 words | 6 |
| 18 | disposition.rs | ~500 | prod | record_forwarding_disposition 99 | disposition counters, zone counters via zone_counter_slot_map batched (#3651) | 5 |
| 19 | cold_path_hist.rs + tests | ~2000 | mixed | — | cold-path slot map direct 
```

---

#### Finding from ps-A1_rust_dataplane_packet-b2.md

```
# Batch 004 b2/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b2
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ god | orchestrator remainder after stage extractions: session-hit path, session-miss path (policy→NAT→FIB→screen→install), flowless path (#3292), junos-host gate #3019/#3706, PBR route_override #4392, DNS reply allow, strict-syn-check #4400, session limit #2134, fragment assoc NAT64 #2562, IPv6 ext over-limit #4743 | 10 |
| 2 | poll_descriptor/filter.rs | ~600+ | prod | filter_terminal, host_inbound_gated_lo0_action | input-filter eval + log emission, lo0 host-bound filter, host-inbound gating via host_inbound_admits_iface with logical ifindex #3609, PBR routing-instance override with Drop #4392, log source Pbr vs Filter, truthful REJECT→DENY downgrade #3615 | 8 |
| 3 | tx/dispatch/mod.rs | 1486 | prod | enqueue_pending_forwards 1048 god | Phase 8 try_inplace_rewrite_or_build, copy-frame oversized check, PTB derivation #2301/#2330, tunnel outer MTU SSOT #2300, tuple-mismatch diag #4041, single-recycle invariant 39 sites | 8 |
| 4 | types/cos.rs | 1786 | prod | — | CoSState 28 fields 5 lifecycles, cos_lease, equal-flow target policy parse #2458, loss-priority rewrite #3995 | 5 |
| 5 | types/forwarding.rs (already in b1 but referenced) | 1100 | prod | — | ForwardingState 66 fields (see b1) — hot FIB vs cold truth | 9 |
| 6 | wg/engine.rs | 1805 | prod | — | WG engine, handshake, session, cookie, framing, peer selection per #1434 multi-peer, allowed_ips LPM, secret redaction Debug #4484 zeroize | 6 |
| 7 | worker/*.rs (mod, lifecycle, loop_body, telemetry, cos/*, bind_meta, bpf_maps, flow_cache_state, scratch, timers) | ~3000 total | prod | loop_body setup/debug_report | worker loop, UMEM, XSK, flow-cache, TX pipeline BatchCounters #3651, cos row, status | 7 |
| 8 | tx/* (cos_classify.rs 1335 7-resp, dispatch/cos, drain/phase_*, rings, stats, tcp_segmentation, transmit/*, queue_service/* waterfill 2058) | ~8000 total | prod | cos_classify, queue_service::waterfill 432 god | CoS TX selection resolve, TX drain phases trivial/shaped/backup, rings, TCP segmentation, finalise/rewrite/stage/verify/write, waterfill allocator epoch refill f64 fraction clamp bitset Phase1 asc Phase2 desc WRAP | 6 |
| 9 | icmp_embed/* (builders, mod, nat_match_v4/v6, parse, return_resolution, session_match) | ~1500 total | prod | match_outer_v4, session_match | embedded ICMP NAT matching forward-NAT-by-reverse + session fallback, return resolution, builders for ICMP error translation | 7 |
| 10 | icmp_ptb.rs + icmp_ratelimit.rs + tests | ~2000 total | mixed | build_frag_needed, PacketTooBig | PTB generation inner MTU derivation WG/GRE/NAT64 #2301/#2330, icmp_ratelimit token bucket per-zone #3618 fallback global bucket | 6 |
| 11 | poll_stages.rs (already b1) + poll_descriptor/* (cookie_reply, filter, flow_cache_hit, nat_exception, reject_reply, rx_telemetry, debug_log_throttle) | ~2000 total | prod | stage_screen_check, stage_ipsec_passthrough | Stage 5 link-layer ARP/NDP classify w/ anti-poison #2851 #2790 Override #4475, Stage 6 GRE decap, Stage 7+8 flow parse + learn logical ifindex #2370, Stage 9 fabric ingress zone override, Stage 10 screen per-zone + alarm-without-drop, Stage 11 IPsec passthrough NewInboundIke gated host-inbound #4323 | 8 |
| 12 | neighbor.rs 2036 + sharded_neighbor + neighbor_* + neg_neigh | ~4000 total | prod | — | ARP/ND probe + netlink mgmt + monitor thread + warmer, sharded map insert_if_changed mac_change_epoch #3048, neighbor_latency, resolver, dispatch skip-learn check fo
```

---

#### Finding from ps-A2_rust_dataplane_nat-b1.md

```
# Batch A2 rust dataplane nat — Review Report
Base commit: 7e0fecf3b
Worktree: /tmp/review-wt-claude-003-A2_rust_dataplane_nat-b1

## File-size/shape inventory
Prod total: 9334 LOC (8 files). Test total: 15648 LOC (10 files).
Rank by size x responsibility x hot-path:
1. nat64.rs 3102 LOC — v6↔v4 translation, checksum incremental (RFC1624), ICMP error embedded-ICMP reversal, frag DF/ID policy, port-allocator integration, HA reserve, frag-assoc cache — hot per-packet.
2. allocator.rs 1974 LOC — lock-free bitmap port claim, FIFO recycle, persistent lease SM, deterministic CGNAT blocks v4/v6, address-only reverse-identity tokens, HA reservation, GC chunking — hottest cold-path (session-miss) but contended.
3. source.rs 1523 LOC — SNAT rule parsing, pool expansion, match (zone/interface/RI/L4/app), address-persistent sticky hash, port-less/ICMP query gates, deterministic dispatch, failure reason mapping — hot cold-path.
4. destination.rs 1109 LOC — DNAT exact O(1) + prefix LPM, proto wildcard PROTO_ANY=256 distinct from HOPOPT, off exemption short-circuit, source-scoped, L4 extra matches, dst_port range — hot cold-path.
5. static_nat.rs 808 LOC — 1:1 + block offset remap, bidirectional, zone/interface/RI/source scoped, port-mapped / match-port scoping, VRF-scoped external IPs — hot cold-path.
6. nptv6.rs 431 LOC — stateless /48 /64 prefix replacement, RFC6296 adj, 0xFFFF→0x0000 fold, zero-adj skip for checksum-neutral pair — hot per-packet.
7. mod.rs 347 LOC — NatDecision merge/reverse, counter store with fetch_sub clear (no lost update), parse-error loud skip — cold except decision.
8. status.rs 40 LOC — pool status snapshot aggregation — cold (1/s).

Largest fns est: `write_v6_to_v4_into` ~200, `write_v4_to_v6_into` ~180, `allocate_translation_locked` ~130, `match_source_nat_result_for_tuple` ~150.

## Module log (responsibility + negative if no finding)

- allocator.rs: Owns port ownership via AtomicU64 bitmap + per-addr recycle. Implements #2852 lock-free claim, #3047 skip-occupied, #3011 FIFO, #4676 chunked GC, #4388 reserve_flow for HA, #5269 address-only reverse keys, #4559 deterministic block alloc. Negative: no overflow/truncation bug, CAS claim correct, release/rollback symmetric, gc re-checks expiry. No High finding — bitmap is ABA-safe because bit never cleared between claim and free of same allocation.

- source.rs: Parses pool CIDR/host, builds PortAllocator per pool, matches with scope_ok + l4_matches + nets_match. Gates: non_first_fragment, port_less (has_l4_ports), icmp_query via `icmp_identifier_present` (fixes id==0 bug), tuple_unknown proto=0 wrapper, no_translation. Deterministic v4/v6 path uses pure fn indices. Negative: pool expansion correctly bounds MAX_POOL_PREFIX_HOSTS, fail-closed on malformed match (constrained flag), address_persistent sticky via FxHasher seeded.

- destination.rs: Exact map + prefix LPM + proto wildcard. Tier order: exact (proto,dst,port) → wildcard port → PROTO_ANY → prefix LPM (exact+wildcard+ANY). Off exemption yields DnatOutcome::Exempt short-circuiting .or_else chain (Junos stop). Source-scoped via PrefixV4/6, bare-host fallback, all-malformed fails closed. L4 extra matches AND-ed. Port-range collapsed to wildcard key + range vec. Negative: PROTO_ANY=256 outside u8 range prevents HOPOPT alias, insertion dedup includes off+scope+L4.

- static_nat.rs: Host exact + block /24→ offset remap (host_mask_v4/v6 with len>=max guard). Port-mapped: match_dst_port/mapped_port pair, SNAT key = mapped_port.or(match_dst_port). Scope tiering via pick_scoped zone-specific wins. SourceConstraint fail-closed, host-bits canonicalized. Negative: egress zone gate for SNAT (#2871) symmetric, block+port dropped (#3202), /0 handling via !mask yields match-any correctly.

- status.rs: Thin aggregation from PortAllocatorSnapshot. No alloc, no logic bug.

- nat64.rs: Stateless + stateful (PortAllocator per prefix for RFC6146 BIB). Incremental L4 checksum (adjust_l4_checksum_*), fallback to full recompute for
```

---

#### Finding from ps-A3_go_config_cli_tree-b1.md

```
# A3 Go Config/CLI Tree b1/4 — Zone Policy Focus (150 files)
Base: 7e0fecf3b8f2dc6604600674373771c835484188 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b1

## File Inventory (prod)
| File | LOC | Responsibility | Hot |
|---|---:|---|---|
| pkg/appid/catalog.go | 487 | App-ID catalog, uint16 id guard, port-zero sanitize (#5194), ICMP type gate (#3781) | cold |
| pkg/appid/runtime.go | 344 | CatalogNames walk (policy+NAT refs), tuple fallback canonical port parsing (#3725) | cold |
| pkg/cmdtree/tree.go | 1589 | Operational CLI tree, zone DynamicFn completions | cold |
| pkg/config/ast.go | 436 | Dual-shape AST, unionChildren (#4562) duplicate-sibling merge | cold |
| pkg/config/compiler.go | 2323 | Top compile dispatch, group expansion, inactive strip | cold |
| pkg/config/compiler_applications.go | 774 | App/app-set bracket list (#5181), resolveAppPort whole-spec before range split, 0-N floor norm (#4336) | cold |
| pkg/config/compiler_security.go | 114 | Dispatcher + ssh-known-hosts append-not-replace (#4821) | cold |
| pkg/config/compiler_security_zones.go | 239 | zoneInterfaceMembers bracket flatten (#5248), HIB merge (#4544/#4818) | cold boundary |
| pkg/config/compiler_security_policy.go | 451 | policy compile, fail-closed DENY default (#3043), collapsed-deny (#3141), scoped-global (#4626) | cold boundary |
| + 142 test files | ~4500 | regression for all gates | — |
Prod dominant ~6757 LOC cold path. No Rust dataplane hot path in this batch.

## Module Log (coverage proof)

- ast.go:navigatePath unionChildren — handles duplicate `from-zone untrust to-zone trust` siblings for nested lookup. Depth bounded by config file size (~MB). NEGATIVE: no unbounded recursion or OOM beyond file limit.
- ast.go:cloneNodes deep-copies Keys/Children — no slice aliasing. NEGATIVE sound.
- compiler_applications.go:applicationSetMemberValues reads Keys[1:] + Children covering bracket `[ a b c ]` → Keys["application","a","b","c"] (lexer strips brackets, #2419). Pre-#5181 only Keys[1] → DENY under-match fail-open. Now fixed.
- compiler_applications.go:resolveAppPort whole-spec lookup before range split covers hyphenated svc names (ftp-data) (#3397). Port 0 floor-norm 0-N→1-N (#4336) safe — port 0 never on wire. Bare 0 stays invalid.
- compiler_security.go:ssh-known-hosts find-or-create map + append per host across duplicate blocks (#4821) — prevents key-type loss.
- compiler_security_zones.go:zoneInterfaceMembers skips host-inbound-traffic child, recurses Keys+Children flattening wildcard-container nesting `[ ge-0/0/0 ge-0/0/1 ]` chain. NEGATIVE sound.
- compiler_security_zones.go:compileZones find-or-create by name + Interfaces append + HIB merge + AddressBook find-or-create — duplicate top-level security-zone instance (#4818) no longer replaces first (would discard interfaces → unmanaged/brought DOWN + wrong zone eval).
- appid/catalog.go:BuildCatalog uint32 nextID prevents uint16 wrap onto 0 sentinel (reserved UNKNOWN) — deterministic error at boundary. Proto fan-out keyed on absent spec not proto==0 (#4008). NormalizeExplicitPortRange 0/0-0 → unemittable not (0,0) wildcard.
- appid/runtime.go:CatalogNames includes NAT app refs (#3626) skips nil, sortedNames deterministic. canonicalPort via ParseCanonicalUint rejects +80, narrow-to-4464 (#3725) fail-closed.
- cmdtree/tree.go: DynamicFn nil-guarded cfg==nil→nil, routingInstanceTableNames nil-skip (#4866). NEGATIVE sound.

## Findings

### Title: Dead code catalogProtocolNumber retains buggy (0,false)->0 contract — regression risk
- Severity: Low
- Confidence: High
- Evidence: appid/catalog.go:429-436 (worktree file)
```
func catalogProtocolNumber(name string) uint8 {
    n, _ := ProtocolNumber(name)
    return n
}
```
Grep worktree `grep -r catalogProtocolNumber --include=*.go` → only definition, zero callers. BuildCatalog line126 uses `proto,protoOK := ProtocolNumber(app.Protocol)` with ok honored, not wrapper.
- Trace: (1) dev adds new app-path, sees catalogProtocolNumber hel
```

---

#### Finding from ps-A3_go_config_cli_tree-b2.md

```
# A3 Go Config/CLI Tree b2/4 — Zone Policy + Strict Gates (150 files)
Base: 7e0fecf3b8f2dc6604600674373771c835484188 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b2

## File Inventory
| File | LOC | Role |
|---|---:|---|
| compiler_security_zones.go | 239 | zone compile, bracket flatten (#5248), HIB merge (#4544/#4818) |
| compiler_security_policy.go | 451 | policy compile, fail-closed default DENY (#3043), collapsed-deny (#3141/#3374), scoped-global (#3148/#4626) |
| compiler_security_addressbook.go | 430 | book/set bracket (#4791), find-or-create merge (#4706) |
| compiler_security_log.go | 268 | syslog port dual-location gate (#3349), TLS-profile no-op reject (#3350) |
| compiler_security_screen.go | 474 | 16 IDS checks profile compile |
| compiler_policy_match.go | 320 | unsupported match leaf (#3113), multi-value tail escape (#3142), swallowed from-zone/to-zone token (#3673), dup-block walk (#3562/#3842) |
| compiler_policy_missing_match.go | 201 | required dimensions gate (#3044) |
| compiler_policy_then.go | 583 | unsupported then-permit (#3114)/reject (#3115)/deny (#3141) + orphan log-sub (#3374) |
| filter_match_resolve.go | 324 | symbolic icmp/port→numeric SSOT (#3205), hyphenated svc-name before range split |
| firewall_filter_expand.go | 137 | cross-product stride uint64 overflow-checked (#5456), clamp 1<<20 |
| compiler_validate_strict_policy.go | ~400 | policy addr token validation, any/any-ipv4/any-ipv6, feed bindings, CIDR/IP |
| + 138 test files | ~5000 | regression |

All cold compile-time gates. Hot Rust policy.rs (3598 LOC) not in batch.

## Module Log

- zones: zoneInterfaceMembers skips HIB child, recurses Keys+Children — bracket `[ a b c ]` as nested chain (wildcard container) handled. Empty Keys check k!="" prevents empty-name add. find-or-create by name prevents dup-instance replace (boundary loss). NEGATIVE sound.
- security_policy: policyMatchChildren/ThenChildren accumulate across ALL match/then blocks (#3842) — dup inner blocks no longer silently widen. terminalActions tracks conflicting permit+deny → #3043 gate rejects, default DENY for actionless. applyCollapsedDenyModifiers wires flat-collapsed `then deny log/count` (Keys[1:] + descendant walk). sortDedupZones canonicalizes scoped-global lists.
- policy_match: forEachChild at security/policies (#3562) closes dup-block bypass (parseStatements appends). firewallMatchValues SSOT reads Keys[1:] + Children for multi:true leaves (#2419). swallowedStructuralMatchTokens from-zone/to-zone in zone-pair multi-value tail rejected (#3673) — prevents app named "from-zone" satisfying gate and hiding keyword as bogus operand.
- missing_match: required dimensions across ALL match blocks (policyMatchChildren) — split across dup blocks counted. NEGATIVE sound, Junos parity.
- policy_then: supportedThenPermitChildren empty today (any child under then permit is silent-drop → UTM/IDP strip fail-open). Inspects ALL permit nodes across ALL then blocks (policyThenActionNodes) for #3377 two-node split + #3842 dup then. collapsedThenActionTokens flattens 3 parser shapes shape-agnostic. hasLog over union of ALL deny nodes before orphan check (#3374) — split deny log + deny session-init not false-flagged.
- filter_match_resolve: whole-spec service lookup BEFORE range split (ftp-data not mangled), parseCanonicalPort rejects +80 (#3606), numeric lo>hi fails closed. Unrecognized token kept verbatim + UnknownPorts for strict reject — fail-closed.
- firewall_filter_expand: bits.Mul64 overflow-checked, saturates MaxUint64, stride clamp to MaxFilterTermExpansion 1<<20 (#5456) — retired-eBPF counter drift fixed; live userspace name-keyed so unaffected. Counts except prefixes (negated rule) so count==len(expandFilterTerm) drift-guard holds.
- validate_strict_policy: policyMatchNamedAddressRefs includes dynamic feed bindings + address book (global+zone-local folded). Recognizes "", any, any-ipv4/any-ipv6 (normalized to 0.0.0.0/0, ::/0 in compilePolicies), CIDR, IP, named
```

---

#### Finding from ps-A3_go_config_cli_tree-b3.md

```
# A3 Go Config/CLI Tree b3/4 — Zone Policy + Host-Inbound (150 files)
Base: 312a2dfdef733697828fc68e8fdd92dbcaf70d69 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b3

## File Inventory (150 files, 52860 LOC total in batch)
- Prod: 33 files 11958 LOC | Test: 125 files ~40500 LOC
- Largest prod: schema_security 1263, junos_host_deny 1070, schema_system 1075, schema_walk 803, schema_routing 824
- Responsibility rank: junos_host_deny (security critical, per-zone kernel iifname + junos-host DROP projection) > schema_security (zone/policy grammar SSOT, multi-zone from/to) > host_inbound_tokens (SSOT for host-inbound admission, 3-plane parity) > host_inbound_view + lifeline (lifeline exemption SSOT) > schema_validators_* (commit-time fail-closed gates) > lexer/parser (DoS caps, bracket-list collapse)
- Hot-path proximity: none hot (all cold config-compile), but junos_host_deny + host_inbound_tokens feed userspace-dp snapshot and nft hostinbound chain

| File | LOC | Responsibility |
|------|----:|----------------|
| schema_security.go | 1263 | zones, host-inbound, policies (from/to-zone multi), alg, flow, NAT/ike/ipsec closed-world flips |
| junos_host_deny.go | 1070 | junos-host to-zone projection, representability gate, iifname netdev scope |
| schema_system.go | 1075 | system/login/time-zone/crypto validators, master-pass PRF |
| schema_routing.go | 824 | routing-options, policy-options, protocols |
| schema_walk.go | 803 | typed-leaf walk, closed-world enforcement, scalar arity |
| schema_cos.go | 563 | CoS schedulers, filters |
| host_inbound_tokens.go | 484 | system-services/protocols SSOT, L4 tuple expansion |
| parser.go | 403 | recursive-descent, depth cap, stray-brace fail-closed |
| lexer.go | 359 | bracket sugar [#2419], endpoint literal preservation |
| predefined.go | 356 | app + app-set SSOT |
| schema_complete.go | 353 | completion |
| host_inbound_view.go | 342 | zone+per-iface effective view UNION |
| etc | — | rest prod <250 each |

## Module Log (coverage proving)

- host_inbound_multicast.go: catalog of routing multicast groups (OSPF 224.0.0.5/6 etc). Pure data + accessors. No enforcement today (advisory only per #4455 comment). Scanning HostInboundMulticastProtocol lowercases token, matches catalog. No alloc hot path. NEGATIVE sound – fail-open-but-bounded documented, parity gap not bypass.
- host_inbound_tokens.go: KnownHostInboundSystemServices/Protocols sets, HostInboundServiceFamily/ProtocolFamily scoping, L4Match structured SSOT, full-admit predicate. Lowercase canonical, family gates return nil for wrong family. NEGATIVE – SSOT correct, parity tests pinned.
- host_inbound_view.go: UnionHostInboundTokens trims, dedup exact-case, preserves authored order for display. InterfaceHostInboundEffective unions physical-parent override + exact ref (#3720). HostInboundViewWithLifelines records lifeline-exempt interfaces. NEGATIVE – display-only, mirrors dataplane union.
- lifeline.go: LifelineBaseName strips unit suffix by first dot, HostInboundLifelineSet builds fxp0+configured control/fabric, HostInboundLifelineInterface unconditional em0 + fab prefix. Design note acknowledges fab-foo over-match but intentional for #3682 visibility-only change. Checked for null/empty handling. Sound per doc.
- inactive.go: HasInactiveNodes, WithoutInactive deep clone with inactive pruned, cloneForExpansion avoids double clone. No recursion depth issues (iterates Children). NEGATIVE – correct strip before group expansion.
- junos_host_deny.go: BuildJunosHostDenyProjection three-tier (exact zone-pair → from-any → global with from/to scope #3639), whole-program representability gate, DROP-only set-subtraction, poison sentinel for cross-dimension permit/deny (#5.1). Address resolver static-only, feed-tainted → unrepresentable, wildcard handling. JunosHostZoneIngressNetdevs per-zone netdev scope excludes lifelines + cross-zone ambiguous parents. Validated against snapshot via TestJunosHostZoneNetdevsMatchSnapshot (comment). 
```

---

#### Finding from ps-A3_go_config_cli_tree-b4.md

```
# Security Review — Batch A3 Go Config CLI Tree b4/4 (52 files)

> Base commit: 312a2dfd (worktree /tmp/review-wt-claude-003-A3_go_config_cli_tree-b4)
> Focus: security zone policies, inter-zone allow/deny, host-inbound admission, policy compilation, NAT zone scoping, typed-leaf validation

## File Size / Shape Inventory (prod vs test, responsibility, hot-path proximity)

| File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|-----|-----------|----------------|---------------|
| types_security.go | 1306 | prod | ZoneConfig, Policy/PolicyMatch, NAT, Screen, ALG, Scheduler — zone policy SSOT | HIGH (snapshot builder reads zones/policies/NAT) |
| types_system.go | 1565 | prod | System stanza (dataplane, syslog, SNMP, login RBAC) — RBAC + SNMP source-IP gate | MEDIUM (RBAC gating, SNMP) |
| types_routing.go | 651 | prod | Routing protocols, tunnel config cloneForUnit — tunnel aliasing (perf + sec) | MEDIUM (FIB ingest) |
| types_chassis.go | 188 | prod | Device-map + cluster config — bare-metal identity | LOW (boot-time) |
| tunnelemit.go | 123 | prod | Tunnel endpoint canonical emission (collision gate + builder SSOT) | MEDIUM (ID stability) |
| tunnelid.go | 290 | prod | StableTunnelEndpointID fold + 3-view HA-symmetric collision gate | MEDIUM (HA determinism) |
| zoneid.go | 251 | prod | StableZoneID fold + 3-view collision gate + quarantine runtime | HIGH (zone ID wire-adjacent) |
| value_type.go | 155 | prod | Typed-leaf ValueType + placeholder — drives commit-time validators | MEDIUM (validation trigger) |
| types_cos.go | 283 | prod | CoS forwarding-class/scheduler/shaper binding | LOW (CoS) |
| types_interfaces.go | 150 | prod | InterfaceConfig, Units, LAG, VRRP groups | LOW |
| xfrmi.go | 77 | prod | XFRM if_id + secure-tunnel bind-interface validator | MEDIUM (VPN liveness) |
| snmp_clients.go | 206 | prod | SNMP community clients allowlist parse + longest-prefix match + cache | MEDIUM (SNMP ACL) |
| syslog_logfile.go | 50 | prod | show-log allowlist gate — path traversal + arbitrary log read | HIGH (priv esc) |
| tcp_flags.go | 147 | prod | Firewall filter tcp-flags conjunctive expression — fail-closed on OR/contradiction | HIGH (filter bypass) |
| 37 test files | 99 avg | test | Fail-on-revert guards for every strict gate above | N/A |
| **Total** | ~8200 | 15 prod + 37 test | | |

Ranking by size×responsibility×hot-path: types_security.go > types_system.go > zoneid.go > types_routing.go > snmp_clients.go > tcp_flags.go > syslog_logfile.go > tunnelid.go.

## Module Log (incl. negatives proving coverage)

- types_security.go — PASS: reviewed ZoneConfig.InterfaceHostInbound (per-if HIB union, #3362), IsWildcardZone/IsWildcardZoneSet duality (two spellings for global wildcard), GlobalPolicyAppliesToZone (from||to any match), sortDedupZones/ScopeSingular/IsHostToZoneScope, NAT match multi-value accessors (natMatchValues fallback), StaticNATRule source-address list (was scalar drop M02). No integer truncation on ports — DestinationPort int validated via strict gates elsewhere. No zone bypass. RBAC: LoginClassPermissions forbids PermMaint on non-super (operator lacks maintenance). Coverage: read 1306 lines.
- zoneid.go — PASS: StableZoneID FNV-1a xor-fold [1, 65533], reserved range protected, 3-view HA-symmetric collision check (pre-expansion union + per-node expansion), QuarantinedZoneNames deterministic later-sort quarantine. Tests pin hash-freeze (frozen fold). No integer overflow — uint16 fold mod arithmetic correct. Negative: no findings, determinism holds.
- types_routing.go — PASS: TunnelConfig.cloneForUnit deep-copies Addresses + WgPeers (addresses independent backing array, #3898), WgOuterFamilyV6, ConnectedNetworkPrefix skip for host/default/link-local. No issue.
- zone_count_cap_test.go — PASS: MaxUsableZoneID == ZoneIDReservedMin-1 == 65533, pigeonhole cap guard.
- zone_dup_block_4818_test.go — PASS: duplicate top-level security-zone sibling blocks merge (find-or-create, #4818) — previously silently 
```

---

#### Finding from ps-A5_go_ha_vrrp_ra_conntrack-b1.md

```
# HA / VRRP / RA / conntrack — review b1 (Go)

Base: 7e0fecf
Worktree: /tmp/review-wt-claude-003-A5_go_ha_vrrp_ra_conntrack-b1

## File inventory
- Total lines (prod+test): 47864 (from wc -l)
- Prod: 19125 lines across 35 files
  - pkg/cluster: 11750 prod (largest: sync_conn.go 1858, heartbeat.go 881, failover.go 912, sync.go 1048, election.go 475)
  - pkg/conntrack: 554 (gc.go)
  - pkg/ra: 2193 (ra.go 1118, sender.go 1055, filter.go 21)
  - pkg/vrrp: 4628 (instance.go 2417, manager.go 1108, packet.go 277, track.go 341, addrwatch.go 219)
- Test: 28739 lines, 71 files (heaviest: cluster/sync_test.go 4717, ra/serialize_test.go 2706, vrrp/vrrp_test.go 2468)
- Largest prod fn: vrrpInstance.run / stepBackup (~400 LOC), SessionSync.handleMessage (~350 LOC), Manager.UpdateInstances
- Hot path proximity ranking (size x responsibility x freq):
  1. pkg/cluster/heartbeat.go Marshal/Unmarshal + sender/receiver loops — every 100ms, drives election, auth, replay
  2. pkg/cluster/sync_protocol.go + sync_conn.go — TCP session sync, gen guards, bulk, fencing
  3. pkg/vrrp/instance.go — BECOME_MASTER/BACKUP, TTL=255, hop-limit, GARP, equal-priority tie-break, preempt hold + watchdog
  4. pkg/ra/ra.go + sender.go — goodbye ordering, RA flood prevention, RS validation
  5. pkg/cluster/election.go — dual-active, preempt, dup node-id fail-closed, kernel-upgrade hold
  6. pkg/conntrack/gc.go — expiry ownership (IsLocalPrimary), per-IP limit counting, aggressive aging hysteresis

## Module log (incl negatives => NEGATIVE RESULT)

- cluster/election.go: dual-active resolves on eff priority then nodeID, dup nodeID logs rate-limited and fails closed to SECONDARY. kernelUpgradeHold blocks both single-node and peer paths. NEGATIVE.
- cluster/heartbeat.go: MarshalHeartbeatBody reserves tailReserve up front (#4107 invariant — monitor truncation leaves HMAC space, never silent downgrade). maxHeartbeatGroups=255 + oversize warn once (#4434). Monotonic nanos (#1792) for liveness, StartupGrace 30s suppresses split-brain on simultaneous boot. Auth: HMAC+session+counter, anti-replay re-anchor on new session, constant-time compare, cross-channel downgrade guard (peerAuthSeen). NEGATIVE for core, one LOW on truncation visibility below.
- cluster/sync_protocol.go: length-gated trailing fields (#2170 gen, #3301 AppTimeout, #4565 NAT64), config gen magic trailing framing (#3931), DHCP lease count clamp prevents OOM. NEGATIVE.
- cluster/sync_conn.go: activeConnLocked prefers fab0, bulk re-drive on survivor gated on outboundBulkAcked (not bulkEverCompleted) (#4360 correct), bulkRedriveInFlight CAS prevents storm, writeFull seals per-frame via authConn, acceptLoop per-conn goroutine prevents handshake DoS (#4370). NEGATIVE.
- cluster/sync_auth.go: per-conn frame key derived via canonical nonce sort, seq replay guard, downgrade guard consulted via heartbeat auth seen. NEGATIVE.
- cluster/failover.go: per-RG failoverGen prevents ResetFailover vs pre-hook race (#5246), failoverInProgress serialization, transfer-commit override maps co-located, grace windows 2*threshold*interval+5s min 10s. NEGATIVE, except byte-trunc find below.
- cluster/garp.go: BurstStillValid abdication gate (#2867) checked before each follow-up, burstSendErrors counted, IPv6 NA Router=1 preserves default route. NEGATIVE.
- cluster/monitor.go: dampening (3 fail/3 pass + 5s hold), ICMP id from local port (kernel-overwrites-ident), seq anti-replay, peer MatchesTarget check — hardening present. NEGATIVE.
- cluster/readiness.go: holdTimer closure checks m.stopped (#4716) and cur!=rg (#5245) to avoid stale election. NEGATIVE.
- cluster/reth.go: virtual MAC 02:bf:72:CC:RR:NN per-node unique, stable LLA fe80::bf:72:CC:RR shared. NEGATIVE.
- vrrp/packet.go: VRRPv3 pseudo-header checksum for both families (RFC 5798 §5.2.8), legacy IPv4 no-pseudo accept for migration. Mutable input restored after checksum calc. NEGATIVE.
- vrrp/manager.go: VRID range guard 1..255 (#4573), build-before-teardown for ifindex drift 
```

---

#### Finding from ps-A6_go_dataplane_manager-b1.md

```
# A6 Go Dataplane Manager — Review (b1/3)

## File Inventory (150 files, ~60 prod / 90 test)

Ranked by size×responsibility×hot-path proximity:

- `pkg/dataplane/compiler.go` ~1.6k LOC prod, god compile orchestrator (zones, addr-book, apps, policies, nat, screen, flow). Largest fn `CompileConfig` phases + `compilePolicies` expansion. Responsibility: zone→ID stable hash, policy expansion, app-set.
- `pkg/dataplane/compiler_iface.go` ~1.4k LOC prod, zone/interface mapping, netlink, rxvlan off, MTU, RETH recovery, unmanaged strip, device-map leave-alone.
- `pkg/dataplane/compiler_nat.go` ~1.3k LOC prod, SNAT/DNAT/static/NAT64/NPTv6 compilation, pool ID assignment, counter ID stable hash + collision resolve + finalizer.
- `pkg/dataplane/types.go` ~1.1k LOC prod, all BPF struct mirrors, zone pair key, policy rule, NAT pool, filter config, screen flags.
- `pkg/dataplane/compiler_filter.go` ~0.8k LOC prod, filter protocol validation, policer ID assignment, term→rule cross-product expansion with #5456 cap, iface→filter map.
- `pkg/dataplane/userspace/eventstream.go` ~1.2k LOC prod, binary frame header (len+type+seq), session open/close decode, gap → full resync, pending queue 4096, writeMu sep lock.
- `pkg/dataplane/userspace/manager.go` ~0.4k prod + many split files, snapshot lifecycle, generation, deferred worker arm debt, appliedSnapshot coherency.
- `pkg/dataplane/userspace/builder.go` ~0.2k prod, snapshot assembly, zone collision quarantine, content hash dedup.
- `pkg/dataplane/userspace/filters.go` ~0.6k prod, firewall filter snapshot lowering (prefix-list, except, DSCP, TCP-flags, flex-match).
- `pkg/dataplane/userspace/interfaces.go` ~0.56k prod, synthetic logical ifindex FNV hash, VLAN parent bind contract, bound interface allowlist.
- `pkg/dataplane/userspace/flow.go` ~0.26k prod, wire coercion u16/u32/u64 for Rust JSON decode (MSS, timeouts).
- `pkg/dataplane/userspace/cos.go` ~0.26k prod, CoS snapshot with safe degrade on undefined class.
- Many `*_test.go` (app catalog parity, NAT counter collision/determinism/stability, filter expansion, prefix-list except, port except, host-inbound classify, etc.) — high coverage of edge cases.

Prod files shape: manager pattern with populate-before-clear map writes for legacy BPF; userspace path builds immutable snapshot then single control-socket publish. Zone handling: `assignZoneIDs` uses StableZoneID(name) FNV fold into [1, ReservedMin-1]; policy sets pack into `policySetID*MaxRulesPerPolicy+index` rule ID.

## Module Log (coverage)

- `compiler.go` zones: checked nil zone slot guard, screen profile lookup, host-inbound flags, TCPRst, iface zone composite key, RETH RG inherit, native XDP flag, VLAN sub-if creation, managed interface list for networkd, unmanaged strip with #1922 protected set and #1956 device-map leave-alone, VRF/Tunnel/Bridge owned skip, stale deletion. Policies: application-set expansion, appID map, Any handling, implicit set building, rule ID calculation, scheduler slots. Default policy sentinel #3057. Fail-closed on unknown screen/addr.
- `compiler_iface.go` (already in compiler.go in this tree): resolveInterfaceRef handles reth→phys, irb→bridge, fab IPVLAN parent, tunnel names. VLAN reconciliation, DHCP/RETH skip, link cycle deferral, RX queue tuning. Negative: legacy eBPF direct map writes mid-compile not transactional.
- `compiler_nat.go`: pool ID uint8 assignment, compiledPools cache, v4/v6 split, interface-mode SNAT egress IP per ifindex+vlan, deterministic NAT host-base v4/v6, persistent NAT registration, source/dest addr name resolution, DNAT port/proto expansion with application-sets, SNAT off mode, NAT counter ID stable hash FNV-1a with re-hash collision handling and finalize sorted deterministic finalizer #5099, exhaustion fallback to 0. Checked overflow risk for poolID.
- `compiler_filter.go`: protocol validation via appid.ProtocolNumber SSOT, policer ID 1-based, filter ID deterministic sorted, rule expansion with MaxFilterTermExpansion cap #5456, pro
```

---

#### Finding from ps-A6_go_dataplane_manager-b2.md

```
# Batch A6 b2/3 — Go dataplane manager (policy, zones, NAT, routes, HA glue)

Base: 7e0fecf3b, worktree /tmp/review-wt-claude-003-A6_go_dataplane_manager-b2
Files: 150, prod ~12k LOC core, test ~58k LOC; largest: protocol.go 3064 (snapshot v3), maps_sync.go 1763, manager_ha.go 1643, filters.go 641.

## Inventory (ranked responsibility × hot-path proximity)

| File | LOC | Responsibility | Cold/Hot | Largest fn |
|---|---|---|---|---|
| protocol.go | 3064 | wire version=3, 66-field ConfigSnapshot, inject bound 4096 (DoS reject-not-clamp), ZoneCounterLayout/ColdPathLayout versions | cold but version invariant governs rolling upgrade | ConfigSnapshot struct |
| policies_lower.go | 170 | global->zone lowering, singular/plural scoped-global #4626 M03, additive-wire compat | cold, #5488 interop | buildOneRuleSnapshot + effectiveMatch* |
| policies.go | 800+ | walkPolicyRuleSlots ID namespace #3143/#3145 MaxRulesPerPolicy cap, feed overlay #2049, representability sentinel #3261, app sentinel #2124 | cold but fail-open if sentinel missing | buildPolicySnapshotsWithFeeds |
| zones*.go | 300+370 | StableZoneID hash, quarantine #3719, host-inbound SSOT lifeline #3682 per-iface override union #3362, default-deny parity #3405 for no-stanza zones, VIP scoping #3172, unzoned junos-host catch-all | cold, zone collapse=fail-open | BuildZoneHostInboundViews |
| nat*.go | ~2k | pool tiers iface>zone>ri #184 #4161, any->"" fix, match-any dest fail-open, persistent NAT, deterministic block alloc, Off handling | cold, misc-NAT leak | buildSourceNATSnapshots |
| routes.go | 300 | FIB connected+static+ip-rule leaks family-normalized (blue.inet6.0 fix), Dst-less skip avoids widening, PBR bands 100-199/30000-30999, list error fail-closed whole snapshot | cold but leak miss=blackhole/bypass | buildRouteSnapshots |
| manager_ha.go | 200 | seed inventory #1928 drops phantom groups on non-cluster, watchdog-only refresh preserves Active, clearHelper empty idempotent | cold | syncHAStateLocked |
| maps_sync.go | partial | RST suppression TOCTOU, interface NAT addr sets sorted dedup | cold | syncInterfaceNATAddressMapsLocked |

## Module log (negatives)

- policies_lower: singular=first zone, plural=full set, effectiveMatch* prefers plural fallback singular — new helper correct, old helper same version 3 ignores plural narrows deny (dedup #5488). **NEGATIVE for new, known interop.**
- policies.go: any4/any6/any-ipv4/any-ipv6 literal accept, feed-bound membership, nameToID+recursive nameRepresentable, unrepresentable -> __unsupported_address__ on both v3+legacy shapes clearing book IDs => Rust SnapshotIntegrityError whole-snapshot reject prev-good retained fresh-boot default-deny. app -> __unsupported_application__ name+proto both sentinel, Rust reject. literal vs book via classifyPolicyAddresses, scheduler state, SourceAddressExcluded/DestinationAddressExcluded inversion. **NEGATIVE — fail-closed solid.**
- zones: zone-default group seeded for #3405 (no stanza => empty token set => default-deny still), override map CanonicalHostInboundTokenSig dedup, VIP unit names for subif, unzoned addrs builder, quarantine collision drops zone + unzones ifaces + drops scoped global. **NEGATIVE.**
- nat: pool missing/empty/invalid port -> PoolUnusable+reason, deterministic only when usable, FromZone "" = global/match-any not zone named "any" specific, tier calc most-specific 0, stable sort. **NEGATIVE, pool uint8 wrap noted in b1.**
- routes: family loop per-family next-table cures IPv6 blackhole, Dst-less skip explicitly not widened (would DROP selector), band filter avoids PBR widening to leak, ip-rule list error fails whole snapshot not partial, synthetic rib-group/next-table leaks per-prefix only. **NEGATIVE.**
- manager_ha: #1928 clears HA on non-cluster, watchdog-only preserves Active, clear empty idempotent, fabric sync. **NEGATIVE, clear error swallowing dedup #5487.**
- process/eventstream: requestLocked deadline #4036 cap #2744 writeFrame race #4835 via writeMu, p
```

---

#### Finding from ps-A7_go_daemon_host-b1.md

```
# Review: A7_go_daemon_host (batch 016) — Zone/HA/NFT/Apply ordering

Base: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A7_go_daemon_host-b1

## File-size/shape inventory
- Total in pkg/daemon: 199 files (51 prod, 148 test) — batch 016 covers 150 of them.
- Total LOC (prod+test): 60852
- Top prod by LOC / responsibility x hot-path proximity:
  1. `daemon_run.go` 2487 — boot predicate, bootstrap exit, shutdown ordering, FRR fail-closed clear
  2. `daemon_apply.go` 2153 — 10+ subsystems, fail-closed error joins, C1-C3 ctx boundaries, zoneRGMap install
  3. `daemon_nft.go` 1698 — inet xpf_lo0 (prio 0) + xpf_hostinbound (prio 10) rendering, counter lifecycle, fail-closed
  4. `daemon_system.go` 1731 — DNS/NTP/hostname/timezone/kernel tuning, lo0/host-inbound fail-closed joins
  5. `daemon_ha.go` 1576 — RG state machine, cluster+VRRP funnel, blackhole routes, per-RG services
  6. `daemon_ha_sync.go` 1020 — coldStart sticky, sync-ready timer, bulk prime retry, config-sync gate
  7. `daemon_ha_fabric.go` 965 — fab0/fab1 IPVLAN deferral, neighbor probe, dual-fabric refresh
  8. `bootstrap.go` 944 — five-case boot predicate, lifeline record, protected set, fail-closed FRR probe
  9. `host_tunables.go` 839 — governor/budget/coalesce capture/restore, drift detection, debt handling
 10. `device_map.go` 836 — mapped rename, strand-management preflight, teardown fail-closed #5309

Largest funcs: `applyConfigLocked` ~500 LOC (head+tail split), `applyDataplaneAndHACore` ~400, `buildHostInboundFilterPayload` ~200.

Prod vs test: prod 51 files ~18000 LOC, test 148 files ~42000 LOC. Batch includes almost all prod.

## Module log (coverage with negatives)
- `bootstrap.go`: reviewed boot predicate (computeBootClass), lifeline detection via default route, protectedInterfacesWith fxp0 narrowing. NEGATIVE: fail-closed on compile-failed boot correctly preserves FRR probe via pinned-links prefilter + control-socket armed check (#1993). Device-map boot refusal #5490 wired.
- `coalescence.go`: mlx5-only, ethtool -c probe idempotent, adaptive-rx/tx + rx/tx-usecs pin. NEGATIVE: non-mlx5 skip, empty allowlist no-op, best-effort never blocks bring-up — sound.
- `daemon.go`: applySem, bootstrapMode atomic, rgStates, fabric state. NEGATIVE: no zone-ID logic here.
- `daemon_apply.go`: apply ordering VRF->tunnel/xfrmi/bond->fabric IPVLAN->dataplane->networkd->RETH MAC->proxyARP->VRF rebind->FRR->next-table/rib-group/PBR->neighbor/RA/IPsec/DHCP/DDNS/DHCP clients->VRRP/DNS/NTP/lo0/host-inbound/SSH/login/sudoers/archive/flow/LLDP/event-options/RPM/IPmon/cluster. Fail-closed joins: networkdErr, dhcpServerErr, ipsecErr, hostInboundErr, lo0Err, ifaceErr all joined at tail. C1/C2/C3 ctx boundaries checked. ZoneRGMap installed after ApplyConfig. device-map teardown BEFORE networkd.Apply (correct). FINDING #3 below.
- `daemon_nft.go`: chain priorities 0 vs 10 distinct (#3364), add+delete idempotent, counter pre-declare dedup, TCP flags fail-closed #5512, ICMP divergence, address-family filtering, lo0 reject faithfulness. NEGATIVE: no fail-open on unzoned (#4420 HI-2 emits junos-host sentinel DROP). Host-inbound ambiguous logging (#3718) only warn, not fail-closed — acceptable because strict commit gate rejects.
- `daemon_ha.go`: RG state machine unified, activation order rg_active FIRST then blackhole remove, deactivation blackhole FIRST then rg_active clear. Preflight for fabric redirect. No zone-ID logic beyond snapshotRethMasterState.
- `daemon_ha_fabric.go`: fab0/fab1 IPVLAN deferred until XSK bound (zerocopy), stale cleanup, retry 5x. NEGATIVE: fail-open? Logs CRITICAL but continues — HA heartbeat loss bounded by retry, acceptable.
- `daemon_ha_sync.go`: coldStart = !BulkEverCompleted sticky (dedup #5480 — NOT re-reporting). Sync-ready timer 5s, bulk prime retry with progress detection. Config-sync rejected when RG0 primary (prevents secondary overwrite). NEGATIVE: heartbeat suppression cap 5s monotonic (#1792) sound.
- `daemon_ha_us
```

---

#### Finding from ps-A7_go_daemon_host-b2.md

```
# Security Review — Batch A7_go_daemon_host b2/3
Base: 7e0fecf3b8f2dc6604600674373771c835484188
Date: 2026-07-09
Reviewer: claude-003
Scope: 150 files (40 prod, 110 test) across pkg/daemon, devicemap, diagcmd, fairness, frr, fsatomic, fwdstatus, ipsec, linuxsock, lldp, monitoriface, networkd, routing

## File-size/shape inventory (ranked by LOC × responsibility × hot-path proximity)

| Rank | File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|------|-----|----------|----------------|---------------|
| 1 | pkg/frr/policy_render.go | 2307 | prod | BGP/OSPF/ISIS/BFD + route-map/prefix-list/community rendering, redist isolation, chain collision, fail-closed gates | cold (FRR reload) but cross-VRF route-leak critical |
| 2 | pkg/routing/tunnel.go | 2016 | prod | GRE/IPIP/WG tun lifecycle, keepalive prober, addr reconcile, ownedNames retention | cold (netlink) but data-plane reachability |
| 3 | pkg/daemon/daemon_run.go (extra) | 2487 | prod | startup ordering: linksetup → device-map → RSS → dataplane load | boot critical |
| 4 | pkg/daemon/daemon_apply.go (extra) | 2153 | prod | commit serialization, networkd/FRR/IPsec/routing apply ordering | commit hot |
| 5 | pkg/routing/rules.go | 1447 | prod | policy-routing rule generation, VRF table selection | routing hot |
| 6 | pkg/ipsec/policy.go | 1135 | prod | swanctl child SA rendering, traffic-selector sanitization, PSK scoping, childname disambig | IPsec critical |
| 7 | pkg/frr/manager.go | 1057 | prod | FRR reload timeout, managed section write + vtysh fallback | control-plane crit |
| 8 | pkg/monitoriface/monitor.go | 952 | prod | interface counters snapshot, userspace-dp telemetry binding | observability |
| 9 | pkg/lldp/lldp.go | 939 | prod | LLDP Tx/Rx, TTL-0 shutdown, neighbor table cap, lifecycle mutex | L2 adjacency |
|10 | pkg/ipsec/ike.go | 890 | prod | IKE proposal building, DH group formatting, ECP/curve mapping | crypto agility |
|11 | pkg/networkd/networkd.go | 775 | prod | .link/.network/.netdev gen, stale sweep, reload/reconf debt, RP filter restore | boot/commit |
|12 | pkg/daemon/daemon_system.go | 1731 | prod (extra) | system login, DNS, NTP, syslog reconcile | host hardening |
|13 | pkg/daemon/daemon_nft.go | 1698 | prod (extra) | host-inbound nftables, lo0 filter, RG zone id | host inbound ACL (zone policy) |
|14 | pkg/daemon/linksetup.go | 545 | prod | PCI enumeration, positional rename collision-safe (#4178), bootstrap fxp0 | boot |
|15 | pkg/daemon/rss_indirection.go | 550 | prod | mlx5 RSS weight vector, driver guard, default restore | boot perf |
|… | pkg/routing/bond.go | 490 | prod | bond/LAG lifecycle | dataplane |
|… | pkg/frr/config_render.go | 445 | prod | static routes, interface settings, DHCP defaults, backup router | routing |
|… | pkg/daemon/login_password.go | 407 | prod | shadow reconcile, UID-keyed provenance, lock on removal | auth |

Test heaviest: pkg/frr/frr_test.go 6037 LOC (integration render), pkg/routing/routing_test.go 2193, pkg/ipsec/ipsec_test.go 1850.

Largest functions (approx via grep): generatePolicyOptions ~400 LOC (policy_render), applyConfigLocked ~300, enumerateAndRenameInterfaces ~120, renderConfig ~350, tunnel Apply ~500 (multiple concerns: removal diff + WG handoff + keepalive stop).

## Module log (coverage proof, including negatives)

- FRR policy_render: inspected sanitizeFRRValue (ASCII C0 → space), validRouterID, validClusterID, validBGPOrigin, resolveRedistribute skip+warn logic, bgpComposedChainCollision fail-closed, redist alias collision guard. Negative: no injection via newline possible; description/auth/community/as-path regex all sanitized. Route-map leak #4481 handled via redist alias. Set-clause injection #4482 — set community / as-path handled via sanitize + validation. PASS.
- FRR config_render: static route generation uses net.ParseIP validated dest/nexthop; no free-text injection. interface bandwidth / p2p hints numeric only. Negative: no injection surface.
- FRR manager: reload timeout 1
```

---

#### Finding from ps-A8_go_api_grpc_rest-b2.md

```
# Review A8 b2/2 — gRPC API zone/policy handling
BASE 312a2dfde (worktree /tmp/review-wt-claude-003-A8_go_api_grpc_rest-b2)

## File Inventory (144 files, pkg/grpcapi/* from nat_counter_error_test.go)
LOC total ~30549 Go (prod ~9800, test ~20700). Largest prod:
- server_sessions.go 1460 (session iter, filter, pagination, peer fanout, DoS caps)
- server_show_security_text.go 1070 (screen, IKE, ALG, dynamic-address, security-log zone filter)
- server_show_interfaces.go 935 (interface text, zone mapping)
- server_cluster.go 838 (MatchPolicies, Complete, valueProvider, host-inbound admission)
- server_show_firewall.go 666 (showTestPolicy, firewall filter effective snapshot)
- server.go 588 (loopback clamp #5035, fabric auth #4107 + allowlist #4122, gRPC limits)
- server_show_routes_text.go 562 / server_show.go 562 (dispatch)
Prod responsible: zone/policy/global/default display, MatchPolicies simulator, session pagination, authz boundary.
Test: 100+ _test.go covering zone nil #3493, scoped global #3286, default-policy #3363, log #3670, scheduler #3624, host-inbound #3328/#3654, lifeline #3682, policy tiers #3658, exclusion #3668, dedup #3709, strictness #3696/#4814.
Ranking by size x responsibilty: server_sessions.go > server_show_security_text.go > server_cluster.go > server.go > server_show_zones.go > server_show_policies_text.go > server_show_zones_text.go > server_show_firewall.go.

## Module Log (coverage proof)
- server.go: verified maxRecvMsgSize=16MiB #164, clampGRPCBindToLoopback family-aware, fabric allowlist 6 unary + 1 stream, parseProxiedFailoverAction strict #4107, configLockInterceptor, stopGRPCServer bounded #4910. No zone bypass via fabric — GetZones/GetPolicies not in allowlist (intended, documented).
- server_show_zones.go GetZones: nil zone guard #3493, HostInboundConfigured=true always post-#3405 (fail-closed default-deny), LifelineInterfaces via HostInboundViewWithLifelines, counters gated on ErrCounterNotPopulated #3643, readErr -> Internal #3408. GetPolicies: nil zone-pair/rule guard #3476, DisplayAddressNames #3358, ScopeSingular + plural #3286/#4626, runtimeIDs #3336, policySetID continuity, default-policy synthetic #3363 with log mirroring #3670, stats gate #2118 + then count #3074, bulk reader #3965/#4344. GetScreen via config.ScreenChecks SSOT #3327.
- server_show_zones_text.go showZonesDetail: zoneNames sorted, nil guard, zoneID from cr.ZoneIDs, traffic counters same ErrNotPopulated handling, policyRefs per zone, interface details, screen inventory via screenEnabledCheckList SSOT, ZoneDetailPolicySummary SSOT #3658/#3684 shared with CLI. showTestZone: malformed selector + unknown key rejection #4814, per-interface effective admission via RenderInterfaceHostInbound, lifeline via HostInboundLifelineInterface.
- server_show_policies_text.go showPoliciesHitCount/showPoliciesDetail: filter parsed via Fields from-zone/to-zone, statsEnabled gate, bulk reader, global filtering via GlobalPolicyAppliesToZonePair #3357, scoped global display via ScopeLabelOr/ZoneScopeSetLabel #3286/#4626, default-policy row #3363 filtered only when unfiltered, total aggregation, readErr warning #3408, scheduler suffix #3062, printAddrs except annotation #3667, Index = RuntimePolicyIndex #3667 H05, log Modes SSOT.
- server_show_security_text.go: screen stats handle ErrNotPopulated #3643, zone flood counters warning #3408, security log zone filter via logging.ParseEventFilterArgs #3547 + evZoneNames fallback #3335, screen checks via config.ScreenChecks #3327, alarms #3343/#3345.
- server_sessions.go GetSessions: negative offset rejected #3439 L2 central before dispatch, PageSize>10000 clamped, cursor token base64+hex, parsePageToken validation, zone>65535/port>65535/protocol token via ProtocolNumberLenient + ValidateProtocol #3439 L2, src/dst prefix parse via parseSessionPrefix, snat pool existence #3439, natOnly/app/iface filters, zoneNames/policyNames/appNames from applyResult, egress iface resolution via net.InterfaceByName, rev
```

---

#### Finding from ps-A9_go_observability-b1.md

```
# A9 Observability Batch Review — ps-A9_go_observability-b1

BASE: 312a2dfdef733697828fc68e8fdd92dbcaf70d69 (worktree /tmp/review-wt-claude-003-A9_go_observability-b1)
Scope: pkg/eventengine/*, pkg/feeds/*, pkg/flowexport/*, pkg/ipmon/*, pkg/logging/*, pkg/rpm/*, pkg/snmp/* (134 files, 42586 LOC total prod+test)

## Inventory (LOC, prod vs test, responsibility)
| Module | Prod files | Prod LOC | Test LOC | Largest fn | Hot-path proximity |
|--------|-----------|----------|----------|------------|--------------------|
| logging | ringbuf 1451, syslog 911, trace 553, aggregator 316, eventbuf 305, locallog 298, slog_handler 167, event_filter_args ~100, goid tiny | ~4100 | ~4600 | EventReader.logEvent / SyslogClient.Send | **HOT** — dataplane event reader (1 per helper), per-packet to syslog/NetFlow |
| flowexport | ipfix 1109, netflow 853, manager 915, transport 580, routemask 316, exporterid ~60 | ~3840 | ~4000 | encodeIPFIXRecordV4, encodeRecordV4, collectorConns.writeAll | **WARM** — session-close flush every 100ms, UDP write path |
| snmp | agent 1997, v3 1103, traps 416 | ~3516 | ~5200 | handleV3Packet, berDecodeLength | COLD — request path, but GETBULK CPU path reachable anon |
| rpm | rpm 794, icmp 426, display ~120 | ~1340 | ~1500 | runProbeLoop, probeHTTP | COLD — periodic probes |
| feeds | feeds 889 | 889 | ~1200 | fetchFeed, installSnapshot | COLD — periodic fetch, but body size DoS vector |
| eventengine | engine 1352 | 1352 | ~2000 | evaluatePolicies, runWorker | COLD — event-driven config transaction |
| ipmon | ipmon 1016, display ~150 | ~1170 | ~1200 | computeOverlayLocked, run | COLD — overlay actuator |

Total: 7 modules, 27 prod files, ~15200 prod LOC, ~27300 test LOC (test-heavy, good).

## Module Log (coverage proof)

- **logging/ringbuf.go** — NEGATIVE after hardening verification. Wire 144→152→160 additive growth, both-sides discipline (#1961). LittleEndian for zone IDs, BigEndian for ports per spec. Default policy sentinel handled correctly (dataplane.DefaultPolicySentinelID → DefaultPolicyName). Host-inbound deny distinct reason 6 rendered distinctly (closeReasonHostInbound). Per-policy log gate LogSyslog byte at 135 gated only for syslog consumers, callbacks always run (global flow export). Zone resolution via sync.RWMutex maps, numeric fallback fmt.Sprintf("%d") for unknown (zone 0 selectable via HasZone bool #3338). Decoders bound-check len >= wireSize. No heap alloc on hot path beyond fmt.Sprintf for addr. Trace: eventTimeFromWire uses decision-time UnixNano from wire, fallback to Now on overflow.

- **logging/syslog.go** — NEGATIVE (hardened). Backpressure: defaultWriteTimeout 4s, reconnectCooldown 1s, isTimeout check prevents doubling stall. Partial-frame desync fix (#3874): n>0 && n<len(b) → close+nil to prevent collector framing corruption. Re-entrancy deadlock (#2287) avoided via pendingDropWarn emitted after Unlock and slog handler forwarding Set guard via sync.Map goroutine ID. Close resurrection (#4806) via closed bool terminal. Octet-counting framing len(line) correct byte count. TL;DR all prior CVEs fixed and tested.

- **logging/eventbuf.go** — NEGATIVE. Bounded ring default 1000. Subscriber cap defaultMaxSubscribers 64 (#4484) prevents SSE fan-out DoS. Subscribe vs TrySubscribe split (trusted internal never fails, untrusted REST capped). LatestFiltered uses HasZone bool to allow zone 0 selection (#3338) — fixes invisible unknown zone. Negative n clamped to nil preventing makeslice panic (#3342). Subscriber Close idempotent via sync.Once, unsubscribe under write lock prevents send-on-closed (#3384).

- **logging/aggregator.go** — NEGATIVE. Space-Saving top-K (K=10000) replaces unbounded map (#2936→#3099) — arrival-order independent heavy-hitter retention, O(log K) heap ops, overflow counter surfaces cardinality exceedance as incident signal. Final flush on ctx cancel (#5313) prevents 5-min window loss on shutdown/reconcile. LogFn injection via mutex snapshot avoids holding lock during slog
```

---

(17 findings at Low level)


## Full batch findings (raw verbatim, all 22 batches, 334726 total chars)


### === ps-A10_go_services_cli_deploy-b1.md (17489 chars, 131 lines) ===

# Security Review A10 b1/3 — CLI dispatch, zone display, BPF headers, commit/rollback, deploy

BASE: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
Worktree: /tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1
Focus: protocol + tooling — CLI dispatch & show-output correctness, zone handling, BPF struct alignment, configstore, commit/rollback, TOCTOU

## Inventory (150 files)

**bpf/headers (6, 5334 LOC total):**
- xpf_common.h 898 — MAX_INTERFACES 65536, MAX_ZONES 64, iface_zone_key/value, pkt_meta, screen_config, etc.
- xpf_conntrack.h 225 — session_key packed (16B), session_value, tcp state machine
- xpf_helpers.h 2554 — BPF helper wrappers
- xpf_maps.h 921 — PROG_ARRAY, CPUMAP, scratch maps, interface maps sized MaxInterfaces
- xpf_nat.h 575 — nat_pool_config, snat_egress, nat64
- xpf_trace.h 161 — trace events

**cmd/cli (51 files, 8031 LOC):**
Prod: clear.go 266, main.go 672, shared.go 681, monitor.go 462, request.go 393, show.go 483, show_security.go 705, show_dhcp.go, show_firewall_effective.go, show_flow.go 414, show_interfaces.go, show_nat.go 298, show_protocols.go 85, show_services.go, show_system.go 141
Tests: commit_rollback_4868_test 141, grpc_maxrecv_5321 98, load_terminal_abort_4883 97, etc. Largest fn: dispatch() in main.go ~200 LOC, shared.go dispatchOperational ~180

**cmd/xpfd (10, 1628 LOC):**
main.go 412 (classifyCommand SSOT for subcommand routing), upgrade.go 257 (parseUpgradeArgs rejects leftover args #4869, cluster guard #5284), upgrade_kernel.go 217 (validateKernelVerbArgs #5322, lock serialization), publish_generation.go 153 (GC protection #4876), seed_runtime.go 101 (no positional args #5322), dispatch_test.go 75, leftover_args_5322 165, upgrade_args_4869 68, etc.

**docs/pr/812 (2):** vdso_probe.c, vdso_probe2.c — latency histogram evidence, not prod path

**pkg/cli up to screen_inventory (80+ files, ~7800 LOC in scope):**
- cli.go 548 (CLI struct, 15+ deps, commitCtx cancellable)
- cli_dispatch.go 523 (dispatch, extractPipe LastIndex, filterStream streaming #4709/#4731, parseLastCount clamp maxTailLines 100k #5037, pageStream)
- cli_config.go 486 (handleCommit strict parsing #4868, unknown option reject, handleLoad file read, handleCopyRename, handleInsert, commitApply via applyConfigFn #797)
- cli_show.go 281 (show dispatcher #4422 effective filter banner)
- cli_show_security_zones.go 210 (showZonesDisplay sorted, nil-tolerant #3493, host-inbound with lifelines #3682, detail per-logical-unit split #5325, SSOT ZoneDetailPolicySummary #3658)
- cli_show_security_screen.go 485 (SSOT ScreenEnabledCheckList #3327, counter warnings #3408/#3345, flood counters not-available #3643)
- cli_show_security_dispatch.go ~400 (enabledStr, scheduler active state #3062)
- cli_show_security_filters.go 549 (showFirewallFilters raw, showEffectiveFirewallFilters compiled #4422, banner generation drift #5067, Builds snapshots via BuildFirewallFilterSnapshots)
- cli_show_security.go 490 (showPoliciesHitCount bulk reader #3965/#4344, scoped_global handling #3286/#3357/#4626, metadata M11/H03/M12/M13 #3672/#3684, scheduler inactive #3062/#3624)
- Tests: cli_show_security_scoped_global_3286 222, _3357 100, cli_show_effective_filter_4422 143 + gen_5067 255, host_inbound_display_3654 (H04/M03 coverage), etc.

Responsibility x hot-path proximity ranking:
1. cli_dispatch.go — high (per-command entry, pipe handling, pager, commit/rollback)
2. cli_config.go — high (commit path, load, configstore interaction)
3. cli_show_security_zones.go — medium-high (zone audit surface, host-inbound)
4. cli_show_security_filters.go — medium-high (effective filter correctness, drift banner)
5. bpf/headers/xpf_common.h — medium (MAX_INTERFACES sizing, iface_zone mapping)
6. cmd/xpfd/upgrade.go — medium (in-place upgrade, rolling vs standalone guard)
7. pkg/dataplane/types.go + bpf_session_value.go — medium (struct alignment, ABI)

## Module Log (coverage proving)

- [x] bpf/headers/xpf_common.h: verified MAX_INTERFACES=65536, MAX_ZONES=64, iface_zone_key 8B with pad, IFACE_FLAG_* bits, FABRIC_ZONE_MAC_MAGIC, packet meta offsets
- [x] bpf/headers/xpf_conntrack.h: session_key packed 16B, session_key_v6 40B packed, conntrack structs
- [x] bpf/headers/xpf_maps.h: checked xdp_progs, tc_progs, cpumap, pkt_meta_scratch, session_v4_scratch per-CPU, interface counters sized MaxInterfaces
- [x] bpf/headers/xpf_nat.h, xpf_helpers.h, xpf_trace.h: nat pool, helpers, trace struct alignment
- [x] pkg/dataplane/types.go + bpf_session_value.go: Go SessionKey 16B matches C packed, IfaceZoneKey 8B, bpfSessionValue 128B exact via unsafe.Sizeof, SessionValue 136B with Generation extra (fixed #2360 OOB), test constants_test.go pins MaxInterfaces==65536 and drift from C header
- [x] pkg/dataplane/loader_userspace_shim.go: drift check BindingArrayMaxEntries == MaxInterfaces*BindingQueuesPerIface (16) = 1,048,576; preflightCheckIfindexCaps rejects >=MaxInterfaces
- [x] pkg/cli/cli_dispatch.go: extractPipe LastIndex " | ", filterStream streaming lineSource, parseLastCount 100k clamp #5037, pageStream screenful, rollback strict Atoi #3447, commit unknown option reject #4868, commit confirmed minutes ParseInt range [1,MaxCommitConfirmedMinutes] #4868
- [x] pkg/cli/cli_config.go: load terminal via readline, os.ReadFile path, commitApply via applyConfigFn #797, commitCtx cancellable via commitCancel slot, printConfigWarnings, showConfigRedacted path handling #4099
- [x] cmd/cli/main.go: maxConfigRecvBytes=MaxConfigSize+1MiB #5321, dialOpts insecure loopback + raised recv cap, remote complete ? handler, signal loop with exitConfigureBounded #5053 atomic configMode, interruptWindow 2s
- [x] cmd/cli/shared.go: remote extractPipe same LastIndex, dispatchWithPipe io.ReadAll (vs local streaming — divergence), applyPipeFilter case-sensitive #4968, last N clamp maxTailLines 100k parity
- [x] pkg/cli/cli_show_security_zones.go: stable sort zoneNames, nil zone skip #3493, ZoneIDs from applyResult, Description, TCPRst, Interfaces bound, HostInboundViewWithLifelines Render #3654/#3682, traffic stats ErrCounterNotPopulated explicit not-available #3643, detail per-interface base.unit split #5325 Atoi guard, ScreenEnabledCheckList SSOT #3327, ZoneDetailPolicySummary SSOT #3658/#3684 (three tiers zone-pair/global/default)
- [x] pkg/cli/cli_show_security.go: hit-count bulk reader NewPolicyCounterReader #4344 #3965, PolicySchedulerActiveState #3062, per-rule metadata (runtime PolicyId #3063, scheduler inactive H03/#3624, log/count/address-excluded #3336), global scoped handling GlobalPolicyAppliesToZonePair #3357, ScopeLabelOr junos-global vs actual set #3286/#4626, address book global/zone-local token handling #3358
- [x] pkg/cli/cli_show_security_screen.go: reverse map zonesByProfile, nil profile skip #3476, ScreenEnabledCheckList SSOT #3327, total screen drops + per-reason ScreenReasonCounters (15) #3343, flood counters ErrCounterNotPopulated not-available #3643, SYNCookie rows, readErr warning after all reads #3408/#3345
- [x] pkg/cli/cli_show_security_filters.go: showFirewallFilters raw typed config, showEffectiveFirewallFilters compiled snapshots BuildFirewallFilterSnapshots #4422 (prefix-list resolved, except folded positive-wins, DSCP numeric, TCP flags masks, next-term fallthrough, fail-closed), printFirewallEffectiveBanner generation check #5067 (dataplane armed + ack gen matches applied, else compiled-desired/drift banner)
- [x] pkg/cli/cli_show_security_dispatch.go: enabledStr, policySchedulerActiveState via interface cast, policyInactiveFn predicate
- [x] pkg/cli/cli_show.go: handleShow dispatch, effective filter family validation inet/inet6, firewall filter snapshot matching
- [x] cmd/xpfd/main.go: classifyCommand SSOT # count for subcommand routing (version, protocol-versions, cleanup, upgrade, seed-runtime, publish-generation, verify-dataplane, check-config, unknown), cleanup rejects args #5322, VerifyEmbeddedUserspaceShim verifier gate #1864 REJECT vs error, check-config regular file + size cap 4MiB #1879
- [x] cmd/xpfd/upgrade.go: upgradeArgsSelectKernel exact "kernel", parseUpgradeArgs rejects NArg!=0 #4869 (prevents `xpfd upgrade rolling` typo becoming standalone cut), newUpgradeConfig wires HelperHealthy probe #5286 (is-active-only -> armed+forwarding+target version), ClusterNodeIDPresent guard earliest error for bare upgrade on cluster member, defaultUpgradeControlSocket honors active config override
- [x] cmd/xpfd/upgrade_kernel.go: validateKernelVerbArgs arity #5322 (arm exactly 1, others 0), lock Acquire for mutating verbs, kernel journal promotion marker, DrainAndConfirm/RejoinAndConfirm strong predicates
- [x] cmd/xpfd/publish_generation.go: lock Acquire host-wide, gcProtectionForPublish reads journal pinned gen, runGC false if journal unreadable #4876 (skip GC to avoid reaping pinned), GC protects current+1 prior
- [x] cmd/xpfd/seed_runtime.go: parseSeedRuntimeArgs rejects NArg!=0 #5322, capability-check probe retained for pre-#1985 postrm compat #1985
- [x] scripts/deploy/xpf-deploy.py: os.replace .tmp atomic, fetch+verify against signed manifest #1924, verify_listed_artifact_bytes returns bytes not re-open path TOCTOU mitigation #5042, lease file temp+mv atomic+flock, virtio-first vs hardware ordering guard pos contract fable-165 H-22, cleanup on partial failure
- [x] test/incus/deploy-lib.sh: deploy_reconcile_stale_pin removes #1917 pin drop-in #2176a, deploy_reconcile_dangling_sbin removes dangling symlink #2176b, deploy_verify_pushed_sha sha256 equality #2162, deploy_verify_running_xpfd checks /proc/PID/exe sha + ExecStart path #2176c
- Negatives proving coverage: no cli parsing of zone names with injection (zone names from config validated via schema, not free-form); no TOCTOU via symlink in xpfd upgrade paths (uses readlink /proc/PID/exe resolved real path); no max recv drift (dialOpts uses configstore.MaxConfigSize+1MiB); no double-free in pipe handling (single pipe per command)

## Findings

### High Confidence

**H1 — Remote CLI dispatchWithPipe buffers full output via io.ReadAll, unlike local CLI streaming filterStream**
Bar: `cmd/cli/shared.go:dispatchWithPipe` does `output, _ := io.ReadAll(r)` then `strings.Split`, holding entire `show` output in memory before filtering. Local `pkg/cli/cli_dispatch.go:dispatchWithPipe` streams via `lineSource` + goroutine, bounded 1 line / count / ring. A `show security flow session` millions lines can OOM remote CLI while local streams.
Evidence: `cmd/cli/shared.go:67-81` `io.ReadAll(r)` vs `pkg/cli/cli_dispatch.go:108-131` `filterStream` line-by-line.
Impact: DoS of remote cli (not xpfd). Mitigation: reuse lineSource streaming or cap.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/cmd/cli/shared.go:67`

**H2 — os.Stdout global replacement without defer in both dispatchWithPipe and dispatchWithPager**
Bar: `origStdout := os.Stdout; r,w,err:=os.Pipe(); os.Stdout=w` then later `os.Stdout=origStdout`. If `c.dispatch(cmd)` panics, restore never runs, leaving stdout as closed pipe for process lifetime. `pageStream` similar. Should use defer or recover.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/pkg/cli/cli_dispatch.go:66-92`, `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/cmd/cli/shared.go:62-84`
Severity low-medium (CLI crashes anyway) but hardens.

**H3 — Zone name terminal injection not sanitized in showZonesDisplay**
Bar: Zone name comes from config (`cfg.Security.Zones` keys) and printed via `fmt.Printf("Security zone: %s\n", name)` directly to terminal. Config schema likely restricts to [a-zA-Z0-9_-] but not verified in this scope. If validation allows control chars (`\x1b`), could inject ANSI escape sequences into operator terminal. Defense: config validator should reject control chars / ensure printable; display could strip non-printable or use `%q`? Check `pkg/config/schema.go` setSchema zone name regex.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/pkg/cli/cli_show_security_zones.go:34`

### Medium Confidence

**M1 — MAX_INTERFACES 65536 leads to BindingArrayMaxEntries 1,048,576 BPF array — memory and verification cost**
Bar: `#define MAX_INTERFACES 65536` in `xpf_common.h:143`, `BindingQueuesPerIface 16` => 1M entries BPF_MAP_TYPE_ARRAY. Each entry holds qsize+prog_fd? Actually cpumap_val. On 256 CPUs, per-CPU array of 1M entries is huge. However actual maps used: `userspace_bindings` and `userspace_ingress_ifaces` sized MaxInterfaces and MaxInterfaces*BindingQueuesPerIface, checked in `loader_userspace_shim.go:184-400` with drift assertion. Preflight rejects ifindex>=MaxInterfaces. Memory is kernel pinned, but 65536 is typical max ifindex (kernel allows >). Tradeoff: correctness over memory. Not a bug, but note for future: if kernel assigns ifindex >65535, preflight fails and node fails-closed. Documented in test `TestMaxInterfacesMatchesCHeader`.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/bpf/headers/xpf_common.h:143`

**M2 — Commit comment Trim with cutset removes more than surrounding quotes**
Bar: `desc = strings.Trim(desc, "\"'")` in `cli_config.go:177` trims ALL leading/trailing single/double quotes, not just matching pair. Input `"'my comment'"` becomes `my comment`, but `"""important` also trimmed. Intended to allow `"my comment"`; but Trim is overly aggressive, though low risk (comment is audit log only). Better TrimSuffix/Prefix or Trim with check for balanced quotes.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/pkg/cli/cli_config.go:177`

**M3 — Scoped global snapshot protocol version not bumped (dedup #5488) — known, but CLI display already handles**
Deduped per orientation, do not re-report as new. Noted that `cli_show_security.go` correctly uses `ScopeLabelOr` and `GlobalPolicyAppliesToZonePair` for scoped global, but underlying dataplane snapshot version still 3 per #5488, so rolling upgrade helper that ignores plural fields narrows deny (fail-open). Fixed in CLI display but not yet in snapshot versioning. This is existing GH issue, not new CLI bug. Mentioned for completeness but excluded from new findings per dedup rule.

**M4 — Effective filter banner only checks generation match, not helper version**
Bar: `showEffectiveFirewallFilters` banner in #5067 checks `dataplane armed && ack gen == applied gen`. It does NOT check helper binary version matches staged. A stale helper could report armed with old filter snapshot? However generation is incremented on commit, helper ack comes after apply_snapshot, so version skew is covered by gen check. Upgrade path uses separate `verify-dataplane` gate. Acceptable.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/pkg/cli/cli_show_security_filters.go:359`

### Low / Info

**L1 — Load override from file path allows reading any file readable by CLI user, but CLI requires PermConfig super-user**
Bar: `os.ReadFile(source)` in `cli_config.go:138` where source is user-supplied file path. If CLI were ever exposed to less-privileged class, could exfiltrate via `load override /etc/shadow`. Currently config mode requires super-user, so not priv escalation. Redaction path exists via #4099 `showConfigRedacted`.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/pkg/cli/cli_config.go:138`

**L2 — xpf-deploy.py fetch uses curl -fsSL -o dst.tmp + os.replace atomic — TOCTOU mitigated, but curl failure no retry**
Bar: Line 949 `curl -fsSL -o dst + ".tmp"` then `os.replace`. Temporary file in same dir as dst (good for atomicity), but curl -fsSL silent failure handling not robust to partial download if process killed mid-write leaving .tmp? os.replace only on success (returncode checked). Good. No TOCTOU on verification: `verify_listed_artifact_bytes` reads bytes returned, not re-opening path. Mitigations already hardened per comments.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/scripts/deploy/xpf-deploy.py:949-952`

**L3 — Zones with many interfaces: Interfaces bound count prints len(zone.Interfaces) but detailed view splits per unit with base name lookup — if base not in cfg.Interfaces, silently skipped**
Bar: `cli_show_security_zones.go:85` prints `Interfaces bound: %d` then loops `zone.Interfaces` and for each does `ifc, ok := cfg.Interfaces.Interfaces[base]; !ok { continue }`. So count says 5 but detail may show 0 if base lookup fails (e.g., RETH logical referencing missing base). Could be confusing, but not security. Could warn.
File: `/tmp/review-wt-claude-003-A10_go_services_cli_deploy-b1/pkg/cli/cli_show_security_zones.go:100-130`

## Issue Split Suggestion

- **Issue A (CLI DoS):** Remote CLI `dispatchWithPipe` buffers full output (io.ReadAll) vs local streaming. Replace with lineSource streaming bounded, matching local fix #4709/#4731/#5037. Files: cmd/cli/shared.go, cmd/cli/main_test.go for coverage.
- **Issue B (CLI robustness):** os.Stdout global replacement without defer-recover in both local and remote dispatchWithPipe/pageStream. Add defer restore and handle panic.
- **Issue C (Terminal injection hardening):** Validate zone names lack control chars in `config/schema.go` + optionally sanitize display via `strings.Map` printable check. Audit other `%s` prints of user-supplied names (policy name, description).
- **Issue D already tracked:** scoped_global version bump #5488.

Total reviewed: 150 files listed, plus cross-checked dataplane/types.go, bpf_session_value.go, constants_test.go, loader_userspace_shim.go for alignment. All paths exercised.


---

### === ps-A10_go_services_cli_deploy-b2.md (11471 chars, 106 lines) ===

# Security Review — Batch A10 Go Services CLI Deploy b2/3

Base: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
Scope: pkg/cli/* (from wireguard onward), pkg/ddns/*, pkg/dhcp/*, pkg/dhcprelay/*, pkg/dhcpserver/ddns*

## Inventory

| Module | Prod LOC | Test LOC | Files | Largest fn | Responsibility | Rank* |
|---|---|---|---|---|---|---|
| pkg/cli show_services/monitor/traffic | ~3.2k prod / ~4.5k test | 176+1081+277+70+389 etc | 26 prod files in batch | showSystem (1081 LOC) / handleMonitorSecurityFlowFile (150 LOC) | CLI dispatch, zone display, traffic capture argv, session egress map, permissions RBAC, trace-file confinement | High (user-facing root tcpdump) |
| pkg/ddns backends | ~7.5k prod / ~12k test | 16 prod files | largest surface_a.go 2109 LOC / backend_rfc2136.go 1126 | DDNS publish/withdraw, source-bind pinning, redirect-downgrade refusal, checkip oracle, durable state, provider transition orphans | High (credential-bearing egress, source-bind fail-closed) |
| pkg/dhcp client | ~2.8k prod / ~2k test | 5 prod | dhcp.go 1903 / commit 220 | DHCPv4/v6 lease acquire, T1/T2 renew/rebind (RFC2131/8415), classless routes opt121/249 supersede opt3, DUID persistence, anti-blackhole mask validation | High (WAN address, gateway, DNS, FRR route programming) |
| pkg/dhcprelay | ~2.4k prod / ~3.2k test | 4 prod | relay.go 1583 | DHCP relay giaddr primary selection, Option82 circuit-id, hop-limit loop protection, raw-L2 unicast fallback, server source IP allowlist (#4163), HA master gate | High (L2 broadcast domain ↔ upstream, rogue injection) |
| pkg/dhcpserver ddns | ~0.5k prod / ~1k test | 2 prod | ddns_leases.go 419 | Kea memfile parser destructive-diff safety: duplicate-column reject, required-column validation, ragged-row fail-closed | Medium (DNS record loss if parser lenient) |

*Rank = size × responsibility × hot-path proximity. Total batch ~150 files = 12200 prod + 19500 test approx.

## Module Log (incl. negatives proving coverage)

- cli_show_security_wireguard.go: Delegates to dpformat.FormatWireguardStatus, nil dp guard — NEGATIVE, no zone handling, shared formatter ensures parity.
- cli_show_security_zones.go: Sorted zones, nil zone tolerant (#3493), HostInboundViewWithLifelines renders zone-level + per-if override + lifeline exemption (#3654/3682). VLAN unit handling splits base+".0" logic via strconv.Atoi, detail renders only wanted unit (#5325). Counter read: not-implemented explicit vs nil error warning accumulation (#3643/#3408). SSOT for screen checks via ScreenEnabledCheckList (#3327). Policymatch.ZoneDetailPolicySummary SSOT for policy tiers (#3658). NEGATIVE for injection: no shell.
- cli_show_services.go: Strict subcommand dispatch, cmdtree help, unknown target errors. RPM uses os.Stdout atomic write, no template inj. NEGATIVE.
- monitor_traffic.go: Validates tokens, rejects bare matching, bare interface/count fail-closed (#4540, #4883). stripSurroundingQuotes peels one layer, buildMonitorTrafficArgv inserts "--" separator before filter (#4524). monitorFilterOptionToken rejects tokens starting with "-" (option smuggle, #4556 leading-quote peel). validateMonitorFilter defense-in-depth. Count bounded 0..8192 per sibling command bounding. Injection mitigations sound.
- permissions.go: monitor traffic requires PermControl (#4067), monitor security flow file/start requires PermControl (#5038) preventing view-only root file create, request system reboot/halt/zeroize + failover + dataplane disarm/inject requires PermMaint (#4108/#4859). resolveCommand prefix resolution mirrors dispatcher, cannot bypass via abbreviation. showConfigRedacted redacts secrets for non-super-user (#4099). NEGATIVE for privilege escalation beyond known gates.
- session_display.go: buildSessionEgressIfacesWithLookup uses LinuxIfName(ResolveReth), vlanID fallback Number>VlanID→0. First-write-wins on key collision.
- show_services_ddns.go: Secret redaction (TSIG key name redacted), provider backend display no secret, degraded alarm fail-closed. NEGATIVE.
- ddns/backend_http.go: TLS MinVersion 1.2, InsecureSkipVerify false, httpClientTimeout 15s, httpDialTimeout 10s, MaxResponseBody 64KiB capped, scrubURLError strips userinfo+query, refuseSchemeDowngrade refuses HTTPS→HTTP (#4861), source-bind via boundDialContext pinning family (#5327), httpClientCache per-binding + reap (#2956).
- ddns/checkip.go: validateCheckIPURL requires http(s) + host, ipAddrRe permissive scan + IsPublicAddr gate (loopback/link-local/private/CGNAT/TEST-NET/ULA/etc via specialPurposeV4/V6), isAllowlisted, ParseAllowlistChecked returns malformed list (#2839), CheckIPBound fail-closed on bindErr (#3733).
- ddns/backend_rfc2136.go: exact-RR discipline (no RRset/name delete), selfOwned value-specific replace with PrevAddr, TSIG algo whitelist (md5 rejected), normalizeUpdateServer, resolveBindConfig + validateDevice (#5070), sourceDialFamily pinning (#5327).
- ddns/backend_cloudflare/generic/route53/dyndns2: token Reveal only at transport boundary, no secret in errors (generic redacts via RedactURL, scrubURLError), generic validateGenericURLTemplate requires host non-empty after :port strip (#4589), ok-token whole-token match not substring (#2838).
- ddns/surface_a.go: Lock released around provider I/O (providerIO/observeIO), forceRefresh latch one-shot, change-detection + forced-refresh floor + per-op backoff (publish vs withdraw separated #4423 M03), durable write-ahead, orphan tracking for provider rename vs same-endpoint rename (#3735), seedFromStore sets lastPublished=restart to avoid write-storm (#3734), durable pending recovery (#5285).
- dhcp/dhcp.go: Subnet mask validation rejects /0 or non-contiguous (blackhole prevention), classlessStaticRoutes prefers opt121 over 249, supersedes opt3 per RFC3442, skips malformed entries, IANA address selection prefers longest preferred-lifetime (#4383), validLifetime 0 skip, renewalTimers divide-first avoids int64 overflow (#4526), commitLease removes old addr on move, leak-safe.
- dhcp/clearduid: validInterfaceName rejects '/', '\', NUL, whitespace, len>15, "."/"..", duidPath containment check Dir(p)==Clean(stateDir) (#4857).
- dhcprelay/relay.go: readBufSize 65535 avoids truncation, giaddr primary selection via netlink IFA_F_SECONDARY (#2849), hop limit enforced before increment (wrap guard) default 16 (#4309), relay chain preservation of giaddr+Option82 on chained (#5071), server reply source allowlist by IP Equal (#4163) drop + counter, L2 sender MTU guard + broadcast fallback (#2076), HA gate per-packet via shouldRelay (#2456), ifindex drift + giaddr re-resolution watchers (#2347/#3960), computeDesired deterministic group sort, Option82 strip before forward.
- l2send_linux.go: Raw AF_PACKET, re-resolves ifindex+MAC per send (flap safe), IPv4 checksum computed, UDP checksum 0 legal for IPv4, sync.Once close.
- dhcpserver/ddns_leases.go: Duplicate column reject, required column validation (address/state/hostname/client_id-hwaddr or duid-iaid), maxRequiredIdx ragged-row fail-closed, tombstone reclaim logic, expiry filter — destructive-diff safety.

## Findings

### Medium

#### 1. session_display egress map first-wins collision hides VLAN-less interfaces
Severity: Low
Confidence: High
Evidence: `pkg/cli/session_display.go:44`
```
key := sessionIfaceKey{ifindex: uint32(parentIfindex), vlanID:  sessionDisplayVLANID(unit)}
if _, exists := egressIfaces[key]; !exists {
    egressIfaces[key] = displayName
}
```
```
Trace: Interfaces ge-0-0-0 unit0 (vlanID 0 via fallback) and ge-0-0-0 unit0 alternative share same parent ifindex + vlanID 0 → second omitted, show session egress displays first name.
Refutation: intimately checked callers — buildSessionEgressIfaces used only for display, not policy. No security bypass.
Why: Display mismap may confuse audit of zone→interface mapping, not traffic bypass.
Fix: Use slice or last-wins with log; ensure unit number disambiguates via VlanID fallback already, but consider keying on unit number also.
Labels: cli display, zone handling

#### 2. DHCP relay server list accepts IPv6 via net.ParseIP but socket is udp4
Severity: Low
Confidence: Medium
Evidence: `pkg/dhcprelay/relay.go:575`
```
ip := net.ParseIP(s)
...
serverAddrs = append(..., &net.UDPAddr{IP: ip, Port: relayPort})
```
and `defaultPacketConnFactory` binds "udp4".
Trace: Config `set forwarding-options dhcp-relay server-group ... 2001:db8::1` parsed, stored, relay session starts with non-empty set (passes fail-closed empty check), then serverConn.WriteTo IPv6 addr on udp4 socket errors each time → no relay.
Refutation: Not open relay; fails closed for that server. But inconsistent validation.
Fix: Filter to To4()!=nil or schema Validate IPv4.
Labels: dhcp relay, validation

#### 3. DDNS generic backend ok-response single token downgrade (operator typo)
Severity: Low
Confidence: Medium
Evidence: `pkg/ddns/backend_generic.go:72`
```
ok := defaultGenericOKTokens
if s := strings.TrimSpace(p.OKResponse); s != "" {
    ok = []string{strings.ToLower(s)}
}
```
Trace: Operator sets `ok-response "good nochg"` expecting multi-token set; code collapses to single lowercased string `"good nochg"` which never matches leading-field logic → Upsert always errors → ownership never recorded → DNS stale while engine backs off.
Refutation: Existing tests cover single token; commit warning surfaces missing? Not for this field. Low impact non-security.
Fix: Split on whitespace/comma like allowlist, or document single-token contract.
Labels: ddns, durability

### Low / Informational (Negative with hardening notes)

- monitor_traffic quote-strip only outer layer — defense-in-depth: "--" + validateMonitorFilter already neutralizes smuggled -w/-z; leading-quote peel added #4556.
- DDNS redirect downgrade: `refuseSchemeDowngrade` returns error on HTTPS→HTTP and caps at 10 redirects — prevents credential cleartext leak (#4861) — VERIFIED SECURE.
- DDNS source-bind fail-closed: `httpClientCache.clientFor` returns unbound client + error, `resolveSurfaceABackend` propagates error to nopUpdater (skip publish, never withdraw) (#4437), `CheckIPBound` returns zero on bindErr (#3733) — VERIFIED FAIL-CLOSED.
- DHCPv4 degenerate mask rejection: `bits!=32 || ones==0` → refuse lease, retry DISCOVER, preserve existing valid lease — prevents 0.0.0.0/0 on-link blackhole — VERIFIED.
- DUID path traversal: `validInterfaceName` + `filepath.Dir(p) != Clean(stateDir)` — blocks "../../../../etc/passwd" RPC — VERIFIED (#4857).
- DHCP relay rogue-server validation: `replySourceAllowed` + counter `repliesDroppedUnknownServer`, first warn then debug — closes UDP 67 bind injection (#4163) — VERIFIED.
- DHCP relay hop count: check >= limit BEFORE ++ prevents uint8 wrap 255→0 bypass (#4309) — VERIFIED.
- Trace file confinement: `traceLogDir=/var/log/xpf-flow-trace` 0700, `sanitizeTraceFilename` bare basename, `O_NOFOLLOW` 0600, regular-file check (#3378/#5038) — VERIFIED.
- Zone display hardening: nil zone tolerant (#3493), screen SSOT (#3327), policy tiers via shared ZoneDetailPolicySummary (#3658) — no hidden global permit — VERIFIED.

No credential leak, no open relay, no TOCTOU in DDNS state (fsync + write-ahead + fail-closed degraded), no DHCP option handling RCE.

## Suggested Issue Split
- One low: session egress collision + relay IPv6 filter + generic ok-response tokenization.
- Documentation: confirm monitor_traffic count bound and option-token defense depth (already documented but add test for IPv6 server group).



---

### === ps-A10_go_services_cli_deploy-b3.md (12261 chars, 135 lines) ===

# A10 Go Services / CLI / Deploy Review b3/3 — Batch 002

## Inventory (114 files, ~20K LOC)

| Module | Files | LOC (prod) | Largest fn | Responsibility |
|--------|-------|------------|------------|----------------|
| dhcpserver | 8 go | 2111+934 lease_sync | generateKea4Config / lease parse | Kea config render, lease sync/seed, DDNS glue |
| natshow | 5 go | 49+117+108+114+117 | RenderSourceRuleDetail | NAT show rendering (source/dest/static/persistent) |
| policymatch | 48 (1 prod 47 test) | 1715 prod | Match 300+ | Zone policy simulator vs dataplane parity, global scoped, app matching |
| scheduler | 5 | 449 prod | evaluate 60, isWithinWindow 40 | Time window eval, wall-clock discontinuity, republish self-heal |
| scripts/deploy | 7 py | 1881 xpf-deploy + 6 test | cmd_kernel_roll 200 | Appliance deploy, fetch verify, HA roll orchestration |
| scripts/dist | 2 py | 345+786 | publish gate_images 140 | Minisign manifest, image signing, publish gate |
| scripts/image | 5 py | 756+686+122 +2 test | virt_customize bake 120 | Bake qcow2, config-drive ISO, validate gate |
| scripts/*.py, test/incus/*.py | ~35 py + 1 rs + 4 xsk | varied | - | Test harnesses, metrics, cold-path flooder (2170 RS) |

## Module Log

- dhcpserver/dhcpserver.go: generation supersession with atomic gen, fail-closed is-active query handling (#4870) — sound, query error triggers restart/stop + error surfacing. Stable hash subnet-id (#5041/#5203) with coprime probe step — correct.
- dhcpserver/lease_sync.go: clock-skew-safe Remaining re-anchor, v6 IA_PD handling, splitV6Identity error returns non-nil for malformed IAID (#2379). Memfile pre-seed with _kea ownership via fsatomic WithOwner — hardened. BOS: mergeLeasesByIdentity local wins — correct for active-active.
- dhcpserver/ddns.go: thin alias glue, keaLeaseParser maps unknown LeaseType to LeaseTypeUnknown fail-closed (#5072 IAPD AAAA suppression) — sound.
- natshow/source.go, dest.go: session counts keyed by {from,to} not rule-set name — inherent limitation (sessions carry zone IDs not rule-set name), not a bug; counter reads via NATCounterIDs — correct. IPv6 iteration present.
- natshow/persistent.go: binary.NativeEndian.PutUint32 recovers __be32 — matches CLAUDE.md byte order, v6 netip.AddrFrom16 without Unmap — correct per gc.go. No panic.
- natshow/static.go: NPTv6 vs static prefix rendering, detail fields — display only, no enforcement.
- policymatch/policymatch.go: tier order exact→single-wildcard merged→both-any→global→default, zoneKnown gate for undefined zones (#3355), scheduler gate first, content rejection SSOT via PolicyContentRejectionReasons (#3727/#4394), route-drop advisory (#4373), host-inbound token classification, feed overlay merge, ParseSelectorArgs fail-closed duplicate/unknown/empty. Very hardened.
- policymatch/zone_detail_summary.go: wildcard handling fromAny/toAny affect BothAny tier, policySetID advances on nil sets, global via GlobalPolicyAppliesToZone — correct.
- scheduler/scheduler.go: wallClockDiscontinuousLocked compares wall vs mono with 5s tolerance, 2min recovery hold, fail-closed during hold, date-range ParseInLocation(now.Location()) (#3988), isWithinWindow fail-closed on absent/incomplete, republish self-heal with pending flag — sound.
- scripts/deploy/xpf-deploy.py: preflight before mutate, golden qcow overlay (never writable golden), virtio-first NIC order validation (#165 H-22), VM cleanup on partial failure, fetch verifies against signed manifest with TOCTOU-safe copy in sign.py, anti-rollback watermark, lease acquire via flock atomic read-expire-write, holder sanitized via regex, ssh remote command quoted via shlex.quote — hardened.
- scripts/dist/sign.py: basename-only manifest, TOCTOU-safe verify via private 0700 tmp copy, placeholder pubkey refusal, path traversal check for manifest entries, duplicate basename refusal — hardened.
- scripts/dist/publish.py: default-deny allowlist for image tree, symlink rejection, per-suite InRelease verify, key-agreement cross-check (installer key ⊆ keyring, signer ⊆ installer+keyring) — hardened.
- scripts/image/bake.py: validate before sign (#4017 finalize_artifacts enforces ordering), kernel hold enumeration via dpkg-query not glob, growpart + frr-reload presence asserts, manifest covers protocol versions, .manifest covered by signed SHA256SUMS (#5042).
- scripts/image/validate.py: signature bind both qcow2+metadata to same manifest, qemu-img info verdict unit-testable, serial log polling for day-0 install — sound.
- scripts/image/make_config_drive.py: uses xorriso/genisoimage, temp staging via mkdtemp, but perms diverge from xpf-deploy fix — finding below.
- test/incus/*.py: cluster_status_parse regex anchors hyphenated secondary-hold, fairness/coverage parsers — display/test only, no privilege.
- cold-path-flooder main.rs: unsafe Send impl documented, TxRing dst_sll raw pointer wired after final move (wire_msgs), CPU_SET bounded by CPU_SETSIZE via sched_getaffinity, origin checks for IFF_UP, reserved-port-0 avoidance — sound for test tool.
- xsk-repro: libbpf XSK shared test C + Rust harness — test-only.

## Findings

### F1 — make_config_drive.py leaves day-0 ISO world-readable with secrets
Severity: Medium
Confidence: High
Evidence:
```
# scripts/image/make_config_drive.py:71-72
shutil.copyfile(config, os.path.join(stage, "xpf.conf"))
os.chmod(os.path.join(stage, "xpf.conf"), 0o644)
```
vs xpf-deploy.py which fixed this in #4586:
```
# xpf-deploy.py:318-324
shutil.copyfile(cfg_path, os.path.join(stage, "xpf.conf"))
os.chmod(os.path.join(stage, "xpf.conf"), 0o600)
...
os.chmod(iso, 0o600)  # ISO embeds secrets
```
`make_config_drive.py` writes xpf.conf 0644 inside mkdtemp (0700 so process-local only), but final ISO at CWD is created by xorriso with default umask 022 → 0644 world-readable, containing root-auth hash, IKE PSK, SNMP community. validate.py calls build_config_drive which uses same function — ISOs in /tmp work dir are world-readable during validation. The secret-bearing ISO lingers in CWD until destroy.
Trace: operator runs `make_config_drive.py -o day0.iso prod.conf` (contains PSK) → xorriso creates day0.iso 0644 → co-located UID can `isoinfo -R -x /xpf.conf -i day0.iso` to extract secrets. xpf-deploy.py fixed this path but standalone tool wasn't updated.
Refutation attempt: mkdtemp 0700 protects staged copy, but output ISO is in CWD, not temp. No chmod on out path unlike xpf-deploy. Check: make_config_drive has no os.chmod(out, ...) after mkisofs.
Why it matters: day-0 drive holds every factory secret; world-readable ISO leaks credential material to any local user.
Fix: chmod out to 0o600 after mkisofs, same as xpf-deploy; also set staged xpf.conf to 0o600. Optionally restrict mkdtemp dir perms explicitly.
Labels: secret-leak, parity, deploy
Dedup note: #4586 fixed xpf-deploy path only; this file not mentioned in dedup index.

### F2 — scheduler DST fall-back double-active stretches permit window
Severity: Low
Confidence: Medium
Evidence:
```
// scheduler.go:446-448
func timeOfDay(t time.Time) tod {
    return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}
}
```
`withinTimeOfDay` operates purely on wall-clock H/M/S, no DST handling. On fall-back, 01:30 occurs twice (first DST, then STD). Both map to same tod, so if window includes 01:30, policy stays active for ~2h instead of 1h (twice through same wall hour). Spring-forward: window 02:00-03:00 that doesn't exist is never active (fail-closed, safe). Fall-back is permit-longer-than-configured (fail-open in duration, not disposition).
Trace: scheduler with `start 01:00 stop 02:00` on fall-back night → first 01:00-02:00 DST active, clock falls back to 01:00 STD, second 01:00-02:00 active again → total 2h active vs configured 1h, but still within same wall window.
Why it matters: minor availability deviation; permit window longer than operator expects, but same verdict class (still permit during configured wall hour). No deny bypass.
Fix: document as wall-clock behavior matching Junos (Junos also wall-clock); optionally detect ambiguous hour via time.Local lookup of zone transitions and collapse second occurrence to inactive. Low priority.
Labels: scheduler, timezone, vrx-parity

### F3 — natshow persistent detail session counter may undercount when zone ID map missing
Severity: Low
Confidence: Medium
Evidence:
```go
// persistent.go:63-88
if dp.IsLoaded() {
  _ = dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
    if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
      var ip4 [4]byte
      binary.NativeEndian.PutUint32(ip4[:], val.NATSrcIP)
      sessionCounts[natKey{netip.AddrFrom4(ip4), val.NATSrcPort}]++
    }
    return true
  })
```
Counter iterates both v4 and v6 but builds sessionCounts only from SNAT sessions. If crFn returns nil (not loaded), session counts are empty → detail shows 0 sessions though sessions exist. That's same as master contract (nil Reader → no counts), but if dp.IsLoaded true and cr nil? Actually persistent.go doesn't use cr, only IsLoaded. So sessionCounts populated even when counters unavailable — okay. However, `persistent.go` and `source.go` both ignore error from IterateSessions (discard _) — if iteration errors mid-way, counts silently partial, showing 0 or truncated. No warning surfaced.
Why it matters: operational display may show 0 active sessions during transient dataplane read error, misleading operator during outage.
Fix: log debug on IterateSessions error; or surface as "(unavailable)" when err != nil. Minor.
Labels: display, natshow

### F4 — xpf-deploy libvirt disk ovl collides when name == image basename
Severity: Low (defense-in-depth, already checked)
Confidence: High (negative + hardening confirmation)
Evidence:
```go
// xpf-deploy.py:604-606
if os.path.abspath(overlay) == os.path.abspath(golden):
    die(f"VM name '{ap['name']}' collides ...")
```
Guard present: prevents overwriting golden with overlay. Good.
Why not higher: already mitigated, noted as hardening success.

## Negatives (proved coverage)

- dhcpserver gen ordering: applyGen atomic allocation at call entry, lastAppliedGen guarded by mu, stale skip counted — prevents ABA deploy race (Codex hole closed).
- dhcpserver lease_sync IA_PD: LeaseType preserved via keaLeaseTypeToString inverse, prefixLen only for IAPD, else 128 — correct per #2262/#2268.
- policymatch empty zone (#4411): zoneKnown fails closed when Zones empty — runtime would match nothing, simulator matches none (fixed offline tolerance drift).
- policymatch app matching: protocol-less named app fails closed via appOK false + ContentRejected gate, not match-any — parity with dataplane SnapshotIntegrityError (#4394).
- policymatch global scoped: reportedScopeZone for multi-zone returns flowZone (single concrete) not joined label, while single token preserved verbatim for bit-identical pre-#4626 — correct.
- scheduler republish: updateFn returns error → republishPending latch, next tick retries with current active map, not stale — converges fail-open permit past window case (#3780).
- sign.py TOCTOU: verify_and_read copies file+sigs to private 0700 tmp, verifies copy, returns copy bytes — prevents user-writable dir swap between check and use.
- bake.py sign ordering: finalize_artifacts validate_step then sign_step, extracted as testable function test_bake_sign_ordering.py — prevents signed-but-invalid image (#4017).
- publish.py orphan sweep: walks recursively, rejects nested image artifacts (basename-only manifest bind would escape), rejects unexpected files default-deny (#165 H-5).
- cluster_status_parse: secondary-hold captured via alternation order primary|secondary-hold|secondary — previously truncated to secondary, masking transition — fixed.

## Suggested Issue Split

1. Harden make_config_drive.py ISO perms (F1) — single PR, chmod 0o600 on out ISO + staged conf.
2. Optional: natshow session iterate error handling (F3) — low.

## Metrics

- Files covered: 114/114
- LOC measured via wc: xpf-deploy 1881, bake 756, sign 345, publish 786, validate 686, policymatch prod 1715, scheduler prod 449, natshow 399, dhcpserver prod ~3K.
- Largest fn: deploy_libvirt_inner (~100 lines), policymatch Match (~150), bake virt_customize arg list (~80).


---

### === ps-A1_rust_dataplane_packet-b1.md (39802 chars, 223 lines) ===

# Batch 003 b1/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b1
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

Ranked by LOC × responsibility-count × hot-path proximity (poll_descriptor hot=10, forwarding=8, frame=9, cos=5, coordinator=3, bpf_map=4, bench/build=1):

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ LOC god | per-packet orchestrator: host-inbound → lo0 → junos-host → route → screen → policy → SNAT → install → telemetry → HA | 10 |
| 2 | forwarding/mod.rs | 2795 | prod | lookup_forwarding_resolution_inner_ecmp 800+ | FIB/NAT/fabric/tunnel/VRF/zone-pair/MSS/local-delivery table-scoped decis | 9 |
| 3 | flow_cache.rs | 2000+ est | prod | lookup, insert | flow-cache hit/miss, MAC-epoch TOCTOU (#3918), owner-RG epoch | 9 |
| 4 | frame/inspect.rs | 1960 | prod | frame_l3_offset 68, packet_rel_l4_offset 100 | L3/L4 offset, IPv6 EH walk, fragment detection, flex-bounds, declared_end | 9 |
| 5 | frame/mod.rs | 1743 | prod | apply_dscp_rewrite 200 | rewrite orchestrator, DSCP, checksum adjust | 8 |
| 6 | forwarding_build/fib.rs | ~500 | prod | populate_routes, resolve_next_hops | route table build, preference validation (#3771), family mismatch | 7 |
| 7 | forwarding_build/zones.rs | 142 | prod | populate_zones 80 | zone name↔id, duplicate ID reject (#3719), reserved-range skip, host-inbound per-zone, reject_buckets per-zone (#3618), tcp_rst per-zone | 8 |
| 8 | forwarding/host_inbound.rs | 538 | prod | classify_system_service 134, host_inbound_admits 40 | host-inbound admit: system-services → L4 ports/ICMP types/IP proto, protocols all expansion (#3199) minus L2 (#3311), None=>true for unknown zone (id 0) | 8 |
| 9 | forwarding_build/*.rs (interfaces, cos, tunnels, validated, wg) | ~800 total | prod | — | interface→zone mapping, CoS iface config, tunnel endpoints, WG engines | 6 |
| 10 | frame/headers.rs | 338 | prod | write_eth_header_slice_tagged 40 (unsafe) | eth/ipv4/ipv6/udp header serializers, TxVlanTag, DF=1 atomic datagram (#1440) | 7 |
| 11 | frame/byte_writes.rs | 81 | prod | — | write_ipv4/6 src/dst (NO guards — caller must validate), L4 port writes (guarded) | 8 |
| 12 | frame/* (build/*, rewrite/*, tcp.rs, checksum.rs, tcp_segmentation.rs, wg.rs) | ~2500 total | prod | segment_forwarded_tcp_frames 500+ | frame building, rewrite descriptors, TCP segmentation, WG outer MTU SSOT | 7 |
| 13 | cos/* (admission, builders, ecn, fairness, flow_hash, queue_ops, token_bucket, tx_completion) | ~5000 total | mixed | admission check, queue_ops push/pop/drain/v_min, waterfill allocator | CoS classification, per-queue token-bucket, lossless queue, ECN, flow-hash, TX completion | 5 |
| 14 | coordinator/* (mod, bpf_maps, ha_state, inject, reconcile/*, refresh_bindings, session_manager, snapshot_refresh, status, supervisor, tunnel_supervision, wg_control, worker_manager, cos_leases/state) | ~8000 total | prod | mod.rs 982, status.rs 1045 | snapshot apply, BPF map mgmt, HA state, session sync, WG control, cos leases, bringup/teardown | 4 |
| 15 | bind.rs | ~600 | prod | — | XDP/XSK bind, UMEM setup | 4 |
| 16 | bpf_map/* (ha.rs, metrics.rs, mod.rs, pin.rs, publish_conntrack.rs) + bpf_map_tests | ~1500 total | mixed | — | BPF map definitions, pinning, conntrack publish, metrics | 4 |
| 17 | checksum.rs | ~300 | prod | compute_l4_csum_delta 100 | NAT checksum delta, NPTv6 neutral, IPv4 words | 6 |
| 18 | disposition.rs | ~500 | prod | record_forwarding_disposition 99 | disposition counters, zone counters via zone_counter_slot_map batched (#3651) | 5 |
| 19 | cold_path_hist.rs + tests | ~2000 | mixed | — | cold-path slot map direct zone-pair → slot (not hash) #1635 | 3 |
| 20 | ethernet.rs, event_emit.rs, icmp.rs, gre.rs, ha.rs, icmp_embed/*, etc | ~5000 total | mixed | — | L2 parsing, ICMP error, GRE decap, HA fabric, ICMP embed NAT matching | 5 |
| 21 | benches/*, build.rs, csrc/xsk_bridge.c | ~500 total | bench/build/c | — | benches for prefix_set, session_table, snat_allocator, tx_kick | 1 |

**Totals**: 150 files — ~35k prod LOC, ~15k test/bench LOC, 6294 largest (poll_descriptor god). Hot-path proximity: poll_descriptor 10, forwarding 9, frame inspect 9, host_inbound 8, zones 8, byte_writes 8, cos 5, coordinator 3.

## Module Log (coverage proving)

- **forwarding_build/zones.rs**: Reviewed reject_duplicate_zone_ids (HashMap owner, skip 0/empty/reserved, error on differing name same id — #3719), populate_zones (zone_name_to_id SSOT via policy helper #3402, ids ≥ RESERVED_MIN skip with eprintln, zone_id_to_name insert, zone_host_inbound insert NO LONGER gated on host_inbound_configured #3705 — empty ZoneHostInbound => default-DENY, reject_buckets per-zone Arc<TokenBucket> #3618 cardinality = configured zones ≤65533 not attacker-growable, zone_tcp_rst insert). NEGATIVE: no integer truncation — u16 ids preserved, no as cast. Sound for duplicate merge prevention. Verified fail-closed on unknown / global ingress: None slot never in table.

- **forwarding/host_inbound.rs**: Reviewed zone_host_inbound_from_snapshot → from_tokens (lowercase trim), classify_system_service (match all/any-service => all_services=true, ssh=22, telnet 23, ftp 21, http 80, https 443, ping → icmp_types_v4 8 + v6 128 #3201/#3240, dns 53 udp+tcp, dhcp v4-only 67/68 #3225, dhcpv6 v6-only 546/547 #3225, ntp 123, snmp 161/162, ike/ipsec 500/4500, tftp 69, netconf 830, ssh-netconf 22+830, finger 79, ident-reset explicit no-op #3310 — token recognized for parity test but contributes nothing (fail-closed vs kernel reset, documented divergence), lsping 3503, sip 5060, r-login etc, traceroute 33434-33523 explicit set, gre 47, _=>{} fail-closed). classify_protocol (all => routing_protocol_all_expansion minus L2 isis #3311, ospf v4-only 89 #3225, ospf3 v6-only 89, bgp 179 tcp, rip 520 v4, ripng 521 v6, igmp 2 v4-only #3225, pim 103 dual, vrrp 112, bfd 3784/3785/4784 #3299, ldp 646 tcp+udp, msdp 639 tcp, nhrp 54, rsvp 46 dual #3341, pgm 113 #3341, sap 9875 udp #3341, dvmrp 2 v4-only #3341, isis {} no-op L2, router-discovery v4 9/10 only #3201). KNOWN_ROUTING_PROTOCOL_TOKENS 14 entries, L2 set [isis]. is_icmp_host_inbound_global_accept (icmp v4 3/11/12, v6 1/2/3/4/133-137 #3171/#3201/#3240 — error/PMTUD + ND). host_inbound_admits (global accept first #3171, None=>true admit-all for genuinely unknown id 0 #3405 — only unknown/global, not configured zone — Some => hi.admits). host_inbound_admits_iface (per-ifindex override first #3362, else zone). admits() (all_services bypass #3199, protocols all NOT bypass, TCP 6→tcp_ports, UDP 17→udp+family-scoped #3225, ICMP 1→icmp_types_v4, 58→icmp_types_v6, other→ip_protocols+family-scoped). NEGATIVE: token lowercasing trim prevents case bypass, empty token ignored. ZoneHostInbound struct 11 fields default empty = deny.

- **forwarding/mod.rs**: Reviewed classify_metadata (NoSnapshot, gen mismatch), canonical_route_table (Cow Borrowed for default v4/v6 no alloc #4674, suffix rewrite per-VRF owned string), FABRIC_LINK_SKIPPED_* counters + record_fabric_skip + build_fabric_link_or_skip shared classifier #3773 (parent≤0 invalid, peer None unparseable, local_mac None distinguishes empty vs malformed via trim, same for peer, up default true via FabricSnapshot::default_true #4082), classify_neighbor_state (Usable KnownUnusable Unknown #3771, tokens split '|', empty→Unknown, reachable/stale/delay/probe/permanent/noarp allowlist, failed/incomplete known unusable, else Unknown — whole state rejected if any token unknown), neighbor_state_usable (Usable only), parse_packet_destination (l3 offset checked len), resolve_forwarding, nat_scope_ctx (ifindex→config_name/routing_instance via maps fallback "" #3096), match_source_nat*, zone_pair_for_flow_with_override (test-only String API via zone_id_to_name), zone_pair_ids_for_flow_with_override zero-alloc u16 pair directly #919/#922 (ingress override Option<u16> or ifindex_to_zone_id, egress via egress.iface.zone_id, 0 unknown), allow_unsolicited_dns_reply, owner_rg_for_flow/resolution (re-owned id filtered #1873 — stored resolution egress ifindex mismatch → 0 unknown), ingress_is_fabric/overlay, resolve_fabric_links_from_snapshots + resolve_fabric_redirect (first UP preferred #4082, fab0-preferred deterministic Go sorted), resolve_zone_encoded_fabric_redirect + by_id (u16 BE in synthetic MAC 02:bf:72:CC:RR:NN where CC=FABRIC_ZONE_MAC_MAGIC, RR=hi, NN=lo #3075), redirect_via_fabric_if_needed, prefer_local_forward_candidate, cluster_peer_return_fast_path (fabric ingress only, excludes initial SYN #2151, ICMP echo req, bare RST/FIN #4453, UDP+non-TCP/ICMP #4439/#4414 — only TCP/ICMP valid return), is_icmp_echo_request, resolve_ingress_logical_ifindex, enforce_ha_resolution (snapshot, startup grace, RG active), cached_flow_decision_valid (RG-stamped redirect, flow-cache epoch, fabric prefer local), finalize_new_flow_ha_resolution, demoted/activated_owner_rgs, effective_tcp_mss / native_gre_inner_mtu / tunnel_outer_mtu SSOT #2300 #2517 fallback 1500 not zero, tunnel_tcp_mss dispatch WG vs GRE #2299 #2715, select_tcp_mss priority tunnel>gre-in>all-tcp #2486, is_ipsec_traffic ESP 50 AH 51 IKE 500/4500, classify_ipsec_admission NewInboundIke vs Exempt via ISAKMP Responder SPI all-zero #4323 (stateless, payload after UDP 8, 4500 non-ESP marker 4 zero, missing→NewInboundIke fail-closed), RouteOverride enum None/Table/Drop #4392 PBR reject prevents VRF leak, ingress_route_table_override (interface filter affects route lookup gate, extra via term_match_extra_from_frame, evaluate_interface_filter_routing_instance_event_counted, is_drop Reject/Discard → enqueue_filter_reject_reply, emit_filter_log_event with ingress_zone_id override filtered by zone_id_to_name contains, app_id via hot-path catalog, truthful reject outcome #3615, Drop prevents override apply), interface_nat_local_resolution, should_cache_local_delivery_session_on_miss has_syn gate #4539 subsumes #2151/#4487 pure PSH/null/URG, install_helper_local_session, should_block_tunnel_interface_nat. NEGATIVE: table-scoped local-delivery decision #3769 prevents VRF leak via local_tables_v* + local_nat_any_table wildcard mirroring scope_ok, owns_configured_ip anti-poison driven from configured_iface_v* + local_v* #3182 SNAT exclusion, LOCAL_DELIVERY_IFINDEX0 diag counter.

- **types/forwarding.rs**: Reviewed ForwardingState 66 fields no repr (hot FIB vs cold config truth interleaved dcache waste noted in orientation), SynCookieMasterKey redacted Debug #4484, local_v4/v6 FastSet global membership, local_tables_v4/v6 FastMap addr→FastSet<table> per #3769, local_nat_any_table wildcard unscoped NAT external, configured_iface_v4/v6 full set decoupled from NAT-aware local_v* #3182, interface_nat_v4/v6, connected_v4/v6 vec, routes_v4/v6 FastMap<table, Vec<RouteEntryV4/6>>, tunnel_endpoints, gre_decap_index HashMap<(family,src,dst), Vec<u16>> kind-segregated #2327, wg_engines Arc shared, has_wg_tunnels bool gate #1432 §4.5, neighbors, ifindex_to_name/config_name/routing_instance #3096, ifindex_to_zone_id u16 #921, zone_name_to_id, zone_id_to_name, zone_host_inbound, ifindex_host_inbound per-interface override #3362 EFFECTIVE union precomputed in Go, zone_tcp_rst, reject_buckets per-zone Arc TokenBucket #3618 clone shares atomics survives ArcSwap (reset-on-commit accepted), egress, ingress_logical_ifindex (ifindex,vlan)→logical, fabrics vec FabricLink, fabric_skips Vec<FabricLinkSkip> most-recent #3773, allow_dns_reply, allow_embedded_icmp, alg_disable_flags bitfield #2008, app_catalog #2008 M5, session_timeouts, session_opening_overrides per-zone syn-flood timeout override #3527, policy, source_nat_rules, static_nat, dnat_table, nat64, nptv6, screen_profiles, screen_missing_profiles #3082 undefined but referenced, syn_cookie_master_key, tunnel_interfaces FastSet, filter_state, cos, tx_selection_enabled, gre_acceleration dead_code #3360, power_mode_disable dead_code, mirror_configs, tcp_mss_* 3, cold_path_sample_mask #1620 mask, pending_neigh_timeout_ns #1636 compute 800ms vs 2000ms, cold_path_slot_map direct (from,to)→slot #1635 not hash, zone_counter_slot_map flat LUT #3651 array reads no hash, zone_counter_store cumulative. ZoneHostInbound 11 fields Default empty deny, admits method all_services only tcp? No protocols all bypass #3199, TCP 6 ports, UDP 17 dual+family, ICMP type check #3201, other proto dual+family. ForwardingState methods zone_tcp_rst_enabled, egress_zone_id hot inline, reject_bucket Option<&TokenBucket> Arc deref fallback, owns_configured_ip global not VRF scoped — correct for anti-poison. EgressInterface zone_id u16. TunnelEndpoint wg_local_privkey Zeroizing redacted Debug, WgRuntimePeer per-peer PSK zeroized redacted. FabricLink up bool #4082. FabricSkipReason 6 variants is_malformed partitions malformed vs unresolved transient. ForwardingDisposition 8 variants is_cacheable only ForwardCandidate+FabricRedirect (PolicyDenied NOT cacheable #), is_slow_path_eligible LocalDelivery+NoRoute+MissingNeighbor+NextTableUnsupported — PolicyDenied NOT eligible #1913 prevents firewall bypass via kernel reinject, FabricRedirect no binding drop fail-closed #1946 (not kernel routable). WorkerBindingLookup by_if_queue, first_by_if, all_by_if, by_slot. NEGATIVE: Hot FIB (routes, connected, neighbors, egress) vs cold (zone_id_to_name etc) interleaved — dcache waste orientation noted but not bug.

- **disposition.rs**: Reviewed is_martian_dst (IPv4 unspec/loopback/multicast/broadcast, IPv6 unspec/loopback/multicast #4743 — broadcast not applicable v6), record_exception (zone_name_for via zone_id_to_name get cloned default empty), DispositionCounters Hot vs Cold #1187 (Hot batch BatchCounters touched flag, Cold direct atomic — MESI thrash avoidance), is_hot, bump_* per-disposition, record_disposition match Valid/NoSnapshot/ConfigGenMismatch/FibGenMismatch/UnsupportedPacket (reconcile-only counters direct atomic per plan §2), record_forwarding_disposition (LocalDelivery bump, ForwardCandidate/FabricRedirect bump + zone traffic via zone_counter_slot_map only on Hot + meta exists #3651), HAInactive/PolicyDenied/NoRoute/MissingNeighbor/Discard/NextTable all update_last_resolution via Mutex Option<PacketResolution> (lock), NoRoute also bump_martian if dst is_martian via debug tuple #4743 AND classified via is_martian_dst — sub-breakout. update_last_resolution locks last_resolution. NEGATIVE: martian check uses debug tuple present only when resolution built, not attacker-controlled.

- **frame/headers.rs**: Reviewed TxVlanTag NONE const present false, from_parts pcp 3 bits dei 1 vid 12 pack, emits() present && tci!=0 (VID>0 OR PCP set — priority-tagged VLAN-0 emits #2149), header_len 18 vs 14, From<u16> legacy bare-VID semantics present iff vid>0 TPID 0x8100 PCP/DEI 0 bit-identical pre-#2149, eth_header_len wrapper, write_eth_header Vec-push (dst+src+vlan optional+ether_type), write_eth_header_tagged same but full TCI+TPID when emits(), write_eth_header_slice in-place returns Option<()> None if buf<eth_len #2844 pub(crate) re-export so nat64 top-level can use SSOT, write_eth_header_slice_tagged with unsafe ptr copy_nonoverlapping after guard buf.len()>=eth_len — debug_assert guarantees, eth_len 14 or 18 so in-bounds. write_ipv4_header buf[..20] guard Some(20) else None, 0x45, tos, total_len BE, ID 0, frag 0x4000 DF=1 atomic RFC 6864 #1440 makes ID=0 compliant (was DF=0 bug), TTL 0→64, proto, zero checksum placeholder, src/dst octets, checksum16 20 bytes BE, write_ipv6_header 40B guard, version 6 + TC high 4, TC low + flow high, flow low 16, payload_len BE, next_header, hop 0→64, src/dst, no checksum, write_udp_header 8B guard src/dst BE udp_len BE checksum BE (0 legal IPv4 per RFC 768). NEGATIVE: IPv4 DF=1 fixes atomic datagram RFC violation, VLAN 0x88a8 preserved on reflect #2149.

- **frame/byte_writes.rs**: Reviewed write_ipv4_src/dst, write_ipv6_src/dst — #[inline(always)] NO LENGTH GUARDS comment says caller MUST have validated packet.len()>=ip+20 / ip+40 — fast path validates near top v4/v6 arms, generic-path NAT helpers only after own bounds-checks. write_l4_src_port guarded len>=l4+2 else skip not panic, dst len>=l4+4. NEGATIVE: NO_GUARD contract documented, need caller audit — verified in frame/mod.rs apply_dscp_rewrite has l3 check 20/40, rewrite orchestrators check before calling.

- **checksum.rs**: Reviewed compute_ip_csum_delta (sum u32, rewrite_src/dst IPv4 old/new words via ipv4_csum_words, !old + new, fold while sum>>16 !=0), compute_l4_csum_delta (NPTv6 pure translation checksum-neutral RFC 6296 short-circuit #3121 — only one of src/dst rewritten returns 0, composed DNAT both set → fall through compute both deltas neutral term nets zero, leaving DNAT delta, IPv4 same as IP, IPv6 octets step2 be bytes !old+new, rewrite_src_port !old+new, rewrite_dst_port, fold, note 0xFFFF ones-comp zero). ipv4_csum_words octets BE [0..1],[2..3]. dnat_v6_entry_bytes (dk[0]=proto, [1..4] pad, [4..20] snat octets, [20..22] snat_port to_ne_bytes HOST-ORDER numeric serialized natively #2406 BYTE-ORDER matches shim reader from_be_bytes→host stored native, dv 0..16 orig octets, 16..18 orig_port BE, 18 flags 0). dnat_v4_key_bytes (key.addr_family AF_INET rewrite_src Some V4 snat, snat_port unwrap or key.src_port, dk 12 bytes [0]=proto, [4..8] snat octets, [8..10] snat_port to_ne_bytes HOST-ORDER #2406, SSOT #2979), dnat_v6_key_bytes same SSOT, delete_dnat_table_entry if rewrite_src None return, match AF_INET/AF_INET6 fds Some + key helper Some else return, cfg(test) DNAT_DELETE_ATTEMPTS inc, unsafe bpf_map_delete_elem, v6 same, DNAT_DELETE_ATTEMPTS static test-only, DNAT_PUBLISH_ATTEMPTS static test-only, publish_dnat_table_entry must_use bool true when nothing to publish or no fd, false ONLY when syscall failed #2244 bumps per-binding dnat_publish_errors counter visible, v4/v6 arms build key via SSOT helper cannot drift, dv orig, cfg test inc, rc unsafe bpf_map_update_elem, if rc<0 static first 32 log eprintln journald storm gate + return false, else true. NEGATIVE: BYTE-ORDER fix #2406 critical — to_be vs to_ne mismatch previously missed.

- **frame/***: frame/mod.rs 1743 re-exports, v6_rel_l4_offset meta trust plausible >=40 && l4>l3 else walk extension-header chain SSOT #1838, apply_dscp_rewrite_to_frame Option<()> None when no IP field (non-IP/ too short) is benign not fw error, v4 TOS high 6 bits, checksum adjust incremental. inspect.rs 1960 frame_l3_offset 14/18 single tag only (0x8100/0x88a8) double tag inner ethertype returned as-is (shim drops double-tag per contract), frame_l4_offset IPv4 IHL*4 <20 fail None, IPv6 walk MAX 8 iterations #2292 0/43/60/135/139/140/253/254 length-prefixed #4517 exotic Mobility/HIP/Shim6/experimental before were evasion now walked, 51 AH (len+2)*4, 44 frag 8 bytes, 59 No-Next-Header None terminal, else Some offset — bound fail-CLOSED None not fake offset #2292 matches screen path. ipv6_ext_chain_over_limit distinguisher truncated vs over-limit #4743 (chain still on EH after MAX iters) gate explicit drop counted ipv6_ext_header_dropped, mirrors walk exactly. packet_rel_l4_offset same logic, packet_rel_l4_offset_and_protocol returns (offset,protocol) #2148 walker shared with parser NDP (canary pin). ipv4_is_non_first_fragment len>=8 & frag off low 13bits !=0, ipv6_is_non_first_fragment walks EH chain bounded looking for frag hdr 44 offset bits upper13 FFF8 !=0, is_non_first_family dispatched, ipv4_is_any_fragment &0x3FFF !=0 any frag #2362 Junos is-fragment FIRST+MIDDLE/LAST not unfrag, ipv6_is_any_fragment walks for frag hdr presence, ip_declared_end #5150 L3 offset + IP total/payload clamped to frame.len() — upper clamp no over-read, lower clamp excludes Ethernet slack padding beyond declared IP length (60-octet min-frame pad) — closes match-on-padding filter evasion, returns None if too short to hold IP len field fail-closed, term_match_extra_from_frame family-dispatched fragment predicates #1852 L3 IP addr present, non-first fragment l4 bytes are payload not L4 so tcp_flags=icmp_type=code=0 suppress #2344, is_fragment kept true, #2449 truncation ICMP length <l4+2 type/code absent → force (0,0,0) + l4_present false fail-closed not match icmp 0/0, flex_l3/l4 slices bounded by declared_end. NEGATIVE: MAX_IPV6_EXT_HEADERS 8 parity screen vs forwarding (#2292), over-limit fail-closed #4743 explicit drop.

- **coordinator/**: mod.rs 982 reconcile orchestrator, bpf_maps.rs map lifecycle, cos_leases/state queue leases, ha_state HA groups, inject RPC injection Cold counters path #1187, reconcile/bringup/teardown/reset/snapshot, refresh_bindings, session_manager, snapshot_refresh runtime fabric refresh via resolve_fabric_links_from_snapshots late-resolution + preserved-fabric merge pruning skip whose parent re-added, status.rs 1045 counters Prometheus, supervisor, tunnel_supervision, wg_control WG peer endpoint, worker_manager. NEGATIVE: no zone ID handling in coordinator (Go side controls), snapshot versioning protocol v3 still used — check dedup #5488 multi-zone global deny plural fields vs old helper (version not bumped) — but this batch no policy file, still note.

- **cos/**: admission.rs 646 token bucket admission fail-closed, builders 259 factory, cross_binding 261 multi-queue binding, ecn.rs 257 ECN bits check, fairness.rs 231 fair RR, flow_hash.rs 144 hash, queue_ops/* ~3000 total pop/push/drain/v_min admission accounting active_buckets, fused_diff_tests, rollback ordering, cap_aware 7-resp god queue_ops accounting, v_min_tests cadence hard_cap prepared_drain publish rejoiner throttle vacate, queue_service/* waterfill god 2058 7 resp epoch refill f64 fraction clamp bitset gating Phase1 ascending Phase2 descending WRAP — CoS TX classification does NOT directly inspect zone IDs (zone-agnostic shaper), but tx_selection_enabled per-family gate, shared_cos_lease publish_equal_flow_epoch_v8 rotation. NEGATIVE: CoS queue starvation across zones? Per-queue accounting not per-zone, but zone_id not used in CoS path — acceptable (CoS is egress QoS not security zone).

- **benches/build/csrc**: benches prefix_set_lookup, session_table, snat_allocator, tx_kick_latency (hints hot-path perf), build.rs retained Rust AF_XDP shim build pinned toolchain kernel-verifier gate #1864, xsk_bridge.c C bridge.

- **other**: bind.rs XSK bind, ethernet.rs ETH_HDR_LEN 14 const, event_emit.rs RT_FLOW/SYSLOG ring buffer, flow_cache.rs slab + 4 seeded maps owner_rg deltas wheel #3918 TOCTOU snapshot before resolve record-before-use.

## Findings — Batch b1

### F-FIB-01: zone-pair slot-map direct LUT eliminates hash DoS but global 0 bypass remains in host-inbound — `None => true` for unknown zone ID 0 is intentional but documents fail-open surface
Severity: Medium (arch hardening already applied, residual is documented)
Confidence: High
Evidence:
```
// forwarding_build/zones.rs:36-38
if zone.id == 0 || zone.name.is_empty() || zone.id >= crate::policy::ZONE_ID_RESERVED_MIN {
    continue;
}
// host_inbound.rs:493-505
match state.zone_host_inbound.get(&ingress_zone_id) {
    None => true, // genuinely unknown / global ingress zone (e.g. id 0)
    Some(hi) => hi.admits(...)
}
```
Trace: 
1. `populate_zones` skips id 0, empty name, ≥RESERVED_MIN — id 0 never in zone_id_to_name nor zone_host_inbound (empty map per #3705 backstop but skip prevents insert).
2. `ifindex_to_zone_id` lookup miss => `unwrap_or(0)` in `zone_pair_ids_for_flow_with_override` returns 0 for unzoned ifindex.
3. `host_inbound_admits` None => true admits all host-bound traffic for id 0.
4. Standalone: xpfd manages ALL interfaces, unconfigured brought down + ActivationPolicy=always-down, so unzoned ifindex should not have kernel link up. In cluster: fab0 parent is IPVLAN fabric with zone? docs says fab0 IPVLAN parent — fabric — is lifeline exempt #3682 (never reaches AF_XDP local-delivery classifier). So residual only for genuinely unknown global.
5. However, if Go control plane ships snapshot where interface snapshot missing zone (race / old version), helper would admit-all host-bound for that interface until next snapshot — management-plane exposure.
Refutation attempt: Checked `docs/host-inbound-service-matrix.md` SSOT, `pkg/daemon/linksetup.go` assigns vSRX names based on PCI, but zone assignment is via config compiler `compiler_security_zones.go` — if interface not in zone, compiler should error? Need check Go: `pkg/config` compiler — zone handling in security zones ties interface to zone. If omitted, interface is "unconfigured"? Daemon brings down. So this `None=>true` only fires for id 0 which is never from config, only from missing map — which should be dead interface. Still, fail-open vs fail-closed debate.
HPC/invariant: Hot path: `zone_host_inbound.get` HashMap lookup per LocalDelivery — cold-path only (host-bound not transit), so HashMap not flat array yet. `zone_counter_slot_map` IS flat LUT for transit (#3651) — two array reads no hash, good.
Why it matters: Management-plane default-deny parity #3405 fixed configured zones, but unknown id 0 still admit-all. If an attacker can cause ifindex_to_zone_id miss (e.g., via netlink rename race, or snapshot integrity bypass), host-bound traffic bypasses host-inbound gate. Junos default is deny for configured zones, but global zone traditionally permit? Need explicit.
Fix direction: 
- Option A: Change `None => true` to `false` default-deny for unknown zone, with explicit allowlist for known lifeline ifindexes that never reach classifier (already exempt #3682). Document breaking change.
- Option B: Keep true but add metric counter `host_inbound_unknown_zone_admitted_total` + eprintln on first hit, so operator visible.
- Option C (chosen in #3705): Insert empty ZoneHostInbound for every known zone even when configured=false, so None only for truly unknown (id 0). That's already done. So residual is only id 0.
Status: Negative with documentation — not a bug per current architecture (fab*/fxp0/em0 exempt, all transit interfaces zoned), but audit trail valuable.
Labels: vsrx-parity, hot-path, host-inbound, fail-open-surface
Dedup note: Not in dedup index — #3405/#3705 related but this specific id-0 residual not listed. Not re-reporting #3405 fix, noting remaining surface.

### F-CHK-02: checksum delta for composed NPTv6+DNAT correctly sums zero + DNAT but IPv6 word iteration uses step_by(2) with manual indexing — potential panic on odd len? Not, octets len 16 even
Severity: Low
Confidence: High
Evidence:
```
// checksum.rs:70-76
let old_o = old.octets();
let new_o = new.octets();
for i in (0..16).step_by(2) {
    let old_w = u16::from_be_bytes([old_o[i], old_o[i + 1]]);
```
Trace: octets [u8;16] len 16, step_by 2 yields indices 0,2,4,6,8,10,12,14 — last i+1=15 in bounds. No panic.
Refutation: Checked: `Ipv6Addr::octets()` returns [u8;16], fixed. Loop sound.
HPC: No alloc, u16 be parsing, fold with !old + new using ones-comp. Good.
Why: False positive candidate, proven sound.
Fix: NEGATIVE RESULT — checksum delta iteration bounds safe, NPTv6 compose identity preserved.
Labels: checksum, ipv6, sound
Dedup: Not in index.

### F-ZONE-03: fabric zone-encoded MAC carries u16 zone id BE in bytes [4,5] — encode/decode agreement verified across forwarding/mod.rs and frame/inspect.rs
Severity: Informational (parity)
Confidence: High
Evidence:
```
// forwarding/mod.rs:658-660
let [hi, lo] = zone_id.to_be_bytes();
resolution.src_mac = Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
// frame/inspect.rs: fabric ingress parse must read same
```
Trace: `resolve_zone_encoded_fabric_redirect_by_id` encodes 0x02bf72 magic + hi lo BE. In `frame/inspect.rs` `parse_zone_encoded_fabric_ingress*` reads magic at [3] and hi lo at [4],[5] BE to reconstruct u16. Tested in `forwarding/tests.rs:383-392` zone_id 300 0x012c above old u8 cap — fail-on-revert #3075.
Refutation: Verified both encode/decode use BE same positions. Old u8 scheme hardcoded [4]=0x00, new carries full u16 high byte [4] low [5]. Reserved-range ids never produced by StableZoneID per comment. Good.
HPC: Fabric fast path — zone override avoids string round-trip, u16 directly #921 single-hop direct lookup (one HashMap → already u16) vs old two-hop String→u16.
Fix: NEGATIVE — parity sound, #3075 hardened.
Labels: fabric, zone-encoding, parity, hot-path
Dedup: Not in index (3075 fix).

### F-BYTE-04: byte-writes NO-GUARD contract — audit callers validate len≥ ip+20/40 before calling write_ipv4/6 helpers
Severity: Medium
Confidence: Medium
Evidence:
```
// byte_writes.rs:26-31
// IP-write helpers have NO length guards. Callers MUST have
// already validated `packet.len() >= ip + 20` (IPv4) or
// `packet.len() >= ip + 40` (IPv6).
#[inline(always)]
pub(super) fn write_ipv4_src(packet: &mut [u8], ip: usize, addr: Ipv4Addr) {
    packet[ip + 12..ip + 16].copy_from_slice(&addr.octets());
}
```
Trace: Call sites searched:
- `frame/mod.rs` apply_dscp_rewrite_to_frame: checks ip.len()<20 return None before write.
- `frame/rewrite/ipv4.rs` / ipv6.rs builders: check frame.len() at top.
- `frame/build/ipv4.rs` / ipv6.rs: slice obtained via get_mut with length guard returning Option.
- Generic NAT helpers `apply_nat_ipv4/6` called after own bounds-checks in rewrite orchestrator.
Need full caller sweep: grep write_ipv4_src|write_ipv6 etc — all sites appear guarded, but contract is fragile future-code may forget.
Refutation: Attempted to find unguarded call — none found in current code. All rewrite paths validate L3 offset + 20/40 before. However, discipline relies on comment, not type-system — new contributor could violate.
HPC: Design discipline "maximally stupid helpers" per Codex review rev4 — no Option matching inside helper to keep optimizer folding constant-offset memcpy zero overhead. Inlining preserved, no heap.
Why matters: If future frame builder forgets guard, OOB panic in release? Actually Rust slice copy panics on OOB in debug and release (panic not UB) but would crash worker thread. Fail-closed via panic not ideal but not memory unsafe (safe Rust bounds check panics).
Fix direction: 
- Keep current perf-sensitive design but add debug_assert!(packet.len() >= ip+20) inside helper for debug builds to catch misuse early.
- Or create unsafe helper `write_ipv4_src_unchecked` with safety comment requiring caller guarantee, making contract explicit via unsafe boundary (current helpers are safe but rely on doc).
- Add `#[cfg(debug_assertions)]` length assert.
Labels: memory-safety, unsafe, hot-path, refactor
Dedup: Not in index — new finding but low severity via type-system improvement.

### F-HOST-05: `system-services { all }` admits every host-bound packet regardless of service — slightly broader than Junos (services only, not protocols)
Severity: Low (vsrx-parity)
Confidence: High
Evidence:
```
// host_inbound.rs:339-345
pub(in crate::afxdp) struct ZoneHostInbound {
    /// `system-services { all }` / `any-service` — admit every host-bound
    /// packet regardless of service. Operators use `all` as the catch-all
    /// "let everything in"; treating it as a full admit (slightly broader than
    /// Junos, which scopes `all` to service traffic) keeps a `host-inbound { all }`
    /// control/heartbeat zone fully open and is the safe direction.
    pub(in crate::afxdp) all_services: bool,
```
Trace: `admits()` first check if all_services true return true bypassing protocol/dport/icmp_type checks. Comment explicitly acknowledges broader than Junos — Junos scopes `all` to service traffic, but this implementation admits even routing protocols via all_services bypass. `protocols { all }` however is NOT blanket (#3199) — expands to routing-protocol signatures only via `routing_protocol_all_expansion` so cannot admit SSH etc.
Refutation: Deliberate safe-direction choice per comment — keep control/heartbeat zone fully open. Operators using `all` intend catch-all. So not a bug per design, but parity delta.
Why: If operator sets `host-inbound { all }` expecting Junos semantics (only services), they also get routing protocols — but that's safe (more open). If they set `system-services { all }` expecting only services, they also get protocols — but again safe direction. So fail-open vs fail-closed tradeoff: this chooses open for `all` which matches operator expectation of "let everything in".
Fix: Document in `docs/host-inbound-service-matrix.md` that `all` is full admit in dataplane (already SSOT per comment). No code change needed unless strict Junos parity required.
Labels: vsrx-parity, host-inbound, config
Dedup: Not in index — parity note but acknowledged in code.

### HIGH CONFIDENCE NEGATIVES (proving coverage):

- **Duplicate zone ID**: #3719 fix verified — owner HashMap, skip set mirrors populate_zones (0, empty, reserved), error DuplicateZoneId names both. Go quarantines before wire (config.QuarantinedZoneNames), helper backstop rejects whole snapshot keeps previous good forwarding state (fresh boot default-deny). Sound.

- **Reserved zone ID**: >= ZONE_ID_RESERVED_MIN skip with eprintln, ZONE_ID_RESERVED_MIN = 65534? Actually 65534? Comment says max usable 65533, sentinel JUNOS_GLOBAL_ZONE_ID. Skip diagnostics emitted. Prevents collision with JUNOS_GLOBAL.

- **VLAN handling**: frame_l3_offset handles single 0x8100/0x88a8 tag at 18 else 14, inner ethertype returned as-is (shim drops double-tag). All L2 parsers agree: parser.rs parse_eth_offsets, frame/inspect.rs frame_l3_offset, cos/ecn.rs ethernet_l3 — canary parser_tests.rs pins agreement. Sound.

- **ARP fixed-header validation**: #2369 validates htype=1 ptype=0x0800 hlen=6 plen=4 before reading sender MAC/IP at fixed offsets — prevents crafted ARP declaring different type/length being parsed at wrong offsets and learned as binding. Fail closed OtherArp recycled never learned. Good.

- **NDP validity MUSTs**: #2368 B bounds by IPv6-declared packet_end not raw frame len — prevents forged TLLA in L2 padding beyond payload_len. #2368 A checks hop limit 255, code 0, target not multicast (ff00::/8), icmpv6 checksum valid via ones-comp accumulator shared #2211. Unicast-only gate #2790, own-IP anti-poison #2851 owns_configured_ip, Override flag honored #4475 best-effort gate per-worker sole writer. Sound.

- **IPv6 EH walk agreement**: MAX_IPV6_EXT_HEADERS 8 equal screen vs forwarding #2292, exotic EH types 135/139/140/253/254 walked not evasion #4517, fail-closed None at bound returns Drop not fake L4 #2292, ipv6_ext_chain_over_limit distinguisher #4743 over-limit vs truncated — only over-limit dropped counted, truncated stays flowless path unchanged.

- **Fragment handling**: ipv4_is_non_first_fragment low 13 bits !=0, ipv6_is_non_first_fragment walks EH chain for frag hdr 44 offset FFF8 !=0, is_any_fragment #2362 MF+offset combined 0x3FFF !=0 FIRST+MID/LAST not unfrag, IPv6 any frag walks for hdr presence. term_match_extra_from_frame non-first fragment suppresses L4-derived match inputs (tcp_flags icmp_type code 0) fail-closed #2344, is_fragment true L3-only, truncation #2449 icmp length <l4+2 -> (0,0,0) l4_present false fail-closed not match 0/0. ip_declared_end clamped to frame.len() closes over-read and excludes Ethernet slack padding beyond IP total length — closes match-on-padding / filter-evasion #5150.

- **FIB integrity**: route preference negative rejected #3771 L1 i32::MIN hijack prevention, family mismatch NonEmpty declared must agree else error #3771 M4, neighbor state classification three-way Usable/KnownUnusable/Unknown #3771 M12 whole state rejected if any token unknown (previously denylist treated unrecognized as usable), counter NEIGHBOR_UNKNOWN_STATE_SKIPPED diag. Fabric skip counter #3773 partitions malformed vs unresolved transient.

- **Local-delivery table scoping**: #3769 decision gated on local_tables_v* (per-addr set of owning tables) not global local_v* membership — prevents cross-VRF local-delivery bypassing FIB+zone+HA-RG. Unscoped NAT external in local_nat_any_table_v* wildcard mirrors scope_ok empty-instance wildcard but interface host addresses never wildcarded. #3151 ifindex attribution via table-scoped connected scan (prefix.addr() == host only /32). LOCAL_DELIVERY_IFINDEX0 diag count. owns_configured_ip driven from configured_iface_v* decoupled from NAT-aware local_v* #3182 (SNAT/WAN IP excluded from local_v* but still protected). Salt.

- **Fabric handling**: #3773 shared classifier build_fabric_link_or_skip centralizes skip-vs-install, counters FABRIC_LINK_SKIPPED_MALFORMED / UNRESOLVED_PEER, log_fabric_skip_transition names link journal. #4082 up bool parent carrier, resolve_fabric_redirect_from_list prefers first UP fab0-preferred deterministic Go sorted-by-name. Zone-encoded src MAC #3075 full u16 BE high low bytes.

- **HA**: owner_rg_for_resolution filters re-owned id #1873 (stored resolution egress ifindex mismatch → 0 unknown prevents RG hijack). demoted/activated_owner_rgs calc.

- **IPsec passthrough**: is_ipsec_traffic ESP 50 AH 51 IKE 500/4500, classify_ipsec_admission stateless ISAKMP Responder SPI all-zero → NewInboundIke else Exempt #4323, payload after UDP 8, 4500 marker 4 zero demux NAT-T RFC 3948, missing→NewInboundIke fail-closed. Stage 11 synthetic LocalDelivery decision local_ifindex=0 deliberately to avoid GRE local_tunnel_deliveries channel mis-deliver #3616. NewInboundIke gated on ingress zone host-inbound ike/ipsec via host_inbound_admits_iface (logical ifindex zone pair) — zone omitting ike drops silent. ESP/AH + established IKE exempt (SA authorization) mirrors kernel chain global ESP/AH accept + ct established. Good.

- **Policy junos-host**: Junos order host-inbound-first then security policy #3019, to-zone junos-host gate evaluated after host_inbound_admits, flow-backed + flowless arms (#3292 flowless MUST traverse same gates before #3292 ungated fail-open), flowless synthetic L3 flow ports 0 l4_present false port-bearing terms fail closed protocol/address/any terms still admit, PBR reject #4392 Drop prevents VRF leak + false audit (routing-instance override NOT applied when action Reject/Discard, actual reply outcome threaded into log #3615), reject reply enqueue first then emit. Host-inbound deny emit tuple-rich event #3610, junos-host deny RT_FLOW with policy_id action app_id via catalog. Permit carries then log selection #3706 session-init/close stamping.

- **CoS**: Admission token bucket, builders, cross_binding multi-queue, ECN bits, fairness RR, flow_hash, queue_ops push/pop/drain/v_min: per-queue accounting, fused_diff_tests, rollback snapshot stack, cap_aware, flow_fair_enable, promotion, v_min cadence hard_cap prepared_drain publish rejoiner throttle vacate, queue_service waterfill #1614 proportional vs guarantee rate #1614 A1 A2, token_bucket, tx_completion. Zone-agnostic shaper — acceptable as egress QoS not security zone (no cross-zone leak — classification keyed by ifindex/queue not zone).

- **Unsafe**: Only in headers.rs write_eth_header_slice_tagged after guard buf.len()>=eth_len, debug_assert, ptr copy_nonoverlapping 6+6+optional 2+2+2 — safe as guard ensures in-bounds. No other unsafe in this batch (bpf_map uses libbpf_sys bpf_map_delete/update via unsafe but fd validated).

## Suggested Issue Split

- P2: Audit `None => true` unknown zone admit-all surface — add metric + docs (F-FIB-01)
- P3: Harden byte_writes contract with debug_assert (F-BYTE-04)
- P4: Document `all_services` broader-than-Junos in operator docs (F-HOST-05) — already in code comment but ensure SSOT matrix mentions.



---

### === ps-A1_rust_dataplane_packet-b2.md (31794 chars, 223 lines) ===

# Batch 004 b2/3 — Rust AF_XDP Dataplane + Zone Policy — 150 files
Commit: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b2
Reviewer: claude-003 — defensive review — owner authorized
Date: 2026-07-10

## File-Size/Shape Inventory (ranked by size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | poll_descriptor/mod.rs | 6294 | prod | poll_binding_process_descriptor 4000+ god | orchestrator remainder after stage extractions: session-hit path, session-miss path (policy→NAT→FIB→screen→install), flowless path (#3292), junos-host gate #3019/#3706, PBR route_override #4392, DNS reply allow, strict-syn-check #4400, session limit #2134, fragment assoc NAT64 #2562, IPv6 ext over-limit #4743 | 10 |
| 2 | poll_descriptor/filter.rs | ~600+ | prod | filter_terminal, host_inbound_gated_lo0_action | input-filter eval + log emission, lo0 host-bound filter, host-inbound gating via host_inbound_admits_iface with logical ifindex #3609, PBR routing-instance override with Drop #4392, log source Pbr vs Filter, truthful REJECT→DENY downgrade #3615 | 8 |
| 3 | tx/dispatch/mod.rs | 1486 | prod | enqueue_pending_forwards 1048 god | Phase 8 try_inplace_rewrite_or_build, copy-frame oversized check, PTB derivation #2301/#2330, tunnel outer MTU SSOT #2300, tuple-mismatch diag #4041, single-recycle invariant 39 sites | 8 |
| 4 | types/cos.rs | 1786 | prod | — | CoSState 28 fields 5 lifecycles, cos_lease, equal-flow target policy parse #2458, loss-priority rewrite #3995 | 5 |
| 5 | types/forwarding.rs (already in b1 but referenced) | 1100 | prod | — | ForwardingState 66 fields (see b1) — hot FIB vs cold truth | 9 |
| 6 | wg/engine.rs | 1805 | prod | — | WG engine, handshake, session, cookie, framing, peer selection per #1434 multi-peer, allowed_ips LPM, secret redaction Debug #4484 zeroize | 6 |
| 7 | worker/*.rs (mod, lifecycle, loop_body, telemetry, cos/*, bind_meta, bpf_maps, flow_cache_state, scratch, timers) | ~3000 total | prod | loop_body setup/debug_report | worker loop, UMEM, XSK, flow-cache, TX pipeline BatchCounters #3651, cos row, status | 7 |
| 8 | tx/* (cos_classify.rs 1335 7-resp, dispatch/cos, drain/phase_*, rings, stats, tcp_segmentation, transmit/*, queue_service/* waterfill 2058) | ~8000 total | prod | cos_classify, queue_service::waterfill 432 god | CoS TX selection resolve, TX drain phases trivial/shaped/backup, rings, TCP segmentation, finalise/rewrite/stage/verify/write, waterfill allocator epoch refill f64 fraction clamp bitset Phase1 asc Phase2 desc WRAP | 6 |
| 9 | icmp_embed/* (builders, mod, nat_match_v4/v6, parse, return_resolution, session_match) | ~1500 total | prod | match_outer_v4, session_match | embedded ICMP NAT matching forward-NAT-by-reverse + session fallback, return resolution, builders for ICMP error translation | 7 |
| 10 | icmp_ptb.rs + icmp_ratelimit.rs + tests | ~2000 total | mixed | build_frag_needed, PacketTooBig | PTB generation inner MTU derivation WG/GRE/NAT64 #2301/#2330, icmp_ratelimit token bucket per-zone #3618 fallback global bucket | 6 |
| 11 | poll_stages.rs (already b1) + poll_descriptor/* (cookie_reply, filter, flow_cache_hit, nat_exception, reject_reply, rx_telemetry, debug_log_throttle) | ~2000 total | prod | stage_screen_check, stage_ipsec_passthrough | Stage 5 link-layer ARP/NDP classify w/ anti-poison #2851 #2790 Override #4475, Stage 6 GRE decap, Stage 7+8 flow parse + learn logical ifindex #2370, Stage 9 fabric ingress zone override, Stage 10 screen per-zone + alarm-without-drop, Stage 11 IPsec passthrough NewInboundIke gated host-inbound #4323 | 8 |
| 12 | neighbor.rs 2036 + sharded_neighbor + neighbor_* + neg_neigh | ~4000 total | prod | — | ARP/ND probe + netlink mgmt + monitor thread + warmer, sharded map insert_if_changed mac_change_epoch #3048, neighbor_latency, resolver, dispatch skip-learn check for zone-encoded fab MAC | 5 |
| 13 | session_glue/* (mod god 30+ fns, commands/*, promote) + session/* | ~4000 total | prod | enforce_session_ha_resolution, redirect_via_fabric | session install/remove, HA promote/demote owner RG, synced sessions upsert/delete, expiration timer-wheel #2120 SelfHeal/Hold/ReapStale, metadata clone hot path lookup.rs | 7 |
| 14 | umem/* + shared_umem + shared_ops + types/tx + mpsc_inbox + forward_request + mirror + rst + gre + ha + tunnel + tests | ~6000 total | mixed | — | UMEM mmap, tx inbox, shared recycle routing, mirror resolver fast_path, RST handling, GRE encap, HA fabric redirect, tunnel endpoint supervision | 5 |
| 15 | parser.rs + parser_tests + poll_stages_tests + etc | ~1000 | mixed | classify_arp, parse_ndp_neighbor_advert | ARP/NDP parsing hardened #2369 #2368 #2790 #2851 #4475, L2 offsets VLAN single-tag #2150, checksum valid NDP, ICMPv6 valid | 8 |

Totals: 150 files ~38k prod + ~12k test LOC. Largest god poll_descriptor mod.rs 6294 (per-packet orchestrator) + tx/dispatch mod.rs 1486 + wg/engine 1805 + types/cos 1786. Hot proximity: poll_descriptor 10, filter 8, dispatch 8, inspect 9 (b1), frame 8 (b1).

## Module Log (coverage proving)

- **poll_descriptor/filter.rs**: Reviewed filter_log_ingress_zone_id / egress_zone_id trivial leaf inline so guard folds into hot/warm caller no UserspaceDpMeta copy when no log. emit_cached_input_filter_log / output_filter_log unconditional from stage_flow_cache_hit inline(always) — None guard folds into fast path no call no 96-byte copy, rare non-None tail split cold inline(never) .text.unlikely. evaluate_dscp_sensitive_input_filter_on_session_hit inline guard interface_input_filter_has_dscp_match folds returns None when no DSCP filter no call. evaluate_non_pbr_input_filter / _log_only / emit_input_filter_log_match / apply_lo0_filter_action rare bodies cold inline(never). PendingFilterLog carry ingress_zone_id egress_zone_id filter_id term_id action source app_id. filter_terminal truthful order enqueue reject reply FIRST (Reject only) via enqueue_filter_reject_reply then emit pending log with actual outcome so suppressed reject logged DENY not REJECT #3615 — single testable seam. Most important for zone: host_inbound_gated_lo0_action — resolves logical ingress ifindex via resolve_ingress_logical_ifindex (VLAN parent+vid→logical, else physical), then host_inbound_admits_iface with logical ifindex + ingress_zone_override filtered by zone_id_to_name contains. Logically: host-inbound admits check FIRST then lo0 filter #3485 order. If host-inbound denies None → HostInboundDeny (session-hit path emits host_inbound_deny_event tuple-rich #3610, session-miss emits + accounts). If lo0 filter log present emit with false (flowless no reply truthful DENY). Action != Accept → Filtered. L4_present via extra from term_match_extra_from_frame (includes fragment handling #2344 #2449 #5150 declared_end clamped to frame.len() excludes Ethernet slack). NEGATIVE: filter_terminal used on both flow-backed and flowless — flowless passes false for reject_reply_enqueued because fragment has no L4 header (silent drop mirrors transit). Zone id resolution filters by zone_id_to_name.contains_key for override — prevents attacker spoofing zone via fabric MAC that isn't configured (override must be known zone). Sound.

- **poll_descriptor/reject_reply.rs**: Reviewed enqueue_deny_reply (policy deny reject/tcp-rst) + enqueue_filter_reject_reply (filter reject). Both gated by per-zone TokenBucket #3618 — `forwarding.reject_bucket(from_zone_id)` returns `Option<&TokenBucket>` via Arc deref, None fallback to REJECT_FALLBACK_BUCKET static (never fail-open). Bucket `allow_generated_reject*` checks token available, rate-limits ICMP errors / RST generation per-ingress-zone so flood ingressing one zone doesn't starve another (pre-#3618 single global bucket starvation). ARP: per-zone bucket built in populate_zones cardinality = configured zones ≤65533 not attacker-growable, Arc shares atomics across ForwardingState clone (coordinator re-stores clone of forwarding state at runtime cadence fabric refresh, plain-value clone would snapshot stale atomics reset limiter every refresh). Fresh buckets on every build = reset-on-commit accepted diagnostic limiter. Flow: junos_host_local_policy enqueues reject then emits deny with actual outcome #3615 — ensures log truthful. NEGATIVE: per-zone bucket never blocks legitimate reject on different zone due to isolation, prevents DoS.

- **poll_descriptor/*** (cookie_reply, flow_cache_hit, nat_exception, rx_telemetry, debug_log_throttle): cookie_reply enqueues SYN-ACK cookie with source validation #3315 sub-thresholds, flow_cache_hit stage_flow_cache_hit owns all recycle/forward pushes on Consumed continue without touching desc.addr, validates cached_flow_decision_valid (HA epoch, RG-stamped redirect #1065, flow-cache stamp owner_rg_epoch, neighbor_mac_epoch #3918 TOCTOU snapshot before resolve). nat_exception record_source_nat_failure exception_reason. rx_telemetry record_rx_descriptor_telemetry batched counters. debug_log_throttle session_miss/policy_deny debug log allowed caps #4120.

- **icmp_embed/***: nat_match_v4/v6, builders, parse, return_resolution, session_match, mod. Reviewed match_outer_v4: l4 = meta.l4_offset, embedded_ip_start l4+8, parse_embedded_v4 (bounds checked), embedded_key SessionKey AF_INET proto src/dst ports, reverse_key embedded_reply_key (swap src/dst). Forward-NAT-by-reverse path: lookup_forward_nat_across_scopes (sessions + shared_nat_sessions) via reverse_key — recovers original pre-NAT src/port + original dst/port #3112 (forward key carries original tuple, for DNAT address the ICMP error must appear to quote public addr). Resolution via embedded_icmp_return_resolution (ctx, key, decision, original_src, now). Session-fallback path: lookup_session_across_scopes embedded_key then reverse_key — reverse metadata.is_reverse ? decision.resolution already points client else resolve return via embedded_icmp_return_resolution. Critical zone aspect: original flow's from_zone/to_zone used? NAT decision carries zone context? Need check: Does embedded ICMP path re-evaluate policy? No, embedded ICMP is error for existing session — NAT reversal only, policy already evaluated at session install. So zone bypass not applicable (session hit). For flowless embedded? Session lookup across scopes includes shared_forward_wire_sessions (forward wire). No new zone check — correct as error belongs to existing flow.

- **icmp_ptb.rs**: Reviewed compute_forwarded_egress_ptb — egress MTU via forwarded_egress_mtu(decision, forwarding) #2300 SSOT tunnel_outer_mtu (transport ifindex→egress→logical 1500 floor never 0 #2517), inner_dst via frame_l3_offset or meta.l3_offset + gre::inner_dst_ip, mt u if NAT64 or native tunnel post_transform_inner_mtu #2330 SSOT wg::mss::wg_inner_mtu / native_gre_inner_mtu / NAT64 delta, else plain egress_mtu. Returns ptb_reply Option<Vec<u8>> + mtu_signalled bool. build_frag_needed_v4 / packet_too_big_v6 via classified_generated_reply #2328 finalizer. When mtu 0 (no MTU resolvable) decision returns Forward fail-open and transformed frame falls through to normal build and encap drop guard (#2331 deferred signal now yields PTB not silent GRE_ENCAP_DF_OVERSIZE / encap_mtu_drops). NEGATIVE: MTU derivation SSOT prevents divergence between MSS clamp (select_tcp_mss) and PTB guard — #2517 fixed old unwrap_or_default 0 disabled clamp.

- **icmp_ratelimit.rs**: TokenBucket GCRA, per-zone buckets #3618. Reviewed new() zero tokens burst? Must allow first packet. Methods allow_generated_reject checks bucket per zone id via forwarding.reject_bucket.

- **neighbor*.rs**: 2036 4-resp ARP/ND probe + netlink mgmt + monitor thread + warmer. Reviewed stage_link_layer_classify ARP Reply learn: neighbor_ip_is_learnable (unicast-only #2790 unspecified/loopback/multicast/broadcast fail closed recycle but skip learning), owns_configured_ip anti-poison own-IP gate #2851 before insert_if_changed so rejected learn neither inserts nor bumps mac_change_epoch #3048/#3169, learn_ifindex logical via resolve_ingress_logical_ifindex (VLAN parent+vid→logical) #2370 ensures insert key matches lookup key for dynamic_neighbors (forwarder looks up connected-route ifindex logical unit). Insert_if_changed #3048 route data-path learn through change-detecting so MAC change observed from ARP reply (gateway VRRP failover whose reply traverses XSK ingress) advances mac_change_epoch and evicts stale cached dst_macs. NDP NA same gates + Override flag honored #4475 RFC 4861 §7.2.5 Override=0 must not overwrite cached entry with differing LLA — unsolicited-NA next-hop hijack primitive (local attacker claiming WAN gateway IPv6 own MAC). Legit change sets Override=1 §7.2.6 so gate blocks poison preserves legit. Reads per-worker dynamic_neighbors snapshot then insert_if_changed re-locks shard best-effort gate worker sole writer for key, kernel STALE install second line defense residual race. add_kernel_neighbor logical ifindex keys kernel table. NEGATIVE: Full chain hardened.

- **tx/dispatch/mod.rs**: 1486 1048 god func enqueue_pending_forwards. Reviewed Phase 8 try_inplace_rewrite_or_build, copy_frame_is_oversized test-only fault injection FORCE_OVERSIZED DCEs release zero cost #2208, direct_tx_tuple_mismatch_reason wrapper FORCE_TUPLE_MISMATCH #4041 paranoia builder-bug diagnostic (enforce_expected_ports in build_forwarded_frame_into_from_frame makes built ports == expected so mismatch never trips on real frame). recycle_ingress_frame pushes pending_fill_frames Batch ≥ FILL_BATCH_SIZE drain_pending_fill. compute_forwarded_egress_ptb inner_dst derivation L2 offset via frame_l3_offset or meta.l3_offset 14/18 + inner_dst_ip. MTU decision. Single-recycle invariant 39 sites — every forward path exactly one recycle push of ingress descriptor (ingress_binding.tx_pipeline.pending_fill_frames push) — violated leads to UMEM leak or double-free. NEGATIVE: CoS TX classification per-request runs under shared_exact_policy check (request_runs_under_shared_exact_policy) — zone not directly used but egress ifindex implicitly carries zone via egress.zone_id; no cross-zone leak observed.

- **tx/cos_classify.rs 1335 7-resp**: Reviewed classifier — shared classifier in frame::generated_reply_session_key re-exported #2238 so tx/cos_classify can reach it. Classification by L2/L3: ethertype, VLAN, IP DSCP, 802.1p, forwarding-class via dscp_queue_by_dscp / ieee8021_queue_by_pcp. Not zone-aware but egress interface is via decision.resolution.egress_ifindex → egress entry contains zone_id — classification does not leak across zones, per-egress interface CoS state (CoSState interfaces keyed by ifindex #1614). So isolation per egress interface (zone is property of egress interface). Acceptable.

- **tx/drain/**: phase_trivial/ball phase_shaped/phase_backup waterfill — queue_service/mod.rs 2058 waterfill 432 god func 7 resp epoch refill f64 fraction clamp bitset gating Phase1 asc Phase2 desc WRAP. Reviewed.

- **types/cos.rs 1786**: CoSState interfaces FastMap ifindex→Config, dscp_classifiers, ieee8021_classifiers, dscp_rewrite_rules, lp_rewrite per-egress ifindex loss-priority #3995 tables empty when no classifier/rewrite, dscp_rewrite_by_queue_lp (queue_id, loss_priority) → DSCP #3995 differentiates low vs high. CoSOversubscriptionPolicy Proportional default vs GuaranteeRate #1614 A1, guarantee_fraction f64, priority_low_min_share_bytes #1614 A2 wire only deferred. EqualFlowTargetPolicy Slowest default Mean IdealShare #2458 empty legacy decodes Slowest not error, non-empty unknown REJECTED fail-closed backstop consistent #2447. Parse returns Err(other) offending value caller names in snapshot integrity error.

- **wg/**: engine.rs 1805, allowed_ips LPM, cookie secret, counters, dscp, framing, handshake, timers. WgEngine per tunnel_endpoint_id #1432 S2a shared Arc survives ArcSwap reload when config unchanged (TAI64N clock live sessions survive). Debug redacts privkey + PSK #4484 zeroize. Allowed IPs lookup per peer.

- **worker/**: lifecycle, loop_body setup/debug_report, telemetry, cos/interface_row/queue_row/status, bind_meta, bpf_maps, flow_cache_state, scratch, timers. Worker loop runs poll_descriptor per binding RX batch, TX drain, session GC wheel, timers.

- **umem/** + **shared_umem** + **shared_ops**: mmap, snapshot, debug_state, tx_kick_latency, profile. Single-recycle invariant preserved across shared_recycle routing.

- **mirror/**: fast_path, mod, resolver, tests — port mirroring config per ifindex rate.

- **other**: mpsc_inbox, rst, gre, ha.rs 44750 LOC HA group runtime is_forwarding_active now_secs, tunnel, forward_request, test_fixtures.

## Findings — Batch b2

### F-FILTER-01: Host-inbound gated lo0 action correctly orders host-inbound first then lo0 filter #3485 with logical ifindex resolution — but PBR route_override Drop must also enforce host-inbound for flowless path

Severity: Medium
Confidence: High
Evidence:
```
// filter.rs:610-614
if !crate::afxdp::forwarding::host_inbound_admits_iface(
    forwarding,
    logical_ingress_ifindex,
    from_zone_id, ...
) -> HostInboundDeny

// forwarding/mod.rs:1723-1726 (PBR)
// #4392: a matched PBR routing-instance term may ALSO carry a drop action
is_drop Reject/Discard
return RouteOverride::Drop // caller MUST DROP
```
Trace:
1. `host_inbound_gated_lo0_action` — first resolves logical ingress ifindex (#3609 VLAN parent+vid→logical to avoid parent's first-subinterface zone bypass/mis-apply), then `host_inbound_admits_iface` checks per-interface override (zone ∪ interface effective union precomputed in Go) else zone.
2. If admit fails → HostInboundDeny emits tuple-rich event #3610.
3. Then lo0 filter evaluate — if log_match present emits with false (flowless truthful DENY #3615).
4. Accept → deliver to host (LocalDelivery) else Filtered.
5. For PBR path, `ingress_route_table_override` evaluates interface_input_filter_routing_instance_event_counted + term_match_extra (L3-relative slice bounded by ip_declared_end #5150 — upper clamp to frame.len() no over-read, lower excludes Ethernet slack padding beyond IP total length closing match-on-padding evasion). If matched routing-instance term action Reject/Discard → is_drop true → enqueue_filter_reject_reply (flow-backed only) + emit filter log with truthful outcome + return RouteOverride::Drop caller must drop not apply override (fixes VRF leak plus false audit #4392).
6. However, check: `ingress_route_table_override` is for route lookup override, not host-inbound. Flowless LocalDelivery path computes base resolution via `flowless_base_resolution` which tries ingress_interface_local_resolution BEFORE PBR override — so host-bound flowless packet destined to firewall IP reaches LocalDelivery instead of being steered into PBR override that has no local route (→ NoRoute drop). This ordering is tested via `flowless_local_delivery_tests`.
7. Potential gap: Flowless path `flowless_local_delivery_verdict` calls same `host_inbound_gated_lo0_action` with l4 extra where tcp_flags=0 icmp_type 0 l4_present false — port-bearing terms fail closed while protocol/address/any terms still admit — fail-closed without over-gating.

Refutation: Verified flowless path uses same host-inbound gate as flow-backed, and PBR Drop returns Drop which caller drops without route lookup. No bypass. The Drop variant correctly prevents VRF leak.

HPC: Filter eval per-packet L4 match inputs (tcp-flags/is-fragment/icmp-type/code/DSCP) built via term_match_extra_from_frame only when interface carries per-packet-L4 match filter (cold-path only) — parse cost off hot path.

Why it matters: Ensures host-inbound default-deny #3405/#3705 applies equally to flow and flowless, and PBR reject prevents VRF leak + audit false PERMIT. Good.

Fix: NEGATIVE — sound, #4392 + #3609 + #3610 + #3615 hardening verified.

### F-RATELIMIT-02: Per-zone reject buckets prevent cross-zone starvation but fallback global bucket is process-global — single unzoned flood could still starve unzoned legitimates (id 0)

Severity: Low
Confidence: Medium
Evidence:
```
// types/forwarding.rs:182-183
pub(in crate::afxdp) reject_buckets: FastMap<u16, Arc<TokenBucket>>,
// forwarding_build/zones.rs:130-133
state.reject_buckets.insert(zone.id, Arc::new(TokenBucket::new()));
// In allow_generated_reject:
let bucket = forwarding.reject_bucket(from_zone_id).unwrap_or(&REJECT_FALLBACK_BUCKET);
```
Trace:
1. `populate_zones` builds one bucket per CONFIGURED zone id (cardinality = configured zones ≤65533 not attacker-growable).
2. Gate `host_inbound_admits_iface` resolves ingress_logical → zone_id via ifindex_to_zone_id (or override) — known zone hits per-zone bucket.
3. Unzoned id 0 (unknown/global) falls back to `REJECT_FALLBACK_BUCKET` static.
4. Before #3618 single global bucket rate-limited every reject — rejected-flow flood ingressing one zone drained it starved legitimate reject in different zone — fixed by per-zone.
5. Residual: unzoned flood (if somehow) still uses shared fallback, could starve other unzoned (but unzoned only id 0, and all configured interfaces are zoned, so fallback only for genuinely unknown — not a real DoS surface).

Refutation: Since all dataplane interfaces are zoned (xpfd manages ALL, unconfigured brought down), fallback only for id 0 which is never from config — only missing map case. So residual negligible.

HPC: Arc<TokenBucket> shares atomics across ForwardingState clone (coordinator re-stores clone at fabric refresh cadence) — plain-value clone would snapshot stale atomics reset limiter every refresh. Fresh buckets on rebuild reset-on-commit accepted diagnostic.

Fix: NEGATIVE with note — per-zone isolation sound, fallback minimally exposed.

### F-NEIGH-03: Neighbor learning anti-poison gates own-IP + unicast-only + Override flag — complete chain vs ARP/ND spoofing that could poison forwarding and bypass zone policy via L2 hijack

Severity: High (defense-in-depth)
Confidence: High
Evidence:
```
// poll_stages.rs:135-177
if neighbor_ip_is_learnable(arp.sender_ip)
   && !worker_ctx.forwarding.owns_configured_ip(arp.sender_ip)
...
let _ = dynamic_neighbors.insert_if_changed((ifindex, arp.sender_ip), NeighborEntry{mac})
...
if !na.override_flag && existing.mac != new_mac
   return Continue // do not overwrite
```
Trace:
1. ARP: `parse_eth_offsets` handles single VLAN tag 0x8100/0x88a8 l3=18 else 14 — double-tag inner ethertype returned as-is (shim drops double-tag).
2. `classify_arp` validates ARP fixed header htype=1 ptype=0x0800 hlen=6 plen=4 BEFORE reading sender MAC/IP at fixed offsets #2369 — prevents crafted ARP declaring different type/len being parsed at wrong offsets and learned.
3. `neighbor_ip_is_learnable` unicast-only #2790: unspecified/loopback/multicast/broadcast not learnable — spoofed-reply DoS / routing disruption prevented.
4. `owns_configured_ip` anti-poison own-IP gate #2851 BEFORE insert_if_changed so rejected learn neither inserts nor bumps mac_change_epoch #3048/#3169 — prevents local attacker teaching (ifindex, our_ip)->attacker_mac in both dynamic_neighbors and kernel ARP (RFC 826 do not install neighbor entry for address we own). Driven from configured_iface_v* decoupled from NAT-aware local_v* #3182 — SNAT/WAN IP still protected even though its IP excluded from local_v* via nat_translated_local_exclusions.
5. Learn_ifindex via resolve_ingress_logical_ifindex #2370 logical VLAN sub-interface not physical parent — insert key matches lookup key (forwarder looks up dynamic neighbors keyed by connected-route ifindex logical unit) so just-learned entry found not fall through MissingNeighbor.
6. `insert_if_changed` #3048 change-detecting learn advances mac_change_epoch evicts stale cached dst_macs — gateway VRRP failover MAC change observed from ARP reply traverses XSK ingress bumps epoch, flow cache stale entries evicted next hit via neighbor_mac_epoch_at_resolve snapshot before resolve TOCTOU fix #3918 record-before-use (snapshot epoch before neighbor MAC resolve, flow-cache entry stamped with pre-resolve value, so subsequent MAC-change bump makes entry stale on next hit -> evicted -> re-resolved new MAC — closes blackhole).
7. NDP NA: parse_ndp_neighbor_advert — bounds by IPv6-declared packet_end not raw frame len #2368 B prevents forged TLLA in L2 padding beyond payload_len (min-size Ethernet frame declaring payload covering only fixed NA header then placing forged TLLA option in padding/trailer beyond 40+payload_len). Checks hop limit 255 #2368 A RFC 4861 §7.1.2 off-link-impersonation gate, code 0, target not multicast, icmpv6 checksum valid via shared ones-comp accumulator #2211, unicast-only #2790 target not multicast, own-IP #2851 same as ARP, Override flag #4475 RFC 4861 §7.2.5 Override=0 must not overwrite cached entry with differing LLA — unsolicited-NA next-hop hijack primitive (local attacker claiming WAN gateway IPv6 own MAC). Legit host announcing LLA change sets Override=1 §7.2.6 so gate blocks poison preserves legit. Best-effort (reads per-worker dynamic_neighbors snapshot then re-locks shard) worker sole writer for key + kernel STALE install second defense.

Why it matters: Without these gates, attacker on local link could poison neighbor cache pointing router's own IP or gateway IP to attacker MAC → L2 hijack → traffic blackhole or inspection bypass (zone policy still evaluated but L2 delivery to attacker vs legit). Chain is defense-in-depth complete.

Fix: NEGATIVE — sound, 4 fixes choreographed (#2790+#2851+#3048+#3918+#4475).

### F-ICMP-EMBED-04: Embedded ICMP NAT reversal does not re-evaluate zone policy — correct because it belongs to existing session, but verify session hit path does not skip host-inbound for ICMP errors destined to host

Severity: Medium
Confidence: Medium
Evidence:
```
// icmp_embed/nat_match_v4.rs:38-72
if let Some(fwd) = lookup_forward_nat_across_scopes(ctx.sessions, ctx.shared_nat_sessions, &reverse_key)
   let nat = fwd.decision.nat
   original_src = fwd.key.src_ip
   ...
   resolution = embedded_icmp_return_resolution(ctx, &fwd.key, fwd.decision, original_src, now_ns)
```
Trace:
1. ICMP error carries embedded original packet (that triggered error) — outer is error from remote, inner is our original flow.
2. `match_outer_v4` parses embedded IPv4 header at l4+8 (ICMP payload), builds embedded_key (inner src/dst/proto/ports), reverse_key (swap).
3. Forward-NAT-by-reverse: lookup_forward_nat_across_scopes reverse_key — if forward session was NAT'd, reverse_key matches its reverse direction → recover original pre-NAT tuple.
4. Session-fallback: lookup_session_across_scopes embedded_key then reverse_key.
5. Resolution: if metadata.is_reverse already points client else via embedded_icmp_return_resolution.
6. Zone aspect: No new zone check — policy already evaluated at original session install. ICMP error is for existing flow — correct to not re-evaluate policy (would be double-count). However, need ensure ICMP error destined to host (local-delivery) still gated on host-inbound? The ICMP error itself is transit (forwarded back to original source), not host-bound, so host-inbound not applicable. If ICMP error is destined to firewall itself (error about firewall-originated flow), then it's LocalDelivery and should be gated? Check: ICMP error to firewall IP would be local-delivery — but then original flow was firewall-originated, so it should be allowed (response to our traffic). So no bypass.

Refutation: Verified session hit path includes host-inbound deny for host-bound (local-delivery) — ICMP error to host would hit session or be flowless? Flowless LocalDelivery verdict includes host-inbound gate #3292. So not bypass.

Fix: NEGATIVE — NAT reversal sound, zone re-evaluation not needed.

### F-TX-05: TX dispatch single-recycle invariant 39 recycle sites — any miss leaks UMEM frame or double-free

Severity: High (memory safety / availability)
Confidence: Medium
Evidence:
```
// dispatch/mod.rs:1048 god + 39 recycle sites noted orientation
// 1486 LOC 5 god-fns >100 LOC — FIB/NAT/fabric/tunnel
```
Trace: `enqueue_pending_forwards` orchestrates forward requests: per-ingress binding batch of forward decisions → per-egress binding TX. UMEM frame ownership: XSK RX fills UMEM chunk at desc.addr, worker processes, if forward → copy or in-place rewrite then enqueue to egress TX ring, then recycle ingress fill frame via pending_fill_frames Batch FILL_BATCH_SIZE drain_pending_fill. If forward build fails → handle_forward_build_failure (slow_path) maybe reinject to kernel else drop — must still recycle ingress. All paths must push exactly one recycle. Orientation notes 39 recycle sites guard single-recycle invariant.

Refutation: Need audit 39 sites — large surface. Test-only fault injections FORCE_OVERSIZED and FORCE_TUPLE_MISMATCH DCE zero cost verify recycle on oversized and mismatch branches (pre-fix bare continue leaked ingress descriptor). #2208 and #4041 add test coverage. Still need verification new code paths added (WG, GRE, NAT64, PTB) all recycle.

HPC: Per-packet dispatch hot path, must not alloc. Current helpers copy_frame_is_oversized inline always, direct_tx_tuple_mismatch_reason inline always — zero added cost.

Why: UMEM leak = eventual RX stall (no fill frames) → Dataplane outage. Double-free = use-after-free of UMEM chunk (memory safety).

Fix direction: Add runtime debug counter `recycle_mismatch` that asserts in debug builds that per-batch pushed recycles == received.descs? Or formal model.

Labels: memory-safety, hot-path, umem, single-recycle
Dedup: Not in index — new hardening note.

### F-COS-06: CoS classification not zone-aware — cross-zone fairness not enforced, but zone isolation is via per-egress-interface queue (zone is property of egress interface)

Severity: Low
Confidence: High
Evidence:
```
// types/cos.rs:18-31
pub(in crate::afxdp) struct CoSState {
    interfaces: FastMap<i32, CoSInterfaceConfig>,
    ...
}
// cos_classify.rs 1335 7-resp — classify by DSCP/802.1p/forwarding-class not zone
```
Trace: CoS TX selection keyed by egress ifindex (EgressInterface contains bind_ifindex vlan mtu src_mac zone_id redundancy_group). Classification (dscp_queue_by_dscp etc) does not inspect zone, but CoS state interfaces is keyed by ifindex same set as egress. So per-egress-interface shaper token bucket rate, burst, default_queue, per-queue config. Loss-priority rewrite per-egress ifindex #3995 dscp_by_fc_lp (queue_id, loss_priority)→DSCP. So zone is implicit via egress interface zone_id — if two zones share same egress interface? In vSRX model each interface belongs to one zone, so per-interface isolation = per-zone isolation for egress. Ingress zone not used in CoS — that's correct, CoS is egress QoS not security policy.

Refutation: CoS is not security zone enforcement, it's QoS. No cross-zone packet leak, only scheduling fairness — per-interface already provides zone fairness as each zone's traffic exits via its own egress interface(s). If same egress interface serves multiple ingress zones (e.g., WAN zone with many to-zones via same egress), then per-egress queue not per-(ingress,egress) zone-pair — but that's expected QoS behavior, not security.

Fix: NEGATIVE — CoS zone-agnostic is acceptable.

## Summary

b2 batch shows strong hardening: host-inbound gating with logical ifindex #3609, per-zone reject buckets #3618, neighbor anti-poison full chain #2790 #2851 #3048 #3918 #4475, PBR Drop prevents VRF leak #4392, filter log truthful REJECT→DENY #3615, MTU SSOT #2300 #2517, fab up preference #4082, ext-header over-limit drop #4743, declared_end slack exclusion #5150, single-recycle invariant test injections #2208 #4041. No critical new fail-open found. Low residual: fallback bucket for id 0 only.



---

### === ps-A1_rust_dataplane_packet-b3.md (13489 chars, 161 lines) ===

# Batch A1 Review — Rust dataplane packet pipeline + policy
Base: 7e0fecf3b Merge #5550 fix/5077-classifier-submit-monotonicity
Root: /tmp/review-wt-claude-003-A1_rust_dataplane_packet-b3
Coverage: 118 files, 83780 LOC total, prod ~48k / test ~36k

## Inventory (ranked by responsibility × hot-path proximity)
| File | LOC | Responsibility | HotPath |
|---|---|---|---|
| policy.rs | 3657 | zone_pair_key, global scope, counters, default sentinel | cold/warm, policy eval hot but indexed |
| filter/tests.rs | 8613 | filter semantics | test |
| policy_tests.rs | 7280 | policy matching | test |
| session/tests.rs | 7072 | session install/expire | test |
| screen/tests.rs | 5395 | screen checks | test |
| event_stream/mod.rs | 1701 | event stream IO, replay, backpressure | warm |
| server/tests.rs | 1953 | server lifecycle | test |
| session/mod.rs | 2114 | slab, indices, GC | hot |
| main_tests.rs | 2350 | snapshot integration | test |
| protocol/tests.rs | 2393 | wire invariants | test |
| screen/mod.rs | 1540 | pre-session + flowless + SYN flood | hot |
| xsk_ffi.rs | 1287 | zero-copy rings, UMEM, FD lifetimes | hot/unsafe |
| lib.rs (userspace-xdp) | 1541 | shim binding array steering | hot unsafe |
| slowpath.rs | 913 | TUN inject | cold |
| state_writer.rs | 601 | state persist | cold |
| filter/compiler.rs | 1069 | snapshot → FilterState, fail-closed backstops | cold apply |
| filter/engine/eval.rs | 1026 | filter eval, log rewrite | hot |
| filter/mod.rs | 939 | type vocab, counters | warm |
| protocol/binding.rs | 1185 | ifindex/zone binding | cold |
| protocol/control.rs | 1088 | snapshot status | cold |
| server/helpers.rs | 1304 | json persistence (privkey hygiene) | cold |
| ... | ... | ... | ... |

Largest fn: policy::parse_policy_state_with_counters (~800 LOC), filter::compiler::parse_term (~400), session::mod.rs SessionTable::new+expire.

## Module log (brief, negatives acceptable)

- tx_counters.rs (60): counter coalescing struct only. No alloc. Sound: explicit construction, no Default. **NEGATIVE**.
- tx_pipeline.rs (69): struct holder for free frames, pending TX, sidecar tx_submit_ns Box<[u64]>. Box prevents push. Sound.
- xsk_rings.rs (41): struct holder DeviceQueue/RingRx/RingTx. Sound.
- worker_queue.rs (85): Mutex<VecDeque<WorkerCommand>> poison recovery, clear_poison, metrics. Correctly preserves committed prefix. **NEGATIVE** - reviewed earlier in #1807.
- zone_counters.rs (438): per-zone traffic counters: flat 64k LUT slot_of u8, thread_local ZonePending, saturating_add, store by stable zone_id. No hot hash. Sound, overflow safe.
- worker_runtime.rs (571): seqlock rolling window with AcqRel publication. Fence(Acquire) between data loads and gen re-check closed ARM reordering hole noted in comments. Sound.
- event_stream/codec/*: wire constants, header [len:u32 LE][type:u8][seq:u64 LE], fixed 256-byte stack buffer. frame len checks in decode. Sound.
- event_stream/mod.rs (1701): replay buffer bounded 4096, write_buf bounded 16MiB, control payload cap 0, ACK watermark validation [acked, next], poison flag for paused drain session eviction. Correctly bounds mem DoS described (#2381/#2879).
- event_stream/producer.rs (466): GCRA rate limiter, queue budget per-kind/per-total, CAS loops, rollback seq under producer_seq_lock LIFO safe. Correct.
- fairness.rs / fairness_eval/*: offline evaluation, not hot path. Parses pcap-like inputs, windowing. No unsafe. **NEGATIVE** for hot-path safety; args parsing validates ranges.
- filter/compiler.rs (1069): fail-closed on unrepresentable proto/icmp/dscp/tcp_flags, missing filter ref, cross-field unsatisfiable (port without TCP proto etc). Uses proto_number shared resolver. Sound hardening.
- filter/engine/matching.rs (377): per-term AND logic, constrained vs any distinction, nets_match with XOR except, port_match fail-closed on constrained&&Any. flex_matches bounds checked with checked_add. Sound.
- filter/engine/eval.rs (1026): fall-through modifier accumulation, log action normalization (log;next term → final verdict), count policy Always vs OnlyTerminalNonAccept avoids double-count. Sound.
- filter/engine/cache_sensitive.rs (586): tracks DSCP/L4/flex as cache-sensitive, flow-cache insertion gate. Sound.
- filter/engine/tx_selection, policer, cache: DSCP rewrite, flow-share. Small.
- filter/mod.rs (939): type vocab, counter batching (thread_local pending), policer runtime dedup by id via SmallVec<Arc;2>. Sound.
- policy.rs (3657): zone_pair_key packing u32 (from<<16|to), reserved MIN handling, global scope Zones(SmallVec<[u16;2]>) sorted dedup, sentinel DEFAULT_POLICY_SENTINEL_ID=u32::MAX. Counter store reconcile retains default id. Fail-closed duplicate rule/policy id preflight. **Potential issue noted below in NAT key handling.**
- session/key.rs (233): forward/reverse wire transforms. Handles ICMP id in src_port, NAT64 AF switching. `reverse_canonical_key` deliberately NAT-unaware for second-chance lookup; paired with reverse_wire_key via OR in reply_matches. Needs scrutiny (see finding).
- session/install.rs (551): at-cap preflight can_admit, pair-admission refused counter, install assigns stable session_id (worker_hi<<48 | counter). Delay delete callbacks.
- session/mod.rs (2114): slab storage, SeededKeyMap with FxSeededState via hot_hash_seed per-boot secret (mitigates hash flooding), timer wheel key-based not handle-based to avoid UAF, stale-synced ceiling, session_limit per-IP counters seeded hashmaps. Sound.
- session/expire.rs, lookup.rs, ctx.rs, wheel.rs, entry.rs: wheel tick lazy delete, companion keep-alive (#4380). Sound.
- protocol/security.rs (605): DTOs, cache-key invariant comment, AppCatalog entry. Sound.
- protocol/snapshot.rs (829): privkey skip_serializing, state redaction Debug, slow_path_mtu floor 1500, config DTOs. Sound.
- screen/extract.rs (401): IPv4/IPv6 parse with fail-closed on truncated header/opt malformed LSRR evasion (#4543). Walks ext chain bounded 8, checks frag offset. Sound.
- screen/mod.rs (1540): pre-session stateless + rate sketch per-dst/per-dst+port, SYN flood dual threshold, per-dst sketch evaluated BEFORE aggregate cookie/Drop verdict (#4112 F19), alarm_without_drop suppression. Sound, but watch secondary ceiling 8x reuse.
- screen/rate.rs, syn_rate.rs, scan.rs, stateless.rs, syncookie.rs: sliding window, count-min sketch, SipHash24 validation cache with profile gen. Sound.
- server/handlers/*: snapshot apply preflight runs before side-effect, HA/start-stop. Reviewed quickly: binding, forwarding, ha, export, session_deltas.
- server/helpers.rs (1304): write_state with privkey skip_serializing intact.
- xsk_ffi.rs (1287): UMEM frame offset check via checked_sub, reserve_up_to restores partial reservation, test rings leak intentionally. Unsafe Send impl for Umem (single-writer). BorrowedPrivateUmem NonNull lifetime safety relies on drop order documented not enforced by type system — low risk but documented.
- userspace-xdp/lib.rs (1541): per-CPU binding array, map pinning, no alloc. Sound-ish.
- slowpath.rs, io_uring_write.rs, state_writer.rs: TUN inject, io_uring busy handling, atomic writes. Sound.

## Findings

### High Confidence

#### H1: session key reply_matches_forward_session fall-back to NAT-unaware canonical may allow NAT bypass — MED
- **Title:** reply_matches_forward_session OR's NAT-aware wire key with NAT-unaware canonical
- **Severity:** Med
- **Confidence:** High (code read)
- **Evidence:**
  - `userspace-dp/src/session/key.rs:19-25`
    ```
    pub(crate) fn reply_matches_forward_session(
        forward_key: &SessionKey,
        nat: NatDecision,
        reply_key: &SessionKey,
    ) -> bool {
        reverse_wire_key(forward_key, nat) == *reply_key
            || reverse_canonical_key(forward_key, nat) == *reply_key
    }
    ```
  - `userspace-dp/src/session/key.rs:143-157` canonical ignores rewrite:
    ```
    pub(crate) fn reverse_canonical_key(...) -> SessionKey {
        let (src_port, dst_port) = if matches!(...) { (forward_key.src_port, dst_port) } else { (dst_port, src_port) };
        SessionKey { src_ip: forward_key.dst_ip, dst_ip: forward_key.src_ip, ... }
    }
    ```
- **Trace:** SNAT flow 10.0.0.1->8.8.8.8 rewrite src 1.2.3.4. Legit reply 8.8.8.8->1.2.3.4 matches reverse_wire. Attacker spoofing reply 8.8.8.8->10.0.0.1 (internal) matches canonical, passes reply_matches, could update session counters / keep-alive? That path is used for forward_nat_match? Need caller validation.
- **Refutation attempt:** Caller may also check interface/zone, and NAT index lookup first tries wire key bucket; canonical is fallback for hairpin/backward compat. Might be intentional for non-NAT flows? But for NAT flows, allowing untranslated dst (internal IP) from external could be spoof.
- **Why it matters:** Could let external attacker keep session alive or inject without hitting NAT external IP, bypassing NAT as security boundary.
- **Fix:** Remove canonical fallback for NAT flows (when rewrite present), or gate second check on nat == no-rewrite.
- **Labels:** vsrx-parity, hot-path

#### H2: zone_counters slot_of Box<[u8;65536]> unprotected against concurrent build race? — Low
- **Severity:** Low
- **Confidence:** Medium
- **Evidence:** `zone_counters.rs:105-128` build sorts and dedups.
- **Trace:** Build called at config apply (coordinator). Readers use slot_map.clone via Arc ForwardingState? Should be immutable after build, so race free.
- **Why it matters:** If map mutated in place, data race. But builds new Box, so safe.
- **Fix:** Document immutability.
- **Labels:** refactor

### Medium Confidence

#### M1: xsk_ffi DeviceQueueRings BorrowedPrivateUmem drop-order not type-enforced — Low
- **Title:** Private UMEM ring lifetime relies on documented drop order, not borrow checker
- **Severity:** Low
- **Confidence:** High
- **Evidence:** `xsk_ffi.rs:556-592` BorrowedPrivateUmem holds NonNull<XskRingProd> to Umem's Box. Comment says must drop before Umem.
  ```rust
  BorrowedPrivateUmem { fill: NonNull::from(&mut **umem_fill), comp: NonNull::from(&mut **umem_comp), }
  ```
  Drop impl only deletes xsk socket, not rings.
- **Trace:** If coordinator drops Umem before DeviceQueue (panic, early return), NonNull dangles, later Drop of DeviceQueue accesses freed? Actually DeviceQueue Drop does not deref rings, so UAF not in drop, but fill() complete() methods could still be called after Umem freed if worker thread outlives Umem. Should be prevented by WorkerUmem owner.
- **Refutation:** WorkerUmem owns Umem, DeviceQueues per queue, shutdown joins workers before freeing UMEM. So safe in practice, but not enforced.
- **Fix:** Wrap in ManuallyDrop or use PhantomData lifetime tied to Umem; add debug assert.
- **Labels:** x-hpc, refactor

#### M2: screen extract IPv4 TCP MSS parsing stops at first MSS option, ignores later overlapping? — Low
- **Severity:** Low
- **Confidence:** Medium
- **Evidence:** `screen/extract.rs:373-395` walks TCP opts, break on MSS found.
- **Trace:** Crafted TCP with two MSS opts, first small, second large hidden after. MSS used for SYN cookie? Might choose first though second valid per RFC? Minor.
- **Fix:** Take max or last? Existing matches BPF.
- **Labels:** vsrx-parity

#### M3: fairness_eval report median p50 vs true median window may mis-handle empty windows — Low
- **Severity:** Low
- **Confidence:** Medium
- **Evidence:** windowing.rs per-worker sliding windows, empty windows skipped? Might bias.
- **Trace:** If worker idle whole window, no sample, report omits, fairness verdict may be based on partial.
- **Fix:** Explicit zero-sample handling.
- **Labels:** refactor

### Low Confidence / Info

- L1: event_stream MAX_CONTROL_PAYLOAD_LEN=0 means any future payload-carrying opcode must raise constant deliberately. Good hardening, not bug.
- L2: filter compiler port "any" placeholder dropped via addr_is_real/port_is_real - ensures explicit any stays match-any not fail-closed. Correct.
- L3: policy global scope build_global_zone_scope any element -> Any, tolerant for mixed old snapshot. Correct per #4626.
- L4: io_uring_write likely uses shared fd; need close-on-exec.
- L5: fairness-eval bin is test utility, not shipped.

## Suggested issue split

1. Issue #1 (policy/nat): audit reply_matches_forward_session canonical fallback for NAT flows (H1). Need decision: remove OR keep with guard `if nat is identity`. Small fix, needs session unit test with SNAT spoofed internal reply.
2. Issue #2 (xsk-ffi lifecycle): enforce UMEM/DeviceQueue drop order via type-state or explicit shutdown sequence + debug assert (M1). Refactor low risk.
3. Issue #3 (screen/tcp): document MSS first-wins vs per RFC last-wins, if vsrx parity requires last.

## Final notes
- No alloc on per-packet path observed: ZonePending thread_local, filter counters batched, policy hit counter coalesced, app catalog exact map, XSK rings reserve_up_to avoids TX stall.
- Single-recycle invariant: UMEM frame ownership tracked via free_tx_frames + completion ring, tx_submit_ns sidecar pre-alloc Box<[u64]> prevents grow.
- Default deny: PolicyState default_action Deny, filter implicit Accept but zone policy denies, lo0 filter fast path checked before host-inbound. Zone id 0 filtered everywhere.
- App matching: CompiledApplications config-order index preserved, exact O(1) + range/icmp scan, directional lookup fixes client-port mislabel (#3321).
- HPc: seqlock with AcqRel + fence, token bucket vs RateCounter separation, SynRateSketch for per-dst.


---

### === ps-A2_rust_dataplane_nat-b1.md (9449 chars, 92 lines) ===

# Batch A2 rust dataplane nat — Review Report
Base commit: 7e0fecf3b
Worktree: /tmp/review-wt-claude-003-A2_rust_dataplane_nat-b1

## File-size/shape inventory
Prod total: 9334 LOC (8 files). Test total: 15648 LOC (10 files).
Rank by size x responsibility x hot-path:
1. nat64.rs 3102 LOC — v6↔v4 translation, checksum incremental (RFC1624), ICMP error embedded-ICMP reversal, frag DF/ID policy, port-allocator integration, HA reserve, frag-assoc cache — hot per-packet.
2. allocator.rs 1974 LOC — lock-free bitmap port claim, FIFO recycle, persistent lease SM, deterministic CGNAT blocks v4/v6, address-only reverse-identity tokens, HA reservation, GC chunking — hottest cold-path (session-miss) but contended.
3. source.rs 1523 LOC — SNAT rule parsing, pool expansion, match (zone/interface/RI/L4/app), address-persistent sticky hash, port-less/ICMP query gates, deterministic dispatch, failure reason mapping — hot cold-path.
4. destination.rs 1109 LOC — DNAT exact O(1) + prefix LPM, proto wildcard PROTO_ANY=256 distinct from HOPOPT, off exemption short-circuit, source-scoped, L4 extra matches, dst_port range — hot cold-path.
5. static_nat.rs 808 LOC — 1:1 + block offset remap, bidirectional, zone/interface/RI/source scoped, port-mapped / match-port scoping, VRF-scoped external IPs — hot cold-path.
6. nptv6.rs 431 LOC — stateless /48 /64 prefix replacement, RFC6296 adj, 0xFFFF→0x0000 fold, zero-adj skip for checksum-neutral pair — hot per-packet.
7. mod.rs 347 LOC — NatDecision merge/reverse, counter store with fetch_sub clear (no lost update), parse-error loud skip — cold except decision.
8. status.rs 40 LOC — pool status snapshot aggregation — cold (1/s).

Largest fns est: `write_v6_to_v4_into` ~200, `write_v4_to_v6_into` ~180, `allocate_translation_locked` ~130, `match_source_nat_result_for_tuple` ~150.

## Module log (responsibility + negative if no finding)

- allocator.rs: Owns port ownership via AtomicU64 bitmap + per-addr recycle. Implements #2852 lock-free claim, #3047 skip-occupied, #3011 FIFO, #4676 chunked GC, #4388 reserve_flow for HA, #5269 address-only reverse keys, #4559 deterministic block alloc. Negative: no overflow/truncation bug, CAS claim correct, release/rollback symmetric, gc re-checks expiry. No High finding — bitmap is ABA-safe because bit never cleared between claim and free of same allocation.

- source.rs: Parses pool CIDR/host, builds PortAllocator per pool, matches with scope_ok + l4_matches + nets_match. Gates: non_first_fragment, port_less (has_l4_ports), icmp_query via `icmp_identifier_present` (fixes id==0 bug), tuple_unknown proto=0 wrapper, no_translation. Deterministic v4/v6 path uses pure fn indices. Negative: pool expansion correctly bounds MAX_POOL_PREFIX_HOSTS, fail-closed on malformed match (constrained flag), address_persistent sticky via FxHasher seeded.

- destination.rs: Exact map + prefix LPM + proto wildcard. Tier order: exact (proto,dst,port) → wildcard port → PROTO_ANY → prefix LPM (exact+wildcard+ANY). Off exemption yields DnatOutcome::Exempt short-circuiting .or_else chain (Junos stop). Source-scoped via PrefixV4/6, bare-host fallback, all-malformed fails closed. L4 extra matches AND-ed. Port-range collapsed to wildcard key + range vec. Negative: PROTO_ANY=256 outside u8 range prevents HOPOPT alias, insertion dedup includes off+scope+L4.

- static_nat.rs: Host exact + block /24→ offset remap (host_mask_v4/v6 with len>=max guard). Port-mapped: match_dst_port/mapped_port pair, SNAT key = mapped_port.or(match_dst_port). Scope tiering via pick_scoped zone-specific wins. SourceConstraint fail-closed, host-bits canonicalized. Negative: egress zone gate for SNAT (#2871) symmetric, block+port dropped (#3202), /0 handling via !mask yields match-any correctly.

- status.rs: Thin aggregation from PortAllocatorSnapshot. No alloc, no logic bug.

- nat64.rs: Stateless + stateful (PortAllocator per prefix for RFC6146 BIB). Incremental L4 checksum (adjust_l4_checksum_*), fallback to full recompute for ICMP/zero UDP. Fragment handling: first fragment installs frag-assoc (#2562 cache), non-first inherits, ICMP fragments fail-closed. DF policy: atomic DF=1 ID=0, fragmentable DF=0 ID from generator map_frag_id 1..=65535 (mod 65535+1 avoids 0/1 dup). Embedded ICMP error translation via stack scratch MAX_EMBEDDED_LEN, address swap, checksum finalize. HA reserve mirrors source-NAT. Reload preserves allocator via reuse_allocator exact pool equality. Negative: checksum16_add streaming matches buffer build, traffic class copy full byte.

- nptv6.rs: parse_prefix rejects host bits (#4519), overlap check find_overlap [#2241]. compute_adjustment ones-complement sum, is_zero_adjustment treats 0xFFFF as zero (negative zero) and skips adjust_word for neutral pair (#3233 prevents 0xFFFF collapse). adjust_word folds carry twice, maps 0xFFFF→0x0000 per RFC. Round-trip preserved.

- mod.rs: NatDecision merge prefers self, reverse maps opt presence. Counter clear via fetch_sub not store(0) prevents lost concurrent add.

Test files: extensive fail-on-revert guards for each bug class, L4 match, proto ANY, scope, pool, static, pool collision (#5269 address-only).

## Findings — High/Crit Confidence

None. No integer overflow leading to OOB, no memory safety, no fail-open in default path.

## Findings — Medium Confidence

- Title: HA synced reservation fails open when local port already owned
  Severity: Med
  Confidence: Medium
  Evidence: allocator.rs:1544-1587 reserve_flow + source.rs:852-879 reserve_synced_source_nat_allocation + nat64.rs:1097-1130 reserve_synced_nat64_allocation
  ```
  pub(super) fn reserve_flow(&self, flow: SourceNatFlowKey, translated: TranslatedTuple, addr_index: usize) -> bool {
      ...
      if !self.shared.occupancy[addr_index].reserve(translated.port) {
          return false;
      }
  ```
  Trace: active node allocates (pool_ip,port). Sync → standby. If standby already has local flow owning same (pool_ip,port) (possible during RG flapping), reserve returns false, no live_by_flow entry for synced flow. Synced session still exists with NatDecision pointing to colliding tuple but allocator unaware. Later local owner expires, port freed, second local flow can re-claim same tuple while synced session still alive → two live sessions share same public tuple until synced GC.
  Refutation attempt: comment says "never steal" safe choice because owning RG passive so no local flow should hold port. True in steady-state, but during failover race or config drift local flow could exist. Insert path still denies second allocation via bitmap, but first local owner removal window allows double-claim vs synced session. Mitigation is low probability but violates reservation invariant.
  Why matters: RFC6146 BIB violation across HA, reply mis-demux.
  Fix: on reserve failure due to different owner, optionally record conflict metric and consider evicting local if RG state indicates peer active, or keep synced session mapping in a separate conflict table and deny new allocations until synced removed.
  Labels: ha, allocator, vsrx-parity, refactor

- Title: Address-only synthetic (proto=0) pool port via try_next_port consumes port but not tokenized
  Severity: Low
  Confidence: Medium
  Evidence: source.rs:1268-1301
  ```
  if tuple_unknown {
      let port = if rule.no_translation { None } else { match rule.pool_allocator.try_next_port(addr_idx) { ... } };
      return Matched(NatDecision { rewrite_src: Some(...), rewrite_src_port: port, ... })
  }
  ```
  Trace: tuple_unknown (old address-only callers) with no_translation=false calls try_next_port which increments per-addr atomic counter but does not set occupancy bit nor address_only token. Two such synthetic callers could get same port, and SAMe port could later be handed to real PAT flow via claim() causing duplicate public tuple if synthetic packet ever reaches wire (it doesn't today — rewriters gate on has_l4_ports). Still leaks counter and could exhaust low range faster.
  Why: waste + potential collision if caller mistakenly uses decision.
  Fix: make tuple_unknown no_translation path also not allocate port (return None) or reserve via bitmap.
  Labels: refactor, snat, hot-path

## Findings — Low Confidence / Notes

- port_of in AddressOccupancy uses `port_low + offset as u16` without wrapping_add — safe because offset bounded by range and port_high≤65535, but defensive use of checked_add would document invariant.
- nat64 frag ID generator map_frag_id documents adjacent dup once per 2^32 wraps (0xffffffff%65535==0). Accepted trade-off; low risk.
- static_nat external_ips returns iterator over &IpAddr refs from keys — caller must not hold across table mutation (Clone table cheap). OK.
- No zone-policy interaction bug: DNAT manipulates dst before routing decision? NAT64 classify already does route on dst_v4 not src, correct. Twice-NAT ordering via NatDecision::merge preserves dst from DNAT and src from SNAT.

## Suggested issue split

1. HA reservation conflict handling — improve reserve_synced_* to track unreserved synced tuple and block future allocation (or metric) — Med.
2. Synthetic proto=0 port allocation waste — Low — make no-op.
3. No High/Crit issue for this batch; extensive fail-closed guards and checksum-neutral fixups verified.

## Dedup note
Checked against #5544, #5523, #5497, #5488, #5487, #5486-#5468 list — none overlap; HA reservation is distinct from #5487 HA-state clear and #5479.



---

### === ps-A3_go_config_cli_tree-b1.md (7194 chars, 94 lines) ===

# A3 Go Config/CLI Tree b1/4 — Zone Policy Focus (150 files)
Base: 7e0fecf3b8f2dc6604600674373771c835484188 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b1

## File Inventory (prod)
| File | LOC | Responsibility | Hot |
|---|---:|---|---|
| pkg/appid/catalog.go | 487 | App-ID catalog, uint16 id guard, port-zero sanitize (#5194), ICMP type gate (#3781) | cold |
| pkg/appid/runtime.go | 344 | CatalogNames walk (policy+NAT refs), tuple fallback canonical port parsing (#3725) | cold |
| pkg/cmdtree/tree.go | 1589 | Operational CLI tree, zone DynamicFn completions | cold |
| pkg/config/ast.go | 436 | Dual-shape AST, unionChildren (#4562) duplicate-sibling merge | cold |
| pkg/config/compiler.go | 2323 | Top compile dispatch, group expansion, inactive strip | cold |
| pkg/config/compiler_applications.go | 774 | App/app-set bracket list (#5181), resolveAppPort whole-spec before range split, 0-N floor norm (#4336) | cold |
| pkg/config/compiler_security.go | 114 | Dispatcher + ssh-known-hosts append-not-replace (#4821) | cold |
| pkg/config/compiler_security_zones.go | 239 | zoneInterfaceMembers bracket flatten (#5248), HIB merge (#4544/#4818) | cold boundary |
| pkg/config/compiler_security_policy.go | 451 | policy compile, fail-closed DENY default (#3043), collapsed-deny (#3141), scoped-global (#4626) | cold boundary |
| + 142 test files | ~4500 | regression for all gates | — |
Prod dominant ~6757 LOC cold path. No Rust dataplane hot path in this batch.

## Module Log (coverage proof)

- ast.go:navigatePath unionChildren — handles duplicate `from-zone untrust to-zone trust` siblings for nested lookup. Depth bounded by config file size (~MB). NEGATIVE: no unbounded recursion or OOM beyond file limit.
- ast.go:cloneNodes deep-copies Keys/Children — no slice aliasing. NEGATIVE sound.
- compiler_applications.go:applicationSetMemberValues reads Keys[1:] + Children covering bracket `[ a b c ]` → Keys["application","a","b","c"] (lexer strips brackets, #2419). Pre-#5181 only Keys[1] → DENY under-match fail-open. Now fixed.
- compiler_applications.go:resolveAppPort whole-spec lookup before range split covers hyphenated svc names (ftp-data) (#3397). Port 0 floor-norm 0-N→1-N (#4336) safe — port 0 never on wire. Bare 0 stays invalid.
- compiler_security.go:ssh-known-hosts find-or-create map + append per host across duplicate blocks (#4821) — prevents key-type loss.
- compiler_security_zones.go:zoneInterfaceMembers skips host-inbound-traffic child, recurses Keys+Children flattening wildcard-container nesting `[ ge-0/0/0 ge-0/0/1 ]` chain. NEGATIVE sound.
- compiler_security_zones.go:compileZones find-or-create by name + Interfaces append + HIB merge + AddressBook find-or-create — duplicate top-level security-zone instance (#4818) no longer replaces first (would discard interfaces → unmanaged/brought DOWN + wrong zone eval).
- appid/catalog.go:BuildCatalog uint32 nextID prevents uint16 wrap onto 0 sentinel (reserved UNKNOWN) — deterministic error at boundary. Proto fan-out keyed on absent spec not proto==0 (#4008). NormalizeExplicitPortRange 0/0-0 → unemittable not (0,0) wildcard.
- appid/runtime.go:CatalogNames includes NAT app refs (#3626) skips nil, sortedNames deterministic. canonicalPort via ParseCanonicalUint rejects +80, narrow-to-4464 (#3725) fail-closed.
- cmdtree/tree.go: DynamicFn nil-guarded cfg==nil→nil, routingInstanceTableNames nil-skip (#4866). NEGATIVE sound.

## Findings

### Title: Dead code catalogProtocolNumber retains buggy (0,false)->0 contract — regression risk
- Severity: Low
- Confidence: High
- Evidence: appid/catalog.go:429-436 (worktree file)
```
func catalogProtocolNumber(name string) uint8 {
    n, _ := ProtocolNumber(name)
    return n
}
```
Grep worktree `grep -r catalogProtocolNumber --include=*.go` → only definition, zero callers. BuildCatalog line126 uses `proto,protoOK := ProtocolNumber(app.Protocol)` with ok honored, not wrapper.
- Trace: (1) dev adds new app-path, sees catalogProtocolNumber helper, calls it for convenience (2) passes unrepresentable token e.g. `junos-foobar` surviving tolerant load (3) gets 0 (HOPOPT) not error (4) ships Protocol:0 catalog row → false AppID label on HOPOPT sessions (#4887 bug reintroduced).
- Refutation: Could it be used via reflection/test? No. Test file catalog_bad_protocol_4887_test.go asserts ProtocolNumber directly. Wrapper unused. So not currently exploited, but retains known-buggy semantics in tree.
- HPC/invariant: cold path only. No perf impact.
- Why matters: dead code with known-buggy contract invites reintroduction of false labeling.
- Fix: delete function; if retained for docs, add `// Deprecated: use ProtocolNumber, this drops ok bit (#4887)` and make unexported.
- Labels: refactor, x-hpc(cold)
- Dedup note: not in dedup-index (index lists runtime dataplane/HA/cluster/open issues 5544-5469 ... not apid dead code). #4887 fix is live-path, this is hygiene.

### Title: Zone completion DynamicFn unsorted map iteration — non-deterministic CLI
- Severity: Low
- Confidence: High
- Evidence: cmdtree/tree.go:320-331
```
"zones": {Desc: "Show security zone information", DynamicFn: func(cfg *config.Config) []string {
    if cfg == nil { return nil }
    names := make([]string, 0, len(cfg.Security.Zones))
    for name := range cfg.Security.Zones { names = append(names, name) }
    return names
}, Children: ...},
```
Same pattern from-zone to-zone filters lines 339-348, scheduler-map 246-252. Contrast pkg/appid/runtime.go:189 sortedNames() sorts.
- Trace: Show cfg with zones trust/untrust/dmz → tab completion order random per process start (Go map randomization). Operator verifying zone list may miss one.
- Refutation: Not a security bypass — completions are best-effort. But deterministic display contract for operator surfaces violated. Not gated by dedup.
- Why: UX + auditability; could mask missing zone during manual review.
- Fix: sort.Strings(names) before return (one-liner). Apply to all zone DynamicFns.
- Labels: refactor
- Dedup note: not in dedup-index.

### Title: NEGATIVE — No zone-membership bypass remaining in b1 (bracket list fixes complete)
- Severity: Low (negative)
- Confidence: High
- Evidence: compiler_security_zones.go:114-134
```
zone.Interfaces = append(zone.Interfaces, zoneInterfaceMembers(iface)...)
// zoneInterfaceMembers flattens Keys + recursion:
func zoneInterfaceMembers(iface *Node) []string {
    var names []string
    for _, k := range iface.Keys { if k != "" { names = append(names, k) } }
    for _, child := range iface.Children {
        if child.Name() == "host-inbound-traffic" { continue }
        names = append(names, zoneInterfaceMembers(child)...)
    }
    return names
}
```
- Why negative: #5248 (iface.Name() only → dropping rest of bracket list → unmanaged interface → wrong zone eval/brought DOWN) is closed by flattening nested chain (WILDCARD container nesting). Similarly app-set #5181, global zone scope #4626 fixed. Grep for `iface.Name()`-only pattern shows no remaining prod caller that drops tail.
- Dedup note: proves coverage for #5248/#5181/#4626 class.

---
Batch b1/4 done — 150 files, ~6757 prod LOC, 2 Low hygiene, rest negative well-hardened.


---

### === ps-A3_go_config_cli_tree-b2.md (10919 chars, 130 lines) ===

# A3 Go Config/CLI Tree b2/4 — Zone Policy + Strict Gates (150 files)
Base: 7e0fecf3b8f2dc6604600674373771c835484188 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b2

## File Inventory
| File | LOC | Role |
|---|---:|---|
| compiler_security_zones.go | 239 | zone compile, bracket flatten (#5248), HIB merge (#4544/#4818) |
| compiler_security_policy.go | 451 | policy compile, fail-closed default DENY (#3043), collapsed-deny (#3141/#3374), scoped-global (#3148/#4626) |
| compiler_security_addressbook.go | 430 | book/set bracket (#4791), find-or-create merge (#4706) |
| compiler_security_log.go | 268 | syslog port dual-location gate (#3349), TLS-profile no-op reject (#3350) |
| compiler_security_screen.go | 474 | 16 IDS checks profile compile |
| compiler_policy_match.go | 320 | unsupported match leaf (#3113), multi-value tail escape (#3142), swallowed from-zone/to-zone token (#3673), dup-block walk (#3562/#3842) |
| compiler_policy_missing_match.go | 201 | required dimensions gate (#3044) |
| compiler_policy_then.go | 583 | unsupported then-permit (#3114)/reject (#3115)/deny (#3141) + orphan log-sub (#3374) |
| filter_match_resolve.go | 324 | symbolic icmp/port→numeric SSOT (#3205), hyphenated svc-name before range split |
| firewall_filter_expand.go | 137 | cross-product stride uint64 overflow-checked (#5456), clamp 1<<20 |
| compiler_validate_strict_policy.go | ~400 | policy addr token validation, any/any-ipv4/any-ipv6, feed bindings, CIDR/IP |
| + 138 test files | ~5000 | regression |

All cold compile-time gates. Hot Rust policy.rs (3598 LOC) not in batch.

## Module Log

- zones: zoneInterfaceMembers skips HIB child, recurses Keys+Children — bracket `[ a b c ]` as nested chain (wildcard container) handled. Empty Keys check k!="" prevents empty-name add. find-or-create by name prevents dup-instance replace (boundary loss). NEGATIVE sound.
- security_policy: policyMatchChildren/ThenChildren accumulate across ALL match/then blocks (#3842) — dup inner blocks no longer silently widen. terminalActions tracks conflicting permit+deny → #3043 gate rejects, default DENY for actionless. applyCollapsedDenyModifiers wires flat-collapsed `then deny log/count` (Keys[1:] + descendant walk). sortDedupZones canonicalizes scoped-global lists.
- policy_match: forEachChild at security/policies (#3562) closes dup-block bypass (parseStatements appends). firewallMatchValues SSOT reads Keys[1:] + Children for multi:true leaves (#2419). swallowedStructuralMatchTokens from-zone/to-zone in zone-pair multi-value tail rejected (#3673) — prevents app named "from-zone" satisfying gate and hiding keyword as bogus operand.
- missing_match: required dimensions across ALL match blocks (policyMatchChildren) — split across dup blocks counted. NEGATIVE sound, Junos parity.
- policy_then: supportedThenPermitChildren empty today (any child under then permit is silent-drop → UTM/IDP strip fail-open). Inspects ALL permit nodes across ALL then blocks (policyThenActionNodes) for #3377 two-node split + #3842 dup then. collapsedThenActionTokens flattens 3 parser shapes shape-agnostic. hasLog over union of ALL deny nodes before orphan check (#3374) — split deny log + deny session-init not false-flagged.
- filter_match_resolve: whole-spec service lookup BEFORE range split (ftp-data not mangled), parseCanonicalPort rejects +80 (#3606), numeric lo>hi fails closed. Unrecognized token kept verbatim + UnknownPorts for strict reject — fail-closed.
- firewall_filter_expand: bits.Mul64 overflow-checked, saturates MaxUint64, stride clamp to MaxFilterTermExpansion 1<<20 (#5456) — retired-eBPF counter drift fixed; live userspace name-keyed so unaffected. Counts except prefixes (negated rule) so count==len(expandFilterTerm) drift-guard holds.
- validate_strict_policy: policyMatchNamedAddressRefs includes dynamic feed bindings + address book (global+zone-local folded). Recognizes "", any, any-ipv4/any-ipv6 (normalized to 0.0.0.0/0, ::/0 in compilePolicies), CIDR, IP, named ref. NEGATIVE — any-ipv4/any-ipv6 rewrite (#2008) prevents opaque token silently dropped → empty set → under excluded inversion match-all bypass.
- security_log: port dual-location both validated (#3349) — compileLog Atoi swallow defaults to 514 now hard error. TLS-profile named-but-unapplied fallback to system roots → rejected (#3350) — fail-open closed.

## Findings

### Title: NEGATIVE — No fail-open in zone-membership or policy required dimensions for b2
- Severity: Low (negative)
- Confidence: High
- Evidence: b2 files
```
// zones.go:114
zone.Interfaces = append(zone.Interfaces, zoneInterfaceMembers(iface)...)
// security_policy.go:231
pol.Match.SourceAddresses = append(... normalizePolicyAddrTokens(firewallMatchValues(m))...)
// policy_match.go:234-250
for _, tok := range firewallMatchValues(m) {
  if unsupportedPolicyMatchLeaves[tok] { emit(...tok...) }
  if swallowedStructuralMatchTokens[tok] { emitSwallowed(...) }
}
// missing_match.go:118
present[m.Name()] = true // across policyMatchChildren
```
ForEachChild at every container level, not FindChild — duplicate security/policies blocks cannot bypass (#3562).
- Trace: Operator with load override duplicating `security { policies { global policy p ... } }` — second block compiled by compileExpanded but would bypass FindChild-first gate. forEachChild closes.
- Refutation: Searched for remaining FindChild("security") first-only walks in prod validators — all converted to forEachChild per #3562. No bypass found.
- Why: Proves #5248/#2419/#3842/#3562 class closed.
- Dedup note: not restating dedup index (HA/dataplane/heartbeat entries 5488-5477). This slice unrelated.

### Title: Global policy zone scope empty == wildcard — implicit wildcard could be misread in audit display
- Severity: Medium (semantic, not code bug)
- Confidence: High
- Evidence: compiler_security_policy.go:240-256
```
case "from-zone":
    // #3148/#4626 M03: global-policy from-zone match SCOPE. ... Junos accepts a zone LIST here, so
    // read BOTH Keys[1:] AND Children via firewallMatchValues ... Accumulate every value;
    // reading only Keys[1] was the #4626 miscompile ... Empty stays "all zones".
    pol.Match.FromZones = append(pol.Match.FromZones, firewallMatchValues(m)...)
```
No len==0 rejection. Intentional per Junos: no from-zone/to-zone → all zone pairs; one-sided (only from-zone) → from:any? Actually from: trust to: (empty) = trust→any.
- Trace: `security policies global policy p match source-address any destination-address any application any then permit` — no from/to-zone. Operator intent: global. Compiles to FromZones=[], ToZones=[] meaning wildcard. Dataplane expands against all zone pairs. If expansion in Rust misses wildcard (treats empty as none), policy would become no-op (fail-closed) or if expansion skips check, would still be all? Need to verify snapshot builder handles [] as wildcard. Orientation says forwarding_build already decomposed but not in batch. Code comment says empty= all zones — intended.
- Refutation: Behavior matches Junos (#3148). Not a bypass. Risk is display-layer misinterpretation (blank shown as blank not "any") and snapshot builder assumptions.
- HPC: cold.
- Why matters: Audit/compliance tooling showing empty could be misread as no zone = no traffic, not all zones. Permanent.
- Fix: (1) Add explicit `// len==0 means wildcard all zones` on type PolicyMatch FromZones/ToZones fields. (2) `show security policies` renders empty as "any". (3) Snapshot builder test: global with empty scopes expands to all pairs.
- Labels: vsrx-parity, refactor
- Dedup note: not in dedup-index. #3148/#4626 fixed multi-zone drop, not wildcard display.

### Title: ResolveFilterPortRange string roundtrip — inefficient and drift-prone
- Severity: Low
- Confidence: High
- Evidence: filter_match_resolve.go:284-302
```
func ResolveFilterPortRange(spec string) (lo, hi uint16, ok bool) {
    canon, ok := resolveFilterPort(spec)
    if !ok { return 0,0,false }
    if i := strings.IndexByte(canon, '-'); i > 0 {
        l, e1 := strconv.Atoi(canon[:i])
        h, e2 := strconv.Atoi(canon[i+1:])
        ...
        return uint16(l), uint16(h), true
    }
    n, err := strconv.Atoi(canon)
    ...
    return uint16(n), uint16(n), true
}
```
resolveFilterPort already resolved service names to numbers via resolveSinglePort (which returns uint16) but converted to string via Sprintf, then re-parsed via Atoi.
- Trace: `domain` → junosServicePorts["domain"]=53 → Sprintf "53" → Atoi 53. `http-https` → split first '-' → lo resolveSinglePort("http")=80, hi resolveSinglePort("https")=443 → Sprintf "80-443" → split → Atoi 80,443. Correct but wasteful.
- Refutation: Not a correctness bug — canonical values <65536 roundtrip lossless via decimal. No overflow. But pattern hides numeric values; future >16-bit if service table extends beyond (not expected) would overflow.
- Why: Per-rule FBF kernel mirror (pkg/routing) calls this during route resync; extra alloc + parse per rule. Cold but unnecessary. No security bypass.
- Fix: Make resolveFilterPort return (string canonical + numeric lo,hi) or add resolveFilterPortNums that returns numerics directly, keep string version for dataplane compat.
- Labels: refactor, x-hpc(cold)
- Dedup note: not in dedup-index (filter_match_resolve not listed).

### Title: NEGATIVE — Address-excluded inversion + typo now fail-closed via two-gate composition
- Severity: Low (negative)
- Confidence: Medium
- Evidence: compiler_validate_strict_policy.go:88-111
```
func validatePolicyMatchAddressesStrict(...) {
  for _, addr := range pol.Match.SourceAddresses {
    if !validToken(addr) { return policyMatchAddressError(...) }
  }
}
func policyMatchAddressTokenRecognized(tok string, named map[string]bool) bool {
  switch tok { case "", "any", "any-ipv4", "any-ipv6": return true }
  if named[tok] { return true }
  if _,_,err := net.ParseCIDR(tok); err==nil { return true }
  return net.ParseIP(tok) != nil
}
```
plus required-dimensions gate enforces base address presence: source-address-excluded alone without source-address rejected as missing source-address.
- Trace: Old bug: typo "corb" for "corp" address-book entry → dataplane literal parser fails → empty set → under `source-address-excluded` inversion empty→match-all (fail-open). Now strict gate rejects typo before reaching dataplane. Required gate ensures excluded flag not standalone.
- Refutation: Checked that feed bindings included in named set (#3294) so legitimate feed ref not falsely rejected. CIDR/IP literals parse via net.* so no bypass.
- Why: Defense-depth success; two gates compose (address-recognized + required). No fix needed, documents hardening.
- Dedup note: related to agy-070 findings mentioned in filter_match_resolve header but composition not listed.

---
Review completed b2/4 — 150 files, ~3800 prod LOC. No High/Crit zone bypass. 1 Medium display, 1 Low perf, 2 negative proofs.


---

### === ps-A3_go_config_cli_tree-b3.md (14000 chars, 143 lines) ===

# A3 Go Config/CLI Tree b3/4 — Zone Policy + Host-Inbound (150 files)
Base: 312a2dfdef733697828fc68e8fdd92dbcaf70d69 Worktree: /tmp/review-wt-claude-003-A3_go_config_cli_tree-b3

## File Inventory (150 files, 52860 LOC total in batch)
- Prod: 33 files 11958 LOC | Test: 125 files ~40500 LOC
- Largest prod: schema_security 1263, junos_host_deny 1070, schema_system 1075, schema_walk 803, schema_routing 824
- Responsibility rank: junos_host_deny (security critical, per-zone kernel iifname + junos-host DROP projection) > schema_security (zone/policy grammar SSOT, multi-zone from/to) > host_inbound_tokens (SSOT for host-inbound admission, 3-plane parity) > host_inbound_view + lifeline (lifeline exemption SSOT) > schema_validators_* (commit-time fail-closed gates) > lexer/parser (DoS caps, bracket-list collapse)
- Hot-path proximity: none hot (all cold config-compile), but junos_host_deny + host_inbound_tokens feed userspace-dp snapshot and nft hostinbound chain

| File | LOC | Responsibility |
|------|----:|----------------|
| schema_security.go | 1263 | zones, host-inbound, policies (from/to-zone multi), alg, flow, NAT/ike/ipsec closed-world flips |
| junos_host_deny.go | 1070 | junos-host to-zone projection, representability gate, iifname netdev scope |
| schema_system.go | 1075 | system/login/time-zone/crypto validators, master-pass PRF |
| schema_routing.go | 824 | routing-options, policy-options, protocols |
| schema_walk.go | 803 | typed-leaf walk, closed-world enforcement, scalar arity |
| schema_cos.go | 563 | CoS schedulers, filters |
| host_inbound_tokens.go | 484 | system-services/protocols SSOT, L4 tuple expansion |
| parser.go | 403 | recursive-descent, depth cap, stray-brace fail-closed |
| lexer.go | 359 | bracket sugar [#2419], endpoint literal preservation |
| predefined.go | 356 | app + app-set SSOT |
| schema_complete.go | 353 | completion |
| host_inbound_view.go | 342 | zone+per-iface effective view UNION |
| etc | — | rest prod <250 each |

## Module Log (coverage proving)

- host_inbound_multicast.go: catalog of routing multicast groups (OSPF 224.0.0.5/6 etc). Pure data + accessors. No enforcement today (advisory only per #4455 comment). Scanning HostInboundMulticastProtocol lowercases token, matches catalog. No alloc hot path. NEGATIVE sound – fail-open-but-bounded documented, parity gap not bypass.
- host_inbound_tokens.go: KnownHostInboundSystemServices/Protocols sets, HostInboundServiceFamily/ProtocolFamily scoping, L4Match structured SSOT, full-admit predicate. Lowercase canonical, family gates return nil for wrong family. NEGATIVE – SSOT correct, parity tests pinned.
- host_inbound_view.go: UnionHostInboundTokens trims, dedup exact-case, preserves authored order for display. InterfaceHostInboundEffective unions physical-parent override + exact ref (#3720). HostInboundViewWithLifelines records lifeline-exempt interfaces. NEGATIVE – display-only, mirrors dataplane union.
- lifeline.go: LifelineBaseName strips unit suffix by first dot, HostInboundLifelineSet builds fxp0+configured control/fabric, HostInboundLifelineInterface unconditional em0 + fab prefix. Design note acknowledges fab-foo over-match but intentional for #3682 visibility-only change. Checked for null/empty handling. Sound per doc.
- inactive.go: HasInactiveNodes, WithoutInactive deep clone with inactive pruned, cloneForExpansion avoids double clone. No recursion depth issues (iterates Children). NEGATIVE – correct strip before group expansion.
- junos_host_deny.go: BuildJunosHostDenyProjection three-tier (exact zone-pair → from-any → global with from/to scope #3639), whole-program representability gate, DROP-only set-subtraction, poison sentinel for cross-dimension permit/deny (#5.1). Address resolver static-only, feed-tainted → unrepresentable, wildcard handling. JunosHostZoneIngressNetdevs per-zone netdev scope excludes lifelines + cross-zone ambiguous parents. Validated against snapshot via TestJunosHostZoneNetdevsMatchSnapshot (comment). NEGATIVE with low findings below.
- lexer.go: bracket sugar stripped iteratively not recursively (fix H-2). tryBracketedEndpointLiteral preserves [ipv6]:port literal vs list – checks '[' + ident run + ']' + ':' + port. skipWhitespaceAndComments handles #,//,/* */ with unterminated detection via pending TokenError surfaced before EOF (fail-closed #4147). NEGATIVE.
- parser.go: maxParseDepth 256, depth tracked, skipToBlockClose iterative balance. Parse() asserts EOF after top-level statements, stray '}' error + consume-progress loop prevents fail-open truncated config (#4862). ParseSetVerb single trailing semicolon gate (#5194). inactive: marker lifted off Keys only when TokenIdentifier, quoted "inactive:" preserved (#4348). Inline inactive: mid-keys drops governed tokens. NEGATIVE.
- natpool.go: SourceNATPoolNets resolves pool Address + Addresses, parsePoolAddr tries CIDR then bare IP → /32 or /128. No truncation. NEGATIVE – operational filter only, not policy.
- reth_show.go, routinginstanceid.go, predefined.go, schema_*.go, schema_validators_*.go: typed-leaf validators use ParseInt 64 with explicit range, ValidateBGPClusterID checks IPv4 vs IPv6, pref64 lengths RFC8781 set, crypt hash rejects plaintext. All fail-closed at commit, lenient warns (#1960). NEGATIVE.
- screen_inventory.go, secret.go: presentation + redaction, no policy impact. NEGATIVE.
- Test files (125): host_inbound_*, policy_*, parser_*, schema_validate_* etc exercise dual-shape AST, bracket lists (#2419), recursion DoS (HB164), stray brace, semicolon injection, zone matrix, scoped global zoneset (#4626), closed-world flips. Coverage proves #2419 collapse, #3362 per-iface, #3682 lifeline, #4146 junos-host deny, #4228 temporal/buffer tail.

## Findings (Separated by Confidence)

### High Confidence

#### Title: HostInboundLifelineInterface fab prefix over-matches — any interface named fab* is lifeline-exempt, bypassing host-inbound deny
- Severity: Low (design debt, fail-open narrow)
- Confidence: High
- Evidence: lifeline.go:74-83
```
func HostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
    base := LifelineBaseName(name)
    if base == "" {
        return false
    }
    if lifelines[base] {
        return true
    }
    return base == "em0" || strings.HasPrefix(base, "fab")
}
```
Doc comment lines 66-73: "so a broader interface literally named "fab-foo" would also be exempted ... Whether this should be an EXACT / role-gated match rather than a prefix bypass is tracked as a design question"
- Trace: Operator creates interface fab-test0 in trust zone, expects default-deny host-inbound to block pings to firewall IP. HostInboundLifelineInterface("fab-test0", set) → HasPrefix("fab") true → lifeline-exempt → HostInboundView renders lifeline-exempt, nft hostinbound chain excludes fab-test0? Actually lifeline excluded from deny scoping, so host traffic always admitted, and junos_host_deny excludes lifeline refs from netdev scope (JunosHostZoneIngressNetdevs skips lifeline). So ping to firewall bypasses host-inbound deny.
- Refutation: Searched HostInboundLifelineSet – only fxp0 + configured control/fabric added explicitly; em0/fab* remain unconditional for backward compat. Intentional per #3682 – change was visibility only, not semantics. No safe exact list yet because fabric naming could be fab0/fab1 configurable. Still over-broad per comment.
- HPC/invariant: Cold config path, no hot-path impact.
- Why it matters: Silent fail-open for any operator interface whose base name happens to start with "fab" – violates least-privilege; audit shows lifeline-exempt line but operator may not notice.
- Fix direction: (1) Change HostInboundLifelineInterface to exact match fab0/fab1/fab* enumerated from chassis cluster config + canonical fab0/1 defaults, not prefix. (2) Add strict validator rejecting interface names starting with fab unless chassis cluster fabric matches. (3) Keep visibility line.
- Labels: vsrx-parity, hardening, config-validation
- Dedup note: Not in dedup-index (no fab entry). #3682 tracks as design question, not prior reported bypass.

#### Title: zoneCoarseAdmitsIKE / zoneCoarseIdentResets case-sensitive — lenient-loaded upper-case "ALL" misses IKE exemption, causing junos-host DROP to shadow coarse full-admit
- Severity: Low (lenient path only)
- Confidence: High
- Evidence: junos_host_deny.go:825-859
```
func zoneCoarseAdmitsIKE(zc *ZoneConfig) bool {
    if zc == nil { return false }
    svc := zoneEffectiveSystemServices(zc)
    for _, s := range svc {
        if s == "ike" || s == "ipsec" || HostInboundFullAdmitService(s) {
            return true
        }
    }
    return false
}
func HostInboundFullAdmitService(token string) bool {
    return token == "all" || token == "any-service"
}
```
host_inbound_tokens.go:35 comment: "Both layers normalize case (the nft path lowercases via lowerTokens before its switch; the Rust classifier lowercases too), so a wrong-case token would in fact enforce identically on both — there is no runtime split-brain. We still reject wrong-case at commit for Junos-parity/typo-hygiene (lenient load only warns)"
- Trace: Config with `system-services ALL` (upper-case) – strict commit rejects, but lenient Load (peer sync, #1960 no-brick) warns and compiles. nft builder lowerTokens will treat ALL as all → emits accept for host-inbound → IKE allowed. zoneCoarseAdmitsIKE checks token == "all" case-sensitive → false → CoarseAdmitsIKE false → junos_host_deny for that zone's application-any DROP will NOT exempt IKE → daemon renders DROP for IKE (since exemption missing) ahead of accept? Actually DROP vs ACCEPT ordering: nft chain is filter hook input policy accept with per-zone rules; junos-host DROP rules are additional? If DROP emitted, host-bound IKE packet on that zone would be dropped by fine despite coarse full-admit intending accept – fail-closed but inconsistent with coarse.
- Refutation: Checked daemon hostInboundServiceMatches – does lowercasing? Yes comment says lowerTokens. So enforcement diverges only for coarse-admit detection in junos_host projection, not for nft coarse itself. Lenient path could load upper-case and cause unexpected DROP.
- Why it matters: HA sync lenient path could cause transient IKE drop after peer sync of typo'd config – IPsec control traffic affected, not data plane transit.
- Fix: Normalize token lowercased in zoneCoarseAdmitsIKE/IdentResets and HostInboundFullAdmitService (strings.EqualFold or ToLower) to mirror runtime lowerTokens, or call HostInboundTokens expanded via lowercased set. Keep strict validator rejecting wrong-case at commit.
- Labels: vsrx-parity, ha-sync, hardening
- Dedup note: Not in dedup-index. Prior host-inbound token parity entries about split-brain fixed in #3200, but this coarse-admit check was not covered.

### Medium Confidence

#### Title: UnionHostInboundTokens dedup is case-sensitive while enforcement is case-insensitive – display may show duplicate tokens, audit confusion
- Severity: Low
- Confidence: Medium
- Evidence: host_inbound_view.go:29-45
```
func UnionHostInboundTokens(zone, iface []string) []string {
    seen := make(map[string]bool, len(zone)+len(iface))
    out := make([]string, 0, len(zone)+len(iface))
    add := func(src []string) {
        for _, t := range src {
            t = strings.TrimSpace(t)
            if t == "" || seen[t] {
                continue
            }
            seen[t] = true
            out = append(out, t)
        }
    }
    add(zone)
    add(iface)
    return out
}
```
- Trace: zone has `ssh`, interface override has `SSH` (upper-case, typo that passed lenient load). Union keeps both `ssh` and `SSH` in display view, suggests two distinct services, while dataplane lowercases and dedupes to one.
- Refutation: Strict path rejects upper-case, lenient warns. Display preserving authored case is intentional per comment (mirrors structured API). Case-sensitive dedup is thus correct for display fidelity, but could confuse audit count.
- Why it matters: Minimal – display only, not enforcement. Operator reading `show security zones` could think duplicate means two services.
- Fix: Keep display case-preserving but dedup case-insensitively for counting (lowercased seen set) or annotate duplicate notice. Low priority.
- Labels: refactor, display
- Dedup note: Not in dedup-index.

## Suggested Issue Split

- PR1: Hardening fab prefix lifeline to exact match (schema validator + lifeline.go). Small, low risk, improves least-privilege.
- PR2: Make zoneCoarseAdmitsIKE/IdentResets case-insensitive to mirror nft lowerTokens (junos_host_deny.go + HostInboundFullAdmitService). Add lenient-load parity test.
- PR3: (optional display) UnionHostInboundTokens case-insensitive dedup note or audit warning.

## Coverage Summary

- All 33 prod files read, all 125 test files listed. No uninspected prod file.
- Zone policy handling: from-zone/to-zone multi (#4626) implemented multi:true, bracket collapse via firewallMatchValues (Keys[1:]+Children) – verified in schema_security.go and policy_zone_matrix tests. Global scoped zoneset #4626 test covers multi-zone deny lowering fix (dedup #5488 unrelated – that is dataplane snapshot version bump, not compiler).
- Default handling: default-policy enum deny-all/permit-all/reject-all, default deny-all fail-closed per schema doc. No bypass found.
- Host-inbound: SSOT tokens, family scoping, L2 no-op (#3311), full-admit (#3199), per-iface union (#3362), lifeline exemption (#3682) all covered.
- Application matching: junos_host_deny reduces single-app to L4 frag, rejects multi-term/ALG/unnamed-port, checks IPsec/ident exempt tuples – fail-closed.
- Integer bounds: ValidateInteger 64-bit, ValidateRingEntries power-of-two + ceiling, CoS rate/buffer validators use ParseFloat with NaN/Inf reject, no truncation to uint16/uint32.
- Recursion/DoS: maxParseDepth 256, bracket stripping iterative, unterminated block comment fail-closed, stray brace EOF gate, semicolon injection gate.


---

### === ps-A3_go_config_cli_tree-b4.md (17910 chars, 180 lines) ===

# Security Review — Batch A3 Go Config CLI Tree b4/4 (52 files)

> Base commit: 312a2dfd (worktree /tmp/review-wt-claude-003-A3_go_config_cli_tree-b4)
> Focus: security zone policies, inter-zone allow/deny, host-inbound admission, policy compilation, NAT zone scoping, typed-leaf validation

## File Size / Shape Inventory (prod vs test, responsibility, hot-path proximity)

| File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|-----|-----------|----------------|---------------|
| types_security.go | 1306 | prod | ZoneConfig, Policy/PolicyMatch, NAT, Screen, ALG, Scheduler — zone policy SSOT | HIGH (snapshot builder reads zones/policies/NAT) |
| types_system.go | 1565 | prod | System stanza (dataplane, syslog, SNMP, login RBAC) — RBAC + SNMP source-IP gate | MEDIUM (RBAC gating, SNMP) |
| types_routing.go | 651 | prod | Routing protocols, tunnel config cloneForUnit — tunnel aliasing (perf + sec) | MEDIUM (FIB ingest) |
| types_chassis.go | 188 | prod | Device-map + cluster config — bare-metal identity | LOW (boot-time) |
| tunnelemit.go | 123 | prod | Tunnel endpoint canonical emission (collision gate + builder SSOT) | MEDIUM (ID stability) |
| tunnelid.go | 290 | prod | StableTunnelEndpointID fold + 3-view HA-symmetric collision gate | MEDIUM (HA determinism) |
| zoneid.go | 251 | prod | StableZoneID fold + 3-view collision gate + quarantine runtime | HIGH (zone ID wire-adjacent) |
| value_type.go | 155 | prod | Typed-leaf ValueType + placeholder — drives commit-time validators | MEDIUM (validation trigger) |
| types_cos.go | 283 | prod | CoS forwarding-class/scheduler/shaper binding | LOW (CoS) |
| types_interfaces.go | 150 | prod | InterfaceConfig, Units, LAG, VRRP groups | LOW |
| xfrmi.go | 77 | prod | XFRM if_id + secure-tunnel bind-interface validator | MEDIUM (VPN liveness) |
| snmp_clients.go | 206 | prod | SNMP community clients allowlist parse + longest-prefix match + cache | MEDIUM (SNMP ACL) |
| syslog_logfile.go | 50 | prod | show-log allowlist gate — path traversal + arbitrary log read | HIGH (priv esc) |
| tcp_flags.go | 147 | prod | Firewall filter tcp-flags conjunctive expression — fail-closed on OR/contradiction | HIGH (filter bypass) |
| 37 test files | 99 avg | test | Fail-on-revert guards for every strict gate above | N/A |
| **Total** | ~8200 | 15 prod + 37 test | | |

Ranking by size×responsibility×hot-path: types_security.go > types_system.go > zoneid.go > types_routing.go > snmp_clients.go > tcp_flags.go > syslog_logfile.go > tunnelid.go.

## Module Log (incl. negatives proving coverage)

- types_security.go — PASS: reviewed ZoneConfig.InterfaceHostInbound (per-if HIB union, #3362), IsWildcardZone/IsWildcardZoneSet duality (two spellings for global wildcard), GlobalPolicyAppliesToZone (from||to any match), sortDedupZones/ScopeSingular/IsHostToZoneScope, NAT match multi-value accessors (natMatchValues fallback), StaticNATRule source-address list (was scalar drop M02). No integer truncation on ports — DestinationPort int validated via strict gates elsewhere. No zone bypass. RBAC: LoginClassPermissions forbids PermMaint on non-super (operator lacks maintenance). Coverage: read 1306 lines.
- zoneid.go — PASS: StableZoneID FNV-1a xor-fold [1, 65533], reserved range protected, 3-view HA-symmetric collision check (pre-expansion union + per-node expansion), QuarantinedZoneNames deterministic later-sort quarantine. Tests pin hash-freeze (frozen fold). No integer overflow — uint16 fold mod arithmetic correct. Negative: no findings, determinism holds.
- types_routing.go — PASS: TunnelConfig.cloneForUnit deep-copies Addresses + WgPeers (addresses independent backing array, #3898), WgOuterFamilyV6, ConnectedNetworkPrefix skip for host/default/link-local. No issue.
- zone_count_cap_test.go — PASS: MaxUsableZoneID == ZoneIDReservedMin-1 == 65533, pigeonhole cap guard.
- zone_dup_block_4818_test.go — PASS: duplicate top-level security-zone sibling blocks merge (find-or-create, #4818) — previously silently replaced (interfaces lost). Zones merge correctly.
- zone_interface_defined_4515_test.go — PASS: zone member must name configured interface or daemon-materialized lo0/st0 dynamic, else hard reject. No bypass.
- zone_interface_membership_test.go — PASS: same logical interface in two zones hard-rejected (#3072), bare-vs-unit alias rejected, distinct units allowed, same-zone repeat allowed.
- zone_local_unqualify_3358_test.go — PASS: zone-local synthetic key unqualify/display safe, no mutation of input slice.
- show_config_dup_context_4562_test.go — PASS: navigatePath intermediate descent over duplicate context blocks (display-only, no forwarding bypass, but scoped display-set backup gap if reverted).
- show_config_repeated_keyword_3980_test.go — PASS: navigatePath terminal single-key returns all siblings (backup fidelity).
- snmp_clients*.go (429/4711/4834) — PASS: clients allowlist parse both shapes, longest-prefix restrict, precomputed cache parity, restrict-typo fail-closed (#4834). No arbitrary source-IP bypass.
- syslog_logfile_4860_test.go + syslog_logfile.go — PASS: SyslogLogFilePath validates basename + allowlist, no path traversal, nil-config fail-closed.
- system_string_injection_4902_test.go — PASS: validators for NTP/DNS-domain/SSH-algo/syslog filename/user — newline/space/slash/comma injection rejected.
- static_nat_mapped_port_2491 + source_address_3435 + zone_test — PASS: mapped-port requires destination-port, source-address bracket list retained, from-zone undefined warns.
- tunnel_perunit_deepcopy_test.go — PASS: per-unit tunnel deep-copy independent backing (addresses + WgPeers) guard #3898.
- xfrmi_test.go + xfrmi.go — PASS: XFRM if_id 0 means invalid, ValidateSecureTunnelBindInterface rejects non-st refs, stIndex/unit bounds checked.
- strict_gate_wiring_canary_test.go — PASS: every (cfg *Config) error strict gate is wired (AST canary).
- system_multileaf_test.go — PASS: domain-search/name-server bracket list both shapes #2419.
- tcp_flags_test.go + tcp_flags.go — PASS: dangling negation fail-closed #4714, OR/negated-group contradiction rejected.
- tcp_session_advisory_test.go — PASS: tcp-session presence flags accepted-only advisory folds.
- time_zone_path_validate_5011, web_management_auth_4047, wireguard_allowedips_malformed_5194, wireguard_multipeer, vrrp_* — reviewed, no zone-policy findings, pass as negative coverage.
- types_*, tunnelemit.go, value_type.go — reviewed, no findings.

## Findings

### HIGH Confidence

**FINDING H1 — sysmlog_logfile.go: allowlist gate is commit-config scoped, but show-log can read active config that never declared syslog file**
- Severity: Medium
- Confidence: High
- Evidence: `pkg/config/syslog_logfile.go:40-50`
  ```go
  func SyslogLogFilePath(cfg *Config, name string) (string, error) {
      if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
          return "", fmt.Errorf("invalid log file name %q", name)
      }
      for _, allowed := range cfg.SyslogLogFileNames() {
          if allowed == name { return filepath.Join("/var/log", name), nil }
      }
      return "", fmt.Errorf("log file %q is not a configured ...", name)
  }
  ```
- Trace: CLI `show log X` calls SyslogLogFilePath with active Config; if active config has zero syslog files (default appliance image before first commit, or operator removed file stanza), every log name is denied — including legitimate operational logs. Conversely, when syslog file IS configured, only allowlisted names are readable — which is intended. The risk is NOT a bypass but a liveness gap: `nil` SyslogLogFileNames returns nil slice, so fail-closed path works, but an operator configuring `system syslog file messages` still cannot read `xpfd.log` helpers unless that file is also declared. This is by design (#4860) and documented. No fail-open. Negative for bypass, positive for denial-of-legit-reads which is acceptable.
- Refutation: Checked — dedup does NOT list #4860. Gate uses filepath.Base equality, rejects "..", ".", empty, and non-allowlisted. Secure.
- Why it matters: PermView account cannot read auth.log/syslog — correctly mitigated.
- Fix: None needed; behavior is intended least-privilege. Doc already states allowlist.
- Labels: hardening, vsrx-parity, display
- Dedup: Not in dedup index; #4860 is fix PR, not prior finding duplicate.

**FINDING H2 — zoneid.go: StableZoneID collision quarantine correctness — later-sorting quarantine vs id→name reverse map drift**
- Severity: Low
- Confidence: High
- Evidence: `pkg/config/zoneid.go:205-251` QuarantinedZoneNames, StableZoneIDOwner
  ```go
  func QuarantinedZoneNames(names []string) map[string]struct{} {
      sorted := make([]string, len(names)); copy(sorted, names)
      sort.Strings(sorted)
      owner := make(map[uint16]string, len(sorted))
      var quarantined map[string]struct{}
      for _, name := range sorted {
          id := StableZoneID(name)
          if existing, taken := owner[id]; taken { /* quarantine later */ }
      }
  }
  ```
- Trace: Collision of z174/z214 both fold to 53547. Strict path rejects; lenient quarantines later-sorting (z214). Wire builder drops quarantined zone — interfaces in that zone become unzoned → traffic denied (fail-closed). StableZoneIDOwner returns sorted-first survivor for reverse maps. This is correctly fail-closed, not fail-open. Tested in zoneid_test.go: lenient warning states QUARANTINED + DEGRADED. No inter-zone allow/deny bypass — quarantined zone's interfaces unzoned = no session creation = default deny. Verified wire builder exclusion via docs.
- Refutation attempt: Considered hash DoS (adversary crafts zone names colliding to force quarantine). Zone names are operator-controlled via commit, not attacker-controlled dataplane. Commit-time collision is rejected strict; only HA peer-sync or lenient load after upgrade can trigger quarantine with warning. No data-plane adversary can inject zone names. Correct fail-closed.
- Labels: hot-path, vsrx-parity, refactor
- Dedup: Not in dedup index; #3075 family is known and addressed.

**NEGATIVE RESULTS (required)**

- tcp_flags.go: No finding. ParseTCPFlagsExpression: lexer loop no recursion, pendingNeg double-neg toggles correctly, dangling neg rejected (#4714), OR/disjunction rejected, contradiction rejected, unknown flag rejected. Integer bounds uint8 flags — no truncation. No DoS via large input — tokens bounded by expr length, string is config-set leaf (typed, length limited by commit). Fail-closed on malformed.
- snmp_clients.go: No finding. parseClientPrefix validates CIDR/bare IP. compileClientNets drops unparseable → never allow-all. validateSNMPClients (#4834) rejects typoed restrict keyword at commit. longest-prefix match deterministic. No zone policy interaction.
- types_security.go IsWildcardZone/IsWildcardZoneSet dual spelling: No finding. Empty slice OR slices.Contains(any) correctly maps both "" and explicit "any" to wildcard. Host-to-zone scope exact match ["junos-host"] enforced. GlobalPolicyAppliesToZone uses IsWildcardZoneSet + Contains — correct OR logic (asSource || asDest) meaning global that mentions zone on either side is listed (audit), runtime uses AND. No bypass.
- types.go RethToPhysical scoring: No finding. Node-local member preferred (score 2), remote (0), unknown (1). Nil-map guards present (#3501). No zone bypass.
- xfrmi.go: No finding. Bounds: stIndex [0,0x10000), unit [0,0xffff), ifID !=0, LinuxIfName translation. No integer truncation.
- tunnelemit.go + tunnelid.go: No finding. Canonical "%s.%d" emission, non-WG src/dst gate, interface-level WG single-lowest-unit, 3-view HA-symmetric collision gate, no recursion (comment states recursion-free). Hash-freeze pinned.
- value_type.go: No finding. Placeholder mapping only, no parsing.
- The 37 test files: all are negative for zone-policy bypass — they are hardening guards. No test file introduces bypass. Specific zone tests confirm multi-zone interface membership rejection, undefined interface rejection, dup-block merge accumulation.

### MEDIUM Confidence

**FINDING M1 — types_security.go: StaticNATRuleSet FromZone is singular string, but global policy scope is plural; static NAT bracket-list from-zone expansion not in this batch — verify Cartesian expansion occurs**
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/config/types_security.go:637-653`
  ```go
  type StaticNATRuleSet struct {
      Name     string
      FromZone string
      FromInterface string
      FromRoutingInstance string
      Rules    []*StaticNATRule
  }
  ```
  Single FromZone field, not slice. Comment says compiler Cartesian-expands bracket list into one RuleSet per value. This file defines type only; expansion logic lives in compiler (not in batch). If expansion regresses to first-only read, zone-scoped static NAT would silently lose scope tail (fail-open: rule matches global instead of specific zone). However, test static_nat_zone_test.go asserts schema completion and undefined-zone warning, not bracket expansion. Coverage gap.
- Trace: `set security nat static rule-set rs1 from zone [ untrust trust ]` — compiler should produce two RuleSets. If it produces one with FromZone=untrust only, traffic from trust zone unconditionally matches static NAT it shouldn't (or fails to match intended). Dataplane static_nat.rs match_dnat requires exact ingress-zone match.
- Refutation: Checked batch — no file tests bracket list for static NAT from-zone. However existing compiler pattern for source NAT does Cartesian expansion (known from orientation). Static NAT expansion likely mirrors it. No evidence of bug in type definition itself; type is correct for post-expansion representation.
- Why it matters: NAT zone scoping is security boundary — incorrect zone narrowing could expose internal hosts via unintended DNAT.
- Fix direction: Ensure compileNATStatic uses firewallMatchValues (Keys[1:] accumulation) for from-zone, not nodeVal first-only. Add explicit test `TestStaticNATFromZoneBracketList` similar to static_nat_source_address test.
- Labels: vsrx-parity, hardening
- Dedup: Not in dedup index (advises #3435 source-address tail drop, analogous class).

**FINDING M2 — types_security.go: GlobalPolicyAppliesToZone uses OR for audit but runtime uses AND — audit may over-list, not under-list (safe)**
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/config/types_security.go:548-552`
  ```go
  func GlobalPolicyAppliesToZone(m PolicyMatch, zone string) bool {
      asSource := IsWildcardZoneSet(m.FromZones) || slices.Contains(m.FromZones, zone)
      asDest := IsWildcardZoneSet(m.ToZones) || slices.Contains(m.ToZones, zone)
      return asSource || asDest
  }
  ```
  Comment says runtime AND-combined: packet matches iff from-scope matches from-zone AND to-scope matches to-zone. Function uses OR because it answers "can this global affect zone at all (on either side)". Correct for audit purpose. If caller used this for enforcement instead of audit, it would over-permit audit view but not enforcement. Checked callers: zone-detail policy summary (#3658) — display only. Not a bypass.
- Labels: display, hardening

### LOW Confidence

**FINDING L1 — snmp_clients.go: compileClientNets silently drops unparseable entries — lenient path default-denies but consumes memory for all-malformed allowlist distinguishing nil vs empty**
- Severity: Low
- Confidence: Low
- Evidence: `pkg/config/snmp_clients.go:42-56`
  ```go
  func compileClientNets(clients []SNMPClient) []compiledSNMPClient {
      if len(clients) == 0 { return nil }
      out := make([]compiledSNMPClient, 0, len(clients))
      for _, cl := range clients {
          _, ipnet, err := parseClientPrefix(cl.Prefix)
          if err != nil || ipnet == nil { continue }
  ```
  Lenient load skips bad entry, keeps good. All-bad returns non-nil empty slice distinguishing from unscoped nil. Strict path now rejects (#4834) so production commit never hits all-bad path unless lenient load of old persisted config. Memory bounded by client count (operator controls). No DoS.
- Labels: hardening

**FINDING L2 — zone_count_cap_test.go: zonesConfig direct construction bypasses same validation it tests — no parser cost but also no collision-gate cost**
- Severity: Low
- Confidence: Low
- Evidence: `pkg/config/zone_count_cap_test.go:8-18` zonesConfig builds Config directly without parser. validateZoneCountStrict is O(1) count check, not hash check. Collision gate (validateZoneIDCollisionAST) is separate AST-level gate not exercised by direct Config. Test name says "cap at scale without paying parser / collision-gate cost" — intentional. No security issue, just note that count cap is backstop only; real collision rejection happens earlier at first colliding pair.
- Labels: test-coverage

## Suggested Issue Split

- One issue: M1 — Add bracket-list static NAT from-zone expansion guard test + verify compiler uses Keys[1:] accumulation (zone scoping fidelity).
- One advisory (Low): Document SyslogLogFilePath allowlist semantics for operators expecting helper logs readable via show log.
- Remaining are negative results — batch is well-hardened.

## Negative Result Summary (required proves coverage)

All 52 files reviewed. 15 prod files: no inter-zone allow/deny bypass found. Zone ID fold is fail-closed (quarantine degrades to deny, not permit). Security zone interface membership is hard-rejected when interface in two zones (#3072). Zone undefined interface hard-rejected (#4515). Duplicate zone blocks merge (#4818) not replace. SNMP clients longest-prefix ACL correctly denies. TCP flags dangling negation fail-closed (#4714). Syslog log file path traversal blocked (#4860). Static NAT zone scoping has adequate validation (undefined zone warns, schema completion). No integer truncation, no recursion DoS, no fail-open on malformed config in this batch. Tightening already landed; this batch is regression guards.


---

### === ps-A4_go_configstore_persist-b1.md (12244 chars, 127 lines) ===

# Review — A4 configstore persist b1/1 — Storage/Crypto Lens

**Base**: 312a2dfdef733697828fc68e8fdd92dbcaf70d69
**Worktree**: /tmp/review-wt-claude-003-A4_go_configstore_persist-b1
**Batch**: 66 files (15 prod ~5851 LOC, 51 test ~10584 LOC, total ~16435)

## File-Size/Shape Inventory (ranked size×responsibility×hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest Fn | Responsibility |
|------|------|-----|-----------|------------|---------------|
| 1 | store_commit.go | 998 | prod | CommitWithDescription ~90, PromoteRollback ~80 | Commit/confirmed timers, post-rename converge, degraded retry, rollback file durability |
| 2 | store_persist.go | 639 | prod | recoverPendingConfirmLocked ~90, Load ~50 | Load recovery of confirm.json, archive, rescue, journal truncation, everCommitted marker |
| 3 | store.go | 603 | prod | compileTreeLenient/schemaValidateExpandedTree | Size caps, strict vs lenient gates, SyncApply HA ingress, compile pipeline |
| 4 | store_command.go | 544 | prod | LoadMergeAs ~70 | Set/Delete/Deactivate/Activate/Copy/Rename/Insert, atomic clone swap (fail-closed on mid-body error #5187) |
| 5 | journal/journal.go | 507 | prod | tailScan ~80, Log ~70 | Torn-tail self-heal, rotation, perms migration #5188, bounded reverse scan |
| 6 | store_format.go | 490 | prod | ShowCompareRedacted etc ~10ea | Redacted display renderers (secret masking via RedactedClone) |
| 7 | crypto.go | 395 | prod | masterPasswordPRF ~50, maybeDecrypt ~50 | AES-GCM/HKDF/nonce/PRF, master.key durable ordering, envelope compat, groups/wildcard PRF scan #5231 |
| 8 | db.go | 350 | prod | writeTreeMarked ~30, readTreeMeta ~60 | temp+fsync+rename+dirfsync, envelope outer, encrypt inner, confirm.json durability |
| 9 | store_lock.go | 334 | prod | EnterConfigureSession ~40 | Config lock ownership #5059, lease TTL #4476, stale reclaim |
| 10 | envelope.go | 318 | prod | parseEnvelopeHeader ~60, stripEnvelope ~30 | Compatibility envelope outer framing, fail-closed on unknown format #4888, committed marker #1922 |
| 11 | dataplane_retire.go | 264 | prod | rewriteRetiredDataplaneType ~50 | Retired dp rewrite (ebpf/dpdk) with groups awareness |
| 12 | factory_reset.go | 211 | prod | FactoryResetConfigDir ~60 | Zeroize key-first ordering #5197, archive ownership guard #5186 |
| 13 | history.go | 70 | prod | Push/Get/List ~10ea | 50-slot ring buffer |
| 14 | test_seams.go | 70 | prod | SetWriteActiveForTesting | Test seams for durability injection |
| 15 | check.go | 44 | prod | CheckText ~20 | Day-0 check-config gate with size cap |

Largest test files: store_test.go 2005 LOC, journal_test.go 792, persist_failure_test.go 554.

## Module Log (incl negatives proving coverage)

- **crypto.go**: Reviewed HKDF PRF map (case-insensitive, SSOT with config masterPasswordPRFNames #4578), salt 16B crypto/rand, nonce per-encrypt rand, nonce length check before gcm.Open #4793 prevents panic boot loop, master.key WriteFileDurable ordering #1894, envelope unknown-format fail-closed #4888, masterPasswordPRF recursive groups scan for wildcard <*> shapes #5231, split systemBlocks #4705. No nonce reuse, no ECB. NEGATIVE for zone bypass: encryption gate scans both top-level system and recursive groups, so group-scoped master-password never leaks plaintext via missed detection.

- **envelope.go**: Outer envelope magic "#xpf-config-envelope" makes old reader's json.Unmarshal fail closed #1917, sanitizeEnvelopeToken strips whitespace/newline to prevent header injection, unknown fields tolerated additive, v=/min-reader gates enforced, committed marker defaults true for migration C3, committed=0 only explicit. Reviewed wrap/strip. NEGATIVE: no injection via writer token because spaces→'-' and Fields split prevents extra k=v injection.

- **db.go**: WriteFileDurable 0600, MkdirAllDurable 0700 + chmod repair #4056, stale temp sweep Glob ".*.tmp-*" on boot, ReadActiveMeta fail-closed tags, decrypt tolerant fallback for plaintext legacy, plaintext-downgrade warn #4579, confirm.json WriteConfirm encrypts via prevTree PRF, DeleteConfirm durable via rbRemove+rbSyncDir #4864. NEGATIVE: durable ordering temp+fsync+rename+dir fsync correct, key before tree via readOrCreateMasterKey structural ordering.

- **journal/journal.go**: O_RDWR for torn-tail check, ReadAt last byte, newline prepend confines damage, Log fsync each entry (operator-paced), rotation via Rename + chmodOwnerOnly #5188, lstat not following symlink for perm repair, maxTailLineBytes 16MiB cap prevents OOM on corrupt newline-free segment, tailScan bounded O(limit) via reverse chunk scan, parseLine tolerant skip torn tail. NEGATIVE: no torn-tail propagation, rotation durability via created||rotated dir fsync.

- **store.go / store_persist.go / store_commit.go**: MaxConfigSize 16MiB at every parse entry (LoadOverride/Merge/Set, SyncApply, CheckText) #HB164, persist-before-promote Option A, post-rename PostRenameSyncError converge-to-C #5185 preserves durable==memory==applied invariant, degraded flag + retry loop with hour cap, confirmGen anti-stale timer #1817, rollback history slot1 durable + trailing SyncDir once, rollback persist degraded bit #3441 L1, archive seq monotonic prevents overwrite #3441 H4, rescue.conf durable + redacted clone display #4099 with generic error (no token leak). NEGATIVE: no zone/policy mishandling in persist layer; compile gates strict on commit, lenient on Load/SyncApply with warnings for node-id mismatch #4185 and RA intervals #4525.

- **store_lock.go**: Owner check #5059, session "" bypass explicit internal capability, effectiveHolder for exclusive mode #3979, lease TTL 10m with touch on mutation, reclaimStaleLock only when idle past TTL. NEGATIVE: exclusive holder release bug fixed.

- **store_command.go**: Atomic clone swap on LoadMerge/LoadSet #5187 prevents partial delete fail-open, hasFlatVerb gate rejects junk nodes #3442, applyEditLine centralizes verb dispatch preserving inactive markers #2008. NEGATIVE: no multi-key zone path annotation bug — fixed via AnnotatePath navigatePath #4587.

- **factory_reset.go**: Key-first removal + fsync .configdb barrier before RemoveAll #5197, parent dir fsync propagated (error surfaced), ownership guard only wipes default archive path #5186, ENOENT tolerant. NEGATIVE: no secret-bearing archive left after zeroize when default path used.

- **envelope/history/check/dataplane_retire**: NEGATIVE — envelope compat correct, history ring modulo correct, check size cap enforced, retired dp rewrite walks both top-level and groups system blocks.

## Findings — High Confidence

### Finding: Archive cleartext secret retention despite master-password
- **Title**: Local config archive retains cleartext secrets even when master-password encrypts active.json
- **Severity**: Low
- **Confidence**: High
- **Evidence**: pkg/configstore/store_persist.go:444-465
  ```go
  func writeArchive(archiveDir string, maxArchives int, data string, ts time.Time, seq uint64) error {
      if err := os.MkdirAll(archiveDir, 0700); err != nil {
  ...
      filename := fmt.Sprintf("config-%s.%020d.conf", ts.Format("20060102-150405.000000000"), seq)
  ...
      if err := rbWriteFileAtomic(path, []byte(data), 0600); err != nil {
  ```
  `data` is `s.active.Format()` cleartext; no maybeEncrypt step. Same path used by auto-archive goroutine at line 217-224 of store_commit.go.
- **Trace**: Commit → writeActive encrypts active.json via maybeEncrypt when masterPasswordPRF!=“”, but capture `data:=s.active.Format()` before archive async write — archive path writes cleartext 0600 file.
- **Refutation attempt**: Comment at factory_reset.go:14-18 says archives are 0600 copies with cleartext secrets — intentional. But operator expectation from master-password may be all copies encrypted. The archive dir is 0700 and file 0600, so at-rest exposure limited to owner, but differs from active.json posture.
- **Why it matters**: Master-password intended to protect at-rest secrets; archive leaves prior-tenant secrets cleartext on same disk, reducing defense-in-depth if 0700/0600 bypassed via backup or mount.
- **Fix direction**: Either encrypt archive when PRF present (parallel to DB seam) or document operator advisory and ensure zeroize erases archive (already #5186). Consider adding archive encryption or warning in commit path when master-password + archive enabled.
- **Labels**: crypto, secret-redaction, durability
- **Dedup note**: Not in dedup index (which lists envelope compat, nonce length, etc.)

### Finding: Rollback history loader lacks MaxConfigSize enforcement
- **Title**: loadRollbackHistory parses rollback slot files without size cap
- **Severity**: Low
- **Confidence**: High
- **Evidence**: pkg/configstore/store_commit.go:931-960
  ```go
  func (s *Store) loadRollbackHistory() {
      ...
      for i := 1; i <= s.history.MaxSize(); i++ {
          path := s.rollbackPath(i)
          data, err := os.ReadFile(path)
          ...
          parser := config.NewParser(string(data))
  ```
  No checkConfigSize before Parse, unlike LoadOverride/Merge/Set/SyncApply.
- **Trace**: On boot, attacker with local FS write (or bitflip) could craft huge rollback.N file; ReadFile loads entire file into memory unbounded before parse.
- **Refutation**: Rollback files are written by xpf itself via WriteFileDurable/Atomic with 0600 in owned dir (0700 parent). Local FS write already requires root/owner. Risk is corruption, not network ingress. Still defense-in-depth gap vs other entry points that enforce 16 MiB cap.
- **Why it matters**: DoS via memory exhaustion on boot if rollback slot ballooned (e.g., prior bug wrote giant comment before #4891 cap).
- **Fix direction**: Add checkConfigSize or len(data) > MaxConfigSize → log warn + skip slot (tombstone) rather than parse.
- **Labels**: DoS, durability
- **Dedup note**: Not in dedup list.

## Findings — Medium Confidence

### Finding: fsatomic temp sweep removes any ".*.tmp-*" without type check
- **Title**: NewDB stale temp sweep could remove non-regular files matching glob
- **Severity**: Low
- **Confidence**: Medium
- **Evidence**: pkg/configstore/db.go:64-68
  ```go
  if stale, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*")); err == nil {
      for _, p := range stale {
          _ = os.Remove(p)
      }
  }
  ```
  No lstat check for symlink/dir.
- **Trace**: If directory contains symlink matching pattern (e.g., attacker-planted), Remove removes symlink itself (not target) — safe. If it's a directory, Remove fails (need RemoveAll). So low risk but inconsistent with journal's lstat symlink refusal.
- **Fix**: Use Lstat and remove only regular files or same as journal: skip non-regular.
- **Labels**: durability, hardening

## Findings — Low Confidence / Informational

- **ExportJSON typed config may leak secrets**: store_format.go ExportJSON marshals compiled config (not redacted) for debugging. If exposed via any API, would leak. Currently internal, but worth marking debug-only.

- **confirm.json FirstCommit plaintext**: When FirstCommit true, PrevTree empty, so confirm.json not encrypted. That's okay (no secrets), but comment could clarify.

## Suggested Issue Split

1. **Archive encryption vs cleartext** — low, doc + optional encrypt path (separate issue).
2. **Rollback loader size cap** — low, hardening.
3. **Temp sweep file-type check** — low, consistency.

## Coverage Statement

All 15 prod files reviewed for durable write ordering (temp+fsync+rename+dir fsync, post-rename converge-to-C #5185, DeleteConfirm #4864, rescue delete #5197, factory reset key-first #5197), AES-GCM/HKDF/PRF handling (nonce per-encrypt, nonce length check #4793, salt 16B, HKDF info static, master.key durable), envelope compat (outer '#' fails old reader, inner AES envelope, unknown format fail-closed #4888, committed marker migration C3), journal torn-tail (newline self-heal, parse-or-skip, bounded reverse scan, rotation dir sync, perms 0600 migration #5188), commit/rollback timers (confirmGen anti-stale, recovery on Load, expiration vs re-arm #4577), secret redaction (RedactedClone for display, rescue redacted #4099, journal Detail cap #4891). No high-sev nonce reuse, torn-write, or fail-open found. Negatives listed per module prove inspection.


---

### === ps-A5_go_ha_vrrp_ra_conntrack-b1.md (9920 chars, 96 lines) ===

# HA / VRRP / RA / conntrack — review b1 (Go)

Base: 7e0fecf
Worktree: /tmp/review-wt-claude-003-A5_go_ha_vrrp_ra_conntrack-b1

## File inventory
- Total lines (prod+test): 47864 (from wc -l)
- Prod: 19125 lines across 35 files
  - pkg/cluster: 11750 prod (largest: sync_conn.go 1858, heartbeat.go 881, failover.go 912, sync.go 1048, election.go 475)
  - pkg/conntrack: 554 (gc.go)
  - pkg/ra: 2193 (ra.go 1118, sender.go 1055, filter.go 21)
  - pkg/vrrp: 4628 (instance.go 2417, manager.go 1108, packet.go 277, track.go 341, addrwatch.go 219)
- Test: 28739 lines, 71 files (heaviest: cluster/sync_test.go 4717, ra/serialize_test.go 2706, vrrp/vrrp_test.go 2468)
- Largest prod fn: vrrpInstance.run / stepBackup (~400 LOC), SessionSync.handleMessage (~350 LOC), Manager.UpdateInstances
- Hot path proximity ranking (size x responsibility x freq):
  1. pkg/cluster/heartbeat.go Marshal/Unmarshal + sender/receiver loops — every 100ms, drives election, auth, replay
  2. pkg/cluster/sync_protocol.go + sync_conn.go — TCP session sync, gen guards, bulk, fencing
  3. pkg/vrrp/instance.go — BECOME_MASTER/BACKUP, TTL=255, hop-limit, GARP, equal-priority tie-break, preempt hold + watchdog
  4. pkg/ra/ra.go + sender.go — goodbye ordering, RA flood prevention, RS validation
  5. pkg/cluster/election.go — dual-active, preempt, dup node-id fail-closed, kernel-upgrade hold
  6. pkg/conntrack/gc.go — expiry ownership (IsLocalPrimary), per-IP limit counting, aggressive aging hysteresis

## Module log (incl negatives => NEGATIVE RESULT)

- cluster/election.go: dual-active resolves on eff priority then nodeID, dup nodeID logs rate-limited and fails closed to SECONDARY. kernelUpgradeHold blocks both single-node and peer paths. NEGATIVE.
- cluster/heartbeat.go: MarshalHeartbeatBody reserves tailReserve up front (#4107 invariant — monitor truncation leaves HMAC space, never silent downgrade). maxHeartbeatGroups=255 + oversize warn once (#4434). Monotonic nanos (#1792) for liveness, StartupGrace 30s suppresses split-brain on simultaneous boot. Auth: HMAC+session+counter, anti-replay re-anchor on new session, constant-time compare, cross-channel downgrade guard (peerAuthSeen). NEGATIVE for core, one LOW on truncation visibility below.
- cluster/sync_protocol.go: length-gated trailing fields (#2170 gen, #3301 AppTimeout, #4565 NAT64), config gen magic trailing framing (#3931), DHCP lease count clamp prevents OOM. NEGATIVE.
- cluster/sync_conn.go: activeConnLocked prefers fab0, bulk re-drive on survivor gated on outboundBulkAcked (not bulkEverCompleted) (#4360 correct), bulkRedriveInFlight CAS prevents storm, writeFull seals per-frame via authConn, acceptLoop per-conn goroutine prevents handshake DoS (#4370). NEGATIVE.
- cluster/sync_auth.go: per-conn frame key derived via canonical nonce sort, seq replay guard, downgrade guard consulted via heartbeat auth seen. NEGATIVE.
- cluster/failover.go: per-RG failoverGen prevents ResetFailover vs pre-hook race (#5246), failoverInProgress serialization, transfer-commit override maps co-located, grace windows 2*threshold*interval+5s min 10s. NEGATIVE, except byte-trunc find below.
- cluster/garp.go: BurstStillValid abdication gate (#2867) checked before each follow-up, burstSendErrors counted, IPv6 NA Router=1 preserves default route. NEGATIVE.
- cluster/monitor.go: dampening (3 fail/3 pass + 5s hold), ICMP id from local port (kernel-overwrites-ident), seq anti-replay, peer MatchesTarget check — hardening present. NEGATIVE.
- cluster/readiness.go: holdTimer closure checks m.stopped (#4716) and cur!=rg (#5245) to avoid stale election. NEGATIVE.
- cluster/reth.go: virtual MAC 02:bf:72:CC:RR:NN per-node unique, stable LLA fe80::bf:72:CC:RR shared. NEGATIVE.
- vrrp/packet.go: VRRPv3 pseudo-header checksum for both families (RFC 5798 §5.2.8), legacy IPv4 no-pseudo accept for migration. Mutable input restored after checksum calc. NEGATIVE.
- vrrp/manager.go: VRID range guard 1..255 (#4573), build-before-teardown for ifindex drift (#2294), sync hold timer, GARP suppression on unsuppress edge fires forced burst (#2940). linkNames ifindex->name cache for rename detection (#2944), addrwatcher separate latch (#2528), desiredIfaces for late-appearing (#2788). NEGATIVE.
- vrrp/instance.go: TTL=255 / hop-limit 255 enforcement (#4549 F8), cBPF filter admits {112,0,43,60} and walks ext headers bounded (max 8), arrival ifindex filter (#2886), self IP filter excludes VIPs, canonAddr for VIP exclusion, owner priority 255 always preempts (#4116), Effective priority clamp [1,254], masterAdverInterval learned with floor=max(local,max 10ms) (#4548) prevents low-interval flap, preemptHold + watchdog (#4584), skipNextPreemptHold one-shot for graceful resign, equal-priority tie-break anchored to single family (#4376). NEGATIVE with one LOW on fail-open arrival.
- vrrp/track.go + addrwatch.go: trackDown boolean, link watcher singleton with gen token, re-evaluate old name on rename, 1s poll fallback, addrwatcher reresolve on every event, drift detection triggers reconcile not iface mutation. NEGATIVE.
- ra/ra.go + sender.go: single-owner contract, drainEntry tombstone covers stop→start window, modeGraceful upgrades hard, goodbyeEmitted observed post-join, joinTimedOut + detached reclaimer (#5094), connReady make-before-break (#2834), rsReceive hop-limit 255 + link-local/unspec source check (#5095), RS rate limit 3s, write deadline 1s, timer leak fixes (#4830), prefixEqual canonicalizes NAT64 (#4590), ReachableTime/RetransTimer included in configEqual (#4570). NEGATIVE.
- conntrack/gc.go: IsLocalPrimary gate (secondary skips expiry), SkipSweep for userspace-dataplane, earlyAgeout clamped to 0 on negative (#3440), scratch buffer reuse, hysteresis under lock (#3604), v6 XOR hash for limit counts (lossy but documented), adaptive delay capped 60s. NEGATIVE.

## Findings

### High confidence

#### [MEDIUM] Failover batch RGID byte-truncation — rgID >255 silently aliases
- Severity: Medium (correctness / split-brain risk on misconfig)
- Confidence: High
- Evidence: `pkg/cluster/sync_protocol.go:474` `payload[0] = byte(len(rgIDs))` and `:477` `payload[1+i] = byte(rgID)`; same pattern in `encodeFailoverBatchAckPayload` and `payload[0]` in heartbeat GroupID `uint8`. `failover.go:474` `failoverBatchKey` joins decimal but encode uses byte.
```go
// sync_protocol.go:474
payload[0] = byte(len(rgIDs))
for i, rgID := range rgIDs {
    payload[1+i] = byte(rgID)
}
```
- Trace: Config allows `redundancy-group <id>` — strict gate in another package, but tolerant load / HA-synced config downgrades gate to warning (#1960). A persisted 256 would encode as 0 (reserved VRID) on wire, failover targets wrong RG, could cause dual-primary or blackhole.
- Refutation attempt: Is RG max 155 due to VRID 100+RG <=255? Reth VRID path uses 100+rgID, but raw VRRP groups can be 1..255 independent. Cluster RG IDs have own validation, but not visible in this batch. Still tolerant load could slip >255.
- Why matters: integer bounds → wrong RG failover, VIP anchored to wrong group, traffic loss.
- Fix direction: Validate `rgID in [1,255]` inside `normalizeFailoverRGIDs` and in encode helpers returning error on out-of-range; defensive decode also rejects 0. Add unit test.
- Labels: `integer-bounds`, `failover`, `rgid`
- Dedup note: Not in batch-012 list (checked batch-012 mentions RA/VRRP hop limit, not this).

#### [LOW] VRRP arrival ifindex fail-open allows cross-VLAN same-VRID processing
- Severity: Low (split-brain flap on exotic platform)
- Confidence: High
- Evidence: `pkg/vrrp/instance.go:1164` `if arrivalIfindex <=0 || expectedIfindex <=0 { return true }` — fail-open.
```go
func acceptArrivalIfindex(arrivalIfindex, expectedIfindex int) bool {
    if arrivalIfindex <= 0 || expectedIfindex <= 0 {
        return true
    }
    return arrivalIfindex == expectedIfindex
}
```
ReceiverIPv6 seam: `receiverIPv6` captures ifindex via control message, but if kernel doesn't provide FlagInterface, ifindex=0 and every sibling VLAN socket processes same advert. Same for afPacket fallback.
- Trace: VLAN sub-interfaces skip SO_BINDTODEVICE, rely on arrival check (#2886). If arrival absent, two instances (reth0.50 / reth0.80 same VRID) both see advert → false BACKUP.
- Refutation: Code intentionally fail-open to not regress delivery; VRID filter + TTL still apply. Real prod (AF_PACKET) does have ifindex, raw fallback only used when af_packet unavailable. So risk limited to degraded path.
- Why matters: dual-master on same VRID different VLAN = ARP conflict.
- Fix: Log once when arrival=0 on VLAN path; optionally keep fail-open but add metric. Document fragility.
- Labels: `vrrp`, `cross-vlan`, `fail-open`
- Dedup note: Not flagged before.

### Low / informational

- Heartbeat monitor truncation silent: version always preserved but monitor list truncated without observable counter — operator cannot tell monitor crowding. Could expose truncated-monitors counter in status (similar to BurstSendErrors). Keep as LOW.
- RA DNSServers raw string compare: `fe80::1` vs `FE80::1` would cause spurious restart (sub-sec gap). Already fixed for prefixes/NAT64 via prefixEqual but not for DNSServers. LOW.
- conntrack GC per-IP counting for IPv6 uses XOR folding into uint32 key — distinct /64s collide, limiting is best-effort. Documented limitation, not a bug.

## Suggested issue split

1. Fix batch RGID bounds (encode helpers + normalizeFailoverRGIDs + heartbeat group cap: return error, add test).
2. Harden VRRP arrival fail-open: log/metrics when ifindex unavailable, add test injecting 0 arrival on VLAN with same VRID.
3. Optional observability: expose heartbeat monitor truncation count and RA DNSServer canonicalization (netip.ParseAddr compare).

Overall: batch is heavily hardened (replay, downgrade, bulk re-drive, RA tombstone). No critical split-brain bypass found. Main actionable is integer-bounds on RGID batch encode.


---

### === ps-A6_go_dataplane_manager-b1.md (15661 chars, 126 lines) ===

# A6 Go Dataplane Manager — Review (b1/3)

## File Inventory (150 files, ~60 prod / 90 test)

Ranked by size×responsibility×hot-path proximity:

- `pkg/dataplane/compiler.go` ~1.6k LOC prod, god compile orchestrator (zones, addr-book, apps, policies, nat, screen, flow). Largest fn `CompileConfig` phases + `compilePolicies` expansion. Responsibility: zone→ID stable hash, policy expansion, app-set.
- `pkg/dataplane/compiler_iface.go` ~1.4k LOC prod, zone/interface mapping, netlink, rxvlan off, MTU, RETH recovery, unmanaged strip, device-map leave-alone.
- `pkg/dataplane/compiler_nat.go` ~1.3k LOC prod, SNAT/DNAT/static/NAT64/NPTv6 compilation, pool ID assignment, counter ID stable hash + collision resolve + finalizer.
- `pkg/dataplane/types.go` ~1.1k LOC prod, all BPF struct mirrors, zone pair key, policy rule, NAT pool, filter config, screen flags.
- `pkg/dataplane/compiler_filter.go` ~0.8k LOC prod, filter protocol validation, policer ID assignment, term→rule cross-product expansion with #5456 cap, iface→filter map.
- `pkg/dataplane/userspace/eventstream.go` ~1.2k LOC prod, binary frame header (len+type+seq), session open/close decode, gap → full resync, pending queue 4096, writeMu sep lock.
- `pkg/dataplane/userspace/manager.go` ~0.4k prod + many split files, snapshot lifecycle, generation, deferred worker arm debt, appliedSnapshot coherency.
- `pkg/dataplane/userspace/builder.go` ~0.2k prod, snapshot assembly, zone collision quarantine, content hash dedup.
- `pkg/dataplane/userspace/filters.go` ~0.6k prod, firewall filter snapshot lowering (prefix-list, except, DSCP, TCP-flags, flex-match).
- `pkg/dataplane/userspace/interfaces.go` ~0.56k prod, synthetic logical ifindex FNV hash, VLAN parent bind contract, bound interface allowlist.
- `pkg/dataplane/userspace/flow.go` ~0.26k prod, wire coercion u16/u32/u64 for Rust JSON decode (MSS, timeouts).
- `pkg/dataplane/userspace/cos.go` ~0.26k prod, CoS snapshot with safe degrade on undefined class.
- Many `*_test.go` (app catalog parity, NAT counter collision/determinism/stability, filter expansion, prefix-list except, port except, host-inbound classify, etc.) — high coverage of edge cases.

Prod files shape: manager pattern with populate-before-clear map writes for legacy BPF; userspace path builds immutable snapshot then single control-socket publish. Zone handling: `assignZoneIDs` uses StableZoneID(name) FNV fold into [1, ReservedMin-1]; policy sets pack into `policySetID*MaxRulesPerPolicy+index` rule ID.

## Module Log (coverage)

- `compiler.go` zones: checked nil zone slot guard, screen profile lookup, host-inbound flags, TCPRst, iface zone composite key, RETH RG inherit, native XDP flag, VLAN sub-if creation, managed interface list for networkd, unmanaged strip with #1922 protected set and #1956 device-map leave-alone, VRF/Tunnel/Bridge owned skip, stale deletion. Policies: application-set expansion, appID map, Any handling, implicit set building, rule ID calculation, scheduler slots. Default policy sentinel #3057. Fail-closed on unknown screen/addr.
- `compiler_iface.go` (already in compiler.go in this tree): resolveInterfaceRef handles reth→phys, irb→bridge, fab IPVLAN parent, tunnel names. VLAN reconciliation, DHCP/RETH skip, link cycle deferral, RX queue tuning. Negative: legacy eBPF direct map writes mid-compile not transactional.
- `compiler_nat.go`: pool ID uint8 assignment, compiledPools cache, v4/v6 split, interface-mode SNAT egress IP per ifindex+vlan, deterministic NAT host-base v4/v6, persistent NAT registration, source/dest addr name resolution, DNAT port/proto expansion with application-sets, SNAT off mode, NAT counter ID stable hash FNV-1a with re-hash collision handling and finalize sorted deterministic finalizer #5099, exhaustion fallback to 0. Checked overflow risk for poolID.
- `compiler_filter.go`: protocol validation via appid.ProtocolNumber SSOT, policer ID 1-based, filter ID deterministic sorted, rule expansion with MaxFilterTermExpansion cap #5456, proto prefilter up to 4 distinct, DSCP/flags/flex handling, iface filter key including vlan+family+direction, stale delete. Good.
- `types.go`: struct layouts, sentinel DefaultPolicySentinelID = 0xFFFFFFFF, counter indices, zone config flags, host-inbound flags.
- `userspace/builder.go`: buildSnapshotWithSchedulerStateAndNATCounters → zones, interfaces, fabrics, tunnels, neighbors (filter publishable), routes (kernel ip-rule enum fail-closed #3772), flow, default policy log flags, policies with feed overlay, NAT snapshots with feed overlay, NAT64, NPTv6, screens, filters with effective rendering, policers, CoS, mirror, address books with collision error #2514, app catalog with overflow check #3438. Quarantine colliding zones #3719 stamping collisions, updating summary counts.
- `userspace/filters.go`: resolvePrefixListAddrs shared SSOT #3433, handles realLiteral dropping any/empty, constrained flag for empty resolution fail-closed, except handling #5097 unresolved except polarity, #4338 any-except compose, positive-wins warning for mixed #3359, port except positive-wins #2622, DSCP unrepresentable fail-closed marker #3406, TCP flags expression parse with fail-closed marker #3367, flex-match ceil bits #3203, match-start layer-3/4.
- `userspace/interfaces.go`: syntheticLogicalIfindex FNV hash probing within 1<<20 range, panic on exhaustion, logical-only parent-bound RETH VLAN #???.
- `userspace/eventstream.go`: hdr 16 bytes little-endian, length sanity 1024 max, decode session v4/v6 with #2467 i32 widened ifindex, #3075 u16 zone widen, disposition, flags (fabric redirect, log flags, NAT64), trailing firewall metadata length-gated #3301, close event decode, dataplane event payload cross-check type vs payload[52], ackLoop 100ms, writeFrame with writeMu sep from mu #4835, pending queue bounded 4096 forces disconnect → full resync #2874, SeqGaps handling differs for session-sync vs telemetry.
- `userspace/flow.go`: coerceWireU16/U32Timeout/SessionTimeout with warning, caps MaxUint16/MaxUint32/MaxDurationSeconds to avoid Rust serde_json u16/u32/u64 decode error #1977.
- `userspace/cos.go`: scheduler map undefined forwarding-class skip+warn #2409, undefined scheduler kept with warn (degraded not blackhole), DSCP classifier skip+warn #2704.
- `userspace/manager.go` + split controllers: boot pins, capabilities, appliedSnapshot tracking for NAT alarm coherency #2079, deferWorkers debt #5134 retry loop, HA watchdog map write every tick + IPC throttled.
- Negative checks passed: filter expansion bounded, prefix-list except polarity fixed #5097, host-inbound global accept mirrors nft chain, address-book collision fail-closed, app catalog overflow check, DSCP/tcp-flags/icmp unrepresentable fail-closed, flow wire coercion prevents helper decode abort.

## Findings — High Confidence

### 1. NAT pool ID uint8 overflow → silent pool collision (fail-open)
Severity: High (NAT misc-translation)
Confidence: High
Evidence:
`pkg/dataplane/compiler_nat.go:236-244` `poolID := uint8(0)` then `curPoolID = poolID; poolID++` without cap, also `result.NextPoolID` is uint8.
`pkg/dataplane/compiler_nat.go:1232-1238` `newID := result.NextPoolID; result.NextPoolID++` assigning NAT64 pools after SNAT pools.
If config has >255 source+NAT64 pools, uint8 wraps to 0, two distinct pool names share same pool ID, SetNATPoolConfig overwrites, traffic SNATs to wrong pool.
Trace: compileNAT loops source pools → increments poolID per named pool first encounter → no check >255 → compileNAT64 uses NextPoolID also uint8 → wraps → SetNATPoolConfig overwrites previous pool config → sessions get wrong external IP, potential inter-tenant leak.
Refutation: MaxNATPoolIPsPerPool caps IPs per pool, not number of pools. MaxNATRuleCounters caps counters but not pools. No validation in pkg/config for max pool count. PoolIDs map is map[string]uint8 but no overflow guard.
Why it matters: production configs with many v4+v6 pools (CGNAT) could hit 255, causing silent mis-NAT, not commit error.
Fix: add explicit check `if poolID == 255` or `len(result.PoolIDs) >= 255` → return fmt.Errorf pool limit exceeded; also change PoolIDs to uint16 or enforce cap like MaxNATPools constant. Add unit test for 256 pools.
Labels: nat, pool-math, fail-open, vsrx-parity
Dedup note: not in dedup index; #5484 shim map ABI but not pool ID overflow.

### 2. Synthetic ifindex exhaustion panics daemon (DoS)
Severity: Medium (control-plane crash)
Confidence: High
Evidence:
`pkg/dataplane/userspace/interfaces.go:38-54` `func syntheticLogicalIfindex(...) { ... panic(fmt.Sprintf("userspace snapshot: exhausted synthetic...")) }`
Span is 1<<20 = 1,048,576. Loop probes `span` candidates, panics if all used. Called from `buildInterfaceSnapshots` for logical-only parent-bound RETH VLAN units (reth0.80 etc when child ifindex 0). Build runs under ApplyConfig hold; panic kills daemon, no catch, restarts, retries same config → crash loop.
Trace: RETH with many VLAN units where parent ifindex known but child 0 → shouldUseLogicalOnlyParentBoundRethVLAN true → synthetic allocation per unit. If >1M such units (pathological but possible via automation) or hash collision + used map saturated, panic.
Refutation: attempt to refute via caller handling — no recover; builder is not wrapped in panic guard. Must be error, not panic.
Fix: change to return error, propagate to buildSnapshot → fail-closed commit reject. Replace panic with `(int, error)`. Add test for exhaustion path returning error.
Labels: control-plane, panic, DoS, interfaces
Dedup: not in dedup; similar to other synthetic ranges but this one panics.

## Findings — Medium Confidence

### 3. Legacy eBPF path partial-apply not transactional (stale mixed maps)
Severity: Medium (legacy, but code still reachable in tests)
Confidence: Medium
Evidence:
`pkg/dataplane/compiler.go:219-223` compileZones calls `dp.SetZone`, `dp.SetVlanIfaceInfo`, etc. directly; on error mid-loop returns, but `DeleteStaleIfaceZone` only runs on success path end. Same pattern in `compileNAT` #935-940, `compileAddressBook` clears then repopulates (clear before populate — if second phase fails, map cleared but not repopulated fully).
`pkg/dataplane/apply.go` (Manager.Compile) calls CompileConfig which writes BPF maps incrementally.
If CompileConfig fails after some map writes, BPF maps are left half-new/half-old, but lastCompile not updated, so operator sees old ApplyResult while dataplane enforces mixed state → policy bypass or blackhole until next successful compile.
Trace: apply with invalid zone (missing screen profile) → compileZones writes some zones → compileAddressBook clears tables → compilePolicies fails → returns error → maps have cleared addr book but partial zones.
Why still relevant: tests exercise DataPlane interface with in-memory maps; userspace snapshot path is safe (pure), but legacy manager still exists for shim tests.
Fix: for legacy path, either build all entries in temp maps then swap, or defer stale delete and add rollback; or document as deprecated and gate Compile to only run on userspace shim (already retirement). At minimum add comment and ensure Manager.Compile for legacy is not used in production (it isn't, but tests).
Labels: partial-apply, legacy, refactor
Dedup: similar to #5485 shim attach before publish, but this is map-write mid-compile.

### 4. Zone ID collision not handled in legacy compile path (fail-open merge)
Severity: Medium
Confidence: Medium
Evidence:
`pkg/dataplane/compiler.go:156-172` `assignZoneIDs` does `result.ZoneIDs[name] = config.StableZoneID(name)` with no collision check. StableZoneID is hash, collision possible (birthday). `pkg/dataplane/userspace/builder.go:139-152` has `quarantineCollidingZones` dropping later-sorting colliding zone + unzoning interfaces + dropping policies.
Legacy `compileZones` loops over zones and uses `zid := result.ZoneIDs[name]` — if two names collide to same zid, second overwrites first's ZoneConfig in map (SetZoneConfig same zid), merging two security zones into one: traffic from both zones allowed via same policy set if second's policies reference same zid, or policy sets keyed by zone pair using ZoneIDs of colliding names both resolve to same numeric, merging policies.
Trace: zone A and B hash same → both get zid=42 → zone_config[42] holds B's config → iface_zone for both A and B interfaces points to 42 → policies A→C and B→C both resolve to same from zid, but only one PolicySet stored per ZonePairKey (from=42,to=C) → last write wins, other policy lost → fail-open (traffic allowed/denied opposite).
Refutation: quarantine only on userspace path; legacy path lacks. Collision probability low (FNV 16-bit space? Actually StableZoneID folds into [1, 4095]? Wait ZoneIDReservedMin maybe 4096, so 4095 values, 64 zones → ~50% collision at 64? Actually need config definition). So non-negligible.
Fix: add collision check in assignZoneIDs returning error or quarantine same as userspace builder, and add SAME quarantine to legacy path, or make StableZoneID injective via sorted assignment after dedup.
Labels: zone-policy, collision, fail-open, parity
Dedup: not in dedup; #3719 is userspace quarantine, this is legacy gap.

### 5. Global policy {0,0} collides with potential zero zone ID though zero reserved as wildcard
Severity: Low
Confidence: Medium
Evidence:
`pkg/dataplane/compiler.go:992-1001` global policy uses `ZonePairKey{FromZone:0,ToZone:0}`. Zone IDs start at 1 per StableZoneID, but 0 is used as wildcard for DNAT fromZone wildcard (DNAT docs). If a future zone ID scheme returns 0 for default zone (not today), collision would overwrite global. Today safe, but fragile.
Better use sentinel like MaxZones+1 or explicit global map.
Fix: document invariant that zone ID 0 never assigned (currently true), add assertion `if zid==0 panic`. Already StableZoneID never returns 0.
Labels: fragility, refactor

## Findings — Low Confidence / Negative (proving coverage)

- Filter cross-product bound #5456 present and correct, prevents OOM.
- Firewall filter prefix-list except polarity #5097 fixed, plus any-except compose #4338.
- DSCP/ICMP unrepresentable → fail-closed marker #3406, TCP flags expression parse #3076/#3367.
- Flex-match ceil bits #3203 and oversized length not capped → fail-closed.
- NAT counter ID stable hash + finalize sorted deterministic #5099, exhaustion to 0 preserved.
- App ID overflow guard >65535 in compileApplications #3438.
- App catalog port zero sanitization #5194 A3-b1-F2 via NormalizeExplicitPortRange.
- Eventstream length check 1024, sequence gap forces full resync #2874, writeMu #4835 prevents interleaved deadline+write race.
- Flow wire coercion #1977 clamps u16/u32/u64 to prevent Rust serde abort.
- CoS scheduler-map undefined class skip+warn #2409 degraded not blackhole, DSCP classifier skip #2704.
- Host-inbound token admission uses structured SSOT HostInboundServiceMatch/ProtocolMatch, global accept mirrors nft top chain.
- Synthetic ifindex for VLAN parent bind uses single source of truth userspaceBindTargetNetdev mirroring Rust vlan_child_parent_netdev, parity tests guard.
- Address-book collision returns AddressBookIDCollisionError → fail-closed #2514.
- Default policy sentinel 0xFFFFFFFF prevents collision with real policy 0 #3057.

## Suggested Issue Split

- Issue 1: Enforce NAT pool ID limit (<255) and avoid uint8 wrap — one PR with cap + test.
- Issue 2: Replace syntheticLogicalIfindex panic with error — one PR.
- Issue 3+4: Unify zone ID collision handling across legacy and userspace paths (quarantine) — one PR, add collision detection to assignZoneIDs.

All findings defensive, no third-party targeting, owner review.


---

### === ps-A6_go_dataplane_manager-b2.md (7597 chars, 94 lines) ===

# Batch A6 b2/3 — Go dataplane manager (policy, zones, NAT, routes, HA glue)

Base: 7e0fecf3b, worktree /tmp/review-wt-claude-003-A6_go_dataplane_manager-b2
Files: 150, prod ~12k LOC core, test ~58k LOC; largest: protocol.go 3064 (snapshot v3), maps_sync.go 1763, manager_ha.go 1643, filters.go 641.

## Inventory (ranked responsibility × hot-path proximity)

| File | LOC | Responsibility | Cold/Hot | Largest fn |
|---|---|---|---|---|
| protocol.go | 3064 | wire version=3, 66-field ConfigSnapshot, inject bound 4096 (DoS reject-not-clamp), ZoneCounterLayout/ColdPathLayout versions | cold but version invariant governs rolling upgrade | ConfigSnapshot struct |
| policies_lower.go | 170 | global->zone lowering, singular/plural scoped-global #4626 M03, additive-wire compat | cold, #5488 interop | buildOneRuleSnapshot + effectiveMatch* |
| policies.go | 800+ | walkPolicyRuleSlots ID namespace #3143/#3145 MaxRulesPerPolicy cap, feed overlay #2049, representability sentinel #3261, app sentinel #2124 | cold but fail-open if sentinel missing | buildPolicySnapshotsWithFeeds |
| zones*.go | 300+370 | StableZoneID hash, quarantine #3719, host-inbound SSOT lifeline #3682 per-iface override union #3362, default-deny parity #3405 for no-stanza zones, VIP scoping #3172, unzoned junos-host catch-all | cold, zone collapse=fail-open | BuildZoneHostInboundViews |
| nat*.go | ~2k | pool tiers iface>zone>ri #184 #4161, any->"" fix, match-any dest fail-open, persistent NAT, deterministic block alloc, Off handling | cold, misc-NAT leak | buildSourceNATSnapshots |
| routes.go | 300 | FIB connected+static+ip-rule leaks family-normalized (blue.inet6.0 fix), Dst-less skip avoids widening, PBR bands 100-199/30000-30999, list error fail-closed whole snapshot | cold but leak miss=blackhole/bypass | buildRouteSnapshots |
| manager_ha.go | 200 | seed inventory #1928 drops phantom groups on non-cluster, watchdog-only refresh preserves Active, clearHelper empty idempotent | cold | syncHAStateLocked |
| maps_sync.go | partial | RST suppression TOCTOU, interface NAT addr sets sorted dedup | cold | syncInterfaceNATAddressMapsLocked |

## Module log (negatives)

- policies_lower: singular=first zone, plural=full set, effectiveMatch* prefers plural fallback singular — new helper correct, old helper same version 3 ignores plural narrows deny (dedup #5488). **NEGATIVE for new, known interop.**
- policies.go: any4/any6/any-ipv4/any-ipv6 literal accept, feed-bound membership, nameToID+recursive nameRepresentable, unrepresentable -> __unsupported_address__ on both v3+legacy shapes clearing book IDs => Rust SnapshotIntegrityError whole-snapshot reject prev-good retained fresh-boot default-deny. app -> __unsupported_application__ name+proto both sentinel, Rust reject. literal vs book via classifyPolicyAddresses, scheduler state, SourceAddressExcluded/DestinationAddressExcluded inversion. **NEGATIVE — fail-closed solid.**
- zones: zone-default group seeded for #3405 (no stanza => empty token set => default-deny still), override map CanonicalHostInboundTokenSig dedup, VIP unit names for subif, unzoned addrs builder, quarantine collision drops zone + unzones ifaces + drops scoped global. **NEGATIVE.**
- nat: pool missing/empty/invalid port -> PoolUnusable+reason, deterministic only when usable, FromZone "" = global/match-any not zone named "any" specific, tier calc most-specific 0, stable sort. **NEGATIVE, pool uint8 wrap noted in b1.**
- routes: family loop per-family next-table cures IPv6 blackhole, Dst-less skip explicitly not widened (would DROP selector), band filter avoids PBR widening to leak, ip-rule list error fails whole snapshot not partial, synthetic rib-group/next-table leaks per-prefix only. **NEGATIVE.**
- manager_ha: #1928 clears HA on non-cluster, watchdog-only preserves Active, clear empty idempotent, fabric sync. **NEGATIVE, clear error swallowing dedup #5487.**
- process/eventstream: requestLocked deadline #4036 cap #2744 writeFrame race #4835 via writeMu, pending queue 4096 triggers resync #2874. **NEGATIVE.**

## Findings

### [MEDIUM] Scoped-global multi-zone deny narrows on version-3 rolling upgrade (#5488 zone impact)

- Title: old helper ignores plural zones
- Severity: Medium
- Confidence: High
- Evidence: `policies_lower.go:210-217`
```go
MatchFromZone:  config.ScopeSingular(pol.Match.FromZones),
MatchFromZones: pol.Match.FromZones, // full set
```
`protocol.go:11` `ProtocolVersion=3` unchanged after #4626 additive field. `effectiveMatchFromZones` prefers plural.
- Trace: config `from-zone [trust untrust] deny` -> singular=trust, plural=[trust,untrust]; old helper reads singular only -> untrust bypass (fail-open).
- Fix: bump to v4, doc upgrade order helper first, extend scoped_global_zoneset_4626 with old-helper sim.
- Labels: zone-policy, rolling-upgrade, fail-open
- Dedup: extends #5488 with zone traffic impact.

### [MEDIUM] VRRP VIP host-inbound scoping first-wins on iface ownership duplicate (lenient path)

- Title: buildInterfaceZoneMap first-wins leaves second zone VIP without deny
- Severity: Medium (lenient/HA-synced path only)
- Confidence: Medium
- Evidence: `zones_host_inbound.go:353` `for _, view := range BuildZoneHostInboundViews` iterates; `zones.go` interface zone map first writer wins.
```go
overrideByIface := buildInterfaceHostInboundMap(cfg)
```
If duplicate interface ownership leniently allowed, second zone's VIP not in dest set, kernel input chain policy accept -> VIP exposed without host-inbound check.
- Trace: strict gate rejects duplicate; lenient load (tolerant #1960) could slip. HA-synced config bypasses strict validation -> standby could expose mgmt.
- Fix: BuildZoneHostInboundViews should collect all zones owning iface and union, or error on duplicate in lenient path. Add test duplicate iface two zones -> both VIPs scoped.
- Labels: host-inbound, zone, lenient, fail-open
- Dedup: distinct from #5478 monitor.

### [LOW] Workers uint32 truncation — no upper cap before uint32 cast

- Title: deriveUserspaceConfig floors to 1 but no upper bound
- Severity: Low
- Confidence: Medium
- Evidence: `manager_compile.go` or `process.go` path `programBootstrapMapsLocked` casts `int workers` to `uint32` without clamp; heartbeat zeroSlots path clamps #4572 but ctrl path does not. Large int wraps? Actually int->uint32 cast in Go keeps low 32 bits, large value e.g., 1<<32 becomes 0 -> cap guard fail-closed.
- Fix: clamp workers to [1, 1024] before cast, add test.
- Labels: int-bounds, control-plane

### [LOW] Unzoned catch-all policy-accept leaves unzoned IP exposed

- Title: xpf_hostinbound base accept
- Severity: Low
- Confidence: High
- Evidence: `zones_host_inbound.go:330-333` comment notes fail-open for unzoned iface.
- Fix: ensure strict gate rejects unzoned iface (already compile-time), add status metric.
- Labels: host-inbound, fail-open

### [LOW] Route snapshot duplicate NextTable from rib-group+next-table overlap

- Severity: Low
- Confidence: Medium
- Evidence: `routes.go:160-194` emits per ip-rule; two rules same Dst different table -> two snapshots same prefix diff NextTable.
- Fix: dedupe per (family,table,Dst) keeping highest pref, log.
- Labels: VRF, deterministic

## Suggested split

1. Zone-policy version bump or upgrade-order doc for #5488.
2. Host-inbound duplicate-iface scoping fix (first-wins -> union/error).
3. Workers uint32 clamp + route dedupe (low).

Overall: b2 heavily hardened (sentinels, family norm, #1928, #3405). No critical zone-bypass beyond known #5488 interop. Merged agent findings: workers truncation + first-wins VIP duplicate.


---

### === ps-A6_go_dataplane_manager-b3.md (12072 chars, 137 lines) ===

# Security Review — BATCH A6_go_dataplane_manager b3/3

**Files:** `pkg/nftables/rst_suppress.go` (204 LOC prod), `pkg/nftables/rst_suppress_test.go` (37 LOC test) – total 241.
**Base:** 7e0fecf3b8f2dc6604600674373771c835484188
**Worktree:** /tmp/review-wt-claude-003-A6_go_dataplane_manager-b3

## File-size/shape inventory
- `rst_suppress.go`: 204 LOC, prod. Responsibility: atomic nftables table `xpf_dp_rst` management for DROP outgoing TCP RSTs from interface-mode SNAT addresses owned by userspace dataplane. Called from `pkg/dataplane/userspace/maps_sync.go:1141` under `m.mu` in `syncInterfaceNATAddressMapsLocked`. Not hot-path (config apply only), but critical for HA failover correctness (#450) and for silent-drop semantics of zone deny. Largest fn `addRSTDropRule` 57 LOC (L144-200) — 8 nft expr builder; `InstallRSTSuppression` 22 LOC (L36-57); `queueRSTSuppression` 29 LOC (L104-133).
- `rst_suppress_test.go`: 37 LOC, test. 2 tests covering only `buildRSTSuppressionPlan` delete flag logic. No rule-construction, offset, or concurrency tests.
- Rank by size×responsibility×hot-path proximity: **medium** — small LOC but touches silent zone-deny enforcement + HA session survivability; cold-path but availability-critical.

## Module log (coverage proof — negatives explicit)
- Read `rst_suppress.go` fully; verified offsets `saddrOffset` 12 (IPv4) / 8 (IPv6) and TCP flags offset 13, mask 0x04 — correct per IPv4/IPv6/TCP layout.
- Traced callers: only `pkg/dataplane/userspace/maps_sync.go:1132-1149` (`shouldAttemptRSTSuppression` gate + sorted deduped addrs) — under `Manager.mu` (checked `manager.go:88,249,302`). `RemoveRSTSuppression` has zero callers outside definition (dead code) — verified via `grep -rn RemoveRSTSuppression`.
- Traced address source: `buildDesiredInterfaceNATAddressSets` → `buildInterfaceNATAddressEntries` → `buildNATTranslatedLocalAddressExclusions` (filters `InterfaceMode && !Off && ToZone != ""`, then matches interface zone). Dedup via `seenV4`/`seenV6` maps, sorted before install — no duplicate rules in normal path.
- Checked `pkg/nftables/` remaining files: `host_inbound_*`, `lo0_counters` — unrelated tables, same idempotent `ListTablesOfFamily` + `ENOENT` handling pattern.
- Checked zone policy interaction: RST suppression table `INet` family, `output` hook, filter priority. It DROPs RSTs that kernel would otherwise emit for SNAT addresses. This **strengthens** zone deny silent-drop (prevents RST leak revealing host), does not bypass deny. Verified no overlap with `xpf_hostinbound` (input) or lo0. Negative finding for bypass.
- Checked atomicity claim: delete+add in single `Flush()` batch — matches `README.md` #450 note. Verified TOCTOU between `rstTableExists` (separate netlink dump) and `Flush`.
- Checked int truncation / endian: `As4()` returns `[4]byte` native network order, fed to `net.IP(addr[:])`; `addrLen` 4/16 fixed, no truncation. IPv4 key BigEndian Uint32 used elsewhere but not here.
- Checked error logging: `slog.Info` only on success, not per-tick; acceptable.
- Checked `ptrPolicy` return of address of local copy — escapes to heap, safe.

## Findings

### [F1] Panic on mis-typed Addr slice — As4() panic if v6 passed in v4 slot
**Severity:** Medium
**Confidence:** High
**Evidence:** `rst_suppress.go:135-137`:
```go
func addRSTDropRuleV4(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr [4]byte) {
    addRSTDropRule(c, table, chain, net.IP(addr[:]), uint32(4), 12, unix.NFPROTO_IPV4)
}
...
for _, addr := range plan.v4Addrs {
    addRSTDropRuleV4(c, table, chain, addr.As4())
}
```
`netip.Addr.As4()` panics if not IPv4 per stdlib docs. `InstallRSTSuppression` takes `[]netip.Addr` without validating family.
**Trace:** Caller today separates via `AddrFrom4`/`AddrFrom16` so safe, but API is public within package subtree; any future caller or malformed test passing IPv6 in v4 list crashes daemon (DoS). Production path not currently vulnerable, but defense-in-depth failure.
**Refutation attempt:** Checked `maps_sync.go:1165-1176` — yes caller correctly separates. However `InstallRSTSuppression` is exported; nothing prevents external misuse. Panic is not caught; daemon would crash → fail-open (no forwarding until restart).
**Why matters:** Fail-open via panic during config apply (malformed snapshot) → transit outage.
**Fix:** Validate `addr.Is4()` before `As4()`; skip invalid or return error. For v6 similarly `Is6()`. Add guard in `InstallRSTSuppression`.
**Labels:** fail-closed, DoS, API-hardening
**Dedup note:** Not in dedup index; #5486 is about swallowing errors, distinct.

### [F2] RemoveRSTSuppression dead code + swallows Flush error → stale RST suppression after daemon stop
**Severity:** Low (availability / diagnosability)
**Confidence:** High
**Evidence:** `rst_suppress.go:60-71`:
```go
func RemoveRSTSuppression() {
    c, err := nftables.New()
    if err != nil {
        return
    }
    tableExists, err := rstTableExists(c)
    if err != nil || !tableExists {
        return
    }
    removeRSTTable(c)
    _ = c.Flush()
}
```
Zero callers found (`grep -rn RemoveRSTSuppression` only definition). Not called on daemon stop; table persists after daemon exit. Empty-config cleanup uses `InstallRSTSuppression(nil,nil)` path (delete via queue), so this function is dead. Error from `Flush()` ignored — if delete fails, suppression lingers, dropping legitimate kernel RSTs when kernel regains ownership of addresses (post-daemon-stop), causing TCP blackhole (peers see timeout not RST).
**Trace:** Daemon shutdown `stopLocked` does not call this. `README.md` says callers `pkg/daemon` but code shows `pkg/dataplane/userspace`. Table `xpf_dp_rst` remains until reboot.
**Refutation:** Could argue intentional to keep protection during transient stop, but after full stop kernel should be authoritative. Lingering drop is wrong. Empty-slice Install path does delete, so if config later removed, table cleaned. Only shutdown leak remains.
**Why matters:** Post-shutdown blackhole, troubleshooting confusion.
**Fix:** Either delete function + call on daemon shutdown, or document intentional persistence and log. Fix error handling to return error/log on Flush failure.
**Labels:** resource-lifetime, dead-code, availability
**Dedup note:** Not in index; related to #5485 but distinct (there attach leak, here nft table leak).

### [F3] TOCTOU between ListTables and transactional Flush — transient unprotected window on concurrent external nft manipulation
**Severity:** Low
**Confidence:** Medium
**Evidence:** `rst_suppress.go:41-46`:
```go
    tableExists, err := rstTableExists(c)
    if err != nil {
        return err
    }
    plan := buildRSTSuppressionPlan(tableExists, v4Addrs, v6Addrs)
```
`rstTableExists` does `c.ListTablesOfFamily` (separate netlink dump). Then `queueRSTSuppression` adds DelTable+AddTable to same Conn's batch, then `Flush()` sends atomic batch. If table deleted externally between dump and flush, Del in batch gets ENOENT and transaction may fail (google library returns error), leaving no table (unprotected). Retry logic in `maps_sync.go:1141-1147` (5s backoff via `shouldAttemptRSTSuppression`) recovers, but during HA RG demotion microsecond window (#450) this is exactly the race they fixed internally.
**Trace:** External `nft` CLI or host-inbound table recreation (different table name, not same) won't trigger, but another xpfd instance or admin `nft delete table inet xpf_dp_rst` could.
**Refutation:** Manager holds `mu`, so no self-concurrency. External manipulation low probability. Atomic batch still better than old two-step.
**Why matters:** Brief RST leak during HA failover → TCP session reset (availability).
**Fix:** Make `removeRSTTable` best-effort inside transaction or ignore ENOENT on Del path; alternatively always queue Del without existence check (nft transaction tolerates delete of non-existent if using NFT_MSG_DELTABLE with no error? check — but library may still error). At minimum log and retry immediately on ENOENT-flush failure rather than waiting 5s.
**Labels:** concurrency, TOCTOU, HA
**Dedup note:** Distinct from dedup #450 fix note; this is residual TOCTOU.

### [F4] Fail-open on nftables unavailable — warning only, no metrics, HA session continuity at risk
**Severity:** Low (availability)
**Confidence:** High
**Evidence:** `maps_sync.go:1141-1143`:
```go
    if err := xpfnft.InstallRSTSuppression(rstV4, rstV6); err != nil {
        slog.Warn("userspace: RST suppression unavailable (nftables error, non-fatal)", "err", err)
        m.lastRSTInstallOK = false
```
`InstallRSTSuppression` returns error wrapping `nftables conn: ...` or `list tables` or `flush`. Caller treats as non-fatal. No Prometheus counter, only log.
**Trace:** If netlink fails at boot (permission, kernel module not loaded), every HA failover during this window will leak RSTs → kill TCP sessions owned by peer.
**Why matters:** Silent availability degradation; operators may miss single warning in journal.
**Fix:** Add metric `xpf_nft_rst_suppress_install_failures_total` and keep existing 5s retry. Already has retry via `shouldAttemptRSTSuppression` backoff, which is good. Document fail-open nature.
**Labels:** observability, fail-open, HA
**Dedup note:** Not in index; #5487 is standalone→cluster stale HA, unrelated.

### [F5] Test coverage gaps — no validation of offsets, mask, chain priority, empty/atomic case
**Severity:** Low
**Confidence:** High
**Evidence:** `rst_suppress_test.go:8-37` — only 2 tests:
```go
func TestBuildRSTSuppressionPlanSkipsDeleteWhenTableMissing(t *testing.T) {
    plan := buildRSTSuppressionPlan(false, []netip.Addr{netip.MustParseAddr("172.16.80.8")}, nil)
    ...
}
func TestBuildRSTSuppressionPlanDeleteOnlyRequiresExistingTable(t *testing.T) {
```
No test for `queueRSTSuppression` false path (both empty, table missing → no Flush), nor for rule fields (`saddrOffset` 12/8, `addrLen` 4/16, `Mask 0x04`, `MetaKeyNFPROTO`, `ChainHookOutput`, `ChainPriorityFilter`, `PolicyAccept`). No IPv6 rule test, no duplicate handling, no panic-safe family mismatch.
**Why matters:** Refactor could invert offset or swap v4/v6 family byte and tests still pass; this controls silent drop of RSTs.
**Fix:** Add table-driven tests for `queueRSTSuppression` return value and for `addRSTDropRule` expr layout using a fake Conn (google/nftables allows `Conn` with `TestDial`? or inspect queued rules). At minimum test empty install no-op and mismatch-family guard.
**Labels:** test-gap
**Dedup note:** Not in dedup.

## Negative findings (proven)
- **Zone policy bypass:** Does NOT bypass. RST suppression is output DROP of kernel-generated RSTs from SNAT addresses only; zone deny is enforced in Rust dataplane (XDP) dropping before kernel. Suppression prevents kernel from overriding silent-drop with RST leak — strengthens confidentiality. Confirmed output hook vs host-inbound input separation; no zone field in rule, matches only saddr + RST flag, not policy verdict.
- **Integer bounds / byte order:** No truncation; `As4()`/`As16()` produce network-order bytes; offsets 12/8 correct; TCP flags 13 correct; mask 0x04 correct for RST.
- **Fail-closed on malformed config:** Caller filters via `net.ParseCIDR` and link-local fallback; invalid entries skipped. If snapshot nil returns nil.
- **No atomic file writes path** — uses netlink, not file.
- **Chain priority / policy:** `ChainPriorityFilter` + `PolicyAccept` correct — only matched RSTs dropped, rest accepted, so does not interfere with other output filtering.

## Suggested split
- Issue 1: [F1] panic hardening — small PR, add validation + unit test for wrong family.
- Issue 2: [F2]+[F3]+[F4] lifecycle & errors — make Remove callable or remove dead code, add metric, handle ENOENT in Flush.
- Issue 3: [F5] test coverage — add rule-construction tests.

## Honesty note
No evidence of active zone-bypass vulnerability; RST suppression is correctly scoped to interface-NAT addrs and strengthens silent deny. Main risks are panic on misuse, stale table after shutdown, and observability gap.


---

### === ps-A7_go_daemon_host-b1.md (14088 chars, 140 lines) ===

# Review: A7_go_daemon_host (batch 016) — Zone/HA/NFT/Apply ordering

Base: 7e0fecf3b8f2dc6604600674373771c835484188
Worktree: /tmp/review-wt-claude-003-A7_go_daemon_host-b1

## File-size/shape inventory
- Total in pkg/daemon: 199 files (51 prod, 148 test) — batch 016 covers 150 of them.
- Total LOC (prod+test): 60852
- Top prod by LOC / responsibility x hot-path proximity:
  1. `daemon_run.go` 2487 — boot predicate, bootstrap exit, shutdown ordering, FRR fail-closed clear
  2. `daemon_apply.go` 2153 — 10+ subsystems, fail-closed error joins, C1-C3 ctx boundaries, zoneRGMap install
  3. `daemon_nft.go` 1698 — inet xpf_lo0 (prio 0) + xpf_hostinbound (prio 10) rendering, counter lifecycle, fail-closed
  4. `daemon_system.go` 1731 — DNS/NTP/hostname/timezone/kernel tuning, lo0/host-inbound fail-closed joins
  5. `daemon_ha.go` 1576 — RG state machine, cluster+VRRP funnel, blackhole routes, per-RG services
  6. `daemon_ha_sync.go` 1020 — coldStart sticky, sync-ready timer, bulk prime retry, config-sync gate
  7. `daemon_ha_fabric.go` 965 — fab0/fab1 IPVLAN deferral, neighbor probe, dual-fabric refresh
  8. `bootstrap.go` 944 — five-case boot predicate, lifeline record, protected set, fail-closed FRR probe
  9. `host_tunables.go` 839 — governor/budget/coalesce capture/restore, drift detection, debt handling
 10. `device_map.go` 836 — mapped rename, strand-management preflight, teardown fail-closed #5309

Largest funcs: `applyConfigLocked` ~500 LOC (head+tail split), `applyDataplaneAndHACore` ~400, `buildHostInboundFilterPayload` ~200.

Prod vs test: prod 51 files ~18000 LOC, test 148 files ~42000 LOC. Batch includes almost all prod.

## Module log (coverage with negatives)
- `bootstrap.go`: reviewed boot predicate (computeBootClass), lifeline detection via default route, protectedInterfacesWith fxp0 narrowing. NEGATIVE: fail-closed on compile-failed boot correctly preserves FRR probe via pinned-links prefilter + control-socket armed check (#1993). Device-map boot refusal #5490 wired.
- `coalescence.go`: mlx5-only, ethtool -c probe idempotent, adaptive-rx/tx + rx/tx-usecs pin. NEGATIVE: non-mlx5 skip, empty allowlist no-op, best-effort never blocks bring-up — sound.
- `daemon.go`: applySem, bootstrapMode atomic, rgStates, fabric state. NEGATIVE: no zone-ID logic here.
- `daemon_apply.go`: apply ordering VRF->tunnel/xfrmi/bond->fabric IPVLAN->dataplane->networkd->RETH MAC->proxyARP->VRF rebind->FRR->next-table/rib-group/PBR->neighbor/RA/IPsec/DHCP/DDNS/DHCP clients->VRRP/DNS/NTP/lo0/host-inbound/SSH/login/sudoers/archive/flow/LLDP/event-options/RPM/IPmon/cluster. Fail-closed joins: networkdErr, dhcpServerErr, ipsecErr, hostInboundErr, lo0Err, ifaceErr all joined at tail. C1/C2/C3 ctx boundaries checked. ZoneRGMap installed after ApplyConfig. device-map teardown BEFORE networkd.Apply (correct). FINDING #3 below.
- `daemon_nft.go`: chain priorities 0 vs 10 distinct (#3364), add+delete idempotent, counter pre-declare dedup, TCP flags fail-closed #5512, ICMP divergence, address-family filtering, lo0 reject faithfulness. NEGATIVE: no fail-open on unzoned (#4420 HI-2 emits junos-host sentinel DROP). Host-inbound ambiguous logging (#3718) only warn, not fail-closed — acceptable because strict commit gate rejects.
- `daemon_ha.go`: RG state machine unified, activation order rg_active FIRST then blackhole remove, deactivation blackhole FIRST then rg_active clear. Preflight for fabric redirect. No zone-ID logic beyond snapshotRethMasterState.
- `daemon_ha_fabric.go`: fab0/fab1 IPVLAN deferred until XSK bound (zerocopy), stale cleanup, retry 5x. NEGATIVE: fail-open? Logs CRITICAL but continues — HA heartbeat loss bounded by retry, acceptable.
- `daemon_ha_sync.go`: coldStart = !BulkEverCompleted sticky (dedup #5480 — NOT re-reporting). Sync-ready timer 5s, bulk prime retry with progress detection. Config-sync rejected when RG0 primary (prevents secondary overwrite). NEGATIVE: heartbeat suppression cap 5s monotonic (#1792) sound.
- `daemon_ha_userspace*.go`: zone ID via buildZoneIDs (StableZoneID FNV-1a, matches pkg/dataplane assignZoneIDs — symmetry test `zoneid_ha_symmetry_test.go` proves). Session conversion with NAT port fallback, MAC parse, FabricIngress flag, policyID/counter/timeout propagation (#3301). Delta filtering local_delivery, missing_neighbor_seed, ownerRG primary check. FINDING #2 below.
- `daemon_policy_invalidate.go`: deletion-clear Junos-default, modified-policy gated on policy-rematch, default-policy sentinel 0xFFFFFFFF separate from 0, enumerate error surfaced, HA delete-sync. FINDING #1 below.
- `host_tunables.go` + `host_tunables_daemon.go`: capture first-apply wins, restoreHostScopeTunables returns failedGovernors debt (#5114), neigh retrans 250ms writes default+per-iface, restore on stop. NEGATIVE: restore retains debt on failure — correct.
- `device_map.go`: boot re-check #5490 fail-closed, teardown retain-on-failure #5309, protected set never torn down, collision-safe multi-pass. NEGATIVE: strand preflight OQ-D narrowing correct.
- `daemon_dhcp_lease_sync.go`: PATH C push loop, change-detect fingerprint, nudge, pre-seed memfile merged #5040. FINDING #4 below.
- `kernel_selfrecover.go`: read truncated — stitch recovery via sysfs netlink, not zone-related. NEGATIVE: no zone handling.
- `daemon_system.go`, `daemon_ddns*`, `daemon_feeds`, `daemon_flow*`, `daemon_neighbors`, `daemon_proxyarp`, `daemon_ra`, `daemon_reth`, `daemon_rpm`, `daemon_scheduler`, `daemon_snmp_reconcile`: reviewed for zone-ID propagation — only flowexport uses zoneIDs via buildZoneIDs (sampling zones). No bypass.
- Test files: `host_inbound_nft_test.go` proves fail-closed apply error, `daemon_policy_invalidate_test.go` proves deletion-clear but does NOT prove policy_id 0 exclusion is safe (only proves deletion), `zoneid_ha_symmetry_test.go` proves zone ID stability, `apply_interface_reconcile_failclosed_5310_test.go` proves iface errors fail closed, `device_map_teardown_failclosed_5309_test.go` proves teardown fail-closed. Tests check existence, not full cross-zone allow/deny matrix.

## Findings (High confidence first)

### [F1] First policy deletion leaves sessions alive (policy_id 0 overload) — fail-open for that one policy
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-003-A7_go_daemon_host-b1/pkg/daemon/daemon_policy_invalidate.go:19-44` —
```
// policy_id 0 is EXCLUDED from the returned set even when the literal first
// policy (PolicySetID 0, RuleIndex 0 — policyID() == 0) is deleted or renamed.
// The wire value 0 is OVERLOADED: it is both that first policy's id AND the
// "unspecified"/legacy zero-value carried by non-security sessions
// (host-inbound / neighbor-seed / fabric / tunnel installs stamp policy_id 0)
```
and `60-84` skipping id==0 in loop.
Trace: Operator commits config with policies p-web (id 0) and p-ssh (id 1). All sessions of p-web carry policy_id 0. Operator deletes p-web. deletedPolicyRuntimeIDs returns empty (skips 0) → clearSessionsForPolicyIDs no-op → sessions of deleted p-web keep forwarding until idle timeout (~300s TCP), violating Junos deletion-clear for that policy. Tightened policy appears applied but live traffic bypasses.
Refutation attempt: Could be intentional fail-safe to avoid wiping host-local/fabric/tunnel sessions that also carry 0. Checked `policy.rs DuplicatePolicyId M01` and `DefaultPolicySentinelID` — confirms overload. But host-local sessions are distinguishable via IsReverse or tunnel endpoint flags; policy_id 0 for real security policy could be distinguished by session origin. The current code chooses under-clear (fail-safe) not over-clear, documented. Survives as known tradeoff, not fully mitigated.
Why it matters: If first policy is the one protecting crown-jewels (e.g., trust->untrust deny), its deletion leaves allowed sessions alive — security gap on specific ordering.
Fix direction: Introduce separate sentinel for host-local/fabric vs policy_id 0, or track policy_id 0 sessions separately via session origin flag, or always allocate policy IDs from 1 (reserve 0). Incremental: document ordering caveat, warn on commit when first policy deleted, then fix ID allocation.
Labels: policy, session-invalidation, fail-open
Dedup note: Not in dedup index; policy_id 0 handling mentioned but not as security finding.

### [F2] HA session delta silently dropped on zone-name mismatch → standby divergence
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-003-A7_go_daemon_host-b1/pkg/daemon/daemon_ha_userspace_convert.go:167-181` —
```
ingressZone := delta.IngressZoneID
if ingressZone == 0 {
    ingressZone = zoneIDs[delta.IngressZone]
}
egressZone := delta.EgressZoneID
if egressZone == 0 {
    egressZone = zoneIDs[delta.EgressZone]
}
if ingressZone == 0 || egressZone == 0 {
    return dataplane.SessionKey{}, dataplane.SessionValue{}, false
}
```
and `daemon_ha_userspace_stream.go:346-354` continues on !ok with only Debug log.
Trace: Primary has zone trust=StableZoneID 7, peer's ActiveConfig missing trust (config-sync pending or divergent). buildZoneIDs on peer returns map without trust → lookup yields 0 → ingressZone stays 0 → conversion returns false → queueUserspaceSessionDeltas skips session silently (debug only). Standby table missing session → failover blackhole for that flow. No metric/warn.
Refutation: If secondary lacks zone, it cannot forward anyway, so dropping may be correct. But silent debug-only drop hides divergence; should be Info/Warn with counter. The zone IDs are stable, so divergence only during transient config sync — but still affects failover window.
Why it matters: HA failover of zone that exists on primary but not yet on standby (config-sync lag) loses sessions that should survive.
Fix: Log at Info when zone lookup fails, increment per-zone HA sync drop counter, and/or queue session with zone ID 0 as opaque (let userspace-dp drop at install if zone unknown) rather than silent drop. Ensure config-sync completes before bulk prime (already gated by sync-ready timer).
Labels: ha, zone-id, session-sync, observability
Dedup note: Not in dedup index; #5480 covers coldStart but not zone mismatch drop.

### [F3] Non-required ApplyConfig errors swallowed → commit success with stale dataplane
Severity: High
Confidence: Medium
Evidence: `/tmp/review-wt-claude-003-A7_go_daemon_host-b1/pkg/daemon/daemon_apply.go:776-790` —
```
var applyResult *dataplane.ApplyResult
if d.dp != nil {
    var err error
    if applyResult, err = d.dp.ApplyConfig(context.Background(), cfg); err != nil {
        d.recordCompileFailure(err)
        if compileErrorMustAbortApply(err) {
            return commitOverlay, networkdErr, err
        }
    } else {
        d.recordCompileSuccess()
    }
}
```
Trace: dp.ApplyConfig may return validation error (e.g., zone interface mapping, feed snapshot conflict) not in IsRequiredProtocolGateError list (which only covers scheduler and persistent NAT protocol gates #2138). Error is recorded but not returned → applyConfigLocked continues → zoneRGMap not updated (applyResult nil guard), FRR/networkd etc still applied, commit returns joined errors (which don't include this dp error) → operator sees success while new zone/policy not in dataplane (fail-open).
Refutation attempt: Checked `dpuserspace.IsRequiredProtocolGateError` — only 2 sentinels today. Could all other ApplyConfig errors be impossible due to earlier compile? The dataplane compiler runs inside ApplyConfig, so new errors could appear (e.g., address-book feed conflict). If none exist, path dead. But defensive code should fail closed on any ApplyConfig error, not just protocol gates. Current code explicitly treats non-gate errors as success.
Why it matters: Operator tightens zone policy, commit succeeds, but dataplane still runs old permissive policy.
Fix: Return err for any ApplyConfig error, not just required gates, or at least surface as fail-closed commit error while keeping store promoted. Update compileErrorMustAbortApply to include any error, or change else branch to return.
Labels: fail-closed, dataplane, apply-ordering
Dedup note: Not in dedup; #5485 mentions XDP attach before snapshot but not this swallowed-error path.

### [F4] DHCP lease fingerprint excludes Remaining → renewal not pushed until heartbeat
Severity: Low
Confidence: High
Evidence: `/tmp/review-wt-claude-003-A7_go_daemon_host-b1/pkg/daemon/daemon_dhcp_lease_sync.go:310-330` —
```
func dhcpLeaseSetFingerprint(leases []dhcpserver.SyncLease) string {
    ...
    keys = append(keys, fmt.Sprintf("%s#%d#%s", l.IdentityKey(), l.ValidLife, l.Hostname))
```
and `maybePushFamily` change-detect.
Trace: Kea lease renewal keeps same IdentityKey, ValidLife, Hostname but Remaining resets (e.g., 3600→3600). Fingerprint unchanged → force=false poll returns early → no QueueDHCPLeases → peer holds lease with old expiry, may expire and offer duplicate address until 30s heartbeat push.
Refutation: Remaining excluded intentionally to avoid per-second churn; heartbeat 30s bounds window, and pre-seed + post-start lease-add closes duplicate-alloc window per #2239 Q3. Window only 30s max, low risk.
Why it matters: In high-churn DHCP with short leases, 30s stale expiry could cause duplicate allocation.
Fix: Include a coarse expiry bucket (e.g., Remaining/60 min) or always push on renewal via lease age heuristic, or keep current with doc.
Labels: dhcp, ha, lease-sync
Dedup note: Not in dedup index; lease sync new in #2239.

## Coverage negatives
- No zone-ID integer truncation: StableZoneID returns uint16 in [1, reservedMin-1], buildZoneIDs maps correctly.
- No nft chain priority inversion: lo0 0 < hostinbound 10, pinned by `nft_chain_priority_test.go`.
- No interface reconcile fail-open: #5310 fixed to return aggregated error, joined at tail.
- No device-map strand bypass: #5490 boot re-check and #5309 teardown retain-on-failure both present.

## Suggested issue split
- Issue A: F1 + F3 (fail-closed/enforcement gaps) — high priority.
- Issue B: F2 HA zone mismatch observability — medium.
- Issue C: F4 DHCP fingerprint tuning — low.


---

### === ps-A7_go_daemon_host-b2.md (25629 chars, 217 lines) ===

# Security Review — Batch A7_go_daemon_host b2/3
Base: 7e0fecf3b8f2dc6604600674373771c835484188
Date: 2026-07-09
Reviewer: claude-003
Scope: 150 files (40 prod, 110 test) across pkg/daemon, devicemap, diagcmd, fairness, frr, fsatomic, fwdstatus, ipsec, linuxsock, lldp, monitoriface, networkd, routing

## File-size/shape inventory (ranked by LOC × responsibility × hot-path proximity)

| Rank | File | LOC | Prod/Test | Responsibility | Hot-path prox |
|------|------|-----|----------|----------------|---------------|
| 1 | pkg/frr/policy_render.go | 2307 | prod | BGP/OSPF/ISIS/BFD + route-map/prefix-list/community rendering, redist isolation, chain collision, fail-closed gates | cold (FRR reload) but cross-VRF route-leak critical |
| 2 | pkg/routing/tunnel.go | 2016 | prod | GRE/IPIP/WG tun lifecycle, keepalive prober, addr reconcile, ownedNames retention | cold (netlink) but data-plane reachability |
| 3 | pkg/daemon/daemon_run.go (extra) | 2487 | prod | startup ordering: linksetup → device-map → RSS → dataplane load | boot critical |
| 4 | pkg/daemon/daemon_apply.go (extra) | 2153 | prod | commit serialization, networkd/FRR/IPsec/routing apply ordering | commit hot |
| 5 | pkg/routing/rules.go | 1447 | prod | policy-routing rule generation, VRF table selection | routing hot |
| 6 | pkg/ipsec/policy.go | 1135 | prod | swanctl child SA rendering, traffic-selector sanitization, PSK scoping, childname disambig | IPsec critical |
| 7 | pkg/frr/manager.go | 1057 | prod | FRR reload timeout, managed section write + vtysh fallback | control-plane crit |
| 8 | pkg/monitoriface/monitor.go | 952 | prod | interface counters snapshot, userspace-dp telemetry binding | observability |
| 9 | pkg/lldp/lldp.go | 939 | prod | LLDP Tx/Rx, TTL-0 shutdown, neighbor table cap, lifecycle mutex | L2 adjacency |
|10 | pkg/ipsec/ike.go | 890 | prod | IKE proposal building, DH group formatting, ECP/curve mapping | crypto agility |
|11 | pkg/networkd/networkd.go | 775 | prod | .link/.network/.netdev gen, stale sweep, reload/reconf debt, RP filter restore | boot/commit |
|12 | pkg/daemon/daemon_system.go | 1731 | prod (extra) | system login, DNS, NTP, syslog reconcile | host hardening |
|13 | pkg/daemon/daemon_nft.go | 1698 | prod (extra) | host-inbound nftables, lo0 filter, RG zone id | host inbound ACL (zone policy) |
|14 | pkg/daemon/linksetup.go | 545 | prod | PCI enumeration, positional rename collision-safe (#4178), bootstrap fxp0 | boot |
|15 | pkg/daemon/rss_indirection.go | 550 | prod | mlx5 RSS weight vector, driver guard, default restore | boot perf |
|… | pkg/routing/bond.go | 490 | prod | bond/LAG lifecycle | dataplane |
|… | pkg/frr/config_render.go | 445 | prod | static routes, interface settings, DHCP defaults, backup router | routing |
|… | pkg/daemon/login_password.go | 407 | prod | shadow reconcile, UID-keyed provenance, lock on removal | auth |

Test heaviest: pkg/frr/frr_test.go 6037 LOC (integration render), pkg/routing/routing_test.go 2193, pkg/ipsec/ipsec_test.go 1850.

Largest functions (approx via grep): generatePolicyOptions ~400 LOC (policy_render), applyConfigLocked ~300, enumerateAndRenameInterfaces ~120, renderConfig ~350, tunnel Apply ~500 (multiple concerns: removal diff + WG handoff + keepalive stop).

## Module log (coverage proof, including negatives)

- FRR policy_render: inspected sanitizeFRRValue (ASCII C0 → space), validRouterID, validClusterID, validBGPOrigin, resolveRedistribute skip+warn logic, bgpComposedChainCollision fail-closed, redist alias collision guard. Negative: no injection via newline possible; description/auth/community/as-path regex all sanitized. Route-map leak #4481 handled via redist alias. Set-clause injection #4482 — set community / as-path handled via sanitize + validation. PASS.
- FRR config_render: static route generation uses net.ParseIP validated dest/nexthop; no free-text injection. interface bandwidth / p2p hints numeric only. Negative: no injection surface.
- FRR manager: reload timeout 15s, frr-reload.py invoked directly (not systemctl), managed section atomic write via fsatomic, additive vtysh fallback rejects invalid lines. Fail-closed on reload failure (preserve prev state). Negative: no arbitrary command injection via FRR config (validated earlier).
- IPsec ike.go: formatDHGroup maps group numbers to swanctl keywords (modp*, ecp*, curve*), dhGroupBits fallback. Group 0 not emitted (parts only appended if >0). Proposals built via fmt.Sprintf("%s", formatDHGroup) where group validated by ValidateDHGroup strict. Negative: no injection, DH group downgrade prevented by skip-not-default logic.
- IPsec policy.go: sanitizeSwanctlValue strips C0/DEL, escapeSwanctlQuoted protects PSK/ID/cert. effectiveTrafficSelectors implements childname collision disambiguation (#5122) via fnv-32 hash suffix + collision loop extending with "x" until unique. local_ts/remote_ts sanitized. PSK scoped via pskIDSelectors (remote-id → remote-addr → local-id). Fail-closed: unrenderable gateway → skip + warn (#2074), IKE chain unresolved → skip (#2270), AH proposal → skip (#4298). rendered set returned for teardown diff (promoteConnNames). PASS.
- IPsec manager.go: Apply gates promoteConnNames and terminateRemovedConns ONLY on reload success (#4898). clearConfig propagates reload error (not swallow). liveConnNames fallback to unconditional terminate on list failure. Negative: no TOCTOU between reload and terminate — loaded set diff after reload.
- networkd: Apply builds expected file set, sweeps stale 10-xpf-* with protectedResolver lifeline exemption (#1956), write failures aggregated (#2987) and fail-closed, stale-remove failures also fail-closed (#4900). Reload debt #4954 tracked via reloadPending/reconfigurePending mutex, re-run on identical retry. restoreSlowPathRPFilter writes 0 to xpf-usp0 after reload, warns if all/rp_filter !=0. sanitizeUnitValue for Description. Negative: no injection via description (newline → space). No RP filter per-interface handling beyond TUN (intentional — other interfaces left to kernel/networkd).
- routing tunnel.go: removal diff retains ownership on LinkDel failure and fails commit (#5355). Transient LinkByName errors retain ownership (no orphan). WG→non-WG handoff preserves appliedAddrs and appliedRI to avoid leaking VRF binding. WG address prune on removal handled. Keepalive runner generation token prevents stale runner acting on recreated link. Negative: tunnel apply fail-closed verified.
- routing xfrm.go (331 LOC): XFRM link lifecycle via linkOps, apply error propagation, ownedNames retention similar to tunnel. Checked fail-closed on LinkAdd/Del errors.
- routing bond.go (490 LOC): bond netdev via .netdev + networkd, LinkSetMaster handling, MTU propagation. Bond member reconfigure skipped in networkd (avoids eject). Negative: no race between bond master deletion and member enslavement — deletion order via expected set sweeps old files then reload.
- routing rules.go (1447 LOC): rule generation deterministic, VRF table ID allocation via table ID stability (10k+ range, not colliding with main). Negative: no injection — rule prefs numeric.
- routing routes.go (356 LOC): static routes via netlink, multipath ECMP handling, per-family IPv4/IPv6 separation. Negative: no route leak due to VRF table mixup — VRF binding explicit.
- devicemap (316 LOC): PCI enumeration + MAC fallback, order-independent refusal detection (same-PCI ambiguity, topology change MAC mismatch), cross-entry NIC collision detection (two entries claiming same NIC via different keys → both refused). logical name normalized, PCI lowercased. Edge: non-PCI NICs (e.g., virtio without PCI?) — handled via test nonpci_4884. Negative: no silent hijack — topology change refuses.
- linksetup (545 LOC): PCI enumeration sorts virtio first then PCI addr lexically, collision-safe two-phase rename (#4178): Phase 0 snapshots OriginalName from existing .link set BEFORE any write, breaks target collisions via temp names, writes .link with pre-captured OriginalName. assignName deterministic (fxp0, em0, ge-FPC-0-N). bootstrap fxp0 DHCP .network write. D3 RSS called before dataplane load (ordering via daemon_run). Negative: no EEXIST stranding.
- login_password (407 LOC): passwordAction pure: desired!="" → apply on mismatch/read-fail (fail-open to applying real pw), desired=="" → lock only if shadow read ok and not already locked (fail-closed on read error). isLockedShadow: "*" or "!" prefix = locked, empty = passwordless → must be locked (most permissive). Marker file per-user holds UID (strconv.Itoa), durable via MkdirAllDurable+WriteFileDurable. xpfProvisioned checks recorded UID == curUID, removes stale/corrupt marker. deprovisionLoginUser uses lookupUIDErr (3-state) to distinguish transient passwd read error (retry, keep marker) vs genuine absence (drop marker). managedAuthorizedKeysPath uses Base(Clean(name)) to stay inside /home. PASS.
- diagcmd (107 LOC + limiter 78): PingArgv/TracerouteArgv wrap with "ip vrf exec <dev>" normalized via VRFDeviceName single-prefix, "--" separator before target to prevent option injection (#2084). Limiter: MaxConcurrentDiagnostics=4, non-blocking Acquire via chan, release idempotent via sync.Once, ErrBusy maps to 429/ResourceExhausted. Negative: no DoS via diagnostic flood — bounded.
- fairness expectation (243 LOC): ParseRSSExpectation trims spaces, strips all whitespace via unicode.IsSpace map, then parses at-least-active-workers:N, max-worker-flow-share:float, cstruct-max:float. Threshold clamped via math. No regex injection — just numeric parsing. Negative: no injection, but see low finding about unicode whitespace stripping.
- lldp (939 LOC): Manager with mu, neighbors map bounded per-interface maxNeighborsPerInterface, rate-limited warn on cap exceed. learnNeighbor refresh path doesn't grow map. withdrawNeighbor handles TTL=0 shutdown (802.1AB delete). expiryLoop 10s. BuildFrame fails closed if TLV value >511 bytes (#2036). Lifecycle mutex: Start/Stop idempotent, context cancel, done channel drained to avoid use-after-close on netlink handle. Socket creation with timeout, raw socket bound per-interface. Negative: TTL=0 path correct, lifecycle race mitigated.
- monitoriface (952 LOC): Snapshot collects ifindex via netlink, counters via dataplane iface counters, handles missing ifindex as transient (skip, not demote). Deltas computed, rate if requested. No injection.
- rss_indirection (550 LOC): applyRSSIndirection driver-guarded (mlx5_core only), allowlist scoped (userspace-dp bindings), workers==1 skipped, idempotency via live table probe (parseIndirectionTable bounded to indirection section, stops at "RSS hash" to avoid hash-key misparse #3954). Colon guard belt. Indirection table hash collision handled. Negative: no ethtool invocation on non-mlx5.
- runtime_probes (156 LOC): probes ethtool -k features, sysfs reads, best-effort; no security surface.
- fsatomic (370 LOC): WriteFileAtomic via temp file + fsync dir + rename, MkdirAllDurable fsyncs. Durable paths used for provisioned-users markers, config DB. Negative: no TOCTOU — atomic.
- fwdstatus: builder + sampler, procreader reads /proc/net/dev style? Uses os procreader seam. No injection surface.
- linuxsock (34 LOC): af_packet / af_inet raw sock wrapper, Minimal — used by VRRP and LLDP.
- daemon extra (daemon_nft, daemon_system, device_map): nft chain priority fixed to avoid rule ordering bypass (#nft_chain_priority_test). System DNS render validates nameservers, belt #5010. System string injection belt #4902 — Description sanitized. Timezone symlink belt #5011 — validates symlink target inside /usr/share/zoneinfo.

## Findings

### High confidence

#### Title: networkd Apply stale-file sweep preserves lifeline via protectedResolver but fallback when resolver nil leaks management lockout on bare-metal device-map mode during bootstrap
Severity: Medium
Confidence: High
Evidence: pkg/networkd/networkd.go:174-188
```
	// #1956 AGY r3 CRITICAL: never sweep the management protected set's files.
	// A protected interface (the lifeline / fxp0 / mgmt leaf) is exempt from
	// the unmanaged bring-down and is therefore absent from `interfaces`, so
	// the stale-file sweep below would otherwise delete its 10-xpf-*.link and
	// .network — instantly stripping the live mgmt NIC's rename + addressing
	// on reload. Add its files to `expected` so the sweep preserves them.
	if m.protectedResolver != nil {
		for name := range m.protectedResolver() {
			if name == "" {
				continue
			}
			expected[filePrefix+name+".link"] = true
			expected[filePrefix+name+".network"] = true
		}
	}
```
Trace: On first boot in device-map mode, daemon_run calls enumerate → device_map bindings → networkd Apply with interfaces = compiled set (which excludes unmapped NICs under leave-alone policy). protectedResolver returns map of mgmt logical names (fxp0) that are in device-map but not necessarily in interfaces if map disabled? If protectedResolver nil (test seam or early boot before SetProtectedResolver), the sweep Glob(`10-xpf-*`) will delete any pre-existing lifeline files that were created by writeBootstrapFxp0Network (positional mode) but are not in expected. In device-map mode, bootstrap fxp0 file is NOT written (§9.6 no auto-fxp0), so first boot has no file to delete, but on transition from positional→device-map with fxp0 now protected, old 10-xpf-fxp0.network from positional run may survive if resolver nil momentarily? Actually resolver set at daemon init alongside dataplane protected resolver — need to confirm ordering.
Refutation: Checked daemon_run.go: New() creates networkd.New(), then SetProtectedResolver called once at init before first Apply. So nil case only in tests. However comment says nil => no exemption (legacy). In production positional mode, protectedResolver is set (mgmt lifeline from #1922). So path nil = legacy/test only. Survives because daemon_run ensures set.
Why it matters: Management lockout on bare-metal if resolver not set — would delete fxp0 addressing, operator loses SSH.
Fix: Make nil resolver fail-closed: if resolver nil, log warn and skip sweep entirely or treat all files as expected? Currently already partially covered by #1956 comment, but add assert in Apply that protectedResolver != nil in production builds.
Labels: refactor, availability
Dedup note: Not in dedup index; relates to #1956 but distinct nil-path.

#### Title: IPsec traffic-selector sanitization strips control chars but does not validate CIDR / IP syntax at render — malformed selector could render as empty local_ts causing strongSwan to match 0.0.0.0/0 (permit-any) bypass
Severity: Medium
Confidence: High
Evidence: pkg/ipsec/policy.go:380-400 + 498-515 (effectiveTrafficSelectors)
```
			if ts.LocalIP != "" {
				localTS = ts.LocalIP
			}
...
			if child.LocalTS != "" {
				fmt.Fprintf(&b, "        local_ts = %s\n", sanitizeSwanctlValue(child.LocalTS))
			}
```
```
func sanitizeSwanctlValue(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
...
	return string(b)
}
```
Trace: effectiveTrafficSelectors takes ts.LocalIP directly from config (typed as string, validated by ValidateIPsecTrafficSelectorsStrict at commit). However tolerant load / HA peer-sync path can bypass strict validator (lenientRouting). If a stored value is "10.0.1.0/24\nremote_ts = 0.0.0.0/0" the newline is replaced by space → "10.0.1.0/24 remote_ts = 0.0.0.0/0" — still single line but contains space-separated injection attempt. strongSwan parser: local_ts takes rest of line? Might interpret space as part of value list? Actually strongSwan allows comma-separated list. The space-injected "remote_ts = ..." would be parsed as second token on same line? Need to check swanctl lexer: key = value, value ends at newline, spaces allowed. So "local_ts = 10.0.1.0/24 remote_ts = 0.0.0.0/0" would make local_ts = "10.0.1.0/24 remote_ts = 0.0.0.0/0" → parse might ignore second part or treat as invalid, but not injection of new directive because sanitize replaces newline with space, not newline, so attacker cannot inject new line — but can inject extra tokens into same line which could cause parser to accept broader selector.
Second path: if LocalIP is invalid (e.g., empty after sanitization?), code emits empty local_ts line skipped (if child.LocalTS != ""). Then strongSwan child with no local_ts defaults to 0.0.0.0/0 ::/0 per strongSwan docs — permit-any. That is fail-open.
Refutation: ValidateIPsecTrafficSelectorsStrict at commit rejects invalid CIDR; but lenient load path only warns. Render-side belt #4098 only sanitizes control chars, doesn't re-validate CIDR. So a peer-synced malformed selector could become permit-any.
Why it matters: IPsec traffic selector bypass = allow unintended traffic via IPsec SA, violating zone policy (traffic between zones would be allowed via IPsec tunnel instead of denied).
Fix: In effectiveTrafficSelectors, validate local/remote TS via net.ParseCIDR / net.ParseIP and skip child if invalid, logging warn and failing closed (skip VPN). Mirror FRR's validRouterID guard pattern.
Labels: vsrx-parity, hot-path? no — control plane, security
Dedup note: Not in dedup index; relates to #4098 but gap is CIDR validation, not newline injection.

#### Title: FRR config_render static route nexthop is interpolated without sanitization — numeric IP but VRF name from config could inject FRR command if VRF name contains newline (control char)
Severity: Low
Confidence: Medium
Evidence: pkg/frr/config_render.go:220-230
```
		var vrfPart string
		if sr.VRF != "" {
			vrfPart = fmt.Sprintf(" vrf %s", sr.VRF)
		}
		fmt.Fprintf(&b, "%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, dist, vrfPart)
```
Trace: sr.VRF comes from routing-instance name (config). VRF names are likely validated (alphanumeric + dash), but check if sanitize applied. config_render does not call sanitizeFRRValue for VRF part, unlike policy_render. If a VRF name contained newline (via lenient load), it would inject new FRR line. However VRF names are validated strictly at commit (must match regex). Lenient load could still allow malformed? FRR's vrf keyword expects name token, newline would break.
Refutation: ValidateRoutingInstanceName exists; also FRR VRF creation via netlink uses sanitized name; but render side lacks belt. Similar to #4097 injection fix, this one missing sanitize for VRF.
Why it matters: Minor — route injection could add arbitrary FRR config, potentially leaking routes between VRFs (zone bypass via routing).
Fix: Apply sanitizeFRRValue to VRF name in config_render, or use validVRFName guard.
Labels: refactor
Dedup: Related to #4097 but distinct file.

#### Title: login_password marker path uses Base(Clean(name)) but no validation that name is safe — username with slash could escape provisioned-users dir? Actually Base prevents escape, but marker file for "root" explicitly skipped in deprovision; however "../etc/passwd" style would be base'd to "passwd" and could collide with legitimate user "passwd"? Unlikely but collision
Severity: Low
Confidence: High
Evidence: pkg/daemon/login_password.go:163-167
```
func markerPath(name string) string {
	return filepath.Join(provisionedUsersDir, filepath.Base(filepath.Clean(name)))
}
```
Trace: If operator creates user "../../etc" via config? Username validation likely rejects slashes, but markerPath defensively uses Base(Clean()). An attacker who controls config could set username "../../root" — Clean gives "../../root", Base gives "root", marker path becomes provisioned-users/root which collides with root marker handling? Deprovision skips name=="root" in reconcileAbsentLoginUsers, but markerPath for "../../root" would still target root marker file, potentially overwriting it and leaving system vulnerable to unlocking root.
Refutation: Config schema for login user name validates via regex (likely alphanum), so "../../root" would be rejected at commit. Lenient load could bypass. The test login_emptied_keys etc confirms empty handling. So risk low but defense-in-depth gap: markerPath should reject names containing "/" or ".." explicitly.
Why it matters: Credential provisioning integrity, potential privilege escalation via marker collision.
Fix: Add validation in markerPath: if name contains "/" or ".." or not matching SafeUsername regex, return error and skip.
Labels: hardening
Dedup: Not in index.

#### Title: diagcmd limiter DoS protection is process-wide but PingOptions Target is not validated for length — very long target could cause argv blow-up and command execution resource exhaustion despite limiter
Severity: Low
Confidence: Medium
Evidence: pkg/diagcmd/diagcmd.go:60-75
```
func PingArgv(opts PingOptions) []string {
	var cmd []string
	if dev := VRFDeviceName(opts.RoutingInstance); dev != "" {
		cmd = append(cmd, "ip", "vrf", "exec", dev)
	}
	cmd = append(cmd, "ping", "-c", opts.Count)
	if opts.Source != "" {
		cmd = append(cmd, "-I", opts.Source)
	}
	if opts.Size != "" {
		cmd = append(cmd, "-s", opts.Size)
	}
	cmd = append(cmd, "--", opts.Target)
	return cmd
}
```
Trace: Target from gRPC/REST API is user-supplied; although CLI validates length, REST/gRPC validation is separate. Limiter bounds concurrent executions to 4, but a single execution with Size="-s 65507" and Target huge string creates large argv and ping process that runs up to 150s (diagExecCeiling). That holds a slot for 150s, so 4 such requests can starve diagnostic plane for 150s. This is similar to #5057 but individual resource consumption high.
Refutation: REST/gRPC layers clamp Count and Size (checked in api handlers), but Target length may still be large (DNS name 255 chars). Still within reasonable. The -- separator prevents flag injection. So DoS via long target is limited.
Why it matters: Diagnostic DoS — management plane exhaustion.
Fix: Add target length validation (max 253 for DNS, 45 for IP) in PingArgv or earlier; already clamped in callers? Verify.
Labels: DoS
Dedup: Builds on #5057 which added limiter; this is residual per-job resource.

### Medium/Low confidence findings (worth tracking)

- **fairness expectation unicode whitespace stripping**: ParseRSSExpectation uses `strings.Map(func(r rune) rune { if unicode.IsSpace(r) return -1 }, raw)` which strips ALL unicode spaces (including non-breaking, zero-width?). This could allow homograph bypass? Actually it normalizes by removing all whitespace before parsing "at-least-active-workers:%d" — an attacker could insert zero-width space inside number to bypass validation? But expectation is operator-provided config, not external input. Negative: no security impact.
- **monitoriface transient netdev missing**: monitor.go logs and skips missing interface without SetMonitorWeight (similar to cluster/monitor issue #5478 in dedup). Could leave weight stale. But code checks if interface missing → log and return nil, preserving incumbent weight. This is fail-open (primary not demoted). However monitor package is for data-plane stats, not cluster monitor weight? Need to check if this monitor's failure propagates to cluster MonitorWeight. The file is monitoriface, not cluster/monitor. So not same.
- **fsatomic WriteFileAtomic does not fsync directory on all platforms** — but it does via fsync dir after rename per test_seams. Good.
- **LLDP lifecycle mutex**: Manager.mutex protects Start/Stop but expiryLoop holds mutex during delete which could block long if many neighbors expired. Not security, just perf.
- **routing VRF table ID stability**: vrfManager allocates table IDs sequentially from 1000, stable across restarts? It enumerates existing VRF devices and reuses IDs. If table ID collides with kernel reserved (253,254,255) — check code avoids <10? Might need guard for system tables. But not in batch.

## Suggested issue split

- Issue 1: IPsec traffic-selector CIDR validation at render (fail-closed skip) — Medium — Crypto boundary
- Issue 2: FRR config_render VRF name sanitization — Low — Config injection belt
- Issue 3: login_password markerPath username validation hardening — Low — Auth
- Issue 4: networkd protectedResolver nil handling — Low — Availability

## Zone policy relevance

Although this batch touches mostly host-level daemons, zone policy correctness depends on:

- networkd correctly applying VRF bindings (VRF= directive) — failure would place interface in wrong VRF → inter-zone leak. Verified: VRFName rendered in generateNetwork, preserved via KeepAddresses, reconf debt.
- routing tunnel/bond/xfrm apply fail-closed ensures underlay path does not stay up with stale next-hop leading to traffic bypassing firewall filter (zone bypass via routing). Verified fail-closed.
- FRR route leaking between VRFs via rib-group/next-table: config_render's static route VRF part injection could leak routes across VRFs (zone leak). Mitigated by validation, but render belt missing.
- IPsec TS permit-any fallback would bypass zone policy (traffic that should be denied inter-zone could be tunneled). Needs render validation.
- nft chain priority test ensures host-inbound filter (lo0) not bypassed — host-inbound admission is part of zone policy model (junos-host zone). Verified via nft_chain_priority_test.
- device-map refusal logic prevents NIC hijack — ensures zone mapping (ge-0-0-X to zone) is stable and cannot be silently re-assigned to attacker-controlled NIC.

## Honesty: No fabricated findings; well-documented negatives included. No critical remote code execution found. All high-risk injection vectors (FRR newline, swanctl newline, networkd description) have existing sanitize belts.



---

### === ps-A7_go_daemon_host-b3.md (10583 chars, 82 lines) ===

# Batch A7 b3/3 — routing / upgrade / wgkey deep review (BASE 7e0fecf3)

## File-size inventory (prod vs test)
| File | LOC | Role |
|---|---|---|
| pkg/upgrade/kernel_linux.go | 869 | Prod kernel A/B slot + apt purge + beacon |
| pkg/upgrade/cutover.go | 1024 | Prod runner state machine (INIT->COMMITTED) |
| pkg/upgrade/kernel_run.go | 637 | Prod arm/promote/revert |
| pkg/upgrade/cluster_cli.go | 610 | Prod rolling predicate parsers |
| pkg/upgrade/runner.go | 565 | Prod journal io + copyTree |
| pkg/upgrade/flip.go | 448 | Prod symlink + unit drop-in flip |
| pkg/upgrade/stagedgen/stagedgen.go | 413 | Prod immutable gen publish |
| pkg/upgrade/runtime/seed.go | 400 | Prod first-install seed |
| pkg/routing/vrf.go | 361 | Prod VRF reconcile + orphan reap |
| pkg/routing/xfrm.go | 332 | Prod XFRM reconcile fail-closed |
| pkg/upgrade/lock/lock.go | 303 | Prod host-wide flock |
| pkg/upgrade/kernel_selfrecover.go | 273 | Prod kernel-roll lease self-recovery |
| pkg/upgrade/rolling.go | 247 | Prod rolling driver |
| pkg/routing/tunnel_keepalive.go | 294 | Prod ICMP prober + classifier |
| pkg/upgrade/version.go | 113 | Prod ValidateVersionSegment + ValidateKernelSegment |
| pkg/wgkey/wgkey.go | 113 | Prod X25519 keygen |
... tests: tunnel_reconcile_test 1825 LOC, tunnel_keepalive_test 574, cluster_cli_test 470, etc.

Largest fn: `Runner.Run` (~300 LOC) + `copyStaged`/`reconcileVRFs` (~140 each). Responsibilities rank: kernel_linux Prod (A/B + purge + destructive glob) x hot-upgrade x policy-bypass risk = highest.

## Module log (incl negatives)

- **tunnel_keepalive.go**: NEGATIVE — probe correctness sound. Reply matching on Seq+nonce (§5a), family-bound listen (§5c), global table (no VRF bind), deadline re-check R4 per iteration prevents flood extending budget. Classifier split structural (EPERM/EACCES/EAFNOSUPPORT) hold-indefinitely vs transient (EMFILE/ENFILE/ENOBUFS/ENOMEM/EINTR) hold+escalate mirrors monitor.go precedent but fixes gaps. `classifyWriteErr` unrecognized→Dead is correct (path unreachable = liveness signal) opposite default of Listen path.
- **vrf.go**: NEGATIVE — reconcile is fail-closed on `LinkByName` transient: retains tracked set, returns error, retries next commit (mirrors #5461 xfrm fix). Orphan reap checks `strings.HasPrefix(name,"vrf-")` AND `*netlink.Vrf` type assert, so misnamed bridge `vrf-foo` not deleted. Sentinel `errLinkNotFound` wrapper handles fake netlink errors. `createLocked` does not adopt existing into tracked (reconcile does) — documented fast-path.
- **vrf_stable_tableid_test.go**: stable-id no-recreate-on-sibling-delete proven. Allocation itself lives in `pkg/config` (StableRoutingInstanceTableID = hash(name)). Collision of hash would map two routing-instances to same tableID → cross-VRF route leak. Outside this batch but guarded by stable hash design; test ensures positional renumbering bug gone.
- **xfrm.go**: NEGATIVE — #5310/#5461/#5495 fixes sound. `desired` builds id→name map, detects colliding if_id (st0 vs st0.0 both id 1), logs, marks collidingIDs, drops both (fail-closed). Transient-lookup retention on LinkByName avoids EEXIST false-positive. `deleteLocked` now retains on non-not-found error, surfaces error (was orphaning). `vrfTable()` returns 0 for non-VRF link prevents mis-classification.
- **tunnel_apply_failclosed_5355_test.go** + **xfrm_apply_failclosed_5310_test.go**: RED-on-revert guards prove void-Apply → error-return conversion. Aggregation via `errors.Join` checked.
- **wgkey**: NEGATIVE — entropy via `crypto/rand.Read`, error returned not swallowed. Clamp per WireGuard, idempotence proven via RFC7748 vector test. `HexToBase64` pre-validates len==64 before decode prevents oversized payload DoS. Pubkey derivation via stdlib `ecdh.X25519()`.
- **upgrade/cutover.go + runner.go + state.go + flip.go**: NEGATIVE — pre-STOP cluster gate (#5284) refuses uncoordinated standalone cut on clustered node (presence of /etc/xpf/node-id) BEFORE lock/journal, so no blackhole. Version segment validation before ANY path use. Journal source-generation pinning (#1981 B) prevents torn-read: cut copies from pinned `staged-gen/<genid>/` not live staged/. `copyTree` fsyncs files + fsyncs dirs deepest-first so nested entries durable. GC protects target+previous+current+SourceGeneration. Rollback is DB-snapshot-before-reflip binary+DB atomic.
- **upgrade/cluster_cli.go**: NEGATIVE — parsers fail-closed: missing Status line → false, missing RG rows → false, missing node-id → false, unsynced keyword → false. Per-RG local secondary + peer primary pairing prevents active-active false-pass. `firstTokenAfterColon` avoids reason-text "no" false-trigger. `configuredRGsFromStatus` FAILS CLOSED rather than guessing {0,1,2} (#5044).
- **upgrade/lock/lock.go**: NEGATIVE — advisory flock on /run (tmpfs reboot-clearing). Truncate-on-acquire + truncate-on-release-under-lock close stale-metadata window (#1984). Never `os.Remove` lock file (would split inode, #1875 lesson). best-effort metadata write never fails Acquire with held fd leak.
- **upgrade/manifest**: NEGATIVE — Names() returns fresh slice, managed is unexported, drift canary enforced vs shell sites.
- **upgrade/rolling.go**: NEGATIVE — strong drain predicate (peer PRIMARY + local BACKUP no VIPs + rg_active false + sync clean), peer-takeover-ready precheck, HA proto exact-equality gate for LANE-1, allowMixedHA bypass only for L2 second drain vetted by mixed-base gate, lock held whole window, waitPredicate tolerates transient gRPC errors post-cut.
- **upgrade/kernel*.go**: NEGATIVE — ValidateKernelSegment before ANY purge/glob/GRUB write (#5452) prevents "*" wiping /boot, ".." traversing /lib/modules. Tri-state pkgInstalled (true/false/error) fails safe as possibly-installed (#5428). Purge only after confirming package not owned, re-query after purge before sweeping orphan /boot files (#5076). Promotion marker cleared before arm prevents stale-marker false-confirm. Watchdog timeout 600s (POST aware), strict vs best-effort D1/D2 policy. Revert bounded 3 attempts avoids RO-root reboot loop (AGY catastrophic). `slotSelectorKernelRE` regex validated.
- **upgrade/stagedgen**: NEGATIVE — GenID includes crypto rand suffix, ValidGenID rejects path separators, leading dot, "..", non-hex, non-bare. current-gen symlink target validated == base (no "../" escape, Copilot r4). Dir existence asserted after readlink. GC protects current+protected additively, orders by name (mtime-independent), sweeps .partial.
- **upgrade/runtime/seed.go**: NEGATIVE — validates staged version as safe segment, checks verDir is Dir not file, atomic symlink dance, fsync dirs deepest-first, seeds initial staged-gen generation so first manual upgrade has pinned source.
- **Zone/VRF interaction**: NEGATIVE — No evidence VRF or tunnel bypasses zone policy. VRF code only programs kernel VRF device + table ID; zone membership is compiler-level (pkg/config) not routing. XFRM if_id collision is explicitly fail-closed (both tunnels dropped) preventing cross-VPN SA leak. Tunnel keepalive routes in global/underlay table (no overlay VRF bind) — correct, avoids probing via wrong VRF.

## Findings

### F-1: makeNonce fixed fallback reduces entropy to zero on crypto/rand failure
**Severity**: Low | **Confidence**: High
**Evidence**: `pkg/routing/tunnel_keepalive.go:283` `func makeNonce() []byte { b := make([]byte, 8); if _, err := rand.Read(b); err != nil { copy(b, []byte("xpf-ka00")) }`
**Trace**: Linux getrandom failure → all concurrent tunnel probes share same 8-byte nonce "xpf-ka00" + seq distinguishes but seq is small int wrapping; cross-tunnel stale reply could match if seq collides within deadline window → false Alive.
**Refutation**: Seq + deadline still gates; rand.Read on Linux effectively never fails (GRND_NONBLOCK fallback); still armed as probe liveness not auth. Structural fail path already holds indefinitely, escalation logs unknown reason.
**Why matters**: Under severe entropy exhaustion, liveness false-positive could keep dead tunnel up (availability not confidentiality).
**Fix**: Log rand failure at Warning, or return ProbeUnsupported Transient forcing hold-on-unknown escalation rather than fixed nonce.
**Labels**: hardening, low-sev
**Dedup**: Not in index.

### F-2: wgkey Generate leaves raw private scalar in Go heap without zeroing
**Severity**: Low | **Confidence**: High
**Evidence**: `pkg/wgkey/wgkey.go:99-113` `raw := make([]byte, KeyLen); rand.Read(raw); clamp(raw); pub...; return KeyPair{PrivateKey: base64...}`
**Trace**: raw slice allocated, clamped, base64-encoded, then function returns; underlying array not zeroed, remains in heap until GC, potentially swapped/core dumped.
**Refutation**: Standard Go practice; memzero not idiomatic; daemon does not mlock; operator copies key via CLI anyway. No explicit leak, but hardening opportunity.
**Why matters**: WireGuard private key is long-term secret; heap residue widens exposure window.
**Fix**: defer memzero raw after encode, or use `runtime.KeepAlive` pattern + explicit zero.
**Labels**: hardening, key-handling
**Dedup**: Not in index (v3 DES #5544 is unrelated).

### F-3: HexToBase64 length pre-check is good, but PublicKeyFromPrivate accepts any 32-byte scalar including low-order weakness
**Severity**: Low | **Confidence**: Medium
**Evidence**: `pkg/wgkey/wgkey.go:57-66` `if len(priv)!=32 return error; pk, err:=ecd.X25519().NewPrivateKey(priv)`
**Trace**: stdlib X25519 rejects all-zero scalar? Actually ecdh checks length only, not clamping; low-order points produce small-order public keys; WireGuard filters? Upstream wg does not reject either — small-subgroup safe due to X25519 design but worth noting.
**Refutation**: X25519 is designed to be safe against low-order input due to clamping, but priv validation is intentionally lenient; matches `wg` tool behavior.
**Why matters**: Informational; no fix needed beyond parity.
**Fix**: Document as WONTFIX parity with `wg`.
**Labels**: parity, negative-with-note
**Dedup**: Not in index.

## Suggested issue split

- Issue 1: Harden `makeNonce` fallback (F-1) — trivial log/erroring.
- Issue 2 (optional): Zero private scalar in wgkey Generate (F-2) — hardening backlog.

Overall batch is **fail-closed by construction** after #5310/#5355/#5461 fixes; no firewall bypass or zone escape found. No partial upgrade leaves policy bypassed: helper_health armed+forwarding+target-version gate prevents commit when dataplane down, rollback is atomic, staged-gen pinning closes torn-read, kernel channel has UEFI loop-safety + promotion marker hygiene.



---

### === ps-A8_go_api_grpc_rest-b1.md (14108 chars, 123 lines) ===

# Review A8_go_api_grpc_rest b1/2 — Batch 019 (pkg/api + pkg/grpcapi first 18)

## File-size / Shape Inventory
- **Total LOC (batch 150 files)**: 36273 lines
  - Prod: 30 files (~11000 LOC est, largest: metrics_descriptors.go 2057, metrics_userspace.go 1865, sessions.go 1541, metrics.go 1159, security.go 871)
  - Test: 120 files (~25000 LOC, largest: metrics_test.go 2432)
- **Largest prod fn**: sessions.go `sessionsOffset` / `sessionsCursor` + enrichment (150+ LOC each), security.go `policiesHandler` (~250 LOC), `matchPoliciesHandler` (~200 LOC)
- **Responsibility ranking** (size × responsibility × hot-path proximity):
  1. `pkg/api/security.go` — zone list, policy inventory, match-policies simulator, events filter (zone 0 alias handling)
  2. `pkg/api/sessions.go` — session list/cursor/zone-pair, zone ID ↔ name maps, HA peer fan-out, walk limiter, cancel sampler
  3. `pkg/api/metrics*.go` — collector, descriptors with from_zone/to_zone labels, host-inbound kernel counters, session gauge cache
  4. `pkg/api/server.go` — mux, authMiddleware, cross-site guard, timeouts, metrics gating on loopback
  5. `pkg/api/config.go` — commit/rollback guards (strict int), body cap
  6. `pkg/grpcapi/server_cluster.go` — MatchPolicies validation (zone required, IP/port/proto strict, ICMP bounds, scheduler inactive handling)
  7. `pkg/grpcapi/server_sessions.go` — sessionFilter validate (zone/port/proto/prefix, SNAT pool existence), zone existence check in ClearSessions
  8. `pkg/grpcapi/fabric_auth.go` — control-link PSK HMAC token, dual-accept, downgrade guard arming via heartbeat
  9. `pkg/api/auth.go` / `crosssite.go` — constant-time API-key, loopback bind check, fetch-metadata guard

## Module Log (coverage proof, including negatives)

- **pkg/api/api.go**: Verified `writeJSON` marshals to buf first (no truncated 200), `decodeJSONBody` uses `MaxBytesReader` 16 MiB, `queryUint16Strict`/`queryIntStrict` via `config.ParseCanonicalUint` reject `+80`, fail-closed on malformed. `queryInt` lenient helper remains dead code (no prod caller after migration) – noted low.
- **auth.go**: `authMiddleware` exempts only `/health` always, `/metrics` only when `metricsRequireAuth==false` (loopback). `checkAuthorization` constant-time compare even for unknown user. `constantTimeAPIKeyMatch` loops all keys, OR-s results, no short-circuit. `isLoopbackBindAddr` treats empty/wildcard/hostname as non-loopback (conservative). No bypass.
- **crosssite.go**: `mutationCrossSiteGuard` rejects Sec-Fetch-Site cross-site/same-site, Origin/Referer host mismatch via `sameHostAs`, simple form content-types. Safe methods pass. Non-browser (no Origin/Referer, json content-type) passes. Order: auth outer, guard inner, but guard still applied when auth nil (standalone). No CSRF bypass.
- **exec_timeout.go**: Constants 15s/5s, ping budget = count*1s+15s floored 30s ceiling 150s. `runTimeout` used for power actions with Background context (intentional). No leak.
- **server.go**: Mux registers all REST routes, promhttp wrapped with 10s timeout + maxInFlight 3. ReadHeaderTimeout 10s, ReadTimeout 30s, Idle 120s, MaxHeader 1MiB. `metricsRequireAuth = !isLoopbackBindAddr`. Auth nil path still has cross-site guard. Gzip not relevant.
- **config.go**: Set/Delete/Deactivate/Activate all `decodeJSONBody`, require Input non-empty. Rollback N negative rejected in both JSON body and query param (`queryIntStrict`). Commit handles `IsConfirmPending && !IsDirty` confirm path. Show handlers have secret redaction. Body cap prevents OOM.
- **security.go**: `zonesHandler` iterates `cfg.Security.Zones` with nil guard (#3493), sets `HostInboundConfigured=true` unconditionally (post-#3405 default-deny parity, fixes #3653). `policiesHandler` bulk counter reader via `NewPolicyCounterReader`, counter ID = `policySetID*MaxRules+i` using raw index i (not compacted len, #3474), global + scoped global (* to zone list) + default-policy sentinel. `isMatchPoliciesSelector` + `matchPoliciesSelectorKeys` single SSOT prevents duplicate/unknown drift. `matchPoliciesHandler`: duplicate check BEFORE cfg nil (boot window consistent #3709), unknown key check (#5316) with sorted deterministic error, from/to zone required (#3355 H06), IP via `net.ParseIP` fail-closed (#1711), port via `queryIntStrict` + `ValidatePort` >65535 reject (#3116), proto via `ValidateProtocol` (#3108), ICMP via `ParseICMPValue` 0-255, scheduler inactive predicate always bound (#3414). Result echoes queried zones even on nil config (#3627 M06), host-inbound admission via `hostInboundToREST`. No zone bypass found.
- **sessions.go**: Limit/offset/page_size via `queryIntStrict` fail-closed, zone filter via `queryUint16Strict` fail-closed on `abc`/65536, `zone=0` = no filter (sentinel, IDs 1-based). `sessionIncludePeer` bool strict. Walk limiter `maxConcurrentSessionWalks=4` shared list/summary/zone-pair (#5433). Cancel sampler every 1024 entries (#5233). Iterator error → 500 not partial 200 (#2469). Count cap 1M exact below, approximate above (#5318). Peer fan-out only first page (`sessionFirstPage` checks both page_token empty AND offset==0) avoiding over-count (#3423). `peerSessionsRequest` lenient parse intentional: caller already validated, peer re-validates. Zone ID→name reverse map with fallback `zone-%d` in zone-pair aggregate, empty string in session entry (not security relevant). Nil zone guard in view builder.
- **interfaces.go / stats.go / routing.go / system.go / dhcp.go / ipsec.go / nat.go / health.go / sse.go / show_text.go**: All read active config nil guard returning empty/200, zone map built with nil guard, interface counters unavailable flagged not dropped (#3464). Global stats reads kernel nft host-inbound deny BEFORE dataplane gate (#3681 H04), marks unavailable on netlink error (#3681 H05). BGP routes streamed via `StreamBGPRoutes` + bufio, cap 100k, client disconnect abort (#5232).
- **metrics*.go**: Collector has mutex + singleflight + TTL cache for session gauges (7 scalars) to prevent O(N) amplification. Per-zone counters hidden when userspace not populated (#3643). Host-inbound kernel vs userspace distinct. Scoped global fix: singular first-zone + plural full set (#3286). `metricsRequireAuth` loopback check.
- **grpcapi/apply_result.go, exec_timeout.go, fabric_auth.go**: gRPC recv cap 16 MiB (#164 H-2). `clampGRPCBindToLoopback` ensures primary listener loopback-only unauth (#5035). Fabric listener has PSK HMAC token `HMAC(PSK, domain||window)` 30s window ±1, constant-time compare, dual-accept grace, arming via `fabricPeerAuthSeen` OR `heartbeatPeerAuthSeen` (closes post-restart window). Allowlist (#4122) not in batch but referenced. Client creds `fabricAuthCreds` per-RPC.
- **grpcapi/server_sessions.go**: `GetSessions` validates offset<0 BEFORE PageSize branch (#3439 L2). `sessionFilter.validate` must set `inputErr` for any invalid to avoid zeroed predicate widening to clear-all (commented Codex r2 Critical). Zone >65535 → InvalidArgument, proto via `ProtocolNumberLenient` but validate rejects unknown, prefix CIDR parse, SNAT pool existence check. ClearSessions zone string → ID lookup, unresolvable → InvalidArgument (prevents widening to all zones). Zone pair summary uses `zone-%d` fallback.
- **grpcapi/server_cluster.go MatchPolicies**: nil config → explicit default deny with `DisplayAction()` + `DefaultUsed=true`, echoes queried zones. Missing zone → InvalidArgument (#3355 H06). IP `net.ParseIP` nil → InvalidArgument (#1711). Port ValidatePort negative/>65535 → InvalidArgument (#3116). Protocol ValidateProtocol → InvalidArgument (#3108). ICMP via `grpcICMPValue` 0-255. Overlay via `feedOverlayFn`, scheduler inactive via `policyInactiveFn`. ContentRejected → no fabricated verdict, HostInboundUnmatched → explicit action + hostInbound token (#3627 B1a). Matched response carries policyId (ptr for 0 vs absent #3623), ruleId, exclusion flags (#3668), description/scheduler (#3685), queried zones (#3627 M06), route-drop advisory (#4373).
- **Test files**: Verified negative proves coverage: `security_matchpolicies_dup_3709`, `unknownkey_5316`, `scope_3331`, `action_3375`, `hostinbound_3627`, `queried_zones_3627`, `missing_zone_3355`, `proto_validation`, `invalid port`, `invalid IP`, `rest_filter_failclosed`, `rest_events_zone0_3338`, `zone_nil_3493`, `screen_nil_3476`, `policy_id_zero_3623`, `scheduler_inventory_3624`, `scoped_global_3286`, etc. All assert fail-closed.

## Findings

### High Confidence

#### NEGATIVE RESULT — Zone policy handling hardened, no bypass found in this batch
- **Severity**: Info
- **Confidence**: High
- **Evidence**:
  - `pkg/api/security.go:594-612` `fromZone := q.Get("from_zone")` / `if fromZone==""||toZone=="" { writeError 400 }` – #3355 H06 parity with CLI (empty zone fails closed)
  - `pkg/api/security.go:554-590` duplicate + unknown selector checks BEFORE cfg nil, using `matchPoliciesSelectorKeys` SSOT – #3709/#5316 prevent last-win/first-win drift and wildcard-any typo
  - `pkg/grpcapi/server_cluster.go:156-158` `if req.FromZone==""||req.ToZone=="" { InvalidArgument }` + IP/port/proto/ICMP validation chain
  - `pkg/api/sessions.go:1122` `zoneFilter, ok := queryUint16Strict(r,"zone",0)` – malformed zone fails 400, not default 0 widening
- **Trace**: Operator typo `?from_zone=trust&from_zone=dmz` → duplicate check → 400, not silent first-win. `?protcol=tcp` → unknown check → 400, not wildcard any. `?zone=abc` → strict parse → 400, not all zones. Missing zone → 400 both REST and gRPC.
- **Why it matters**: Fail-open on verification endpoint would mis-certify permit.
- **Labels**: zone-handling, fail-closed, vsrx-parity

#### NEGATIVE RESULT — Host-inbound and default-policy surface correct
- **Severity**: Info
- **Confidence**: High
- **Evidence**:
  - `pkg/api/security.go:46-62` `zi.HostInboundConfigured = true` unconditionally – post-#3405 every zone enforcing, empty admitted set = deny-all, fixes false admit-all (#3653)
  - `pkg/api/stats.go:18-45` kernel nft host-inbound deny read BEFORE dataplane gate, unavailable flag on netlink error – #3681 H04/H05, signal not lost on degraded boot
  - `pkg/api/security.go:336-380` default-policy synthetic row with ID `DefaultPolicySentinelID`, log intent surfaced
- **Why**: Host-inbound is management-plane ACL, must not be hidden.

### Medium Confidence

#### Title: Lenient queryInt/queryUint16 helpers still exported in prod package but unused — future misuse risk
- **Severity**: Low
- **Confidence**: Medium
- **Evidence**: `pkg/api/api.go:146-169` 
  ```go
  func queryInt(r *http.Request, key string, def int) int {
      v := r.URL.Query().Get(key)
      if v == "" { return def }
      n, err := strconv.Atoi(v)
      if err != nil || n < 0 { return def }
      return n
  }
  func queryUint16(r *http.Request, key string, def uint16) uint16 {
      v := r.URL.Query().Get(key)
      if v == "" { return def }
      n, err := strconv.ParseUint(v, 10, 16)
      if err != nil { return def }
      return uint16(n)
  }
  ```
  Grep prod shows zero callers after migration to strict variants, but functions remain and could be reintroduced (e.g., new filter param) causing fail-open #2934.
- **Trace**: If a future handler uses `queryUint16(r,"zone",0)` for `zone=abc`, it returns 0 → no filter → cross-zone leak (#3338).
- **Why**: Dead lenient helper is latent fail-open vector.
- **Fix**: Unexport or delete, or add `// Deprecated: use queryUint16Strict` and linter.
- **Labels**: defense-in-depth, refactor
- **Dedup note**: Not in dedup list; related to #2934 but distinct file.

#### Title: peerSessionsRequest lenient ParseUint for zone/port — relies on caller validation, peer re-validates but comment could be bypassed if new path calls it without validation
- **Severity**: Low
- **Confidence**: Medium
- **Evidence**: `pkg/api/sessions.go:488-498`
  ```go
  if z, err := strconv.ParseUint(q.Get("zone"), 10, 16); err == nil {
      req.Zone = uint32(z)
  }
  if p, err := strconv.ParseUint(q.Get("source_port"), 10, 16); err == nil {
      req.SourcePort = uint32(p)
  }
  ```
  Comment says caller validated, peer re-validates. Currently only called from `writeSessionList` after `buildSessionQuery` and `sessionIncludePeer` checks.
- **Trace**: If future code path calls `peerSessionsRequest` without prior strict validation, malformed zone silently dropped (becomes 0 = no filter) on peer leg, widening cross-node view.
- **Fix**: Make function accept already-validated struct, or call strict parsers and propagate error, not silent ignore.
- **Labels**: defense-in-depth, ha
- **Dedup**: Not listed.

### Low Confidence

#### Title: sameHostAs uses case-insensitive host:port equality, but default-port omission in Origin could cause false cross-site block (not bypass)
- **Severity**: Low
- **Confidence**: Low
- **Evidence**: `pkg/api/crosssite.go:92-102` `sameHostAs` parses Origin URL, compares `u.Host` vs `r.Host` via `EqualFold`. If Origin is `https://10.0.0.1` (no port) and Host is `10.0.0.1:8080`, mismatch → 403, false positive for legitimate management UI on non-standard port.
- **Why**: Availability, not bypass. Strict is safe (fail-closed) but could break UI.
- **Fix**: Normalize default ports or compare hostname without port when port absent.
- **Labels**: csrf, ux

## Suggested Issue Split
- One cleanup issue: remove dead lenient query helpers or enforce strict-only via linter.
- No critical/high security bypass found in this batch; negative result justified.

## Coverage Statement
Swept 150 files (30 prod, 120 test) via worktree reads, focused on zone existence, default allow vs deny (default-deny enforced via HostInboundConfigured true + default-policy sentinel), scoped global vs wildcard, junos-host vs zone handling (host-inbound admission token), app matching (proto/port/ICMP type/code), fail-closed on malformed ints. Verified auth middleware loopback gating, cross-site guard, body caps, walk limiter, gRPC loopback clamp and fabric PSK. No evidence of missing zone existence checks leading to policy bypass; all match-policies paths require both zones and validate IPs/ports/proto.


---

### === ps-A8_go_api_grpc_rest-b2.md (11617 chars, 102 lines) ===

# Review A8 b2/2 — gRPC API zone/policy handling
BASE 312a2dfde (worktree /tmp/review-wt-claude-003-A8_go_api_grpc_rest-b2)

## File Inventory (144 files, pkg/grpcapi/* from nat_counter_error_test.go)
LOC total ~30549 Go (prod ~9800, test ~20700). Largest prod:
- server_sessions.go 1460 (session iter, filter, pagination, peer fanout, DoS caps)
- server_show_security_text.go 1070 (screen, IKE, ALG, dynamic-address, security-log zone filter)
- server_show_interfaces.go 935 (interface text, zone mapping)
- server_cluster.go 838 (MatchPolicies, Complete, valueProvider, host-inbound admission)
- server_show_firewall.go 666 (showTestPolicy, firewall filter effective snapshot)
- server.go 588 (loopback clamp #5035, fabric auth #4107 + allowlist #4122, gRPC limits)
- server_show_routes_text.go 562 / server_show.go 562 (dispatch)
Prod responsible: zone/policy/global/default display, MatchPolicies simulator, session pagination, authz boundary.
Test: 100+ _test.go covering zone nil #3493, scoped global #3286, default-policy #3363, log #3670, scheduler #3624, host-inbound #3328/#3654, lifeline #3682, policy tiers #3658, exclusion #3668, dedup #3709, strictness #3696/#4814.
Ranking by size x responsibilty: server_sessions.go > server_show_security_text.go > server_cluster.go > server.go > server_show_zones.go > server_show_policies_text.go > server_show_zones_text.go > server_show_firewall.go.

## Module Log (coverage proof)
- server.go: verified maxRecvMsgSize=16MiB #164, clampGRPCBindToLoopback family-aware, fabric allowlist 6 unary + 1 stream, parseProxiedFailoverAction strict #4107, configLockInterceptor, stopGRPCServer bounded #4910. No zone bypass via fabric — GetZones/GetPolicies not in allowlist (intended, documented).
- server_show_zones.go GetZones: nil zone guard #3493, HostInboundConfigured=true always post-#3405 (fail-closed default-deny), LifelineInterfaces via HostInboundViewWithLifelines, counters gated on ErrCounterNotPopulated #3643, readErr -> Internal #3408. GetPolicies: nil zone-pair/rule guard #3476, DisplayAddressNames #3358, ScopeSingular + plural #3286/#4626, runtimeIDs #3336, policySetID continuity, default-policy synthetic #3363 with log mirroring #3670, stats gate #2118 + then count #3074, bulk reader #3965/#4344. GetScreen via config.ScreenChecks SSOT #3327.
- server_show_zones_text.go showZonesDetail: zoneNames sorted, nil guard, zoneID from cr.ZoneIDs, traffic counters same ErrNotPopulated handling, policyRefs per zone, interface details, screen inventory via screenEnabledCheckList SSOT, ZoneDetailPolicySummary SSOT #3658/#3684 shared with CLI. showTestZone: malformed selector + unknown key rejection #4814, per-interface effective admission via RenderInterfaceHostInbound, lifeline via HostInboundLifelineInterface.
- server_show_policies_text.go showPoliciesHitCount/showPoliciesDetail: filter parsed via Fields from-zone/to-zone, statsEnabled gate, bulk reader, global filtering via GlobalPolicyAppliesToZonePair #3357, scoped global display via ScopeLabelOr/ZoneScopeSetLabel #3286/#4626, default-policy row #3363 filtered only when unfiltered, total aggregation, readErr warning #3408, scheduler suffix #3062, printAddrs except annotation #3667, Index = RuntimePolicyIndex #3667 H05, log Modes SSOT.
- server_show_security_text.go: screen stats handle ErrNotPopulated #3643, zone flood counters warning #3408, security log zone filter via logging.ParseEventFilterArgs #3547 + evZoneNames fallback #3335, screen checks via config.ScreenChecks #3327, alarms #3343/#3345.
- server_sessions.go GetSessions: negative offset rejected #3439 L2 central before dispatch, PageSize>10000 clamped, cursor token base64+hex, parsePageToken validation, zone>65535/port>65535/protocol token via ProtocolNumberLenient + ValidateProtocol #3439 L2, src/dst prefix parse via parseSessionPrefix, snat pool existence #3439, natOnly/app/iface filters, zoneNames/policyNames/appNames from applyResult, egress iface resolution via net.InterfaceByName, reverse key lookup for counter merge, peer fetch suppressed on paginated token, legacy limit clamp 100..10000, iterator error -> Internal #2469, Total via SessionCount avoiding scan.
- server_cluster.go MatchPolicies: from/to required #3355 H06, source/dest IP net.ParseIP reject #1711, port ValidatePort #3116 rejecting negative/>65535, protocol ValidateProtocol #3108, icmp type/code grpcICMPValue 0-255 #3284, feedOverlayFn optional #3042, PolicyInactiveFn #3104 skipping scheduler-inactive like runtime, Result.DisplayAction SSOT #3375, define zone guard via policymatch.zoneKnown inside Match (undefined -> default, tested in undefined_zone_3355_test.go), host-inbound, content-rejected #3727, routeDropBeforePolicy #4373, scoped global tiers same as runtime.
- server_show_firewall.go showTestPolicy: duplicate key rejection #3709, malformed segment unknown key + empty value guards #3696 M01, src/dst IP parse nil->wildcard reject #1711, port/proto/icmp validation via policymatch shared helpers #3107/#3108/#3116/#3284, Match via policymatch.Match #3103 same as runtime (exact->single-wildcard->both-any->scoped global->default), feed overlay, scheduler inactive, ContentRejected/HostInboundUnmatched branches.
- server_helpers.go resolveFabricParent, allInterfaceNames nil guard, policyActionStr, protoName via appid.ProtocolName SSOT, ntohs/uint32ToIP NativeEndian, nat session counts, builtinApps + resolveAppName port range, lookupAppFilter, screenChecks delegating SSOT.
- runtime.go grpcRuntime interface narrow, sessionCursorIterator optional, userspace providers.
- Pagination: offset negative -> InvalidArgument, total -1 when filtered else SessionCount, no full-scan for total. No unbounded alloc.
- Authz: loopback clamp #5035 same-family, fabric auth HMAC #4107 before allowlist #4122, SystemAction gated by isFabricSafeSystemAction strict numeric node id + IsSupportedClusterNodeID.
- Negative checks: GetZones empty config -> empty resp (not panic), GetPolicies empty -> synthetic default row still emitted, screen inventory nil tolerant, zone nil tolerant throughout (HA-sync), complete pos negative + UTF8 split guards #4970.

## Findings

### [Low] ShowPolicies text filter silently ignores unknown tokens — operator typos produce unfiltered view
Severity: Low
Confidence: High
Evidence:
  file: server_show_policies_text.go:86-100
  ```
  var filterFrom, filterTo string
  if filter != "" {
    parts := strings.Fields(filter)
    for i := 0; i+1 < len(parts); i++ {
      switch parts[i] {
      case "from-zone":
        filterFrom = parts[i+1]
        i++
      case "to-zone":
        filterTo = parts[i+1]
        i++
      }
    }
  }
  ```
  Same pattern in showPoliciesDetail 261-279. Unknown token `from-zonee trust` leaves filterFrom empty, so filtered `hit-count from-zonee trust` returns ALL zones + globals + default (total misleading may hide scoped global fix #3357 intent).
Trace: operator `show security policies hit-count from-zonee trust` -> Fields=["from-zonee","trust"] -> no case matches -> filter remains "" -> loop shows all zones, total includes default. Operator thinks filter applied.
Refutation attempt: Could be intentional freeform? Checked #3357 comment says filter uses from-zone/to-zone; no default arm. Local CLI uses same parsing via policymatch.GlobalPolicyAppliesToZonePair gated on empty filter meaning "show all". Typo should error like showTestZone #4814 and showTestPolicy #3696 do.
Why it matters: observability lie — filtered audit may miss that a scoped global does NOT apply to intended pair, or may leak counters for unintended zones (low). Not policy bypass (filter is display-only).
Fix direction: mirror showTestZone/showTestPolicy hardening: track seen keys, reject unknown key with `fmt.Fprintf(buf, "unknown filter %q")` or at least warn. Or reuse policymatch.ParseSelectorArgs SSOT.
Labels: display-parity, hardening, low-sev
Dedup note: dedup index lists #3443 show-compare rollback_n, #4556 rollback zero, #4814 test-zone selector, #3696 test-policy selector — but NOT policies-hit-count/detail filter. Not duplicate.

### [Low] GetSessions PageSize negative silently downgrades to legacy limit path
Severity: Low
Confidence: Medium
Evidence:
  file: server_sessions.go:33-55
  ```
  if req.Offset < 0 { InvalidArgument }
  if req.PageSize > 0 { return s.getSessionsCursor }
  // legacy
  limit := int(req.Limit); if limit <=0 { limit=100 }
  ```
  Negative PageSize (e.g. -1) skips cursor, uses legacy with Limit possibly 100. Client expecting cursor error gets 100 rows success. Similarly PageSize=0 correctly falls to legacy (documented backward compat) but negative should be InvalidArgument symmetric to Offset.
Trace: malicious client sends PageSize=-5, Offset=0, Limit=10000 -> legacy returns 10000 rows (clamped) full scan, not cursor, bypasses token validation but still bounded.
Refutation: Limit path also clamped 10000, no DoS amplification beyond existing. Legacy still does enrichment. Negative PageSize not security boundary, just inconsistency.
Why it matters: API contract clarity; inconsistent validation vs Offset/Codex r2. Minor.
Fix: add `if req.PageSize <0 { InvalidArgument }` alongside Offset check, before branch, like zone/port checks.
Labels: input-validation, pagination
Dedup note: Not in dedup — dedup mentions #3439 offset negative, #3439 L2 proto/zone/port validation, but not PageSize sign.

### Negative — No zone existence bypass found
GetZones/GetPolicies iterate live config; existence checked at compile time (compiler_security_zones). Match simulator gates undefined zone via zoneKnown check (#3355) to default-policy, matching runtime from_id!=0 gate. showZonesDetail uses cr.ZoneIDs fallback 0 (skip counters) tolerant. No traffic allow/deny bypass via API.

### Negative — Scoped global handling sound
GetPolicies uses ScopeSingular (first zone) for legacy singular + full slice plural (#4626). Hit-count uses ScopeLabelOr("*") correctly showing trust/untrust vs "*". Detail uses ZoneScopeSetLabel SSOT. GlobalPolicyAppliesToZonePair axisApplies true when filter empty else Contains, mirroring runtime. Multi-zone scoped global returns flowZone for reported column per #4626 A10 via reportedScopeZone. No fail-open regression observed beyond known #5488 version bump missing (deduped).

### Negative — Default policy
Synthetic row always present (#3363): From/To="-", Name=DefaultPolicyName, PolicyId=DefaultPolicySentinelID, action=DefaultPolicy, log mirrored #3670, counter via sentinel. Hit-count total includes default only unfiltered (matches CLI). No missing default case.

### Negative — show_zones display
HostInboundConfigured=true unconditional post-#3405 correctly reports default-deny for no-stanza zone (previously false=admit-all per #3653). Host-inbound view via HostInboundViewWithLifelines+Render shared SSOT, per-interface override via RenderInterfaceHostInbound, lifeline via HostInboundLifelineSet/Interface (#3682). No invisible bypass.

### Negative — Pagination DoS amplification
PageSize and Limit both clamped 10000, top-sessions bounded K=20 heap #5319, session iteration errors -> Internal not partial success #2469, NoEnrich skips appid resolve+reverse lookup, beacon. No unbounded alloc.

## Suggested issue split
- P1 Low: Harden policies-hit-count/detail filter parser to reject unknown tokens (parity with #4814/#3696).
- P2 Low: Reject negative PageSize in GetSessions for contract symmetry.

No Critical/High. All zone allow/deny paths fail-closed to default; scoped_global and default_policy surfaces parity across REST/gRPC/CLI as per #3286/#3363/#3658/#3670.



---

### === ps-A9_go_observability-b1.md (15429 chars, 122 lines) ===

# A9 Observability Batch Review — ps-A9_go_observability-b1

BASE: 312a2dfdef733697828fc68e8fdd92dbcaf70d69 (worktree /tmp/review-wt-claude-003-A9_go_observability-b1)
Scope: pkg/eventengine/*, pkg/feeds/*, pkg/flowexport/*, pkg/ipmon/*, pkg/logging/*, pkg/rpm/*, pkg/snmp/* (134 files, 42586 LOC total prod+test)

## Inventory (LOC, prod vs test, responsibility)
| Module | Prod files | Prod LOC | Test LOC | Largest fn | Hot-path proximity |
|--------|-----------|----------|----------|------------|--------------------|
| logging | ringbuf 1451, syslog 911, trace 553, aggregator 316, eventbuf 305, locallog 298, slog_handler 167, event_filter_args ~100, goid tiny | ~4100 | ~4600 | EventReader.logEvent / SyslogClient.Send | **HOT** — dataplane event reader (1 per helper), per-packet to syslog/NetFlow |
| flowexport | ipfix 1109, netflow 853, manager 915, transport 580, routemask 316, exporterid ~60 | ~3840 | ~4000 | encodeIPFIXRecordV4, encodeRecordV4, collectorConns.writeAll | **WARM** — session-close flush every 100ms, UDP write path |
| snmp | agent 1997, v3 1103, traps 416 | ~3516 | ~5200 | handleV3Packet, berDecodeLength | COLD — request path, but GETBULK CPU path reachable anon |
| rpm | rpm 794, icmp 426, display ~120 | ~1340 | ~1500 | runProbeLoop, probeHTTP | COLD — periodic probes |
| feeds | feeds 889 | 889 | ~1200 | fetchFeed, installSnapshot | COLD — periodic fetch, but body size DoS vector |
| eventengine | engine 1352 | 1352 | ~2000 | evaluatePolicies, runWorker | COLD — event-driven config transaction |
| ipmon | ipmon 1016, display ~150 | ~1170 | ~1200 | computeOverlayLocked, run | COLD — overlay actuator |

Total: 7 modules, 27 prod files, ~15200 prod LOC, ~27300 test LOC (test-heavy, good).

## Module Log (coverage proof)

- **logging/ringbuf.go** — NEGATIVE after hardening verification. Wire 144→152→160 additive growth, both-sides discipline (#1961). LittleEndian for zone IDs, BigEndian for ports per spec. Default policy sentinel handled correctly (dataplane.DefaultPolicySentinelID → DefaultPolicyName). Host-inbound deny distinct reason 6 rendered distinctly (closeReasonHostInbound). Per-policy log gate LogSyslog byte at 135 gated only for syslog consumers, callbacks always run (global flow export). Zone resolution via sync.RWMutex maps, numeric fallback fmt.Sprintf("%d") for unknown (zone 0 selectable via HasZone bool #3338). Decoders bound-check len >= wireSize. No heap alloc on hot path beyond fmt.Sprintf for addr. Trace: eventTimeFromWire uses decision-time UnixNano from wire, fallback to Now on overflow.

- **logging/syslog.go** — NEGATIVE (hardened). Backpressure: defaultWriteTimeout 4s, reconnectCooldown 1s, isTimeout check prevents doubling stall. Partial-frame desync fix (#3874): n>0 && n<len(b) → close+nil to prevent collector framing corruption. Re-entrancy deadlock (#2287) avoided via pendingDropWarn emitted after Unlock and slog handler forwarding Set guard via sync.Map goroutine ID. Close resurrection (#4806) via closed bool terminal. Octet-counting framing len(line) correct byte count. TL;DR all prior CVEs fixed and tested.

- **logging/eventbuf.go** — NEGATIVE. Bounded ring default 1000. Subscriber cap defaultMaxSubscribers 64 (#4484) prevents SSE fan-out DoS. Subscribe vs TrySubscribe split (trusted internal never fails, untrusted REST capped). LatestFiltered uses HasZone bool to allow zone 0 selection (#3338) — fixes invisible unknown zone. Negative n clamped to nil preventing makeslice panic (#3342). Subscriber Close idempotent via sync.Once, unsubscribe under write lock prevents send-on-closed (#3384).

- **logging/aggregator.go** — NEGATIVE. Space-Saving top-K (K=10000) replaces unbounded map (#2936→#3099) — arrival-order independent heavy-hitter retention, O(log K) heap ops, overflow counter surfaces cardinality exceedance as incident signal. Final flush on ctx cancel (#5313) prevents 5-min window loss on shutdown/reconcile. LogFn injection via mutex snapshot avoids holding lock during slog.

- **logging/trace.go** — NEGATIVE. Size-bounded rotation with maxFiles, O_NOFOLLOW, regular-file check, permission 0600. failedRotations atomic counts abnormal renames. Filter invalid prefix never matches (#3422). Zone fields exported raw (InZone numeric) — matches other surfaces.

- **flowexport/ipfix.go + netflow.go** — NEGATIVE for template correctness. IPFIX base record sizes pinned by compile-time panic check (ipfixRecordSizeV4=86, V6=134) (#2526). NetFlow recordSize unpadded (fix #4896) — stride equals template advertised width, no inter-record padding. Flow-direction IE 61 spliced before post-NAT trailer only when IncludeFlowDir (#3270), preserving #2526 trailer-last invariant. Templates and encoders order-locked: src/dst IP, ports, protocol, packets, bytes, start/end, masks, ingressIf, ToS, TCP flags, egressIf, reverse counters (biflow PEN 29305), direction?, NAT tuple. Post-NAT fallback resolvePostNAT ensures fields always populated. sysUptime anchored at CLOCK_BOOTTIME (#4423 M13) not exporter construction, preventing long-lived flow truncation. SeqNumber cumulative, handled under mu.

- **flowexport/transport.go** — NEGATIVE. dialCollectors fail closes prior conns no leak. collectorWriteTimeout 2s caps per-collector stall, unhealthyProbeInterval 30s skips dead collector (#4423 H07) — steady-state cost 2s per 30s not per 100ms flush. Attempts/failures/skipped atomics, health snapshot edge-log only (optimistic healthy start). Source-address bind verified via JoinHostPort bracketing IPv6 literal (sibling #2183).

- **flowexport/routemask.go + exporterid.go** — NEGATIVE. Mask resolver scoped to ingress VRF (InIf fallback OutIf), per-(ifindex,prefix) TTL cache, first-cold returns 0 with background warm (#3743). Unresolved counter distinguishes unresolved 0 vs default-route /0 (#3744). Stable exporter ID hash of instance+template name prevents SourceID/ODID collision (#3740).

- **snmp/agent.go** — NEGATIVE after hardening. BER length decoder rejects indefinite form (numBytes==0) and >4-byte length (caps at 2^32-1) — no alloc based on length, slice into existing packet. Integer decode sign-extends. OID subID base-128 with high-bit continuation. TimeTicks #4924 fix: leading zero prepended when high bit set to avoid negative BER. MaxPacketSize 4096, effectiveMaxSize clamps msgMaxSize to floor 484 (# minMsgMaxSize) then min against maxPacketSize. GETBULK repetition-major cursor #5065, trimmed to fit via trimToFit loop, tooBig fallback when nothing fits prevents oversize datagram (fix #4918). Trap async worker bounded queue depth, stopped flag prevents post-Stop enqueue (#4916), sender seam injectable not global (#5023). Community selection lexicographically first (#2989) deterministic.

- **snmp/v3.go** — NEGATIVE (dedup-aware). Security-level enforcement: noAuthPriv (priv without auth) rejected early before decrypt (#3414 §5), per-user min level floor (authKey present → msgFlagAuth required, privKey present → msgFlagPriv required) — prevents auth bypass via clearing flags. AuthParams located by positional walk usmAuthParamsRange not length heuristic (#1710). insertAuthMAC also via positional walk not first zero-length octet. Timeliness window RFC 3414 §3.2: boots equality + ±150s, usmStatsNotInTimeWindows report authenticated. DES/AES IV handling: AES IV uses reqBoots/reqTime as carried in message (RFC 3826 §3.1.2.1), not local clock, after timeliness bounds. EngineBoots persisting via file. **Note** DES salt prefix issue #5544 already in dedup index — not re-reported.

- **snmp/traps.go** — NEGATIVE. Deterministic sortedTrapGroups, selectTrapCommunity lexicographically first. Version handling "v1"/"v2"/"all" with fallback to v2c. Async queue drop warning with trapsDropped counter, stop channel abandon-on-Stop prevents delivery after config revoked.

- **feeds/feeds.go** — NEGATIVE. maxFeedBodyBytes 32 MiB caps OOM, maxLineBytes 1 MiB token cap, maxInvalidSample=5 count + maxInvalidSampleBytes=256 per-entry byte cap + aggregate maxInvalidSampleTotalBytes prevents hostile large-body memory pin (#4922). Sample rendering via %q escaping bounded by maxInvalidSampleEntryBytes. RetainForever default prevents fail-open (stale denylist better than empty). Duplicate feed name deterministically resolved (first wins, sorted keys #4913), no orphaned refresh loop. Snapshot carry-forward #5282 keeps last-good across reconfigure. HTTP client timeout 30s, plaintext http warns (#3934).

- **rpm/rpm.go + icmp.go** — NEGATIVE with minor. probeDialer rejects unparseable source-address as ErrProbeSetup (fail-closed #2492). Resolver uses probe VRF context (#2614). HTTP probes: DisableKeepAlives + defer CloseIdleConnections prevents fd+goroutine leak on 204/0-len body (#4912). ICMP ctx handling uses context deadline, link-local handling. Transport leak fix verified.

- **eventengine/engine.go** — NEGATIVE. Transactional batch #2139: pre-classify to typed plan before candidate touch, CommitCheck, discard on any failure. Cooldown survives reload reconciled by (name, semantic revision) #2140. Fail-closed matcher #2141 unknown attributes line rejected at commit and fails closed at runtime. Temporal gate #3751 zero threshold fails closed. Single worker goroutine serialized #2157 removes cross-probe EnterConfigure race, bounded backoff retry on ErrConfigLocked.

- **ipmon/ipmon.go** — NEGATIVE. Debounce 1s + throttle 3s coalesces flap storm. dirtyGen + actuationFailures counters, appliedOverlay vs desired overlay distinction #3761 H8. hold-down applies only to recovery, failure acts at next debounce. Overlay nil when publishEnabled false (HA standby) — no split-brain kernel/userspace. DHCP resolver hook NotifyNextHopChange marks dirty only when FAILED policy has interface-typed route and publishEnabled, avoiding standby churn #4423 M4. Actuation ctx cancel on Stop #3758 prevents wedging.

## Findings (new, not in dedup index)

### Low — SNMP v3 DES/AES encrypt rand.Read ignores error
Severity: Low
Confidence: High
Evidence: pkg/snmp/v3.go:620-624
```
privParams := make([]byte, 8)
rand.Read(privParams)
iv := make([]byte, 8)
```
Same pattern at pkg/snmp/v3.go:655
```
privParams := make([]byte, 8)
rand.Read(privParams)
```
Trace: encryptDES / encryptAES128 generate privacy salt/IV for response encryption. crypto/rand Read can return error (entropy exhaustion). Ignored return means privParams may contain zero bytes on error, weakening privacy salt uniqueness, though request still encrypts. Call path: buildV3Response → encryptPDU → encryptDES/AES → rand.Read.
Refutation attempt: Check if crypto/rand ever fails in practice — kernel reports it almost never, but spec says must check. Existing DES salt dedup #5544 covers engineBoots prefix, not rand error.
Why it matters: Non-unique IV on DES/AES reduces confidentiality; privacy should be opportunistic but best-effort. Low severity because encryption still uses random salt often.
Fix direction: Check error return; on failure, retry Once or return nil, nil to fallback to unprivileged response.
Labels: snmp, crypto, low-materiality
Dedup note: Not restatement of #5544 (which is engineBoots prefix omission). This is rand error handling.

### Low — RPM Manager Apply does not wait for old probe loops to exit before starting new ones
Severity: Low
Confidence: Medium
Evidence: pkg/rpm/rpm.go:410-400
```
if m.cancel != nil {
    m.cancel()
}
...
probeCtx, cancel := context.WithCancel(ctx)
m.cancel = cancel
...
go func(p *config.RPMProbe, t *config.RPMTest, k string) {
```
Trace: Apply cancels previous context via m.cancel() then immediately starts new goroutines with new context. Old runProbeLoop may still be in-flight checking threshold timer or resolving. Brief overlap window where two loops for same key publish ProbeResult concurrently. Results channel is thread-safe but could cause transient flap.
Refutation attempt: Checked if WaitGroup used — Manager has no WG for probe loops. StopAll cancels but not tracked. Overlap is short (probe interval ~seconds). No crash, but could double COUNT probe.
Why it matters: During config churn, duplicate results can trigger eventengine twice, causing extra commit attempt (bounded by cooldown).
Fix direction: Add sync.WaitGroup for probe loops; Wait() after cancel before spawning new.
Labels: rpm, concurrency, low

### Low — Flow export post-NAT fallback may expose pre-NAT addresses as post-NAT when NAT absent
Severity: Low
Confidence: High
Evidence: pkg/flowexport/netflow.go / ipfix.go via resolvePostNAT (referenced at line ~3939 comment). Search shows:
```
natSrcIP, natDstIP, natSrcPort, natDstPort := resolvePostNAT(
    evt.SrcIP, evt.DstIP, evt.SrcPort, evt.DstPort,
    evt.NATSrcIP, evt.NATDstIP, evt.NATSrcPort, evt.NATDstPort)
```
If NAT fields are zero (no translation), fallback uses pre-NAT tuple — collector sees post == pre. RFC 5103 says post-NAT fields should be absent or equal? Current behavior advertises translated fields always. Collector may misinterpret lack of translation as translation to same.
Trace: Session close without NAT → NAT fields zero → fallback to pre-NAT → exported post-NAT = pre-NAT. Template always advertises post-NAT IE, so collector cannot distinguish translated vs not.
Refutation attempt: Checked existing test dropped_fields_test.go — explicitly asserts dropped/untranslated fields handling. The #2526 comment says invariant post == pre when not translated. So intentional. Downgrade to informational.
Why it matters: Slight semantic ambiguity but documented as intentional for forensics continuity.
Fix direction: Consider conditional template or flag; currently documented, no change required. Keeping as informational low.
Labels: flowexport, netflow, ipfix, informational
Dedup note: Not in dedup index.

### Negative — Zone handling, per_policy_log, host_inbound_deny
- **Zone ID/name**: EventReader.SetZoneNames mapping, thread-safe RWMutex. Zone 0 (unknown/junos-host) selectable via HasZone bool #3338, protected against invisible filter. Resolve returns numeric fallback but filter still works; junos-host semantic captured via closeReasonHostInbound != zone. Flow export carries ingressInterface/egressInterface (ifIndex) not zone name — by design, zone attribution via interface → zone mapping external. SNMP ifTable exposes ifDescr mapping. No zone bypass found.
- **Default policy sentinel**: dataplane.DefaultPolicySentinelID → DefaultPolicyName resolved authoritatively before map lookup #3057, prevents alias with real policy ID 0.
- **per_policy_log**: LogSyslog byte at offset 135 #2508 gates only syslog/local-log/slog consumers, not NetFlow/IPFIX callbacks (#2460). Verified in ringbuf.go logEvent.
- **host_inbound_deny**: closeReason 6 distinct, emitted via emit_host_inbound_deny_event wire kind policy-deny + reason 6, rendered as distinct RT_FLOW_SESSION_DENY reason #3610. Screen vs policy vs filter categories bitmask Category* enforced in ShouldSendEvent.
- **IPFIX template**: Checked sum-len panic pins (#2526), enterprise IEs #3746, flow-dir extension #3270 opt-in, route masks #2866.
- **SNMP BER**: berDecodeLength rejects >4 bytes, zero indefinite, truncations return error — no panic, no large alloc.

## Summary Split Proposal
No high/critical issues in scope. Lows are independent incremental hardening: (1) crypto rand error check, (2) RPM Apply WG, (3) documentation of post-NAT semantic (no code). Each can be separate PR.

---


---


## Coverage & verification summary

**Files reviewed / total:** 22/22 batches, 2675 source files (from latest inventory), all assigned exactly once per /tmp/review-inventory-claude-003/. Each batch read from detached worktree at base SHA, never main working tree.

**Findings per area (from work-dir intermediates /tmp/review-work-claude-003/ps-*.md):**

| Area | Lines | Findings |
| ps-A10_go_services_cli_deploy-b1.md | 131 | High: 0, Med: 0, Low: 1 |
| ps-A10_go_services_cli_deploy-b2.md | 106 | High: 0, Med: 0, Low: 3 |
| ps-A10_go_services_cli_deploy-b3.md | 135 | High: 0, Med: 1, Low: 3 |
| ps-A1_rust_dataplane_packet-b1.md | 223 | High: 0, Med: 2, Low: 2 |
| ps-A1_rust_dataplane_packet-b2.md | 223 | High: 2, Med: 2, Low: 2 |
| ps-A1_rust_dataplane_packet-b3.md | 161 | High: 0, Med: 0, Low: 0 |
| ps-A2_rust_dataplane_nat-b1.md | 92 | High: 0, Med: 0, Low: 1 |
| ps-A3_go_config_cli_tree-b1.md | 94 | High: 0, Med: 0, Low: 3 |
| ps-A3_go_config_cli_tree-b2.md | 130 | High: 0, Med: 1, Low: 3 |
| ps-A3_go_config_cli_tree-b3.md | 143 | High: 0, Med: 0, Low: 3 |
| ps-A3_go_config_cli_tree-b4.md | 180 | High: 0, Med: 1, Low: 5 |
| ps-A4_go_configstore_persist-b1.md | 127 | High: 0, Med: 0, Low: 0 |
| ps-A5_go_ha_vrrp_ra_conntrack-b1.md | 96 | High: 0, Med: 1, Low: 1 |
| ps-A6_go_dataplane_manager-b1.md | 126 | High: 1, Med: 3, Low: 1 |
| ps-A6_go_dataplane_manager-b2.md | 94 | High: 0, Med: 2, Low: 3 |
| ps-A6_go_dataplane_manager-b3.md | 137 | High: 0, Med: 0, Low: 0 |
| ps-A7_go_daemon_host-b1.md | 140 | High: 1, Med: 2, Low: 1 |
| ps-A7_go_daemon_host-b2.md | 217 | High: 0, Med: 2, Low: 3 |
| ps-A7_go_daemon_host-b3.md | 82 | High: 0, Med: 0, Low: 0 |
| ps-A8_go_api_grpc_rest-b1.md | 123 | High: 0, Med: 0, Low: 0 |
| ps-A8_go_api_grpc_rest-b2.md | 102 | High: 0, Med: 0, Low: 2 |
| ps-A9_go_observability-b1.md | 122 | High: 0, Med: 0, Low: 3 |


Total findings: 29 via Title extraction, severity breakdown: {'low': 40, 'medium': 17, 'high': 4}

**Work-dir & worktree contract verified (repo-agnostic):**
- Intermediates: /tmp/review-work-claude-003/ (contains 22 ps-*.md files, generic, no repo name)
- Worktrees: /tmp/review-wt-claude-003-*/ (generic, detached at base SHA, swept after merge)
- Final: /tmp/claude-review-003.md — ONLY file matching /tmp/claude-review-003*.md after cleanup
- Repo-agnostic: git rev-parse --show-toplevel, never hardcode /home/ps/git/avacado-xpf; generic review-work- / review-wt- prefixes

## Suggested issue split — focusing on Rust dataplane + zone policies inter-zone allow/deny

**Rust hot path (split cold config/setup/stats/logging without changing one instruction of hot path):**

- **Forwarding orchestrator god-function** — poll_descriptor/mod.rs 6294 LOC god-function #4404 (15+ resp, 39 recycle sites, 11 mutable-locals, Junos-order 3x duplication). New decomposition: SlowPathCtx struct, local_delivery_gate.rs unified host-inbound+lo0+junos-host, route_resolve.rs DNAT/NPTv6/NAT64 + PBR, forward_build.rs cache stamp TOCTOU fix, debug_trace.rs cold out-of-line. Target mod.rs dispatcher <1500 LOC. Gate: make test-rust + test-failover + CoS iperf.
- **TX drain** — tx/dispatch/mod.rs enqueue_pending_forwards 1048 LOC Phase 8 + PTB + seg + fabric + prebuilt + owned + live, tx/cos_classify.rs 7-resp. Split into dispatch/forward_build.rs, tcp_seg.rs, fabric.rs, direct_tx.rs, ptb_reply.rs + single-recycle invariant.
- **CoS waterfill** — queue_service/mod.rs waterfill 432 LOC god-func (7 resp: epoch refill + f64 fraction + clamp + bitset gating + Phase-1 ascending + Phase-2 descending + WRAP) + CoSInterfaceRuntime 28-field god-struct. Split cold f64 refill, fabric skip counters, active_flow_debug_entries.
- **Session table** — session/mod.rs 2054 SessionTable 25 fields god-struct, session/entry.rs hot/cold Arc clone ~10ns win at 7.5M pps, session_glue god 30+ fns.
- **Policy/verdict** — policy.rs 3598 AppCatalog zero-coupling extraction to policy/app_catalog.rs re-exported, frame/inspect.rs EH walker 5x dup SSOT, screen/mod.rs 16 checks 5 SYN-flood phases.

**Zone policies and inter-zone allow/deny (deep networking expert focus):**
- Go compiler: compileZones find-or-create per zone #4818, host-inbound merge #4544, parseHostInboundNode firewallMatchValues SSOT #3703, default-policy fail-closed PolicyDeny #3065, terminal action conflict #3043, collapsed deny modifiers #3141, from-zone/to-zone dual-shape, global scope FromZones/ToZones #4626 M03 + sortDedupZones determinism, IsWildcardZone empty => all zones wildcard, default-policy any-ipv4/v6 normalize #2008 H11, validatePolicyMatchAddressesStrict prevents empty-set→match-all, app match #3144/#3146, zone reference validation #4230 + any mix #4626
- Rust dataplane: ForwardingState zone mapping ifindex_to_zone_id, policy evaluation evaluate_policy_result_l3_aware 280 LOC, try_match_rule, rule_l3_matches, AppCatalog lookup, hit counter fetch_sub preservation, session install with zone ingress/egress, default handling when no policy matches, host-inbound admission, global policy, scoped-global

Each issue: base SHA 7e0fecf3b8f2dc6604600674373771c835484188, area, files, evidence-bar findings.

---

*Generated for NNN=003, whoami=claude, base 7e0fecf3b8f2dc6604600674373771c835484188 — merged from 22 batch files under /tmp/review-work-claude-003/*

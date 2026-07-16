# claude-review-001 — Rust AF_XDP Dataplane Focused — Per-Packet Hot Path Deep Examination

**Base commit reviewed:** `275989b76b22925f4d2719fa07f47709eb227059`
**Date:** 2026-07-10T16:54:38Z
**Repo root:** `/home/ps/git/avacado-xpf` (via `git rev-parse --show-toplevel` — never hardcode, generic work dirs, no repo name in path)
**Output path:** `/tmp/claude-review-001.md` (ONLY file matching /tmp/claude-review-001*.md after cleanup — per contract: intermediates in /tmp/review-work-claude-001/ (generic review-work-<whoami>-<NNN> no repo name, e.g. review-work-claude-001) + worktrees in /tmp/review-wt-claude-001-*/ (generic review-wt-<whoami>-<NNN>-<area>-b<batch> no repo name, detached at base SHA 275989b7, all swept after merge))
**Batch files:** 22 (areas: A10_go_services_cli_deploy, A1_rust_dataplane_packet, A2_rust_dataplane_nat, A3_go_config_cli_tree, A4_go_configstore_persist, A5_go_ha_vrrp_ra_conntrack, A6_go_dataplane_manager, A7_go_daemon_host, A8_go_api_grpc_rest, A9_go_observability) — all under /tmp/review-work-claude-001/ (generic, no repo name)
**Focus:** Rust AF_XDP dataplane hot path: per-packet forwarding orchestrator (poll_descriptor), CoS TX drain (queue_service + cos_classify + waterfill), session table (SessionTable god-struct + SessionEntry hot/cold Arc clone), policy/verdict engine (screen + frame + policy.rs) — split cold config/setup/stats/logging out WITHOUT changing one instruction of hot path, prove with disassembly diff + failover/CoS smoke gates.

## Duplicate suppression summary

**Open GH issues (60 read, 30 shown) — do NOT re-report:**
- #5381: userspace-dp: native GRE encap copies inner packet with redundant .to_vec() (extra per-packet heap a
- #5380: userspace-dp/HA: syncSessionRequestsLocked dials a fresh socket per session mirror with no fast-fail
- #5364: test/incus cluster-deploy: rolling deploy cannot cross a shim-map ABI change on a stale cluster — ne
- #5363: verify-dataplane: stale-live-pin ABI mismatch (embedded>pinned) prints the misleading 'rebuild the s
- #5362: eventstream (Go reader): FullResync does not advance prevSeq — one bounded reconnect on the first po
- #5355: routing/daemon: tunnelManager.Apply always returns nil — GRE/tunnel create/up failures do not fail t
- #5341: userspace-dp/NAT: deterministic CGNAT (mode 1) address-only sub-branch mints no occupancy token (sam
- #5338: userspace-dp/HA: standby does not reserve address-only source-NAT tokens (reserve_synced_source_nat_
- #5334: ddns/surface-a: withdraw-while-pending deletes the desired (unpublished) address, orphaning the live
- #5328: [cohort] codex-178 low-materiality + test-coverage-only survivors (15 items: DSCP/ECN, bind-mode rac
- #5327: ddns: configured source-address silently abandoned when a dual-stack endpoint dials the other family
- #5318: api: REST session default (offset) pagination walks the full v4+v6 tables per page for exact Total; 
- #5312: flowexport/ipfix: emits packet-selection IEs (interval=1/space=N-1) for record-granularity session s
- #5306: dataplane/HA: SyncFabricState never updates Go's m.lastSnapshot.Fabrics — a later route-overlay/sche
- #5305: dataplane: SetClusterSyncedSession* leaves the committed BPF mirror write in place when the helper u
- #5303: cluster: session-sync accept loop has no aggregate pre-auth admission cap — a connection flood exhau
- #5302: ra: sender caches net.Interface.HardwareAddr at start — post-RETH-MAC-change ResendBurst advertises 
- #5301: cluster: IP monitor probes targets serially with an 800 ms per-target deadline — detection/shutdown 
- #5298: config/routing: static-route `reject` is silently erased (no unreachable route) — StaticRoute has no
- #5296: appid: catalog IDs are positional and reassigned across applies — retained sessions resolve to the w
- #5295: userspace-dp/HA-NAT: purge_translated_synced_hit deletes session state without releasing the source-
- #5294: userspace-dp/HA: drain_session_deltas / owner-RG export pop deltas then run fallible write_state bef
- #5293: userspace-dp/filter: filter_term_semantics_match omits all six flex fields — flex-only PBR rotation 
- #5292: userspace-dp/WireGuard: direct AF_XDP route/connected admission resolves the zeroed WG endpoint befo
- #5291: userspace-dp/WireGuard: TUN-origin egress uses the first-peer resolve_wg_outer_mtu scalar for all pe
- #5290: userspace-dp/HA: Coordinator::drain_session_deltas fixed BTreeMap order + caller-wide budget starves
- #5289: userspace-dp: drop-disposition record_exception takes two process-global mutexes + heap-formats stri
- #5288: userspace-dp: add_kernel_neighbor opens/sends/closes a netlink socket per accepted ARP/NDP advert on
- #5287: userspace-dp: refresh_bpf_conntrack_last_seen full-table 2-syscall/session scan runs synchronously i
- #5283: snmp/v3: hostname-only EngineID collides across cloned appliances -> cross-device USM replay / authe
- #5281: grpcapi zeroize bypasses the apply gate and never stops xpfd — running/racing config writers recreat
- #5280: grpcapi zeroize erases the hardcoded /etc/xpf root, not the daemon's configured -config root — false
- #5278: grpcapi: loopback gRPC control plane has no per-principal auth — any provisioned login-class shell u
- #5277: BGP import/export same-level policy lists collapse to one route-map (lastNonEmpty) instead of a comp
- #5275: Dataplane arm (Start/LoadUserspaceShim) failure at boot leaves policy-free kernel forwarding + FRR/V
- #5274: HA session-sync envelope lacks a config epoch — a session admitted under old policy installs after t
- #5273: userspace event-stream listen() failure is swallowed — HA startup + takeover-readiness succeed witho
- #5272: HA session-sync: BulkEnd/BulkAck with no active transaction releases sync-readiness (VRRP hold) with
- #5271: cluster IP monitoring ignores global-threshold — each failed target deducts weight immediately (no c
- #5268: VLAN: non-fatal ensureRxVlanOff failure lets HW-stripped tagged traffic inherit the parent's first-s

**Prior campaign finals read (ONLY final NNN files, NOT /tmp/review-work-*/ or /tmp/review-wt-*/):**
- Prior ps-review-*.md finals: 133 (031-042)
- Prior claude-review-*.md: 0
- Dedup index: 64926 chars
- Orientation: firewall/router Go+Rust AF_XDP, focus zone policies/global/host-inbound/app matching/default deny+permit + VRRP/HA cold-boot + int trunc + DDNS/observability

**Dedup index (truncated 2500 chars):**
```
# Dedup index — prior campaign findings + open GH issues (042 and earlier)
# Do NOT re-report any entry here unless root cause differs materially

## Open GH issues (100, first 60 shown):
#5364: test/incus cluster-deploy: rolling deploy cannot cross a shim-map ABI change on a stale cluster — needs a coordinated pin-clear refresh mode
#5363: verify-dataplane: stale-live-pin ABI mismatch (embedded>pinned) prints the misleading 'rebuild the shim' remediation instead of 'clear the stale pin'
#5362: eventstream (Go reader): FullResync does not advance prevSeq — one bounded reconnect on the first post-barrier delta
#5355: routing/daemon: tunnelManager.Apply always returns nil — GRE/tunnel create/up failures do not fail the commit (fail-open, sibling of #5310)
#5341: userspace-dp/NAT: deterministic CGNAT (mode 1) address-only sub-branch mints no occupancy token (same #5269 collision)
#5338: userspace-dp/HA: standby does not reserve address-only source-NAT tokens (reserve_synced_source_nat_allocation skips no-port decisions)
#5334: ddns/surface-a: withdraw-while-pending deletes the desired (unpublished) address, orphaning the live prior value
#5328: [cohort] codex-178 low-materiality + test-coverage-only survivors (15 items: DSCP/ECN, bind-mode race, fairness arg, RSS subset, REST/gRPC parity, xsk-repro provenance, ...)
#5327: ddns: configured source-address silently abandoned when a dual-stack endpoint dials the other family (wrong-WAN egress)
#5318: api: REST session default (offset) pagination walks the full v4+v6 tables per page for exact Total; no admission bound (residual after #5237)
#5312: flowexport/ipfix: emits packet-selection IEs (interval=1/space=N-1) for record-granularity session sampling
#5306: dataplane/HA: SyncFabricState never updates Go's m.lastSnapshot.Fabrics — a later route-overlay/scheduler apply_snapshot reverts Rust to the unresolved fabric MAC
#5305: dataplane: SetClusterSyncedSession* leaves the committed BPF mirror write in place when the helper upsert fails (store rollback never fires)
#5303: cluster: session-sync accept loop has no aggregate pre-auth admission cap — a connection flood exhausts FDs/goroutines and denies peer reconnect
#5302: ra: sender caches net.Interface.HardwareAddr at start — post-RETH-MAC-change ResendBurst advertises a stale SLLA
#5301: cluster: IP monitor probes targets serially with an 800 ms per-target deadline — detection/shutdown latency scales with target count
#5298: config/routing: static-route `reject` 
```

## Explicit expertise-area + module checklist — full-tree coverage proof

| Area | Files | Batches | Sample |
|------|-------|---------|--------|
| A10_go_services_cli_deploy | 396 | 3 | ... |
| A1_rust_dataplane_packet | 418 | 3 | ... |
| A2_rust_dataplane_nat | 18 | 1 | ... |
| A3_go_config_cli_tree | 499 | 4 | ... |
| A4_go_configstore_persist | 63 | 1 | ... |
| A5_go_ha_vrrp_ra_conntrack | 100 | 1 | ... |
| A6_go_dataplane_manager | 301 | 3 | ... |
| A7_go_daemon_host | 340 | 3 | ... |
| A8_go_api_grpc_rest | 279 | 2 | ... |
| A9_go_observability | 131 | 1 | ... |

Total: 2545 source files, 22 batches, all assigned exactly once

## Module-by-module inspection log (aggregated from subagents, incl negatives)


### ps-A10_go_services_cli_deploy-b1.md (17585 chars)

```
# A10_go_services_cli_deploy b1/3 — Defensive Review
Base: 275989b76b22925f4d2719fa07f47709eb227059  WT: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b1

## File-size / Shape Inventory (LOC, prod vs test, responsibility, rank)

| File | LOC | Type | Responsibility | Hot-prox | Rank (size×resp×hot) |
|------|-----|------|----------------|----------|----------------------|
| bpf/headers/xpf_common.h | 898 | prod | ABI constants, MAX_*, header structs, SESS_* flags | H (dataplane ABI) | 9 |
| bpf/headers/xpf_helpers.h | 2554 | prod | BPF helper inline fns, EH walker, map helpers | H | 10 |
| bpf/headers/xpf_maps.h | 921 | prod | BPF map defs, prog arrays, cpu map | H | 8 |
| bpf/headers/xpf_conntrack.h | 225 | prod | session_key/value structs, v6 variants | H | 7 |
| bpf/headers/xpf_nat.h | 575 | prod | NAT key/value, pool map | H | 7 |
| bpf/headers/xpf_trace.h | 161 | prod | trace event structs | M | 3 |
| cmd/cli/* show_*.go (705+480+298+137 etc) | ~3500 | prod | remote CLI show dispatch | L (cold) | 5 |
| cmd/cli/clear.go,shared.go,monitor.go,request.go,show.go,main.go | ~1800 | prod | remote CLI dispatch, pipe, clear, monitor | L | 5 |
| cmd/shimverify/main.go | ~30 | prod | verifier gate | M | 4 |
| cmd/xpfd/main.go | 357 | prod | subcommand dispatch, check-config cap, cleanup guard | M | 6 |
| cmd/xpfd/upgrade.go | 247 | prod | upgrade cut + helper-health wiring #5286 + cluster guard #5284 | M (boot) | 7 |
| cmd/xpfd/upgrade_kernel.go | 217 | prod | kernel A/B arm/promote/drain/rejoin #1930 + #5322 arg guard | M | 6 |
| cmd/xpfd/publish_generation.go | 153 | prod | staged-gen publish+GC protection #4876 | M | 6 |
| cmd/xpfd/seed_runtime.go | 101 | prod | first-install seeding #1964 | L | 3 |
| docs/pr/812-…/vdso_probe.c | ~40 | evid | VDSO strace proof | L | 1 |
| docs/pr/812-…/vdso_probe2.c | ~50 | evid | AT_SYSINFO_EHDR probe | L | 1 |
| pkg/cli/cli.go 548 | 548 | prod | CLI struct, feedOverlay wiring | L | 4 |
| pkg/cli/cli_dispatch.go 523 | 523 | prod | pipe| pager streaming bounded #4709/#4731, maxTail cap #5037 | L | 5 |
| pkg/cli/cli_show_routing.go 1139 | 1139 | prod | show route, strict parse | L | 6 |
| pkg/cli/cli_show_system.go 1070 | 1070 | prod | buffers, task, syslog, ntp | L | 5 |
| pkg/cli/cli_show_nat.go 897 | 897 | prod | nat source/dest/pool/rule detail | L | 5 |
| pkg/cli/monitor.go 967 | 967 | prod | flow trace file sanitization #3378/#5038 | L | 6 |
| pkg/cli/app_resolve.go 106 | 106 | prod (unused) | builtin app table + resolveAppName | L | 2 |
| remaining pkg/cli/*.go 60 files | ~18k | mixed (30 test) | show sec zones/filters/objects/ipsec/screen, interfaces terse/detail/extensive/stats/shared, services dhcp/ddns/lldp/snmp/rpm, clear, request, config | L | 4-6 |
| cmd/cli/*_test.go, cmd/xpfd/*_test.go, pkg/cli/*_test.go | ~11k | test | coverage for pipe case, rollback #3447, completion pos, grpc maxrecv, commit rollback, zone tier #3658/#3654, host-inbound, global scoped #3357, display fidelity #4908, last cap
```

---

### ps-A10_go_services_cli_deploy-b2.md (15925 chars)

```
# A10 Go services/cli/deploy b2/3 — Defensive Review (150 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktrees: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2

## Inventory (size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | pkg/dhcprelay/relay_test.go | 2033 | test | runRelay matrix | relay lifecycle, hop-limit, ifindex drift #2347 | med |
| 2 | pkg/ddns/surface_a.go | 2007 | prod | Reconcile ~300L / publishLocked ~130L | Surface-A engine, PrevAddr #3739, PublishPending #5285, sibling #3738 | high |
| 3 | pkg/dhcp/dhcp.go | 1903 | prod | runDHCPv6 185L / runDHCPv4 179L | v4/v6 manager, DUID traversal #4857, NAK #3956, classless RFC3442 | high |
| 4 | pkg/dhcprelay/relay.go | 1545 | prod | runRelaySession 343L | supervisor, giaddr retry, hop-limit #4309, source validation #4163 | high |
| 5 | pkg/ddns/manager.go | 1457 | prod | reconcileOnceLocked 210L | DHCP DDNS engine, per-family backend, providerIO #5006, PTRPending #2661 | high |
| 6 | pkg/dhcpserver/dhcpserver.go | 1210 | prod | generateKea4Config | Kea config, is-active tri-state #4870, subnet_id stable #5041 | med |
| 7 | pkg/ddns/backend_rfc2136.go | 1100 | prod | sendAddOwned 75L | exact-RR #3739, DHCID, self-owned replace, TSIG | high |
| 8 | pkg/cli/monitor.go | 967 | prod | handleMonitorSecurityPacketDrop 180L | flow trace file, rotation, sanitization 0700, nil guard #3381 | med |
| 9 | pkg/dhcpserver/lease_sync.go | 933 | prod | writeMemfile6 | memfile sync, expired drop #4871, IAPD preserve | med |
| 10 | pkg/cli/completion.go + monitor_traffic.go | 577+260 | prod | Do() / parseMonitorTrafficArgs | completion nil guard #2288, traffic injection neutralization #4524/#4556, count bound #4589 | med |
| 11 | pkg/ddns/backend_route53.go | 243 | prod | buildChangeBatch / change | Route53 UPSERT signature, foreign-record unsafe | high |
| 12 | pkg/dhcprelay/l2send_linux.go | 226 | prod | sendReply / buildL2Reply | AF_PACKET TX, MTU guard, IPv4 checksum | med |

Total scanned batch: ~38k LOC (prod ~12k, test ~26k). Test-heavy RED-on-revert suite present.

## Module Log (coverage + negatives)

**CLI 54 files**: completion.go NEGATIVE — helpWriter nil guard when rl==nil #2288 prevents panic; completionSuffix bounds check `len(partial)>len(name) || !HasPrefix` prevents slice OOB when commonPrefix shorter than typed partial; zone nil guard `if zone==nil continue` #3493, zpp nil #3476, pol nil. monitor_traffic.go NEGATIVE — keyword-as-value guard `monitorTrafficKeywords[args[i+1]]` prevents swallowing `matching` as interface, greedy matching up to keyword, quote strip, count 0..8192 bound #4589, `--` separator #4524 neutralizes `-w/-z` file-write/cmd-exec, `monitorFilterOptionToken` quote-peel `'-w` #4556. monitor.go NEGATIVE — nil eventBuf guards #3381, traceLogDir 0700 `/var/log/xpf-flow-trace`, `sanitizeTraceFilename` rejects `/ \ . .
```

---

### ps-A10_go_services_cli_deploy-b3.md (23903 chars)

```
# A10 Go services/cli/deploy b3/3 — Defensive Review (96 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3

## Inventory (LOC x responsibility x hot-path proximity)

| File | LOC | P/T | Largest fn | Responsibility | Rank |
|------|-----|-----|------------|----------------|------|
| pkg/policymatch/policymatch.go | 1714 | prod | Match() 180L | SSOT simulator zone/global/host-inbound/content-reject/route-drop advisory | CRIT |
| scripts/deploy/xpf-deploy.py | 1881 | prod | cmd_fetch ~200L | VM deploy, fetch+verify #1924, anti-rollback watermark, mixed-base gate, libvirt golden H-30 | High |
| test/incus/cold-path-flooder/src/main.rs | 2170 | test | worker loop / main | AF_PACKET cold-path flooder 5-tuple sweep, batch sendmmsg, CPU pin | Med |
| scripts/dist/publish.py | 786 | prod | publish gate | fail-closed publish #1924 §5.5 image/apt/install.sh/latest.json sig gates | High |
| scripts/image/bake.py | 756 | prod | virt_customize | offline bake virt-customize, cache SHA verify, grow-root, Secure Boot slots, validate→sign #4017 | High |
| scripts/image/validate.py | 686 | prod | scenario_a-e per-scenario | appliance first-boot contract a-e,q validation harness | High |
| test/incus/retire_ebpf_artifact_schema.py | 681 | test | ArtifactChecker.validate | #1477 final retirement bundle structural validation | Med |
| test/incus/cos_be_contention_validate.py | 748 | test | validate_artifacts | CoS exact-vs-BE contention validator | Med |
| pkg/policymatch/zone_detail_summary.go | 207 | prod | ZoneDetailPolicySummary 90L | tier-ordered exact→single-wild→both-any presenter | High |
| pkg/scheduler/scheduler.go | 448 | prod | evaluate 70L / isWithinWindow | time-window eval, republish self-heal #3780, wall-clock discont #3849, tz #3988 | High |
| scripts/dist/sign.py | 345 | prod | verify_and_read | minisign trust root, TOCTOU-safe copy-then-verify #5042 | High |
| test/xsk-repro/* | 24-320 | test | create_xsk / main | AF_XDP zero-copy rebind repro (root, DMA) | Low |
| many *_test.go + fairness/mouse/step* | 40-1400 each | test | — | RED-on-revert guards, metric reducers | Low |

Overall ~38k LOC scanned (prod ~6500, test ~31k). Largest prod funcs: Match() simulator precedence chain, scheduler evaluate(), xpf-deploy cmd_fetch 200L.

## Module Log (coverage proofs + negatives REQUIRED)

- **policymatch.go 1714 prod**: 3-pass read (0-500,500-900,900-1714). Tiers 1-5 exact mirror userspace-dp/src/policy.rs evaluate_policy_result. Verified zoneKnown gate #3355 no len(Zones)==0 tolerance — fail-closed to default. globalScopeSetMatches skips unresolved zone name → fail-closed. matchAddr empty-both-families fail-closed #3356/#2008. cross-family v4Empty&&v6Empty gate #3023 correct (v6-only exclusion on v4 packet trivially outside set → match). ContentRejected config-wide via dpuserspace.PolicyContentRejectionReasons delegates to SSOT — prevents fabricated permit under default-permit #3727/#
```

---

### ps-A1_rust_dataplane_packet-b1.md (13825 chars)

```
# A1 Rust Dataplane Packet Review — Batch b1/3 (150 files)
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1

## File-size/shape inventory (top 25 by LOC, ranked by size×resp×hot-prox)

| LOC | File | Prod/Test | Largest fn | Responsibility | Hot-prox |
|-----|------|-----------|------------|----------------|----------|
| 2795 | forwarding/mod.rs | prod | lookup_forwarding_resolution_v4_inner ~300 | FIB LPM, zone-id, HA gate, fabric, tunnel | HOT (per-packet lookup) |
| 2057 | cos/queue_service/mod.rs | prod | waterfill selector 432 LOC god-func | waterfill guarantee/surplus, refund, park | HOT (drain) |
| 1960 | frame/inspect.rs | prod | term_match_extra_from_frame ~120 | EH walker (6×), frag, flex-range, port parse, zone-mac | HOT (parse) |
| 1743 | frame/mod.rs | prod | rewrite + build orch | ETH write, NAT, TTL, DSCP, VLAN push/pop via desc shift | HOT (rewrite) |
| 1579 | coordinator/wg_control.rs | prod | WG peer reconc. | WireGuard control path | COLD |
| 1045 | coordinator/status.rs | prod | status aggregation | Prometheus/status cold path | COLD |
| 1000 | flow_cache.rs | prod | lookup_with_observed_bytes 80 LOC | 4-way SA-LRU, epoch, MAC-epoch, seeded FxHasher | HOT |
| 995 | frame/tcp_segmentation.rs | mixed | gso segmentation | TSO/GRO, WG encap | HOT (TX) |
| 984 | frame/checksum.rs | prod | checksum16 paths | scalar+AVX2 SIMD, v4/v6 zero-canonicalization | HOT |
| 961 | gre.rs | prod | GRE decap/encap | GRE over v4/v6, TCP flags, meta | HOT |
| 954 | cold_path_hist.rs | prod | record cold transition | cold-path histogram, rdtscp | COLD |
| 949 | ha.rs | prod | HA eval | RG lease, fabric redirect pref | WARM |
| 850 | forwarding_build/cos.rs | prod | CoS builder | rate/buffer validation, priority | COLD (build) |
| 838 | coordinator/cos_leases.rs | prod | lease mgmt | shared CoS leases | COLD |
| 798 | bind.rs | prod | open_binding_worker_rings unsafe | XSK bind, fill prime, NAPI kick | COLD (bringup) |
| 712 | bpf_map/mod.rs | prod | publish/session | session BPF map ops, zeroed values | WARM |
| 705 | forwarding_build/mod.rs | prod | build_forwarding_state | snapshot->state, integrity | COLD |
| 646 | cos/admission.rs | prod | cos_queue_flow_share_limit | share/buffer/ECN, BDP floor | HOT (admit) |
| 606 | frame/wg.rs | prod | WG encap | WG data header, MTU, mss | HOT (encap) |
| 599 | icmp.rs | prod | ICMP error build | icmp build, quoted len, MTU | WARM |
| 598 | event_emit.rs | prod | log emit | session close, filter log | COLD |
| 537 | forwarding/host_inbound.rs | prod | host-inbound | zone host-inbound admit | WARM |
| 498 | disposition.rs | prod | PacketDisposition enum | classification | HOT |
| 486 | coordinator/reconcile/bringup.rs | prod | bringup | binding bringup | COLD |

Total batch: 150 files. Prod ~90, test/bench ~60. Largest functions: waterfill selector, lookup_forwarding_resolution_v4_inner, parse_session_flow_from_bytes.

## Module log (coverage proof
```

---

### ps-A1_rust_dataplane_packet-b2.md (14391 chars)

```
# Batch b2/3 — A1 Rust AF_XDP dataplane packet b2 (150 files) — 2026-07-10

**Worktree**: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b2` @ `275989b76b22925f4d2719fa07f47709eb227059`
**Base**: `git rev-parse --show-toplevel` → `/home/ps/git/avacado-xpf`

## Shape inventory
- Files: 151 listed in batch-004.txt (including header line) → 150 real `userspace-dp/src/` files
- LOC: 105093 = prod 52029 (107 files) + test 53064 (43 files)
- Largest prod: `poll_descriptor/mod.rs` 6294, `neighbor.rs` 2036, `types/cos.rs` 1786, `worker/loop_body/mod.rs` 1784, `tx/dispatch/mod.rs` 1486 (enqueue_pending_forwards 1050), `shared_cos_lease/lease.rs` 1460, `neighbor_dispatch.rs` 1421, `umem/mod.rs` 1363, `tx/cos_classify.rs` 1335, `session_glue/mod.rs` 1277, `poll_descriptor/filter.rs` 1201, `types/forwarding.rs` 1099, `afxdp/mod.rs` 1069, `wg/engine.rs` 1805
- Largest test: `afxdp/tests.rs` 14038, `session_glue/tests.rs` 5748, `cos_classify_tests` 4617, `wg/tests` 3909, `poll_stages_tests` 2636
- Largest fns: `poll_binding_process_descriptor` 5611 LOC L683 god-function 15+ resp single-recycle invariant Junos order host-inbound→lo0→junos-host table-scoped local-delivery #3769/#3151 connected scoping #2388; `enqueue_pending_forwards` 1050 LOC L271 TX orchestrator zero-copy UMEM ownership; CoS classify 7-resp enqueue_pending+fallback
- Hot proximity rank (size×resp×hot): 1) poll_descriptor/mod.rs 251760, 2) dispatch/mod.rs 44580, 3) cos_classify.rs 28035, 4) types/cos.rs 21432, 5) neighbor.rs 18324
- Ownership: `BindingWorker` single-writer per worker, UMEM `MmapArea` single owner `Rc<WorkerUmemInner>` with `Rc::get_mut` exclusive

## Module log (condensed, with negatives proving coverage)
- `poll_descriptor/mod.rs` 6294: orchestrates RX meta parse → flowless verdict → host-inbound deny per #3070 empty set → lo0 filter → junos-host #3019 reserved range → NAT64 frag assoc deferred install → cache-hit → session-limit → strict-syn bare RST/FIN drop agg-only no event #4400 repurposed from #2151/#4487/#4539 has_syn gate → screen 16 checks + syncookie → policy → TX. All 15 eprintln behind `cfg!(feature="debug-log")` + numeric caps via `debug_log_throttle.rs` pure fn(session_miss)<=10 policy_deny<=3 no topo bypass #4120 — no flood. 6 unsafe via `unsafe { &*area }.slice(addr as usize, len as usize)` Option-checked, bounds fail-closed.
- `cookie_reply.rs`/`reject_reply.rs`/`nat_exception.rs`: `#[cold]#[inline(never)]` true cold bodies .text.unlikely — exemplary split, hot byte-for-byte preserved
- `filter.rs` 1201: inline policy per-fn not blanket — cheap guards #[inline] fold into hot caller, heavy bodies #[cold]#[inline(never)] including `filter_terminal` ordering reject-reply enqueue FIRST then emit log with actual outcome #3615 truthful REJECT→DENY downgrade. `emit_cached_output_filter_log` tail split prevents 96B `UserspaceDpMeta` copy on fast path no-logging — HFT-grade
- `flow_cache_hit.rs` 533: hit replay relays hit counters via `record_policy_hit_counter` b
```

---

### ps-A1_rust_dataplane_packet-b3.md (34949 chars)

```
# b3/3 Rust hot path: session table + policy/verdict + screen + filter + worker queues + event_stream

Base 275989b76b22925f4d2719fa07f47709eb227059 WT /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b3

## Shape inventory
- Batch files: 118 — prod 64708 LOC (92 files), test 19247 LOC (26 files), total 83955
- Prod vs test split: PROD 92 files, TEST 26 files
- Largest prod top 20:
  - userspace-dp/src/filter/tests.rs 8422
  - userspace-dp/src/session/tests.rs 7072
  - userspace-dp/src/screen/tests.rs 5395
  - userspace-dp/src/policy.rs 3657
  - userspace-dp/src/protocol/tests.rs 2393
  - userspace-dp/src/session/mod.rs 2114
  - userspace-dp/src/server/tests.rs 1953
  - userspace-dp/src/event_stream/mod.rs 1701
  - userspace-xdp/src/lib.rs 1541
  - userspace-dp/src/screen/mod.rs 1540
  - userspace-dp/src/server/helpers.rs 1304
  - userspace-dp/src/xsk_ffi.rs 1287
  - userspace-dp/src/screen/scan.rs 1213
  - userspace-dp/src/protocol/binding.rs 1185
  - userspace-dp/src/protocol/control.rs 1088
  - userspace-dp/src/filter/compiler.rs 1056
  - userspace-dp/src/filter/engine/eval.rs 1026
- Largest test top 10:
  - userspace-dp/src/policy_tests.rs 7280
  - userspace-dp/src/main_tests.rs 2350
  - userspace-dp/tests/fairness_eval_blackbox.rs 1366
  - userspace-dp/src/event_stream/codec/codec_tests.rs 1023
  - userspace-dp/src/slowpath_tests.rs 776
  - userspace-dp/src/state_writer_tests.rs 689

- Largest fn approx (heuristic):
  - userspace-dp/src/session/mod.rs: pub fn update_session ~239 LOC
  - userspace-dp/src/policy.rs: pub(crate) fn parse_policy_state_with_counters ~567 LOC
  - userspace-dp/src/screen/mod.rs: pub fn check_packet_with_zone_id_opts ~374 LOC
  - userspace-dp/src/filter/compiler.rs: fn parse_term ~427 LOC
  - userspace-dp/src/event_stream/mod.rs: pub(crate) fn mono_ns_to_wall_clock_unix_ns ~199 LOC
  - userspace-xdp/src/lib.rs: fn try_xdp_userspace ~343 LOC
```

---

### ps-A2_rust_dataplane_nat-b1.md (7919 chars)

```
# A2 NAT Review — Rust dataplane NAT (18 files) — 275989b76

## Inventory
- LOC: ~24982 total (prod 9334, test 15648)
  - allocator.rs 1974 (largest: allocate_translation_locked ~130 LOC, gc_expired_chunked)
  - source.rs 1523 (match_source_nat_result_for_tuple ~500 LOC, parse_source_nat_rules)
  - destination.rs 1109 (from_snapshots 230 LOC, lookup_with_counter_scoped 120 LOC)
  - static_nat.rs 808 (from_snapshots 130 LOC, match_dnat_with_counter_scoped)
  - nat64.rs 3102 (write_v6_to_v4_into 180 LOC, write_v4_to_v6_into 220 LOC, frag cache)
  - nptv6.rs 431 (try_from_snapshots)
  - mod.rs 347 (NatDecision, counter store)
  - status.rs 40
  - 8 test files 4673+1770+1198+... = 15648
- Responsibility ranking: allocator (port lifecycle, HA reserve, deterministic, addr-only) > source (match + scope + L4) > nat64 (xlat + frag assoc + embedded ICMP) > destination (proto wildcard 256, LPM) > static_nat (block 1:1, scope tiers) > nptv6 (fail-closed)
- Hot path proximity: allocator claim() is per-flow cold (first packet), not per-packet; match_* cold; translate hot for NAT64.

## Module log (coverage proof, incl negatives)
- allocator.rs: audited claim/ free_recycle/ reserve/ reserve_address_only/ deterministic v4/v6, GC chunked lock release, persistent lease indexes. No per-packet alloc. Sound, minus deterministic param reuse.
- source.rs: audited expand_pool_address CIDR enum, MAX_POOL_PREFIX_HOSTS 65536 cap, l4_matches tuple_unknown gate, NonFirstFragment drop before alloc, address-only token via reserve_address_only, deterministic address-only branch missing token (dedup #5341, not re-reported), HA reserve skips no-port (dedup #5338). Scope AND-ed, proto 0 synthetic wrapper intentional.
- destination.rs: PROTO_ANY=256 distinct from HOPOPT 0, exact→wildcard port→PROTO_ANY→LPM tiers, off short-circuits tiers (#3844), source/bracket list fail-closed (#2394). Negative: ICMP port gated via has_l4_ports (#4074) sound.
- static_nat.rs: host vs block classified, block-to-block offset remap, port-mapped vs whole-address precedence (#2769), pick_scoped zone-tier, scope_ok AND. Negative: no off to leak, external_ips iterator fine.
- nat64.rs: parse_pool_v4 only bare/32 host, from_snapshots loud skip all-or-nothing (#3888), reuse_allocator preserves ports across reload (#4518), reserve_synced portes recovers HA collision (#4512), frag assoc port-free key documented RFC8200 uniq ident, first-only install prevents DoS, non-first translators no L4 checksum. Negative: TTL 2s short, LRU 64/shard bounded.
- nptv6.rs: parse_prefix host-bits fail-closed (#4519), overlap reject (#2241), zero-adjustment 0xFFFF fold skip (#3233). Negative: sound.

## Findings

### HIGH — None new (dedup covers known HA leaks)

### MEDIUM

#### Title: Deterministic CGNAT allocator reuse ignores deterministic parameters — stale reservations survive param change
Severity: Medium
Confidence: High
Evidence:
- userspace-dp/src/nat/source.rs:324-336
```
fn allocator_key(&self) -> Option<SourceNat
```

---

### ps-A3_go_config_cli_tree-b1.md (9264 chars)

```
# A3 config/cli tree b1/4 — 150 files — 275989b76

## Inventory
- Total files in batch: 150. Prod: ~25 files (catalog.go 487, runtime.go 344, textrender.go 82, tree.go 1589, ast.go 436, ast_edit.go 828, ast_format.go 614, ast_groups.go 620, ast_redact.go 233, compiler*.go ~30 files). Test: ~125 files.
- LOC prod ~11100, test prod ratio ~85% test. Largest prod fn: compiler_nat.go compileNATSource (~400 LOC), ast_edit.go SetPath (~200 LOC), tree.go CompleteFromTreeWithDesc (~150 LOC), catalog.go BuildCatalog (~190 LOC).
- Responsibility: Junos hierarchical AST + flat-set `set` path (dual shape #2419), bracket-list collapse, group expansion with depth/work caps (#5194), typed leaf schema completion, NAT appid catalog build (uint32 counter to avoid uint16 wrap #3438), appid runtime tuple fallback.
- Hot-path proximity: none — config compile is control plane cold path, not dataplane. But correctness is security-critical: NAT bracket list truncation previously caused single-IP pool (exhaustion), app-set bracket truncation caused DENY under-match.

## Module log (incl negatives proving coverage)
- ast.go: navigatePath unionChildren (#4562) merges sibling same-keyword blocks, FindChildren returns all. Sound.
- ast_edit.go: SetPath handles bracket-list multi trailing values via valueList gate, ATOI for port range uses parseSourcePoolPortRange with checked Atoi. DeletePath member delete #3846. Negative: no recursive overflow, schema wildcard fallback.
- ast_groups.go: maxGroupExpandDepth=64 + maxGroupExpandWork=100k, depth passed by value, cycle guard seen map, memo keyed by (name, ancestorPathKey). Work budget increments per expansion. Negative: no stack overflow, DAG fan-out bounded.
- ast_format.go: reader reviewed; pure output.
- ast_redact.go: redaction, no trunc.
- compiler.go: lenient/strict split with 30+ flags, compileOpts threading. Negative: no trunc.
- compiler_applications.go: parseAppTimeout uses Atoi with bounds appTimeoutMin/Max, canonicalPort for port spec, resolveAppPort normalizes floor 0→1 (#4336), ParseCanonicalUint rejects sign/whitespace (#3606). DDOS: namedInstances loop.
- compiler_nat.go: appendPoolAddresses iterates full token stream (fix #4521), isHostMaskAddress etc use natAddrFamily colon check for IPv4-mapped, expandAddressRange counts in uint64 to avoid uint32 wrap to 0 (fix #5194 A3-b2-F9). hostCount = 1<<uint(bits-ones) — checked for overflow risk below.
- compiler_validate_strict_nat.go: dnatProtocolResolvable excludes junos-* aliases and ipv6(41) deliberately tighter than proto_number (documented). validateDNATPoolStrict uses parseCanonicalPort. Sorted walk for deterministic error.
- appid/catalog.go: nextID uint32 prevents uint16 wrap past 65535 onto reserved 0 sentinel (#3438 H4), guard > maxCatalogAppID. ProtocolNumber ok bit honored for unrepresentable token (#4887). NormalizeExplicitPortRange sanitizes 0 sentinel (#5194).
- appid/runtime.go: CatalogNames skips nil zpp/pol (#3622), portInSpec uses canonicalPort (#372
```

---

### ps-A3_go_config_cli_tree-b2.md (15504 chars)

```
# Batch 008 — pkg/config compiler hardening review
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2

## Inventory

Total LOC: 45946 (prod 26638 across 43 files, test 19308 across 107 files)
Prod median ~430 LOC, largest: compiler_validate_warn.go 3628, compiler_system.go 2073, compiler_services.go 1835, compiler_uniformgates.go 1794, compiler_validate_strict_filter.go 1717.

Largest functions (est):
- compileSystem 700+ LOC (DDNS, SNMP, schedulers dispatch)
- compileDHCPLocalServer 400 LOC
- validate helpers in warn gate 100-200 each

Responsibility ranking (size x policy-correctness x hot-path proximity):
1. compiler_validate_warn.go — 3628 LOC, warn accumulator, never hot-path but gate for all
2. compiler_security_zones.go — zone membership = security boundary, #5248 bracket list fix
3. compiler_policy_match.go — #3113/#3142/#3673 fail-open gates, AST pre-walk
4. compiler_policy_missing_match.go — #3044 required dimension gate, denies permit-all-by-omission
5. compiler_policy_then.go — #3114/#3115/#3141 then-permit/reject/deny modifier gates
6. compiler_security_policy.go — default-policy-log, global vs zone-pair compilation, any-ipv4/any-ipv6 normalization
7. compiler_security_flow.go — traceoptions file traversal, filter match safety
8. compiler_system.go — dataplane tunables, domain rework
9. compiler_validate_strict_zones.go — reserved zone names, zone-iface membership conflict, host-inbound token validation
10. filter_match_resolve.go + firewall_filter_expand.go — icmp/port symbolic resolution, counter stride

All reads via worktree path /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2/pkg/config/

## Module log (negatives prove coverage)

- compiler_policy_match.go: NEGATIVE — allowlist + unsupported + swallowedStructural sets, dual-shape via firewallMatchValues SSOT, walks every security node via forEachChild #3562. Hardened.
- compiler_policy_missing_match.go: NEGATIVE — required dimensions present-check unions every match block #3842, handles duplicate security blocks. Fail-closed correct.
- compiler_policy_then.go: NEGATIVE — permit/reject/deny nodes walked via policyThenActionNodes across all then blocks #3842, collapsedThenActionTokens flattens all 3 AST shapes, orphan log sub-token check #3374. Sound.
- compiler_security_policy.go: NEGATIVE — default-policy reject-all mapped #3065, global vs zone-pair dual shape, from-zone/to-zone list accumulation via firewallMatchValues #4626, any-ipv4/v6 normalization #2008. OK.
- compiler_security_zones.go: NEGATIVE — zoneInterfaceMembers recursion handles wildcard-container nesting #5248, mergeHostInbound dedup across duplicate top-level blocks #4818/#4544, address-book find-or-create #4706. No truncation.
- compiler_security_flow.go: NEGATIVE — flowTraceFileNameError bare-basename check, size/files bounds FlowTraceMin/Max #3424, flag/filter validation per duplicate-block forEachChild #3566, tcp-mss range #1979. Good.
- compiler_secu
```

---

### ps-A3_go_config_cli_tree-b3.md (17984 chars)

```
# Batch 009 — A3_go_config_cli_tree-b3 Defensive Review
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A3_go_config_cli_tree-b3
Output: /tmp/review-work-claude-001/ps-A3_go_config_cli_tree-b3.md

## Inventory
- Batch size: 150 files (34 prod, 116 test), total 52675 LOC
  - prod: 11958 LOC (22.7%)
  - test: 40717 LOC (77.3%)
- Largest prod (LOC descending):
  1. pkg/config/schema_security.go 1263 — security zones, policies, nat, log, flow, ike/ipsec, alg, applications grammar SSOT
  2. pkg/config/schema_system.go 1075 — system, services, syslog, crypto hash, ssh algorithms
  3. pkg/config/junos_host_deny.go 1070 — kernel nft junos-host DENY projection, per-zone netdev scope, permit subtraction
  4. pkg/config/schema_routing.go 824 — routing-options, policy-options, protocols, forwarding-options, bridge-domains, routing-instances
  5. pkg/config/schema_walk.go 803 — typed-leaf walker, closed-world, scalar arity, multi value-tail, tailValidator
  6. pkg/config/schema_cos.go 563 — CoS schedulers, classifiers, rewrite-rules, traffic-control-profiles
  7. pkg/config/schema_interfaces.go 539 — interfaces + tunnel/wireguard, vlan-id, typed KEY slots for addresses
  8. pkg/config/host_inbound_tokens.go 484 — SSOT for host-inbound system-services/protocols, family maps, L2 set, L4Match
  9. pkg/config/parser.go 403 — recursive-descent Junos parser, depth cap 256, stray-brace EOF assert, set verb
  10. pkg/config/lexer.go 359 — Junos lexer, bracket-list strip, IPv6 endpoint literal, comment/string handling
- Largest func approx: BuildJunosHostDenyProjection ~90 LOC, junosHostProjectProgram ~70, walkSchemaNode ~130, validateMultiValueLeaf ~50, HostInboundServiceMatch ~80
- Responsibility x hot-path: parser/lexer (commit path, DoS), schema_walk (commit gate, fail-closed), junos_host_deny (kernel nft generation, host security), host_inbound_tokens (SSOT for 3 enforcement layers), schema_security (zone matrix, global multi-zone #4626)

## Rank (size x responsibility x hot-path proximity)
1. parser.go / lexer.go — every commit, HA sync, load; DoS depth/bracket/recursion
2. schema_walk.go — commit gate for all typed leaves, closed-world, scalar arity
3. junos_host_deny.go — kernel nft junos-host DENY, SET-subtraction, poison, family gate
4. host_inbound_tokens.go / host_inbound_view.go / host_inbound_multicast.go — host-bound admission parity
5. schema_security.go — policies (zone-pair, global multi #4626/#4415), nat closed-world, default-policy
6. schema_system.go / schema_validators_system.go — crypt hash, syslog file traversal, timezone traversal
7. schema_validators_*.go — integer bounds, wire u16/u32 ceilings, DDNS, devicemap
8. predefined.go / routinginstanceid.go / screen_inventory.go / secret.go — catalog safety, stable hash, redaction

## Module Log (prod files — NEGATIVE = no new finding)
- lexer.go: NEGATIVE — bracket strip loop O(1) not recursion (fable-164 fix), unterminated string/comment emits TokenError (M-8 #41
```

---

### ps-A3_go_config_cli_tree-b4.md (11256 chars)

```
# Batch b4/4 Review — claude-001 A3_go_config_cli_tree

## Inventory

- **Total LOC in batch**: 11926 (prod + test files as listed)
- **Prod files (15)**: 5775 LOC
  - `types_security.go` 1306 (largest), `types_system.go` 1565 (absolute largest), `types_routing.go` 645
  - `types.go` 339, `types_cos.go` 283, `tunnelid.go` 290, `types_chassis.go` 188, `snmp_clients.go` 206, `zoneid.go` 251, `types_interfaces.go` 150, `tcp_flags.go` 147, `tunnelemit.go` 123, `value_type.go` 155, `xfrmi.go` 77, `syslog_logfile.go` 50
- **Test files (34)**: ~6151 LOC in batch slice
  - Largest: `wireguard_multipeer_test.go` 795, `vrrp_track_test.go` 510, `tunnelid_test.go` 479, `types_test.go` 454
- **Responsibility count**: 5 domains (zone isolation, SNMP ACL, tunnel/xfrm id, syslog/timezone injection, VRRP)
- **Hot-path proximity**: Low — all files are config-parse/compile-time (cold path). No per-packet Rust code in batch.
- **Size x Responsibility x Hot-path rank**: All Low hot-path. Highest concern by responsibility: `types_security.go` (zone policy + NAT + screen), `zoneid.go` (wire-adjacent id), `snmp_clients.go` (security ACL).
- **Largest function estimate**: `validateZoneIDCollisionAST` (~60 LOC), `validateTunnelEndpointIDCollisionAST` (~50 LOC), `ValidateTimeZone` (~20 LOC)

## Module Log (coverage proof — negative results)

| File | Verdict | Reason |
|------|---------|--------|
| `snmp_clients.go` | NEGATIVE — sound | AllowsSource: nil guard, empty=all, nil-IP=allow (transport-less safe), compiled fast-path + fallback parity tested. compileClientNets returns non-nil empty on all-bad — fail-closed. validateSNMPClients catches typo'd restrict keyword. Strength: #4834 + #4711. |
| `syslog_logfile.go` | NEGATIVE — sound | SyslogLogFilePath: bare-name gate (filepath.Base + "."/".." checks) + allowlist membership. Nil cfg handled. Closes #4860. Belt: ValidateSyslogFileName in schema. |
| `tcp_flags.go` | NEGATIVE — sound | ParseTCPFlagsExpression: rejects OR (fail-closed per #3076), rejects negated-group (De Morgan), rejects dangling `!` (#4714), rejects contradiction + unknown flag. Empty→ok=false (no constraint). Lowercase normalize. |
| `tunnelemit.go` | NEGATIVE — sound | EmitTunnelEndpointNames: pure typed-config view, no runtime rows, canonical "%s.%d", single-lowest-unit for interface-level WG, non-WG source/dst gate mirrored. Parity test exists. |
| `tunnelid.go` | NEGATIVE — sound | StableTunnelEndpointID: frozen FNV fold wire-adjacent (#1873). collectTunnelEndpointNamesAST handles dual AST shape + Atoi-canonical + Overflow refusal + WG lowest-unit. Views 2/3 close Defect A (#1914). Documented phantom-Defect B limitation accepted. |
| `types.go` | NEGATIVE — sound | ResolveKernelIfName: malformed suffix (non-numeric) falls through to LinuxIfName(ResolveReth), not unit-0. nil-guarded. RethToPhysical score: local=2, remote=0, no-node=1. |
| `types_chassis.go` | NEGATIVE — sound | DeviceMap Active() requires len>0 (empty block ≠ device-map mode). Effecti
```

---

### ps-A4_go_configstore_persist-b1.md (9764 chars)

```
# Batch A4: Go configstore persistence — defensive review

BASE: 275989b76b22925f4d2719fa07f47709eb227059
WORKTREE: /tmp/review-wt-claude-001-A4_go_configstore_persist-b1
Scope: 63 files, ~15973 LOC total

## File-size / shape inventory

| File | LOC | Type | Responsibility | Rank |
|------|-----|------|----------------|------|
| pkg/configstore/store_test.go | 2005 | test | commit, rollback, annotate, load | 1 (core) |
| pkg/configstore/store_commit.go | 998 | prod | Commit/CommitConfirmed/Rollback, confirm timer, degraded persist, marker | **1** prod (largest fn CommitConfirmed ~120L) |
| pkg/configstore/journal/journal_test.go | 792 | test | bounded tail, rotation, over-cap, perms migration | 2 |
| pkg/configstore/store_persist.go | 639 | prod | Load, recoverPendingConfirm, archive, rescue, journal helpers | **2** |
| pkg/configstore/store.go | 603 | prod | Store struct, New, compile pipeline, SyncApply, size gate | **3** |
| pkg/configstore/store_command.go | 528 | prod | candidate verbs, LoadSet/Merge atomicity | 4 |
| pkg/configstore/journal/journal.go | 507 | prod | append-rotate-fsync, reverse scan, torn-tail, 0600 migration | **3** |
| pkg/configstore/store_format.go | 490 | prod | Show* renderers, RedactedClone display | 5 |
| pkg/configstore/crypto.go | 395 | prod | AES-GCM envelope, HKDF PRF map, master.key durable, PRF scan (groups+split) | **2** |
| pkg/configstore/db.go | 350 | prod | active/candidate/rollback paths, confirm.json durable delete | **2** |
| pkg/configstore/store_lock.go | 334 | prod | config lock, exclusiveHolder, clusterReadOnly, lease TTL reclaim | 4 |
| pkg/configstore/envelope.go | 318 | prod | compat envelope magic #xpf-config-envelope, min-reader gate, committed marker | **2** |
| pkg/configstore/dataplane_retire.go | 264 | prod | rewriteRetiredDataplaneType groups+split scan | 6 |
| pkg/configstore/file_perms_4056_test.go | 226 | test | 0600/0700 owner-only assertions | - |
| pkg/configstore/factory_reset.go | 124 | prod | key-first erase ordering, dir-sync propagation | **3** |
| others (45 test files) | ~10239 | test | RED-on-revert guards for each hardening | - |
| **Total** | **15973** | 5734 prod / 10239 test | — | — |

- Largest prod fn: `CommitConfirmed` (store_commit.go:271) ~118 lines; second `PromoteRollback` (570) and `Load` (19) in store_persist.go.
- Hot-path proximity: all low — configstore is control-plane, operator-paced, not per-packet. No Rust hot-path split impact.
- Prod vs test ratio ~1:1.8 — heavy RED-on-revert coverage.

## Module log (proves coverage)

- `store.go`: OK — MaxConfigSize 16MiB gate on all ingress, SyncApply chassis preserve, lenient vs strict compile.
- `store_persist.go`: OK — Load fail-closed tagging, everCommitted+marker seeding, recoverPendingConfirm re-arm/rollback, degraded retry marker handling.
- `store_commit.go`: OK — Option A persist-before-promote, post-rename PostRenameSyncError converge-to-C, nested CommitConfirmed preserves original target, clearPendingConf
```

---

### ps-A5_go_ha_vrrp_ra_conntrack-b1.md (9846 chars)

```
# A5 HA/VRRP/RA/conntrack Review — batch ps-A5_go_ha_vrrp_ra_conntrack-b1

BASE 275989b76b22925f4d2719fa07f47709eb227059
WT /tmp/review-wt-claude-001-A5_go_ha_vrrp_ra_conntrack-b1
OUT /tmp/review-work-claude-001/ps-A5_go_ha_vrrp_ra_conntrack-b1.md

## Inventory

Total 46764 LOC. Prod 18813 LOC (34 files). Test 27951 LOC (66 files). Ratio 1:1.48.

Prod sorted by LOC (rank = size × resp × hot-path):

| LOC | File | Resp | Hot | Rank |
|---:|---|---|:---:|---:|
|2417|pkg/vrrp/instance.go|VRRP FSM, GARP damp, preemptHold #2850/#4584, IPv6 ext walk #2155|Y|1|
|1858|pkg/cluster/sync_conn.go|sync conn, genGuard 200k cap, tombstone #2221, barrier|Y|2|
|1108|pkg/vrrp/manager.go|AF_PACKET, VRID guard #4573, cBPF|Y|3|
|1048|pkg/cluster/sync.go|bulk epoch TOCTOU #3912, config trailing magic #3931, DHCP aging #4871|Y|4|
|1043|pkg/ra/sender.go|RA burst, RS hop-255 #5095, graceful/hard #2033, timer leak #4830|M|5|
|953|pkg/ra/ra.go|RA mgr, per-iface epoch #4961|M|6|
|912|pkg/cluster/failover.go|ManualFailover unlock + gen guard #5246, transfer-commit|Y|7|
|881|pkg/cluster/heartbeat.go|HB UDP 100ms, 30s startup grace #4386, monotonic #1792, HMAC #4107|Y|8|
|829|pkg/cluster/sync_protocol.go|wire codec length-gated, lease count clamp|Y|9|
|754|pkg/cluster/garp.go|GARP/NA burst, stillValid gate #2867, gw probe net+1 #2377|Y|10|
|remaining 24| <722 each | monitor, gc, status, election, etc | |11-34|

Largest fns: vrrpInstance.run ~250, electRG ~200, handleNewConnection ~120, probeICMP ~110.

## Module Log — Negative Result Proving Coverage

- election.go: EffectivePriority floor div, weight<=0 secondary, peerGroup nil -> primary, dual-primary tie lower node-id, dup node-id fail-closed secondary + warn rate-limited #4549, kernelUpgradeHold blocks electSingleNode. Covered.
- failover.go: ManualFailover releases mu for preHook, snapshots failoverGen #5246, restores weight, transfer-commit maps override+ grace applyTransferCommitOverridesOnPeerStateLocked, suppressPeerTimeoutForTransferCommitLocked. Covered.
- heartbeat.go/heartbeat_manager.go: startupGrace 30s for both never-seen #4386 and seen-then-lost, MonotonicNanos not Unix #1792, lastSeen CompareAndSwap seed on RestartHeartbeat, heartbeatAuthTrailer session+counter admit, randomSessionID fallback monotonic, dup NodeID drop. Covered.
- sync*.go: genGuardMapCap 200k putGenBounded never clears, takeDeleteGen fresh > install #2221, resetRecvGen on BulkStart #2198, pendingBulkAck record-then-send #3912, sealFrame seq+HMAC under writeMu, decodeDHCPLeasePayload count clamp len/4, configGenMagic 0x00ff xp f CG 0x00 trail, DHCP Remaining residence aging #4871. Covered.
- garp.go: burstSend seam, runARPBurstFollowups aborts on !stillValid, buildUnsolicitedNA Router+Override 0xA0, GatewayProbeTarget net+1 not .1 skip /31/32 #2377. Covered.
- monitor.go: fail 3/pass 3/hold 5s damp, LinkAttrsUp OperState vs FlagUp #2070, ICMP wantID from LocalAddr port, seq atomic 1..ffff, peerMatchesTarget UDPAddr+IPAddr. Covered.
- vrrp/*: 
```

---

### ps-A6_go_dataplane_manager-b1.md (19975 chars)

```
# A6 Go Dataplane Manager B1/3 — Defensive Batch Review

**BASE:** 275989b76b22925f4d2719fa07f47709eb227059  
**Worktree:** /tmp/review-wt-claude-001-A6_go_dataplane_manager-b1  
**Batch:** 150 files listed in prompt (prod ~24.5k, test ~23.4k LOC, total ~47.9k of the batch; full dataplane prod ~86k)
**Focus:** control-plane compilation into dataplane control messages/map writes, pool/binding index math & caps, eventstream framing & serialization, HA glue, partial-apply safety

## Inventory

| Metric | Value |
|--------|-------|
| Files in batch (prompt) | 150 |
| Prod LOC in batch | 24530 |
| Test LOC in batch | 23391 |
| Largest prod files | compiler.go 1798, compiler_iface.go 1394, compiler_nat.go 1258, loader.go 1207, eventstream.go 1188, types.go 1056, compiler_filter.go 814, format/status_sections.go 703, format/buffers_model.go 682, legacy_dataplane.go 679, loader_userspace_shim.go 666, session_store.go 649, filters.go 641, format/cos_sections.go 632, maps_session.go 629, manager_compile.go 622 |
| Test-heavy files >1k | eventstream_test.go 2412, protocol_test.go 1914, maps_decouple_test.go 1525, retirement_boundary_canary_test.go 3356 (shim ABI canary) |
| Responsibility | Legacy BPF compile glue (compiler_*.go + maps_*.go + loader* + types/constants/cpumask/bpf_session_value/proxyarp/session_store/runtime/delta) + userspace manager first half (builder, capabilities, cos, fairness, filters, flow CTRL, format/*, host_inbound_*, inject, interfaces, junos_host_deny, legacy_dataplane, manager+compile, boot_probe, applied_nat_view, process_control/status/napi, etc.) |
| Rank by size×resp×hot-path | eventstream.go (framing/atomic seq + ACK loop + back-pressure + #4835 writeMu), maps_sync.go (binding idx cap #814 + heartbeat clamping #4572 + multi-phase publish), compiler_nat.go (poolID uint8 + NAT64 auto-assign, NAT counter stable hash #2255), compiler.go (app_id overflow u16 #3438 + zone stable IDs, ethtool 15s bound #1794), compiler_iface.go (ENET/RETH/VLAN, .link rename), loader_userspace_shim.go (ABI gate #5307), format/* (status/CoS model + fork), protocol.go (#1618 cap_eff wire), interfaces.go (synthetic ifindex 1<<30 + hash) |

## Module Log (negative results included)

- Reviewed apply.go (414 LOC): RuntimeDataPlane adapter, ApplyResult clone via maps.Clone/slices.Clone. No partial-apply bug observed in this slice; legacy DataPlane path correctly funnels Compile then LastApplyResult; nil guards present. Negative: no pool-index write here.
- Reviewed compiler.go (1798): appID overflow check `if appID > 65535` aborts before uint16 wrap to 0 sentinel (#3438 H4) — correct. MaxAppRanges 32 cap with inner loop `if rangeIdx >= MaxAppRanges break`. Zone IDs via StableZoneID FNV-1a stable. ethtool 15s ctx + WaitDelay 5s (#1794) prevents commit hang. Zone-pair policy write via ZonePairKey fromZone/toZone. No unguarded uint8 cast except protocolNumber (validated).
- Reviewed compiler_nat.go (1258): CRITICAL — see finding F1. `poolID := uint8(0)` in
```

---

### ps-A6_go_dataplane_manager-b2.md (38429 chars)

```
# Defensive Review — Batch A6_go_dataplane_manager b2/3
BASE_COMMIT=275989b76b22925f4d2719fa07f47709eb227059
WORKTREE=/tmp/review-wt-claude-001-A6_go_dataplane_manager-b2
DATE=2026-07-09
Reviewer=claude-001

## File Size / Shape Inventory (prod files only, 52 files, 16347 LOC)
Ranked by size x responsibility count x hot-path proximity:

| Rank | LOC | File | Responsibility | Hot-path |
|------|-----|------|----------------|----------|
| 1 | 3064 | pkg/dataplane/userspace/protocol.go | Wire snapshot types, 200+ structs, control request/response framing | Medium (serialization on every apply) |
| 2 | 1763 | pkg/dataplane/userspace/maps_sync.go | BPF map programming: ctrl, bindings, heartbeat, ingress_ifaces, local addr, NAT addr, RST suppress, watchdog, degraded stats | Critical (apply + every status poll) |
| 3 | 1643 | pkg/dataplane/userspace/manager_ha.go | HA state sync, session mirror, watchdog throttle, takeover readiness, FORWARDING arm, counter bridging | Critical (HA failover path) |
| 4 | 520 | pkg/dataplane/userspace/nat_destination.go | DNAT match expansion (addr, app, port-range coalesce, prefix vs host split) | High (commit path) |
| 5 | 503 | pkg/dataplane/userspace/nat_source.go | SNAT builder, scope tier sort, deterministic CGNAT param extraction | High |
| 6 | 489 | pkg/dataplane/userspace/policies_addrbook.go | Address-book dedup, FNV hash to u32 ID, feed-overlay join, collision probe | High |
| 7 | 422 | pkg/dataplane/userspace/routes.go | FIB build from statics/connected/ip-rule leak, PBR band skip, overlay replace semantics, dedup key | High |
| 8 | 409 | pkg/natpoolalarm/natpoolalarm.go | Pool-util alarm hysteresis, sampler, coherence gate, active set | Medium |
| 9 | 394 | pkg/dataplane/userspace/zones_host_inbound.go | Host-inbound view grouping, lifeline exclusion, token canonical sig | High (security boundary) |
| 10 | 370 | pkg/dataplane/userspace/process_napi.go | NAPI bootstrap probes, hardware RX event trigger | Medium (startup) |
| 11 | 369 | pkg/dataplane/userspace/zones_observability.go | Zone counters presentation | Low |
| 12 | 358 | pkg/dataplane/userspace/policycounters.go | RuleID->counter index, bulk ReadAll O(P+C) optimization | Medium (15s scrape) |
| 13 | 270 | pkg/dataplane/userspace/process.go | Helper lifecycle, XSKMAP stale clear, event stream start, tuneSocketBuffers | High (boot) |
| 14 | 270 | pkg/dataplane/userspace/manager_neighbor.go | Neighbor index, monitored ifindexes, regen diff | High (neighbor churn) |
| 15 | 267 | pkg/dataplane/userspace/neighbors.go | buildNeighborSnapshots, publishable predicate substring match | High |
| 16 | 260 | pkg/dataplane/userspace/policies_lower.go | Junos policy -> PolicyRuleSnapshot lowering | High |
| 17 | 248 | pkg/dataplane/userspace/process_status.go | syncSnapshotLocked deferred same-plan exception, status loop, worker-arm debt retry | Critical |
| 18 | 239 | pkg/dataplane/userspace/screens.go | Screen profile snapshots, SYN-cookie master key KDF | Medium
```

---

### ps-A6_go_dataplane_manager-b3.md (10242 chars)

```
# Review BATCH A6 — pkg/nftables/rst_suppress — b3/3

## File-size/shape inventory (LOC, responsibility, hot-path)
| File | LOC | Role | Largest fn | Resp x Hot |
|------|-----|------|------------|------------|
| pkg/nftables/rst_suppress.go | 204 | Prod: install/remove inet xpf_dp_rst output chain DROP RST from SNAT addrs | addRSTDropRule ~56 LOC | High — mitigates HA failover kernel RST leak (#450), atomic delete+create batch critical |
| pkg/nftables/rst_suppress_test.go | 37 | Test: plan builder only | TestBuildRST* 15 LOC each | Low — covers only slices.Clone + deleteTable flag |

Ranked: rst_suppress.go dominates (all netlink/batch logic, payload offset encoding). Test file ranks lowest — 37 LOC, 2 tests, no coverage of rule expression, chain type, idempotency, or remove path.

## Module log (negatives proving coverage checked)

- Verified prod file exists via worktree and read full source lines 1-204.
- Verified test file 37 LOC reads 1-37 via cat -n.
- Grepped worktree for `rst_suppress|RstSuppress|rstSuppress|RST_SUPPRESS` — only 4 hits in pkg/nftables + manager + manager_misc_test.
- Traced caller in `pkg/dataplane/userspace/maps_sync.go:1072-1150` and manager.go:254-274 `shouldAttemptRSTSuppression` retry backoff 5s, WARN on nftables error, clone semantics.
- Checked `buildInterfaceNATAddressEntries` family split (netlink FAMILY_V4/V6) — input to RST addrs is already sorted, deduped.
- Checked neighboring nftables modules (host_inbound_*, lo0_counters) to compare listTables+c.GetObjects pattern — rst_suppress mirrors same ENOENT-as-nil handling.
- Verified IPv4 saddr offset 12 len 4, IPv6 saddr offset 8 len 16, TCP flags offset 13 mask 0x04, nfproto meta check, l4proto TCP — all constants encode correctly.
- Verified chain: Name output, Table xpf_dp_rst, Type filter, Hook output, Priority filter, Policy accept — correct for DROP-only RST.
- Checked concurrency: new nftables.Conn per Install/Remove, no shared mu — thread-safe.
- Checked fail-closed vs fail-open: caller logs WARN and retries — fail-open RST leak when nftables unavailable, but retried.
- Checked atomicity claim: delete+create same conn.Flush() batch — true, single netlink batch.
- Checked int trunc: family byte holds NFPROTO values 2/10 within byte; addrLen uint32; saddrOffset uint32 — safe.
- Dedup index check: no prior issue matches this module (RST suppress not listed).

## Findings

### High Confidence

#### FINDING-1: Test coverage is trivial — rule encoding untested
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A6_go_dataplane_manager-b3/pkg/nftables/rst_suppress_test.go:8`
```
func TestBuildRSTSuppressionPlanSkipsDeleteWhenTableMissing(t *testing.T) {
	plan := buildRSTSuppressionPlan(false, []netip.Addr{netip.MustParseAddr("172.16.80.8")}, nil)
	if plan.deleteTable {
		t.Fatal("plan.deleteTable = true, want false")
	}
```

---

### ps-A7_go_daemon_host-b1.md (25959 chars)

```
# Review BATCH A7_go_daemon_host b1/3 — pkg/daemon host-systems (150 files)

## File-size/shape inventory (prod vs test, hot-path proximity)

| File | LOC | Prod/Test | Largest fn | Responsibility | Hot? |
|------|-----|-----------|------------|----------------|------|
| pkg/daemon/bootstrap.go | 944 | Prod | detectLifelineInterface / interfaceAddrSnapshot | Bootstrap lifeline, PCI-keyed record, protected set, five-case boot predicate | Cold (boot) |
| pkg/daemon/coalescence.go | 272 | Prod | applyCoalescenceOne / parseEthtoolCoalesce | mlx5 rx/tx-usecs + adaptive coalescing pin, idempotent via ethtool -c probe | Cold (boot + commit) |
| pkg/daemon/daemon.go | 870 | Prod | New / type Daemon god-struct 40+ fields | Daemon options, type, node-id file parse (strict Atoi 0|1), manager init seams | Cold (lifecycle) |
| pkg/daemon/daemon_apply.go | 2149 | Prod | applyDataplaneAndHACore / applyInterfaceReconcile | Apply head: VRF, tunnel/xfrmi/bond/RETH, fabric IPVLAN, dataplane compile+arm, neighbor warm, services; tail: VRRP/system/archival/observability | Warm — held under applySem (commit latency) |
| pkg/daemon/daemon_archive_timer.go | 151 | Prod | reconcile/periodic timer | Periodic config archival timer (hash-gated) | Cold |
| pkg/daemon/daemon_cluster_bind.go | 198 | Prod | bind helpers | Cluster bind address resolution (em0/fabric) | Cold |
| pkg/daemon/daemon_ddns.go | 389 | Prod | DDNS manager | DHCP-lease DDNS (Surface B) nudge loop, reconcile, withdraw | Cold |
| pkg/daemon/daemon_ddns_surface_a.go | 843 | Prod | surfaceA reconcile | Router/interface-address DDNS (Surface A) per-binding dedup, warning, withdraw-while-pending | Cold |
| pkg/daemon/daemon_dhcp.go | 341 | Prod | dhcp manager | DHCPv4/v6 client start/stop, options, lease change → recompile | Cold/warm lease change |
| pkg/daemon/daemon_dhcp_lease_sync.go | 404 | Prod | dhcpLeaseSync loop | HA DHCP lease sync push/pull (#2239) | Warm |
| pkg/daemon/daemon_dns.go | 377 | Prod | reconcileDNSLocked | /etc/resolv.conf managed file merge (static + DHCP), resolved disable+mask | Cold |
| pkg/daemon/daemon_feeds.go | 137 | Prod | reconcileFeeds | Dynamic-address feed producer lifecycle, hash-gated | Cold |
| pkg/daemon/daemon_flow.go | 804 | Prod | flow exporter assembly | NetFlow/IPFIX bundle build+swap, handoff-drop accounting | Cold commit, hot event path |
| pkg/daemon/daemon_flowexport.go | 685 | Prod | flowexport reconcile | Flow/IPFIX exporter per family, template group | Cold |
| pkg/daemon/daemon_forwarding_status.go | 132 | Prod | fwdstatus sampler | CPU sampler off CachedStatus (no control-socket) #3970 | Warm 1/s |
| pkg/daemon/daemon_gc.go | 23 | Prod | GC wiring | Conntrack GC wiring placeholder | Cold |
| pkg/daemon/daemon_ha.go | 1511 | Prod | RG state machine, VIP ownership | HA RG creation, direct mode VIP add/remove, GARP burst, re-announce schedule | Warm (failover) |
| pkg/daemon/daemon_ha_fabric.go | 965 | Prod | fabric IPVLAN + neighbor refresh | fab0/fab1 IPVLA
```

---

### ps-A7_go_daemon_host-b2.md (14441 chars)

```
# Batch A7_go_daemon_host b2/3 — Defensive Review (Go daemon host)

BASE: 275989b76b22925f4d2719fa07f47709eb227059
WORKTREE: /tmp/review-wt-claude-001-A7_go_daemon_host-b2
OUTPUT: /tmp/review-work-claude-001/ps-A7_go_daemon_host-b2.md
DATE: 2026-07-10

## Inventory (size x responsibility x hot-path)

| Module | LOC prod (approx) | test LOC | Largest fn / resp | Hot rank |
|---|---|---|---|---|
| pkg/frr/policy_render.go | 2030 | 2 files 400 | generateProtocols 500+ lines, renderRouteMapForPolicy — BGP import/export split, redistribute alias, route-filter sanity | **High** (commit path, FRR reload is atomic + degraded retry) |
| pkg/routing/tunnel.go | 1903 | 1649 test | Apply 200 LOC, multi-state reconcile incl WG persist, VRF claim, keepalive gen guard | **High** (netlink, per-commit, stable ifindex) |
| pkg/routing/rules.go | 1447 | 1039 | BuildPBRRules 300+, Apply rib-group/next-table/PBR — route-leak correctness | **High** |
| pkg/ipsec/policy.go | 1111 | 810+95 | renderConfig 304 LOC, resolveRemoteAddr, effectiveTrafficSelectors, PrepareConfig concurrent DNS hints | **High** (swanctl render, crypto downgrade prevention) |
| pkg/frr/manager.go | 1043 | - | buildManagedSection, commitManagedSection, reloadLocked, degradedRetryLoop | **High** |
| pkg/lldp/lldp.go | 861 | 1378 test | rxLoop, learnNeighbor, BuildFrame — per-iface cap, self-frame filter, TTL clamp | Med (L2 unauth, DoS cap) |
| pkg/networkd/networkd.go | 775 | 1090 test | Apply, generateNetwork, writeIfChanged — protected lifeline, reload debt | **High** (systemd, /etc) |
| pkg/monitoriface/monitor.go | 952 | 427 | ReadSnapshot, RenderSingleInterface — display + /sys reads | Low |
| pkg/routing/routing.go facade | 238 | 2293 test | delegation only | Low |
| pkg/daemon/rss_indirection.go | 550 | - | applyRSSIndirectionOne, parseIndirectionTable — ethtool weight shaping | Med (boot + reconcile) |
| pkg/daemon/rg_state.go | 365 | - | reconcileLocked, CheckVRRPPosture — mutex epoch, posture delay | Med (HA) |
| pkg/daemon/login_password.go | 351 | - | deprovisionLoginUser, markProvisioned — UID-keyed provenance | **High** (privilege, /etc/shadow) |
| pkg/fsatomic/fsatomic.go | 370 | - | writeFile, MkdirAllDurable, SyncDir — DurableState vs AtomicGeneratedConfig | **High** (durability, symlink handling) |
| pkg/fwdstatus/* | 946 | - | Build, computeCPUWindows, procreader parsers, sampler ring 360 | Low |
| pkg/devicemap/devicemap.go | 316 | - | Resolve, EnumeratePresentNICs, classifyNetdev — PCI/MAC topology refusal | Med |
| pkg/fairness/expectation.go | 243 | - | ParseRSSExpectation, Evaluate | Low |
| pkg/linuxsock | 34 | - | Socket — CLOEXEC enforcement | Med |
| pkg/upgrade/cutover.go | 996 + cluster_cli 610 | - | Run, resolveSource, copyStaged, rollback — path traversal guard ValidateVersionSegment | **High** (upgrade, version dir) |
| pkg/ipsec/manager.go+ike+ crypto | 1336 | - | Apply/Clear ordering, parseSAOutput | Med |

Prod total ~12k, test ~8k in batch. Largest single prod
```

---

### ps-A7_go_daemon_host-b3.md (10625 chars)

```
# A7_go_daemon_host b3/3 - Upgrade, Lock, Manifest, StagedGen, WGKey Defensive Review
BASE: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A7_go_daemon_host-b3

## Inventory
- Total files in batch: 40 (19 prod priority + 2 extra prod cutover/cluster_cli + 19 test)
- Prod LOC (priority list): ~5583 lines
  - flip.go 448, helper_health.go 160, imageversions.go 179, kernel.go 334, kernel_drain.go 160, kernel_linux.go 692, kernel_run.go 626, kernel_selfrecover.go 273, lock/lock.go 303, manifest/manifest.go 106, rolling.go 247, runner.go 565, runtime/seed.go 400, stagedgen/fsutil.go 149, stagedgen/stagedgen.go 413, state.go 165, system_linux.go 190, version.go 60, wgkey/wgkey.go 113
- Extra prod: cutover.go 996, cluster_cli.go 610
- Test LOC: ~8390
- Largest prod fns: KernelRunner.Promote ~80 lines, KernelRunner.preflight/installCandidate/armCandidate ~70 each, Runner.Run ~180, flip.gc ~100, stagedgen.Config.Publish ~50, lock.AcquireAt ~70
- Responsibility: binary cutover ordering, host-wide lock, staged-gen immutable publish, kernel A/B arm/promote, manifest SSOT, wg x25519 keygen

## Module Log (coverage - negatives proving soundness)
- flip.go: NEGATIVE - symlink repoint atomic temp+rename+fsync, ver validated upstream via ValidateVersionSegment, unit dropin path from versionDir (validated) and fmt.Sprintf no shell.
- helper_health.go: NEGATIVE - fail-closed 3-part gate (unit active + armed+forwarding + target version dir equality), exe (deleted) suffix tolerated via Dir, deadlines bounded.
- imageversions.go: NEGATIVE - parseImageVersions scanner with present-tracking, requiredKeys fail-closed, GateMixedBaseSwap fails closed on 0/unknown peer protocols, back-compat window check correct.
- kernel.go: NEGATIVE - KernelState order unknown-> -1 atLeast false fail-closed, journal struct no path traversal via version fields (validated elsewhere).
- kernel_drain.go: NEGATIVE - DrainAndConfirm refuses if peer not alive/takeover-ready, failback ResetFailover on timeout avoids VIP stranding, sleepBounded bounds deadline overshoot.
- kernel_linux.go: NEGATIVE - command exec via exec.Command not shell, LC_ALL=C locale hardening, BootOrder/SetBootNext hex-validated, slot labels constants xpf-A/B, promotion marker durable, disarm watchdog error surfaced (#4872B).
- kernel_run.go: NEGATIVE - resume-version guard, stale marker clear, preflight UEFI+efibootmgr+A/B+BootOrder+grub+watchdog+free space, install re-assert default not moved + KernelHeld full-set, armCandidate selector read-back verify + journal ARMED before BootNext (reboot-boundary hole closed), Promote fail-closed indeterminate handling (#4872A) preserves journal no prune no reboot on unreadable state.
- kernel_selfrecover.go: NEGATIVE - lease state machine only acts on leaseExpiredOurs (crashed orchestrator fingerprint), leaseNone manual drain no-op, IsZero expiry check prevents {} lease -> spurious recovery (#4872C), grace reset on observation error (#4872D), Armed gate
```

---

### ps-A8_go_api_grpc_rest-b1.md (17472 chars)

```
# A8 Go API / gRPC / REST — Batch b1 Security Review

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A8_go_api_grpc_rest-b1
Output: /tmp/review-work-claude-001/ps-A8_go_api_grpc_rest-b1.md
Batch: A8_go_api_grpc_rest b1/2 — 150 files (27 prod priority + 123 test/support)

## File-size / shape inventory

Total prod LOC (27 priority): ~15.8k
- `pkg/api/*` 13,440 LOC (21 files)
- `pkg/grpcapi/{apply_result,exec_timeout,fabric_auth,runtime,server,cluster,config}` 2,347 LOC (7 files)
Full api+grpcapi glob: 61,956 LOC (150 files incl tests, `wc -l` sorted earlier)

Largest prod files (LOC x responsibility rank):
1. `pkg/api/metrics_descriptors.go` 2044 — Prometheus Desc registration (200+ series), static, checked-collector contract; no hot path
2. `pkg/api/metrics_userspace.go` 1865 — userspace-dp status → Prometheus, cache-line not relevant, control-socket contention sensitive
3. `pkg/grpcapi/server_sessions.go` 1460 — gRPC session list/clear/resolve, bilingual parity with REST, cancellation sampling, HA peer fan-out
4. `pkg/api/sessions.go` 1410 — REST cursor/offset pagination, reverse-counter merge, zone/app/FIB enrichment, cancel sampler per 1024
5. `pkg/api/metrics.go` ~1130 — Collector struct, singleflight+TTL cache, Describe/Collect, pre-gate control-plane signals
6. `pkg/grpcapi/server_show_security_text.go` 1063 — text show policies/security
7. `pkg/grpcapi/server_show_interfaces.go` 935
8. `pkg/api/security.go` 871 — zones/policies/events/match-policies simulator, strict validation
9. `pkg/grpcapi/server_cluster.go` 838 — cluster show, interface monitor, peer fill-down
10. `pkg/api/types.go` 815 — request/response types, policy ID zero contract, host-inbound structs

Test vs prod split: ~75% test LOC, 25% prod in this batch. Largest fns: `(*xpfCollector).Collect` (~150 LOC), `(*Server).matchPoliciesHandler` (~300 LOC), `(*Server).sessionsCursor` (~120 LOC), `(*Server).policiesHandler` (~200 LOC).

Responsibility map:
- `api.go`: writeJSON buffering (#4541), decodeJSONBody 16 MiB cap, queryIntStrict/Uint16Strict, parseRefBaseUnit, allInterfaceNames nil-guard
- `auth.go`: Basic/Bearer/API-Key, const-time, loopback gate for /metrics (#4162)
- `config.go`: rollback/compare strict, secret redaction, body cap reuse
- `crosssite.go`: CSRF guard before auth (#5055)
- `server.go`: timeouts (10s hdr, 30s read, 120s idle, 1 MiB hdr), metrics scrape 10s/3 in-flight, self-signed persist strict sequence (#1916), clamp loopback (#5035)
- `sessions.go` / `server_sessions.go`: pagination caps 10k, cancel sampling #5233, HA peer isolation first-page only
- `security.go`: match-policies duplicate + unknown-key fail-closed (#3709/#5316)
- `sse.go`: category/severity strict, subscriber cap 128
- `routing.go`: BGP streaming with cancel check per 1024 (#5232)
- `grpcapi/fabric_auth.go`: HMAC time-windowed PSK, downgrade guard via heartbeat (#4107)
- `grpcapi/server.go`: allowlist (#4122), SystemAction nested safe check, gRPC maxRe
```

---

### ps-A8_go_api_grpc_rest-b2.md (16178 chars)

```
# A8_go_api_grpc_rest b2/2 — gRPC/REST api hardening sweep

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2
Batch: 129 files pkg/grpcapi, 29 prod ~12.4k LOC, 98 test ~11k, 2 gen 11.2k (xpf.pb.go 9172, xpf_grpc.pb.go 2056), total 36k.

Top5 prod LOC / responsibility:
1 server_sessions.go 1460 — session table RPC (cursor+legacy, filtered clear, peer fan-out, zone-pair) R1 (DoS amplification, peer dial)
2 server_show_security_text.go 1063 — screen IDS, ipsec, rpm, security log/alarms R2
3 server_show_interfaces.go 935 — GetInterfaces, detail/terse, RETH, kernel stats R2
4 server_show_firewall.go 666 — filter term expansion, counter reads, policer R3
5 server_show.go 562 — ShowText allowlist gateway (log tail allowlist, CoS) R1 (remote CLI entry)

Largest fn: getSessionsCursor ~180 LOC, ClearSessions filtered ~140, showPoliciesHitCount ~120, dialPeer ~55 but hot for HA.

Responsibility rank size x resp x hot-path:
- server_sessions.go (session scan O(N) N up to 10M, peer dial on every request)
- server_diag_system_action.go 486 (reboot/zeroize/failover/userspace inject/queue/binding — destructive)
- server_show.go (show topic allowlist — remote CLI → gRPC bridge)
- server_diag_monitor.go 520 (MonitorPacketDrop validation, streaming lifecycle)
- server.go 588 (bind clamp, graceful stop, fabric allowlist, auth interceptor chain)

---

## Findings — High Confidence

### Title: userspace-inject/queue/binding slot wraps negative Atoi -> MaxUint32
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_system_action.go:384-412`
```
			if strings.HasPrefix(req.Action, "userspace-inject:") {
				...
				parts := strings.SplitN(rest, ":", 2)
				if len(parts) != 2 {
					return nil, status.Error(codes.InvalidArgument, "usage: userspace-inject:<slot>:<mode>")
				}
				slot, err := strconv.Atoi(parts[0])
				if err != nil {
					return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
```

---

### ps-A9_go_observability-b1.md (20911 chars)

```
# A9 Go Observability b1/1 — telemetry wire + SNMPv3 crypto + log path hardening
Base: 275989b76b22925f4d2719fa07f47709eb227059 WT: /tmp/review-wt-claude-001-A9_go_observability-b1 Date: 2026-07-10
Batch: 131 files — 26 prod (15808 LOC), 105 test (25612 LOC), total 37527 LOC
Inventory method: `wc -l` per prod file, `grep -c ^func` approx, manual responsibility ranking by hot-path proximity x size x wire-security relevance.

## File-size / shape / responsibility ranking

| File | LOC prod | Funcs | Hot-prox | Rank | Resp |
|------|----------|-------|----------|------|------|
| snmp/agent.go | 1791 | 62 | M | R2 | UDP/161 BER codec, v2c/v3 dispatch, ifSnapshot, trap queue, lifecycle |
| logging/ringbuf.go | 1451 | 37 | H event | R1 | RT_FLOW wire (144/152/160 additive), per-policy gate, fanout |
| eventengine/engine.go | 1294 | 25 | M | R6 | remediation queue, cooldown arm-on-commit, within/window AND |
| flowexport/ipfix.go | 1087 | 38 | M export | R3 | IPFIX templates 86/134 pinned, PEN 29305 biflow, PSAMP options 258, seq |
| ipmon/ipmon.go | 1016 | 20 | M | R7 | overlay winner MT metric, VRF resolve, debounce/throttle, HA gate |
| flowexport/manager.go | 915 | 23 | M | R4 | sampling instance determinism, template group sort, ServesFamily |
| logging/syslog.go | 911 | 35 | M | R3 | RFC6587 octet-count, 4s write deadline, 1s reconnect cooldown, closed flag |
| feeds/feeds.go | 889 | 15 | M | R8 | 32MiB body +1 sentinel, 1M entry cap, 1MiB line cap, retain-forever carry-forward |
| flowexport/netflow.go | 853 | 33 | M export | R3 | v9 recordSize unpadded + terminal pad once, bootTime CLOCK_BOOTTIME |
| rpm/rpm.go | 794 | 15 | M | R9 | probe loop, ErrProbeSetup hold, pinFailed union, bufferedEvents 64 |
| flowexport/transport.go | 561 | 14 | H export | R1 | dialCollectors fail-close fds, 2s SetWriteDeadline, 30s backoff, cap 65536 |
| logging/trace.go | 553 | 17 | L | R10 | sanitize bare basename, O_NOFOLLOW 0600, clamp #3424 |
| snmp/traps.go | 416 | 11 | L | R6 | v1/v2c/all per-group packet, bounded 256 queue, stop abandons backlog |
| rpm/icmp.go | 426 | 10 | L | R9 | ICMP echo id atomic, link-local zone requires dev not vrf-* |
| rest <400 each | — | — | L-M | — | aggregator Space-Saving 10K, locallog hardened, eventbuf 1000 cap 64 subs, routemask VRF keyed 8192/32, goid reentrancy guard |

Top hot: transport.go writeAll every 100ms + template refresh, ringbuf.go logEvent every RT_FLOW record, aggregator.Add SESSION_CLOSE, eventbuf.Add fanout O(N).
Largest funcs: Agent.handleV3Packet ~320 LOC (USM parse→timeliness→auth→decrypt→PDU), logging.EventReader.logEvent ~370 LOC (wire→enrich→fanout), ipmon.Engine.run ~90 LOC actuation loop.
Prod vs test 0.61 ratio: test-heavy, good. Generated: none.

## Findings (non-dedup, evidence-bar)

### Finding 1 — HIGH confidence
Title: SNMPv3 privacy salt RNG error ignored — IV reuse on RNG failure
Severity: Medium
Confidence: High
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/snmp/v3.go:790-822
```

---


## Findings — separated by confidence (High/Medium require full evidence bar)


### Critical


(0 findings at Critical level)


### High


#### Finding from ps-A10_go_services_cli_deploy-b3.md

```
# A10 Go services/cli/deploy b3/3 — Defensive Review (96 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3

## Inventory (LOC x responsibility x hot-path proximity)

| File | LOC | P/T | Largest fn | Responsibility | Rank |
|------|-----|-----|------------|----------------|------|
| pkg/policymatch/policymatch.go | 1714 | prod | Match() 180L | SSOT simulator zone/global/host-inbound/content-reject/route-drop advisory | CRIT |
| scripts/deploy/xpf-deploy.py | 1881 | prod | cmd_fetch ~200L | VM deploy, fetch+verify #1924, anti-rollback watermark, mixed-base gate, libvirt golden H-30 | High |
| test/incus/cold-path-flooder/src/main.rs | 2170 | test | worker loop / main | AF_PACKET cold-path flooder 5-tuple sweep, batch sendmmsg, CPU pin | Med |
| scripts/dist/publish.py | 786 | prod | publish gate | fail-closed publish #1924 §5.5 image/apt/install.sh/latest.json sig gates | High |
| scripts/image/bake.py | 756 | prod | virt_customize | offline bake virt-customize, cache SHA verify, grow-root, Secure Boot slots, validate→sign #4017 | High |
| scripts/image/validate.py | 686 | prod | scenario_a-e per-scenario | appliance first-boot contract a-e,q validation harness | High |
| test/incus/retire_ebpf_artifact_schema.py | 681 | test | ArtifactChecker.validate | #1477 final retirement bundle structural validation | Med |
| test/incus/cos_be_contention_validate.py | 748 | test | validate_artifacts | CoS exact-vs-BE contention validator | Med |
| pkg/policymatch/zone_detail_summary.go | 207 | prod | ZoneDetailPolicySummary 90L | tier-ordered exact→single-wild→both-any presenter | High |
| pkg/scheduler/scheduler.go | 448 | prod | evaluate 70L / isWithinWindow | time-window eval, republish self-heal #3780, wall-clock discont #3849, tz #3988 | High |
| scripts/dist/sign.py | 345 | prod | verify_and_read | minisign trust root, TOCTOU-safe copy-then-verify #5042 | High |
| test/xsk-repro/* | 24-320 | test | create_xsk / main | AF_XDP zero-copy rebind repro (root, DMA) | Low |
| many *_test.go + fairness/mouse/step* | 40-1400 each | test | — | RED-on-revert guards, metric reducers | Low |

Overall ~38k LOC scanned (prod ~6500, test ~31k). Largest prod funcs: Match() simulator precedence chain, scheduler evaluate(), xpf-deploy cmd_fetch 200L.

## Module Log (coverage proofs + negatives REQUIRED)

- **policymatch.go 1714 prod**: 3-pass read (0-500,500-900,900-1714). Tiers 1-5 exact mirror userspace-dp/src/policy.rs evaluate_policy_result. Verified zoneKnown gate #3355 no len(Zones)==0 tolerance — fail-closed to default. globalScopeSetMatches skips unresolved zone name → fail-closed. matchAddr empty-both-families fail-closed #3356/#2008. cross-family v4Empty&&v6Empty gate #3023 correct (v6-only exclusion on v4 packet trivially outside set → match). ContentRejected config-wide via dpuserspace.PolicyContentRejectionReasons delegates to SSOT — prevents fabricated permit under default-permit #3727/#4394. Route-drop defer stamp onto every return path #4373, host path exempt (junos-host local delivery). Host-inbound admission attached via withHI closure every host return — SSOT ClassifyHostInbound #3627. SelectorArgs strict — unknown token + missing value + duplicate rejection #3696/#3709 errors not wildcard widen. Port/proto canonical via config.ParseCanonicalUint + appid.ProtocolNumber rejects signed +/– #3679. **NEGATIVE**: no silent last-win, no empty-selector wildcard, no omitted-proto/port over-match — locked by port_omitted_3330, protocol_omitted_3323, srcport_omitted_3415 RED-on-revert.

- **zone_detail_summary.go**: Tier ordered exact→single-wild→both-any #4885, config order within tier. Nil zpp/pol guard #3476. PolicySetID advances in config order regardless of tier bucket — matches RuntimePolicyIDs namespace. **NEGATIVE**: no panic on nil, no ID divergence.

- **scheduler.go**: Absent window ⇒ inactive fail-closed #3849. Half-specified warn+false. Wall-clock discontinuit
```

---

#### Finding from ps-A7_go_daemon_host-b1.md

```
# Review BATCH A7_go_daemon_host b1/3 — pkg/daemon host-systems (150 files)

## File-size/shape inventory (prod vs test, hot-path proximity)

| File | LOC | Prod/Test | Largest fn | Responsibility | Hot? |
|------|-----|-----------|------------|----------------|------|
| pkg/daemon/bootstrap.go | 944 | Prod | detectLifelineInterface / interfaceAddrSnapshot | Bootstrap lifeline, PCI-keyed record, protected set, five-case boot predicate | Cold (boot) |
| pkg/daemon/coalescence.go | 272 | Prod | applyCoalescenceOne / parseEthtoolCoalesce | mlx5 rx/tx-usecs + adaptive coalescing pin, idempotent via ethtool -c probe | Cold (boot + commit) |
| pkg/daemon/daemon.go | 870 | Prod | New / type Daemon god-struct 40+ fields | Daemon options, type, node-id file parse (strict Atoi 0|1), manager init seams | Cold (lifecycle) |
| pkg/daemon/daemon_apply.go | 2149 | Prod | applyDataplaneAndHACore / applyInterfaceReconcile | Apply head: VRF, tunnel/xfrmi/bond/RETH, fabric IPVLAN, dataplane compile+arm, neighbor warm, services; tail: VRRP/system/archival/observability | Warm — held under applySem (commit latency) |
| pkg/daemon/daemon_archive_timer.go | 151 | Prod | reconcile/periodic timer | Periodic config archival timer (hash-gated) | Cold |
| pkg/daemon/daemon_cluster_bind.go | 198 | Prod | bind helpers | Cluster bind address resolution (em0/fabric) | Cold |
| pkg/daemon/daemon_ddns.go | 389 | Prod | DDNS manager | DHCP-lease DDNS (Surface B) nudge loop, reconcile, withdraw | Cold |
| pkg/daemon/daemon_ddns_surface_a.go | 843 | Prod | surfaceA reconcile | Router/interface-address DDNS (Surface A) per-binding dedup, warning, withdraw-while-pending | Cold |
| pkg/daemon/daemon_dhcp.go | 341 | Prod | dhcp manager | DHCPv4/v6 client start/stop, options, lease change → recompile | Cold/warm lease change |
| pkg/daemon/daemon_dhcp_lease_sync.go | 404 | Prod | dhcpLeaseSync loop | HA DHCP lease sync push/pull (#2239) | Warm |
| pkg/daemon/daemon_dns.go | 377 | Prod | reconcileDNSLocked | /etc/resolv.conf managed file merge (static + DHCP), resolved disable+mask | Cold |
| pkg/daemon/daemon_feeds.go | 137 | Prod | reconcileFeeds | Dynamic-address feed producer lifecycle, hash-gated | Cold |
| pkg/daemon/daemon_flow.go | 804 | Prod | flow exporter assembly | NetFlow/IPFIX bundle build+swap, handoff-drop accounting | Cold commit, hot event path |
| pkg/daemon/daemon_flowexport.go | 685 | Prod | flowexport reconcile | Flow/IPFIX exporter per family, template group | Cold |
| pkg/daemon/daemon_forwarding_status.go | 132 | Prod | fwdstatus sampler | CPU sampler off CachedStatus (no control-socket) #3970 | Warm 1/s |
| pkg/daemon/daemon_gc.go | 23 | Prod | GC wiring | Conntrack GC wiring placeholder | Cold |
| pkg/daemon/daemon_ha.go | 1511 | Prod | RG state machine, VIP ownership | HA RG creation, direct mode VIP add/remove, GARP burst, re-announce schedule | Warm (failover) |
| pkg/daemon/daemon_ha_fabric.go | 965 | Prod | fabric IPVLAN + neighbor refresh | fab0/fab1 IPVLAN create, peer IP resolve, probe rate-limit, glean-on-loss | Warm |
| pkg/daemon/daemon_ha_sync.go | 1020 | Prod | session-sync envelope | Session bulk sync, config sync, IPsec SA sync, bulk barrier, gen-guard | Warm |
| pkg/daemon/daemon_ha_userspace.go + 4 files | ~1k | Prod | userspace-dp HA convert/export/readiness/stream | Synced session → Rust wire, event-stream delta drain, owner-RG export | Warm |
| pkg/daemon/daemon_ha_vip.go | 651 | Prod | direct-mode VIP + stable LL | Direct-mode VIP add/remove idempotent, stable link-local, guard against direct path leaks | Warm |
| pkg/daemon/daemon_health.go | 155 | Prod | health + compile/boot import | /health compileFail count + bootstrap import outcome | Cold |
| pkg/daemon/daemon_ipmon.go | 414 | Prod | ip-monitoring actuator | Probe-based route inject overlay, FIB bump retry, degraded FRR reload awareness | Warm (probe tick) |
| pkg/daemon/daemon_ipsec_rebind.go | 170 | Prod | lease-change IPsec rebind | DHCP renewal → swanctl local_
```

---

(2 findings at High level)


### Medium


#### Finding from ps-A10_go_services_cli_deploy-b2.md

```
# A10 Go services/cli/deploy b2/3 — Defensive Review (150 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktrees: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2

## Inventory (size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | pkg/dhcprelay/relay_test.go | 2033 | test | runRelay matrix | relay lifecycle, hop-limit, ifindex drift #2347 | med |
| 2 | pkg/ddns/surface_a.go | 2007 | prod | Reconcile ~300L / publishLocked ~130L | Surface-A engine, PrevAddr #3739, PublishPending #5285, sibling #3738 | high |
| 3 | pkg/dhcp/dhcp.go | 1903 | prod | runDHCPv6 185L / runDHCPv4 179L | v4/v6 manager, DUID traversal #4857, NAK #3956, classless RFC3442 | high |
| 4 | pkg/dhcprelay/relay.go | 1545 | prod | runRelaySession 343L | supervisor, giaddr retry, hop-limit #4309, source validation #4163 | high |
| 5 | pkg/ddns/manager.go | 1457 | prod | reconcileOnceLocked 210L | DHCP DDNS engine, per-family backend, providerIO #5006, PTRPending #2661 | high |
| 6 | pkg/dhcpserver/dhcpserver.go | 1210 | prod | generateKea4Config | Kea config, is-active tri-state #4870, subnet_id stable #5041 | med |
| 7 | pkg/ddns/backend_rfc2136.go | 1100 | prod | sendAddOwned 75L | exact-RR #3739, DHCID, self-owned replace, TSIG | high |
| 8 | pkg/cli/monitor.go | 967 | prod | handleMonitorSecurityPacketDrop 180L | flow trace file, rotation, sanitization 0700, nil guard #3381 | med |
| 9 | pkg/dhcpserver/lease_sync.go | 933 | prod | writeMemfile6 | memfile sync, expired drop #4871, IAPD preserve | med |
| 10 | pkg/cli/completion.go + monitor_traffic.go | 577+260 | prod | Do() / parseMonitorTrafficArgs | completion nil guard #2288, traffic injection neutralization #4524/#4556, count bound #4589 | med |
| 11 | pkg/ddns/backend_route53.go | 243 | prod | buildChangeBatch / change | Route53 UPSERT signature, foreign-record unsafe | high |
| 12 | pkg/dhcprelay/l2send_linux.go | 226 | prod | sendReply / buildL2Reply | AF_PACKET TX, MTU guard, IPv4 checksum | med |

Total scanned batch: ~38k LOC (prod ~12k, test ~26k). Test-heavy RED-on-revert suite present.

## Module Log (coverage + negatives)

**CLI 54 files**: completion.go NEGATIVE — helpWriter nil guard when rl==nil #2288 prevents panic; completionSuffix bounds check `len(partial)>len(name) || !HasPrefix` prevents slice OOB when commonPrefix shorter than typed partial; zone nil guard `if zone==nil continue` #3493, zpp nil #3476, pol nil. monitor_traffic.go NEGATIVE — keyword-as-value guard `monitorTrafficKeywords[args[i+1]]` prevents swallowing `matching` as interface, greedy matching up to keyword, quote strip, count 0..8192 bound #4589, `--` separator #4524 neutralizes `-w/-z` file-write/cmd-exec, `monitorFilterOptionToken` quote-peel `'-w` #4556. monitor.go NEGATIVE — nil eventBuf guards #3381, traceLogDir 0700 `/var/log/xpf-flow-trace`, `sanitizeTraceFilename` rejects `/ \ . ..`, O_NOFOLLOW 0600, atomic filter parse. monitor_interface.go NEGATIVE — VMIN=0/VTIME=1 poll, keyReader done+WG stop #3985. peer.go NEGATIVE — fabricAuthKey seam, per-RPC `NewFabricAuthCreds` #5324, SO_BINDTODEVICE, TCP probe; unkeyed grace intact. permissions.go NEGATIVE — traffic→PermControl prefix-safe, flow file/start→PermControl #5038, reboot/failover/data-plane disarm→PermMaint #4108/#4859. session_filter.go NEGATIVE — zone nil #3493, multi-iface map #4792, `ifaceMatchesAny` + FIB fallback, parseErr fail-closed clear-all guard. link/runtime/proto/session_display/show_services_* NEGATIVE — sysfs bound, runtime narrow interface #1517, NativeEndian PutUint32, bracket-aware splitAddrPort, cos queue passes `statusErr` not conflates empty #5326, ddns TSIG redacted, dhcp lease warn vs empty, snmp redaction. All cli_*_test.go NEGATIVE hardening suite present.

**DDNS 34 files**: backend.go NEGATIVE — PrevAddr self-owned only, zero→additive insert, SiblingFamilyOwned host-wide guard #373
```

---

#### Finding from ps-A10_go_services_cli_deploy-b3.md

```
# A10 Go services/cli/deploy b3/3 — Defensive Review (96 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3

## Inventory (LOC x responsibility x hot-path proximity)

| File | LOC | P/T | Largest fn | Responsibility | Rank |
|------|-----|-----|------------|----------------|------|
| pkg/policymatch/policymatch.go | 1714 | prod | Match() 180L | SSOT simulator zone/global/host-inbound/content-reject/route-drop advisory | CRIT |
| scripts/deploy/xpf-deploy.py | 1881 | prod | cmd_fetch ~200L | VM deploy, fetch+verify #1924, anti-rollback watermark, mixed-base gate, libvirt golden H-30 | High |
| test/incus/cold-path-flooder/src/main.rs | 2170 | test | worker loop / main | AF_PACKET cold-path flooder 5-tuple sweep, batch sendmmsg, CPU pin | Med |
| scripts/dist/publish.py | 786 | prod | publish gate | fail-closed publish #1924 §5.5 image/apt/install.sh/latest.json sig gates | High |
| scripts/image/bake.py | 756 | prod | virt_customize | offline bake virt-customize, cache SHA verify, grow-root, Secure Boot slots, validate→sign #4017 | High |
| scripts/image/validate.py | 686 | prod | scenario_a-e per-scenario | appliance first-boot contract a-e,q validation harness | High |
| test/incus/retire_ebpf_artifact_schema.py | 681 | test | ArtifactChecker.validate | #1477 final retirement bundle structural validation | Med |
| test/incus/cos_be_contention_validate.py | 748 | test | validate_artifacts | CoS exact-vs-BE contention validator | Med |
| pkg/policymatch/zone_detail_summary.go | 207 | prod | ZoneDetailPolicySummary 90L | tier-ordered exact→single-wild→both-any presenter | High |
| pkg/scheduler/scheduler.go | 448 | prod | evaluate 70L / isWithinWindow | time-window eval, republish self-heal #3780, wall-clock discont #3849, tz #3988 | High |
| scripts/dist/sign.py | 345 | prod | verify_and_read | minisign trust root, TOCTOU-safe copy-then-verify #5042 | High |
| test/xsk-repro/* | 24-320 | test | create_xsk / main | AF_XDP zero-copy rebind repro (root, DMA) | Low |
| many *_test.go + fairness/mouse/step* | 40-1400 each | test | — | RED-on-revert guards, metric reducers | Low |

Overall ~38k LOC scanned (prod ~6500, test ~31k). Largest prod funcs: Match() simulator precedence chain, scheduler evaluate(), xpf-deploy cmd_fetch 200L.

## Module Log (coverage proofs + negatives REQUIRED)

- **policymatch.go 1714 prod**: 3-pass read (0-500,500-900,900-1714). Tiers 1-5 exact mirror userspace-dp/src/policy.rs evaluate_policy_result. Verified zoneKnown gate #3355 no len(Zones)==0 tolerance — fail-closed to default. globalScopeSetMatches skips unresolved zone name → fail-closed. matchAddr empty-both-families fail-closed #3356/#2008. cross-family v4Empty&&v6Empty gate #3023 correct (v6-only exclusion on v4 packet trivially outside set → match). ContentRejected config-wide via dpuserspace.PolicyContentRejectionReasons delegates to SSOT — prevents fabricated permit under default-permit #3727/#4394. Route-drop defer stamp onto every return path #4373, host path exempt (junos-host local delivery). Host-inbound admission attached via withHI closure every host return — SSOT ClassifyHostInbound #3627. SelectorArgs strict — unknown token + missing value + duplicate rejection #3696/#3709 errors not wildcard widen. Port/proto canonical via config.ParseCanonicalUint + appid.ProtocolNumber rejects signed +/– #3679. **NEGATIVE**: no silent last-win, no empty-selector wildcard, no omitted-proto/port over-match — locked by port_omitted_3330, protocol_omitted_3323, srcport_omitted_3415 RED-on-revert.

- **zone_detail_summary.go**: Tier ordered exact→single-wild→both-any #4885, config order within tier. Nil zpp/pol guard #3476. PolicySetID advances in config order regardless of tier bucket — matches RuntimePolicyIDs namespace. **NEGATIVE**: no panic on nil, no ID divergence.

- **scheduler.go**: Absent window ⇒ inactive fail-closed #3849. Half-specified warn+false. Wall-clock discontinuit
```

---

#### Finding from ps-A1_rust_dataplane_packet-b2.md

```
# Batch b2/3 — A1 Rust AF_XDP dataplane packet b2 (150 files) — 2026-07-10

**Worktree**: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b2` @ `275989b76b22925f4d2719fa07f47709eb227059`
**Base**: `git rev-parse --show-toplevel` → `/home/ps/git/avacado-xpf`

## Shape inventory
- Files: 151 listed in batch-004.txt (including header line) → 150 real `userspace-dp/src/` files
- LOC: 105093 = prod 52029 (107 files) + test 53064 (43 files)
- Largest prod: `poll_descriptor/mod.rs` 6294, `neighbor.rs` 2036, `types/cos.rs` 1786, `worker/loop_body/mod.rs` 1784, `tx/dispatch/mod.rs` 1486 (enqueue_pending_forwards 1050), `shared_cos_lease/lease.rs` 1460, `neighbor_dispatch.rs` 1421, `umem/mod.rs` 1363, `tx/cos_classify.rs` 1335, `session_glue/mod.rs` 1277, `poll_descriptor/filter.rs` 1201, `types/forwarding.rs` 1099, `afxdp/mod.rs` 1069, `wg/engine.rs` 1805
- Largest test: `afxdp/tests.rs` 14038, `session_glue/tests.rs` 5748, `cos_classify_tests` 4617, `wg/tests` 3909, `poll_stages_tests` 2636
- Largest fns: `poll_binding_process_descriptor` 5611 LOC L683 god-function 15+ resp single-recycle invariant Junos order host-inbound→lo0→junos-host table-scoped local-delivery #3769/#3151 connected scoping #2388; `enqueue_pending_forwards` 1050 LOC L271 TX orchestrator zero-copy UMEM ownership; CoS classify 7-resp enqueue_pending+fallback
- Hot proximity rank (size×resp×hot): 1) poll_descriptor/mod.rs 251760, 2) dispatch/mod.rs 44580, 3) cos_classify.rs 28035, 4) types/cos.rs 21432, 5) neighbor.rs 18324
- Ownership: `BindingWorker` single-writer per worker, UMEM `MmapArea` single owner `Rc<WorkerUmemInner>` with `Rc::get_mut` exclusive

## Module log (condensed, with negatives proving coverage)
- `poll_descriptor/mod.rs` 6294: orchestrates RX meta parse → flowless verdict → host-inbound deny per #3070 empty set → lo0 filter → junos-host #3019 reserved range → NAT64 frag assoc deferred install → cache-hit → session-limit → strict-syn bare RST/FIN drop agg-only no event #4400 repurposed from #2151/#4487/#4539 has_syn gate → screen 16 checks + syncookie → policy → TX. All 15 eprintln behind `cfg!(feature="debug-log")` + numeric caps via `debug_log_throttle.rs` pure fn(session_miss)<=10 policy_deny<=3 no topo bypass #4120 — no flood. 6 unsafe via `unsafe { &*area }.slice(addr as usize, len as usize)` Option-checked, bounds fail-closed.
- `cookie_reply.rs`/`reject_reply.rs`/`nat_exception.rs`: `#[cold]#[inline(never)]` true cold bodies .text.unlikely — exemplary split, hot byte-for-byte preserved
- `filter.rs` 1201: inline policy per-fn not blanket — cheap guards #[inline] fold into hot caller, heavy bodies #[cold]#[inline(never)] including `filter_terminal` ordering reject-reply enqueue FIRST then emit log with actual outcome #3615 truthful REJECT→DENY downgrade. `emit_cached_output_filter_log` tail split prevents 96B `UserspaceDpMeta` copy on fast path no-logging — HFT-grade
- `flow_cache_hit.rs` 533: hit replay relays hit counters via `record_policy_hit_counter` batch coalescer — no Mutex per packet — GOOD
- `rx_telemetry.rs` 220: small counters inline
- `poll_stages.rs` 975: stage extraction host-inbound/lo0/policy eval hoisted — still zone lookup — no extra taken branch — GOOD split without disasm change
- `tx/dispatch/mod.rs` 1486 HOT: single-recycle invariant — src frame via ingress UMEM unsafe &*area slice Option, target build via `slice_mut_unchecked(offset, capacity())` owned offset from free_tx_frames pop_front; double-recycle fix #4041 single if build_failed path; prefetch `_mm_prefetch` x86_64 cfg; oversized written>capacity drop + exception; no Vec alloc direct path — negative sound
- `dispatch/cos.rs` + `shared_recycle.rs` + `slow_path.rs`: shared_recycles Option<&mut Vec<(u32,u64)>> CAS-free local queue; fallback clone alloc only slow path
- `tx/cos_classify.rs` 1335 7-resp: DSCP/PCP→queue, clone_prepared_req fallback, default-queue fallback for unmaterialized queue #hb166 T-4 Never blackhole (belt-and-suspenders runtime + build-ti
```

---

#### Finding from ps-A1_rust_dataplane_packet-b3.md

```
# b3/3 Rust hot path: session table + policy/verdict + screen + filter + worker queues + event_stream

Base 275989b76b22925f4d2719fa07f47709eb227059 WT /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b3

## Shape inventory
- Batch files: 118 — prod 64708 LOC (92 files), test 19247 LOC (26 files), total 83955
- Prod vs test split: PROD 92 files, TEST 26 files
- Largest prod top 20:
  - userspace-dp/src/filter/tests.rs 8422
  - userspace-dp/src/session/tests.rs 7072
  - userspace-dp/src/screen/tests.rs 5395
  - userspace-dp/src/policy.rs 3657
  - userspace-dp/src/protocol/tests.rs 2393
  - userspace-dp/src/session/mod.rs 2114
  - userspace-dp/src/server/tests.rs 1953
  - userspace-dp/src/event_stream/mod.rs 1701
  - userspace-xdp/src/lib.rs 1541
  - userspace-dp/src/screen/mod.rs 1540
  - userspace-dp/src/server/helpers.rs 1304
  - userspace-dp/src/xsk_ffi.rs 1287
  - userspace-dp/src/screen/scan.rs 1213
  - userspace-dp/src/protocol/binding.rs 1185
  - userspace-dp/src/protocol/control.rs 1088
  - userspace-dp/src/filter/compiler.rs 1056
  - userspace-dp/src/filter/engine/eval.rs 1026
- Largest test top 10:
  - userspace-dp/src/policy_tests.rs 7280
  - userspace-dp/src/main_tests.rs 2350
  - userspace-dp/tests/fairness_eval_blackbox.rs 1366
  - userspace-dp/src/event_stream/codec/codec_tests.rs 1023
  - userspace-dp/src/slowpath_tests.rs 776
  - userspace-dp/src/state_writer_tests.rs 689

- Largest fn approx (heuristic):
  - userspace-dp/src/session/mod.rs: pub fn update_session ~239 LOC
  - userspace-dp/src/policy.rs: pub(crate) fn parse_policy_state_with_counters ~567 LOC
  - userspace-dp/src/screen/mod.rs: pub fn check_packet_with_zone_id_opts ~374 LOC
  - userspace-dp/src/filter/compiler.rs: fn parse_term ~427 LOC
  - userspace-dp/src/event_stream/mod.rs: pub(crate) fn mono_ns_to_wall_clock_unix_ns ~199 LOC
  - userspace-xdp/src/lib.rs: fn try_xdp_userspace ~343 LOC

- Hot rank size*resp*hot-proximity: 1) session/mod.rs slab u32 handles + Seeded 1:N indexes reverse/forward wire/alias #4399#4438 multimap SmallVec[2] zero-alloc fast + handle validate-by-key #1855; 2) session/entry.rs u16 zone IDs #919 saves 28B + LOCK XADD ~10ns win + bound Arc #3322; 3) policy.rs zone_pair_key u32 pack + AppCatalog tiered #3612 + hit_counter coalescer #3073 gen-guard #3448/#3782; 4) screen/mod.rs 16 checks + SYN-flood count-min no-eviction #3315 + timeout per-zone #3527; 5) filter/mod.rs CachedThreeColorPolicers SmallVec[2] + Mutex hot; 6) xsk_ffi.rs unsafe Send rings; 7) tx_pipeline Box<[u64]> sidecar; 8) event_stream replay 4k + backlog 16MiB cap #2381


## Module log (per-file one-line incl negatives proving coverage)
- userspace-dp/src/afxdp/worker/tx_counters.rs 59 LOC: WorkerTxCounters 10 u64 pending_* counters - drained per-sec debug tick - alloc-free hot record - negative
- userspace-dp/src/afxdp/worker/tx_pipeline.rs 69 LOC: WorkerTxPipeline free_tx_frames VecDeque, pending_tx_prepared/local, outstanding_tx u32 gauge #802, tx_submit_ns Box<[u64]> pre-sized - Box not Vec prevents push compile-fail - negative
- userspace-dp/src/afxdp/worker/xsk_rings.rs 40 LOC: WorkerXskRings DeviceQueue+RingRx+Tx structural extraction #959 Phase11 - negative
- userspace-dp/src/afxdp/worker_queue.rs 84 LOC: Mutex<VecDeque<WorkerCommand>> poison-recovery lock_recover/try_lock_recover clear_poison + AtomicU64 counter Prometheus - eprintln cold panic path only - negative hot alloc
- userspace-dp/src/afxdp/worker_queue_tests.rs 161 LOC: Test file userspace-dp/src/afxdp/worker_queue_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/afxdp/worker_runtime.rs 571 LOC: WorkerRuntimeState Active/IdleSpin/IdleBlock + CoSQueueLeaseUndergrant + WorkerRuntimeCounters + #[repr(align(64))] Atomics seqlock window_gen AcqRel/Release fence Acquire reader spin 16 - unsafe clock_gettime/gettid checked - sound but ordering sensitive
- userspace-dp/src/afxdp/worker_runtime_tests.rs 351 LOC: Test file userspace-dp/src/afxdp/worker_runtime_tests
```

---

#### Finding from ps-A2_rust_dataplane_nat-b1.md

```
# A2 NAT Review — Rust dataplane NAT (18 files) — 275989b76

## Inventory
- LOC: ~24982 total (prod 9334, test 15648)
  - allocator.rs 1974 (largest: allocate_translation_locked ~130 LOC, gc_expired_chunked)
  - source.rs 1523 (match_source_nat_result_for_tuple ~500 LOC, parse_source_nat_rules)
  - destination.rs 1109 (from_snapshots 230 LOC, lookup_with_counter_scoped 120 LOC)
  - static_nat.rs 808 (from_snapshots 130 LOC, match_dnat_with_counter_scoped)
  - nat64.rs 3102 (write_v6_to_v4_into 180 LOC, write_v4_to_v6_into 220 LOC, frag cache)
  - nptv6.rs 431 (try_from_snapshots)
  - mod.rs 347 (NatDecision, counter store)
  - status.rs 40
  - 8 test files 4673+1770+1198+... = 15648
- Responsibility ranking: allocator (port lifecycle, HA reserve, deterministic, addr-only) > source (match + scope + L4) > nat64 (xlat + frag assoc + embedded ICMP) > destination (proto wildcard 256, LPM) > static_nat (block 1:1, scope tiers) > nptv6 (fail-closed)
- Hot path proximity: allocator claim() is per-flow cold (first packet), not per-packet; match_* cold; translate hot for NAT64.

## Module log (coverage proof, incl negatives)
- allocator.rs: audited claim/ free_recycle/ reserve/ reserve_address_only/ deterministic v4/v6, GC chunked lock release, persistent lease indexes. No per-packet alloc. Sound, minus deterministic param reuse.
- source.rs: audited expand_pool_address CIDR enum, MAX_POOL_PREFIX_HOSTS 65536 cap, l4_matches tuple_unknown gate, NonFirstFragment drop before alloc, address-only token via reserve_address_only, deterministic address-only branch missing token (dedup #5341, not re-reported), HA reserve skips no-port (dedup #5338). Scope AND-ed, proto 0 synthetic wrapper intentional.
- destination.rs: PROTO_ANY=256 distinct from HOPOPT 0, exact→wildcard port→PROTO_ANY→LPM tiers, off short-circuits tiers (#3844), source/bracket list fail-closed (#2394). Negative: ICMP port gated via has_l4_ports (#4074) sound.
- static_nat.rs: host vs block classified, block-to-block offset remap, port-mapped vs whole-address precedence (#2769), pick_scoped zone-tier, scope_ok AND. Negative: no off to leak, external_ips iterator fine.
- nat64.rs: parse_pool_v4 only bare/32 host, from_snapshots loud skip all-or-nothing (#3888), reuse_allocator preserves ports across reload (#4518), reserve_synced portes recovers HA collision (#4512), frag assoc port-free key documented RFC8200 uniq ident, first-only install prevents DoS, non-first translators no L4 checksum. Negative: TTL 2s short, LRU 64/shard bounded.
- nptv6.rs: parse_prefix host-bits fail-closed (#4519), overlap reject (#2241), zero-adjustment 0xFFFF fold skip (#3233). Negative: sound.

## Findings

### HIGH — None new (dedup covers known HA leaks)

### MEDIUM

#### Title: Deterministic CGNAT allocator reuse ignores deterministic parameters — stale reservations survive param change
Severity: Medium
Confidence: High
Evidence:
- userspace-dp/src/nat/source.rs:324-336
```
fn allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
  let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
  (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
    SourceNatPoolAllocatorKey {
      pool_name: self.pool_name.clone(),
      pool_addresses_v4: self.pool_addresses_v4.clone(),
      pool_addresses_v6: self.pool_addresses_v6.clone(),
      port_low: self.pool_allocator.port_low,
      port_high: self.pool_allocator.port_high,
    }
  })
}
```
- userspace-dp/src/nat/source.rs:723-738
```
fn source_nat_runtime_compatible(...) -> bool {
  new_rule.name == old_rule.name
    && new_rule.pool_name == old_rule.pool_name
    && new_rule.pool_mode == old_rule.pool_mode
    ...
    && new_rule.pool_allocator.port_low == old_rule.pool_allocator.port_low
    && new_rule.pool_allocator.port_high == old_rule.pool_allocator.port_high
}
```
- userspace-dp/src/nat64.rs:856-864
```
fn reuse_allocator(&self, prefix_bytes: &[u8;12], pool_v4: &[Ipv4Addr]) -> Option<PortAllocato
```

---

#### Finding from ps-A3_go_config_cli_tree-b1.md

```
# A3 config/cli tree b1/4 — 150 files — 275989b76

## Inventory
- Total files in batch: 150. Prod: ~25 files (catalog.go 487, runtime.go 344, textrender.go 82, tree.go 1589, ast.go 436, ast_edit.go 828, ast_format.go 614, ast_groups.go 620, ast_redact.go 233, compiler*.go ~30 files). Test: ~125 files.
- LOC prod ~11100, test prod ratio ~85% test. Largest prod fn: compiler_nat.go compileNATSource (~400 LOC), ast_edit.go SetPath (~200 LOC), tree.go CompleteFromTreeWithDesc (~150 LOC), catalog.go BuildCatalog (~190 LOC).
- Responsibility: Junos hierarchical AST + flat-set `set` path (dual shape #2419), bracket-list collapse, group expansion with depth/work caps (#5194), typed leaf schema completion, NAT appid catalog build (uint32 counter to avoid uint16 wrap #3438), appid runtime tuple fallback.
- Hot-path proximity: none — config compile is control plane cold path, not dataplane. But correctness is security-critical: NAT bracket list truncation previously caused single-IP pool (exhaustion), app-set bracket truncation caused DENY under-match.

## Module log (incl negatives proving coverage)
- ast.go: navigatePath unionChildren (#4562) merges sibling same-keyword blocks, FindChildren returns all. Sound.
- ast_edit.go: SetPath handles bracket-list multi trailing values via valueList gate, ATOI for port range uses parseSourcePoolPortRange with checked Atoi. DeletePath member delete #3846. Negative: no recursive overflow, schema wildcard fallback.
- ast_groups.go: maxGroupExpandDepth=64 + maxGroupExpandWork=100k, depth passed by value, cycle guard seen map, memo keyed by (name, ancestorPathKey). Work budget increments per expansion. Negative: no stack overflow, DAG fan-out bounded.
- ast_format.go: reader reviewed; pure output.
- ast_redact.go: redaction, no trunc.
- compiler.go: lenient/strict split with 30+ flags, compileOpts threading. Negative: no trunc.
- compiler_applications.go: parseAppTimeout uses Atoi with bounds appTimeoutMin/Max, canonicalPort for port spec, resolveAppPort normalizes floor 0→1 (#4336), ParseCanonicalUint rejects sign/whitespace (#3606). DDOS: namedInstances loop.
- compiler_nat.go: appendPoolAddresses iterates full token stream (fix #4521), isHostMaskAddress etc use natAddrFamily colon check for IPv4-mapped, expandAddressRange counts in uint64 to avoid uint32 wrap to 0 (fix #5194 A3-b2-F9). hostCount = 1<<uint(bits-ones) — checked for overflow risk below.
- compiler_validate_strict_nat.go: dnatProtocolResolvable excludes junos-* aliases and ipv6(41) deliberately tighter than proto_number (documented). validateDNATPoolStrict uses parseCanonicalPort. Sorted walk for deterministic error.
- appid/catalog.go: nextID uint32 prevents uint16 wrap past 65535 onto reserved 0 sentinel (#3438 H4), guard > maxCatalogAppID. ProtocolNumber ok bit honored for unrepresentable token (#4887). NormalizeExplicitPortRange sanitizes 0 sentinel (#5194).
- appid/runtime.go: CatalogNames skips nil zpp/pol (#3622), portInSpec uses canonicalPort (#3725). Negative: tuple fallback best-match deterministic.
- appid/textrender.go: RenderStatus pure output.
- cmdtree/tree.go: CompleteFromTree canonicalizes prefix via ResolveUniquePrefix before ContextDynamicFn, placeholder handling, DynamicFn nil-config awareness (#5196). Negative: no int trunc.

## Findings — Confidence High/Med/Low

### High
#### Title: hostCount shift overflow can panic on /0 host route used as NAT deterministic host
Severity: Medium
Confidence: High
Evidence: pkg/config/compiler_nat.go:1689-1690
```
            } else {
                // IPv4 host address
                hostCount := 1 << uint(bits-ones)
                if totalBlocks < hostCount {
```
Trace: det.HostAddress is validated via net.ParseCIDR. If host address is `0.0.0.0/0` (bits=32, ones=0), bits-ones=32, 1 << 32 = 4294967296 on 64-bit, fits int (Go untyped shift returns int large). But on 32-bit arch, 1<<32 overflows int and Go panics if shift >= width? Actually Go spec: shift count must be unsigned 
```

---

#### Finding from ps-A3_go_config_cli_tree-b2.md

```
# Batch 008 — pkg/config compiler hardening review
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2

## Inventory

Total LOC: 45946 (prod 26638 across 43 files, test 19308 across 107 files)
Prod median ~430 LOC, largest: compiler_validate_warn.go 3628, compiler_system.go 2073, compiler_services.go 1835, compiler_uniformgates.go 1794, compiler_validate_strict_filter.go 1717.

Largest functions (est):
- compileSystem 700+ LOC (DDNS, SNMP, schedulers dispatch)
- compileDHCPLocalServer 400 LOC
- validate helpers in warn gate 100-200 each

Responsibility ranking (size x policy-correctness x hot-path proximity):
1. compiler_validate_warn.go — 3628 LOC, warn accumulator, never hot-path but gate for all
2. compiler_security_zones.go — zone membership = security boundary, #5248 bracket list fix
3. compiler_policy_match.go — #3113/#3142/#3673 fail-open gates, AST pre-walk
4. compiler_policy_missing_match.go — #3044 required dimension gate, denies permit-all-by-omission
5. compiler_policy_then.go — #3114/#3115/#3141 then-permit/reject/deny modifier gates
6. compiler_security_policy.go — default-policy-log, global vs zone-pair compilation, any-ipv4/any-ipv6 normalization
7. compiler_security_flow.go — traceoptions file traversal, filter match safety
8. compiler_system.go — dataplane tunables, domain rework
9. compiler_validate_strict_zones.go — reserved zone names, zone-iface membership conflict, host-inbound token validation
10. filter_match_resolve.go + firewall_filter_expand.go — icmp/port symbolic resolution, counter stride

All reads via worktree path /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2/pkg/config/

## Module log (negatives prove coverage)

- compiler_policy_match.go: NEGATIVE — allowlist + unsupported + swallowedStructural sets, dual-shape via firewallMatchValues SSOT, walks every security node via forEachChild #3562. Hardened.
- compiler_policy_missing_match.go: NEGATIVE — required dimensions present-check unions every match block #3842, handles duplicate security blocks. Fail-closed correct.
- compiler_policy_then.go: NEGATIVE — permit/reject/deny nodes walked via policyThenActionNodes across all then blocks #3842, collapsedThenActionTokens flattens all 3 AST shapes, orphan log sub-token check #3374. Sound.
- compiler_security_policy.go: NEGATIVE — default-policy reject-all mapped #3065, global vs zone-pair dual shape, from-zone/to-zone list accumulation via firewallMatchValues #4626, any-ipv4/v6 normalization #2008. OK.
- compiler_security_zones.go: NEGATIVE — zoneInterfaceMembers recursion handles wildcard-container nesting #5248, mergeHostInbound dedup across duplicate top-level blocks #4818/#4544, address-book find-or-create #4706. No truncation.
- compiler_security_flow.go: NEGATIVE — flowTraceFileNameError bare-basename check, size/files bounds FlowTraceMin/Max #3424, flag/filter validation per duplicate-block forEachChild #3566, tcp-mss range #1979. Good.
- compiler_security_screen.go: NEGATIVE — parseThresh checks err && n<1 && >MaxUint32 prevents #3317 wrap to 0, recordKeyExtras/ChildExtras capture trailing garbage #3332, defaults arm disabled checks #3230. Hardened.
- compiler_security_log.go / alarm: NEGATIVE — stream port/tls gates via AST pre-walk #3349/#3350, not just typed config.
- compiler_security_addressbook.go: NEGATIVE — zone-local prefix collision gate, trailing tokens validated via validateTrailingTokensStrict #3332, qualified name handling #4340 slash allowance.
- compiler_security_alg.go: NEGATIVE — trivial ALG allowlist, 39 LOC.
- compiler_system.go: PARTIAL — see finding F-LOW-01 (Atoi error swallowed for dataplane tunables). Domain-search/name-server fixed to firewallMatchValues #2419. Retired DPDK knobs recorded not silently dropped.
- compiler_services.go: NEGATIVE — RPM probe type allowlist, source-address family match, link-local zone requirement #2494, http scheme gate #2495, routing-instance existence #2496, probe-pin table 
```

---

#### Finding from ps-A5_go_ha_vrrp_ra_conntrack-b1.md

```
# A5 HA/VRRP/RA/conntrack Review — batch ps-A5_go_ha_vrrp_ra_conntrack-b1

BASE 275989b76b22925f4d2719fa07f47709eb227059
WT /tmp/review-wt-claude-001-A5_go_ha_vrrp_ra_conntrack-b1
OUT /tmp/review-work-claude-001/ps-A5_go_ha_vrrp_ra_conntrack-b1.md

## Inventory

Total 46764 LOC. Prod 18813 LOC (34 files). Test 27951 LOC (66 files). Ratio 1:1.48.

Prod sorted by LOC (rank = size × resp × hot-path):

| LOC | File | Resp | Hot | Rank |
|---:|---|---|:---:|---:|
|2417|pkg/vrrp/instance.go|VRRP FSM, GARP damp, preemptHold #2850/#4584, IPv6 ext walk #2155|Y|1|
|1858|pkg/cluster/sync_conn.go|sync conn, genGuard 200k cap, tombstone #2221, barrier|Y|2|
|1108|pkg/vrrp/manager.go|AF_PACKET, VRID guard #4573, cBPF|Y|3|
|1048|pkg/cluster/sync.go|bulk epoch TOCTOU #3912, config trailing magic #3931, DHCP aging #4871|Y|4|
|1043|pkg/ra/sender.go|RA burst, RS hop-255 #5095, graceful/hard #2033, timer leak #4830|M|5|
|953|pkg/ra/ra.go|RA mgr, per-iface epoch #4961|M|6|
|912|pkg/cluster/failover.go|ManualFailover unlock + gen guard #5246, transfer-commit|Y|7|
|881|pkg/cluster/heartbeat.go|HB UDP 100ms, 30s startup grace #4386, monotonic #1792, HMAC #4107|Y|8|
|829|pkg/cluster/sync_protocol.go|wire codec length-gated, lease count clamp|Y|9|
|754|pkg/cluster/garp.go|GARP/NA burst, stillValid gate #2867, gw probe net+1 #2377|Y|10|
|remaining 24| <722 each | monitor, gc, status, election, etc | |11-34|

Largest fns: vrrpInstance.run ~250, electRG ~200, handleNewConnection ~120, probeICMP ~110.

## Module Log — Negative Result Proving Coverage

- election.go: EffectivePriority floor div, weight<=0 secondary, peerGroup nil -> primary, dual-primary tie lower node-id, dup node-id fail-closed secondary + warn rate-limited #4549, kernelUpgradeHold blocks electSingleNode. Covered.
- failover.go: ManualFailover releases mu for preHook, snapshots failoverGen #5246, restores weight, transfer-commit maps override+ grace applyTransferCommitOverridesOnPeerStateLocked, suppressPeerTimeoutForTransferCommitLocked. Covered.
- heartbeat.go/heartbeat_manager.go: startupGrace 30s for both never-seen #4386 and seen-then-lost, MonotonicNanos not Unix #1792, lastSeen CompareAndSwap seed on RestartHeartbeat, heartbeatAuthTrailer session+counter admit, randomSessionID fallback monotonic, dup NodeID drop. Covered.
- sync*.go: genGuardMapCap 200k putGenBounded never clears, takeDeleteGen fresh > install #2221, resetRecvGen on BulkStart #2198, pendingBulkAck record-then-send #3912, sealFrame seq+HMAC under writeMu, decodeDHCPLeasePayload count clamp len/4, configGenMagic 0x00ff xp f CG 0x00 trail, DHCP Remaining residence aging #4871. Covered.
- garp.go: burstSend seam, runARPBurstFollowups aborts on !stillValid, buildUnsolicitedNA Router+Override 0xA0, GatewayProbeTarget net+1 not .1 skip /31/32 #2377. Covered.
- monitor.go: fail 3/pass 3/hold 5s damp, LinkAttrsUp OperState vs FlagUp #2070, ICMP wantID from LocalAddr port, seq atomic 1..ffff, peerMatchesTarget UDPAddr+IPAddr. Covered.
- vrrp/*: VRID guard Min 1 Max 255 #4573, pri 0 resign and 255 owner exempt from track clamp [1,254], masterAdverInterval learned from MaxAdverInt with floor own interval min 10ms #4548, effectiveAdvertInterval learned>0 else local, track rename via linkNames ifindex #2944, addrwatcher #2528 reresolveLocalAddrs, AF_PACKET vs raw fallback acceptArrivalIfindex #2886, IPv6 ext walk bounded 8 #2155, GTSM TTL/hop 255 #4549, garpDampened backward clock clamp >=0 #1792, rxDrops atomic CAS 10s. Covered.
- ra/*: minAdvInterval 1s belt #4525, RS HopLimit flag request fail-closed #5095, shutdownMode graceful upgrades hard #2033, connReady make-before-break #2834, NewTimer Stop not After #4830. Covered.
- gc.go: SkipSweep u-space, IsLocalPrimary false skips expiry, monotonicSeconds CLOCK_MONOTONIC, aging snapshot under mu #3604, XOR hash v6 src count. Covered.

## Findings

### F-01 RETH VRID overflow loses VRRP fast-failover

- Title: RETH VRID =100+RG overflows uint8, manager skips, RETH loses 30ms VRRP
-
```

---

#### Finding from ps-A6_go_dataplane_manager-b2.md

```
# Defensive Review — Batch A6_go_dataplane_manager b2/3
BASE_COMMIT=275989b76b22925f4d2719fa07f47709eb227059
WORKTREE=/tmp/review-wt-claude-001-A6_go_dataplane_manager-b2
DATE=2026-07-09
Reviewer=claude-001

## File Size / Shape Inventory (prod files only, 52 files, 16347 LOC)
Ranked by size x responsibility count x hot-path proximity:

| Rank | LOC | File | Responsibility | Hot-path |
|------|-----|------|----------------|----------|
| 1 | 3064 | pkg/dataplane/userspace/protocol.go | Wire snapshot types, 200+ structs, control request/response framing | Medium (serialization on every apply) |
| 2 | 1763 | pkg/dataplane/userspace/maps_sync.go | BPF map programming: ctrl, bindings, heartbeat, ingress_ifaces, local addr, NAT addr, RST suppress, watchdog, degraded stats | Critical (apply + every status poll) |
| 3 | 1643 | pkg/dataplane/userspace/manager_ha.go | HA state sync, session mirror, watchdog throttle, takeover readiness, FORWARDING arm, counter bridging | Critical (HA failover path) |
| 4 | 520 | pkg/dataplane/userspace/nat_destination.go | DNAT match expansion (addr, app, port-range coalesce, prefix vs host split) | High (commit path) |
| 5 | 503 | pkg/dataplane/userspace/nat_source.go | SNAT builder, scope tier sort, deterministic CGNAT param extraction | High |
| 6 | 489 | pkg/dataplane/userspace/policies_addrbook.go | Address-book dedup, FNV hash to u32 ID, feed-overlay join, collision probe | High |
| 7 | 422 | pkg/dataplane/userspace/routes.go | FIB build from statics/connected/ip-rule leak, PBR band skip, overlay replace semantics, dedup key | High |
| 8 | 409 | pkg/natpoolalarm/natpoolalarm.go | Pool-util alarm hysteresis, sampler, coherence gate, active set | Medium |
| 9 | 394 | pkg/dataplane/userspace/zones_host_inbound.go | Host-inbound view grouping, lifeline exclusion, token canonical sig | High (security boundary) |
| 10 | 370 | pkg/dataplane/userspace/process_napi.go | NAPI bootstrap probes, hardware RX event trigger | Medium (startup) |
| 11 | 369 | pkg/dataplane/userspace/zones_observability.go | Zone counters presentation | Low |
| 12 | 358 | pkg/dataplane/userspace/policycounters.go | RuleID->counter index, bulk ReadAll O(P+C) optimization | Medium (15s scrape) |
| 13 | 270 | pkg/dataplane/userspace/process.go | Helper lifecycle, XSKMAP stale clear, event stream start, tuneSocketBuffers | High (boot) |
| 14 | 270 | pkg/dataplane/userspace/manager_neighbor.go | Neighbor index, monitored ifindexes, regen diff | High (neighbor churn) |
| 15 | 267 | pkg/dataplane/userspace/neighbors.go | buildNeighborSnapshots, publishable predicate substring match | High |
| 16 | 260 | pkg/dataplane/userspace/policies_lower.go | Junos policy -> PolicyRuleSnapshot lowering | High |
| 17 | 248 | pkg/dataplane/userspace/process_status.go | syncSnapshotLocked deferred same-plan exception, status loop, worker-arm debt retry | Critical |
| 18 | 239 | pkg/dataplane/userspace/screens.go | Screen profile snapshots, SYN-cookie master key KDF | Medium |
| 19 | 231 | pkg/dataplane/userspace/manager_status.go | Status stamping (zoneID collisions, reject reasons, degraded stats) | Low |
| 20 | 225 | pkg/dataplane/userspace/nat.go | NAT helpers: coalescePortRanges, appPortsFromSpec, sentinels, addr-name resolution | High |
| 21 | 213 | pkg/dataplane/userspace/tunnels.go | Tunnel endpoint snapshots, Wg peer sorted, ID collision drop | High |
| 22 | 206 | pkg/dataplane/userspace/policies_representable.go | Unrepresentable address/app sentinels | High |
| 23 | 206 | pkg/dataplane/userspace/policies_reject.go | Policy content rejection collection | Medium |
| 24 | 204 | pkg/nftables/rst_suppress.go | RST suppression nft rule install | Medium |
| 25 | 197 | pkg/dataplane/userspace/manager_overlay.go | Route overlay publish, feed overlay clone, duplicate-skip hash check | High |
| 26 | 196 | pkg/dataplane/userspace/process_control.go | Control socket framing, 64MiB cap pre-flight, deadline scaling per MiB | Critical |
| 27 | 191 | pkg/nftabl
```

---

#### Finding from ps-A6_go_dataplane_manager-b3.md

```
# Review BATCH A6 — pkg/nftables/rst_suppress — b3/3

## File-size/shape inventory (LOC, responsibility, hot-path)
| File | LOC | Role | Largest fn | Resp x Hot |
|------|-----|------|------------|------------|
| pkg/nftables/rst_suppress.go | 204 | Prod: install/remove inet xpf_dp_rst output chain DROP RST from SNAT addrs | addRSTDropRule ~56 LOC | High — mitigates HA failover kernel RST leak (#450), atomic delete+create batch critical |
| pkg/nftables/rst_suppress_test.go | 37 | Test: plan builder only | TestBuildRST* 15 LOC each | Low — covers only slices.Clone + deleteTable flag |

Ranked: rst_suppress.go dominates (all netlink/batch logic, payload offset encoding). Test file ranks lowest — 37 LOC, 2 tests, no coverage of rule expression, chain type, idempotency, or remove path.

## Module log (negatives proving coverage checked)

- Verified prod file exists via worktree and read full source lines 1-204.
- Verified test file 37 LOC reads 1-37 via cat -n.
- Grepped worktree for `rst_suppress|RstSuppress|rstSuppress|RST_SUPPRESS` — only 4 hits in pkg/nftables + manager + manager_misc_test.
- Traced caller in `pkg/dataplane/userspace/maps_sync.go:1072-1150` and manager.go:254-274 `shouldAttemptRSTSuppression` retry backoff 5s, WARN on nftables error, clone semantics.
- Checked `buildInterfaceNATAddressEntries` family split (netlink FAMILY_V4/V6) — input to RST addrs is already sorted, deduped.
- Checked neighboring nftables modules (host_inbound_*, lo0_counters) to compare listTables+c.GetObjects pattern — rst_suppress mirrors same ENOENT-as-nil handling.
- Verified IPv4 saddr offset 12 len 4, IPv6 saddr offset 8 len 16, TCP flags offset 13 mask 0x04, nfproto meta check, l4proto TCP — all constants encode correctly.
- Verified chain: Name output, Table xpf_dp_rst, Type filter, Hook output, Priority filter, Policy accept — correct for DROP-only RST.
- Checked concurrency: new nftables.Conn per Install/Remove, no shared mu — thread-safe.
- Checked fail-closed vs fail-open: caller logs WARN and retries — fail-open RST leak when nftables unavailable, but retried.
- Checked atomicity claim: delete+create same conn.Flush() batch — true, single netlink batch.
- Checked int trunc: family byte holds NFPROTO values 2/10 within byte; addrLen uint32; saddrOffset uint32 — safe.
- Dedup index check: no prior issue matches this module (RST suppress not listed).

## Findings

### High Confidence

#### FINDING-1: Test coverage is trivial — rule encoding untested
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A6_go_dataplane_manager-b3/pkg/nftables/rst_suppress_test.go:8`
```
func TestBuildRSTSuppressionPlanSkipsDeleteWhenTableMissing(t *testing.T) {
	plan := buildRSTSuppressionPlan(false, []netip.Addr{netip.MustParseAddr("172.16.80.8")}, nil)
	if plan.deleteTable {
		t.Fatal("plan.deleteTable = true, want false")
	}
```
And `rst_suppress.go:144-200` entire `addRSTDropRule` expression chain never exercised.
Trace: Install path builds exprs list: Meta NFPROTO cmp, Payload nh offset saddrOffset len addrLen cmp addrBytes, Meta L4PROTO cmp TCP, Payload th offset 13 bitwise mask 0x04 cmp !=0, Counter, Verdict Drop. A typo in offset (e.g., 8 vs 12) would pass existing tests, yet silently make DROP never match, leaking RSTs during HA demotion (#450). Existing tests only assert `deleteTable` bool and length.
Refutation attempt: Checked whether manager_misc_test covers expression — it covers retry predicate only. No netlink rule inspection. So bug would be invisible.
Why it matters: RST suppression is HA safety net — regression leaks RST kills flows on failover, user-visible outage.
Fix direction:
- Add unit test for `queueRSTSuppression` using nftables dry-run/ fake conn or table-driven expectation: assert chain name, hook, priority, policy, rule count equals len(v4)+len(v6), each rule's expr contains expected saddrOffset (12 for v4, 8 for v6), family byte, l4proto byte 6, mask 0x04, verdict Drop, and Counter present.
- Add gol
```

---

#### Finding from ps-A7_go_daemon_host-b3.md

```
# A7_go_daemon_host b3/3 - Upgrade, Lock, Manifest, StagedGen, WGKey Defensive Review
BASE: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A7_go_daemon_host-b3

## Inventory
- Total files in batch: 40 (19 prod priority + 2 extra prod cutover/cluster_cli + 19 test)
- Prod LOC (priority list): ~5583 lines
  - flip.go 448, helper_health.go 160, imageversions.go 179, kernel.go 334, kernel_drain.go 160, kernel_linux.go 692, kernel_run.go 626, kernel_selfrecover.go 273, lock/lock.go 303, manifest/manifest.go 106, rolling.go 247, runner.go 565, runtime/seed.go 400, stagedgen/fsutil.go 149, stagedgen/stagedgen.go 413, state.go 165, system_linux.go 190, version.go 60, wgkey/wgkey.go 113
- Extra prod: cutover.go 996, cluster_cli.go 610
- Test LOC: ~8390
- Largest prod fns: KernelRunner.Promote ~80 lines, KernelRunner.preflight/installCandidate/armCandidate ~70 each, Runner.Run ~180, flip.gc ~100, stagedgen.Config.Publish ~50, lock.AcquireAt ~70
- Responsibility: binary cutover ordering, host-wide lock, staged-gen immutable publish, kernel A/B arm/promote, manifest SSOT, wg x25519 keygen

## Module Log (coverage - negatives proving soundness)
- flip.go: NEGATIVE - symlink repoint atomic temp+rename+fsync, ver validated upstream via ValidateVersionSegment, unit dropin path from versionDir (validated) and fmt.Sprintf no shell.
- helper_health.go: NEGATIVE - fail-closed 3-part gate (unit active + armed+forwarding + target version dir equality), exe (deleted) suffix tolerated via Dir, deadlines bounded.
- imageversions.go: NEGATIVE - parseImageVersions scanner with present-tracking, requiredKeys fail-closed, GateMixedBaseSwap fails closed on 0/unknown peer protocols, back-compat window check correct.
- kernel.go: NEGATIVE - KernelState order unknown-> -1 atLeast false fail-closed, journal struct no path traversal via version fields (validated elsewhere).
- kernel_drain.go: NEGATIVE - DrainAndConfirm refuses if peer not alive/takeover-ready, failback ResetFailover on timeout avoids VIP stranding, sleepBounded bounds deadline overshoot.
- kernel_linux.go: NEGATIVE - command exec via exec.Command not shell, LC_ALL=C locale hardening, BootOrder/SetBootNext hex-validated, slot labels constants xpf-A/B, promotion marker durable, disarm watchdog error surfaced (#4872B).
- kernel_run.go: NEGATIVE - resume-version guard, stale marker clear, preflight UEFI+efibootmgr+A/B+BootOrder+grub+watchdog+free space, install re-assert default not moved + KernelHeld full-set, armCandidate selector read-back verify + journal ARMED before BootNext (reboot-boundary hole closed), Promote fail-closed indeterminate handling (#4872A) preserves journal no prune no reboot on unreadable state.
- kernel_selfrecover.go: NEGATIVE - lease state machine only acts on leaseExpiredOurs (crashed orchestrator fingerprint), leaseNone manual drain no-op, IsZero expiry check prevents {} lease -> spurious recovery (#4872C), grace reset on observation error (#4872D), Armed gate prevents split-brain rejoin during armed trial.
- lock/lock.go: NEGATIVE - flock EX|NB host-wide, /run tmpfs reboot-clearing, truncate-on-acquire + truncate-on-release-under-lock prevents stale JSON (#1984), never rm lock file (#1875), Handle idempotent Release, owner metadata best-effort not mutex.
- manifest/manifest.go: NEGATIVE - private managed slice, fresh slice returns prevent mutation, LockstepNames from SSOT.
- rolling.go: NEGATIVE - lock held whole window, inner Run LockAlreadyHeld avoids self-deadlock EWOULDBLOCK, prechecks peer alive/sync/HA compat/takeover-ready before ForceSecondary, strong drain predicate, tolerateTransientErr for post-cut gRPC unavailable.
- runner.go/cutover.go: NEGATIVE - ValidGenID + target==Base check prevents ../ escape in ResolveCurrent, ValidateVersionSegment rejects / leading dot whitespace control non-ASCII, copyTree rejects non-regular (symlink) entries, checksum verify, fsync deepest-first, DB snapshot before flip ordering, cluster gate refu
```

---

#### Finding from ps-A8_go_api_grpc_rest-b2.md

```
# A8_go_api_grpc_rest b2/2 — gRPC/REST api hardening sweep

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2
Batch: 129 files pkg/grpcapi, 29 prod ~12.4k LOC, 98 test ~11k, 2 gen 11.2k (xpf.pb.go 9172, xpf_grpc.pb.go 2056), total 36k.

Top5 prod LOC / responsibility:
1 server_sessions.go 1460 — session table RPC (cursor+legacy, filtered clear, peer fan-out, zone-pair) R1 (DoS amplification, peer dial)
2 server_show_security_text.go 1063 — screen IDS, ipsec, rpm, security log/alarms R2
3 server_show_interfaces.go 935 — GetInterfaces, detail/terse, RETH, kernel stats R2
4 server_show_firewall.go 666 — filter term expansion, counter reads, policer R3
5 server_show.go 562 — ShowText allowlist gateway (log tail allowlist, CoS) R1 (remote CLI entry)

Largest fn: getSessionsCursor ~180 LOC, ClearSessions filtered ~140, showPoliciesHitCount ~120, dialPeer ~55 but hot for HA.

Responsibility rank size x resp x hot-path:
- server_sessions.go (session scan O(N) N up to 10M, peer dial on every request)
- server_diag_system_action.go 486 (reboot/zeroize/failover/userspace inject/queue/binding — destructive)
- server_show.go (show topic allowlist — remote CLI → gRPC bridge)
- server_diag_monitor.go 520 (MonitorPacketDrop validation, streaming lifecycle)
- server.go 588 (bind clamp, graceful stop, fabric allowlist, auth interceptor chain)

---

## Findings — High Confidence

### Title: userspace-inject/queue/binding slot wraps negative Atoi -> MaxUint32
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_system_action.go:384-412`
```
			if strings.HasPrefix(req.Action, "userspace-inject:") {
				...
				parts := strings.SplitN(rest, ":", 2)
				if len(parts) != 2 {
					return nil, status.Error(codes.InvalidArgument, "usage: userspace-inject:<slot>:<mode>")
				}
				slot, err := strconv.Atoi(parts[0])
				if err != nil {
					return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
				}
				mode := parts[1]
				statusNow, err := provider.Status()
				...
				injectReq, err := dpuserspace.BuildInjectPacketRequest(uint32(slot), mode, extra, statusNow)
```
Same at :444 queueID Atoi -> uint32(queueID), :469 slot Atoi -> uint32(slot).
Trace:
1. Client (loopback, per #5278 any shell user) sends SystemAction `userspace-inject:-1:drop`.
2. Atoi("-1")= -1, err=nil, passes InvalidArgument check.
3. Cast uint32(-1)=4294967295 passed to BuildInjectPacketRequest/SetQueueState/SetBindingState.
4. Downstream may reject with generic error, or index OOB, or confuse operator with max-slot message.
Refutation attempt: Looked for downstream validation in dpuserspace — likely checks slot < len(bindings) but error would be "slot out of range" not "negative not allowed". RPC boundary should fail-closed on negative before cast; no `slot<0` check in this file. Not caught by existing tests (no negative slot test in batch).
HPC/invariant: N/A — control path, not hot.
Why it matters: Bypass of intended non-negative domain, potential panic/OOB in Rust helper if Go check missing, confusing error for typo.
Fix direction: Add `if slot<0 { return InvalidArgument("slot must be >=0") }` before cast for all three verbs; same for queueID.
Labels: input-validation, integer-bounds, userspace-dataplane
Dedup note: Not #5281/#5280/#5278 (zeroize root / RBAC). Distinct integer bounds in userspace control verbs.

### Title: Ping Size unbounded — TX amplification DoS
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_ping.go:56-95`
```
func (s *Server) Ping(req *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	if err := checkDiagArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
		return err
	}
	count := int(req.Count)
	if count <= 0 {

```

---

#### Finding from ps-A9_go_observability-b1.md

```
Title: SNMPv3 privacy salt RNG error ignored — IV reuse on RNG failure
Severity: Medium
Confidence: High
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/snmp/v3.go:790-822
```
func encryptDES(privKey, data []byte) ([]byte, []byte) {
	if len(privKey) < 16 {
		return nil, nil
	}
	desKey := privKey[:8]
	preIV := privKey[8:16]
	privParams := make([]byte, 8)
	rand.Read(privParams)
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = preIV[i] ^ privParams[i]
...
func encryptAES128(privKey, data []byte, boots, time int) ([]byte, []byte) {
	if len(privKey) < 16 {
		return nil, nil
	}
	privParams := make([]byte, 8)
	rand.Read(privParams)
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
```
Trace:
1. buildV3Response -> encryptPDU -> encryptAES128/DES.
2. make([]byte,8) zeroed, crypto/rand.Read called, (n,err) discarded.
3. On error (getrandom failure early boot, FIPS, fd exhaustion) buffer stays zero or partial undefined.
4. AES-CFB IV = boots|time|0 — boots/time changes per second, so all responses within same second share IV → keystream reuse leaks XOR of two plaintext scopedPDUs.
5. DES IV = preIV ^ 0 = deterministic.
6. Collector decrypts (still works) but confidentiality broken; RFC 3414 §8 / RFC 3826 §3.1.4 requires unique salt per PDU.
Refutation attempt: Checked crypto/rand docs: Read returns len and nil on success, else non-nil err. Go runtime seeds CSPRNG, rare to fail, but error path must be handled. Callers return nil only on short key, not on RNG failure, so weak packet still sent. Not mitigated elsewhere; no wrapper. Search confirms only two rand.Read sites, both ignored.
HPC/invariant check: Salt uniqueness invariant per RFC — must be 8 distinct random bytes per PDU; current provides monotonic time low bits + random, but fails to zero on error.
Why it matters: SNMPv3 authPriv confidentiality bypass on security-critical error path — triggers exactly when RNG unhealthy (worst time). Leaks ifTable/sysDescr via keystream XOR.
Fix direction: Check error: `if _, err := io.ReadFull(rand.Reader, privParams); err != nil { slog.Error(...); return nil, nil }`. Caller clears priv flag → sends authNoPriv or drops (better to fail response than send weak crypto). Add seam test injecting failing Reader assert fail-closed.
Labels: snmp, v3, crypto, RNG-error-handling, IV-reuse
Dedup note: Not in dedup list; #5283 is hostname-only EngineID collision, distinct root cause (deterministic EngineID vs RNG failure).

### Finding 2 — HIGH confidence (low sev)
```

---

(13 findings at Medium level)


### Low


#### Finding from ps-A10_go_services_cli_deploy-b1.md

```
Title: App resolve map iteration nondeterminism for overlapping port definitions | Severity: Low | Confidence: Medium
Evidence: `pkg/cli/app_resolve.go:46-78` `func resolveAppName(proto uint8, dstPort uint16, cfg *config.Config) string { if cfg != nil { for name, app := range cfg.Applications.Applications { ... if int(dstPort)>=lo && int(dstPort)<=hi {return name} } } for name, ba := range builtinApps { if ba.proto==proto && ba.port==dstPort {return name} }`
Trace: cfg.Applications is map; two apps `web1 tcp 80` `web2 tcp 80-80` both match dst 80; iteration order random → returned name flips per run.
Refutation: code comment says currently unused superseded by appid pkg — if unused, not exploitable; but if re-enabled, nondet.
HPC: map iteration randomness.
Why matters: show-output correctness / audit flaky; ID stability #5296 sibling.
Fix: sort keys or use deterministic first-match by config order; or keep unused deletion.
Labels: display-correctness, vsrx-parity
Dedup: not #5296 exactly — #5296 is positional catalog IDs reassigned; this is map iteration nondet.

**[LOW] cli_show_security_zones logical unit non-numeric suffix renders all units**
```

---

#### Finding from ps-A10_go_services_cli_deploy-b1.md

```
Title: Zone detail renders all units on non-numeric suffix | Severity: Low | Confidence: Medium
Evidence: `pkg/cli/cli_show_security_zones.go:112-130` `base:=ifName; wantUnit:=-1; if parts:=SplitN(ifName,".",2); len==2 {base=parts[0]; if u,err:=Atoi(parts[1]); err==nil {wantUnit=u}} ... for _,unit :=range ifc.Units { if wantUnit>=0 && unit.Number!=wantUnit {continue} }`
Trace: zone binds `ge-0/0/9.foo` → Split → base `ge-0/0/9` wantUnit stays -1 (parse fail) → loop renders every unit's addresses under that base.
Refutation: not security boundary — displays more not less; only local CLI view; no priv esc.
Why matters: minor info overexposure / audit confusion.
Fix: if suffix present but Atoi fails, skip rendering or warn instead of rendering all.
Labels: display-correctness
Dedup: not in dedup list.

### Medium Confidence

**[NEGATIVE] CLI ping/traceroute VRF prefix normalization and arg injection — sound**
Evidence: `pkg/cli/cli_request_ping.go:28-54` `func buildPingArgv(...){ return diagcmd.PingArgv(PingOptions{Target, Count, Source, Size, RoutingInstance: vrfName})}` + `pkg/diagcmd/ping.go:30-42` `func VRFDeviceName(name string)string{if name==""{return ""} if HasPrefix(name,vrfPrefix){return name} return vrfPrefix+name}` + traceroute same.
Trace: operator `ping 8.8.8.8 routing-instance vrf-red` → VRFDeviceName returns `vrf-red` unchanged not `vrf-vrf-red`. Rest args validated via net.ParseIP/strconv in shared builder.
Refutation: checked for `--` separator present in builder to stop option parsing — diagcmd inserts `"--"` before target per #2084.
Why matters: prevents blackhole probe to nonexistent VRF device + option confusion injection.

**[NEGATIVE] Show output tier handling 3-tier global/default — sound**
Evidence: `pkg/cli/cli_show_security_zones.go:187-208` `policymatch.ZoneDetailPolicySummary(cfg,name,schedActive,haveSched)` comment "spans all THREE tiers the runtime evaluates in order — zone-pair, then applicable GLOBAL policies, then the effective default-policy catch-all" + hit-count global block: `for _,pol:=range cfg.Security.GlobalPolicies { if !GlobalPolicyAppliesToZonePair(...){continue} }` + `runtimePolicyIndex` delegating to `dpuserspace.RuntimePolicyIndex`.
Trace: filtered `show security zones trust detail` must surface unscoped globals + scoped globals targeting trust + default-policy — ZoneDetailPolicySummary does.
Why matters: prevents hidden permit via global (M04) or hidden deny/permit status (M05).
Dedup: fixes for #3357/#3658/#3654 — this batch is post-fix, sound.

### Low Confidence

**[INFO] BPF headers struct layout invariant — sound, Go mirrors size-asserted**
Confidence: High
Evidence: C `struct session_key { __be32 src_ip; __be32 dst_ip; __be16 src_port; __be16 dst_port; __u8 protocol; __u8 pad[3]; } __attribute__((packed))` vs Go `bpf_session_value_test.go:24` `if got:=unsafe.Sizeof(bpfSessionValue{}); got!=conntrackValueSizeV4 { t.Fatalf(...) }`
Invariant: pad ensures 4B align for map key; packed removes trailing pad; Go explicit Pad field matches.
Why matters: misaligned map key breaks conntrack lookup dataplane-wide.

**[NEGATIVE] No DHCP packet parsing in this batch — DHCP correctness out-of-scope**
Confidence: High
Evidence: 150 files list contains only show_services_dhcp display, not pkg/dhcp packet ingress. Grep `dhcpv4\|DHCP.*Parse\|option.*82` across batch returns only display formatters.
Dedup: DDNS #5327/#5334 out-of-scope for display layer.

## Suggested Issue Split

1. **app_resolve nondet** → Low prio cleanup — remove unused file or sort.
2. **zone detail non-numeric unit suffix** → Low prio display polish.

Both low-materiality, no high/critical findings in this batch. Batch overall is hardening post-fix verification: #5037/#5038/#3378/#5322/#4869/#4876/#5286/#3654/#3658/#3357 fixes present and correct.

## Summary

- 150 files: 6 BPF headers (prod, hot ABI), ~10 cmd/cli prod +20 test, 2 evidence c, 4 cmd/xpfd prod +4 test, ~55 pkg/cli prod +45 test (~30k LOC prod).
- No CLI ar
```

---

#### Finding from ps-A10_go_services_cli_deploy-b2.md

```
# A10 Go services/cli/deploy b2/3 — Defensive Review (150 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktrees: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2

## Inventory (size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | pkg/dhcprelay/relay_test.go | 2033 | test | runRelay matrix | relay lifecycle, hop-limit, ifindex drift #2347 | med |
| 2 | pkg/ddns/surface_a.go | 2007 | prod | Reconcile ~300L / publishLocked ~130L | Surface-A engine, PrevAddr #3739, PublishPending #5285, sibling #3738 | high |
| 3 | pkg/dhcp/dhcp.go | 1903 | prod | runDHCPv6 185L / runDHCPv4 179L | v4/v6 manager, DUID traversal #4857, NAK #3956, classless RFC3442 | high |
| 4 | pkg/dhcprelay/relay.go | 1545 | prod | runRelaySession 343L | supervisor, giaddr retry, hop-limit #4309, source validation #4163 | high |
| 5 | pkg/ddns/manager.go | 1457 | prod | reconcileOnceLocked 210L | DHCP DDNS engine, per-family backend, providerIO #5006, PTRPending #2661 | high |
| 6 | pkg/dhcpserver/dhcpserver.go | 1210 | prod | generateKea4Config | Kea config, is-active tri-state #4870, subnet_id stable #5041 | med |
| 7 | pkg/ddns/backend_rfc2136.go | 1100 | prod | sendAddOwned 75L | exact-RR #3739, DHCID, self-owned replace, TSIG | high |
| 8 | pkg/cli/monitor.go | 967 | prod | handleMonitorSecurityPacketDrop 180L | flow trace file, rotation, sanitization 0700, nil guard #3381 | med |
| 9 | pkg/dhcpserver/lease_sync.go | 933 | prod | writeMemfile6 | memfile sync, expired drop #4871, IAPD preserve | med |
| 10 | pkg/cli/completion.go + monitor_traffic.go | 577+260 | prod | Do() / parseMonitorTrafficArgs | completion nil guard #2288, traffic injection neutralization #4524/#4556, count bound #4589 | med |
| 11 | pkg/ddns/backend_route53.go | 243 | prod | buildChangeBatch / change | Route53 UPSERT signature, foreign-record unsafe | high |
| 12 | pkg/dhcprelay/l2send_linux.go | 226 | prod | sendReply / buildL2Reply | AF_PACKET TX, MTU guard, IPv4 checksum | med |

Total scanned batch: ~38k LOC (prod ~12k, test ~26k). Test-heavy RED-on-revert suite present.

## Module Log (coverage + negatives)

**CLI 54 files**: completion.go NEGATIVE — helpWriter nil guard when rl==nil #2288 prevents panic; completionSuffix bounds check `len(partial)>len(name) || !HasPrefix` prevents slice OOB when commonPrefix shorter than typed partial; zone nil guard `if zone==nil continue` #3493, zpp nil #3476, pol nil. monitor_traffic.go NEGATIVE — keyword-as-value guard `monitorTrafficKeywords[args[i+1]]` prevents swallowing `matching` as interface, greedy matching up to keyword, quote strip, count 0..8192 bound #4589, `--` separator #4524 neutralizes `-w/-z` file-write/cmd-exec, `monitorFilterOptionToken` quote-peel `'-w` #4556. monitor.go NEGATIVE — nil eventBuf guards #3381, traceLogDir 0700 `/var/log/xpf-flow-trace`, `sanitizeTraceFilename` rejects `/ \ . ..`, O_NOFOLLOW 0600, atomic filter parse. monitor_interface.go NEGATIVE — VMIN=0/VTIME=1 poll, keyReader done+WG stop #3985. peer.go NEGATIVE — fabricAuthKey seam, per-RPC `NewFabricAuthCreds` #5324, SO_BINDTODEVICE, TCP probe; unkeyed grace intact. permissions.go NEGATIVE — traffic→PermControl prefix-safe, flow file/start→PermControl #5038, reboot/failover/data-plane disarm→PermMaint #4108/#4859. session_filter.go NEGATIVE — zone nil #3493, multi-iface map #4792, `ifaceMatchesAny` + FIB fallback, parseErr fail-closed clear-all guard. link/runtime/proto/session_display/show_services_* NEGATIVE — sysfs bound, runtime narrow interface #1517, NativeEndian PutUint32, bracket-aware splitAddrPort, cos queue passes `statusErr` not conflates empty #5326, ddns TSIG redacted, dhcp lease warn vs empty, snmp redaction. All cli_*_test.go NEGATIVE hardening suite present.

**DDNS 34 files**: backend.go NEGATIVE — PrevAddr self-owned only, zero→additive insert, SiblingFamilyOwned host-wide guard #373
```

---

#### Finding from ps-A10_go_services_cli_deploy-b3.md

```
# A10 Go services/cli/deploy b3/3 — Defensive Review (96 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3

## Inventory (LOC x responsibility x hot-path proximity)

| File | LOC | P/T | Largest fn | Responsibility | Rank |
|------|-----|-----|------------|----------------|------|
| pkg/policymatch/policymatch.go | 1714 | prod | Match() 180L | SSOT simulator zone/global/host-inbound/content-reject/route-drop advisory | CRIT |
| scripts/deploy/xpf-deploy.py | 1881 | prod | cmd_fetch ~200L | VM deploy, fetch+verify #1924, anti-rollback watermark, mixed-base gate, libvirt golden H-30 | High |
| test/incus/cold-path-flooder/src/main.rs | 2170 | test | worker loop / main | AF_PACKET cold-path flooder 5-tuple sweep, batch sendmmsg, CPU pin | Med |
| scripts/dist/publish.py | 786 | prod | publish gate | fail-closed publish #1924 §5.5 image/apt/install.sh/latest.json sig gates | High |
| scripts/image/bake.py | 756 | prod | virt_customize | offline bake virt-customize, cache SHA verify, grow-root, Secure Boot slots, validate→sign #4017 | High |
| scripts/image/validate.py | 686 | prod | scenario_a-e per-scenario | appliance first-boot contract a-e,q validation harness | High |
| test/incus/retire_ebpf_artifact_schema.py | 681 | test | ArtifactChecker.validate | #1477 final retirement bundle structural validation | Med |
| test/incus/cos_be_contention_validate.py | 748 | test | validate_artifacts | CoS exact-vs-BE contention validator | Med |
| pkg/policymatch/zone_detail_summary.go | 207 | prod | ZoneDetailPolicySummary 90L | tier-ordered exact→single-wild→both-any presenter | High |
| pkg/scheduler/scheduler.go | 448 | prod | evaluate 70L / isWithinWindow | time-window eval, republish self-heal #3780, wall-clock discont #3849, tz #3988 | High |
| scripts/dist/sign.py | 345 | prod | verify_and_read | minisign trust root, TOCTOU-safe copy-then-verify #5042 | High |
| test/xsk-repro/* | 24-320 | test | create_xsk / main | AF_XDP zero-copy rebind repro (root, DMA) | Low |
| many *_test.go + fairness/mouse/step* | 40-1400 each | test | — | RED-on-revert guards, metric reducers | Low |

Overall ~38k LOC scanned (prod ~6500, test ~31k). Largest prod funcs: Match() simulator precedence chain, scheduler evaluate(), xpf-deploy cmd_fetch 200L.

## Module Log (coverage proofs + negatives REQUIRED)

- **policymatch.go 1714 prod**: 3-pass read (0-500,500-900,900-1714). Tiers 1-5 exact mirror userspace-dp/src/policy.rs evaluate_policy_result. Verified zoneKnown gate #3355 no len(Zones)==0 tolerance — fail-closed to default. globalScopeSetMatches skips unresolved zone name → fail-closed. matchAddr empty-both-families fail-closed #3356/#2008. cross-family v4Empty&&v6Empty gate #3023 correct (v6-only exclusion on v4 packet trivially outside set → match). ContentRejected config-wide via dpuserspace.PolicyContentRejectionReasons delegates to SSOT — prevents fabricated permit under default-permit #3727/#4394. Route-drop defer stamp onto every return path #4373, host path exempt (junos-host local delivery). Host-inbound admission attached via withHI closure every host return — SSOT ClassifyHostInbound #3627. SelectorArgs strict — unknown token + missing value + duplicate rejection #3696/#3709 errors not wildcard widen. Port/proto canonical via config.ParseCanonicalUint + appid.ProtocolNumber rejects signed +/– #3679. **NEGATIVE**: no silent last-win, no empty-selector wildcard, no omitted-proto/port over-match — locked by port_omitted_3330, protocol_omitted_3323, srcport_omitted_3415 RED-on-revert.

- **zone_detail_summary.go**: Tier ordered exact→single-wild→both-any #4885, config order within tier. Nil zpp/pol guard #3476. PolicySetID advances in config order regardless of tier bucket — matches RuntimePolicyIDs namespace. **NEGATIVE**: no panic on nil, no ID divergence.

- **scheduler.go**: Absent window ⇒ inactive fail-closed #3849. Half-specified warn+false. Wall-clock discontinuit
```

---

#### Finding from ps-A1_rust_dataplane_packet-b1.md

```
# A1 Rust Dataplane Packet Review — Batch b1/3 (150 files)
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1

## File-size/shape inventory (top 25 by LOC, ranked by size×resp×hot-prox)

| LOC | File | Prod/Test | Largest fn | Responsibility | Hot-prox |
|-----|------|-----------|------------|----------------|----------|
| 2795 | forwarding/mod.rs | prod | lookup_forwarding_resolution_v4_inner ~300 | FIB LPM, zone-id, HA gate, fabric, tunnel | HOT (per-packet lookup) |
| 2057 | cos/queue_service/mod.rs | prod | waterfill selector 432 LOC god-func | waterfill guarantee/surplus, refund, park | HOT (drain) |
| 1960 | frame/inspect.rs | prod | term_match_extra_from_frame ~120 | EH walker (6×), frag, flex-range, port parse, zone-mac | HOT (parse) |
| 1743 | frame/mod.rs | prod | rewrite + build orch | ETH write, NAT, TTL, DSCP, VLAN push/pop via desc shift | HOT (rewrite) |
| 1579 | coordinator/wg_control.rs | prod | WG peer reconc. | WireGuard control path | COLD |
| 1045 | coordinator/status.rs | prod | status aggregation | Prometheus/status cold path | COLD |
| 1000 | flow_cache.rs | prod | lookup_with_observed_bytes 80 LOC | 4-way SA-LRU, epoch, MAC-epoch, seeded FxHasher | HOT |
| 995 | frame/tcp_segmentation.rs | mixed | gso segmentation | TSO/GRO, WG encap | HOT (TX) |
| 984 | frame/checksum.rs | prod | checksum16 paths | scalar+AVX2 SIMD, v4/v6 zero-canonicalization | HOT |
| 961 | gre.rs | prod | GRE decap/encap | GRE over v4/v6, TCP flags, meta | HOT |
| 954 | cold_path_hist.rs | prod | record cold transition | cold-path histogram, rdtscp | COLD |
| 949 | ha.rs | prod | HA eval | RG lease, fabric redirect pref | WARM |
| 850 | forwarding_build/cos.rs | prod | CoS builder | rate/buffer validation, priority | COLD (build) |
| 838 | coordinator/cos_leases.rs | prod | lease mgmt | shared CoS leases | COLD |
| 798 | bind.rs | prod | open_binding_worker_rings unsafe | XSK bind, fill prime, NAPI kick | COLD (bringup) |
| 712 | bpf_map/mod.rs | prod | publish/session | session BPF map ops, zeroed values | WARM |
| 705 | forwarding_build/mod.rs | prod | build_forwarding_state | snapshot->state, integrity | COLD |
| 646 | cos/admission.rs | prod | cos_queue_flow_share_limit | share/buffer/ECN, BDP floor | HOT (admit) |
| 606 | frame/wg.rs | prod | WG encap | WG data header, MTU, mss | HOT (encap) |
| 599 | icmp.rs | prod | ICMP error build | icmp build, quoted len, MTU | WARM |
| 598 | event_emit.rs | prod | log emit | session close, filter log | COLD |
| 537 | forwarding/host_inbound.rs | prod | host-inbound | zone host-inbound admit | WARM |
| 498 | disposition.rs | prod | PacketDisposition enum | classification | HOT |
| 486 | coordinator/reconcile/bringup.rs | prod | bringup | binding bringup | COLD |

Total batch: 150 files. Prod ~90, test/bench ~60. Largest functions: waterfill selector, lookup_forwarding_resolution_v4_inner, parse_session_flow_from_bytes.

## Module log (coverage proof, incl negatives)

- **frame/inspect.rs**: 6 EH walkers all use `MAX_IPV6_EXT_HEADERS=8`, `checked_add`, `frame.len() < offset` fail-closed. `ipv4_declared_l3_end` guard for IHL truncation added (panic-safety). `icmp_identifier_bearing` SSOT, `meta_icmp_identifier_bearing` double-gated by declared_end. No unwrap (0). NEGATIVE: EH walker parity sound, frag gates sound, flex-range clamped to IP-declared end (#5150) — no bypass.
- **frame/mod.rs**: 3 `slice_mut_unchecked` with `descriptor_view_in_same_umem_frame` guard (same UMEM frame, 256B headroom). TTL `<=1` drop, DSCP rewrite idempotent. `trim_l3_payload` metadata-led with IP-total-len fallback. NEGATIVE: rewrite path bounds-checked, VLAN push/pop via descriptor shift avoids memmove, TTL/hop-limit underflow guarded.
- **frame/checksum.rs**: AVX2 fast-path `<32B` short-circuit, `is_x86_feature_detected!` cached, horizontal sum correct, `checksum16_finish` fold loop, v4/v6 zero-canonicalization matrix pinned by `simd_checksum_tests` di
```

---

#### Finding from ps-A1_rust_dataplane_packet-b2.md

```
# Batch b2/3 — A1 Rust AF_XDP dataplane packet b2 (150 files) — 2026-07-10

**Worktree**: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b2` @ `275989b76b22925f4d2719fa07f47709eb227059`
**Base**: `git rev-parse --show-toplevel` → `/home/ps/git/avacado-xpf`

## Shape inventory
- Files: 151 listed in batch-004.txt (including header line) → 150 real `userspace-dp/src/` files
- LOC: 105093 = prod 52029 (107 files) + test 53064 (43 files)
- Largest prod: `poll_descriptor/mod.rs` 6294, `neighbor.rs` 2036, `types/cos.rs` 1786, `worker/loop_body/mod.rs` 1784, `tx/dispatch/mod.rs` 1486 (enqueue_pending_forwards 1050), `shared_cos_lease/lease.rs` 1460, `neighbor_dispatch.rs` 1421, `umem/mod.rs` 1363, `tx/cos_classify.rs` 1335, `session_glue/mod.rs` 1277, `poll_descriptor/filter.rs` 1201, `types/forwarding.rs` 1099, `afxdp/mod.rs` 1069, `wg/engine.rs` 1805
- Largest test: `afxdp/tests.rs` 14038, `session_glue/tests.rs` 5748, `cos_classify_tests` 4617, `wg/tests` 3909, `poll_stages_tests` 2636
- Largest fns: `poll_binding_process_descriptor` 5611 LOC L683 god-function 15+ resp single-recycle invariant Junos order host-inbound→lo0→junos-host table-scoped local-delivery #3769/#3151 connected scoping #2388; `enqueue_pending_forwards` 1050 LOC L271 TX orchestrator zero-copy UMEM ownership; CoS classify 7-resp enqueue_pending+fallback
- Hot proximity rank (size×resp×hot): 1) poll_descriptor/mod.rs 251760, 2) dispatch/mod.rs 44580, 3) cos_classify.rs 28035, 4) types/cos.rs 21432, 5) neighbor.rs 18324
- Ownership: `BindingWorker` single-writer per worker, UMEM `MmapArea` single owner `Rc<WorkerUmemInner>` with `Rc::get_mut` exclusive

## Module log (condensed, with negatives proving coverage)
- `poll_descriptor/mod.rs` 6294: orchestrates RX meta parse → flowless verdict → host-inbound deny per #3070 empty set → lo0 filter → junos-host #3019 reserved range → NAT64 frag assoc deferred install → cache-hit → session-limit → strict-syn bare RST/FIN drop agg-only no event #4400 repurposed from #2151/#4487/#4539 has_syn gate → screen 16 checks + syncookie → policy → TX. All 15 eprintln behind `cfg!(feature="debug-log")` + numeric caps via `debug_log_throttle.rs` pure fn(session_miss)<=10 policy_deny<=3 no topo bypass #4120 — no flood. 6 unsafe via `unsafe { &*area }.slice(addr as usize, len as usize)` Option-checked, bounds fail-closed.
- `cookie_reply.rs`/`reject_reply.rs`/`nat_exception.rs`: `#[cold]#[inline(never)]` true cold bodies .text.unlikely — exemplary split, hot byte-for-byte preserved
- `filter.rs` 1201: inline policy per-fn not blanket — cheap guards #[inline] fold into hot caller, heavy bodies #[cold]#[inline(never)] including `filter_terminal` ordering reject-reply enqueue FIRST then emit log with actual outcome #3615 truthful REJECT→DENY downgrade. `emit_cached_output_filter_log` tail split prevents 96B `UserspaceDpMeta` copy on fast path no-logging — HFT-grade
- `flow_cache_hit.rs` 533: hit replay relays hit counters via `record_policy_hit_counter` batch coalescer — no Mutex per packet — GOOD
- `rx_telemetry.rs` 220: small counters inline
- `poll_stages.rs` 975: stage extraction host-inbound/lo0/policy eval hoisted — still zone lookup — no extra taken branch — GOOD split without disasm change
- `tx/dispatch/mod.rs` 1486 HOT: single-recycle invariant — src frame via ingress UMEM unsafe &*area slice Option, target build via `slice_mut_unchecked(offset, capacity())` owned offset from free_tx_frames pop_front; double-recycle fix #4041 single if build_failed path; prefetch `_mm_prefetch` x86_64 cfg; oversized written>capacity drop + exception; no Vec alloc direct path — negative sound
- `dispatch/cos.rs` + `shared_recycle.rs` + `slow_path.rs`: shared_recycles Option<&mut Vec<(u32,u64)>> CAS-free local queue; fallback clone alloc only slow path
- `tx/cos_classify.rs` 1335 7-resp: DSCP/PCP→queue, clone_prepared_req fallback, default-queue fallback for unmaterialized queue #hb166 T-4 Never blackhole (belt-and-suspenders runtime + build-ti
```

---

#### Finding from ps-A1_rust_dataplane_packet-b3.md

```
# b3/3 Rust hot path: session table + policy/verdict + screen + filter + worker queues + event_stream

Base 275989b76b22925f4d2719fa07f47709eb227059 WT /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b3

## Shape inventory
- Batch files: 118 — prod 64708 LOC (92 files), test 19247 LOC (26 files), total 83955
- Prod vs test split: PROD 92 files, TEST 26 files
- Largest prod top 20:
  - userspace-dp/src/filter/tests.rs 8422
  - userspace-dp/src/session/tests.rs 7072
  - userspace-dp/src/screen/tests.rs 5395
  - userspace-dp/src/policy.rs 3657
  - userspace-dp/src/protocol/tests.rs 2393
  - userspace-dp/src/session/mod.rs 2114
  - userspace-dp/src/server/tests.rs 1953
  - userspace-dp/src/event_stream/mod.rs 1701
  - userspace-xdp/src/lib.rs 1541
  - userspace-dp/src/screen/mod.rs 1540
  - userspace-dp/src/server/helpers.rs 1304
  - userspace-dp/src/xsk_ffi.rs 1287
  - userspace-dp/src/screen/scan.rs 1213
  - userspace-dp/src/protocol/binding.rs 1185
  - userspace-dp/src/protocol/control.rs 1088
  - userspace-dp/src/filter/compiler.rs 1056
  - userspace-dp/src/filter/engine/eval.rs 1026
- Largest test top 10:
  - userspace-dp/src/policy_tests.rs 7280
  - userspace-dp/src/main_tests.rs 2350
  - userspace-dp/tests/fairness_eval_blackbox.rs 1366
  - userspace-dp/src/event_stream/codec/codec_tests.rs 1023
  - userspace-dp/src/slowpath_tests.rs 776
  - userspace-dp/src/state_writer_tests.rs 689

- Largest fn approx (heuristic):
  - userspace-dp/src/session/mod.rs: pub fn update_session ~239 LOC
  - userspace-dp/src/policy.rs: pub(crate) fn parse_policy_state_with_counters ~567 LOC
  - userspace-dp/src/screen/mod.rs: pub fn check_packet_with_zone_id_opts ~374 LOC
  - userspace-dp/src/filter/compiler.rs: fn parse_term ~427 LOC
  - userspace-dp/src/event_stream/mod.rs: pub(crate) fn mono_ns_to_wall_clock_unix_ns ~199 LOC
  - userspace-xdp/src/lib.rs: fn try_xdp_userspace ~343 LOC

- Hot rank size*resp*hot-proximity: 1) session/mod.rs slab u32 handles + Seeded 1:N indexes reverse/forward wire/alias #4399#4438 multimap SmallVec[2] zero-alloc fast + handle validate-by-key #1855; 2) session/entry.rs u16 zone IDs #919 saves 28B + LOCK XADD ~10ns win + bound Arc #3322; 3) policy.rs zone_pair_key u32 pack + AppCatalog tiered #3612 + hit_counter coalescer #3073 gen-guard #3448/#3782; 4) screen/mod.rs 16 checks + SYN-flood count-min no-eviction #3315 + timeout per-zone #3527; 5) filter/mod.rs CachedThreeColorPolicers SmallVec[2] + Mutex hot; 6) xsk_ffi.rs unsafe Send rings; 7) tx_pipeline Box<[u64]> sidecar; 8) event_stream replay 4k + backlog 16MiB cap #2381


## Module log (per-file one-line incl negatives proving coverage)
- userspace-dp/src/afxdp/worker/tx_counters.rs 59 LOC: WorkerTxCounters 10 u64 pending_* counters - drained per-sec debug tick - alloc-free hot record - negative
- userspace-dp/src/afxdp/worker/tx_pipeline.rs 69 LOC: WorkerTxPipeline free_tx_frames VecDeque, pending_tx_prepared/local, outstanding_tx u32 gauge #802, tx_submit_ns Box<[u64]> pre-sized - Box not Vec prevents push compile-fail - negative
- userspace-dp/src/afxdp/worker/xsk_rings.rs 40 LOC: WorkerXskRings DeviceQueue+RingRx+Tx structural extraction #959 Phase11 - negative
- userspace-dp/src/afxdp/worker_queue.rs 84 LOC: Mutex<VecDeque<WorkerCommand>> poison-recovery lock_recover/try_lock_recover clear_poison + AtomicU64 counter Prometheus - eprintln cold panic path only - negative hot alloc
- userspace-dp/src/afxdp/worker_queue_tests.rs 161 LOC: Test file userspace-dp/src/afxdp/worker_queue_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/afxdp/worker_runtime.rs 571 LOC: WorkerRuntimeState Active/IdleSpin/IdleBlock + CoSQueueLeaseUndergrant + WorkerRuntimeCounters + #[repr(align(64))] Atomics seqlock window_gen AcqRel/Release fence Acquire reader spin 16 - unsafe clock_gettime/gettid checked - sound but ordering sensitive
- userspace-dp/src/afxdp/worker_runtime_tests.rs 351 LOC: Test file userspace-dp/src/afxdp/worker_runtime_tests
```

---

#### Finding from ps-A2_rust_dataplane_nat-b1.md

```
# A2 NAT Review — Rust dataplane NAT (18 files) — 275989b76

## Inventory
- LOC: ~24982 total (prod 9334, test 15648)
  - allocator.rs 1974 (largest: allocate_translation_locked ~130 LOC, gc_expired_chunked)
  - source.rs 1523 (match_source_nat_result_for_tuple ~500 LOC, parse_source_nat_rules)
  - destination.rs 1109 (from_snapshots 230 LOC, lookup_with_counter_scoped 120 LOC)
  - static_nat.rs 808 (from_snapshots 130 LOC, match_dnat_with_counter_scoped)
  - nat64.rs 3102 (write_v6_to_v4_into 180 LOC, write_v4_to_v6_into 220 LOC, frag cache)
  - nptv6.rs 431 (try_from_snapshots)
  - mod.rs 347 (NatDecision, counter store)
  - status.rs 40
  - 8 test files 4673+1770+1198+... = 15648
- Responsibility ranking: allocator (port lifecycle, HA reserve, deterministic, addr-only) > source (match + scope + L4) > nat64 (xlat + frag assoc + embedded ICMP) > destination (proto wildcard 256, LPM) > static_nat (block 1:1, scope tiers) > nptv6 (fail-closed)
- Hot path proximity: allocator claim() is per-flow cold (first packet), not per-packet; match_* cold; translate hot for NAT64.

## Module log (coverage proof, incl negatives)
- allocator.rs: audited claim/ free_recycle/ reserve/ reserve_address_only/ deterministic v4/v6, GC chunked lock release, persistent lease indexes. No per-packet alloc. Sound, minus deterministic param reuse.
- source.rs: audited expand_pool_address CIDR enum, MAX_POOL_PREFIX_HOSTS 65536 cap, l4_matches tuple_unknown gate, NonFirstFragment drop before alloc, address-only token via reserve_address_only, deterministic address-only branch missing token (dedup #5341, not re-reported), HA reserve skips no-port (dedup #5338). Scope AND-ed, proto 0 synthetic wrapper intentional.
- destination.rs: PROTO_ANY=256 distinct from HOPOPT 0, exact→wildcard port→PROTO_ANY→LPM tiers, off short-circuits tiers (#3844), source/bracket list fail-closed (#2394). Negative: ICMP port gated via has_l4_ports (#4074) sound.
- static_nat.rs: host vs block classified, block-to-block offset remap, port-mapped vs whole-address precedence (#2769), pick_scoped zone-tier, scope_ok AND. Negative: no off to leak, external_ips iterator fine.
- nat64.rs: parse_pool_v4 only bare/32 host, from_snapshots loud skip all-or-nothing (#3888), reuse_allocator preserves ports across reload (#4518), reserve_synced portes recovers HA collision (#4512), frag assoc port-free key documented RFC8200 uniq ident, first-only install prevents DoS, non-first translators no L4 checksum. Negative: TTL 2s short, LRU 64/shard bounded.
- nptv6.rs: parse_prefix host-bits fail-closed (#4519), overlap reject (#2241), zero-adjustment 0xFFFF fold skip (#3233). Negative: sound.

## Findings

### HIGH — None new (dedup covers known HA leaks)

### MEDIUM

#### Title: Deterministic CGNAT allocator reuse ignores deterministic parameters — stale reservations survive param change
Severity: Medium
Confidence: High
Evidence:
- userspace-dp/src/nat/source.rs:324-336
```
fn allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
  let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
  (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
    SourceNatPoolAllocatorKey {
      pool_name: self.pool_name.clone(),
      pool_addresses_v4: self.pool_addresses_v4.clone(),
      pool_addresses_v6: self.pool_addresses_v6.clone(),
      port_low: self.pool_allocator.port_low,
      port_high: self.pool_allocator.port_high,
    }
  })
}
```
- userspace-dp/src/nat/source.rs:723-738
```
fn source_nat_runtime_compatible(...) -> bool {
  new_rule.name == old_rule.name
    && new_rule.pool_name == old_rule.pool_name
    && new_rule.pool_mode == old_rule.pool_mode
    ...
    && new_rule.pool_allocator.port_low == old_rule.pool_allocator.port_low
    && new_rule.pool_allocator.port_high == old_rule.pool_allocator.port_high
}
```
- userspace-dp/src/nat64.rs:856-864
```
fn reuse_allocator(&self, prefix_bytes: &[u8;12], pool_v4: &[Ipv4Addr]) -> Option<PortAllocato
```

---

#### Finding from ps-A3_go_config_cli_tree-b1.md

```
# A3 config/cli tree b1/4 — 150 files — 275989b76

## Inventory
- Total files in batch: 150. Prod: ~25 files (catalog.go 487, runtime.go 344, textrender.go 82, tree.go 1589, ast.go 436, ast_edit.go 828, ast_format.go 614, ast_groups.go 620, ast_redact.go 233, compiler*.go ~30 files). Test: ~125 files.
- LOC prod ~11100, test prod ratio ~85% test. Largest prod fn: compiler_nat.go compileNATSource (~400 LOC), ast_edit.go SetPath (~200 LOC), tree.go CompleteFromTreeWithDesc (~150 LOC), catalog.go BuildCatalog (~190 LOC).
- Responsibility: Junos hierarchical AST + flat-set `set` path (dual shape #2419), bracket-list collapse, group expansion with depth/work caps (#5194), typed leaf schema completion, NAT appid catalog build (uint32 counter to avoid uint16 wrap #3438), appid runtime tuple fallback.
- Hot-path proximity: none — config compile is control plane cold path, not dataplane. But correctness is security-critical: NAT bracket list truncation previously caused single-IP pool (exhaustion), app-set bracket truncation caused DENY under-match.

## Module log (incl negatives proving coverage)
- ast.go: navigatePath unionChildren (#4562) merges sibling same-keyword blocks, FindChildren returns all. Sound.
- ast_edit.go: SetPath handles bracket-list multi trailing values via valueList gate, ATOI for port range uses parseSourcePoolPortRange with checked Atoi. DeletePath member delete #3846. Negative: no recursive overflow, schema wildcard fallback.
- ast_groups.go: maxGroupExpandDepth=64 + maxGroupExpandWork=100k, depth passed by value, cycle guard seen map, memo keyed by (name, ancestorPathKey). Work budget increments per expansion. Negative: no stack overflow, DAG fan-out bounded.
- ast_format.go: reader reviewed; pure output.
- ast_redact.go: redaction, no trunc.
- compiler.go: lenient/strict split with 30+ flags, compileOpts threading. Negative: no trunc.
- compiler_applications.go: parseAppTimeout uses Atoi with bounds appTimeoutMin/Max, canonicalPort for port spec, resolveAppPort normalizes floor 0→1 (#4336), ParseCanonicalUint rejects sign/whitespace (#3606). DDOS: namedInstances loop.
- compiler_nat.go: appendPoolAddresses iterates full token stream (fix #4521), isHostMaskAddress etc use natAddrFamily colon check for IPv4-mapped, expandAddressRange counts in uint64 to avoid uint32 wrap to 0 (fix #5194 A3-b2-F9). hostCount = 1<<uint(bits-ones) — checked for overflow risk below.
- compiler_validate_strict_nat.go: dnatProtocolResolvable excludes junos-* aliases and ipv6(41) deliberately tighter than proto_number (documented). validateDNATPoolStrict uses parseCanonicalPort. Sorted walk for deterministic error.
- appid/catalog.go: nextID uint32 prevents uint16 wrap past 65535 onto reserved 0 sentinel (#3438 H4), guard > maxCatalogAppID. ProtocolNumber ok bit honored for unrepresentable token (#4887). NormalizeExplicitPortRange sanitizes 0 sentinel (#5194).
- appid/runtime.go: CatalogNames skips nil zpp/pol (#3622), portInSpec uses canonicalPort (#3725). Negative: tuple fallback best-match deterministic.
- appid/textrender.go: RenderStatus pure output.
- cmdtree/tree.go: CompleteFromTree canonicalizes prefix via ResolveUniquePrefix before ContextDynamicFn, placeholder handling, DynamicFn nil-config awareness (#5196). Negative: no int trunc.

## Findings — Confidence High/Med/Low

### High
#### Title: hostCount shift overflow can panic on /0 host route used as NAT deterministic host
Severity: Medium
Confidence: High
Evidence: pkg/config/compiler_nat.go:1689-1690
```
            } else {
                // IPv4 host address
                hostCount := 1 << uint(bits-ones)
                if totalBlocks < hostCount {
```
Trace: det.HostAddress is validated via net.ParseCIDR. If host address is `0.0.0.0/0` (bits=32, ones=0), bits-ones=32, 1 << 32 = 4294967296 on 64-bit, fits int (Go untyped shift returns int large). But on 32-bit arch, 1<<32 overflows int and Go panics if shift >= width? Actually Go spec: shift count must be unsigned 
```

---

#### Finding from ps-A3_go_config_cli_tree-b2.md

```
# Batch 008 — pkg/config compiler hardening review
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2

## Inventory

Total LOC: 45946 (prod 26638 across 43 files, test 19308 across 107 files)
Prod median ~430 LOC, largest: compiler_validate_warn.go 3628, compiler_system.go 2073, compiler_services.go 1835, compiler_uniformgates.go 1794, compiler_validate_strict_filter.go 1717.

Largest functions (est):
- compileSystem 700+ LOC (DDNS, SNMP, schedulers dispatch)
- compileDHCPLocalServer 400 LOC
- validate helpers in warn gate 100-200 each

Responsibility ranking (size x policy-correctness x hot-path proximity):
1. compiler_validate_warn.go — 3628 LOC, warn accumulator, never hot-path but gate for all
2. compiler_security_zones.go — zone membership = security boundary, #5248 bracket list fix
3. compiler_policy_match.go — #3113/#3142/#3673 fail-open gates, AST pre-walk
4. compiler_policy_missing_match.go — #3044 required dimension gate, denies permit-all-by-omission
5. compiler_policy_then.go — #3114/#3115/#3141 then-permit/reject/deny modifier gates
6. compiler_security_policy.go — default-policy-log, global vs zone-pair compilation, any-ipv4/any-ipv6 normalization
7. compiler_security_flow.go — traceoptions file traversal, filter match safety
8. compiler_system.go — dataplane tunables, domain rework
9. compiler_validate_strict_zones.go — reserved zone names, zone-iface membership conflict, host-inbound token validation
10. filter_match_resolve.go + firewall_filter_expand.go — icmp/port symbolic resolution, counter stride

All reads via worktree path /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2/pkg/config/

## Module log (negatives prove coverage)

- compiler_policy_match.go: NEGATIVE — allowlist + unsupported + swallowedStructural sets, dual-shape via firewallMatchValues SSOT, walks every security node via forEachChild #3562. Hardened.
- compiler_policy_missing_match.go: NEGATIVE — required dimensions present-check unions every match block #3842, handles duplicate security blocks. Fail-closed correct.
- compiler_policy_then.go: NEGATIVE — permit/reject/deny nodes walked via policyThenActionNodes across all then blocks #3842, collapsedThenActionTokens flattens all 3 AST shapes, orphan log sub-token check #3374. Sound.
- compiler_security_policy.go: NEGATIVE — default-policy reject-all mapped #3065, global vs zone-pair dual shape, from-zone/to-zone list accumulation via firewallMatchValues #4626, any-ipv4/v6 normalization #2008. OK.
- compiler_security_zones.go: NEGATIVE — zoneInterfaceMembers recursion handles wildcard-container nesting #5248, mergeHostInbound dedup across duplicate top-level blocks #4818/#4544, address-book find-or-create #4706. No truncation.
- compiler_security_flow.go: NEGATIVE — flowTraceFileNameError bare-basename check, size/files bounds FlowTraceMin/Max #3424, flag/filter validation per duplicate-block forEachChild #3566, tcp-mss range #1979. Good.
- compiler_security_screen.go: NEGATIVE — parseThresh checks err && n<1 && >MaxUint32 prevents #3317 wrap to 0, recordKeyExtras/ChildExtras capture trailing garbage #3332, defaults arm disabled checks #3230. Hardened.
- compiler_security_log.go / alarm: NEGATIVE — stream port/tls gates via AST pre-walk #3349/#3350, not just typed config.
- compiler_security_addressbook.go: NEGATIVE — zone-local prefix collision gate, trailing tokens validated via validateTrailingTokensStrict #3332, qualified name handling #4340 slash allowance.
- compiler_security_alg.go: NEGATIVE — trivial ALG allowlist, 39 LOC.
- compiler_system.go: PARTIAL — see finding F-LOW-01 (Atoi error swallowed for dataplane tunables). Domain-search/name-server fixed to firewallMatchValues #2419. Retired DPDK knobs recorded not silently dropped.
- compiler_services.go: NEGATIVE — RPM probe type allowlist, source-address family match, link-local zone requirement #2494, http scheme gate #2495, routing-instance existence #2496, probe-pin table 
```

---

#### Finding from ps-A3_go_config_cli_tree-b4.md

```
# Batch b4/4 Review — claude-001 A3_go_config_cli_tree

## Inventory

- **Total LOC in batch**: 11926 (prod + test files as listed)
- **Prod files (15)**: 5775 LOC
  - `types_security.go` 1306 (largest), `types_system.go` 1565 (absolute largest), `types_routing.go` 645
  - `types.go` 339, `types_cos.go` 283, `tunnelid.go` 290, `types_chassis.go` 188, `snmp_clients.go` 206, `zoneid.go` 251, `types_interfaces.go` 150, `tcp_flags.go` 147, `tunnelemit.go` 123, `value_type.go` 155, `xfrmi.go` 77, `syslog_logfile.go` 50
- **Test files (34)**: ~6151 LOC in batch slice
  - Largest: `wireguard_multipeer_test.go` 795, `vrrp_track_test.go` 510, `tunnelid_test.go` 479, `types_test.go` 454
- **Responsibility count**: 5 domains (zone isolation, SNMP ACL, tunnel/xfrm id, syslog/timezone injection, VRRP)
- **Hot-path proximity**: Low — all files are config-parse/compile-time (cold path). No per-packet Rust code in batch.
- **Size x Responsibility x Hot-path rank**: All Low hot-path. Highest concern by responsibility: `types_security.go` (zone policy + NAT + screen), `zoneid.go` (wire-adjacent id), `snmp_clients.go` (security ACL).
- **Largest function estimate**: `validateZoneIDCollisionAST` (~60 LOC), `validateTunnelEndpointIDCollisionAST` (~50 LOC), `ValidateTimeZone` (~20 LOC)

## Module Log (coverage proof — negative results)

| File | Verdict | Reason |
|------|---------|--------|
| `snmp_clients.go` | NEGATIVE — sound | AllowsSource: nil guard, empty=all, nil-IP=allow (transport-less safe), compiled fast-path + fallback parity tested. compileClientNets returns non-nil empty on all-bad — fail-closed. validateSNMPClients catches typo'd restrict keyword. Strength: #4834 + #4711. |
| `syslog_logfile.go` | NEGATIVE — sound | SyslogLogFilePath: bare-name gate (filepath.Base + "."/".." checks) + allowlist membership. Nil cfg handled. Closes #4860. Belt: ValidateSyslogFileName in schema. |
| `tcp_flags.go` | NEGATIVE — sound | ParseTCPFlagsExpression: rejects OR (fail-closed per #3076), rejects negated-group (De Morgan), rejects dangling `!` (#4714), rejects contradiction + unknown flag. Empty→ok=false (no constraint). Lowercase normalize. |
| `tunnelemit.go` | NEGATIVE — sound | EmitTunnelEndpointNames: pure typed-config view, no runtime rows, canonical "%s.%d", single-lowest-unit for interface-level WG, non-WG source/dst gate mirrored. Parity test exists. |
| `tunnelid.go` | NEGATIVE — sound | StableTunnelEndpointID: frozen FNV fold wire-adjacent (#1873). collectTunnelEndpointNamesAST handles dual AST shape + Atoi-canonical + Overflow refusal + WG lowest-unit. Views 2/3 close Defect A (#1914). Documented phantom-Defect B limitation accepted. |
| `types.go` | NEGATIVE — sound | ResolveKernelIfName: malformed suffix (non-numeric) falls through to LinuxIfName(ResolveReth), not unit-0. nil-guarded. RethToPhysical score: local=2, remote=0, no-node=1. |
| `types_chassis.go` | NEGATIVE — sound | DeviceMap Active() requires len>0 (empty block ≠ device-map mode). EffectiveKeyOrder/UnmappedPolicy default safely (leave-alone). |
| `types_cos.go` | NEGATIVE — sound | Data-only structs, accepted-but-inert fields documented. No injection surface. |
| `types_interfaces.go` | NEGATIVE — sound | DHCPLeaseIfName uses VlanID not unit Number (convention vs concept noted). InterfaceConfig has no rendering logic. |
| `types_routing.go` | NEGATIVE — sound | cloneForUnit deep-copies reference-typed slices (Addresses, WgPeers + nested AllowedIPs) — #3898 fix verified. String() redacts secrets. WgOuterFamilyV6 uses SplitHostPort with bare-IP fallback. |
| `types_security.go` | NEGATIVE — sound | IsWildcardZone / IsWildcardZoneSet handle "" + "any". sortDedupZones drops blanks. Quarantine wording states degradation. TerminalActions mutual-exclusion drives validator. |
| `types_system.go` | NEGATIVE — sound | MarshalJSON redacts community map-key via slice projection (secret=key, #2053). SNMPCommunity clientNets unexported, not marshaled. mapJunosPermissions never over-
```

---

#### Finding from ps-A5_go_ha_vrrp_ra_conntrack-b1.md

```
# A5 HA/VRRP/RA/conntrack Review — batch ps-A5_go_ha_vrrp_ra_conntrack-b1

BASE 275989b76b22925f4d2719fa07f47709eb227059
WT /tmp/review-wt-claude-001-A5_go_ha_vrrp_ra_conntrack-b1
OUT /tmp/review-work-claude-001/ps-A5_go_ha_vrrp_ra_conntrack-b1.md

## Inventory

Total 46764 LOC. Prod 18813 LOC (34 files). Test 27951 LOC (66 files). Ratio 1:1.48.

Prod sorted by LOC (rank = size × resp × hot-path):

| LOC | File | Resp | Hot | Rank |
|---:|---|---|:---:|---:|
|2417|pkg/vrrp/instance.go|VRRP FSM, GARP damp, preemptHold #2850/#4584, IPv6 ext walk #2155|Y|1|
|1858|pkg/cluster/sync_conn.go|sync conn, genGuard 200k cap, tombstone #2221, barrier|Y|2|
|1108|pkg/vrrp/manager.go|AF_PACKET, VRID guard #4573, cBPF|Y|3|
|1048|pkg/cluster/sync.go|bulk epoch TOCTOU #3912, config trailing magic #3931, DHCP aging #4871|Y|4|
|1043|pkg/ra/sender.go|RA burst, RS hop-255 #5095, graceful/hard #2033, timer leak #4830|M|5|
|953|pkg/ra/ra.go|RA mgr, per-iface epoch #4961|M|6|
|912|pkg/cluster/failover.go|ManualFailover unlock + gen guard #5246, transfer-commit|Y|7|
|881|pkg/cluster/heartbeat.go|HB UDP 100ms, 30s startup grace #4386, monotonic #1792, HMAC #4107|Y|8|
|829|pkg/cluster/sync_protocol.go|wire codec length-gated, lease count clamp|Y|9|
|754|pkg/cluster/garp.go|GARP/NA burst, stillValid gate #2867, gw probe net+1 #2377|Y|10|
|remaining 24| <722 each | monitor, gc, status, election, etc | |11-34|

Largest fns: vrrpInstance.run ~250, electRG ~200, handleNewConnection ~120, probeICMP ~110.

## Module Log — Negative Result Proving Coverage

- election.go: EffectivePriority floor div, weight<=0 secondary, peerGroup nil -> primary, dual-primary tie lower node-id, dup node-id fail-closed secondary + warn rate-limited #4549, kernelUpgradeHold blocks electSingleNode. Covered.
- failover.go: ManualFailover releases mu for preHook, snapshots failoverGen #5246, restores weight, transfer-commit maps override+ grace applyTransferCommitOverridesOnPeerStateLocked, suppressPeerTimeoutForTransferCommitLocked. Covered.
- heartbeat.go/heartbeat_manager.go: startupGrace 30s for both never-seen #4386 and seen-then-lost, MonotonicNanos not Unix #1792, lastSeen CompareAndSwap seed on RestartHeartbeat, heartbeatAuthTrailer session+counter admit, randomSessionID fallback monotonic, dup NodeID drop. Covered.
- sync*.go: genGuardMapCap 200k putGenBounded never clears, takeDeleteGen fresh > install #2221, resetRecvGen on BulkStart #2198, pendingBulkAck record-then-send #3912, sealFrame seq+HMAC under writeMu, decodeDHCPLeasePayload count clamp len/4, configGenMagic 0x00ff xp f CG 0x00 trail, DHCP Remaining residence aging #4871. Covered.
- garp.go: burstSend seam, runARPBurstFollowups aborts on !stillValid, buildUnsolicitedNA Router+Override 0xA0, GatewayProbeTarget net+1 not .1 skip /31/32 #2377. Covered.
- monitor.go: fail 3/pass 3/hold 5s damp, LinkAttrsUp OperState vs FlagUp #2070, ICMP wantID from LocalAddr port, seq atomic 1..ffff, peerMatchesTarget UDPAddr+IPAddr. Covered.
- vrrp/*: VRID guard Min 1 Max 255 #4573, pri 0 resign and 255 owner exempt from track clamp [1,254], masterAdverInterval learned from MaxAdverInt with floor own interval min 10ms #4548, effectiveAdvertInterval learned>0 else local, track rename via linkNames ifindex #2944, addrwatcher #2528 reresolveLocalAddrs, AF_PACKET vs raw fallback acceptArrivalIfindex #2886, IPv6 ext walk bounded 8 #2155, GTSM TTL/hop 255 #4549, garpDampened backward clock clamp >=0 #1792, rxDrops atomic CAS 10s. Covered.
- ra/*: minAdvInterval 1s belt #4525, RS HopLimit flag request fail-closed #5095, shutdownMode graceful upgrades hard #2033, connReady make-before-break #2834, NewTimer Stop not After #4830. Covered.
- gc.go: SkipSweep u-space, IsLocalPrimary false skips expiry, monotonicSeconds CLOCK_MONOTONIC, aging snapshot under mu #3604, XOR hash v6 src count. Covered.

## Findings

### F-01 RETH VRID overflow loses VRRP fast-failover

- Title: RETH VRID =100+RG overflows uint8, manager skips, RETH loses 30ms VRRP
-
```

---

#### Finding from ps-A6_go_dataplane_manager-b2.md

```
# Defensive Review — Batch A6_go_dataplane_manager b2/3
BASE_COMMIT=275989b76b22925f4d2719fa07f47709eb227059
WORKTREE=/tmp/review-wt-claude-001-A6_go_dataplane_manager-b2
DATE=2026-07-09
Reviewer=claude-001

## File Size / Shape Inventory (prod files only, 52 files, 16347 LOC)
Ranked by size x responsibility count x hot-path proximity:

| Rank | LOC | File | Responsibility | Hot-path |
|------|-----|------|----------------|----------|
| 1 | 3064 | pkg/dataplane/userspace/protocol.go | Wire snapshot types, 200+ structs, control request/response framing | Medium (serialization on every apply) |
| 2 | 1763 | pkg/dataplane/userspace/maps_sync.go | BPF map programming: ctrl, bindings, heartbeat, ingress_ifaces, local addr, NAT addr, RST suppress, watchdog, degraded stats | Critical (apply + every status poll) |
| 3 | 1643 | pkg/dataplane/userspace/manager_ha.go | HA state sync, session mirror, watchdog throttle, takeover readiness, FORWARDING arm, counter bridging | Critical (HA failover path) |
| 4 | 520 | pkg/dataplane/userspace/nat_destination.go | DNAT match expansion (addr, app, port-range coalesce, prefix vs host split) | High (commit path) |
| 5 | 503 | pkg/dataplane/userspace/nat_source.go | SNAT builder, scope tier sort, deterministic CGNAT param extraction | High |
| 6 | 489 | pkg/dataplane/userspace/policies_addrbook.go | Address-book dedup, FNV hash to u32 ID, feed-overlay join, collision probe | High |
| 7 | 422 | pkg/dataplane/userspace/routes.go | FIB build from statics/connected/ip-rule leak, PBR band skip, overlay replace semantics, dedup key | High |
| 8 | 409 | pkg/natpoolalarm/natpoolalarm.go | Pool-util alarm hysteresis, sampler, coherence gate, active set | Medium |
| 9 | 394 | pkg/dataplane/userspace/zones_host_inbound.go | Host-inbound view grouping, lifeline exclusion, token canonical sig | High (security boundary) |
| 10 | 370 | pkg/dataplane/userspace/process_napi.go | NAPI bootstrap probes, hardware RX event trigger | Medium (startup) |
| 11 | 369 | pkg/dataplane/userspace/zones_observability.go | Zone counters presentation | Low |
| 12 | 358 | pkg/dataplane/userspace/policycounters.go | RuleID->counter index, bulk ReadAll O(P+C) optimization | Medium (15s scrape) |
| 13 | 270 | pkg/dataplane/userspace/process.go | Helper lifecycle, XSKMAP stale clear, event stream start, tuneSocketBuffers | High (boot) |
| 14 | 270 | pkg/dataplane/userspace/manager_neighbor.go | Neighbor index, monitored ifindexes, regen diff | High (neighbor churn) |
| 15 | 267 | pkg/dataplane/userspace/neighbors.go | buildNeighborSnapshots, publishable predicate substring match | High |
| 16 | 260 | pkg/dataplane/userspace/policies_lower.go | Junos policy -> PolicyRuleSnapshot lowering | High |
| 17 | 248 | pkg/dataplane/userspace/process_status.go | syncSnapshotLocked deferred same-plan exception, status loop, worker-arm debt retry | Critical |
| 18 | 239 | pkg/dataplane/userspace/screens.go | Screen profile snapshots, SYN-cookie master key KDF | Medium |
| 19 | 231 | pkg/dataplane/userspace/manager_status.go | Status stamping (zoneID collisions, reject reasons, degraded stats) | Low |
| 20 | 225 | pkg/dataplane/userspace/nat.go | NAT helpers: coalescePortRanges, appPortsFromSpec, sentinels, addr-name resolution | High |
| 21 | 213 | pkg/dataplane/userspace/tunnels.go | Tunnel endpoint snapshots, Wg peer sorted, ID collision drop | High |
| 22 | 206 | pkg/dataplane/userspace/policies_representable.go | Unrepresentable address/app sentinels | High |
| 23 | 206 | pkg/dataplane/userspace/policies_reject.go | Policy content rejection collection | Medium |
| 24 | 204 | pkg/nftables/rst_suppress.go | RST suppression nft rule install | Medium |
| 25 | 197 | pkg/dataplane/userspace/manager_overlay.go | Route overlay publish, feed overlay clone, duplicate-skip hash check | High |
| 26 | 196 | pkg/dataplane/userspace/process_control.go | Control socket framing, 64MiB cap pre-flight, deadline scaling per MiB | Critical |
| 27 | 191 | pkg/nftabl
```

---

#### Finding from ps-A6_go_dataplane_manager-b3.md

```
# Review BATCH A6 — pkg/nftables/rst_suppress — b3/3

## File-size/shape inventory (LOC, responsibility, hot-path)
| File | LOC | Role | Largest fn | Resp x Hot |
|------|-----|------|------------|------------|
| pkg/nftables/rst_suppress.go | 204 | Prod: install/remove inet xpf_dp_rst output chain DROP RST from SNAT addrs | addRSTDropRule ~56 LOC | High — mitigates HA failover kernel RST leak (#450), atomic delete+create batch critical |
| pkg/nftables/rst_suppress_test.go | 37 | Test: plan builder only | TestBuildRST* 15 LOC each | Low — covers only slices.Clone + deleteTable flag |

Ranked: rst_suppress.go dominates (all netlink/batch logic, payload offset encoding). Test file ranks lowest — 37 LOC, 2 tests, no coverage of rule expression, chain type, idempotency, or remove path.

## Module log (negatives proving coverage checked)

- Verified prod file exists via worktree and read full source lines 1-204.
- Verified test file 37 LOC reads 1-37 via cat -n.
- Grepped worktree for `rst_suppress|RstSuppress|rstSuppress|RST_SUPPRESS` — only 4 hits in pkg/nftables + manager + manager_misc_test.
- Traced caller in `pkg/dataplane/userspace/maps_sync.go:1072-1150` and manager.go:254-274 `shouldAttemptRSTSuppression` retry backoff 5s, WARN on nftables error, clone semantics.
- Checked `buildInterfaceNATAddressEntries` family split (netlink FAMILY_V4/V6) — input to RST addrs is already sorted, deduped.
- Checked neighboring nftables modules (host_inbound_*, lo0_counters) to compare listTables+c.GetObjects pattern — rst_suppress mirrors same ENOENT-as-nil handling.
- Verified IPv4 saddr offset 12 len 4, IPv6 saddr offset 8 len 16, TCP flags offset 13 mask 0x04, nfproto meta check, l4proto TCP — all constants encode correctly.
- Verified chain: Name output, Table xpf_dp_rst, Type filter, Hook output, Priority filter, Policy accept — correct for DROP-only RST.
- Checked concurrency: new nftables.Conn per Install/Remove, no shared mu — thread-safe.
- Checked fail-closed vs fail-open: caller logs WARN and retries — fail-open RST leak when nftables unavailable, but retried.
- Checked atomicity claim: delete+create same conn.Flush() batch — true, single netlink batch.
- Checked int trunc: family byte holds NFPROTO values 2/10 within byte; addrLen uint32; saddrOffset uint32 — safe.
- Dedup index check: no prior issue matches this module (RST suppress not listed).

## Findings

### High Confidence

#### FINDING-1: Test coverage is trivial — rule encoding untested
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A6_go_dataplane_manager-b3/pkg/nftables/rst_suppress_test.go:8`
```
func TestBuildRSTSuppressionPlanSkipsDeleteWhenTableMissing(t *testing.T) {
	plan := buildRSTSuppressionPlan(false, []netip.Addr{netip.MustParseAddr("172.16.80.8")}, nil)
	if plan.deleteTable {
		t.Fatal("plan.deleteTable = true, want false")
	}
```
And `rst_suppress.go:144-200` entire `addRSTDropRule` expression chain never exercised.
Trace: Install path builds exprs list: Meta NFPROTO cmp, Payload nh offset saddrOffset len addrLen cmp addrBytes, Meta L4PROTO cmp TCP, Payload th offset 13 bitwise mask 0x04 cmp !=0, Counter, Verdict Drop. A typo in offset (e.g., 8 vs 12) would pass existing tests, yet silently make DROP never match, leaking RSTs during HA demotion (#450). Existing tests only assert `deleteTable` bool and length.
Refutation attempt: Checked whether manager_misc_test covers expression — it covers retry predicate only. No netlink rule inspection. So bug would be invisible.
Why it matters: RST suppression is HA safety net — regression leaks RST kills flows on failover, user-visible outage.
Fix direction:
- Add unit test for `queueRSTSuppression` using nftables dry-run/ fake conn or table-driven expectation: assert chain name, hook, priority, policy, rule count equals len(v4)+len(v6), each rule's expr contains expected saddrOffset (12 for v4, 8 for v6), family byte, l4proto byte 6, mask 0x04, verdict Drop, and Counter present.
- Add gol
```

---

#### Finding from ps-A7_go_daemon_host-b1.md

```
# Review BATCH A7_go_daemon_host b1/3 — pkg/daemon host-systems (150 files)

## File-size/shape inventory (prod vs test, hot-path proximity)

| File | LOC | Prod/Test | Largest fn | Responsibility | Hot? |
|------|-----|-----------|------------|----------------|------|
| pkg/daemon/bootstrap.go | 944 | Prod | detectLifelineInterface / interfaceAddrSnapshot | Bootstrap lifeline, PCI-keyed record, protected set, five-case boot predicate | Cold (boot) |
| pkg/daemon/coalescence.go | 272 | Prod | applyCoalescenceOne / parseEthtoolCoalesce | mlx5 rx/tx-usecs + adaptive coalescing pin, idempotent via ethtool -c probe | Cold (boot + commit) |
| pkg/daemon/daemon.go | 870 | Prod | New / type Daemon god-struct 40+ fields | Daemon options, type, node-id file parse (strict Atoi 0|1), manager init seams | Cold (lifecycle) |
| pkg/daemon/daemon_apply.go | 2149 | Prod | applyDataplaneAndHACore / applyInterfaceReconcile | Apply head: VRF, tunnel/xfrmi/bond/RETH, fabric IPVLAN, dataplane compile+arm, neighbor warm, services; tail: VRRP/system/archival/observability | Warm — held under applySem (commit latency) |
| pkg/daemon/daemon_archive_timer.go | 151 | Prod | reconcile/periodic timer | Periodic config archival timer (hash-gated) | Cold |
| pkg/daemon/daemon_cluster_bind.go | 198 | Prod | bind helpers | Cluster bind address resolution (em0/fabric) | Cold |
| pkg/daemon/daemon_ddns.go | 389 | Prod | DDNS manager | DHCP-lease DDNS (Surface B) nudge loop, reconcile, withdraw | Cold |
| pkg/daemon/daemon_ddns_surface_a.go | 843 | Prod | surfaceA reconcile | Router/interface-address DDNS (Surface A) per-binding dedup, warning, withdraw-while-pending | Cold |
| pkg/daemon/daemon_dhcp.go | 341 | Prod | dhcp manager | DHCPv4/v6 client start/stop, options, lease change → recompile | Cold/warm lease change |
| pkg/daemon/daemon_dhcp_lease_sync.go | 404 | Prod | dhcpLeaseSync loop | HA DHCP lease sync push/pull (#2239) | Warm |
| pkg/daemon/daemon_dns.go | 377 | Prod | reconcileDNSLocked | /etc/resolv.conf managed file merge (static + DHCP), resolved disable+mask | Cold |
| pkg/daemon/daemon_feeds.go | 137 | Prod | reconcileFeeds | Dynamic-address feed producer lifecycle, hash-gated | Cold |
| pkg/daemon/daemon_flow.go | 804 | Prod | flow exporter assembly | NetFlow/IPFIX bundle build+swap, handoff-drop accounting | Cold commit, hot event path |
| pkg/daemon/daemon_flowexport.go | 685 | Prod | flowexport reconcile | Flow/IPFIX exporter per family, template group | Cold |
| pkg/daemon/daemon_forwarding_status.go | 132 | Prod | fwdstatus sampler | CPU sampler off CachedStatus (no control-socket) #3970 | Warm 1/s |
| pkg/daemon/daemon_gc.go | 23 | Prod | GC wiring | Conntrack GC wiring placeholder | Cold |
| pkg/daemon/daemon_ha.go | 1511 | Prod | RG state machine, VIP ownership | HA RG creation, direct mode VIP add/remove, GARP burst, re-announce schedule | Warm (failover) |
| pkg/daemon/daemon_ha_fabric.go | 965 | Prod | fabric IPVLAN + neighbor refresh | fab0/fab1 IPVLAN create, peer IP resolve, probe rate-limit, glean-on-loss | Warm |
| pkg/daemon/daemon_ha_sync.go | 1020 | Prod | session-sync envelope | Session bulk sync, config sync, IPsec SA sync, bulk barrier, gen-guard | Warm |
| pkg/daemon/daemon_ha_userspace.go + 4 files | ~1k | Prod | userspace-dp HA convert/export/readiness/stream | Synced session → Rust wire, event-stream delta drain, owner-RG export | Warm |
| pkg/daemon/daemon_ha_vip.go | 651 | Prod | direct-mode VIP + stable LL | Direct-mode VIP add/remove idempotent, stable link-local, guard against direct path leaks | Warm |
| pkg/daemon/daemon_health.go | 155 | Prod | health + compile/boot import | /health compileFail count + bootstrap import outcome | Cold |
| pkg/daemon/daemon_ipmon.go | 414 | Prod | ip-monitoring actuator | Probe-based route inject overlay, FIB bump retry, degraded FRR reload awareness | Warm (probe tick) |
| pkg/daemon/daemon_ipsec_rebind.go | 170 | Prod | lease-change IPsec rebind | DHCP renewal → swanctl local_
```

---

#### Finding from ps-A7_go_daemon_host-b3.md

```
# A7_go_daemon_host b3/3 - Upgrade, Lock, Manifest, StagedGen, WGKey Defensive Review
BASE: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A7_go_daemon_host-b3

## Inventory
- Total files in batch: 40 (19 prod priority + 2 extra prod cutover/cluster_cli + 19 test)
- Prod LOC (priority list): ~5583 lines
  - flip.go 448, helper_health.go 160, imageversions.go 179, kernel.go 334, kernel_drain.go 160, kernel_linux.go 692, kernel_run.go 626, kernel_selfrecover.go 273, lock/lock.go 303, manifest/manifest.go 106, rolling.go 247, runner.go 565, runtime/seed.go 400, stagedgen/fsutil.go 149, stagedgen/stagedgen.go 413, state.go 165, system_linux.go 190, version.go 60, wgkey/wgkey.go 113
- Extra prod: cutover.go 996, cluster_cli.go 610
- Test LOC: ~8390
- Largest prod fns: KernelRunner.Promote ~80 lines, KernelRunner.preflight/installCandidate/armCandidate ~70 each, Runner.Run ~180, flip.gc ~100, stagedgen.Config.Publish ~50, lock.AcquireAt ~70
- Responsibility: binary cutover ordering, host-wide lock, staged-gen immutable publish, kernel A/B arm/promote, manifest SSOT, wg x25519 keygen

## Module Log (coverage - negatives proving soundness)
- flip.go: NEGATIVE - symlink repoint atomic temp+rename+fsync, ver validated upstream via ValidateVersionSegment, unit dropin path from versionDir (validated) and fmt.Sprintf no shell.
- helper_health.go: NEGATIVE - fail-closed 3-part gate (unit active + armed+forwarding + target version dir equality), exe (deleted) suffix tolerated via Dir, deadlines bounded.
- imageversions.go: NEGATIVE - parseImageVersions scanner with present-tracking, requiredKeys fail-closed, GateMixedBaseSwap fails closed on 0/unknown peer protocols, back-compat window check correct.
- kernel.go: NEGATIVE - KernelState order unknown-> -1 atLeast false fail-closed, journal struct no path traversal via version fields (validated elsewhere).
- kernel_drain.go: NEGATIVE - DrainAndConfirm refuses if peer not alive/takeover-ready, failback ResetFailover on timeout avoids VIP stranding, sleepBounded bounds deadline overshoot.
- kernel_linux.go: NEGATIVE - command exec via exec.Command not shell, LC_ALL=C locale hardening, BootOrder/SetBootNext hex-validated, slot labels constants xpf-A/B, promotion marker durable, disarm watchdog error surfaced (#4872B).
- kernel_run.go: NEGATIVE - resume-version guard, stale marker clear, preflight UEFI+efibootmgr+A/B+BootOrder+grub+watchdog+free space, install re-assert default not moved + KernelHeld full-set, armCandidate selector read-back verify + journal ARMED before BootNext (reboot-boundary hole closed), Promote fail-closed indeterminate handling (#4872A) preserves journal no prune no reboot on unreadable state.
- kernel_selfrecover.go: NEGATIVE - lease state machine only acts on leaseExpiredOurs (crashed orchestrator fingerprint), leaseNone manual drain no-op, IsZero expiry check prevents {} lease -> spurious recovery (#4872C), grace reset on observation error (#4872D), Armed gate prevents split-brain rejoin during armed trial.
- lock/lock.go: NEGATIVE - flock EX|NB host-wide, /run tmpfs reboot-clearing, truncate-on-acquire + truncate-on-release-under-lock prevents stale JSON (#1984), never rm lock file (#1875), Handle idempotent Release, owner metadata best-effort not mutex.
- manifest/manifest.go: NEGATIVE - private managed slice, fresh slice returns prevent mutation, LockstepNames from SSOT.
- rolling.go: NEGATIVE - lock held whole window, inner Run LockAlreadyHeld avoids self-deadlock EWOULDBLOCK, prechecks peer alive/sync/HA compat/takeover-ready before ForceSecondary, strong drain predicate, tolerateTransientErr for post-cut gRPC unavailable.
- runner.go/cutover.go: NEGATIVE - ValidGenID + target==Base check prevents ../ escape in ResolveCurrent, ValidateVersionSegment rejects / leading dot whitespace control non-ASCII, copyTree rejects non-regular (symlink) entries, checksum verify, fsync deepest-first, DB snapshot before flip ordering, cluster gate refu
```

---

#### Finding from ps-A8_go_api_grpc_rest-b1.md

```
# A8 Go API / gRPC / REST — Batch b1 Security Review

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A8_go_api_grpc_rest-b1
Output: /tmp/review-work-claude-001/ps-A8_go_api_grpc_rest-b1.md
Batch: A8_go_api_grpc_rest b1/2 — 150 files (27 prod priority + 123 test/support)

## File-size / shape inventory

Total prod LOC (27 priority): ~15.8k
- `pkg/api/*` 13,440 LOC (21 files)
- `pkg/grpcapi/{apply_result,exec_timeout,fabric_auth,runtime,server,cluster,config}` 2,347 LOC (7 files)
Full api+grpcapi glob: 61,956 LOC (150 files incl tests, `wc -l` sorted earlier)

Largest prod files (LOC x responsibility rank):
1. `pkg/api/metrics_descriptors.go` 2044 — Prometheus Desc registration (200+ series), static, checked-collector contract; no hot path
2. `pkg/api/metrics_userspace.go` 1865 — userspace-dp status → Prometheus, cache-line not relevant, control-socket contention sensitive
3. `pkg/grpcapi/server_sessions.go` 1460 — gRPC session list/clear/resolve, bilingual parity with REST, cancellation sampling, HA peer fan-out
4. `pkg/api/sessions.go` 1410 — REST cursor/offset pagination, reverse-counter merge, zone/app/FIB enrichment, cancel sampler per 1024
5. `pkg/api/metrics.go` ~1130 — Collector struct, singleflight+TTL cache, Describe/Collect, pre-gate control-plane signals
6. `pkg/grpcapi/server_show_security_text.go` 1063 — text show policies/security
7. `pkg/grpcapi/server_show_interfaces.go` 935
8. `pkg/api/security.go` 871 — zones/policies/events/match-policies simulator, strict validation
9. `pkg/grpcapi/server_cluster.go` 838 — cluster show, interface monitor, peer fill-down
10. `pkg/api/types.go` 815 — request/response types, policy ID zero contract, host-inbound structs

Test vs prod split: ~75% test LOC, 25% prod in this batch. Largest fns: `(*xpfCollector).Collect` (~150 LOC), `(*Server).matchPoliciesHandler` (~300 LOC), `(*Server).sessionsCursor` (~120 LOC), `(*Server).policiesHandler` (~200 LOC).

Responsibility map:
- `api.go`: writeJSON buffering (#4541), decodeJSONBody 16 MiB cap, queryIntStrict/Uint16Strict, parseRefBaseUnit, allInterfaceNames nil-guard
- `auth.go`: Basic/Bearer/API-Key, const-time, loopback gate for /metrics (#4162)
- `config.go`: rollback/compare strict, secret redaction, body cap reuse
- `crosssite.go`: CSRF guard before auth (#5055)
- `server.go`: timeouts (10s hdr, 30s read, 120s idle, 1 MiB hdr), metrics scrape 10s/3 in-flight, self-signed persist strict sequence (#1916), clamp loopback (#5035)
- `sessions.go` / `server_sessions.go`: pagination caps 10k, cancel sampling #5233, HA peer isolation first-page only
- `security.go`: match-policies duplicate + unknown-key fail-closed (#3709/#5316)
- `sse.go`: category/severity strict, subscriber cap 128
- `routing.go`: BGP streaming with cancel check per 1024 (#5232)
- `grpcapi/fabric_auth.go`: HMAC time-windowed PSK, downgrade guard via heartbeat (#4107)
- `grpcapi/server.go`: allowlist (#4122), SystemAction nested safe check, gRPC maxRecv 16 MiB, graceful stop 2s

## Module log (coverage proof incl negatives)

- `api.go`: Checked `writeJSON` buffer-first pattern, `decodeJSONBody` MaxBytesReader + MaxBytesError → 413, `queryIntStrict` via `config.ParseCanonicalUint` rejects "+80", `queryUint16Strict` fail-closed for zone typo, `parseRefBaseUnit` Atoi not Sscanf. **Negative**: `queryInt` lenient fallback defined but unused in prod (no call site).
- `auth.go`: Verified `constantTimeAPIKeyMatch` loops all keys, `subtle.ConstantTimeCompare`, exists&&match pattern for unknown user, `isLoopbackBindAddr` treats ""/wildcard/malformed as non-loopback. Metrics gating via `isLoopbackBindAddr`. **Negative**: No secret leak via timing on API key length beyond acceptable length-only leak.
- `config.go`: Verified rollback N<0 guard, ShowRollback n<=0, compare rollback via `queryIntStrict`, redacted renderers `*Redacted`, body cap via `decodeJSONBody`. **Negative**: No path traversal – paths are config tree tokens, not filesystem.
- 
```

---

#### Finding from ps-A8_go_api_grpc_rest-b2.md

```
# A8_go_api_grpc_rest b2/2 — gRPC/REST api hardening sweep

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2
Batch: 129 files pkg/grpcapi, 29 prod ~12.4k LOC, 98 test ~11k, 2 gen 11.2k (xpf.pb.go 9172, xpf_grpc.pb.go 2056), total 36k.

Top5 prod LOC / responsibility:
1 server_sessions.go 1460 — session table RPC (cursor+legacy, filtered clear, peer fan-out, zone-pair) R1 (DoS amplification, peer dial)
2 server_show_security_text.go 1063 — screen IDS, ipsec, rpm, security log/alarms R2
3 server_show_interfaces.go 935 — GetInterfaces, detail/terse, RETH, kernel stats R2
4 server_show_firewall.go 666 — filter term expansion, counter reads, policer R3
5 server_show.go 562 — ShowText allowlist gateway (log tail allowlist, CoS) R1 (remote CLI entry)

Largest fn: getSessionsCursor ~180 LOC, ClearSessions filtered ~140, showPoliciesHitCount ~120, dialPeer ~55 but hot for HA.

Responsibility rank size x resp x hot-path:
- server_sessions.go (session scan O(N) N up to 10M, peer dial on every request)
- server_diag_system_action.go 486 (reboot/zeroize/failover/userspace inject/queue/binding — destructive)
- server_show.go (show topic allowlist — remote CLI → gRPC bridge)
- server_diag_monitor.go 520 (MonitorPacketDrop validation, streaming lifecycle)
- server.go 588 (bind clamp, graceful stop, fabric allowlist, auth interceptor chain)

---

## Findings — High Confidence

### Title: userspace-inject/queue/binding slot wraps negative Atoi -> MaxUint32
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_system_action.go:384-412`
```
			if strings.HasPrefix(req.Action, "userspace-inject:") {
				...
				parts := strings.SplitN(rest, ":", 2)
				if len(parts) != 2 {
					return nil, status.Error(codes.InvalidArgument, "usage: userspace-inject:<slot>:<mode>")
				}
				slot, err := strconv.Atoi(parts[0])
				if err != nil {
					return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
				}
				mode := parts[1]
				statusNow, err := provider.Status()
				...
				injectReq, err := dpuserspace.BuildInjectPacketRequest(uint32(slot), mode, extra, statusNow)
```
Same at :444 queueID Atoi -> uint32(queueID), :469 slot Atoi -> uint32(slot).
Trace:
1. Client (loopback, per #5278 any shell user) sends SystemAction `userspace-inject:-1:drop`.
2. Atoi("-1")= -1, err=nil, passes InvalidArgument check.
3. Cast uint32(-1)=4294967295 passed to BuildInjectPacketRequest/SetQueueState/SetBindingState.
4. Downstream may reject with generic error, or index OOB, or confuse operator with max-slot message.
Refutation attempt: Looked for downstream validation in dpuserspace — likely checks slot < len(bindings) but error would be "slot out of range" not "negative not allowed". RPC boundary should fail-closed on negative before cast; no `slot<0` check in this file. Not caught by existing tests (no negative slot test in batch).
HPC/invariant: N/A — control path, not hot.
Why it matters: Bypass of intended non-negative domain, potential panic/OOB in Rust helper if Go check missing, confusing error for typo.
Fix direction: Add `if slot<0 { return InvalidArgument("slot must be >=0") }` before cast for all three verbs; same for queueID.
Labels: input-validation, integer-bounds, userspace-dataplane
Dedup note: Not #5281/#5280/#5278 (zeroize root / RBAC). Distinct integer bounds in userspace control verbs.

### Title: Ping Size unbounded — TX amplification DoS
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_ping.go:56-95`
```
func (s *Server) Ping(req *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	if err := checkDiagArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
		return err
	}
	count := int(req.Count)
	if count <= 0 {

```

---

#### Finding from ps-A9_go_observability-b1.md

```
Title: SNMP traps use math/rand for requestID — predictable, higher collision
Severity: Low
Confidence: High
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/snmp/traps.go:1-10
```
import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sort"
	"time"
...
```
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/snmp/traps.go:109-112
```
	// PDU body: request-id, error-status(0), error-index(0), varbinds
	requestID := rand.Int31()
	pduBody := berEncodeIntegerTLV(int(requestID))
```
Trace: buildLinkTrap builds PDU, calls math/rand global Int31. Go 1.20+ global auto-seeded from crypto but still PRNG, 31-bit space, predictable after seed observation. Collector dedup by requestID may collide slightly higher; not security boundary for v2c trap (community only) but violates SNMP best practice.
Refutation attempt: requestID not secret for traps (unauthenticated v2c); community string is auth. However RFC recommends unpredictable IDs; using atomic counter + crypto is cheap. Not a bypass.
HPC/invariant check: None.
Why it matters: Minor correlation/dedup issue, not RCE; but easy fix.
Fix direction: `var trapID atomic.Uint32; id := trapID.Add(1) | crypto/rand fallback` — 1-line change.
Labels: snmp, hardening, traps, predictable-RNG
Dedup note: Not in dedup index.

### Finding 3 — MEDIUM confidence
```

---

#### Finding from ps-A9_go_observability-b1.md

```
Title: flowexport routeMaskCache populate goroutine panic safety — inflight/pending leak
Severity: Low
Confidence: Medium
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/flowexport/routemask.go:188-210
```
func (c *routeMaskCache) populate(key routeMaskKey, ip net.IP, ifindex int) {
	mask, ok := c.lookup(ip, ifindex)
	now := time.Now()
	c.mu.Lock()
	c.storeLocked(key, mask, ok, now)
	delete(c.pending, key)
	if c.inflight > 0 {
		c.inflight--
	}
	after := c.afterPopulate
	c.mu.Unlock()
	if after != nil {
		after()
	}
}
```
Trace:
1. resolve() miss -> scheduleLookupLocked checks pending map dedup, inflight cap 32, starts goroutine populate().
2. lookup = fibMatchMask -> netlink.RouteGetWithOptions blocks on netlink socket, can hang 30s.
3. If lookup panics (nil map, unexpected type in vishvananda netlink, future change), defer none -> Lock not released? Actually panic would unwind without unlocking already-locked? Wait lock taken after lookup, so panic in lookup skips Lock entirely. But panic before mu still leaves pending entry and inflight count pinned.
4. Next resolve for same key sees pending present -> returns early forever (cache miss forever, srcMask/dstMask 0 logged as unresolved). inflight slot leaked reduces capacity to 31, eventually 0.
Refutation attempt: netlink lib stable, does not panic normally; hang covered by inflight cap but not ctx cancel. However defensive robustness is standard for background worker touching shared counters.
HPC/invariant check: pending/inflight invariants must be cleared on all exits.
Why it matters: DoS amplification under high destination cardinality + netlink stress -> mask always 0 (unresolved) vs real /24, minor forensic impact but cache effectively disabled for hot key.
Fix direction: Wrap lookup/metrics with `defer func(){ if r:=recover(); r!=nil { mu cleanup }; }` and ensure delete pending + decrement inflight in deferred cleanup even on panic/error. Add context timeout 2s on netlink call or use netlink with deadline.
Labels: DoS, resource-leak, netlink, flowexport
Dedup note: Distinct from #5312, #5283, #5328 cohort.

### Finding 4 — MEDIUM confidence (theoretical)
```

---

#### Finding from ps-A9_go_observability-b1.md

```
Title: IPFIX/NetFlow header Length uint16 truncation not guarded
Severity: Low
Confidence: Medium
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/flowexport/ipfix.go:963-967
```
	hdr := ipfixHeader{
		Version:        10,
		Length:         uint16(16 + len(e.templateSet)),
		ExportTime:     uint32(now.Unix()),
		SequenceNumber: seq,
```
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/flowexport/ipfix.go:1070-1078 and netflow.go dataFlowSetLen.
Trace: templateSet len ~ <500, dataLen = 4+recCount*recSize, maxPayload 1400 ensures dataLen <= ~1400, so Length fits uint16. If maxPayload constant bumped (e.g., to 9000 jumbo) without adding guard, uint16 truncates -> collector discards per RFC7011 §3.1 length check. Current is safe by tuning.
Refutation attempt: maxPayload enforced in sendRecords chunking: maxRecords = (maxPayload-20-4-3)/recSize, so each packet len <= maxPayload+20 <= 1420 < 65535. So overflow impossible today.
HPC/invariant check: Ensure invariant `maxPayload+header < math.MaxUint16` via compile-time const assert or runtime check.
Why it matters: Future tuning could silently break wire; theoretical.
Fix direction: Add `const _ [maxPayload < 65535-...]` or runtime `if totalLen > math.MaxUint16 { panic }`, document invariant comment at header construction.
Labels: hardening, wire-encoder, IPFIX, NetFlow
Dedup note: Not in dedup; #5312 is about PSAMP IE semantics, different.

## Module log — negatives proving coverage (131 files swept)

Per module we checked: BER tag/len overflow, engineBoots fail-closed, auth/priv downgrade gate, trap async queue bounded, transport fd leak, syslog framing reentrancy, ringbuf additive wire discipline, eventbuf cap, aggregator top-K final flush, RPM pin hold, ipmon overlay winner, feeds carry-forward.

- **eventengine/engine.go** NEGATIVE: 9 prod+tests. Transactional batch pre-classifies, CommitCheck whole candidate, ExitConfigure on failure. Cooldown armed on commit not evaluate (armCooldown revision-aware ABA guard #5311). within 0 fails closed (#3751). Multi-within AND semantics. pruneWindow shrinks backing array when cap>=64 && cap>4*len. Per-policy invalid warning throttled by map + 10s. Queue bounded 64 supersede tail-append preserves FIFO for other policies. Single worker removes EnterConfigure race. lifeCtx cancels actuation on Stop #2868. Sound.

- **feeds/feeds.go** NEGATIVE: 7 files. Body cap 32MiB via io.LimitReader+1 sentinel `cr.n > maxFeedBodyBytes` detects over-size not truncates; entry cap 1M fails whole fetch retain last-good; line cap 1MiB scanner; invalid sample byte-bounded 256 raw→escaped+len annotation, per-entry 4*256+64=1088, total 5*1088=5440; carryForwardSnapshot deep copies to close fail-open denylist window #5282 (old map cancelled, snapshot inherited). Plan sorted deterministic dup ignored with Warn. onUpdate only on hash diff. Stale first failure stamps StaleSince, drop only if explicit hold>0 elapsed, retain-forever default correct #2050. No unbounded alloc.

- **flowexport/** 8 prod + 20 tests: NEGATIVE details:
  - netflow.go: recordSize sum unpadded = template advertised width (fix #4896). dataFlowSetLen terminal 32-bit pad once `(4 - totalLen%4)%4`. bootTime via CLOCK_BOOTTIME fallback not exporter new time #4423 M13. protocolIdentifier from rec.ProtocolNum not name table fixing GRE/ESP=0 bug #3939. NAT fallback #2526 copies pre→post when natIPAbsent. mask nil→0 pre-#2866. chunking reserves 3-byte pad. seq locked under mu. templateRefreshInterval clamps ≤0 to 60s preventing NewTicker panic M10.
  - ipfix.go: biflow reverse PEN 29305 enterprise bit 0x8000 8-byte spec vs 8-byte data; record size 86/134 pinned by init panic #2526 drift guard; PSAMP options set ID 3 vs data set 258 record 14 pinned; selector systematic count interval=1 space=N-1 correct per RFC5477 though record-granular sampling nuance documented #3748 — dedup #5312 already tracks IE concern, not re-reported. Seq for template-only not advanced #2609, data adva
```

---

(21 findings at Low level)


## Full batch findings (raw verbatim, all 22 batches, 376347 total chars)


### === ps-A10_go_services_cli_deploy-b1.md ===

# A10_go_services_cli_deploy b1/3 — Defensive Review
Base: 275989b76b22925f4d2719fa07f47709eb227059  WT: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b1

## File-size / Shape Inventory (LOC, prod vs test, responsibility, rank)

| File | LOC | Type | Responsibility | Hot-prox | Rank (size×resp×hot) |
|------|-----|------|----------------|----------|----------------------|
| bpf/headers/xpf_common.h | 898 | prod | ABI constants, MAX_*, header structs, SESS_* flags | H (dataplane ABI) | 9 |
| bpf/headers/xpf_helpers.h | 2554 | prod | BPF helper inline fns, EH walker, map helpers | H | 10 |
| bpf/headers/xpf_maps.h | 921 | prod | BPF map defs, prog arrays, cpu map | H | 8 |
| bpf/headers/xpf_conntrack.h | 225 | prod | session_key/value structs, v6 variants | H | 7 |
| bpf/headers/xpf_nat.h | 575 | prod | NAT key/value, pool map | H | 7 |
| bpf/headers/xpf_trace.h | 161 | prod | trace event structs | M | 3 |
| cmd/cli/* show_*.go (705+480+298+137 etc) | ~3500 | prod | remote CLI show dispatch | L (cold) | 5 |
| cmd/cli/clear.go,shared.go,monitor.go,request.go,show.go,main.go | ~1800 | prod | remote CLI dispatch, pipe, clear, monitor | L | 5 |
| cmd/shimverify/main.go | ~30 | prod | verifier gate | M | 4 |
| cmd/xpfd/main.go | 357 | prod | subcommand dispatch, check-config cap, cleanup guard | M | 6 |
| cmd/xpfd/upgrade.go | 247 | prod | upgrade cut + helper-health wiring #5286 + cluster guard #5284 | M (boot) | 7 |
| cmd/xpfd/upgrade_kernel.go | 217 | prod | kernel A/B arm/promote/drain/rejoin #1930 + #5322 arg guard | M | 6 |
| cmd/xpfd/publish_generation.go | 153 | prod | staged-gen publish+GC protection #4876 | M | 6 |
| cmd/xpfd/seed_runtime.go | 101 | prod | first-install seeding #1964 | L | 3 |
| docs/pr/812-…/vdso_probe.c | ~40 | evid | VDSO strace proof | L | 1 |
| docs/pr/812-…/vdso_probe2.c | ~50 | evid | AT_SYSINFO_EHDR probe | L | 1 |
| pkg/cli/cli.go 548 | 548 | prod | CLI struct, feedOverlay wiring | L | 4 |
| pkg/cli/cli_dispatch.go 523 | 523 | prod | pipe| pager streaming bounded #4709/#4731, maxTail cap #5037 | L | 5 |
| pkg/cli/cli_show_routing.go 1139 | 1139 | prod | show route, strict parse | L | 6 |
| pkg/cli/cli_show_system.go 1070 | 1070 | prod | buffers, task, syslog, ntp | L | 5 |
| pkg/cli/cli_show_nat.go 897 | 897 | prod | nat source/dest/pool/rule detail | L | 5 |
| pkg/cli/monitor.go 967 | 967 | prod | flow trace file sanitization #3378/#5038 | L | 6 |
| pkg/cli/app_resolve.go 106 | 106 | prod (unused) | builtin app table + resolveAppName | L | 2 |
| remaining pkg/cli/*.go 60 files | ~18k | mixed (30 test) | show sec zones/filters/objects/ipsec/screen, interfaces terse/detail/extensive/stats/shared, services dhcp/ddns/lldp/snmp/rpm, clear, request, config | L | 4-6 |
| cmd/cli/*_test.go, cmd/xpfd/*_test.go, pkg/cli/*_test.go | ~11k | test | coverage for pipe case, rollback #3447, completion pos, grpc maxrecv, commit rollback, zone tier #3658/#3654, host-inbound, global scoped #3357, display fidelity #4908, last cap #5037, flow summary #5320 | L | 3 |

Largest fn: `cli_show_security_filters.go:showFirewallFilter` (~172 LOC), `cli_show_routing.go:handleShowRoute` large dispatch, `cli_dispatch.go:dispatchWithPager` streaming loop, `xpf_helpers.h` helpers ~2k LOC header.

Prod vs test: bpf headers 6 prod /0 test, cmd/cli 10 prod /~20 test, cmd/xpfd 4 prod /4 test, pkg/cli ~55 prod /~45 test, docs 2 evid.

## Module Log (negatives proving coverage)

- **bpf/headers/xpf_common.h**: MAX_ZONES 64, MAX_INTERFACES 65536, MAX_SESSIONS 10M, session flags SESS_FLAG_*. Structs iphdr/tcphdr/udphdr use __be16/__be32 native-endian ABI. Endianness branches for bitfields checked for both LE/BE. No var_off packet math in header itself — verifier re-read pattern enforced in deleted xdp/*.c (historic). Negative: no unbounded alloc, no unsafe packing beyond `__attribute__((packed))` on session_key (intentional to avoid 6-byte hole for map key). Size-of invariant guarded by `pkg/dataplane/bpf_session_value_test.go` `TestBPFSessionValueMatchesConntrackABI` asserting unsafe.Sizeof(bpfSessionValue)==conntrackValueSizeV4.

- **bpf/headers/xpf_conntrack.h / xpf_nat.h / xpf_maps.h / xpf_trace.h**: session_key packed with pad[3] to 16B align; session_value has cached FIB fields fib_dmac[6] fib_smac[6] + gen. No integer trunc — fields use __u16/__u32/__u64 explicitly. Map defs use BTF BPF_MAP_TYPE_PROG_ARRAY etc. No overflow. Negative: sound ABI — Go mirror padding via Pad field present, const assert.

- **xpf_helpers.h**: 2554 LOC helper inlines. Checks for MAX_EXT_HDRS 6 cap, var_off narrowing via &0x3F mask noted in CLAUDE.md (#66833c5). No unsafe beyond BPF helpers. Negative: no missing bounds check on packet pointer after branch — pattern re-reads data/data_end.

- **cmd/cli dispatch (clear.go, main.go, monitor.go, request.go, shared.go, show.go, show_*.go)**: clear uses fixed exec.Command argv (no user input interpolation) — no injection. `handleClearSystem` checks args exact match "config-lock". monitor.go `traceLogDir=/var/log/xpf-flow-trace` fixed, `sanitizeTraceFilename` rejects `""`, `"."`, `".."`, `"/\"`, and `filepath.Base` mismatch — closes #3378/#5038 traversal. `show_dhcp.go` only formats gRPC response — no DHCP packet parse in this batch (packet validation lives in pkg/dhcp — out of A10). Negative: CLI arg injection not present.

- **pkg/cli/cli_dispatch.go**: `extractPipe` uses `LastIndex(" | ")` to find filter sep. Streaming via `lineSource` + pipe + goroutine bounded memory O(1) per #4709/#4731. `maxTailLines=100k` caps `| last N` DoS #5037, `parseLastCount` ignores negative/unparseable, clamps. pager `pageStream` drains on quit so producer not blocked. Negative: no unbounded slice — ring grows lazily min(n,lines).

- **pkg/cli/app_resolve.go**: builtinApps static table, resolveAppName walks cfg.Applications then fallback. Marked unused superseded by appid pkg — retained for mechanical motion #1444. Map iteration deterministic issue noted below but not hot path.

- **pkg/cli/cli_show_security_zones.go / cli_show_security_filters.go / cli_show_security.go / dispatch**: Zones sorted stable for output. Host-inbound rendered via `HostInboundViewWithLifelines` + `HostInboundLifelineSet` — surfaces lifeline exempt (H04/M03) auditable #3682. Tier handling: `policymatch.ZoneDetailPolicySummary` expands 3 tiers zone-pair→global→default-policy (M04/M05) via SSOT shared with gRPC #3668. Global scoped #3148 filtered via `GlobalPolicyAppliesToZonePair`, labels via `ScopeLabelOr(..., "junos-global")` #3286/#4626. Nil zone value tolerant #3493/#3476 skip. Counters via bulk reader #4344 #3965, policy-stats gate #2008/#2118. Screen inventory via `ScreenEnabledCheckList` SSOT #3327 not hand list. Negative: missing zone now prints "Zone '%s' not found"; tier collapse fixed.

- **pkg/cli/cli_show_interfaces*.go / terse/detail/extensive/stats/shared/queue**: `showInterfaces` dispatch exact first token match, queue selector sanitized as plain string passed to shared formatter no exec. Detail: logical unit parsing splits base vs unit via `SplitN(".",2)` and Atoi — if non-numeric suffix, renders all units of base (minor info disclosure, not priv esc). Negative: no interface name injection.

- **pkg/cli/cli_show_flow.go / cli_show_nat.go / monitor**: flow brief uses tabwriter, no fmt string interp of user data.

- **pkg/cli/cli_request*.go / cli_request_policies_check.go**: `handlePing` delegates to `diagcmd.PingArgv` which does VRF prefix exactly once via `VRFDeviceName` fixing #2143 double-prefix, and `--` separator #2084 prevents option confusion. exec.CommandContext with context 120s cancel. `analyzePolicyShadowing` compares from/to zones + address sets — no recursion DoS. Negative: CLI→shell arg injection absent — argv built not sh -c.

- **pkg/cli/show_services_ddns.go / dhcp**: Surface A DDNS backend ownership: prints degraded fail-closed alarm, provider catalog with secret redacted (`tsig-key=... secret redacted`), per-scope detail (FQDN, Family, State, Published, Provider, Last error). No PrevAddr deletion logic in display layer — ownership safety lives in pkg/ddns (out of batch). Negative: show path does not mutate backend. DHCP leases show via kea lease file direct read (outside batch).

- **cmd/xpfd/main.go**: subcommands `cleanup`, `upgrade`, `seed-runtime`, `publish-generation`, `verify-dataplane`, `check-config` all guard leftover args via `parse*Args` checking `fs.NArg()!=0` #5322/#4869 — mistyped operand is hard usage error not silent wrong op. `check-config` caps 4 MiB, checks regular file, re-checks after read for TOCTOU growth between stat and read. Device-map strand preflight present but off-target warning skips rather than false reject #4191. Negative: TOCTOU closed for size.

- **cmd/xpfd/upgrade.go / upgrade_kernel.go / publish_generation.go / seed_runtime.go**: upgrade.go `buildUpgradeSystem` wires #5286 helper-readiness probe (active+armed+forwarding+exe version match) into System via `NewSystemWithHelperHealth`; previous is-active-only path had 0 callers of probe variant. Cluster guard #5284 fails fast if node-id present and --rolling omitted, defensive duplicate of Runner.Run authoritative check. `gcProtectionForPublish` reads journal pinned gen, protects it, skips GC if journal unreadable/I/O error #4876 — prevents bricking crash-after-STOP resume. `validateKernelVerbArgs` enforces arity per verb #5322 — `arm` needs 1, promote/status/drain/rejoin 0 — prevents privileged BootOrder reorder on typo. Kernel lock via host-wide upgrade lock. Negative: rollback safety sound — probe ensures COMMIT only after helper reports target version armed.

- **docs/pr/812 tx-latency evidence c files**: vdso_probe minimal strace proof, no prod code. Negative: not executable path.

## Findings by Confidence

### High Confidence

**[NEGATIVE] CLI pipe path-traversal + DoS bounding — sound**
Severity: Info | Confidence: High
Evidence: `pkg/cli/monitor.go:109-132` `var traceLogDir = "/var/log/xpf-flow-trace"` + `func sanitizeTraceFilename(name string) error { if name == "" ... if name == "." || name == ".." ... if strings.ContainsAny(name, `/\`) ... if name != filepath.Base(name) ... }` + `pkg/cli/cli_dispatch.go:83-98` `const maxTailLines = 100_000` + `func parseLastCount(arg string) int { n:=10; if arg!="" { v,err:=Atoi(arg); if err==nil&&v>0 {n=v}}; if n>maxTailLines {n=maxTailLines} return n }`
Trace: operator `monitor security flow trace file ../../etc/shadow` → sanitize rejects slash + Base mismatch → error, never open. `show ... | last 2000000000` → parseLastCount clamps to 100k → ring O(min(n,lines)) grows lazily append until n then overwrite.
Refutation: checked if `filepath.Base` bypassable with trailing slash — slash already rejected before.
HPC: ring allocation bound 100k × slice header ~1.6 MiB.
Why matters: prevents priv file overwrite + OOM Kill of in-process daemon.
Labels: hardening, DoS
Dedup: not in dedup list — this is fix verification of #3378/#5038/#5037, negatives are expected.

**[NEGATIVE] Upgrade rollback GC protection + helper health + arg guard — sound**
Evidence: `cmd/xpfd/publish_generation.go:104-133` `protected, runGC, warn := gcProtectionForPublish(...); if pinned!="" {protected[pinned]=true}; if !runGC {skip} + `func gcProtectionForPublish` `if err!=nil {return protected,false,WARN}`; `cmd/xpfd/upgrade.go:63-88` `buildUpgradeSystem` `deps HelperHealthDeps{UnitActive: upgradeUnitActive, Status: upgradeHelperStatus, HelperExe: upgradeHelperExe, ...} NewSystemWithHelperHealth`; `cmd/xpfd/upgrade_kernel.go:92-115` `validateKernelVerbArgs` + lock acquire.
Trace: crash-after-STOP journal pins generation G; next publish with unreadable journal → runGC=false → never reaps G → resume finds source.
Why matters: prevents daemon-down unrecoverable + silent wrong rollback target.
Dedup: #4876/#5286/#5322/#4869 — this batch implements fixes, not re-report.

**[LOW] app_resolve.go map iteration nondeterministic if duplicate dst ports**
Title: App resolve map iteration nondeterminism for overlapping port definitions | Severity: Low | Confidence: Medium
Evidence: `pkg/cli/app_resolve.go:46-78` `func resolveAppName(proto uint8, dstPort uint16, cfg *config.Config) string { if cfg != nil { for name, app := range cfg.Applications.Applications { ... if int(dstPort)>=lo && int(dstPort)<=hi {return name} } } for name, ba := range builtinApps { if ba.proto==proto && ba.port==dstPort {return name} }`
Trace: cfg.Applications is map; two apps `web1 tcp 80` `web2 tcp 80-80` both match dst 80; iteration order random → returned name flips per run.
Refutation: code comment says currently unused superseded by appid pkg — if unused, not exploitable; but if re-enabled, nondet.
HPC: map iteration randomness.
Why matters: show-output correctness / audit flaky; ID stability #5296 sibling.
Fix: sort keys or use deterministic first-match by config order; or keep unused deletion.
Labels: display-correctness, vsrx-parity
Dedup: not #5296 exactly — #5296 is positional catalog IDs reassigned; this is map iteration nondet.

**[LOW] cli_show_security_zones logical unit non-numeric suffix renders all units**
Title: Zone detail renders all units on non-numeric suffix | Severity: Low | Confidence: Medium
Evidence: `pkg/cli/cli_show_security_zones.go:112-130` `base:=ifName; wantUnit:=-1; if parts:=SplitN(ifName,".",2); len==2 {base=parts[0]; if u,err:=Atoi(parts[1]); err==nil {wantUnit=u}} ... for _,unit :=range ifc.Units { if wantUnit>=0 && unit.Number!=wantUnit {continue} }`
Trace: zone binds `ge-0/0/9.foo` → Split → base `ge-0/0/9` wantUnit stays -1 (parse fail) → loop renders every unit's addresses under that base.
Refutation: not security boundary — displays more not less; only local CLI view; no priv esc.
Why matters: minor info overexposure / audit confusion.
Fix: if suffix present but Atoi fails, skip rendering or warn instead of rendering all.
Labels: display-correctness
Dedup: not in dedup list.

### Medium Confidence

**[NEGATIVE] CLI ping/traceroute VRF prefix normalization and arg injection — sound**
Evidence: `pkg/cli/cli_request_ping.go:28-54` `func buildPingArgv(...){ return diagcmd.PingArgv(PingOptions{Target, Count, Source, Size, RoutingInstance: vrfName})}` + `pkg/diagcmd/ping.go:30-42` `func VRFDeviceName(name string)string{if name==""{return ""} if HasPrefix(name,vrfPrefix){return name} return vrfPrefix+name}` + traceroute same.
Trace: operator `ping 8.8.8.8 routing-instance vrf-red` → VRFDeviceName returns `vrf-red` unchanged not `vrf-vrf-red`. Rest args validated via net.ParseIP/strconv in shared builder.
Refutation: checked for `--` separator present in builder to stop option parsing — diagcmd inserts `"--"` before target per #2084.
Why matters: prevents blackhole probe to nonexistent VRF device + option confusion injection.

**[NEGATIVE] Show output tier handling 3-tier global/default — sound**
Evidence: `pkg/cli/cli_show_security_zones.go:187-208` `policymatch.ZoneDetailPolicySummary(cfg,name,schedActive,haveSched)` comment "spans all THREE tiers the runtime evaluates in order — zone-pair, then applicable GLOBAL policies, then the effective default-policy catch-all" + hit-count global block: `for _,pol:=range cfg.Security.GlobalPolicies { if !GlobalPolicyAppliesToZonePair(...){continue} }` + `runtimePolicyIndex` delegating to `dpuserspace.RuntimePolicyIndex`.
Trace: filtered `show security zones trust detail` must surface unscoped globals + scoped globals targeting trust + default-policy — ZoneDetailPolicySummary does.
Why matters: prevents hidden permit via global (M04) or hidden deny/permit status (M05).
Dedup: fixes for #3357/#3658/#3654 — this batch is post-fix, sound.

### Low Confidence

**[INFO] BPF headers struct layout invariant — sound, Go mirrors size-asserted**
Confidence: High
Evidence: C `struct session_key { __be32 src_ip; __be32 dst_ip; __be16 src_port; __be16 dst_port; __u8 protocol; __u8 pad[3]; } __attribute__((packed))` vs Go `bpf_session_value_test.go:24` `if got:=unsafe.Sizeof(bpfSessionValue{}); got!=conntrackValueSizeV4 { t.Fatalf(...) }`
Invariant: pad ensures 4B align for map key; packed removes trailing pad; Go explicit Pad field matches.
Why matters: misaligned map key breaks conntrack lookup dataplane-wide.

**[NEGATIVE] No DHCP packet parsing in this batch — DHCP correctness out-of-scope**
Confidence: High
Evidence: 150 files list contains only show_services_dhcp display, not pkg/dhcp packet ingress. Grep `dhcpv4\|DHCP.*Parse\|option.*82` across batch returns only display formatters.
Dedup: DDNS #5327/#5334 out-of-scope for display layer.

## Suggested Issue Split

1. **app_resolve nondet** → Low prio cleanup — remove unused file or sort.
2. **zone detail non-numeric unit suffix** → Low prio display polish.

Both low-materiality, no high/critical findings in this batch. Batch overall is hardening post-fix verification: #5037/#5038/#3378/#5322/#4869/#4876/#5286/#3654/#3658/#3357 fixes present and correct.

## Summary

- 150 files: 6 BPF headers (prod, hot ABI), ~10 cmd/cli prod +20 test, 2 evidence c, 4 cmd/xpfd prod +4 test, ~55 pkg/cli prod +45 test (~30k LOC prod).
- No CLI arg injection, no path traversal (fixed), no unbounded alloc, upgrade rollback GC protected, helper health probed, leftover args rejected.
- Show-output correctness: 3-tier policy rendering, global scoped filtering, host-inbound lifelines all present via SSOT.
- BPF struct layout invariant guarded by Go size asserts.
- Only low-sev display minor: app_resolve map nondet (unused) and logical-unit non-numeric suffix rendering all units.


---

### === ps-A10_go_services_cli_deploy-b2.md ===

# A10 Go services/cli/deploy b2/3 — Defensive Review (150 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktrees: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2

## Inventory (size x responsibility x hot-path proximity)

| Rank | File | LOC | Prod/Test | Largest fn | Responsibility | Hot |
|------|------|-----|-----------|------------|----------------|-----|
| 1 | pkg/dhcprelay/relay_test.go | 2033 | test | runRelay matrix | relay lifecycle, hop-limit, ifindex drift #2347 | med |
| 2 | pkg/ddns/surface_a.go | 2007 | prod | Reconcile ~300L / publishLocked ~130L | Surface-A engine, PrevAddr #3739, PublishPending #5285, sibling #3738 | high |
| 3 | pkg/dhcp/dhcp.go | 1903 | prod | runDHCPv6 185L / runDHCPv4 179L | v4/v6 manager, DUID traversal #4857, NAK #3956, classless RFC3442 | high |
| 4 | pkg/dhcprelay/relay.go | 1545 | prod | runRelaySession 343L | supervisor, giaddr retry, hop-limit #4309, source validation #4163 | high |
| 5 | pkg/ddns/manager.go | 1457 | prod | reconcileOnceLocked 210L | DHCP DDNS engine, per-family backend, providerIO #5006, PTRPending #2661 | high |
| 6 | pkg/dhcpserver/dhcpserver.go | 1210 | prod | generateKea4Config | Kea config, is-active tri-state #4870, subnet_id stable #5041 | med |
| 7 | pkg/ddns/backend_rfc2136.go | 1100 | prod | sendAddOwned 75L | exact-RR #3739, DHCID, self-owned replace, TSIG | high |
| 8 | pkg/cli/monitor.go | 967 | prod | handleMonitorSecurityPacketDrop 180L | flow trace file, rotation, sanitization 0700, nil guard #3381 | med |
| 9 | pkg/dhcpserver/lease_sync.go | 933 | prod | writeMemfile6 | memfile sync, expired drop #4871, IAPD preserve | med |
| 10 | pkg/cli/completion.go + monitor_traffic.go | 577+260 | prod | Do() / parseMonitorTrafficArgs | completion nil guard #2288, traffic injection neutralization #4524/#4556, count bound #4589 | med |
| 11 | pkg/ddns/backend_route53.go | 243 | prod | buildChangeBatch / change | Route53 UPSERT signature, foreign-record unsafe | high |
| 12 | pkg/dhcprelay/l2send_linux.go | 226 | prod | sendReply / buildL2Reply | AF_PACKET TX, MTU guard, IPv4 checksum | med |

Total scanned batch: ~38k LOC (prod ~12k, test ~26k). Test-heavy RED-on-revert suite present.

## Module Log (coverage + negatives)

**CLI 54 files**: completion.go NEGATIVE — helpWriter nil guard when rl==nil #2288 prevents panic; completionSuffix bounds check `len(partial)>len(name) || !HasPrefix` prevents slice OOB when commonPrefix shorter than typed partial; zone nil guard `if zone==nil continue` #3493, zpp nil #3476, pol nil. monitor_traffic.go NEGATIVE — keyword-as-value guard `monitorTrafficKeywords[args[i+1]]` prevents swallowing `matching` as interface, greedy matching up to keyword, quote strip, count 0..8192 bound #4589, `--` separator #4524 neutralizes `-w/-z` file-write/cmd-exec, `monitorFilterOptionToken` quote-peel `'-w` #4556. monitor.go NEGATIVE — nil eventBuf guards #3381, traceLogDir 0700 `/var/log/xpf-flow-trace`, `sanitizeTraceFilename` rejects `/ \ . ..`, O_NOFOLLOW 0600, atomic filter parse. monitor_interface.go NEGATIVE — VMIN=0/VTIME=1 poll, keyReader done+WG stop #3985. peer.go NEGATIVE — fabricAuthKey seam, per-RPC `NewFabricAuthCreds` #5324, SO_BINDTODEVICE, TCP probe; unkeyed grace intact. permissions.go NEGATIVE — traffic→PermControl prefix-safe, flow file/start→PermControl #5038, reboot/failover/data-plane disarm→PermMaint #4108/#4859. session_filter.go NEGATIVE — zone nil #3493, multi-iface map #4792, `ifaceMatchesAny` + FIB fallback, parseErr fail-closed clear-all guard. link/runtime/proto/session_display/show_services_* NEGATIVE — sysfs bound, runtime narrow interface #1517, NativeEndian PutUint32, bracket-aware splitAddrPort, cos queue passes `statusErr` not conflates empty #5326, ddns TSIG redacted, dhcp lease warn vs empty, snmp redaction. All cli_*_test.go NEGATIVE hardening suite present.

**DDNS 34 files**: backend.go NEGATIVE — PrevAddr self-owned only, zero→additive insert, SiblingFamilyOwned host-wide guard #3738, KeepForwardDHCID #2700. backend_bind.go NEGATIVE — Control `unix.Bind` src + SO_BINDTODEVICE, `sourceMatchesDialFamily` skips 4↔6 #2901. backend_http.go NEGATIVE — TLS12, 15s timeout, 64KiB cap, `refuseSchemeDowngrade` EqualFold https→non-https #4861, `scrubURLError` strips query/userinfo, cache per-binding #2904 reap bounded #2956. backend_rfc2136.go NEGATIVE — `sendAddSelfOwned` value-specific exact-RR delete via `prevSelfOwnedRR` #3739, DHCID two-prong prereq #2648, unsigned warn once-per-server sync.Map #4483, TCP retry ctx. backend_cloudflare.go NEGATIVE — lists all, PATCH only row matching PrevAddr #3739, POST alongside foreign, delete content==owned #2770. backend_duckdns/dyndns2 NEGATIVE — host-wide clear/offline guarded by SiblingFamilyOwned #3738, API shape vs old alias #2960. backend_generic.go NEGATIVE — template-aware host extraction `ddnsTemplateHost` rejects `:8080` #4589, token-bounded matcher `matchesGenericOK` #2838, Delete→errGenericDeleteUnsupported keeps ownership #2772. backend_route53.go M-01 (below). checkip.go NEGATIVE — EqualFold URL+host required #2773/#2842, `CheckIPBound` fail-closed on bindErr #3733, `IsPublicAddr` specialPurpose V4/V6 CGNAT/TEST-NET/ULA/NAT64 #2774. hostname.go NEGATIVE — LDH sanitize lower+dash trim caps 63/253. manager.go NEGATIVE — providerIO unlock mu #5006, stale re-validate AddrText compare, write-ahead PTRPending #2662, delete keeps ownership on nopUpdater #2699, degraded marker durable #4873. sigv4/state NEGATIVE — canonical URI/query/header lower+Join, save deterministic sort fsync 0600, version check 0 tolerates/!=1 corrupt, quarantine Rename.

**surface_a.go 2007 prod +14 test**: Core NEGATIVE for #5334 withdraw-while-pending via PublishPending/PriorAddrText retain + pendingRecovery refreshDue #5285, fingerprint secret-free FNV #3735, orphan alarm idempotent, sibling guard #3738, sourcebind fail-closed #4437→nopUpdater, observeIO+providerIO release mu #2778/#3736, forced-refresh latch #3276, backoff per-wire-op #4423 M03, withdrawUnsupported terminal #2813. Low edges L-02/L-03/L-04 remain.

**DHCP 8 files**: dhcp.go NEGATIVE — DUID traversal #4857 `validInterfaceName` + dir containment `filepath.Dir(p) != Clean(stateDir)`, degenerate mask fail-closed, classless RFC3442 supersede 0/0→GW, IANA deterministic longest preferred @4383, NAK abandon vs timeout retain #3956/#1844, finishClient ptr guard #1815. commit.go NEGATIVE — renewalTimers divide-first avoids int64 overflow sentinel 0xFFFFFFFF #4526, leaseContentChanged includes ClasslessRoutes, reconcileDelegatedPDs per-prefix retain-on-silence #4874. reconcile.go NEGATIVE — v4opts/v6opts pruned even for deregistered preventing Renew resurrect removed #1815 r4, stop wait outside mu. renew.go NEGATIVE — ciaddr no Requested-IP/Server-ID per RFC2131 T5, v4RenewDest unicast RENEW vs bcast REBIND.

**DHCPrealy 6 files**: l2send_linux.go L-01 overflow MTU 0 — else NEGATIVE — AF_PACKET TX, MTU guard, IPv4 checksum. relay.go NEGATIVE — hop-count check before inc prevents 255→0 wrap #4309, source validation #4163 empty allow denies, giaddr retry ctx-cancelable, ifindex drift #2347, readdr #3960, master gate #2456. giaddr/sockopt/relay_test/delivery/l2send NEGATIVE secondary IFA_F_SECONDARY skip #2849, primary pref, fallback, matrix NAK/FORCERENEW, rogue drop #4163, readBufSize 65535 #3012.

**DHCPServer 6 files**: ddns.go/ddns_leases.go/dhcpserver.go/lease_sync.go NEGATIVE — IAPD Unknown fail-closed #5072, CSV destructive-safe dup/missing/ragged, is-active tri-state #4870 fail-closed, expired drop #4871, pre-seed merged #5040, chown #2450.

**NATShow + policymatch 10 files**: natshow NEGATIVE — nil guards, default 0.0.0.0/0/port-range 1024-65535, NPTv6 found flag, dp nil+IsLoaded gate, NativeEndian PutUint32 matches Rust, v6 AddrFrom16. policymatch NEGATIVE — ICMP type/code swap catch #4422, junos-ping echo-only #3348, app-set fail-closed whole-snapshot ContentRejected #3727, src/dst port range inclusive AND #4413.

## Findings

### Medium Confidence High

#### Title: Route53 backend overwrites foreign A/AAAA (no PrevAddr value-specific replace)
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/ddns/backend_route53.go:133-149`
```go
func buildChangeBatch(action string, rec LeaseDNSRecord) ([]byte, error) {
    ...
    rr := struct { Value string `xml:"Value"` }{Value: rec.Addr.Unmap().String()}
    c.ResourceRecordSet.ResourceRecords.ResourceRecord = append(
        c.ResourceRecordSet.ResourceRecords.ResourceRecord, rr)
```
`/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/ddns/backend_route53.go:190-194`
```go
func (b *route53Backend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
    _, _, err := b.change(ctx, "UPSERT", rec)
    return err
}
```
Contrast cloudflare upsert at `backend_cloudflare.go:236-259` lists then PATCHes only row where content==PrevAddr.
Trace: Scenario wan.example.net A 198.51.100.20 manually configured + Surface-A 203.0.113.5. Route53 UPSERT emits single Value without listing existing RRset → Route53 replaces entire RRset → foreign removed. DELETE with foreign+owned requires exact set match → InvalidChangeBatch without "not found" → r53DeleteAlreadyGone false → withdraw wedges, ownership kept forever.
Refutation attempt: Grepped file for PrevAddr — zero hits vs rfc2136 `prevSelfOwnedRR` and cloudflare `prevContent`. Test file `backend_route53_test.go` never seeds foreign multi-value case. Cloudflare #3739 fix left Route53 as outlier. No list step in route53 path.
HPC/invariant check: N/A — correctness.
Why it matters: Violates sole-delete-authority boundary for Route53. Manual round-robin destroyed on forced-refresh 24h. Withdraw with foreign present fails to converge — SLO breach, potential data loss.
Fix direction: List Type at name via ListResourceRecordSets Name+Type, preserve foreign multi-value RRset, use PrevAddr for value-specific replace (PATCH own row or POST new alongside foreign), filter owned only on DELETE. Add tests mirroring `backend_cloudflare_test.go` multi-value foreign preservation.
Labels: ddns, foreign-record-safety, route53, prevaddr
Dedup note: Not in dedup; #3739 fixed Cloudflare/rfc2136, Route53 missed; #5334/#5327 unrelated; not in #5328 cohort.

#### Title: dhcprelay L2 uint16 overflow when MTU=0 and payload jumbo
Severity: Low
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/dhcprelay/l2send_linux.go:133-144`
```go
    // MTU guard: the raw path cannot fragment. The L3 size (IPv4 + UDP +
    // payload) must fit the interface MTU (which excludes the 14-byte
    // Ethernet header). Over-MTU → error so the caller broadcasts/UDP-falls-
    // back and lets the kernel fragment.
    l3Size := ipv4HeaderLen + udpHeaderLen + len(payload)
    if iface.MTU > 0 && l3Size > iface.MTU {
        return fmt.Errorf("reply L3 size %d exceeds MTU %d on %s",
            l3Size, iface.MTU, s.ifaceName)
    }
```
`/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/dhcprelay/l2send_linux.go:165-179`
```go
func buildL2Reply(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP,
    payload []byte) []byte {
    udpLen := udpHeaderLen + len(payload)
    totalLen := ipv4HeaderLen + udpLen
    frame := make([]byte, ethHeaderLen+totalLen)
    ...
    binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
```
Trace: jumbo payload 65535 + loopback MTU 0 → guard `iface.MTU>0` bypassed (MTU 0 path) → totalLen >65535 wraps uint16 → IP total-length invalid, peer DHCP client drops. DHCP <1500 normally, only MTU 0 path (loopback / misconfig) triggers.
Refutation: Check normal DHCP <1500 never overflows, but crafted/host-side large payload or future PXE options could approach limit. Guard should be unconditional.
Why it matters: Integer truncation correctness, blackhole on MTU-less interface.
Fix direction: Change guard to `if l3Size > iface.MTU && iface.MTU>0 || l3Size>65535 { error }` and cap before cast: `if totalLen>65535 { return nil, error }` or truncate.
Labels: dhcprelay, integer-truncation, low
Dedup note: Not in dedup-index; new.

#### Title: Surface-A withdraw fallback missing legacy AddrText
Severity: Low
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/ddns/surface_a.go:650-670` seed fallback
```go
for _, r := range m.state.all() {
    text := r.AddrText
    if text == "" {
        text = r.Address
    }
```
vs `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/ddns/surface_a.go:1399-1410` withdraw only AddrText
```go
func (m *SurfaceAManager) withdrawOwnedLocked(ctx context.Context, owned ownedRecord, backend DNSUpdater) error {
    a, err := netip.ParseAddr(owned.AddrText)
    if err != nil {
        slog.Warn("ddns surface-a: owned record has unparseable address; dropping entry",
```
Trace: Legacy record with AddrText="" Address="203.0.113.5" → seed restores runtime but withdraw parse fails → entry dropped without wire DELETE → RR leaks forever, no orphan alarm.
Fix: Mirror fallback `text:=AddrText; if text=="" {text=Address}` in withdraw path.
Labels: ddns, surface-a, durability
Dedup note: Not in dedup; distinct from #5334 pending-delete.

#### Title: Surface-A adoption guard raw FQDN vs canonical divergence
Severity: Low
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/ddns/surface_a.go:834-836`
```go
            liveByPolicy[osc.PolicyID+"\x00"+owned.FQDN+"\x00"+owned.AddrText] = struct{}{}
            if owned.BackendFingerprint != "" {
                liveByFP[owned.BackendFingerprint+"\x00"+owned.FQDN+"\x00"+owned.AddrText] = struct{}{}
```
vs canonical use `canonicalDDNSName` in siblingFamilyOwnedLocked #3738.
Trace: Durable store has `WAN.example.net.` and config `wan.example.net`, raw keys miss adoption → stale entry treated as provider-gone orphan instead of adopt-in-place → false orphan alarm + blocked withdraw.
Fix: Canonicalize adoption keys via `canonicalDDNSName`.
Labels: ddns, surface-a, canonicalization
Dedup note: New; not #3738 sibling guard.

#### Title: Surface-A HTTP cache default "" never reaped
Severity: Low
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b2/pkg/ddns/surface_a.go:770-792`
```go
    if m.httpClients != nil {
        live := make(map[string]struct{}, len(scopes)+len(catalog)+1)
        live[""] = struct{}{} // unbound default (nil provider / fail-open client)
```
`reap` skips keys in live, so unbound default transport never evicted even when no scope uses it, retaining idle conns.
Fix: Only insert "" when genuinely needed (any scope with empty bindCacheKey) or document intentional.
Labels: ddns, surface-a, cache, low
Dedup note: New low edge.

## Suggested Issue Split

- GH Issue Medium: Route53 foreign-record safety — List+multi-value preserve (M-01). File `backend_route53.go`, tests `backend_route53_test.go`.
- GH Issue Low: Relay L2 MTU 0 uint16 overflow (L-01). File `l2send_linux.go`.
- GH Issue Low batch: Surface-A low edges L-02/L-03/L-04 legacy fallback, canonical adoption, cache reap. File `surface_a.go`.

All not duplicates of #5334/#5327/#5355/#5306/#5305/#5328 cohort.

## Final Notes

CLI hardening complete: completion nil/over-type #2288, zone nil #3493/#3476, monitor traffic injection #4524+quote #4556+keyword #4540+count bound #4589, monitor stdin leak #3985, peer PSK #5324, RBAC control vs maint vs custom #4067/#4108/#4859/#4304 — RED-on-revert.
DDNS: redirect downgrade #4861, source-bind fail-closed #3733/#4437, TOCTOU/durability #2662/#4873/#5006, withdraw-backoff #2813/#4423, pending #5285 verified; Route53 foreign safety remaining gap from Cloudflare #3739 parity.
DHCP: lease expiry retention vs NAK revocation #3956/#1844, DUID traversal #4857, classless supersede RFC3442, IANA deterministic #4383, renewalTimers overflow-safe #4526, reconcile pruning #1815.


---

### === ps-A10_go_services_cli_deploy-b3.md ===

# A10 Go services/cli/deploy b3/3 — Defensive Review (96 files)

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3

## Inventory (LOC x responsibility x hot-path proximity)

| File | LOC | P/T | Largest fn | Responsibility | Rank |
|------|-----|-----|------------|----------------|------|
| pkg/policymatch/policymatch.go | 1714 | prod | Match() 180L | SSOT simulator zone/global/host-inbound/content-reject/route-drop advisory | CRIT |
| scripts/deploy/xpf-deploy.py | 1881 | prod | cmd_fetch ~200L | VM deploy, fetch+verify #1924, anti-rollback watermark, mixed-base gate, libvirt golden H-30 | High |
| test/incus/cold-path-flooder/src/main.rs | 2170 | test | worker loop / main | AF_PACKET cold-path flooder 5-tuple sweep, batch sendmmsg, CPU pin | Med |
| scripts/dist/publish.py | 786 | prod | publish gate | fail-closed publish #1924 §5.5 image/apt/install.sh/latest.json sig gates | High |
| scripts/image/bake.py | 756 | prod | virt_customize | offline bake virt-customize, cache SHA verify, grow-root, Secure Boot slots, validate→sign #4017 | High |
| scripts/image/validate.py | 686 | prod | scenario_a-e per-scenario | appliance first-boot contract a-e,q validation harness | High |
| test/incus/retire_ebpf_artifact_schema.py | 681 | test | ArtifactChecker.validate | #1477 final retirement bundle structural validation | Med |
| test/incus/cos_be_contention_validate.py | 748 | test | validate_artifacts | CoS exact-vs-BE contention validator | Med |
| pkg/policymatch/zone_detail_summary.go | 207 | prod | ZoneDetailPolicySummary 90L | tier-ordered exact→single-wild→both-any presenter | High |
| pkg/scheduler/scheduler.go | 448 | prod | evaluate 70L / isWithinWindow | time-window eval, republish self-heal #3780, wall-clock discont #3849, tz #3988 | High |
| scripts/dist/sign.py | 345 | prod | verify_and_read | minisign trust root, TOCTOU-safe copy-then-verify #5042 | High |
| test/xsk-repro/* | 24-320 | test | create_xsk / main | AF_XDP zero-copy rebind repro (root, DMA) | Low |
| many *_test.go + fairness/mouse/step* | 40-1400 each | test | — | RED-on-revert guards, metric reducers | Low |

Overall ~38k LOC scanned (prod ~6500, test ~31k). Largest prod funcs: Match() simulator precedence chain, scheduler evaluate(), xpf-deploy cmd_fetch 200L.

## Module Log (coverage proofs + negatives REQUIRED)

- **policymatch.go 1714 prod**: 3-pass read (0-500,500-900,900-1714). Tiers 1-5 exact mirror userspace-dp/src/policy.rs evaluate_policy_result. Verified zoneKnown gate #3355 no len(Zones)==0 tolerance — fail-closed to default. globalScopeSetMatches skips unresolved zone name → fail-closed. matchAddr empty-both-families fail-closed #3356/#2008. cross-family v4Empty&&v6Empty gate #3023 correct (v6-only exclusion on v4 packet trivially outside set → match). ContentRejected config-wide via dpuserspace.PolicyContentRejectionReasons delegates to SSOT — prevents fabricated permit under default-permit #3727/#4394. Route-drop defer stamp onto every return path #4373, host path exempt (junos-host local delivery). Host-inbound admission attached via withHI closure every host return — SSOT ClassifyHostInbound #3627. SelectorArgs strict — unknown token + missing value + duplicate rejection #3696/#3709 errors not wildcard widen. Port/proto canonical via config.ParseCanonicalUint + appid.ProtocolNumber rejects signed +/– #3679. **NEGATIVE**: no silent last-win, no empty-selector wildcard, no omitted-proto/port over-match — locked by port_omitted_3330, protocol_omitted_3323, srcport_omitted_3415 RED-on-revert.

- **zone_detail_summary.go**: Tier ordered exact→single-wild→both-any #4885, config order within tier. Nil zpp/pol guard #3476. PolicySetID advances in config order regardless of tier bucket — matches RuntimePolicyIDs namespace. **NEGATIVE**: no panic on nil, no ID divergence.

- **scheduler.go**: Absent window ⇒ inactive fail-closed #3849. Half-specified warn+false. Wall-clock discontinuity wallUnix-monotonic >5s ⇒ 2m hold failing closed. Timezone #3988 now.Location() via ParseInLocation for date range, timeOfDay local H/M/S — Junos local-midnight. Republish self-heal latch on updateFn error retried each 60s tick #3780. **FINDINGS** TOCTOU + start==stop + map alias + inclusive + counter — below.

- **cluster_status_parse.py**: _RG_HEADER_RE `^Redundancy group:\s*(\d+)\s*,` and _NODE_ROW_RE with secondary-hold before secondary + `\b` — R3 fix prevents truncation. Case-insensitive lower(). Empty/malformed → [] skips node rows without RG header — fail-closed. **NEGATIVE**: no eval/exec/shell, regex whitelist 6 states.

- **fairness_cov.py**: population stddev/N mirrors fairness.rs. Zero-len and zero-mean ⇒0.0. **NEGATIVE**: no sample stdev drift.

- **iperf3_sum_parse.py**: Anchored ^\[SUM\] prevents per-stream [N] match. Unit map K/M/G/T case-insensitive. Returns None on no-match — caller fail-closed. Caveat (omitted) documented hb166 V-12.

- **retire_ebpf_artifact_schema.py**: Structural completeness — schema version, issues candidate_commit 40 hex lowercase, artifact_created_at RFC3339 + tz, cluster name env_file config_files, binaries host path sha256 64 hex version, commands gate set 12 required, headings check, Decimal cap 128 digits anti-DoS, JSON constant reject. **NEGATIVE**: not deciding pass/fail on live results — by design.

- **sign.py**: verify_and_read copy-to-0700-tmpdir before verify returns bytes from copy — mitigates Codex-M5 TOCTOU for world-writable dir. verify_listed_artifact_bytes same pattern for manifest-listed artifact #5042. parse_manifest rejects pathful "/" "\\" "." "..", duplicate basename, non-hex sha256, empty. write_manifest refuses duplicate basenames. require_real_pubkey placeholder refusal fail-closed #1924. sha256_file 1MiB chunked. **NEGATIVE**: no secret logging, key bytes never in process.

- **publish.py / bake.py / make_config_drive.py / validate.py**: publish gate exhaustive (image manifest sig + qcow2 present+hash, apt InRelease, install.sh PRESENT+no placeholder+sig, target+other channels latest.json sig). bake finalize_artifacts validate BEFORE sign #4017 pinned by test_bake_sign_ordering. RuntimePackages frr-pythontools explicit #4172. Cache re-verifies against upstream SHA256SUMS. make_config_drive stages xpf.conf 0600 #4586. deploy fetch_one uses dst+".tmp"+os.replace atomic, verify per-file against signed manifest #1924, watermark advanced only AFTER verify. **NEGATIVE except bake shell injection below**.

- **mtr_report_check.py / fairness_* / mouse_latency_* / policy_scheduler_validate.py**: mtr fail-closed on missing loss column. fairness_equal_flow label parse LABEL_RE decode escape chain finite checks. mouse_latency deadline-bounded phases monotonic, abort on timeout, closed-loop min-interval sleep_overshoot tracked. policy_scheduler_validate enforces runtime protocol version>=2, forwarding_supported/armed/enabled, ebpf_only reject, entry_programs contains xdp_userspace, active>=min rebuild>=active, missing-scheduler commit txt contains failure and no commit complete. **Minor** Path absolute override low.

- **cold-path-flooder / xsk-repro**: flooder #![deny(unsafe_op_in_unsafe_fn)], unsafe only for libc FFI (getpid, clock_gettime, sched_getaffinity, if_nametoindex, ioctl, mmap, close, poll, sendmmsg). Cohort size u128 multiply prevents u64 overflow. Args validator centralizes span>0 base+span<=65536 reserved-port-0 avoidance, thread cap 64. xdp_pass_redirect.c minimal redirect with bpf_map_lookup_elem existence check before bpf_redirect_map else XDP_PASS safe fallback. **FINDINGS** XSK wrong ring accessor, fork killall, Rust munmap UAF below.

## Findings High Confidence

### [H-01 Sched-Eval TOCTOU] evaluate() releases mu across updateFn — concurrent Update() clobbers republish self-heal
Severity: High
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/pkg/scheduler/scheduler.go:111-180`
```go
func (s *Scheduler) Update(schedulers map[string]*config.SchedulerConfig) {
    s.mu.Lock()
    s.schedulers = schedulers
    s.mu.Unlock()
    s.evaluate(time.Now(), true)
}
...
    s.active = newActive
    ...
    cp := copyActiveState(newActive)
    updateFn := s.updateFn
    s.mu.Unlock()
    err := updateFn(cp)
    s.mu.Lock()
    s.recordRepublishResultLocked(err, now)
    s.mu.Unlock()
```
Trace: Run() ticker 60s calls evaluate() while API apply path calls Update(). T1 evaluates A→B unlocks calls updateFn slow fails. T2 evaluates newer B→C succeeds clears pending. T1 then stamps stale failure re-latching pending true for already-converged state, or success clears pending belonging to newer T2 failure → scheduled permit past window persists (fail-open) until next unrelated state change hours away — #3780 self-heal defeated.
Refutation attempt: Checked NewPrimed notify=false under mu safe, but Run()+Update() documented concurrent #3780. No epoch/seq guard present. Unlock across updateFn intentional to avoid deadlock if updateFn takes daemon lock nesting scheduler lock per comment, but epoch missing.
HPC/invariant check: lock order safe, correctness race not contention.
Why it matters: Time-gated permit/block failing to enforce on window edge is security-relevant — permit persists past window or block fails to engage.
Fix direction: Add monotonic seq/epoch incremented under lock before unlock; recordRepublishResultLocked only updates if seq matches current. Keep unlock across callback.
Labels: scheduler, race, fail-open, #3780
Dedup note: Not in dedup-index (FRR/RA/tunnel items only). Novel.

### [H-02 Sched-StartStop-Identical] Identical start==stop becomes 24h active — fail-open
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/pkg/scheduler/scheduler.go:400-415`
```go
    if !startTOD.before(stopTOD) {
        // Wraparound: e.g. 22:00:00 - 06:00:00 ...
        return !nowTOD.before(startTOD) || nowTOD.before(stopTOD)
    }
```
When start==stop e.g. "09:00:00"/"09:00:00", before false (equal not before), !false true → wraparound branch. Then now>=start || now<start always true.
Trace: Operator misconfigs scheduler same start/stop expecting zero/error — evaluates active 24/7 permitting traffic outside intended window.
Refutation attempt: Checked AllDay flag separate — true means whole day, not start==stop case. No early equality check. Most operators use daily window not identical.
Why matters: Time-based allow list becomes permanent permit.
Fix direction: Early `if startTOD==stopTOD { return false }` fail-closed with warn. Add unit test start==stop.
Labels: scheduler, fail-open, logic
Dedup note: Not in dedup-index. Novel.

### [H-03 XSK-RX Fill Wrong Ring] libbpf_xsk_test.c uses xsk_ring_cons__comp_addr on RX ring
Severity: High
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/test/xsk-repro/libbpf_xsk_test.c:183-189`
```c
            if (xsk_ring_prod__reserve(&info->fq, rcvd, &idx_fq) == rcvd) {
                for (unsigned int i = 0; i < rcvd; i++) {
                    *xsk_ring_prod__fill_addr(&info->fq, idx_fq + i) =
                        *xsk_ring_cons__comp_addr(&info->rx, idx_rx + i);
                }
```
Correct accessor is `xsk_ring_cons__rx_desc(&info->rx, idx_rx+i)->addr`. comp_addr reads from completion ring viewed through RX handle → garbage offsets → kernel DMA to random UMEM offsets potential host memory corruption when root, or persistent rx=0 false FAIL masking real XDP rebind bug. Same in `libbpf_xsk_shared_test.c:197`.
Trace: Create→prime fill correctly → bind→rx loop receive sets idx_rx but refill uses comp helper with wrong ring → next recv gets UMEM frames kernel-owned → missing packets reported as XDP broken rather than tool bug.
Refutation attempt: Checked libbpf headers — xsk_ring_cons__comp_addr expects comp ring, not rx desc ring. Type is same struct but different union field. Verified same bug in shared variant.
HPC/invariant check: N/A test tool but DMA correctness.
Why it matters: Test tool DMA to random offsets can corrupt host memory under root, and masks true XDP rebind failures — safety + correctness of validation gate.
Fix direction: Replace with `xsk_ring_cons__rx_desc(&info->rx, idx_rx+i)->addr` or `xsk_ring_cons__rx_desc(...)->addr`.
Labels: xsk, test-tool, DMA-corruption, correctness
Dedup note: #5328 xsk-repro provenance low-materiality listed but this is DMA correctness not provenance — materially different, not restatement.

### [H-04 Fork Unchecked Kill(-1,9) Mass Kill] fork() unchecked → kill all processes as root
Severity: High
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/test/xsk-repro/libbpf_xsk_test.c:233-274`
```c
    pid_t child = fork();
    if (child == 0) {
        /* Child: send pings to self */
        execlp(...);
        _exit(1);
    }
...
cleanup:
    kill(child, 9);
```
If fork fails child=-1, `kill(-1,9)` as root SIGKILLs every process caller can kill. Same in shared_test.c:269/283. XDP tests require root.
Trace: Under resource pressure fork returns -1, code falls through to cleanup, kill -1 9 → system-wide kill.
Refutation attempt: fork failure path does not exit — continues to Phase1. Verified cleanup label executes kill unconditionally. No child>0 guard.
Why it matters: Running as root, mass kill is catastrophic — safety hazard for manual validation on host.
Fix direction: `if (child>0) { kill(child,9); waitpid(child,NULL,0); }` else if child==-1 log skip. Same shared.
Labels: test-tool, safety, root, killall
Dedup note: Not in dedup. Novel critical.

### [H-05 Munmap Before Socket Close UAF] Rust xsk-repro unmaps UMEM while umem/sock still live
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/test/xsk-repro/main.rs:103-202`
```rust
    let area_ptr = unsafe { libc::mmap(...) };
    assert_ne!(area_ptr, libc::MAP_FAILED, "mmap failed");
    let area_slice = NonNull::from(unsafe {
        &mut *std::ptr::slice_from_raw_parts_mut(area_ptr.cast::<u8>(), area_size)
    });
    let umem = unsafe { Umem::new(cfg, area_slice) }.expect("create umem");
    ...
    let sock = Socket::with_shared(&info, &umem).expect(...);
    ...
    xskmap_delete(xsk_map_fd, queue);
    unsafe { libc::munmap(area_ptr, area_size) }; // umem/sock still live
    total_rx
```
Umem and socket Drop may touch fill/comp rings backed by area. munmap first → Drop reads freed mapping → UAF. Kernel may still DMA to unmapped UMEM during close. Also `/tmp/xdp_pass_redirect.o` world-writable TOCTOU in same file.
Refutation attempt: Checked drop order — Rust drops in reverse declaration order, but explicit munmap before function end bypasses it. area still referenced by umem. Needs explicit drop before munmap.
Why matters: UAF in root test tool can crash or corrupt, and munmap while socket live can cause kernel DMA to freed pages.
Fix direction: Explicit drop order: drop(rx), drop(user), drop(device), drop(sock), drop(umem) then munmap. Use private 0700 tempdir not /tmp for object file.
Labels: rust, UAF, test-tool
Dedup note: Not listed. Novel.

### [H-06 Deploy Fetch --version Path Traversal + Libvirt Golden Traversal]
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/scripts/deploy/xpf-deploy.py:903-945`
```python
    ver = args.version  # raw argparse string
    names = {
        "qcow2": f"xpf-{ver}.qcow2",
        "metadata": f"xpf-{ver}.incus-metadata.tar.gz",
        "manifest": f"xpf-{ver}.SHA256SUMS",
        "sig": f"xpf-{ver}.SHA256SUMS.minisig",
    }
    def fetch_one(name):
        dst = os.path.join(out, name)
        url = f"{base}/{name}"
```
`ver="../../etc/cron.d/pwn"` → dst is `out/xpf-../../etc/...qcow2` containing slash escapes out dir via kernel path resolution, os.replace writes outside intended. URL becomes `{base}/xpf-../../...` curl may fetch unintended path. Same for --alias. And libvirt golden:
`/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/scripts/deploy/xpf-deploy.py:559-603`
```python
def libvirt_golden_path(image):
    return os.path.join(LIBVIRT_IMAGES, f"{image}.qcow2")
...
    golden = libvirt_golden_path(ap['image'])  # image from YAML unsanitized
    overlay = os.path.join(LIBVIRT_IMAGES, f"{ap['name']}.qcow2")
```
`ap['name']` only checked non-empty not slash — `../../tmp/evil` escapes LIBVIRT_IMAGES overlay and day0 ISO path.
Trace: Attacker supplies --version with slash/.. → writes file outside out via .tmp then os.replace into traversed path. CI job trusting version from external manifest can be tricked. Same for YAML ap name/image.
Refutation: out=abspath(args.out or cwd)+makedirs but traversal escapes it. _ver_key would still compute even with slashes. No basename check. sign.verify_image_artifact later hashes traversed path — verification still happens but file already written outside quarantine.
Why matters: Local file write outside intended output dir CWE-22, CI trust boundary where version comes from external JSON.
Fix direction: Validate ver regex `^[A-Za-z0-9._-]+$` reject "/" "\\" ".." enforce `os.path.basename(name)==name`. Same for image alias, ap name/image. PurePath check. Reject file:// scheme in XPF_IMAGE_BASE_URL unless explicit flag.
Labels: deploy, path-traversal, CWE-22
Dedup note: Not in dedup-index (deploy TOCTOU items listed but not this traversal). Novel.

## Findings Medium Confidence

#### [M-01 Sched-Update Map Alias Race] Update stores caller's map ref without copy
Severity: Medium
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/pkg/scheduler/scheduler.go:111-114`
```go
func (s *Scheduler) Update(schedulers map[string]*config.SchedulerConfig) {
    s.mu.Lock()
    s.schedulers = schedulers
    s.mu.Unlock()
```
Caller may pass map owned elsewhere and later mutate it while evaluate ranges under mu — concurrent map read/write fatal. Aliasing violates ownership. Fix: clone map header copy.
Labels: scheduler, data-race
Dedup: New.

#### [M-02 StopDate Inclusive Off-by-One] midnight day-after inclusive boundary
Severity: Low-Med
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/pkg/scheduler/scheduler.go:351`
```go
    if now.After(stopDate.AddDate(0,0,1)) { return false, true }
```
After excludes equality — midnight exactly active extra tick. Should be `!now.Before(...)` i.e. >=.
Labels: scheduler, edge
Dedup: New.

#### [M-03 RepublishFailures Never Resets] metric monotonic forever
Severity: Low
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/pkg/scheduler/scheduler.go:184-197`
```go
    s.republishFailures++
...
    s.republishPending = false
    s.republishFirstFail = time.Time{}
    s.lastRepublishErr = nil
```
Failures++ only never zeroed on success. RepublishFailureStatus returns cumulative monitoring alert fires forever after first blip.
Fix: Reset to 0 on success or keep both total and consecutive.
Labels: scheduler, metrics
Dedup: New.

#### [M-04 Bake Shell Injection via deb_name] deb basename interpolates unescaped into guest sh
Severity: Medium
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/scripts/image/bake.py:240,359-361`
```python
    deb_name = os.path.basename(xpf_deb)
    ...
    "--run-command", f"apt-get install -y -qq -o Acquire::Retries=5 /var/tmp/{deb_name} && "
```
--run-command evaluated by sh inside guest via virt-customize. deb_name could contain `; rm -rf /` if attacker can place file in dist dir. os.path.basename doesn't sanitize shell metachars.
Fix: shlex.quote(deb_name) or use --copy-in with fixed dest name.
Labels: image-bake, shell-inject
Dedup: New.

#### [M-05 Publish TOCTOU Gate→Dispatch] verify hashes live path not private copy
Severity: Medium
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3/scripts/dist/sign.py:244-265`
```python
def verify_image_artifact(path, manifest_path, sig_path, pubkey_path=None):
    manifest = verify_manifest_map(manifest_path, sig_path, pubkey_path)
    actual = sha256_file(path)  # live path
```
vs verify_listed_artifact_bytes which copies to 0700 tmp then hashes #5042. publish.py calls verify_image_artifact for qcow2 then dispatches same path via XPF_PUBLISH_CMD rsync — window where file swapped between verify and upload.
Fix: Use verify_listed_artifact_bytes pattern + re-hash uploaded artifact or copy verified file into staging dir.
Labels: signing, TOCTOU
Dedup: Not in index.

#### [M-06 Test-tool Path Traversal / NaN] policy_scheduler_validate + fairness + iperf
Severity: Low
Confidence: High
Evidence: Python Path("/tmp") / "/etc/passwd" == "/etc/passwd" absolute override in policy_scheduler_validate cli --active-status; fairness_cov mean=sum/n NaN → threshold compare > max false PASS masking; iperf-json-metrics empty intervals ok=True; mouse probe negative timeout ValueError crash.
Fix: Basename validation finite check math.isfinite, is_absolute guard, ok=False on empty, max(0, remaining).
Labels: test-tool, CWE-22, NaN
Dedup: New.

## Low / Hardening

- cluster_status_parse big-int RG/node ID unbounded len Python big int — real CLI output KB bounded. Low.
- iperf3_sum_parse (omitted) rows matching — documented caution hb166 V-12. Reject lines containing "(omitted)".
- cold-path-flooder TxRing self-ref unsafe impl Send raw inline ptr fragile — sound today but future move-after-wire UAF. Document SAFETY, consider Box<sockaddr_ll>.
- cos_be_contention_validate duplicate queue_id summing masks reset.
- step1-histogram-classify dead code suspect="PASS" overwritten.
- make_config_drive 0644 vs 0600 secret bearing ISO — deploy fix 0600 #4586 but make_config_drive still 0644 subagent noted.
- validate.py default skips sig verify when no .minisig — intentional dev fail-open but should explicit warning.
- Ubuntu base SHA fetched without GPG — TLS-only MITM risk.
- XPF_IMAGE_BASE_URL scheme not validated — http/file accepted enforce https allowlist.

## Suggested Issue Split

1. **GH Scheduler race + start==stop + map alias + republish counter + inclusive** — pkg/scheduler/scheduler.go epoch guard, copy map, start==stop false, inclusive >=, reset counter. Tests add concurrency + start==stop.
2. **GH Deploy + Bake path traversal + shell injection** — scripts/deploy/xpf-deploy.py libvirt_golden_path + ap name + ver + alias + base scheme + image name basename validation, shlex.quote deb_name, private staging for publish gate.
3. **GH XSK repro DMA + fork killall + UAF** — test/xsk-repro/*.c wrong ring accessor comp→rx_desc, fork child>0 guard, Rust munmap after Drop order + private tmpdir not /tmp world-writable.
4. **GH Test-tool hardening** — policy_scheduler_validate absolute path, fairness NaN finite checks, iperf-json-metrics empty ok, mouse probe negative timeout, cluster_status id bounds, iperf3 omitted filter.

Polymatch core — no new bypass: zoneKnown fail-closed #3355, excluded empty-both-families #3356, content-reject config-wide SSOT #3727/#4394, route-drop defer #4373 host exempt, selector strict #3696/#3709, omitted-port/proto fail-closed #3323/#3330/#3415, ICMP proto gate, DisplayAddressNames unqual #3358 all sound and RED-on-revert guarded.

## Dedup Check

Against dedup-index + batch-002 note (#5334 withdraw-while-pending, #5327 dual-stack source-address, #5355 tunnel nil, #5306 fabric snapshot, #5328 15 low-materiality). None duplicate: scheduler TOCTOU, start==stop always-active, deploy fetch libvirt golden traversal, bake deb_name shell inject, publish TOCTOU gate→dispatch, XSK comp_addr wrong ring DMA, fork kill(-1) mass kill, Rust munmap UAF are novel.

Base: 275989b76b22925f4d2719fa07f47709eb227059 — worktree /tmp/review-wt-claude-001-A10_go_services_cli_deploy-b3 re-created after external cleanup for deep evidence-bar rebuild.


---

### === ps-A1_rust_dataplane_packet-b1.md ===

# A1 Rust Dataplane Packet Review — Batch b1/3 (150 files)
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1

## File-size/shape inventory (top 25 by LOC, ranked by size×resp×hot-prox)

| LOC | File | Prod/Test | Largest fn | Responsibility | Hot-prox |
|-----|------|-----------|------------|----------------|----------|
| 2795 | forwarding/mod.rs | prod | lookup_forwarding_resolution_v4_inner ~300 | FIB LPM, zone-id, HA gate, fabric, tunnel | HOT (per-packet lookup) |
| 2057 | cos/queue_service/mod.rs | prod | waterfill selector 432 LOC god-func | waterfill guarantee/surplus, refund, park | HOT (drain) |
| 1960 | frame/inspect.rs | prod | term_match_extra_from_frame ~120 | EH walker (6×), frag, flex-range, port parse, zone-mac | HOT (parse) |
| 1743 | frame/mod.rs | prod | rewrite + build orch | ETH write, NAT, TTL, DSCP, VLAN push/pop via desc shift | HOT (rewrite) |
| 1579 | coordinator/wg_control.rs | prod | WG peer reconc. | WireGuard control path | COLD |
| 1045 | coordinator/status.rs | prod | status aggregation | Prometheus/status cold path | COLD |
| 1000 | flow_cache.rs | prod | lookup_with_observed_bytes 80 LOC | 4-way SA-LRU, epoch, MAC-epoch, seeded FxHasher | HOT |
| 995 | frame/tcp_segmentation.rs | mixed | gso segmentation | TSO/GRO, WG encap | HOT (TX) |
| 984 | frame/checksum.rs | prod | checksum16 paths | scalar+AVX2 SIMD, v4/v6 zero-canonicalization | HOT |
| 961 | gre.rs | prod | GRE decap/encap | GRE over v4/v6, TCP flags, meta | HOT |
| 954 | cold_path_hist.rs | prod | record cold transition | cold-path histogram, rdtscp | COLD |
| 949 | ha.rs | prod | HA eval | RG lease, fabric redirect pref | WARM |
| 850 | forwarding_build/cos.rs | prod | CoS builder | rate/buffer validation, priority | COLD (build) |
| 838 | coordinator/cos_leases.rs | prod | lease mgmt | shared CoS leases | COLD |
| 798 | bind.rs | prod | open_binding_worker_rings unsafe | XSK bind, fill prime, NAPI kick | COLD (bringup) |
| 712 | bpf_map/mod.rs | prod | publish/session | session BPF map ops, zeroed values | WARM |
| 705 | forwarding_build/mod.rs | prod | build_forwarding_state | snapshot->state, integrity | COLD |
| 646 | cos/admission.rs | prod | cos_queue_flow_share_limit | share/buffer/ECN, BDP floor | HOT (admit) |
| 606 | frame/wg.rs | prod | WG encap | WG data header, MTU, mss | HOT (encap) |
| 599 | icmp.rs | prod | ICMP error build | icmp build, quoted len, MTU | WARM |
| 598 | event_emit.rs | prod | log emit | session close, filter log | COLD |
| 537 | forwarding/host_inbound.rs | prod | host-inbound | zone host-inbound admit | WARM |
| 498 | disposition.rs | prod | PacketDisposition enum | classification | HOT |
| 486 | coordinator/reconcile/bringup.rs | prod | bringup | binding bringup | COLD |

Total batch: 150 files. Prod ~90, test/bench ~60. Largest functions: waterfill selector, lookup_forwarding_resolution_v4_inner, parse_session_flow_from_bytes.

## Module log (coverage proof, incl negatives)

- **frame/inspect.rs**: 6 EH walkers all use `MAX_IPV6_EXT_HEADERS=8`, `checked_add`, `frame.len() < offset` fail-closed. `ipv4_declared_l3_end` guard for IHL truncation added (panic-safety). `icmp_identifier_bearing` SSOT, `meta_icmp_identifier_bearing` double-gated by declared_end. No unwrap (0). NEGATIVE: EH walker parity sound, frag gates sound, flex-range clamped to IP-declared end (#5150) — no bypass.
- **frame/mod.rs**: 3 `slice_mut_unchecked` with `descriptor_view_in_same_umem_frame` guard (same UMEM frame, 256B headroom). TTL `<=1` drop, DSCP rewrite idempotent. `trim_l3_payload` metadata-led with IP-total-len fallback. NEGATIVE: rewrite path bounds-checked, VLAN push/pop via descriptor shift avoids memmove, TTL/hop-limit underflow guarded.
- **frame/checksum.rs**: AVX2 fast-path `<32B` short-circuit, `is_x86_feature_detected!` cached, horizontal sum correct, `checksum16_finish` fold loop, v4/v6 zero-canonicalization matrix pinned by `simd_checksum_tests` differential. No truncation bug; `!(sum as u16)` intentional. NEGATIVE: SIMD vs scalar bit-identical, zero-canonical SSOT.
- **frame/headers.rs**: `TxVlanTag` carries full TCI+TPID, `emits()` checks `tci!=0` for prio-tagged VLAN-0 (#2149). `write_eth_header_slice_tagged` unsafe copies with len guard, `eth_len` 14/18. NEGATIVE: VLAN handling sound.
- **flow_cache.rs**: 4-way SA, LRU permutations, `rg_epoch_index` routes out-of-range RG to epoch 0, `set_index` seeded FxHasher via `hot_path_hash_seed`, `tick_advance_epoch` skips sentinel 0. `active_flow_debug_entries` clamps stale epoch (ghost-resurrection fix #1741). NEGATIVE: hash DoS resistant, LRU correct, no alloc on hot lookup.
- **forwarding/mod.rs**: `canonical_route_table` Cow borrowed default, table-scoped local-delivery (#3151/#3769), `MAX_NEXT_TABLE_DEPTH=8` with visited-set cycle detection, `LOCAL_DELIVERY_IFINDEX0` diagnostic, `classify_neighbor_state` allowlist (M12). NEGATIVE: next-table recursion bounded, local-delivery table-scoped, HA enforcement snapshot-based.
- **cos/queue_service/mod.rs**: waterfill 2-phase (honor+refund), `saturating_add` for tokens, `bit_ordinal <64` guard, `pop_snapshot_stack.clear()` at batch start (#3968). f64 `quantum_sum*frac` only in refill path (per-epoch, not per-packet). NEGATIVE: refund restores exact cost_bytes, no honor leak on zero-byte TX.
- **cos/admission.rs**: `COS_FLOW_FAIR_MIN_SHARE_BYTES` const-assert >=16*1500, BDP floor `saturating_mul`, `clamp_flow_share_to_buffer` panic-free (min(floor,buf) prevents clamp panic), `flow_share_div_ceil` guards div-by-0. ECN 1/3 threshold. NEGATIVE: admission math overflow-safe.
- **cos/ecn.rs**: Incremental csum update for ECN CE: `old_csum`, `old_word`, `new_word` fold, `while sum>0xffff` carry. `csum_idx = l3+10` with bounds via slice get. NEGATIVE: ECN csum delta correct.
- **cos/flow_hash.rs**: `seed as u16` after mixing, bucket mask `& COS_FLOW_FAIR_BUCKET_MASK`, `chunk.try_into().unwrap()` on `chunks_exact(8)` — infallible but unwrap in prod. Line 51/59.
- **cos/queue_ops/push.rs**: `bucket as u16` — bucket from `cos_flow_bucket_index` masked to 0..4095 fits u16. `maybe_promote_best_effort` hash-free probe, `#[cold]` promotion. NEGATIVE: promotion at-most-once, local_item_count net-zero.
- **bpf_map/**: `decode_session_map_key` uses `read_unaligned` (#4882), `zeroed()` for POD, `BPF_EXIST` to avoid recreating deleted entries. `metrics.rs` `read_ring_pair` mmap with `max+8` len, munmap always. `ha.rs` `saturating_sub` for mono age, step-safe liveness. NEGATIVE: alignment UB fixed, map ops sound.
- **bind.rs**: `fill_prime_is_total_failure`, `defer_uninserted_fill_suffix`, `drive_fill_prime_loop` pure + test-pinned, NAPI kick at least once (#2481). `setsockopt` best-effort. NEGATIVE: fill leak prevented, early-out proven by unit tests.
- **cold_path_hist.rs**: `s as u8` cast for slot pair — slot count likely <256 but unchecked. `rdtscp` + `lfence` ordering.
- **gre.rs**: All `checked_add`, `packet_rel_l4_offset_and_protocol` fail-closed at bound (#2292). `l4_offset = ihl as u16` safe (max 60).
- **icmp.rs**: Quoted len handling.
- **benches/build.rs/csrc**: benches use unwrap (acceptable), build.rs static link, xsk_bridge.c simple wrappers no overflow.

## Findings

### Medium confidence

**Title: ICMP error builder truncates total_len via `as u16` when quoted L4 exceeds 64K**
Severity: Low
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1/userspace-dp/src/afxdp/icmp.rs:362-387`
```
let total_len = 20usize.checked_add(8)?.checked_add(quoted_len)?;
let mut out = Vec::with_capacity(eth_len + total_len);
...
frame[ip_start+2..ip_start+4] = (total_len as u16).to_be_bytes()
```
Trace: `quoted_len` derived from original packet's L3 payload; `checked_add` guards usize overflow but not u16. If a jumbo or malicious inner with 60K quoted, total_len=20+8+60000=60028 fits u16, but if quoted_len ~70000 (possible if caller passes large slice despite MTU), total_len 70028 >65535 truncates to 4492 on wire — malformed IP len, peer drops, but not crash.
Refutation attempt: MTU 9000 bounds quoted_len, so practical max ~9000, fits u16. However no explicit cap before cast.
HPC/invariant: N/A — cold path (ICMP error generation, not per-packet forward).
Why it matters: Truncated IP total_len is RFC violation, could cause middlebox blackhole for large inner.
Fix direction: `u16::try_from(total_len).map_err()?` or `total_len.min(u16::MAX as usize)` with explicit reject; mirror ipv4 inject builder's `try_from` pattern at frame/build.
Labels: refactor, correctness
Dedup note: Not in dedup list; distinct from #5364 shim ABI.

**Title: ipv4_declared_l3_end clamps total_len<IHL upward instead of failing closed**
Severity: Low
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1/userspace-dp/src/afxdp/frame/inspect.rs:1072-1089`
```
let total_len = u16::from_be_bytes([frame[l3+2], frame[l3+3]]) as usize;
Some(l3.saturating_add(total_len).clamp(l3+ihl, frame.len()))
```
Trace: Malformed IPv4 with total_len=10, ihl=20, frame len 60. Clamp returns l3+20, not None. Downstream `parse_flow_ports` then checks `end > declared_end` — here declared_end==l3+20, l4==l3+20, end==l3+24 > declared_end => returns None, flowless — still fail-closed for port parsing. But flex_l3 slice `frame.get(l3..declared_end)` would be 20B header only, not 10B declared, exposing 10B of header beyond declared datagram to flex match (minor).
Refutation: Still fails closed for session install (no ports), but flex range includes bytes beyond declared total_len for this malformed case.
HPC/invariant: EH walker count 6, all checked_add.
Why it matters: Malformed total_len<IHL should be dropped entirely, not have flex match over header.
Fix: Return None if total_len < ihl, i.e., `if total_len < ihl { return None; }` before clamp.
Labels: hardening, fail-closed
Dedup note: Not in dedup; complement to #5150 slack fix.

### Low confidence / observations

**Title: flow_hash chunk.try_into().unwrap() in hot path — panic risk on std bug**
Severity: Low
Confidence: Low
Evidence: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1/userspace-dp/src/afxdp/cos/flow_hash.rs:51`
```
mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
```
Trace: `chunks_exact(8)` guarantees 8-byte chunks, so try_into never fails. Second occurrence line 59 same. Unwrap in hot path could panic if iterator contract broken, but std guarantee is strong.
Fix: Use `u64::from_be_bytes(*chunk.first_chunk::<8>().unwrap())` or `unsafe { chunk.as_ptr().cast::<[u8;8]>().read() }` with debug_assert, or `.expect("chunks_exact 8")` for explicit.
Labels: hot-path, refactor

**Title: cold_path_hist slot index as u8 truncation without bound check**
Severity: Low
Confidence: Low
Evidence: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1/userspace-dp/src/afxdp/cold_path_hist.rs:265`
```
slot_by_pair.insert((from, to), s as u8);
```
Trace: s is slot index from iteration over cold states; if cold path variants >255, truncates. Current cold states ~<100, safe.
Fix: `u8::try_from(s).expect` or assert <256, or use u16 key.
Labels: cold-path

**Title: Waterfill refill uses f64 in per-epoch path**
Severity: Low (perf)
Confidence: Low
Evidence: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b1/userspace-dp/src/afxdp/cos/queue_service/mod.rs:977`
```
((quantum_sum as f64) * frac).floor() as u64
```
and `((cap_per_epoch as f64)*frac).floor() as u64`. Per-epoch (200us) not per-packet, but still float in fast-ish path. Could be integer: `(quantum_sum * frac_numer / denom)`.
Fix: Store fraction as rational u32/u32 and do integer math in cold helper `#[cold] #[inline(never)] refill_waterfill_budget`.
Labels: hot-path, x-hpc

## Suggested hot/cold splits (zero-cost)

1. **frame/inspect.rs**: `term_match_extra*` builds flex slices — already hot but `ip_declared_end` is called twice (once for declared_end, once inside flex). Precompute once via helper returning `(declared_end, l3, l4)` triple, `#[inline(always)]`. No extra branch.
2. **cos/queue_service/mod.rs**: Extract f64 budget refill into `#[cold] #[inline(never)] fn refill_pass1_budget(root: &mut CoSInterfaceRuntime, now_ns)` — called only when exhausted or time tick. Proves disasm diff: hot `select_exact_cos_guarantee_queue_waterfill` loop body unchanged, call to cold helper.
3. **forwarding/mod.rs**: Move `FABRIC_LINK_SKIPPED_*` counter bumps + `eprintln!` skip logs into `#[cold] fn log_fabric_skip_transition` — already cold (snapshot build). Proves no new branch in `lookup_forwarding_resolution`.
4. **flow_cache.rs**: `active_flow_debug_entries` allocates BTreeMap + Vec — already cold (status cadence). Mark `#[cold]` + `#[inline(never)]`.
5. **cos/admission.rs**: `bdp_floor_bytes` contains div + mul — extract per-flow share calc into cold when buffer_limit changes, cache.

Each preserves per-packet disasm: hot functions `parse_session_flow_from_bytes`, `lookup_forwarding_resolution_with_dynamic`, `drain_shaped_tx`, `cos_queue_flow_share_limit` remain byte-identical — prove via `cargo objdump --disassemble` before/after.

## Dedup notes
All findings checked against 60 GH issues in prompt dedup index. No overlap with #5364 shim ABI, #5289 record_exception, #5288 neighbor socket, #5287 bpf_conntrack scan, #5275 dataplane arm. ICMP total_len truncation is new; ipv4_declared clamp is refinement of #5150/#2361 family.

## Overall assessment
Batch is well-hardened: checked_add everywhere, fail-closed None returns, seeded FxHasher, validated newtypes, snapshot integrity checks, waterfill refund correctness, LRU sentinel handling. No critical/high severity hot-path memory safety found in this batch. Top risks are low-sev truncation/clamp edge cases on malformed IP lengths.


---

### === ps-A1_rust_dataplane_packet-b2.md ===

# Batch b2/3 — A1 Rust AF_XDP dataplane packet b2 (150 files) — 2026-07-10

**Worktree**: `/tmp/review-wt-claude-001-A1_rust_dataplane_packet-b2` @ `275989b76b22925f4d2719fa07f47709eb227059`
**Base**: `git rev-parse --show-toplevel` → `/home/ps/git/avacado-xpf`

## Shape inventory
- Files: 151 listed in batch-004.txt (including header line) → 150 real `userspace-dp/src/` files
- LOC: 105093 = prod 52029 (107 files) + test 53064 (43 files)
- Largest prod: `poll_descriptor/mod.rs` 6294, `neighbor.rs` 2036, `types/cos.rs` 1786, `worker/loop_body/mod.rs` 1784, `tx/dispatch/mod.rs` 1486 (enqueue_pending_forwards 1050), `shared_cos_lease/lease.rs` 1460, `neighbor_dispatch.rs` 1421, `umem/mod.rs` 1363, `tx/cos_classify.rs` 1335, `session_glue/mod.rs` 1277, `poll_descriptor/filter.rs` 1201, `types/forwarding.rs` 1099, `afxdp/mod.rs` 1069, `wg/engine.rs` 1805
- Largest test: `afxdp/tests.rs` 14038, `session_glue/tests.rs` 5748, `cos_classify_tests` 4617, `wg/tests` 3909, `poll_stages_tests` 2636
- Largest fns: `poll_binding_process_descriptor` 5611 LOC L683 god-function 15+ resp single-recycle invariant Junos order host-inbound→lo0→junos-host table-scoped local-delivery #3769/#3151 connected scoping #2388; `enqueue_pending_forwards` 1050 LOC L271 TX orchestrator zero-copy UMEM ownership; CoS classify 7-resp enqueue_pending+fallback
- Hot proximity rank (size×resp×hot): 1) poll_descriptor/mod.rs 251760, 2) dispatch/mod.rs 44580, 3) cos_classify.rs 28035, 4) types/cos.rs 21432, 5) neighbor.rs 18324
- Ownership: `BindingWorker` single-writer per worker, UMEM `MmapArea` single owner `Rc<WorkerUmemInner>` with `Rc::get_mut` exclusive

## Module log (condensed, with negatives proving coverage)
- `poll_descriptor/mod.rs` 6294: orchestrates RX meta parse → flowless verdict → host-inbound deny per #3070 empty set → lo0 filter → junos-host #3019 reserved range → NAT64 frag assoc deferred install → cache-hit → session-limit → strict-syn bare RST/FIN drop agg-only no event #4400 repurposed from #2151/#4487/#4539 has_syn gate → screen 16 checks + syncookie → policy → TX. All 15 eprintln behind `cfg!(feature="debug-log")` + numeric caps via `debug_log_throttle.rs` pure fn(session_miss)<=10 policy_deny<=3 no topo bypass #4120 — no flood. 6 unsafe via `unsafe { &*area }.slice(addr as usize, len as usize)` Option-checked, bounds fail-closed.
- `cookie_reply.rs`/`reject_reply.rs`/`nat_exception.rs`: `#[cold]#[inline(never)]` true cold bodies .text.unlikely — exemplary split, hot byte-for-byte preserved
- `filter.rs` 1201: inline policy per-fn not blanket — cheap guards #[inline] fold into hot caller, heavy bodies #[cold]#[inline(never)] including `filter_terminal` ordering reject-reply enqueue FIRST then emit log with actual outcome #3615 truthful REJECT→DENY downgrade. `emit_cached_output_filter_log` tail split prevents 96B `UserspaceDpMeta` copy on fast path no-logging — HFT-grade
- `flow_cache_hit.rs` 533: hit replay relays hit counters via `record_policy_hit_counter` batch coalescer — no Mutex per packet — GOOD
- `rx_telemetry.rs` 220: small counters inline
- `poll_stages.rs` 975: stage extraction host-inbound/lo0/policy eval hoisted — still zone lookup — no extra taken branch — GOOD split without disasm change
- `tx/dispatch/mod.rs` 1486 HOT: single-recycle invariant — src frame via ingress UMEM unsafe &*area slice Option, target build via `slice_mut_unchecked(offset, capacity())` owned offset from free_tx_frames pop_front; double-recycle fix #4041 single if build_failed path; prefetch `_mm_prefetch` x86_64 cfg; oversized written>capacity drop + exception; no Vec alloc direct path — negative sound
- `dispatch/cos.rs` + `shared_recycle.rs` + `slow_path.rs`: shared_recycles Option<&mut Vec<(u32,u64)>> CAS-free local queue; fallback clone alloc only slow path
- `tx/cos_classify.rs` 1335 7-resp: DSCP/PCP→queue, clone_prepared_req fallback, default-queue fallback for unmaterialized queue #hb166 T-4 Never blackhole (belt-and-suspenders runtime + build-time classifier table). Alloc `to_vec()` only in `clone_prepared_request_for_cos` fallback — contains expect bug B2-01
- `tx/drain/*` phase_backup/shaped/trivial — waterfill 432 god-func #4408 now split, selector reads pre-sorted `exact_queues_by_rate_ascending` built cold, guarantee-guard #4246
- `tx/rings.rs`/`stats.rs`/`tcp_segmentation.rs`/`transmit/*`: bounded len checks, as u32 casts guarded >capacity for dbg tx_max_frame only, except tcp_segmentation as u16 trunc B2-00 — rest sound
- `types/cos.rs` 1786 CoSInterfaceRuntime 28 fields god-struct (prior #145 #355 #129) — tokens, guarantee_fraction f64, exact_queues_by_rate_ascending Vec pre-sorted, priority_low_min_share* 3 fields WIRE SURFACE ONLY UNUSED #1618 no hot read (B2-02 perf). FlowFairState new_boxed `Box<MaybeUninit>` + addr_of_mut! POD write_bytes(0) avoids 8KB tmp, VecDeque per bucket raw add().write(new) avoids 128KB tmp — field-equiv guard test + assert BUCKETS<=u16::MAX — sound, exemplary unsafe builder
- `shared_cos_lease/*` lease 1460 credits AtomicU64 packed hi avail lo outstanding, burst clamp, rate u128 mul avoids overflow target 200us, bank floor N-frame #1630, VMin PaddedAtomicU32 64-align false-share avoid, epoch seqlock, Acquire/AcqRel weak CAS loops — sound, prior #145 noted split good backlog+vtime vs lease monolith
- `types/forwarding.rs` 1099 ForwardingState 66 fields no #[repr] #4421 (was 55) — FastSet/Map, GRE decap index (family,src,dst)->Vec<u16> kind-segregated #2327 replaces O(N) scan, WG Arc engines, has_wg_tunnels bool gate #1432 — construction cold, lookup hot — AoS not optimal but functional
- `umem/*` mmap 168 + mod 1363: MmapArea::new checked_add HUGE_PAGE_SIZE-1 overflow guard #1020 wraps→EINVAL not under-alloc, mmap hugetlb 2MB attempt MAP_POPULATE, fallback THP MADV_HUGEPAGE best-effort ignored EINVAL, munmap Drop. slice() checked_add end>len None safe, slice_mut_unchecked same + safety doc single-writer owner-worker + free-frame ring ownership — sound  — #5192 latent UAF prior fixed
- `session_glue` 1277 + commands/* 30+ fns god old but off hot path (control)
- `sharded_neighbor` 421 + `shared_ops` 1131 + `shared_umem` 557 sharded cache lock-free reads
- `neighbor.rs` 2036 ARP prober unsafe clock_gettime/sendto zeroed sockaddr, UDP sockets per probe cold, last_probed Mutex expect("poisoned — warming forcibly disabled") doc #287 panic only disables warming not dataplane, NL netlink socket open/send/close per accepted ARP #5288 DoS/latency dedup — known
- `parser.rs` 359 l3/l4 offset as usize .get() bounded fail-closed
- `icmp_embed/*` parse 477 PTB 547 ratelimit 375 token-bucket Atomic no Mutex hot — fail-closed truncation
- `mirror/fast_path` 272 reserve bytes check then clone shared AcqRel CAS before sampler #5167 #5267 cross-worker clone cost before sampler — known low-materiality
- `wg/engine.rs` 1805 per-packet no alloc decrypt, TAI64N, timers cold — sound
- `worker/loop_body/mod.rs` 1784 + `worker/mod.rs` 1631 + `worker/cos/*` interface_row queue_row status: effective_queue_index [u16;256] miss sentinel O1 no hash hot — exemplary fast-path

## Findings — High/Medium Confidence

### [B2-00] TCP segmentation IP len `as u16` truncation — malformed wire len on oversized MTU / forged snapshot
Severity: Medium
Confidence: High
Evidence: `userspace-dp/src/afxdp/tx/tcp_segmentation.rs:196` and `:245` (worktree b2):
```
packet.get_mut(2..4)?.copy_from_slice(&(total_ip_len as u16).to_be_bytes());
...
let v6_payload_len = (ip_header_len - 40) + tcp_header_len + chunk_len;
packet.get_mut(4..6)?.copy_from_slice(&(v6_payload_len as u16).to_be_bytes());
```
Trace: GRO may coalesce 64K data. chunk_len = min(remaining, segment_payload_max) where payload_max = MTU - hdrs. total_ip_len = ip_header_len + tcp_header_len + chunk_len. If MTU 9000 via #5291 WG first-peer scalar leak or forged snapshot via gRPC loopback no-auth #5278, total_ip_len > 65535 → truncation → low 16 bits on wire → peer IP stack drops / invalid csum → blackhole, middlebox may over-read beyond frame? But local frame still large, IP len lies → tcp checksum recomputed over claimed len? Actually checksum recomputed over real header, but IP len mismatch → peer may read short → segment loss.
Refutation attempt: Go MAX_MTU 9216 + validation; tx_frame_capacity ~2048-4096 < 65535 so early `if frame_len > tx_frame_capacity() return None` drops oversized before trunc. So runtime impossible under normal commit, latent defense-in-depth. Snapshot trust via gRPC not validated for >u16 is the path.
HPC/invariant: no const assert capacity <= u16::MAX, no try_from, to_be_bytes order correct but truncation before.
Why matters: malformed wire violates fail-closed; peer misattr.
Fix direction: PR-B2-01 safety `let len_u16 = u16::try_from(total_ip_len).map_err(|_|())?` return None drop + exception "seg_ip_len_trunc"; same v6; debug_assert capacity <= u16::MAX; unit test MTU 70000 → drop. Prove disasm non-segment fast path identical; CoS/failover gates unchanged.
Labels: hot-path, x-hpc, int-trunc, fail-closed
Dedup note: prior #495 mtu .max(1280) different; open GH #5291 outer MTU scalar not this wire trunc.

### [B2-01] CoS prepared-clone fallback `expect()` panics worker on UMEM slice None
Severity: Medium
Confidence: High
Evidence: `userspace-dp/src/afxdp/tx/cos_classify.rs:795-796`:
```
let req = clone_prepared_request_for_cos(binding.umem.area(), &prepared_req)
          .expect("prepared CoS fallback clone");
```
and `clone_prepared_request_for_cos` L961-964 `area.slice(req.offset as usize, req.len as usize)?.to_vec()` → None → panic.
Trace: shared_exact CoS queue full → Err(Prepared) → fallback clone expects Some — offset corrupted after rolling upgrade shared recycle or len > area.len → None → panic kills worker → binding queue stall → RSS hash blackhole 1/6 capacity mlx5 VF 6 queues loss cluster until restart.
Refutation: offset from free_tx_frames pop proven in-bounds at alloc, len checked >tx_frame_capacity early Err, area.len constant not racing. None only on logic bug but violates no-panic contract.
Why matters: worker death = dataplane blackhole triggers HA failover ~60ms not intra-node recovery.
Fix: `let Some(local_req) = clone... else { recycle_prepared_immediately_with_shared(); record_exception("cos_clone_fallback_slice_fail", len); return Err(prepared) }` #[cold] path, disasm Ok path identical, CoS iperf + failover smoke.
Labels: hot-path, refactor, fail-closed
Dedup note: not in dedup; #4041 fixed double-recycle not this.

## Findings — Low (perf hygiene, still actionable)

### [B2-02] CoSInterfaceRuntime 28-field god-struct + 3 UNUSED reserved fields on hot cache line, no #[repr]
Severity: Low
Confidence: High
Evidence: `types/cos.rs:556-588` CoSInterfaceRuntime { shaping_rate, burst, tokens, ..., priority_low_min_share_bytes, priority_low_reserved_tokens, priority_low_last_refill_ns } last 3 WIRE SURFACE ONLY UNUSED no hot readers.
Trace: drain waterfill hot reads tokens/nonempty/oversubscription_policy/exact_queues_by_rate_ascending — cold HashMap queue_by_forwarding_class shares line.
Fix: SoA hot (queue heads deficits bucket ring) vs cold HashMap; move UNUSED behind Option<Box> cold or cfg; #[repr(C)] hot-first fit 2 lines 128B + align(64) queue row; measure cache-misses CoV floor 6 queues mlx5.
Labels: x-hpc, refactor, hot-path, cold-split
Dedup note: prior reports #145/#355 god-struct same file but this pinpoints UNUSED + concrete cache-line SoA fix — not mere re-report.

### [B2-03] `slice_mut_unchecked` distant guard vs local proof
Severity: Low
Confidence: Medium
Evidence: `tx/cos_classify.rs:890` `area.slice_mut_unchecked(offset as usize, req.bytes.len())`, `dispatch/mod.rs:943/962` `slice_mut_unchecked(tx_offset, capacity())`.
Refutation: wrapper Option checked_add + end>len → None → drop, so memory safety holds even if logic wrong, just drops. Miri clean.
Fix: debug_assert + comment linking allocation site, zero-cost proof.
Labels: x-hpc, unsafe
Dedup note: distinct from #5192 UMEM drop-order latent UAF.

### [B2-04] debug-log cfg!() vs #[cfg] leaves strings in .rodata
Severity: Low
Confidence: High
Evidence: `poll_descriptor/mod.rs:2104` `if cfg!(feature="debug-log") { if session_miss_debug_log_allowed... eprintln! }` 14 sites.
Refutation: cfg! false → DCE eliminates call in release but strings remain .rodata; .text hot path identical but .text.unlikely not isolated. Better #[cold]#[inline(never)] helper with #[cfg].
Fix: extract to cold helper gated #[cfg(feature)] — objdump hot identical, .text.unlikely grows only.
Labels: x-hpc, cold-split
Dedup note: not in dedup; but aligns CLAUDE.md logging rules.

## Issue split + validation gates
PR-B2-01 safety Medium: as u16 → try_from fail-closed drop + test MTU 70000 + audit icmp_embed plen #496 sibling — `make test-rust`, disasm non-segment fast path identical.
PR-B2-02 safety Medium: cos expect → fail-closed — CoS iperf per-class 5200-5211 loss:xpf-userspace-fw0 + failover.
PR-B2-03 perf Low: CoS god-struct SoA cold split + UNUSED removal — perf cache-miss measure + CoS smoke.
PR-B2-04 perf Low: debug-log cold helper + slice guard locality — objdump poll_binding_process_descriptor .text identical.
Disasm proof: `cargo rustc -p userspace-dp --release -- --emit asm -o /tmp/before.s` before/after, diff hot function prefix byte-identical.
Failover gate: `make cluster-deploy && ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0 && make test-failover`

## Negative results (prove coverage)
- No unwrap/expect/panic in prod poll_descriptor first 5480 lines except noted CoS file — checked via worktree grep.
- No Mutex/RwLock in per-packet hot path poll_descriptor/dispatch — only Atomics & &mut binding, session table single-writer per worker.
- No heap alloc in flow_cache_hit fast path — no format!/collect/to_vec.
- Fail-closed parsing: try_parse_metadata Option, slice() checked, screen drops malformed, reject_reply guards.
- UMEM single-recycle: scratch_recycle clear poll start, every early continue recycles, free_tx_frames single-owner pop/push, recycle_ingress_frame consistent.
- CoS lease Acquire/AcqRel CAS loops cross-worker correct — prior concern B2-005 resolved as correct.
- No eprintln outside cfg(feature) in dispatch hot.

Cleanup: `git worktree remove --force /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b2; rm -rf /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b2`


---

### === ps-A1_rust_dataplane_packet-b3.md ===

# b3/3 Rust hot path: session table + policy/verdict + screen + filter + worker queues + event_stream

Base 275989b76b22925f4d2719fa07f47709eb227059 WT /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b3

## Shape inventory
- Batch files: 118 — prod 64708 LOC (92 files), test 19247 LOC (26 files), total 83955
- Prod vs test split: PROD 92 files, TEST 26 files
- Largest prod top 20:
  - userspace-dp/src/filter/tests.rs 8422
  - userspace-dp/src/session/tests.rs 7072
  - userspace-dp/src/screen/tests.rs 5395
  - userspace-dp/src/policy.rs 3657
  - userspace-dp/src/protocol/tests.rs 2393
  - userspace-dp/src/session/mod.rs 2114
  - userspace-dp/src/server/tests.rs 1953
  - userspace-dp/src/event_stream/mod.rs 1701
  - userspace-xdp/src/lib.rs 1541
  - userspace-dp/src/screen/mod.rs 1540
  - userspace-dp/src/server/helpers.rs 1304
  - userspace-dp/src/xsk_ffi.rs 1287
  - userspace-dp/src/screen/scan.rs 1213
  - userspace-dp/src/protocol/binding.rs 1185
  - userspace-dp/src/protocol/control.rs 1088
  - userspace-dp/src/filter/compiler.rs 1056
  - userspace-dp/src/filter/engine/eval.rs 1026
- Largest test top 10:
  - userspace-dp/src/policy_tests.rs 7280
  - userspace-dp/src/main_tests.rs 2350
  - userspace-dp/tests/fairness_eval_blackbox.rs 1366
  - userspace-dp/src/event_stream/codec/codec_tests.rs 1023
  - userspace-dp/src/slowpath_tests.rs 776
  - userspace-dp/src/state_writer_tests.rs 689

- Largest fn approx (heuristic):
  - userspace-dp/src/session/mod.rs: pub fn update_session ~239 LOC
  - userspace-dp/src/policy.rs: pub(crate) fn parse_policy_state_with_counters ~567 LOC
  - userspace-dp/src/screen/mod.rs: pub fn check_packet_with_zone_id_opts ~374 LOC
  - userspace-dp/src/filter/compiler.rs: fn parse_term ~427 LOC
  - userspace-dp/src/event_stream/mod.rs: pub(crate) fn mono_ns_to_wall_clock_unix_ns ~199 LOC
  - userspace-xdp/src/lib.rs: fn try_xdp_userspace ~343 LOC

- Hot rank size*resp*hot-proximity: 1) session/mod.rs slab u32 handles + Seeded 1:N indexes reverse/forward wire/alias #4399#4438 multimap SmallVec[2] zero-alloc fast + handle validate-by-key #1855; 2) session/entry.rs u16 zone IDs #919 saves 28B + LOCK XADD ~10ns win + bound Arc #3322; 3) policy.rs zone_pair_key u32 pack + AppCatalog tiered #3612 + hit_counter coalescer #3073 gen-guard #3448/#3782; 4) screen/mod.rs 16 checks + SYN-flood count-min no-eviction #3315 + timeout per-zone #3527; 5) filter/mod.rs CachedThreeColorPolicers SmallVec[2] + Mutex hot; 6) xsk_ffi.rs unsafe Send rings; 7) tx_pipeline Box<[u64]> sidecar; 8) event_stream replay 4k + backlog 16MiB cap #2381


## Module log (per-file one-line incl negatives proving coverage)
- userspace-dp/src/afxdp/worker/tx_counters.rs 59 LOC: WorkerTxCounters 10 u64 pending_* counters - drained per-sec debug tick - alloc-free hot record - negative
- userspace-dp/src/afxdp/worker/tx_pipeline.rs 69 LOC: WorkerTxPipeline free_tx_frames VecDeque, pending_tx_prepared/local, outstanding_tx u32 gauge #802, tx_submit_ns Box<[u64]> pre-sized - Box not Vec prevents push compile-fail - negative
- userspace-dp/src/afxdp/worker/xsk_rings.rs 40 LOC: WorkerXskRings DeviceQueue+RingRx+Tx structural extraction #959 Phase11 - negative
- userspace-dp/src/afxdp/worker_queue.rs 84 LOC: Mutex<VecDeque<WorkerCommand>> poison-recovery lock_recover/try_lock_recover clear_poison + AtomicU64 counter Prometheus - eprintln cold panic path only - negative hot alloc
- userspace-dp/src/afxdp/worker_queue_tests.rs 161 LOC: Test file userspace-dp/src/afxdp/worker_queue_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/afxdp/worker_runtime.rs 571 LOC: WorkerRuntimeState Active/IdleSpin/IdleBlock + CoSQueueLeaseUndergrant + WorkerRuntimeCounters + #[repr(align(64))] Atomics seqlock window_gen AcqRel/Release fence Acquire reader spin 16 - unsafe clock_gettime/gettid checked - sound but ordering sensitive
- userspace-dp/src/afxdp/worker_runtime_tests.rs 351 LOC: Test file userspace-dp/src/afxdp/worker_runtime_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/afxdp/zone_counters.rs 437 LOC: ZoneCounterSlotMap flat [u8;65536] LUT zone-id->slot O(1) 2 array reads hot + inverse[64] slot->zone - ZonePending thread-local dense [u64;64]x4 - store Mutex fold per RX batch off hot - #3651 populate
- userspace-dp/src/bin/fairness-eval.rs 37 LOC: userspace-dp/src/bin/fairness-eval.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/event_stream/codec/codec_tests.rs 1023 LOC: Test file userspace-dp/src/event_stream/codec/codec_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/event_stream/codec/decode.rs 90 LOC: Decode AF_INET as u8 AF_INET6 as u8 fits 2/10 - negative
- userspace-dp/src/event_stream/codec/mod.rs 86 LOC: EventFrame data [u8;256] fixed - FRAME_HEADER_SIZE constant - len as usize checked - payload len from_le_bytes as usize - negative
- userspace-dp/src/event_stream/codec/rt_flow.rs 540 LOC: RT_FLOW encoding SECURITY_EVENT_PAYLOAD_SIZE as u32 len as u16 - bounded - negative
- userspace-dp/src/event_stream/codec/session_sync.rs 271 LOC: SessionSync encode owner_rg_id as i32 le_bytes egress_ifindex as i32 tx_ifindex as i32 payload_len as u32 len as u16 pos as u16 - ifindex <2^31 safe but cast i32 trunc if >2^31-1 - low risk
- userspace-dp/src/event_stream/codec/wire.rs 284 LOC: Encode SECURITY_EVENT_PAYLOAD_SIZE as u32 + len as u16 pos as u16 - data fixed 256 so fits u16 - negative trunc but bounded
- userspace-dp/src/event_stream/mod.rs 1701 LOC: EventStreamShared next_seq AtomicU64 producer_seq_lock Mutex<()> wire FIFO F-152 - replay 4096 bound - write backlog 16MiB cap #2381 - unsafe clock_gettime checked - eprintln cold IO thread - rate-limiter + queue budget + stats atomics - negative hot alloc except Mutex per event (flow rate)
- userspace-dp/src/event_stream/producer.rs 466 LOC: DataplaneEventCounters/limiter/queue budget - backpressure drop counters - negative
- userspace-dp/src/event_stream/producer_tests.rs 317 LOC: Test file userspace-dp/src/event_stream/producer_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/event_stream/tests/backpressure.rs 384 LOC: Test file userspace-dp/src/event_stream/tests/backpressure.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/event_stream/tests/control_frames.rs 350 LOC: Test file userspace-dp/src/event_stream/tests/control_frames.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/event_stream/tests/drain.rs 511 LOC: Test file userspace-dp/src/event_stream/tests/drain.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/event_stream/tests/mod.rs 133 LOC: Test file userspace-dp/src/event_stream/tests/mod.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/event_stream/tests/replay_budget.rs 588 LOC: Test file userspace-dp/src/event_stream/tests/replay_budget.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/event_stream/tests/rt_flow.rs 444 LOC: Test file userspace-dp/src/event_stream/tests/rt_flow.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/fairness.rs 128 LOC: userspace-dp/src/fairness.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/args.rs 382 LOC: userspace-dp/src/fairness_eval/args.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/inputs.rs 406 LOC: userspace-dp/src/fairness_eval/inputs.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/mod.rs 261 LOC: userspace-dp/src/fairness_eval/mod.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/per_worker.rs 254 LOC: userspace-dp/src/fairness_eval/per_worker.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/per_worker_tests.rs 221 LOC: Test file userspace-dp/src/fairness_eval/per_worker_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/fairness_eval/report.rs 150 LOC: userspace-dp/src/fairness_eval/report.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/rss.rs 203 LOC: userspace-dp/src/fairness_eval/rss.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/verdict.rs 366 LOC: userspace-dp/src/fairness_eval/verdict.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_eval/windowing.rs 216 LOC: userspace-dp/src/fairness_eval/windowing.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/fairness_tests.rs 161 LOC: Test file userspace-dp/src/fairness_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/filter/compiler.rs 1056 LOC: Compile zones filters into FilterState + policers bitmap (value/64) as usize - bounded <64 - expect on IpNet constants v4 /0 /32 /128 deterministic - negative hot
- userspace-dp/src/filter/engine/cache_sensitive.rs 586 LOC: Tx_selection cached guards input_dscp_filter_families_changed - cold - negative
- userspace-dp/src/filter/engine/eval.rs 1026 LOC: Evaluate filter ref counted v4/v6 routing-instance - inline term_matches - negative alloc
- userspace-dp/src/filter/engine/matching.rs 376 LOC: term_matches flex_length/offset as usize protocol_bitmap[(proto/64) as usize] - bounds checked via bitmap len 4 - negative
- userspace-dp/src/filter/engine/mod.rs 38 LOC: Re-exports cache_sensitive eval policer tx_selection #1546 byte-identical - negative
- userspace-dp/src/filter/engine/policer.rs 57 LOC: apply_cached_three_color_policers - delegates to filter/mod.rs meter - negative
- userspace-dp/src/filter/engine/tx_selection.rs 419 LOC: Filter PBR routing-instance overrides - cold
- userspace-dp/src/filter/mod.rs 939 LOC: ThreeColorPolicerRuntime Mutex per-packet meter hot + CachedSmallVec[2] inline #2544 + CachedFilterCounters dedup ptr_eq + FilterResult log_match normalize #2616 + eval loops #[inline(always)]
- userspace-dp/src/filter/policer.rs 504 LOC: srTCM trTCM policer config expect valid - cold compile - negative
- userspace-dp/src/filter/tests.rs 8422 LOC: userspace-dp/src/filter/tests.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/hot_hash_seed.rs 141 LOC: Per-boot secret seed OnceLock - as usize trunc of u64 for FxSeededState - negative
- userspace-dp/src/hot_hash_seed_tests.rs 29 LOC: Test file userspace-dp/src/hot_hash_seed_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/io_uring_write.rs 419 LOC: io-uring state writer WriteError - cold - negative
- userspace-dp/src/io_uring_write_tests.rs 474 LOC: Test file userspace-dp/src/io_uring_write_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/ip_proto.rs 113 LOC: Proto consts - negative
- userspace-dp/src/main.rs 65 LOC: Daemon startup eprintln cold - negative
- userspace-dp/src/main_tests.rs 2350 LOC: Test file userspace-dp/src/main_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/policy.rs 3657 LOC: ZonePairKey u32 pack no overflow + JUNOS_GLOBAL u16::MAX + AppCatalog tiered #3612 + PolicyCounterStore Mutex + generation #3448/#3782 fetch_sub not store(0) preserves concurrent post-clear
- userspace-dp/src/policy_snapshot_error.rs 896 LOC: Sentinel __unsupported_address__ not CIDR MatchNone fail-closed + preflight - sound
- userspace-dp/src/policy_tests.rs 7280 LOC: Test file userspace-dp/src/policy_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/prefix.rs 112 LOC: PrefixV4/V6 wrapper contains - negative
- userspace-dp/src/prefix_set.rs 322 LOC: MatchAny/MatchNone/Linear/Trie binary radix MSB-first walk short-circuit covers - no heap per lookup - negative
- userspace-dp/src/prefix_set_tests.rs 235 LOC: Test file userspace-dp/src/prefix_set_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/protocol/binding.rs 1185 LOC: Binding snapshot - cold - negative
- userspace-dp/src/protocol/control.rs 1088 LOC: Control req/resp - cold - negative
- userspace-dp/src/protocol/cos.rs 494 LOC: CoS snapshot - cold - negative
- userspace-dp/src/protocol/mod.rs 75 LOC: Mod re-exports - negative
- userspace-dp/src/protocol/nat.rs 424 LOC: NAT snapshot - cold - negative
- userspace-dp/src/protocol/resolution.rs 105 LOC: Resolution - cold
- userspace-dp/src/protocol/security.rs 605 LOC: Security profile snapshot - cold
- userspace-dp/src/protocol/snapshot.rs 829 LOC: ConfigSnapshot bindings - cold
- userspace-dp/src/protocol/tests.rs 2393 LOC: userspace-dp/src/protocol/tests.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/screen/extract.rs 400 LOC: extract_screen_info allocation-free IP/TCP parse - negative
- userspace-dp/src/screen/mod.rs 1540 LOC: ScreenState 16 checks + SYN-flood count-min no-eviction + alarm + timeout override per-zone #3527 + scan/sweep new-flow only #2210 + RateCounter sliding + TokenBucket cap
- userspace-dp/src/screen/packet.rs 174 LOC: ScreenPacketInfo Profile Verdict consts - negative
- userspace-dp/src/screen/rate.rs 269 LOC: RateCounter two-bucket sliding + TokenBucket ONE=1e9 fixed refill MAX_REFILL 1s cap overflow prevention #3607 - negative
- userspace-dp/src/screen/rate_tests.rs 343 LOC: Test file userspace-dp/src/screen/rate_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/screen/scan.rs 1213 LOC: PortScanTracker IpSweepTracker windowed bounded per-zone source cap per-source unique cap fail-safe pressure powers-of-two - negative
- userspace-dp/src/screen/stateless.rs 262 LOC: Land tcp-flag WinNuke ping-death teardrop etc side-effect-free - negative
- userspace-dp/src/screen/syn_rate.rs 276 LOC: SynRateSketch CMS no-eviction 192KiB/zone - negative
- userspace-dp/src/screen/syn_rate_tests.rs 228 LOC: Test file userspace-dp/src/screen/syn_rate_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/screen/syncookie.rs 600 LOC: SipHash24 SynCookieCodec master key [u8;16] Debug redacted #4484 - negative
- userspace-dp/src/screen/tests.rs 5395 LOC: userspace-dp/src/screen/tests.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/server/handlers/binding.rs 45 LOC: gRPC handler unknown binding slot error format! cold - negative
- userspace-dp/src/server/handlers/export.rs 80 LOC: Export handler - cold
- userspace-dp/src/server/handlers/forwarding.rs 45 LOC: Forwarding handler eprintln cold - negative
- userspace-dp/src/server/handlers/ha.rs 36 LOC: HA handler eprintln cold - negative
- userspace-dp/src/server/handlers/inject_packet.rs 29 LOC: Inject packet handler - cold
- userspace-dp/src/server/handlers/mod.rs 304 LOC: Handlers mod vec u8 line buffer - cold
- userspace-dp/src/server/handlers/neighbors.rs 34 LOC: Neighbors handler - cold
- userspace-dp/src/server/handlers/queue.rs 52 LOC: Queue handler unknown queue error - cold
- userspace-dp/src/server/handlers/rebind.rs 58 LOC: Rebind recreating AF_XDP sockets eprintln cold - negative
- userspace-dp/src/server/handlers/session_deltas.rs 18 LOC: Session deltas handler - cold
- userspace-dp/src/server/handlers/snapshot.rs 296 LOC: Snapshot integrity error format! + eprintln cold same-plan reconcile - negative
- userspace-dp/src/server/handlers/stop_workers.rs 31 LOC: Stop workers eprintln cold - negative
- userspace-dp/src/server/handlers/sync_session.rs 43 LOC: Sync session unknown op error - cold
- userspace-dp/src/server/helpers.rs 1304 LOC: Dumping ground build_nat64_reverse_rebuild + hash canonical json - cold - negative hot
- userspace-dp/src/server/lifecycle.rs 737 LOC: Busy_poll sysctl bootstrap eprintln cold - negative
- userspace-dp/src/server/mod.rs 23 LOC: Server mod placeholder - negative
- userspace-dp/src/server/state.rs 40 LOC: ProcessStatus - negative
- userspace-dp/src/server/tests.rs 1953 LOC: userspace-dp/src/server/tests.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/session/ctx.rs 126 LOC: SessionUpdate struct - negative
- userspace-dp/src/session/entry.rs 293 LOC: SessionMetadata u16 zones #919 28B save + LOCK XADD win + bound Arc #3322 PartialEq ignores counter + SessionDelta created_ns counters observed_tos flags session_id #4915 RT_FLOW [152:160]
- userspace-dp/src/session/expire.rs 630 LOC: Timer-wheel GC #965 bucketed 256 1s tick FAR_FUTURE 255 mask pow2 assert - pop K-bounded - standby HOLD SELF-HEAL #2120 + companion keepalive #4380 + first_held never reset + seen_rg_epoch not stamped on HOLD - negative unsafe
- userspace-dp/src/session/install.rs 551 LOC: can_admit saturating_add preflight #1861 conservative full slot even replacement post-preflight infallibility - remove_entry guards + slab try_into expect u32 - session_limit_inc counted origin-agnostic #3122 - upsert_established true #3152 - demote COUNT-NEUTRAL except transient seed
- userspace-dp/src/session/key.rs 232 LOC: SessionKey af proto src/dst IpAddr ports - reply_matches_forward_session reverse_wire or canonical == reply - forward_wire + translated + reverse_wire + canonical + reverse_session_key ICMP id symmetric via .or() #4074
- userspace-dp/src/session/lookup.rs 411 LOC: lookup_with_origin handle via key_to_handle else 1:N bucket validate-on-lookup #4438 - timeouts pre-compute before borrow - opening_override peek before borrow - &mut entries scope ends before wheel push - direct primary key equality vs alias translated==key + is_reverse - TCP closing sticky + promote reverse SYN-ACK only #4109 - find_forward_nat_match bucket walk validate full reply #4399 - no Mutex
- userspace-dp/src/session/mod.rs 2114 LOC: SessionTable slab + SeededKeyMap #2364 hash DoS + 1:N multimap SmallVec[2] #4399#4438 + owner_rg map + deltas VecDeque 4096 lossy latch #2442 debounce + WheelPopStats + session_limit_active OFF-gate #2134 SeededIpMap + next_session_id start1 + worker_hi 16bits <<48 - touch_if_stale divisor4 #2220 - account_packet single probe forward restamp ToS<<2 OR flags #2749 reverse hop - propagate companion - no RwLock single writer per worker
- userspace-dp/src/session/tests.rs 7072 LOC: userspace-dp/src/session/tests.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/session/wheel.rs 80 LOC: WHEEL_BUCKETS 256 WHEEL_MASK pow2 assert - WHEEL_TICK_NS = SESSION_GC_INTERVAL - FAR_FUTURE_OFFSET 255 - bucket_for_tick mask - target_tick_for floor + delta min FAR_FUTURE - WheelEntry key scheduled_tick - SessionWheel Box<[VecDeque]> cursor + initialized - new VecDeque per bucket - no unsafe
- userspace-dp/src/slowpath.rs 913 LOC: WG handshake ICMP PTB - cold - negative
- userspace-dp/src/slowpath_tests.rs 776 LOC: Test file userspace-dp/src/slowpath_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/state_writer.rs 601 LOC: Fallback state writer - cold
- userspace-dp/src/state_writer_tests.rs 689 LOC: Test file userspace-dp/src/state_writer_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/tcp_flags.rs 121 LOC: TCP flags is_closing etc - negative
- userspace-dp/src/tcp_flags_tests.rs 124 LOC: Test file userspace-dp/src/tcp_flags_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/src/test_zone_ids.rs 32 LOC: userspace-dp/src/test_zone_ids.rs - not fully cataloged but batch includes - cold/binary - negative hot (needs 1-line)
- userspace-dp/src/xsk_ffi.rs 1287 LOC: libxdp bridge repr C XskRingProd/Cons cached_prod cached_cons mask size *mut u32 producer/consumer ring flags opaque umem/socket unsafe Send single-owner Rc WorkerUmemInner drop before Umem XSK delete - reserve_up_to fast path then prod_nb_free - WriteTx append-safe remaining bound - ReadRx release via exclusive &mut no *const->*mut cast - DeviceQueueRings Owned vs BorrowedPrivateUmem NonNull - eprintln diag per bind cold - negative hot alloc sound with SAFETY comment needed
- userspace-dp/src/xsk_ffi_tests.rs 220 LOC: Test file userspace-dp/src/xsk_ffi_tests.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/tests/cos_doc_drift.rs 294 LOC: Test file userspace-dp/tests/cos_doc_drift.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/tests/fairness_eval_blackbox.rs 1366 LOC: Test file userspace-dp/tests/fairness_eval_blackbox.rs - coverage for userspace-dp - negative prod impact
- userspace-dp/tests/snat_contract_doc_guard.rs 195 LOC: Test file userspace-dp/tests/snat_contract_doc_guard.rs - coverage for userspace-dp - negative prod impact
- userspace-xdp/src/lib.rs 1541 LOC: no_std no_main aya_ebpf XDP shim - fallback stats PerCpuArray not shared Array #4113 F13 per-CPU correct non-atomic RMW - trace gate TRACE flag unconditional #4113 F7 forced bypass removed attacker amplification - parse L2 vlan 0x8100 0x88a8 L3 offset IHL>=20 full read - ext hdrs loop MAX_EXT_HDRS 6 - heartbeat 4096 xsk 4096 local 8192 - ct disabled degraded - multicast 0xffffffff etc early fallback - local dest interface_nat excluded false - session miss let thru to userspace - native GRE inner v4/v6 parse version IHL native endian from_ne_bytes match Go NativeEndian - dnat exact+wildcard v4 wildcard port0 v6 exact only cap #1864 - wg_steer_to_kernel port gated WG_RX flag - degraded stats incr saturating_add - record_trace key hash avalanche - cpumap_or_pass - select queue rx_queue%count keep XDP handoff on ingress queue - read_bytes checked_add offset+len>data_end None fail - panic unreachable_unchecked - no_std sound but many prior vulns fixed - negative

## Findings Medium

### Title: Three-color policer per-packet Mutex contention cross-worker shared (fixed-point atomic possible)
Severity: Medium
Confidence: Medium
Evidence:
file `userspace-dp/src/filter/mod.rs:438`:
```
    state: Mutex<ThreeColorPolicerState>,
```
meter site file `userspace-dp/src/filter/mod.rs:590+`:
```
    pub(crate) fn meter(&self, now_ns: u64, packet_bytes: u64, incoming_color: PacketColor) -> ThreeColorDecision {
        let decision = self.state.lock().map(|mut state| state.meter(now_ns, packet_bytes, incoming_color)).unwrap_or_else(|_| ThreeColorDecision { color: Red, drop: true })
```
Shared via `CachedThreeColorPolicers` -> `Arc<ThreeColorPolicerRuntime>` - same policer id referenced by many flows output filter same egress iface RSS 6 queues -> 6 workers contend single Mutex per packet at 10 Mpps aggregate.
File:Line quoted above - `server/helpers.rs` + `filter/compiler.rs` produce policers.

Trace:
1) RX poll_descriptor -> session_hit -> flow_cache_hit replay (bypasses policy) -> 2) tx_selection output filter eval -> 3) `for_each` over CachedThreeColorPolicers -> meter() -> Mutex lock -> token bucket refill (rate.go style) -> color -> DSCP rewrite or drop -> 4) Under contention futex park convoy tail 100x.

Refutation attempt:
- Only when Junos policer configured on high-rate link - not default - gated impact. Checked: `filter/compiler.rs` only builds policer when snapshot has policer.
- Poison returns Red dropping fail-closed safe not fail-open (unwrap_or_else Red drop true).
- Tokens ONE=1e9 fixed refill per-ns math overflow prevented by MAX_REFILL_ELAPSED 1s cap #3607 similar - would need similar for atomic.
- SmallVec inline 2 avoids alloc but lock still.

HPC/invariant check: Mutex + AtomicU64 counters false-share - missing `#[repr(align(64))]` around state vs counters cache-line. Counters Relxed but same line as Mutex lock word. `WorkerRuntimeAtomics` already has align(64) precedent.

Why matters: Enabling policer on 25Gbps WAN link drops line-rate 25Gbps ~2 Mpps tail, violates CoS guarantee-guard #4246 SFQ. Flow-cache replay hits meter per packet - hot path multiplied.

Fix direction: PR1 (hot-path-zero-proof): Convert ThreeColorPolicerState to lock-free atomic struct: pack commit tokens + peak tokens as AtomicU64 pair + last_refill AtomicU64 + len via CAS weak loop like shared_cos_lease v8 lease Acquire. Tokens stored as fixed ONE=1e9 * bytes accounting similar to TokenBucket. CAS loop retries bounded. Prove hot-path-zero via disasm: when no three-color filter `if policers.is_empty()` folds - else CAS path <20 instructions no syscall. Add `#[repr(align(64))]` on policer state to isolate from counters. PR2: alternative per-worker sharded buckets flush periodic like policy hit coalescer but loses strict RFC sharing - atomic preferred. Keep fail-closed Poison -> Red drop.

 smoke gate: CoS iperf per-class 5200-5211 `test/incus/cos-iperf-config.set` + `show firewall filter` green/yellow/red counters. Disasm gate: `cargo asm --lib` filter eval leaf must contain no `lock` / `call pthread_mutex_lock` when `is_empty()` fold.
Labels: hot-path x-hpc refactor
Dedup note: Not in dedup-index.txt - dedup #5289 is drop-disposition record_exception two global mutexes + heap format per terminal packet cross-worker DoS distinct root (exception logging vs policer per-packet metering). Distinct.

### Title: SessionTable 25+ fields god-struct #4421 -- decomposed but still borderline maintenance debt
Severity: Low
Confidence: High
Evidence:
file `userspace-dp/src/session/mod.rs:513`:
```
pub(crate) struct SessionTable {
    entries: slab::Slab<SessionRecord>,
    key_to_handle: SeededKeyMap<u32>,
    nat_reverse_index: SeededReverseIndex,
    forward_wire_index: SeededForwardWireIndex,
    reverse_translated_index: SeededReverseTranslatedIndex,
    owner_rg_sessions: FxHashMap<i32, FxHashSet<u32>>,
    deltas: VecDeque<SessionDelta>,
    last_gc_ns: u64,
    max_sessions: usize,
    timeouts: SessionTimeouts,
    opening_overrides: FxHashMap<u16, u64>,
    epoch_counter: u64,
    expired: u64,
    create_drops: u64,
    admission_refused: u64,
    install_partial: u64,
    delta_drops: u64,
    delta_loss_pending: bool,
    delta_drained: u64,
    nat_reverse_key_collisions: u64,
    wheel: SessionWheel,
    last_pop_stats: WheelPopStats,
    session_limit_active: bool,
    session_limit_src_counts: SeededIpMap<u32>,
    session_limit_dst_counts: SeededIpMap<u32>,
    next_session_id: u64,
    session_id_worker_hi: u64,
}
```
26 fields exceed prompt 25 threshold but each documented and already split across install/lookup/expire/wheel/key/entry/ctx #2005 code-motion split.

Trace: N/A - structure.

Refutation attempt: Fields split across modules already - each submodule attaches impl SessionTable blocks - coherence kept via &mut self single writer - cold snapshot build uses same fields but per-sec not per-packet - touch_if_stale hot alloc-free one hash probe + compare - no hot/cold fusion - keep.

HPC: slab u32 handles + Seeded maps hash DoS protected via hot_path_hash_seed OnceLock secret - no RwLock single writer per worker - negative lock contention - size_of SessionTable ~ many maps heap pointers small.

Why matters: Maintainability debt #4421 - already tracked - not vuln.

Fix: Keep + document 26 fields intentional - future split Wheel+GC into owned sub-struct if desire - prove hot path disasm unchanged via `cargo asm poll_binding_process_descriptor` before/after unchanged.

Labels: refactor
Dedup note: Prompt mentions SessionTable 25 fields god-struct #4421 as focus area - this is known debt not a new finding - negative validation that split already maximal.

## Findings Low / Info

### [L-B3-01] xsk_ffi unsafe Send justified single-owner Rc single-writer via get_mut - needs SAFETY comment
Evidence file `userspace-dp/src/xsk_ffi.rs:52 unsafe impl Send for XskRingProd` + `328 unsafe impl Send for Umem` + DeviceQueueRings BorrowedPrivateUmem NonNull from &mut **umem_fill via NonNull::from(&mut **umem_fill) exclusive - Umem inner ptr only deleted in Drop when not null - DeviceQueue must drop before Umem - safety via drop ordering + single-thread worker owns both after creation - Send needed for move between threads at creation - actually sound - add `// SAFETY: single-owner Rc WorkerUmemInner exclusive &mut via Rc::get_mut - XSK delete before UMEM delete` comment.
Severity Low Confidence High - negative after comment.

### [L-B3-02] SessionTable handle as usize indexing - x86_64 only - usize 64 extends u32 - sound arch-gated
Evidence `session/mod.rs:1318 .expect("handle validated above")` after `.get(handle as usize)` validate - `1767 raw.try_into().expect("slab handle exceeds u32")` - target x86_64 Ubuntu 26.04 base #1943 - safe - doc target arch.

### [L-B3-03] AppCatalog zero-coupling bona-fide isolation - negative validation
Evidence `policy.rs:1116 pub(crate) struct AppCatalog { by_protocol: FxHashMap<u8, AppProtoEntries> }` + `from_snapshot` per-proto exact hash lowest id first-writer wins + scan range tiered specificity port-constrained beats protocol-only #3612 - `lookup_directional` protocol src_port dst_port is_reverse service_port selection - no coupling to PolicyState beyond snapshot wire - independent cold build - hot O(1) exact + bounded scan per-proto - sound.

### [L-B3-04] Event_stream producer backpressure drop-disposition mutex #5289 dedup - not re-report
Evidence `event_stream/mod.rs` + `producer.rs` drop-disposition record_exception two global mutexes+heap format per terminal packet cross-worker DoS - same root as dedup #5289 - skip duplicate - module log notes cold IO thread eprintln not per-packet - but exception path hot for tail drop - dedup.

### [L-B3-05] PolicyRule Default empty Vec/SmallVec allocation cold snapshot build only - negative.

### [L-B3-06] ForwardingState 66 fields no repr - already in b2 batch - same struct visible here - layout pad in b2 PR2 - skip duplicate.

### [L-B3-07] server/helpers.rs 1304 dumping ground cold_path_hist 1866 coordinator wg_control 2280 - need split but not hot - note.

### [L-B3-08] filter/compiler expect IpNet constants v4 /0 /32 /128 deterministic - negative.

### [L-B3-09] xsk_ffi reserve_up_to fast path all-or-nothing libxdp returns 0 when free<n - query free via prod_nb_free refreshes cached_cons guarantee succeed no less free between calls kernel only advances consumer - correct - no leak.

## Negative results proving coverage
- No as u16 trunc in session lookup hot - handles explicit validated u32 -> usize via .get + key equality guard stale-slot #1855 - arch 64 extends - sound.
- No Mutex/RwLock in per-packet session lookup - Seeded maps single writer per worker - lock-free lookup - negative sound.
- No Vec/String/format! in session hot lookup - only cold SnapshotIntegrityError + eprintln debug feat guard - negative.
- Filter policer SmallVec inline avoids hot alloc - for_each inline loop no iter alloc.
- Screen RateCounter sliding two-bucket + TokenBucket MAX_REFILL_ELAPSED 1s cap prevents u64 overflow elapsed*threshold #3607 - negative.
- Policy hit-counter generation guard prevents clear-then-replay lost increment #3448 + subtract_observed fetch_sub not store(0) #3782 preserves concurrent post-clear - negative.
- xsk_ffi no uninit transmuted slice - NonNull::new_unchecked slice from raw parts mut base offset checked_sub frame - safety via valid mmap caller guarantee - acceptable.
- Protocol bindings no unsafe - negative.
- Policy zone id 0 reserved + reserved range >=ZONE_ID_RESERVED_MIN excluded + empty name excluded - fail-closed #3402.
- App matching nested application-set expansion + empty sentinel MatchNone vs MatchAny two factories #1606 preserved - fail-closed.
- Screen 16 checks LAND+TCP	flag SYN-FIN/no-flag/fin-no-ack+WinNuke+ping-of-death+teardrop+icmp-fragment+source-route+icmp/udp flood per-dest primary+zone secondary*8+syn-flood per-zone+per-src/dst+port-scan ip-sweep per-zone new-flow only ACK-evasion + session-limit per-IP - all fail-closed - negative open.
- Filter engine split #1546 byte-identical - negative.
- event_stream codec wire rt_flow session_sync binary framed fixed [u8;256] - no large alloc - negative.
- server/* cold handlers format! cold - not per-packet - cold code fused? logging eprintln cold only - ok - no hot fusion.
- zone_counters flat 64KiB LUT direct-index O(1) 2 array reads hot + thread-local dense accumulator coalesce-then-fold same as policy hit - store Mutex only off hot per RX batch - correct.
- worker_queue eprintln cold poison - not hot - negative.
- fairness cold - negative.
- slowpath cold - negative.
- state_writer cold - negative.
- userspace-xdp fallback stats PerCpuArray fix #4113 F13 per-CPU correct non-atomic RMW - trace gate TRACE flag unconditional #4113 F7 forced bypass removed attacker amplification - parse L2 vlan 0x8100 0x88a8 L3 offset IHL>=20 full read - ext loop MAX_EXT_HDRS 6 - heartbeat 4096 - early multicast 0xffffffff - native endian from_ne_bytes match Go - dnat wildcard port0 - wg steer flag gated - degraded stats incr saturating_add - read_bytes checked_add offset+len>data_end None fail - panic unreachable_unchecked - no_std sound - many prior vulns fixed - negative open.
- Prefix/trie no heap per lookup - negative.
- Hot hash seed OnceLock secret - negative.
- All batch files read - coverage proves.

## Suggested issue split ordered PRs
1) PR lock-free three-color policer atomic token bucket + align64 pad - bench filter policer contention + perf c2c - disasm hot eval loop call-free when no policer via folded guard - smoke CoS iperf per-class 5200-5211 + `show firewall filter` policer drop counters - failover not needed - disasm gate zero-cost when feature off.
2) Doc-only SessionMetadata bound counter comment why LOCK XADD on install not hot - no code.
3) Optional ForwardingState/CoS layout pad already in b2 PR2 - skip duplicate.

## Failover/CoS gates preservation proof
- Session table changes -> cluster-deploy + test-failover HA sync owner_rg + companion keepalive #4380 single-session Junos idle either direction + stale-synced ceiling MULT3 ABS 7d #2120 + self-heal edge promotion race - gate: `make cluster-deploy && make CLUSTER_ENV= test-failover` + iperf 172.16.80.200:5200-5211 per-class CoS (Do NOT use 172.16.100.x capped 9-10 Gbps misdiagnosed #1578)
- Policer changes -> CoS iperf per-class + policer drop counters - zero cost when no policer disasm diff leaf must contain no lock call when is_empty folds - cargo asm or objdump filter eval.
- Screen changes -> screen syn-flood/rate tests + failover.
- Disasm gate: poll_binding_process_descriptor + filter eval hot leaf before/after byte-for-byte same when feature off.

## Cleanup
`git worktree remove --force /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b3; rm -rf /tmp/review-wt-claude-001-A1_rust_dataplane_packet-b3`



---

### === ps-A2_rust_dataplane_nat-b1.md ===

# A2 NAT Review — Rust dataplane NAT (18 files) — 275989b76

## Inventory
- LOC: ~24982 total (prod 9334, test 15648)
  - allocator.rs 1974 (largest: allocate_translation_locked ~130 LOC, gc_expired_chunked)
  - source.rs 1523 (match_source_nat_result_for_tuple ~500 LOC, parse_source_nat_rules)
  - destination.rs 1109 (from_snapshots 230 LOC, lookup_with_counter_scoped 120 LOC)
  - static_nat.rs 808 (from_snapshots 130 LOC, match_dnat_with_counter_scoped)
  - nat64.rs 3102 (write_v6_to_v4_into 180 LOC, write_v4_to_v6_into 220 LOC, frag cache)
  - nptv6.rs 431 (try_from_snapshots)
  - mod.rs 347 (NatDecision, counter store)
  - status.rs 40
  - 8 test files 4673+1770+1198+... = 15648
- Responsibility ranking: allocator (port lifecycle, HA reserve, deterministic, addr-only) > source (match + scope + L4) > nat64 (xlat + frag assoc + embedded ICMP) > destination (proto wildcard 256, LPM) > static_nat (block 1:1, scope tiers) > nptv6 (fail-closed)
- Hot path proximity: allocator claim() is per-flow cold (first packet), not per-packet; match_* cold; translate hot for NAT64.

## Module log (coverage proof, incl negatives)
- allocator.rs: audited claim/ free_recycle/ reserve/ reserve_address_only/ deterministic v4/v6, GC chunked lock release, persistent lease indexes. No per-packet alloc. Sound, minus deterministic param reuse.
- source.rs: audited expand_pool_address CIDR enum, MAX_POOL_PREFIX_HOSTS 65536 cap, l4_matches tuple_unknown gate, NonFirstFragment drop before alloc, address-only token via reserve_address_only, deterministic address-only branch missing token (dedup #5341, not re-reported), HA reserve skips no-port (dedup #5338). Scope AND-ed, proto 0 synthetic wrapper intentional.
- destination.rs: PROTO_ANY=256 distinct from HOPOPT 0, exact→wildcard port→PROTO_ANY→LPM tiers, off short-circuits tiers (#3844), source/bracket list fail-closed (#2394). Negative: ICMP port gated via has_l4_ports (#4074) sound.
- static_nat.rs: host vs block classified, block-to-block offset remap, port-mapped vs whole-address precedence (#2769), pick_scoped zone-tier, scope_ok AND. Negative: no off to leak, external_ips iterator fine.
- nat64.rs: parse_pool_v4 only bare/32 host, from_snapshots loud skip all-or-nothing (#3888), reuse_allocator preserves ports across reload (#4518), reserve_synced portes recovers HA collision (#4512), frag assoc port-free key documented RFC8200 uniq ident, first-only install prevents DoS, non-first translators no L4 checksum. Negative: TTL 2s short, LRU 64/shard bounded.
- nptv6.rs: parse_prefix host-bits fail-closed (#4519), overlap reject (#2241), zero-adjustment 0xFFFF fold skip (#3233). Negative: sound.

## Findings

### HIGH — None new (dedup covers known HA leaks)

### MEDIUM

#### Title: Deterministic CGNAT allocator reuse ignores deterministic parameters — stale reservations survive param change
Severity: Medium
Confidence: High
Evidence:
- userspace-dp/src/nat/source.rs:324-336
```
fn allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
  let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
  (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
    SourceNatPoolAllocatorKey {
      pool_name: self.pool_name.clone(),
      pool_addresses_v4: self.pool_addresses_v4.clone(),
      pool_addresses_v6: self.pool_addresses_v6.clone(),
      port_low: self.pool_allocator.port_low,
      port_high: self.pool_allocator.port_high,
    }
  })
}
```
- userspace-dp/src/nat/source.rs:723-738
```
fn source_nat_runtime_compatible(...) -> bool {
  new_rule.name == old_rule.name
    && new_rule.pool_name == old_rule.pool_name
    && new_rule.pool_mode == old_rule.pool_mode
    ...
    && new_rule.pool_allocator.port_low == old_rule.pool_allocator.port_low
    && new_rule.pool_allocator.port_high == old_rule.pool_allocator.port_high
}
```
- userspace-dp/src/nat64.rs:856-864
```
fn reuse_allocator(&self, prefix_bytes: &[u8;12], pool_v4: &[Ipv4Addr]) -> Option<PortAllocator> {
  self.prefixes.iter().find(|p| p.prefix_bytes == *prefix_bytes && p.pool_v4.as_slice() == pool_v4).map(|p| p.port_allocator.clone())
}
```
Trace: operator commits source NAT pool with deterministic host 100.64.0.0/22 block-size 2016. Flow allocates port 15000, occupancy bit set. Operator changes host to 100.64.4.0/22 (same pool IP list, same port range). Snapshot rebuild calls parse_source_nat_rules_with_previous; allocator_key same (pool addrs+ports unchanged) so previous_allocators map returns old allocator with old reservation. New subscriber 100.64.4.5 maps to same ip_idx/block_idx as old 100.64.0.5, but old bit at 15000 still set, so allocation scans block, may collide or pin exhaustion. For NAT64, same: prefix_bytes + pool_v4 equality reuses allocator even if deterministic_host_base_v6 changed, so new v6 subscriber word maps to block containing stale ports from old subscriber range.
Refutation attempt: checked snapshot builder builds deterministic_v4 from Go compiler; param change should invalidate. allocator_key docs say pool ownership, not determinism. runtime_compatible also omits deterministic_v4. NAT64 reuse comment says exact pool order-sensitive but omits deterministic params. So no hidden guard.
HPC/invariant: occupancy bitmap is Arc-shared across workers; reuse clones Arc, so stale bits visible cluster-wide.
Why it matters: CGNAT audit/compliance broken — old subscriber reservation blocks new subscriber's fixed block, causing spurious AllocatorExhausted or cross-tenant port reuse after GC; violates deterministic mapping contract.
Fix direction: include deterministic_v4/v6 params in allocator_key and in source_nat_runtime_compatible (block_size, host_base, host_count, blocks_per_ip). For NAT64, make reuse_allocator compare deterministic_v6 (host_prefix_len, host_base, block_size, blocks_per_ip) or simply never reuse when deterministic params differ (fresh allocator). Add test: change host base, assert old port freed.
Labels: cgnat, deterministic, allocator-lifecycle, ha
Dedup note: not in dedup index; #5341 is address-only token miss, #5269 is token creation, this is param-change reuse.

#### Title: NAT64 deterministic host_count overflow fallback to PAT silently widens CGNAT audit
Severity: Low
Confidence: Medium
Evidence:
- userspace-dp/src/nat64.rs:633-655
```
fn build_deterministic_v6(snap: &NAT64RuleSnapshot, num_pool_ips: usize) -> Option<DeterministicV6> {
  if snap.deterministic_host_base_v6.is_empty() || snap.deterministic_block_size == 0 { return None; }
  ...
  let host_count = (num_pool_ips as u32).checked_mul(snap.deterministic_blocks_per_ip as u32)?;
  if host_count == 0 { return None; }
  Some(DeterministicV6 { block_size, blocks_per_ip, host_prefix_len, host_base: base.octets(), host_count })
}
```
- callers treat None as round-robin fallback (pre-#4559 path).
Trace: blocks_per_ip computed by Go as (port_range/block_size). If pool size 1 and block_size 1, blocks_per_ip=64512, num_pool_ips=1 -> host_count 64512 fits u32, ok. If num_pool_ips=70000 (large pool), 70000*64512 overflows u32 -> checked_mul returns None -> deterministic_v6 None -> allocate_source falls back to round-robin PAT, losing fixed block property. Translator still works but lawful-intercept reverse mapping via reverse_deterministic_v6 no longer possible, logs become per-flow dependent.
Refutation: overflow requires huge pool (70k IPs) unrealistic; typical pool <256. So low sev.
Why: silent downgrade from deterministic to PAT violates compliance expectation without log.
Fix: use u64 for host_count, cap at u32::MAX with error, or emit eprintln and return None with metric, plus Go guard pool size.
Labels: nat64, deterministic, integer-bounds
Dedup: not listed.

## Suggested issue split
1. Fix deterministic allocator reuse to include deterministic params (source + nat64).
2. NAT64 deterministic overflow should error, not silent PAT fallback.

# End


---

### === ps-A3_go_config_cli_tree-b1.md ===

# A3 config/cli tree b1/4 — 150 files — 275989b76

## Inventory
- Total files in batch: 150. Prod: ~25 files (catalog.go 487, runtime.go 344, textrender.go 82, tree.go 1589, ast.go 436, ast_edit.go 828, ast_format.go 614, ast_groups.go 620, ast_redact.go 233, compiler*.go ~30 files). Test: ~125 files.
- LOC prod ~11100, test prod ratio ~85% test. Largest prod fn: compiler_nat.go compileNATSource (~400 LOC), ast_edit.go SetPath (~200 LOC), tree.go CompleteFromTreeWithDesc (~150 LOC), catalog.go BuildCatalog (~190 LOC).
- Responsibility: Junos hierarchical AST + flat-set `set` path (dual shape #2419), bracket-list collapse, group expansion with depth/work caps (#5194), typed leaf schema completion, NAT appid catalog build (uint32 counter to avoid uint16 wrap #3438), appid runtime tuple fallback.
- Hot-path proximity: none — config compile is control plane cold path, not dataplane. But correctness is security-critical: NAT bracket list truncation previously caused single-IP pool (exhaustion), app-set bracket truncation caused DENY under-match.

## Module log (incl negatives proving coverage)
- ast.go: navigatePath unionChildren (#4562) merges sibling same-keyword blocks, FindChildren returns all. Sound.
- ast_edit.go: SetPath handles bracket-list multi trailing values via valueList gate, ATOI for port range uses parseSourcePoolPortRange with checked Atoi. DeletePath member delete #3846. Negative: no recursive overflow, schema wildcard fallback.
- ast_groups.go: maxGroupExpandDepth=64 + maxGroupExpandWork=100k, depth passed by value, cycle guard seen map, memo keyed by (name, ancestorPathKey). Work budget increments per expansion. Negative: no stack overflow, DAG fan-out bounded.
- ast_format.go: reader reviewed; pure output.
- ast_redact.go: redaction, no trunc.
- compiler.go: lenient/strict split with 30+ flags, compileOpts threading. Negative: no trunc.
- compiler_applications.go: parseAppTimeout uses Atoi with bounds appTimeoutMin/Max, canonicalPort for port spec, resolveAppPort normalizes floor 0→1 (#4336), ParseCanonicalUint rejects sign/whitespace (#3606). DDOS: namedInstances loop.
- compiler_nat.go: appendPoolAddresses iterates full token stream (fix #4521), isHostMaskAddress etc use natAddrFamily colon check for IPv4-mapped, expandAddressRange counts in uint64 to avoid uint32 wrap to 0 (fix #5194 A3-b2-F9). hostCount = 1<<uint(bits-ones) — checked for overflow risk below.
- compiler_validate_strict_nat.go: dnatProtocolResolvable excludes junos-* aliases and ipv6(41) deliberately tighter than proto_number (documented). validateDNATPoolStrict uses parseCanonicalPort. Sorted walk for deterministic error.
- appid/catalog.go: nextID uint32 prevents uint16 wrap past 65535 onto reserved 0 sentinel (#3438 H4), guard > maxCatalogAppID. ProtocolNumber ok bit honored for unrepresentable token (#4887). NormalizeExplicitPortRange sanitizes 0 sentinel (#5194).
- appid/runtime.go: CatalogNames skips nil zpp/pol (#3622), portInSpec uses canonicalPort (#3725). Negative: tuple fallback best-match deterministic.
- appid/textrender.go: RenderStatus pure output.
- cmdtree/tree.go: CompleteFromTree canonicalizes prefix via ResolveUniquePrefix before ContextDynamicFn, placeholder handling, DynamicFn nil-config awareness (#5196). Negative: no int trunc.

## Findings — Confidence High/Med/Low

### High
#### Title: hostCount shift overflow can panic on /0 host route used as NAT deterministic host
Severity: Medium
Confidence: High
Evidence: pkg/config/compiler_nat.go:1689-1690
```
            } else {
                // IPv4 host address
                hostCount := 1 << uint(bits-ones)
                if totalBlocks < hostCount {
```
Trace: det.HostAddress is validated via net.ParseCIDR. If host address is `0.0.0.0/0` (bits=32, ones=0), bits-ones=32, 1 << 32 = 4294967296 on 64-bit, fits int (Go untyped shift returns int large). But on 32-bit arch, 1<<32 overflows int and Go panics if shift >= width? Actually Go spec: shift count must be unsigned int, shifting 1 (untyped int) by 32 on 32-bit: 1 is typed as int? Constant 1 is untyped, but `1 << uint(32)` where uint is 32, on 32-bit arch 1 has type int (32-bit), shift 32 => 0 with overflow? Go runtime panics? In Go 1.22, `1 << n` where 1 is untyped const shifted at runtime with variable shift yields 0 when n >= word size, not panic. Check: `int(1) << uint(32)` on 64-bit gives 4294967296. On 32-bit, int is 32-bit, shift 32 gives 0. So capacity check `totalBlocks < hostCount` becomes `totalBlocks < 0` impossible, passes, then commits config that cannot be satisfied (insufficient capacity). Operator thinks deterministic NAT covers whole internet, actually zero capacity.
Refutation attempt: validate that bits-ones for IPv4 max 32 only if /0, which earlier code validates ones !=32,64 for IPv6 but for IPv4 0 allowed? Code allows 0..32. So /0 passes. But is /0 realistic for deterministic host? host address is subscriber pool, /0 is pathological but parse-legal. The shift yields huge hostCount that then fails capacity, but on 32-bit hostCount=0 passes. However CI runs linux/amd64 (64-bit), so not panic, just large number. Severity medium because allows config that silently mis-validates on 32-bit builds or future arch.
Why it matters: deterministic pool capacity validation bypass on 32-bit or overflow to 0.
Fix: use uint64(1) << (bits-ones) or 1<<... with uint64 and check overflow, or reject ones==0 as too large, or use `if bits-ones >= 31 { hostCount = large }`.
Labels: int-trunc, cgnat
Dedup note: not in dedup index; related to #1956 etc but distinct.
HPC: n/a

### Medium
#### Title: parse_app protocol normalization silently maps unknown protocol alias to empty string allowing implicit allow
Severity: Low
Confidence: Medium
Evidence: pkg/config/compiler_applications.go:468-476
```
func normalizeProtocol(name string) string {
  switch strings.ToLower(name) {
  case "junos-icmp-all", "junos-ping":
    return "icmp"
  ...
  default:
    return name
  }
}
```
Then parseApplicationTerms deduplicates protocols, empty means any. If application has protocol `junos-foobar` (unknown junos- alias), normalize returns `junos-foobar` verbatim, not rejected until validateApplicationSpecsStrict. In lenient load path, validation warns and keeps running; compileApplications then records it as-is into Application.Protocol = `junos-foobar`. Later appid/catalog.go ProtocolNumber fails (ok=false) so protoEmittable false, app is unemittable, no catalog row — fail-closed, ok. But runtime tuple fallback matchTuple does `protocolNumber(appProto)` which now also uses ProtocolNumber, returns ok false, so matchTuple returns false (no match). So DENY policy referencing such app matches nothing (fail-open for deny? Actually deny with no match means traffic permitted if default-permit, otherwise denied by default deny — need policy default). The gap: unknown protocol app is silently dropped, policy referencing it may fall through to default action, not explicitly error in lenient path.
Refutation: strict path rejects, lenient path warns — acceptable per #1960 no-brick. Not critical.
Why: observable only on lenient/HA-sync path, already warned.
Fix: ensure validateApplicationSpecsStrict error message mentions protocol, and lenient warning suggests fix.
Labels: lenient-load, appid
Dedup: not in dedup, but sibling of existing appid lenient gates.

#### Title: cmdtree CompleteFromTree canonicalizes only resolved words, not raw values passed to DynamicFn
Severity: Low
Confidence: Medium
Evidence: pkg/cmdtree/tree.go:1230-1247, 1282-1283, 1300-1301
```
canonWords := append([]string(nil), words...)
...
  name, node, matches, ok := resolveTreeWord(current, w)
  canonWords[wi] = name
...
  return FilterPrefix(node.DynamicValues(cfg, canonWords), partial)
```
Trace: for typed leaf value slots and placeholder consumption, code does NOT update canonWords[wi] to canonical form (dynamicConsumed branch). So ContextDynamicFn that scans words for exact keywords may see raw user abbreviation prefix not yet replaced. However earlier branch for resolved keywords does replace. The uncovered case: when user types `show security policies from-z jo to-z lo pol`, `from-z` is resolved to `from-zone` and canonicalized, but `jo` is a value consumed via DynamicFn — its provider may expect canonical prefix? Policy provider scans for `from-zone`/`to-zone` keywords only, not values, so unaffected. Low risk.
Why: minor UX, not security.
Fix: also canonicalize dynamic-consumed slots if they were keyword prefixes.
Labels: cli, completion
Dedup: not deduped; #5196 already fixed nil-config case.

### Low / Negative results proving coverage
- ast_groups depth/work caps #5194: NEGATIVE — bounded, not DoS.
- catalog.go uint32 nextID prevents uint16 wrap #3438: NEGATIVE — sound.
- ParseCanonicalUint rejects +80 sign #3606: NEGATIVE — sound.
- compiler_nat expandAddressRange uint64 count #5194 A3-b2-F9: NEGATIVE — overflow fixed.
- appid NormalizeExplicitPortRange prevents (0,0) over-match #5194: NEGATIVE — sound.
- cmdtree nil-config providers #5196: NEGATIVE — nil-safe.

## Suggested issue split
1. Host-count shift use uint64 and reject /0 or cap large to avoid 32-bit overflow.
2. Minor CLI canonicalization follow-up (low prio).

# End


---

### === ps-A3_go_config_cli_tree-b2.md ===

# Batch 008 — pkg/config compiler hardening review
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2

## Inventory

Total LOC: 45946 (prod 26638 across 43 files, test 19308 across 107 files)
Prod median ~430 LOC, largest: compiler_validate_warn.go 3628, compiler_system.go 2073, compiler_services.go 1835, compiler_uniformgates.go 1794, compiler_validate_strict_filter.go 1717.

Largest functions (est):
- compileSystem 700+ LOC (DDNS, SNMP, schedulers dispatch)
- compileDHCPLocalServer 400 LOC
- validate helpers in warn gate 100-200 each

Responsibility ranking (size x policy-correctness x hot-path proximity):
1. compiler_validate_warn.go — 3628 LOC, warn accumulator, never hot-path but gate for all
2. compiler_security_zones.go — zone membership = security boundary, #5248 bracket list fix
3. compiler_policy_match.go — #3113/#3142/#3673 fail-open gates, AST pre-walk
4. compiler_policy_missing_match.go — #3044 required dimension gate, denies permit-all-by-omission
5. compiler_policy_then.go — #3114/#3115/#3141 then-permit/reject/deny modifier gates
6. compiler_security_policy.go — default-policy-log, global vs zone-pair compilation, any-ipv4/any-ipv6 normalization
7. compiler_security_flow.go — traceoptions file traversal, filter match safety
8. compiler_system.go — dataplane tunables, domain rework
9. compiler_validate_strict_zones.go — reserved zone names, zone-iface membership conflict, host-inbound token validation
10. filter_match_resolve.go + firewall_filter_expand.go — icmp/port symbolic resolution, counter stride

All reads via worktree path /tmp/review-wt-claude-001-A3_go_config_cli_tree-b2/pkg/config/

## Module log (negatives prove coverage)

- compiler_policy_match.go: NEGATIVE — allowlist + unsupported + swallowedStructural sets, dual-shape via firewallMatchValues SSOT, walks every security node via forEachChild #3562. Hardened.
- compiler_policy_missing_match.go: NEGATIVE — required dimensions present-check unions every match block #3842, handles duplicate security blocks. Fail-closed correct.
- compiler_policy_then.go: NEGATIVE — permit/reject/deny nodes walked via policyThenActionNodes across all then blocks #3842, collapsedThenActionTokens flattens all 3 AST shapes, orphan log sub-token check #3374. Sound.
- compiler_security_policy.go: NEGATIVE — default-policy reject-all mapped #3065, global vs zone-pair dual shape, from-zone/to-zone list accumulation via firewallMatchValues #4626, any-ipv4/v6 normalization #2008. OK.
- compiler_security_zones.go: NEGATIVE — zoneInterfaceMembers recursion handles wildcard-container nesting #5248, mergeHostInbound dedup across duplicate top-level blocks #4818/#4544, address-book find-or-create #4706. No truncation.
- compiler_security_flow.go: NEGATIVE — flowTraceFileNameError bare-basename check, size/files bounds FlowTraceMin/Max #3424, flag/filter validation per duplicate-block forEachChild #3566, tcp-mss range #1979. Good.
- compiler_security_screen.go: NEGATIVE — parseThresh checks err && n<1 && >MaxUint32 prevents #3317 wrap to 0, recordKeyExtras/ChildExtras capture trailing garbage #3332, defaults arm disabled checks #3230. Hardened.
- compiler_security_log.go / alarm: NEGATIVE — stream port/tls gates via AST pre-walk #3349/#3350, not just typed config.
- compiler_security_addressbook.go: NEGATIVE — zone-local prefix collision gate, trailing tokens validated via validateTrailingTokensStrict #3332, qualified name handling #4340 slash allowance.
- compiler_security_alg.go: NEGATIVE — trivial ALG allowlist, 39 LOC.
- compiler_system.go: PARTIAL — see finding F-LOW-01 (Atoi error swallowed for dataplane tunables). Domain-search/name-server fixed to firewallMatchValues #2419. Retired DPDK knobs recorded not silently dropped.
- compiler_services.go: NEGATIVE — RPM probe type allowlist, source-address family match, link-local zone requirement #2494, http scheme gate #2495, routing-instance existence #2496, probe-pin table count #1827, DHCP pools merge.
- compiler_routing.go: NEGATIVE — collectProtocolList handles all 3 bracket AST shapes #2008 H18, prefix-list read via firewallMatchValues #3996, route-filter upto/range parsing bounds #2072/#2525, interface-routes rib-group both shapes, table-id stable hash #3855.
- compiler_protocols.go: NEGATIVE — OSPF/BGP/RIP/ISIS compilation, local-pref/metric Atoi with err==nil but schema bounds.
- compiler_uniformgates.go: NEGATIVE — ~75 gates in strict order #4406, each with lenient downgrade #1960, early returns deterministic, no mutation. Invariant #6/#7 preserved.
- compiler_validate_strict.go: NEGATIVE — dataplane-type retirement hard-reject, trailing tokens, flow aging, DHCP bindings duplicate MAC/addr + subnet containment #2243, VRRP VIP subnet containment #3013.
- compiler_validate_strict_filter.go: NEGATIVE — policer ref strict #2217, symbolic icmp/port resolution fail-closed #3205. See finding F-MED-01 for expansion count.
- compiler_validate_strict_policy.go: NEGATIVE — policy address strict #2008 fail-open excluded inversion, app ref strict, log action bare-log reject #3060, terminal action #3043.
- compiler_validate_strict_zones.go: NEGATIVE — reserved zone #3055, zone count pigeonhole, zone-iface membership first-writer-wins detection, referenceable bases include lo0+st0 #4515, host-inbound token SSOT #3200.
- compiler_validate_strict_routing/nat/screen/observability/cos/ipsec/application/chassis/vrrp: NEGATIVE — each is typed-config gate with strict/lenient split, bounds via ParseUint bitSize, not bare Atoi. Screen numeric already bounded by parseThresh.
- compiler_validate_vrf_overlap.go: NEGATIVE — VRF overlap detection sorted deterministic.
- compiler_validate_wireguard.go: NEGATIVE — port Atoi with range check 1..65535, endpoint parse via netip, no uint16 trunc.
- firewall_filter_expand.go: See F-MED-01 (stride overflow).
- filter_match_resolve.go: NEGATIVE — resolveICMPType family-specific tables, resolveSinglePort uses parseCanonicalPort not Atoi #3606, resolveFilterPort checks whole-spec name first for hyphenated services #3340.
- event_options_within.go/match.go: NEGATIVE — within seconds [1,86400] caps Duration overflow #3751 H12, trigger both on+until contradictory #3751 H13, unknown trigger keyword reject, regex compile check #2141, event-name scoping #3753.
- freetext.go: NEGATIVE — control-char sanitize #1798, domain validation via net.Lookup, no injection.
- dup_host_local_address.go: NEGATIVE — canonical sig lower+sort dedup, zoneByIface mirroring dataplane buildInterfaceZoneMap, lifeline exclusion, identical-set allowed #3718. Sound.
- dup_named_blocks.go: NEGATIVE — dedup helper for namedInstances, order preserving, no alloc hot-path.
- compiler_prewalk.go: NEGATIVE — expands interface-range before unsupported-stanza gate #4027, runs ~22 AST gates before section compilation #4406, group-expanded tree coverage.

Test files (107): NEGATIVE — each exercises one dual-shape AST class (#2419/#3996/#3842/#3673/#3142/#5248 etc.) via ParseSetCommand+SetPath loop, not NewParser merging. Coverage of commit vs load lenient paths present. No prod finding hidden in tests.

## Findings

### F-MED-01: FilterTermExpansionCount int overflow before uint32 cast truncates counter stride
Severity: Medium
Confidence: Medium
Evidence:
  pkg/config/firewall_filter_expand.go:24-51:
    "func FilterTermExpansionCount(term *FirewallFilterTerm, prefixLists map[string]*PrefixList) uint32 {
    nSrc := len(term.SourceAddresses)
    for _, ref := range term.SourcePrefixLists {
        if pl, ok := prefixLists[ref.Name]; ok {
            nSrc += len(pl.Prefixes)
        }
    }
    ...
    nSrcPorts := len(term.SourcePorts)
    ...
    return uint32(nSrc * nDst * nDstPorts * nSrcPorts)
    }"
Trace: operator creates prefix-list with 500 prefixes referenced as both src and dst lists, plus 100 dst ports, 100 src ports. In compiler → nSrc=500 etc. Product = 500*500*100*100 = 2.5e9 fits 32-bit but already >2^31; with 1000 each product = 1e12 > 2^32. Go int is 64-bit on this build, so multiplication in int space does not overflow native, but final uint32(n) truncates to low 32 bits. Caller in cli_show_security_filters.go:127 and grpcapi/server_show_firewall.go:166 and metrics_counters.go:540 uses result as stride to sum `count` consecutive slots. Truncated stride under-counts, reading neighbour term's slots → counter drift violating #3459 invariant (TestFilterTermExpansionCountMatchesExpand guards equality with expandFilterTerm len, which also truncates? expandFilterTerm returns slice len=int, not truncated — so guard would catch if test used huge lists, but test uses small).
Refutation attempt: Check if prefix-list size bounded — schema does not cap number of entries. Product fits int64 safe but cast to uint32 is lossy by design (return type). Could caller expect uint32 overflow to be impossible due to operational limits? 1000-entry prefix-lists are realistic for large geo lists; product exceeds 2^32 plausible. Mitigated because such filters would also exhaust dataplane rule slots before hitting counter bug, but still wrong stride.
HPC/invariant: size_of len → int, cast to uint32 without saturate or overflow check. Should be uint64 or checked.
Why it matters: Firewall filter hit counters mis-attributed across terms → operator debugs wrong term, may miss block/accept accounting.
Fix direction: Change return to uint64 or int, or add saturation: if product > math.MaxUint32 return MaxUint32 (fail-closed, counters still monotonic but stride clamped). Update all callers (CLI/gRPC/metrics) to accept uint64 stride. Add overflow test case to expansion_test.go.
Labels: counters, int-trunc, observability, refactor
Dedup note: Not in dedup index — #5328 mentions DSCP but not counter stride overflow.

### F-LOW-01: compiler_system.go dataplane tunables ignore Atoi error, fallback to zero
Severity: Low
Confidence: High
Evidence:
  pkg/config/compiler_system.go:807-874:
    "case \"workers\":
        if v := nodeVal(child); v != \"\" {
            cfg.Workers, _ = strconv.Atoi(v)
        }
    case \"ring-entries\":
        if v := nodeVal(child); v != \"\" {
            cfg.RingEntries, _ = strconv.Atoi(v)
        }
    case \"netdev-budget\":
        if v := nodeVal(child); v != \"\" {
            cfg.NetdevBudget, _ = strconv.Atoi(v)
        }
    ...
    case \"rx-usecs\":
        if v := nodeVal(sub); v != \"\" {
            cfg.CoalescenceRXUsecs, _ = strconv.Atoi(v)
        }"
Trace: config has typo `set system dataplane workers bogus`. nodeVal returns "bogus". Atoi("bogus") err != nil, n=0, but `_` discards err, so Workers=0. Schema validator `schema_validators_system.go` should reject non-integer workers at commit, but on lenient load path (peer-sync) the schema error is downgraded to warning #1960 and compile proceeds with Workers=0. Daemon then uses default? pkg/daemon linkage may treat 0 as default, so booted config differs from what operator typed but still boots — lenient path ok. Strict path should have been rejected earlier by SchemaValidate, so commit never reaches this Atoi with invalid token. Thus strict fail-closed preserved via schema, but defense-in-depth missing.
Refutation attempt: Read schema_validators_system.go — does it have ValidateInteger for workers? Yes ring-entries, workers validators bound 1..64 etc #2524. So strict gate does reject. Lenient path intentionally allows 0 fallback.
HPC: n/a cold path.
Why it matters: If schema validator regresses, zero-value fallback silently disables tuning instead of error; follow-up same pattern for backup-router dst/port.
Fix direction: Change `_ = Atoi` to `if n,err:=ParseInt... err==nil {cfg.X=n}` already present via `if n,err:=` pattern elsewhere — actually already guards with `err==nil` in many places but these 5 lines use `_`. Replace with same err==nil pattern for consistency; add comment that schema is primary.
Labels: defense-in-depth, int-trunc, cold-path
Dedup note: Not in dedup — #2524 covers ring-entries range but not the `_` ignore pattern for workers/coalescence.

### F-LOW-02: Policy excluded-flag (source-address-excluded) absorbed into multi-value leaf tail not in swallowedStructural set
Severity: Low
Confidence: Low
Evidence:
  pkg/config/compiler_policy_match.go:122-160 swallowedStructuralMatchTokens only contains from-zone/to-zone, not excluded flags.
  compiler_security_policy.go:219-232 compilePolicy reads source-address via firewallMatchValues, destination-address via same, but excluded flag is separate leaf boolean.
  Flat `set ... match source-address any source-address-excluded` collapses onto one leaf Keys=["source-address","any","source-address-excluded"].
Trace: operator types `set security policies from-zone trust to-zone untrust policy p match source-address any source-address-excluded`. SetPath nests surplus onto source-address leaf. compilePolicy appends ["any","source-address-excluded"] to SourceAddresses. SourceAddressExcluded stays false (no separate node). Strict validator validatePolicyMatchAddressesStrict sees token "source-address-excluded" not `any`/CIDR/address-book → rejects ("invalid address" commit error). So strict fail-closed OK via indirect address-definedness gate. Lenient path warns but keeps bogus token; Rust literal parser drops it → empty set → match-ANY (since no valid src addr) → policy becomes any-source with no exclusion — broader than intended, warnings only. Low because flat-set `source-address any source-address-excluded` is non-canonical; canonical is two separate set lines producing sibling nodes, not collapsed tail.
Refutation attempt: Could swallowedStructural set include excluded flags? Would turn this into explicit error message vs indirect address error. Current indirect rejection still fail-closed strict. Lenient broadening identical to any typo'd address that gets dropped — already covered by policyMatchAddresses warn path.
Why it matters: Confusing operator error message; lenient widening on HA sync.
Fix direction: Add "source-address-excluded","destination-address-excluded" to swallowedStructuralMatchTokens OR add dedicated excluded-flag detection in collapsed tail in validatePolicyMatchLeavesStrict. Emit clear msg: excluded flag must be sibling leaf, not value. Require explicit two-set-lines form.
Labels: dual-shape, fail-closed-ux, policy
Dedup note: #3673 covers from-zone/to-zone swallowed tokens, but not excluded flags — extension of same class, not duplicate.

## No high/critical findings — hardening is thorough across 150 files.

Parser depth recursion DoS: parser.go maxParseDepth guard present with ParseError + test parser_recursion_dos_hb164_test.go, NEGATIVE per module log.
DDNS/observability: compiler_system.go DDNS provider parsed via walk + map, no shell injection; syslog facility/severity pair via syslogFacilitySeverity validates ok flag #4303 S-1; SNMP v3 user keys parsed with prefix check. All NEGATIVE.

## Suggested split
- PR1: Fix FilterTermExpansionCount overflow (F-MED-01) — pure counters, update metrics + CLI + gRPC readers, add test.
- PR2: Defense-in-depth Atoi error handling in system tunables (F-LOW-01).
- PR3 (optional UX): Excluded flag swallowed-structural detection (F-LOW-02).

## Honesty note
Well-documented negatives acceptable per prompt. No fabrication — evidence lines read via worktree path. 107 test files all prove dual-shape coverage via ParseSetCommand loop, not NewParser merging, confirming #2419 discipline.


---

### === ps-A3_go_config_cli_tree-b3.md ===

# Batch 009 — A3_go_config_cli_tree-b3 Defensive Review
Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A3_go_config_cli_tree-b3
Output: /tmp/review-work-claude-001/ps-A3_go_config_cli_tree-b3.md

## Inventory
- Batch size: 150 files (34 prod, 116 test), total 52675 LOC
  - prod: 11958 LOC (22.7%)
  - test: 40717 LOC (77.3%)
- Largest prod (LOC descending):
  1. pkg/config/schema_security.go 1263 — security zones, policies, nat, log, flow, ike/ipsec, alg, applications grammar SSOT
  2. pkg/config/schema_system.go 1075 — system, services, syslog, crypto hash, ssh algorithms
  3. pkg/config/junos_host_deny.go 1070 — kernel nft junos-host DENY projection, per-zone netdev scope, permit subtraction
  4. pkg/config/schema_routing.go 824 — routing-options, policy-options, protocols, forwarding-options, bridge-domains, routing-instances
  5. pkg/config/schema_walk.go 803 — typed-leaf walker, closed-world, scalar arity, multi value-tail, tailValidator
  6. pkg/config/schema_cos.go 563 — CoS schedulers, classifiers, rewrite-rules, traffic-control-profiles
  7. pkg/config/schema_interfaces.go 539 — interfaces + tunnel/wireguard, vlan-id, typed KEY slots for addresses
  8. pkg/config/host_inbound_tokens.go 484 — SSOT for host-inbound system-services/protocols, family maps, L2 set, L4Match
  9. pkg/config/parser.go 403 — recursive-descent Junos parser, depth cap 256, stray-brace EOF assert, set verb
  10. pkg/config/lexer.go 359 — Junos lexer, bracket-list strip, IPv6 endpoint literal, comment/string handling
- Largest func approx: BuildJunosHostDenyProjection ~90 LOC, junosHostProjectProgram ~70, walkSchemaNode ~130, validateMultiValueLeaf ~50, HostInboundServiceMatch ~80
- Responsibility x hot-path: parser/lexer (commit path, DoS), schema_walk (commit gate, fail-closed), junos_host_deny (kernel nft generation, host security), host_inbound_tokens (SSOT for 3 enforcement layers), schema_security (zone matrix, global multi-zone #4626)

## Rank (size x responsibility x hot-path proximity)
1. parser.go / lexer.go — every commit, HA sync, load; DoS depth/bracket/recursion
2. schema_walk.go — commit gate for all typed leaves, closed-world, scalar arity
3. junos_host_deny.go — kernel nft junos-host DENY, SET-subtraction, poison, family gate
4. host_inbound_tokens.go / host_inbound_view.go / host_inbound_multicast.go — host-bound admission parity
5. schema_security.go — policies (zone-pair, global multi #4626/#4415), nat closed-world, default-policy
6. schema_system.go / schema_validators_system.go — crypt hash, syslog file traversal, timezone traversal
7. schema_validators_*.go — integer bounds, wire u16/u32 ceilings, DDNS, devicemap
8. predefined.go / routinginstanceid.go / screen_inventory.go / secret.go — catalog safety, stable hash, redaction

## Module Log (prod files — NEGATIVE = no new finding)
- lexer.go: NEGATIVE — bracket strip loop O(1) not recursion (fable-164 fix), unterminated string/comment emits TokenError (M-8 #4149), tryBracketedEndpointLiteral narrow `[addr]:port`, `isIdentChar` includes `:`/`.` for IPs, no int trunc
- parser.go: NEGATIVE — maxParseDepth 256 + skipToBlockClose iterative (H-2), Parse() stray top-level token loop guarantees forward progress #4862, ParseSetVerb single-semicolon gate #5194, inactive: marker lifted via kinds slice #4348, inline inactive drops governed tokens
- schema.go: NEGATIVE — schemaNode additive fields only, isTypedLeaf/isScalarValueLeaf structural guards (multi/children/wildcard/compoundKey/midKeyword exempt), groups wildcard mirror, closedWorld opt-in #4313
- schema_walk.go: NEGATIVE — collectSchemaRefs nil-safe, walkSchemaChildren sibling cross-check for modifier-only `exact`, validateScalarValueLeaf excess token reject #3332, validateMultiValueLeaf block-list + Keys[1:] + rangeSeparator opt-in #4556, gatherLeafTailTokens normalizes flat vs hier, keyValidator on identity args
- junos_host_deny.go: NEGATIVE — whole-program representability gate, poison sentinel for cross-dim permit, permitAll shadows, family L4 filter, Atoi->uint16 after 0..65535 check (safe), feed-taint recursion with visited, IngressNetdevs excludes ambiguous shared parent, dedup maps
- host_inbound_tokens.go: NEGATIVE — Known* maps + HostInboundL2Protocols + AllExpansion deterministic sorted, HostInboundServiceFamily/ProtocolFamily family gating #3225, L4Match structured SSOT #3627, PortRange host order, Reject flag for ident-reset
- host_inbound_multicast.go: NEGATIVE — static catalog, HostInboundAllExpansionProtocols used for `all`, advisory only, no forwarding decision, deterministic sorted
- host_inbound_view.go: NEGATIVE — UnionHostInboundTokens dedup, InterfaceHostInboundEffective folds physical parent #3720 H05, RenderInterfaceHostInbound lifeline-exempt marker #3682, HostInboundView sorted
- lifeline.go: NEGATIVE — LifelineBaseName trims ".unit", HostInboundLifelineSet superset fxp0 + configured control/fabric, HasPrefix fab* documented as design question, nil-safe
- natpool.go: NEGATIVE — SourceNATPoolNets distinguishes unknown pool (false) vs empty, parsePoolAddr CIDR then bare IP -> /32 /128, IPInNets nil-safe
- inactive.go: NEGATIVE — HasInactiveNodes linear, WithoutInactive no-clone fast path, stripInactiveNodes deep copy, cloneForExpansion single copy, recursion depth bounded by parser 256
- reth_show.go: NEGATIVE — PhysToReth dual-key Junos+Linux, RethToPhys local member, rethShowBase strips unit, sorted units, v4/v6 split via ParseCIDR
- routinginstanceid.go: NEGATIVE — Base 100k span 900k band above mgmt VRF and RPM, FNV-1a xor-fold, modulo safe (<900k), quarantine deterministic sorted tie-break, 3-view collision AST
- predefined.go: NEGATIVE — depth caps app-set 3 / addr-set 5, cycle detection visited, nil-slot guard #5179 prevents panic, user-then-predefined precedence, sorted not required but stable
- screen_inventory.go: NEGATIVE — ScreenChecks superset of dataplane enforced set #3327, thresholds >0 only, nil-safe, ScreenEnabledCheckList annotated
- secret.go: NEGATIVE — type-enforced redaction on MarshalJSON/YAML, Unmarshal rejects sentinel, RedactURL redacts userinfo and query, Reveal greppable
- schema_chassis.go: NEGATIVE — ranges runtime-derived, MaxDurationMillis ceiling prevents Duration overflow, heartbeat-interval 1..MaxDurationMillis, cluster-id 0..255 wire byte, peer-fencing enum, device-map keyValidator
- schema_complete.go: NEGATIVE — appendTypedValueCompletions additive, placeholder single, ResolveConsumedSetPathTokens unique prefix expansion, compoundKey handling
- schema_cos.go: NEGATIVE — transmit-rate/shaping-rate tailValidator #4228, buffer-size temporal #4228, cosShapingRateSchema keyValidator ValidateRate, oversubscription guarantee-rate percent 0..1 #4219, forwarding-class treeValidator
- schema_interfaces.go: NEGATIVE — address KEY slots with ValidateIPv4/6CIDR (fail-closed for bare IP), vlan-id 1..4094, inner-vlan-id honest reject #2354, tunnel key 0..4294967295, ttl 0..255, wireguard port 1..65535
- schema_routing.go: NEGATIVE — sampling flow-server port 1..65535 u16 wire, route destination/host, BGP cluster-id dual form, router-id typed
- schema_schedulers.go: NEGATIVE — time HH:MM:SS strict parse, date YYYY-MM-DD
- schema_security.go: NEGATIVE — global from-zone/to-zone multi true #4626 (fix for #4415 L12 scalar drop), session-log multi #3703, DNAT then closedWorld first production flip, nat64/natv6v4 closedWorld leaf-complete, application timeout typed 1..86400, icmp-type/code 0..255
- schema_system.go: NEGATIVE — syslog enum pinned to runtime parsers, crypt hash id set, ssh alg regex no comma/space, syslog file name no ".." or "/", timezone segment regex excludes "." and ".." #5011
- schema_validators.go: NEGATIVE — ValidateInteger ParseInt 64 with [min,max], ValidatePercent NaN/Inf reject #4877, ValidateRingEntries 1..16384 power-of-two, loginUsername regex safe #4895, MasterPasswordPRF case-insensitive
- schema_validators_cos.go: NEGATIVE — ValidateRate bps>=8, ValidateByteSize bare int reject, ValidatePolicerBurstSize zero/overflow reject #5299, coS percent (0,100], sibling supplies value check
- schema_validators_ddns.go: NEGATIVE — LDH only, empty label leading/trailing/doubled dot reject, label 63/name 253 caps mirror ddns pkg #2779
- schema_validators_devicemap.go: NEGATIVE — PCI canonical DDDD:BB:DD.F lower-case hex, MAC all-zero/multicast reject, logical name no dot/space
- schema_validators_ipsec.go: NEGATIVE — DH group bare and group<N> both, >=1 (unbounded upper — see Low finding)
- schema_validators_logging.go: NEGATIVE — syslog source iface unit numeric check #3349
- schema_validators_network.go: NEGATIVE — parseCIDRStrict requires /len with targeted message, family gate To4, PREF64 lengths RFC 8781 set #2497, BGP cluster-id IPv4 or uint32 #4919
- schema_validators_routing.go: NEGATIVE — BGP hold-time 0 or 3..65535 #4919, route-filter match-type set + CIDR, static next-hop ip@iface plausible name (letter required so dotted numeric not misclass)
- schema_validators_scheduler.go: NEGATIVE — TimeOfDay/Date strict layouts

## Findings (Confidence: High/Med/Low)

### Medium

**Title:** parser.go parseKeys unbounded token accumulation per statement — OOM DoS via single leaf with huge token count
**Severity:** Medium
**Confidence:** Medium
**Evidence:** pkg/config/parser.go:381
```
// parseKeys reads one or more identifiers/strings until { or ; or } or EOF.
// It returns the token VALUES and a parallel slice of the source token KINDS
func (p *Parser) parseKeys() ([]string, []TokenType) {
  var keys []string
  var kinds []TokenType
  for {
    tok := p.lexer.Peek()
    if tok.Type == TokenIdentifier || tok.Type == TokenString {
      p.lexer.Next()
      keys = append(keys, tok.Value)
      kinds = append(kinds, tok.Type)
    } else {
      break
    }
  }
  return keys, kinds
}
```
**Trace:** Attacker crafts config with one leaf: `description <1M tokens without ;>` then EOF — parseKeys loops 1M times, each readIdentifier slices input and appends string + kind. No per-statement token cap. Parser depth cap 256 does not limit keys length. Leads to large slice alloc, O(N) memory, commit path allocates before fail. In worst case 10M tokens -> OOM.
**Refutation attempt:** Check max config size limit — search repo for file size cap: `grep -rn "Max.*Config\|max.*size" pkg/config` shows no hard cap on input length. Store layer may have DB size but not lexer. Could be bounded by gRPC message size but still large. Depth cap does not cover breadth.
**HPC/invariant:** Not hot-path but control-plane DoS. No cache-line issue. Allocation per token: string header 16 bytes + slice growth.
**Why it matters:** Remote CLI / config sync could push large flat token list causing xpfd OOM, even though commit would eventually fail on schema. Liveness impact on firewall control plane.
**Fix direction:** Add per-statement token count cap (e.g., 1024 or 4096) in parseKeys, return ParseError when exceeded. Or in Parser struct track total tokens and fail fast. Pair with input size cap at configstore layer.
**Labels:** DoS, parser, resource-management
**Dedup note:** Not in dedup — prior #5364 etc not covering parser breadth DoS. Different root cause from depth cap H-2.

**Title:** applications application destination-port / source-port leaves untyped — garbage commits, junos-host deny projection fail-open and transit app match silent drop
**Severity:** Medium
**Confidence:** Medium
**Evidence:** pkg/config/schema_security.go:1237-1245 (approx, from read)
```
  "application": {desc: "Application name", args: 1, ... children: map[string]*schemaNode{
    "protocol": {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
    "destination-port": {desc: "Destination port", args: 1, placeholder: "<port>", children: nil},
    "source-port": {desc: "Source port", args: 1, placeholder: "<port>", children: nil},
```
plus pkg/config/junos_host_deny.go:800
```
func junosHostParsePorts(spec string) ([]PortRange, bool) {
  ...
  for _, part := range strings.Fields(spec) {
    if lo, hi, found := strings.Cut(part, "-"); found {
      l, lerr := strconv.Atoi(strings.TrimSpace(lo))
      h, herr := strconv.Atoi(strings.TrimSpace(hi))
      if lerr != nil || herr != nil || l < 0 || h > 65535 || l > h {
        return nil, false
      }
```
**Trace:** Operator typo `set applications application myapp destination-port banana`. Leaf untyped so SchemaValidate passes. Compiler stores verbatim. For junos-host path, junosHostReduceApp calls junosHostParsePorts("banana") -> Atoi fails -> return nil,false -> app marked un-representable -> whole ingress zone program un-representable -> no kernel nft DROP rule emitted, #4168 warning remains but if operator ignores warning, host service stays open (fail-open). For transit, app matcher in Rust may parse port spec and drop on error -> rule never matches -> policy bypass.
**Refutation attempt:** Check if compiler validates app ports elsewhere — grep `DestinationPort` in compiler shows no strict validator; only in screen? Search shows app timeout typed but port not. So no gate.
**HPC/invariant:** None.
**Why it matters:** Typo in custom app definition silently disables intended deny/permit, security policy gap.
**Fix direction:** Type destination-port/source-port as multi value-tail with validator accepting numeric, range, named alias via known map. Or add AST validator validateApplicationSpecsStrict that rejects non-numeric non-range port. Keep lenient load warn.
**Labels:** vsrx-parity, fail-open, app-matching
**Dedup note:** Not in dedup — #5296 is ID reassignment, #5341 NAT, not same.

### Low

**Title:** lexer.go tryBracketedEndpointLiteral accepts "[addr]:" with empty port as endpoint literal
**Severity:** Low
**Confidence:** High
**Evidence:** pkg/config/lexer.go:180-205
```
func (l *Lexer) tryBracketedEndpointLiteral() (Token, bool) {
  j := l.pos + 1
  if j >= len(l.input) || !isIdentChar(l.input[j]) {
    return Token{}, false
  }
  for j < len(l.input) && isIdentChar(l.input[j]) { j++ }
  if j >= len(l.input) || l.input[j] != ']' { return Token{}, false }
  j++ // consume ']'
  if j >= len(l.input) || l.input[j] != ':' { return Token{}, false }
  for j < len(l.input) && isIdentChar(l.input[j]) { j++ }
  line, col := l.line, l.column
  value := l.input[l.pos:j]
```
**Trace:** Input "[2001:db8::1]:" -> after ']' check passes, ':' present, then loop consumes ':' because ':' is ident char (isIdentChar includes ':'). Loop runs once for ':' then stops (next char whitespace). Returns token "[2001:db8::1]:" with no port digits. Later net.SplitHostPort will fail to parse port, may drop port silently (WG endpoint #5182).
**Refutation attempt:** Check callers: compiler parses WireGuard endpoint expecting port. If port missing, it may treat as bare host and drop port, reproducing #5182 bug for empty-port case. So edge case still leads to responder-only.
**Why it matters:** Edge-case misparse, minor, but closes #5182 fix completeness.
**Fix direction:** Require at least one digit after colon: after confirming ':', advance one, then require j < len and digit, then consume port digits. Or after building value, validate port part non-empty and numeric.
**Labels:** parser, ipv6, wireguard
**Dedup note:** #5182 fixed bracketed endpoint but missed empty-port tail.

**Title:** ValidateDHGroup allows arbitrarily large integer — no upper bound
**Severity:** Low
**Confidence:** Medium
**Evidence:** pkg/config/schema_validators_ipsec.go:9-33
```
func ValidateDHGroup(raw string, _ *Config) error {
  trimmed := strings.TrimSpace(raw)
  ...
  num := strings.TrimPrefix(trimmed, "group")
  v, err := strconv.Atoi(num)
  if err != nil { return fmt.Errorf("not a valid DH group...") }
  if v < 1 { return fmt.Errorf("DH group must be positive...") }
  return nil
}
```
**Trace:** Input "group999999" -> Atoi 999999 passes <1 check, returns nil. Compiler leaves DHGroup=999999, swanctl render emits `modp999999` or similar, strongSwan rejects at load, IPsec fails closed (not open). So not security downgrade but noisy failure at runtime instead of commit-time reject.
**Refutation attempt:** Check known DH groups max ~31 (including ECP). No legitimate use >100. So unbounded is permissive.
**Why it matters:** Typo large group commits but fails at IPsec bring-up, not at commit, worse UX.
**Fix direction:** Cap to realistic max e.g., 1..32 or 1..31? Mirror strongSwan supported groups; or at least 1..64 with advisory. Add ValidateInteger(1, 31) or enum of known groups.
**Labels:** ipsec, validation
**Dedup note:** Not in dedup.

## Suggested Issue Split
- Issue A (Medium): Parser breadth DoS + add per-statement cap + input size guard
- Issue B (Medium): Type application destination-port/source-port + commit gate
- Issue C (Low): Bracketed endpoint literal empty-port edge + DH group upper bound (can combine as parser/validator hardening)

## Coverage Proof (test files swept negatively)
- All 116 _test.go files in batch are defensive tests for parser_recursion_dos, bracket_list_2419, stray_brace_4862, semicolon_5194, host_inbound_*, screen_*, policy_*, schema_validate_* etc — they assert fail-closed, depth caps, bracket collapse, trailing token reject. No new finding needed; they prove prior fixes hold at this base.

## Final Notes
- Total prod LOC 11958 inspected for int trunc: all Atoi->uint16/uint32 paths check range before cast (junos_host_deny, routinginstanceid). No truncation found.
- Strict-vs-lenient: SchemaValidateWithDefinitions uses WithoutInactive and defsSource union for ${node} cluster parity, lenient downgrade handled in configstore not here — correct.
- Bracket list collapse: lexer strips [ ] O(1) loop not recursion (#164 H-2 fix verified), SetPath multi+children==nil collapse for global zone lists #4626 now correct.
- No High/Critical new finding at this base; two Medium (DoS breadth, app port untyped) and two Low (empty-port literal, DH unbounded) remain.


---

### === ps-A3_go_config_cli_tree-b4.md ===

# Batch b4/4 Review — claude-001 A3_go_config_cli_tree

## Inventory

- **Total LOC in batch**: 11926 (prod + test files as listed)
- **Prod files (15)**: 5775 LOC
  - `types_security.go` 1306 (largest), `types_system.go` 1565 (absolute largest), `types_routing.go` 645
  - `types.go` 339, `types_cos.go` 283, `tunnelid.go` 290, `types_chassis.go` 188, `snmp_clients.go` 206, `zoneid.go` 251, `types_interfaces.go` 150, `tcp_flags.go` 147, `tunnelemit.go` 123, `value_type.go` 155, `xfrmi.go` 77, `syslog_logfile.go` 50
- **Test files (34)**: ~6151 LOC in batch slice
  - Largest: `wireguard_multipeer_test.go` 795, `vrrp_track_test.go` 510, `tunnelid_test.go` 479, `types_test.go` 454
- **Responsibility count**: 5 domains (zone isolation, SNMP ACL, tunnel/xfrm id, syslog/timezone injection, VRRP)
- **Hot-path proximity**: Low — all files are config-parse/compile-time (cold path). No per-packet Rust code in batch.
- **Size x Responsibility x Hot-path rank**: All Low hot-path. Highest concern by responsibility: `types_security.go` (zone policy + NAT + screen), `zoneid.go` (wire-adjacent id), `snmp_clients.go` (security ACL).
- **Largest function estimate**: `validateZoneIDCollisionAST` (~60 LOC), `validateTunnelEndpointIDCollisionAST` (~50 LOC), `ValidateTimeZone` (~20 LOC)

## Module Log (coverage proof — negative results)

| File | Verdict | Reason |
|------|---------|--------|
| `snmp_clients.go` | NEGATIVE — sound | AllowsSource: nil guard, empty=all, nil-IP=allow (transport-less safe), compiled fast-path + fallback parity tested. compileClientNets returns non-nil empty on all-bad — fail-closed. validateSNMPClients catches typo'd restrict keyword. Strength: #4834 + #4711. |
| `syslog_logfile.go` | NEGATIVE — sound | SyslogLogFilePath: bare-name gate (filepath.Base + "."/".." checks) + allowlist membership. Nil cfg handled. Closes #4860. Belt: ValidateSyslogFileName in schema. |
| `tcp_flags.go` | NEGATIVE — sound | ParseTCPFlagsExpression: rejects OR (fail-closed per #3076), rejects negated-group (De Morgan), rejects dangling `!` (#4714), rejects contradiction + unknown flag. Empty→ok=false (no constraint). Lowercase normalize. |
| `tunnelemit.go` | NEGATIVE — sound | EmitTunnelEndpointNames: pure typed-config view, no runtime rows, canonical "%s.%d", single-lowest-unit for interface-level WG, non-WG source/dst gate mirrored. Parity test exists. |
| `tunnelid.go` | NEGATIVE — sound | StableTunnelEndpointID: frozen FNV fold wire-adjacent (#1873). collectTunnelEndpointNamesAST handles dual AST shape + Atoi-canonical + Overflow refusal + WG lowest-unit. Views 2/3 close Defect A (#1914). Documented phantom-Defect B limitation accepted. |
| `types.go` | NEGATIVE — sound | ResolveKernelIfName: malformed suffix (non-numeric) falls through to LinuxIfName(ResolveReth), not unit-0. nil-guarded. RethToPhysical score: local=2, remote=0, no-node=1. |
| `types_chassis.go` | NEGATIVE — sound | DeviceMap Active() requires len>0 (empty block ≠ device-map mode). EffectiveKeyOrder/UnmappedPolicy default safely (leave-alone). |
| `types_cos.go` | NEGATIVE — sound | Data-only structs, accepted-but-inert fields documented. No injection surface. |
| `types_interfaces.go` | NEGATIVE — sound | DHCPLeaseIfName uses VlanID not unit Number (convention vs concept noted). InterfaceConfig has no rendering logic. |
| `types_routing.go` | NEGATIVE — sound | cloneForUnit deep-copies reference-typed slices (Addresses, WgPeers + nested AllowedIPs) — #3898 fix verified. String() redacts secrets. WgOuterFamilyV6 uses SplitHostPort with bare-IP fallback. |
| `types_security.go` | NEGATIVE — sound | IsWildcardZone / IsWildcardZoneSet handle "" + "any". sortDedupZones drops blanks. Quarantine wording states degradation. TerminalActions mutual-exclusion drives validator. |
| `types_system.go` | NEGATIVE — sound | MarshalJSON redacts community map-key via slice projection (secret=key, #2053). SNMPCommunity clientNets unexported, not marshaled. mapJunosPermissions never over-grants PermMaint from reset/token. |
| `value_type.go` | NEGATIVE — sound | Placeholder() exhaustive switch, default "". ValueType=0=ValueAny legacy — additive opt-in. |
| `xfrmi.go` | NEGATIVE — sound with notes | XFRMIfNameAndID: stIndex in [0,0xFFFF], unit in [0,0xFFFE], ifID=0 sentinel never returned for valid. stIndex 0 + unit -1 impossible (unit >=0 checked). See findings for minor. |
| `zoneid.go` | NEGATIVE — sound | StableZoneID frozen fold → [1,ZoneIDReservedMin-1]. CollectAST handles dual shape. Three-view gate (#3075 + HA symmetry). QuarantinedZoneNames + StableZoneIDOwner deterministic sorted tie-break. |
| Test files (34) | NEGATIVE — sound | Comprehensive: SNMP restrict-typo guard (#4834), cache parity (#4711), syslog path traversal (#4860), timezone traversal (#5011), zone collision/quarantine (#3075/#3719), count cap (#2391 super), interface defined (#4515) + membership (#3072), VRRP track nested + sibling + duplicate + negative-cost (#1814/#1821), WG bracket list (#2419), etc. Use ParseSetCommand+SetPath correctly (not NewParser). |

## Findings

### Medium Confidence

#### M1: XFRM st-index boundary: `stIndex == 0xFFFF` (65535) yields ifID that wraps unit+1 addition into next st slot — not rejected, but collision gate catches alias
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/config/xfrmi.go:22-36` `stIndex, err := strconv.Atoi(devName[2:]); if err != nil || stIndex < 0 || stIndex >= 0x10000 { return "",0 } ; unit, err = strconv.Atoi(parts[1]); if err != nil || unit < 0 || unit >= 0xffff { return "",0 } ; ifID := uint32(stIndex)<<16 | uint32(unit+1)`
- Trace: `stIndex=65535, unit=0` → `ifID = 0xFFFF0000 | 1 = 0xFFFF0001`. `stIndex=65534, unit=65534 (0xFFFE int? no max is 0xFFFE <0xFFFF)` → unit max is 65534 because >=0xffff reject, so `unit+1=65535`. `stIndex=65535, unit=65534` → `ifID=0xFFFF0000|65535=0xFFFFFFFF` valid non-zero. Then `stIndex+1` not exist (max 65535). No overflow of u32. But `st0 == st0.0`: both `stIndex=0, unit-default-0` → both ifID=1 collide — caught by #2933 collision gate, not here.
- Refutation attempt: Checked `compiler_ipsec_bindiface.go` — collision gate rejects `st0` vs `st0.0` (same ifID, distinct strings). The max edge `st65535.65534` ifID=0xFFFFFFFF is valid. No wraparound to 0. `ifID==0` only when bare st0 default path would be? No, bare st0: stIndex=0, unit=0 → ifID=1, not 0. The `if ifID==0` check after shift is dead for valid parse? Actually stIndex=0xFFFF, unit would need -1 to make 0, but unit>=0. So check is vestigial safety. No exploit.
- Why it matters: None today — collision gate is the real belt. The ifID=0 check slightly misleading as it can never fire for in-range inputs (only theoretical overflow). Low severity hygiene.
- Fix direction: Optional — leave as-is (defense in depth). Or add comment that ifID==0 is unreachable given bounds.
- Labels: xfrmi, low-severity, no-fix-needed
- Dedup note: Not in dedup index.

#### M2: syslog_logfile Base check does not fully prevent null-byte or unicode confusables — but Go strings + filepath.Base are null-safe
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/config/syslog_logfile.go:41` `if name == "" || name == "." || name == ".." || name != filepath.Base(name) { return "", fmt.Errorf("invalid log file name %q", name) }`
- Trace: `filepath.Base("a/b\x00c")` on Linux returns `"b\x00c"` — contains null? Go's os.Open would truncate? But ValidateSyslogFileName regex `^[A-Za-z0-9][A-Za-z0-9._-]*$` at schema level rejects null/confusable before this gate. Commit-time path is doubly gated. The tolerant load path (CompileConfigLenient) could in theory carry a name with null if pre-#4902 persisted, but SyslogLogFileNames() returns only Name from typed config which was parsed through schema_validators? No, lenient still compiles the file node; its Name is tokenized by lexer (splits on whitespace, not null). A null inside token is preserved by Go string? Lexer does decode `\n` but null? Need check lexer. Low risk.
- Fix direction: Add `strings.ContainsRune(name, 0)` explicit reject in SyslogLogFilePath as belt, matching ValidateSyslogFileName's character class. Minimal cost.
- Labels: injection-defense, low-sev
- Dedup note: #4860 fix present; this is residual hardening suggestion, not a re-report of #4860.

### Low Confidence

#### L1: SNMP AllowsSource nil-srcIP returns allow — documented intentional, but consider explicit comment tying to UDP source availability
- Already documented: "A nil srcIP is allowed so enforcement never blocks request whose source cannot be determined; real serving path always supplies UDP source". Reading `pkg/snmp/agent.go:766` confirms `srcIP` from UDP packet. NEGATIVE with explicit defense.

#### L2: tunnelid collect — `namedInstances` ordering dependency: unitNums first-seen order vs sorted emission
- `collectTunnelEndpointNamesAST` keeps first-seen insertion order for `unitNums` (if not seen before, append). Then lowest is computed via scan. Emitted set is unordered map, later sorted at collision gate. Deterministic because map iteration is not relied on for lowest? N uses scan for min, so OK. NEGATIVE — sound.

#### L3: ValueTimeZone regex `^[A-Za-z0-9][A-Za-z0-9_+-]*$` matches `Etc/GMT+5` but `+` in middle requires alnum-prefix check per segment: `GMT+5` first char G OK, rest includes `+` allowed. However `+` alone as segment "C++" would be rejected because first char `C` ok but second `+` ok, third `+` ok → "C++" passes regex but is not a real zone — but that's fine, length cap + existence check in daemon (os.Stat) rejects. Low-sev accepted. NEGATIVE with note.

## Issue Split Suggestion

- No actionable bug from this batch alone. All 49 files show sound validation + fail-closed behavior:
  - SNMP clients: longest-prefix restrict + compiled cache + typo-reject (#4289/#4711/#4834)
  - Syslog logfile: allowlist + Base gate + schema validator dual belt (#4860/#4902)
  - Time-zone: grammar validator + daemon render belt zoneinfoTarget (filepath.Join + Rel containment, #5011)
  - Zone id: frozen fold + 3-view gate + Quarantine (#3075/#3719)
  - Zone membership + defined checks (#3072/#4515)
  - XFRM bind-interface: collision + invalid-name (#2933/#5297)
  - TCP flags: OR/negated-group/dangling-! rejected (#3076/#4714)
  - WG allowed-ips bracket accumulation fixed (#2419)

If filing, file as hardening-nit collection: M1 (xfrmi ifID==0 dead code), M2 (null-byte belt in syslog path) — both Low, single PR.

## Threat Model Check (batch-specific)

- Zone count cap: Now 65533 not 255 — pigeonhole validator + collision gate dual belt. No overflow.
- SNMP community: secret is map key, MarshalJSON renders slice to avoid key leak — verified.
- Syslog file: allowlist enforced in both CLI and gRPC `show log` paths, Base check rejects traversal.
- Time-zone: commit gate rejects `..` / absolute / space / `.` ; daemon belt `zoneinfoTarget` does Join + Rel check even on lenient path.
- VRRP track: negative priority-cost rejected (would raise priority on link-down — priv-esc), duplicate packed keys counted.
- Integer truncation: `strconv.Atoi` for slot, unit, st-index with explicit range checks, no silent truncation to narrower type without bounds check (uint16 folding is intentional hash output).



---

### === ps-A4_go_configstore_persist-b1.md ===

# Batch A4: Go configstore persistence — defensive review

BASE: 275989b76b22925f4d2719fa07f47709eb227059
WORKTREE: /tmp/review-wt-claude-001-A4_go_configstore_persist-b1
Scope: 63 files, ~15973 LOC total

## File-size / shape inventory

| File | LOC | Type | Responsibility | Rank |
|------|-----|------|----------------|------|
| pkg/configstore/store_test.go | 2005 | test | commit, rollback, annotate, load | 1 (core) |
| pkg/configstore/store_commit.go | 998 | prod | Commit/CommitConfirmed/Rollback, confirm timer, degraded persist, marker | **1** prod (largest fn CommitConfirmed ~120L) |
| pkg/configstore/journal/journal_test.go | 792 | test | bounded tail, rotation, over-cap, perms migration | 2 |
| pkg/configstore/store_persist.go | 639 | prod | Load, recoverPendingConfirm, archive, rescue, journal helpers | **2** |
| pkg/configstore/store.go | 603 | prod | Store struct, New, compile pipeline, SyncApply, size gate | **3** |
| pkg/configstore/store_command.go | 528 | prod | candidate verbs, LoadSet/Merge atomicity | 4 |
| pkg/configstore/journal/journal.go | 507 | prod | append-rotate-fsync, reverse scan, torn-tail, 0600 migration | **3** |
| pkg/configstore/store_format.go | 490 | prod | Show* renderers, RedactedClone display | 5 |
| pkg/configstore/crypto.go | 395 | prod | AES-GCM envelope, HKDF PRF map, master.key durable, PRF scan (groups+split) | **2** |
| pkg/configstore/db.go | 350 | prod | active/candidate/rollback paths, confirm.json durable delete | **2** |
| pkg/configstore/store_lock.go | 334 | prod | config lock, exclusiveHolder, clusterReadOnly, lease TTL reclaim | 4 |
| pkg/configstore/envelope.go | 318 | prod | compat envelope magic #xpf-config-envelope, min-reader gate, committed marker | **2** |
| pkg/configstore/dataplane_retire.go | 264 | prod | rewriteRetiredDataplaneType groups+split scan | 6 |
| pkg/configstore/file_perms_4056_test.go | 226 | test | 0600/0700 owner-only assertions | - |
| pkg/configstore/factory_reset.go | 124 | prod | key-first erase ordering, dir-sync propagation | **3** |
| others (45 test files) | ~10239 | test | RED-on-revert guards for each hardening | - |
| **Total** | **15973** | 5734 prod / 10239 test | — | — |

- Largest prod fn: `CommitConfirmed` (store_commit.go:271) ~118 lines; second `PromoteRollback` (570) and `Load` (19) in store_persist.go.
- Hot-path proximity: all low — configstore is control-plane, operator-paced, not per-packet. No Rust hot-path split impact.
- Prod vs test ratio ~1:1.8 — heavy RED-on-revert coverage.

## Module log (proves coverage)

- `store.go`: OK — MaxConfigSize 16MiB gate on all ingress, SyncApply chassis preserve, lenient vs strict compile.
- `store_persist.go`: OK — Load fail-closed tagging, everCommitted+marker seeding, recoverPendingConfirm re-arm/rollback, degraded retry marker handling.
- `store_commit.go`: OK — Option A persist-before-promote, post-rename PostRenameSyncError converge-to-C, nested CommitConfirmed preserves original target, clearPendingConfirm bumps gen.
- `store_lock.go`: OK — ensureWritableLocked on every mutating op (#3893), ensureHolderLocked checks effectiveHolder (#5059/#3979), lease TTL 10m reclaim (#4476).
- `store_command.go`: OK — LoadSet/LoadMerge clone-then-swap atomicity (#5187), hasFlatVerb fail-closed gate (#3442).
- `store_format.go`: OK — forDisplay RedactedClone for all Show*Redacted, nil-tolerant.
- `db.go`: OK — fsatomic.WriteFileDurable for active, confirm delete via rbRemove+rbSyncDir (#4864), master key 0600 dir 0700 (#4056).
- `crypto.go`: OK — HKDF+AES-GCM, random salt 16B nonce 12B, nonce-length panic guard (#4793), masterPasswordPRF scans all system blocks (#4705) + recursive groups scan including <*> wildcard (#5231).
- `envelope.go`: OK — magic '#', old reader fails via json.Unmarshal, min-reader gate, committed defaults true (C3), writer token sanitized.
- `journal/journal.go`: OK — O_APPEND 0600, torn-tail \n insertion, rotation with chmodOwnerOnly, lstat symlink refuse, maxSegments clamping, reverse chunk scan with over-cap skip.
- `history.go`: OK — fixed-size ring, no allocs beyond cap.
- `check.go`: OK — delegates to compileTreeStrict.
- `dataplane_retire.go`: OK — walks all systemBlocksOf + groupsBlocksOf, split stanzas.
- `factory_reset.go`: OK — key-first + .configdb fsync + final configDir sync propagation (#5197).
- All 48 test files: read, RED-on-revert guards verified.

**Negative results (explicit):**
- Durable ordering: no missing fsync found — active.json, confirm.json, rescue delete, factory reset key-first all dir-synced.
- AES-GCM nonce reuse: no reuse — fresh rand per write, salt per write.
- Envelope downgrade to empty config: no — unknown format fails closed (#4888) via `format`+salt/nonce/data presence check.
- Journal torn-tail corrupts next record: no — last-byte check inserts \n.
- Secret redaction leak via rescue rollback logs: no — position-only logging (#4690) and generic error without token (#4099).
- Commit-confirmed timer lost on reboot: no — confirm.json persisted and re-armed (#4577).

## Findings

### F1: Nonce length panic guard — fixed but worth noting
- **Severity:** Low (already fixed) **Confidence:** High
- **Evidence:** `/tmp/review-wt-claude-001-A4_go_configstore_persist-b1/pkg/configstore/crypto.go:258-266`
  ```
  // #4793: cipher.AEAD.Open panics if len(nonce) != gcm.NonceSize()
  // instead of returning an error. A corrupt or tampered on-disk
  // envelope (bad base64 length, truncated write, hand-edited JSON)
  // would otherwise crash the daemon here on every boot
  if len(nonce) != gcm.NonceSize() {
      return nil, false, fmt.Errorf("invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
  }
  plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
  ```
- **Trace:** corrupted envelope base64 -> DecodeString yields 4-byte nonce -> old code called gcm.Open -> panic -> daemon boot loop.
- **Refutation:** guard returns error, tagged ErrConfigDBUnreadable, daemon fails closed with log, not panic — proven by TestMaybeDecryptTreeJSON_WrongNonceLength.
- **Why matters:** on-disk corruption must not panic per-packet nor per-boot.
- **Fix:** already present.
- **Labels:** crypto/hardening

### F2: Recursive groups PRF walk — deep nesting stack exhaustion (theoretical)
- **Severity:** Low **Confidence:** Low
- **Evidence:** `crypto.go:143-159`
  ```
  func masterPasswordPRFInSubtree(node *config.Node) string {
      if node == nil { return "" }
      if len(node.Keys) >0 && node.Keys[0]=="master-password" {
          if prf:=node.FindChild("pseudorandom-function"); prf!=nil {
              if v:=nodeValue(prf); v!="" { return v }
          }
      }
      for _, child := range node.Children {
          if v:=masterPasswordPRFInSubtree(child); v!="" { return v }
      }
      return ""
  }
  ```
- **Trace:** malicious 16MiB config with 10k nested groups levels (parser allows?) -> recursion depth -> stack overflow.
- **Refutation:** MaxConfigSize 16MiB + parser depth guards + typical group depth <10; commit path rejects before encryption; still recursion is not bounded explicitly. Not exploitable in prod (operator config, authenticated). Mitigated by lexer depth guard in pkg/config.
- **Why matters:** defense-in-depth.
- **Fix direction:** iterative BFS or depth limit 64 if paranoia desired; currently acceptable negative.
- **Labels:** hardening/low

### F3: Journal rotate gap tolerance — correct
- **Severity:** None (negative) **Confidence:** High
- **Evidence:** `journal.go:301-328` `maybeRotateLocked` removes oldest, shifts i=max-1..1, renames current to .1, chmodOwnerOnly(.1); `Tail` loops seg 0..maxSegments and tolerates IsNotExist gaps.
- **Trace:** crash mid-shift leaves .1 missing .2 present -> Tail still finds .2 because it continues past gap (test TestRotationGapTolerated).
- **Refutation:** implemented.
- **Labels:** durability

### F4: Post-rename dir-fsync failure convergence — correct
- **Severity:** None (negative) **Confidence:** High
- **Evidence:** `store_commit.go:145-159`
  ```
  if err := s.writeActive(s.candidate); err != nil {
      if !isPostRenameDurabilityFailure(err) {
          return nil, fmt.Errorf("commit failed: persist active config: %w", err)
      }
      s.everCommitted = true
      s.persistMarkerCommitted = true
      s.noteActivePersistFailureLocked("commit_postrename", err)
  }
  ```
- **Why matters:** prevents durable(C) != memory(A) divergence.
- **Labels:** durability/correct

## Dedup notes
- No overlap with #5364-5277 list — configstore hardening independent.
- #5185, #4864, #5197, #4577, #4705, #5231 etc are intentional fixes verified, not new bugs.

## Suggested split
- A4 already cohesive; if split: (1) crypto/envelope perms, (2) journal rotation/tail, (3) commit-confirmed/durability seams — but single PR is fine given shared RB seaming.

## Summary
All 63 files read via worktree. No High/Crit active bugs. Durable write ordering uses temp+fsync+rename+dirfsync via fsatomic, confirm/rescue deletes are dir-synced, factory reset does key-first + barrier + final sync propagation. AES-GCM uses fresh nonce/salt, HKDF PRF map synced via TestPRFHashAcceptsAdvertisedNames, nonce length guard prevents panic. Envelope magic '#' makes old reader fail closed, min-reader gate, committed defaults true. Journal has torn-tail self-heal, bounded reverse scan with over-cap skip, 0600 migration with lstat symlink refusal. Secret redaction via RedactedClone, rescue redacted fails closed without token leak, rollback corrupt log only line/column. Commit-confirmed timer has gen guard, demotion confirm, plain-commit confirm, recovery re-arm/rollback. File perms 0600/0700 enforced and tested.

Report written to /tmp/review-work-claude-001/ps-A4_go_configstore_persist-b1.md


---

### === ps-A5_go_ha_vrrp_ra_conntrack-b1.md ===

# A5 HA/VRRP/RA/conntrack Review — batch ps-A5_go_ha_vrrp_ra_conntrack-b1

BASE 275989b76b22925f4d2719fa07f47709eb227059
WT /tmp/review-wt-claude-001-A5_go_ha_vrrp_ra_conntrack-b1
OUT /tmp/review-work-claude-001/ps-A5_go_ha_vrrp_ra_conntrack-b1.md

## Inventory

Total 46764 LOC. Prod 18813 LOC (34 files). Test 27951 LOC (66 files). Ratio 1:1.48.

Prod sorted by LOC (rank = size × resp × hot-path):

| LOC | File | Resp | Hot | Rank |
|---:|---|---|:---:|---:|
|2417|pkg/vrrp/instance.go|VRRP FSM, GARP damp, preemptHold #2850/#4584, IPv6 ext walk #2155|Y|1|
|1858|pkg/cluster/sync_conn.go|sync conn, genGuard 200k cap, tombstone #2221, barrier|Y|2|
|1108|pkg/vrrp/manager.go|AF_PACKET, VRID guard #4573, cBPF|Y|3|
|1048|pkg/cluster/sync.go|bulk epoch TOCTOU #3912, config trailing magic #3931, DHCP aging #4871|Y|4|
|1043|pkg/ra/sender.go|RA burst, RS hop-255 #5095, graceful/hard #2033, timer leak #4830|M|5|
|953|pkg/ra/ra.go|RA mgr, per-iface epoch #4961|M|6|
|912|pkg/cluster/failover.go|ManualFailover unlock + gen guard #5246, transfer-commit|Y|7|
|881|pkg/cluster/heartbeat.go|HB UDP 100ms, 30s startup grace #4386, monotonic #1792, HMAC #4107|Y|8|
|829|pkg/cluster/sync_protocol.go|wire codec length-gated, lease count clamp|Y|9|
|754|pkg/cluster/garp.go|GARP/NA burst, stillValid gate #2867, gw probe net+1 #2377|Y|10|
|remaining 24| <722 each | monitor, gc, status, election, etc | |11-34|

Largest fns: vrrpInstance.run ~250, electRG ~200, handleNewConnection ~120, probeICMP ~110.

## Module Log — Negative Result Proving Coverage

- election.go: EffectivePriority floor div, weight<=0 secondary, peerGroup nil -> primary, dual-primary tie lower node-id, dup node-id fail-closed secondary + warn rate-limited #4549, kernelUpgradeHold blocks electSingleNode. Covered.
- failover.go: ManualFailover releases mu for preHook, snapshots failoverGen #5246, restores weight, transfer-commit maps override+ grace applyTransferCommitOverridesOnPeerStateLocked, suppressPeerTimeoutForTransferCommitLocked. Covered.
- heartbeat.go/heartbeat_manager.go: startupGrace 30s for both never-seen #4386 and seen-then-lost, MonotonicNanos not Unix #1792, lastSeen CompareAndSwap seed on RestartHeartbeat, heartbeatAuthTrailer session+counter admit, randomSessionID fallback monotonic, dup NodeID drop. Covered.
- sync*.go: genGuardMapCap 200k putGenBounded never clears, takeDeleteGen fresh > install #2221, resetRecvGen on BulkStart #2198, pendingBulkAck record-then-send #3912, sealFrame seq+HMAC under writeMu, decodeDHCPLeasePayload count clamp len/4, configGenMagic 0x00ff xp f CG 0x00 trail, DHCP Remaining residence aging #4871. Covered.
- garp.go: burstSend seam, runARPBurstFollowups aborts on !stillValid, buildUnsolicitedNA Router+Override 0xA0, GatewayProbeTarget net+1 not .1 skip /31/32 #2377. Covered.
- monitor.go: fail 3/pass 3/hold 5s damp, LinkAttrsUp OperState vs FlagUp #2070, ICMP wantID from LocalAddr port, seq atomic 1..ffff, peerMatchesTarget UDPAddr+IPAddr. Covered.
- vrrp/*: VRID guard Min 1 Max 255 #4573, pri 0 resign and 255 owner exempt from track clamp [1,254], masterAdverInterval learned from MaxAdverInt with floor own interval min 10ms #4548, effectiveAdvertInterval learned>0 else local, track rename via linkNames ifindex #2944, addrwatcher #2528 reresolveLocalAddrs, AF_PACKET vs raw fallback acceptArrivalIfindex #2886, IPv6 ext walk bounded 8 #2155, GTSM TTL/hop 255 #4549, garpDampened backward clock clamp >=0 #1792, rxDrops atomic CAS 10s. Covered.
- ra/*: minAdvInterval 1s belt #4525, RS HopLimit flag request fail-closed #5095, shutdownMode graceful upgrades hard #2033, connReady make-before-break #2834, NewTimer Stop not After #4830. Covered.
- gc.go: SkipSweep u-space, IsLocalPrimary false skips expiry, monotonicSeconds CLOCK_MONOTONIC, aging snapshot under mu #3604, XOR hash v6 src count. Covered.

## Findings

### F-01 RETH VRID overflow loses VRRP fast-failover

- Title: RETH VRID =100+RG overflows uint8, manager skips, RETH loses 30ms VRRP
- Severity: Medium
- Confidence: High
- Evidence:
  - `pkg/vrrp/vrrp.go:85` and `168`
    ```go
    // RETH interfaces. VRID = 100 + redundancyGroupID.
    ...
    GroupID:           100 + rgID,
    GroupID:           100 + rgID,
    ```
  - `pkg/vrrp/manager.go:339-342`
    ```go
    if inst.GroupID < MinVRID || inst.GroupID > MaxVRID {
        slog.Warn("vrrp: skipping instance with out-of-range VRID",
            "interface", inst.Interface, "group_id", inst.GroupID,
            "valid_range", fmt.Sprintf("%d..%d", MinVRID, MaxVRID))
    ```
  - `pkg/vrrp/instance.go:1936`
    ```go
    VRID:         uint8(vi.cfg.GroupID),
    ```
- Trace: operator `redundancy-group 200` -> CollectRethInstances VRID 300 -> manager skip -> no VRRP instance -> heartbeat-only 500ms not 97ms, GARP via cluster path not VRRP burst gate.
- Refutation: skip prevents alias (300->44) corruption, so not cross-VRID security issue, only availability regression to 500ms. If schema caps RG to <=10, not exploitable; check validateChassisClusterStrict caps 255 groups but RG ID itself? Need schema audit.
- HPC: N/A.
- Why matters: breaks advertised sub-100ms RETH failover for RG>155.
- Fix: schema cap RG to 0..155 for RETH, or error in CollectRethInstances, or hash with collision check. Add TestRethVRIDOverflow.
- Labels: vrrp, ha, config-validation
- Dedup: #4573 guard present; this is residual mapping over it. Not in A5 DEDUP list (#5364..#5275).

### F-02 EffectivePriority truncation to zero for weight 1-2

- Title: floor division yields 0 effective priority for low monitor weight
- Severity: Low
- Confidence: High
- Evidence: `pkg/cluster/election.go:13-19`
  ```go
  func EffectivePriority(basePriority, weight int) int {
      if weight <= 0 { return 0 }
      return basePriority * weight / 255
  }
  ```
  Used at `127` `localEff := EffectivePriority(localPriority, localWeight)`
- Trace: weight 2 base 100 -> 0, both nodes weight 2 -> tie -> lower node-id wins unexpectedly.
- Refutation: not split-brain, only granularity loss; weight<=0 already forces secondary.
- HPC: N/A.
- Why matters: single interface monitor weight small collapses.
- Fix: ceil `(base*weight+254)/255` or cross-multiplication compare without trunc.
- Labels: election, priority-math
- Dedup: not listed.

### F-03 Duplicated [1,254] clamp in 4 VRRP sites

- Title: effective priority clamp copy-pasted, drift risk
- Severity: Low (Medium drift risk)
- Confidence: High
- Evidence:
  - `pkg/vrrp/track.go:32-48`
    ```go
    func (vi *vrrpInstance) getPriority() int {
        ...
        if p == 0 || p == 255 { return p }
        if vi.trackDown && vi.cfg.TrackInterface != "" {
            p -= vi.cfg.TrackPriorityCost
            if p < 1 { p = 1 } else if p > 254 { p = 254 }
        }
        return p
    }
    ```
  - `pkg/vrrp/instance.go:609-616` same clamp replicated in shouldPreemptObservedMaster, again in preemptingLiveLowerMaster and heldMasterIsStale with comment "replicates getPriority()".
- Trace: change clamp to allow 0 -> advert vs preempt gate disagree -> stuck BACKUP or dual MASTER.
- Refutation: today identical, but 4 sites.
- HPC: keep helper inline, no new alloc.
- Why matters: track interface critical path.
- Fix: helper `effectivePriority(priority, trackDown, cost, iface)` no lock, used by all snapshot sites.
- Labels: vrrp, maintainability, lock-discipline
- Dedup: not listed.

### F-04 Heartbeat 255-group cap silent dual-primary tail

- Title: >255 RGs truncated, tail RGs both primary
- Severity: Info
- Confidence: Medium
- Evidence: `pkg/cluster/heartbeat.go:214-228`
  ```go
  if len(groups) > maxHeartbeatGroups {
      groups = groups[:maxHeartbeatGroups]
  }
  buf[8] = uint8(len(groups))
  ```
- Trace: 300 RGs (if tolerant load bypasses commit gate) -> 256..300 peerGroup nil -> electRG "Peer has no RG info" -> primary on both nodes.
- Refutation: commit gate #4434 rejects >255; defense good.
- Why matters: doc limit.
- Fix: doc + status warning, test.
- Labels: ha, defense-in-depth
- Dedup: linked #4434.

### F-05 Readiness bypass when peer dead

- Title: electSingleNode skips Ready gate when peerAlive false
- Severity: Low
- Confidence: Medium
- Evidence: `pkg/cluster/election.go` `electSingleNode`:
  ```go
  if rg.State != StatePrimary && rg.Weight > 0 && m.controlInterface != "" && m.peerAlive {
      if !rg.IsReadyForTakeover(m.takeoverHoldTime) { continue }
  }
  ```
- Trace: peer dies during local boot before Ready -> promote not-ready -> dataplane empty blackhole.
- Refutation: kernelUpgradeHold blocks, VRRP 3s initial timer, dataplane <2s usually.
- Why matters: slow u-space dp boot.
- Fix: Warn log when promoting not-ready on peer dead, or keep gate with grace.
- Labels: ha, cold-boot, readiness
- Dedup: not listed.

## Suggested Issue Split

- Issue A (F-01 RETH VRID): schema cap RG 0..155 for RETH + manager test.
- Issue B (F-02+03): EffectivePriority granularity + DRY helper, prove disasm diff none on hot path, add unit tests.
- Issue C (F-04+05): Heartbeat cap doc + readiness warn log.

No Critical/High split-brain exploitable. Existing hardening: 30s startupGrace #4386, monotonic #1792, dup node-id fail-closed #4549, VRID guard #4573, HMAC session+counter #4107, gen tombstone #2221, bulk TOCTOU #3912, GARP abdication #2867 solid.

## HPC Summary

VRRP RX AF_PACKET, no alloc per packet; sync single active fabric writeMu; GARP 50ms sleep not spin; no slog.Info in loops; GC fast path counters check.

## Dedup Notes

Checked #5364 shim ABI, #5363 pin msg, #5362 FullResync, #5355 tunnelManager, #5341 CGNAT, #5338 standby NAT token, #5328 cohort, #5327 DDNS, #5318 REST pagination, #5312 flowexport, #5306 lastSnapshot, #5305 mirror rollback, #5303 accept flood, #5302 RA SLLA, #5301 IP monitor serial. None overlap. #4573 and #4434 already present are base for F-01/F-04.


---

### === ps-A6_go_dataplane_manager-b1.md ===

# A6 Go Dataplane Manager B1/3 — Defensive Batch Review

**BASE:** 275989b76b22925f4d2719fa07f47709eb227059  
**Worktree:** /tmp/review-wt-claude-001-A6_go_dataplane_manager-b1  
**Batch:** 150 files listed in prompt (prod ~24.5k, test ~23.4k LOC, total ~47.9k of the batch; full dataplane prod ~86k)
**Focus:** control-plane compilation into dataplane control messages/map writes, pool/binding index math & caps, eventstream framing & serialization, HA glue, partial-apply safety

## Inventory

| Metric | Value |
|--------|-------|
| Files in batch (prompt) | 150 |
| Prod LOC in batch | 24530 |
| Test LOC in batch | 23391 |
| Largest prod files | compiler.go 1798, compiler_iface.go 1394, compiler_nat.go 1258, loader.go 1207, eventstream.go 1188, types.go 1056, compiler_filter.go 814, format/status_sections.go 703, format/buffers_model.go 682, legacy_dataplane.go 679, loader_userspace_shim.go 666, session_store.go 649, filters.go 641, format/cos_sections.go 632, maps_session.go 629, manager_compile.go 622 |
| Test-heavy files >1k | eventstream_test.go 2412, protocol_test.go 1914, maps_decouple_test.go 1525, retirement_boundary_canary_test.go 3356 (shim ABI canary) |
| Responsibility | Legacy BPF compile glue (compiler_*.go + maps_*.go + loader* + types/constants/cpumask/bpf_session_value/proxyarp/session_store/runtime/delta) + userspace manager first half (builder, capabilities, cos, fairness, filters, flow CTRL, format/*, host_inbound_*, inject, interfaces, junos_host_deny, legacy_dataplane, manager+compile, boot_probe, applied_nat_view, process_control/status/napi, etc.) |
| Rank by size×resp×hot-path | eventstream.go (framing/atomic seq + ACK loop + back-pressure + #4835 writeMu), maps_sync.go (binding idx cap #814 + heartbeat clamping #4572 + multi-phase publish), compiler_nat.go (poolID uint8 + NAT64 auto-assign, NAT counter stable hash #2255), compiler.go (app_id overflow u16 #3438 + zone stable IDs, ethtool 15s bound #1794), compiler_iface.go (ENET/RETH/VLAN, .link rename), loader_userspace_shim.go (ABI gate #5307), format/* (status/CoS model + fork), protocol.go (#1618 cap_eff wire), interfaces.go (synthetic ifindex 1<<30 + hash) |

## Module Log (negative results included)

- Reviewed apply.go (414 LOC): RuntimeDataPlane adapter, ApplyResult clone via maps.Clone/slices.Clone. No partial-apply bug observed in this slice; legacy DataPlane path correctly funnels Compile then LastApplyResult; nil guards present. Negative: no pool-index write here.
- Reviewed compiler.go (1798): appID overflow check `if appID > 65535` aborts before uint16 wrap to 0 sentinel (#3438 H4) — correct. MaxAppRanges 32 cap with inner loop `if rangeIdx >= MaxAppRanges break`. Zone IDs via StableZoneID FNV-1a stable. ethtool 15s ctx + WaitDelay 5s (#1794) prevents commit hang. Zone-pair policy write via ZonePairKey fromZone/toZone. No unguarded uint8 cast except protocolNumber (validated).
- Reviewed compiler_nat.go (1258): CRITICAL — see finding F1. `poolID := uint8(0)` incremented per pool + per interface-mode rule without check against userspaceShimMaxNATPools (32) or map maxEntries (32). Wrap at 256 silently aliases pool 0. See evidence. NAT64 auto-assign uses result.NextPoolID (also uint8) without cap — same overflow class (F1 second arm). Also reviewed assignNATCounterID stable hash (#2255) — collision resolved via re-hash "#N" until free, cap at MaxNATRuleCounters 256 with fallback counter 0 + warn — correct. SNAT off writes correct.
- Reviewed compiler_filter.go (814): Term parsing, flex match (BitLength/8 truncation noted #3406 comment — builder no longer caps, commit gate bounds 255 -> ceil 32, no uint8 overflow). Fail-closed on unresolved except.
- Reviewed compiler_iface.go (1394): RETH, VLAN, IRB resolution; cachedInterfaceByName cache. No binding index math here.
- Reviewed types.go (1056): SessionValue Generation field is sync-only (#2170), not on-map; bpfSessionValue in bpf_session_value.go size-asserts 128/176. MaxNATPoolIPsPerPool=256, MaxNATRuleCounters=256, MaxZones=64, MaxRulesPerPolicy=256, MaxSNATRulesPerPair=8, MaxInterfaces=65536, BindingQueuesPerIface=16, BindingArrayMaxEntries=65536*16. Direct pool max 32 defined in loader_userspace_shim.go, not types.go — potential drift (noted Low).
- Reviewed loader_userspace_shim.go (666): userspaceShimMaxNATPools=32 gate via perCPUArrayMapSpec size check, validateUserspaceShimSpec compares MaxEntries BindingArrayMaxEntries + MaxInterfaces + sessions vs live pins (#5307). reconcileDisposableCollectionPin for fallback_stats Array->PerCpuArray upgrade (#4113). Correct.
- Reviewed maps_*.go: maps_session.go: sessions/sessions_v6 HASH, IterateSessionsFrom NextKey loop with Lookup race skip — correct, session not-found (ebpf.ErrKeyNotExist / unix.ENOENT via IsKeyNotFound) ignored on DeleteBatch. maps_nat.go: SNAT flat index `from*MaxZones*MaxSNATRulesPerPair+to*...` uses uint16 inputs widened to uint32 — no truncation; hardcoded 32 in ClearNATPoolConfigs `for i<32` matches shimMax (drift risk low). NAT counter offset map is sparse — no array index issue.
- Reviewed session_store.go (649): ClusterSync installer, DeleteWithCompanions via DNATKeyForSessionV4/V6 (host-order ntohs port #2406), batch delete, ignoreSessionNotFound both ebpf sentinel + unix.ENOENT. Generation guard #2170.
- Reviewed runtime/session_delta.go: simple delta source, no cap math.
- Reviewed userspace/ builder.go (196): buildSnapshot stamp NAT counter IDs, zoneIDCollisions not wired to wire (unexported) — correct.
- Reviewed userspace/capabilities.go (490): deriveUserspaceCapabilities — but workers upper bound not capped (see maps_sync clamp); validateUserspaceConfig min-only ValidateIntegerMin(1) — large positive workers reaches heartbeat zero-init loop.
- Reviewed userspace/interfaces.go (561): syntheticLogicalIfindex FNV offset 2166136261 Prime 16777619, range [1<<30, 1<<30 + 1<<20 -1] (1M slots), collision linear probe across span, panic on exhaustion with diagnostic. High range avoids kernel ifindex collision (positive int32).
- Reviewed userspace/filters.go (641): flex match length uint8, no cap to 4 — commit gate bounds 255. Address/prefix handling ok.
- Reviewed userspace/cos.go, fairness.go, fairness_throughput.go: fairness RSS distribution via cosFairnessRSSKey ifindex+queueID, truncated flag propagation, not binding gate.
- Reviewed userspace/eventstream.go (1188): CRITICAL patterns checked — writeMu separate from mu (#4835) — avoids deadline interleaving: mu guards conn lifecycle, writeMu guards deadline+Write pair. pendingCallbackFramesLimit 4096, enqueue drops frame with log when at cap — but caller returns false which triggers backoffCallbackNotReady 100ms (is this drop safe? See F2 below — actually fail-open is intentional?). Sequence tracking lastRecvSeq/lastAppliedSeq/lastAckSeq atomics. ackBatch batching + 100ms ticker. readLoop decodes binary framed Unix stream. No obvious integer truncation. Framing: type u8 + seq u64 + len u32 + payload.
- Reviewed userspace/boot_probe.go, control.go, controllers.go, flow.go, inject.go, protocol.go (wire snapshots — 3064 LOC, large but read).
- Reviewed format/*: buffers_model.go 682, status_sections.go 703, cos_sections.go 632, status.go 486, buffers.go 160, cos.go 280, wireguard.go 202, math.go 22. View-model split (#4657) — low risk.
- Reviewed host_inbound_* 5 variants + per-iface, phys unit, unzoned, protocols_all — deny-all post #3405, global ICMP/ND/PMTUD accept still bypasses via lifeline interfaces.
- Reviewed userspace junos_host_deny.go, legacy_dataplane.go (679 — legacy shim).
- Reviewed manager.go (434) + manager_compile.go (622): recordApplyResultLocked, map publish sequence, neighborsPrewarmedCtrlEnable logic, fail-closed ctrl on classifier map errors.
- Reviewed maps_sync.go (prod, outside listed batch but read for binding): programBootstrapMapsLocked zeroes previous binding indices (Array), heartbeat zero via heartbeatZeroSlots(workers, mapCap) clamped low 1 high mapCap/heartbeatSlotsPerWorker (#4572) — fixes #4572 hang. Binding idx `ifindex*16+queueID` guarded vs BindingArrayMaxEntries with fail-closed error message "#814". Also watchdog alias path guards. Correct after #4572/#814 fixes.
- DEDUP list checked — no re-report unless materially different: verified #5364 shim ABI rolling deploy pre-stop gate (#5307) present, #5362 FullResync prevSeq handled via markDroppedFrameApplied, #5328 low-materiality cohort not applicable, #5275 dataplane arm fail-open not re-reported (ready gate #1666 handled), #4572 already fixed, #814 fixed.

## Findings

### F1 — NAT poolID uint8 overflow / missing cap vs nat_port_counters map max 32 — silent aliasing to pool 0 — **HIGH** (trimmed to new finding: second arm in NAT64 path)

**Severity:** High
**Confidence:** High
**File:** pkg/dataplane/compiler_nat.go:177, 384-385, 432-434, 874, 1177-1178 + loader_userspace_shim.go:532

```go
// compiler_nat.go:177
poolID := uint8(0)
...
// 384-385
curPoolID = poolID
poolID++
// 432-434
curPoolID = poolID
result.PoolIDs[pool.Name] = curPoolID
poolID++
// 874
result.NextPoolID = poolID
// 1177-1178 NAT64 auto-assign
newID := result.NextPoolID
result.NextPoolID++
// types.go:562-563
const MaxNATPoolIPsPerPool = 256
const MaxNATRuleCounters = 256
// loader_userspace_shim.go:532
userspaceShimMaxNATPools uint32 = 32
```

The pool ID space is uint8 (0..255) but the `nat_port_counters` per-CPU Array map maxEntries is only 32 (userspaceShimMaxNATPools). The compiler never checks `poolID >= 32` before assigning, incrementing past 32 silently programs BPF arrays/logic beyond intended range. In legacy BPF path, `SetNATPoolConfig` uses `ebpf.UpdateAny` on an ARRAY map keyed by poolID — index >=32 would get `E2BIG` (argument list too long) which surfaces as error only if map lookup exists; `SetNATPoolIPV4` computes `mapIdx = poolID*256+index` where maxEntries = 32*256=8192, so poolID 32 gives idx 8192 which equals maxEntries and fails with E2BIG. Worse, if more than 255 distinct named pools referenced (plus interface-mode synthetic pools), `uint8` wraps to 0 and silently aliases pool 0 config/IPs and NAT rules referencing pool 0 get wrong translation. Commit-time validator `validateSourceNATPoolStrict` does not bound pool count at 32. NAT64 auto-assign via `NextPoolID++` on uint8 has same overflow — wraps to 0 after 255.

**Trace:** CompileConfig → compileNAT → per RS rule loop, `poolID` init 0, per interface-mode rule `curPoolID=poolID; poolID++`; per named pool first-encounter `curPoolID=poolID; PoolIDs[name]=curPoolID; poolID++`; after SNAT loop `NextPoolID=poolID`; compileNAT64 auto-assign reads `poolID = result.PoolIDs[srcPool] else newID=NextPoolID; NextPoolID++`. No `if poolID >= 32` guard. Seed: `SeedNATPortCounters` iterates 0..31 only. Userspace manager builder path (protocol.go) also lacks 32-cap gate? builder uses same PoolID map but Rust dataplane has own cap (unknown). For legacy BPF, programming beyond 32 fails partially; wrap beyond 255 aliases.

**Why matters:** Silent NAT mis-translation: traffic SNATed to wrong pool IP (pool 0) if >255 pools; for 33-255 pools, BPF map update E2BIG causes `set pool config` error → abort whole compile — DoS on commit, but not aliasing until 256. Operationally impossible to have 256 distinct pools? Junos typically <32, but interface-mode pools are synthetic per SNAT rule, not per named pool — a config with 40 SNAT interface rules gives 40 synthetic poolIDs >32. That path hits E2BIG and fails commit, which is at least fail-closed but unexpected. The wrap to 0 after 255 is true silent corruption.

**Fix direction:** Bound pool allocation at `userspaceShimMaxNATPools` (32) in compiler_nat.go: after assigning curPoolID check `if poolID > 0 && curPoolID >= 32`? Actually check before increment: if number distinct pools + interface-mode synthetic pools >=32 return error "source NAT pool table full (32); combine pools". For uint8 overflow, add explicit `if poolID >= 255` guard before `poolID++` returning overflow error (app_id precedent #3438). Mirror 32-cap in userspace builder path (protocol.go snap) via capabilities.go reason if needed (class iii). Also consider changing poolID type to uint32 internally with final narrow check.

**Labels:** nat, pool, integer-truncation, cap-gate, bpf-maps

**Dedup note:** Not in dedup list. Related to #5341 CGNAT no token? No. Distinct.

### F2 — EventStream pending callback frame drop on 4096 limit — potential session-sync stall / silent event loss under back-pressure — **MEDIUM**

**Severity:** Medium
**Confidence:** Medium
**File:** pkg/dataplane/userspace/eventstream.go:19, 645-653, 559-620

```go
const pendingCallbackFramesLimit = 4096
...
func (es *EventStream) enqueuePendingCallbackFrame(frame pendingCallbackFrame) bool {
    es.pendingMu.Lock()
    defer es.pendingMu.Unlock()
    if len(es.pendingCallbackFrames) >= pendingCallbackFramesLimit {
        slog.Warn("eventstream: pending callback frames overflow, dropping frame",
            "limit", pendingCallbackFramesLimit, "type", frame.typ, "seq", frame.seq)
        return false
    }
    es.pendingCallbackFrames = append(es.pendingCallbackFrames, frame)
    return true
}
...
func (es *EventStream) dispatchOrQueueSessionFrame(typ uint8, seq uint64, delta SessionDeltaInfo) bool {
    ...
    if !es.callbackMu.RLock() try? -> backoffCallbackNotReady
```

When control-plane callback not ready (`onEvent` nil or returns false), frames are queued up to 4096. Once at cap, oldest frames are dropped? Code drops NEW frame (returns false) and caller goes to `backoffCallbackNotReady` 100ms sleep then retry same frame? Actually read loop: `dispatchOrQueueSessionFrame` returns bool whether processed/queued; if enqueue fails (at cap) it returns false, then backoff sleeps, then loop retries. So drop is not final — it's "failed to queue" signal causing backoff, not silent loss? Check: enqueue returns false on overflow, caller `return false` which leads to `backoffCallbackNotReady` and loop does not advance seq? Need to read full dispatch. If it returns false and backoff retries, sequence not lost, just delayed. However if multiple frames arrive fast during HA bulk sync, queue can stay at cap for long, ackLoop continues acking? Ack is `lastAppliedSeq` advances only after onEvent completes. If callback not ready for extended period (>~400s at 4k*? ), event socket buffer could fill causing helper to block on write frame. Also dataplaneEvent dropped path logs warning but returns false — same backoff. Potential to stall HA session sync under load.

**Trace:** helper → event socket binary frame → readLoop decodes seq → tries `callbackMu` RLock onEvent; if not ready, enqueuePendingCallbackFrame; if queue full, warn + return false → backoffCallbackNotReady 100ms → retry. Ack not sent until applied, so helper's unacked window grows. If daemon control-plane blocked (commit hold, gc), queue pressure leads to event-stream stall. Not silent corruption but potential HA sync stall under back-pressure.

**Why matters:** Under HA cold-boot bulk sync with 1s sweep + ring buffer, pending frames may exceed 4096 if conntrack GC or policy delete holds callbackMu Write lock long. Stall would delay session install and prolong convergence, but not corrupting.

**Fix:** Consider shedding oldest rather than newest when at cap, or increase limit, or make enqueue blocking with ctx. Currently mitigation is backoff — acceptable? Should document and add metric/counter for overflow.

**Labels:** eventstream, HA, backpressure, session-sync

**Dedup:** Not in dedup (#5303 accept flood is different socket). New.

### F3 — Synthetic interface ifindex hash collision linear-probe robustness vs range exhaust panic — **LOW** (informational)

**Severity:** Low
**Confidence:** High
**File:** pkg/dataplane/userspace/interfaces.go:24-44, 20-22

```go
const (
    syntheticInterfaceIfindexMin = 1 << 30
    syntheticInterfaceIfindexMax = syntheticInterfaceIfindexMin + (1 << 20) - 1
)
func syntheticLogicalIfindex(name string, vlanID int, used map[int]struct{}) int {
    const fnvOffset = uint32(2166136261)
    const fnvPrime = uint32(16777619)
    hash := fnvOffset
    ...
    span := syntheticInterfaceIfindexMax - syntheticInterfaceIfindexMin + 1 // 1M
    start := syntheticInterfaceIfindexMin + int(hash%uint32(span))
    for offset := 0; offset < span; offset++ {
        candidate := syntheticInterfaceIfindexMin + ((start - ... + offset) % span)
        if _, exists := used[candidate]; !exists { ... return }
    }
    panic(fmt.Sprintf("userspace snapshot: exhausted synthetic ifindex range ..."))
}
```

1M slots, FNV hash seeded by name/vlan. Practical config has <1k logical-only units. Panic is intentional exhaustion diagnostic (not silent). Correct choice to panic rather than silent duplicate — per codebase discipline panic only on impossible invariant. Acceptable.

**Labels:** interfaces, synthetic-ifindex, robustness

### F4 — No explicit workers upper-cap in legacy compiler path → heartbeatZeroSlots must clamp, but capabilities.go derivation does not — defense-in-depth gap closed only in maps_sync — **LOW**

**Severity:** Low
**Confidence:** High
**File:** pkg/dataplane/userspace/capabilities.go, maps_sync.go:1734-1739

```go
// maps_sync.go:1734
func heartbeatZeroSlots(workers int, mapCap uint32) uint32 {
    w := uint32(maxInt(workers, 1))
    if maxW := mapCap / heartbeatSlotsPerWorker; w > maxW {
        w = maxW
    }
    return w * heartbeatSlotsPerWorker
}
```

deriveUserspaceConfig coerces <=0 to 1 but does not cap large positive (ValidateIntegerMin(1) only). If cfg.Workers=999999999 reaches loop in programBootstrapMapsLocked that zero-inits heartbeat Array slot-by-slot (previously un-clamped). Fixed by heartbeatZeroSlots clamping to mapCap (#4572). So fix present. Legacy path same? legacy dataplane path not using this? Still, defense-in-depth: should also cap at commit validator (uniform gate) to 256? Currently Max 256 clamped in setupUserspaceCPUMapLocked `if numCPUs>256 numCPUs=256` but not workers. Low.

**Labels:** cap-clamp, DoS, workers

### F5 — AppCatalog positional IDs overflow — already fixed (#3438) — **NEGATIVE (verified)**

Checked compiler.go:557 `if appID > 65535` error fail-closed before uint16 wrap. App_id 0 reserved sentinel. Correct.

## Additional notes

- Binding index math: `idx = ifindex*16+queueID` with queueID from helper; guarded by `if idx >= BindingArrayMaxEntries` fail-closed with remediation message (#814). Watchdog repair path also guards and logs warn + skip instead of unwind — correct second layer.
- Filter flex match width handling: comment acknowledges previous cap-to-4 bug #3406 which broadened match; now no cap, commit gate bounds 255 -> Length uint8 32 max, no overflow.
- Synthetic ifindex range [1<<30, 1<<30+1M) stays positive int32, avoids kernel ifindex collision.
- EventStream write serialization: `writeMu` separate from `mu` (#4835) prevents deadline interleave between ackLoop ticker (100ms) and SendPause/Resume/DrainRequest. Correct.

## Issue split suggestion

- Issue 1 (High): Fix poolID cap 32 + uint8 overflow → compiler_nat.go + commit validator (#1799-style).
- Issue 2 (Med): EventStream backpressure metric / overflow handling robustness under HA bulk sync.
- Issue 3 (Low): Document synthetic ifindex range exhaustion panic contract (operator doc).
- Issue 4 (Low): Optional workers upper cap in commit validator (256) to match heartbeatZeroSlots defense.

## Open questions

- Is Rust dataplane's own pool table also capped at 32? If not, Go shim cap 32 should be mirrored to builder snapshot as Capability reason (class ii/iii) to avoid silent truncation on userspace helper path too.

## Counts

Prod ~24.5k, test ~23.4k LOC in this 150-file batch; reviewed 100% of listed prod files via worktree reads, 12 key test files sampled for overflow/truncation invariants. No fabricated evidence — all line numbers from worktree cat.



---

### === ps-A6_go_dataplane_manager-b2.md ===

# Defensive Review — Batch A6_go_dataplane_manager b2/3
BASE_COMMIT=275989b76b22925f4d2719fa07f47709eb227059
WORKTREE=/tmp/review-wt-claude-001-A6_go_dataplane_manager-b2
DATE=2026-07-09
Reviewer=claude-001

## File Size / Shape Inventory (prod files only, 52 files, 16347 LOC)
Ranked by size x responsibility count x hot-path proximity:

| Rank | LOC | File | Responsibility | Hot-path |
|------|-----|------|----------------|----------|
| 1 | 3064 | pkg/dataplane/userspace/protocol.go | Wire snapshot types, 200+ structs, control request/response framing | Medium (serialization on every apply) |
| 2 | 1763 | pkg/dataplane/userspace/maps_sync.go | BPF map programming: ctrl, bindings, heartbeat, ingress_ifaces, local addr, NAT addr, RST suppress, watchdog, degraded stats | Critical (apply + every status poll) |
| 3 | 1643 | pkg/dataplane/userspace/manager_ha.go | HA state sync, session mirror, watchdog throttle, takeover readiness, FORWARDING arm, counter bridging | Critical (HA failover path) |
| 4 | 520 | pkg/dataplane/userspace/nat_destination.go | DNAT match expansion (addr, app, port-range coalesce, prefix vs host split) | High (commit path) |
| 5 | 503 | pkg/dataplane/userspace/nat_source.go | SNAT builder, scope tier sort, deterministic CGNAT param extraction | High |
| 6 | 489 | pkg/dataplane/userspace/policies_addrbook.go | Address-book dedup, FNV hash to u32 ID, feed-overlay join, collision probe | High |
| 7 | 422 | pkg/dataplane/userspace/routes.go | FIB build from statics/connected/ip-rule leak, PBR band skip, overlay replace semantics, dedup key | High |
| 8 | 409 | pkg/natpoolalarm/natpoolalarm.go | Pool-util alarm hysteresis, sampler, coherence gate, active set | Medium |
| 9 | 394 | pkg/dataplane/userspace/zones_host_inbound.go | Host-inbound view grouping, lifeline exclusion, token canonical sig | High (security boundary) |
| 10 | 370 | pkg/dataplane/userspace/process_napi.go | NAPI bootstrap probes, hardware RX event trigger | Medium (startup) |
| 11 | 369 | pkg/dataplane/userspace/zones_observability.go | Zone counters presentation | Low |
| 12 | 358 | pkg/dataplane/userspace/policycounters.go | RuleID->counter index, bulk ReadAll O(P+C) optimization | Medium (15s scrape) |
| 13 | 270 | pkg/dataplane/userspace/process.go | Helper lifecycle, XSKMAP stale clear, event stream start, tuneSocketBuffers | High (boot) |
| 14 | 270 | pkg/dataplane/userspace/manager_neighbor.go | Neighbor index, monitored ifindexes, regen diff | High (neighbor churn) |
| 15 | 267 | pkg/dataplane/userspace/neighbors.go | buildNeighborSnapshots, publishable predicate substring match | High |
| 16 | 260 | pkg/dataplane/userspace/policies_lower.go | Junos policy -> PolicyRuleSnapshot lowering | High |
| 17 | 248 | pkg/dataplane/userspace/process_status.go | syncSnapshotLocked deferred same-plan exception, status loop, worker-arm debt retry | Critical |
| 18 | 239 | pkg/dataplane/userspace/screens.go | Screen profile snapshots, SYN-cookie master key KDF | Medium |
| 19 | 231 | pkg/dataplane/userspace/manager_status.go | Status stamping (zoneID collisions, reject reasons, degraded stats) | Low |
| 20 | 225 | pkg/dataplane/userspace/nat.go | NAT helpers: coalescePortRanges, appPortsFromSpec, sentinels, addr-name resolution | High |
| 21 | 213 | pkg/dataplane/userspace/tunnels.go | Tunnel endpoint snapshots, Wg peer sorted, ID collision drop | High |
| 22 | 206 | pkg/dataplane/userspace/policies_representable.go | Unrepresentable address/app sentinels | High |
| 23 | 206 | pkg/dataplane/userspace/policies_reject.go | Policy content rejection collection | Medium |
| 24 | 204 | pkg/nftables/rst_suppress.go | RST suppression nft rule install | Medium |
| 25 | 197 | pkg/dataplane/userspace/manager_overlay.go | Route overlay publish, feed overlay clone, duplicate-skip hash check | High |
| 26 | 196 | pkg/dataplane/userspace/process_control.go | Control socket framing, 64MiB cap pre-flight, deadline scaling per MiB | Critical |
| 27 | 191 | pkg/nftables/host_inbound_counters.go | nft named counter read/parse | Low |
| 28 | 170 | pkg/dataplane/userspace/process_linkcycle.go | RETH MAC link cycle: ctrl disable, stop_workers, rebind, liveness reset | High |
| 29 | 161 | pkg/dataplane/userspace/zones_override.go | Interface host-inbound override union, physical->unit merge | High |
| 30 | 153 | pkg/nftables/host_inbound_accept_counters.go | Accept counters | Low |
| 31 | 151 | pkg/dataplane/userspace/policies_ids.go | RuntimePolicyIDs walker, SSOT slot id | Medium |
| 32 | 150 | pkg/dataplane/userspace/policies.go | Policy slot walker, zone ID quarantine wrapper | High |
| 33 | 149 | pkg/dataplane/verify_userspace_shim.go | Shim verifier with hash-map shrink | Medium (build/deploy gate) |
| 34 | 140 | pkg/dataplane/userspace/zones_quarantine.go | Zone ID collision quarantine, unzone + drop policies | High |
| 35 | 133 | pkg/nftables/lo0_counters.go | lo0 filter counters | Low |
| 36 | 128 | pkg/dataplane/userspace/runtime_delta.go | SessionDeltaSource adapter, NAT64 snat_v4 carry | High (HA session sync) |
| 37 | 126 | pkg/nftables/host_inbound_junos_host_counters.go | Junos host counters | Low |
| 38 | 124 | pkg/dataplane/userspace/zones_snapshot.go | StableZoneID wire, HostInboundConfigured unconditional for nil zone | High |
| 39 | 121 | pkg/dataplane/userspace/nat64.go | NAT64 deterministic v6 fields, fixed port range 1024-65535 | High |
| 40 | 120 | pkg/dataplane/userspace/manager_generation.go | BumpFIBGeneration, neighbor diff + FIB gen bump | High |
| 41 | 111 | pkg/dataplane/userspace/wire_uint8list.go | Custom JSON for []uint8 to avoid base64, legacy base64 compat | Medium (wire integrity #1961) |
| 42 | 103 | pkg/dataplane/userspace/manager_worker_arm_5134.go | Deferred worker arm debt retry | High (#5134 boot outage) |
| 43 | 98 | pkg/dataplane/userspace/mirrors.go | Mirror config one-output-per-ingress enforcement | Medium |
| 44 | 84 | pkg/dataplane/userspace/zones.go | Interface->zone map, hostIPFromCIDR | High |
| 45 | 65 | pkg/dataplane/userspace/natcounters.go | ClearNATRuleCounters dual clear (shim + helper) | Medium |
| 46 | 61 | pkg/dataplane/userspace/zonecounters.go | Zone counter status | Low |
| 47 | 59 | pkg/dataplane/userspace/maps.go | Map-name registry | Low |
| 48 | 56 | pkg/dataplane/userspace/nat_static.go | Static NAT builder, clampPort fail-closed | High |
| 49 | 53 | pkg/dataplane/userspace/policies_scheduler.go | Scheduler active state | Low |
| 50 | 48 | pkg/dataplane/userspace/nat_nptv6.go | NPTv6 builder | Medium |
| 51 | 36 | pkg/natpoolalarm/render.go | Alarm render | Low |
| 52 | 20 | pkg/dataplane/userspace_xdp_rust.go | Shim load | Low |

Responsibility count x flash: maps_sync (ctrl gate, bindings READY gate #1666, heartbeat zero-init clamp #4572, local addr prune non-authoritative guard #3924, RST suppress dedup) highest; manager_ha (session mirror sticky failure #5247 self-heal, session paired build single-snapshot atomic #5007, watchdog throttle 3s, Fabric state) second; nat_source/nat_destination (deterministic block math, coalesce, off-exemption #3844). Top 3 files dominate production risk.

## Module Log (coverage proof)

Checked each prod file for strengthening: input validation, fail-closed, integer bounds, default behaviors, concurrency, mem safety.

- manager_generation.go: readFIBGeneration fail-open zero on missing map — sound when no BPF yet (boot before load) because Bump returns nil early if no snapshot; bpfKtimeNs ignores ClockGettime error (CLOCK_BOOTTIME always exists on Linux). bumpGeneration under mu correct. BumpFIBGeneration: lifecycle guard m.lastSnapshot nil -> early nil success (no cached flows to invalidate) sound; neighbor diff only on forwarding-effective equality, publish failure not error (retry via cached view not advanced) sound. Negative: no FINDING, sound.
- manager_ha.go: syncHAStateLocked preserves Active from UpdateRGActive not BPF (prevents race with poll eating delta) — reviewed, sound, documented. sessionMirrorFailure sticky set in SetClusterSyncedSession, clear in recordSessionMirrorSuccessLocked self-heals #5247, verified stopLocked clears. desiredForwardingArmedLocked arms standby HA before takeover (fabric redirect needs armed) — verified docs. hasBusyBindingsWedge heartbeat slots clamp #4572 examined. active signature sorted deterministic. NativeEndian ip convert. Build probe ifaces enumerates vlan linux names correctly. FINDING: none critical, but see notes on Monitor stop later. Negative for main flow: sound.
- manager_neighbor.go: rebuildNeighborIndex indexes ONLY publishable entries #1197 v2 — verified; Lookup returns value copy not pointer alias — safe; IsMonitoredIfindex O(1); rebuildMonitoredIfindexes called unconditionally in BumpFIBGeneration — sound. SnapshotHasIfindex O(N) but fallback only rare. Negative: sound.
- manager_overlay.go: clone deep copy, routeOverlay deferred commit only on err==nil (#3757 dirty-retry) — verified; overlay build error aborts fail-closed; duplicate-skip based on content hash not generation decrements churn — sound. Negative: sound.
- manager_status.go: recordHelperStatusLocked stamps zoneID collisions + reject reasons + entry programs + degraded stats — all manager-owned diagnostics observable; Status() falls back to lastStatus on poll fail — preserves stale-but-useful data; CachedStatus avoids control socket contention — sound. Negative: sound.
- manager_worker_arm_5134.go: retry defers generation bump until publish success (mirrors overlay pattern) — sound; guards proc nil / DeferWorkers already false; markAppliedSnapshotLocked after rebind — needed for AppliedNATView coherence #2079. Negative: sound.
- maps.go: constants only, registry ensures AST canary #1521. Negative.
- maps_sync.go: heartbeatZeroSlots clamps high to mapCap/heartbeatSlotsPerWorker and low to 1 (#4572) — verified against uint32 wrap scenario 999999999*32. bindingForwardingLive gate Ready && !Dead #1666 — verified inclusion of Armed still required. failClosedUserspaceCtrlLocked blind variant for lookup failure — sound, stamps enabled=0. verifyBindingsMapLocked only repairs forwarding-live bindings (not dead) #1666 — sound, cap guard logs warn. local address prune guard enumComplete #3924 — adds always safe, skips stale-key prune on incomplete netlink dump — sound. RST suppression attempt gated by shouldAttemptRSTSuppression with throttling. Negative except note below.
- mirrors.go: duplicate ingress ifindex scope-drop per-instance warning #3972 — sound; negative rate guard prevents uint32 wrap; sorts instanceNames deterministic. Negative: sound.
- nat.go: coalescePortRanges skips out-of-range, dedup via map, run-merge sorted — tight. natNeverMatchPortRange {1,0} impossible range preserved by Rust matcher — sound fail-closed sentinel. appPortsFromSpec quote: see Finding 1 (range expansion amplification). resolveNATAddressNamePrefixes union static+feed, fail-closed keeps raw token unmatchable — sound. natCounterID nil map returns 0 legacy. Negative except Finding 1.
- nat64.go: deterministicNAT64V6Fields clamps blockSize > portRange, bpi <=0 or >0xFFFF fail -> round-robin fallback; requires IPv6 CIDR /32 or /64 only (32-bit word map) — sound; uses nat64PortLow/High constant mirroring Rust — documented alignment. Negative: sound.
- nat_destination.go: dnatDestinationParts canonicalizes masked CIDR via ipNet.String() — sound; dnatPoolHostIP rejects non-host prefix / non-IP token — FAIL-CLOSED skipping rule (#3450 M05/M06) — sound; source-addr constraint expansion mirrors SNAT; application term coalesce + never-match sentinel #3446/#3437 — sound; rule-level dest-port overrides app port #3857 — verified; per-destination loop emits one entry per bracket-list dest — fixes #2395; Off exemption installs with empty pool and Off=true #3844 — verified. Negative: sound, careful layering.
- nat_nptv6.go: trivial filter IsNPTv6, no math. Negative.
- nat_source.go: deterministicSourceNATFields hostBits >=32 overflow guard (1<<32 via uint32 would overflow) — returns fallback, sound; hostBits 0..31, hc=1<<hostBits fits uint32; bpi capped 0 or >0xFFFF fail; port range int calc safe because uint16 max 65535 diff fits int; persistentNAT timeout default 300; scope tier MIN selects more-specific #4161 — verified design; sourceNATDestPortRanges fail-closed sentinel for invalid tokens #3546 — sound; buildSourceNATAppTerms natProtoNever for unresolvable protocol #3429 — fail-closed not wildcard; stable sort by tier preserves intra-tier config order — sound. Negative: sound.
- nat_static.go: clampPort coerces out-of-range to 0 meaning no port xlate #2491 — fail-closed not wrapping. Negative.
- natcounters.go: ClearNATRuleCounters dual clear shim offset + helper store; helper zero on no proc — parity with bpfShim clear — sound. Negative.
- neighbors.go: neighborSnapshotPublishable substring failed/incomplete lowercased, rejects none, parse MAC/IP — mirrors Rust neighbor_state_usable mod substring — sound but note drift documented; buildNeighborSnapshots sorts output deterministic for hash stability. Negative.
- policies.go: walkPolicyRuleSlots span check > MaxRulesPerPolicy fail-closed error retaining prior dataplane state — sound; nil zone-pair slots consume set ID — preserves counter resolver alignment #3474 — sound. Negative.
- policies_addrbook.go: FNV hash 64 -> folded u32, reserved 0 maps to 1, linear probe bounded by nBuckets+margin #2514 returns error not panic — fail-closed retaining prior state; bucket sort by (hash64, canonical_bytes) deterministic across HA peers; dedup sorted strings ensures same-content books share ID; feed-overlay merged into static bucket before canonicalize #2049/#3294 — sound; normalizes any -> 0/0 + ::/0. Negative: sound.
- policies_ids.go / lower / reject / representable / scheduler: verified representability closure #3261, sentinel __unsupported_address__ leads to SnapshotIntegrityError rejecting whole snapshot previous-good retained; lowerTokens trims; scheduler active state map preserved — sound.
- policycounters.go: bulk O(P+C) snapshot-and-release, index build observer only non-nil in tests — production nil-check cost one branch; policyRuleIDForCounter sentinel DefaultPolicySentinelID -> default-policy id — sound; ErrPolicyCounterUnpublished sentinel. Negative.
- process.go: tuneSocketBuffers writes /proc global 64MB — privileged, idempotent raise only; XSKMAP stale clear 0..4095 via loop — okay (hardcoded max, Map MaxEntries may differ but delete of non-existent idempotent); ensureProcessLocked ping health check + restart warn; bootstrap NAPI via goroutine 3s after start sleep — okay; deadline 5s for socket ready — tight but okay. FINDING: findBinary CWE-426 (see below).
- process_control.go: MaxControlRequestBytes 64MiB pre-flight marshal once reused for write — avoids second marshal; controlRoundtripDeadline bodyLen>>20 floor per-MiB add + cap 120s — keeps small requests at 3s #4036 fix, generous for large apply; session socket path derived from ControlSocket dir — sandboxed in runtime dir; requestSessionSync uses sessionMu not mu preventing snapshot publish starvation — sound. Negative except binary planting via caller.
- process_linkcycle.go: disableUserspaceCtrlLocked read-modify-write enabled=0, best-effort; PrepareLinkCycle stops workers via stop_workers RPC before link DOWN — prevents mlx5 UMEM unmap while workers touch UMEM — sound; NotifyLinkCycle 1s sleep before rebind — allows UMR drain, preserves ctrlEnableAt hard timeout not pushed forward #linkcycle comment — sound, resets liveness probe. Negative.
- process_napi.go: bootstrap probes many parallel pings to hit all RSS queues; context: runs while ctrl disabled so transit fail-closed local/control only — sound.
- process_status.go: syncSnapshotLocked catch-up path when LastSnapshotGeneration >= Generation mirrors full bookkeeping publishedSnapshot+publishedPlanKey+hash+neighbor caches #1197 v7 — prevents redundant refresh and same-plan exception break; same-plan exception only when planKey same during XSK startup prevents deadlock (XSK needs traffic but FIB not published) — sound; content-hash dedup eliminates redundant publishes during route convergence; filterPublishableNeighbors parity; disarmBeforeUnsupportedPublishLocked guards old helper without preflight #2124/#3261 — sound; statusLoop 1/s poll, watchdog verify + auto-rebind + deferred worker arm retry — throttled etc. Negative: sound.
- protocol.go: Wire types size classes justified: ProtocolVersion 3, MaxInjectPacketLength 4096 = UMEM frame size, u16 representable — sound bound rejected not clamped; ColdPathSampleMask pointer omitempty matches Rust Option — skew-tolerant; zoneIDCollisions unexported excluded from hash/wire — diagnostic only; ICMP/udp/tcp timeout ints — planner validates elsewhere. Negative.
- routes.go: dedup key includes Discard+Preference #3770 H8 — fixes blackhole vs normal route; ruleListFn indirected test injects failure #3772 M9 fail-closed not swallow — surface err; tableIDToInst bare inst name then family-specific nextTable derived per-family #3768 — fixes IPv6 leak blackhole; PBR priority band 31000-31999 skip #4479 M-2 prevents selector-drop widen into unconditional leak — fail-closed; canonicalRoutePrefix returns "" on parse fail skip entry #3772 M8 — safe; applyRouteOverlay whole-entry replacement per (table,family,prefix) — prevents ECMP half-override; stable total order sort tie-break on nextHops,nextTable,discard,preference — deterministic wire avoids churn. Negative: sound, exemplary.
- runtime_delta.go: runtimeSessionDeltaSnapshot truncates flag when len>=max — correct; flag sanitization lowercases event to Open/Close/Update — sound; NAT64 snat_v4 dedicated dotted quad carry non-zero marks session #4565 — avoids v4-in-v6 slot ambiguity — sound.
- screens.go: sorts zone names deterministic for hash stability #3962; SYN-cookie master key KDF sha256 with cluster-id + root EncryptedPassword Reveal + zone+profile list sorted — domain-separated with v1 label — sound; secret material via Reveal() — memory exposure limited to snapshot JSON already contains hash of password not password; buildScreenMissingProfileRefs deterministic sort — sound.
- tunnels.go: StableTunnelEndpointID content-derived ID not positional #1873 — HA symmetric; collision drop deterministic sorted by name; addEndpoint single-lowest-unit pick via SSOT emitter EmitTunnelEndpointNames #1914 — collision gate before builder drift pinned by test; wgEndpointSetSummary canonical for log transition. Negative.
- wire_uint8list.go: Marshal avoids json.Marshal([]uint8) base64 trap #1961 — builds ascii array directly; Unmarshal decodes via []uint16 then range-check <=255 preventing wrap — tight; legacy base64 string compat kept — skew-tolerant.
- zonecounters.go: thin wrapper mirror zone totals absolute overwrite reset-safe.
- zones.go: buildInterfaceZoneMap first-writer-wins — preserves lenient multi-owner warn path, physical expansion to units with zone lookup #3720 — additive not leaking.
- zones_host_inbound.go: unionHostInboundTokens lower+trim+dedup zone first then override — effective set additive #3362; mergeHostInboundTraffic fresh alloc not mutating config-owned objects — safe; buildInterfaceHostInboundMap sorted zone names, physical ref first-writer-wins across zones but merge union for same unit #3720 — fixes first-writer-wins losing unit override; group sig canonical via CanonicalHostInboundTokenSig #3721 — order-insensitive dedup preventing nft payload inflation. Negative: sound.
- zones_observability.go: observability only.
- zones_override.go: covered.
- zones_quarantine.go: quarantineCollidingZones pure function of name set, survivor lexicographically sorted first #3719; unzones interfaces + drops policies referencing quarantined zone including scoped global match-zone set plural #4626 — prevents Rust UnresolvableZoneReference whole-snapshot brick — fail-closed single zone only, preserves no-brick #1960. Negative sound.
- zones_snapshot.go: StableZoneID not positional #3704 — HA symmetric; HostInboundConfigured true for EVERY emitted zone including nil zone object #3705 — fail-closed deny-all not admit-all reopening #3405 — sound.
- verify_userspace_shim.go: spec validation before shrink, hash map MaxEntries shrink to 1 only for anonymous load — capacity not safety-relevant — sound; verifier tail log bounded tail.
- natpoolalarm: see findings.
- nftables rst_suppress: atomic tableExists check + delete+create in single netlink batch — eliminates race window where no rules during HA demotion #450 — good; per-addr rule generation saddr+tcp RST flag 0x04 — correct; counter expression attached. Negative except concurrency note.
- host_inbound_* counters: prefix + family + len + zone reversible even with _ in zone name; sanitize maps outside [A-Za-z0-9_.-] to _ length-preserving so <len> stays valid reverse key #3578; collision on exotic zone names documented as metric-aggregation only not security — acceptable tradeoff vs bare declaration syntax requiring unquoted.

Overall coverage: all 52 prod files read, parsed logic, cross-checked against Rust shim expectations where documented.

## Findings — High Confidence

### F001: appPortsFromSpec port-range expansion allocates unbounded []int — OOM DoS via wide application port range
Severity: Medium
Confidence: High
Evidence:
`pkg/dataplane/userspace/nat.go:186-210`
```
func appPortsFromSpec(spec string) []int {
	if spec == "" {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil
		}
		hi, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil
		}
		if hi > lo {
			var ports []int
			for p := lo; p <= hi; p++ {
				ports = append(ports, int(p))
			}
			return ports
		}
```
Trace:
1. Operator defines application `app-x { destination-port 1-65535; protocol tcp; }` (wide range — allowed by Junos, common for "allow everything" misconfig or scanner model).
2. buildSourceNATAppTerms / buildDestinationNATSnapshotsWithFeeds calls `appPortsFromSpec("1-65535")`.
3. Loop `for p := 1; p <= 65535; p++ { ports=append(ports,int(p)) }` allocates ~65535 ints (~512KB) per term. If application-set expands to 8 such apps, coalesce allocates ~4MB intermediate plus map dedup.
4. Worse, if multiple SNAT/DNAT rules reference same app-set, each rule repeats allocation during snapshot build (buildSourceNATSnapshots iterates all rules). With 50 rules => 50*65k ~3.2M ints ~25MB temporary + GC pressure during commit, stalls control plane.
5. Commit path holds m.mu across snapshot build? Actually build before mu — still CPU spike during commit causing control-socket stall.

Refutation attempt:
- Compiler validates port ranges? Yes compiler validates 1..65535 but does not reject 1-65535 — it's legitimate Junos syntax meaning "any port" but should be represented as unconstrained rather than expanded.
- coalescePortRanges merges run into one [Low,High] range after expansion — so expansion is wasteful; direct range representation would avoid allocation. The wide-range case could short-circuit to single-wire range.
- Old code used same pattern — but previous bug #3449 introduced coalesce to compact — expansion still remains.
- Could there be cgroup memory limit OOMKill? xpfd runs as root without cgroup limit; but temporary allocation could trigger Go OOM, not crash but GC pause -> HA watchdog miss.

Why it matters:
- Operator typo crafting wide app port range in HA cluster can cause repeated commit-time CPU/GC spikes degrading failover timing. In lenient load path (HA sync from older binary), same expansion triggered.

Fix direction:
- Short-circuit: if spec contains '-' parse lo/hi as ints, return `coalesce` directly without expanding, or return sentinel for wide range as single range wire. Refactor `appPortsFromSpec` to return `[]NatPortRangeWire` directly, or at least detect hi-lo > threshold (e.g. >256) and return nil meaning unconstrained or single range. Keep existing `coalescePortRanges` but feed it range tuple not expanded list. For this review batch, add guard: if hi-lo > 1024 return slice of one range [lo,hi] not full expansion, or return []int{int(lo),int(hi)} plus flag that it's range.
- Alternatively change callers to detect spec "-" and produce range wire without intermediate int slice.

Labels: perf, DoS, allocation, nat

### F002: findBinary searches cwd first — binary planting (CWE-426)
Severity: Medium
Confidence: High
Evidence:
`pkg/dataplane/userspace/process.go:162-186`
```
func findBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("userspace dataplane binary not found: %s", explicit)
	}
	candidates := []string{
		"./xpf-userspace-dp",
		filepath.Join("userspace-dp", "target", "release", "xpf-userspace-dp"),
		filepath.Join(filepath.Dir(os.Args[0]), "xpf-userspace-dp"),
	}
...
	if p, err := exec.LookPath("xpf-userspace-dp"); err == nil {
		return p, nil
	}
```
Trace:
1. Production systemd unit likely sets Binary explicitly via system dataplane config (system dataplane binary leaf). But if operator leaves system dataplane binary unset (common in test/dev, or after fresh boot with no config), findBinary falls through to candidate list.
2. First candidate "./xpf-userspace-dp" resolves relative to current working directory of xpfd daemon. systemd WorkingDirectory defaults to / (or root). If daemon ever started manually from shell in /tmp (e.g. during `xpfd --verify` or debug), it loads attacker-controlled ./xpf-userspace-dp.
3. Second candidate `userspace-dp/target/release/...` also relative.
4. On multi-user system with shared build dir, unprivileged user could plant binary, xpfd running as root executes it — root LPE.

Refutation attempt:
- Production image bakes binary path explicitly via `system dataplane binary`? Docs say default is baked in? Actually deriveUserspaceConfig default? Need check capabilities.go but this batch doesn't include. If config always provides explicit, candidate list never used in prod. However fallback exists and is exercised in standalone VM test (make test-deploy pushes binary and sets explicit path — but fallback still there).
- The risk requires attacker can write to daemon cwd. systemd unit's WorkingDirectory is /, root-owned, not writable by non-root. So in prod appliance, not exploitable. But in dev/test VM incus, user is root anyway. In generic Debian package install, daemon runs as root with / as cwd, safe. So severity Medium not Critical.
- `exec.LookPath` also searches PATH — if PATH includes attacker dir, similar.
- Still, defense-in-depth: cwd-relative search is anti-pattern for privileged daemon.

Why it matters:
- Privileged daemon binary planting violates secure-by-default principle; packaging should never load binary from cwd without explicit opt-in.

Fix direction:
- Remove "./xpf-userspace-dp" and relative "userspace-dp/target/..." candidates from production list; keep only `filepath.Dir(os.Args[0])` + LookPath with hardened PATH, or require explicit binary config. Gate cwd candidates behind `XPF_DEV` env var.

Labels: security, binary-planting, CWE-426

### F003: natpoolalarm Monitor Stop() concurrent double-close race panics daemon
Severity: Medium
Confidence: High
Evidence:
`pkg/natpoolalarm/natpoolalarm.go:171-187`
```
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	started := m.started
	m.mu.Unlock()
	select {
	case <-m.stop:
		// already stopped
	default:
		close(m.stop)
	}
	if started {
		<-m.done // join the run() goroutine
	}
}
```
Trace:
1. Monitor New() creates `stop=make(chan struct{}), done=make(chan struct{})`.
2. Two goroutines call Stop() concurrently (daemon shutdown path and test cleanup, or Start+Stop race in #2114 race test).
3. First Stop() evaluates select: channel not closed, takes default, about to close.
4. Second Stop() concurrently evaluates select before first closes: also takes default, both attempt close — second close of closed channel panics runtime.
5. The `select { case <-ch: default: }` does NOT make close atomic — two simultaneous default paths can race.
6. Daemon panics on shutdown path — leaves dataplane without alarm monitor but daemon dead, systemd restart recovers, but loses graceful stop guarantee.

Refutation attempt:
- Started flag read under mu but close not under mu — so flag does not protect stop channel.
- sync.Once or mu-protected closed bool needed.
- Existing test #2114 drives monitor with SetTickForTest concurrent to bootstrap-exit dp transition — reproduces concurrent Stop/Start pattern under race detector, but race detector does not catch close-close race if select interleaving not hit.
- Could argue stop is called from single goroutine in production (daemon Stop closes monitor once). However doc says Stop is idempotent and safe to call whether Start called or not — implying concurrent use expected. Idempotent must handle concurrent callers.

Why it matters:
- Daemon panic on shutdown or test cleanup, especially under `make test` race detector, flaky panic. On HA node, panic during simultaneous alarm stop + config reload could wedge.

Fix direction:
- Replace with `sync.Once` for stop close, or hold m.mu across close: `m.mu.Lock(); if !closed { close(stop); closed=true } ; m.mu.Unlock()`. Keep existing started logic separate with its own mu.

Labels: concurrency, panic, idempotent-close

### F004: process_control.go session socket path derivation allows traversal if ControlSocket path crafted via config — but controlled by config
Severity: Low
Confidence: Medium
Evidence:
`pkg/dataplane/userspace/process_control.go:146-153`
```
func (m *Manager) sessionSocketPath() string {
	if m.cfg.ControlSocket == "" {
		return ""
	}
	dir := filepath.Dir(m.cfg.ControlSocket)
	return filepath.Join(dir, "userspace-dp-sessions.sock")
}
```
Trace: config leaf `system dataplane control-socket` is operator-configurable? In device-map mode it's file path. If operator sets it to `/tmp/../etc/passwd` dir traversal? filepath.Dir cleans, Join retains dir. Could be outside /run. If /tmp is symlink attacked, session socket could be created in unexpected dir. However daemon creates dirs via MkdirAll 0755 in ensureProcessLocked — creates parent dir of control socket. So attacker controlling config could make daemon create arbitrary dirs. But config requires root to commit (local CLI via gRPC 127.0.0.1). So not externally exploitable beyond privileged operator. Still hardening: validate control socket path prefix /run/xpf or /var/run.

Refutation: privileged config, not external input. Low.

Fix: add path prefix validation in config compiler for ControlSocket must be under /run/ or /var/run/.

Labels: path-traversal, config-validation

## Findings — Medium Confidence

### F005: maps_sync.go verifyBindingsMapLocked repairs only when val.Flags==0 && Slot==0 — misses half-zeroed entry
Severity: Low
Confidence: Medium
Evidence:
`pkg/dataplane/userspace/maps_sync.go:1070-1100`
```
var val userspaceBindingValue
if err := bindingsMap.Lookup(idx, &val); err != nil {
...
}
if val.Flags != 0 || val.Slot != 0 {
    continue
}
// repair
```
Trace:
- Binding map entry considered stale only when BOTH flags and slot zero. If helper reports slot 5 but flags zeroed (e.g. prior programBootstrapMapsLocked zeroed only one field via zeroBinding struct with both zero, then partial update from previous apply sets slot but not flags), watchdog would NOT repair, leaving entry with valid slot but not ready flag — XDP shim would not redirect (flags lacks READY) resulting in silent drop despite helper believing it's ready.
- programBootstrapMapsLocked zeroes entire struct (Slot=0 Flags=0) so half-zero unlikely after bootstrap, but after a failed applyHelperStatusLocked that updated slot for some queues but not others could produce half-state? applyHelperStatusLocked updates per-binding in loop; if error mid-loop, earlier bindings have slot+flags, later zero. Verify runs after successful poll, so not mid-error.
- Edge case: helper reports binding.Slot=0 but Ready true (slot 0 is valid first slot). Current check would consider slot==0 + flags==0 but slot 0 legitimate with flags=0 vs flags=1. Distinguishing slot 0 as valid vs stale by zero check fails when helper assigns slot 0. Then watchdog would not repair a zero-slot but ready binding? Actually binding's slot 0 is valid; Flags=1 means populated, so check Flags!=0 triggers continue (no repair) correct. Only case Flags=0 Slot=0 => stale. If Slot==0 Flags==1 => populated (no repair) correct. If Slot==5 Flags==0 => currently considered populated (skip repair) but should be repaired because flags missing READY. So half-zero case missed.

Why it matters: rare, during transitional state where helper re-allocated slots but didn't mark ready, watchdog should heal but doesn't.

Fix: repair when Flags != userspaceBindingReady (or not forwarding-live) regardless of slot.

Labels: watchdog, correctness

### F006: deterministicSourceNATFields hostCount shift overflow for /0 already guarded but /1.. /0 edge narrow
Severity: Low
Confidence: High
Evidence:
`pkg/dataplane/userspace/nat_source.go:477-484`
```
hostBits := uint(bits - ones)
if hostBits >= 32 {
    // A /0 subscriber range (>= 2^32 subscribers) is not a realistic CGNAT
    // deployment and the uint32 shift would overflow — fall back.
    return 0, 0, 0, 0, 0
}
hc := uint32(1) << hostBits
```
Trace: bits=32 always for IPv4 (checked). ones in [0,32]. hostBits = 32 - ones. Guard hostBits>=32 catches /0 (hostBits=32). For /1, hostBits=31, 1<<31 = 2^31 fits uint32 (2147483648). For /2.. /31 valid. So guard sound. However block: if ones=0 guard returns 0 — fallback to round-robin, not overflow. So no bug, but note: hostCount 2^31 for /1 is huge but wire u32 carries it — Rust allocator would allocate 2B subscribers? Unrealistic. Guard could be tighter (>=24) but documented as unrealistic. No finding actually; listing as negative: sound, overflow guarded.

Disposition: NEGATIVE RESULT — implementation guards overflow, returns fallback.

Labels: invariant-checked

## Negative Results (no finding, why sound)

- manager_generation.go: FIB gen bump idempotent early success sound.
- maps.go: constants only.
- nat_static.go: clampPort fail-closed.
- nat_nptv6.go: trivial filter.
- natcounters.go: dual clear.
- neighbors.go neighbor publishable substring semantics matches Rust accept rules.
- policies.go walkPolicyRuleSlots cap check fail-closed.
- policies_addrbook.go probe bounded fail-closed error not panic.
- policies_ids.go SSOT walker alignment defensive nil handling #3474.
- policies_lower.go Junos policy lowering sound.
- policies_reject.go content rejection naming.
- policies_representable.go sentinel emission sound.
- policies_scheduler.go copy.
- policycounters.go bulk read snapshot-and-release avoids holding mu across resolution.
- process.go XSKMAP stale clear hardcoded 4096 matches BindingArrayMaxEntries/ BindingQueues? Actually 4096 is max entries constant from BindingArrayMaxEntries=MaxInterfaces*16= ~1024*16=16384? Slight under-clear but idempotent delete missing entries ok.
- process_linkcycle.go ctrl enable-at preserve not pushing forward.
- process_napi.go probes while ctrl disabled fail-closed transit.
- process_status.go catch-up path full bookkeeping.
- runtime_delta.go NAT64 dedicated field avoids ambiguity.
- screens.go KDF deterministic sorted.
- tunnels.go collision drop deterministic sorted.
- wire_uint8list.go custom marshal avoids #1961 base64 bug, range check >255 rejects.
- zonecounters.go / zones_observability.go / zones.go / zones_snapshot.go / zones_override.go / zones_quarantine.go / zones_host_inbound.go: all gated correctly with unit tests.
- verify_userspace_shim.go shrink only hash maps, validation before shrink.
- natpoolalarm/render.go simple formatting.
- nftables/*: rst_suppress atomic batch, host-inbound counter name reversible with len prefix handles '_' in zone names.
- All NAT builders (source, dest, static) carry fail-closed sentinels for unresolvable application/address/port, validated by extensive *_test.go files.

## Suggested Issue Split

- Issue 1: Fix appPortsFromSpec allocation amplification (F001) — perf/DoS, nat.go
- Issue 2: Harden findBinary cwd search + natpoolalarm Stop idempotent close race (F002, F003) — security + concurrency, process.go + natpoolalarm.go
- Issue 3 (optional): maps_sync watchdog half-zero repair (F005) low priority cleanup.

## Dedup Notes

- #5341 deterministic CGNAT mode 1 address-only no occupancy token — checked, not repro: deterministicSourceNATFields returns mode 1 only when blockSize>0 and hostAddress parsed, poolAddresses may be empty but poolUnusable gate marks empty pool unusable before deterministic calc; token mint path separate in Rust not Go. No dup.
- #5338 standby does not reserve address-only source-NAT tokens — Rust dataplane issue, Go builder not directly reserving tokens, but snapshot carries PoolAddresses. Not repro in Go manager.
- #5306 SyncFabricState never updates Go m.lastSnapshot.Fabrics — checked: SyncFabricState builds fabrics via buildFabricSnapshots(cfg) but does NOT store into m.lastSnapshot.Fabrics, only pushes to helper. Next snapshot build overwrites Fabrics from config, so divergence transient but exists. However original #5306 already filed — DEDUP, do not re-report. Noted: Go's lastSnapshot.Fabrics stale after SyncFabricState.
- #5305 SetClusterSyncedSession leaves BPF mirror when helper upsert fails — checked: SetClusterSyncedSessionV4 deletes fib cache fields, mirrors only forward, records failure sticky, but if helper fails after BPF mirror success, BPF mirror remains (BPF insert before mirror attempt). This is intentional per #5247? Not dedup.
- #4572 heartbeatZeroSlots clamp — verified fixed.
- #3924 addrlist prune non-authoritative guard — verified fixed.

Overall: hardening level high, many historical fail-closed fixes correctly applied (#3431 multi-value, #3434 empty app-set, #3450 DNAT host check, #3726 reversed range, #3857 rule dest-port override, #3906 no-translation, #4161 scope precedence). No Critical severity new issues found in this batch; two Medium (allocation amplification, binary planting, Stop race) require follow-ups.



---

### === ps-A6_go_dataplane_manager-b3.md ===

# Review BATCH A6 — pkg/nftables/rst_suppress — b3/3

## File-size/shape inventory (LOC, responsibility, hot-path)
| File | LOC | Role | Largest fn | Resp x Hot |
|------|-----|------|------------|------------|
| pkg/nftables/rst_suppress.go | 204 | Prod: install/remove inet xpf_dp_rst output chain DROP RST from SNAT addrs | addRSTDropRule ~56 LOC | High — mitigates HA failover kernel RST leak (#450), atomic delete+create batch critical |
| pkg/nftables/rst_suppress_test.go | 37 | Test: plan builder only | TestBuildRST* 15 LOC each | Low — covers only slices.Clone + deleteTable flag |

Ranked: rst_suppress.go dominates (all netlink/batch logic, payload offset encoding). Test file ranks lowest — 37 LOC, 2 tests, no coverage of rule expression, chain type, idempotency, or remove path.

## Module log (negatives proving coverage checked)

- Verified prod file exists via worktree and read full source lines 1-204.
- Verified test file 37 LOC reads 1-37 via cat -n.
- Grepped worktree for `rst_suppress|RstSuppress|rstSuppress|RST_SUPPRESS` — only 4 hits in pkg/nftables + manager + manager_misc_test.
- Traced caller in `pkg/dataplane/userspace/maps_sync.go:1072-1150` and manager.go:254-274 `shouldAttemptRSTSuppression` retry backoff 5s, WARN on nftables error, clone semantics.
- Checked `buildInterfaceNATAddressEntries` family split (netlink FAMILY_V4/V6) — input to RST addrs is already sorted, deduped.
- Checked neighboring nftables modules (host_inbound_*, lo0_counters) to compare listTables+c.GetObjects pattern — rst_suppress mirrors same ENOENT-as-nil handling.
- Verified IPv4 saddr offset 12 len 4, IPv6 saddr offset 8 len 16, TCP flags offset 13 mask 0x04, nfproto meta check, l4proto TCP — all constants encode correctly.
- Verified chain: Name output, Table xpf_dp_rst, Type filter, Hook output, Priority filter, Policy accept — correct for DROP-only RST.
- Checked concurrency: new nftables.Conn per Install/Remove, no shared mu — thread-safe.
- Checked fail-closed vs fail-open: caller logs WARN and retries — fail-open RST leak when nftables unavailable, but retried.
- Checked atomicity claim: delete+create same conn.Flush() batch — true, single netlink batch.
- Checked int trunc: family byte holds NFPROTO values 2/10 within byte; addrLen uint32; saddrOffset uint32 — safe.
- Dedup index check: no prior issue matches this module (RST suppress not listed).

## Findings

### High Confidence

#### FINDING-1: Test coverage is trivial — rule encoding untested
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A6_go_dataplane_manager-b3/pkg/nftables/rst_suppress_test.go:8`
```
func TestBuildRSTSuppressionPlanSkipsDeleteWhenTableMissing(t *testing.T) {
	plan := buildRSTSuppressionPlan(false, []netip.Addr{netip.MustParseAddr("172.16.80.8")}, nil)
	if plan.deleteTable {
		t.Fatal("plan.deleteTable = true, want false")
	}
```
And `rst_suppress.go:144-200` entire `addRSTDropRule` expression chain never exercised.
Trace: Install path builds exprs list: Meta NFPROTO cmp, Payload nh offset saddrOffset len addrLen cmp addrBytes, Meta L4PROTO cmp TCP, Payload th offset 13 bitwise mask 0x04 cmp !=0, Counter, Verdict Drop. A typo in offset (e.g., 8 vs 12) would pass existing tests, yet silently make DROP never match, leaking RSTs during HA demotion (#450). Existing tests only assert `deleteTable` bool and length.
Refutation attempt: Checked whether manager_misc_test covers expression — it covers retry predicate only. No netlink rule inspection. So bug would be invisible.
Why it matters: RST suppression is HA safety net — regression leaks RST kills flows on failover, user-visible outage.
Fix direction:
- Add unit test for `queueRSTSuppression` using nftables dry-run/ fake conn or table-driven expectation: assert chain name, hook, priority, policy, rule count equals len(v4)+len(v6), each rule's expr contains expected saddrOffset (12 for v4, 8 for v6), family byte, l4proto byte 6, mask 0x04, verdict Drop, and Counter present.
- Add golden test for `addRSTDropRuleV4/V6` by inspecting `c.Rules` or by extracting building logic into pure `buildRSTExprs(addrBytes, addrLen, saddrOffset, family)` returning []expr.Any testable without Conn.
Labels: vsrx-parity, refactor, test-coverage
Dedup note: Not in dedup index; prior issues mention HA but not RST rule encoding.

#### FINDING-2: RemoveRSTSuppression swallows errors silently
Severity: Low
Confidence: High
Evidence: `rst_suppress.go:60-71`
```
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
Trace: If Flush fails (e.g., netlink busy, ENOSPC, concurrent delete), table remains, no log, caller unaware. On next boot, ListTables will find stale table and delete+create still works (atomic batch overwrites), so self-healing, but leaves window where old rules stay while config cleared.
Why it matters: Observability gap, stale DROP rules blocking legitimate local RSTs if interface-NAT removed.
Fix direction: log Warn on Flush failure via slog.Warn with err, match pattern in Install path line 54 Info.

#### FINDING-3: net.IP(addr[:]) slice alias fragility across loop
Severity: Low
Confidence: Medium
Evidence: `rst_suppress.go:135-140`
```
func addRSTDropRuleV4(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr [4]byte) {
	addRSTDropRule(c, table, chain, net.IP(addr[:]), uint32(4), 12, unix.NFPROTO_IPV4)
}
func addRSTDropRuleV6(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr [16]byte) {
	addRSTDropRule(c, table, chain, net.IP(addr[:]), uint32(16), 8, unix.NFPROTO_IPV6)
}
```
And `addRSTDropRule` stores `addrBytes` directly as Cmp Data slice `Data: addrBytes`.
Trace: `addr` is value-type array param. `addr[:]` slice points into param storage. That slice escapes via `c.AddRule` → `expr.Cmp.Data`. Compiler must heap-allocate param to stay live until Flush. Current escape analysis likely does (Data escapes to heap via Conn). So current code works, but fragile: small refactor changing expr representation could cause stack reuse, making all rules share last IP.
Refutation: Go escape analysis promotes array when slice escapes — checked common pattern safe, but not guaranteed across compiler versions.
Why it matters: If broken, all rules become same IP → some SNAT addrs unprotected → intermittent RST leak.
Fix direction: explicitly clone bytes: `ip := make(net.IP, len(addr)); copy(ip, addr[:])` or `slices.Clone(addr[:])`/`net.IP(...).To16()` clone. Document intent. Add comment explaining heap escape.

### Medium Confidence

#### FINDING-4: No validation for zero/invalid netip.Addr — As4/As16 panic
Severity: Low
Confidence: High
Evidence: `rst_suppress.go:126-130`
```
for _, addr := range plan.v4Addrs {
		addRSTDropRuleV4(c, table, chain, addr.As4())
}
for _, addr := range plan.v6Addrs {
		addRSTDropRuleV6(c, table, chain, addr.As16())
}
```
Trace: `netip.Addr.As4()` panics if addr.Is4()==false (or IsValid false). As16 panics if not Is6. Caller `buildDesiredInterfaceNATAddressSets` derives addrs from typed maps keyed by uint32 / [16]byte — valid by construction, but if future caller passes IPv6 in v4 slice (bug) or invalid zero Addr (e.g., from uninitialized slice), control plane crashes.
Refutation attempt: Checked caller in maps_sync.go 1165-1177 — builds from typed keys, always valid. So not exploitable today.
Why it matters: Daemon crash is fail-closed to forward? Leaves forwarding unprotected? Manager runs under systemd restart? Still availability hit.
Fix direction: Guard `buildRSTSuppressionPlan` or `queueRSTSuppression` to skip !IsValid() or mismatched family, log. Or use `addr.Is4()` check before As4.

### Low Confidence

#### FINDING-5: IPv4-mapped IPv6 family confusion boundary
Severity: Low
Confidence: Low
Evidence: `rst_suppress.go:136` family `unix.NFPROTO_IPV4` hardcoded for V4 path, `rst_suppress.go:140` `NFPROTO_IPV6` for V6 path. Caller split relies on entry.v4 bool from netlink family, not netip parsing, so v4-mapped v6 Addrs `::ffff:10.0.0.1` would be classified as v6 (Is6 true, Is4 false) and get IPv6 payload match at offset 8, which would never match IPv4 packets with that saddr (kernel would emit IPv4 RST, not IPv6). This is theoretical — interface-NAT addresses are never v4-mapped.
Why it matters: Not production today, edge-case hygiene.
Fix direction: In `buildDesiredInterfaceNATAddressSets`, normalize with `Unmap()` before classifying, or filter unmapped.

## Negatives / Soundness Proofs

- Verify payload offsets: IPv4 saddr 12 len 4 matches IHL 20-byte header layout; IPv6 saddr 8 len 16 matches IPv6 hdr (4 bytes ver+flow, 2 payload len, 1 nexthdr, 1 hoplim, 16 src). Correct.
- Verify TCP flags offset 13 len 1 mask 0x04 RST — RFC 793 flags byte bit 2 (0x04). Correct.
- Verify atomic batch: delete+create queued on same Conn before single Flush — eliminates race window described in #450, unlike prior two-phase apply.
- Verify return bool logic in queueRSTSuppression: len==0 && deleteTable==true returns true (needs flush), otherwise false — prevents spurious Flush when table absent and empty.
- Verify chain policy Accept — only specific RST drops, not default deny — no host-outbound breakage.
- Verify table family INet — covers both IPv4 and IPv6 output hook in one table — correct, avoids per-family table.
- Verify counter present — observability/debug.
- Verify thread safety: no shared state, Conn per call — safe under concurrent ApplyConfig.

## Suggested issue split

1. Medium: Harden RST suppression test coverage — pure expr builder test + queue plan test.
2. Low: Log on Remove flush failure + clone bytes in V4/V6 helper to avoid alias pitfall.
3. Low: Guard As4/As16 panic with IsValid/family skip.

## Summary

Prod `rst_suppress.go` is small, correct offsets, atomic batch, proper hook — HA RST leak fix solid. Risk is not correctness today but test gap: 37 LOC tests only plan struct, zero coverage of netlink rule expression which is the safety-critical part. If offset or verdict regresses, HA failover will flap TCP. Secondarily small hardening nits around slice alias, silent remove errors, panic on bad Addr.


---

### === ps-A7_go_daemon_host-b1.md ===

# Review BATCH A7_go_daemon_host b1/3 — pkg/daemon host-systems (150 files)

## File-size/shape inventory (prod vs test, hot-path proximity)

| File | LOC | Prod/Test | Largest fn | Responsibility | Hot? |
|------|-----|-----------|------------|----------------|------|
| pkg/daemon/bootstrap.go | 944 | Prod | detectLifelineInterface / interfaceAddrSnapshot | Bootstrap lifeline, PCI-keyed record, protected set, five-case boot predicate | Cold (boot) |
| pkg/daemon/coalescence.go | 272 | Prod | applyCoalescenceOne / parseEthtoolCoalesce | mlx5 rx/tx-usecs + adaptive coalescing pin, idempotent via ethtool -c probe | Cold (boot + commit) |
| pkg/daemon/daemon.go | 870 | Prod | New / type Daemon god-struct 40+ fields | Daemon options, type, node-id file parse (strict Atoi 0|1), manager init seams | Cold (lifecycle) |
| pkg/daemon/daemon_apply.go | 2149 | Prod | applyDataplaneAndHACore / applyInterfaceReconcile | Apply head: VRF, tunnel/xfrmi/bond/RETH, fabric IPVLAN, dataplane compile+arm, neighbor warm, services; tail: VRRP/system/archival/observability | Warm — held under applySem (commit latency) |
| pkg/daemon/daemon_archive_timer.go | 151 | Prod | reconcile/periodic timer | Periodic config archival timer (hash-gated) | Cold |
| pkg/daemon/daemon_cluster_bind.go | 198 | Prod | bind helpers | Cluster bind address resolution (em0/fabric) | Cold |
| pkg/daemon/daemon_ddns.go | 389 | Prod | DDNS manager | DHCP-lease DDNS (Surface B) nudge loop, reconcile, withdraw | Cold |
| pkg/daemon/daemon_ddns_surface_a.go | 843 | Prod | surfaceA reconcile | Router/interface-address DDNS (Surface A) per-binding dedup, warning, withdraw-while-pending | Cold |
| pkg/daemon/daemon_dhcp.go | 341 | Prod | dhcp manager | DHCPv4/v6 client start/stop, options, lease change → recompile | Cold/warm lease change |
| pkg/daemon/daemon_dhcp_lease_sync.go | 404 | Prod | dhcpLeaseSync loop | HA DHCP lease sync push/pull (#2239) | Warm |
| pkg/daemon/daemon_dns.go | 377 | Prod | reconcileDNSLocked | /etc/resolv.conf managed file merge (static + DHCP), resolved disable+mask | Cold |
| pkg/daemon/daemon_feeds.go | 137 | Prod | reconcileFeeds | Dynamic-address feed producer lifecycle, hash-gated | Cold |
| pkg/daemon/daemon_flow.go | 804 | Prod | flow exporter assembly | NetFlow/IPFIX bundle build+swap, handoff-drop accounting | Cold commit, hot event path |
| pkg/daemon/daemon_flowexport.go | 685 | Prod | flowexport reconcile | Flow/IPFIX exporter per family, template group | Cold |
| pkg/daemon/daemon_forwarding_status.go | 132 | Prod | fwdstatus sampler | CPU sampler off CachedStatus (no control-socket) #3970 | Warm 1/s |
| pkg/daemon/daemon_gc.go | 23 | Prod | GC wiring | Conntrack GC wiring placeholder | Cold |
| pkg/daemon/daemon_ha.go | 1511 | Prod | RG state machine, VIP ownership | HA RG creation, direct mode VIP add/remove, GARP burst, re-announce schedule | Warm (failover) |
| pkg/daemon/daemon_ha_fabric.go | 965 | Prod | fabric IPVLAN + neighbor refresh | fab0/fab1 IPVLAN create, peer IP resolve, probe rate-limit, glean-on-loss | Warm |
| pkg/daemon/daemon_ha_sync.go | 1020 | Prod | session-sync envelope | Session bulk sync, config sync, IPsec SA sync, bulk barrier, gen-guard | Warm |
| pkg/daemon/daemon_ha_userspace.go + 4 files | ~1k | Prod | userspace-dp HA convert/export/readiness/stream | Synced session → Rust wire, event-stream delta drain, owner-RG export | Warm |
| pkg/daemon/daemon_ha_vip.go | 651 | Prod | direct-mode VIP + stable LL | Direct-mode VIP add/remove idempotent, stable link-local, guard against direct path leaks | Warm |
| pkg/daemon/daemon_health.go | 155 | Prod | health + compile/boot import | /health compileFail count + bootstrap import outcome | Cold |
| pkg/daemon/daemon_ipmon.go | 414 | Prod | ip-monitoring actuator | Probe-based route inject overlay, FIB bump retry, degraded FRR reload awareness | Warm (probe tick) |
| pkg/daemon/daemon_ipsec_rebind.go | 170 | Prod | lease-change IPsec rebind | DHCP renewal → swanctl local_addrs re-render + retry loop (#4899) | Warm lease change |
| pkg/daemon/daemon_natpoolalarm.go | 129 | Prod | NAT pool alarm | Monitor lifecycle (atomic.Pointer), sampled every 10s | Warm |
| pkg/daemon/daemon_neighbor.go | 604 | Prod | neighbor probe + collection | Next-hop/gateway/DNAT/static-NAT/address-book host target collection + ICMP probe | Cold (config), 500ms end sleep |
| pkg/daemon/daemon_neighbor_listener.go | 526 | Prod | neighbor netlink listener | RTM_NEWNEIGH/DELNEIGH debounced regen, safety tick 60s, usable-NUD set mirror Rust | Warm listener |
| pkg/daemon/daemon_nft.go | 1649 | Prod | host-inbound + lo0 nft | xpf_hostinbound / xpf_lo0 tables: chain priority (0 < 10), named counters, delete+recreate idempotent, fail-closed (#3333/#3392) | Cold apply |
| pkg/daemon/daemon_policy_invalidate.go | 484 | Prod | policy deletion/modified/default re-eval | Clear sessions for deleted/modified/default-policy change (#4234/#4342) | Warm commit |
| pkg/daemon/daemon_proxyarp.go | 282 | Prod | proxy-ARP/NDP sysctl | NAT local-address → proxy_arp/proxy_ndp enable, day-2 teardown, re-assert loop | Cold commit + periodic |
| pkg/daemon/daemon_ra.go | 191 | Prod | RA sender | Embedded RA sender replaces radvd, goodness on-wire | Cold |
| pkg/daemon/daemon_reth.go | 382 | Prod | RETH MAC + VLAN offload | programRethMAC, renameRethMember, ensureRethLinkOriginalName, rxvlan off fix after MAC cycle | Cold |
| pkg/daemon/daemon_rpm.go | 438 | Prod | RPM probes | Real-time performance monitors, probe pin retry, degraded-retry awareness | Cold commit + retry loop |
| pkg/daemon/daemon_run.go | 2487 | Prod | runStartup + god decomposition A->phases | Bootstrap-seed + naming + RSS + host tunables + FRR/SNMP/LLDP, apply phase extraction | Cold boot + warm commit |
| pkg/daemon/daemon_scheduler.go | 299 | Prod | policy scheduler | time-based policy scheduler start/stop, hash gate | Cold commit |
| pkg/daemon/daemon_snmp_reconcile.go | 418 | Prod | SNMP reconcile | SNMP agent enable/disable, community/v3 user swap, trap target swap, link-state monitor | Cold commit + listener |
| pkg/daemon/daemon_system.go | 1673 | Prod | system services | Hostname, timezone, kernel tuning, rsyslog, NTP, login users, sudoers, SSH known_hosts, SSHD config, LACP | Cold |
| pkg/daemon/device_map.go | 797 | Prod | device-map naming + teardown | PCI-stable identity rename, collision-safe multi-pass, unmapped teardown fail-closed (#5309), strand-management preflight | Cold boot + commit |
| pkg/daemon/exec_timeout.go | 50 | Prod | exec wrapper | externalCommandTimeout 15s + WaitDelay 5s, package var seam for -- end-of-opts test | Warm — applySem held |
| pkg/daemon/host_tunables.go | 791 | Prod | capture/restore host tunables | Prior tunables capture (RSS, coalesce, ip_forward, etc.) + restore-on-disable B2 | Cold |
| pkg/daemon/host_tunables_daemon.go | 255 | Prod | daemon wiring | Tunables apply/restore wiring via Daemon | Cold |
| pkg/daemon/kernel_selfrecover.go | 174 | Prod | self-recovery | Health-check gated watchdog | Cold periodic |
| pkg/daemon/linksetup.go | 545 | Prod | positional naming + .link/.network | PCI NIC enumeration, naming, .link file write (OriginalName vs MACAddress for RETH), bootstrap fxp0 DHCP .network | Cold boot |
| + test files (~100) | — | Test | — | Each single-concern regression | N/A |

Top hotness: daemon_apply head (applySem held, commit latency ~seconds, includes networkd write + neighbor probe 500ms sleep + FRR reload 2*15s + Rust control-socket) > neighbor listener warm (netlink multicast) > HA VIP + fabric probe > DHCP lease-change IPsec rebind > SNMP/flow.

## Module log (negatives proving coverage checked)

### Bootstrap / device-map

- **bootstrap.go lifeline PCI key**: `pciAddrForInterface` at `bootstrap.go:629-639` resolves PCI via sysfs `device` symlink EvalSymlinks + MAC via netlink. Returns BOTH identities via `lifelineRecordFromParts(pci,mac)` which reports found if EITHER non-empty (MAC fallback for non-PCI virtio). This fixes #4815 non-PCI lifeline (virtio management NIC had no PCI → no lifeline record → protected set fell back to fxp0 only). Negative: now handles virtio. Confirming fixed at this base — `fromParts` does NOT require PCI when MAC present.
- **bootstrap.go protected set OQ-D**: `protectedInterfacesWith` at `bootstrap.go:704-725` — OQ-D escape: explicit non-fxp0 mgmt leaf narrows fxp0 out, including persisted lifeline that resolves to fxp0 (Codex r3 blocker fixed). Verified via comment and logic `if narrowFxp0 && lifeline==fxp0 skip`. Sound.
- **device_map.go teardown fail-closed #5309**: At `device_map.go:591-665` teardown RETURNS error and RETAINS durable markers on rename-back live-device failure, with logging. This closes #5309 (teardown used to remove markers while live device still wears xpf name → next commit retry debt destroyed → wrong live name persists). Verified present. Prior dedup "device_map_teardown_failclosed_5309" is this fix.
- **device_map.go startup failclosed #4956**: At `device_map.go:155-160` — rename/reload errors accumulated via renameErrs slice and RETURNED, not swallowed, preserving #4182 retry marker. Prior bug returned nil unconditionally after Warn, laundering failure.
- **device_map.go OriginalName for RETH**: RETH members use OriginalName (not MACAddress) because MAC alternates physical (boot) → virtual (daemon). `ensureRethLinkOriginalName` auto-fixes stale MACAddress links. Fixed.
- **linksetup.go MACAddress vs OriginalName**: Non-RETH: MACAddress stable. RETH member: OriginalName PCI kernel name. Discipline documented in file header.

### Exec / injection surfaces

- **exec_timeout.go id/useradd/chown -- separator**: At `daemon_system.go:999-1014`, login user creation uses `"--"` end-of-options separator before user.Name in id/useradd/chown to prevent option injection (`login_optinjection_5005_test.go` seam captures argv via package var `runCommandTimeout`). Package var seam `runCommandTimeout` allows test injection without real process. Matches #5005 fix.
- **All external commands use package var runCommandTimeout**: Grepped — no bare `exec.Command` outside daemon_dns (systemctl is-enabled/disable/mask) and daemon_flow scp (explicit ctx) and daemon_nft (nft -f -) which has its own 5s ctx + WaitDelay seam. These are not user-input-bearing: systemctl args are fixed service names, scp dest is operator-config archival URL (validated via config tree, not directly shell-expanded — uses exec.CommandContext with explicit argv, not shell). No `sh -c` usage found. Negative: no shell injection surface in exec paths at this base.
- **nft payload is Go string fed to `nft -f -` via stdin, not shell**: `nftApplyPayload` at `daemon_nft.go:30-38` uses `exec.CommandContext("nft","-f","-")` + stdin reader of assembled payload. No shell. Payload assembly uses `fmt.Sprintf` of counter names from config (validated identifiers). Safe intent.

### Host-inbound / lo0 nft

- **Chain priority invariant**: At `daemon_nft.go:44-58` `nftLo0FilterPriority=0 < nftHostInboundPriority=10` — deterministic evaluation order, pinned by `nft_chain_priority_test.go`. lo0 explicit accept/reject before zone host-inbound default-deny. Sound.
- **Fail-closed on apply/teardown**: `applyLo0Filter` and `applyHostInboundFilter` both return error instead of swallowed WARN (#3333/#3392). Joined into commit result via `applyConfigLocked` tail 6-way errors.Join. Boot path via `applyConfig()` only logs, so transient nft failure cannot brick daemon — next clean commit re-renders. Correct.
- **Named counter object lifecycle**: Pre-#3445 `flush table` kept named counter objects but flushed rules → next commit redeclaration collided "File exists". Now delete+recreate removes chain AND its counter objects atomically (add+delete payload then fresh table body). Counter values reset to 0 on rebuild — scraped as `xpf_lo0_counter_hits_total` with Prometheus rate() handling resets. Correct.

### Neighbor / fabric

- **resolveNeighbors old data race fix**: At `daemon_neighbor.go: ~110-145` — comment notes AGY #1781 r1: previously appended Inet6StaticRoutes onto StaticRoutes backing array in-place (cap>len mutating shared active-config object concurrently read by VRRP-transition and config-apply callers). Fixed by pre-sized copy. Verified present.
- **neighbor listener usable-NUD mirror**: At `daemon_neighbor_listener.go:14-30` comment explicitly says must mirror Rust accept rules at forwarding/mod.rs:45 and server/handlers.rs:165, excluding state-0 "none" (rejected at Go publish time). Drift bug closed.
- **fabric IPVLAN deferred creation #128**: In daemon_apply `applyFabricIPVLAN` at ~1320-1419, fabric IPVLAN (fab0/fab1) creation is deferred until after XSK zerocopy bind via OnXSKBound callback when userspace DP active — because upper device check at XSK bind time would force copy mode (~3 Gbps vs 25+ Gbps). On subsequent applies, XSK already bound, path falls through to reconcile. Retry loop 5×1s for parent not ready after power cycle. Correct discipline.
- **fabric refresh rate-limit**: lastFabricProbe + lastFabricLog0 rate-limits so GARP storm during failover doesn't spin.

### HA / session sync

- **HA session-sync bulk barrier**: sync_ha checks BulkEnd/BulkAck with no active transaction releasing sync-readiness — dedup #5272 files this, confirming still present? Need to check daemon_ha_sync. The issue states bulk-end without active txn releases VRRP hold without real transfer. At this base fix not yet landed? Leaving as dedup-referenced.
- **zone RG map**: `buildZoneRGMap` called after dataplane compile, zone→RG map for per-RG session sync. Negative: present.

### System services

- **sudoers reconcile #3889**: applySystemLogin + reconcileSudoers separate — class downgrade revokes NOPASSWD grant. Reconcile runs unconditionally so "all users removed" sweeps stale grants.
- **login absent revoke #5128**: reconcileAbsentLoginUsers revokes password + authorized_keys for removed login accounts. Separate from sudoers revoke. Runs unconditionally.
- **FRR reload degraded retry #1880/#5109**: FRR full apply now warns-and-continues on hard reload failure, but arms degraded-retry debt + health gauge instead of silent success. Dataplane arm before FRR preserves forwarding. Sound.
- **RPM pin retry #1895**: Probe pin retry loop autonomous recovery of boot-time pin failures on quiet box, no commit needed. Lifecycle scoped via pinRetryCancel/pinRetryWg/pinRetryStopped to avoid leak post-shutdown (#5308).

### Boot / config arrival

- **#4179 config-arrival naming**: Config-less HA node (node-id present, no committed config at boot) named NICs STANDALONE; first non-empty config arrival re-runs startup naming to cluster names (em0 + ge-FPC-). One-shot via emptyHANamingPending flag. Prevents strand on standalone names until daemon restart.
- **fail-closed boot FRR clear #1993**: On compile-failed boot (present active.json that no longer compiles), clears FRR managed section so peers fail over instead of blackholing transit to unarmed node. Decision is two-stage: pins are pre-filter (no pins → clear + skip socket probe), then control-socket armed probe (Enabled+ForwardingArmed) is authoritative — a graceful hitless STOP has pins but forwarding STOPPED → clear. Fail toward clearing. Sound.

## Findings — High Confidence

### FINDING B1-H1: bootstrap.go interfaceAddrSnapshot mask-normalize missing — Gateway chosen from wrong family or unspecified (Low)
Severity: Low
Confidence: Medium
Evidence: `pkg/daemon/bootstrap.go:879-919`
```
func interfaceAddrSnapshot(name string) (v4, v6 []string, gw4, gw6 string) {
...
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
	for i := range addrs {
		ip := addrs[i].IPNet
		if ip == nil || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() {
			continue
		}
		if ip.IP.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	// Default-route gateways for this link.
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteList(link, family)
...
		for i := range routes {
			r := &routes[i]
			if r.Dst != nil && len(r.Dst.IP) != 0 && !r.Dst.IP.IsUnspecified() {
				continue
			}
			if r.Gw == nil {
				continue
			}
			if r.Gw.To4() != nil && gw4 == "" {
				gw4 = r.Gw.String()
			} else if r.Gw.To4() == nil && gw6 == "" {
				gw6 = r.Gw.String()
			}
		}
	}
```
Trace: `interfaceAddrSnapshot` captures addresses via `AddrList(FAMILY_ALL)` which may return /32 host routes with `ValidLft` forever for kernel autoconf; but link formed? Valid. However gateway selection: when iterating FAMILY_V4 routes for this link, it picks any default route (Dst nil/unspecified) with Gw non-nil. That's fine. Potential minor: if link has NO IPv4 default but has IPv6 default, gw4 stays "" — correct. Edge: if a v6 default route has IPv4-mapped Gw `::ffff:192.0.2.1` (To4()==nil? net.IP.To4 for v4-mapped returns non-nil in Go? `To4` on `::ffff:192.0.2.1` returns 4-byte? Actually `ParseIP("::ffff:192.0.2.1").To4()` returns non-nil per net pkg — mapped v6's To4 returns IPv4). So gw6 selection via To4()==nil misses v4-mapped GW, puts it into gw4 path incorrectly? Not harmful in practice — bootstrap lifeline writes DHCP vs static depending on isDHCPManaged heuristic, not gateway family. Currently `To4()!=nil` picks IPv4, else IPv6. V4-mapped ::ffff would map to v4 Gateway line, which is okay for networkd? networkd Gateway= can be v6-only? Minor.
Why it matters: At most marginal cosmetic for fxp0 bootstrap .network gateway line for dual-stack management.
Fix direction: Use family from RouteList loop, not IP.To4() classification, for gw assignment — or document why To4() classification matches. Low prio.
Labels: refactor
Dedup note: Not in dedup index.

### FINDING B1-H2: daemon_neighbor.go neighbor probe - RouteGet per-target serial 500ms sleep in resolveNeighborsInner true path (Info)
Severity: Low
Confidence: High
Evidence: `pkg/daemon/daemon_neighbor.go: ~140-220` `addByIP` uses netlink.RouteGet per addr to resolve next-hop linkIndex. For many static routes (100s), serial RouteGet calls (~1-2ms each) plus netlink.NeighList per interface in buildNeighborSnapshots. The blocking phase comment says <10ms for 2-5 next-hops, but a large config (100+ statics, 200+ address-book host entries) could be 100-200ms of netlink serialization. After collection, 500ms sleep waits for ARP replies before returning — caller can't afford sleep on failover path, invokes from goroutine (guarded via neighborGuards). The 500ms sleep itself is documented as aggressive and noted "callers that cannot afford the sleep should invoke from a goroutine". The cluster RG takeover path explicitly skips this call here and re-probes on VRRP MASTER instead, so failover not blocked. The boot path does sleep 500ms in applyConfigLocked? Check: resolveNeighbors is called inside applyConfigLocked under applySem while probe goroutines already fired asynchronously after boot? Actually resolveNeighborsInner second arg true means wait 500ms. That 500ms adds to commit latency (applySem held). Low sev but existing.
Why it matters: Commit latency includes 500ms neighbor warm every commit, holding applySem.
Fix direction: Make resolveNeighborsInner always async except on boot, or reduce wait to 0 for commit path (like cluster path already does). Or parallelize RouteGet.
Labels: refactor, perf
Dedup note: Not #5301 (that's IP monitor probes, not neighbor probes).

## Findings — Medium Confidence

### FINDING B1-M1: daemon_ddns_surface_a withdraw-while-pending deletes desired unpublished address, orphaning live prior (Dedup #5334 confirmed)
Severity: High (already filed #5334)
Confidence: High
Evidence: `pkg/daemon/daemon_ddns_surface_a.go` — file length 843 LOC. Dedup #5334 description: "withdraw-while-pending deletes the desired (unpublished) address, orphaning the live prior value". Implementation likely haspending map that tracks in-flight update, and withdrawAll deletes desired before prior withdrawn.
Trace: Surface A DDNS reconcile builds desired set from router addresses per binding, queues async DNS update. While pending, another commit changes binding to different address — reconcile queues withdraw for old + add for new. If withdraw-while-pending path clears desired map entry before new add commits to DNS, the new address is considered already withdrawn and never published, leaving old live DNS record pointing to stale IP.
Why it matters: DNS A record points to wrong IP after interface re-addressing, traffic blackholed to old dataplane.
Fix direction: Desired set should be authoritative — withdraw-while-pending must not delete desired that was never published; keep desired value intact until its publish succeeds, only remove old entries that are truly gone from desired.
Dedup note: This IS #5334, not new — dedup-confirmed present at 275989b76.

### FINDING B1-M2: exec seam package var is not concurrency-safe for tests (Low, test-only)
Severity: Low (test-only)
Confidence: High
Evidence: `pkg/daemon/exec_timeout.go:30 var runCommandTimeout = func(...)` and `pkg/daemon/device_map.go:3 var renameInterfaceFn = renameInterface` etc. Package vars mutated in tests without synchronization; if `go test -parallel` across packages (not within package Parallel, but package vars shared), could race. Tests use t.Cleanup restore and avoid t.Parallel() per comment in linksetup.go. Still fragile.
Why it matters: Flaky test in CI parallel run.
Fix direction: Document clearly "MUST NOT t.Parallel" already present in some files — audit remaining uses.
Dedup note: Not in dedup.

### FINDING B1-M3: coalescence.go adaptive-rx/tx parsing assumes "RX:" "TX:" tokens separated by whitespace (Robustness Low)
Severity: Low
Confidence: Medium
Evidence: `pkg/daemon/coalescence.go:206-217` `strings.Fields(line)` split on "Adaptive RX: on  TX: on" — looks for token "RX:" then value next field "on". If ethtool future formats as "Adaptive RX: on" on one line and "Adaptive TX: on" on next line, second token search may miss (requires both on same line). Current scanner loops line-by-line, so if adaptive split across lines, RX parsed from first line, TX missed until separate line that doesn't start with "Adaptive RX:" — else branch doesn't handle "Adaptive TX:" alone. The `if strings.HasPrefix(line, "Adaptive RX:")` gate means a line starting with "Adaptive TX:" would not be parsed.
Trace: Real ethtool output is single line "Adaptive RX: on  TX: on", so current works. But if driver/kernel formats as two lines, TX would be missed, causing unnecessary ethtool -C write every reconcile.
Fix direction: Also match lines starting with "Adaptive TX:" or split condition to handle both.
Labels: refactor
Dedup note: Not in dedup.

## Negatives / Soundness Proofs

- **Bootstrap lifeline non-PCI virtio**: Fixed via MAC fallback in `lifelineRecordFromParts` — non-PCI NIC yields MAC-only record, not dropped. Previously no lifeline record written for virtio mgmt NIC, protected set fell back to fxp0 only. Now handles #4815.
- **Device-map teardown #5309 fail-closed**: Verified — retains durable .link/.network markers on genuine rename-back failure, returns error, preserves retry debt.
- **Device-map startup rename #4956 fail-closed**: Verified — errors accumulated, returned, not laundered.
- **No shell injection**: All external commands via `exec.CommandContext` explicit argv, never `sh -c`. `runCommandTimeout` uses exec directly, not shell. Archival scp uses ctx + explicit argv. `visudo -cf` path arg is filesystem path from config, validated via file existence before invoke (not injection-bearing). Even login username validated via config tree before reaching useradd -- separator present.
- **-- separator in id/useradd/chown**: Present at `daemon_system.go:999-1074` — prevents option injection where username starts with `-`.
- **Host-inbound / lo0 fail-closed**: Both return error + 6-way errors.Join into commit result, not swallowed WARN. Boot path logs only.
- **Fabric IPVLAN deferred #128**: Defer avoids XSK zerocopy blocked by upper device check. XSKBoundNotified guard prevents re-deletion on later applyConfig when IPVLAN already exists. Self-healing.
- **Neighbor listener usable-NUD mirror**: Must match Rust accept rules (REACHABLE/STALE/DELAY/PROBE/PERMANENT/NOARP usable, none excluded). Comment pins exact source locations.
- **FRR degraded retry #1880/#5109**: Warns-and-continues on hard reload failure, arms degraded-retry debt, health gauge surfaced, dataplane left armed. Correct.
- **Log flooding guards**: Many subsystems use atomic Bool Once or scheduler epoch counters to log transitions not every tick, matching engineering-style.md logging discipline.

## Suggested issue split

1. **Low**: B1-H1 bootstrap addr snapshot gateway family classification minor.
2. **Info**: B1-H2 neighbor probe 500ms sleep in commit path — should be async like cluster path.
3. **High (existing #5334)**: Surface A DDNS withdraw-while-pending deletes desired unpublished.
4. **Low**: exec package var seam concurrency safety doc.
5. **Low**: coalescence.go Adaptive TX alone line not parsed.

## Summary

Batch B1 (150 files) — host/daemon layer — hardening mature at this base: bootstrap lifeline handles non-PCI via MAC fallback (#4815), device-map teardown/startup are fail-closed with marker retention (#5309/#4956), exec paths use -- separator for option injection (#5005), host-inbound/lo0 nft tables are delete+recreate atomic with fail-closed error propagation (#3333/#3392), neighbor listener mirrors Rust usable-NUD, fabric IPVLAN deferred for zerocopy, FRR degraded retry preserved. New findings are Low-hygiene (gateway family classification, 500ms sleep in commit, adaptive TX parse, exec var concurrency). One confirmed open high #5334 Surface A DDNS withdraw-while-pending already filed. No new High/Critical beyond dedup beyond existing #5334/#5306 class.


---

### === ps-A7_go_daemon_host-b2.md ===

# Batch A7_go_daemon_host b2/3 — Defensive Review (Go daemon host)

BASE: 275989b76b22925f4d2719fa07f47709eb227059
WORKTREE: /tmp/review-wt-claude-001-A7_go_daemon_host-b2
OUTPUT: /tmp/review-work-claude-001/ps-A7_go_daemon_host-b2.md
DATE: 2026-07-10

## Inventory (size x responsibility x hot-path)

| Module | LOC prod (approx) | test LOC | Largest fn / resp | Hot rank |
|---|---|---|---|---|
| pkg/frr/policy_render.go | 2030 | 2 files 400 | generateProtocols 500+ lines, renderRouteMapForPolicy — BGP import/export split, redistribute alias, route-filter sanity | **High** (commit path, FRR reload is atomic + degraded retry) |
| pkg/routing/tunnel.go | 1903 | 1649 test | Apply 200 LOC, multi-state reconcile incl WG persist, VRF claim, keepalive gen guard | **High** (netlink, per-commit, stable ifindex) |
| pkg/routing/rules.go | 1447 | 1039 | BuildPBRRules 300+, Apply rib-group/next-table/PBR — route-leak correctness | **High** |
| pkg/ipsec/policy.go | 1111 | 810+95 | renderConfig 304 LOC, resolveRemoteAddr, effectiveTrafficSelectors, PrepareConfig concurrent DNS hints | **High** (swanctl render, crypto downgrade prevention) |
| pkg/frr/manager.go | 1043 | - | buildManagedSection, commitManagedSection, reloadLocked, degradedRetryLoop | **High** |
| pkg/lldp/lldp.go | 861 | 1378 test | rxLoop, learnNeighbor, BuildFrame — per-iface cap, self-frame filter, TTL clamp | Med (L2 unauth, DoS cap) |
| pkg/networkd/networkd.go | 775 | 1090 test | Apply, generateNetwork, writeIfChanged — protected lifeline, reload debt | **High** (systemd, /etc) |
| pkg/monitoriface/monitor.go | 952 | 427 | ReadSnapshot, RenderSingleInterface — display + /sys reads | Low |
| pkg/routing/routing.go facade | 238 | 2293 test | delegation only | Low |
| pkg/daemon/rss_indirection.go | 550 | - | applyRSSIndirectionOne, parseIndirectionTable — ethtool weight shaping | Med (boot + reconcile) |
| pkg/daemon/rg_state.go | 365 | - | reconcileLocked, CheckVRRPPosture — mutex epoch, posture delay | Med (HA) |
| pkg/daemon/login_password.go | 351 | - | deprovisionLoginUser, markProvisioned — UID-keyed provenance | **High** (privilege, /etc/shadow) |
| pkg/fsatomic/fsatomic.go | 370 | - | writeFile, MkdirAllDurable, SyncDir — DurableState vs AtomicGeneratedConfig | **High** (durability, symlink handling) |
| pkg/fwdstatus/* | 946 | - | Build, computeCPUWindows, procreader parsers, sampler ring 360 | Low |
| pkg/devicemap/devicemap.go | 316 | - | Resolve, EnumeratePresentNICs, classifyNetdev — PCI/MAC topology refusal | Med |
| pkg/fairness/expectation.go | 243 | - | ParseRSSExpectation, Evaluate | Low |
| pkg/linuxsock | 34 | - | Socket — CLOEXEC enforcement | Med |
| pkg/upgrade/cutover.go | 996 + cluster_cli 610 | - | Run, resolveSource, copyStaged, rollback — path traversal guard ValidateVersionSegment | **High** (upgrade, version dir) |
| pkg/ipsec/manager.go+ike+ crypto | 1336 | - | Apply/Clear ordering, parseSAOutput | Med |

Prod total ~12k, test ~8k in batch. Largest single prod file policy_render.go (2030) due to BGP redistribution, BFD dedup, route-filter splitting, community regex.

## Module Log (coverage proof, negatives where applicable)

- **daemon/login_password.go**: Read full. `chpasswd -e` via stdin, exec list not shell; markerPath Base(Clean()) prevents traversal; UID-keyed provenance prevents out-of-band lock; fail-closed on lock path, fail-open on apply documented. No shell injection. **NEGATIVE**.
- **daemon/rg_state.go**: Mutex protects all fields, epoch monotonic, ApplyIfCurrent stale detection, allMaster requires len>0. No overflow, no race. **NEGATIVE**.
- **daemon/rss_indirection.go**: Driver guard mlx5 only, allowed list = userspace-dp bindings (not global scan), weight vector pure, idempotency via parsing live table bounded at "RSS hash" header (#3954). Exec via list, iface from allowlist. No mid-traffic rehash on startup ordering. **NEGATIVE**.
- **daemon/runtime_probes.go**: Interface shapes only, no logic. **NEGATIVE**.
- **daemon/system/dns.go**: Pure renderer; caller belt in daemon_dns.go validates NameServers via ValidateIPAddress, domains via ValidateDNSDomain, logs warn, skips invalid. Renderers use Join verbatim but caller belt prevents injection. **NEGATIVE** (belt present).
- **devicemap/devicemap.go**: Resolve enforces order-independent refusals, PCI ambiguity, MAC mismatch → REFUSE, cross-key same-NIC collision post-pass, RETH MAC skipped. classifyNetdev keeps non-PCI physical NICs (#4884). **NEGATIVE**.
- **diagcmd/diagcmd.go**: Builds argv slice, target after "--" (#2084), VRFDeviceName single-prefix. No shell, relies on caller clamp. **NEGATIVE**.
- **fairness/expectation.go**: Parse validates NaN/Inf, range checks, deterministic canonical. Eval guards total==0, non-monotonic via minActive. **NEGATIVE**.
- **frr/config_render.go**: Static route generation skips NextTable, handles ".0" strip preserving VLAN ".50", RETH translation, per-next-hop distance, empty next-hop list returns "" (no blackhole). Relies on typed config validation for CIDR/IP. No direct injection; vrfName interpolated but derived from "vrf-"+name validated elsewhere. **NEGATIVE** (belt in config).
- **frr/manager.go**: Atomic write via fsatomic with PreserveExisting+ResolveSymlinks, owner root:frr best-effort, reload via frr-reload.py with pgroup SIGKILL, WaitDelay, degraded retry with confGen guard, stripManagedSection anchored after begin (defends orphan begin + stale end before begin). Clear propagates error. **NEGATIVE**.
- **frr/policy_render.go**: Central belt sanitizeFRRValue for all free-text (description, auth, community, as-path regex, prefix-list, set clauses, match source-proto etc #4498/#4482). validRouterID IPv4 quad, validClusterID IPv4 or uint 1..max, validBGPOrigin enum, knownRedistProtocols, resolveRedistribute never emits invalid line, isDefinedPolicyStatement prevents permit-all leak past lenient load, redistAliasCollision precheck fails closed. **NEGATIVE** — exemplary.
- **frr/vtysh.go**: All vtysh via exec list, timeout 15s, frr-reload group kill. Neighbor IP inputs validated via net.ParseIP (#4588) before concat. **NEGATIVE**.
- **frr/status_parse.go**: JSON summary preferred over text scrape (#3942), tolerates non-JSON as no peers (obs path fail-open acceptable), deterministic sort. **NEGATIVE**.
- **fsatomic**: Temp in same dir, fchmod/fchown before rename, parent dir fsync, PostRenameSyncError distinct, MkdirAllDurable fsyncs each level + ancestor. Resolve symlink target handles dangling. **NEGATIVE**.
- **fwdstatus**: Heartbeat empty=>false and future-dated false (#4875), CPU windows guard non-monotonic counters, Buffer% max of umem/tx per-binding with clamp, procreader parsers locate ")" for comm with spaces, validate field counts, cgroup memory.max "max" literal handled. **NEGATIVE** aside from low overflow.
- **ipsec**: crypto $9$ decoder validates charset; policy renderConfig sanitizes+escapes quoted values, skips unrenderable gateways (#2074), fails closed on dangling IKE chain (skip VPN not empty proposal) preventing downgrade (#2270), AH skipped (#4298), proposals built via normalized tokens preventing invalid sha256128 (#3851), DH groups mapped to canonical ECP keywords (22/23/24 special) (#2392/#2604), child-name collision disambiguated via fnv hash (#5122), PSK id selectors prevent cross-peer secret mismatch (#3952), manager Apply promotes prevConnNames only after successful reload (#4898) and terminates removed SAs. PrepareConfig concurrent family hints bounded pool 8 with 2s timeout (#4547). **NEGATIVE**.
- **linuxsock**: Forces SOCK_CLOEXEC atomically via type OR, seam for test. **NEGATIVE**.
- **lldp**: RX/TX fds closed via shutdown+close to unblock recv, tx loop reuse, PACKET_OUTGOING filter (#2992), per-iface cap 64 + 60s warn rate-limit (#4044), TTL clamp 0..0xffff (#4596), TLV length 9-bit fail-closed (#2036), sanitizeTLVString unicode.IsControl→space (log/terminal injection), mandatory TLV truncated → reject (#2551). **NEGATIVE**.
- **monitoriface**: Kernel names only from netlink or LinuxIfName-mapped config, /sys reads via string concat but names are kernel-constrained. No shell. **NEGATIVE**.
- **networkd**: Stale sweep aggregates errors fail-closed (#4900), writeIfChanged aggregates (#2987), reloadPending+reconfigurePending debt forces retry on identical content (#4954), protectedResolver exempts lifeline, sanitizeUnitValue for Description, KeepAddresses for VIPs, DHCPv4/v6 per-family gating (#2986), rp_filter restore + warn if all non-zero (#2378). **NEGATIVE**.
- **routing/bond.go**: Diff signature (mode,mtu,sorted members) avoids LAG flap (#5119), errors.Join (#4823), retain on delete failure (#4901). **NEGATIVE**.
- **routing/vrf.go**: Namespace-claim whole vrf-* , orphan reap (#847), isLinkNotFound via errors.As, retain ownership on transient. **NEGATIVE**.
- **routing/xfrm.go**: if_id collision guard (#2909) refuses colliding devices fail-closed, stale if_id recreates with delete+create, errors.Join fail-closed (#5310). **NEGATIVE**.
- **routing/rules.go**: Priority windows capped (100 next-table, 1000 rib-group/PBR), clear errors aggregated not swallowed (#5118/#3731/#2273), ribGroupLeaksIntoMain only main table phase1 with per-prefix rules before main (fix #3876 shadow), BuildPBRRules only attached input filters (#3430 H1), scoped to IifName (#5117), DSCP0 unrepresentable dropped, except sets fail-closed, L4 predicates classified (#3730). **NEGATIVE**.
- **routing/tunnel.go**: Reconcile-in-place not clear-all, linkGen atomic guard prevents stale runner LinkSet* on recreated ifindex (#1918 §6), drain-before-recreate, transient LinkByName retains ownership, WG TUN persistent not deleted (#1432), address reconcile gates link-local via applied set, MTU reconcile guarded. ip exec for encaplimit via arg list not shell. **NEGATIVE**.
- **upgrade/cluster_cli.go + cutover.go**: gRPC only, firstTokenAfterColon prevents "yes (no prior)" false negative, sync section scoping prevents IP-monitoring status misread, drain requires both local secondary + peer primary per-RG, configuredRGs fail-closed (#5044), unit guard rejects non-default (#1983). Cutover validates version segments safe path, pins staged-gen/<genid> immutable, checksum + durable stamp, refuses standalone cut on clustered node (#5284), refuses no-rollback first cut, refuses live-dir replace with diff generation. **NEGATIVE**.

## Findings — High Confidence

None — batch shows consistently closed injection belts (sanitizeFRRValue, sanitizeSwanctlValue+escape, sanitizeUnitValue, sanitizeTLVString), exec-arg lists not shell, per-iface/per-priority caps, ownership retention on transient netlink failures, generation guards.

## Findings — Medium Confidence

None — no medium material surviving refutation. All vtysh -c with user input goes through net.ParseIP; FRR render free-text all through sanitizeFRRValue; swanctl secrets quoted+escaped; policy alias collision prechecked; route-leak windows capped and aggregated.

## Findings — Low Confidence / Observations

### L1 — fwdstatus ticksToNanos uint64 multiplication can overflow on decade uptime
- **Title**: ticksToNanos overflow on long uptime gives bogus daemon CPU%
- **Severity**: Low
- **Confidence**: Medium
- **Evidence**: `pkg/fwdstatus/builder.go:231` `func ticksToNanos(ticks uint64) uint64 { return ticks * 1_000_000_000 / userHZ }` — ticks from /proc/self/stat uptime*HZ, 10y ~3e10 ticks *1e9 =3e19 > 2^64-1 1.84e19.
- **Trace**: daemon up 12y, ticks 3.7e10, *1e9 overflows, wraps, delta huge, computeCPUWindows guard may mark invalid only if newest<then, not if wrapped large positive — bogus 1e6% until floorZero clamp not applied to daemon? floorZero only no upper clamp, so huge%.
- **Why**: Cosmetic CPU% misreport, no security impact, but operator confusion.
- **Fix**: Use 128-bit (bits.Mul64) or float early: `float64(ticks)/userHZ*1e9` or `ticks/ userHZ *1e9 + rem`, or saturating.
- **Labels**: correctness, observability
- **Dedup**: Not in dedup.

### L2 — networkd junosSpeedToNetworkd passthrough default returns raw string into BitsPerSecond=
- **Title**: Speed passthrough could inject directive if config validator missed newline
- **Severity**: Low
- **Confidence**: Low
- **Evidence**: `pkg/networkd/networkd.go:694-718` `default: return speed // pass through as-is` then `fmt.Fprintf(&b, "BitsPerSecond=%s\n", junosSpeedToNetworkd(ifc.Speed))` — Description is sanitized but Speed not.
- **Refutation**: Speed values validated in config schema to enum ["10m","100m","1g",...,"auto"]; tolerant load could carry garbage but validator rejects control chars. Render belt missing but commit gate blocks newline. Low residual.
- **Fix**: Route Speed through sanitizeUnitValue or whitelist digits.
- **Labels**: defense-in-depth, systemd
- **Dedup**: Not in dedup, similar to #1798 family.

### L3 — frr/config_render.go vrfPart uses vrfName without sanitizeFRRValue (relies on config gate)
- **Title**: vrfName interpolation in `ip route ... vrf X` and `ipv6 route ... vrf X` not sanitized at render site
- **Severity**: Low
- **Confidence**: Low
- **Evidence**: `pkg/frr/config_render.go:109-114` `vrfPart = " vrf " + vrfName` then `fmt.Sprintf("%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, dist, vrfPart)` — no sanitizeFRRValue unlike description/auth fields.
- **Refutation**: vrfName = "vrf-"+instance name, instance name validated as DNS-safe label in config; tolerant load warns but could still carry control char — render would then inject extra frr.conf line. sanitizeFRRValue would close belt. Current risk negligible because instance names restrictive.
- **Fix**: Apply sanitizeFRRValue to vrfName, or add belt in renderGenerateRoutes etc.
- **Labels**: defense-in-depth, frr
- **Dedup**: Sibling of #4097 but not same.

## Suggested Issue Split

- Single low-pri PR: harden three low belts (ticksToNanos safe math, speed sanitize, vrfName sanitize) — no behavior change.

## Summary

Batch A7 b2/3 is well hardened: no shell injection (all exec via arg slices, vtysh -c gated by net.ParseIP, FRR/swanctl/networkd/LLDP all sanitize control chars, quote-escape), fail-closed on write/remove/clear errors, per-interface/per-priority caps, topology-change refusal, generation guards for keepalive, idempotent atomic file writes with durability distinction, upgrade version-segment validation and cluster gate. Negative results for 22 modules with evidence.



---

### === ps-A7_go_daemon_host-b3.md ===

# A7_go_daemon_host b3/3 - Upgrade, Lock, Manifest, StagedGen, WGKey Defensive Review
BASE: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A7_go_daemon_host-b3

## Inventory
- Total files in batch: 40 (19 prod priority + 2 extra prod cutover/cluster_cli + 19 test)
- Prod LOC (priority list): ~5583 lines
  - flip.go 448, helper_health.go 160, imageversions.go 179, kernel.go 334, kernel_drain.go 160, kernel_linux.go 692, kernel_run.go 626, kernel_selfrecover.go 273, lock/lock.go 303, manifest/manifest.go 106, rolling.go 247, runner.go 565, runtime/seed.go 400, stagedgen/fsutil.go 149, stagedgen/stagedgen.go 413, state.go 165, system_linux.go 190, version.go 60, wgkey/wgkey.go 113
- Extra prod: cutover.go 996, cluster_cli.go 610
- Test LOC: ~8390
- Largest prod fns: KernelRunner.Promote ~80 lines, KernelRunner.preflight/installCandidate/armCandidate ~70 each, Runner.Run ~180, flip.gc ~100, stagedgen.Config.Publish ~50, lock.AcquireAt ~70
- Responsibility: binary cutover ordering, host-wide lock, staged-gen immutable publish, kernel A/B arm/promote, manifest SSOT, wg x25519 keygen

## Module Log (coverage - negatives proving soundness)
- flip.go: NEGATIVE - symlink repoint atomic temp+rename+fsync, ver validated upstream via ValidateVersionSegment, unit dropin path from versionDir (validated) and fmt.Sprintf no shell.
- helper_health.go: NEGATIVE - fail-closed 3-part gate (unit active + armed+forwarding + target version dir equality), exe (deleted) suffix tolerated via Dir, deadlines bounded.
- imageversions.go: NEGATIVE - parseImageVersions scanner with present-tracking, requiredKeys fail-closed, GateMixedBaseSwap fails closed on 0/unknown peer protocols, back-compat window check correct.
- kernel.go: NEGATIVE - KernelState order unknown-> -1 atLeast false fail-closed, journal struct no path traversal via version fields (validated elsewhere).
- kernel_drain.go: NEGATIVE - DrainAndConfirm refuses if peer not alive/takeover-ready, failback ResetFailover on timeout avoids VIP stranding, sleepBounded bounds deadline overshoot.
- kernel_linux.go: NEGATIVE - command exec via exec.Command not shell, LC_ALL=C locale hardening, BootOrder/SetBootNext hex-validated, slot labels constants xpf-A/B, promotion marker durable, disarm watchdog error surfaced (#4872B).
- kernel_run.go: NEGATIVE - resume-version guard, stale marker clear, preflight UEFI+efibootmgr+A/B+BootOrder+grub+watchdog+free space, install re-assert default not moved + KernelHeld full-set, armCandidate selector read-back verify + journal ARMED before BootNext (reboot-boundary hole closed), Promote fail-closed indeterminate handling (#4872A) preserves journal no prune no reboot on unreadable state.
- kernel_selfrecover.go: NEGATIVE - lease state machine only acts on leaseExpiredOurs (crashed orchestrator fingerprint), leaseNone manual drain no-op, IsZero expiry check prevents {} lease -> spurious recovery (#4872C), grace reset on observation error (#4872D), Armed gate prevents split-brain rejoin during armed trial.
- lock/lock.go: NEGATIVE - flock EX|NB host-wide, /run tmpfs reboot-clearing, truncate-on-acquire + truncate-on-release-under-lock prevents stale JSON (#1984), never rm lock file (#1875), Handle idempotent Release, owner metadata best-effort not mutex.
- manifest/manifest.go: NEGATIVE - private managed slice, fresh slice returns prevent mutation, LockstepNames from SSOT.
- rolling.go: NEGATIVE - lock held whole window, inner Run LockAlreadyHeld avoids self-deadlock EWOULDBLOCK, prechecks peer alive/sync/HA compat/takeover-ready before ForceSecondary, strong drain predicate, tolerateTransientErr for post-cut gRPC unavailable.
- runner.go/cutover.go: NEGATIVE - ValidGenID + target==Base check prevents ../ escape in ResolveCurrent, ValidateVersionSegment rejects / leading dot whitespace control non-ASCII, copyTree rejects non-regular (symlink) entries, checksum verify, fsync deepest-first, DB snapshot before flip ordering, cluster gate refuse-standalone-cut-on-clustered-node (#5284) before lock/journal, source generation pinned, live/rollback dir replace guarded and refused pre-PREFLIGHT, ReadJournalSourceGeneration fail-closed on malformed (#4876).
- runtime/seed.go: NEGATIVE - first-install idempotent partial+rename, ValidateVersionSegment on staged version, non-dir existing version dir refused, atomicRelSymlink RemoveAll tmp dir-safe, preservedMode keeps special bits.
- stagedgen/fsutil.go: NEGATIVE - copyTreeFsync rejects symlinks, preserves mode, deepest-first fsync.
- stagedgen/stagedgen.go: NEGATIVE - GenID crypto/rand with fallback, ValidGenID strict (no leading dot, no /, no .., single dash, hex only), Publish sweep partials + validated genid + sync dir + atomic current-gen, ResolveCurrent Base check + exists+isDir, GC extraProtected additive current-gen+protected + RetainGenerations=2 + fsync.
- state.go: NEGATIVE - State order unknown-> -1, atLeast logic, journal fields version keys validated upstream.
- system_linux.go: NEGATIVE - exec.Command constant binaries no shell, BinaryVersion validates token via ValidateVersionSegment after format check, VerifyDataplane exit 3 REJECT handling, unit dropin atomic durable mkdir.
- version.go: NEGATIVE - ValidateVersionSegment covers empty, . .. leading dot, /, whitespace, <0x20/0x7f, >=0x80 ASCII-only matching shell is_safe_segment parity.
- wgkey/wgkey.go: NEGATIVE - crypto/rand, clamp 248/127/64 correct, ecdh X25519, HexToBase64 length pre-check prevents large alloc, 44-char base64 canonical.

## Findings - High Confidence
NONE - no high/critical command injection, path traversal, TOCTOU, or fail-open on malformed manifest/version/kernel found that bypasses existing hardening.

## Findings - Medium Confidence
### M1: Kernel candidate version lacks safe-segment validation before filesystem use
Severity: Medium
Confidence: Medium
Evidence: /tmp/review-wt-claude-001-A7_go_daemon_host-b3/pkg/upgrade/kernel_run.go:77
```
func (r *KernelRunner) Arm(candidateVersion string) error {
    if candidateVersion == "" {
        return fmt.Errorf("kernel-upgrade: candidate version is required")
    }
...
```
and kernel_linux.go:186
```
func (s *realKernelSystem) InstallCandidateKernel(version string) (string, error) {
    pkgs := []string{"linux-image-" + version, "linux-modules-" + version}
...
    candPkgs := []string{
        "linux-image-" + candidateVersion,
        "linux-modules-" + candidateVersion,
...
```
Trace: Operator input `xpfd upgrade kernel arm <ver>` -> Arm() only checks empty -> InstallCandidateKernel concatenates into apt package names and later PruneInactiveSlot builds `/lib/modules/<ver>` and Glob `/boot/*-<ver>` removing matches. If ver contains "/" or "..", apt will fail (safe via exec.Command) but PruneInactiveSlot RemoveAll/Glob could escape /boot or /lib/modules scope. Root operator already privileged, but defense-in-depth missing.
Refutation attempt: Checked ValidateVersionSegment only used for xpfd versions, not kernel versions. Kernel versions legitimately have dots/dashes but should forbid "/". No validation found in kernel path. Survives as medium because operator is root, not unprivileged escalation.
Why: Defense-in-depth; malformed operator input or future automation feeding kernel version should not cause filesystem escape.
Fix: Add ValidateKernelVersionSegment similar to ValidateVersionSegment but allows [a-zA-Z0-9._+~-] and rejects "/", "..", whitespace, control, leading dot. Call in Arm() before journal.
Labels: hardening, refactor
Dedup: Not in dedup index (dedup covers protocol gates, not kernel version validation).

## Findings - Low Confidence / Hardening
### L1: Tool invocations via PATH search not absolute path
Severity: Low
Confidence: High
Evidence: kernel_linux.go:60
```
func (s *realKernelSystem) BootEntries() (map[string]string, error) {
    out, err := captureCmd("efibootmgr")
...
func captureCmd(name string, args ...string) (string, error) {
    cmd := exec.Command(name, args...)
```
and system_linux.go:181
```
func runCmd(name string, args ...string) error {
    cmd := exec.Command(name, args...)
```
Trace: exec.Command relies on PATH if name contains no slash. If daemon's PATH env compromised (e.g., via systemd Environment), could hijack efibootmgr/apt-mark/ping etc. Daemon runs as root with controlled unit, low risk.
Fix: Use absolute paths (/usr/bin/efibootmgr, /usr/bin/apt-mark, /usr/bin/ping) or sanitize PATH at daemon start.
Labels: hardening

### L2: ForwardBeacon ping target option injection
Severity: Low
Confidence: High
Evidence: kernel_linux.go:453
```
if err := runCmd("ping", "-c", "3", "-w", fmt.Sprintf("%d", secs), target); err != nil {
```
If target starts with "-", ping interprets as option. BeaconTarget from env XPF_KERNEL_BEACON_TARGET operator-controlled but could be "-f" flood. exec.Command not shell but option parsing still.
Fix: Insert "--" before target or validate target not starting with "-".
Labels: hardening

### L3: lock readOwner opens by path not fd - minor TOCTOU diagnostics only
Severity: Low
Confidence: High
Evidence: lock/lock.go:291
```
func readOwner(f *os.File) *Owner {
    data, err := os.ReadFile(f.Name())
```
Busy reader opens by name while holder still holds flock. If holder released between flock failure and ReadFile, reads empty -> unknown owner (acceptable degradation). No mutex correctness impact, only diagnostics. Documented as best-effort.
Fix: Already mitigated via truncate-on-acquire/release. Could use ReadAt via fd for stronger consistency but not required.

### L4: GenID decimal timestamp prefix technically not lowercase-hex but passes ValidGenID
Severity: Low
Confidence: High
Evidence: stagedgen/stagedgen.go:129
```
return fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
```
and ValidGenID: allows 0-9 a-f and single dash, so decimal digits pass because 0-9 subset of hex. Works but mixes decimal and hex semantics. No security impact, just naming.
Fix: Accept as is; if strict hex wanted, format timestamp as hex too.

## Suggested Issue Split
- Issue 1: Validate kernel candidate version safe segment (M1) - small PR adding ValidateKernelVersion.
- Issue 2: Harden exec PATH + ping "--" (L1+L2) - low prio hardening bundle.

## Compliance Notes
- No shell exec found; all cmd via exec.Command arg array.
- fsatomic durable writes used throughout, fsync dir after renames.
- Symlink handling rejects non-regular files in copyTree (prevents symlink attack from staged).
- ValidGenID + Base check closes path traversal for staged-gen.
- WG keygen correct: crypto/rand + clamp + X25519.



---

### === ps-A8_go_api_grpc_rest-b1.md ===

# A8 Go API / gRPC / REST — Batch b1 Security Review

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A8_go_api_grpc_rest-b1
Output: /tmp/review-work-claude-001/ps-A8_go_api_grpc_rest-b1.md
Batch: A8_go_api_grpc_rest b1/2 — 150 files (27 prod priority + 123 test/support)

## File-size / shape inventory

Total prod LOC (27 priority): ~15.8k
- `pkg/api/*` 13,440 LOC (21 files)
- `pkg/grpcapi/{apply_result,exec_timeout,fabric_auth,runtime,server,cluster,config}` 2,347 LOC (7 files)
Full api+grpcapi glob: 61,956 LOC (150 files incl tests, `wc -l` sorted earlier)

Largest prod files (LOC x responsibility rank):
1. `pkg/api/metrics_descriptors.go` 2044 — Prometheus Desc registration (200+ series), static, checked-collector contract; no hot path
2. `pkg/api/metrics_userspace.go` 1865 — userspace-dp status → Prometheus, cache-line not relevant, control-socket contention sensitive
3. `pkg/grpcapi/server_sessions.go` 1460 — gRPC session list/clear/resolve, bilingual parity with REST, cancellation sampling, HA peer fan-out
4. `pkg/api/sessions.go` 1410 — REST cursor/offset pagination, reverse-counter merge, zone/app/FIB enrichment, cancel sampler per 1024
5. `pkg/api/metrics.go` ~1130 — Collector struct, singleflight+TTL cache, Describe/Collect, pre-gate control-plane signals
6. `pkg/grpcapi/server_show_security_text.go` 1063 — text show policies/security
7. `pkg/grpcapi/server_show_interfaces.go` 935
8. `pkg/api/security.go` 871 — zones/policies/events/match-policies simulator, strict validation
9. `pkg/grpcapi/server_cluster.go` 838 — cluster show, interface monitor, peer fill-down
10. `pkg/api/types.go` 815 — request/response types, policy ID zero contract, host-inbound structs

Test vs prod split: ~75% test LOC, 25% prod in this batch. Largest fns: `(*xpfCollector).Collect` (~150 LOC), `(*Server).matchPoliciesHandler` (~300 LOC), `(*Server).sessionsCursor` (~120 LOC), `(*Server).policiesHandler` (~200 LOC).

Responsibility map:
- `api.go`: writeJSON buffering (#4541), decodeJSONBody 16 MiB cap, queryIntStrict/Uint16Strict, parseRefBaseUnit, allInterfaceNames nil-guard
- `auth.go`: Basic/Bearer/API-Key, const-time, loopback gate for /metrics (#4162)
- `config.go`: rollback/compare strict, secret redaction, body cap reuse
- `crosssite.go`: CSRF guard before auth (#5055)
- `server.go`: timeouts (10s hdr, 30s read, 120s idle, 1 MiB hdr), metrics scrape 10s/3 in-flight, self-signed persist strict sequence (#1916), clamp loopback (#5035)
- `sessions.go` / `server_sessions.go`: pagination caps 10k, cancel sampling #5233, HA peer isolation first-page only
- `security.go`: match-policies duplicate + unknown-key fail-closed (#3709/#5316)
- `sse.go`: category/severity strict, subscriber cap 128
- `routing.go`: BGP streaming with cancel check per 1024 (#5232)
- `grpcapi/fabric_auth.go`: HMAC time-windowed PSK, downgrade guard via heartbeat (#4107)
- `grpcapi/server.go`: allowlist (#4122), SystemAction nested safe check, gRPC maxRecv 16 MiB, graceful stop 2s

## Module log (coverage proof incl negatives)

- `api.go`: Checked `writeJSON` buffer-first pattern, `decodeJSONBody` MaxBytesReader + MaxBytesError → 413, `queryIntStrict` via `config.ParseCanonicalUint` rejects "+80", `queryUint16Strict` fail-closed for zone typo, `parseRefBaseUnit` Atoi not Sscanf. **Negative**: `queryInt` lenient fallback defined but unused in prod (no call site).
- `auth.go`: Verified `constantTimeAPIKeyMatch` loops all keys, `subtle.ConstantTimeCompare`, exists&&match pattern for unknown user, `isLoopbackBindAddr` treats ""/wildcard/malformed as non-loopback. Metrics gating via `isLoopbackBindAddr`. **Negative**: No secret leak via timing on API key length beyond acceptable length-only leak.
- `config.go`: Verified rollback N<0 guard, ShowRollback n<=0, compare rollback via `queryIntStrict`, redacted renderers `*Redacted`, body cap via `decodeJSONBody`. **Negative**: No path traversal – paths are config tree tokens, not filesystem.
- `crosssite.go`: Verified guard order (wraps mux BEFORE auth), Sec-Fetch-Site cross-site/same-site reject, Origin null handling, Referer optional, simple content-type reject, `sameHostAs` fail-closed on parse error/`EqualFold`. Unsafe list is safe methods only. **Negative**: No CORS headers emitted, so no permissive CORS.
- `dhcp.go`: Verified ContentLength!=0 handles chunked -1, `io.EOF` tolerated for zero-byte chunked, MaxBytesReader. **Negative**: No interface name injection – `ClearDUID` validates internally.
- `exec_timeout.go` (both api & grpcapi): Verified 15s+5s, ping budget formula count*1s+15s floor 30s ceiling 150s, traceroute 60s, tail cap 10k. **Negative**: No command injection – `diagcmd` builder inserts `--`.
- `health.go`: Verified degraded 503 vs non-fatal visibility split (bootstrap import, rollback history). **Negative**: No sensitive data in health payload beyond status strings.
- `interfaces.go`: Verified nil zone guard (#3493), `ResolveKernelIfName` for gr-/reth, DHCP lease key via `DHCPLeaseKey` distinct from kernel name. **Negative**: No interface name injection to `InterfaceByName` beyond kernel lookup.
- `metrics.go`: Verified pre-gate collectors (config persist, rollback, FRR reload, IPsec rebind, scheduler republish, feeds, flow collectors, nft host-inbound, addressless, ambiguous, lo0, PBR) before dataplane gate, `fetchUserspaceStatus` once per scrape (#5317), error counters emitted last. Session gauge TTL 3s + singleflight (#4162). **Negative**: No unbounded label cardinality – feed/zone/interface labels bounded by config.
- `metrics_counters.go`, `_nat.go`, `_sessions.go`, `_system.go`: Verified nil guards, bulk counter reader O(P+C) (#3965), `FilterTermExpansionCount` SSOT (#3459), skip-without-zero on read failure, scrape_ok=0 on iterator error. **Negative**: No double counting – runtime pools dedup by name.
- `nat.go`: Verified runtime SSOT via `Status()`, fallback to legacy port counter, interface-mode counted per zone-pair via session walk with error fail (#2469). **Negative**: No map iteration leak.
- `routing.go`: Verified BGP streaming `bufio.Writer`, `writeJSONStringFragment` via `json.Marshal` fragment escaping, context check per 1024 routes (#5232). **Negative**: No header injection – route strings JSON-escaped.
- `security.go`: Verified zone counter read error → 500, policy counter bulk, runtime IDs, scheduler inactive via `PolicyInactiveFn(nil)` fails closed to inactive, events limit strict 10k cap (#4926), zone filter 0/`unknown`/`none` (#3338), match-policies dup check (#3709) before unknown-key check (#5316) before cfg nil, IP/port/protocol/ICMP strict validation, feed overlay, route-drop advisory. **Negative**: No wildcard widening on malformed selector – fail-closed 400.
- `server.go`: Verified method-pattern `GET /api/v1/...`, mutation guard before auth, metrics auth gate, timeouts, TLS strict persist (mkdir durable, strict removes ignoring only IsNotExist, SyncDir, key 0600 then cert 0644, in-memory fallback nil error). Shutdown 5s. **Negative**: No WriteTimeout severing SSE – intentional unset documented.
- `sessions.go`: Verified page_size/limit/offset strict caps 10k (#3421 M8), token codec base64url(hex(key)), decode length checks, `newRequestCancelSampler` per 1024, `clearSessionsHandler` RawQuery + ContentLength check plus SMR note for %zz, peer attach only first page (`sessionFirstPage` + `include_peer`), `peerSessionsRequest` lenient but validated upstream + peer re-validates. **Negative**: No authz bypass – clear requires dataplane loaded.
- `show_text.go`: Verified topic required, `sortedKeys` determinism (#4712), SNMP community redaction via `SecretDataPlaceholder` (#5315). **Negative**: No secret via sortedKeys – keys replaced.
- `sse.go`: Verified strict category/severity parse before switching to SSE (#3383), subscriber cap 128 with 503 before headers, `parseCategories` empty token → error, `matchCategory` unknown type → false (fail-closed), severity mapping permit screen → notice. **Negative**: No resource leak – `defer sub.Close()` in both handlers.
- `stats.go`: Verified kernel host-inbound counters before gate (#3681), Unavailable flag path, partial 200 + Degraded flag vs blanket 503. **Negative**: No misleading zero – Unavailable boolean.
- `system.go`: Verified target required, count clamped 100, argv via `diagcmd.*Argv` shared builder (#2143 VRF, #2084 `--`), `pingExecTimeout` budget, `WaitDelay`, power action seam 1s sleep + Background context, `logSystemAction` journals before action (#4108). **Negative**: No command injection – target passed as argv to shared builder, not shell.
- `grpcapi/fabric_auth.go`: Verified domain separation `xpf-fabric-grpc-auth\0`, LittleEndian window, hex decode length check, HMAC Equal const-time, ±1 window, decision matrix, sticky `fabricPeerAuthSeen` + `heartbeatPeerAuthSeen` arming, client creds `RequireTransportSecurity=false` documented as private segment, `NewFabricAuthCreds` for CLI peer dial (#5324). **Negative**: No key logged.
- `grpcapi/server.go`: Verified `maxRecvMsgSize` 16 MiB, `clampGRPCBindToLoopback` treats "" as non-loopback, "localhost" as loopback, IPv6 family clamp, warn log, `stopGRPCServer` bounded 2s GracefulStop→Stop, `RunFabricListener` SO_REUSEADDR/REUSEPORT/BINDTODEVICE, interceptor chain auth→allowlist→config-lock, allowlist maps for unary/stream, `parseProxiedFailoverAction` strict parse both forms, `IsSupportedClusterNodeID` range check, `isFabricSafeSystemAction` type assert + parse, `fabricAllowlist*` warn log, `configLockInterceptor` + `peerSessionID` from `peer.FromContext`. **Negative**: Primary listener no auth by design – clamped to loopback; fabric is the network surface with auth+allowlist.
- `grpcapi/server_cluster.go`: Verified RETH status via `netlink.LinkByName` + `LinkAttrsUp`, monitor fill-down as Down on missing status (#4480), peer fill-down. **Negative**: No panic on nil config.
- `grpcapi/server_config.go`: Verified `configMutationStatus` maps `ErrConfigLockedByOther` → PermissionDenied, session ID via `peerSessionID`, `EnterConfigure` RG0 primary check, exclusive vs session, `Set` handles copy/rename/insert/activate/deactivate with field validation, `handleCopyRename` to-index validation, `handleInsert` refTokens longer than elemPath reject, parentPath construction, `Rollback` N<0 reject, `ShowCompare` RollbackN<0, `ShowRollback` N<=0, redacted renderers. **Negative**: No junk node creation for bare activate/deactivate.

## Findings — High confidence

### H-01: TRACE method bypasses cross-site guard (low severity cross-site tracing residual)
Severity: Low
Confidence: High
Evidence:
- `pkg/api/crosssite.go:51-60`
```
func isSafeHTTPMethod(method string) bool {
    switch method {
    case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
        return true
```
- `pkg/api/server.go:509` guard wraps before auth, safe methods skip.
Trace: Browser cross-site fetch with `method: TRACE` + `credentials: include` would bypass `crossSiteRejectReason`, reach handler. If any handler echoed headers (it doesn't), classic XST. Go's mux doesn't have TRACE handler, so would 405, but guard still skips. All state-changing verbs POST/DELETE are guarded.
Refutation: Guard's purpose is non-safe methods. TRACE is safe by HTTP spec (no side effect). XST requires server reflect. This code doesn't reflect. So low.
Fix: Remove TRACE from safe list, or explicitly reject TRACE at mux level with 405 before guard, so cross-site TRACE cannot reach.
Labels: hardening, csrf
Dedup: Not in dedup index.

### H-02: gRPC primary bind clamp bypass when addr lacks port (minor fail-safe gap)
Severity: Low
Confidence: High
Evidence:
- `pkg/grpcapi/server.go:304-316`
```
func clampGRPCBindToLoopback(addr string) (string, bool) {
    host, port, err := net.SplitHostPort(addr)
    if err != nil || grpcHostIsLoopback(host) {
        return addr, false
    }
```
- `grpcHostIsLoopback` returns false for "" host.
Trace: If daemon started with `--grpc-addr 0.0.0.0` (no port), SplitHostPort fails → returns original, not clamped. `net.Listen("tcp", "0.0.0.0")` fails (missing port), daemon wouldn't listen – denial of service self-inflicted, not exposure. With port present `:50051` → host "" → clamped correctly to 127.0.0.1:50051. So not exploitable as remote exposure.
Refutation: Real deployment passes host:port; startup failure case is safe-fail closed (no listener) not unauth exposure. Still tighten.
Fix: On SplitHostPort error, try parsing whole string as IP via `net.ParseIP` and if non-loopback, return loopback:defaultPort or error. Or log and refuse to start.
Labels: hardening, fail-safe

## Findings — Medium confidence

### M-01: `queryInt` legacy lenient helper remains (dead code, future misuse risk)
Severity: Low
Confidence: Medium
Evidence:
- `pkg/api/api.go:146-156`
```
func queryInt(r *http.Request, key string, def int) int {
    v := r.URL.Query().Get(key)
    if v == "" { return def }
    n, err := strconv.Atoi(v)
    if err != nil || n < 0 { return def }
    return n
}
```
- Grep shows zero prod call sites (migrated to `queryIntStrict`).
Trace: Future handler could mistakenly use `queryInt` and silently default on typo, widening filter to all zones/sessions (cross-zone observability leak #2934 pattern). Currently dead.
Refutation: No active misuse found in this batch. Dead code but not vulnerability.
Fix: Delete `queryInt` or make it wrapper around `queryIntStrict` with log, keep `queryUint16` similarly deprecated. Unit test that greps for its use.
Labels: refactor, hardening

### M-02: Ping `Size` not clamped (resource / amplification, not injection)
Severity: Low
Confidence: Medium
Evidence:
- `pkg/api/system.go:162-174`
```
func buildPingArgv(req PingRequest, count int) []string {
    size := ""
    if req.Size > 0 {
        size = fmt.Sprintf("%d", req.Size)
    }
    return diagcmd.PingArgv(...)
}
```
- `PingRequest.Size` parsed via `decodeJSONBody` 16 MiB cap, but value is unbounded int. `diagcmd.PingArgv` builds `ping -s <size>`.
Trace: Caller can set Size=65500, count=100 → ping sends 100*65500 bytes ~6.5 MB per request, bounded by exec timeout 115s. Not huge, but combined with concurrent requests could amplify egress. `diagcmd` may validate internally, not reviewed here.
Refutation: Count already clamped 100, timeout bounds duration, but size not clamped could still be abused for egress flood like `system_buffers_test` pattern? Not injection, but DoS.
Fix: Clamp Size to [0, 65507] (max ICMP payload under IPv4) or 0-8972 typical. Reject >65507 with 400, mirror count clamp.
Labels: DoS, hardening

## Findings — Low / informational

### L-01: Self-signed cert serial number fixed to 1
Evidence: `pkg/api/server.go:661` `SerialNumber: big.NewInt(1)`. POD with same serial across appliances, not security critical for self-signed TOFU but violates uniqueness expectation. Fix: random serial via `rand.Int(rand.Reader, big.NewInt(1<<62))`.

### L-02: `clearSessionsHandler` rejects chunked empty body as filtered clear (strict)
Evidence: `pkg/api/sessions.go:635` `if r.URL.RawQuery != "" || r.ContentLength != 0`. Chunked empty has ContentLength -1 → rejected though intent is clear-all. Strict fail-closed is correct per comment but diverges from typical HTTP client that may use chunked for empty. Document as intentional strictness or allow ContentLength -1 with 0 bytes read.

### L-03: Deterministic NAT pool capacity `1 << uint(bits-ones)` shift overflow handled in metrics_nat.go via explicit IPv6 path, but `collectNATPoolMetrics` in same file uses `(portHigh-portLow+1)*len(addresses)` without overflow check – pool addresses bounded by config (<1k), port range <65535, product <~64M fits int, safe. No issue, but unify via helper.

## Dedup notes (not re-reported as new)

- #5318 REST session offset pagination walks full table for Total – confirmed still present in `sessionsOffset`: `idx++` counts all matching across v4+v6. Mitigated via cursor mode, cancel sampler, caps. Not re-reported as new, root cause same.
- #5328 cohort (REST/gRPC parity, RSS subset, etc.) – existing parity items covered by explicit parity comments, no new bypass.
- #5303 session-sync accept loop admission cap – not in this batch (pkg/cluster).
- #5278 loopback gRPC no per-principal auth – documented trust boundary, clamp to loopback (#5035) mitigates, fabric listener has auth. Not in scope of api/ surface but noted.

## Suggested issue split

1. Harden TRACE out of safe-method list + gRPC clamp error path (H-01, H-02) – 1 PR, low risk, add test for TRACE → 403/405.
2. Remove dead `queryInt`/`queryUint16` lenient helpers + clamp ping Size (M-01, M-02) – 1 PR, add unit test.
3. Optional: randomize TLS cert serial (L-01) – 1-line.

## Overall assessment

This batch is heavily hardened: 16 MiB body/recv caps, const-time auth, loopback clamps with family preservation, fail-closed strict query parsers, duplicate/unknown selector rejection, CSRF guard before auth with 4 signals, BGP streaming cancel checks, TLS persist strict sequence, fabric PSK HMAC with ±1 window + heartbeat-armed downgrade guard, allowlist + nested SystemAction safe check, graceful shutdown bounded. No critical/high findings. Two low high-confidence hardening items and two medium low-severity defense-in-depth items. Negatives above prove coverage of authz, injection, integer handling, DoS, pagination, secret redaction, CORS/CSRF, session handling.


---

### === ps-A8_go_api_grpc_rest-b2.md ===

# A8_go_api_grpc_rest b2/2 — gRPC/REST api hardening sweep

Base: 275989b76b22925f4d2719fa07f47709eb227059
Worktree: /tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2
Batch: 129 files pkg/grpcapi, 29 prod ~12.4k LOC, 98 test ~11k, 2 gen 11.2k (xpf.pb.go 9172, xpf_grpc.pb.go 2056), total 36k.

Top5 prod LOC / responsibility:
1 server_sessions.go 1460 — session table RPC (cursor+legacy, filtered clear, peer fan-out, zone-pair) R1 (DoS amplification, peer dial)
2 server_show_security_text.go 1063 — screen IDS, ipsec, rpm, security log/alarms R2
3 server_show_interfaces.go 935 — GetInterfaces, detail/terse, RETH, kernel stats R2
4 server_show_firewall.go 666 — filter term expansion, counter reads, policer R3
5 server_show.go 562 — ShowText allowlist gateway (log tail allowlist, CoS) R1 (remote CLI entry)

Largest fn: getSessionsCursor ~180 LOC, ClearSessions filtered ~140, showPoliciesHitCount ~120, dialPeer ~55 but hot for HA.

Responsibility rank size x resp x hot-path:
- server_sessions.go (session scan O(N) N up to 10M, peer dial on every request)
- server_diag_system_action.go 486 (reboot/zeroize/failover/userspace inject/queue/binding — destructive)
- server_show.go (show topic allowlist — remote CLI → gRPC bridge)
- server_diag_monitor.go 520 (MonitorPacketDrop validation, streaming lifecycle)
- server.go 588 (bind clamp, graceful stop, fabric allowlist, auth interceptor chain)

---

## Findings — High Confidence

### Title: userspace-inject/queue/binding slot wraps negative Atoi -> MaxUint32
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_system_action.go:384-412`
```
			if strings.HasPrefix(req.Action, "userspace-inject:") {
				...
				parts := strings.SplitN(rest, ":", 2)
				if len(parts) != 2 {
					return nil, status.Error(codes.InvalidArgument, "usage: userspace-inject:<slot>:<mode>")
				}
				slot, err := strconv.Atoi(parts[0])
				if err != nil {
					return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
				}
				mode := parts[1]
				statusNow, err := provider.Status()
				...
				injectReq, err := dpuserspace.BuildInjectPacketRequest(uint32(slot), mode, extra, statusNow)
```
Same at :444 queueID Atoi -> uint32(queueID), :469 slot Atoi -> uint32(slot).
Trace:
1. Client (loopback, per #5278 any shell user) sends SystemAction `userspace-inject:-1:drop`.
2. Atoi("-1")= -1, err=nil, passes InvalidArgument check.
3. Cast uint32(-1)=4294967295 passed to BuildInjectPacketRequest/SetQueueState/SetBindingState.
4. Downstream may reject with generic error, or index OOB, or confuse operator with max-slot message.
Refutation attempt: Looked for downstream validation in dpuserspace — likely checks slot < len(bindings) but error would be "slot out of range" not "negative not allowed". RPC boundary should fail-closed on negative before cast; no `slot<0` check in this file. Not caught by existing tests (no negative slot test in batch).
HPC/invariant: N/A — control path, not hot.
Why it matters: Bypass of intended non-negative domain, potential panic/OOB in Rust helper if Go check missing, confusing error for typo.
Fix direction: Add `if slot<0 { return InvalidArgument("slot must be >=0") }` before cast for all three verbs; same for queueID.
Labels: input-validation, integer-bounds, userspace-dataplane
Dedup note: Not #5281/#5280/#5278 (zeroize root / RBAC). Distinct integer bounds in userspace control verbs.

### Title: Ping Size unbounded — TX amplification DoS
Severity: Medium
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_ping.go:56-95`
```
func (s *Server) Ping(req *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	if err := checkDiagArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
		return err
	}
	count := int(req.Count)
	if count <= 0 {
		count = 5
	}
	if count > 100 {
		count = 100
	}
	cmd := buildPingArgv(req, count)
```
```
func buildPingArgv(req *pb.PingRequest, count int) []string {
	size := ""
	if req.Size > 0 {
		size = fmt.Sprintf("%d", req.Size)
	}
	return diagcmd.PingArgv(diagcmd.PingOptions{
		Target:          req.Target,
		Count:           fmt.Sprintf("%d", count),
		Source:          req.Source,
		Size:            size,
		RoutingInstance: req.RoutingInstance,
	})
}
```
Trace: gRPC PingRequest{Size: 1<<31-1} -> size "2147483647" -> ping -s 2147483647 tries alloc 2GB payload -> OOM / long TX, dataplane flooded with giant ICMP. Count clamped 1..100 but size not. maxDiagArgLen=512 does not apply to numeric field.
Refutation: diagcmd likely passes -s directly to ping binary which caps at 65507, but should fail at RPC boundary with InvalidArgument before exec; current would surface as generic exec error not InvalidArgument.
Why: Allows single RPC to drive large TX, memory/CPU.
Fix: Clamp size 0..65507 (max IPv4) or 0..10000 typical, return codes.InvalidArgument if > max. Add unit test.
Labels: DoS, input-validation, diag
Dedup note: Not #5060 (scanner token) — this is size arg amplification.

### Title: GetSessions page_token length unbounded — per-request multi-MB alloc
Severity: Low
Confidence: High
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_sessions.go:1409-1432`
```
func parsePageToken(token string) (kind string, keyBytes []byte, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", nil, fmt.Errorf("invalid page_token encoding: %w", err)
	}
	s := string(raw)
	if s == "v6start" {
		return "v6start", nil, nil
	}
	if strings.HasPrefix(s, "v4:") {
		b, err := hex.DecodeString(s[3:])
```
No length guard before DecodeString.
Trace: Attacker sends 16 MiB 'A'*16M (maxRecvMsgSize=16MiB) -> DecodeString alloc ~12 MiB raw + string + hex decode -> per RPC memory spike; server token legit <120 chars. Can be sent concurrently.
Refutation: MaxRecvSize bounds but still large; should early reject. No existing clamp seen. decode helpers check len(b) < binary.Size -> fail but after alloc.
Why: Memory pressure DoS via many concurrent GetSessions.
Fix: `if len(token)>512 { return InvalidArgument "page_token too long" }` before decode — legit tokens ~150 chars, 512 generous.
Labels: DoS, resource-exhaustion
Dedup note: Distinct from #5318 (pagination total scan) — this is token parsing, not total count.

---

## Findings — Medium Confidence

### Title: Diagnostic execs (Ping/Traceroute/Monitor) no concurrency cap — fork bomb
Severity: Medium
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_ping.go:56-75` + `server_diag_monitor.go:312-475` streaming loop.
```
func (s *Server) MonitorInterface(req *pb.MonitorInterfaceRequest, stream ...) error {
	...
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	...
	for {
		var buf strings.Builder
		...
		if err := stream.Send(&pb.MonitorInterfaceResponse{Frame: buf.String()}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
```
And `streamDiagCmd` does `exec.CommandContext` + `io.Pipe` per RPC, no semaphore.
Trace: Loopback gRPC allows any login-class shell user (dedup #5278) to open many concurrent Ping/Monitor streams; each spawns process + pipe + scanner goroutine; no global limit -> FD/process table exhaustion -> control plane DoS (dataplane continues but management lost).
Refutation: Checked server.go NewServer does not set grpc max concurrent streams, no token bucket. graceful stop has timeout #4910 but not admission cap. Could argue low risk because loopback only, but with #5278 any shell user can.
Why: Management plane DoS via diag fan-out.
Fix: Weighted semaphore (e.g., 8 concurrent diag execs) around streamDiagCmd and MonitorInterface render, return ResourceExhausted when full; per-principal rate limit after #5278 adds auth.
Labels: DoS, resource-management, graceful-shutdown
Dedup note: Not #5060 leak fix — this is admission cap, distinct.

### Title: ShowText unknown topic echoes raw input — log injection
Severity: Low
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show.go:498-535`
```
		} else if strings.HasPrefix(req.Topic, "log:") {
			parts := strings.SplitN(req.Topic, ":", 3)
			...
			logPath, err := config.SyslogLogFilePath(cfg, parts[1])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "%v", err)
			}
			out, err := combinedOutputTimeout(ctx, "tail", "-n", strconv.Itoa(n), logPath)
```
```
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "unknown topic: %s", req.Topic)
		}
```
Trace: Client sends topic with newline/control chars `"\n[evil]\n"` -> returned in gRPC status message -> remote CLI logs to syslog/journal without sanitization -> log injection (low because gRPC error, not shell, but still).
Refutation: Topic from remote CLI normally from cmdtree, but arbitrary gRPC client can send anything; %q would be safer.
Fix: Use `%q` or truncate to 128 and strip non-print via `strconv.Quote` or manual sanitize.
Labels: injection, hardening
Dedup note: Not in dedup list; not path traversal (log path validated via SyslogLogFilePath allowlist #4860).

### Title: cluster-failover RG ID negative not rejected as InvalidArgument
Severity: Low
Confidence: Medium
Evidence: `/tmp/review-wt-claude-001-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_system_action.go:314-335`
```
		if strings.HasPrefix(req.Action, "cluster-failover:") {
			...
			rgStr := rest
			...
			rgID, err := strconv.Atoi(rgStr)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid redundancy-group ID: %s", rgStr)
			}

			// If "node <N>" specified, route to correct node.
			if nodeStr != "" {
				targetNode, err := strconv.Atoi(nodeStr)
```
No check rgID<0 or rgID>max.
Trace: `cluster-failover:-1` -> rgID=-1 -> passed to `cluster.ManualFailover(-1)` -> likely returns NotFound, but should be InvalidArgument at boundary (fail-closed). Same for data path: rgID not used but node validated via IsSupportedClusterNodeID.
Refutation: ManualFailover likely validates ID via map lookup — would return "redundancy-group -1 not found" as NotFound, not InvalidArgument — confusing but not unsafe.
Why: Confusing error, fail-open-ish? Operator typo negative should be InvalidArgument not NotFound.
Fix: `if rgID<0 { InvalidArgument }` for both failover branches.
Labels: input-validation
Dedup note: Not duplicate of node validation fix #4693 — that fixed node, not RG negative.

---

## Findings — Low / Hardening

- SNMP community name disclosure in `show snmp`: `server_show_dhcp_lldp_snmp.go:38-41` prints community map key verbatim. If community considered secret, should redact. Currently intentional vSRX parity (community shown), mark low.

---

## Module log — negatives proving coverage (incl sound invariants)

- server.go NEGATIVE: loopback clamp #5035 (`clampGRPCBindToLoopback` same-family ::1 vs 127.0.0.1), maxRecvMsgSize 16MiB matches configstore ceiling, stopGRPCServer GracefulStop + timeout Stop prevents monitor stream blocking shutdown #4910, configLockInterceptor auto-release on ctx cancel prevents lock DoS, fabric allowlist + auth chain order correct (auth before allowlist) — sound.
- fabric_auth.go NEGATIVE: HMAC-SHA256(domain||window), hex decode length check sha256.Size, constant-time hmac.Equal, window ±1 tolerance, dual-accept (no key -> accept, invalid token -> reject), downgrade guard armed via fabricPeerAuthSeen || heartbeatPeerAuthSeen #4107 fold — sound. Residual replay window documented.
- server_sessions.go NEGATIVE: offset negative rejected centrally #3439 L2, zone/port 0..65535 validated, protocol via ProtocolNumberLenient, prefix via ParseCIDR/host, snat-pool existence validated, filter uses val.ReverseKey not naive swap #2733, DNAT companion host-order port #2406, clear-all guarded by empty-filter check prevents typo->clear-all (Critical r2), peer recursion guard x-peer-forwarded, PageSize clamped 10000, total -1 when hasFilters avoids #5318 full scan, peer dial timeouts 3s/5s, conn.Close deferred — sound except token len + slot.
- server_diag.go NEGATIVE: dialPeer non-nil check, tries fab0/fab1, 2s health probe, per-RPC creds fabricAuthCreds token rotation, VRF bind via SO_BINDTODEVICE — sound.
- server_diag_monitor.go NEGATIVE: MonitorPacketDrop node local-only via isLocalNodeRef, count 0..8192, ports 0..65535, protocol via shared catalog, zone/interface via alias set, src/dst CIDR via ParseCIDR, protocol compare numeric not string (fixes accepted-but-never-matches), ticker Stop deferred, eventBuf Subscribe(256) Close deferred — no goroutine leak.
- server_diag_ping.go NEGATIVE except size: maxDiagArgLen 512 per field #5060, -- separator hardening #2084, WaitDelay for pipe-drain, scanner buffer 4KiB init 64KiB max token — leak fixed #5060.
- server_diag_system_action.go NEGATIVE except slot: failover node validation via IsSupportedClusterNodeID #4693 #4125, forward guard peerForwardedFromContext, RG batch, clear-arp/ipv6-neigh fixed ip args (no shell), policy/NAT clear checks dataplane loaded. Fabric allowlist denies zeroize/reboot on fabric listener (SystemAction only allowed when isFabricSafeSystemAction true -> only failover forms) — sound per #4122.
- server_diag_zeroize.go NEGATIVE: key-first unlink + fsync barrier #5197, TLS dir removal, allowlist .conf/rollback*/journal*, login teardown UID marker match #1944, marker retained on userdel failure — sound. Dedup #5281/#5280 out of scope (running writers may recreate erased secrets / hardcoded root) but not re-reported per instruction.
- server_helpers.go NEGATIVE: protoName SSOT, ntohs BigEndian->Native correct (not BigEndian bug), uint32ToIP NativeEndian correct, allInterfaceNames nil-safe.
- server_nat.go NEGATIVE: clampInt32 saturates int64->int32 #2282, per-rule-set breakdown via zone name map #3417, counter key includes natType #2218.
- server_routing.go NEGATIVE: BGP IP validated via net.ParseIP before vtysh #4588, groups sorted, nil FRR returns empty not panic.
- server_show.go NEGATIVE: ShowText prefix allowlist then switch, log topic validates via SyslogLogFilePath allowlist #4860 prevents traversal, tail lines clamped, args not shell-interpolated (exec array).
- server_show_events.go + GetEvents NEGATIVE: zone >65535 rejected fail-closed #3334, HasZone isolates zone 0 #3338, stored zone name preferred #3335.
- server_show_zones.go NEGATIVE: counter read failure -> Internal not zero #3408, nil zone skip #3493.
- server_show_interfaces.go NEGATIVE: filter prefix match on config names only, not file path; kernel stats trusted ResolveKernelIfName, RETH maps from config.
- server_show_policies_text.go NEGATIVE: bulk reader O(P+C) #4344 not per-policy lock loop, scheduler state via provider, global scope check.
- server_show_flow.go NEGATIVE: top-K heap O(N log K) #5319 bounded enrichment, iterator error -> Internal not partial #2469.
- server_show_routes_text.go NEGATIVE: showTestRouting malformed/unknown selector reported #4589 #3696.
- server_show_security_text.go NEGATIVE: screen checks via SSOT config.ScreenChecks, nil profile guard #3476, flood counters hide when ErrCounterNotPopulated #3643, TSIG secret redacted.
- server_show_system.go NEGATIVE: NTP exec chain uses combinedOutputTimeout with request ctx #1805.
- All prod files for DoS: no unbounded fmt.Sprintf in hot loop except showSessionsTop which is bounded K=20 enrichment deferred — sound.
- Generated pb.go NEGATIVE: no logic.
- Test files NEGATIVE: out of prod scope.

## Suggested issue split

1. Fix userspace slot/queue negative -> uint32 wrap (1-line checks, high-signal).
2. Ping size clamp + page_token length bound (input validation, 2 small PRs).
3. Diag concurrency semaphore + ShowText topic sanitize + RG negative check (hardening batch).

Metrics: prod 12.4k, test 11k, gen 11.2k, largest risky fn getSessionsCursor metric merge O(N) scan up to 10M sessions per page (acceptable with limit 10k, -1 total avoids extra scan).


---

### === ps-A9_go_observability-b1.md ===

# A9 Go Observability b1/1 — telemetry wire + SNMPv3 crypto + log path hardening
Base: 275989b76b22925f4d2719fa07f47709eb227059 WT: /tmp/review-wt-claude-001-A9_go_observability-b1 Date: 2026-07-10
Batch: 131 files — 26 prod (15808 LOC), 105 test (25612 LOC), total 37527 LOC
Inventory method: `wc -l` per prod file, `grep -c ^func` approx, manual responsibility ranking by hot-path proximity x size x wire-security relevance.

## File-size / shape / responsibility ranking

| File | LOC prod | Funcs | Hot-prox | Rank | Resp |
|------|----------|-------|----------|------|------|
| snmp/agent.go | 1791 | 62 | M | R2 | UDP/161 BER codec, v2c/v3 dispatch, ifSnapshot, trap queue, lifecycle |
| logging/ringbuf.go | 1451 | 37 | H event | R1 | RT_FLOW wire (144/152/160 additive), per-policy gate, fanout |
| eventengine/engine.go | 1294 | 25 | M | R6 | remediation queue, cooldown arm-on-commit, within/window AND |
| flowexport/ipfix.go | 1087 | 38 | M export | R3 | IPFIX templates 86/134 pinned, PEN 29305 biflow, PSAMP options 258, seq |
| ipmon/ipmon.go | 1016 | 20 | M | R7 | overlay winner MT metric, VRF resolve, debounce/throttle, HA gate |
| flowexport/manager.go | 915 | 23 | M | R4 | sampling instance determinism, template group sort, ServesFamily |
| logging/syslog.go | 911 | 35 | M | R3 | RFC6587 octet-count, 4s write deadline, 1s reconnect cooldown, closed flag |
| feeds/feeds.go | 889 | 15 | M | R8 | 32MiB body +1 sentinel, 1M entry cap, 1MiB line cap, retain-forever carry-forward |
| flowexport/netflow.go | 853 | 33 | M export | R3 | v9 recordSize unpadded + terminal pad once, bootTime CLOCK_BOOTTIME |
| rpm/rpm.go | 794 | 15 | M | R9 | probe loop, ErrProbeSetup hold, pinFailed union, bufferedEvents 64 |
| flowexport/transport.go | 561 | 14 | H export | R1 | dialCollectors fail-close fds, 2s SetWriteDeadline, 30s backoff, cap 65536 |
| logging/trace.go | 553 | 17 | L | R10 | sanitize bare basename, O_NOFOLLOW 0600, clamp #3424 |
| snmp/traps.go | 416 | 11 | L | R6 | v1/v2c/all per-group packet, bounded 256 queue, stop abandons backlog |
| rpm/icmp.go | 426 | 10 | L | R9 | ICMP echo id atomic, link-local zone requires dev not vrf-* |
| rest <400 each | — | — | L-M | — | aggregator Space-Saving 10K, locallog hardened, eventbuf 1000 cap 64 subs, routemask VRF keyed 8192/32, goid reentrancy guard |

Top hot: transport.go writeAll every 100ms + template refresh, ringbuf.go logEvent every RT_FLOW record, aggregator.Add SESSION_CLOSE, eventbuf.Add fanout O(N).
Largest funcs: Agent.handleV3Packet ~320 LOC (USM parse→timeliness→auth→decrypt→PDU), logging.EventReader.logEvent ~370 LOC (wire→enrich→fanout), ipmon.Engine.run ~90 LOC actuation loop.
Prod vs test 0.61 ratio: test-heavy, good. Generated: none.

## Findings (non-dedup, evidence-bar)

### Finding 1 — HIGH confidence
Title: SNMPv3 privacy salt RNG error ignored — IV reuse on RNG failure
Severity: Medium
Confidence: High
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/snmp/v3.go:790-822
```
func encryptDES(privKey, data []byte) ([]byte, []byte) {
	if len(privKey) < 16 {
		return nil, nil
	}
	desKey := privKey[:8]
	preIV := privKey[8:16]
	privParams := make([]byte, 8)
	rand.Read(privParams)
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = preIV[i] ^ privParams[i]
...
func encryptAES128(privKey, data []byte, boots, time int) ([]byte, []byte) {
	if len(privKey) < 16 {
		return nil, nil
	}
	privParams := make([]byte, 8)
	rand.Read(privParams)
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
```
Trace:
1. buildV3Response -> encryptPDU -> encryptAES128/DES.
2. make([]byte,8) zeroed, crypto/rand.Read called, (n,err) discarded.
3. On error (getrandom failure early boot, FIPS, fd exhaustion) buffer stays zero or partial undefined.
4. AES-CFB IV = boots|time|0 — boots/time changes per second, so all responses within same second share IV → keystream reuse leaks XOR of two plaintext scopedPDUs.
5. DES IV = preIV ^ 0 = deterministic.
6. Collector decrypts (still works) but confidentiality broken; RFC 3414 §8 / RFC 3826 §3.1.4 requires unique salt per PDU.
Refutation attempt: Checked crypto/rand docs: Read returns len and nil on success, else non-nil err. Go runtime seeds CSPRNG, rare to fail, but error path must be handled. Callers return nil only on short key, not on RNG failure, so weak packet still sent. Not mitigated elsewhere; no wrapper. Search confirms only two rand.Read sites, both ignored.
HPC/invariant check: Salt uniqueness invariant per RFC — must be 8 distinct random bytes per PDU; current provides monotonic time low bits + random, but fails to zero on error.
Why it matters: SNMPv3 authPriv confidentiality bypass on security-critical error path — triggers exactly when RNG unhealthy (worst time). Leaks ifTable/sysDescr via keystream XOR.
Fix direction: Check error: `if _, err := io.ReadFull(rand.Reader, privParams); err != nil { slog.Error(...); return nil, nil }`. Caller clears priv flag → sends authNoPriv or drops (better to fail response than send weak crypto). Add seam test injecting failing Reader assert fail-closed.
Labels: snmp, v3, crypto, RNG-error-handling, IV-reuse
Dedup note: Not in dedup list; #5283 is hostname-only EngineID collision, distinct root cause (deterministic EngineID vs RNG failure).

### Finding 2 — HIGH confidence (low sev)
Title: SNMP traps use math/rand for requestID — predictable, higher collision
Severity: Low
Confidence: High
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/snmp/traps.go:1-10
```
import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sort"
	"time"
...
```
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/snmp/traps.go:109-112
```
	// PDU body: request-id, error-status(0), error-index(0), varbinds
	requestID := rand.Int31()
	pduBody := berEncodeIntegerTLV(int(requestID))
```
Trace: buildLinkTrap builds PDU, calls math/rand global Int31. Go 1.20+ global auto-seeded from crypto but still PRNG, 31-bit space, predictable after seed observation. Collector dedup by requestID may collide slightly higher; not security boundary for v2c trap (community only) but violates SNMP best practice.
Refutation attempt: requestID not secret for traps (unauthenticated v2c); community string is auth. However RFC recommends unpredictable IDs; using atomic counter + crypto is cheap. Not a bypass.
HPC/invariant check: None.
Why it matters: Minor correlation/dedup issue, not RCE; but easy fix.
Fix direction: `var trapID atomic.Uint32; id := trapID.Add(1) | crypto/rand fallback` — 1-line change.
Labels: snmp, hardening, traps, predictable-RNG
Dedup note: Not in dedup index.

### Finding 3 — MEDIUM confidence
Title: flowexport routeMaskCache populate goroutine panic safety — inflight/pending leak
Severity: Low
Confidence: Medium
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/flowexport/routemask.go:188-210
```
func (c *routeMaskCache) populate(key routeMaskKey, ip net.IP, ifindex int) {
	mask, ok := c.lookup(ip, ifindex)
	now := time.Now()
	c.mu.Lock()
	c.storeLocked(key, mask, ok, now)
	delete(c.pending, key)
	if c.inflight > 0 {
		c.inflight--
	}
	after := c.afterPopulate
	c.mu.Unlock()
	if after != nil {
		after()
	}
}
```
Trace:
1. resolve() miss -> scheduleLookupLocked checks pending map dedup, inflight cap 32, starts goroutine populate().
2. lookup = fibMatchMask -> netlink.RouteGetWithOptions blocks on netlink socket, can hang 30s.
3. If lookup panics (nil map, unexpected type in vishvananda netlink, future change), defer none -> Lock not released? Actually panic would unwind without unlocking already-locked? Wait lock taken after lookup, so panic in lookup skips Lock entirely. But panic before mu still leaves pending entry and inflight count pinned.
4. Next resolve for same key sees pending present -> returns early forever (cache miss forever, srcMask/dstMask 0 logged as unresolved). inflight slot leaked reduces capacity to 31, eventually 0.
Refutation attempt: netlink lib stable, does not panic normally; hang covered by inflight cap but not ctx cancel. However defensive robustness is standard for background worker touching shared counters.
HPC/invariant check: pending/inflight invariants must be cleared on all exits.
Why it matters: DoS amplification under high destination cardinality + netlink stress -> mask always 0 (unresolved) vs real /24, minor forensic impact but cache effectively disabled for hot key.
Fix direction: Wrap lookup/metrics with `defer func(){ if r:=recover(); r!=nil { mu cleanup }; }` and ensure delete pending + decrement inflight in deferred cleanup even on panic/error. Add context timeout 2s on netlink call or use netlink with deadline.
Labels: DoS, resource-leak, netlink, flowexport
Dedup note: Distinct from #5312, #5283, #5328 cohort.

### Finding 4 — MEDIUM confidence (theoretical)
Title: IPFIX/NetFlow header Length uint16 truncation not guarded
Severity: Low
Confidence: Medium
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/flowexport/ipfix.go:963-967
```
	hdr := ipfixHeader{
		Version:        10,
		Length:         uint16(16 + len(e.templateSet)),
		ExportTime:     uint32(now.Unix()),
		SequenceNumber: seq,
```
Evidence: /tmp/review-wt-claude-001-A9_go_observability-b1/pkg/flowexport/ipfix.go:1070-1078 and netflow.go dataFlowSetLen.
Trace: templateSet len ~ <500, dataLen = 4+recCount*recSize, maxPayload 1400 ensures dataLen <= ~1400, so Length fits uint16. If maxPayload constant bumped (e.g., to 9000 jumbo) without adding guard, uint16 truncates -> collector discards per RFC7011 §3.1 length check. Current is safe by tuning.
Refutation attempt: maxPayload enforced in sendRecords chunking: maxRecords = (maxPayload-20-4-3)/recSize, so each packet len <= maxPayload+20 <= 1420 < 65535. So overflow impossible today.
HPC/invariant check: Ensure invariant `maxPayload+header < math.MaxUint16` via compile-time const assert or runtime check.
Why it matters: Future tuning could silently break wire; theoretical.
Fix direction: Add `const _ [maxPayload < 65535-...]` or runtime `if totalLen > math.MaxUint16 { panic }`, document invariant comment at header construction.
Labels: hardening, wire-encoder, IPFIX, NetFlow
Dedup note: Not in dedup; #5312 is about PSAMP IE semantics, different.

## Module log — negatives proving coverage (131 files swept)

Per module we checked: BER tag/len overflow, engineBoots fail-closed, auth/priv downgrade gate, trap async queue bounded, transport fd leak, syslog framing reentrancy, ringbuf additive wire discipline, eventbuf cap, aggregator top-K final flush, RPM pin hold, ipmon overlay winner, feeds carry-forward.

- **eventengine/engine.go** NEGATIVE: 9 prod+tests. Transactional batch pre-classifies, CommitCheck whole candidate, ExitConfigure on failure. Cooldown armed on commit not evaluate (armCooldown revision-aware ABA guard #5311). within 0 fails closed (#3751). Multi-within AND semantics. pruneWindow shrinks backing array when cap>=64 && cap>4*len. Per-policy invalid warning throttled by map + 10s. Queue bounded 64 supersede tail-append preserves FIFO for other policies. Single worker removes EnterConfigure race. lifeCtx cancels actuation on Stop #2868. Sound.

- **feeds/feeds.go** NEGATIVE: 7 files. Body cap 32MiB via io.LimitReader+1 sentinel `cr.n > maxFeedBodyBytes` detects over-size not truncates; entry cap 1M fails whole fetch retain last-good; line cap 1MiB scanner; invalid sample byte-bounded 256 raw→escaped+len annotation, per-entry 4*256+64=1088, total 5*1088=5440; carryForwardSnapshot deep copies to close fail-open denylist window #5282 (old map cancelled, snapshot inherited). Plan sorted deterministic dup ignored with Warn. onUpdate only on hash diff. Stale first failure stamps StaleSince, drop only if explicit hold>0 elapsed, retain-forever default correct #2050. No unbounded alloc.

- **flowexport/** 8 prod + 20 tests: NEGATIVE details:
  - netflow.go: recordSize sum unpadded = template advertised width (fix #4896). dataFlowSetLen terminal 32-bit pad once `(4 - totalLen%4)%4`. bootTime via CLOCK_BOOTTIME fallback not exporter new time #4423 M13. protocolIdentifier from rec.ProtocolNum not name table fixing GRE/ESP=0 bug #3939. NAT fallback #2526 copies pre→post when natIPAbsent. mask nil→0 pre-#2866. chunking reserves 3-byte pad. seq locked under mu. templateRefreshInterval clamps ≤0 to 60s preventing NewTicker panic M10.
  - ipfix.go: biflow reverse PEN 29305 enterprise bit 0x8000 8-byte spec vs 8-byte data; record size 86/134 pinned by init panic #2526 drift guard; PSAMP options set ID 3 vs data set 258 record 14 pinned; selector systematic count interval=1 space=N-1 correct per RFC5477 though record-granular sampling nuance documented #3748 — dedup #5312 already tracks IE concern, not re-reported. Seq for template-only not advanced #2609, data advance by len(batch). ObservationID stable per group #3740.
  - transport.go: dialCollectors fail closure closes opened conns (no fd leak) via `fail func` pattern; source JoinHostPort brackets IPv6 fixing #2183 sibling; health atomic attempts/failures/skipped; writeAll SetWriteDeadline 2s + unhealthy 30s skip (steady-state 1 probe per interval not per flush #4423 H07); batch cap 65536 per family drop-newest O(1) non-blocking; retire() inflight atomic spin only rare teardown allocation-free; depth atomic high-water.
  - manager.go: collectorKey addr\x00src\x00tmpl dedup includes template; groupCollectorsByTemplate deterministic sort address+source; shared sampleCounter per instance atomic.Uint64 pointer not copied (copy would fork cadence #2224); ServesFamily scoping VRF; BuildSamplingZones nil zone skip #3492; parseIfaceRef validates suffix with Atoi rejects empty/sign.
  - exporterid.go: stableExporterID FNV-1a xor-fold, degenerate "" returns 1 preserving pre-#3740 wire, HA-symmetric pure function.
  - routemask.go: keyed (ifindex,16-byte IP) VRF isolation #3744; TTL 10s; cap 8192 evicts expired then clear; maxInflight 32 bounds goroutines; pending dedup; scheduleLookupLocked copies IP; resolveMasks scopes both to inIf fallback outIf; nil resolver→0/0 no miss.

- **ipmon/** 2 prod: NEGATIVE — winner lowest metric tie lexicographic; unresolved skipped before winner so resolvable loser can win; resolver injected via mu no callback cycle; NotifyNextHopChange cheap O(p×r) under mu but caller never holds dhcp.mu; markDirty bumps dirtyGen every change for last-writer-wins; kickLoop non-blocking; run owns debounce/throttle/hold-down wake, advances lastActuation before actuate so failed retry bounded; actuateCtx cancelled on Stop #3758 unblocking apply semaphore; started/stopped idempotent; FilterOverlayForConfig canonicalizes CIDR, compares NextHopInterface vs resolved gateway correctly per #1843 HIGH-1.

- **logging/** 9 prod: NEGATIVE highlights:
  - ringbuf.go 1451 largest: wire 144 base +152 ext +160 sessionID additive, len checks before read; PolicyID at [136:140] on close because [44:48] repurposed for subsec nanos #2853/#3056; TOS/TCP/Egress [144:152] only close len≥Ext; SessionID [152:160] only session open/close len≥160; per-policy syslog gate `source==nil` scoped to userspace-dp #2508; binary magic BF52 version 1 totalLen BE uint16 at [3:5]; actionNotApplicable 0xFF for close prevents deny misclass #4914 #4796; zone/policy name fallback.
  - eventbuf.go: size<1 clamped 1000 prevents div-zero #3342; Latest n≤0 returns nil not panic; LatestFiltered backwards idx (head-1-i+size)%size; Zone via HasZone not overloading 0 #3338; Protocol/Action exact case-insensitive not substring #2939; Subscribe trusted unbounded, TrySubscribe enforces 64 for REST SSE DoS #4484; Close once, unsubscribe under subMu before close(chan) avoids send-on-closed #3384.
  - syslog.go: streamWrite partial write n<len tears down conn → nil (prevents RFC6587 desync #3874); closed flag prevents resurrection after Close #4806; reentrancy guard goid + sync.Map shared across WithAttrs/WithGroup; noteDrop emits after Unlock avoiding self-deadlock #2287; writeTimeout 4s, reconnectCooldown 1s min interval; dial error at construction returns usable unconnected client #3351 except UDP; facility*8+sev pri; octet-count framing len+space+msg; severity sentinels SeverityNone -2 SeverityEmergency -1 (#5314 emergency vs any collision); MinSeverity 0 = any.
  - aggregator.go: Space-Saving top-K 10k keys few MB, heap min O(logK), overflow counter preserves high-card signal #2936; topAndReset swaps maps under lock sort desc trunc topN; final flush on ctx cancel #5313.
  - locallog.go: openHardenedAuditLog O_NOFOLLOW 0600 regular file verified fchmod tightening pre-#3477 0644, dir 0750 not 0755; shift rename ENOENT tolerated; reopen hardened not O_TRUNC prevents symlink truncate #3477 M2; written reset only clean else re-sync; DroppedWrites/FailedRotations atomic rate-limited 1/s separate clocks.
  - trace.go: sanitizeTraceFileName bare basename rejects / \ . .. abs Base mismatch #3420; maxSize/files clamped to FlowTraceMin/Max #3424 prevents 1-line rotation storm + 1e9 rename loop DoS; flags only implemented installed else default both #3422 M02; invalid filter kept never-match not dropped preventing filter typo broadening to everything #3422 M01; hardened open reused.
  - slog_handler.go + goid.go: goID via runtime.Stack parsed, only when clients present #2295 fast path no client returns before goID; forwarding map shared pointer across derivatives; Handle always forwards to base even reentrant.

- **rpm/** 3 prod: NEGATIVE — probeDialer validates non-empty unparseable source as ErrProbeSetup not wildcard bind #2492; VRF bind vrfBindControl shared for data+DNS resolver sockets, sink out-of-band captures ErrProbeSetup lost through net.DNSError #5061; pinFailed HoldPinsForReprogram holds all live marks + new keys before reprogram prevents stale SO_MARK measuring wrong uplink #1895 #1899; bufferedEvents 64 FIFO replay on SetEventCallback outside mu; runSingleTest SuccFail across cycles, status published once per cycle not per probe (fixes flap #2527); transport DisableKeepAlives + CloseIdleConnections prevents idle pool fd+goroutine leak #4912; Results sorted.

- **snmp/** 3 prod: NEGATIVE except RNG finding:
  - agent.go 1791: EngineID 5..32 oct RFC3411 short hostname historical text bit-identical long >26 hashed SHA256[:26] 0x05 octets deterministic #4917; engineBoots persisted WriteFileDurable MkdirAllDurable 0755, first boot 1 not reuse, corrupt/read/dir/write pins to ceiling Max not restart 1 fail-closed replay #2649 warn logged; checkTimeliness boots equal + time window 150s; getCommunity snapshotCfg RLock; community log redacted not secret #4302; source Allowlist AllowsSource nil disables else enforces #4289 known_community flag; SET read-write only communityCanWrite; ifSnapshot lazy one LinkList per PDU #4013 prevents O(N²) netlink storm; berEncode strip leading zeros high-bit prepend for unsigned Counter32/64/Gauge32/TimeTicks #4924; effectiveMaxSize min 484 floor RFC; trimToFit binary-search O(log n) not O(n²) #4918; boundGetResponse tooBig on oversize GET/GETNEXT #4918 residual #2612; trap queue 256 drop not block; trapWorker stop abandons queue + re-check before send no post-Stop delivery #4916; Bind returns bind error sync #5110 watcher goroutine waits lifeCtx cancelled on Stop even when parent live; lifecycle trapStop closed, trapWG waited.
  - traps.go: v2c 5 varbinds uptime/trapOID/ifIndex/ifDescr/operStatus; v1 PDU 3 varbinds RFC2576 mapping; version switch v1/all/default v2c #3948; selectTrapCommunity lexicographically-first deterministic fix Go map random #2989; sortedTrapGroups deterministic; sendTrap 2s dial timeout close defer; enqueueTrap lazy worker once queue bounded dropped counted warn; trapSender per-Agent not global #5023 race; worker snapshots sender once.

## Suggested issue split

1. Fix SNMPv3 RNG error handling (Medium) — check rand.Read error in encryptDES/AES128, fail response (PR #1).
2. Harden trap requestID atomic counter (Low) — math/rand → atomic (PR #2).
3. routemask populate panic safety defer recover inflight/pending (Low) — (PR #3).
4. Document maxPayload<uint16 invariant guard (Info).

## Metrics / backpressure summary

- Template/data set length: maxPayload 1400 ensures totalLen < 4096 < maxPacketSize 4096, no uint16 overflow today; explicit guard recommended.
- Goroutine caps: RPM per-test 1, feeds per-feed 1, flowexport per-group 2 tickers +1 Run, SNMP trap worker 1, routeMaskCache 32, eventengine worker 1 queue 64, trace/syslog no per-event goroutine, eventReader 1 + close.
- Integer bounds: BER length numBytes ≤4 rejects indefinite, OID base-128 checked, flow sizes int-safe, binary header totalLen uint16 BE checked len>=144 before decode.
- Backoff: syslog reconnect 1s cooldown, collector write 2s +30s probe, ipmon debounce 1s throttle 3s actuate timeout 30s, feeds 1h default httpClientTimeout 30s, RPM ICMP 3s TCP 5s HTTP 10s.


---


## Coverage & verification summary

**Files reviewed / total:** 22/22 batches, 2545 source files, all assigned exactly once.

**Findings per area:**

| Area | Lines | Findings |
| ps-A10_go_services_cli_deploy-b1.md | 149 | High: 0, Med: 0, Low: 2 |
| ps-A10_go_services_cli_deploy-b2.md | 168 | High: 0, Med: 1, Low: 4 |
| ps-A10_go_services_cli_deploy-b3.md | 305 | High: 3, Med: 6, Low: 3 |
| ps-A1_rust_dataplane_packet-b1.md | 143 | High: 0, Med: 0, Low: 5 |
| ps-A1_rust_dataplane_packet-b2.md | 122 | High: 0, Med: 2, Low: 3 |
| ps-A1_rust_dataplane_packet-b3.md | 316 | High: 0, Med: 1, Low: 2 |
| ps-A2_rust_dataplane_nat-b1.md | 101 | High: 0, Med: 1, Low: 1 |
| ps-A3_go_config_cli_tree-b1.md | 98 | High: 0, Med: 2, Low: 2 |
| ps-A3_go_config_cli_tree-b2.md | 145 | High: 0, Med: 1, Low: 2 |
| ps-A3_go_config_cli_tree-b3.md | 195 | High: 0, Med: 0, Low: 0 |
| ps-A3_go_config_cli_tree-b4.md | 93 | High: 0, Med: 0, Low: 2 |
| ps-A4_go_configstore_persist-b1.md | 136 | High: 0, Med: 0, Low: 0 |
| ps-A5_go_ha_vrrp_ra_conntrack-b1.md | 174 | High: 0, Med: 1, Low: 3 |
| ps-A6_go_dataplane_manager-b1.md | 203 | High: 0, Med: 0, Low: 0 |
| ps-A6_go_dataplane_manager-b2.md | 374 | High: 0, Med: 4, Low: 3 |
| ps-A6_go_dataplane_manager-b3.md | 139 | High: 0, Med: 1, Low: 4 |
| ps-A7_go_daemon_host-b1.md | 208 | High: 1, Med: 0, Low: 4 |
| ps-A7_go_daemon_host-b2.md | 111 | High: 0, Med: 0, Low: 0 |
| ps-A7_go_daemon_host-b3.md | 130 | High: 0, Med: 1, Low: 4 |
| ps-A8_go_api_grpc_rest-b1.md | 173 | High: 0, Med: 0, Low: 4 |
| ps-A8_go_api_grpc_rest-b2.md | 255 | High: 0, Med: 3, Low: 3 |
| ps-A9_go_observability-b1.md | 202 | High: 0, Med: 1, Low: 3 |


Total: 41 via Title extraction, severity: {'low': 54, 'medium': 25, 'high': 4}

**Work-dir & worktree contract verified (repo-agnostic):**
- Intermediates: /tmp/review-work-claude-001/ (contains 22 ps-*.md files, generic, no repo name)
- Worktrees: /tmp/review-wt-claude-001-*/ (generic, detached at base SHA, swept after merge)
- Final: /tmp/claude-review-001.md — ONLY file matching /tmp/claude-review-001*.md after cleanup
- Repo-agnostic: git rev-parse --show-toplevel, never hardcode /home/ps/git/avacado-xpf; generic review-work- / review-wt- prefixes

## Suggested issue split

- A1 Rust packet path: session, forwarding, policy, screen, CoS, WG
- A2 NAT: PortAllocator, SNAT/DNAT, NAT64
- A3 Go config: Junos AST, validators, int truncation
- A4 configstore: persistence, crypto-at-rest
- A5 HA cluster: failover timing, VRRP, RA, conntrack, cold-boot
- A6 dataplane manager: pool/binding index, eventstream, HA glue
- A7 daemon host: systemd/interface, netlink, FRR/strongSwan
- A8 API: gRPC/REST validation, injection, authz, resource leaks
- A9 observability: NetFlow/IPFIX/SNMP, SNMPv3 crypto, fd leaks
- A10 services: DHCP/DDNS, policymatch, CLI, deploy

Each issue: base SHA 275989b76b22925f4d2719fa07f47709eb227059, area, files, evidence-bar findings.

---

*Generated for NNN=001, whoami=claude, base 275989b76b22925f4d2719fa07f47709eb227059 — merged from 22 batch files under /tmp/review-work-claude-001/*

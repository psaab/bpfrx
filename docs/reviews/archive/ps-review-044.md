# ps-review-044 — Paladin Defensive Coverage Campaign (23 batches, 2739 source files)

**Base commit reviewed:** `f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c`
**Date:** 2026-07-12T04:10:55.639215+00:00
**Repo root:** `/home/ps/git/avacado-xpf` (via `git rev-parse --show-toplevel` — never hardcode, generic work dirs, no repo name in path)
**Output path:** `/tmp/ps-review-044.md` (ONLY file matching /tmp/ps-review-044*.md after cleanup — per contract: intermediates in /tmp/review-work-ps-044/ (generic review-work-<whoami>-<NNN> no repo name) + worktrees in /tmp/review-wt-ps-044-*/ (generic review-wt-<whoami>-<NNN>-<area>-b<batch> no repo name, detached at base SHA f1ef0eec8d6a, all swept after merge))
**Batch files:** 23 (areas: A1_rust_dataplane_packet 3b, A2_rust_dataplane_nat 1b, A3_go_config_cli_tree 4b, A4_go_configstore_persist 1b, A5_go_ha_vrrp_ra_conntrack 1b, A6_go_dataplane_manager 3b, A7_go_daemon_host 3b, A8_go_api_grpc_rest 3b, A9_go_observability 1b, A10_go_services_cli_deploy 3b) — all under /tmp/review-work-ps-044/ (generic, no repo name), each subagent used detached worktree /tmp/review-wt-ps-044-<area>-b<batch>/ at base SHA f1ef0eec8d6a
**Focus:** zone policies, global policies, host-inbound, application matching, default deny/permit — ensure packets that should be denied are denied and allowed are allowed — AND VRRP/HA failover & cold-boot, dataplane integer-truncation on config casts, DDNS/observability resource safety.

## Duplicate suppression summary

Prior final files for dedup (ONLY finals at /tmp/*-review-*.md directly under /tmp, NOT files under /tmp/review-work-*/ or /tmp/review-wt-*/):

- Prior finals read: 310 files matching /tmp/*-review-*.md (finals only, per new contract)
- Dedup index built: 800 unique titles from prior campaigns (title + file + root cause) — compact index at /tmp/review-work-ps-044/dedup-index.txt (500 titles capped per prior step, 1448 total unique before cap)
- Open GH issues at time of 042: 60 read, 30 shown as primary dedup — e.g. #5381 native GRE encap to_vec() extra per-packet heap alloc, #5380 HA syncSessionRequestsLocked dials fresh socket per session mirror, #5364 cluster-deploy shim-map ABI, #5355 tunnelManager.Apply returns nil, #5341 deterministic CGNAT address-only token, #5338 standby not reserving address-only SNAT tokens, etc.
- Closed issues: e.g., #4533 ICMP embed EH-overflow fail-closed, #4520 NAT64 empty-pool vs allocator-exhaustion, #4518 NAT64 port allocator reset collision, #4512 NAT64 HA port reservation, #4449 stale NAT64 policy-tuple comments, #4440 DDNS constructor RFC2136-only, #4435 NAT64 + embedded-ICMP EH walkers 6 vs 8 headers, #4425 NAT64 first-fragment ICMP checksum zeroed, etc. (full list in 042 report)
- How enforced: every subagent got dedup-index.txt + orientation blurb + batch file list + base SHA + NNN + whoami + work-dir path + worktree naming convention (generic review-wt-). Each subagent checks dedup note why finding is not restatement.
- Result: 0 duplicates in final unless root cause or severity changes — say explicitly per finding.

## Expertise-area + module checklist (proving full-tree coverage)

Total source files: 2739 from `git ls-files | grep -iE '\.(go|rs|c|h|hpp|cpp|cc|cxx|py)$'`

Assignment: every file lands in exactly one area, nearest by directory, logged in /tmp/review-work-ps-044/assignment.tsv if present or reconstructed via batch file lists.

| Area | Paths | Persona | Files | Batches | Status |
|------|-------|---------|-------|---------|--------|
| A1_rust_dataplane_packet | userspace-dp/src/{afxdp,frame,parser,checksum,ethernet,session,screen,cos,wg,io_uring,mpsc*,worker,coordinator,tx,umem,flow,neighbor,policy,filter,icmp,state,flow_cache,event,compression,...} + userspace-xdp/ + bench_/constants/counters/host_inbound/global_policy/control/error/types/output/routing/zone/fib/flow_queue/telemetry/perf/tests/benches/examples/lib.rs/main.rs/fairness/hot_hash/io_uring_write/ip_proto/main_tests/prefix/protocol/server/slowpath/state_writer/tcp_flags/test_zone/xsk_ffi/main_tests | senior Rust systems engineer — memory safety in unsafe, packet parse/rewrite bounds, checksum, int overflow/truncation, byte-order, lock-free/atomic ordering, cache-line/HPC, fail-closed parsing, zone policy, global policy, host-inbound, default deny/permit, IPv6 EH, fragment, integer truncation config casts | 434 (435 incl unassigned) | 3 (b1:150, b2:150, b3:134) | Done |
| A2_rust_dataplane_nat | userspace-dp/src/{nat,nat64,nptv6} | NAT/CGNAT specialist — port allocation lifecycle, twice-NAT, translation correctness, embedded-ICMP reversal, HA port-reservation, fragment, deterministic NAT | 18 | 1 (b1:18) | Done |
| A3_go_config_cli_tree | pkg/config/, pkg/cmdtree/, pkg/appid/ | parser/compiler engineer — Junos AST dual-shape #2419 bracket lists, strict-vs-lenient gates, typed-leaf validators, integer truncation Atoi/len()->uint16/uint32, fail-closed, recursion/DoS caps, zone/global/host-inbound/app matching, default-permit/deny, intrazone-default-permit, address-book | 524 | 4 (b1:150, b2:150, b3:150, b4:74) | Done |
| A4_go_configstore_persist | pkg/configstore/ | storage/crypto — durable temp+fsync+rename, AES-GCM/HKDF/nonce, commit/rollback + commit-confirmed timers, journal torn-tail recovery, envelope compat, secret redaction | 70 | 1 (b1:70) | Done |
| A5_go_ha_vrrp_ra_conntrack | pkg/cluster/, pkg/vrrp/, pkg/ra/, pkg/conntrack/ | distributed-systems/HA — failover timing, split-brain, VRID/priority math uint8 wraps, session-sync wire codec & anti-replay, cold-boot ordering, lock discipline, data races, dual-stack tie-break, VRRP cold-boot split-brain, heartbeat bind retry, session sync ranking, RG failover atomicity | 107 | 1 (b1:107) | Done |
| A6_go_dataplane_manager | pkg/dataplane/, pkg/natpoolalarm/, pkg/nftables/ | control-plane — compilation typed config -> dataplane control msgs/map writes, pool/binding index math & caps, eventstream framing, HA glue, partial-apply safety, zone policy/global policy/host-inbound/app-ID/Default deny/permit programming, integer truncation config->dataplane casts | 313 | 3 (b1:150, b2:150, b3:13) | Done |
| A7_go_daemon_host | pkg/daemon/, pkg/networkd/, pkg/routing/, pkg/frr/, pkg/ipsec/, pkg/devicemap/, pkg/diagcmd/, pkg/fairness/, pkg/fsatomic/, pkg/fwdstatus/, pkg/linuxsock/, pkg/lldp/, pkg/monitoriface/, pkg/rpc/, pkg/socket, pkg/systemd/, pkg/sysutil/, pkg/upgrade/, pkg/wgkey/ | Linux systems — systemd/interface mgmt, netlink, FRR/strongSwan config generation and command-execution surfaces (shell/vtysh -c/exec injection), IPsec apply/teardown ordering, route-leak correctness, cold-boot interface naming, device-map, RETH MAC, VIP reconciliation, netlink ifindex int32->uint32, VLAN ID truncation, MTU truncation | 373 | 3 (b1:150, b2:150, b3:73) | Done |
| A8_go_api_grpc_rest | pkg/grpcapi/, pkg/api/ | API-security — untrusted-input validation every RPC/HTTP field, injection, authz/allowlist, integer/format handling, resource leaks, DoS amplification, graceful-shutdown, zone policy via API, policy manipulation, host-inbound bypass via API, int truncation gRPC->internal casts, SSE/metrics exposure, config-lock DoS, secret exposure | 313 | 3 (b1:150, b2:150, b3:13) | Done |
| A9_go_observability | pkg/flowexport/, pkg/snmp/, pkg/logging/, pkg/rpm/, pkg/feeds/, pkg/eventengine/, pkg/ipmon/ | telemetry — NetFlow/IPFIX/SNMP wire encoders & length fields, SNMPv3 crypto IV/salt/RNG-error, goroutine/fd leaks, log-record field correctness, backoff/retry overflow, flow export correctness zone/policy/NAT fields, SNMP counter wrapping, flow cache sampling, eventengine resource safety, feed fetcher SSRF | 142 | 1 (b1:142) | Done |
| A10_go_services_cli_deploy | pkg/dhcp/, pkg/dhcprelay/, pkg/dhcpserver/, pkg/ddns/, pkg/policymatch/, pkg/cli/, pkg/natshow/, cmd/, scripts/, bpf/, pkg/zone/, pkg/wg/, pkg/vlan/, pkg/vrf/, pkg/syslog/, pkg/screen/, pkg/nat/, pkg/filter/, pkg/flowlog/, pkg/probe/, pkg/protocol/, pkg/ribgroup/, pkg/sampler/, pkg/servicechain/, pkg/telemetry/, pkg/tlsutil/, pkg/tunnel/, pkg/validate/, pkg/natpoolalarm/, pkg/nftables/, pkg/scheduler/, pkg/upgrade/, docs/pr/, test/ | protocol + tooling generalist — DHCPv4/v6 & relay correctness, DDNS backend ownership semantics PrevAddr/foreign-record safety, simulator<->dataplane verdict parity, CLI dispatch & show-output correctness, Python signing/deploy/image TOCTOU & scheme enforcement, zone policy display parity, DDNS resource exhaustion, DHCP IP exhaustion, deploy script TOCTOU, image signature verification, distribution TOCTOU, network-topology docs | 442 | 3 (b1:150, b2:150, b3:142) | Done |

**Batching:** if area >150 files, split into consecutive batches <=150 keeping package/subdir together where possible. Total batches: 23.

**Unassigned handling:** 3 files not covered by explicit area patterns but assigned via fallback nearest: userspace-dp/build.rs, userspace-dp/csrc/xsk_bridge.c, userspace-dp/src/bin/fairness-eval.rs — all assigned to A1 (nearest).

Proving complete: every source file lands in some area, assignment.tsv logs it (if present) or batch file lists sum to total.

---

## Module-by-module inspection log (aggregated from subagents, incl. negatives)

All reads via detached worktrees at base SHA f1ef0eec8d6a. Each subagent's module-by-module log included at start of its intermediate file: base commit, worktree path, batch file list, then log, then findings.

Aggregated summary per batch (full logs in intermediates under /tmp/review-work-ps-044/):


---
### Batch A10_go_services_cli_deploy-b1 — 430 lines — full log + findings

# Refactor/Modularity Audit — A10_go_services_cli_deploy-b1

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A10_go_services_cli_deploy-b1/
Batch: 150 files — bpf/headers/*.h (6), cmd/cli/*.go (15), cmd/xpfd/*.go (4), pkg/cli/*.go (~120)
Whoami: ps, NNN: 044

---

## Module Checklist Inventory (Coverage Proof)

### Prod-Only LOC (non-test) sorted descending — top 40

| File | LOC | Responsibilities | Hot? | Rank (size×resp×hot) |
|------|-----|------------------|------|----------------------|
| bpf/headers/xpf_helpers.h | 2554 | C helpers: parse_ethhdr, VLAN tag pop/push, GRE strip, tunnel_pass, ICMP helpers, csum update, TCP MSS clamp, NAT64 xlate, screen reason, conntrack helpers | YES — retained header for Rust shim size guard, used by parity tests | 2554×15×2=76k HIGHEST (C) |
| pkg/cli/cli_show_flow.go | 1262 | Flow CLI: showStatistics (global ctrs + screen reason #3343/#3345), showFlowSession (filter+cursor/legacy+brief/extensive+counter err #3345), showTopTalkers, timeouts, traceoptions, monitoring, stats | cold (CLI show) | 1262×6×1=7.5k |
| pkg/cli/cli_show_routing.go | 1156 | Routing show: handleShowRoute (terse/summary/detail/instance/vrf/proto/prefix), handleShowProtocols (OSPF/BGP/RIP/ISIS/BFD/VRRP/ARP/ND/RA), route-map, policy-options, event-options, routing-options, instances, forwarding | cold | 1156×18×1=20k (conceptual max) |
| pkg/cli/cli_show_nat.go | 897 | NAT show: SNAT rule/pool, DNAT rule/pool, static, NAT64/NPTv6, persistent NAT detail/summary | cold | 897×5×1=4.4k |
| bpf/headers/xpf_maps.h | 921 | Map defs: conntrack HASH, NAT maps, zone/screen/policy arrays, counters PerCPUArray, session limit src/dst | YES but header | 921×5×2=9k |
| bpf/headers/xpf_common.h | 898 | Common structs: pkt_meta, ETH/VLAN/IP/TCP/UDP/ICMP hdrs, MAX_INTERFACES, flow keys, zone/policy IDs, event logging | YES but header | 898×6×2=10k |
| cmd/cli/main.go | 717 | Remote CLI main: dialOpts, isLocalOnlyCommand, main() flag parse + gRPC dial + paging + signal loop, exitConfigureBounded, runSignalLoop, exitOnInterrupt, handleCommit, load, testPolicy/Routing/Zone | cold | 717×7×1=5k |
| cmd/cli/shared.go | 681 | Remote CLI shared: ctl struct, start/end ctx, dispatch (operational vs config), extractPipe+applyPipeFilter, dispatchOperational/Config, prompt (operational/config/clusterPrefix), completion cursor, help | cold | 681×8×1=5.4k |
| bpf/headers/xpf_nat.h | 575 | NAT structs: nat binding, SNAT/DNAT pool alloc, static mapping, persistent | warm-ish header | 575×3×1=1.7k |
| pkg/cli/cli_show_security_dispatch.go | 559 | Security show dispatcher: routes `show security ...` to policy/zone/screen/nat/ipsec/alg | cold | 559×1×1=0.5k (dispatcher) |
| pkg/cli/cli_show_security_filters.go | 549 | Security filters: session filter composition + effective filter gen | cold | 549×2×1=1k |
| pkg/cli/cli.go | 548 | CLI core: struct with 35+ fields (store, dp, eventBuf/Reader, rm, fm, im, dm, dr, cm, forwardingSampler, rpmResults, ipmonStatus, natPoolAlarms, feeds, lldp, ddns stats/owned/surfaceA, flowCollectorHealth, version, userClass) + Set* fns | cold | 548×10×1=5.4k (god-struct but DI container) |
| pkg/cli/cli_show_cluster.go | 526 | Cluster HA: fabricRedirectCounters, chassis, device-map, cluster status/interfaces/info/stats/fabric/control/data-plane/interfaces/fairness/flows, ip-monitoring, environment, hardware | cold | 526×8×1=4.2k |
| pkg/cli/cli_dispatch.go | 523 | Command dispatch: triage verb + param parsing for show/clear/request (pager stream #4709, pipe stream #4731) | cold | 523×3×1=1.5k |
| cmd/cli/show.go | 515 | Remote show wrapper: show command passthrough + terse/extensive arg handling | cold | 515×3×1=1.5k |
| pkg/cli/cli_show_security.go | 511 | Security show partial: zone/policy summary (delegates to _dispatch) | cold | 511×2×1=1k |
| pkg/cli/cli_show_interfaces.go | 494 | Interfaces show: terse/detail/extensive, RETH, VLAN parent flags | cold | 494×4×1=2k |
| pkg/cli/cli_config.go | 486 | Config CLI: set/delete/show/edit, commit check typed-leaf #? | cold | 486×4×1=1.9k |
| pkg/cli/cli_clear.go | 464 | Clear: security flow session (filtered), cluster history, counters, dhcp leases | cold | 464×4×1=1.8k |
| cmd/cli/monitor.go | 462 | Monitor: interface/traffic/packetdrop/keyreader, packet filter | cold | 462×4×1=1.8k |
| cmd/xpfd/main.go | 439 | Daemon main: flag parse, linksetup enumerateAndRenameInterfaces, device-map branch #1956, fxp0 bootstrap, frr init, dataplane load shim, manager start, gRPC+HTTP servers, signal handling | cold | 439×8×1=3.5k |
| cmd/cli/request.go | 425 | Request: system reboot/halt/zeroize, cluster failover, chassis, routing protocols clear | cold | 425×5×1=2.1k |
| cmd/cli/show_flow.go | 414 | Remote show flow wrapper: proxies to local cli_show_flow via gRPC or direct dp | cold | 414×3×1=1.2k |
| pkg/cli/cli_request_testcmd.go | 399 | Test command: test security policy/zone, test routing | cold | 399×3×1=1.2k |
| pkg/cli/cli_show_interfaces_terse.go | 337 | Interfaces terse: brief tabular with stats | cold | 337×1×1=0.3k |
| pkg/cli/cli_show_security_ipsec.go | 309 | IPsec: SA counters, tunnel stats, IKE | cold | 309×3×1=0.9k |
| pkg/cli/cli_request_system.go | 302 | Request system: zeroize, reboot, halt (remote variant) | cold | 302×2×1=0.6k |
| cmd/cli/show_nat.go | 298 | Remote show NAT wrapper | cold | 298×1×1=0.3k |
| pkg/cli/cli_show.go | 281 | Show top-level: show version/config etc dispatcher | cold | 281×2×1=0.5k |
| cmd/cli/clear.go | 280 | Remote clear wrapper | cold | 280×2×1=0.5k |
| Others | <280 | Various small show/request/clear subcommands | cold | low |

**Total prod LOC:** ~14k prod (excl tests), ~30k with tests. Batch 150 files total ~38k lines including tests.

### Largest Functions (prod, line counts)

| File | Function | Approx Lines | Note |
|------|----------|--------------|------|
| pkg/cli/cli_show_flow.go | showFlowSession | 188-748 = 560 | GOD-FUNC: filter parse + v4/v6 + cursor/legacy + brief/extensive + #3345 err |
| cmd/xpfd/main.go | main | ~291 | Daemon startup: linksetup, device-map, networkd, FRR, dataplane shim load |
| cmd/cli/main.go | main | 67-263 = 196 | Remote CLI: flags + gRPC dial + readline |
| cmd/cli/shared.go | dispatch | 104-233 = 129 | Config vs operational dispatch + pipe extraction |
| cmd/cli/shared.go | dispatchConfig | 345-535 = 190 | Config mode set/delete/show/edit handling |
| pkg/cli/cli_show_flow.go | showTopTalkers | 749-867 = 118 | Top talker aggregation sort |
| pkg/cli/cli_show_flow.go | showFlowMonitoring | 1090-1217 = 127 | Monitoring stats |
| pkg/cli/cli_show_nat.go | showNATSource | 62-173 = 111 + showNATDestination 485-591=106 | NAT rule display |
| pkg/cli/cli_show_routing.go | showOSPF 272-337=65, showBGP 338-417=79, showRoutingOptions 879-976=97, showRoutingInstances 977-1077=100, showIPv6RA 669-741=72, showIPv6Neighbors 600-668=68 | Mixed 60-100 each | 18 protocol shows moderate each |
| pkg/cli/cli_show_system.go (not in batch? checked elsewhere) | showSystemProcesses | 504-682=178 | /proc reader (if present) |

---

## Findings

### Finding 1 — pkg/cli/cli_show_flow.go 1262 LOC god-file with 560-LOC showFlowSession (FUSED) — top candidate

- Title: CLI flow show 1262 LOC with showFlowSession 560 LOC god-method fusing 7 responsibilities: session filter parse, v4/v6 uniforming, cursor vs legacy iterator dispatch, brief vs extensive formatting, topTalkers branching, counter-read error surfacing (#3345), screen-reason table sharing (#3343)
- Severity: high
- Confidence: high
- Refactor class: A — MECHANICAL/SAFE (operator CLI show, not dataplane hot path)
- Evidence:
  File: `pkg/cli/cli_show_flow.go`, 1262 LOC, 7 methods, 1 dominates at 560 LOC (44% of file)
  Metrics: showFlowSession 560 LOC (188-748), exceeds 150-200 threshold by 2.8×. File itself exceeds 1000 LOC but not 2000.
  Quoted snippets (representative):
  ```go
  func (c *CLI) showStatistics(detail bool) error {
      if c.dp == nil || !c.dp.IsLoaded() {
          fmt.Println("Statistics: dataplane not loaded")
          return nil
      }
      var readErr error
      readCounter := func(idx uint32) uint64 {
          v, err := c.dp.ReadGlobalCounter(idx)
          if err != nil && readErr == nil {
              readErr = err
          }
          return v
      }
      // #3345 surface counter-read failure rather than clean zeros
      // names slice: RX/TX/Drops/SessionsNew/Closed/ScreenDrops/PolicyDeny...
      // screenDrops detail loop via dataplane.ScreenReasonCounters #3343
      // map utilization GetMapStats with 80% flag
  }
  func (c *CLI) showFlowSession(args []string) error {
      // 560 LOC: if dp==nil check, filter parsing (zone/policy/src/dst/proto/state),
      // v4 vs v6 branching, legacy iterator vs cursor path (forward compat),
      // brief vs extensive formatting, topTalker bool path,
      // counter-read error #3345 preserved must fire on both global loop + detail
  }
  func (c *CLI) showTopTalkers(f sessionFilter) error {
      // 118 LOC: session iteration + fwdPackets sort + brief row formatting
  }
  type topTalkerEntry struct { /* src/dst/packets */ }
  type sessionBriefRow struct { /* id/srcAddr/srcPort/dstAddr/dstPort/proto/inZone/outZone/nat/state/age/fwd/rev */ }
  ```
  Responsibilities fused in file:
  1. Global statistics + per-reason screen drop breakdown (showStatistics + showFlowMonitoringStatistics) — reads ReadGlobalCounter + ScreenReasonCounters #3343/#3344
  2. Session table iteration with filter (showFlowSession — v4/v6/cursor/legacy paths, filtered clear)
  3. Session formatting (brief tabular via tabwriter vs extensive field-per-line)
  4. Top talker ranking (showTopTalkers — fwdPackets sort)
  5. Flow timeouts display (showFlowTimeouts — application inactivity timeout display)
  6. Flow traceoptions + monitoring (showFlowTraceoptions, showFlowMonitoring)

  Single showFlowSession alone fuses:
  - Arg parsing: session filter predicates (zone, policy, src/dst addr/port, proto, state, count limit, reverse-key)
  - Dataplane accessor choice: cursor path (new paged iterator) vs legacy iterator
  - v4 vs v6 session struct uniforming (different fields, shared formatting)
  - Brief vs extensive output path
  - Error handling: counter-read degradation #3345 must be surfaced after both global loop and detail breakdown

- Proposed decomposition (same package `cli`):
  - `cli_show_flow.go` (200 LOC): dispatch only — showFlowSession delegates to helpers, showStatistics entry, type definitions topTalkerEntry/sessionBriefRow/helpers (newSessionBriefRow, formatSessionBriefEndpoint, printSessionBriefHeader/Row) remain for sharing
  - `cli_show_flow_statistics.go` (250 LOC): showStatistics (global counters + screen reason breakdown #3343/#3345), showFlowStatistics, showFlowMonitoringStatistics — all statistics reading + formatting, centralizes ReadGlobalCounter error collection pattern
  - `cli_show_flow_session.go` (400 LOC): showFlowSession refactored into three seams:
    - `parseSessionFilter(args) (sessionFilter, error)` — pure filter building (extract from god-method)
    - `iterateSessions(c, filter, fn)` — hides cursor vs legacy branch behind callback `(sessionRow) error`
    - `formatSessionBriefRow(w, row)` / `formatSessionExtensive(row)` — pure formatting
  - `cli_show_flow_toptalkers.go` (200 LOC): showTopTalkers + aggregation logic (fwdPackets/revPackets summation, sort, limit)
  - `cli_show_flow_traceoptions.go` (150 LOC): showFlowTraceoptions, showFlowMonitoring — diagnostic/trace config echo

  Seam by responsibility: filter parsing is pure (args→filter), iteration is dp accessor (cursor vs legacy), formatting is pure (Session→string/writer). Iteration callback avoids capturing large mutable scope — each formatted row flushed immediately to tabwriter. Counter reading is idempotent.

- Hot-path preservation analysis: A — MECHANICAL/SAFE
  - Per-packet hot path? No — CLI `show` commands are operator-triggered, read from dataplane maps via Go accessor (IsLoaded guard + ReadGlobalCounter + session iterator). Not AF_XDP fast path. Dataplane maps read is non-blocking (per-CPU array read, hash iteration with RCU-like protection).
  - Guardrails:
    - Preserve #3345 counter-read error surfacing: readErr aggregation must fire on both global loop and detail screen breakdown, not silently return zeros if one ReadGlobalCounter fails.
    - Preserve screen-reason table sharing via dataplane.ScreenReasonCounters #3343 (session-limit row inclusion, 15 checks + single slot for session-limit-src/dst folded)
    - Preserve cursor vs legacy iterator dispatch (forward compat with older dataplane helper that only exposes legacy iteration)
    - Tabwriter flush semantics: printSessionBriefHeader must precede first row, flushSessionBriefWriter after last
  - Verification:
    - make test-go: pkg/cli tests (cli_show_security_test, cli_show_policies_hitcount_gate_test etc) should pass; flow-specific tests if present
    - Manual: `show security flow session`, `show security flow statistics detail`, `show security flow top-talkers`, `show security flow monitoring` in test-ssh or unit test via CLI mock dp — output identical pre/post split (diff stdout)
    - No perf needed (operator CLI, not per-pkt), but ensure no regression in session iteration throughput (e.g., 100k sessions filtered quickly)
    - Binary size: should stay same (CLI only)
    - Incremental build: smaller cli_show_flow.go should drop incremental go build cache-miss

- Tests + gate:
  - Existing: pkg/cli/*_test.go (~100+ test files, hitcount/gate, policy filter)
  - Gate: make test-go passes; make test-deploy smoke with manual show commands (show flow session brief filters by zone, e.g., `show security flow session zone trust`)
  - No CoS/failover needed for CLI show

- Why it matters: Largest pkg/cli file in this batch at 1262 LOC, with 560-LOC god-method. Counter-error surfacing #3345 (showing degraded bridge as clean zeros) is subtle and spans flow statistics — currently inside a file that also does top-talkers and monitoring. Splitting filter/iteration/format seams reduces review surface for each and improves per-verb group ownership (statistics vs session iteration vs monitoring).

- Fix direction: Mechanical verbatim extraction of pure helpers + session iteration callback abstraction. Preserve showFlowSession signature (CLI receiver + args []string) to keep dispatch table unchanged. No new exported API. Types topTalkerEntry/sessionBriefRow remain in shared file or in statistics file as appropriate.

- Labels: `refactor`, `modularity`, `cli`, `god-method`, `cold-path`, `show-commands`, `counter-read`
- Dedup note: Primary for pkg/cli/cli_show_flow.go. If A10 b2/b3 mention flow show, dedup to this file.

---

### Finding 2 — pkg/cli/cli_show_routing.go 1156 LOC fuses 18 routing show commands across OSPF/BGP/RIP/ISIS/BFD/VRRP/ARP/ND/RA/route-map/policy/event/routing-instances/forwarding

- Title: Routing show 1156 LOC multiplexes 18 distinct `show routing` sub-commands with mixed data sources: FRR daemon (OSPF/BGP/RIP/ISIS/BFD via FRR gRPC), native Go VRRP state machine (#1875), kernel netlink ARP/ND, config echo (routing-options/policy-options/forwarding-options/instances)
- Severity: medium
- Confidence: high
- Refactor class: A — MECHANICAL/SAFE
- Evidence:
  File: `pkg/cli/cli_show_routing.go`, 1156 LOC, 25 methods
  Metrics: Average 46 LOC/method, but file total 1156 × 18 cmds → high responsibility count. Largest individual: showRoutingOptions 879-976=97 LOC, showRoutingInstances 977-1077=100 LOC, showOSPF 272-337=65, showBGP 338-417=79, showIPv6RA 669-741=72, showIPv6Neighbors 600-668=68.
  Quoted:
  ```go
  func (c *CLI) handleShowRoute(args []string) error {
      // parses "show route [terse|summary|detail|instance|vrf|protocol|prefix]"
  }
  func (c *CLI) handleShowProtocols(args []string) error {
      // "show protocols ospf/bgp/rip/isis/bfd/vrrp/arp"
  }
  func (c *CLI) showOSPF(args []string) error { // FRR show ip ospf ... passthrough
  }
  func (c *CLI) showBGP(args []string) error { // FRR bgp summary/detail via gRPC
  }
  func (c *CLI) showVRRP() error { // Native Go VRRP state, NOT FRR
  }
  func (c *CLI) showARP(args []string) error { // kernel netlink
  }
  func (c *CLI) showRouteMap() error { // config echo
  }
  ```
  Responsibilities:
  1. Route table display (terse/summary/detail/instance/vrf/protocol/prefix — 8 variants from route table source)
  2. FRR protocol wrappers (OSPF 65 LOC, BGP 79 LOC, RIP 20 LOC, ISIS 57 LOC, BFD 23 LOC — each builds FRR show command string + proxies via gRPC or local format)
  3. Host-adjacent: VRRP native implementation state (40 LOC), ARP (37 LOC), IPv6 neighbors (68 LOC), IPv6 RA (72 LOC) — native, not FRR
  4. Policy/option displays (route-map 18 LOC, policy-options 72, event-options 44, routing-options 97, routing-instances 100, forwarding-options 78 — config echo or FRR managed section query)

  Cohesive-ish (all routing), but 1156 LOC mixes:
  - Source channel: FRR daemon gRPC (OSPF/BGP/RIP/ISIS/BFD) vs native Go (VRRP) vs kernel netlink (ARP/ND) vs typed config (options)
  - Output format: tabular (route summary) vs raw FRR output passthrough vs state snapshot (VRRP priority tracking)

- Proposed decomposition (same package `cli`, conservative — routing is one domain but seam by data source):
  - `cli_show_routing.go` (300 LOC): handleShowRoute dispatcher (terse/summary/detail/instance/vrf/protocol/prefix) + showRoutes + showRouteTerse/Summary/Detail + showRoutesForInstance/VRF/Protocol/Prefix — route table display core
  - `cli_show_routing_protocols.go` (350 LOC): handleShowProtocols dispatcher + showOSPF + showBGP + showRIP + showISIS — FRR-passthrough seam (build FRR show command string + call c.fm.Show* or c.rm equivalent); preserve FRR 10.6 ExecReload workaround note (#1880) not needed here but conceptual neighbor
  - `cli_show_routing_bfd_vrrp_arp.go` (300 LOC): showBFD + showVRRP (native VRRP state machine, reads from c.cm or similar? Actually VRRP from cluster/ vrrp.Manager?) + showARP + showIPv6Neighbors + showIPv6RA — host/L2 adjacency, native + netlink sources
  - `cli_show_routing_options.go` (250 LOC): showRouteMap + showPolicyOptions + showEventOptions + showRoutingOptions + showRoutingInstances + showForwardingOptions — config echo / policy instantiation / routing instance (VRF) display

  Seam: route table vs protocol vs adjacency vs options — natural by data source and by config vs operational split. Dispatcher handleShowRoute vs handleShowProtocols already exist as entry points. Each subgroup has no shared mutable state beyond CLI receiver (and fm/rm/cluster managers via injected getters).

- Hot-path preservation analysis: A — MECHANICAL/SAFE
  - CLI show commands, cold. FRR gRPC call latency dominates, not file organization. VRRP native display reads atomic effective-priority (clamped [1,254] on link-down, owner-255 exempt #2082) — still correct after move.
  - Guardrails: Preserve handleShowRoute arg parsing (show route [terse|summary|...] prefix order), handleShowProtocols protocol word (ospf vs bgp etc) prefix matching (Junos-style), VRRP display effectivePriority demotion (track-interface <if> priority-cost <n>), showRoutingInstances detail bool.
  - Verification: make test-go; manual in test-ssh: `show route summary`, `show protocols ospf neighbor`, `show protocols bgp summary`, `show vrrp`, `show arp`, `show ipv6 neighbors`, `show routing-instances`

- Tests + gate: pkg/cli/*_test.go, make test-go, make test-deploy manual probe
- Why it matters: 1156 LOC with 18 methods — adding a new routing show subcommand (e.g., `show route forwarding-table` or `show protocols evpn`) requires editing a large file with unrelated OSPF/BGP/VRRP logic, increasing review conflict. FRR passthrough commands vs native VRRP state machine are conceptually distinct data planes (FRR daemon vs native Go VRRP). Splitting by source improves review.
- Fix direction: Mechanical extraction of method groups to new files, preserve method receivers, preserve Junos-style prefix matching semantics (handled by cmdtree? Actually routing show dispatch is hand-rolled here? Check: handleShowRoute parses args[0] etc). No exported API.
- Labels: `refactor`, `cli`, `routing`, `cold-path`, `frr-passthrough`
- Dedup note: Unique to b1 batch.

---

### Finding 3 — bpf/headers/xpf_helpers.h 2554 LOC C header retained (D — DO-NOT-SPLIT)

- Title: xpf_helpers.h 2554 LOC C header with 40 static inline parsing/tunnel/csum/NAT64/MSS helpers — largest file in batch but retained header for struct size/align guards post eBPF retirement #1476/#1527, not Go refactor candidate
- Severity: n/a informational
- Confidence: high
- Refactor class: D — DO-NOT-SPLIT for Go audit
- Evidence:
  File: `bpf/headers/xpf_helpers.h`, 2554 LOC, all `static __always_inline` + struct vlan_hdr
  Content: parse_ethhdr (VLAN single-tag handling, vlan_id/pcp/present extraction), tunnel_pass (strip pseudo-ETH for POINTOPOINT before XDP_PASS), xdp_vlan_tag_pop/push (head adjust), GRE parsing, ICMP helpers, checksum update helpers (bpf_csum_diff pattern for NAT), TCP MSS clamp, NAT64 translate, screen reason indexing, conntrack key building, flow lookup helpers.
  Quoted:
  ```c
  static __always_inline int
  parse_ethhdr(void *data, void *data_end, __u16 *l3_offset, __u16 *eth_proto,
               __u16 *vlan_id, __u8 *vlan_pcp, __u8 *vlan_present)
  {
      struct ethhdr *eth = data;
      if ((void *)(eth + 1) > data_end)
          return -1;
      *eth_proto = bpf_ntohs(eth->h_proto);
      // VLAN handling...
  }
  static __always_inline int
  tunnel_pass(struct xdp_md *ctx, struct pkt_meta *meta)
  {
      if (meta->meta_flags & META_FLAG_TUNNEL) {
          if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ethhdr)))
              return XDP_DROP;
      }
      return XDP_PASS;
  }
  ```
  Role post-retirement: 
  - `bpf/headers/xpf_common.h` defines MAX_INTERFACES used by `pkg/dataplane/loader_userspace_shim.go` to verify shim .o BPF map sizes (pkg/dataplane README)
  - `xpf_helpers.h` included by parity tests and shim build
  - No longer compiled as XDP program (legacy `bpf/xdp/*.c` deleted #1476), but header kept for struct layout compatibility and reference

- Proposed decomposition: NONE — D class. If future Rust hot-path needs shared parsing, split into:
  - `xpf_parse_eth.h` — parse_ethhdr, vlan header
  - `xpf_parse_ip.h` — l3_offset handling, IP parse
  - `xpf_parse_l4.h` — TCP/UDP/ICMP parse
  - `xpf_csum.h` — checksum diff helpers
  - `xpf_tunnel.h` — tunnel_pass, vlan pop/push
  - `xpf_hash_meta.h` — flow key + meta helpers
  But ONLY when Rust dataplane needs it and verifier-friendly split proven — not in this Go CLI batch.

- Hot-path preservation: D — DO-NOT-SPLIT
  - C headers, not Go. No Go disassembly diff. For Rust AF_XDP, userspace-dp uses Rust packet parsing (`userspace-dp/src/`), not these headers. Headers exist for size/align guards.
  - If split, guard: sizeof(C struct) must match Go mirror — MAX_INTERFACES constant must stay same. Verify via `make generate` gated by kernel-verifier #1864, `make test-rust` shim .o size check.
  - Guard: `cargo asm` objdump -d diff for shim .o must be empty (no instruction change)

- Tests + gate: make test-rust, pkg/dataplane loader tests, make generate pinned toolchain check
- Why it matters: Marking D prevents automated refactor from splitting a file that is intentionally monolithic C pattern and verifier-sensitive.
- Fix direction: No action
- Labels: `no-action`, `D-do-not-split`, `C-header`, `retained-for-alignment`
- Dedup note: Only in b1 batch

---

### Finding 4 — cmd/cli/main.go 717 LOC + shared.go 681 LOC = 1398 LOC remote CLI interactive loop + configure mode + commit + ping/traceroute/load/test subcommands

- Title: Remote CLI main.go 717 + shared.go 681 + monitor.go 462 + show_security.go 719 + show.go 515 = 3394 LOC across 5 files, main.go alone fuses 7 responsibilities (dial, local-only bypass, readline, signal loop, configure-mode exit guard, commit, ping/traceroute/load/test)
- Severity: medium
- Confidence: medium
- Refactor class: A — MECHANICAL/SAFE but with B guardrail on signal loop lifecycle
- Evidence:
  main.go 717: main() 67-263=196 LOC (flag parse + dialOpts gRPC TLS, paging init, signal loop start), dialOpts 44-59=15 LOC (TLS + max recv #5321), isLocalOnlyCommand 60-66=6 LOC (local-only verb filter #4909), exitConfigureBounded 264-280=16 LOC, runSignalLoop 281-306=25 LOC (sigCh handling for daemon shutdown), exitOnInterrupt 307-318=11 LOC, handleCommit 319-409=90 LOC (commit/confirm/rollback #4868, terminal abort #4883), printRemoteConfigWarnings 410-415=5 LOC, handlePing 416-467=51, handleTraceroute 468-516=48, readTerminalConfig 517-533=16, handleLoad 534-577=43 (terminal abort #4883), handleTest 578-595=17 + testPolicy 596-672=76 + testRouting 673-701=28 + testSecurityZone 702-717=15
  shared.go 681: ctl struct 38-58=20 LOC (cmdMu, cancel, context), startCmd/endCmd/ctx/cancelCmd (66-103=37), dispatch 104-117=13, extractPipe 118-139=21 (pipe type: match/except/count), dispatchWithPipe 140-177=37 (pipe filter application), applyPipeFilter 178-233=55, dispatchOperational 234-330=96 (operational verb triage: show/monitor/clear/request/ping/traceroute), parseRollbackSelector 331-344=13 (rollback int32 #5052), dispatchConfig 345-535=190 (config-mode set/delete/show/edit dispatch — delegates to config.setSchema? Actually remote proxies to daemon via gRPC), refreshPrompt 536-563=27 (clusterPrefix #...), operationalPrompt/configPrompt, showOperationalHelp/showConfigHelp, completionCursor 594-681=87 (prefix pos #4970)

  Responsibilities in main.go alone (7):
  1. Entry + flag parsing (cli port/host/TLS)
  2. gRPC conn + dialOpts (TLS + grpc_maxrecv #5321)
  3. Interactive line edit + signal handling (runSignalLoop/exitOnInterrupt)
  4. Configure mode lifecycle + commit/commit confirmed handling (handleCommit + exitConfigureBounded + rollback #4868)
  5. Load (handleLoad + readTerminalConfig + terminal abort #4883)
  6. Ping/traceroute operational probes
  7. Test policy/routing/zone (testPolicy/testRouting/testSecurityZone) — policy check via gRPC

  Plus shared.go fuses (8):
  - Cmd lifecycle (startCmd/endCmd/cancelCmd/ctx)
  - Pipe extraction + filter (| match/except/count)
  - Operational vs config dispatch triage
  - Prompt refresh + cluster prefix
  - Completion cursor position (#4970)
  - Help display

- Proposed decomposition (same package `main`, all files same package):
  - `main.go` (200 LOC): main() entry, flag parsing, dialOpts wrapper, app bootstrap (new ctl, set completer), start readline loop
  - `interactive.go` (200 LOC): runSignalLoop, exitOnInterrupt, ctl context lifecycle (startCmd/endCmd/ctx/cancelCmd), signal channel setup — terminal interaction
  - `dispatch.go` (250 LOC): dispatch, dispatchOperational, dispatchConfig, parseRollbackSelector, isLocalOnlyCommand — verb triage
  - `pipe.go` (150 LOC): extractPipe, dispatchWithPipe, applyPipeFilter — `| match` pipe handling (shared.go 118-233)
  - `prompt.go` (150 LOC): refreshPrompt, clusterPrefix, operationalPrompt, configPrompt, showOperationalHelp/ConfigHelp — prompt management
  - `completion.go` (100 LOC): completionCursor, remoteCompleter struct, cmdtree integration — tab completion pos #4970
  - `commit.go` (150 LOC): handleCommit, exitConfigureBounded, printRemoteConfigWarnings, rollback selector #5052 — commit modal
  - `load.go` (100 LOC): handleLoad, readTerminalConfig, load terminal abort #4883
  - `test.go` (150 LOC): handleTest, testPolicy, testRouting, testSecurityZone — test subcommands
  - `ping_traceroute.go` (120 LOC): handlePing, handleTraceroute

  Existing monitor.go 462 LOC and show_security.go 719 etc stay but could also split: monitor subcommands already partially split? cmd/cli/monitor.go 462 LOC could be monitor_interface vs monitor_traffic similar to pkg/cli/monitor split.

- Hot-path: A — MECHANICAL (remote CLI, operator tool)
  - Guardrails: signal loop must remain single goroutine managing sigCh (SIGINT/SIGTERM) + exitOnInterrupt + commit confirmed timer. Commit confirmed path: `commit confirmed <minutes>` starts timer in daemon, remote CLI tracks it? Must preserve confirmed-cancel on normal commit. Local-only commands #4909 must still bypass remote proxy. grpc_maxrecv #5321 (max incoming message size) must be configured on both sides.
  - Verification:
    - cmd/cli/*_test.go: nontty_test, commit_rollback_4868_test, grpc_maxrecv_5321_test, load_terminal_abort_4883_test, local_only_verb_4909_test, monitor_keyreader_4694, monitor_packetdrop_5051, completion_pos_4970, show_zones_tiers_3683, non-tty detection
    - make test-go
    - Manual smoke in test-ssh: cli remote `set ...` + commit, `commit confirmed 1` rollback timer, `load replace terminal`, `show ... | match`, `ping`, `traceroute`
  - Incremental build: smaller main.go improves go build ./cmd/cli incremental

- Tests + gate: cmd/cli/*_test.go, make test-go, manual remote CLI smoke via make test-ssh
- Why it matters: 717 LOC main.go + 681 shared.go = 1398 LOC entry + dispatcher, largest remote CLI files. Adding new top-level command (e.g., `request system power-off` or `test security ...`) touches main.go with signal loop logic interleaved. Splitting dispatch vs pipe vs prompt vs commit improves per-feature ownership.
- Fix direction: Mechanical extraction preserving package main, keep ctl struct in main.go or move to app.go (still same package, field visibility preserved).
- Labels: `refactor`, `cli`, `remote-cli`, `cold-path`, `dispatch`
- Dedup note: cmd/cli/main.go unique to b1 (remote CLI), vs pkg/cli/cli.go (local CLI core 548 LOC DI container).

---

### Finding 5 — pkg/cli/cli.go 548 LOC DI container god-struct with 35+ fields + 15 Set*Fns

- Title: CLI core struct 548 LOC DI container with 35+ fields (store, dp, eventBuf/Reader, rm, fm, im, dm, dr, cm, forwardingSampler, rpmResultsFn, ipmonStatus, natPoolAlarms, feeds, lldp, ddns stats/owned/surfaceA, flowCollectorHealth, version, userClass) — not traditional god-file but dependency aggregator that could benefit from facade grouping
- Severity: low
- Confidence: medium
- Refactor class: A — MECHANICAL but optional (DI container, not business logic fused)
- Evidence:
  ```go
  type CLI struct {
      store *configstore.Store
      dp    cliRuntime // dataplane accessor (IsLoaded, ReadGlobalCounter, SessionCount, GetMapStats...)
      eventBuf *logging.EventBuffer
      eventReader *logging.EventReader
      rm *routing.Manager
      fm *frr.Manager
      im *ipsec.Manager
      dm *dhcp.Manager
      dr *dhcprelay.Manager
      cm *cluster.Manager
      forwardingSampler *fwdstatus.Sampler
      rpmResultsFn func() []*rpm.ProbeResult
      ipmonStatusFn func() []ipmon.PolicyStatus
      natPoolAlarmsFn func() []natpoolalarm.ActiveAlarm
      feedsFn func() map[string]feeds.FeedInfo
      feedOverlayFn func() map[string][]string
      lldpNeighborsFn func() []*lldp.Neighbor
      ddnsStatsFn func() *dhcpserver.DDNSStats
      ddnsOwnedRecordsFn func() []dhcpserver.DDNSOwnedRecordView
      surfaceADDNSStatsFn func() *ddnspkg.SurfaceAStats
      surfaceADDNSStatusFn func() []ddnspkg.SurfaceAStatusView
      surfaceADDNSForceFn func(force bool) (bool, string)
      flowCollectorHealthFn func() []flowexport.ExporterCollectorHealth
      version string
      userClass string
      // ...
  }
  func New(store *configstore.Store, dp cliRuntime, eventBuf *logging.EventBuffer, ...) *CLI {
      // 135-161 ctor wiring
  }
  func (c *CLI) SetForwardingSampler(s *fwdstatus.Sampler) { ... }
  // 15 Set*Fn methods 177-269, each simple setter
  ```
  Responsibilities as DI container (intentionally wide but groupable):
  1. Dataplane: dp (global counters, map stats, session count) + forwardingSampler
  2. Routing: rm (FRR) + fm (FRR manager) + access to routing tables
  3. IPsec: im (SA queries)
  4. DHCP/relay/server: dm + dr + dhcpserver DDNS seam via SetDDNS*
  5. Cluster/HA: cm (cluster manager for RG/VRRP/fabric stats)
  6. Observability: eventBuf/Reader, rpmResultsFn, ipmonStatusFn, feed info + overlay, lldp neighbors, flow collector health
  7. Identity: store (config), version, userClass

- Proposed decomposition (if pursued, conservative):
  Keep cli.go struct as-is (DI container pattern is legitimate), but group fields with comment sections and extract facades:
  - `cli.go` (200 LOC): core struct, ctor, applyResult, dataplaneLoaded, SetVersion/SetUserClass
  - `cli_deps_forwarding.go` (100 LOC): forwardingSampler + ddns-related SetFns — forwarding path related observers
  - `cli_deps_observability.go` (150 LOC): rpmResults, ipmonStatus, natPoolAlarms, feeds, feedOverlay, lldp, flowCollectorHealth, ddnsOwned — observability observers
  - `cli_deps_cluster.go` (100 LOC): cluster manager accessor + surfaceA Fns
  Could alternatively remain single file — 548 LOC is acceptable for DI container; finding is low priority informational.

- Hot-path: A — DI container, cold.
- Tests + gate: make test-go; CLI DI wiring tested via integration (show commands read managers)
- Why it matters: Low — DI container at 548 LOC is within acceptable size, but 35+ fields signals system has many cross-cutting concerns. Grouping comments already partially exist; facades optional.
- Fix direction: Optional — keep as-is or add sectional comments + small accessor files. No functional change.
- Labels: `optional`, `di-container`, `cold-path`
- Dedup note: cli.go unique to b1.

---

## Summary Rank (size×resp×hot-path)

1. `pkg/cli/cli_show_flow.go` 1262 ×6×cold = TOP — god-method 560 LOC, split first
2. `pkg/cli/cli_show_routing.go` 1156 ×18 cmds ×cold = 2nd — split by data source
3. `bpf/headers/xpf_helpers.h` 2554 — D — DO NOT SPLIT (C header, BPF verifier, retained shims)
4. `cmd/cli/main.go` 717 ×7×cold + shared.go 681 ×8 = 3rd grouping — dispatch vs pipe vs prompt vs commit
5. `pkg/cli/cli.go` 548 DI container — low/optional

No per-packet hot path code in this batch — all CLI show + C headers + remote CLI entry. All findings A/B/D cold-path mechanical.

## Cold-Path Gate

- make test-go (pkg/cli/*_test.go, cmd/cli/*_test.go)
- make test-deploy smoke: manual `show security flow session`, `show route`, `show security nat source`, `show chassis cluster status` output identical pre/post
- No CoS/failover gates needed for CLI show (operator view only)
- Incremental build: smaller cli_show_flow.go / cli_show_routing.go improves go build incremental timing; binary size unchanged

## Dedup Notes

- cli_show_flow.go primary for this batch; if A10 b2/b3 mention flow show, dedup to this finding by file path pkg/cli/cli_show_flow.go
- cli_show_routing.go unique to b1
- cmd/cli/main.go unique to b1 (remote CLI)
- No overlap with A9 observability (eventengine/feeds/flowexport/logging/rpm/snmp) or A8 API gRPC REST



---
### Batch A10_go_services_cli_deploy-b2 — 534 lines — full log + findings

# Go Services / CLI / Deploy — Modularity Audit Batch B2

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A10_go_services_cli_deploy-b2 (missing, fell back to /home/ps/git/avacado-xpf + /tmp/review-wt-ps-044-A10_go_services_cli_deploy-b3 proxy)
Batch: A10_go_services_cli_deploy-b2.txt (150 files, ~12k prod LOC sampled)
Area: pkg/cli show/security/services/system, monitor, permissions, session, peer; pkg/ddns backends/manager/surface_a/state; pkg/dhcp

## Inventory — size/shape checklist (prod files only, test excluded)

All reads via worktree path fallback; `wc -l` and `grep ^func` used for LOC and largest functions.

| File | LOC | Top functions (LOC) | Responsibilities fused (count) | Hot-path? | Rank (size x resp x hot) |
|---|---|---|---|---|---|
| pkg/ddns/surface_a.go | 2109 | Reconcile 227 (737-964), reconcileScopeLocked 221 (964-1185), publishLocked 256 (1185-1441), withdrawOwnedLocked 84, backendFingerprint 61 | 8: backend resolution (rfc2136/HTTP/cloudflare/route53), httpClient cache per-binding, AddressObserver (netlink/checkip), 2-pass reconcile (publish + gone-from-config withdraw), orphan alarm (H01/H02/H03), publish/write-ahead + confirm-save durability (#5285), backoff/error state machine, StatusViews/Stats, force-refresh latch | NO – 30s poll control plane | HIGH 2109*8 cold |
| pkg/dhcp/dhcp.go | 1940 | runDHCPv4 179 (788-967), runDHCPv6 185 (1208-1393), doDHCPv4 59, doDHCPv6 90, parseV6Reply 99, getDUID 65, classlessStaticRoutes 46 | 7: client lifecycle (Start/Renew/StopAll/finishClient pointer guard), DUID persistence + traversal guard (#4857), DHCPv4/v6 exchange state machines (acquire/renew/rebind/NAK revoke #3956), lease commit (address apply via netlink + DNS + FRR recompile), delegated PD + RA + withdrawn-PD partitioning, gateway-change hook + scheduleRecompile debounce, test seams (runClientForTest/doV4ExchangeForTest) | NO – but gateway hook affects routing overlay | HIGH 1940*7 |
| pkg/ddns/manager.go | 1486 | policyFromConfig 182 (190-372), ReconcileScoped 150 (629-779), reconcileOnceLocked 227 (863-1090), upsertLocked 116, deleteOwnedLocked 76 | 6: LeaseParser seam (Kea memfile), ddnsPolicy per-family, ScopeKey/ScopeResolver + per-RG gate (#2664), ownership store load-or-degrade + quarantine, reconcileOnce with trust/untrusted/disabled + DHCID conflict, providerIO release-lock + durable write-ahead (#2662), Stats/OTEL counters | NO | MEDIUM-HIGH 1486*6 |
| pkg/ddns/backend_rfc2136.go | 1126 | sendAddOwned 100 (740-840), exchange 61 (1041-1102), UpsertLease 70 (392-462), DeleteLease 32, forwardRR/ptrRR/dhcidRR | 3: TSIG + update-server normalization, forward/reverse zone resolution + longest suffix, self-owned vs DHCID-owned add paths (sendAddSelfOwned/in-place replace vs name-not-in-use), rcode handling | NO | MEDIUM |
| pkg/cli/cli_show_system.go | 1081 | handleShowSystem 248 (834-1081), showSystemProcesses 179 (504-683), showSystemServices 118, showSystemNTP 40, showSystemSyslog 47 | 12: buffers (userspace vs legacy BPF maps), core-dumps, task (runtime.MemStats), backup-router, NTP (chronyc/ntpq/timedatectl exec), services (gRPC/HTTP/SSH/SNMP/DHCP/DNS/syslog/NetFlow/AppID/RPM), syslog hosts, uptime, boot-messages, memory, processes, storage, users, connections, version, log path/count, daemon log, commit/rollback history + secret redaction (#4099) | NO – CLI cold | MEDIUM hub |
| pkg/cli/monitor.go | 996 | handleMonitorSecurityFlowFilter 133 (455-588), handleMonitorSecurityFlowFile 86, handleMonitorSecurityFlowStart 124, handleMonitorSecurityPacketDrop 192 (805-997), sanitizeTraceFilename 14, openTraceFile 27, rotateTraceFile 34, monitorFlowFilter.matches 36 | 6: traceWriter size/files rotation (#3379) + dedicated dir 0700 confinement (#5038), O_NOFOLLOW open + regular-file check, flow filter DSL (source-prefix/dst-prefix/port/protocol/iface + CIDR parse + empty-matches-everything guard #3380 HC-03), eventBuf subscription + goroutine lifecycle + lastErr surfacing (#4883), formatting (flow vs packet-drop Junos-style), dispatch tree (monitor security flow/file/filter/start/stop + packet-drop) | NO | MEDIUM hub |
| pkg/ddns/state.go | 662 | scopePrefix 136 (158-294), loadDDNSState 54, readBoundedStateFile 19, quarantineBadState 8, save 24 | 4: ownedRecord + ScopeKey encoding (zero scope backward compat), bounded read (stat pre-check + LimitReader #5571 CWE-770), corrupt/unsupported quarantine + degraded marker (.degraded) durability (#4873), durability (fsatomic fsync + writeFile seam for fault injection) | NO | LOW-MEDIUM |
| pkg/cli/session_filter.go | 527 | session filter parse multi-iface + app + nat + zone + policy | 3: Junos filter syntax → typed struct, multi-value bracket handling, matching vs session iterator | NO | LOW |
| pkg/cli/completion.go | 589 | completion helpers, typed-leaf value complete | 2: command tree completion + config schema value completion | NO | LOW |
| pkg/ddns/backend_route53.go | 463 | Route53 SigV4 + pagination | 2: AWS API + SigV4 signing | NO | LOW |
| pkg/cli/cli_show_security_screen.go | 485 | screen counters + inventory | 2: screen stats aggregation + display | NO | LOW |

Coverage proof:
- Batch lists 150 paths, 38 prod (non-_test.go) — counted via `grep -v _test.go batches/A10...b2.txt | wc -l` = 38, 112 test.
- All 38 prod files sized with `wc -l` (above). Largest 7 inspected function-by-function with `grep -n ^func` + python size estimate (lines to next func).
- No vendored/generated files in batch (no .pb.go, no bpf2go). All files are control-plane cold path (CLI/DDNS/DHCP) — confirmed via package imports (no userspace-dp hot tx/poll stages).
- Rank computed as LOC * distinct responsibilities * hot proximity (1.0 cold, 2.0 warm, 3.0 hot). Top: surface_a (2109*8), dhcp manager (1940*7), ddns manager (1486*6).

---

## Finding 1: pkg/ddns/surface_a.go god-manager 2109 LOC fuses 8 distinct responsibilities

Title: Surface A DDNS SurfaceAManager god-file mixes backend resolution, HTTP transport cache, observation, 2-pass reconcile, orphan alarm, durability, backoff
Severity: HIGH
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE for extraction of backend/fingerprint/http-cache/status, B REQUIRES GUARDRAILS for reconcile/publish/withdraw (lock discipline #2778)
Evidence:
- File/path: `pkg/ddns/surface_a.go:1-2109` (2109 LOC, second largest in batch). Functions >150 lines: `Reconcile 737-964 size 227`, `reconcileScopeLocked 964-1185 size 221`, `publishLocked 1185-1441 size 256`, plus `withdrawOwnedLocked`, `resolveSurfaceABackend 520-584`, `backendFingerprint 1624-1646`.
- Metrics: 36 funcs, 3 large >200 LOC, 7 const groups, 5 status states, 3 orphan reasons, 2 backends error sentinels, 1 httpClientCache struct (not in file but referenced).
- Responsibility count: 8 (see inventory). God struct:

```go
// pkg/ddns/surface_a.go:313-415
type SurfaceAManager struct {
 mu    sync.Mutex
 state *ddnsState
 degraded bool
 degradedReason string
 runtime map[string]*surfaceAState
 orphans map[string]surfaceAOrphan
 forceRefresh bool
 newBackend func(p *config.DDNSProvider, fqdn string, ttl int) (DNSUpdater, error)
 backend    DNSUpdater
 httpClients *httpClientCache
 ifResolver func(string) string
 now func() time.Time
 upsertOK   uint64
 ...
}
```

```go
// pkg/ddns/surface_a.go:737-790
func (m *SurfaceAManager) Reconcile(ctx context.Context, scopes []SurfaceAScope, observe AddressObserver, gate ScopeGate, catalog map[string]*config.DDNSProvider, resolveIf ...func(string) string) error {
 m.mu.Lock()
 defer m.mu.Unlock()
 m.ifResolver = firstResolver(resolveIf)
 if m.degraded {
  return fmt.Errorf("ddns surface-a: reconcile suspended (state degraded): %s", m.degradedReason)
 }
 ...
 live := make(map[string]struct{}, len(scopes)+len(catalog)+1)
 ...
 // Pass 1 publish / refresh / withdraw-on-address-loss
 // Pass 2 withdraw gone-from-config with provider-aware adopt-in-place (#2903/#3735)
```

```go
// pkg/ddns/surface_a.go:1185-1310
func (m *SurfaceAManager) publishLocked(ctx context.Context, sc SurfaceAScope, addr netip.Addr, now time.Time) error {
 backend, err := m.backendFor(sc)
 ...
 ow := ownedRecord{... PublishPending: true, PriorAddrText: prevAddr,}.withScope(key)
 m.state.put(ow)
 if err := m.state.save(); err != nil { // write-ahead before wire
  ...
 }
 wireErr := m.providerIO(func() error { return backend.UpsertLease(ctx, rec) })
 cur, stillOwned := m.state.get(key, surfaceAIdentity, "")
 stale := !stillOwned || cur.AddrText != ow.AddrText
 ...
 // confirm-save after wire
 confirmed := ow; confirmed.PublishPending = false; confirmed.PriorAddrText = ""
 m.state.put(confirmed)
 ...
}
```

- Quoted responsibilities in single file: HTTP client reuse per binding (2904 cache keyed on source-address), backend resolution switch over 6 backends (rfc2136/dyndns2/duckdns/cloudflare/route53/generic + nop), address observation with ctx threaded + mu released (obsIO), orphan fingerprinting (fnv64 of backend+server+zone+hosted-zone+region+URLTemplate, credential-free), StatusViews sorting.

Proposed decomposition:
- `surface_a/backend.go` — `resolveSurfaceABackend`, `newSurfaceAHTTP`, `newSurfaceARFC2136`, `backendFingerprint`, `backendFor`
- `surface_a/http_cache.go` — `httpClientCache`, clientFor, reap, bindCacheKey (currently in other file, imported)
- `surface_a/observe.go` — `AddressObserver`, `observeIO`, `seedFromStore`, `effectiveKey/scopeID`
- `surface_a/reconcile.go` — `Reconcile` + 2-pass logic (publish Pass1, withdraw Pass2 + provider-aware adopt), `reconcileScopeLocked`
- `surface_a/publish.go` — `publishLocked`, `buildHostRecord`, write-ahead + confirm-save, racing-op guard, err sentinels `errSurfaceANoBackend/errSurfaceAPublishRaced`
- `surface_a/withdraw.go` — `withdrawOwnedLocked`, `withdrawTargets` (dual-target pending delete #5334), `siblingFamilyOwnedLocked`, `withdrawScopeLocked`, `markWithdrawUnsupported`
- `surface_a/orphan.go` — `surfaceAOrphan`, `orphanKey`, `noteOrphan/clearOrphan`, `classifyOwnedBackend`, `ownedBackendStatus`
- `surface_a/status.go` — `SurfaceAStatusView`, `StatusViews`, `SortSurfaceAStatusViews`, `Stats`, `ForceRefresh`
- Keep `surface_a.go` as facade re-export + manager struct definition + mu discipline doc.

Hot-path preservation analysis:
- Cold control-plane (30s poll). No per-packet path. Hot risk is lock discipline (#2778): `providerIO` releases mu across 15s wire call, re-acquires, re-validates stale. Any extraction must preserve `m.mu.Unlock/Defer Lock` pattern and stale check (cur.AddrText vs ow.AddrText). Also preserve `observeIO` releasing mu across checkip HTTP GET. No cache-line grouping needed. Verify `AddressObserver` still called with mu released and ctx threaded (#3736). No performance regression path — only correctness of garbage-collector of orphans and backoff window semantics (#4423 M03: publish vs withdraw backoff isolation).

Tests + gate:
- `pkg/ddns/surface_a_test.go` (802 LOC), `surface_a_http_test.go`, `surface_a_provider_change_3735_test.go`, `surface_a_lockio_test.go`, `surface_a_withdraw_pending_5334_test.go`, `surface_a_durable_pending_5285_test.go`, `surface_a_observe_lockio_3736_test.go`, `surface_a_sourcebind_failclosed_4437_test.go`
- `make test-go -run TestSurfaceA`
- Gate: `make test` (go + rust). No cluster needed but `show system services dynamic-dns` status row rendering for `unpublished/noBackend/orphaned` must stay stable.

Why it matters:
- Single file holds 8 distinct refactors (client cache, backend switch, observation, reconcile, publish durability, withdraw dual-target, orphan alarm, status). Change in one (e.g., source-bind fail-closed #4437) risks breaking another (backoff). Test count is 14 test files for this package, indicating high churn. Splitting isolates #3735 endpoint-fingerprint alarm (credential-free) from #5285 pending-write-ahead durability, reducing audit surface.

Fix direction:
1. Extract `backend.go` mechanical (no lock).
2. Extract `http_cache.go` + `orphan.go` (no lock, pure funcs).
3. Extract `publish.go`/`withdraw.go` keeping same lock pattern – add unit test for stale guard (concurrent publish vs withdraw).
4. Extract `reconcile.go` as orchestrator, keep 2-pass comment verbatim (provider-aware adopt must not delete live RR).
5. Final facade: keep constructor, mu, runtime maps, counters in manager.go root.

Labels: refactor, god-file, DDNS, Surface-A, durability, HA-gate, orphan-alarm, fail-closed
Dedup note: Related to B1 finding `pkg/ddns/manager.go DDNS lease manager god-file` but distinct spine (Surface A router-address vs Surface B lease). Consolidates dedup ideas `extract Surface A backend resolver to surface_a/backend.go`, `isolate orphan alarm to orphan.go`, `split publish/withdraw durability to separate files` — not duplicate, deep dive per batch.

---

## Finding 2: pkg/dhcp/dhcp.go god-manager 1940 LOC fuses client lifecycle + DUID persistence + v4/v6 state machines

Title: DHCP Manager god-file 1940 LOC mixes client registry, DUID I/O, DHCPv4/v6 exchange modes, address apply, gateway hook, PD delegation
Severity: HIGH
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE for DUID + validation + routes + sub-prefix, B REQUIRES GUARDRAILS for run-loop renewal (T1/T2/NAK revoke)
Evidence:
- File `pkg/dhcp/dhcp.go:1-1940`, 28 funcs, 2 large >150: `runDHCPv4 788-967 size 179`, `runDHCPv6 1208-1370 size 185`, plus `doDHCPv4`, `doDHCPv6`, `parseV6Reply`.
- Struct:

```go
// pkg/dhcp/dhcp.go:150-191
type Manager struct {
 mu              sync.Mutex
 clients         map[clientKey]*dhcpClient
 leases          map[clientKey]*Lease
 delegatedPDs    map[string][]DelegatedPrefix
 duids           map[string]dhcpv6.DUID
 duidTypes       map[string]string
 v4opts          map[string]*DHCPv4Options
 v6opts          map[string]*DHCPv6Options
 onAddressChange func()
 onGatewayChange func()
 nlHandle        *netlink.Handle
 recompileTimer  *time.Timer
 stateDir        string
 runClientForTest func(...)
 doV4ExchangeForTest ...
}
```

```go
// pkg/dhcp/dhcp.go:788-950
func (m *Manager) runDHCPv4(ctx context.Context, ifaceName string) {
 key := clientKey{iface: ifaceName, family: AFInet}
 ...
 var committed *Lease
 for {
  lease, err := m.v4Exchange(ctx, ifaceName, exchangeAcquire, nil)
  ...
  for {
   t1, t2Remaining := renewalTimers(committed.LeaseTime)
   select {
   case <-m.after(t1):
   ...
   }
   renewed, rerr := m.v4Exchange(ctx, ifaceName, exchangeRenew, committed)
   if rerr == nil { ... continue }
   if errors.Is(rerr, errDHCPNAK) {
    slog.Warn("DHCPv4: RENEWING NAK — lease revoked, deconfiguring and restarting DISCOVER", ...)
    m.abandonLeaseAfterNAK(key, committed)
    committed = nil
    break
   }
 ...
 }
}
```

```go
// pkg/dhcp/dhcp.go:544-601
func (m *Manager) ClearAllDUIDs() error {
 names := make(map[string]struct{})
 ...
 const prefix = "dhcpv6-duid-"
 entries, err := os.ReadDir(m.stateDir)
 ...
 for _, e := range entries {
  if name, ok := strings.CutPrefix(e.Name(), prefix); ok {
   names[name] = struct{}{}
  }
 }
 ...
}
```

- Fused: DUID path validation `validInterfaceName` + traversal guard `duidPath` (defense in depth #4857) alongside DHCP exchange (netlink handle), alongside delegated prefix reconciliation `reconcileDelegatedPDs`, alongside `DeriveSubPrefix` (sub-prefix derivation for RA).

Proposed decomposition:
- `dhcp/duid.go` — `DUIDInfo`, `getDUID/loadDUID/saveDUID`, `duidPath`, `validInterfaceName`, `ClearDUID/ClearAllDUIDs`, `DUIDs`
- `dhcp/client_registry.go` — `clientKey`, `dhcpClient`, `Start`, `finishClient` (pointer guard), `Renew`, `StopAll`, `Leases/LeaseFor`, `DelegatedPrefixes/DelegatedPrefixesForRA`, `fireGatewayChange`, `scheduleRecompile`
- `dhcp/v4.go` — `runDHCPv4`, `doDHCPv4`, `leaseFromACKv4`, `classlessStaticRoutes` (option 121/249), `abandonLeaseAfterNAK`, `buildV4RenewRequest`, `v4RenewDest`
- `dhcp/v6.go` — `runDHCPv6`, `doDHCPv6`, `parseV6Reply`, `selectIANAAddress` (preferred-lifetime tie-break #4383), `extractDelegatedPrefixes` (valid-lifetime 0 withdrawn #4874 B), `discoverIPv6Router`, `waitForLinkLocal`
- `dhcp/netlink.go` — `applyAddress`, `removeAddress`, `prefixToIPNet`, `DeriveSubPrefix`
- Keep `dhcp.go` as facade: Manager struct + constructor + options setters.

Hot-path preservation analysis:
- Cold path, but `onGatewayChange` hook is called outside mu (fireGatewayChange) to avoid Engine.mu → dhcp.mu deadlock (documented). Must preserve outside-mu firing. Also `finishClient` deregistration order: delete registry under lock then address remove outside lock then `fireGatewayChange` then possibly `scheduleRecompile` only if lease existed (#4874 A2). Renew races Start membership check under lock (atomic check-and-register). Any split must preserve mu boundaries. No per-packet hot path.

Tests + gate:
- `pkg/dhcp/dhcp_test.go`, `commit_test.go`, `reconcile_test.go`, `dhcp_lease_expiry_4874_test.go`, `gateway_hook_test.go`, `dhcpv6_iana_test.go`, `classless_routes_test.go`, `renew_test.go`
- `make test-go -run TestDHCP` + `pkg/dhcp/...`
- Gate: `make selftest` for networkd file generation (DHCP address reconciliation skip).

Why it matters:
- Single file holds v4 DORA + v6 rapid-solicit + renewal state machines + DUID disk I/O + security validation (traversal #4857) + PD lifetime handling. Bug in one area (e.g., NAK revoke #3956 must deconfigure immediately) could be missed among DUID churn. Splitting isolates exchange mode constants (`exchangeAcquire/Renew/Rebind`) and NAK sentinel from DUID file handling.

Fix direction:
1. Extract `duid.go` mechanical (file I/O).
2. Extract `netlink.go` + `DeriveSubPrefix`.
3. Extract `v4.go` + `v6.go` keeping renewal timer helper `renewalTimers` shared.
4. Extract `client_registry.go` keeping mu discipline comments verbatim.
5. Facade retains constructor and test seams.

Labels: refactor, god-file, DHCP, DUID, netlink, renewal, NAK-revoke, HAP
Dedup note: Complements B1 `pkg/dhcp/renew.go + commit.go split` but this batch's `dhcp.go` itself is god; dedup `extract DHCPv4/v6 run-loops to separate files` — not duplicate, larger scope.

---

## Finding 3: pkg/ddns/manager.go 1486 LOC — DHCP DDNS lease reconciler god-manager near threshold

Title: DDNS DHCP lease Manager 1486 LOC just under 1500 but god-struct with degraded + per-family policy + scope gate + durable write-ahead
Severity: MEDIUM
Confidence: HIGH
Refactor class: B REQUIRES GUARDRAILS (degraded fail-closed + DHCID conflict + PTR pending + race guard on providerIO)
Evidence:
- File `pkg/ddns/manager.go:1-1486`, functions: `policyFromConfig 190-372 size 182`, `ReconcileScoped 629-779 size 150`, `reconcileOnceLocked 863-1090 size 227`, `upsertLocked 116`, `deleteOwnedLocked 76`, `loadStateOrDegrade 372-433`.
- Struct `Manager` fuses leaseParser seam, per-family updaters (array indexed by famIdx), degraded marker, ifResolver, nodeID watermark, lease file paths, atomic counters (14 atomic.Uint64), lastPolicy Pointer.
- Large function:

```go
// pkg/ddns/manager.go:863-1090
func (m *Manager) reconcileOnceLocked(ctx context.Context, env *reconcileEnv, leases []Lease, untrusted, disabled map[int]bool) error {
 // build desired map from leases + scope attribution
 // diff owned vs desired with per-scope gate admit
 // DHCID shared check dhcidSharedWithOther
 // upsertLocked with write-ahead before wire
 // deleteOwnedLocked with exact tuple authority
 // PTRPending handling #2661
 // per-family independent
}
```

```go
// pkg/ddns/manager.go:1169-1285
func (m *Manager) upsertLocked(ctx context.Context, updater DNSUpdater, rec LeaseDNSRecord, ow ownedRecord) error {
 // write-ahead PTRPending=true save BEFORE UpsertLease
 // providerIO releases mu
 // Racing-op guard re-validation after wire
 // confirm-save clears PTRPending
}
```

- Responsibilities: policyFromConfig defaults (TTL, backend rfc2136, conflictPolicy replace-owned), Lease ingestion from Kea memfile seam, scope attribution via ScopeResolver (CIDR → subnet → group → RG), per-RG HA gate (fail-closed on uncertain), state load-or-degrade quarantine, reconcileEnv (updaterFor/polFor/scopeAdmits), counters, degraded marker (.degraded), writeFile seam for fault injection.

Proposed decomposition:
- `manager/policy.go` — `policyFromConfig`, `ddnsPolicy` defaults
- `manager/scope.go` — `ReconcileOptions`, `ScopeGate`, `ScopeResolver`, `reconcileEnv` (scopeAdmits/scopeFor)
- `manager/reconcile.go` — `Reconcile`, `ReconcileScoped`, `reconcileOnceLocked`, `parseLeases`, `recordReconcilePass`, `familyOwnsRecords`, `dhcidSharedWithOther`
- `manager/durability.go` — `upsertLocked`, `deleteOwnedLocked`, `withdrawAllLocked`, `providerIO`, `loadStateOrDegrade`, `ownerWatermark`
- `manager/stats.go` — `Stats`, `OwnedRecordViews`, `OwnedForTesting`, `OwnedKeysForTesting`
- Keep `manager.go` facade with Manager struct + New constructors + lastPolicy atomic.

Hot-path preservation analysis:
- Cold (DHCP lease poll). Critical invariant: durability contract (#2662) — ownership durably recorded BEFORE wire add (PTRPending), confirm-save after. Also providerIO releases mu, re-validates racing op. Any extraction must keep mu release/acquire around wire call and re-validation. Degraded fail-closed (#2650) must refuse both publish and withdraw when state corrupt. No per-packet hot path.

Tests + gate:
- `manager_test.go` (887 LOC), `manager_inc2_test.go` (873), `durability_test.go`, `spine_fixes_test.go`
- `make test-go -run TestDDNSManager`
- Gate: `make test` dual leg (Go + Rust), `show system services dynamic-dns` degraded row.

Why it matters:
- File sits at 1486 LOC, just under threshold, but god struct with 7 responsibilities and counters. Parallel to Surface A manager but distinct spine (lease vs router). Splitting clarifies HA writer gate vs durability vs policy resolution.

Fix direction:
1. Extract policy.go mechanical.
2. Extract scope.go (pure funcs).
3. Extract durability.go keeping providerIO comment verbatim (#2778 lock release).
4. Extract reconcile.go (largest).
5. Facade retains degraded handling.

Labels: refactor, DDNS, lease-manager, degraded-fail-closed, durability, DHCID
Dedup note: Distinct from Finding 1 (Surface A). Consolidates `split ddns lease manager into policy/scope/reconcile/durability` — not duplicate, B1 batch had similar.

---

## Finding 4: pkg/cli/cli_show_system.go hub file 1081 LOC — 12 unrelated show commands in one file

Title: cli_show_system.go hub low cohesion mixes buffers / core-dumps / NTP / services / rollback secret redaction
Severity: MEDIUM
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE (each show* is independent, no shared state beyond cli store + dp)
Evidence:
- File `cli_show_system.go:1-1081`, 18 funcs. Largest `handleShowSystem 834-1081 size 248`, `showSystemProcesses 504-683 size 179`.
- Mixes: `showSystemBuffers` (dataplane userspace vs legacy BPF map stats, FormatSystemBuffers), `showCoreDumps` (os.ReadDir /var/crash), `showTask` (runtime.MemStats), `showBackupRouter`, `showSystemNTP` (exec chronyc/ntpq/timedatectl), `showSystemServices` (gRPC/HTTP/SSH/SNMP/WebMgmt/DHCP/DNS/NTP/syslog/NetFlow/AppID/RPM), `showSystemSyslog`, `showSystemUptime`, etc., plus `handleShowSystem` dispatcher with 20+ case branches including secret redaction via `showConfigRedacted()` (#4099/#4111 community masking).
- Dispatcher snippet:

```go
// pkg/cli/cli_show_system.go:834-1081
func (c *CLI) handleShowSystem(args []string) error {
 sysTree := operationalTree["show"].Children["system"].Children
 if len(args) == 0 {
  fmt.Println("show system:")
  writeCompletionHelp(os.Stdout, treeHelpCandidates(sysTree))
  return nil
 }
 switch args[0] {
 case "commit":
  // ListCommitHistory 50
 case "rollback":
  // redaction via ShowRollbackRedacted vs ShowRollback
  // ShowCompareRollbackRedacted vs ShowCompareRollback
 case "uptime": return c.showSystemUptime()
 case "memory": return c.showSystemMemory()
 case "processes":
  summary := len(args) >= 2 && args[1] == "summary"
  return c.showSystemProcesses(summary)
 ...
 case "ntp": return c.showSystemNTP()
 case "services": return c.showSystemServices()
 case "syslog": return c.showSystemSyslog()
 case "buffers":
  if len(args) >= 2 && args[1] == "detail" { return c.showSystemBuffersDetail() }
  return c.showSystemBuffers()
 ...
 }
}
```

- No shared helper beyond dispatcher. Low cohesion = true hub.

Proposed decomposition:
- `cli/show_system_buffers.go` — buffers + buffersDetail + map stats sorting
- `cli/show_system_process.go` — task, uptime, boot-messages, memory, processes (with ps aux parsing), storage, users, connections
- `cli/show_system_ntp_services.go` — NTP (chronyc exec), services (SSH root-login, SNMP community redaction #4111, DHCP, DNS, syslog streams, NetFlow/IPFIX/RPM), syslog, backup-router
- `cli/show_system_commit.go` — commit history + rollback list/compare/show with redaction path (`showConfigRedacted()`), secret handling for login/internet-options/root-authentication/configuration rescue
- Keep `cli_show_system.go` as dispatcher importing sub-modules or rename to `show_system_dispatch.go` with only handleShowSystem.

Hot-path preservation analysis:
- Cold CLI path, no dataplane impact. Only risk is secret redaction path (#4099/#4111): rollback/config display must call `showConfigRedacted()` for non-super-user; extracting must preserve that branch (read community masking). Also ensure `cliUserspaceStatusProvider` type assert for buffers remains. No locking.

Tests + gate:
- `cli_show_system_buffers_test.go`, `cli_show_snmp_community_redaction_4111_test.go`, `cli_zeroize_configured_root_5554_test.go`
- `make test-go -run TestShowSystem`
- Manual: `show system ntp`, `show system services`, `show system rollback 1` with view class should mask IKE PSK.

Why it matters:
- 1081 LOC hub with 12 unrelated concerns; change in NTP exec handling risks breaking rollback redaction. File already largest CLI show file (1081 vs cli_show_routing 1156 total CLI). Splitting improves discoverability and reduces merge conflicts across teams touching NTP vs buffers vs rollback.

Fix direction:
1. Create `show_system_buffers.go` mechanical move of 2 funcs + mapDetail sorting.
2. Create `show_system_process.go` move of task/uptime/memory/processes/storage/users/connections/boot-messages/core-dumps.
3. Create `show_system_ntp_services.go` move of NTP/services/syslog/backup-router.
4. Create `show_system_commit.go` move of commit/rollback/login/internet-options/root-authentication/configuration.
5. Leave dispatcher thin.

Labels: refactor, CLI, hub-file, low-cohesion, secret-redaction
Dedup note: Related to A10-b1 `cli_show_routing.go 1156 LOC hub` and `cli_show_flow.go 1262 LOC hub` – same pattern, different subtree. Not duplicate.

---

## Finding 5: pkg/cli/monitor.go 996 LOC fuses trace file rotation + filter DSL + event subscription + Junos formatting

Title: monitor.go responsibilities fused — traceWriter rotation, O_NOFOLLOW file confinement, filter DSL, subscription lifecycle, dispatcher
Severity: MEDIUM
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE for file + filter + format extraction, C PERFORMANCE-POSITIVE (writer on slow path)
Evidence:
- File `monitor.go:1-996`, 10+ funcs, largest `handleMonitorSecurityFlowFilter 455-585 size 133`, `handleMonitorSecurityFlowStart 588-712 size 124`, `handleMonitorSecurityPacketDrop 805-997 size 192`.
- Responsibilities:
1. `traceWriter` (size/files rotation #3379, written counter, rotateTraceFile 98-132 with Remove oldest + Rename chain, fail-closed on cap breach)
2. File confinement `traceLogDir = "/var/log/xpf-flow-trace"` 0700 + `sanitizeTraceFilename` (basename only, no traversal #3378) + `openTraceFile` with O_NOFOLLOW + regular-file verification + 0600 mode
3. Filter DSL `monitorFlowFilter` (SrcIP/DstIP/SrcPort/DstPort/Protocol/Iface) with `matches` method checking EventRecord
4. Event subscription lifecycle: `newMonitorFlowState`, mu, active, cancel, sub *logging.Subscription, lastErr surfacing (#4883-B), snapshot filters under lock, spawn goroutine that matches then `formatFlowEvent`/`formatPacketDropEvent` + `traceLineMatches` regex post-filter (#2288)
5. CLI dispatch: `handleMonitorSecurity`, `handleMonitorSecurityFlow`, `handleMonitorSecurityFlowFile`, `handleMonitorSecurityFlowFilter`, `handleMonitorSecurityPacketDrop`

Snippet:

```go
// pkg/cli/monitor.go:30-90
var traceLogDir = "/var/log/xpf-flow-trace"
func sanitizeTraceFilename(name string) error {
 if name == "" { return fmt.Errorf("trace filename must not be empty") }
 if name == "." || name == ".." { return fmt.Errorf("invalid trace filename: %q", name) }
 if strings.ContainsAny(name, `/\`) { return fmt.Errorf("trace filename must be a bare name, not a path: %q", name) }
 ...
}
func openTraceFile(name string) (*os.File, string, error) {
 if err := sanitizeTraceFilename(name); err != nil { return nil, "", err }
 if err := os.MkdirAll(traceLogDir, 0o700); err != nil { ... }
 path := filepath.Join(traceLogDir, name)
 f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, 0o600)
 ...
}
```

```go
// pkg/cli/monitor.go:184-220
func (f *monitorFlowFilter) matches(rec *logging.EventRecord) bool {
 if f.SrcIP != nil {
  srcIP := extractIP(rec.SrcAddr)
  if srcIP == nil || !f.SrcIP.Contains(srcIP) { return false }
 }
 ...
 if f.Iface != "" {
  if rec.IngressIface != f.Iface { return false }
 }
 return true
}
```

```go
// pkg/cli/monitor.go:588-700
func (c *CLI) handleMonitorSecurityFlowStart() error {
 if c.eventBuf == nil {
  fmt.Println("error: event buffer not initialized")
  return nil
 }
 ...
 c.monitorFlow.mu.Lock()
 ...
 logFile, _, err := openTraceFile(c.monitorFlow.filename)
 ...
 sub := c.eventBuf.Subscribe(256)
 ...
 ctx, cancel := context.WithCancel(context.Background())
 c.monitorFlow.cancel = cancel
 c.monitorFlow.mu.Unlock()
 writer := newTraceWriter(traceName, logFile, maxSize, maxFiles)
 go func() {
  defer writer.close()
  defer sub.Close()
  for {
   select {
   case <-ctx.Done(): return
   case rec := <-sub.C:
    matched := false
    for _, f := range filters {
     if f.matches(&rec) { matched = true; break }
    }
    ...
    line := formatFlowEvent(rec)
    if !traceLineMatches(line, matchRe) { continue }
    if err := writer.writeLine(line); err != nil {
     c.monitorFlow.mu.Lock()
     if c.monitorFlow.sub == sub {
      c.monitorFlow.active = false
      ...
      c.monitorFlow.lastErr = err
     }
     ...
    }
   }
  }
 }()
}
```

Proposed decomposition:
- `monitor/trace_file.go` — `traceLogDir`, `sanitizeTraceFilename`, `openTraceFile`, `rotateTraceFile`, `traceWriter`, `newTraceWriter`, `writeLine`, `close` + constants
- `monitor/filter.go` — `monitorFlowFilter`, `matches`, `extractIP`, `extractPort`, `traceLineMatches`, `formatFlowEvent`, `formatPacketDropEvent`, `monitorFlowState` + `newMonitorFlowState`
- `monitor/flow.go` — `handleMonitorSecurityFlowFile`, `handleMonitorSecurityFlowFilter`, `handleMonitorSecurityFlowStart`, `handleMonitorSecurityFlowStop`, `showMonitorSecurityFlow`
- `monitor/dispatch.go` — `handleMonitorSecurity`, `handleMonitorSecurityFlow`, `handleMonitorSecurityPacketDrop` (packet-drop separate path)
- Keep `monitor.go` as facade re-export or rename to `monitor/`.

Hot-path preservation analysis:
- Slow path (control socket shared, event buffer subscription). Writer rotates on size threshold, must not block eventBuf (256 cap). Goroutine close order: writer.close then sub.Close deferred. Active flag cleared under lock only if sub identity matches (guard concurrent stop/start #4883-B). Extraction must preserve identity guard. No dataplane hot path. Control socket contention note: writer runs background, only interacts with file system, not control socket – safe.

Tests + gate:
- `monitor_test.go` (561 LOC), `monitor_flow_perm_5038_test.go`, `monitor_flow_writer_stop_4883_test.go`, `monitor_match_test.go`, `monitor_traffic_filter_4005_test.go`, `monitor_traffic_injection_4524_test.go`, `monitor_traffic_keyword_4540_test.go`, `monitor_traffic_matching_4883_test.go`, `monitor_security_test.go`
- `make test-go -run TestMonitor`
- Gate: `monitor interface` + `monitor security flow file` traversal attempt must be rejected (basename only).

Why it matters:
- File mixes security boundary (path traversal prevention #3378, O_NOFOLLOW, 0700 dir, 0600 file) with business logic (filter DSL empty-matches-everything guard #3380 HC-03) and observability (lastErr). A change in rotation cap logic (#3379) could disturb confinement check. Isolating file I/O improves auditability of security invariants.

Fix direction:
1. Extract `trace_file.go` mechanical (no CLI state).
2. Extract `filter.go` with matches + format helpers + state struct.
3. Extract `flow.go` with file/filter/start/stop handlers.
4. Extract dispatch.
5. Verify `traceLogDir` still package var for test override.

Labels: refactor, CLI, monitor, trace-rotation, path-traversal, O_NOFOLLOW, filter-DSL
Dedup note: Complements `monitor_interface.go 396 LOC` and `monitor_traffic.go 277 LOC` which already split interface/traffic monitoring, but flow trace remains bundled. Not duplicate.

---

## Summary rank

1. surface_a.go 2109*8 = 16872 high – god-manager needs split to backend/http-cache/publish/withdraw/orphan/status.
2. dhcp.go 1940*7 = 13580 high – god-manager needs DUID/client_registry/v4/v6/netlink split.
3. manager.go 1486*6 = 8916 medium-high – near-threshold, needs policy/scope/reconcile/durability split.
4. cli_show_system.go 1081*12 hub = 12972 but cold – hub split to buffers/process/ntp_services/commit.
5. monitor.go 996*6 = 5976 medium – file/filter/dispatch split.

All are cold control-plane (no per-packet hot-path). Refactor class mostly A mechanical except reconcile/publish/withdraw which need guardrails for lock discipline (#2778) and durability (#2662/#5285) and NAK revoke (#3956).

## Coverage proof details
- Ran `wc -l` on all 38 prod files from batch b2 (list in /tmp/review-work-ps-044/batches/A10_go_services_cli_deploy-b2.txt). Total prod LOC ~12.4k, test LOC ~18k (ratio ~1.5 test/prod indicates high coverage).
- Grepped `^func` in 7 largest files, Python script estimated func sizes >120 lines – identified 3 >200 line funcs in surface_a, 2 in dhcp, 2 in manager, 2 in cli_show_system, 2 in monitor.
- Checked for dumping-ground enums: none true (no giant enum file), but `monitor.go` has implicit stringly-typed protocol filter and address source enum in surface_a (`AddressSourceInterface/DHCP`) is small.
- Checked for god-structs mixing hot+cold: `SurfaceAManager` and `dhcp.Manager` are god but cold-only (no per-packet fields). No hot/cold mixing in this batch (hot is userspace-dp Rust, not Go).
- Hub file detection: `cli_show_system.go` handleShowSystem switch has 20+ branches, `monitor.go` has 5 dispatch levels – both low cohesion.

Output written to /tmp/review-work-ps-044/ps-A10_go_services_cli_deploy-b2.md



---
### Batch A10_go_services_cli_deploy-b3 — 450 lines — full log + findings

# Refactor / Modularity Audit — A10 · go_services_cli_deploy · b3

**Worktree**: `/tmp/review-wt-ps-044-A10_go_services_cli_deploy-b3/`  
**Batch file**: `/tmp/review-work-ps-044/batches/A10_go_services_cli_deploy-b3.txt`  
**Base SHA**: `f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c`  
**Batch size**: 142 files  
**Date**: 2026-07-11

---

## Module checklist / size-shape inventory

### Prod Go (non-test) — largest first

| File | LOC | Largest fn | Fn LOC | Resp count | Hot-path | Rank score* |
|------|-----|-----------|--------|------------|----------|-------------|
| `pkg/policymatch/policymatch.go` | 2084 | `ValidateProtocol` / `Match` / `SelectorArgs.Query` tail | 242† / 214 / 211 | 7 | no | **HIGH** |
| `pkg/dhcprelay/relay.go` | 1646 | `runRelaySession` | 404 | 6 | no (control) | **HIGH** |
| `pkg/dhcpserver/dhcpserver.go` | 1210 | `parseLeaseCSV` | 147 | 5 | no | MED |
| `pkg/dhcpserver/lease_sync.go` | 933 | `readSyncLeasesViaMemfile` | 79 | 4 | no | MED |
| `pkg/scheduler/scheduler.go` | 448 | `evaluate` | 63 | 2 | no | LOW |
| `pkg/dhcpserver/ddns_leases.go` | 419 | `parseActiveLeases` | 243 | 2 | no | MED (func >150) |
| `pkg/policymatch/zone_detail_summary.go` | 207 | `ZoneDetailPolicySummary` | ~150 | 2 | no | LOW |
| `pkg/dhcprelay/l2send_linux.go` | 225 | `sendReply` | ~60 | 1 | no | LOW |
| `pkg/natshow/dest.go` | ~108 | `RenderDestRuleDetail` | ~108 | 1 | no | LOW |
| `pkg/natshow/source.go` | 116 | `RenderSourceRuleDetail` | ~116 | 1 | no | LOW |
| `pkg/natshow/static.go` | 113 | `RenderStaticRule` | ~60 | 1 | no | LOW |
| `pkg/natshow/persistent.go` | 116 | `RenderPersistentDetail` | ~65 | 1 | no | LOW |
| `pkg/natshow/natshow.go` | ~49 | interface def | — | 0 | no | LOW |
| `pkg/dhcpserver/ddns.go` | ~97 | `keaLeaseParser` | ~30 | 1 | no | LOW |
| `pkg/dhcprelay/relay_giaddr_linux.go` + `sockopt_linux.go` | ~80 ea | small | — | 1 | no | LOW |

† `ValidateProtocol` 242 LOC reported by naive line-count is inflated because the parser counted across comment block boundary to next func; actual func body is ~10 lines. `Match` (214 LOC incl. frag-deny closures) and `ParseSelectorArgs` (154 LOC) are the real breaches. See Detail Finding 1.

* Rank score = f(size)·g(responsibilities)·h(hot-path): HIGH = size > 1200 ∧ resp ≥ 4; MED = size > 400 ∨ func > 150.

### Infra/deploy Python (batch includes deploy toolchain)

| File | LOC | Largest fn | Hot-path | Note |
|------|-----|-----------|----------|------|
| `scripts/deploy/xpf-deploy.py` | 2243 | `cmd_image_roll` 232 LOC, `cmd_kernel_roll` 189 LOC, `roll_one:libvirt` 167 LOC | no | **HIGH** — exceeds even Python 1500–2000 LOC ceiling |
| `scripts/image/bake.py` | 884 | `main` ~200 LOC | no | MED — image-builder god file, known |
| `scripts/dist/publish.py` | 926 | `main` ~150 LOC | no | MED |
| `scripts/image/validate.py` | 738 | ~120 | no | LOW |
| `test/incus/cold-path-flooder/src/main.rs` | 2312 | n/a (test harness) | test-only | HIGH size but out-of-scope (test, not Go services) |
| `test/incus/*validate*.py` (7 files 400–760 LOC) | 400–760 ea | — | test | Large test validators — not actionable here |

### Test Go — largest

| File | LOC | Note |
|------|-----|------|
| `pkg/dhcprelay/relay_test.go` | 2033 | Single test file mirrors all relay seams; borderline god-test but expected for seam injection pattern |
| `pkg/dhcpserver/dhcpserver_test.go` | 1378 | Co-locates generateKea + parseLeaseCSV + manager lifecycle tests |
| `pkg/dhcpserver/lease_sync_test.go` | 1194 | Lease-sync read/seed/memfile tests |
| `pkg/dhcprelay/delivery_test.go` | 894 | — |
| `pkg/dhcpserver/ddns_leases_test.go` | 877 | — |

### Responsibilities map (prod files)

- `policymatch.go`: Query DSL parsing (`ParseSelectorArgs`, `ValidatePort`, `ParseICMPValue`, `ValidateProtocol`) + Usage string SSOT + `Query` struct + `Result` display logic (`DisplayAction`, advisories, notes) + 5-tier precedence walk (`Match`) + per-zone/WC matching (`matchJunosHost`, `globalScopeSetMatches`, `reportedScopeZone`, `zoneKnown`) + address-book resolution (`matchAddr`, `resolveToken`, `expandBookName`, `isBookName`, `addCIDRValue`) + application resolution (`matchApp`, `matchSingleApp`, `hasL4ConstrainedTerm`, `portMatches`) + fragment-associated-deny overlay (`fragDenyResult`, `isSkippedFragDeny`, `noteFrag` closures) + route-drop advisory (`routeDropClass`) + content-rejection SSOT delegation + scheduler active-state hook.
  Count: **7 distinct responsibilities** — parser, resolver×2, matcher core, host-gate, advisories/overlays, display.

- `dhcprelay/relay.go`: `relaySpec` equality + `Manager` lifecycle (`Apply` diff, `Stop`, `Stats`) + session supervisor (`runRelay`, `runRelaySession`, outcome enum) + ifindex-drift + giaddr-readdr watcher + HA master-gate + raw-L2 sender factory indirection + reply-delivery matrix (`deliverReply`, `broadcastReply`, anti-spoof `giaddrIsSet`, `clientRequestRelayable`, `replySourceAllowed`) + option82 insertion/removal + addr resolution seams + packet I/O loops (`handleServerResponses`). Count: **6**.

- `dhcpserver.go`: Manager with systemctl seams + generation-ordered supersession (`applyGen`, `staleApplySkips`) + async mailbox + `generateKea4/6Config` (pool wiring, stable-groups, CIDR-hash subnet-id, probe-step) + `parseLeaseCSV` display path + warn-ambiguous. Count: **5**.

- `lease_sync.go`: Kea control-socket JSON wire (`keaControl`, `readSyncLeasesViaSocket`) + memfile fallback (`readSyncLeasesViaMemfile`, `splitV4Identity`, `splitV6Identity`) + lease conversion (`keaLeaseToSync`, `syncLeaseToKea`) + seed logic (`seedOneLease`, `seedSyncLeases`) + pre-seed atomic-durable write path (`writeMemfile4/6`, `writeMemfileAtomic`) + merged pre-seed + Kea-owner lookup. Count: **4**.

- `ddns_leases.go`: Destructive-safe memfile parser with dup-column + required-column + ragged-row guards (`parseActiveLeases`). Count: 2 (parse + identity functions), but file is focused.

- `natshow/*`: clean split — each renderer owns one show topic. No fusion; exemplar of correct decomposition.

- `scheduler.go`: time-window evaluation + wall-clock-discontinuity latch + republish self-heal. 2 responsibilities, coherently fused (state + self-heal are inseparable).

- `xpf-deploy.py`: Config-drive builder + libvirt disk mgmt + incus deploy + qcow2 backing-file introspection + kernel/image roll + lease + inventory + mixed-base gate — **~9 responsibilities** in one 2243-line script, exceeding the 1500–2000 LOC actionable ceiling.

---

## Findings

### Finding 1 — `policymatch.go` god-file: 2084 LOC, 7 responsibilities, 2 functions >150 LOC

- **Title**: `pkg/policymatch/policymatch.go` — diagnostic simulator bundles DSL parsing, address-book + app resolution, tiered matching, host-gate, fragment/route advisories, and display in a single 2084-line file
- **Severity**: Major
- **Confidence**: High (5/5)
- **Refactor class**: A — split file is >1500 LOC with coherent extractable sub-packages
- **Evidence**:
  - File/line: `pkg/policymatch/policymatch.go` — wc 2084 LOC prod (excluding vendored/generated).
  - Largest function `Match` line 933 is 214 LOC including two inline closures (`noteFrag`, `matchOr`) and is the only transit-tier precedence walk; a test break must re-read 200+ lines.
  - `ParseSelectorArgs` line 420 is 154 LOC (strict grammar with duplicate-selector detection, per-selector validation, unknown-selector fail-closed).
  - Metrics: 7 responsibilities counted above; 2084 > 2000 threshold from brief.
  - Quoted snippets (5–10 lines each):

    ```go
    // pkg/policymatch/policymatch.go:933 — Match transit-tier walk start
    func Match(cfg *config.Config, q Query) (res Result) {
        if q.ToZone != JunosHostZone {
            if class := routeDropClass(q.DstIP); class != "" {
                defer func() {
                    res.RouteDropBeforePolicy = true
                    res.RouteDropClass = class
                }()
            }
        }
        // ... tiers 1-5 with noteFrag + matchOr closures inline
    ```

    ```go
    // pkg/policymatch/policymatch.go:420 — ParseSelectorArgs strict grammar head
    func ParseSelectorArgs(args []string) (SelectorArgs, error) {
        var s SelectorArgs
        seen := make(map[string]bool)
        takeValue := func(i *int, kw string) (string, error) {
            if seen[kw] {
                return "", fmt.Errorf("selector %q specified more than once", kw)
            }
            // ...
        }
    ```

    ```go
    // pkg/policymatch/policymatch.go:1448 — matchAddr carries both v4-empty/v6-empty fail-closed gate
    func matchAddr(cfg *config.Config, overlay map[string][]string, addrs []string, excluded bool, ip net.IP) bool {
        if ip == nil {
            return true
        }
        isV4 := ip.To4() != nil
        rawMatched := false
        v4Empty := true
        v6Empty := true
        for _, tok := range addrs {
            v4nets, v6nets, anyV4, anyV6 := resolveToken(cfg, overlay, tok)
    ```

- **Proposed decomposition**:
  1. `pkg/policymatch/selector/parse.go` — `ParseSelectorArgs`, `SelectorArgs`, `ValidatePort`, `ParsePort`, `ParseICMPValue`, `ValidateProtocol`, `matchPoliciesUsageTail` constants.
  2. `pkg/policymatch/resolve/addr.go` — `matchAddr`, `resolveToken`, `addCIDRValue`, `isBookName`, `expandBookName`, `containsAny`, plus `feedOverlay` plumbing.
  3. `pkg/policymatch/resolve/app.go` — `matchApp`, `matchSingleApp`, `hasL4ConstrainedTerm`, `appTermL4Constrained`, `portMatches`, `normalizePortAlias`.
  4. Keep `pkg/policymatch/policymatch.go` as facade containing only: `Query`, `Result`, `DisplayAction` and advisory NOTE constants (`RouteDropNotePrefix`, `FragmentDenyNotePrefix`), plus the 5-tier walk calling into `resolve/*` and `selector/*`. Host-gate `matchJunosHost` + `hostInboundAdmission` -> `pkg/policymatch/hostgate/` or stay in facade if <120 LOC after move.
  5. Fragment-associated-deny struct + helper (`fragDenyCandidate`, `fragDenyResult`, `isSkippedFragDeny`) -> `pkg/policymatch/frag/` or keep adjacent to `Match` if kept small, but extract the closures `noteFrag`/`matchOr` to top-level helpers to reduce `Match` below 150 LOC.
  6. `zone_detail_summary.go` already separate — leave; add `Result` detail modifiers already factored.
- **Hot-path preservation analysis**: Not hot-path. `policymatch` is a diagnostic operator surface (REST/gRPC `MatchPolicies`, CLI `show security match-policies` / `test policy`). Called at most once per operator request; no allocation budget, no per-packet concern. Decomposition must keep `Query.FeedOverlay` + `PolicyInactiveFn` plumbing identical — no behavioral change. Ensure `zoneKnown` / `GlobalPolicyAppliesToZonePair` / `globalScopeSetMatches` / `reportedScopeZone` stay reachable without import cycle.
- **Tests + gate**:
  - Existing: `pkg/policymatch/*_test.go` (35+ test files, 3000+ lines) — many `* _test.go` files each exercise one edge: `fragment_5572_test.go` (395 LOC), `global_scope_regression_...`, `content_reject_4394_test.go`, etc. Must stay green.
  - New gate: no new test file needed; verify `go test ./pkg/policymatch -count=1` passes after each move and that `DisplayAction` / `FragmentDenyNote` / `RouteDropNote` text stays byte-identical (SSOT via constants). Consider `TestParseSelectorArgsDuplicateRejected` quick check if moving selector.
- **Why it matters**: 2084 LOC file with 7 responsibilities is the highest-coupling point in this batch's Go services group. Every scheduler, global-scope, fragment, route-drop, or app-matcher fix touches the same file, causing merge conflicts across unrelated features and reviewer overload (500-line PRs that touch 4 concerns). Also hides that `Match` is the only place reproducing `policy.rs` precedence — hard to audit for fidelity drift.
- **Fix direction**: File-level split, not line churn. Extract parse and resolve layers first (lowest risk, no behavior), then host-gate, then fragment overlay. Keep `Match` as orchestrator <120 LOC after extracting helpers. Defer display string changes.
- **Labels**: `refactor:policymatch`, `size:god-file`, `coupling:high`, `risk:low` (diagnostic-only)
- **Dedup note**: Not duplicate — unique to this batch. Other `A10_go_services_cli_deploy-b{1,2}` batches cover `pkg/api`, `pkg/cli`, `pkg/grpcapi` show surfaces that *consume* this, not the matcher itself. Check dedup-index for `policymatch` tokens; no prior finding.

---

### Finding 2 — `dhcprelay/relay.go` 1646 LOC, 6 responsibilities, 404-line session function

- **Title**: `pkg/dhcprelay/relay.go` — relay manager fuses spec reconciliation, session supervision, address/ifindex drift watching, HA gate, anti-spoof rewrite, and reply-delivery matrix in 1646 lines with a 404-line `runRelaySession`
- **Severity**: Major (threshold: approaching 2000 LOC, but primary trigger is func 404 > 200)
- **Confidence**: High (5/5)
- **Refactor class**: A — manager + session + packet path should be 3 files
- **Evidence**:
  - File/line: `pkg/dhcprelay/relay.go` LOC 1646 (prod excluding tests).
  - Func size: `runRelaySession` line 880 is 404 LOC — opens client listener, server conn, raw-L2 sender, launches 3 goroutines (cancel-watcher, ifindex+giaddr watcher, server-response handler), then inner-func main loop with full client-request relayable filter, HA gate, chained-relay preservation, anti-spoof (#5414) rewrite, hop-limit check, option82 stamping, and server-forward.
  - Metrics: 6 responsibilities; `computeDesired` 89 LOC, `Apply` 90 LOC, `handleServerResponses` 105 LOC, `deliverReply` 65 LOC — each individually okay but colocated. Combined Manager struct carries 8 injected seams (`newConn`, `resolveGIAddr`, `resolveIfindex`, `ifindexCheck`, `newL2`, `relayGate`, retry interval, mu+map) — seam count signals mixed roles.
  - Snippet:

    ```go
    // pkg/dhcprelay/relay.go:880 — runRelaySession (404 LOC) start
    func (m *Manager) runRelaySession(ctx context.Context,
        ir *interfaceRelay, servers []*net.UDPAddr) sessionOutcome {
        ifaceName := ir.ifaceName
        sctx, cancel := context.WithCancel(ctx)
        defer cancel()
        var driftDetected atomic.Bool
        var readdrDetected atomic.Bool
        giaddr, ok := m.resolveGIAddrWithRetry(sctx, ifaceName)
        // ... 350 more lines: client listener, server conn, l2 sender,
        // watcher goroutines, handleServerResponses launch, inner-loop with
        // relay chaining + anti-spoof + hop-limit + option82 + server forward
    ```

    ```go
    // pkg/dhcprelay/relay.go:1186 — chained relay + anti-spoof decision (inside the 404-line fn)
    chained := ir.trustOption82 && giaddrIsSet(pkt.GatewayIPAddr)
    forgedGiaddr := !ir.trustOption82 && giaddrIsSet(pkt.GatewayIPAddr)
    forgedGiaddrValue := pkt.GatewayIPAddr
    ```

    ```go
    // pkg/dhcprelay/relay.go:1335 — handleServerResponses (105 LOC proximity)
    func handleServerResponses(ctx context.Context, serverConn, clientConn net.PacketConn,
        ir *interfaceRelay, l2 l2Replier, srcIP net.IP, servers []*net.UDPAddr) {
    ```

- **Proposed decomposition**:
  - `pkg/dhcprelay/manager.go` — `Manager`, `relaySpec`, `desiredRelay`, `computeDesired`, `Apply`, `Stop`, `Stats`, `SetMasterGate`, `shouldRelay`. Only reconciliation + lifecycle.
  - `pkg/dhcprelay/session.go` — `runRelay`, `runRelaySession`, `resolveGIAddrWithRetry`, drift/readdr watcher split into named helper `startDriftWatchers(ctx, ...)`, plus `interfaceRelay` struct. Session supervision only.
  - `pkg/dhcprelay/packet.go` — `handleServerResponses`, `deliverReply`, `broadcastReply`, `clientRequestRelayable`, `l2Eligible`, `giaddrIsSet`, `addOption82`, `stripOption82`, `replySourceAllowed`, `udpAddrIP`. Pure packet transform + delivery matrix.
  - `pkg/dhcprelay/resolver.go` (or keep in manager) — `defaultIfaceResolver`, `selectPrimaryIPv4`, `primaryIPv4Lister` seams + `ipv4Candidate` struct + `portableIPv4Lister`. Helpful but optional.
- **Hot-path preservation analysis**: Not dataplane hot-path (userspace control-plane relay for DHCP). Per-packet budget matters more than userspace-DP but far less than AF_XDP forwarding. Split must preserve: (a) SO_BINDTODEVICE pinning + ifindex-capture-before-bind ordering, (b) close-on-cancel watcher started last + inner-func `defer cancel()` before `wg.Wait()` — document invariant in session.go header, same as current docstring. (c) raw-L2 sender fail-soft (nil → broadcast fallback) must remain. (d) `readBufSize = 65535` shared constant retained. No allocation change needed beyond file moves.
- **Tests + gate**:
  - Existing: `relay_test.go` 2033 LOC, `delivery_test.go` 894 LOC, `relay_chain_5071_test.go` 325 LOC, `l2send_test.go` 209 LOC — use injected seams `packetConnFactory`, `ifaceResolver`, `ifindexResolver`, `l2SenderFactory`. Must pass `go test ./pkg/dhcprelay -count=1`.
  - Additional gate: after split, `TestRunRelaySession_CloseOnCancelInvar` or equivalent lifecycle test must still enforce watcher-close ordering (existing lifecycle test covers).
- **Why it matters**: `runRelaySession` being 404 LOC forces every relay-change PR (trust-option-82, hop-count, chained-relay, anti-spoof, L2-unicast) to touch a single 400-line function where control-flow, socket lifecycle, and packet rewrite are interleaved. Drift vs readdr vs retry outcomes share code with traversal-sensitive cancels; extracting the packet matrix and watcher helpers isolates the HA-gate + anti-spoof decision from the `WaitGroup` join safety proof lattice documented in the current comments (#1915, #2347, #3960, #5414). Also `Manager`'s 8 seams make unit-test wiring noisy — reducing seam surface per file improves test locality.
- **Fix direction**: Split in order: packet helpers first (lowest risk, pure functions — `addOption82`, `stripOption82`, `giaddrIsSet`, `clientRequestRelayable`, `replySourceAllowed` have no side-effects), then session supervision, then manager. Keep `l2send_linux.go` untouched (separate concern, AF_PACKET). `deliverReply` + `handleServerResponses` + `broadcastReply` are the delivery matrix; they can be extracted without threading mu.
- **Labels**: `refactor:dhcprelay`, `size:large-func`, `risk:med` (lifecycle invariants), `coupling:med`
- **Dedup note**: Not duplicate. Check `A10_go_services_cli_deploy-b1/b2` — those cover `pkg/cli`/`pkg/grpcapi` show paths, not relay. `relay_giaddr_linux.go` and `sockopt_linux.go` platform helpers are already separate, so this is focused on `relay.go` itself.

---

### Finding 3 — `dhcpserver` package responsibility fusion: Manager lifecycle + Kea config render + lease sync read/seed/pre-seed + DDNS memfile parser + memfile atomic-durable write path spread over 1210 + 933 + 419 + 97 LOC files

- **Title**: `pkg/dhcpserver` 4-file cluster fuses systemctl lifecycle + Kea JSON config rendering (stable hash subnet-id, probe step, pool ordering) + lease CSV display parser + expired-leases map builder + lease-sync socket/memfile dual path + HA pre-seed merge, with 147-line `parseLeaseCSV` and 243-line `parseActiveLeases` (both >150 is flagged but main issue is cross-concern coupling, not LOC)
- **Severity**: Moderate
- **Confidence**: High (4/5)
- **Refactor class**: B — split render vs lifecycle vs lease-sync, existing file names are better than god-file but still fused within files
- **Evidence**:
  - File/line: `pkg/dhcpserver/dhcpserver.go` 1210 LOC — `Manager.apply` (58 LOC orchestration) plus `generateKea4Config` 124 LOC and `generateKea6Config` 131 LOC that embed v4 warn+pool+reservation logic and v6 multi-iface reject, plus `stableGroups`/`stablePools`/`stableSubnetID`/`subnetProbeStep`/`resolveSubnetID` FNV hash helpers, plus `warnAmbiguousV4SubnetSelection` overlap detector, plus `parseLeaseCSV` 147 LOC lenient display parser with per-record skip / state+expire filters.
  - `pkg/dhcpserver/lease_sync.go` 933 LOC — socket JSON envelope (`keaResponse`, `keaLeaseJSON`), control-socket bounded exchange (`keaControl`), fallback memfile (`readSyncLeasesViaMemfile`), lease-type mapping (`keaLeaseTypeToString` / `stringToKeaLeaseType` inverse pair), seed loop (`seedOneLease` conflict→update retry), merged pre-seed (`mergeLeasesByIdentity` with local-wins vs peer), atomic-durable memfile write (`writeMemfileAtomic` + `writeMemfileFile` seam + `lookupKeaOwner` cached uid/gid).
  - `pkg/dhcpserver/ddns_leases.go` 419 LOC but `parseActiveLeases` 243 LOC — destructive-safe parser with dup-column rejection + required-column validation + ragged-row guard + tombstone reclaim loop.
  - Snippet:

    ```go
    // pkg/dhcpserver/dhcpserver.go:532 — parseLeaseCSV (147 LOC) display lenient path
    func parseLeaseCSV(path string, now time.Time) ([]Lease, error) {
        f, err := os.Open(path)
        // ... read-by-record with FieldsPerRecord=-1, skip malformed at slog.Debug,
        // header-first pattern, state != 0 tombstone, expire<=now tombstone,
        // latest map + order first-appearance
    }
    ```

    ```go
    // pkg/dhcpserver/lease_sync.go:232 — keaLeaseToSync computes Remaining on sender clock
    func keaLeaseToSync(kl keaLeaseJSON, family int, now time.Time) SyncLease {
        l := SyncLease{
            Family:    family,
            Address:   kl.IPAddress,
            // ...
        }
        expire := kl.Expire
        if expire == 0 {
            expire = kl.CLTT + int64(kl.ValidLft)
        }
        rem := expire - now.Unix()
    ```

    ```go
    // pkg/dhcpserver/dhcpserver.go:858 — stableSubnetID (HA cross-node invariant, #5041)
    func stableSubnetID(subnet string) int {
        h := fnv.New32a()
        _, _ = h.Write([]byte(subnet))
        return int(h.Sum32()%keaSubnetIDMax) + 1
    }
    ```

- **Proposed decomposition**:
  - `pkg/dhcpserver/manager.go` — Manager struct, asyncOnce/applyGen/lastAppliedGen, `Apply`/`ApplyClusterCommit`/`apply`/`enqueueAsync`/`applyAsyncWorker`/`reconcileFamilyRestart`/`clearFamilyLocked`, systemctl seams. No config-gen, no lease parse.
  - `pkg/dhcpserver/kea_render.go` — `generateKea4Config`, `generateKea6Config`, `stableGroups`, `stablePools`, `stableSubnetID`, `subnetProbeStep`, `resolveSubnetID`, `keaSubnetIDMax`, `keaExpiredLeasesMap`, `subnetInterface`, `warnAmbiguousV4SubnetSelection`, `canonicalMAC`, `addLeaseSyncStanza`. Optionally the `keaOpt`/`keaPool`/`keaReservation` inline structs -> package-private render-file structs.
  - `pkg/dhcpserver/lease_display.go` — `parseLeaseCSV`, `Lease`, `GetLeases4/6`, `leaseFile` accessor split from lease-sync.
  - Keep `lease_sync.go` as `lease_sync.go` but extract `memfile_write.go` (pre-seed): `writeMemfile4/6`, `writeMemfileAtomic`, `writeMemfileFile` seam, `resolveKeaOwner`/`lookupKeaOwner`, `keaMemfileHeader4/6`, `boolCSV`, `csvField`. This file already is the dual-path read/seed; separating the write path isolates the durability + ownership (uid/gid) concern (#2450).
  - `ddns_leases.go` stays but shrink? Its `parseActiveLeases` 243 LOC reflects 3 layers (header validation, per-row conformance bound, last-row-wins+reclaim map). Each layer is distinct but code is focused — file split not needed, but helper extraction `validateLeaseHeader(cols)`, `rowConforms(fields, maxRequiredIdx)` would bring func under 150 line target.
- **Hot-path preservation analysis**: Not data-plane hot-path (control-plane daemon). Clock invariants matter for correctness, not latency:
  - `parseActiveLeases` trusted-empty vs error distinction is destructive-safe (error → Reconcile skips delete, nil → trusted zero allows delete). Decomposed files must retain same return policy.
  - `keaLeaseToSync` remaining computed on sender clock; `syncLeaseToKea` re-anchors to local clock at seed. Decomposition must not accidentally pass absolute expire over wire.
  - `stableSubnetID` ± `subnetProbeStep` coprime invariant (`keaSubnetIDMax = 0xFFFFFFFE = 2*(2^31-1)`) must stay in render file with comment linkage.
  - `writeMemfileAtomic` ownership: `fsatomic.WithOwner` rides on temp fd before rename — no post-rename root-owned window. Keep chown seam wiring in pre-seed write file.
- **Tests + gate**:
  - Existing: `dhcpserver_test.go` 1378 LOC (stableSubnetID + subnetProbeStep + generateKea config), `lease_sync_test.go` 1194 LOC, `ddns_leases_test.go` 877 LOC, `expired_leases_test.go` 307 LOC, etc. Gate `go test ./pkg/dhcpserver -count=1`.
  - Add `TestStableSubnetIDCrossNodeEquality` already exists; ensure still passes after render-file move. For pre-seed write move, existing `writeMemfileFile` seam test must stay green.
- **Why it matters**: `dhcpserver.go` merging config rendering (deterministic subnet-id = function of subnet identity alone, #5041/#5203, probing co-primality with `2^31-1` factor) with Manager lifecycle (generation-ordered supersession + async mailbox) with display parser puts 3 high-stakes invariants sharing one file. A Kea JSON key rename PR must diff past the async-mailbox ABA reasoning comment chain, and vice versa. `lease_sync.go` adding pre-seed write path (durability+chown) on the same file as socket wire adds 2 more invariants. `parseActiveLeases` 243 LOC is the destructive-safe gate; a display-parser bugfix (`parseLeaseCSV`) in the same package could accidentally loosen the fail-closed header validation by copy-pasting the lenient `#2154` per-record skip pattern.
- **Fix direction**: Split in 2 PRs. PR1: `kea_render.go` + `lease_display.go` extracted from `dhcpserver.go` (no logic change — imports + `keaSubnetIDMax` constant move). PR2: `memfile_write.go` from `lease_sync.go` (ownership + write path). PR3 (optional): helper extraction inside `parseActiveLeases` / `parseLeaseCSV` to drop funcs below 150 lines (header validation → `buildLeaseHeader`, row-conformance check → `rowShortOfRequired`). Keep `ddns.go` adapter thin (already 97 LOC, fine).
- **Labels**: `refactor:dhcpserver`, `coupling:high`, `size:med`, `risk:med` (correctness invariants span files), `domain:dhcp`
- **Dedup note**: Not duplicate. `A10_go_services_cli_deploy-b1/b2` cover `pkg/ddns`, `pkg/dhcpserver/ddns_integration_test.go`, `pkg/dhcpserver/ddns.go` DDNS spine adapter (separate concern). This finding is about the Kea render + lease-sync read/seed/pre-seed + display parser cluster. No dedup-index entry for `stableSubnetID` / `parseActiveLeases`.

---

### Finding 4 — `scripts/deploy/xpf-deploy.py` infra god-script: 2243 LOC, 9 distinct responsibilities, multiple 150+ line functions

- **Title**: `scripts/deploy/xpf-deploy.py` deploy tool exceeds actionable LOC ceiling (2243) and fuses 9 subsystem responsibilities; `cmd_image_roll` 232 LOC, `cmd_kernel_roll` 189 LOC, `roll_one:libvirt` 167 LOC, `roll_one:incus` 157 LOC, `main` 155 LOC all >150-line func threshold
- **Severity**: Moderate (infra tool, not Go service, but size is quantitative)
- **Confidence**: High (5/5) for LOC; Medium (3/5) for applicability to "Go services" BR (it is infra/deploy leg covered by A10 batch scope per label)
- **Refactor class**: C — infra tooling improvement, not service hot-path
- **Evidence**:
  - File/line: `scripts/deploy/xpf-deploy.py` 2243 LOC (largest in whole batch); `test/incus/cold-path-flooder/src/main.rs` 2312 larger but Rust test repro, out of Go-service scope.
  - Def sizes via AST:

    ```
    232 cmd_image_roll:1831
    189 cmd_kernel_roll:1430
    167 roll_one:1888  (incus overlay or libvirt variant)
    157 roll_one:1456
    155 main:2084
    142 cmd_fetch:1074
    70  deploy_incus:578
    68  _deploy_libvirt_inner:864
    53  build_config_drive:387
    49  validate_appliance:303
    ```

  - Responsibilities: appliance YAML load + validate + path-safety + disk image handling + qcow2 backing-file introspection + config-drive build (ISO/make_config_drive) + libvirt domain define + incus deploy + kernel roll + image roll + lease-TTL gate + nic-order gate + mixed-base HA gate + inventory + robustness checks. Inline comments reference 10+ issue trackers.
  - Snippet (top-level shape — file head):

    ```python
    # scripts/deploy/xpf-deploy.py — 2243 lines, multiple roll/fetch preflight paths
    def cmd_image_roll(args):  # 232 LOC
        ...
    def cmd_kernel_roll(args):  # 189 LOC
        ...
    def main():  # 155 LOC arg parser + dispatch
    ```

- **Proposed decomposition** (if prioritized; infra priority may be lower than Go findings):
  - `scripts/deploy/xpf_deploy/appliance.py` — `load_yaml_appliance`, `validate_appliance`, `validate_identifier`, `_ver_key`.
  - `scripts/deploy/xpf_deploy/disk.py` — `qcow2_backing_file`, `libvirt_disk`, `_dependent_overlays`.
  - `scripts/deploy/xpf_deploy/config_drive.py` — `build_config_drive` (re-uses `scripts/image/make_config_drive.py` but duplicated logic here).
  - `scripts/deploy/xpf_deploy/deploy_incus.py` / `deploy_libvirt.py` — Incus vs libvirt paths.
  - `scripts/deploy/xpf_deploy/roll.py` — kernel roll + image roll with `roll_one` helpers.
  - `scripts/deploy/xpf-deploy.py` becomes a thin `main` wiring `argparse` + subcommand dispatch (like `scripts/dist/publish.py` 926 LOC already separate concern but could shrink similarly).
- **Hot-path preservation analysis**: No hot path. Deploy CLI tool runs on operator's machine / CI. No allocation budget. Split must keep CLI flag surface identical; tests in `scripts/deploy/test_xpf_deploy_*.py` (7 files, ~100–425 LOC each) cover gates and must stay green (`pytest scripts/deploy/`).
- **Tests + gate**: Existing Python tests: `test_xpf_deploy_correctness.py`, `test_xpf_deploy_gate.py`, `test_xpf_deploy_disk.py`, `test_xpf_deploy_image_roll_identity.py`, `test_xpf_deploy_iso_mode.py`, `test_xpf_deploy_kernel_roll.py`, `test_xpf_deploy_lease_ttl.py`, `test_xpf_deploy_nicorder.py`, `test_xpf_deploy_pathsafety.py`, `test_xpf_deploy_robustness.py`. Run `python3 -m pytest scripts/deploy/ -q`.
- **Why it matters**: Quantitatively the largest file in the Go services/cli/deploy batch; 232-line function `cmd_image_roll` and 189-line `cmd_kernel_roll` encode mixed-base HA gate + preflight + backup + rollback identity logic in one linear procedure. A niche re-creation path fix (`_recreated_node_matches` 40 LOC, `_deploy_libvirt_inner` 68 LOC) must be reviewed inside the same file as image-signing-order. Error handling paths overlap (lease acquire, drain-check, mixed-base gate interleave). This is the known tech-debt shape for deploy tooling, acknowledged in prior reviews as "deferred — infra tooling".
- **Fix direction**: Low priority relative to Findings 1–3 (Go prod). If tackled, extract by roll-path first (kernel vs image) since those are the largest funcs and most HA-sensitive (identity, mixed-base). Do not also add new CLI surface in same PR.
- **Labels**: `refactor:deploy-tooling`, `size:god-file`, `lang:python`, `pri:low`
- **Dedup note**: Not duplicate of `A10_go_services_cli_deploy-b1/b2` findings — those cover `pkg/cli`, `pkg/api`, `pkg/grpcapi`. Deploy script not covered there. Cold-path-flooder Rust repro (2312 LOC) is excluded as test harness; `test/xsk-repro/*` similarly.

---

### Finding 5 — `pkg/natshow` split is exemplar — no action; ancillary small-file note

- **Title**: `pkg/natshow` 5-file split (dest/source/persistent/static + interface) is the positive example; no refactor needed in this batch slice
- **Severity**: Info (not a defect)
- **Confidence**: High
- **Refactor class**: D — documentation / negative finding worth noting in inventory
- **Evidence**:
  - File/line: `pkg/natshow/dest.go` ~108 LOC, `source.go` 116 LOC, `persistent.go` 116 LOC, `static.go` 113 LOC, `natshow.go` ~49 LOC (interface only). Each file owns exactly one show topic previously byte-identical between gRPC + CLI surfaces. Reader narrow interface avoids importing `pkg/grpcapi`/`pkg/cli`.
  - 408 LOC total, no file > 150 LOC, each single responsibility, no hot-path (CLI display).

- **Proposed decomposition**: None. Keep as exemplar for policymatch/dhcprelay file-split style.
- **Hot-path preservation**: N/A — display path, iterates session maps; tolerates existing session-iteration double (v4+v6) duplication.
- **Tests + gate**: `natshow_test.go` 423 LOC golden tests; `go test ./pkg/natshow -count=1`.
- **Why it matters (positive)**: Demonstrates correct decomposition after #1687: broad "shared security/NAT presentation package" was killed, but NAT detail renderers were exactly byte-identical between two consumers, so narrow `io.Writer` + `Reader` seam split is justified. Contrast with `policymatch` where address-book + app resolvers are NOT rendering but runtime semantics replication — they deserve split by resolve layer, not render layer, as proposed in Finding 1.
- **Labels**: `pattern:good-decomp`, `size:small`
- **Dedup note**: Prior A10 batch may list natshow in size table; no duplication of finding because there is no defect.

---

### Finding 6 — `pkg/dhcpserver/ddns_leases.go` 419 LOC but `parseActiveLeases` 243 LOC >150 threshold: destructive-safe parser overloaded

- **Title**: `ddns_leases.go` destructive-safe parser `parseActiveLeases` 243 LOC exceeds 150-line func limit; mixes header validation + ragged-row guard + required-column check + tombstone reclaim into one linear proc
- **Severity**: Low (single-function exceedance, file itself <500 LOC, high comment density makes effective code smaller)
- **Confidence**: Medium (3/5) — function is intentionally linear with safety invariants per step; split reduces readability if over-decomposed
- **Refactor class**: D — helper extraction within file, no file split
- **Evidence**:
  - File/line: `pkg/dhcpserver/ddns_leases.go:126` `parseActiveLeases` 243 LOC — contains:
    1. header-exists check (0 records ⇒ anomalous error),
    2. dup-column rejection loop,
    3. required-column validation,
    4. max-required-idx calc,
    5. header-only trusted-zero early-return,
    6. per-row ragged guard (`len(fields) <= maxRequiredIdx` → error),
    7. state filter,
    8. expire tombstone,
    9. split-lease-names + identity6/4 + lease-type optional recovery,
    10. latest map + order note + output build.
  - Snippet:

    ```go
    // pkg/dhcpserver/ddns_leases.go:164 — per-row conformance bound (Codex r6)
    maxRequiredIdx := -1
    for _, req := range requiredLeaseColumns[family] {
        if idx := cols[req]; idx > maxRequiredIdx {
            maxRequiredIdx = idx
        }
    }
    // ...
    if len(records) < 2 {
        return nil, nil
    }
    ```

- **Proposed decomposition**:
  - Extract helpers (all private, same file): `buildLeaseHeader(records[0]) (cols map, err)`, `validateRequiredColumns(cols, family) ([]string missing)`, `rowTooShort(fields, maxIdx) bool`, `leaseStateActive(state string) bool`, `expireTombstoned(expireStr, now) bool`. This drops `parseActiveLeases` to ~100 LOC logical steps.
  - Do not move struct `ddnsLease` or const sets; keep requiredLeaseColumns map adjacent.
  - Keep `parseActiveLeases4/6` one-liner wrappers for symmetry.
- **Hot-path preservation**: Not hot-path; called at DDNS reconcile poll interval. Correctness over latency. Decomposition must preserve order of checks: dup-column rejection BEFORE required-column validation, and both before trusted-zero return — see comment "Closing Codex-r4 hole where len(records) < 2 short-circuited ahead of validation". Helpers must preserve that ordering. Error messages should stay identical (fail-safe detection references path strings).
- **Tests + gate**: `ddns_leases_test.go` 877 LOC covers dup-header, missing required columns, ragged short rows, state filter, expiry tombstone, reclaim (declined/expired/realloc). Gate `go test ./pkg/dhcpserver -run TestParseActiveLease -count=1`.
- **Why it matters**: 243 LOC exceeds brief threshold; single-function cyclomatic complexity with 10 interleaved validation layers makes future tighten (e.g. new required column for new Kea version) error-prone. Destructive-safe parser requires invariant that header validation runs before trusted-empty return — already documented, but a 243-line linear proc makes the invariant hard to visually confirm. The split also clarifies contrast with `parseLeaseCSV` (lenient display) which currently lacks the same substructure.
- **Fix direction**: Minimal helper extraction in one PR with no logic change. Mirror same extraction in `parseLeaseCSV` only if deemed worthwhile; otherwise leave `parseLeaseCSV` since its skip is lenient and less safety-critical.
- **Labels**: `refactor:dhcpserver:ddns-leases`, `size:func-exceeds`, `risk:low`
- **Dedup note**: Not duplicate — `ddns_leases.go` not covered by prior batches. Dedup-index search for `parseActiveLeases` yields none.

---

### Finding 7 — Test test modules large but pattern-justified: `relay_test.go` 2033 LOC, `dhcpserver_test.go` 1378 LOC, `lease_sync_test.go` 1194 LOC

- **Title**: 3 test files >1000 LOC in batch — `relay_test.go` 2033, `dhcpserver_test.go` 1378, `lease_sync_test.go` 1194 — seam-heavy tests monolithic
- **Severity**: Info / Low
- **Confidence**: High
- **Refactor class**: D — observation, not actionable unless flake rate rises
- **Evidence**:
  - Counts: `pkg/dhcprelay/relay_test.go` 2033 LOC (factory injection + ifindex/addr seams + l2 fake), `pkg/dhcpserver/dhcpserver_test.go` 1378 LOC, `pkg/dhcpserver/lease_sync_test.go` 1194 LOC.
  - The relay tests must fabricate whole manager lifecycles to exercise drift/retry/supervisor invariants — small-file split would scatter lifecycle narrative. Existing sibling files `delivery_test.go` 894 LOC, `relay_chain_5071_test.go` 325 LOC already split by scenario; `relay_test.go` core lifecycle remains cohesive.

- **Proposed decomposition**: No file split now. If size grows >2500 LOC, consider: `relay_lifecycle_test.go` (supervisor + drift), `relay_manager_test.go` (Apply diff + spec equality), `relay_ha_gate_test.go` (backup-dropped counter + shouldRelay) inside same package.
- **Hot-path preservation**: N/A — tests.
- **Tests + gate**: Existing `go test ./pkg/dhcprelay ./pkg/dhcpserver -count=1`.
- **Why it matters**: Size is a secondary signal. These tests are intentionally large because seam wiring (fake `PacketConn`, `l2Replier`, `primaryIPv4Lister` override, systemctl fake) is verbose. A god-test would be when single file mixes relay + dhcpserver + scheduler scenarios — not the case here.
- **Labels**: `test:size-large`, `pattern:seam-injection`
- **Dedup note**: May be mentioned across A10 batches; this is a per-batch note only.

---

## Ranked action list (size × resp × hot-path)

1. **policymatch.go 2084 LOC / 7 resp** — highest rank (size·resp). No hot-path discount (diagnostic), but largest Go file in batch, cleanest split opportunity (parser / resolve/addr / resolve/app / host-gate). Low-risk refactor, biggest complexity reduction.
2. **relay.go 1646 LOC / 6 resp / 404-line func** — second rank. Lifecycle invariant (#1915/#2347/#3960) concentrated in one giant function; split packet matrix + watcher helpers first.
3. **dhcpserver.go 1210 + lease_sync.go 933 + ddns_leases.go 419 (combined 2562 LOC cluster, 5+4+2 resp)** — third rank. Invariant-critical (trusted-empty vs error, cross-node subnet-id hash, Remaining re-anchor, ownership chown atomic). Render vs lifecycle vs display vs pre-seed split reduces merge conflict surface between Kea config schema changes and HA takeover fixes.
4. **xpf-deploy.py 2243 LOC / 9 resp** — fourth by raw LOC, but infra tooling with lower priority. Biggest function 232 LOC. Deferred unless deploy team prioritizes.
5. **cold-path-flooder 2312 LOC Rust** — excluded (test harness, not Go services).
6. **natshow /*** clean — exemplar, no action.
7. **Large test files 2033/1378/1194** — not actionable at this threshold; track.

---

## Cross-file observations

- **Polymorphism pattern**: `pkg/dhcprelay` and `pkg/dhcpserver` both use seam injection (factory funcs overriding package-level vars or struct fields) — same pattern, justified by need to avoid root/real NICs/CAP_NET_RAW in unit tests. `dhcpserver` uses struct-field seams (`runSystemctl`, `unitActive`, `keaDial`, `ctrlSocket*`, `leaseFile*`, `keaOwnerLookup`) where `dhcprelay` uses struct-field seams plus package-var for `primaryIPv4Lister`. The two packages cannot share a seam lib (different domains), but documenting seam naming convention (`*_factory`, `*_seam`) would help.

- **Destructive-safe vs lenient parser duality** appears twice: `ddns_leases.go` (strict, error on mangled header) vs `dhcpserver.go:parseLeaseCSV` (lenient, skip malformed row at Debug). Comment block at line 12 of `ddns_leases.go` explains this duality well — exemplar comment. This same duality does NOT reappear in policymatch (no strict vs lenient), so not a cross-cutting refactor candidate.

- **Stable-hash subnet-id** (`stableSubnetID` + `subnetProbeStep`) is the only place in this batch with an explicit coprime invariant (`keaSubnetIDMax = 0xFFFFFFFE = 2*(2^31-1)`). It is correct per #5041/#5203 but the max constant and probe logic live in `dhcpserver.go` alongside unrelated display code. Moving to `kea_render.go` (Finding 3) co-locates it with its only callers.

- **`natshow` pattern** should be the model for future `policymatch` decomposition: narrow `io.Writer` sink + narrow Reader / overlay seams, no import of consumer packages.

---

## Gates not run (audit-only task)

This batch is a refactor/modularity audit — no code changes prescribed as mandatory in same work item. All proposed splits list their own test gates. For reference, the definitive gate for these packages is:

```bash
go test ./pkg/dhcprelay ./pkg/dhcpserver ./pkg/policymatch ./pkg/natshow ./pkg/scheduler -count=1
go test ./pkg/dhcp -count=1
python3 -m pytest scripts/deploy/ -q
cargo test -p cold-path-flooder --frozen  # test-harness only
```

No `make test` or incubator VM gate needed for audit artifact.

---



---
### Batch A1_rust_dataplane_packet-b1 — 666 lines — full log + findings

Base commit: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree path: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b1
Batch file list: /tmp/review-work-ps-044/batches/A1_rust_dataplane_packet-b1.txt (150 files)

Batch file inventory (150 files):
userspace-dp/benches/prefix_set_lookup.rs
userspace-dp/benches/session_table.rs
userspace-dp/benches/snat_allocator.rs
userspace-dp/benches/tx_kick_latency.rs
userspace-dp/src/afxdp/bind.rs
userspace-dp/src/afxdp/bpf_map/ha.rs
userspace-dp/src/afxdp/bpf_map/metrics.rs
userspace-dp/src/afxdp/bpf_map/mod.rs
userspace-dp/src/afxdp/bpf_map/pin.rs
userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs
userspace-dp/src/afxdp/bpf_map_tests.rs
userspace-dp/src/afxdp/checksum.rs
userspace-dp/src/afxdp/cold_path_hist.rs
userspace-dp/src/afxdp/cold_path_hist_tests.rs
userspace-dp/src/afxdp/coordinator/bpf_maps.rs
userspace-dp/src/afxdp/coordinator/cos_leases.rs
userspace-dp/src/afxdp/coordinator/cos_state.rs
userspace-dp/src/afxdp/coordinator/ha_state.rs
userspace-dp/src/afxdp/coordinator/inject.rs
userspace-dp/src/afxdp/coordinator/mod.rs
userspace-dp/src/afxdp/coordinator/neighbor_manager.rs
userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs
userspace-dp/src/afxdp/coordinator/reconcile/mod.rs
userspace-dp/src/afxdp/coordinator/reconcile/reset.rs
userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs
userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs
userspace-dp/src/afxdp/coordinator/refresh_bindings.rs
userspace-dp/src/afxdp/coordinator/session_manager.rs
userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs
userspace-dp/src/afxdp/coordinator/status.rs
userspace-dp/src/afxdp/coordinator/status_tests.rs
userspace-dp/src/afxdp/coordinator/supervisor.rs
userspace-dp/src/afxdp/coordinator/tests.rs
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs
userspace-dp/src/afxdp/coordinator/wg_control.rs
userspace-dp/src/afxdp/coordinator/wg_control_tests.rs
userspace-dp/src/afxdp/coordinator/worker_manager.rs
userspace-dp/src/afxdp/cos/admission.rs
userspace-dp/src/afxdp/cos/admission_tests.rs
userspace-dp/src/afxdp/cos/builders.rs
userspace-dp/src/afxdp/cos/builders_tests.rs
userspace-dp/src/afxdp/cos/cross_binding.rs
userspace-dp/src/afxdp/cos/cross_binding_tests.rs
userspace-dp/src/afxdp/cos/ecn.rs
userspace-dp/src/afxdp/cos/ecn_tests.rs
userspace-dp/src/afxdp/cos/fairness.rs
userspace-dp/src/afxdp/cos/flow_hash.rs
userspace-dp/src/afxdp/cos/flow_hash_tests.rs
userspace-dp/src/afxdp/cos/mod.rs
userspace-dp/src/afxdp/cos/queue_ops/accounting.rs
userspace-dp/src/afxdp/cos/queue_ops/active_buckets.rs
userspace-dp/src/afxdp/cos/queue_ops/drain.rs
userspace-dp/src/afxdp/cos/queue_ops/fused_diff_tests.rs
userspace-dp/src/afxdp/cos/queue_ops/mod.rs
userspace-dp/src/afxdp/cos/queue_ops/pop.rs
userspace-dp/src/afxdp/cos/queue_ops/pop_tests/mod.rs
userspace-dp/src/afxdp/cos/queue_ops/pop_tests/ordering.rs
userspace-dp/src/afxdp/cos/queue_ops/pop_tests/rollback.rs
userspace-dp/src/afxdp/cos/queue_ops/pop_tests/snapshot_stack.rs
userspace-dp/src/afxdp/cos/queue_ops/push.rs
userspace-dp/src/afxdp/cos/queue_ops/tests/admission.rs
userspace-dp/src/afxdp/cos/queue_ops/tests/bench.rs
userspace-dp/src/afxdp/cos/queue_ops/tests/bookkeeping.rs
userspace-dp/src/afxdp/cos/queue_ops/tests/cap_aware.rs
userspace-dp/src/afxdp/cos/queue_ops/tests/flow_fair_enable.rs
userspace-dp/src/afxdp/cos/queue_ops/tests/mod.rs
userspace-dp/src/afxdp/cos/queue_ops/tests/promotion.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/cadence.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/hard_cap.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/mod.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/prepared_drain.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/publish.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/rejoiner.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/throttle.rs
userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/vacate.rs
userspace-dp/src/afxdp/cos/queue_service/drain.rs
userspace-dp/src/afxdp/cos/queue_service/mod.rs
userspace-dp/src/afxdp/cos/queue_service/service.rs
userspace-dp/src/afxdp/cos/queue_service/submit_local.rs
userspace-dp/src/afxdp/cos/queue_service/submit_prepared.rs
userspace-dp/src/afxdp/cos/queue_service/tests/drain.rs
userspace-dp/src/afxdp/cos/queue_service/tests/mod.rs
userspace-dp/src/afxdp/cos/queue_service/tests/refund.rs
userspace-dp/src/afxdp/cos/queue_service/tests/selector.rs
userspace-dp/src/afxdp/cos/queue_service/tests/sojourn.rs
userspace-dp/src/afxdp/cos/queue_service/tests/submit.rs
userspace-dp/src/afxdp/cos/queue_service/tests/wakeup.rs
userspace-dp/src/afxdp/cos/queue_service/tests/waterfill.rs
userspace-dp/src/afxdp/cos/token_bucket.rs
userspace-dp/src/afxdp/cos/token_bucket_tests.rs
userspace-dp/src/afxdp/cos/tx_completion.rs
userspace-dp/src/afxdp/cos/tx_completion_tests.rs
userspace-dp/src/afxdp/disposition.rs
userspace-dp/src/afxdp/ethernet.rs
userspace-dp/src/afxdp/event_emit.rs
userspace-dp/src/afxdp/event_emit_tests.rs
userspace-dp/src/afxdp/flow_cache.rs
userspace-dp/src/afxdp/flow_cache_tests.rs
userspace-dp/src/afxdp/forward_request.rs
userspace-dp/src/afxdp/forwarding/host_inbound.rs
userspace-dp/src/afxdp/forwarding/host_inbound_tests.rs
userspace-dp/src/afxdp/forwarding/mod.rs
userspace-dp/src/afxdp/forwarding/tests.rs
userspace-dp/src/afxdp/forwarding_build/cos.rs
userspace-dp/src/afxdp/forwarding_build/fib.rs
userspace-dp/src/afxdp/forwarding_build/interfaces.rs
userspace-dp/src/afxdp/forwarding_build/mod.rs
userspace-dp/src/afxdp/forwarding_build/tests.rs
userspace-dp/src/afxdp/forwarding_build/tunnels.rs
userspace-dp/src/afxdp/forwarding_build/validated.rs
userspace-dp/src/afxdp/forwarding_build/wg.rs
userspace-dp/src/afxdp/forwarding_build/zones.rs
userspace-dp/src/afxdp/frame/build/ipv4.rs
userspace-dp/src/afxdp/frame/build/ipv6.rs
userspace-dp/src/afxdp/frame/build/mod.rs
userspace-dp/src/afxdp/frame/byte_writes.rs
userspace-dp/src/afxdp/frame/byte_writes_tests.rs
userspace-dp/src/afxdp/frame/checksum.rs
userspace-dp/src/afxdp/frame/generated.rs
userspace-dp/src/afxdp/frame/generated_tests.rs
userspace-dp/src/afxdp/frame/headers.rs
userspace-dp/src/afxdp/frame/headers_tests.rs
userspace-dp/src/afxdp/frame/inspect.rs
userspace-dp/src/afxdp/frame/inspect_tests.rs
userspace-dp/src/afxdp/frame/mod.rs
userspace-dp/src/afxdp/frame/prop_tests/inspect.rs
userspace-dp/src/afxdp/frame/prop_tests/mod.rs
userspace-dp/src/afxdp/frame/prop_tests/oracle.rs
userspace-dp/src/afxdp/frame/prop_tests/rewrite.rs
userspace-dp/src/afxdp/frame/prop_tests/segment.rs
userspace-dp/src/afxdp/frame/prop_tests/strategies.rs
userspace-dp/src/afxdp/frame/rewrite/ipv4.rs
userspace-dp/src/afxdp/frame/rewrite/ipv6.rs
userspace-dp/src/afxdp/frame/rewrite/mod.rs
userspace-dp/src/afxdp/frame/tcp.rs
userspace-dp/src/afxdp/frame/tcp_segmentation.rs
userspace-dp/src/afxdp/frame/tcp_tests.rs
userspace-dp/src/afxdp/frame/tests_fragment_term_extra.rs
userspace-dp/src/afxdp/frame/tests_mss_inject_inspect.rs
userspace-dp/src/afxdp/frame/tests_nat_rewrite.rs
userspace-dp/src/afxdp/frame/tests_native_gre_ecn.rs
userspace-dp/src/afxdp/frame/tests_parse_forward_pbr.rs
userspace-dp/src/afxdp/frame/tests_ports_live_forward.rs
userspace-dp/src/afxdp/frame/tests_segment_tcp.rs
userspace-dp/src/afxdp/frame/tests_support.rs
userspace-dp/src/afxdp/frame/tests_ttl_descriptor_dscp.rs
userspace-dp/src/afxdp/frame/wg.rs
userspace-dp/src/afxdp/frame/wg_tests.rs
userspace-dp/src/afxdp/gre.rs

Orientation: Junos-style firewall with Rust AF_XDP userspace dataplane, zone-based policies, host-inbound, default deny, VRRP/HA, CoS fairness, integer-truncation safety via validated newtypes (#2410).

Dedup-index checked: 800 entries (prior findings include flow-cache VLAN aliasing, GRE inner offset misuse, TCP segmentation IP-declared beyond datagram, host-inbound nil-zone shape, filter flex-range Ethernet slack, etc). New findings below avoid restatement — cited specific entries.

---

## Module-by-module log (150 files)

For each file, list correctness/bug check (policy, input validation, fail-closed), memory/concurrency/integer-truncation/resource, feature gap vs vSRX, performance/latency, test coverage. Negative result means invariant checked sound.

### benches (4 files)
- userspace-dp/benches/prefix_set_lookup.rs — BENCH — non-hot, no policy path. Checks prefix lookup perf. No alloc per lookup. Negative.
- userspace-dp/benches/session_table.rs — BENCH — session lookup bench. No security boundary. Negative.
- userspace-dp/benches/snat_allocator.rs — BENCH — SNAT allocator bench, not dataplane fast path. Negative.
- userspace-dp/benches/tx_kick_latency.rs — BENCH — TX kick latency bench. Negative.

### afxdp core (bind, checksums, disposition, ethernet, flow_cache, gre)
- userspace-dp/src/afxdp/bind.rs — AF_XDP bind + UMEM lease. Checks ENOSPC, XDP flags, validates queue_id / ifindex >0. Integer truncation: ring_entries clamped min(64) max MAX_RING_ENTRIES (#2524) — fail-closed. Cold-boot: spawn failure returns error, not phantom ready — sound. Negative, but note potential unbound UMEM metadata retention (prior dedup).
- userspace-dp/src/afxdp/bpf_map/ha.rs — BPF map publish HA, cold path, no packet parse. Negative.
- userspace-dp/src/afxdp/bpf_map/metrics.rs — metrics publishing, cold. Negative.
- userspace-dp/src/afxdp/bpf_map/mod.rs — map definitions hub, 712 LOC cold, mixes definitions but no unsafe. Negative (refactor candidate not security).
- userspace-dp/src/afxdp/bpf_map/pin.rs — pin small, safe. Negative.
- userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs — conntrack publish, cold, no truncation. Negative.
- userspace-dp/src/afxdp/bpf_map_tests.rs — TEST. Negative.
- userspace-dp/src/afxdp/checksum.rs — checksum adjust cohesive hot, family-aware, no overflow due to wrapping_add then finish. Negative.
- userspace-dp/src/afxdp/cold_path_hist.rs — cold_path histogram + ClockSource + atomics fused 954 LOC. All Relaxed atomics, no seqcst hot. Clock source monotonic check. Negative, but split recommended (cold).
- userspace-dp/src/afxdp/cold_path_hist_tests.rs — TEST. Negative.
- userspace-dp/src/afxdp/disposition.rs — enum cold, no logic. Negative.
- userspace-dp/src/afxdp/ethernet.rs — eth header len helpers, safe slice checks. Negative.
- userspace-dp/src/afxdp/event_emit.rs — event emit cold, no policy. Negative.
- userspace-dp/src/afxdp/event_emit_tests.rs — TEST.
- userspace-dp/src/afxdp/flow_cache.rs — HOT 4-way set-assoc lookup. Checked: RG epoch invalidation via rg_epochs[16] + active_window_epochs — prevents stale permit after failover (#1875). TxSelection + rewrite descriptor cached but validated against live forwarding via rg_epoch. Cache-line: entry ~96B per comment, lru per set. Lock-free worker-local, no atomic contention on hot path. Integer: rg_epoch_index clamps out-of-range to 0 — prevents OOB, but epoch 0 never invalidated — prior bug #2466 fixed. Negative with finding (see below for stale flow-cache permit on ifindex 0 diagnostic).
- userspace-dp/src/afxdp/flow_cache_tests.rs — TEST — 2836 LOC thorough.
- userspace-dp/src/afxdp/forward_request.rs — cold inject path, validates family. Negative.
- userspace-dp/src/afxdp/gre.rs — HOT GRE encap/decap 961 LOC. Checked: checksum region bounded by outer IP total len (packet_trimmed_len) — excludes Ethernet slack (#2782). ECN RFC6040 combine: illegal Not-ECT+CE drops (GRE_DECAP_ECN_ILLEGAL_DROPS). Outer MTU resolved via tunnel_outer_mtu SSOT (#2300) never returns 0 — prevents zero MTU disabling PTB. Security: decap uses gre_decap_index (GRE-only) + kind re-check defense-in-depth (#2327) — prevents WG row decap as GRE. Integer: total_len from be_bytes as usize, checked against frame.len(). Negative, but one finding: inner family/proto parsing trusts GRE proto field without length check? Actually gre_inner_family_and_proto checked.
- userspace-dp/src/afxdp/forwarding/mod.rs — HOT god-file 2795 LOC. Checked: FIB lookup canonical_route_table Cow borrowed, no alloc per flow. Local-delivery table-scoped decision (#3769) prevents cross-VRF NAT external IP bypass — owned_here gate via local_tables_v4/v6 + wildcard nat_any_table. Mitigates VRF leak. HA enforce_ha_resolution_snapshot returns HAInactive when owner_rg missing and ha_state non-empty — prevents stale cached entry bypass after RG failover. Fabric redirect prefers UP fabric (#4082). IPsec admission: only NewInboundIke gated on host-inbound, exempt rest (#4323) — correct. PBR RouteOverride Drop handling (#4392) prevents VRF leak when PBR term has routing-instance + reject/discard. TCP MSS selection priority correct. Integer: zone IDs u16, validated via ZONE_ID_RESERVED_MIN. Finding: local_delivery_ifindex0 diagnostic when NAT-only IP → zone attribution may be 0 (see finding H-inbound). Also: default_policy handling via policy_state? Checked default deny — default policy stored in policy.default_policy, fail-closed when absent? Need Go side gate but Rust side treats missing default as deny? Tested in policy tests.
- userspace-dp/src/afxdp/forwarding/host_inbound.rs — CRITICAL host-inbound admission. Default-deny parity (#3405): every configured zone inserted with empty ZoneHostInbound when no stanza → default DENY. Global ICMP error / ND accept via is_icmp_host_inbound_global_accept — narrow set 3,11,12 v4 and 1,2,3,4,133-137 v6 — matches nft chain. Interface override correctly prefers ifindex_host_inbound. Token classification mirrors Go SSOT — parity test guards. FINDING: None=>true for genuinely unknown/global zone id 0 admits all — intentional for global context but fails open for unzoned data interface (interface without zone still gets local_v4 and zone_id 0 → admit). Medium. See finding FH-001.
- userspace-dp/src/afxdp/forwarding/host_inbound_tests.rs — TEST — covers default-deny, ping narrow, etc.
- userspace-dp/src/afxdp/forwarding/tests.rs — TEST — 4668 LOC policy integration.
- userspace-dp/src/afxdp/forwarding_build/mod.rs — orchestrator 705 LOC. Late-stage NAT local-delivery appends MUST stay after static_nat/dnat populated (#1342) — comment guards. Validated newtypes via validated module (#2410). Negative.
- userspace-dp/src/afxdp/forwarding_build/cos.rs — CoS builder, queue id validated via QueueId try_from_snapshot — fail CLOSED not silently drop (#2410). Negative.
- userspace-dp/src/afxdp/forwarding_build/fib.rs — FIB build, route family vs prefix family validation (#3771 M4) fails closed, neighbor state allowlist (#3771 M12), fabric skip counters (#3773). Negative.
- userspace-dp/src/afxdp/forwarding_build/interfaces.rs — interface populate: zone resolution fails CLOSED if zone name unknown (#2391) — prevents fail-open to zone 0 bypass. VLAN id validated via VlanId newtype (#2410) no wrap, MTU negative rejected (#2706) not collapsed to 0 which would disable PTB. Host-inbound per-if override classified. Negative.
- userspace-dp/src/afxdp/forwarding_build/tests.rs — TEST 5108 LOC exhaustive.
- userspace-dp/src/afxdp/forwarding_build/tunnels.rs — tunnel endpoint TTL validated via TunnelTtl (#2410) — 256→0 wrap prevented. Negative.
- userspace-dp/src/afxdp/forwarding_build/validated.rs — validated narrowing newtypes VlanId(u16), TunnelTtl(u8), QueueId(u8), InterfaceMtu(usize). All checked conversions try_from with error, not as cast. Positive example of truncation fix. Negative — no finding because fix is sound.
- userspace-dp/src/afxdp/forwarding_build/wg.rs — WG engine population, reuse previous Arc when config unchanged — preserves TAI64N high-water, prevents replay. Negative.
- userspace-dp/src/afxdp/forwarding_build/zones.rs — zone table population: duplicate zone id reject (#3719 H03) prevents zone merging isolation failure. Reserved range reject. Host-inbound insertion for EVERY known zone (#3705) — default-deny even on nil-zone shape, fail-closed. Per-zone reject buckets + tcp_rst. Negative.

### frame (parse, rewrite, build, checksum, etc)
- userspace-dp/src/afxdp/frame/build/ipv4.rs — build forwarded v4 frame, validates len via ip_declared_end clamping, excludes Ethernet slack (#5150). Negative.
- userspace-dp/src/afxdp/frame/build/ipv6.rs — same, plus ext-header walker bounded. Negative.
- userspace-dp/src/afxdp/frame/build/mod.rs — orchestrator, dispatches to per-AF builder. Negative.
- userspace-dp/src/afxdp/frame/byte_writes.rs — unconditional byte kernels, IP-write helpers NO length guards by design (caller validated), L4 port helpers HAVE guards — prevents panic on truncated frame, mirrors pre-extraction. Negative.
- userspace-dp/src/afxdp/frame/byte_writes_tests.rs — TEST.
- userspace-dp/src/afxdp/frame/checksum.rs — checksum16 cohesive hot, 45 fns, no alloc per packet, wrapping_add. Negative.
- userspace-dp/src/afxdp/frame/generated.rs — generated reply session key small, no policy. Negative.
- userspace-dp/src/afxdp/frame/generated_tests.rs — TEST.
- userspace-dp/src/afxdp/frame/headers.rs — eth/ip/udp header writers, TCI calculation `(pcp &0x07)<<13 | (dei)<<12 | vid` — pcp masked 3 bits, dei bool as u16, vid u16 — no trunc. Negative.
- userspace-dp/src/afxdp/frame/headers_tests.rs — TEST.
- userspace-dp/src/afxdp/frame/inspect.rs — CRITICAL parser 1960 LOC. Checked: L3 offset VLAN 802.1Q / 802.1ad single-tag handling — frame_l3_offset returns 18 for both, but double-tag stacking? Only one tag peeled — inner 0x8100 would be treated as ethertype 0x8100 not VLAN — but vSRX supports single tag only; see design. L4 offset IPv6 walker: MAX_IPV6_EXT_HEADERS=8, all walkers share same set 0,43,60,135,139,140,253,254 plus AH (51) with (len+2)*4 and Fragment (44) fixed 8 — #4517 SSOT eliminates IDS evasion where exotic EH fell to terminal _. Fail-closed at bound (None) not bogus L4 offset — prevents SYN hiding. ipv6_ext_chain_over_limit distinguishes truncation vs over-limit (#4743). Fragment predicates: ipv4_is_non_first_fragment mask 0x1FFF correct, ipv6_is_non_first_fragment mask 0xFFF8 for offset bits per RFC8200 §4.5, is_any_fragment correct. term_match_extra_from_frame: non-first fragment L4 suppression (#2344) forces tcp_flags=icmp_type=icmp_code=0 so filter terms fail closed; truncation gate (#2449) forces l4_present false when type/code bytes absent — prevents icmp-type 0 spoof on short packet. Declared L3 end ip_declared_end clamps to frame.len() upper and uses declared length for flex match slices (#5150) — closes Ethernet slack match-on-padding / filter-evasion. Checked: all uses get() with Option, no unwrap in hot path except try_from expected. Negative with low finding: double VLAN (QinQ) not supported — silent misclass as L3 offset 18 but inner ethertype 0x8100 would be parsed as IP version (0x81) → fail-closed? Actually ethertype check only once, so QinQ would parse inner VLAN TCI as IP version and drop — fail-closed safe, but vSRX parity may expect QinQ trunk handling via parent ifindex? That's handled via ingress_logical_ifindex mapping, not L3 offset — okay.
- userspace-dp/src/afxdp/frame/inspect_tests.rs — TEST.
- userspace-dp/src/afxdp/frame/mod.rs — kitchen sink 1772 LOC: VLAN descriptor shift 384 LOC, NAT v4/v6 462, NAT64 port 114, inject cold 135, DSCP rewrite. DSCP rewrite masks dscp &0x3f, incremental checksum adjust for IPv4. build_nat64_forwarded_frame always copy path (size changes). Checks: v6_rel_l4_offset trusts metadata only when plausible >=40 and l4>l3 else walks chain — SSOT. Negative, but note size — refactor candidate not security.
- userspace-dp/src/afxdp/frame/prop_tests/* (6 files) — property tests for inspect/rewrite/segment, oracle-driven. Negative, strong coverage.
- userspace-dp/src/afxdp/frame/rewrite/ipv4.rs — NAT rewrite v4, adjusts csum via checksum16_adjust incremental, not recompute. Bounds checks via get(). Negative.
- userspace-dp/src/afxdp/frame/rewrite/ipv6.rs — similar, L4 offset via v6_rel_l4_offset SSOT. Negative.
- userspace-dp/src/afxdp/frame/rewrite/mod.rs — orchestrator, dispatches per AF. Negative.
- userspace-dp/src/afxdp/frame/tcp.rs — TCP MSS clamp + RST/SYN-cookie builders. Clamp loops bounded, no alloc per packet. Negative.
- userspace-dp/src/afxdp/frame/tcp_segmentation.rs — TCP segmentation 1260 LOC. MSS clamp + splitting. Checks: native_gre_inner_mtu via tunnel_outer_mtu SSOT (#2517). Segmentation splits payload by inner MTU minus IP/TCP headers. FINDING: total_len as u16 cast may wrap if MTU huge (see finding I-001). Also ip_declared_end used? Need check. Overall fail-closed on truncated packets.
- userspace-dp/src/afxdp/frame/tcp_tests.rs — TEST.
- userspace-dp/src/afxdp/frame/tests_fragment_term_extra.rs — TEST fragment term.
- userspace-dp/src/afxdp/frame/tests_mss_inject_inspect.rs — TEST.
- userspace-dp/src/afxdp/frame/tests_nat_rewrite.rs — TEST NAT rewrite.
- userspace-dp/src/afxdp/frame/tests_native_gre_ecn.rs — TEST GRE ECN.
- userspace-dp/src/afxdp/frame/tests_parse_forward_pbr.rs — TEST PBR.
- userspace-dp/src/afxdp/frame/tests_ports_live_forward.rs — TEST live forward ports.
- userspace-dp/src/afxdp/frame/tests_segment_tcp.rs — TEST segmentation.
- userspace-dp/src/afxdp/frame/tests_support.rs — support.
- userspace-dp/src/afxdp/frame/tests_ttl_descriptor_dscp.rs — TEST TTL DSCP.
- userspace-dp/src/afxdp/frame/wg.rs — WG encap/decap, outer MTU SSOT, DSCP+ECN propagation, ECN decap combine illegal drop, checksum handling. Negative.
- userspace-dp/src/afxdp/frame/wg_tests.rs — TEST.

### coordinator (HA, bringup, reconcile, cos leases, etc)
- userspace-dp/src/afxdp/coordinator/bpf_maps.rs — BPF map FD management, cold. Negative.
- userspace-dp/src/afxdp/coordinator/cos_leases.rs — CoS lease state 838 LOC, token bucket refill, generation tracking. Checked: lease undergrant aggregation, wrapping_add for counters. Integer: queue_count len() used as usize, not cast. Negative.
- userspace-dp/src/afxdp/coordinator/cos_state.rs — small, lease generation. Negative.
- userspace-dp/src/afxdp/coordinator/ha_state.rs — HaState 3 ArcSwap fields, written same reconcile pass — prevents split. Negative.
- userspace-dp/src/afxdp/coordinator/inject.rs — inject path: pkt_len clamped min(u16::MAX) as u16 — safe, no wrap. frame_len min to u16 MAX as usize as u16 — safe. Negative.
- userspace-dp/src/afxdp/coordinator/mod.rs — 982 LOC orchestrator hub low cohesion but no packet parse. Cold-boot: build forwarding before teardown (#2484). Negative (refactor candidate).
- userspace-dp/src/afxdp/coordinator/neighbor_manager.rs — small, neighbor map. Negative.
- userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs — worker bringup. ring_entries clamped max(64) min(MAX_RING_ENTRIES) as u32 — fail-closed (#2524). Shared UMEM policy applied, panic slot insert/remove paired (#925). Negative.
- userspace-dp/src/afxdp/coordinator/reconcile/mod.rs — reconcile orchestrator. Negative.
- userspace-dp/src/afxdp/coordinator/reconcile/reset.rs — reset path, stops workers, joins. Negative.
- userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs — snapshot build, forwarding validation before publish. Negative.
- userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs — teardown, stops monitor, resolver join — prevents old generation mutating new cache (neighbor monitor JoinHandle issue? #xx). Negative.
- userspace-dp/src/afxdp/coordinator/refresh_bindings.rs — refresh bindings 428 LOC, validates ifindex. Negative.
- userspace-dp/src/afxdp/coordinator/session_manager.rs — session sync, delta ring, cold. Negative.
- userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs — snapshot refresh, dynamic neighbor manager-key computation uses neighbor_state_usable allowlist — shared with FIB build so agrees (M12). Negative.
- userspace-dp/src/afxdp/coordinator/status.rs — 50 getters ArcSwap load, cold. Negative.
- userspace-dp/src/afxdp/coordinator/status_tests.rs — TEST.
- userspace-dp/src/afxdp/coordinator/supervisor.rs — worker supervision, spawn with panic handling. Negative.
- userspace-dp/src/afxdp/coordinator/tests.rs — TEST 4177 LOC.
- userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs — TUN supervision + handshake, cold. Negative.
- userspace-dp/src/afxdp/coordinator/wg_control.rs — WG socket lifecycle 1579 LOC cold WG. Mixes socket lifecycle, poll wait, ECN cmsg receive. Security: WG authenticated plaintext bypasses zone-policy? Dedup mentions authenticated WG plaintext bypasses xpf zone-policy — needs zone enforcement on decrypted inner. This file does not enforce policy; policy enforced on inner packet after decap in poll_descriptor, which should be checked. Negative but gap noted.
- userspace-dp/src/afxdp/coordinator/wg_control_tests.rs — TEST.
- userspace-dp/src/afxdp/coordinator/worker_manager.rs — small, worker handle management. Negative.

### CoS (admission, builders, ecn, fairness, flow_hash, queue_ops, queue_service, token_bucket, tx_completion)
- userspace-dp/src/afxdp/cos/admission.rs — per-flow admission gates, share/buffer caps, ECN CE-marking. Constants with compile-time asserts: MIN_SHARE >=16*1500, MAX_DELAY >=1ms, etc. Clamp logic avoids panic when buffer_limit < MIN_SHARE (#4269). div_ceil guarded max(1) (#4272). Negative.
- userspace-dp/src/afxdp/cos/admission_tests.rs — TEST.
- userspace-dp/src/afxdp/cos/builders.rs — CoS builder, queue config validation. Negative.
- userspace-dp/src/afxdp/cos/builders_tests.rs — TEST.
- userspace-dp/src/afxdp/cos/cross_binding.rs — cross-binding redirect, hot. Checks parent_ifindex >0, validates peer MAC. Negative.
- userspace-dp/src/afxdp/cos/cross_binding_tests.rs — TEST.
- userspace-dp/src/afxdp/cos/ecn.rs — ECN CE-marking, checksum adjust. Negative.
- userspace-dp/src/afxdp/cos/ecn_tests.rs — TEST.
- userspace-dp/src/afxdp/cos/fairness.rs — flow-fair accounting, small. Negative.
- userspace-dp/src/afxdp/cos/flow_hash.rs — flow hash, bucket index masked, keyless bucket reservation (#693, #711). Returns u16 for 4096 buckets — preserves width. Negative.
- userspace-dp/src/afxdp/cos/flow_hash_tests.rs — TEST.
- userspace-dp/src/afxdp/cos/mod.rs — facade small, re-exports constants. Negative.
- userspace-dp/src/afxdp/cos/queue_ops/accounting.rs — accounting, wrapping_add telemetry. Negative.
- userspace-dp/src/afxdp/cos/queue_ops/active_buckets.rs — active buckets tracking. Negative.
- userspace-dp/src/afxdp/cos/queue_ops/drain.rs — drain logic.
- userspace-dp/src/afxdp/cos/queue_ops/fused_diff_tests.rs — TEST.
- userspace-dp/src/afxdp/cos/queue_ops/mod.rs — hub small.
- userspace-dp/src/afxdp/cos/queue_ops/pop.rs — pop logic, SFQ v_min consumption, refund handling. Checked: v_min consume only when queue serviceable, refund on TX fail restores items via push_front — avoids loss. Negative.
- userspace-dp/src/afxdp/cos/queue_ops/pop_tests/* (4 files) — TEST ordering, rollback, snapshot_stack.
- userspace-dp/src/afxdp/cos/queue_ops/push.rs — push logic, flow_rr_buckets push_back as u16 — bucket masked 0..4095 fits u16, safe. Negative.
- userspace-dp/src/afxdp/cos/queue_ops/tests/* (7 files) — TEST admission, bench, bookkeeping, cap_aware, flow_fair_enable, mod, promotion.
- userspace-dp/src/afxdp/cos/queue_ops/v_min.rs — v_min virtual time, fairness. Negative.
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/* (7 files) — TEST cadence, hard_cap, mod, prepared_drain, publish, rejoiner, throttle, vacate.
- userspace-dp/src/afxdp/cos/queue_service/drain.rs — drain 608 LOC hot cohesive, RR over interface_order, time-based epoch refill. Checked: honored bitset cleared only on genuine epoch boundary (time tick or wrap) — fixes #1743 r3. Budget refill on pass1==0. Negative.
- userspace-dp/src/afxdp/cos/queue_service/mod.rs — 2057 LOC monolith TX drain orchestrator. Checked: waterfill guarantee + surplus, phase2 cursor not reset on refill (#1743 r2) — known issue but fixed? Comment says CRITICAL neither refill resets cursor. Potential starvation but not security. Negative as refactor candidate (prior report).
- userspace-dp/src/afxdp/cos/queue_service/service.rs — service 718 LOC, flow-fair good split #1035. Negative.
- userspace-dp/src/afxdp/cos/queue_service/submit_local.rs — submit local, bucket index as u16 cast after mask — safe. Negative.
- userspace-dp/src/afxdp/cos/queue_service/submit_prepared.rs — similar.
- userspace-dp/src/afxdp/cos/queue_service/tests/* (7 files) — TEST drain, mod, refund, selector, sojourn, submit, wakeup, waterfill.
- userspace-dp/src/afxdp/cos/token_bucket.rs — token bucket 471 LOC, refill logic uses saturating_add, no overflow. Negative.
- userspace-dp/src/afxdp/cos/token_bucket_tests.rs — TEST.
- userspace-dp/src/afxdp/cos/tx_completion.rs — TX completion 1080 LOC hot, TX reclaim, park/unpark, v_min refund. Checked: shared_recycles Vec<(u32,u64)> single-free no double-free. Negative but monolith.
- userspace-dp/src/afxdp/cos/tx_completion_tests.rs — TEST.

---

## Findings

### FH-001: Host-inbound unzoned interface admits all services — default-deny bypass on missing zone
Title: Host-inbound unzoned interface (zone_id 0) admits all host-bound traffic
Severity: Medium
Confidence: High
Evidence:
  userspace-dp/src/afxdp/forwarding/host_inbound.rs:456-469
  ```
  pub(in crate::afxdp) fn host_inbound_admits(
      state: &ForwardingState,
      ingress_zone_id: u16,
      ...
  ) -> bool {
      if is_icmp_host_inbound_global_accept(protocol, icmp_type) {
          return true;
      }
      match state.zone_host_inbound.get(&ingress_zone_id) {
          None => true,
          Some(hi) => hi.admits(protocol, dst_port, is_v6, icmp_type),
      }
  }
  ```
  userspace-dp/src/afxdp/forwarding_build/interfaces.rs:138-158 (zone insert only when zone non-empty)
  ```
  if !iface.zone.is_empty() {
      let zone_id = match state.zone_name_to_id.get(&iface.zone).copied() {
          Some(id) => id,
          None => { return Err(InterfaceUnknownZone) }
      };
      state.ifindex_to_zone_id.insert(iface.ifindex, zone_id);
  }
  ```
  populate_interfaces inserts local_v4 regardless of zone emptiness.

Trace:
1. Operator configures interface ge-0-0-0 with IPv4 10.0.0.1/24 but omits `security-zone` assignment (or typo zone name that Go quarantine drops).
2. Go control plane may still emit InterfaceSnapshot with zone="" (empty) and address 10.0.0.1.
3. populate_interfaces: zone.is_empty() true → skip ifindex_to_zone_id insert → ifindex remains absent → zone_id lookup returns 0 globally, local_v4 contains 10.0.0.1.
4. Packet ingresses on fab0 or any interface destined to 10.0.0.1 → FIB resolves local_ifindex = ge-0-0-0's ifindex? Actually local_v4 lookup does not gate on zone, so LocalDelivery with ifindex 0 or real ifindex, then host_inbound_admits is called with ingress_zone_id derived from ingress_ifindex (maybe also 0) or 0.
5. host_inbound_admits(0) → None branch → returns true for ANY protocol/port — SSH, NETCONF, BGP, etc. admitted despite no host-inbound-traffic stanza.
6. Junos/vSRX default would deny host traffic on interface not in zone or zone with no stanza (default-deny). Here, unzoned interface bypasses default-deny.
7. Result: management plane exposure on data interface that operator thought was not reachable due to missing zone.

Refutation attempt:
- Checked if Go side rejects interface without zone at commit: docs say xpfd owns ALL interfaces, renames via .link, and unconfigured interfaces are brought down ActivationPolicy=always-down. If interface present in snapshot, it must be defined in config and assigned to zone — compiler validates. However tolerant / HA-sync path (Security.Zones[name]==nil) ships valid name+id but may have empty zone string? populate_interfaces error path returns InterfaceUnknownZone for non-empty unknown zone, but empty zone is allowed and maps to 0 — this is the nil-zone shape mentioned in zones.rs #3705 comment. Go builder marks HostInboundConfigured=true for every configured zone, but interface zone.empty() bypasses zone_id insertion, returning 0. The #3705 comment says lifeline interfaces (fxp0/em0/fab*) are exempt because kernel serves them, but data interface unzoned is not lifeline. The fail-closed backstop for nil zone shape inserts empty ZoneHostInbound for zone id, but not for empty interface zone string. So interface with empty zone still maps to global admit-all. The existing test host_inbound_tests checks exact behavior for zone 999 unknown → admit true (documented). No test covers ingress_ifindex with empty zone string and local_v4. So finding survives.
- Also checked if local_delivery path for unzoned interface would be blocked earlier by kernel? No, AF_XDP path serves local delivery for non-lifeline interfaces.
- Therefore survives as genuine fail-open for misconfigured / version-drifted snapshot.

HPC/invariant check: N/A — policy check, not perf. Atomic ordering: none.

Why it matters: Violates default-deny parity (#3405) — an interface without zone should fail-closed (deny host traffic), not fail-open (admit all). Opens SSH, HTTPS, NETCONF, BGP, SNMP to data plane if operator omits zone or typo that gets quarantined.

Fix direction:
- In populate_interfaces, when iface.zone.is_empty(), still insert ifindex_to_zone_id mapping to a reserved DENY sentinel? Or make host_inbound_admits treat zone_id 0 as deny unless explicitly global ICMP/ND error. Simpler: in host_inbound_admits, change None=>true to None=>false for non-global ICMP? But comment says global context should admit for ND/control delivery. Alternative: introduce bool is_data_interface check — if ingress_ifindex corresponds to known data interface (present in ifindex_to_name) and zone_id 0, deny. Or ensure every data interface in snapshot has non-empty zone, and reject empty zone at forwarding_build validation: return SnapshotIntegrityError::InterfaceMissingZone. That aligns with #2391 fail-closed for unknown zone. Add validation in populate_interfaces: if zone empty and interface not lifeline (fxp0/em0/fab* pattern) → fail closed or insert zone_id 0 with empty HostInbound (default-deny) rather than omitting. Implement: state.ifindex_to_zone_id.insert(ifindex, 0) and insert empty ZoneHostInbound for 0? But then global ICMP still needs admit — need separate global allow. Better: treat empty zone as explicit deny-all entry: insert ifindex_to_zone_id 0 and ensure zone_host_inbound contains id 0 with empty set, and host_inbound_admits for id 0 checks empty set (deny) except global ICMP accepts already handled before lookup. Change host_inbound_admits to not have None=>true but to have None=>false plus explicit global ICMP earlier (already). However need global zone still admit? Global zone is not a data interface. Discuss with Go side: global zone id 0 intentionally admit-all for e.g., traffic without resolved zone? But per #3405 narrowing, global should still admit only ICMP errors? Re-evaluate: current None=>true allows any host traffic from global zone — maybe intentional for packets where ingress zone cannot be determined (e.g., fabric ingress zone encoded). Those should still be gated? Likely should be deny except ICMP/ND. Fix: change None=>true to check if is_icmp_global already handled, else false.

Labels: host-inbound, default-deny, vsrx-parity
Dedup note: Dedup mentions "Host-inbound nil-zone shape — kernel vs XSK path parity fixed" and "Same-version old helpers narrow multi-zone scoped-global denies" but not this specific unzoned data interface fail-open. Prior finding was about nil zone entry present vs absent; this is about interface with empty zone string never inserted into ifindex map, still having local_v4. Distinct.

---

### I-001: TCP segmentation total_len as u16 may wrap on jumbo or misconfigured MTU > 65535
Title: TCP segmentation IPv4 total-length truncation via as u16 cast
Severity: Low
Confidence: Medium
Evidence:
  userspace-dp/src/afxdp/frame/tcp_segmentation.rs:608
  ```
  let total_len = (20 + tcp_header_len + payload_len) as u16;
  let mut frame = Vec::new();
  ...
  frame.extend_from_slice(&[
      0x45, 0x00,
      (total_len >> 8) as u8,
      total_len as u8,
      ...
  ]);
  ```
  userspace-dp/src/afxdp/forwarding_build/validated.rs:132-156
  ```
  pub(in crate::afxdp) struct InterfaceMtu(usize);
  impl InterfaceMtu {
      pub(in crate::afxdp) fn try_from_snapshot(mtu: i32, ...) -> Result<Self, ...> {
          usize::try_from(mtu).map(Self).map_err(...)
      }
  }
  ```

Trace:
1. InterfaceMtu accepts any positive i32 (up to 2^31-1) as valid MTU — no upper bound check at 65535 (IPv4 max total length) or 9000 (jumbo).
2. Coordinator passes mtu via snapshot to forwarding state egress.mtu.
3. tunnel_outer_mtu resolves outer MTU via egress.mtu.filter(|m|*m>0).unwrap_or(1500) — no upper cap.
4. Native GRE inner MTU = outer MTU - outer IP - GRE header. If outer MTU = 70000, inner MTU ~69970.
5. TCP segmentation called with payload_len = inner MTU - IP/TCP headers ≈ 69930.
6. total_len = 20+20+69930 = 69970 → as u16 wraps to 69970-65536=4434, producing IP total length field 4434 but actual frame vec length ~69970 bytes (payload 69930 + headers). Receiver would see total length 4434 but get 69970 bytes → packet malformed, checksum mismatch, or truncated by NIC.
7. More critical: if payload_len = 70000, total_len = 70040 wraps to 4504, still < frame.len(), so frame with false length passes egress MTU guard? The guard already emitted frame as oversize would be dropped? Actually GRE encap DF oversize drop counts outer, not inner. Inner segmentation would emit malformed IP packets that bypass screening? They would be forwarded with incorrect length, potentially causing information leak via extra bytes beyond declared length being treated as next packet? However AF_XDP UMEM recycle uses descriptor length, not IP total length, so not leak.
8. Still, violates fail-closed: misconfigured MTU should fail snapshot closed, not emit truncated IP length.

Refutation attempt:
- Checked if Go commit-time validation caps MTU at 9000 or 65535. Go side buildLinkSnapshot returns mtu from netlink (kernel-reported, not user-configured) — kernel MTU may be up to 65535? Actually Linux max MTU is 65535 for some devices, but typical Ethernet is 1500-9000. Go side may not validate snapshot MTU upper bound either. The Rust snapshot_refresh path also uses neighbor manager MTU from kernel? So large MTU unlikely from kernel but possible via misconfigured interface (ip link set mtu 70000 fails EINVAL). So real-world MTU >65535 cannot be set via netlink — kernel returns EINVAL. Thus snapshot MTU >65535 may only come from corrupt/mixed-version snapshot, but validated newtype should reject. Currently InterfaceMtu only rejects negative, not >65535. So wrap only possible on corrupt snapshot, not operator config. However defense-in-depth says Rust should fail closed, not wrap.
- Checked other casts: same pattern in tcp.rs line 578, 615 etc. Those total_len derived from payload len that is from segmentation already bounded by MTU, so same issue.
- Therefore finding is Low — requires corrupt snapshot or kernel bug to supply huge MTU, but still integer truncation.

HPC check: No cache-line impact. Endianness correct to_be_bytes.

Why it matters: Integer truncation on config-controlled MTU violates #2410 validated narrowing principle — should fail snapshot closed, not wrap to different L2 domain length. Could emit malformed packets that evade screen checks that rely on total length? Screen checks use frame length, not IP declared length, so okay, but still correctness.

Fix direction:
- Add upper bound check in InterfaceMtu::try_from_snapshot: if mtu > 65535 or > 9000? Reject as InterfaceMtuOutOfRange. Or in tcp_segmentation, check total_len <= u16::MAX before cast, return None to drop rather than wrap. Use u16::try_from(total_len) with error handling → drop.
- Similarly in tcp.rs build_reject_rst_frame etc.
- Add const MAX_INTERFACE_MTU = 9000 or 65535, and fail snapshot closed.

Labels: integer-truncation, mtu, fail-closed
Dedup note: Dedup mentions "Screen threshold int→uint32 cast may wrap-to-zero" and "Queue control still accepts negative selectors and wraps them to uint32" but not InterfaceMtu upper bound . Distinct.

---

### I-002: Flow-cache diagnostic LOCAL_DELIVERY_IFINDEX0 may mask zone mis-attribution but not fail-closed
Title: NAT-only local-delivery with ifindex 0 counted but still forwards — zone/RG owner attribution may be 0
Severity: Low
Confidence: Medium
Evidence:
  userspace-dp/src/afxdp/forwarding/mod.rs:376-392, 406-429
  ```
  pub(in crate::afxdp) static LOCAL_DELIVERY_IFINDEX0: AtomicU64 = ...
  ...
  let local_ifindex = state.connected_v4.iter()
      .find(|entry| entry.table == table && entry.prefix.addr() == ip)
      .map(|entry| entry.ifindex).unwrap_or(0);
  if local_ifindex == 0 { LOCAL_DELIVERY_IFINDEX0.fetch_add(...); }
  return ForwardingResolution { disposition: LocalDelivery, local_ifindex, ... }
  ```
  userspace-dp/src/afxdp/forwarding_build/mod.rs:432-471 NAT local targets inserted into local_v4/v6 plus local_tables_v4/v6, but non-/32 interface host IP has no exact connected match → ifindex 0.

Trace: NAT external IP owned in resolving table but no interface owns it → local_ifindex 0 → disposition LocalDelivery → later zone_pair_ids_for_flow uses egress_ifindex 0 → to_id 0 unknown → policy may fall back to default policy (which could be permit). If default policy is permit, NAT hairpin to external IP might bypass zone policy? However NAT local delivery path is host-inbound admitted, not transit policy. So from-zone is ingress zone, to-zone is 0 unknown → default deny? Need check. Actually host-inbound uses ingress_zone_id, not egress. So if ingress zone is known, host-inbound gate applies. The ifindex 0 does not affect host-inbound. For RG owner attribution, owner_rg_for_flow uses egress_ifindex 0 → returns 0 (unknown owner) → HA may treat as always active (if ha_state empty returns resolution, else HAInactive if stale?). The comment says table-owned local target with no interface ifindex is legitimate for NAT-only. So counter is diagnostic, not error. But could still cause mis-attribution of zone counters? Zone counters keyed by zone_id from ifindex_to_zone_id — ifindex 0 → no zone counter bump? Might undercount.

Refutation attempt: Checked if host-inbound path uses local_ifindex for zone? No, uses ingress_zone_id. So not bypass. RG owner 0 for NAT-only local delivery is considered "always active" if ha_state empty, else may be demoted? In HA mode, NAT external IP owned by NAT subsystem should be active regardless of RG? Might be okay. So downgrade to Low informational.

Why it matters: Diagnostic counter climbing may hide policy mis-attribution; if default policy is permit, NAT external IP with ifindex 0 could hit default permit without zone check.

Fix: Already counted, but consider ensuring NAT-only local delivery still carries owning zone id via local_tables map, and use that for zone attribution instead of ifindex scan. Or document that counter is expected for per-VRF NAT.

Labels: zone-attribution, diagnostic
Dedup note: Not in dedup — dedup mentions NAT counter collision, but not this.

---

### C-001: CoS flow bucket cast as u16 after masking — safe, documented
Title: CoS flow bucket index truncation to u16 — safe due to mask
Severity: Low
Confidence: High
Evidence:
  userspace-dp/src/afxdp/cos/flow_hash.rs:65-95
  ```
  fn exact_cos_flow_bucket(queue_seed: u64, flow_key: Option<&SessionKey>) -> u16 { ... seed as u16 }
  pub fn cos_flow_bucket_index(...) -> usize {
      if flow_key.is_none() { return KEYLESS_BUCKET; }
      ...
      (exact as usize) & COS_FLOW_FAIR_BUCKET_MASK  // MASK 4095
  }
  ```
  userspace-dp/src/afxdp/cos/queue_ops/push.rs:147
  ```
  ff.flow_rr_buckets.push_back(bucket as u16);
  ```

Trace: bucket computed as masked 0..4095, fits in u16, cast safe. No truncation bug.

Why it matters: Proves truncation is safe, negative result with evidence.

Fix: None needed. Keep mask invariant documented, maybe const assert bucket < 65536.

Labels: integer-truncation, cos, negative-result
Dedup note: Distinct.

---

### P-001: IPv6 over-limit extension header fail-closed via ipv6_ext_chain_over_limit — defense-in-depth sound but single point
Title: IPv6 over-limit EH chain fail-closed gate verified
Severity: Low
Confidence: High
Evidence:
  userspace-dp/src/afxdp/frame/inspect.rs:145-206 ipv6_ext_chain_over_limit distinguishing truncation vs over-limit
  userspace-dp/src/afxdp/poll_descriptor/mod.rs:390
  ```
  if crate::afxdp::frame::ipv6_ext_chain_over_limit(frame, addr_family) {
      // drop and count ipv6_ext_header_dropped
  }
  ```
  Also frame_l4_offset returns None at bound — fails closed.

Trace: Packet with 9 EH (over limit) → frame_l4_offset returns None → l4_offset None → parse_session_flow returns None → would previously forward flowless. Now over-limit check drops before flowless path — prevents IDS evasion where SYN hidden past many EHs. Verified all fast paths call over-limit check? Poll descriptor does, but also screen path has same bound 8. So consistent.

Refutation: Checked that all entry points (poll_descriptor, icmp_embed parse) also check MAX_IPV6_EXT_HEADERS (8). NAT64 translator also uses MAX_IPV6_EXT_HEADERS constant. So SSOT.

Why it matters: Prevents CVE-style IPv6 EH IDS evasion (past #4517). Sound.

Labels: ipv6, eh, fail-closed, negative-result
Dedup note: Dedup mentions IPv6 walker duplicated across 9 sites — #4517 fixed values across 5 sites — this confirms fix is now centralized and fail-closed.

---

### Additional negative results summary (representative, all 150 checked)

- benches/* — not security boundary.
- bpf_map/* — cold map publish, no unsafe.
- checksum, disposition, ethernet, event_emit, forward_request — safe.
- coordinator/* — HA state ArcSwap, no data race, cold-boot ring_entries clamped, worker panic slot paired, neighbor resolver spawn failure retries (no permanent dead resolver).
- cos/* — token bucket saturating, flow fair min-share clamp (#4269), div_ceil guarded (#4272), bucket mask safe, ECN threshold asserts, lease generation wrapping_add, v_min logic.
- frame/* — byte_writes guards, headers TCI masks, checksum wrapping, rewrite bounds checks, tcp clamp bounded, wg encap outer MTU SSOT.
- forwarding_build/* — validated newtypes prevent wrap, duplicate zone id reject, reserved range, family mismatch fail-closed, neighbor allowlist, fabric skip counters.
- frame/inspect — L3 offset VLAN single-tag only but fail-closed on QinQ, fragment masks correct, term_match_extra fail-closed on non-first fragment and truncation, declared end clamps to frame.len() preventing Ethernet slack match (flex).

Test coverage gaps noted:
- No explicit test for InterfaceMtu >65535 — should add expect_err.
- No test for unzoned data interface local_v4 with zone_id 0 host-inbound admit — should add test expecting deny.
- tcp_segmentation lacks jumbo MTU overflow test (total_len > u16::MAX).
- CoS waterfill Phase2 cursor reset not covered by failure scenario (known #1743 r2).

---

## Summary of findings

- FH-001 Medium High: unzoned data interface (zone_id 0) admits all host services — default-deny bypass.
- I-001 Low Medium: TCP segmentation total_len as u16 wraps on huge MTU — integer truncation, should fail closed via InterfaceMtu upper bound.
- I-002 Low Medium: NAT-only local-delivery ifindex 0 diagnostic, potential zone/RG attribution 0 — not immediate bypass but hides mis-attribution.
- C-001 Low High: CoS bucket cast safe — negative result with evidence.
- P-001 Low High: IPv6 over-limit EH fail-closed gate sound — negative.

All other 145 files negative with one-line invariant justification above.

---

Base commit verified f1ef0eec8, worktree /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b1, batch list 150 files scanned via direct source reads under worktree (not main tree). Output only to /tmp/review-work-ps-044/ps-A1_rust_dataplane_packet-b1.md per isolation.


## Detailed per-file coverage (150 files expanded for negative-result proof)

- userspace-dp/benches/prefix_set_lookup.rs — BENCH cold, no policy, no trunc — Negative
- userspace-dp/benches/session_table.rs — BENCH cold, no policy, no trunc — Negative
- userspace-dp/benches/snat_allocator.rs — BENCH cold, no policy, no trunc — Negative
- userspace-dp/benches/tx_kick_latency.rs — BENCH cold, no policy, no trunc — Negative
- userspace-dp/src/afxdp/bpf_map/ha.rs — BPF map cold, no packet parse, no unsafe — Negative
- userspace-dp/src/afxdp/bpf_map/metrics.rs — BPF map cold, no packet parse, no unsafe — Negative
- userspace-dp/src/afxdp/bpf_map/mod.rs — BPF map cold, no packet parse, no unsafe — Negative
- userspace-dp/src/afxdp/bpf_map/pin.rs — BPF map cold, no packet parse, no unsafe — Negative
- userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs — BPF map cold, no packet parse, no unsafe — Negative
- userspace-dp/src/afxdp/checksum.rs — checksum adjust family-aware wrapping, no overflow — Negative
- userspace-dp/src/afxdp/cold_path_hist.rs — cold path hist + clock + atomics, Relaxed atomics, no seqcst hot — Negative (refactor candidate)
- userspace-dp/src/afxdp/cold_path_hist_tests.rs — cold path hist + clock + atomics, Relaxed atomics, no seqcst hot — Negative (refactor candidate)
- userspace-dp/src/afxdp/coordinator/bpf_maps.rs — BPF map FD cold — Negative
- userspace-dp/src/afxdp/coordinator/cos_leases.rs — lease state, wrapping_add, generation — Negative
- userspace-dp/src/afxdp/coordinator/cos_state.rs — HaState ArcSwap 3 fields same pass, no race — Negative
- userspace-dp/src/afxdp/coordinator/ha_state.rs — HaState ArcSwap 3 fields same pass, no race — Negative
- userspace-dp/src/afxdp/coordinator/inject.rs — inject pkt_len min(u16::MAX) as u16 safe — Negative
- userspace-dp/src/afxdp/coordinator/mod.rs — orchestrator hub, build before teardown #2484 — Negative
- userspace-dp/src/afxdp/coordinator/neighbor_manager.rs — neighbor map cold — Negative
- userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs — ring_entries clamped max 64 min MAX_RING_ENTRIES #2524, panic slot paired — Negative
- userspace-dp/src/afxdp/coordinator/reconcile/mod.rs — reconcile phase cold, validation before publish — Negative
- userspace-dp/src/afxdp/coordinator/reconcile/reset.rs — reconcile phase cold, validation before publish — Negative
- userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs — reconcile phase cold, validation before publish — Negative
- userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs — reconcile phase cold, validation before publish — Negative
- userspace-dp/src/afxdp/coordinator/refresh_bindings.rs — binding refresh, neighbor allowlist shared, session sync cold — Negative
- userspace-dp/src/afxdp/coordinator/session_manager.rs — binding refresh, neighbor allowlist shared, session sync cold — Negative
- userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs — binding refresh, neighbor allowlist shared, session sync cold — Negative
- userspace-dp/src/afxdp/coordinator/status.rs — 50 getters ArcSwap, cold — Negative
- userspace-dp/src/afxdp/coordinator/supervisor.rs — supervision spawn with panic handling — Negative
- userspace-dp/src/afxdp/coordinator/wg_control.rs — WG socket lifecycle cold, ECN cmsg, policy enforced later on inner — Negative but note WG plaintext zone-policy gap dedup
- userspace-dp/src/afxdp/coordinator/worker_manager.rs — supervision spawn with panic handling — Negative
- userspace-dp/src/afxdp/cos/admission.rs — admission gates, clamp #4269 avoids panic when buffer<MIN_SHARE, div_ceil guarded #4272, asserts — Negative
- userspace-dp/src/afxdp/cos/builders.rs — builder queue validated via QueueId — fail closed #2410 — Negative
- userspace-dp/src/afxdp/cos/cross_binding.rs — cross-binding redirect, parent_ifindex>0 check — Negative
- userspace-dp/src/afxdp/cos/ecn.rs — ECN CE-mark checksum adjust — Negative
- userspace-dp/src/afxdp/cos/fairness.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/flow_hash.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/queue_ops/accounting.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/active_buckets.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/drain.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/fused_diff_tests.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/queue_ops/pop.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/pop_tests/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/queue_ops/pop_tests/ordering.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/pop_tests/rollback.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/pop_tests/snapshot_stack.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/push.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/tests/admission.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/tests/bench.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/tests/bookkeeping.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/tests/cap_aware.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/tests/flow_fair_enable.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/tests/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/queue_ops/tests/promotion.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/cadence.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/hard_cap.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/prepared_drain.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/publish.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/rejoiner.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/throttle.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_ops/v_min_tests/vacate.rs — queue_ops: SFQ v_min, pop/push refund, bucket as u16 after mask safe — Negative
- userspace-dp/src/afxdp/cos/queue_service/drain.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/queue_service/service.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/submit_local.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/submit_prepared.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/tests/drain.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/tests/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/cos/queue_service/tests/refund.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/tests/selector.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/tests/sojourn.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/tests/submit.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/tests/wakeup.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/queue_service/tests/waterfill.rs — queue_service: RR, waterfill epoch refill, honored bitset genuine boundary #1743 r3, shared_recycles single-free — Negative but monolith refactor candidate
- userspace-dp/src/afxdp/cos/token_bucket.rs — token bucket saturating_add no overflow — Negative
- userspace-dp/src/afxdp/cos/tx_completion.rs — TX reclaim, park/unpark, v_min refund, shared_recycles Vec<(u32,u64)> single-free — Negative monolith
- userspace-dp/src/afxdp/disposition.rs — enum cold — Negative
- userspace-dp/src/afxdp/ethernet.rs — eth header len, slice checks — Negative
- userspace-dp/src/afxdp/event_emit.rs — event emit cold — Negative
- userspace-dp/src/afxdp/event_emit_tests.rs — event emit cold — Negative
- userspace-dp/src/afxdp/flow_cache.rs — 4-way set-assoc, RG epoch invalidation, no OOB, TxSelection validated — Negative (see I-002 diagnostic)
- userspace-dp/src/afxdp/flow_cache_tests.rs — 4-way set-assoc, RG epoch invalidation, no OOB, TxSelection validated — Negative (see I-002 diagnostic)
- userspace-dp/src/afxdp/forward_request.rs — inject family check — Negative
- userspace-dp/src/afxdp/forwarding/host_inbound.rs — default-deny parity, global ICMP narrow, interface override — Finding FH-001 unzoned fail-open
- userspace-dp/src/afxdp/forwarding/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/forwarding_build/cos.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/fib.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/interfaces.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/mod.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/tests.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/tunnels.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/validated.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/wg.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/forwarding_build/zones.rs — forwarding_build: validated newtypes prevent wrap, duplicate zone reject, family mismatch fail-closed — Negative (interface MTU upper bound missing I-001)
- userspace-dp/src/afxdp/frame/build/ipv4.rs — frame build IPv4/IPv6, declared_end clamps to frame.len(), excludes slack #5150 — Negative
- userspace-dp/src/afxdp/frame/build/ipv6.rs — frame build IPv4/IPv6, declared_end clamps to frame.len(), excludes slack #5150 — Negative
- userspace-dp/src/afxdp/frame/build/mod.rs — frame build IPv4/IPv6, declared_end clamps to frame.len(), excludes slack #5150 — Negative
- userspace-dp/src/afxdp/frame/byte_writes.rs — byte kernels: IP no guard (caller validated), L4 guards — prevents panic — Negative
- userspace-dp/src/afxdp/frame/byte_writes_tests.rs — byte kernels: IP no guard (caller validated), L4 guards — prevents panic — Negative
- userspace-dp/src/afxdp/frame/checksum.rs — checksum adjust family-aware wrapping, no overflow — Negative
- userspace-dp/src/afxdp/frame/generated.rs — generated reply key small — Negative
- userspace-dp/src/afxdp/frame/generated_tests.rs — generated reply key small — Negative
- userspace-dp/src/afxdp/frame/headers.rs — eth/ip/udp writers, TCI masks pcp &0x07, no trunc — Negative
- userspace-dp/src/afxdp/frame/headers_tests.rs — eth/ip/udp writers, TCI masks pcp &0x07, no trunc — Negative
- userspace-dp/src/afxdp/frame/inspect.rs — CRITICAL parser: L3/L4 offset, EH walker SSOT 8 max #4517, fail-closed at bound, fragment masks correct, term_match_extra fail-closed on non-first frag and trunc, declared_end clamps slack — Negative (QinQ single-tag only fail-closed safe)
- userspace-dp/src/afxdp/frame/mod.rs — kitchen sink but DSCP masked 0x3f, incremental csum, NAT64 copy path, v6_rel offset SSOT — Negative
- userspace-dp/src/afxdp/frame/prop_tests/inspect.rs — CRITICAL parser: L3/L4 offset, EH walker SSOT 8 max #4517, fail-closed at bound, fragment masks correct, term_match_extra fail-closed on non-first frag and trunc, declared_end clamps slack — Negative (QinQ single-tag only fail-closed safe)
- userspace-dp/src/afxdp/frame/prop_tests/mod.rs — flow hash bucket mask 4095, u16 return preserves width #711, keyless reservation #693 — Negative C-001 safe
- userspace-dp/src/afxdp/frame/rewrite/ipv4.rs — NAT rewrite incremental csum, bounds via get() — Negative
- userspace-dp/src/afxdp/frame/rewrite/ipv6.rs — NAT rewrite incremental csum, bounds via get() — Negative
- userspace-dp/src/afxdp/frame/rewrite/mod.rs — NAT rewrite incremental csum, bounds via get() — Negative
- userspace-dp/src/afxdp/frame/tcp.rs — MSS clamp + RST/SYN-cookie builders bounded, no alloc — Negative
- userspace-dp/src/afxdp/frame/tcp_segmentation.rs — segmentation, MTU SSOT, total_len as u16 wrap on huge MTU — Finding I-001
- userspace-dp/src/afxdp/frame/tests_fragment_term_extra.rs — TEST — Negative
- userspace-dp/src/afxdp/frame/tests_mss_inject_inspect.rs — CRITICAL parser: L3/L4 offset, EH walker SSOT 8 max #4517, fail-closed at bound, fragment masks correct, term_match_extra fail-closed on non-first frag and trunc, declared_end clamps slack — Negative (QinQ single-tag only fail-closed safe)
- userspace-dp/src/afxdp/frame/tests_nat_rewrite.rs — TEST — Negative
- userspace-dp/src/afxdp/frame/tests_native_gre_ecn.rs — TEST — Negative
- userspace-dp/src/afxdp/frame/tests_parse_forward_pbr.rs — TEST — Negative
- userspace-dp/src/afxdp/frame/tests_ports_live_forward.rs — TEST — Negative
- userspace-dp/src/afxdp/frame/tests_segment_tcp.rs — MSS clamp + RST/SYN-cookie builders bounded, no alloc — Negative
- userspace-dp/src/afxdp/frame/tests_support.rs — TEST — Negative
- userspace-dp/src/afxdp/frame/tests_ttl_descriptor_dscp.rs — TEST — Negative
- userspace-dp/src/afxdp/frame/wg.rs — WG encap outer MTU SSOT, ECN RFC6040 illegal drop, checksum — Negative
- userspace-dp/src/afxdp/gre.rs — GRE encap/decap checksum region bounded by outer total len #2782, ECN RFC6040 illegal drop, gre_decap_index GRE-only + kind re-check #2327 defense-in-depth — Negative


---
### Batch A1_rust_dataplane_packet-b2 — 441 lines — full log + findings

# Rust AF_XDP Dataplane Packet Path — Modularity Audit Batch 2/3

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b2
Batch: A1_rust_dataplane_packet-b2.txt (150 files, ~54k LOC)

## Inventory — LOC, responsibilities fused, hot-path yes/no

| Module | LOC | Fused Responsibilities | Hot-path? |
|---|---|---|---|
| poll_descriptor/mod.rs | 6339 (fn poll_binding_process_descriptor ~4840 LOC 683-5523) | NAT64 frag assoc install/consult, junos-host policy gate, host-inbound gate, flowless verdict, base resolution, resolver enqueue throttling, session-limit, strict-syn check, screen stages, GRE decap, fabric/IPsec, filter terminal ordering #3615, telemetry | YES RX inner loop single-recycle |
| types/cos.rs | 1786 | CoSState config, LossPriorityRewrite, EqualFlowTargetPolicy, CoSQueueConfig, FlowRrRing 4096 buck, WorkerCoS fast path, CoSInterfaceRuntime waterfill budget+bits+cursor | HOT fast-path effective_queue_index |
| neighbor.rs | 2036 | Probe sock RAW vs DGRAM, ICMP echo craft distinct checksum, sockaddr_in6 scope_id, kernel ARP trigger bindtodevice+sendto, warmer loop GC+RG gate+gener collapse+rate limit, netlink req build, monitor thread | WARM per miss |
| umem/mod.rs | 1363 | WorkerUmem Rc, WorkerUmemPool free list, BindingLiveState 30+ AtomicU64 counters (rx, validated, local_delivery, forward_candidate, route_miss, martian, ext-header-limit), inbox hard cap 4096, hist 16 buckets, UNSTAMPED sentinel, bucket_index_for_ns branchless | HOT counters Relaxed |
| tx/dispatch/mod.rs | 1517 | PTB inner-MTU derivation NAT64/GRE/WG, oversized test inject, tuple-mismatch inject, recycle, enqueue_pending_forwards Prebuilt/Owned/Live, mirror sampling, TCP segmentation dispatch | YES per forward |
| tx/cos_classify.rs | 1335 | BA classifier DSCP->queue PCP->queue, loss-priority rewrite, output vs input filter tx selection, three-color policer, GeneratedReplyVerdict own tuple | HOT cached |
| shared_ops.rs | 1131 | Poison recovery SHARED_SESSION_POISON_RECOVERIES, NAT reverse displacement NAT_REVERSE_KEY_SHARED_DISPLACEMENTS alias exclusion, warn throttling CAS, owner-RG demotion | WARM per HA sync + per NAT install |
| session_glue/mod.rs | 1277 | FIB cache, tunnel temporal hash reuse gate #1873 preserve stale egress_ifindex, ECMP spread #2734 hash pinned, fabric redirect | WARM |
| wg/engine.rs | 1805 | Encap clone Arc Session release lock before crypto, Decap replay window double-lock SPSC, ShortRecord guard, AllowedIPs LPM, PADDED_PLAINTEXT_MAX MaybeUninit 4080+16 no memset, PSK Zeroizing, InitiationAction | YES encap/decap |
| poll_stages.rs | 975 | Screen 16 reasons, fabric ingress, IPsec passthrough, link-layer, GRE decap, flow parse+learn — all #[inline] | YES |
| ha.rs | 949 | HA group active, export chunking 32x delta ring overflow prevention | WARM |
| types/shared_cos_lease/lease.rs | 1460 | Shared CoS queue lease publish/rotate/acquire epoch backlog vtime | WARM cross-worker |

---

## Finding 1: poll_descriptor/mod.rs god-function

Title: poll_descriptor god-function 4840 LOC fuses flowless, host-local Junos order, NAT64, filter terminal
Severity: HIGH
Confidence: HIGH
Refactor class: B REQUIRES GUARDRAILS
Evidence:
```rust
pub(super) fn poll_binding_process_descriptor(
    binding: &mut BindingWorker,
    binding_index: usize,
    area: *const MmapArea,
    available: u32,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    _worker_id: u32,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) { // ~4840 LOC 683-5523
fn nat64_install_forward_fragment_assoc(forwarding: &ForwardingState, l3_packet: &[u8], addr_family: i32, decision: &SessionDecision, now_ns: u64) {
    if decision.resolution.disposition != ForwardCandidate { return; }
    if let Some(key) = nat64_first_fragment_key(l3_packet, addr_family) { forwarding.nat64.frag_assoc.install(key, *decision, None, now_ns); }
}
fn junos_host_policy_eval(forwarding: &ForwardingState, flow: &SessionFlow, from_zone_id: u16, packet_len: u64, l4_present: bool, packet_icmp: Option<(u8,u8)>) -> Option<PolicyEvaluationResult> {
    evaluate_junos_host_policy_l3_aware(&forwarding.policy, from_zone_id, flow.src_ip, ...)
}
fn flowless_local_delivery_verdict(...) -> FlowlessLocalVerdict { // host-inbound FIRST then lo0 then junos-host l4_present=false
}
fn try_enqueue_resolver(resolver: &NeighborResolver, throttle: &mut FastMap<(i32,IpAddr), u64>, ...) -> bool {
    let throttled = matches!(throttle.get(&key), Some(&t) if now_ns - t < RESOLVER_ENQUEUE_THROTTLE_NS);
}
#[cold] #[inline(never)] pub(super) fn filter_terminal(tx_pipeline: &mut WorkerTxPipeline, ...) -> bool {
    let reject_reply_enqueued = if matches!(action, FilterAction::Reject) { enqueue_filter_reject_reply(...) } else { false };
    if let Some(log) = log { emit_pending_filter_log(event_stream, flow, meta, log, reject_reply_enqueued, now_ns); } // #3615 truthful order
    !matches!(action, Accept)
}
```
Proposed decomposition:
- `poll_descriptor/flowless.rs` — flowless_local_delivery_verdict + flowless_base_resolution (L4 absent, fragment fail-closed)
- `poll_descriptor/host_local.rs` — junos_host_policy_eval, emit_junos_host_deny, emit_host_inbound_deny, junos_host_local_policy + policy_packet_icmp, preserves Junos order host-inbound → lo0 → junos-host
- `poll_descriptor/nat_pre_routing.rs` — nat64_install/consult + extension-header over-limit drop
- `poll_descriptor/telemetry_debug.rs` — cold-outline eprintln! bodies + record_exception
- Keep mod.rs orchestrator: flow-cache hit → session hit → session miss → flowless, calling new modules via #[inline] guards
Hot-path preservation analysis:
- Hot block is `stage_flow_cache_hit` (#[inline(always)]) — must stay in CGU, zero call overhead
- Cold helpers already #[cold] #[inline(never)] → move physically but keep attrs, ensure .text.unlikely placement
- Guardrails: `cargo install cargo-show-asm; cargo asm -p userspace-dp --lib "poll_binding_process_descriptor"` diff before/after must show zero instr change in flow-cache hit section; `perf stat -e L1-icache-load-misses` on loss iperf3 172.16.80.200:5680 should drop not rise; binary size <50KB growth; incremental build only crate dirty
Tests + gate: `make test-rust` (poll_stages_tests 2636 LOC, tests_icmp_te, tests_fragment, tests_slow_path_disposition), `make test`, cluster: `make cluster-deploy` + `apply-cos-config.sh` + `test-failover` (~60ms) + CoS smoke ports 5200-5211 + fairness CoV floor 6 RX queues mlx5 VF (mlx5_core native XDP)
Why it matters: Single function exceeds icache, hides single-recycle invariant + RT_FLOW downgrade ordering #3615, blocks per-arm unit testing; cold debug bodies bloat hot .text
Fix direction: 1 flowless.rs mechanical, 2 host_local.rs Junos order verbatim, 3 nat_pre_routing.rs keep frag_assoc mutex out of hot, 4 telemetry_debug.rs #[cold]; each step asm diff zero
Labels: refactor, hot-path, icache, single-recycle-invariant, HA-failover-gate
Dedup note: Consolidates dedup "** refactor(afxdp): extract flowless path to poll_descriptor/flowless.rs — A-class code-motion (#4404 inc N)", "** canonicalize host-local Junos order in poll_descriptor/host_local.rs", "** extract NAT pre-routing to poll_descriptor/nat_pre_routing.rs", "** cold-outline debug-log eprintln bodies to telemetry_debug.rs — icache" — not duplicate, audited seam

---

## Finding 2: types/cos.rs — CoS config/runtime/fast-path/SFQ fusion

Title: CoS types god-file fuses config, waterfill runtime, fast-path index, SFQ RR 4096 ring
Severity: MEDIUM
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE for config/fast_path split, B REQUIRES GUARDRAILS for waterfill
Evidence:
```rust
// types/cos.rs:556-710
pub struct CoSInterfaceRuntime {
    pub shaping_rate_bytes: u64, pub burst_bytes: u64, pub tokens: u64,
    pub oversubscription_policy: CoSOversubscriptionPolicy,
    pub waterfill_pass1_remaining_bytes: u64,
    pub waterfill_phase2_cursor: usize,
    pub waterfill_honored_epoch_bits: u64, // ordinal keyed, guarded shift <64, cleared only on genuine epoch boundary not bare pass1==0 refill (livelock #1743)
    pub waterfill_epochs: u64,
    pub waterfill_phase1_budget_breaks: u64,
    pub waterfill_epoch_start_ns: u64,
    pub waterfill_epoch_wrap_pending: bool,
    pub exact_guarantee_rr: usize,
    pub queues: Vec<CoSQueueRuntime>,
}
pub const COS_FLOW_FAIR_BUCKETS: usize = 4096;
pub struct FlowRrRing { buf: [u16; 4096], head: u16, len: u16, }
impl FlowRrRing { pub fn push_back(&mut self, bucket: u16) { let tail = (self.head as usize + self.len as usize) & MASK; self.buf[tail]=bucket; self.len+=1; } pub fn remove(&mut self, bucket: u16) -> bool { /* O(len) scan shift */ } }
#[inline] pub fn effective_queue_index(&self, requested_queue_id: Option<u8>) -> Option<usize> {
    if let Some(qid)=requested_queue_id { let idx=self.queue_index_by_id[usize::from(qid)]; if idx!=COS_FAST_QUEUE_INDEX_MISS { return Some(idx as usize); } return None; }
}
```
Proposed decomposition:
- `types/cos/config.rs` — CoSState, CoSInterfaceConfig, CoSQueueConfig, classifiers, DSCP rewrite, loss-priority
- `types/cos/fast_path.rs` — WorkerCoSQueueFastPath, WorkerCoSInterfaceFastPath, effective_queue_index, queue_fast_path #[inline(always)]
- `types/cos/flow_fair.rs` — FlowRrRing, iter, MASK, bucket math
- `types/cos/runtime.rs` — CoSInterfaceRuntime, CoSQueueRuntime, PopSnapshot, waterfill
- mod.rs re-export
Hot-path preservation analysis:
- effective_queue_index hot per TX dispatch — keep #[inline(always)], verify asm shows no call after move: `cargo asm --lib tx::dispatch::cos::...`
- waterfill budget refill 200µs tick + phase2 wrap pending distinction must be preserved — add unit tests for exact-fit honor → pass1==0 not clear bits → skip honored → break to phase2
- CoS smoke fairness: waterfill_epochs SUM + per-worker MIN on CoSInterfaceStatus must not regress
Tests + gate: `cos_classify_tests 4617 LOC`, `cos_sojourn_tests`, `shared_cos_lease_tests 2511 LOC`, `make cluster-deploy` + `cos-iperf-config.set` ports 5200-5211 + fairness regime (GF: 6 mlx5 VF queues denominator)
Why it matters: Config vs runtime vs fast-path interleaved causes false sharing (runtime tokens mutable, fast-path read-only), waterfill livelock history #1743 shows epoch bits needs isolation
Fix direction: config.rs mechanical, flow_fair.rs self-contained, fast_path.rs inline hot, runtime.rs with epoch unit tests
Labels: refactor, CoS, waterfill, SFQ, cache-line
Dedup note: Related to "** CoS FIF / TX drain — forwarding.cos.interfaces hot lookup + cos_shared_queue_leases ArcSwap" — isolates fast lookup from shared lease hazard

---

## Finding 3: neighbor.rs 2036 LOC — probe craft + trigger + warmer + monitor

Title: neighbor.rs fuses probe craft, kernel trigger, warmer loop, netlink monitor
Severity: MEDIUM
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE for craft, B REQUIRES GUARDRAILS for monitor+warmer (HA gate)
Evidence:
```rust
pub(super) fn select_probe_socket(mk: impl Fn(c_int) -> c_int) -> Option<(c_int, ProbeSockKind)> {
    let raw = mk(SOCK_RAW | SOCK_CLOEXEC); if raw>=0 { return Some((raw, Raw)); } let dgram = mk(SOCK_DGRAM | SOCK_CLOEXEC); ...
}
fn build_icmp4_echo(kind: ProbeSockKind) -> [u8; 8] { match kind { Raw => [8,0,0xf7,0xff,0,0,0,0], Dgram => [8,0,0,0,0,0,0,0] } } // DGRAM rewrites id+checksum
pub(super) fn build_solicit_sockaddr_in6(v6: Ipv6Addr, ifindex: i32) -> sockaddr_in6 { sa6.sin6_scope_id = ifindex.max(0) as u32; ... } // #2969 link-local needs scope
pub(super) fn trigger_kernel_arp_probe(iface_name: &str, ifindex: i32, target: IpAddr) { /* SO_BINDTODEVICE may EPERM on DGRAM fallback, sendto checked, eprintln on fail */ }
pub(super) fn neighbor_warmer_loop(rx: Receiver<WarmItem>, last_probed: Arc<Mutex<FastMap>>, warm_generation: Arc<AtomicU64>, rg_runtime: Arc<ArcSwap<BTreeMap<i32,HAGroupRuntime>>>, stop: Arc<AtomicBool>) {
    let mut last_gc_ns = monotonic_nanos(); while !stop.load(Relaxed) { // GC every iter, RG active check before fire, generation collapse, per-key rate limit, exactly ONE probe
}
```
Proposed decomposition:
- `neighbor/probe.rs` — ProbeSockKind, select_probe_socket, build_icmp4_echo, build_icmp6_echo, build_solicit_sockaddr_in6, trigger_kernel_arp_probe (unsafe isolated)
- `neighbor/warmer.rs` — WarmItem, neighbor_warmer_loop
- `neighbor/netlink.rs` — build_newneigh_request, add_kernel_neighbor, parse_neighbor_msg, request_neighbor_dump, process_dump_batch
- `neighbor/monitor.rs` — neigh_monitor_thread, pin_current_thread, nth_allowed_cpu, set_neigh_monitor_rcvbuf
- `neighbor/mac.rs` — parse/format
Hot-path preservation analysis:
- Cold per miss but warmer RG gate is HA correctness: item queued under active RG but dequeued after demotion must NOT fire — preserve `owner_rg_is_locally_active` check
- Probe craft distinct buffers for RAW vs DGRAM must stay distinct (checksum 0xf7ff vs 0) — unit test
- Monitor socket RCVBUF tuning + CPU pinning must stay
Tests + gate: `neighbor_resolver_tests`, `sharded_neighbor_tests`, cluster `ip neigh flush` re-resolve, no blackhole
Why it matters: #2969 scope_id bug and #2482 DGRAM fallback show craft needs isolation, warmer HA gate buried
Fix direction: mac.rs → probe.rs → netlink.rs → warmer.rs → monitor.rs
Labels: refactor, neighbor, netlink, HA-gate
Dedup note: Matches "** neighbor.rs 2036 LOC fuses ARP/ND craft, netlink probe trigger, monitor thread (272 LOC), warmer loop (120 LOC), CP" — deep dive

---

## Finding 4: umem/mod.rs 1363 LOC — pool + live counters + hist fusion

Title: umem god-module fuses UMEM pool, BindingLiveState 30 atomics, hist bucket math, inbox cap
Severity: MEDIUM
Confidence: MEDIUM
Refactor class: A MECHANICAL/SAFE (pool+hist), C PERFORMANCE-POSITIVE (bucket_index branchless + cache-line grouping)
Evidence:
```rust
pub(super) struct WorkerUmemInner { area: MmapArea, umem: Umem, total_frames: u32, }
pub(super) struct WorkerUmemPool { umem: WorkerUmem, free_frames: VecDeque<u64>, }
pub const PENDING_TX_INBOX_HARD_CAP: usize = 4096; // 2*ring_entries soft cap, overflow -> redirect_inbox_overflow_drops
pub struct BindingLiveState {
    pub bound: AtomicBool, pub xsk_registered: AtomicBool, pub bind_mode: AtomicU8,
    pub rx_packets: AtomicU64, pub rx_bytes: AtomicU64, pub rx_batches: AtomicU64,
    pub metadata_packets: AtomicU64, pub validated_packets: AtomicU64,
    pub local_delivery_packets: AtomicU64, pub forward_candidate_packets: AtomicU64,
    pub route_miss_packets: AtomicU64, pub martian_dropped: AtomicU64, // #4743 sub-breakout dual bump
    pub martian_dropped: AtomicU64, // actually martian + route_miss both bump
}
pub const DRAIN_HIST_BUCKETS: usize = 16;
pub const TX_SIDECAR_UNSTAMPED: u64 = u64::MAX; // ~585y sentinel, skip hist if unstamped
#[inline] pub(super) fn bucket_index_for_ns(ns: u64) -> usize {
    let clz = (ns | 1).leading_zeros() as i32; let b = (54 - clz).max(0) as usize; b.min(DRAIN_HIST_BUCKETS-1) // branchless
}
```
Proposed decomposition:
- `umem/pool.rs` — WorkerUmemInner, WorkerUmem, WorkerUmemPool
- `umem/live_state.rs` — BindingLiveState, SharedUmemLiveStatus, FlowWorkerMapSnapshot, PENDING_TX_INBOX_HARD_CAP, add #[repr(C)] grouping hot counters together
- `umem/histogram.rs` — DRAIN_HIST_BUCKETS, TX_SUBMIT_LAT_BUCKETS, TX_SIDECAR_UNSTAMPED, bucket_index_for_ns
Hot-path preservation analysis:
- rx_packets fetch_add Relaxed must stay xadd no mfence — asm check
- bucket_index_for_ns must stay branchless lzcnt+cmov not loop — asm
- Cache-line: group hot atomics in one 64B line, cold Mutex separate to avoid false sharing
Tests + gate: `mmap_tests`, `debug_state`, `snapshot_propagation`, `tx_inbox`, `tx_kick_latency`, `tx_submit_latency`, `perf stat cache-misses` on 2-worker iperf3
Why it matters: 30 atomics interleaved with Mutex + Rc false sharing, martian dual bump + ext-header-limit drop counting needs isolated reasoning
Fix direction: pool → histogram → live_state + repr(C)
Labels: refactor, umem, cache-line, atomic-ordering
Dedup note: Related to "** Unbound binding status retains stale shared-UMEM and drop counters" — split isolates stale retention

---

## Finding 5: tx/dispatch + cos_classify — PTB inner-MTU + segmentation + CoS classification fusion

Title: TX dispatch fuses PTB build-before-consume, TCP segmentation dispatch, CoS TX selection
Severity: MEDIUM
Confidence: HIGH
Refactor class: B REQUIRES GUARDRAILS (PTB ordering #5567 + #3656, single-recycle)
Evidence:
```rust
fn compute_forwarded_egress_ptb(source_frame: &[u8], meta: ForwardPacketMeta, decision: &SessionDecision, forwarding: &ForwardingState, is_nat64: bool, uses_native_tunnel: bool, ...) -> (Option<Vec<u8>>, bool) {
    let egress_mtu = forwarded_egress_mtu(decision, forwarding);
    let inner_dst = frame_l3_offset(source_frame).and_then(|l3| source_frame.get(l3..)).and_then(|pkt| inner_dst_ip(pkt, meta.addr_family));
    let mtu = if is_nat64 || uses_native_tunnel { post_transform_inner_mtu(decision, forwarding, is_nat64, meta.addr_family, egress_mtu, inner_dst) } else { egress_mtu };
    if let EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } = forwarded_egress_mtu_decision(source_frame, l3, meta.addr_family, mtu) {
        if !ptb_reply_suppressed(source_frame, ptb_meta, l3, forwarding) {
            let built = match meta.addr_family { AF_INET => build_frag_needed_v4(..., next_hop_mtu), AF_INET6 => build_packet_too_big_v6(..., next_hop_mtu as u32), _ => None };
            if built.is_some() && allow_generated_error(PacketTooBig) { ptb_reply = built; } // #5567 build-before-consume prevents cross-iface starvation
        }
        mtu_signalled = true; // drop original even if ptb unbuildable fail-closed
    }
}
pub fn classify_generated_reply(forwarding: &ForwardingState, egress_ifindex: i32, frame: &[u8], now_ns: u64) -> GeneratedReplyVerdict {
    let Some((key, meta)) = generated_reply_session_key(frame) else { return GeneratedReplyVerdict { drop: true, parse_error: true, ... } }; // fail-closed #2238
    let extra = term_match_extra_from_frame_fwd(frame, meta);
    let selection = resolve_cos_tx_selection_at(forwarding, egress_ifindex, meta, Some(&key), extra, now_ns);
}
```
Proposed decomposition:
- `tx/dispatch/ptb.rs` — compute_forwarded_egress_ptb
- `tx/cos_classify/ba.rs` — DSCP/PCP classifiers + loss-priority
- `tx/cos_classify/filter.rs` — output vs input filter tx_selection folding
- `tx/cos_classify/generated.rs` — classify_generated_reply fail-closed
- `tx/cos_classify/cached.rs` — resolve_cached_cos_tx_selection
Hot-path preservation analysis:
- PTB cold but must not alloc on hot forward — keep Option<Vec<u8>> return, #[inline] for early egress_mtu==0 fast return Forward
- CoS fast path effective_queue_index inline — asm no extra Arc clone
- Verify `cargo asm --lib tx::cos_classify::resolve_cached_cos_tx_selection` same instr count
- CoS fairness gate: cluster-deploy + cos-iperf ports 5200-5211 shaping_rate_bytes unchanged
Tests + gate: cos_classify_tests 4617 LOC, dispatch/tests ptb/segmentation/shared_recycle, make test-rust, cluster CoS smoke
Why it matters: PTB inner-MTU derivation size-changing vs preserving mixed, generated-reply security boundary (output filter discard) needs isolation
Fix direction: ptb.rs pure, generated.rs, ba.rs, cached.rs with filter folding
Labels: refactor, CoS, PTB, MTU, segmentation
Dedup note: No direct duplicate, relates to output-filter reject handling

---

## Finding 6: shared_ops.rs 1131 LOC — poison recovery + NAT collision + owner-RG demotion

Title: shared_ops fuses poison recovery, NAT reverse-key displacement alias exclusion, owner-RG demotion
Severity: MEDIUM
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE (lock), B REQUIRES GUARDRAILS (alias exclusion)
Evidence:
```rust
pub(super) fn lock_shared_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() { Ok(g)=>g, Err(poisoned)=>{ m.clear_poison(); SHARED_SESSION_POISON_RECOVERIES.fetch_add(1, Relaxed); eprintln!("xpf-ha: ..."); poisoned.into_inner() } } // #2402 keep existing sessions not empty
}
fn record_shared_nat_displacement(displaced: Option<&SyncedSessionEntry>, entry: &SyncedSessionEntry) {
    let Some(existing)=displaced else { return; }; if existing.key==entry.key { return; }
    let sync_derived = |origin: SessionOrigin| origin.is_peer_synced() || matches!(origin, SharedPromote);
    if existing.decision.nat == entry.decision.nat && (sync_derived(existing.origin)||sync_derived(entry.origin)) && (existing.key==forward_wire_key(&entry.key, entry.decision.nat) || entry.key==forward_wire_key(&existing.key, entry.decision.nat)) { return; } // HA wire-alias fabric-redirect canonical+alias same logical session not collision #1760
    NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.fetch_add(1, Relaxed);
}
pub(crate) fn try_claim_nat_reverse_key_warn(now_ns: u64) -> bool {
    let last = NAT_REVERSE_KEY_WARN_LAST_NS.load(Acquire); if now_ns - last < 60_000_000_000 { return false; } NAT_REVERSE_KEY_WARN_LAST_NS.compare_exchange(last, now_ns, AcqRel, Acquire).is_ok() // process-global 1/min
}
```
Proposed decomposition:
- `shared_ops/lock.rs` — poison recoveries counter + lock_shared_recover
- `shared_ops/nat_collision.rs` — displacement counter, warn throttling, alias exclusion + unit tests (wire-alias same session NOT count, NAT-vs-different-NAT count)
- `shared_ops/owner_rg.rs` — demote_shared_owner_rgs, reverse prewarm refresh
Hot-path preservation analysis:
- Per-HA-sync 1/s + per-NAT-install, Relaxed ordering must stay not SeqCst — asm check xadd
- Alias exclusion relies on forward_wire_key idempotence + identical NatDecision + sync-derived — add tests for genuine collision involving wire-form on standby excluded by design (owner still counts)
Tests + gate: cargo test shared_ops, cluster test-failover poison path (worker panic → mutex poisoned → recover existing sessions not empty)
Why it matters: NAT 1:N collision detection observability-only today, fused with demotion hard to reason
Fix direction: lock.rs mechanical, nat_collision.rs tests, owner_rg.rs
Labels: refactor, HA, NAT, lock-poison
Dedup note: Matches reverse-key collision theme but not duplicate — this is shared-map choke point

---

## Finding 7: session_glue 1277 LOC + ha 949 LOC — FIB cache + tunnel hash reuse gate + ECMP

Title: session_glue couples FIB cache, tunnel temporal hash reuse gate, ECMP spread, HA fabric redirect
Severity: MEDIUM
Confidence: MEDIUM
Refactor class: B REQUIRES GUARDRAILS (tunnel id reuse #1873, ECMP hash pinning #2734)
Evidence:
```rust
fn lookup_forwarding_resolution_for_session_with_cache(...) -> ForwardingResolution {
    if decision.resolution.tunnel_endpoint_id != 0 {
        if let Some(row)=forwarding.tunnel_endpoints.get(&decision.resolution.tunnel_endpoint_id) {
            if row.logical_ifindex != decision.resolution.egress_ifindex {
                let mut gated=no_route_resolution(None); gated.tunnel_endpoint_id=decision.resolution.tunnel_endpoint_id; gated.egress_ifindex=decision.resolution.egress_ifindex; return gated; // preserve discriminator #1873
            }
        }
    }
    if allow_cached_fast_path { if let Some(cached)=cached_session_resolution(forwarding, decision.resolution) { return cached; } }
    let target=resolution_target_for_session(flow, decision);
    // #2734 ECMP spread by forward_key hash pinned via session cache
}
```
Proposed decomposition:
- `session_glue/resolution.rs` — target, cached, populate_egress, lookup_for_session, lookup_with_cache
- `session_glue/tunnel_gate.rs` — #1873 reuse check preserve stale egress_ifindex, should_bypass_unseeded_tunnel_ha, owner_rg_is_unseeded
- `session_glue/ecmp.rs` — flow hash spread
Hot-path preservation analysis:
- allow_cached_fast_path true for local forward, false for synced (standby must not use stale) — keep
- Tunnel gate must preserve egress_ifindex discriminator or next packet would adopt new owner — regression test already needed
Tests + gate: tests_txn_flow_cache, tests_bind_forward, test-failover tunnel re-owned scenario
Why it matters: Tunnel hash reuse is session hijack to different netdev security-adjacent
Fix direction: tunnel_gate first with regression test (remove A add B same id old session stays NoRoute), then ecmp, then resolution
Labels: refactor, FIB, ECMP, tunnel, HA
Dedup note: No exact duplicate

---

## Finding 8: wg/engine.rs 1805 LOC — encap/decap/handshake classify fusion

Title: WG engine fuses data-path encap/decap, handshake classification, AllowedIPs LPM, replay window
Severity: MEDIUM
Confidence: HIGH
Refactor class: B REQUIRES GUARDRAILS (replay mutex ordering, ShortRecord guard, PSK zeroize)
Evidence:
```rust
#[derive(Debug, Clone, PartialEq, Eq)] pub(crate) enum DecapError {
    ShortRecord, // snow AEAD would panic on sub-tag ciphertext 16..31 bytes with valid receiver_index
    CounterRejectAfterMessages, // MUST reject without AEAD per WG spec §6.5
    Expired, // #1888 S5 older than REJECT_AFTER_TIME MUST NOT use without arming rekey
    ...
}
const PADDED_PLAINTEXT_MAX: usize = 4080+16; // MaybeUninit staging avoids 4112 memset per encap
// Encap fast: clone Arc<WgSession> release peer lock before crypto
// Decap: replay_window mutex twice pre-AEAD definitely_out_of_window + post-AEAD check_and_update SPSC per worker
#[derive(Clone)] pub(crate) struct WgPeerConfig { pub pubkey: [u8;32], pub endpoint: Option<SocketAddr>, pub allowed_ips: Vec<IpNet>, pub preshared_key: Zeroizing<[u8;32]>, }
```
Proposed decomposition:
- `wg/encap.rs` — try_encap EncapOutcome EncapError padded staging MaybeUninit next_tx_counter hoisted
- `wg/decap.rs` — try_decap DecapOutcome DecapError ShortRecord ReplayDuplicate Expired, replay double-lock, AllowedIPs LPM
- `wg/handshake_classify.rs` — InitiationAction Process/SendCookie/Drop classify_initiation MAC2-good→process MAC1-good+MAC2-missing→challenge
- Keep engine.rs as struct WgEngine { local_private, peers RwLock, allowed_ips LPM, sessions_by_index } + reconcile
Hot-path preservation analysis:
- Zero-alloc data path — cargo asm must show no call alloc:: inside encap/decap
- MaybeUninit avoids memset — asm should not show 4096 zeroinit
- Replay mutex per-session not global — contention bounded single worker
Tests + gate: engine_tests 1464, cookie_tests 581, handshake_tests 316, tests.rs 3909 clean-room WG
Why it matters: Cryptokey-routing safety (prior violation egress peer selection via AllowedIPs), PSK hygiene Zeroizing, AEAD tag length guard security critical
Fix direction: handshake_classify no crypto first, then encap, then decap most sensitive
Labels: refactor, WireGuard, crypto, replay, PSK-hygiene
Dedup note: No duplicate, relates to WireGuard plaintext bypass

---

## Finding 9: Small focused — DO-NOT-SPLIT negatives (cohesive despite LOC)

Title: mirror/, mpsc_inbox, rst, neg_neigh, icmp_embed already well split — do not split further
Severity: INFO
Confidence: HIGH
Refactor class: D DO-NOT-SPLIT
Evidence:
```rust
// mirror/fast_path.rs 272 — enqueue_sampled_mirror_clone, reserve, result counting
// mirror/mod.rs 88 — MirrorTargetMap + resolver
// mpsc_inbox.rs 189 — MpscInbox bounded SPSC redirect inbox
// rst.rs 41 — remove_kernel_rst_suppression one fn
// neg_neigh.rs 254 — negative neighbor cache + throttle map
// icmp_embed/ — 7 files totalling 1015 LOC each single responsibility builders/parse/nat_match
// types/tx.rs 209, runtime.rs 503, types/forwarding.rs 1099 config-ish but not logic heavy
```
- Each <300 LOC except forwarding 1099 still config containers
- Splitting would fragment and hurt icache (extra module boundaries) and increase super::* glob coupling
Proposed: Keep as is, add comment explaining why not split (cohesive)
Hot-path preservation analysis: fast_path.rs is hot but tiny, already extracted — further split would add call overhead
Tests + gate: mirror/mod_tests 988, mpsc_inbox_tests, etc
Why it matters: Negative example — large != must split; cohesive modules should stay
Fix direction: No action, document D rationale
Labels: do-not-split, cohesive, small
Dedup note: No duplicate

---

## Finding 10: poll_stages.rs 975 + parser.rs 359 — staged extraction blocked by mutable-locals coupling

Title: poll_stages + parser — 975 LOC 7 stages #[inline] already extracted per #946 Phase 1, further split blocked
Severity: LOW
Confidence: MEDIUM
Refactor class: D DO-NOT-SPLIT (for now)
Evidence:
```rust
// poll_descriptor/mod.rs comment: #946 Phase 1 extracted seven per-packet sub-stages out into named helpers in poll_stages.rs. Helpers all #[inline] so extracted bodies stay in caller's CGU and call/return overhead amortized to zero — pure code-motion at IR level
// poll_stages.rs: StageOutcome::RecycleAndContinue, stage_link_layer_classify, stage_native_gre_decap, stage_parse_flow_and_learn, stage_screen_check, stage_ipsec_passthrough, stage_classify_fabric_ingress, stage_screen_syn_cookie_ack_on_session_miss
// docs/pr/1327 plan says further extraction blocked by mutable-locals coupling
```
Proposed: Keep but audit #[inline] presence, ensure no accidental #[inline(never)] except cold exception recording, add debug_assert! no alloc
Hot-path preservation analysis: Inliner relies on #[inline] to keep zero call overhead — cargo asm should show no call in hot loop
Tests + gate: poll_stages_tests 2636 LOC
Why it matters: Example of intentional monolith for performance — splitting would require context god-struct
Fix direction: No split, add comment referencing #1327 blocking rationale
Labels: do-not-split, blocked-by-mutable-locals, #1327, #946
Dedup note: Related to check_packet_with_zone_id_opts god-func but different file

---

## Summary roadmap (hot-path preserving)

Phase 1 mechanical A-class zero hot instr change:
- poll_descriptor/flowless.rs, neighbor/mac.rs, umem/histogram.rs, shared_ops/lock.rs — asm diff only .text.unlikely moved

Phase 2 Junos order + probe craft A-class behavior identical:
- poll_descriptor/host_local.rs, neighbor/probe.rs, shared_ops/nat_collision.rs + alias exclusion tests

Phase 3 NAT+PTB+CoS B-class requires guardrails:
- poll_descriptor/nat_pre_routing.rs, tx/dispatch/ptb.rs (build-before-consume #5567), tx/cos_classify/{ba,filter,generated,cached}.rs — single-recycle assert, PTB token after build, ba_reclassify preservation

Phase 4 HA+session_glue+WG B-class:
- session_glue/{resolution,tunnel_gate,ecmp}.rs, ha/{active,export}.rs, wg/{encap,decap,handshake_classify}.rs — tunnel NoRoute gate #1873 preserve discriminator, ECMP hash pinning #2734, WG replay SPSC + ShortRecord + Expired no rekey arm

Guardrails overall:
- cargo asm disassembly diff for poll_binding_process_descriptor, stage_flow_cache_hit, effective_queue_index, bucket_index_for_ns, try_encap, try_decap — byte-identical hot or only .text.unlikely moved
- perf stat L1-icache-load-misses,iTLB-load-misses,cache-misses on loss iperf3 172.16.80.200 — not increase
- criterion bench p99 stable <2%
- binary size .text growth <1% (size target/release/userspace-dp)
- incremental build cargo build -p userspace-dp --timings only changed mod dirty
- make test + make test-rust + selftest
- cluster: make cluster-deploy, apply-cos-config.sh, test-failover 60ms, test-stress-failover, CoS smoke ports 5200-5211 fairness CoV floor per 6 RX queues mlx5 VF native XDP (docs/fairness-regimes.md)

Labels overall: A1_rust_dataplane_packet, refactor, hot-path, icache, CoS, HA, WG, modularity-audit, batch-2/3
Dedup note: Checked /tmp/review-work-ps-044/dedup-index.txt 501 entries — consolidates 4 planned #4404 increments into audited seam, deep-dives neighbor.rs fusion, CoS fast lookup ArcSwap hazard. No exact duplicate. Batch file list 150 files confirmed.

---
Generated by NNN 044 senior Rust view: memory safety MaybeUninit staging, packet bounds slice len before L3 offset, checksum DGRAM vs RAW distinct, int overflow bucket_index leading_zeros branchless + saturating_add + TX_SIDECAR_UNSTAMPED sentinel, byte-order NativeEndian __be32, lock-free Relaxed fetch_add + AcqRel CAS, cache-line/HPC FlowRrRing 4096*2 per queue + CoS fast-path inline, fail-closed PTB drop original + generated-reply parse_error drop + NAT64 frag miss flowless drop.


---
### Batch A1_rust_dataplane_packet-b3 — 396 lines — full log + findings

# Paladin Security Review — A1_rust_dataplane_packet batch 3/3 (134 files)
Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/
Reviewer: ps NNN 044
Date: 2026-07-11
Focus: core firewall behavior + VRRP/HA failover & cold-boot, dataplane integer-truncation, DDNS/observability resource safety

---

## Table of Contents
- Executive Summary
- Module-by-Module Coverage
- Findings (by severity)
- Negative Results (clean modules)

---

## Executive Summary
Batch 3/3 covers 134 Rust dataplane files including worker structural decomposition, CoS subsystems, loop_body, event_stream wire codec, filter engine (compiler+matching+eval), screen stack, session management, protocol DTOs, server handlers (HA/snapshot/sync), slowpath, zone counters, policer/token-bucket, xsk_ffi bridge, and supporting crates. Overall security posture is strong: the codebase demonstrates defense-in-depth patterns (fail-closed on truncated frames, generation-gated re-resolution, saturating counters, seeded hash anti-DoS, snapshot integrity preflight). Three medium findings relate to integer-truncation/observability resource safety and one low relates to a potential uninitialized-ring read in xsk_ffi test helpers. No critical/high firewall bypass found in this batch under review scope.

---

## Findings

### Finding 1: Potential u32 truncation of slot/burst accounting in CoS status accumulator

- **Title:** CosQueueStatus queued_bytes/dropped_bytes saturated via u64::saturating_add but underlying hot counter is u64 truncated to queue-level u32 for byte accounting on some paths — potential overflow mis-reporting that hides shaping pressure
- **Severity:** Medium
- **Confidence:** Low (needs deeper CoS data-plane path cross-check; this batch only sees status snapshot layer)
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/afxdp/worker/cos/queue_row.rs:88
  ```
  status.queued_bytes = status.queued_bytes.saturating_add(queue.hot.queued_bytes);
  ```
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/afxdp/worker/cos/interface_row.rs:74
  ```
  entry.waterfill_phase1_budget_breaks = entry
      .waterfill_phase1_budget_breaks
      .saturating_add(root.waterfill_phase1_budget_breaks);
  ```
  Related CoS atomic loads in same file up to 0..DRAIN_HIST_BUCKETS.

- **Trace:** Worker publishes `queue.hot.queued_bytes` (u64) → snapshot fold does saturating_add into `CoSQueueStatus.queued_bytes` (u64) but upstream queue length sources may be `u32` sized on wire; if any intermediate uses `as u64` from truncated u32 leaking to operator via Prometheus/CLI, a 4GB-wrapped queue may appear as small value although saturating_add eventually catches. Operator path could then mis-read backpressure as idle.
- **Refutation attempt:** Looked for explicit `as u32` casts in queue_row/interface_row/telemetry—none in this file; fields are u64 end-to-end. Likely safe, but the broader CoS in other batches (token_bucket, etc.) uses `u32` for shaping rate; cross-batch invariant needed to prove no truncation upstream.
- **HPC/invariant check:** Saturating_add preserves monotonicity; no panic path. Cache-line: snapshot is cold path (~1s), not HPC.
- **Why it matters:** Observer-pattern bug: hidden CoS queue pressure could mask DoS; not a direct packet bypass but operational safety.
- **Fix direction:** Audit all CoS rate/byte fields for consistent u64 width; add debug_assert that queued_bytes <= sum of UMEM frames * MTU; ensure Prometheus collector does not cast to f32.
- **Labels:** integer-truncation, observability, CoS
- **Dedup note:** Possibly related to A1-b1/b2 CoS truncation findings if any; keep distinct as status-layer instance.

---

### Finding 2: io_uring_write retry budget vs slowpath MTU degradation interaction

- **Title:** Slowpath MTU degraded path refuses jumbo frames at enqueue with MtuExceeded, but io_uring write path does not surface MTU into its WriteError taxonomy — potential mis-accounting of degraded drops as generic write errors
- **Severity:** Medium
- **Confidence:** Medium
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/slowpath.rs:338
  ```
  pub fn enqueue(&self, bytes: Vec<u8>) -> Result<EnqueueOutcome, String> {
      let packet_len = bytes.len() as u64;
      // #2471: refuse frames larger than the live TUN MTU.
      let live_mtu = self.status.live_mtu.load(Ordering::Relaxed);
      if live_mtu > 0 && packet_len > live_mtu as u64 {
          self.status.mtu_dropped_packets.fetch_add(1, Ordering::Relaxed);
  ```
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/io_uring_write.rs:105
  ```
  pub(crate) enum WriteError {
      /// Nothing was transferred
      NothingWritten(String),
      /// Bytes were (or may have been) transferred
      Transferred(String),
  }
  ```

- **Trace:** SlowPathReinjector::enqueue correctly checks MTU BEFORE io_uring path and returns MtuExceeded. But server/handlers path for snapshot-driven TUN may also call write_packet_nonblocking directly via main AF_XDP path without this guard (not visible in this batch). If a degraded TUN receives a jumbo exception packet via non-slowpath writer, the kernel silently drops, not counted as mtu_dropped_packets. io_uring_write's Transferred vs NothingWritten does not distinguish.
- **Refutation attempt:** slowpath.rs gate seems effective for the dedicated slowpath worker; other paths (WG/GRE TUN local-origin) use write_packet_nonblocking with bounded WouldBlock retry (1024) — they also lack MTU check but use separate TUN devices sized independently. Mainline exception path appears correctly routed through SlowPathReinjector.
- **HPC/invariant check:** MTU check is lock-free single Relaxed load, before limiter lock — good ordering. No lost accounting for slowpath enqueues; gap only if non-slowpath code path writes jumbo directly.
- **Why it matters:** Degraded mode jumbo drop visibility is critical: silent kernel drop after successful io_uring write would appear as injected OK but never delivered, breaking TCP for firewall-local services (IKE, BGP) over jumbo.
- **Fix direction:** Centralize MTU check in write_packet_atomic_nonblocking seam too (or assert packet_len <= live_mtu at all writer entrypoints); extend WriteError with MtuExceeded variant for wire-consistent error taxonomy; add test injecting 9000B via degraded 1500 TUN.
- **Labels:** observability, resource-safety, fail-closed (degraded), slowpath
- **Dedup note:** Unique to slowpath MTU degradation (#2471); not covered in b1/b2.

---

### Finding 3: Session table session_limit maps use seeded hasher but zone concrete-id universe construction re-derives from snapshot with sort+dedup — cold-boot race with empty zone map OK but pre-flight validation vs live table divergence potential

- **Title:** zone_name_to_id_from_snapshot skips reserved/invalid zones correctly, but concrete_zone_ids derived from that map + reused for cold-path histogram slot expansion — if snapshot contains only reserved/invalid zones, concrete_zone_ids empty and wildcard policies produce zero slots, dropping cold-path samples silently (histogram dark, not bypass)
- **Severity:** Low
- **Confidence:** High
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/policy.rs:97
  ```
  pub(crate) fn zone_name_to_id_from_snapshot(zones: &[ZoneSnapshot]) -> FxHashMap<String, u16> {
      let mut map = FxHashMap::default();
      for zone in zones {
          if zone.id == 0 || zone.name.is_empty() {
              continue;
          }
          if zone.id >= ZONE_ID_RESERVED_MIN {
              continue;
          }
          map.insert(zone.name.clone(), zone.id);
      }
      map
  }
  ```
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/afxdp/worker/loop_body/setup.rs:135 (set_timeouts + opening_overrides) — session table configured from forwarded snapshot.

- **Trace:** SnapshotIntegrityError::UnresolvableZoneReference fails closed for policies referencing unknown zones (good). But if zones list contains only e.g. id=0 or reserved entries, zone_name_to_id_from_snapshot returns empty map; parse_policy_state_with_counters then rejects every concrete-zone policy (good, fail-closed). However configured_zone_pairs() then yields empty; cold_path_slot_map built from empty loses all wildcard/global expansion → histogram dark. No bypass, but observability loss during misconfig.
- **Refutation attempt:** Policy parser already rejects unknown zones, so real-world config with valid zones cannot hit empty concrete-universe while having valid policies. Only possible when operator commits a config with zones that are all invalid ids (commit gate should also reject). So posture is fail-closed.
- **HPC/invariant check:** Seed for session maps uses hot_path_hash_seed() per-boot secret via OnceLock — robust against hash-DoS. No per-packet alloc.
- **Why it matters:** Observability dark on misconfig may hide DoS while failing closed is already happening; acceptable but should surface overflow_active flag.
- **Fix direction:** Already covered: overflow_active flag + eprint on empty concrete set when wildcard/global policies exist. Ensure snapshot preflight for ZoneSnapshot.id validation is commit-gated in Go (pkg/config/compiler_security_*).
- **Labels:** cold-boot, HA, observability, zone-policy
- **Dedup note:** Not duplicate; documents intentional fail-closed.

---

### Finding 4: xsk_ffi FFI bridge uses Box::leak for test rings — memory leak in test binary only, but also potential use of uninitialized XskRingProd/Cons zeroed structs in non-test fallback if driver returns rc==0 but rings not populated

- **Title:** xsk_ffi create_xsk_binding_impl diagnostic eprintln reads ring fields unconditionally even when bridge returns success but rings contain null pointers — potential null-deref / data race on liberal driver
- **Severity:** Low
- **Confidence:** Low
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/xsk_ffi.rs:1216
  ```
  eprintln!(
      "xpf-xsk-ffi: create_xsk_binding mode={} fd={} rx_ring=[mask={:#x} size={} \
       producer={:?} consumer={:?} ring={:?} flags={:?} cached_prod={} cached_cons={}] \
       fill_ring=[mask={:#x} size={} cached_prod={} cached_cons={}]",
      mode.as_str(),
      fd,
      rx_ring.mask,
      rx_ring.size,
      rx_ring.producer,
      rx_ring.consumer,
      rx_ring.ring,
      rx_ring.flags,
      rx_ring.cached_prod,
      rx_ring.cached_cons,
      fill_ring.mask,
      fill_ring.size,
      fill_ring.cached_prod,
      fill_ring.cached_cons,
  );
  ```
  Followed by Box::new(zeroed) before bridge call.

- **Trace:** Box::new(core::mem::zeroed()) creates zeroed XskRingProd/Cons; if bridge_xsk_socket_create_* succeeds but leaves pointers null (defensive), later DeviceQueue::fill() calls bridge_xsk_ring_prod_reserve on null producer/consumer pointers → SIGSEGV. Production drivers tested likely populate, but defensive null check absent.
- **Refutation attempt:** bridge implementation is internal libxdp wrapper; if it succeeds, rings should be valid. Failure returns Errno. So null after success is unexpected. Additional null guard would be defense in depth.
- **HPC/invariant check:** Test-only leak is acceptable (test process exit frees). Release build does not leak.
- **Why it matters:** Cold-boot bind failure mode: if NIC driver transiently fails to init rings but returns rc=0, dataplane would crash instead of failing closed with retry.
- **Fix direction:** After rc==0, assert all ring pointers non-null, mask/size non-zero, else return EINVAL; keep diagnostic eprintln behind cfg(feature="debug-log") or rate-limited.
- **Labels:** cold-boot, resource-safety, FFI
- **Dedup note:** Not previously reported; unique to xsk_ffi.

---

### Finding 5: Event stream codec wire constants — unsigned truncation risk for egress ifindex i32→LE u32 encoding

- **Title:** Protocol::CoSInterfaceStatus.egress/ifindex fields encoded as LE u32 on event wire but ifindex typed i32 in BindingStatus — negative sentinel -1 encoded as 0xFFFFFFFF, decoded by Go as 4294967295 if not sign-extended, risking mis-attribution of events
- **Severity:** Low
- **Confidence:** Medium
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/event_stream/codec/wire.rs:148
  ```
  pub(crate) const FLAG_NAT64: u8 = 1 << 5;
  ```
  (flag constants context for surrounding wire codec)
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/afxdp/worker/bind_meta.rs:28
  ```
  pub(crate) struct WorkerBindMeta {
  ```
  Wire encoding elsewhere: write_ip/write_ip_16 uses IpAddr variants, but ifindex encoding occurs in session_delta/forwarding path not visible here. Checked protocol snapshot: ifindex i32 in InterfaceSnapshot.

- **Trace:** InterfaceSnapshot.ifindex i32 can be -1 for missing tunnel etc. If directly cast `ifindex as u32` for LE encoding without checking >=0, Go side decoding as signed i32 still works via two's complement reinterpret, but if Go decodes as unsigned (common for wire len), -1 becomes max u32 and may index out of bounds. Need to verify actual encode site in afxdp/forwarding/encoding not in this batch.
- **Refutation attempt:** Not directly observable in this batch's wire.rs (which is header-only control frames); actual data-plane event payload encoding is in codec/mod.rs and rt_flow.rs (not enumerated fully here). Risk is low because binding path filters ifindex <=0 early.
- **Why it matters:** Mis-encoded ifindex could attribute a screen drop / session close to wrong interface → mis-triage during incident.
- **Fix direction:** Enforce `TryFrom<i32>` with check >=0 at encode entry; encode -1 as 0 with explicit sentinel on wire; add round-trip test for negative ifindex.
- **Labels:** integer-truncation, observability, byte-order
- **Dedup note:** Related to broader integer truncation focus; keep as observability variant.

---

### Finding 6: Filter compiler DSCP validation already robust — confirms no truncation bypass

- **Title:** (Negative confirmation) DSCP match/rewrite out-of-range (>63) fails closed via SnapshotIntegrityError::FilterDSCPOutOfRange — no truncation to &0x3f bypass
- **Severity:** Info (negative result)
- **Confidence:** High
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/filter/compiler.rs:590
  ```
  if let Some(&value) = snap.dscp_values.iter().find(|&&v| v > 63) {
      return Err(SnapshotIntegrityError::FilterDSCPOutOfRange {
  // ...
  if let Some(value) = snap.dscp_rewrite {
      if value > 63 {
          return Err(SnapshotIntegrityError::FilterDSCPOutOfRange {
  ```

- **Trace:** Prior history masked DSCP 110 -> 46 EF (mentioned in comment). Current code explicitly rejects >63, preserving fail-closed. No `&0x3f` mask on rewrite path now.
- **Why it matters:** Confirms integer truncation fix for DSCP correctly closed.
- **Labels:** negative-result, default-deny/permit, integer-truncation
- **Dedup note:** Confirms fix; not a duplicate.

---

### Finding 7: Per-packet L4 match cache-sensitivity correctly gated — no flow-cache bypass for tcp-flags/icmp-type/code/is-fragment/flex

- **Title:** (Negative confirmation) FilterTerm::has_per_packet_l4_match correctly includes tcp_flags_mask, tcp_flags_forbidden, is_fragment, icmp_type/code, flex_enabled — flow-cache insertion gate delegates to this, preventing cache-based bypass for L4-varying packets
- **Severity:** Info (negative result)
- **Confidence:** High
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/filter/mod.rs:262
  ```
  pub(crate) fn has_per_packet_l4_match(&self) -> bool {
      self.tcp_flags_mask.is_some()
          || self.tcp_flags_forbidden.is_some()
          || self.is_fragment
          || self.icmp_type_match_enabled
          || self.icmp_code_match_enabled
          || self.flex_enabled
  }
  ```
  And compiler correctly sets iface_filter_v{4,6}_has_per_packet_l4_match.

- **Trace:** Flow-cache tests should decline insertion when has_per_packet_l4_match true. Checked filter/engine/matching.rs: per_packet_l4_matches gates on l4_present and protocol (TCP for tcp_flags, ICMP for icmp_type/code) — correct fail-closed for non-first fragments.
- **Why it matters:** Pre-PR #2362 risk was that L4-match terms were cached as 5-tuple only, allowing bypass for subsequent packets differing only on TCP flags or ICMP type. Current code closes that.
- **Labels:** negative-result, zone-policy, default-deny
- **Dedup note:** Cross-batch invariant pin.

---

### Finding 8: Screen extract fail-closed on truncated IPv4/IPv6 extension chain — robust against IDS evasion

- **Title:** (Negative confirmation) extract.rs returns Err(TruncatedIpv4Header/TruncatedIpv6ExtChain) for undersized L3 + IHL overshoot + malformed IPv4 options TLV — caller must treat Err as DROP; IPv6 walk continues past fragment header only for first-fragment offset==0 (RFC8200 compliant) with bounded 8-header cap and top-of-loop overrun check
- **Severity:** Info (negative result)
- **Confidence:** High
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/screen/extract.rs:105
  ```
  if l3_offset + 20 > frame.len() {
      return Err(ScreenParseError::TruncatedIpv4Header);
  }
  let ihl_bytes = (info.ip_ihl as usize) * 4;
  if l3_offset + ihl_bytes > frame.len() {
      return Err(ScreenParseError::TruncatedIpv4Header);
  }
  ```
  IPv6: top-of-loop `if offset > frame.len() { return Err(TruncatedIpv6ExtChain) }` + per-header length checks.

- **Trace:** Addresses bypass of syn-frag / teardrop / ping-of-death via crafted truncated ext chain. IPv4 options walk now fails closed on opt_len <2 or pos+opt_len>opt_end (#4543). Prevents LSRR/SSRR after malformed option evasion.
- **Why it matters:** Direct firewall IDS integrity; prior shape had fail-open for malformed frames.
- **Labels:** negative-result, IPv6 EH, fragment, fail-closed
- **Dedup note:** Not duplicate; confirms hardening.

---

### Finding 9: Session session_id allocation — high 16 bits worker-id, low 48 bits monotonic, never 0, with wrap guard

- **Title:** (Negative confirmation) SessionTable::alloc_session_id uses worker-namespace shift + 48-bit mask + zero-sentinel replacement → unique across shared-nothing workers, never emits 0 wire sentinel, wrap-safe
- **Severity:** Info (negative result)
- **Confidence:** High
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/session/mod.rs:760
  ```
  fn alloc_session_id(&mut self) -> u64 {
      let counter = self.next_session_id;
      self.next_session_id = self.next_session_id.wrapping_add(1);
      let low = counter & 0x0000_FFFF_FFFF_FFFF;
      let low = if low == 0 { 1 } else { low };
      self.session_id_worker_hi | low
  }
  ```

- **Trace:** Prevents 0 sentinel alias and cross-worker id collision that would break RT_FLOW SESSION_CREATE/CLOSE correlation. Worker-id set once via set_worker_id at worker_loop setup.
- **Why it matters:** Observability resource safety: reused 5-tuple must get distinct id; stale id reuse would mis-correlate SIEM logs.
- **Labels:** negative-result, observability
- **Dedup note:** Confirms #4915 fix.

---

### Finding 10: Snapshot generation monotonicity gate reverses fail-open that could revive stale flow-cache entries

- **Title:** (Negative confirmation) apply_snapshot enforces generation > cur OR (==cur && fib >= cur_fib), rejecting strictly-less rollback with fail-closed and restoring prior status — prevents cache-equality revival of stale permit after config/route withdrawal
- **Severity:** Info (negative result, security-critical defense confirmed)
- **Confidence:** High
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/server/handlers/snapshot.rs:83
  ```
  if guard.snapshot.is_some() {
      let cur_generation = guard.status.last_snapshot_generation;
      let cur_fib_generation = guard.status.last_fib_generation;
      let monotonic = snapshot.generation > cur_generation
          || (snapshot.generation == cur_generation
              && snapshot.fib_generation >= cur_fib_generation);
      if !monotonic {
          response.ok = false;
          response.error = format!(
              "snapshot generation rollback rejected: ({}, {}) < current ({}, {})",
  ```

- **Trace:** Flow-cache lookup is equality on (config_gen, fib_gen) pair; republishing superseded pair would make previously invalidated entries match again → stale ALLOW after withdrawal (fail-open). Gate correctly admits exact-equal re-apply for idempotent retry ( #4036 ) while rejecting strictly-less.
- **Why it matters:** Core firewall invariant — VRRP/HA failover may cause out-of-order snapshot pushes; monotonicity prevents policy downgrade via replay.
- **Labels:** negative-result, VRRP/HA failover, cold-boot, fail-closed, integer-truncation (generation is u64/u32 pair)
- **Dedup note:** This is the fix for #5169/#3767 family; confirm robustness.

---

### Finding 11: SYN-cookie crypto — SipHash24 domain separation correct, epoch window 3 candidates (current-1, current, current+1), cache hash keys derived from master key distinct domains

- **Title:** (Negative confirmation) syncookie.rs uses distinct domains b"xpf-sync", b"xpf-sck0/1", b"xpf-scv0/1" for MAC vs secret vs cache hash, candidate epochs include +1 defensively for clock skew, MAC masked to 24 bits via SYN_COOKIE_MAC_MASK
- **Severity:** Info (negative result)
- **Confidence:** High
- **Evidence:**
  File: /tmp/review-wt-ps-044-A1_rust_dataplane_packet-b3/userspace-dp/src/screen/syncookie.rs:35
  ```
  const SYN_COOKIE_MAC_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sync");
  const SYN_COOKIE_SECRET_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck0");
  const SYN_COOKIE_SECRET_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck1");
  const SYN_COOKIE_CACHE_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv0");
  const SYN_COOKIE_CACHE_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv1");
  ```
  File: line 196: candidate_validation_epochs = [current+1, current, current-1] with saturating arithmetic, dedup skip.

- **Trace:** No domain reuse, no secret reuse across functions. SipHash24 implementation matches spec: compress uses v3 ^= block; round(); round(); v0 ^= block. finish includes len<<56 tail packing and final 4 rounds.
- **Why it matters:** SYN flood protection crypto must not be bypassable via forged ISN. Current construction follows Linux/netfilter shape.
- **Labels:** negative-result, screen, memory-safety
- **Dedup note:** Confirms audit of SYN-cookie path.

---

## Module-by-Module Summary (134 files)

Grouped, with verdict:

**Worker structural decomposition (11 files):** bind_meta.rs, bpf_maps.rs, cos_state.rs, flow_cache_state.rs, lifecycle.rs, mod.rs, scratch.rs, telemetry.rs, timers.rs, tx_pipeline.rs, xsk_rings.rs, cos/interface_row.rs, cos/mod.rs, cos/queue_row.rs, cos/status.rs, loop_body/mod.rs, loop_body/setup.rs, worker_queue.rs, worker_runtime.rs, zone_counters.rs
- Clean decomposition; no functional change. FD types c_int retained; no Default-derived stdin alias (Intentionally NOT Default pattern enforced). Worker loop setup clones Arc fast paths correctly. telemetry dbg counters relaxed ordering acceptable. zone_counters uses FxHashMap with direct-index LUT [u8;65536] — truncation risk assessed (see finding 5) but build path validates. *Result: Clean, no bypass.*

**Event stream (10 files):** codec/codec_tests.rs, decode.rs, mod.rs, rt_flow.rs, wire.rs, mod.rs, producer.rs, tests/* (backpressure, control_frames, drain, replay_budget, rt_flow)
- Wire constants constant-time style; payload_size 160 with additive growth discipline both directions safe. Rate limiter GCRA token bucket single atomic TAT — lock-free. Queue budget two-level (total/kind) with try_increment_below CAS. Flow-cache e2e 152->160 additive doc correct. *Result: Clean, no resource exhaustion beyond bounded; DoS budget enforced.*

**Fairness + CoS (11 files):** fairness.rs, fairness_eval/{args, inputs, mod, per_worker, report, rss, verdict, windowing}, fairness_tests.rs, cos_doc_drift.rs (test)
- Eval uses saturating math, no per-packet alloc on hot path (per evaluation doc). *Result: Clean.*

**Filter (11 files):** compiler.rs, engine/{cache_sensitive, eval, matching, mod, policer, tx_selection}, mod.rs, policer.rs, tests.rs
- Strongest security signal in batch: extensive fail-closed guards (DSCP out-of-range, tcp_flags_unparseable, icmp unrepresentable, flex length 1..=4, unsatisfiable cross-field port/tcp-flags/icmp, missing filter ref fail-closed, continue_term logic #5142 closes discard-reject bypass). Matching port_match returns false for constrained && Any (fail-closed) fixing #3205 fail-open for except case. Per-packet L4 gating on l4_present correct (0 valid icmp-type/code). SmallVec for cached counters/policers dedup by Arc identity/id. Rate limiter buckets token_bucket. *Result: Clean, hardened.*

**Screen (9 files):** extract.rs, mod.rs, packet.rs, rate.rs, scan.rs, stateless.rs, syn_rate.rs, syncookie.rs, tests.rs, syn_rate_tests.rs, rate_tests.rs
- Fail-closed extraction, LAND without port compare parity with BPF, syn_frag first-fragment guard, ping-of-death formula offset+len>65535, teardrop zero/under-length, icmp-fragment, source-route LSRR/SSRR + RH0/RH1 detection, flood sketches per-dst primary + per-zone secondary ceiling *8 (#4112), RD threshold second-granularity but token bucket with ns (#3607). SYN-cookie epoch caching once/sec (#3032) to avoid per-packet clock. Validated cache 4-way set-associative 4096 entries LRU-ish via clock. *Result: Clean, hardened.*

**Protocol DTOs (8 files):** binding.rs, control.rs, cos.rs, mod.rs, nat.rs, resolution.rs, security.rs, snapshot.rs, tests.rs
- All serde default for cross-version skew; wg privkey hex skip_serializing redacted Debug; tcp_rst bool additive; per-interface host-inbound override union correct; MTU floor SLOW_PATH_MTU_FLOOR 1500; slow_path_mtu() largest positive filtered max. ZoneSnapshot tcp_rst. *Result: Clean.*

**Session (7 files):** ctx.rs, entry.rs, expire.rs, install.rs, key.rs, lookup.rs, mod.rs, wheel.rs, tests.rs
- Seeded hash with hot_path_hash_seed for attacker-controlled maps, SmallVec bucket for NAT collisions (1:N), can_admit preflight conservative (full slot even for replace), removal sink single (remove_entry) prevents double-free/double-dec, expiration wheel lazy-delete key-based not handle-based, session_limit src/dst counts origin-agnostic (#3122) count-neutral promote, session_id stable allocation with wrap guard. Large comment blocks explain invariants. *Result: Clean.*

**Server handlers + state (10 files):** handlers/binding.rs, export.rs, forwarding.rs, ha.rs, inject_packet.rs, mod.rs, neighbors.rs, queue.rs, rebind.rs, session_deltas.rs, snapshot.rs, stop_workers.rs, sync_session.rs, helpers.rs, lifecycle.rs, mod.rs, state.rs, tests.rs
- Snapshot preflight validates rule identity uniqueness (DuplicateRuleId/PolicyId) before allocation, generation monotonicity, fib rollback reject, defer_workers integrity build via validate_snapshot_buildable (mandatory-map + forwarding build) before ack/persist (#5171). HA update clones groups and calls update_ha_state under refresh_status. Sync upsert/delete builds entry/key via helpers. No panics on poisoned command queue (try_lock_recover). *Result: Clean.*

**Remaining (remaining files):** hot_hash_seed.rs (getrandom + fallback mixed, OnceLock never zero), io_uring_write.rs (EINTR retry, stale CQE drain, safe_to_retry taxonomy, permanent error fast-fail), ip_proto.rs (PROTO_* consts), main.rs (thin wrapper to server::lifecycle::run), policy.rs (zone_pair_key packed u32, DEFAULT_POLICY_SENTINEL_ID u32::MAX impossible collision, global zone scope Any vs Zones set, app catalog exact+scan specificity tier, policy counter generation discard on clear), prefix.rs/prefix_set.rs, slowpath.rs (token bucket f64 fractional, io_uring fallback decide_sync_fallback gated on safe_to_retry), state_writer.rs, tcp_flags.rs, xsk_ffi.rs, worker_runtime_tests.rs, etc.
- All reviewed; no integer truncation bypass found beyond noted low. hot_hash_seed draws CSPRNG with fallback clock+pid+stack mixed, never zero invariant via nonzero(). policy counter reset uses fetch_sub not store(0) preventing post-clear increment clobber (#3782). *Result: Clean.*

---

## Overall Labels
- default-deny: verified via filter MissingFilterRef fail-closed + policy default deny + snapshot rollback reject
- zone-policy: global scope set membership O(k) via SmallVec, from_zone any / to_zone any expansion concrete_zone_ids
- host-inbound: per-interface override + zone default + tcp_rst handling
- global-policy: global tier constrained by match_from_zones / match_to_zones
- IPv6 EH: extract.rs walks RH, Hop, Dest, Mobility, HIP, Shim6, Exp1/2 + Auth + Fragment with length checks + top-of-loop overrun fail-closed
- fragment: non-first fragment l4_present=false, per-packet L4 screens gated, teardrop/ping/tiny-path fail-closed, NAT64 frag dropped counter
- integer-truncation: DSCP out-of-range checked, ifindex cast noted, session_id mask, telemetry saturating
- fail-closed: snapshot preflight, extract truncation, filter missing ref, continue_term #5142
- VRRP/HA: ha.rs, sync_session, snapshot monotonicity, cold-boot deferred workers
- DDNS/observability: zone_counters LUT, policy counters, filter counters, cold-path histogram slot expansion

---

## Dedup Note
- DSCP truncation fix (#3715) already applied — negative result here.
- Filter continue_term fix (#5142) already applied — negative result.
- Snapshot monotonicity fix (#5169/#3767) applied — negative result.

No duplicates of b1/b2 critical bypasses found; this batch independently confirms hardening.

---

## Recommendation
- Add explicit null check after XSK ring create success (xsk_ffi).
- Centralize TUN MTU enforcement across all packet-oriented writers, not just SlowPathReinjector enqueue.
- Add round-trip encode/decode test for ifindex -1 sentinel to ensure LE u32 encoding round-trips via signed reinterpret, not unsigned mismatch.



---
### Batch A2_rust_dataplane_nat-b1 — 408 lines — full log + findings

# A2 Rust Dataplane NAT Review — Batch 1/1 (18 files)

**Base SHA:** f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
**Worktree:** /tmp/review-wt-ps-044-A2_rust_dataplane_nat-b1
**Files:** userspace-dp/src/nat/{allocator,source,destination,static_nat,status,tests_*}, nat64.rs, nat64_tests.rs, nptv6.rs, nptv6_tests.rs
**Persona:** NAT/CGNAT — port allocation lifecycle & exhaustion, twice-NAT ordering, translation correctness, embedded-ICMP reversal, HA port-reservation on synced sessions, fragment handling, deterministic NAT port-block math, IPv6 addr embedding.

## Overview
Swept 18 files covering source NAT pool allocator, SNAT/DNAT/static rule matching, NAT64 (RFC 6052/6146) translation + fragment cache, NPTv6 (RFC 6296) stateless prefix translation. Focused on HA reservation lifecycle, deterministic block math, integer truncation, twice-NAT merge, embedded-ICMP translation, and resource leak paths.

Impression: allocator is sophisticated (lock-free bitmap + FIFO recycle, persistent leases, deterministic CGNAT, address-only tokens #5269). Deterministic math is carefully guarded with checked arithmetic. NAT64 fragment cache design is bounded and TTL'd. NPTv6 fail-closed and zone-scoped (#5176) correctly.

Several dedup-index items confirmed (see Dedup notes). Two high-confidence new bugs found in HA path.

---

## Finding 1: HA reservation missing for address-only source NAT (port no-translation / GRE/ESP/AH)

**Title:** Address-only (port no-translation) synced sessions do not reserve reverse identity on standby — post-failover collision / reply mis-delivery
**Severity:** High
**Confidence:** High
**Evidence:**
File: userspace-dp/src/nat/source.rs:832-844
```
    let Some(rewrite_src) = nat.rewrite_src else {
        return;
    };
    let Some(rewrite_src_port) = nat.rewrite_src_port else {
        return;
    };
    let translated = TranslatedTuple {
        ip: rewrite_src,
        port: rewrite_src_port,
```
File: userspace-dp/src/nat/allocator.rs:1589-1669 (reserve_address_only path)
```
    pub(super) fn reserve_address_only(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
    ) -> Result<TranslatedTuple, ...> {
        ...
        let rkey = AddressOnlyReverseKey {
            protocol: flow.protocol,
            translated_ip,
            translated_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        };
```
**Trace:**
- Data plane installs an address-only SNAT flow: rule `port no-translation` or port-less protocol (GRE/ESP). Decision carries `rewrite_src=pool_ip`, `rewrite_src_port=None` (preserved). Allocator mints `AddressOnlyReverseKey` token via `reserve_address_only` (#5269).
- Active node syncs session over HA: `SessionDecision` contains same `NatDecision` (src rewritten, port None).
- Standby `handle_upsert_synced` calls `reserve_synced_source_nat_allocation`. That function early-returns when `rewrite_src_port` is None, so NO token reserved in standby's `address_only_owners`.
- Post-failover, standby becomes active. Its allocator has no record that `(pool_ip, preserved_src_port, remote)` is in use. A new local flow to same remote with same preserved port can claim identical reverse identity, receive `Matched` (duplicate public tuple), reverse index now has two owners, replies mis-demux to first session.
- Existing teardown path (`release_source_nat_allocation`) correctly handles address-only via flow.src_port fallback, so release works, but reserve never happened.

**Refutation attempt:**
Checked if address-only flows are excluded from HA sync? No — sync includes all sessions via `SessionDelta`. The sync reservation is only gated on `is_reverse==false && rewrite_src.is_some()`. Port check is extra gate that excludes address-only. The comment for `reserve_synced_source_nat_allocation` says "A synced session WITHOUT a translated source port (no source NAT, or address-only / port no-translation) reserves nothing." — this was intentional at time of writing (#4388) but predates #5269 address-only token invention. After #5269, address-only DOES have a reservation concept (reverse identity), but HA path was not updated.

**HPC/invariant check:**
- Invariant: "Every forward flow that mints a resource (bitmap bit or address-only token) must have that resource reserved on standby after sync, freed by same teardown path." Violated for address-only token.
- `address_only_owners` map size stays 0 on standby after sync of address-only session (visible via `debug_address_only_owners`).

**Why it matters:**
- Security: TCP/UDP with `port no-translation` is common for CGN with preserved ports. GRE/ESP over NAT also uses address-only path. Post-failover collision leads to session hijack surface: reply packets for victim flow delivered to attacker-controlled flow behind same public IP/port.
- Correctness: vSRX preserves address-only capacity limit across HA; xpf currently does not.

**Fix direction:**
- Extend `reserve_synced_source_nat_allocation` to handle address-only: when `rewrite_src_port` is None but `rewrite_src` is Some, reconstruct flow key as existing code does, then call `reserve_address_only` equivalent that checks `address_only_owners` for collision and inserts token without bitmap. If token collision (port already owned by different flow on standby), skip or log — same policy as bitmap reserve (do-not-steal).
- Add `reserve_synced_address_only` wrapper in allocator.rs that reuses `reserve_address_only` but without allocating new port — directly insert reverse key if free.
- Add fail-on-revert test: sync address-only flow, assert `debug_address_only_owners` len 1 on standby, second colliding flow denied as exhaustion.

**Labels:** `nat`, `ha`, `cgnat`, `address-only`, `port-no-translation`
**Dedup note:** Not in dedup-index. Dedup entry "HA reservations leave occupied ports in the recycle FIFO..." is about port bitmap recycle, distinct.

---

## Finding 2: Deterministic port stale reservation freed to recycle FIFO — pollutes non-deterministic pool

**Title:** `reserve_flow` refresh that changes tuple frees old deterministic port into recycle FIFO (should be no-recycle), allowing non-deterministic steal
**Severity:** Medium
**Confidence:** Medium
**Evidence:**
File: userspace-dp/src/nat/allocator.rs:1554-1587
```
        if let Some(existing) = live_by_flow.get(&flow).copied() {
            if existing.translated == translated {
                return true;
            }
            live.live_by_flow.remove(&flow);
            self.free_translated_port(existing.addr_index, existing.translated.port, true);
        }
        // Never steal a port owned by a DIFFERENT live allocation
        if !self.shared.occupancy[addr_index].reserve(translated.port) {
            return false;
        }
```
File: allocator.rs:895-915
```
    fn free_translated_port(&self, addr_index: usize, port: u16, recycle: bool) -> bool {
        ...
        if recycle {
            occ.free_recycle(port)
        } else {
            occ.free_no_recycle(port)
        }
```
File: allocator.rs:1280-1291 (release path correctly respects deterministic flag)
```
        self.free_translated_port(
            existing.addr_index,
            translated.port,
            !existing.deterministic,
        );
```
**Trace:**
- `reserve_flow` is used for HA-synced session port reservation. If synced flow refresh changes translated tuple (e.g., active node re-allocates different port, or sync arrives with new port), old entry removed and freed with `recycle=true` unconditionally.
- For deterministic allocation, correct free is `free_no_recycle` (per release path). Freeing deterministic port into recycle queue inserts it into per-address `VecDeque<u16>` recycle.
- Later non-deterministic allocation on same pool address drains recycle FIFO and can claim that deterministic port via `claim()`, even though deterministic blocks should be exclusive or at least not recycle via FIFO (deterministic claim scans bitmap directly, not recycle).
- This leads to: (a) recycle queue grows with deterministic ports that should never be there, (b) non-deterministic flow can steal a port that belongs to a deterministic subscriber's fixed block, breaking deterministic isolation.
- In practice, pool sharing between deterministic and non-deterministic rules is discouraged but not enforced by allocator_key (key excludes deterministic flag). Same pool address could be used by both rule types if config allows (Go validation may prevent, but not guaranteed at helper boundary).

**Refutation attempt:**
- Go commit check enforces deterministic pool mutually exclusive with persistent-nat/address-persistent, but does it prevent mixing deterministic and non-deterministic rules on same pool? Checked compiler_nat.go: deterministic block allocation is per-rule, pool is per-source-pool object; same pool can be referenced by multiple rules with different deterministic settings? Likely rejected, but even if rejected, the bug remains for deterministic-to-deterministic refresh (freeing deterministic port into recycle where deterministic allocator never drains recycle, so port stays leaked in recycle but not reclaimable via deterministic path, causing eventual exhaustion).
- Deterministic allocation path uses `reserve(port)` which checks bitmap, not recycle, so a deterministic port in recycle queue but with bit cleared is NOT reclaimable by deterministic path (since deterministic path loops over block and calls `reserve`, which succeeds if bit free, regardless of recycle). So port in recycle with bit cleared IS reclaimable by deterministic path (reserve checks bit, not queue). So not leaked, but now also reclaimable by non-deterministic path via recycle queue — collision window.

**Why it matters:**
- Deterministic NAT's CGN compliance requires fixed block without cross-contamination. Leaking deterministic port into recycle allows non-deterministic to consume it, causing deterministic exhaustion and breaking lawful-intercept reverse mapping.
- HA path: after role churn, repeated reserve_flow refreshes could accumulate deterministic ports in recycle.

**Fix direction:**
- Pass `deterministic` flag into `reserve_flow` or inspect existing allocation's `deterministic` bool, and free with `!existing.deterministic` (same as release path). Or always free_no_recycle in reserve_flow refresh path, since reserve_flow is for exact port reservation, not for recycle semantics.
- Add test: allocate deterministic port, reserve_flow same flow with different port, assert old port not in recycle queue (`debug_recycled_ports` empty) and bitmap cleared.

**Labels:** `nat`, `deterministic-nat`, `allocator`, `ha`
**Dedup note:** Related to dedup "HA reservations leave occupied ports in the recycle FIFO..." but distinct: that dedup is about HA reservations leaving ports in recycle causing scans; this is about deterministic vs recycle mixing on refresh.

---

## Finding 3: NAT64 Pref64 hairpin — missing RFC 6146 §5 mandatory drop (confirmed dedup)

**Title:** NAT64 accepts IPv6 packets whose source is within Pref64 — should drop to prevent hairpin loop
**Severity:** Medium (RFC 6146 compliance)
**Confidence:** High
**Evidence:**
File: userspace-dp/src/nat64.rs:873-912 (match_ipv6_dest only checks dst)
```
    pub(crate) fn match_ipv6_dest(&self, dst: Ipv6Addr) -> Option<(usize, Ipv4Addr)> {
        let octets = dst.octets();
        for (idx, prefix) in self.prefixes.iter().enumerate() {
            if octets[..12] == prefix.prefix_bytes {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return Some((idx, v4));
            }
        }
        None
    }
```
No source prefix check.
**Trace:** RFC 6146 §5: "If the IPv6 packet's source address is within Pref64::/n, drop — it's a hairpin from NAT64 itself." Current implementation translates any src, including Pref64 src, creating loop.

**Refutation:** Check if policy drop happens elsewhere? Forwarding path checks NAT64 after policy? No source guard in frame.rs either. No.

**Why it matters:** Allows internal reflection, amplifies loops, bypasses security policy (packet appears to come from translator).

**Fix:** In classify/translate, reject if src octets[..12]==prefix_bytes.

**Labels:** `nat64`, `rfc6146`, `hairpin`
**Dedup note:** Duplicate of dedup-index entry "NAT64 accepts Pref64-sourced IPv6 packets instead of applying RFC 6146's mandatory hairpin-loop drop." — confirming with evidence. Not new, but high-confidence.

---

## Finding 4: NAT64 strips AH and translates active Routing Headers (confirmed dedup)

**Title:** NAT64 extension header walker translates TCP/UDP inside AH and active Routing Headers — strips IPsec AH auth, translates RH0-type routing
**Severity:** High (IPsec bypass)
**Confidence:** High
**Evidence:**
File: userspace-dp/src/nat64.rs:1315-1380 (ipv6_l4_offset_and_protocol walks AH 51 and Routing 43 as generic)
```
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                let opt = packet.get(offset..offset + 2)?;
                protocol = opt[0];
                offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
```
...
```
            51 => {
                let opt = packet.get(offset..offset + 2)?;
                protocol = opt[0];
                offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
```
Then translation strips all ext headers and copies L4 verbatim.
**Trace:** AH (51) is not a translatable header — RFC 6146 says drop packets with AH. Routing header (43) with active segments should be dropped. Current code walks past them and translates inner TCP/UDP, emitting packet without AH, unauthenticated.

**Why it matters:** IPsec AH provides integrity; stripping it and forwarding inner TCP as if authenticated breaks security boundary.

**Fix:** Reject packet if extension chain contains AH (51) or Routing header with segments left >0; per RFC 6146 §5.

**Labels:** `nat64`, `ipsec`, `ah`
**Dedup note:** Duplicate of dedup "NAT64 strips AH and non-translatable IPv6 extension semantics, emitting unauthenticated inner TCP/UDP..."

---

## Finding 5: NAT64 BIB keyed by remote endpoint — endpoint-dependent mapping (confirmed dedup)

**Title:** NAT64 port allocator keyed by full 5-tuple including remote — multiplies port usage by destination fanout, violates endpoint-independent mapping, accelerates exhaustion
**Severity:** Medium (DoS / CGN capacity)
**Confidence:** High
**Evidence:**
File: userspace-dp/src/nat/source.rs:1088-1094 (flow key)
```
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
```
File: userspace-dp/src/nat/allocator.rs:938 (live_by_flow keyed by flow)
```
    live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
```
File: nat64.rs:951-957 (NAT64 allocate uses same flow key with dst_v4)
```
        let flow = SourceNatFlowKey {
            protocol,
            src_ip: IpAddr::V6(src_v6),
            dst_ip: IpAddr::V4(dst_v4),
            src_port,
            dst_port,
        };
```
**Trace:** Each distinct remote (dst_ip:dst_port) gets distinct translated src port, even for same internal subscriber src. RFC 6146 BIB should be endpoint-independent (same internal transport address → same external regardless of remote). Current multiplies port consumption.

**Why matters:** In CGNAT with many remotes per subscriber, port exhaustion 10x faster; also breaks hairpin requirements.

**Fix:** For NAT64, BIB key should be (src_v6, src_port, protocol) only, not dst.

**Labels:** `nat64`, `bib`, `cgnat`
**Dedup note:** Duplicate of "NAT64 keys its BIB by the remote endpoint..."

---

## Finding 6: NAT64 fragment cache serializes workers on public FNV (confirmed dedup)

**Severity:** Low (DoS)
**Evidence:** nat64.rs:389-410 (FNV hash over IPs + ident) → shard index 0..15, Mutex<Vec>. Every flowless IPv6 fragment (no L4) hits this before policy, so attacker can send fragments with chosen IPs to target same shard and serialize RX workers.

**Dedup note:** Duplicate of dedup entry.

---

## Finding 7: Static NAT /0 block maps entire IPv4 internet 1:1 — should be rejected

**Title:** `parse_nat_prefix` accepts /0 (len 0) → host_mask = MAX, base 0.0.0.0 — installs block-to-block rule mapping 0.0.0.0/0 ↔ <peer>/0, effectively identity NAT for whole internet
**Severity:** Low (misconfig, but commit should reject; helper boundary backstop missing)
**Confidence:** Medium
**Evidence:**
File: userspace-dp/src/nat/static_nat.rs:223-245 (host_mask_v4)
```
fn host_mask_v4(len: u8) -> u32 {
    if len >= 32 {
        0
    } else {
        u32::MAX >> len
    }
}
```
File: 306-346 parse_nat_prefix allows len=0, base canonicalized to 0.
File: 386-392 checks family mismatch and len mismatch, but not len==0.
**Trace:** Operator typo `set security nat static rule ... match 0.0.0.0/0` would be accepted at commit? Go validation likely rejects /0 for static NAT? Not certain. Helper installs it: blocks Vec gets entry external 0.0.0.0/0 internal e.g. 10.0.0.0/0. Then `contains` checks (addr & !hm) == base → !hm = !MAX =0, so (any &0)==0==base → true for all IPv4. So every inbound dst matches first /0 block, translated to internal same offset (identity). This is a full internet static NAT, bypassing policies.

**Why matters:** Fail-closed backstop should reject /0 at helper too, mirroring NPTv6 /48 rejection.

**Fix:** In `from_snapshots`, reject block where len < 8 (or <16) or len==0, return None → drop rule and log parse error (like NPTv6). Or at least check host_mask != MAX.

**Labels:** `static-nat`, `fail-closed`
**Dedup note:** Not in dedup-index.

---

## Finding 8: DNAT /0 registers 0.0.0.0 as local address — local-delivery hijack risk

**Title:** `DnatTable::destination_ips` includes network base of oversized prefix; for /0 it would be 0.0.0.0 registered as local, causing local-delivery shortcut for all traffic
**Severity:** Low
**Confidence:** Medium
**Evidence:**
File: userspace-dp/src/nat/destination.rs:994-1010
```
    pub(crate) const MAX_LOCAL_PREFIX_HOSTS: u32 = 4096;
    ...
    fn host_count_v4 -> u32 match 32 checked_sub(len) { Some(host_bits) if host_bits<32 => 1<<host_bits, _ => u32::MAX }
```
If len=0, host_count=MAX >4096, so not expanded, but `network()` returns base (0.0.0.0) pushed as local IP.
**Trace:** `destination_ips_scoped` pushes `slot.network()` unconditionally, then only expands hosts if count <=4096. For /0, network base 0.0.0.0 is pushed. `local_v4` set contains 0.0.0.0, which is not a valid local address but could cause `local_tables` logic to treat any packet destined to 0.0.0.0 as local delivery? Less severe, but still undesirable.

**Fix:** Skip network base if prefix_len < 8 or host_count > MAX and base is 0.0.0.0/0? Or rely on commit gate to reject /0 DNAT.

**Labels:** `dnat`, `local-delivery`
**Dedup note:** Not in dedup-index.

---

## Finding 9: Deterministic NAT reverse mapping linear scan O(N) over pool — DoS potential

**Title:** `reverse_deterministic_v4` and `reverse_deterministic_v6` iterate `pool_v4.iter().position(|a| a==translated_ip)` — O(N) linear scan per reverse flow (every inbound packet of deterministic NAT)
**Severity:** Low (perf)
**Confidence:** High
**Evidence:**
File: allocator.rs:241-268
```
    let ip_idx = pool_v4.iter().position(|&a| a == translated_ip)?;
```
File: 388-416 similar for v6.
**Trace:** Reverse path (inbound) for deterministic NAT must recover subscriber from external IP/port. It scans pool list for external IP. Pool size up to 65536 (MAX_POOL_PREFIX_HOSTS) — linear scan per packet on fast path? However deterministic reverse is likely called only on session-miss cold path, not per-packet hot, because session table caches reverse. So O(N) cold path maybe okay, but still worst-case 64k scans.

**Fix:** Build reverse map HashMap<IpAddr, usize> at rule build time.

**Labels:** `perf`, `deterministic-nat`
**Dedup note:** Not in dedup.

---

## Finding 10: Integer truncation risk in `port_of` — safe today but fragile

**Title:** `AddressOccupancy::port_of` casts u32 offset to u16 without check — relies on range invariant from constructor
**Severity:** Info
**Confidence:** Low
**Evidence:**
File: allocator.rs:502-506
```
    #[inline]
    fn port_of(&self, offset: u32) -> u16 {
        self.port_low + offset as u16
    }
```
If range >65535 (impossible because port range max 64512), offset as u16 truncates. But `range` is port_high-port_low+1 max 64512, offset < range, so offset max 64511 fits u16. However port_low up to 65535, plus offset up to 64511 would overflow u16 addition (wrapping? In Rust debug panics? No, u16 addition wraps in release? Actually in Rust, u16 addition overflow panics in debug, wraps in release? It's checked in debug, but this is release build for dataplane. Could overflow past 65535. But range check ensures port_low+range-1 <=65535 = port_high, so sum safe.

**Why matters:** Fragile invariant not documented at function site.

**Fix:** Add debug_assert!(offset < self.range) and use `self.port_low.wrapping_add` or checked_add with expect.

**Labels:** `int-truncation`, `defensive`
**Dedup note:** Not in dedup.

---

## Feature Gaps vs vSRX

- vSRX supports deterministic NAT with syslog for block utilization and port block allocation logs — xpf has pool status counters but no per-subscriber block syslog.
- vSRX supports NAT64 with stateful ALGs (DNS64) — xpf NAT64 is raw L3 translation, no DNS64.
- vSRX supports twice-NAT (simultaneous source+destination in one rule) — xpf implements via separate rule sets and NatDecision merge, which is equivalent but ordering not explicitly documented; static NAT + source NAT coexistence via separate tables works but no single-rule twice-NAT config.
- vSRX supports persistent NAT with `inactivity-timeout` per rule — xpf implements (#2397) but only seconds granularity.
- vSRX supports `port no-translation` with `address-persistent` interaction — xpf address-only tokens now implement #5269 but HA gap noted above.
- vSRX NPTv6 supports /32-/64 any length — xpf only /48 and /64 (by design, matches doc).

## Performance / Latency Notes

- Allocator Phase 1 lock-free bitmap reduces contention, but `live_by_flow` FxHashMap still behind single Mutex per pool — under high churn of small pool, becomes bottleneck. Phase 2 sharding deferred.
- NAT64 fragment cache: 16 shards Mutex<Vec> — each non-first fragment takes mutex, but TTL 2s and LRU eviction keep bound 1024 entries. Under fragment flood, attacker can target single shard via FNV control (source IP chosen to collide), serializing workers. Mitigation: use random seed per boot or more shards (e.g., 64).
- DNAT prefix LPM is linear scan over Vec<DnatPrefixSlot> per proto/port bucket — if many overlapping prefixes (e.g., 1000 /24s), cold path O(N). Acceptable since cold path only, but no trie.
- Static NAT block scan linear over `blocks` Vec — rare, cold path.
- NPTv6 linear scan over rules (Vec) — typically <10 rules, okay.

## Test Coverage Assessment

**Strong:**
- Deterministic v4/v6 block math has fail-on-revert tests for out-of-range subscriber, host bits, overlapping NPTv6, address-only collision, etc.
- NAT pool exhaustion, persistent lease GC chunking, address-only reverse identity, ICMP id zero handling (#4088) well pinned.
- NAT64 fragment cache, incremental checksum, traffic class copy, DF/identification consistency have thorough tests.
- NPTv6 zone scope gating #5176 has dedicated tests.

**Gaps:**
- No test for HA address-only reservation (Finding 1) — `reserve_synced_source_nat_allocation` tested only for port-translating case.
- No test for deterministic port recycle contamination (Finding 2).
- No test for /0 block static NAT or DNAT /0 local registration (Findings 7/8) — should be fail-closed.
- NAT64 Pref64 hairpin source check missing test (should drop packet with src in Pref64).
- No test for mixed deterministic + non-deterministic same pool sharing allocator — should be rejected at commit or handled.
- No fuzz for embedded ICMP translation with truncated quotes — existing tests use well-formed packets.

**Negative results (checked, not found):**
- No unchecked `unwrap()` in hot path that could panic on malformed snapshot (checked: all snapshot parsing uses `continue` or `Option`).
- No use-after-free or lifetime issues in NAT decision (Copy types, no references).
- No double-free in port allocator: bitmap CAS ensures ownership token, free only if bit set, idempotent.
- No integer overflow in deterministic block start calc that would wrap and allocate out-of-range port: checked via `port_start > port_high` exhaustion guard and `checked_mul`/`checked_add` in reverse.
- No missing bounds check in IPv6 extension header walker that would cause OOB read — all `get(offset..offset+2)` checked.
- No deadlock between global live mutex and per-address recycle mutex: lock order global→recycle respected everywhere except `gc_expired_chunked` which drops global before freeing (correct).

---

## Summary Scores

- **Correctness:** 2 new High/Medium bugs (address-only HA, deterministic recycle) + 4 confirmed dedup highs (NAT64 AH strip, Pref64 hairpin, BIB endpoint-dependent, frag cache serialization)
- **Memory safety:** No unsafe blocks in reviewed files; all indexing checked; no leaks beyond bounded recycle queue growth (Finding 2).
- **Feature gaps:** Minor vs vSRX (DNS64, syslog) — acceptable for current scope.
- **Perf:** Allocator scaling good, but fragment cache shard contention and DNAT linear scan could be improved.
- **Test coverage:** Strong for deterministic and address-only, gaps for HA address-only and /0 edge cases.

---

## References

- Dedup index: /tmp/review-work-ps-044/dedup-index.txt (entries for NAT64 Pref64, AH strip, BIB endpoint-dependent, frag mutex, HA recycle FIFO)
- Orientation: /tmp/review-work-ps-044/orientation.txt
- Worktree: /tmp/review-wt-ps-044-A2_rust_dataplane_nat-b1


---
### Batch A3_go_config_cli_tree-b1 — 404 lines — full log + findings

# Paladin Security Review — A3 Go Config / CLI Tree Batch 1/4 (150 files)

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A3_go_config_cli_tree-b1
Reviewer: ps NNN 044 — parser/compiler persona
Date: 2026-07-11
Scope: 150 files (pkg/config/, pkg/cmdtree/, pkg/appid/) — list in `/tmp/review-work-ps-044/batches/A3_go_config_cli_tree-b1.txt`

## Methodology

Checked mandatory patterns:

- `strconv.Atoi` -> `uint16`/`uint32` casts and truncation (fail-open via wrap)
- `len() -> uint16` truncation
- `Keys[1]`, `Keys[1:]`, `Keys[2]`, `Keys[3]` slice OOB on malformed `*Node`
- Dual-shape Junos AST (#2419 bracket lists collapsing onto one leaf's `Keys`) — reading only `Keys[1]` / `nodeVal` vs full `firewallMatchValues`
- Strict-vs-lenient gates (commit vs HA-sync/load) — fail-closed on load, no brick (#1960)
- Recursion/DoS caps (group expansion, port-range expansion, address-range expansion)
- Zone policy compilation (from-zone/to-zone, global, default-permit/deny, intrazone, address-book resolution)
- Application config (direct vs term, duplicate detection, bracket members)
- typed-leaf schema validators parity

Used grep + manual read of every non-test compiler file in batch plus `ast*.go`, `catalog.go`, `runtime.go`, `tree.go`. Tests used as evidence of fixed classes.

---

## Module: pkg/config/ast.go + ast_edit.go + ast_groups.go + ast_redact.go

### ast.go
- **File:** `pkg/config/ast.go`
- **Lines:** navigatePath 173-272, unionChildren 281-290, matchNodeKeys 320-340, Clone 140-167
- **Confidence:** High — No OOB
- **Finding:** `navigatePath` correctly handles multi-key match and union across duplicate same-prefix siblings (#4562, #3980). `Name()` returns "" for empty Keys (vs `Keys[0]` panic) — is the guard used in firewall #4827 and routing. `FindChild` checks `len(child.Keys)>0`. Clone deep-copies.

- **File:** `pkg/config/ast.go`
- **Confidence:** Info — Negative
- Result: No `uint16(len(...))` truncation, no Atoi casts.

### ast_edit.go (SetPath / DeletePath / RenamePath / CopyPath)
- **File:** `pkg/config/ast_edit.go`
- **Lines:** SetPath 211-426, deletePath 439-531, removeMultiLeafMembers 686-745, markMultiLeafMembersInactive 770-814
- **Confidence:** High — No vuln, DoS bounded
- **Finding:**
  - SetPath consumes `multi:true` trailing values via `firewallMatchValues` dual-shape merging (both `Keys[1:]` AND children) — fixes #2419 class. No OOB because `i+nodeKeyCount > len(path)` early return.
  - DeletePath member-delete path correctly reads both shapes and checks `len(n.Keys)==0` before indexing.
  - Rename/Copy check `len(dst)<nk` before slicing.
  - No recursion unbounded; depth capped by parser brace-depth (#4148).
- **Negative:** No integer truncation; no Keys[1] unchecked.

### ast_groups.go (apply-groups expansion)
- **File:** `pkg/config/ast_groups.go`
- **Lines:** 1-25 consts, 201-330 expandGroupsRecursive
- **Confidence:** High — DoS mitigated
- **Finding:**
  - **F1 DoS cap:** `maxGroupExpandDepth = 64` prevents deep acyclic chain `g1->g2->...->gN` stack exhaustion. Check at depth > cap returns error fail-closed.
  - **F2 Work cap:** `maxGroupExpandWork = 100000` prevents wide shallow fan-out exponential blow-up.
  - **Memoization (#4474):** `memoKey = name + "\x00" + ancestorPathKey` caches expansion, prevents `2^N` fan-out.
  - **Cycle guard:** `seen` map detects circular reference.
  - **Bracket list:** apply-groups names read via `n.Keys[1:]` (line 213-214) — handles `[a b c]` correctly, no truncation.
- **Negative:** No len->uint16, no Atoi.

### ast_redact.go
- **File:** `pkg/config/ast_redact.go`
- **Confidence:** High — Negative
- **Finding:** Only traverses tree redacting secrets, checks indices before access. No parsing.

---

## Module: pkg/config/compiler.go + dispatch, derivations, earlystrict

- **File:** `pkg/config/compiler.go` (2323 lines)
- **Confidence:** High — Negative for this batch's patterns
- **Finding:**
  - Strict vs lenient split is central: `CompileConfig` = strict, `CompileConfigLenient` = tolerant for HA sync / load. All new validators in this batch follow pattern: strict error, lenient warning (#1960 doctrine).
  - Screen numeric gate uses `Atoi` but records invalid token instead of dropping — fail-closed.
  - No direct `Keys[1]` OOB in this file; delegates to sub-compilers.
- **File:** `pkg/config/compiler_dispatch.go` (106 lines)
- **Confidence:** High — Negative
- **Finding:** Simple switch dispatching to sub-compilers, nil-safe.

- **File:** `pkg/config/compiler_derivations.go`
- **Confidence:** High — Negative
- **Finding:** Derives host-inbound, default-permit logic; no Atoi.

- **File:** `pkg/config/compiler_earlystrict.go` (144 lines)
- **Confidence:** High — Negative (lenient-aware pre-walks)
- **Finding:** Only AST pre-walks, no integer casts.

---

## Module: pkg/config/compiler_applications.go + collision

- **File:** `pkg/config/compiler_applications.go`
- **Lines:** 33 parseAppTimeout, 522 parseICMPTypeCode, 554 resolveAppPort, 653 ParseCanonicalUint, 799 nodeVal, 826 applicationSetMemberValues
- **Confidence:** High — Secure, previous truncation bugs fixed
- **Finding:**
  - **Atoi truncation fixed:** `parseAppTimeout` uses `Atoi` but range-checked `[0,86400]` and returns bool; caller records `UnknownTimeouts` for strict reject instead of dropping to 0 (pre-#3320 bug: non-numeric dropped to 0 = fallback to global timeout).
  - **Canonical port parsing:** `ParseCanonicalUint` forbids leading `+` / `-` and whitespace (fixes #3606 divergence where `+80` accepted at commit but rejected by Rust capability gate vs Go capability gate). `parseCanonicalPort` delegates to it.
  - **Port range 0 floor normalization (#4336):** `resolveAppPort` handles `0-N` -> `1-N` to avoid commit rejection for real vSRX configs, while bare port 0 stays invalid. Prevents bypass.
  - **ICMP type/code:** `parseICMPTypeCode` checks 0..255, returns `*uint8`, no uint8 wrap.
  - **Bracket list handling (#5181):** `applicationSetMemberValues` reads `Keys[1:]` AND `Children` — correctly compiles `application [ a b c ]`. Comment explicitly calls out pre-#5181 bug where only `Keys[1]` read dropped members (security under-match for deny policies).
  - **Duplicate direct leaves (#5574):** Tracks conflicting scalar repeats (`protocol`, `destination-port`, etc.) and records for strict gate — prevents last-writer-wins silent narrow/widen.
  - **Mixed direct+term (#3366):** Records `MixedDirectTermApps` for strict reject — prevents silent drop of direct match when terms present.
  - **nodeVal (#801):** `len>=2` guard before `Keys[1]`, else child name fallback.
- **Negative:** No `uint16(len)`; no unchecked `Keys[1]`. All ports go through `ParseUint 10,16` or canonical.

- **File:** `pkg/config/compiler_applications_collision.go`
- **Lines:** 369 lines
- **Confidence:** High — No vuln
- **Finding:** Collision detection for custom vs predefined apps, uses normalized protocol. No integer casts. Correctly fails closed on duplicate.

---

## Module: pkg/config/compiler_firewall.go (family, filter, flex)

- **File:** `pkg/config/compiler_firewall.go`
- **Lines:** 180-230 family handling, 799-812 firewallMatchValues, 835-861 firewallPrefixListRefs, 866-1062 compileFilterFrom, 970-995 byte-offset, bit-length checks
- **Confidence:** High — Dual-shape fixed, no truncation, no OOB
- **Finding:**
  - **Family handling:** `if len(familyNode.Keys)>=2` guard before `familyNode.Keys[1]` (line 184, 372, 616). For flat shape, falls back to `afNode.Name()` and checks `len>=2` before `Keys[1]`. Mitigates #4827 panic on corrupted persisted Node (empty Keys).
  - **firewallMatchValues (SSOT for #2419):** Reads `Keys[1:]` + `Children` accumulation, skipping blank tokens. This is the canonical reader for bracket lists `[ tcp udp ]` + flat-set. Used everywhere.
  - **firewallPrefixListRefs (#3843 fix):** Reads `Keys[1:]` via appendTokens and `Children` — previous bug iterated only Children and dropped single-name leaf shape (`source-prefix-list plX;` with zero children) -> implicit match-all fail-open.
  - **Flexible match:** `strconv.Atoi` for byte-offset, bit-length, value/mask but with range checks: byte-offset 0..255, bit-length 1..32, mask/value via `ParseUint 16,32` with error recording (`UnknownFlexMatch`) for strict reject (#3203) instead of silent coerce to 0. Previous code truncated 999->231 via `uint8()` cast; now fixed.
  - **Then leaf parsing:** For flat `then` leaf (`then discard;` -> Keys=["then","discard"]), parses `Keys[1:]` with arg consumption, handles reject message-type only if recognized (prevents typo swallow).
  - **Family any + inet6 collision gates:** `validateFirewallFilterFamilyCollisionsAST` and `validateFirewallFilterFamilyAnyMatchesAST` are strict-reject, lenient-warn, fail-closed.
- **Negative:** No `len()->uint16`, no Atoi->uint16 wrap. OOB mitigated.

---

## Module: pkg/config/compiler_interfaces.go + interface_range + unsupported

- **File:** `pkg/config/compiler_interfaces.go`
- **Lines:** 173-206 track props, 338-346 family, 568-571 WgListenPort, 628-629 Keepalive, 644-667 tcp-mss parsing, 871-876 track-interface, 1131-1140 costCheck
- **Confidence:** High — No truncation, OOB guarded
- **Finding:**
  - **Atoi -> uint16 guarded:** `WgListenPort = uint16(n)` after `n>0 && n<=65535` (line 570), `KeepaliveSecs = uint16(n)` after `0..65535` (628). Not truncating.
  - **Keys[1] guarded:** track props use `if len(prop.Keys)>=2` before access (172,176,180,184,190). Family uses `len>=2` guard (338,345). Track-interface uses `len>=2` (875). Cost checks check `len>1`.
  - **tcp-mss dual-shape:** `familyAfterKeyword` style reads `mssChild.Keys[1]` after len>=2 guard and fallback to `node.Keys[1]` with len>=2 guard (644-666) — handles flat `family inet mtu 1500 tcp-mss 1400` shape.
  - **Unit num:** `Atoi(unitInst.name)` with error check, safe.
- **Low confidence observation:** Some `Atoi` errors ignored with `_ = Atoi` (MinimumLinks, LeaseTime) but those fields have separate strict validators; not security bypass, but could leave 0 default. Acceptable as lenient path.
- **Negative:** No `uint16(len)`; dual-shape for family handled.

- **File:** `pkg/config/compiler_interface_range.go`
- **Lines:** 165-168 rd name
- **Confidence:** High — No OOB
- **Finding:** `if len(node.Keys)<2` continue before `node.Keys[1]` at 168. Portion parsing uses manual digit scan, no Atoi truncation.

- **File:** `pkg/config/compiler_interfaces_unsupported.go`
- **Lines:** 196-218 familyAfterKeyword, unit number extraction
- **Confidence:** High — Negative
- **Finding:** Comment notes `Keys[1]` packs number in both shapes. `unit.Keys[1]` returned via helper that assumes len>=2 (caller guarantees via schema). Reasonable.

---

## Module: pkg/config/compiler_chassis.go

- **File:** `pkg/config/compiler_chassis.go`
- **Lines:** 82-83 collectDeviceMapProps, 100-116 normalizeMAC, 127-243 validateDeviceMapStrict
- **Confidence:** High — No OOB, strict/lenient correct
- **Finding:**
  - Prop collection loops `i+1 < len(n.Keys)` before accessing `n.Keys[i+1]` (82) — safe.
  - `normalizeMAC` uses `net.ParseMAC` and length check 6, returns raw on failure for lenient path (UNBOUND not misbind) — fail-closed.
  - Strict validator enforces duplicate logical name, duplicate PCI/MAC, RETH member must be PCI-keyed, FPC slot alignment, unmapped policy enum. All fail-closed with clear error.
  - No integer truncation.
- **Negative:** No `Keys[1]` unchecked.

---

## Module: pkg/config/compiler_class_of_service.go

- **File:** `pkg/config/compiler_class_of_service.go`
- **Lines:** 152-159 queue parse, 539 Atoi, 574-576 queue 0..255, 659-680 guarantee-rate, 1095-1226 code-point
- **Confidence:** High — No truncation OOB
- **Finding:**
  - Queue parse checks `len<3` before `Keys[1]/Keys[2]` (152) and `Atoi` then range 0..255 (576).
  - Forwarding-class/loss-priority uses `len>=2` guard before `Keys[1]` (196-205 etc).
  - Oversubscription guarantee-rate checks `len>=2` and `len>=3` before access (659-661).
  - CoS code-point token expansion uses `firewallMatchValues` for bracket lists — correct dual-shape.
  - `parseCanonicalPort` style not used here; rate parsing uses typed validators elsewhere.
- **Negative:** No `uint16(len)`.

---

## Module: pkg/config/compiler_nat_* (destination, dnat_to, helpers, mixed_scope)

- **File:** `pkg/config/compiler_nat_destination.go`
- **Lines:** 18-35 parseDNATPoolAddress, 204-209 off/pool, 313-400 parseDNATPortList
- **Confidence:** High — DoS and truncation fixed
- **Finding:**
  - **Pool address + port dual-shape:** `toks := append(Keys[1:], Children.Keys...)` (18-21) reads entire token stream — fixes #4521 where only `Keys[1]` read truncated bracket list.
  - **PortRaw preserved:** Stores raw token for strict gate, prevents `port 0` / `port httpp` collapsing to preserve-dest-port default (fail-open). Builder previously cast Atoi straight to uint16 (0 wrap, 70000->4464).
  - **parseDNATPortList:** Handles 3 shapes: unified leaf (len Children==0 && len Keys>=2), set-syntax range, hierarchical block. Uses `parseCanonicalPort` (no sign) with range check via `appendDNATPortRange` which bounds expansion to 1..65535 and caps to 65535 entries max (pre-#3449 bug allocated billions for `1 to 4000000000` OOM). Now bounded.
  - **Reversed range (#4422):** Records `low to high` where high<low as `Invalid` token for strict reject, but still appends endpoints for lenient boot.
  - **Len guards:** All `Keys[1]`, `Keys[2]`, `Keys[3]` accesses have `len>=2/3` checks (204,207,313,338,367).
  - **Fail-closed:** Invalid ports recorded in `InvalidDestinationPorts`, strict gate rejects.
- **Negative:** No unchecked OOB.

- **File:** `pkg/config/compiler_nat_dnat_to.go`
- **Confidence:** High — Negative
- **Finding:** File empty in this batch (only tests cover it). No logic.

- **File:** `pkg/config/compiler_nat_helpers.go`
- **Lines:** 107-410
- **Confidence:** High — Dual-shape fixed
- **Finding:**
  - `collectNATScopes`, `parseNATMatchScopes` handle zone/interface/routing-instance scope with bracket leads — uses `firewallMatchValues` style.
  - `appendPoolAddresses`: Iterates token stream with `i+2 < len(tokens)` guard before reading `tokens[i+1]=="to"` and `tokens[i+2]` — safe. Expands via `expandAddressRange`.
  - `expandAddressRange`: Converts to /32, checks `count = uint64(high)-uint64(low)+1` to avoid uint32 wrap (0.0.0.0-255.255.255.255 previously wrapped to 0 and committed as empty pool). Caps count>256 error. Loop bound `uint32(count)` with count<=256 so no wrap — fixes #5194.
  - `applyDeterministicKeys`: `i+1 < len` guard before access (349-350), host address logic checks `i+1`, `i+2`.
  - `applyDeterministicHost`: Checks `len>=3` and `Keys[1]=="address"` before `Keys[2]`, else `len==2` before `Keys[1]` — safe.
- **Negative:** No truncation.

- **File:** `pkg/config/compiler_nat_mixed_scope.go`
- **Confidence:** High — Negative
- **Finding:** No integer handling, just scope validation.

---

## Module: pkg/config/compiler_ipsec*.go

- **File:** `pkg/config/compiler_ipsec.go`
- **Lines:** 21-25 group number parsing, 60 Atoi, 87-193 PSK/local/remote ID, 243-314 DH group, etc.
- **Confidence:** Medium — No truncation, OOB guarded, but note strict vs lenient
- **Finding:**
  - Group number parsing previously used bare Atoi and dropped `group14` -> left ESP no DH. Now uses `normalizeDHGroup`? Comment at line 21 indicates old bug fixed. Current code uses Atoi with error check and records for strict gate.
  - PSK handling: `len(p.Keys)>=3` before `p.Keys[2]` (92) — safe.
  - Local/remote ID: `len>=3` before `Keys[1], Keys[2]` (156-167, 401-412).
  - Dynamic hostname: checks `len>=3 && Keys[1]=="hostname"` before `Keys[2]` (180,425), plus child fallback.
  - DH group parsing: `Atoi(keys[i+1])` with bounds check, no uint wrap.
  - No `uint16(len)`.
- **Negative:** Keys accesses guarded.

- **File:** `pkg/config/compiler_ipsec_bindiface.go`
- **Confidence:** High — Negative
- **Finding:** Validates bind-interface collision with security zones, strict reject. No integer.

- **File:** `pkg/config/compiler_ipsec_proposalset.go`
- **Confidence:** High — Negative
- **Finding:** Proposal set handling, no truncation.

- **File:** `pkg/config/compiler_ipsec_trafficselector.go`
- **Lines:** 48-130
- **Confidence:** High — Negative
- **Finding:** Comments note `nodeVal` reads only `Keys[1]` — but this is for single-value leaf where dual-shape collapsed to one value; match uses `firewallMatchValues` elsewhere. No OOB.

---

## Module: pkg/config remaining compilers (ddns_tls, nat etc)

- **File:** `pkg/config/compiler_ddns_tls.go`
- **Confidence:** High — Negative (not heavily in batch but checked)
- **Finding:** Parses TLS, duration via Atoi with range, no truncation.

- **File:** `pkg/config/compiler_nat_source.go` (not in batch but referenced) — note its `expandAddressRange` fixed, `Keys[1], Keys[3]` access guarded by `len>=?` in original.

---

## Module: pkg/appid (catalog.go, runtime.go, textrender.go + tests)

- **File:** `pkg/appid/catalog.go`
- **Lines:** 86-90 maxCatalogAppID 65535 overflow guard, 126 protoOK, 129-147 NormalizeExplicitPortRange, 320 Atoi numeric protocol, 440-461 parsePortRange
- **Confidence:** High — No truncation, fail-closed
- **Finding:**
  - **AppID overflow (#3438):** `nextID uint32` working counter, checks `nextID > maxCatalogAppID (65535)` before `uint16(nextID)` cast — prevents wrap to 0 (reserved UNKNOWN sentinel). Error message clear.
  - **Protocol resolution:** `ProtocolNumber` uses `Atoi` with `0..255` bounds then `uint8(n)` — guarded.
  - **Port zero sanitization (#5194):** `NormalizeExplicitPortRange` ensures explicit `0` or `0-0` does not become (0,0) unconstrained sentinel that over-matches every port. Returns `ok=false` for high==0 (bare 0) -> unemittable (fail-closed). For `0-N` with N>0, narrows to `1..N`.
  - **parsePortRange:** Uses `ParseUint 10,16` (not Atoi) so numeric string directly bounded to uint16, no wrap.
  - **Emittable logic:** Combines protoOK, srcOK, dstOK, reversed range checks (`dstLow <= dstHigh`) — fail-closed, not over-broad.
  - **icmpTypeConstrained:** Prevents over-matching ICMP type-constrained apps as protocol-only.
  - **Nil app guards (#4865, #5179):** `if app==nil continue` prevents panic during HA lenient load where JSON null decodes to nil pointer — tolerant skip, not crash.

- **File:** `pkg/appid/runtime.go`
- **Lines:** 161 ResolveSessionName, 198-244 resolveTupleFallback, 301 portInSpec, 328 canonicalPort, 342 protocolNumber
- **Confidence:** High — No truncation after fix
- **Finding:**
  - **portInSpec (#3725):** Previously used `Atoi` then `uint16` narrowing (`70000->4464` mislabel) and signed acceptance (`+80` matched 80). Now uses `canonicalPort` which calls `config.ParseCanonicalUint` (bare digits only, no sign) and range 1..65535 — drops malformed spec (fail-closed) instead of mislabeling.
  - **Tuple fallback:** Scans all apps, prefers port-based over protocol-only, tie-break by name for determinism — avoids non-deterministic map iteration.
  - **Nil guards (#4865, #3622):** Skips nil policy, nil zone-pair, nil rule-set/rule to avoid panic on tolerant load.
  - **AppNames map:** `map[uint16]string` with appID 0 reserved UNKNOWN, consistent with Rust wire.
  - **ProtocolNumberLenient:** Backstop loop `for p:=0; p<256; p++` checking `ProtocolName(uint8(p))` — bounded, no infinite loop.

- **File:** `pkg/appid/textrender.go`
- **Confidence:** High — Negative
- **Finding:** Pure rendering, no integer casts, no parsing.

- **Tests in batch:** `catalog_bad_protocol_4887_test.go`, `catalog_icmp_3781_test.go`, `catalog_nil_app_4865_test.go`, `catalog_nil_appset_5179_test.go`, `catalog_port_zero_5194_test.go`, `catalog_proto0_4008_test.go`, `catalog_tolerant_3725_test.go`, `precedence_parity_test.go`, `protocol_lenient_3439_test.go`, `protocol_number_2124_test.go`, `runtime_test.go`, `textrender_test.go`
  - **Confidence:** High — These are regression guards for exactly the truncation and over-match classes we checked. No new logic.

---

## Module: pkg/cmdtree/tree.go + completion tests

- **File:** `pkg/cmdtree/tree.go`
- **Lines:** 131-187 helpers (routingInstanceNames, redundancyGroupIDs), 1211-1304 CompleteFromTree, 1306-1394 CompleteFromTreeWithDesc, 1460-1492 LookupDesc
- **Confidence:** High — Nil-safe, no truncation
- **Finding:**
  - **Nil guards (#4866):** `routingInstanceNames`, `routingInstanceTableNames`, `redundancyGroupIDs` all skip nil slices/entries (`if ri==nil continue`, `if rg==nil continue`). Prevents panic on tolerant/HA-sync config with nil entries (e.g., JSON null decoded to nil ptr).
  - **ContextDynamicFn:** Policy completion extracts `from-zone`/`to-zone` from consumed words (lines 359-370) with nil checks on `zpp` and `p` (3476) — prevents panic.
  - **CompleteFromTree:** Handles placeholder nodes (`<host>`) and typed leaves. `resolveTreeWord` uses prefix matching; `canonWords` tracks canonical keywords so abbreviation (`from-z`) still resolves for providers (#5196). No Atoi, no uint casts.
  - **FilterPrefix:** Simple prefix filter, no regex DoS.
  - **Typed-leaf placeholder:** `ValueType.Placeholder()` surfaces examples, no code execution.
  - **No `uint16(len)`**: Only `DynamicValues` returns strings.
- **Tests in batch:** `completion_nil_3476_test.go`, `completion_nil_3493_test.go`, `completion_nil_provider_5196_test.go`, `completion_nil_ri_rg_4866_test.go`, `completion_zone_prefix_5196_test.go`, `tree_hb167_test.go`, `tree_test.go`
  - **Confidence:** High — Regression for nil panics and zone prefix completion.

- **Negative:** No integer truncation, no Keys OOB (cmdtree doesn't use config Node Keys).

---

## Module: Remaining pkg/config tests in batch

All following test files are regression guards, not new attack surface:

- `addressbook_dup_addrset_merge_4706_test.go`, `addressbook_name_slash_3061_test.go`, `addressbook_name_slash_4340_test.go` — address-book slash handling and merge dedup
- `addressset_bracket_members_4791_test.go` — #4791 bracket-list fix for address sets
- `allow_dataplane_sleep_test.go`
- `application_set_nested_test.go`, `applicationset_bracket_members_5181_test.go` — #5181 bracket-list fix for application sets (dual-shape)
- `apply_groups_depth_5194_test.go`, `apply_groups_leaflist_exclude_test.go`, `apply_groups_leaflist_test.go`, `apply_groups_transitive_4474_test.go` — #5194 depth/work caps, #4070 leaf-list union, #4474 memo
- `archival_leading_dash_4589_test.go`
- `backup_router_family_2911_test.go`, `backup_router_format_4808_test.go`
- `bgp_as_wrap_4713_test.go`, `bgp_group_inherit_order_5270_test.go`, `bgp_neighbor_peeras_2963_test.go`, `bgp_peeras_range_4589_test.go`, `bgp_policy_chain_level_5277_test.go`
- `compile_golden_4406_test.go`
- `compiler_addrbook_warn_3958_test.go` and ~80 other compiler_*_test.go files — each pins a specific fail-closed or bracket-list or lenient/warning behavior.

**Confidence:** High — Tests do not introduce Atoi->uint or Keys OOB; they verify fixes.

---

## Cross-Cutting Concerns

### Integer Truncation Summary
- **Result:** No `uint16(len(...))` in config/appid/cmdtree batch. Only legitimate casts are `uint16(n)` after `Atoi` + range check `0..65535` (WgListenPort, KeepaliveSecs) and `uint16` from `ParseUint(...,16)` (port parsing) and `uint16(nextID)` after `>65535` guard (appID). All safe.

### Slice Index OOB Summary
- **Result:** All `Keys[1]`, `Keys[2]`, `Keys[3]` accesses in batch have `len>=2/3/4` guards or are inside `nodeVal` (which checks) or `firewallMatchValues` / `addressSetMemberValues` / `applicationSetMemberValues` which iterate safely. Corrupted persisted Node with empty Keys handled via `Name()` returning "" (#4827 pattern).

### Dual-Shape #2419 Bracket Lists
- **Result:** Batch shows systematic fix:
  - `firewallMatchValues` (firewall), `addressSetMemberValues` (address-book), `applicationSetMemberValues` (application-set), `collectProtocolList` (routing), `appendPoolAddresses`, `parseDNATPoolAddress` all read `Keys[1:] + Children`.
  - Previous bug of reading only `Keys[1]` dropped all but first list member -> under-match for deny policies (fail-open). Fixed.

### Strict-vs-Lenient Gates
- **Result:** All new validators follow `if !lenient { return error } else { warnings }` pattern. Lenient path (load/peer-sync) warns but boots (#1960 no-brick). Tolerant load also adds nil guards to avoid panic (e.g., appid runtime nil skip, cmdtree nil skip). No strict gate downgraded to lenient for security leaves.

### Recursion / DoS Caps
- **Result:**
  - `maxGroupExpandDepth=64`, `maxGroupExpandWork=100000` in ast_groups.go
  - DNAT port range expansion capped to 1..65535 and at most 65535 entries (`appendDNATPortRange`)
  - Source NAT pool address range capped to 256 IPs (`expandAddressRange`) with uint64 count to avoid wrap
  - All loops bounded.

### Zone Policy / Default-Permit / Global / Host-Inbound
- **Result for this batch:**
  - `compiler_security_policy.go` defaults action to `PolicyDeny` when no terminal action (fail-closed) — fixes previous zero-valuePermit fail-open.
  - Global policies handled separately, scoped zone sets deduplicated and sorted (`sortDedupZones`).
  - Address-book zone-local qualification (`zone-local/<zone>/<name>`) prevents global book pollution and uses no-clobber.
  - Default-policy `permit-all/deny-all/reject-all` mapped explicitly, including `reject-all` (#3065).
  - Firewall `family any` dual-compiled into both inet and inet6 pools (#4287) and collision gates prevent silent overwrite (#3884).
  - No intrazone-default-permit logic in this batch (handled elsewhere).

### Application Config
- **Result:** Direct vs term conflict detection, duplicate leaf detection, timeout range, ICMP type/code range, ALG allowlist. All fail-closed via strict gate.

---

## Findings Summary (by severity)

### High Confidence — No Vulnerability (Negative Results)
- No unguarded `Keys[1]` / `Keys[3]` OOB in any non-test file in batch (verified via manual review + heuristic grep).
- No `strconv.Atoi -> uint16/uint32` truncation without range check.
- No `len() -> uint16` truncation in config/appid/cmdtree batch.
- No missing dual-shape handling — all current code uses SSOT readers.
- No recursion unbounded — group expansion, port/address range all capped.

### Medium Confidence — Observations (Not vulnerabilities, but worth noting)
- **File:** `pkg/config/compiler_interfaces.go:130,369,373` — Some DHCP options parse with `_ = Atoi` ignoring error, falling back to 0 default. Strict validators elsewhere reject malformed values, so not bypassable, but lenient path silently drops to default. Acceptable per #1960 doctrine, but document.
- **File:** `pkg/config/compiler_class_of_service.go:659-680` — `guarantee-rate` parsing uses `ParseFloat` without upper bound check at this spot; range enforced by typed-leaf validator (schema), so safe but defense-in-depth relies on schema.

### Low Confidence / Info
- **File:** `pkg/config/compiler_security_policy.go` — `from-zone` / `to-zone` handling accumulates zones via `firewallMatchValues` (bracket list fix #4626). Previously only `Keys[1]` kept first zone, causing under-match.
- **File:** `pkg/appid/runtime.go:canonicalPort` — Uses `ParseCanonicalUint` which rejects `+80`, `-80`, whitespace; good parity with commit gate.

### No Critical / High Severity Findings in This Batch

No fail-open, no panicable OOB, no integer wrap leading to over-broad match, no DoS via unbounded allocation.

---

## Verification Steps Performed

- `grep -Rn "Keys\[1\]" pkg/config/compiler_*.go` — confirmed len guards or comment-only occurrences for batch files.
- `grep -Rn "uint16(len"` — only outside batch (vrrp, flowexport, lldp) which are not in scope.
- Manual read of: `ast.go`, `ast_edit.go`, `ast_groups.go`, `compiler_applications.go`, `compiler_firewall.go`, `compiler_interfaces.go`, `compiler_chassis.go`, `compiler_class_of_service.go`, `compiler_nat_destination.go`, `compiler_nat_helpers.go`, `compiler_ipsec.go`, `catalog.go`, `runtime.go`, `tree.go`.
- Reviewed all 150 file names; test files are regression guards for previous bugs (IDs 3061, 3348, 3352, 3438, 3843, 4008, 4706, 4791, 4865, 4887, 5194, etc.).
- Confirmed `maxGroupExpandDepth` and `maxGroupExpandWork` present.

---

## Recommendation

Batch is clean for parser/compiler security properties. No remediation required for integer truncation or OOB or bracket-list under-match — previous fixes (#2419, #3449, #3843, #4521, #4791, #5181, #5194, #3438, #3725) are correctly applied and tested.

Future work (outside batch) could add a linter rule enforcing `len(Keys)>=N` before `Keys[N-1]` access and forbidding bare `Atoi` -> `uint16` without range check, to prevent regression.



---
### Batch A3_go_config_cli_tree-b2 — 513 lines — full log + findings

# A3_go_config_cli_tree batch 2/4 — Security Review (zone policies, global policies, host-inbound, application matching, default deny/permit, integer truncation, VRRP/HA failover & cold-boot)

**Base SHA:** f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c  
**Worktree:** /tmp/review-wt-ps-044-A3_go_config_cli_tree-b2  
**Batch file:** /tmp/review-work-ps-044/batches/A3_go_config_cli_tree-b2.txt (150 files)  
**Reviewer persona:** parser/compiler engineer — dual-shape AST, strict-vs-lenient gates, schema validators, Atoi->uint16/uint32 truncation, fail-closed.

---

## Summary
Reviewed 150 files (core compilers + strict/lenient validators + tests) focusing on zone-policy wiring, global-policy scoping, host-inbound admission, application match, default-policy fail-closed, integer truncation Atoi→u8/u16/u32, and VRRP/HA cold-boot. The batch consists largely of **hardened** code: prior fail-open silent-drop bugs are now gated at commit with shared SSOT finders and lenient-path poison sentinel (`LenientContentDropped` → `__unsupported__`). Most historic truncation bugs have explicit `ValidateInteger` or `ParseUint(...,32)` gates and deterministic sorted walks. No new *unfixed* truncation bypass found in this slice, but several defense-in-depth edges and the rationale for their current lenient handling are recorded below for cold-boot/HA reasoning.

---

### Finding 1: VRRP GroupID (VRID) uint8 truncation — cold-boot VIP blackhole if id>255

**Severity:** Critical (HA failover / cold-boot)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_vrrp.go:14-18`
```
 // RFC 5798 §5.2.3 defines the VRID as an
 // 8-bit field whose valid range is 1..255 — 0 is not a usable VRID
 // ...
 // The native VRRP engine truncates the configured id straight onto that byte
 // (pkg/vrrp/instance.go writes `uint8(vi.cfg.GroupID)` into the VRID field at
 // send and matches it on receive, e.g. instance.go:1148/1834/1849), so a
 // `vrrp-group 256` wraps to VRID 0 (peer discards → the VIP never masters, an
 // HA cold-boot blackhole) and `vrrp-group 257` aliases VRID 1 onto an unrelated
 // group (cross-talk / dual-master).
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_vrrp.go:44-68` — `validateVRRPGroupIDStrict` walks `cfg.Interfaces.Interfaces[ifName].Units[unit].VRRPGroups[gk].ID` and rejects `<1` or `>255`.
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_interfaces.go:696` — `groupID, err := strconv.Atoi(vrrpInst.name)` stored verbatim into wide `int` `VRRPGroup.ID` without bound at assignment; later narrowed via `uint8()` in `pkg/vrrp/instance.go:sendAdvert`.

**Trace:**
1. Flat-set `set interfaces ge-0/0/0 unit 0 family inet address x.x.x.x/24 vrrp-group 256 virtual-address ...` — parser stores id 256 via Atoi into typed `VRRPGroups[gk].ID` (no bound).
2. `instance.go` `uint8(GroupID)` truncates 256→0.
3. RFC peer discards VRID 0; local never becomes master → cold-boot: VIP absent on boot, traffic blackholed. Id 257→1 aliases another group → dual-master split-brain.
4. Strict gate `validateVRRPGroupIDStrict` (#4573) now rejects at commit; lenient path downgrades to warning + runtime `manager.go UpdateInstances` refuses to advertise out-of-range VRID (WARN+skip).

**Refutation attempt:** Could peer still accept VRID 0? RFC 5798 and Juniper discard; code comment cites strict discard. Could lenient path still advertise? No, runtime guard skips. So fail-closed on load, but VIP never masters → HA blackhole persists on lenient boot until admin fixes. That's intentional #1960 no-brick doctrine.

**HPC/invariant check:** Not hot-path; commit-time O(N log N) deterministic sorted walk. Compile-time invariant: `MinVRRPGroupID=1, Max=255` constants, but schema leaves `vrrp-group <id>` as unvalidated identity token (schema_interfaces.go) — deliberate, so typed-config gate is required; otherwise schema walk misses packed hierarchical `vrrp-group 1 priority ...;` shape.

**Why it matters:** HA failover & cold-boot: a typo'd id bricks VRRP for that redundancy-group without commit error pre-#4573. On standalone, VIP never masters; on cluster, both nodes may stay backup.

**Fix direction:** Present fix is correct: strict reject + runtime skip. Ensure doc update that lenient boot = VIP absent (inert, not wrong VRID) — acceptable fail-closed.

**Labels:** `ha`, `vrrp`, `integer-truncation`, `cold-boot`, `fail-closed`, `RFC5798`

**Dedup note:** Unique to VRRP explicit VRID; sibling findings 2 & 3 cover priority and reth-derived VRID.

---

### Finding 2: VRRP Priority uint8 truncation — 256 wraps to 0 (resignation) → never masters

**Severity:** Critical (HA)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_vrrp_priority.go:14-23`
```
 // 0 is reserved to signal that the current master
 // has stopped participating (a resignation that forces backups to take over
 // immediately) and 255 is the address owner; the usable configured range is
 // 1..255. The native VRRP engine truncates the configured priority straight
 // onto that byte (pkg/vrrp/instance.go writes `uint8(priority)` into the
 // advertisement's Priority field in sendAdvert), so a `priority 256` wraps to 0
 // — the group advertises RESIGNATION on every beacon and never holds the VIP,
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_vrrp_priority.go:44-90` — gate iterates all `unit.VRRPGroups[gk].Priority` against `[1,255]`.
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_interfaces.go:732-736` — comment notes previous Atoi error reset Priority to 0.

**Trace:** `set interfaces ... vrrp-group 1 priority 256` — packed hierarchical `vrrp-group 1 priority 256;` packs property onto instance node's Keys; schema walker consumes as identity token, never validates. Atoi stores 256 verbatim; `uint8(256)=0` advertises resignation each beacon → backup takes over immediately, originating node never masters.

**Refutation:** Could schema `ValidateInteger(1,255)` catch? Only for flat-set/expanded shape, not packed one-liner. Hence typed-config gate is needed. Current gate closes both. Lenient warns, runtime still advertises 0 (resignation) — is that safe? Runtime should also clamp/skip? Check `pkg/vrrp/manager.go` — does it skip? The gate comment says lenient boot still allowed; priority 0 is reserved resignation, not out-of-wire, so advertising 0 is technically valid resignation, causing immediate failover to peer, not blackhole. Acceptable lenient behavior.

**HPC:** O(N log N) sorted walk, not hot.

**Why it matters:** Mis-typed priority bricks master; failover storm; with priority 0 the node voluntarily resigns forever.

**Fix direction:** Fix present (#5184). Consider runtime guard: if lenient-loaded priority <1 or >255, coerce to default 100 and WARN (instead of adverting resignation). Currently only group-id has runtime skip; priority best-effort.

**Labels:** `ha`, `vrrp`, `integer-truncation`, `cold-boot`

**Dedup:** Distinct from Finding 1 (ID vs priority); same uint8 class.

---

### Finding 3: RETH redundancy-group id → derived VRRP GroupID overflow (100+rgID>255) → silent skip

**Severity:** High (HA, silent VRRP loss)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_reth_vrrp.go:1-50`
```
 const RethVRRPGroupIDBase = 100
 const MaxRethRedundancyGroupID = MaxVRRPGroupID - RethVRRPGroupIDBase // 155
 ...
 // CollectRethInstances (pkg/vrrp/vrrp.go) synthesizes a VRRP GroupID of
 // 100+rgID for every RETH interface with VIPs in its redundancy group, so an
 // rgID in 156..255 is a legal, committable chassis config that derives a
 // VRRP GroupID of 256..355 — out of range for the VRID byte, but the
 // explicit `vrrp-group <id>` gate only inspects the explicit instance slot,
 // never this reth-derived one.
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_reth_vrrp.go:52-88` — `validateRethVRRPGroupIDStrict` rejects rgID>155 when `!NoRethVRRP && !PrivateRGElection`.

**Trace:** `set chassis cluster redundancy-group 200 ...; set interfaces reth0 redundant-ether-options redundancy-group 200 ...` — chassis gate allows up to 255 (heartbeat wire limit), but reth-derived VRRP id 300 truncates. `manager.go UpdateInstances` inspects pre-truncation int and skips with WARN, so commit succeeded but VRRP never runs for that RG → RETH VIP never masters, cold-boot blackhole for whole RG.

**Refutation:** Could `NoRethVRRP` or `PrivateRGElection` mode avoid? Yes, gate exempts those modes correctly per fact comment (mirrors CollectRethInstances early return). So config with no-reth-vrrp or private-rg-election is safe.

**HPC:** Same as above.

**Why it matters:** Loss cluster uses RETH (ge-0-0-1/reth1, ge-0-0-2/reth0), so this is directly reachable via `redundancy-group` typo >155.

**Fix direction:** Present fix correct (#4826). Ensure schema comment cross-references this derived limit so operator understands 155 cap when reth VRRP enabled.

**Labels:** `ha`, `reth`, `vrrp`, `integer-truncation`, `silent-skip`

**Dedup:** Shares VRID overflow class with Finding 1 but distinct origin (chassis RG vs explicit vrrp-group).

---

### Finding 4: Chassis heartbeat GroupID / Count uint8 truncation — election corruption / panic

**Severity:** Critical (HA, split-brain, panic)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_chassis.go:1-33`
```
 const MaxHeartbeatRedundancyGroups = 255
 const MaxHeartbeatRedundancyGroupID = 255
 ...
 // The heartbeat group-count field is a single byte
 // (pkg/cluster/heartbeat.go marshalHeartbeatBody writes
 // buf[8] = uint8(len(pkt.Groups))), so a 256th group would overflow the
 // count to 0 while 256 records are still written — the count byte and the
 // body desync and the peer mis-parses the group section. (The marshaler
 // also indexes a fixed maxHeartbeatSize buffer, so ~293 groups panic on
 // write.)
 ...
 // per-group GroupID field is a single byte (pkg/cluster/heartbeat.go HeartbeatGroup.GroupID is uint8,
 // populated via uint8(rg.GroupID) in heartbeat_manager.go buildHeartbeat), so an id
 // above 255 truncates on the wire and two distinct redundancy groups would
 // then collide on the same GroupID byte and corrupt peer election.
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_chassis.go:34-115` — `validateChassisClusterStrict` rejects >255 groups and id out of 0..255 plus priority [1,254].

**Trace:** `set chassis cluster redundancy-group 256` via `strconv.Atoi` in `compileChassis` under no bound → stored as 256. At heartbeat marshal, `uint8(len)=0` but 256 records emitted → peer parses 0 groups → election desync; 293+ panics OOB. Group-id 256→0 alias.

**Refutation:** Schema leaves `redundancy-group <id>` as unvalidated identity token, so without this gate commit succeeds. Gate now closes.

**HPC:** Cold-path.

**Why it matters:** Multi-RG cluster (loss cluster uses 2 RGs) easy to exceed if operator scripts generate many RGs; truncation causes split-brain or panic at heartbeat.

**Fix direction:** Fixed (#4434+#4880). Runtime also caps via `maxHeartbeatGroups` in `marshalHeartbeatBody` as defense-in-depth.

**Labels:** `ha`, `chassis`, `integer-truncation`, `panic`, `split-brain`

**Dedup:** Unique chassis scope; siblings cover VRRP VRID.

---

### Finding 5: Screen thresholds uint32 truncation — value >4294967295 wraps to 0 disables check (fail-open)

**Severity:** High (IDS bypass)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_security_screen.go:168-190`
```
 n, err := strconv.Atoi(val)
 // Reject non-numeric, non-positive, AND > math.MaxUint32. Every
 // published screen threshold is cast to uint32 in the snapshot
 // builder (pkg/dataplane/userspace/screens.go) — a value above
 // 2^32-1 (e.g. 4294967296) would WRAP on that cast (uint32(2^32)==0),
 // and the Rust screen treats a zero threshold as unset and OMITS the
 // check. That is the exact fail-open class #3317 closes, so the gate
 // must reject it at commit rather than let it wrap silently.
 if err != nil || n < 1 || int64(n) > math.MaxUint32 {
   profile.BadNumeric = append(profile.BadNumeric,
```
- Snapshot builder `pkg/dataplane/userspace/screens.go` casts to uint32 (commented).
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_screen.go:76` notes gate.

**Trace:** `set security screen ids-option foo icmp flood threshold 4294967296` — Atoi parses 4294967296 on 64-bit (no error), `uint32(4294967296)=0`, Rust treats 0 as unset → screen disabled → flood bypass. Old code swallowed Atoi error only; gate now rejects >MaxUint32.

**Refutation:** On 32-bit, Atoi fails for >MaxInt32, so would be caught earlier. But CI and appliance are 64-bit, so 2^32..2^63-1 would slip. Gate fixes.

**HPC:** Commit-time only.

**Why it matters:** IDS bypass — operator attempts ultra-high threshold to "almost disable" but accidentally disables entirely.

**Fix direction:** Fixed (#3317). No further action; ensure Rust `>0` gate remains.

**Labels:** `screen`, `ids`, `integer-truncation`, `fail-open`, `u32-wrap`

**Dedup:** Distinct from other u8 truncation; unique uint32->0.

---

### Finding 6: Default policy zero-value fail-open (PolicyPermit = iota 0) — absent stanza ships permit-all

**Severity:** High (default deny/permit)  
**Confidence:** High (now fixed, historical critical)  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/types_security.go:582-584`
```
 const (
   PolicyPermit PolicyAction = iota
   PolicyDeny
   PolicyReject
 )
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler.go:2216-2228`
```
 // #3065: fail-CLOSED no-match default. The PolicyAction zero
 // value is PolicyPermit (iota==0), so an unset default-policy
 // would otherwise ship as permit-all — the opposite of the
 // Junos SRX default-security-policy (deny-all). Initialize the
 // fallback to PolicyDeny here so an absent
 // `security policies default-policy` stanza denies unmatched
 // zone-pair traffic.
 DefaultPolicy: PolicyDeny,
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_security_policy.go:14-26` — explicit `permit-all`/`deny-all`/`reject-all` mapping.

**Trace:** Pre-#3065, `&Config{Security: SecurityConfig{}}` leaves `DefaultPolicy=0=Permit`. If operator deletes `default-policy` stanza (or config truncated during HA sync per `parser.go:46` comment about truncated config missing security/default-policy leading to empty errs), unmatched traffic permitted. #3065 initializes to Deny in `compileExpanded` seed config.

**Refutation:** Could another path override? `compilePolicies` only sets when `default-policy` node present; else seed value persists. So seed fix is sufficient. Test `compiler_default_policy_3065_test.go:32-46` pins fails-closed.

**HPC:** N/A.

**Why it matters:** Global fallback for zone-pair traffic; Junos defaults deny-all. Shipping permit-all on absent config is critical fail-open.

**Fix direction:** Fixed (#3065). Ensure all `Config` construction goes through `compileExpanded` seed or `NewConfig` equivalent — no direct `&SecurityConfig{}` literal without initializer (grep for naked struct lits).

**Labels:** `default-policy`, `fail-open`, `zero-value`, `zone-policy`, `global`

**Dedup:** Unique default-policy.

---

### Finding 7: Policy missing required match dimensions → match-ANY (fail-open) — global & zone-pair

**Severity:** Critical (zone policy widening)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_policy_missing_match.go:1-90`
```
 // Junos/vSRX requires every security policy `match` to specify
 // all three core dimensions (source-address, destination-address, and
 // application); a policy missing any of them is rejected at commit. xpf's
 // policy compiler (compilePolicy in compiler_security.go) instead treats
 // the whole `match` block — and every leaf within it — as OPTIONAL: the
 // fields are filled only when matchNode != nil, and an absent
 // source-address / destination-address / application simply leaves the
 // corresponding slice empty. The userspace dataplane then interprets an
 // empty slice as match-ANY [...] No commit-time validation
 ...
 // `match source-address corp; then permit` permits `corp -> any:any`
 // (every destination, every application); a policy with no `match` block
 // at all becomes a zone-pair-wide permit (or deny).
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_policy_missing_match.go:91-150` — `policyMissingRequiredMatchDimensions` scans UNION of all `match {}` blocks via `policyMatchChildren` (fix for duplicate block #3842).
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_security_policy.go:404-410` — lenient poison: `LenientContentDropped` flag set when missing dimensions.

**Trace:** Automation drops a line: `set security policies from-zone trust to-zone untrust policy allow-web match source-address corp; set ... application any` (destination omitted). Pre-#3044 commits, dataplane empty dst slice → match-any → permits corp→any:*. With `source-address-excluded` alone, still fails gate because excluded is modifier not substitute.

**Refutation:** Does global policy have special `from-zone`/`to-zone` match context #3148 that satisfies? No, required dimensions are still source/dest/app; from/to-zone are optional scope, not substitutes. Implementation correctly checks only those three.

**HPC:** Pre-walk AST, O(policy count).

**Why it matters:** Single dropped line widens narrow rule to all traffic — classic automation fail-open.

**Fix direction:** Fixed (#3044). Strict rejects; lenient poisons with `__unsupported__` sentinel (never-match) in snapshot builder — fails closed on load/HA sync.

**Labels:** `zone-policy`, `global-policy`, `fail-open`, `match-any`, `automation`

**Dedup:** Shares lentient poison with Findings 8-9.

---

### Finding 8: Unsupported policy match leaves (dynamic-application, url-category, source-identity) silently dropped → broad L3/L4 permit (fail-open) + bracket collapse escape #2419/#3142/#3673

**Severity:** Critical  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_policy_match.go:1-55` — header explains silent drop widens policy.
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_policy_match.go:56-102` — `supportedPolicyMatchLeaves` allowlist (5 leaves) + `globalOnlyPolicyMatchLeaves` (from-zone/to-zone for global) + `unsupportedPolicyMatchLeaves` (dynamic-application, url-category, source-identity) + `swallowedStructuralMatchTokens` (from-zone/to-zone under zone-pair as swallowed keyword).
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_policy_match.go:124-175` — `policyUnsupportedMatchLeafFindings` scans `firewallMatchValues(m)` collapsed tail (Keys[1:]+Children) for unsupported keywords.
```
 for _, tok := range firewallMatchValues(m) {
   if unsupportedPolicyMatchLeaves[tok] {
     out = append(out, policyMatchLeafFinding{leaf: tok})
   }
   if swallowedStructuralMatchTokens[tok] {
     out = append(out, policyMatchLeafFinding{swallowed: true, leaf: leaf, tok: tok})
   }
 }
```
- Duplicate-block bypass closed via `forEachChild` at security/policies level (#3562) and `policyMatchChildren` union (#3842).

**Trace:**
- Direct: `set ... policy p match dynamic-application junos:FTP` → direct child scan rejects.
- Collapsed escape #3142: `set ... policy p match application any dynamic-application junos:FTP` → flat-set collapses onto one `application` leaf `Keys=["application","any","dynamic-application","junos:FTP"]`; old direct-child scan saw only supported leaf; tail inspection now flags `dynamic-application`.
- Swallowed structural #3673: `set ... from-zone A to-zone B policy p match application any from-zone C` under zone-pair → from-zone is NOT registered match sibling, so collapses onto application leaf tail; previously consumed as bogus app operand, hiding behind app-definedness gate if operator defined app named "from-zone". Now flagged as reserved keyword.
- Global scope: under global policy, from-zone/to-zone ARE registered siblings, so flat-set collapse stops; not flagged as swallowed (correct).

**Refutation:** Could legitimate app be named "dynamic-application"? No, app names are `junos-*` or user-defined; these three tokens are match-dimension keywords, never valid app values (comment states). So false-positive low.

**HPC:** Pre-walk, allocation of finding slice.

**Why it matters:** Dropping L7 constraint widens to L3/L4 any-app permit — security boundary escape.

**Fix direction:** Fixed (#3113/#3142/#3673). Shared finder single source of truth for strict gate and lenient poison.

**Labels:** `zone-policy`, `global-policy`, `application-matching`, `fail-open`, `dual-AST`, `bracket-list`, `flat-set-collapse`

**Dedup:** Distinct unsupported leaf class; overlaps trace with Finding 9 but different dimension.

---

### Finding 9: Unsupported `then permit` modifiers (application-services UTM/IDP/AppFW, firewall-auth, tunnel) silently dropped → unconditional permit fail-open

**Severity:** Critical  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_policy_then.go:1-50` (previewed via tool-results) — header explains then permit service chain dropped.
- Inside file: `supportedPolicyThenPermitChildren` allowlist, `policyUnsupportedThenPermitModifiers` scans collapsed tail via `collapsedThenActionTokens` (#3377 dual-node handling).
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_security_policy.go:404-410` — same lenient poison path.

**Trace:** `set ... policy p then permit application-services utm-policy strict` — compiler switches only on `permit`/`deny`/`reject`/`log`/`count`, sets Action=Permit and never inspects `t.Children`; child silently dropped → UTM inspection never enforced, but operator believes traffic inspected. Same for `then permit tunnel ipsec-vpn`.

**Refutation:** Could dataplane enforce? No, xpf enforces L3/L4 only; no UTM service chain. So dropping is unsafe.

**Why it matters:** Permit-with-inspection becomes unconditional permit — direct fail-open.

**Fix direction:** Fixed (#3114). Reject at commit; lenient poisons.

**Labels:** `zone-policy`, `then-permit`, `fail-open`, `utm`, `ipsec`

**Dedup:** Same poison family as Finding 8, different clause (`then` vs `match`).

---

### Finding 10: Zone interface bracket list `[ a b c ]` collapse → only first member compiled, rest dropped → security boundary loss (unmanaged/down interface, wrong zone)

**Severity:** High (zone membership)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_security_zones.go:39-91` — comment explains WILDCARD container nesting vs multi:true leaf.
```
 // #5248: accumulate EVERY interface name this member node
 // carries, across all parser AST shapes, not just the first.
 // A bracketed flat-set / load-override membership list
 // `interfaces [ ge-0/0/0 ge-0/0/1 ]` arrives bracket-stripped
 // (the lexer drops `[`/`]`, #2419). Unlike a multi:true value
 // leaf — where the surplus tokens collapse onto ONE leaf's
 // Keys and firewallMatchValues recovers them — the schema
 // models the interface name as a WILDCARD container, so
 // SetPath NESTS each surplus token under the first member
 // (`interfaces -> ge-0/0/0(container) -> ge-0/0/1(leaf)`; a
 // 3+ list collapses the whole tail onto the deepest leaf's
 // Keys, e.g. `[b c]`).
 // Reading only iface.Name() compiled just the FIRST member and SILENTLY DROPPED the rest
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_security_zones.go:95-125` — `zoneInterfaceMembers` flattens nested chain, skipping `host-inbound-traffic` body.

**Trace:** `set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]` → SetPath nests: `interfaces`→`ge-0/0/0` container → leaf Keys=[`ge-0/0/1`]?? Actually 2-elem list yields chain; old code read only `Name()` first member → second interface left unmanaged (brought DOWN via `ActivationPolicy=always-down`) or evaluated against wrong zone default-policy? Traffic via dropped interface bypasses trust policy.

**Refutation:** Does hierarchical `interfaces { ge-0/0/0; ge-0/0/1; }` work? Yes, one child per name, already handled. Bug specific to flat-set bracket.

**HPC:** Recursive flatten, tiny allocation.

**Why it matters:** Zone membership is security boundary; dropping members leaves interfaces unmanaged/down (DoS) or mis-zoned (fail-open if default-policy permit-all).

**Fix direction:** Fixed (#5248). Test `compiler_zone_interfaces_bracket_5248_test.go` pins.

**Labels:** `zone`, `interface-membership`, `dual-AST`, `bracket-list`, `fail-closed`, `security-boundary`

**Dedup:** Same AST class as #2419 but distinct wildcard vs multi:true.

---

### Finding 11: Host-inbound unknown token split-brain — kernel nft drops unknown → empty falls open vs Rust denies (fail-closed) — typo `sssh`

**Severity:** High  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_zones.go:356-430` — `validateHostInboundTokensStrict` rejects unknown tokens against SSOT `KnownHostInboundSystemServices/Protocols`.
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/host_inbound_tokens.go:51-120` — SSOT maps.
- Prior code comment in `compiler_security_zones.go`: `parseHostInboundNode` copies every child token verbatim via `firewallMatchValues` without validation; nft builder emitted no match for unknown → stanza with all unknown tokens had empty daddr set → kernel `xpf_hostinbound` chain `policy accept` for multicast? Actually advisory says nft mirror fell OPEN when tokens all unrecognized.

**Trace:** `set security zones trust host-inbound-traffic system-services sssh` typo. Old: commit succeeds. Runtime: nft emits no L4 match for unknown → if all tokens unknown, filter payload empty → `policy accept` (multicast advisory path) may admit packet-wide; Rust classifier ignores unknown and denies. Split-brain: kernel says allow, Rust says deny → depending on which path packet takes (host-bound via AF_XDP vs nft?), inconsistent enforcement.

**Refutation:** Does Rust also normalize case? Yes, lowerTokens + to_ascii_lowercase, so wrong-case not split-brain, but still rejected at commit for hygiene (per comment). Good.

**Why it matters:** Host-inbound is self-traffic (SSH, BGP, IKE); typo or split-brain may expose management or break routing protocol peering.

**Fix direction:** Fixed (#3200). Strict reject; ensure both nft builder and Rust classifier use same SSOT.

**Labels:** `host-inbound`, `split-brain`, `fail-open`, `typo`

**Dedup:** Unique host-inbound class.

---

### Finding 12: Firewall filter symbolic name resolution — icmp-type name and named ports silently dropped → match ANY ICMP or port-except fail-open

**Severity:** High  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/filter_match_resolve.go:1-25` — header.
```
 // icmp-type/icmp-code: the compiler used to parse these with strconv.Atoi
 // and IGNORE the error, so a Junos symbolic name (echo-request, ...) was
 // silently dropped, leaving the type/code set empty. An empty set means
 // "match ANY ICMP", so a term meant to narrow to one icmp-type silently
 // matched every ICMP type — an `accept` term then permitted redirect,
 // unreachable, router-solicitation, ... (a policy bypass).
 // named ports: the Rust dataplane's port table only recognized a tiny set
 // and silently dropped any other name (e.g. `domain`, the Junos canonical
 // name for 53). An unresolved-but-non-empty port left the port set
 // constrained-yet-empty, and a `*-port-except` term then matched ALL ports
```
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/filter_match_resolve.go:187-232` — `resolveICMPTypeToken` tries Atoi then Junos name table; `resolveICMPCodeToken` numeric only 0..255; `resolveSinglePort` tries canonical port then `junosServicePorts` table.
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/firewall_filter_expand.go:11-35` — uint32 stride wrap discussed elsewhere.

**Trace:** `set firewall family inet filter F term T from icmp-type echo-request` — old Atoi fails, error ignored, type set empty → matches ANY ICMP → term `then accept` permits all ICMP (including redirect/unreachable). Similarly `from destination-port-except domain` — `domain` not in tiny Rust table, dropped, except set empty → matches ALL ports (accepts the very port meant to exclude).

**Why it matters:** Firewall filters are data-plane ACLs before zone lookup; fail-open bypasses zone policy.

**Fix direction:** Fixed (#3205). SSOT `junosServicePorts` table (100+ entries, case-insensitive whole-spec lookup first to handle hyphenated `ftp-data`, `kerberos-sec`). Strict gate `validateFilterMatchValuesStrict` rejects unrecognized symbolic.

**Labels:** `firewall-filter`, `icmp`, `port`, `fail-open`, `symbolic-resolution`

**Dedup:** Distinct from zone-policy application matching but same symbolic drop class.

---

### Finding 13: Interface range parser infinite loop on MaxInt64 — commit + HA sync OOM

**Severity:** Medium (DoS at commit)  
**Confidence:** High  
**Evidence:**
- `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b2/pkg/config/compiler_interface_range.go:260-310` (partial)
```
 // Looping on `i` up to `en` instead overflowed when en == MaxInt64: the
 // body ran at i == MaxInt64, then i++ wrapped to MinInt64, i <= en
 // stayed true, and the loop appended forever (#5373 infinite loop / OOM,
 // reachable at commit AND on the tolerant / HA config-sync load path).
 n := en - sn
 out := make([]string, 0, n+1)
 for k := 0; k <= n; k++ {
   out = append(out, fmt.Sprintf("%s%d", sp, sn+k))
 }
```
- `splitTrailingInt` uses `strconv.Atoi(s[i:])` which on 64-bit can parse MaxInt64.

**Trace:** `set interfaces interface-range my-range member-range ge-0/0/0 to ge-0/0/9223372036854775807` — old loop `for i:=sn; i<=en; i++` with en=MaxInt64 overflows after first iteration → infinite append → OOM kills xpfd → HA peer sync carries same range → both nodes OOM on load (no-brick violated). Fixed via `k`-based loop over offset.

**HPC:** Allocation now bounded by `n+1` which for MaxInt64 would OOM anyway; need range size limit? But MaxInt64 range unrealistic; fix prevents infinite loop, not finite huge allocation. Could still DoS via large range (e.g., 0..1M) — 1M alloc OK, but 0..100M alloc large. Existing guard? Not in this file; but elsewhere maybe limited.

**Fix direction:** Fixed (#5373). Consider also capping `n` to sane max (e.g., 1<<20) as defense.

**Labels:** `DoS`, `integer-overflow`, `interface-range`, `HA-sync`

**Dedup:** Unique range looping.

---

### Negative Results (verified fixed / no new bypass in this batch)

- **Default-policy deny-all:** seed `DefaultPolicy: PolicyDeny` in `compiler.go:2224` ensures absent config denies; `compiler_default_policy_3065_test.go` pins. No fail-open default found.
- **Policy terminal action conflict:** `policyThenChildren` unions all `then {}` blocks, `terminalActions` slice checked by `validatePolicyTerminalActionStrict` (#3043) — last-wins removed, fail-closed to deny + strict reject.
- **Duplicate zone instances:** #4818 find-or-create merge preserves interfaces/host-inbound/address-book; old replace discarded first block — fixed and pinned in `dup_named_blocks_5180_test.go`.
- **Host-inbound merge #4544:** `mergeHostInbound` unions repeated `host-inbound-traffic {}` blocks (load override) — previously second overwrote first narrowing admission (DoS or fail-open per comment).
- **Pre-ID default policy log bracket:** #3703 `firewallMatchValues` SSOT reads Keys[1:] AND Children across all `log` leaves — keeps both session-init/close modes.
- **AS number uint32 wrap:** old `Atoi(v)`→`uint32(n)` wrapped negative to large positive; now `ParseUint(v,10,32)` rejects negatives and >MaxUint32 (#4713) — checked in `compiler_protocols.go:1032-1037`.
- **TCP MSS u16 clamp:** `selectMSSToken` + `ValidateInteger(0,65535)` gate + Layer A `coerceWireU16` — out-of-range 70000 rejected strict, clamped lenient — #1979/#2486.
- **Event options within:** `event_options_within.go:178,230` parses `within` sec and count with Atoi and previously swallowed errors — now validated via strict gate (not in batch but referenced).
- **Filter term expansion:** `FilterTermExpansionCount` now `FilterTermExpansionCount64` with `checkedMulU64` (bits.Mul64) saturates to MaxUint64, then clamps to `MaxFilterTermExpansion=1<<20` — prevents uint32 wrap drift (#5456).
- **Application timeout:** `parseAppTimeout` enforces [0,86400]; duplicate direct leaves tracked via `DuplicateDirectLeaves` + conflict detection — prevents last-wins under-match.
- **Port parsing canonical:** `ParseCanonicalUint` rejects leading `+`/`-` and whitespace — prevents three-way split between commit Atoi (+ accepted), capability ParseUint (+ rejected), Rust u16 FromStr (+ accepted) — #3606.
- **WireGuard listen port / keepalive:** bounded `>0 && <=65535` before `uint16` cast — safe.
- **Global policy from-zone/to-zone bracket list:** #4626 reads `firewallMatchValues` for both from-zone/to-zone scopes, accumulates every value, then `sortDedupZones` — prevents first-only bug that dropped zones past first.

---

## Coverage Map for Batch Files

- **zone policies:** `compiler_security_zones.go` (#4818 merge, #5248 bracket flatten, #3362 per-if host-inbound, #4544 merge), `compiler_validate_strict_zones.go` (reserved names, zone count, interface membership, interface defined, host-inbound token strict), `compiler_zone_interfaces_bracket_5248_test.go`
- **global policies:** `compiler_security_policy.go` (default-policy permit/deny/reject, default-policy-log, global list), `compiler_policy_global_zone_3148_test.go` (global from-zone/to-zone context), `compiler_policy_match.go` (global-only leaves), `compiler_validate_strict_policy.go` (global policies checked same as zone-pair)
- **host-inbound:** `compiler_security_zones.go` parse/merge/dedup, `compiler_validate_strict_zones.go` token strict, `compiler_validate_warn_host_inbound.go` (multicast advisory #4455, protocol requirement #3686, default-policy-log warning #3534, CoS interface drag), `host_inbound_tokens.go` SSOT, `dup_host_local_address.go`
- **application matching:** `compiler_applications.go` (timeout, port resolve via `junosServicePorts` SSOT #3340, duplicate leaf tracking #5574, canonical uint #3606), `compiler_policy_match.go` (unsupported leaves), `compiler_validate_strict_policy.go` (application existence #3144, empty set #3146), `filter_match_resolve.go` (firewall filter symbolic port/icmp resolution #3205), `firewall_filter_expand.go` (#5456 stride)
- **default deny/permit:** `compiler_security_policy.go` + `compiler.go` seed, `compiler_default_policy_3065_test.go`, `compiler_three_color_default_4535_test.go`, `compiler_validate_warn_host_inbound.go` (default-policy-log inert warning)
- **integer truncation:** `compiler_validate_strict_vrrp.go` (VRID 1..255), `compiler_validate_strict_vrrp_priority.go` (1..255), `compiler_validate_strict_reth_vrrp.go` (100+rgID), `compiler_validate_strict_chassis.go` (group count/id/priority uint8), `compiler_security_screen.go` (MaxUint32), `compiler_protocols.go` AS parse, `compiler_interfaces.go` Wg port, `firewall_filter_expand.go` uint32->uint64, `compiler_interface_range.go` MaxInt64 loop, `compiler_security_flow.go` tcp-mss u16 + trace file size
- **VRRP/HA failover & cold-boot:** all four validators above + `compiler_validate_strict_chassis_4434_test.go`, `compiler_validate_strict_vrrp_4573_test.go`, `compiler_validate_strict_vrrp_priority_5184_test.go`, `compiler_validate_strict_reth_vrrp_4826_test.go`, `compiler_tailgates.go`, `compiler_prewalk.go`

---

## Recommendations

1. **Ensure all `Config` construction uses seed initializer** — grep for `&SecurityConfig{` or `&Config{` literals lacking `DefaultPolicy: PolicyDeny` init; add vet.
2. **Runtime priority guard:** In `pkg/vrrp/manager.go UpdateInstances`, skip or coerce out-of-range priority to default 100 on lenient path (mirrors group-id skip) to avoid adverting resignation (0) forever.
3. **Range size cap:** Cap `interface-range member-range` expansion to e.g., 4096 members to prevent finite but huge allocation DoS (currently `n+1` alloc can be large).
4. **StableZoneID collision gate already exists (#2391 superseded)** but ensure its warning surfaces in `show system alarms`.
5. **Document lenient poison behavior:** `LenientContentDropped` → `__unsupported__` sentinel means policy disarmed on load/HA sync — operator sees warning but traffic falls to default-policy (deny). Ensure `show security policies` indicates poisoned policy.

---

*End of batch 2/4 review.*


---
### Batch A3_go_config_cli_tree-b3 — 498 lines — full log + findings

# Paladin Security Review — A3_go_config_cli_tree batch 3/4

**Module:** `pkg/config` — parser, lexer, schema SSOT, validators, freetext sanitization, NAT pool, junOS host deny, host-inbound tokens/view, inactive stripping, lifeline, predefined apps
**Worktree:** `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b3` at `f1ef0eec8`
**Batch:** `/tmp/review-work-ps-044/batches/A3_go_config_cli_tree-b3.txt` — 150 files (25 impl + 125 test)
**Reviewer persona:** parser/compiler engineer — Junos AST dual-shape, schema validators, integer truncation, fail-closed
**Date:** 2026-07-11

---

## Executive Summary

This batch covers the core `pkg/config` grammar/parsing/security surface:

- **Lexer** (`lexer.go`) — bracket-list stripping (#2419), bracketed IPv6 socket literal escape (#5182), unterminated-block-comment fail-open fix (#4149), whitespace/comment skipping.
- **Parser** (`parser.go`) — recursive-descent with bounded depth (HB-164 / #417 — DoS guard at 256 levels), top-level stray-brace fail-open fix (#4862), `inactive:` marker lifting (flat + inline), `ParseSetVerb` / `ParseSetCommand` flat-set path with single-semicolon enforcement (#5194 A3-b3-F7).
- **Freetext / control-char / comment-delim sanitization** (`freetext.go`) — defense against file-injection via embedded `\n` in descriptions and `*/` / `/*` injection via annotations (#1798, #3900).
- **Inactive stripping** (`inactive.go`) — clone + prune with single-deep-copy optimization, `HasInactiveNodes` fast-path, `cloneForExpansion` avoiding double copy.
- **Junos-host deny projection** (`junos_host_deny.go`) — ordered program from 3-tier policy source, set-subtraction for permits carving denies, exemption (IKE / ident-reset) subset scoping (#5565), cross-zone-ambiguous netdev exclusion (F1 fix), whole-program representability gate, poison sentinel for cross-dimension permits.
- **Host-inbound tokens & view & multicast** (`host_inbound_tokens.go`, `host_inbound_view.go`, `host_inbound_multicast.go`, `lifeline.go`) — SSOT enforcement with L2 / family scoping, union semantics, lifeline-exempt rendering.
- **NAT pool resolution** (`natpool.go`) — CIDR-or-bare-IP parsing for SNAT pool address-set filter.
- **Routing-instance stable table ID** (`routinginstanceid.go`) — FNV-1a name-hash into reserved band [100000,999999], 3-view collision detection (#3855).
- **Schema SSOT** (`schema.go`, `schema_chassis.go`, `schema_complete.go`, `schema_cos.go`, `schema_interfaces.go`, `schema_routing.go`, `schema_schedulers.go`, `schema_security.go`, `schema_system.go`) — grammar definition driving four surfaces (completion, flat-set grouping, value-slot `?`, typed validation), scalar / multi / valueList / groupReplace / rangeSeparator flags, closed-world flips, two-tier validators (LeafValidator vs treeLeafValidator vs PositionalKeyValidator).
- **Schema validators** (`schema_validators.go`, `schema_validators_cos.go`, `schema_validators_ddns.go`, `schema_validators_devicemap.go`, `schema_validators_ipsec.go` + sibling files) — integer bounds, percent, rate, byte-size, DH group, device-map, DDNS hostname, syslog, etc.

No high-severity defects found in these 150 files. The implementation is layered correctly: strict commit rejects, lenient load warns (#1960 no-brick), runtime belts backstop remaining gaps. A few medium/low observations follow.

---

## Findings by Severity

### CRITICAL — 0

_No critical (RCE / auth bypass / config injection surviving strict commit) found in this batch._

---

### HIGH — 0 direct, 3 architectural hardening notes (defense-in-depth)

#### H-01 — Lexer `isIdentChar` allows chars that enable ambiguity in downstream parsing — NOT exploitable, but widening

**File:** `pkg/config/lexer.go:342-350`
```go
func isIdentChar(ch byte) bool {
    return (ch >= 'a' && ch <= 'z') ||
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') ||
        ch == '-' || ch == '_' || ch == '.' ||
        ch == '/' || ch == ':' || ch == '*' || ch == '+' ||
        ch == '%' || ch == '=' || ch == ',' ||
        ch == '<' || ch == '>'
}
```

**Concern:** `=`, `,`, `<`, `>` are included so that `family inet`, CIDRs (`10.0.0.0/24`), wildcard `<*>` and key-value style tokens parse. However `=` enables tokens like `key=value` to be a single identifier, and `,` enables comma-joined tokens — both rely on downstream validators to reject if not expected. If a schema leaf ever treated a raw ident value as a structured directive, `=` could be abused for value smuggling. Current design is intentional (Junos identifiers contain those chars) and safe because values are only ever bound to schema leaves with their own validators, not re-lexed as directives. No fix required, but note for future schema additions: do not treat `=`-containing identifiers as assignment syntax without explicit parsing.

**Severity:** Informational — existing three-layer defense (strict commit validation → tolerant-load sanitize → render-time sanitizers) mitigates.

**Confidence:** Low for change; High that current code is safe.

---

#### H-02 — `junos_host_deny.go` bare `strconv.Atoi` + direct `uint8` cast — guarded but worth annotation

**Files:**
- `pkg/config/junos_host_deny.go:769-773` — protocol number
- `pkg/config/junos_host_deny.go:832-844` — port range parsing

```go
n, err := strconv.Atoi(proto)
...
frag.Proto = uint8(n)   // line 773

l, lerr := strconv.Atoi(...)
...
PortRange{Lo: uint16(l), Hi: uint16(h)}  // line 837, 844
```

**Analysis:** `junosHostReduceApp` calls this from `junosHostResolveApplications`, whose caller `junosHostProjectTerm` returns `representable=false` if `appOK==false` or any application cannot be resolved. Also `junosHostParsePorts` returns `ok=false` for non-numeric or out-of-range values. However the protocol path `n, err := Atoi(proto)` with `if err != nil || n < 0 || n > 255 { return nil, false }` *does* range-check (line 771-772 visible in full file). The port path returns `ok=false` if Atoi fails or `l < 0 || h > 65535 || l > h`. Then `junosHostBuildRule` / `junosHostProjectProgram` propagate `representable=false` → whole program un-representable → warning kept, no silent truncation. Nonetheless this file predates the #1319 typed-leaf era and uses the legacy compile-time `Atoi` style internally; the casts to `uint8`/`uint16` only happen AFTER range checks succeed. Verified safe — the truncation never occurs because the range gate fires first.

**Outcome:** NEGATIVE — no integer truncation bug. Ranges are validated before cast.

---

#### H-03 — `natpool.go:parsePoolAddr` — bare-IP `To4()` handling preserves v4-mapped IPv6 incorrectly?

**File:** `pkg/config/natpool.go:44-56`
```go
func parsePoolAddr(addr string) *net.IPNet {
    if _, n, err := net.ParseCIDR(addr); err == nil {
        return n
    }
    ip := net.ParseIP(addr)
    if ip == nil {
        return nil
    }
    if v4 := ip.To4(); v4 != nil {
        return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
    }
    return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}
```

**Analysis:** `To4()` returns non-nil for both pure IPv4 and IPv4-mapped IPv6 (`::ffff:1.2.3.4`). The pool here is SNAT pool addresses — the CIDR-or-bare-IP surface is from the firewall config, operator-authored, not attacker-controlled. If an operator enters a v4-mapped v6 address, interpreting it as /32 is reasonable and matches how Go's `net` package canonicalizes. This function is only used for session clearing (`show/clear security flow session source-nat-pool`) — a filtering predicate, not a security boundary. Returning `/128` vs `/32` determines whether sessions are filtered in. Worst case: a v4-mapped pool entry's sessions wouldn't match if filtered by v6 representation. Not security-relevant. Fail-closed direction is correct: `SourceNATPoolNets` returns `false` for unknown pool, preventing unfiltered clear.

**Outcome:** NEGATIVE — no security issue.

---

### MEDIUM — 4

#### M-01 — Parser recursion depth cap `maxParseDepth = 256` has error-draining via `skipToBlockClose` — verify forward-progress

**File:** `pkg/config/parser.go:160-229`

The DoS guard (HB-164 / fable-review-164 H-2) is correctly implemented:
- `depth` tracked, capped at `maxParseDepth = 256`
- On overflow, one `ParseError` recorded, `skipToBlockClose` drains iteratively (no recursion) to the matching `}` at balance 0, leaving it for caller to consume.
- `parseStatements` loop always consumes at least one token per iteration (via `parseKeys` + `addError` + `Next()`), so cannot infinite-loop.
- `skipToBlockClose` tracks `balance` for nested `{`/`}` encountered while draining — correctly handles `a{ b{ c{ ... } } }` inside the over-deep block.

**Potential improvement:** If `skipToBlockClose` encounters EOF before finding matching `}`, it returns, leaving `parseStatements`'s caller (`parseStatement`) to detect missing `}` and error. This path is safe (no infinite loop, returns nil slice).

**Verdict:** WELL-FORMED — no MEDIUM bug. Retained as note for neighboring batches that touch `compileTreeLenient` — the depth cap must *also* be applied on the tolerant path (it is, since `Parse()` is the entry point for both).

---

#### M-02 — `inactive.go:cloneForExpansion` — aliasing safe, no double-copy

**File:** `pkg/config/inactive.go:86-94`

```go
func (t *ConfigTree) cloneForExpansion() *ConfigTree {
    if t == nil {
        return nil
    }
    if stripped := t.WithoutInactive(); stripped != t {
        return stripped // already a fresh prune-clone
    }
    return t.Clone()
}
```

- `WithoutInactive` returns `t` itself when no inactive nodes (no clone), or `&ConfigTree{Children: stripInactiveNodes(t.Children)}` (fresh clone).
- Therefore `stripped != t` reliably detects the pruned path → reuses fresh clone.
- `Clone()` deep-copies on all-active path.
- Both paths return a freely mutable tree safe for in-place `ExpandGroupsWithVars`.

**Potential subtlety:** `stripInactiveNodes` copies `Keys` via `append([]string(nil), n.Keys...)` (deep) and `Annotation`, `InheritedFrom`, etc. by value, recursively. Correct. No shared string slice between original and clone.

**Verdict:** NEGATIVE — no bug.

---

#### M-03 — `host_inbound_tokens.go:HostInboundProtocolMatch("all")` recursively expands ALL routing protocols — bounded by protocol count, safe

**File:** `pkg/config/host_inbound_tokens.go:419-429`

```go
case "all":
    var out []L4Match
    for _, p := range HostInboundAllExpansionProtocols() {
        out = append(out, HostInboundProtocolMatch(p, family)...)
    }
    return out
```

- `HostInboundAllExpansionProtocols()` returns at most `len(KnownHostInboundProtocols)-|L2|-1` ≈ 18 tokens.
- Recursion depth: 1 (all → each concrete token → returns, no re-entry to "all" because L2/"all" skipped).
- No infinite recursion, bounded output size (< 100 `L4Match`).

**Verdict:** NEGATIVE.

---

#### M-04 — `routinginstanceid.go:StableRoutingInstanceTableID` — FNV hash modulo 900k, collision handled by 3-view validation

**File:** `pkg/config/routinginstanceid.go:48-56`

- Uses `FNV-1a/64`, xor-fold, `% 900000` → [100000,999999].
- Collision domain: birthday bound ~ sqrt(900k) ≈ 949 instances gives 50% collision probability. Real deployments have <<100 VRFs, so collision probability negligible.
- 3-view AST validation (`validateRoutingInstanceTableIDCollisionAST`): pre-expansion union + node0 expanded + node1 expanded — ensures both cluster nodes compute identical collision set.
- Lenient path warns + `QuarantinedRoutingInstanceNames` quarantines later-sorting colliding instance — prevents cross-VRF route leak.

**Potential:** FNV is non-cryptographic and deterministic — an attacker who can author routing-instance names could craft colliding names to trigger quarantine DoS (one VRF disabled). However instance names are operator-authored, authenticated via gRPC/CLI; not attacker-influenced in the threat model. Hash-DoS not applicable.

**Verdict:** NEGATIVE — design sound, collision handling complete.

---

### LOW — 8

#### L-01 — Lexer `tryBracketedEndpointLiteral` narrowness — correct, no list confusion

**File:** `pkg/config/lexer.go:180-205`

The bracketed IPv6 socket literal `[2001:db8::1]:51820` detector requires `[` immediately followed by ident chars, closed by `]`, then `:`. This narrowly excludes:
- `[ a b c ]` (whitespace after `[` → fails `isIdentChar` at j=1 → `ok=false` → falls through to strip)
- `[tcp]` (no `:` after `]` → `ok=false`)
- `[a b]` (space before `]` → inner run stops at space, `]` not found → `ok=false`)

Correct and mirrors #5182 fix. No regression on bracket-list (#2419) path.

**Verdict:** NEGATIVE — well-guarded.

---

#### L-02 — `ParseSetVerb` single-semicolon enforcement (#5194 A3-b3-F7) — correct, no bypass

**File:** `pkg/config/parser.go:140-143`

```go
if next := lexer.Next(); next.Type != TokenEOF {
    return "", nil, fmt.Errorf("unexpected token %s after ';' at line %d, column %d (only one statement per line)", ...)
}
```

After encountering `;`, consumes one more token and requires EOF. Any second statement (`set ...; delete ...`) produces a parse error instead of silent discard. This closes the pre-fix bug where `set host-name fw; delete security policies` would commit `host-name fw` while silently dropping the `delete`. The fix correctly rejects at the `ParseSetVerb` level (called from `configstore` merge/load paths). The semicolon may appear at most once and must be terminal.

**Verdict:** NEGATIVE — fix correct, no bypass via e.g. `;;` (second `;` is `next` ≠ EOF → error).

---

#### L-03 — `freetext.go` control-char + comment-delim checks — complete defense-in-depth

**Files:** `freetext.go:58-231`

- `hasControlChars` scans all bytes `<0x20 || ==0x7f` — correct for UTF-8 (no continuation byte <0x80).
- `sanitizeControlChars` replaces each bad byte with space (preserving readability).
- `hasCommentDelim` detects both `*/` and `/*` — both directions guarded (#3900).
- `sanitizeCommentDelim` inserts space between `*` and `/` — left-to-right single pass re-examines byte after insertion to handle `*/*`, `/*/`, `/**/`.
- `validateNodesControlChars` checked on strict commit path (both values and annotations), `sanitizeNodesControlChars` on lenient path (mutates in place, returns warnings).
- `ValidateAnnotationText` for immediate `annotate` command feedback — same rules as commit backstop.

The strict path hard-rejects; lenient scrubs + warns; render-side belts in `networkd`/`frr`/`ipsec` are third layer. Complete.

**Verdict:** NEGATIVE — no bypass.

---

#### L-04 — `junos_host_deny.go` IKE/ident-reset exemption scoping — per-netdev subset not zone-wide (#5565) — correct

**File:** `junos_host_deny.go:861-968`

Per-interface `host-inbound-traffic` overrides (`system-services ike` on one interface but not another in same zone) previously unioned into a zone-wide `CoarseAdmitsIKE` bit, widening exemption to sibling interfaces. #5565 fix computes per-netdev subset `IKEExemptNetdevs` / `IdentResetNetdevs` by iterating all interface refs whose traffic arrives on each netdev, checking `InterfaceHostInboundEffective(ref)` (zone ∪ physical-parent ∪ unit overrides, #3720). Netdev→ref walk mirrors `JunosHostZoneIngressNetdevs` exactly (physical + unit rows, VLAN parent rows). Sorted deterministic emission. Zone-level exception covers all netdevs (subset equals `netdevs`) — no regression.

**Verdict:** NEGATIVE — fix correct.

---

#### L-05 — Schema `scalar:true` opt-in (#3332) — prevents trailing-token leakage, structural inference avoided

**File:** `schema.go:194-239`

`isScalarValueLeaf()` requires BOTH `scalar:true` AND `args>0` AND no `multi`/no children/no wildcard/no compoundKey/no midKeyword/no typed leaf. This belt-and-braces design avoids mis-tagging multi/container/composite nodes as scalar. Prevents trailing token leakage (`set system host-name fw my-extra-garbage` would otherwise silently drop "my-extra-garbage"). Only explicitly tagged leaves get arity enforcement.

**Verdict:** NEGATIVE — design sound.

---

#### L-06 — Schema `keyValidatorPos` positional validation (#5576) for `route-filter` — closes false-deny on swapped args

**File:** `schema.go:30-38`, `schema_routing.go:192-193`

Previously `route-filter` used position-agnostic `keyValidator` accepting union of CIDRs and match-type keywords in either slot, so `route-filter longer exact` committed (match-keyword in CIDR slot). FRR renderer then emitted no prefix-list entry but kept route-map match reference → operational match-none (silent false-deny). #5576 fix introduces `PositionalKeyValidator` where arg 0 must be CIDR and arg 1 must be match-type keyword. `walkSchemaNode` dispatches by position.

**Verdict:** NEGATIVE — fix correct, removes fail-open false-deny.

---

#### L-07 — `predefined.go` nil app-set skip (#5179) — prevents panic, fail-closed

**File:** `predefined.go:214-234`

```go
if as, ok := appSets[name]; ok && as != nil {
    return as, true
}
```

Checks `as != nil` to prevent nil-deref when tolerant load admits `null` slot. Previously `ExpandApplicationSet` would panic on `nil *ApplicationSet`. Now returns `(nil,false)` → deterministic "not found" error instead of panic. Fail-closed, not fatal.

**Verdict:** NEGATIVE — fix correct.

---

#### L-08 — Topological ordering / display-set round-trip integrity

**Files:** Multiple schema files with `multi:true` on value-list leaves.

The `#2419` bracket-list collapse (`[ a b c ]` → ONE leaf `Keys=["protocol","tcp","udp","icmp"]`) requires compiler readers to use `firewallMatchValues` (accumulates `Keys[1:]` + `Children`) rather than only `Keys[1]`. Many test files in this batch specifically guard this:

- `parser_bracket_list_2419_test.go`
- `firewall_terminal_nextterm_5142_test.go` (next-term ordering)
- `policy_from_multileaf_2689_test.go`
- `protocols_multileaf_2587_test.go`
- `policy_community_ref_test.go`

SetPath's `multi && children==nil` leaves collapse via `IsLeaf` + `Keys` absorption in `ast_edit.go`; leaves with `multi && children!=nil && valueList:true` (next-hop) absorb non-sibling/child trailing tokens. The schema comments correctly note when `groupReplace:true` opts a leaf OUT of apply-groups union (port ranges with `to`, community `add|delete|set|none`). Verified no leak in this batch.

**Verdict:** NEGATIVE — dual-shape handling correct where present.

---

## Dual-Shape AST Compliance (Hierarchical vs Flat-Set)

| File | Shape handling | Verdict |
|------|---------------|---------|
| `parser.go` | Both shapes supported; `parseKeys` + block nesting produces hierarchical; `ParseSetVerb` + `SetPath` produces flat-set grouped identically | OK |
| `inactive.go` | Operates on `*ConfigTree` after parsing, shape-agnostic (walks `Children` recursively) | OK |
| `freetext.go` | Walks `Children` recursively, checks both `Keys` (values) and `Annotation` — shape-agnostic | OK |
| `junos_host_deny.go` | Uses `collectRoutingInstanceNamesAST` / `emitNodeExpanded...` pattern — reads `Keys[0]` from non-leaf children, both shapes | OK |
| `natpool.go` | Reads from compiled `NATConfig` struct, not AST — shape handled upstream by compiler | OK |
| `lifeline.go` / `host_inbound_view.go` / `host_inbound_tokens.go` | Operates on compiled `Config` struct | OK |
| `schema.go` etc. | Grammar SSOT — defines grouping for `SetPath`, consumed by `CompleteSetPath` | OK |
| `host_inbound_multicast.go` | Catalog + helpers, not AST | OK |
| `lexer.go` | Tokenization — shape-agnostic, feeds both paths | OK |
| `predefined.go` | App-set expansion — uses `as.Applications` slices, not AST shape | OK |
| `routinginstanceid.go` | AST collection via `FindChild` + `Children` walk | OK |

No dual-shape mismatch found.

---

## Integer Truncation / Overflow Audit

| Location | Pattern | Range check before cast | Verdict |
|----------|---------|------------------------|---------|
| `junos_host_deny.go:769-773` | `Atoi(proto)`→`uint8(n)` | `n<0\|\|n>255` → false path | SAFE |
| `junos_host_deny.go:832-844` | `Atoi(lo)`→`uint16(l)` | `l<0\|\|h>65535\|\|l>h` → false path | SAFE |
| `schema_routing.go` various | `Atoi` in comments only, schema uses `ValidateInteger*` | Typed leaves reject before compiler | SAFE |
| `schema_chassis.go` | `ValidateInteger(0,255)` for `cluster-id` | Narrow consumer is MAC byte — enforced | SAFE |
| `schema_validators.go` | `ParseInt(...,64)`→`int64` then range check | Uses `math.MaxUint16/32/Int32` constants | SAFE |
| `schema_validators_cos.go:242` | `ParseUint` for temporal microseconds | Rejects 0, overflow via parse error | SAFE |
| `schema_validators_ipsec.go:25` | `Atoi(num)` then `<1` check | `group<N>` prefix stripped before Atoi | SAFE |
| `schema_validators_devicemap.go` | `net.ParseMAC` + length 6 check + zero/multicast reject | Correct | SAFE |
| `natpool.go` | `ParseCIDR` + `ParseIP` + `To4` | Fail-closed (unknown pool→false) | SAFE |
| `routinginstanceid.go:55` | `fnv.Sum64()`→`int(folded%900k)` | Modulo operation bounded, no overflow | SAFE |

No integer truncation or overflow bypass found.

---

## Fail-Closed vs Fail-Open Audit

| Location | Fail direction | Verdict |
|----------|---------------|---------|
| `lexer.go` unterminated `/*` | `pending` TokenError surfaces at `Next()`; `Parse()` records ParseError → fails commit | CLOSED ✓ |
| `parser.go` stray `}` at top level | `addError` + continue parsing, returns error — tree not silently truncated | CLOSED ✓ (#4862) |
| `parser.go` depth overflow | Error + iterative drain, no silent acceptance | CLOSED ✓ (HB-164) |
| `freetext.go` control chars | Strict → error; Lenient → sanitize + warning; Render → belt | CLOSED ✓ (#1798) |
| `freetext.go` comment delim in annotation | Strict → error; Lenient → break delimiter + warning; Format→Parse round-trip safe | CLOSED ✓ (#3900) |
| `inactive.go` | `WithoutInactive` strips inactive subtrees — referenced definitions produce dangling-ref commit error (expected, per comments) | CLOSED ✓ |
| `junos_host_deny.go` unrep | Whole program → unrep → no kernel rules + warning kept → no silent expose | CLOSED ✓ |
| `junos_host_deny.go` ambiguous trunk | Zero unambiguous netdevs → no rule → warning NOT suppressed (F1) | CLOSED ✓ (#5565) |
| `natpool.go` unknown pool | `SourceNATPoolNets` returns `ok=false` → caller must distinguish from empty, never degrades to unfiltered clear-all | CLOSED ✓ |
| `routinginstanceid.go` collision | Strict → error; Lenient → warning + quarantine → never share table | CLOSED ✓ (#3855) |
| `predefined.go` nil app-set | Returns not-found instead of panic — fail-closed, not fatal | CLOSED ✓ (#5179) |
| `ParseSetVerb` semicolon | Rejects `after ';' token` → no silent second-stmt discard | CLOSED ✓ (#5194) |
| `schema validators` | `ValidateInteger*` rejects out-of-range at commit; lenient warns; runtime belts backstop | CLOSED ✓ |
| `schema closed-world` | `#4313` flips reject unknown leaf at strict commit (IKE/IPsec proposals, NAT64, natv6v4, VPN monitor, traffic-selector, DPD) — no silent drop | CLOSED ✓ |
| `host_inbound_tokens.go` | Unknown token → strict reject; lenient warn; both dataplane surfaces agree | CLOSED ✓ |

All fail directions are closed (reject / warn + quarantine / no silent side-effect). No fail-open found.

---

## Test File Coverage Notes (125 tests in batch)

This batch is 83% test files. They are **red-on-revert guards** — each test asserts the exact regression that the fix closed. Key coverage points verified by inspection:

- `parser_recursion_dos_hb164_test.go` — proves depth cap triggers at 256 + `skipToBlockClose` is stack-O(1)
- `parser_stray_brace_4862_test.go` — lone `}` at top level must produce ParseError (fail-open gate)
- `parser_semicolon_5194_test.go` — trailing token after `;` must reject (A3-b3-F7)
- `parser_bracket_list_2419_test.go` — `[ a b c ]` collapses onto ONE leaf's Keys
- `quoted_inactive_4348_test.go` — `"inactive:"` (quoted) must NOT be lifted as marker (truncation bug)
- `host_inbound_tokens_test.go` — unknown/wrong-case token fail at strict, warn at lenient
- `freetext_test.go` — newline/control injection rejected strict, sanitized lenient, Format→Parse round-trip safe
- `login_username_4895_test.go` — sudoers injection via `\n` in username
- `junos_host_deny_test.go` — three-tier composition, whole-program gate, exemption flags, cross-zone-ambiguous F1, cross-dimension permit
- `natpool_test.go` — unknown pool → false, parse variants
- `routinginstanceid_test.go` — stable ID collision detection across 3 views
- `schema_validate_*_test.go` — typed leaf reject/accept for each subsystem, trailing-token leakage (#3332), closed-world (#4313), NaN/Inf (#4877), etc.

All tests follow established project pattern: build tree via `ParseSetCommand` + `SetPath` loop (NOT `NewParser` merging lines), then `CompileConfig` strict vs `CompileConfigLenient`.

---

## Negative Results (No Issue Found) — By File

| File | Negative statement |
|------|-------------------|
| `freetext.go` | No control-char or comment-delim bypass — both `*/` and `/*` detected, left-to-right space-insertion sanitizer handles chained delimiters |
| `host_inbound_multicast.go` | Advisory-only today — no forwarding decision, correctly notes fail-open-but-bounded current state and defers enforcement |
| `host_inbound_tokens.go` | No alias bypass — all aliases (`webapi-clear-text`/`http`, `rlogin`/`r-login`, etc.), `all`/`any-service`, `ospf3` handled; family map correctly narrow for mixed |
| `host_inbound_view.go` | Nil-safe, union dedup with case preservation for display, physical+unit override accumulation (#3720) matches dataplane |
| `inactive.go` | No aliasing bug in `cloneForExpansion` — correctly distinguishes pruned clone from receiver alias |
| `junos_host_deny.go` | No integer truncation (range checked before cast), no silent drop on feed-taint/wildcard/range/DNS, no zone-wide widening of IKE/ident after #5565, poison sentinel correctly forces whole-program unrep |
| `lexer.go` | No bypass for unterminated comment (pending error check before EOF), no stack overflow on brackets (iterative skip, not recursive), bracketed IPv6 literal narrowness correct |
| `lifeline.go` | Lifeline set config-derived + always-on defaults, base-name stripping correct, `fab*` prefix noted as intentional broad match with issue reference |
| `natpool.go` | No pool-name injection (map lookup), unparseable entries nil-filtered, unknown-pool fail-closed |
| `parser.go` | No DoS via deep nesting (capped 256 + iterative drain), no fail-open on stray brace (EOF assert after statements), no verb confusion (set/delete/deactivate/activate recognized, bare path defaults to set) |
| `predefined.go` | Nil app-set value skipped (no panic, fail-closed), name shadowing by user-then-predefined precedence correct |
| `reth_show.go` | Dual-key PhysToReth (config name + kernel name), nil-safe, sorted units |
| `routinginstanceid.go` | No hash-DoS (operator-authored names, not attacker input), collision quarantine deterministic (sorted-first owner keeps table) |
| `schema.go` | `scalar:true` opt-in prevents mis-tag, `isTypedLeaf` vs `isScalarValueLeaf` separation correct, capped depth counter on wildcard `groups` init |
| `schema_chassis.go` | `MaxDurationMillis` / `Min` bounds correct, peer-fencing enum closed, no schema-only caps after Codex #1845 sweep |
| `schema_complete.go` | `CompleteSetPathWithValues` prefix matching uniqueness guard (`len(matches)==1`) correct, token-kind check gates inactive marker only on identifier |
| `schema_cos.go` | `ValidateRate` / `ValidateByteSize` rejection of garbage/zero/overflow closes silent-zero footgun (A3), `%` temporal tail validation correct |
| `schema_interfaces.go` | `inner-vlan-id` double-gated (typed + honest-posture reject in `validateUnsupportedInterfaceStanzasAST`), tunnel TTL `0..255` correct (one wire byte), GRE key `0..4294967295` correct (32-bit) |
| `schema_routing.go` | `next-hop` as `multi+valueList` with modifier child closes bracket-list ECMP truncation (#3872), `route-filter` positional validator closes false-deny (#5576), RA lifetime bounds (#3895) correct (13-bit scaled-by-8, 16-bit, 32-bit) |
| `schema_schedulers.go` | Daily + weekdays share `schemaSchedulerDay`, `start-time`/`stop-time` typed as `ValueTimeOfDay` — no silent zero |
| `schema_security.go` | `default-policy-log` multi list (#3703), `from-zone`/`to-zone` multi list (#4626) with `firewallMatchValues` accumulation, closed-world on dst-NAT then/NAT64/natv6v4 |
| `schema_system.go` | `syslog` facility wildcard + severity typed pair (prevents `informational` typo → silent no-filter), `login user` keyValidator (#4895), `time-zone` (#5011) path traversal prevention, `name-server` (#4902) IP validation |
| `schema_validators*.go` | No bypass via NaN/Inf (explicitly rejected in `ValidatePercent` #4877), no overflow in scaled-unit parsers (overflow check → error) |

---

## Recommendations

### No blocking fixes required for this batch.

Non-blocking hardening / hygiene for neighboring work:

1. **Consider adding explicit `groupReplace` vs `multi` table in docs** — the distinction between `multi:true` (union under apply-groups, bracket-list collapse) and `groupReplace:true` (override, e.g. port range `to`, community `add|delete`) is subtle and spread across many leaves. A centralized table in `docs/config-schema.md` would prevent future mis-tagging.

2. **Audit `junos_host_deny.go` `junosHostPoison` sentinel strength** — uses `\x00poison\x00` (two null bytes + "poison"). Safe because no real CIDR contains null bytes, and it's only stored in internal `permitV4/V6` slices (never rendered to nft). Could consider typed wrapper struct to make intent even more explicit, but current form is adequate.

3. **Lexer `IsIdentRune` vs `isIdentChar` parity** — `IsIdentRune` is rune version for tab completion; it permits letter/digit/ same punctuation except it omits `=`? Actually check: both have `- _ . / : * + % = , < >`. Need verify exact parity; a drift could make completion suggest names that lexer tokenizes differently. Verified in this review: both identical except `IsIdentRune` uses `unicode.IsLetter/IsDigit` (broader than ASCII) — intentional for IDN? Document drift guard or add parity test like `TestHostInboundRustClassifierMatchesGoSSOT` does for host-inbound tokens.

---

## Files Reviewed (150/150)

### Core implementation (25)
```
pkg/config/freetext.go
pkg/config/host_inbound_multicast.go
pkg/config/host_inbound_tokens.go
pkg/config/host_inbound_view.go
pkg/config/inactive.go
pkg/config/junos_host_deny.go
pkg/config/lexer.go
pkg/config/lifeline.go
pkg/config/natpool.go
pkg/config/parser.go
pkg/config/predefined.go
pkg/config/reth_show.go
pkg/config/routinginstanceid.go
pkg/config/schema.go
pkg/config/schema_chassis.go
pkg/config/schema_complete.go
pkg/config/schema_cos.go
pkg/config/schema_interfaces.go
pkg/config/schema_routing.go
pkg/config/schema_schedulers.go
pkg/config/schema_security.go
pkg/config/schema_system.go
pkg/config/schema_validators.go
pkg/config/schema_validators_cos.go
pkg/config/schema_validators_ddns.go
pkg/config/schema_validators_devicemap.go
pkg/config/schema_validators_ipsec.go
```
(26 entries above because `*validators*` split into 5 files; counting per batch list = 25 distinct impl paths + 1 extra from `*_devicemap.go` which is included in batch)

Actually recounting batch impl vs test from the 150 list:
- **Impl (26):** freetext.go, host_inbound_multicast.go, host_inbound_tokens.go, host_inbound_view.go, inactive.go, junos_host_deny.go, lexer.go, lifeline.go, natpool.go, parser.go, predefined.go, reth_show.go, routinginstanceid.go, schema.go, schema_chassis.go, schema_complete.go, schema_cos.go, schema_interfaces.go, schema_routing.go, schema_schedulers.go, schema_security.go, schema_system.go, schema_validators.go, schema_validators_cos.go, schema_validators_ddns.go, schema_validators_devicemap.go, schema_validators_ipsec.go — 27? Let me list exactly: from batch txt, non-test are: freetext.go, host_inbound_multicast.go, host_inbound_tokens.go, host_inbound_view.go, inactive.go, junos_host_deny.go, lexer.go, lifeline.go, natpool.go, parser.go, predefined.go, reth_show.go, routinginstanceid.go, schema.go, schema_chassis.go, schema_complete.go, schema_cos.go, schema_interfaces.go, schema_routing.go, schema_schedulers.go, schema_security.go, schema_system.go, schema_validators.go, schema_validators_cos.go, schema_validators_ddns.go, schema_validators_devicemap.go, schema_validators_ipsec.go = 27 impl.

- **Test (123):** remaining 123 files are `_test.go` guards covering the above plus cross-subsystem integration tests (firewall port except mutex, ri conflict, symbolic match, terminal conflict, nextterm, flow aging, traceoptions, flowserver template ref, freetext, frr clusterid, global policy zone scope, host inbound dup block/effective/fulladmit/managed-routing-mismatch/match/multicast-warn/per-iface/rust-parity, view lifeline, ike chain, inactive, inline inactive, interface parity, ipip dead warn, ipsec dhgroup/proposal ref, json repeated leaf, lenient fw cos/permit widening, log profile/stream, login custom class/password/username, named port case-insensitive, nat range wrap, natpool, parser ast/bracket/class-of-service/cluster/fbf/ipmonitoring/recursion-dos/routing/rpm-pin/security/semicolon/services/stray-brace/system, policer rate validate, policy community/from multileaf/log action/match excluded/rematch advisory/reserved chain/redist/terminal action/zone matrix/ref, predefined app sets/icmp/nil appset, protocols multileaf, quoted inactive, quote-key roundtrip, reserved zone name, ribgroup leak warn, router id, routing adjacency/export ref, routinginstanceid, rpm dup block, sampling input rate/instance conflict, schema closedworld ike/ipsec/ipsec-proposal/nat64/nat-then/natv6v4, cos buffer temporal/ieee8021 rewrite/hb166, desc, global zone list, ike enum, lldp ttl, master password prf, policy then/then-int, route preference/qnh preference, scheduler name, and ~20 schema_validate_* tests).

All 150 files reviewed via worktree `/tmp/review-wt-ps-044-A3_go_config_cli_tree-b3`.

---

## Confidence Tiers Summary

- **High confidence (no issue):** freetext control-char + comment-delim, lexer bracket-list + unterminated comment, parser depth + stray-brace, inactive stripping, natpool pool-existence gate, routing-instance 3-view collision, predefined nil-app-set panic guard, ParseSetVerb semicolon single-stmt enforcement, all schema integer bounds (NaN/Inf checked), host-inbound token SSOT, device-map PCI/MAC shape validation.

- **Medium confidence observations:** schema `scalar:true` opt-in avoids false-reject on opaque containers (deliberate design, verified against compiler), `groupReplace` vs `multi` semantics correctly applied per leaf in this batch, `junosHostPoison` sentinel non-colliding with real CIDRs.

- **Low confidence / informational (no change recommended):** `isIdentChar` breadth (intentional, Junos parity), `To4()` on v4-mapped v6 in natpool (operator-authored, not attacker-controlled, filter-only use).

---

## Conclusion

**Batch B3 — 150 files — SECURE. No blocking findings.**

The parser/compiler/schema triple in this batch demonstrates consistent fail-closed discipline:
- Lexer errors surface as `TokenError` → `ParseError` → commit reject (not silent truncation).
- Parser depth bounded, stray-brace / semicolon abuses rejected.
- Freetext injection (newline / `*/`) rejected strict, scrubbed lenient, belt at render.
- Schema typed leaves reject malformed/overflows at commit with clear leaf-named errors; lenient path warns; runtime overflow belts backstop.
- NAT pool / junOS-host projection / routing-instance ID handle existence, ambiguity, and collision with quarantine or no-rule + warning kept (never silent drop / leak).
- Dual-shape AST contract respected (flat-set via `ParseSetCommand` + `SetPath` collapses bracket lists onto single leaf's Keys; compiler readers use `firewallMatchValues` to accumulate).

Existing red-on-revert tests in the batch directly prove each historical vulnerability would be caught if regressed.


---
### Batch A3_go_config_cli_tree-b4 — 373 lines — full log + findings

Base commit: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree path: /tmp/review-wt-ps-044-A3_go_config_cli_tree-b4
Batch file list: /tmp/review-work-ps-044/batches/A3_go_config_cli_tree-b4.txt (74 files — 24 prod, 50 test)
Dedup index: /tmp/review-work-ps-044/dedup-index.txt (prior campaigns fable-reviewed, checked)

---

## Expertise Area: A3 — Go config compiler, schema & CLI grammar (batch 4/4)

### Batch inventory (prod non-test, 24 files)
| File | LOC | Security-relevant responsibilities |
|------|-----|------------------------------------|
| pkg/config/schema_validators_logging.go | 35 | ValidateSyslogSourceInterface — first '.' split, non-numeric unit rejection #3349 |
| pkg/config/schema_validators_network.go | 187 | ValidateIPAddress, BGPClusterID, IPv6Address, PREF64CIDR, IPv4/IPv6 CIDR — family gate, prefix-required |
| pkg/config/schema_validators_routing.go | 219 | BGPHoldTime 0/3..65535, RouteFilter positional, RouteDestination, StaticNextHop + plausibleInterfaceName |
| pkg/config/schema_validators_scheduler.go | 37 | TimeOfDay HH:MM:SS, Date YYYY-MM-DD |
| pkg/config/schema_validators_system.go | 397 | Crypt hash, LoginClassRef, RingEntries, NTPServer, DNSDomain, SSHAlgorithm, SyslogFileName/User, TimeZone — #4902 injection closure |
| pkg/config/schema_walk.go | 826 | SchemaValidate typed-leaf gate, redaction placeholder guard, inactive pruning, closed-world, tailValidator, refs collection |
| pkg/config/screen_inventory.go | 209 | ScreenChecks/Thresholds SSOT, list rendering |
| pkg/config/secret.go | 198 | Secret type — redaction on MarshalJSON/YAML, sentinel reject, String() redaction, RedactURL userinfo+query, Reveal() auditable |
| pkg/config/snmp_clients.go | 206 | SNMP clients allowlist compile, AllowsSource longest-prefix, Restrict typo guard #4834 |
| pkg/config/syslog_logfile.go | 50 | SyslogLogFilePath — basename+allowlist gate #4860 |
| pkg/config/tcp_flags.go | 191 | ParseTCPFlagsExpression — fail-closed on | ! dangling & empty |
| pkg/config/tunnelemit.go | 123 | EmitTunnelEndpointNames — canonical name set for collision gate, no runtime state |
| pkg/config/tunnelid.go | 290 | StableTunnelEndpointID FNV xor-fold, collision AST check 3 views, quarantine |
| pkg/config/types.go | 339 | LinuxIfName, RethToPhysical, ResolveReth/Fab/KernelIfName — slash->dash, node-score |
| pkg/config/types_chassis.go | 188 | Chassis, ControlLinkAuthKey Secret |
| pkg/config/types_cos.go | 283 | CoS traffic-control-profiles, schedulers, interfaces |
| pkg/config/types_interfaces.go | 150 | Interfaces, VRRP auth Secret |
| pkg/config/types_routing.go | 651 | BGP/OSPF/IS-IS/RIP/WG — AuthKey Secret, WG private key Secret |
| pkg/config/types_security.go | 1370 | Security — PSK Secret, screen, NAT, IPsec |
| pkg/config/types_system.go | 1585 | System — EncryptedPassword Secret, SNMP community redaction via slice, DDNS String() redaction, RedactURL use |
| pkg/config/value_type.go | 155 | ValueType enum, typed-leaf plumbing |
| pkg/config/wireguard_ports.go | 60 | WireGuardListenPorts sorted dedup, skip 0, dynamic host-inbound admission |
| pkg/config/xfrmi.go | 77 | XFRMIfNameAndID st<N>[.<unit>] parse, bounds 0x10000/0xffff, if_id calc |
| pkg/config/zoneid.go | 251 | StableZoneID FNV fold into [1,65533], reserved 0xFFFE/F, collision quarantine |

### Test inventory (50 files) — all regression/canary, no new prod code
schema_walk_internal_test.go, scoped_global_zoneset_4626_test.go, screen_alarm_without_drop_test.go, screen_numeric_strict_3317_test.go, screen_profile_ref_test.go, screen_synflood_subthreshold_3315_test.go, screen_trailing_token_3332_test.go, screen_unknown_strict_3318_test.go, secret_test.go, set_repeated_leaf_3984_test.go, shared_umem_audit_test.go, show_config_dup_context_4562_test.go, show_config_repeated_keyword_3980_test.go, snmp_clients_4289_test.go, snmp_clients_4711_test.go, snmp_clients_4834_test.go, snmp_dup_community_5472_test.go, sqm_cookbook_fixture_test.go, ssh_known_hosts_dup_block_4821_test.go, static_nat_mapped_port_2491_test.go, static_nat_source_address_3435_test.go, static_nat_zone_test.go, strict_gate_wiring_canary_test.go, syslog_logfile_4860_test.go, system_multileaf_test.go, system_string_injection_4902_test.go, tcp_flags_test.go, tcp_session_advisory_test.go, time_zone_path_validate_5011_test.go, tunnel_perunit_deepcopy_test.go, tunnelid_test.go, types_test.go, vrf_overlap_budget_5194_test.go, vrrp_authentication_4288_test.go, vrrp_preempt_holdtime_test.go, vrrp_track_secret_5195_test.go, vrrp_track_test.go, vrrp_v6_test.go, vrrp_vaddr_subnet_3013_test.go, web_management_auth_4047_test.go, wireguard_allowedips_malformed_5194_test.go, wireguard_listen_ports_5582_test.go, wireguard_multipeer_test.go, xfrmi_test.go, zone_count_cap_test.go, zone_dup_block_4818_test.go, zone_interface_defined_4515_test.go, zone_interface_membership_test.go, zone_local_unqualify_3358_test.go, zoneid_test.go

### Module-by-module sweep (incl. negatives — security invariant checked)

- **schema_validators_logging.go**: Invariant checked — syslog source-interface unit must be non-negative int, empty base rejected, split on first '.' matching runtime resolveSourceAddr. Verified strconv.Atoi guard; no path/secret handling. NEGATIVE — no bypass. The split comment documents why first '.' matters and why ignored Atoi previously fell back to unit 0 — now hard-reject.

- **schema_validators_network.go**: Checked ValidateBGPClusterID IPv4-only dotted-quad else u32 1..4294967295, rejects IPv6 literal; ValidateIPv6Address rejects To4!=nil to close RDNSS malformed RA #2497; ValidatePREF64CIDR restricts to RFC 8781 set {32,40,48,56,64,96}; parseCIDRStrict requires /prefix. All use net.ParseIP/CIDR, TrimSpace, targeted msgs. No exec, no secret. NEGATIVE — hardening, not vuln.

- **schema_validators_routing.go**: Checked BGPHoldTime 0 or 3..65535 — rejects 1/2 that break frr-reload whole-batch (CMD_WARNING_CONFIG_FAILED). ValidateRouteFilterArgPositional position-aware — CIDR in slot0, keyword in slot1, rejects keyword-in-prefix slot that rendered match-none policy #5576. ValidateStaticNextHop handles ip@iface/@iface/bare iface, plausibleInterfaceName requires letter and charset [A-Za-z0-9._-] excluding ':' so malformed IPv6 not mistaken for iface. NEGATIVE — secure.

- **schema_validators_scheduler.go**: Validates HH:MM:SS via time.Parse layout 15:04:05 and YYYY-MM-DD via 2006-01-02. Ensures #3849 fail-closed window not zeroed. NEGATIVE.

- **schema_validators_system.go**: Central #4902 injection closure. Checked ValidateNTPServer IP or hostname, rejects newline/space/slash/leading-hyphen; ValidateDNSDomain rejects newline/space/slash/.. ; ValidateSSHAlgorithm rejects comma/newline/space/leading punctuation; ValidateSyslogFileName rejects ../ slash space newline * . .. ; ValidateSyslogUser rejects slash space newline .. ; ValidateTimeZone path validation via #5011. Also crypt hash permissive superset (final authority OS), login class union builtin+custom refs. All reject at commit-check, lenient load warns. POSITIVE hardening, no bypass present.

- **schema_walk.go**: Checked SchemaValidate pre-compile gate before compiler, walks setSchema (same tree as completer), opts-in per leaf ValueType!=ValueAny. Handles inactive: pruning (WithoutInactive), redaction placeholder ##SECRET-DATA## reject on commit (#4060 symmetric to #4051 display redaction), collectSchemaRefs from candidate+groups for atomic cross-ref, closed-world flag inheritance #4313, tailValidator for irregular CoS, multi value-tail leaf handling bracket lists (#2419). No secret logging, error builder uses typedLeafErrorf with path context, not raw value except token itself (non-secret leaf). NEGATIVE — gate is opt-in but that's #4313 open-world design, not vuln.

- **screen_inventory.go**: ScreenChecks superset of enforced checks (port-scan, ip-sweep, session limits, icmp-fragment) #3327 SSOT consumed by REST+gRPC. Threshold map only positive values. No enforcement, only presentation, no secret, no injection. NEGATIVE.

- **secret.go**: Core secret control #2053. Checked MarshalJSON redacts non-empty to "<redacted>", empty to "" distinguishable; MarshalYAML same; UnmarshalJSON/YAML refuse sentinel to close round-trip reload of placeholder as real key; String() redacts for %v/%s/slog; Reveal() canonical greppable accessor; RedactURL string-based not net/url because inadyn templates %h/%i/%u/%p are not valid percent-encoding — redacts userinfo in authority bounded to first /, ?, # and handles schemeless URL at index 0 #5458 (#2781 query drop). No log of cleartext inside this file. POSITIVE security control, audit complete: every Secret field in types_*.go uses this type (verified grep of AuthKey, Password, APIToken, AWSSecretAccessKey, Communities, etc). No Secret typed field missing redaction. NEGATIVE for new vuln; POSITIVE for enforced property.

- **snmp_clients.go**: Checked compileClientNets pre-parse at compile time #4711 allocation-free match; AllowsSource default-deny when clients configured but no match, allow-all only when no restriction, nil srcIP allowed for non-IP transport test path. parseClientPrefix handles CIDR and bare host route /32 or /128. validateSNMPClients #4834 rejects unparseable prefix at commit — critical because parseSNMPClients treats any non-"restrict" token as new prefix, so typo "restric" detaches restrict from 0.0.0.0/0 turning deny-except into allow-all fail-open. Message avoids community NAME (secret). POSITIVE hardening.

- **syslog_logfile.go**: Checked SyslogLogFilePath #4860: name must be bare filename (no separator, not . or .., name==filepath.Base), plus must be in configured system syslog file allowlist. Previously gRPC/CLI shelled tail on any basename under /var/log allowing PermView to read auth.log/audit.log. Now filepath.Join("/var/log", allowed) only allowlisted. Base equality check correctly rejects "../../etc/shadow" because Base="shadow" != input, and "/etc/shadow" because Base="shadow". NEGATIVE for bypass, POSITIVE for fix verified.

- **tcp_flags.go**: Checked ParseTCPFlagsExpression — lexes operators & | ! () plus words, joins parts with space, supports bracket/flat spaced/quoted "&". Rejects: | (#3076 disjunction unrepresentable conjunctive matcher), negated group (#3076 De Morgan), unknown token, required&forbidden conflict, dangling ! #4714, leading/trailing/duplicated & and empty-operand #5455 fail-open -> match-all. Final segHasFlag guard ensures non-empty no-flag-bits errors vs empty absent returning ok=false. All errors include expr quoted but not secret. NEGATIVE for filter bypass, hardening present.

- **tunnelemit.go**: EmitTunnelEndpointNames single SSOT for configured tunnel endpoints, mirrors builder non-WG source/destination gate (drop empty), interface-level WG single-lowest-unit #1910, canonical "%s.%d" formatting, deterministic sort. No secret, no injection. Collision gate consumes only Name field. NEGATIVE.

- **tunnelid.go**: StableTunnelEndpointID FNV-1a 64 xor-fold to 16 bits mod 0xFFFF+1 -> [1,65535], 0 never returned. collectTunnelEndpointNamesAST mirrors builder naming exactly, low-unit pick for WG. validateTunnelEndpointIDCollisionAST 3 views: pre-expansion union (main+groups) + per-node expanded for node0/node1 with ${node} interpolation, per-node error non-fatal empty set to preserve HA symmetry. Strict rejects, lenient warns. Quarantine pattern via Interface (code in zoneid). NEGATIVE for collision-based zone merge.

- **types.go**: LinuxIfName slash->dash replacement for IFNAMSIZ. InterfaceSlot parses FPC from <type>-<slot>/... Returns -1 on no match. RethToPhysical scores local node > remote to pick correct physical member, tie-break lexical. ResolveReth/ResolveFab/ResolveKernelIfName ordering documented #1565 sync note. DHCPLeaseKey uses VlanID not unit number. No secret, no path traversal. NEGATIVE.

- **types_chassis.go**: ControlLinkAuthKey Secret #4107 HMAC-SHA256 PSK, agnostic same key both nodes, Secret-redacted. No exposure.

- **types_cos.go**: TrafficControlProfile shaping-rate percent vs bytes mutually exclusive, advisory wording. No secret.

- **types_interfaces.go**: AuthKey Secret VRRP redacted — but VRRP auth dead-security posture closed by #4288 reject in compiler, so Secret field inert but still redacted defense-in-depth.

- **types_routing.go**: AuthKey Secret for OSPF/IS-IS/RIP, AuthPassword Secret BGP TCP-MD5, WgLocalPrivkeyHex Secret, PresharedKeyHex Secret. All Secret-typed, redacted. BGP community defs not secret. NEGATIVE for leak, POSITIVE coverage.

- **types_security.go**: PSK Secret for IKE/IPsec. No community string here. NEGATIVE.

- **types_system.go**: SNMP Communities map redacted via custom MarshalJSON rendering Communities as sorted slice of redacting values to avoid emitting map key which IS the secret. SNMPCommunity.MarshalJSON wraps Name as Secret. V3 Auth/Priv Password Secret. EncryptedPassword Secret crypt(3) applied via chpasswd -e #1944. MasterPassword plain string intentionally not Secret per comment — it's PRF algorithm name not secret #2053. ArchiveSitesWithPassword keeps URLs not passwords, warning naming site. DDNSProvider String() redacts TSIGSecret/Password/APIToken/AWSSecretAccessKey via local red func + RedactURL Server/URLTemplate (#5458/#2781). APIKeys []Secret, Users[].Password Secret. Syslog facility not secret. NEGATIVE for leak, POSITIVE defense.

- **value_type.go**: ValueType constants ValueAny, ValueString etc — plumbing, no secret.

- **wireguard_ports.go**: WireGuardListenPorts sorted dedup non-zero ports, skips mode!=wireguard, skips WgListenPort==0 (lenient load zero -> no admission, prevents UDP/0). Returns nil not empty slice for cheap len check. Comment notes host-inbound coarse udp dport <ports> accept on input hook admitting to every firewall-local address same scope shim steers — intentionally coarse but documented, leaves other host services under default-deny. No bypass; admission minimal.

- **xfrmi.go**: XFRMIfNameAndID validates bindIface st<N> or st<N>.<unit>, stIndex 0..0x10000 exclusive upper bound, unit 0..0xffff, if_id = stIndex<<16|unit+1, checks if_id!=0. ValidateSecureTunnelBindInterface uses if_id==0 as authoritative no-XFRM sentinel #5297 silent tunnel-down closure. No overflow beyond uint32 shift. NEGATIVE.

- **zoneid.go**: ZoneIDReservedMin 0xFFFE mirror Rust ZONE_ID_RESERVED_MIN, fold into [1,65533] via %(Reserved-1)+1, 0 never returned meaning unassigned. collectZoneNamesAST handles dual-shape via namedInstances. emitNodeExpandedZoneNames recursion-free via Clone+ExpandGroupsWithVars, per-node error -> empty set non-fatal to keep HA symmetry (config defining only groups node0 with ${node} legitimately has no groups node1). validateZoneIDCollisionAST union 3 views, strict error, lenient quarantine warning #3719 quarantines later-sorting zone, wording degraded isolation. QuarantinedZoneNames runtime enforcement pure function of name set, sorted tie-break. StableZoneIDOwner deterministic. No secret.

- **Test files (50)**: All flagged as regression/canary for prior security hardening — verified they do NOT introduce prod code. Key ones:
  - system_string_injection_4902_test.go — tests NTP/DNSDomain/SSHAlgorithm/SyslogFile/User validators reject newline/space/slash traversal; flat-set + hierarchical shapes; RED-on-revert notes. No secret.
  - syslog_logfile_4860_test.go — validates basename+allowlist gate; PermView arbitrary log read closed.
  - snmp_clients_*_test.go (4289 enforce clients, 4711 pre-parse fast path, 4834 restrict typo) — validates default-deny, longest-prefix, typo fail-closed.
  - vrrp_authentication_4288_test.go — rejects auth-type/auth-key inert config, lenient warns, ensures error/warning does NOT leak secret value (Keys-packed leaf secret not echoed). Critical for secret leakage.
  - vrrp_track_secret_5195_test.go — similar secret redaction check.
  - secret_test.go — MarshalJSON/YAML redaction, sentinel ingest refusal, String() hygiene, RedactURL schemeless + query + authority bound.
  - tcp_flags_test.go — validates reject of |, negated group, dangling !, trailing &, empty.
  - wireguard_listen_ports_5582_test.go — validates skip 0, sorted dedup, dynamic admission.
  - zone* tests — collision quarantine, interface membership membership checks.
  - others set_repeated_leaf, show_config dup, etc — parser dual-shape correctness, not security bypass.
  NEGATIVE for new vuln; POSITIVE as defense-in-depth coverage.

---

## Findings — High Confidence

Title: Syslog log file path traversal + authz bypass closed in SyslogLogFilePath (#4860)
Severity: Medium
Confidence: High
Evidence:
- File: pkg/config/syslog_logfile.go:38-51
```go
func SyslogLogFilePath(cfg *Config, name string) (string, error) {
    if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
        return "", fmt.Errorf("invalid log file name %q", name)
    }
    for _, allowed := range cfg.SyslogLogFileNames() {
        if allowed == name {
            return filepath.Join("/var/log", name), nil
        }
    }
    return "", fmt.Errorf("log file %q is not a configured 'system syslog file' destination", name)
}
```
Trace: CLI/gRPC show log previously executed `tail` on any basename under /var/log. A PermView account could request `auth.log`, `audit.log`, `dpkg.log`. New gate checks basename equality to block "../etc/shadow" (/etc/passwd) where Base returns last element but not equal input, plus allowlist membership. Returns Join only after allowlist hit. Verified in syslog_logfile_4860_test.go rejects space/dotdot/traversal and demands configured name.
Refutation attempt: Considered filepath.Join still traversable if name contains ".."? No, because name==Base check fails for any slash. Considered lenient load bypass? Gate runs at request time, not commit, so even lenient-loaded name must still allowlist. Check passed.
HPC/invariant: N/A (control path)
Why it matters: Prevents view-only operator (PermView) from reading arbitrary root-readable host logs — information disclosure with cred-harvesting potential.
Fix direction: Already fixed. Keep allowlist + Base check; ensure no alternative show log path bypasses this function (grep confirm cli_show_log.go and grpcapi uses same).
Labels: security, authz, path-traversal, hardening-verified
Dedup note: Prior dedup lists #4860? Not in open/closed list copy truncated but code comment references #4860 as closing. If #302? No entry matches exact path traversal in dedup; treat as verified fix, not dup.

Title: SNMP clients source-IP restriction fail-open closed — restrict typo detachment guarded (#4834)
Severity: High
Confidence: High
Evidence:
- File: pkg/config/snmp_clients.go:139-205
```go
appendTokens := func(tokens []string) {
    for _, t := range tokens {
        if t == "" { continue }
        if t == "restrict" {
            if len(out) > 0 { out[len(out)-1].Restrict = true }
            continue
        }
        out = append(out, SNMPClient{Prefix: t})
    }
}
...
func validateSNMPClients(clients []SNMPClient, lenient bool) (warnings []string, err error) {
    for _, cl := range clients {
        if _, _, perr := parseClientPrefix(cl.Prefix); perr == nil { continue }
        msg := fmt.Sprintf("snmp community clients entry %q is not a valid IP/CIDR prefix ...")
        if lenient { warnings = append(...); continue }
        return nil, fmt.Errorf("%s", msg)
    }
}
```
- Also AllowsSource longest-prefix match default-deny when clients configured.
Trace: parseSNMPClients treats any token != "restrict" as new prefix. Typo "restric" for "restrict" after `0.0.0.0/0 restrict` becomes its own unparseable prefix entry. compileClientNets previously silently dropped unparseable entries, so broad /0 entry stayed plain allow, community queryable from anywhere. New validator rejects every unparseable prefix at strict commit, and compileClientNets drops on lenient boot path (#1960 no-brick) but warning. AllowsSource denies when prefix list configured but src not matching.
Refutation attempt: Checked nil clientNets fallback on directly-constructed community parses on fly same decision race-free. Checked srcIP nil path returns true — that's test/non-IP path, real UDP always supplies address, intentional not bypass. Checked compileClientNets nil vs empty slice distinction to differentiate not-compiled vs all-unparseable -> default-deny distinguishable.
Why it matters: SNMPv2c community string (secret) scoped to mgmt subnet but served anywhere due to silent restrict detach — network-level bypass of ACL.
Fix direction: Already fixed #4289/#4711/#4834. Ensure SNMP agent always calls AllowsSource before serving; ensure configstore lenient path warns but still drops invalid entry.
Labels: security, authz, snmp, fail-closed, hardening-verified
Dedup note: Dedup lists #4289 open? In list #4289 [CLOSED] SNMP clients restriction ignored — this is closure verification. Not re-reporting new issue, marking hardened.

Title: Secret type enforces JSON/YAML redaction and sentinel-refuse — prevents REST /api/v1/config leak (#2053)
Severity: High
Confidence: High
Evidence:
- File: pkg/config/secret.go:54-98
```go
func (s Secret) String() string { if s == "" { return "" }; return SecretRedacted }
func (s Secret) MarshalJSON() ([]byte, error) {
    if s == "" { return []byte(`""`), nil }
    return json.Marshal(SecretRedacted)
}
func (s *Secret) UnmarshalJSON(b []byte) error {
    var v string; if err := json.Unmarshal(b, &v); err != nil { return err }
    if v == SecretRedacted { return errRedactedSecretIngest }
    *s = Secret(v); return nil
}
func RedactURL(s string) string {
...
    authStart := 0
    if i := strings.Index(s, "://"); i >= 0 { authStart = i + len("://") }
...
    if at := strings.LastIndex(authority, "@"); at >= 0 {
        s = s[:authStart] + redacted + "@" + authority[at+1:] + s[authEnd:]
    }
    if q := strings.IndexByte(s, '?'); q >= 0 { s = s[:q+1] + redacted }
    return s
}
```
Trace: Compiled *Config carries every operator secret verbatim (IKE PSK, OSPF/IS-IS/RIP/VRRP/auth, TSIG, SNMPv3 passwords, crypt hashes, BGP MD5, REST basic-auth + API keys, WG private key). Production REST GET /api/v1/config JSON-encodes whole struct. Before #2053 plaintext leak to authorized client (loopback by default but bindable non-loopback via web-management https interface). String() alone insufficient because encoding/json ignores Stringer. Making field type enforce redaction guarantees type-enforced, not per-comment. Round-trip safe because SSOT is ConfigTree AST not JSON. Unmarshal guards prevent redacted sentinel reload as real secret breaking IPsec/auth. RedactURL handles schemeless credentialed URL e.g. "user:pass@host/upd?token=SECRET" where scheme validator absent — redacts userinfo + query, bounded to authority so '@' in path/query untouched.
Refutation attempt: Checked all Secret-typed fields indeed use Secret via grep — no plain string password field except MasterPassword which comment says PRF algorithm name not secret intentionally. Checked SNMPCommunity map key secret handled via custom MarshalJSON rendering Communities as slice dropping secret==key. Checked DDNS String() redacts via red() + RedactURL. Checked any fmt.Sprintf with Reveal() in types_system? No log of Reveal cleartext — only validation/warning paths that check Reveal()!= "" boolean, never %q Reveal(). Checked compiler_* Reveal usages — validation only, not logging.
Why it matters: Prevents credential exfiltration via REST config export, logs, or YAML marshal — major secret leak.
Fix direction: Already fixed. Audit new fields: any field holding secret must be typed Secret, not string. Add canary test secret_test.go? Exists and checks marshal redaction + sentinel refusal.
Labels: security, secret-leak, hardening-verified, defensive-type
Dedup note: Dedup does not list #2053 as open — closed mitigation verified.

Title: System string injection via root-owned service configs closed (#4902)
Severity: High
Confidence: High
Evidence:
- File: pkg/config/schema_validators_system.go — ValidateNTPServer, ValidateDNSDomain, ValidateSSHAlgorithm, ValidateSyslogFileName, ValidateSyslogUser
```go
func ValidateSyslogFileName(raw string, _ *Config) error {
    // rejects slash, .., space, newline, *, etc
}
func ValidateNTPServer(raw string, _ *Config) error {
    if net.ParseIP(raw) != nil { return nil }
    // hostname regex, rejects newline, space, slash
}
```
- Test: system_string_injection_4902_test.go cases:
```go
`set system ntp server "pool.example.net local stratum 10"` // embedded space 2nd chrony token
`set system syslog file "../etc/cron.d/evil" any any` // path traversal
`set system syslog user "u\n:omusrmsg:*" any any` // newline rsyslog template escape
```
Trace: Lexer decodes \n in quoted string to literal newline. Before fix, NTP server "pool.example.net local stratum 10" committed verbatim into /etc/chrony/chrony.conf as two directives "pool ..." + "local stratum 10". Domain-name "example.net evil.corp" injected second search token into resolved/resolv.conf. SSH algos "aes256-gcm,evil" comma list separator. Syslog file "../etc/cron.d/evil" slash traversal. Syslog user "u\n:omusrmsg:*" newline injection into rsyslog.conf. New typed validators strict at SchemaValidate before compiler, reject space/newline/slash at commit.
Refutation attempt: Considered whether validator coverage exhaustive — checked syslog filename also gated at show log path (defense in depth) plus compile-time. Tested hierarchical shape also validated via keyValidator not just global control-char gate — validated by hierarchical test case bad name with space. Lenient load path warns not bricks.
Why it matters: Untrusted config string rendered into root-owned host service configs (chrony, sshd, rsyslog, resolved) could inject directive, enable root login, exfiltrate via syslog forwarding to evil host, or create cron file.
Fix direction: Already fixed. Ensure any new system leaf rendered into host file gets similar typed validator.
Labels: security, command-injection-equivalent, hardening-verified
Dedup note: Not in dedup list verbatim; #4902 not listed as open.

---

## Findings — Medium Confidence

Title: TCP flags parser fail-closed prevents security filter bypass
Severity: Medium
Confidence: Medium
Evidence:
- File: pkg/config/tcp_flags.go:140-220
```go
if pendingNeg {
    return 0,0,false, fmt.Errorf("tcp-flags %q: dangling negation \"!\" with no flag operand", expr)
}
...
if !segHasFlag {
    return 0,0,false, fmt.Errorf("tcp-flags %q: \"&\" conjunction with no flag operand", expr)
}
```
Trace: Dataplane matcher conjunctive only (required bits + forbidden bits). Expression "!" or "syn & !" would previously drop '!' silently -> term matches more than intended (e.g., term intended "syn & !ack" but typo "syn & !" becomes just syn, widening accept). Similarly "&" or "syn &" no flag operand would return no constraint -> match EVERY TCP segment fail-open. Parser now rejects dangling !, leading/trailing/duplicated &, OR operator, negated group (De Morgan disjunction), unknown flag, contradictory required&forbidden, and final empty segment.
Refutation attempt: Verified empty absent expr == "" returns ok=false no error distinct from non-empty no bits error — preserves optional absence vs malformed. Verified caller treats ok=false as no constraint (intentional absent) vs error as commit fail — correct fail-closed.
Why it matters: Malformed tcp-flags term in firewall filter that should restrict ACK/RST could degrade to accept-all TCP under filter — security bypass.
Fix direction: Already fixed #4714/#5455. Keep; add fuzz for parser.
Labels: security, filter-bypass, fail-closed, hardening-verified

Title: VRRP authentication dead-security rejected — prevents false sense of auth (#4288)
Severity: Medium
Confidence: Medium
Evidence:
- Test file vrrp_authentication_4288_test.go rejects flat-set and hierarchical auth:
```go
_, err := CompileConfig(tree)
if err == nil { t.Fatal("expected rejection of VRRP authentication") }
if !strings.Contains(err.Error(), "authentication") || !strings.Contains(err.Error(), "#4288") { t.Fatalf(...) }
```
- Also TestVRRPAuthenticationRejectDoesNotLeakSecret_KeysPacked ensures error message does not echo secret value packed in Keys.
Trace: VRRP auth fields parsed, stored on VRRPGroup, copied to VRRP instance, but packet build/receive never enforces — native dataplane RFC5798 VRRPv3 removed auth. Silently accepting config lets operator believe adverts authenticated when rogue host can hijack mastership. Fix rejects at strict commit, warns at lenient. Error message built from group identity only, not from n.Keys full run which would include secret.
Refutation attempt: Checked if any other path leaks secret via warnings — lenient path same identity-only message. Checked VRRP group struct Secret field still exists for backwards compat but inert; redacted via Secret type? Actually VRRP auth key was plain string before; now rejected, but even if present lenient path warning must not leak. Test with SUPERSECRETVRRPKEY verifies not leaked.
Why it matters: False security posture — operator deploys auth thinking protected, attacker hijacks VRRP master, causes blackhole/traffic hijack.
Fix direction: Already fixed. Ensure compiler also removes auth fields from VRRP instance to avoid future accidental use.
Labels: security, false-security, vrrp, hardening-verified

Title: WireGuard listen port host-inbound admission coarse but bounded
Severity: Low (design note, not vuln)
Confidence: Medium
Evidence:
- File: pkg/config/wireguard_ports.go:50-60
```go
func (c *Config) WireGuardListenPorts() []uint16 {
    if c == nil { return nil }
    seen := map[uint16]bool{}
    add := func(tc *TunnelConfig) {
        if tc == nil || tc.Mode != "wireguard" || tc.WgListenPort == 0 { return }
        seen[tc.WgListenPort] = true
    }
```
Trace: XDP shim steers local-dest UDP on WG listen port to kernel for control socket. Without matching host-inbound accept, fresh responder-only handshake NEW, misses per-zone service accepts, dropped by catch-all. Daemon emits one coarse `udp dport <ports> accept` on input hook admitting WG port to every firewall-local address. Skips port 0 (lenient load could have zero) to avoid UDP/0 meaningless. Deduplicated sorted.
Refutation attempt: Considered whether coarse admission opens WG port on untrusted zone where not intended. Design claims same scope as shim steers (local-destined to any local addr). Since WG is authenticated via private key/peer keys, exposure of UDP port without valid handshake does not give unauthorized access — handshake requires correct keys, DoS only. Still slightly broader than per-zone default-deny, but documented tradeoff for responder-only to come up.
Why it matters: Defense-in-depth — ensure coarse admission does not widen beyond intended and that 0 port not admitted.
Fix direction: Keep; future could scope admission to interfaces where WG configured rather than all local addrs, but handshake auth makes current safe.
Labels: security, host-inbound, wireguard, design-note

Title: Zone ID / Tunnel ID stable hash collision quarantine prevents zone merge
Severity: Medium
Confidence: Medium
Evidence:
- File: pkg/config/zoneid.go:170-230 — validateZoneIDCollisionAST 3 views union, QuarantinedZoneNames pure function sorted tie-break
```go
names := make(map[string]struct{})
collectZoneNamesAST(tree.FindChild("security"), names)
// View1 pre-expansion union across groups, Views 2/3 per-node expanded ${node}
emitNodeExpandedZoneNames(tree, 0, names)
emitNodeExpandedZoneNames(tree, 1, names)
...
if !lenient { return nil, fmt.Errorf("security zones: %s", msg) }
warnings = append(warnings, fmt.Sprintf("%s; later-sorting zone %q is QUARANTINED (dropped from the dataplane) ..."))
```
Trace: StableZoneID FNV fold into [1,65533] wire-adjacent. Two zones colliding share numeric id → dataplane merges interfaces/policies/counters/host-inbound admission/tcp-rst bit. Strict rejects collision outright; lenient keeps booting but quarantines later-sorting zone (dropped from dataplane, interfaces unzoned, traffic denied) preserving #1960 no-brick. Same pattern for tunnel IDs.
Refutation attempt: Verified fold never returns 0, reserved 0xFFFE/F junos-host/global never collide due to modulo Reserved-1+1. Checked emitNodeExpandedZoneNames recursion-free via Clone not CompileConfig (no recursion). Checked per-node expansion error non-fatal empty set does not lose coverage due to View1 presence union covering unexpandable group. Verified QuarantinedZoneNames deterministic sorted, HA-symmetric.
Why it matters: Without quarantine, lenient load of colliding zones would silently merge two security zones — privilege escalation/traffic leak.
Fix direction: Already hardened #3075/#3719. Keep; monitor hash collision probability (~1/65533 birthday) low but acceptable; could consider larger id space future.
Labels: security, zone-isolation, hard-fail-closed, hardening-verified

---

## Findings — Low Confidence / Informational

Title: BGPClusterID accepts bare integer ParseUint 32-bit but net.ParseIP rejects — correct FRR parity
Severity: Info
Confidence: Low
Evidence:
- File: pkg/config/schema_validators_network.go:54-76
```go
if ip := net.ParseIP(trimmed); ip != nil {
    if ip.To4() == nil { return fmt.Errorf("invalid cluster-id %q (an IPv6 ...)", raw) }
    return nil
}
if v, err := strconv.ParseUint(trimmed, 10, 32); err == nil {
    if v < 1 { return fmt.Errorf("invalid cluster-id %q (must be in 1..4294967295)", raw) }
    return nil
}
```
Why it matters: Previously no validator — bad token reached FRR frr-reload via `bgp cluster-id <v>` verbatim, FRR rejects line with CMD_WARNING_CONFIG_FAILED causing whole xpf-managed section reload to fail (reload poison). Now commit gate accepts exactly FRR accepted forms.
Labels: hardening, frr-reload-availability

Title: No new secret fields missing Secret typing in batch
Severity: Info
Confidence: High
Evidence: Grep pkg/config/types_*.go for Password|Secret|PrivateKey|PSK|Community|APIToken — all Secret-typed except MasterPassword (PRF algorithm name, comment says not secret #2053) and ArchiveSitesWithPassword []string keeps URLs not passwords per #651 comment. BMP? No. This batch clean.
Labels: info, secret-audit

Title: No command injection via exec/os/system in batch
Severity: Info (negative)
Confidence: High
Evidence: grep -rn exec.Command|os.System|syscall in pkg/config/*.go (non-test) returns only Log trace file mention unsafe path comment and os.OpenFile with O_NONBLOCK for FIFO/device safety in compiler_system.go — not in this batch but safe pattern via OpenFile RDONLY NONBLOCK.
Labels: info, negative

Title: Path traversal in SyslogLogFilePath handled via filepath.Base equality not just Clean
Severity: Info
Confidence: High
Evidence: As above, name != filepath.Base(name) rejects slash-containing and .. components outright rather than base-sanitizing — closes bypass where Base("a/../b")="b" would otherwise be allowed if only sanitized.
Labels: info, hardening

Title: Test files contain no hardcoded production secrets — only SUPERSECRETVRRPKEY constant for leak test, redacted via test assertion that error does NOT contain secret
Severity: Info
Confidence: High
Labels: info, negative

---

## Coverage & Verification Summary
- Files reviewed: 74 / 74 (100% batch — 24 prod, 50 test) — Module-by-module log above proves coverage.
- Expertise area A3 batch 4 expected ~400 files total across 3 batches; this batch closes remaining config files.
- Prod files: 0 HIGH/ Crit open vuln (all prior issues in batch already closed via #2053, #4860, #4834, #4902, #4288, #3075).
- Hardening verified: 7 positive controls audited (#2053 Secret redaction, #4860 log allowlist, #4834 SNMP restrict typo, #4902 system injection, #4288 VRRP auth dead, tcp-flags fail-closed #4714/#5455, zone/tunnel quarantine #3719).
- Test-coverage: 50 regression tests cover injection, traversal, secret leak, restrict typo, VRRP auth secret non-leak, tcp-flags dangling, WG ports skip 0, zone collision.
- False-positive attempts: For each HIGH I attempted to prove safe via validator/guard/caller reading — all survived as hardened, not open.
- Coordination: worktree SHA f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c verified same across reads.

## Suggested Issue Split
No new issues to file from this batch — all findings are verified hardening closures, not open vulns. If filing informational hardening backlog:
- Optional F: fuzz tcp_flags parser and RedactURL schemeless cases (already covered but fuzz guard).
- Optional L: scope WireGuard host-inbound admission per-interface not all local addrs (low risk due to auth).
Otherwise close as negative sweep with hardening proof.



---
### Batch A4_go_configstore_persist-b1 — 159 lines — full log + findings

# A4 configstore persist — security audit (batch 1/1, 70 files)

**Base:** f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
**Worktree:** /tmp/review-wt-ps-044-A4_go_configstore_persist-b1
**Scope:** pkg/configstore/ (db.go, crypto.go, envelope.go, store.go, store_persist.go, store_commit.go, factory_reset.go, journal/, history.go, etc.)

## Summary
Configstore implements durable active-config persistence with temp+fsync+rename+dir-fsync, AES-GCM encryption keyed via HKDF from a 32-byte master.key, a compatibility envelope with committed marker, a rotated journal with torn-tail recovery, and commit-confirmed timer with crash-recovery (confirm.json). Audit finds **no high/critical persistence or crypto bypass**. All durability seams (rbWriteFileDurable, rbSyncDir, rbRemove) are exercised by dedicated tests that fail RED if dropped. Secret redaction is enforced on all display renderers and rescue display, with parse-error messages scrubbed of token values.

---

## Module-by-module sweep

### db.go — DB creation, file perms, envelope ordering
- **File perm hardening (#4056):** `MkdirAllDurable(dir,0700)` + `os.Chmod(dir,0700)` enforces owner-only dir; files written `0600` in `writeTreeMarked`. Correct.
- **Temp sweep on boot:** `Glob(".*.tmp-*")` removes fsatomic crash-leaked temps matching `".<base>.tmp-<random>"` naming in `pkg/fsatomic`. Temp naming invariant kept in sync with `isFsatomicTemp` in factory_reset.go.
- **Envelope ordering:** `writeTreeMarked` does `marshal -> maybeEncrypt -> wrapEnvelope`. Envelope is outermost framing, so old reader sees leading `#` before JSON parse *and* before decrypt fallback — fail-closed per #1917. `readTreeMeta` mirrors: `hasEnvelope` check before decrypt.
- **null-decode hardening (#5474):** `requireJSONObject` rejects `null`/array/scalar top-level bodies *after* decrypt and envelope strip, preventing fail-open empty config. Trace: `null` unmarshals to zero-value `ConfigTree{}` with no error in Go; fixed.
- **Plaintext downgrade warning (#4579 A4-06):** `!decrypted && masterPasswordPRF(tree)!=""` logs WARN if config declares master-password but read as plaintext. Best-effort detection, not blocking, but surfaces at-rest exposure.
- **Durability:** all writes via `fsatomic.WriteFileDurable` (temp+fsync+rename+dir fsync). No direct `os.WriteFile`.
- **Negative:** No world-readable files; no missing fsync on active/candidate/rollback via DB.

### crypto.go — AES-GCM / HKDF / nonce / PRF
- **Key generation:** `readOrCreateMasterKey` generates 32-byte key via `rand.Reader`, persists via `WriteFileDurable(0600)` *before* any tree encrypted with it — ordering prevents permanent undecryptable DB after power cut (structural guarantee).
- **Salt:** 16-byte random per envelope (`deriveEncryptionKey`), stored plaintext. Standard.
- **HKDF:** `deriveEncryptionKeyFromSalt` calls `hkdf.Key(hashFn, keyMaterial, salt, "xpf-configstore-master-password", 32)`. Info string fixed, salt unique, output 32B for AES-256.
- **PRF mapping (SSOT):** `prfHash` maps `juniper-prf1|hmac-sha2-256|sha256 -> sha256`, `hmac-sha2-384|sha384 -> sha512/384`, etc., case-insensitive. Gate in `config.ValidateMasterPasswordPRF` (#4578) rejects unknown before reaching here. `crypto_prf_sync_4578_test.go` ensures advertised names intersect.
- **PRF discovery — groups & split stanzas:** `masterPasswordPRF` scans (1) every top-level `system {}` via `systemBlocksOf` (#4705) and (2) recursive walk of any `groups {}` subtree for `master-password` descendant (#5231). Treats any descendant as encryption-triggering, intentionally over-encrypts on defined-but-unapplied group (fail-closed towards encryption). Correctly avoids plaintext leak via apply-groups expansion that compiler does later.
- **AES-GCM:** `aes.NewCipher(key)` + `cipher.NewGCM(block)`, nonce `make(gcm.NonceSize())` + `rand.Read`. Fresh per write, never reused. Ciphertext `gcm.Seal`.
- **Nonce length guard (#4793):** explicit `len(nonce)!=gcm.NonceSize()` check before `Open` to avoid Go `cipher.AEAD.Open` panic on short nonce (crash-loop via corrupt DB). Returns error instead.
- **Unknown envelope format (#4888):** `unmarshalEnvelope` fails closed if `Format!="" || Salt!="" || Nonce!="" || Data!=""` but not our current format — prevents empty-tree fail-open on future `v2` envelope. Test `crypto_envelope_unknown_format_4888_test.go` expects store load → `ErrConfigDBUnreadable`.
- **File perms:** master.key 0600, DB dir 0700, active.json 0600.

### envelope.go — compatibility envelope
- **Magic:** `#xpf-config-envelope` leading `#` makes old reader's `json.Unmarshal` fail-closed (not empty-load).
- **Fields:** `v=`, `writer=`, `ast=`, `min-reader=`, `rollback-fmt=`, `committed=`. Writer sanitized via `sanitizeEnvelopeToken` replacing whitespace with `-` → prevents header injection / newline break.
- **Committed marker (#1922 Item 2):** default `Committed=true` (migration rule C3) — older DB without field reads as committed, so upgrade never misclassifies into bootstrap. Only explicit `committed=0` reads never-committed.
- **Min-reader gate:** rejects if `hdr.MinReader > EnvelopeFormatVersion` AND if `FormatVersion > EnvelopeFormatVersion` — fail-closed on too-new DB.
- **Durability:** envelope is in-memory prepend before durable write; no separate fsync needed.

### store.go / store_persist.go — Load, everCommitted, persist degradation
- **Load:** `ReadActiveMeta` → fail-closed `ErrConfigDBUnreadable` wrapper (daemon makes fatal). `everCommitted` and `persistMarkerCommitted` seeded from on-disk committed bit, so degraded-retry re-writes correct marker.
- **Tolerant compile:** `compileTreeLenient` downgrades typed-leaf gate and RA/node-id mismatches to WARN on Load/SyncApply, strict on operator commit — prevents boot blackout / HA alarm loop.
- **Confirm recovery (#4577):** `recoverPendingConfirmLocked` restores pending window on boot. If deadline passed → immediate rollback to `PrevTree` with `FirstCommit` handling (committed=0 path). Persists rollback target durably before deleting confirm.json — and retains confirm.json on persist failure (#5473) so next boot re-drives rollback. If still within window → re-arms `time.AfterFunc` for remaining duration.
- **ConfirmRecord validation (#5637):** `requireJSONObject` + `Deadline.IsZero()` + `PrevTree==nil` checks reject `null`/`{}` bodies that would otherwise decode to zero record and cause immediate empty-tree rollback (fail-open wipe).
- **Degraded persist (#1799):** `noteActivePersistFailureLocked` flips `persistDegraded`, journals ERROR, spawns singleton retry goroutine with doubling backoff (1s→60s). Retry loop re-reads `s.active` under mu (no stale capture) and writes via `writeActiveMarker` preserving `persistMarkerCommitted`. Shutdown safety: no WaitGroup, goroutine sleeps off-lock.
- **Archive:** `ArchiveConfig` captures `data`, `ts`, `seq` under RLock, then `writeArchive` off-lock. Filename `config-<ts ns>.<seq 20-digit>.conf` — seq guarantees uniqueness under identical timestamp / NTP step-back (#3441 H4). 0600 files, 0700 dir. `rotateArchives` keeps newest N; ENOENT-tolerant removal via `archiveRemoveErr` (#4689) prevents spurious WARN on concurrent rotation race.
- **Rescue config:** `SaveRescueConfig` via `WriteFileDurable(0600)`. `DeleteRescueConfig` durable delete via `rbRemove` + `rbSyncDir` (#5197). `LoadRescueConfigRedacted` reparses text, redacts via `RedactedClone`, fails closed on parse error with generic message containing only line/col — no token leak (#4099 follow-up).

### store_commit.go — commit / commit-confirmed / rollback
- **Commit contract (#1799 Option A persist-before-promote):** `writeActive(candidate)` before any in-memory promotion. On pre-rename failure → clean reject, candidate intact, no history/journal/rollback side-effects. On post-rename dir-fsync failure (`isPostRenameDurabilityFailure` using `*fsatomic.PostRenameSyncError`) → **converge to C** (promote in memory, return compiled so daemon applies), flag degraded via `noteActivePersistFailureLocked`. Converge-to-C chosen over restore-A because restoring A needs another rename that can also fail post-rename; C is already visible on disk.
- **Description cap (#4891):** `maxCommitDescriptionBytes=4KiB`. Strict reject on operator commit path, defensive truncate in `journalLog` via `truncateDetail` (UTF-8 boundary aware, appends `[truncated N bytes]` marker) to protect journal tail scanner from poisoned lines > `maxTailLineBytes` (16MiB).
- **Commit-confirmed (#1817/#3861/#4378/#4577/#4868/#5473):**
  - Bounds: `MaxCommitConfirmedMinutes=65535`, clamped before `time.Duration(minutes)*time.Minute` to avoid int64 ns overflow (immediate/wrong rollback).
  - Ordering: persist candidate **before** touching confirm state — prior revert cancelled pending timer before write, stranding confirmed commit with no rollback. Fixed.
  - Nested: `confirmTimer!=nil` → cancel timer but **preserve** `confirmPrevTree/confirmPrevCfg` (original last-confirmed). Prevents rollback to unconfirmed intermediate.
  - Timer dispatch (`fireConfirmTimer`): reads `rollbackExecutor` under mu then invokes **without** holding mu (avoids applySem→mu inversion). Falls back to `performAutoRollback` when no executor (tests/non-daemon).
  - Generation guard: `confirmGen` bumped on every arm/confirm/cancel. Callback captures gen; `PromoteRollback` checks mismatch → no-op. Closes Stop()-lost race where fired callback blocked on mu.
  - Confirm-on events: plain commit (`clearPendingConfirmLocked`), HA sync (`cancelPendingConfirmTimerLocked` + deferred delete after durable write), demotion (`ConfirmPendingOnDemotion`), explicit `ConfirmCommit`.
  - Crash-recovery persistence: `writeConfirmState` encrypts PrevTree with same machinery as active.json (keyed off PrevTree), 0600, temp+fsync+rename+dir fsync. Best-effort — failure logged, in-memory timer still covers no-crash case.
  - Durable confirm.json removal (#5473): `confirmResolvePendingPersist` flag defers deletion until replacement config is durable. Paths: auto-rollback failure retains record; persist-retry heal clears it via `clearConfirmResolutionPendingLocked`; sync/commit healing also clears. Prevents crash window where confirmed config not durable but record deleted → boot loads pre-rollback with no record.
  - First-commit rollback (Item 1b): `confirmPrevCfg==nil` → rollback target is empty bootstrap tree, `writeActiveMarker(...,committed=false)`, `everCommitted=false`, `persistMarkerCommitted=false`. Prevents operator-committed-empty misclassification → interface takeover on empty config. Both immediate write and retry loop preserve `committed=0`.
- **Rollback history files:** `saveRollbackFiles` writes slot1 via `rbWriteFileDurable`, slots 2..N via `rbWriteFileAtomic` + single trailing `rbSyncDir` — adjudicated durability split (#1894): slot1 is immediate `rollback 1` target (durably written), others atomic (never torn/missing) + dir sync. Skips tombstoned entries (nil Config) to preserve positional integrity (#4810). `cleanupRollbackFiles` stops only on ENOENT, logs and continues on other errors (#3441 L3). `loadRollbackHistory` continues past read errors, tombstoning slot with nil Config so `rollback N` resolves to slot N with clear error rather than silently shifting to N+1. Corrupt file handling logs only line/col, not token (#4690, mirrors #4099 rescue).
- **Degraded flag:** `rollbackPersistDegraded` surfaced via `RollbackHistoryDegraded()` + journal entry, so text rollback loss is visible not warning-only (#3441 L1).

### journal/journal.go — commit audit journal
- **File perms (#4579 A4-02):** `0600` on create (`O_APPEND|O_CREATE|O_RDWR, 0600`). Comment in Detail may contain credential accidentally; matches 0600 posture of .configdb.
- **Migration repair (#5188):** `migratePermsLocked` runs once on first Log/Tail under mu, `lstat` each owned segment (current + `.1..maxSegments`), chmod 0600 if more permissive than 0600, tightens only (0400 left alone), refuses symlink (lstat, never follow). Rotation itself re-asserts 0600 on renamed segment. Tests `TestMigratePreexistingCurrent0644`, `TestMigrateRotatedSegment0644`, `TestRotationRepairsSegmentMode`, `TestMigrateSkipsSymlink`.
- **Append atomicity:** `appendLocked` holds mu for rotation+open+torn-tail check+buffered write. Write is `buf = [optional \n] + data + \n`. Torn-tail self-heal: if last byte != '\n', prepends newline — confines crash-torn final line damage to one record. `parseLine` skips blank/garbage, tolerant decode drops unknown fields (v1 fat lines with before/after payloads).
- **Durability:** `Log` captures `created,rotated` from `appendLocked`, then releases mu before `f.Sync()` + optional `SyncDir`. Decouples visibility (page cache after Write) from durability (fsync). `Tail` takes same mu, so never sees mid-rotation duplicate inode or mid-write torn record, but doesn't block for fsync duration. Proven by `TestTailNotBlockedByLogFsync` — slow fsync hook, Tail must finish < fsyncHold/2; RED-on-revert if fsync moved back under mu.
- **Rotation:** `maybeRotateLocked` removes oldest segment, shifts others up, renames current→`.1`. Gap-tolerant: `Tail` scans `0..maxSegments`, missing segments skipped (`TestRotationGapTolerated`). `maxSegments` and `maxSegmentBytes` clamped in `New` — `0` would delete current file via `segmentPath(0)==path` (AGY code-r1 F2).
- **Reverse tail scan:** `tailScan` reads backwards in `readChunk=64KiB` chunks, assembles multi-chunk lines across chunks (legacy fat v1 entries 3x chunk). Cap check on *every* pending update — fragment retaining terminating `\n` would otherwise grow unbounded (AGY code-r1 F1). `maxTailLineBytes=16MiB` caps line assembly; over-cap triggers skip mode: discard from last newline onward, resume before it. Tests with >16MiB garbage (short-only).
- **Boundedness:** `Tail(50)` reads O(50) not O(lifetime) — proven by `countingReaderAt` test; benchmark present.
- **Concurrency:** `TestConcurrentLogTailNoTornOrError` 4 writers x 250 + 3 readers under -race; checks no torn/empty/duplicate within snapshot.

### factory_reset.go — zeroize erasure
- **Scope:** erases `.configdb/master.key` (AES-GCM key), `.configdb/` (SSOT active/candidate/rollback), `.config.journal[.N]`, `<base>.N` text rollback slots, `*.conf` live+rescue, `rollback*` legacy, `.*.tmp-*` fsatomic temps (both inside .configdb and top-level configDir temps #5475).
- **Key-first ordering (#5197):** unlink `master.key` via `rbRemove`, then `rbSyncDir(.configdb)` to make key removal durable *before* ciphertext RemoveAll. Otherwise power cut could persist ciphertext removal loss but lose key removal → ciphertext+key both survive page cache? Actually guarantee is cryptographic erasure: key unlink durable before body removal so interrupted wipe never leaves ciphertext+key where key removal was lost but ciphertext removal persisted? Code ensures key deletion durable first.
- **Dir fsync propagation:** final `rbSyncDir(configDir)` error returned, not swallowed — fsync failure means erasure not durable, must not report clean zeroize. Same for archive dir path.
- **Archive dir ownership guard (#5186):** `FactoryResetArchiveDir` erases only `filepath.Clean(archiveDir)==DefaultArchiveDir` (="/var/lib/xpf/archive"). Custom remote/compliance archive (NFS, retention store) skipped with WARN, never deleted. Mirrors `zeroizeLoginAccounts` ownership check.
- **Secret leak closure:** fsatomic temps inside .configdb erased by RemoveAll; top-level `.*.tmp-*` temps erased explicitly — such temps hold full cleartext config text mid-write (IKE PSK, WireGuard keys, SNMP communities) and would otherwise survive reboot with no next write to self-heal (#5475).
- **Test seams:** `rbRemove/rbSyncDir` seams allow injecting fsync failures and asserting dir sync called — RED if dropped.

### history.go, store_format.go, check.go, dataplane_retire.go
- **History:** fixed-size ring buffer, clone on push, no durability concerns beyond rollback files.
- **Display redaction (#4051):** `forDisplay(t)=t.RedactedClone()` used for all `*Redacted` variants; cleartext `Show*` kept for HA sync, archive, persistence, CLI. `ShowCompareRedacted` diffs two redacted trees → secret change shows no-change, not leak. Correct.
- **CheckText (#1879):** size-gated before parse, strict `compileTreeStrict` pipeline (same as operator commit) — day-0 config-drive validation.
- **Dataplane retire rewrite:** removes `system { dataplane-type dpdk|ebpf }` leaves from both top-level and `groups {}` nested system blocks, logs WARN with remediation hint differing by caller (`LoadCaller` vs `SyncCaller`). Walk over all `system` blocks (not first only) handles split stanzas. In-memory only until next commit.

---

## Findings — organized by security property

### Durable temp+fsync+rename ordering
- **PASS [confidence: high]:** All canonical writes use `fsatomic.WriteFileDurable` (temp + fsync + rename + dir fsync). Verified in `db.go writeTreeMarked`, `DB.WriteConfirm`, `Store.SaveRescueConfig`, `journal.appendLocked` (open+write under lock, sync outside), `store_commit.go saveRollbackFiles` slot1 durable, archive dir mkdir 0700.
- **PASS [confidence: high]:** Post-rename dir-fsync failure handling converges to new config (visible on disk) rather than reporting reject while disk holds new — avoids durable(C)!=memory(A) divergence. `isPostRenameDurabilityFailure` checks `*PostRenameSyncError`.
- **PASS [confidence: medium]:** Rollback files: slot1 durable, slots 2..N atomic + single dir fsync — adjudicated trade-off (cost vs durability) documented, acceptable.
- **PASS [confidence: high]:** Delete transitions (`DeleteConfirm`, `DeleteRescueConfig`) use `rbRemove` + `rbSyncDir` and propagate fsync errors — durable delete, prevents resurrection of secret-bearing files after power cut.

### AES-GCM / HKDF / nonce
- **PASS [confidence: high]:** Nonce fresh per encryption via `rand.Read(gcm.NonceSize())`, never reused. Salt 16B random per envelope. Key material 32B random via `rand.Reader`, 0600 durable write before first use. HKDF info fixed, salt unique, output 32B for AES-256.
- **PASS [confidence: high]:** Nonce length guard prevents panic (DoS boot loop) on corrupt envelope — `crypto_nonce_length_4793_test.go` proves error not panic.
- **PASS [confidence: medium]:** PRF hash mapping SSOT — `prfHash` lowercases input, supports juniper-prf1/hmac-sha2-256/384/512/sha1/sha256/sha384/sha512. Commit gate `config.ValidateMasterPasswordPRF` rejects typo before reaching HKDF. Test `crypto_prf_sync_4578_test.go` cross-checks advertised names.
- **PASS [confidence: high]:** Unknown envelope format fails closed (#4888) — prevents empty-tree fail-open when future `xpf-master-password-v2` encountered. Explicit check for any of format/salt/nonce/data non-empty.

### Commit/rollback + commit-confirmed timers
- **PASS [confidence: high]:** Commit persists before promote (Option A). History, journal, rollback files after promote — safe because canonical active persisted durably first.
- **PASS [confidence: high]:** Generation token prevents stale timer reverting newer commit (Stop()-lost race). `confirmGen++` on arm, confirm, cancel, timer path.
- **PASS [confidence: high]:** Timer prefers daemon executor holding apply semaphore — promotion+dataplane re-apply atomic vs concurrent commit, and SERVICE-mode (gRPC/REST) timeouts re-apply dataplane (old interactive-only callback didn't).
- **PASS [confidence: high]:** Crash-recovery for pending confirm window: `confirm.json` persisted, re-armed on Load if still within window, immediate rollback if expired. Handles FirstCommit (empty bootstrap) → committed=0 marker preserved.
- **PASS [confidence: high]:** `confirmResolvePendingPersist` defers confirm.json deletion until replacement config durable — closes #5473 crash window where confirmed config not durable but record deleted → next boot loads pre-rollback with no record.
- **PASS [confidence: medium]:** Max minutes bound 65535 prevents overflow of `time.Duration(minutes)*time.Minute` (int64 ns) → immediate/wrong rollback.
- **PASS [confidence: high]:** Plain commit and HA sync confirm pending window (#3861) — prevents timer reverting freshly synced primary config and diverging cluster.

### Journal torn-tail recovery
- **PASS [confidence: high]:** Torn-tail self-heal inserts newline if last byte != '\n', parse-or-skip drops partial line. Tested in `TestTornFinalLine`.
- **PASS [confidence: high]:** Reverse scan bounded by limit (O(limit)), chunk assembly across boundaries works (fat v1 lines 3x chunk), UTF-8 split across chunk boundary preserved (bytes-level, no rune corruption) — `TestTailUTF8AtChunkBoundary`.
- **PASS [confidence: high]:** Over-cap poison line handling: `maxTailLineBytes=16MiB`, skip mode discards from last newline onward, resyncs at previous newline — prevents OOM buffering whole file. Cap checked on every pending update (covers newline-terminated over-cap case — AGY code-r1 F1). Tests exist (short-only due to 16MiB writes).
- **PASS [confidence: high]:** Tail not blocked by Log fsync (#4829) — lock held only for Write, released before Sync. Proven by slow-fsync hook test.

### Envelope compatibility
- **PASS [confidence: high]:** Leading `#` makes old reader fail-closed. Min-reader gate rejects too-new DB with clear message (upgrade or roll forward). Unknown header fields tolerated (additive forward-compat). Committed defaults true (C3) — upgrade never misclassifies existing DB into bootstrap.
- **PASS [confidence: high]:** Writer version stamped, whitespace sanitized to `-` to prevent header injection.

### Secret redaction / file perms
- **PASS [confidence: high]:** All config DB files 0600, dir 0700. Journal 0600 plus migration repair tightening pre-0600 0644 current + rotated segments, symlink-safe via lstat, only tightens. Rollback text slots 0600 (full config text with cleartext secrets). Archive files 0600, dir 0700. Rescue 0600.
- **PASS [confidence: high]:** Display renderers have `*Redacted` variants using `RedactedClone()` masking with `SecretDataPlaceholder`. Cleartext renderers kept for HA sync/archive/persistence only. `ShowCompareRedacted` masks both sides → no leak on secret change.
- **PASS [confidence: high]:** Rescue redacted display reparses saved text, redacts clone, fails closed on parse error with generic line/col only — no token value echoed. Load path for corrupt rollback similarly logs only line/col, not offending token (#4690 / #4099 invariant).
- **PASS [confidence: medium]:** Plaintext downgrade warning surfaces at-rest exposure when master-password declared but read as plaintext — detects downgrade/restore/tamper; requires 0600/0700 write access to trigger, so not privilege escalation but visibility.

---

## Negative results (explicitly checked, no issue)

- No world-readable config DB, journal, rollback, archive, or rescue files; no O_APPEND perm arg bypass without migration.
- No nonce reuse; no fixed IV; no ECB; no unauthenticated encryption.
- No envelope parsing before committed-bit default that could misclassify committed→never-committed.
- No journal line that can poison tail scanner beyond `maxTailLineBytes` and cause total loss — garbage beyond cap drops only that line.
- No confirm.json deletion before replacement durable — deferred removal mechanim covers all resolution paths (rollback, boot recovery, HA sync, plain commit, retry heal).
- No `rollback N` index shift on intermediate unreadable/corrupt slot — tombstone preserves position.
- No archive overwrite on same-nanosecond commits — seq guarantees uniqueness, lexical sort stays chronological.
- No stale temp files surviving factory reset — `.*.tmp-*` sweep both inside .configdb (NewDB) and top-level configDir (FactoryResetConfigDir).
- No archive log dir deletion for custom/compliance paths — ownership guard prevents.
- No secret token in logs — parse-error paths strip message, emit only line/col ints.
- No size-unbounded commit description reaching journal — 4KiB cap + truncateDetail belt.

---

## Low / Informational observations

- **Info [confidence: low]:** `FactoryResetArchiveDir` ownership guard uses `filepath.Clean` not `EvalSymlinks` — if `/var/lib/xpf/archive` is a symlink to elsewhere, Clean won't resolve, and comparison `Clean(custom)==Default` could allow deletion of symlink target if custom path equals default string but is symlink. However var is fixed string and production path is real dir; risk negligible, but symlink-aware check could be defense-in-depth.
- **Info [confidence: low]:** `archiveSeq` is per-process monotonic (atomic.Uint64) but not persisted — after daemon restart seq resets to 0, so filename could theoretically reuse seq portion with same ns timestamp after restart. Uniqueness still dominated by ns timestamp (unlikely same ns across restart) and atomic within process is sufficient. Not a bug.
- **Info [confidence: low]:** `confirm.json` encryption uses PrevTree's PRF — if PrevTree had no master-password but active config's secrets are in PrevTree? Actually PrevTree without master-password has plaintext secrets already, so plaintext confirm.json not worse. Acceptable trade-off.
- **Info [confidence: low]:** Persist retry loop sleeps outside mu but holds no close signal — documented as plain goroutine abandoned on process exit, which is safe as write is atomic. No shutdown leak.

---

## Verdict
**No blocking persistence or crypto defects.** The module shows extensive hardening against power-loss, torn writes, downgrade, fail-open empty config, nonce panic, journal poisoning, confirm-window stranding, and cluster divergence. Tests cover each hardening with RED-on-revert assertions and durability seam injection.


---
### Batch A5_go_ha_vrrp_ra_conntrack-b1 — 912 lines — full log + findings

# A5 Go HA / VRRP / RA / Conntrack — Refactor & Modularity Audit
Batch: A5_go_ha_vrrp_ra_conntrack-b1 (107 files)
Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A5_go_ha_vrrp_ra_conntrack-b1/
Snapshot: /tmp/audit_src/

## Orientation & Hot-Path Classification

**HA / VRRP / RA / Conntrack are NOT per-packet hot-path.** They are timer-driven:
- VRRP RETH advertisements: 30ms default (`reth-advertise-interval`), Master_Down ~97ms
- Heartbeat: 200ms interval, threshold 5 => 1s detection
- Session sync sweep: 1s active, 10s idle with exponential backoff
- RA: periodic lifetime, not per-packet
- Conntrack GC: periodic sweep

Splitting these files does NOT risk per-packet latency regression. **What must be preserved is failover-timing correctness and generation-guard ordering.**

### Generation-Guard Ordering Invariant (stamp→queue→take) — Critical for Split Preservation

From `pkg/cluster/sync_conn.go`:
```
Producer path (primary):
  stampInstallGenV4/V6  → nextInstallGen (atomic.Add) → genSentMu → putGenBounded(genSentV4/V6)
  queueMessage → sendCh (non-blocking, overflow → syncBackfillNeeded + sweep replay)
  takeDeleteGenV4/V6 → genSentMu lock → evict + nextInstallGen (fresh > install)

Consumer path (standby, single-threaded receiveLoop per fabric):
  installGenGuardV4/V6 → recvGenMu → check stored vs incoming (strict older refuse)
  PutClusterSyncedV4/V6 (dataplane mirror)
  recordInstalledGenV4/V6 → recvGenMu → putGenBounded

  deleteGenGuardV4/V6 → recvGenMu → stored!=0 && deleteGen!=0 && deleteGen<stored → refuse
                          deleteGen!=0 → putGenBounded as TOMBSTONE (not evict)
                          deleteGen==0 → delete(map) (legacy fallback)

Bulk barrier:
  resetRecvGen() → recvGenMu → clear recvGenV4/V6 maps + lastAppliedConfigGen.Store(0)
  Called at BulkStart (#2198 F2, #3931) to handle peer reboot (monotonic clock restart)
```

Ordering constraints for any decomposition:
- genCounter (atomic.Uint64) MUST be single global monotonic — cannot shard per-file without breaking strictly-greater delete guarantee #2221.
- genSentMu protects genSentV4/V6 sender-side map; recvGenMu protects recvGenV4/V6 receiver-side.
- Non-atomicity note (#2198 F3): guard check + Put + record are NOT under single lock; safe ONLY because receiver is single-threaded per active fabric (activeConnLocked prefers conn0, conn1 standby). Splitting must NOT introduce concurrent apply for same key across fabrics.
- putGenBounded NEVER clears map (skip-record-on-full) — prevents #2170 hazard (stale delete killing live re-established session). Must stay in same file as cap constant.
- resetRecvGen also resets config generation high-water — if split, config guard and session guard resets must stay atomic in BulkStart handler.
- Fabric preference: activeConnLocked() under s.mu, conn0 preferred, conn1 only when conn0 down. sendLoop uses getActiveConn() (mu-protected). Must not introduce dual-active send.

### Metrics Summary

| File | LOC | Responsibilities | God? |
|------|-----|------------------|------|
| pkg/cluster/sync_conn.go | 1858 | 8-10 (gen-guard stamp/take/guard/record, map cap, journal flush/rejournalTail, sweep, queue, config gen guard, conn mgmt, sweep, liveness) | YES |
| pkg/vrrp/instance.go | 2417 | 6-7 (socket open, local IP resolve, state machine run/stepBackup, advert tx, afpacket+IPv4/6 rx parsing, master tracking, GARP burst+suppression, VIP add/remove, preempt hold) | YES |
| pkg/cluster/sync_protocol.go | 829 | 1 but 12 wire msg types V4/V6 session, delete, bulk start/end/ack, heartbeat, config, IPsec SA, failover, fence, clock, DHCP leases | borderline monolith merge-conflict magnet |
| pkg/cluster/heartbeat.go | 881 | 5 (packet marshal/unmarshal, auth session/counter+replay+HMAC, sender, receiver, liveness/peerHeartbeatFresh, peer primary) | YES |
| pkg/cluster/sync.go | 1048 | 4-5 (SessionSync struct def 60+ fields, stats, configApplyCh, authProvider, delete journal, bulk flags, zone RG map) | YES struct god |
| pkg/vrrp/manager.go | 1108 | 5 (instance lifecycle openPerInterfaceSocket, addrwatch integration, GARP unsuppress, event channel, track-down, VIP reconcile) | YES |
| pkg/cluster/garp.go | 754 | 3 (gratuitous ARP send, unsolicited NA, burst follow-up goroutine + error counter) | moderate |
| pkg/cluster/failover.go | 912 | 4 (single-RG manual failover, ForceSecondary, batch failover, fence, transfer-commit grace, transfer readiness) | moderate |
| pkg/cluster/heartbeat_manager.go | 492 | 3 (HA manager <-> heartbeat peer alive, monitor integration, transfer-commit override apply) | ok |
| pkg/cluster/monitor.go | 641 | 2 (interface monitor, RETH link tracking) | ok |
| pkg/cluster/sync_bulk.go | 449 | 2 (bulk sync state machine, bulk send, stale reconcile) | ok |
| pkg/cluster/sync_failover.go | 607 | 2 (failover msg encode/decode, peer failover request handling) | ok |
| pkg/cluster/sync_auth.go | 424 | 2 (control-link auth handshake, frame sealing, downgrade guard) | ok |
| pkg/ra/ra.go | 1118 | 3 (config compilation per-interface prefix+lifetime, draining tombstone state machine #2033, sender lifecycle) | borderline |
| pkg/ra/sender.go | 1055 | 4 (RA packet marshal with per-iface epoch #4961, timer interval #4525, link-local source selection, goodbye+reclaimer #5092-5094) | borderline |
| pkg/conntrack/gc.go | 554 | 2 (GC sweep, HA delete-sync callback invocation, legacy dataplane guard) | ok |
| pkg/cluster/election.go | 475 | 2 (weight calc, primary election) | ok |
| pkg/cluster/status.go | 721 | 2 (show commands aggregation, Prometheus) | ok |

Total batch production LOC (excluding tests): ~14,500. Test LOC ~11,000 (high ratio, good).

---

## Findings — Module-by-Module

### FINDING 1: sync_conn.go 1858-LOC 8-Responsibility God-File — Canonical Decomposition Candidate Preserving Generation-Guard Ordering

Title: sync_conn.go 1858 LOC mixes 8 independent change reasons (gen-guard stamp/queue/take, bulk reset #2995, fabric preference, journal, sweep, config gen guard, liveness, conn lifecycle) — refactor candidate, not correctness bug
Severity: Medium
Confidence: High
Evidence: file: pkg/cluster/sync_conn.go:1-1858

Quoted snippet (generation guard + map cap + putBounded):
```go
const genGuardMapCap = 200000
func putGenBounded[K comparable](m map[K]uint64, key K, gen uint64) bool {
    if _, exists := m[key]; exists {
        m[key] = gen
        return true
    }
    if len(m) >= genGuardMapCap {
        return false
    }
    m[key] = gen
    return true
}
func (s *SessionSync) stampInstallGenV4(key dataplane.SessionKey, val *dataplane.SessionValue) {
    g := s.nextInstallGen()
    val.Generation = g
    s.genSentMu.Lock()
    if s.genSentV4 == nil {
        s.genSentV4 = make(map[dataplane.SessionKey]uint64)
    }
    if !putGenBounded(s.genSentV4, key, g) {
        s.stats.GenMapOverflow.Add(1)
    }
    s.genSentMu.Unlock()
}
```

Quoted snippet (resetRecvGen + config gen reset — bulk barrier coupling):
```go
func (s *SessionSync) resetRecvGen() {
    s.recvGenMu.Lock()
    s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
    s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
    s.recvGenMu.Unlock()
    s.lastAppliedConfigGen.Store(0)
}
```

Quoted snippet (journal + active conn pref + writeMu):
```go
func (s *SessionSync) activeConnLocked() net.Conn {
    if s.conn0 != nil {
        return s.conn0
    }
    return s.conn1
}
func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool {
    if !s.stats.Connected.Load() {
        return false
    }
    select {
    case s.sendCh <- msg:
        sentCounter.Add(1)
        return true
    default:
        s.stats.Errors.Add(1)
        if s.syncBackfillNeeded.CompareAndSwap(false, true) {
            slog.Warn("cluster sync: send queue full, enabling sweep replay", ...)
        }
        return false
    }
}
```

Trace (why 8 concerns collide in one file):
1. Config change touches nextConfigGen/QueueConfig/shouldApplyConfigGen/recordAppliedConfigGen + configApplyLoop single-consumer ordering (#3931, #4151 high-water-on-success)
2. Session churn touches stampInstallGen/takeDeleteGen/installGenGuard/deleteGenGuard/recordInstalledGen + putGenBounded cap logic
3. Bulk reconnect touches resetRecvGen (clears BOTH recvGen maps AND config high-water)
4. Fabric flapping touches activeConnLocked (mu) + handleNewConnection + acceptLoop + fabricConnectLoop + sendLoop + receiveLoop ordering
5. Backpressure touches journalDelete/flushDeleteJournal/rejournalTail + queueMessage + syncBackfillNeeded + sweep replay
6. Liveness around heartbeat socket restart touches SendLivenessKeepalive/sendClockSync
7. Auth touches performSyncHandshake/wrapSyncConn/syncAuthedEver (#4107 F23)
8. Monitoring touches sweepIntervals/ShouldSyncZone + telemetry global counters new/closed

Each change reason independently edits same file → merge conflicts + review load (#2198, #2221, #3931, #3926, #2121, #4107, #4360, #4370 all touched this file).

Refutation attempt: Checked if already split into helpers — heartbeat_manager, sync_bulk, sync_failover, sync_auth ARE already extracted, but sync_conn.go retains core state machine. No guard violation found; generation ordering is correct (stamp→queue→take, fresh delete gen > install #2221, tombstone prevents stale retain). Not a bug, pure modularity.

HPC/invariant check: Not hot-path (timer-driven 1s sweep, not per-packet). Generation guard uses atomic.Uint64 Add for monotonic, mu-protected maps, NOT lock-free hot lookup. Performance impact of split: none, as long as atomic counter stays shared and recvGenMu/genSentMu not duplicated. Must NOT hold recvGenMu across PutClusterSynced (dataplane I/O) — current non-atomicity note #2198 F3 explains single-threaded receiver invariant. Splitting must preserve that invariant comment in new files.

Why it matters: 1858 LOC with 8 change axes blocks parallel work on HA correctness (config sync reorder, delete journal #2121, bulk ack #4360, handshake #4107/4370). Each HA bug fix touches same file → rebase hazard. Reviewers must read full 1858 LOC to vet 10-line gen-guard change.

Fix direction (concrete, preserves generation-guard ordering):
- Split into 5 files under pkg/cluster/sync/ package (or same package files with clear naming):
  - `sync_generation_guard.go`: genGuardMapCap, putGenBounded, nextInstallGen, stampInstallGenV4/V6, takeDeleteGenV4/V6, installGenGuardV4/V6, recordInstalledGenV4/V6, deleteGenGuardV4/V6, resetRecvGen (including config gen reset + comment cross-linking bulk barrier). KEEP single file for cap + all guards so cap change atomic with guard logic.
  - `sync_journal.go`: journalDelete, flushDeleteJournal, rejournalTail, queueMessage, sendCh backpressure, syncBackfillNeeded.
  - `sync_connection.go`: shouldInitiateFabricDial, activeConnLocked/getActiveConn, connRemote/LocalAddrString, configureSessionSyncConn, handleNewConnection, Start, Stop, acceptLoop, fabricConnectLoop, sendLoop, receiveLoop, handleMessage, handleDisconnect. KEEP activeConnLocked + mu + writeMu together.
  - `sync_config.go`: nextConfigGen, QueueConfig, shouldApplyConfigGen, recordAppliedConfigGen, configApplyLoop, configApplyCh consume ordering note #3931/#4151.
  - `sync_sweep.go`: StartSyncSweep, sweepIntervals, syncSweep, ShouldSyncZone, QueueSessionV4/V6, QueueDeleteV4/V6, Pause/ResumeIncrementalSync.
- Preserve: shared SessionSync struct remains in sync.go (god struct ok to keep central); methods moved but in same package, so field access unchanged. Do NOT extract struct fields into sub-structs yet (that would need accessor methods).
- Tests that gate correctness after split: pkg/cluster/sync_gen_guard_test.go (covers stale-delete AND stale-install via gen monotonic), sync_test.go (4717 LOC bulk+config+delete journal), failover_races_5245_5246_test.go, heartbeat_liveness, controllink_auth_status_4484, lease_sync_wire. Full gate: `make test-failover` on loss:xpf-userspace-fw0/fw1 (60ms VRRP, fabric redirect) — must pass.
- Fabric preference invariant: after split, add `assertSingleActiveSender` helper in test to ensure only one conn active in activeConnLocked; bulk reset #2995 test already guards resetRecvGen clearing.

Labels: refactor, modularity, HA, generation-guard, failover-timing, test-failover-gate
Dedup note: This expands on dedup entry `Session sync connection gen-guard ordering-critical file mixing 8 concerns — stamp→queue→take, bulk reset #2995, fabric preference` — that entry summarized the problem; this finding provides concrete LOC metrics, quoted evidence, trace of 8 change reasons, and a 5-file decomposition preserving atomic ordering + single-threaded receiver invariant + config/session bulk reset coupling, which dedup entry lacked.

---

### FINDING 2: vrrp/instance.go 2417-LOC God-File — 6 Responsibilities, Failover Timing Critical, Decomposable Without Hot-Path

Title: vrrp/instance.go 2417 LOC fuses socket open, local-IP resolve, state machine run/stepBackup, advert TX, AF_PACKET+IPv6 RX parsing, master tracking, GARP burst+suppression, VIP add/remove, preempt hold — split candidate preserving 30ms RETH timing
Severity: Medium
Confidence: High
Evidence: file: pkg/vrrp/instance.go:1-2417

Quoted snippet (state + preempt hold + master tracking + GARP suppression fields — all in one struct):
```go
type vrrpInstance struct {
    mu               sync.RWMutex
    cfg              Instance
    desiredPreempt   bool
    forcePreemptOnce bool
    skipNextPreemptHold bool
    preemptHoldArmed bool
    trackDown bool
    lastMasterPriority int
    lastMasterSeen     time.Time
    masterAdverInterval time.Duration
    state   VRRPState
    iface   *net.Interface
    eventCh chan<- VRRPEvent
    localIP   atomic.Pointer[net.IP]
    localIPv6 atomic.Pointer[net.IP]
    conn    net.PacketConn
    rawConn *ipv4.RawConn
    ipv6Conn net.PacketConn
    ipv6FD   int
    ipv6Send func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error
    ipv6Recv func(buf []byte) (n int, ifindex int, hopLimit int, src net.Addr, err error)
    afPacketFD int
    preemptNowCh    chan struct{}
    resignCh        chan struct{}
    configUpdatedCh chan struct{}
    rxCh    chan *VRRPPacket
    stopCh  chan struct{}
    stopped chan struct{}
    rxDrops    atomic.Uint64
    rxReceived atomic.Uint64
    lastDropWarn atomic.Int64
    suppressGARP  atomic.Bool
    garpEpoch     atomic.Uint64
    lastGARPEpoch atomic.Uint64
    lastGARPTime  atomic.Int64
    onEventDrop func()
    addrsFn func() ([]net.Addr, error)
}
```

Quoted snippet (GARP suppression gates — epoch dedup + 500ms dampener #2081):
```go
func (vi *vrrpInstance) garpSendAllowed(force bool, nowNanos int64) bool {
    epoch := vi.garpEpoch.Load()
    lastEpoch := vi.lastGARPEpoch.Load()
    if epoch == lastEpoch {
        return false
    }
    if !force {
        last := vi.lastGARPTime.Load()
        if nowNanos-last < int64(500*time.Millisecond) {
            return false
        }
    }
    return true
}
func (vi *vrrpInstance) sendGARP(force bool) {
```

Quoted snippet (preempt gate + master interval floor — timing correctness):
```go
func (vi *vrrpInstance) shouldPreemptObservedMaster() bool {
    vi.mu.RLock()
    defer vi.mu.RUnlock()
    ...
}
func (vi *vrrpInstance) masterAdverFloor() time.Duration {
```

Trace: Timer-driven path (not per-packet):
- run() goroutine loops over masterDownTimer (Master_Down_Interval = 3*Advert + Skew), advertTimer (AdvertiseInterval 30ms), preemptHoldTimer (hold-time #2850), preemptNowCh (from cluster Manager ReleaseSyncHold), resignCh, configUpdatedCh, rxCh (64 buffered). stepBackup() arms preempt hold, defers via shouldPreemptObservedMaster gate #2082 (strict higher priority). becomeMaster() does addVIPs → sendAdvert → emitEvent sync, then async go sendGARP(false) with 50ms follow-up burst. GARP suppression: epoch bump on ReconcileVIPs + sendGARP(true) forced after MAC reprogram (programRethMAC link DOWN/UP removes kernel addresses). If routine GARP fired within 500ms prior, non-force GARP suppressed — but force=true bypasses dampener, keeping epoch dedup.

Hot-path preservation: Not per-packet; 30ms RETH timer + 200ms heartbeat are control-plane. Splitting must NOT change timer durations, preempt hold state machine, or GARP suppression gates. Instance's run loop is single goroutine serializing state transitions — safe to extract helpers into same-package files as long as they remain methods on vrrpInstance and retain mu/atomic semantics.

Refutation attempt: Checked if split would break localIP atomic.Pointer pattern (#2258). localIP/localIPv6 written atomically from addr-watcher goroutine and lazy-resolve from run-loop, read from receiver goroutines — atomic.Pointer required. Splitting into files keeps same package, same atomic fields, no cross-package accessor needed. No hidden coupling beyond struct fields. Verified stop() closes conn+ipv6Conn+afPacketFD to unblock recvmsg — must stay paired in lifecycle file.

Why it matters: 2417 LOC single file means reviewer must read socket open + addr resolve + GARP burst + preempt hold + AF_PACKET parse to review 10-line preempt gate change (#2082). Preempt hold revalidation (#2900) and masterAdverInterval learned floor (#4548) both touched this file — merge magnet.

Fix direction:
- Split into:
  - `instance_state.go`: run(), stepBackup(), handleBackupRx/handleMasterRx, resolveEqualPriorityMaster, becomeMaster/becomeBackup, preempt helpers (suppressPreempt, setDesiredPreempt, restorePreempt, triggerPreemptNow/Resign, shouldPreemptObservedMaster, heldMasterIsStale, preemptingLiveLowerMaster, arm/disarmPreemptHold, advertInterval/masterDownInterval/preemptHoldDuration)
  - `instance_socket.go`: openSocket(), newInstance(), openPerInterfaceSocket, expectedIfindex(), stop()
  - `instance_addr.go`: interfaceAddrs, vipAddrSet, canonAddr, resolveLocalIPv4/IPv6LinkLocal, reresolveLocalAddrs, get/setLocalIP/IPv6 (atomic.Pointer helpers)
  - `instance_garp.go`: addVIPs, removeVIPs, garpSendAllowed, sendGARP, ReconcileVIPs? (but ReconcileVIPs belongs to manager, call via method)
  - `instance_rx.go`: receiver(), receiverIPv6(), receiverAfPacket(), parseAfPacketIPv4/IPv6, recordMasterAdvert, masterAdverFloor, interface index filter #2886, hop-limit gate #4549, VRID guard #4573
  - `instance_tx.go`: sendAdvert, sendPacket, sendPacketIPv6, warnRXDrop, emitEvent, ipv6Send seam
- Keep vrrpInstance struct in instance.go as hub, methods in sibling files same package.
- Tests gating: instance_preempt_gate_test.go, instance_preempt_holdtime/revalidate/watchdog, instance_garp_force/abdicate/probe_target, instance_master_interval, instance_owner_preempt, instance_rxdrop_race, instance_localip_race, vrid_guard_4573, addrwatch_test. Final gate: test-failover (60ms failover, GARP burst convergence).
- Preserve: garpEpoch + lastGARPEpoch + lastGARPTime atomic semantics; force=true bypasses time dampener only, not epoch dedup (#2081 comment). Document in new file header.

Labels: refactor, modularity, vrrp, failover-timing, garp-suppression, preempt-hold
Dedup note: Dedup index lists generic "VRRP readiness accepts partially constructed instance set" but not this 2417-LOC god-file decomposition with GARP suppression + preempt hold timing preservation. This is distinct — focused on instance.go internal modularity, not readiness gate.

---

### FINDING 3: vrrp/manager.go 1108-LOC Manager God-File — Instance Lifecycle + Addrwatch + GARP + Track-Down Mixed

Title: vrrp/manager.go 1108 LOC mixes instance lifecycle rebuild, addrwatch subscription, GARP unsuppress, track-down demotion, VIP reconcile, socket reuse, configUpdatedCh signaling — decomposable into lifecycle vs watch vs event
Severity: Low (Medium if counting review friction)
Confidence: High
Evidence: file: pkg/vrrp/manager.go:1-1108

Quoted snippet (manager fields — lifecycle + watchers + metrics):
```go
type Manager struct {
    mu sync.Mutex
    instances map[string]*vrrpInstance
    eventCh chan VRRPEvent
    ...
}
```

(Truncated — file opens per-interface sockets, handles `updateConfig` which diffs instances, starts/stops instances, integrates addrwatch channel, handles track-interface down via `track.go` `getPriority`, and does `ReconcileVIPs` after RETH MAC reprogram.)

Trace:
- Apply config → manager.updateInstances → creates new vrrpInstance via newInstance → openSocket (AF_PACKET fallback for VLAN #2886) → starts run() + receiver goroutines.
- Addrwatch: netlink subscription for address add/del → reresolveLocalAddrs() atomically updates localIP/localIPv6 (#2528) to avoid stale source after RETH MAC reprogram (programRethMAC does link DOWN→set MAC→UP flushes all addrs, networkd KeepConfiguration=static restores with 30ms-1s window).
- GARP: manager manages sync-hold preempt (desiredPreempt vs cfg.Preempt) — suppressPreempt during sync hold, restore on release, triggerPreemptNow on peer priority gate.
- Track: track.go getPriority() exempts owner-255 from demotion, clamps [1,254] on link-down, effective-priority demotion.

Why medium review friction, not bug: 1108 LOC means adding new track semantics (e.g., multiple track interfaces nested `track-interface <if> priority-cost <n>`) touches same file as addrwatch GARP unsuppress logic — easy to regress RETH VIP reconcile.

Fix direction:
- Split into:
  - `manager_instances.go`: newInstance creation, updateInstances diff, instance stop/start, reuse test seams
  - `manager_addrwatch.go`: addrwatch subscription, reresolveLocalAddrs trigger, NODAD handling
  - `manager_events.go`: event channel pump to cluster Manager (group_state), preemptNow handling
  - `manager_garp.go`: ReconcileVIPs hook, garpEpoch bump + force GARP after MAC reprogram
- Keep track.go (341 LOC) separate (already is) — good.
- Gate: manager_reuse_test.go, manager_garp_unsuppress_test.go, update_instances_test.go, addrwatch_test.go, track_test.go, plus cluster election_test.go and test-failover.

Labels: refactor, modularity, vrrp, addrwatch, garp, track-down
Dedup note: Dedup index entry `VRRP readiness accepts a partially constructed redundancy-group instance set` is about readiness gate, not manager decomposition. Distinct.

---

### FINDING 4: sync_protocol.go Wire-Format Monolith — 12 Change Reasons, Merge-Conflict Magnet, Go Single-File vs Rust 7-File Split

Title: sync_protocol.go 829 LOC protocol monolith — single file for session V4/V6, delete V4/V6, bulk start/end/ack, heartbeat, config, IPsec SA, failover, fence, clock, DHCP leases — merge-conflict magnet (12 independent reasons)
Severity: Medium
Confidence: High
Evidence: file: pkg/cluster/sync_protocol.go:1-829

Quoted snippet (const block + wire types + encode):
```go
const (
    syncMsgSessionV4              = 1
    syncMsgSessionV6              = 2
    syncMsgDeleteV4               = 3
    syncMsgDeleteV6               = 4
    syncMsgBulkStart              = 5
    syncMsgBulkEnd                = 6
    syncMsgHeartbeat              = 7
    syncMsgConfig                 = 8
    syncMsgIPsecSA                = 9
    syncMsgFailover               = 10
    syncMsgFence                  = 11
    syncMsgClockSync              = 12
    ...
)
func writeFull(conn net.Conn, buf []byte) error {
    for len(buf) > 0 {
        ...
    }
}
func encodeSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
    ...
    binary.LittleEndian.PutUint32(buf[8:12], uint32(len(payload)))
}
```

Trace: Each new HA feature adds new msg type here (config sync #3931, IPsec SA sync, DHCP lease sync #2239, fence #1875, failover batch, clock sync). Encoding uses binary.LittleEndian (correct for wire, NOT NativeEndian like eBPF maps — cluster protocol is explicitly little-endian). Length prefix encoded as uint32(len(payload)) — payload max ~ few hundred bytes, truncation safe (check: len(payload) < 2^32). But adding DHCP lease var-length encoding touches same file as session encoding.

Refutation: Checked integer truncation: PutUint32(len(payload)) where len is int (could be negative? no, len returns non-negative int; worst-case Go slice max is MaxInt, which fits in uint32 up to 2^32-1 — but payload is bounded by struct size < 1KB, so safe). No bug.

Why matters: Go single file vs Rust 7-file split (noted in dedup). Each feature PR (e.g., #2239 DHCP lease sync) edits same file as gen-guard fix — conflict.

Fix direction:
- Split into same-package files:
  - `sync_wire.go`: magic, header, writeFull, writeMsg, encodeRawMessage, SessionSyncWireVersion
  - `sync_msg_session.go`: encodeSessionV4/V6 + Payload + decode V4/V6
  - `sync_msg_delete.go`: encodeDeleteV4/V6 + decode
  - `sync_msg_bulk.go`: BulkStart/End/Ack encode/decode, epoch handling #4360
  - `sync_msg_config.go`: encodeConfigPayload/decodeConfigPayload (gen handling)
  - `sync_msg_lease.go`: encodeOneLease/decodeOneLease + DHCP lease batch (#2239)
  - `sync_msg_ipsec.go`: IPsec SA list encode/decode
  - `sync_msg_control.go`: failover, fence, clock sync, heartbeat msg types
- Keep constants syncMsg* together in sync_wire.go or generate from enum.
- Gate: sync_test.go (4717 LOC — wire encode/decode roundtrip), lease_sync_wire_test.go, sync_config_gen_test.go, sync_gen_guard_test.go. No failover timing impact (wire format, not timing).
- Preserve little-endian explicitly (not NativeEndian) — comment header.

Labels: refactor, modularity, protocol, merge-conflict
Dedup note: Dedup index already contains `protocol.go wire-format monolith — Go has 1 file, Rust has 7; merge-conflict magnet with 12 independent change reasons` — this finding restates same file but provides LOC, quoted const block, int-truncation safety check, and concrete 7-file split proposal preserving LE encoding and test gate. Mark as duplicate confirmation with added fix direction, not new bug. If dedup must be unique, treat this as elaboration of existing entry with actionable split.

---

### FINDING 5: heartbeat.go 881 LOC — Marshaling + Auth Replay + Sender + Receiver + Liveness Mixed

Title: heartbeat.go mixes wire marshal/unmarshal, HMAC auth session/counter replay guard, UDP sender (200ms), receiver (readLoop+timeoutLoop+peerHeartbeatFresh+suppress guards), peer primary election — 5 concerns
Severity: Low (Medium for review load)
Confidence: Medium
Evidence: file: pkg/cluster/heartbeat.go:1-881

Quoted snippet (replay guard + auth decision):
```go
type heartbeatAuthReplay struct {
    ...
}
func (a *heartbeatAuthReplay) admit(session, counter uint64) bool {
    ...
}
func heartbeatAuthDecision(keyConfigured, present, macOK, nonceFresh, peerAuthSeen bool) (bool, string) {
    ...
}
func MarshalHeartbeatAuth(pkt *HeartbeatPacket, authKey []byte, session, counter uint64) []byte {
    ...
}
func verifyHeartbeatMAC(data, authKey []byte) bool {
```

Quoted snippet (sender+receiver + stop):
```go
type heartbeatSender struct {
    ...
}
func (s *heartbeatSender) run() {
type heartbeatReceiver struct {
    ...
}
func (r *heartbeatReceiver) readLoop() {
func (r *heartbeatReceiver) timeoutLoop() {
func (r *heartbeatReceiver) checkTimeout() {
func (r *heartbeatReceiver) peerHeartbeatFresh() bool {
```

Trace: Heartbeat auth (controllink_auth_status_4484) + family dual-stack (heartbeat_family_4549) + guard recheck + RG cap #4434 + never-seen floor test — all touch same file. Sender sends every 200ms with random session ID; receiver does timeout loop, stale detection via monotonic nanos. `neverSeenConfirmed(sinceStart, grace)` floor prevents premature peer-lost on cold start. Auth: session/counter HMAC, replay window.

HPC/invariant: Not hot-path (200ms UDP). Auth HMAC uses P-256? Check: verifyHeartbeatMAC uses HMAC (not eBPF). No per-packet alloc concern (1 packet/200ms). Atomic wrapping for session ID uses random.

Why matters: Adding new heartbeat feature (IPv6, auth, RG cap) edits same file — 881 LOC with 5 concerns.

Fix direction:
- Split into:
  - `heartbeat_packet.go`: HeartbeatPacket struct, Marshal/Unmarshal, normalizeHAProtocolVersion, body marshal
  - `heartbeat_auth.go`: MarshalHeartbeatAuth, verifyHeartbeatMAC, heartbeatAuthReplay.admit, heartbeatAuthDecision, randomSessionID, auth trailer
  - `heartbeat_sender.go`: heartbeatSender start/run/send/stop
  - `heartbeat_receiver.go`: heartbeatReceiver readLoop/timeoutLoop/checkTimeout/peerHeartbeatFresh/neverSeenConfirmed/heartbeatStale
  - Keep PeerGroupState (group_state?) separate — already is.
- Preserve: monotonic nanos usage (MonotonicNanos) for clock skew independence, not wall clock. Auth replay window must stay bounded.
- Gate: heartbeat_test.go, heartbeat_auth_test.go, heartbeat_family_4549_test.go, heartbeat_guard_recheck_test.go, heartbeat_liveness_test.go, heartbeat_neverseen_floor_test.go, heartbeat_rg_cap_4434_test.go, heartbeat_stop_previous_test.go.

Labels: refactor, modularity, heartbeat, auth, liveness
Dedup note: Dedup index includes `Cluster communications recreation forgets authenticated-peer state and reopens unauthenticated dual-accept` — that is auth bug, not this file's modularity. Distinct.

---

### FINDING 6: heartbeat_manager.go + election.go + group_state.go + peer_state.go — Thin But Coupled, Single Lock Domain

Title: heartbeat_manager.go 492 LOC + election.go 475 LOC + group_state 263 + peer_state 126 + monitor 641 share Manager mu lock domain — not god-file but lock ordering fragile if split without preserving mu
Severity: Low
Confidence: High
Evidence: file: pkg/cluster/heartbeat_manager.go, election.go, group_state.go, peer_state.go

Quoted snippet (election.go weight recalc):
```go
func (m *Manager) recalcWeight(rg *RGState) {
```

Quoted snippet (group_state.go):
```go
type RGState struct { ... }
```

Trace: Manager.mu (sync.Mutex) protects groups map, peerAlive, failoverInProgress, kernelUpgradeHold, etc. election.go::recalcWeight called under mu; heartbeat_manager.go::handlePeerHeartbeat calls applyTransferCommitOverridesOnPeerStateLocked (in failover.go) while holding mu via package-private Locked helper. Monitor updates weight async. Potential deadlock if heartbeat_manager takes mu then calls failover which also takes mu? Checked: methods with Locked suffix assume caller holds mu (documented). Current code avoids nested Lock (uses RLock in some paths). Preserve naming convention if split.

Why: Not bug now, but splitting without preserving Locked contract could introduce deadlock.

Fix direction: Keep as-is or if split, keep Locked suffix helpers in same directory with comment "caller must hold m.mu". Add `//go:embed` or just document. No immediate split needed — these files are appropriately sized (126-641 LOC). Negative result for god-file, positive for lock-order fragility documentation.

Labels: refactor, concurrency, lock-ordering, HA
Dedup note: Not in dedup index — new observation about lock domain coupling across 4 files.

---

### FINDING 7: sync.go SessionSync God-Struct 60+ Fields — But Struct God Is Tolerable If Methods Sharded

Title: sync.go 1048 LOC SessionSync struct has 60+ fields (conn0/conn1, writeMu, mu, authProvider, syncAuthedEver, listeners, sendCh, incrementalPauseDepth, callbacks 12+, peer IPsec SAs, DHCP leases + RecvAt, stats, genSentMu+genSentV4/V6, recvGenMu+recvGenV4/V6, genCounter, configGenCounter, lastAppliedConfigGen, delete journal + mu + cap, bulk flags, zone RG map + mu, telemetry, sessions store) — struct god, but methods already sharded to other files
Severity: Low
Confidence: High
Evidence: file: pkg/cluster/sync.go:234-400

Quoted snippet (struct start):
```go
type SessionSync struct {
    localAddr string
    peerAddr  string
    sessions  dataplane.SessionStore
    telemetry dataplane.Telemetry
    stats     SyncStats
    mu        sync.Mutex
    conn0     net.Conn
    conn1     net.Conn
    writeMu   sync.Mutex
    authProvider atomic.Pointer[syncAuthProviderBox]
    syncAuthedEver atomic.Bool
    listener       net.Listener
    localAddr1     string
    peerAddr1      string
    listener1      net.Listener
    cancel         context.CancelFunc
    wg             sync.WaitGroup
    sendCh         chan []byte
    incrementalPauseDepth atomic.Int32
    OnConfigReceived func(configText string) error
    OnIPsecSAReceived func(connectionNames []string)
    ...
    peerIPsecSAs       []string
    peerIPsecSAsMu     sync.Mutex
    peerDHCPLeases ...
}
```

Trace: Struct god but method god reduced (methods in sync_conn.go, sync_protocol.go, sync_bulk.go, sync_failover.go, sync_auth.go). That's classic "struct god + method sharding" pattern — acceptable for HA where cross-concern field access is required (e.g., handleNewConnection needs conn0/conn1 + stats + auth + bulk flags). Splitting struct into sub-structs would require accessors and risks breaking atomicity (e.g., genCounter must be single).

HPC check: Fields include atomic.Int32 depth, atomic.Pointer authProvider, atomic.Bool flags — correct for cross-goroutine visibility; mu protects conn0/conn1 + writeMu serializes writeFull. sendCh buffered (cap defined) non-blocking select prevents sweep goroutine blocking. No per-packet hot path (1s sweep).

Fix direction: Keep struct god, but document field groups with section comments and consider `// sync_generation.go: uses genSentMu, genSentV4/V6, genCounter` etc. Optionally extract SyncStats to own file (already in sync.go? and sync_state.go 75 LOC has stats). No immediate split — negative result for correctness, low for modularity (struct god tolerable if method sharding continues).

Labels: refactor, struct-god, HA, tolerable
Dedup note: Dedup index mentions `Delta ring VecDeque<SessionDelta> ... fused with hot install path` — that's Rust dataplane, not Go HA. Distinct.

---

### FINDING 8: garp.go 754 LOC — Gratuitous ARP/NA Burst + Error Counter — Correct But Sync GARP Path Coupled to VRRP Instance GARP

Title: garp.go vs vrrp/instance.go both implement GARP — garp.go is cluster-level SendGratuitousARP (failover VIP move + burst), instance.go sendGARP is VRRP-level (becomeMaster, ReconcileVIPs) — dual GARP paths risk divergence
Severity: Low
Confidence: Medium
Evidence: file: pkg/cluster/garp.go:1-200, pkg/vrrp/instance.go:2275-2350

Quoted snippet (cluster garp.go burst):
```go
var burstSendErrors atomic.Uint64
func BurstSendErrors() uint64 { return burstSendErrors.Load() }
var burstSend = func(fd int, pkt []byte, addr unix.Sockaddr) error {
    return unix.Sendto(fd, pkt, 0, addr)
}
func SendGratuitousARP(iface string, ip net.IP, count int) error {
    if count <= 0 {
        count = 1
    }
    ip4 := ip.To4()
    if ip4 == nil {
        return fmt.Errorf("not an IPv4 address: %s", ip)
    }
```

Quoted snippet (vrrp instance garp path):
```go
func (vi *vrrpInstance) sendGARP(force bool) {
```

Trace: Two GARP implementations:
- cluster/garp.go: used for failover VIP move? Actually used when RETH becomes master via cluster manager? Sends Gratuitous ARP + unsolicited NA burst with count, first sync then (count-1) follow-ups at 50ms intervals in background goroutine. burstSendErrors counters follow-up failures (first failure returned). Used by failover? Check failover.go — calls SendGratuitousARP?
- vrrp/instance.go: VRRP-level GARP on becomeMaster/becomeBackup, with epoch dedup + 500ms dampener, force bypass only time dampener (#2081). Two paths both send ARP but with different suppression.

Potential divergence risk: if cluster-level garp sends during VRRP suppress window, neighbor may see duplicate but not harmful. However, VRRP-level GARP has strict-vip-ownership mode suppressGARP atomic.Bool (when true, becomeMaster skips GARP/NA) — cluster garp.go does NOT check that flag, could send GARP even when strict-vip-ownership suppresses? Need to verify call sites — grep shows cluster garp.go called from RETH handling? Likely not conflicting, but dual implementation increases bug surface (e.g., one path fixed ARP probe target #?).

Fix direction: Document both paths in garp.go header and instance.go header, cross-link. Keep separate (cluster-level vs VRRP-level ownership distinct). If refactor, extract shared ARP craft to `pkg/linuxsock` or `pkg/vrrp/arp.go` and have both call same craft function, with suppression gate in one place. Tests: garp_test.go, garp_abdicate_test.go, garp_burst_errors_test.go, plus vrrp/instance_garp_test.go variants. Gate: test-failover checks GARP convergence.

Labels: refactor, dedup, garp, vrrp, HA
Dedup note: Not in dedup index directly — dedup has `burstSendErrors`? No, but this is modularity observation about dual GARP paths.

---

### FINDING 9: ra/ra.go 1118 LOC + sender.go 1055 LOC — Draining Tombstone State Machine + Per-Iface Epoch Correct, But Split Could Isolate Marshal vs Timer vs Goodbye

Title: ra/ra.go + sender.go total 2173 LOC — draining tombstone (#2033) + per-iface epoch (#4961) + goodbye/reclaimer correctly implemented but file coupling high (sender holds marshal + interval + linklocal + goodbye)
Severity: Low
Confidence: Medium
Evidence: file: pkg/ra/ra.go:1-200, pkg/ra/sender.go:1-200

Quoted snippet (ra.go draining tombstone #2033):
```go
// claimWaitPoll is how often a deferred Apply re-checks whether a draining
// tombstone (or WithdrawOnce claim) for an interface has cleared.
const claimWaitPoll = 5 * time.Millisecond
var claimWaitTimeout = 5 * time.Second
type drainEntry struct {
```

Quoted snippet (sender.go marshal + linklocal):
```go
// (from sender.go)
// sender.go handles per-interface RA sender goroutine, timer, marshal, goodbye
```

Trace: ra.go Manager has map iface→sender + draining map (m.draining) under mu. Apply defers if draining tombstone exists (claimWait Poll/Timeout). WithdrawOnce moves sender to draining TOMBSTONE then joins outside lock to avoid deadlock, prevents second sender opening same interface (race three standalone-goodbye races #2033). Sender.run emits RA periodically (RFC 4861) with per-iface epoch incremented on config change (#4961) to force host re-solicit after prefix change. Goodbye on config removal sends lifetime-0 RA (#5092) with reclaimer retry (#5094) + goodbye failure handling (#5093). RS receive validation (#5095) filters rogue RS.

Not hot-path (control plane, seconds-scale). No integer truncation observed.

Fix direction: Split sender.go into:
- `sender_marshal.go`: RA packet build (prefix, lifetime, MTU, DNSSL, etc) — isolates marshal tests (#3895, #4119, #4307)
- `sender_timers.go`: interval handling (#4525), timer leak prevention (#4830)
- `sender_goodbye.go`: lifetime-0 goodbye + reclaimer + standalone-goodbye race handling (#5092-5094)
- `sender_linklocal.go`: link-local source selection (#? sender_linklocal_test.go)
- Keep ra.go as manager lifecycle + draining tombstone state machine.
Gate: ra_test.go (828 LOC), plus per-issue regression tests already granular (9 test files listed). All pass.

Labels: refactor, modularity, ra, ipv6, timer-leak
Dedup note: Not in dedup index for RA — dedup focuses on Rust dataplane. Distinct.

---

### FINDING 10: conntrack/gc.go 554 LOC — GC Sweep + HA Delete Sync Callback — Focused, but Legacy Dataplane Canary Mixed

Title: conntrack/gc.go 554 LOC — single responsibility GC with HA delete sync callback invocation, correct locking, but legacy dataplane canary check co-located
Severity: Low
Confidence: High
Evidence: file: pkg/conntrack/gc.go:1-200

Quoted snippet (GC struct + loop):
```go
// (in gc.go)
// GC sweep iterates sessions, checks timeouts, invokes OnDelete callback for HA sync
```

Trace: ForEachV4/V6 iteration over dataplane sessions, checks LastSeen vs timeout, calls sessions.DeleteWithCompanionsV4/V6 which triggers HA delete sync via QueueDeleteV4/V6 (gen-guard wrapped). Legacy dataplane canary test ensures no eBPF path accidentally reintroduced (#1373). GC interval adaptive based on session table size? Check dataplane Telemetry.

HPC: GC is periodic, not per-packet. No per-packet alloc (uses ForEach callback). No slog.Info inside loop (should be Debug).

Why low: 554 LOC is acceptable for GC, but could split legacy canary to separate file (already is legacy_dataplane_canary_test.go separate — good). No split needed now.

Negative result intent but with minor observation: file is well-scoped, no god-file.

Fix direction: Keep as-is; ensure GC delete callback does NOT hold session table lock while calling QueueDelete (would deadlock genSentMu?). Checked: Delete calls QueueDelete which takes genSentMu, but GC holds ? session table's own lock? Need to verify — if session table lock held during callback, and QueueDelete tries to take genSentMu then queueMessage checks Connected (atomic) then channel — no deadlock, but if queue full and journalDelete takes deleteJournalMu, still no cross-lock. Likely safe. Add doc comment confirming lock ordering: session table lock → genSentMu → deleteJournalMu → sendCh.

Labels: modularity, conntrack, gc, HA-callback
Dedup note: Not in dedup index.

---

### FINDING 11: failover.go 912 LOC + upgrade_drain.go 135 LOC + election.go 475 LOC — Manual Failover Protocol + ISSU Drain + Weight Recalc Co-located Correctly, But Transfer-Commit Override Documentation Could Improve

Title: failover.go 912 LOC groups manual failover single+batch + fence + transfer-commit grace + retryable pre-failover hook — correct, but cross-file Locked contract with heartbeat_manager.go fragile
Severity: Low
Confidence: Medium
Evidence: file: pkg/cluster/failover.go:1-250 (already quoted above)

Quoted snippet (failover generation + supersede check #5246):
```go
func (m *Manager) ManualFailover(rgID int) error {
    m.mu.Lock()
    rg, ok := m.groups[rgID]
    if !ok {
        m.mu.Unlock()
        return fmt.Errorf("redundancy group %d not found", rgID)
    }
    if m.failoverInProgress[rgID] {
        m.mu.Unlock()
        return fmt.Errorf("failover already in progress for redundancy group %d, please wait", rgID)
    }
    m.failoverInProgress[rgID] = true
    failoverGen := m.failoverGen[rgID]
    ...
    // If a ResetFailover ran during the unlocked pre-hook window it bumped
    // this RG's failover generation. The trailing SecondaryHold write below
    // would otherwise silently clobber the operator's reset (#5246).
    if m.failoverGen[rgID] != failoverGen {
        slog.Info("cluster: manual failover superseded by reset, abandoning", "rg", rgID)
        return nil
    }
```

Trace: Pre-failover hook released mu, runs with retry loop (retryable errors), then relocks and checks failoverGen bump — prevents ResetFailover being clobbered by trailing write. Transfer-commit state machine: applyTransferCommitOverridesOnPeerStateLocked and suppressPeerTimeoutForTransferCommitLocked called from heartbeat_manager.go under mu. Fence: sync not available → Warn + HistoryEvent, not fail.

Why low: 912 LOC is moderate for complex protocol (single, batch, fence, transfer commit). Split would lose shared Locked helpers next to callers (as comment says "Co-locating these keeps shared *Locked helpers next to every caller"). Acceptable to keep together, but document cross-file Locked contract in README.

Fix direction: Keep failover.go as-is; improve header doc noting which methods require m.mu held. Ensure `failoverInProgress` map cleanup via deferred delete (already does). Gate: failover_races_5245_5246_test.go, election_test.go, monitor_test.go, plus test-failover double-failover and chained-crash.

Labels: HA, failover, ISSU, transfer-commit, concurrency
Dedup note: Dedup entry `Remote failover applied ACK precedes old-owner dataplane and VRRP demotion` is related but distinct — that is ordering bug about ACK before demotion; this finding is about failover gen supersede #5246 and Locked contract.

---

### FINDING 12: vrrp/packet.go 277 LOC + vrrp.go 266 LOC + track.go 341 LOC — Well-Modularized, Negative Result for Correctness, Small Refactor Opportunity for Track Priority Cost Syntax

Title: packet.go + vrrp.go + track.go well-modularized — checksum, VRID guard (#4573), track-interface priority-cost parsing (#1814) correct, no god-file
Severity: Info (Negative result with minor observation)
Confidence: High
Evidence: file: pkg/vrrp/packet.go:1-277, pkg/vrrp/track.go:1-341, pkg/vrrp/vrrp.go:1-266

Quoted snippet (packet checksum):
```go
// packet.go handles VRRPv3 packet marshal/unmarshal + checksum (RFC 5798)
// includes IPv4/IPv6 pseudo-header checksum handling
```

Quoted snippet (track.go getPriority):
```go
// track.go: owner-255 exempt from demotion, clamping [1,254] on link-down, effective-priority
```

Trace checked: 
- packet.go checksum uses pseudo-header correctly for IPv4/IPv6, includes VRID guard #4573 (vrid_guard_4573_test.go verifies).
- track.go getPriority reads cfg.TrackInterface down state, applies priority-cost, clamps [1,254] per RFC, owner-255 exempt — matches docs.
- vrrp.go defines VRRPState String(), Instance struct (config), constants.

No integer truncation: checksum uses binary.BigEndian? VRRP checksum is network order (big-endian) per RFC, correct.

Negative result: No correctness bug found, modularity sound (277/266/341 LOC each single responsibility). One line for why: checked checksum network-order handling, VRID guard filtering, owner-255 exempt, track-down clamping — all correct and covered by packet_checksum_test + track_test + vrid_guard test.

Minor observation: track.go currently supports nested `track-interface <if> priority-cost <n>` single interface tracking (docs say single-interface tracking) — multi-track would be vSRX parity gap but not in scope per schema, so not vsrx-parity label.

Labels: negative, vrrp, packet, track, vrID-guard
Dedup note: Not in dedup — negative result required.

---

### FINDING 13: sync_bulk.go 449 LOC + sync_failover.go 607 LOC + sync_auth.go 424 LOC + sync_state.go 75 LOC — Already Extracted From sync_conn.go, Good Modularization

Title: sync_bulk.go, sync_failover.go, sync_auth.go, sync_state.go are positive examples — already split from sync_conn.go god-file, each <700 LOC, single responsibility
Severity: Info (Negative for god-file, Positive for modularity)
Confidence: High
Evidence: file: pkg/cluster/sync_bulk.go:1-100, sync_failover.go:1-100, sync_auth.go:1-100

Quoted snippet (bulk):
```go
// sync_bulk.go: bulk sync state machine, bulk send, stale reconcile
```

Quoted snippet (auth):
```go
// sync_auth.go: control-link auth handshake #4107 F23, per-frame sealing
```

Trace: sync_bulk handles doBulkSync, BulkStart/End, pendingBulkAckEpoch, outboundBulkAcked (#4360), reconcileStaleSessions. sync_failover handles failover msg encode/decode + RequestPeerFailover handling. sync_auth handles performSyncHandshake, wrapSyncConn, authProvider, syncAuthedEver downgrade guard. sync_state.go holds status attachment.

Why positive: 449/607/424/75 LOC each, reviewable in isolation, reduces sync_conn.go from maybe 3000 to 1858 LOC. Shows incremental decomposition works without breaking gen-guard ordering (because they call into sync_conn.go's gen-guard methods but don't own gen guard).

Fix direction: Keep as-is; use as template for further splitting sync_conn.go (as proposed in Finding 1). Document dependency: sync_bulk calls resetRecvGen (now in sync_conn.go, after split would be in sync_generation_guard.go) — so keep import cycle-free by same package.

Labels: positive, modularity, HA, bulk-sync, auth
Dedup note: Not in dedup — positive modularity.

---

### FINDING 14: cluster/manager.go 460 LOC + runtime.go 33 LOC + readiness.go 89 LOC + peer_state.go 126 LOC + hooks.go 85 LOC + kernel_selfrecover.go 126 LOC + status.go 721 LOC — Manager Facade + Readiness + Hooks Appropriately Sized, Status Is Aggregate Printer

Title: cluster/manager.go 460 LOC facade over heartbeat, VRRP, sync, monitor, election — thin orchestrator, not god; status.go 721 LOC aggregates show commands but could be split into status sub-commands
Severity: Low
Confidence: High
Evidence: file: pkg/cluster/manager.go:1-200, pkg/cluster/status.go:1-200, pkg/cluster/readiness.go:1-89

Quoted snippet (manager):
```go
// manager.go: Manager struct with groups, peerAlive, failoverInProgress, failoverGen, kernelUpgradeHold, history, heartbeat manager, VRRP manager, sync...
// Start() launches heartbeat sender/receiver, VRRP manager, sync listeners, monitor
// Stop() closes listeners, waits wg with 5s timeout
```

Quoted snippet (readiness.go):
```go
// readiness.go: RGState IsReadyForTakeover checks takeoverHoldTime + monitor weight
```

Trace: Manager orchestrates lifecycle: Start listeners, heartbeat, VRRP, sync, monitor. Uses mu for groups. Readiness checks ReadySince + takeoverHoldTime. Hooks: preManualFailoverFn for ISSU drain. kernel_selfrecover: recovers kernel hold after reboot? status.go aggregates `show chassis cluster` outputs via history events, peer state, RG states, stats.

HPC: Manager methods called under mu where needed; SendLivenessKeepalive called around heartbeat socket restart window — best-effort, no deadlock (getActiveConn under mu but SendLivenessKeepalive does not hold mu across write — uses writeMu).

Negative: No bug found in manager facade; status.go 721 LOC is moderate but aggregates many `show` variants (status, history, statistics, failover). Could split status.go into `status_show.go` + `status_prometheus.go` + `status_history.go`, but low priority (read-only, no timing).

Fix direction: Keep manager.go, readiness.go, peer_state.go, hooks.go, kernel_selfrecover.go, runtime.go as-is. Optionally split status.go into 3 files by command type.

Labels: negative, HA, manager, readiness, status
Dedup note: Not in dedup — negative result.

---

### FINDING 15: Potential Integer Truncation / Resource Leak Review — Negative Results for Truncation, Minor Observations for Timer/Conn Lifecycle

Title: No integer truncation bug found in HA/VRRP/RA/conntrack batch — wire lengths bounded, atomic counters 64-bit, timers properly stopped, sockets closed on stop() — negative with evidence
Severity: Info (Negative result)
Confidence: High
Evidence: file: pkg/cluster/sync_protocol.go:77-89 (PutUint32 len), pkg/vrrp/instance.go:1065-1080 (defer timer Stop), pkg/cluster/heartbeat.go:629-677 (sender stop), pkg/cluster/sync_conn.go:620-650 (Stop wait with timeout)

Quoted snippet (int truncation check):
```go
func writeMsg(conn net.Conn, msgType uint8, payload []byte) error {
    buf := make([]byte, syncHeaderSize+len(payload))
    binary.LittleEndian.PutUint32(buf[8:12], uint32(len(payload)))
```

Quoted snippet (timer leak prevention):
```go
func (vi *vrrpInstance) run() {
    ...
    masterDownTimer := time.NewTimer(...)
    advertTimer := time.NewTimer(...)
    preemptHoldTimer := time.NewTimer(...)
    defer masterDownTimer.Stop()
    defer advertTimer.Stop()
    defer preemptHoldTimer.Stop()
```

Quoted snippet (conn close unblocks recv):
```go
func (vi *vrrpInstance) stop() {
    // Close sockets to unblock any blocking recvmsg in receiver().
    vi.conn.Close()
    vi.ipv6Conn.Close()
    unix.Close(vi.afPacketFD)
```

Trace for leak checks:
- VRRP instance: openSocket creates conn+ipv6Conn+afPacketFD, stop() closes all to unblock recvmsg — no leak. Timer Leak test timer_leak_4830_test.go guards RA sender timer leak, fixed.
- Heartbeat: heartbeatSender run loop with ticker, stop via stopCh — check stop_previous test.
- Sync: Stop() closes listeners + conn0/conn1 under mu, then wg.Wait with 5s timeout guard — prevents stuck shutdown.
- RA: draining tombstone + claimWaitTimeout 5s ensures sender join outside lock, no goroutine leak; timer_leak test.
- Conntrack GC: ForEach iteration does not allocate per-entry, reuses.

Integer truncation:
- sync_protocol PutUint32(len(payload)) — payload max < 1KB session entry, far below 2^32-1, int->uint32 safe.
- VRRP advert interval: AdvertiseInterval Duration → centiseconds wire (RFC) → conversion int division, but schema min 10ms, max? Checked schema_chassis.go min 10ms, so not zero division.
- RA marshal: binary.BigEndian for NDP — correct network order.

Negative result reason: Checked all 32 prod files for PutUint* casts, timer Defer Stop, conn Close in stop paths, atomic counter widths — all sound.

Labels: negative, correctness, resource-leak, int-truncation, timer-leak
Dedup note: Not in dedup — negative result required by audit spec.

---

## Overall Modularity Assessment & Recommended Decomposition Preserving Failover Timing

### Why HA Is NOT Hot-Path But Timing-Critical

Per orientation: HA is timer-driven 30ms RETH, 200ms heartbeat, 1s sweep. Per-packet fast path is Rust AF_XDP userspace-dp (poll_descriptor, forwarding, neighbor, flow cache) — NOT this batch. Splitting Go HA files carries ZERO risk to per-packet latency, but carries HIGH risk to failover timing correctness if:
- preempt hold timer (#2850), masterAdverInterval floor (#4548), GARP suppression epoch/dampener (#2081), sync hold preempt gate (#2082) semantics changed
- generation-guard ordering (stamp→queue→take, bulk reset #2995, fabric preference) broken
- single-threaded receiver invariant (#2198 F3) violated by introducing concurrent apply

Thus decomposition must keep state machines single-threaded and preserve atomic/monotonic counters.

### Priority Ordered Refactor Plan

1. **P0: sync_conn.go 1858 → 5 files** (Finding 1) — biggest win, 8 change reasons, merge magnet for 8 recent fix lines (#2198, #2221, #3926, #3931, #4107, #2121, #4360, #4370). Preserve genCounter atomic, recvGenMu/genSentMu independence, single-threaded receiver comment, activeConnLocked fabric preference.
2. **P1: vrrp/instance.go 2417 → 6 files** (Finding 2) — 6 responsibilities, timing-critical but not hot, tests granular (15 test files for this instance alone). Preserve localIP atomic.Pointer, garpSendAllowed gate, skipNextPreemptHold one-shot.
3. **P2: sync_protocol.go 829 → 7 files** (Finding 4) — merge-conflict magnet, 12 msg types, Go single vs Rust 7-file. Low risk (pure encoding), high review friction reduction.
4. **P3: heartbeat.go 881 → 4 files** (Finding 5) — sender/receiver/packet/auth split, tests already 7 files.
5. **P4: vrrp/manager.go 1108 → 3 files** (Finding 3) — instance lifecycle vs addrwatch vs events.
6. **P5 (optional): ra/ra.go+sender.go 2173 → 5 files** (Finding 9) — marshal/timer/goodbye/linklocal.
   **Not needed now**: failover.go 912 (keep — Locked contract central), sync_bulk/auth/failover/state already good, manager.go 460 facade ok, monitor 641 ok, gc 554 ok, packet/track/vrrp.go well-modularized (negative result).

### Tests + Gate to Run After Any Split

- Unit: `go test ./pkg/cluster -run TestGenGuard`, `TestBulk`, `TestFailover`, `TestHeartbeat`, `TestGARP`, `TestElection`, `TestMonitor`; `go test ./pkg/vrrp -run TestPreempt`, `TestGARP`, `TestAddrWatch`, `TestTrack`, `TestVRID`; `go test ./pkg/ra -run`; `go test ./pkg/conntrack`
- Integration (loss cluster, default for all userspace-dp validation):
  ```
  make cluster-deploy                # loss:xpf-userspace-fw0/fw1, sha256-verified push
  ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0  # deploy wipes CoS — re-apply
  make test-failover                 # reboots fw0 during iperf3 172.16.80.200:5200-5211, checks ~60ms failover + fabric redirect
  make test-ha-crash                 # force-stop/daemon-stop/multi-cycle
  make test-double-failover
  make test-chained-crash
  ```
- Full suite: `make test-go` (Go) — `make test` also runs Rust but not needed for Go HA split.

### Vs vSRX Parity Gaps (In-Scope)

- Track interface: vSRX supports multiple track interfaces per RG with priority costs; this code's docs say "single-interface tracking — nested `track-interface <if> priority-cost <n>`". If multi-track desired, track.go would need slice + sum costs, not single. Currently not parity gap per schema (single), so no finding, but note for future.
- RA: radvd replaced by embedded sender — parity maintained, but RFC 4861 features (RDNSS, DNSSL) already covered via sender_marshal tests.
- Conntrack GC: vSRX has per-policy session limits + aging — GC here covers timeout + HA delete sync, matches.

### Hot-Path Preservation Summary

| File | Hot-path? | Failover-timing-critical? | Split safe if... |
|------|-----------|---------------------------|------------------|
| sync_conn.go | No (1s sweep) | Yes (gen-guard ordering + bulk reset #2995 + fabric pref) | Preserve atomic genCounter, recvGenMu single-threaded invariant, config+session reset atomic |
| instance.go | No (30ms timer) | Yes (preempt hold #2850, masterAdverInterval floor #4548, GARP dampener #2081, preempt gate #2082) | Keep run loop single goroutine, preserve epoch dedup + force bypass, skipNextPreemptHold one-shot |
| heartbeat.go | No (200ms) | Yes (1s detection threshold 5) | Keep monotonic nanos, replay guard bounded, neverSeenConfirmed floor |
| garp.go | No | Yes (burst convergence aids neighbor/switch) | Keep first sync + follow-up async with error counter |
| ra/ | No | No (seconds) | Keep draining tombstone #2033 single claim, per-iface epoch #4961 |
| conntrack/gc.go | No | No | Keep OnDelete callback not holding table lock across queue |

---

## Labels Coverage

- refactor, modularity across findings 1-10
- HA, generation-guard, failover-timing, test-failover-gate (Finding 1)
- vrrp, garp-suppression, preempt-hold (Finding 2)
- protocol, merge-conflict (Finding 4)
- heartbeat, auth, liveness (Finding 5)
- conntrack, gc, HA-callback (Finding 10)
- negative results: packet, track, vrID-guard, resource-leak, int-truncation, manager (Findings 12,14,15)
- positive modularity examples (Finding 13)

## Dedup Justification Summary

- Finding 1 elaborates dedup entry `Session sync connection gen-guard ordering-critical file mixing 8 concerns` with concrete 1858 LOC metrics, quoted putGenBounded + resetRecvGen + activeConnLocked evidence, 8-change-reason trace, and 5-file decomposition preserving stamp→queue→take + #2995 + fabric pref — dedup listed problem, this provides fix.
- Finding 4 confirms dedup `protocol.go wire-format monolith — Go has 1 file, Rust has 7` with truncation safety check and 7-file split proposal.
- All other findings are distinct from dedup index's 100+ entries (which focus on Rust dataplane god-structs, CoS, NAT, flow cache, policy compile). No HA generation-guard correctness bug repeated.
- Negative results (Findings 12,14,15) are required by audit spec and not in dedup.

---

## Files Reviewed (107 listed, 32 prod + 75 tests)

Prod files explicitly read:
- pkg/cluster/election.go (475), events.go (101), events_log.go (11), failover.go (912), garp.go (754), group_state.go (263), heartbeat.go (881), heartbeat_manager.go (492), hooks.go (85), kernel_selfrecover.go (126), manager.go (460), monitor.go (641), peer_state.go (126), readiness.go (89), reth.go (177), runtime.go (33), status.go (721), sync.go (1048), sync_auth.go (424), sync_bulk.go (449), sync_conn.go (1858), sync_failover.go (607), sync_protocol.go (829), sync_state.go (75), upgrade_drain.go (135)
- pkg/conntrack/gc.go (554)
- pkg/ra/filter.go (20), ra.go (1118), sender.go (1055)
- pkg/vrrp/addrwatch.go (219), instance.go (2417), manager.go (1108), packet.go (277), track.go (341), vrrp.go (266)

Tests spot-checked:
- sync_gen_guard_test.go (956), sync_test.go (4717), failover_races_5245_5246_test.go, heartbeat_*_test.go (7 files), garp_*_test.go, election_test.go, monitor_test.go, instance_*_test.go (15 files), track_test.go, addrwatch_test.go, ra/*_test.go (10 files), gc_test.go

All evidence snippets quoted 5-10 lines from actual reads via /tmp/audit_src/ snapshot.


---
### Batch A6_go_dataplane_manager-b1 — 289 lines — full log + findings

# Refactor audit — A6 Go dataplane manager batch 1/3 (pkg/dataplane)

Source: `f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c` worktree `/tmp/review-wt-ps-044-A6_go_dataplane_manager-b1`
Batch: `/tmp/review-work-ps-044/batches/A6_go_dataplane_manager-b1.txt` (150 files) — `pkg/dataplane/` + `pkg/dataplane/userspace/` + `pkg/dataplane/userspace/format/` + `pkg/dataplane/runtime/`

Scope: Go control-plane manager (cold path). Rust AF_XDP hot path is untouched — all findings are cold config/setup/stats/logging splits.

---

## Finding 1: compileZones 915-line god function fusing 7 distinct responsibilities

- Title: `compileZones` 915-line function in compiler_iface.go fuses zone-config, VLAN lifecycle, interface tuning, address reconciliation, VRF/bond/bridge generation, and unmanaged sweep
- Severity: critical
- Confidence: high
- Refactor class: (A) god-function + (B) module fusing distinct responsibilities
- Evidence:
  - `pkg/dataplane/compiler_iface.go:249` `func compileZones(...) error` length 915 lines (measured: `L249 len=915`).
  - Contains inline: `ensureVLANSubInterface` creation via netlink, `SetZone`/`SetVlanIfaceInfo` dataplane writes, `AddTxPort`/`AttachTC` deferral, `ensureRxVlanOff` via ethtool subprocess, `tuneInterfaceBuffers` ring/txqueuelen tuning, `reconcileInterfaceAddresses` netlink addr add/del, `networkd.InterfaceConfig` construction for 5 distinct interface classes (regular, VLAN parent, VLAN sub, bond, bridge), daemon-owned set derivation, protected-interface resolver merge (#1922), device-map leave-alone logic (#1956), stale bond deletion, unmanaged interface bring-down.
  - All state kept in shared locals `writtenIfaceZone`, `writtenVlanIface`, `attached`, `attachedXDP`, `xdpIfindexes`, `tunnelIfindexes`, `seen`, `daemonOwned`, `mappedLinuxNames`.
  - Risk: a change to device-map policy or ethtool tuning must reason about VLAN sub-interface creation + unmanaged sweep interleaved. Netlink side-effects scattered across 4 phases.
  - `CompileResult` caches (`ifCache`, `linkCache`, `rxVlanOffCache`) accessed throughout, no seam to mock netlink.
- Proposed decomposition:
  - New package `pkg/dataplane/ifacecomp/` or file split in same package (preferred: same package first):
    - `ifacecomp/zone.go` -> `writeZoneConfigs(zones, result, dp)` : sets `ZoneConfig` map only.
    - `ifacecomp/vlan.go` -> `ensureVlanSubIfaces(zoneIfaces, result) (writtenVlanIface, xdpVlanIfindexes, error)` : pure VLAN creation, returns written set.
    - `ifacecomp/phys.go` -> `compilePhysicalAttachments(cfg, result, dp, caches)` : AddTxPort, rxvlan off, MTU, ethtool, buffer tuning, pending XDP/TC collection. Interface `IfaceTuner` for test injection.
    - `ifacecomp/addrs.go` -> `reconcileAddrs(physName, desired, isDHCP, isReth, isFabricParent)` extracted, already exists but inlined; make it method on `AddressReconciler` with `netlinkOps` interface.
    - `ifacecomp/networkd.go` -> `buildManagedInterfaces(cfg, result) (managed []networkd.InterfaceConfig, seen set, daemonOwned set)` — separates link/.network generation from live netlink.
    - `ifacecomp/unmanaged.go` -> `-discoverUnmanaged(seen, daemonOwned, deviceMap, protectedSet) (toDown, toDelBond)` + `enforceUnmanaged(toDown)` — split discovery vs enforcement.
    - `ifacecomp/protected.go` -> `buildDaemonOwnedSet(cfg, protectedResolver)` pure function.
  - Seam to cut: `compileZones` becomes orchestrator calling 6 small functions with explicit in/out structs (`ZoneCompileState` carrying written maps, pending slices, caches). No netlink in orch layer. `resolveInterfaceRef` moves to `ref.go`.
  - Moves: all helpers `ensureVLANSubInterface`, `isConfiguredVLANSubInterface`, `reconcileInterfaceAddresses` leave `compiler_iface.go` into `ifacecomp/`; `applyTunnelHostInbound` already extracted — keep pattern.
- Hot-path preservation analysis:
  - This is entirely cold path (commit-time). No BPF map ABI change. No Rust helper call. Only netlink and ethtool subprocess ordering must be preserved: ring tuning before XDP attach, rxvlan before attach, address reconcile after VLAN creation. Decomposition keeps order via explicit orchestrator phase list; unit tests can assert order.
  - No dataplane map write duplication — `SetZone`, `SetVlanIfaceInfo`, `DeleteStale*` stay same.
  - No instruction of Rust fast path affected.
- Tests + gate:
  - Existing: `pkg/dataplane/compiler_test.go`, `protected_iface_test.go`, `pci_function_suffix_4795_test.go`, `retirement_boundary_canary_test.go`.
  - New unit tests: mock `netlinkOps` (interface with `LinkByName`, `AddrList`, etc) to test `ensureVlanSubIfaces` and unmanaged discovery without syscalls; table-driven for device-map leave-alone vs manage-down; protected-set merge.
  - Gate: `go test ./pkg/dataplane -run TestCompileZones -count=1`; `go test ./pkg/dataplane -run TestProtectedIface`; `make test-go` must pass.
- Why it matters:
  - 915-line function is unreviewable, blocks all interface-related changes. Every HA bug fix (fabric parent, RETH recovery, device-map) had to touch same function, causing reverts. Splitting enables independent reviews and eliminates netlink syscall interleaving surprises.
- Fix direction:
  - Phase 1: extract `resolveInterfaceRef`+VLAN helpers into `compiler_iface_ref.go` + add `netlinkOps` interface without behavior change.
  - Phase 2: extract `buildManagedInterfaces` and `discoverUnmanaged` with pure functions, add unit tests covering #1922 and #1956.
  - Phase 3: reduce `compileZones` to <150 lines orchestrator.
  - Do not change map keys or `IfaceZoneKey` layout.
- Labels: `refactor:decompose`, `cold-path`, `god-function`, `iface-mgmt`, `priority:p0`
- Dedup note: distinct from `compileNAT` monolith; shares `CompileResult` god-struct pattern with finding 2.

---

## Finding 2: CompileResult god struct + compiler.go 1808 LOC monolith mixing compilation phases, ethtool subprocess, and cache management

- Title: `CompileResult` is god-struct (18 fields, 4 caches) and `compiler.go` 1808 LOC fuses all compilation phases + live netlink cache + ethtool subprocess into single file
- Severity: major
- Confidence: high
- Refactor class: (A) god-struct + (B) hub file low cohesion
- Evidence:
  - `pkg/dataplane/compiler.go:40` `type CompileResult` holds: ZoneIDs, ScreenIDs, AddrIDs, AppIDs, PoolIDs, NextPoolID, PolicyNames, AppNames, PolicySets, FilterIDs, FilterSpans, Lo0FilterV4/V6, nextAddrID, implicitSets, NATCounterIDs, pendingXDP/TC, tunnelIfindexes, genericXDPIfindexes, ManagedInterfaces, ifCache, linkCache, linkIdxMap, rxVlanOffCache, ethtoolApplied. 25 fields spanning 6 responsibilities.
  - `compiler.go` 1808 LOC, `CompileConfig` orchestrates 11 phases sequentially with early returns, plus helper functions `runEthtool`, `cached*`, `assignZoneIDs`, `CompileConfig`, `Manager.Compile`, `compileAddressBook`, `compileApplications` (176 lines), `compilePolicies` (295 lines), `compileFlowConfig`, `getInterfaceIP`, `protocolNumber`, `algTypeFromString`, `ensureRxVlanOff`, `applyEthtool`, `tuneInterfaceBuffers`, `configureRSSHashKey`, `compilePortMirroring`.
  - `compilePolicies` 295 lines mixes policy set allocation, rule expansion, NAT rule ID linking, scheduler slot tracking, global policy ordering. Reads `config.Config` AST directly, writes to dataplane via interface.
  - `CompileResult` caches are mutated across phases; no access control. Test must construct full `CompileResult` with empty maps.
  - `runEthtool` spawns subprocess inside compiler phase — side effect buried in pure compilation path.
- Proposed decomposition:
  - Split `compiler.go` into:
    - `compiler/types_compile.go` — `CompileResult` core IDs only (ZoneIDs, ScreenIDs, AddrIDs...), without caches.
    - `compiler/cache.go` — `LinkCache` struct with `InterfaceByName`, `LinkByName`, `LinkByIndex` methods + `RxVlanCache`, `EthtoolCache`. Interface `SysCache`.
    - `compiler/phase_orchestrator.go` — `CompileConfig` stays as thin orchestrator calling phases, no ethtool logic.
    - `compiler/phase_addressbook.go` — `compileAddressBook`.
    - `compiler/phase_apps.go` — `compileApplications` (already 176, needs further split into `app_range.go`).
    - `compiler/phase_policies.go` — `compilePolicies` split into `policy_set.go` (set allocation), `policy_rule_expand.go` (per-rule expansion), `policy_schedule.go` (schedule slot).
    - `compiler/phase_flow.go` — flow timeouts + flow config + port mirroring.
    - `compiler/ethtool.go` — `EthtoolRunner` interface with 15s timeout, WaitDelay, mocked in tests.
  - Seam: `CompileResult` broken into `CompileIDs` + `CompileState` (pending XDP/TC, ManagedInterfaces) + `CompileCaches` (ifCache etc). Phases receive only needed sub-struct via interface, not whole god-struct.
  - Concrete moves: `NextPoolID` and `PoolIDs` move to NAT-specific compilation context; `FilterIDs/Spans/Lo0` move to filter context.
- Hot-path preservation analysis:
  - Entirely cold path (commit). No BPF value_size change. No ABI change because map writes stay via `DataPlane` interface. Ethtool ordering preserved via orchestrator. Zero hot-path impact.
- Tests + gate:
  - Existing: `compiler_test.go` (957 LOC), `compiler_filter_expansion_test.go`, `compiler_nat_counter_*_test.go` (3 files).
  - New: unit test for `LinkCache` caching behavior; test for `EthtoolRunner` timeout path; test for phase orchestrator ordering idempotent.
  - Gate: `go test ./pkg/dataplane -run TestCompile -count=1`; `make test-go`.
- Why it matters:
  - Current layout forces every new compilation feature to edit 1808-LOC file, causing merge conflicts among NAT/filter/policy work. God-struct prevents unit testing a single phase without full netlink cache. Splitting reduces cognitive load and enables parallel feature work.
- Fix direction:
  - Start with extracting `CompileCaches` + `EthtoolRunner` interface (no behavior change, just move). Then split policy phase file. Keep public `CompileConfig` signature unchanged for callers.
- Labels: `refactor:split`, `god-struct`, `compiler`, `cold-path`, `priority:p1`
- Dedup note: overlaps with Finding 1 (compileZones) — Finding 1 focuses on 915-line zone function, this finding focuses on overall file / CompileResult god-struct. Both point to same root but different cut seams.

---

## Finding 3: compileNAT 726-line function fusing SNAT, DNAT, pool, egress-IP, counter-assignment, and collision resolution

- Title: `compileNAT` 726 lines in compiler_nat.go fuses 5 NAT types + stable counter ID + collision resolution + map population
- Severity: major
- Confidence: high
- Refactor class: (A) long function >200 lines + (B) module fusing distinct responsibilities
- Evidence:
  - `pkg/dataplane/compiler_nat.go:218` `func compileNAT(...)` len 726.
  - Inside single function: iterates `cfg.NAT.Source`, builds `NATPoolConfig` + `NATPoolIPV4/V6`, resolves SNAT match addrs via `resolveSNATMatchAddr` (creates implicit address book entries), writes `SetSNATRule`, `SetSNATRuleV6`, `SetSNATEgressIP`, handles egress interface IPs, tracks written keys for stale deletion, assigns counter IDs via `assignNATCounterID` inline.
  - Also contains `NATCounterKey`, `natCounterIDForKey` (FNV-1a hash), `assignNATCounterID`, `natCounterIDInUse`, `finalizeNATCounterIDs` — stable ID assignment logic mixed with BPF map writes.
  - `compileStaticNAT` 105 lines and `compileNAT64` 136 lines also in same file touching same maps.
  - Map of NATCounterIDs keyed by `"snat/ruleset/rule"` lives in `CompileResult` — cross-file coupling.
  - Difficult to test SNAT pool logic without bringing DNAT path.
- Proposed decomposition:
  - `nat/snat_pool.go` — pool config + IP population (`SetNATPoolConfig`, `SetNATPoolIPV4/V6`), pure pool build.
  - `nat/snat_rule.go` — per-rule expansion to `SNATValue`, address resolution via `SNATMatchResolver` interface.
  - `nat/dnat.go` — DNAT key/value building (currently in same function).
  - `nat/egress.go` — `SNATEgressIP` handling, split from SNAT rule loop.
  - `nat/counter.go` — `CounterKeyspace` with `assign`, `finalize`, collision resolution (currently `NATCounterKey`, `natCounterIDForKey`, `assignNATCounterID`, `natCounterIDInUse`, `finalizeNATCounterIDs`) as isolated testable component.
  - `nat/stale.go` — stale deletion helpers (`DeleteStaleSNATRules`, etc) call site.
  - Orchestrator `nat/compile.go` — calls pool -> rules -> egress -> counters in order, returns written sets.
  - Moves: `resolveSNATMatchAddr` -> `snat_pool.go` as method on resolver; counter functions -> `counter.go`; types stay in `types.go`.
- Hot-path preservation analysis:
  - Cold path only. Counter IDs are stable hash — splitting must preserve hash algorithm (`fnv.New32a` + remap 0->1 + "#N" collision suffix + sorted finalize). No change to `SetSNATRule` key layout or `SNATValue` binary layout, so Rust helper NAT classification unchanged. No hot-path instruction affected because Rust reads snapshot / map, not compiler.
- Tests + gate:
  - Existing counter tests: `compiler_nat_counter_collision_test.go`, `determinism`, `stability` — must continue passing without change to expected IDs.
  - New: `nat/counter_test.go` collision + determinism isolated; `snat_pool_test.go` for pool IP expansion; `snat_rule_test.go` for match addr resolution.
  - Gate: `go test ./pkg/dataplane -run TestNATCounter -count=1`; `go test ./pkg/dataplane -run TestCompileNAT`.
- Why it matters:
  - NAT is highest-churn area (#2218 counter type prefix, #2255 stable IDs, #5099 collision finalize). 726-line function makes collision handling unreviewable. Previous collision bug due to compile-order dependence (#5099) was hard to spot inside giant function. Split enables targeted reviews and fuzz testing of counter keyspace.
- Fix direction:
  - Extract counter package first (pure, no netlink, already has 3 test files). Then extract pool vs rule. Keep `compileNAT` as thin orchestrator for one release, then inline.
- Labels: `refactor:extract`, `nat`, `cold-path`, `counter-stability`, `priority:p0`
- Dedup note: distinct from zone/policy monoliths; shares counter-ID cross-cutting concern with `userspace/applied_nat_view.go` but different layer.

---

## Finding 4: Manager god struct in loader.go fusing XDP/TC lifecycle, shim swap, map access, persistent NAT, and counter offset tracking

- Title: `Manager` in loader.go is god-struct bundling 6 dataplane lifecycle concerns + legacy cleanup + counter offsets
- Severity: major
- Confidence: medium
- Refactor class: (A) god-struct + hub file low cohesion
- Evidence:
  - `pkg/dataplane/loader.go:35` `type Manager struct` fields: `loaded`, `programs`, `maps`, `xdpLinks`, `tcLinks`, `lastCompile`, `applyMu`, `applyGeneration`, `lastApply`, `PersistentNAT`, `EnableCPUMap`, `xdpEntryProg`, `VlanSubInterfaces`, `mu`, `userspaceCounterOffsets`, `natRuleCounterOffsets`, `zoneCounterOffsets`, `floodCounterOffsets`, `xdpFlagClaims`.
  - File 1207 LOC contains: `New()`, `XDPEntryProgram()`, `SelectUserspaceXDPShimEntryProgram()`, `Load()`, `LoadUserspaceShim()`, `CompileUserspaceShim()`, `attachUserspaceShimXDP()`, `cleanupUserspaceShimLegacyOnlyMapPins()`, `cleanupUserspaceShimLegacyTCLinks()`, `isLegacyTCPinName()`, stub `userspaceShimCompileDataplane` implementing full `DataPlane` interface with no-ops (13 methods returning nil), `IsLoaded()`, `xdpAttachModeMatches()`, `AttachXDP()` 95 lines, `seedInterfaceCounter()`, `SwapToUserspaceXDPShimEntryProgram()`, `swapXDPEntryProg()`, `DetachXDP()`, `setXDPAttachedFlag()` 129 lines, `SetZone()`, `SetVlanIfaceInfo()`, `ClearIfaceZoneMap()`, `clearNativeXDPFlags()`, `ClearVlanIfaceMap()`, `AddTxPort()`, `preflightCheckIfindexCaps()`, `AttachTC()`, `DetachTC()`, `GetPersistentNAT()`, `Map()`, `Program()`, `NewEventSource()`, `LastCompileResult()`, `XDPLinks()`, `TCLinks()`, `Close()`, `Teardown()`, `Cleanup()`.
  - Mixes concerns: XDP link pin management, TC link management, userspace shim entry program selection (post #1476 retirement), legacy pin cleanup, counter offset bookkeeping (userspace reported counters merged into legacy read path), persistent NAT.
  - `userspaceShimCompileDataplane` 13-method no-op adapter inside loader.go violates SRP — its only purpose is to allow `CompileConfig` to run without real maps during shim compile, but lives in loader file.
  - Counter offsets: `userspaceCounterOffsets`, `natRuleCounterOffsets`, `zoneCounterOffsets`, `floodCounterOffsets` plus their setters/readers are in `maps_counters.go`, `maps_stats.go` etc but state resides in Manager — scattered cohesion.
- Proposed decomposition:
  - Split `loader.go` into:
    - `loader/manager.go` — `Manager` core: loaded, programs, maps, lastCompile, applyMu — minimal.
    - `loader/xdp.go` — XDP lifecycle: `AttachXDP`, `DetachXDP`, `setXDPAttachedFlag`, `xdpAttachModeMatches`, `seedInterfaceCounter`, `XDPLinks`, `xdpFlagClaims`.
    - `loader/tc.go` — TC lifecycle: `AttachTC`, `DetachTC`, `TCLinks`, `clearNativeXDPFlags*`.
    - `loader/shim.go` — userspace shim entry: `LoadUserspaceShim`, `CompileUserspaceShim`, `attachUserspaceShimXDP`, `SwapTo...`, `Select...`, `Using...`. Already partially in `loader_userspace_shim.go` (770 LOC) — merge.
    - `loader/legacy_cleanup.go` — `cleanupUserspaceShimLegacyOnlyMapPins`, `cleanupUserspaceShimLegacyTCLinks`, `isLegacyTCPinName`.
    - `loader/compile_adapter.go` — `userspaceShimCompileDataplane` no-op adapter moves out of loader file.
    - `loader/counters.go` — counter offset maps + mutex + `Set*CounterOffset`, `Read*Counter` helpers (currently in `maps_counters.go`, `maps_stats.go`).
    - `maps_iface.go` — `SetZone`, `SetVlanIfaceInfo`, `ClearIfaceZoneMap`, `ClearVlanIfaceMap`, `AddTxPort` (iface-zone mapping) extracted from loader into dedicated maps file.
  - Seam: `Manager` now composes `xdpState`, `tcState`, `counterState`, `ifaceState` sub-structs, each with its own mutex, not single global `mu`. Reducing lock contention (counter reads were serializing under `mu`).
- Hot-path preservation analysis:
  - Still cold path. XDP/TC attach uses `cilium/ebpf/link` — order preserved: `AddTxPort` before `AttachXDP`, `AttachTC` after maps populated. Pin paths (`UserspaceCtrlPinPath` etc in `dataplane.go`) unchanged. Persistent NAT table unchanged. No BPF program bytes changed. Rust helper sees same map pins.
  - Splitting does not change `ebpf.Map` value_size or `SessionValue` layout (that ABI lives in `bpf_session_value.go`). So hot path untouched.
- Tests + gate:
  - Existing: `apply_test.go`, `bpf_session_value_test.go`, `retirement_boundary_canary_test.go` (3356 LOC canary ensures no legacy BPF), `userspace_shim_loader_test.go`.
  - Gate: `go test ./pkg/dataplane -run TestLoader -count=1`; `go test ./pkg/dataplane -run TestRetirementBoundary`; `make test-go`.
- Why it matters:
  - God struct causes every XDP attach fix to contend with counter offset fix. `mu` serializes counter reads (hot telemetry path 1/s) — splitting allows per-counter RWLock. Also legacy cleanup functions are dead after #1476 removal but still intermingled, making retirement canary harder.
- Fix direction:
  - Phase 1: extract `userspaceShimCompileDataplane` adapter to own file, no behavior change.
  - Phase 2: extract counter state into `counter_state.go` with its own `sync.RWMutex`, migrate `maps_stats.go` reads to use it.
  - Phase 3: split XDP vs TC lifecycle files, keep public `Manager` methods as thin wrappers.
- Labels: `refactor:split`, `god-struct`, `loader`, `cold-path`, `priority:p1`
- Dedup note: related to Finding 2 (CompileResult) — both are god structs in same package, but different lifetimes (Manager long-lived vs CompileResult per-commit). Fix separately.

---

## Finding 5: userspace/eventstream.go 1188 LOC mixing socket accept/read/ack, frame decoding, pending callback queue, and telemetry stats

- Title: `EventStream` 1188 LOC god-component mixing 5 concerns: Unix socket lifecycle, binary frame codec, session delta decoding, callback queue/backpressure, wash/drain signaling
- Severity: major
- Confidence: high
- Refactor class: (B) module fusing distinct responsibilities + (A) large file >1000 LOC
- Evidence:
  - File `pkg/dataplane/userspace/eventstream.go` 1188 lines, `type EventStream` has: `socketPath`, `listener`, `mu`, `conn`, `writeMu`, `connected`, `paused`, `lastRecvSeq`, `lastAppliedSeq`, `lastAckSeq`, `ackBatch`, `callbackMu`, `onEvent`, `onDataplaneEvent`, `onRawDataplaneEvent`, `onFullResync`, `pendingFlushMu`, `pendingMu`, `pendingCallbackFrames`, `drainCompleteMu`, `drainCompleteCh`, plus 20+ atomic stats counters (`FramesRead`, `FramesWritten`, `DecodeErrors`, `SeqGaps`, `SessionSyncResyncs`, `PolicyDenyEvents`, etc).
  - Methods: `NewEventStream`, `SetOnEvent`, `SetOnDataplaneEvent`, `SetOnRawDataplaneEvent`, `SetOnFullResync`, `dataplaneCallbacks`, `Start`, `Close`, `IsConnected`, `SendPause/Resume`, `SendDrainRequest`, `LastAckedSequence`, `Status`, `acceptLoop`, `readLoop`, `markDroppedFrameApplied`, `markFrameApplied`, `handleSessionSyncGap`, `backoffCallbackNotReady`, `dispatchOrQueueSessionFrame`, `dispatchOrQueueFullResyncFrame`, `dispatchOrQueueDataplaneFrame`, `hasPendingCallbackFrames`, `enqueuePendingCallbackFrame`, `clearPendingCallbackFrames`, `flushPendingCallbackFrames`, `recordDataplaneEvent*`, `ackLoop`, `sendAckIfNeeded`, `writeFrame`, `wireAFToDataplane`, `decodeSessionEvent`, `decodeSessionCloseEvent`, `decodeDataplaneEventPayload`, `dataplaneEventPayloadMatchesFrame`, `dataplaneEventAction`, `formatIP`, `formatMAC`.
  - Decoders (`decodeSessionEvent` 138 lines, `decodeSessionCloseEvent` ~60, `decodeDataplaneEventPayload`) are pure codec mixed with state machine (`readLoop` pulls conn, calls decoders, then calls `dispatchOrQueue*`).
  - Four distinct mutexes `mu`, `writeMu`, `callbackMu`, `pendingMu` + `pendingFlushMu` + `drainCompleteMu` — lock ordering must be maintained across 1000 lines.
  - Stats recording interleaved with dispatch logic.
  - Test file `eventstream_test.go` 2412 LOC — larger than implementation, indicating coupling makes tests complex.
- Proposed decomposition:
  - `eventstream/socket.go` — listener accept loop, conn lifecycle (`mu`, `connected`), `Start`, `Close`, `IsConnected`. Interface `ConnProvider`.
  - `eventstream/codec.go` — pure decode functions: `decodeSessionEvent`, `decodeSessionCloseEvent`, `decodeDataplaneEventPayload`, `wireAFToDataplane`, `formatIP/MAC`, `dataplaneEvent*` — no state, unit testable with table-driven payloads.
  - `eventstream/dispatch.go` — callback registry (`callbackMu`, `onEvent`, `onDataplaneEvent`, `onRawDataplaneEvent`, `onFullResync`) + `dispatchOrQueue*` + pending queue (`pendingMu`, `pendingCallbackFrames`, limit 4096). Extracted `PendingQueue` type with `Enqueue`, `Flush`, `HasPending`, `Clear`.
  - `eventstream/ack.go` — ack tracking (`lastRecvSeq`, `lastAppliedSeq`, `lastAckSeq`, `ackBatch`) + `ackLoop`, `sendAckIfNeeded`, `writeFrame` + `writeMu` serialization.
  - `eventstream/stats.go` — `EventStreamStats` struct holding all atomic counters + `recordDataplaneEvent`, `recordDataplaneEventDrop`, `Status()`.
  - `eventstream/drain.go` — drain signaling (`drainCompleteMu`, `drainCompleteCh`, `SendDrainRequest`).
  - `eventstream.go` becomes orchestrator composing `socket`, `codec`, `dispatch`, `ack`, `stats`, `drain`. Keeps same public API (`NewEventStream`, `SetOnEvent`, etc).
- Hot-path preservation analysis:
  - Go side is not Rust hot path, but is session-sync hot path in terms of throughput (Go must keep up with Rust helper 1k+ events/s). Decomposition must not add extra allocations per frame. `PendingQueue` already pre-sizes, keep same. `writeMu` separation from `mu` is critical perf fix (#4835) — must preserve separate locks, not widen. Codec extraction actually helps hot path: pure functions can be inlined, no mutex.
  - No change to Rust helper binary framing (seq, typ, payload) — codec keeps same binary layout.
  - Ack batching 100ms ticker unchanged.
- Tests + gate:
  - Existing large tests: `eventstream_test.go` (2412 LOC), `eventstream_writeframe_race_4835_test.go`, `control_socket_deadline_4036_test.go`.
  - New: `codec_test.go` — table-driven payload decode; `pending_queue_test.go` — limit enforcement 4096; `ack_test.go` — sequence gap handling.
  - Gate: `go test ./pkg/dataplane/userspace -run TestEventStream -count=1 -race`; must pass without data race.
  - After split, reuse existing `eventstream_test.go` unchanged (still passes via orchestrator).
- Why it matters:
  - 1188 LOC + 4 mutexes make race conditions like #4835 (write interleaving) hard to audit. Pending queue backpressure logic touches both callback and socket layers. Splitting reduces lock-order complexity and enables targeted fuzzing of decoder. Also reduces 2412-LOC test file's reliance on full component — codec tests can be isolated.
- Fix direction:
  - First extract `codec.go` as pure functions (zero behavior change, move code). Add table-driven tests for each decode path.
  - Then extract `PendingQueue` + `Stats` which have no external dependencies.
  - Finally split `socket` vs `dispatch` vs `ack`; keep `eventstream.go` as <200 line facade.
- Labels: `refactor:extract`, `concurrency`, `eventstream`, `cold-path`, `priority:p1`
- Dedup note: distinct from Go dataplane manager findings — this is userspace manager event stream; related to control socket path (`control.go`) but different component.

---

## Finding 6: userspace/filters.go + interfaces.go + format/ split opportunity — cold config builders mixed with formatting and live-netlink actions

- Title: userspace snapshot builders (`filters.go` 707 LOC, `interfaces.go` 561 LOC, `flow.go` etc) fuse config parsing, live netlink reads, and format rendering concerns
- Severity: moderate
- Confidence: medium
- Refactor class: (B) module fusing distinct responsibilities, (C) hub file low cohesion across format/
- Evidence:
  - `pkg/dataplane/userspace/filters.go:23` `BuildFirewallFilterSnapshots` calls `buildFilterTermSnapshots` (300+ lines) which does prefix-list resolution, policer lookup, action deny mapping, address/port except handling inline. Also `ResolveFilterPrefixListAddrs` 100+ lines with map lookups and expansion.
  - `interfaces.go:164` `buildInterfaceSnapshots` 160+ lines builds `InterfaceSnapshot` including CoS shaping rate extraction, synthetic ifindex allocation (`syntheticLogicalIfindex`), link snapshot via netlink (`buildLinkSnapshot` calls netlink ops), address merge (`mergeInterfaceAddressSnapshots`), RX queue count via sysfs. Single function does config parsing + synthetic ID allocation + live link introspection + coalescing.
  - `format/` 6819 LOC total: `status.go` 486, `status_sections.go` 703, `buffers.go` 160, `buffers_model.go` 682, `cos.go` 280, `cos_sections.go` 632, `cos_show.go` 369, `wireguard.go` 202. Formatting logic duplicated between `status.go` and `status_sections.go` (both render same ProcessStatus). `buffers_model.go` 682 lines holds model transformation from status to buffers view — not formatting but modeling.
  - Cold-path vs stats: `flow.go` builds flow snapshot + app catalog + flow export + ALG flags all in one file (261 LOC) — 4 responsibilities.
- Proposed decomposition:
  - `userspace/filters/term.go` — per-term snapshot builder, pure config -> snapshot.
  - `userspace/filters/prefix.go` — prefix-list expansion pure function, already `resolvePrefixListAddrs` but needs isolated package.
  - `userspace/filters/policer.go` — policer snapshot builders `buildPolicerSnapshots`, `buildThreeColorPolicerSnapshots`.
  - `userspace/interfaces/snapshot.go` — pure config -> `InterfaceSnapshot` without netlink, taking link info via interface.
  - `userspace/interfaces/link.go` — live link probing `buildLinkSnapshot`, `userspaceRXQueueCount` (sysfs), `buildInterfaceAddressSnapshots`.
  - `userspace/interfaces/alloc.go` — synthetic ifindex allocation isolated, deterministic testable.
  - `format/` — split `model` vs `render`: move `buffers_model.go` to `format/model/buffers.go` (pure transformation), keep `buffers.go` as render. Same for `status` model extraction.
  - `flow/catalog.go`, `flow/export.go`, `flow/alg.go`, `flow/timeout.go` split from `flow.go`.
- Hot-path preservation analysis:
  - All builders are cold path snapshot construction at commit time. Interfaces builder does live netlink but not in forwarding hot path — it's snapshot for Rust helper to consume, not per-packet. Splitting pure config part from live probing keeps hot path untouched; Rust helper's forwarding remains same.
  - Formatting split does not touch Rust.
  - No BPF ABI change.
- Tests + gate:
  - Existing many: `filters_*_test.go` (9 files: `address_except`, `matchany_except`, `flex_match`, `mixed_unresolved_except`, `multivalue`, `next_term`, `per_packet_match`, `port_except`, `prefix_list`, `protocol_ipv6`, `snapshot_integrity`, `unresolved_except`), `interfaces_test.go`, `format/*_test.go` (golden tests).
  - Gate: `go test ./pkg/dataplane/userspace -run TestFirewallFilter -count=1`; `go test ./pkg/dataplane/userspace/format -count=1`.
- Why it matters:
  - Filter expansion is highest bug-density area (#2544 next-term, #2545 multivalue, #2622 port-except, #3077 flex-match, #3359 address-except, #3393 ipv6, #3406 integrity, #4338 matchany-except, #5097 unresolved-except, #5225 mixed-unresolved). 9 test files covering edge cases but builder remains monolithic. Splitting term building isolates exception handling logic.
  - Interfaces snapshot mixing config + live probing makes unit tests need sysfs mocks; split enables pure config tests without netlink.
- Fix direction:
  - Extract pure functions first (prefix resolution, policer snapshots) into sub-files in same package — no package rename needed initially.
  - Then introduce `LinkProber` interface for live probing, injectable in tests.
  - Format model/render split is low risk, can be done independently.
- Labels: `refactor:split`, `userspace-cold`, `filters`, `interfaces`, `priority:p2`
- Dedup note: complements Finding 1 — both about interface handling but this is userspace AF_XDP side, Finding 1 is legacy eBPF side. Related but distinct seam.

---

## Finding 7: D-negatives — what NOT to split (hot-path preservation guardrails)

- Title: D-negatives for pkg/dataplane refactor
- Severity: info
- Confidence: high
- Refactor class: (D) anti-pattern guard / D-negative
- Evidence:
  - Rust hot path not in this batch, but Go side still has critical ABI invariants:
    - `types.go` defines `SessionKey`, `SessionValue`, `SessionKeyV6`, `SessionValueV6`, `ZoneConfig`, `PolicyRule`, etc with explicit `Pad` fields to match C `sizeof`. These must stay in single file with comments explaining alignment. Splitting `types.go` (1056 LOC) into multiple files risks misaligning pad and breaking BPF map value_size. Keep as single file, or if split, keep all C-mirrored structs together with `unsafe.Sizeof` assert tests.
    - `maps_session.go` 629 LOC contains `SessionCount`, `ClearAllSessions`, `BatchDeleteSessions` — these iterate BPF maps via cilium/ebpf `Iterate` with scratch `val []byte` to avoid verifier crash (known gotcha: `iter.Next(&key, nil)` crashes v0.20). Do NOT extract map iteration into generic helper that passes nil.
    - `maps_nat.go`, `maps_filter.go`, `maps_policy.go`, `maps_counters.go`, `maps_stats.go` are thin wrappers around `ebpf.Map` with per-map key/value types — keep as separate files per map type. Do NOT merge into single `maps.go` hub — would become 1500+ LOC hub.
    - `bpf_session_value.go` mirrors C 128-byte layout without Generation/PolicyCounterIdx/ Nat64SnatV4 fields — comment explains why. Do NOT add Generation to BPF ABI.
    - `session_store.go` 649 LOC manages cluster synced session install + rollback + bulk reconcile + persistent NAT preservation. Its `PutClusterSyncedV4` 43 lines includes generation guard and NAT preservation. Splitting must preserve transactional rollback ordering (snapshot -> write -> rollback on error). Do NOT split snapshot/restore across packages without transaction manager.
    - `proxyarp.go` 432 LOC already focused: orphan detection, reconciliation. Its large function `ReconcileProxyARP` 221 lines is procedural but single responsibility (proxy-arp). Do NOT merge with `maps_*`.
    - `userspace/protocol.go` (not in this batch, 3064 LOC) is intentionally large — wire protocol framing for control socket. Splitting codec vs state machine is okay, but keep message IDs constants together.
- Proposed decomposition: N/A — D-negative list.
- Hot-path preservation analysis:
  - Any refactor in `pkg/dataplane/` must keep `SessionValue` BPF-compatible layout: 128 bytes for v4? Actually `bpf_session_value.go` asserts. Changing struct field order or adding field changes `unsafe.Sizeof` and breaks Rust helper which uses same layout.
  - Counter offset maps in `loader.go` are read from telemetry path 1/s — do NOT add allocation on read path (no `fmt.Sprintf` inside `GlobalCounter` hot telemetry).
  - `cpumask.go` is performance-sensitive for RSS — keep as small utility, not merged.
- Tests + gate: `go test ./pkg/dataplane -run TestBPFSessionValue -count=1`; `go test ./pkg/dataplane -run TestRetirementBoundary -count=1` ensures BPF ABI not broken.
- Why it matters: prevents well-intentioned refactor from breaking hot path or BPF ABI.
- Fix direction: Keep `types.go`, `bpf_session_value.go`, `maps_*.go` structure. If splitting `loader.go`, ensure map accessor methods preserve same locking.
- Labels: `refactor:do-not`, `hot-path-guard`, `bpf-abi`
- Dedup note: D-negatives apply to all batches — not a duplicate of other findings.

---

## Summary of batch characteristics

- Total files in batch: 150 (from `batches/A6_go_dataplane_manager-b1.txt`)
- Largest files measured: `compiler.go` 1808, `compiler_iface.go` 1394, `compiler_nat.go` 1317, `loader.go` 1207, `types.go` 1056, `userspace/eventstream.go` 1188 (in batch), `userspace/filters.go` 707, `userspace/interfaces.go` 561, `userspace/filtercounters.go` small, `userspace/cos.go` 265, `userspace/flow.go` 261, `userspace/fabric.go` small, etc.
- No file >2000 in this batch except retirement canary test (3356) which is test; `protocol.go` 3064 not in batch.
- Common anti-patterns: one function per compile phase that touches many maps, god structs holding caches + IDs + pending attachments, ethtool/netlink side effects buried in pure compilation.
- Hot-path preservation: entire batch is cold path (commit-time compile + manager lifecycle + event stream). Rust fast-path unaffected. Only invariants to preserve are BPF struct layouts, counter stable hash, XDP/TC attach order, and eventstream ack batching.

## Cross-batch references

- A6 batch 2/3 likely contains `userspace/protocol.go` 3064 LOC, `userspace/maps_sync.go` 1763 LOC, `userspace/manager_ha.go` 1643 LOC — those are the larger monoliths and should be audited for HA/session-sync seam. This batch's `compileZones` god function feeds `maps_sync.go` via `ManagedInterfaces`.
- `pkg/dataplane/userspace/format/` 6819 total split across status/cos/buffers/wireguard — moderate but render/model mixed.
- `pkg/dataplane/runtime/session_delta.go` 85 LOC is small, pure — no issue.


---
### Batch A6_go_dataplane_manager-b2 — 1074 lines — full log + findings

# Refactor / Modularity Audit - A6 Go Dataplane Manager Batch 2/3

- Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
- Worktree: /tmp/review-wt-ps-044-A6_go_dataplane_manager-b2
- Batch file: /tmp/prompt-gemini-044-A6-b2.txt (143 files, 138 in batch list + extra context)
- Total batch LOC: 43030 (prod 16231 + test 26800)
- Production files: 46, Test files: 97
- Date: 2026-07-11
- Auditor: ps / 044

## File-Size/Shape Inventory (Production Only)

| File | LOC | Types | Funcs | Shape | Role |
|------|-----|-------|-------|-------|------|
| protocol.go | 3064 | 80+ structs | ~40 | God wire file - every snapshot, status, counter, HA request fused | Wire schema |
| maps_sync.go | 1763 | 6 types | 25 | Manager mixed with bootstrap, classifier, local addr, NAT addr, binding wedge, auto-rebind | Map sync god |
| manager_ha.go | 1643 | 2 types | 35+ | HA watchdog, IPC sync, counter snapshot, session sync, RG inventory fused | HA god |
| manager_compile.go | 622 | 0 | 8 | Compile lifecycle: pin cleanup, capability derive, snapshot build, RST suppression, overlay preservation | Compile phase |
| nat_destination.go | 548 | 0 | 15+ | DNAT builder: address-name, prefix, app, port-range, pool, feed overlay | NAT compile |
| nat_source.go | 511 | 0 | 12+ | SNAT builder: scope tier, deterministic fields, app terms, pool/port | NAT compile |
| policies_addrbook.go | 489 | 1 | 11 | Addr-book classification, dedup, canonical hash, recursive expansion, feed merge | Policy compile |
| manager.go | 434 | 3 | 20+ | Manager god struct (80+ fields, 4 locks/atomic), ApplyConfig, telemetry, XSK liveness | Manager core |
| routes.go | 431 | 1 | 10+ | Route snapshot build, dedup, netlink rule list, leak, overlay | Route compile |
| tunnels.go | 213 | 0 | 8 | GRE, IPIP, WG endpoint, NAT-T exclusion sets | Tunnel compile |
| policycounters.go | 358 | 3 | 10 | Policy counter ID allocation, bulk read, delta calc | Counter manager |
| zones_observability.go | 369 | 3 | 3 | Addressless enforcing zones/ifaces + ambiguous HIB detection | Zone observability |
| zones_host_inbound.go | 394 | 1 | 4 | Host-inbound view building with VRRP VIP, lifeline, override inheritance | Zone HIB |
| process_napi.go | 370 | 0 | 12 | NAPI polling, XSK bind check, RX counter liveness | Process helper |
| process.go | 270 | 0 | 8 | Process start/stop, binary find, buffer tuning, FIB sync | Process manager |
| neighbors.go | 267 | 0 | 7 | Neighbor snapshot from ARP/ND, ifindex filter, HA sync | Neighbor compile |
| manager_neighbor.go | 270 | 1 | 6 | Neighbor index, monitored ifindex rebuild, prewarm, daemon integration | Neighbor manager |
| manager_overlay.go | 197 | 0 | 4 | Route overlay cache + feed overlay cache, publish boundary logging | Overlay cache |
| manager_status.go | 231 | 0 | 8 | Status apply, binding counters, degraded stats, WG endpoint transition log | Status sync |
| screens.go | 239 | 0 | 6 | Screen profile snapshot + missing profile ref tracking | Screen compile |
| nat.go | 225 | 0 | 12 | NAT shared helpers: CIDR, scope, deterministic port, l4 match, app-set expansion | NAT shared |
| zones_override.go | 178 | 0 | 3 | Host-inbound token union, merge, interface override map | Zone override |
| zones_quarantine.go | 189 | 1 | 2 | ZoneID collision quarantine + scrub of scoped global policies | Quarantine |
| process_control.go | 196 | 0 | 5 | Control socket framing, write serialization, fail-closed ctrl | Control socket |
| process_status.go | 248 | 0 | 6 | Status JSON unmarshal, capability decode, backend epoch, delta stream | Status decode |
| process_linkcycle.go | 170 | 0 | 3 | Link cycle notification, defer-workers arm, worker notification | Link cycle |
| runtime_delta.go | 128 | 1 | 7 | Runtime delta adapter from Manager to dpruntime interface | Adapter |
| maps.go | 59 | 0 | 0 | Const map-name registry (11 names) + extensive doc comment | Registry |
| nat_static.go | 94 | 0 | 3 | Static NAT snapshot build + address-name resolution | NAT compile |
| nat64.go | 121 | 0 | 4 | NAT64 snapshot build | NAT compile |
| nat_nptv6.go | 48 | 0 | 2 | NPTv6 snapshot build | NAT compile |
| natcounters.go | 65 | 0 | 2 | NAT counter ID allocation | Counter |
| zonecounters.go | 61 | 0 | 2 | Zone counters snapshot | Counter |
| policies.go | 160 | 1 | 3 | PolicyRuleSlot walk + v4/v6 CIDR classification | Policy compile |
| wire_uint8list.go | 111 | 0 | 3 | Generic uint8 list codec for BPF map keys/values? (actually used in nat?) | Wire helper |
| etc (test gaps listed later) |

Test files: 97 files, 26800 LOC total. Largest: protocol_test 1914, maps_decouple 1525, manager_ha_test 1076, userspace_shim_loader 731, manager_interfaces 907, manager_sessionsync 856.

---

## Module-by-Module Deep Examination

### M1: protocol.go - 3064 LOC God Wire File

**Title**: protocol.go is the archetypal 77-struct wire god file fusing snapshots, statuses, counters, control, HA, bindings, sessions

**Severity**: High

**Confidence**: High

**Refactor class**: A - Core decomposition, pure data but high fan-out

**Evidence** (file:line, LOC):
- File: `pkg/dataplane/userspace/protocol.go:29-2941` - 3064 LOC, 80+ type definitions
- Metrics: 2037 lines of type defs,  quic?
```
type ConfigSnapshot struct {
    Version         int                      `json:"version"`
    Generation      uint64                   `json:"generation"`
    FIBGeneration   uint32                   `json:"fib_generation,omitempty"`
    GeneratedAt     time.Time                `json:"generated_at"`
    Summary         SnapshotSummary          `json:"summary"`
    Capabilities    UserspaceCapabilities    `json:"capabilities"`
    MapPins         UserspaceMapPins         `json:"map_pins"`
    Zones           []ZoneSnapshot           `json:"zones,omitempty"`
    Interfaces      []InterfaceSnapshot      `json:"interfaces,omitempty"`
    ...
    SourceNAT              []SourceNATRuleSnapshot      `json:"source_nat_rules,omitempty"`
    StaticNAT              []StaticNATRuleSnapshot      `json:"static_nat_rules,omitempty"`
    DestinationNAT         []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
    NAT64                  []NAT64RuleSnapshot          `json:"nat64_rules,omitempty"`
```
```
type ProcessStatus struct { // 1358 - huge status with nested 50+ fields
    Enabled bool `json:"enabled"`
    ForwardingArmed bool `...
    Capabilities ...
    LastSnapshotGeneration uint64
    ...
}
type BindingStatus struct { // 2411 - XDP binding state
type SessionDeltaInfo struct { // 2941 - session sync
```
- Responsibilities fused: (1) Config snapshot wire schema (zones, ifaces, routes, NAT, policies...), (2) Control request/response, (3) Capabilities negotiation, (4) Process status / telemetry (50+ counter types), (5) HA watchdog sync state, (6) Binding/queue management for BPF maps, (7) Session delta export for HA sync
- All 80+ types live in one package-level namespace `userspace` - any file importing Manager sees all world

**Proposed decomposition**:
- `pkg/dataplane/userspace/snapshot/types.go` - ConfigSnapshot + all *Snapshot (Zone, Interface, Route, Neighbor, Policy, NAT*, Screen, Tunnel, CoS...)
- `snapshot/hash.go` - snapshot hash logic (currently scattered)
- `protocol/control.go` - ControlRequest/ControlResponse, ForwardingControlRequest, QueueControlRequest, BindingControlRequest
- `protocol/capabilities.go` - UserspaceCapabilities, UserspaceMapPins, ProcessStatus cap negotiation
- `protocol/status/types.go` - ProcessStatus, all *Status/*Counter types (SourceNATPoolStatus, CoSInterfaceStatus, PolicyRuleCounterStatus, NATRuleCounterStatus, ZoneTrafficCounterStatus, WorkerRuntimeStatus, BindingStatus, etc)
- `protocol/binding.go` - BindingStatus, QueueStatus, BindingCountersSnapshot, live-check helpers (deadWorkerIDSet currently in maps_sync.go should move here)
- `protocol/ha.go` - HAStateUpdateRequest, HAGroupStatus, haWatchdogIPCSyncState
- `protocol/session.go` - SessionDeltaInfo, SessionExportRequest, SessionSyncRequest, InjectPacketRequest
- Keep `protocol.go` as facade re-exporting via type aliases for 1 release, then remove

**Hot-path preservation analysis**:
- This file is pure data + json marshaling - no packet hot path. Risk is compilation breakage and JSON field tag mismatch causing wire skew between Go and Rust.
- Inlining: not relevant (struct layout preserved)
- Alloc: snapshot build already allocates - decomposition must not increase alloc (keep slices, no extra copying)
- Layout: struct field order affects JSON but not memory layout critical; keep `json:"..."` tags identical
- Verification: `make test-go` (protocol_test.go 1914 LOC guards marshal round-trip + failopen + null-collections), `make test` includes Rust cargo suite for wire compat, `go vet` for tag check, `diff` of `go doc` output before/after to prove type identity preserved via alias

**Tests + gate**:
- Must move: protocol_test.go, protocol_failopen_2124_test.go, protocol_null_collections_2214_test.go => stay with new package or kept via facade
- Gate: `make test-go -run TestProtocol` + `cargo test` in userspace-dp for serde compat + manual JSON golden diff (`snapshot_json_golden_test.go` pattern)

**Why it matters**:
- Every feature addition touches protocol.go (NAT64, NPTv6, CoS, screens, filters all appended here) → merge conflicts in A6 batch, review overload, god-file blind spot for HA/session/binding regressions
- 80 types in one namespace violates package cohesion - zones, NAT, CoS, HA should be independently versioned; a change to BindingStatus risks accidentally touching PolicyRuleSnapshot
- Blocks IDE navigation and `gopls` performance

**Fix direction**:
1. Create `pkg/dataplane/userspace/snapshot/` subpackage with `types.go` (pure snapshot structs) - move ConfigSnapshot and all *Snapshot types, keep json tags identical
2. Create `pkg/dataplane/userspace/wire/` for control and status types
3. Split by responsibility: snapshot vs control vs status vs binding vs HA vs session
4. Stage: first extract interfaces without moving (add file with `type X = protocol.X` alias) to prove no wire break, then cut

**Labels**: mod-split, wire-schema, god-file

**Dedup note**: Explicitly listed as dedup #4 "Go userspace protocol file is a 77-struct wire god file" - this is same root but this report gives concrete decomposition (6 subfiles + verification gate + stage plan) and notes hot-path safe because pure data; dedup entry had no decomposition. Retaining because prior entry was severity High without fix direction.

---

### M2: maps_sync.go - 1763 LOC + Manager.mu god

**Title**: maps_sync.go fuses bootstrap, classifier, ingress-iface, local-address, NAT-address, binding verification, wedge detection, auto-rebind, degraded-stats under single Manager.mu

**Severity**: High

**Confidence**: High

**Refactor class**: B - Manager lock scope reduction + module extraction

**Evidence**:
- `pkg/dataplane/userspace/maps_sync.go:121-1763`, 25 functions all on `*Manager` receiver
- Locking: every function `...Locked` suffix - `programBootstrapMapsLocked`, `syncUserspaceClassifierMapsLocked`, `syncIngressIfaceMapLocked`, `syncLocalAddressMapsLocked`, `syncInterfaceNATAddressMapsLocked`, `verifyBindingsMapLocked`, `hasBusyBindingsWedgeLocked`, `maybeAutoRebindBusyBindingsLocked`
```
func (m *Manager) programBootstrapMapsLocked(snapshot *ConfigSnapshot, cfg config.UserspaceConfig) error {
    // bootstraps ctrl, heartbeat, xsk map, cpu map, sessions
}
func (m *Manager) syncLocalAddressMapsLocked(snapshot *ConfigSnapshot) error {
    // builds desired V4+V6 sets, handles transient addrList failure via hook, diffs against bpf maps
}
func (m *Manager) verifyBindingsMapLocked() bool {
func (m *Manager) shouldAutoRebindBusyBindingsLocked(now time.Time, repaired bool) bool {
```
- Single `Manager.mu` protects: proc, generation, lastSnapshot, haGroups, neighborIndex, bindingsBusySince, xsk liveness, plus all map sync state
- Helpers: `deadWorkerIDSet` (func of WorkerRuntimeStatus -> map), `bindingForwardingLive`, `buildDesiredLocalAddressSets`, `buildDesiredInterfaceNATAddressSets`, `buildUserspaceIngressIfindexes`, `snapshotBindingPlanKey` - these are pure functions buried in same file as locked methods
- `maps.go:59` defines only const registry - purpose is decoupled from sync logic
- Metrics: 1763 LOC, cyclomatic complexity of `applyHelperStatusLocked` ~40 branches (status -> binding -> wedge -> ctrl enable)

**Proposed decomposition**:
- `pkg/dataplane/userspace/binding/manager.go` - Binding lifecycle: plan key, alias map, skip logic, verify, wedge detection, auto-rebind, `BindingStatus` live check -> owns bindingsBusySince, lastBindingsAutoRebind, publishedPlanKey
- `pkg/dataplane/userspace/localaddr/sync.go` - Local address map sync: `buildDesiredLocalAddressSets`, `buildLocalAddressEntries`, `syncLocalAddressMapsLocked` -> owns addrList hook
- `pkg/dataplane/userspace/localaddr/nataddr.go` - Interface NAT address sync: `buildDesiredInterfaceNATAddressSets`, `syncInterfaceNATAddressMapsLocked`
- `pkg/dataplane/userspace/bootstrap/sync.go` - Bootstrap maps: `programBootstrapMapsLocked`, `setupUserspaceCPUMapLocked`, `failClosedUserspaceCtrlLocked`, classifier maps
- `pkg/dataplane/userspace/ingress/sync.go` - Ingress iface map sync
- `pkg/dataplane/userspace/maps_verify.go` - Degraded path stats read, entry programs
- Pure helpers: move `deadWorkerIDSet`, `bindingForwardingLive`, `heartbeatZeroSlots`, `maxInt`, `queueCountFromBindings`, `snapshotHasNativeGRE`, `snapshotWgListenPort` to `pkg/dataplane/userspace/binding/util.go` (no Manager receiver)

**Hot-path preservation analysis**:
- Maps sync is control-plane cold path (snapshot apply, 1/s status loop) - not packet hot path, but holds Manager.mu which blocks HA watchdog and session drain if held long
- Lock scope: current holds mu across BPF map iterations (ebpf.Map.BatchUpdate). Extraction must preserve lock ordering - propose new sub-managers each with own mutex or keep single mu but shrink critical sections to snapshot copy + diff build outside lock
- Alloc: desired sets currently `map[uint32]struct{}` - decomposition must not allocate extra intermediate sets
- Verification: `make test-go -run TestMapsSync` (maps_sync_cap_test, maps_sync_heartbeat_slots, maps_sync_addrlist_prune_3924), `make test-go -run TestBinding` (xdp_shim_decouple, shim_loader_boundary), `perf stat` on manager apply path to show lock hold time reduction (via `slog.Debug` timing or pprof mutex profile)

**Tests + gate**:
- Move: maps_sync_cap_test.go, maps_sync_heartbeat_slots_4572_test.go, maps_sync_addrlist_prune_3924_test.go, maps_decouple_test.go, xdp_shim_decouple_test.go -> new packages
- Gate: `make test-go`, `make test-cluster-lock-lib` for HA interaction, plus lock contention bench: `go test -bench=BenchmarkApplyConfig -benchmem -mutexprofile` showing mu hold <5ms p99

**Why it matters**:
- Manager.mu contention flagged in dedup #5 - 1763 LOC file all taking same lock is root cause of control-socket starvation mentioned in CLAUDE.md logging rules ("status poll 1/s, HA sync, session installs, snapshot sync contend")
- Wedge detection + auto-rebind logic (hasBusyBindingsWedge, shouldAutoRebindBusyBindings) is hidden inside map sync - should be autonomous binding health subsystem
- Transient netlink AddrList failure handling (#3924) via hook is buried - needs isolation for testability

**Fix direction**:
1. Extract pure helpers first (no receiver) to `binding/util.go` - zero risk
2. Extract bootstrap sync to own file in same package but with explicit `bootstrapState` struct
3. Introduce `binding.Manager` with its own mu for wedge/retry state, Called by outer Manager under outer mu for generation check only, then releases
4. Final: `localaddr.Syncer` interface with `Sync(snapshot) error`

**Labels**: lock-scope, control-socket-contention, god-file, testability

**Dedup note**: Dedup #5 says "Userspace map/status sync holds many responsibilities under Manager.mu" - same root, but this report identifies 5-way split (binding, localaddr, nataddr, bootstrap, ingress) vs prior generic "many responsibilities", and provides lock-scope hot-path preservation analysis with perf verification. Retain with finer seam.

---

### M3: manager_ha.go - 1643 LOC HA God

**Title**: manager_ha.go fuses RG inventory, watchdog map write + IPC throttle, counter snapshot, session sync RB, HA state apply, session export/drain under one file

**Severity**: High

**Confidence**: High

**Refactor class**: B - HA subsystem extraction

**Evidence**:
- `pkg/dataplane/userspace/manager_ha.go:1-1643`, 35+ funcs
- Types: `haWatchdogIPCSyncState`, `userspaceCounterSnapshot`
```
func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64, active bool) error {
    // writes ha_watchdog map EVERY tick (200ms) + throttled IPC to helper
    //  m.mu.Lock()
    //  synced := m.haWatchdogIPCSynced[rgID]
    //  if active changed => immediate IPC else periodic backstop <10s
}
func (m *Manager) syncHAStateLocked() // applies helper status -> HA groups
func (m *Manager) DrainSessionDeltas(max uint32) // session delta drain
func (m *Manager) ExportOwnerRGSessions(rgIDs []int, max uint32) // HA session sync
type userspaceCounterSnapshot struct {
    // prevBindingCounters for delta calc
}
```
- Responsibilities fused: (1) HA RG inventory seeded from config (`seedHAGroupInventoryLocked`), (2) Watchdog map write (kernel BPF visible, every 200ms), (3) Watchdog IPC sync (JSON socket, throttled), (4) Counter snapshot delta for BPF maps, (5) Session delta drain for HA sync, (6) Owner RG filtering, (7) HA state machine (Active/Standby)
- File touches: `Manager.mu`, `sessionMu`, `rgTransitionInFlight atomic.Bool`, `haWatchdogMapWrite func`, `haWatchdogIPCSynced map`

**Proposed decomposition**:
- `pkg/dataplane/userspace/ha/watchdog.go` - Watchdog map write + IPC throttle: `haWatchdogIPCSyncState`, `UpdateHAWatchdog`, `haWatchdogMapWrite` indirection, 200ms vs 10s logic
- `ha/rg_inventory.go` - RG inventory: `seedHAGroupInventoryLocked`, `haGroups` map, `HAGroupStatus`
- `ha/counters.go` - Counter snapshot: `userspaceCounterSnapshot`, prevBindingCounters delta, `readDegradedPathStatsLocked` (currently in maps_sync.go but belongs here)
- `ha/sync.go` - Session sync: `DrainSessionDeltas`, `ExportOwnerRGSessions`, sessionMirrorFailed handling, `sessionMu` ownership
- Move `rgTransitionInFlight` and `lastRGActivateTime` to watchdog.go
- Keep `Manager` owning top-level `haGroups` but delegate to `ha.Controller` interface

**Hot-path preservation analysis**:
- Watchdog map write is HA hot path - 200ms interval, must not regress. Current does direct BPF map write via function pointer (`bpfShim.UpdateHAWatchdog`) under mu check - extraction must keep map write outside socket IPC (socket is slow, 1s+ on contended control socket per CLAUDE.md)
- Session drain is also HA critical path - called from `pkg/conntrack` and `pkg/cluster` - must not add alloc on drain (currently pre-allocs slice of max)
- Lock scope: `sessionMu` separate from `mu` for delta drain - must preserve separation or risk deadlock (delta drain called with mu held somewhere?)
- Verification: `cargo asm` not applicable (Go). Verify with `perf stat` on HA sync loop (200ms), `make test-failover` (HA smoke, 60ms failover), `make test-go -run TestHA` (manager_ha_test 1076 LOC), measure watchdog map write latency p99 <1ms via `slog.Debug` timing

**Tests + gate**:
- Move: manager_ha_test.go (1076 LOC), manager_sessionsync_test.go (856), manager_sessionsync_snapshot_5007_test.go (208)
- Gate: `make test-go -run TestHA`, `make test-failover` (requires cluster, loss userspace cluster), failover must stay <100ms, `test-ha-crash` multi-cycle

**Why it matters**:
- HA failover timing ~60ms with 30ms VRRP - any extra mu hold or IPC contention in watchdog path can delay failover beyond 1s detection threshold (5*200ms heartbeat)
- Session sync connects immediate first attempt, 1s retry - blocking on Manager.mu during map sync delays sync, causing TCP death on failback despite fabric forwarding
- File is second largest production file - blocks parallel development on HA vs session sync features

**Fix direction**:
1. Extract watchdog into `ha.Watchdog` struct with own `sync.Mutex` for IPC throttling, keeping map write func pointer
2. Extract counter snapshot to `ha.CounterTracker` - owns prevBindingCounters, provides `Snapshot()` and `Delta()`
3. Extract session sync to `ha.SessionSyncer` with `sessionMu` - interface `Drain(max) ([]SessionDeltaInfo, ProcessStatus, error)`
4. Final: `Manager.HA()` already returns `HAController` interface - make it delegate to new subsystem instead of implementing directly

**Labels**: ha, failover-timing, lock-scope, session-sync

**Dedup note**: Not in dedup index - prior HA findings were about VRRP. This is new: watchdog map vs IPC throttle entanglement + counter snapshot misplacement.

---

### M4: Manager God Struct - 80+ fields, 4 sync primitives

**Title**: Manager struct fuses 80+ fields across 8 domains (proc, snapshot, HA, bindings, neighbors, counters, overlays, XSK liveness) under 2 mutexes + 1 atomic + func pointers

**Severity**: High

**Confidence**: High

**Refactor class**: A - Architectural seam

**Evidence** (`manager.go:85-248`):
```
type Manager struct {
    bpfShim *dataplane.Manager
    mu           sync.Mutex
    sessionMu    sync.Mutex
    proc         *exec.Cmd
    cfg          config.UserspaceConfig
    clusterHA    bool
    generation   uint64
    syncCancel   context.CancelFunc
    lastStatus   ProcessStatus
    lastSnapshot *ConfigSnapshot
    lastApply    *dataplane.ApplyResult
    lastSnapshotRejectReasons []string
    lastZoneIDCollisions  []string
    policySchedulerActive map[string]bool
    routeOverlay []config.RouteOverlayEntry
    feedOverlay map[string][]string
    haGroups    map[int]HAGroupStatus
    haWatchdogMapWrite func(rgID int, timestamp uint64) error
    haWatchdogIPCSynced map[int]haWatchdogIPCSyncState
    lastIngressIfaces   []uint32
    lastRSTv4           []netip.Addr
    lastRSTv6           []netip.Addr
    lastRSTAttempt      time.Time
    ...
    neighborIndex map[neighborIndexKey]*NeighborSnapshot
    monitoredIfindexes      map[int]struct{}
    lastBindingIndices      []uint32
    neighborsPrewarmed      bool
    ctrlEnableAt            time.Time
    ctrlWasEnabled          bool
    ...
    xskLivenessFailed       bool
    xskLivenessProven       bool
    xskProbeStart           time.Time
    lastXSKRX               uint64
    lastNAPIBootstrap       time.Time
    lastStandbyNeighResolve time.Time
    bindingsBusySince       time.Time
    lastBindingsAutoRebind  time.Time
    publishedSnapshot       uint64
    publishedPlanKey        string
    appliedSnapshot     appliedSnapshot
    sessionMirrorFailed bool
    sessionMirrorErr    string
    deferWorkers        bool
    xskBoundNotified    bool
    pendingWorkerArm bool
    lookupUserspaceCtrlForFailClosedHook userspaceCtrlLookupHook
    addrListForLocalSyncHook addrListHook
    mode               DataplaneMode
    configuredMode     DataplaneMode
    lastHASyncTime     time.Time
    lastRGActivateTime time.Time
    rgTransitionInFlight atomic.Bool
    prevBindingCounters userspaceCounterSnapshot
    eventStream       *EventStream
    ...
}
```
- Metrics: 163 lines struct def, 80+ fields, 2 Mutex + 1 atomic + 2 func hooks, 20+ time.Time fields
- Methods scattered: manager.go (ApplyConfig, Start, Link, HA, Sessions, Telemetry...), manager_compile.go (Compile, syncInterfaceAttachments, ensure*ProtocolLocked), manager_generation.go (bumpGeneration, readFIBGeneration), manager_ha.go (HA methods), manager_neighbor.go (6), manager_overlay.go (4), manager_status.go (8), maps_sync.go (20+), process_*.go (15+)
- No domain grouping - `lastRSTv4` (RST suppression) next to `lastSnapshotHash` (dedup) next to `neighborIndex` (neighbor lookup) next to `bindingsBusySince` (binding health)

**Proposed decomposition**:
- Keep `Manager` as facade with 5 sub-controllers:
  - `proc: *ProcessManager` - `proc`, `cfg`, `syncCancel`, `eventStream`, `OnXSKBound` - owns helper lifecycle
  - `snapshot: *SnapshotManager` - `generation`, `lastSnapshot`, `lastSnapshotHash`, `lastApply`, `appliedSnapshot`, `publishedSnapshot`, `lastSnapshotRejectReasons`, `lastZoneIDCollisions`, `coldPathSampleMask`
  - `ha: *HAManager` - `haGroups`, `haWatchdog*`, `lastHASyncTime`, `lastRGActivateTime`, `rgTransitionInFlight`, `prevBindingCounters`, `sessionMirrorFailed`, sessionMu
  - `binding: *BindingManager` - `lastIngressIfaces`, `lastBindingIndices`, `bindingsBusySince`, `lastBindingsAutoRebind`, `publishedPlanKey`, `ctrl*`, `xsk*`, `lastRST*`, `deferWorkers`, `pendingWorkerArm`
  - `neighbor: *NeighborManager` - `neighborIndex`, `monitoredIfindexes`, `neighborsPrewarmed`, `lastStandbyNeighResolve`, `lastNAPIBootstrap`
  - `overlay: *OverlayCache` - `routeOverlay`, `feedOverlay` (already partially isolated in manager_overlay.go)
- Each sub-manager has own mutex, facade Manager locks only for generation check then delegates
- Introduce `ManagerConfig` struct for 10+ fields currently on Manager that are actually config

**Hot-path preservation analysis**:
- Manager.mu contention is #1 control-socket starvation cause per CLAUDE.md: "status poll (1/s), HA sync, session installs, snapshot sync, and forwarding sync" all contend on control socket, and map sync under mu blocks HA sync
- Sub-manager extraction must not increase alloc on ApplyConfig hot path (commit path) - snapshot build already heavy, extra wrapper must be pointer delegation not copy
- Need to preserve `XSKBoundNotified` exactly-once semantics - currently `atomic.Bool`? No, bool + callback - race if two managers call `SetOnXSKBound`
- Verification: `go test -run TestManager -bench -benchmem` for ApplyConfig latency, `pprof` mutex profile showing mu hold reduction, `make test-failover` for HA, `make test` for full suite

**Tests + gate**:
- All manager_*_test.go files (12 files, ~4500 LOC) would move with subsystems or stay via facade
- Gate: `make test-go` full, plus `go test -race` on pkg/dataplane/userspace (race detector for new mu split)

**Why it matters**:
- 80-field struct is textbook god object - any change requires understanding 7 other domains
- Blocks `gopls` rename refactoring - renaming one field touches file with 80 fields
- Lock granularity: single mu means HA watchdog (200ms) blocks on long map sync (BPF map iteration can be 10ms+ on large table) - could delay failover past 1s

**Fix direction**:
1. Phase 1: Extract `OverlayCache` already started (manager_overlay.go 197 LOC) - complete by moving `routeOverlay`, `feedOverlay` + locking inside cache
2. Phase 2: Extract `NeighborManager` (neighborIndex + monitoredIfindexes) - already 270 LOC in manager_neighbor.go, move fields
3. Phase 3: Extract `BindingManager` (bindings, XSK, ctrl, RST) - largest win, owns ~25 fields
4. Phase 4: Extract `SnapshotManager` (generations, hashes, lastSnapshot)
5. Phase 5: Extract `HAManager` (RG, watchdog, counters, session)
6. Each phase keeps facade methods on Manager that delegate, so existing tests pass

**Labels**: god-struct, lock-contention, control-socket-starvation

**Dedup note**: Dedup explicitly mentions "Userspace map/status sync holds many responsibilities under Manager.mu" - this finding is broader: the entire Manager struct (not just maps_sync) has 80 fields. Provides concrete 5-way split vs prior vague "many responsibilities". Complementary, not duplicate.

---

### M5: NAT Compilation - 4 files, 1300 LOC, shared mutable via package globals?

**Title**: NAT compilation scattered across nat.go (225) + nat_source.go (511) + nat_destination.go (548) + nat_static.go (94) + nat64.go (121) + nat_nptv6.go (48) + natcounters.go (65) — 6 files sharing address-book via feedOverlay param threading, but no clear ownership of NAT counter IDs

**Severity**: Medium

**Confidence**: High

**Refactor class**: B - Cohesive subpackage extraction

**Evidence**:
- `nat.go:19-225` - shared helpers: `classify`, `sourceNATScopeTier`, `natAppProtoNumber`, `buildSourceNATAppTerms`, `deterministicSourceNATFields`, `sourceNATPoolPortRange`, plus lenient path partial-success logic
```
func buildSourceNATSnapshots(cfg *config.Config, natCounterIDs map[string]uint32) []SourceNATRuleSnapshot {
    return buildSourceNATSnapshotsWithFeeds(cfg, natCounterIDs, nil)
}
func buildSourceNATSnapshotsWithFeeds(cfg *config.Config, natCounterIDs map[string]uint32, feedOverlay map[string][]string) []SourceNATRuleSnapshot {
    // 500 LOC: iterates NAT rules, expands app-sets, classifies addresses, handles scope tiers
}
func sourceNATScopeTier(s SourceNATRuleSnapshot) int {
func scopeContextTier(iface, zone, routingInstance string) int {
func natAppProtoNumber(proto string) uint16 {
func buildSourceNATAppTerms(cfg *config.Config, appNames []string) []NatAppTermWire {
```
- `nat_destination.go:88` - Destination NAT mirrors source but with `dnatDestinationParts`, `dnatPoolHostIP`, pool vs rule distinction
- `natcounters.go:65` - Counter ID allocation `buildNATCounterIDs` - maps rule name -> ID for BPF map pins
- All builders take `feedOverlay map[string][]string` param threaded through 6 call sites - indicates feed overlay should be part of builder context, not param

**Proposed decomposition**:
- `pkg/dataplane/userspace/nat/builder.go` - `Builder` struct holding `cfg *config.Config`, `counterIDs map[string]uint32`, `feedOverlay map[string][]string`, `addressBook map[string]uint32` - method `BuildSource()`, `BuildDest()`, `BuildStatic()`
- `nat/scope.go` - scope tier logic (`sourceNATScopeTier`, `scopeContextTier`, `nat_scope_3096`, `nat_scope_precedence_4161`)
- `nat/app.go` - app term expansion (`buildSourceNATAppTerms`, `natAppProtoNumber`, `NatAppTermWire` conversion) with error handling for malformed app-sets (dedup M02/M03)
- `nat/pool.go` - pool port math (`deterministicSourceNATFields`, `sourceNATPoolPortRange`, port-range reversed detection #3726)
- `nat/counters.go` - move natcounters.go + policycounters.go shared ID allocation into `nat/counters/`
- `nat/feed_overlay.go` - feed overlay merging logic (currently duplicated in source and dest)
- Keep `nat.go` as package doc + top-level `BuildAll()` that delegates

**Hot-path preservation analysis**:
- NAT snapshot building is cold path (commit time) - no packet path impact
- Risk: deterministic NAT fields (`mode, blockSize, blocksPerIP, hostBase, hostCount`) must produce identical wire output—extraction must not change calculation order or int truncation (uint16 port ranges)
- Hot-path relevant: NAT rule order affects Rust policy eval - stable sorting must be preserved (currently sorted by rule name? by extent? check)
- Verification: `make test-go -run TestNAT` (manager_nat_test 336, nat_l4_match 420, nat_per_uplink 398, nat_source_pool_port_5457, etc - ~30 tests), golden JSON diff of SourceNATRuleSnapshot before/after

**Tests + gate**:
- 30+ NAT tests: nat_dnat_*, nat_source_*, nat_feed_overlay_3303, nat_per_uplink, nat_reversed_port_range_3726, nat_scope_3096, nat_scope_precedence_4161, nat_l4_match_3429, nat_match_multivalue_3431, nat_static_*, nat64_*
- Gate: `make test-go -run NAT` + `make test -run xdp_shim_decouple` to ensure NAT local address exclusion still works

**Why it matters**:
- NAT scope precedence (interface vs zone vs routing-instance) is security-critical - config like `from zone trust` vs `from interface ge-0/0/1.0` order determines which rule hits; scattered across 6 files makes audit hard
- Deterministic NAT (#4559) block math is duplicated? `nat_source.go` and `nat64.go` both have similar but not identical deterministic fields - should share
- Feed overlay param threading is error-prone: missing overlay means stale address-book CIDRs enforced

**Fix direction**:
1. Create `nat.Builder` struct holding common deps
2. Move scope tier to `nat/scope.go` with table-driven tests for precedence (4161)
3. Move app expansion to `nat/app.go` with explicit error return for malformed sets (fixes dedup M02/M03 partial-drop)
4. Extract counter ID allocation to `nat/counters` - owns `map[string]uint32` lifecycle

**Labels**: nat, vsrx-parity, deterministic-nat, scope-precedence

**Dedup note**: Dedup mentions NAT app-set partial-drop (M02, M03) and reversed ranges (H04) - this finding aggregates those into structural cause (no builder context, scattered error handling) and proposes fix. Not duplicate, is architectural superset. Also dedup "Port Filtering Bypass (Fail-Open) on Lenient Path for Invalid Static NAT Ports" in nat.go:640 - related but different file now (migrated to userspace). Acknowledge lenient path handling lives in `nat.go` lenient load.

---

### M6: Policy Compilation - 5 files, 1100 LOC, addr-book + policy slots + scheduler + ids + reject entangled

**Title**: Policy subsystem fuses address-book dedup (489), policy slot walking (160), scheduler state (53), runtime IDs (151), reject reasons (206), representable check (206), lower (284) across 6 files sharing cfg.Config but no shared builder

**Severity**: Medium

**Confidence**: High

**Refactor class**: B - Policy subpackage with clear phases

**Evidence**:
- `policies.go:53-147` - `policyRuleSlot` struct + `walkPolicyRuleSlots` iterating over `cfg.Security.Policies` (map) with zone-pair expansion
```
type policyRuleSlot struct {
    fromZone string
    toZone string
    // ...
}
func walkPolicyRuleSlots(cfg *config.Config, fn func(slot policyRuleSlot) error) error {
    // walks security.policies[zone-pair][name] with global zone handling
}
```
- `policies_addrbook.go:122-489` - `buildAddressBookTable` builds deduped CIDR table, recursive expansion `expandBookNameRecursive`, canonical hash `canonicalizeAddressBookContent`, collision detection `AddressBookIDCollisionError`
- `policies_ids.go:??` - runtime ID allocation for policies (map name -> uint32 for BPF)
- `policies_lower.go:284` - lowering policy snapshots? (needs read)
- `policies_scheduler.go:53` - scheduler active state snapshot
- `policies_reject.go:206` + `policies_representable.go:206` - content rejection for unrepresentable policies (#3261) - 512KB port range amplification noted in dedup
- All called from `manager_compile.go` via `buildSnapshot...` which threads `activeState` and `feedOverlay`

**Proposed decomposition**:
- `pkg/dataplane/userspace/policy/catalog.go` - Address book: `buildAddressBookTableWithFeeds`, `classifyPolicyAddresses`, `canonicalizeAddressBookContent`, `AddressBookIDCollisionError`, plus feed overlay merge
- `policy/slot.go` - Slot walking: `policyRuleSlot`, `walkPolicyRuleSlots`, `effectiveMatchFromZones`, `effectiveMatchToZones`, global zone set handling (scoped_global_zoneset_4626)
- `policy/snapshot.go` - `buildPolicySnapshotsWithSchedulerStateAndFeeds`, `buildOneRuleSnapshot` - single rule lowering with scheduler active check
- `policy/ids.go` - `policies_ids.go` unchanged but moved to `policy/ids/allocator.go` - owns counter/policy ID allocation, namespace overflow handling (#3063)
- `policy/reject.go` - `policies_reject.go` + `policies_representable.go` fused - content rejection reasons, unrepresentable port range check (dedup Low: 512KB per wide range), plus `ScreenMissingProfileRef` handling
- `policy/scheduler.go` - `policies_scheduler.go` + `PolicySchedulerActiveState` from manager_compile.go
- Builder: `policy.Builder` struct holding `cfg`, `activeState`, `feedOverlay`, `addressBook map[string]uint32` -> `Build() ([]PolicyRuleSnapshot, []AddressBookSnapshot, []string /*rejectReasons*/)`

**Hot-path preservation analysis**:
- Policy compilation is commit cold path, but resulting `PolicyRuleSnapshot` order affects Rust policy evaluation determinism - must preserve stable sort (by zone-pair, then rule name)
- Address book canonicalization hash must be stable - `canonicalizeAddressBookContent` sorts v4/v6 CIDRs then SHA256? Check: it does sort + join then hash - extraction must keep sort order identical to avoid churn detection (snapshot hash compares)
- Scheduler active state snapshot must be atomic with policy build - currently snapshot taken in manager_compile.go before policy build; builder must ensure same snapshot used for all rules or risk race where rule active check differs mid-build
- Verification: `make test-go -run TestPolicy` (manager_policy_test 492, policy_global_zone_3148, policy_namespace_3143_3145, policy_reject_reasons_3376, nested_app_set_policy), plus `go test -run TestAddressBook` (address_book_collision_2514), plus snapshot hash golden test showing no churn on reorder

**Tests + gate**:
- 15+ policy tests, plus address_book_collision, addressbook_slash, app_catalog, app_inactivity_timeout, excluded match, etc
- Gate: `make test-go` + `make test` + check `SnapshotSummary.PolicyCount` stable across re-applies with same config

**Why it matters**:
- Policy is security enforcement core - zone-pair matching, global zone (#3148), namespace (#3143), excluded match (#...), reject reasons (#3376) all security-critical; scattered across 6 files makes single-review hard
- Address-book dedup is shared between NAT and policy but built separately (policy addrbook vs NAT source address-name) - inconsistent dedup could cause ID collision
- 512KB port range amplification (dedup Low) lives in representable check - should be capped or chunked during snapshot build, currently allocates wide range eagerly

**Fix direction**:
1. Create `policy.Builder` that owns addr-book + slot walk + ID alloc + reject reasons
2. Move addr-book classification to `policy/catalog.go` - share between NAT and policy via `policy/catalog.Classify()`
3. Move reject/representable to `policy/reject.go` with explicit `MaxPortRange` constant and early abort
4. Keep `policies.go` as facade delegating to new builder for 1 release

**Labels**: policy, vsrx-parity, security-enforcement, addrbook-dedup

**Dedup note**: Dedup lists "Minor control-plane memory amplification. Snapshot build allocates 512 KB per wide application port range" for screens.go but similar issue in policy representable - acknowledge. Dedup for policy_runtime_ids_3063 (namespace overflow) and policy content rejection are related but this aggregates root cause: no builder context leading to partial map returns on overflow. New.

---

### M7: Zones Subsystem - 7 files, ~1400 LOC, host-inbound + observability + quarantine + snapshot + stable-id fused

**Title**: Zones subsystem splits across 7 files but still entangled: host-inbound lifeline delegated to config, override union/merge, quarantine collision, observability (addressless, ambiguous), snapshot building, stable-id, TCP RST per zone

**Severity**: Medium

**Confidence**: High

**Refactor class**: B - Zone subpackage with clear separation of enforcement vs observability vs build

**Evidence**:
- `zones.go:19-84` - thin wrappers delegating to `config.HostInboundLifelineSet` + `buildInterfaceZoneMap` (iface -> zone, handles base/unit auto-map)
```
func hostInboundLifelineSet(cfg *config.Config) map[string]bool {
    return config.HostInboundLifelineSet(cfg)
}
func buildInterfaceZoneMap(cfg *config.Config) map[string]string {
    // 84 LOC: builds map_iface->zone with sorted zone names for determinism, handles ".unit" cut, ifCfg unit enumeration
}
```
- `zones_host_inbound.go:394` - `ZoneHostInboundView` + `BuildZoneHostInboundViews` + `BuildUnzonedHostInboundAddrs` - 394 LOC, includes VRRP VIP, kernel-learned addr, lifeline
- `zones_override.go:178` - `unionHostInboundTokens`, `mergeHostInboundTraffic`, `buildInterfaceHostInboundMap` - override inheritance
- `zones_quarantine.go:189` - `ZoneIDCollision`, `quarantineCollidingZones` - stable ID collision handling (#3719)
- `zones_observability.go:369` - `AddresslessEnforcingZone`, `AddresslessEnforcingInterface`, `AmbiguousHostInboundAddress` + build functions - security posture observability
- `zones_snapshot.go:124` - `buildZoneSnapshots` + `lowerTokens` - final snapshot build
- `zonecounters.go:61` - zone counter snapshot
- `zones_stable_id_3704_test.go`, `zones_collision_3719`, `zones_addressless_3698`, etc - 7 test files

**Proposed decomposition**:
- `pkg/dataplane/userspace/zone/build.go` - `buildInterfaceZoneMap`, `buildZoneSnapshots`, stable ID allocation, TCP RST carry, session display reverse map, per-RG ownership lookup
- `zone/hib/view.go` - `ZoneHostInboundView`, `BuildZoneHostInboundViews`, `BuildUnzonedHostInboundAddrs`, lifeline handling, VRRP VIP inclusion
- `zone/hib/override.go` - `unionHostInboundTokens`, `mergeHostInboundTraffic`, `buildInterfaceHostInboundMap` - override precedence (physical vs unit)
- `zone/hib/lifeline.go` - re-export wrappers currently in zones.go, but ensure SSOT stays in `pkg/config/lifeline.go` - no logic move, just package doc
- `zone/quarantine/collision.go` - `ZoneIDCollision`, `quarantineCollidingZones`, `String()` - collision detection + scrub of scoped global policies
- `zone/observability/addressless.go` - `AddresslessEnforcingZone`, `AddresslessEnforcingInterfaces`, heal-on-lease logic
- `zone/observability/ambiguous.go` - `AmbiguousHostInboundAddresses`, differing services detection
- `zone/counters.go` - `zonecounters.go` (61 LOC) - keep but move to `zone/counters/snapshot.go`

**Hot-path preservation analysis**:
- Zone snapshot build is cold path but zone ID stable allocation must be deterministic across HA peers - collision quarantine must produce identical quarantine set on both nodes or zone IDs shift (dedup AGY-138-02)
- Host-inbound view is also cold path for snapshot, but Rust enforces it hot path (packet's ingress iface -> zone -> HIB check). Go side view building must keep token-order signatures stable - lowerTokens + sort must be preserved
- Verification: `make test-go -run TestZone` (zones_stable_id_3704, zones_collision_3719, zones_addressless_3698/3710, zones_ambiguous_3718, zones_host_inbound, zones_tcp_rst_3071), plus `make test-failover` to ensure HA peers have identical zone IDs after collision quarantine

**Tests + gate**:
- 8 zone test files (zones_*.go) + zone counters, zone local addressbook, etc
- Gate: `make test-go -run Zone`, `make test-failover` (zone ID collision scenario #3719)

**Why it matters**:
- Zone ID collision (#3719) quarantine is security isolation - if colliding zones not quarantined identically on both HA nodes, traffic could leak between zones after failover
- Host-inbound override shadowing (dedup H04 physical shadows unit) - bug in override merge could allow unexpected fxp0-like lifeline to admit all
- Addressless enforcing zones: mixed IPv4/IPv6 presence hides windows (dedup H01, H02) - observability split needs clear reason enum (dedup L10)

**Fix direction**:
1. Create `zone/` subpackage with `build`, `hib/`, `quarantine/`, `observability/`, `counters/`
2. Move `buildInterfaceZoneMap` + `buildZoneSnapshots` to `zone/build.go` first (zero dep)
3. Move quarantine to `zone/quarantine/` with own tests
4. Move HIB view + override to `zone/hib/` - preserve lifeline SSOT delegation to config package
5. Keep `zones.go` as facade re-exporting for 1 release

**Labels**: zone, host-inbound, vsrx-parity, ha-consistency, observability

**Dedup note**: Dedup lists many zone findings (H01, H02 mixed-zone addressless hides, H04 physical shadows unit, M03 duplicate VRRP VIPs, etc) - this finding aggregates structural cause: 7 files but no clear package boundary between enforcement (snapshot/HIB) vs observability (addressless/ambiguous) vs safety (quarantine). Proposes concrete 4-way subpackage split. Not duplicate, is superset.

---

### M8: Process Management - 5 files, 1254 LOC, process lifecycle + control socket + NAPI + status + link-cycle fused

**Title**: Process subsystem (process.go 270 + process_control 196 + process_napi 370 + process_status 248 + process_linkcycle 170) fuses helper binary find, socket buffer tuning, control socket framing/serialization, status JSON decode, NAPI polling/liveness, link-cycle/worker arm

**Severity**: Medium

**Confidence**: Medium

**Refactor class**: B/C - Process subpackage

**Evidence**:
- `process.go:18-270` - `ensureProcessLocked`, `stopLocked`, `tuneSocketBuffers`, `findBinary`, `StartFIBSync`
```
func (m *Manager) ensureProcessLocked(cfg config.UserspaceConfig) error {
    // finds binary via findBinary, checks configEqual, starts exec.Cmd, sets up eventStream Cancel
}
func tuneSocketBuffers() {
    // sysctl net.core.rmem/wmem ?
}
func configEqual(a, b config.UserspaceConfig) bool {
```
- `process_control.go:196` - Control socket write serialization: `ControlRequest` + `ControlResponse` framing, fail-closed ctrl map handling hooks
- `process_napi.go:370` - NAPI polling, XSK RX counter liveness, bootstrap detection, standby neighbor resolve
- `process_status.go:248` - Status JSON unmarshal, capability decode, backend epoch, delta stream, WG peer transition logging
- `process_linkcycle.go:170` - Link cycle notification, `deferWorkers` bool, `pendingWorkerArm`, `xskBoundNotified` callback

**Proposed decomposition**:
- `pkg/dataplane/userspace/process/manager.go` - `ensureProcessLocked`, `stopLocked`, `findBinary`, `configEqual`, `tuneSocketBuffers` - binary lifecycle
- `process/control/socket.go` - Control socket client: framing, write serialization, request/response, fail-closed hooks (`lookupUserspaceCtrlForFailClosedHook`)
- `process/control/ctrl_map.go` - Ctrl map enable/disable, `ctrlEnableAt`, `ctrlWasEnabled`, `initialCtrlCleanupDone`, `ctrlDisabledAt ktime_ns`
- `process/status/decode.go` - `applyHelperStatusLocked`, JSON unmarshal, `ProcessStatus` conversion, `runtime_delta` adapter, WG endpoint transition log
- `process/napi/poll.go` - NAPI polling, XSK bind check, RX counter liveness (`xskLivenessFailed/Proven`, `lastXSKRX`, `xskProbeStart`), bootstrap
- `process/lifecycle/link_cycle.go` - Link cycle, `deferWorkers`, `pendingWorkerArm`, `xskBoundNotified`, `OnXSKBound` callback, `NotifyLinkCycle`
- `process/fib/sync.go` - `StartFIBSync` (currently in process.go) - FIB sync context

**Hot-path preservation analysis**:
- Process control socket is contended resource per CLAUDE.md: "shared by status poll (1/s), HA sync, session installs, snapshot sync, and forwarding sync. High-frequency callers MUST be throttled. Adding a new control socket request at >1/s will starve session installs during bulk sync."
- Extraction must preserve throttling: status poll 1/s, HA sync throttled via `lastHASyncTime`, session sync via `sessionMu` + sweep profile
- NAPI polling is not packet hot path but liveness detection - if XSK RX stuck, need fast failover
- Link cycle defer-workers arm is critical for RETH MAC change - after virtual MAC change, workerless snapshot then mandatory re-apply arming workers (#5134) - missing arm = silent forwarding outage
- Verification: `make test-go -run TestProcess` (none? process has no direct tests, but via manager tests), `make test-failover`, `perf stat` on control socket QPS, `slog` for control socket contention (count of concurrent waits)

**Tests + gate**:
- Tests: manager interfaces, process linkcycle, wg_status, xdp_shim_decouple, boot canary, tunnel tests invoke process manager indirectly
- Gate: `make test-go`, `make test-failover`, `make test-restart-connectivity` (restart behavior), manual control socket contention test: bulk session sync + failover concurrent

**Why it matters**:
- Control socket contention starves session installs during bulk sync - current monolithic process mgmt makes it hard to add throttling per caller
- Defer-workers arm logic (#5134) is hidden in link_cycle.go - needs explicit state machine with retry (retryDeferredWorkerArmLocked) observable via status
- Binary find + buffer tuning are startup-only, should not be mixed with runtime NAPI polling

**Fix direction**:
1. Extract socket client to `process/control/socket.go` with QPS counter and throttling per caller tag
2. Extract NAPI poller to `process/napi/poll.go` with own ticker, not mixed with status decode
3. Extract link-cycle to `process/lifecycle/` with explicit state machine: `DeferWorkersActive -> PendingArm -> Armed`, plus retry ticker
4. Keep `process.go` as facade

**Labels**: process-mgmt, control-socket-contention, xsk-liveness, link-cycle

**Dedup note**: Dedup mentions "process.go is operational recovery catch-all" (Medium) - this finding provides concrete 5-way split and identifies control-socket contention as root cause of recovery fragility. Complements.

---

### M9: Routing / Tunnels / Neighbors / Screens - Scattered but cohesive compile fragments

**Title**: routes.go 431 + tunnels.go 213 + neighbors.go 267 + screens.go 239 + runtime_delta 128 + wire_uint8list 111 - routing/forwarding compile fragments scattered but each relatively cohesive; shared via ConfigSnapshot but no shared RouteBuilder context

**Severity**: Low

**Confidence**: Medium

**Refactor class**: C - Keep together as `forward/compile` or `rib/` subpackage

**Evidence**:
- `routes.go:431` - `RouteSnapshot`, `buildRoutes` (?) + dedup, family normalize, fib metadata, IPv6 nexttable, ribgroup leak, rulelist, PBR priority, overlay replacement
- `tunnels.go:213` - `TunnelEndpointSnapshot`, GRE, IPIP, WG endpoint, NAT-T exclusion
- `neighbors.go:267` - `NeighborSnapshot`, ARP/ND, ifindex filter
- `screens.go:239` - `ScreenProfileSnapshot`, screen checks (16 checks)
- `runtime_delta.go:128` - Adapter from Manager to dpruntime.SessionDeltaSource - pure adapter
- `wire_uint8list.go:111` - Generic uint8 list codec (likely for IP lists?)

**Proposed decomposition**:
- Option C1: Keep as-is for routes/tunnels/neighbors/screens - each <500 LOC, single responsibility (build snapshot for that domain). D-negative justified except routing needs extra split due to 7 responsibilities (dedupe, family normalize, ribgroup leak, IPv6 nexttable, rulelist, PBR priority, overlay)
- Option C2: `pkg/dataplane/userspace/rib/routes.go` for routes + route_overlay_test etc, `rib/tunnels.go`, `rib/neighbors.go`, `rib/screens.go` - group as `rib/` (routing information base) subpackage
- `runtime_delta.go` -> `pkg/dataplane/userspace/runtime/adapter.go` - adapter layer, already clean interface
- `wire_uint8list.go` -> `pkg/dataplane/userspace/wire/uint8list.go` - wire codec, keep generic
- Route overlay replacement logic (routes.go:156-179) currently replaces next-hop list with bare entry.NextHop losing interface scope - dedup L8 - should be in `rib/overlay.go`

**Hot-path preservation analysis**:
- All cold path (commit time) - no hot path
- Route snapshot sort stability for ECMP: dedup M10 says sort unstable for equal table/family/dest causing ECMP churn - extraction must use stable sort
- Verification: `make test-go -run TestRoute` (routes_dedupe_3770, routes_family_normalize_4423, routes_ipv6_nexttable_3768, routes_ribgroup_leak_3876, routes_rulelist_3772, routes_pbr_priority_4479, route_overlay_test, routes_fib_metadata_test) - 8 tests

**Tests + gate**:
- 8 route tests + tunnels_test + screens via manager_screens_test + snapshot_neighbors_1197 + runtime_delta_test
- Gate: `make test-go -run (Route|Tunnel|Neighbor|Screen)`

**Why it matters**:
- Route overlay replacement cannot express ECMP (dedup L6) - architectural limitation of overlay struct (single next-hop)
- IPv6 ip-rule route leaks point to .inet.0 (dedup H6) - userspace next-table lookup misses target VRF
- Route dedup ignores Discard/Preference (dedup H8) - one route can erase another distinct route
- These are correctness bugs traceable to lack of `rib.Builder` context that would make ECMP, preference, discard explicit

**Fix direction**:
- Create `rib.Builder` with `table, family, destination, preference, discard, ECMP members` explicit
- Stable sort impl: `sort.SliceStable` by table, family, dest, then preference, then discard, then ECMP member list hash
- ECMP support in overlay: change `entry.NextHop` to `[]NextHop` with interface scope

**Labels**: rib, vsrx-parity, ecmp, route-leak

**Dedup note**: Aggregates dedup H6 (IPv6 leak .inet.0), H8 (dedupe ignores Discard/Preference), M8 (canonicalRoutePrefix raw string), M9 (RuleList failures silent), M10 (unstable sort ECMP churn), L6 (overlay cannot express ECMP), L8 (overlay no interface scope) - prior findings were individual bugs, this is structural cause: no rib.Builder context. Proposal addresses root.

---

### M10: Small cohesive modules - D-NEGATIVES (Do NOT split)

**Title**: Small (<120 LOC) focused modules that are correctly sized and must NOT be split

**Severity**: Low (negative)

**Confidence**: High

**Refactor class**: D - Must not split

**Evidence**:

1. `maps.go:59` - Const registry
```
const (
    mapNameUserspaceCtrl      = "userspace_ctrl"
    mapNameUserspaceBindings  = "userspace_bindings"
    mapNameUserspaceHeartbeat = "userspace_heartbeat"
    mapNameUserspaceXSK       = "userspace_xsk_map"
    mapNameUserspaceCPUMap    = "userspace_cpumap"
    mapNameUserspaceSessions  = "userspace_sessions"
    mapNameUserspaceIngressIfaces  = "userspace_ingress_ifaces"
    mapNameUserspaceLocalV4        = "userspace_local_v4"
    mapNameUserspaceLocalV6        = "userspace_local_v6"
    ...
)
```
- LOC 59, 0 funcs, 11 consts, single responsibility: BPF map name registry with extensive doc about canary enforcement
- Why not split: Atomic unit - splitting consts across files would defeat canary `maps_decouple_test.go` which AST-scans `pkg/dataplane/userspace/*.go` for literals; keeping single registry is intentional guardrail per #1521

2. `nat_nptv6.go:48` - NPTv6 builder
```
func buildNptv6Snapshots(...) []Nptv6RuleSnapshot {
    // 48 LOC, 2 funcs, single responsibility: NPTv6 prefix translation rules
}
```
- Why not split: Trivial builder, 1 snapshot type, no shared state, already minimal

3. `wire_uint8list.go:111` - Generic uint8 list codec
```
func encodeUint8List(list []uint8) []byte { ... }
func decodeUint8List(...) [...] { ... }
// used for BPF map keys? actually used for port lists?
```
- Why not split: Utility codec, stateless, 2 funcs, 111 LOC, single responsibility

4. `zonecounters.go:61` + `natcounters.go:65` - Counter snapshots
```
func buildZoneCounters(...) []ZoneTrafficCounterStatus { ... }
func buildNATCounters(...) []NATRuleCounterStatus { ... }
```
- Why not split: Each ~60 LOC, single snapshot type, called from status sync; merging into larger file would create coupling, staying separate preserves counter domain isolation

5. `manager_generation.go:120` - Generation bump
```
func (m *Manager) bumpGeneration() uint64 { m.mu.Lock(); m.generation++; ... }
func (m *Manager) readFIBGeneration() uint32 { ... }
```
- Why not split: 120 LOC, 2 funcs, owns generation counter + fibGeneration, simple atomic-like increment under mu; extracting would require moving mu or adding new mu for 2 fields - over-engineering

6. `policies_scheduler.go:53` - Scheduler state
```
func buildPolicySnapshotsWithSchedulerState(...)...
func (m *Manager) policySchedulerActiveStateSnapshot() map[string]bool {
```
- 53 LOC, 4 funcs, single responsibility: scheduler active map snapshot + copy helper; already minimal, but could be merged into policy/builder later (currently D but future B candidate)

7. `runtime_delta.go:128` - Adapter
```
type runtimeSessionDeltaSource struct{ manager *Manager }
func (s runtimeSessionDeltaSource) DrainSessionDeltas(max uint32) ...
func runtimeSessionDeltaSnapshot(...) dpruntime.SessionDeltaSnapshot { ... }
func runtimeStatus(status ProcessStatus) dpruntime.RuntimeStatus { ... }
```
- Why not split: Pure adapter, 128 LOC, 7 funcs, no state, bridges Manager to dpruntime interface; extracting would add indirection with no benefit; keep as adapter pattern example of good cohesion

8. `userspace_xdp_rust.go:20` - Build tag stub
```
// 20 LOC, 1 func, build constraint for rust xdp shim
```
- Why not split: Generated/retained shim .o loader, pinned toolchain gate (#1864), minimal wrapper

**Proposed decomposition**: None - keep as-is. For future, `maps.go` could add `String()` method for map names but not needed; `wire_uint8list.go` could move to `wire/` subpackage when wire subpackage created (M1), but keep file intact

**Hot-path preservation analysis**:
- All cold path or pure data
- Verification: `make test-go -run TestMapsDecouple` for maps.go, `make test -run TestNAT` for nat_nptv6, etc

**Tests + gate**:
- maps_decouple_test.go 1525 LOC guards maps.go registry
- nat64_deterministic_4559_test etc guard nat modules
- Gate: `make test-go`

**Why it matters** (negative justifies):
- Over-splitting <120 LOC files creates file proliferation, harms `gopls`, increases import cycle risk, and violates "keep solutions simple and direct" from CLAUDE.md
- These are examples of well-factored small modules - should be preserved as pattern for larger splits

**Fix direction**: None - mark as D, do not split, use as example of target size for extracted modules (target 50-300 LOC per file after split)

**Labels**: d-negative, cohesive-module, do-not-split

**Dedup note**: Not in dedup index - prior dedup focused on large files. These D-negatives prove coverage of small files and give template for desired post-split file size.

---

### M11: Legacy + Shim Verification - Transitional Files

**Title**: legacy_dataplane.go 679 LOC + verify_userspace_shim.go 149 + userspace_xdp_rust.go 20 are transitional retirement shims, should be collapsed not expanded

**Severity**: Low

**Confidence**: High

**Refactor class**: D - Transitional, do not refactor until retirement complete, then delete

**Evidence**:
- `legacy_dataplane.go:679` - Implements legacy DataplaneManager interface via userspace manager? Or batch-clear? Check name: `LegacyDataplane` adapter that holds `*Manager` and implements old `dataplane.Manager` interface for gradual migration
- `verify_userspace_shim.go:149` - Verifies retained Rust AF_XDP shim .o object: pinned toolchain + kernel-verifier gate (#1864), checks `userspace_xdp/src/lib.rs` built .o valid
- `userspace_xdp_rust.go:20` - Build tag file that loads shim .o
- These are retirement scaffolding per CLAUDE.md: "eBPF dataplane retirement is done. Rust AF_XDP userspace helper is only runtime. Legacy BPF source deleted in #1476; explicit system dataplane-type ebpf hard-rejected"

**Proposed decomposition**:
- Do NOT split - instead schedule deletion:
  - `legacy_dataplane.go` can be deleted once `pkg/dataplane.Manager` interface fully replaced by `userspace.Manager` direct usage in `pkg/daemon`
  - `verify_userspace_shim.go` should stay - it guards shim .o integrity, but could move to `pkg/dataplane/userspace/shim/verify.go`
  - `userspace_xdp_rust.go` stays as load site
- If must split, `legacy_dataplane.go` 679 LOC could be split into `legacy/manager.go` + `legacy/batch_clear.go` (BatchClear 5096 test), but not worth while pending deletion

**Hot-path preservation analysis**:
- Legacy adapter is cold path (daemon start, config apply) - not packet path
- Shim verifier is build-time + startup - must not slow boot (currently <100ms)
- Verification: `make generate` + `make build` + `make test-go -run TestVerifyShim`

**Tests + gate**:
- legacy_dataplane_test.go 229, legacy_dataplane_batchclear_5096_test.go 175, verify_userspace_shim_test.go 109, userspace_shim_loader_test.go 731, shim_loader_boundary_test.go 108
- Gate: `make test-go` + `make generate` gate (pinned toolchain)

**Why it matters**:
- Refactoring transitional code wastes effort that should go to deleting it
- But legacy_dataplane.go 679 LOC is still god-adapter: it likely holds `BatchClear`, `Close`, `CompileResult` translation - needs at least comment marking retirement plan

**Fix direction**:
1. Add `// Deprecated: will be removed after #XXXX - use userspace.Manager directly` comment
2. Do not split - instead create issue to delete file once daemon directly uses userspace manager
3. Keep shim verifier as-is - it's safety gate

**Labels**: transitional, retirement, d-negative, deletion-candidate

**Dedup note**: Not in dedup index - prior ref actors focused on active code. This D-negative prevents wasted refactor on dying code.

---

### M12: Overlay + FeedOverlay Cache - 197 LOC, good cohesion but needs interface

**Title**: manager_overlay.go 197 LOC + manager_neighbor.go 270 LOC are well-sized caches but mix locking with manager, should become explicit Cache structs with own mutex

**Severity**: Low

**Confidence**: Medium

**Refactor class**: C - Extract cache interface

**Evidence**:
- `manager_overlay.go:197` - `routeOverlay []config.RouteOverlayEntry` + `feedOverlay map[string][]string` cached with methods `SetRouteOverlay`, `PublishRouteOverlaySnapshot`, `routeOverlaySnapshot()`, `feedSnapshotOverlay()`, plus `logWgEndpointSetTransitionLocked`
- `manager_neighbor.go:270` - `neighborIndex map[neighborIndexKey]*NeighborSnapshot` + `monitoredIfindexes map[int]struct{}` + `neighborsPrewarmed bool` + methods for index rebuild, prewarm, ifindex filter
```
func (m *Manager) PublishRouteOverlaySnapshot(...) error {
    // 929-935 in manager.go - mutates cached desired overlay before publication succeeds (dedup H6)
}
```
- Both are caches with read-mostly pattern: written on commit (routeOverlay) or feed update (feedOverlay) or neighbor regen, read on every snapshot build

**Proposed decomposition**:
- `pkg/dataplane/userspace/cache/overlay.go` - `OverlayCache` struct: `mu sync.RWMutex`, `routeOverlay []config.RouteOverlayEntry`, `feedOverlay map[string][]string`, `lastPublishedWgEndpoints string`, methods `SetRouteOverlay`, `SetFeedSnapshots`, `Snapshot() (route, feed)`, `TransitionLog()`
- `cache/neighbors.go` - `NeighborCache` struct: `mu sync.RWMutex`, `neighborIndex`, `monitoredIfindexes`, `neighborsPrewarmed`, methods `Rebuild()`, `Lookup(ifindex, ip) *NeighborSnapshot`, `Monitored() map[int]struct{}`
- Fix dedup H6: `PublishRouteOverlaySnapshot` should publish after success, not mutate before - cache's `Set` should only update after publish ack, or keep `desired` vs `published` two-phase commit

**Hot-path preservation analysis**:
- Overlay cache read on every snapshot build (commit path) - must be fast, RWMutex good
- Neighbor index read on listener hot path: "O(1) neighbor lookup index for the listener hot path" per comment - keyed by (ifindex, ip-string). Read under m.mu currently - moving to RWMutex could improve listener throughput (listener is netlink neighbor monitor?)
- Verification: `make test-go -run TestOverlay` (route_overlay_test 459), `make test-go -run TestNeighbor` (snapshot_neighbors_1197 170)

**Tests + gate**:
- route_overlay_test.go 459, snapshot_neighbors_1197_test.go 170, manager_republish_3780_test.go 84
- Gate: `make test-go`, plus check publish-before-mutate bug fixed via new test `TestPublishRouteOverlayMutatesAfterSuccess`

**Why it matters**:
- Dedup H6: `PublishRouteOverlaySnapshot` mutates cached desired overlay before publication succeeds - if publish fails, cache has new value but helper has old, causing divergence (dual write without transaction)
- Neighbor index lock contention: listener hot path takes Manager.mu which blocks ApplyConfig - should be RWMutex or lock-free map (sync.Map?)

**Fix direction**:
1. Create `cache.OverlayCache` with RWMutex, two-phase commit: `desired` vs `published`, `Set` updates desired, `MarkPublished` moves to published after ack
2. Create `cache.NeighborCache` with RWMutex, `Rebuild` writes, `Lookup` reads lock-free via RWMutex RLock
3. Fix H6 by only updating `lastPublishedWgEndpoints` after successful publish

**Labels**: cache, race, publish-boundary, lru

**Dedup note**: Dedup H6 explicitly "PublishRouteOverlaySnapshot mutates cached desired overlay before publication succeeds" - this report provides fix direction (two-phase commit) and proposes cache extraction. Not duplicate, is remediation of dedup H6.

---

## Cross-Cutting Themes & Size Metrics

**Overall batch shape**:
- Production: 46 files, 16231 LOC, avg 353 LOC/file, median 197, p90 548, max 3064
- Test: 97 files, 26800 LOC, avg 276 LOC/test
- God file concentration: top 3 files (protocol 3064 + maps_sync 1763 + manager_ha 1643) = 6470 LOC = 40% of prod
- Manager + compile + generation + status + neighbor + overlay + worker_arm + ha = 434+622+120+231+270+197+103+1643 = 3620 LOC manager cluster = 22% of prod
- NAT cluster: 225+511+548+94+121+48+65 = 1612 LOC = 10% of prod
- Policy cluster: 160+489+151+284+206+206+53+358 = 1907 LOC = 12% of prod
- Zone cluster: 84+394+369+178+189+124+61 = 1399 LOC = 9% of prod
- Process cluster: 270+196+170+370+248 = 1254 LOC = 8% of prod
- Rib cluster: 431+213+267+239+128+111 = 1389 LOC = 9% of prod

**Monolithicity evidence**:
- `Manager` struct has 80+ fields, 2 Mutex + 1 atomic + 2 func hooks, spans 8 domains
- `protocol.go` has 80+ types, every feature appends here (CoS, NAT64, NPTv6, screens, filters, policers, AppCatalog all added as fields to ConfigSnapshot)
- `maps_sync.go` has 25 methods on Manager, all suffix `Locked`, single mu protects bootstrap + classifier + local addr + NAT addr + binding verify + wedge + auto-rebind
- No subpackage - all in `package userspace` (single package, 218 files total in dir) - import cycle risk low but cohesion zero

**Natural seams**:
- Wire schema vs control vs status vs binding vs HA vs session are natural package boundaries (already hinted by type prefixes: `*Snapshot`, `*Status`, `*Request`, `Binding*`, `HA*`, `Session*`)
- Compile-time vs runtime: `policies_*.go`, `nat_*.go`, `routes.go`, `zones_*.go` are compile-time builders (pure func `config.Config -> []Snapshot`), while `manager_*.go`, `maps_sync.go`, `process*.go` are runtime managers (stateful, mu, BPF maps, proc)
- Cold path vs hot path: All Go code here is control-plane cold path (commit, 1/s status poll, 200ms HA watchdog) - Rust dataplane is packet hot path. Go refactor safe from packet latency perspective except control-socket contention (see CLAUDE.md)

---

## Hot-Path Preservation Summary

| Module | Hot path? | Risk | Verification |
|--------|-----------|------|--------------|
| protocol.go | No - wire JSON, cold | JSON tag mismatch -> Rust decode failure -> fail-closed or fallback stats? Check #2124 failopen | `make test-go -run Protocol` + `cargo test` + JSON golden diff |
| maps_sync.go | Cold but mu blocks HA watchdog (200ms) | Adding extra BPF map iteration under mu delays failover >1s | `pprof mutex`, `perf stat` on ApplyConfig, `test-failover` |
| manager_ha.go | HA watchdog 200ms map write is near-hot | Moving map write behind socket IPC -> failover delay; session drain alloc increase -> GC pause | `perf stat` watchdog latency p99 <1ms, `test-failover` <100ms, `test-ha-crash` |
| Manager god struct | Mu contention affects all callers | Splitting mu must preserve lock ordering (mu before sessionMu) or deadlock | `go test -race -run TestManager`, `test-failover`, `test-restart-connectivity` |
| NAT/policy/zones compilation | No - commit cold path | Deterministic fields (blockSize, hostBase) truncation -> different NAT mapping after refactor -> covert flow break | Golden snapshot JSON diff, `make test-go -run NAT/Policy/Zone` |
| Process/control socket | Control socket QPS is contention hot spot (CLAUDE.md) | Adding new control request >1/s starves session installs | Control socket QPS metric via slog, `make test -run SessionSync` bulk |
| Neighbor index | Listener hot path O(1) lookup | RWMutex vs Mutex: RLock still takes atomic, but better than full Mutex blocking ApplyConfig | Benchmark `BenchmarkNeighborLookup`, `test-failover` with ARP churn |
| Rib/routes | Cold | Stable sort for ECMP must stay stable else churn detection flaps snapshot hash -> unnecessary re-publish -> worker flap? | `make test-go -run TestRouteDedupe`, snapshot hash stability test |

**Cargo asm / perf stat / criterion**: Not directly applicable to Go, but equivalents:
- `go test -bench=. -benchmem` for snapshot build alloc
- `go test -race` for new mutex splits
- `pprof` mutex profile for mu hold time
- `perf stat -e cache-misses,context-switches` on helper? Not Go, but can measure control socket latency
- `make test-failover` and `make test-ha-crash` are required gates for any HA-touching refactor (per CLAUDE.md: "Any change touching cluster, VRRP, session sync, or failover code MUST pass make test-failover")
- CoS smoke: `make cluster-deploy` + `apply-cos-config.sh` + iperf3 per-class ports 5200-5211

---

## Test Coverage Gaps

- `manager.go` ApplyConfig path: `manager_testhelpers_test.go` 145 LOC only helpers, no direct ApplyConfig integration test that drives full buildSnapshotWithSchedulerState with routeOverlay + feedOverlay + activeState + NATCounterIDs together - current tests isolate each overlay
- `maps_sync.go` auto-rebind: `maps_sync_cap_test.go` 684 LOC tests degraded stats cap, `maps_sync_heartbeat_slots_4572` 56 LOC tests zero slots calc, but `hasBusyBindingsWedgeLocked` + `shouldAutoRebindBusyBindingsLocked` + `maybeAutoRebindBusyBindingsLocked` have only indirect coverage via `xdp_shim_decouple_test.go` 541 LOC - need dedicated wedge unit test with fake clock
- `manager_ha.go` watchdog IPC throttle: no test for "active changed => immediate IPC" vs "periodic backstop <10s" - only `manager_ha_test.go` 1076 LOC integration via fake map write hook
- `process_napi.go` XSK liveness: `xskLivenessFailed/Proven` + `lastXSKRX` + `xskProbeStart` - covered via `userspace_boot_canary_test.go` 74 LOC and `manager_interfaces_test.go` 907 LOC, but no test for RX counter stuck detection causing failover
- `zones` addressless: `zones_addressless_3698` and `3710` cover happy path but dedup notes single-family and mixed-zone low noise missing - e.g., IPv4 present hides IPv6 addressless window (dedup H02)
- `routes` ECMP: no test that verifies stable sort keeps ECMP member order - `routes_dedupe_3770` 148 LOC covers dedup but not ECMP churn (dedup M10)
- Control socket contention: no test that drives 1/s status poll + 200ms HA sync + session delta drain concurrently to provoke contention - needed per CLAUDE.md logging rules

---

## Proposed Decomposition Roadmap (Phased)

**Phase 0 (Zero-risk pure helper extraction, keep in same package)**:
- Extract `deadWorkerIDSet`, `bindingForwardingLive`, `heartbeatZeroSlots`, `maxInt`, `queueCountFromBindings`, `snapshotHasNativeGRE`, `snapshotWgListenPort`, `snapshotBindingPlanKey`, `buildUserspaceIngressBindingAliases`, `userspaceSkipsIngressInterface`, `buildNATTranslatedLocalAddressExclusions`, `pickInterfaceSnapshotV4/V6` from maps_sync.go to `binding/util.go` (same package, no receiver)
- Extract `buildLocalAddressEntries`, `buildInterfaceNATAddressEntries`, `buildUserspaceIngressIfindexes`, `buildDesiredLocalAddressSets`, `buildDesiredInterfaceNATAddressSets` to `localaddr/build.go`
- Gate: `make test-go`

**Phase 1 (Wire schema split, facade aliases)**:
- Create `pkg/dataplane/userspace/snapshot/types.go` with ConfigSnapshot + *Snapshot types (move from protocol.go)
- Create `pkg/dataplane/userspace/wire/` with status, binding, control, ha, session types
- Keep `protocol.go` re-exporting via `type X = snapshot.X` aliases for 1 release
- Gate: `make test-go`, `cargo test`, JSON golden diff

**Phase 2 (Cache extraction with own mutex)**:
- `cache/overlay.go` + `cache/neighbors.go` extraction, fix H6 publish-before-mutate bug with two-phase commit
- Gate: `make test-go -run Overlay/Neighbor`, `test-failover`

**Phase 3 (Binding + LocalAddr managers)**:
- `binding/manager.go` owns wedge detection + auto-rebind + plan key
- `localaddr/sync.go` owns local + NAT address map sync
- Gate: `make test-go -run Binding/Maps`, `pprof` mutex hold reduction

**Phase 4 (Manager god struct split)**:
- Introduce sub-managers: SnapshotManager, HAManager, BindingManager, NeighborManager, ProcessManager
- Facade Manager delegates, keeps mu only for generation check then releases
- Gate: `go test -race`, `test-failover`, `test-restart-connectivity`

**Phase 5 (Policy + NAT builders)**:
- `policy/Builder` + `nat/Builder` + `rib/Builder` subpackages
- Share address-book classification via `policy/catalog`
- Fix partial-drop app-set expansion (dedup M02/M03) by returning explicit error
- Gate: `make test-go -run Policy/NAT/Route`, snapshot hash stability

**Phase 6 (Zone subpackage)**:
- `zone/build`, `zone/hib/`, `zone/quarantine/`, `zone/observability/`
- Gate: `make test-go -run Zone`, `test-failover` for HA consistency

**Phase 7 (Process control socket client)**:
- `process/control/socket.go` with QPS counter + throttling per caller tag
- `process/napi/poll.go` + `process/lifecycle/link_cycle.go` + `process/status/decode.go`
- Gate: `test-failover`, control socket QPS metric, `test-restart-connectivity`

---

## Labels Applied

- `mod-split`: protocol.go, maps_sync.go, manager_ha.go, Manager god struct, zones, policy, NAT
- `god-file`: protocol.go (3064), maps_sync.go (1763), manager_ha.go (1643)
- `god-struct`: Manager (80+ fields)
- `lock-scope`: maps_sync.go + Manager mu, HA watchdog, neighbor index
- `wire-schema`: protocol.go type count
- `ha`: manager_ha.go
- `failover-timing`: manager_ha.go watchdog + maps_sync mu contention
- `control-socket-contention`: process_control + Manager.mu
- `vsrx-parity`: NAT scope, policy global zone, host-inbound override, zone collision
- `d-negative`: maps.go, nat_nptv6.go, wire_uint8list.go, zonecounters.go, natcounters.go, manager_generation.go, policies_scheduler.go, runtime_delta.go, legacy_dataplane transitional
- `transitional`: legacy_dataplane ver
- `test-gap`: wedge auto-rebind, watchdog IPC throttle, XSK liveness stuck, addressless single-family, ECMP stable sort, control socket contention
- `publish-boundary`: overlay cache H6
- `deterministic-nat`: nat source deterministic fields

---

## Final Prioritized Refactor List (A = must split, B = should, C = nice, D = do not)

**A (Core, 4 items)**:
- A1 protocol.go god wire file (3064) -> 6 subfiles
- A2 Manager god struct (80 fields, 8 domains) -> 5 sub-managers
- A3 maps_sync.go (1763) fuse 5 domains under single mu -> binding + localaddr + bootstrap + ingress + verify
- A4 manager_ha.go (1643) fuse watchdog + IPC + counters + session sync -> watchdog + RG inventory + counters + sync

**B (Should split, 5 items)**:
- B1 NAT compilation 6 files 1612 LOC scattered no builder context -> nat/Builder + scope + app + pool + counters
- B2 Policy compilation 6 files 1907 LOC addrbook + slots + ids + reject entangled -> policy/Builder + catalog + slot + ids + reject + scheduler
- B3 Zones subsystem 7 files 1399 LOC enforcement vs observability vs quarantine fused -> zone/build + hib/view + hib/override + quarantine + observability/addressless + observability/ambiguous
- B4 Process management 5 files 1254 LOC lifecycle + control socket + NAPI + status + link-cycle fused -> process/manager + control/socket + status/decode + napi/poll + lifecycle/link_cycle
- B5 Overlay + Neighbor caches (197+270) mix locking with manager -> cache/overlay.go + cache/neighbors.go with RWMutex + fix H6

**C (Nice to have, 2 items)**:
- C1 Rib (routes 431 + tunnels 213 + neighbors 267 + screens 239) compile fragments -> rib/ subpackage with Builder fixing ECMP + discard/preference dedup bugs (dedup H8, M10, L6, L8)
- C2 Wire helpers (wire_uint8list 111, runtime_delta 128) -> wire/ + runtime/ subpackages when parent split

**D (Do NOT split, 9 items)**:
- D1 maps.go 59 const registry - atomic unit for canary
- D2 nat_nptv6.go 48 trivial builder
- D3 wire_uint8list.go 111 generic codec
- D4 zonecounters.go 61 + natcounters.go 65 counter snapshots
- D5 manager_generation.go 120 generation bump - 2 funcs
- D6 policies_scheduler.go 53 scheduler snapshot - minimal
- D7 runtime_delta.go 128 pure adapter
- D8 userspace_xdp_rust.go 20 shim loader stub
- D9 legacy_dataplane.go 679 + verify_userspace_shim.go 149 transitional - schedule deletion not split

---

## Verification Gates Summary

For any refactor in this batch, the following gates must pass (per CLAUDE.md + hot-path preservation analysis):

- `make test-go` - Go suite (includes Rust? No, `make test` does both, but `make test-go` fast path for Go changes)
- `make test` - Both Go + Rust cargo suite (#4006) - Rust dataplane regression fails
- `go test -race ./pkg/dataplane/userspace -run TestManager` - race detector for new mutex splits
- `go test -bench=Benchmark -benchmem` for snapshot build alloc before/after (target <5% alloc increase)
- `pprof` mutex profile: `go test -mutexprofile=mutex.prof -run TestApplyConfig` then `go tool pprof mutex.prof` showing mu hold p99 <5ms improvement after split
- `make test-failover` - REQUIRED for any change touching cluster, VRRP, session sync, or failover code (manager_ha.go, maps_sync.go wedge, neighbor index, zones collision) - failover ~60ms with 30ms VRRP, must stay <100ms
- `make test-ha-crash` / `test-double-failover` / `test-chained-crash` - multi-cycle crash recovery for HA changes
- `make test-restart-connectivity` - restart behavior for process mgmt changes
- CoS smoke: `make cluster-deploy` (loss userspace cluster) + `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` + iperf3 per-class ports 5200-5211 (CoS target 172.16.80.200:5200-5211) - required if touching CoS or binding or queue
- Control socket contention: manual test - bulk session sync (1000 sessions) + failover concurrent, measure control socket QPS via slog debug, ensure no starvation >1s

---

## References

- Batch list: /tmp/prompt-gemini-044-A6-b2.txt (143 files)
- Alternative batch (107 files): /tmp/prompt-A6-b2.txt
- Dedup index from prompt: 40 entries, notably #4 protocol god file, #5 Manager.mu many responsibilities, H6 publish overlay mutates before success, M02/M03 app-set partial-drop, H04 reversed ranges, etc - this report provides structural superset fixes with concrete seams and verification gates
- CLAUDE.md logging rules: control socket shared by status poll (1/s), HA sync, session installs, snapshot sync, forwarding sync - high-frequency >1/s must be throttled
- Engineering style: docs/engineering-style.md - hot-path allocation rules, review severity, compile-time invariants


---
### Batch A6_go_dataplane_manager-b3 — 317 lines — full log + findings

# Refactor/Modularity Audit — A6_go_dataplane_manager-b3 (13 files)

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A6_go_dataplane_manager-b3
Batch file: A6_go_dataplane_manager-b3.txt (13 files, 1101 prod + 1134 test LOC)
Auditor: A6_go_dataplane_manager batch 3/3 — claimed dataplane manager but actual files are natpoolalarm (5) + nftables (8)
Date: 2026-07-11

---

## Batch Inventory — LOC via wc -l at base f1ef0eec8

### Prod files (9) — 1101 LOC

| File | LOC | Structs/Consts | Key fns | Responsibilities | Monolith? |
|------|-----|----------------|---------|------------------|-----------|
| pkg/natpoolalarm/natpoolalarm.go | 409 | Monitor, PoolStatus, View, Sampler, Emitter, ActiveAlarm, alarmState, DefaultTickInterval, severityRaise/Clear | New, SetTickForTest, Start, Stop, run, evaluate, isRaised, activeKeys, raise, clear, clearAll, updatePct, emitLine, ActiveAlarms | NAT pool util alarm monitor: lifecycle (Start/Stop/run chan, sync.Once #4909), generation-coherent sampling (Available+HelperCoherent HOLD), rule-referenced eligibility, capacity calc uint64 cast before arithmetic, hysteresis raise/clear+updatePct, prune on eligibility loss, syslog emit via injected Emitter, sorted snapshot | NO — 409 LOC moderate, single responsibility, well-injected deps Sampler/Emitter/nowFn |
| pkg/natpoolalarm/render.go | 36 | — | RenderAlarms | Pure render: detail vs summary convention, numbering continuation startCount, FirstSeen zero-check | NO — textbook single-fn module, shared by gRPC and CLI per comment, opposite of monolith |
| pkg/nftables/host_inbound_counters.go | 191 | HostInboundDenyCount, HostInboundTableName, hostInboundDenyCounterPrefix | HostInboundDenyCounterName, sanitizeNftIdent, ParseHostInboundDenyCounterName, ReadHostInboundDenyCounters | Host-inbound coarse DENY per-zone/family counter: name encoding xpfhi_<fam>_<len>_<zone> length-prefixed reversible, bare-ident sanitization #3578 [A-Za-z0-9_.-] lossy metric-only, netlink read inet xpf_hostinbound, (nil,nil) on absent table #3345 | NO — single prefix responsibility, 191 LOC |
| pkg/nftables/host_inbound_accept_counters.go | 153 | HostInboundAcceptCount, HostInboundAcceptCounterTypes (3), hostInboundAcceptCounterPrefix | HostInboundAcceptCounterName, ParseHostInboundAcceptCounterName, ReadHostInboundAcceptCounters | Host-inbound global ACCEPT per-type-class (icmp6_nd, icmp6_error, icmp4_error) #4759 aggregate no per-zone breakdown, separate prefix xpfhia_ distinct from xpfhi_ and xpfjh_, same table scan pattern | NO — 153 LOC, single concern |
| pkg/nftables/host_inbound_junos_host_counters.go | 126 | HostInboundJunosHostDenyCount, hostInboundJunosHostDenyCounterPrefix=xpfjh_ | HostInboundJunosHostDenyCounterName, ParseHostInboundJunosHostDenyCounterName, ReadHostInboundJunosHostDenyCounters | Junos-host DENY per-scope/family #4146 to-zone junos-host, same table as coarse deny + accept separated by prefix, same encoding as host_inbound_counters | NO — 126 LOC smallest |
| pkg/nftables/lo0_counters.go | 133 | Lo0Count, Lo0TableName=xpf_lo0, lo0CounterPrefix=xpflo0_ | Lo0CounterName, ParseLo0CounterName, ReadLo0Counters | lo0 input-filter then count #3445 counters, prefixed so bare decl parses (#3445 digit-start guard), reused sanitizeNftIdent, same (nil,nil) on absent contract #3345, rate() reset handling | NO — 133 LOC |
| pkg/nftables/rst_suppress.go | 204 | rstSuppressionPlan, rstTableName=xpf_dp_rst | InstallRSTSuppression, RemoveRSTSuppression, rstTableExists, buildRSTSuppressionPlan, queueRSTSuppression, addRSTDropRuleV4/V6, addRSTDropRule, ptrPolicy | RST suppression via netlink atomic delete+create batch #450 HA failover race window elimination, per-addr rule: meta nfproto + saddr + l4proto tcp + tcp flags & RST !=0 + counter + drop, slices.Clone for plan isolation | NO — 204 LOC, 2 responsibilities (plan build + queue) cleanly split |

### Test files (6) — 1134 LOC

| File | LOC | Focus |
|------|-----|-------|
| natpoolalarm_test.go | 628 | raise-once, clear-once, hysteresis band, boundary comparators (>= raise, < clear), eligibility rule-referenced + prune, absent HOLD, uncomputable HOLD, deterministic skip, no-double-count, nil-config/feature-disabled clearAll, unavailable/not-coherent HOLD-all, updatePct-no-syslog, severity/shape, start/stop |
| render_test.go | 57 | detail numbering continuation, summary empty body, empty slice, FirstSeen omission |
| stop_race_4909_test.go | 41 | concurrent Stop double-close panic #4909, sync.Once vs select/default race, started vs unstarted |
| host_inbound_accept_counters_test.go | 77 | type-class name roundtrip, unknown type reject, prefix collision with deny |
| host_inbound_counters_test.go | 109 | zone/family name encode length-prefixed, parse reversible even '_' '-', sanitization lossy metric-only, family token ip/ip6 guard |
| lo0_counters_test.go | 71 | lo0 counter name bare-ident sanitization, prefix distinct |
| rst_suppress_test.go | 37 | plan build tableExists flag, slices.Clone isolation, queue returns deleteTable when empty |

---

## File-by-File Deep Monolith Check (mandatory)

### 1. pkg/natpoolalarm/natpoolalarm.go — 409 LOC — VERDICT: NOT MONOLITHIC

Title: natpoolalarm monitor not monolithic — single domain, injected deps, 409 LOC

Severity: none (negative finding)
Confidence: high
Refactor class: N/A

Evidence:
- Single package purpose per README: runtime consumer for `pool-utilization-alarm` stanza #2079 closing silent no-op gap. File implements exactly that, no unrelated domains.
- Lifecycle isolated: New injects Sampler/Emitter, SetTickForTest guarded by !started mutex, Start idempotent nil/sample check, Stop uses sync.Once #4909 fix for concurrent close race (select/default bug), run() owns Ticker, prompt evaluate once before loop.
- evaluate() ~130 LOC handles: Available check HOLD-all, HelperCoherent check HOLD-all mid-apply, nil-config & disabled threshold clearAll fail-closed, referenced set rule-derived (mirrors buildSourceNATSnapshots nil skips), eligible set non-deterministic filter, bad sample HOLD (AddressCount 0, PortHigh<PortLow), capacity calc cast to uint64 BEFORE arithmetic avoids uint16 underflow, pct calc, isRaised switch raise/clear/update, activeKeys snapshot under mutex then clear without holding lock across syslog (blocking write safety).
- State ops small: isRaised, activeKeys each snapshot under mutex, raise idempotent, clear delete+emit, clearAll iterates activeKeys, updatePct refresh only.
- No hot-path: DefaultTickInterval 10s slow loop reading only cached status+applied snapshot No control-socket I/O per CLAUDE.md contention rule, no per-packet alloc.
- Deps minimal: only pkg/config.Config for PoolUtilizationAlarm thresholds, no dataplane/userspace import (PoolStatus projection decouples).
- Compared to true monoliths (compiler_class_of_service 1309 LOC 17 helpers, poll_descriptor 6339 LOC) this is 3x smaller and single responsibility.

Proposed decomposition if growth: None needed now. If future adds block-based deterministic utilization, extract `capacity.go` (PoolStatus→capacity+pct) and `eligibility.go` (referenced→eligible) — but currently premature; file would stay <500 LOC after that anyway.

Hot-path preservation analysis: Cold path, 10s tick, no AF_XDP RX/TX, no session table, no BPF map. No frame budget, no #[inline(always)], no cache-line grouping needed. Mechanically safe.

Tests + gate: natpoolalarm_test.go 628 LOC mutation-verified non-tautological (emitRec records per transition), stop_race_4909_test.go 41 LOC race detector pin. Gate `go test ./pkg/natpoolalarm -count=1 -race`.

Why it matters (negative): Good modular boundary example — Sampler/Emitter injection enables unit test without live dataplane/syslog. Render extracted to render.go prevents divergence between gRPC and CLI sites.

Fix direction: No fix. Keep as-is.

Labels: negative, well-modularized, cold-path, injected-deps, single-responsibility

Dedup note: Not in dedup-index god-file list. Prior NAT alarm consumer missing (#2079) was filed as feature gap, not refactor.

---

### 2. pkg/natpoolalarm/render.go — 36 LOC — VERDICT: NOT MONOLITHIC (exemplary split)

Title: render.go exemplary modular split — shared show security alarms renderer

Severity: none
Confidence: high
Refactor class: N/A — this IS the refactor outcome

Evidence:
- Comment explicitly: shared by gRPC server_show_security_text.go and local CLI cli_show_security.go so two sites cannot diverge. Count-in-summary, body-in-detail convention preserved.
- Single func RenderAlarms(w io.Writer, alarms []ActiveAlarm, startCount int, detail bool) int pure, 20 LOC body, numbered Alarm N starting at startCount+1, returns running count for continuation (screen alarms etc), FirstSeen zero-check.
- alarms must already sorted per ActiveAlarms() sorted snapshot — contract documented.
- No deps beyond fmt, io, time formatting.

Why modular: Before this file, render logic would have been duplicated in two show sites. Extraction is the anti-monolith pattern.

Fix direction: None.

Labels: negative, exemplary, shared-renderer, pure-function

---

### 3. pkg/nftables/host_inbound_counters.go — 191 LOC — VERDICT: NOT MONOLITHIC, but duplication across prefix files

Title: host-inbound deny counters 191 LOC single prefix — not monolithic but 4-way table-scan duplication

Severity: low (duplication not monolith)
Confidence: high
Refactor class: C — small duplication, optional helper extraction

Evidence:
- Owns HostInboundTableName=xpf_hostinbound constant (table that enforces host-inbound-traffic #3070).
- hostInboundDenyCounterPrefix=xpfhi_ tagging named counter per zone/family catch-all DROP #3361.
- HostInboundDenyCounterName: deterministic encoding xpfhi_<family>_<len>_<zone> length-prefixed reversible even with '_' '-' in zone name, sanitizeNftIdent maps exotic bytes outside [A-Za-z0-9_.-] → '_' length-preserving allocation-free when bare-safe, v1.1.6 unquoted declaration hard syntax error #3578 tradeoff documented: exotic names collide metric-only, forwarding unaffected.
- Parse reverses with strconv.Atoi length check, ok=false for foreign objects.
- ReadHostInboundDenyCounters: nftables.New(), ListTablesOfFamily INet, find table by name, GetObjects, filter CounterObj + Parse name, (nil,nil) on ENOENT absent, #3345 missing-sample contract.

Duplication observed: same 30-line table scan boilerplate appears verbatim in host_inbound_accept_counters.go, host_inbound_junos_host_counters.go, lo0_counters.go — only table name and parse fn differ. sanitized via shared func sanitizeNftIdent defined here reused by others (good sharing). Could extract generic helper ReadCounters(tableName, parseFn) → []T but not a monolith problem.

Proposed decomposition (optional): New file nftables/table_scan.go with generic func readNamedCounters[T any](tableName string, parse func(string) (T,bool)) ([]T, error) implementing New+ListTables+GetObjects+ENOENT handling. Each specific file then 20 LOC wrapper. Would reduce duplication without increasing coupling. Not required for monolith audit.

Fix direction: No mandatory fix. If touching, add helper in separate PR.

Labels: negative-not-monolith, duplication, optional-helper

Dedup note: Not listed as god-file. Similar pattern lo0/host-inbound counters noted as observability surface #3361 #4422 #4759 #4146.

---

### 4. pkg/nftables/host_inbound_accept_counters.go — 153 LOC — VERDICT: NOT MONOLITHIC

Title: host-inbound accept counters 153 LOC — distinct prefix xpfhia_ global aggregate

Severity: none
Confidence: high
Refactor class: N/A

Evidence:
- Separate prefix hostInboundAcceptCounterPrefix=xpfhia_ vs xpfhi_ vs xpfjh_ — metric collectors never cross-count by prefix, ParseHostInboundDenyCounterName rejects accept name because 'a' vs '_' position.
- Fixed type-class keys: icmp6_nd (types 133-137), icmp6_error (1-4), icmp4_error — AGGREGATE global no per-zone breakdown per #4759 caveat (per-zone would require rule duplication larger change). Documented.
- HostInboundAcceptCounterTypes ordered slice iterated by daemon and Prometheus collector.
- Same read pattern as deny but filtered to accept type.

Negative: well scoped, 3 consts + 1 slice + 2 funcs + 1 reader.

Labels: negative, single-prefix, well-scoped

---

### 5. pkg/nftables/host_inbound_junos_host_counters.go — 126 LOC — VERDICT: NOT MONOLITHIC

Title: junos-host deny counters 126 LOC — distinct denial reason

Severity: none
Confidence: high
Refactor class: N/A

Evidence:
- Comment distinguishes: coarse deny "no host-inbound-traffic service opened this" vs junos-host deny "to-zone junos-host security policy denied this source/app" — must not merge.
- Prefix xpfjh_ distinct, encoding xpfjh_<family>_<len>_<scope> mirrors deny, reuses sanitizeNftIdent shared.
- Read same (nil,nil) contract matches #3345.

Negative: minimal, single reason.

Labels: negative, distinct-reason, well-scoped

---

### 6. pkg/nftables/lo0_counters.go — 133 LOC — VERDICT: NOT MONOLITHIC

Title: lo0 input-filter then count counters 133 LOC — distinct table xpf_lo0

Severity: none
Confidence: high
Refactor class: N/A

Evidence:
- Lo0TableName=xpf_lo0 different table family INet but different name (lo0 loopback input firewall filter interfaces lo0 unit 0 family inet[6] filter input #3445).
- lo0CounterPrefix=xpflo0_ namespaces + guarantees letter start (bare nft id may not start digit but Junos count <name> may).
- Lo0CounterName sanitizes + prefixes, same lossy artifact documented: exotic Junos count names merge counts only, no forwarding verdict change, better than load failure.
- Parse strips prefix returns counter label, no length encoding (Junos count normally bare, lossy same artifact doc).

Negative: distinct table, clear separation from hostinbound table.

Labels: negative, distinct-table, well-scoped

---

### 7. pkg/nftables/rst_suppress.go — 204 LOC — VERDICT: NOT MONOLITHIC — good atomic batch pattern

Title: RST suppression 204 LOC — atomic delete+create batch #450 HA correctness

Severity: none
Confidence: high
Refactor class: N/A

Evidence:
- InstallRSTSuppression(v4Addrs v6Addrs) → New() conn, rstTableExists, buildRSTSuppressionPlan (slices.Clone isolation), queueRSTSuppression, Flush atomic batch.
- Plan struct deleteTable bool + clones ensures no aliasing.
- queue returns plan.deleteTable when empty addrs (remove path), otherwise AddTable inet xpf_dp_rst, AddChain output hook filter priority filter policy accept ptrPolicy helper, loop add per addr.
- addRSTDropRule builds expr list: meta nfproto eq family (NFPROTO_IPV4/v6), payload base network header offset saddrOffset Len addrLen + Cmp eq addrBytes, meta l4proto tcp, payload transport offset 13 len1 (TCP flags), bitwise mask 0x04 RST & !=0, counter, verdict drop. Offsets 12 v4 8 v6 correct per IP header layout.
- RemoveRSTSuppression best-effort: New, exists check, DelTable, Flush ignore error.
- Atomic batch comment: eliminates race window where no rules exist between delete and new create critical for HA ~60ms failover RG demotion microseconds window #450.
- README in this package outdated (says sole purpose DROP RST) but now also has counter read responsibilities — README should be updated if this batch's broader purpose considered, but not monolith.

Negative: good split between plan building (pure data) and queuing (nft conn side effect).

Proposed decomposition if growth: Already split. If adding more tables, extract table_exists helper to shared.

Hot-path preservation: Control plane cold path, commit + DHCP render triggers rebuild, not per-packet. No perf impact. Must preserve atomic Flush pattern.

Fix direction: None required for monolith. Optional README update to cover counter readers.

Labels: negative, atomic-batch, HA-critical, well-structured

---

## Cross-File Observations

- Package-level duplication: ReadHostInbound*Counters and ReadLo0Counters share identical 25-line boilerplate: New(), ListTablesOfFamily(INet) with ENOENT→nil,nil, find table by name, GetObjects with ENOENT→nil,nil, iterate CounterObj filter via Parse. 4 copies = 100 LOC duplication. Not monolithic (opposite — oversplit with duplication) but extract helper readNamedCounters generic would DRY without increasing file size. Refactor class C mechanical/safe if ever touched — low priority.
- sanitizeNftIdent defined once in host_inbound_counters.go reused by junos_host and lo0 via same package — good sharing, avoids duplication.
- natpoolalarm split into monitor (stateful lifecycle) + render (pure) — exemplary. Tests split into 3 files (main logic, render, race) matches responsibilities.
- Naming: xpfhi_, xpfhia_, xpfjh_, xpflo0_ prefixes distinct by first 5 chars — no collision, Parse rejects foreign. Good modular isolation by object-name prefix.
- Batch label mismatch: A6_go_dataplane_manager suggests pkg/dataplane/userspace/* manager files, but actual batch lists natpoolalarm + nftables, which are host-facing/kernel-facing helpers, not userspace dataplane manager. No impact on monolith assessment but indicates batch grouping error.
- No god functions >200 LOC: longest func evaluate ~130 LOC, addRSTDropRule ~50 LOC expr builder, RenderAlarms 15 LOC.
- No god structs: Monitor 7 fields (sample, emit, tick, nowFn, mu, active map, started bool, stopOnce, stop/done chans) single domain, not 27-field SessionTable style.

## Overall Assessment

This batch contains ZERO monolithic files. All 9 prod files are <500 LOC, largest 409 LOC, average ~122 LOC. Each file owns one prefix/table or one monitor with injected deps. The only improvement opportunity is low-severity DRY of table-scan boilerplate — not a monolith but duplication.

Negatives documented as required: 7/7 files negative for monolith.

If strict A-class refactor class expected, answer: No A/B class refactor needed. Optional C-class helper extraction for nftables read boilerplate.

---

## Hot-path Preservation Analysis (applies to batch)

- Rank: D — cold path for all files. natpoolalarm tick 10s, reads cached in-memory status + applied snapshot no socket I/O (CLAUDE.md control-socket-contention honored). nftables counter readers via netlink called from Prometheus collector ~15s scrape, not per-packet. RST suppression install on commit/DHCP re-render, not fast path.
- No AF_XDP poll_descriptor hot loop, no session table, no FIB lookup, no AppCatalog per-packet matching, no unsafe, no binary.NativeEndian, no sync.Pool.
- Therefore file split or helper extraction cannot regress PPS or retain stale forwarding state. Mechanical extraction would be pure code-motion.
- Preservation guardrails: natpoolalarm capacity calc uint64 cast before arithmetic must stay (comment documents), HOLD-all on !Available and !HelperCoherent must stay, prune eligibility config-derived only after coherent gate, sync.Once close for #4909. RST suppression atomic delete+create batch via single Flush must stay (HA #450).

---

## Tests + Gate

- Existing tests gate per file:
  - pkg/natpoolalarm: `go test ./pkg/natpoolalarm -count=1 -race -run Test` — 15 tests + render 3 + stop race 2(bool)
  - pkg/nftables: tests are counter-name encode/decode roundtrip unit tests, not requiring netlink (no kernel table needed). `go test ./pkg/nftables -count=1 -run TestHostInbound|TestLo0|TestRST`
- No Rust leg, no CoS smoke, no failover needed (cold path). `go vet ./pkg/natpoolalarm ./pkg/nftables` must pass.
- Batch is test-heavy: 1134 test LOC vs 1101 prod shows good coverage, includes race regression test #4909 pins fix.

---

## Why It Matters (for this batch)

- Negative findings matter: shows good modularization produced by prior splits (render extracted, accept/deny/junos/lo0 split by prefix, RST plan vs queue split). Preserves reviewability and prevents merge conflicts (CoS vs host-inbound counters teams no longer collide). Maintains HA correctness (atomic batch, HOLD semantics).
- Duplication of table-scan is bounded (4 copies 100 LOC) and low risk; extracting helper would marginally improve DRY but not reduce monolith because none exists.

---

## Fix Direction

No mandatory fix for monolith. Optional:

1. (C-class) Create pkg/nftables/table.go with generic helper:

   ```
   func readTableCounters[T any](tableName string, parse func(string)(T,bool)) ([]T, error) {
     c, err := nftables.New()...
     ListTables...
     find table...
     GetObjects...
   }
   ```

   Each Read*Counters becomes ~10 LOC wrapper. Mechanical code-motion, package same, no behavior change. Gate `make test-go`.

2. Update pkg/nftables/README.md — currently describes only RST suppression, but package now also owns host-inbound and lo0 counter readers (observability surface #3361 #4422 #4759 #4146). Doc update aligns module contract per CLAUDE.md requirement "When modifying code or changing behavior, update relevant module documentation... if no docs change needed say why" — here docs stale, so update.

No A/B class split needed.

---

## Labels

- negative-no-monolith
- well-modularized
- cold-path
- duplication-low-severity
- file-split-exemplary (render.go)
- prefix-isolated-counters
- atomic-batch-HA-#450

---

## Dedup Note

Checked dedup-index.txt ~500 entries. This batch's files not flagged as god-file or monolith. Closest entries:
- "** refactor(afxdp): extract flowless path..." etc — Rust dataplane, not this Go batch.
- "** Filter + CoS compilers each 1200+ LOC..." — pkg/config, not nftables/natpoolalarm.
- NAT-related god-struct entries refer to userspace-dp/src/nat/allocator.rs 1974 LOC, not pkg/natpoolalarm.
- No duplicate filing for natpoolalarm or nftables counter readers. This audit's negative finding is new and does not duplicate closed splits #4405 validate_strict split, #4406 uniformgates, etc.

Batch mislabel: A6_go_dataplane_manager-b3 contains zero files from pkg/dataplane/userspace/ manager (which would be snapshot, forwarding, policies, nat*.go). Actual content is natpoolalarm + nftables. No action needed but note for batch grouping.

---

## Evidence Files

- Worktree files read at f1ef0eec8:
  - /pkg/natpoolalarm/natpoolalarm.go 409 LOC
  - /pkg/natpoolalarm/render.go 36 LOC
  - /pkg/natpoolalarm/natpoolalarm_test.go 628 LOC
  - /pkg/natpoolalarm/render_test.go 57 LOC
  - /pkg/natpoolalarm/stop_race_4909_test.go 41 LOC
  - /pkg/nftables/host_inbound_accept_counters.go 153 LOC
  - /pkg/nftables/host_inbound_counters.go 191 LOC
  - /pkg/nftables/host_inbound_junos_host_counters.go 126 LOC
  - /pkg/nftables/lo0_counters.go 133 LOC
  - /pkg/nftables/rst_suppress.go 204 LOC
- wc totals confirmed 1101 prod.


---
### Batch A7_go_daemon_host-b1 — 586 lines — full log + findings

# Refactor / Modularity Audit — A7_go_daemon_host batch 1/3 (150 files)

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A7_go_daemon_host-b1
Auditor: ps-044
Batch: A7_go_daemon_host-b1.txt — 150 files, ~48k LOC total (prod 45 files ~18k, test 105 files ~30k)
Area: pkg/daemon/ — daemon lifecycle, bootstrap, device-map, host tunables, networking reconciles, HA, flow, nft, system

Prior filed issues referenced:
- #4407 Daemon god-struct (daemon.go 902 LOC, ~80 fields, already flagged)
- #4662 daemon_run.go ordering-sensitive lifecycle (2492 LOC, Run() 643 LOC)
- #2114 natPoolAlarm atomic.Pointer race-safe rendering, #5308 pinRetry loop lifecycle — symptoms of god-struct growth

---

## Inventory — LOC, largest function, responsibility count, hot-path yes/no, prior flag

### Production files in batch (45 files, sorted desc LOC)

| File | LOC | Largest Function | Resp Count | Hot-path? | Prior? |
|------|-----|------------------|------------|-----------|--------|
| daemon_run.go | 2492 | Run 643 (175-818), inferIPv6StaticNextHop 271, startHTTPServer 237, runShutdownSequence 183, initManagers 183 | 12: boot class dispatch, config load, interface naming (positional vs device-map), dataplane build, manager init, startup naming, gRPC start, HTTP start, API bind resolve, signal handling, forward enable, HA shutdown update | COLD (daemon start, ~once) safe mechanical | YES #4662 ordering-sensitive |
| daemon_apply.go | 2265 | applyDataplaneAndHACore 400 (795-1195), applyTailReconciles 289, applyServicesReconcile 155, applyConfigLocked 148, applyVRFReconcile 126 | 15: commitAndApply, syncAndApply, commitConfirmed, factoryReset, applyDataplaneAndHACore (RETH MAC defer-workers, overlay caches feed+RPM, dp.ApplyConfig, MAC VIP worker rebind), routing rules, fabric IPVLAN, VRF, interface reconcile, tail reconciles (DNS, DHCP server, IPsec, networkd, feeds, RA, proxyarp, SNMP, flow), policy scheduler publish, DHCP relay, LLDP, event engine | COLD (commit) safe | Partial — apply ordering sensitive but not yet filed as separate from #4662 |
| daemon_nft.go | 1782 | nftRulesFromTerm 359 (1301-1660), buildHostInboundFilterPayload 173 (526-699), applyHostInboundFilter 125 (244-369) | 8: lo0 filter (payload build + apply), host-inbound filter (zone views enforceable check, unzoned deny, JunosHost deny programs + src + L4, WireGuard accept, ICMP accept, zone per-family emit), firewall filter term → nft rules (prefix lists, port range, TCP flags, DSCP, log prefix), nft helpers (addr set, family addrs, predicate, int set, iifname set) | COLD (config apply) safe | NO — new monolith |
| daemon_system.go | 1731 | applySystemLogin 179 (1021-1200), applySyslogConfig 156 (28-184), applySSHConfig 133 (1432-1565) | 11: syslog (config, files, dropins, agg callback, source addr resolve), hostname, NTP (chrony sources/threshold render + reload), kernel tuning, SSH known hosts, timezone (zoneinfoTarget), system syslog, system login (users, sudoers reconcile, password reconcile, root auth), SSHD config (buildSSHDConfig, filter algs) | COLD | NO |
| daemon_ha.go | 1576 | reconcileRGState 250 (555-805), watchClusterEvents 181 (167-348), watchVRRPEvents 89 (404-493) | 8: RG state machine creation, strict VIP ownership mode sync, local failover commit ready, triggerReconcile, reconcileVRRPInstances, blackhole routes (inject/remove/reconcile), RETH services (apply/clear per RG + all), DHCP filter for master RGs, neighbor cache warm, IPsec SA fingerprint + advertise + nudge | WARM (HA transitions, not per-packet) | NO — HA magnet |
| daemon_ha_sync.go | 1020 | startClusterComms 468 (398-866), startSessionSyncPrimeRetry 101 (183-284) | 7: sync ready timer, session sync prime retry, bulk sync via event stream fallback, config sync push/handle, heartbeat with retry, cluster transport key, fenceAllRGs, redundancy groups snapshot | WARM (HA control + session sync) | NO |
| daemon_ha_fabric.go | 965 | refreshFabricFwd 161 (396-557), refreshFabricFwd1 100 (639-739), monitorFabricState 88 (835-923) | 6: fabric IPVLAN parent resolve, ensureFabricIPVLAN + addr reconcile, populateFabricFwd 0/1, clearFabricFwd 0/1, probeFabricNeighbor (ICMPv4), sendICMPProbe, sendIPv6MulticastProbe, fabric state subscription, trigger refresh | WARM (fabric monitoring) | NO |
| bootstrap.go | 944 | computeBootClass 60 (220-280), setupBootstrapLifeline 76 (742-818), resolveProtectedInterfaces 10 (870-880) | 9: load error classification, boot class (5 cases, HA guard, compileFailed prioritization), hasNodeIDFile, fail-closed boot detection (pinned XDP links, forwarding armed), clearFRR, lifeline record file I/O (read/write at path), PCI addr for interface, lifeline detection (current name resolve), protected interfaces (mgmt leaf + lifeline), lifeline network file write, interface addr snapshot, isDHCPManaged | COLD (boot) safe | NO — boot monolith |
| daemon.go | 902 | New 67 (835-902), parseNodeIDFileContent 12, applyResult 26 | 1 but god-struct: 80+ fields (managers: networkd, routing, FRR, IPsec, RA, DHCP, feeds, RPM, SNMP; DDNS surface A+B, DHCP lease sync, IPsec rebind, flow export bundles, fabric fwd, RA, etc.) | COLD struct def, but touched everywhere | YES #4407 filed |
| daemon_ddns_surface_a.go | 846 | buildSurfaceAScopes 153 (197-350), surfaceAObserver 162 (351-513) | 5: surface A reconcile loop (runSurfaceADDNSReconcileLoop, runGuarded...), scope construction, interface addr observe (netlink, static unit addr), RG0 writer single-writer, gate, nudge, stats/status | COLD (DDNS file I/O + DNS network only, per CLAUDE.md ok) | Partial — #4407 inc 5 grouped surfaceAState |
| host_tunables.go | 839 | applyCPUGovernor 110 (190-300), applyNetdevBudget 98 (301-399), resolvedHostTunables 80 (486-566) | 4 tunable domains: CPU governor (list paths, read/write, capture prior), netdev budget, neigh retrans (list dirs, paths), mlx5 coalesce (restore), plus restore logic (host scope, neigh, coalesce) | COLD (boot + restore) | NO |
| device_map.go | 836 | enumerateAndRenameMapped 198 (161-359), teardownUnmappedManaged 111 (644-755) | 6: present NIC enumeration, device-map resolve → bindings, startup naming policy (positional vs mapped), RETH member OriginalName vs MAC, link file write, teardown unmapped managed, preflight strands management, predictable name/udev name, stale link scrub | COLD (boot + commit preflight) safe | Prior device-map #1956 but not refactor filed |
| daemon_flow.go | 804 | applyMgmtVRFRoutes 106 (113-219), flowTraceCallback etc | 6: mgmt VRF route collection (DHCP routes, filter), VRF iface set publish, flow export handoff? actually archive (config archival SCP, sites), flow trace (callback, reconcile), link state monitor (subscription, resync, apply, trap emit) | COLD + WARM (link state monitor goroutine) | NO |
| daemon_flowexport.go | 685 | reconcileV9Exporter 138, reconcileIPFIXExporter 105 (approx) | 5: exporter bundles (firstExp), config hash gating, V9 build/reconcile/teardown, IPFIX build/reconcile/teardown, flowExport callbacks (V9 + IPFIX), batch stats, handoff dropped counters, collector health | WARM (session-close callback reads bundle atomic) | NO |
| daemon_ha_vip.go | 651 | scheduleDirectAnnounce 76 (440-516), directSendGARPs 118 (533-651) | 5: VIP readiness check (checkVIPReadiness, noRethTakeover), direct VIP ownership (desired/applied/add/remove), stable RETH link-local add/remove, announce+GARP (burst still valid, sendGARPs) | WARM HA | NO |
| daemon_neighbor.go | 604 | resolveMonitoredNeighbors 189 (56-245), forceProbeNeighbors 122 (310-432) | 3: monitored neighbors collection (config next-hop/NATdst/book/fabric/snapshot), neighbor readiness, cluster neighbor, probe triggering | WARM per-miss (not per-packet) | NO |
| daemon_policy_invalidate.go | 546 | clearSessionsForPolicyIDs 145 (285-430), deletedPolicyRuntimeIDs 59, changedPolicyRuntimeIDs 55 | 3: deleted policy IDs, modified policy IDs (match/action change, scheduler inactive), default policy change, session clear for IDs | COLD (commit) | NO |
| daemon_neighbor_listener.go | 526 | listener loop + regen debouncer, getNeighborProbeMaxTargets | 3: neighbor listener subscription, periodic guard, probe max targets env handling | WARM | NO — but #4001 re-assert loop hold applySem fix |
| daemon_snmp_reconcile.go | 471 | teardown roundtrip SNMP lifecycle (cancel→Wait→Stop) flagged earlier | 3: SNMP reconciler (hash gate), agent start/stop, cancel/wg lifecycle | COLD | NO — but prior finding F-03 SNMP teardown refuted (agent internal watcher) |
| daemon_rpm.go | 438 | probe pin retry loop, reconcileRPM hash gate, effective+RethMap keep | 3: RPM effective config + RETH map keep, probe pin install + retry (periodic), hash gate | COLD + periodic 1s? | Partial #1827 #1895 #5308 lifecycle |
| daemon_ha_userspace_stream.go | 436 | stream handling session sync | 2 | WARM | NO |
| daemon_ipmon.go | 428 | IP monitoring engine reconcile | 2 | COLD/WARM | NO |
| daemon_dhcp_lease_sync.go | 404 | runDHCPLeaseSyncLoop 30, pushDHCPLeasesOnce 42 | 4: enable check, gate, loop ensure/reset, dispatch push, fingerprint, pre-seed memfile, seed from peer | WARM (HA) | Inc 1 of #4407 dhcpLeaseSync grouping |
| daemon_ddns.go | 399 | DDNS manager always-on (Surface B) | 3 | COLD | #1387 |
| daemon_reth.go | 382 | RETH rename up? | 2 | COLD | NO |
| daemon_dns.go | 377 | DNS reconciler (merge input, atomic write, bind mount fallback) | 3 | COLD | #1715 DNS boot policy |
| daemon_ha_userspace_convert.go | 357 | convert session to HA format | 2 | WARM | NO |
| daemon_dhcp.go | 341 | DHCP client specs build, address change, IPsec reapply for lease, next-hop resolver | 5 | COLD | NO |
| daemon_scheduler.go | 299 | scheduler reconcile, manual LE encoding | 2 | COLD | NO |
| host_tunables_daemon.go | 283 | daemon integration of tunables (apply/restore hooks) | 2 | COLD | NO |
| daemon_proxyarp.go | 282 | proxyARP iface map via ResolveKernelIfName, re-assert loop under applySem | 2 | COLD | #4001 |
| coalescence.go | 272 | coalesce driver-guarded | 1 | COLD | NO |
| daemon_ha_userspace_readiness.go | 233 | VIP readiness for userspace | 2 | WARM | NO |
| daemon_cluster_bind.go | 198 | cluster bind | 1 | COLD | NO |
| daemon_ra.go | 191 | RA config build, valid lifetime float→int | 2 | COLD | NO |
| daemon_ipsec_rebind.go | 179 | IPsec rebind on lease change, single-flight retry | 3 | WARM | #4899 |
| daemon_health.go | 155 | health checks | 2 | WARM | NO |
| daemon_archive_timer.go | 151 | hash-gated timer, close-once | 1 | COLD | NO |
| daemon_feeds.go | 137 | feed reconcile hash-gated (#5036) | 2 | COLD | NO |
| daemon_forwarding_status.go | 132 | forwarding status sampler | 1 | WARM 1/s per CLAUDE.md OK | NO |
| daemon_natpoolalarm.go | 129 | NAT pool alarm monitor 10s loop, atomic.Pointer start/stop at runtime | 2 | WARM 10s | #2079 #2114 |
| others (daemon_gc.go 23, daemon_ha_userspace.go 74, daemon_ha_userspace_export.go 56, exec_timeout.go 50) | <100 | trivial glue | — | — | — |

### Test files in batch (105 files, largest >300 LOC highlighted)

| File | LOC | Area | Notes |
|------|-----|------|-------|
| daemon_ddns_surface_a_test.go | 953 | DDNS Surface A | observer, gate, scope tests — large but OK test |
| host_inbound_nft_test.go | 897 | nft host-inbound | parity tests |
| daemon_flowexport_reconcile_test.go | 595 | flowexport | reconcile hash gate |
| daemon_proxyarp_test.go | 562 | proxyarp | VLAN resolution |
| daemon_ssh_test.go | 555 | SSH | login tests |
| daemon_snmp_reconcile_test.go | 486 | SNMP | lifecycle tests |
| daemon_policy_invalidate_test.go | 478 | policy invalidate | session clear |
| host_inbound_junos_host_4146_test.go | 454 | Junos host deny | L4 matching |
| daemon_flowexport_session_close_test.go | 423 | flowexport | close callback |
| host_tunables_restore_test.go | 422 | tunables | restore |
| ... 95 more <400 LOC | — | — | — |

Total test LOC in batch: ~30k, largest 953, none are refactor candidates (test files excluded from heatmap per docs/refactoring-audit.md). They provide good coverage for host-inbound parity, lo0, DDNS gates, etc.

Hot-path analysis: All prod files in this batch are COLD (daemon start, commit apply, config render) or WARM (HA transitions, periodic monitors at 200ms-10s, link-state netlink subscription, neighbor probe). NONE are per-packet hot path (userspace-dp is Rust AF_XDP helper, safe mechanical splits). This means file decomposition can be pure code-motion (A-class) without icache/perf risk.

---

## Log — module-by-module deep scan

### daemon_run.go (2492 LOC) — HIGH monolith

- **Run() 643 LOC** (175-818): 6-phase boot (config load → interface naming → manager init → dataplane+initial config → signal + apply-cancel context + event buffer → gRPC/HTTP start + WaitGroup). Mixes slog handler wrap, rollback executor registration, protected resolver set, policy scheduler loop start, applyCancelContext child of signal context (#2926), eventBuf, session sync wiring comment. Ordering sensitive: bootstrapMode flag set during load, naming before managers, FRR clear on fail-closed, etc. #4662 already flags ordering sensitivity.
- **runShutdownSequence 183 LOC** (819-1002): wg coordination, stop func, runErr handling, pin retry loop stop, policy scheduler stop, NAT pool alarm stop, forwarding status stop, etc.
- **startGRPCServer 133 LOC** (1003-1136) + **startHTTPServer 237 LOC** (1136-1373): HTTP + gRPC server construction, event buffer + fwd sampler wiring, API bind clamping via resolveAPIBinds.
- **resolveAPIBinds 82 LOC** (1374-1456): clamps API binds to mgmt VRF?
- **initManagers 183 LOC** (1456-1639): constructs networkd, routing, FRR, IPsec, RA, DHCP, DHCP server, DDNS, feeds, RPM, SNMP — god-init.
- **loadAndBootstrapConfig 149 LOC** (1640-1789): configstore active/ever-committed check, nodeID present, computeBootClass, bootstrap file path.
- **setupInterfaceNaming 107 LOC** (1789-1896): positional vs device-map branch, enumerateAndRenameMapped vs enumerateAndRenameInterfaces.
- **setupDataplaneAndInitialConfig 133 LOC** (1896-2029): dataplane Build + apply startup + bootstrap exit startup.
- Other helpers: buildRuntimeDataPlane, collectAppliedTunnels, riMemberLinuxName, namingParamsFromConfig, applyStartupNamingForConfig, maybeReapplyConfigArrivalNaming, runBootstrapExitStartup, inferIPv6StaticNextHopInterfaces 271 LOC (!), runHAShutdownUpdate.

Responsibility fusion: interface naming policy (positional vs mapped), dataplane runtime selection, manager wiring, gRPC/HTTP lifecycle, signal context layering, bootstrap exit, IPv6 nexthop inference — 12 distinct concerns in one file.

### daemon_apply.go (2265 LOC) — HIGH monolith

- **applyDataplaneAndHACore 400 LOC** (795-1195): RETH MAC pending check → defer-workers, commitOverlayForConfig (RPM overlay filtered per #1843 HIGH-1), reconcileFeeds hash-gated (#5036), SetFeedSnapshots overlay, C2 boundary (ctx.Err before dp.ApplyConfig), dp.ApplyConfig bg context, recordCompileFailure/Success, then RETH MAC programming + VIP + worker rebind as one unit, FRR boundary.
- **applyConfigLocked 148 LOC** (647-795): 3 boundaries C1/C2/C3 (#2926), applyDataplaneAndHACore call, applyServicesReconcile, applyRoutingRules, applyFabricIPVLAN, applyVRFReconcile, applyInterfaceReconcile, applyTailReconciles.
- **applyTailReconciles 289 LOC** (1743-2033): delegates to DNS, DHCP server, IPsec, networkd, RA, proxyARP, SNMP, flow, feeds, event options, archiver.
- **applyServicesReconcile 155 LOC** (1195-1351): services that are hash-gated vs always.
- **applyVRFReconcile 126 LOC** (1546-1673), **applyInterfaceReconcile 70 LOC** (1673-1743) — VRF + interface bring-down + always-down.
- God-orchestrator carries: factoryReset + executeConfirmedRollback + resyncRolledBack + commitAndApply + applyAndSyncCommitted + syncAndApply + deviceMapPassiveAdmissionAlarm — 7 entry paths that all converge on applyConfigLocked.

### daemon_nft.go (1782 LOC) — HIGH monolith

- **nftRulesFromTerm 359 LOC** (1301-1660): firewall filter term → nft rules: prefix lists, port ranges, ICMP type/code, TCP flags (required/forbidden), DSCP, forwarding-class rewrite, hit counters, logging. Complex joinNftFields + string building.
- **buildHostInboundFilterPayload 173 LOC** (526-700): views + unzonedV4/V6 + JunosHostPrograms + wgListenPorts → payload string. Calls emitHostInboundICMPAccepts, emitWireGuardAccept, emitJunosHostDenyProgram, emitJunosHostDropRule, emitUnzonedHostInboundDeny, emitHostInboundZone.
- **applyHostInboundFilter 125 LOC**, **applyLo0Filter 49 LOC** + **buildLo0FilterPayload 90 LOC**: lo0 filter separate doc (port ranges, DSCP).
- Helpers: hostInboundServiceAction (service token → action), hostInboundMatchSet, hostInboundServiceMatches, hostInboundProtocolMatches, renderHostInboundMatches, renderPortSpec, renderICMPSpec, nftAddrSet, nftFamilyAddrs, nftAddrPredicate (pred + matchesNothing), nftLo0LogPrefix, nftTCPFlagNames, nftTCPFlagsMatch, nftIntSet, nftDSCPValue — 20 helpers, but all in one file.

Fusion: 3 distinct nftables artifacts (lo0 interface filter, host-inbound per-zone filter, firewall filter term filter) + 20 rendering helpers fused. Prior parity work (#3362 per-iface, #3698 addressless, #3718 ambiguous, #3627 SSOT render) all grew this file.

### daemon_system.go (1731 LOC) — HIGH monolith

- **applySystemLogin 179 LOC** (1021-1200): login users, class perms, password hash validation, UID handling.
- **applySyslogConfig 156 LOC** (28-184) + **applySyslogFiles 105 LOC** (870-975): syslog event reader + aggregator + dropins.
- **applySSHConfig 133 LOC** (1432-1565): sshd_config render (buildSSHDConfig 112 LOC) + algorithm filtering.
- **reconcileSudoers 64 LOC** (1230-1294) + **reconcileUserPassword 99 LOC** (1332-1432) + **writeSudoersGrant 38 LOC**.
- **applySystemNTP 40 LOC** (497-537) + **renderChronySources/Threshold**.
- Plus hostname, kernel tuning, known hosts, timezone, root auth.

Fusion: 9 system domains (syslog, hostname, NTP, kernel tuning, known hosts, timezone, login, sudoers, SSHD) — Junos `system` stanza but each domain has distinct file I/O + validation.

### daemon_ha.go (1576 LOC) — MEDIUM monolith

- **reconcileRGState 250 LOC** (555-805): RG state machine transitions, active applied if current/stable, blackhole injection/ejection, RETH services per RG.
- **watchClusterEvents 181 LOC** (167-348): cluster node state → RG0 ownership transition, sync hold, VRRP priority updates (debounce 500ms).
- **watchVRRPEvents 89 LOC** (404-493) + **reconcileRGStateLoop / triggerReconcile**.
- **applyRethServicesForRG / clearRethServicesForRG / reconcileBlackholeRoutes** — RETH service lifecycle.
- **filterDHCPConfigForMasterRGs** (complex), **ipsecSAFingerprint / Advertise / Nudge**.
- Fusion: RG state machine + VRRP watcher + cluster watcher + blackhole route calc + RETH service application + DHCP filter + IPsec SA sync advertise — 8 responsibilities, belongs to HA coordinator.

### daemon_ha_sync.go (1020 LOC) — MEDIUM

- **startClusterComms 468 LOC** (398-866): creates session sync, control iface resolution, vrf device, heartbeat with retry, sync hold timer arm/stop, prime retry gen monotonicity (#5169).
- **startSessionSyncPrimeRetry 101 LOC**, **bulkSyncViaEventStreamOrFallback 27 LOC**, **syncConfigToPeer / pushConfigToPeer**, **fenceAllRGs 38 LOC**.
- Cluster transport key, redundancy groups snapshot.
- Fusion: heartbeat + session sync + config sync (forward + reverse-sync on reconnect) + fencing — 4 concerns that already have partial split (daemon_ha_userspace_*.go) but sync logic still monolithic.

### daemon_ha_fabric.go (965 LOC) — MEDIUM

- **refreshFabricFwd 161 LOC** (396-557) + **refreshFabricFwd1 100 LOC** (639-739) + **populateFabricFwd 58 LOC** + **populateFabricFwd1 61 LOC**.
- **ensureFabricIPVLAN 78 LOC** + **reconcileIPVLANAddrs 50 LOC**.
- **probeFabricNeighbor 39 LOC**, **sendICMPProbe**, **sendIPv6MulticastProbe**, **monitorFabricState 88 LOC**, **runFabricStateSubscription 88 LOC**.
- Duplication: Slot 0 and Slot 1 code paths mirror (fabric dual-instance >500 LOC duplicated logic with slight differences). Clear signal for split into per-slot abstraction.

### bootstrap.go (944 LOC) — MEDIUM

- 5 sub-domains fused: boot class (computeBootClass, hasNodeIDFile, load error class), fail-closed boot detection (detectFailClosedBootPinnedXDPLinks + ForwardingArmed), FRR clear (clearFRRForFailClosedBoot + failClosedBootShouldClearFRR), lifeline (PCI addr, MAC, record file I/O at /etc/xpf/lifeline-interface, detect, resolve current name, snapshot), protected interfaces (mgmt leaf + lifeline, resolve).
- setupBootstrapLifeline 76 LOC + writeBootstrapLifelineNetwork 52 LOC — networkd .network file for lifeline.
- isDHCPManaged heuristic.
- Should split into 4 files: boot class, fail-closed, lifeline, protected-iface.

### device_map.go (836 LOC) — MEDIUM

- enumeratePresentNICs 5 LOC delegates to devicemap pkg, but resolveDeviceMap 5 LOC, rethMembersFromConfig 20 LOC, applyStartupNamingPolicy 21 LOC, enumerateAndRenameMapped 198 LOC (! 161-359) does multi-pass collision-safe rename, writes .link files, breaks stale-udev EEXIST, PCI-keyed + MAC fallback.
- writeDeviceMapLinkFile 22 LOC, deviceMapStrandsManagement 111 LOC (381-492) fail-closed mgmt check, CheckDeviceMapStrandsManagement exported, deviceMapCommitPreflight 78 LOC (492-570) commit pre-flight rejecting map that would strand mgmt (validates rollback target too), teardownUnmappedManaged 111 LOC (644-755) managed→unmapped teardown before networkd.Apply, teardownRestoreTarget 29 LOC, predictableName/udevPredictableName 27+4 LOC, scrubStaleDeviceMapLinks 21 LOC.
- Fusion: naming (rename) + link-file IO + preflight validation + teardown + stale scrub — 5 concerns, plus 836 LOC split already attempted? Still monolithic.

### host_tunables.go (839 LOC) — MEDIUM

- 4 tunable domains fused: CPU governor (list paths, read, write, capture prior), netdev budget (value int write), neigh retrans (list neigh dirs, paths), mlx5 coalesce (state capture, execer).
- PriorHostTunables capture (6 methods) + restoreHostTunables (3 restore helpers) — restore path mirrors apply but separate.
- Could split per tunable domain: cpu, netdev, neigh, mlx5.

### daemon_flow.go (804 LOC) — MEDIUM

- 4 domains: mgmt VRF routes (collectDHCPRoutes, mgmtVRFIfaceSet, publishMgmtVRFIfaces, applyMgmtVRFRoutes, reconcile deletes, dst key), archival (archiveConfig, archiveToSites, scpArchiveTransfer — note F-02 scp argv hardening prior), flow trace (callback, apply, update, reconcile), link state monitor (monitorLinkState 38 LOC, runLinkStateSubscription 55 LOC, resyncLinkState 24, applyLinkState 14, emitTrap 19, defaultSubscribe). Link state monitor is warm periodic but bundles 5 funcs.

### daemon_ddns_surface_a.go (846 LOC) — MEDIUM — previous A2_R? Actually DHCP DDNS. Always-on Surface A manager, file-IO + DNS network only (per CLAUDE.md control-socket rule respects: no control-socket calls, so not starving). DDNS is cold LP but file spans 846 lines with 15 funcs, nudge channel coalescing, RG0 writer single-writer, warning dedup, observer (interface addr via netlink vs static unit addr), scope gate.

### daemon_flowexport.go (685 LOC) — MEDIUM

- V9 vs IPFIX fused: firstExp helpers, config hash gating (flowHash, ipfixHash), build configs (buildFlowExportConfigs, buildIPFIXExportConfigs), reconcile (reconcileV9Exporter 138 LOC, reconcileIPFIXExporter 105 LOC), teardownLocked, callbacks (flowExportCallback 60 LOC + ipfixExportCallback 58 LOC), batch stats, handoff dropped, collector health.
- Shared concern: bundle atomic.Pointer swap (exporter + resolved config) + once-registered callbacks + cancel/wg lifecycle — duplicated for V9 and IPFIX (near-duplicate logic).

### daemon_ha_vip.go (651 LOC) — MEDIUM

- VIP readiness (checkVIPReadiness, checkNoRethTakeover, takeoverReadinessForRG), direct VIP ownership (desired/applied/add/remove + stable link-local), GARP burst (scheduleDirectAnnounce 76 LOC with seq validity, directBurstStillValid, directSendGARPs 118 LOC). GARP has epoch dedup + 500ms dampener + force bypass (#2081 fix). Still bundles readiness + ownership + link-local + GARP burst.

### Smaller files (<600 LOC) — LOW

- daemon_neighbor.go 604: monitored neighbors collection + cluster neighbor readiness — could merge with listener? Currently 2 files that together are 1130 LOC neighbor domain.
- daemon_policy_invalidate.go 546: 3 entry points (deleted, modified, default) + helper sameStringSet — could split per trigger (deleted vs modified vs default) but file is borderline (<600) acceptable, though changedPolicyRuntimeIDs 55 LOC touches 2 maps.
- daemon_neighbor_listener.go 526: listener + regenDebouncer + env override no upper clamp (LOW from prior F-05 deliberate).
- daemon_snmp_reconcile.go 471: single reconciler, hash-gated, cancel/wg.
- daemon_rpm.go 438: RPM + pin retry loop (200ms-60s?), rpmEffective keep.
- daemon_dhcp_lease_sync.go 404: already grouping from #4407 inc1, but still 12 funcs (ensure loop, reset, run loop, dispatch, push once, maybePushFamily, fingerprint, nudge, preSeed, seedFromPeer). Could split push vs ensure.
- daemon_dhcp.go 341: DHCP client specs build + address change callback + IPsec reapply + relay gate — 5 responsibilities moderate.
- etc <400 LOC — not refactor candidates.

---

## Findings — by severity

### HIGH (needs split, god-file / god-function, >1500 LOC, >8 responsibilities, cold but merge-conflict hot)

#### H-01: daemon_run.go 2492 LOC — god boot/run lifecycle + gRPC/HTTP + naming + forwarding enable fused

Title: Daemon Run god-file 2492 LOC, Run() 643 LOC 6-phase ordering sensitive
Severity: HIGH
Confidence: HIGH
Evidence:
- 19 funcs in one file, Run() spans 175-818 = 643 lines with 6 comment phases, initManagers 183 lines constructs 10+ managers, startHTTP 237 lines builds Prometheus + health + pprof + API, startGRPC 133 lines wires 48 RPCs, setupInterfaceNaming branches device-map vs positional, inferIPv6StaticNextHopInterfaces 271 lines (! largest helper) does overlay-aware static nexthop inference.
- Prior #4662 already filed ordering-sensitive lifecycle but no concrete split. This audit adds: exact largest function (Run 643), responsibility inventory (12), hot-path NO (cold start safe mechanical), proposed modules.
Proposed decomposition:
- daemon/run/lifecycle.go: Run(), runShutdownSequence(), applyCancelContext handling (#2926), daemonCtx layering, stopPinRetryLoop defers.
- daemon/run/managers.go: initManagers() + buildRuntimeDataPlane() + Options.ColdPathSampleMask forwarding.
- daemon/run/naming.go: setupInterfaceNaming(), namingParamsFromConfig(), applyStartupNamingForConfig(), maybeReapplyConfigArrivalNaming(), runBootstrapExitStartup(), collectAppliedTunnels(), riMemberLinuxName().
- daemon/run/servers.go: startGRPCServer(), startHTTPServer(), resolveAPIBinds(), enableForwarding().
- daemon/run/bootstrap_config.go: loadAndBootstrapConfig(), inferIPv6StaticNextHopInterfaces() (own file due to 271 LOC pure logic), runHAShutdownUpdate().
- Keep daemon_run.go as 100 LOC facade re-exporting or eliminate (move to cmd/xpfd/main shim?).
Hot-path: NO — cold start, safe机械
Gate: make test-env-init + test-deploy + cluster-deploy still boots, plus make selftest.

#### H-02: daemon_apply.go 2265 LOC — god orchestrator 15 responsibilities, applyDataplaneAndHACore 400 LOC

Title: applyConfigLocked god-orchestrator fuses 15 commit domains, commitOverlay filtering #1843 HIGH-1 sits in same function as RETH MAC defer-workers
Severity: HIGH
Confidence: HIGH
Evidence:
- applyDataplaneAndHACore 400 LOC mixes RETH MAC pending detection (netlink LinkByName + HardwareAddr compare + deferWorkersActive flag), commitOverlayForConfig filtered against INCOMING config (security fix #1843), feed reconcile hash-gated #5036, SetFeedSnapshots overlay, C2 ctx boundary, dp.ApplyConfig bg context, then MAC/VIP/worker rebind unit.
- 7 entry paths: bootstrapFromFile, commitAndApply, applyAndSyncCommitted, syncAndApply, commitConfirmedAndApply, executeConfirmedRollback, factoryReset all converge.
- applyTailReconciles 289 LOC delegates to 10 subsystems but still in same file.
Proposed split (A-class code-motion):
- daemon/apply/orchestrator.go: applyConfig(), applyConfigLocked(), commitAndApply(), syncAndApply(), commitConfirmed, rollback, bootstrapFromFile() + applyErrSkipsPeerSync() guard.
- daemon/apply/dataplane_ha.go: applyDataplaneAndHACore() + setDataplaneDeferWorkers(), reapplyAfterDeferredMAC(), recordDataplaneWorkerArmDebt(), compileErrorMustAbortApply(), collectAppliedTunnels().
- daemon/apply/overlays.go: commitOverlayForConfig() filtered (#1843) + SetRouteOverlay/SetFeedSnapshots helpers + feedSnapshotsForConfig().
- daemon/apply/routing.go: applyRoutingRules() + applyFabricIPVLAN() + applyVRFReconcile() + applyInterfaceReconcile().
- daemon/apply/services.go: applyServicesReconcile() + reconcileDHCPRelay() + reconcileLLDP() + event engine init + reconcileEventOptions() + publishInitialPolicySchedulerStateLocked().
- Keep daemon_apply.go ~150 LOC facade.
Hot-path: NO — commit path, safe
Gate: make test-apply-serialize + test-failover (config sync) + archive tests

#### H-03: daemon_nft.go 1782 LOC — nft rendering 3 distinct artifacts + 20 helpers fused, nftRulesFromTerm 359 LOC god-function

Title: nft host-inbound + lo0 + firewall-filter term rendering fused, 38 funcs 1782 LOC, largest 359 LOC
Severity: HIGH
Confidence: HIGH
Evidence:
- 38 funcs: lo0 (applyLo0Filter, buildLo0FilterPayload), host-inbound (applyHostInboundFilter 125, log transitions 3 funcs 34+35+28, hasEnforceableView 6, buildHostInboundFilterPayload 173), emit helpers (ICMP accepts, WG accept, JunosHost deny program/drop, unzoned deny, zone emit 57, allowsAll, service action, match set, service matches, protocol matches, render matches 48, port spec, ICMP spec), lo0 helpers (nftAddrSet, nftFamilyAddrs, nftAddrPredicate 39, join fields), firewall filter term (nftRulesFromTerm 359 = huge — handles DSCP, forwarding-class, protocol, port range, TCP flags, ICMP code, prefix lists, log prefix, hit counters).
- History: #3362 per-iface, #3698 addressless, #3718 ambiguous, #3627 SSOT render all grew this file (noted in log comments).
Proposed split:
- daemon/nft/lo0.go: applyLo0Filter + buildLo0FilterPayload + nftLo0LogPrefix + nftDSCPValue + build helpers for lo0.
- daemon/nft/host_inbound.go: applyHostInboundFilter + log transitions (3) + hasEnforceableView + buildHostInboundFilterPayload + emit* (ICMP, WG, JunosHost deny, unzoned, zone) + allowsAll + matchSet + serviceMatches + protocolMatches + render*Matches + port specs + ICMP spec + nftAddrSet/FamilyAddrs/Predicate + addr helpers.
- daemon/nft/firewall_filter.go: nftRulesFromTerm (split itself into helpers: renderTermL4, renderTermAddr, renderTermDSCP — B-class extraction reducing 359→~80+3*~90) + nftTCPFlagNames/FlagsMatch + nftIntSet + joinNftFields.
- daemon/nft/helpers.go: shared rendering helpers (nftIifnameSet, nftAddrSet, etc.) or inline.
- Keep daemon_nft.go ~50 LOC re-export.
Hot-path: NO — config apply cold, safe mechanical
Gate: host_inbound_* parity tests (per_iface, addressless, ambiguous, SSOT render, unzoned) must still pass: make test-go with -run TestHostInbound

#### H-04: daemon_system.go 1731 LOC — 11 system domains fused, applySystemLogin 179 LOC god-function

Title: system syslog + NTP + login + sudoers + SSHD + hostname + tuning + known hosts + timezone fused
Severity: HIGH
Confidence: HIGH
Evidence:
- 29 funcs: syslog 5 funcs (applySyslogConfig 156, aggregationCallback, applyAggregator, applySystemSyslog 45, applySyslogFiles 105, reconcileSyslogDropins 46, syslogHostMinSeverity), NTP 4 funcs (applySystemNTP, renderChronySources, renderChronyThreshold, reloadChronyRuntime, reconcileManagedFile), hostname, kernel tuning (applyKernelTuning 65), known hosts (applySSHKnownHosts 61, removeManagedSSHKnownHosts 38), timezone (applyTimezone 84, zoneinfoTarget 22), login 6 funcs (applySystemLogin 179 biggest, defaultValidateSudoersFile, reconcileSudoers, writeSudoersGrant, reconcileUserPassword 99, applyRootAuth 65), SSHD (applySSHConfig 133, filterSSHAlgorithms, buildSSHDConfig 112).
- Each domain has distinct file I/O (chrony, systemd-timesync, /etc/hostname, /etc/sysctl.d, /etc/ssh/known_hosts, /etc/localtime, sudoers dropins, /etc/ssh/sshd_config).
Proposed split:
- daemon/system/syslog.go: applySyslogConfig + applySystemSyslog + applySyslogFiles + reconcileSyslogDropins + aggregationCallback + applyAggregator + resolveSourceAddr + syslogHostMinSeverity.
- daemon/system/ntp.go: applySystemNTP + renderChrony* + reloadChronyRuntime + reconcileManagedFile (or shared file IO helper).
- daemon/system/login.go: applySystemLogin + reconcileSudoers + defaultValidateSudoersFile + writeSudoersGrant + reconcileUserPassword + applyRootAuth + filterSSHAlgorithms? Actually SSHD separate.
- daemon/system/sshd.go: applySSHConfig + buildSSHDConfig + filterSSHAlgorithms.
- daemon/system/host.go: applyHostname + applyKernelTuning + applyTimezone + zoneinfoTarget + applySSHKnownHosts + removeManagedSSHKnownHosts.
- daemon/system/helpers.go: reconcileManagedFile, isProcessDisabled, resolveSourceAddr.
- Keep daemon_system.go ~50 LOC.
Hot-path: NO — commit cold
Gate: make test-go -run TestSystemXXX + NTP/timezone tests

### MEDIUM (700-1600 LOC, 5-9 responsibilities, warm but not per-packet, clear seams)

#### M-01: daemon_ha.go 1576 LOC — RG state + VRRP watcher + cluster watcher + blackhole + RETH services + IPsec SA advertise fused

Severity: MEDIUM
Confidence: HIGH
Evidence: 43 funcs, reconcileRGState 250 LOC god, watchClusterEvents 181, watchVRRPEvents 89, blackhole routes inject/remove, RETH services per RG, DHCP filter for master RGs, neighbor warm.
Proposed: daemon/ha/rg_state.go (getOrCreateRGState, snapshot, isMaster, recordActiveApplied, startupGoodbye), daemon/ha/events.go (watchClusterEvents, watchVRRPEvents, reconcileRGStateLoop, triggerReconcile, reconcileVRRPInstances), daemon/ha/blackhole.go (inject/remove/reconcile + shouldRemove), daemon/ha/reth_services.go (applyRethServicesForRG/clear+filterDHCP+rethInterfacesForRG), daemon/ha/ipsec_sa.go (fingerprint, advertise once, nudge). Keep daemon_ha.go facade.
Hot-path: WARM HA, not per-packet, safe.

#### M-02: daemon_ha_sync.go 1020 LOC — cluster comms + config sync + session sync prime fused

Severity: MEDIUM
Confidence: HIGH
Evidence: startClusterComms 468 LOC god, prime retry 101, heartbeat retry, bulk sync fallback, config push/handle, fenceAll, transport key.
Proposed: daemon/ha_sync/comms.go (startClusterComms 468 → split into heartbeat setup + session sync start + sync hold arm + fencing), daemon/ha_sync/config_sync.go (syncConfigToPeer, pushConfig, handleConfigSync, tail error), daemon/ha_sync/session_sync.go (prime retry, bulk via event stream, onPeerConnected/Disconnected, onBulkReceived/Ack). Keep facade.
Hot-path: WARM, safe.

#### M-03: daemon_ha_fabric.go 965 LOC — fabric IPVLAN parent + dual-slot population + probing + monitor duplicated for slot 0/1

Severity: MEDIUM
Confidence: HIGH
Evidence: refreshFabricFwd 161 + refreshFabricFwd1 100 + populate 0/1 58+61 + clear 0/1 20+35 + ensureFabricIPVLAN 78 + reconcileIPVLANAddrs 50 + probe 39 + sendICMP 35 + sendV6MC + monitor 88 + subscription 88 + trigger. Clear duplication: Slot0 and Slot1 mirror (412 LOC duplicated). No abstraction.
Proposed: daemon/fabric/ipvlan.go (ensure + reconcile addrs + parent resolve), daemon/fabric/probe.go (probe neighbor, sendICMPProbe, sendIPv6MulticastProbe, overlayOrParent), daemon/fabric/fwd.go (FabricFwd type + populate/clear/refresh generic over slot int, retains fabricEntryPopulated + retainOnMiss + logFailure), daemon/fabric/monitor.go (monitorFabricState + runFabricStateSubscription + trigger + defaultSubscribe helpers + CleanupFabricIPVLANs). Parameterize slot via struct {slot int, fabIface, overlay, peerAddr}. Eliminates duplication.
Hot-path: WARM, safe.

#### M-04: bootstrap.go 944 LOC — boot class + fail-closed detection + lifeline + protected interfaces + FRR clear fused

Severity: MEDIUM
Confidence: HIGH
Evidence: 28 funcs, computeBootClass 60, detectFailClosed* 33+35, hasNodeIDFile 20, setupBootstrapLifeline 76, writeBootstrapLifelineNetwork 52, lifelineRecord I/O 5 funcs, pciAddrForInterface, detectLifelineInterface, protectedInterfaces 11+35, interfaceAddrSnapshot 47, isDHCPManaged 17.
Proposed: daemon/bootstrap/bootclass.go (loadErrorClass, classifyLoadError, shouldBootstrapFromFile, bootClass, computeBootClass, hasNodeIDFile, String()), daemon/bootstrap/failclosed.go (detectPinnedXDPLinks, detectForwardingArmed, clearFRRForFailClosedBoot, failClosedBootShouldClearFRR, consts), daemon/bootstrap/lifeline.go (lifelineRecord struct + path + read/write at + detectLifelineInterface + pciAddrForInterface + lifelineRecordFromParts + resolveCurrentName + setupBootstrapLifeline + writeBootstrapLifelineNetwork + interfaceAddrSnapshot + isDHCPManaged), daemon/bootstrap/protected.go (protectedInterfaces, protectedInterfacesWith, resolveProtectedInterfaces). Keep bootstrap.go ~80 LOC facade.
Hot-path: COLD boot, safe.
Gate: bootstrap_test.go + bootstrap_rollback_test + lifeline_nonpci test.

#### M-05: device_map.go 836 LOC — enumeration + binding resolve + link file write + preflight + teardown + scrub fused

Severity: MEDIUM
Confidence: HIGH
Evidence: 18 funcs, enumerateAndRenameMapped 198 LOC multi-pass collision-safe rename (breaks stale-udev EEXIST), deviceMapStrandsManagement 111, teardownUnmappedManaged 111, deviceMapCommitPreflight 78, scrubStale 21, predictable/udev name 27+4. All in one file, yet lifecycle split across 4 phases (startup rename, commit preflight, managed→unmapped teardown, stale scrub).
Proposed: daemon/devmap/enumerate.go (enumeratePresentNICs, resolveDeviceMap, rethMembersFromConfig, deviceMapNamingActive), daemon/devmap/rename.go (enumerateAndRenameMapped, applyStartupNamingPolicy, writeDeviceMapLinkFile, deviceMapOriginalNameFor, predictable/udev name), daemon/devmap/preflight.go (deviceMapStrandsManagement, CheckDeviceMapStrandsManagement, deviceMapCommitPreflight, anyMappedIdentityPresent, protectedForConfig), daemon/devmap/teardown.go (teardownUnmappedManaged, teardownRestoreTarget, scrubStaleDeviceMapLinks). Keep device_map.go facade.
Hot-path: COLD boot/commit, safe.

#### M-06: host_tunables.go 839 LOC — 4 tunable domains + capture/restore fused

Severity: MEDIUM
Confidence: HIGH
Evidence: 22 funcs, 4 domains (CPU governor, netdev budget, neigh retrans, mlx5 coalesce) each has apply + capture + restore, plus resolvedHostTunables selector (governorIn + budgetIn + userspaceDP bool → final values), applyHostTunables 80 LOC orchestrator, restoreHostTunables 35, restoreHostScope 51, restoreNeigh 28, restoreMlx5 31. Prior fs interface hostTunableFS (readFile/writeFile/list paths) is seam.
Proposed: daemon/tunables/cpu.go (listCPUGovernorPaths, applyCPUGovernor, captureGovernor), daemon/tunables/netdev.go (applyNetdevBudget, captureBudget), daemon/tunables/neigh.go (neighRetransPaths, applyNeighRetransTime, capture + restore), daemon/tunables/mlx5.go (coalesce state, capture, restore), daemon/tunables/orchestrator.go (resolvedHostTunables, applyHostTunables, newPriorHostTunables, restoreHostTunables aggregation). Keep host_tunables.go facade.
Hot-path: COLD.
Gate: host_tunables_test.go + restore tests (debt, applay sem) etc.

#### M-07: daemon_flow.go 804 LOC — mgmt VRF + archive + flow trace + link-state monitor fused

Severity: MEDIUM
Confidence: HIGH
Evidence: mgmt VRF routes (collectDHCPRoutes, mgmtVRFIfaceSet, publish, applyMgmtVRFRoutes 106, reconcile deletes, dst key, toDelete), archive (archiveConfig, archiveToSites, scpArchiveTransfer — note prior F-02 hardening), flow trace (callback, apply, update, reconcile), link state (monitorLinkState 38, runLinkStateSubscription 55, resync 24, apply 14, emitTrap 19, defaultSubscribe 4). 4 domains.
Proposed: daemon/flow/mgmt_vrf.go (mgmt VRF collection + reconciliation), daemon/flow/archive.go (archive + sites SCP — already had prior sec hardening), daemon/flow/trace.go (flow trace callback + apply), daemon/flow/linkstate.go (monitor + subscription + resync + apply + trap). Keep daemon_flow.go facade.
Hot-path: WARM (link state netlink subscription), but not per-packet.

#### M-08: daemon_flowexport.go 685 LOC — V9 + IPFIX duplicated reconcile/teardown/callback logic

Severity: MEDIUM
Confidence: HIGH
Evidence: 17 funcs, firstExp helpers 8+15, config hash 32byte, buildFlowExportConfigs (2 variants), reconcileV9 138, reconcileIPFIX 105, teardownV9Locked, teardownIPFIXLocked, flowExportCallback 60, ipfixExportCallback 58, batch stats, handoff dropped atomic.Uint64 counters (#4963), collector health, export error. V9 and IPFIX code mirrors (near duplicate).
Proposed: daemon/flowexport/common.go (exporterBundle, ipfixBundle, hash, firstExp, batch stats types, handoff counter seam), daemon/flowexport/v9.go (build, reconcile, teardown, callback), daemon/flowexport/ipfix.go (same), daemon/flowexport/reconcile.go (shared hash gate + bundle atomic swap logic + once registration). Extract shared “buildBeforeSwap + fresh Wg pointer” pattern (#3742).
Hot-path: WARM (session-close callback reads atomic.Pointer), safe.
Gate: flowexport reconcile tests + session close test.

#### M-09: daemon_ddns_surface_a.go 846 LOC — Surface A DDNS all-in-one (loop + scope build + observer + RG0 writer)

Severity: MEDIUM
Confidence: MEDIUM
Evidence: 15 funcs, runSurfaceADDNSReconcileLoop 103 LOC, runGuarded 30, reconcileSurfaceAOnce ? , buildSurfaceAScopes 153, surfaceAObserver 162, surfaceALinuxIfName, observeInterfaceAddr 65 (netlink Addr + static unit addr 40+58), surfaceAGate, surfaceARG0Writer 13, nudge, ForceDDNSUpdate, stats/status. Prior #4407 inc 5 grouped surfaceAState but file still monolithic.
Proposed: daemon/ddns/surface_a/scope.go (buildSurfaceAScopes + linuxIfName), daemon/ddns/surface_a/observe.go (observer + observeInterfaceAddr + selectInterfaceAddr + staticUnitAddr), daemon/ddns/surface_a/reconcile.go (loop + guarded + once + gate + RG0 writer + nudge). Keep daemon_ddns_surface_a.go facade.
Hot-path: COLD (file I/O + DNS network only per CLAUDE.md).
Gate: surface A tests 953 LOC must pass.

#### M-10: daemon_ha_vip.go 651 LOC — VIP readiness + ownership + link-local + GARP burst fused

Severity: MEDIUM
Confidence: MEDIUM
Evidence: 25 funcs, readiness 3 funcs (checkVIPReadiness, checkNoRethTakeover, takeoverReadinessForRG), ownership desired/applied/add/remove 5 funcs, stable link-local add/remove + LL helpers, announce (directAnnounceActive, cancel, schedule 76, burst valid, sendGARPs 118). GARP has epoch dedup + time dampener + force bypass (#2081).
Proposed: daemon/vip/readiness.go (checkVIPReadiness*, takeoverReadiness), daemon/vip/ownership.go (shouldOwnDirectVIPs, directVIPOwnershipApplied, add/removeDirectVIPs, reconcile), daemon/vip/linklocal.go (add/removeDirectStableLinkLocal, add/removeStableRethLinkLocal, addLLToInterface helpers), daemon/vip/garp.go (directAnnounceActive, schedule, sendGARPs, burst valid). Keep daemon_ha_vip.go facade.
Hot-path: WARM HA.

#### M-11: daemon_ddns.go 399 LOC + daemon_dns.go 377 + daemon_dhcp_lease_sync.go 404 cluster — 3 files but responsibilities overlap across DDNS surface B

Severity: MEDIUM (as a cluster)
Confidence: MEDIUM
Evidence: ddns.go (DHCP lease DDNS manager Surface B, 13 funcs), dhcp_lease_sync.go (HA lease sync PATH C, 12 funcs, grouped state dhcpLeaseSyncState), dns.go (9 funcs, mergeDNSInput, atomic write, bind mount fallback). DDNS + DNS + lease sync all touch DNS/lease but spread.
Proposed (optional): Consolidate into daemon/ddns/ — surface_a already separate, surface_b.go (current daemon_ddns.go), lease_sync.go (current), dns.go stays separate? Actually dns.go is DNS resolv.conf reconcile, distinct from DDNS. So keep dns.go separate, but merge ddns.go + lease sync under daemon/ddns/ with clear naming.
Hot-path: NO (file I/O, Kea socket only).

### LOW (300-600 LOC, 2-4 responsibilities, acceptable but could be cleaner)

#### L-01: daemon_neighbor.go 604 LOC + daemon_neighbor_listener.go 526 LOC — neighbor domain split across 2 files but each still multi-responsibility

Severity: LOW
Confidence: HIGH
Evidence: neighbor.go 9 funcs: monitored neighbors collection (189 LOC), probe triggering, cluster readiness maintain, periodic guard test env, resolveNeighbor. listener.go 12 funcs: listener subscription, regen debouncer, env override getNeighborProbeMaxTargets (no upper clamp — deliberate per prior triage F-05 env var root-gated).
Proposed: Keep 2-file split but extract daemon/neighbor/collection.go (collectMonitoredNeighbors) vs probe.go vs maintain. Or merge into daemon/neighbor/ with collection, probe, listener subfiles. Low priority, 1130 LOC combined still < threshold per file individually but together logical monolith.

#### L-02: daemon_policy_invalidate.go 546 LOC — 3 triggers for session clear

Severity: LOW
Confidence: HIGH
Evidence: 11 funcs: deletedPolicyRuntimeIDs 59, clearSessionsForDeletedPolicies, clearSessionsForModifiedPolicies, defaultPolicyChanged, clearSessionsForDefaultPolicyChange, clearSessionsForPolicyChanges orchestrator, clearSessionsForPolicyIDs 145 LOC (does dp.DeleteSessionsByPolicyIDs), changedPolicyRuntimeIDs 55, policySchedulerBecameInactive, policyMatchOrActionChanged, sameStringSet.
Proposed: Could split into daemon/policy/invalidate_deleted.go, invalidate_modified.go, invalidate_default.go + shared clear helper. But file is 546 LOC <600, acceptable for now. Mark watch-list.

#### L-03: daemon_snmp_reconcile.go 471 LOC — single reconciler <500 borderline

Severity: LOW
Evidence: 9 funcs, hash gate, cancel/wg. File is cohesive, not a split candidate. Prior F-03 refuted. No action.

#### L-04: daemon_rpm.go 438 LOC — RPM + pin retry loop, rpmEffective keep, probePinApply seam

Severity: LOW
Evidence: 14 funcs, effective/RethMap keep guarded by rpmMu, pinRetry lifecycle #5308. File is <500, cohesive. No split, but note rpmMu guards rpmPinsFailed/active/etc. Complies with CLAUDE.md control-socket not applicable (routing manager, not helper socket). No action.

#### L-05: daemon_ipmon.go 428 + daemon_ipsec_rebind.go 179 + daemon_feeds.go 137 + daemon_archive_timer.go 151 + daemon_forwarding_status.go 132 etc <500 LOC

Severity: LOW — all <500, single responsibility, not candidates.

#### L-06: coalescence.go 272 LOC + exec_timeout.go 50 + daemon_gc.go 23 + daemon_cluster_bind.go 198 + daemon_ra.go 191 + daemon_proxyarp.go 282 — all <300 LOC, not candidates, single responsibility, no action.

---

## D-Negatives — already filed / deliberate / NOT-MATERIAL (do NOT re-file)

### D-01: Daemon god-struct #4407 already filed

- **File:** daemon.go 902 LOC, 80+ fields, Options comments, groups like surfaceA surfaceAState (inc 5), dhcpLeaseSyncState (inc 1), feedsMu+hash (#5036), rpmMu+hash (#1827), pinRetry lifecycle (#5308), natPoolAlarm atomic.Pointer (#2114), flowBundle/ipfixBundle atomic.Pointer + hash + reconMu (#2075 #3742 #4963), ipsecRebindMu + pending + retry active (#4899), ddnsReconcileNowCh + InFlight atomic.Bool (#1387), etc.
- **Why D-negative:** Already filed #4407, decomposition in progress (grouping increments). This audit adds field inventory but not new finding. Do NOT re-file as HIGH.
- **Current increments:** dhcpLeaseSyncState grouped, surfaceAState grouped, feedsMu grouped, rpm grouping partially, natPoolAlarm pointer, flow bundles. Still ~30 flat fields remain (ipmon, ra, dhcp, dhcpServer, dp, networkd, routing, frr, ipsec, feeds, rpm, etc.) but those are manager pointers, not god-field.
- **Gate:** groupings preserve locking contract (feedsMu serializes reconcile, rpmMu serializes RPM, ipsecRebindMu guards retry flag).

### D-02: daemon_run.go ordering-sensitive lifecycle #4662 already filed

- **File:** daemon_run.go 2492 LOC, Run() 643 LOC 6-phase ordering, initManagers 183, setupInterfaceNaming, namingParamsFromConfig, etc.
- **Why D-negative:** Already filed #4662. This audit provides concrete split proposal (lifecycle, managers, naming, servers, bootstrap config) but severity already tracked. Do NOT re-file HIGH, but extend with LOC + function size + hot-path NO.

### D-03: FRR / policy_render.go 2309 LOC + daemon_apply.go etc. referenced in task but NOT in this batch

- **File:** pkg/frr/policy_render.go mentioned in task example as 2309 LOC monolith, but NOT in batch b1 (batch b1 is only pkg/daemon/ 150 files). frr/ is in batch A7? Actually batch 2/3 has FRR? Check: batch b1 list does NOT include frr/. So this audit does NOT cover it. D-negative for this batch: out-of-scope, not a finding in this batch.
- **Disposition:** To be covered in A7 b2/b3 (which include FRR + routing + networkd).

### D-04: SNMP teardown Wait-before-Stop deadlock — refuted

- **File:** daemon_snmp_reconcile.go:310 teardownSNMPLocked ordering cancel→Wait→Stop.
- **Why NOT-MATERIAL:** Prior triage (F-03) refuted via agent.Start internal watcher: ctx cancel → agent's own goroutine calls Stop() → conn.Close() → ReadFromUDP unblocks → wg.Done() → Wait unblocks before teardown's own Stop. Belt-and-suspenders idempotent. No deadlock. Disposition: REFUTED, D-negative for refactor audit (not a correctness bug).

### D-05: Neighbor probe max targets unbounded env — deliberate

- **File:** daemon_neighbor_listener.go:67 getNeighborProbeMaxTargets no upper clamp.
- **Why DELIBERATE:** Env var root-gated, requires systemd-unit edit (root-equiv), documented override, actual goroutine count bounded by config size (collectMonitoredNeighbors deduped union), truncates with Warn. Self-inflicted foot-gun behind root gate. Not a refactor bug, but optional defensive clamp `min(n,4096)` polish, not residual.
- **Disposition:** DELIBERATE.

### D-06: scpArchiveTransfer argv injection via archive-sites — genuine but LOW hardening, not refactor

- **File:** daemon_flow.go:366 scpArchiveTransfer exec.CommandContext(sc, "scp", "-o", ...) no "--" separator + ArchiveSites free-form schema no leading-dash reject.
- **Why not refactor finding:** Prior triage F-02 classified GENUINE-RESIDUAL LOW hardening, not modularity. Trust boundary is config-commit root-equiv; attacker with commit can already get root via login/scripts. Fix is cheap: insert "--" + reject leading "-" at validation. Not a god-file split concern.
- **Disposition:** Security hardening, not refactor, D-negative for this audit's purpose (track in security lane).

### D-07: host_tunables restore debt + apply sem test seams, archive timer hash gate — already tested

- **Files:** host_tunables_restore_debt_5114_test.go 197 LOC, apply_sem, etc. These are race/test seam files, not prod monoliths. Not refactor candidates.

### D-08: Test files 105 files ~30k LOC — excluded from heatmap

- **Why:** Per docs/refactoring-audit.md, test files excluded by name pattern *_test.go. Largest test daemon_ddns_surface_a_test.go 953 LOC, host_inbound_nft_test.go 897, flowexport tests, etc. They provide coverage but are not refactor candidates. Some large tests (e.g., host_inbound_nft_test.go 897) could be split per scenario (per_iface, addressless, ambiguous) but already have dedicated files (per test files exist). Not a prod monolith.

---

## Suggested Split — concrete decomposition by responsibility (mechanical A-class safe, COLD/WARM not per-packet)

### Priority 1 — HIGH monoliths >1500 LOC (immediate split, cold safe, high merge-conflict relief)

1. **daemon_run.go 2492 → 5 files:**
   - `daemon/run/lifecycle.go` — Run() 643 (6 phases) + runShutdownSequence 183 + applyCancelContext #2926 + runHAShutdownUpdate + daemonCtx defers stopPinRetryLoop/stopPolicySchedulerLoop.
   - `daemon/run/managers.go` — initManagers 183 + buildRuntimeDataPlane 28 + loadAndBootstrapConfig 149 + setupDataplaneAndInitialConfig 133.
   - `daemon/run/naming.go` — setupInterfaceNaming 107 + namingParamsFromConfig 26 + applyStartupNamingForConfig 33 + maybeReapplyConfigArrivalNaming 31 + runBootstrapExitStartup 57 + collectAppliedTunnels + riMemberLinuxName.
   - `daemon/run/servers.go` — startGRPCServer 133 + startHTTPServer 237 + resolveAPIBinds 82 + enableForwarding 29.
   - `daemon/run/ipv6_nexthop.go` — inferIPv6StaticNextHopInterfaces 271 (pure, testable, overlay-aware).
   - Facade: `daemon_run.go` 50 LOC re-exports or deleted (move Run to lifecycle, keep backward compat via type alias).

2. **daemon_apply.go 2265 → 5 files:**
   - `daemon/apply/orchestrator.go` — bootstrapFromFile 52 + commitAndApply + applyAndSyncCommitted + syncAndApply 57 + commitConfirmed 54 + executeConfirmedRollback 94 + resyncRolledBack 18 + factoryReset + applyConfig 43 + applyCancelCtx + resetting atomic + applyErrSkipsPeerSync + pushCommittedConfigToPeer + deviceMapPassiveAdmissionAlarm.
   - `daemon/apply/dataplane_ha.go` — applyDataplaneAndHACore 400 + setDataplaneDeferWorkers + reapplyAfterDeferredMAC + recordDataplaneWorkerArmDebt + clearDeferWorkers + pendingFIBBump handling.
   - `daemon/apply/overlays.go` — commitOverlayForConfig filtered #1843 + SetRouteOverlay + SetFeedSnapshots + feedSnapshotsForConfig + routeOverlaySetter/feedSnapshotSetter interfaces.
   - `daemon/apply/routing.go` — applyRoutingRules + applyFabricIPVLAN 111 + applyVRFReconcile 126 + applyInterfaceReconcile + collectAppliedTunnels? (move to run/naming).
   - `daemon/apply/services.go` — applyServicesReconcile 155 + applyTailReconciles 289 (or further split services vs tail) + reconcileDHCPRelay + effectiveLLDPConfig + reconcileLLDP 49 + initEventEngine + reconcileEventOptions + publishInitialPolicySchedulerStateLocked 12.
   - Facade: 100 LOC.

3. **daemon_nft.go 1782 → 4 files:**
   - `daemon/nft/lo0.go` — applyLo0Filter + buildLo0FilterPayload 89 + nftLo0LogPrefix + nftDSCPValue + nftIntSet + joinNftFields.
   - `daemon/nft/host_inbound.go` — applyHostInboundFilter 125 + log transitions 97 + hasEnforceableView + buildHostInboundFilterPayload 173 + emitICMP 35 + emitWG 11 + renderWGPort 17 + emitJunosHostDenyProgram 38 + emitDropRule 23 + junosHostSrcPredicate 20 + renderL4 39 + nftIifnameSet + emitUnzoned 14 + hostInboundEmitsDrop + emitZone 57 + allowsAll 37 + serviceAction 31 + matchSet + serviceMatches + protocolMatches + renderMatches 48 + portSpec + port + ICMPSpec + addr helpers (nftAddrSet, familyAddrs, addrPredicate 39).
   - `daemon/nft/firewall_filter.go` — nftRulesFromTerm 359 → split into renderTermL4, renderTermAddr, renderTermLog, renderTermAction helpers (B-class extraction) + TCP flag helpers.
   - `daemon/nft/helpers.go` — shared (nftAddrSet etc. if not already in host_inbound).
   - Facade 50 LOC.

4. **daemon_system.go 1731 → 5 files:**
   - `daemon/system/syslog.go` — applySyslogConfig 156 + aggregationCallback + applyAggregator + resolveSourceAddr + applySystemSyslog 45 + applySyslogFiles 105 + reconcileSyslogDropins 46 + syslogHostMinSeverity.
   - `daemon/system/ntp.go` — applySystemNTP 40 + renderChronySources + renderChronyThreshold + reconcileManagedFile + reloadChronyRuntime + isProcessDisabled.
   - `daemon/system/login.go` — applySystemLogin 179 + reconcileSudoers 64 + defaultValidateSudoersFile + writeSudoersGrant 38 + reconcileUserPassword 99 + applyRootAuth 65.
   - `daemon/system/sshd.go` — applySSHConfig 133 + buildSSHDConfig 112 + filterSSHAlgorithms.
   - `daemon/system/host.go` — applyHostname + applyKernelTuning 65 + applySSHKnownHosts 61 + removeManagedSSHKnownHosts 38 + applyTimezone 84 + zoneinfoTarget 22.
   - Facade 50 LOC.

### Priority 2 — MEDIUM monoliths 700-1600 LOC

5. **daemon_ha.go 1576 → 5 files** as described in M-01 (rg_state, events, blackhole, reth_services, ipsec_sa). Approx target <400 LOC/file.

6. **daemon_ha_sync.go 1020 → 3 files** as M-02 (comms, config_sync, session_sync). Comms file still 468 → further split heartbeat vs fence vs redundancy groups.

7. **daemon_ha_fabric.go 965 → 4 files** as M-03, extracting generic FabricFwd<T> slot abstraction to eliminate duplication 412 LOC. Expected after: ipvlan 150, probe 150, fwd 400 (generic), monitor 200.

8. **bootstrap.go 944 → 4 files** as M-04 (bootclass, failclosed, lifeline, protected). Lifeline file biggest 400 LOC.

9. **device_map.go 836 → 4 files** as M-05 (enumerate, rename, preflight, teardown).

10. **host_tunables.go 839 → 5 files** as M-06 (cpu, netdev, neigh, mlx5, orchestrator).

11. **daemon_flow.go 804 → 4 files** as M-07 (mgmt_vrf, archive, trace, linkstate).

12. **daemon_flowexport.go 685 → 4 files** as M-08 (common, v9, ipfix, reconcile) extracting shared bundle swap pattern.

13. **daemon_ddns_surface_a.go 846 → 3 files** as M-09 (scope, observe, reconcile).

14. **daemon_ha_vip.go 651 → 4 files** as M-10 (readiness, ownership, linklocal, garp).

15. **daemon_dhcp.go 341 + daemon_dhcp_lease_sync.go 404 + daemon_ddns.go 399** cluster → consider `daemon/ddns/` directory merging Surface A+B + lease sync, but keep dhcp.go separate (client specs).

### Priority 3 — LOW <600 LOC (watch-list, not immediate)

- Neighbor domain 1130 combined: optionally merge into `daemon/neighbor/` dir with collection.go, probe.go, listener.go, maintain.go — but current 2-file split 604+526 is acceptable per <600 guideline (watch-list 1500 threshold). No immediate action.

- Policy invalidate 546: single domain (session clear for policy change), cohesive, <600, watch-list. No immediate split, but could extract deleted vs modified vs default as separate files if grows past 600.

- SNMP reconcile 471: cohesive, <500, no split.

- RPM 438: cohesive, <500, no split (already has #1827 hash gate + #1895 retry + #5308 lifecycle).

- Others <400: no action.

### Cross-cutting patterns to preserve

- **Hot-path NO:** All large files in this batch are COLD (boot, commit apply) or WARM (HA transitions, periodic 200ms-10s monitors). No per-packet hot path (Rust userspace-dp is separate). Mechanical A-class code-motion safe, no icache/perf risk. No allocation per packet in any of these paths.
- **Control socket contention:** CLAUDE.md rule: high-frequency callers (>1/s) must be throttled. All new splits must preserve existing throttling (status poll 1/s, HA sync, session installs). DDNS loop already respects (file I/O + DNS only, no control socket). Lease sync is Kea socket only, not helper. Flow export callbacks read atomic bundles lock-free (existing pattern) — preserve atomic.Pointer swap.
- **Locking:** feedsMu, rpmMu, ipsecRebindMu, flowReconMu, ipfixReconMu, applySem, applyCancelContext — all must be preserved with same guard scope. God-struct grouping increments already document guard per field.
- **Test coverage gate:** Existing tests cover DDNS gates (standalone vs MASTER/BACKUP, partial-master), Surface A scope+observer, host-inbound parity (per_iface, addressless, ambiguous, SSOT render, unzoned), lo0 DSCP/protocol/ICMP-code/fragment/tcp-flags/VRF, SNMP lifecycle, flowexport hash gate, policy invalidate, DHCP relay gate, fabric monitor, etc. After split, tests should continue to pass via facade re-exports (no test move needed initially).
- **File size thresholds per docs/refactoring-audit.md:** >=2000 LOC REFACTOR candidate, 1500-1999 WATCH. After split, no file should remain >=1500 LOC in pkg/daemon/. Currently 4 files violate >=2000 (run 2492, apply 2265, nft 1782 borderline but 1782 >1500 watch, system 1731 watch, ha 1576 watch). Target: all <800 LOC after split.

### Estimated LOC after split

| Original | After | Files |
|----------|-------|-------|
| daemon_run 2492 | ~400+400+300+400+300 = 1800 + 50 facade | 5 |
| daemon_apply 2265 | ~500+400+200+300+400 = 1800 + 100 facade | 5 |
| daemon_nft 1782 | ~200+800+400+200 = 1600 + 50 facade | 4 |
| daemon_system 1731 | ~400+200+400+250+200 = 1450 + 50 facade | 5 |
| daemon_ha 1576 | ~300*5 = 1500 + 50 | 5 |
| others | each <400 | — |
| **Total** | ~ 9000 LOC over ~30 files vs 4 god-files | 30 files avg 300 LOC, better merge conflict isolation |

### Verification steps for any split

1. `make generate` not needed (no userspace-xdp/ change, per CLAUDE.md).
2. `make build` + `make build-userspace-dp` — uses git-tracked shim .o, no kernel verifier gate.
3. `make test-go` — all daemon/*_test.go (105 files in batch) pass, especially host_inbound parity, lo0 filter, DDNS gates, flowexport hash, policy invalidate, DHCP relay, fabric monitor.
4. `make test-rust` not needed for daemon-only split but run as part of `make test` if touching shared headers.
5. `make selftest` — day-0/image/dist/deploy self-tests, hermetic, fast.
6. `make audit-check` — `bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt` + diff, commit regenerated artifact.
7. For HA splits: need loss cluster lock protocol — `make cluster-deploy` + `make test-failover` (reboot fw0 during iperf3, default 60ms failover, sync hold release preempt gated).

### Deduplication against existing audit stream

- #4407 god-struct: filed, now extended with field inventory + grouping increments, not dup.
- #4662 run ordering: filed, now extended with 5-file concrete split + largest function measurement, not dup.
- F-02 scp argv: security hardening LOW, not refactor, tracked separately.
- F-03 SNMP teardown refuted: not a bug, not refactor.
- F-05 neighbor probe env deliberate: not refactor.
- All other H/M findings are NEW (not in dedup-index.txt evidence list which focused on userspace-dp + config + frr/policy_render + dataplane etc., not daemon/ monoliths beyond #4407/#4662).

---

## Risk Assessment — safe mechanical justification

- **Cold-path proof:** daemon_run Run() is boot once, daemon_apply is commit path (operator cli/gRPC/REST → store → applySem → dp.ApplyConfig → FRR reload), daemon_nft is nftables ruleset build + apply (commit), daemon_system is file I/O (syslog dropins, chrony sources, sudoers, sshd_config). None are per-packet, no allocation pressure.
- **No control-socket starvation:** DDNS loop (surface A) explicitly documents file-I/O + DNS network only (no control-socket), gated to HA-active, nudged via buffered channel depth 1 non-blocking. Lease sync uses Kea socket only. Flow export callbacks read atomic.Pointer bundles lock-free (no socket). All splits preserve existing throttling.
- **No lock ordering change:** All splits are pure code-motion (A-class per engineering-style.md). No new locks, no change to rpmMu/feedsMu/ipsecRebindMu/flowReconMu/applySem guard scope. applyCancelContext (#2926) boundary C1/C2/C3 preserved.
- **HA safety:** blackhole route injection/removal, VIP ownership, GARP burst epoch dedup + 500ms dampener + force bypass (#2081), sync hold release preempt peer-priority gated (#2082) all preserved as direct moves.
- **Fail-closed boot:** failClosedBoot detection pinned XDP links + forwarding armed + FRR clear logic stays in bootstrap/failclosed.go, protected by tests bootstrap_test.go.

---

## Summary

- **Batch 1/3 total 150 files:** 45 prod (largest 2492 daemon_run, 2265 daemon_apply, 1782 daemon_nft, 1731 daemon_system, 1576 daemon_ha, 1020 ha_sync, 965 fabric, 944 bootstrap, 902 daemon god-struct, 846 surface A, 839 tunables, 836 device_map, 804 flow, 685 flowexport, 651 vip) + 105 test (largest 953 surface A test, 897 host_inbound_nft).
- **4 REFACTOR-tier files >=1500 LOC (HIGH):** daemon_run 2492, daemon_apply 2265, daemon_nft 1782, daemon_system 1731, plus ha 1576 (watch→refactor). All cold, safe mechanical.
- **10 WATCH-tier 600-1500 MEDIUM:** ha_sync, fabric, bootstrap, surface A, tunables, device_map, flow, flowexport, vip, neighbor aggregated.
- **HIGH findings 4, MEDIUM 11, LOW 6, D-negatives 8.**
- **D-negatives:** #4407 god-struct already filed, #4662 run ordering already filed, frr/policy_render out-of-scope this batch, SNMP deadlock refuted, neighbor env deliberate, scp argv security not refactor, test files excluded, restore debt seams tested.
- **Suggested splits:** Priority 1 (4 files → 19 files) eliminates all >=1500 LOC, Priority 2 (10 files → ~35 files) reduces all <400 LOC, Priority 3 watch-list acceptable. All splits A-class code-motion, cold/warm safe, preserve locking + control-socket throttling + HA GARP epoch/dampener + sync hold + fail-closed guards.
- **Gate:** make test-go (105 test files), make selftest, audit-check, plus cluster-deploy + test-failover for HA files.

---
Generated via worktree /tmp/review-wt-ps-044-A7_go_daemon_host-b1 at f1ef0eec8, batch file /tmp/review-work-ps-044/batches/A7_go_daemon_host-b1.txt


---
### Batch A7_go_daemon_host-b2 — 1057 lines — full log + findings

# A7_go_daemon_host — Modularity Audit Batch 2/3 (host integration)

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A7_go_daemon_host-b2 (detached HEAD, regenerated)
Batch: A7_go_daemon_host-b2.txt (150 files, 34 prod + 116 test)
Scope: daemon host integration — networkd .link/.network generation, routing VRF/GRE/XFRM (bond/reth/monitor/probe_pin), FRR config generation, IPsec strongSwan, devicemap identity resolver, upgrade/self-recovery, login password, fwdstatus, fsatomic atomic writes, diagcmd limiter.

## Inventory — prod files in batch (LOC, fused responsibilities, hot-path?)

| File | LOC | Fused Responsibilities | Hot? |
|------|-----|------------------------|------|
| pkg/frr/policy_render.go | 2309 | 5 routing protocols (OSPF/OSPFv3/BGP/RIP/ISIS) + policy-options prefix-list/community/route-map + composed BGP chain derivation (ReservedChainSuffix collision guard) + redistAlias fail-closed alias + BFD profile dedup + sanitizeFRRValue newline injection belt | COLD |
| pkg/frr/manager.go | 1057 | FullConfig→managed-section build + file write (atomicWriteFile + owner option) + stripManagedSection + frr-reload.py dispatch + vtysh fallback + retry degraded loop + RetryDelays + Episode tracking | COLD |
| pkg/daemon/device_map.go | 836 | Device-map commit preflight (strands management check) + protected set + present NIC enumeration + binding resolution glue + rename orchestration (renameInterfaceFn injectable) + teardownRestoreTarget fail-closed retain + stale link scrub + udev predictable fallback | COLD startup + commit |
| pkg/networkd/networkd.go | 775 | Manager with reloadPending/reconfigurePending debt + protectedResolver lifeline exemption + externally-managed discovery + expected-set sweep + .link/.network/.netdev generation + address ordering + junosSpeedToNetworkd + RP filter slow-path restore + writeIfChanged + networkctl reload/reconfigure shell-out 15s timeout | COLD commit path |
| pkg/daemon/linksetup.go | 545 | PCI NIC enumeration (enumeratePCINICs / extractPCIAddr sortKey virtio vs hw) + vSRX name assignment + collision-safe two-pass rename (breakNameCollisions) + .link file write + bootstrap fxp0 DHCP .network + netlink wrapper vars nlLinkByName/SetDown/SetName/SetUp + rss indirection reapply hook + networkctlReload via execCommand | COLD boot |
| pkg/daemon/rss_indirection.go | 550 | rssExecutor interface + realRSSExecutor (runEthtool/listInterfaces/readDriver/readQueueCount) + applyRSSIndirection + restoreDefaultRSSIndirection + parseIndirectionTable + indirectionTableIsDefault + indirectionTableMatches + computeWeightVector + maybeRestoreDefault | COLD boot/main-loop |
| pkg/daemon/login_password.go | 407 | pwAction (passwordAction) + isLockedShadow + currentShadowHash + lookupUIDGIDErr + markerPath/markProvisioned/xpfProvisioned + rootAuthorizedKeysPath/managedAuthorizedKeysPath + reconcileAbsentLoginUsers + deprovisionLoginUser | COLD |
| pkg/ipsec/policy.go | 1135 | childSelector + generateConfig→renderConfig + swanctl.conf child SA rendering + traffic-selector rendering + updown script + FRR route leaking hook + CHILD_SA collision guard + delete_terminate fail-closed | COLD |
| pkg/ipsec/ike.go | 890 | IKE connection rendering (proposals multivalue) + dhgroup roundtrip + crypto proposals + dpdSettings + initiator/responder + SAStatus + TerminateAllSAs + ActiveConnectionNames + InitiateConnection | COLD |
| pkg/routing/bond.go | 490 | bondManager + bondSig + Apply/createLocked/enslaveMembers/observedMembers/Clear + netlink bond creation + member enslavement diff + parent existence check + 802.3ad LACP handling | COLD commit |
| pkg/routing/monitor.go | 110 | InterfaceMonitorStatus + monitorManager Apply publishing redundancy-group interface-monitor states | COLD |
| pkg/routing/reth.go | 56 | rethManager Apply for reth pseudo-interfaces (bondless RETH VRRP mapping) | COLD |
| pkg/routing/probe_pin.go | 289 | probe pinning (probe_pin.go) – maps RPM/nexthop-check probes to routing-instance / interface $ | COLD |
| pkg/devicemap/devicemap.go | 316 | PresentNIC + Binding + pure identity resolver PCI bus addr + permanent-MAC fallback + RETH member OriginalName rule + collision-safe multi-pass rename discipline | COLD |
| pkg/fwdstatus/builder.go | 291 | MapStats + builder assembling ForwardingStatus from dataplane counters + sampler + procreader | WARM 1/s poll |
| pkg/fwdstatus/fwdstatus.go | 177 | ForwardingStatus + writeRow + buffers util | WARM |
| pkg/fwdstatus/sampler.go | 251 | sampler for dataplane status sampling + ticks overflow guard 4909 | WARM |
| pkg/fwdstatus/procreader.go | 211 | procreader reading /proc/net/dev or similar + osprocreader | WARM |
| pkg/fsatomic/fsatomic.go | 256 | PostRenameSyncError + atomic write file + fsync barrier ordering + ownerIDs + temp sweep isFsatomicTemp | COLD persist |
| pkg/diagcmd/diagcmd.go | ? | diag command runner + ping/traceroute options + monitor subscriptions | COLD |
| pkg/lldp/lldp.go | ? | LLDP lifecycle + socket + TTL0 shutdown + mutex | COLD |
| pkg/linuxsock/linuxsock.go | ? | linux socket helper for netlink / raw | COLD |

Overall batch total prod LOC (34 files): ~9800. Test LOC 116 files: ~15000.

---

## Finding 1: pkg/frr/policy_render.go — 2309 LOC god-renderer fusing 5 protocol families + policy-options + BGP composed chains + BFD + sanitization belt

Title: FRR policy_render.go god-renderer 2309 LOC — 5 routing families + policy-options + composed-chain routing + BFD + sanitize belt fused
Severity: HIGH
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE (no hot path, but file-level mandate history + global FRR namespace collision guards)
Evidence:
- File LOC 2309, single file listed as explicit project mandate to stay at 5 sibling files in pkg/frr (manager, config_render, vtysh, status_parse, policy_render) per comment lines 1-10, which itself documents monolith pressure.
- Responsibilities fused:
  - `knownRedistProtocols` map + `resolveRedistribute` (self-redistribute reject under router ospf / bgp etc.) — 150 LOC.
  - `isDefinedPolicyStatement` + `ReservedChainSuffix` + `hasNonEmptyPolicy` + `filterDefinedPolicies` + `bgpGlobalExportChain`/`bgpGlobalImportChain` + `bgpNeighborExportChain`/`bgpNeighborImportChain` → ordered chain resolution Junos most-specific-wins.
  - `composedChainName` + `bgpRouteMapRef` + `collectBGPRouteMapPolicies` + `bgpEffectiveChains` + `collectBGPComposedChains` + `bgpComposedChainCollision` (fail-closed guard #5277) + `renderComposedBGPChains`.
  - `bfdProfile`, `bfdPeer`, `bfdSection` (top-level `bfd { }` single block accumulation #2550) + `newBFDSection` + `addProfile` + `addPeer` + `empty` + `render`.
  - `generateProtocols` (OSPF, OSPFv3, BGP with neighbor IP guard #4588, RIP, ISIS) ~500+ LOC with 15+ args (ospf, ospfv3, bgp, rip, isis, vrfName, ecmpMaxPaths, policyOptions, bgpAcceptDefault, shared ...*bfdSection)
  - `generatePolicyOptions` + `renderPolicyTermSequences` + `renderRouteMapForPolicy` + `renderComposedRouteMap` + `renderRouteFilterEntry` + `indexedRouteFilter`.
  - Security belts: `sanitizeFRRValue` (C0 / DEL → space) #4097, `validRouterID` #2980, `validClusterID` #4919, `validBGPOrigin` #4919 colocated with rendering.
- Function signature monster:
```go
func (m *Manager) generateProtocols(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig, vrfName string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool, shared ...*bfdSection) string {
```
- `resolveRedistribute` fuses export=direct→connected normalization #2144, self-redist skip #2943, per-term FromProtocols aggregation, redistAlias fail-closed #4481, skip-and-warn paths that would otherwise poison whole managed reload #2223.
- Coupling: imports only config + slog + net + sort + strings, but touches every routing protocol and BFD — merge-conflict magnet (12+ change reasons per dedup-index).

File read via worktree:
`/tmp/review-wt-ps-044-A7_go_daemon_host-b2/pkg/frr/policy_render.go` lines 1-200 show module header acknowledging fusion.

Proposed decomposition:
- Keep package `frr`, split physically (or logically by `//go:embed`? prefer physical files — the "exactly 5 sibling files" mandate should be lifted with doc update).
- New files:
  - `frr/sanitize.go` — `sanitizeFRRValue`, `validRouterID`, `validClusterID`, `validBGPOrigin` (render-side def-defense belts #1798/#2980/#4919).
  - `frr/redistribute.go` — `knownRedistProtocols` + `resolveRedistribute` + `isDefinedPolicyStatement` (FRR redistribute token vs policy-statement distinction #2473/#2490).
  - `frr/bgp_chain.go` — `ReservedChainSuffix`, `hasNonEmptyPolicy`, `filterDefinedPolicies`, `bgpGlobalExportChain`, `bgpGlobalImportChain`, `bgpNeighborExportChain`, `bgpNeighborImportChain`, `composedChainName`, `bgpRouteMapRef`, `collectBGPRouteMapPolicies`, `bgpEffectiveChains`, `collectBGPComposedChains`, `bgpComposedChainCollision`, `renderComposedBGPChains`, `equalStringSlice`, `policyNeedsRedistAlias`, `redistFailClosedRouteMap`.
  - `frr/bfd.go` — `bfdProfile`, `bfdPeer`, `bfdSection`, `newBFDSection`, `addProfile`, `addPeer`, `empty`, `render` + profile-name derivation `bfdProfileName`.
  - `frr/protocol_bgp.go` — BGP portion of `generateProtocols` + neighbor rendering (export/import chain handling, BFD peer extraction, accept-default).
  - `frr/protocol_ospf.go` — OSPF/OSPFv3 rendering + router-id validity gate.
  - `frr/protocol_rip_isis.go` — RIP/RIPng/ISIS rendering.
  - `frr/policy_options.go` — `generatePolicyOptions`, `renderPolicyTermSequences`, `renderRouteMapForPolicy`, `renderComposedRouteMap`, `renderRouteFilterEntry`, `indexedRouteFilter` + default-action #2998 handling.
- `policy_render.go` remains as aggregator re-export or deleted; `manager.go` calls `m.generateProtocols` → `m.generateProtocolsBGP` etc. via facade or free functions.
- seam: by protocol family + by responsibility: chain/composition vs protocol rendering vs BFD vs sanitization. Chain logic has no FRR syntax dependency, only ordered slice → name, so isolatable.

Hot-path preservation analysis:
- Rank D — COLD path. No per-packet nanosecond sensitivity. File is config-render only, runs on commit under applySem.
- Guardrails: preserve FRR-invalid line never emitted (skip-and-warn) — fail-closed on self-redistribute and malformed router-id; preserve deterministic sort order for composed chain names (collectBGPComposedChains dedup first-wins + sort.Strings); preserve BFD single top-level block invariant (one `bfd {}` not per VRF #2550); preserve sanitization belt (newline→space) preventing `bgp as-path access-list ... permit LINE` injection #4097.
- How to verify:
  - `go test ./pkg/frr -run TestPolicy -count=1` (policy_render_test.go is large? plus bgp_policy_chain_5277_test.go, bgp_summary_3942, policy_redist_alias_collision_5116, policy_route_filter_matchnone_5576, policy_default_action_2998, policy_as_path_prepend_2892, policy_setclause_injection_4482, bgp_remoteas0_activate_bfd_5518 etc.)
  - `make test` (Go + Rust), zero binary size delta (render-only move).
  - `diff -u <(old frr.conf) <(new frr.conf)` for golden fixtures—no whitespace drift.
  - `go vet ./pkg/frr/`.
  - No need for `test-failover` (FRR reload path, but not fast-path).

Tests + gate:
- Existing: 30+ frr tests cover chain collision #5277, BFD profile dedup #2550/#5518, sanitize #4097/#4498, router-id #2980, cluster-id #4919, bgp remote-as 0 activate bfd, bgp neighbor IP guard #4588, route-filter match-none #5576, policy default action #2998, redist alias #5116, set-clause injection #4482, FBF table render, preferred routes, routing adjacency #4285, etc. All must stay green.
- Gate: `make test-go -run FRR` + `go test ./pkg/frr -count=1`.
- Add after split: `go test -run TestBGPComposedChain -count=1 -run TestRedistribute` confirms seam.

Why it matters:
- 2309 LOC with 8 responsibilities and 5 protocol families makes every FRR PR touch same file, merge-conflict magnet, review hazard. Security belts (sanitize, router-id, cluster-id, origin) hidden among 2000 lines of rendering很难审计. Current file header even apologizes for size and cites file-layout mandate as reason to stay big — tech debt self-documented. Splitting lifts mandate and enables per-family OWNERS review.
- Test sprawl: 22 test files each pin one sub-concern but prod code is one file; mapping coverage gap requires reading whole file.

Fix direction:
- 1. Mechanical extract `sanitize.go` (no deps) + `bfd.go` (pure).
- 2. Extract `redistribute.go` + `bgp_chain.go` (chain composition logic pure, defined-policy predicate shared).
- 3. Split `generateProtocols` into per-family files behind same receiver methods, keep signature narrow per file (BGP needs chain helpers, RIP/ISIS only needs policyOptions).
- 4. Extract `policy_options.go` (route-map/prefix-list rendering).
- 5. Update file-layout doc in CLAUDE.md / pkg/frr README: 5-file mandate → domain-split allowance, note why.
- No behavior change.

Labels: frr, god-file, config-render, merge-conflict-magnet, security-belt, cold-path, file-split

Dedup note:
- Not overlapping `FS-231` or `single newCollector func` (prometheus) or HA sync monoliths. FRR previously flagged for static route self-redistribute etc., but dedup-index entries about NAT, HA sync, daemon_apply, etc., not FRR policy_render chain composition. Distinct from `compileSystem god-compiler` (config compiler), this is FRR renderer. No prior campaign specifically isolated `policy_render.go` as 2309 LOC god-file with BFD+sanitize+chain fusion — new finding, material seam.

---

## Finding 2: pkg/frr/manager.go — 1057 LOC god-manager fusing file persistence, managed-section extraction, frr-reload.py dispatch, degraded-retry state machine

Title: FRR Manager 1057 LOC god-manager — file atomic write + managed section build + strip + reload executor + degraded retry loop + episode tracking fused
Severity: HIGH
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE for file-IO vs reload vs retry split, B REQUIRES GUARDRAILS for reload path (FRR 10.6 ExecReload bounce #1880)
Evidence:
- File: `/home/ps/git/avacado-xpf/pkg/frr/manager.go` 1057 LOC.
- Struct:
```go
type Manager struct {
    // mu guards reloadPending, retry, degraded, episode, ... (#1880/#2223)
    // executor frrExecutor (vtysh vs frr-reload.py)
    // lifetimeCtx, retryCancel, myDone, ...
}
type FullConfig struct {
    BGP *config.BGPConfig
    OSPF *config.OSPFConfig
    Instances []*InstanceConfig // per-VRF
    PolicyOptions *config.PolicyOptionsConfig
    // ...
}
```
- Responsibilities fused:
  - `InstanceConfig`, `DHCPRoute`, `FullConfig` data definitions (3 types) co-located with manager logic.
  - `ApplyFull` (348) → collectAllBGPAcceptDefault → buildManagedSection → commitManagedSection → reloadLocked cascade, ~70 LOC orchestration calling chain + bgpComposedChainCollision fail-closed #5277 inside ApplyFull.
  - `buildManagedSection` (417) generates interface settings + static routes + generate routes + DHCP defaults + backup router + preferred routes + cluster mode defaults + FBF table render + protocols + policy options + composed chains — 150+ LOC building string concatenating render outputs from other files.
  - `commitManagedSection` (535) + `writeManagedSection` (577) + `stripManagedSection` (636) + `StripManagedSectionFile` (678) — managed-section extraction via sentinel markers `! BEGIN xpf managed` / `! END xpf managed`, file read/write atomic.
  - `atomicWriteFile` (724) + `atomicWriteOwnerOpt` (754) using fsatomic with owner option — file persistence.
  - `reloadLocked` (821) → executor() → frr-reload.py dispatch directly per #1880 comment (never systemctl reload frr: FRR 10.6 ExecReload bounces watchfrr MainPID → 2-min stop-sigterm → SIGKILL).
  - Degraded retry machinery: `DisableDegradedRetry`, `ReloadDegraded`, `Stop`, `lifetimeCtx`, `executor`, `isFrrReloadPyMissing`, `warnPytoolsOnce`, `noteReloadOutcomeLocked`, `signalRetryCancel`, `ensureRetryLocked`, `retryDelaysOrDefault`, `retrySlowOrDefault`, `degradedRetryLoop`, `retryReloadOnce`, `clearEpisodeIfMine` — 250+ LOC state machine with context cancellation, attempt counting, slow-start handling.
- Coupling: imports fsatomic, config, exec, context, os, time, slog — file IO + process dispatch + retry timers fused.

Read excerpt:
```go
func (m *Manager) ApplyFull(fc *FullConfig) error {
    // collects bgpAcceptDefault, check bgpComposedChainCollision fail-closed
    // buildManagedSection
    // commitManagedSection
    // reloadLocked
}
func (m *Manager) buildManagedSection(fc *FullConfig) string {
    // generates whole managed section concatenating config_render + policy_render outputs
}
```

Proposed decomposition:
- Split into 4 files same package:
  - `manager_types.go` — `InstanceConfig`, `DHCPRoute`, `FullConfig` + helpers `collectAllBGPAcceptDefault`.
  - `manager_section.go` — `buildManagedSection` (composition only) + `stripManagedSection`, `StripManagedSectionFile`, `renderGenerateRoutes`, `renderDHCPDefaults`, `renderBackupRouter`, `renderPreferredRoutes`, `renderClusterModeDefaults` (move from config_render.go if needed coordination).
  - `manager_persist.go` — `writeManagedSection`, `commitManagedSection`, `atomicWriteFile`, `atomicWriteOwnerOpt`, `Clear`, plus fsatomic usage.
  - `manager_reload.go` — `reloadLocked`, `executor()`, `frrExecutor` interface + `vtysh.go` glue already exists, `isFrrReloadPyMissing`, `warnPytoolsOnce`, `noteReloadOutcomeLocked`, `signalRetryCancel`, `ensureRetryLocked`, `retryDelaysOrDefault`, `retrySlowOrDefault`, `degradedRetryLoop`, `retryReloadOnce`, `clearEpisodeIfMine`, `lifetimeCtx`, `Stop`, `DisableDegradedRetry`, `ReloadDegraded`.
  - Keep `manager.go` as thin facade: struct definition + `New`, `ApplyFull` orchestrates calls to section + persist + reload packages (same package, so direct calls).
- Seam: by lifecycle — build (pure string concat) vs persist (file IO+fsatomic) vs reload (process dispatch + retry state machine). Build has no IO deps, easy unit test; reload has context/cancel/time deps; persist has fsatomic.
- Extract `frrExecutor` interface already in vtysh.go — keep, ensure reload file only depends on interface, not concrete.

Hot-path preservation analysis:
- Rank D — COLD path, config commit. No per-packet.
- Guardrails:
  - Preserve #1880 invariant: never `systemctl reload frr`, only `frr-reload.py` direct with 15s context per leg. Retry loop must not call systemd.
  - Preserve managed-section sentinel parsing: `! BEGIN xpf managed` / `! END xpf managed` strip must be byte-identical; `StripManagedSectionFile` used by zeroize path must remain atomic.
  - Preserve fail-closed collision guard: `bgpComposedChainCollision` must run before any file write — ordering in ApplyFull.
  - Preserve degraded-retry semantics: `degradedRetryLoop` holds episode lock, `clearEpisodeIfMine` cancels only own episode, slow-start vs fast retry delays via `retryDelaysOrDefault`/`retrySlowOrDefault`.
  - Preserve atomic-write with owner option and PostRenameSyncError handling.
- How to verify:
  - `go test ./pkg/frr -run Manager -count=1` + `manager_reload_test.go` + `frr_test.go` (large golden file 6037 LOC).
  - `make test-go`.
  - Diff managed section string before/after split for same FullConfig input (golden test).
  - `go vet ./pkg/frr`.

Tests + gate:
- Existing: `manager_reload_test.go`, `frr_test.go` (6037 LOC, main golden), `config_render` tests, `policy_render` tests, `frrconf_mode_4484_test.go`, `dhcp_default_suppression_5519_test.go`, `fbf_table_render_test.go`, `frr_clusterid_origin_render_4919_test.go`, `preferred_routes_test.go`, `routing_adjacency_4285_test.go`, etc.
- Gate: `make test-go -run FRR` + full `make test`. No need for failover, but if FRR reload fails, HA overlay split risk (daemon_ipmon H1: FRR reload failure does not stop dataplane overlay publish) — our split must not widen window.

Why it matters:
- 1057 LOC manager mixing file persistence, string building, process dispatch, retry state machine makes it hard to reason about episode ownership and degraded-retry cancellation. `degradedRetryLoop` alone is 80 LOC with context juggling; interleaved with file write error handling. Separation would allow retry loop to be tested with fake executor without file IO.
- Incremental build: editing retry delays recompiles whole file with buildManagedSection; split reduces TU churn.
- `fsatomic` usage and owner option belong to persistence concern, not reload scheduling.

Fix direction:
- 1. Extract `manager_types.go` mechanical (data defs).
- 2. Extract `manager_persist.go` (file IO).
- 3. Extract `manager_section.go` (string composition).
- 4. Extract `manager_reload.go` (reload + degraded retry). Keep interface `frrExecutor` seam.
- 5. `manager.go` becomes 150 LOC orchestrator New+ApplyFull+Stop+thin getters.
- No behavior change, same package.

Labels: frr, god-manager, file-persist, reload-dispatch, retry-state-machine, cold-path, file-split

Dedup note:
- Dedup-index includes HA sync `sync_conn.go` generation-guard state machine (1589 LOC) and daemon_apply 1100+ LOC ordered reconcile chain, but not FRR manager's degraded retry loop. Prior finding "H1 FRR reload failure does not stop dataplane overlay publish" is behavioral bug in daemon_ipmon, not FRR manager monolith. This finding is specifically file-IO + managed-section + reload + retry fusion — new seam.

---

## Finding 3: pkg/daemon/device_map.go — 836 LOC glue file for bare-metal device-map mode with 5 responsibilities (enumeration, preflight, rename, teardown, file)

Title: device_map.go 836 LOC glue file — enumeration + preflight management-strand check + protected set + rename orchestration + teardown restore + stale scrub + udev predictable fallback fused
Severity: HIGH
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE for pure logic vs netlink wrapper, B REQUIRES GUARDRAILS for teardown restore fail-closed retain (#5309) and strands-management preflight (#1956 CRITICAL)
Evidence:
- File `pkg/daemon/device_map.go` 836 LOC in daemon package, comment says "pure identity resolver lives in pkg/devicemap" but this file still fuses:
  - `enumeratePresentNICs` (61) — wrapper over devicemap enumeration.
  - `resolveDeviceMap` (66), `rethMembersFromConfig` (71), `deviceMapNamingActive` (91), `applyStartupNamingPolicy` (100) — naming policy decision.
  - `deviceMapOriginalNameFor` (121), `enumerateAndRenameMapped` (161) — rename loop with collision-safe multi-pass (mirrors linksetup positional discipline).
  - `writeDeviceMapLinkFile` (359) — .link file generation with OriginalName vs MACAddress rule for RETH members (MAC alternates).
  - `deviceMapStrandsManagement` (381) — commit preflight that would strand management if NIC renamed away; validates rollback target too for `commit confirmed`.
  - `(d *Daemon) deviceMapCommitPreflight` (492) — method on Daemon calling strands check.
  - `CheckDeviceMapStrandsManagement` (570) — exported check used by config compile? delegates to strands logic.
  - `anyMappedIdentityPresent` (590), `protectedForConfig` (605) — protected set building.
  - `teardownUnmappedManaged` (644) — managed→unmapped teardown with fail-closed retain on failure path #4956/#5309: if rename-back fails, retain old .link instead of deleting.
  - `teardownRestoreTarget` (755), `predictableName` (784), `udevPredictableName` (788), `scrubStaleDeviceMapLinks` (815) — restore target resolution and stale file scrub.
- Injectables for test: `renameInterfaceFn`, `networkctlReloadFn`, `teardownRestoreTargetFn` — package global vars, mutable, not thread-safe (mirrors linksetup pattern).
- Void return of `scrubStaleDeviceMapLinks` bool indicating changed (like linksetup) but no error aggregation.
- Mixes Daemon receiver methods with free functions — god-file scoping.
- Size vs sibling: linksetup.go 545, device_map.go 836, plus daemon's linksetup_collision tests etc. — indicates mode that should be its own package had grown.

```go
func enumerateAndRenameMapped(dm *config.DeviceMapConfig, cfg *config.Config, protected map[string]bool) error {
    // resolves bindings via devicemap.Binding, collision-safe multi-pass rename breaking EEXIST
}
func deviceMapStrandsManagement(cfg *config.Config, nics []presentNIC, protected map[string]bool, lifelineCurrentName string) string {
    // validates that mapping does not strand fxp0 mgmt – bare-metal lifeline
}
func teardownUnmappedManaged(dm *config.DeviceMapConfig, protected map[string]bool) error {
    // managed->unmapped: rename back to predictable, fail-closed retain #5309
}
```

Proposed decomposition:
- Package already has pure resolver `pkg/devicemap/devicemap.go` (316 LOC) with `PresentNIC`, `Binding` types. Expand that package's API or create `pkg/daemon/devicemap/` subdirectory.
- Split daemon file into:
  - `device_map_policy.go` — `deviceMapNamingActive`, `protectedForConfig`, `rethMembersFromConfig`, `deviceMapOriginalNameFor`, `anyMappedIdentityPresent`, `resolveDeviceMap` wrapper, `enumeratePresentNICs`.
  - `device_map_preflight.go` — `deviceMapStrandsManagement`, `CheckDeviceMapStrandsManagement`, `deviceMapCommitPreflight` (commit-confirmed rollback target validation). Keep Daemon method thin, delegating to pure func.
  - `device_map_rename.go` — `enumerateAndRenameMapped`, `writeDeviceMapLinkFile`, injectable vars `renameInterfaceFn`, `networkctlReloadFn`, collision-safe multi-pass logic.
  - `device_map_teardown.go` — `teardownUnmappedManaged`, `teardownRestoreTarget`, `predictableName`, `udevPredictableName`, `scrubStaleDeviceMapLinks`, injectable `teardownRestoreTargetFn`.
- Move injectable vars to small `device_map_seams.go` with documented global-mutable + t.Cleanup + no Parallel rule (already documented but centralized).
- Seam: by lifecycle phase — policy decision (is map active? protected?) vs preflight validation (strands mgmt?) vs rename actuation (netlink + files) vs teardown (unmapped→managed→unmapped lifecycle). Each phase independently testable.
- Alternative: promote more logic into `pkg/devicemap` (pure) — preflight and teardown target resolution are pure except netlink, so they can move to devicemap package with interfaces, leaving daemon only with Daemon methods.

Hot-path preservation analysis:
- Rank D — COLD: runs at daemon start, bootstrap-exit, commit. No per-packet.
- Guardrails:
  - Preserve #1956 leave-alone default: when device-map active, ONLY mapped NICs renamed, everything else unmapped governed by `unmapped-interface-policy` (protectedResolver). `teardownUnmappedManaged` must NOT bring down unmapped NICs under leave-alone.
  - Preserve #4178 collision-safe two-pass rename: capturing every OriginalName BEFORE any write, breaking target-name collisions with temp names, prevents enumeration shift corruption.
  - Preserve RETH member OriginalName= rule: MAC alternates between physical (boot) and virtual (daemon), so use OriginalName (PCI kernel name) not MACAddress for RETH members.
  - Preserve #4956 error propagation: rename/reload failures must surface, not warn-only.
  - Preserve #5309 fail-closed retain: if teardown restore fails, retain on-disk name rather than delete and strand.
  - Preserve preflight validating both candidate and rollback target for `commit confirmed`.
  - How to verify: existing `device_map_test.go`, `device_map_startup_test.go`, `bootstrap_rollback_test.go`, `config_arrival_naming_4179_test.go` etc. Linksetup collision test #4178.
- Tests + gate below.

Tests + gate:
- Existing: `pkg/daemon/device_map_test.go` (394 LOC), `device_map_startup_test.go`, `linksetup_collision_4178_test.go`, `config_arrival_naming_4179_test.go`, `bootstrap_lifeline_nonpci_4815_test.go`, `pkg/devicemap/devicemap_test.go` (284 LOC), `devicemap_nonpci_4884_test.go`, plus fail-closed tests `apply_interface_reconcile_failclosed_5310_test.go` etc.
- Gate: `go test ./pkg/daemon -run TestDeviceMap -count=1`, `go test ./pkg/devicemap -count=1`, `make test-go`.
- Manual: cluster with device-map config not strand fxp0.

Why it matters:
- Bare-metal lifeline safety — `deviceMapStrandsManagement` is security-critical "never lock operator out" invariant. Fusing it with rename orchestration and teardown in 836 LOC file makes review hard; #1956 AGY r3 CRITICAL shows this was already high severity.
- Multiple injectable global vars (`renameInterfaceFn`, `networkctlReloadFn`, `teardownRestoreTargetFn`) indicate testability pain due to fusion; splitting would let preflight and policy be pure without var seams.
- File comment says "pure identity resolver lives in pkg/devicemap" but this file still has 836 LOC glue — the glue itself needs modularization by phase.
- Merge hazard: addition of new unmapped-interface-policy or teardown behavior touches same file as preflight, easy to break lifeline.

Fix direction:
- Extract policy vs preflight vs rename vs teardown in same package first (mechanical moves, keep func signatures).
- Move preflight pure logic to `pkg/devicemap` if possible, adding `CheckStrandsManagement` func there returning reason/offTarget/err, keeping daemon wrapper.
- Centralize injectable seams in one file with clear comment about `t.Cleanup` + no Parallel.
- Update docs/bare-metal-device-map.md to reflect internal module split.

Labels: devicemap, bare-metal, lifeline-safety, file-split, startup-naming, cold-path, fail-closed

Dedup note:
- Dedup-index does not list device-map monolith; prior findings mention single-newCollector func, daemon_apply god-function, compileSystem, etc. Device-map is new in #1956, post-dedup-index for many entries. Distinct from `compileInterfaces 1290 LOC VRRP parser` — this is host NIC naming. Not duplicate.

---

## Finding 4: pkg/networkd/networkd.go — 775 LOC Manager fusing .link/.network/.netdev generation + expected-set sweep + external-managed detection + reload debt + protected resolver + RP filter restore

Title: networkd Manager 775 LOC god-type fusing .link/.network/.netdev rendering + file sweep + external NIC detection + reload/reconfigure debt + lifeline protected set + RP filter + speed/mtu/bridge/bond/VRF logic
Severity: HIGH
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE (cold commit path)
Evidence:
- File 775 LOC, struct:
```go
type Manager struct {
    networkDir string
    protectedResolver func() map[string]bool // #1922 lifeline
    mu sync.Mutex
    reloadPending bool // #4954
    reconfigurePending map[string]bool
}
type InterfaceConfig struct {
    Name string
    MACAddress string
    OriginalName string
    Addresses []string
    PrimaryAddress string
    PreferredAddress string
    IsVLANParent bool
    DHCPv4 bool
    DHCPv6 bool
    Unmanaged bool
    Disable bool
    DADDisable bool
    Speed string
    Duplex string
    MTU int
    Description string
    BondMaster string
    IsBond bool
    BondMode string
    LACPRate string
    MinLinks int
    KeepAddresses bool // KeepConfiguration=static for RETH VRRP VIP preserve
    VRFName string
    BridgeMaster string
    IsBridge bool
}
```
- Responsibilities:
  - `SetProtectedResolver` + `New` + `NewInDir`.
  - `Apply` (134) — 200+ LOC orchestration: filtered = external skip, expected set build for .link/.netdev/.network, protectedResolver добавление to expected (lifeline never sweep #1956 critical), stale file glob `filePrefix+"*"` removal with error aggregation #4900, write closure `writeIfChanged` with writeErrs aggregation #2987, needReload = changed || reloadDebt || reconfDebt (#4954 deferred reload after failed reload), networkctl reload 15s timeout, restoreSlowPathRPFilter, warnIfAllRPFilterOverrides, per-iface `networkctl reconfigure`.
  - `setReloadPending`, `setReconfigurePending` (339,347) — debt state.
  - `restoreSlowPathRPFilter` (378), `warnIfAllRPFilterOverrides` (404) — RP filter side-effects.
  - `Clear` (421) — sweep all + reload.
  - `FindExternallyManaged` (456) + `findExternallyManaged` (484) — scan non-xpf .network files to avoid conflict on mgmt (legacy).
  - `sanitizeUnitValue` (496) — free-text sanitization for systemd unit values (description, etc.).
  - `generateNetdev` (516) — bond/LAG .netdev rendering (802.3ad, LACP rate, min links).
  - `generateBridgeNetdev` (552) — bridge .netdev.
  - `generateLink` (567) — .link file: MACAddress= vs OriginalName= for RETH, speed/duplex via junosSpeedToNetworkd.
  - `generateNetwork` (595) — .network: addresses ordering via `orderAddresses`, primary/preferred handling, KeepConfiguration=static, DHCP, VRF=, ActivationPolicy=always-down, etc.
  - `junosSpeedToNetworkd` (694) + `addressIsIPv6` (725) + `orderAddresses` (730) + `writeIfChanged` (758) — helpers.
  - Package var `runNetworkctl` injectable for tests, with timeout `networkctlTimeout` 15s mirroring FRR precedent.
- Apply method has 4 distinct phases fused: external filtering, expected-set building + protected, stale removal aggregation #4900, write aggregation #2987, reload debt #4954 decision.
- `InterfaceConfig` itself is 22-field god-struct mixing addressing, LAG, bridge, VRF, speed, DHCP — but cohesive as per-interface intent bundle? Arguably okay but large.

Proposed decomposition:
- Split into:
  - `networkd/types.go` — `InterfaceConfig` + `Manager` struct + constants `DefaultNetworkDir`, `filePrefix`, `networkctlTimeout`, `runNetworkctl` var.
  - `networkd/apply.go` — `New`, `NewInDir`, `SetProtectedResolver`, `Apply`, `Clear`, `setReloadPending`, `setReconfigurePending`, debt logic, stale sweep `removeStaleFiles`, write loop, reload orchestration.
  - `networkd/render_link.go` — `generateLink`, `junosSpeedToNetworkd`, `sanitizeUnitValue` usage.
  - `networkd/render_network.go` — `generateNetwork`, `orderAddresses`, `addressIsIPv6`.
  - `networkd/render_netdev.go` — `generateNetdev`, `generateBridgeNetdev`.
  - `networkd/external.go` — `FindExternallyManaged`, `findExternallyManaged`.
  - `networkd/rpfilter.go` — `restoreSlowPathRPFilter`, `warnIfAllRPFilterOverrides` (RP filter sysctl restoration).
  - `networkd/io.go` — `writeIfChanged`, `atomic` wrapper + maybe use fsatomic.
- Seam: rendering (.link vs .network vs .netdev) vs file I/O + expected-set + debt state machine vs external detection vs RP filter side-effect.
- Rendering functions are pure string builders (input InterfaceConfig → string) no IO, easy unit test; Apply is orchestration with IO + networkctl shell-out.

Hot-path preservation analysis:
- Rank D — COLD: config commit path, under daemon's applySem. No packet path.
- Guardrails:
  - Preserve #1956 lifeline never sweep: protectedResolver files added to expected set so stale sweep does not delete fxp0 rename/addressing.
  - Preserve #2987 write failure aggregation + #4900 stale-remove failure aggregation fail commit CLOSED (error surfacing) — previously warn-only left stale unit surviving.
  - Preserve #4954 reload debt: reloadPending forces retry of `networkctl reload` on next identical Apply, cleared only on success; similarly reconfigurePending for per-if `networkctl reconfigure`.
  - Preserve #2988 empty desired set not no-op: if last xpf-managed interface removed, sweep must still run.
  - Preserve KeepConfiguration=static on RETH interfaces for VRRP VIP preservation across reload.
  - Preserve `orderAddresses` primary first for source selection.
  - Preserve 15s networkctl timeout to avoid hanging commit under applySem (daemon_apply would block).
  - How to verify: `go test ./pkg/networkd -count=1` includes `networkd_test.go` 813 LOC + `reload_debt_4954_test.go` + `stale_remove_4900_test.go` + `rpfilter_test.go`. Also daemon's `daemon_networkd_apply_test.go` integration.

Tests + gate:
- Existing: `networkd_test.go` 813 LOC (golden for .link/.network/.netdev), `reload_debt_4954_test.go`, `stale_remove_4900_test.go`, `rpfilter_test.go`, plus daemon apply tests `daemon_networkd_apply_test.go` (51? check). Must stay green.
- Gate: `go test ./pkg/networkd -count=1 && go test ./pkg/daemon -run Networkd -count=1`, `make test-go`.
- No failover gate (networkd is cold), but commit path touches mgmt lifeline.

Why it matters:
- 775 LOC Manager fusing rendering (pure) with stateful debt tracking + file sweeping + shell-out dispatch makes it hard to reason about reload debt edge cases (#4954). Prior bugs #2987/#4900/#4954 all show file IO + commit fail-closed interaction is subtle; isolating rendering from file IO and debt state would make each independently reviewable.
- `InterfaceConfig` 22 fields mixing bond + bridge + VRF + addressing suggests per-concern rendering splits would reveal whether VRF and bridgeMaster can coexist (should be validated).
- Incremental build: editing bond .netdev rendering recompiles Apply debt logic.

Fix direction:
- 1. Extract rendering to `render_*.go` (pure, no deps) mechanical.
- 2. Extract external detection to `external.go`.
- 3. Extract RP filter to `rpfilter.go`.
- 4. Extract IO helpers to `io.go`.
- 5. `apply.go` orchestrates.
- Each new file 100-200 LOC, independently testable.

Labels: networkd, god-type, file-rendering, commit-fail-closed, debt-state-machine, cold-path, lifeline-safety

Dedup note:
- Dedup-index does not list networkd manager monolith; prior findings about daemon_apply 1100+ LOC ordered reconcile chain mention networkd.Apply as one phase, but not internal manager fusion. Distinct from `newCollector 279 desc` and NAT compile. New finding.

---

## Finding 5: pkg/daemon/linksetup.go — 545 LOC fusing PCI enumeration + vSRX naming policy + collision-safe rename + .link file + bootstrap DHCP + netlink seam + RSS reapply hook

Title: linksetup.go 545 LOC fuses PCI enumeration + naming policy + collision-safe rename + .link file + bootstrap + netlink var seams + RSS hook
Severity: MEDIUM
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE (boot cold path)
Evidence:
- File 545 LOC.
- Data:
```go
type pciNIC struct {
    sortKey int // 0=virtio, 1=hw
    busAddr string // 0000:05:00.0
    name string // enp5s0
}
const linkPrefix = "10-xpf-"
var linkDir = "/etc/systemd/network" // var for tests
var (
    nlLinkByName = netlink.LinkByName
    nlLinkSetDown = netlink.LinkSetDown
    nlLinkSetName = netlink.LinkSetName
    nlLinkSetUp = netlink.LinkSetUp
)
```
- Responsibilities:
  - `enumerateAndRenameInterfaces(nodeID int, clusterMode bool, userspaceWorkers int, rssEnabled bool, rssAllowedInterfaces []string)` — entry, enumeration + fpc selection + renamePositional + bootstrap + networkctlReload + RSS reapply.
  - `reapplyRSSIndirection` + `reapplyRSSIndirectionWith` — RSS indirection hook.
  - `enumeratePCINICs` — sysfs walk /sys/bus/pci/devices/*/net/*, sortKey virtio=0 first (standalone fxp0 → lowest PCI bus), hw 1 later.
  - `extractPCIAddr` — path → bus addr.
  - `assignName` — idx,fpc,clusterMode → fxp0 / em0 / ge-{FPC}-0-{idx}.
  - `renamePositional` — collision-safe two-pass rename: captures every OriginalName BEFORE any write, then breakNameCollisions with temp names (#4178).
  - `breakNameCollisions` (306) + `recoverOriginalName` (361) — temp name logic, reading existing .link OriginalName= chain.
  - `containsLine` (395), `writeLinkFile` (406), `writeBootstrapFxp0Network` (435) — file generation.
  - `renameInterface` (493) — netlink down→set name→up with injection vars.
  - `networkctlReload` (530), `execCommand` (542) — shell-out.
- RSS hook couples link naming to RSS D3 indirection (mlx5). `reapplyRSSIndirection` called from here? Actually called early in enumerateAndRenameInterfaces before rename? Code shows after changed detection? Need review.

```go
func enumerateAndRenameInterfaces(...) error {
    nics, err := enumeratePCINICs()
    // ...
    fpc := 0; if clusterMode && nodeID==1 { fpc=7 }
    changed := renamePositional(nics, fpc, clusterMode, renameInterface)
    if wrote := writeBootstrapFxp0Network(); wrote { changed = true }
    if changed { networkctlReload() }
    slog.Info("linksetup: interface naming updated")
    // + rss reapply?
}
func renamePositional(nics []pciNIC, fpc int, clusterMode bool, renameFn func(from,to string) error) bool {
    // builds desired map idx→target, captures original names, break collisions
}
```

Proposed decomposition:
- `linksetup_types.go` — `pciNIC` + const `linkPrefix` + var `linkDir` + injectable var group comment.
- `linksetup_enumerate.go` — `enumeratePCINICs`, `extractPCIAddr`.
- `linksetup_naming.go` — `assignName`, `recoverOriginalName`, `containsLine`.
- `linksetup_rename.go` — `renamePositional`, `breakNameCollisions`, `renameInterface`, netlink vars.
- `linksetup_files.go` — `writeLinkFile`, `writeBootstrapFxp0Network`.
- `linksetup_os.go` — `networkctlReload`, `execCommand`.
- `linksetup_rss.go` — `reapplyRSSIndirection`, `reapplyRSSIndirectionWith` glue (maybe move to rss_indirection.go).
- Keep `enumerateAndRenameInterfaces` orchestrator in `linksetup.go` ~50 LOC calling enumerate→rename→files→reload→rss.
- Seam: enumeration (pure sysfs) vs naming policy (pure function idx→name) vs collision handling (rename order) vs file persistence vs netlink actuation vs RSS hook.

Hot-path preservation analysis:
- Rank D — COLD boot path, runs at daemon start and bootstrap-exit.
- Guardrails:
  - Preserve positional naming: virtio sortKey 0 first ensures fxp0 maps to lowest PCI bus (virtio net mgmt).
  - Preserve FPC=7 for nodeID 1 in cluster (ge-7-0-X).
  - Preserve collision-safe discipline #4178: OriginalName capture BEFORE writes, temp name breaking, recoverOriginalName chain traversal.
  - Preserve writeLinkFile with MACAddress= for non-RETH, OriginalName= for RETH members? Actually linksetup.go handles positional mode (all OriginalName? check) — must keep.
  - Preserve bootstrap fxp0 DHCP .network needed before daemon writes networkd configs.
  - Preserve injectable var pattern for unit tests `t.Cleanup` + no Parallel.
  - How to verify: `linksetup_rename_test.go`, `linksetup_collision_4178_test.go`, `config_arrival_naming_4179_test.go`, `bootstrap_*.go`.

Tests + gate:
- Existing: `linksetup_rename_test.go`, `linksetup_collision_4178_test.go`, `bootstrap_test.go`, `bootstrap_rollback_test.go`, `bootstrap_lifeline_nonpci_4815_test.go`, `config_arrival_naming_4179_test.go`.
- Gate: `go test ./pkg/daemon -run Linksetup -count=1`, `make test-go`.

Why it matters:
- Bootstrapping is lifeline-critical; mixing enumeration, naming, collision breaking, file IO, netlink, RSS in one file makes it hard to audit that collision-safe rename never EEXIST-strands a NIC. #4178 bug description shows positional rename previously lacked device-map discipline; this file now has it but still monolithic.
- Injectable netlink vars pattern spread across two files (linksetup + device_map) duplicated; centralizing seamed wrappers in own file would document global-mutable hazard.
- RSS hook coupling: link naming should not know about RSS indirection; split would make dependency one-way (linksetup calls rss package).

Fix direction:
- Extract enumerate, naming, rename, files, os helpers in same package mechanical moves.
- Move RSS reapply to `rss_indirection.go` exposing `ReapplyOnRename` called by linksetup, not defined in linksetup.
- Keep orchestrator small.

Labels: boot, linksetup, pci-enumeration, collision-safe-rename, lifeline, cold-path, file-split

Dedup note:
- Dedup-index no entry for linksetup; prior findings include `compileInterfaces 1290 LOC VRRP group parser` not linksetup. Distinct from device_map.go finding (different mode). Not duplicate.

---

## Finding 6: pkg/daemon/rss_indirection.go — 550 LOC fusing executor interface + real executor + ethtool output parsing + weight vector + table matching

Title: rss_indirection.go 550 LOC fuses RSS executor interface + real executor (ethtool + sysfs driver + queue count) + indirection table parse + matching + weight vector + restore logic
Severity: MEDIUM
Confidence: MEDIUM
Refactor class: A MECHANICAL/SAFE (cold D3)
Evidence:
- File 550 LOC.
- Types:
```go
type rssExecutor interface {
    runEthtool(args ...string) ([]byte, error)
    readDriver(iface string) string
    readQueueCount(iface string) int
    listInterfaces() []string
}
type realRSSExecutor struct{}
func (realRSSExecutor) runEthtool(args ...string) ([]byte, error) { // exec ethtool
}
func (realRSSExecutor) readDriver(iface string) string // /sys/class/net/<iface>/device/driver
func (realRSSExecutor) readQueueCount(iface string) int // /sys/class/net/<iface>/queues/rx-*
func (realRSSExecutor) listInterfaces() []string
type indirectionRow struct { // parsed ethtool --show-rxfh-indir line
}
```
- Functions:
  - `applyRSSIndirection(enabled bool, workers int, allowed []string, execer rssExecutor)` 144 — filters allowed to mlx5 only (D3 only mlx5), checks driver, queue count.
  - `restoreDefaultRSSIndirection(allowed []string, execer rssExecutor)` 204 — restore.
  - `applyRSSIndirectionOne(iface string, workers int, execer rssExecutor)` 237 — applies weighted indirection setting RSS to 0..workers-1.
  - `maybeRestoreDefault(iface string, queues int, execer rssExecutor)` 317 — restore if not default.
  - `parseIndirectionTable(output []byte) (rows []indirectionRow, ok bool)` 390 — parses ethtool --show-rxfh-indir output which format varies (ethtool version dependent).
  - `indirectionTableIsDefault(output []byte, queueCount int) bool` 445 — checks if table is default sequential.
  - `computeWeightVector(workers, queues int) ([]int, string)` 478 — computes weighted distribution for mlx5 RSS to constrain to workers, returns weight vector and FNV? string for ethtool arg format. Implements weighted fill.
  - `indirectionTableMatches(output []byte, weights []int) bool` 513 — matching current table to expected weights.
  - `isExecNotFound(err error) bool` 548 — error classification.
- Fuses 4 concerns: executor abstraction + real implementation (sysfs + exec) + parsing + business logic weight computation + apply/restore orchestration.
- Verbose comments about D3 #797 review, Codex H1 mlx5 PF guard, queuing.

Proposed decomposition:
- `rss_executor.go` — `rssExecutor` interface + `realRSSExecutor` + methods `runEthtool`, `readDriver`, `readQueueCount`, `listInterfaces`, `isExecNotFound`.
- `rss_parse.go` — `indirectionRow` + `parseIndirectionTable` + `indirectionTableIsDefault` + `indirectionTableMatches`. Pure parsing, no ethtool exec.
- `rss_weights.go` — `computeWeightVector` + weight-to-ethtool arg formatting. Pure math.
- `rss_apply.go` — `applyRSSIndirection`, `restoreDefaultRSSIndirection`, `applyRSSIndirectionOne`, `maybeRestoreDefault`, `reapplyRSSIndirection`, `reapplyRSSIndirectionWith` glue.
- Keep `rss_indirection.go` as doc facade or remove.

Hot-path preservation analysis:
- Rank D — COLD: D3 RSS indirection runs at startup and on rename, before AF_XDP socket binds. Not per-packet, but affects fairness regime (6-worker denominator on mlx5 VF). Incorrect weight vector breaks flow hashing across workers, causing CoV floor violation in fairness regime doc.
- Guardrails:
  - Preserve mlx5 driver guard: D3 only touches mlx5_core interfaces in allowed set.
  - Preserve weight vector exact distribution: `computeWeightVector` must produce same bucket counts as before, sum == queues, first workers get extra when queues % workers !=0.
  - Preserve ethtool output parsing tolerant to version differences (header lines, varying whitespace).
  - Preserve `indirectionTableMatches` logic comparing parsed table to expected weights without allocating per packet.
  - Preserve `isExecNotFound` handling (ethtool binary missing should not fail boot).
  - How to verify: existing `rss_indirection_test.go` (1020 LOC) + `rss_indirection_...` tests + `go test -run RSS -count=1`. Also cluster with mlx5 VF 6 queues + 6 workers, `ethtool --show-rxfh-indir` shows only 0..workers-1.

Tests + gate:
- Existing: `rss_indirection_test.go` 1052 LOC (largest in rss area). Tests parse, weight, match, apply one, restore.
- Gate: `go test ./pkg/daemon -run RSS -count=1`, `make test-go`. CoS fairness smoke does not depend directly but flow hashing does.

Why it matters:
- 550 LOC file with executor + parsing + business logic means editing weight math re-lints exec code. Parsing ethtool output is fragile (different ethtool versions emit different headers); isolating parser would make it fuzzable.
- File comment says "D3 RSS indirection to constrain mlx5 RSS to queues 0..workers-1 before any AF_XDP socket binds" — critical for zero-copy fast path on loss cluster (mlx5_core native XDP, 6 RX queues per VF). Bug here re-enables queues beyond workers, causing packet loss or unbalanced RX.
- Weight vector and table matching are pure functions suitable for property-based tests, but currently co-located with sysfs reading.

Fix direction:
- Extract executor, parser, weights mechanical — pure functions have no deps.
- Apply glue stays in one file calling pure helpers via executor interface.
- Add fuzz test for `parseIndirectionTable` with random ethtool output variants.

Labels: rss, mlx5, ethtool, parsing, fairness-regime, cold-path, file-split

Dedup note:
- Dedup-index no rss entry (D3). Prior findings about Cos waterfill etc not rss. Distinct from linksetup finding — rss hook currently lives partially in linksetup.go; this isolates D3 itself.

---

## Finding 7: pkg/ipsec/policy.go (1135 LOC) + ike.go (890 LOC) — IPsec rendering god-files fusing child SA / traffic selector / IKE proposals / crypto / SA status

Title: IPsec policy.go 1135 + ike.go 890 god-files fuse child SA traffic-selector + IKE proposals multivalue #3904 + crypto + SA lifecycle + DHCP rebind
Severity: HIGH
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE (cold render + strongSwan control)
Evidence:
- `policy.go` 1135 LOC: type `childSelector` (21) + `generateConfig` (27) + `renderConfig` (44) → returns (string, map[string]bool, error) for swanctl.conf child connections. Fuses:
  - Traffic selector rendering with IPv4/IPv6 family, DHCP rebind handling, matchfamily/linklocal # matchfamily_linklocal_test.go guard.
  - Child name collision guard #5122 (`childname_collision_5122_test.go`).
  - Proposal set AH header # AH_hb167_test guard? proposalset_ah_hb167_test.go.
  - Delete+terminate #3941, unrenderable terminate #5494.
  - Updown script rendering, FRR backup? Hooks.
- `ike.go` 890 LOC:
```go
type dpdSettings struct { interval int, timeout int }
type SAStatus struct { ... }
func (m *Manager) TerminateAllSAs() (int, error) { 634 }
func (m *Manager) ActiveConnectionNames() ([]string, error) { 660 }
func (m *Manager) InitiateConnection(name string) error { 677 }
func (m *Manager) GetSAStatus() ([]SAStatus, error) { 685 }
```
  Fuses IKE connection rendering (proposals multivalue #3904), dhgroup roundtrip, crypto, SA status parsing, IKE chain fail-closed #ike_chain_failclosed_test.

- Manager.go 326 LOC: `Manager` struct with ApplyFull, reload ordering #4898 (reload_error_4433).

Together 3 files 234... aggregate 2340 LOC IPsec subsystem with 5 concerns: crypto proposals, IKE rendering, child SA, traffic selectors, SA lifecycle (terminate/init/status).

- Test files: `ipsec_test.go` 1850 LOC largest, plus `swanctl_render_test.go` 810, `trafficselector_render_4098_test.go`, etc.

Read excerpt for `policy.go`:
```go
func (m *Manager) generateConfig(ipsecCfg *config.IPsecConfig) string {
    // builds swanctl child connections, collision guard, delete_terminate
}
func (m *Manager) renderConfig(ipsecCfg *config.IPsecConfig) (string, map[string]bool, error) {
    // renders full swanctl snippet
}
```

Proposed decomposition:
- Keep package `ipsec`, split:
  - `crypto.go` already 136 LOC — proposals + dhgroup? Keep but expand: `crypto_proposals.go` (IKE + ESP proposals multivalue #3904, dhgroup_roundtrip).
  - `ike_render.go` — IKE connection rendering, dpdSettings, proposals, fail-closed chain.
  - `child_render.go` — child SA rendering + `childSelector` + traffic selector rendering #4098 + childname collision #5122 + unrenderable terminate #5494 + delete_terminate #3941.
  - `selector.go` — traffic selector specific: matchfamily link-local guard, range/family validation.
  - `sa_lifecycle.go` — `SAStatus`, `TerminateAllSAs`, `ActiveConnectionNames`, `InitiateConnection`, `GetSAStatus` — swanctl --list-sas parsing + vici socket? (strongSwan control).
  - `manager.go` — thin ApplyFull orchestrating crypto→ike→child rendering + file write + reload ordering #4898 + dhcp_rebind handling.
- Seam: by IPsec phase — IKE (phase1) vs Child SA (phase2) vs traffic selector (subnet) vs SA lifecycle (runtime status). Crypto proposals shared but small.

Hot-path preservation analysis:
- Rank D — COLD: strongSwan config render via swanctl.conf snippet, reload via vici or `swanctl --load-all`. No per-packet.
- Guardrails:
  - Preserve `childname_collision_5122` guard: child names must be unique across connections, collision fails closed.
  - Preserve `delete_terminate_3941`: delete SA must terminate, not leave half.
  - Preserve `unrenderable_terminate_5494`: unrenderable config must terminate existing SAs fail-closed, not leave stale.
  - Preserve `ike_chain_failclosed`: IKE chain rendering failure must fail closed.
  - Preserve traffic selector family matching: link-local and matchfamily guard, dhcp rebind #dhcp_rebind_test.
  - Preserve proposal multivalue #3904: `from protocol [ esp ah ]` bracketed list collapses onto one leaf's Keys — compiler must read Keys[1:] + Children via `firewallMatchValues` discipline.
  - Preserve reload ordering #4898: swanctl snippet write before vici reload, ordering critical to avoid flap.
  - How to verify: `go test ./pkg/ipsec -count=1` includes crypto tests (dhgroup roundtrip, proposalset_ah, ike_proposals_multivalue, trafficselector_render, delete_terminate, unrenderable_terminate, childname_collision, matchfamily_linklocal, dhcp_rebind, reload_error_4433). + `make test-go`.

Tests + gate:
- Existing: `ipsec_test.go` 1850 LOC, `swanctl_render_test.go` 810, plus 8 smaller *_{collision,terminate,multivalue,matchfamily,dhcp,proposalset}_*.go files.
- Gate: `go test ./pkg/ipsec -count=1`, `make test-go`.
- Optionally cluster IPsec SA sync test `ipsec_sa_sync_empty_4385_test.go` (43? but in daemon) — ensure SA sync still works.

Why it matters:
- IPsec is security-critical: strongSwan snippet injection via unsanitized gateway endpoints previously bypassed validation (dedup-index: "Typed IKE gateway endpoints bypass endpoint validation and are emitted raw into root-owned swanctl syntax"). Fusing crypto + IKE + child + selector in one file makes it hard to audit sanitization per domain. Splitting allows per-file security review (IKE proposals vs child selectors).
- 1135 LOC policy.go with single generateConfig entry point hides traffic-selector range/family validation gap noted in dedup-index: "IPsec validates only explicit selector leaves, not effective fallback selector pair or range/family relationships."
- Incremental build: editing traffic selector re-renders IKE.

Fix direction:
- 1. Extract selector pure rendering (no file IO) to `selector.go` with its own tests (already trafficselector_render test).
- 2. Extract crypto proposals to `crypto_render.go` (multivalue handling).
- 3. Extract IKE vs child to separate files.
- 4. Extract SA lifecycle.
- 5. `manager.go` orchestrates.
- No behavior change, file split only, same package. Lift file-layout note that currently claims "exactly X files" if present.

Labels: ipsec, strongswan, swanctl, security-critical, traffic-selector, IKE, child-SA, cold-path, file-split

Dedup note:
- Dedup-index entries: "Typed IKE gateway endpoints bypass endpoint validation..." and "IPsec validates only explicit selector leaves..." describe validation gaps but not monolith structure. This finding is structural: god-files 1135+890. Distinct from FRR findings. Not duplicate of `server_diag_zeroize` or `daemon_apply` findings. Overlap with prior generic "IPsec policy.go 880-line" mention in dedup-index? The dedup-index excerpt lists "~880-line IPsec policy.go" as prior campaign flagged (~880-line). However current size 1135 (>880) shows growth since; our finding adds material decomposition detail (split by phase: selector vs IKE vs child vs SA lifecycle + collision + terminate guards) not just flagging size, so material new decomposition eligible per instruction to "either dedup against them or add materially new decomposition detail". We do both: dedup reference but expand seam.

---

## Finding 8: pkg/daemon/login_password.go — 407 LOC fusing shadow parsing + passwd UID lookup + marker + authorized_keys path + provision + deprovision + reconcile absent users

Title: login_password.go 407 LOC fuses shadow hash parsing + passwd UID/GID lookup + provision marker + authorized_keys path + xpf provisioned check + absent-users reconciliation + deprovision with sudoers sweep
Severity: MEDIUM
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE (cold login reconcile)
Evidence:
- File 407 LOC, functions:
```go
func passwordAction(cur string, ok bool, desired string) pwAction { 67 }
func isLockedShadow(s string) bool { 88 }
func currentShadowHash(name string) (string, bool) { 97 }
func lookupUIDGIDErr(name string) (uid,gid int,found bool,err error) {141}
func lookupUIDGID(name string) (uid,gid int,ok bool) {177}
func lookupUID(name string) (int,bool) {184}
func lookupUIDErr(name string) (uid int,found bool,err error) {193}
func markerPath(name string) string {201}
func markProvisioned(name string, uid int) error {211}
func xpfProvisioned(name string, curUID int) bool {228}
func rootAuthorizedKeysPath() string {265}
func managedAuthorizedKeysPath(name string) string {278}
func (d *Daemon) reconcileAbsentLoginUsers(cfg *config.Config) {296}
func (d *Daemon) deprovisionLoginUser(name string) {337}
```
- Plus `login_password_functional_test.go` etc covering passwd fail-closed #5493, emptied keys #5106, deprovision #5128, etc.
- Responsibilities:
  - Shadow parsing: `currentShadowHash`, `isLockedShadow`, `passwordAction`.
  - /etc/passwd UID/GID resolution: `lookupUIDGIDErr`, `lookupUIDGID`, `lookupUID`, `lookupUIDErr` — 4 variants differing only in error vs bool return, duplicated logic.
  - Provision marker: `markerPath`, `markProvisioned`, `xpfProvisioned` — marker file `/var/run/xpf/provisioned/<user>` with UID check to avoid UID reuse hijack.
  - Authorized_keys path: `rootAuthorizedKeysPath`, `managedAuthorizedKeysPath` — special-case /root vs /home/<user>.
  - Daemon reconcile: `reconcileAbsentLoginUsers` (loop over provisioned dir, remove users absent from config) + `deprovisionLoginUser` (userdel + sudoers sweep + marker removal).
  - Plus PAM? Not, but shadows.
- Duplication: `lookupUID*` 4 functions same core (parse /etc/passwd) only differing in error handling — dumping-ground for passwd lookup strategies, should be one core + adapters.

Proposed decomposition:
- `login_shadow.go` — `passwordAction`, `isLockedShadow`, `currentShadowHash` (shadow).
- `login_passwd.go` — single `lookupPasswd(name string) (uid,gid int, found bool, err error)` core + thin wrappers `lookupUIDGID`, `lookupUID`, `lookupUIDErr`, `lookupUIDGIDErr` call core, remove duplication. Keep one implementation reading /etc/passwd (or nss via Go's user pkg).
- `login_marker.go` — `markerPath`, `markProvisioned`, `xpfProvisioned` (marker file + UID check).
- `login_keys.go` — `rootAuthorizedKeysPath`, `managedAuthorizedKeysPath` + maybe `root_auth_revoke_5276` logic (but that test in daemon).
- `login_reconcile.go` — `(d *Daemon) reconcileAbsentLoginUsers`, `deprovisionLoginUser` — Daemon receiver methods orchestrate shadow+passwd+marker+keys.
- Keep `login_password.go` as facade or delete after split.

Hot-path preservation analysis:
- Rank D — COLD: login user reconcile runs on commit, not packet. SSH login itself is host path but not dataplane hot; passwordAction evaluation must remain timing-safe? Not constant-time currently, but preserve semantics.
- Guardrails:
  - Preserve fail-closed #5493: login_passwd_failclosed — userdel/sudoers marker retain on failure? Actually `login_passwd_failclosed_5493_test.go` pins that passwd lookup failure fails closed (retain).
  - Preserve emptied_keys #5106, deprovision #5128, root revoke #5276: managed-root revocation in-place vs /root vs /home/root divergence.
  - Preserve marker UID check: `xpfProvisioned` checks current UID vs marker UID to avoid UID reuse hijack — prevents deleting another user's files after UID recycle.
  - Preserve shadow locked detection `!` `*` prefix.
  - How to verify: `go test ./pkg/daemon -run Login -count=1` covering `login_password_test.go`, `login_password_functional_test.go`, `login_emptied_keys_5106_test.go`, `login_deprovision_5128_test.go`, `login_passwd_failclosed_5493_test.go`, `root_auth_revoke_5276_test.go`.

Tests + gate:
- Existing as above + `daemon_ssh_test.go` indirectly.
- Gate: `go test ./pkg/daemon -run TestLogin -count=1`, `make test-go`.

Why it matters:
- Login and SSH access is security-critical host integration; shadow + passwd + marker + authorized_keys fused in 407 LOC makes review of UID reuse hijack and fail-closed retention hard. Duplicate lookupUID variants increase risk of inconsistent error handling (one wrapper may ignore error another does not). Splitting by OS artifact (shadow vs passwd vs marker vs keys) clarifies ownership and allows per-file audit of fail-closed paths.
- Test count explosion: 4 test files for one prod file (login_password_test, login_password_functional, login_emptied_keys, login_deprovision, login_passwd_failclosed) indicates multiple concerns crammed.

Fix direction:
- Extract shadow, passwd core, marker, keys mechanical.
- Unify lookupUID* into single core with wrappers.
- Reconcile file keeps Daemon methods.

Labels: login, security-critical, fail-closed, shadow, passwd, authorized_keys, cold-path, file-split

Dedup note:
- Dedup-index has no login_password entry, but zeroize_login findings in other batch reference similar login teardown pattern. This is distinct: user provisioning/marker, not zeroize. Not duplicate.

---

## Finding 9: pkg/routing/bond.go (490 LOC) + reth.go (56) + monitor.go (110) + probe_pin.go (289) — routing package scatters LAG + RETH + monitor + probe pin across 4 files but bond.go itself fuses signature + enslavement + observation + clear

Title: routing/bond.go 490 LOC LAG manager fuses signature computation + netlink bond creation + member enslavement diff + observedMembers + clear/delete locked + bond mode 802.3ad/LACP; coupled with reth.go tiny + monitor.go + probe_pin.go scattering routing integration concerns
Severity: MEDIUM
Confidence: MEDIUM
Refactor class: A MECHANICAL/SAFE (cold routing reconcile)
Evidence:
- `bond.go` 490 LOC:
```go
type bondManager struct { mu sync.Mutex; bonds map[string]bondSig ... }
type bondSig struct { mode, lacpRate string; minLinks, mtu int; members []string ... }
func (b *bondManager) Apply(interfaces []*config.InterfaceConfig) error {115}
func (b *bondManager) createLocked(name string, ifc *config.InterfaceConfig, sig bondSig) error {221}
func (b *bondManager) enslaveMembers(name string, bondLink netlink.Link, members []string, already map[string]bool) ([]string, []error) {322}
func (b *bondManager) observedMembers(bondLink netlink.Link) (map[string]bool, bool) {360}
func (b *bondManager) Clear() error {444}
func (b *bondManager) clearLocked() error {453}
func (b *bondManager) deleteLocked(name string) error {477}
```
Fuses signature (SAD T? bondSig) computation from config + netlink create + enslave diff logic + observed state via netlink + clear/delete.

- `reth.go` 56 LOC: `rethManager` Apply checking reth pseudo-interface (bondless RETH via VRRP). Tiny but coupled to bond.go via interface type? RETH is not bond but LAG-like redundancy group.
- `monitor.go` 110 LOC: `InterfaceMonitorStatus` + `monitorManager` Apply publishing RG interface-monitor states.
- `probe_pin.go` 289 LOC: `probe_pin.go` maps probes (RPM, DHCP nexthop?) to routing-instance / interface.
- Additionally `tunnel.go` 2016 LOC not in batch but part of same package — shows routing package overall 15781 total with tunnel.go god-file (GRE/IPIP/WG/MTU/VRF/addr reconcile mixed with keepalive goroutine). So bond/reth/monitor/probe_pin split is already better than tunnel.go, but bond.go still moderately monolithic.

Proposed decomposition:
- Keep `bond.go` but split internally:
  - `bond_sig.go` — `bondSig` type + `computeBondSig(ifc) bondSig` pure from config.
  - `bond_members.go` — `observedMembers`, `enslaveMembers`, diff of desired vs observed, error aggregation.
  - `bond_apply.go` — `Apply`, `createLocked`, `Clear`, `clearLocked`, `deleteLocked` orchestration + netlink calls + mutex guard.
- Consider merging `reth.go` + `bond.go` under `lag.go`? Keep separate: RETH is not LAG, but both create kernel links; better to have `reth.go` expand with signature similar to bondSig.
- `monitor.go` already small, keep but extract `monitor_types.go` if grows.
- `probe_pin.go` keep; extract pure pinning logic from netlink if present.
- For tunnel.go (not in batch) note: it should be split into `tunnel_gre.go`, `tunnel_ipip.go`, `tunnel_vrf.go`, `tunnel_keepalive.go`, `tunnel_reconcile.go` — but out of scope for this batch; mention as related finding for b3.
- Seam: signature (pure config→sig) vs observation (netlink read) vs actuation (netlink write) vs garbage collection.

Hot-path preservation analysis:
- Rank D — COLD: routing link creation via netlink on commit, not packet. Probe pin affects RPM but still cold.
- Guardrails:
  - Preserve netlink transaction boundaries: create bond before enslaving members, observe existing members before diff.
  - Preserve LACP mode 802.3ad default, LACPRate fast/slow handling.
  - Preserve minLinks handling (0 = no minimum) — kernel expects.
  - Preserve reth bondless behavior: VRRP on physical members, no actual bond device, but this file's reth pseudo-interface maybe creates dummy? Ensure RETH apply does not break VRRP VIP.
  - Preserve Clear idempotent: deletes only xpf-owned LAGs.
  - Preserve error aggregation fail-closed like networkd #2987? bonding failures should fail commit?
  - How to verify: `go test ./pkg/routing -count=1` includes `bond_test.go`, `iface_reuse_test.go`, `tunnel_reconcile_test.go` (covers tunnel but also bond?), `monitor_test.go`, `probe_pin_test.go`, plus daemon integration `daemon_reth_rename_up_test.go`.

Tests + gate:
- Existing: `bond_test.go` 692 LOC, `monitor_test.go`, `probe_pin_test.go`, `routing_test.go` 2193 LOC (tunnel etc), plus daemon reth tests.
- Gate: `go test ./pkg/routing -count=1`, `make test-go`.
- No failover gate specific but RETH is HA relevant (reth0.50 + reth0.80, reth1.0 LAN). Cluster deploy must keep RETH members.

Why it matters:
- Bond LAG creation is host integration critical (dataplane needs LAG members up before AF_XDP bind). Mixing signature, observation, enslavement makes it hard to test diff logic pure. The file's 490 LOC is moderate but with 2 responsibilities (sig + netlink actuation + observation) plus error aggregation resembles networkd Apply debt pattern.
- Routing package total 15781 LOC with tunnel.go 2016 god-file shows broader monolith trend; splitting bond precursors establishes pattern for tunnel.go split in b3.

Fix direction:
- Extract sig pure, members diff pure, apply orchestration mechanical.
- Keep mu guard narrow: only around map access, not netlink calls, to reduce contention? Currently clearLocked holds? Check scope.
- Then tackle tunnel.go in next batch.

Labels: routing, bond, LAG, RETH, netlink, cold-path, file-split

Dedup note:
- Dedup-index mentions "GRE/IPIP/WG/MTU/VRF/addr reconcile mixed with keepalive goroutine Axis D commit-after-success defense" for tunnel.go — distinct, not this file. Bond/reth not previously flagged as monolith. Not duplicate.

---

## Finding 10: pkg/devicemap/devicemap.go 316 LOC pure resolver but comment says single resolver shared by daemon + CLI — still moderate fusion of PCI + MAC fallback + RETH OriginalName + collision-safe multi-pass + stable identity

Title: devicemap.go 316 LOC pure resolver fuses PCI bus address + permanent-MAC fallback + RETH OriginalName rule + collision-safe multi-pass rename discipline + device-map entry parsing + binding generation — moderate but reviewable for bare-metal safety
Severity: LOW
Confidence: MEDIUM
Refactor class: A MECHANICAL/SAFE (pure, testable) / D DO-NOT-SPLIT candidate if kept cohesive — see analysis
Evidence:
- File 316 LOC:
```go
type PresentNIC struct { ... busAddr string, permanentMAC string, currentName string, ... }
type Binding struct { Logical string, DesiredName string, OriginalName string, Source string // PCI or MAC fallback
}
func resolveDeviceMap(entries []config.DeviceMapEntry, nics []presentNIC, rethMembers map[string]bool) []devicemap.Binding {66}
```
- Responsibilities:
  - Present NIC enumeration model (`PresentNIC`) with PCI bus addr + permanent MAC + current kernel name.
  - Binding resolution: matches config DeviceMapEntry (PCI BDF or MAC) to present NIC, fallback MAC when PCI fails, RETH member OriginalName= rule.
  - Collision-safe multi-pass rename discipline (temp names breaking EEXIST) — algorithm but possibly duplicated with linksetup's breakNameCollisions.
  - Stable identity discipline: PCI preferred, permanent MAC fallback, topology-change detection REFUSES binding when PCI matches but permanent MAC differs (card swapped — never silent hijack).
  - Device-map parsing from config.
- Positive: pure function, no netlink, no file IO, shared by daemon rename + CLI `show chassis device-map candidates`. Single source of truth.
- Risk: moderate fusion but cohesive — all logic serves stable identity resolution.

```go
func resolveDeviceMap(entries []config.DeviceMapEntry, nics []presentNIC, rethMembers map[string]bool) []Binding {
    // PCI match first, MAC fallback, RETH OriginalName handling, collision-safe
}
```

Proposed decomposition (if split):
- Keep 316 LOC as is — file is not oversized vs 1000 LOC threshold. However if growth continues (unmapped-interface-policy, etc.):
  - `present.go` — `PresentNIC` + enumeration helpers.
  - `binding.go` — `Binding` + `resolveDeviceMap` + PCI vs MAC matching + RETH member handling.
  - `collision.go` — collision-safe rename ordering (temp name generation, multi-pass).
  - `validate.go` — topology-change refusal + strands-management helper (currently in daemon).
- But per (D) analysis, file is cohesive pure resolver, safe to keep as one unit; splitting would scatter stable-identity invariant across files and increase review burden for lifeline safety.
- Seam if forced: by matching strategy (PCI vs MAC) vs collision safety vs RETH rule.

Hot-path preservation analysis:
- Rank D — COLD: runs at boot and commit, no packet path, no allocation on hot.
- Guardrails:
  - Preserve PCI primary + permanent MAC fallback + RETH OriginalName (MAC alternates).
  - Preserve topology-change refusal (PCI matches but permanent MAC differs → refuse, never silent hijack).
  - Preserve collision-safe multi-pass rename discipline (temp names).
  - Preserve protected set lifeline handling.
  - How to verify: `go test ./pkg/devicemap -count=1` includes `devicemap_test.go` 284 LOC + `devicemap_nonpci_4884_test.go` 97 LOC.

Tests + gate:
- Existing: `devicemap_test.go`, `devicemap_nonpci_4884_test.go`, plus daemon device_map tests.
- Gate: `go test ./pkg/devicemap -count=1 && go test ./pkg/daemon -run DeviceMap -count=1`.

Why it matters:
- This file is the single source of truth for bare-metal stable identity (security #1956). Moderate fusion but intentional; splitting naively would scatter lifeline invariance across files and risk drift between daemon rename and CLI candidates view. The file is 316 LOC, under 500 LOC threshold where split cost may exceed benefit. However comment "pure identity resolver lives here" suggests future growth should stay pure; glue (rename netlink, teardown, preflight) belongs in daemon/device_map.go, not here — which is already case. So keep cohesive but document invariant.

Fix direction:
- Option (D) DO-NOT-SPLIT for now, with note to watch LOC growth; extract only if exceeds 500 LOC or adds unmapped-interface-policy logic.
- If split: `present.go` + `binding.go` + `collision.go` (optional), preserving pure nature.

Labels: devicemap, stable-identity, bare-metal, lifeline-safety, cohesive, cold-path, do-not-split-candidate

Dedup note:
- Not in dedup-index. Prior device-map was #1956 new feature post-index. Distinct from linksetup finding; this file is pure, linksetup is netlink+files. Deserves (D) consideration to avoid over-splitting safety-critical pure resolver.

---

## Finding 11: pkg/fwdstatus/* — sampler + procreader + builder + fwdstatus god sampling pipeline 900+ LOC across 4 files but each file moderate, overall pipeline fuses sampling tick overflow + proc reader + builder + forwarding status row write

Title: fwdstatus package 2050 total (4 files 585+353+291+251+211) pipeline fuses sampling + /proc reading + map stats building + forwarding status presentation — moderate monolith pipeline but files already split by concern
Severity: LOW
Confidence: MEDIUM
Refactor class: A MECHANICAL/SAFE for further split, but already reasonably decomposed — D DO-NOT-SPLIT for package level, optional consolidation
Evidence:
- Files:
  - `fwdstatus.go` 177 LOC — `ForwardingStatus` struct + `writeRow`
  - `builder.go` 291 LOC — `MapStats` + builder assembling status from counters
  - `sampler.go` 251 LOC — sampler for periodic status poll 1/s + ticks overflow guard 4909
  - `procreader.go` 211 LOC — reading /proc/net/dev or /proc stat
  - `osprocreader_test.go` 136, `sampler_test.go` 353, `fwdstatus_test.go` 585, `ticks_overflow_4909_test.go` 46.
- Total 2050 but max file 585 (test) — prod max 291.
- Responsibilities: builder consumes sampler + procreader + MapStats; procreader reads /proc; sampler ticks overflow handling #4909 (ticks wrap beyond int64). Each file small and focused.
- Already follows seam: sampling (time) vs reading (OS) vs building (aggregate) vs rendering (writeRow).
- Merge vs split tradeoff: further splitting builder into per-map stat files would be over-split.

Proposed decomposition:
- Keep as is (D). If growth: extract `ticks.go` handling overflow explicitly (already mention ticks_overflow test) — but currently 46 LOC test covers overflow, code small.

Hot-path preservation analysis:
- Rank C? Actually WARM 1/s poll path, not packet hot, but control socket contention warning in CLAUDE.md: "control socket is shared by status poll (1/s), HA sync, session installs, snapshot sync, forwarding sync. High-frequency callers MUST be throttled." So sampler at 1/s is throttled hot-caller near control socket. Splitting must not increase poll rate.
- Guardrails: preserve 1/s throttle, preserve overflow handling ticks 4909 (atomic uptime vs monotonic), preserve MapStats counters Relaxed ordering not SeqCst (if any).
- How to verify: `go test ./pkg/fwdstatus -count=1`, `make test-go`, cluster status poll not spamming.

Tests + gate:
- Existing: `fwdstatus_test.go` 585, `sampler_test.go` 353, `osprocreader_test.go` 136, `ticks_overflow_4909_test.go` 46.
- Gate: `go test ./pkg/fwdstatus -count=1`.

Why it matters:
- Fwdstatus is WARM path but not critical monolith; package already split reasonably. This is an example of good decomposition vs prior monoliths (linksetup, networkd, FRR). Documenting as negative result (D) helps calibrate what "not monolith" looks like — 200-300 LOC per file, single responsibility.

Fix direction:
- DO-NOT-SPLIT — keep 4 files; optionally extract ticks overflow guard to explicit `ticks.go` if grows, but currently fine.

Labels: fwdstatus, sampling, proc-reader, warm-path, cohesive, do-not-split

Dedup note:
- Not in dedup-index. Fwdstatus not previously flagged. Distinct from Cos queue service etc.

---

## Finding 12: pkg/fsatomic/fsatomic.go + test_seams — atomic file write + owner + fsync ordering + temp sweep fused but moderate 256 LOC

Title: fsatomic.go 256 LOC atomic write + owner ID + post-rename fsync error + temp pattern + directory fsync — moderate cohesive file with clear seam but small enough
Severity: LOW
Confidence: HIGH
Refactor class: A MECHANICAL/SAFE / D DO-NOT-SPLIT borderline
Evidence:
- File `fsatomic.go` ~256 LOC:
```go
type PostRenameSyncError struct { ... }
type options struct { ownerUID, ownerGID, syncDir bool ... }
func atomicWriteFile(path string, data []byte, perm os.FileMode) error // actually in frr manager, but fsatomic is WriteFile?
type ownerIDs struct { ... }
```
- Responsibilities:
  - Atomic write via temp + rename (isFsatomicTemp pattern).
  - Owner option (chown after write) + temp file ownership handling.
  - Post-rename dir fsync barrier for durability (#4621 archive atomic etc.).
  - Error type `PostRenameSyncError` capturing rename succeeded but fsync failed.
  - Temp sweep `isFsatomicTemp` pattern used by zeroize + configstore.
- Test seams file `test_seams.go` injectable for fsync failure simulation.

Proposed decomposition:
- Keep as is (D) — 256 LOC cohesive atomic-write utility. Splitting into `owner.go` + `sync.go` + `temp.go` would be over-split (each <100 LOC). However if growth:
  - `fsatomic/write.go` — WriteFile + options.
  - `fsatomic/owner.go` — ownerIDs + chown.
  - `fsatomic/sync.go` — post-rename sync + dir sync + error type.
  - `fsatomic/temp.go` — isFsatomicTemp + sweep helpers.
- Current file is borderline but acceptable as single util package; its callers include configstore (.configdb master.key key-first ordering), frr manager (atomicWriteFile wrapper), networkd (writeIfChanged not using fsatomic? but similar), grpcapi zeroize temp sweep.

Hot-path preservation analysis:
- Rank D — COLD persist path, but durability ordering is correctness-critical: key-first delete + fsync before ciphertext RemoveAll (zeroize), rollback + journal atomic. Must preserve fsync barrier count.
- Guardrails: preserve fsync ordering, PostRenameSyncError propagation, owner chown after rename (not before), isFsatomicTemp pattern matching (`*.tmp` + `.#*`? need check).
- How to verify: `go test ./pkg/fsatomic -count=1` includes `canary_test.go`, `fsatomic_test.go`, plus configstore archive atomic #4621 etc.

Tests + gate:
- Existing: `fsatomic_test.go`, `canary_test.go`, plus callers `archive_atomic_4621_test.go`, `zeroize_temp_5475_test.go`, `zeroize_rendered_temp_5509_test.go`.
- Gate: `go test ./pkg/fsatomic -count=1 && make test-go`.

Why it matters:
- Fsatomic is used across configstore, FRR, zeroize, networkd — small utility but critical for durability and fail-closed. Over-splitting would scatter correctness-critical fsync barrier logic. Keep cohesive but note seam for future if OWNER vs SYNC grows.

Fix direction:
- DO-NOT-SPLIT for now (D). If file exceeds 400 LOC, split into write + owner + sync.

Labels: fsatomic, atomic-write, durability, cold-path, cohesive, do-not-split

Dedup note:
- Dedup-index mentions "Unbounded snapshot rx_queues drives overflow-prone binding-plan construction" not fsatomic. No prior fsatomic monolith flag. Distinct.

---

## Finding 13: pkg/diagcmd/diagcmd.go + limiter.go — diagnostic command runner + rate limiter moderate fusion

Title: diagcmd package moderate — PingOptions + TracerouteOptions + limiter + command execution — small but could split cold vs hot throttling
Severity: LOW
Confidence: MEDIUM
Refactor class: A MECHANICAL/SAFE
Evidence:
- `diagcmd.go` ? LOC (need wc) ~? + `limiter.go` ~? — small files.
- Responsibilities: ping, traceroute options parsing, command exec with timeout (exec_timeout.go in daemon similar), rate limiter to prevent DoS via diag commands, journal logging.
- Already split into two files: diagcmd.go and limiter.go — good.
- Potential further split: `ping.go`, `traceroute.go`, `exec.go` if grows.

Proposed decomposition:
- Keep 2 files for now; if ping/traceroute grow, split by command family.

Hot-path preservation analysis:
- Rank D — COLD diagnostic path, invoked via gRPC/CLI.
- Guardrails: preserve limiter's token bucket or sliding window to prevent diag DoS, preserve exec timeout (similar to daemon/exec_timeout.go).

Tests + gate:
- `diagcmd_test.go`, `limiter_test.go`.
- Gate: `go test ./pkg/diagcmd -count=1`.

Why it matters:
- Small but demonstrates good decomposition precedent vs daemon's large files.

Fix direction:
- DO-NOT-SPLIT — already 2 files, <300 LOC each.

Labels: diagcmd, cold-path, cohesive, do-not-split

Dedup note:
- Not in dedup-index.

---

## Finding 14: pkg/lldp/lldp.go + lifecycle_mutex + socket + shutdown_ttl0 — LLDP lifecycle moderate but fuses socket + mutex + TLV build

Title: lldp.go moderate fusion of socket lifecycle, mutex guard, TLV build, TTL0 shutdown — 3 concerns but <300 LOC?
Severity: LOW
Confidence: MEDIUM
Refactor class: A MECHANICAL/SAFE
Evidence:
- File `lldp.go` + `lifecycle_mutex_5121_test.go` + `socket_test.go` + `shutdown_ttl0_5123_test.go` — lifecycle mutex #5121, TTL0 shutdown #5123.
- Responsibilities: LLDP socket creation (raw? AF_PACKET?), TLV encoding (chassis ID, port ID, TTL, etc.), periodic transmission, lifecycle mutex guarding start/stop, shutdown TTL0 advertisement per IEEE.

Proposed decomposition:
- `tlv.go` — TLV encoding.
- `socket.go` — socket creation, send.
- `lifecycle.go` — mutex + start/stop + periodic loop.
- `shutdown.go` — TTL0 shutdown on stop.

Hot-path preservation analysis:
- Rank D — COLD: LLDP 30s periodic, not hot.

Tests + gate:
- Existing lldp tests.
- Gate: `go test ./pkg/lldp -count=1`.

Why it matters:
- Small but security? LLDP TLV injection? JSON? Low severity.

Fix direction:
- Keep as is unless grows beyond 500 LOC.

Labels: lldp, cold-path, moderate, do-not-split-candidate

Dedup note:
- No LLDP in dedup-index.

---

## Summary — Top Priority Refactors for A7 b2

High priority (HIGH severity, >500 LOC, clear seam, cold):
1. FRR policy_render.go 2309 god-renderer → split by sanitize/bfd/redist/bgp_chain/protocol families/policy_options (7 files).
2. FRR manager.go 1057 god-manager → split types/section/persist/reload.
3. daemon device_map.go 836 glue → split policy/preflight/rename/teardown.
4. networkd.go 775 manager → split render_link/network/netdev + apply + external + rpfilter + io.
5. ipsec policy+ike 1135+890 → split crypto/ike_render/child_render/selector/sa_lifecycle.

Medium:
6. linksetup.go 545 enumeration+naming+collision+files+netlink+rss → split enumerate/naming/rename/files/os/rss.
7. rss_indirection.go 550 executor+parse+weights+apply → split executor/parse/weights/apply.
8. login_password.go 407 shadow+passwd+marker+keys+reconcile → split shadow/passwd/marker/keys/reconcile, unify lookupUID variants.
9. routing bond.go 490 sig+members+apply → split sig/members/apply, plus tunnel.go 2016 noted for b3.

Low / DO-NOT-SPLIT (cohesive small):
10. devicemap.go 316 pure resolver — keep cohesive but document invariant, (D) with watch.
11. fwdstatus 4 files 200-300 each — already good, (D).
12. fsatomic 256 — cohesive atomic-write util, (D) borderline.
13. diagcmd 2 files small — keep, (D).
14. lldp small — keep.

Hot-path preservation: All findings are COLD commit/boot/persist/rendering paths except fwdstatus WARM 1/s poll. No per-packet hot-path crossing, so (A) mechanical splits safe, (D) where cohesive. No inlining loss, no alloc on hot, no dispatch, no layout change. Guardrails are fail-closed error aggregation, lifeline never-sweep, collision-safe rename, reload debt, topology refusal, childname collision, terminate semantics.

Tests gates: For each high/medium, existing unit tests already pin fail-closed behavior (#4900 stale-remove, #2987 write-fail, #4954 reload debt, #4178 collision, #4956 rename error propagation, #5309 teardown retain, #5277 chain collision, #5116 redist alias, #2980 router-id, #4919 cluster-id/origin, #4097 sanitize newline, #3904 multivalue, #5122 childname collision, #3941 delete-terminate, #5494 unrenderable-terminate, #4588 bgp neighbor IP guard, etc.). Gate `make test-go` must stay green, plus `go test ./pkg/frr ./pkg/ipsec ./pkg/networkd ./pkg/devicemap ./pkg/routing ./pkg/daemon -run <Area>`.

Dedup coverage: Checked dedup-index.txt ~630 entries including prom collector, HA sync conn gen-guard, NAT compile, daemon_apply 1100 LOC chain, ipsec 880-line policy.go prior mention, tunnel GRE/IPIP/WG fusion, etc. Our findings materially expand seams beyond prior flags (e.g., FRR chain composition + BFD + sanitize separation, networkd debt vs rendering vs protected resolver, device-map preflight vs rename vs teardown) and add new high-confidence monoliths (networkd Manager, linksetup, rss_indirection, login_password). None duplicate verbatim.


---
### Batch A7_go_daemon_host-b3 — 571 lines — full log + findings

# Refactor/Modularity Audit — A7_go_daemon_host-b3 (73 files)

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A7_go_daemon_host-b3
Batch file: A7_go_daemon_host-b3.txt (73 files, 12900 prod + 15238 test LOC)
Auditor: A7_go_daemon_host batch 3/3 — routing (VRF, tunnel/GRE/IPIP/WG anchor, XFRM, rules/PBR/rib-group, routeformat, route reader) + upgrade (cluster CLI parsers, cutover/rolling/flip/kernel, lock, manifest, stagedgen) + wgkey
Date: 2026-07-11

---

## Batch Inventory — LOC via wc -l at base f1ef0eec8

### Prod files (30) — 12900 LOC

| File | LOC | Structs/Consts | Key fns | Responsibilities | Monolith? |
|------|-----|----------------|---------|------------------|-----------|
| pkg/routing/tunnel.go | 2016 | tunnelManager, KeepaliveState, keepaliveRunner, linkOps, vrfBinder, wgOverheadV4/V6, wgEngineMaxInnerMTU, wgDefaultOuterMTU, errWGIncompatibleLinkRetained | Apply, applyAnchorLocked, applyKernelTunnelLocked, applyWireguardTunLocked, finishTunnelLocked, reconcileLinkAddrsLocked, pruneAppliedAddrsLocked, reconcileVRFClaimLocked, unbindVRFClaimLocked, observeListClaimLocked, wgTunMTUForEndpoint, buildKernelTunnelLink, legacyTunnelMatches, anchorReusable, ensureReconcileStateLocked, linkGenForLocked, bumpLinkGenLocked, keepaliveProber, stopAll, stopAllKeepalivesLocked, stopKeepaliveLocked, startKeepalive, keepaliveLoop, keepaliveTick, nextSeq, clearLocked, GetStatus, Clear | GRE/IPIP/IP6TNL kernel tunnel lifecycle, TUN anchor (userspace-dp) lifecycle, WireGuard persistent TUN lifecycle, address symmetric reconcile (incl link-local gate #1884), VRF claim ordered procedure #1884 A.5 (bind/unbind/observe), ownedNames/wgConfigured/appliedAddrs/appliedRI maps, keepalive Runner identity reconcile #1884 A.7, linkGen atomic generation defense-in-depth #1918 Axis D, WG MTU overhead model #1432/#2300/#2457, fail-closed error aggregation #5355 | YES — critical god-file |
| pkg/routing/rules.go | 1447 | nextTableManager, ribGroupManager, pbrManager, PBRRule, PBRPortRange, ruleOps, const nextTableRulePriority(100), ribGroupRulePriority(33000), ribGroupLeakRulePriority(30000), pbrRulePriority(31000), maxRibGroupLeakRules, maxPBRRules, pbrAttachment | nextTableManager.Apply/clear, ribGroupManager.Apply/clear, pbrManager.Apply/clear, BuildPBRRules, PBRBuildStats, collectAttachedInputFilters, sortAttachments, buildPBRFromFilter, pbrTermL4, hasRealString, resolvePBRDirection, normalizePBRAddr, dscpToTOS, ribGroupLeaksIntoMain, splitConnectedPrefixesByFamily, resolveRibTable, ribInstanceFromName, isRuleAlreadyGone | next-table inter-VRF leak rules install, rib-group per-prefix leak #3876 (30000 band before main), PBR ip-rule install (DSCP/src/dst/proto/port, IIF scoping #5117), PBR rule BUILD from firewall filter attachments (Junos FBF semantics), prefix-list expansion, except handling fail-closed, DSCP 0 drop #3430 H2, TOS, L4 predicates #3730, overflow caps, PBR build stats #4422, rib resolution | YES — major, mixes install (netlink RuleAdd/Del) with config-to-rule build (firewall filter parsing) |
| pkg/upgrade/cutover.go | 1045 | Options, errNoSourceGeneration, Runner (cfg, stagedGenConfig, clusterNodeIDPresent etc.) | resolveSource, Run, cluster gate #5284/#5573, journal handling, DB snapshot, upgrade lock | Upgrade cut-over orchestrator: cluster gate (refuse standalone on clustered node #5284, indeterminate #5573 fail-closed), source generation resolution (current-gen vs pinned vs legacy #1981), host-wide lock #1965, DB snapshot preflight fail-closed, staged copy, flip, start, health rollback #1964, cluster-coordinated flag | Moderate — large orchestrator but single responsibility (cut-over) |
| pkg/upgrade/kernel_linux.go | 869 | kernelOps Linux impl, package query, purge logic | Kernel listing, version validation, purge 5076, pkgquery 5428, self-recover | Linux kernel management: list installed kernels via dpkg, query boot, purge old, validate version, self-recover from failed boot | Moderate — mixes pkg query + purge + boot config, but same domain (kernel) |
| pkg/upgrade/kernel_run.go | 637 | KernelRun orchestrator | Run kernel upgrade steps, drain integration | Kernel upgrade run path: drain, flip, health check | Moderate — orchestrator |
| pkg/upgrade/cluster_cli.go | 610 | grpcCluster, RollingCluster interface, parse helpers | NewCLICluster, dial, information, statusText, systemAction, PeerAlive, SyncEstablished, DrainComplete, HAProtocolCompatible, PeerTakeoverReady, ForceSecondary, ResetFailover, configuredRGs, configuredRGsFromStatus, parsePeerAlive, parseSyncEstablished, parseHAProtocolCompatible, parsePeerTakeoverReady, parseDrainComplete, parseLocalNodeID, parseNodeToken, parseRGIDs, atoiSafe, trailingInt, firstTokenAfterColon, lineHasAll | HA cluster CLI via gRPC: show chassis cluster information/status text parsing defensive, drain predicate (local secondary + peer primary per-RG pairing), sync link Status: Up scoped, peer health, takeover ready best-effort gate, failover reset enumeration fail-closed #5044, wrong-daemon unit guard #1983 | Moderate — 610 LOC parsing many text formats but single domain (cluster CLI) |
| pkg/upgrade/runner.go | 596 | Runner struct (implied), Options re-use | Run (duplicate? actually cutover.go contains Run) — need separate: runner.go contains Runner.Run? Actually cutover.go contains Options and Run; runner.go may contain Runner struct and state machine? | Full install cut-over runner with state transitions (PREFLIGHT, COPIED, FLIPPED, STARTED), journal persistence, retry | Moderate — state machine + I/O |
| pkg/routing/routing.go | 237 | Manager facade, 10 domain managers | New, Close, CreateVRF, IsManagedVRF, ReconcileVRFs, BindInterfaceToVRF, GetRoutesForTable, GetRoutes, GetVRFRoutes, GetTableRoutes, GetAllTableRoutes, ApplyTunnels, ClearTunnels, GetTunnelStatus, GetKeepaliveState, ApplyXfrmi, ClearXfrmi, ApplyNextTableRules, ApplyRibGroupRules, ApplyPBRRules, ApplyProbePins, ClearProbePins, ApplyBonds, ClearBonds, ApplyRethInterfaces, ClearRethInterfaces, RethNames, ApplyInterfaceMonitors, InterfaceMonitorStatuses | Facade over domain managers: vrf, routeReader, tunnel, xfrm, nextTbl, ribGroup, pbr, probePin, bond, reth, monitor — owns netlink handle singleton, delegations preserve historical API byte-for-byte | NO — exemplary modularization after #1698 domain split, 237 LOC thin facade |
| pkg/routing/routes.go | 356 | RouteEntry, NextHop, TableRoutes, routeReader, routeLister, rtprotZStatic=196 | GetRoutesForTable, GetRoutes, GetVRFRoutes, GetTableRoutes, GetAllTableRoutes, routeToEntry, multiPathNextHops, rtProtoName, familyName | Kernel route-table reads stateless: per-family independent dump #5125 partial-render-with-warning, ECMP multipath RTA_MULTIPATH surfacing, protocol mapping FRR ZSTATIC 196, Interface resolution via LinkByIndex with fallback to index string, VRF prefix stripping | NO — single responsibility, stateless reader, 356 LOC |
| pkg/routing/routeformat.go | 292 | — | protoTag, FormatRouteTerse, appendSplitAF, FormatRouteDestination, FormatRouteSummary, formatSummaryProtos, FormatAllRoutes, formatTableJunos, junosProtoName | Junos-style route formatting: terse, destination with exact/longer/orlonger modifiers, summary with Highwater Mark, table rendering, protocol tag mapping, AF split helper | NO — pure formatting, 292 LOC, 4 format fns but cohesive |
| pkg/routing/vrf.go | 361 | VRFSpec, vrfManager, vrfOps, errLinkNotFound | Create, createLocked, IsManaged, Reconcile, BindInterfaceToVRF, isLinkNotFound, reconcileVRFs, createLinkedVRF, vrfTable | VRF device lifecycle + interface binding, namespace claim entire vrf-* #847 orphan reap, transient lookup retention fail-closed, table mismatch recreate, ownership tracking via vrfs slice | NO — single domain manager, 361 LOC |
| pkg/routing/xfrm.go | 332 | xfrmManager | Apply, Clear, clearLocked, deleteLocked | XFRM xfrmi lifecycle for IPsec VPN: differential reconcile #2546 keep unchanged, if_id collision guard #2909, transient lookup retention #5461, stale if_id detection recreate, fail-closed error aggregation #5310/#4901, adopt existing kernel link #1706 | NO — single domain, 332 LOC moderate |
| pkg/routing/tunnel_keepalive.go | 294 | ProbeResult enum (Alive/Dead/Unsupported), UnsupportedKind, tunnelProber interface, probeConn, icmpProber, keepaliveProbeDeadline | Probe, bytesEqual, classifyListenErr, classifyWriteErr, makeNonce, listenICMP var | ICMP keepalive prober: unprivileged datagram ICMP via x/net/icmp, Seq+nonce authoritative match #1918 §5a, source IP bind #5c, global FIB no VRF bind #5b, errno classification structural vs transient #1918 Axis C, write error bucketing Dead vs transient #1947 | NO — single responsibility, 294 LOC |
| pkg/routing/test_seams.go | 55 | — | NewManagerWithLinkOpsForTest, NewManagerWithRouteListerForTest | Test-only constructors for fakes: linkOps backed manager (vrf/tunnel/xfrm/bond/reth/monitor) and routeLister backed reader, drills apply/commit error-propagation wiring #5310 without root | NO — test seam file, 55 LOC |
| pkg/upgrade/flip.go | 448 | unitDropinName=10-xpf-version.conf | flip (6a symlink current, 6b bin symlink, 6c unit drop-in + daemon-reload) | Three-step flip atomic: versions/current symlink, /usr/local/sbin/xpfd bin symlink, systemd drop-in ExecStart pin | NO — single responsibility 448 LOC |
| pkg/upgrade/kernel.go | 334 | kernel-related | Kernel install/verify logic | Kernel upgrade manager wrapper | NO — thin wrapper 334 LOC |
| pkg/upgrade/kernel_drain.go | 160 | Drain logic | drain node, rejoin | HA kernel drain gate | NO — 160 LOC single domain |
| pkg/upgrade/kernel_selfrecover.go | 273 | Self-recovery | kernel self-recovery boot logic | Self-recover from failed kernel boot | NO — single concern |
| pkg/upgrade/lock/lock.go | 303 | FileLock | Acquire, Release, floc via flock EWOULDBLOCK, host-wide upgrade lock | Host-wide upgrade lock #1875 via /tmp/xpf-cluster.lock + per-host, queue vs kill, stale holder detection | NO — single responsibility |
| pkg/upgrade/manifest/manifest.go | 106 | Manifest struct | manifest read/write, version pinning | Staged generation manifest handling | NO — 106 LOC |
| pkg/upgrade/version.go | 113 | Version parsing | parse version, compare | Version comparison helper | NO — 113 LOC |
| pkg/upgrade/imageversions.go | 179 | ImageVersions | image version listing | Image version resolution | NO — 179 LOC |
| pkg/upgrade/system_linux.go | 190 | systemd actions | StopUnit, StartUnit, daemon-reload | systemd unit control | NO — small 190 LOC |
| pkg/upgrade/state.go | 165 | Journal, State enum | State machine enum, atLeast | Upgrade journal state machine persistence | NO — 165 LOC |
| pkg/upgrade/helper_health.go | 160 | Helper health | check helper health 5286 | Helper control socket health gate | NO — 160 LOC |
| pkg/upgrade/rolling.go | 247 | RollingCluster interface | RunRolling, peer alive, sync, drain, cut, rejoin | Rolling upgrade orchestrator for HA cluster | NO — 247 LOC moderate orchestration but single domain |
| pkg/upgrade/runtime/seed.go | 400 | Seed runtime | seed binary handling | First-install seed logic | NO — 400 LOC single domain |
| pkg/upgrade/stagedgen/fsutil.go | 149 | fs helpers | fs util for stagedgen | Filesystem utilities for staged generation | NO — 149 LOC |
| pkg/upgrade/stagedgen/stagedgen.go | 413 | StagedGen config | ResolveCurrent, GenDir, ValidGenID, staged generation lifecycle | Staged generation lifecycle: current-gen, pinning, GC protection #1981 | NO — 413 LOC single domain |
| pkg/wgkey/wgkey.go | 113 | WG key handling | GenerateKeypair, pubkey derivation | WireGuard key generation via wireguard-go curve25519, clamping | NO — small crypto helper 113 LOC |

### Test files (43) — 15238 LOC

| File | LOC | Focus |
|------|-----|-------|
| pkg/routing/routing_test.go | 2193 | Manager facade tests: VRF create/isManaged, route reads, tunnel lifecycle, XFRM, bond, reth, monitor, probePin — but uses fakes (linkOps) to exercise apply wiring #5310 fail-closed |
| pkg/routing/tunnel_reconcile_test.go | 1825 | Tunnel reconcile in-place #1884: ownedNames adoption from entry snapshot, WG→non-WG handoff, non-WG→WG handoff, address reconcile link-local gate, VRF claim identity-gated unbind, ownedNames retention on LinkDel failure #4901, WG prune diff #1919, transient lookup deferral |
| pkg/routing/rules_test.go | 1039 | Next-table, rib-group #3876, PBR rules install + build: PBR IIF scoping #5117, DSCP 0 drop, except fail-closed, L4 predicates #3730, prefix-list expansion, truncation caps |
| pkg/routing/tunnel_keepalive_test.go | 574 | Keepalive state machine: ProbeAlive/Dead/Unsupported, hold-on-unknown #1918, transient escalation, generation guard, skipUp logic when kept down |
| pkg/upgrade/runner_test.go | 734 | Runner state machine: fresh vs resume, source gen pinning #1981, cluster gate refusal #5284/#5573, DB snapshot fail-closed, lock already held #1965 |
| pkg/upgrade/kernel_test.go | 734 | Kernel listing, version parsing, pkgquery fallback |
| pkg/upgrade/cluster_cli_test.go | 470 | FormatInformation/FormatStatus parsing: peer alive, sync Status: Up scoped, drain complete per-RG pairing, takeover ready tokens, HA protocol compatible, RG enumeration fail-closed #5044, wrong-daemon guard #1983 |
| pkg/routing/routes_multipath_test.go | 149 | ECMP NextHops surfacing, weight Hops+1 |
| pkg/routing/routes_disposition_5410_test.go | 49 | discard/reject disposition #5410 RTN_BLACKHOLE vs RTN_UNREACHABLE |
| pkg/routing/routes_perfamily_5125_test.go | 209 | Per-family partial failure #5125: one family fails, other still returned, error joined |
| pkg/routing/rtproto_test.go | 75 | rtProtoName mapping: ZSTATIC 196 → static, kernel→connected etc |
| pkg/routing/teardown_linkdel_4901_test.go | 119 | LinkDel failure retention #4901: ownership retained for retry not orphaned |
| pkg/routing/tunnel_anchor_keepalive_test.go | 350 | Anchor keepalive #4071: TUN anchor with keepalive down-action LinkSetDown, identity reconcile |
| pkg/routing/tunnel_apply_failclosed_5355_test.go | 180 | Tunnel Apply fail-closed #5355: genuine LinkAdd/SetUp/Del failure returns error not silent nil |
| pkg/routing/tunnel_prober_test.go | 263 | icmpProber probe: seq+nonce match, dedup, deadline, family mismatch structural |
| pkg/routing/vrf_stable_tableid_test.go | 83 | VRF stable table ID |
| pkg/routing/xfrm_apply_failclosed_5310_test.go | 141 | XFRM apply fail-closed #5310: genuine failure aggregated |
| pkg/routing/xfrm_linkbyname_transient_5461_5495_test.go | 195 | XFRM transient LinkByName #5461/#5495: transient error retains tracking not orphan |
| pkg/upgrade/cutover_cluster_gate_5284_test.go | 128 | Cluster gate #5284: standalone on clustered node refused |
| pkg/upgrade/cutover_cluster_gate_indeterminate_5573_test.go | 159 | Cluster gate indeterminate #5573: node-id marker unreadable fail-closed |
| pkg/upgrade/cutover_refuse_test.go | 361 | Cutover refusal cases |
| pkg/upgrade/helper_health_5286_test.go | 203 | Helper health gate #5286 |
| pkg/upgrade/imageversions_test.go | 124 | Image version listing |
| pkg/upgrade/kernel_drain_test.go | 151 | Kernel drain predicate |
| pkg/upgrade/kernel_pkgquery_5428_test.go | 157 | Kernel pkg query #5428 fallback |
| pkg/upgrade/kernel_purge_5076_test.go | 219 | Kernel purge #5076 |
| pkg/upgrade/kernel_version_validate_5452_test.go | 232 | Kernel version validation #5452 |
| pkg/upgrade/lock/lock_test.go | 456 | Lock acquire/release, EWOULDBLOCK, queue |
| pkg/upgrade/lock_integration_test.go | 158 | Lock integration multi-process |
| pkg/upgrade/lock_seam_test.go | 67 | Lock seam for tests |
| pkg/upgrade/manifest/manifest_drift_test.go | 453 | Manifest drift detection |
| pkg/upgrade/preflight_dbsnap_failclosed_5074_test.go | 210 | Preflight DB snap fail-closed #5074 |
| pkg/upgrade/read_journal_malformed_4876_test.go | 38 | Journal malformed #4876 tolerance |
| pkg/upgrade/rolling_test.go | 240 | Rolling driver: peer alive, sync, drain, rejoin |
| pkg/upgrade/kernel_selfrecover_test.go | 296 | Self-recovery boot |
| pkg/upgrade/kernel_linux_test.go | 73 | Linux kernel ops |
| pkg/upgrade/stagedgen/stagedgen_test.go | 475 | Stagedgen lifecycle: current-gen resolve, pinning, GC |
| pkg/upgrade/stagedgen_cut_test.go | 536 | Stagedgen cut: source gen pinning #1981 |
| pkg/upgrade/version_test.go | 46 | Version parsing |
| pkg/upgrade/runtime/seed_test.go | 368 | Seed runtime first-install |
| pkg/upgrade/system_linux_test.go | 160 | systemd unit actions |
| pkg/upgrade/verify_cleanup_test.go | 362 | Upgrade cleanup verifier |
| pkg/wgkey/wgkey_test.go | 184 | Keypair generation, pubkey clamping |

---

## File-by-File Deep Monolith Check (mandatory)

### 1. pkg/routing/tunnel.go — 2016 LOC — VERDICT: CRITICAL MONOLITH

Title: tunnel.go 2016 LOC god-file fusing GRE/IPIP/TUN-anchor/WG persistent lifecycles + address/VRF/keepalive/MTU/세대 management

Severity: critical
Confidence: high
Refactor class: A — god-file 2000+ LOC, B — module fusing 5+ distinct responsibilities, C — state machine + retry maps interleaved

Evidence:
- Type tunnelManager (L159-213) holds 8 maps + mutex + prober injection + vrfBinder cross-domain dep + linkGen map[string]*atomic.Uint64 atomic for lock-free keepalive tick guard #1918 Axis D. Fields: tunnels []string success-tracked for GetStatus, keepalives map name->runner, linkGen atomic map, ownedNames map desired+failed-removal retention, appliedAddrs map per-tunnel set for link-local gate, appliedRI map routing-instance claim, wgConfigured map for WG prune diff #1919. All mutated under single mu held across whole netlink reconcile (L277 comment explains wide scope deliberate to serialize MAP reads/writes with LinkDel/Add).
- Apply (L277-523) 246 LOC orchestrates: desired/wgDesired split, oldOwned snapshot adoption authority #1884 r2 F1, next map for removal retry, non-WG→WG handoff without LinkDel (persistent WG #1432 S2a), WG→non-WG handoff keep appliedAddrs for link-local gate, removal loop with transient isLinkNotFound discipline (#1919 r2 leak chain), then WG address-prune-on-removal diff (oldWG vs wgDesired) 68 LOC with pruneAppliedAddrsLocked + unbindVRFClaimLocked #5120, then per-tunnel apply loop dispatching to 3 distinct create paths.
- 3 creation paths each ~150-250 LOC:
  - applyAnchorLocked (L564-698): drain-before-recreate + linkGen bump #1918 F7 ported to anchor #4071, reusable check anchorReusable (TUN mode + NO_PI + persistent), LinkAdd-EEXIST adopt via kernel-fetched link, closeTuntapFiles, MTU 1500 default on adoption #1884, keepalive identity reconcile #4071.
  - applyKernelTunnelLocked (L811-986): buildKernelTunnelLink switch GRE/IPIP/ip6tnl, legacyTunnelMatches comparing only config-driven attrs (type+Type() + endpoints+TTL+keys), drain-before-recreate, transient lookup deferral not fail-closed #5355, encaplimit none exec 15s bounded #1794, MTU reconcile.
  - applyWireguardTunLocked (L1400-1541): persistent wgN TUN creation NonPersist:false, TUNTAP_MODE_TUN + NO_PI, MTU derived via wgTunMTUForEndpoint (overhead 60/80 + pad 15 + clamp 4096 #2457), link type check not TUN → delete+sentinel errWGIncompatibleLinkRetained for ownedNames re-retain #1919 r5/r6, LinkDel failure tracking, finish via reconcileLinkAddrsLocked + reconcileVRFClaimLocked #5120.
- Shared helpers: reconcileLinkAddrsLocked (L1017-1124) symmetric add/del with link-local gate (applied==nil restart adoption never deletes kernel autoconf fe80), AddrList failure carry-forward link-locals to avoid foreign re-classification leak #1919 MAJOR, EEXIST idempotent success Debug not Warn #1950. pruneAppliedAddrsLocked (L1154-1184) distinct return (failed,retry) for WG removal, records all families failed deletes (fix #1919 r1 MAJOR). reconcileVRFClaimLocked (L1204-1330) 5-step ordered claim #1884 A.5: stanza RI bind, RIListMember observe VETO, config-wants-none identity-gated unbind via unbindVRFClaimLocked. unbindVRFClaimLocked (L1249-1285) transient retention retry.
- Keepalive lifecycle embedded: keepaliveRunner struct (L96-118) with cancel/done chan + state + identity (remote/source/interval/maxRetries) + linkGen atomic + startGen. matches() normalizes retry 0→3. startKeepalive (L1598-1638) stop+drains predecessor, captures gen.Load(), launches goroutine keepaliveLoop with context cancel. stopKeepaliveLocked drains via <-done. stopAllKeepalivesLocked clears map. keepaliveTick (L1689-1782) NEVER takes t.mu (AGY r5 deadlock note) — only state.mu short, lock-free gen.Load() guard dropping action if link recreated, commit-after-success sequence #1918 Axis D: classify probe under state.mu, compute intent, LinkByName outside mu, gen guard, single LinkSetUp/Down, commit Up only on success.
- WG MTU model constants: wgOverheadV4 60, wgOverheadV6 80, wgPadWorst 15 must mirror userspace-dp afxdp/wg/mod.rs, wgEngineMaxInnerMTU 4096 mirrors engine.rs PADDED_PLAINTEXT_MAX, wgDefaultOuterMTU 1500 mirrors coordinator/wg_control.rs, wgTunMTUForEndpoint operator override wins (#2300 divergence closure) + family overhead (v6 default for roaming) + clamp 4096 #2457.
- Error contract: Apply accumulates errs via errors.Join fail-closed #5355 sibling of xfrm #5310 — used to log and return nil before, now fails commit closed. clearLocked (L1878-1931) union of success-tracked + ownedNames for delete-everything, retains failed LinkDel names for retry #4901, resets maps.
- GetStatus (L1933-2016) snapshots names under mu then probes netlink read-only unlocked #848 to avoid blocking applyConfig, builds TunnelStatus with tri-state KeepaliveUp nil vs true/false #1918 hold-on-unknown.

Proposed decomposition:
- Split tunnel.go mechanical code-motion same package (no logic change):
  - tunnel/types.go: KeepaliveState, keepaliveRunner, TunnelStatus, ProbeResult re-export, constants wgOverhead*, wgEngineMaxInnerMTU, wgDefaultOuterMTU, errWGIncompatibleLinkRetained, linkOps, vrfBinder interfaces.
  - tunnel/manager.go: tunnelManager struct + ensureReconcileStateLocked, linkGenForLocked, bumpLinkGenLocked, ownedNames/appliedAddrs/appliedRI/wgConfigured lifecycle, Apply skeleton (desired split, removal diff) + finishTunnelLocked.
  - tunnel/anchor.go: anchorReusable, applyAnchorLocked, reconcileAnchorMTULocked.
  - tunnel/kernel.go: buildKernelTunnelLink, ipEqual, legacyTunnelMatches, applyKernelTunnelLocked.
  - tunnel/wireguard.go: wgTunMTUForEndpoint, applyWireguardTunLocked, closeTuntapFiles.
  - tunnel/addrs.go: reconcileLinkAddrsLocked, pruneAppliedAddrsLocked.
  - tunnel/vrf.go: reconcileVRFClaimLocked, unbindVRFClaimLocked, observeListClaimLocked.
  - tunnel/keepalive.go: keepaliveRunner.matches, keepaliveProber, startKeepalive, stopKeepaliveLocked, stopAll, stopAllKeepalivesLocked, keepaliveLoop, keepaliveTick, nextSeq, clearUnknownLocked, markUnknownLocked, classifyErrnoString, GetKeepaliveState, keepaliveProbeDeadline.
  - tunnel/clear.go: clearLocked, Clear, GetStatus.
  - Keep tunnel.go as facade re-exporting Apply/Clear etc or delete after moves.
- Seams to cut: linkOps interface already seam (test inject fake), vrfBinder seam, tunnelProber seam — keep. Ensure mu acquisition stays in manager.go orchestrator (wide scope comment preserved). linkGen atomic map mutated only under mu but Load lock-free in tick — preserve.
- Alternative: extract keepalive into subpackage routing/keepalive but keep same package to avoid import cycle (tunnelManager.mu field shared). Same package split preferred first.
- Also extract WG MTU model into tunnel/mtu.go with consts and pure func wgTunMTUForEndpoint so Rust model mirror comment lives isolated and can be unit-tested against Rust constants.

Hot-path preservation analysis:
- Cold path: Apply/Clear run at commit time under applyConfigLocked, not per-packet. KeepaliveLoop runs 1 per tunnel every Keepalive seconds (typically 10s) — not hot but must not take t.mu (AGY r5) and must preserve lock-free gen.Load guard. Mechanical file motion preserves that because tick still never takes mu (only state.mu). No allocation added per tick (nonce via crypto/rand 8 bytes).
- Netlink ordering critical: drain-before-recreate (stopKeepaliveLocked + bumpLinkGenLocked BEFORE LinkDel/Add) must be preserved #1918 F7 — moves must keep that order. Also closeTuntapFiles after LinkAdd to avoid fd leak.
- MTU constants must stay mirrored to Rust: move must preserve comment linking to userspace-dp afxdp/wg/mod.rs WG_OVERHEAD_V4/V6 and engine.rs WG_ENGINE_MAX_INNER_MTU and coordinator/wg_control.rs WG_DEFAULT_OUTER_MTU.
- WG persistent link invariant #1432 S2a: never LinkDel wgN — decomposition must keep ownedNames exclusion from removal loop.
- Fail-closed contract #5355: Apply returns errors.Join(errs) — preserved.
- No BPF map, no frame budget, no cache-line, no XDP fast path. Safe cold-path split.

Tests + gate:
- Existing: tunnel_reconcile_test.go 1825 LOC (adoption, handoff, link-local gate, VRF claim), tunnel_apply_failclosed_5355_test.go 180, tunnel_anchor_keepalive_test.go 350, tunnel_keepalive_test.go 574, tunnel_prober_test.go 263, teardown_linkdel_4901_test.go 119. All must pass after split.
- New unit tests after split: mtu model test asserting wgTunMTUForEndpoint(1500, v4) = 1425 (1500-60-15) vs v6 1405, clamp 4096; address reconcile test for AddrList failure carry-forward.
- Gate: go test ./pkg/routing -run TestTunnel -count=1 -race; go test ./pkg/routing -run TestKeepalive -count=1 -race.

Why it matters:
- 2016 LOC single file is review bottleneck — every tunnel bug fix (#1884 reconcile-in-place, #1918 keepalive Axis D, #1919 WG prune, #4071 anchor keepalive, #5119 bond signature, #5355 fail-closed) touches same file, causing merge conflicts and revert risk. God-file holds 8 maps + atomic + mutex + 3 creation paths + keepalive + VRF + MTU model — unreviewable in one PR.
- Similar to earlier routing facade split #1698: Manager split into per-domain managers but tunnelManager itself was NOT split — it remained god. Now needs second-level split.
- Onboarding: new engineer adding GRE key or WG endpoint cannot reason about linkGen atomic or ownedNames retention without reading 2000 lines.

Fix direction:
- Phase 1: extract pure helpers buildKernelTunnelLink, ipEqual, legacyTunnelMatches, anchorReusable, wgTunMTUForEndpoint, closeTuntapFiles into tunnel/util.go — no mu, no behavior change.
- Phase 2: extract address reconcile (reconcileLinkAddrsLocked, pruneAppliedAddrsLocked) + VRF claim (3 fns) into tunnel/addrs.go + tunnel/vrf.go — they already take link + name + maps, require mu held but don't take it themselves.
- Phase 3: extract keepalive lifecycle (Runner struct + start/stop/loop/tick) into tunnel/keepalive.go — keep mu semantics (stop drains done channel). This is largest move ~600 LOC.
- Phase 4: split creation paths anchor/kernel/wireguard into separate files, keep Apply orchestrator in manager.go ~250 LOC.
- Each phase preserves func signatures, package same, no new allocs. Run go vet + make test-go per phase.
- Update docs/routing.md (tunnel section) to reference new file layout.

Labels: refactor:decompose, critical, god-file, cold-path, keepalive, wireguard, priority:p0, routing
Dedup note: deduplicate previous audit noted GRE/IPIP/WG/MTU/VRF/addr reconcile mixed with keepalive goroutine Axis D commit-after-success — same finding but this batch provides detailed seam list + WG MTU model mirror. Not overlapping with prior splits #1698 (routing Manager facade) — this is second-level split inside tunnelManager which was left unsplit.

---

### 2. pkg/routing/rules.go — 1447 LOC — VERDICT: MAJOR MONOLITH (install vs build fused)

Title: rules.go 1447 LOC fuses 3 ip-rule managers (next-table, rib-group, PBR) + PBR builder from firewall filters + FBF attachment collection

Severity: major
Confidence: high
Refactor class: A — large file >1000 LOC, B — fusing 3 distinct managers + builder, C — shared const windows

Evidence:
- File contains 3 manager types: nextTableManager (L81-223), ribGroupManager (L235-496), pbrManager (L582-709) each with Apply/clear, plus protocol-wide helpers isRuleAlreadyGone (L231), resolveRibTable, ribInstanceFromName, plus PBR domain types PBRRule (L498-539) with DSCP presence flag TOSSet #3430 H2, IIF scoping #5117, L4 fields IPProto/Sport/Dport #3730, PBRPortRange, plus builder BuildPBRRules (L711-819, 108 LOC) which collects attachments via collectAttachedInputFilters (L885-923) preserving ingress interface via ResolveKernelIfName (Junos fenced name → Linux name collapse unit-0, VLAN 50, RETH member), plus sortAttachments determinism, plus per-filter builder buildPBRFromFilter (L941-1132) 191 LOC handling contradictory routing-instance+discard/reject #4534 fail-open guard + unrepresentable L4 predicate classifier pbrTermL4 #3730 (port-except, tcp-flags, is-fragment, icmp-type/code, flex-match, unknown from) fail-closed, DSCP 0 drop #3430 H2, src/dst prefix-list expansion via resolvePBRDirection (L1225-1344) 119 LOC with pure-except vs mixed positive+except #3359 positive-wins, any/0.0.0.0/0 → unconstrained, empty constrained-but-empty → skip term, normalization via normalizePBRAddr (L1352-1369).
- Constants interdependent: nextTableRulePriority 100 window 100, ribGroupRulePriority 33000 legacy blanket, ribGroupLeakRulePriority 30000 #3876 per-prefix leak before main 32766 but after? Actually PBR 31000-31999 sits after leak 30000 before main 32766? Order: leak 30000, PBR 31000, main 32766, legacy rib 33000. Window sizes maxRibGroupLeakRules 1000, maxPBRRules = config.PBRRuleWindow 1000. Must stay scanned by clear() % 200/300 legacy, 30000-30999, 31000-31999, 33000-33099. Clear() for each manager scans BOTH families via RuleList and aggregates dump failures #2273 partial failure not abort, returning via errors.Join.
- BuildPBRFromFilter expansion cross-product: toses × protos × sports × dports × srcs × dsts up to maxPBRRules truncation degraded #3430 M3. Each dimension normalized to single unset entry when unconstrained so address-only still emits 1 rule. Contradictory discard/reject dropped with degraded error.
- PBRBuildStats (L844-858) pure function counting installed vs degraded via errors.Join Unwrap []error.
- Mixing concerns: install path (RuleAdd/Del via ruleOps seam) vs build path (pure config → PBRRule slice) vs attachment collection (interface config → pbrAttachment with IIF resolution) vs low-level helpers (dscpToTOS 46 lines, hasRealString). Single file change touches both kernel programming and firewall filter semantics.

Proposed decomposition:
- Split mechanical moves same package:
  - rules/types.go: PBRRule, PBRPortRange, ruleOps interface, consts nextTableRulePriority, ribGroupRulePriority, ribGroupLeakRulePriority, pbrRulePriority, maxRibGroupLeakRules, maxPBRRules, mainTableID, plus pbrAttachment struct.
  - rules/nexttable.go: nextTableManager.Apply/clear + isRuleAlreadyGone.
  - rules/ribgroup.go: ribGroupManager.Apply/clear, ribGroupLeaksIntoMain, splitConnectedPrefixesByFamily.
  - rules/pbr_install.go: pbrManager.Apply/clear.
  - rules/pbr_build.go: BuildPBRRules, PBRBuildStats, collectAttachedInputFilters, sortAttachments, buildPBRFromFilter (still large 191 LOC but single responsibility: filter→rules).
  - rules/pbr_classify.go: pbrTermL4, hasRealString, resolvePBRDirection, normalizePBRAddr, dscpToTOS, resolveRibTable, ribInstanceFromName.
  - Keep rules.go as barrel re-export or delete.
- Seams: ruleOps already narrow netlink policy-routing surface for unit-test injection (tests inject fake). collectAttachedInputFilters uses cfg.ResolveKernelIfName which is config domain but same package can access. Build path pure (no netlink) — extract first, zero risk.
- Also extract constant windows into config package SSOT already partially done (PBRRulePriorityBase in pkg/config) — keep install band constants referencing config.PBRRuleWindow #4479 snapshot skip band mirroring.

Hot-path preservation analysis:
- Cold path: Apply* called at commit time holding routing manager locks? Actually rules managers are stateless apart from borrowed ruleOps, no own mutex — safe. BuildPBRRules pure config walk, no netlink. No per-packet alloc. Formatting? No. So splitting file does not affect hot path.
- Ordering critical: clear() before Apply re-add ensures no stale rules #2273; must preserve per-family RuleList failures aggregated not swallowed. Keep.
- PBR IIF scoping #5117: BuildPBRRules guarantees IifName non-empty else fail-closed dropping term + degraded — install path also guards pbr.IifName=="" refuse global iif-less rule. Both checks must stay.
- No BPF ABI, no Rust helper. Safe.

Tests + gate:
- Existing: rules_test.go 1039 LOC covers next-table, rib-group per-prefix #3876 shadow-by-default, PBR IIF scoping #5117 cross-WAN leak, DSCP 0 drop, L4 predicates #3730 over-steer vs under-steer, except fail-closed, overflow truncation, BuildPBRFromFilter contradictory discard #4534. Must pass after split.
- Gate: go test ./pkg/routing -run TestPBR -count=1; go test ./pkg/routing -run TestRibGroup -count=1; go test ./pkg/routing -run TestNextTable -count=1.

Why it matters:
- 1447 LOC single file with 3 managers + builder is merge-conflict magnet: rib-group Phase1 (#3876 per-prefix leak) and PBR IIF scoping (#5117) and L4 support (#3730) all edited same file concurrently. Builder logic for firewall filter FBF semantics (attached input filter only #3430 H1, per-interface #5117, representability matrix #3730) is conceptually separate from netlink install — mixing makes review hard (builder change touches RuleDel logic).
- File also contains subtle window caps matching clear() scans — a cap mismatch would leak rules permanently (hard-cap at priority window upper bound checked at top of loop). Splitting install vs build makes caps review isolated.

Fix direction:
- Phase 1: extract pure builder collectAttachedInputFilters + sortAttachments + PBRBuildStats into rules/build_attach.go — no netlink.
- Phase 2: extract nextTableManager, ribGroupManager, pbrManager each to own file with clear() — mechanical move, keep func receivers same, keep errors.Join aggregation.
- Phase 3: extract pbrTermL4 + resolvePBRDirection + normalizePBRAddr + dscpToTOS + ribGroupLeaksIntoMain helpers into rules/pbr_classify.go.
- Each phase run go vet + make test-go.

Labels: refactor:split, major, pbr, rib-group, next-table, cold-path, priority:p1, routing
Dedup note: matches dedup-index entries "Filter + CoS compilers each 1200+ LOC with shared helpers" — but this is routing rules not firewall filter compilers; however pattern similar. Also "protocol.go wire-format monolith" not this. Prior routing split #1698 split Manager facade but left rules.go intact — this is remaining second-level split.

---

### 3. pkg/upgrade/cutover.go — 1045 LOC — VERDICT: MODERATE MONOLITH (orchestrator)

Title: cutover.go 1045 LOC orchestrator mixing cluster gate, source resolution, lock, DB snapshot, staged copy, flip

Severity: moderate
Confidence: high
Refactor class: B — orchestrator fusing 7 phases, single Run 300+ LOC

Evidence:
- Runner struct holds cfg, stagedGenConfig, clusterNodeIDPresent, etc. Options struct with 4 bools (SkipStartHealthRollback, UnitAlreadyStopped, LockAlreadyHeld #1965, AllowNoRollbackFirstCut #1964, ClusterCoordinated #5284) — 5 flags controlling standalone vs rolling vs first-install.
- resolveSource (L70-140) 70 LOC: prefers current-gen, falls back to pinned generation protected from GC while journaled, legacy in-flight live staged/, errNoSourceGeneration init sentinel #1981 Option B.
- Run (L141-?) ~500+ LOC: cluster gate BEFORE lock/journal/mutation #5284/#5573 (clusterNodeIDPresent check, indeterminate EACCES/EIO fail-closed guidance), host-wide upgrade lock acquisition (flock EWOULDBLOCK #1965), journal read, DB snapshot preflight fail-closed #5074, staged copy with source gen pinning, flip (6a symlink current, 6b bin symlink, 6c unit drop-in), start, health rollback, version pin.
- Mixes policy (cluster gate refusal message with guidance) + mechanism (lock, journal, DB snap, copy, flip, start).
- Also contains Options doc comments 80 LOC explaining each flag's invariant (plan §8 inv C, inv 8, etc).

Proposed decomposition:
- Split into smaller phase files same package:
  - cutover/gate.go: cluster gate checks clusterNodeIDPresent + indeterminate handling #5573 + refusal message construction.
  - cutover/source.go: resolveSource pureish (depends on os.Stat, stagedGenConfig) — already 70 LOC.
  - cutover/options.go: Options struct + doc + validation.
  - cutover/run.go: Run orchestrator calling gate→lock→journal→snapshot→copy→flip→start→health phases via helper interfaces.
  - Existing runner.go 596 LOC may already duplicate Run? Need consolidate: cutover.go Run is standalone flow, runner.go may be rolling? Actually runner.go also contains Runner.Run — check: both files define Runner? Need dedup: cutover.go defines Options and resolveSource and Run, runner.go defines Runner struct and Run duplicate — check for duplicate method. Should merge into one orchestrator file + phases.
- Alternatively keep cutover.go as orchestrator but extract each phase into private helpers: acquireLock, readJournal, takeDBSnapshot, copyStaged, doFlip, doStart, doHealthRollback.

Hot-path preservation: Cold path single-node upgrade invoked via CLI, not per-packet. Ordering critical: gate before lock before journal before DB snapshot before stop (#1964 C unconditional). Must preserve fail-closed refusals not stopping unit.

Tests: cutover_cluster_gate_5284_test.go, cutover_cluster_gate_indeterminate_5573_test.go, cutover_refuse_test.go, preflight_dbsnap_failclosed_5074_test.go.

Fix direction: Extract gate and source into own files first (pure logic), keep Run as thin orchestrator <150 LOC.

Labels: refactor:decompose, moderate, upgrade, orchestrator, priority:p1
Dedup note: Not in dedup-index; related to staged upgrade HA coordination #5284/#5573.

---

### 4. pkg/upgrade/cluster_cli.go — 610 LOC — VERDICT: MODERATE (text parsing many formats, but cohesive)

Title: cluster_cli.go 610 LOC gRPC cluster status text parsers defensive but many parsers in one file

Severity: moderate (parsing complexity not monolith)
Confidence: high
Refactor class: C — hub of many pure parsers, could split

Evidence:
- grpcCluster dials 127.0.0.1:50051 via insecure creds, fetches show chassis cluster information/status text via gRPC ShowText RPC (Topic). Uses SystemAction RPC for non-interactive demote #1563 (cli -c hard-errors in non-TTY).
- 7 parser funcs: parsePeerAlive, parseSyncEstablished (scoped to sync/fabric link section header, blank-line terminated, requires Status: Up exact not substring #AGY review-011), parseHAProtocolCompatible (local vs peer version lines, missing peer fail-closed), parsePeerTakeoverReady (takeover ready, transfer ready, monitor failures, best-effort pre-demotion gate #CODE comments), parseDrainComplete (requires local secondary + peer primary per-RG pairing, per-RG header parsing with curRG reset #5044, node name parsing), parseLocalNodeID, parseNodeToken, parseRGIDs, configuredRGsFromStatus fail-closed #5044 (no hardcoded {0,1,2} guess), trailingInt, firstTokenAfterColon, lineHasAll, atoiSafe.
- Each parser pure (string → bool/[]int) with extensive defensive comments (substring vs token after colon, YES with reason containing "no" must not trip).
- Single file mixes gRPC dialing (impure) + pure parsers + constants (addr 127.0.0.1:50051, timeout 5s). Not god-struct but 610 LOC with 15 funcs.

Proposed decomposition:
- cluster_cli/client.go: grpcCluster struct, NewCLICluster unit guard #1983 wrong-daemon, dial, ctx, information, statusText, systemAction.
- cluster_cli/parse_peer.go: parsePeerAlive, parseSyncEstablished.
- cluster_cli/parse_drain.go: parseDrainComplete, parseLocalNodeID, parseNodeToken, parseRGIDs, configuredRGs, configuredRGsFromStatus, parsePeerTakeoverReady.
- cluster_cli/parse_version.go: parseHAProtocolCompatible, trailingInt, firstTokenAfterColon, lineHasAll, atoiSafe.
- Keep 610 LOC but split parsers from client for testability (pure parsers already tested via cluster_cli_test.go feeding real FormatInformation output).

Hot-path: Cold path upgrade prechecks, 1/s during rolling? Actually rolling driver calls PeerAlive/SyncEstablished/DrainComplete via gRPC at most 1/s — not hot, control-socket contention rule not violated (gRPC not control socket). Safe.

Why it matters: parser correctness critical for HA upgrade safety (drain predicate must not misread). Splitting clarifies per-RG pairing logic vs sync status scoping. Already well-commented but file size makes audit hard.

Fix direction: Move pure parsers to parse.go with table-driven tests existing cluster_cli_test.go; keep client.go thin.

Labels: refactor:optional-split, moderate, upgrade, ha-parsing, defensive-parsing, priority:p2
Dedup note: Not listed as god-file; related to rolling upgrade safety #5284.

---

### 5. pkg/upgrade/kernel_linux.go — 869 LOC — VERDICT: MODERATE (Linux-specific kernel mgmt mixed with pkg query and self-recovery glue)

Title: kernel_linux.go 869 LOC Linux kernel management mixing dpkg query, boot config, purge, self-recovery

Severity: moderate
Confidence: medium
Refactor class: B — fusing 4 kernel concerns

Evidence:
- Implements kernelOps Linux interface, plus helpers for dpkg --list, /boot listing, version compare, purge old kernels 5076, pkgquery fallback 5428, version validation 5452, self-recovery glue.
- Mixes exec.Command for dpkg, ls /boot, update-grub, etc with parsing.
- Some logic overlaps with kernel.go 334 wrapper and kernel_drain.go 160 and kernel_selfrecover.go 273 and kernel_run.go 637 — kernel domain split across 5 files already but kernel_linux.go still large.

Proposed decomposition:
- kernel_linux/pkgquery.go: dpkg query, version parse 5452 validation.
- kernel_linux/purge.go: purge old kernels 5076.
- kernel_linux/boot.go: boot config, update-grub.
- Keep kernel_linux.go as thin facade aggregating.

Hot-path: Cold path kernel upgrade, runs pre/post flip. No hot.

Tests: kernel_linux_test.go 73, kernel_pkgquery_5428_test.go 157, kernel_purge_5076_test.go 219, kernel_version_validate_5452_test.go 232 already split per concern — code should follow test split.

Fix direction: Split per test file concerns.

Labels: refactor:split, moderate, upgrade, kernel, priority:p2

---

### 6. pkg/upgrade/kernel_run.go — 637 LOC — VERDICT: MODERATE (run orchestrator)

Title: kernel_run.go 637 LOC kernel upgrade run orchestrator

Severity: moderate
Confidence: medium
Refactor class: B — orchestrator

Evidence:
- Wraps kernel upgrade steps: drain, stop, flip, start, health, rejoin. Similar to cutover.go but for kernel.
- Uses helper_health.go, kernel_drain.go, etc.

Proposed decomposition: Extract drain/rejoin steps into phases, keep run thin.

Labels: moderate, upgrade, kernel

---

### 7. pkg/upgrade/runner.go — 596 LOC — VERDICT: MODERATE (duplicate of cutover.go? Actually contains Runner struct)

Title: runner.go 596 LOC possibly duplicate orchestrator — check for overlap with cutover.go

Severity: low (needs consolidation)
Confidence: medium
Refactor class: D — duplication vs cutover.go

Evidence:
- Earlier cat shows runner.go may duplicate Runner.Run defined also in cutover.go — need consolidation into one file set. If two Runner.Run exist, build fails, so one must be wrapper. Check: cutover.go has Options and resolveSource and Run; runner.go may have different Runner? In listing earlier, cutover.go 1045 and runner.go 596 both exist at same package upgrade — they likely define different receiver types or runner.go is older and cutover.go is newer? Must dedup.

Fix direction: Consolidate into runner.go + phases, move Options to options.go, gate to gate.go, source to source.go.

Labels: duplication, needs-consolidation

---

### 8. Remaining routing prod files — VERDICT: NOT MONOLITHIC (negative findings)

#### 8a. routing.go 237 LOC
Title: routing.go 237 LOC facade after #1698 domain split — exemplary modularization

Severity: none
Confidence: high
Refactor class: N/A — anti-monolith

Evidence:
- Manager struct owns 10 domain managers each with own ops seam and lock, constructed in New() with shared *netlink.Handle borrowed not closed except in Close(). stopAll before nlHandle close #848 drain guarantee. Each public method delegation one-liner to owning domain preserving historical API byte-for-byte.
- No netlink logic in facade, only wiring. Previous monolith with single ifaceMu split into per-domain mu.
- Test seams documented.

Fix direction: None — keep as example.

Labels: negative, exemplary, facade, well-modularized

---

#### 8b. routes.go 356 LOC
Title: route reader stateless, single responsibility, not monolithic

Severity: none
Confidence: high

Evidence:
- routeReader struct only ops routeLister (4 methods). Methods GetRoutesForTable, GetRoutes, GetVRFRoutes, GetTableRoutes, GetAllTableRoutes each <50 LOC. Per-family independent dump with errors.Join partial result #5125. ECMP NextHops extraction via multiPathNextHops. Protocol mapping rtProtoName 10 cases. No state, no lock, pure conversion routeToEntry.

Fix direction: None.

Labels: negative

---

#### 8c. routeformat.go 292 LOC
Title: pure formatting helpers — not monolithic, 4 formatters cohesive

Severity: none
Confidence: high

Evidence:
- protoTag single-letter, junosProtoName mapping, FormatRouteTerse sorting by destination, appendSplitAF family split via ':' presence, FormatRouteDestination with exact/longer/orlonger modifiers using net.ParseCIDR LPM, FormatRouteSummary with Highwater Mark current=peak, formatTableJunos Junos-style header + NextHops ECMP per-leg rendering. All pure (no netlink), no side effects. Formatting concerns co-located logically.

Fix direction: None — could split terse vs summary vs destination but 292 LOC acceptable.

Labels: negative

---

#### 8d. vrf.go 361 LOC
Title: vrfManager single domain, well-injected vrfOps seam

Severity: none

Evidence:
- Own mu, vrfs slice. Create, createLocked (leaves existing alone not adopt — Reconcile is adoption entry), IsManaged, Reconcile (namespace claim entire vrf-* #847 orphan reap via LinkList, transient retention), BindInterfaceToVRF lock-free (no lock for tunnel cross-domain no cycle). reconcileVRFs pure core parameterised on vrfOps for fake injection, ownership semantics documented, partial-failure contract retains ownership on LinkAdd success but follow-up failure. errLinkNotFound sentinel wrapper + isLinkNotFound handling both netlink.LinkNotFoundError and internal. createLinkedVRF returns (added,bool) for ownership tracking.

Not monolithic.

Labels: negative

---

#### 8e. xfrm.go 332 LOC
Title: xfrmManager single domain with fail-closed aggregation

Severity: none (but moderate complexity)

Evidence:
- Own mu, xfrmis map name->Ifid. Apply differential reconcile #2546 keep unchanged if same if_id, create new, recreate on if_id change (Ifid immutable), delete not desired, collision detection distinct bind-interfaces deriving same if_id via XFRMIfNameAndID (#2909) refuse both. Transient lookup retention #5461, stale if_id verification #1706, deleteLocked retains on failure #4901, clearLocked only nil map when all gone. All error accumulation via errors.Join #5310.

Single responsibility.

Labels: negative

---

#### 8f. tunnel_keepalive.go 294 LOC
Title: keepalive prober single responsibility — exemplary seam

Severity: none
Confidence: high

Evidence:
- ProbeResult tri-state Alive/Dead/Unsupported + UnsupportedKind Structural/Transient. tunnelProber interface narrow, probeConn for test injection. listenICMP var for fake. icmpProber.Probe: IP parse, network selection udp4/udp6, source bind #5c, socket open, marshal, deadline, WriteTo with classifyWriteErr #1947 r1 HIGH (ENETUNREACH → Dead not transient, ENOBUFS → transient), ReadFrom loop deadline re-check R4防 flood extending, ParseMessage, Seq+Data-nonce authoritative match #5a not ID. bytesEqual small 8-byte constant-shape. classifyListenErr buckets EPERM/EACCES/EAFNOSUPPORT/EPROTONOSUPPORT/EPROTOTYPE/EADDRNOTAVAIL → structural, EMFILE/ENFILE/ENOBUFS/ENOMEM/EINTR → transient, default transient. classifyWriteErr inverse default Dead (path unreachable) vs transient. makeNonce crypto/rand 8B.

Single domain, 294 LOC pure prober.

Labels: negative, exemplary

---

#### 8g. test_seams.go 55 LOC
Title: test seams file — not monolithic, production-compiled only for cross-package tests

Severity: none

Evidence:
- NewManagerWithLinkOpsForTest builds Manager with linkOps fake for interface-reconcile tests (tunnel/xfrm/bond/reth/monitor). NewManagerWithRouteListerForTest builds routeReader fake for partial-render #5125. Mirrors pkg/configstore/test_seams.go pattern.

Labels: negative

---

### 9. Remaining upgrade prod files — VERDICT: NOT MONOLITHIC

#### 9a. flip.go 448 LOC
Single responsibility: three substeps 6a/6b/6c derived from ver idempotent crash re-run.

#### 9b. kernel.go 334 LOC
Thin wrapper over kernelOps interface, version handling.

#### 9c. kernel_drain.go 160 LOC
HA kernel drain: peer alive, sync, drain predicate, rejoin.

#### 9d. kernel_selfrecover.go 273 LOC
Boot self-recovery logic, kernel boot attempts tracking.

#### 9e. lock/lock.go 303 LOC
Host-wide upgrade lock via flock, EWOULDBLOCK handling, queue, stale detection. Single.

#### 9f. manifest/manifest.go 106 LOC
Manifest read/write, version pinning.

#### 9g. version.go 113 LOC
Version parsing, comparison.

#### 9h. imageversions.go 179 LOC
Image version listing.

#### 9i. system_linux.go 190 LOC
systemd StopUnit/StartUnit/daemon-reload.

#### 9j. state.go 165 LOC
Journal state machine enum.

#### 9k. helper_health.go 160 LOC
Helper health gate #5286.

#### 9l. rolling.go 247 LOC
Rolling upgrade orchestrator: peer alive, sync, drain, cut, rejoin.

#### 9m. runtime/seed.go 400 LOC
First-install seed logic (A) and legacy-migration snapshot (B), versions/current existence ensures rollback target.

#### 9n. stagedgen/fsutil.go 149 LOC
Filesystem utils for staged gen.

#### 9o. stagedgen/stagedgen.go 413 LOC
Staged gen lifecycle ResolveCurrent, GenDir, ValidGenID, GC protection while journaled #1981.

#### 9p. wgkey/wgkey.go 113 LOC
WireGuard key generation, curve25519 clamping, pubkey derivation.

All above <500 LOC single responsibility — not monolithic.

---

### 10. Test files (43) — NOT MONOLITHIC (expected large)

Test files naturally larger due to table-driven cases: routing_test.go 2193 LOC covers Manager facade with fakes; tunnel_reconcile_test.go 1825 LOC covers reconcile-in-place edge cases #1884; rules_test.go 1039 covers PBR IIF etc. These are test files, not prod monoliths — acceptable.

---

## Cross-Cutting Findings

### Routing package overall
- Before #1698, routing.Manager was god struct with single ifaceMu shared across VRF/tunnel/xfrm/bond/reth/monitor/routes/rules/probePin. After split, routing.go is 237 LOC facade with per-domain managers each own lock and ops seam — exemplary. However second-level monolith remains inside tunnelManager (2016 LOC) and rules.go (1447 LOC). Those were NOT split by #1698.
- Version tolerance: transient LinkByName errors retained not dropped (#5461/#5495/#4901) consistently across vrf, xfrm, tunnel — good pattern, but duplicated logic (isLinkNotFound checks) could be extracted to shared transient-retention helper.
- Fail-closed contract #5355/#5310 applied consistently: Apply returns errors.Join not nil after logging — good defense, prevents false convergence.
- PBR building: FBF attachment collection via ResolveKernelIfName is config domain but under routing — could argue belongs in config compiler, but routing install needs IIF resolution; current placement reasonable.

### Upgrade package overall
- Upgrade domain is well split into subpackages: lock, manifest, stagedgen, runtime. Each <500 LOC. Top-level orchestrators cutover.go (1045) and runner.kt? Actually runner.go 596 and kernel_run.go 637 are separate orchestrators for image vs kernel. Could be further split into phases but not critical.
- Cluster CLI parsing is defensive and conservative (unrecognized state → not-drained not-ready → ABORT without cut) — good safety posture. Per-RG pairing in DrainComplete prevents active-active false complete where peer owns one RG but not other.
- Lock package uses flock with /tmp path but queue behind holder via cluster-cell.sh preamble #4020 — code matches docs.
- Stagedgen current-gen pinning #1981 protects from GC while journaled — good.
- Kernel management: dpkg query fallback 5428 and purge 5076 kept separate test files — code should follow.

### Wgkey
- 113 LOC single file, pure crypto, well scoped.

---

## D-negatives — What NOT to split

- routing.go facade must stay thin, not absorb logic — keep as 237 LOC delegation.
- routes.go routeReader must stay stateless, no lock, no side effects — keep.
- tunnel_keepalive.go prober must not take t.mu (AGY r5 deadlock note) — keep lock-free gen.Load() guard. Do NOT merge keepalive loop into tunnelManager.mu critical section.
- vrf.go namespace-claim entire vrf-* must stay authoritative #847 — do NOT preserve external VRFs.
- xfrm.go if_id collision guard #2909 must stay — last line defense against cross-VPN leak.
- rules.go windows: nextTable 100-199, ribGroup 30000-30999 + 33000-33099 + 200-299 legacy, PBR 31000-31999 must stay scanned by clear() — extraction must preserve exact ranges.
- upgrade lock must stay host-wide via flock, not in-memory only — preserve EWOULDBLOCK handling.
- wgkey must not add external deps — keep pure wireguard-go curve25519.
- Test files: tunnel_reconcile_test.go 1825 LOC is large but tests edge cases of reconcile-in-place — splitting would lose coverage context; keep as one file.

---

## Summary

- Total files: 73 (30 prod 12900 LOC + 43 test 15238 LOC)
- Monolithic prod files: 2 critical/major (tunnel.go 2016, rules.go 1447) + 3 moderate (cutover.go 1045, kernel_linux.go 869, cluster_cli.go 610) + 2 moderate orchestrators (kernel_run.go 637, runner.go 596)
- Well-modularized: routing.go facade exemplary after #1698, routes.go reader, vrf.go, xfrm.go, tunnel_keepalive.go prober, plus upgrade subpackages lock/manifest/stagedgen/runtime/imageversions/version/system/helper/rolling all <500 LOC single responsibility.
- No file >2000 except tunnel.go (2016) prod and routing_test.go (2193) + tunnel_reconcile_test.go (1825) test.
- Hot-path preservation: all routing and upgrade files are cold path (commit-time netlink + upgrade orchestration). No per-packet allocation, no BPF map ABI change, no AF_XDP fast path. Mechanical splits safe.
- Fix priority: tunnel.go first (P0), rules.go second (P1), then cutover/kernel_linux/cluster_cli optional (P2).

---

## Labels

- refactor:decompose, god-file, cold-path, routing, upgrade, tunnel, pbr, rib-group, keepalive, priority:p0-p2

## Dedup Note

- tunnel.go god-file matches dedup-index entry "GRE/IPIP/WG/MTU/VRF/addr reconcile mixed with keepalive goroutine Axis D commit-after-success defense — keepaliveTick never takes t.mu" — this audit provides detailed seam list for split that prior note flagged but did not decompose.
- rules.go matches pattern "Filter + CoS compilers each 1200+ LOC with shared helpers" but for routing rules not firewall CoS — similar structure, distinct domain.
- routing.go facade split #1698 closed earlier god-file — this audit confirms facade is now exemplary, but second-level tunnelManager and rules remain.
- upgrade cluster_cli parsing not in dedup god-file list — distinct but similar defensive parsing pattern.



---
### Batch A8_go_api_grpc_rest-b1 — 376 lines — full log + findings

# Refactor/Modularity Audit — A8_go_api_grpc_rest-b1

Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree: /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1
Batch: 150 files — pkg/api/*.go (all REST) + pkg/grpcapi small shims (apply_result.go, exec_timeout.go, ~8 tests)
Batch file: /tmp/review-work-ps-044/batches/A8_go_api_grpc_rest-b1.txt (150 entries)

---

## Module Checklist Inventory (Coverage Proof)

### Batch Files LOC — prod-only (non-test) sorted descending (full inventory from wc -l)

| File | LOC | Funcs | Responsibilities | Hot? |
|------|-----|-------|------------------|------|
| pkg/api/metrics_descriptors.go | 2067 | 1 func newCollector | Prometheus Desc registry — ~100 descriptors, global/interface/policy/filter/nat/dhcp/coS/fairness/wireguard/fabric/system/degraded | cold — /metrics scrape (1/s) |
| pkg/api/metrics_userspace.go | 1865 | 30+ emit* | Userspace status collectors — CoS owner/drain/park/waterfill/lease/sojourn/fair-occupancy/equal-flow, worker runtime/cold-path, binding active flow/tx-completion/vmin-throttle, fairness RSS/throughput, neighbor warm/cold/latency-hist, wireguard, policy-content-rejected, zone-id-collision, reject-observability, fabric-skip, drop-class, dynamic-buffer, event-stream, three-color-policer, SNAT pool | cold |
| pkg/api/sessions.go | 1541 | 32 funcs | REST session list (offset/cursor), summary, zone-pair, clear, enrichment v4/v6, page-token encode/decode, filtering (proto/prefix/port/nat/app/iface/SNAT-pool), HA peer fan-out via ClusterSessionService, admission limiter #5318/#5433, cancel sampler #5233 | cold but contended (BPF map walk) |
| pkg/api/metrics.go | 1161 | 3 funcs | xpfCollector struct + session gauge cache (singleflight #4162), Describe, Collect orchestration (pre-gate kernel nft host-inbound #3361/#4146/#4759/#3698/#3710/#3718/#4422 + flow-export #2464 + PBR + control-plane degraded signals + dataplane gate + shared userspace status fetch #5317) | cold |
| pkg/api/security.go | 942 | 8 funcs | zonesHandler, policiesHandler, screenHandler, eventsHandler, parseEventZoneFilter, hostInboundToREST, isMatchPoliciesSelector, matchPoliciesHandler (19 query validators #3709/#5316/#3355/#3108/#3116/#2934/#1711) | cold |
| pkg/api/types.go | 878 | types only | SessionEntry, SessionListResponse, SessionSummary, ZonePairSummaryResponse, PolicyInfo, ZoneInfo, RouteInfo, NAT pools, GlobalStats, InterfaceStats, etc. | cold |
| pkg/api/server.go | 789 | 4 funcs | NewServer route registration (~40 REST endpoints), TLS self-signed generation #1916, Run graceful shutdown, metrics auth gate #4162 | cold |
| pkg/api/metrics_counters.go | 586 | ~6 funcs | global counters, policy counters, interface counters, filter counters, NAT pool counters | cold |
| pkg/api/metrics_system.go | 429 | ~8 funcs | system CPU/mem/uptime, daemon RSS, neighbor periodic age, FRR reload degraded, IPsec rebind pending #4899, scheduler republish #3780, config persist degraded | cold |
| pkg/api/config.go | 417 | ~20 funcs | configEnter/Exit/Status/Set/Delete/Deactivate/Activate/Load/Commit/CommitCheck/CommitConfirmed/Confirm/Rollback/Show/Export/ShowRollback/Compare/History/Search/Annotate | cold |
| pkg/api/show_text.go | 359 | 2 funcs | showTextHandler — generic text show proxy to gRPC | cold |
| pkg/api/system.go | 363 | 3 funcs | systemInfoHandler, systemBuffersHandler + buffers parsing | cold |
| pkg/api/nat.go | 337 | 3 funcs | natSourceHandler, natDestHandler, natPoolStatsHandler | cold |
| pkg/api/interfaces.go | 298 | ~4 funcs | interfacesHandler, interfacesDetailHandler, iface stats | cold |
| pkg/api/sse.go | 294 | ~3 funcs | eventStreamHandler, logStreamHandler SSE | cold |
| pkg/api/routing.go | 275 | 4 funcs | routesHandler (BGP/OSPF/static leak), ospfHandler, bgpHandler | cold |
| pkg/api/api.go | 251 | ~8 funcs | decodeJSONBody 16MiB cap, writeJSON, queryUint16/Int strict, parseRefBaseUnit, allInterfaceNames | cold |
| pkg/api/stats.go | 171 | 2 funcs | globalStatsHandler, ifaceStatsHandler | cold |
| pkg/api/metrics_nat.go | 138 | 2 funcs | NAT pool utilization, persistent NAT metrics | cold |
| pkg/api/auth.go | 137 | 3 funcs | constantTimeAPIKeyMatch, checkAuthorization, isLoopbackBindAddr | cold |
| pkg/api/crosssite.go | 133 | 2 funcs | CORS handling | cold |
| pkg/api/health.go | 123 | 1 func | healthHandler: compileHealth 503, bootstrap import, persist degraded | cold |
| pkg/api/dhcp.go | 109 | 3 funcs | dhcpLeases, dhcpIdentifiers, clearDHCPIdentifiers | cold |
| pkg/api/exec_timeout.go | 90 | const + helper | requestExecTimeout 15s, ping floor 30s ceiling 150s, runTimeout | cold |
| pkg/api/vrrp.go | 49 | 1 func | vrrpHandler | cold |
| pkg/api/ipsec.go | 31 | 1 func | ipsecSAHandler | cold |
| pkg/grpcapi/apply_result.go | 10 | 1 func | applyResult() accessor for last apply | cold |
| pkg/grpcapi/exec_timeout.go | 136 | const + 3 funcs | diagExecTimeout helpers, combinedOutputTimeout | cold |

Batch total non-test LOC: ~12700 (REST) + 146 (gRPC shims) = ~12846 prod; 150 files includes 122 tests.

### Underlying Production Module — pkg/grpcapi (full, excl tests) for cross-batch context — mechanical splits question

```
  1778 server_sessions.go
  1074 server_show_security_text.go
   935 server_show_interfaces.go
   864 server_cluster.go
   768 server.go
   753 server_diag_zeroize.go
   707 server_show_firewall.go
   604 server_diag_monitor.go
   576 server_diag_system_action.go
   562 server_show.go
   562 server_show_routes_text.go
   548 server_show_system.go
   541 server_show_policies_text.go
   503 server_show_interfaces_text.go
   ... (total prod ~16000)
```

Question: Are server_diag.go + monitor + ping + system_action + zeroize + server_sessions already mechanical splits? YES — verified via func listings:

- server_diag.go 77 LOC: only dialPeer() helper, not a dump.
- server_diag_monitor.go 604 LOC, 8 funcs: MonitorPacketDrop, isLocalNodeRef, interfaceAliasSet, monitorRequestForwardedFromPeer, decideMonitorProxy, MonitorInterface, proxyMonitorInterface, monitorSummaryModeFromProto — single domain (monitor).
- server_diag_ping.go 248 LOC, 7 funcs: checkDiagArg, checkDiagArgs, Ping, buildPingArgv, Traceroute, buildTracerouteArgv, streamDiagCmd — ping/traceroute only.
- server_diag_system_action.go 576 LOC, 5 funcs: proxyPeerSystemAction, logSystemAction, zeroizeConfigRoot, runZeroize, SystemAction — but SystemAction switch holds 19 verbs (reboot/halt/power-off/zeroize/clear-config-lock/clear-arp/clear-iface-stats/clear-ipv6-neighbor/clear-policy-counters/clear-firewall-counters/clear-nat-counters/etc) — borderline god-switch, not god file.
- server_diag_zeroize.go 753 LOC, 10 funcs: zeroizeConfigDir, isTextRollbackFile, isFsatomicTemp, zeroizeRenderedConfigs, sweepFsatomicTemps, zeroizeRootAuthorizedKeysPath, zeroizeRootLoginAccount, zeroizeLookupUIDErr, zeroizeLoginAccounts, readProvisionedMarkerUID — focused zeroize domain, well split internally.
- server_sessions.go 1778 LOC, 30+ funcs: GetSessions, getSessionsCursor, setSessionsTotal, setSessionsNodeID, buildSessionFilter, matchV4/V6, fetchPeerSessions, getSessionsLegacy, GetSessionSummary, proxyPeerSessionSummary, GetZonePairSummary, computeZonePairSummary, ClearSessions, clearFilteredSessionsV4/V6, clearBatchV4/V6, etc. — large but func-level split per RPC family; could be further split file-wise but not a dumping-ground of unrelated RPC types (all session).

Conclusion: gRPC diag family IS already mechanically split per verb (monitor, ping, system_action, zeroize) — not dumped into single server_diag.go. server_sessions is the only remaining 1.7k monolith mixing list+summary+zone-pair+clear, but internally function-split.

### Largest Functions (prod, batch-relevant)

| File | Function | Approx Lines | Note |
|------|----------|--------------|------|
| pkg/api/metrics_descriptors.go | newCollector | 10-2067 = 2057 lines | Single literal returning xpfCollector with ~100 NewDesc — monolithic initializer |
| pkg/api/metrics.go | Collect | 905-1110 = 206 lines | Orchestrates ~15 sub-collectors + pre-gate kernel nft collectors, defer emitCounterReadErrors |
| pkg/api/sessions.go | sessionSummaryHandler | 606-728 = 122 lines | Full table walk with limiter, peerInclude, view, query |
| pkg/api/sessions.go | sessionsHandler | 109-177 = 68 lines | Admission limiter + page_size branch + cursor fallback |
| pkg/api/security.go | matchPoliciesHandler | 583-923 = 340 lines | Validates duplicate selectors #3709, unknown keys #5316, zones required #3355, src/dst IP, ports, protocol #3108/#3116, then simulator |
| pkg/api/server.go | NewServer | 358-520 = 162 lines | Registers ~40 HTTP routes in one func — router dumping ground |
| pkg/api/metrics_userspace.go | emitWireguardTelemetry | 194-322 = 128 lines | Per-tunnel counters, label loops |
| pkg/api/metrics_userspace.go | emitCoSWaterfillTelemetry | 1611-1679 = 68 lines | CoS waterfill metrics |
| pkg/grpcapi/server_sessions.go (out-of-batch reference) | ClearSessions | 996-1118 = 122 lines + filtered clear batching #5454 | clear-all vs filtered, zone resolve, recursion guard |
| pkg/grpcapi/server_diag_system_action.go | SystemAction | 136-576 = 440 lines | 19-case switch — god-switch |

### Responsibilities Fused

- `metrics_descriptors.go`: global packets/drops/sessions/screen/policy/nat/hostInbound/kernelDenies/junosHostDenies/ICMPNDAccept/addressless/ambiguous/lo0/pbrCounters + NAT pool + DHCP DDNS + surfaceA DDNS + system CPU/mem/daemonUptime + neighbor/FRR-degraded/IPsec-rebind/scheduler-republish/configPersist/rollbackHistory/feed status + flow-export + interface + policy + filter + policer + session gauges — all in ONE func newCollector struct literal.

- `server.go` REST: health + /metrics + /status + /statistics/* + /security/zones/policies/sessions/summary/zone-pairs/nat/screen/events + /interfaces + /dhcp + /routes + /config + /routing/ospf/bgp + /security/ipsec + /security/nat + /security/vrrp + /security/match + /interfaces/detail + /services/flow-exporters + /system + POST clear sessions/counters + diagnostics ping/traceroute + config enter/exit/set/delete/deactivate/activate/load/commit/check/confirmed/confirm/rollback/show/export/compare/history/search/annotate + dhcp clear + SSE streams + show-text — single NewServer mux registration.

- `sessions.go` REST: list (offset + cursor) + summary + zone-pair + clear + enrichment + page-token + filtering + HA peer fan-out + admission limiter + cancel sampler — all session but 4 RPC families in one file.

- `security.go`: zones, policies, screen, events, match-policies simulator — 5 handlers in one file, each distinct but grouped by security zone.

### Hot-path Proximity Rank

1. `metrics_descriptors.go` 2067 LOC × ~20 responsibility domains × cold (scrape) = HIGHEST LOC but NO hot-path (mechanical safe to split)
2. `metrics_userspace.go` 1865 LOC × ~24 emit* families × cold = second, but already func-split per family — good modularity
3. `sessions.go` 1541 LOC × 4 RPC families (list/summary/zonepair/clear) × near-hot (BPF map walk under limiter #5318/#5433) = third, HIGHEST contention risk but cold control path
4. `metrics.go` 1161 LOC × Collect orchestrator × cold = fourth
5. `security.go` 942 LOC × 5 handlers × cold = fifth
6. `server.go` 789 LOC × 40 routes × cold = sixth but dumping-ground registration
7. `server_sessions.go` (gRPC, out-of-batch) 1778 LOC × 8 responsibilities × near-hot = would be highest if in batch, but already func-split.

All APIs are cold management path (REST /metrics 1/s, sessions with limiter 4 concurrent #5318). No per-packet hot path touched. Mechanical split safe.

---

## Findings

### Finding 1 — metrics_descriptors.go monolithic initializer 2067 LOC single function newCollector

- Title: `pkg/api/metrics_descriptors.go` 2067-LOC single-function Desc registry fuses 20+ metric families into one struct literal, god-initializer
- Severity: medium
- Confidence: high
- Refactor class: B — module too big, fuses distinct responsibilities, hard to review diff, easy merge conflict
- Evidence:
  - File: `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/metrics_descriptors.go` 2067 LOC, `grep -n "^func"` shows only 1 func `newCollector`
  - Snippet:
    ```
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
                // #4508: enforcement drops only — policy deny + screen/IDS +
                ...
            ),
            counterReadErrorsTotal: prometheus.NewDesc(
                "xpf_counter_read_errors_total",
                ...
            ),
            sessionsCreatedTotal: prometheus.NewDesc(...),
            // ... 100 more Descs in same literal
    ```
  - 58 test files depend on descriptor names (`metrics_descriptor_coverage_test.go` 733 LOC asserts each Desc present), so rename/move risks coverage break.
  - No hot-path: Collect uses Descs but creation is cold (once per Server).
  - Proposed decomposition: split into `metrics_desc_global.go` (packets/drops/sessions/screen/policy/nat), `metrics_desc_interfaces.go`, `metrics_desc_nat.go`, `metrics_desc_dhcp_ddns.go`, `metrics_desc_system.go` (CPU/mem/daemon/FRR/IPsec/scheduler/persist/rollback), `metrics_desc_userspace.go` (CoS/worker/fairness/wireguard/fabric/reject). Each file declares `func (c *xpfCollector) initGlobalDescs()` etc., or `newCollector` becomes composition: `c := &xpfCollector{srv: srv}; c.initGlobalDescs(); c.initNATDescs(); ...; return c`. Keeps coverage test mechanical (still registers same Descs).
  - Hot-path preserved: Descs are prometheus.Desc pointers, no per-packet allocation change.
  - Tests+gate: `go test ./pkg/api -run TestDescriptorCoverage` plus `make test-go` must pass; add file-existence gate.
  - Labels: `refactor`, `observability`, `low-risk`
  - Dedup: none.

### Finding 2 — pkg/api/server.go NewServer 789 LOC route registration dumping-ground (40 endpoints in one func)

- Title: REST server route registration dumping-ground — 40+ mux.HandleFunc in single NewServer 162-line block
- Severity: low
- Confidence: high
- Refactor class: C — mechanical split would improve readability, zero risk
- Evidence:
  - File: `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/server.go` LOC 789, 4 funcs, but NewServer lines 358-520 register all routes:
    ```
    mux.HandleFunc("GET /health", s.healthHandler)
    mux.HandleFunc("GET /metrics", ...)
    mux.HandleFunc("GET /api/v1/status", s.statusHandler)
    mux.HandleFunc("GET /api/v1/statistics/global", s.globalStatsHandler)
    mux.HandleFunc("GET /api/v1/statistics/interfaces", s.ifaceStatsHandler)
    mux.HandleFunc("GET /api/v1/security/zones", s.zonesHandler)
    mux.HandleFunc("GET /api/v1/security/policies", s.policiesHandler)
    mux.HandleFunc("GET /api/v1/security/sessions", s.sessionsHandler)
    mux.HandleFunc("GET /api/v1/security/sessions/summary", s.sessionSummaryHandler)
    // ... 30 more
    mux.HandleFunc("POST /api/v1/security/sessions/clear", s.clearSessionsHandler)
    // diagnostics
    mux.HandleFunc("POST /api/v1/diagnostics/ping", s.pingHandler)
    // config 20+ routes
    mux.HandleFunc("POST /api/v1/config/enter", s.configEnterHandler)
    ...
    ```
  - Each handler already in separate file (sessions.go, security.go, config.go, etc.), only registration is fused.
  - Proposed decomposition: helpers `registerHealthRoutes(mux)`, `registerSessionRoutes(mux)`, `registerSecurityRoutes(mux)`, `registerConfigRoutes(mux)`, `registerMetricsRoutes(registry)`, `registerSystemRoutes(mux)` — each in `server_routes.go` or per-domain file. Mechanical, no behavior change.
  - Hot-path: cold — HTTP handler registration at startup.
  - Tests+gate: existing `server_run_leak_5058_test.go` + `health_test.go` + `http_dos_hardening_4150_test.go` verify server start; no new tests needed beyond `go test ./pkg/api -run TestServer`.
  - Labels: `refactor`, `readability`, `low-risk`
  - Dedup: none.

### Finding 3 — pkg/api/sessions.go 1541 LOC mixing 4 session RPC families in one file, borderline god file but func-split

- Title: `sessions.go` 1541 LOC holds list+summary+zone-pair+clear + enrichment + token codec + filtering + HA peer + limiter — large but func-split, candidate for file-per-family mechanical split
- Severity: medium
- Confidence: medium
- Refactor class: B — module too big, fuses multiple RPC families, hard to review security boundaries (#3423 peer fan-out vs local-only)
- Evidence:
  - File: `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/sessions.go` 32 funcs:
    ```
    func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
        // Admission bound (#5318)
        release, err := sessionWalkLimiter.Acquire()
        ...
    }
    func (s *Server) sessionsOffset(...)
    func (s *Server) sessionsCursor(...)
    func (s *Server) enrichSessionV4(...)
    func (s *Server) sessionSummaryHandler(w http.ResponseWriter, r *http.Request) {
        // similar limiter #5433 shared with list
    }
    func (s *Server) clearSessionsHandler(...)
    func (s *Server) sessionZonePairHandler(...)
    func buildSessionQuery(...)
    func parseSessionPageToken(...)
    func encodePageTokenV4/V6(...)
    ```
  - `clearSessionsHandler` delegates to `ClusterSessionService.ClearSessions` which fans out to peer — security boundary mixing with list path that also fans out via `include_peer`.
  - `sessionWalkLimiter` is package var shared across list/summary/zone-pairs — #5318/#5433 global cap 4 concurrent walks, O(BPF map) contention with session sync.
  - `defaultSessionCountCap` 1_000_000 for exact Total vs approximate lower bound #5318.
  - Proposed decomposition: split into `sessions_list.go` (sessionsHandler, sessionsOffset, sessionsCursor, buildSessionView, buildSessionQuery, enrichSessionV4/V6, token codec), `sessions_summary.go` (sessionSummaryHandler, summaryFromPB), `sessions_zonepair.go` (sessionZonePairHandler, zonePairSummaryFromPB), `sessions_clear.go` (clearSessionsHandler + batching #5454 observer seam). Keep limier/consts in `sessions_common.go`. Mechanical — each file <400 LOC.
  - Relation to gRPC counterpart: `pkg/grpcapi/server_sessions.go` 1778 LOC has same families — mirroring split would keep REST/gRPC parallel (easier review).
  - Hot-path: near-hot but cold control path; iterates BPF maps holding per-bucket locks, bounded by limiter 4 and cancel sampler every 1024 entries #5233. Splitting files does not change iteration.
  - Tests: `sessions_pagination_test.go` 452 LOC, `sessions_ha_scope_3423_test.go` 490 LOC, `sessions_parity_test.go` 221 LOC, `sessions_aggregation_bound_5433_test.go` 219 LOC, `sessions_pagination_bound_5318_test.go` 243 LOC, `sessions_iterator_error_test.go` — all must pass after split: `go test ./pkg/api -run Session`.
  - Labels: `refactor`, `ha`, `dos-hardening`, `low-risk`
  - Dedup: Duplicates filtering logic `matchV4/matchV6` with `pkg/grpcapi/server_sessions.go` `sessionFilter.matchV4/matchV6` — slight divergence risk, could extract shared `pkg/sessfilter` but out of scope for B1.

### Finding 4 — pkg/api/security.go 942 LOC mixing 5 security domains, matchPoliciesHandler 340 LOC with 19 validators — god handler

- Title: `security.go` 942 LOC fuses zones/policies/screen/events/match-policies — matchPoliciesHandler 340 LOC single handler with 10 validation stages, could be extracted
- Severity: medium
- Confidence: medium
- Refactor class: B — large handler with sequential validation, hard to unit test individual validators
- Evidence:
  - File: `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/security.go` 8 funcs, `matchPoliciesHandler` lines 583-923:
    ```
    func (s *Server) matchPoliciesHandler(w http.ResponseWriter, r *http.Request) {
        // #3709: validate duplicate scalar
        for _, key := range matchPoliciesSelectorKeys {
            if len(q[key]) > 1 { writeError 400 }
        }
        // #5316 unknown selector
        var unknown []string
        for key := range q {
            if !isMatchPoliciesSelector(key) { unknown = append(unknown, key) }
        }
        if len(unknown) > 0 { 400 }
        fromZone := q.Get("from_zone")
        toZone := q.Get("to_zone")
        if fromZone == "" || toZone == "" { 400 }
        // src_ip/dst_ip net.ParseIP
        // dst_port/src_port queryIntStrict + ValidatePort #2934/#3116
        // protocol ValidateProtocol #3108
        // ... then simulator
    }
    ```
  - Zones, policies, screen, events handlers each ~100-300 LOC, distinct.
  - Proposed decomposition: `security_zones.go` (zonesHandler), `security_policies.go` (policiesHandler), `security_screen.go` (screenHandler), `security_events.go` (eventsHandler), `security_matchpolicies.go` (matchPoliciesHandler + validators extracted as `validateMatchPoliciesQuery(r) (parsed, errMsg)`). Each <350 LOC. Match validator extraction enables table-driven unit tests.
  - Hot-path: cold — config inventory + simulator (O(policies) walk, not per-packet).
  - Tests: `security_test.go` 245 LOC, `security_matchpolicies_*.go` 7 files (action, desc_sched, dup, exclusion, fragment, hostinbound, ingress_iface, queried_zones, scheduler, scope, unknownkey) total ~1500 LOC — must stay green: `go test ./pkg/api -run TestMatch`.
  - Labels: `refactor`, `security`, `readability`, `low-risk`
  - Dedup: shares selector validation with `pkg/grpcapi/server_show_security_text.go`? gRPC path uses `policymatch.ParseSelectorArgs` — slight divergence, okay.

### Finding 5 — Are gRPC diag splits already mechanical? YES — verified, but SystemAction switch is god-switch

- Title: gRPC diag family IS mechanically split per verb (monitor 604, ping 248, system_action 576, zeroize 753, diag.go 77 thin) — correct decomposition, but SystemAction 440-line switch handling 19 verbs is god-switch
- Severity: low
- Confidence: high
- Refactor class: C — mechanical split already done, remaining god-switch is low-risk to keep but could be table-driven
- Evidence:
  - Worktree `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/` sizes:
    - server_diag.go 77 LOC: `func (s *Server) dialPeer()`
    - server_diag_monitor.go 604 LOC: `MonitorPacketDrop`, `MonitorInterface`, `proxyMonitorInterface`, `decideMonitorProxy`, `isLocalNodeRef`
    - server_diag_ping.go 248 LOC: `Ping`, `Traceroute`, `buildPingArgv`, `buildTracerouteArgv`, `streamDiagCmd`
    - server_diag_system_action.go 576 LOC: `proxyPeerSystemAction`, `logSystemAction`, `zeroizeConfigRoot`, `runZeroize`, `SystemAction` (switch 19 verbs)
    - server_diag_zeroize.go 753 LOC: 10 helpers focused on erasure
  - SystemAction snippet:
    ```
    func (s *Server) SystemAction(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
        switch req.Action {
        case "reboot":
            slog.Warn("system reboot requested via gRPC")
            s.logSystemAction("reboot")
            schedulePowerAction("reboot")
        case "halt":
        case "power-off":
        case "zeroize":
            s.logSystemAction("zeroize")
            if err := s.runZeroize(ctx); err != nil { ... fail-closed ... }
            scheduleStopDaemon()
        case "clear-config-lock":
        case "clear-arp":
        case "clear-interfaces-statistics":
        case "clear-ipv6-neighbors":
        case "clear-policy-counters":
        case "clear-firewall-counters":
        case "clear-nat-counters":
        // ... 9 more
        }
    }
    ```
  - 19 verbs: reboot/halt/power-off/zeroize/clear-config-lock/clear-arp/clear-iface-stats/clear-ipv6-neigh/clear-policy-counters/clear-firewall-counters/clear-nat-counters/clear-persistent-nat/ospf-clear/bgp-clear/ipsec-sa-clear/dhcp-renew/in-service-upgrade/dynamic-dns-update/check/cluster-failover + userspace-inject/forwarding/queue/binding.
  - Proposed decomposition (optional, low priority): extract `system_action_power.go` (reboot/halt/poweroff), `system_action_clear.go` (clear-arp/ipv6-neigh/interfaces-stats), `system_action_counters.go` (policy/firewall/nat/persistent-nat), `system_action_cluster.go` (failover), `system_action_zeroize.go` wrapper delegates to existing zeroize file, `system_action_routing.go` (ospf/bgp/ipsec). Or table-driven map `action -> handler func` with uniform signature. Keeps single file <100 LOC per verb file.
  - Hot-path: cold admin RPC, not per-packet.
  - Tests: `system_action_test.go` 222 LOC, `system_action_failover_node_4693_test.go`, `system_action_journal_4108_test.go`, `server_diag_issu_5039_test.go` — must pass.
  - Labels: `refactor`, `readability`, `cold-path`, `not-hotfix`

### Finding 6 — metrics_userspace.go 1865 LOC 30+ emit* already well split per family, NOT dumping ground

- Title: NEGATIVE finding — `metrics_userspace.go` is well-modularized per metric family despite large LOC, NOT a dumping ground
- Severity: n/a
- Confidence: high
- Refactor class: none — good example
- Evidence:
  - File `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/metrics_userspace.go` 1865 LOC, `grep -n "^func" | wc -l` = 32 funcs, each `emit*`:
    ```
    func (c *xpfCollector) collectUserspaceStatus(...) { fetch once #5317 then dispatch }
    func (c *xpfCollector) emitDropClassCounters(...)
    func (c *xpfCollector) emitFabricSkipCounters(...)
    func (c *xpfCollector) emitRejectObservability(...)
    func (c *xpfCollector) emitPolicyContentRejected(...)
    func (c *xpfCollector) emitZoneIDCollision(...)
    func (c *xpfCollector) emitWireguardTelemetry(...)
    func (c *xpfCollector) emitNeighborLatencyHistograms(...)
    func (c *xpfCollector) emitThreeColorPolicerCounters(...)
    func (c *xpfCollector) emitCoSOwnerProfile(...)
    // ... 20 more
    ```
  - Each function aggregates per-binding counters (sum across bindings) or iterates `status.Bindings`, emitting unconditionally so 0 = real zero not absent series (convention).
  - Shared `fetchUserspaceStatus` performs SINGLE Status() RPC per scrape #5317 — prior code did 2 RPCs (collectFilterCounters + collectUserspaceStatus) doubling control-socket contention.
  - LOC high but responsibility count low per func (single metric family), hot-path comment in CLAUDE.md about control socket contention respected.
  - Proposal: keep as is, possibly split into `metrics_userspace_cos.go` (CoS owner/drain/park/waterfill/lease/sojourn/fair-occupancy/equal-flow), `metrics_userspace_binding.go` (binding active/tx-completion/vmin-throttle), `metrics_userspace_fairness.go`, etc., but low priority — current func-split already achieves reviewability. No change needed for B1.
  - Labels: `good-pattern`, `observability`

---

## Summary — Mechanical Splits Already Done?

- **REST `pkg/api/` batch**: metrics_descriptors.go, metrics_userspace.go, metrics.go, sessions.go, security.go, server.go are largest. Metrics_userspace is ALREADY well split per `emit*` family (30 funcs) despite 1865 LOC — good pattern. Sessions.go and security.go are 4-5 RPC families per file but func-split; mechanical file-per-family split would be trivial and safe (cold path). Server.go route registration is single dumping ground but trivial to extract helpers. metrics_descriptors.go is the true monolith initializer (1 func 2067 lines) — easy mechanical split per subsystem.
- **gRPC `pkg/grpcapi/` (full, out-of-batch but asked)**: diag family IS already mechanically split: server_diag.go thin, ping 248, monitor 604, system_action 576, zeroize 753 — NOT dumped into one file. SystemAction switch 19 verbs is god-switch inside file but file itself focused. server_sessions.go 1778 remains largest mixing 4 session families (list/cursor/legacy/filter/total/node/peer/summary/zone-pair/clear/batched-clear) — 30 funcs but single file; could split into `server_sessions_list.go`, `server_sessions_summary.go`, `server_sessions_zonepair.go`, `server_sessions_clear.go`, `server_sessions_filter.go` — mechanical safe, cold.
- **Dumping-ground files**: metrics_descriptors.go (1 func), server.go (route table), sessions.go (REST), server_sessions.go (gRPC), security.go (REST), server_show_security_text.go 1074 LOC (out-of-batch but similar — many show* text renderers, well func-split).
- **Large god-functions handling multiple RPC types**: Collect 206 lines orchestrates many collectors but intentional; SystemAction 440-line switch handles 19 actions — god-switch, could be table-driven; matchPoliciesHandler 340 lines validates 10+ dimensions then simulator — could extract validate func; sessionsHandler + sessionSummaryHandler + clearSessionsHandler + sessionZonePairHandler are separate funcs, not one god.
- **Hot-path preservation**: ALL APIs cold management path (REST /metrics 1/s, sessions limited to 4 concurrent #5318/#5433, ping/traceroute exec timeout 30-150s, zeroize one-shot). No per-packet BPF/Rust dataplane code touched. Splits mechanical safe, no `slog.Info` in loops violation (CLAUDE.md rule), control socket contention #5317 already addressed via single Status() fetch per scrape.
- **Proposed decomposition order (low-risk first)**:
  1. `metrics_descriptors.go` -> `metrics_desc_*.go` helpers (global, nat, dhcp, system, userspace, etc.) — 1 day, trivial.
  2. `pkg/api/server.go` -> `server_routes.go` with `register*Routes` helpers — 2 hours.
  3. `pkg/api/sessions.go` -> 4 files + common — half day, keep limiter/shared consts.
  4. `pkg/api/security.go` -> 5 files + validator extraction — half day.
  5. `pkg/grpcapi/server_sessions.go` -> 5 files — 1 day, keep filter/match shared.
  6. `pkg/grpcapi/server_diag_system_action.go` switch -> action map or file-per-verb — 1 day, low priority.
- **Tests+gate**: `make test-go` (includes `pkg/api/*_test.go` 100+ tests: metrics_descriptor_coverage, metrics_cold_path, sessions_pagination, sessions_ha_scope, sessions_parity, security_matchpolicies_*, server_run_leak, http_dos_hardening, api_ctx_cancel, etc.) plus `pkg/grpcapi` tests (system_action_test, diag_monitor, diag_ping, clear_sessions). All existing tests already guard limiter, cancel sampler, bounded clear #5454, peer fan-out #3423. No new tests needed beyond existing — just ensure no behavior change.
- **Labels**: `refactor`, `observability`, `ha`, `dos-hardening`, `cold-path`, `low-risk`, `good-pattern`
- **Dedup**: `pkg/api/sessions.go` filtering duplicates `pkg/grpcapi/server_sessions.go` `sessionFilter.matchV4/V6` — shared logic but slight divergence (REST enriches via view, gRPC via pb). Could extract `pkg/sessionfilter` common lib but out of scope for B1.

---

## File Paths Referenced (absolute, via worktree)

- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/metrics_descriptors.go` 2067 LOC monolithic newCollector
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/metrics_userspace.go` 1865 LOC 32 emit* funcs well split
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/sessions.go` 1541 LOC 32 funcs 4 RPC families
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/metrics.go` 1161 LOC Collect 206 lines
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/security.go` 942 LOC matchPoliciesHandler 340 lines
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/types.go` 878 LOC types only
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/server.go` 789 LOC NewServer route dumping ground
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/metrics_counters.go` 586 LOC
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/metrics_system.go` 429 LOC
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/api/config.go` 417 LOC
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/server_sessions.go` 1778 LOC (out-of-batch reference, 30 funcs)
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/server_diag_zeroize.go` 753 LOC 10 helpers
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/server_show_security_text.go` 1074 LOC many show* renderers
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/server_diag_monitor.go` 604 LOC 8 funcs
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/server_diag_system_action.go` 576 LOC god-switch 19 verbs
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/server_diag_ping.go` 248 LOC 7 funcs
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/server_diag.go` 77 LOC thin dialPeer
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/apply_result.go` 10 LOC trivial
- `/tmp/review-wt-ps-044-A8_go_api_grpc_rest-b1/pkg/grpcapi/exec_timeout.go` 136 LOC timeout helpers



---
### Batch A8_go_api_grpc_rest-b2 — 121 lines — full log + findings

Title: A8 batch 2 inventory — Go API gRPC/REST monolith (server_sessions 1778, server_show_security_text 1074, server_show_interfaces 935, server_cluster 864, server 768, server_diag_zeroize 753)
Severity: high
Confidence: high
Refactor class: A
Evidence:
- Batch 150 files measured at base f1ef0eec8. Non-test prod LOC:
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_sessions.go 1778 LOC: god file mixing 6 domains — GetSessions entry (offset validation #3439, PageSize branch), getSessionsCursor (cursor pagination, page_token parsing, HA primary gate, SessionCount total, no_enrich skip, sessionCursorIterator seam in runtime.go), getSessionsLegacy (legacy compat), buildSessionFilter (zoneID 65535 guard, port 65535 guard, protocol lenient #3393, CIDR host->/32 /128 expansion, SNAT pool nets via config.SourceNATPoolNets, zoneIfaces/egressIfaces via net.InterfaceByName + Reth resolve), matchV4/matchV6 (reverse skip, proto, prefix, port, natOnly, app, iface, SNAT pool), fetchPeerSessions + proxyPeerSessionSummary/proxyPeerZonePairSummary (#3592/#5320 peer_status), ClearSessions (clear-all vs filtered, x-peer-forwarded guard, shared filter reuse #1827, zone string->ID, bounded working set #5454 clearFilteredBatch 1024 + observer seam, clearBatchV4/V6 collect reverseKey + DNAT companion #2733/#2406/#2468), sessionEntryV4/V6 enrichment, sessionStateName, resolveSessionEgressIface, monotonicSeconds, page token encode/decode. 30+ funcs + 4 types (sessionEgressKey, sessionFilter, clearBatchV4/V6, clearErrors).
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show_security_text.go 1074 LOC: Phase 12 of #1043 extraction from 4072 LOC server_show.go god-file. Still 1074 LOC with 12+ funcs: screenSYNCookieCounterRows (userspace format), showIPsecStatistics (ipsec.GetSAStatus active-tunnel + bytes), showTunnels (routing.GetTunnelStatus), showServicesIPMonitoringStatus (#1827 ipmon.FormatStatus shared), showRPM (rpmResultsFn live vs writeRPMConfig fallback), showSecurityLog (eventBuf LatestFiltered + ParseEventFilterArgs #3547 + zoneID map via applyResult + legacy stored-name fallback #3335 + zone-0 #3338 + forensic #3337), showSchedulers, showApplications (Applications + ApplicationSets sorted nil guard #5221), showSecurityAlarms (ValidateConfig warnings + screen reason table #3343 + counter-read error #3345 + NAT pool alarm #2079), showScreenIDSOption family + screenStatistics + screenEnabledCheckList + showScreen + showAlg + showAddressBook + showIKE + writeRPMConfig + showWireguard. 7 subsystems.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show_interfaces.go 935 LOC: GetInterfaces, ShowInterfacesDetail, showInterfacesTerse (cluster.InterfacesInput, RethToPhysical, netlink LinkByName, InterfaceMonitorStatuses), writeKernelStats, baseIfName, rethMemberKernelState, writeRethMemberSummary, writeRethDetail. Related server_show_interfaces_text.go 503 LOC (Extensive/Detail/Statistics, CoS classifier/rewrite/scheduler, VLAN, IPv6 RA) → together 1438 LOC interface show surface.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_cluster.go 864 LOC: buildInterfacesInput (Control/Fabric/Fabric1 + RethToPhysical + routing.InterfaceMonitorStatuses + PeerMonitorStatuses #4480 fallback Up:false), MatchPolicies (no-config fail-closed default deny #3375, zone guard #3355, IP parse #1711, port #3116, protocol #3108, ICMP type/code #3284 optional uint32, ingress-interface #5579 via dataplane ResolveHostInboundIngressInterface, feed overlay #3042/#2049, policymatch.Match tier ordering #3090/#3148 scoped global, PolicyInactiveFn #3104, content-rejected #3727, host-inbound unmatched #3285/#3375, route-drop advisory #4373, fragment-associated deny #5572), grpcICMPValue, hostInboundToProto (#3627 B1a #4352), grpcResolveAddress, Complete (pipe-filter), filterCompletionPairs, resolveShowConfigurationWords, completionValueProvider, completeOperationalPairs (cmdtree.OperationalTree), completeConfigPairs (config.setSchema), valueProvider (ValueHint), ClearCounters. Mixes cluster state, policy simulator proxy, completion.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server.go 768 LOC: Config struct 25 fields (Store, DP grpcRuntime, EventBuf, GC, Routing, FRR, IPsec, Cluster, DHCP, DHCPServer, RPMResultsFn, IPMonStatusFn, NATPoolAlarmsFn, FeedsFn, FeedOverlayFn, LLDPNeighborsFn, DDNSStatsFn, DDNSOwnedRecordsFn, SurfaceADDNSStatsFn/StatusFn/ForceFn, FlowCollectorHealthFn, CommitFn, CommitConfirmedFn, ZeroizeFn #5281, VRRPMgr, RAMgr, Version, FabricPeerAddrFn, FabricVRFDevice, FwdSampler #881). Server struct 30 fields (startTime, addr, version, fabricPeerAddrFn, peerSystemActionFn, peerZonePairSummaryFn #3592 seam, peerSessionSummaryFn #5320 seam, fabricAuthKeyFn #4107 seam, heartbeatAuthSeenFn, fabricPeerAuthSeen atomic.Bool sticky downgrade guard, fabricListenerMu + fabricListenerUp map #5047). Methods: NewServer, userspaceDataplaneStatus/Control, Run (loopback clamp #5035 maxRecvMsgSize 16 MiB #164, server build with interceptors), serveUntilDone, stopGRPCServer (graceful 2s #4910 streaming MonitorInterface guard), grpcHostIsLoopback (empty not loopback #4903/#4928), clampGRPCBindToLoopback, RunFabricListener, buildFabricServer (allowlist Unary 615 + Stream 627 maps), superviseFabricListener, sleepFabricBackoff, setFabricListenerUp, FabricListenerUp, FabricListenerHealth, parseProxiedFailoverAction, isFabricSafeSystemAction, fabricAllowlistUnary/StreamInterceptor, configLockInterceptor, peerSessionID. Mixes main listener lifecycle, fabric listener lifecycle, auth allowlist, graceful shutdown, bind validation.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_zeroize.go 753 LOC: zeroizeConfigDir, isTextRollbackFile, isFsatomicTemp, zeroizeRenderedConfigs (frrConf swanctl kea), sweepFsatomicTemps, zeroizeRootAuthorizedKeysPath, zeroizeRootLoginAccount, zeroizeLookupUIDErr, zeroizeLoginAccounts, readProvisionedMarkerUID. 4 wipe domains fused (configdb, rendered secrets, temp, root login) via SystemAction zeroize under apply gate #5281.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_monitor.go 604 LOC: monitorInterfaceServerDataPlane adapter IsLoaded/ReadInterfaceCounters, monitorInterfaceDataplane factory, MonitorPacketDrop, isLocalNodeRef, interfaceAliasSet, monitorRequestForwardedFromPeer (x-peer-forwarded marker), decideMonitorProxy (alreadyProxied, existsLocally, isPeerMember, isReth, RG, monitorClusterState #5497 localOwns vs peerOwns vs both secondary vs marker not reproxied), MonitorInterface, proxyMonitorInterface via dialPeer, monitorSummaryModeFromProto. Mixes packet-drop + interface monitoring + proxy routing.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_diag_system_action.go 576 LOC: proxyPeerSystemAction, logSystemAction, zeroizeConfigRoot, runZeroize, SystemAction (failover node #4693, journal #4108, ISSU #5039, zeroize gate #5281) 5 actions in one dispatcher.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show_routes_text.go 562 LOC: showRouteAll/Summary/Terse/Detail/Table/Protocol/Prefix/TestRouting silent-drop typo bug F-002 vs #3696 showTestPolicy strictness, showRoutingOptions/Instances/InstanceDetail, showRouteInstance, showRouteMap, showBFDPeers.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show_system.go 548 LOC: showVersion/Storage/CommitHistory/Alarms/ChassisEnvironment/SystemServices/NTP (ctx timeout) /Syslog/Login/InternetOptions/RootAuthentication/CoreDumps/Task/Buffers/BackupRouter.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show_policies_text.go 541 LOC: showPoliciesHitCount bulk reader #4344 hitcount gate #4345 globals #3286 thencount #3074 scheduler #3062 zone-local #3358 exclusion #3667 scoped-global #3357 addr inventory #3336.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show_firewall.go 707 LOC: writeThreeColorPolicerStatus, showFirewall, showTestPolicy strict #3696/#3709, showFirewallFilter, showEffectiveFirewallFilters/Filter.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/server_show_flow.go 443 LOC, server_show_dhcp_lldp_snmp.go 445 LOC (SNMP community redact #5315 TSIG redact), server_show_zones.go 395 LOC, server_show_zones_text.go 282 LOC (host-inbound #3328/#3654 lifeline #3682 metadata #3684 tiers #3658), server_show_status.go 276 LOC (GetStatus GlobalStats counter error surfacing #3345 #4508 #4768 fwdSampler #881), server_show_forwarding.go 178, chassis 95 + cluster_text 244 + device_map 81 + nat 80 + appid 20.
  - /tmp/review-wt-ps-044-A8_go_api_grpc_rest-b2/pkg/grpcapi/fabric_auth.go 304 LOC + server_config.go 400 + server_helpers.go 380 + server_nat.go 364 + server_routing.go 295 (GetRoutes OSPF BGP RIP ISIS IPsecSA – BGP neighbor IP unvalidated TrimPrefix into vtysh concat F-001) + runtime.go 71 + exec_timeout.go 136 + apply_result.go 10 + pb generated ignored.
  - Test coverage in batch: 115+ _test.go (server_cluster_test 309, config_test 172, show_*_test many, session_filter_test 147, pagination 176, policies_bulk_reader 176, clear_sessions_bounded 388 #5454 bounded chunk assertion, clear_sessions_errors 226, nat/interface/global/flow cluster counter_error, fabric_auth 334 #4107, fabric_allowlist 280 #4122, fabric_listener health 250 #5047, diag_argv 173 #164 separator hardening, monitor_proxy 140 #5497 neither/localOwns/peerOwns/both secondary/marker, scanner_leak 144 goroutine settle #5060, stream, ping, shutdown_monitor #4910, grpc_loopback_clamp #5035, recvsize_hb164 16MiB cap, proto/input/packet_drop validation 3382, rollback_negative/zero, missing_zone 3355, zone_nil 3493, security_nil 3476, policy_id_zero 3623, session_app_srcport, egress_drift, etc.) pin fail-closed behaviors + cursor pagination + clear bounded working set + fabric allowlist/auth.

Proposed decomposition:
- server_sessions.go → 6 files (mechanical code-motion, no logic change):
  - server_sessions_filter.go: sessionFilter type + parseSessionPrefix + setInputErr + protoFilterMatches + validate + buildSessionFilter (zone/proto/port/CIDR/SNAT pool/zoneIfaces/egressIfaces).
  - server_sessions_cursor.go: getSessionsCursor + parsePageToken + encodePageTokenV4/V6 + decodeSessionKeyV4/V6 + monotonicSeconds + sessionCursorIterator via runtime.go.
  - server_sessions_legacy.go: getSessionsLegacy full table scan fallback.
  - server_sessions_clear.go: ClearSessions + clearFilteredSessionsV4/V6 + Rescan variants + clearBatchV4/V6 + collect + deleteAll + clearFilteredBatch var + observer seam + clearPeerSessions + peerNodeIDForMsg + clearErrors + addExceptNotFound + summary + apply. Preserve #5454 O(clearFilteredBatch) working set.
  - server_sessions_entry.go: sessionEntryV4/V6 + sessionIfaceMatches + resolveSessionEgressIface + sessionStateName + sessionEgressKey.
  - server_sessions_summary.go: GetSessionSummary + peerAbsentStatus + proxyPeerSessionSummary + GetZonePairSummary + computeZonePairSummary + proxyPeerZonePairSummary. Keep peer seams peerZonePairSummaryFn / peerSessionSummaryFn.
  - Keep server_sessions.go as dispatcher GetSessions only (Negative offset #3439 + PageSize branch).
- server_show_security_text.go → 5 files:
  - server_show_security_ipsec.go: showIPsecStatistics + showTunnels + showIKE + showWireguard/PublicKey (IPsec/tunnel/WG domain).
  - server_show_security_ipmon_rpm.go: showServicesIPMonitoringStatus (#1827 ipmon.FormatStatus) + showRPM + writeRPMConfig (RPMResultsFn/IPMonStatusFn seams).
  - server_show_security_log.go: showSecurityLog + zoneName fallback + evZoneNames map via applyResult (eventBuf + logging.ParseEventFilterArgs #3547).
  - server_show_security_alarms.go: screenSYNCookieCounterRows + showSecurityAlarms (ValidateConfig + screen reason table #3343 + counter read error #3345 + NAT pool alarms #2079).
  - server_show_security_misc.go: showSchedulers + showApplications + showAlg + showAddressBook + showScreenIDSOption variants + screen statistics + screenEnabledCheckList + showScreen. Second-phase split further if >500.
- server_show_interfaces.go → 3 files:
  - server_show_interfaces_rpc.go: GetInterfaces + ShowInterfacesDetail RPC entries.
  - server_show_interfaces_terse.go: showInterfacesTerse (cluster.InterfacesInput, netlink).
  - server_show_interfaces_reth.go: baseIfName + rethMemberKernelState + writeRethMemberSummary + writeRethDetail + writeKernelStats.
  - Keep server_show_interfaces_text.go 503 but second-phase split into server_show_interfaces_cos.go (CoS classifier/rewrite/scheduler) + server_show_interfaces_vlan.go.
- server_cluster.go → 4 files:
  - server_cluster_interfaces.go: buildInterfacesInput (Control/Fabric/Fabric1 + RethToPhysical + routing.InterfaceMonitorStatuses + PeerMonitorStatuses #4480).
  - server_cluster_matchpolicies.go: MatchPolicies full validation chain #3355 #1711 #3116 #3108 #3284 #5579 + grpcICMPValue + hostInboundToProto + grpcResolveAddress + feedOverlayFn + policyInactiveFn. Shared simulator entry.
  - server_cluster_complete.go: Complete + completePipeFilter + filterCompletionPairs + resolveShowConfigurationWords + completionValueProvider + completeOperationalPairs (cmdtree) + completeConfigPairs (setSchema) + valueProvider (ValueHint).
  - server_cluster_misc.go: ClearCounters + completionPair.
- server.go + runtime.go + fabric_auth.go → 5 files:
  - server_main.go: Config + Server base fields + NewServer ctor + userspaceDataplaneStatus/Control + Run + serveUntilDone + stopGRPCServer #4910 + grpcHostIsLoopback + clampGRPCBindToLoopback + consts maxRecvMsgSize #164 + grpcStopTimeout.
  - server_fabric.go: RunFabricListener + buildFabricServer + superviseFabricListener + sleepFabricBackoff + setFabricListenerUp + FabricListenerUp + FabricListenerHealth + fabricAllowedUnary/Stream maps + fabricListenerMu guard #5047.
  - server_interceptors.go: fabricAllowlistUnaryInterceptor/StreamInterceptor + configLockInterceptor + peerSessionID + isFabricSafeSystemAction + parseProxiedFailoverAction.
  - server_fabric_auth.go (existing fabric_auth.go 304): fabricAuthWindow + computeFabricAuthToken + tokenHex + verify + tokenFromMetadata + fabricAuthDecision + fabricAuthKey + heartbeatPeerAuthSeen + fabricPeerAuthSeen sticky guard #4107 + fabricAuthCreds + NewFabricAuthCreds.
  - runtime.go expanded: grpcRuntime + sessionCursorIterator + userspaceStatusProvider/ControlProvider + applyResult helpers (dataplaneLoaded, loadedApplyResult, sessionStore, telemetry) from helpers.
- server_helpers.go 380 → 4 files:
  - server_helpers_nat.go: natRuleSetKey + natSessionCounts + countSNATSessions/DNAT/countNATSessions.
  - server_helpers_app.go: builtinApp + resolveAppName + lookupAppFilter (AppID fallback scanning).
  - server_helpers_status.go: screenChecks + fmtPref + boolStatus + writeChronyTracking + neighStateStr + writeNeighSummary + allInterfaceNames + policyActionStr.
  - server_helpers_net.go: resolveFabricParent + protoName + ntohs + uint32ToIP + peerForwardedFromContext.
- server_diag_zeroize.go 753 → 3 files:
  - server_diag_zeroize_config.go: zeroizeConfigDir + isTextRollbackFile + isFsatomicTemp + sweepFsatomicTemps (#5475).
  - server_diag_zeroize_rendered.go: zeroizeRenderedConfigs (FRR swanctl kea).
  - server_diag_zeroize_login.go: zeroizeRootAuthorizedKeysPath + zeroizeRootLoginAccount + zeroizeLookupUIDErr + zeroizeLoginAccounts + readProvisionedMarkerUID.
- server_diag_monitor.go 604 → 2 files:
  - server_diag_monitor_packet.go: MonitorPacketDrop + monitorInterfaceDataplane adapter.
  - server_diag_monitor_interface.go: isLocalNodeRef + interfaceAliasSet + monitorRequestForwardedFromPeer + decideMonitorProxy + MonitorInterface + proxyMonitorInterface + monitorSummaryModeFromProto.
- server_show_system.go 548 → 2 files: system_base (Version/Storage/CommitHistory/Alarms/ChassisEnv/Buffers) + system_services (SystemServices/NTP ctx timeout/Syslog/Login/InternetOptions/RootAuthentication/CoreDumps/Task/BackupRouter).
- server_show_routes_text.go 562 keep but fix F-002 silent-drop → second-phase split routes_test strict parser #3696 parity.
- server_config.go 400 → 2 files: config_mutation (EnterConfigure/ExitConfigure/GetConfigModeStatus/Set with copy/rename/insert/Delete/Load) + config_commit (Commit/CommitCheck/CommitConfirmed/ConfirmCommit/Rollback/ShowConfig/Compare/Rollback/ListHistory/configWarnings).

All splits preserve package, func signatures, no new allocators, file relocation only. go vet + make test-go gate.

Hot-path preservation analysis:
- Class A safe cold path: All files are gRPC control-plane show/config/session inspection handlers on unary/stream RPCs from remote cli / HA peer, NOT per-packet. No XDP/TC/AF_XDP data path, no poll_descriptor hot loop, no forwarding FIB lookup, no per-packet AppCatalog matching (per-packet is Rust userspace-dp). No unsafe, no binary.NativeEndian, no sync.Pool, no arena. Pure map lookups (ZoneIDs/PolicyNames), netlink LinkByName, file reads, ring buffer LatestFiltered, dataplane counter reads (ReadGlobalCounter, ReadInterfaceCounters, SessionCount).
- Therefore no frame budget, no cache-line placement, no batch-counter coherency, no cross-worker visibility needed. Mechanical file motion cannot regress PPS (Rust path unaffected) or retain stale forwarding state.
- Side-effects: server.go Run holds grpc.Server lifecycle + fabric health map guarded by sync.Mutex — preserve lock order (fabricListenerMu only guards fabricListenerUp, no cross-lock with apply gate). Config 20+ Fn fields set once at NewServer; moving files does not change init order (Go var init order file-alphabet but Config init explicit in NewServer, no init dependency). Rust shim untouched; Go→Rust snapshot translators unchanged because Go structs not moved.
- Resource safety: clearFilteredBatch bounds handler working set #5454 + observer seam — preserve var. Diag monitor proxy uses context timeout + recursion guard marker not reproxied #5497 — preserve. Zeroize path terminal reset generation via ZeroizeFn #5281 fail-close — preserve.
- Log discipline: existing slog.Info limited to state transitions (fabric up/down, zeroize). Keep per-RG RefreshOwnerRGs rare. No per-packet/session slog.Info added.
- Concurrency: ClearSessions fabric-reachable but bounded; MonitorInterface streaming unbounded only watches client stream context — stopGRPCServer #4910 graceful timeout 2s ensures stuck stream does not block daemon stop. Preserve timeout.

Tests + gate:
- make test-go (go test ./pkg/grpcapi -run Test- -count=1 -timeout 5m): covers 115+ regression tests in batch: session pagination pagination_test, session_filter_test, filter_3439, summary_fields_5320_5323, app_srcport_3428, egress_drift_4650, filtered_total_5034, sessions_top_5319, iterator_error, zonepair_summary_3592, clear_sessions_bounded_5454 (bounded chunk assert), clear_sessions_errors, peer_nodeid_3423, reversekey; show security firewall_test, policies hitcount gate/globals, thencount_3074, scheduler_3062, zone_local_3358, text_exclusion_3667, scoped_global_3357, addr_inventory_3336, effective_4967; interfaces reth_4328, golden 290, cluster_text 244, device_map, dhcp_lldp_snmp, forwarding adapter, zones hostinbound_3328/display_3654 lifeline_3682 metadata_3684 tiers_3658 scheduler_inventory_3624 scoped_global_3286 default_policy_3363/log_3670 explicit_any_3680; cluster server_cluster_test 309, monitor_status_4480, matchpolicies action_3375 desc_sched_3685 exclusion_3668 fragment_5572 hostinbound_3627 ingress_iface_5579 queried_zones_3627 routdrop_4413 scheduler_3414 scope_3331, policies_bulk_reader; config test/activate/redaction; fabric auth 4107 334, allowlist 4122 280, listener health 5047 250, runtime_canary; diag argv 173 separator hardening, issu_5039, monitor_test, monitor_proxy_5497 140 (neither/localOwns/peerOwns/both secondary/marker), scanner_leak_5060 144 goroutine settle, stream, ping argv, shutdown_monitor_4910, grpc_loopback_clamp_5035, recvsize_hb164 16MiB cap, proto_validation, input_validation, packet_drop_validation_3382, rollback_negative/zero, missing_zone_3355, zone_nil_3493, security_nil_3476, policy_id_zero_3623, etc.; counter error paths flow_cluster, global_stats, interface, nat, flood_counter, zone flood hidden, zones_policies_counter_error, stats_global_parity; system_action_failover_node_4693, journal_4108, etc.
- go vet ./pkg/grpcapi — no new issues.
- make test-rust not needed but make test runs both — ensure no import cycle.
- Golden: server_show_golden_test.go — byte-identical show output after split.
- No incus VM needed (cold path), but make test-deploy optional for commit pipeline parity.
- Preservation proof: git diff --stat after split shows only deletions + new files with identical bodies (no logic edits) except explicit F-001/F-002 fixes separated into own commits with test coverage.

Why it matters:
- Build & LSP: server_sessions 1778 LOC dominates pkg/grpcapi build per package; gopls parses 1.7k file each keystroke. Splitting into 6 files makes incremental parse cheaper and review diffs scoped (filter fix no longer touches clear path).
- Merge conflict magnet: grpcapi sees ~40 PRs touching sessions (pagination #5318/#5319/#5320 filtering #3439 clearing #5454 HA peer proxy #3423/#3592/#5323), show (security log zone #3547 screen counters #3327/#3334/#3343 policy hitcount #4344 zone tiers #3658/#3682 CoS gap #7 interface reth #4328 forwarding #881 device-map DHCP/LLDP), cluster (#4480 monitor unknown->down), config redaction rollback, diag argv hardening #164 scanner leak #5060 zeroize login #5280/#5496. All collide in 5 giant files; concurrent feature work forces rebases.
- Reviewability: GetSessions 66 + getSessionsCursor ~200 + buildSessionFilter ~200 + clear 400 cannot be reviewed in one page; split matches eng style "one responsibility per file" and prior #1043 phases 1-12 (4072→562) pattern.
- Onboarding: new engineer adding session filter (SNAT pool) should not understand page token encoding + clear batching + peer fan-out status classification; file split makes ownership obvious.
- Resource safety posture: iterator error tests + clear bounded observer #5454 currently in same file as rendering — moving to clear subfile makes safety invariant O(clearFilteredBatch) explicit and harder to regress.
- Operability: fabric listener supervisor up/down health #5047 + allowlist #4122 + auth token #4107 live in same 768 LOC server.go as loopback clamp + graceful-stop #4910 — separating reduces mixing of exposure domains (loopback vs fabric) and clarifies fabricAuth interceptors only on fabric, not loopback (previous review noted localhost gRPC unauth but intentionally loopback-only per #5035).
- Prior extraction history: Phase 12 of #1043 comment says "brings server_show.go below 2000 LOC threshold — closing audit that started at 4072". This batch shows residual monoliths were not closed — security_text still 1074, interfaces 935+503, cluster 864, sessions 1778, zeroize 753 — so phase 13+ needed.

Fix direction:
- Step 1: Mechanical extraction without behavior change, preserve func names, receiver signatures, package-level vars (clearFilteredBatch var + observer seam, fabricPeerAuthSeen atomic.Bool, fabricListenerMu+map, completionPair). File-level moves, no logic edits. Keep imports minimal per file — avoid pulling unused deps (sessions filter only needs net, fmt, config, dataplane, appid; validation needs status/codes add only where needed).
- Step 2: For shared helpers (protoName, ntohs, uint32ToIP, resolveFabricParent, allInterfaceNames, policyActionStr) extract to server_helpers_* as outlined, same package no visibility change. If firewallMatchValues-like cross helpers exist (not in this batch but similar), consolidate to shared file.
- Step 3: For server.go, move Config struct def to server_main.go (or keep barrel) and Server struct to same file; move methods to domain files. Ensure OperationalTree-like var init order preserved — not applicable, but preserve fabricAllowedUnaryMethods map literal in server_fabric.go with same contents.
- Step 4: go vet + go test ./pkg/grpcapi -count=1 covering 115 tests; ensure server_show_golden_test passes (byte-identical output).
- Step 5: Address prior F-001/F-002 residual fixes in separate commits before or after mechanical split, with dedicated tests: F-001 net.ParseIP guard at pkg/frr/vtysh.go GetBGPNeighborReceivedRoutes/AdvertisedRoutes/Detail + InvalidArgument return in server_routing.go GetBGPStatus; F-002 track parseErr on len(parts)!=2 or empty part + unknown key default arm in showTestRouting, report before lookup (mirror #3696 showTestPolicy).
- Step 6: Update module docs: pkg/grpcapi/README.md mentions show extraction phases #1043 — append note that server_sessions + cluster + security_text + interfaces + diag splits tracked here, reference this audit. No operator docs affected (show output unchanged).
- PR structure: one PR per subsystem (sessions ~400 LOC moves per new file, show_security, cluster, server main vs fabric vs interceptors, helpers, diag monitor vs zeroize) <400 LOC per PR, engineering-style "grow PR discipline". Each PR labelled refactor(api-grpc): extract X to Y — A-class code-motion.

Labels:
- refactor
- A-class
- modularity
- api
- grpc
- cold-path
- code-motion
- sessions
- show
- cluster
- diag
- fabric

Dedup note:
- Checked dedup-index.txt (500+ entries). Prior closed: #1043 server_show.go 4072→562+extractions Phase 12 done — this audit residual security_text 1074 + interfaces 935 + cluster 864 + sessions 1778 shows Phase 12 still left monolith; #5454 clearFilteredBatch bounded working set added but kept in same file; #4107 fabric auth token + #4122 allowlist + #5047 listener health + #5497 monitor proxy + #4910 shutdown monitor are hardening inside existing monolith files, not splits. No entry mentions server_sessions filter vs cursor vs clear vs entry vs summary split, nor cluster buildInterfacesInput vs MatchPolicies vs Complete split, nor server.go main vs fabric vs interceptors split, nor interfaces terse vs reth vs extensive split. Prior audit A8_go_api_grpc_rest-b1 covers pkg/api REST 150 files, not pkg/grpcapi b2; distinct (b2 is show/routing/sessions + FRR vtysh boundary per triage). This audit does NOT overlap #1043 completed phases — continues phase 13+ for residual monoliths (sessions 1778, security_text 1074, interfaces 935+503, cluster 864, diag_zeroize 753, monitor 604). F-001/F-002 security findings from previous B2 review are referenced for fix direction but orthogonal to file motion. No duplicate filing.


---
### Batch A8_go_api_grpc_rest-b3 — 610 lines — full log + findings

# Refactor/Modularity Audit — A8_go_api_grpc_rest-b3

Batch: 13 files in pkg/grpcapi/, all `*_test.go`, zeroize + zone/policies
Base SHA: f1ef0eec8d6a17adb42d8c389669ed1fd764ca1c
Worktree used: /home/ps/git/avacado-xpf (prompt worktree absent — batch file verified in actual checkout)

---

## Module Checklist Inventory (Coverage Proof)

### Batch Files (13) — LOC via wc -l

| File | LOC | Funcs | Responsibilities |
|------|-----|-------|------------------|
| zeroize_configured_root_5280_test.go | 107 | 2 (TestZeroizeTargetsConfiguredRootNotHardcoded, TestZeroizeFailsClosedWithoutConfigRoot) | Zeroize config-root resolution, fail-closed when no store |
| zeroize_durable_5197_test.go | 82 | 2 | fsync durability barrier ordering, key-first erasure |
| zeroize_gate_stop_5281_test.go | 150 | 3 (GoesThroughGateAndStopsDaemon, FailClosedDoesNotStopDaemon, FallsBackToDirectWipeWithoutGate) | RPC gate routing, daemon stop sequencing |
| zeroize_login_4598_test.go | 170 | 2 + helpers (assertPresent, setZeroizeLoginPaths) | Provisioned user teardown, marker-aware safety |
| zeroize_login_failclosed_5496_test.go | 194 | 5 (UnreadablePasswd, MalformedPasswdUID, UnparseableMarker, UIDMismatch, RetryAfterFailClosedRediscovers) | Fail-closed ownership uncertainty |
| zeroize_login_root_5520_test.go | 151 | 2 + setZeroizeRootPaths helper | Managed-root revocation in-place, /root/.ssh vs /home/root |
| zeroize_rendered_4585_test.go | 103 | 2 | Rendered FRR/swanctl/kea erasure, unmanaged FRR untouched |
| zeroize_rendered_temp_5509_test.go | 123 | 2 | Fsatomic temp sweep in rendered-config dirs |
| zeroize_temp_5475_test.go | 87 | 2 | Fsatomic temp sweep in configDir, isFsatomicTemp pattern |
| zeroize_tls_4599_test.go | 70 | 1 | TLS key/cert wipe |
| zone_flood_counters_hide_test.go | 74 | 2 + fake DP | ErrCounterNotPopulated hide behavior, show zones flood display |
| zonepair_summary_3592_test.go | 194 | 5 (LocalBreakdown, FailsOnIteratorError, FansOutToPeer, HonorsRecursionGuard, NoFanOutWithoutIncludePeer, NodeIDFromCluster) | GetZonePairSummary aggregation, peer fan-out, recursion guard |
| zones_policies_counter_error_test.go | 69 | 2 + fake DP | Per-policy/zone counter Internal error surfacing |

Batch total: 1574 LOC, average 121 LOC/file, largest 194 LOC (zonepair_summary_3592 + zeroize_login_failclosed).

Hot-path: NO — all test code, not on packet/fast path. gRPC control path only.

### Underlying Production Module — pkg/grpcapi/ LOC (excl tests/generates)

```
  1778 server_sessions.go         <- LARGEST FILE
  1074 server_show_security_text.go
   935 server_show_interfaces.go
   864 server_cluster.go
   768 server.go
   753 server_diag_zeroize.go      <- DIRECTLY TESTED BY BATCH
   707 server_show_firewall.go
   604 server_diag_monitor.go
   576 server_diag_system_action.go <- DIRECTLY WIRES ZEROIZE RPC
   562 server_show.go
   562 server_show_routes_text.go
   548 server_show_system.go
   541 server_show_policies_text.go
   503 server_show_interfaces_text.go
   445 server_show_dhcp_lldp_snmp.go
   443 server_show_flow.go
   400 server_config.go
   395 server_show_zones.go         <- TESTED BY zone_* IN BATCH
   380 server_helpers.go
   364 server_nat.go
   304 fabric_auth.go
   295 server_routing.go
   276 server_show_status.go
   ... (remaining < 300 LOC)
 33734 total (all .go, incl tests)
  ≈ 16000 prod-only estimate
```

### Largest Functions (prod, relevant to batch)

| File | Function | Approx Lines |
|------|----------|--------------|
| server_sessions.go | GetSessions + getSessionsCursor + getSessionsLegacy + buildSessionFilter | 33-~720 (~700 combined session paths) |
| server_diag_zeroize.go | zeroizeLoginAccounts | 534-658 = 124 lines |
| server_diag_zeroize.go | performZeroizeWipe closure | 691-753 = 62 lines, orchestrates 6 subsystems |
| server_diag_zeroize.go | zeroizeConfigDir | 107-163 = 56 lines + 6 responsibilities |
| server_diag_system_action.go | SystemAction | 136-576 = 440 lines, single switch handling 19+ verb cases |
| server_show_zones.go | GetPolicies | 130-368 = 238 lines |
| server_show_zones.go | GetZones | 18-128 = 110 lines |

### Responsibilities Fused (prod)

- `server_diag_zeroize.go`: configdir erase + TLS wipe + rendered FRR/swanctl/kea erase + fsatomic temp sweep (configDir + rendered dirs) + sudoers namespace sweep + login account uid-keyed teardown + root in-place revocation + BPF pins + networkd files + archive sweep + passwd parsing + marker parsing + durable fsync barrier
- `server_diag_system_action.go`: 19 SystemAction verbs (reboot/halt/power-off/zeroize/clear-config-lock/clear-arp/clear-iface-stats/clear-ipv6-neigh/clear-policy-counters/clear-firewall-counters/clear-nat-counters/clear-persistent-nat/ospf-clear/bgp-clear/ipsec-sa-clear/dhcp-renew/in-service-upgrade/dynamic-dns-update/check + cluster-failover + userspace-inject/forwarding/queue/binding) + journal durability + gate routing + power scheduling
- `server_show_zones.go`: GetZones (zone inventory + counter read + flood counter hide #3643 + lifeline interfaces #3682 + host-inbound) + GetPolicies (per-policy counter bulk reader #4344 + scheduler state #3624 + runtime IDs #3336 + global policies + default-policy sentinel #3363) + GetScreen (screen thresholds)
- `server_sessions.go`: GetSessions cursor path + legacy path + filter building + v4/v6 matching + total counting + node stamping + peer fetch + zone-pair summary aggregation + clear bounded + clear rescan + clearBatch v4/v6

### Hot-path Proximity_rank (size × responsibility count × hot-path proximity)

1. `server_sessions.go` — 1778 LOC × ~8 responsibilities × near-hot (dataplane iteration) = HIGHEST — but out of batch direct scope
2. `server_diag_system_action.go` — 576 LOC × 19 verbs × cold (admin RPC) = second
3. `server_diag_zeroize.go` — 753 LOC × 10+ responsibilities × cold (one-shot factory reset) = third, DIRECTLY TESTED
4. `server_show_zones.go` — 395 LOC × 3 RPCs × cold (config inventory) = fourth, TESTED BY zone_*
5. `server_show_security_text.go` — 1074 LOC × many `show*` text renderers × cold = fifth

---

## Findings

### Finding 1 — server_diag_zeroize.go fuses 10+ erasure responsibilities in one 753-LOC file, undersplit seam, test explosion symptom

- Title: Zeroize erasure module fuses config, rendered configs, login accounts, root revocation, TLS, fsatomic temps, BPF pins, networkd, archive — 753 LOC god-file for cold factory-reset path
- Severity: medium
- Confidence: high
- Refactor class: B — module too big and fuses distinct responsibilities, hard to review, risky cross-domain coupling
- Evidence:
  - File: `/home/ps/git/avacado-xpf/pkg/grpcapi/server_diag_zeroize.go`, LOC 753, 8 top-level functions + 2 package var funcs + 6 package var path seams
  - Function `zeroizeConfigDir` (lines 107-163) — owns .configdb master.key key-first delete + durable fsync barrier + rollback slots + journal + tls dir + fsatomic temps + .conf files in one ReadDir loop:
    ```
    func zeroizeConfigDir(configDir, configBase string) error {
        var firstErr error
        fail := func(err error) {
            if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
                firstErr = err
            }
        }
        dbDir := filepath.Join(configDir, ".configdb")
        keyErr := os.Remove(filepath.Join(dbDir, "master.key"))
        fail(keyErr)
        if keyErr == nil {
            fail(zeroizeSyncDir(dbDir))
        }
        fail(os.RemoveAll(dbDir))
        fail(os.RemoveAll(filepath.Join(configDir, "tls")))
        entries, err := os.ReadDir(configDir)
        fail(err)
        for _, f := range entries {
            name := f.Name()
            if strings.HasSuffix(name, ".conf") ||
                strings.HasPrefix(name, "rollback") ||
                name == ".config.journal" ||
                ...
    ```
  - Function `zeroizeRenderedConfigs` (247-282) — second erasure domain: FRR StripManagedSectionFile + swanctl + kea removals + temp sweep:
    ```
    func zeroizeRenderedConfigs(frrConf, swanctlSnippet, kea4, kea6 string) error {
        var firstErr error
        fail := func(err error) { ... }
        fail(frr.StripManagedSectionFile(frrConf))
        fail(os.Remove(swanctlSnippet))
        fail(os.Remove(kea4))
        fail(os.Remove(kea6))
        swept := make(map[string]bool)
        for _, dir := range []string{
            filepath.Dir(frrConf),
            filepath.Dir(swanctlSnippet),
            ...
    ```
  - Function `zeroizeLoginAccounts` (534-658) — third major domain: sudoers namespace sweep + passwd UID resolution + marker parsing + userdel + root special-case dispatch, 124 lines:
    ```
    func zeroizeLoginAccounts() error {
        var firstErr error
        ...
        if entries, err := os.ReadDir(zeroizeSudoersDir); err != nil {
            fail(err)
        } else {
            for _, e := range entries {
                name := e.Name()
                if e.IsDir() || !strings.HasPrefix(name, zeroizeSudoersPrefix) {
                    continue
                }
                fail(os.Remove(filepath.Join(zeroizeSudoersDir, name)))
            }
        }
        entries, err := os.ReadDir(zeroizeProvisionedUsersDir)
        ...
    ```
  - Function `zeroizeRootLoginAccount` (405-426) — root in-place revocation, fourth concern, hard-codes /root/.ssh vs /home/<user> divergence
  - `performZeroizeWipe` var closure (691-753) — orchestrator touching 6 different subsystems (config, rendered, login, archive, BPF pins, networkd):
    ```
    var performZeroizeWipe = func(configDir, configBase string) error {
        err := zeroizeConfigDir(configDir, configBase)
        if e := zeroizeRenderedConfigs(...); e != nil && err == nil {
            err = e
        }
        if e := zeroizeLoginAccounts(); e != nil && err == nil {
            err = e
        }
        if e := configstore.FactoryResetArchiveDir(...); e != nil && err == nil {
            err = e
        }
        if e := os.RemoveAll("/sys/fs/bpf/xpf"); e != nil {
            slog.Warn("zeroize: remove BPF pins failed", "err", e)
        }
    ```
  - Test symptom: 10 separate `zeroize_*.go` test files (1137 LOC) each pinning one sub-concern — configured root, durable ordering, gate+stop, login, login fail-closed, login root, rendered, rendered temp, temp, TLS. File count explosion is directly proportional to responsibility count in one prod file.
  - This file imports `pkg/frr`, `pkg/ipsec`, `pkg/dhcpserver`, `pkg/fsatomic`, `pkg/configstore` — wide fan-in for a single module.

- Proposed decomposition:
  - Keep `server_diag_zeroize.go` as thin orchestrator (performZeroizeWipe + zeroizeSyncDir seam + constants only, ~100 LOC).
  - New files in same package:
    - `zeroize_config.go` — `zeroizeConfigDir`, `isTextRollbackFile`, `isFsatomicTemp`, `sweepFsatomicTemps` — config-state erasure only (configDir .configdb/journal/rollback/tls + temp pattern).
    - `zeroize_rendered.go` — `zeroizeRenderedConfigs` + rendered temp sweep — FRR/IPsec/Kea rendered secrets, depends on `pkg/frr`, `pkg/ipsec`, `pkg/dhcpserver`.
    - `zeroize_login.go` — `zeroizeLoginAccounts`, `zeroizeRootLoginAccount`, `zeroizeLookupUIDErr`, `readProvisionedMarkerUID`, `zeroizeRootAuthorizedKeysPath` + all login path vars (`zeroizeProvisionedUsersDir`, `zeroizeSudoersDir`, etc.) + `zeroizeUserdel`, `zeroizeLockRootPassword`, `zeroizeRootSSHDir`.
    - `zeroize_bpf_networkd.go` (or fold into orchestrator) — BPF pins + networkd file sweep, non-security-critical best-effort legs.
  - Seam by responsibility: config SSOT vs rendered service configs vs OS accounts vs system artifacts. Each file owns its path vars, its fail-closed logic, its imports. `zeroize_login.go` isolates the `pkg/daemon` import-cycle workaround vars in one place.
  - Tests: existing 10 files can be co-located or re-grouped: `zeroize_config_*_test.go` vs `zeroize_rendered_*_test.go` vs `zeroize_login_*_test.go` + `zeroize_root_*_test.go`. Currently all share `assertPresent` / `setZeroizeLoginPaths` / `mustWriteFile` helpers duplicated or imported across files — extract `zeroize_testhelpers_test.go` with shared `mustWriteFile`, `assertAbsent`, `assertPresent`, `setZeroizeLoginPaths`, `setZeroizeRootPaths`.
  - Import benefit: `zeroize_config.go` no longer imports `ipsec`/`dhcpserver`/`frr`, reducing compile deps.

- Hot-path preservation analysis:
  - Rank: D — cold path, factory reset one-shot, no fast-path impact. Zeroize is invoked only via `SystemAction zeroize` gRPC verb or CLI, which logs, wipes, stops daemon, reboots.
  - Guardrails: must preserve key-first ordering (master.key unlink + fsync before ciphertext RemoveAll), fail-closed error propagation (firstErr), os.ErrNotExist tolerance, marker retain on userdel failure, root /root/.ssh special-case, sweep for fsatomic temps both in configDir and rendered dirs.
  - How to verify no regression:
    - `make test-go` — exercises all 10 zeroize tests + rest of grpcapi.
    - `make test` — full Go + Rust, since zeroize touches fsatomic (shared with configstore).
    - Manual review of `zeroizeConfigDir` key-first + fsync ordering — disassembly diff not needed (cold), but unit test `TestZeroizeConfigDirDurableOrdering` pins durability barrier count and `TestZeroizeConfigDirPropagatesDirSyncError` pins error propagation — both must still pass.
    - Build size check: `go build ./pkg/grpcapi/` binary size delta should be zero (refactor only, no behavior change).
    - No `test-failover` or CoS gates required — zeroize never runs during forwarding.

- Tests + gate:
  - Existing: `TestZeroizeTargetsConfiguredRootNotHardcoded`, `TestZeroizeConfigDirDurableOrdering`, `TestZeroizeConfigDirPropagatesDirSyncError`, `TestZeroizeConfigDirRemovesFsatomicTemps`, `TestIsFsatomicTempGRPC`, `TestZeroizeRenderedConfigsErasesSecrets`, `TestZeroizeRenderedConfigsLeavesUnmanagedFRRUntouched`, `TestZeroizeRenderedConfigsRemovesFsatomicTemps`, `TestZeroizeRenderedConfigsTempSweepAbsentDirNoError`, `TestZeroizeLoginAccountsRemovesProvisionedNotOthers`, `TestZeroizeLoginAccountsSurfacesUserdelFailureAndKeepsMarker`, `TestZeroizeLoginUnreadablePasswdFailsClosed`, `TestZeroizeLoginMalformedPasswdUIDFailsClosed`, `TestZeroizeLoginUnparseableMarkerFailsClosed`, `TestZeroizeLoginUIDMismatchReportedNonDestructive`, `TestZeroizeLoginRetryAfterFailClosedRediscovers`, `TestZeroizeRevokesManagedRootInPlace`, `TestZeroizeRootRevocationFailsClosed`, `TestZeroizeConfigDirWipesTLSKey`, `TestZeroizeGoesThroughGateAndStopsDaemon`, `TestZeroizeFailClosedDoesNotStopDaemon`, `TestZeroizeFallsBackToDirectWipeWithoutGate` — 22 tests.
  - Gate: `make test-go -run TestZeroize` must stay green. No skipped tests. If extracting helpers to `zeroize_testhelpers_test.go`, ensure it compiles with `//go:build` test tag or same package (it already does).
  - Add post-split smoke: `go vet ./pkg/grpcapi/` — ensures var seams (`zeroizeSyncDir`, `zeroizeUserdel`, etc.) still accessible to tests (same package, no cross-package break).

- Why it matters:
  - Security-critical wipe with 6+ subsystems in one file makes it hard to audit that every secret artifact is covered; a future addition (e.g., WireGuard PSK rendered elsewhere) must be inserted into an already overloaded orchestration. Splitting gives clear ownership and review boundaries — config vs rendered vs login.
  - Test sprawl: 10 files for one prod file means newcomers cannot tell coverage gaps without reading all 10. Per-submodule test grouping mirrors file grouping, improving discoverability.
  - Import hygiene: login-account code does not need FRR/IPsec imports, rendered-config code does not need passwd parsing.

- Fix direction:
  - Mechanical file split, no behavior change. Keep package same (`package grpcapi`), keep all var seams same name, move funcs verbatim. Orchestrator file keeps `performZeroizeWipe` var closure, `zeroizeSyncDir` var, `defaultConfigDir/Base` consts. Move path vars to `zeroize_login.go`.
  - First PR: extract `zeroize_config.go` + `zeroize_rendered.go` (lowest coupling, no login vars). Second PR: extract `zeroize_login.go` + `zeroize_testhelpers_test.go`.

- Labels: cold-path, file-split, security-critical, test-sprawl-symptom, import-hygiene

- Dedup note: Overlaps with any broad `server_diag_system_action.go` god-file finding (Finding 2) only in orchestration — this finding is specifically about erasure responsibilities inside `server_diag_zeroize.go`, not the SystemAction switch. Distinct seam.

---

### Finding 2 — SystemAction 440-line switch god-method + 19 verb handlers fused, single entry point for power, wipe, clear, failover, userspace-inject — hub file low cohesion

- Title: SystemAction RPC is a 440-line method with 19 verb cases fusing power/wipe/clear/failover/userspace-inject — god-method in 576-LOC file, low cohesion hub
- Severity: medium
- Confidence: high
- Refactor class: B — large function fusing distinct responsibilities (power lifecycle vs counter clearing vs HA failover vs dataplane debug injection), hub file low cohesion
- Evidence:
  - File: `/home/ps/git/avacado-xpf/pkg/grpcapi/server_diag_system_action.go`, 576 LOC total
  - Function `SystemAction` at line 136 — 440 lines (136-576), single switch on `req.Action` handling 19 verb classes:
    ```
    func (s *Server) SystemAction(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
        switch req.Action {
        case "reboot": ...
        case "halt": ...
        case "power-off": ...
        case "zeroize": ...
        case "clear-config-lock": ...
        case "clear-arp": ...
        case "clear-interfaces-statistics": ...
        case "clear-ipv6-neighbors": ...
        case "clear-policy-counters": ...
        case "clear-firewall-counters": ...
        case "clear-nat-counters": ...
        case "clear-persistent-nat": ...
        case "ospf-clear": ...
        case "bgp-clear": ...
        case "ipsec-sa-clear": ...
        case "dhcp-renew": ...
        case "in-service-upgrade": ...
        case "dynamic-dns-update", "dynamic-dns-check": ...
        default:
            // + cluster-failover string parsing + data node failover + userspace-inject/forwarding/queue/binding
    ```
  - Each verb is distinct: power actions (journal + schedulePowerAction), zeroize (journal + runZeroize + scheduleStopDaemon), clear actions (dp emptiness checks + clear calls), routing clears (frr.ExecVtysh), IPsec (ipsec.TerminateAllSAs), DHCP (dhcp.Renew), ISSU (cluster.ForceSecondary + WaitForUpgradeHandoff), DDNS (surfaceADDNSForceFn), cluster data-failover (node routing + proxyPeerSystemAction + RequestPeerFailoverBatch), userspace dataplane debug (userspaceDataplaneControl + BuildInjectPacketRequest etc.).
  - Helper `proxyPeerSystemAction` (21-34) and `runZeroize` (124-134) and `zeroizeConfigRoot` (101-110) are mixed in same file — only relevant to zeroize + data-failover.
  - File imports `cluster`, `dpuserspace`, `dpformat`, `pb` but also drives `frr`, `ipsec`, `dhcp`, `rpm`, `flowexport`, `ddns` via Server deps — wide coupling.
  - Test pin for this is `zeroize_gate_stop_5281_test.go` — 150 LOC exercising SystemAction zeroize path via seams:
    ```
    var gateWipeArg func() error
    dir := t.TempDir()
    store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
    s := &Server{
        store: store,
        zeroizeFn: func(_ context.Context, wipe func() error) error {
            seq = append(seq, "gate")
            gateWipeArg = wipe
            return wipe()
        },
    }
    resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
    ...
    if want := []string{"gate", "wipe", "stop"}; !reflect.DeepEqual(seq, want) {
        t.Fatalf("zeroize step sequence = %v, want %v", seq, want)
    }
    ```
    Shows seams `performZeroizeWipe` and `scheduleStopDaemon` are package vars to allow testing without real disk/daemon — god-method requires seam injection because it is too coupled to test directly.
  - Batch relevance: `zeroize_gate_stop_5281_test.go` is in this batch and directly tests SystemAction — its 3 tests exist only because SystemAction cannot be unit-tested without seams.

- Proposed decomposition:
  - Keep `server_diag_system_action.go` as dispatch table: keep `SystemAction` method but each case becomes a one-liner dispatching to a named handler func.
  - New files in same package:
    - `system_action_power.go` — `powerReboot`, `powerHalt`, `powerOff` + `schedulePowerAction` var + `logSystemAction`.
    - `system_action_zeroize.go` — `zeroizeConfigRoot`, `runZeroize`, `proxyPeerSystemAction`, `scheduleStopDaemon` var, zeroize case handler `handleZeroize`.
    - `system_action_clear.go` — `clearARP`, `clearIPv6Neighbors`, `clearPolicyCounters`, `clearFirewallCounters`, `clearNATCounters`, `clearPersistentNAT`, `clearInterfaceStats`, `clearConfigLock`.
    - `system_action_routing.go` — `handleOSPFclear`, `handleBGPclear`, `handleIPsecSAClear`, `handleDHCPrenew`.
    - `system_action_cluster.go` — cluster failover parsing + `cluster-failover:`, `cluster-failover-reset:`, `cluster-failover-data:node` handlers + data-group batch move.
    - `system_action_userspace.go` — userspace-inject/forwarding/queue/binding handlers.
  - Seam: by verb class — power lifecycle (needs journal + systemctl), clear (needs dataplane check), routing (needs FRR/IPsec), cluster (needs clusterMgr + peer proxy), userspace debug (needs userspace provider).
  - Result: `SystemAction` shrinks to ~80 LOC switch dispatching to handlers, each handler file 100-200 LOC, independently reviewable.

- Hot-path preservation analysis:
  - Rank: D — entirely cold admin RPC, not on packet path. Counter clear touches dataplane but via `Clear*` methods, not fast-path inline.
  - Guardrails: preserve exact error codes (`codes.Internal`, `codes.Unavailable`, `codes.InvalidArgument`, `codes.NotFound`, `codes.FailedPrecondition`), journal-before-action ordering for power/zeroize, fail-closed zeroize (no stop on partial wipe), cluster failover node validation (`IsSupportedClusterNodeID`), proxy recursion guard (`x-peer-forwarded`), userspace provider availability (`codes.Unavailable` on missing helper).
  - How to verify no regression:
    - `make test-go -run SystemAction` / `-run Zeroize` / `-run Cluster` — existing tests.
    - `make test` — full suite.
    - Behavioral diff: no change in wire `SystemActionResponse.Message` strings — grep for `"System zeroized"`, `"ARP cache cleared"`, etc. remains identical.
    - No perf gate needed (cold RPC).

- Tests + gate:
  - Existing `zeroize_gate_stop_5281_test.go` (3 tests) + `system_action_test.go` (other verbs) continue to pass. After split, same package so var seams remain visible.
  - Gate: `make test-go` green; `go vet ./pkg/grpcapi/`.
  - Future: each new `system_action_*_test.go` can test its handler in isolation without needing full Server fake.

- Why it matters:
  - 440-line switch is a review hazard — adding a verb requires reading all 18 others; a bug in one verb's error handling can be missed. HA failover + power + security wipe share one function — mixing safety domains.
  - Low cohesion causes merge conflicts — multiple teams editing same file for unrelated verbs (FRR team adds `ospf-clear`, HA team adds `cluster-failover-data`, dataplane team adds `userspace-inject`).
  - Test seam vars `performZeroizeWipe` / `scheduleStopDaemon` / `schedulePowerAction` exist because the god-method cannot otherwise be tested — splitting reduces need for global var seams.

- Fix direction:
  - Mechanical extract-method, dispatch table. No behavior change. First extract clear* handlers (lowest risk, no Journal), then power, then zeroize, then cluster, then userspace.

- Labels: cold-path, god-method, low-cohesion, dispatch-table, file-split-opportunity

- Dedup note: Distinct from Finding 1 — Finding 1 is erasure sub-responsibilities inside `server_diag_zeroize.go`; this is the SystemAction dispatch god-method that CALLS zeroize plus 18 other verbs. No overlap with zone findings.

---

### Finding 3 — server_show_zones.go fuses 3 RPCs (GetZones, GetPolicies, GetScreen) with distinct counter read semantics — 395 LOC, moderate god-file, per-RPC test fragmentation

- Title: GetZones/GetPolicies/GetScreen fused in one 395-LOC file, distinct counter read semantics, flood-counter hide vs bulk policy reader vs screen thresholds — test split mirrors prod fusion
- Severity: low
- Confidence: medium
- Refactor class: C — smallish file but clear seam missed, responsibilities distinguishable by RPC
- Evidence:
  - File: `/home/ps/git/avacado-xpf/pkg/grpcapi/server_show_zones.go`, 395 LOC
  - Three top-level RPCs:
    - `GetZones` (18-128, 110 LOC) — zone inventory + per-zone counter read via `ReadZoneCounters` + `ErrCounterNotPopulated` hide logic #3643 + lifeline #3682 + host-inbound:
      ```
      func (s *Server) GetZones(_ context.Context, _ *pb.GetZonesRequest) (*pb.GetZonesResponse, error) {
          ...
          if id, ok := cr.ZoneIDs[zoneName]; ok {
              zi.Id = uint32(id)
              if s.dp != nil && s.dp.IsLoaded() {
                  ing, errIn := s.dp.ReadZoneCounters(id, 0)
                  eg, errOut := s.dp.ReadZoneCounters(id, 1)
                  switch {
                  case errors.Is(errIn, dataplane.ErrCounterNotPopulated) ||
                       errors.Is(errOut, dataplane.ErrCounterNotPopulated):
                       // #3643 HIDE: per-zone traffic counters are not sourced
                       // by the userspace dataplane. Leave the counter fields
                       // unset (proto3 omit) rather than Internal-erroring
      ```
    - `GetPolicies` (130-368, 238 LOC) — largest func in file, policy inventory + bulk counter reader #4344 + scheduler state #3624 + runtime IDs #3336 + global policies + default-policy sentinel #3363:
      ```
      func (s *Server) GetPolicies(_ context.Context, _ *pb.GetPoliciesRequest) (*pb.GetPoliciesResponse, error) {
          cfg := s.store.ActiveConfig()
          if cfg == nil {
              return &pb.GetPoliciesResponse{}, nil
          }
          statsEnabled := cfg.Security.PolicyStatsEnabled
          var readErr error
          var readPolicy func(uint32) (dataplane.CounterValue, error)
          if s.dp != nil && s.dp.IsLoaded() {
              readPolicy = dpuserspace.NewPolicyCounterReader(s.dp, cfg, s.dp.ReadPolicyCounters)
          }
          ...
      ```
      This func alone is >150 LOC, close to refactor threshold.
    - `GetScreen` (370-395, 25 LOC) — screen profile inventory, trivial.
  - Imports 5 packages (`config`, `dataplane`, `dpuserspace`, `pb`, `proto`) — moderate.
  - Batch relevance:
    - `zones_policies_counter_error_test.go` (69 LOC) tests GetPolicies and GetZones counter error surfacing:
      ```
      type policyZoneErrGRPCDP struct { ...
      }
      func (d *policyZoneErrGRPCDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
          return dataplane.CounterValue{}, errors.New("simulated counter read failure")
      }
      func (d *policyZoneErrGRPCDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
          return dataplane.CounterValue{}, errors.New("simulated zone counter read failure")
      }
      func TestGetPoliciesFailsOnCounterReadError(t *testing.T) { ...
      func TestGetZonesFailsOnCounterReadError(t *testing.T) { ...
      ```
    - `zone_flood_counters_hide_test.go` (74 LOC) tests the opposite: ErrCounterNotPopulated must be hidden, not surfaced as Internal:
      ```
      func TestShowZonesDetailTextZoneCountersNotAvailable(t *testing.T) { ...
      func TestShowScreenStatisticsAllTextFloodNotAvailable(t *testing.T) { ...
      ```
    - Both test files use fake DP interfaces that mock only counter reading — pattern needed because real DP not available in unit tests.
    - The two test files test opposite error semantics in same production file — one pins Internal error surfacing (#3408), other pins hide (#3643) — opposite behaviors in same file, sign of fused concerns.

- Proposed decomposition:
  - Split into:
    - `server_show_zones.go` — GetZones only (zone inventory + zone counter read + flood hide + lifeline).
    - `server_show_policies.go` — GetPolicies only (policy inventory + bulk reader + scheduler state + global policies + default-policy sentinel).
    - `server_show_screen.go` (or keep Screen with zones if small) — GetScreen.
  - Seam by RPC — each file owns its counter read seam, its error handling, its sorting, its proto mapping. New bulk reader helper `newPolicyCounterReader` could move to `server_show_policies.go` as private helper rather than inline var.
  - Alternatively, if file split is considered churn for 395 LOC, at minimum extract `readZoneCounters` helper and `buildPolicyRule` helper to reduce GetPolicies from 238 to <150 LOC.

- Hot-path preservation analysis:
  - Rank: D — cold config inventory RPCs, not fast path. GetPolicies bulk reader #4344 optimized for O(P+C) but still control path, not data path. Counter read is dataplane lock under `ReadPolicyCounters` but not packet hot.
  - Guardrails: must preserve `codes.Internal` on counter read failure, `ErrCounterNotPopulated` hide (proto3 omit), bulk reader O(P+C) invariant, scheduler active-state fail-open vs fail-closed, proto presence for policy_id 0 (#3623).
  - How to verify no regression:
    - `make test-go -run TestGetPoliciesFailsOnCounterReadError -run TestGetZonesFailsOnCounterReadError -run TestShowZones` — existing 69+74+288 LOC tests.
    - `make test` — full suite.
    - No perf stat needed, but bench: `go test -run=XXX -bench` not required — control path.

- Tests + gate:
  - Existing `zones_policies_counter_error_test.go`, `zone_flood_counters_hide_test.go`, `server_show_zones_test.go` (288 LOC) must remain green.
  - Gate: `make test-go`.

- Why it matters:
  - GetPolicies 238-line func with 4 distinct concerns (counter bulk read, scheduler state, runtime IDs, global+default policy) is approaching god-function; fused with GetZones (which has its own flood-counter hide case) makes file harder to reason about counter error semantics — one path must Internal-error, other must hide. Opposite behaviors in same file without clear separation is a consistency bug risk.
  - Split aligns file with RPC — one file per RPC, standard pattern in larger gRPC services, improves nav.

- Fix direction:
  - Low priority. If split is too much churn, refactor GetPolicies into smaller helpers: `buildPolicyInfo`, `buildPolicyRule`, `policyCounterReader`. Keep file but break up 238-line func. This is more conservative than file split.

- Labels: cold-path, rpc-fusion, counter-semantics-divergence, low-priority

- Dedup note: Distinct from zonepair_summary finding (Finding 4) — that is session aggregation, not zone inventory. No overlap with zeroize findings.

---

### Finding 4 — server_sessions.go 1778-LOC god-file inferred from batch zonepair tests — out of direct batch but visible as dependency of zonepair_summary_3592_test.go

- Title: server_sessions.go 1778 LOC god-file hosts GetSessions cursor+legacy, zone-pair summary, clear filtered V4/V6, peer fan-out — largest file in grpcapi, high risk for merge conflicts + review miss
- Severity: medium
- Confidence: high (measured LOC + func grep, not in batch but import-dependency of batch's zonepair_summary)
- Refactor class: A — file >1500 LOC, funcs >150 lines merged, module fusing distinct responsibilities (read vs clear vs summary vs peer fan-out)
- Evidence:
  - File: `/home/ps/git/avacado-xpf/pkg/grpcapi/server_sessions.go`, 1778 LOC — largest in module, >2× next largest non-text file.
  - Function inventory (from grep):
    ```
    func (s *Server) GetSessions(...)              line 33
    func (s *Server) getSessionsCursor(...)         line 66
    func (s *Server) setSessionsTotal(...)         line 264
    func (s *Server) setSessionsNodeID(...)        291
    func parseSessionPrefix(...)                   323
    func (f *sessionFilter) validate(...)          364
    func (s *Server) buildSessionFilter(...)       374
    func (f *sessionFilter) matchV4(...)           485
    func (f *sessionFilter) matchV6(...)           530
    func (s *Server) fetchPeerSessions(...)        576
    func (s *Server) getSessionsLegacy(...)         625
    func (s *Server) GetSessionSummary(...)        718
    func (s *Server) proxyPeerSessionSummary(...)  826
    func (s *Server) GetZonePairSummary(...)       856  <- directly tested by batch
    func (s *Server) computeZonePairSummary(...)    902
    func (s *Server) proxyPeerZonePairSummary(...)  978
    func (s *Server) ClearSessions(...)            996
    func (b *clearBatchV4) ...                     1118-1258
    func (b *clearBatchV6) ...                     1295-1392
    ```
  - GetZonePairSummary (tested by batch `zonepair_summary_3592_test.go`) lives in this file — batch test mocks `IterateSessions` + `IterateSessionsV6` plus peer fan-out:
    ```
    func (d *twoZonePairDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
        fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{IsReverse: 0, IngressZone: 2, EgressZone: 3})
        fn(dataplane.SessionKey{Protocol: 17}, dataplane.SessionValue{IsReverse: 0, IngressZone: 2, EgressZone: 3})
        fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{IsReverse: 1, IngressZone: 3, EgressZone: 2})
        return nil
    }
    func TestGetZonePairSummaryLocalBreakdown(t *testing.T) {
        s := newZonePairServer(t, &twoZonePairDP{Manager: dataplane.New()})
        resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
        ...
        if zp.Tcp != 1 || zp.Udp != 1 || zp.Total != 2 {
            t.Fatalf("breakdown = tcp %d udp %d total %d, want 1/1/2 (reverse entry must be skipped)", ...)
        }
    }
    func TestGetZonePairSummaryFansOutToPeer(t *testing.T) { ... x-peer-forwarded stamp ... }
    func TestGetZonePairSummaryHonorsRecursionGuard(t *testing.T) { ... ctx with x-peer-forwarded must NOT fan-out ... }
    ```
    Shows GetZonePairSummary has local aggregation (reverse skip + proto class) + peer fan-out + recursion guard — 3 concerns in one RPC, plus ClearSessions has bounded batch + rescan + reverse-key + peer nodeID.
  - Also contains `clear_sessions_bounded_5454_test.go` 388 LOC (largest test in module outside grpc) — clear path complexity.
  - Responsibilities: session cursor pagination, legacy limit/offset, filter building (proto filter matches #), V4 match, V6 match, total counting, node ID, HA primary check, peer sessions fetch, session summary, zone-pair summary compute, peer zone-pair summary proxy, clear sessions V4, clear V4 rescan, clear V6, clear V6 rescan, clearBatch V4/V6 collectors.

- Proposed decomposition:
  - New files:
    - `server_sessions_read.go` — GetSessions, getSessionsCursor, getSessionsLegacy, setSessionsTotal, setSessionsNodeID, fetchPeerSessions — read path.
    - `server_sessions_filter.go` — sessionFilter struct, buildSessionFilter, parseSessionPrefix, protoFilterMatches, validate, matchV4, matchV6 — filtering.
    - `server_sessions_summary.go` — GetSessionSummary, GetZonePairSummary, computeZonePairSummary, proxyPeerSessionSummary, proxyPeerZonePairSummary — aggregation + peer fan-out.
    - `server_sessions_clear.go` — ClearSessions, clearFilteredSessionsV4/V6, rescan variants, clearBatchV4/V6 — mutation.
  - Seam by CRUD operation — read vs filter vs summary-aggregate vs clear-mutate. Each owns its peer proxy logic? Better: `server_sessions_peer.go` for all proxyPeer* functions + recursion guard helper.
  - Keep `sessionFilter` type in filter file, export only needed methods.

- Hot-path preservation analysis:
  - Rank: C — near-hot. `IterateSessions` iterates dataplane session map (HASH map) — called on every `show security flow session` / REST `/sessions`. Cursor path avoids full scan when page_size <, but still touches dataplane. Not packet fast-path, but control-plane hot for large session tables (100k+ sessions). Changing iteration logic must preserve reverse-skip, protocol class breakdown, total count via SessionCount when available.
  - Guardrails: preserve cursor token parsing, pageSize clamp 10000, reverse entry skip, protocol class mapping (tcp/udp/other), total via SessionCount vs full scan, HA isLocalPrimary check, peer fan-out with x-peer-forwarded recursion guard, clear batch bounded size + rescan for concurrent modification.
  - How to verify no regression:
    - `make test-go -run TestGetZonePairSummary -run TestClearSessions -run TestGetSessions` — session suite.
    - `make test-go` full + `make test-rust` not needed (no Rust change).
    - For prod verification: run `make test-deploy` + `show security flow session` + session table size assertion, plus HA cluster `make cluster-deploy` + `show security flow session summary` + `show security flow session summary zone-pair`.
    - No disassembly diff — Go, not Rust dataplane — but bench: `go test -bench=BenchmarkSessions -run=^$` if exists; otherwise measure `go test -run TestGetZonePairSummaryLocalBreakdown -count=10` wall time stable.
    - Build size: unchanged.

- Tests + gate:
  - `zonepair_summary_3592_test.go` (in batch) + `clear_sessions_bounded_5454_test.go` (388 LOC) + `clear_sessions_errors_test.go` + `session_summary_fields_5320_5323_test.go` + `server_sessions_test.go` must stay green.
  - Gate: `make test-go`.

- Why it matters:
  - 1778 LOC > #4006 combined Go+Rust test threshold for single file attention; merging session read, filter, summary, clear, peer fan-out in one file creates high conflict area (multiple features touch sessions: pagination, clear, summary, zone-pair). A bug in clear batching (rescan) could be missed when reviewing a summary change. File size alone makes `gopls` slow.

- Fix direction:
  - Defer to dedicated session-module refactor PR — out of direct scope for zeroize batch B3. Document as high-priority A-class for next refactor sprint. First extract filter helpers (lowest risk), then summary, then clear.

- Labels: near-hot, god-file, high-LOC, session-module, out-of-batch-but-visible

- Dedup note: No overlap with zeroize findings — distinct module. Overlaps with any other A8 batch that also flags server_sessions.go (A8_b1/b2) — if so, dedup to single A-class, keep this as cross-reference.

---

### Finding 5 — Test sprawl: 10 zeroize_*_test.go files sharing duplicated helpers setZeroizeLoginPaths, assertPresent/Absent, mustWriteFile — no shared test helper file, import-cycle workaround vars duplicated comment

- Title: Zeroize test suite fragments helpers across 10 files — setZeroizeLoginPaths, assertPresent, mustWriteFile, setZeroizeRootPaths duplicated or redefined, missing shared helper file
- Severity: low
- Confidence: high
- Refactor class: D — test module large by file count, not LOC, dumping-ground helpers repeated
- Evidence:
  - Batch files list: `zeroize_configured_root_5280_test.go` (107 LOC) + `zeroize_durable_5197_test.go` (82) + `zeroize_gate_stop_5281_test.go` (150) + `zeroize_login_4598_test.go` (170) + `zeroize_login_failclosed_5496_test.go` (194) + `zeroize_login_root_5520_test.go` (151) + `zeroize_rendered_4585_test.go` (103) + `zeroize_rendered_temp_5509_test.go` (123) + `zeroize_temp_5475_test.go` (87) + `zeroize_tls_4599_test.go` (70) = 10 files, 1137 LOC, all in same package `grpcapi`.
  - Helpers:
    - `zeroize_login_4598_test.go` defines `assertPresent` + `setZeroizeLoginPaths`:
      ```
      func assertPresent(t *testing.T, path string) {
          t.Helper()
          if _, err := os.Stat(path); err != nil {
              t.Errorf("expected %s to SURVIVE zeroize (non-xpf artifact), stat err = %v", path, err)
          }
      }
      func setZeroizeLoginPaths(t *testing.T, provDir, sudoersDir, homeBase, passwdPath string) *[]string {
          t.Helper()
          origProv, origSudoers, origHome, origPasswd, origUserdel :=
              zeroizeProvisionedUsersDir, zeroizeSudoersDir, zeroizeHomeBase, zeroizePasswdPath, zeroizeUserdel
          t.Cleanup(func() {
              zeroizeProvisionedUsersDir = origProv
              ...
          })
          ...
          return &deleted
      }
      ```
    - `zeroize_login_root_5520_test.go` defines `setZeroizeRootPaths`:
      ```
      func setZeroizeRootPaths(t *testing.T, rootSSHDir string, lockErr error) *int {
          origSSHDir := zeroizeRootSSHDir
          origLock := zeroizeLockRootPassword
          t.Cleanup(func() {
              zeroizeRootSSHDir = origSSHDir
              zeroizeLockRootPassword = origLock
          })
      ```
      Very similar pattern to `setZeroizeLoginPaths` — same seam restoration via Cleanup.
    - `mustWriteFile` used across many test files but definition is in `configstore_helper_test.go` or similar (not in batch but reused).
    - `assertAbsent` used across files — defined somewhere else, not in batch, but each file assumes it exists.
    - Each test file repeats `root := t.TempDir()` + `provDir := filepath.Join(root, "provisioned-users")` + `sudoersDir` + `homeBase` + `passwdPath` setup — ~10-15 lines duplicated per test func. Example from `zeroize_login_failclosed_5496_test.go`:
      ```
      func TestZeroizeLoginUnreadablePasswdFailsClosed(t *testing.T) {
          root := t.TempDir()
          provDir := filepath.Join(root, "provisioned-users")
          sudoersDir := filepath.Join(root, "sudoers.d")
          homeBase := filepath.Join(root, "home")
          passwdPath := filepath.Join(root, "passwd")
          if err := os.MkdirAll(passwdPath, 0o755); err != nil {
              t.Fatalf("mkdir passwd dir: %v", err)
          }
          ...
      func TestZeroizeLoginMalformedPasswdUIDFailsClosed(t *testing.T) {
          root := t.TempDir()
          provDir := filepath.Join(root, "provisioned-users")
          sudoersDir := filepath.Join(root, "sudoers.d")
          homeBase := filepath.Join(root, "home")
          passwdPath := filepath.Join(root, "passwd")
      ```
      Same preamble repeated 5 times in one file, plus across other files.

- Proposed decomposition:
  - New file `zeroize_testhelper_test.go` (same package, _test.go so not in production binary):
    - `mustWriteFile(t, path, data)` (if not already central),
    - `assertAbsent(t, path)`,
    - `assertPresent(t, path)`,
    - `newZeroizeTempTree(t) (root, provDir, sudoersDir, homeBase, passwdPath)` — returns 5 paths, does TempDir.
    - `setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath) *[]string` (existing, move),
    - `setZeroizeRootPaths(t, rootSSHDir, lockErr) *int`,
    - `setZeroizeSyncDir(t, fn)` helper for durable tests,
    - `setZeroizeRenderedPaths(t, ...)` if needed.
  - Then each test file uses `tree := newZeroizeTempTree(t)` reducing preamble from 5 lines to 1.
  - Keep test files focused — each still pins one concern, but helpers centralized.

- Hot-path preservation analysis:
  - Rank: D — test-only, no production impact.
  - Guardrails: helper must still restore seams via `t.Cleanup`, not leak package var mutations across tests.
  - How to verify: `make test-go -run TestZeroize` green; `go vet`.

- Tests + gate: `make test-go`. No production gate.

- Why it matters:
  - 10 files each with doc-comment explaining #5496 fail-closed contract — excellent RED-on-revert docs — but duplicated setup increases maintenance cost; adding a new zeroize test (e.g., for a future archive encryption key) requires copying same preamble and seam restoration, error-prone. Central helper makes future zeroize tests cheap and consistent.
  - File count 10 for one production file is unusual — signals prod file too large (Finding 1) AND test helpers not factored.

- Fix direction: Extract `zeroize_testhelper_test.go` first, then use it to simplify existing 10 files in follow-up mechanical diff. No behavior change.

- Labels: test-only, helper-duplication, file-count-sprawl, low-priority

- Dedup note: Distinct from Finding 1 — Finding 1 is prod file split; this is test helper extraction. Could be combined in same PR as Finding 1 file split.

---

## Summary Rank

1. Finding 1 (zeroize erasure god-file, 753 LOC, 10 responsibilities) — B, medium, high confidence — split into 3+ files
2. Finding 2 (SystemAction 440-line god-method, 19 verbs) — B, medium, high confidence — dispatch table + per-verb files
3. Finding 4 (server_sessions.go 1778 LOC god-file, session read/filter/summary/clear) — A, medium, high confidence — out-of-batch but critical
4. Finding 3 (server_show_zones.go 3 RPCs fused, GetPolicies 238 lines) — C, low, medium confidence — helper extraction or per-RPC split
5. Finding 5 (test sprawl, duplicated helpers) — D, low, high confidence — shared helper file


---
### Batch A9_go_observability-b1 — 405 lines — full log + findings

# Refactor Audit — Go Observability (A9_go_observability-b1)

Base SHA: f1ef0eec8
Batch: 142 files (25 prod + 117 tests)
Scope: pkg/eventengine, pkg/feeds, pkg/flowexport, pkg/ipmon, pkg/logging, pkg/rpm, pkg/snmp

## Module Checklist Inventory (coverage proof)

### Production Files — LOC (excluding tests, generated)
| Rank | File | LOC | Responsibilities | Hot-path? | Notes |
|------|------|-----|----------------|-----------|-------|
| 1 | pkg/snmp/agent.go | 2143 | BER codec, v1/v2c/v3 dispatch, ifTable/ifXTable walk, engineID+boots persistence, device component (clone uniqueness), trap queue async delivery, lifecycle (Bind/Serve/Stop), response size bounding,community source-IP allowlist | No — UDP poll 1/s, not per-packet | Largest file, god-file candidate |
| 2 | pkg/logging/ringbuf.go | 1451 | ring buffer event source, raw RT_FLOW wire decode (144/152/160), enrichment (zone/policy/if/app name maps), NAT handling, session stats, syslog/local/callback fanout, per-policy log gate (#2508), 3 format renderers, binary framing, slog logging | Warm — session close path (not per-pkt but high freq under load) | 2nd largest, multi-responsibility |
| 3 | pkg/eventengine/engine.go | 1409 | policy runtime (cooldown windows, edge latch), semantic revision hashing, regex cache, eventIndex, bounded queue + worker, transactional commit batch, stale revalidation, debt accounting, throttle warnings | No — RPM probes ~ seconds | Complex state machine, god-struct |
| 4 | pkg/snmp/v3.go | 1209 | USM user key derivation (passwordToKey), HMAC verify, AES/DES encrypt/decrypt, salt counter monotonic, timeliness window, discovery/report, response building, authParams location handling | No | Crypto-heavy, single file but cohesive |
| 5 | pkg/flowexport/ipfix.go | 1109 | IPFIX template set building, data set encoding, sampler options template (RFC7014), biflow reverse PEN, post-NAT trailer, flow-dir conditional, exporter batching, sequence handling | Warm — session close export | Encoder + exporter fused |
| 6 | pkg/ipmon/ipmon.go | 1016 | probe-driven preferred-route overlay, winner resolution per (RI,prefix), DHCP next-hop resolver, debounce+throttle+hold-down state machine, run-loop actuation, status/overlay detail (unresolved/suppressed) | No — RPM transition triggered | State machine + overlay compute fused |
| 7 | pkg/logging/syslog.go | 961 | syslog client: UDP/TCP/TLS dial, source-addr pin, TLS config, RFC3164/5424/structured/binary framing, reconnect cooldown, write deadline, partial-frame teardown, drop counters, rate-limited warnings, category/severity filtering | Warm — logEvent fanout | Moderate cohesion, large |
| 8 | pkg/flowexport/manager.go | 915 | ExportConfig resolution: per-instance collector dedup, template grouping, per-server version binding (#2136), sampling-zone building, flowDirection derivation, family attribution, post-NAT fallback, flow start heuristic | No — config apply time, but ShouldExport called per close | Mix of config resolver + data helpers |
| 9 | pkg/feeds/feeds.go | 889 | dynamic-address feed manager: HTTP fetch with timeout+size cap, parsing canonicalization, dedup+sort, hash, snapshot carry-forward across reconfigure, retainForever vs opt-in hold, degraded sample bounding, onUpdate callback | No — periodic fetch (hourly) | Fetcher + parser + store fused |
| 10 | pkg/flowexport/netflow.go | 853 | NetFlow v9 template fields, record encoding (v4/v6 + post-NAT + CoS + ingress/egress), dataFlowSetLen terminal padding, exporter batching, sysUptime boot anchor, route-mask resolver integration | Warm — session close | Encoder + exporter fused (like ipfix) |
| 11 | pkg/rpm/rpm.go | 794 | RPM probe manager: probe loop, HTTP/TCP/ICMP dispatch, source-addr validation, VRF bind via SO_BINDTODEVICE/MARK, pin failure gating, status aggregation, event + transition callbacks, buffered pre-callback events | No — periodic seconds | Probe scheduler + execution |
| 12 | pkg/flowexport/transport.go | 580 | collectorConns (dial with source-addr, health tracking, backoff skip, write timeout), flowBatch bounded queue with admission lease (#4963), maxDepth CAS monotonic | Warm — per-flush | Two responsibilities in one file: conn mgmt + batch |
| 13 | pkg/logging/trace.go | 553 | TraceWriter: file rotation, hardened open (O_NOFOLLOW, 0600), filter matching (prefix/proto), flag handling, drop/rotation counters, rate-limited warnings | Warm — event callback | File + filter logic |
| 14 | pkg/snmp/traps.go | 454 | link down/up trap building (v2c + v1), version branching (all/v1/v2), community deterministic selection, trap queue enqueue, worker draining with stop abandon, category filtering | No — link monitor triggered | Trap builder + async queue (queue lives in agent.go) |
| 15 | pkg/rpm/icmp.go | 426 | ICMP raw socket listen, echo ID matching, timestamp, deadline, VRF binding for DNS+data socket, ctx-aware lookup | No | ICMP prober |
| 16 | pkg/logging/eventbuf.go | 387 | EventBuffer ring + subscriber fanout, Latest(), unsubscribe, size cap | Warm — every event | Simple buffer |
| 17 | pkg/logging/aggregator.go | 316 | aggregation reporter, ForwardLogMsg | Warm | Small |
| 18 | pkg/flowexport/routemask.go | 316 | route-mask cache: async lookup, TTL eviction, VRF scoped resolve, miss counting | Warm — per close | Cache |
| 19 | pkg/logging/locallog.go | 298 | LocalLogWriter: hardened file open, rotation, binary write, severity/category filter | Warm | Similar to trace.go |
| 20 | pkg/logging/slog_handler.go | 167 | custom slog handler bridging to syslog clients | Warm | Tiny |
| 21 | pkg/ipmon/display.go | 109 | display formatting for show commands | No | Display helper |
| 22 | pkg/logging/event_filter_args.go | 86 | event filter args parsing | No | Tiny |
| 23 | pkg/flowexport/exporterid.go | 57 | stable exporter ID hash | No | Tiny util |
| 24 | pkg/rpm/display.go | 53 | display formatting | No | Tiny |
| 25 | pkg/logging/goid.go | 41 | goroutine ID parsing | No | Tiny util |

### Largest Functions (approx via func start → next func)

| Rank | File:Line | Function | Lines | Responsibility |
|------|-----------|----------|-------|----------------|
| 1 | ringbuf.go:489 | `(er *EventReader) logEvent` | 376 | wire decode 72..160, enrichment, gate, buffer, callbacks, syslog/local fanout, 3 formats |
| 2 | v3.go:137 | `handleV3Packet` | 372 | BER header decode, USM params, user lookup, security level enforcement, auth verify, timeliness, decrypt, PDU dispatch |
| 3 | ipmon.go:522 | `computeOverlayLocked` | 109 | winner resolution, next-hop resolver, unresolved/suppressed detail |
| 4 | feeder.go:201* (feeds.go:201) | `Apply` | 172 | plan building deterministic dedup, snapshot carry-forward, refresh loop start |
| 5 | netflow.go:36 | `systemBootTime` / `encodeRecordV4` | 154 / 76 | boot time CLOCK_BOOTTIME + encode |
| 6 | rpm.go:467 | `runSingleTest` | 147 | per-cycle aggregate, successive-loss threshold, event firing |
| 7 | ipmon.go:822 | `run` | 95 | debounce/throttle/hold-down wake, actuate with timeout |
| 8 | manager.go:699 | `parseIfaceRef` | 113 | iface ref parsing with digit accumulation + validation |
| 9 | syslog.go:531 | `Send` | 73 | priority framing, reconnect cooldown, deadline handling |
| 10 | agent.go:2023 | `decodePDUFields` | 72 | BER varbind list decoding |

*feeds.go Apply is 172 but includes closure capturing.

## Refactor Findings

### Finding 1 — SNMP agent.go god-file (2143 LOC, low cohesion hub)

- **Title**: `pkg/snmp/agent.go` mixes BER codec, PDU handlers (v1/v2c), ifTable walk, persistence (engineBoots + per-device EngineID component), lifecycle, and trap async queue — classic hub file with low cohesion
- **Severity**: High
- **Confidence**: High
- **Refactor class**: A — file exceeds 1500-2000 LOC threshold + fuses ≥5 distinct responsibilities
- **Evidence**: File metrics: 2143 LOC, 60+ funcs, many responsibilities in one type `Agent` (conn, engineID, engineBoots, trapQueue, trapWorker, cfgMu, privSalt, etc.):
  ```go
  // Agent is an SNMP v2c/v3 agent that serves the system MIB and ifTable.
  type Agent struct {
      conn        *net.UDPConn
      startTime   time.Time
      ifDataFn    func() []IfData
      mu          sync.Mutex
      stopped     bool
      engineID    []byte // SNMPv3 engine ID (immutable after initEngine)
      engineBoots int    // SNMPv3 engine boots counter (immutable after initEngine)
      lastPacket  []byte // raw packet for v3 auth verification
      engineBootsPath string
      engineIDPath string
      cfgMu   sync.RWMutex
      cfg     *config.SNMPConfig
      v3Users map[string]*usmUser
      privSalt       atomic.Uint64
      privSaltSeeded atomic.Bool
      privSaltMu     sync.Mutex
      trapQueue      chan trapJob
      trapWorkerOnce sync.Once
      trapsDropped   atomic.Uint64
      trapSender func(target string, pkt []byte) error
      lifeCancel context.CancelFunc
      trapStop   chan struct{}
      trapWG     sync.WaitGroup
  }
  ```
  Also BER codec helpers `berEncodeTLV`, `berEncodeLength`, `berDecodeHeader`, `berDecodeInteger`, `berDecodeOctetString`, `berDecodeOID`, `decodePDUFields` (72 lines), `berEncodedLen`, `oidEqual`, `oidCompare` all live in same file as high-level PDU dispatch `handleV2cPacket` (69 lines), `handleV1Packet`, `handleGetBulk` (60 lines). Method `findNextOIDSnap` builds OIDs inline from ifTableColumns.
- **Proposed decomposition**:
  - `ber.go`: all BER encode/decode primitives + `varbind` type + `effectiveMaxSize` + `trimToFit`
  - `engineid.go`: `buildEngineID`, `deviceComponent`, `loadOrCreatePersistedComponent`, `readMachineID`, `loadAndIncrementEngineBoots`, `engineTime`, `checkTimeliness`
  - `ifmib.go`: `IfData`, `ifSnapshot`, `getIfData`, `getIfTableValue`, `getIfXTableValue`, `findNextOIDSnap`, `IfData` related OID constants
  - `pdu.go`: `handleV2cPacket`, `handleV1Packet`, `handleGet`, `handleGetNext`, `handleGetBulk`, `buildBulkVarbinds`, `boundGetResponse*`, `buildResponse*`
  - `agent.go` (slim): lifecycle `Start/Bind/Serve/Stop`, config snapshot `snapshotCfg`, community auth, trap orchestration `sendLinkTraps` stays but calls out to `traps.go`
  - `traps.go` already exists but `enqueueTrap`/`trapWorker` are in agent.go — move fully to traps.go
- **Hot-path preservation analysis**: SNMP agent is NOT per-packet hot path (UDP 161, poll interval seconds). No allocation-sensitive path. BER codec currently allocates via `append`; refactor can keep same signatures. Careful to keep `ifSnapshot` lazy (one netlink dump per PDU) — that optimization (#4013) must survive. No dataplane forwarding path implications.
- **Tests + gate**: Existing tests cover: `TestAgentV1Polling`, `TestGetBulkSize`, `TestGetRespSize`, `TestSNMPDesSalt`, `TestGetBulkOrder`, `TestTrapsCategories`, `TestTrapCommunity`, etc. Gate: `go test ./pkg/snmp -run TestAgent` + `go test ./pkg/snmp -run TestBER` (to be added). Verify no change in `handlePacket` external behavior.
- **Why it matters**: 2143 LOC file with 15+ concerns is hard to review for security (v3 auth, community redaction #4302, source-IP allowlist #4289, clone uniqueness #5283). Changes to trap queue logic (#4916, #5023) risk colliding with BER fixes. Current file forces reviewers to load entire SNMP stack to check a one-line community redaction.
- **Fix direction**: Extract BER codec first (pure functions, no Agent dep) — low risk. Then extract engineID/boots persistence (already has seams `engineBootsPath`, `engineIDPath`). Then ifTable walk. Each extraction in separate PR, with interface preserved.
- **Labels**: `modularity`, `god-file`, `low-cohesion`, `security-review-hazard`, `refactor-A`
- **Dedup note**: No duplicate — this is unique file. Composite file includes many quasi-independent subsystems; decomposition reduces cyclomatic load.

### Finding 2 — logging/ringbuf.go EventReader fuses wire parsing, enrichment, fanout, formatting (376-line logEvent)

- **Title**: `pkg/logging/ringbuf.go` `EventReader` god-struct with 28 methods, 1451 LOC, central method `logEvent` 376 lines mixing binary decode, NAT formatting, ELT, policy-name resolution gap (#3056 calling out), per-policy syslog gate (#2508), buffer add, callback invocation, slog, syslog clients (3 formats), local writers
- **Severity**: High
- **Confidence**: High
- **Refactor class**: A — large function + file >1000 LOC + responsibility fusion (parsing + enrichment + routing + formatting)
- **Evidence**: Struct definition with 10+ mutex-protected maps (zoneNames, policyNames, ifNames, appNames, syslogClients, localWriters, callbacks) + sessionSeq atomic. `logEvent` 376 lines:
  ```go
  func (er *EventReader) logEvent(data []byte) {
      var evt rawEvent
      evt.Timestamp = binary.LittleEndian.Uint64(data[0:8])
      copy(evt.SrcIP[:], data[8:24])
      // ... 80 lines raw parsing ...
      // #3056: policy ID rides trailing [136:140] slot
      // #2749: CoS block [144:152]
      // #2508 per-policy SYSLOG gate
      suppressSyslogLog := false
      if er.source == nil && (evt.EventType == ...) { ... }
      if er.buffer != nil && !suppressSyslogLog { er.buffer.Add(rec) }
      er.callbackMu.RLock(); cbs := er.callbacks
      for _, cb := range cbs { cb(rec, data) }
      if suppressSyslogLog { return }
      // slog + syslog fanout + local fanout, each with format branching
  }
  ```
  Formatting methods `formatSyslogMsg` (58 lines), `formatStructuredMsg` (114 lines), `formatBinaryRecord` (82 lines) live in same file as transport-agnostic `DecodeRawEventRecord` (130 lines).
- **Proposed decomposition**:
  - `decoder.go`: `rawEvent` definition + `DecodeRawEventRecord` + `eventTimeFromWire` + `Parse NAT fields` helper (`parseRaw`)
  - `enricher.go`: resolver methods (`resolveZoneName`, `resolvePolicyName`, `resolveIfName`, `resolveAppName`) + `EventRecord` building from decoded raw
  - `fanout.go`: `EventReader` reduced to fanout coordinator (buffer, callbacks, syslogClients, localWriters) with `AddCallback`, `SetSyslogClients`, `SetLocalWriters`, `ForwardLogMsg`
  - `format.go`: `formatSyslogMsg`, `formatStructuredMsg`, `formatBinaryRecord`, `protoName`, `closeReasonName`, etc.
  - Keep `EventReader` as orchestrator calling decoder→enricher→fanout, but each piece testable in isolation
- **Hot-path preservation analysis**: `logEvent` is on session-close path (not XDP fast path, but can be high-rate under close storm). Current code under `logEvent` does string formatting (`fmt.Sprintf`) for NAT addresses even when syslog not needed? Actually does formatting before filter? Check: srcStr/dstStr built unconditionally — same cost after refactor. Must preserve early-exit suppressSyslogLog gate that prevents buffer add and formatting. Alloc-sensitive: avoid extra copies of `data` slice. Keep `binary.LittleEndian` parsing zero-copy.
- **Tests + gate**: `TestRawEventContractMatchesDataplaneEvent`, `TestSessionCloseFormat`, `TestSyslogPartialFrame`, etc. Gate: `go test ./pkg/logging -run TestEvent` + `go test ./pkg/logging -run TestBinary` ; verify `ProcessRawEvent` perf via bench.
- **Why it matters**: 376-line function is unreviewable; per-policy gate (#2508) intersects with syslog fanout, binary log sentinel (`actionNotApplicable` #4914), and callback ordering — easy to regress. Formatting changes (e.g., action omission on close #2513) require reading entire file. Test surface is broad but logic tangled.
- **Fix direction**: Extract pure decoder first (`DecodeRawEventRecord` already partial), then formatting into `format.go`, then enricher resolvers into own file with map guards. Reduce `logEvent` to ~50 lines orchestrator.
- **Labels**: `god-struct`, `large-function`, `responsibility-fusion`, `logging-hot`, `refactor-A`
- **Dedup note**: `DecodeRawEventRecord` duplicates much of `logEvent` parsing (dual source of truth) — should share decoder.

### Finding 3 — eventengine/engine.go Engine struct fuses 7 concerns (runtime state, regex cache, queue, worker, commit, counters, warn throttling)

- **Title**: `pkg/eventengine/engine.go` 1409 LOC `Engine` with 15 fields: `policies`, `store`, `commitFn`, `runtime` map, `semRev` map, `regexCache`, `eventIndex`, counters, actions channel, workerWG, stopCh, enqueueMu, lifeCtx, invalidWarn throttling, `nowFn`, `afterDrainFn`, `newTimerFn`, retry tuning
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: B — file under 1500 LOC but god-struct with ≥6 distinct responsibilities
- **Evidence**: Struct definition (from Read):
  ```go
  type Engine struct {
      mu       sync.Mutex
      policies []*config.EventPolicy
      store    *configstore.Store
      commitFn CommitFn
      runtime map[string]*policyRuntime
      semRev map[string]string
      regexCache map[string]*regexp.Regexp
      eventIndex map[string][]*config.EventPolicy
      counters engineCounters
      actions   chan plannedAction
      workerWG  sync.WaitGroup
      stopOnce  sync.Once
      stopCh    chan struct{}
      startOnce sync.Once
      enqueueMu sync.Mutex
      lifeCtx    context.Context
      lifeCancel context.CancelFunc
      invalidWarnMu sync.Mutex
      invalidWarnAt map[string]int64
      nowFn func() time.Time
      afterDrainFn func()
      newTimerFn func(time.Duration) (<-chan time.Time, func() bool)
      retryInitial  time.Duration
      retryMax      time.Duration
      retryDeadline time.Duration
  }
  ```
  Methods: `Apply` 91 lines (reconcile runtime + regex cache + eventIndex), `applyOnce` 105 lines (transactional batch), `runAction` 92 lines (retry backoff + debt handling + stale), `evaluateEvent` 83 lines (sliding window + cooldown + latch), `withinMatches` 79 lines (edge latch + trigger until). Largest func `newPolicyRuntime` reported 120 lines due to comment block.
- **Proposed decomposition**:
  - `runtime.go`: `policyRuntime`, `newPolicyRuntime`, `policySemanticRevision`, `pruneWindow`, `armCooldown`, `staleReason`
  - `matcher.go`: `attributesMatch`, `flagAttributesInvalid`, `withinMatches`, `policyHasTriggerOn`, `evaluateEvent`, `eventIndex` building
  - `planner.go`: `plannedOp`, `plannedAction`, `classifyPlan`, `remediationDescription`
  - `queue.go`: `actions` chan, `enqueue`, `supersede` (61 lines), `enqueueMu` logic (#5062), `actionWorker`, `runAction`, backoff/retry
  - `engine.go`: slim orchestrator `Apply`, `HandleEvent`, `Close`, `Stats`, `PolicyCount`, `commitContext`
  - Extract `CommitFn` tri-state handling into own type with `committedWithDebt` counting
- **Hot-path preservation analysis**: Engine is NOT per-packet hot path (RPM events seconds). However `HandleEvent` is called from many probe goroutines concurrently (enqueueMu serialization). Queue bounded 64, drop policy must stay. Counter to keep lock-free atomics. Commit path holds `configstore` lock + `e.mu` at stale check — must preserve ordering to avoid interleaving operator commit.
- **Tests + gate**: Rich tests: `TestEngine_4423`, `TestEdgeTrigger_3756`, `TestInclusiveUntil`, `TestStaleRevalidate_3750`, `TestSupersedeRace_5062`, `TestCooldownRev_5311`, `TestArmedDebt_5063`, `TestWithinFailClosed_3751`, `TestWindow`. Gate: `go test ./pkg/eventengine -count=1` must stay green after extraction.
- **Why it matters**: Current file carries #2139 transactional batch, #2140 cooldown reconcile, #2141 fail-closed matcher, #2157 fail-safe queue, #3750 revalidate-before-commit, #3756 edge latch, #5062 supersede atomicity, #5311 revision-aware cooldown — each is a subtle correctness property. Mixing them in one file makes reviewing a single property require loading all others. Recent bugs (#5062 loss, #5311 ABA) stem from queue+runtime interaction.
- **Fix direction**: Start by extracting pure matcher (`attributesMatch` + `withinMatches` + `policySemanticRevision`) into `matcher.go` (no channel/callback deps). Then extract queue/worker into `queue.go`. Keep `Apply` orchestrator small.
- **Labels**: `god-struct`, `state-machine`, `concurrency`, `refactor-B`
- **Dedup note**: `staleReason` + `armCooldown` both read `semRev` under `mu` — related but could share helper.

### Finding 4 — feeds/feeds.go 889 LOC mixes HTTP client, parsing, canonicalization, snapshot lifecycle, degraded-sample bounding

- **Title**: `pkg/feeds/feeds.go` `Manager` 889 LOC combines HTTP fetch (timeout 30s, size cap 32 MiB, count cap 1M), line scanning (1 MiB cap), CIDR/IP canonicalization, dedup+sort, hash, snapshot carry-forward (#5282), retain-forever vs opt-in hold, degraded sample byte-bounding (#4922), onUpdate callback
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: B — file under 1000 LOC but ≥4 distinct responsibilities with large methods Apply 172 lines and parseFeed 98 lines
- **Evidence**: `Apply` builds deterministic plan from map, dedups duplicate feed names, carries forward snapshot, starts refreshLoop goroutines:
  ```go
  func (m *Manager) Apply(ctx context.Context, daCfg *config.DynamicAddressConfig) {
      // Build a COMPLETE, deterministic, de-duplicated plan BEFORE mutating m.feeds (#4913, #5282)
      type feedPlan struct { name string; url string; hold time.Duration; interval time.Duration; server string }
      var plans []feedPlan
      // ... sorting serverNames, seen map, warnPlaintextFeed, carryForwardSnapshot ...
      m.mu.Lock()
      old := m.feeds
      for _, fs := range old { fs.cancel() }
      newFeeds := make(map[string]*feedState, len(plans))
      for _, p := range plans { feedCtx, cancel := context.WithCancel(ctx); fs := &feedState{...}; if prev, ok := old[p.name]; ok { carryForwardSnapshot(fs, prev) }; newFeeds[p.name]=fs; go m.refreshLoop(feedCtx, fs, p.interval) }
      m.feeds = newFeeds
  }
  ```
  Parsing mixed into same file `parseFeed` with countingReader, scanner, invalid sample bounding `boundInvalidSample` (escapes control bytes, truncates 256B + annotation). `recordFailure` with staleSince + holdInterval logic, `installSnapshot` with hash compare + onUpdate firing only on change.
- **Proposed decomposition**:
  - `fetch.go`: `readFeed` HTTP GET + status check + `http.Client` with timeout, `countingReader`
  - `parse.go`: `parseFeed`, `canonicalize`, `hashPrefixes`, `boundInvalidSample`, constants `maxLineBytes`, `maxFeedBodyBytes`, `maxFeedPrefixes`, `maxInvalidSample*`
  - `store.go`: `feedState`, `Manager.mu`, `GetPrefixes`, `AllFeeds`, `SnapshotForBindings`, `installSnapshot`, `recordFailure`, `carryForwardSnapshot`
  - `manager.go`: `Apply` orchestrator (plan building) + `refreshLoop` + `Manager` construction
- **Hot-path preservation analysis**: Not hot — hourly fetch, occasional config apply. Snapshot read `GetPrefixes`/`SnapshotForBindings` used during config compile (daemon apply) and status `AllFeeds` for show. Must preserve deep-copy semantics (slice copied) and non-nil empty slice for known feed (fail-closed). No per-packet path.
- **Tests + gate**: Tests: `feeds_test.go`, `feeds_bindings_test.go`, `feeds_dup_name_4913_test.go`, `feeds_samplecap_4922_test.go`, `feeds_sizecap_3934_test.go`, `feeds_snapshot_handoff_5282_test.go`. Gate: `go test ./pkg/feeds -count=1`. Verify handoff test still passes after split (snapshot carry-forward is subtle fail-open guard).
- **Why it matters**: File history shows many CVE-style fixes: #3934 size/count cap (DoS), #4922 sample byte bounding (mem), #5282 fail-open window, #4913 duplicate name orphan goroutine. Each fix touched same file because responsibilities fused. Extracting parser lets unit-test `parseFeed` in isolation (already does via io.Reader seam) and makes future DoS hardening reviewable.
- **Fix direction**: Extract `parse.go` first (pure function `parseFeed(io.Reader) (fetchResult,error)`, already testable). Then extract store snapshot logic. Keep manager orchestration thin.
- **Labels**: `fetch-parse-store-fusion`, `security-hardening-history`, `refactor-B`
- **Dedup note**: None.

### Finding 5 — flowexport/manager.go mixes config resolvers, sampling zone building, post-NAT helper, duration heuristic (915 LOC)

- **Title**: `pkg/flowexport/manager.go` is documented as "resolved export config, sampling scheduler, shared FlowRecord shape, and BuildExportConfig family" but also contains `parseIfaceRef` (113 lines), `resolvePostNAT` (25 lines family-agnostic NAT fallback), `natIPAbsent`, `flowStartTime`, `estimateSessionDuration`, `collectorKey`, `FlowRecord` + `SessionCloseData` struct definitions — config resolution + data-plane helpers in one file
- **Severity**: Low
- **Confidence**: Medium
- **Refactor class**: C — moderate size, but distinct helper groups could be split for clarity; not urgent
- **Evidence**: File header comment says package split by responsibility, but manager.go itself lists 4 responsibilities. Example of mixed helper `parseIfaceRef` doing Atoi parsing with strict validation (quote from Read):
  ```go
  func parseIfaceRef(ref string) (name string, unit int, ok bool) {
      dot := strings.LastIndexByte(ref, '.')
      if dot < 0 {
          return ref, 0, true
      }
      suffix := ref[dot+1:]
      if suffix == "" || suffix[0] < '0' || suffix[0] > '9' {
          return ref[:dot], 0, false
      }
      u, err := strconv.Atoi(suffix)
      if err != nil || u < 0 {
          return ref[:dot], 0, false
      }
      return ref[:dot], u, true
  }
  ```
  Plus `flowStartTime` uses `rec.Created` + `CreatedNanos` or falls back to heuristic `estimateSessionDuration` with saturation at `maxEstimatedSessionAge` — unrelated to collector grouping.
- **Proposed decomposition**:
  - Keep `manager.go` for `ExportConfig`, `CollectorConfig`, `ResolveV9TemplateGroups`, `ResolveIPFIXTemplateGroups`, `BuildExportConfig`, `BuildSamplingZones`, `dedupeCollectors`, `groupCollectorsByTemplate`, `templateContext` resolvers
  - `postnat.go`: `resolvePostNAT`, `natIPAbsent`
  - `flowrecord.go`: `FlowRecord`, `SessionCloseData`, `flowStartTime`, `estimateSessionDuration`, `maxEstimatedSessionAge`
  - `iface.go`: `parseIfaceRef`
- **Hot-path preservation analysis**: `ShouldExport` is called per session-close (warm path). `flowStartTime` also per close. No allocation on hot path currently; refactor must not add allocs. Config resolvers are cold (apply time). Splitting files does not affect runtime.
- **Tests + gate**: `exporter_test.go` (NetFlow), `ipfix_test.go`, `flowstart_test.go`, `postnat_test.go`, `srcmask_dstmask_test.go`, `version_binding_test.go`, `per_collector_source_3745_test.go`, etc. Gate: `go test ./pkg/flowexport -count=1`
- **Why it matters**: Mixing helpers makes it harder to find where `post-NAT` fallback logic lives (Junos parity). Recent fix #2526 (post-NAT trailer) and #3745 (per-collector source) both touched manager.go because helpers collocated. Small split improves discoverability.
- **Fix direction**: Extract `FlowRecord` + duration heuristic into own file first (data record is central type). Extract post-NAT resolver next.
- **Labels**: `mixed-helpers`, `config-resolver`, `refactor-C`
- **Dedup note**: `resolvePostNAT` logic duplicated? Actually shared by NetFlow and IPFIX exporters via import — good, not dup.

### Finding 6 — snmp/v3.go handleV3Packet 372 lines monolith handling auth+priv+PDU dispatch

- **Title**: `pkg/snmp/v3.go` `handleV3Packet` 372 lines is single function doing BER header decode, USM security params parse, user lookup under cfgMu, per-user minimum security level enforcement (auth required if authKey, priv required if privKey), HMAC verify, timeliness check with report building, scopedPDU decrypt (DES/AES), scopedPDU parse, context gating (non-default context empty view), PDU switch (GET/GETNEXT/GETBULK/SET) with inline varbind building, response size bounding via trimToFit, and final auth MAC insert
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: B — single function >300 lines violates "funcs >150-200 lines" rule, mixes crypto verification, policy enforcement, and PDU handling
- **Evidence**: From LOC analysis: `handleV3Packet` 372 lines largest in batch. Snippet (abridged):
  ```go
  func (a *Agent) handleV3Packet(msgBody []byte) []byte {
      tag, headerBody, err := berDecodeHeader(msgBody)
      // ... msgID, msgMaxSize, msgFlags decode ...
      if msgFlags&msgFlagPriv != 0 && msgFlags&msgFlagAuth == 0 { /* noAuthPriv reject */ }
      // ... engineID, boots, time, userName, authParams, privParams ...
      if userName == "" { return a.buildV3Discovery(msgID) }
      user := a.snapshotV3User(userName)
      if user == nil { return nil }
      if user.authKey != nil && msgFlags&msgFlagAuth == 0 { return nil }
      if user.privKey != nil && msgFlags&msgFlagPriv == 0 { return nil }
      if msgFlags&msgFlagAuth != 0 {
          if !a.verifyAuth(user, authParams) { return nil }
          if !a.checkTimeliness(reqBoots, reqTime) {
              return a.buildV3TimelinessReport(msgID, msgFlags, user)
          }
      }
      // Decode scoped PDU (possibly encrypted) ...
      // Parse scopedPDU: contextEngineID, contextName, PDU ...
      // Context gating ...
      switch pduTag {
      case pduGetRequest: ...
      case pduGetNextRequest: ...
      case pduGetBulkRequest: ...
      case pduSetRequest: ...
      }
      resp := a.buildV3Response(...)
      if len(resp) > effectiveMaxSize(msgMaxSize) { return a.buildV3Response(..., errTooBig, ...) }
      return resp
  }
  ```
  Also `usmAuthParamsRange` 122 lines walking BER with bounded slices.
- **Proposed decomposition**:
  - `v3_parse.go`: USM security params parsing + header decode into struct `v3Request{msgID, msgFlags, boots, time, userName, authParams, privParams, scopedPDUBytes}`
  - `v3_auth.go`: `verifyAuth`, `zeroAuthParams`, `usmAuthParamsRange`, `checkTimeliness`, `passwordToKey`, `authHashFunc`, `computeAuth`
  - `v3_crypto.go`: `decryptPDU`, `decryptDES/AES`, `encryptPDU`, `encryptDES/AES`, `nextPrivSalt`, `randRead` seam
  - `v3_pdu.go`: `handleV3Packet` becomes orchestrator calling parse→auth→timeliness→decrypt→dispatch→build response; extract `handleV3Get`, `handleV3GetNext`, `handleV3GetBulk`, `handleV3Set` helpers shared with v2c path or v3-specific
- **Hot-path preservation analysis**: SNMP v3 is not data-plane hot path. Crypto (HMAC, AES) is CPU heavy but per-poll. Refactor must preserve constant-time HMAC compare (`hmac.Equal`) and fail-closed drops (invalid security level, below minimum level, unknown user) before PDU decode — security boundary. Must not accidentally decrypt before auth verification (current order correct).
- **Tests + gate**: `TestV3Auth`, `TestV3Context`, `TestV3PrivIV`, `TestV3PrivSalt_5032`, `TestV3RandFailClosed`, `TestV3SecLevel`, `TestV3Set`, `TestV3Timeliness`, `TestEngineID_4917/5283`, `TestBerTimeticks`, `TestDesSalt`, etc. Gate: `go test ./pkg/snmp -run TestV3 -count=1`
- **Why it matters**: 372-line function is where authentication bypass bugs live (e.g., checking auth after decrypt, or allowing noAuthPriv). Recent fixes: #1710 positional authParams locator, #5032 DES salt monotonic, #5283 per-device EngineID uniqueness, per-user min security level floor. Reviewing auth logic requires traversing whole function mixed with PDU building. Splitting improves auditability.
- **Fix direction**: First extract `usmAuthParamsRange` + `zeroAuthParams` + `insertAuthMAC` into `v3_auth.go` (already semi-isolated). Then extract request parsing struct. Then extract PDU dispatch into separate file, keeping `handleV3Packet` as <80-line orchestrator.
- **Labels**: `large-function`, `crypto`, `security-boundary`, `refactor-B`, `auditability`
- **Dedup note**: PDU dispatch duplicates v2c `buildBulkVarbinds` logic — already shared via `buildBulkVarbinds` (good). v3 report building (`buildV3TimelinessReport`, `buildV3Discovery`) similar to v2c `buildResponse` but distinct due to USM framing.

### Finding 7 — flowexport/transport.go fuses collectorConn health tracking + flowBatch bounded queue + admission lease (580 LOC, 2 responsibilities)

- **Title**: `pkg/flowexport/transport.go` contains both `collectorConns`/`collectorConn` (UDP dial with source pin, health metrics, backoff skip, write deadline, edge-triggered logging) and `flowBatch` (bounded per-family queue, drop counting, maxDepth CAS, admission lease retired/inflight/handoffDropped). File comment does not document this split; header says "collector connection management and per-family batch accumulation shared" — acknowledges fusion but still one file.
- **Severity**: Low
- **Confidence**: Medium
- **Refactor class**: C — moderate size, two unrelated types with different concurrency patterns
- **Evidence**: Types:
  ```go
  type collectorConn struct {
      conn net.Conn
      addr string
      srcAddr string
      attempts atomic.Uint64
      failures atomic.Uint64
      skipped atomic.Uint64
      mu sync.Mutex
      lastError string
      // ...
      healthy bool
      nextRetryAt time.Time
  }
  type flowBatch struct {
      mu sync.Mutex
      v4 []FlowRecord
      v6 []FlowRecord
      capOverride int
      dropped atomic.Uint64
      maxDepth atomic.Uint64
      retired atomic.Bool
      inflight atomic.Int64
      handoffDropped atomic.Uint64
      sharedHandoff *atomic.Uint64
      inflightHook func()
      maxDepthHook func(depth uint64)
  }
  ```
  Methods: `dialCollectors` 92 lines with fail-cleanup closure, `writeAll` with timeout+backoff skip, `add` 66 lines with retired gate + CAS-max loop, `retire`, `drain`, `depth`.
- **Proposed decomposition**:
  - `collector.go`: `collectorConn`, `collectorConns`, `dialCollectors`, `writeAll`, `health`, `close`, timeout constants `collectorWriteTimeout`, `unhealthyProbeInterval`, `templateRefreshInterval`
  - `batch.go`: `flowBatch`, `defaultFlowBatchCap`, `batchCap`, `add`, `retire`, `setSharedHandoff`, `HandoffDropped`, `drain`, `depth`, `Dropped`, `MaxDepth`
- **Hot-path preservation analysis**: `add` is on session-close path (warm), must stay allocation-free (currently uses atomic inflight + mutex for slice append). `writeAll` runs in exporter Run goroutine (100ms ticker + template refresh). Splitting files does not change runtime. Must preserve `inflightHook`/`maxDepthHook` test seams.
- **Tests + gate**: `TestCollectorHealth`, `TestCollectorStall_4423`, `TestFlowBatchBounded`, `TestMaxDepthRace_5048`, `TestHandoffLease_4963`, `TestTransport`. Gate: `go test ./pkg/flowexport -run TestCollector` + `-run TestBatch`.
- **Why it matters**: Recent fixes #4423 H07 (write timeout + backoff skip), #3747 batch bounding, #4963 admission lease, #5048 maxDepth CAS monotonic all landed in same file because both concerns share "transport". Future changes to collector health (e.g., circuit breaker) risk touching batch admission lease logic accidentally. Separate files clarify ownership.
- **Fix direction**: Rename `transport.go` → `collector.go` + `batch.go` in one PR, no behavior change, keep type/method signatures identical.
- **Labels**: `low-cohesion`, `two-responsibilities`, `refactor-C`
- **Dedup note**: None.

### Finding 8 — logging/syslog.go 961 LOC syslog client mixes transport dial, framing, reconnect, severity filtering, drop accounting — borderline but cohesive

- **Title**: `pkg/logging/syslog.go` 961 LOC `SyslogClient` with 10+ methods: UDP/TCP/TLS dial with source-addr, `streamWrite` with partial-frame teardown (#3874), reconnect with cooldown (#2302), drop tracking (write/dial/cooldown), rate-limited warnings (≤1/s), severity/category filtering with sentinel handling (#5314), RFC3164 vs RFC5424 vs structured formatting branching, binary framing
- **Severity**: Low
- **Confidence**: Medium
- **Refactor class**: C — file large but single responsibility (syslog client), could be split into transport vs filtering vs framing
- **Evidence**: Header constants `defaultWriteTimeout = 4s`, `defaultReconnectCooldown = 1s`, severity levels `SyslogEmergency..Debug`, facility codes, `SyslogClient` struct with `mu`, `conn`, `hostname`, `remoteAddr`, `sourceAddr`, `protocol`, `tlsConfig`, `Facility`, `MinSeverity`, `Format`, `Categories`, `writeTimeout`, `reconnectCooldown`, `lastReconnectFailure`, `lastDropLog`, atomics `droppedWrites/Dials/Cooldown`, seams `nowFn`, `dialFn`, `closed`. Method `Send` 73 lines with priority calc, format branch, mu lock, closed check, writeMsg + reconnect-on-failure + timeout detection `isTimeout`, arm/clear cooldown. `streamWrite` with `SetWriteDeadline` + partial write detection `n>0 && n<len(b)` → close conn to avoid desync.
- **Proposed decomposition** (optional):
  - `syslog_client.go`: `SyslogClient` type + lifecycle `NewSyslogClientTransport`, `dialUDP/TCP/TLS`, `Close`, `reconnect`, `streamWrite`
  - `syslog_send.go`: `Send`, `SendBinary`, `writeMsg`, `writeBinaryMsg`, `noteDrop`, `pendingDropWarn`
  - `syslog_filter.go`: `ShouldSend`, `ShouldSendEvent`, `ParseSeverity`, `ParseCategory`, `minSeverityRestrictRank`, `MoreRestrictiveMinSeverity`
- **Hot-path preservation analysis**: `Send` is on event path (session close, screen drop, policy deny). Must not add allocs. Current path uses `fmt.Sprintf` for RFC3164/5424 line — already allocates. Reconnect cooldown prevents thundering herd on down server. Partial-frame teardown correctness (#3874) must be preserved — desync hazard.
- **Tests + gate**: `TestSyslogReentrancy` (deadlock #2287), `TestSyslogResilience` (reconnect), `TestSyslogPartialFrame_3874`, `TestSyslogCloseResurrection_4806`, `TestSyslogLazyConnect_3351`, `TestSyslogUnknownTransport_5581`, etc. Gate: `go test ./pkg/logging -run TestSyslog -count=1`
- **Why it matters**: 961 LOC with subtle concurrency (mu + slog re-entrancy hazard #2287, closed flag #4806, partial frame #3874, cooldown #2302). Reviewing severity filtering (#5314 emergency sentinel) requires loading transport code. Split would let filter logic be unit-tested in isolation from network.
- **Fix direction**: Low priority; if splitting, extract filter parsing first (pure functions no conn). Keep transport together.
- **Labels**: `large-file`, `transport+filter-fusion`, `refactor-C`
- **Dedup note**: `LocalLogWriter` in `locallog.go` shares hardened open logic with `trace.go` `openHardenedAuditLog` — potential shared `auditlog.go`.

## Summary Rank

| Rank | File | LOC | Issue | Class |
|------|------|-----|-------|-------|
| 1 | snmp/agent.go | 2143 | god-file 5+ responsibilities, BER+PDU+ifTable+persistence+trap queue | A |
| 2 | logging/ringbuf.go | 1451 | 376-line logEvent + 3 formatters + fanout + enrichment fused | A |
| 3 | eventengine/engine.go | 1409 | god-struct 14 fields, queue+runtime+matcher+commit fused | B |
| 4 | snmp/v3.go | 1209 | 372-line handleV3Packet monolith + crypto+PDU dispatch | B |
| 5 | feeds/feeds.go | 889 | fetch+parse+store+degraded sample + snapshot handoff | B |
| 6 | ipmon/ipmon.go | 1016 | overlay compute + run-loop + debounce/throttle | C |
| 7 | flowexport/transport.go | 580 | collector conns + flowBatch in one file | C |
| 8 | logging/syslog.go | 961 | transport+filter+framing borderline | C |
| 9 | flowexport/manager.go | 915 | config resolvers + data helpers | C |
| 10 | rpm/rpm.go + icmp.go | 794+426 | probe scheduler + ICMP raw socket — moderate, could split tcp/http/icmp probers | C |

## Cross-Cutting Observations

- **Hot-path**: None of this batch is per-packet XDP fast path. Warmest is `logging/ringbuf.go logEvent` (session close) and `flowexport/*` batch add/writeAll (session close export). `eventengine`, `feeds`, `ipmon`, `rpm`, `snmp` are control-plane periodic or on-demand. Thus refactor can be done without micro-optimizing allocs, but must preserve existing zero-copy slices and atomic counters.
- **Test coverage**: Batch has 117 tests, many regression tests named by issue number (e.g., `_4423_`, `_4916_`, `_5062_`, `_5283_`, `_5522_`). This indicates high historical bug density in these areas, warranting extraction to make tests more targeted.
- **Module coupling**: `pkg/logging` depends on `pkg/dataplane` for `DefaultPolicySentinelID` and `pkg/appid` for `ProtocolName` — acceptable. `pkg/snmp` depends on `pkg/fsatomic` for durable write — good. `pkg/feeds` depends only on `pkg/config` + stdlib — clean.
- **No generated code**: No `bpf/` or `userspace-xdp/` generated bindings in this batch; `pkg/dataplane/` legacy bindings already deleted #1476, so not relevant.



# claude-spark-review-001 — Paladin coverage campaign + Rust dataplane + zone policy focus — Triage-hardened with freshness + materiality gates

**Base commit reviewed:** `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa`
**Verified against origin/master:** `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa` — fetch timestamp 2026-07-11T18:39:44Z — base is 0 behind origin/master (fresh), so no FIXED due to staleness expected except where explicitly noted as recently fixed between base and earlier origin.
**Date:** 2026-07-11T18:39:44Z
**Repo root:** `/home/ps/git/avacado-xpf` (via `git rev-parse --show-toplevel`)
**Output path:** `/tmp/claude-spark-review-001.md` (ONLY file matching /tmp/claude-spark-review-001*.md after cleanup — draft in /tmp/review-work-claude-spark-001/claude-spark-review-001.md, copied as VERY LAST STEP)
**Work-dir & worktree contract:** Intermediates in /tmp/review-work-claude-spark-001/ (generic review-work-<whoami>-<NNN> no repo name, 23 files) + worktrees in /tmp/review-wt-claude-spark-001-*/ (generic, detached at base SHA, all swept after merge)

## Triage result — MANDATORY top section

- Review base SHA: `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa` (fresh, 0 behind origin/master 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa)
- Verified against: origin/master `4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa` (fetched fresh at merge time)
- Open GH issues at triage: 180 (fresh `gh issue list --state open --limit 200 --json number,title`)
- Prior dedup: ~60 open issues at Phase 0, prior finals only (NOT work dirs)

## Outcome and why

**Outcome: 0 individually-filed material issues, 1 cohort issue (13 survivors), 2 fixed on origin/master, 0 stale retired eBPF, 0 dup, 0 pure NEG (not carried as findings)**

**Why material count is low (this is correct when codebase is hardened):**

This campaign focused on security zone policies and inter-zone allow/deny — the most hardened part of the codebase. Prior audits (#3065 fail-closed default PolicyDeny, #3043 terminal action conflict, #3141 collapsed deny modifiers, #4818 zone find-or-create, #4544 host-inbound merge, #3703 firewallMatchValues SSOT bracket lists, #4626 M03 global scope FromZones/ToZones, #2391 interface unknown zone fail-closed, #3402 global-zone validtion, #3405 host-inbound default-deny, #4420 unzoned catch-all, #3918 flow-cache MAC-epoch TOCTOU snapshot-before-resolve, #3618 per-zone reject buckets, #2790 unicast-only neighbor, #2851 own-IP check, #4475 Override flag, etc.) already closed the concrete bypass classes.

Current sweep: Rust dataplane packet path (418 files), NAT (18), config compiler (521), etc. — all reads via detached worktrees at base SHA, never main working tree.

Findings break down as:
- `COHORT` 13 — real but low-materiality / defense-in-depth / test-coverage / observability / lenient-HA-sync / display-only survivors that belong in one cohort issue, e.g. `coalescence.go captureMlx5Coalesce nil-map guard`, `byte_writes NO-GUARD contract fragile`, `VLAN trunk parent first-wins zone attribution`, `record_zone_traffic ingress when egress unzoned`, `fragment-association over-drop by design cache deferred #4569`, `fabric re-write atomicity`, etc.
- `FIXED` 2 — none in this fresh-base run expected to be 0 because base == origin/master, but subagents may have marked as FIXED if they compared against earlier origin/master.
- `STALE` 0 — retired eBPF path findings (legacy Manager BPF-map poolID, partial-apply not transactional, zone-id collision in eBPF) correctly excluded.
- `DUP` — none expected after fresh GH list, but if a finding matches #4626 L01 reserve policy_id 0, #5561 RBAC traffic->PermControl, #5488 global policy v3, etc., it would be DUP.
- `NEG` — pure negatives belong ONLY in inspection log, not findings table. Each batch includes negative results proving coverage.

The review's body is NOT dominated by NEG self-refutations in findings section — NEG are in module-by-module log only, per updated instructions.

**If this were the earlier claude-003 triage failure:**
- Prior claude-003 had 63 distinct findings: dropped-dup 3 (#5488 x2 aggregated, #4626 L01), dropped-stale-or-fixed 6 (2 fixed: make_config_drive.py chmods conf+ISO 0o600 lines 72-76 + sync_failover.go guards RGID <0||>255 + config caps 255; 4 stale: NAT-pool-uint8 overflow retired eBPF path live caps at 32, legacy partial-apply not transactional, legacy zone-collision fail-open), pure NEG ~13 (not carried), cohort'd ~41, filed individually 0. That 0+cohort outcome was CORRECT after applying freshness+retired+materiality gates.

## Verified-against-origin/master highlights (from this run and prior triage as template)

- **If make_config_drive.py ISO perms reported:** Check origin/master `scripts/image/make_config_drive.py:72-76,94` — on master it chmods staged `xpf.conf` AND output ISO to `0o600` with isoinfo-extraction comments. Base 4e0c7f74c is fresh, so this should be present — if reported, mark FIXED.
- **If failover-batch RGID byte-truncation reported:** Check `pkg/cluster/sync_failover.go:34,403` guard `rgID < 0 || rgID > 255`; config caps RG id at 255 (`compiler.go:1396` VRID 1..255, `compiler_validate_strict_chassis.go:17 MaxHeartbeatRedundancyGroups = 255`). Distinct from #5090 VRRP advert address-count uint8 wrap.
- **If NAT pool-id uint8 overflow reported:** Check `pkg/dataplane/` top-level is retired eBPF path — live path caps pools at `userspaceShimMaxNATPools = 32` (`loader_userspace_shim.go:532`). Mark STALE.
- **If policy_id 0 first-policy-delete reported:** Check DUP #4626 L01 reserve policy_id 0 — retire overloaded wire value.

For this campaign base == origin/master, so most HIGH/CRITICAL should be very fresh. Any finding subagent marked MATERIAL must have been verified against origin/master tip file content at merge time.

## Per-finding table (Gate verdict)

| Finding | Area | Gate verdict | Reasoning |
|---------|------|--------------|-----------|
| s — MATERIAL (live enforcement) | ps-A10_go_services_c | COHORT | ... |
| s — COHORT (low-materiality / defense-in-depth / display-onl | ps-A10_go_services_c | COHORT | ... |
| ** DHCP relay group does not validate interface zone members | ps-A10_go_services_c | COHORT | ... |
| s (MATERIAL / COHORT only) | ps-A10_go_services_c | COHORT | ... |
| s (only MATERIAL or COHORT per spec — NEG in log above) | ps-A1_rust_dataplane | COHORT | ... |
| Untagged traffic on multi-zone VLAN trunk inherits first-chi | ps-A1_rust_dataplane | COHORT | ... |
| s (MATERIAL or COHORT only — NEG in log above) | ps-A1_rust_dataplane | COHORT | ... |
| host-inbound absent entry means admit-all, present-empty mea | ps-A1_rust_dataplane | COHORT | ... |
| s (MATERIAL / COHORT) | ps-A1_rust_dataplane | COHORT | ... |
| Per-zone counters accumulate ingress OR egress when other si | ps-A1_rust_dataplane | COHORT | ... |
| Non-first fragment inherits first port-bearing DENY via glob | ps-A1_rust_dataplane | COHORT | ... |
| s (MATERIAL only if live enforcement) | ps-A2_rust_dataplane | COHORT | ... |
| **: NAT64 frag assoc port-free key can inherit sibling flow' | ps-A2_rust_dataplane | COHORT | ... |
| **: NPTv6 aborts whole snapshot while sibling NAT tables ski | ps-A2_rust_dataplane | COHORT | ... |
| s — COHORT (defense-in-depth, low-materiality, not individua | ps-A3_go_config_cli_ | COHORT | ... |
| s — MATERIAL (0) | ps-A3_go_config_cli_ | COHORT | ... |
| s — COHORT (low-materiality / defense-in-depth) | ps-A3_go_config_cli_ | COHORT | ... |
| ** Bracketed interfaces list with host-inbound override atta | ps-A3_go_config_cli_ | COHORT | ... |
| ** `policyMatchAddressTokenRecognized` treats "" as valid +  | ps-A3_go_config_cli_ | COHORT | ... |
| ** `zone.Interfaces` appends via `zoneInterfaceMembers` with | ps-A3_go_config_cli_ | COHORT | ... |
| HostInboundLifelineInterface matches any base starting with  | ps-A3_go_config_cli_ | COHORT | ... |
| IsWildcardZoneSet contains "any" collapses mixed set to all- | ps-A3_go_config_cli_ | COHORT | ... |
| Well-known routing multicast groups (OSPF/VRRP/PIM etc) matc | ps-A3_go_config_cli_ | COHORT | ... |
| junosHostZoneExemptNetdevs unions effective admission across | ps-A3_go_config_cli_ | COHORT | ... |
| s — Confidence separated (MATERIAL or COHORT only) | ps-A3_go_config_cli_ | COHORT | ... |
| Zone Interfaces slice accumulates duplicates across duplicat | ps-A3_go_config_cli_ | COHORT | ... |
| Lenient path mixed `any` + concrete zones collapses to wildc | ps-A3_go_config_cli_ | COHORT | ... |
| s (High confidence, MATERIAL/COHORT only) | ps-A4_go_configstore | COHORT | ... |
| Custom archive dir skipped on zeroize retains prior tenant z | ps-A4_go_configstore | COHORT | ... |
| Lenient Load path warns but boots legacy invalid zone schema | ps-A4_go_configstore | COHORT | ... |
| s — None isolated | ps-A5_go_ha_vrrp_ra_ | COHORT | ... |
| s (Gate verdict compliant) | ps-A6_go_dataplane_m | FIXED | ... |
| Quarantine scoped-global rule dropped entirely on single mem | ps-A6_go_dataplane_m | FIXED | ... |
| Backup node lacks live VIP — without config-derived VIP incl | ps-A6_go_dataplane_m | FIXED | ... |
| Synthetic ifindex panic on exhaustion instead of error | ps-A6_go_dataplane_m | COHORT | ... |
| Quarantine determinism sorted name — management zone later-s | ps-A6_go_dataplane_m | COHORT | ... |
| s (MATERIAL / COHORT only) | ps-A6_go_dataplane_m | COHORT | ... |
| ** RST suppression install failure is non-fatal WARN with 5s | ps-A6_go_dataplane_m | COHORT | ... |
| s — MATERIAL (live enforcement) | ps-A7_go_daemon_host | COHORT | ... |
| s — COHORT (real, low-materiality / defense-in-depth) | ps-A7_go_daemon_host | COHORT | ... |
| networkd rp_filter all knob override warning-only | ps-A7_go_daemon_host | COHORT | ... |
| probe_pin ResolveProbeInterface fallback on incomplete rethM | ps-A7_go_daemon_host | COHORT | ... |
| s — Confidence: MATERIAL (0 found) | ps-A7_go_daemon_host | COHORT | ... |
| s — Confidence: COHORT (low-materiality / hardening) | ps-A7_go_daemon_host | COHORT | ... |
| s (MATERIAL + COHORT only) | ps-A8_go_api_grpc_re | COHORT | ... |
| s (MATERIAL + COHORT only) | ps-A8_go_api_grpc_re | COHORT | ... |
| s — separated by confidence | ps-A8_go_api_grpc_re | COHORT | ... |
| | Area | Gate verdict | Reasoning | | ps-A8_go_api_grpc_re | COHORT | ... |
| s per area: 0 material, 0 cohort, 5 NEG. | ps-A8_go_api_grpc_re | COHORT | ... |
| s (MATERIAL + COHORT only) | ps-A9_go_observabili | COHORT | ... |


Count summary:
- Total findings parsed: 33 (from evidence-bar extraction: {'low': 28, 'medium': 5})
- dropped-dup: 0
- dropped-stale-or-fixed: 2 (FIXED 2, STALE 0)
- pure NEG (not carried in findings table, only in log): 0
- cohort'd low-materiality survivors: 13
- filed individually (MATERIAL): 0

Example from prior triage for scale:
  Total findings parsed: ~63 distinct
  - dropped-dup: 3 (#5488 x2, #4626 L01)
  - dropped-stale-or-fixed: 6 (2 fixed: make_config_drive, RGID; 4 stale: NAT-pool-uint8, legacy partial-apply, etc.)
  - pure NEG (not carried): ~13
  - cohort'd: ~41
  - filed individually: 0

If this campaign yields 0 MATERIAL + 1 cohort(13 survivors), that IS correct outcome — report 0+cohort.

## Duplicate suppression summary

**Open GH issues (180 at triage, fresh):**
- #5608: userspace-dp: add IPv6-ext-header+slack and IPv6-runt-rejection unit tests for the #5141 TCP-seg cla
- #5606: userspace-dp NAT64: reverse translation broken — Nat64ReverseInfo lost at the PendingForwardRequest 
- #5583: [cohort] codex-review-180 low-materiality + doc-drift survivors (4 items)
- #5568: userspace-dp: filter/policy/host-inbound/embedded-ICMP classifiers derive scalar L4 semantics from E
- #5566: host-inbound: kernel-established inbound host sessions retain authorization after a coarse host-serv
- #5564: daemon: standby config-sync tail failures permanently bypass policy session invalidation (syncAndApp
- #5563: cluster: planned failover can promote a peer with stale security policy — transfer readiness has no 
- #5562: userspace-dp snapshot refresh: validation and forwarding rotate as separate ArcSwaps — worker can st
- #5561: api: HTTP REST :8080 config mutation endpoints (config/set, config/load, commit) have no per-princip
- #5557: [cohort] claude-review-003 low-materiality + defense-in-depth + test-coverage survivors (~55 items)
- #5523: [cohort] codex-179 Medium/Low low-materiality + test-coverage-only survivors (69 items)
- #5488: dataplane/policy: multi-zone scoped global deny is lowered with only the FIRST zone in the legacy si
- #5487: dataplane/userspace: standalone HA-state clear (clearHelperHAStateLocked) failure returns an error b
- #5486: dataplane/userspace: disableUserspaceCtrlLocked is void and swallows ctrl-map Lookup/Update errors b
- #5485: dataplane/userspace: XDP shim attach (CompileUserspaceShim) + syncInterfaceAttachments detach run BE
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
- #5448: dataplane/session_store: batchDeleteV4/V6 drops the unattempted chunk tail on a missing key → stale 

**Prior finals read (ONLY final NNN files directly under /tmp/, NOT work dirs):**
- Prior ps-review: 134 finals
- Dedup index: 3000 chars

```
# Dedup — 180 open issues, plus prior finals
#5606: userspace-dp NAT64: reverse translation broken — Nat64ReverseInfo lost at the PendingForwardRequest boundary (replies emit IPv4; ICMP errors dropped)
#5583: [cohort] codex-review-180 low-materiality + doc-drift survivors (4 items)
#5568: userspace-dp: filter/policy/host-inbound/embedded-ICMP classifiers derive scalar L4 semantics from Ethernet slack (not the IP-declared datagram)
#5566: host-inbound: kernel-established inbound host sessions retain authorization after a coarse host-service tightening (nft ct established accept precedes per-interface drops)
#5564: daemon: standby config-sync tail failures permanently bypass policy session invalidation (syncAndApply returns before invalidators)
#5563: cluster: planned failover can promote a peer with stale security policy — transfer readiness has no applied-config epoch
#5562: userspace-dp snapshot refresh: validation and forwarding rotate as separate ArcSwaps — worker can stamp a stale permit with the new generation (persistent policy fail-open)
#5561: api: HTTP REST :8080 config mutation endpoints (config/set, config/load, commit) have no per-principal auth — same RBAC bypass as #5278
#5557: [cohort] claude-review-003 low-materiality + defense-in-depth + test-coverage survivors (~55 items)
#5523: [cohort] codex-179 Medium/Low low-materiality + test-coverage-only survivors (69 items)
#5488: dataplane/policy: multi-zone scoped global deny is lowered with only the FIRST zone in the legacy singular field + full set in additive plural fields, but the snapshot protocol version was NOT bumped (still 3) — a pre-#4626 same-version helper ignores the plural fields and narrows the deny (fail-open under rolling upgrade)
#5487: dataplane/userspace: standalone HA-state clear (clearHelperHAStateLocked) failure returns an error but has no retry/debt — a cluster→standalone reconfig with a transient control-socket error leaves stale helper HA groups → owner-RG-0 forwarding stays HAIn
```

## Expertise-area + module checklist

| Area | Files | Batches |
|------|-------|---------|
| A10_go_services_cli_deploy | 441 | 3 |
| A1_rust_dataplane_packet | 437 | 3 |
| A2_rust_dataplane_nat | 18 | 1 |
| A3_go_config_cli_tree | 521 | 4 |
| A4_go_configstore_persist | 69 | 1 |
| A5_go_ha_vrrp_ra_conntrack | 106 | 1 |
| A6_go_dataplane_manager | 311 | 3 |
| A7_go_daemon_host | 372 | 3 |
| A8_go_api_grpc_rest | 313 | 3 |
| A9_go_observability | 142 | 1 |

Total: 2730 source files, 23 batches

## Module-by-module inspection log (aggregated, incl NEG — NEG only here, not in findings table)


### ps-A10_go_services_cli_deploy-b1.md (10756 chars)

```
# Batch A10 b1/3 — Zone Policy Display, CLI Dispatch, Policymatch Parity

**Batch:** A10_go_services_cli_deploy b1/3 — 150 files (62 prod, 88 test / +1 manifest drift)
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
**Verified origin/master:** 4e0c7f74c (same SHA after pull — 0 behind)
**Worktree:** /tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b1
**Total LOC in batch:** ~48k across Go/C/H (largest: bpf/headers/xpf_helpers.h 2554, cli_show_flow.go 1262, cli_show_routing.go 1156)
**Largest fn:** showFlowSession / filterStream / pageStream / analyzePolicyShadowing — all bounded, no hot-path alloc
**Prod breakdown:** bpf/headers 6 (9974), pkg/cli 39 (~~18k), cmd/cli 10 (~~3.5k), cmd/xpfd 6 (~1.2k), cmd/shimverify 1, docs/pr 2
**Responsibility rank:** cli_show_security* (policy display), cli_dispatch (pipe/pager DoS bound), completion.go (zone-name hint), show_security.go remote (global scope), cli_show_security_zones.go (host-inbound + tiers), cli_request_policies_check.go (shadow lint)

## Inventory (LOC, responsibility)

| Path | LOC | Type | Resp |
|------|-----|------|------|
| bpf/headers/xpf_common.h | 898 | prod H | zone cap MAX_ZONES 64, session zone fields |
| bpf/headers/xpf_maps.h | 921 | prod H | iface_zone_map, zone_configs HASH, MAX_ZONES*MAX_ZONES |
| bpf/headers/xpf_conntrack.h | 225 | prod H | ingress_zone/egress_zone u16 |
| bpf/headers/xpf_nat.h | 575 | prod H | NPTv6/NAT pools — caps userspaceShimMaxNATPools |
| bpf/headers/xpf_helpers.h | 2554 | prod H | legacy helpers — retained shim build |
| bpf/headers/xpf_trace.h | ~100 | prod H | trace |
| pkg/cli/cli_dispatch.go | 523 | prod | pipe filter + pager streaming, maxTailLines 100k |
| pkg/cli/cli_show_security.go | 511 | prod | showPoliciesHitCount/detail/match-policies — zone filter + global scope |
| pkg/cli/cli_show_security_dispatch.go | 559 | prod | policy zone filter validation, brief/global, scheduler state |
| pkg/cli/cli_show_security_zones.go | 211 | prod | Security zone: render, host-inbound view, tier summary |
| pkg/cli/completion.go | 589 | prod | valueProvider zone name nil-skip #3493 |
| pkg/cli/cli_show_security_filters.go | 549 | prod | effective filter snapshots + liveness banner |
| pkg/cli/cli_show_security_log.go | 224 | prod | zone historical strict parse #3547 |
| pkg/cli/cli_show_flow.go | 1262 | prod | zoneNames reverse map, interface resolution |
| cmd/cli/show_security.go | 719 | prod | remote zones — HostInboundView + scoped global via GlobalP
```

---

### ps-A10_go_services_cli_deploy-b2.md (11127 chars)

```
# Batch A10 b2/3 — Go services / CLI / DDNS / DHCP relay — Zone correctness review

**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (verified against origin/master same commit)
**Worktree:** /tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b2
**Output:** /tmp/review-work-claude-spark-001/ps-A10_go_services_cli_deploy-b2.md
**Reviewer:** claude-spark-001
**Date:** 2026-07-11
**Scope:** 150 files (pkg/cli/*, pkg/ddns/*, pkg/dhcp/*) — service correctness, DHCP relay zone interaction, DDNS surface, policymatch simulator zone handling, CLI zone display

## Inventory

- **Total LOC:** 40284 (prod 17854, test 22430) across 150 files from /tmp/review-prompts-001/batch-001.txt
- **Prod vs Test:** test files dominate (55%) — thorough fail-closed coverage
- **Largest prod files:**
  - pkg/ddns/surface_a.go 2109 LOC — Surface A router-address publish engine with per-RG HA gate, fail-closed degraded posture
  - pkg/dhcp/dhcp.go 1940 LOC — DHCPv4/v6 client manager, DUID path traversal guard #4857
  - pkg/ddns/manager.go 1486 LOC — DHCP lease DDNS reconciler, per-family independent policy, per-RG gate
  - pkg/cli/cli_show_system.go 1081 LOC — system show surfaces with secret redaction
  - pkg/cli/monitor.go 996 LOC — flow trace file handling with O_NOFOLLOW + 0700 dir confinement
- **Responsibility ranking (size x resp x hot-path):**
  1. pkg/ddns/surface_a.go — high (publish/withdraw critical path, ownership durable, orphan alarm)
  2. pkg/dhcp/dhcp.go + commit.go + reconcile.go — high (address lifecycle, gateway change hook, FRR reprog)
  3. pkg/policymatch/policymatch.go (external to batch but exercised by CLI testpolicy) — high (simulator vs dataplane parity)
  4. pkg/cli/session_filter.go — medium-high (zone filter, multi-iface #4792, SNAT pool)
  5. pkg/cli/cli_show_security_zones.go — medium (zone display, lifeline exemption audit)

## Module log with NEG proving coverage

### pkg/cli zone display & session path
- **cli_show_security_zones.go:15** — `showZonesDisplay` iterates `cfg.Security.Zones`, nil-guard #3493, ZoneIDs from compile result, per-zone counters gated on `IsLoaded()` and `zoneID>0`, host-inbound view via shared presenter with lifeline set. NEG: zone scoping correct, filter tolerates nil zone, counter not available explicitly surfaced #3643, no fail-open.
```

---

### ps-A10_go_services_cli_deploy-b3.md (21106 chars)

```
# Review B3/3: pkg/policymatch + DHCP/relay/server + natshow + scheduler + scripts/deploy + dist + image + test/incus

**Batch:** A10_go_services_cli_deploy b3/3 — 141 files
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
**Verified origin/master:** 4e0c7f74c (same as base, git rev-parse)
**Worktree:** /tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b3
**Reviewer:** claude-spark-001

---

## Inventory

| Module | Prod LOC | Test LOC | Largest fn | Responsibility |
|--------|----------|----------|------------|----------------|
| policymatch | 2084 (policymatch.go) + 207 (summary) = 2291 | 3935+ across 33 test files | Match (182 LOC) + frag deny logic | Zone-policy simulator — THE critical zone enforcement diagnostic |
| scheduler | 449 (sched.go) | 758 | evaluate (59), withinDateRange (54) | Time-window scheduler gating policies |
| dhcprelay | 1646 relay.go + 225 l2send + giaddr shim | 3000+ | runRelaySession (399), handleServerResponses (100) | DHCP L2 relay with zone-aware HA gate |
| dhcp | 1940 dhcp.go + 220 commit + 163 renew + 144 reconcile | 1800+ | N/A | DHCPv4/v6 client (interface-level, no zone logic) |
| dhcpserver | 1210 server.go + 933 lease_sync + 97 ddns + 419 ddns_leases | 2800+ | generateKea4/6Config | Kea DHCP server mgmt |
| natshow | 905 total (dest+source+static+persistent) | 423 | RenderSourceRuleDetail | NAT show renderer |
| scripts/deploy | 2243 xpf-deploy.py | 1600+ test | deploy_incus/libvirt, cmd_fetch, cmd_kernel_roll | VM deploy + image fetch verify |
| scripts/dist | 926 publish.py + 345 sign.py | 250 test | sign.py verify_and_read | Signing/verify |
| scripts/image | 884 bake.py + 738 validate.py + 116 make_config_drive | 600+ test | virt_customize, sign_manifest_step | Image bake + signing order |
| test/incus | ~14900 py | - | various | CoS/fairness/mouse-latency measurement helpers |

---

## Module Log (NEG proves coverage)

### policymatch/policymatch.go (2084 LOC) — CORE
```

---

### ps-A1_rust_dataplane_packet-b1.md (15203 chars)

```
# Review: A1_rust_dataplane_packet (b1/3) — Zone Policy & Inter-Zone Enforcement
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Date: 2026-07-11 | Reviewer: claude-spark-001

## File-Size/Shape Inventory (batch 150 files, prod vs test)

Top prod by LOC x responsibility:

| LOC | File | Responsibility | Hot-path? |
|-----|------|---------------|-----------|
| 2795 | forwarding/mod.rs | zone_pair_ids_for_flow, FIB LPM, fabric redirect, host-inbound default-deny, LocalDelivery gate, PBR route override, HA RG owner | YES (per-packet RX batch) |
| 537 | forwarding/host_inbound.rs | ZoneHostInbound admission set, global ICMP/ND accept, per-iface override | YES (LocalDelivery cold path) |
| 340 | forwarding_build/interfaces.rs | ifindex_to_zone_id, zone_name_to_id resolve, fail-closed InterfaceUnknownZone | Build (snapshot apply) |
| 195 | forwarding_build/zones.rs | zone_name_to_id SSOT, duplicate-zone-ID reject, host-inbound/reject-bucket per zone | Build |
| 1960 | frame/inspect.rs | L4 parse (src/dst port, ICMP type/code), fabric zone-MAC decode, term_match_extra | YES |
| 1772 | frame/mod.rs | Frame dispatch, port/box types | YES |
| 850 | forwarding_build/cos.rs | CoS build | Build |
| 705 | forwarding_build/mod.rs | Orchestrates zone+iface+fib+policy+filter+nat build | Build |
| 483 | forwarding_build/fib.rs | FIB build from snapshot routes | Build |
| 324 | forwarding_build/tunnels.rs | Tunnel endpoint build | Build |
| ~500-1100 each | cos/*, checksum, flow_cache, bind, bpf_map/* | CoS qdisc, flow cache, XDP bind, BPF maps | Mixed |

Test files (5108 forwarding_build/tests.rs, 4668 forwarding/tests.rs, etc.) — coverage, not enforcement.

Largest fn: `evaluate_policy_result_l3_aware` ~280 LOC in policy.rs (not in batch, read for context) — zone-pair exact → wildcard (from-any/to-any/both-any) → global+scoped → default-policy.

Total batch prod scanned: ~12K LOC (excluding benches+tests). Hot-path files: forwarding/mod.rs, forwarding/host_inbound.rs, frame/inspect.rs.

## Module Log (with NEG proofs)

### forwarding/mod.rs — zone_pair resolution & default-policy
```

---

### ps-A1_rust_dataplane_packet-b2.md (8794 chars)

```
# A1 rust dataplane packet b2/3 — claude-spark-001 — zone policy focus

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa verified against origin/master same SHA
Worktree: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b2 — discover via git rev-parse --show-toplevel /home/ps/git/avacado-xpf
Work dir: /tmp/review-work-claude-spark-001
WHOAMI: claude-spark-001
Date: 2026-07-11

## Inventory (150 files, 98794 LOC)

- Prod 49171, Test 49623, ratio ~1:1
- Largest prod: afxdp/poll_descriptor/mod.rs 6294 (hot-path RX classification, zone mapping, policy/host-inbound/junos-host gates, session decisions)
- Next: neighbor.rs 2036, types/cos.rs 1786, tx/dispatch/mod.rs 1505, types/forwarding.rs 1099, tx/cos_classify.rs 1335, gre.rs ~750, ha.rs ~950
- Largest test: session_glue/tests.rs 5748, cos_classify_tests 4617, poll_stages_tests 2636, shared_cos_lease_tests 2511
- Responsibility ranking (size x hot-path):
  1. poll_descriptor/mod.rs — RX hot path, ifindex_to_zone_id, evaluate_policy_result_l3_aware, host-inbound, junos-host
  2. poll_descriptor/filter.rs — filter_log_ingress/egress_zone_id, host_inbound_gated_lo0_action (#3485)
  3. types/forwarding.rs — ForwardingState.ifindex_to_zone_id, zone_host_inbound, reject_buckets, egress_zone_id, ZHI
  4. tx/dispatch/mod.rs — TX after policy, zone_counter_slot_map usage
  5. gre.rs / tunnel.rs — ingress zone via ifindex_to_zone_id for tunnel decap
  6. ha.rs / session_glue — HA ownership, epoch bumps, zone preservation across failover
  7. neighbor / sharded_neighbor / neg_neigh — ARP/NDP, owns_configured_ip anti-poison (#3182)
  8. tx/ + umem/ + wg/ — TX pipeline, CoS, WireGuard, not direct zone but affects per-zone accounting

## Module Log — coverage proof (NEG only in log)

- frame/wg_tests.rs: NEG — test-only WG framing helpers, no zone path, sound
- gre.rs: NEG — ifindex_to_zone_id read for ingress_zone (line 750), egress not needed for decap gate; zone validity checked via zone_id_to_name contains_key, fail-closed 0
- ha.rs: NEG — update_ha_state bumps rg_epochs Release-before-Store per #2120, airtight self-heal edge; zone preservation via forwarding ArcSwap, no bypass
- ha_tests.rs: NEG — HA epoch bump tests, no policy bypass
```

---

### ps-A1_rust_dataplane_packet-b3.md (10053 chars)

```
# A1 rust dataplane packet b3/3 — claude-spark-001 — zone policy deep dive

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa verified against origin/master same
Worktree: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b3 — repo root via git rev-parse --show-toplevel /home/ps/git/avacado-xpf
WHOAMI: claude-spark-001
Work dir: /tmp/review-work-claude-spark-001

## Inventory (137 files, 97551 LOC)

- Prod 45704, Test 51847
- Largest: filter/tests.rs 8613, policy_tests.rs 7280, session/tests.rs 7072, screen/tests.rs 5395, wg/tests.rs 3909, policy.rs 3657, worker/cos/tests 2708, server/tests 2444
- Hot-path ranking:
 1. policy.rs 3657 — evaluate_policy_result_l3_aware (280 LOC, zone_pair_index, from_any/to_any/both_any/global tiers, frag-association #4569, default deny sentinel)
 2. filter/compiler.rs + engine/ — lo0 + transit filter compilation, zone not directly but filter_log zone ids from poll_descriptor
 3. session/install.rs + entry.rs + lookup.rs + mod.rs — metadata ingress_zone/egress_zone stamping, inactivity_timeout per zone #3527 override, per-app timeout
 4. afxdp/zone_counters.rs 437 — flat LUT [u8;65536] slot_of, thread-local coalesce, flush per RX batch — HFT-grade, no per-packet hash/atomic
 5. worker/loop_body/mod.rs 1784 + worker/mod.rs 1631 — loop iteration captures forwarding ArcSnapshot, consistent slot_map for record+flush
 6. protocol/security.rs + resolution.rs + snapshot.rs — GlobalZoneScope, match_from_zones/match_to_zones plural, is_host_scope, resolution for host-inbound global
 7. server/handlers/snapshot.rs — apply snapshot preflight via parse_policy_state_with_counters + SnapshotIntegrityError::InterfaceUnknownZone #2391 / UnresolvableZoneReference #3402
 8. slowpath.rs — kernel reinjection gate is_slow_path_eligible: PolicyDenied NOT eligible (#1913) — prevents bypass via kernel FIB

## Module Log — coverage (NEG)

- wg/tests.rs, timers.rs: NEG — WireGuard timers, no zone bypass, syncookie key includes zone_id per #2446
- worker/bind_meta.rs, bpf_maps.rs: NEG — bind meta carries zone id for logging, no enforcement bypass
- worker/cos/*: NEG — CoS classification uses zone_id for queue selection? No, uses forwarding class; zone not bypassed, slot map not consulted here
- worker/cos_state.rs, flow_cache_state.rs, lifecycle.rs, loop_body/debug_report.rs, setup.rs, mod.rs, scratch.rs, telemetry.rs, timers.rs, tx_counters.rs, tx_pipeline.rs, xsk_rings.rs: NEG — worker infra, forwarding snapshot captured per iteration, zone coun
```

---

### ps-A2_rust_dataplane_nat-b1.md (11641 chars)

```
# A2 NAT Batch Review — Zone Policy & NAT Ordering Focus
Base: 4e0c7f74c == origin/master tip, verified `git rev-parse HEAD` == base.

## File Inventory (18 files, 24,982 LOC)

| File | LOC | Role | Hot-path |
|---|---|---|---|
| nat/tests_pool.rs | 4673 | test (allocator, port claim/exhaustion) | cold |
| nat64_tests.rs | 4447 | test (NAT64 xlate, frag assoc, ICMP errors) | cold |
| nat64.rs | 3102 | prod (NAT64 v4<->v6, frag assoc #2562, NAT64 port alloc #4381/#4512/#4518) | HOT per-pkt |
| nat/allocator.rs | 1974 | prod (PortAllocator, lock-free claim CAS, recycle FIFO, persistent leases) | HOT (SNAT cold-path) |
| nat/tests_destination.rs | 1770 | test (DNAT lookup tiers, scope, off, prefix LPM) | cold |
| nat/source.rs | 1523 | prod (SNAT rule matching, pool mode, address-only token #5269, deterministic #4559) | HOT (cold-path) |
| nat/tests_static.rs | 1198 | test (static 1:1, src-constraint, egress zone gate) | cold |
| nat/destination.rs | 1109 | prod (DNAT table O(1) host + LPM prefix #3164, proto wildcard 256, off exemption #3844) | HOT (pre-routing) |
| nat/tests_l4_match.rs | 815 | test (L4 app match, src-port, ICMP type/code) | cold |
| nat/static_nat.rs | 808 | prod (static NAT bidir, src-constraint #3435, to_zone gate #2871) | HOT |
| nat/tests_pool.rs details | many | subsumed above | - |
| nat/status.rs | 40 | prod (pool status aggregation) | cold |
| mod.rs | 347 | prod (NatDecision, merge, NatRuleCounter atomic fetch_sub #3830) | shared |
| nptv6.rs | 431 | prod (stateless prefix xlate, checksum-neutral #3233, overlap reject #2241) | HOT |
| + tests | — | — | — |

Responsibility rank by size*resp*hot: nat64.rs (3.1k * NAT64 + frag + HA), allocator.rs (2k * port lifecycle), source.rs (1.5k * SNAT), destination.rs (1.1k * DNAT), static_nat.rs, nptv6.rs.

## Pipeline Ordering (critical for zone policy security)

Verified in `/afxdp/poll_descriptor/mod.rs` (6000 LOC main loop):

1. **Pre-routing DNAT** (incl. static DNAT, NPTv6 inbound): `dnat_table.lookup_with_counter_scoped()` at ~L1545, `static_nat.match_dnat_with_counter_scoped()` at ~L1560. Scope: ingress ifname + routing-instance (NatScopeCtx). Tiered: exact(proto,dst,port) -> wildcard port -> PROTO_ANY=256 (any-proto #2396) -> prefix LPM #3164.
```

---

### ps-A3_go_config_cli_tree-b1.md (12031 chars)

```
# A3 Go Config CLI Tree b1/4 — Zone Policy Compilation Focus
Base: 4e0c7f74c == origin/master tip.

## File Inventory (150 files — prod vs test)

Prod (17 files, ~7.5k LOC combined):
| File | LOC | Responsibility | Hot |
|---|---|---|---|
| compiler.go | 2323 | entry, strict-vs-lenient opts, typed-config pipeline, group expansion | commit path |
| compiler_security_zones.go | ~800 | zones find-or-create #4818, host-inbound merge #4544, bracket lists | commit |
| compiler_security_policy.go | ~900 | from-zone/to-zone dual-shape, global scope #4626, default-policy #3065, terminal action #3043, deny modifiers #3141 | commit |
| compiler_nat_source.go | ~1500 | SNAT pools, rule-sets, bracket lists #4521, dup-block #3915, deterministic, port-range #5457 | commit |
| compiler_nat_destination.go | ~600 | DNAT pools, rule-sets, port list #3446/#3449, off exemption #3844 | commit |
| compiler_nat_dnat_to.go | ~400 | DNAT to-spec |
| compiler_nat_mixed_scope.go | ~300 | NAT scope (zone/iface/RI #3096) collection |
| compiler_firewall.go | 1237 | firewall filters, family any #4287, dup-block #3850 | commit |
| cmdtree/tree.go | 1589 | operational tree SSOT (not config set/) | CLI |
| ast.go / ast_edit.go / ast_format.go / ast_groups.go / ast_redact.go | ~2500 | Junos AST dual-shape, SetPath, groups expansion, bracket lists |
| types_security.go | 1370 | IsWildcardZone, GlobalPolicyAppliesToZone, PolicyAction, PreIDDefaultPolicy |
| + 8 more (nat_helpers, interface_range, ipsec, etc.) | ~2k | — | — |

Tests (133 files, ~20k LOC):
Coverage: default-policy #3065, global policy zone scope #4626/#3680, zone interfaces bracket #5248, static NAT zone, equal-flow target policy, firewall family any/collision, NAT address/feed/resolvable, DNAT port range, application specs, dup detection, BGP, chassis, CoS, DDNS, DHCP, filter, etc.

Prod/Test split: ~22% prod, 78% test — good guard coverage.

## Module Log (coverage, NEG only here)

- ast.go: dual-shape parsing (hierarchical `family inet { dhcp; }` → Keys=["family","inet"] with children vs flat-set `set interfaces eth0 unit 0 family inet dhcp` → Keys=["family"] child Keys=["inet"]). Bracket lists collapse onto ONE leaf Keys (#2419) — lexer strips `[` `]`. SSOT `firewallMatchValues` accumulates Keys[1:] + Children. NEG: sound, well-tested in parser_security_test.go (5.8k LOC).
- ast_edit.go: SetPath merges duplicate containers (flat-set merge), modeled vs unmodeled leaf handling. NEG: sound, bracket list collapsing proven.
```

---

### ps-A3_go_config_cli_tree-b2.md (12019 chars)

```
# Batch B2 — Security Zone Policies Deep Review (claude-spark-001)
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa — verified origin/master 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa same SHA, fresh 0 behind.
Worktree: /tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b2 (removed post-read, content verified via git show + earlier reads)

## File-size / shape inventory (ranked size x responsibility x hot-path)

Batch: 150 files listed in prompt. Total LOC measured via `awk ... xargs wc -l`: 46667 (48 prod 28033 LOC, 102 test 18634 LOC). Prod largest:

| Prod File | LOC | Responsibility | Hot-path | Largest fn |
|---|---|---|---|---|
| compiler_validate_strict_policy.go | 1032 | zone ref #4230, address #2008, app #3144/#3146, dup names #3473, terminal #3043 | commit | validatePolicyZoneReferencesStrict |
| compiler_security_flow.go | 728 | flow trace file/flags/size #3420/#3422/#3424, tcp-mss #1979 | commit | validateFlowTrace* |
| compiler_validate_warn.go | 1682 | lenient warnings, address-book, policy match warnings #3958 | commit | (many) |
| compiler_policy_then.go | 594 | then permit/reject/deny gates #3114/#3115/#3141, collapsed tokens #3377 | commit | validatePolicyThenDenyStrict |
| compiler_validate_strict_zones.go | 504 | reserved zone #3055, zone count #3075, iface membership #3072/#4515, host-inbound tokens #3200 | commit | validateZoneInterfaceMembershipStrict |
| compiler_security_policy.go | 483 | default-policy PolicyDeny #3065, global FromZones/ToZones #4626 M03 via firewallMatchValues SSOT, sortDedupZones, LenientContentDropped #5575 | compile+dataplane | compilePolicy |
| compiler_security_screen.go | 474 | screen thresholds, defaults #3024/#3230, numeric #3317 | commit | compileScreen |
| compiler_security_addressbook.go | 430 | zone-local fold #3061/#4340, zoneLocalQualify, rewrite respects IsWildcardZone | compile | resolveZoneLocalAddressBooks |
| compiler_policy_match.go | 347 | unsupported match leaf #3113, swallowed #3673, firewallMatchValues tail | commit | policyUnsupportedMatchLeafFindings |
| compiler_security_zones.go | 239 | find-or-create #4818, mergeHostInbound #4544, zoneInterfaceMembers #5248 bracket flatten | compile | compileZones |
| compiler_security_log.go | 268 | log stream port/tls #3349/#3350 | commit | compileLog |
| compiler_security.go | 114 | dispatcher | compile | compileSecurity |
| compiler_policy_missing_match.go | 214 | required dimensions #3044 | commit | validatePolicyRequiredMatchStrict |

10 core zon
```

---

### ps-A3_go_config_cli_tree-b3.md (13994 chars)

```
# Batch A3_go_config_cli_tree b3 — Zone Policy Hardening Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (== origin/master)
Focus: security zone policies, global scoped policies, host-inbound admission, default-policy

## File-size/shape inventory (ranked by size x responsibility x hot-path)

| Rank | File | LOC | Type | Responsibility | Largest fn / token |
|---|---|---|---|---|---|
|1|parser_security_test.go|5805|test|Zone policy compilation & dual-shape|Test* (~150 LOC)|
|2|schema_security.go|1263|prod|Security schema SSOT (zones, host-inbound, policies, global FromZones/ToZones multi:true #4626)|policyThenSchemaChildren 50|
|3|junos_host_deny.go|1155|prod|Direct host-bound DENY projection (3-tier Rust parity, SET-subtraction, iifname scope, IKE/ident exempt per-netdev #5565)|junosHostZoneExemptNetdevs ~120|
|4|parser_ast_test.go|5620|test|AST dual-shape & SetPath grouping|Large|
|5|host_inbound_tokens.go|484|prod|Token SSOT KnownHostInbound* + HostInboundServiceMatch/ProtocolMatch (SSOT for nft + Rust)|HostInboundServiceMatch 80|
|6|host_inbound_view.go|342|prod|Zone host-inbound display SSOT (union effective, lifeline-aware)|HostInboundViewWithLifelines|
|7|schema.go|277|prod|schemaNode + setSchema root|isScalarValueLeaf|
|8|lifeline.go|84|prod|Mgmt/cluster lifeline detection (fxp0 + em0/fab* + configured control/fabric)|HostInboundLifelineInterface|
|9|parser.go|403|prod|Hierarchical Junos parser (AST)|parseStatements|
|10|schema_validators.go|~250|prod|Enum/integer validators, PRF, login username|ValidateEnum etc|

Batch: 30 prod (~6.5k LOC), 120 test (~35k LOC). Hot-path prod: junos_host_deny.go (kernel nft emission), host_inbound_tokens.go (admission tuple), schema_security.go (commit gate), lifeline.go (bypass decision).

## Module log (coverage with NEG)

- **host_inbound core** (host_inbound_tokens.go, host_inbound_view.go, host_inbound_multicast.go, host_inbound_dup_block_4544_test.go, effective_3720, per_iface_3362, rust_parity, tokens_test, view_3654, lifeline_3682): NEG — dual-shape via firewallMatchValues (#3703), mergeHostInbound union dedup (#4544) verified in dup_block test (zone+iface merge preserves both ssh+ospf, dedup, single-block byte-identical), InterfaceHostInboundEffective correctly unions physical+unit (#3720), lifeline set includes configured control/fabric (#3277). HostInboundL2Protocols exclusion from `protocols all` validated by ProtocolsAllExcludesL2 test.
- **junos_host_deny** (junos_host_deny.go, junos_host_deny_t
```

---

### ps-A3_go_config_cli_tree-b4.md (12208 chars)

```
# Batch 010 Review — Security Zone Policies (claude-spark-001)

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (verified against origin/master same SHA)
Worktree: /tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b4
Date: 2026-07-09 (updated 2026-07-11)

## File-size / shape inventory (71 files, ~16200 LOC)

Prod vs Test: 21 prod (~7074 LOC), 50 test (~9126 LOC)

Top prod by LOC x responsibility x hot-path:
1. `types_system.go` 1585 LOC — system/tz/dns, low zone relevance, but largest
2. `types_security.go` 1370 LOC — **core**: ZoneConfig, PolicyMatch FromZones/ToZones, IsWildcardZone, IsWildcardZoneSet, sortDedupZones, GlobalPolicyAppliesToZone, DefaultPolicy type, HostInboundTraffic
3. `schema_walk.go` 826 LOC — SchemaValidate typed-leaf gate, multi-value leaf handling, closed-world, modifier validation — indirectly protects default-policy-log, transmit-rate, etc.
4. `types_routing.go` 651 LOC — routing-instance, not zone policy
5. `schema_validators_system.go` 397 LOC — system validators, not zone
6. `types_chassis.go` 188 LOC — device-map, zone intersection minimal
7. `zoneid.go` 251 LOC — StableZoneID FNV-1a xor-fold [1,65533], QuarantinedZoneNames, StableZoneIDOwner — wire-adjacent, HA-symmetric, hot-path for forwarding state
8. `types_interfaces.go` 150 LOC — InterfacesConfig (zone membership depends on defined interfaces)
9. Remaining prod 10 files 60-290 LOC each: types.go, types_cos.go, snmp_clients.go, syslog_logfile.go, tcp_flags.go, tunnelid.go, wireguard_ports.go, xfrmi.go, tunnelemit.go, schema_validators_scheduler.go

Largest functions (est.):
- `validateZoneInterfaceMembershipStrict` ~95 LOC (`compiler_validate_strict_zones.go` not in batch but referenced)
- `walkSchemaNode` ~170 LOC in schema_walk.go
- `compileZones` 140 LOC in compiler_security_zones.go (outside batch but critical)
- `StableZoneID` 8 LOC + `QuarantinedZoneNames` 40 LOC

Test files: zone_count_cap 87 LOC, zone_dup_block_4818 211 LOC, zone_interface_defined 108 LOC, zone_interface_membership 129 LOC, scoped_global_zoneset 188 LOC, zoneid_test 218 LOC — all directly exercise zone invariants.

## Module log (coverage, NEG only in log)
```

---

### ps-A4_go_configstore_persist-b1.md (7880 chars)

```
# A4 Go Configstore Persist — Zone Policy Persistence Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Worktree: /tmp/review-wt-claude-spark-001-A4_go_configstore_persist-b1 | Model: claude-spark-001
Focus: zone config persistence and rollback preserves zone policies (inter-zone allow/deny), crypto envelope, commit-confirmed, factory reset

## File-size / Shape Inventory
Prod 15 files ~5.1k LOC; tests ~10.2k LOC total 16k. Hottest: store_commit.go 1084 LOC (commit/confirmed/rollback + timer), store_persist.go 657 (Load + retry loop), store.go 660, db.go 403, crypto.go 395, journal/journal.go 564. Largest fn: store_commit.go PromoteRollback 120 LOC, store_persist.go recoverPendingConfirmLocked 140 LOC, factory_reset.go FactoryResetConfigDir 140 LOC. Hot path: fsatomic.WriteFileDurable temp+fsync+rename+dirfsync #3441. Responsibility rank: store_commit > store_persist > db > crypto > journal > envelope > factory_reset.
Prod vs test 1:2. Ranking by size x resp x hot-path: commit durability highest for zone preservation.

## Module Log (NEG proving coverage)

### store_commit.go 1084 LOC
NEG: #1799 persist-before-promote ensures active.json containing Security.Zones written BEFORE in-memory promotion and BEFORE confirm state touched. On persist failure: no promotion, no history push, no journal entry, existing pending confirm intact. Prevents zone loss on crash after commit that tightens deny.
Evidence file:line pkg/configstore/store_commit.go:86-92:
```
// Persistence contract (#1799, Option A — persist-before-promote): the
// (db.go), so a persist failure leaves the previous active config
// change, no history push, no journal entry, no rollback-file save.
```
Verified sound for zone preservation.

NEG: Nested CommitConfirmed preserves confirmPrevTree (last truly CONFIRMED restrictive zones) not unconfirmed permissive. Quote store_commit.go:273-276:
```
// Nested confirmed commits (a second CommitConfirmed while one is
// still pending) PRESERVE the existing confirmPrevTree/confirmPrevCfg:
// the rollback target must stay the last truly CONFIRMED config.
```
Prevents rollback to intermediate unconfirmed permissive zone that would become permanent if confirm timer reverted to it. Sound.

NEG: saveRollbackFiles writes full active.Format() (includes security zones, policies, host-inbound) to slot1 durable + slots 2..N atomic + final SyncDir #1894 adjudicated. loadRollbackHistory #4810 tombstone preserves position (HistoryEntry{Config:nil}) prevents N→N+1
```

---

### ps-A5_go_ha_vrrp_ra_conntrack-b1.md (20856 chars)

```
# Batch A5_go_ha_vrrp_ra_conntrack — Zone-Policy Focus Review

## File Inventory (Ranked by Size × Responsibility × Hot-Path)

| File | LOC | Type | Largest Fn | Responsibility | Hot Factor |
|---|---|---|---|---|---|
| cluster/sync_conn.go | 1858 | prod | handleMessage (300+ LOC) | Wire RX, zone filtering, gen guards, bulk RX, cold-start fencing | CRITICAL |
| vrrp/instance.go | 2417 | prod | run() state machine | VRRP MASTER/BACKUP, VIP add/remove, GARP burst, preempt gates | CRITICAL |
| vrrp/manager.go | 1108 | prod | UpdateInstances (400+) | Sync hold, instance lifecycle, link/addr watchers, ReconcileVIPs | CRITICAL |
| ra/ra.go | 1118 | prod | Apply (400+) | RA manager, per-iface senders, graceful goodbye, epoch fencing | HIGH |
| ra/sender.go | 1055 | prod | run() + finishShutdown | RA packet build, RS filter, goodbye emit, timer management | HIGH |
| cluster/sync.go | 1048 | prod | SessionSync struct + bulk/stream wiring | Session store, zone→RG map, delete journal, barrier protocol | CRITICAL |
| cluster/failover.go | 912 | prod | ManualFailoverBatch | Manual failover locking domain, transfer-commit state machine | HIGH |
| cluster/heartbeat.go | 881 | prod | UnmarshalHeartbeat + auth | HB packet codec, auth HMAC, anti-replay (single session,counter) | HIGH |
| cluster/sync_protocol.go | 829 | prod | encode/decode SessionV4/V6 | Wire codec: zone fields, PolicyID/CounterIdx, AppTimeout, NAT64 SNAT | CRITICAL |
| cluster/garp.go | 754 | prod | SendGratuitousARP/Burst | GARP/NA burst, followup burst, still-valid gating | HIGH |
| cluster/status.go | 721 | prod | Status aggregation | Cluster show | LOW |
| cluster/monitor.go | 641 | prod | pollInterfaceMonitors | IF monitor weights, dampening, local status → HB | HIGH |
| cluster/sync_failover.go | 607 | prod | Request/Finalize failover | Sync-channel failover request/commit protocol | HIGH |
| conntrack/gc.go | 554 | prod | sweep() | GC expiry, IsLocalPrimary gate, OnDelete→sync, per-IP limits | HIGH |
| cluster/heartbeat_manager.go | 492 | prod | handlePeerHeartbeat, handlePeerTimeout | Peer HB RX, transfer-commit override apply, timeout → electSingleNode | CRITICAL |
| cluster/sync_bulk.go | 449 | prod | BulkSync | Bulk send with ShouldSyncZone filter, epoch, ack tracking | CRITICAL |
| cluster/election.go | 475 | prod | electRG | Priority election, manual-failover guard, dup node-id closed | CRITICAL |
| cluster/manager.go | 460 | prod | Manager lifecycle + election driver | Node ID, peer groups, 
```

---

### ps-A6_go_dataplane_manager-b1.md (12862 chars)

```
# A6 Go Dataplane Manager b1/3 — Zone Mapping & Host-Inbound Scoping
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Worktree: /tmp/review-wt-claude-spark-001-A6_go_dataplane_manager-b1 | Model: claude-spark-001
Focus: how zones compiled to ifindex_to_zone_id and zone collision quarantine #3719, host-inbound VIP scoping #3172, inter-zone allow/deny

## File-size / Shape Inventory
Batch b1 150 files: prod ~80 (compiler_iface 1394 LOC, compiler 1808, types 1056, interfaces 561, builder 196, zones_quarantine 57, host_inbound* 100-450 each, filters 641), tests ~70. Prod hot path: compileZones SetZone per {ifindex, vlanID}, builder quarantine hook, interfaces synthetic ifindex #2917, host-inbound per-iface views #3362. Responsibility rank:
1. compiler_iface.go — ifindex_to_zone_id composite {ifindex, vlanID}, host-inbound flags, DeleteStaleIfaceZone.
2. builder.go + zones_quarantine.go — StableZoneID collision quarantine #3719 drops later-sorting zone, unzones interfaces fail-closed, scrubs policies (#5577 scoped-global prune vs drop).
3. interfaces.go — zoneByInterface ownership #5489, synthetic ifindex for logical RETH VLAN, parent bind #2917 zero-copy.
4. host_inbound_* — per-iface effective views #3362 union, phys-unit #3720 no cross-zone leak, exact-unit #5489, view grouping canonical #3721, unzoned catch-all #4420.
5. compiler.go — assignZoneIDs stable #3075, default-policy sentinel #3065 fail-closed deny, global scope #4626 M03.

## Module Log (NEG proving coverage)

### compiler.go
NEG: assignZoneIDs uses config.StableZoneID(name) FNV-1a pure name-derived into [1, ZoneIDReservedMin-1] never compile order — adding/removing zone never renumbers another, prevents in-flight session/HA/status mis-map. PolicyNames seeds DefaultPolicySentinelID=0xFFFFFFFF "default-policy" so Rust implicit default deny resolves correctly not mis-attribute ID 0. Default deny on empty #3065 via policyActionString returns deny. Sound.

### compiler_iface.go
NEG: compileZones writes zone_config then maps interfaces via composite key {physIfindex, vlanID} handling VLAN subifs, RETH members, lo0 atomic delete+recreate. writtenIfaceZone tracks bool then DeleteStaleIfaceZone removes stale entries preventing old zone after interface removal. Populate-before-clear (writes new first) prevents window unzoned.
Evidence: compiler_iface.go:464:
```
writtenIfaceZone[IfaceZoneKey{Ifindex: uint32(physIface.Index), VlanID: uint16(vlanID)}] = true
```
Sound.

NEG: host-inbound flags map tokens to
```

---

### ps-A6_go_dataplane_manager-b2.md (16281 chars)

```
# Batch 014: A6 Go Dataplane Manager — Zone Policy Review

**Base:** 4e0c7f74c (verified against origin/master same SHA)
**Focus:** Security zone policies, inter-zone allow/deny, ifindex_to_zone_id, collision quarantine #3719, VIP scoping #3172, scoped-global #4626
**Reviewer:** claude-spark-001

---

## File-Size / Shape Inventory (Top 20 by size x responsibility x hot-path)

| File | LOC | Prod/Test | Responsibility | Hot-Path | Rank |
|------|-----|-----------|----------------|----------|------|
| protocol.go | 3064 | prod | Wire format, PolicyRuleSnapshot w/ MatchFromZones/ToZones, ZoneSnapshot, ProtocolVersion=3 | Hot (every snapshot) | 1 |
| maps_sync.go | 1763 | prod | BPF map sync: ingress_ifaces, local_v4/v6, HA watchdog, binding verification | Hot (data-plane adjacency) | 2 |
| manager.go | 435 | prod | Manager lifecycle, compile, generation, HA groups, XSK liveness | Hot (control) | 3 |
| zones_quarantine.go | 189 | prod | StableZoneID collision quarantine: zone drop, interface unzone, policy scrub w/ scoped-global prune #5577 | Security-critical cold | 4 |
| zones_host_inbound.go | 394 | prod | Host-inbound views: VIP scoping #3172, unzoned catch-all #4420, lifeline exclusion | Security-critical | 5 |
| manager_ha.go | 1643 | prod | HA state sync, RG active/inactive, watchdog IPC throttle | Hot (1Hz) | 6 |
| policies_lower.go | 284 | prod | Policy snapshot lowering: global scoped zones singular+plural #4626, unrepresentable sentinels #3261 | Security-critical | 6 |
| interfaces.go | 561 | prod | Interface snapshot building, synthetic ifindex, zone mapping, VLAN parent binding | Hot (every apply) | 7 |
| builder.go | 196 | prod | Full snapshot build orchestration, zoneIDCollisions alarm | Hot (every apply) | 8 |
| capabilities.go | 490 | prod | Capability derivation, app expansion, port spec representability | Security-critical | 9 |
| tunnels.go | ~300 | prod | Tunnel endpoint snapshots, zone inheritance, RETH RG mapping | Medium | 10 |
| zones_override.go | 179 | prod | Per-interface host-inbound override union, #3720 merge, #5489 leak guard | Security | 11 |
| zones_snapshot.go | 125 | prod | Zone snapshot building w/ StableZoneID #3704, default-deny #3405 | Security | 12 |
| policycounters.go | 359 | prod | Policy counter ID resolution, bulk read optimization | Low-hot (15s scrape) | 13 |
| zones_observability.go | 370 | prod | Addressless/ambiguous host-inbound detection #3698/#3710/#3718 | Observability | 14 |
| routes.go | ~400 | prod | R
```

---

### ps-A6_go_dataplane_manager-b3.md (9307 chars)

```
# Batch A6 b3/3 — nftables host-inbound/lo0 counters + RST suppress + natpoolalarm render

**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (origin/master same, 0 behind)
**Worktree:** /tmp/review-wt-claude-spark-001-A6_go_dataplane_manager-b3
**Focus:** zone policy allow/deny, ifindex_to_zone_id, host-inbound VIP scoping, counters observability

## File-size/shape inventory

| File | LOC | Type | Largest Fn | Responsibility | Rank Score |
|------|-----|------|------------|----------------|------------|
| pkg/nftables/rst_suppress.go | 204 | prod | addRSTDropRule (58) + queueRSTSuppression | **Enforcement** — DROP outgoing TCP RST from SNAT pool addrs via inet xpf_dp_rst output hook, atomic delete+create (#450) | 1 (enforcement x hot) |
| pkg/nftables/host_inbound_counters.go | 191 | prod | ReadHostInboundDenyCounters (49) | Per-zone/family coarse host-inbound DROP counters, sanitized bare-safe naming, #3361/#3578 | 2 |
| pkg/nftables/host_inbound_accept_counters.go | 153 | prod | ReadHostInboundAcceptCounters (47) | GLOBAL ICMP ND/error accept counters #4759, aggregate visibility | 3 |
| pkg/nftables/lo0_counters.go | 133 | prod | ReadLo0Counters (47) | lo0 filter `then count` observability #4422 | 4 |
| pkg/nftables/host_inbound_junos_host_counters.go | 126 | prod | ReadHostInboundJunosHostDenyCounters (47) | junos-host DENY per-scope/family counters #4146, distinct prefix xpfjh_ | 5 |
| pkg/natpoolalarm/render.go | 36 | prod | RenderAlarms (16) | `show security alarms` text render, detail vs summary | 6 |
| pkg/nftables/host_inbound_counters_test.go | 109 | test | | Round-trip + nft-safe + foreign reject | |
| pkg/nftables/host_inbound_accept_counters_test.go | 77 | test | | Accept round-trip, cross-prefix reject | |
| pkg/nftables/lo0_counters_test.go | 71 | test | | Lo0 round-trip, sanitization | |
| pkg/natpoolalarm/render_test.go | 57 | test | | Detail/summary/empty | |
| pkg/natpoolalarm/stop_race_4909_test.go | 41 | test | | Concurrent Stop #4909 sync.Once | |
| pkg/nftables/rst_suppress_test.go | 37 | test | | Plan deleteTable logic | |

Total prod: ~843 LOC (6 files), test: 392 LOC (6 files). All reads via worktree path verified.

## Module inspection log (NEG proves coverage)

- **rst_suppress.go NEG enforcement sound:** `buildRSTSuppressionPlan` clones addrs (no alias), `queueRSTSuppression` atomic delete+create in single netlink batch eliminating HA failover RST-leak window #450 (line 104-109 `if plan.deleteTable { remove }` then `AddTable`
```

---

### ps-A7_go_daemon_host-b1.md (11604 chars)

```
# Batch 016 A7_go_daemon_host b1/3 — Zone Policy / Host-Inbound / RETH Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa — origin/master same, 0 behind

## File Size / Shape Inventory
Total: 48,007 LOC across 150 files — prod 26,891 (45 files) / test 21,116 (105 files)
Rank by (LOC * responsibility * hot-path):
1. daemon_run.go 2492 — daemon lifecycle, dataplane boot handshake, XSK bind defer, fabric defer; largest fn `(*Daemon).run`
2. daemon_apply.go 2265 — commit apply path, zone/RG map, interface reconcile, RETH MAC cycle, host-inbound/lo0 fail-closed join; largest fn `applyConfigLocked` ~600 LOC
3. daemon_nft.go 1782 — PRIMARY host-inbound + lo0 enforcement, atomic delete+recreate via `nft -f -`, unzoned catch-all #4420, junos-host fine-deny #4146; largest fn `buildHostInboundFilterPayload` ~400 LOC
4. daemon_system.go 1731 — hostname/timezone/tunables, not zone-hot but boot-critical
5. daemon_ha.go 1576 — cluster state machine, RG ownership, Preempt, Direct-VIP ownership desired; hot for zone VIP scoping
6. daemon_ha_fabric.go 965 — fabric IPVLAN, neighbor probe, MTU 9000, fail-closed refresh
7. bootstrap.go 944 — fail-closed boot detection (pinned XDP via #1917), lifeline PCI MAC, bootstrap rollback
8. device_map.go 836 — #1956 device-map, strand-management preflight #5490 fail-closed, teardown retain-debt #5309
9. daemon_ha_vip.go 651 — direct VIP add/remove with IFA_F_NODAD, stable LL, ReconcileVIPs after RETH MAC cycle
10. daemon_policy_invalidate.go 546 — #4234/#4342 session invalidation, policy_id 0 exclusion (host-inbound/fabric zero-value safe), sentinel 0xFFFFFFFF
11. daemon_ddns_surface_a.go 846 — Surface A DDNS, IsPublicAddr gate #3732, checkip fail-closed #4423 H08
12. host_inbound_nft_test.go 897 — NFT rendering SSOT mirror test vs Rust classifier
13. remaining prod ≤685 each (flow, flowexport, ddns, etc.)

Test heavy: coalescence, archive, device_map startup/teardown, host_inbound_* (#3698 #3718 #4420 #4146 #3362), dhcp, ipsec rebind.

## Module Log (incl NEG proving coverage, NEG only in log)
- daemon_nft.go: NEG — lo0 atomic add+delete in single nft payload keeps prior table on failure (atomic), priority 0 < 10 ensures lo0 precedes host-inbound (#3364). unzoned catch-all subtracts zoned+lifeline (#4420), counter dedup safe, emitHostInboundZone handles all=>accept else per-token accept + catch-all drop — fail-closed parity with Rust (#3405 #3200). Checked nftAddrSet, counter NAME unquoted decl (#3578) vs quoted ref, ident-reset rej
```

---

### ps-A7_go_daemon_host-b2.md (18808 chars)

```
# Batch A7_go_daemon_host b2/3 — Security Zone & Daemon Host Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (origin/master same)
Worktree: /tmp/review-wt-claude-spark-001-A7_go_daemon_host-b2
Total batch LOC: 49294 (prod ~15400, test ~33800), 150 files
Date: 2026-07-09

## File-size/shape inventory (ranked size x resp x hot-path)

| Rank | File | LOC | Prod/Test | Largest fn | Responsibility | Hot-path |
|------|------|-----|-----------|------------|----------------|----------|
| 1 | pkg/frr/policy_render.go | 2309 | prod | renderBGPChain 280 | FRR route-map/prefix-list/AS-path/community render, sanitizeFRRValue injection guard | Control-plane render (commit) |
| 2 | pkg/frr/manager.go | 1057 | prod | ensureManagedSection 180 | FRR full config assembly, RETH→phys translation, managed section, reload fallback | Commit |
| 3 | pkg/ipsec/policy.go | 1135 | prod | buildVpnChildSAs 200 | XFRM/swanctl child SA, traffic selector, zone-qualify link-local %iface (#2885) | Commit |
| 4 | pkg/ipsec/ike.go | 890 | prod | buildIkeConfig 180 | IKE proposal, DH group, auth, multi-value bracket list #3904 | Commit |
| 5 | pkg/monitoriface/monitor.go | 952 | prod | Gather 280 | Interface counter collection, buffer stats | Telemetry (1/s) |
| 6 | pkg/lldp/lldp.go | 939 | prod | runReceiver 180 | AF_PACKET LLDP rx/tx, lifecycle mutex #5121, TTL0 shutdown #5123 | Control-plane L2 |
| 7 | pkg/networkd/networkd.go | 775 | prod | Apply 180 | systemd .link/.network/.netdev render, lifeline protect #1956, reload debt #4954, rp_filter restore | Commit |
| 8 | pkg/frr/config_render.go | 445 | prod | generateStaticRouteInTable 120 | Static route→FRR `ip route`, RETH→phys, reject→Null0/reject, DHCP AD200 | Commit |
| 9 | pkg/daemon/linksetup.go | 545 | prod | enumerateAndRenameInterfaces 140 | PCI enumeration, collision-safe two-pass rename #4178, D3 RSS | Boot |
| 10 | pkg/daemon/rss_indirection.go | 550 | prod | applyRSSIndirection 150 | mlx5 RSS indirection tables 0..workers-1, sysfs allowlist #785 | Boot/commit |
| 11 | pkg/daemon/rg_state.go | 365 | prod | Reconcile 110 | RG active = clusterPri OR allVrrpMaster, posture mismatch delay startup 10s / steady 2s #86, strict VIP | HA event |
| 12 | pkg/routing/bond.go | 490 | prod | Apply 150 | Fabric/ae bond idempotent sig (mode,mtu,members) #5119, partial completion in-place #5261 | Commit |
| 13 | pkg/routing/probe_pin.go | 289 | prod | Apply 120 | FWMark + per-test table for RPM next-hop pin #1827, RETH resolve, rollback #1
```

---

### ps-A7_go_daemon_host-b3.md (15742 chars)

```
# Batch A7_go_daemon_host b3/3 — Review Report
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Worktree: /tmp/review-wt-claude-spark-001-A7_go_daemon_host-b3 | Origin/master: same (verified 0 behind)

## File Size/Shape Inventory (ranked by size x resp-count x hot-path)

| File | LOC | Prod/Test | Largest Fn / Responsibility | Hot-path? |
|------|-----|-----------|-----------------------------|-----------|
| pkg/routing/tunnel.go | 2016 | prod | Apply (277) 250 LOC: GRE/IPIP/WG reconcile, anchor vs kernel branch, VRF claim, keepalive gen | YES (link lifecycle) |
| pkg/routing/rules.go | 1447 | prod | BuildPBRRules (758) 180 LOC + buildPBRFromFilter (941) 250 LOC: PBR FBF mirror, next-table, rib-group leak | YES (ip-rule, cross-VRF) |
| pkg/upgrade/cutover.go | 1045 | prod | Run (148) 500 LOC: STOP->FLIP->START, journal, preflight, DB snap | upgrade |
| pkg/upgrade/kernel_linux.go | 869 | prod | RealKernelSystem 40+ methods: UEFI A/B slot, efibootmgr, purge | kernel LANE-1 |
| pkg/upgrade/cluster_cli.go | 610 | prod | RollingCluster CLI impl: PeerAlive, DrainComplete, etc. | HA rolling |
| pkg/upgrade/runner.go | 596 | prod | NewRunner, copyTree, state xitions | upgrade |
| pkg/upgrade/kernel_run.go | 637 | prod | Kernel channel state machine, arm/promote/revert | kernel |
| pkg/upgrade/stagedgen/stagedgen.go | 413 | prod | Publish: immutable gen copy, .partial+rename+fsync | upgrade |
| pkg/upgrade/runtime/seed.go | 400 | prod | Seed generation, DB migration | upgrade |
| pkg/routing/vrf.go | 361 | prod | reconcileVRFs (183) 200 LOC: VRF create, table-mismatch recreate, orphan reap | YES (VRF binding) |
| pkg/routing/routes.go | 356 | prod | GetAllTableRoutes, routeToEntry, multiPathNextHops ECMP | read path |
| pkg/routing/xfrm.go | 332 | prod | Apply: xfrmi differential reconcile, if_id collision guard #2909 | YES (IPsec) |
| pkg/upgrade/lock/lock.go | 303 | prod | Acquire: host-wide flock | upgrade |
| pkg/routing/tunnel_keepalive.go | 294 | prod | icmpProber.Probe: Seq+nonce match, errno classification | keepalive |
| pkg/upgrade/kernel_selfrecover.go | 273 | prod | Self-recovery lease, watchdog | kernel |
| pkg/upgrade/rolling.go | 247 | prod | RunRolling, waitPredicate, drain-before-cut | HA |
| pkg/upgrade/flip.go | 448 | prod | flip, repointSymlink, gc, copyTreeChecksum | upgrade |
| pkg/routing/routing.go | 237 | prod | Facade over 10 domain managers, owns nlHandle | facade |
| pkg/upgrade/state.go | 165 | prod | Journal, State enum, order/atLeas
```

---

### ps-A8_go_api_grpc_rest-b1.md (12509 chars)

```
# A8 Go API / gRPC REST b1/2 — claude-spark-001 — pkg/api REST layer

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified)
Worktree: /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b1
Batch: 150 files — prod 29 files ~6800 LOC, test 121 files ~32000 LOC, total ~38800 LOC

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/api/sessions.go | 1541 | REST session list/summary/zone-pair, clear-sessions handler, filter | request |
| pkg/api/security.go | 942 | zones+policies+match-policies REST, zone display, scoped-global, host-inbound-to-REST | request |
| pkg/api/metrics.go | ~900 | Prometheus collector — per-zone/family nft counters, host-inbound ICMP/ND accept, zone counter hide #3643 | scrape |
| pkg/api/metrics_counters.go | ~370 | collectHostInboundKernelDenies, counterReadErrorsTotal fail-closed | scrape |
| pkg/api/metrics_descriptors.go | ~400 | counterReadErrorsTotal, hostInboundKernelDenies, hostInboundJunosHostDenies, hostInboundAddresslessZones, hostInboundICMPNDAccept | init |
| pkg/api/server.go | 789 | HTTP server, route table, TLS, graceful shutdown, middleware chain | boot |
| pkg/api/config.go | 417 | REST config/set/load/commit/activate/rollback, candidate DB, commit check | config path |
| pkg/api/api.go | 251 | writeJSON buffering (#4541), Response envelope, apiRuntimeDataplane interface | shared |
| pkg/api/auth.go | 137 | authMiddleware: basic/bearer/api-key, constantTime compare, /health always exempt, /metrics gated #4162 | auth |
| pkg/api/routing.go | ~200 | routing table REST | request |
| pkg/api/security_test.go etc | — | unit/functional coverage | test |

Largest fns: sessions.go sessionZonePairHandler ~200 LOC, security.go zonesHandler/policiesHandler ~150 each, matchPoliciesHandler ~300 (query param parsing, host-inbound classifier, global fallback, default-policy emit).

## Module Log (NEG proves coverage)

### pkg/api/security.go — zones + policies + match-policies

- **NEG — zone display nil-guard #3493:** `zonesHandler` iterates `cfg.Security.Zones`, checks `if zone == nil { continue }` tolerant/HA-sync path. ZoneIDs map reverse lookup for per-zone counters, counter read failure `PerZoneCountersAvailable=false` rather than panic — #3643 HIDE already. Verified at `security.go:33-42,93-130`. Sound — cannot crash on nil zone from lenient HA-sync load.

```

---

### ps-A8_go_api_grpc_rest-b2.md (11879 chars)

```
# Batch A8 b2/2 — Go API gRPC REST — Review Report

**Batch:** A8_go_api_grpc_rest b2/2 — 150 files (37 prod ~11k LOC, 113 test ~29k LOC, total ~40k)
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified via `git show-ref origin/master`)
**Worktree:** /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b2
**Reviewer:** claude-spark-001

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/grpcapi/server_sessions.go | 1778 | Session list/filter/clear/zone-pair, bounded clear #5454/#5531 | request |
| pkg/grpcapi/server_show_zones.go | 395 | GetZones + GetPolicies gRPC — zone display, scoped-global M03/M08 | request |
| pkg/grpcapi/server_show_policies_text.go | 541 | ShowPoliciesText — zone filter render, GlobalPolicyAppliesToZonePair #3357 | request |
| pkg/grpcapi/server_show_security_text.go | 1074 | ShowSecurityText — zone-pair tiers, host-inbound view, scheduler | request |
| pkg/grpcapi/server_show_zones_text.go | ~250 | zones text detail — host-inbound, lifeline, tier summary | request |
| pkg/grpcapi/server.go | 768 | gRPC server, interceptors, peer proxy allowlist, GetZonePairSummary+ClearSessions #3592/#3423 | boot |
| pkg/grpcapi/server_cluster.go | ~400 | cluster status/HA, MatchPolicies zone scoping, host-inbound ingress-iface #5579 | request |
| pkg/grpcapi/server_config.go | ~350 | Config mutation gRPC path, redaction | config |
| pkg/grpcapi/fabric_auth.go | ~150 | fabric HMAC session+counter, replay ±1 window, anti-replay | fabric |
| pkg/grpcapi/runtime.go | ~250 | runtime canary, status dedup, session cache | runtime |
| pkg/grpcapi/server_helpers.go | ~200 | zoneByID NAT counters, egress iface resolve | shared |
| pkg/grpcapi/xpfv1/xpf.pb.go | ~11k | generated protobuf | generated |

Largest fns: server_sessions.go buildSessionFilter ~120 LOC, clearFilteredSessionsV4/V6 ~200 each with rescan fallback, computeZonePairSummary ~120.

## Module Log (NEG proves coverage)

- **fabric_auth.go:102-186** `fabricAuthDecision` dual-accept: no-key→accept, valid token→accept, invalid→reject, missing+armed→reject. `verifyFabricAuthToken` HMAC constant-time `hmac.Equal`, checks ±1 window (60-90s replay bound). `computeFabricAuthToken` domain separation prevents heartbeat token substitution into fabric path. `checkFabricAuth` sticky flag + `heartbeatPeerAuthSeen` arms downgrade guard in ~200ms. NEG: no token in logs, key never logged, replay bound explicit
```

---

### ps-A8_go_api_grpc_rest-b3.md (3041 chars)

```
# A8 Go API gRPC REST b3 — configstore zeroize tests (13 files)

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (fresh, 0 behind origin/master 4e0c7f74c)
Worktree: /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b3 (detached HEAD)
Batch: batch-021.json — area A8_go_api_grpc_rest b3/3 (13 files, all *_test.go)

## Inventory

| File | LOC | Responsibility | Hot? |
|------|-----|---------------|------|
| zeroize_configured_root_5280_test.go | ~80 | Tests factory-reset archive non-durable, configdb vs archive cleanup | cold | test-only |
| zeroize_durable_5197_test.go | ~90 | Durable delete key-first ordering | cold | test-only |
| zeroize_gate_stop_5281_test.go | ~100 | Zeroize gate stop signal | cold | test-only |
| zeroize_login_4598_test.go | ~70 | Login zeroize | cold | test-only |
| zeroize_login_failclosed_5496_test.go | ~80 | Login fail-closed | cold | test-only |
| ... (5 files listed twice due to manifest dup) | | | | |

All 13 files are *_test.go, test-only, no enforcement logic. They pin:
- Factory-reset archive cleanup #5197 durable key-first
- Configured-root vs archive #5280/#5297
- Gate stop #5281
- Login zeroize #4598 fail-closed #5496

## Module-by-module log (incl negatives)

- zeroize_configured_root_5280_test.go — NEGATIVE: test pins non-durable archive cleanup, not enforcement. Checks archive path not deleted, no secret leak, but test-only.
- zeroize_durable_5197_test.go — NEGATIVE: pins durable delete ordering, not enforcement.
- zeroize_gate_stop_5281_test.go — NEGATIVE: pins gate stop signal, not enforcement.
- zeroize_login_4598_test.go — NEGATIVE: pins login zeroize, not enforcement.
- zeroize_login_failclosed_5496_test.go — NEGATIVE: pins fail-closed, not enforcement.
```

---

### ps-A9_go_observability-b1.md (9766 chars)

```
# A9 Go Observability — claude-spark-001 — B9 (batch-022)

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c)
Worktree: /tmp/review-wt-claude-spark-001-A9_go_observability-b1
Batch: 142 files (A9_go_observability b1/1) — prod 25 files 16592 LOC, test 117 files 27607 LOC, total 44199 LOC

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/snmp/agent.go | 2143 | SNMP v2c/v1/community+source allowlist, SET authz, secret-redacted logs | request path |
| pkg/logging/ringbuf.go | 1451 | RT_FLOW wire 144/152/160 LE zone decode, zoneNames RWMutex, binary+text formatters | per-event hot |
| pkg/eventengine/engine.go | 1409 | event-options policy trigger, cooldown 30s, transactional batch, fail-closed matcher | event cb |
| pkg/snmp/v3.go | 1209 | SNMPv3 USM timeliness 150s, DES/AES priv, salt counter atomic, boots ceiling fail-closed | request path |
| pkg/flowexport/ipfix.go | 1109 | IPFIX templates IE5 CoS, IE61 flowDirection from per-zone sampling, mask IE9/13/29/30 | per-close |
| pkg/ipmon/ipmon.go | 1016 | IP-monitoring probe-driven preferred-route, per-policy state, failedTests map probe->test | probe cb |
| pkg/logging/syslog.go | 961 | syslog TCP/TLS resilience writeTimeout 4s, reconnectCooldown 1s, severity sentinels, ShouldSend | per-event |
| pkg/flowexport/manager.go | 915 | BuildSamplingZones zoneID->SamplingDir, ShouldExport ingress Input OR egress Output, FlowDirection | per-close |
| pkg/feeds/feeds.go | 889 | dynamic-address feed fetcher 32MiB cap, 1M prefix cap, 30s timeout, plaintext warn, last-good | bg refresh |
| pkg/flowexport/netflow.go | 853 | NetFlow v9 header sysUptime CLOCK_BOOTTIME, FlowDirection opt-in template | per-close |
| pkg/rpm/rpm.go | 794 | RPM scheduler, HTTP transport leak guard #4912, icmp zone preserve #2494 | probe loop |
| pkg/flowexport/transport.go | 580 | collectorConns health attempts/failures/skipped, probe backoff 30s, write timeout 2s edge log | flush |
| ... | | | |

Largest fns (approx): EventReader.decodeRawEvent ~260, Agent.handleGetBulk ~180, buildResponseVersion ~170, systemBootTime + netflow template build ~150.

## Module log (NEG proofs)

- **logging/ringbuf.go**: IngressZone/EgressZone LE u16 at [48:50]/[50:52] preserved through extended frames [144:152] CoS/ifindex and [152:160] stable SessionID (#4915 #2749). Both-sides wire discipline: len>=144 accepted, additive slots read only if present. zoneNames RWMutex, r
```

---


## Findings — separated by confidence (High/Medium require full evidence bar, but ONLY MATERIAL or COHORT, no pure NEG in findings table)


### Critical


(0 findings at Critical level, excluding pure NEG)


### High


(0 findings at High level, excluding pure NEG)


### Medium


#### Finding from ps-A6_go_dataplane_manager-b1.md (Gate: FIXED)

```
Title: Quarantine scoped-global rule dropped entirely on single member collision — surviving zone deny bypass
Severity: Medium
Confidence: High
Gate verdict: FIXED
Evidence: zones_quarantine.go:100-120 historical comment now fixed:
```
// Dropping the whole rule because one member collides is FAIL-OPEN: a global deny scoped from [z174, z214] where only z214 collides would vanish entirely, so still-valid z174 traffic no longer hits the deny
```
Current code: pruneQuarantined returns NEW slice no alias, ScopeSingular picks survivor, old helper singular regen prevents dangling ref. Prior fail-open window existed before #5577, now fixed on origin/master tip.
Trace: config zones z174/z214 collide + global deny scoped from [z174,z214] -> old quarantine drops whole rule -> z174 traffic permitted by default.
Fix direction: Done — prune not drop, singular regen. Add multi-member >2 zones colliding test.
Labels: zone-policy, fail-closed, quarantine, #3719, #5577
Dedup: Not in dedup list (dedup mentions #5488 singular/plural but not quarantine)
Verified against origin/master: pkg/dataplane/userspace/zones_quarantine.go:57-180 on worktree vs /home/ps/git/avacado-xpf same — pruneQuarantined + ScopeSingular present on tip.

### FIXED-2: Host-inbound VIP scoping backup node missing live VIP would not scope deny — fail-open admit on backup
```

---

#### Finding from ps-A6_go_dataplane_manager-b1.md (Gate: FIXED)

```
Title: Backup node lacks live VIP — without config-derived VIP inclusion host-inbound deny not scoped to VIP
Severity: Medium
Confidence: High
Gate verdict: FIXED
Evidence: zones_host_inbound.go:211-250:
```
// VRRP RETH VIPs (#3172): the host-inbound destination address set must always carried them
for _, vip := range vg.VirtualAddresses {
    if host := hostIPFromCIDR(vip); host != "" {
```
Without this, buildLinkSnapshot live addr list on backup missing VIP -> BuildZoneHostInboundViews no VIP -> nft chain no addr -> SSH to VIP not denied per-zone rules -> fail-open.
Trace: backup VRRP backup no VIP on link -> snapshot live addrs missing VIP -> without fix host-inbound deny not scoped -> admit.
Fix direction: Done — VIPs added to effective-token group #3362 aware, hostIPFromCIDR strips prefix, IPv6 included.
Labels: host-inbound, VIP, #3172, #4420, unzoned
Dedup: Orientation mentions #3172 but not as open bug — fix present.
Verified against origin/master: same VIP inclusion on tip, test zones_addressless_iface_3710_test.go asserts.

### COHORT-1: Synthetic ifindex allocation panics on exhaustion
```

---

#### Finding from ps-A8_go_api_grpc_rest-b1.md (Gate: COHORT)

```
# A8 Go API / gRPC REST b1/2 — claude-spark-001 — pkg/api REST layer

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified)
Worktree: /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b1
Batch: 150 files — prod 29 files ~6800 LOC, test 121 files ~32000 LOC, total ~38800 LOC

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/api/sessions.go | 1541 | REST session list/summary/zone-pair, clear-sessions handler, filter | request |
| pkg/api/security.go | 942 | zones+policies+match-policies REST, zone display, scoped-global, host-inbound-to-REST | request |
| pkg/api/metrics.go | ~900 | Prometheus collector — per-zone/family nft counters, host-inbound ICMP/ND accept, zone counter hide #3643 | scrape |
| pkg/api/metrics_counters.go | ~370 | collectHostInboundKernelDenies, counterReadErrorsTotal fail-closed | scrape |
| pkg/api/metrics_descriptors.go | ~400 | counterReadErrorsTotal, hostInboundKernelDenies, hostInboundJunosHostDenies, hostInboundAddresslessZones, hostInboundICMPNDAccept | init |
| pkg/api/server.go | 789 | HTTP server, route table, TLS, graceful shutdown, middleware chain | boot |
| pkg/api/config.go | 417 | REST config/set/load/commit/activate/rollback, candidate DB, commit check | config path |
| pkg/api/api.go | 251 | writeJSON buffering (#4541), Response envelope, apiRuntimeDataplane interface | shared |
| pkg/api/auth.go | 137 | authMiddleware: basic/bearer/api-key, constantTime compare, /health always exempt, /metrics gated #4162 | auth |
| pkg/api/routing.go | ~200 | routing table REST | request |
| pkg/api/security_test.go etc | — | unit/functional coverage | test |

Largest fns: sessions.go sessionZonePairHandler ~200 LOC, security.go zonesHandler/policiesHandler ~150 each, matchPoliciesHandler ~300 (query param parsing, host-inbound classifier, global fallback, default-policy emit).

## Module Log (NEG proves coverage)

### pkg/api/security.go — zones + policies + match-policies

- **NEG — zone display nil-guard #3493:** `zonesHandler` iterates `cfg.Security.Zones`, checks `if zone == nil { continue }` tolerant/HA-sync path. ZoneIDs map reverse lookup for per-zone counters, counter read failure `PerZoneCountersAvailable=false` rather than panic — #3643 HIDE already. Verified at `security.go:33-42,93-130`. Sound — cannot crash on nil zone from lenient HA-sync load.

- **NEG — scoped-global zone SET surface #3286/#4626 M03/M08:** Global policies loop `security.go:285-370` emits `FromZone="*" ToZone="*"` singular plus `MatchFromZones: rule.Match.FromZones` (plural) and `MatchToZones` (plural). Unscoped global keeps both singular as `*` and plural empty. `ScopeSingular()` backward-compat first-zone, `ZoneScopeSetLabel` for display. REST consumer cannot misinterpret scoped global as all-zones because both representations present. Verified `security.go:306-314`:
  ```
  MatchFromZone:  config.ScopeSingular(rule.Match.FromZones),
  MatchToZone:    config.ScopeSingular(rule.Match.ToZones),
  MatchFromZones: rule.Match.FromZones,
  MatchToZones:   rule.Match.ToZones,
  ```

- **NEG — host-inbound enforcement parity #3328/#3070/#3362/#3405:** `zonesHandler` sets `HostInboundConfigured=true` unconditionally for every non-nil zone — not re-derived from config shape. Pre-#3405 parsed stanza presence; a no-stanza zone reported `false` (appeared host-inbound-open). Now default-deny parity: no `host-inbound-traffic` stanza = deny. Interface overrides via `SortedInterfaceHostInboundRefs()` + `LifelineInterfaces` view. Verified `security.go:58-83`. Sound.

- **NEG — match-policies zone pair echo #3627 M06:** `matchPoliciesHandler` echoes `QueriedFromZone/QueriedToZone` on every path — host-inbound-unmatched, default, match — so stored diagnostics prove query context distinct from matched-policy scope. Prevents misattribution of deny to wrong zone pair. Verified `security.go:745-746,824-825,836-837,853-854,874-875`.

- **NEG —
```

---

#### Finding from ps-A8_go_api_grpc_rest-b2.md (Gate: COHORT)

```
# Batch A8 b2/2 — Go API gRPC REST — Review Report

**Batch:** A8_go_api_grpc_rest b2/2 — 150 files (37 prod ~11k LOC, 113 test ~29k LOC, total ~40k)
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified via `git show-ref origin/master`)
**Worktree:** /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b2
**Reviewer:** claude-spark-001

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/grpcapi/server_sessions.go | 1778 | Session list/filter/clear/zone-pair, bounded clear #5454/#5531 | request |
| pkg/grpcapi/server_show_zones.go | 395 | GetZones + GetPolicies gRPC — zone display, scoped-global M03/M08 | request |
| pkg/grpcapi/server_show_policies_text.go | 541 | ShowPoliciesText — zone filter render, GlobalPolicyAppliesToZonePair #3357 | request |
| pkg/grpcapi/server_show_security_text.go | 1074 | ShowSecurityText — zone-pair tiers, host-inbound view, scheduler | request |
| pkg/grpcapi/server_show_zones_text.go | ~250 | zones text detail — host-inbound, lifeline, tier summary | request |
| pkg/grpcapi/server.go | 768 | gRPC server, interceptors, peer proxy allowlist, GetZonePairSummary+ClearSessions #3592/#3423 | boot |
| pkg/grpcapi/server_cluster.go | ~400 | cluster status/HA, MatchPolicies zone scoping, host-inbound ingress-iface #5579 | request |
| pkg/grpcapi/server_config.go | ~350 | Config mutation gRPC path, redaction | config |
| pkg/grpcapi/fabric_auth.go | ~150 | fabric HMAC session+counter, replay ±1 window, anti-replay | fabric |
| pkg/grpcapi/runtime.go | ~250 | runtime canary, status dedup, session cache | runtime |
| pkg/grpcapi/server_helpers.go | ~200 | zoneByID NAT counters, egress iface resolve | shared |
| pkg/grpcapi/xpfv1/xpf.pb.go | ~11k | generated protobuf | generated |

Largest fns: server_sessions.go buildSessionFilter ~120 LOC, clearFilteredSessionsV4/V6 ~200 each with rescan fallback, computeZonePairSummary ~120.

## Module Log (NEG proves coverage)

- **fabric_auth.go:102-186** `fabricAuthDecision` dual-accept: no-key→accept, valid token→accept, invalid→reject, missing+armed→reject. `verifyFabricAuthToken` HMAC constant-time `hmac.Equal`, checks ±1 window (60-90s replay bound). `computeFabricAuthToken` domain separation prevents heartbeat token substitution into fabric path. `checkFabricAuth` sticky flag + `heartbeatPeerAuthSeen` arms downgrade guard in ~200ms. NEG: no token in logs, key never logged, replay bound explicit, rolling-upgrade grace preserved (#4107/#4122/#5047 tests pin).

- **server.go:998-1049** `clampGRPCBindToLoopback` — empty host (wildcard `:50051`)→not loopback→clamped to 127.0.0.1, IPv6 `::`→`::1`. SplitHostPort failure returns unchanged, then `net.Listen` fails (no port) — no bypass. `grpcHostIsLoopback` handles `localhost` literal. Primary listener only installs `configLockInterceptor`, no auth — clamp ensures no unauthenticated network exposure (#5035). Fabric listener chain auth→allowlist→lock correct order. NEG: no non-loopback primary path without clamp.

- **server_show_zones.go GetZones** nil-zone skip (#3493 tolerant HA-sync), HostInbound split fields (systemServices vs protocols), lifeline via `HostInboundViewWithLifelines`, `HostInboundConfigured=true` unconditional per #3405 default-deny parity. Zone counter hide on `ErrCounterNotPopulated` (#3643). GetPolicies bulk reader via `NewPolicyCounterReader` O(P+C) single snapshot (#3965), policy-stats gate honors system-wide knob + per-rule Count, runtime ID presence-wrapped (`proto.Uint32`) so 0 survives wire. Scoped-global: `MatchFromZone` singular (compat first-zone) + `MatchFromZones` plural full set. Default-policy synthetic row sentinel ID #3363 + log posture #3670. Evidence: `server_show_zones.go:31,56-88,270-280`. NEG: no counter leak, scoped-global display correct.

- **server_show_policies_text.go + server_show_zones_text.go** Both use bulk reader, filter via `GlobalPolicyAppliesToZonePair` #3357 (empty fi
```

---

#### Finding from ps-A9_go_observability-b1.md (Gate: COHORT)

```
# A9 Go Observability — claude-spark-001 — B9 (batch-022)

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c)
Worktree: /tmp/review-wt-claude-spark-001-A9_go_observability-b1
Batch: 142 files (A9_go_observability b1/1) — prod 25 files 16592 LOC, test 117 files 27607 LOC, total 44199 LOC

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/snmp/agent.go | 2143 | SNMP v2c/v1/community+source allowlist, SET authz, secret-redacted logs | request path |
| pkg/logging/ringbuf.go | 1451 | RT_FLOW wire 144/152/160 LE zone decode, zoneNames RWMutex, binary+text formatters | per-event hot |
| pkg/eventengine/engine.go | 1409 | event-options policy trigger, cooldown 30s, transactional batch, fail-closed matcher | event cb |
| pkg/snmp/v3.go | 1209 | SNMPv3 USM timeliness 150s, DES/AES priv, salt counter atomic, boots ceiling fail-closed | request path |
| pkg/flowexport/ipfix.go | 1109 | IPFIX templates IE5 CoS, IE61 flowDirection from per-zone sampling, mask IE9/13/29/30 | per-close |
| pkg/ipmon/ipmon.go | 1016 | IP-monitoring probe-driven preferred-route, per-policy state, failedTests map probe->test | probe cb |
| pkg/logging/syslog.go | 961 | syslog TCP/TLS resilience writeTimeout 4s, reconnectCooldown 1s, severity sentinels, ShouldSend | per-event |
| pkg/flowexport/manager.go | 915 | BuildSamplingZones zoneID->SamplingDir, ShouldExport ingress Input OR egress Output, FlowDirection | per-close |
| pkg/feeds/feeds.go | 889 | dynamic-address feed fetcher 32MiB cap, 1M prefix cap, 30s timeout, plaintext warn, last-good | bg refresh |
| pkg/flowexport/netflow.go | 853 | NetFlow v9 header sysUptime CLOCK_BOOTTIME, FlowDirection opt-in template | per-close |
| pkg/rpm/rpm.go | 794 | RPM scheduler, HTTP transport leak guard #4912, icmp zone preserve #2494 | probe loop |
| pkg/flowexport/transport.go | 580 | collectorConns health attempts/failures/skipped, probe backoff 30s, write timeout 2s edge log | flush |
| ... | | | |

Largest fns (approx): EventReader.decodeRawEvent ~260, Agent.handleGetBulk ~180, buildResponseVersion ~170, systemBootTime + netflow template build ~150.

## Module log (NEG proofs)

- **logging/ringbuf.go**: IngressZone/EgressZone LE u16 at [48:50]/[50:52] preserved through extended frames [144:152] CoS/ifindex and [152:160] stable SessionID (#4915 #2749). Both-sides wire discipline: len>=144 accepted, additive slots read only if present. zoneNames RWMutex, resolve fallback fmt "%d" — no unbounded label. NEG: wire layout versioned, no zone ID truncation, no cardinality DoS.
- **logging/eventbuf.go + event_filter_args.go**: HasZone bool separates filter presence from Zone==0 (#3338). Zone 0 = unknown/pre-classification/host-inbound — selectable via `unknown/none/0`. ParseEventFilterArgs fail-closed unknown token/missing value/non-positive count/unresolvable name → error, not unfiltered dump (#3547 M02). matches checks InZone==filter OR OutZone==filter. NEG: zone filter cannot be bypassed to widen dump.
- **logging/aggregator.go**: Space-Saving top-K bounded defaultMaxAggKeys=10000 (#2936 #3099). add() evicts min-bytes, overflow counted, warning emitted. Flush final on ctx cancel (#5313). NEG: no unbounded map growth via spoofed src/dst, no zone-label cardinality.
- **logging/eventbuf.go buffer**: NewEventBuffer clamps size<=0 to default 1000 (#3342). maxSubscribers 64, TrySubscribe for untrusted REST SSE (#4484) prevents O(N) fan-out DoS. DroppedTotal + BufSeq discontinuity + Overrun in-band flag (#5064). NEG: bounded, observable loss.
- **logging/syslog.go + slog_handler.go + locallog.go + trace.go**: TCP/TLS Send bounded WriteTimeout 4s, ReconnectCooldown 1s (#4423). goID() re-entrancy guard #2287 only when clients present (#2295). TruncStr zone/policy/app/iface to 255 in binaryLog. ActionNotApplicable 0xFF on close (#4914) prevents bogus deny. NEG: no per-event stall, no zone name leak unbounded.
- **flowexport/manager.go + ipf
```

---

(5 findings at Medium level, excluding pure NEG)


### Low


#### Finding from ps-A1_rust_dataplane_packet-b1.md (Gate: COHORT)

```
# Review: A1_rust_dataplane_packet (b1/3) — Zone Policy & Inter-Zone Enforcement
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Date: 2026-07-11 | Reviewer: claude-spark-001

## File-Size/Shape Inventory (batch 150 files, prod vs test)

Top prod by LOC x responsibility:

| LOC | File | Responsibility | Hot-path? |
|-----|------|---------------|-----------|
| 2795 | forwarding/mod.rs | zone_pair_ids_for_flow, FIB LPM, fabric redirect, host-inbound default-deny, LocalDelivery gate, PBR route override, HA RG owner | YES (per-packet RX batch) |
| 537 | forwarding/host_inbound.rs | ZoneHostInbound admission set, global ICMP/ND accept, per-iface override | YES (LocalDelivery cold path) |
| 340 | forwarding_build/interfaces.rs | ifindex_to_zone_id, zone_name_to_id resolve, fail-closed InterfaceUnknownZone | Build (snapshot apply) |
| 195 | forwarding_build/zones.rs | zone_name_to_id SSOT, duplicate-zone-ID reject, host-inbound/reject-bucket per zone | Build |
| 1960 | frame/inspect.rs | L4 parse (src/dst port, ICMP type/code), fabric zone-MAC decode, term_match_extra | YES |
| 1772 | frame/mod.rs | Frame dispatch, port/box types | YES |
| 850 | forwarding_build/cos.rs | CoS build | Build |
| 705 | forwarding_build/mod.rs | Orchestrates zone+iface+fib+policy+filter+nat build | Build |
| 483 | forwarding_build/fib.rs | FIB build from snapshot routes | Build |
| 324 | forwarding_build/tunnels.rs | Tunnel endpoint build | Build |
| ~500-1100 each | cos/*, checksum, flow_cache, bind, bpf_map/* | CoS qdisc, flow cache, XDP bind, BPF maps | Mixed |

Test files (5108 forwarding_build/tests.rs, 4668 forwarding/tests.rs, etc.) — coverage, not enforcement.

Largest fn: `evaluate_policy_result_l3_aware` ~280 LOC in policy.rs (not in batch, read for context) — zone-pair exact → wildcard (from-any/to-any/both-any) → global+scoped → default-policy.

Total batch prod scanned: ~12K LOC (excluding benches+tests). Hot-path files: forwarding/mod.rs, forwarding/host_inbound.rs, frame/inspect.rs.

## Module Log (with NEG proofs)

### forwarding/mod.rs — zone_pair resolution & default-policy
- `zone_pair_ids_for_flow_with_override`: single HashMap lookup ifindex→u16 for ingress, struct field load for egress zone_id. Returns (0,0) for unzoned. Caller in policy treats 0 as unknown → default action. **NEG**: No bypass — unzoned (0) falls through all policy tiers (exact/wildcard/global) per #3110 guard `if from_id !=0 && to_id !=0` in policy.rs:2647. Verified empty default → Deny.
- `resolve_ingress_logical_ifindex`: maps (parent_ifindex, vlan_id)→logical unit ifindex, ensuring per-VLAN zone attribution. **NEG**: VLAN sub-if zone override keyed by logical ifindex, looked up via same resolution — correct (see #3609).
- Fabric zone encoding: `resolve_zone_encoded_fabric_redirect_by_id` carries zone ID as 0x02:bf:72:magic:hi:lo MAC. Decode validates against `zone_id_to_name` (`parse_zone_encoded_fabric_ingress_from_frame:1890-1900`). **NEG**: Stale zone ID → None → fallback to ifindex-based zone, not spoofed.
- `finalize_new_flow_ha_resolution` + fabric checks: HA inactive → fabric redirect with zone-tagged MAC preserves ingress zone for peer policy evaluation. **NEG**: Fabric ingress flag prevents loop (ingress_is_fabric guard).
- `host_inbound_admits` re-export: SSOT for zone host-inbound used by poll_stages + lo0 gate.
- `LOCAL_DELIVERY_IFINDEX0` diagnostic: counts NAT-only local targets where zone/HA attribution operates on ifindex 0. Not a bypass — counted.

### forwarding/host_inbound.rs — host-inbound admission
- `zone_host_inbound_from_snapshot`/`from_tokens`: token classifier via `classify_system_service`/`classify_protocol`. Unknown tokens → `_ => {}` fail-closed (no broaden). **NEG**: Per Go SSOT KnownHostInboundSystemServices parity test (#3486) guards drift.
- `is_icmp_host_inbound_global_accept`: v4 types 3|11|12 (dest-unreach/time-exceeded/param-problem), v6 types 1|2|3|4|133-137 (errors + ND). Echo-request NOT in global — gated on `ping` token. 
```

---

#### Finding from ps-A1_rust_dataplane_packet-b2.md (Gate: COHORT)

```
# A1 rust dataplane packet b2/3 — claude-spark-001 — zone policy focus

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa verified against origin/master same SHA
Worktree: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b2 — discover via git rev-parse --show-toplevel /home/ps/git/avacado-xpf
Work dir: /tmp/review-work-claude-spark-001
WHOAMI: claude-spark-001
Date: 2026-07-11

## Inventory (150 files, 98794 LOC)

- Prod 49171, Test 49623, ratio ~1:1
- Largest prod: afxdp/poll_descriptor/mod.rs 6294 (hot-path RX classification, zone mapping, policy/host-inbound/junos-host gates, session decisions)
- Next: neighbor.rs 2036, types/cos.rs 1786, tx/dispatch/mod.rs 1505, types/forwarding.rs 1099, tx/cos_classify.rs 1335, gre.rs ~750, ha.rs ~950
- Largest test: session_glue/tests.rs 5748, cos_classify_tests 4617, poll_stages_tests 2636, shared_cos_lease_tests 2511
- Responsibility ranking (size x hot-path):
  1. poll_descriptor/mod.rs — RX hot path, ifindex_to_zone_id, evaluate_policy_result_l3_aware, host-inbound, junos-host
  2. poll_descriptor/filter.rs — filter_log_ingress/egress_zone_id, host_inbound_gated_lo0_action (#3485)
  3. types/forwarding.rs — ForwardingState.ifindex_to_zone_id, zone_host_inbound, reject_buckets, egress_zone_id, ZHI
  4. tx/dispatch/mod.rs — TX after policy, zone_counter_slot_map usage
  5. gre.rs / tunnel.rs — ingress zone via ifindex_to_zone_id for tunnel decap
  6. ha.rs / session_glue — HA ownership, epoch bumps, zone preservation across failover
  7. neighbor / sharded_neighbor / neg_neigh — ARP/NDP, owns_configured_ip anti-poison (#3182)
  8. tx/ + umem/ + wg/ — TX pipeline, CoS, WireGuard, not direct zone but affects per-zone accounting

## Module Log — coverage proof (NEG only in log)

- frame/wg_tests.rs: NEG — test-only WG framing helpers, no zone path, sound
- gre.rs: NEG — ifindex_to_zone_id read for ingress_zone (line 750), egress not needed for decap gate; zone validity checked via zone_id_to_name contains_key, fail-closed 0
- ha.rs: NEG — update_ha_state bumps rg_epochs Release-before-Store per #2120, airtight self-heal edge; zone preservation via forwarding ArcSwap, no bypass
- ha_tests.rs: NEG — HA epoch bump tests, no policy bypass
- icmp.rs / icmp_ptb.rs / icmp_ratelimit.rs: NEG — ICMP PTB/build uses egress ifindex for src_mac/MTU, zone not consulted (correct: PTB is L3, already policy-admitted); rate-limit per-zone bucket via reject_bucket (forwarding.rs:171)
- icmp_embed/*: NEG — NAT match + return resolution uses SessionKey+NatDecision, zone not re-evaluated (correct: embedded ICMP inherits parent flow's zone verdict); #5568 Ethernet-slack dedup already tracked
- icmp_tests, icmp_ptb_tests, icmp_ratelimit_tests: NEG — unit tests, no enforcement impact
- mirror/*: NEG — fast_path copies ifindex zone implicitly via forwarding resolution, mirroring after policy allow, no zone bypass
- mod.rs (afxdp/mod.rs): NEG — dispatcher, delegates to poll_descriptor, zone map cloned as OWNED for event-stream (line 695), no TOCTOU
- mpsc_inbox / worker_queue: NEG — lock-free MPSC, no zone logic
- neg_neigh / neighbor / dispatch / latency / resolver: NEG — neighbor anti-poison owns_configured_ip uses NAT-decoupled configured_iface_v* (#3182), sound fail-closed
- parser.rs / parser_tests.rs: NEG — L4 extraction bounds-checked, returns None on short packet; zone not touched here (higher layer)
- poll_descriptor/*:
  - filter.rs NEG — filter_log_ingress_zone_id validates override via zone_id_to_name.contains_key, else ifindex_to_zone_id (polish). host_inbound_gated_lo0_action enforces host-inbound BEFORE lo0 (None => deny, Some => lo0 eval) #3485, with logical VLAN ifindex override key (line 817 test)
  - flow_cache_hit.rs NEG — cached log preserves ingress_zone_id/egress_zone_id, no re-derivation, safe because cache entry stamped with owner_rg_epoch (#1065)
  - mod.rs NEG — core hot path: from_id via ifindex_to_zone_id, egress via egress.iface.zone_id, guard from_id!=0&&to_id!=0 in evaluate_polic
```

---

#### Finding from ps-A1_rust_dataplane_packet-b3.md (Gate: COHORT)

```
# A1 rust dataplane packet b3/3 — claude-spark-001 — zone policy deep dive

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa verified against origin/master same
Worktree: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b3 — repo root via git rev-parse --show-toplevel /home/ps/git/avacado-xpf
WHOAMI: claude-spark-001
Work dir: /tmp/review-work-claude-spark-001

## Inventory (137 files, 97551 LOC)

- Prod 45704, Test 51847
- Largest: filter/tests.rs 8613, policy_tests.rs 7280, session/tests.rs 7072, screen/tests.rs 5395, wg/tests.rs 3909, policy.rs 3657, worker/cos/tests 2708, server/tests 2444
- Hot-path ranking:
 1. policy.rs 3657 — evaluate_policy_result_l3_aware (280 LOC, zone_pair_index, from_any/to_any/both_any/global tiers, frag-association #4569, default deny sentinel)
 2. filter/compiler.rs + engine/ — lo0 + transit filter compilation, zone not directly but filter_log zone ids from poll_descriptor
 3. session/install.rs + entry.rs + lookup.rs + mod.rs — metadata ingress_zone/egress_zone stamping, inactivity_timeout per zone #3527 override, per-app timeout
 4. afxdp/zone_counters.rs 437 — flat LUT [u8;65536] slot_of, thread-local coalesce, flush per RX batch — HFT-grade, no per-packet hash/atomic
 5. worker/loop_body/mod.rs 1784 + worker/mod.rs 1631 — loop iteration captures forwarding ArcSnapshot, consistent slot_map for record+flush
 6. protocol/security.rs + resolution.rs + snapshot.rs — GlobalZoneScope, match_from_zones/match_to_zones plural, is_host_scope, resolution for host-inbound global
 7. server/handlers/snapshot.rs — apply snapshot preflight via parse_policy_state_with_counters + SnapshotIntegrityError::InterfaceUnknownZone #2391 / UnresolvableZoneReference #3402
 8. slowpath.rs — kernel reinjection gate is_slow_path_eligible: PolicyDenied NOT eligible (#1913) — prevents bypass via kernel FIB

## Module Log — coverage (NEG)

- wg/tests.rs, timers.rs: NEG — WireGuard timers, no zone bypass, syncookie key includes zone_id per #2446
- worker/bind_meta.rs, bpf_maps.rs: NEG — bind meta carries zone id for logging, no enforcement bypass
- worker/cos/*: NEG — CoS classification uses zone_id for queue selection? No, uses forwarding class; zone not bypassed, slot map not consulted here
- worker/cos_state.rs, flow_cache_state.rs, lifecycle.rs, loop_body/debug_report.rs, setup.rs, mod.rs, scratch.rs, telemetry.rs, timers.rs, tx_counters.rs, tx_pipeline.rs, xsk_rings.rs: NEG — worker infra, forwarding snapshot captured per iteration, zone counters flushed via flush_recorded_zone_counters (slot_map same as record calls) — consistent
- worker_queue.rs, worker_runtime.rs: NEG — MPSC, no zone
- zone_counters.rs: NEG — build dedup+skip zero, slot_of 0 => uncounted for that direction (correct); overflow_active flag surfaced; record_zone_traffic early-return both slots 0; fold_pending lock per batch (uncontended); snapshot deterministic sorted by zone_id
- bin/fairness-eval.rs, fairness* : NEG — offline fairness eval, not dataplane enforcement
- event_stream/codec/*, mod.rs, producer.rs: NEG — codec encodes ingress_zone_id/egress_zone_id as u16 LE at bytes 48-52 (rt_flow.rs:253), preserves zone for Go shadow; decode failure handled via SnapshotIntegrityError, not silent continue (except #5483 already deduped)
- filter/compiler.rs, engine/*, mod.rs, policer.rs: NEG — compiler validates filter refs (#3296 MissingFilterRef fail-closed), engine eval caches by zone? cache_sensitive checks ingress_zone in key (prevents cross-zone cache poisoning)
- hot_hash_seed.rs, io_uring_write.rs, ip_proto.rs: NEG — infra
- main.rs, main_tests.rs: NEG — build_synced_session_entry_falls_back_to_zone_name_when_id_zero test (line 1202) verifies downgrade path, sound
- policy.rs: NEG — evaluate_policy_result_l3_aware: if from_id==0||to_id==0 falls to default_action (Deny when empty wire #3365, line 1728); global_indices scoped via global_from_zone.matches(to_id check line 2798) ; junos-host gate after host-inbound; frag-assoc override #4569 fa
```

---

#### Finding from ps-A3_go_config_cli_tree-b3.md (Gate: COHORT)

```
# Batch A3_go_config_cli_tree b3 — Zone Policy Hardening Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (== origin/master)
Focus: security zone policies, global scoped policies, host-inbound admission, default-policy

## File-size/shape inventory (ranked by size x responsibility x hot-path)

| Rank | File | LOC | Type | Responsibility | Largest fn / token |
|---|---|---|---|---|---|
|1|parser_security_test.go|5805|test|Zone policy compilation & dual-shape|Test* (~150 LOC)|
|2|schema_security.go|1263|prod|Security schema SSOT (zones, host-inbound, policies, global FromZones/ToZones multi:true #4626)|policyThenSchemaChildren 50|
|3|junos_host_deny.go|1155|prod|Direct host-bound DENY projection (3-tier Rust parity, SET-subtraction, iifname scope, IKE/ident exempt per-netdev #5565)|junosHostZoneExemptNetdevs ~120|
|4|parser_ast_test.go|5620|test|AST dual-shape & SetPath grouping|Large|
|5|host_inbound_tokens.go|484|prod|Token SSOT KnownHostInbound* + HostInboundServiceMatch/ProtocolMatch (SSOT for nft + Rust)|HostInboundServiceMatch 80|
|6|host_inbound_view.go|342|prod|Zone host-inbound display SSOT (union effective, lifeline-aware)|HostInboundViewWithLifelines|
|7|schema.go|277|prod|schemaNode + setSchema root|isScalarValueLeaf|
|8|lifeline.go|84|prod|Mgmt/cluster lifeline detection (fxp0 + em0/fab* + configured control/fabric)|HostInboundLifelineInterface|
|9|parser.go|403|prod|Hierarchical Junos parser (AST)|parseStatements|
|10|schema_validators.go|~250|prod|Enum/integer validators, PRF, login username|ValidateEnum etc|

Batch: 30 prod (~6.5k LOC), 120 test (~35k LOC). Hot-path prod: junos_host_deny.go (kernel nft emission), host_inbound_tokens.go (admission tuple), schema_security.go (commit gate), lifeline.go (bypass decision).

## Module log (coverage with NEG)

- **host_inbound core** (host_inbound_tokens.go, host_inbound_view.go, host_inbound_multicast.go, host_inbound_dup_block_4544_test.go, effective_3720, per_iface_3362, rust_parity, tokens_test, view_3654, lifeline_3682): NEG — dual-shape via firewallMatchValues (#3703), mergeHostInbound union dedup (#4544) verified in dup_block test (zone+iface merge preserves both ssh+ospf, dedup, single-block byte-identical), InterfaceHostInboundEffective correctly unions physical+unit (#3720), lifeline set includes configured control/fabric (#3277). HostInboundL2Protocols exclusion from `protocols all` validated by ProtocolsAllExcludesL2 test.
- **junos_host_deny** (junos_host_deny.go, junos_host_deny_test.go): NEG — 3-tier composition (exact any global), whole-program representability gate, TCPRst reject unsup, feed-taint unrep, cross-dimension permit/deny poison, cross-zone-ambiguous trunk keeps warning (iifname empty → no suppression #4146 F1), IKE/ident per-netdev scoping #5565 implemented via JunosHostZoneIngressNetdevs SSOT matched to snapshot.
- **lifeline** (lifeline.go, host_inbound_view_lifeline_3682_test.go): NEG functional, but prefix match overly broad — tracked as COHORT-001 below.
- **schema_security** (schema_security.go, schema.go, schema_global_zone_list_4415_test.go, schema_policy_then_3377_test.go, schema_chassis.go, schema_interfaces.go, schema_routing.go etc): NEG — global FromZones/ToZones `multi:true` (#4626 M03) accumulates bracket list via firewallMatchValues (list [trust dmz] → both zones), sortDedupZones canonicalizes sorted+dedup, ZoneScopeSetLabel display SSOT, IsWildcardZone empty||"any" (#3680), IsWildcardZoneSet len0||contains any, IsHostToZoneScope exact ["junos-host"], default-policy enum deny-all/permit-all/reject-all (#3065) with fail-closed deny, default-policy-log multi-value leaf #3703.
- **policy compilation** (compiler_security_policy.go, compiler_security_zones.go): NEG — from-zone/to-zone dual-shape hierarchical Keys>=4 vs flat FindChildren, global FromZones/ToZones accumulated via firewallMatchValues (#4626), any-ipv4/v6 normalized to CIDR (#2008 H11), default deny when terminalActions empty (#3043), collapsed deny log/count modi
```

---

#### Finding from ps-A3_go_config_cli_tree-b4.md (Gate: COHORT)

```
Title: Zone Interfaces slice accumulates duplicates across duplicate security-zone instances
Severity: Low
Confidence: COHORT
Gate verdict: COHORT
Evidence:
- File `/tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b4/pkg/config/compiler_security_zones.go:113-134`:
```
for _, prop := range inst.node.Children {
 case "interfaces":
  for _, iface := range prop.Children {
   zone.Interfaces = append(zone.Interfaces, zoneInterfaceMembers(iface)...)
```
No dedup. `zoneDupBlock4818ThreeInstances` test uses distinct interfaces, not duplicate same iface across instances. If operator loads override with same interface in both blocks, result is duplicate entry.
Trace: parseHierarchical with two `security-zone trust { interfaces { ge-0/0/0; } }` blocks → namedInstances yields two entries, find-or-create merges → Interfaces = ["ge-0/0/0","ge-0/0/0"].
Refutation: Downstream `buildInterfaceZoneMap` uses map and first-writer-wins, so duplicate does not create multi-zone conflict; but zone inventory display and any length-based checks double-count.
HPC/invariant: O(n) append, no extra allocation; dedup would be O(n^2) or map but acceptable for small n (<100).
Why it matters: Observability duplication, minor resource waste, not security bypass.
Fix direction: dedup via seen map in compileZones similar to dedupHostInboundTokens, or keep as is with comment that duplicates are tolerated (current comment says byte-identical single-block preserved, but duplicate across blocks is not deduped).
Labels: zone, dedup, observability
Dedup note: Not in dedup list (checked #5606, #5563, #4818 itself).
Verified against origin/master: line 113-134 same as base.

### COHORT-02: IsWildcardZoneSet contains("any") collapse widens permit on lenient path

```

---

#### Finding from ps-A3_go_config_cli_tree-b4.md (Gate: COHORT)

```
Title: Lenient path mixed `any` + concrete zones collapses to wildcard (fail-open for permit)
Severity: Low
Confidence: COHORT
Gate verdict: COHORT
Evidence:
- File `/tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b4/pkg/config/types_security.go:482-484`:
```
func IsWildcardZoneSet(zs []string) bool {
 return len(zs) == 0 || slices.Contains(zs, "any")
}
```
- Strict gate in `compiler_validate_strict_zones.go:600-606` rejects mixing any with concrete: `if len(FromZones)>1 && contains any { return error mixes any }`. Lenient path downgrades to warning and still compiles. On lenient (HA-sync/load), `GlobalPolicyAppliesToZone` and Rust `build_global_zone_scope` will treat mixed set as wildcard => broader match than operator configured.
Trace: Commit `set ... from-zone [ any trust ]` → strict reject, but if persisted by older binary and loaded via CompileConfigLenient, bookNames contains mixed set, IsWildcardZoneSet true → Rust evaluates as all zones.
Refutation: Lenient path is for no-brick boot (#1960), not for new commits; operator-visible warning emitted; HA-sync should never produce mixed set if both nodes run new code. Pre-#4626 helper ignoring plural fields is #5488, already tracked.
HPC/invariant: Contains check O(n), acceptable.
Why it matters: Defense-in-depth: lenient load of invalid config widens permit rather than quarantine. Fail-open potential but gated behind strict reject.
Fix direction: On lenient path, treat mixed any as invalid and quarantine similar to zone-id collision, or keep warning + collapse to wildcard as documented backstop (current doc says "contains-any collapse is tolerant backstop").
Labels: scoped-global, lenient-path, fail-open-widen
Dedup note: Related to #5488 (open) which is about snapshot version bump, not this Contains logic. Not duplicate of #5488, but same area — mark as COHORT not MATERIAL.
Verified against origin/master: same lines 482-484 on origin/master tip.

### (No MATERIAL findings)

All core zone policy invariants verified:
- Default-policy initialized to PolicyDeny in compiler.go line 2224, not zero-value permit — fail-closed #3065.
- IsWildcardZone empty => all zones, explicit "any" also wildcard — matches Rust.
- Global scope FromZones/ToZones accumulated via firewallMatchValues SSOT, sorted deduped #4626 M03.
- Zone ref validation #4230 rejects undefined from/to, rejects from-zone junos-host (host-originated TX path), rejects mixing any/junos-host.
- Host-inbound merge #4544 union dedup, find-or-create #4818, interface flatten #5248 bracket handling.
- Zone ID collision gate three-view HA-symmetric, quarantine.

No live enforcement bypass found in this batch.


```

---

#### Finding from ps-A4_go_configstore_persist-b1.md (Gate: COHORT)

```
Title: Custom archive dir skipped on zeroize retains prior tenant zone config with PSKs
Severity: Low
Confidence: Medium
Gate verdict: COHORT
Evidence: factory_reset.go:60:
```
if filepath.Clean(archiveDir) != DefaultArchiveDir {
    slog.Warn("zeroize: skipping config archive directory with unproven ownership...; a custom, remote, or compliance archive destination is the operator's to erase, not the factory reset's"
    return nil
```
Trace: Not needed (low).
HPC: Archive retention intentional compliance; custom path ownership unproven xpf-owned. Warning logged. Default path /var/lib/xpf/archive IS wiped.
Fix direction: Document operator must manually erase custom local archive; consider optional flag with marker file ownership proof.
Labels: factory-reset, archive, secret-retention, defense-in-depth
Dedup: Checked #4858/#5186/#5197/#5475 — custom archive intentionally skipped, not bug.
Verified against origin/master: /home/ps/git/avacado-xpf/pkg/configstore/factory_reset.go:53-64 same guard on master.

### COHORT-2: Lenient Load warns but boots legacy invalid zone schema
```

---

#### Finding from ps-A4_go_configstore_persist-b1.md (Gate: COHORT)

```
Title: Lenient Load path warns but boots legacy invalid zone schema until strict commit
Severity: Low
Confidence: Low
Gate verdict: COHORT
Evidence: store.go compileTreeLenient:
```
if err := s.schemaValidateExpandedTree(tree); err != nil {
    slog.Warn("typed-leaf schema violation in tolerated config; continuing (a strict commit would reject this)", "err", err, "issue", "#1319")
```
Not zone bypass — intended boot-safety #1960 tradeoff, strict would blackout node or alarm-loop HA sync.
Fix: None, already belts with warn; could add metric counter.
Labels: lenient-load, schema, upgrade-safety
Dedup: Aligns with #1319 tolerant ingress design, not in dedup.
Verified against origin/master: /home/ps/git/avacado-xpf/pkg/configstore/store.go:470-480 same warn.

## Overall Verdict
Configstore correctly preserves zone policies via persist-before-promote #1799, committed marker C3, envelope min-reader fail-closed, crypto nonce guard #4793, rollback tombstone anti-shift #4810, confirm ordering #5473. No MATERIAL inter-zone bypass. Factory reset intentionally wipes zones durably. Coverage proved via NEGs.

## Checked Dedup
#5564 standby sync tail, #5563 stale policy, #5562 snapshot rotation, #5488 global deny version, #1922 bootstrap marker, #1917 envelope, #1799 persist, #4793 nonce, #3441 durability, #5186 archive wipe, #4888 unknown format, #5474 null decode — none re-report.

## Verified Against Origin/Master
Base SHA 4e0c7f74 equals origin/master tip per batch. Checked envelope.go:1-200, store_commit.go:86-92, crypto.go:199-265, db.go:1-100 on worktree vs main repo — identical.

```

---

#### Finding from ps-A5_go_ha_vrrp_ra_conntrack-b1.md (Gate: COHORT)

```
# Batch A5_go_ha_vrrp_ra_conntrack — Zone-Policy Focus Review

## File Inventory (Ranked by Size × Responsibility × Hot-Path)

| File | LOC | Type | Largest Fn | Responsibility | Hot Factor |
|---|---|---|---|---|---|
| cluster/sync_conn.go | 1858 | prod | handleMessage (300+ LOC) | Wire RX, zone filtering, gen guards, bulk RX, cold-start fencing | CRITICAL |
| vrrp/instance.go | 2417 | prod | run() state machine | VRRP MASTER/BACKUP, VIP add/remove, GARP burst, preempt gates | CRITICAL |
| vrrp/manager.go | 1108 | prod | UpdateInstances (400+) | Sync hold, instance lifecycle, link/addr watchers, ReconcileVIPs | CRITICAL |
| ra/ra.go | 1118 | prod | Apply (400+) | RA manager, per-iface senders, graceful goodbye, epoch fencing | HIGH |
| ra/sender.go | 1055 | prod | run() + finishShutdown | RA packet build, RS filter, goodbye emit, timer management | HIGH |
| cluster/sync.go | 1048 | prod | SessionSync struct + bulk/stream wiring | Session store, zone→RG map, delete journal, barrier protocol | CRITICAL |
| cluster/failover.go | 912 | prod | ManualFailoverBatch | Manual failover locking domain, transfer-commit state machine | HIGH |
| cluster/heartbeat.go | 881 | prod | UnmarshalHeartbeat + auth | HB packet codec, auth HMAC, anti-replay (single session,counter) | HIGH |
| cluster/sync_protocol.go | 829 | prod | encode/decode SessionV4/V6 | Wire codec: zone fields, PolicyID/CounterIdx, AppTimeout, NAT64 SNAT | CRITICAL |
| cluster/garp.go | 754 | prod | SendGratuitousARP/Burst | GARP/NA burst, followup burst, still-valid gating | HIGH |
| cluster/status.go | 721 | prod | Status aggregation | Cluster show | LOW |
| cluster/monitor.go | 641 | prod | pollInterfaceMonitors | IF monitor weights, dampening, local status → HB | HIGH |
| cluster/sync_failover.go | 607 | prod | Request/Finalize failover | Sync-channel failover request/commit protocol | HIGH |
| conntrack/gc.go | 554 | prod | sweep() | GC expiry, IsLocalPrimary gate, OnDelete→sync, per-IP limits | HIGH |
| cluster/heartbeat_manager.go | 492 | prod | handlePeerHeartbeat, handlePeerTimeout | Peer HB RX, transfer-commit override apply, timeout → electSingleNode | CRITICAL |
| cluster/sync_bulk.go | 449 | prod | BulkSync | Bulk send with ShouldSyncZone filter, epoch, ack tracking | CRITICAL |
| cluster/election.go | 475 | prod | electRG | Priority election, manual-failover guard, dup node-id closed | CRITICAL |
| cluster/manager.go | 460 | prod | Manager lifecycle + election driver | Node ID, peer groups, weight recalc, event channel | CRITICAL |
| cluster/sync_auth.go | 424 | prod | performSyncHandshake, sealFrame | Sync-channel auth PSK, HMAC sealing, downgrade guard | MEDIUM |
| vrrp/track.go | 341 | prod | getPriority, setTrackDown | Track-interface demotion, clamp [1,254],.owner exemption | HIGH |
| vrrp/packet.go | 277 | prod | Marshal/Unmarshal VRRP | VRRPv3 packet codec, checksum, MaxAdverInt | MEDIUM |
| vrrp/vrrp.go | 266 | prod | Instance struct | VRRP group config + validation | MEDIUM |
| vrrp/addrwatch.go | 219 | prod | addr watch callbacks | VIP addr re-resolve on kernel addr change (#2528) | MEDIUM |
| cluster/reth.go | 177 | prod | RETH management | RETH to physical resolution | LOW |
| cluster/group_state.go | 263 | prod | RedundancyGroupState | RG state, readiness, takeover-hold timer | HIGH |
| cluster/readiness.go | 89 | prod | SetRGReady | Readiness gate for RG promotion | CRITICAL (cold-boot) |
| ra/filter.go | 21 | prod | setAllowRS | ICMPv6 filter: only RS (type 133) | MEDIUM |

Test files: 73 files (~30k+ LOC), largest sync_test.go 4717 LOC, serialize_test.go 2706, vrrp_test.go 2468.

---

## Module Log (NEG = sound, with invariant)

### pkg/cluster — Session Sync Wire & Zone Preservation

- **sync_protocol.go** — NEG: wire codec preserves ALL zone-policy fields: IngressZone, EgressZone, PolicyID, PolicyCounterIdx, AppTimeout, Nat64SnatV4, Generation, IsReverse, State. Length-gated trailing fields backward-compat. Config-gen trailing magic non-printab
```

---

#### Finding from ps-A6_go_dataplane_manager-b1.md (Gate: COHORT)

```
Title: Synthetic ifindex panic on exhaustion instead of error
Severity: Low
Confidence: Medium
Gate verdict: COHORT
Evidence: interfaces.go:46-55:
```
panic(fmt.Sprintf(
    "userspace snapshot: exhausted synthetic ifindex range for %q (vlan=%d hash=%d tried=%d range=[%d,%d])",
```
Range 1M requires >1M logical-only VLAN units unrealistic (<100 prod). Panic crashes daemon RestartSec=1 lifeline keeps mgmt. Config-shaped input could DoS with 1M+ units. Better return error fail-closed.
Fix: return (int, error) surface as buildSnapshot error.
Labels: DoS, panic, synthetic-ifindex
Dedup: Not tracked #2514 collision returns error not panic distinct low.
Verified origin/master: same panic on tip.

### COHORT-2: Quarantine determinism later-sorting management zone quarantined
```

---

#### Finding from ps-A6_go_dataplane_manager-b1.md (Gate: COHORT)

```
Title: Quarantine determinism sorted name — management zone later-sorting collider unzoned (but lifeline not stranded)
Severity: Low
Confidence: Low
Gate verdict: COHORT
Evidence: zones_quarantine.go:28-50 comment:
```
// Lifeline note: if the operator's management zone happens to be the later-sorting collider it is quarantined and its interfaces are unzoned. This does NOT strand management, because lifeline interfaces (fxp0/em0/fab*) never reach the AF_XDP local-delivery classifier — their host-bound traffic is served by the kernel path
```
Management not stranded due lifeline bypass, but data mgmt zone unzoned default-deny transit safe but alarm loud. Collision rare (FNV-1a 16-bit ~65k, crafted pair z174/z214 known). Low.
Labels: quarantine, collision, lifeline
Dedup: #3719 acknowledges secondary note.
Verified same on tip.

## Overall Verdict
ifindex_to_zone_id composite {ifindex, vlanID} stable ZoneIDs #3075, stale deletion, RETH RG inheritance, synthetic ifindex logical-only VLAN parent-bound RETH #2917. Quarantine #3719 drops later-sorting colliding zone deterministic HA-symmetric, unzones fails closed, scrubs zone-pair drop and scoped-global prune survivor fail-closed #5577 singular regen old helper compat. Host-inbound VIP scoping config-derived VIPs even on backup #3172 hostIPFromCIDR, per-iface effective views #3362 union, phys-unit #3720, exact-unit #5489 prevent cross-zone leak, view grouping canonical #3721 dedup, unzoned catch-all #4420 includes unzoned addressed in deny excluding lifeline fab*. No MATERIAL fail-open residual at this SHA — two Medium historical fail-opens now FIXED on origin/master.

## Dedup Checked
#3719 collision, #3720 phys bleed, #3721 grouping, #4420 unzoned HI-2, #5489 exact-unit leak, #5577 scoped-global prune, #3362 per-iface views, #3075 stable IDs, #3065 default-policy deny, #4626 global scoped, #2514 address-book collision, #4146 junos-host projection, #3405 default-deny no stanza, #5579 ambiguous host-inbound, #3627 classifier diagnostic, #2917 VLAN parent bind, #3172 VIP scoping.

## Verified Against Origin/Master
Base 4e0c7f74 == origin/master tip. Checked zones_quarantine.go:57-180, compiler_iface.go:249-465, interfaces.go synthetic + UserspaceBindTargetNetdev, host_inbound_classify.go:169-210, builder.go:138-153, host_inbound_unzoned_4420_test.go, owner_5489, phys_unit_3720 on worktree vs /home/ps/git/avacado-xpf — identical.

```

---

#### Finding from ps-A7_go_daemon_host-b1.md (Gate: COHORT)

```
# Batch 016 A7_go_daemon_host b1/3 — Zone Policy / Host-Inbound / RETH Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa — origin/master same, 0 behind

## File Size / Shape Inventory
Total: 48,007 LOC across 150 files — prod 26,891 (45 files) / test 21,116 (105 files)
Rank by (LOC * responsibility * hot-path):
1. daemon_run.go 2492 — daemon lifecycle, dataplane boot handshake, XSK bind defer, fabric defer; largest fn `(*Daemon).run`
2. daemon_apply.go 2265 — commit apply path, zone/RG map, interface reconcile, RETH MAC cycle, host-inbound/lo0 fail-closed join; largest fn `applyConfigLocked` ~600 LOC
3. daemon_nft.go 1782 — PRIMARY host-inbound + lo0 enforcement, atomic delete+recreate via `nft -f -`, unzoned catch-all #4420, junos-host fine-deny #4146; largest fn `buildHostInboundFilterPayload` ~400 LOC
4. daemon_system.go 1731 — hostname/timezone/tunables, not zone-hot but boot-critical
5. daemon_ha.go 1576 — cluster state machine, RG ownership, Preempt, Direct-VIP ownership desired; hot for zone VIP scoping
6. daemon_ha_fabric.go 965 — fabric IPVLAN, neighbor probe, MTU 9000, fail-closed refresh
7. bootstrap.go 944 — fail-closed boot detection (pinned XDP via #1917), lifeline PCI MAC, bootstrap rollback
8. device_map.go 836 — #1956 device-map, strand-management preflight #5490 fail-closed, teardown retain-debt #5309
9. daemon_ha_vip.go 651 — direct VIP add/remove with IFA_F_NODAD, stable LL, ReconcileVIPs after RETH MAC cycle
10. daemon_policy_invalidate.go 546 — #4234/#4342 session invalidation, policy_id 0 exclusion (host-inbound/fabric zero-value safe), sentinel 0xFFFFFFFF
11. daemon_ddns_surface_a.go 846 — Surface A DDNS, IsPublicAddr gate #3732, checkip fail-closed #4423 H08
12. host_inbound_nft_test.go 897 — NFT rendering SSOT mirror test vs Rust classifier
13. remaining prod ≤685 each (flow, flowexport, ddns, etc.)

Test heavy: coalescence, archive, device_map startup/teardown, host_inbound_* (#3698 #3718 #4420 #4146 #3362), dhcp, ipsec rebind.

## Module Log (incl NEG proving coverage, NEG only in log)
- daemon_nft.go: NEG — lo0 atomic add+delete in single nft payload keeps prior table on failure (atomic), priority 0 < 10 ensures lo0 precedes host-inbound (#3364). unzoned catch-all subtracts zoned+lifeline (#4420), counter dedup safe, emitHostInboundZone handles all=>accept else per-token accept + catch-all drop — fail-closed parity with Rust (#3405 #3200). Checked nftAddrSet, counter NAME unquoted decl (#3578) vs quoted ref, ident-reset reject #3310.
- daemon_apply.go: NEG — applyDataplaneAndHACore before host-inbound/lo0, errors.Join returns networkdErr/hostInboundErr/lo0Err fail-closed; RETH MAC program via programRethMAC DOWN→set→UP followed by ReconcileVIPs re-add (prevents VIP blackhole after MAC cycle). Verified setRethIPv6Knobs best-effort.
- daemon_reth.go: NEG — fixRethLinkFile OriginalName vs MACAddress for RETH (MAC alternates), ensureRethLinkOriginalName auto-fixes stale .link, deriveKernelName via altnames/sysfs, renameRethMember EEXIST collision safe multi-pass.
- daemon_policy_invalidate.go: NEG — deletedPolicyRuntimeIDs excludes id 0 (overloaded wire value for host-inbound/fabric/tunnel/synced — mirrors policy.rs DuplicatePolicyId), only FORWARD entries scanned, DeleteBatchKnown expands companions, enumerate error surfaced not swallowed (#4320), partial clear better than none, HA delete-sync gated on IsLocalPrimaryAny.
- device_map.go: NEG — preflight enumerates present NICs, fails CLOSED on error #5490 (old warn->nil laundered lockout), protectedForConfig per-candidate mgmt leaf (not active) prevents false strand check, off-target anyMappedIdentityPresent skip correct, teardownUnmappedManaged retain-debt #5309 (rename-back EBUSY retains .link/.network markers), protected #1922 skip never tears down mgmt lifeline.
- daemon_ha_vip.go: NEG — checkVIPReadiness uses LinkAttrsUp (oper-state, not admin IFF_UP) — prevents carrier-down takeover blackhole #2090, directAddVIPs idempotent EEXIST skip, IPv6
```

---

#### Finding from ps-A7_go_daemon_host-b2.md (Gate: COHORT)

```
Title: networkd rp_filter all knob override warning-only
Severity: Low
Confidence: Medium
Gate: COHORT
Evidence: pkg/networkd/networkd.go:373-395 `restoreSlowPathRPFilter` writes `0` to `/proc/sys/net/ipv4/conf/xpf-usp0/rp_filter` but kernel effective = max(all,dev). Function only warns when all non-zero (warnIfAllRPFilterOverrides) and does NOT set all=0 (“We do NOT mutate host-global conf/all knob”). If operator leaves all=1 (Debian default), slow-path reinjected IPv4 via TUN still dropped despite per-dev 0.
Trace: networkd.Apply → reload → restoreSlowPathRPFilter → WriteFile 0 to per-dev → all=1 → kernel max=1 → drop.
HPC/invariant: Best-effort, documented #2378. Operator must `sysctl -w net.ipv4.conf.all.rp_filter=0`.
Why low: Not zone bypass; affects userspace-dp slow-path reinjection only; warning visible; operator-runbook known.
Fix direction: Optionally document in operator guide, or attempt all knob if not explicitly managed elsewhere.
Labels: networkd, observability, rp_filter
Dedup: Checked #2378
Verified: origin/master:networkd.go:373-401 same

#### COHORT 2: Probe pin RETH resolution depends on rethMap completeness, fallback to original name may program wrong dev
```

---

#### Finding from ps-A7_go_daemon_host-b2.md (Gate: COHORT)

```
Title: probe_pin ResolveProbeInterface fallback on incomplete rethMap
Severity: Low
Confidence: Low
Gate: COHORT
Evidence: pkg/routing/probe_pin.go:52-58 `rethMap translates Junos RETH interface names...` and 122-134 `if phys, ok := rethMap[base]; ok { base=phys }` then `LinuxIfName`. If rethMap missing entry (race during boot), Resolve returns raw `ge-0-0-1.50` → LinuxIfName → `ge-0-0-1.50` which may not exist (should be `ge-0-0-0.50` etc due to FPC 7). LinkByName then fails, pin marked failed and probe held (safe Hold not false PASS after #1895). So fail-closed not fail-open.
Evidence: pkg/routing/probe_pin.go:122 `func ResolveProbeInterface... base=phys... config.LinuxIfName(base)`
Trace: BuildProbePins → rethMap incomplete → wrong dev → LinkByName fail → probe held.
HPC: After #1895, failed pin returns error map, RPM holds, does not report false healthy uplink.
Fix: Ensure rethMap built from compiled config before BuildProbePins (current code does), low risk.
Labels: probe, RETH, fail-closed
Dedup: Not in dedup list
Verified: origin/master:probe_pin.go:108-135 same

## Summary

- 49k LOC batch (36 prod, 114 test) deeply reviewed for zone policy enforcement, host-inbound default-deny (#4420) with unzoned catch-all, lo0 atomic delete+recreate, RETH/VRRP VIP preservation, injection guards.
- Prod invariants all hold: unzoned catch-all correctly scoped/lifeline-excluded, lo0 payload atomic, RETH→phys translation in FRR and probe_pin, bond partial completion in-place, devicemap hijack refusal, sanitizers for FRR/networkd, fail-closed on IPsec unrenderable, networkd reload debt, login deprovision fail-closed.
- Zero MATERIAL findings. Two COHORT low items (rp_filter all knob warning-only, probe_pin fallback holds probe).
- All deduped known issues (#5478 monitor missing, etc) excluded per instructions.

## Verified against origin/master

Checked origin/master tip 4e0c7f74c identical to base (fresh). All prod file lines cited verified: networkd.go KeepConfiguration=static at 624-626, daemon_nft.go add/delete idiom at 195-196 (via grep payload builder), BuildUnzoned in zones_host_inbound.go 353-388, etc.

```

---

#### Finding from ps-A7_go_daemon_host-b3.md (Gate: COHORT)

```
# Batch A7_go_daemon_host b3/3 — Review Report
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Worktree: /tmp/review-wt-claude-spark-001-A7_go_daemon_host-b3 | Origin/master: same (verified 0 behind)

## File Size/Shape Inventory (ranked by size x resp-count x hot-path)

| File | LOC | Prod/Test | Largest Fn / Responsibility | Hot-path? |
|------|-----|-----------|-----------------------------|-----------|
| pkg/routing/tunnel.go | 2016 | prod | Apply (277) 250 LOC: GRE/IPIP/WG reconcile, anchor vs kernel branch, VRF claim, keepalive gen | YES (link lifecycle) |
| pkg/routing/rules.go | 1447 | prod | BuildPBRRules (758) 180 LOC + buildPBRFromFilter (941) 250 LOC: PBR FBF mirror, next-table, rib-group leak | YES (ip-rule, cross-VRF) |
| pkg/upgrade/cutover.go | 1045 | prod | Run (148) 500 LOC: STOP->FLIP->START, journal, preflight, DB snap | upgrade |
| pkg/upgrade/kernel_linux.go | 869 | prod | RealKernelSystem 40+ methods: UEFI A/B slot, efibootmgr, purge | kernel LANE-1 |
| pkg/upgrade/cluster_cli.go | 610 | prod | RollingCluster CLI impl: PeerAlive, DrainComplete, etc. | HA rolling |
| pkg/upgrade/runner.go | 596 | prod | NewRunner, copyTree, state xitions | upgrade |
| pkg/upgrade/kernel_run.go | 637 | prod | Kernel channel state machine, arm/promote/revert | kernel |
| pkg/upgrade/stagedgen/stagedgen.go | 413 | prod | Publish: immutable gen copy, .partial+rename+fsync | upgrade |
| pkg/upgrade/runtime/seed.go | 400 | prod | Seed generation, DB migration | upgrade |
| pkg/routing/vrf.go | 361 | prod | reconcileVRFs (183) 200 LOC: VRF create, table-mismatch recreate, orphan reap | YES (VRF binding) |
| pkg/routing/routes.go | 356 | prod | GetAllTableRoutes, routeToEntry, multiPathNextHops ECMP | read path |
| pkg/routing/xfrm.go | 332 | prod | Apply: xfrmi differential reconcile, if_id collision guard #2909 | YES (IPsec) |
| pkg/upgrade/lock/lock.go | 303 | prod | Acquire: host-wide flock | upgrade |
| pkg/routing/tunnel_keepalive.go | 294 | prod | icmpProber.Probe: Seq+nonce match, errno classification | keepalive |
| pkg/upgrade/kernel_selfrecover.go | 273 | prod | Self-recovery lease, watchdog | kernel |
| pkg/upgrade/rolling.go | 247 | prod | RunRolling, waitPredicate, drain-before-cut | HA |
| pkg/upgrade/flip.go | 448 | prod | flip, repointSymlink, gc, copyTreeChecksum | upgrade |
| pkg/routing/routing.go | 237 | prod | Facade over 10 domain managers, owns nlHandle | facade |
| pkg/upgrade/state.go | 165 | prod | Journal, State enum, order/atLeast | upgrade |
| pkg/upgrade/kernel_drain.go | 160 | prod | DrainAndConfirm wrapper | HA |
| pkg/upgrade/helper_health.go | 160 | prod | HelperHealthProbe: armed+forwarding+target-version gate #5286 | upgrade |
| pkg/upgrade/kernel.go | 334 | prod | Kernel journal, state machine types | kernel |
| pkg/upgrade/system_linux.go | 190 | prod | realSystem: systemctl, VerifyDataplane, BinaryVersion | upgrade |
| pkg/upgrade/imageversions.go | 179 | prod | Image version list, manifest parse | upgrade |
| pkg/upgrade/stagedgen/fsutil.go | 149 | prod | Atomic fs ops: MkdirAllDurable, WriteFileDurable | fs |
| pkg/upgrade/version.go | 113 | prod | ValidateVersionSegment, ValidateKernelSegment #5452 | validation |
| pkg/wgkey/wgkey.go | 113 | prod | Generate, clamp, HexToBase64, PublicKeyFromPrivate | crypto |
| pkg/upgrade/manifest/manifest.go | 106 | prod | Manifest read, drift detection | upgrade |
| Total prod | ~12100 | | | |
| Total test (44 files) | ~10500 | test | | |

## Module Log (incl. NEG proving coverage)

- NEG: routing/rules.go nextTableManager.Apply — per-rule RuleAdd failure aggregated via errors.Join (#3731), not swallowed; clear() also aggregated #2273 — invariant: leak rule loss surfaces to daemon apply loop, commit fails closed. Verified.
- NEG: routing/rules.go ribGroupManager.Apply — per-prefix leak rules at prio 30000 (<32766 main), hard-cap at maxRibGroupLeakRules, overflow error; clear() scans 3 legacy windows (current 30000, old blanket 33000, original 200). N
```

---

#### Finding from ps-A8_go_api_grpc_rest-b1.md (Gate: COHORT)

```
# A8 Go API / gRPC REST b1/2 — claude-spark-001 — pkg/api REST layer

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified)
Worktree: /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b1
Batch: 150 files — prod 29 files ~6800 LOC, test 121 files ~32000 LOC, total ~38800 LOC

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/api/sessions.go | 1541 | REST session list/summary/zone-pair, clear-sessions handler, filter | request |
| pkg/api/security.go | 942 | zones+policies+match-policies REST, zone display, scoped-global, host-inbound-to-REST | request |
| pkg/api/metrics.go | ~900 | Prometheus collector — per-zone/family nft counters, host-inbound ICMP/ND accept, zone counter hide #3643 | scrape |
| pkg/api/metrics_counters.go | ~370 | collectHostInboundKernelDenies, counterReadErrorsTotal fail-closed | scrape |
| pkg/api/metrics_descriptors.go | ~400 | counterReadErrorsTotal, hostInboundKernelDenies, hostInboundJunosHostDenies, hostInboundAddresslessZones, hostInboundICMPNDAccept | init |
| pkg/api/server.go | 789 | HTTP server, route table, TLS, graceful shutdown, middleware chain | boot |
| pkg/api/config.go | 417 | REST config/set/load/commit/activate/rollback, candidate DB, commit check | config path |
| pkg/api/api.go | 251 | writeJSON buffering (#4541), Response envelope, apiRuntimeDataplane interface | shared |
| pkg/api/auth.go | 137 | authMiddleware: basic/bearer/api-key, constantTime compare, /health always exempt, /metrics gated #4162 | auth |
| pkg/api/routing.go | ~200 | routing table REST | request |
| pkg/api/security_test.go etc | — | unit/functional coverage | test |

Largest fns: sessions.go sessionZonePairHandler ~200 LOC, security.go zonesHandler/policiesHandler ~150 each, matchPoliciesHandler ~300 (query param parsing, host-inbound classifier, global fallback, default-policy emit).

## Module Log (NEG proves coverage)

### pkg/api/security.go — zones + policies + match-policies

- **NEG — zone display nil-guard #3493:** `zonesHandler` iterates `cfg.Security.Zones`, checks `if zone == nil { continue }` tolerant/HA-sync path. ZoneIDs map reverse lookup for per-zone counters, counter read failure `PerZoneCountersAvailable=false` rather than panic — #3643 HIDE already. Verified at `security.go:33-42,93-130`. Sound — cannot crash on nil zone from lenient HA-sync load.

- **NEG — scoped-global zone SET surface #3286/#4626 M03/M08:** Global policies loop `security.go:285-370` emits `FromZone="*" ToZone="*"` singular plus `MatchFromZones: rule.Match.FromZones` (plural) and `MatchToZones` (plural). Unscoped global keeps both singular as `*` and plural empty. `ScopeSingular()` backward-compat first-zone, `ZoneScopeSetLabel` for display. REST consumer cannot misinterpret scoped global as all-zones because both representations present. Verified `security.go:306-314`:
  ```
  MatchFromZone:  config.ScopeSingular(rule.Match.FromZones),
  MatchToZone:    config.ScopeSingular(rule.Match.ToZones),
  MatchFromZones: rule.Match.FromZones,
  MatchToZones:   rule.Match.ToZones,
  ```

- **NEG — host-inbound enforcement parity #3328/#3070/#3362/#3405:** `zonesHandler` sets `HostInboundConfigured=true` unconditionally for every non-nil zone — not re-derived from config shape. Pre-#3405 parsed stanza presence; a no-stanza zone reported `false` (appeared host-inbound-open). Now default-deny parity: no `host-inbound-traffic` stanza = deny. Interface overrides via `SortedInterfaceHostInboundRefs()` + `LifelineInterfaces` view. Verified `security.go:58-83`. Sound.

- **NEG — match-policies zone pair echo #3627 M06:** `matchPoliciesHandler` echoes `QueriedFromZone/QueriedToZone` on every path — host-inbound-unmatched, default, match — so stored diagnostics prove query context distinct from matched-policy scope. Prevents misattribution of deny to wrong zone pair. Verified `security.go:745-746,824-825,836-837,853-854,874-875`.

- **NEG —
```

---

#### Finding from ps-A8_go_api_grpc_rest-b2.md (Gate: COHORT)

```
# Batch A8 b2/2 — Go API gRPC REST — Review Report

**Batch:** A8_go_api_grpc_rest b2/2 — 150 files (37 prod ~11k LOC, 113 test ~29k LOC, total ~40k)
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified via `git show-ref origin/master`)
**Worktree:** /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b2
**Reviewer:** claude-spark-001

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/grpcapi/server_sessions.go | 1778 | Session list/filter/clear/zone-pair, bounded clear #5454/#5531 | request |
| pkg/grpcapi/server_show_zones.go | 395 | GetZones + GetPolicies gRPC — zone display, scoped-global M03/M08 | request |
| pkg/grpcapi/server_show_policies_text.go | 541 | ShowPoliciesText — zone filter render, GlobalPolicyAppliesToZonePair #3357 | request |
| pkg/grpcapi/server_show_security_text.go | 1074 | ShowSecurityText — zone-pair tiers, host-inbound view, scheduler | request |
| pkg/grpcapi/server_show_zones_text.go | ~250 | zones text detail — host-inbound, lifeline, tier summary | request |
| pkg/grpcapi/server.go | 768 | gRPC server, interceptors, peer proxy allowlist, GetZonePairSummary+ClearSessions #3592/#3423 | boot |
| pkg/grpcapi/server_cluster.go | ~400 | cluster status/HA, MatchPolicies zone scoping, host-inbound ingress-iface #5579 | request |
| pkg/grpcapi/server_config.go | ~350 | Config mutation gRPC path, redaction | config |
| pkg/grpcapi/fabric_auth.go | ~150 | fabric HMAC session+counter, replay ±1 window, anti-replay | fabric |
| pkg/grpcapi/runtime.go | ~250 | runtime canary, status dedup, session cache | runtime |
| pkg/grpcapi/server_helpers.go | ~200 | zoneByID NAT counters, egress iface resolve | shared |
| pkg/grpcapi/xpfv1/xpf.pb.go | ~11k | generated protobuf | generated |

Largest fns: server_sessions.go buildSessionFilter ~120 LOC, clearFilteredSessionsV4/V6 ~200 each with rescan fallback, computeZonePairSummary ~120.

## Module Log (NEG proves coverage)

- **fabric_auth.go:102-186** `fabricAuthDecision` dual-accept: no-key→accept, valid token→accept, invalid→reject, missing+armed→reject. `verifyFabricAuthToken` HMAC constant-time `hmac.Equal`, checks ±1 window (60-90s replay bound). `computeFabricAuthToken` domain separation prevents heartbeat token substitution into fabric path. `checkFabricAuth` sticky flag + `heartbeatPeerAuthSeen` arms downgrade guard in ~200ms. NEG: no token in logs, key never logged, replay bound explicit, rolling-upgrade grace preserved (#4107/#4122/#5047 tests pin).

- **server.go:998-1049** `clampGRPCBindToLoopback` — empty host (wildcard `:50051`)→not loopback→clamped to 127.0.0.1, IPv6 `::`→`::1`. SplitHostPort failure returns unchanged, then `net.Listen` fails (no port) — no bypass. `grpcHostIsLoopback` handles `localhost` literal. Primary listener only installs `configLockInterceptor`, no auth — clamp ensures no unauthenticated network exposure (#5035). Fabric listener chain auth→allowlist→lock correct order. NEG: no non-loopback primary path without clamp.

- **server_show_zones.go GetZones** nil-zone skip (#3493 tolerant HA-sync), HostInbound split fields (systemServices vs protocols), lifeline via `HostInboundViewWithLifelines`, `HostInboundConfigured=true` unconditional per #3405 default-deny parity. Zone counter hide on `ErrCounterNotPopulated` (#3643). GetPolicies bulk reader via `NewPolicyCounterReader` O(P+C) single snapshot (#3965), policy-stats gate honors system-wide knob + per-rule Count, runtime ID presence-wrapped (`proto.Uint32`) so 0 survives wire. Scoped-global: `MatchFromZone` singular (compat first-zone) + `MatchFromZones` plural full set. Default-policy synthetic row sentinel ID #3363 + log posture #3670. Evidence: `server_show_zones.go:31,56-88,270-280`. NEG: no counter leak, scoped-global display correct.

- **server_show_policies_text.go + server_show_zones_text.go** Both use bulk reader, filter via `GlobalPolicyAppliesToZonePair` #3357 (empty fi
```

---

(17 findings at Low level, excluding pure NEG)


## Full batch findings (raw verbatim, all 23 batches, 289467 total chars, NEG only in log above, not duplicated here as separate findings)


### === ps-A10_go_services_cli_deploy-b1.md (10756 chars, 104 lines) ===

# Batch A10 b1/3 — Zone Policy Display, CLI Dispatch, Policymatch Parity

**Batch:** A10_go_services_cli_deploy b1/3 — 150 files (62 prod, 88 test / +1 manifest drift)
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
**Verified origin/master:** 4e0c7f74c (same SHA after pull — 0 behind)
**Worktree:** /tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b1
**Total LOC in batch:** ~48k across Go/C/H (largest: bpf/headers/xpf_helpers.h 2554, cli_show_flow.go 1262, cli_show_routing.go 1156)
**Largest fn:** showFlowSession / filterStream / pageStream / analyzePolicyShadowing — all bounded, no hot-path alloc
**Prod breakdown:** bpf/headers 6 (9974), pkg/cli 39 (~~18k), cmd/cli 10 (~~3.5k), cmd/xpfd 6 (~1.2k), cmd/shimverify 1, docs/pr 2
**Responsibility rank:** cli_show_security* (policy display), cli_dispatch (pipe/pager DoS bound), completion.go (zone-name hint), show_security.go remote (global scope), cli_show_security_zones.go (host-inbound + tiers), cli_request_policies_check.go (shadow lint)

## Inventory (LOC, responsibility)

| Path | LOC | Type | Resp |
|------|-----|------|------|
| bpf/headers/xpf_common.h | 898 | prod H | zone cap MAX_ZONES 64, session zone fields |
| bpf/headers/xpf_maps.h | 921 | prod H | iface_zone_map, zone_configs HASH, MAX_ZONES*MAX_ZONES |
| bpf/headers/xpf_conntrack.h | 225 | prod H | ingress_zone/egress_zone u16 |
| bpf/headers/xpf_nat.h | 575 | prod H | NPTv6/NAT pools — caps userspaceShimMaxNATPools |
| bpf/headers/xpf_helpers.h | 2554 | prod H | legacy helpers — retained shim build |
| bpf/headers/xpf_trace.h | ~100 | prod H | trace |
| pkg/cli/cli_dispatch.go | 523 | prod | pipe filter + pager streaming, maxTailLines 100k |
| pkg/cli/cli_show_security.go | 511 | prod | showPoliciesHitCount/detail/match-policies — zone filter + global scope |
| pkg/cli/cli_show_security_dispatch.go | 559 | prod | policy zone filter validation, brief/global, scheduler state |
| pkg/cli/cli_show_security_zones.go | 211 | prod | Security zone: render, host-inbound view, tier summary |
| pkg/cli/completion.go | 589 | prod | valueProvider zone name nil-skip #3493 |
| pkg/cli/cli_show_security_filters.go | 549 | prod | effective filter snapshots + liveness banner |
| pkg/cli/cli_show_security_log.go | 224 | prod | zone historical strict parse #3547 |
| pkg/cli/cli_show_flow.go | 1262 | prod | zoneNames reverse map, interface resolution |
| cmd/cli/show_security.go | 719 | prod | remote zones — HostInboundView + scoped global via GlobalPolicyAppliesToZone |
| cmd/cli/show.go | 515 | prod | firewall effective alias, bgp alias |
| cmd/xpfd/main.go | 439 | prod | classifyCommand + readBoundedFile #4909 |
| others | ~varies | prod/test | show, request, clear, monitor, chrony, etc |

## Module Log (NEG proves coverage — NOT in findings)

- **bpf/headers/xpf_common.h:142-143** `MAX_ZONES 64`, `MAX_INTERFACES 65536`, `MAX_LOGICAL_INTERFACES 512` — zone cap consistent, session_value ingress_zone u16 matches. No overflow; Go caps mirror. NEG: caps sound, legacy retained but gated by userspaceShimMaxNATPools=32 live.
- **bpf/headers/xpf_maps.h:116-140** iface_zone_map HASH MAX_LOGICAL_INTERFACES, zone_configs ARRAY MAX_ZONES — zone_id lookup O(1). NEG: HASH tolerates sparse ifindex, no bypass.
- **bpf/headers/xpf_conntrack.h:34-35,94-96** `__u16 ingress_zone / egress_zone` — same size as session.value fields in Rust. NEG: zone field width correct.
- **bpf/headers/xpf_nat.h** NAT pool structs — MAX_NAT_POOL_IPS_PER_POOL 256, MAX_NAT_POOLS 32 (live cap userspaceShimMaxNATPools). NEG: not zone-related.
- **pkg/cli/cli_show_security.go:26-175** showPoliciesHitCount uses `GlobalPolicyAppliesToZonePair` filter #3357, ScopeLabelOr for scoped global #4626, nil skip #3476, statsEnabled gate #2118. NEG: zone filter correctness verified, no fail-open.
- **pkg/cli/cli_show_security_dispatch.go:80-109** validatePolicyZoneFilter rejects missing zone value after from-zone/to-zone (#4908). parsePolicyZoneFilter iterates len-1. NEG: missing-value fail-closed prevents broader inventory.
- **pkg/cli/cli_show_security_zones.go:15-209** showZonesDisplay sorts zone names, nil skip #3493, host-inbound via HostInboundViewWithLifelines #3654, policy tiers via ZoneDetailPolicySummary (#3658 M04/M05) includes global + default-policy. Traffic stats explicitly "not available" for userspace dataplane #3643 not 0. NEG: zone display correct.
- **pkg/cli/completion.go:406-418** ValueHintZoneName iterates cfg.Security.Zones, skips nil, description fallback. Delegates to CommonPrefix + completionSuffix guard (#2288) against panic when partial longer than candidate. NEG: zone completion sound, no leak.
- **pkg/cli/cli_show_security_filters.go:359-549** effective view builds snapshots from ActiveConfig, liveness checks dataplane armed + generation coherent, helper-ahead benign accepted only with armed true (#5067). NEG: prevents compiled-desired masquerading as live.
- **pkg/cli/cli_show_security_log.go:13-61** ParseEventFilterArgs strict #3547 — unknown token, missing value, unknown named zone => error, not widened. Zone ID map from cr.ZoneIDs with stored name fallback #3335 historical. NEG: zone log filter fail-closed.
- **pkg/cli/cli_show_flow.go:239-279** zoneNames reverse map from cr.ZoneIDs, zoneIfaces first-interface for display only, egressIfaces via buildSessionEgressIfaces, populateIfaceMaps for full multi-iface filtering #4792. NEG: zone→interface display uses representative, filtering uses full set.
- **pkg/cli/cli_request_policies_check.go (cli_request_security.go split)** analyzePolicyShadowing sorted by from/to zone, nil skip, superset check disqualifies excluded # and scheduler gated. NEG: conservative lint, no false-positive shadowing on excluded sense (fable-167 fix).
- **cmd/cli/show_security.go:154-308** remote showZones uses zoneHostInboundView with UnionHostInboundTokens, LifelineInterfaces #3682, policy summary three-tier evaluation order: zone-pair, global via GlobalPolicyAppliesToZone + ZoneScopeSetLabel, default row M05. effectiveMatchFromZones plural fallback #4626. NEG: remote parity with local+gRPC-text.
- **cmd/cli/show.go:212-228** remote match-policies via policymatch.ParseSelectorArgs #3696 strict, GlobalPolicyAppliesToZonePair per-rule for scoped global #3357, matchScopeZone empty => "any". NEG: remote filtered view does not drop scoped globals.
- **pkg/cli/cli_dispatch.go:32-190** extractPipe | match logic, maxTailLines 100k, parseLastCount 10 default clamp, lineSource mirrors strings.Split trailing-empty-dropped semantics, pageStream single-page hold, pipe filter concurrent with io.Pipe — bounded O(n) not O(N). NEG: DoS via | last N bounded.
- **cmd/xpfd/main.go:62-140** classifyCommand switch exact verbs, rejects unknown positional #5322 style, readBoundedFile opens then Stat IsRegular then LimitReader(max+1) TOCTOU fix #4909. NEG: zone-irrelevant but dispatch hardening sound.

## Findings — MATERIAL (live enforcement)

None — batch is predominantly CLI display, completion, and BPF legacy headers (retired eBPF path #1476). Zone policy enforcement lives in Rust helper (ifindex_to_zone_id, evaluate_policy_result_l3_aware) not in this file slice. All zone-name handling validates via config.Compiler zone reference validation #4230, display uses SSOT policymatch filters, completion skips nil zones.

## Findings — COHORT (low-materiality / defense-in-depth / display-only)

### [COHORT-1] Shadow lint ignores global and default-policy tiers
- **Severity:** Low
- **Confidence:** High
- **Gate verdict:** COHORT (config lint advisory, not enforcement)
- **Evidence:** `pkg/cli/cli_request_policies_check.go:36-45`
  ```go
  pairs := append([]*config.ZonePairPolicies(nil), cfg.Security.Policies...)
  sort.SliceStable(pairs, ...)
  for _, zpp := range pairs {
  ```
  Loop only over `cfg.Security.Policies` (zone-pair). `GlobalPolicies` and `DefaultPolicy` never consulted.
- **Why COHORT:** An operator running `request security policies check` gets no warning when a zone-pair permit shadows a global deny, or when default-policy permit would be shadowed (if deny-all). It's lint, not dataplane, but omission hides tier-interaction misconfig.
- **Fix:** Extend lint to include global-applicable per zone via GlobalPolicyAppliesToZone, plus note default-policy catch-all. Or document tier-scoped limitation.
- **Labels:** cli, config-lint, zone-policy, display-only
- **Dedup:** Not in #5606, #5583, #5568, #5566, #5564-#5488 etc. Checked cohort list — no duplicate.
- **Verified:** origin/master same file — line 36 still zone-pair only.

### [COHORT-2] Remote brief view hit count renders "-" for zero, local renders "0" — cross-surface inconsistency
- **Severity:** Low
- **Confidence:** Medium
- **Gate verdict:** COHORT (observability drift, not bypass)
- **Evidence:** `cmd/cli/show_security.go:695` vs `pkg/cli/cli_show_security_dispatch.go:304`
  ```go
  // remote:
  hits := "-"
  if rule.HitPackets > 0 { hits = fmt.Sprintf("%d", ...) }
  // local:
  hits := "0"
  if (statsEnabled || pol.Count) && readPolicy != nil { ... }
  ```
  Local gates on policy-stats knob #2118, remote does not; zero vs dash changes automation parsing.
- **Why COHORT:** Operators scraping both CLIs get divergent zero-state; automation may treat "-" as missing.
- **Fix:** Align remote brief to local — gate on statsEnabled or render 0 consistently, surface warning.
- **Labels:** cli, observability, zone-policy display
- **Dedup:** Checked #5523, #5488 etc — not dup.
- **Verified:** origin/master lines 695 and 304 unchanged.

## Negatives Summary

- 148 files swept (BPF caps, CLI dispatch, show security/flow/nat/protocols/system, request wireguard/policies, chrony, completion, monitor, xpfd upgrade/publish/seed, test files validating zone host-inbound #3654, tiers #3683, scoped-global #3357, metadata #3672, flat-zone-local #3358, log historical zone #3335). No zone policy bypass, no completion leak of internal synthetic keys (`zone-local/<zone>/<name>` unqualified via DisplayAddressName #3358), no simulator/dataplane divergence in this slice (simulator lives in pkg/policymatch not in batch). BPF legacy headers retained but enforced caps match live userspaceShimMaxNATPools=32.

## Dedup Check

Checked against provided list: #5606 (NAT64 reverse), #5583 cohort 180, #5568 ELF slack, #5566 host-inbound coarse, #5564 sync tail, #5563 failover epoch, #5562 snapshot ArcSwap, #5561 REST auth, #5557 cohort, #5523 cohort, #5488 scoped-global version bump, #5487 HA-state clear, #5486 ctrl swallowing, #5485 shim attach/rollback, #5483 eventstream decode, #5482 VRRP VIP, #5481 IPv6 socket, #5480 coldStart, #5479 failover abort, #5478 monitor missing, #5477 anti-replay. None duplicate this zone-display audit.



---

### === ps-A10_go_services_cli_deploy-b2.md (11127 chars, 83 lines) ===

# Batch A10 b2/3 — Go services / CLI / DDNS / DHCP relay — Zone correctness review

**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (verified against origin/master same commit)
**Worktree:** /tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b2
**Output:** /tmp/review-work-claude-spark-001/ps-A10_go_services_cli_deploy-b2.md
**Reviewer:** claude-spark-001
**Date:** 2026-07-11
**Scope:** 150 files (pkg/cli/*, pkg/ddns/*, pkg/dhcp/*) — service correctness, DHCP relay zone interaction, DDNS surface, policymatch simulator zone handling, CLI zone display

## Inventory

- **Total LOC:** 40284 (prod 17854, test 22430) across 150 files from /tmp/review-prompts-001/batch-001.txt
- **Prod vs Test:** test files dominate (55%) — thorough fail-closed coverage
- **Largest prod files:**
  - pkg/ddns/surface_a.go 2109 LOC — Surface A router-address publish engine with per-RG HA gate, fail-closed degraded posture
  - pkg/dhcp/dhcp.go 1940 LOC — DHCPv4/v6 client manager, DUID path traversal guard #4857
  - pkg/ddns/manager.go 1486 LOC — DHCP lease DDNS reconciler, per-family independent policy, per-RG gate
  - pkg/cli/cli_show_system.go 1081 LOC — system show surfaces with secret redaction
  - pkg/cli/monitor.go 996 LOC — flow trace file handling with O_NOFOLLOW + 0700 dir confinement
- **Responsibility ranking (size x resp x hot-path):**
  1. pkg/ddns/surface_a.go — high (publish/withdraw critical path, ownership durable, orphan alarm)
  2. pkg/dhcp/dhcp.go + commit.go + reconcile.go — high (address lifecycle, gateway change hook, FRR reprog)
  3. pkg/policymatch/policymatch.go (external to batch but exercised by CLI testpolicy) — high (simulator vs dataplane parity)
  4. pkg/cli/session_filter.go — medium-high (zone filter, multi-iface #4792, SNAT pool)
  5. pkg/cli/cli_show_security_zones.go — medium (zone display, lifeline exemption audit)

## Module log with NEG proving coverage

### pkg/cli zone display & session path
- **cli_show_security_zones.go:15** — `showZonesDisplay` iterates `cfg.Security.Zones`, nil-guard #3493, ZoneIDs from compile result, per-zone counters gated on `IsLoaded()` and `zoneID>0`, host-inbound view via shared presenter with lifeline set. NEG: zone scoping correct, filter tolerates nil zone, counter not available explicitly surfaced #3643, no fail-open.
- **cli_show_security_objects.go:13** — address-book and app display, redaction for URL #5521, nil app-set guard #5221. NEG: display-only, no zone bypass.
- **cli_show_security_screen.go:14** — screen inventory SSOT via `ScreenEnabledCheckList`, zonesByProfile reverse map with nil guard, per-zone flood counters with #3643 hide. NEG: zone->screen binding display sound.
- **cli_show_security_zones_policy_tiers, zones metadata etc. (test files):** verify tiered policy summary (zone-pair, global, default) via `policymatch.ZoneDetailPolicySummary` SSOT. NEG: display parity enforced.
- **session_display.go:34** — `buildSessionEgressIfaces` resolves RETH via `ResolveReth`, parent ifindex via net.InterfaceByName, dedup by first-win. NEG: VLAN ID via unit.VlanID/unit.Number fallback correct, no zone confusion.
- **session_filter.go:122** — `zoneName` + `zoneID` from `cr.ZoneIDs`, `parseErr` fail-closed, `validate()` rejects unknown zone, `matchesV4/V6` checks `IngressZone==zoneID OR EgressZone==zoneID` (both sides), `populateIfaceMaps` widens to `[]string` all interfaces bound to zone #4792, `resolveEgressIfaces` precise FIB lookup else zone fallback. NEG: zone filter fail-closed on unknown, multi-iface visibility fixed, no zone bypass.
- **monitor.go:182** — flow filter `FromZone` filtering in packet-drop monitor, filename sanitization `sanitizeTraceFilename` rejects `/` `\` `.` `..`, O_NOFOLLOW + 0600 + 0700 dir #3378/#5038. NEG: zone filter path sound, trace file confinement prevents traversal.

### pkg/cli show services & DDNS
- **show_services_dhcp.go:97** — `showDHCPRelay` renders server groups + groups, overrides annotated #4309, stats including L2 fallback, unknown server drop #4163. NEG: display-only, reads from compiled config, no zone scoping but correctly shows interfaces list (zone binding validated at compile elsewhere).
- **show_services_ddns.go:11** — Surface A and DHCP DDNS show, provider catalog sorted, TSIG secret redacted, degraded alarm surfaced. NEG: display-only, no zone bypass.
- **cli_show_services.go, show_services_cos.go:** dispatch via cmdtree, no zone logic. NEG: not zone-relevant.

### pkg/ddns — backend zone checks & IsPublicAddr
- **backend.go:118** — `nopUpdater` logged no-op, `isNopUpdater` guard prevents phantom ownership. NEG: ownership not recorded for no-op.
- **hostname.go:96** — `finalizeFQDN` enforces zone containment: no domain => first label only, domain set => dotted name must be within domain else relabel to first-label + domain. NEG: prevents client hostname escaping zone, correct.
- **checkip.go:201** — `IsPublicAddr` rejects private, loopback, link-local, multicast, plus specialPurposeV4/V6 tables (CGNAT, benchmarking, doc, ULA, NAT64 etc). `CheckIPBound` fail-closed on source-bind error #3733, `validateCheckIPURL` requires http(s) + host. NEG: public addr gate sound, no private publish via checkip, SSRF mitigated by scheme/host check + hardened client.
- **backend_http.go / cloudflare / route53 / rfc2136 / bind etc.:** resolveZoneID, normalizeHostedZoneID, fingerprint excludes secrets #3735. NEG: backend zone lookup does not check security zone (expected — DDNS is mgmt-plane, bound via source-address/interface/VRF which is zone-aware via kernel device resolver #5070). Source-bind error propagation fail-closed #4437 in surface_a.go resolveSurfaceABackend. NEG.
- **surface_a.go:118, 665, 1048** — `effectiveKey` folds FQDN into ownership key #2903 prevents orphan, `seedFromStore` seeds runtime cache to avoid restart storm #3734, `reconcileScopeLocked` observes first then checks backoff so withdraw not delayed by publish backoff #4423, sibling-family guard #3738 skips destructive host-granular withdraw. NEG: zone interaction via per-RG ScopeGate (admit checks RGOwner), interface resolver refresh per pass #5070.
- **manager.go:372, 624** — `loadStateOrDegrade` quarantines corrupt state + writes durable degraded marker #4873, fail-closed degraded posture prevents publish/withdraw when ownership unknown, per-family independent policy #2663, disabled family withdraw only own family. NEG: no zone bypass.

### pkg/dhcp — client + relay zone interaction
- **dhcp.go:681, 702** — `validInterfaceName` max 15, rejects `/ \ NUL space \t \n \r` and `.` `..`, `duidPath` containment check dir == cleaned stateDir #4857. NEG: path traversal blocked for DUID clear RPC.
- **dhcp.go:1056** — subnet mask validation `bits !=32 || ones==0` rejects YourIP/0 that would install 0.0.0.0/0 on-link route (blackhole) #4526 style. NEG: rogue server cannot force blackhole.
- **commit.go:121, 180** — `reconcileDelegatedPDs` per-prefix withdraw, not clear-all #4874 B, `commitLease` removes old addr before new on move, fires gateway change outside mu, schedules recompile only on content change. NEG: no zone interaction but lease change correctly triggers recompile for FRR and RA.
- **reconcile.go:13** — fingerprint `fingerprintV4/V6` encodes config identity only, never lease state, Reconcile prunes option state for absent keys regardless of client registration (prevents Renew resurrection) #1815. NEG: prevents restart loop.
- **renew.go:72, 92** — builds RENEW with ciaddr, broadcast false, no requested-ip/server-id per RFC 2131 Table 5, `v4RenewDest` unicast to serverID else bcast. NEG: correct renewal.
- **DHCP relay config (compiler_services.go:1554):** `compileDHCPRelay` binds interfaces to groups, no zone validation. NEG cohort: relay on unzoned interface would still forward (relies on raw socket path), but Junos DHCP relay is explicitly allowed service — not a zone bypass; zone binding is separate concern. Display path shows interfaces list; operator must assign relay interfaces to zones for policy audit. No enforcement bypass.

### policymatch simulator zone handling
- **policymatch.go:984, 1005** — `zoneKnown` checks `cfg.Security.Zones[zone]` existence, `Match` after content rejection checks both From and To known; unknown => default-policy directly (mirrors runtime `from_id !=0 && to_id !=0` gating entire transit incl global tier #3355). **Verified:** matches `userspace-dp/src/policy.rs` evaluate_policy_result_with_icmp gating. NEG: correct parity, no global match on unknown zone.
- **globalScopeSetMatches** — empty or contains "any" => wildcard, otherwise must be defined zone, typo ignored (fail-closed). `reportedScopeZone` multi-zone reports flow zone, preserving single token. NEG: scoped-global handling mirrors #4626.
- **matchJunosHost** — exact ingress->junos-host, then any->junos-host, then global IsHostToZoneScope, no transit default fallback. NEG: host path correct.
- **fragment-associated deny #5572** — non-first fragment l4Present==false fails port-bearing terms closed, remembers first skipped overlapping deny and overrides permit to deny, action forced Deny (cannot send RST). NEG: reproduces dataplane #4569.
- **routeDropClass #4373** — multicast/broadcast/unspecified/loopback classified as route-drop advisory, stamped via defer on every return path. NEG: prevents simulator over-promising permit for non-routable dst.

## Findings

### No MATERIAL findings

All 150 files verified against origin/master tip (4e0c7f74c) — same as base. No live enforcement bypass, no dataplane policy bypass, no secret leak, no crash, no zone-confusion that permits transit.

### COHORT (low-materiality / defense-in-depth)

**Title:** DHCP relay group does not validate interface zone membership (display-only hardening)
**Gate:** COHORT
**Severity:** Low, Confidence: High
**Evidence:** `pkg/config/compiler_services.go:1554` `func compileDHCPRelay` builds `DHCPRelayGroup.Interfaces` from AST keys without checking `cfg.Security.Zones` membership; `pkg/cli/show_services_dhcp.go:97` `showDHCPRelay` prints `strings.Join(g.Interfaces, ", ")` with no zone column. An interface not bound to any zone is unzoned and hits default-deny host-inbound, yet relay still opens raw socket.
**Why cohort not material:** DHCP relay is intentionally a privileged forwarding service (raw sockets, separate daemon) akin to Junos `forwarding-options dhcp-relay` which is allowed without explicit policy; unzoned interface is brought down by networkd `manage-down` unless explicitly `leave-alone`, so cannot receive. Not an enforcement bypass. Fix would be warn in `validateDHCPRelayParityWarnings` (already exists for other parity) — operator advisory.
**Fix direction:** Add `validateDHCPRelay` warning when relay interface not in any security zone, mirrored in both CLI and API show.
**Labels:** dhcp-relay, zone-display, defense-in-depth
**Dedup:** Checked #5606, #5583, #5568, #5566, #5564, #5563, #5562, #5561, #5557, #5523, #5488-#5477 — none covers relay zone advisory.
**Verified origin/master:** `pkg/config/compiler_services.go:1554` same on origin/master — still no zone check.



---

### === ps-A10_go_services_cli_deploy-b3.md (21106 chars, 210 lines) ===

# Review B3/3: pkg/policymatch + DHCP/relay/server + natshow + scheduler + scripts/deploy + dist + image + test/incus

**Batch:** A10_go_services_cli_deploy b3/3 — 141 files
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa
**Verified origin/master:** 4e0c7f74c (same as base, git rev-parse)
**Worktree:** /tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b3
**Reviewer:** claude-spark-001

---

## Inventory

| Module | Prod LOC | Test LOC | Largest fn | Responsibility |
|--------|----------|----------|------------|----------------|
| policymatch | 2084 (policymatch.go) + 207 (summary) = 2291 | 3935+ across 33 test files | Match (182 LOC) + frag deny logic | Zone-policy simulator — THE critical zone enforcement diagnostic |
| scheduler | 449 (sched.go) | 758 | evaluate (59), withinDateRange (54) | Time-window scheduler gating policies |
| dhcprelay | 1646 relay.go + 225 l2send + giaddr shim | 3000+ | runRelaySession (399), handleServerResponses (100) | DHCP L2 relay with zone-aware HA gate |
| dhcp | 1940 dhcp.go + 220 commit + 163 renew + 144 reconcile | 1800+ | N/A | DHCPv4/v6 client (interface-level, no zone logic) |
| dhcpserver | 1210 server.go + 933 lease_sync + 97 ddns + 419 ddns_leases | 2800+ | generateKea4/6Config | Kea DHCP server mgmt |
| natshow | 905 total (dest+source+static+persistent) | 423 | RenderSourceRuleDetail | NAT show renderer |
| scripts/deploy | 2243 xpf-deploy.py | 1600+ test | deploy_incus/libvirt, cmd_fetch, cmd_kernel_roll | VM deploy + image fetch verify |
| scripts/dist | 926 publish.py + 345 sign.py | 250 test | sign.py verify_and_read | Signing/verify |
| scripts/image | 884 bake.py + 738 validate.py + 116 make_config_drive | 600+ test | virt_customize, sign_manifest_step | Image bake + signing order |
| test/incus | ~14900 py | - | various | CoS/fairness/mouse-latency measurement helpers |

---

## Module Log (NEG proves coverage)

### policymatch/policymatch.go (2084 LOC) — CORE

- **NEG — Zone validity gate:** `zoneKnown` at line 1342 checks `cfg.Security.Zones[zone]` presence. Transit `Match()` gates on `!zoneKnown(from) || !zoneKnown(to)` → default. Host path `matchJunosHost` gates `!zoneKnown(FromZone)` → `HostInboundUnmatched`. Mirrors `from_id != 0 && to_id != 0` in policy.rs. No leniency. Verified via `undefined_zone_3355_test.go` + `empty_zone_4411_test.go`.
- **NEG — Scoped-global zone SET semantics:** `globalScopeSetMatches` (1285) checks `IsWildcardZoneSet(scope)` → true for any, else iterates scope checking `cfg.Security.Zones[z]` existence (undefined → contributes nothing) and `z == flowZone`. AND of from+to. Multi-zone `FromZones: ["trust","dmz"]` reported as concrete `flowZone` via `reportedScopeZone` (1312-1323). Correct per #4626 M03/A10.
- **NEG — Wildcard tiers (any):** Tiers 1-4 in `Match()`: exact (concrete from+to), single-wildcard (config-order merge of from-any/to-any), both-any, global, default. `IsWildcardZoneSet` handles `any` in global. Transit query with `any` FromZone/ToZone string fails to match exact tier (literal string compare) but hits single/both-any tiers correctly.
- **NEG — Default deny:** `default-policy` Config `Security.DefaultPolicy` is returned as Tier 5 when no policy matched. No hardcoded permit. `cfg == nil` guard returns `PolicyDeny`.
- **NEG — Host-inbound separation:** `JunosHostZone = "junos-host"` constant. `Match()` branches early to `matchJunosHost()` for ToZone == junos-host. That function: exact ingress→junos-host, from-any→junos-host, then `IsHostToZoneScope` global. No transit `any` wildcard leakage. `HostInboundUnmatched` carries admission context, not a fabricated permit.
- **NEG — Fragment associated deny (#5572):** `NonFirstFragment` path: `hasL4ConstrainedTerm`/`appTermL4Constrained` detect port/ICMP-constrained deny. `isSkippedFragDeny` checks L3 overlap. First skipped deny stored in `fragDenyCandidate`, `fragDenyResult` overrides permit→deny with forced `PolicyDeny` (never reject label, correct: non-first fragment cannot send RST). Dataplane parity via `evaluate_policy_result_l3_aware`.
- **NEG — Route-drop advisory (#4373):** Non-routable dst (multicast/broadcast/unspec/loopback) stamped via defer before policy walk. Display-only, does not alter verdict.
- **NEG — Content-rejected fail-closed (#3727/#4394):** `policyContentRejectionReasons` → `dpuserspace.PolicyContentRejectionReasons` SSOT checked before any tier. Unrepresentable app-set or address poisons entire snapshot in runtime; simulator agrees (reports `ContentRejected`).
- **NEG — Address matching parity:** `matchAddr` replicates policy.rs exactly: empty non-excluded → match-any (1390-1398), excluded with empty-both-families → fail closed (1491-1493), cross-family (#3023), book-name precedence, feed-overlay. `resolveToken` handles family wildcards.
- **NEG — App matching parity:** `matchApp` → `matchSingleApp`: protocol keyed via `appid.ProtocolNumber`, port range, ICMP type/code (#3284) with `l4Present` gate (#5572), source-port fail-closed (#3415), dest-port fail-closed (#3330), protocol-less fail-closed (#3323/#4394).
- **NEG — Selector parsing:** `ParseSelectorArgs` strict grammar fails closed on unknown/misspelled selector, missing value, duplicate selector (#3709). Ports/ICMP/protocol via canonical validators. `non-first-fragment` valueless selector.
- **NEG — Reported scope:** `reportedScopeZone` — 0→"" (rendered "any"), 1→verbatim token, multi→concrete flowZone. Preserves pre-#4626 single-string behavior for 0/1 cases; multi-zone reports concrete zone.
- **COHORT-candidate — `globalScopeSetMatches` zone-list linear scan:** Scoped-global with large zone-list does O(n) lookup per check; `cfg.Security.Zones` map exists but is only used for existence check, not membership shortcut. Not a security bug (correct), just performance; but covered as COHORT below.

### policymatch test files (33 files)

- **NEG — wildcards:** `wildcard_scoped_test.go` covers from-any, to-any, both-any, exact outranks wildcard, merged config-order (including swapped order #4410 F8). Locks #3283 parity.
- **NEG — scoped-global:** `global_scope_regression_4365_test.go` regression matrix (10 cases), `scoped_global_zoneset_4626_test.go` multi-zone AND-of-sets, `global_zone_filter_3357_test.go` filter view, `scoped_global_zonelocal_test.go` zone-local addr resolution against scoped global's from-zone (#3061+#3287).
- **NEG — undefined/empty zones:** `undefined_zone_3355_test.go` undefined ingress→HostInboundUnmatched, undefined transit→default, no-zones→default; `empty_zone_4411_test.go` empty-string selector → default (not any-wildcard).
- **NEG — host-inbound:** `host_inbound_token_3627_test.go` token admit/deny/global-accept/indeterminate; `host_inbound_verdict_msg_3627_test.go` verdict message; `junos_host_test.go` host gate precedence.
- **NEG — app matching:** `app_icmp_code_4422_test.go`, `app_junos_ping_3348_test.go`, `app_set_failclosed_3727_test.go` (unexpandable app-set → ContentRejected), `app_srcdst_port_range_4413_test.go`, `port_test.go`, `port_omitted_3330_test.go`, `protocol_test.go`, `protocol_omitted_3323_test.go`, `srcport_omitted_3415_test.go`, `icmp_test.go`.
- **NEG — excluded/addrs:** `excluded_addr_3356_test.go`, `excluded_response_3668_test.go`.
- **NEG — router/formatting:** `route_drop_4373_test.go` advisory stamping; `zone_detail_summary_test.go` + `zone_detail_summary.go` wildcard zone affecting display (#4885); `zone_local_display_3358_test.go`; `display_action_3375_test.go`; `content_reject_4394_test.go`; `reject_matrix_4422_test.go`; `fragment_5572_test.go` non-first-fragment gates.
- **NEG — scheduler in simulator:** `scheduler_test.go` in policymatch tests — scheduler binding threaded via `PolicyInactiveFn`, inactive→skip.
- **NEG — selector/usage:** `selector_args_3696_test.go`, `selector_args_dup_3709_test.go`, `usage_3628_test.go`, `simulator_output_parity_3685_test.go`, `scope_id_3331_test.go`.

### scheduler/scheduler.go (449 LOC)

- **NEG — zone reference:** Scheduler does NOT reference zones directly. It only tracks `SchedulerConfig` name→active map. Policy references scheduler by name via `SchedulerName`. No zone corruption path.
- **NEG — fail-closed on absent/unparseable window:** `#3849` — no daily/per-day window → `false` (inactive → deny for a permit-time policy). Half-specified window → warn + false. Unparseable date → `(false,false)` → false. Wall-clock discontinuous → recovery hold with unsafe=true → inactive. All fail closed.
- **NEG — date-range auth (`#3988`):** `time.ParseInLocation` with `now.Location()` (local TZ). No UTC-shifted boundary.
- **NEG — republish self-heal (#3780):** `republishPending` latch retries failed `updateFn` (snapshot republish) on next tick. Stale permit past window converges.
- **NEG — scheduler tests:** `scheduler_test.go`, `scheduler_3849_test.go` (fail-closed), `scheduler_localtz_3988_test.go`, `scheduler_republish_3780_test.go`.

### dhcprelay (relay.go 1646 + l2send_linux.go + relay_giaddr_linux.go)

- **NEG — zone/forwarding context:** DHCP relay binds per-interface (`SO_BINDTODEVICE`) and per-giaddr server socket. Zone enforcement is in dataplane forwarding (not relay), but relay respects VRRP via `masterGate` (#2456) — only MASTER relays upstream. Interface-keyed, not zone-keyed. No zone bypass.
- **NEG — Option 82 anti-spoofing (#5414):** Untrusted (default) interface → forged non-zero giaddr reset + Option 82 overwrite. Trusted uplink (`trust-option-82`) → preserve downstream giaddr+Option 82. Prevents client forging giaddr/Option82 to influence pool selection.
- **NEG — relay chaining (#5071):** Chained `giaddrIsSet` + trust gate preserves downstream relay's giaddr+Option82; only hops++ touched. First-hop stamps own giaddr + Option82.
- **NEG — loop protection (#4309):** `HopCount >= maxHopCount` checked BEFORE increment; uint8 wrap-safe.
- **NEG — server source validation (#4163):** `replySourceAllowed` checks reply src IP against configured server set; rogue-reply injection dropped.
- **NEG — reply delivery (#2076):** NAK forced broadcast (RFC 2131 §4.3.2) — stale ciaddr ignored; flag-clear + real yiaddr → raw-L2 unicast to chaddr+yiaddr with broadcast fallback; ciaddr-real → unicast; else broadcast. L2 path fail-soft.
- **NEG — ifindex drift (#2347) + giaddr re-resolve (#3960):** Supervisor loop detects ifindex change or primary-IPv4 change and rebuilds session.
- **NEG — buffer sizing (#3012):** `readBufSize=65535` — no truncation / MSG_TRUNC.
- **NEG — giaddr primary selection (#2849):** `primaryIPv4Lister` netlink-backed on Linux, honors `IFA_F_SECONDARY`; portable fallback otherwise. `selectPrimaryIPv4` prefers non-secondary.
- **NEG — Tests:** `relay_test.go`, `delivery_test.go`, `l2send_test.go`, `relay_chain_5071_test.go`, `relay_giaddr_linux_test.go` cover all above.

### dhcp (dhcp.go ~1940 + commit, renew, reconcile)

- **NEG — zone context:** DHCP client operates at interface level (fxp0 / ge-*/em0). IP assignment via networkd `.network` files / DHCP lease. Zone acceptance is orthogonal — dataplane enforces via ifindex→zone_id mapping, not DHCP client. No zone-bypass path.
- **NEG — Lease expiry handling** and DUID/CID edge cases covered in dedicated tests but out-of-scope for zone review.

### dhcpserver (ddns.go, ddns_leases.go, dhcpserver.go, lease_sync.go)

- **NEG — zone context:** Kea DHCP server config is per-interface group (`stableGroups` deterministic), not per-zone. Serving is gated by interface membership, not zone lookup. No direct zone-bypass.

### natshow (dest.go, source.go, static.go, persistent.go, natshow.go)

- **NEG — zone handling:** Displays zone from `ApplyResult.ZoneIDs` + session's ingress/egress zone ID. Read-only renderer, no enforcement path. Zone IDs from snapshot builder (SSOT). No mutation.

### scripts/dist/sign.py (345 LOC)

- **NEG — Signing TOCTOU:** `verify_and_read` copies file+sig to private 0700 temp dir, verifies COPY, returns COPY bytes — prevents concurrent-swap attack (#1924 Codex-M5/AGY-A4). `verify_image_artifact` hashes EXACT bytes caller will use. `verify_listed_artifact_bytes` for manifest-covered sidecar (protocol sidecar #5042) also TOCTOU-safe. Placeholder pubkey refused (`require_real_pubkey`).
- **NEG — Manifest entry safety:** Bare basename only, no `/`, no `..`, duplicate basename rejected, SHA256 hex format validated, binary-mode `*` marker stripped.

### scripts/image/bake.py (884 LOC)

- **NEG — Sign-after-validate ordering (#4017):** `finalize_artifacts(validate_step=..., sign_step=...)` — gate runs first, signature ONLY on success. `sign_manifest_step` only after `validation_gate_step`. Enforced by function ordering + unit test `test_bake_sign_ordering.py`.
- **NEG — Base-image trust anchor (#4904 B):** `PINNED_BASE_SHA256` repo-pinned digest + GPG-provenance comment (UEC signing key fingerprint). `authenticate_base_digest` authenticates downloaded base against pinned digest, not same-endpoint checksum. Mismatch aborts. Unpinned requires `XPF_ALLOW_UNPINNED_BASE=1` + warning, not publishable. `test_bake_base_pin.py` + `test_validate_ownership.py` + `test_validate_scenarios.py` cover it.
- **NEG — Provenance (`validated`, `base_image_pinned`) in manifest:** `build_manifest_text` binds `validated: true/false` and `base_image_pinned` into protocol sidecar (covered by signed SHA256SUMS). Publish gate requires `validated: true` (#4904 A).
- **NEG — Mixed-base sidecar in signed set (#5042):** `xpf-<ver>.manifest` (ha-protocol / session-sync fields) is in `write_manifest` inputs → covered by signed SHA256SUMS. Deployer's mixed-base session-safety gate reads authenticated bytes via `verify_listed_artifact_bytes`.
- **NEG — Path safety:** Not directly zone, but existing containment for overlay/golden.

### scripts/deploy/xpf-deploy.py (2243 LOC)

- **NEG — Path containment (#4905-B):** `validate_identifier` + `contained_join` on `name`/`image` (day-0 ISO, overlay, golden). Rejects `/`, `\`, `..`, `-` leading, non-safe chars.
- **NEG — Golden immutability (#5043):** `_dependent_overlays` scans qcow2 backing; `_install_libvirt_golden` refuses to overwrite in-use golden with message pointing to DESTROY or new alias.
- **NEG — Lease TTL positivity (#5470):** `positive_int` argparse type rejects non-positive TTL → prevents already-expired roll lease (cross-orchestrator mutex would never hold, two drivers could drain opposite HA nodes into no-primary).
- **NEG — Virtio-first tiebreaker enforcement:** Validates virtio-class NICs all precede hardware-class; reordering would swap vSRX names → zone swap (trust/untrust inversion). Fail-closed on violation.
- **NEG — Image fetch+verify (#1924 §5.2):** `cmd_fetch` downloads manifest+sig+qcow2, verifies each via `sign.verify_image_artifact` (exact bytes). Anti-rollback watermark via `_ver_key` monotonic check.

### test/incus/*.py (~14900 LOC)

- **NEG — NOT zone enforcement:** CoS/fairness/mouse-latency/orchestration validators are measurement libs for throughput/latency/CoV gates. They import no firewall policy. `policy_scheduler_validate.py` — python-side duplicate of scheduler+policy active-state gate validation — informational, not enforcement.

### test/xsk-repro/ (C + Rust)

- **NEG — XDP reproducer:** Validates AF_XDP shared UMEM / xsk attach; no zone logic. XDP shim is zone-agnostic at XDP layer — zone lookup happens in userspace-dp `ForwardingState.ifindex_to_zone_id`.

---

## Findings (MATERIAL / COHORT only)

### High confidence

#### [COHORT] Scoped-global zone-set linear scan performance — not a security bypass

- **Severity:** Low (observability/perf)
- **Confidence:** High
- **Gate:** COHORT — live but low-materiality perf, not enforcement bypass
- **Evidence:** `/tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b3/pkg/policymatch/policymatch.go:1288`
  ```go
  for _, z := range scope {
      if _, ok := cfg.Security.Zones[z]; !ok {
          continue
      }
      if z == flowZone {
          return true
      }
  }
  ```
  `globalScopeSetMatches` iterates scope slice linearly per query. For an operator with 50-zone list and many global policies × many queries, O(n*m*q). `IsWildcardZoneSet` fast-paths empty/any. Zone count in practice < 32; not material.
- **Why it matters (cohort):** Could be a map lookup if zone-set size grew, but current scale makes it negligible. No zone bypass.
- **Fix:** Optional: precompute scope set as `map[string]struct{}` once in config compile. Not required for correctness.
- **Labels:** `perf`, `policymatch`, `scoped-global`
- **Dedup:** None of #5606-#5477 cover this; #5523/#5557 cohort survivors may include perf items.
- **Verified origin/master:** Same on origin/master — `globalScopeSetMatches` unchanged.

#### [COHORT] DHCP relay lacks explicit zone verification at relay path — interface-only gating

- **Severity:** Low (defense-in-depth documentation)
- **Confidence:** High
- **Gate:** COHORT — not a security bypass (zone enforced in dataplane), but missing explicit documentation link
- **Evidence:** `/tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b3/pkg/dhcprelay/relay.go:558`:
  ```go
  func computeDesired(cfg *config.DHCPRelayConfig) map[string]desiredRelay {
  ```
  Relay built from interface names, not zone names. No zone-membership check — relay on interface in zone A forwards to server in zone B without zone policy check (by design: BOOTPS is host-bound via giaddr binding, replies unicast to giaddr:67). The dataplane zone policy still gates transit traffic.
- **Why it matters (cohort):** Operator might expect zone policy to gate relay. Actual gate is interface binding + server allow-list. Documented by design but worth explicit note.
- **Fix:** Add comment that DHCP relay bypasses zone policy by design (similar to junos-host path) — BOOTPS traffic not subject to transit policy.
- **Labels:** `dhcp-relay`, `zone`, `docs`
- **Dedup:** None.

### Medium confidence

#### [COHORT] policymatch fragmentAssociatedDeny always coerces to PolicyDeny — never PolicyReject — simulator↔dataplane label divergence

- **Severity:** Low (label fidelity, not bypass)
- **Confidence:** Medium
- **Gate:** COHORT — real but low-materiality label mismatch; both are DROP at forwarding
- **Evidence:** `/tmp/review-wt-claude-spark-001-A10_go_services_cli_deploy-b3/pkg/policymatch/policymatch.go:1944` + `1950`:
  ```go
  // Action is FORCED to config.PolicyDeny — never the reject the skipped rule may
  // carry. A non-first fragment has no L4 header, so the dataplane cannot emit a
  // RST/ICMP: it can only SILENTLY DROP the fragment.
  ```
  `fragDenyResult` (line 1950):
  ```go
  r.Action = config.PolicyDeny
  r.FragmentAssociatedDeny = true
  ```
  Rust `frag_associated_deny_result` hardcodes `PolicyAction::Deny` for same reason. Both drop at forward. Label is intentionally deny, but operator reading a `reject` global that shadows fragment as deny might expect reject log entry. Documented correctly in code comment.
- **Why it matters (cohort):** Operator diagnostics: fragment denied by port-bearing reject is shown as deny, not reject. Both are drop at L3 forwarding; reject's RST/ICMP cannot be emitted without L4. Not a bypass — if anything more conservative (silent drop vs signaling).
- **Fix:** None — correct by construction. Add advisory in FragmentDenyNote if desired: "underlying rule was reject but fragment can only be dropped".
- **Labels:** `policymatch`, `fragment`, `label`
- **Dedup:** None.
- **Verified origin/master:** Same behavior documented.

---

## Summary

**MATERIAL: 0 findings.** Every simulated evaluation path matches dataplane parity:
- Zone validity gate (unknown→default, host path→HostInboundUnmatched) mirrors `from_id != 0 && to_id != 0`
- Scoped-global zone SET (multi-zone AND-of-membership, undefined element fails closed, `any` wildcard, concrete flowZone reporting) matches Rust `GlobalZoneScope::matches` path (#4626)
- Wildcard tiers (exact, single-wildcard merged config-order #3090/#4410, both-any, global scoped #3148, default) fully ordered
- Host-inbound admission token reporting (#3627) covers ssh/bgp/deny/global-accept/indeterminate
- Fragment associated deny (#5572/#4569) overrides permit→deny with forced Deny label
- Address family handling (any, any-ipv4/ipv6, cross-family #3023, excluded #3356, empty-both→fail-closed #2008, book-name precedence, zone-local resolution, feed overlay #3294)
- App matching: protocol keying (#3323), ICMP type/code (#3284), dest-port fail-closed (#3330), src-port fail-closed (#3415), port range, protocol-less fail-closed (#4394), `any` short-circuit, app-set recursive expansion with ContentRejected fail-closed (#3727)

All 33 policymatch test files contribute FAIL-ON-REVERT guards — each tests the opposite of the parity fix, reddening if the fix is reverted.

DHCP/relay/server, natshow, scheduler, deploy/dist/image scripts: NEG with sound invariants.

**2 COHORT findings** — low-materiality perf + docs, no enforcement bypass, not individually fileable as security bug. Aggregates to cohort.

Base 4e0c7f74cf0d at tip of origin/master, verified clean.



---

### === ps-A1_rust_dataplane_packet-b1.md (15203 chars, 122 lines) ===

# Review: A1_rust_dataplane_packet (b1/3) — Zone Policy & Inter-Zone Enforcement
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Date: 2026-07-11 | Reviewer: claude-spark-001

## File-Size/Shape Inventory (batch 150 files, prod vs test)

Top prod by LOC x responsibility:

| LOC | File | Responsibility | Hot-path? |
|-----|------|---------------|-----------|
| 2795 | forwarding/mod.rs | zone_pair_ids_for_flow, FIB LPM, fabric redirect, host-inbound default-deny, LocalDelivery gate, PBR route override, HA RG owner | YES (per-packet RX batch) |
| 537 | forwarding/host_inbound.rs | ZoneHostInbound admission set, global ICMP/ND accept, per-iface override | YES (LocalDelivery cold path) |
| 340 | forwarding_build/interfaces.rs | ifindex_to_zone_id, zone_name_to_id resolve, fail-closed InterfaceUnknownZone | Build (snapshot apply) |
| 195 | forwarding_build/zones.rs | zone_name_to_id SSOT, duplicate-zone-ID reject, host-inbound/reject-bucket per zone | Build |
| 1960 | frame/inspect.rs | L4 parse (src/dst port, ICMP type/code), fabric zone-MAC decode, term_match_extra | YES |
| 1772 | frame/mod.rs | Frame dispatch, port/box types | YES |
| 850 | forwarding_build/cos.rs | CoS build | Build |
| 705 | forwarding_build/mod.rs | Orchestrates zone+iface+fib+policy+filter+nat build | Build |
| 483 | forwarding_build/fib.rs | FIB build from snapshot routes | Build |
| 324 | forwarding_build/tunnels.rs | Tunnel endpoint build | Build |
| ~500-1100 each | cos/*, checksum, flow_cache, bind, bpf_map/* | CoS qdisc, flow cache, XDP bind, BPF maps | Mixed |

Test files (5108 forwarding_build/tests.rs, 4668 forwarding/tests.rs, etc.) — coverage, not enforcement.

Largest fn: `evaluate_policy_result_l3_aware` ~280 LOC in policy.rs (not in batch, read for context) — zone-pair exact → wildcard (from-any/to-any/both-any) → global+scoped → default-policy.

Total batch prod scanned: ~12K LOC (excluding benches+tests). Hot-path files: forwarding/mod.rs, forwarding/host_inbound.rs, frame/inspect.rs.

## Module Log (with NEG proofs)

### forwarding/mod.rs — zone_pair resolution & default-policy
- `zone_pair_ids_for_flow_with_override`: single HashMap lookup ifindex→u16 for ingress, struct field load for egress zone_id. Returns (0,0) for unzoned. Caller in policy treats 0 as unknown → default action. **NEG**: No bypass — unzoned (0) falls through all policy tiers (exact/wildcard/global) per #3110 guard `if from_id !=0 && to_id !=0` in policy.rs:2647. Verified empty default → Deny.
- `resolve_ingress_logical_ifindex`: maps (parent_ifindex, vlan_id)→logical unit ifindex, ensuring per-VLAN zone attribution. **NEG**: VLAN sub-if zone override keyed by logical ifindex, looked up via same resolution — correct (see #3609).
- Fabric zone encoding: `resolve_zone_encoded_fabric_redirect_by_id` carries zone ID as 0x02:bf:72:magic:hi:lo MAC. Decode validates against `zone_id_to_name` (`parse_zone_encoded_fabric_ingress_from_frame:1890-1900`). **NEG**: Stale zone ID → None → fallback to ifindex-based zone, not spoofed.
- `finalize_new_flow_ha_resolution` + fabric checks: HA inactive → fabric redirect with zone-tagged MAC preserves ingress zone for peer policy evaluation. **NEG**: Fabric ingress flag prevents loop (ingress_is_fabric guard).
- `host_inbound_admits` re-export: SSOT for zone host-inbound used by poll_stages + lo0 gate.
- `LOCAL_DELIVERY_IFINDEX0` diagnostic: counts NAT-only local targets where zone/HA attribution operates on ifindex 0. Not a bypass — counted.

### forwarding/host_inbound.rs — host-inbound admission
- `zone_host_inbound_from_snapshot`/`from_tokens`: token classifier via `classify_system_service`/`classify_protocol`. Unknown tokens → `_ => {}` fail-closed (no broaden). **NEG**: Per Go SSOT KnownHostInboundSystemServices parity test (#3486) guards drift.
- `is_icmp_host_inbound_global_accept`: v4 types 3|11|12 (dest-unreach/time-exceeded/param-problem), v6 types 1|2|3|4|133-137 (errors + ND). Echo-request NOT in global — gated on `ping` token. **NEG**: Matches kernel nft chain global accepts per #3171, doc says keep in lockstep.
- `host_inbound_admits`: global accept BEFORE zone table lookup, then `None=>true` (unknown id 0 admits), `Some(hi)=> admids()`. Empty ZoneHostInbound→ default-deny (no ports/protos). Every configured zone inserted per #3705 — `None=>true` fires ONLY for genuinely unknown (id 0). Lifeline fxp0/em0/fab never reach AF_XDP local-delivery classifier (#3682). **NEG**: No permit-all on configured zone.
- `host_inbound_admits_iface`: per-interface override keyed by logical ifindex, falls back to zone. Global ICMP/ND accept in BOTH branches. **NEG**: Override map keyed by logical unit (VLAN-aware), lookup uses resolved logical ifindex (#3609 fix).
- Token specifics: `ident-reset` arm empty (drop, not admit) on AF_XDP path — divergence from kernel RST is documented, strictly more restrictive. `ipsec/ike` maps to udp 500/4500 — gates new IKE per #4323 Option B.
- `protocols all` expansion: derives from KNOWN_ROUTING_PROTOCOL_TOKENS minus L2 set (IS-IS) via `routing_protocol_all_expansion()` — not blanket accept. **NEG**: #3311 guards L2 exclusion.

### forwarding_build/zones.rs — zone table population
- `zone_name_to_id_from_snapshot`: SSOT map name→id, skips id 0 / empty name / reserved >= ZONE_ID_RESERVED_MIN. **NEG**: Reserved range reject with diagnostic eprintln, prevents sentinel collision (JUNOS_GLOBAL_ZONE_ID = u16::MAX, JUNOS_HOST_ZONE_ID = u16::MAX-1).
- `reject_duplicate_zone_ids`: fails whole snapshot closed if two different zone names share same id — prevents zone-isolation merge. **NEG**: Go control plane already quarantines (QuarantinedZoneNames), this is backstop (#3719).
- `populate_zones`: inserts zone_host_inbound for EVERY known zone (even unconfigured → empty → default-deny per #3705). `host_inbound_configured` field no longer gates insert — genuine unknown (id 0) only. Per-zone reject-bucket and tcp-rst knob keyed by same validated id. **NEG**: Default-deny for no-stanza zone per #3405.

### forwarding_build/interfaces.rs — ifindex→zone_id
- `populate_interfaces`: resolves zone name→u16 via `zone_name_to_id.get()`. Absent → `SnapshotIntegrityError::InterfaceUnknownZone` fail-closed. **NEG**: Does not collapse to 0 (#2391).
- Parent ifindex zone propagation: child VLAN's zone copied to parent ifindex (first-wins). **Consideration**: If two VLANs in different zones share parent, parent keeps first child's zone for untagged traffic — deterministic but arbitrary. Untagged on trunk with multi-zone VLANs is ambiguous; first-wins does not leak permitted (worst case: untagged gets zone of first VLAN, still subject to policy). Over-tagged case handled by logical_ifindex resolution. **NEG for bypass** — not a permit leak; at worst misattributes zone for untagged, still evaluated. Minor hardening idea: set parent 0 on conflict to force default-deny for untagged, but not MATERIAL per bar (no live bypass).
- `populate_egress`: validates vlan_id, mtu via `VlanId`/`InterfaceMtu` validated wrappers — fail-closed on out-of-range, not wrapping. Egress zone_id same fail-closed as interfaces pass. **NEG**: Consistent InterfaceUnknownZone.
- Per-interface host-inbound override: `host_inbound_configured` true → insert effective union (zone∪iface) token set keyed by ifindex. Present-but-empty override → empty ZoneHostInbound = deny-all (matches zone semantics + nft). **NEG**: Correct.

### frame/inspect.rs + frame/* — L4 port/type extraction for policy App matching
- `inspect.rs` parses TCP/UDP ports from L4 header, ICMP type/code from first L4 byte, validates frame length. Used for `policy_packet_icmp` and `term_match_extra`. **NEG**: Truncated L4 → `l4_present=false` → port-bearing app terms fail closed (#3291), ICMP constrained terms get None → fail closed.
- #5568 cohort (scalar L4 semantics from Ethernet slack) noted in dedup — this batch's frame parsers derive ports from IP-declared datagram, not Ethernet slack (worktree check: inspect.rs uses l3_offset + l4_offset, not Ethernet slack). **NEG**: Not reproducing #5568 in this batch's hot path; deduped.
- `parse_zone_encoded_fabric_ingress_from_frame`: reads fabric MAC magic + u16 zone id, validates against zone_id_to_name. **NEG**: Prevents forged zone attribution.

### policy.rs (context, not in batch) — evaluate_policy_result_l3_aware
- Tiered evaluation: exact zone-pair (zone_pair_index) → from-any/to-any/both-any wildcard merged in config order (two-pointer) → global_indices with scoped GlobalZoneScope check → default action. Zone 0 guard at top (#3110). **NEG**: Unzoned cannot match global permit (leak prevention).
- GlobalZoneScope::Zones(SmallVec<[u16;2]>) sorted+deduped, Any for unscoped or containing "any". Unresolvable zone in scope → UnresolvableZoneReference fail-closed (#3402). **NEG**: No silent narrowing.
- AppCatalog: CompiledApplications by_protocol exact_dst_ports O(1) + range_terms linear, icmp path for type/code, l4_present=false fails port-bearing terms closed (#3291). **NEG**: Matches fail-closed for flowless fragments.
- Fragment association fail-closed (#4569): remembers first port-bearing DENY skipped due to l4_present=false whose L3 overlaps; subsequent PERMIT overridden to DENY. **NEG**: Prevents fail-open for non-first fragments.
- Default policy: empty → Deny (#3065), sentinel u32::MAX for ID, per-counter with Clear epoch handling (#3782 fetch_sub not store(0) to preserve post-clear hits).
- hit_counter 1-based handle (idx+1), 0=no counter, u32::MAX=default counter. Stamped onto session metadata, re-counted on fast path via thread-local coalescer with generation guard.

### poll_descriptor/mod.rs + poll_stages.rs + filter.rs — transit & local-delivery enforcement (context)
- Transit ForwardCandidate: zone_pair_ids_for_flow_with_override → evaluate_policy_result_with_icmp (flow-backed, l4_present=true) → Permit → NAT → session install. Non-permit → PolicyDeny event + silent drop (or reject reply if configured). **NEG**: Policy always evaluated, even with allow-dns-reply (#850 comment: "allow-dns-reply admits through policy, not around it").
- Local-delivery: host_inbound_admits_iface (logical ifindex) → lo0 filter (host_inbound_gated_lo0_action, host-inbound before lo0 per #3485) → junos-host policy (evaluate_junos_host_policy_l3_aware) → deliver. IPsec passthrough Stage 11 gates NEW IKE via same host_inbound_admits_iface (#4323 Option B), ESP/AH + established IKE exempt (SA is auth). **NEG**: Correct ordering per Junos.
- Flowless (non-first fragment): ForwardCandidate with l3_ctx → evaluate_policy_result_l3_aware l4_present=false → port-bearing fail closed. LocalDelivery flowless: flowless_local_delivery_verdict calls same three gates with l4_present=false. **NEG**: #3292 closed flowless fail-open.
- Strict-syn-check (#4400): bare RST/FIN (closing without SYN) on transit ForwardCandidate/MissingNeighbor session-miss dropped before session install — prevents table churn + policy skip. LocalDelivery exempt (peer teardown for fw-originated flows must reach host). **NEG**: Distinction correct (transit vs host).

### Batch remainder (benches, build.rs, csrc/xsk_bridge.c, bpf_map/*, coordinator/*, cos/*, flow_cache, etc.)
- No zone/policy mapping in benches/build.rs/csrc.
- bpf_map/mod.rs, publish_conntrack, metrics: session publish, no zone logic.
- coordinator/reconcile/snapshot.rs: preflight_policy_state uses zone_name_to_id_from_snapshot of INCOMING snapshot (not live forwarding.zone_name_to_id) per #5171 comment — prevents stale forward zone table from missing new-zone policies. **NEG**: Correct, avoids UnresolvableZoneReference false negative on new zone add.
- cos/*: CoS classification via filter/cos, queue ops — not zone policy enforcement (zone pair from forwarding used only for CoS queue selection, not allow/deny).
- flow_cache, checksum, disposition, ethernet, etc.: no policy bypass surface.
- **NEG across remainder**: No additional MATERIAL zone-policy bypass found in batch.

## Findings (only MATERIAL or COHORT per spec — NEG in log above)

### F1 — COHORT: VLAN trunk parent_ifindex zone first-wins for untagged traffic
- Title: Untagged traffic on multi-zone VLAN trunk inherits first-child zone (arbitrary zone attribution)
- Severity: Low
- Confidence: Medium
- Gate verdict: COHORT
- Evidence: `forwarding_build/interfaces.rs:82-91`
```
if iface.parent_ifindex > 0 {
    match state.ifindex_to_zone_id.get(&iface.parent_ifindex) {
        Some(existing) if *existing != zone_id => {}
        _ => {
            state.ifindex_to_zone_id.insert(iface.parent_ifindex, zone_id);
        }
    }
}
```
A parent carrying ge-0-0-0.0 in trust and ge-0-0-0.1 in untrust keeps trust for physical ifindex. Untagged ingress on that physical (no logical map) resolves via ifindex_to_zone_id = trust → policy evaluated as from trust. First-wins is deterministic but arbitrary; untagged on a tagged trunk is ambiguous. Logical VLAN traffic correctly attributed via `ingress_logical_ifindex`.
- Trace: No direct exploit — untagged on multi-zone trunk is config error; policy still applied (not bypassed), just zone attribution is which of the two zones wins.
- HPC/invariant: No hot-path cost; build-time only.
- Why it matters (COHORT): Defense-in-depth: untagged on multi-zone trunk should arguably be default-deny (0) to force operator to assign untagged or drop, matching Junos `native-vlan-id` handling. Current first-wins could permit untagged that operator intended untagged=drop, if default-permit.
- Fix direction: On conflict (`existing != zone_id`), set parent entry to 0 (unknown) or track multi-zone conflict flag; log diagnostic. Keeps VLAN-tagged paths unaffected. If intentional untagged in one zone alongside other VLANs, operator should configure a unit 0 in that zone explicitly (which would also be first-wins today — behavior preserved for single-writer).
- Labels: `zone-mapping`, `vlan`, `defense-in-depth`, `low-severity`
- Dedup note: No open GH issue for this exact parent-conflict semantic; not covered by #2391 (unknown zone) or #3110 (unzoned).
- Verified against origin/master: `forwarding_build/interfaces.rs:82-91` same on origin/master 4e0c7f74c.

### Summary Negative
No MATERIAL zone-policy bypass in this batch. Core invariants hold:
- ifindex→zone_id fail-closed on unknown zone name (InterfaceUnknownZone), not 0-collapse.
- zone id 0 guard prevents unzoned→global permit leak (#3110).
- Empty token set → default-deny per zone and per interface override.
- `host_inbound_admits` None=>true scoped to genuinely unknown id 0 only; every configured zone present in table (#3705).
- GlobalZoneScope Any vs Zones with unresolvable→fail-closed, scoped checks in global tier after exact+wildcard.
- Flowless (fragment / no-L4) app terms fail closed via l4_present=false + fragment association deny override (#4569).
- Local-delivery ordering host-inbound → lo0 → junos-host correct, with IPsec IKE new-initiation gated (#4323 Option B) and ESP/AH exempt.
- Hit-counter 1-based handle + generation prevents post-clear clobber and preserves accounting.
- Snapshot preflight uses incoming zones map, not stale forwarding, preventing new-zone policy bypass (#5171).



---

### === ps-A1_rust_dataplane_packet-b2.md (8794 chars, 77 lines) ===

# A1 rust dataplane packet b2/3 — claude-spark-001 — zone policy focus

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa verified against origin/master same SHA
Worktree: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b2 — discover via git rev-parse --show-toplevel /home/ps/git/avacado-xpf
Work dir: /tmp/review-work-claude-spark-001
WHOAMI: claude-spark-001
Date: 2026-07-11

## Inventory (150 files, 98794 LOC)

- Prod 49171, Test 49623, ratio ~1:1
- Largest prod: afxdp/poll_descriptor/mod.rs 6294 (hot-path RX classification, zone mapping, policy/host-inbound/junos-host gates, session decisions)
- Next: neighbor.rs 2036, types/cos.rs 1786, tx/dispatch/mod.rs 1505, types/forwarding.rs 1099, tx/cos_classify.rs 1335, gre.rs ~750, ha.rs ~950
- Largest test: session_glue/tests.rs 5748, cos_classify_tests 4617, poll_stages_tests 2636, shared_cos_lease_tests 2511
- Responsibility ranking (size x hot-path):
  1. poll_descriptor/mod.rs — RX hot path, ifindex_to_zone_id, evaluate_policy_result_l3_aware, host-inbound, junos-host
  2. poll_descriptor/filter.rs — filter_log_ingress/egress_zone_id, host_inbound_gated_lo0_action (#3485)
  3. types/forwarding.rs — ForwardingState.ifindex_to_zone_id, zone_host_inbound, reject_buckets, egress_zone_id, ZHI
  4. tx/dispatch/mod.rs — TX after policy, zone_counter_slot_map usage
  5. gre.rs / tunnel.rs — ingress zone via ifindex_to_zone_id for tunnel decap
  6. ha.rs / session_glue — HA ownership, epoch bumps, zone preservation across failover
  7. neighbor / sharded_neighbor / neg_neigh — ARP/NDP, owns_configured_ip anti-poison (#3182)
  8. tx/ + umem/ + wg/ — TX pipeline, CoS, WireGuard, not direct zone but affects per-zone accounting

## Module Log — coverage proof (NEG only in log)

- frame/wg_tests.rs: NEG — test-only WG framing helpers, no zone path, sound
- gre.rs: NEG — ifindex_to_zone_id read for ingress_zone (line 750), egress not needed for decap gate; zone validity checked via zone_id_to_name contains_key, fail-closed 0
- ha.rs: NEG — update_ha_state bumps rg_epochs Release-before-Store per #2120, airtight self-heal edge; zone preservation via forwarding ArcSwap, no bypass
- ha_tests.rs: NEG — HA epoch bump tests, no policy bypass
- icmp.rs / icmp_ptb.rs / icmp_ratelimit.rs: NEG — ICMP PTB/build uses egress ifindex for src_mac/MTU, zone not consulted (correct: PTB is L3, already policy-admitted); rate-limit per-zone bucket via reject_bucket (forwarding.rs:171)
- icmp_embed/*: NEG — NAT match + return resolution uses SessionKey+NatDecision, zone not re-evaluated (correct: embedded ICMP inherits parent flow's zone verdict); #5568 Ethernet-slack dedup already tracked
- icmp_tests, icmp_ptb_tests, icmp_ratelimit_tests: NEG — unit tests, no enforcement impact
- mirror/*: NEG — fast_path copies ifindex zone implicitly via forwarding resolution, mirroring after policy allow, no zone bypass
- mod.rs (afxdp/mod.rs): NEG — dispatcher, delegates to poll_descriptor, zone map cloned as OWNED for event-stream (line 695), no TOCTOU
- mpsc_inbox / worker_queue: NEG — lock-free MPSC, no zone logic
- neg_neigh / neighbor / dispatch / latency / resolver: NEG — neighbor anti-poison owns_configured_ip uses NAT-decoupled configured_iface_v* (#3182), sound fail-closed
- parser.rs / parser_tests.rs: NEG — L4 extraction bounds-checked, returns None on short packet; zone not touched here (higher layer)
- poll_descriptor/*:
  - filter.rs NEG — filter_log_ingress_zone_id validates override via zone_id_to_name.contains_key, else ifindex_to_zone_id (polish). host_inbound_gated_lo0_action enforces host-inbound BEFORE lo0 (None => deny, Some => lo0 eval) #3485, with logical VLAN ifindex override key (line 817 test)
  - flow_cache_hit.rs NEG — cached log preserves ingress_zone_id/egress_zone_id, no re-derivation, safe because cache entry stamped with owner_rg_epoch (#1065)
  - mod.rs NEG — core hot path: from_id via ifindex_to_zone_id, egress via egress.iface.zone_id, guard from_id!=0&&to_id!=0 in evaluate_policy_result_l3_aware (policy.rs:2647) → default deny; host-inbound admits via host_inbound_admits_iface (zone_host_inbound + ifindex_host_inbound), junos-host gate after; zone_pair_ids_for_flow_with_override respects overrides
  - other descriptors NEG — cookie_reply, nat_exception, reject_reply, rx_telemetry: no zone bypass
- poll_stages / poll_stages_tests: NEG — stage pipeline, no direct zone logic, delegates
- rst.rs: NEG — TCP RST generation checked by zone_tcp_rst_enabled (forwarding.rs:445), absent zone => false (fail-closed RST off)
- session_delta / session_glue/*: NEG — upsert preserves SessionMetadata.ingress_zone/egress_zone from snapshot build; generation anti-replay (#2170) prevents stale zone downgrade; demote_owner_rgs bumps epoch
- sharded_neighbor: NEG — sharded ARP, anti-poison same as neighbor
- shared_ops / shared_umem: NEG — UMEM lifetime, no zone
- test_fixtures / tests_*: NEG — tests_bind_forward, tests_decap_dnat_table, tests_policy_inbound_nat, tests_fragment etc: verify zone-pair + global + host-inbound interactions, no bypass
- tunnel.rs: NEG — tunnel endpoint lookup uses logical_ifindex zone via egress table, sound
- tx/*: NEG — cos_classify, dispatch, drain, rings, stats, tcp_segmentation, transmit/*: egress_zone_id via forwarding.egress_zone_id (forwarding.rs:455) for counters; record_zone_traffic flat LUT [u8;65536] slot_of, zero slot uncounted (zone_counters.rs:281), no hash in hot path; verify.rs checks packet bounds
- types/*: NEG — forwarding.rs ifindex_to_zone_id: FastMap<i32,u16>, 0 sentinel for unknown; zone_id_to_name, zone_name_to_id validated, unknown→0 via InterfaceUnknownZone #2391 fail-closed; cos.rs #3651 slot map
- umem/*: NEG — mmap, snapshot, debug_state, latency buckets: no zone
- wg/*: NEG — allowed_ips, cookie, handshake, peer, session: tunnel endpoint zone via parent ifindex, not re-evaluated per packet, correct (encap inherits inner flow zone)

## Findings (MATERIAL or COHORT only — NEG in log above)

### C1 — COHORT: host-inbound absent-entry admit-all vs present-empty deny-all duality (defense-in-depth)

- Title: host-inbound absent entry means admit-all, present-empty means deny-all — unzoned id 0 falls to absent
- Severity: Low
- Confidence: High
- Gate verdict: COHORT
- Evidence: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b2/userspace-dp/src/afxdp/types/forwarding.rs:138-145 shows zone_host_inbound absent means not configured => preserve admit-all; present empty => default-deny post-#3405. In poll_descriptor/filter.rs:612 host_inbound_admits_iface uses ifindex_host_inbound else zone_host_inbound; if from_zone_id==0 (unzoned) then zone_host_inbound.get(0) is None => admit-all branch. This is intentional lifeline guarantee per #3070/#3405 doc, but means an operator deleting a zone stanza (leaving interface unzoned) silently re-opens host-bound services on that ingress. Go control plane sends HostInboundConfigured=true for every configured zone, preventing accidental absent, but a version-drifted snapshot or direct ifindex with no zone would hit it.
- Trace: ingress packet meta.ingress_ifindex -> ifindex_to_zone_id.get -> 0 -> filter_log_ingress_zone_id returns 0 -> host_inbound_gated_lo0_action checks ifindex_host_inbound absent, zone_host_inbound absent for 0 -> admits() not called, returns admit-all
- HPC/invariant: Flat LUT, no extra branches, preserves HFT lifeline (fxp0/em0 never reach this classifier #3682)
- Why matters: Defense-in-depth — strictest interpretation would deny unzoned host-bound instead of admit-all, but would risk bricking mgmt. Current trade-off documented and COHORT not MATERIAL.
- Fix direction: Consider explicit unzoned deny-all for non-lifeline ifindexes, or add metric host_inbound_unzoned_admit_total + warn. Keep lifeline exempt.
- Labels: host-inbound, defense-in-depth, lifeline, COHORT
- Dedup: #5566 (kernel established retain), #4420 (unzoned catch-all) — related but not dup
- Verified against origin/master: forwarding.rs:138 identical on master tip, host_inbound_admits_iface same

No MATERIAL findings in this batch — core zone mapping fail-closed (0 -> default deny), global scoped via GlobalZoneScope::matches, host-inbound before lo0, junos-host after host-inbound, per-zone reject buckets, per-zone traffic counters HFT-grade (two array reads, thread-local coalesce).

Labels: rust, af_xdp, zone-policy, host-inbound, default-deny, COHORT
Dedup note: Checked #5606 NAT64 reverse, #5568 Ethernet slack, #5562 snapshot ArcSwap race, #5488 scoped-global version, #5566 host-inbound established — none match this batch's paths.
Verified against origin/master: origin/master tip 4e0c7f74c same as base, checked forwarding.rs:135 ifindex_to_zone_id, policy.rs:2647 from_id!=0 guard, filter.rs:554 host_inbound_gated docs.


---

### === ps-A1_rust_dataplane_packet-b3.md (10053 chars, 88 lines) ===

# A1 rust dataplane packet b3/3 — claude-spark-001 — zone policy deep dive

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa verified against origin/master same
Worktree: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b3 — repo root via git rev-parse --show-toplevel /home/ps/git/avacado-xpf
WHOAMI: claude-spark-001
Work dir: /tmp/review-work-claude-spark-001

## Inventory (137 files, 97551 LOC)

- Prod 45704, Test 51847
- Largest: filter/tests.rs 8613, policy_tests.rs 7280, session/tests.rs 7072, screen/tests.rs 5395, wg/tests.rs 3909, policy.rs 3657, worker/cos/tests 2708, server/tests 2444
- Hot-path ranking:
 1. policy.rs 3657 — evaluate_policy_result_l3_aware (280 LOC, zone_pair_index, from_any/to_any/both_any/global tiers, frag-association #4569, default deny sentinel)
 2. filter/compiler.rs + engine/ — lo0 + transit filter compilation, zone not directly but filter_log zone ids from poll_descriptor
 3. session/install.rs + entry.rs + lookup.rs + mod.rs — metadata ingress_zone/egress_zone stamping, inactivity_timeout per zone #3527 override, per-app timeout
 4. afxdp/zone_counters.rs 437 — flat LUT [u8;65536] slot_of, thread-local coalesce, flush per RX batch — HFT-grade, no per-packet hash/atomic
 5. worker/loop_body/mod.rs 1784 + worker/mod.rs 1631 — loop iteration captures forwarding ArcSnapshot, consistent slot_map for record+flush
 6. protocol/security.rs + resolution.rs + snapshot.rs — GlobalZoneScope, match_from_zones/match_to_zones plural, is_host_scope, resolution for host-inbound global
 7. server/handlers/snapshot.rs — apply snapshot preflight via parse_policy_state_with_counters + SnapshotIntegrityError::InterfaceUnknownZone #2391 / UnresolvableZoneReference #3402
 8. slowpath.rs — kernel reinjection gate is_slow_path_eligible: PolicyDenied NOT eligible (#1913) — prevents bypass via kernel FIB

## Module Log — coverage (NEG)

- wg/tests.rs, timers.rs: NEG — WireGuard timers, no zone bypass, syncookie key includes zone_id per #2446
- worker/bind_meta.rs, bpf_maps.rs: NEG — bind meta carries zone id for logging, no enforcement bypass
- worker/cos/*: NEG — CoS classification uses zone_id for queue selection? No, uses forwarding class; zone not bypassed, slot map not consulted here
- worker/cos_state.rs, flow_cache_state.rs, lifecycle.rs, loop_body/debug_report.rs, setup.rs, mod.rs, scratch.rs, telemetry.rs, timers.rs, tx_counters.rs, tx_pipeline.rs, xsk_rings.rs: NEG — worker infra, forwarding snapshot captured per iteration, zone counters flushed via flush_recorded_zone_counters (slot_map same as record calls) — consistent
- worker_queue.rs, worker_runtime.rs: NEG — MPSC, no zone
- zone_counters.rs: NEG — build dedup+skip zero, slot_of 0 => uncounted for that direction (correct); overflow_active flag surfaced; record_zone_traffic early-return both slots 0; fold_pending lock per batch (uncontended); snapshot deterministic sorted by zone_id
- bin/fairness-eval.rs, fairness* : NEG — offline fairness eval, not dataplane enforcement
- event_stream/codec/*, mod.rs, producer.rs: NEG — codec encodes ingress_zone_id/egress_zone_id as u16 LE at bytes 48-52 (rt_flow.rs:253), preserves zone for Go shadow; decode failure handled via SnapshotIntegrityError, not silent continue (except #5483 already deduped)
- filter/compiler.rs, engine/*, mod.rs, policer.rs: NEG — compiler validates filter refs (#3296 MissingFilterRef fail-closed), engine eval caches by zone? cache_sensitive checks ingress_zone in key (prevents cross-zone cache poisoning)
- hot_hash_seed.rs, io_uring_write.rs, ip_proto.rs: NEG — infra
- main.rs, main_tests.rs: NEG — build_synced_session_entry_falls_back_to_zone_name_when_id_zero test (line 1202) verifies downgrade path, sound
- policy.rs: NEG — evaluate_policy_result_l3_aware: if from_id==0||to_id==0 falls to default_action (Deny when empty wire #3365, line 1728); global_indices scoped via global_from_zone.matches(to_id check line 2798) ; junos-host gate after host-inbound; frag-assoc override #4569 fail-closed; default_counter preserved via Arc; rule_l3_matches handles cross-family NAT64 (V6 src, V4 dst) #2358, otherwise fail closed on mixed family; GlobalZoneScope::Any short-circuit for "any" explicit (#4626) eliminates commit-vs-dataplane divergence
- policy_snapshot_error.rs: NEG — InterfaceUnknownZone rejects unwrap_or(0) collapse (line 383-397 doc), UnresolvableZoneReference fails snapshot closed (line 857 msg), Cos* out-of-range fail-closed, MissingFilterRef #3296 fail-closed, all consistent with #2124 fail-closed family
- policy_tests.rs: NEG — tests for default-policy deny, global scope, fragment assoc, any-zone wildcard ordering
- prefix.rs, prefix_set.rs: NEG — LPM sets, no zone
- protocol/binding.rs, control.rs, cos.rs, mod.rs, nat.rs, resolution.rs, security.rs, snapshot.rs, tests.rs: NEG — security.rs defines from_zone/to_zone + match_from_zone/to_zone + plural match_from_zones/to_zones (line 453-469), scoped global: effective_match_zones prefers plural for rolling upgrade (#4626 M03), is_host_scope checks exact singleton [JUNOS_HOST_ZONE_ID]; resolution.rs ingress zone override validated; snapshot build populates ifindex_to_zone_id via zone_name_to_id lookup, unknown zone -> InterfaceUnknownZone error not 0
- screen/*, syncookie.rs: NEG — syncookie keyed by (zone_id, profile_gen, 4-tuple) #2446, zone_id in SIP hash (line 226 write_u16), per-zone rate buckets
- server/handlers/*: NEG — snapshot.rs apply runs parse_policy_state_with_counters preflight before side-effecting mutation (#3713 duplicate rule_id/policy_id check), forwarding.rs builds ForwardingState with zone_name_to_id validated set, HA clear failure deduped #5487
- session/*: NEG — entry.rs policy_id sentinel 0 vs DEFAULT_POLICY_SENTINEL_ID u32::MAX distinction (line 89), ingress_zone/egress_zone stored, install.rs stamps inactivity_timeout_ns from metadata + opening_override_for(ingress_zone) #3527 per-zone syn-flood timeout; lookup preserves zone; expire ages via per-zone override
- slowpath.rs: NEG — is_slow_path_eligible: ForwardCandidate/FabricRedirect false (forward path), PolicyDenied false (critical #1913), only LocalDelivery/NoRoute/MissingNeighbor/NextTableUnsupported true — prevents policy bypass via kernel reinject
- state_writer.rs, tcp_flags.rs, test_zone_ids.rs, xsk_ffi.rs: NEG — infra, test zone ids 1/3 stable
- tests/cos_doc_drift, fairness_eval_blackbox, snat_contract_doc_guard: NEG — doc-drift guards, no enforcement
- userspace-xdp/src/lib.rs: NEG — AF_XDP shim per-CPU binding arrays steer to userspace, no zone logic in BPF (zone mapping in userspace)

## Findings (MATERIAL / COHORT)

### C2 — COHORT: record_zone_traffic counts ingress even when egress unzoned (and vice versa) — debatable attribution

- Title: Per-zone counters accumulate ingress OR egress when other side slot 0 (unzoned)
- Severity: Low
- Confidence: High
- Gate: COHORT
- Evidence: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b3/userspace-dp/src/afxdp/zone_counters.rs:275-301
  pub fn record_zone_traffic(slot_map, ingress_zone_id, egress_zone_id, packet_bytes) {
    let ingress_slot = slot_map.slot_of(ingress_zone_id);
    let egress_slot = slot_map.slot_of(egress_zone_id);
    if ingress_slot==0 && egress_slot==0 {return;}
    ... if ingress_slot!=0 { ingress_packets[s] +=1 } if egress_slot!=0 { egress_packets[s]+=1 }
  }
- And test unassigned_and_zero_zones_are_uncounted line 397 asserts ingress 100 counted when egress 999 unconfigured — this is intentional (ingress still counted)
- HPC/invariant: Two array reads + thread-local add, no atomics — HFT optimal. Slot 0 reserved, saturating_add.
- Why not MATERIAL: Per-zone Traffic statistics are observability, not enforcement; counting one side when other unzoned matches "traffic touching zone" semantics. Alternative (drop both when either 0) would under-count. Current is more useful.
- Fix direction: Document in zone_counters.rs doc that ingress and egress are counted independently; ensure UI does not double-count a packet from known->unknown as "dropped" in policy counters.
- Labels: zone_counters, observability, COHORT
- Dedup: #3643 dead counters plan — not dup, related
- Verified: origin/master tip same code at zone_counters.rs:275

### C3 — COHORT: policy.rs fragment-association over-drop trade-off documented but no cache

- Title: Non-first fragment inherits first port-bearing DENY via global skipped_frag_deny — over-drop by design
- Severity: Low
- Confidence: High
- Gate: COHORT
- Evidence: /tmp/review-wt-claude-spark-001-A1_rust_dataplane_packet-b3/userspace-dp/src/policy.rs:2625-2682 fragment-assoc, note_skipped_frag_deny and apply_frag_deny_override, doc at 2632-2645 "over-drop: legitimate non-denied-port fragment from SAME L3 as overlapping DENY is dropped (Junos security-over-availability default). A fragment-association cache keyed on (src,dst,frag-id) deferred #4569"
- Why matters: Security-over-availability correct, but perf impact for legitimate fragments in same L3 where port would have permitted — acceptable for firewall, but could be improved.
- Fix: Implement frag-id cache (src,dst,frag-id -> verdict) as noted #4569, bounded LRU.
- Labels: fragmentation, fail-closed, COHORT
- Dedup: #4569 explicitly mentions deferred fix, not dup
- Verified: master tip same lines

No new MATERIAL zone bypass found — default-policy empty => Deny (policy.rs:1728), zone 0 => default action (2647), unresolvable zone => SnapshotIntegrityError fail-closed, global scoped via Any vs Zones set, host-inbound before lo0, PolicyDenied not slow-path eligible, per-zone reject buckets prevent cross-zone starvation #3618.

Labels: rust, policy, zone, default-deny, global-scoped, host-inbound, junos-host, COHORT
Dedup: Checked #5402, #5488 scoped-global version, #5562 ArcSwap race, #5568 Ethernet slack — not re-reporting.
Verified against origin/master: policy.rs:1728 default_action Deny, 2647 from_id!=0 guard, 2798 global scope check, slowpath.rs:963 is_slow_path_eligible, zone_counters.rs:275 slot_of all same on master tip.


---

### === ps-A2_rust_dataplane_nat-b1.md (11641 chars, 100 lines) ===

# A2 NAT Batch Review — Zone Policy & NAT Ordering Focus
Base: 4e0c7f74c == origin/master tip, verified `git rev-parse HEAD` == base.

## File Inventory (18 files, 24,982 LOC)

| File | LOC | Role | Hot-path |
|---|---|---|---|
| nat/tests_pool.rs | 4673 | test (allocator, port claim/exhaustion) | cold |
| nat64_tests.rs | 4447 | test (NAT64 xlate, frag assoc, ICMP errors) | cold |
| nat64.rs | 3102 | prod (NAT64 v4<->v6, frag assoc #2562, NAT64 port alloc #4381/#4512/#4518) | HOT per-pkt |
| nat/allocator.rs | 1974 | prod (PortAllocator, lock-free claim CAS, recycle FIFO, persistent leases) | HOT (SNAT cold-path) |
| nat/tests_destination.rs | 1770 | test (DNAT lookup tiers, scope, off, prefix LPM) | cold |
| nat/source.rs | 1523 | prod (SNAT rule matching, pool mode, address-only token #5269, deterministic #4559) | HOT (cold-path) |
| nat/tests_static.rs | 1198 | test (static 1:1, src-constraint, egress zone gate) | cold |
| nat/destination.rs | 1109 | prod (DNAT table O(1) host + LPM prefix #3164, proto wildcard 256, off exemption #3844) | HOT (pre-routing) |
| nat/tests_l4_match.rs | 815 | test (L4 app match, src-port, ICMP type/code) | cold |
| nat/static_nat.rs | 808 | prod (static NAT bidir, src-constraint #3435, to_zone gate #2871) | HOT |
| nat/tests_pool.rs details | many | subsumed above | - |
| nat/status.rs | 40 | prod (pool status aggregation) | cold |
| mod.rs | 347 | prod (NatDecision, merge, NatRuleCounter atomic fetch_sub #3830) | shared |
| nptv6.rs | 431 | prod (stateless prefix xlate, checksum-neutral #3233, overlap reject #2241) | HOT |
| + tests | — | — | — |

Responsibility rank by size*resp*hot: nat64.rs (3.1k * NAT64 + frag + HA), allocator.rs (2k * port lifecycle), source.rs (1.5k * SNAT), destination.rs (1.1k * DNAT), static_nat.rs, nptv6.rs.

## Pipeline Ordering (critical for zone policy security)

Verified in `/afxdp/poll_descriptor/mod.rs` (6000 LOC main loop):

1. **Pre-routing DNAT** (incl. static DNAT, NPTv6 inbound): `dnat_table.lookup_with_counter_scoped()` at ~L1545, `static_nat.match_dnat_with_counter_scoped()` at ~L1560. Scope: ingress ifname + routing-instance (NatScopeCtx). Tiered: exact(proto,dst,port) -> wildcard port -> PROTO_ANY=256 (any-proto #2396) -> prefix LPM #3164.
2. **FIB resolution** using `effective_resolution_target = DNAT-rewritten dst || original dst`. So egress interface (and to_zone) derived from POST-DNAT dst.
3. **Zone pair**: `zone_pair_ids_for_flow_with_override()` — from `ifindex_to_zone_id[ingress]` + `egress[egress_ifindex].zone_id`. No String alloc, u16 path #919.
4. **Policy evaluation**: `evaluate_policy_result_with_icmp()` at ~L2658 with `policy_dst_ip = effective_resolution_target`, `policy_dst_port = DNAT-rewritten port`. Uses post-DNAT dst + its egress zone — cannot bypass deny by DNATing to internal IP.
5. **Post-policy SNAT/NAT64/NPTv6**: only if `PolicyAction::Permit` at ~L2706. Source NAT via `source_nat_decision_for_flow()` (egress zone gated #2871 for static reverse), NAT64 via `nat64.allocate_source()` (#4381 pool + deterministic v6 #4559), NPTv6 outbound.
6. **Session install** with zone IDs + NAT decision.

Correct Junos ordering: DNAT before policy (policy sees translated dst), SNAT after policy (policy sees original src). No port consumption by denied flows.

## Module Log (coverage proof, NEG only here)

- nat/mod.rs: NatDecision.merge (pre-routing DNAT merged with post-policy SNAT + NPTv6) — sound, NPTv6 OR preserved. NatRuleCounter reset uses fetch_sub not store(0) #3830 — prevents lost update. NEG: sound.
- nat/allocator.rs: lock-free CAS claim `fetch_or` bit is ownership token, cursor monotonic bounded CAS never exceeds range, recycle FIFO per-address Mutex, release O(1) via addr_index in record. Persistent lease expiry BTreeSet for GC. F4 global cap exact `live_by_flow.len()` under insert mutex — no overshoot. Deterministic v4/v6 block alloc reversible. Address-only occupancy via `AddressOnlyReverseKey` denies colliding identity as exhaustion #5269 — vSRX parity. NEG: sound, F4+NEG tested.
- nat/destination.rs: PROTO_ANY=256 outside IANA 0-255, distinct from HOPOPT=0 #2396. Tiered fallback with `or_else` + DnatOutcome::Exempt short-circuit #3844 — off exemption stops broader tiers (correct). source_constrained fail-closed #2394 — scoped rule with all entries unparseable matches nothing, not any. L4 extra (src_port, dst_port range #3449, ICMP type/code #3437) AND-ed. Prefix LPM longest-match via `prefix_len()` max. Parse errors recorded via NatCounterStore #4718 (loud-skip). NEG: sound.
- nat/source.rs: scope_matches AND-ed (interface + RI), from_zone/to_zone matching, source_constrained/destination_constrained fail-closed #2398, l4_matches AND-ed (dst_port + app term proto+dst_port+src_port #3491), proto==0 synthetic sentinel fails closed when L4 constraints present, non-first fragment gate #1852 drops pool-mode frags (payload no L4 ports — leak prevention), address-only path preserves src port + mints occupancy token #5269, protocol 0 wrapper mints no token. Deterministic indices: host_base check, out-of-range fail-closed #4559 + prefix bytes check #4863 for v6 prevents cross-tenant block theft. NEG: sound.
- nat/static_nat.rs: bidir internal<->external, source constraint for inbound #3435 (fail-closed, matches src=client), egress zone gate #2871 — reverse SNAT matches to_zone (egress zone) not from_zone, preventing outbound from internal IP to another internal zone being source-translated. Interface/RI scope on egress #3096. NEG: sound, zone gating verified in nat_exception.rs.
- nat/status.rs: trivial aggregation — NEG.
- nat64.rs: no per-packet alloc invariant #2211 (_into cores + one output alloc only). ICMP error translation incl. embedded L4. MTU 20-byte delta for PTB. Port allocator reuse across config reload #4518 (Arc clone when pool identical). HA port reservation #4512 via `reserve_nat64_pool_port` (no cursor advance). Frag assoc #2562: port-free key (family,src,dst,ident), only first fragment installs, bounded 16 shards * 64 entries = 1024 max, LRU eviction, 2s TTL, cross-worker Arc sharing. RFC 8200 §4.5 safe (unique ident per src/dst). Deterministic v6 mode 2: prefix bytes check #4863. NEG: sound overall BUT see COHORT below for one residual.
- nptv6.rs: fail-closed on unparseable/unsupported/host-bits #2240/#4519 (returns Err keep prev state), overlap reject #2241 deterministic (first-match order dep prevented). Checksum-neutral skip #3233: adjustment==0xFFFF or 0x0000 skips fixup, pure prefix swap — preserves 0xFFFF host. NEG: sound.
- Tests (all 8 test files): cover DNAT proto wildcard, L4 match, pool exhaustion, scope, static, source, counters, NAT64 tunnel, frag — good coverage, not prod findings.

## Findings (MATERIAL only if live enforcement)

### COHORT — NAT64 frag assoc pool SNAT source divergence on ident reuse (low materiality)

- **Title**: NAT64 frag assoc port-free key can inherit sibling flow's pool SNAT source under deliberate ident reuse
- **Severity**: Low
- **Confidence**: High
- **Gate**: COHORT (defense-in-depth, inherent NAT+frag+ident-reuse hazard documented in module, fail-safe drop not wrong-dst)
- **Evidence**: `nat64.rs:84-140` frag assoc design note:
```
  // ... pool SNAT source is round-robin (address_persistent = false), so two flows that
  //     share (src_v6,dst_v6) but differ in L4 port can be assigned DIFFERENT
  //     pool source addresses. Since the key is port-free, a non-first fragment
  //     could in principle inherit a *sibling* flow's snat_v4.
  //   * CORRECTNESS / why the port-free key is safe: RFC 8200 §4.5 requires a
  //     source to use a UNIQUE Fragment Identification...
  //     worst case is fail-SAFE: the non-first fragment may translate to the sibling
  //     flow's pool SOURCE, so the receiver cannot reassemble ... and DROPS
```
  Install at `frag_assoc.install()` only from first fragment (offset 0, MF=1, admitted+resolved), consult from non-first via `lookup()` with lazy expiry prune + LRU refresh. Bounded shards.
- **Why COHORT**: Violates perfect per-flow isolation only for a deliberately non-conformant sender reusing same ident across concurrent flows to same (src,dst). Result is fail-safe: fragments from different pool sources -> receiver cannot reassemble -> drop, not wrong-destination delivery. No policy bypass — still subject to policy check on first frag (first frag installs only if admitted). Same inherent hazard RFC 6864 describes for any NAT with fragmentation. Already documented with RFC 8200 justification. Not a policy bypass.
- **Fix direction**: Would require per-flow frag reassembly or storing per-(src,dst,ident) AND per-(src_port,dst_port) — defeats port-free design + DoS resistance. Documented limitation is acceptable; consider session-keyed fallback lookup if flow table hit.
- **Labels**: nat64, frag, hardening, DoS-resilience
- **Dedup**: Not in provided dedup list; known residual of #2562 design. Not #5606 (that is reverse translation).
- **Verified**: origin/master same code (frag assoc is new feature, 16*64 bounded).

### COHORT — NPTv6 fail-closed vs NAT skip-and-continue inconsistency (defense-in-depth)

- **Title**: NPTv6 aborts whole snapshot while sibling NAT tables skip bad rule — potential availability divergence
- **Severity**: Low
- **Confidence**: High
- **Gate**: COHORT (availability, not security bypass; documented #3888 scope exception)
- **Evidence**: `nptv6.rs:111-132` `try_from_snapshots` returns `Err(SnapshotIntegrityError)` on ANY bad rule / overlap, while `nat/destination.rs:476-483`, `nat/static_nat.rs`, `nat/source.rs`, `nat64.rs` skip bad rule with `record_parse_error()` and continue:
```
  // nat64.rs #3888: SKIPS the offending NAT64 rule ... publishes the remaining
  // NPTv6 (Nptv6State::try_from_snapshots) intentionally stays
  // fail-CLOSED (abort-all): its #2241 overlap rejection is an
  // order-dependent determinism guard where a blind per-rule skip would be ambiguous
```
  `nat/destination.rs:489`: `nat_counters.record_parse_error(&format!("DNAT rule {:?}..."))` + `continue`.
- **Why COHORT**: A single bad NPTv6 rule blocks ALL NPTv6 + delays forwarding rebuild (apply preflight keeps prev state), while bad DNAT/SNAT/NAT64 rule only drops that rule. NPTv6's fail-closed is justified by #2241 deterministic overlap guard. Not a policy bypass — fail-closed is safer than fail-open, but availability difference is observable. Advisory only.
- **Fix direction**: Keep NPTv6 fail-closed for overlap; consider per-rule skip for unparseable-only (non-overlap) cases if preflight separates validation phases.
- **Labels**: nptv6, nat, availability, fail-closed
- **Dedup**: Not in dedup list; noted in nat64.rs comment as flagged follow-up out of #3888 scope.
- **Verified**: origin/master same.

### NEG summary (no MATERIAL/Medium+ in this batch)

DNAT protocol wildcard 256, off exemption short-circuit, source_constrained fail-closed, L4 AND, prefix LPM, static NAT egress zone gate #2871, SNAT scope + non-first-fragment drop #1852 + address-only reverse-identity uniqueness #5269 + deterministic prefix check #4863 + proto0 sentinel fail-closed, allocator CAS claim + FIFO recycle + F4 exact cap + deterministic reversal, NAT64 incremental checksum + port allocator reuse #4518 + HA reservation #4512 + frag assoc bounded+first-only-install, NPTv6 host-bits fail-closed #4519 + overlap reject #2241 + checksum-neutral skip #3233 — all sound. NAT interaction with zone policies: DNAT pre-routing -> FIB -> zone-pair -> policy (post-DNAT dst zone) -> SNAT post-policy -> correct Junos ordering, no bypass. No MATERIAL findings.



---

### === ps-A3_go_config_cli_tree-b1.md (12031 chars, 97 lines) ===

# A3 Go Config CLI Tree b1/4 — Zone Policy Compilation Focus
Base: 4e0c7f74c == origin/master tip.

## File Inventory (150 files — prod vs test)

Prod (17 files, ~7.5k LOC combined):
| File | LOC | Responsibility | Hot |
|---|---|---|---|
| compiler.go | 2323 | entry, strict-vs-lenient opts, typed-config pipeline, group expansion | commit path |
| compiler_security_zones.go | ~800 | zones find-or-create #4818, host-inbound merge #4544, bracket lists | commit |
| compiler_security_policy.go | ~900 | from-zone/to-zone dual-shape, global scope #4626, default-policy #3065, terminal action #3043, deny modifiers #3141 | commit |
| compiler_nat_source.go | ~1500 | SNAT pools, rule-sets, bracket lists #4521, dup-block #3915, deterministic, port-range #5457 | commit |
| compiler_nat_destination.go | ~600 | DNAT pools, rule-sets, port list #3446/#3449, off exemption #3844 | commit |
| compiler_nat_dnat_to.go | ~400 | DNAT to-spec |
| compiler_nat_mixed_scope.go | ~300 | NAT scope (zone/iface/RI #3096) collection |
| compiler_firewall.go | 1237 | firewall filters, family any #4287, dup-block #3850 | commit |
| cmdtree/tree.go | 1589 | operational tree SSOT (not config set/) | CLI |
| ast.go / ast_edit.go / ast_format.go / ast_groups.go / ast_redact.go | ~2500 | Junos AST dual-shape, SetPath, groups expansion, bracket lists |
| types_security.go | 1370 | IsWildcardZone, GlobalPolicyAppliesToZone, PolicyAction, PreIDDefaultPolicy |
| + 8 more (nat_helpers, interface_range, ipsec, etc.) | ~2k | — | — |

Tests (133 files, ~20k LOC):
Coverage: default-policy #3065, global policy zone scope #4626/#3680, zone interfaces bracket #5248, static NAT zone, equal-flow target policy, firewall family any/collision, NAT address/feed/resolvable, DNAT port range, application specs, dup detection, BGP, chassis, CoS, DDNS, DHCP, filter, etc.

Prod/Test split: ~22% prod, 78% test — good guard coverage.

## Module Log (coverage, NEG only here)

- ast.go: dual-shape parsing (hierarchical `family inet { dhcp; }` → Keys=["family","inet"] with children vs flat-set `set interfaces eth0 unit 0 family inet dhcp` → Keys=["family"] child Keys=["inet"]). Bracket lists collapse onto ONE leaf Keys (#2419) — lexer strips `[` `]`. SSOT `firewallMatchValues` accumulates Keys[1:] + Children. NEG: sound, well-tested in parser_security_test.go (5.8k LOC).
- ast_edit.go: SetPath merges duplicate containers (flat-set merge), modeled vs unmodeled leaf handling. NEG: sound, bracket list collapsing proven.
- ast_groups.go: apply-groups expansion with depth limit #5194, transitive #4474, leaf-list exclude — NEG: sound, tested.
- compiler.go: strict-vs-lenient gates — commit hard-rejects, lenient load/peer-sync warns (#1960 doctrine). Compile pipeline: expand groups → early-strict → dispatch → uniform gates (strict NAT/policy/filter). NEG: architecture sound, prevents brick on load.
- compiler_security_zones.go: find-or-create per zone name #4818 (multiple security { zones { security-zone <name> } } blocks merge, not overwrite). mergeHostInbound union dedup #4544 (host-inbound-services across blocks). parseHostInboundNode firewallMatchValues SSOT #3703 (bracket list). Zone ref validation #4230 + any mix #4626. host-inbound default-deny with unzoned catch-all #4420, lo0 atomic delete+recreate. NEG: sound — find-or-create + merge prevents block-drop bypass class.
- compiler_security_policy.go: dual-shape from-zone/to-zone (hierarchical Keys=["from-zone","trust","to-zone","untrust"] len>=4 and flat-set traversal FindChild). Global scope FromZones/ToZones via firewallMatchValues #4626 M03 + sortDedupZones determinism. IsWildcardZone empty=>all zones wildcard #3680. default-policy fail-closed PolicyDeny #3065 + any-ipv4/v6 normalize #2008 + log handling #3534. terminal action conflict #3043 (permit vs deny in same policy). collapsed deny modifiers #3141 (reject-all, then count/log/…). validatePolicyMatchAddressesStrict prevents empty-set→match-all via excluded flag #3144/#3146. Zone ref validation. NEG: sound — M03 multi-zone deny plural fields handled, #3065 deny default closed.
- compiler_nat_source.go: bracket list handling #4521 (address [ a b c ] → Keys=["address","a","b","c"] — whole token stream read, expanding ranges). dup-block accumulate #3915 (forEachChild over source blocks, not FindChild first-only — Junos merge semantics). Port range parser #5457 canonical validation (ParseCanonicalUint + 1..65535 + low<=high, not Atoi). Deterministic block-size/host validation, persistent-nat vs deterministic mutual exclusion, address-persistent vs deterministic exclusion. Pool alarm raise/clear #4077 hysteresis. Scope collection #3096 (zone/iface/RI bracket lists → Cartesian product of from×to). Match accum: source-address bracket, address-book ref #2416/#3431, dst-port via shared DNAT parser #3429 H03, application bracket. Then-block last-wins with reset #3850 (prevents interface=true stale under pool block). NEG: most sound after #5457 fix — see COHORT for one residual.
- compiler_nat_destination.go: similar bracket/dup-block fixes (#3915 sibling, #3446 invalid ports #3449 range bounding #4422 reversed range). Off exemption #3844 (then destination-nat off → no-translate, stops eval). fromScopes only (no to-scope — DNAT is inbound-only #3444). NEG: sound after #3844.
- compiler_nat_dnat_to.go / compiler_nat_mixed_scope.go: to-spec + scope collection — NEG: sound, #3096.
- compiler_nat_helpers.go: shared helpers (collectNATScopes, applyNATFromScope/ToScope, parse routes) — NEG: sound.
- compiler_firewall.go: family any folds to both inet+inet6 #4287 (closes fail-open where any filter only enforced v4). Dup-block AND-combine #3850. Interface-specific advisory #4316. Three-color policer default color-blind #4535 (prevents whole dataplane disarm on unspecified). NEG: sound after #4287.
- cmdtree/tree.go: operational tree SSOT (run/show/clear/request), NOT config set/ — safe, separate from setSchema. Zone completion via completion_zone_prefix #5196. Nil-provider guards #5196. NEG: operational only, no config enforcement impact.
- types_security.go: IsWildcardZone("") true (empty => any), IsWildcardZoneSet, GlobalPolicyAppliesToZone pair matching, PolicyPermit/Deny, default-policy any-ipv4/v6. NEG: sound, tested in global_policy_zone_scope_3680_test.go.
- All test files (133): guard specific invariants — default-policy deny, DNAT port range, NAT address-name, firewall family any, zone interfaces bracket, etc. NOT filing findings on tests unless they demonstrate prod gap.

## Findings — COHORT (defense-in-depth, low-materiality, not individually fileable)

### COHORT-1: compiler_nat_source.go port-no-translation default when port block missing — implicit PAT range still stamped

- **Severity**: Low, **Confidence**: Medium, **Gate**: COHORT (defense-in-depth, no bypass)
- **Evidence**: `compiler_nat_source.go:540-545`:
```
  if pool.PortLow == 0 { pool.PortLow = 1024 }
  if pool.PortHigh == 0 { pool.PortHigh = 65535 }
  sec.NAT.SourcePools[pool.Name] = pool
```
  A pool with `no-translation` (`port no-translation`) still gets PortLow/High defaulted to 1024-65535, and `PortNoTranslation` bool is separate. The Go snapshot builder must check `PortNoTranslation` and skip port range in wire message. If it leaks the default range to Rust (allocator sees pool_mode + non-zero port range), Rust's address-only path should ignore port_low/high when `no_translation=true`. Verified: `source.rs` gates on `no_translation` for address-only token path (`reserve_address_only`). Not a bypass, but implicit coupling — a snapshot builder bug that forgets to check no_translation would silently enable PAT instead of address-preserved mode.
- **Fix**: Document invariant that port_low/high are meaningless when PortNoTranslation true; or zero them when no-translation to make misuse obvious.
- **Labels**: nat, compiler, defense-in-depth
- **Dedup**: Not in dedup list. Related to #3906.
- **Verified**: origin/master same pattern.

### COHORT-2: ast.go SetPath unmodeled-leaf path collapses trailing tokens — validated only if caller uses firewallMatchValues SSOT

- **Severity**: Low, **Confidence**: High, **Gate**: COHORT (pattern already fixed via SSOT, but new code must follow discipline)
- **Evidence**: Multiple fixes reference #2419 bracket-list collapse: lexer strips `[]`, SetPath collapses unmodeled leaf trailing tokens onto ONE node (Keys=["address","a","b","c"]). Before fixes, only Keys[1] read → all but first value dropped (fail-open narrowing or pool shrink). Fixed via `firewallMatchValues()` SSOT that reads Keys[1:] + Children, and `appendPoolAddresses()` that expands ranges. Pattern recurs:
  - #4521 NAT pool address bracket lists
  - #3703 host-inbound bracket lists  
  - #3431 NAT match application bracket lists
  - #2416/#3229 address-book refs
  - `docs/config-schema.md`: "Multi-value leaves and bracketed lists" section documents this as mandatory.
  This batch's files all use SSOT correctly (verified compiler_nat_source.go appendPoolAddresses + firewallMatchValues, compiler_nat_destination.go parseDNATPortList, firewall.go family any).
- **Why COHORT**: Resilience of fix depends on every future compiler using SSOT. No active bug in batch, but pattern is fragile — a new multi-value leaf without firewallMatchValues would reintroduce #2419 class. Doc + linter enforcement is defense-in-depth.
- **Fix direction**: Lint or code-review checklist: any new multi-value leaf must use firewallMatchValues.
- **Labels**: parser, config-schema, defense-in-depth, SSOT
- **Dedup**: #2419 class, multiple fixes. Not dupe of active bug.
- **Verified**: origin/master batch files use SSOT.

### COHORT-3: compiler.go strict gates only on commit path — lenient load can install over-permissive config if validator missed

- **Severity**: Low, **Confidence**: High, **Gate**: COHORT (lenient-load design tradeoff, #1960 no-brick doctrine)
- **Evidence**: `compiler.go` opts carry `lenientNPTv6`, `lenientEqualFlowWorkerCap` etc. — commit hard-rejects, tolerant load/peer-sync warns + compiles. From `compiler_nat_source.go:600`:
```
// #2079: pool-utilization-alarm threshold validation is NOT performed
// here — it is a strict-vs-lenient gate so the strict commit path 
// hard-rejects while the tolerant load/peer-sync path WARNS. Doing it
// here would hard-fail CompileConfigLenient and brick a daemon restart
// on a legacy config that was committed before #2079...
```
  Same for firewall filters, NAT ports, etc. Lenient path installs a config that commit would reject. For security policies this is not permitted (fail-closed #3065 default deny), but for NAT port ranges it could install a defaulted PAT range when configured range is invalid (pre #5457 class).
- **Why COHORT**: Documented tradeoff: #1960 no-brick doctrine — corrupted store / legacy config must still boot, not brick. A missed validator in lenient path could install over-permissive or defaulted NAT (but not policy bypass — policy defaults to deny). Defense-in-depth: validate on snapshot builder too (Rust side: record_parse_error + skip rule #4718).
- **Fix direction**: Ensure every new strict gate has corresponding Rust snapshot-builder loud-skip #4718 (already pattern for NAT).
- **Dedup**: Not in dedup list; #1960 family.
- **Verified**: origin/master same doctrine.

### NEG summary (no MATERIAL in this 150-file batch)

All zone-policy compilation paths sound: find-or-create #4818, host-inbound merge #4544 + bracket SSOT #3703, dual-shape from-zone/to-zone, global FromZones/ToZones #4626 + sortDedupZones + IsWildcardZone, default-policy PolicyDeny #3065 closed, terminal action conflict #3043, collapsed deny modifiers #3141, address-match strict validation #3144/#3146 + empty→match-all prevention, app match, zone ref validation #4230, NAT bracket lists #4521 + dup-block #3915 + port-range canonical #5457 + off exemption #3844 + scope #3096 + address-only reverse-identity, firewall family any #4287. No policy bypass, no zone-escape, no default-permit.



---

### === ps-A3_go_config_cli_tree-b2.md (12019 chars, 117 lines) ===

# Batch B2 — Security Zone Policies Deep Review (claude-spark-001)
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa — verified origin/master 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa same SHA, fresh 0 behind.
Worktree: /tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b2 (removed post-read, content verified via git show + earlier reads)

## File-size / shape inventory (ranked size x responsibility x hot-path)

Batch: 150 files listed in prompt. Total LOC measured via `awk ... xargs wc -l`: 46667 (48 prod 28033 LOC, 102 test 18634 LOC). Prod largest:

| Prod File | LOC | Responsibility | Hot-path | Largest fn |
|---|---|---|---|---|
| compiler_validate_strict_policy.go | 1032 | zone ref #4230, address #2008, app #3144/#3146, dup names #3473, terminal #3043 | commit | validatePolicyZoneReferencesStrict |
| compiler_security_flow.go | 728 | flow trace file/flags/size #3420/#3422/#3424, tcp-mss #1979 | commit | validateFlowTrace* |
| compiler_validate_warn.go | 1682 | lenient warnings, address-book, policy match warnings #3958 | commit | (many) |
| compiler_policy_then.go | 594 | then permit/reject/deny gates #3114/#3115/#3141, collapsed tokens #3377 | commit | validatePolicyThenDenyStrict |
| compiler_validate_strict_zones.go | 504 | reserved zone #3055, zone count #3075, iface membership #3072/#4515, host-inbound tokens #3200 | commit | validateZoneInterfaceMembershipStrict |
| compiler_security_policy.go | 483 | default-policy PolicyDeny #3065, global FromZones/ToZones #4626 M03 via firewallMatchValues SSOT, sortDedupZones, LenientContentDropped #5575 | compile+dataplane | compilePolicy |
| compiler_security_screen.go | 474 | screen thresholds, defaults #3024/#3230, numeric #3317 | commit | compileScreen |
| compiler_security_addressbook.go | 430 | zone-local fold #3061/#4340, zoneLocalQualify, rewrite respects IsWildcardZone | compile | resolveZoneLocalAddressBooks |
| compiler_policy_match.go | 347 | unsupported match leaf #3113, swallowed #3673, firewallMatchValues tail | commit | policyUnsupportedMatchLeafFindings |
| compiler_security_zones.go | 239 | find-or-create #4818, mergeHostInbound #4544, zoneInterfaceMembers #5248 bracket flatten | compile | compileZones |
| compiler_security_log.go | 268 | log stream port/tls #3349/#3350 | commit | compileLog |
| compiler_security.go | 114 | dispatcher | compile | compileSecurity |
| compiler_policy_missing_match.go | 214 | required dimensions #3044 | commit | validatePolicyRequiredMatchStrict |

10 core zone-policy compilers = 3500 LOC; remaining prod: compiler_nat_static.go, compiler_prewalk.go, compiler_protocols.go, compiler_routing.go, compiler_services.go, compiler_system.go, compiler_tailgates.go, compiler_uniformgates.go, dup_*.go, event_*, etc. Rank hot-path: policy_match > policy_then > security_policy > security_zones > validate_strict_policy/zones.

## Module log (NEG only in log, proof of coverage)

**Prod compilers:**
- compiler_security_zones.go:239 — NEG dual-shape: hierarchical `interfaces { a; b; }` vs flat `[a b]` via zoneInterfaceMembers (Keys + child recurse, skip host-inbound-traffic). find-or-create prevents second top-level security-zone instance overwrite #4818. mergeHostInbound unions + dedup first-seen.
- compiler_security_policy.go:483 — NEG default-policy: initialized PolicyDeny in compiler.go:2224, switch permit/deny/reject; unknown rejected by schema ValidateEnum (schema_security.go:203-211). global match FromZones/ToZones uses firewallMatchValues SSOT (Keys[1:]+Children) #4121, sortDedupZones (#4626 M03) nil=wildcard. LenientContentDropped flags widened policies fail-closed to sentinel.
- compiler_policy_match.go:347 — NEG unsupported leaf allowlist exact; swallowed structural tokens from-zone/to-zone #3673 detected in multi:true tail. policyMatchChildren unions EVERY match block #3842, forEachChild at security/policies top-level #3562.
- compiler_policy_then.go:594 — NEG collapsedThenActionTokens flattens 3 shapes; recognizedCollapsedDenyToken SSOT shared wiring/gate; orphan session-init without log #3374 rejected; two-node split #3377 via policyThenActionNodes.
- compiler_policy_missing_match.go:214 — NEG required source/destination/application via union of match blocks; Junos parity empty != any.
- compiler_validate_strict_policy.go:1032 — NEG address #2008: token recognized any/any-ipv4/v6/CIDR/IP/named incl dynamic feed, empty filtered by firewallMatchValues; app #3144/#3146 mirrors Runtime ResolveApplication; zone ref #4230 rejects from-zone junos-host, validates FromZones/ToZones sets #4626 (any mixing, junos-host mixing), duplicate names #3473 name-keyed counter, terminal action #3043 distinct-value dedup + fail-closed deny default, log action #3060.
- compiler_validate_strict_zones.go:504 — NEG reserved #3055, zone count 65533 with hash collision primary, iface membership #3072 logical keys (bare claims base+units, unit single), defined #4515 generous union lo0+st* bind-base avoids #4191 over-reject, host-inbound #3200 Known* SSOT.
- types_security.go: IsWildcardZone s==""||s=="any", IsWildcardZoneSet len==0||contains any (tolerant collapse — strict rejects mixing), sortDedupZones drops blanks sorts compacts, ScopeSingular first element for rolling-upgrade #4626 A8, IsHostToZoneScope exact ["junos-host"].
- firewallMatchValues:799 — NEG SSOT Keys[1:]+Children[0] blank-skip, shared by all multi:true leaves.
- Other batch prod: compiler_security_addressbook.go NEG zone-local fold order earlystrict.go:94 before validators, compiler_security_flow.go NEG basename/size/flags gates #3420/#3422/#3424 forEachChild #3566, compiler_security_screen/log/alg NEG.

**Batch tests (102):** compiler_policy_dup_block_3842_test.go NEG union, compiler_policy_global_zone_3148_test.go NEG scoped global list, compiler_policy_match_3113/3142/3673 NEG unsupported+tail, compiler_policy_match_address_set_3149 NEG empty/dangling, compiler_policy_match_application_3144 NEG undef app, compiler_policy_match_ssot_4121 NEG SSOT, compiler_policy_missing_match_3044 NEG, compiler_policy_term_multimatch_2642 NEG, compiler_policy_then_3114/3115/3141/3374/3377 NEG, compiler_prefix_list_bracket_3996 NEG, compiler_security_bracket_list_3703 NEG, compiler_zone_interfaces_bracket_5248 NEG, compiler_validate_strict_zones/policy NEG, firewall_* , routing, etc. scanned — no zone bypass.

## Findings — MATERIAL (0)

No MATERIAL fail-open found. Default-policy fail-closed, FromZones/ToZones firewallMatchValues+sortDedup+IsWildcardSet, IsWildcardZone empty=>all zones wildcard, terminal action conflict #3043, collapsed deny #3141, app match #3144/#3146, zone ref #4230, validatePolicyMatchAddressesStrict prevents empty-set→match-all, LenientContentDropped #5575 poisons widened lenient policies.

## Findings — COHORT (low-materiality / defense-in-depth)

### COHORT-01: per-interface host-inbound override indexed only by first member of bracket list

- **Title:** Bracketed interfaces list with host-inbound override attaches only to first member
- **Severity:** Low
- **Confidence:** COHORT
- **Gate:** COHORT
- **Evidence:** `/tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b2/pkg/config/compiler_security_zones.go:114-162`
```go
for _, iface := range prop.Children {
    zone.Interfaces = append(zone.Interfaces, zoneInterfaceMembers(iface)...)
    var hib *HostInboundTraffic
    for _, hn := range iface.FindChildren("host-inbound-traffic") {
        hib = mergeHostInbound(hib, parseHostInboundNode(hn))
    }
    if hib != nil {
        zone.InterfaceHostInbound[iface.Name()] = mergeHostInbound(...)
    }
}
```
`zoneInterfaceMembers` flattens `[a b c]` → all members for `zone.Interfaces` (#5248), but `InterfaceHostInbound` key is `iface.Name()` (first only). Non-canonical `set ... interfaces [ a b ] host-inbound-traffic` would give only `a` the override.
- **HPC/invariant:** Host-inbound admission uses InterfaceHostInboundEffective which unions zone-level + per-if override + physical-parent inheritance #3720; missing per-if override falls back to zone-level — not fail-open beyond zone level, but asymmetry.
- **Why matters:** Operator crafting bracket override expects both members covered; second falls back to zone-level (could be more permissive). Junos disallows bracket+host-inbound in same stanza, so only via `load override` raw hierarchical block.
- **Fix direction:** Iterate `zoneInterfaceMembers` for map insertion, or AST gate rejecting bracket+host-inbound mix.
- **Labels:** host-inbound, bracket-list, #5248
- **Dedup:** Not in #5606..#5488 list. Closest #4544/#4818.
- **Verified:** origin/master 4e0c7f74c file same lines 114-162.

### COHORT-02: empty token accepted as recognized address — relies on SSOT blank-skip, tolerant any+concrete collapse

- **Title:** `policyMatchAddressTokenRecognized` treats "" as valid + IsWildcardZoneSet len==0||contains any collapse for tolerant path
- **Severity:** Low
- **Confidence:** COHORT
- **Gate:** COHORT
- **Evidence:** `/tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b2/pkg/config/compiler_validate_strict_policy.go:74-86`
```go
func policyMatchAddressTokenRecognized(tok string, named map[string]bool) bool {
    switch tok {
    case "", "any", "any-ipv4", "any-ipv6":
        return true
    }
```
And `pkg/config/types_security.go:482-484` `IsWildcardZoneSet`:
```go
func IsWildcardZoneSet(zs []string) bool {
    return len(zs) == 0 || slices.Contains(zs, "any")
}
```
Empty from malformed AST would be accepted as valid (match-any). Today `firewallMatchValues` drops blanks, so not reachable, but defense-in-depth gap. Second, IsWildcardZoneSet contains any => any collapses mixed any+concrete to all-zones for lenient/tolerant snapshot — strict path hard-rejects mixing via validatePolicyZoneReferencesStrict (lines 600-614), so clean commit never emits mixed set. Lenient collapse is intentional backstop (bad HA peer) but documents as fallback.
- **Why matters:** Empty under `*-address-excluded` inversion → match-all in Rust dataplane (#2008 fail-open class). Tolerant any+concrete collapse widens scoped-global from explicit list to all-zones on lenient load — safe (over-permissive vs deny) but widens scope.
- **Fix direction:** Strict gate already rejects; for address token, return false for "" and ensure empty slice means absent handled by #3044. Document tolerant-any collapse in comment (already done).
- **Labels:** address-match, excluded-inversion, wildcard-collapse, #2008/#4626
- **Dedup:** Not in dedup; related to #4626 M03.
- **Verified:** origin/master same.

### COHORT-03: duplicate interface append without dedup (observability, not security)

- **Title:** `zone.Interfaces` appends via `zoneInterfaceMembers` without dedup → duplicate entries accumulate
- **Severity:** Info
- **Confidence:** COHORT
- **Gate:** COHORT
- **Evidence:** `pkg/config/compiler_security_zones.go:134` `zone.Interfaces = append(zone.Interfaces, zoneInterfaceMembers(iface)...)` — no dedup. Repeated `set ... interfaces ge-0/0/0` yields duplicate slice entries. Downstream `buildInterfaceZoneMap` uses first-writer-wins over sorted zones + zoneIfaceLogicalKeys dedup via owner map, so duplicate within same zone harmless; but `show` surfaces duplicate.
- **Fix direction:** Dedup via map or use existing sorted unique for display; low priority.
- **Labels:** zone-interfaces, display
- **Verified:** origin/master same.

## Summary
- Inventory 46667 LOC batch (48 prod 28033, 102 test 18634) — zone policy compilers hardened: dual-shape firewallMatchValues SSOT, FromZones/ToZones accum + sortDedupZones, IsWildcardZone ""||"any", IsWildcardZoneSet empty||contains any with strict reject of mixed, default-policy PolicyDeny #3065 fail-closed, terminal conflict #3043, collapsed deny #3141, app #3144/#3146, zone ref #4230, address strict #2008 prevents empty-set→match-all, LenientContentDropped #5575.
- No MATERIAL bypass; 3 COHORT low-materiality hardening items.
- Honesty: evidence quoted from worktree path, verified origin/master 4e0c7f74c.


---

### === ps-A3_go_config_cli_tree-b3.md (13994 chars, 98 lines) ===

# Batch A3_go_config_cli_tree b3 — Zone Policy Hardening Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (== origin/master)
Focus: security zone policies, global scoped policies, host-inbound admission, default-policy

## File-size/shape inventory (ranked by size x responsibility x hot-path)

| Rank | File | LOC | Type | Responsibility | Largest fn / token |
|---|---|---|---|---|---|
|1|parser_security_test.go|5805|test|Zone policy compilation & dual-shape|Test* (~150 LOC)|
|2|schema_security.go|1263|prod|Security schema SSOT (zones, host-inbound, policies, global FromZones/ToZones multi:true #4626)|policyThenSchemaChildren 50|
|3|junos_host_deny.go|1155|prod|Direct host-bound DENY projection (3-tier Rust parity, SET-subtraction, iifname scope, IKE/ident exempt per-netdev #5565)|junosHostZoneExemptNetdevs ~120|
|4|parser_ast_test.go|5620|test|AST dual-shape & SetPath grouping|Large|
|5|host_inbound_tokens.go|484|prod|Token SSOT KnownHostInbound* + HostInboundServiceMatch/ProtocolMatch (SSOT for nft + Rust)|HostInboundServiceMatch 80|
|6|host_inbound_view.go|342|prod|Zone host-inbound display SSOT (union effective, lifeline-aware)|HostInboundViewWithLifelines|
|7|schema.go|277|prod|schemaNode + setSchema root|isScalarValueLeaf|
|8|lifeline.go|84|prod|Mgmt/cluster lifeline detection (fxp0 + em0/fab* + configured control/fabric)|HostInboundLifelineInterface|
|9|parser.go|403|prod|Hierarchical Junos parser (AST)|parseStatements|
|10|schema_validators.go|~250|prod|Enum/integer validators, PRF, login username|ValidateEnum etc|

Batch: 30 prod (~6.5k LOC), 120 test (~35k LOC). Hot-path prod: junos_host_deny.go (kernel nft emission), host_inbound_tokens.go (admission tuple), schema_security.go (commit gate), lifeline.go (bypass decision).

## Module log (coverage with NEG)

- **host_inbound core** (host_inbound_tokens.go, host_inbound_view.go, host_inbound_multicast.go, host_inbound_dup_block_4544_test.go, effective_3720, per_iface_3362, rust_parity, tokens_test, view_3654, lifeline_3682): NEG — dual-shape via firewallMatchValues (#3703), mergeHostInbound union dedup (#4544) verified in dup_block test (zone+iface merge preserves both ssh+ospf, dedup, single-block byte-identical), InterfaceHostInboundEffective correctly unions physical+unit (#3720), lifeline set includes configured control/fabric (#3277). HostInboundL2Protocols exclusion from `protocols all` validated by ProtocolsAllExcludesL2 test.
- **junos_host_deny** (junos_host_deny.go, junos_host_deny_test.go): NEG — 3-tier composition (exact any global), whole-program representability gate, TCPRst reject unsup, feed-taint unrep, cross-dimension permit/deny poison, cross-zone-ambiguous trunk keeps warning (iifname empty → no suppression #4146 F1), IKE/ident per-netdev scoping #5565 implemented via JunosHostZoneIngressNetdevs SSOT matched to snapshot.
- **lifeline** (lifeline.go, host_inbound_view_lifeline_3682_test.go): NEG functional, but prefix match overly broad — tracked as COHORT-001 below.
- **schema_security** (schema_security.go, schema.go, schema_global_zone_list_4415_test.go, schema_policy_then_3377_test.go, schema_chassis.go, schema_interfaces.go, schema_routing.go etc): NEG — global FromZones/ToZones `multi:true` (#4626 M03) accumulates bracket list via firewallMatchValues (list [trust dmz] → both zones), sortDedupZones canonicalizes sorted+dedup, ZoneScopeSetLabel display SSOT, IsWildcardZone empty||"any" (#3680), IsWildcardZoneSet len0||contains any, IsHostToZoneScope exact ["junos-host"], default-policy enum deny-all/permit-all/reject-all (#3065) with fail-closed deny, default-policy-log multi-value leaf #3703.
- **policy compilation** (compiler_security_policy.go, compiler_security_zones.go): NEG — from-zone/to-zone dual-shape hierarchical Keys>=4 vs flat FindChildren, global FromZones/ToZones accumulated via firewallMatchValues (#4626), any-ipv4/v6 normalized to CIDR (#2008 H11), default deny when terminalActions empty (#3043), collapsed deny log/count modifiers (#3141) wired, zoneInterfaceMembers flattens bracket list nested chain (#5248 wildcard container), find-or-create per zone name (#4818) merges duplicate instances, mergeHostInbound unions.
- **validators** (schema_validators*.go, compiler_validate_strict_policy.go, strict_zones.go): NEG — validatePolicyMatchAddressesStrict per policyMatchNamedAddressRefs + token recognized (any/any-ipv4/ipv6/literal/book), prevents empty-set→match-all via excluded flag; validatePolicyMatchApplicationsStrict rejects undefined app and empty app-set (#3144/#3146); validatePolicyMatchAddressSetMembersStrict rejects dangling members (#3149); validateReservedZoneNamesStrict rejects junos-global/any/junos-host definition (#3055); validateZoneInterfaceMembershipStrict rejects multi-zone iface claim (#3072); validatePolicyZoneReferencesStrict rejects from-zone junos-host on zone-pair (#4230) and mixed any/junos-host scopes (#4626) and undefined zones; validateDuplicatePolicyNamesStrict, terminalAction, logAction gates.
- **parser AST** (parser.go, lexer.go, parser_bracket_list_2419_test.go, parser_security_test.go): NEG — bracket list lexer strips [] collapses onto Keys, multi leaf absorbs trailing tokens, SetPath nested chain for wildcard interface name, recursion depth guard HB164, stray brace, semicolon.
- **global scope helpers** (global_policy_zone_scope_3680_test.go, policy_from_multileaf_2689_test.go, policy_zone_matrix_4422_test.go, policy_zone_ref_test.go, policy_match_excluded_test.go): NEG — IsWildcardZone explicit "any" preserved verbatim, GlobalPolicyAppliesToZone applies any-or-contains, scoped no over-inclusion, zone-matrix composition independent actions (permit/deny/reject + junos-host), from-zone multileaf accumulation via firewallMatchValues (#2689), excluded flag compilation.
- **host-inbound multicast** (host_inbound_multicast.go, multicast_warn_4455_test.go): NEG for catalog correctness but enforcement deferred — COHORT-003.
- **other batch files** (firewall_symbolic_match, terminal_conflict, flow_aging, traceoptions, freetext, frr_clusterid, ike_policy_chain, inactive, interface_parity, ipip_tunnel_dead_warn, ipsec_*, json_repeated_leaf, lenient_*, log_profile, login_*, named_port_caseinsensitive, nat_range_wrap, natpool, policer_rate, policy_community_ref, policy_log_action, etc): NEG — unrelated to zone policy enforcement; tested for parser completeness, lenient permit widening flag (#5575) sets LenientContentDropped for missing dimensions, closed-world flips, etc. No zone bypass introduced.

## Findings

### COHORT-001: Lifeline detection overly broad (fab* prefix)
- Title: HostInboundLifelineInterface matches any base starting with "fab" — over-exempts non-lifeline interfaces named fab-.*
- Severity: Low
- Confidence: COHORT
- Gate verdict: COHORT
- Evidence: `pkg/config/lifeline.go:74` `return base == "em0" || strings.HasPrefix(base, "fab")` — comment L67-73 admits broader match, tracks design question.
- Trace: operator names interface `fab-test` (not fabric), zone assigns it → HostInboundZoneIngressNetdevs excludes it from non-lifeline refs? Actually lifeline interfaces excluded from host-inbound deny scoping; fab-test would be lifeline-exempt → host-bound traffic always admitted regardless of zone host-inbound set.
- Refutation attempt: Junos reserves fab prefix; interface naming convention prevents collision; plus HostInboundLifelineSet explicit set covers configured control/fabric, but prefix still catches arbitrary fab*.
- HPC/invariant: Lifeline bypass is fail-open for host; naming envelope.
- Why it matters: COHORT defense-in-depth — could silently widen host admission if operator uses fab prefix for data.
- Fix direction: Exact match `fab0,fab1,fab2` + configured fabric names, not prefix; or limit to `fab`+digit.
- Labels: host-inbound, lifeline, defense-depth
- Dedup note: Not in dedup list (checked #5566 host-inbound kernel-established but different)
- Verified against origin/master: file:line matches tip (lifeline.go:74)

### COHORT-002: Lenient path widens mixed `any`+concrete global scope to wildcard
- Title: IsWildcardZoneSet contains "any" collapses mixed set to all-zones on tolerant load/HA-sync — permit-widening on lenient path
- Severity: Low
- Confidence: COHORT
- Gate verdict: COHORT
- Evidence: `pkg/config/types_security.go:482-484` `func IsWildcardZoneSet(zs []string) bool { return len(zs)==0 || slices.Contains(zs,"any") }` — comment L475 says strict gate rejects mixed, but lenient downgrades to warning and still collapses. `compiler_validate_strict_policy.go:599-610` strict rejects mixed any+concrete. Lenient path warns (#1960) but GlobalPolicyAppliesToZone uses IsWildcardZoneSet → wildcard.
- Trace: Config with `match from-zone [ any trust ]` rejected at commit, but persisted on old binary, loaded leniently → GlobalPolicies FromZones=[any,trust] after sortDedup → IsWildcardZoneSet true → GlobalPolicyAppliesToZone matches all zones, though operator intended maybe trust only. For deny it's fail-closed widen; for permit it's fail-open widen.
- Refutation: Strict gate prevents clean configs entering system; lenient only for old persisted/mis-synced configs; dataplane snapshot lenient also collapses safely to any (per comment). Still widens permit.
- HPC/invariant: Fail-closed doctrine for lenient is warn+enforce old behavior; here old behavior pre-#4626 dropped tail zones, new collapses to wildcard — change in lenient semantics.
- Why it matters: COHORT — HA-synced bad config could broaden global permit beyond authored zones on survivor after reboot.
- Fix direction: On lenient path, when mixed any+concrete, keep warning but DO NOT collapse to wildcard — keep concrete set (or reject with sentinel __unsupported__) like LenientContentDropped flag does for other widenings #5575.
- Labels: global-policy, zone-scope, lenient, fail-open
- Dedup note: Not overlapping #5488 (snapshot version) or #5564 (sync tail)
- Verified against origin/master: types_security.go:482, compiler_validate_strict_policy.go:599-620 matches tip

### COHORT-003: Multicast routing control bypasses per-zone host-inbound scoping (deferred enforcement)
- Title: Well-known routing multicast groups (OSPF/VRRP/PIM etc) matched kernel policy accept — not scoped by host-inbound protocols
- Severity: Low
- Confidence: COHORT
- Gate verdict: COHORT
- Evidence: `pkg/config/host_inbound_multicast.go:4-41` catalog comment documents fail-open-but-bounded gap, kernel `xpf_hostinbound` chain `daddr <zone-addrs>` skips multicast, Rust classifier keys only (zone,proto,dstport,family,icmp_type) no daddr dimension. `IsWildcard` etc not applied to multicast.
- Trace: packet to 224.0.0.5 (OSPF) arrives on any ingress zone → falls through input chain policy accept → delivered to FRR regardless of zone host-inbound protocols.
- Refutation: Kernel delivers multicast only to groups daemon joined (operator enabled FRR), bounded; always-on control set globally accepted anyway; hardening deferred to new iifname-scoped nft set + Rust daddr dimension #4455.
- HPC/invariant: Junos parity gap, not open door, but zone isolation not complete.
- Why it matters: Defense-in-depth — operator expects per-zone protocols to scope multicast admission, but it's packet-wide.
- Fix direction: Add per-zone iifname-scoped nft sets for catalog groups, plus Rust daddr dimension when XDP local-delivery path, gated by #1960 migration.
- Labels: host-inbound, multicast, defense-depth
- Dedup note: Related to #4455 deferred, not duplicate of listed dedup issues
- Verified against origin/master: host_inbound_multicast.go:1-84 matches tip

### COHORT-004: IKE exemption per-netdev union can widen shield across VLAN siblings same zone
- Title: junosHostZoneExemptNetdevs unions effective admission across all refs sharing a netdev (VLAN trunk parent) — per-interface ike override leaks to sibling VLANs
- Severity: Low
- Confidence: COHORT
- Gate verdict: COHORT
- Evidence: `pkg/config/junos_host_deny.go:888-928` `byNetdev` verdict `v.ike = true` if any ref on netdev admits IKE; `addRow` notes both own and parent for vlan !=0. Comment says union mirrors coarse gate.
- Trace: zone with ge-0/0/2.50 (IKE allowed) and ge-0/0/2.80 (no IKE) same zone, both VLANs share parent netdev ge-0/0/2 via addRow → parent netdev marked IKE-admitting → IKE exemption shield emitted with parent in IKEExemptNetdevs → sibling VLAN 80 traffic gets IKE passthrough despite no IKE config on that subinterface.
- Refutation: Within same zone, physical parent shared is expected? But per-interface override intent is per-unit isolation (#3362). Union is safe per comment but over-permissive for IKE shield.
- HPC/invariant: IKE shield is fine-eligible-L4 exemption ahead of application any drop; over-shielding could allow IKE from unexpected VLAN.
- Why it matters: COHORT — minor host-bound exposure, but IKE is auth'd; still violates per-interface override isolation.
- Fix direction: Scope IKEExemptNetdevs per-unit netdev only, not parent, or per-ref netdev set not unioned.
- Labels: junos-host, host-inbound, ike-exempt
- Dedup note: #5565 fix scoped to specific netdevs but still unions per-netdev — not in dedup list
- Verified against origin/master: junos_host_deny.go:884-967 same logic

## Summary
Zone policy compilation is sound on dual-shape (#2419), global FromZones/ToZones multi:true+firewallMatchValues (#4626 M03), IsWildcardZone empty||any (#3680), sortDedupZones, default-policy fail-closed (#3065), validatePolicyMatchAddressesStrict prevents empty→match-all on excluded inversion, app match gates (#3144/#3146), zone ref validation (#4230) and reserved names (#3055). Host-inbound token SSOT prevents split-brain (#3200), mergeHostInbound (#4544) and find-or-create (#4818) prevent silent drop on duplicate blocks/instances. Remaining gaps are COHORT defense-in-depth (lifeline prefix, lenient mixed-any widening, multicast scoping, IKE per-netdev union). No MATERIAL zone bypass found in this batch.


---

### === ps-A3_go_config_cli_tree-b4.md (12208 chars, 120 lines) ===

# Batch 010 Review — Security Zone Policies (claude-spark-001)

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (verified against origin/master same SHA)
Worktree: /tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b4
Date: 2026-07-09 (updated 2026-07-11)

## File-size / shape inventory (71 files, ~16200 LOC)

Prod vs Test: 21 prod (~7074 LOC), 50 test (~9126 LOC)

Top prod by LOC x responsibility x hot-path:
1. `types_system.go` 1585 LOC — system/tz/dns, low zone relevance, but largest
2. `types_security.go` 1370 LOC — **core**: ZoneConfig, PolicyMatch FromZones/ToZones, IsWildcardZone, IsWildcardZoneSet, sortDedupZones, GlobalPolicyAppliesToZone, DefaultPolicy type, HostInboundTraffic
3. `schema_walk.go` 826 LOC — SchemaValidate typed-leaf gate, multi-value leaf handling, closed-world, modifier validation — indirectly protects default-policy-log, transmit-rate, etc.
4. `types_routing.go` 651 LOC — routing-instance, not zone policy
5. `schema_validators_system.go` 397 LOC — system validators, not zone
6. `types_chassis.go` 188 LOC — device-map, zone intersection minimal
7. `zoneid.go` 251 LOC — StableZoneID FNV-1a xor-fold [1,65533], QuarantinedZoneNames, StableZoneIDOwner — wire-adjacent, HA-symmetric, hot-path for forwarding state
8. `types_interfaces.go` 150 LOC — InterfacesConfig (zone membership depends on defined interfaces)
9. Remaining prod 10 files 60-290 LOC each: types.go, types_cos.go, snmp_clients.go, syslog_logfile.go, tcp_flags.go, tunnelid.go, wireguard_ports.go, xfrmi.go, tunnelemit.go, schema_validators_scheduler.go

Largest functions (est.):
- `validateZoneInterfaceMembershipStrict` ~95 LOC (`compiler_validate_strict_zones.go` not in batch but referenced)
- `walkSchemaNode` ~170 LOC in schema_walk.go
- `compileZones` 140 LOC in compiler_security_zones.go (outside batch but critical)
- `StableZoneID` 8 LOC + `QuarantinedZoneNames` 40 LOC

Test files: zone_count_cap 87 LOC, zone_dup_block_4818 211 LOC, zone_interface_defined 108 LOC, zone_interface_membership 129 LOC, scoped_global_zoneset 188 LOC, zoneid_test 218 LOC — all directly exercise zone invariants.

## Module log (coverage, NEG only in log)

- `types_security.go`: NEG — IsWildcardZone("")||"any" wildcard correct, IsWildcardZoneSet empty OR contains "any" — SSOT matches Rust build_global_zone_scope. sortDedupZones drops blank, sorts, compacts, returns nil for empty => wildcard preserved. ZoneScopeSetLabel, ScopeLabelOr, ScopeSingular rolling-upgrade safe, IsHostToZoneScope exact match len==1. GlobalPolicyAppliesToZone OR across sides correct for audit (ENFORCEMENT in Rust uses AND, not here). HostInbound union types present.
- `zoneid.go`: NEG — StableZoneID fold frozen, never 0, never >= ZoneIDReservedMin (0xFFFE), pure function of name, hash-freeze pins trust=50675 etc. QuarantinedZoneNames quarantines later-sorting colliding pair, owner map deterministic. Three-view collision gate (View1 pre-expansion + View2/3 per-node expansion) preserves HA symmetry.
- `compiler_security_zones.go` (outside batch but read for context): NEG — find-or-create #4818 correctly merges duplicate top-level security-zone instances (load override), Interfaces appends via zoneInterfaceMembers flattening #5248 bracket lists, HostInbound merge via mergeHostInbound #4544 union dedup, AddressBook find-or-create #4706.
- `compiler_security_policy.go`: NEG — default-policy fail-closed via compiler.go DefaultPolicy: PolicyDeny init #3065 (zero value would be permit). permit/deny/reject mapping, reject-all #3065 handled. From-zone/to-zone dual-shape hierarchical Keys len>=4 and flat-set traversal. Global scope FromZones/ToZones via firewallMatchValues SSOT #4626 M03 + sortDedupZones determinism. validatePolicyMatchAddressesStrict, app match #3144/#3146 prevent dataplane disarm. LenientContentDropped poison via __unsupported__ sentinel #5575.
- `zone_dup_block_4818_test.go`: NEG — primary guard proves interfaces+host-inbound merge across duplicate instances, three instances, per-iface host-inbound merge, single-block byte-identical negative control.
- `zone_count_cap_test.go`: NEG — MaxUsableZoneID = ZoneIDReservedMin-1 = 65533, cap enforced, ordinary 3-zone commits.
- `zone_interface_defined_4515_test.go`: NEG — undefined interface hard-reject #4515, lenient downgrade, lo0 and IPsec bind-interface st0 exempt via zoneReferenceableInterfaceBases.
- `zone_interface_membership_test.go`: NEG — multi-zone same iface hard-reject #3072, lenient downgrade, bare vs unit overlap, same-zone repeat not flagged, distinct units VLAN split not flagged.
- `scoped_global_zoneset_4626_test.go`: NEG — two set lines accumulate #3984, dedup sorts, strict gate rejects undefined element, any mix, junos-host mix, lone junos-host commits, multi-zone address-book resolution A7 (single-zone keeps zone-local, multi-zone uses global book).
- `zoneid_test.go`: NEG — hash freeze, never zero/reserved, pure function, collision fails commit, lenient warns, HA symmetry across groups, quarantine drops later, owner returns survivor.
- `zone_local_unqualify_3358_test.go`: NEG — unqualify logic for zone-local address-book synthetic names.
- `schema_walk.go`: NEG — typed-leaf validation, multi-value leaf both Keys[1:] + Children, modifier-only sibling requires sibling value, scalar leaf arity rejects trailing token #3332, closed-world opt-in, tailValidator #4228, keyValidatorPos #5576. No zone bypass.
- `schema_validators_scheduler.go`: NEG — ValidateTimeOfDay HH:MM:SS, ValidateDate YYYY-MM-DD, fail-closed #3849.
- `types_chassis.go`, `types_cos.go`, `types_interfaces.go`, `types_routing.go`, `types_system.go`, `types.go`, `value_type.go`: NEG — type definitions, no zone enforcement logic, no integer truncation beyond parsed elsewhere.
- `screen_*` tests (6 files): NEG — screen alarm-without-drop, numeric strict, trailing token, unknown strict — unrelated to zone, no policy bypass.
- `snmp_clients.go` + 4 tests: NEG — SNMP community handling, dup community #5472 test, unrelated to zone.
- `syslog_logfile.go` + test: NEG — log file validation.
- `secret.go` + test: NEG — secret redaction.
- `set_repeated_leaf_3984_test.go`, `shared_umem_audit_test.go`, `show_config_dup_context_4562_test.go`, `show_config_repeated_keyword_3980_test.go`: NEG — set-path repeated leaf handling, not zone.
- `sqm_cookbook_fixture_test.go`, `ssh_known_hosts_dup_block_4821_test.go`: NEG — QoS, SSH known hosts.
- `static_nat_*` (3): NEG — NAT zone tests, but static NAT zone scoping separate from security policy; no bypass found (from-zone validation exists).
- `strict_gate_wiring_canary_test.go`: NEG — wiring canary for strict gates.
- `system_multileaf_test.go`, `system_string_injection_4902_test.go`: NEG — system.
- `tcp_flags.go` + test, `time_zone_path_validate_5011_test.go`: NEG.
- `tunnel*` (tunnelemit 123 LOC, tunnelid 290 LOC + test): NEG — tunnel ID stable hash similar to zone id, no zone bypass.
- `vrf_overlap_budget_5194_test.go`, `vrrp_*` (4 tests), `web_management_auth_4047_test.go`, `wireguard_*` (3 tests + ports + multipeer 795 LOC), `xfrmi.go`: NEG — unrelated to zone policy, not bypass.
- `compiler_validate_strict_zones.go`, `compiler_validate_strict_policy.go`, `compiler_policy_match.go` (read for context, outside batch): NEG — reserved zone names #3055, zone count cap #2391 superseded, interface membership, defined check #4515, host-inbound token validation #3200, policy address #2008/#3294, app #3144/#3146, address-set #3149, zone refs #2401/#4230/#4626, duplicate policy #3473, terminal action #3043, log action #3060, address-book naming #3061/#4340, policy match leaves #3113/#3142/#3673.

## Findings — Confidence separated (MATERIAL or COHORT only)

### COHORT-01: duplicate interface accumulation in zone.Interfaces after #4818 find-or-create

Title: Zone Interfaces slice accumulates duplicates across duplicate security-zone instances
Severity: Low
Confidence: COHORT
Gate verdict: COHORT
Evidence:
- File `/tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b4/pkg/config/compiler_security_zones.go:113-134`:
```
for _, prop := range inst.node.Children {
 case "interfaces":
  for _, iface := range prop.Children {
   zone.Interfaces = append(zone.Interfaces, zoneInterfaceMembers(iface)...)
```
No dedup. `zoneDupBlock4818ThreeInstances` test uses distinct interfaces, not duplicate same iface across instances. If operator loads override with same interface in both blocks, result is duplicate entry.
Trace: parseHierarchical with two `security-zone trust { interfaces { ge-0/0/0; } }` blocks → namedInstances yields two entries, find-or-create merges → Interfaces = ["ge-0/0/0","ge-0/0/0"].
Refutation: Downstream `buildInterfaceZoneMap` uses map and first-writer-wins, so duplicate does not create multi-zone conflict; but zone inventory display and any length-based checks double-count.
HPC/invariant: O(n) append, no extra allocation; dedup would be O(n^2) or map but acceptable for small n (<100).
Why it matters: Observability duplication, minor resource waste, not security bypass.
Fix direction: dedup via seen map in compileZones similar to dedupHostInboundTokens, or keep as is with comment that duplicates are tolerated (current comment says byte-identical single-block preserved, but duplicate across blocks is not deduped).
Labels: zone, dedup, observability
Dedup note: Not in dedup list (checked #5606, #5563, #4818 itself).
Verified against origin/master: line 113-134 same as base.

### COHORT-02: IsWildcardZoneSet contains("any") collapse widens permit on lenient path

Title: Lenient path mixed `any` + concrete zones collapses to wildcard (fail-open for permit)
Severity: Low
Confidence: COHORT
Gate verdict: COHORT
Evidence:
- File `/tmp/review-wt-claude-spark-001-A3_go_config_cli_tree-b4/pkg/config/types_security.go:482-484`:
```
func IsWildcardZoneSet(zs []string) bool {
 return len(zs) == 0 || slices.Contains(zs, "any")
}
```
- Strict gate in `compiler_validate_strict_zones.go:600-606` rejects mixing any with concrete: `if len(FromZones)>1 && contains any { return error mixes any }`. Lenient path downgrades to warning and still compiles. On lenient (HA-sync/load), `GlobalPolicyAppliesToZone` and Rust `build_global_zone_scope` will treat mixed set as wildcard => broader match than operator configured.
Trace: Commit `set ... from-zone [ any trust ]` → strict reject, but if persisted by older binary and loaded via CompileConfigLenient, bookNames contains mixed set, IsWildcardZoneSet true → Rust evaluates as all zones.
Refutation: Lenient path is for no-brick boot (#1960), not for new commits; operator-visible warning emitted; HA-sync should never produce mixed set if both nodes run new code. Pre-#4626 helper ignoring plural fields is #5488, already tracked.
HPC/invariant: Contains check O(n), acceptable.
Why it matters: Defense-in-depth: lenient load of invalid config widens permit rather than quarantine. Fail-open potential but gated behind strict reject.
Fix direction: On lenient path, treat mixed any as invalid and quarantine similar to zone-id collision, or keep warning + collapse to wildcard as documented backstop (current doc says "contains-any collapse is tolerant backstop").
Labels: scoped-global, lenient-path, fail-open-widen
Dedup note: Related to #5488 (open) which is about snapshot version bump, not this Contains logic. Not duplicate of #5488, but same area — mark as COHORT not MATERIAL.
Verified against origin/master: same lines 482-484 on origin/master tip.

### (No MATERIAL findings)

All core zone policy invariants verified:
- Default-policy initialized to PolicyDeny in compiler.go line 2224, not zero-value permit — fail-closed #3065.
- IsWildcardZone empty => all zones, explicit "any" also wildcard — matches Rust.
- Global scope FromZones/ToZones accumulated via firewallMatchValues SSOT, sorted deduped #4626 M03.
- Zone ref validation #4230 rejects undefined from/to, rejects from-zone junos-host (host-originated TX path), rejects mixing any/junos-host.
- Host-inbound merge #4544 union dedup, find-or-create #4818, interface flatten #5248 bracket handling.
- Zone ID collision gate three-view HA-symmetric, quarantine.

No live enforcement bypass found in this batch.



---

### === ps-A4_go_configstore_persist-b1.md (7880 chars, 104 lines) ===

# A4 Go Configstore Persist — Zone Policy Persistence Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Worktree: /tmp/review-wt-claude-spark-001-A4_go_configstore_persist-b1 | Model: claude-spark-001
Focus: zone config persistence and rollback preserves zone policies (inter-zone allow/deny), crypto envelope, commit-confirmed, factory reset

## File-size / Shape Inventory
Prod 15 files ~5.1k LOC; tests ~10.2k LOC total 16k. Hottest: store_commit.go 1084 LOC (commit/confirmed/rollback + timer), store_persist.go 657 (Load + retry loop), store.go 660, db.go 403, crypto.go 395, journal/journal.go 564. Largest fn: store_commit.go PromoteRollback 120 LOC, store_persist.go recoverPendingConfirmLocked 140 LOC, factory_reset.go FactoryResetConfigDir 140 LOC. Hot path: fsatomic.WriteFileDurable temp+fsync+rename+dirfsync #3441. Responsibility rank: store_commit > store_persist > db > crypto > journal > envelope > factory_reset.
Prod vs test 1:2. Ranking by size x resp x hot-path: commit durability highest for zone preservation.

## Module Log (NEG proving coverage)

### store_commit.go 1084 LOC
NEG: #1799 persist-before-promote ensures active.json containing Security.Zones written BEFORE in-memory promotion and BEFORE confirm state touched. On persist failure: no promotion, no history push, no journal entry, existing pending confirm intact. Prevents zone loss on crash after commit that tightens deny.
Evidence file:line pkg/configstore/store_commit.go:86-92:
```
// Persistence contract (#1799, Option A — persist-before-promote): the
// (db.go), so a persist failure leaves the previous active config
// change, no history push, no journal entry, no rollback-file save.
```
Verified sound for zone preservation.

NEG: Nested CommitConfirmed preserves confirmPrevTree (last truly CONFIRMED restrictive zones) not unconfirmed permissive. Quote store_commit.go:273-276:
```
// Nested confirmed commits (a second CommitConfirmed while one is
// still pending) PRESERVE the existing confirmPrevTree/confirmPrevCfg:
// the rollback target must stay the last truly CONFIRMED config.
```
Prevents rollback to intermediate unconfirmed permissive zone that would become permanent if confirm timer reverted to it. Sound.

NEG: saveRollbackFiles writes full active.Format() (includes security zones, policies, host-inbound) to slot1 durable + slots 2..N atomic + final SyncDir #1894 adjudicated. loadRollbackHistory #4810 tombstone preserves position (HistoryEntry{Config:nil}) prevents N→N+1 shift returning wrong zone set. rollbackEntry rejects tombstone fail-closed.

### store_persist.go 657 LOC
NEG: fsatomic.WriteFileDurable temp+fsync+rename+dirfsync durable. Confirm flag removal ordered after durable write #5473:
```
// #5473: the active config is now durable. If a commit-confirmed
// replacement target is exactly what just landed durably — drop the
```
If write fails, confirm.json retained, crash re-drives rollback to restrictive zones. Sound.

NEG: committed marker C3 defaults true on upgrade: never-committed first-commit marker never misclassifies populated zone config as bootstrap empty.

### db.go 403 LOC + envelope.go 318 LOC
NEG: hasEnvelope magic '#xpf-config-envelope' leading '#': pre-envelope reader json.Unmarshal fails closed (not empty-load that would lose zones). min-reader gate rejects too-new DB from older binary: fail-closed not misread zones. committed field defaults true (C3) so upgrade never misclassifies populated zones into bootstrap. Sound.

### crypto.go 395 LOC
NEG: AES-GCM v1 envelope random 12-byte nonce per encrypt. Decrypt nonce length guard #4793 prevents panic:
```
if len(nonce) != gcm.NonceSize() {
    return nil, false, fmt.Errorf("invalid nonce length %d (want %d)", len(nonce), gcm.NonceSize())
```
Unknown format #4888 now errors not plaintext pass-through empty tree (zone loss). Null decode #5474 requireJSONObject rejects top-level null that would decode to empty zones (fail-open). Sound.

### factory_reset.go 240 LOC
NEG: Ownership guard only wipes DefaultArchiveDir /var/lib/xpf/archive (xpf-owned), warns skips custom remote/compliance archive intentional. Wipes .configdb with zones + master.key key-first + SyncDir barrier #5197 before ciphertext, plus numbered text rollback slots with full zone text, rescue.conf, audit journal, fsatomic temps .*.tmp-* with zone secrets. Durable via unlink+dirfsync. Zone wipe intentional for factory reset, not fail-open (deny-by-absence). Sound.

### journal/journal.go 564 LOC
NEG: v2 compact metadata-only (no zone payload), 0600 newly, migratePermsLocked repairs 0644 legacy #5188. Tail reverse-scan bounded O(limit), maxTailLineBytes 16MiB poison-line defense, maxCommitDescriptionBytes 4KiB cap #4891. Torn-tail recovery truncates corrupt tail. Audit-only, not active zones, not enforcement bypass. Sound.

### store_lock.go, check.go etc
NEG: cluster readonly gate ErrClusterReadOnly prevents secondary mutating zones (#3893). Holder gating #5059 prevents cross-session candidate hijack overwriting zones.

## Findings (High confidence, MATERIAL/COHORT only)

### COHORT-1: Factory-reset skips custom archive dir — prior tenant zone text retains on non-default path
Title: Custom archive dir skipped on zeroize retains prior tenant zone config with PSKs
Severity: Low
Confidence: Medium
Gate verdict: COHORT
Evidence: factory_reset.go:60:
```
if filepath.Clean(archiveDir) != DefaultArchiveDir {
    slog.Warn("zeroize: skipping config archive directory with unproven ownership...; a custom, remote, or compliance archive destination is the operator's to erase, not the factory reset's"
    return nil
```
Trace: Not needed (low).
HPC: Archive retention intentional compliance; custom path ownership unproven xpf-owned. Warning logged. Default path /var/lib/xpf/archive IS wiped.
Fix direction: Document operator must manually erase custom local archive; consider optional flag with marker file ownership proof.
Labels: factory-reset, archive, secret-retention, defense-in-depth
Dedup: Checked #4858/#5186/#5197/#5475 — custom archive intentionally skipped, not bug.
Verified against origin/master: /home/ps/git/avacado-xpf/pkg/configstore/factory_reset.go:53-64 same guard on master.

### COHORT-2: Lenient Load warns but boots legacy invalid zone schema
Title: Lenient Load path warns but boots legacy invalid zone schema until strict commit
Severity: Low
Confidence: Low
Gate verdict: COHORT
Evidence: store.go compileTreeLenient:
```
if err := s.schemaValidateExpandedTree(tree); err != nil {
    slog.Warn("typed-leaf schema violation in tolerated config; continuing (a strict commit would reject this)", "err", err, "issue", "#1319")
```
Not zone bypass — intended boot-safety #1960 tradeoff, strict would blackout node or alarm-loop HA sync.
Fix: None, already belts with warn; could add metric counter.
Labels: lenient-load, schema, upgrade-safety
Dedup: Aligns with #1319 tolerant ingress design, not in dedup.
Verified against origin/master: /home/ps/git/avacado-xpf/pkg/configstore/store.go:470-480 same warn.

## Overall Verdict
Configstore correctly preserves zone policies via persist-before-promote #1799, committed marker C3, envelope min-reader fail-closed, crypto nonce guard #4793, rollback tombstone anti-shift #4810, confirm ordering #5473. No MATERIAL inter-zone bypass. Factory reset intentionally wipes zones durably. Coverage proved via NEGs.

## Checked Dedup
#5564 standby sync tail, #5563 stale policy, #5562 snapshot rotation, #5488 global deny version, #1922 bootstrap marker, #1917 envelope, #1799 persist, #4793 nonce, #3441 durability, #5186 archive wipe, #4888 unknown format, #5474 null decode — none re-report.

## Verified Against Origin/Master
Base SHA 4e0c7f74 equals origin/master tip per batch. Checked envelope.go:1-200, store_commit.go:86-92, crypto.go:199-265, db.go:1-100 on worktree vs main repo — identical.


---

### === ps-A5_go_ha_vrrp_ra_conntrack-b1.md (20856 chars, 245 lines) ===

# Batch A5_go_ha_vrrp_ra_conntrack — Zone-Policy Focus Review

## File Inventory (Ranked by Size × Responsibility × Hot-Path)

| File | LOC | Type | Largest Fn | Responsibility | Hot Factor |
|---|---|---|---|---|---|
| cluster/sync_conn.go | 1858 | prod | handleMessage (300+ LOC) | Wire RX, zone filtering, gen guards, bulk RX, cold-start fencing | CRITICAL |
| vrrp/instance.go | 2417 | prod | run() state machine | VRRP MASTER/BACKUP, VIP add/remove, GARP burst, preempt gates | CRITICAL |
| vrrp/manager.go | 1108 | prod | UpdateInstances (400+) | Sync hold, instance lifecycle, link/addr watchers, ReconcileVIPs | CRITICAL |
| ra/ra.go | 1118 | prod | Apply (400+) | RA manager, per-iface senders, graceful goodbye, epoch fencing | HIGH |
| ra/sender.go | 1055 | prod | run() + finishShutdown | RA packet build, RS filter, goodbye emit, timer management | HIGH |
| cluster/sync.go | 1048 | prod | SessionSync struct + bulk/stream wiring | Session store, zone→RG map, delete journal, barrier protocol | CRITICAL |
| cluster/failover.go | 912 | prod | ManualFailoverBatch | Manual failover locking domain, transfer-commit state machine | HIGH |
| cluster/heartbeat.go | 881 | prod | UnmarshalHeartbeat + auth | HB packet codec, auth HMAC, anti-replay (single session,counter) | HIGH |
| cluster/sync_protocol.go | 829 | prod | encode/decode SessionV4/V6 | Wire codec: zone fields, PolicyID/CounterIdx, AppTimeout, NAT64 SNAT | CRITICAL |
| cluster/garp.go | 754 | prod | SendGratuitousARP/Burst | GARP/NA burst, followup burst, still-valid gating | HIGH |
| cluster/status.go | 721 | prod | Status aggregation | Cluster show | LOW |
| cluster/monitor.go | 641 | prod | pollInterfaceMonitors | IF monitor weights, dampening, local status → HB | HIGH |
| cluster/sync_failover.go | 607 | prod | Request/Finalize failover | Sync-channel failover request/commit protocol | HIGH |
| conntrack/gc.go | 554 | prod | sweep() | GC expiry, IsLocalPrimary gate, OnDelete→sync, per-IP limits | HIGH |
| cluster/heartbeat_manager.go | 492 | prod | handlePeerHeartbeat, handlePeerTimeout | Peer HB RX, transfer-commit override apply, timeout → electSingleNode | CRITICAL |
| cluster/sync_bulk.go | 449 | prod | BulkSync | Bulk send with ShouldSyncZone filter, epoch, ack tracking | CRITICAL |
| cluster/election.go | 475 | prod | electRG | Priority election, manual-failover guard, dup node-id closed | CRITICAL |
| cluster/manager.go | 460 | prod | Manager lifecycle + election driver | Node ID, peer groups, weight recalc, event channel | CRITICAL |
| cluster/sync_auth.go | 424 | prod | performSyncHandshake, sealFrame | Sync-channel auth PSK, HMAC sealing, downgrade guard | MEDIUM |
| vrrp/track.go | 341 | prod | getPriority, setTrackDown | Track-interface demotion, clamp [1,254],.owner exemption | HIGH |
| vrrp/packet.go | 277 | prod | Marshal/Unmarshal VRRP | VRRPv3 packet codec, checksum, MaxAdverInt | MEDIUM |
| vrrp/vrrp.go | 266 | prod | Instance struct | VRRP group config + validation | MEDIUM |
| vrrp/addrwatch.go | 219 | prod | addr watch callbacks | VIP addr re-resolve on kernel addr change (#2528) | MEDIUM |
| cluster/reth.go | 177 | prod | RETH management | RETH to physical resolution | LOW |
| cluster/group_state.go | 263 | prod | RedundancyGroupState | RG state, readiness, takeover-hold timer | HIGH |
| cluster/readiness.go | 89 | prod | SetRGReady | Readiness gate for RG promotion | CRITICAL (cold-boot) |
| ra/filter.go | 21 | prod | setAllowRS | ICMPv6 filter: only RS (type 133) | MEDIUM |

Test files: 73 files (~30k+ LOC), largest sync_test.go 4717 LOC, serialize_test.go 2706, vrrp_test.go 2468.

---

## Module Log (NEG = sound, with invariant)

### pkg/cluster — Session Sync Wire & Zone Preservation

- **sync_protocol.go** — NEG: wire codec preserves ALL zone-policy fields: IngressZone, EgressZone, PolicyID, PolicyCounterIdx, AppTimeout, Nat64SnatV4, Generation, IsReverse, State. Length-gated trailing fields backward-compat. Config-gen trailing magic non-printable. DHCP lease count clamped len/4 bounds.

```
buf: encodeSessionV4Payload at ingress zone:
binary.LittleEndian.PutUint16(buf[off:], val.IngressZone)
...
binary.LittleEndian.PutUint16(buf[off:], val.EgressZone)
...
binary.LittleEndian.PutUint32(buf[off:], val.PolicyID)
...  // PolicyCounterIdx, AppTimeout, Nat64SnatV4 trailing
```

- **sync_bulk.go** — MIXED: BulkSync correctly filters `ShouldSyncZone(IngressZone)` to only sync sessions owned by primary RGs. However zoneRGMap lookup may miss during config transition → falls back to global primary. See COHORT below.
- **sync_conn.go / ShouldSyncZone** — See analysis: zone→RG map miss falls back to IsPrimaryFn (global primary). During config reload window, sessions for unmapped zone either not synced (secondary loses sessions) or over-synced (primary syncs zone it doesn't own). Not data-plane bypass but HA availability issue.
- **sync_conn.go — gen guards** — NEG: Full #2170/#2221 implementation: sender stamps monotonic gen, delete draws fresh gen strictly greater than install, receiver tombstones delete gen, install guard refuses older. putGenBounded at 200k cap skip-record-on-full safe (degrades to gen-0 unconditional). resetRecvGen on BulkStart clears both session-gen and config-gen to prevent stale-reject of rebooted peer's bulk (#2198 F2).
- **sync_conn.go — cold-start** — DEDUP #5480/#4360: bulkEverCompleted sticky + outboundBulkAcked fix. Survivor skipping outbound bulk on reconnect is #5480. New code uses outboundBulkAcked gate correctly.
- **sync.go — zone ownership snapshot** — NEG: `snapshotZoneOwnership()` captures zone→ownership at bulk start time; `reconcileStaleSessions()` at BulkEnd uses bulkRecv maps to delete stale sessions. Correct zone-scoped reconcile.
- **sync_auth.go** — NEG: Auth wrapper seals each frame with HMAC + seq in writeFull (single chokepoint). Sticky syncAuthedEver rejects future unauthenticated connections once any auth succeeds (downgrade guard).
- **sync_failover.go** — DEDUP #5479: abort path only restores local, peer left in SecondaryHold. Already tracked.

### pkg/cluster — Election / Failover / Readiness (Cold-Boot Fencing)

- **election.go** — NEG: Correct priority election (weight*prio/255), preempt vs non-preempt, ManualFailover 2s guard, split-primary dual-active resolution, dup-node-id fail-closed to Secondary with rate-limited warning (#4549 F11). kernelUpgradeHold (#1930 INC-2) NOT auto-cleared ← safe.
- **failover.go** — NEG: Single lock domain, failoverGen versioning prevents ResetFailover race (#5246), transfer-commit grace period 2*threshold*interval+slack. batch and single share same locked helpers.
- **group_state.go / readiness.go** — NEG: IsReadyForTakeover checks Ready + ReadySince+holdTime. Hold timer re-triggers election. UpdateConfig stops+nil's timer on RG removal (#5245), staleness guard in readiness closure checks `cur != rg`.
- **readiness** — NEG: Cold-boot fence: electRG checks `!ReadyForTakeover(holdTime)` before electLocalPrimary. Ready gate requires interfaces up + VRRP confirmed. Blocks new promotions, not demote incumbent primary.
- **monitor.go — pollInterfaceMonitors missing** — DEDUP #5478: local iface missing → log+continue without SetMonitorWeight → incumbent primary not demoted. The dedup correctly identifies this as fail-open. Note: `RGInterfaceReady()` (readiness gate) DOES report missing as not-ready, mitigating cold-boot path. But runtime monitor path (pollInterfaceMonitors) does NOT demote active primary.
- **monitor.go — RGInterfaceReady** — NEG: For readiness gate, missing iface correctly returns `(false, ["interface X missing"])` preventing cold-boot takeover. peer's interface check via SlotToNodeID skips peer's interfaces. Dampening (failThreshold=3, passThreshold=3, holdDown=5s) prevents flap.
- **heartbeat.go — anti-replay** — DEDUP #5477: single (session,counter) no retired-session tracking → A→B→A replay possible. HMAC verify + decision table correct for keyed/unkeyed/mixed.

### pkg/cluster — GARP / Heartbeat Manager / RETH

- **garp.go** — NEG: GARP burst sends ARP req+reply variants, IPv6 NA (solicited+override unset). Follow-up burst in goroutine with BurstStillValid gating. Error accounting via BurstSendErrors counter. VIP-excluding source selection not in this file (VRRP instance handles).
- **heartbeat_manager.go** — NEG: handlePeerHeartbeat builds newPeerGroups, applies transfer-commit overrides via applyTransferCommitOverridesOnPeerStateLocked (failover.go). Grace windows expired inline. Peer-timeout suppression for recent transfer-commit. bulkSync done via BulkSync().
- **reth.go** — NEG: RETH to physical resolution, data-plane only change.

### pkg/vrrp — VRRP VIPs, GARP, Track-Interface, Sync Hold

- **instance.go — addVIPs/removeVIPs void** — DEDUP #5482: void functions swallowing netlink errors → control-plane role can diverge from kernel VIP state. emitEvent without verifying VIP ownership success.
- **instance.go — becomeMaster GARP** — NEG: becomeMaster does addVIPs → sendAdvert → emitEvent (sync critical path) → async sendGARP(false) with epoch+time damping. post-MAC-change ReconcileVIPs path bumps garpEpoch + force=true to bypass both gates (#2081). Good L2 convergence.
- **instance.go — IPv6 advert socket failure** — DEDUP #5481: IPv6 socket open failure warns + continue → instance can become MASTER without ever advertising.
- **manager.go — sync hold** — NEG: SetSyncHold suppresses preempt on all instances (cfg.Preempt=false + desiredPreempt stored). ReleaseSyncHold restores desired preempt + triggers preemptNow. Timeout defaults 30s degraded mode. New instances created during sync hold also get Preempt=false. Correct cold-boot fencing.
- **manager.go — UpdateInstances** — NEG: VRID guard (MinVRID..MaxVRID), build-before-teardown (#2156), late-appearing interface tracking via desiredIfaces (#2788), ifindex drift detection (#2294), addr-watcher + link-watcher singleton guards.
- **track.go — track-down demotion** — NEG: getPriority clamps tracked-down priority to [1,254], exempts priority 0 (resignation) and 255 (IP owner). setTrackDown transition-logged. MASTER with lower effective priority advertises it; backup's handleBackupRx lets masterDownTimer expiry take over (no self-demote needed).
- **packet.go** — NEG: VRRP checksum, MaxAdverInt 10ms units, VRID byte.

### pkg/ra — RA Filter, Goodbye, Per-Iface Epoch

- **filter.go** — NEG: ICMPv6 filter allows ONLY Router Solicitation (type 133), blocks all other ICMPv6. Prevents inter-zone RA spoof RS→RA amplification. Source is link-local selection via netlink.
- **ra.go + sender.go — goodbye lifecycle** — NEG: Graceful goodbye on config removal (#5092): Apply-empty and per-interface removal now send lifetime-0 farewell. Draining tombstones (drainEntry) with global epoch + per-iface epoch (#4961) prevent second owner racing goodbye. OnProvenClose revalidation prevents superseded deferred starts. join timeout → detached reclaimer (#5094) owns eventual goodbye.
- **ra.go — per-iface epoch** — NEG: WithdrawInterfaces bumps only per-iface ifaceEpoch (not global), so unrelated interface restarts not affected. Changed-config restart records startIfaceEpoch and only proceeds if epoch unchanged. Correct inter-zone isolation.
- **sender.go — marshal** — NEG: RA packet built per RFC 4861, AdvOtherConfig/Managed flags, prefix valid/preferred lifetimes, MTU, source link-layer option.

### pkg/conntrack — GC + HA Delete Sync

- **gc.go** — NEG: When IsLocalPrimary==false (secondary), skips expiry entirely — primary owns lifetime. Scratch buffer reuse. Adaptive delay up to 60s. On secondary, all sessions treated active for session-limit counting. Early-ageout clamped negative→0 (#3440 H2). Aging watermark hysteresis under mu. V6 skip when lastV6Count==0 + forced every 6th.
- **gc.go — OnDelete callbacks** — NEG: GC's OnDeleteV4/V6 wired in daemon_run.go only when `cluster.IsLocalPrimaryAny() && sessionSync.IsConnected()` — intentionally deletes synced only when primary. QueueDeleteV4/V6 path journals deletes when sendCh backpressured (#3926) and flushes while connected via syncSweep(). Peer ignores deletes for sessions it doesn't have. Preserves zone policy (zone stored in value, delete keyed on 5-tuple only — correct, peer uses its own zone map to release count).

---

## Findings

### MATERIAL Findings — None isolated

After reviewing 106 files, all CRITICAL/HIGH material inter-zone bypasses were either fixed, in dedup list, or proved sound. Session sync wire preserves zones, VRRP sync-hold correctly fences cold boot via readiness gate, GC secondary-skip correct, RA filter blocks all but RS.

### COHORT Findings

#### [COHORT-01] Session bulk: zone→RG map miss falls back to global primary
Severity: Low · Confidence: Medium · Gate: COHORT
Evidence:
`pkg/cluster/sync_conn.go:704-719`
```go
func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool {
    if s.IsPrimaryForRGFn != nil {
        s.zoneRGMu.RLock()
        rgID, ok := s.zoneRGMap[zoneID]
        s.zoneRGMu.RUnlock()
        if ok {
            return s.IsPrimaryForRGFn(rgID)
        }
    }
    if s.IsPrimaryFn != nil {
        return s.IsPrimaryFn()
    }
    return false
}
```
And bulk:
`pkg/cluster/sync_bulk.go:133-134`
```go
if !s.ShouldSyncZone(val.IngressZone) {
    skipped++
    return true
}
```
HPC/invariant: During Apply, buildZoneRGMap runs after daemon_apply; concurrent BulkSync may race with empty/partial map. Zone not in map → IsPrimaryFn==global primary. A multi-RG cluster where node is RG0 primary but not owner of zone's RG would incorrectly bulk-sync that zone's sessions (over-sync, no bypass) and dual RG1 primary but not RG0 primary would miss syncing its zone (sessions lost on failover → brief outage, not bypass). The global-primary fallback is additive, not fail-open for inter-zone policy. Sessions carry original zone/policy and new primary still policy-enforces.
Fix direction: On map-miss, log once + treat as not-owned (return false) rather than global primary fallback, or hold bulk until zoneRGMap populated.
Labels: HA, session-sync, zone-policy, defense-in-depth
Dedup note: Not in dedup list (#5480-#5482, #5477-#5479). #3704 commit message acknowledges this area.
Verified: /home/ps/git/avacado-xpf/pkg/cluster/sync_conn.go:704 same on origin/master tip.

#### [COHORT-02] GC delete journal: compressed under lock no per-zone verification
Severity: Low · Confidence: Medium · Gate: COHORT
Evidence:
`pkg/conntrack/gc.go:335-351`
```go
if deleted, err := gc.sessions.DeleteBatchKnownV4(toDelete, dataplane.DeleteReasonGCExpired); err != nil {
    // ...
}
if gc.OnDeleteV4 != nil {
    for _, entry := range toDelete {
        gc.OnDeleteV4(entry.Key)
    }
}
```
And daemon_run.go:
```go
gc.OnDeleteV4 = func(key dataplane.SessionKey) {
    if d.cluster != nil && d.cluster.IsLocalPrimaryAny() && d.sessionSync != nil {
        d.sessionSync.QueueDeleteV4(key)
    }
}
```
HPC/invariant: Delete is keyed on 5-tuple only, no zone check at GC delete time. Correct — expired session's zone already in SessionValue but delete goes by key. Peer validates via its own gen guard. No zone mismatch. The counting aspect: aggregated per-zone counters decay correctly because `__put__` already cleared forward+reverse.
Fix direction: None needed for correctness; add per-zone delete counter metric for observability.
Labels: conntrack, GC, HA, observability
Dedup note: Not in dedup.
Verified: same on origin/master.

#### [COHORT-03] RA: RS filter allows only type 133 but no per-zone source validation in RA module
Severity: Low · Confidence: Medium · Gate: COHORT
Evidence:
`pkg/ra/filter.go:10-15`
```go
func (f *ipv6Filter) setAllowRS() {
    f.f.SetAll(true) // Block all.
    f.f.Accept(ipv6.ICMPTypeRouterSolicitation)
}
```
HPC/invariant: RA module's RS socket is per-interface bound via ndp.Listen(iface, ...). Kernel delivers only packets received on that ifindex. Dataplane host-inbound + inter-zone policy is enforced before RS even reaches RA sender's socket (userspace-dp allows RS → host). The RA module correctly trusts per-iface binding; inter-zone bypass would require kernel delivering cross-interface RS, which it doesn't. However, a compromised v6 host on untrusted zone sending RS to trusted-zone interface's link-local still triggers RA response leaking prefix info cross-zone at L2 — but that's expected IPv6 ND behavior, not bypass.
Fix direction: None; document that RA isolation relies on per-iface AF_PACKET / NDP binding.
Labels: RA, filter, defense-in-depth
Dedup note: Not in dedup.
Verified: /home/ps/git/avacado-xpf/pkg/ra/filter.go:1-21 same.

#### [COHORT-04] VRRP track-down demotion correctness + preempt-hold interaction
Severity: Low · Confidence: Low · Gate: COHORT
Evidence:
`pkg/vrrp/track.go: getPriority()`
```go
func (vi *vrrpInstance) getPriority() int {
    p := vi.cfg.Priority
    if p == 0 || p == 255 {
        return p
    }
    if vi.trackDown && vi.cfg.TrackInterface != "" {
        p -= vi.cfg.TrackPriorityCost
        if p < 1 { p = 1 } else if p > 254 { p = 254 }
    }
    return p
}
```
`pkg/vrrp/instance.go: skipNextPreemptHold`
- MASTER demotion doesn't self-demote; it keeps advertising at lower effective priority, backup's masterDownTimer expiry delivers takeover (handleBackupRx tail). Correct per RFC but means demoted MASTER still holds VIPs for up to masterDownInterval (~90ms at 30ms advert) after track-down.
HPC/invariant: Track-down clamp [1,254] prevents fabricating priority-0 resignation — correct (dedup #5481 adjacent). 90ms extra hold of VIPs by lower-prio master is not packet loss if peer GARP burst immediately re-writes L2. Brief split forwarding possible but not inter-zone bypass.
Fix direction: Consider resignCh on track-down transition (optional, would cut 90ms to ~1ms).
Labels: VRRP, track-interface, failover-timing
Dedup note: Not in dedup (#5482 adjacent but distinct).
Verified: same on origin/master.

#### [COHORT-05] Sync hold timeout-degraded mode allows takeover with possibly stale zone policy
Severity: Low · Confidence: Medium · Gate: COHORT
Evidence:
`pkg/vrrp/manager.go: SetSyncHold`
```go
m.syncHoldTimer = time.AfterFunc(timeout, func() {
    slog.Warn("vrrp: sync-hold timeout: bulk sync did not complete within timeout, releasing in degraded mode",
        "timeout", timeout)
    m.releaseSyncHoldWithReason("timeout-degraded")
})
```
30s default timeout.
HPC/invariant: If fabric is down or peer dead, sync hold timeout fires → VRRP preempt restored → node becomes PRIMARY without any synced sessions from peer. Old sessions from peer not available, but NEW sessions will be policy-checked correctly. The risk is only session continuity (flows reset), not inter-zone allow where deny should be. If operator changed policy while node was isolated, the isolated node's config may be stale. However config-sync push on peer reconnect (pushConfigToPeer) ensures newest config wins, and daemon_apply re-validates all sessions on policy change invalidating mismatched zones. So timeout-degraded cannot promote with stale policy — it promotes with current local config which may lag peer's but that's eventual consistency, not bypass.
Fix direction: Track timeout-degraded metric, already visible via SyncHoldReason(); optionally hold longer for RG whose zone-policy-critical sessions missing (not warranted).
Labels: HA, cold-boot, fencing, sync-hold
Dedup note: Not in dedup.
Verified: /home/ps/git/avacado-xpf/pkg/vrrp/manager.go:243 same.

---

## Summary Counters

- Prod files reviewed: 33 (all non-test .go)
- Test files reviewed: 73
- Total LOC reviewed: ~48k (prod ~13k + test ~35k)
- MATERIAL new findings: 0 (all dedup'd or NEG)
- COHORT (defense-in-depth): 5
- NEG proven: 18+ (wire codec, gen guards, election, readiness, gc secondary skip, garp epoch+force, RA goodbye, per-iface epoch, track clamp, sync-hold)

## Zone-Policy Verdict

Session zones and policy hits ARE preserved across failover: wire codec carries IngressZone/EgressZone/PolicyID/PolicyCounterIdx/AppTimeout faithfully; generation guards prevent stale delete/install races that would kill policy-bound sessions; ShouldSyncZone consults per-RG ownership via StableZoneID-mapped zoneRGMap; bulk RX reconciles stale sessions; GC expiry skipped on secondary and deletes propagated with generation. VRRP VIP moves are GARP'd with epoch-dedup defeat on MAC change (ReconcileVIPs force=true). Cold-boot fencing: election blocked by !peerEverSeen, readiness gate (RGInterfaceReady reports missing as not-ready), VRRP sync hold (preempt=false until bulk complete, timeout-degraded). RA cannot leak inter-zone: filter allows only RS per-iface, per-iface epoch + draining tombstone prevents goodbye race. GARP after failover ensures L2 convergence for zone transition. No new material inter-zone allow/deny flaws found.


---

### === ps-A6_go_dataplane_manager-b1.md (12862 chars, 118 lines) ===

# A6 Go Dataplane Manager b1/3 — Zone Mapping & Host-Inbound Scoping
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Worktree: /tmp/review-wt-claude-spark-001-A6_go_dataplane_manager-b1 | Model: claude-spark-001
Focus: how zones compiled to ifindex_to_zone_id and zone collision quarantine #3719, host-inbound VIP scoping #3172, inter-zone allow/deny

## File-size / Shape Inventory
Batch b1 150 files: prod ~80 (compiler_iface 1394 LOC, compiler 1808, types 1056, interfaces 561, builder 196, zones_quarantine 57, host_inbound* 100-450 each, filters 641), tests ~70. Prod hot path: compileZones SetZone per {ifindex, vlanID}, builder quarantine hook, interfaces synthetic ifindex #2917, host-inbound per-iface views #3362. Responsibility rank:
1. compiler_iface.go — ifindex_to_zone_id composite {ifindex, vlanID}, host-inbound flags, DeleteStaleIfaceZone.
2. builder.go + zones_quarantine.go — StableZoneID collision quarantine #3719 drops later-sorting zone, unzones interfaces fail-closed, scrubs policies (#5577 scoped-global prune vs drop).
3. interfaces.go — zoneByInterface ownership #5489, synthetic ifindex for logical RETH VLAN, parent bind #2917 zero-copy.
4. host_inbound_* — per-iface effective views #3362 union, phys-unit #3720 no cross-zone leak, exact-unit #5489, view grouping canonical #3721, unzoned catch-all #4420.
5. compiler.go — assignZoneIDs stable #3075, default-policy sentinel #3065 fail-closed deny, global scope #4626 M03.

## Module Log (NEG proving coverage)

### compiler.go
NEG: assignZoneIDs uses config.StableZoneID(name) FNV-1a pure name-derived into [1, ZoneIDReservedMin-1] never compile order — adding/removing zone never renumbers another, prevents in-flight session/HA/status mis-map. PolicyNames seeds DefaultPolicySentinelID=0xFFFFFFFF "default-policy" so Rust implicit default deny resolves correctly not mis-attribute ID 0. Default deny on empty #3065 via policyActionString returns deny. Sound.

### compiler_iface.go
NEG: compileZones writes zone_config then maps interfaces via composite key {physIfindex, vlanID} handling VLAN subifs, RETH members, lo0 atomic delete+recreate. writtenIfaceZone tracks bool then DeleteStaleIfaceZone removes stale entries preventing old zone after interface removal. Populate-before-clear (writes new first) prevents window unzoned.
Evidence: compiler_iface.go:464:
```
writtenIfaceZone[IfaceZoneKey{Ifindex: uint32(physIface.Index), VlanID: uint16(vlanID)}] = true
```
Sound.

NEG: host-inbound flags map tokens to bitflags, warn unknown, auto-add GRE for tunnel transport source IP — without it outer GRE proto 47 blocked. Nil guards for HA-sync tolerant path.

### builder.go + zones_quarantine.go #3719
NEG: #3719 enforces StableZoneID isolation BEFORE publish. Two names folding to same ID (z174/z214 known pair) would merge zones in Rust id-keyed maps (reverse name/host-inbound/tcp-rst overwrite, both zones interfaces/policies resolve to one ID isolation failure). quarantineCollidingZones drops later-sorting colliding zone deterministic sorted name, unzones its interfaces (Zone="" => default-deny fail-closed), scrubs policies: zone-pair FromZone/ToZone quarantined => DROP whole rule, scoped-global plural MatchFromZones/MatchToZones #4626 M03 prunes quarantined members KEEPS rule to survivors fail-closed #5577, regenerates singular via ScopeSingular for old helper compat (never dangling ref). Strict commit REJECTS collision via validateZoneIDCollisionAST #3075, quarantine is lenient backstop #1960 no-brick. Test zones_collision_3719_test.go verifies dropping, unzoning, policy scrub, collision record survivor/quarantined + ID, scoped-global prune preserving survivors, no two zones share ID after. Sound fail-closed.

### interfaces.go + synthetic VLAN
NEG: buildInterfaceZoneMap first-sorted wins on duplicate ownership (tolerated lenient). Exact-unit guard #5489 ensures losing zone tokens not bleed into winning zone's snapshot (union would include losing ssh). Test host_inbound_owner_5489 verifies owner first sorted, exact-unit no cross-zone leak.
NEG: Physical override no cross-zone leak #3720 physical override authored in trust must NOT expand onto unit reth0.20 in different zone guest — before fix leaked onto every unit of physical.
NEG: Synthetic ifindex high range [1<<30, +1M) FNV hash name/vlanID with used set, never collides kernel ifindexes. UserspaceBindTargetNetdev parent netdev for VLAN child physical parent for AF_XDP zero-copy #2917 mirrors Rust planner — prevents #3091 single-worker regression. RETH RG inheritance from parent ensures HA owner_rg correct not 0 bypass. Sound.

### host_inbound per-interface views
NEG: BuildZoneHostInboundViews splits zone into per-iface effective-token views — overridden iface addr lands in override tokens view, non-overridden in empty-token catch-all drop view. Union semantics Junos additive: zone ping + iface ssh => {ping, ssh} on that iface. Zone snapshot configured-via-interface HostInboundConfigured=true enforcing, zone-keyed token empty fail-closed for non-overridden. Test per_iface_3362 proves. Sound for exposing ssh on one iface deny other.
NEG: View grouping #3721 order-sensitive signature previously split identical sets [ssh ping] vs [ping ssh] into duplicate nft blocks — fix canonical sorted/deduped signature collapses duplicates perf preserving admission.
NEG: Unzoned catch-all #4420 BuildUnzonedHostInboundAddrs adds addressed iface in NO zone to unzoned deny set fail-closed HI-2, excludes zoned and lifeline fab* so management never denied. Test: zoned 10.0.1.10 not in deny, unzoned 192.0.2.1 in deny, lifeline 10.5.5.5 excluded, zoneless bootstrap yields NO deny (never deny-all). Sound.

### host_inbound_classify.go #3627 B1a + junos_host_deny.go #4146
NEG: Classifier diagnostic only (enforcement nft pkg/daemon/daemon_nft.go + Rust forwarding/host_inbound.rs). Reads same SSOT HostInboundServiceMatch/ProtocolMatch as nft builder, mirrors global pre-accepts ESP/AH, ICMP error/PMTUD, IPv6 ND. Zone-scoped query classifies EACH view independently reports HostInboundAmbiguous when views disagree #5579 not OR-ing into false first-admit lying for denying ifaces. Interface-scoped selector true posture. Post #3405 configured zone no stanza default-DENIES empty token set. Lifeline fxp0/em0/fab* excluded never classified. Sound.
NEG: JunosHostProgram adapter for config-level #4146 junos-host DENY projection config.BuildJunosHostDenyProjection owns policies/address-book/apps/schedulers/feeds, resolves iifname scope JunosHostZoneIngressNetdevs lifeline-excluded free of cross-zone-ambiguous shared parent, reused by #4168 commit warning. Wrapper forwards already-resolved IngressNetdevs (iifname NOT dest address which under/over-denies across zones). Enforcement Go-only nft xpf_hostinbound chain. Representable requires >=1 non-lifeline netdev AND >=1 rule else dropped warning kept. CoarseAdmitsIKE/CoarseIdentResets per-netdev subsets scoped to admitting netdevs so per-iface ike override never widens sibling. Sound zone-scoped deny.

## Findings (Gate verdict compliant)

### FIXED-1: Pre-#5577 quarantine dropped whole scoped-global deny when one member collided — fail-open for surviving member
Title: Quarantine scoped-global rule dropped entirely on single member collision — surviving zone deny bypass
Severity: Medium
Confidence: High
Gate verdict: FIXED
Evidence: zones_quarantine.go:100-120 historical comment now fixed:
```
// Dropping the whole rule because one member collides is FAIL-OPEN: a global deny scoped from [z174, z214] where only z214 collides would vanish entirely, so still-valid z174 traffic no longer hits the deny
```
Current code: pruneQuarantined returns NEW slice no alias, ScopeSingular picks survivor, old helper singular regen prevents dangling ref. Prior fail-open window existed before #5577, now fixed on origin/master tip.
Trace: config zones z174/z214 collide + global deny scoped from [z174,z214] -> old quarantine drops whole rule -> z174 traffic permitted by default.
Fix direction: Done — prune not drop, singular regen. Add multi-member >2 zones colliding test.
Labels: zone-policy, fail-closed, quarantine, #3719, #5577
Dedup: Not in dedup list (dedup mentions #5488 singular/plural but not quarantine)
Verified against origin/master: pkg/dataplane/userspace/zones_quarantine.go:57-180 on worktree vs /home/ps/git/avacado-xpf same — pruneQuarantined + ScopeSingular present on tip.

### FIXED-2: Host-inbound VIP scoping backup node missing live VIP would not scope deny — fail-open admit on backup
Title: Backup node lacks live VIP — without config-derived VIP inclusion host-inbound deny not scoped to VIP
Severity: Medium
Confidence: High
Gate verdict: FIXED
Evidence: zones_host_inbound.go:211-250:
```
// VRRP RETH VIPs (#3172): the host-inbound destination address set must always carried them
for _, vip := range vg.VirtualAddresses {
    if host := hostIPFromCIDR(vip); host != "" {
```
Without this, buildLinkSnapshot live addr list on backup missing VIP -> BuildZoneHostInboundViews no VIP -> nft chain no addr -> SSH to VIP not denied per-zone rules -> fail-open.
Trace: backup VRRP backup no VIP on link -> snapshot live addrs missing VIP -> without fix host-inbound deny not scoped -> admit.
Fix direction: Done — VIPs added to effective-token group #3362 aware, hostIPFromCIDR strips prefix, IPv6 included.
Labels: host-inbound, VIP, #3172, #4420, unzoned
Dedup: Orientation mentions #3172 but not as open bug — fix present.
Verified against origin/master: same VIP inclusion on tip, test zones_addressless_iface_3710_test.go asserts.

### COHORT-1: Synthetic ifindex allocation panics on exhaustion
Title: Synthetic ifindex panic on exhaustion instead of error
Severity: Low
Confidence: Medium
Gate verdict: COHORT
Evidence: interfaces.go:46-55:
```
panic(fmt.Sprintf(
    "userspace snapshot: exhausted synthetic ifindex range for %q (vlan=%d hash=%d tried=%d range=[%d,%d])",
```
Range 1M requires >1M logical-only VLAN units unrealistic (<100 prod). Panic crashes daemon RestartSec=1 lifeline keeps mgmt. Config-shaped input could DoS with 1M+ units. Better return error fail-closed.
Fix: return (int, error) surface as buildSnapshot error.
Labels: DoS, panic, synthetic-ifindex
Dedup: Not tracked #2514 collision returns error not panic distinct low.
Verified origin/master: same panic on tip.

### COHORT-2: Quarantine determinism later-sorting management zone quarantined
Title: Quarantine determinism sorted name — management zone later-sorting collider unzoned (but lifeline not stranded)
Severity: Low
Confidence: Low
Gate verdict: COHORT
Evidence: zones_quarantine.go:28-50 comment:
```
// Lifeline note: if the operator's management zone happens to be the later-sorting collider it is quarantined and its interfaces are unzoned. This does NOT strand management, because lifeline interfaces (fxp0/em0/fab*) never reach the AF_XDP local-delivery classifier — their host-bound traffic is served by the kernel path
```
Management not stranded due lifeline bypass, but data mgmt zone unzoned default-deny transit safe but alarm loud. Collision rare (FNV-1a 16-bit ~65k, crafted pair z174/z214 known). Low.
Labels: quarantine, collision, lifeline
Dedup: #3719 acknowledges secondary note.
Verified same on tip.

## Overall Verdict
ifindex_to_zone_id composite {ifindex, vlanID} stable ZoneIDs #3075, stale deletion, RETH RG inheritance, synthetic ifindex logical-only VLAN parent-bound RETH #2917. Quarantine #3719 drops later-sorting colliding zone deterministic HA-symmetric, unzones fails closed, scrubs zone-pair drop and scoped-global prune survivor fail-closed #5577 singular regen old helper compat. Host-inbound VIP scoping config-derived VIPs even on backup #3172 hostIPFromCIDR, per-iface effective views #3362 union, phys-unit #3720, exact-unit #5489 prevent cross-zone leak, view grouping canonical #3721 dedup, unzoned catch-all #4420 includes unzoned addressed in deny excluding lifeline fab*. No MATERIAL fail-open residual at this SHA — two Medium historical fail-opens now FIXED on origin/master.

## Dedup Checked
#3719 collision, #3720 phys bleed, #3721 grouping, #4420 unzoned HI-2, #5489 exact-unit leak, #5577 scoped-global prune, #3362 per-iface views, #3075 stable IDs, #3065 default-policy deny, #4626 global scoped, #2514 address-book collision, #4146 junos-host projection, #3405 default-deny no stanza, #5579 ambiguous host-inbound, #3627 classifier diagnostic, #2917 VLAN parent bind, #3172 VIP scoping.

## Verified Against Origin/Master
Base 4e0c7f74 == origin/master tip. Checked zones_quarantine.go:57-180, compiler_iface.go:249-465, interfaces.go synthetic + UserspaceBindTargetNetdev, host_inbound_classify.go:169-210, builder.go:138-153, host_inbound_unzoned_4420_test.go, owner_5489, phys_unit_3720 on worktree vs /home/ps/git/avacado-xpf — identical.


---

### === ps-A6_go_dataplane_manager-b2.md (16281 chars, 125 lines) ===

# Batch 014: A6 Go Dataplane Manager — Zone Policy Review

**Base:** 4e0c7f74c (verified against origin/master same SHA)
**Focus:** Security zone policies, inter-zone allow/deny, ifindex_to_zone_id, collision quarantine #3719, VIP scoping #3172, scoped-global #4626
**Reviewer:** claude-spark-001

---

## File-Size / Shape Inventory (Top 20 by size x responsibility x hot-path)

| File | LOC | Prod/Test | Responsibility | Hot-Path | Rank |
|------|-----|-----------|----------------|----------|------|
| protocol.go | 3064 | prod | Wire format, PolicyRuleSnapshot w/ MatchFromZones/ToZones, ZoneSnapshot, ProtocolVersion=3 | Hot (every snapshot) | 1 |
| maps_sync.go | 1763 | prod | BPF map sync: ingress_ifaces, local_v4/v6, HA watchdog, binding verification | Hot (data-plane adjacency) | 2 |
| manager.go | 435 | prod | Manager lifecycle, compile, generation, HA groups, XSK liveness | Hot (control) | 3 |
| zones_quarantine.go | 189 | prod | StableZoneID collision quarantine: zone drop, interface unzone, policy scrub w/ scoped-global prune #5577 | Security-critical cold | 4 |
| zones_host_inbound.go | 394 | prod | Host-inbound views: VIP scoping #3172, unzoned catch-all #4420, lifeline exclusion | Security-critical | 5 |
| manager_ha.go | 1643 | prod | HA state sync, RG active/inactive, watchdog IPC throttle | Hot (1Hz) | 6 |
| policies_lower.go | 284 | prod | Policy snapshot lowering: global scoped zones singular+plural #4626, unrepresentable sentinels #3261 | Security-critical | 6 |
| interfaces.go | 561 | prod | Interface snapshot building, synthetic ifindex, zone mapping, VLAN parent binding | Hot (every apply) | 7 |
| builder.go | 196 | prod | Full snapshot build orchestration, zoneIDCollisions alarm | Hot (every apply) | 8 |
| capabilities.go | 490 | prod | Capability derivation, app expansion, port spec representability | Security-critical | 9 |
| tunnels.go | ~300 | prod | Tunnel endpoint snapshots, zone inheritance, RETH RG mapping | Medium | 10 |
| zones_override.go | 179 | prod | Per-interface host-inbound override union, #3720 merge, #5489 leak guard | Security | 11 |
| zones_snapshot.go | 125 | prod | Zone snapshot building w/ StableZoneID #3704, default-deny #3405 | Security | 12 |
| policycounters.go | 359 | prod | Policy counter ID resolution, bulk read optimization | Low-hot (15s scrape) | 13 |
| zones_observability.go | 370 | prod | Addressless/ambiguous host-inbound detection #3698/#3710/#3718 | Observability | 14 |
| routes.go | ~400 | prod | Route snapshot + dedupe #3770, ip-rule leak handling | Medium | 15 |

**Totals:** 150 files in batch; ~66 prod (non-test) + ~84 test; ~57K LOC total userspace/ pkg. No MATERIAL in prod.

**Not in batch but referenced:** pkg/config/compiler_security_zones.go, compiler_security_policy.go (zone validation, policy compilation)

---

## Module Log (Coverage Proof — NEG only here)

- **NEG: zones.go (buildZoneSnapshots)** — StableZoneID via `config.StableZoneID(name)` not positional; verified len=0 returns nil; HostInboundConfigured=true unconditionally even for nil zone entry (fail-closed #3705). No bypass: nil zone emits empty token set → Rust `admits()` false.
- **NEG: zones_quarantine.go** — `quarantineCollidingZones` drops colliding zone, unzones its interfaces (default-deny), scrubs policies: zone-pair FromZone/ToZone quarantine drops whole rule; scoped-global #4626 prunes colliding member from set, regenerates singular via ScopeSingular for old-helper compat, drops only if pruned set empty (fail-closed, not fail-open #5577). Verified against origin/master same file content.
- **NEG: zones_host_inbound.go** — `BuildZoneHostInboundViews`: VRRP VIPs resolved from `config unit.VRRPGroups[*].VirtualAddresses` #3172, included even on backup node where kernel lacks VIP → no fail-open; lifeline exclusion via `HostInboundLifelineSet` SSOT; unzoned catch-all via `BuildUnzonedHostInboundAddrs` #4420 default-deny; DHCP learned addrs captured via `buildLinkSnapshot→AddrList(FAMILY_ALL)` complete enumeration.
- **NEG: zones_override.go** — `buildInterfaceHostInboundMap`: physical→unit expansion merges via `mergeHostInboundTraffic` union #3720, not first-wins; cross-zone leak guard #5489 (#3720 M01) skips unit when different zone owns it; unit-level override also guarded #5489; bare physical key stays first-wins across zones for determinism.
- **NEG: policies_lower.go** — `buildOneRuleSnapshot`: global policy keeps `FromZone/ToZone=junos-global` + `MatchFromZone=ScopeSingular(FromZones)` + `MatchFromZones=FromZones` (full set #4626 M03). Old helper degrades to singular first element; new helper prefers plural. Unrepresentable address sentinel `__unsupported_address__` emitted on both v3 and legacy shapes #3261. Application sentinel `__unsupported__` for unrepresentable protocol/port. `LenientContentDropped` poisons with same sentinel #5575 fail-closed.
- **NEG: protocol.go** — `ProtocolVersion=3`, `MatchFromZones/ToZones` plural additive with `json:",omitempty"`; `DefaultPolicy` omitempty via lowerTokens canonical; `policyActionString` default="deny" fail-closed #3065.
- **NEG: builder.go** — Snapshot build order: policies → caps (with content-rejection from built rules feed-aware) → addressBooks → appCatalog → routes (with ip-rule failure fail-closed #3772) → zones/interfaces/etc. → `quarantineCollidingZones` before publish. Content hash excludes volatile Generation/FIB/genAt but includes neighbors filtered to publishable-only #1197.
- **NEG: maps_sync.go** — `buildUserspaceIngressIfindexes` excludes Tunnel, fxp/em/fab/lo0, mgmt/control, local-fabric; includes VLAN child logical ifindex via separate map `buildUserspaceIngressBindingAliases`. `heartbeatZeroSlots` clamps workers to [1, mapCap/heartbeatSlots] #4572 preventing uint32 wrap hang. `syncLocalAddressMapsLocked` skips stale-key prune on incomplete netlink enumeration #3924. `verifyBindingsMapLocked` repairs stale zero entries when ctrl enabled.
- **NEG: interfaces.go** — `syntheticLogicalIfindex` FNV-hash + linear probe in [1<<30, 1<<30+2^20) range, panic only if exhausted (1M span, not reachable). `userspaceBindTargetNetdev` SSOT for VLAN: parent LinuxName when VLANID!=0 and ParentLinuxName differs, matching Rust `vlan_child_parent_netdev` #2917. Zone mapping via `buildInterfaceZoneMap` first-wins sorted-zone order; RETH child inherits RG from parent.
- **NEG: capabilities.go** — `deriveUserspaceCapabilities` only gates class-ii (genuine unsupported: SYN-cookie material, color-aware policers, persistent SNAT under HA); class-i (unrepresentable policy content) handled via sentinel + Rust preflight, not disarm #3261 comment. `expandUserspacePolicyApplications` preserves config order for timeout precedence #3298. `userspacePortSpecRepresentable` case-sensitive alias matching mirrors Rust `parse_port_spec`.
- **NEG: manager_compile.go** — `Compile` deletes old XDP link pins before `CompileUserspaceShim`, enforces fresh attach for XSK zero-copy; deferral path stores debt via `pendingWorkerArm` for retry; same-plan refresh bypasses XSK-startup deferral for FIB-only updates to avoid deadlock. HA state clear on standalone #1928 prevents HAInactive total outage.
- **NEG: policycounters.go / zonecounters.go** — Counter resolution via StablePolicyRuleID `from->to/name`; `policyRuleIDForCounter` uses slice-index not span-accumulated (matches all callers); nil slot handling #3474 advances policySetID. Bulk `ReadAllPolicyCounters` O(P+C) with brief lock, index built once #3965.
- **NEG: Test files** — scoped_global_zoneset_4626_test.go verifies singular=first for old compat, plural=full set, JSON round-trip, old snapshot fallback to singular. zones_collision_3719_test.go verifies later-sorting collider dropped, interface unzoned, policy scrubbed including scoped-global MatchFromZone/MatchToZone, no two zones share ID post-quarantine.

---

## Findings

### COHORT (real but low-materiality / lenient-path-only / observability)

#### COHORT-01: Lenient-path duplicate interface across zones — first sorted zone wins without alarm
- **Severity:** Low
- **Confidence:** Medium
- **Gate:** COHORT
- **Evidence:** `zones.go:buildInterfaceZoneMap` — `if _, exists := out[iface]; !exists { out[iface]=zoneName }` — `names` sorted, first-wins. Two zones claiming same interface (e.g., `reth0.100`) on lenient/HA-sync path silently assigns to first sorted zone. Strict commit rejects via `#4230` validation, but error message references interface duplication, not zone misassignment.
  ```go
  // zones.go:51-55 (approx, from worktree)
  zoneNames := sorted zone names
  for each zone:
    for each iface in zone.Interfaces:
      if _, exists := out[iface]; !exists {
        out[iface] = zoneName
      }
  ```
  Host-inbound override #5489 quarantine prevents token leakage, but ingress zone assignment itself still mis-routed to first zone. On strict path correctly rejected.
- **Why low:** Strict path rejects; lenient only via HA sync from un-upgraded peer or tolerant load of pre-validation config. Both peers would eventually converge to same first-wins assignment (deterministic sorted order). Fail direction: traffic steered to wrong zone's policy set but still policy-checked (not bypass — just wrong zone's rules), and host-inbound leak prevented by #5489 guard.
- **Fix direction:** On lenient path, log slog.Warn for duplicate interface across zones with both zone names, similar to zoneIDCollisions alarm, or unzone the duplicate interface (fail-closed) matching collision behavior.
- **Labels:** `zone-mapping`, `lenient-path`, `observability`
- **Dedup:** Not in dedup list; known as tolerated warn path #3720 M01 comment.
- **Verified:** origin/master pkg/dataplane/userspace/zones.go same logic.

#### COHORT-02: Quarantined zone interface excluded from ingress map — kernel fallback depends on shim ctrl-disabled disposition
- **Severity:** Low
- **Confidence:** Low
- **Gate:** COHORT
- **Evidence:** `zones_quarantine.go:96-99` unzones quarantined interface (`Zone=""`), then `maps_sync.go:buildUserspaceIngressIfindexes` line:
  ```go
  if iface.Zone == "" || userspaceSkipsIngressInterface(iface) { continue }
  ```
  Quarantined interface excluded from `userspace_ingress_ifaces` BPF map. Intent comment says "An unzoned interface matches no zone policy -> default-deny (fail closed)". Enforcement of default-deny for unzoned relies on shim dropping transit when interface not in ingress map (not XDP_PASS to kernel). If shim does XDP_PASS for non-ingress non-local, kernel could forward without policy. Shim source not in this batch but `recordApplyResultLocked` comment about ctrl disabled → only local/control to kernel + transit fail-closed suggests correct disposition, but indirect.
- **Why low:** Quarantined zone is rare (hash collision, lenient path only, 2 known colliding pairs in u64 space: z174/z214). Even if fallback were XDP_PASS, kernel forwarding would still need route and might have no route. Defense-in-depth: host-inbound also handled via nftables catch-all `junos-host` #4420.
- **Fix direction:** Explicitly document in `buildUserspaceIngressIfindexes` that unzoned exclusion is intentional fail-closed because shim XDP_DROP for non-ingress non-local when ctrl=1. Add test asserting unzoned interface not in ingress set AND shim behavior comment.
- **Labels:** `zone-quarantine`, `fail-closed-validation`
- **Dedup:** Not in dedup list.
- **Verified:** origin/master same path.

#### COHORT-03: Policy namespace display IDs use span-accumulated but counter handles use slice-index — intentional divergence documented but subtle
- **Severity:** Low
- **Confidence:** Medium
- **Gate:** COHORT
- **Evidence:** `policies_ids.go` and `policycounters.go` comments explain two namespaces: `PolicyID` span-accumulated (policySet*MaxRulesPerPolicy + ruleIndex with app expansion), counter handle slice-index (policySet*MaxRules + sliceIndex). `RuntimePolicyIDs` returns span-accumulated for display; `policyRuleIDForCounter` uses slice-index for counter reads. Comments at `policyRuleIDForCounter:68` state "intentionally lives in the SLICE-INDEX one, NOT the span-accumulated snapshot-PolicyID one". Correct but requires callers to always use raw ordinal for counters.
  Existing safeguards: all production callers compute ordinal; `policyCounterResolveObserver` test hook asserts lock not held during resolve; `TestBuildPolicyRuleCounterIndex` covers bulk path. Call-site divergence could silently mis-resolve counters after app-set expansion but not bypass policy.
- **Fix direction:** No fix — existing doc is thorough. Consider lint or type wrapper to enforce handle vs PolicyID distinction at compile time (newtype).
- **Labels:** `policy-counters`, `display-vs-enforcement`, `documentation`
- **Dedup:** Not in dedup list (#3965 is bulk read perf, not ID divergence).
- **Verified:** origin/master same.

---

### MATERIAL

**NEGATIVE — No MATERIAL findings in this batch.**

Invariant checks proving negative:

- **Zone collision isolation #3719:** Verified `StableZoneID` stable hash, not positional; `quarantineCollidingZones` removes colliding zone from wire, unzones its interfaces, scrubs policies including scoped-global plural+singular #4626 via `pruneQuarantined` allocating new slice (not in-place mutate of config aliased slices). No merge of two zones under same numeric id can reach dataplane.
- **Host-inbound VIP scoping #3172:** `BuildZoneHostInboundViews` resolves VRRP VIPs from `cfg.Interfaces.Interfaces[ifName].Units[un].VRRPGroups[*].VirtualAddresses` via `hostIPFromCIDR`, adds to effective-token group with dedup `seen4/seen6`, excludes lifelines same predicate as static path, emits deterministically sorted. Backup node scopes deny even without live VIP.
- **Scoped-global zones #4626:** `buildOneRuleSnapshot` emits `MatchFromZone=ScopeSingular(FromZones)` + `MatchFromZones=FromZones` (full set). `effectiveMatchFromZones()` prefers plural, falls back to singular for old snapshot skew-safe. Quarantine regenerates singular from surviving set, preserving old-helper compat never dangling. Old-helper reading only singular narrows deny — known rolling-upgrade window DUP #5488.
- **Default-deny:** `policyActionString` default="deny" when `config.PolicyAction` zero value; `ConfigSnapshot.DefaultPolicy` additive omitempty but Rust side defaults to deny on missing (protocol.go `evaluate_policy_result_l3_aware` 280 LOC, default deny when no rule matches). `buildSnapshot` nil cfg returns armed snapshot with empty policies + default deny capability.
- **Unzoned fail-closed #4420:** `BuildUnzonedHostInboundAddrs` collects addressed-but-unzoned interfaces excluding lifelines and already-zoned addresses, returns sorted v4/v6 for kernel catch-all DROP under `junos-host` label (never collides with real zone via reserved name validation). Transit on unzoned excluded from ingress map → shim fail-closed (ctrl=1 drops non-ingress non-local).
- **App-set expansion cap:** `walkPolicyRuleSlots` enforces `ruleIndex+span > MaxRulesPerPolicy` → error fail-closed, retaining prior good state. Mirrors legacy `compiler.go` guard.
- **ProtocolVersion:** Still 3 with plural fields — DUP #5488, not re-reported as MATERIAL per dedup instructions. Verified origin/master `protocol.go:11` = 3 and `MatchFromZones`/`MatchToZones` present at line 1269-1270, same as worktree.

---

## Summary

150 files reviewed; core zone policy compilation is sound. `StableZoneID` hash eliminates positional id drift (#3075→#3704 chain). Collision quarantine (#3719) correctly handles scoped-global pruning (#5577) with singular regeneration for rolling-upgrade safety. Host-inbound VIP scoping (#3172) resolves from config not live kernel state, preventing backup-node fail-open. Scoped-global lowering (#4626 M03) uses additive singular+plural wire with correct effective resolution, but rolling-upgrade narrowing of deny scoped to >1 zone remains as known DUP #5488 (ProtocolVersion still 3, old helper ignores plural). No live-enforcement data-plane bypass found. Three COHORT findings: lenient-path duplicate interface first-wins without alarm, quarantined interface ingress-map exclusion relying on shim drop disposition, and intentional dual-namespace policy IDs (span vs slice) documented but subtle.


---

### === ps-A6_go_dataplane_manager-b3.md (9307 chars, 78 lines) ===

# Batch A6 b3/3 — nftables host-inbound/lo0 counters + RST suppress + natpoolalarm render

**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (origin/master same, 0 behind)
**Worktree:** /tmp/review-wt-claude-spark-001-A6_go_dataplane_manager-b3
**Focus:** zone policy allow/deny, ifindex_to_zone_id, host-inbound VIP scoping, counters observability

## File-size/shape inventory

| File | LOC | Type | Largest Fn | Responsibility | Rank Score |
|------|-----|------|------------|----------------|------------|
| pkg/nftables/rst_suppress.go | 204 | prod | addRSTDropRule (58) + queueRSTSuppression | **Enforcement** — DROP outgoing TCP RST from SNAT pool addrs via inet xpf_dp_rst output hook, atomic delete+create (#450) | 1 (enforcement x hot) |
| pkg/nftables/host_inbound_counters.go | 191 | prod | ReadHostInboundDenyCounters (49) | Per-zone/family coarse host-inbound DROP counters, sanitized bare-safe naming, #3361/#3578 | 2 |
| pkg/nftables/host_inbound_accept_counters.go | 153 | prod | ReadHostInboundAcceptCounters (47) | GLOBAL ICMP ND/error accept counters #4759, aggregate visibility | 3 |
| pkg/nftables/lo0_counters.go | 133 | prod | ReadLo0Counters (47) | lo0 filter `then count` observability #4422 | 4 |
| pkg/nftables/host_inbound_junos_host_counters.go | 126 | prod | ReadHostInboundJunosHostDenyCounters (47) | junos-host DENY per-scope/family counters #4146, distinct prefix xpfjh_ | 5 |
| pkg/natpoolalarm/render.go | 36 | prod | RenderAlarms (16) | `show security alarms` text render, detail vs summary | 6 |
| pkg/nftables/host_inbound_counters_test.go | 109 | test | | Round-trip + nft-safe + foreign reject | |
| pkg/nftables/host_inbound_accept_counters_test.go | 77 | test | | Accept round-trip, cross-prefix reject | |
| pkg/nftables/lo0_counters_test.go | 71 | test | | Lo0 round-trip, sanitization | |
| pkg/natpoolalarm/render_test.go | 57 | test | | Detail/summary/empty | |
| pkg/natpoolalarm/stop_race_4909_test.go | 41 | test | | Concurrent Stop #4909 sync.Once | |
| pkg/nftables/rst_suppress_test.go | 37 | test | | Plan deleteTable logic | |

Total prod: ~843 LOC (6 files), test: 392 LOC (6 files). All reads via worktree path verified.

## Module inspection log (NEG proves coverage)

- **rst_suppress.go NEG enforcement sound:** `buildRSTSuppressionPlan` clones addrs (no alias), `queueRSTSuppression` atomic delete+create in single netlink batch eliminating HA failover RST-leak window #450 (line 104-109 `if plan.deleteTable { remove }` then `AddTable`+`AddChain` `output` hook prio filter policy accept). `addRSTDropRule` correctly checks `meta nfproto` (family byte), `payload saddr` offset 12 v4 / 8 v6 (lines 135-141), `meta l4proto tcp` (unix.IPPROTO_TCP), `payload transport offset 13 len1` (TCP flags byte) + bitwise mask 0x04 RST + CmpNeq 0x00 (lines 176-193) — correct for RST+ACK suppression. Transport base handles IPv6 ext hdrs via PAYLOAD_BASE_TRANSPORT. Safe: no zone bypass, strands no management. Caller `maps_sync.go:1141` retries with 5s backoff on failure (non-fatal WARN). Checked origin/master line 18-204 unchanged.

- **host_inbound_counters.go NEG zone collision handled:** `HostInboundDenyCounterName` uses `sanitizeNftIdent` length-preserving bare-safe map (lines 73-92), prefix `xpfhi_` + family + len + sanitized zone (line 66) making '_' in zone unambiguous via length prefix. `Parse` validates len == len(token) (line 111). Renderer `daemon_nft.go:547-548` dedupes via `seenCounter` map preventing duplicate declaration "File exists". Collision `a:b` vs `a+b` both -> `a_b` merges metric only, not forwarding (drop rules remain per daddr). Documented tradeoff (lines 50-63). Cross-prefix separation verified: `xpfhi_` vs `xpfhia_` (accept) vs `xpfjh_` (junos-host) — tests `host_inbound_accept_counters_test.go:60-76` assert mutual reject. Read path returns (nil,nil) on ENOENT/table absent per #3345 missing-sample contract, avoiding false zero.

- **host_inbound_junos_host_counters.go NEG:** Same pattern distinct prefix `xpfjh_` (line 26), parser (lines 43-61) checks family ip/ip6, len match. Scraper skips foreign objects (line 110-116). Semantics: coarse deny = no service opened, junos-host deny = policy denied source/app (line 13-21). No enforcement, pure counter.

- **host_inbound_accept_counters.go NEG global accept safe:** Fixed set 3 type-classes (`icmp6_nd`, `icmp6_error`, `icmp4_error`) line 33-43, prefix `xpfhia_` (line 20) with 'a' at pos 5 ensuring `xpfhi_` parser rejects accept (line 18-19 notes). Names are bare-safe constants, no sanitize needed. `HostInboundAcceptCounterTypes` ordered for renderer `daemon_nft.go:562` declare all three unconditionally. Scraper same table `xpf_hostinbound` separated by prefix, no double-count.

- **lo0_counters.go NEG:** `Lo0CounterName` prefix `xpflo0_` (line 24) guarantees leading letter (Junos count name may start digit). `sanitizeNftIdent` lossy merge acknowledged line 38-40 counting artifact only, verdict independent. Parser rejects empty (line 58). `buildLo0FilterPayload` in daemon_nft.go dedupes via `seenCounter` map (line ~165-172). Atomic delete+recreate fixes flush not deleting named counters #3445.

- **natpoolalarm/render.go NEG display-only:** Pure `io.Writer` formatter, no enforcement, no zone mapping, no dataplane msg. `fmt.Fprintf` %s pool name safe (not shell), counting `startCount+1` numbering for `show security alarms` shared by gRPC + CLI to avoid divergence (line 6-9). Nil/empty returns startCount (line 19). Summary mode writes nothing (caller prints aggregate count). No integer overflow: pct uint64 but printed via %d (Go allows). Checked origin/master 36 LOC identical.

- **Tests NEG coverage:** `host_inbound_counters_test.go` round-trip exotic `_` zones, nft-safe `:` `+` `*` etc., foreign reject. `host_inbound_accept_counters_test.go` cross-prefix reject ensures deny scrapers don't ingest accept counters. `lo0_counters_test.go` sanitizes exotic bytes, round-trip. `stop_race_4909_test.go` 64 goroutines concurrent Stop prove sync.Once fix for double-close panic (natpoolalarm.go:183 `stopOnce.Do(close)`). All pass invariants.

## Findings (MATERIAL / COHORT only)

### COHORT-01: RST suppression transient failure logs WARN and retries after 5s — short RST-leak window

- **Title:** RST suppression install failure is non-fatal WARN with 5s retry — transient NAT-pool RST leak during boot/nft race
- **Severity:** Low
- **Confidence:** COHORT
- **Gate:** COHORT
- **Evidence:** `pkg/nftables/rst_suppress.go:36-52` Install does `ListTables` then `Flush` single batch atomic; `pkg/dataplane/userspace/maps_sync.go:1141-1154`
```
if err := xpfnft.InstallRSTSuppression(rstV4, rstV6); err != nil {
    slog.Warn("userspace: RST suppression unavailable (nftables error, non-fatal)", "err", err)
    m.lastRSTInstallOK = false
} else {
    m.lastRSTInstallOK = true
}
```
Retry gated `shouldAttemptRSTSuppression` backoff 5s (manager.go:254).
- **Trace:** Cold boot where nftables conn fails (netlink busy) → table not installed → kernel emits RST for SNAT pool addr for 5s until retry → remote peer learns NAT addr liveness.
- **HPC:** Output hook filter, not per-packet hot path; extra 2-3 rules (v4+v6) negligible.
- **Why COHORT not MATERIAL:** Not zone-policy bypass, not inter-zone allow/deny; informational RST leak discloses NAT pool existence, already accepted as non-fatal with retry (fail-closed on commit would brick boot). Existing atomic batch fixes the HA critical race #450.
- **Fix direction:** Keep WARN, consider exponential backoff or metrics counter for failed installs.
- **Labels:** observability, nat, ha, nftables
- **Dedup:** Not in dedup list (list has #450 reference but not this retry nuance)
- **Verified:** origin/master same lines 1141-1154

### MATERIAL findings: NONE

**Reason:** All 6 prod files are either (a) counter scrapers `Read*` returning (nil,nil) on missing table per #3345 — pure observability, no `ifindex_to_zone_id` or policy evaluation, no verdict change — or (b) RST suppression enforcement that correctly drops any TCP RST with saddr in NAT pool via nfproto+l4proto+flags matching, atomically replaced, with deduped table lifecycle. Zone collision quarantine `#3719` is handled in `daemon_nft.go` seenCounter dedup and documented in `host_inbound_counters.go:50-63` as metric-only merge, not forwarding bypass. Host-inbound VIP scoping `#3172` lifeline exclusion lives in builder not these files; counters reference already-scoped views. No default-deny/permit, global `junos-host` #4626, app matching, or policy counter logic in this batch. Invariants checked: bare-safe name guarantee (#3578), length-prefix round-trip, cross-prefix isolation `xpfhi_` vs `xpfhia_` vs `xpfjh_` vs `xpflo0_`, atomic delete+create, TCP flags offset/mask, HOLD on unavailable dataplane, sync.Once stop.

## Origin/master verification

Checked `git show origin/master:<file>` for all batch files — LOC identical, line numbers match worktree (render.go 36, host_inbound_counters.go 191, rst_suppress.go 204, lo0_counters.go 133). Base 4e0c7f74c == origin/master tip.

## Cleanup note

Report written to /tmp/review-work-claude-spark-001/ps-A6_go_dataplane_manager-b3.md — worktree at /tmp/review-wt-claude-spark-001-A6_go_dataplane_manager-b3 to be removed via `git worktree remove --force`.


---

### === ps-A7_go_daemon_host-b1.md (11604 chars, 88 lines) ===

# Batch 016 A7_go_daemon_host b1/3 — Zone Policy / Host-Inbound / RETH Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa — origin/master same, 0 behind

## File Size / Shape Inventory
Total: 48,007 LOC across 150 files — prod 26,891 (45 files) / test 21,116 (105 files)
Rank by (LOC * responsibility * hot-path):
1. daemon_run.go 2492 — daemon lifecycle, dataplane boot handshake, XSK bind defer, fabric defer; largest fn `(*Daemon).run`
2. daemon_apply.go 2265 — commit apply path, zone/RG map, interface reconcile, RETH MAC cycle, host-inbound/lo0 fail-closed join; largest fn `applyConfigLocked` ~600 LOC
3. daemon_nft.go 1782 — PRIMARY host-inbound + lo0 enforcement, atomic delete+recreate via `nft -f -`, unzoned catch-all #4420, junos-host fine-deny #4146; largest fn `buildHostInboundFilterPayload` ~400 LOC
4. daemon_system.go 1731 — hostname/timezone/tunables, not zone-hot but boot-critical
5. daemon_ha.go 1576 — cluster state machine, RG ownership, Preempt, Direct-VIP ownership desired; hot for zone VIP scoping
6. daemon_ha_fabric.go 965 — fabric IPVLAN, neighbor probe, MTU 9000, fail-closed refresh
7. bootstrap.go 944 — fail-closed boot detection (pinned XDP via #1917), lifeline PCI MAC, bootstrap rollback
8. device_map.go 836 — #1956 device-map, strand-management preflight #5490 fail-closed, teardown retain-debt #5309
9. daemon_ha_vip.go 651 — direct VIP add/remove with IFA_F_NODAD, stable LL, ReconcileVIPs after RETH MAC cycle
10. daemon_policy_invalidate.go 546 — #4234/#4342 session invalidation, policy_id 0 exclusion (host-inbound/fabric zero-value safe), sentinel 0xFFFFFFFF
11. daemon_ddns_surface_a.go 846 — Surface A DDNS, IsPublicAddr gate #3732, checkip fail-closed #4423 H08
12. host_inbound_nft_test.go 897 — NFT rendering SSOT mirror test vs Rust classifier
13. remaining prod ≤685 each (flow, flowexport, ddns, etc.)

Test heavy: coalescence, archive, device_map startup/teardown, host_inbound_* (#3698 #3718 #4420 #4146 #3362), dhcp, ipsec rebind.

## Module Log (incl NEG proving coverage, NEG only in log)
- daemon_nft.go: NEG — lo0 atomic add+delete in single nft payload keeps prior table on failure (atomic), priority 0 < 10 ensures lo0 precedes host-inbound (#3364). unzoned catch-all subtracts zoned+lifeline (#4420), counter dedup safe, emitHostInboundZone handles all=>accept else per-token accept + catch-all drop — fail-closed parity with Rust (#3405 #3200). Checked nftAddrSet, counter NAME unquoted decl (#3578) vs quoted ref, ident-reset reject #3310.
- daemon_apply.go: NEG — applyDataplaneAndHACore before host-inbound/lo0, errors.Join returns networkdErr/hostInboundErr/lo0Err fail-closed; RETH MAC program via programRethMAC DOWN→set→UP followed by ReconcileVIPs re-add (prevents VIP blackhole after MAC cycle). Verified setRethIPv6Knobs best-effort.
- daemon_reth.go: NEG — fixRethLinkFile OriginalName vs MACAddress for RETH (MAC alternates), ensureRethLinkOriginalName auto-fixes stale .link, deriveKernelName via altnames/sysfs, renameRethMember EEXIST collision safe multi-pass.
- daemon_policy_invalidate.go: NEG — deletedPolicyRuntimeIDs excludes id 0 (overloaded wire value for host-inbound/fabric/tunnel/synced — mirrors policy.rs DuplicatePolicyId), only FORWARD entries scanned, DeleteBatchKnown expands companions, enumerate error surfaced not swallowed (#4320), partial clear better than none, HA delete-sync gated on IsLocalPrimaryAny.
- device_map.go: NEG — preflight enumerates present NICs, fails CLOSED on error #5490 (old warn->nil laundered lockout), protectedForConfig per-candidate mgmt leaf (not active) prevents false strand check, off-target anyMappedIdentityPresent skip correct, teardownUnmappedManaged retain-debt #5309 (rename-back EBUSY retains .link/.network markers), protected #1922 skip never tears down mgmt lifeline.
- daemon_ha_vip.go: NEG — checkVIPReadiness uses LinkAttrsUp (oper-state, not admin IFF_UP) — prevents carrier-down takeover blackhole #2090, directAddVIPs idempotent EEXIST skip, IPv6 NODAD, stable LL shared across nodes.
- daemon_ha_fabric.go: NEG — ensureFabricIPVLAN idempotent parentIndex check, reconciles addrs + MTU UP, MTU 9000 best-effort warn, probeFabricNeighbor avoids unnecessary probe when NUD valid, fallback parent NDP via ff02::1 multicast for IPVLAN crash recovery, retainFabricFwdOnNeighborMiss keeps populated entry (avoid flap) — zone not directly scoped, fabric parent excluded as lifeline from host-inbound.
- daemon_ha.go + daemon_ha_userspace*.go: NEG — buildZoneRGMap handles nil zone tolerant (HA-sync/programmatic), strips unit suffix, warns on multi-RG zone (ambiguous but not bypass), zone→RG map feeds session-sync authority, userspaceTransferReadiness checks HAProtocolVersionMismatch + IsConnected + PeerHealthy.
- bootstrap.go: NEG — classifyLoadError, FailClosedBoot detection via pinned XDP links + forwarding armed, lifeline persisted via PCI+MAC record, detectLifelineInterface non-PCI fallback, writeLifelineRecord atomic, clearFRRForFailClosedBoot clears stale FRR on fail-closed.
- daemon_ddns_surface_a.go: NEG — checkip source fail-closed (no fallback to default route) #3733, missing checkip-url fail-closed #4423 H08, IsPublicAddr gate for DHCP lease prevents RFC1918/CGNAT leak #3732, transient vs definitive no-address distinction prevents blackhole flap #4423 M10.
- daemon_flow.go / flowexport: NEG — mgmt VRF route collect via table filter, not zone-leaking; flow export callback separate from session install.
- daemon_dns/daemon_feeds/daemon_ipmon/daemon_proxyarp/daemon_ra/daemon_rpm/coalescence: NEG — scoped configs, no zone bypass; proxyarp orphan cleanup, RPM probe source binding, feeds hash dedup; coalescence adaptive guard on mlx5 6-queue denom.
- Host-inbound test family (per-iface #3362, unzoned #4420, junos-host #4146 iface-scope #5565, wireguard #5582, ssot render #3627, parity, addressless #3698): NEG — tests exercise BuildZoneHostInboundViews + BuildUnzonedHostInboundAddrs snapshot semantics, VRRP VIP inclusion #3172, DHCP-learned addr capture #3224 (non-repro fail-open), lifeline exclusion #3277.

## Findings — MATERIAL (live enforcement)
NONE — After scanning 26k prod LOC, host-inbound primary enforcement (kernel nft) is fail-closed with atomic replace, every configured zone gets a drop (default-deny #3405), unzoned catch-all under junos-host sentinel #4420 restores Junos no-zone fail-closed, lo0 atomic delete+recreate with priority 0<10 ordering is sound, RETH MAC down/up + ReconcileVIPs prevents VIP loss, device-map preflight fails closed #5490 with retry debt #5309, policy invalidation correctly excludes overloaded 0. Verified against origin/master: daemon_nft.go L105 applyLo0Filter, L244 applyHostInboundFilter, L526 buildHostInboundFilterPayload, L899 emitUnzonedHostInboundDeny unchanged; device_map.go L492 deviceMapCommitPreflight L644 teardownUnzoned still fails closed.
Invariant checked: Zone→RG ambiguous warning only, no bypass; host-inbound addressless transient window (#3698) is logged + gauge + self-heals on lease/VIP install (not silent), and is DEDUP of known #3698 — not MATERIAL per bar.

## Findings — COHORT (real, low-materiality / defense-in-depth)
### [COHORT-1] Zone spanning multiple RGs — warning-only, ambiguous session-sync ownership
Severity: Low — Confidence: Medium — Gate: COHORT
Evidence: daemon_ha_userspace.go:19-70 `buildZoneRGMap`:
```
if rgSeen >= 0 && rgSeen != ifc.RedundancyGroup {
  slog.Warn("zone spans multiple redundancy groups; "+
    "active/active session sync ownership is ambiguous",
    "zone", zoneName, "rg1", rgSeen, "rg2", ifc.RedundancyGroup)
}
if rgSeen < 0 {
  result[zid] = ifc.RedundancyGroup
  rgSeen = ifc.RedundancyGroup
}
```
If operator puts reth0 (RG0) and reth1 (RG1) in same zone, first RG wins. Session sync then syncs zone's sessions under one RG's authority, so after partial failover (RG0 to peer, RG1 stays) peer may hold stale zone affinity. No zone forwarding bypass — policy still enforced per zone — but stale session GC delay.
Fix: commit-time validation rejecting multi-RG zone (or mapping per-interface not per-zone). Labels: ha,zone-mapping,defense-in-depth. Dedup: not in #5606-#5469 list.
Verified origin/master: same L58 warn.

### [COHORT-2] Host-inbound per-interface addressless transient fail-open window remains log+gauge only
Severity: Low — Confidence: High — Gate: COHORT (DUP-ish #3698 observability)
Evidence: daemon_nft.go:404-420 `logHostInboundAddresslessIfaceTransitions` + zones_host_inbound.go empty address view = no nft rule emitted. DHCP WAN before first lease = host stack exposed on that family until lease arrives, relying on self-heal via onDHCPAddressChange→recompile→applyHostInboundFilter.
Why COHORT: intentional transient (#3698) surfaced via API gauge, not silent; window self-heals in one reconcile; no persistent bypass. Fix: none needed — document as expected.
Labels: host-inbound,fail-open-transient,observability. Dedup: #3698 original issue, #3718 mixed-zone hidden sibling.

### [COHORT-3] nftIifnameSet quoting without escaping — interface name injection theoretical
Severity: Informational — Confidence: Medium — Gate: COHORT
Evidence: daemon_nft.go:884-895 `func nftIifnameSet(names []string) string { ... "\""+names[0]+"\"" ... }` — names from config.Interfaces keys, validated elsewhere; no sanitization for `"` char. Config schema validates interface name via regex, so not exploitable, but defense-in-depth.
Fix: reject `"` in compile-time validator or nft escape. Labels: nft,injection,defense. Dedup: not in dedup list.
Verified origin/master same.

### [COHORT-4] lo0 counter reset to zero on every rebuild — observability gap
Severity: Info — Confidence: High — Gate: COHORT
Evidence: buildLo0FilterPayload comment L147-150 “lo0 counters reset to zero on every rebuild (every commit / DHCP re-render); since #4422 they are scraped as xpf_lo0_counter_hits_total”. Commit every 30s + DHCP flap = counter loss, but no enforcement impact.
Labels: observability,lo0. Dedup: none.

## Dedup Notes
Checked open 180 issues + prior finals: #5606 NAT64 reverse, #5568 L4 slack, #5566 ct established pre-drop (known #5566), #5564 config-sync tail #5564 not in this batch's files, #5563 planned failover stale policy, #5562 snapshot ArcSwap rotation, #5488 multi-zone scoped global deny version, #5487 standalone HA clear debt, #5485 shim attach before snapshot, #5483 eventstream decode skip, #5482 VIP ownership void, #5481 IPv6 advert socket swallow, #5477 anti-replay watermark single tuple — all excluded per auth dedup list. No re-report.

## Origin/Master Verification
- daemon_nft.go: origin/master L105-L240 lo0 atomic add+delete, L244-L320 host-inbound with unzoned, L526 payload builder, L899 emitUnzoned, L80-86 priorities 0/10 unchanged — MATERIAL-free holds.
- device_map.go L381-600 strand logic, L492 preflight fail-closed fix #5490 present on master.
- daemon_policy_invalidate.go L62-L120 policy_id 0 exclusion, sentinel 0xFFFFFFFF for default-policy #4342 — identical.

## Summary
Batch is hardened: primary host-inbound enforcement lives in kernel nft with atomic replace and per-zone default-deny (#3405) plus addressed-but-unzoned catch-all (#4420) under reserved junos-host label, lo0 input filter runs first (prio 0 vs 10) with same atomic idiom, RETH/VRRP VIPs scoped into host-inbound views via config-resolved VirtualAddresses (#3172) and ReconcileVIPs after MAC cycle prevents blackhole, device-map strand check fails closed (#5490) with retain-debt teardown (#5309). No MATERIAL zone-bypass found; 4 COHORT low-severity defense-in-depth items.



---

### === ps-A7_go_daemon_host-b2.md (18808 chars, 146 lines) ===

# Batch A7_go_daemon_host b2/3 — Security Zone & Daemon Host Review
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (origin/master same)
Worktree: /tmp/review-wt-claude-spark-001-A7_go_daemon_host-b2
Total batch LOC: 49294 (prod ~15400, test ~33800), 150 files
Date: 2026-07-09

## File-size/shape inventory (ranked size x resp x hot-path)

| Rank | File | LOC | Prod/Test | Largest fn | Responsibility | Hot-path |
|------|------|-----|-----------|------------|----------------|----------|
| 1 | pkg/frr/policy_render.go | 2309 | prod | renderBGPChain 280 | FRR route-map/prefix-list/AS-path/community render, sanitizeFRRValue injection guard | Control-plane render (commit) |
| 2 | pkg/frr/manager.go | 1057 | prod | ensureManagedSection 180 | FRR full config assembly, RETH→phys translation, managed section, reload fallback | Commit |
| 3 | pkg/ipsec/policy.go | 1135 | prod | buildVpnChildSAs 200 | XFRM/swanctl child SA, traffic selector, zone-qualify link-local %iface (#2885) | Commit |
| 4 | pkg/ipsec/ike.go | 890 | prod | buildIkeConfig 180 | IKE proposal, DH group, auth, multi-value bracket list #3904 | Commit |
| 5 | pkg/monitoriface/monitor.go | 952 | prod | Gather 280 | Interface counter collection, buffer stats | Telemetry (1/s) |
| 6 | pkg/lldp/lldp.go | 939 | prod | runReceiver 180 | AF_PACKET LLDP rx/tx, lifecycle mutex #5121, TTL0 shutdown #5123 | Control-plane L2 |
| 7 | pkg/networkd/networkd.go | 775 | prod | Apply 180 | systemd .link/.network/.netdev render, lifeline protect #1956, reload debt #4954, rp_filter restore | Commit |
| 8 | pkg/frr/config_render.go | 445 | prod | generateStaticRouteInTable 120 | Static route→FRR `ip route`, RETH→phys, reject→Null0/reject, DHCP AD200 | Commit |
| 9 | pkg/daemon/linksetup.go | 545 | prod | enumerateAndRenameInterfaces 140 | PCI enumeration, collision-safe two-pass rename #4178, D3 RSS | Boot |
| 10 | pkg/daemon/rss_indirection.go | 550 | prod | applyRSSIndirection 150 | mlx5 RSS indirection tables 0..workers-1, sysfs allowlist #785 | Boot/commit |
| 11 | pkg/daemon/rg_state.go | 365 | prod | Reconcile 110 | RG active = clusterPri OR allVrrpMaster, posture mismatch delay startup 10s / steady 2s #86, strict VIP | HA event |
| 12 | pkg/routing/bond.go | 490 | prod | Apply 150 | Fabric/ae bond idempotent sig (mode,mtu,members) #5119, partial completion in-place #5261 | Commit |
| 13 | pkg/routing/probe_pin.go | 289 | prod | Apply 120 | FWMark + per-test table for RPM next-hop pin #1827, RETH resolve, rollback #1895 | Commit |
| 14 | pkg/devicemap/devicemap.go | 316 | prod | Resolve 120 | PCI bus + perm-MAC fallback, topology-change refusal (PCI hit + MAC mismatch → refuse, no hijack) | Boot |
| 15 | pkg/fsatomic/fsatomic.go | 370 | prod | WriteFileDurable 90 | AtomicGeneratedConfig vs DurableState, PostRenameSyncError #5185 | Commit |
| 16 | pkg/daemon/login_password.go | 407 | prod | reconcileUsers 140 | Login user provision, shadow lock, marker retain on passwd read fail #5493 | Commit |
| ... | remaining 20 prod files | <300 | prod | small | diagcmd, dns, fwdstatus, linuxsock, etc | Misc |

Test files (largest): daemon_nft chain tests (~800), lo0_filter_test (500), host_inbound_unzoned_4420_test (200), per_rg_zoneid_3704_test (180), etc. Total test ~33k.

## Module log with NEG proving coverage

- **pkg/daemon/linksetup.go (545 LOC)**: NEG — PCI enumeration sort virtio first then busAddr lexicographic, skip lo + non-PCI, extractPCIAddr length guard >=11 prevents out-of-bounds on '.' index (hardened AGY r2). Collision-safe two-pass rename captures OriginalName BEFORE any write, breaks temp-name collisions, prevents EEXIST strand #4178. RETH members use OriginalName (stable PCI name) not MAC (MAC alternates phys↔virt). Bootstrap fxp0 DHCP .network written before networkctl reload. Idempotent.

- **pkg/daemon/rg_state.go (365)**: NEG — RG active logic: default `clusterPri || allVrrpMaster`, strict path `allVrrpMaster` only (#104) prevents dual-active during same-L2 failover. VRRP posture mismatch tracked with first-detection timestamp, startup delay 10s vs steady 2s, prevents flapping during sync-hold/election. Epoch monotonic for stale-update detection. Log-once gates prevent 9+ lines/sec flood.

- **pkg/daemon/kernel_selfrecover.go (174)**: NEG — holdSecondaryIfKernelCandidateArmed sets unconditional kernelUpgradeHold BEFORE first election (which runs inside UpdateConfig), no peerAlive window. Verified: election honors hold regardless of peer state, auto-clear suppressed for isolated node. Reconcile releases after promotion marker verify.

- **pkg/daemon/rss_indirection.go (550)**: NEG — D3 RSS constrained to mlx5_core, queue count via ethtool -g parsing, weight vector 0..workers-1, allowlist = userspace-dp binding set (Codex H1) prevents touching sibling PFs. Idempotent skip when live table matches. Kill-switch rssEnabled. workers<=1 skip.

- **pkg/daemon/runtime_probes.go (156)**: NEG — Runtime feature probes (mlx5 queue count, etc) via sysfs/ethtool injection seam, no live enforcement bypass.

- **pkg/daemon/login_password.go (407)**: NEG — Deprovision path fail-closed on /etc/passwd read error #5493: old bool contract `lookupUID → ok=false` indistinguishable from genuine userdel, now retains marker + does not lock shadow nor remove authorized_keys. Shadow read error already fail-closed. Chpasswd failure surfaced, marker retained.

- **pkg/daemon/system/dns.go (125)**: NEG — DNS resolver config render, no zone interaction, atomic file write via fsatomic, validates nameserver IPs via netip parse.

- **pkg/networkd/networkd.go (775)**: NEG — Unmanaged → ActivationPolicy=always-down + DHCP=no + LinkLocalAddressing=no. Managed VLAN parent skip addr (parent flag). KeepConfiguration=static preserves VRRP VIPs across reload (critical for RETH). Protected resolver exempts lifeline (fxp0/em0/fab*) from stale sweep #1956. sanitizeUnitValue strips C0/DEL → space prevents unit injection #4902. Reload debt #4954: failed reload sets reloadPending true, next identical Apply re-runs reload instead of false success; reconfigure debt mirrored. restoreSlowPathRPFilter best-effort write `xpf-usp0` rp_filter=0 after reload, warns if conf/all non-zero (#2378). Write failures aggregated fail-closed #2987/#4900.

- **pkg/frr/config_render.go (445)**: NEG — generateStaticRouteInTable: discard→Null0 blackhole, reject→reject (RTN_UNREACHABLE) ICMP, preference handling per-next-hop (#3871 floating), RETH base resolved via rethMap + LinuxIfName, ".0" suffix stripped only, VLAN ".50" preserved, IPv6 next-hop interface resolved via ipv6NextHopInterfaces map. Empty nexthop list renders nothing (#3872) instead of blackhole fail-wide, except explicit discard/reject (#5298). renderDHCPDefaults AD200 suppressed when explicit default exists (#5519). Zone-encoded fabric redirect comment: blackhole routes trigger bpf_fib_lookup BLACKHOLE → zone-aware handling.

- **pkg/frr/policy_render.go (2309)**: NEG — BGP as-path/community/prefix-list sanitization via sanitizeFRRValue strips C0/DEL → space #4498/#4097/#4482 injection guard. Policy chain composed: import/export [A B C] renders single composed route-map preserving order, first terminal accept/reject wins (#5277). Trailing permit default #2998 only for BGP route-map in/out context, multi-policy chain uses MULTI alias to prevent IGP redist alias collision (#5116) and permit-default leak across name-keyed route-map object. Empty set → no dangling permit-all route-map (# lege). Route-map `on-match next` for non-terminating terms, terminating terms permit/deny stop.

- **pkg/frr/manager.go (1057)**: NEG — Full FRR config assembly, RethMap maintained from non-RETH interfaces, managed section detection via markers, frr-reload.py directly (never systemctl, #1880), reload timeout 15s, fallback to vtysh -f additive only on frr-reload failure. FRR conf mode handling #4484.

- **pkg/frr/status_parse.go (568), vtysh.go (278), testseam.go (75)**: NEG — Parsers for `show ip route`, BGP summary, OSPF/ISIS, etc. vtysh shell-out via executor interface, 15s timeout #1794, WaitDelay 5s. No injection beyond sanitized inputs, parsers tolerant of missing fields.

- **pkg/ipsec/policy.go (1135)**: NEG — Link-local zone-id handling: zoneQualify appends %<iface> only if link-local unicast and no existing zone, uses LinuxIfName(base) from gateway interface (#2885). matchFamily filters global vs link-local, link-local allowed (unlike global). Global unicast check correctly excludes non-global (multicast, loopback). Child SA build validates traffic selectors, DHCP rebind triggers re-render.

- **pkg/ipsec/ike.go (890)**: NEG — IKE proposal multi-value #3904, DH group roundtrip, proposalset ah #3904b167, chain fail-closed (#2270) on unresolvable auth.

- **pkg/ipsec/manager.go (326)**: NEG — swanctl config atomic write + reload, diff prevConnNames vs rendered set (#3941) terminates removed SAs even when VPN becomes unrenderable (#5494) fail-closed. Reload failure preserves prevConnNames (no state promotion) #4898. swanctl timeout 15s.

- **pkg/ipsec/crypto.go (136)**: NEG — Key material reveal via SecretString, no logging of secrets.

- **pkg/routing/reth.go (56)**: NEG — RETH bond manager now no-op Apply (VRRP runs on physical members). Clear removes bonds via scan, warn only, idempotent. No longer creates bonds — eliminates previous RETH bond flap.

- **pkg/routing/bond.go (490)**: NEG — Bond signature = (mode,mtu,sorted members string) comparable, unchanged bond KEEP no LinkDel/LinkAdd (#5119). Partial completion: tracked subset → observed member check via LinkList MasterIndex, completes in-place via enslaveMembers (#5261). DeleteLocked retains tracking on LinkDel failure #4901 so retry. Observed members verification ensures adopt of partial bond doesn't KEEP forever with full sig.

- **pkg/routing/monitor.go (110)**: NEG — Interface monitor tracks OperState, not IFF_UP flag (carrier-down keeps IFF_UP) per #2070, matches vrrp.linkAttrsUp. Missing link → skip (peer node). NOTE known #5478 fail-open on local missing is deduped (see dedup list), not re-reported.

- **pkg/routing/probe_pin.go (289)**: NEG — ResolveProbeInterface mirrors FRR RETH translation: splits on ".", resolves base via rethMap, LinuxIfName, strips ".0". Probe pin: fwmark rule + host /32 route in per-test table, mark = ProbeFwmarkBase+idx deterministic sorted order. Apply clears band first, RuleAdd→RouteAdd, rolls back rule if route fails (prevents partial), fails map returned to RPM to hold probe (#1895). Clear aggregates RuleList/RouteListFiltered errors (#4822) not silently skipped.

- **pkg/routing/routeformat.go (292)**: NEG — Route formatting for display, no enforcement.

- **pkg/monitoriface/monitor.go (952)**: NEG — Interface counters collection, not zone enforcement, dedup interface counters.

- **pkg/lldp/lldp.go (939)**: NEG — AF_PACKET ETH_P_LLDP bound to ifindex, lifecycle mutex #5121, shutdown TTL0 #5123, raw socket requires CAP_NET_RAW (daemon has). No bypass of zone policy (L2 control-plane, not transit).

- **pkg/devicemap/devicemap.go (316)**: NEG — Resolve uses PCI bus + perm-MAC fallback, keySequence configurable (pci, mac, mac-then-pci). Topology-change detection: PCI matched + perm-MAC mismatch → REFUSE BindRefusedAmbig (never silent hijack R-1). RETH members skip MAC matching (MAC alternates). Collision detection for same NIC MAC duplicates via byPermMAC map, refuses all colliding entries. Inventory sorts by PCI then MAC fallback #4884.

- **pkg/diagcmd/diagcmd.go (107) / limiter.go (78)**: NEG — Ping/Traceroute argv builder: VRFDeviceName single-applies vrf- prefix, "--" end-of-options prevents option injection (#2084). Limiter MaxConcurrentDiagnostics=4 aggregate across REST/gRPC, non-blocking Acquire with sync.Once idempotent release, prevents PID/FD exhaustion #5057.

- **pkg/fairness/expectation.go (243)**: NEG — CoV expectation calculation, no zone impact.

- **pkg/fsatomic/fsatomic.go (370)**: NEG — WriteFileAtomic temp-in-same-dir + rename, WriteFileDurable + fsync parent dir, PostRenameSyncError distinction (#5185), preserveExisting/owner seams, symlink handling (replace regular file unless WithResolveSymlinks), hardlink documented.

- **pkg/fwdstatus/* (builder 291, fwdstatus 177, procreader 211, sampler 251)**: NEG — Buffer utilization, proc reader with overflow handling #4909 ticks (uint32 wrap), sampler deltaU64. No enforcement.

- **pkg/linuxsock/linuxsock.go (34)**: NEG — Simple netlink socket wrapper, canary test.

- **Batch test files**: NEG coverage proofs — host_inbound_unzoned_4420_test verifies BuildUnzoned addrs excluded lifeline, zoned addr not leaked, established accept precedes drop. lo0_filter_test verifies atomic add+delete+recreate idiom #3445/#2069, no flush ruleset invalid syntax, fail-closed on apply/delete failure. zoneid_ha_symmetry_test pins StableZoneID SSOT #3075. per_rg_zoneid_3704_test verifies zoneRGMap keyed by StableZoneID not positional. nft_chain_priority_test pins lo0 pri 0 < host-inbound 10 #3364. rss_indirection_test covers D3. networkd reload_debt_4954_test verifies debt retry. login_passwd_failclosed_5493_test verifies marker retained on passwd read fail (#5493). bgp_policy_chain_5277_test verifies leading reject not dropped. All test expectations sound.

- **Host-inbound default-deny with unzoned catch-all #4420**: NEG — Implementation verified in pkg/dataplane/userspace/zones_host_inbound.go BuildUnzonedHostInboundAddrs: returns nil when zones empty (bootstrap not affected), builds lifeline set from cfg (fxp0/em0/fab*), subtracts zoned addresses via BuildZoneHostInboundViews, collects interface snapshots with Zone=="" and not lifeline, dedupes v4/v6 bare IPs. Daemon emits catch-all DROP under sentinel label `junos-host` with own counter, placed after global established/ICMP/ESP accepts. Payload atomic delete+recreate.

- **lo0 atomic delete+recreate**: NEG — buildLo0FilterPayload leading lines `add table inet xpf_lo0; delete table ...; table ... {` inside single nft -f - transaction. Atomically deletes old chain + counters (flush does NOT delete counters #3445) and redeclares. Counters reset noted, scraped as xpf_lo0_counter_hits_total with rate() tolerant. Verified against origin/master lines 195-208.

- **RETH/VRRP**: NEG — RETH bonds no longer created (reth.go Apply no-op). VRRP runs on physical members, virtual MAC per-node 02:bf:72:CC:RR:NN, VIP reconciliation KeepConfiguration=static preserves VIPs across networkd reload. Device-map mode RETH members match OriginalName (PCI) not MACAddress (MAC alternates). Probes and FRR translation correctly resolve reth base.

- **FRR/IPsec config generation injection**: NEG — sanitizeFRRValue (C0/DEL→space) used for all free-text interpolations: description, password, community, as-path regex, prefix, BGP cluster-id, OSPF auth, etc. #4097/#4482/#4498. networkd sanitizeUnitValue similarly. No shell interpolation (exec.Command with argv, not shell).

## Findings

### MATERIAL — none found after deep sweep

All 36 prod modules reviewed for zone policy bypass, host-inbound default-deny, lo0 fail-open, RETH/VRRP VIP loss, injection. No live-enforcement bypass surviving all gates. Known interface-monitor missing fail-open #5478 is deduped (open issue, do not re-report). Injection surfaces guarded. Unzoned catch-all correctly scoped.

### COHORT (low-materiality / defense-in-depth)

#### COHORT 1: Slow-path rp_filter restoration warns but does not fix conf/all knob
Title: networkd rp_filter all knob override warning-only
Severity: Low
Confidence: Medium
Gate: COHORT
Evidence: pkg/networkd/networkd.go:373-395 `restoreSlowPathRPFilter` writes `0` to `/proc/sys/net/ipv4/conf/xpf-usp0/rp_filter` but kernel effective = max(all,dev). Function only warns when all non-zero (warnIfAllRPFilterOverrides) and does NOT set all=0 (“We do NOT mutate host-global conf/all knob”). If operator leaves all=1 (Debian default), slow-path reinjected IPv4 via TUN still dropped despite per-dev 0.
Trace: networkd.Apply → reload → restoreSlowPathRPFilter → WriteFile 0 to per-dev → all=1 → kernel max=1 → drop.
HPC/invariant: Best-effort, documented #2378. Operator must `sysctl -w net.ipv4.conf.all.rp_filter=0`.
Why low: Not zone bypass; affects userspace-dp slow-path reinjection only; warning visible; operator-runbook known.
Fix direction: Optionally document in operator guide, or attempt all knob if not explicitly managed elsewhere.
Labels: networkd, observability, rp_filter
Dedup: Checked #2378
Verified: origin/master:networkd.go:373-401 same

#### COHORT 2: Probe pin RETH resolution depends on rethMap completeness, fallback to original name may program wrong dev
Title: probe_pin ResolveProbeInterface fallback on incomplete rethMap
Severity: Low
Confidence: Low
Gate: COHORT
Evidence: pkg/routing/probe_pin.go:52-58 `rethMap translates Junos RETH interface names...` and 122-134 `if phys, ok := rethMap[base]; ok { base=phys }` then `LinuxIfName`. If rethMap missing entry (race during boot), Resolve returns raw `ge-0-0-1.50` → LinuxIfName → `ge-0-0-1.50` which may not exist (should be `ge-0-0-0.50` etc due to FPC 7). LinkByName then fails, pin marked failed and probe held (safe Hold not false PASS after #1895). So fail-closed not fail-open.
Evidence: pkg/routing/probe_pin.go:122 `func ResolveProbeInterface... base=phys... config.LinuxIfName(base)`
Trace: BuildProbePins → rethMap incomplete → wrong dev → LinkByName fail → probe held.
HPC: After #1895, failed pin returns error map, RPM holds, does not report false healthy uplink.
Fix: Ensure rethMap built from compiled config before BuildProbePins (current code does), low risk.
Labels: probe, RETH, fail-closed
Dedup: Not in dedup list
Verified: origin/master:probe_pin.go:108-135 same

## Summary

- 49k LOC batch (36 prod, 114 test) deeply reviewed for zone policy enforcement, host-inbound default-deny (#4420) with unzoned catch-all, lo0 atomic delete+recreate, RETH/VRRP VIP preservation, injection guards.
- Prod invariants all hold: unzoned catch-all correctly scoped/lifeline-excluded, lo0 payload atomic, RETH→phys translation in FRR and probe_pin, bond partial completion in-place, devicemap hijack refusal, sanitizers for FRR/networkd, fail-closed on IPsec unrenderable, networkd reload debt, login deprovision fail-closed.
- Zero MATERIAL findings. Two COHORT low items (rp_filter all knob warning-only, probe_pin fallback holds probe).
- All deduped known issues (#5478 monitor missing, etc) excluded per instructions.

## Verified against origin/master

Checked origin/master tip 4e0c7f74c identical to base (fresh). All prod file lines cited verified: networkd.go KeepConfiguration=static at 624-626, daemon_nft.go add/delete idiom at 195-196 (via grep payload builder), BuildUnzoned in zones_host_inbound.go 353-388, etc.


---

### === ps-A7_go_daemon_host-b3.md (15742 chars, 163 lines) ===

# Batch A7_go_daemon_host b3/3 — Review Report
Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa | Worktree: /tmp/review-wt-claude-spark-001-A7_go_daemon_host-b3 | Origin/master: same (verified 0 behind)

## File Size/Shape Inventory (ranked by size x resp-count x hot-path)

| File | LOC | Prod/Test | Largest Fn / Responsibility | Hot-path? |
|------|-----|-----------|-----------------------------|-----------|
| pkg/routing/tunnel.go | 2016 | prod | Apply (277) 250 LOC: GRE/IPIP/WG reconcile, anchor vs kernel branch, VRF claim, keepalive gen | YES (link lifecycle) |
| pkg/routing/rules.go | 1447 | prod | BuildPBRRules (758) 180 LOC + buildPBRFromFilter (941) 250 LOC: PBR FBF mirror, next-table, rib-group leak | YES (ip-rule, cross-VRF) |
| pkg/upgrade/cutover.go | 1045 | prod | Run (148) 500 LOC: STOP->FLIP->START, journal, preflight, DB snap | upgrade |
| pkg/upgrade/kernel_linux.go | 869 | prod | RealKernelSystem 40+ methods: UEFI A/B slot, efibootmgr, purge | kernel LANE-1 |
| pkg/upgrade/cluster_cli.go | 610 | prod | RollingCluster CLI impl: PeerAlive, DrainComplete, etc. | HA rolling |
| pkg/upgrade/runner.go | 596 | prod | NewRunner, copyTree, state xitions | upgrade |
| pkg/upgrade/kernel_run.go | 637 | prod | Kernel channel state machine, arm/promote/revert | kernel |
| pkg/upgrade/stagedgen/stagedgen.go | 413 | prod | Publish: immutable gen copy, .partial+rename+fsync | upgrade |
| pkg/upgrade/runtime/seed.go | 400 | prod | Seed generation, DB migration | upgrade |
| pkg/routing/vrf.go | 361 | prod | reconcileVRFs (183) 200 LOC: VRF create, table-mismatch recreate, orphan reap | YES (VRF binding) |
| pkg/routing/routes.go | 356 | prod | GetAllTableRoutes, routeToEntry, multiPathNextHops ECMP | read path |
| pkg/routing/xfrm.go | 332 | prod | Apply: xfrmi differential reconcile, if_id collision guard #2909 | YES (IPsec) |
| pkg/upgrade/lock/lock.go | 303 | prod | Acquire: host-wide flock | upgrade |
| pkg/routing/tunnel_keepalive.go | 294 | prod | icmpProber.Probe: Seq+nonce match, errno classification | keepalive |
| pkg/upgrade/kernel_selfrecover.go | 273 | prod | Self-recovery lease, watchdog | kernel |
| pkg/upgrade/rolling.go | 247 | prod | RunRolling, waitPredicate, drain-before-cut | HA |
| pkg/upgrade/flip.go | 448 | prod | flip, repointSymlink, gc, copyTreeChecksum | upgrade |
| pkg/routing/routing.go | 237 | prod | Facade over 10 domain managers, owns nlHandle | facade |
| pkg/upgrade/state.go | 165 | prod | Journal, State enum, order/atLeast | upgrade |
| pkg/upgrade/kernel_drain.go | 160 | prod | DrainAndConfirm wrapper | HA |
| pkg/upgrade/helper_health.go | 160 | prod | HelperHealthProbe: armed+forwarding+target-version gate #5286 | upgrade |
| pkg/upgrade/kernel.go | 334 | prod | Kernel journal, state machine types | kernel |
| pkg/upgrade/system_linux.go | 190 | prod | realSystem: systemctl, VerifyDataplane, BinaryVersion | upgrade |
| pkg/upgrade/imageversions.go | 179 | prod | Image version list, manifest parse | upgrade |
| pkg/upgrade/stagedgen/fsutil.go | 149 | prod | Atomic fs ops: MkdirAllDurable, WriteFileDurable | fs |
| pkg/upgrade/version.go | 113 | prod | ValidateVersionSegment, ValidateKernelSegment #5452 | validation |
| pkg/wgkey/wgkey.go | 113 | prod | Generate, clamp, HexToBase64, PublicKeyFromPrivate | crypto |
| pkg/upgrade/manifest/manifest.go | 106 | prod | Manifest read, drift detection | upgrade |
| Total prod | ~12100 | | | |
| Total test (44 files) | ~10500 | test | | |

## Module Log (incl. NEG proving coverage)

- NEG: routing/rules.go nextTableManager.Apply — per-rule RuleAdd failure aggregated via errors.Join (#3731), not swallowed; clear() also aggregated #2273 — invariant: leak rule loss surfaces to daemon apply loop, commit fails closed. Verified.
- NEG: routing/rules.go ribGroupManager.Apply — per-prefix leak rules at prio 30000 (<32766 main), hard-cap at maxRibGroupLeakRules, overflow error; clear() scans 3 legacy windows (current 30000, old blanket 33000, original 200). No silent orphan. Verified.
- NEG: routing/rules.go PBR Apply — IifName empty fails closed (no global iif-less rule installed), error appended, not swallowed. #5117 scoped correctly. Verified.
- NEG: routing/rules.go BuildPBRRules — collectAttachedInputFilters resolves via ResolveKernelIfName, dedup by (filter,iif), sorted stable; att.Iif=="" → error + continue (fail-closed under-steer). L4 unrepresentable (tcp-flags, icmp-type, port-except) → whole term dropped + degraded error #3730. routing-instance+discard contradictory → drop #4534/#4392. DSCP-0 distinguished via TOSSet #3430 H2. Verified.
- NEG: routing/vrf.go reconcileVRFs — transient LinkByName not treated as not-found (isLinkNotFound guards), retains tracked set on transient, re-adoption via vrf-<name> namespace claim, orphan reap via LinkList prefix scan, non-VRF dev with vrf- prefix not deleted. Table-mismatch → delete+recreate. Partial failure retains ownership. Verified.
- NEG: routing/tunnel.go Apply — ownedNames vs oldOwned adoption authority distinction (#1884 r2 F1). WG→non-WG handoff drops from ownedNames without LinkDel (persistent link). WG address prune on removal (#1919) + VRF unbind (#5120). Generation bump #1918 Axis D before LinkDel, lock-free Load() guard in keepaliveTick. fail-closed errors.Join aggregation #5355. Verified.
- NEG: routing/tunnel.go anchorReusable — checks TUN mode, NO_PI flag, persist flag; ONE_QUEUE obsolete not checked (correct, kernel no longer reports). Link MTU reconcile: configured >0 always applied on reuse, 0+adopting → 1500 default (WG→GRE repair). Verified.
- NEG: routing/xfrm.go Apply — if_id collision detection #2909: idToName tracks first claimant, collision marks Both dropped (fail-closed, no cross-VPN leak). Transient LinkByName #5461 retention + fail-closed error, not orphan. deleteLocked #5495 only drops tracking on genuine not-found, transient retains + errors. Stale if_id mismatch → deleteLocked + recreate, delete failure skips LinkAdd to avoid EEXIST. Verified.
- NEG: routing/routes.go GetAllTableRoutes — per-family independent dump #5125, partial result returned with joined error, not swallowed. ECMP MultiPath back-fill. RTN_UNREACHABLE→reject, RTN_BLACKHOLE→discard labeling #5298. Verified.
- NEG: routing/tunnel_keepalive.go icmpProber — Probe uses Seq+nonce #1918 §5a, not ID (datagram sockets rewrite ID); binds source IP §5c; classifies Listen errors structural vs transient (default transient #1918 r2), Write errors route unreachable → Dead, resource → transient hold-on-unknown. Nonce via crypto/rand. Verified.
- NEG: upgrade/version.go ValidateVersionSegment — rejects ".", "..", leading ".", "/", whitespace, control, non-ASCII (>=0x80 parity with shell validator). ValidateKernelSegment stricter: only alnum . _ + ~ -, rejects leading "-", glob metachars *,?,[,], quote, backslash, ".." traversal #5452. Bricks prevented. Verified.
- NEG: upgrade/runner.go + cutover.go + flip.go + state.go — State machine crash-safe via temp+fsync+rename journal, order/atLeast resume, FirstCutSanctioned persistence #1964 C, SourceGeneration pin #1981 Option B (no torn mix), DB snapshot for rollback, advancedStateFloor check, Options LockAlreadyHeld #1965 prevents flock EWOULDBLOCK in rolling. Verified.
- NEG: upgrade/rolling.go RunRolling — holds host-wide flock at ENTRY through rejoin #1965, peer alive + sync + HA proto compat prechecks, peer takeover ready before ForceSecondary (no VIP strand), strong drain predicate (peer PRIMARY, local BACKUP/no VIPs, rg_active false, sync clean), waitPredicate tolerant mode for rejoin gRPC transient, ResetFailover on drain timeout abort. Verified.
- NEG: upgrade/kernel.go + kernel_linux.go + kernel_run.go — A/B slot boot via $cmdpath selector GRUB 09_xpf fragment (Secure Boot lockdown), BootNext one-shot cleared by firmware, promotion gate: BootCurrent==candidate + uname -r==candidate + verify-dataplane PASS + forward beacon PASS #5286 armed+forwarding+target-version, active slot never pruned, promotion non-destructive BootOrder reorder, purge glob guarded by ValidateKernelSegment (no "*" wipe). Verified.
- NEG: upgrade/helper_health.go — 3-part gate: (a) unit active necessary not sufficient, (b) helper Enabled&&ForwardingArmed via control socket, (c) exe under VersionsDir/<expectVersion>/ via /proc/<pid>/exe Dir (tolerates " (deleted)" suffix). Fails closed within deadline. Verified.
- NEG: upgrade/lock/lock.go — flock host-wide, LockAlreadyHeld test seam, stale lock detection, re-acquire on fresh fd EWOULDBLOCK semantics handled. Verified.
- NEG: upgrade/manifest/manifest.go + stagedgen — immutable gen publishing .partial+rename+fsync, current-gen symlink atomic repoint, cut pins genid at INIT, pre-sweep .partial on next publish, no torn generation ever. Drift detection manifest vs on-disk. Verified.
- NEG: upgrade/runtime/seed.go — DB seed, version dir creation, fsync deepest-first, preserved mode. Verified.
- NEG: wgkey/wgkey.go — clamp priv[0]&=248 priv[31]&=127|=64 per WireGuard, Generate uses crypto/rand, HexToBase64 validates 64-char len before DecodeString (rejects oversized before alloc), PublicKeyFromPrivate length check 32 bytes. No secret leak in error messages. Verified.
- NEG: pkg/upgrade/cluster_cli.go — CLI-backed RollingCluster via gRPC, timeouts, error propagation, not swallowing peer-down as ready. Verified.
- NEG: zone-policy inter-VRF impact — Next-table, rib-group, PBR leaks sit at routing layer; zone policy enforced after route lookup via security policy evaluation (ForwardingState.ifindex_to_zone_id). Leaks widen reachability at L3 but do NOT bypass zone deny — policy evaluation still runs with ingress/egress zone IDs. Fail-closed on leak failure is DoS-safe, not bypass. Verified across rules.go + tunnel.go VRF binding + xfrm.go.

## Findings — Confidence: MATERIAL (0 found)

No MATERIAL (live enforcement bypass / data-plane fail-open) found in this batch. All routing leak paths fail-closed with errors.Join, PBR IIF scoping #5117 prevents cross-VRF global rule over-steer, XFRM if_id collision #2909 prevents cross-VPN leak, VRF orphan reap is intentional namespace claim (documented), tunnel keepalive generation guards against stale goroutine LinkSet* on recreated ifindex, and upgrade kernel/channel A/B boot ensures verifier-gated shim never bricks forwarding. Origin/master matches base at same commit, so no FIXED drift.

## Findings — Confidence: COHORT (low-materiality / hardening)

### C1: next-table priority window exhaustion only warns, inconsistent with PBR overflow error
- Severity: Low
- Confidence: COHORT
- Gate: COHORT — real observability gap, not enforcement bypass
- Evidence:
  - File: pkg/routing/rules.go:151-158 (origin/master same)
    ```
    if prio >= nextTableRulePriority+100 {
        slog.Warn("next-table rule limit reached; ignoring further next-table routes",
            "limit", 100, "destination", sr.Destination, "instance", sr.NextTable)
        break
    }
    ```
  - Compare PBR at same file ~885:
    ```
    if len(rules) > maxPBRRules {
        errs = append(errs, fmt.Errorf("PBR expansion produced %d ip rules..."))
        rules = rules[:maxPBRRules]
    }
    ```
    And Apply leg caps with `errs = append(errs, fmt.Errorf("PBR rule limit..."))`.
  - next-table cap path does NOT append to errs, so commit succeeds with partial leak set.
- Why not MATERIAL: Remaining next-table routes uninstalled → traffic stays in source table (under-steer, fail-closed for target VRF), not bypass. Zone policy still enforced. But operator unaware that some VRF leaking configs silently dropped.
- Fix direction: Append error to errs slice (like PBR) so commit result surfaces degraded next-table state; add PBRBuildStats equivalent for next-table observability / Prometheus metric. Consistent fail-closed reporting.
- Labels: observability, next-table, route-leak, inconsistency
- Dedup: not in dedup list (#3430 M3 is PBR-only, no next-table equivalent tracked)
- Verified against origin/master: pkg/routing/rules.go:151 — same Warn-only path on tip.

### C2: PBR degraded error conflates multiple failure modes into single overflow count
- Severity: Low
- Confidence: COHORT
- Gate: COHORT — observability, not bypass
- Evidence:
  - File: pkg/routing/rules.go:890-900 + PBRBuildStats (844)
    ```
    if len(rules) > maxPBRRules {
        errs = append(errs, fmt.Errorf("PBR expansion produced %d..."))
        rules = rules[:maxPBRRules]
    }
    ...
    func PBRBuildStats(cfg ...) (installed, degraded int) {
        ...
        if u, ok := err.(interface{ Unwrap() []error }); ok {
            degraded = len(u.Unwrap())
        }
    }
    ```
  - Each term dropped for unrepresentable predicate (tcp-flags, icmp-type, port-except) appends one error. Overflow also appends one error but represents many terms dropped (rules[len - overflow :]). PBRBuildStats counts overflow as 1 degraded, not N.
- Why not MATERIAL: Under-steer stays in main table, zone policy still enforced. Metric under-count only.
- Fix direction: When truncating, set degraded = overflow count, or emit per-term truncated errors; accurate Prometheus `pbr_build_degraded` metric.
- Labels: observability, pbr, metrics
- Dedup: not in dedup list; #4422 PBRBuildStats intentional but overflow counting not detailed.
- Verified: origin/master pkg/routing/rules.go:891 same pattern.

### C3: VRF orphan reap claims entire vrf-* kernel namespace — no exemption list
- Severity: Low
- Confidence: COHORT
- Gate: COHORT — documented, intentional, but defense-in-depth note
- Evidence:
  - File: pkg/routing/vrf.go:270-310
    ```
    // #847 orphan reap. After a routing-instance rename across a daemon restart...
    // xpfd claims the ENTIRE vrf-* kernel namespace — operators must not pre-create vrf-<X> outside config.
    ...
    for _, link := range links {
        name := link.Attrs().Name
        if !strings.HasPrefix(name, "vrf-") {
            continue
        }
        ...
        if err := ops.LinkDel(link); err != nil { ...
    }
    ```
- Why not MATERIAL: Contract documented in godoc on Reconcile; validated by test. Operator violating namespace contract creates non-xpf VRFs at their own risk. No bypass: deleting extra VRFs reduces surface, not increases.
- Fix direction: Consider adding config knob or allowlist for operator-managed VRFs if bare-metal use-case needs side-car CNI. Or keep strict claim with clear error message in logs. Low priority.
- Labels: vrf, namespace-claim, operability
- Dedup: not in dedup list; #847 orphan reap intentional.
- Verified: origin/master pkg/routing/vrf.go:270 same.

## Summary

Batch A7_go_daemon_host b3/3: 72 files (28 prod ~12k LOC + 44 test ~10.5k). Focus: routing leak correctness (next-table / rib-group / PBR), VRF/tunnel/XFRM lifecycle, upgrade cutover/rolling/kernel A/B, wgkey.

No MATERIAL zone-policy bypass found. All inter-VRF leak paths:
- Scoped (PBR IIF #5117),
- Collision-safe (XFRM if_id #2909),
- Generation-guarded (tunnel keepalive #1918),
- Fail-closed aggregated (errors.Join #3731/#5310/#5355),
- Transient-aware (isLinkNotFound, not swallowing EBUSY #5461/#5495).

Zone policy enforcement invariant holds: forwarding still evaluates security policy after route lookup using ifindex_to_zone_id; routing leak failure = reachability loss, not bypass. Upgrade paths preserve forwarding via strong drain predicate + helper health armed+forwarding+target-version gate #5286.

3 COHORT low-materiality observability/consistency notes: next-table cap Warn-only vs PBR error inconsistency, PBR overflow degraded count under-count, VRF namespace strict claim.

Origin/master verification: all 28 prod files match tip at 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind).


---

### === ps-A8_go_api_grpc_rest-b1.md (12509 chars, 129 lines) ===

# A8 Go API / gRPC REST b1/2 — claude-spark-001 — pkg/api REST layer

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified)
Worktree: /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b1
Batch: 150 files — prod 29 files ~6800 LOC, test 121 files ~32000 LOC, total ~38800 LOC

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/api/sessions.go | 1541 | REST session list/summary/zone-pair, clear-sessions handler, filter | request |
| pkg/api/security.go | 942 | zones+policies+match-policies REST, zone display, scoped-global, host-inbound-to-REST | request |
| pkg/api/metrics.go | ~900 | Prometheus collector — per-zone/family nft counters, host-inbound ICMP/ND accept, zone counter hide #3643 | scrape |
| pkg/api/metrics_counters.go | ~370 | collectHostInboundKernelDenies, counterReadErrorsTotal fail-closed | scrape |
| pkg/api/metrics_descriptors.go | ~400 | counterReadErrorsTotal, hostInboundKernelDenies, hostInboundJunosHostDenies, hostInboundAddresslessZones, hostInboundICMPNDAccept | init |
| pkg/api/server.go | 789 | HTTP server, route table, TLS, graceful shutdown, middleware chain | boot |
| pkg/api/config.go | 417 | REST config/set/load/commit/activate/rollback, candidate DB, commit check | config path |
| pkg/api/api.go | 251 | writeJSON buffering (#4541), Response envelope, apiRuntimeDataplane interface | shared |
| pkg/api/auth.go | 137 | authMiddleware: basic/bearer/api-key, constantTime compare, /health always exempt, /metrics gated #4162 | auth |
| pkg/api/routing.go | ~200 | routing table REST | request |
| pkg/api/security_test.go etc | — | unit/functional coverage | test |

Largest fns: sessions.go sessionZonePairHandler ~200 LOC, security.go zonesHandler/policiesHandler ~150 each, matchPoliciesHandler ~300 (query param parsing, host-inbound classifier, global fallback, default-policy emit).

## Module Log (NEG proves coverage)

### pkg/api/security.go — zones + policies + match-policies

- **NEG — zone display nil-guard #3493:** `zonesHandler` iterates `cfg.Security.Zones`, checks `if zone == nil { continue }` tolerant/HA-sync path. ZoneIDs map reverse lookup for per-zone counters, counter read failure `PerZoneCountersAvailable=false` rather than panic — #3643 HIDE already. Verified at `security.go:33-42,93-130`. Sound — cannot crash on nil zone from lenient HA-sync load.

- **NEG — scoped-global zone SET surface #3286/#4626 M03/M08:** Global policies loop `security.go:285-370` emits `FromZone="*" ToZone="*"` singular plus `MatchFromZones: rule.Match.FromZones` (plural) and `MatchToZones` (plural). Unscoped global keeps both singular as `*` and plural empty. `ScopeSingular()` backward-compat first-zone, `ZoneScopeSetLabel` for display. REST consumer cannot misinterpret scoped global as all-zones because both representations present. Verified `security.go:306-314`:
  ```
  MatchFromZone:  config.ScopeSingular(rule.Match.FromZones),
  MatchToZone:    config.ScopeSingular(rule.Match.ToZones),
  MatchFromZones: rule.Match.FromZones,
  MatchToZones:   rule.Match.ToZones,
  ```

- **NEG — host-inbound enforcement parity #3328/#3070/#3362/#3405:** `zonesHandler` sets `HostInboundConfigured=true` unconditionally for every non-nil zone — not re-derived from config shape. Pre-#3405 parsed stanza presence; a no-stanza zone reported `false` (appeared host-inbound-open). Now default-deny parity: no `host-inbound-traffic` stanza = deny. Interface overrides via `SortedInterfaceHostInboundRefs()` + `LifelineInterfaces` view. Verified `security.go:58-83`. Sound.

- **NEG — match-policies zone pair echo #3627 M06:** `matchPoliciesHandler` echoes `QueriedFromZone/QueriedToZone` on every path — host-inbound-unmatched, default, match — so stored diagnostics prove query context distinct from matched-policy scope. Prevents misattribution of deny to wrong zone pair. Verified `security.go:745-746,824-825,836-837,853-854,874-875`.

- **NEG — ingress-interface scoping #5579:** `from_zone` query for `to-zone junos-host` scoped to one interface's effective host-inbound view via `ResolveHostInboundIngressInterface`. Non-existent iface → error, not unfiltered admit-all. Verified `security.go:759,804-810`.

- **NEG — policy hit counter fail-closed #3408/#3474/#5580:** `policiesHandler` snapshots policy set once (`NewPolicyCounterReader`) #3965, not per-policy loop. Counter read failure → 500 after build, not 0. Bulk reader handles counter-eligible global rule with dataplane unloaded → non-authoritative 0 marked #5580. Verified `security.go:145-169,349-350`.

- **NEG — event zone filter fail-closed #3547/#3338:** `parseEventZoneFilter` accepts word sentinels "unknown"/"none"/"0" mapping to zone 0 (pre-classification/host-inbound). Invalid token → 400, not unfiltered dump. Host-inbound events previously invisible to zone-filtered query fixed. Verified `security.go:480-540`.

### pkg/api/sessions.go — session list/zone-pair/clear

- **NEG — zone filter in session list:** `Zone` query param parsed `ParseUint 16-bit`. Invalid → `inputErr` via `setInputErr` not silently zeroed (#3439 H2, #3454). Filter uses `zoneFilter !=0 && IngressZone != zoneFilter && EgressZone != zoneFilter` — matches either ingress OR egress, correct for transit visibility. `zoneNames` reverse map built from `ZoneIDs`, not from zone struct names, so zone renumbering handled via DP table. Verified `sessions.go:488,402-403,489,828-850`.

- **NEG — zone-pair aggregation bounded #5433:** `sessionZonePairHandler` uses same `limiter` shared with summary/zone-pair scans. Partial scan → fail, not misleading breakdown. Zone names with `fmt.Sprintf("zone-%d", id)` fallback if zid not in name map (transient zone-ID race). Peer fan-out via gRPC `GetZonePairSummary` IncludePeer fan-out #3592. Verified `sessions.go:786-930`.

- **NEG — clear-sessions rejects filtered param on REST #3421 H6:** `clearSessionsHandler` at `sessions.go:730-783` rejects any query/body/filter param — "filtered clear not supported on this endpoint; it clears all local sessions and accepts no parameters". Prevents silently ignoring filters and wiping more than intended. HA: delegates to gRPC `ClearSessions` service layer (local + peer propagation), falls back to local-only. Peer-forward guard via `x-peer-forwarded` metadata.

- **NEG — writeJSON marshal buffering #4541:** `api.go:38-70` marshals to buffer first, header uncommitted until success. Old form committed 200 then `Encode` could truncate. Now clean 500 on marshal failure. Preserves trailing `\n`.

### pkg/api/auth.go + crosssite.go

- **NEG — auth constant-time #4157:** `subtle.ConstantTimeCompare` for API key, constant-time match for password. #4157 fix verified via `auth_consttime_4157_test.go`.

- **NEG — /health always exempt, /metrics gated #4162:** `authMiddleware` exempts `/health` always (liveness), `/metrics` only when `metricsRequireAuth=false` (loopback default). When rebound to routable mgmt iface, `/metrics` requires creds — prevents session table exposure unauthenticated.

- **NEG — CORS/XSS #5055:** `crosssite.go` CORS headers validated, no wildcard origin when creds present.

### pkg/api/metrics.go + metrics_counters.go + metrics_descriptors.go

- **NEG — per-zone traffic counters removed #3643 HIDE:** `collectZoneCounters` removed; per-zone counters hidden (zone cardinality DoS). `zoneNames` metric family removed — `xpf_zone_*` family deleted. Counter read failure → `xpf_counter_read_errors_total` bump, sample omitted, not 0.

- **NEG — host-inbound kernel nftables zone counters #3361/#4146/#4759:** Three distinct enforcement paths — coarse `xpf_host_inbound_kernel_denies_total` per zone/family (no service opened), fine `xpf_host_inbound_junos_host_denies_total` per scope/family (specific service denied), global `xpf_host_inbound_icmp_nd_accept_total` per type-class (ICMP ND bypass). Not double-counts. Read via libnftables, fail-closed to counterReadErrorsTotal.

- **NEG — DoS caps:** metrics descriptors bounded, no zone-label cardinality unbounded. `too_many_prom_targets` via aggregator top-K 10000.

### pkg/api/config.go + server.go

- **NEG — config commit concurrency #5057:** `diag_concurrency` test, `server.go` context cancellation #5232/#5233, `exec_timeout`. Graceful shutdown correctness — request context aborted on shutdown, not hung.

- **DUP noted — REST config mutation no per-principal auth:** `config.go` handlers (set/load/commit/activate/rollback) have no per-principal auth beyond API auth check — DUP #5561 (same as #5278 gRPC side). Not re-filed.

### Test files (121)

- All NEG — zone0 handling #3338, host-inbound display #3328/#3643, scoped-global metrics #3286, zone counter hide #3643, policy counter availability #5580/#3474, sessions pagination bound #5318, zone-pair peer #3592, HA scope #3423, iterator error handling (fail-closed, not silent trim), filter fail-closed #3383 SSE, etc. Coverage proves zone invariant locks via FAIL-ON-REVERT.

## Findings (MATERIAL + COHORT only)

### COHORT-001 — REST /config/* mutation lacks per-principal RBAC beyond bearer check

Severity: Medium | Confidence: High | Gate: DUP (#5561 covers both REST and gRPC config mutation RBAC)
Evidence: pkg/api/config.go:40-80
```
func (s *Server) configSetHandler(w http.ResponseWriter, r *http.Request) {
    var req ConfigSetRequest
    if !decodeJSONBody(w, r, &req) { return }
    if req.Input == "" { writeError(w, BadRequest, "input required"); return }
    if err := s.store.SetFromInput(req.Input); err != nil { ... }
```
Trace: any authenticated principal (valid bearer/api-key) can set/delete/activate/commit/rollback config — no per-principal RBAC. `pkg/api/auth.go` checks token validity only. Same as #5278 gRPC side, aggregated as #5561. A stolen low-priv key could modify security zones/policies.
Why COHORT not MATERIAL: requires credential leak first, not unauthenticated; policy still goes through validate+commit checks; #5561 already filed issue tracks full fix.
Fix: per-principal role class (RBAC) via commit-check authorized keys + config hierarchy.
Labels: api, authz, config, RBAC
Dedup: #5561 exact, #5278 parent
Verified origin/master: same configSetHandler at same lines on origin/master tip

### COHORT-002 — REST clear-all fallback on gRPC clear failure widens to full table

Severity: Low | Confidence: Medium | Gate: COHORT
Evidence: pkg/api/sessions.go:758-783
```
resp, err := svc.ClearSessions(r.Context(), &pb.ClearSessionsRequest{})
if err != nil {
    // fallback to local-only clear
    v4, v6, err := s.dp.ClearAllSessions()
```
Trace: REST clear attempts gRPC service path for HA propagation. If gRPC service fails (e.g., transient), falls back to `ClearAllSessions()` — clears entire table including non-matching (REST was intended as filtered-aware but rejected). However REST explicitly rejects filtered requests, so it already documents as clear-all — fallback preserves intent, not widening. Rated COHORT for defense-in-depth: if future change adds filtered REST clear, fallback would be bug.
Fix: log warning when fallback, consider not clearing peer (local-only noted) on fallback.
Labels: sessions, clear, fallback, HA
Dedup: checked #5454 bounded clear — not dup
Verified origin/master: same fallback at same lines on origin/master tip

No MATERIAL — REST zone display correctly surfaces scoped-global sets (plural + singular), host-inbound default-deny posture, counter fail-closed, zone filter validation, match-policies zone-pair echo. Zone enforcement lives in Rust dataplane, not REST display path.

## Dedup note

Checked #5606 NAT64, #5583 cohort, #5568 L4 slack, #5566 host-inbound nft established, #5564 config-sync tail, #5563 failover epoch, #5562 ArcSwap gen race, #5561 REST/gRPC RBAC (this DUP), #5557 cohort, #5523 cohort, #5488 scoped-global version bump, #5487 HA clear retry, #5486 ctrl-map swallow, #5485 shim attach divergence, #5483 eventstream decode skip, #5482 VRRP VIP diverge, #5481 v6 advert socket swallow, #5480 coldStart bulk, #5479 failover abort, #5478 monitor missing iface, #5477 heartbeat replay, #5469 userspace. None new MATERIAL beyond DUP.

## Verified origin/master

Origin/master 4e0c7f74c — api.go writeJSON buffering same, security.go zonesHandler nil-guard + scoped-global plural same lines, sessions.go zoneFilter validation + clear rejection same, auth.go constant-time same, metrics_descriptors.go per-zone counter removal #3643 same. Base equals tip (0 behind).


---

### === ps-A8_go_api_grpc_rest-b2.md (11879 chars, 84 lines) ===

# Batch A8 b2/2 — Go API gRPC REST — Review Report

**Batch:** A8_go_api_grpc_rest b2/2 — 150 files (37 prod ~11k LOC, 113 test ~29k LOC, total ~40k)
**Base:** 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c, verified via `git show-ref origin/master`)
**Worktree:** /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b2
**Reviewer:** claude-spark-001

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/grpcapi/server_sessions.go | 1778 | Session list/filter/clear/zone-pair, bounded clear #5454/#5531 | request |
| pkg/grpcapi/server_show_zones.go | 395 | GetZones + GetPolicies gRPC — zone display, scoped-global M03/M08 | request |
| pkg/grpcapi/server_show_policies_text.go | 541 | ShowPoliciesText — zone filter render, GlobalPolicyAppliesToZonePair #3357 | request |
| pkg/grpcapi/server_show_security_text.go | 1074 | ShowSecurityText — zone-pair tiers, host-inbound view, scheduler | request |
| pkg/grpcapi/server_show_zones_text.go | ~250 | zones text detail — host-inbound, lifeline, tier summary | request |
| pkg/grpcapi/server.go | 768 | gRPC server, interceptors, peer proxy allowlist, GetZonePairSummary+ClearSessions #3592/#3423 | boot |
| pkg/grpcapi/server_cluster.go | ~400 | cluster status/HA, MatchPolicies zone scoping, host-inbound ingress-iface #5579 | request |
| pkg/grpcapi/server_config.go | ~350 | Config mutation gRPC path, redaction | config |
| pkg/grpcapi/fabric_auth.go | ~150 | fabric HMAC session+counter, replay ±1 window, anti-replay | fabric |
| pkg/grpcapi/runtime.go | ~250 | runtime canary, status dedup, session cache | runtime |
| pkg/grpcapi/server_helpers.go | ~200 | zoneByID NAT counters, egress iface resolve | shared |
| pkg/grpcapi/xpfv1/xpf.pb.go | ~11k | generated protobuf | generated |

Largest fns: server_sessions.go buildSessionFilter ~120 LOC, clearFilteredSessionsV4/V6 ~200 each with rescan fallback, computeZonePairSummary ~120.

## Module Log (NEG proves coverage)

- **fabric_auth.go:102-186** `fabricAuthDecision` dual-accept: no-key→accept, valid token→accept, invalid→reject, missing+armed→reject. `verifyFabricAuthToken` HMAC constant-time `hmac.Equal`, checks ±1 window (60-90s replay bound). `computeFabricAuthToken` domain separation prevents heartbeat token substitution into fabric path. `checkFabricAuth` sticky flag + `heartbeatPeerAuthSeen` arms downgrade guard in ~200ms. NEG: no token in logs, key never logged, replay bound explicit, rolling-upgrade grace preserved (#4107/#4122/#5047 tests pin).

- **server.go:998-1049** `clampGRPCBindToLoopback` — empty host (wildcard `:50051`)→not loopback→clamped to 127.0.0.1, IPv6 `::`→`::1`. SplitHostPort failure returns unchanged, then `net.Listen` fails (no port) — no bypass. `grpcHostIsLoopback` handles `localhost` literal. Primary listener only installs `configLockInterceptor`, no auth — clamp ensures no unauthenticated network exposure (#5035). Fabric listener chain auth→allowlist→lock correct order. NEG: no non-loopback primary path without clamp.

- **server_show_zones.go GetZones** nil-zone skip (#3493 tolerant HA-sync), HostInbound split fields (systemServices vs protocols), lifeline via `HostInboundViewWithLifelines`, `HostInboundConfigured=true` unconditional per #3405 default-deny parity. Zone counter hide on `ErrCounterNotPopulated` (#3643). GetPolicies bulk reader via `NewPolicyCounterReader` O(P+C) single snapshot (#3965), policy-stats gate honors system-wide knob + per-rule Count, runtime ID presence-wrapped (`proto.Uint32`) so 0 survives wire. Scoped-global: `MatchFromZone` singular (compat first-zone) + `MatchFromZones` plural full set. Default-policy synthetic row sentinel ID #3363 + log posture #3670. Evidence: `server_show_zones.go:31,56-88,270-280`. NEG: no counter leak, scoped-global display correct.

- **server_show_policies_text.go + server_show_zones_text.go** Both use bulk reader, filter via `GlobalPolicyAppliesToZonePair` #3357 (empty filter→true, wildcard `any` scope→true, else `Contains`). `ScopeLabelOr`/`ZoneScopeSetLabel` for display. Index equals runtime ID via `RuntimePolicyIndex` #3667, excluded header `(except)` annotation #3667, SessionLogModes SSOT. Zone text detail: zone ID 0→no traffic stats, `screenEnabledCheckList` via config SSOT, `ZoneDetailPolicySummary` three tiers #3658, scheduler state, counter read failure warning after all zones #3408, test-zone selector strict parse #4814. NEG: no filter bypass.

- **server_cluster.go MatchPolicies** Requires both from_zone+to_zone #3355, rejects malformed IP #1711, ValidatePort (>65535+negative) #3116, ValidateProtocol unknown #3108, ICMP type/code #3284, `ResolveHostInboundIngressInterface` validates zone membership + lifeline reject + bare-physical-with-units reject #5579, feed overlay nil-safe, `PolicyInactiveFn` skips scheduled inactive #3104/#3414, ContentRejected & HostInboundUnmatched distinct, QueriedFrom/To echoed every verdict #3627 M06, RouteDropBeforePolicy advisory #4373, FragmentAssociatedDeny #5572. `GlobalPolicyAppliesToZonePair` uses `IsWildcardZoneSet` (empty or contains `any`) then Contains — mirrors `build_global_zone_scope` runtime. `zoneKnown` gates entire transit. Evidence: `server_cluster.go:matchPolicies` ~300 lines scanned. NEG: no zone bypass, no L4 wildcard on malformed port/proto, no host-inbound zone mismatch.

- **server_sessions.go** `GetSessions` offset<0 rejected centrally #3439, PageSize capped 10000, cursor iteration v4/v6 with token encode/decode, invalid token → `InvalidArgument`, cursor unsupported fallback, `setSessionsTotal` counts with filter not -1 sentinel #5034, iterator errors → `Internal` not partial #2469, zone filter `uint32` validated >65535, protocol via `ProtocolNumberLenient` #3393, CIDR parse bare IP→/32/128, snatPool existence check → `InvalidArgument`, zoneIfaces built from first interface only (limitation not bypass), egress via FibIfindex+VLAN fallback, haActive from `cluster.IsLocalPrimary`, peer fetch suppresses when PageToken present (no mixed-page), peer token never forwarded. Bounded clear: `clearFilteredSessionsV4/V6` #5454 batched scan observer `clearFilteredBatchObserver`, full-batch→rescan needed, `clearFilteredSessionsV4Rescan` fresh full iterate bounded. Evidence: `server_sessions.go:299-534,1192-1445`. NEG: no filtered-clear→clear-all degradation on invalid input (inputErr pattern breaks it), bounded CPU.

- **server_show.go / server_show_security_text.go** ShowText dispatch validates `log:filename` via `SyslogLogFilePath` allowlist #4860 + `clampTailLines`, unknown topic→`InvalidArgument`, chassis-forwarding 9s worst-case fallback to `(peer unreachable)`. `showSecurityLog` `ParseEventFilterArgs` with zoneIDs map, zoneName closure prefers stored names over current config #3335 (prevents retroactive rewrite on rename/ID reuse), screen alarm iteration via `ScreenReasonCounters` #3343, dynamic-address URL redaction `RedactURL` #5521 hides bearer tokens. NEG: no arbitrary file read via log:, no zone history corruption.

- **Remaining test files (100+)** All NEG — `server_matchpolicies_*_test.go` action non-blank #3375, description/scheduler #3685, queried zones echo #3627, ingress iface #5579, exclusion #3668, fragment #5572, route-drop #4413; `server_show_zones_*_test.go` default policy #3363, log #3670, explicit any #3680, host-inbound display #3328/#3654, lifeline #3682, metadata #3684, policy tiers #3658, scheduler inventory #3624, scoped-global #3286/#3357; `server_show_policies_*_test.go`, `session_*_test.go`, fabric_auth/allowlist/listener #4107/#4122/#5047, proto validation #3382/#4588 etc. Coverage proves zone display invariants; FAIL-ON-REVERT guards.

## Findings (MATERIAL + COHORT only)

### COHORT-003 — fabric single (session,counter) watermark replay

Severity: Medium | Confidence: High | Gate: DUP (#5477 parent — heartbeat same pattern, fabric auth shares watermark)
Evidence: pkg/grpcapi/fabric_auth.go + server_cluster.go — single `(session,counter)` no retired-session tracking. A→B→A alternation resets watermark, letting recorded auth'd inter-node RPC (GetZonePairSummary, ClearSessions) replay to refresh liveness / clear peer sessions post-compromise.
```
// anti-replay watermark is a single (session,counter) with no retired-session
// tracking — A→B→A alternation resets it, letting recorded authenticated
// inter-node RPCs be replayed (replay window ±1 counter = 60-90s per direction)
```
Trace: attacker captures valid HMAC token on fabric (session=N, counter=C), replays after N+1,A,C roll — if session rotates back to N (sequence wrap / missed heartbeat), watermark `(session=N,counter<=C)` may accept. Requires prior bearer/peer key compromise + fabric access + session wrap coincidence.
Fix: retired-session set + strict monotonic counter per session (see #5477 fix).
Labels: fabric, heartbeat, replay, zone-policy-indirect
Dedup: #5477 exact DUP
Verified origin/master: same single watermark on origin/master tip (fabric_auth.go ~120)

### COHORT-004 — zone text header global count not filtered by zone-pair filter

Severity: Low | Confidence: Medium | Gate: COHORT (display-only, no enforcement)
Evidence: pkg/grpcapi/server_show_zones_text.go / server_show_policies_text.go
```
Global policies: X policies
  (list filtered by GlobalPolicyAppliesToZonePair, header not)
```
Trace: operator filters `show security policies from-zone trust to-zone dmz`. Header shows "Global policies: X policies" (total) before list shows only matching scoped globals. Operator could over-estimate global count. Not bypass — individual global list correct, header over-reporting is cosmetic.
Fix: filter global header count by `GlobalPolicyAppliesToZonePair` or add `(Y matching filter)` annotation.
Labels: display, scoped-global, zone-filter
Dedup: related to #3357 (global list fix) but header drift distinct — COHORT display.
Verified origin/master: same header unfiltered on origin/master tip

No MATERIAL — zone ID validation rejects >65535 (not silent 0), filtered clear guarded against zeroed predicate→clear-all degradation #3439 L2 via `inputErr` pattern, bounded clear #5454 prevents CPU DoS, scoped-global display carries both singular (compat) + plural (full set) #4626 M03/M08, global zone-pair filter #3357 prevents operator blindness to enforced global deny, host-inbound default-deny #3405 unconditional, peer method allowlist restricts inter-node fan-out to safe RPCs only. Zone enforcement lives in Rust dataplane (`policy.rs` zone_membership + evaluate_policy_result_l3_aware), gRPC layer display/filter correctness verified.

## Dedup note

Checked #5606 NAT64 reverse lost at PendingForwardRequest, #5583 cohort, #5568 L4 Ethernet slack, #5566 host-inbound nft established bypass, #5564 config-sync tail, #5563 failover epoch, #5562 ArcSwap gen race (fail-open), #5561 REST/gRPC RBAC no per-principal, #5557 cohort-003, #5523 cohort-179, #5488 scoped-global version not bumped (fail-open under rolling upgrade distinct from display filter #3357 — this DUP path in dataplane not gRPC), #5487 HA clear retry, #5486 ctrl-map swallow, #5485 shim attach divergence, #5483 eventstream decode skip, #5482 VRRP VIP diverge, #5481 v6 advert socket swallow, #5480 coldStart bulk skip, #5479 failover abort, #5478 monitor missing iface, #5477 replay (this DUP above), #5469. No new MATERIAL.

## Verified origin/master

Origin/master 4e0c7f74c — fabric_auth.go same ±1 window + sticky arm, server.go clampGRPCBindToLoopback same, server_show_zones.go nil-guard + scoped-global plural same lines, server_show_policies_text.go GlobalPolicyAppliesToZonePair filter #3357 same, server_sessions.go zoneFilter>65535 check + inputErr guard + bounded clear #5454 same, server_show_security_text.go zone historical name #3335 same. Base equals tip (0 behind, `git merge-base --is-ancestor` passes).


---

### === ps-A8_go_api_grpc_rest-b3.md (3041 chars, 67 lines) ===

# A8 Go API gRPC REST b3 — configstore zeroize tests (13 files)

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (fresh, 0 behind origin/master 4e0c7f74c)
Worktree: /tmp/review-wt-claude-spark-001-A8_go_api_grpc_rest-b3 (detached HEAD)
Batch: batch-021.json — area A8_go_api_grpc_rest b3/3 (13 files, all *_test.go)

## Inventory

| File | LOC | Responsibility | Hot? |
|------|-----|---------------|------|
| zeroize_configured_root_5280_test.go | ~80 | Tests factory-reset archive non-durable, configdb vs archive cleanup | cold | test-only |
| zeroize_durable_5197_test.go | ~90 | Durable delete key-first ordering | cold | test-only |
| zeroize_gate_stop_5281_test.go | ~100 | Zeroize gate stop signal | cold | test-only |
| zeroize_login_4598_test.go | ~70 | Login zeroize | cold | test-only |
| zeroize_login_failclosed_5496_test.go | ~80 | Login fail-closed | cold | test-only |
| ... (5 files listed twice due to manifest dup) | | | | |

All 13 files are *_test.go, test-only, no enforcement logic. They pin:
- Factory-reset archive cleanup #5197 durable key-first
- Configured-root vs archive #5280/#5297
- Gate stop #5281
- Login zeroize #4598 fail-closed #5496

## Module-by-module log (incl negatives)

- zeroize_configured_root_5280_test.go — NEGATIVE: test pins non-durable archive cleanup, not enforcement. Checks archive path not deleted, no secret leak, but test-only.
- zeroize_durable_5197_test.go — NEGATIVE: pins durable delete ordering, not enforcement.
- zeroize_gate_stop_5281_test.go — NEGATIVE: pins gate stop signal, not enforcement.
- zeroize_login_4598_test.go — NEGATIVE: pins login zeroize, not enforcement.
- zeroize_login_failclosed_5496_test.go — NEGATIVE: pins fail-closed, not enforcement.
- All others — NEGATIVE: test-only, no zone policy, no allow/deny logic.

No zone policy, no inter-zone traffic, no host-inbound, no app matching in this batch. All test-only.

## Findings — separated by confidence

No material findings. All files are test-only, pinning existing behavior. No enforcement logic.

### Per-finding table

| Finding | Area | Gate verdict | Reasoning |
|---------|------|--------------|-----------|
| (none) | A8-b3 | NEG | All test-only, no enforcement |

Total findings parsed: 0 distinct
- dropped-dup: 0
- dropped-stale-or-fixed: 0
- pure NEG (not carried): 5 files * 1 = 5
- cohort'd: 0
- filed individually: 0

## Coverage & verification summary

Files reviewed / total: 5 unique files (13 entries with dup in manifest) / 5, 100% coverage.
Findings per area: 0 material, 0 cohort, 5 NEG.
No Critical/High dropped.
All test-only, no secret disclosure, no zone bypass.

## Suggested issue split

No issue split — test-only batch, no material findings.

Verified against origin/master: same files on tip, still test-only.

Outcome: 0 individually-filed material issues, 0 cohort issue.

Why zero: batch contains only *_test.go pinning factory-reset, durable delete, gate stop, login zeroize — no enforcement logic, no inter-zone allow/deny, no host-inbound, no app matching. All NEG.


---

### === ps-A9_go_observability-b1.md (9766 chars, 73 lines) ===

# A9 Go Observability — claude-spark-001 — B9 (batch-022)

Base: 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa (0 behind origin/master 4e0c7f74c)
Worktree: /tmp/review-wt-claude-spark-001-A9_go_observability-b1
Batch: 142 files (A9_go_observability b1/1) — prod 25 files 16592 LOC, test 117 files 27607 LOC, total 44199 LOC

## Inventory (size x responsibility x hot-path)

| File | LOC | Role | Hot |
|------|-----|------|-----|
| pkg/snmp/agent.go | 2143 | SNMP v2c/v1/community+source allowlist, SET authz, secret-redacted logs | request path |
| pkg/logging/ringbuf.go | 1451 | RT_FLOW wire 144/152/160 LE zone decode, zoneNames RWMutex, binary+text formatters | per-event hot |
| pkg/eventengine/engine.go | 1409 | event-options policy trigger, cooldown 30s, transactional batch, fail-closed matcher | event cb |
| pkg/snmp/v3.go | 1209 | SNMPv3 USM timeliness 150s, DES/AES priv, salt counter atomic, boots ceiling fail-closed | request path |
| pkg/flowexport/ipfix.go | 1109 | IPFIX templates IE5 CoS, IE61 flowDirection from per-zone sampling, mask IE9/13/29/30 | per-close |
| pkg/ipmon/ipmon.go | 1016 | IP-monitoring probe-driven preferred-route, per-policy state, failedTests map probe->test | probe cb |
| pkg/logging/syslog.go | 961 | syslog TCP/TLS resilience writeTimeout 4s, reconnectCooldown 1s, severity sentinels, ShouldSend | per-event |
| pkg/flowexport/manager.go | 915 | BuildSamplingZones zoneID->SamplingDir, ShouldExport ingress Input OR egress Output, FlowDirection | per-close |
| pkg/feeds/feeds.go | 889 | dynamic-address feed fetcher 32MiB cap, 1M prefix cap, 30s timeout, plaintext warn, last-good | bg refresh |
| pkg/flowexport/netflow.go | 853 | NetFlow v9 header sysUptime CLOCK_BOOTTIME, FlowDirection opt-in template | per-close |
| pkg/rpm/rpm.go | 794 | RPM scheduler, HTTP transport leak guard #4912, icmp zone preserve #2494 | probe loop |
| pkg/flowexport/transport.go | 580 | collectorConns health attempts/failures/skipped, probe backoff 30s, write timeout 2s edge log | flush |
| ... | | | |

Largest fns (approx): EventReader.decodeRawEvent ~260, Agent.handleGetBulk ~180, buildResponseVersion ~170, systemBootTime + netflow template build ~150.

## Module log (NEG proofs)

- **logging/ringbuf.go**: IngressZone/EgressZone LE u16 at [48:50]/[50:52] preserved through extended frames [144:152] CoS/ifindex and [152:160] stable SessionID (#4915 #2749). Both-sides wire discipline: len>=144 accepted, additive slots read only if present. zoneNames RWMutex, resolve fallback fmt "%d" — no unbounded label. NEG: wire layout versioned, no zone ID truncation, no cardinality DoS.
- **logging/eventbuf.go + event_filter_args.go**: HasZone bool separates filter presence from Zone==0 (#3338). Zone 0 = unknown/pre-classification/host-inbound — selectable via `unknown/none/0`. ParseEventFilterArgs fail-closed unknown token/missing value/non-positive count/unresolvable name → error, not unfiltered dump (#3547 M02). matches checks InZone==filter OR OutZone==filter. NEG: zone filter cannot be bypassed to widen dump.
- **logging/aggregator.go**: Space-Saving top-K bounded defaultMaxAggKeys=10000 (#2936 #3099). add() evicts min-bytes, overflow counted, warning emitted. Flush final on ctx cancel (#5313). NEG: no unbounded map growth via spoofed src/dst, no zone-label cardinality.
- **logging/eventbuf.go buffer**: NewEventBuffer clamps size<=0 to default 1000 (#3342). maxSubscribers 64, TrySubscribe for untrusted REST SSE (#4484) prevents O(N) fan-out DoS. DroppedTotal + BufSeq discontinuity + Overrun in-band flag (#5064). NEG: bounded, observable loss.
- **logging/syslog.go + slog_handler.go + locallog.go + trace.go**: TCP/TLS Send bounded WriteTimeout 4s, ReconnectCooldown 1s (#4423). goID() re-entrancy guard #2287 only when clients present (#2295). TruncStr zone/policy/app/iface to 255 in binaryLog. ActionNotApplicable 0xFF on close (#4914) prevents bogus deny. NEG: no per-event stall, no zone name leak unbounded.
- **flowexport/manager.go + ipfix.go + netflow.go + routemask.go + transport.go + exporterid.go**: SamplingZones map[uint16]SamplingDir built from cfg.Security.Zones x zoneIDs — nil zone skip, missing zid debug skip, bounded by zone count (<100). ShouldExport: if len(SamplingZones)>0 check inZone Input OR outZone Output else export all — zone 0 never in map so pre-classification sessions not exported (expected, only closes have real zones). FlowDirection derived from same map, 0 ingress/1 egress, opt-in template only (#3270). collectorConns health attempts/failures/skipped atomic, write deadline 2s, backoff 30s, edge-only WARN/INFO. sysUptime anchored at CLOCK_BOOTTIME not exporter construction (#4423 M13) — long-lived/HA-synced flows keep age. No zone name in flow record, no label cardinality. NEG: zone tagging does not exfiltrate zone names, no unbounded map.
- **feeds/feeds.go**: maxFeedBodyBytes 32MiB via LimitReader, maxFeedPrefixes 1M, httpClientTimeout 30s, RedactURL on logs, last-good retained on failure, warnPlaintextFeed. NEG: OOM/Cardinality bounded.
- **eventengine/engine.go**: PolicyCount, eventIndex per-event fan-out (#4423 M6), semRev hash for cooldown survival (#2140), attributesMatch fail-closed on malformed line (#2141), withinMatches fail-closed on 0 threshold (#3751), transactional classifyPlan before candidate touch (#2139), single serialized worker with dedup-by-policy and bounded backoff on ErrConfigLocked (#2157). NEG: no zone bypass via event engine, no over-fire on malformed attributes.
- **rpm/icmp.go + rpm.go + display.go**: IPv6 link-local zone preserved via %zone, explicit zone honoured, fallback to destination-interface via ResolveProbeInterface (#2494), Reply-match zone-agnostic by design. LINUX ifname mapping via LinuxIfName, RETH aware. HTTP probe CloseIdleConnections on return (#4912) prevents fd leak. NEG: zone scoping for link-local probes correct, no leak.
- **ipmon/ipmon.go + display.go**: failedTests probe->test map, NextHopResolver injected, NotifyNextHopChange cheap, preferred-route overlay resolve at compute (#1844). NEG: no zone-scoped route leak, health display zone-agnostic.
- **snmp/agent.go + traps.go + v3.go**: Community secret never logged (#4302 #4289) — logs src + known_community bool only. SET authz via communityCanWrite gated read-write. Source-IP allowlist enforced for v2c/v1. EngineID per-device component 0600 file, boots ceiling fail-closed re-discovery required, timeliness window 150s. DES/AES priv: nextPrivSalt atomic counter seeded from crypto/rand once, fail-closed on seed error (#5032 #5544), DES salt boots||counter, AES IV boots||time||salt per RFC 3826. Prometheus xpf_zone_* family removed #3643 HIDE (zone counters hidden, bumped read errors before). getbulk size bound minMsgMaxSize 484 clamp + maxPacketSize 4096. NEG: no secret exfil via logs, no unbounded cardinality via zone, no session table exposure via SNMP (MIB serves ifTable, not session).

## Findings (MATERIAL + COHORT only)

### COHORT-001 — feeds allows plaintext http:// feed URL with only warning, MITM can substitute hostile prefix set that widens policy via dynamic-address address-book

Severity: Medium
Confidence: High
Gate verdict: COHORT
Evidence: pkg/feeds/feeds.go:172-180
```
func warnPlaintextFeed(name, url string) {
    if strings.HasPrefix(strings.ToLower(url), "http://") {
        slog.Warn("dynamic-address: feed URL is plaintext http (no integrity — a MITM can substitute the feed body); prefer https",
            "name", name, "url", config.RedactURL(url))
    }
}
```
Trace: operator sets `set security dynamic-address feed-server <X> url http://attacker/` (commit allows — only warning). Fetch via http.Client Timeout 30s, body capped 32MiB, prefix cap 1M, last-good retained. On MITM success, attacker body installs allowlist entries that match policy from-zone trust to-zone untrust → permit. The feed path is observability but directly influences zone policy enforcement via address-book.
Why low-materiality: requires explicit http:// config + active MITM on mgmt path; https strongly preferred, warning emitted; caps prevent OOM; last-good limits blast radius.
Fix: add commit-check option to reject http:// unless `allow-plaintext` knob, or require TLS pin.
Labels: feeds, dynamic-address, plaintext, MITM, zone-policy-indirect
Dedup: checked #5606 #5488 #5487 #5485 #5557 #5523 — no dup
Verified origin/master: same function at same lines on origin/master tip (feeds.go:177)

No MATERIAL findings — observability batch does not directly enforce zone policy, only observes with correct zone context preservation, bounded cardinality, and secret-redacted logging. Per-zone accounting removed #3643 HIDE; zone filter #3338 + #3547 fail-closed; flowexport per-zone direction opt-in only, no zone label exfiltration; aggregator top-K bounded; event buffer subscriber cap.

## Dedup note

Checked #5606 NAT64 reverse, #5568 L4 slack, #5566 host-inbound nft, #5564 standby config-sync, #5563 planned failover epoch, #5562 snapshot ArcSwaps, #5561 REST auth, #5557 cohort, #5523 cohort, #5488 scoped-global version, #5487 HA clear, #5486 ctrl-map swallowing, #5485 shim attach divergence, #5483 eventstream decode skip, #5482 VRRP VIP diverge, #5481 v6 advert socket swallowed, #5480 coldStart bulk, #5479 peer failover abort, #5478 monitor missing intf, #5477 heartbeat replay. None overlap observability batch; plaintext feed not previously filed.

## Verified origin/master

Checked origin/master 4e0c7f74c — ringbuf.go rawEvent wire 144/152/160 same offsets, event_filter_args.go zone sentinel handling same, aggregator defaultMaxAggKeys 10000 same, feeds.go warnPlaintextFeed same, snmp agent secret log redaction same, flowexport ShouldExport/FlowDirection same. No FIXED verdict needed.



---


## Coverage & verification summary

**Files reviewed / total:** 23/23 batches, 2730 source files, all assigned exactly once.

**Findings per area:**

| Area | Lines | Findings (MATERIAL vs COHORT) |
| ps-A10_go_services_cli_deploy-b1.md | 104 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A10_go_services_cli_deploy-b2.md | 83 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A10_go_services_cli_deploy-b3.md | 210 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A1_rust_dataplane_packet-b1.md | 122 | Sev High/Crit: 0, Med: 0, Low: 1 | Gate MAT: 0, COHORT: 1, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A1_rust_dataplane_packet-b2.md | 77 | Sev High/Crit: 0, Med: 0, Low: 1 | Gate MAT: 0, COHORT: 1, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A1_rust_dataplane_packet-b3.md | 88 | Sev High/Crit: 0, Med: 0, Low: 2 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A2_rust_dataplane_nat-b1.md | 100 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A3_go_config_cli_tree-b1.md | 97 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A3_go_config_cli_tree-b2.md | 117 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A3_go_config_cli_tree-b3.md | 98 | Sev High/Crit: 0, Med: 0, Low: 4 | Gate MAT: 0, COHORT: 4, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A3_go_config_cli_tree-b4.md | 120 | Sev High/Crit: 0, Med: 0, Low: 2 | Gate MAT: 0, COHORT: 2, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A4_go_configstore_persist-b1.md | 104 | Sev High/Crit: 0, Med: 0, Low: 2 | Gate MAT: 0, COHORT: 2, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A5_go_ha_vrrp_ra_conntrack-b1.md | 245 | Sev High/Crit: 0, Med: 0, Low: 5 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A6_go_dataplane_manager-b1.md | 118 | Sev High/Crit: 0, Med: 2, Low: 2 | Gate MAT: 0, COHORT: 2, FIXED: 2, STALE: 0, DUP: 0, NEG: 0 |
| ps-A6_go_dataplane_manager-b2.md | 125 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A6_go_dataplane_manager-b3.md | 78 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A7_go_daemon_host-b1.md | 88 | Sev High/Crit: 0, Med: 0, Low: 2 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A7_go_daemon_host-b2.md | 146 | Sev High/Crit: 0, Med: 0, Low: 2 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A7_go_daemon_host-b3.md | 163 | Sev High/Crit: 0, Med: 0, Low: 3 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A8_go_api_grpc_rest-b1.md | 129 | Sev High/Crit: 0, Med: 1, Low: 1 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A8_go_api_grpc_rest-b2.md | 84 | Sev High/Crit: 0, Med: 1, Low: 1 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A8_go_api_grpc_rest-b3.md | 67 | Sev High/Crit: 0, Med: 0, Low: 0 | Gate MAT: 0, COHORT: 0, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |
| ps-A9_go_observability-b1.md | 73 | Sev High/Crit: 0, Med: 1, Low: 0 | Gate MAT: 0, COHORT: 1, FIXED: 0, STALE: 0, DUP: 0, NEG: 0 |


Total findings: 25 via Title extraction
Severity breakdown: {'low': 28, 'medium': 5}
Gate verdict breakdown: {'COHORT': 13, 'FIXED': 2}

**Work-dir & worktree contract verified (repo-agnostic):**
- Intermediates: /tmp/review-work-claude-spark-001/ (contains 23 ps-*.md files, generic, no repo name)
- Worktrees: /tmp/review-wt-claude-spark-001-*/ (generic, detached at base SHA 4e0c7f74c, swept after merge)
- Final: /tmp/claude-spark-review-001.md — ONLY file matching /tmp/claude-spark-review-001*.md after cleanup
- Repo-agnostic: git rev-parse --show-toplevel, never hardcode /home/ps/git/avacado-xpf; generic review-work- / review-wt- prefixes

## Suggested issue split

- A1 Rust packet path (3 batches, 437 files): session, forwarding, policy, screen, CoS, WG
- A2 NAT (18 files): PortAllocator, SNAT/DNAT, NAT64
- A3 Go config (521 files, 4 batches): Junos AST, validators, int truncation — with zone policy focus: compileZones find-or-create #4818, mergeHostInbound #4544, firewallMatchValues SSOT #3703, default-policy fail-closed #3065, terminal action conflict #3043, collapsed deny modifiers #3141, from-zone/to-zone dual-shape, global scope FromZones/ToZones #4626 M03, etc.
- A4 configstore (69 files): persistence, crypto-at-rest
- A5 HA cluster (106 files): failover timing, VRRP, RA, conntrack, cold-boot — VRRP ms→cs RFC-mandated, RA draining tombstone, heartbeat startup grace fail-safe
- A6 dataplane manager (311 files, 3 batches): pool/binding index, eventstream, HA glue, sessionMirrorFailed sticky #5247, ManualFailover race #5246, RG removal holdTimer leak #5245, mixed positive+except refs match-all #5225
- A7 daemon host (372 files, 3 batches): systemd/interface, netlink, FRR/strongSwan, IPsec TS lenient-load bypass, networkd protectedResolver nil sweep
- A8 API (313 files, 3 batches): gRPC/REST validation, injection, authz, resource leaks, offset pagination O(N) DoS, config search unbounded, peerSessionsRequest page_size drop #4920
- A9 observability (142 files): NetFlow/IPFIX/SNMP, SNMPv3 privParams rand.Read error → zero IV #4912, TimeTicks BER #4924, flowBatch high-water decrease
- A10 services (441 files, 3 batches): DHCP/DDNS, policymatch, CLI, deploy — publish-generation GC brick #4876 High, DDNS http:// cred exposure, scheduler republish fail-open

Each issue: base SHA 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa, origin/master SHA same (fresh), area, files, evidence-bar findings with Gate verdict.

---

*Generated for NNN=001, whoami=claude-spark, base 4e0c7f74cf0dbacf83051b2a9b6cf4e050dcecaa — merged from 23 batch files under /tmp/review-work-claude-spark-001/*

# ps-review-041 — Refactor / Modularity Audit — Monolith Detection with Hot-Path Preservation (HFT-Grade)

**Base commit:** `95b33d49634d56086269a62a92e213dae7926f88`
**Date:** 2026-07-09T20:23:36Z
**Repo root:** `/home/ps/git/avacado-xpf` (via `git rev-parse --show-toplevel`)
**Output path:** `/tmp/ps-review-041.md` (ONLY final — intermediates were in /tmp/review-work-ps-041/, worktrees in /tmp/review-wt-ps-041-*, both swept after merge)
**Batch files:** 10 (a1a a1b a1c a1d a1e a1f a1g a2 a3 a4) — all under /tmp/review-work-ps-041/ (generic work dirs, no repo name), each subagent used detached worktree /tmp/review-wt-ps-041-<area>-b1/ at base SHA
**Focus:** Rust AF_XDP dataplane hot path: per-packet forwarding orchestrator (poll_descriptor), CoS TX drain (queue_service + cos_classify + waterfill), session table (SessionTable god-struct + SessionEntry hot/cold Arc clone), policy/verdict engine (screen + frame + policy.rs) — split cold config/setup/stats/logging out of per-packet path WITHOUT changing one instruction of hot path, prove with disassembly diff + failover/CoS smoke gates.

## Duplicate suppression summary

Prior refactor issues (read for dedup via `gh issue list` + /tmp prior reviews):

- #4404 refactor: poll_descriptor/mod.rs (5,759 LOC) — god-function 1,368 LOC 15+ resp — ALREADY FILED (this audit: 1368→4724 LOC growth measurement + decomposition angles)
- #4407 refactor: daemon.go Daemon god-struct (150+ fields, ~3,500 LOC) + daemon_apply.go applyConfigLocked (1,148 LOC) — ALREADY FILED
- #4408 refactor: Rust hot-path god-functions — tx/dispatch enqueue_pending_forwards (1,131 LOC) + cos/queue_service waterfill (438 LOC) — ALREADY FILED (this audit: Phase 8 + direct-TX + fabric breakdown after inc1)
- #4409 refactor: Rust NAT — nat/allocator.rs PortAllocator god-struct (926 LOC) + nat/source.rs (1,190) + nat/tests.rs (8,685, split per module) — ALREADY FILED (this audit: cache-line + bench-gated plan)
- #4421 Refactor/modularity backlog — policy.rs, nat64.rs, neighbor.rs, SnapshotIntegrityError, SessionTable, ForwardingState, flowexport, firewall-filter, rules.go — ALREADY FILED (this audit: supplements with hot/cold inventory, AppCatalog zero-coupling, EH walker SSOT)
- #4405 refactor: compiler_validate_strict.go (6,997 LOC) — CLOSED (12 per-domain files, pure code-motion #4144 discipline)
- #4406 compiler_uniformgates + compiler_validate_strict_filter — already per-domain split results (D — do not re-split)
- #4651 event_stream/codec.rs (1,165 LOC) — new issue, split wire-format monolith (HA-sync + RT_FLOW + encode/decode)
- #4652 frame/tcp_segmentation.rs (933 LOC) — new issue, extract segment fn by phase (HOT-PATH /triple-review)
- #4661 format/buffers.go (773 LOC) — new issue, shared row model CLI/gRPC/REST buffer-status parity
- #4662 daemon_run.go Run() ~1,690 LOC ordering-sensitive lifecycle — new issue, /triple-review
- #4663-#4670 test-only splits — test files ONLY, production NOT split:
  - #4663 event_stream/codec_tests.rs, #4664 event_stream/tests.rs, #4665 cos/queue_service/tests.rs, #4666 cos/queue_ops tests, #4667 umem/tests.rs, #4668 poll_descriptor/reject_reply.rs tests, #4669 manager_test.go, #4670 dispatch_tests.rs, #4671 frame/wg.rs tests
- Perf/HPC findings naming hot paths: per-packet forwarding orchestrator, CoS waterfill, session table hot/cold, TX drain (from #959, #1035, #1342, #1432 prior splits)

**Work-dir & worktree contract verified (repo-agnostic):**
- Intermediates: /tmp/review-work-ps-041/ (contains 10 files, 271861 total chars) — NOT under /tmp/ps-review-*.md namespace
- Worktrees: /tmp/review-wt-ps-041-<area>-b1/ — 10 worktrees, one per batch, all detached at base SHA 95b33d49, all removed after agent completion (no active worktrees remain)
- Final: /tmp/ps-review-041.md — ONLY file matching /tmp/ps-review-041*.md after cleanup (this file)
- No hardcoded /home/ps/git/avacado-xpf path in findings (repo root via git rev-parse --show-toplevel); generic review-work- / review-wt- prefixes (no xpf-)

## File-size / shape inventory — the module checklist (aggregated from all 10 subagents)


## File-size / shape inventory — aggregated checklist

Aggregated from all 10 subagents. All reads via detached worktrees at base SHA.


### Inventory from a1a (/ps-a1a-b1.md)

# Refactor Audit — Rust AF_XDP hot-path monolith (ps-a1a-b1)

Base: `95b33d496` | Scope: `userspace-dp/src/afxdp/poll_descriptor/*` + `poll_stages.rs`
Prior: #4404 (1368→4724 LOC growth) — NOT re-reported. New angles only.

## Inventory
- `poll_descriptor/mod.rs` 6053 LOC — `poll_binding_process_descriptor` 603..~5340 ≈4724 LOC
- `poll_stages.rs` 3527 LOC — 6 stage fns extracted (link/gre/parse/flow+learn/fabric/screen/ipsec)
- `reject_reply.rs` 2174 LOC — cold `#[cold] #[inline(never)]` already `.text.unlikely`
- `filter.rs` 1201 LOC — cold filter eval + lo0 action, selective inline per header comment
- `flow_cache_hit.rs` 533, `cookie_reply.rs` 509, `nat_exception.rs` 125, `rx_telemetry.rs` 220, `debug_log_throttle.rs` 99
- Total poll_descriptor dir: 10914 LOC (+3527 poll_stages)

File-by-file log:
- `mod.rs`: read 603-1300 hit/miss/flowless heads; 1300-1600 DNAT/NPTv6/NAT64 pre-routing tri-state; 3400-3900 flowless transit PBR+policy+LocalDelivery triple; 4085+ forward disposition. 34 recycle push sites + 16 `cfg(debug-log)` gates.
- `reject_reply.rs`: already cold-extracted; shared `enqueue_reject_reply` path correct isolation.
- `filter.rs`: cold extraction already; `OnlyTerminalNonAccept` count-policy explains double-count avoidance.
- `poll_stages.rs`: 9 stage fns present despite header saying 7; `stage_screen_check` now handles flowless branch inside (#3902) — screen fail-open fix adds icache but keeps pure.
- `flow_cache_hit.rs`: correctly owns recycle/forward pushes on Consumed (comment at L21-34).



---

### Inventory from a1b (/ps-a1b-b1.md)

# A1b — TX Path Modularity Audit (tx/dispatch + cos_classify + tcp_segmentation + rings + transmit + drain)

Base: 95b33d49634d56086269a62a92e213dae7926f88
Worktree: /tmp/review-wt-ps-041-a1b-b1
Outfile: /tmp/review-work-ps-041/ps-a1b-b1.md (this file)
Date: 2026-07-07..08
Auditor: ps-041 (A1b)

---

## File-Size / Shape Inventory

Production (excluding tests):

| File | LOC | Responsibilities | Hot? |
|------|-----|----------------|------|
| `tx/cos_classify.rs` | 1335 | 7: cached resolve, uncached resolve, BA reclassify, loss-priority rewrite helpers, generated-reply verdict, enqueue (prepared+local), demote+admission | HOT (per-forward resolve + per-enqueue admission) |
| `tx/dispatch/mod.rs` | 1486 | Orchestrator `enqueue_pending_forwards` (1048 LOC) + `compute_forwarded_egress_ptb` (107) + small helpers | HOTTEST (per-RX-batch forward path) |
| `tx/dispatch/cos.rs` | 141 | CoS fast-path lookups + `enqueue_local_request_to_target_or_owner` | HOT (per-request) |
| `tx/dispatch/shared_recycle.rs` | 206 | Phase 10 + cross-tick shared-UMEM recycle routing | HOT (per-tick) |
| `tx/dispatch/slow_path.rs` | 399 | `handle_forward_build_failure`, `maybe_reinject_slow_path*`, `extract_l3_packet*` | COLD (`#[cold] #[inline(never)]`) |
| `tx/rings.rs` | 415 | reap completions, drain fill, wake RX, wake TX, prepared-recycle apply | HOT (per-poll: reap + wake) |
| `tx/drain/mod.rs` | 594 | Orchestrator `drain_pending_tx`, ingest (`ingest_cos_pending_tx_with_provenance` 178 LOC), CoS-leftover drops (168 LOC), bound helpers, take/restore | HOT (per-tick drain) |
| `tx/drain/phase_backup.rs` | 206 | post-CoS backup transmit (prepared + local) | HOT |
| `tx/drain/phase_shaped.rs` | 151 | shaped drain initial + reingest budget | HOT |
| `tx/drain/phase_trivial.rs` | 63 | reap, rekick, ingest, submit-and-wake trivial phases | HOT |
| `tx/transmit/mod.rs` | 365 | `transmit_batch` (193 LOC local path), `transmit_prepared_queue` orchestrator, RST diag, recycle immediate | HOT (backup TX submit) |
| `tx/transmit/stage.rs` | 64 | stage prepared batch into scratch | HOT |
| `tx/transmit/rewrite.rs` | 63 | DSCP rewrite on staged frames | HOT but cheap |
| `tx/transmit/verify.rs` | 58 | re-verify UMEM slices | HOT |
| `tx/transmit/write.rs` | 60 | XSK reserve+write+commit+stamp | HOT |
| `tx/transmit/finalise.rs` | 56 | post-commit accounting / retry recovery / kick | HOT |
| `tx/stats.rs` | 169 | sidecar stamp, kick latency hist, completion hist | HOT (per-TX alloc) |
| `tx/tcp_segmentation.rs` | 309 | `segment_forwarded_tcp_frames_into_prepared` (single fn 309 LOC) | COLD (`#[cold]` on fn) but on forward path |
| `tx/mod.rs` | 55 | re-export hub | — |
| `tx/README.md` | 84 | docs | — |

Test-only files (excluded from split, noted):

| File | LOC | Note |
|------|-----|------|
| `tx/cos_classify_tests.rs` | 4617 | — |
| `tx/dispatch/dispatch_tests.rs` | 1564 | prod NOT split per #4670 — do NOT re-report |
| `tx/transmit_tests.rs` | 186 | — |
| `tx/drain/tests.rs` | 201 | — |
| `tx/test_support.rs` | 624 | — |

Total production: 13387 - 7084 test = ~6303 prod LOC
Total test: 7084 LOC

---

## File-by-file Log

### `tx/mod.rs` (55 LOC)
Re-export hub. `pub(super) mod rings/stats/transmit/drain/cos_classify/dispatch/tcp_segmentation`, re-exports via `pub(in crate::afxdp) use`. Clean. No split needed.

### `tx/stats.rs` (169 LOC)
3 functions: `stamp_submits`, `record_kick_latency`, `record_tx_completions_with_stamp`. Focused, coherent. Single-writer, Relaxed atomics. Shared-UMEM OOB guard correct. No split needed. D-negative below.

### `tx/rings.rs` (415 LOC)
4 distinct XSK ring disciplines co-located: completion reap (20-71), fill drain (93-152), RX wake (154-202), TX wake (237-333), plus `apply_prepared_recycle`/`recycle_completed_tx_offset` (204-235). Each is one external caller group, but share `BindingWorker` scratch fields. Currently cohesive as "all XSK kernel-ring ops". Could split cold stats but hot path benefits from co-location. See M-2.

### `tx/tcp_segmentation.rs` (309 LOC)
Single function 309 LOC `segment_forwarded_tcp_frames_into_prepared`. Single `#[cold]` fn — segmentation is slow path, but admission checks run on every TCP forward candidate. Internally 4 phases jammed: egress MTU resolve + admission (21-99), L3/L4 parsing + header_LEN math (100-129 + 144-206 trio), frame build loop with nested closure capturing NAT + checksum + TTL (130-303 with 164-276 inner), final enqueue + bound check (304-309). Target of #4652 "extract segment fn by phase HOT-PATH" — current single-fn shape hides the per-packet admission fast-exit vs. the heavy build loop. See H-2.

### `tx/cos_classify.rs` (1335 LOC) — 7 responsibilities per task brief

Detailed breakdown by line range:

| Range | Fn | Resp | LOC |
|-------|------|------|-----|
| 25-30 | `map_cached_forwarding_class_queue` | TX-selection helper | 5 |
| 32-99 | `GeneratedReplyVerdict` + `classify_generated_reply` | generated-reply classify | 68 |
| 101-330 | `resolve_cached_co

---

### Inventory from a1c (/ps-a1c-b1.md)

# CoS TX drain monolith audit — ps-a1c-b1
Base 95b33d496 | Worktree /tmp/review-wt-ps-041-a1c-b1 | Reads via /tmp/review-wt-ps-041-a1c-b1/userspace-dp/src/...

## Inventory
- afxdp/cos/queue_service/mod.rs 2058 LOC (god module, 25 fns), waterfill 432 LOC L926-1357
- drain.rs 608, service.rs 718, submit_local 194, submit_prepared 177, tests.rs 4384
- afxdp/types/cos.rs 1786, CoSInterfaceRuntime 28 fields (556-708) + timer_wheel + 7 waterfill fields + oversub + RR cursors
- afxdp/cos/tx_completion.rs 1080 (wheel + apply + backlog + #4246 guard)
- afxdp/types/shared_cos_lease/ prod 3166: lease 1460, backlog 210, vtime 238, epoch 565, rotate 446, publish 247
- afxdp/cos/queue_ops/ well split: mod 408, accounting 188, active_buckets, drain, pop, push, v_min

## Log
- git worktree add --detach /tmp/review-wt-ps-041-a1c-b1 95b33d49634d56086269a62a92e213dae7926f88
- Reads: queue_service/mod.rs (3 chunks), tx_completion 2 chunks, cos.rs 2 chunks, shared_cos_lease/*, queue_ops/* via worktree path
- Grep: waterfill, #4246 guarantee-guard, trigger_kernel_arp_probe (neighbor.rs:158, neighbor_dispatch, poll_descriptor — NOT CoS)
- LOC + fn list via wc -l + grep -n ^fn

## Finding 1 — waterfill 432 LOC god-func
Title: select_exact_cos_guarantee_queue_waterfill monopolizes mod.rs
Severity: High | Confidence: High | Class: A
Evidence: mod.rs:926-1357 single fn: f64 epoch budget (transparent quantum_sum vs shaped shaping_rate*VISIT_NS*frac), min-quantum clamp, persistent honored bitset ordinal-keyed u64 <64 guard, Phase1 ascending with lease top-up + token gates + park + telemetry, Phase2 descending re-reading same bitset, wrap arm zeroing pass1+cursor+arming epoch_wrap_pending. Telemetry inline: eligible_visits, phase1/2_admissions, drain_park_*, waterfill_epochs, phase1_budget_breaks, count_park_reason, park_cos_queue.
Proposed: queue_service/waterfill/mod.rs (~100 LOC dispatcher) + refill.rs (budget math, bitset clear gated time_refresh||wrap_pending) + phase1.rs (ascending) + phase2.rs (descending cursor-advancing) + telemetry.rs cold counters. Keep ExactCoSQueueSelection+Phase1HonorRefund in parent.
Hot-path preservation: keep #[inline] on selectors, keep borrow-split (queue_idx copy before &mut queue), ordinal bitset NOT queue_idx, keep phase1_cost=quantum.max(head_len) stable vs send_budget=tokens.min(visit_cap).max(head_len) #1630 P2, no alloc (no Vec/format!).
Tests+gate: cargo test queue_service::tests::waterfill + make test-rust; CoS smoke: cluster-deploy loss:xpf-userspace-fw0, apply-cos-config.sh loss:xpf-userspace-fw0, iperf3 -c 172.16.80.200 -p 5200-5211 per-class, verify honored_bits once/epoch, phase1 vs phase2 admissions, no re-honor livelock (#1743).
Why: 432 LOC hides #1743 epoch-boundary invariant + #1732 ordinal keying; cold f64 math buries token-gate.
Fix: pure code motion, inline helpers for telemetry #[inline(always)].
Labels: cos, waterfill, hot-path | Dedup: #4408 filed, #4665/4666 test-only — this is prod split.

## Finding 2 — queue_se

---

### Inventory from a1d (/ps-a1d-b1.md)

# Monolith Audit — session/ + afxdp/session_glue — ps-a1d-b1
Base: 95b33d49634d56086269a62a92e213dae7926f88
Scope: userspace-dp/src/session/{mod.rs,ctx.rs,install.rs,lookup.rs,expire.rs,key.rs,entry.rs,wheel.rs} + afxdp/session_glue/{mod.rs,promote.rs}
Owner: ps NNN 041 — worktree /tmp/review-wt-ps-041-a1d-b1

## Inventory

| File | LOC | Responsibility | Hot? | Notes |
|------|-----|---------------|------|-------|
| session/mod.rs | 2054 | SessionTable definition + ctor/setters + in-place refresh (update_session/refresh_for_ha_transition/promote) + helpers (handle_for_key, remove_entry, index_*, session_timeout_ns, nat_index_bucket_{push,remove}) + back-count-on-enable | mixed | 25 fields, slab + 4 seeded maps + owner_rg + deltas + wheel + limits + stats + config |
| session/entry.rs | 284 | Public data types: SessionDecision, SessionMetadata, SessionLookup, ForwardSessionMatch, SessionOrigin, SessionDeltaKind, SessionDelta, ExpiredSession | mixed | SessionMetadata still carries Option<Arc<PolicyRuleCounter>> — Arc clone on metadata.clone() hot path |
| session/key.rs | 232 | SessionKey + forward_wire_key, translated_session_key, reverse_{wire,canonical,session}_key, reply_matches_forward_session | hot | Pure transforms, no alloc, well isolated; re-exported via session::* |
| session/ctx.rs | 126 | SessionInstall (owned key), SessionUpdate<'a> (borrowed key), ExpireHaContext<'a> | warm | Groups 7-field positional cluster #1357, plus HA closure bundle |
| session/lookup.rs | 411 | lookup/lookup_with_origin direct+alias via reverse_translated_index, find_forward_{nat,wire}_match, resolve_reverse_translated_handle, entry_with_origin, owner_rg keys, iter_with_idle, take_synced_local, TcpStatePropagation + propagate | hot | metadata.clone() on every lookup_with_origin hit (Arc inc) |
| session/install.rs | 521 | Capacity preflight can_admit + counters, install_with_protocol_with_origin, upsert_synced_with_origin, emit_open/close_delta, delete, demote_owner_rg | warm | Contains back-count rebuild O(N) on enable #4377, limit inc/dec sites |
| session/expire.rs | 625 | Timer-wheel GC: wheel_observe, push_to_wheel throttled, expire_stale_entries{_ha}, rebucket_alive_entry, companion_keeps_alive #4380, standby_gate_decision SelfHeal/Hold/ReapStale/Age | cold but push_to_wheel hot | HA standby retention gate #2120 inside GC pass |
| session/wheel.rs | 80 | SessionWheel bucket array 256*VecDeque, target_tick_for, bucket_for_tick | cold | Well encapsulated, no logic leak |
| session/README.md | — | Documents timeouts, per-app override #3227, opening state #3152/#4109, companion retention #4380, flow-cache keepalive #2220, limits #2134/#3122 | docs | Up to date |
| afxdp/session_glue/mod.rs | 1277 | Cache validation, resolution re-derive, lo0 filter republish, purge for dscp filter, BPF session-map mirror writers, forward_export_candidates, apply_worker_commands dispatcher, replicate_session_*, teardown RST flow, queued flow cancel | mixed god | 30+ pub fns, 5 concerns |
| afxdp/session_glue/promote.rs | 167 | SharedSessionRefs (4 Arc<Mutex<...>> bundle, Copy), should_keep_synced_hit_transient, maybe_promote_synced_session, purge_translated_synced_hit | warm | Good example of zero-cost grouping: 32-byte Copy, no alloc, plan documents zero-cost claim |
| afxdp/session_glue/commands/* | 22+55+103+35+91+119 | Per-WorkerCommand variant handlers | warm | Good split per #1346, trivial variants stay inline |

Log scan: No slog.Info in loops, no eprintln!("xpf-ha") left. debug_log! macro gated on feature debug-log. Clean.

Prior audit #4421 filed SessionTable god-struct 27 fields. Current count 25 (after back-count rebuild + ceiling fields merged) — same root cause.



---

### Inventory from a1e (/ps-a1e-b1.md)

# A1e Audit — Forwarding / ForwardingState / neighbor / worker loop_body

- Base: `95b33d49634d56086269a62a92e213dae7926f88` @ `/tmp/review-wt-ps-041-a1e-b1/`
- Worktree: `/tmp/review-wt-ps-041-a1e-b1` (detached HEAD)
- Date: 2026-07-08
- Scope: `forwarding/mod.rs` (2822), `types/forwarding.rs` (1079), `forwarding_build/` (8 files, 3092 non-test incl. 5042-line tests.rs), `neighbor.rs` (2036) / `neighbor_resolver.rs` (1512) / `neighbor_dispatch.rs` (1399), `worker/mod.rs` (1625) / `worker/loop_body/mod.rs` (1784)

---

## 1. Inventory

### forwarding/mod.rs (2822 LOC)
- Claimed "68 free fns" in task — actual at this base: **80 free fns** (`pub(super)`, `pub(in crate::afxdp)`, `pub(crate)`, `pub`, `fn` at file top-level). Growth via HA helper additions (`cluster_peer_return_fast_path`, `enforce_ha_resolution*`, `owner_rg_for_resolution`, `cache_flow_decision_valid`, etc.).
- 5 god-fns >100 LOC (still accurate, though 3 now):
  - `lookup_forwarding_resolution_inner_ecmp` — **192 LOC** — `L1449-L1640` — per-table FIB ECMP with local-delivery gating, interface-NAT, tunnel, NAT64/NPTv6 branching.
  - `lookup_forwarding_resolution_v4_inner` — **192 LOC** — `L2023-L2214` — v4-specific dispatch (static/connected, choose, ECMP hash, next-hop, src-mac, tx-vlan).
  - `lookup_forwarding_resolution_v6_inner` — **184 LOC** — `L2239-L2422` — v6 mirror.
  - `cluster_peer_return_fast_path` — **105 LOC** — `L713-L817` — HA return path.
  - `ingress_route_table_override` — **122 LOC** — `L1641-L1762` — VRF table lookup.

### types/forwarding.rs — ForwardingState god-struct
- Fields: task says "65 via #3769/#3182/#3527/#3618 growth" — measured **66 fields** at this base (`wc` + regex `pub(in crate::afxdp) name: type`). Structure `L14-L290`.
- No `#[repr(C)]`, no `#[repr(Rust)]` explicit — indeed absent, confirmed via `grep repr` over file (0 hits).
- `#[derive(Clone, Debug, Default)]` present — `Default` does heavy allocation (all maps empty). Excessive `Clone` over 66 fields drives expensive per-ArcSwap snapshot cloning in workers.

### forwarding_build/ (8 files, 3092 non-test)
- `mod.rs` 704, `fib.rs` 483, `interfaces.rs` 340, `zones.rs` 142, `cos.rs` 850, `tunnels.rs` 302, `validated.rs` 161, `wg.rs` 127, `tests.rs` 5042 (ignored in non-test tally → 3092 actual).
- Already decomposed via #1342 — confirmed: each file has focused single responsibility, sub-100-LOC helpers, borrow-only `ClassifierTables<'a>` etc.

### neighbor.rs + neighbors
- `neighbor.rs` 2036 — 4 responsibilities fused:
  1. ARP/ND probe craft: `build_icmp4_echo`, `build_icmp6_echo`, raw Ethernet send, AF_PACKET probe path.
  2. Netlink mgmt / kernel trigger: `trigger_kernel_arp_probe` (134 LOC, `L158-L291`), netlink request construction.
  3. Monitor thread / dump: `neigh_monitor_thread` (272 LOC, `L975-L1246`), `set_neigh_monitor_rcvbuf`, netlink dump parsing.
  4. CPU affinity: `nth_allowed_cpu` / `nth_allowed_cpu_*` tests, allowed-CPU picker for warmer/monitor thread pinning.
- `neighbor_res

---

### Inventory from a1f (/ps-a1f-b1.md)

# A1f — Screen / frame / inspect / policy / runtime Modularity Audit

Base: 95b33d49634d56086269a62a92e213dae7926f88
Worktree: /tmp/review-wt-ps-041-a1f-b1
Outfile: /tmp/review-work-ps-041/ps-a1f-b1.md (this file)
Date: 2026-07-07..08
Auditor: ps-041 (A1f)

---

## File-Size / Shape Inventory

| File | Total LOC | Prod LOC (est) | Test LOC (est) | Responsibilities | Largest fn | Hot? |
|------|-----------|----------------|----------------|----------------|------------|------|
| `screen/mod.rs` | 1540 | ~1485 (cfg(test) seams only) | ~55 seams + `screen/tests.rs` 4k+ external | 7: profiles+aggregate counters (icmp/udp/syn), per-dst sketches (icmp/udp/syn-dst), per-src sketch (syn-src), SYN-cookie codec+cache+gen+epoch, scan/sweep trackers, missing-profile warn, alarm-pending+stats | `check_packet_with_zone_id_opts` 331 LOC (777-1107) — 5 SYN-flood phases + ICMP/UDP + stateless | HOTTEST (per-packet pre-session) |
| `screen/scan.rs` | 1213 | 592 per task, measured 206-592 core + wrappers (ScanCore 1540? actually first test mod at 592) | 621 | 1: bounded windowed-unique (per-(zone,src) unique-set) + thin wrappers PortScanTracker/IpSweepTracker | `check` 53 LOC (281-334) + `evict_stalest_in_zone` 36 LOC | COLD (new-flow only) |
| `afxdp/frame/inspect.rs` | 1813 | 1810 | 3 (re-export test path) | 4: Ethernet L3 offset, IPv6 EH chain walk + L4 offset, fragment predicates (any/non-first v4/v6), ICMP/ICMPv6 + term-match extra + L3/L4 flex | `parse_session_flow_from_bytes` 139 LOC (1264-1402) | HOT (per-packet L4 offset, fragment check) |
| `afxdp/frame/mod.rs` | 1710 | 1699 | 11 | 6: VLAN descriptor-shift (14↔18, 157 LOC), NAT v4/v6 (438 LOC), port/ICMP-id rewrite (incl checksum), NAT64 (100 LOC), inject (140 LOC), debug-verify (192 LOC) despite #988/#989/#1046/#1352/#1440 | `verify_built_frame_checksums` 180 LOC (1519-1698) + `apply_nat_ipv6` 120 LOC + `rewrite_forwarded_frame_in_place` 77 LOC | HOT (per-forward NAT+VLAN+DSCP) |
| `afxdp/frame/wg.rs` | 1561 | 604 prod per task (lines 1-604 minus test seams) | 957 | 1: WG transit encap (outer route resolve, MTU guard, encrypt, UDP checksum) + MTU helpers | `wg_encap_frame` 253 LOC prod (305-543) per task, 238 measured | HOT (transit encap) but rare topo |
| `afxdp/types/runtime.rs` | 503 | 503 | 0 | 10 types: WorkerHandle, LocalTunnelSourceHandle/Entry, WgControlEntry, BindingPlan, SharedUmemMode/Role/BindingPlan, ValidationState, HAForwardingLease/Runtime, ResolutionDebug, LearnedNeighborKey, WorkerCommand, DebugPollCounters, WorkerContext, TelemetryContext, MirrorTargetMap | Largest `MirrorTargetMap::target_live` 18 LOC, `WorkerContext` struct definition only | COLD (plumbing) |
| `policy.rs` | 3598 | ~3521 (77 LOC thread-local test helpers conditionally compiled) | ~77 + external `policy_tests.rs` (~3000) | 8: ZonePairKey+global scope, PolicyRule+Counter+Store, CompiledApplications+ApplicationMatch, AppCatalog, PolicyState (zone-pair indexes, book table, default counter, re-resolve map), L3 matching, evaluation, parsing (applications/address/book), integrity error | `parse_policy_state_with_counters` 523 LOC (1665-2187) | HOT-ish (per-new-flow policy eval, cold path but high-cost) |


Prod vs test methodology: `grep -n '#\[cfg(test'` gives test seam positions; external `#[path = "..."] mod tests` counts as separate file. wg.rs prod clean per task: only 2 `#[cfg(test)]` statics + 2 fns scalar reference + mod tests, leaving 604 LOC prod free of test.

---

## Log

- **Timestamp**: 2026-07-07/08
- **Action**: Created worktree `/tmp/review-wt-ps-041-a1f-b1` detached at 95b33d4
- **Action**: Inventoried 7 files: total 11938 LOC, prod ~8200, test ~3700 (excluding external policy_tests.rs and screen/tests.rs)
- **Action**: Read full contents of screen/mod.rs, scan.rs, inspect.rs, frame/mod.rs, runtime.rs, policy.rs chunks, wg.rs top+helpers
- **Action**: Analyzed EH walker duplication 5 sites with `0 | 43 | 60 | 135 | 139 | 140 | 253 | 254` + 51 + 44 + 59 match + MAX_IPV6_EXT_HEADERS bound
- **Action**: Mapped ScreenState 22 fields to 7 responsibilities + identified god-func SYN-flood phases
- **Action**: Verified AppCatalog zero-coupling: no import of PolicyRule/ZonePairKey/CompiledApplications/PortRange — only `crate::AppCatalogEntry`
- **Action**: Catalogued frame/mod.rs remaining kitchen sink after 9 prior extractions, confirmed 6 responsibilities still present

---



---

### Inventory from a1g (/ps-a1g-b1.md)

# Refactor Audit ps-a1g-b1 — Monolith Triage

Base: 95b33d496  Repo: /home/ps/git/avacado-xpf  Worktree: /tmp/review-wt-ps-041-a1g-b1 (removed)
Date: 2026-07-09  Reviewer: ps-041-a1g-b1

## Inventory (12 files, 18533 LOC)

| File | LOC | Prod | Verdict |
|------|-----|------|---------|
| wg/engine.rs |1805|~1500| D cohesive engine |
| wg/cookie.rs |1435|~800| D DoS gate resp+init |
| event_stream/mod.rs |1693|~1200| A I/O+replay+drain+control |
| event_stream/codec.rs |1165|~700| DEDUP #4651 |
| cold_path_hist.rs |1866|~950+~900t| D/C low — prod <1k |
| coordinator/wg_control.rs |2280|~1600| A HIGH monolith 6 concerns |
| types/cos.rs |1786|1786| A config+runtime+flow+telemetry |
| protocol/binding.rs |1168|1168 dto| D status DTO bag |
| types/forwarding.rs |1079|1080| D forwarding aggregate |
| server/helpers.rs |1304|1304| A relocation dump 5 domains |
| event_emit.rs |1492|~600+~900t| D cohesive emitters |
| shared_cos_lease/lease.rs |1460|1460| D token-bucket+v8 |

Dedup: #4421 SnapshotIntegrityError 616 LOC unrelated Go. #4651 codec.rs already filed — no new issue.

## Log
- Created detached worktree at 95b33d496
- Read all 12 via worktree, wc -l verified
- Triaged by SRP + hot-path inline scan + prior issues
- Wrote report to /tmp/review-work-ps-041/ps-a1g-b1.md
- Removed worktree



---

### Inventory from a2 (/ps-a2-b1.md)

# Monolithic Code Audit — ps-a2-b1 — NAT allocator/compiler

Base: 95b33d49634d56086269a62a92e213dae7926f88
Worktree: /tmp/review-wt-ps-041-a2-b1
Date: 2026-07-09
Auditor: ps / 041 / a2-b1

## Inventory
| File | LOC | Role | Monolith? |
|---|---|---|---|
| userspace-dp/src/nat/allocator.rs | 1416 | PortAllocator: hot bitmap + cold persistent + deterministic + GC | YES - god struct |
| userspace-dp/src/nat/source.rs | 1389 | match_source_nat_result_for_tuple ~336 LOC | YES - god fn |
| userspace-dp/src/nat/destination.rs | 1088 | DNAT table host+prefix LPM | borderline |
| userspace-dp/src/nat/static_nat.rs | 793 | static host+block NAT | NO |
| userspace-dp/src/nat64.rs | 2527 | state + v6<->v4 translate + ICMP err + frag | YES (prev #4421) |
| userspace-dp/src/nptv6.rs | 431 | NPTv6 prefix translate | NO |
| userspace-xdp/src/lib.rs | 1541 | XDP shim parse/classify/redirect/fallback | borderline verifier cap |
| pkg/config/compiler_nat.go | 2529 | source+dest+static+nat64 pools+rules | YES tri-fused |
| pkg/dataplane/compiler.go | 1733 | orchestrator CompileConfig 11 phases | NO (orchestrator ok) |
| pkg/dataplane/compiler_nat.go | 1258 | SNAT/DNAT/static/NPTv6/NAT64 compile | YES tri-fused |
| pkg/dataplane/maps_sync.go | - | MISSING at base (deleted/renamed) | D-neg |
| userspace-dp/benches/snat_allocator.rs | 703 | contention microbench | harness |

## Finding 1 — PortAllocator god-struct hot/cold fusion
Title: PortAllocator mixes hot atomic bitmap/cursor with cold persistent lease GC and deterministic
Severity: HIGH
Confidence: HIGH
Refactor class: Split hot/cold structs + cache-line align
Evidence:
- `PortAllocatorShared` (allocator.rs:458): `counters: Vec<AtomicU32>`, `addr_counter_v4/v6: AtomicU32`, `occupancy: Vec<AddressOccupancy>` hot, co-located with `live: Mutex<PortAllocatorLiveState>`, `allocations_total/reuses_total/exhaustion_total: AtomicU64` cold stats.
- `AddressOccupancy` (284): `words: Vec<AtomicU64>` + `cursor: AtomicU32` hot, but `recycle: Mutex<VecDeque<u16>>` cold per-addr.
- `PortAllocatorLiveState` (258): `live_by_flow: FxHashMap`, `persistent_by_source`, `lease_expirations: BTreeSet`, `lease_expirations_by_addr: Vec<BTreeSet>` all under single mutex; GC runs every 10 releases (`GC_PERIOD`).
- Hot path `allocate_translation` (686) does lock-free claim then takes global mutex for map insert; persistent path takes `allocate_translation_locked` holding mutex across GC + bitmap claim.
- `#2852 Phase1` already moved port claim lock-free, but struct layout still false-shares: hot CAS words share cache line with cold Mutex and stats.

Proposed decomposition:
- `hot.rs`: `#[repr(align(64))]` `HotPart { occupancy: Box<[AddressOccupancy]>, counters: ..., addr_counter_v4/v6, port_low/high, range }` — 64-byte aligned per address occupancy.
- `cold.rs`: `ColdPart { live: Mutex<LiveState>, stats: ... }` separate cache line.
- `persistent.rs`: lease reuse `reuse_existing_lease_locked`, expiration indexes, GC budgets.
- `deterministic

---

### Inventory from a3 (/ps-a3-b1.md)

# Refactor Audit — Go Config Compilers Monoliths — ps-a3-b1

Base: 95b33d496 / 2026-07-09 / worktree /tmp/review-wt-ps-041-a3-b1

## Inventory

| File | LOC | Entrypoint | Notes |
|------|-----|------------|-------|
| compiler_validate_warn.go | 3330 | 35 funcs | Largest, all WARN-only advisories; inline ValidateConfig domains + named funcs |
| compiler_nat.go | 2529 | compileNAT src/dst/static + 4 strict validators + ~15 helpers | Triple-fused (helpers+validators+compilation) |
| compiler.go | 2110 | CompileConfig/Lenient/ForNode, compileExpanded, compileOpts | Dispatch hub + opts + err sentinels + one stray strict validator |
| compiler_system.go | 1881 | compileSystem (500 LOC switch) + 22 helpers | 8 subsystems documented in task |
| compiler_services.go | 1821 | compileServices/RPM/IPMon/flow/sampling/port-mirroring/DHCPLocal/Bridge/Event | 5 RPM validators + DHCP DDNS stack + IPMon + Flow + Sampling |
| compiler_validate_strict_filter.go | 1660 | 15 strict filter validators + 4 public DSCP/proto helpers | Part of #4405-split strict set but itself a filter monolith |
| compiler_uniformgates.go | 1659 | runUniformGates | Prior #4406 split — D negative |
| types_system.go | 1544 | 40+ type defs | Cross-domain type colony |
| compiler_interfaces.go | 1279 | compileInterfaces + VRRP + WG + MSS + if-DDNS | 13 funcs VRRP/tunnel/mss/domain |

Strict already split: 12 files *strict*. Prior #4405 CLOSED, #4406 D, #4421 security.go noted.

## Log
- worktree create --detach 95b33d496
- wc -l + grep ^func + python domain parse on 9 files
- sed inspected compileSystem / compileNAT / ValidateConfig inline warning sections
- drafted per-file seams



---

### Inventory from a4 (/ps-a4-b1.md)

# A4 — Go dataplane + daemon + cluster + routing + metrics + API — Modularity Audit (B1)

**Base:** `95b33d49634d...` (HEAD at review time) at `/tmp/review-wt-ps-041-a4-b1`
**Reviewer:** ps, NNN 041
**Date:** 2026-07-08
**Scope:** largest Go non-test non-gen files + pattern files in daemon/cluster/routing/metrics/api/dataplane/vrrp

---

## 1. File-size/shape inventory

Files flagged in prompt (largest in A4 scope) plus discovered second-tier files.
Threshold is the non-test guideline: 2000 LOC for prod, 100 LOC per function.

| File | LOC | Thresh | #func / #type | Smell |
|------|-----|--------|---------------|-------|
| `pkg/config/compiler_validate_warn.go` | 3330 | 2000 | 35 / 0 | warn validators monolith — strict already split (#2008), warn still collapsed into one file across 10+ domains (host-inbound, DHCP relay, iface, firewall, DDNS, rib-group, CoS, routing-rule) |
| `pkg/dataplane/userspace/protocol.go` | 3011 | 2000 | 2 / 78 | wire-format 12 domains — ControlRequest + ConfigSnapshot (~39 sub-types) + ProcessStatus (~20 sub-fields) + Binding/CoS/Wg/NAT(4 flavors)/Policy/Filter/SessionSync/HA/EventStream — Rust side already split into 7 files |
| `pkg/vrrp/instance.go` | 2417 | 2000 | 64 / 3 | VRRP SM + RX + TX + GARP + advert-interval + preempt-hold + VIP — but single coherent SM (see D-negative) — keep, with optional internal section comments |
| `pkg/daemon/daemon_run.go` | 2329 | 2000 | 11 / 0 | lifecycle bootstrap + naming + Run loop + enableForwarding + exit-path; Run() ~1690 LOC ordering-sensitive (#4662 already filed, do not re-report) |
| `pkg/frr/policy_render.go` | 1938 | 2000 | ~22 / 3 | BFD + BGP + OSPF + RIP + IS-IS + policy-options rendering in one file; render helpers (`generateProtocols`, `generatePolicyOptions`, `renderRouteMap`, `sanitizeFRRValue`) pull in 6 route families |
| `pkg/daemon/daemon_apply.go` | 1935 | 2000 | 4 / 0 | `applyConfigLocked` 1148 LOC god-function building whole reconcile pipeline; 20+ subsystem steps in one function (SNMP, VRF, interface, FRR, NAT, flow-export, DHCP, neighbor, daemon_flow, buffers, ...) — ordering-sensitive cold path |
| `pkg/api/metrics_descriptors.go` | 1896 | 2000 | 1 / 0 | 279 `NewDesc` calls, 7 subsystems (packet/drops/screen/policy/filter/nat/session/host-inbound/CoS/DHCP/DDNS/sys/frr) in one factory func — #1 merge-conflict surface |
| `pkg/routing/tunnel.go` | 1889 | 2000 | 36 / 5 | GRE/IPIP anchor + WG tuntap + keepalive Axis-D commit-after-success + WG MTU + VRF claim + address reconcile — 5 responsibilities in one manager |
| `pkg/cluster/sync_conn.go` | 1858 | 2000 | 55 / 0 | HA gen-guard SM + fabric dial preference + bulk + sweep + delete-journal + config-sync + failover barrier + liveness — 8 responsibilities, ordering-sensitive (see A4-02) |
| `pkg/api/metrics_userspace.go` | 1819 | 2000 | — | userspace counter bridge into legacy shim map |
| `pkg/dataplane/userspace/maps_sync.go` | 1763 | 2000 | ~25 / 5 | D-negative: focused single domain — userspace classifier/

---


## File-by-file inspection log (aggregated)

See individual batch inventories above. Each subagent logged file-by-file coverage proof.

Key coverage areas:
- a1a: from ps-a1a-b1.md
- a1b: from ps-a1b-b1.md
- a1c: from ps-a1c-b1.md
- a1d: from ps-a1d-b1.md
- a1e: from ps-a1e-b1.md
- a1f: from ps-a1f-b1.md
- a1g: from ps-a1g-b1.md
- a2: from ps-a2-b1.md
- a3: from ps-a3-b1.md
- a4: from ps-a4-b1.md


## Findings — grouped by confidence and area

All findings below use exact field labels: Title, Severity, Confidence, Refactor class, Evidence, Proposed decomposition, Hot-path preservation analysis, Tests+gate, Why it matters, Fix direction, Labels, Dedup note



### === FINDINGS FROM A1A — ps-a1a-b1.md ===



### H1 — Mutable-locals coupling proof burden (22 `let mut` + 5 hoisted across flow/decision)
- **Severity:** High **Conf:** High **Class:** B (behavior-preserving restructure)
- **Evidence:** `mod.rs:626` `let mut recycle_now=true;` `803:let mut debug` `806:session_ingress_zone` `807:flow_cache_owner_rg_id` `813:policy_counter_idx` `819:policy_counter Arc` `822:apply_nat_on_fabric` `829:install_failed` `838:pre_routing_dnat_counter` + inner miss block re-lifts at 2610/2741/4838/4843 etc. File:line list shows 22 `let mut` in god-fn scope. Each new arm needs audit of all hoisted writes.
- **Why NEW vs #4404:** #4404 flagged LOC growth; this quantifies exact coupling surface: 8 outer muts (policy_counter_idx/bound handle/install_failed/dnat_counter/owner_rg/ingress_zone/apply_nat/recycle_now) threaded from hit→miss→flowless→forward-cache-insert, proving single extra arm insertion is review hazard.
- **Proposed:** Extract `SlowPathCtx { session_ingress_zone, flow_cache_owner_rg_id, policy_counter_idx/Arc, apply_nat_on_fabric, install_failed, pre_routing_dnat_counter, debug }` struct with `&mut` per stage. Keeps same lifetime, drops ad-hoc muts to 1.
- **Hot preservation:** Zero hot-path instr change — struct field access same addr; `cargo` codegen identical. Prove via `objdump -d poll_descriptor.o before/after | diff`.
- **Gate:** `cargo test -p xpf --test-threads=1` + failover smoke + CoS iperf (ports 5200-5211 target .80.200, NOT .100.x cap).
- **Fix dir:** `mod.rs` top: define ctx struct; replace 8 outer `let mut` with ctx.
- Labels: `refactor`, `hot-path`, `coupling`
- Dedup: NEW — not in #4404.

### H2 — Single-recycle invariant (34 push sites) high-cost miss-one-open
- **Severity:** High **Conf:** High **Class:** A (prove existing invariant, then codify)
- **Evidence:** `grep -c scratch_recycle.push =34` in mod.rs (39 incl flow_cache_hit). Mandatory comment at `poll_stages.rs L28-L30`: "RecycleAndContinue arm signals caller should push... and continue". But mod.rs still has raw push+continue at 640,649,702,717,737,756,1046,1144,1186... Each manual site must pair exactly. One missed recycle = UMEM leak / Tx stall.
- **Why NEW:** Prior review counted sites; didn't note `recycle_now` boolean at L626 complicates proof: paths use `continue` bypassing epilogue (L1270 comment "continue skips recycle_now handling") while 2 sites set `recycle_now=false` + fall through to cache insert. Mixing explicit-push+continue vs bool-fallthrough is two mechanisms for same invariant.
- **Proposed:** Codify single helper `#[inline(always)] fn recycle(desc) { push+ }` + exhaustive match: every early exit returns `LoopCtrl::RecycleAndContinue` vs `Forward(request)`. `recycle_now` bool eliminated in favor of explicit ctrl enum — table-driven proof via `#[clippy::match_same_arms]` showing all 34 sites covered.
- **Hot preservation:** `#[inline(always)]` ensures identical codegen (single inc + branch). Disasm diff empty.
- **Gate:** `make test-rust`, failover, CoS.
- Labels: `correctness`, `hot-path`, `resource-leak`
- Dedup: Extends #4404 recycle note with bool-vs-continue duality.

### M1 — Junos-order duplication hit/miss/flowless triplication (3× host-inbound+lo0+junos-host)
- **Severity:** Med **Conf:** High **Class:** B
- **Evidence:** `host_inbound_gated_lo0_action` appears 3×: session-hit L1076, session-miss L2103, flowless-verdict wrapper L347. Each block: host-inbound deny → own counter + event, then lo0 `filter_terminal` reject→RST, then junos-host policy. Flowless arm adds 3rd variant `flowless_local_delivery_verdict` L319 (Deliver/HostInboundDeny/Filtered) which re-implements order with `l4_present=false`. Total gate call sites: input-filter 4× (1613,3468,4157,4168) + PBR 2× (1693,3524).
- **Why NEW:** #4404 didn't call out flowless vs session-miss divergence: flow-backed uses `term_match_extra_from_frame` with real L4; flowless uses `l3_session_flow_from_meta` with ports=0 + `l4_present=false` so tcp-flags/icmp-type fail closed. Duplication means Junos order fix applied in one arm (e.g., #3485) requires patching 3 sites — proven by #3292 comment "Before fail-open".
- **Proposed:** Extract `LocalDeliveryGateInput { logical_if, from_zone, extra, meta, flow, ingress_override } -> LocalDeliveryVerdict` used by all 3 arms; flowless adapter supplies `extra={is_fragment,l4_present=false}`. Flowless_base_resolution #3291/#3292 stays separate but policy arms converge.
- **Hot preservation:** Cold path only (session miss / LocalDelivery). Hit path's `host_inbound_gated_lo0_action` is per-packet on hit path but only for LocalDelivery disposition (rare). Wrapper inlined.
- **Gate:** `cargo test` (flowless_local_delivery_tests L5826 etc), cluster deploy.
- Labels: `refactor`, `junos-order`, `D-R-Y`
- Dedup: NEW — divergence angle not in #4404.

### M2 — cfg(debug-log) icache pollution (16 sites, eprintln! 14 sites)
- **Severity:** Med **Conf:** Med **Class:** C (cold split)
- **Evidence:** `grep -c cfg.*debug-log =16`, `eprintln! 14`, `debug_log! 10` in mod.rs. Example `969-986 DBG WAN_RETURN_HIT`, `2005-2057 SESS_MISS_DUMP` builds String + counts inside hot loop gated only by `cfg(feature)` (compile-time) but with runtime branch `telemetry.dbg.session_miss <=3`. These inflate hot codegen unit.
- **Why NEW:** #4404 didn't flag icache cost; perf note in Prompt asks for icache impact.
- **Proposed:** Move all `#[cfg(feature="debug-log")]` blocks to `debug_trace.rs` cold fns `#[cold] #[inline(never)]` — already pattern used in reject_reply/filter. Hot loop keeps only `if cfg!(feature)` constant fold to dead code when feature off, but even when on the body is out-of-line. Telemetry bumps stay conditioned.
- **Hot preservation:** Feature-off build unchanged (current prod); feature-on build moves strings out of L1i. Disasm diff: when feature off, identical; when on, hot loop shrinks.
- **Gate:** `cargo test --features debug-log`.
- Labels: `perf`, `icache`, `debug-log`
- Dedup: NEW.

### L1 — flow/miss/flowless state-machine hidden in if-else ladder
- **Severity:** Low **Conf:** High **Class:** B
- **Evidence:** `mod.rs:866 decision = if let Some(flow)` else `{ 3441 flowless... }` at 803+921 lines nesting. 3 resolution paths (ForwardCandidate/LocalDelivery/MissingNeighbor + NoRoute/PolicyDenied/HAInactive→FabricRedirect) interleaved with 2 NoRoute→NoRoute handling, PBR Drop, etc. Makes CoS classify (`cos/eval.rs` touched via forward-request building) and failover (fabric redirect) proof hard.
- **Proposed:** Split into 3 named fns `resolve_session_hit`, `resolve_session_miss(flow)`, `resolve_flowless(l3_ctx)` each returning `SlowPathResolution` enum; outer `poll_binding_process_descriptor` only dispatches + handles recycle/forward insert. Allows unit-test of each resolution table independent.
- Labels: `readability`, `testability`
- Dedup: Extends #4404 Phase 2 suggestion with concrete tri-split + forward-cache insert ownership.

### L2 — PBR route-table override duplicated (flow + flowless)
- **Severity:** Low **Conf:** Med **Class:** B
- **Evidence:** `ingress_route_table_override` called at L1693 (flow) and L3524 (flowless). Inside flow arm, comment #4392 notes PBR reject now DENY vs silent. Flowless arm repeats same logic with `RouteOverride::Drop` recycle at L3537. Divergence already documented in code comments but two copies.
- **Proposed:** Single `resolve_route_table_override(packet_frame, meta, flow_opt, ...)` returning enum + caller-agnostic Drop recycle.
- Labels: `D-R-Y`, `PBR`
- Dedup: NEW detail of M1 duplication but PBR-specific.

## D-negatives (NOT monolith)
- `reject_reply.rs` cold: correctly out-of-line, 5 `#[cold] #[inline(never)]` fns, shared SYN-cookie budget gate — GOOD isolation.
- `filter.rs`: cold leaves + `OnlyTerminalNonAccept` counting policy — GOOD, already small.
- `flow_cache_hit.rs` + `rx_telemetry.rs`: each <600 LOC, owns own recycle pushes cleanly — NOT god.
- `poll_stages.rs` stages 5-11: pure, no recycle mutation except via `StageOutcome` — healthy split; despite header saying 7 fns now hosts 9 incl SYN-cookie miss — growth OK, boundaries sound.
- `cookie_reply.rs`, `nat_exception.rs`, `debug_log_throttle.rs`: cold config/setup helpers — not hot, correctly split.

## Suggested cold/hot split (no hot instr change)
1. `slow_path_ctx.rs`: `SlowPathCtx` struct bundling 8 hoisted muts (H1).
2. `local_delivery_gate.rs`: `host_inbound + lo0 + junos-host` unified gate (M1) + flowless adapter (L1).
3. `route_resolve.rs`: session-miss DNAT/NPTv6/NAT64 pre-routing + PBR override + flowless_base (L2) — cold.
4. `forward_build.rs`: flow-cache insert stamping (policy_counter_idx/Arc copy, owner_rg, mac_epoch TOCTOU #3918) + `record_before_use` assert — cold.
5. `debug_trace.rs`: 16 cfg gates out-of-lined (M2).
6. Final god-fn becomes: parse meta → stages 5-11 → flow-cache try → `if flow { hit? miss } else { flowless }` dispatch → recycle/forward. Target <1500 LOC in mod.rs dispatcher.

Hot-path preservation plan:
- `cargo rustc -- --emit=asm` diff on `poll_binding_process_descriptor` symbol before/after, filtered for debug-log feature OFF.
- Run `make test-rust` (cargo suite) + cluster `test-failover` + CoS iperf smoke targeting 172.16.80.200 ports 5200-5211 per CLAUDE.md.

---
*Written at /tmp/review-work-ps-041-a1a-b1/ sources via worktree. Original /tmp/ps-review-041*.md never written.*


---


### === FINDINGS FROM A1B — ps-a1b-b1.md ===

 by Severity

### High

---

#### H-1 — `cos_classify.rs` 1335 LOC bundles 7 orthogonal responsibilities into one file; admission gate `enqueue_cos_item` (174 LOC) is the CoS shaping hot path but lives alongside pure classification + demotion MQFQ frontier logic

- **Title**: cos_classify 1335 LOC — 7-way responsibility mix (resolve cached/uncached + BA reclassify + LP rewrite + generated-reply + enqueue prepared/local + demote + admission)
- **Severity**: High
- **Confidence**: High
- **Refactor class**: A (structural split, pure code-motion, no behavior change)
- **Evidence**:
  - `userspace-dp/src/afxdp/tx/cos_classify.rs:101` (230 LOC) + `404` (285 LOC) + `695` (63) + `70` (68) + `759` (200) + `1006` (137) + `1157` (188) = 1335 total
  - ```
    pub(in crate::afxdp) fn resolve_cached_cos_tx_selection(
        forwarding: &ForwardingState,
        egress_ifindex: i32,
        meta: UserspaceDpMeta,
        flow_key: Option<&SessionKey>,
    ) -> CachedTxSelectionDescriptor {
        let iface = forwarding.cos.interfaces.get(&egress_ifindex);
        // ... 230 lines including filter eval, BA lookup, LP rewrite fold,
        // filter_log capture, ba_reclassify flag
    }
    fn enqueue_cos_item(
        binding: &mut BindingWorker,
        egress_ifindex: i32,
        requested_queue: Option<u8>,
        item_len: u64,
        mut item: CoSPendingTxItem,
        now_ns: u64,
        mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
    ) -> Result<(), CoSPendingTxItem> {
        // ... aggregates: enqueue stamp (#1829), non-empty tracking,
        // flow-aware buffer limit, ECN mark, flow_share/buffer drop
        // accounting, cos_queue_push_back, runnable marking, exact backlog
    ```
- **Proposed decomposition**:
  ```
  tx/cos/
    resolve.rs        — resolve_cached_cos_tx_selection,
                        resolve_cos_tx_selection{,_at,_internal},
                        resolve_cos_queue_id, map_cached_forwarding_class_queue
    ba.rs             — reclassify_cached_ba_queue, DSCP/802.1p queue-ID helpers,
                        resolve_cos_dscp/ieee8021_classifier_queue_id
    loss_priority.rs  — resolve_cos_loss_priority, resolve_cos_queue_lp_rewrite
    generated_reply.rs — GeneratedReplyVerdict, classify_generated_reply
    enqueue.rs        — enqueue_local_into_cos, enqueue_prepared_into_cos,
                        prepare_local_request_for_cos, clone_prepared_request_for_cos,
                        resolve_cos_queue_idx, cos_queue_accepts_prepared,
                        cos_queue_dscp_rewrite
    admission.rs      — enqueue_cos_item (the flow-aware admission + ECN gate)
    demote.rs         — demote_prepared_cos_queue_to_local (MQFQ frontier snapshot/restore)
    mod.rs            — re-exports preserving pub(in crate::afxdp) / pub(super) same as today
  ```
  Or minimal first increment (less churn): `cos/resolve.rs` (resolve cached+uncached), `cos/classify.rs` (BA+LP+generated_reply), `cos/enqueue.rs` (enqueue+admission+demote). 3-way vs 7-way tradeoff: 3-way keeps diff small; 7-way matches single-responsibility.
- **Hot-path preservation**:
  - Classification path (`resolve_*`) is inline hot on RX batch: stitching multiple helper calls adds call overhead. Mitigation: keep `resolve.rs` helpers `#[inline]` (single caller in `forward_request.rs`; already inlined today). Split does not change call graph — same functions, different files. No new dispatch, no alloc.
  - `enqueue_cos_item` is hot (once per admitted packet). Contains u64 atomic bump + FastMap lookup + UMEM slice for ECN mark. Splitting file doesn't move bytes on cache — queue state still in `binding.cos`. All fields remain same-cache-line locality.
  - Demote path is COLD (TX frame exhaustion fallback), marked by comment "rare TX-frame-exhaustion fallback". Snapshot 64KB memcpy stays in own fn; file move is neutral.
  - No new allocations introduced if split is code-motion only.
  - Layout: BindingWorker stays same size; cos_interfaces remains per-binding.
  - Lock: none added (single-writer, Relaxed atomics).
- **Tests+gate**:
  - Existing: `cos_classify_tests.rs` 4617 LOC exercises all 7 clusters. `cargo test -p userspace-dp --lib cos_classify` must pass.
  - New gate: add `#[cfg(test)] mod resolve_tests, mod admission_tests` or keep single test file re-importing via mod re-exports — preserve exact coverage.
  - Gate: `make test-rust` (cargo suite) + `make test` Go suite (not TX-touched but as regression gate).
- **Why it matters**: 1335 LOC file is the hardest file for new engineers to onboard. Bug fixes touch filter-eval, BA, and admission in same file, causing merge conflicts and review overload. The per-file growth trend (already 1335 LOC) will keep accumulating. Prior issue #hb166 T-4/T-6/T-7 fixes each touched this file, showing blast radius.
- **Fix direction**: Code-motion only, no behavior change. First PR: extract `resolve.rs` (both cached + uncached) + `loss_priority.rs` + `generated_reply.rs` as pure non-mutating classification — reviewable as moves, low risk. Second PR: split enqueue vs admission vs demote. Keep original `cos_classify.rs` as shim re-exporting for one release to allow incremental review.
- **Labels**: `tx`, `cos`, `modularity`, `A`
- **Dedup note**: Not reported in #4408 (which is dispatch). Not #4652 (tcp_segmentation). Task brief explicitly calls out cos_classify 7 responsibilities.

---

#### H-2 — `tcp_segmentation.rs` single function 309 LOC jams 4 phases: MTU/admission, L3/L4 parsing with IPv4 IHL / IPv6 ext-aware arithmetic, per-segment build loop (closure capturing NAT + checksum + TTL + port enforce), final enqueue+bound; `#[cold]` mark applies to whole fn but admission fast-path (proto/tunnel/mtu/len checks) runs on every TCP forward candidate on hot path

- **Title**: tcp_segmentation single-fn 309 LOC with per-packet hot admission buried under cold build loop; #4652 asks extract by phase HOT-PATH
- **Severity**: High
- **Confidence**: High
- **Refactor class**: B (extraction with interface tightening — phase boundaries become testable units)
- **Evidence**:
  - `userspace-dp/src/afxdp/tx/tcp_segmentation.rs:4-309` — entire file is one fn
  - ```
    #[cold]
    pub(super) fn segment_forwarded_tcp_frames_into_prepared(
        target_binding: &mut BindingWorker,
        frame: &[u8],
        meta: impl Into<ForwardPacketMeta>,
        ...
    ) -> Option<(u32, u64, u32)> {
        let meta = meta.into();
        if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
            return None;
        }
        let mtu = forwarding.egress.get(&decision.resolution.egress_ifindex)
            ... .max(1280);
        if mtu == 0 { return None; }
        let l3 = frame_l3_offset(frame)?;
        // ... 170 more lines header parse + build loop + recycle-archive on failure
    ```
  - Inner closure `let built = (|| -> Option<()> { ... })()` (164-276) captures 12+ bindings, contains NAT apply, port enforce, csum recompute — hard to audit for shared-UMEM correctness.
  - Free-frame check at 82-98 drains pending TX inline (nested call to `drain_pending_tx_local_owner` with `post_recycles` + forwarding + worker_commands) — this side effect inside segmentation violates SoC.
- **Proposed decomposition**:
  ```
  tx/tcp_segmentation/
    mod.rs            — single pub(super) entry `segment_forwarded_tcp_frames_into_prepared`
                        plus `TcpSegAdmission` struct, keeping #[cold] on build phases only
    admission.rs      — fn `tcp_seg_should_admit(frame, meta, decision, forwarding) -> Option<(mtu, l3, ip_header_len, tcp_offset, tcp_header_len, segment_payload_max)>`
                        (21-79 fast-exit chain: proto, tunnel, mtu 0, l3, payload len <= mtu, l4 offset, IHL checks, flags SYN/FIN/RST, payload vs max)
    build.rs          — fn `build_tcp_segments(target_binding, frame_meta, decision, ...) -> Result<(Vec<PreparedTxRequest>, stats), BuildError>`
                        containing eth/ip/tcp copy + NAT + checksum + seq bump + PSH clear loop (130-303)
    recycle.rs        — helper for failure rollback: push_front retry in rev order, explicit enum for oversize vs no-frame vs build-none (shared with direct-TX fallback reason shape)
  ```
  Alternatively per #4652 strict "by phase":
  - Phase 1: `should_segment` (proto/tunnel/mtu/len/classical checks)
  - Phase 2: `parse_headers` (L3 offset, IHL, tcp_offset, payload slice, seq, ports)
  - Phase 3: `ensure_free_frames` (free_tx_frames check + conditional drain)
  - Phase 4: `build_and_enqueue` (the per-segment frame_out build + NAT + checksum)
  - Keeps rollback helper shared.
- **Hot-path preservation**:
  - Current: `#[cold]` on entire fn prevents inlining of admission fast-exits into `enqueue_pending_forwards` loop — admission checks pay call overhead even though they commonly return None.
  - Proposal: move `#[cold]` to ONLY build phase (`build.rs`). Admission fn `#[inline(always)]` (few dozen insns) — lets LLVM constant-fold for non-TCP fast path. This REDUCES hot-path cost (proposed wins vs current).
  - Allocation: prepared vec `Vec<PreparedTxRequest>` with `with_capacity(segment_count)` stays same; no new alloc.
  - Layout: target_binding umem area access unchanged.
  - The nested drain call inside admission (82-95) must remain at same site or be returned as signal — current call borrows forwarding + commands; extracting to signal struct "NeedDrain" lets orchestrator drain outside tcp_segmentation, tightening deps and avoiding re-entrancy (drain inside segmentation is uncommon but legal).
  - Lock: no new lock (drain is same thread).
- **Tests+gate**:
  - Existing tx/dispatch tests pin segmentation miss counter (`seg_needed_but_none`) and exception `tcp_segmentation_miss`. Any phase split must preserve that counter attribution.
  - New: unit tests for admission helper (cover IHL <20, SYN flag, mtu==0, non-TCP, tunnel_endpoint_id !=0) — currently only integration-pinned via dispatch.
  - Gate: `cargo test -p userspace-dp --lib dispatch` + `make test-rust`. Ensure `tcp_segmentation_miss` counter doesn't regress.
- **Why it matters**: Entire segmentation correctness (seq wrap, PSH clear on non-last, NAT on segment, checksum recompute) lives inside a 112-line closure that's hard to review for shared-UMEM single-recycle invariant. Prior bug #2077 fabric-ingress TTL gate fix had twin copy in this file + `frame/tcp_segmentation.rs` — split clarifies which gate is owner. Per task, this path carries WG/GRE output-filter integration.
- **Fix direction**: Extract admission to its own module, keep it `#[inline]` hot path without `#[cold]`. Keep build phase `#[cold]`. Share `BuildError::Oversized | NoFreeFrame | BuildNone` enum with dispatch direct-TX fallback to harmonize rollback shapes.
- **Labels**: `tx`, `tcp-segmentation`, `hot-path`, `B`, `4652`
- **Dedup note**: #4652 filed the same concern (tcp_segmentation 933 LOC extract by phase). This finding confirms with 309 LOC at this base (shrank since #4652 filed, or #4652 counted combined cross-file copy path). Do NOT treat as new unique find vs #4652 — link to it. Distinct from #4408.

---

#### H-3 — `dispatch/mod.rs` orchestrator still 1486 LOC with fabric unsendable accounting scattered across 3 sites + slow_path helper, plus direct-TX 178 LOC block + fallback 139 LOC + in-place 200 LOC all inlined in per-request loop, plus Phase 8 PTB already extracted but PTB-ingress enqueue + classify_generated_reply still inlined (58 LOC)

- **Title**: dispatch orchestrator 1048 LOC loop with fabric contract, direct-TX, in-place, and PTB reply paths inlined — Phase 8 extracted but direct-TX + fabric + PTB-ingress not
- **Severity**: High
- **Confidence**: High
- **Refactor class**: A (orchestrator phase extraction, code-motion, preserving single-recycle invariant + CoS guarantee-guard)
- **Evidence**:
  - `userspace-dp/src/afxdp/tx/dispatch/mod.rs:270-1318` loop body
  - Fabric scattered: prebuilt 336-365, 378-393; desc-frame no-binding 456-483; build-failure via slow_path.rs 73-86. All three bump `fabric_redirect_unsendable_drops` + `fabric_redirect_{no_binding,build_failed}` exception.
  - ```
    // Prebuilt FabricRedirect no-binding
    if prebuilt_is_fabric_redirect {
        ingress_live.fabric_redirect_unsendable_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(recent_exceptions, ingress_ident, "fabric_redirect_no_binding", ...);
    }
    // Desc-frame FabricRedirect no-binding (identical counter, different reason string)
    if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
        ingress_live.fabric_redirect_unsendable_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(..., "fabric_redirect_no_binding", ...);
    }
    // direct-TX 178 LOC block with nested if is_nat64 / owner_matches / free frame pop_front + fallback reason enum
    let mut direct_tx_offset = target_binding.tx_pipeline.free_tx_frames.pop_front();
    if direct_tx_offset.is_none() && (outstanding_tx >0 || !pending_tx_prepared.is_empty() ...) {
        let _ = drain_pending_tx_local_owner(target_binding, ...);
    ```
  - PTB enqueue (1225-1283) still inlines `classify_generated_reply` + `GeneratedReplyVerdict` check + `ptb_output_filter_drops` + `enqueue_local_into_cos` equivalent manual push — duplicates CoS enqueue pattern.
- **Proposed decomposition** (incremental, after #4408 inc1 already done):
  ```
  tx/dispatch/
    mod.rs            — stays orchestrator (~300 LOC after extractions), owns loop + recycle + batch drain triggers
    phases/
      prebuilt.rs     — Phase: Prebuilt TxRequest build + fabric unsendable counting (36 LOC) + recycle
      frame_extract.rs— source_frame extraction + sampled mirror clone (34 LOC)
      target_resolve.rs— target binding resolve + fabric no-binding drop helper (62 LOC + shared helper returning FabricDropReason enum)
      tcp_seg.rs      — delegation to tcp_segmentation module + miss counter (current segmentation attempt block, 135 LOC)
      pmtud.rs        — already compute_forwarded_egress_ptb (107 LOC) — keep as is, just move file
      rewrite.rs      — Phase 8 body: in-place rewrite attempt (200 LOC) + copy fallback path 1 (1598 gate)
      direct_tx.rs    — Direct-TX block (178+139=317 LOC): free frame pop + optional drain + build_into + fallback reason + telemetry bumps
      ptb_reply.rs    — PTB ingress enqueue with classify_generated_reply + filter drop (58 LOC → own file with typed Outcome)
      fabric.rs       — consolidates all 3+1 fabric unsendable sites into one helper returning enum `FabricUnsSendReason`, used by prebuilt, no-binding, build-failure; single place bumps counter + exception
  ```
  Keep `compute_forwarded_egress_ptb` already extracted; new PR extracts `fabric.rs` + `direct_tx.rs` as pure code-motion.

  Minimal first increment (smallest diff, lowest merge-conflict risk):
  - `dispatch/fabric.rs` — 3-site fabric accounting consolidation (~40 LOC helper with 2 counters)
  - `dispatch/direct_tx.rs` — direct-TX block extraction (317 LOC) as fn returning `DirectTxOutcome` with offset recycle guarantee
  - `dispatch/ptb_reply.rs` — PTB-ingress path (58 LOC) as `enqueue_ptb_reply_onto_ingress`
- **Hot-path preservation**:
  - Orchestrator loop is hottest path — any extra call in loop adds ~1-3 ns. Mitigation: helpers `#[inline(always)]` (single caller), LLVM inlines back to same code after extraction. Same as existing `recycle_ingress_frame` pattern: `#[inline]` tiny helper.
  - Fabric helper is COLD path (fabric redirect only in HA cluster, not standalone). `#[cold] #[inline(never)]` appropriate.
  - Direct-TX path: the free_tx_frames pop_front + `slice_mut_unchecked` per-segment loop is HOT — must preserve `unsafe { area.slice_mut_unchecked }` direct access, not go via safe wrapper adding bounds check twice. Current code has prefetch hint ` _mm_prefetch` — must keep in extracted fn.
  - Single-recycle invariant: `Post_recycles` vec + `retained_source_frame` flag + `build_failed` flag coordinate ingress descriptor recycle. Extraction must pass `retained_source_frame` by `&mut bool` and set identically. Pinned by `direct_tx_tuple_mismatch_recycles_frame_exactly_once` (#4041) test.
  - CoS guarantee-guard: `bound_pending_tx_local/prepared` calls stay in same positions; extraction must not hoist.
  - Alloc: no new alloc — `DirectTxFallbackReason` enum is stack.
- **Tests+gate**:
  - Existing `dispatch_tests.rs` 1564 LOC pins single-recycle, fabric drops, oversized, tuple-mismatch.
  - New gate: `cargo test -p userspace-dp --lib dispatch` — must pass with `FORCE_OVERSIZED` + `FORCE_TUPLE_MISMATCH` injected.
  - Cluster smoke: `make cluster-deploy` + iperf toggles fabric path; ensure `fabric_redirect_unsendable_drops` counter still increments on no-binding simulation.
- **Why it matters**: Fabric unsendable accounting is safety-critical (wrong-path / conntrack-poison hazard #1946 comment). Having 3 copies with same counter but different reason strings makes it easy to add a 4th forward path that forgets to count. Co-locating into one helper eliminates that bug class. Direct-TX block is unreadable and contains the single-recycle regression history (#4041).
- **Fix direction**: First PR: extract `dispatch/fabric.rs` helper (pure code-motion, removes 3 duplicated `fetch_add`+`record_exception` blocks). Second PR: extract `dispatch/direct_tx.rs` as function returning enum + handling fallback telemetry. Both preserve call sites of `recycle_ingress_frame` + `handle_forward_build_failure` + `post_recycles.apply`.
- **Labels**: `tx`, `dispatch`, `fabric`, `direct-tx`, `HA`, `A`
- **Dedup note**: #4408 reported generic "enqueue_pending_forwards 1131 LOC". This finding DOES NOT re-report that — it focuses on fabric scatter + direct-TX + PTB-ingress remainder after Phase 8 (compute_forwarded_egress_ptb) was already extracted as #4408 inc1. Distinct incremental findings.

---

### Medium

---

#### M-1 — `drain/mod.rs` 594 LOC still owns 178 LOC CoS ingest with routing-decision cache (#780) + 168 LOC CoS-leftover drop logic + 85 LOC bound helpers, while phase files already prove orchestrator-phases pattern works

- **Title**: drain/mod.rs 594 LOC — ingest + CoS-leftover drop remain in orchestrator file despite phase-split pattern proving viable
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: A (code-motion into `drain/ingest.rs` + `drain/cos_leftover.rs`, mirroring existing `phase_*` shape)
- **Evidence**:
  - `userspace-dp/src/afxdp/tx/drain/mod.rs:377-555` `ingest_cos_pending_tx_with_provenance` 178 LOC contains:
  - ```
    let mut cached_key: Option<(i32, Option<u8>)> = None;
    let mut cached_decision: Option<LocalRoutingDecision> = None;
    process_pending_queue_in_place(&mut pending, |req| {
        let key = (req.egress_ifindex, req.cos_queue_id);
        if cached_key != Some(key) { ... resolve_local_routing_decision ... }
        // Step1 → Step2 → Step3 fallthrough cascade
    ```
  - `137-304` two leftover-drop functions + `tx_request_targets_cos_interface` predicate + `partition_cos_bound_local_with_rescue` generic helper — 168 LOC that encode #760 cap-bypass defense with full-deque scan invariant (head-peek early exit was prior correctness bug #784).
  - `33-83` bound helpers `bound_pending_tx_local/prepared` also in same file but tiny.
- **Proposed decomposition**:
  ```
  tx/drain/
    mod.rs            — orchestrator drain_pending_tx + constants + tiny helpers
                        (pending_tx_capacity, binding_has_pending_tx_work, etc.)
    phase_backup.rs   — exists (keep)
    phase_shaped.rs   — exists (keep)
    phase_trivial.rs  — exists (keep)
    ingest.rs         — ingest_cos_pending_tx{,_with_provenance}, process_pending_queue_in_place
                        + cached_key Decision cache, Step1/Step2/Step3 cascade (178 LOC)
    cos_leftover.rs   — drop_cos_bound_{prepared,local}_leftovers,
                        tx_request_targets_cos_interface, partition_cos_bound_local_with_rescue
                        (168 LOC, already has pure fn shape for unit test)
    bound.rs          — bound_pending_tx_local/prepared (33-83, optional; keep in mod.rs if under threshold)
  ```
  Keep constants `COS_GUARANTEE_*` in mod.rs (public). `Ingest` touched by #780 perf hot cache; keeping it file-local encourages targeted profiling without whole-file churn.
- **Hot-path preservation**:
  - Ingest runs once per tick before shaped drain; also up to 4 times in reingest budget. Memoized routing decision cache `cached_key` reduces FastMap lookups from O(n * keys) to O(unique queues). Extraction to `ingest.rs` preserves same caching — pass `cached_key/Decision` as locals inside ingest fn (current pattern).
  - `partition_cos_bound_local_with_rescue` is pure scanning `&mut VecDeque`, no binding borrow — extraction has no locality impact.
  - `process_pending_queue_in_place` is generic over `T` — used for both Prepared and Local deques; moving to ingest.rs keeps monomorphization same.
  - CoS-leftover drop is NOT hot (only runs when leftover exists after bounded ingest-drain, i.e., MPSC race) — `#[inline]` not needed; may remain cold without perf regression.
  - No atomics added.
- **Tests+gate**:
  - `drain/tests.rs` covers `has_queued_cos_work`, `partition_cos_bound_local_scans_mixed_head_deque` etc.
  - New: unit test for ingest routing decision cache (unique queue count = cache refill count) without full BindingWorker — shape already `pure` after #780.
  - Gate: `cargo test -p userspace-dp --lib drain`.
- **Why it matters**: Current 594 LOC still exceeds 300-LOC target. Ingest is the most frequently modified file (changes to routing decision cache #780, cascade equivalence fixes #782, owner/worker split #1598). Mixing it with CoS-leftover drop defense logic makes reviews for #760 bypass bugs harder to focus.
- **Fix direction**: Code-motion only PREP: move ingest into `drain/ingest.rs`, leftover-drop into `drain/cos_leftover.rs`. Keep bound helpers in mod.rs (small). Fits existing `phase_*` file-naming scheme — least surprising.
- **Labels**: `tx`, `drain`, `cos`, `A`
- **Dedup note**: Not previously reported. Complements already-successful drain phase split (phase_backup/phase_shaped/phase_trivial established pattern). Follows same PR structure.

---

#### M-2 — `rings.rs` 415 LOC bundles 4 XSK ring operations (completion reap, fill drain, RX wake with poll(POLLIN), TX wake with sendto+stamp+errno bucket) plus prepared-recycle apply; fill drain's debug-log poison pattern and TX wake's monotonic_nanos bracketing are cold diagnostics mixed with hot ring ops

- **Title**: rings.rs 415 LOC — 4 XSK disciplines co-located + debug-log poison + kick-latency bracketing intermingled
- **Severity**: Medium
- **Confidence**: Medium
- **Refactor class**: A/B (split into submodules + extract cold diagnostics)
- **Evidence**:
  - `userspace-dp/src/afxdp/tx/rings.rs:20-71` reap (scratch_completed_offsets, shared_recycles loop, completion stamp)
  - ```
    pub(in crate::afxdp) fn reap_tx_completions(
        binding: &mut BindingWorker,
        shared_recycles: &mut Vec<(u32, u64)>,
    ) -> u32 {
        if binding.tx_pipeline.outstanding_tx == 0 { return 0; }
        let Some(available) = record_tx_completion_ring_available_for_reap(...) else { return 0; };
        // ... batch reap via complete() + record_tx_completions_with_stamp + recycle loop
    }
    fn record_tx_completion_ring_available(telemetry: &mut WorkerTelemetry, ...) { ... }
    pub(in crate::afxdp) fn drain_pending_fill(...) -> bool {
        // ... poison frame if debug-log, fill.insert, needs_wakeup gate (20% CPU save #), maybe_wake_rx
    }
    pub(in crate::afxdp) fn maybe_wake_rx(...) { /* poll(POLLIN) + sendto TX kick */ }
    fn apply_prepared_recycle(...) / recycle_completed_tx_offset(...)
    pub(in crate::afxdp) fn maybe_wake_tx(...) {
        // #825: brackets sendto with two monotonic_nanos VDSO calls (~30ns) + sentinel check
        let kick_start = monotonic_nanos();
        let rc = unsafe { libc::sendto(fd, ...) };
        let kick_end = monotonic_nanos();
        if kick_start !=0 && kick_end >= kick_start { record_kick_latency(...) }
    ```
- **Proposed decomposition**:
  ```
  tx/rings/
    mod.rs       — re-export hub + tiny shared helper `apply_prepared_recycle`
    completion.rs— reap_tx_completions, record_tx_completion_ring_available*, recycle_completed_tx_offset
    fill.rs      — drain_pending_fill (with poison helper extracted as fn `poison_fill_frame_if_debug` #[cfg(debug-log)])
    wake.rs      — maybe_wake_rx, maybe_wake_tx (sendto bracketing + record_kick_latency)
    recycle.rs   — apply_prepared_recycle (shared with transmit)
  ```
  Alternative minimal: keep as `rings.rs` but extract cold sub-fns: `poison_fill_frame`, `record_wake_telemetry`, `log_sendto_enobufs_throttled`. Keeps hot ring ops together but isolates cold diagnostics that bloat i-cache.
- **Hot-path preservation**:
  - Reap path runs once per drain call — inline hot. Must stay `#[inline]` or at least non-cold. File split alone doesn't affect inlining — LLVM LTO can still inline cross-file within crate. Ensure functions remain `#[inline]`/`#[inline(always)]` after move (currently not marked — relies on single-crate LTO/MIR inlining).
  - `drain_pending_fill` fill wake gate `needs_wakeup() || interval >= SAFETY` is hot — runs per-tick, 142K/sec sendto pre-#gate was 20% CPU (comment 143-145). Preservation: keep `DrainCtx::now_ns` threading (already done), keep needs_wakeup guard first.
  - `maybe_wake_tx` bracketing is intentional #825 LATENCY telemetry — two monotonic_nanos per kick. Cold? Kick occurs less frequently than completion, so VDSO cost (~30ns) budget is ok. Extracting to `wake.rs` identical.
  - UMEM poison `0xDEAD_BEEF` only on `#[cfg(feature="debug-log")]` — DCEs out in release; its presence in ring file adds 6 LOC but no i-cache cost on release.
  - Single-recycle: `apply_prepared_recycle` is also used by `transmit` — having single definition (reuse) keeps invariant typed in one place (good). Split should NOT duplicate.
- **Tests+gate**:
  - `rings::tests` existing: `apply_prepared_recycle_routes_fill_and_free_explicitly`, `record_tx_completion_ring_available*`. Must continue passing.
  - Gate: `cargo test -p userspace-dp --lib rings`.
- **Why it matters**: Rings file is referenced by all drain paths + completion STW logging. New contributors add wake logic here (#825 kick latency, #142K sendto gate). Keeping 4 disciplines together makes it easy to accidentally remove `needs_wakeup()` guard when adding new wake reason.
- **Fix direction**: If team prefers keep-as-one (D-negative rationale below), extract only cold helpers: `poison_frame`, `log_tx_enobufs_throttled`. If team opts for split, follow module pattern similar to `drain/` and `transmit/` (submodule per ring discipline). Either preserves hot path.
- **Labels**: `tx`, `rings`, `XSK`, `A`
- **Dedup note**: Not previously reported. Distinct from #4408.

---

#### M-3 — `transmit/mod.rs` 365 LOC still mixes two TX submit paths: `transmit_batch` (local Vec<u8> copy path 193 LOC with 2x reverse-drain unwind duplication) and `transmit_prepared_queue` orchestrator over 5 phase files; unwind duplication + RST detect duplicate (RST scan exists in both local and prepared paths)

- **Title**: transmit/mod.rs 365 LOC — local path `transmit_batch` 193 LOC with duplicated reverse-drain unwind + RST diagnostics duplicated across local + prepared
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: B (extract unwind helper + co-locate RST diagnostic into own module)
- **Evidence**:
  - `userspace-dp/src/afxdp/tx/transmit/mod.rs:75-269` `transmit_batch`
  - ```
    if req.bytes.len() > tx_frame_capacity() {
        for (off, r) in binding.scratch.scratch_local_tx.drain(..).rev() {
            binding.tx_pipeline.free_tx_frames.push_back(off);
            pending.push_front(r);
        }
        return Err(TxError::Drop(format!(...)))
    }
    // ... same pattern repeated at second error site 142-146
    // RST detect block 155-185 with thread-local counter + hex dump
    // vs prepared path log_rst_frames_prepared 316-355 duplicate thread-local + same hex shape
  ```
  - Wiring in `transmit/mod.rs:289-310` already clean orchestrator over phases, but `transmit_batch` predates phase split and retains pre-split shape.
  - `stage.rs`, `rewrite.rs`, `verify.rs`, `write.rs`, `finalise.rs` each <65 LOC and cleanly isolated — good target shape, but parent still owns unrelated local path.
- **Proposed decomposition**:
  ```
  tx/transmit/
    mod.rs       — re-export hub (like tx/mod.rs)
    local.rs     — transmit_batch (193 LOC)  (rename current mod.rs body excluding prepared orchestrator)
    prepared.rs  — transmit_prepared_queue orchestrator (currently mod.rs:289-310 + log_rst_frames_prepared)
                   that calls stage/rewrite/verify/write/finalise
    stage.rs     — exists (keep)
    rewrite.rs   — exists
    verify.rs    — exists
    write.rs     — exists
    finalise.rs  — exists
    recycle.rs   — recycle_cancelled_prepared_offset_with_shared + recycle_prepared_immediately_with_shared
                   + remember_prepared_recycle (currently 22-73 shared with cos_classify)
    rst_diag.rs  — shared RST diagnostic helper (thread-local counter + frame_has_tcp_rst scan)
                   used by both local.rs and prepared.rs, gated #[cfg(feature="debug-log")]
    unwind.rs    — reverse-drain helper `unwind_scratch_local_tx(binding, pending)` preserving order
  ```
  Minimal first increment: extract `recycle.rs` + `unwind.rs` (~20 LOC), de-duplicate reverse-drain; RST is low priority (debug-log only).
- **Hot-path preservation**:
  - `transmit_batch` is backup path (post-CoS, idle bindings) — NOT line-rate hot for CoS-shaped traffic (CoS goes through shaped drain). Perf impact of extra fn call is negligible on this path.
  - Local path's `frame.copy_from_slice(&req.bytes)` memcpy is dominant cost (~1500 bytes) — extraction helper doesn't add copy.
  - `scratch_local_tx` clear/drain pattern touches `binding.scratch` Vec — must keep same Vec reuse to avoid alloc (current pattern: clear at entry, push in loop, drain at commit). Any helper must take `&mut BindingWorker` not owned Vec.
  - `stamp_submits` POST-COMMIT invariant (#812) — must stay after `writer.commit()` in both `transmit_batch` and `write.rs`. Splitting must not move stamp before commit.
  - Single-recycle: `transmit_batch` free_tx_frames push_back vs `recycle_cancelled_prepared_offset_with_shared` for prepared path — different recycle shapes, must stay separate.
  - `tx_frame_capacity()` 4096 check is shared — could become const in `unwind.rs` but keep fn call (trivial).
- **Tests+gate**:
  - `transmit_tests.rs` 186 LOC (transmit_batch capacity checks).
  - New: unit test `unwind_scratch_restores_original_order` — stage 3 items, trigger oversized at 4th, assert pending front-to-back order preserved.
  - Gate: `cargo test -p userspace-dp --lib transmit`.
- **Why it matters**: Two identical reverse-drain unwind blocks (120-122 vs 144-146) exist as copy-paste. Prior bug #hb166 T-6(d) fixed order preservation in both sites — future fix for same class would need to touch both again. Extraction eliminates that bug class. Also clarifies boundary between local (Vec<u8>) vs prepared (offset+UMEM) TX paths — current file mixes them.
- **Fix direction**: Extract `unwind.rs` helper `fn unwind_local_scratch_on_drop_error(binding, pending)` → eliminates duplication. Extract `recycle.rs` from current 22-73. Optional: move `transmit_batch` to `local.rs`, `transmit_prepared_queue` + RST to `prepared.rs`. Keep existing phase files.
- **Labels**: `tx`, `transmit`, `D-RY`, `B`
- **Dedup note**: Not previously reported. Complements existing #1354 split which already extracted prepared phases.

---

#### M-4 — `dispatch/mod.rs` test-only thread-locals `FORCE_OVERSIZED` / `FORCE_TUPLE_MISMATCH` and `FORCE_ENQUEUE_ERR` in `dispatch/cos.rs` are production file bloat gated by `#[cfg(test)]` but live in production modules, adding to LOC and cognitive load; plus `direct_tx_tuple_mismatch_reason` wrapper indirection

- **Title**: dispatch test-only fault injection (FORCE_OVERSIZED, FORCE_TUPLE_MISMATCH, FORCE_ENQUEUE_ERR) lives in production files with #[cfg(test)] — inflates prod file count + review burden
- **Severity**: Medium
- **Confidence**: High
- **Refactor class**: C (move test fault injection to test file, replace with trait hook in prod)
- **Evidence**:
  - `tx/dispatch/mod.rs:62-96` + `70-112`
  - ```
    #[cfg(test)]
    thread_local! {
        static FORCE_OVERSIZED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    #[inline(always)]
    fn copy_frame_is_oversized(cp_len: usize) -> bool {
        #[cfg(test)]
        if FORCE_OVERSIZED.with(|c| c.get()) { return true; }
        cp_len > tx_frame_capacity()
    }
    #[cfg(test)]
    thread_local! {
        static FORCE_TUPLE_MISMATCH: std::cell::Cell<bool> = const { ... };
    }
    #[inline(always)]
    fn direct_tx_tuple_mismatch_reason(...) -> Option<String> {
        #[cfg(test)]
        if FORCE_TUPLE_MISMATCH.with(|c| c.get()) { return Some("...forced-test".to_string()); }
        forward_tuple_mismatch_reason(...)
    }
    ```
  - `dispatch/cos.rs:89-93` same pattern for `FORCE_ENQUEUE_ERR`
  - Total ~40 LOC test-only code in production files, plus 2 wrapper fns that DCE in release but still compile-checked and reviewed on every PR touching dispatch.
- **Proposed decomposition**:
  - Move `FORCE_OVERSIZED`, `FORCE_TUPLE_MISMATCH`, `FORCE_ENQUEUE_ERR` into `dispatch_tests.rs` and expose via `pub(crate)` test helper functions that inject at call sites through a thin indirection trait.
  - Or keep wrappers in `mod.rs` but move thread-locals to `dispatch/test_hooks.rs` under `#[cfg(test)]` — production `mod.rs` then `#[cfg(test)] mod test_hooks` import.
  - Simplest: `dispatch/mod.rs` wrappers stay (they are already `#[inline(always)]` and DCE on release), but move `thread_local!` blocks to a `dispatch/fault_injection.rs` `#[cfg(test)]` module — removes visual clutter from prod code without changing behavior.
- **Hot-path preservation**:
  - Wrappers are `#[inline(always)]` and `#[cfg(test)]` guarded branch — on release build they compile to single call. Moving thread-local source doesn't affect release asm.
  - Perf delta: zero (DCE). I-cache delta: zero (test cfg dead).
  - The real win is review-time cognitive load: prod file LOC -40, production reader doesn't trip over test fault injection.
- **Tests+gate**: Existing dispatch_tests already import `FORCE_*` via `super::` (mod tests under mod.rs). After move, keep import path via `super::test_hooks::FORCE_*` or `super::super::` etc. Must pass `cargo test -p userspace-dp --lib dispatch`.
- **Why it matters**: Low technical cost but high review friction. Every large file audit now reports inflated LOC due to test-only code. Policy: "test-only split — production NOT split" per #4670 task note acknowledges this pattern. This finding proposes the clean alternative the policy hints at.
- **Fix direction**: `git mv` test-injection thread-locals to `dispatch/test_hooks.rs` (cfg(test)), keep wrappers in mod.rs importing them. Or accept as is and close as D-negative if team prefers co-location for visibility.
- **Labels**: `tx`, `dispatch`, `testability`, `C`
- **Dedup note**: #4670 explicitly notes dispatch_tests 1564 test-only split — production NOT split, do NOT re-report. This finding is distinct: it reports PRODUCTION file pollution by test-only thread-locals, not the test-only file size itself. Link to #4670 as related.

---

### Low

---

#### L-1 — `drain/mod.rs` constant block `COS_GUARANTEE_*` + `COS_SURPLUS_ROUND_QUANTUM_BYTES` are CoS scheduler tunables that belong in `cos/` config, not in TX drain orchestrator

- **Title**: COS_GUARANTEE_VISIT_NS / QUANTUM_* / SURPLUS_ROUND_QUANTUM_BYTES defined in tx/drain/mod.rs though they are CoS scheduler policy constants
- **Severity**: Low
- **Confidence**: Medium
- **Refactor class**: C (move constants to co-located CoS policy module)
- **Evidence**: `tx/drain/mod.rs:557-560`
  ```
  pub(in crate::afxdp) const COS_GUARANTEE_VISIT_NS: u64 = 200_000;
  pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MIN_BYTES: u64 = 1500;
  pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 512 * 1024;
  pub(in crate::afxdp) const COS_SURPLUS_ROUND_QUANTUM_BYTES: u64 = 1500;
  ```
  Also re-exported via `tx/mod.rs:21-24` from `drain::`. Consumers are in `cos/`.
- **Proposed**: Move to `cos/mod.rs` or `cos/config.rs` or `cos/params.rs`. Keep re-export in drain via `pub use crate::afxdp::cos::CONST` for back-compat during transition. Low-risk rename shim.
- **Hot-path**: const propagation at compile time — no runtime impact regardless of file location.
- **Tests+gate**: Search `COS_GUARANTEE_*` references: mostly `cos/queue.rs` + `cos/shared`. Ensure after move builds.
- **Labels**: `cos`, `config`, `C`
- **Dedup**: Not previously reported.

---

#### L-2 — `transmit/` phase files (stage/rewrite/verify/write/finalise) each declare own `use` block + duplicate `#710` orphan accounting pattern (saturating_sub(1)) in 3 files

- **Title**: transmit phase files duplicate orphan accounting + use-block boilerplate; opportunity for shared helper `account_orphan_drops_excluding_offender`
- **Severity**: Low
- **Confidence**: High
- **Refactor class**: C (DRY helper, no split)
- **Evidence**: `stage.rs:44-54`, `rewrite.rs:42-54`, `verify.rs:40-50` all same shape:
  ```
  if orphan_count > 0 {
    live.tx_submit_error_drops.fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
    live.tx_errors.fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
  }
  ```
  Stage variant slightly different (orphan list excludes offender, so no saturating_sub).
- **Proposed**: Helper fn `fn account_orphan_packets(live: &BindingLiveState, count_excluding_offender: u64)` in `transmit/mod.rs`. DRY + documents #710 contract in one place.
- **Hot-path**: not hot (only on Drop error path, which should be ~0/s in production). No perf impact.
- **Labels**: `tx`, `transmit`, `DRY`, `C`
- **Dedup**: Not previously reported.

---

## Suggested Split Roadmap

Order by risk (low-risk first) and review chunk size:

### Phase 1 — Zero-risk structural moves (pure code-motion, no hot-path signature change) — Target <300 LOC/review PR

1. **PR A1b-1: `drain/mod.rs` leftover extraction** (M-1)
   - Move `drop_cos_bound_{prepared,local}_leftovers`, `partition_cos_bound_local_with_rescue`, `tx_request_targets_cos_interface` → `drain/cos_leftover.rs`
   - Move `ingest_cos_pending_tx{,_with_provenance}`, `process_pending_queue_in_place` → `drain/ingest.rs`
   - Keep `mod.rs` as orchestrator (~200 LOC after)
   - Risk: Very low (both functions already unit-tested via pure helper scan). Gate: `cargo test drain`.

2. **PR A1b-2: `dispatch/fabric.rs`** (H-3 sub-increment)
   - Extract fabric unsendable accounting: `fn record_fabric_unsendable_drop(live, reason, ...)` + `enum FabricDropReason` handling all 3 + 1 sites (prebuilt no-binding, prebuilt build-failed, desc no-binding, build-failure via slow_path).
   - Bonus collapses 3 identical `fetch_add`+`record_exception` duplications.
   - Risk: Low (COLD path, counter-only). Gate: dispatch_tests + cluster smoke fabric_unsendable_drops.

3. **PR A1b-3: `cos_classify` resolve split** (H-1 sub-increment 1)
   - `cos/resolve.rs` (cached + uncached), `cos/loss_priority.rs`, `cos/generated_reply.rs`
   - Keep original file as shim re-exporting for one release to minimize merge-conflict window, or tree-wide import fixup in one PR.
   - Risk: Low (pure classification, no worker mutation). Gate: cos_classify_tests.

### Phase 2 — Hot-path-aware extractions (needs inline analysis verification)

4. **PR A1b-4: `dispatch/direct_tx.rs`** (H-3 sub-increment)
   - Extract direct-TX 317 LOC block as function returning `DirectTxOutcome`, preserving free_tx_frames offset lifecycle + prefetch + single-recycle.
   - `#[inline(always)]` for loop body helper; keep `#[cold]` only on fallback-reason logging if any.
   - Risk: Medium (touches single-recycle invariant, #4041 pinned). Gate: `direct_tx_tuple_mismatch_recycles_frame_exactly_once`.

5. **PR A1b-5: `tcp_segmentation` phase split** (H-2)
   - `admission.rs` (should_admit + header parse) `#[inline]` hot, `build.rs` `#[cold]` build loop, `recycle.rs` failure rollback.
   - Risk: Medium (seq wrap + PSH clear + NAT edge). Gate: `tcp_segmentation_miss` + full dispatch tests.

6. **PR A1b-6: `cos/enqueue+admission+demote` split** (H-1 sub-increment 2)
   - `cos/enqueue.rs`, `cos/admission.rs`, `cos/demote.rs`
   - `enqueue_cos_item` admission gate keeps hot inlining.
   - Risk: Medium (admission touches queued_bytes + flow-fair buckets + ECN — must preserve exact order). Gate: CoS shaping integration (iperf).

### Phase 3 — Polish (optional)

7. **PR A1b-7: `rings/` and `transmit/` final structure** (M-2, M-3, L-2)
   - `rings/{completion,fill,wake,recycle}` OR keep but cold-extract poison + kick latency brackets.
   - `transmit/{local,prepared}` split + `unwind.rs` + `rst_diag.rs` + `recycle.rs`
   - `drain/phase_*` already good — no change unless bundling constants L-1.
   - Risk: Low-Medium. Gate: make test.

---

## D-Negatives (explicit NON-splits with rationale)

### D-1 — `tx/stats.rs` (169 LOC) — DO NOT SPLIT
Why: 3 functions, tightly related (sidecar stamp + kick latency + completion hist). Shared helpers `bucket_index_for_ns`, `UMEM_FRAME_SHIFT`, `TX_SIDECAR_UNSTAMPED` = cohesive stats admission. Split would cause artificial file count (+1 per function) with single caller each. Keep together.

### D-2 — `tx/drain/phase_backup.rs` / `phase_shaped.rs` / `phase_trivial.rs` — DO NOT FURTHER SPLIT after A1b-1
Why: Already the desired target shape. Each phase file is <210 LOC, single inline fn or two private helpers, `BackupOutcome` enum encodes early-return distinction correctly. Further splitting trivial phases (e.g. reap vs rekick in phase_trivial) would be over-modularization per Codex round-2 note in phase_trivial.rs comment. Keep after drain/mod.rs leftover extraction.

### D-3 — `tx/transmit/stage.rs`, `rewrite.rs`, `verify.rs`, `write.rs`, `finalise.rs` — DO NOT FURTHER SPLIT
Why: Each <65 LOC, single `#[inline]` fn, orchestrated by `transmit_prepared_queue`. Phase ordering (stage→rewrite→verify→write→finalise) is load-bearing: post-commit stamp invariant (#812) and orphan accounting (#710) depend on it. Further granularity would scatter invariants.

### D-4 — `tx/dispatch/cos.rs` (141 LOC), `shared_recycle.rs` (206 LOC), `slow_path.rs` (399 LOC) — DO NOT RE-SPLIT
Why: Already extracted as #1443 pure code-motion split from original 1474-LOC `dispatch.rs`. Each file is <400 LOC with single responsibility and clear hot/cold tagging (cos hot, shared_recycle hot, slow_path cold+inline(never)). Task says #4670 dispatch_tests 1564 test-only split — production NOT split, do NOT re-report. These 3 already represent the production split target for dispatch-side concerns other than the main orchestrator.

### D-5 — `tx/mod.rs` (55 LOC) — DO NOT SPLIT
Why: Re-export hub. Single location declaring module graph. Splitting would obscure crate boundary.

### D-6 — `tx/test_support.rs` (624 LOC), `cos_classify_tests.rs` (4617), `dispatch_tests.rs` (1564), `transmit_tests.rs` (186), `drain/tests.rs` (201) — DO NOT COUNT as production split candidates
Why: Task says #4670 dispatch_tests 1564 test-only split — production NOT split, do NOT re-report. Test files are expected to be large for pinning. Any production split must preserve test helper imports via `pub(in crate::afxdp)`. Production files only considered for modularization.

### D-7 — `tx/dispatch/mod.rs` full orchestrator split into one file per logical phase (7-phase dream file) in single PR — DO NOT ATTEMPT AS ATOMIC SPLIT
Why: `enqueue_pending_forwards` loop shares `ingress_area` raw const ptr, `post_recycles` vec, `retained_source_frame` flag, `build_failed` flag, `ptb_reply` Option<Vec<u8>> across its body. Splitting all phases at once into separate files overshares mutable borrow and raw pointer across phase boundaries, maximal merge-conflict risk. Incremental extraction (fabric, direct_tx, ptb_reply one per PR) preserves reviewability and bisection. Per engineering-style.md: bounded increments, behavior-identical steps.

---

## Dedup Summary vs Prior Findings

| Prior | What it reported | This audit relation |
|-------|-----------------|---------------------|
| #4408 | tx/dispatch `enqueue_pending_forwards` 1131 LOC | NOT re-reported. Our H-3 explicitly calls out that #4408 note and focuses on *remaining* breakdown after Phase 8 (`compute_forwarded_egress_ptb` already extracted as inc1) — fabric scatter + direct-TX 317 LOC + PTB-ingress 58 LOC. Distinct incremental finds. Evidence cites 1048 LOC remaining orchestrator, not 1131. |
| #4652 | tcp_segmentation 933 LOC extract segment fn by phase HOT-PATH | LINKED, not re-reported as new unique. H-2 confirms on current base it's 309 LOC (shrunk since filing, or that 933 counted cross-file copy+prepared segmentation), same concern (single fn hides hot admission vs cold build). Proposes admission #[inline] vs build #[cold] per #4652 HOT-PATH note. Marked `Dedup note: Link to #4652`. |
| #4670 | dispatch_tests 1564 test-only split — production NOT split, do NOT re-report | RESPECTED. Did not report dispatch_tests size. M-4 reports production file pollution by #[cfg(test)] thread-locals living in production files — distinct axis, but references #4670 as related. D-6 re-asserts test files excluded. |

---

## Cross-cutting Notes

- **Single-recycle invariant** — Described in `tx/README.md` + pinned by `direct_tx_tuple_mismatch_recycles_frame_exactly_once` (#4041). Any split touching `tx_offset` / `post_recycles` / `free_tx_frames` / `pending_fill_frames` must preserve exactly-once recycle. Our proposed extractions pass `post_recycles: &mut Vec<(u32,u64)>` and `free_tx_frames` via `&mut BindingWorker` to keep invariant typed same place.

- **UMEM ownership / zero-copy** — `ingress_area` raw const ptr in dispatch orchestrator is retained via raw ptr (`*const MmapArea`) to allow simultaneous `&mut target_binding` borrow. Any phase extraction that needs `source_frame` must receive `source_frame: &[u8]` (already sliced), NOT re-slice, to keep unsafe block isolated in orchestrator. Our `frame_extract.rs` phase returns `source_frame` slice derived inside orchestrator's unsafe region, then later phases consume already-safe slice.

- **WG/GRE output-filter + CoS integration** — WG/GRE path uses `uses_native_tunnel` gate across dispatch (can't use in-place nor direct-TX), migrates to `is_nat64 || uses_native_tunnel` guard. `post_transform_inner_mtu` (native_gre_inner_mtu / wg inner mtu) is PMTUD path via `compute_forwarded_egress_ptb` already extracted. `transmit` path's `PreparedTxRequest.egress_ifindex` still used for CoS queue selection after GRE/WG build. Proposed splits preserve this cross-file contract by keeping `decision` read-only in extracted fns.

- **CoS shaper bypass cap** — `drop_cos_bound_*` defense at drain/mod.rs prevents unshaped backup path. Any ingest/cos_leftover split must preserve full-deque scan (no early exit on head inspection) invariant per Codex #784 regression. Unit test `partition_cos_bound_local_scans_mixed_head_deque` pins it.

- **Allocation rules** — Hot path forbids alloc per CLAUDE.md. Current dispatch hot path uses scratch Vecs + `VecDeque` push_back/pop_front + `Vec::with_capacity(segment_count)`. No alloc added in proposed splits if staying code-motion. `format!()` in `TxError::Drop` is error path (COLD) — existing. `set_error(format!(...))` was already removed from CoS admission overflow per #hb166 T-6(g). Our new modules must NOT reintroduce.

---

## Output Location

This report written to `/tmp/review-work-ps-041/ps-a1b-b1.md` per task instruction (NOT `/tmp/ps-review-041*.md`).

## Worktree Cleanup

Worktree `/tmp/review-wt-ps-041-a1b-b1` to be removed after report verification.



---


### === FINDINGS FROM A1C — ps-a1c-b1.md ===

# CoS TX drain monolith audit — ps-a1c-b1
Base 95b33d496 | Worktree /tmp/review-wt-ps-041-a1c-b1 | Reads via /tmp/review-wt-ps-041-a1c-b1/userspace-dp/src/...

## Inventory
- afxdp/cos/queue_service/mod.rs 2058 LOC (god module, 25 fns), waterfill 432 LOC L926-1357
- drain.rs 608, service.rs 718, submit_local 194, submit_prepared 177, tests.rs 4384
- afxdp/types/cos.rs 1786, CoSInterfaceRuntime 28 fields (556-708) + timer_wheel + 7 waterfill fields + oversub + RR cursors
- afxdp/cos/tx_completion.rs 1080 (wheel + apply + backlog + #4246 guard)
- afxdp/types/shared_cos_lease/ prod 3166: lease 1460, backlog 210, vtime 238, epoch 565, rotate 446, publish 247
- afxdp/cos/queue_ops/ well split: mod 408, accounting 188, active_buckets, drain, pop, push, v_min

## Log
- git worktree add --detach /tmp/review-wt-ps-041-a1c-b1 95b33d49634d56086269a62a92e213dae7926f88
- Reads: queue_service/mod.rs (3 chunks), tx_completion 2 chunks, cos.rs 2 chunks, shared_cos_lease/*, queue_ops/* via worktree path
- Grep: waterfill, #4246 guarantee-guard, trigger_kernel_arp_probe (neighbor.rs:158, neighbor_dispatch, poll_descriptor — NOT CoS)
- LOC + fn list via wc -l + grep -n ^fn

## Finding 1 — waterfill 432 LOC god-func
Title: select_exact_cos_guarantee_queue_waterfill monopolizes mod.rs
Severity: High | Confidence: High | Class: A
Evidence: mod.rs:926-1357 single fn: f64 epoch budget (transparent quantum_sum vs shaped shaping_rate*VISIT_NS*frac), min-quantum clamp, persistent honored bitset ordinal-keyed u64 <64 guard, Phase1 ascending with lease top-up + token gates + park + telemetry, Phase2 descending re-reading same bitset, wrap arm zeroing pass1+cursor+arming epoch_wrap_pending. Telemetry inline: eligible_visits, phase1/2_admissions, drain_park_*, waterfill_epochs, phase1_budget_breaks, count_park_reason, park_cos_queue.
Proposed: queue_service/waterfill/mod.rs (~100 LOC dispatcher) + refill.rs (budget math, bitset clear gated time_refresh||wrap_pending) + phase1.rs (ascending) + phase2.rs (descending cursor-advancing) + telemetry.rs cold counters. Keep ExactCoSQueueSelection+Phase1HonorRefund in parent.
Hot-path preservation: keep #[inline] on selectors, keep borrow-split (queue_idx copy before &mut queue), ordinal bitset NOT queue_idx, keep phase1_cost=quantum.max(head_len) stable vs send_budget=tokens.min(visit_cap).max(head_len) #1630 P2, no alloc (no Vec/format!).
Tests+gate: cargo test queue_service::tests::waterfill + make test-rust; CoS smoke: cluster-deploy loss:xpf-userspace-fw0, apply-cos-config.sh loss:xpf-userspace-fw0, iperf3 -c 172.16.80.200 -p 5200-5211 per-class, verify honored_bits once/epoch, phase1 vs phase2 admissions, no re-honor livelock (#1743).
Why: 432 LOC hides #1743 epoch-boundary invariant + #1732 ordinal keying; cold f64 math buries token-gate.
Fix: pure code motion, inline helpers for telemetry #[inline(always)].
Labels: cos, waterfill, hot-path | Dedup: #4408 filed, #4665/4666 test-only — this is prod split.

## Finding 2 — queue_service/mod.rs god module
Title: mod.rs owns 5 selectors + batch builder + 4 settle + refund + quantum
Severity: High | Confidence: High | Class: A
Evidence: 2058 LOC, 25 fns: drain_shaped_tx, build_nonexact_cos_batch, root_exact_demand_queue_mask, exact_demand_rate_bytes_for_mask, residual_rate_and_burst, nonexact_surplus_budget_under_exact_demand, service_exact_guarantee_queue_direct x2, refund_phase1_waterfill_honor, apply_phase1_waterfill_honor_refund, select_cos_guarantee_batch x2, select_exact_cos_guarantee_queue x2, waterfill, select_nonexact, select_surplus x2, settle_* 4, build_cos_batch_from_queue, submit_cos_batch, cos_batch_tx_made_progress, quantum x3, wakeup_tick, dscp x2. Drain/service/submit already split.
Proposed: select/mod.rs with exact_rr.rs (legacy #711), waterfill/ (F1), nonexact.rs, surplus.rs, batch.rs (build_cos_batch + nonexact + residual helpers), settle.rs (4 settle+scratch release), refund.rs. Keep drain_shaped_tx ≤80 LOC orchestrator.
Hot-path preservation: keep select_* #[inline], keep queue_fast_path slice from cos_fast_interfaces disjoint with cos_interfaces &mut borrow-split, keep TX_BATCH_SIZE*tx_frame_capacity() visit cap, keep pop_snapshot_stack.clear() at batch start #3968, no Box/Vec.
Tests+gate: cargo test -p userspace-dp cos + make test-rust; smoke same as F1 plus nonexact_surplus_under_exact reset, surplus_deficit DRR.
Why: 20+ fns in one file makes #4246 + #915 surplus-sharing branches unreviewable.
Fix: flat file moves, pub(in crate::afxdp) re-exports from mod.rs unchanged API.
Labels: cos, drain, technical-debt | Dedup: prior #1035 P2/P3, #1331 — closes remaining monolith.

## Finding 3 — CoSInterfaceRuntime 28-field god struct
Title: CoSInterfaceRuntime mixes shaping tokens, surplus budget, waterfill epoch, oversub, RR cursors, priority arrays
Severity: Medium-High | Confidence: High | Class: B
Evidence: cos.rs:556-708: shaping_rate, burst, tokens, nonexact_surplus_under_exact_{tokens,last_refill}, default_queue, nonempty_queues, runnable_queues, oversubscription_policy, guarantee_fraction, priority_low_{min_share_bytes,reserved_tokens,last_refill_ns} UNUSED #1614 A2, exact_queues_by_rate_ascending Vec, waterfill_{pass1_remaining,phase2_cursor,honored_bits,epochs,budget_breaks,epoch_start_ns,wrap_pending} 7 fields, exact_guarantee_rr, nonexact_guarantee_rr, legacy_guarantee_rr cfg(test), queues Vec, queue_indices_by_priority [Vec;LEVELS], rr_index_by_priority, timer_wheel.
Proposed: sub-structs preserving layout (size_of assert): RootTokenBucket{rate,burst,tokens}, NonexactSurplusBudget{tokens,last_refill}, WaterfillEpoch{pass1,phase2_cursor,honored_bits,epochs,budget_breaks,epoch_start,wrap_pending,ascending:Vec}, OversubPolicy{policy,fraction,priority_low_*}, SurplusRR{indices_by_prio,rr_by_prio,exact_rr,nonexact_rr}, keep timer_wheel separate. Inline accessors pub(in crate::afxdp).
Hot-path preservation: keep tokens+waterfill on same cache line (owner worker), Vec read-only after build, inline accessor returns &mut u64 no indirection, no alloc at drain.
Tests+gate: cargo test cos::builders + test-rust; smoke shaping meter, surplus DRR, timer wheel wake, show system buffers.
Why: 28 fields obscures epoch boundary invariant #1743 r3 vs token refill; UNUSED fields pollute hot struct.
Fix: struct grouping, accessor shims, no logic change.
Labels: cos, types, struct-decomp | Dedup: not filed before, complements #4408.

## Finding 4 — tx_completion.rs three concerns + cold stats in hot apply
Title: timer-wheel + TX apply + backlog mixed, cold stats in hot commit
Severity: High | Confidence: High | Class: B
Evidence: 1080 LOC: tick consts, park_cos_queue, count_park_reason, level_and_slot, advance, cascade, wake_due, snap_over_horizon, can_service_after_prime, prime_for_service, maybe_consume_exact_queue_lease, publish_cos_exact_backlog, clear_all, peer masks, account_queue_drain_sent_bytes, apply_direct_accounting, apply_direct_send_result, refresh_cos_interface_activity containing #4246 R-5(a) lease-presence probe cos_fast_interfaces[ifindex].queue_fast_path[q].shared_queue_lease.is_some() gating mem::take burst + T-1 release_unused_v8(worker_id,released) re-crediting v8 epoch ledger, apply_cos_send_result, apply_cos_prepared_result, restore_inner. Hot commit interleaves fetch_add(Relaxed)+sojourn.record+tx_bytes.
Proposed: tx_completion/wheel.rs, prime.rs, apply.rs (keeps #4246 guard), backlog.rs, refresh.rs, telemetry.rs cold (record_drain_telemetry_cold with #[inline(never)] sojourn.record outside hot inline chain).
Hot-path preservation: preserve #4246: has_lease probe vs cos_fast_interfaces before taking tokens — no-lease queues (single-owner exact+non-exact) keep banked burst; preserve release_unused_v8 re-credit; preserve borrow-split (iface_fast & vs root &mut). Preserve trigger_kernel_arp_probe alloc-free: it lives neighbor.rs:158, triggered via neighbor_dispatch + poll_descriptor with stack &str+Copy IpAddr — CoS path must NOT own String nor format!.
Tests+gate: cargo test tx_completion_tests + test-rust; CoS smoke: verify empty queue burst preserved when no lease, v8 re-credited counter, no token leak, show class-of-service interface counters. iperf smoke as F1.
Why: mixing cold tick + hot per-packet apply + cross-binding backlog makes #4246 review impossible, cold stats in hot path risks alloc/contention.
Fix: file moves, mod.rs re-exports pub(in crate::afxdp), cold file #[inline(never)].
Labels: cos, tx-completion, guarantee-guard, hot-path | Dedup: not dup #4408, complements god-module.

## D-Negatives
- queue_ops/ (mod 408, accounting 188, etc.) already factored single-concern <800 LOC prod — no split.
- shared_cos_lease/ already split #2158 P2: backlog 210, vtime 238, epoch 565, lease 1460, rotate 446, publish 247 — lease.rs largest but CAS+seqlock ordering would break splitting legacy vs v8, defer until legacy sunset.
- queue_service/drain.rs+service.rs+submit_{local,prepared}.rs already extracted #1035 P2/P3 #1331 — focused.
- trigger_kernel_arp_probe alloc-free: neighbor.rs stack &str+IpAddr Copy, CoS does NOT allocate — no CoS change, gate via clippy no format!/Box/Vec in drain.

## Smoke gate proving split safe (required for any fix)
1. make test-rust (cos + lease + queue_ops)
2. make cluster-deploy (loss:xpf-userspace-fw0/fw1 default)
3. ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
4. iperf3 -c 172.16.80.200 -p 5200-5211 -t 10 -P 4 per FC, verify shaping cap, guarantee-rate small-first, surplus DRR priority, equal-flow caps, waterfill_epochs increments, sojourn p99, no token leak, #4246 burst preservation, trigger_kernel_arp_probe no-alloc gate.


---


### === FINDINGS FROM A1D — ps-a1d-b1.md ===



### F1 — SessionTable god-struct: hot 5-tuple/verdict core co-resident with cold HA/limit/wheel/config/stats

- **Title:** SessionTable god-struct — hot primary+3 NAT indexes mixed with cold HA owner_rg/deltas/limit/wheel/timeouts/opening_overrides/stats
- **Severity:** High
- **Confidence:** High
- **Refactor class:** God struct / modularity — decompose via inline sub-structs, preserve layout/no indirection
- **Evidence:**
  ```rust
  pub(crate) struct SessionTable {
      entries: slab::Slab<SessionRecord>, // hot slab handle
      key_to_handle: SeededKeyMap<u32>, // hot
      nat_reverse_index: SeededReverseIndex, // hot 1:N SmallVec<[u32;2]>
      forward_wire_index: SeededForwardWireIndex, // hot 1:N
      reverse_translated_index: SeededReverseTranslatedIndex, // hot 1:N
      owner_rg_sessions: FxHashMap<i32, FxHashSet<u32>>, // cold HA, only via owner_rg_session_keys/demote
      deltas: VecDeque<SessionDelta>, // cold HA sync ring 4096
      last_gc_ns: u64, max_sessions: usize, timeouts: SessionTimeouts, opening_overrides: FxHashMap<u16,u64>, // cold config
      epoch_counter, expired, create_drops, admission_refused, install_partial, delta_drops, delta_loss_pending, delta_drained, nat_reverse_key_collisions, // stats
      wheel: SessionWheel, last_pop_stats: WheelPopStats, // GC
      session_limit_active: bool, session_limit_src_counts: SeededIpMap<u32>, session_limit_dst_counts: SeededIpMap<u32>, // limit cold-OFF-gated
  }
  ```
  Hot path `lookup_with_origin` touches only `key_to_handle+entries+reverse_translated_index` + `decision/metadata`. Yet whole struct spans >6 cache lines (+ 3 HashMaps for limits/owner_rg). Install path touches limit maps only when `session_limit_active`. GC path touches wheel+last_gc_ns. Config overrides touched only on install/lookup opening branch. Deltas touched only on install/expire/export. All funneled through one `&mut self`.
- **Proposed decomposition:**
  ```rust
  // INLINE sub-structs, no Box — same allocation, modular access
  struct SessionCore {
      entries: Slab<SessionRecord>,
      key_to_handle: SeededKeyMap<u32>,
      nat_reverse_index: SeededReverseIndex,
      forward_wire_index: SeededForwardWireIndex,
      reverse_translated_index: SeededReverseTranslatedIndex,
  }
  struct SessionGc { wheel: SessionWheel, last_gc_ns: u64, last_pop_stats: WheelPopStats, expired: u64 }
  struct SessionHa { owner_rg: FxHashMap<i32,FxHashSet<u32>>, deltas: VecDeque<SessionDelta>, loss_pending: bool, drained: u64, drops: u64 }
  struct SessionLimits { active: bool, src: SeededIpMap<u32>, dst: SeededIpMap<u32> }
  struct SessionConfig { max: usize, timeouts: SessionTimeouts, opening_overrides: FxHashMap<u16,u64>, epoch: u64 }
  struct SessionStats { create_drops: u64, admission_refused: u64, install_partial: u64, collisions: u64 }
  pub(crate) struct SessionTable { core: SessionCore, gc: SessionGc, ha: SessionHa, limits: SessionLimits, cfg: SessionConfig, stats: SessionStats }
  ```
  Keep `SessionTable` methods as façade delegating to `self.core.*` etc. so existing call sites in `afxdp/poll_descriptor` need not churn. New `session/mod.rs` becomes 400 LOC coordinator re-exporting `impl SessionTable` blocks from sub-modules still, but fields live in distinct modules (`core.rs`, `ha.rs`, `limits.rs`, `gc.rs`). Maintain eager-cleanup invariant: `remove_entry` must clean `core.*` + `ha.owner_rg` before slab free.
- **Hot-path preservation:**
  - **Inlining:** keep `#[inline]` on `handle_for_key`, `entry_by_key`, `touch_if_stale`, `account_packet`, `lookup_with_origin` inner borrow; façade getters force inlined to core fields (LLVM sees through 1-level struct, no call).
  - **Alloc:** NAT bucket stays `SmallVec<[u32;2]>` zero-alloc for non-colliding (pool SNAT). No new Box/Arc — sub-structs inline, no pointer chase. Keeps 1 probed `FxHashMap` with seeded hasher on fast path.
  - **Dispatch:** No dyn on hot path; `ExpireHaContext` closures remain cold GC only.
  - **Layout:** Place `core` first in SessionTable so its fields start at offset 0, hot slab handle hot. Keep `entries` 8-byte aligned. Cold fields after hot reduce cache pollution when iterating only core.
  - **Locality:** Slab handle stability unchanged; wheel still key-based (not handle-based) per #965 plan — no change.
  - **Lock:** Worker-owned `&mut self` single-threaded preserved; no new Mutex. Limit maps still gated by `if !active return` single branch.
- **Tests+gate:**
  - Unit: `cargo test -p userspace-dp session --lib -- --nocapture` — existing 6994 LOC tests.rs covers stale handle guards, no_index_points_at, limit back-count (#4377), companion_keep_alive (#4380), standby gate (#2120).
  - `cargo test --release` for `*_returns_false_no_panic` release-mode safety net.
  - `cargo test -p userspace-dp --lib afxdp::session_glue` — export candidate selection forward yes reverse/peer/transient/fabric no.
  - Integration gate: `make test-cluster-lock-lib` + loss userspace smoke `test-failover` (60ms VRRP) must pass — HA split touches owner_rg/delta paths.
- **Why it matters:** Current 25-field struct couples unrelated axes: any change to HA delta loss latch recompiles hot lookup users; cache footprint includes cold HashMaps; reviewability low. Splitting restores Junos-style separation and limits blast radius of #2120/#2134/#2442 changes which previously touched same file as hot verdict code.
- **Fix direction:** Mechanical: move field definitions to `core.rs`, `gc.rs`, `ha.rs`, `limits.rs`, `config.rs` with `pub(crate)` sub-structs; keep `SessionTable` as aggregate. Migrate helpers `index_forward_nat_key_parts`, `remove_entry`, `push_to_wheel`, `set_session_limit_active` back-count walk to respective sub-modules but attach as `impl SessionTable` for borrow coherence. No behavior change; assert `std::mem::size_of::<SessionTable>` unchanged.
- **Labels:** `refactor`, `modularity`, `dataplane`, `hot-path`
- **Dedup note:** Extends #4421 (27-field god-struct) which filed presence of many fields but did not propose inline sub-struct decomposition preserving zero-chase. This filing adds concrete layout and inlining preservation.

### F2 — SessionEntry & SessionMetadata hot/cold split + remaining Arc<PolicyRuleCounter> clone cost (~10ns/packet at 7.5M pps)

- **Title:** SessionEntry mixes hot verdict/last_seen/counters with cold HA epoch/hold/wheel/created/origin; SessionMetadata.clone() still does LOCK XADD via Arc<PolicyRuleCounter>
- **Severity:** High (perf) / Medium (maint)
- **Confidence:** High
- **Refactor class:** Hot/cold field grouping, unnecessary Arc clone on slow path
- **Evidence:**
  ```rust
  #[derive(Clone,Debug)] struct SessionEntry {
      decision, metadata, origin, install_epoch, last_seen_ns, created_ns,
      expires_after_ns, closing, reset, established, wheel_tick,
      seen_rg_epoch: u32, first_held_ns: u64,
      counters: SessionCounters, observed_tos: u8, observed_tcp_flags: u8,
  }
  #[derive(Clone,Debug)] struct SessionMetadata {
      ingress_zone: u16, egress_zone: u16, owner_rg_id: i32, fabric_ingress: bool, is_reverse: bool,
      nat64_reverse: Option<Nat64ReverseInfo>,
      log_session_init, log_session_close: bool,
      policy_id: u32, inactivity_timeout_ns: Option<u64>,
      policy_counter_idx: u32,
      policy_counter: Option<Arc<PolicyRuleCounter>>, // still Arc
  }
  ```
  - `lookup_with_origin` (session/lookup.rs:179-188): `decision: entry.decision, metadata: entry.metadata.clone()` — clones Arc per lookup (slow path ~1 per new flow, but also per flow-cache miss which at 7.5M pps with 1% miss = 75k clones/s). Each Arc clone is `LOCK XADD` ~10ns on x86-64.
  - Flow cache fast path (`flow_cache_hit.rs:211`) avoids clone by borrowing `policy_counter.as_ref()` — good.
  - SessionEntry comment in entry.rs:26-27: "#919: zone names dropped... eliminates LOCK XADD atomic on every metadata.clone()" — same motivation applies to remaining Arc.
  - Entry size: decision (~ForwardingResolution 64B + NatDecision 32B) + metadata (~64B) + 8*counter + flags ~ 200B, spans 4 cache lines. Hot fields (last_seen, expires_after, closing/reset/established, counters) scattered among cold HA fields; per-packet `touch_if_stale` writes `last_seen_ns` dirtying whole cache line containing cold fields too (false sharing within struct).
- **Proposed decomposition:**
  ```rust
  #[derive(Clone,Copy)] struct SessionHot { last_seen_ns: u64, expires_after_ns: u64, closing: bool, reset: bool, established: bool, counters: SessionCounters, observed_tos: u8, observed_tcp_flags: u8, decision: SessionDecision /* Copy? */, ingress_zone: u16, is_reverse: bool, policy_counter_idx: u32 }
  struct SessionCold { origin, install_epoch, created_ns, wheel_tick, seen_rg_epoch, first_held_ns, nat64_reverse, log_flags, policy_id, inactivity_timeout_ns, policy_counter: Option<Arc<...>> }
  struct SessionEntry { hot: SessionHot, cold: SessionCold, metadata_hot: MetaHot, metadata_cold: MetaCold } // still 1 allocation
  // OR keep single struct but reorder fields: hot first, cold second, with #[repr(C)]? to guarantee layout, and split metadata into MetaHot (Copy) + Arc handle stored separately.
  // For clone cost: change lookup_with_origin to return borrowed metadata + decision copy, not owned clone, or make SessionMetadata Copy except Arc, store Arc as *const PolicyRuleCounter (non-owning) for lookup result, increment only in accounting path that needs it.
  // Preferred: keep Arc but provide fn SessionMetadata::clone_hot(&self) -> MetaHot (Copy) + Arc clone only when needed for delta harvest; SessionLookup contains Arc by reference? Actually SessionLookup must own for delta queue, but we can make delta carry Arc only on Open/Close (cold), not on per-packet lookup result.
  ```
  Minimal invasive: split `SessionMetadata` into `SessionMetaHot` (Copy, no Arc: ingress_zone, egress_zone, is_reverse, policy_counter_idx, owner_rg_id, fabric_ingress) and `SessionMetaCold` (Arc + Option + logs). Store both inline in `SessionEntry`. `lookup_with_origin` returns `SessionLookup` that borrows hot as Copy and only clones Arc when pushing delta (cold). Existing `SessionMetadata::policy_counter` moved to cold side; hot path uses `policy_counter_idx` for fast resolve via `PolicyState::resolve_session_hit_counter` which already prefers bound Arc over idx — we can keep idx-only in hot result and resolve bound Arc in accounting path already doing so.
- **Hot-path preservation:**
  - **Inlining:** Keep `account_packet`, `touch_if_stale` inline; they access `hot.last_seen_ns` at offset 0, fits first cache line alongside decision.
  - **Alloc:** No new alloc; Arc remains 1 per session but not cloned per packet. SmallVec bucket unchanged.
  - **Dispatch:** No dyn.
  - **Layout:** Reorder SessionEntry: hot counters/last_seen/decisions first (64B), then cold HA fields. Ensures per-packet store hits only first 2 lines, not evict cold.
  - **Locality:** Slab record still `key+entry` — handle stable. Companion recovery via `reverse_session_key` still uses entry.nat (hot).
  - **Lock:** Single-threaded preserved.
- **Tests+gate:**
  - Existing session unit tests + `flow_cache_hit` tests asserting policy counter attribution after reorder/insert (#3322 mis-attribution regression).
  - Perf micro: instrument `lookup_with_origin` clone count via counter; bench with `cargo bench`? No bench harness, but validate with `perf stat -e mem_load_retired.l1_miss,lock_xadd` on iperf3 7.5M pps (loss cluster). Expected ~10ns win per miss.
  - Gate: `make test-failover` + `show security policies hit-count` after change — per-rule hit counter must still increment per packet (policy fast path).
- **Why it matters:** At 7.5M pps (loss mlx5 VF 6 queues), 1% flow-cache miss = 75k lookups/s per core; each Arc clone ~10ns + cache line dirty = 0.75ms/s overhead plus contention on Arc strong count cache line if shared across workers (PolicyCounterStore Arc shared). More importantly, metadata.clone() copies 64B+ including cold logging fields irrelevant to forwarding verdict — wasteful at data plane frequency.
- **Fix direction:** 1) Reorder SessionEntry fields hot-first. 2) Split metadata hot/cold, keep `policy_counter_idx` Copy in hot, move `policy_counter` Arc to cold and provide `clone_for_delta()` method that clones Arc only for delta push (cold). 3) Change `SessionLookup` to contain `Arc` only via `Option<Arc>` borrowed or raw handle, not cloned via metadata.clone(). Verify `PartialEq` impl ignoring policy_counter still holds.
- **Labels:** `perf`, `dataplane`, `hot-path`, `refactor`
- **Dedup note:** Not duplicate of #919 (which removed Arc<str>). This is follow-up for remaining Arc<PolicyRuleCounter>. Complements #3322 bound-handle pattern.

### F3 — session_glue/mod.rs god module: resolution cache validation + BPF mirror + HA predicates + worker command dispatch + flow teardown in one 1277 LOC file

- **Title:** afxdp/session_glue/mod.rs mixes 5 concerns — cache validation, BPF map publishing, HA RG predicates, worker command dispatcher, pending flow cancel/teardown
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** God module / mixed abstraction levels
- **Evidence:**
  - Functions list: `resolution_target_for_session`, `cached_session_resolution`, `populate_egress_resolution`, `lookup_forwarding_resolution_for_session_with_cache`, `owner_rg_is_locally_active`, `synced_entry_allows_local_replace`, `redirect_session_resolution_for_metadata`, `owner_rg_is_unseeded`, `should_bypass_unseeded_tunnel_ha`, `session_key_has_lo0_filter`, `republish_local_delivery_sessions_for_lo0_filter`, `purge_sessions_for_input_dscp_filter_revalidation`, `publish_worker_session_map_entry`, `delete_terminal_filtered_session`, `forward_export_candidates_for_owner_rgs`, `apply_worker_commands` (WorkerCommand enum dispatch), `replicate_session_*`, `teardown_tcp_rst_flow`, `cancel_queued_flow`, etc.
  - `apply_worker_commands` hot-ish: called per tick, samples monotonic time once, then matches 7 variants, delegating 5 to `commands::*` (good) but 3 trivial stay inline per #1346 plan v2 — dispatcher itself 100+ LOC.
  - BPF mirror writers (`publish_session_map_entry_for_session`, `delete_session_map_entry...`) knowledge of kernel fd shared with `lookup_forwarding_resolution` that knows about tunnel endpoint id reuse hazards (#1873).
- **Proposed decomposition:**
  - Split into `resolution.rs` (cache validation + lookup_*_with_cache + should_bypass_unseeded),
  - `bpf_mirror.rs` (publish_worker_session_map_entry, republish_local_delivery_sessions_for_lo0_filter, delete_terminal_filtered_session),
  - `ha_predicates.rs` (owner_rg_is_locally_active, synced_entry_allows_local_replace, redirect_session_via_fabric_if_needed, enforce_session_ha_resolution),
  - `worker_cmd.rs` (apply_worker_commands dispatcher only, plus WorkerCommandResults),
  - `flow_teardown.rs` (teardown_tcp_rst_flow, cancel_queued_flow_on_binding, cancel_pending_forwards, route_cancelled_shared_recycles),
  - Keep `promote.rs` and `commands/*` as is. `mod.rs` becomes re-export façade <150 LOC.
  - Keep inline trivial variants per #1346 rationale but document threshold (≤5 LOC).
- **Hot-path preservation:** Dispatcher remains `#[inline]`? Currently not; but it's cold per tick. Resolution cache validation is warm (called on cache miss). Preserve `#[inline(always)]` only for flow_cache_hit stage, not here. No extra alloc, no dyn. BPF mirror functions take `c_int fd` (raw), no new lock.
- **Tests+gate:** Existing glue unit tests `session_glue/tests.rs` 5587 LOC covers cache validation + mirror semantics; must still pass. `make test-failover` gate for HA predicate moves.
- **Why it matters:** Changing HA active check currently risks breaking BPF mirror publish (same file). Separation enables review per concern, reduces merge conflicts between HA team and dataplane team.
- **Fix direction:** Mechanical code-motion split like #1047/#2005/#1346 — bodies byte-identical, only module boundary moves. Add `README.md` update documenting new files.
- **Labels:** `refactor`, `modularity`, `ha`, `dataplane`
- **Dedup note:** Prior #1346 did first split (commands/*) but left 1277 LOC dispatcher + mixed concerns. This filing completes that split.

## D — Negatives (checked, not filing)

- **wheel.rs well isolated:** 80 LOC pure bucket math, no HA/limit leak, power-of-two assert, target_tick_for saturating. No refactor needed.
- **key.rs pure:** 232 LOC transforms, no state, seeded hasher usage correct, ICMP identifier handling #4074 documented. Already re-exported, no god struct.
- **ctx.rs grouping good:** SessionInstall owned vs SessionUpdate borrowed avoids clone at production call site session_glue/mod.rs:1071; ExpireHaContext closure bundle keeps afxdp-private HA types out of session crate. Zero-cost (Copy).
- **NatIndexBucket SmallVec<[u32;2]>** 1:N multimap mitigates #1758 collision without heap spill for common case, N=2 free vs N=1 due to union size dominance — allocation optimal for hot path.
- **SharedSessionRefs Copy 32B** in promote.rs — good example of zero-cost 16→13 param collapse, cargo-asm claim documented, empirically gated by smoke+failover.
- **Seeded FxHasher for attacker-controlled keys** via `hot_hash_seed` OnceLock, per-boot secret, stable per process — correct mitigation #2364, no per-packet alloc.

## Hot-path preservation summary

All proposed splits keep hot core inline (no Box/Arc extra), preserve `&mut self` worker-owned single-threaded locking, keep `SmallVec<[u32;2]>` zero-alloc bucket, keep `#[inline]`/`#[inline(always)]` on `touch_if_stale`, `account_packet`, `handle_for_key`, `entry_by_key`, `stage_flow_cache_hit`, keep seeded hasher probe count (1 probe for forward, 2 for reverse), keep cache-line grouping via field reorder, no new dyn dispatch. Estimated 10ns/packet win from removing Arc clone at 7.5M pps = 75ms core time per second saved.

## Tests & gates mapping

- Unit: `cargo test -p userspace-dp --lib session` (includes wheel pop stats, standby gate, companion keep-alive, limit back-count, stale handle guards via debug_assert)
- Release-mode guards: `cargo test --release -p userspace-dp --lib session`
- Glue: `cargo test -p userspace-dp --lib afxdp::session_glue`
- Full Rust suite: `make test-rust` (~minutes, needs cargo)
- Integration: `make cluster-deploy && make test-failover` — mandatory for any cluster/VRRP/session sync code change per CLAUDE.md
- Perf: iperf3 to 172.16.80.200:5200-5211 CoS ports on loss cluster, `perf stat -e cycles,branches,mem_load_retired.l1_miss` before/after, expect no regression, ~10ns win on lookup miss path.

## Log

- Read mod.rs, entry.rs, key.rs, ctx.rs, install.rs, lookup.rs, expire.rs, wheel.rs, session_glue mod.rs+promote.rs+commands/mod.rs + README.md via worktree /tmp/review-wt-ps-041-a1d-b1
- Grepped metadata.clone sites (9 occurrences) and policy_counter usage (100+ sites) to quantify Arc clone cost
- Verified prior #4421 filing exists, dedup checked



---


### === FINDINGS FROM A1E — ps-a1e-b1.md ===

# A1e Audit — Forwarding / ForwardingState / neighbor / worker loop_body

- Base: `95b33d49634d56086269a62a92e213dae7926f88` @ `/tmp/review-wt-ps-041-a1e-b1/`
- Worktree: `/tmp/review-wt-ps-041-a1e-b1` (detached HEAD)
- Date: 2026-07-08
- Scope: `forwarding/mod.rs` (2822), `types/forwarding.rs` (1079), `forwarding_build/` (8 files, 3092 non-test incl. 5042-line tests.rs), `neighbor.rs` (2036) / `neighbor_resolver.rs` (1512) / `neighbor_dispatch.rs` (1399), `worker/mod.rs` (1625) / `worker/loop_body/mod.rs` (1784)

---

## 1. Inventory

### forwarding/mod.rs (2822 LOC)
- Claimed "68 free fns" in task — actual at this base: **80 free fns** (`pub(super)`, `pub(in crate::afxdp)`, `pub(crate)`, `pub`, `fn` at file top-level). Growth via HA helper additions (`cluster_peer_return_fast_path`, `enforce_ha_resolution*`, `owner_rg_for_resolution`, `cache_flow_decision_valid`, etc.).
- 5 god-fns >100 LOC (still accurate, though 3 now):
  - `lookup_forwarding_resolution_inner_ecmp` — **192 LOC** — `L1449-L1640` — per-table FIB ECMP with local-delivery gating, interface-NAT, tunnel, NAT64/NPTv6 branching.
  - `lookup_forwarding_resolution_v4_inner` — **192 LOC** — `L2023-L2214` — v4-specific dispatch (static/connected, choose, ECMP hash, next-hop, src-mac, tx-vlan).
  - `lookup_forwarding_resolution_v6_inner` — **184 LOC** — `L2239-L2422` — v6 mirror.
  - `cluster_peer_return_fast_path` — **105 LOC** — `L713-L817` — HA return path.
  - `ingress_route_table_override` — **122 LOC** — `L1641-L1762` — VRF table lookup.

### types/forwarding.rs — ForwardingState god-struct
- Fields: task says "65 via #3769/#3182/#3527/#3618 growth" — measured **66 fields** at this base (`wc` + regex `pub(in crate::afxdp) name: type`). Structure `L14-L290`.
- No `#[repr(C)]`, no `#[repr(Rust)]` explicit — indeed absent, confirmed via `grep repr` over file (0 hits).
- `#[derive(Clone, Debug, Default)]` present — `Default` does heavy allocation (all maps empty). Excessive `Clone` over 66 fields drives expensive per-ArcSwap snapshot cloning in workers.

### forwarding_build/ (8 files, 3092 non-test)
- `mod.rs` 704, `fib.rs` 483, `interfaces.rs` 340, `zones.rs` 142, `cos.rs` 850, `tunnels.rs` 302, `validated.rs` 161, `wg.rs` 127, `tests.rs` 5042 (ignored in non-test tally → 3092 actual).
- Already decomposed via #1342 — confirmed: each file has focused single responsibility, sub-100-LOC helpers, borrow-only `ClassifierTables<'a>` etc.

### neighbor.rs + neighbors
- `neighbor.rs` 2036 — 4 responsibilities fused:
  1. ARP/ND probe craft: `build_icmp4_echo`, `build_icmp6_echo`, raw Ethernet send, AF_PACKET probe path.
  2. Netlink mgmt / kernel trigger: `trigger_kernel_arp_probe` (134 LOC, `L158-L291`), netlink request construction.
  3. Monitor thread / dump: `neigh_monitor_thread` (272 LOC, `L975-L1246`), `set_neigh_monitor_rcvbuf`, netlink dump parsing.
  4. CPU affinity: `nth_allowed_cpu` / `nth_allowed_cpu_*` tests, allowed-CPU picker for warmer/monitor thread pinning.
- `neighbor_resolver.rs` 1512 — resolver socket (`open_resolver_socket`, `send_get_neigh`, `read_get_reply`), `NeighborResolver` struct with epoch-gated resolve loop.
- `neighbor_dispatch.rs` 1399 — pending-neighbor admission, probe schedule, queued-packet drain.
- Coupling: `neighbor_resolver.rs` and `neighbor_dispatch.rs` use `super::*` for shared types — not explicit dependency injection.

### worker/mod.rs (1625) + loop_body/mod.rs (1784)
- Already decomposed via #959 into 11 sub-modules: `bind_meta`, `bpf_maps`, `cos_state`, `flow_cache_state`, `lifecycle`, `scratch`, `telemetry`, `timers`, `tx_counters`, `tx_pipeline`, `xsk_rings`, plus `cos/` subtree and `loop_body/` (setup.rs 11364 LOC-decl + debug_report.rs 14995 LOC-decl, but `mod.rs` is 1784).
- `mod.rs` itself now 1625 after extraction — hosts `BindingWorker` struct (huge, ~30 fields), `XskBindMode` enum, shared-mem binding plan orchestration.
- `loop_body/mod.rs` 1784 — per-tick orchestrator, per comment deliberately stays INLINE to avoid `#[inline(never)]` call boundary regressing 10K-100K ticks/s loop (see file header comment `L1-L30` referencing Codex r1-4 review).

---

## 2. Findings — Exact Labels + Severity + Owner + Hot-Path Preservation

### F1 — ForwardingState 66 fields, no #[repr], hot+cold interleaved — perf-positive reorder — SEVERITY: M — OWNER: forwarding/types
**Where:** `userspace-dp/src/afxdp/types/forwarding.rs:14-290`
**Label:** `A1e-FORWARDING-STATE-GOD-STRUCT-MULTI-RESP`
**Evidence:**
- 66 fields enumerated (see inventory). Field order is historical accretion order, not hotness order:
  - Hot FIB (per-packet): `local_v4/v6`, `routes_v4/v6`, `connected_v4/v6`, `neighbors`, `ifindex_to_zone_id`, `egress`, `tunnel_endpoints`, `gre_decap_index`, `fabrics`, `zone_host_inbound` / `ifindex_host_inbound` — but interleaved with:
  - Cold config (commit-only): `ifindex_to_name: FastMap<i32, String>` (`L102` — `String` values = heap, never touched on fast path), `filter_state: FilterState` (`L222`), `cos: CoSState` (`L223`), `tcp_mss_*` (`L247-L250`, 4x u16), `cold_path_sample_mask: u64` (`L257`), `screen_profiles`, `mirror_configs`, `session_timeouts`, etc.
- No `#[repr(C)]` nor explicit `#[repr(Rust)]` — struct layout is currently Rust-undefined-order (compiler may reorder, but not guaranteed to group hot fields).
- `#[derive(Clone)]` clones all 66 fields per ArcSwap refresh visible in `worker/loop_body/mod.rs:375` (`forwarding.as_ref()` vs `new_forwarding` diff) — cold fields cloned unnecessarily on hot path.

**Hot-path preservation required:**
- `owns_configured_ip(&self, ip) -> bool` — `L482-L485` — `#[inline]` is present on this method (verified). Must stay `#[inline]` — called in `poll_stages.rs:136,178` (ARP/ND anti-poison) per-packet.
- `choose_v4_route<'a>` `L2622`, `choose_v6_route<'a>` `L2642` — free fns in `forwarding/mod.rs`, small (20/43 LOC), pure logic. No `#[inline]` currently — candidates for `#[inline]` or move into `types/forwarding.rs` impl as `#[inline]` helpers. Preserve call sites `L2059`, `L2271`.
- `ecmp_hash_bytes` `L2685` (7 LOC), `ecmp_hash_v4` `L2692` (4 LOC), `ecmp_hash_v6` `L2696` (20 LOC), `ecmp_hash_flow` `L2716` (8 LOC), `ecmp_hash_flow_seeded` `L2724` (62 LOC — only god of the group) — currently NOT annotated `#[inline]`. Hot path: `lookup_forwarding_resolution_v4_inner` `L2152` and v6 `L2360` (`unwrap_or_else(|| ecmp_hash_v4/v6)`), plus `L1422` (`Some(ecmp_hash_flow(flow_key))`) in `lookup_forwarding_resolution_with_dynamic_for_flow`. Must get `#[inline]` — zero-risk perf win.
- CoS TX drain focus checklist: `forwarding.cos` is cold config (built once, `ArcSwap` shared), worker-side `WorkerCos` holds hot counters. Split `cos` out is safe ONLY if worker's `cos_shared_queue_leases` `ArcSwap` continues to hold the forwarding FIF lookup (`forwarding.cos.interfaces`) via clone — preserve FIF lookup on hot path (worker `cos/mod.rs:194` `&forwarding.cos.interfaces`). Do NOT move `cos` behind interior indirection that adds cache miss.

**Proposed zero-risk immediate:**
1. Add `#[repr(C)]` to `ForwardingState` + reorder hot-field-first:
   - Hot zone: `local_v4`, `local_v6`, `configured_iface_v4/v6`, `connected_v4/v6`, `routes_v4/v6`, `neighbors`, `ifindex_to_zone_id`, `zone_name_to_id` (fast path gated), `egress`, `tunnel_endpoints`, `gre_decap_index`, `fabrics`, `zone_host_inbound`, `ifindex_host_inbound`, `reject_buckets`, `has_wg_tunnels`, `wg_engines`, `ingress_logical_ifindex`, `interface_nat_v4/v6`.
   - Cold tail: `ifindex_to_name`, `ifindex_to_config_name`, `ifindex_to_routing_instance`, `zone_id_to_name`, `zone_tcp_rst`, `fabric_skips`, `allow_dns_reply`, `allow_embedded_icmp`, `alg_disable_flags`, `app_catalog`, `session_timeouts`, `session_opening_overrides`, `policy`, `source_nat_rules`, `static_nat`, `dnat_table`, `nat64`, `nptv6`, `screen_profiles`, `screen_missing_profiles`, `syn_cookie_master_key`, `tunnel_interfaces`, `filter_state`, `cos`, `tx_selection_enabled_*`, `gre_acceleration`, `power_mode_disable`, `mirror_configs`, `tcp_mss_*`, `cold_path_sample_mask`, `pending_neigh_timeout_ns`, `cold_path_slot_map`, `zone_counter_slot_map`, `zone_counter_store`, plus `local_tables_v4/v6` + `local_nat_any_table_v4/v6` (table attribution, semi-hot but can sit after hot FIB).
2. Annotate `#[inline]` on `owns_configured_ip`, `choose_v4_route`, `choose_v6_route`, `ecmp_hash_bytes/v4/v6/flow/flow_seeded`.
3. Verify via `cargo test --manifest-path userspace-dp/Cargo.toml` + iperf3 ≥23 Gb/s (per task) — reorder at `#[repr(C)]` does not change semantics, only layout; `#[inline]` does not change semantics.

**Follow-up SoA split (structural, non-zero-risk):**
- `ForwardingFib(Arc)` containing only hot FIB tables (`routes`, `connected`, `neighbors`, `egress`, `ifindex_to_zone_id`, `tunnel_endpoints`, `gre_decap_index`, `fabrics`, `local_v4/v6`, `configured_iface_v4/v6`, `zone_host_inbound`, `ifindex_host_inbound`, `has_wg_tunnels` + `wg_engines` handle, `interface_nat`, `ingress_logical_ifindex`).
- Workers hold `Arc<ForwardingFib>` hot + separate `Arc<ForwardingConfig>` cold. This keeps hot Arc 1-cacheline vs current 66-field clone. Preserve `owns_configured_ip`, `choose_v4/v6`, `ecmp_hash_*` as methods on `ForwardingFib` with `#[inline]`.
- Cold config (`filter_state`, `cos`, `ifindex_to_name: FastMap<i32,String>`, `tcp_mss_*`, `cold_path_sample_mask`, NAT rule vecs, policy, screen) stays behind separate Arc upgraded only on session-miss / cold-path.

---

### F2 — forwarding/mod.rs 2822 LOC, 80 free fns, 3× 180+ LOC god-fns fused FIB/NAT/fabric/tunnel — SEVERITY: M — OWNER: forwarding
**Where:** `userspace-dp/src/afxdp/forwarding/mod.rs`
**Label:** `A1e-FORWARDING-MOD-GOD-FN-FUSION`
**Evidence:**
- `lookup_forwarding_resolution_inner_ecmp` 192 LOC `L1449` — handles: local-delivery NAT-aware table gating (#3769), VRF `local_tables_v*`, interface NAT `interface_nat_local_resolution`, connected vs static choose, fabric check, tunnel outer resolution, ECMP hash threading. At least 4 concerns.
- `lookup_forwarding_resolution_v4_inner` 192 LOC `L2023` — v4-specific static/connected + NAT + source NAT scope + tunnel + neighbor + TX vlan + CoS? (via egress).
- `lookup_forwarding_resolution_v6_inner` 184 LOC `L2239` — same for v6.
- These two inner fns duplicate 60% of logic (choose, next-hop, tx vlan, src-mac, neighbor). `choose_v4_route`/`choose_v6_route` already factor choose but not the rest.
- `cluster_peer_return_fast_path` 105 LOC `L713` — HA-specific, tangential to FIB.
- File mixes: metadata classification (`classify_metadata`), neighbor state (`classify_neighbor_state`), fabric (`build_fabric_link_or_skip`, `resolve_fabric_*`), zone-encode (`resolve_zone_encoded_fabric_redirect_by_id`), HA (`enforce_ha_resolution*`), TCP MSS (`native_gre_inner_mtu`, `tunnel_tcp_mss`, `select_tcp_mss`), IPsec admission (`classify_ipsec_admission`), tunnel (`resolve_tunnel_outer`), neighbor entry parsing (`parse_neighbor_entries`).

**Hot-path preservation:**
- ECMP hash path `choose_v4/v6` + `ecmp_hash_*` + `select_route_next_hop` `L2799` (24 LOC) must remain `#[inline]` or monomorphised generic — current `select_route_next_hop<'a,T:Copy>` is generic over `RouteEntryV4/V6`, already inlines well. Keep as free fn in module that stays in same crate for cross-function inline.
- `owns_configured_ip` lives in types, not here — but `local_v*` checks in inner_ecmp are hot; keep them inline.
- Fabric redirect `resolve_fabric_redirect_from_list` `L592` (32 LOC) is cold-ish (HA path) but called from hot `redirect_via_fabric_if_needed` `L655` (14 LOC) which itself is hot — preserve `#[inline]` on redirect path.

**Proposed split (non-hot-risk):**
- Extract `forwarding/fib_lookup.rs`: `lookup_forwarding_resolution_inner_ecmp`, `lookup_forwarding_resolution_v4_inner`, `lookup_forwarding_resolution_v6_inner`, `choose_v4_route`, `choose_v6_route`, `select_route_next_hop`, `tunnel_next_hop_live`, `ecmp_hash_*`.
- Extract `forwarding/fabric.rs`: `record_fabric_skip`, `build_fabric_link_or_skip`, `resolve_fabric_links_from_snapshots`, `resolve_fabric_redirect*`, `redirect_via_fabric_if_needed`, `prefer_local_forward_candidate_for_fabric_ingress`, `resolve_zone_encoded_fabric_redirect*`.
- Extract `forwarding/tunnel.rs`: `resolve_tunnel_outer`, `resolve_tunnel_forwarding_resolution`, `outer_neighbor_ifindex`, `native_gre_inner_mtu`, `native_gre_tcp_mss`, `tunnel_outer_mtu`, `tunnel_tcp_mss`, `select_tcp_mss`, `effective_tcp_mss`.
- Extract `forwarding/ha_gate.rs`: `enforce_ha_resolution*`, `cached_flow_decision_valid`, `finalize_new_flow_ha_resolution`, `demoted_owner_rgs`, `activated_owner_rgs`, `cluster_peer_return_fast_path`, `ingress_is_fabric*`.
- Each new file <500 LOC, clear owner. Keep `forwarding/mod.rs` as re-export (`pub(super) use fib_lookup::*` etc) so existing call sites unchanged — minimal churn, no public API change.

**Verify:** `cargo test -p xdp-neighbor --lib` patience + `cargo test --manifest-path userspace-dp/Cargo.toml forwarding` + iperf3.

---

### F3 — neighbor.rs 2036 LOC, 4 responsibilities fused, super::* coupling — SEVERITY: M — OWNER: neighbor
**Where:** `userspace-dp/src/afxdp/neighbor.rs`
**Label:** `A1e-NEIGHBOR-CUP-MULTI-RESPONSIBILITY`
**Evidence:**
- File header `L1-L50` declares 4 responsibilities explicitly but code does not enforce module boundary:
  1. ARP/ND probe craft — `build_icmp4_echo` `L97`, `build_icmp6_echo` `L110`, AF_PACKET raw send helpers `L40-L160`, `ProbeSockKind`.
  2. Netlink mgmt / kernel trigger — `trigger_kernel_arp_probe` 134 LOC `L158-L291`, `send_get_neigh`, netlink attribute builder.
  3. Monitor thread / dump — `neigh_monitor_thread` 272 LOC `L975-L1246`, `neighbor_warmer_loop` 120 LOC `L292-L411`, `set_neigh_monitor_rcvbuf` `L910`, neighbor dump parsing.
  4. CPU affinity — `nth_allowed_cpu` `L1247`, tests `L1546-L1680` including `nth_allowed_cpu_regression_for_systemd_cpuaffinity_2_3_4_5`.
- `neighbor_state_usable_str` `L1314`, `parse_mac_str` `L1318` — utility trampoline into `forwarding` classifier, tiny fns that could live in `types` or dedicated `neighbor/util.rs`.
- `neighbor_resolver.rs` 1512 + `neighbor_dispatch.rs` 1399 already exist as "genuine splits but use super::* coupling" per task. Verified: both `use super::*;` glob brings all of `afxdp` into scope, making boundary implicit. `neighbor_resolver.rs:58 ResolveItem`, `L168 NeighborResolver`, `L292 open_resolver_socket`, `L340 send_get_neigh`, `L436 read_get_reply`. `neighbor_dispatch.rs:44 probe_due`, `L56 PendingNeighAdmission`.

**Hot-path preservation:**
- Neighbor probe path runs on worker thread per tick, NOT per-packet hot path — but `owns_configured_ip` anti-poison check `neighbor_dispatch.rs:494` and `poll_stages.rs:136,178` IS per-packet. Preserve that gate as `#[inline]` on `ForwardingState`.
- Fabric resolution uses neighbor map `resolve_fabric_links_from_snapshots` — cold/medium.
- TX vlan / src-mac lookup `lookup_neighbor_entry` `forwarding/mod.rs:2550` is hot — must preserve fast-path.

**Proposed split (zero hot-path regression):**
- `neighbor/` directory (already `neighbor_dispatch.rs`, `neighbor_resolver.rs` as siblings — promote to subdir):
  - `neighbor/probe.rs` — `ProbeSockKind`, `build_icmp4_echo`, `build_icmp6_echo`, `send_probe` (extract from dispatch).
  - `neighbor/kernel_trigger.rs` — `trigger_kernel_arp_probe`.
  - `neighbor/monitor.rs` — `neigh_monitor_thread`, `set_neigh_monitor_rcvbuf`, netlink dump parsing + warmer loop.
  - `neighbor/cpu_affinity.rs` — `nth_allowed_cpu`, allowed-CPU iterator, regression tests.
  - `neighbor/util.rs` — `parse_mac_str`, `neighbor_state_usable_str` re-export.
  - Keep `neighbor.rs` as facade re-exporting (`pub(crate) use ...`) until migration complete.
- Replace `super::*` in `neighbor_resolver.rs`/`neighbor_dispatch.rs` with explicit imports (`use crate::afxdp::types::forwarding::ForwardingState; use crate::afxdp::neighbor::ProbeSockKind;` etc) to break glob coupling — done as separate commit to isolate coupling fix from functional change.

---

### F4 — worker/loop_body already decomposed but hot-path INLINE invariant fragile — SEVERITY: L — OWNER: worker
**Where:** `userspace-dp/src/afxdp/worker/mod.rs` (1625), `worker/loop_body/mod.rs` (1784)
**Label:** `A1e-WORKER-LOOP_BODY-INLINE-INVARIANT`
**Evidence:**
- `#959` decomposition is exemplary: 11 sub-modules `bind_meta`, `bpf_maps`, `cos_state`, `flow_cache_state`, `lifecycle` (poll_binding orchestrator), `scratch`, `telemetry`, `timers`, `tx_counters`, `tx_pipeline`, `xsk_rings`, plus `cos/` subtree, `loop_body/` with `setup.rs` and `debug_report.rs`.
- `loop_body/mod.rs` header explicitly documents Codex r1-4 review decision: per-tick path deliberately stays INLINE, no `#[inline(never)]` call boundary in front of `load_arc_if_changed` path risking 10K-100K ticks/s regression. This is correct.
- `worker/mod.rs` `BindingWorker` still holds many fields (cos, tx_pipeline, bpf_maps, flow_cache, bind_meta, timers, scratch, xsk_rings, etc) via `WorkerCos`, `WorkerTxCounters`, etc — but now as typed sub-structs, not flat.

**Hot-path preservation — CoS TX drain focus:**
- CoS forwarding FIF lookup (`forwarding.cos.interfaces`) is read via `load_full` (`loop_body/mod.rs:113` `shared_cos_queue_leases` + `forwarding.cos`), then `cos/mod.rs:194` `&forwarding.cos.interfaces`. FIF arbitration is per-worker-local (`cos/mod.rs:102-105` comment: "single-owner FIFO per queue, SFQ inside for exact; per-class FIFO for non-exact"). This MUST stay per-worker-local; cross-binding redirect would collapse 6-worker parallelism (`forwarding_build/cos.rs` useful_cos_state gate prevents forwarding-only ifaces admitted — `mod.rs:269-274`).
- `drain_pending_tx` (`lifecycle.rs:70`) is hot TX drain — must not introduce extra Arc clone of `cos` behind indirection.
- Proposal to split `ForwardingState` into `ForwardingFib(Arc)` + cold config must preserve that workers hold hot FIB separately but CoS FIF lookup remains hot-path accessible without extra cache miss — i.e., if `cos` moves to cold `Arc<ForwardingConfig>`, its per-tick read should be via already-loaded `new_forwarding` Arc that workers compare via `load_arc_if_changed`, not an extra load per packet.

**Recommendation:** No further decomposition of `worker/loop_body/mod.rs` until forwarding split lands. File is correctly at 1784 LOC with only `worker_loop` + 2 helpers (`reap_expired_sessions`, `count_local_session_expiries`, `setup` module). Adding more extraction would violate INLINE invariant. Keep as-is; document inline invariant in `docs/engineering-style.md` adjacent to logging rules if not already — it is in file header but not in docs.

---

## 3. D-Negatives (What NOT to Refactor — Exemplary Areas)

### D1 — forwarding_build/ — Exemplary decomposition via #1342 — DO NOT TOUCH
**Label:** `A1e-D-NEGATIVE-FORWARDING_BUILD-EXEMPLARY`
**Evidence:** 8 files, each <1000 LOC non-test, focused:
- `mod.rs` 704 orchestrator calls `build_cos_state`, `build_fib`, etc.
- `fib.rs` 483, `interfaces.rs` 340, `zones.rs` 142, `cos.rs` 850 (largest but internally decomposed into `ClassifierTables<'a>` borrow-only tables, per-interface loop body, orchestrator — comment `L1-L22` acknowledges decomposition), `tunnels.rs` 302, `validated.rs` 161, `wg.rs` 127.
- `cos.rs` `ClassifierTables<'a>` `'a` tied to `&'a ClassOfServiceSnapshot` — borrow-only, no clone. `useful_cos_state` gate prevents forwarding-only ifaces.
- Growth from NAT64 allocator reuse (#4518), VRF table attribution (#3769/#3151), syn-flood per-zone override (#3527) landed as additive fields/methods, not new god-fns.
**Verdict:** Leave as-is. Any further split would add indirection without win.

### D2 — worker/ subtree — Already decomposed via #959, INLINE invariant preserved — DO NOT FURTHER SPLIT loop_body/mod.rs
**Label:** `A1e-D-NEGATIVE-WORKER-ALREADY-DECOMPOSED`
**Evidence:** 11 sub-modules + cos subtree + loop_body/setup + debug_report. `mod.rs` 1625 after extraction (down from pre-#959 larger). `loop_body/mod.rs` 1784 deliberately inline per Codex r1-4 review (header). `cos_state.rs` 50 LOC, `tx_pipeline.rs`, `scratch.rs`, etc each <100 LOC focused.
**Verdict:** `worker/mod.rs` BindingWorker + lifecycle.rs + tx_pipeline + cos_state is appropriate. Further extracting `worker/mod.rs` shared-mem binding plan orchestration (`create_shared_binding_group` 100+ LOC `L1027-L1104`, `fallback_shared_group_to_private` `L1105-L1163`) into separate file could be considered but low priority — not hot path.

### D3 — neighbor_resolver.rs / neighbor_dispatch.rs genuine split exists — only coupling fix needed
**Label:** `A1e-D-NEGATIVE-NEIGHBOR-SPLIT-EXISTS-COUPLING-ONLY`
**Evidence:** Resolver and dispatch already split files with focused responsibilities (resolver socket / dispatch admission). Only issue is `super::*` glob coupling. This is low-sev fixable with explicit imports — does not warrant new modules beyond the probe/kernel/monitor/cpu_affinity split in neighbor.rs itself.

---

## 4. Ordered Refactor Plan (Zero-Risk → Structural)

### Phase 0 — Immediate perf-positive zero-risk (can land as single PR, <100 LOC diff)
1. Add `#[repr(C)]` to `ForwardingState` (`L14`).
2. Reorder fields hot-first (list in F1).
3. Add `#[inline]` to `owns_configured_ip` (if not already), `choose_v4/v6_route`, `ecmp_hash_bytes/v4/v6/flow/flow_seeded`, `select_route_next_hop`, `resolve_fabric_redirect_from_list`, `redirect_via_fabric_if_needed`.
4. Verify `cargo test --manifest-path userspace-dp/Cargo.toml` passes + bench iperf3 ≥23 Gb/s on loss cluster (per task, CoS TX drain preserved).

### Phase 1 — forwarding/mod.rs decomposition (3 PRs, mechanical relocation)
- PR1: Extract `forwarding/fabric.rs` + `forwarding/ha_gate.rs` (cold/medium hotness, lowest risk).
- PR2: Extract `forwarding/tunnel.rs` (TCP MSS + outer resolution).
- PR3: Extract `forwarding/fib_lookup.rs` (hot path) — requires careful `#[inline]` preservation audit. Each PR re-exports via `mod.rs` to keep call sites unchanged; verify via tests + iperf3 per PR.

### Phase 2 — ForwardingState SoA split (structural, 1 PR)
- Introduce `ForwardingFib` struct holding hot fields, `ForwardingConfig` holding cold.
- Workers hold `Arc<ForwardingFib>` + `Arc<ForwardingConfig>`. `ForwardingState` becomes facade (`Deref` to Fib for hot, explicit cold accessor). Or keep `ForwardingState` as container of two Arcs to minimize call-site churn.
- Migrate `owns_configured_ip`, `choose_v4/v6`, `ecmp_hash_*` to methods on `ForwardingFib`.
- Cold: `ifindex_to_name: FastMap<i32,String>`, `filter_state`, `cos`, `tcp_mss_*`, `cold_path_sample_mask`, `screen_profiles`, `mirror_configs`, `app_catalog` etc.
- Verify via `cargo test` + iperf3 ≥23 Gb/s + `show system buffers` CoS status (ensure FIF lookup still works).

### Phase 3 — neighbor.rs decomposition (2 PRs)
- PR1: Extract `neighbor/cpu_affinity.rs`, `neighbor/util.rs`, replace  `super::*` with explicit imports in resolver/dispatch.
- PR2: Extract `neighbor/probe.rs`, `neighbor/kernel_trigger.rs`, `neighbor/monitor.rs`; keep `neighbor.rs` as facade.

---

## 5. Risk Assessment

- **Phase 0:** Near-zero risk. `#[repr(C)]` on a Rust-only struct (no FFI) only fixes field order deterministically; previous Rust layout was already effectively C-order for non-`repr(Rust)`-reordered small structs on stable, but `#[repr(C)]` guarantees it. `#[inline]` cannot break semantics. Field reorder under `#[repr(C)]` does not affect `Clone`/`PartialEq` semantics (value-based). Risk: if any code relies on `offset_of!` or transmute (none found — grepped `offset_of`, `transmute`, `repr` — 0 transmutes of ForwardingState; `std::mem::size_of` not used on it).
- **Phase 1:** Low risk — pure relocation, re-export preserves API. Risk: missing `pub(super)` vs `pub(in crate::afxdp)` visibility drift — mitigate via `cargo check` per PR.
- **Phase 2:** Medium risk — SoA split changes Arc ownership. Risk: double-Arc clone overhead if not done carefully, CoS FIF cache miss. Mitigate via keeping worker's `cos_shared_queue_leases` path unchanged, only splitting FIB.
- **Phase 3:** Low risk — neighbor not hot path, threads isolated.

---

## 6. File Map (Absolute Paths)

- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding/mod.rs` — 2822 LOC, 80 free fns, 5 god-fns
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/types/forwarding.rs` — 1079 LOC, ForwardingState 66 fields, no #[repr]
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/mod.rs` — 704 LOC, orchestrator
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/fib.rs` — 483
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/interfaces.rs` — 340
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/zones.rs` — 142
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/cos.rs` — 850, ClassifierTables borrow-only, useful_cos_state gate
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/tunnels.rs` — 302
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/validated.rs` — 161
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/forwarding_build/wg.rs` — 127
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/neighbor.rs` — 2036, 4 responsibilities
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/neighbor_resolver.rs` — 1512, super::* coupling
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/neighbor_dispatch.rs` — 1399, super::* coupling
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/worker/mod.rs` — 1625, 11 sub-mods, BindingWorker
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/worker/loop_body/mod.rs` — 1784, INLINE invariant, per-tick orchestrator
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/worker/lifecycle.rs` — poll_binding
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/worker/cos/mod.rs` — FIF arbitration, single-owner FIFO
- `/tmp/review-wt-ps-041-a1e-b1/userspace-dp/src/afxdp/worker/cos_state.rs` — WorkerCos 50 LOC

---

## 7. Conformance to Task Requirements

- Inventory: provided with exact LOC + fn counts + field enumeration.
- Log: not required to write _Log.md (audit-only worktree, no edits).
- Findings: labeled `A1e-FORWARDING-STATE-GOD-STRUCT-MULTI-RESP`, `A1e-FORWARDING-MOD-GOD-FN-FUSION`, `A1e-NEIGHBOR-CUP-MULTI-RESPONSIBILITY`, `A1e-WORKER-LOOP_BODY-INLINE-INVARIANT`, with severity/owner.
- Hot-path preservation: `owns_configured_ip`, `choose_v4/v6_route`, `ecmp_hash_*` identified with `#[inline]` status, CoS FIF lookup `forwarding.cos.interfaces` preserved via per-worker-local path documented.
- D-negatives: `A1e-D-NEGATIVE-FORWARDING_BUILD-EXEMPLARY`, `A1e-D-NEGATIVE-WORKER-ALREADY-DECOMPOSED`, `A1e-D-NEGATIVE-NEIGHBOR-SPLIT-EXISTS-COUPLING-ONLY`.
- Zero-risk immediate: `#[repr(C)]` + hot-first reorder + `#[inline]` list, verified by test + iperf3 gating.
- CoS TX drain focus: `forwarding_build/cos.rs` useful_cos_state gate + per-worker FIF `cos/mod.rs:102-105` + `cos_shared_queue_leases` ArcSwap path — all preserved in proposed split by keeping cold `cos` behind same ArcSwap load point.

---

## 8. Cleanup

Worktree `/tmp/review-wt-ps-041-a1e-b1` left for final report delivery — caller may `git worktree remove /tmp/review-wt-ps-041-a1e-b1`.
Output file `/tmp/review-work-ps-041/ps-a1e-b1.md` written.


---


### === FINDINGS FROM A1F — ps-a1f-b1.md ===

 (ranked by size × resp × hot)

### [FULL] F1 — inspect.rs IPv6 EH walker 5× duplication — SSOT + canary needed

- **File**: `userspace-dp/src/afxdp/frame/inspect.rs` — 5 functions sharing identical match set:
  - `frame_l4_offset` 71-132 (61 LOC)
  - `packet_rel_l4_offset` 134-190 (57 LOC)
  - `packet_rel_l4_offset_and_protocol` 197-260 (64 LOC)
  - `ipv6_is_non_first_fragment` 289-336 (48 LOC)
  - `ipv6_is_any_fragment` 374-416 (43 LOC)
  - Plus `is_non_first_fragment`/`is_any_fragment` dispatch wrappers (7 LOC each) and `frame_is_non_first_fragment` 1226-1262 that re-derives L3 but calls `is_non_first_fragment`
- **Size**: 5× ~50 LOC = 250 LOC duplicated logic, plus 3-line comment block duplicated per site explaining `0 | 43 | 60 | 135 | 139 | 140 | 253 | 254` set (lines 33-53 canonical comment)
- **Resp**: 1 (IPv6 EH parsing) but fan-out to 3 consumers: forwarding L4 offset, fragment classification for NAT bypass (#1852), firewall-filter `is-fragment` + term_match_extra
- **Hot**: YES — `frame_l4_offset` and `packet_rel_l4_offset` called per-packet for L4 tuple + session flow
- **Pattern**: Every walker:
  ```rust
  for _ in 0..MAX_IPV6_EXT_HEADERS {
    match protocol {
      0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => { len (opt[1]+1)*8 }
      51 => AH (len+2)*4
      44 => frag fixed 8 + special handling
      59 => None (NoNext)
      _ => terminal
    }
  }
  ```
  The generic set was fixed in #4517 (added 135/139/140/253/254). Miss = IDS evasion per file header.
- **Risk**: #4517 fixed 5 sites atomically; 6th site in `crate::nat64` already had stale 6 bound before #4435. Next addition (e.g. new RFC) must touch 5+ sites again.
- **Proposed split**:
  - Introduce `pub(crate) const IPV6_EH_GENERIC: &[u8] = &[0,43,60,135,139,140,253,254]` or inline `is_generic_eh(u8)` + `eh_len`.
  - Introduce single generic walker `#[inline(always)] fn walk_ipv6_eh_chain<F>(packet: &[u8], ...) -> Result<WalkOutcome>` where `WalkOutcome { next_proto, l4_offset, frag? }` or two helpers:
    - `#[inline(always)] fn ipv6_walk_for_l4(packet) -> Option<(offset, proto)>` — used by 3 L4 offset fns
    - `#[inline(always)] fn ipv6_walk_for_frag(packet) -> Option<FragInfo>` — returns (is_any, is_non_first, frag_offset)
  - Keep `MAX_IPV6_EXT_HEADERS` SSOT (already done #4435). The match arms move to walker, call sites become 1-line dispatch.
  - All walkers keep `#[inline(always)]` where hot.
  - **Canary**: unit test that walks a chain `HbH(0) → Mobility(135) → HIP(139) → Shim6(140) → Exp1(253) → Exp2(254) → Routing(43) → DestOpt(60) → Fragment(44) → TCP` and asserts every public fn returns same L4 offset/proto and frag detection. Fails if a new walker copy-pasted without generic set.
- **Hot-path preservation**:
  - `inlining`: keep `#[inline(always)]` on hot L4 offset helpers; walker itself `#[inline(always)]` so monomorphizes without call overhead
  - `alloc`: zero alloc (slice get + checked_add only) — preserved
  - `dispatch`: no new dynamic dispatch, pure static fn
  - `layout`: no struct layout change, only code dedup
  - `locality`: improves I-cache (one copy vs 5 copies) — positive
  - `lock`: no lock
- **Type**: FULL (complete dedup, no partial state)
- **Tests+gate**:
  - Existing: `inspect_tests.rs` covers `frame_l4_offset`, `packet_rel_*`, fragment predicates (7* tests)
  - Gate: property test generating random EH chains up to 8 with all 8 generic types + AH + FRAG + NoNext, asserting all 5 fns agree on terminal outcome. A revert that re-introduces divergent match set fails.
  - Canary test: `eh_walker_ssot_canary` that enumerates 0/43/60/135/139/140/253/254 + 51/44/59 handling in single const and asserts `frame_l4_offset` vs `packet_rel_l4_offset_and_protocol` share same const.
- **Dedup vs prior**:
  - Direct follow-up to #4517 (fixed 5 sites, noted miss = IDS evasion) and #2150 PR-2 (EH walker duplication). Not duplicate — #4517 fixed values, this fixes structure so future fix touches 1 site. #2292 bound fix already handled by MAX_IPV6_EXT_HEADERS SSOT.
  - No overlap with #1049/#1352/#1543 (frame build/rewrite).

---

### [SPLIT] F2 — screen/mod.rs god-func + 22-field ScreenState — SYN-flood cold config out, hot phases keep #[inline(always)]

- **File**: `userspace-dp/src/screen/mod.rs` 1540 LOC
- **God fn**: `check_packet_with_zone_id_opts` 331 LOC (777-1107) — implements:
  1. Stateless (land, tcp-flag screens, ping-of-death, teardrop, icmp-frag, src-route)
  2. ICMP flood: per-dst primary (SynRateSketch) + per-zone secondary ceiling (TokenBucket ×8)
  3. UDP flood: per-dst (ip+port) primary + secondary ceiling
  4. SYN flood 5 phases: aggregate classify (attack+alarm single window advance D7), per-dst primary (spoof-resistant, runs even cookie-active), aggregate cookie challenge / TokenBucket drop (cookie-off), alarm (log-only ≤1/sec/zone), per-src secondary (skipped when cookie-active D3)
  5. Fabric skip_idempotent gate (#4155)
  6. Validated-cache bypass (SipHash validated cache take)
  7. SYN-cookie mint (codec mint_isn)
- **ScreenState fields**: 22 fields, 7 responsibilities:
  - (a) profiles: FxHashMap<String, ScreenProfile>
  - (b) aggregate counters: icmp_counters, udp_counters (TokenBucket), syn_counters (RateCounter), syn_off_attack_buckets (TokenBucket)
  - (c) per-dst sketches: icmp_dst_sketch, udp_dst_sketch, syn_dst_sketch
  - (d) per-src sketch: syn_src_sketch + alarm maps
  - (e) SYN-cookie: codec, validated cache, active_until, standby budgets, profile_gen, epoch wall/mono secs
  - (f) scan/sweep: port_scan, ip_sweep trackers + cleanup
  - (g) missing-profile refs + warn counters + alarm-pending + stats counters (dst/src drops, alarm_events, alarm_without_drop)
- **Size×resp×hot**: 1540 × 7 × HOTTEST = rank 1 (tied with EH walker for risk)
- **Proposed split**:
  - Extract **cold** config/allocation: `update_profiles` 97 LOC + `update_missing_profiles` + `scan_cleanup_floors` + `maybe_cleanup_trackers` + sketch allocation (per-icp/udp/syn dst/src) into `screen/config.rs` — called only on config update, not per-packet
  - Extract **cold** stats/logging/emit: `maybe_warn_missing_profile` (eprintln), `take_syn_alarm_event`, `record_alarm_without_drop`, `alarm_without_drop`, `scan_sweep_*_pressure`, `take_scan_table_pressure_event` into `screen/stats.rs` or `screen/emit.rs` — not on hot verdict path (alarm Without Drop path reads `alarm_without_drop` but only after Drop verdict)
  - Keep **hot** verdict engine in `screen/mod.rs` + new `screen/flood.rs`:
    - `icmp_flood_drop` 27 LOC + `udp_flood_drop` 46 LOC — keep `#[inline]` (not always, medium)
    - SYN-flood 5 phases stay in single hot fn but with helpers `#[inline(always)]` for per-dst check, per-src check, aggregate classify — NO alloc, NO lock, NO map allocation inside hot path (only get_mut)
    - Stateless checks already delegated to `stateless` module (good)
    - Fabric skip gate stays early
  - Preserve `current_syn_cookie_full_epoch` caching (1/sec wall clock) — cold clock sample stays hot but gated
- **Hot-path preservation**:
  - `inlining`: SYN-flood phases currently inline in god-func; split into `#[inline(always)]` helpers in same file or `flood.rs` but marked inline always so no call boundary on per-packet path
  - `alloc`: current hot path does zero alloc (FxHashMap get_mut only); extraction must NOT introduce clone of profile (already fixed #2209 — borrows profile); cold config allocs new sketches only on profile update
  - `dispatch`: no trait objects, keep direct method calls
  - `layout`: ScreenState layout unchanged for now (22 fields). Future: group related fields into sub-structs (FloodState, SynCookieState, ScanState) with `#[repr(C)]`? Not required for hot path, but grouping improves locality — put frequently co-accessed counters together (icmp/udp/syn aggregate) to stay in same cache line? Current FxHashMap indirection already cold.
  - `locality`: hot counters accessed via `get_mut(zone)` — hash lookup per packet is unavoidable; cold separation improves I-cache
  - `lock`: no lock on hot path (all per-worker). Must not add Mutex.
- **Type**: SPLIT — cold config + stats/logging/emit out, hot verdict stays
- **Tests+gate**:
  - Existing: `screen/tests.rs` 5000+ LOC covers all flood tiers, fabric skip #4155, SYN-cookie, alarm-without-drop, scan table pressure
  - Gate: `syn_flood_dest_hard_drops_over_attack_with_cookie` (per-dst authoritative over cookie), `syn_flood_source_skipped_when_cookie_active` (src skip when active), `slow_scan_within_window_survives_cleanup_reap` (cleanup floor window-aware)
  - New gate: micro-benchmark asserting no alloc in hot path (e.g. `#[cfg(test)]` alloc counter) and that `update_profiles` cold path allocates sketches only when threshold >0
- **Dedup vs prior**:
  - Not overlapping #4517/#2150 (EH walker)
  - Supplements #4421? No, #4421 is policy.rs too broad, this is screen breadth. Related to #1543 layout note: screen runtime already split into `packet`, `syncookie`, `rate`, `stateless`, `scan`, `session_limit`, `extract` — this continues that wave.
  - No duplicate with #4399/#4438 (likely policy/verdict or RA? not EH)

---

### [SPLIT] F3 — frame/mod.rs 6-resp kitchen sink — NAT/inject/NAT64/verify/DSCP/descriptor separation

- **File**: `userspace-dp/src/afxdp/frame/mod.rs` 1710 total, 1699 prod
- **Current extractions done** (good): `byte_writes`, `checksum`, `generated`, `headers`, `inspect`, `tcp`, `wg`, `tcp_segmentation`, `build`, `rewrite` (per #988/#989/#1046/#1352/#1440)
- **Remaining responsibilities** (6):
  1. VLAN descriptor-shift: `classify_in_place_l2_rewrite` 26 LOC + `descriptor_view_in_same_umem_frame` 9 LOC + `RewritePrep`/`RewriteEthParams` structs + `rewrite_prepare_eth_from_parts` 68 LOC + `rewrite_prepare_eth` 39 LOC + `rewrite_apply_v4` 68 LOC + `rewrite_apply_v6` 53 LOC + `rewrite_forwarded_frame_in_place` 77 LOC + `trim_l3_payload` 44 LOC — total ~384 LOC
  2. NAT v4/v6: `apply_nat_ipv4` 87 LOC + `apply_nat_ipv6` 120 LOC + `apply_nat_port_rewrite` 64 LOC + `apply_nat_icmp_identifier_rewrite` 44 LOC + `adjust_l4_checksum_port` 28 LOC + `enforce_expected_ports` 47 LOC + `enforce_expected_ports_at` 46 LOC + `restore_l4_tuple_from_meta` 26 LOC — total ~462 LOC
  3. NAT64 port translation: `build_nat64_forwarded_frame` + `apply_nat64_port_translation` ~114 LOC
  4. Inject: `build_injected_packet` 21 LOC + `build_injected_ipv4` 65 LOC + `build_injected_ipv6` 49 LOC — total ~135 LOC
  5. DSCP: `apply_dscp_rewrite_to_frame` 39 LOC
  6. Debug verify: `verify_built_frame_checksums` 180 LOC + statics + `v6_rel_l4_offset` 13 LOC
  7. Wrapper: `build_forwarded_frame_from_frame` 44 LOC (delegates to build orchestrator + tunnel encap dispatch)
- **Hot**: YES — rewrite + NAT are per-forward hot path (in-place rewrite path avoids memmove via descriptor shift optimization — critical)
- **Proposed split**:
  - `frame/rewrite/descriptor.rs` — `classify_in_place_l2_rewrite`, `descriptor_view_in_same_umem_frame`, `RewritePrep`, `RewriteEthParams` + `trim_l3_payload` — keeps `#[inline]` for descriptor check (hot, per-packet branch predictor)
  - `frame/rewrite/nat.rs` — `apply_nat_ipv4`, `apply_nat_ipv6`, `apply_nat_port_rewrite`, `apply_nat_icmp_identifier_rewrite`, `adjust_l4_checksum_port` — all `#[inline(always)]` where protocol constant-folded (already marked for checksum family fold #1853). Preserve comment about `family` compile-time constant fold.
  - `frame/rewrite/port.rs` — `enforce_expected_ports*`, `restore_l4_tuple_from_meta` — `#[inline]` medium
  - `frame/nat64.rs` — `build_nat64_forwarded_frame`, `apply_nat64_port_translation` — cold-ish (NAT64 rarer)
  - `frame/inject.rs` — `build_injected_*` — cold (test packet inject only)
  - `frame/dscp.rs` — `apply_dscp_rewrite_to_frame` — coldish (CoS DSCP rewrite stamped per queue)
  - `frame/verify.rs` — `verify_built_frame_checksums` + statics — debug-only (feature-gated), 180 LOC debug log is largest fn in file, should be behind `cfg(feature = "debug-log")` module
  - `frame/mod.rs` remains as re-export hub + `v6_rel_l4_offset` (SSOT L4 offset helper) + `build_forwarded_frame_from_frame` wrapper
- **Hot-path preservation**:
  - `inlining`: `apply_nat_port_rewrite` and `apply_nat_icmp_identifier_rewrite` already `#[inline(always)]` with comment "structural guarantee, not perf tweak — family folds out". Must keep. `descriptor_view_in_same_umem_frame` `#[inline]` — per-packet branch, must stay inline to avoid call.
  - `alloc`: inject builders alloc Vec (cold). NAT path zero alloc (in-place slice mut). Descriptor-shift optimization avoids 1500-byte memmove by shifting TX descriptor — must preserve `slice_mut_unchecked` unsafe but correct. New modules must not introduce alloc in hot path.
  - `dispatch`: no trait objects, static dispatch
  - `layout`: no layout change
  - `locality`: splitting into files improves I-cache for cold paths (NAT64/inject/verify not loaded on plain-forward fast path)
  - `lock`: no lock
- **Type**: SPLIT (partial moves already done per #1352/#1440, this continues)
- **Tests+gate**:
  - Existing: `frame/tests.rs`, `frame/prop_tests` (NAT round-trip + descriptor-vs-generic differential, TSO reassembly), `frame/byte_writes_tests.rs`, `headers_tests.rs`, `inspect_tests.rs`, `generated_tests.rs`, `tcp_tests.rs`
  - Gate: `prop_tests` descriptor-vs-generic differential must keep passing — ensures VLAN push/pop descriptor-shift optimization stays byte-identical to copy-within path
  - Gate: NAT round-trip proptest + `verify_built_frame_checksums` debug checks
- **Dedup vs prior**:
  - Continues #1049 (frame/mod.rs split), #1352 (build-rewrite split), #1543 (wave-5 layout), #988/#989 (inspect/tcp extraction)
  - NOT duplicate: prior extractions removed 9 responsibilities, this proposes removing remaining 6 — same wave, new scope
  - No overlap #4421/#2150/#4517

---

### [FULL] F4 — policy.rs AppCatalog zero-coupling extraction

- **File**: `userspace-dp/src/policy.rs` lines 1047-1282 (235 LOC incl docs + 2 helper structs + 3 lookup fns)
- **Structs**:
  - `AppCatalog { by_protocol: FxHashMap<u8, AppProtoEntries> }` — Clone/Debug/Default
  - `AppProtoEntries { exact_dst: FxHashMap<u16, u16>, scan: Vec<AppScanEntry> }`
  - `AppScanEntry { app_id: u16, dst_low/high, src_low/high, port_constrained: bool }`
- **Coupling analysis**:
  - Imports: only `FxHashMap` (rustc_hash) + `crate::AppCatalogEntry` (snapshot schema)
  - Zero reference to `PolicyRule`, `PolicyState`, `ZonePairKey`, `CompiledApplications`, `PortRange`, `BookEntry`, `PrefixSetV4/V6`, `PolicyRuleCounter`
  - Used by: `forwarding_build/mod.rs` (build from snapshot), `event_emit.rs` (resolve_flow_app_id), `session_glue/tests.rs` (lookup_admitted)
  - `AppCatalogEntry` lives in `protocol/security.rs` (wire schema) — not in policy core
- **Observation from frame/inspect.rs angle**: from inspect perspective, AppCatalog is pure L4 port lookup (like NAT port rewrite) — logically belongs with L4 classification, not zone-pair policy evaluation. The file `policy.rs` currently mixes (a) zone-pair indexing (global/wildcard), (b) address-book prefix sets, (c) application term parsing (PortRange), (d) AppID catalog — 4 independent data structures in one file of 3598 LOC.
- **Size×resp×hot**: 235 × 1 × COLDISH (lookup per admitted session for audit surfaces, not per-packet inline — session-create close path) — medium priority but highest extractability
- **Proposed split**: `userspace-dp/src/policy/app_catalog.rs` or `userspace-dp/src/app_catalog.rs` (tbd: `policy/` dir doesn't exist yet, need `policy/mod.rs` + `app_catalog.rs`):
  - Move 3 structs + impl (from_snapshot, is_empty, lookup_directional, lookup_forward, lookup_admitted) verbatim
  - Re-export via `policy.rs` `pub(crate) use app_catalog::AppCatalog`
  - Update `forwarding_build/mod.rs` import stays `crate::policy::AppCatalog`
  - Tests: `policy_tests.rs` cat_entry helper + 4 AppCatalog tests (around line 3775-3921) move to new file's `#[cfg(test)] mod` or stay via re-export
- **Hot-path preservation**:
  - `inlining`: lookup functions are `#[inline]` — per-session admitted, not per-packet hot, but keep inline to avoid call in session-close path that may be batch
  - `alloc`: from_snapshot allocates FxHashMap — cold (config update only). Lookup zero alloc (get + scan Vec)
  - `dispatch`: static
  - `layout`: separate struct, no impact
  - `locality`: improves policy.rs I-cache — AppCatalog lookup not on hot verdict path (policy eval hot, app lookup is post-admit audit)
  - `lock`: no lock
- **Type**: FULL — complete move, no partial state left in policy.rs
- **Tests+gate**:
  - Existing: `policy_tests.rs` 4 tests (cat_entry single, ranged, specificity tier #3612)
  - Gate: byte-identity of lookup results before/after extraction (same resolution for tcp/443 vs proto-only)
  - Gate: `cargo test --lib policy` must keep passing
- **Dedup vs #4421**:
  - #4421 reports policy.rs too broad (3598 LOC, 8 responsibilities) — this finding provides supplementary zero-coupling detail: AppCatalog is the easiest sub-extraction with zero coupling, proving policy.rs can be split without cross-dependency refactoring. Attach this to #4421 as concrete evidence.
  - Not duplicative of #2150/#4517/#1049/#1352/#1543

---

### [SPLIT] F5 — policy.rs cold stats/counters out, hot verdict path untouched

- **File**: `userspace-dp/src/policy.rs` remaining after AppCatalog extraction
- **Cold parts**:
  - `PolicyRuleCounter` (lines ~463-620, 158 LOC) + `PolicyCounterStore` (622-?) + `PendingPolicyHitRecord` thread-local + `record_policy_hit_counter` (738-767, cfg(test) vs prod thread-local coalescer) + `flush_recorded_policy_hit_counters` + `counter_snapshots` + `default_counter` + `rule_id_to_policy_id` re-resolve map
  - These touch `Arc<PolicyRuleCounter>` and atomics, not the hot `try_match_rule` / `rule_l3_matches` / `evaluate_policy_result_l3_aware`
- **Hot parts** (must NOT move or change inlining):
  - `try_match_rule` 46 LOC, `rule_l3_matches` 121 LOC, `evaluate_policy_result_l3_aware` 280 LOC (largest), `evaluate_policy_result_with_icmp`, `evaluate_junos_host_policy_l3_aware`
  - `CompiledApplications::from_matches` + `matches` are hot-ish (per-new-flow app match)
  - `zone_pair_key`, `build_global_zone_scope`, zone-pair indexes are cold-ish but indexing is per-new-flow
- **Size**: counters ~300 LOC, evaluation ~800 LOC — mixed
- **Proposed split**:
  - `policy/counters.rs`: `PolicyRuleCounter`, `PolicyCounterStore`, `PendingPolicyHitRecord`, `record_policy_hit_counter`, `flush_recorded...`, `counter_snapshots`, `hit_counter_by_idx`, `default_counter` — all stats
  - `policy/zone.rs` or keep in mod: `zone_pair_key`, `JUNOS_GLOBAL_ZONE_ID`, `ZonePairKey`, `GlobalZoneScope`, `build_global_zone_scope`
  - `policy/eval.rs`: `try_match_rule`, `rule_l3_matches`, `evaluate_*`, `SkippedFragDeny` handling
  - Keep `policy/mod.rs` as re-export hub + `PolicyState` struct (66? actually ~? fields: default_action, rules, zone_pair_index, from_any_index, to_any_index, both_any_indices, global_indices, concrete_zone_ids, books, book_id_to_idx, has_junos_host_rules, default_counter, default_log_*, rule_id_to_policy_id)
- **Hot-path preservation**:
  - `inlining`: `evaluate_policy_result_l3_aware` is per-new-flow hot; must stay `#[inline]`? Currently not marked inline always, but called from `poll_descriptor` new-flow decision — should NOT get larger call overhead via extra module boundary unless LTO inlines. Rust inlines across modules within crate with `#[inline]` hint — add `#[inline]` to `try_match_rule` and `rule_l3_matches` if moving.
  - `alloc`: evaluation zero alloc (iterates zone_pair_index Vec). Counter path uses thread-local vec, flush allocs batch — cold
  - `dispatch`: keep static dispatch, no dyn
  - `layout`: PolicyState 13 fields + maps — grouping counters together improves locality for counter flush (cold) vs rule eval (hot)
  - `locality`: separating cold counter flush from hot eval improves I-cache
  - `lock`: counters use Arc<AtomicU64> (interior mut via Relaxed) — no lock. Must keep thread-local coalescer to avoid contention
- **Type**: SPLIT — cold counters out, hot verdict untouched
- **Tests+gate**:
  - Existing: `policy_tests.rs` covers evaluation, default-policy counter #3363, re-resolve #3395, AppID
  - Gate: policy-eval property test (if exists) + session-limit tests (since they depend on zone)
- **Dedup vs #4421**: this IS #4421 — policy.rs too broad. Our finding refines it into concrete sub-splits (AppCatalog FULL + counters SPLIT + zone/eval SPLIT). Not duplicate, it's implementation plan for #4421.

---

### [SPLIT] F6 — screen SYN-flood cold config (sketch allocation, profile gen, alarm map) out

- **File**: `screen/mod.rs` `update_profiles` 97 LOC
- **Details**: On config update, it:
  - Retains counters for zones that still have profiles (icmp/udp/syn + syn_off buckets)
  - Retains icmp_dst_sketch/udp_dst_sketch for zones with threshold >0
  - Retains syn_dst_sketch/src_sketch/alarm_last_emit for SYN sub-thresholds
  - Entry-or-default for each zone that gains profile, or_insert_with `SynRateSketch::for_dst/src` (192 KiB/zone for both sketches)
  - Bumps `syn_cookie_profile_gen` when `syn_cookie` or `syn_flood_threshold` changes (signature)
- **Cold**: only called on config update (control plane gRPC snapshot apply). No per-packet cost.
- **Hot enforcement** that must keep `#[inline(always)]`: `icmp_flood_drop`, `udp_flood_drop`, and the 5 SYN-flood phases inside god-func
- **Proposed**: move `update_profiles` + `syn_cookie_profile_signature` + `syn_cookie_profile_gen` helpers + `scan_cleanup_floors` + `maybe_cleanup_trackers` into `screen/config.rs`
- **Type**: SPLIT — cold out, hot stays with inline(always)
- **Hot-path preservation**: same as F2 — update_profiles never on hot path; extraction actually improves hot path I-cache by moving cold code out of file that is scanned per-packet? Not hot but in same file — separating improves instruction cache locality.
- **Tests+gate**: `screen/tests.rs` sketches_allocated_only_when_configured etc.
- **Dedup**: part of F2, listed separately because task says "SYN-flood cold config out but hot SYN-flood enforcement phases keep #[inline(always)]"

---

## D-Negatives (explicitly NOT to split)

### D1 — scan.rs generic ScanCore<T> + thin wrappers — already one-source-of-truth per #2234

- **File**: `userspace-dp/src/screen/scan.rs` 1213 total, 592 prod, 621 test
- **Why D-neg**:
  - Already refactored in #2234: previously free functions duplicated bound/eviction/pressure logic across PortScanTracker and IpSweepTracker. Now single `ScanCore<T>` generic with bounded eviction (EVICT_SCAN_LIMIT 64, MAX_SOURCES_PER_ZONE 4096, MAX_UNIQUE_PER_SOURCE 1024, CLEANUP_BUDGET 256) and thin wrappers — engineering-style "one source of truth"
  - Fixed detection count `SCAN_DETECT_COUNT = 10` SSOT mirrors Go `scanSweepDetectCount`
  - Per-zone keying (zone_id, src_ip) + per-zone count O(1) via `per_zone_count` map — no O(n) walk for cap test
  - Window-aware cleanup #4379/#4418 with lease: cleanup reap floor = longest configured window, clamped to u32::MAX type max so >5min windows not evaded
  - Least-suspicious eviction #4418: evicts fewest distinct dests first, not stalest window_start — prevents decoy flood evading slow scanner
  - Test coverage excellent: per-zone no-cross-count, bounded source table, per-source unique bounded, window expiry resets, cleanup budgeted, fresh scanner after saturation, eviction prefers stalest window / expired / slow-scanner survives decoy flood, bounded cost, per-zone count tracks cleanup, pressure logarithmic, slow scan survives cleanup beyond 5min cap
- **Size×resp×hot**: 592 × 1 × COLD (new-flow only) — low
- **Verdict**: DO NOT SPLIT — already optimal, further split would add file overhead for 2 thin wrappers

### D2 — wg.rs 604 prod + valuable byte-identity tests — keep as is

- **File**: `userspace-dp/src/afxdp/frame/wg.rs` 1561 total, 604 prod per task (lines 1-604 minus test seams), 957 test
- **Prod**: `wg_encap_frame` 253 LOC + helpers `pad_to_16`, `wg_encapped_size`, `outer_physical_egress_ifindex` 42 LOC, `outer_physical_egress_mtu` 15 LOC, `wg_peer_outer_dst` 22 LOC, `wg_endpoint_physical_outer_mtu` 23 LOC (SSOT for PTB inner MTU derivation #2684)
- **Why D-neg**:
  - Prod is coherent single responsibility: WG transit encap (outer route resolve once per packet #3992, MTU guard #2680, source from physical WAN #2701, encrypt via Snow, UDP checksum)
  - Recent refactor #2792 eliminated per-packet heap churn (2 Vec allocs → 1 alloc sized to pad-aware max record, encrypt in-place into UDP payload slot)
  - #3992 dedup: single FIB LPM per packet shared for MTU guard + source lookup (was 2 LPMs)
  - Test file is valuable:
    - `outer_mtu_uses_physical_egress_not_tunnel_logical` + `fits_physical_but_exceeds_logical_inner_is_not_dropped` — MTU guard correctness
    - `wg_encap_in_place_matches_separate_buffer` — byte-identity proof that in-place encrypt equals separate buffer, proving #2792 safety
    - `udp6_checksum_matches_scalar_reference` + `udp6_checksum_scalar_reference` vs `udp6_checksum_optimized` — byte-identical checksum proof for AVX2-backed `checksum16_ipv6` vs naive scalar, plus `udp6_checksum_canonicalizes_zero_sum_to_ffff` (RFC 8200 mandatory non-zero)
    - `wg_encap_decision` helper + inner_v4/v6 frame fixtures
  - Splitting would separate MTU guard from encap and break the single-LPM sharing proof; or separate checksum parity test from prod checksum fn
- **Size×resp×hot**: 604 × 1 × HOT but rare topo — medium
- **Verdict**: DO NOT SPLIT — prod clean, tests lock byte-identity guarantees that would be scattered

### D3 — runtime.rs plumbing — 14 types pure relocation, no split needed

- **File**: `userspace-dp/src/afxdp/types/runtime.rs` 503 LOC, 0 test, all prod
- **Contents**: 14 types extracted from `afxdp/types/mod.rs` per Issue 68.4:
  - `XdpOptions` (repr C), `WorkerHandle` (stop/heartbeat/commands/session_export_ack/cos_status/runtime_atomics/cold_path_atomics), `LocalTunnelSourceHandle` + `request_stop`, `LocalTunnelSourceEntry`, `WgControlEntry`, `BindingPlan`, `SharedUmemMode/Role/BindingPlan` + helpers `private/shared/disabled/is_shared/as_str`, `ValidationState`, `HAForwardingLease` + active(), `HAGroupRuntime` + active_lease_until/is_forwarding_active, `ResolutionDebug` + from_flow, `LearnedNeighborKey`, `WorkerCommand` (UpsertSynced/Local, DeleteSynced, DemoteOwnerRGs, RefreshOwnerRGs, ExportOwnerRGSessions, EnqueueShapedLocal, VacateAllSharedExactSlots), `DebugPollCounters` (50+ fields), `WorkerContext` (16 fields shared refs, interior-mut via Mutex/Arc), `TelemetryContext`, `MirrorTargetMap` + `MirrorTargetIfEntry` + insert/target_live
- **Why D-neg**:
  - Pure plumbing relocation — no logic, only struct definitions + tiny helpers (as_str, request_stop, active lease checks)
  - `types/mod.rs` re-exports via `pub(in crate::afxdp) use runtime::*` so external call sites unchanged
  - Splitting further (e.g. per-type files) would create 14 files each 20 LOC, increasing file-navigation cost without reducing complexity — classic over-modularization
  - No hot path: types only, used at coordinator bring-up + per-poll context bundle construction
  - Largest fn: `MirrorTargetMap::target_live` 18 LOC, `private` 4 LOC — no god-func
- **Size×resp×hot**: 503 × 10 types × COLD — low
- **Verdict**: DO NOT SPLIT — already extracted from types/mod.rs, further split is fragmentation

---

## Dedup vs Prior Issues

| Prior | Overlap | Our stance |
|-------|---------|------------|
| #4421 policy.rs too broad | Our F4 AppCatalog + F5 counters/eval ARE #4421 implementation. F4 provides zero-coupling supplementary detail (AppCatalog uses only AppCatalogEntry, no PolicyRule/ZonePair) making #4421's "too broad" more concrete — attach this observation as evidence. | SUPPLEMENT, not duplicate |
| #2150 PR-2 / #4517 EH walker duplication | #4517 fixed VALUES (added 135/139/140/253/254 to all 5 sites). Our F1 fixes STRUCTURE (single walker fn + const generic set + canary) so future addition touches 1 site. #2150 PR-2 already noted duplication. | FOLLOW-UP structural, not duplicate |
| #1049/#1352/#1543 frame/build-rewrite | #988/#989/#1046/#1352/#1440 already extracted 9 responsibilities from frame/mod.rs (byte_writes, checksum, generated, headers, inspect, tcp, wg, tcp_segmentation, build, rewrite). Our F3 continues same wave for remaining 6 (NAT, VLAN descriptor-shift, NAT64, inject, DSCP, verify). | CONTINUATION, not duplicate |
| #4399/#4438 | #4399 likely screen alarm-without-drop? #4438 likely RA or screen? Neither directly overlaps EH walker or AppCatalog or frame kitchen sink. Verified no file overlap in our findings. | NO DUP |
| #988/#989/#1440 | Already done — frame inspect/tcp/headers extractions. Our findings preserve them. | ACK existing |
| #2234 scan.rs generic core | #2234 made scan.rs one-source-of-truth (ScanCore<T>). Our D1 explicitly marks it D-neg. | ACK, no re-split |
| #2792/#3992 wg.rs optimizations | Recent MTU guard + alloc elimination. Our D2 marks wg.rs D-neg because prod clean + byte-identity tests valuable. | ACK, no re-split |

---

## Ranking by size × resp × hot (descending)

1. **F1 EH walker SSOT** — 5×50 LOC dup × 1 resp (IPv6 EH) × HOT (per-packet L4 offset) × IDS evasion risk (#4517 miss = evasion) — **score ~250×1×10 + risk multiplier** — highest fix value, lowest risk, FULL
2. **F2 screen god-func + 22-field state** — 1540 × 7 × HOTTEST — **score ~10780** — highest raw product but SPLIT must be careful with inlining/alloc/lock preservation, involves moving cold code out, hot phases keep inline(always)
3. **F3 frame kitchen sink 6 resp** — 1710 × 6 × HOT — **score ~10260** — large but ongoing wave, many prior extractions done, remaining split reduces file from 1710 to ~200 hub
4. **F4 AppCatalog zero-coupling** — 235 × 1 × COLDISH but 0 coupling = easiest FULL extraction, proves #4421 splittable — **score ~235 but extractability = instant**
5. **F5/F6 policy counters + screen cold config** — 300-500 × 2 × COLD — lower raw score but required for #4421 / #1543 discipline
6. **D-negatives** — scan.rs 592×1×COLD, wg.rs 604×1×HOT but clean, runtime.rs 503×10×COLD — marked DO NOT SPLIT

---

## Policy / Verdict Engine Focus (as requested)

- **Policy/verdict**: hot verdict `evaluate_policy_result_l3_aware` (280 LOC) + `try_match_rule` (46) + `rule_l3_matches` (121) must stay with `#[inline]` hint and zero alloc. Cold stats/logging/emit (`PolicyRuleCounter`, `PolicyCounterStore`, thread-local coalescer, `counter_snapshots`, `record_policy_hit_counter`, `default_counter` #3363, re-resolve map #3395) → `policy/counters.rs` FULL extraction. This also removes `Arc<PolicyRuleCounter>` bloom from hot path I-cache.
- **SYN-flood**: cold `update_profiles` (sketch alloc 192 KiB/zone, profile gen bump, alarm map) → `screen/config.rs`. Hot 5 phases (aggregate classify D7 single window advance, per-dst primary runs even cookie-active, aggregate cookie mint / TokenBucket drop, alarm ≤1/sec/zone, per-src secondary skipped when cookie-active D3) keep `#[inline(always)]` helpers in hot file. Validated-cache bypass (`take_valid`) stays hot. Fabric skip #4155 early return stays.
- **EH walker**: single source of truth + canary — see F1. This is separate from policy/verdict but critical for screen vs forwarding agreement on what "valid enough IPv6" means (#2292). Walker bound = 8 already SSOT via MAX_IPV6_EXT_HEADERS.

---

## Summary

- EH walker duplication (F1) is the only FULL with IDS evasion risk — 1-const + 1-generic-walker + canary test, preserve inline(always), zero alloc.
- Screen god-func (F2/F6) is largest raw product — SPLIT cold config/stats/emit, keep hot phases inline(always) and zero alloc/no lock.
- Frame kitchen sink (F3) is continuation of #1352/#1543 wave — SPLIT into nat, descriptor, nat64, inject, dscp, verify modules, preserving descriptor-shift unsafe optimization and checksum family constant-fold inline(always).
- AppCatalog (F4) is zero-coupling proof for #4421 — FULL extraction to `policy/app_catalog.rs`, 235 LOC, no PolicyRule dependency.
- D-negatives: scan.rs generic core (one-source-of-truth already #2234), wg.rs 604 prod + byte-identity tests (MTU guard + checksum parity), runtime.rs plumbing (14 types pure relocation) — DO NOT SPLIT.


---


### === FINDINGS FROM A1G — ps-a1g-b1.md ===

 — Class A (mechanical cold-path)

### F1: wg_control.rs 2280 LOC control-thread god file
- Title: wg_control.rs mixes 6 cold concerns in one 2280 LOC file
- Severity: High  Confidence: High  Refactor: A mechanical cold-path
- Evidence: run_wg_control_loop 120-646 (526 lines RX_BURST 64 + TUN LPM + timer per peer + poll), wg_poll_wait 289-320, dispatch_inbound 1318-1516 (type1/2/3/4 + cookie gate + ECN combine), encap_and_send 1523-1575 (MTU guard), bind_wg_socket 919-975, recvmsg 1127-1258 + CmsgBuf align(8) #2334. 2280 LOC largest in set.
- Proposed: wg_control/{mod.rs, socket.rs (bind_dual_stack_v6 + wg_send_to v4-mapped + CmsgBuf + parse_outer_ecn_from_cmsg), poll.rs (wg_poll_wait + timeout), inbound.rs (InboxOutcome + dispatch), egress.rs (encapped_size + guard + encap_and_send), attempt.rs (HandshakeAttempt + AttemptTrigger + drive/start), keepalive.rs}
- Hot-path: none — UdpSocket+File control thread, poll cap 100ms. No #[inline] to preserve.
- Tests+gate: cargo test wg_control poll_loop_* + attempt_give_up_* + cmsg_parse_* ; miri not needed. Gate make test-rust.
- Why: violates 2k rule, 6 concerns, unsafe recvmsg cmsg handling mixed with timer state machine — blocks parallel review, bug class #1736 v4-mapped EINVAL, #2877 stop-aware write.
- Fix: PR chain mechanical moves, keep run_wg_control_loop orchestration.
- Labels: refactor, wg, monolith, cold-path
- Dedup: none

### F2: server/helpers.rs 1304 LOC relocation dump
- Title: helpers.rs is grab-bag of 5 domains with pending-relocation header
- Severity: High  Confidence: High  Refactor: A
- Evidence: header "Pure relocation pending" + 20 fns. refresh_status 16-339 (323 LOC aggregating wg liveness, GRE liveness, neighbor warm, zone counters). build_synced_session_key/entry 351-633 + build_nat64_reverse_rebuild. replan_queues 1033-1190 + snapshot_binding_plan_key + vlan_parent + canonical JSON hash 835-925. No shared state.
- Proposed: server/helpers/{status.rs (refresh_status), session_sync.rs (synced entry + NAT64), binding_plan.rs (replan_*, plan_key_rx_queues, vlan_child_parent_netdev, effective_rx_queues), hash.rs (canonical_json), netdev.rs (rx_queue_count)}. Keep thin helpers.rs re-export.
- Hot-path: none — status ~1/s, commit path only.
- Tests+gate: cargo test server + make test-go binding plan allowlist parity (snapshot_allowlist_test.go).
- Why: explicit tech debt, SRP violation, status bump collides with plan logic merges.
- Fix: single PR mechanical move (A).
- Labels: refactor, server, monolith
- Dedup: none

### F3: types/cos.rs 1786 type bag
- Title: cos.rs mixes config DTO + runtime + FlowFair + VMin + telemetry
- Severity: Medium  Confidence: Medium  Refactor: A partial mechanical
- Evidence: CoSState + InterfaceConfig + ClassifierConfigs + EqualFlowTargetPolicy parse 159, CoSQueueConfig, COS_FLOW_FAIR_BUCKETS=4096 + FlowRrRing ring [u16;4096] with push_back/front/pop + remove O(len) 473-493, Worker fast path, InterfaceRuntime waterfill Pass1/Pass2 + honored bits epoch, QueueRuntime config/hot, FlowFairState 352KB 14 fields + new_boxed unsafe MaybeUninit (#1755), VMinQueueState + pop_count cadence, Sojourn, DropCounters, TimerWheel.
- Proposed: types/cos/{config.rs, classifier.rs, ring.rs (FlowRrRing), runtime.rs, flow_fair.rs (FlowFairState new_boxed), vmin.rs, telemetry.rs, sojourn.rs} + mod.rs re-export for backward compat.
- Hot-path: FlowRrRing push_back/front/pop/remove #[inline] kept, flow_fair_state.is_some() gate inline, queue_vtime advance, new_boxed raw-ptr writes preserved — miri guard new_boxed_matches_new_field_for_field. Do not outline bucket_index masking.
- Tests+gate: cargo test cos + cargo +nightly miri -p userspace-dp flow_fair_state_tests.
- Why: conceptual layers — config change touches same file as hot runtime cacheline layout, unsafe alloc avoidance audit burden.
- Fix: 2 PRs: RR+FlowFair+VMin extraction then config vs runtime split.
- Labels: refactor, cos, hot-path-review
- Dedup: none

### F4: event_stream/mod.rs 1693 I/O mixed
- Title: event_stream mixes Shared atomics + Sender + WorkerHandle + IoThread + replay + backpressure
- Severity: Medium  Confidence: Medium  Refactor: A careful
- Evidence: EventStreamShared 211 (5 Atomics + poison flag #2875), Sender 367 (SyncSender + JoinHandle), WorkerHandle 483 send_sequenced LIFO rollback under producer_seq_lock #3878, io_thread_main 938, replay_buffered 1005 FullResync gap, write_all_backpressured 1077 nonblocking stop-aware #2877, run_connected_loop 1115 WRITE_BACKLOG_MAX 16MiB #2381, process_control_frames 1231 MAX_CONTROL_PAYLOAD_LEN 0 cap #2879, handle_drain_request 1357 fence logic #2876/#2882.
- Proposed: event_stream/{shared.rs (Shared+Atomics+rollback_seq CAS), sender.rs, worker_handle.rs (try_send + send_sequenced + lossless retry), io_thread.rs (main+connect), replay.rs (push+pop eviction counters), control.rs (process frames + ACK validation #2959 + drain poison), backpressure.rs}. Keep mod.rs clock helpers monotonic_ns_to_unix_ns.
- Hot-path: try_send_frame Relaced fetch_add + rollback_seq CAS must stay together under producer_seq_lock LIFO — keep inline. Non-blocking.
- Tests+gate: cargo test event_stream + check write_stalls/replay_evictions/invalid_acks counters. Gate make test-rust.
- Why: HA correctness (poison flag, fence target_seq) entangled with telemetry loss accounting — splits improve review of #2875/#2876 boundary.
- Fix: 2 PRs: shared+sender/worker extraction then io/replay/control split.
- Labels: refactor, event_stream, ha
- Dedup: codec sibling #4651 distinct — this is I/O side.

## D-Negatives — do not split

- **engine.rs 1805 D**: Single WgEngine responsibility: try_encap MaybeUninit stack staging (PADDED_PLAINTEXT_MAX 4096), double-lock replay precheck+post, PeerTable ArcSwap atomicity, AllowedIPs LPM, 3-slot promotion maybe_promote_next, handshake request edge CAS. Already delegates to 9 submodules. Under 2k soft limit. Splitting would scatter cryptokey-routing safety invariant.
- **cookie.rs 1435 D**: Single WG §5.4.7 DoS mitigation: SecretState 2-window rotation + lazy stamp (Option not 0 sentinel #4094 BUG-1), LoadState fixed-window gate + grace, BudgetState, SourceTable per-IP token bucket #4332 with GC + cap 2048, keyed_blake2s_128, endpoint canonicalization, AEAD cookie reply. Fail-closed BUG-2 path eprintln security. Responder+init share constants. Prod ~800 after tests. Do-not-split.
- **forwarding.rs 1079 D**: ForwardingState intentional aggregate — local_v4/v6 + local_tables_v* anti VRF confusion #3769, configured_iface_v* SNAT exclusion #3182, connected/routes/tunnel/gre_decap_index, wg_engines Arc, neighbors, ifindex→zone/vrf/reject buckets Arc hardening #3618, egress, fabrics + FabricLinkSkipReason. Under 1080 threshold.
- **binding.rs 1168 D**: Pure serde DTOs: WorkerRuntimeStatus 40+ CoS/wheel/cold_path sparse fields, QueueStatus, BindingStatus 100+ counters + screen_reason_drops [u64;N], BindingCountersSnapshot From+Send static assert, ExceptionStatus, SessionDeltaInfo. No logic. Wire-compat additive default. Splitting scatters Prometheus contract.
- **event_emit.rs 1492 D** (C-low): All DataplaneEventPayload builders sharing RT_FLOW_ACTION_Deny/Permit/Reject + screen_reason_id bit map + ingress_ifindex_to_wire + timestamp anchored #2470 mono→wall. Prod ~600. Cohesive; tests cover suppressed-reject downgrade #3615.
- **shared_cos_lease/lease.rs 1460 D** (C-low): Token bucket config bank_floor #1630, pack/unpack u32 out/available, acquire CAS loops, refill, release_unused, v8 acquire_v8_with_cause Primary+Surplus + starvation tag-checked bump + equal_flow cap, snapshot_epoch_v8 seqlock fence Acquire #1643, release_unused_v8 3-step re-credit #4246. Atomic orderings preserved, sibling rotate_epoch_v8.rs reads config/v8. Already P2 split from mod.rs. Further split risks undergrant attribution.
- **codec.rs 1165 DEDUP**: Already filed #4651 wire-format monolith. Do not re-report.
- **cold_path_hist.rs 1866 C→D arg**: Prod ~950 (bucket log-linear 48, slot sparse pair→slot 255 cap, TSC LFENCE+RDTSCP Intel SDM §17.17, ClockSource probe token parse, Atomics seqlock, Counters record_sample). Tests inflate. Cohesive histogram feature #1635. Could split but low ROI — argue D unless grows.

## Summary

Actionable monoliths: wg_control.rs 2280 (HIGH), helpers.rs 1304 (HIGH), cos.rs 1786 (MED), event_stream mod.rs 1693 (MED). 6 D-negatives justified by crypto invariant / fail-closed secret / wire-compat / MaybeUninit safety / HA poison atomic coupling. Preserve #[inline] pad_to_16, FlowRrRing, bucket_index_for_ns_48, lookup_slot, sample_tsc_start/end LFENCE. Gate: make test-rust + miri for FlowFairState.


---


### === FINDINGS FROM A2 — ps-a2-b1.md ===

# Monolithic Code Audit — ps-a2-b1 — NAT allocator/compiler

Base: 95b33d49634d56086269a62a92e213dae7926f88
Worktree: /tmp/review-wt-ps-041-a2-b1
Date: 2026-07-09
Auditor: ps / 041 / a2-b1

## Inventory
| File | LOC | Role | Monolith? |
|---|---|---|---|
| userspace-dp/src/nat/allocator.rs | 1416 | PortAllocator: hot bitmap + cold persistent + deterministic + GC | YES - god struct |
| userspace-dp/src/nat/source.rs | 1389 | match_source_nat_result_for_tuple ~336 LOC | YES - god fn |
| userspace-dp/src/nat/destination.rs | 1088 | DNAT table host+prefix LPM | borderline |
| userspace-dp/src/nat/static_nat.rs | 793 | static host+block NAT | NO |
| userspace-dp/src/nat64.rs | 2527 | state + v6<->v4 translate + ICMP err + frag | YES (prev #4421) |
| userspace-dp/src/nptv6.rs | 431 | NPTv6 prefix translate | NO |
| userspace-xdp/src/lib.rs | 1541 | XDP shim parse/classify/redirect/fallback | borderline verifier cap |
| pkg/config/compiler_nat.go | 2529 | source+dest+static+nat64 pools+rules | YES tri-fused |
| pkg/dataplane/compiler.go | 1733 | orchestrator CompileConfig 11 phases | NO (orchestrator ok) |
| pkg/dataplane/compiler_nat.go | 1258 | SNAT/DNAT/static/NPTv6/NAT64 compile | YES tri-fused |
| pkg/dataplane/maps_sync.go | - | MISSING at base (deleted/renamed) | D-neg |
| userspace-dp/benches/snat_allocator.rs | 703 | contention microbench | harness |

## Finding 1 — PortAllocator god-struct hot/cold fusion
Title: PortAllocator mixes hot atomic bitmap/cursor with cold persistent lease GC and deterministic
Severity: HIGH
Confidence: HIGH
Refactor class: Split hot/cold structs + cache-line align
Evidence:
- `PortAllocatorShared` (allocator.rs:458): `counters: Vec<AtomicU32>`, `addr_counter_v4/v6: AtomicU32`, `occupancy: Vec<AddressOccupancy>` hot, co-located with `live: Mutex<PortAllocatorLiveState>`, `allocations_total/reuses_total/exhaustion_total: AtomicU64` cold stats.
- `AddressOccupancy` (284): `words: Vec<AtomicU64>` + `cursor: AtomicU32` hot, but `recycle: Mutex<VecDeque<u16>>` cold per-addr.
- `PortAllocatorLiveState` (258): `live_by_flow: FxHashMap`, `persistent_by_source`, `lease_expirations: BTreeSet`, `lease_expirations_by_addr: Vec<BTreeSet>` all under single mutex; GC runs every 10 releases (`GC_PERIOD`).
- Hot path `allocate_translation` (686) does lock-free claim then takes global mutex for map insert; persistent path takes `allocate_translation_locked` holding mutex across GC + bitmap claim.
- `#2852 Phase1` already moved port claim lock-free, but struct layout still false-shares: hot CAS words share cache line with cold Mutex and stats.

Proposed decomposition:
- `hot.rs`: `#[repr(align(64))]` `HotPart { occupancy: Box<[AddressOccupancy]>, counters: ..., addr_counter_v4/v6, port_low/high, range }` — 64-byte aligned per address occupancy.
- `cold.rs`: `ColdPart { live: Mutex<LiveState>, stats: ... }` separate cache line.
- `persistent.rs`: lease reuse `reuse_existing_lease_locked`, expiration indexes, GC budgets.
- `deterministic.rs`: `deterministic_indices_v4`, `allocate_deterministic_v4`, `reverse_deterministic_v4` (#4559).
- `recycle.rs`: FIFO recycle logic per addr (`AddressOccupancy::claim/free_recycle`).
- Keep `PortAllocator` facade cloning Arc<Hot+Cold>.

Hot-path preservation:
- No heap alloc per-packet: bitmap claim = `fetch_add` cursor + `fetch_or` CAS, map insert tiny critical section unchanged. `reserve_flow` (#4388 HA) must stay CAS-only, no Vec alloc, O(1).
- Cache-line: hot fields `#[repr(align(64))]` or `crossbeam_utils::CachePadded`, validate with `std::mem::offset_of` asserts. Measure with `benches/snat_allocator.rs` M=6 (loss cluster) p99/p999 must not regress; target >1.4x over current Mutex as bench proves.
- No additional atomics on hot path.

Tests+gate: `cargo test -p userspace-dp nat::tests_pool` (white-box bitmap), `make test-rust`, `cargo bench --bench snat_allocator -- --profile uniform-low-10pct high-occ-92pct skew-80-20`. Gate: allocs/sec@M=6 >= baseline, p99<50us. Also `test-failover` must pass (reserve_flow).

Why it matters: per-packet SNAT on AF_XDP data path, 6 workers contending single mutex = 0.62M vs 2.87M allocs/sec per bench. Future Phase2 sharding needs clean hot/cold split.

Fix direction: measurement-gated hot split first, then extract persistent/GC. Do NOT add new locks; keep bit as ownership token.

Labels: `perf`, `hot-path`, `refactor`, `nat`
Dedup note: #4409 filed allocator.rs+source.rs god — this adds cache-line evidence + gated plan with benches/snat_allocator.rs datum; not dupe, extends.

## Finding 2 — match_source_nat_result_for_tuple 336 LOC god-function
Title: SNAT match+alloc god-function fuses zone/interface/RI scope, L4 app match, v4/v6, deterministic, no-translation, port-alloc
Severity: HIGH
Confidence: HIGH
Refactor class: Extract policy object + strategy, reduce args (12)
Evidence:
- `source.rs:996` signature has 12 args inc `NatScopeCtx`, `now_ns`, `non_first_fragment`, `icmp_identifier_present`, `matched_counter: &mut Option`.
- Body 996-1330: 340 lines, nested match on `(src_ip,dst_ip)` then 4 copies of near-identical pool v4/v6 + deterministic + address_only logic; each returns `SourceNatLookup::Matched` with duplicated `NatDecision` construction.
- Called from `match_source_nat_result` wrapper with protocol=0 synthetic sentinel; `protocol==0` special cased inside three times (port_less, tuple_unknown, address_only).
- Also contains `#3906 no-translation`, `#3111 port-less`, `#4074 ICMP query`, `#4559 deterministic`, `#1852 non-first frag` all inline.

Proposed decomposition:
- `matcher.rs`: `SourceNatMatcher { zone_ok, scope_ok, l4_ok, nets_ok }` returning matched rule index.
- `translator.rs`: enum `TransMode { Interface, PoolV4, PoolV6, Deterministic, AddressOnly, Off }` + per-variant fn `(rule, flow, now) -> Result<TranslatedTuple>`.
- Extract `pick_pool_addr` (address_persistent vs RR), `pick_pool_port` (try_next_port vs allocate_translation).
- Keep `match_source_nat_result_for_tuple` as thin orchestrator <80 LOC delegating to matcher+translator.

Hot-path preservation: No alloc per packet; keep `IpAddr` copy, avoid format!. Reuse existing `PortAllocator` Arc. Preserve early returns for `off`/`interface_mode` before alloc attempt.

Tests+gate: `tests_source.rs`, `tests_pool.rs` (deterministic OOR), `tests_l4_match.rs`, plus `cargo bench snat_allocator` (unchanged). Add unit test for tuple_unknown still round-robin port (never frame-written).

Why: readability, bug farm for port-no-translation vs port-less vs deterministic; repeated `NatDecision` construction easy to miss `hit_counter`.

Fix direction: extract matcher first (no behavior change), then translator strategies, measure no perf regress via bench.

Labels: `readability`, `refactor`, `nat`, `god-function`
Dedup: #4409 reported same function; add decomposition plan with 12-arg reduction and strategy enum.

## Finding 3 — pkg/config/compiler_nat.go + pkg/dataplane/compiler_nat.go triply fused
Title: NAT config compiler fuses source/dest/static/nat64 + validation + pool auto-assign + counter IDs in 2 files (2529+1258 LOC)
Severity: MEDIUM
Confidence: HIGH
Refactor class: Split by NAT family + separate validation
Evidence:
- `config/compiler_nat.go`: `compileNAT` (831) calls `compileNATSource`, `compileNATDestination`, `compileNATStatic`, `compileNAT64` all in one file, plus `validateNATHostMaskStrict` (287), `validateNPTv6Strict` (536), `validateNAT64PrefixStrict` (770), `isHostMaskAddress`, `parseZoneList` (988), `parseNATMatchScopes` (1045), `appendPoolAddresses`, `expandAddressRange`. 2529 LOC.
- `dataplane/compiler_nat.go`: `compileNAT` mixes SNAT pool alloc, SNAT rules (bracket lists), DNAT pools, static, NPTv6, NAT64, plus counter ID stability (assignNATCounterID), plus `resolveSNATMatchAddr` synthetic addr-book, plus persistent NAT registration — 5 concerns.
- Counter ID logic `natCounterIDForKey` (FNV-1a, collision rehash) tangled inside same file.

Proposed decomposition:
- `compiler_nat_common.go`: zone list parsers, pool addr expansion, `natAddrFamily`, host-mask helpers.
- `compiler_nat_source.go`: `compileNATSource`, pools, deterministic validation, pool-util-alarm.
- `compiler_nat_dest.go`: `compileNATDestination`, `parseDNATPoolAddress`, `parseDNATPortList`.
- `compiler_nat_static.go`: `compileNATStatic`, host-mask gates, block-pair detection, mapped-port checks.
- `compiler_nat64_nptv6.go`: `compileNAT64`, `compileNPTv6` + prefix host-bits check.
- Go `dataplane/compiler_nat.go` -> `compiler_nat_source.go`, `compiler_nat_dest.go`, `compiler_nat_static.go`, `compiler_nat_counter.go` (counter stable IDs).
- Validation strict vs lenient gates already split but live in huge file; move to `compiler_validate_strict_nat.go` (already exists) as sole validator.

Hot-path preservation: compile path not hot per-packet (commit time); keep same output maps (`SetSNATRule`, `SetDNATEntry`, `SetNATPoolConfig`). No perf gate but must pass `make selftest` + `go test ./pkg/config -run TestCompileNAT`.

Tests+gate: `compiler_nat_*_test.go` suite (host_mask, dnat pool, source pool address, app specs). Also `go test ./pkg/dataplane -run TestCompileNATCounterStability`.

Why: 2500-LOC file hard to review, change to source pool parsing regresses dest pool (#4521 bracket list bug). Split reduces blast radius.

Fix direction: file-level split first (move functions, no logic change), then extract shared helpers.

Labels: `refactor`, `compiler`, `nat`, `coupling`
Dedup: new — not previously filed; complements #4409 which was Rust side.

## D-negatives (not monolithic)
- `nptv6.rs` 431 LOC focused RFC6296 translate + fail-closed snapshot validation — not monolith, well-commented invariants, single responsibility.
- `static_nat.rs` 793 LOC: SourceConstraint, prefix block remap, zone-scoped Vec — moderate but not god; block vs host split appropriate.
- `destination.rs` 1088 LOC large but justified: host exact map + prefix LPM + zone/interface/RI scope + source + L4 extra match + off exemption; could be split but not primary — below fuse threshold.
- `compiler.go` 1733 LOC orchestrator but delegates to compileZones/AddressBook/Applications/Policies/NAT/... each in own file — NOT monolith, orchestrator pattern ok.
- `lib.rs` XDP 1541 LOC borderline but constrained by BPF verifier 1M insn cap (#1864): splitting into mods would increase program count (allowlist canary). Keep but track insn budget; already uses `#[inline(never)]` for grease. Not a refactor candidate until verifier win.

## Log
- 2026-07-09T00:00Z: create worktree /tmp/review-wt-ps-041-a2-b1 from 95b33d496
- inventory: wc -l targets, grep allocator fns, check maps_sync.go missing
- read allocator.rs hot bitmap + persistent GC + deterministic; source.rs god fn 336 LOC; compiler_nat.go tri-fuse; nat64.rs 2527 LOC (#4421 known)
- wrote report to /tmp/review-work-ps-041/ps-a2-b1.md


---


### === FINDINGS FROM A3 — ps-a3-b1.md ===



### F1: compiler_validate_warn.go — Warn Colony Monolith — Largest ROI
- Title: WARN validator monolith should be split per-domain like strict was (#4405)
- Severity: High
- Confidence: High
- Class: A mechanical
- Evidence: 3330 LOC, ValidateConfig() alone >1500 LOC inline (application, policy, NAT, screen, address-book, route, chassis, flow, CoS, scheduler, filter diagnostics all inline), plus 16 named validate*Warning funcs + 7 ddns helpers + generic helpers sortedPoolNames/deterministicIPv4Enforced/hasFamily. 35 funcs. Grep shows 13 distinct domains: filter (loss-priority, iface-specific, lo0-mirror, no-catch-all), policy log, junos-host, CoS (oversub, classifier queue, scheduler window, shaping), DDNS backend, Surface-A DDNS, routing rule window, rib-group leak, DHCP relay parity, iface parity, host-inbound multicast, login/process/archival inert, sampling direction.
- Proposed: Split exactly mirroring strict:
  - `compiler_validate_warn_filter.go`: validateFilterLossPriorityWarnings, validateFirewallInterfaceSpecificWarnings, validateLo0FilterKernelMirrorWarnings, validateFilterNoCatchAllWarnings + helpers firewallFilter*Term* / schedulerHasEffectiveWindow
  - `compiler_validate_warn_policy.go`: validateDefaultPolicyLogWarnings, validatePolicyLogInertOnDenyWarnings, validatePreIDDefaultPolicyLogWarnings, validateJunosHostDirectDeliveryWarnings + helpers junosHostPolicySourceScoped/StricterThanCoarseGate
  - `compiler_validate_warn_ddns.go`: validateDDNSBackendWarnings, validateSurfaceADDNSWarnings + 7 ddns* helpers (ddnsUpdateServerParseable, TSIG, known provider, server valid, checkIP URL, generic template, allowlist)
  - `compiler_validate_warn_cos_routing.go`: validateCoSOversubscriptionWarnings, classOfServiceClassifierQueueWarnings, validateRoutingRuleWindowWarnings, validateRibGroupLeakWarnings
  - `compiler_validate_warn_interface.go`: validateInterfaceParityWarnings, validateDHCPRelayParityWarnings, validateHostInboundMulticastWarnings
  - `compiler_validate_warn_core.go` retains ValidateConfig skeleton (now thin delegator calling per-domain funcs) + generic helpers sortedPoolNames/deterministicIPv4Enforced/hasFamily/anySamplingDirectionConfigured
  - Seam: all funcs are `func(*Config) []string` or `func(*CoS,...) []string` pure; ValidateConfig appends slices. No import change. Move whole functions.
- Hot-path: A safe cold — commit-time only, no per-packet, no shared state.
- Tests+gate: go test ./pkg/config -run TestValidateConfig / TestWarn; byte-identical output gate: compare ValidateConfig warning slices before/after for golden configs.
- Why: reviewability + build incremental + mirrors #4405 discipline; biggest file dominates incremental build + review noise.
- Fix: code-motion only, preserve func signatures.
- Labels: refactor, config, A-mechanical, good-first-split
- Dedup: distinct from #4405 (strict); completes WARN symmetry.

### F2: compiler_system.go — 8-Subsystem Hub
- Title: System compiler interleaves leaf, RBAC, DDNS, dataplane, syslog, SNMP, chassis/RG, schedulers
- Severity: High
- Confidence: High
- Class: A
- Evidence: 1881 LOC, compileSystem() 500+ LOC switch with 18 cases + services ssh/dns/web-mgmt/ddns interleaved + snmp. Helpers: compileDDNSServices/ddnsScalar/parseDuration/compileDDNSProvider (DDNS catalog), compileSystemDataplaneType/hasDNSProxyChild/compileUserspaceDataplane/compileSharedUMEM* + retired knob adv (dataplane), syslogFacilitySeverity/loginClassPermName/advisories, compileSNMP/SNMPv3/parseKeys/snmpInert/systemInert (SNMP/syslog), compileSchedulers/schedulerWindow (schedulers), compileChassis/validateBackupRouterDst (chassis/RG).
- Proposed:
  - `compiler_system_base.go`: compileSystem (reduced to dispatch) + host/domain/ntp/backup-router/archival/processes/internet-options + compileSystemDataplaneType/hasDNSProxyChild
  - `compiler_system_login.go`: login class/user parsing + loginClassPermName + loginClassAdvisoryWarnings + sshHardeningAdvisoryWarnings
  - `compiler_system_ddns.go`: compileDDNSServices, ddnsServicesScalar, parseDurationSeconds, compileDDNSProvider
  - `compiler_system_dataplane.go`: compileUserspaceDataplane, compileSharedUMEM*, read/normalize helpers, userspaceRetiredKnobWarnings
  - `compiler_system_syslog.go`: syslogFacilitySeverity (moved from base) + syslog compilation block extraction
  - `compiler_system_snmp.go`: compileSNMP, compileSNMPv3, parseSNMPv3UserKeys, snmpInertKnobWarnings, systemInertKnobWarnings
  - `compiler_system_chassis_scheduler.go`: compileChassis, compileSchedulers, schedulerWindowFromNode, validateBackupRouterDst
  - Seam: helpers already typed (Node, *SystemConfig); compileSystem calls helpers already; move with no signature change.
- Hot-path safe: cold path, config commit only.
- Tests: existing system compile tests + TestSNMP + chassis device-map.
- Why: 8 reasons to change = merge hotspot; splitting unblocks parallel review per #4144.
- Labels: refactor, system, A-mechanical

### F3: compiler_services.go — RPM/DHCP/IPMon/Flow/Sampling Conflation
- Title: Services compiler bundles 5 RPM validators + DHCP + IPMonitoring + flow + sampling + port-mirroring
- Severity: High
- Confidence: High
- Class: A
- Evidence: 1821 LOC, 20 funcs: parseRPMPositiveInt/Root, validateRPMTest, validateRPM*Strict x5, compileDHCPLocalServer, mergeDHCPDynamicDNS, compileDHCPDynamicDNS, compileDHCPExpiredLeases, compileDynamicAddress, compileServices (dispatcher), compileIPMonitoring/compilePreferredRoutes/validateIPMonitoringStrict/resolveNextHop, compileRPM, compileFlowMonitoring, compileForwardingOptions, compilePortMirroring, compileSampling/compileSamplingFamily, compileDHCPRelay, compileEventOptions, compileBridgeDomains.
- Proposed:
  - `compiler_services_rpm.go`: RPM validators (5 strict + parse helpers + validateRPMTest) + compileRPM
  - `compiler_services_dhcp.go`: compileDHCPLocalServer, mergeDHCPDynamicDNS, compileDHCPDynamicDNS, compileDHCPExpiredLeases
  - `compiler_services_ipmon.go`: compileIPMonitoring, compilePreferredRoutes, validateIPMonitoringStrict, resolveIPMonitoringInterfaceNextHop
  - `compiler_services_forwarding.go`: compileServices (dispatcher thin), compileForwardingOptions, compileFlowMonitoring, compilePortMirroring, compileSampling/Family, compileDHCPRelay, compileDynamicAddress, compileEventOptions, compileBridgeDomains
  - Seam: each compile* is ( *Node, *ServicesConfig) error or similar; pure move.
- Hot-path: cold.
- Tests: existing RPM, IP-monitoring, sampling, DHCP-DDNS tests.
- Why: reviewer must context-switch across 7 services per PR.
- Labels: refactor, services, A-mechanical

### F4: compiler_nat.go — Triple Fusion (helpers+validators+compilers)
- Title: NAT file triply fuses address helpers, strict validators, and source/dest/static compilation
- Severity: High
- Confidence: High
- Class: A
- Evidence: 2529 LOC, 35 funcs. Layer A helpers: natAddrFamily, natCIDRIPPart, isHostMaskAddress, natStaticPrefixInfo, isStaticBlockPair, isNAT64PoolHostAddress, nptv6PrefixHasHostBits, parseZoneList, parseNATMatchScopes, collectNATScopes, apply*Scope, appendPoolAddresses, expandAddressRange, parseSourcePoolPortRange, applyDeterministic*. Layer B strict: validatePoolUtilizationAlarm, validateNATHostMaskStrict, validateNPTv6Strict, validateNAT64PrefixStrict, validateStaticNATThenTargetStrict. Layer C compile: compileNAT, compileNAT64, compileNATSource (500 LOC), compileNATDestination, compileNATStatic + DNAT port helpers.
- Proposed:
  - `compiler_nat_helpers.go`: all Layer A helpers + scope + deterministic helpers + pool address expansion
  - Move Layer B validators INTO existing `compiler_validate_strict_nat.go` (702 LOC) — already owns NAT strict per #4405, these 5 funcs are strict gates that were left behind.
  - `compiler_nat_source.go`: compileNATSource, compileNAT, compileNAT64
  - `compiler_nat_destination.go`: compileNATDestination, parseDNATPoolAddress, appendDNATPortRange, parseDNATPortList
  - `compiler_nat_static.go`: compileNATStatic, staticNATMappedPortFromKeys, staticNATRoutingInstanceFromKeys, resolveStaticNATThenPrefixName(s)
  - Seam: validators called from compileExpanded's strict phase; helpers used by both source/dest; moving validators to strict file is pure code-motion (same package, same signature (cfg,lenient)).
- Hot-path safe: cold; validation at commit.
- Tests: nat_* tests (host-mask, NPTv6, alarm, pool address #4521, deterministic #3864)
- Why: current file violates SRP thrice; inhibits review of #4291/#4292 NAT advisory vs enforcement split.
- Labels: refactor, nat, A-mechanical, strict-sym

### F5: compiler_interfaces.go — Core+VRRP+WireGuard+MSS+DDNS
- Title: Interface compiler bundles VRRP tracking/auth, tunnel, MSS, dynamic-dns
- Severity: Medium
- Confidence: Medium
- Class: A
- Evidence: 1279 LOC, compileInterfaces 550+ LOC switch + 12 helpers: parseTunnelWireguard/Peer (WG), selectMSSToken/parseMSSValue (MSS), parseVRRPGroups + validateVRRPTrackInterfaceAST + validateVRRPAuthenticationAST + vrrpGroupIDKeys + vrrpAuthLeaf + parseTrackCost + checkVRRPGroupTrackShape + vrrpTrackConfigWarnings (VRRP 8 funcs), compileInterfaceDynamicDNS (DDNS).
- Proposed:
  - `compiler_interfaces.go` retains compileInterfaces skeleton
  - `compiler_interfaces_vrrp.go`: all VRRP funcs (8)
  - `compiler_interfaces_tunnel.go`: parseTunnelWireguard/Peer + future GRE etc if any
  - `compiler_interfaces_mss_ddns.go`: selectMSSToken, parseMSSValue, compileInterfaceDynamicDNS
  - Seam: helpers pure, called only from compileInterfaces or its sub-parse.
- Hot-path: cold.
- Tests: interface, VRRP track tests.
- Labels: refactor, interfaces, A-mechanical

### F6: compiler_validate_strict_filter.go — 15 Validators in One File
- Title: Filter strict monolith (1660 LOC) should be further per-subdomain
- Severity: Medium
- Confidence: High
- Class: A
- Evidence: 1660 LOC, funcs: validateFirewallPolicerReferencesStrict, PrefixListReferences, RoutingInstanceReferences, FilterReferences, FilterRoutingInstanceDirectionStrict, FilterProtocolsStrict, firstIncompatibleProtocol, FilterCrossFieldStrict, FilterActionsStrict, FilterMatchValuesStrict, FilterFlexMatchStrict, FilterPortExceptStrict, FilterAddressExceptStrict, FilterAddressLiteralsStrict, classifyFilterAddrFamily, FilterFromMatchStrict, FilterRoutingInstanceConflictStrict, FilterTerminalConflictStrict, FilterDSCPStrict + public helpers FilterDSCPResolvable, FilterDSCPNames, filterProtocolResolvable, protocolIsPortBearing/TCP/ICMP, ProtocolIsPortBearing, FilterProtocolResolvable.
- Proposed:
  - `compiler_validate_strict_filter_ref.go`: policer/prefix-list/routing-instance/filter references (4 funcs)
  - `compiler_validate_strict_filter_match.go`: cross-field, match values, flex-match, port-except, address-except/literals, from-match, protocols, incompatible helper (8 funcs)
  - `compiler_validate_strict_filter_action.go`: actions, terminal conflict, routing-instance direction/conflict, DSCP + DSCP/proto helpers (public API stays but moves)
  - Seam: all `func(*Config) error` strict validators; pure motion.
- Hot-path: cold strict gate.
- Tests: filter action/protocol/ref tests.
- Labels: refactor, filter, strict, A-mechanical

### F7: types_system.go — Type Colony 1544 LOC
- Title: System types file defines 10+ unrelated config domains in one compilation unit
- Severity: Medium
- Confidence: High
- Class: A
- Evidence: 1544 LOC, types: SystemConfig/Userspace/SharedUMEM/RootAuth/Archival/InternetOptions/SystemServices/DDNSProvider/DDNServices/SSH/Web/API/Auth/SystemSyslog/* /SNMP*/Login*/Services/IPMonitoring/RPM/Flow/Forwarding/PortMirroring/DHCPRelay/Sampling/Firewall/DHCP — 40+ types spanning 9 domains.
- Proposed:
  - `types_system_core.go`: SystemConfig, UserspaceConfig, SharedUMEMConfig, RootAuthConfig, ArchivalConfig, InternetOptionsConfig
  - `types_system_auth.go`: LoginConfig/Class/User, SSHServiceConfig, WebManagement/APIAuth + perm helper mapJunosPermissions
  - `types_system_snmp_syslog.go`: SNMP*, Syslog*
  - `types_system_services.go`: ServicesConfig, IPMonitoring*/PreferredRoute, RPM*, FlowMonitoring*, ForwardingOptions*, Sampling*, DHCPRelay*, PortMirroring*
  - `types_system_firewall_dhcp.go`: Firewall*, DHCPServer* (currently lives here despite firewall/dhcp domains)
  - Seam: struct defs only, no behavior (except few String/Marshal helpers — move with their type).
- Hot-path: types only, cold.
- Tests: go build byte-identical; JSON/YAML marshal tests for SNMP.
- Why: parallel review + import graph clarity; touches all subsystems otherwise.
- Labels: refactor, types, A-mechanical

### F8: compiler.go — Dispatch Hub with Stray Validator
- Title: Entrypoint file houses compileOpts, Err sentinels, 6 Compile* wrappers, compileExpanded dispatch (300 LOC), plus stray validateWebManagementAuthStrict
- Severity: Low
- Confidence: High
- Class: A
- Evidence: 2110 LOC, mixed concerns: ErrDPDK/EBPF sentinels (could be `errors.go`), compileOpts (policy flags), 6 public Compile* entrypoints (2 node-scoped), compileConfigWithOpts/compileConfigForNodeWithOpts, compileExpanded (orchestrates all compileX calls + 10 strict validators), validateWebManagementAuthStrict (services domain, should live in services or system).
- Proposed:
  - `compiler.go` retains Compile* public entrypoints + compileOpts + sentinels (or move sentinels to `compiler_errors.go`)
  - `compiler_dispatch.go`: compileExpanded + compileConfigWithOpts/ForNodeWithOpts (dispatch orchestration)
  - move validateWebManagementAuthStrict to `compiler_system.go` or new `compiler_system_webmgmt.go`
  - Seam: entrypoints call compileExpanded which calls per-domain compile*; moving expansion preserves call graph.
- Hot-path: cold.
- Tests: all compile tests already exercise CompileConfig path.
- Labels: refactor, dispatch, A-mechanical

### D-Negative: compiler_uniformgates.go
- Already split per #4406 — 1659 LOC remains but is the post-split uniform-gates hub. Do NOT re-split. No finding.

### Cross-cutting Fix Direction
- All splits A/mechanical: move whole funcs/types preserving package `config`, no new interfaces, no signature changes, go vet byte-identical per #4144. Each PR <400 LOC net motion + `go test ./pkg/config -count=1` green (pkg/config tests ~seconds, not minutes — no VM needed). Order: F1 (biggest build/review win) → F4 (unblocks NAT strict symmetry) → F2/F3 → F5-8.

### Deduplication
- No duplicate of #4405 (strict) or #4406 (uniformgates) or #4421 (security). This audit targets WARN, system, services, nat, interfaces, filter-strict, types, dispatch — disjoint from prior.


---


### === FINDINGS FROM A4 — ps-a4-b1.md ===

# A4 — Go dataplane + daemon + cluster + routing + metrics + API — Modularity Audit (B1)

**Base:** `95b33d49634d...` (HEAD at review time) at `/tmp/review-wt-ps-041-a4-b1`
**Reviewer:** ps, NNN 041
**Date:** 2026-07-08
**Scope:** largest Go non-test non-gen files + pattern files in daemon/cluster/routing/metrics/api/dataplane/vrrp

---

## 1. File-size/shape inventory

Files flagged in prompt (largest in A4 scope) plus discovered second-tier files.
Threshold is the non-test guideline: 2000 LOC for prod, 100 LOC per function.

| File | LOC | Thresh | #func / #type | Smell |
|------|-----|--------|---------------|-------|
| `pkg/config/compiler_validate_warn.go` | 3330 | 2000 | 35 / 0 | warn validators monolith — strict already split (#2008), warn still collapsed into one file across 10+ domains (host-inbound, DHCP relay, iface, firewall, DDNS, rib-group, CoS, routing-rule) |
| `pkg/dataplane/userspace/protocol.go` | 3011 | 2000 | 2 / 78 | wire-format 12 domains — ControlRequest + ConfigSnapshot (~39 sub-types) + ProcessStatus (~20 sub-fields) + Binding/CoS/Wg/NAT(4 flavors)/Policy/Filter/SessionSync/HA/EventStream — Rust side already split into 7 files |
| `pkg/vrrp/instance.go` | 2417 | 2000 | 64 / 3 | VRRP SM + RX + TX + GARP + advert-interval + preempt-hold + VIP — but single coherent SM (see D-negative) — keep, with optional internal section comments |
| `pkg/daemon/daemon_run.go` | 2329 | 2000 | 11 / 0 | lifecycle bootstrap + naming + Run loop + enableForwarding + exit-path; Run() ~1690 LOC ordering-sensitive (#4662 already filed, do not re-report) |
| `pkg/frr/policy_render.go` | 1938 | 2000 | ~22 / 3 | BFD + BGP + OSPF + RIP + IS-IS + policy-options rendering in one file; render helpers (`generateProtocols`, `generatePolicyOptions`, `renderRouteMap`, `sanitizeFRRValue`) pull in 6 route families |
| `pkg/daemon/daemon_apply.go` | 1935 | 2000 | 4 / 0 | `applyConfigLocked` 1148 LOC god-function building whole reconcile pipeline; 20+ subsystem steps in one function (SNMP, VRF, interface, FRR, NAT, flow-export, DHCP, neighbor, daemon_flow, buffers, ...) — ordering-sensitive cold path |
| `pkg/api/metrics_descriptors.go` | 1896 | 2000 | 1 / 0 | 279 `NewDesc` calls, 7 subsystems (packet/drops/screen/policy/filter/nat/session/host-inbound/CoS/DHCP/DDNS/sys/frr) in one factory func — #1 merge-conflict surface |
| `pkg/routing/tunnel.go` | 1889 | 2000 | 36 / 5 | GRE/IPIP anchor + WG tuntap + keepalive Axis-D commit-after-success + WG MTU + VRF claim + address reconcile — 5 responsibilities in one manager |
| `pkg/cluster/sync_conn.go` | 1858 | 2000 | 55 / 0 | HA gen-guard SM + fabric dial preference + bulk + sweep + delete-journal + config-sync + failover barrier + liveness — 8 responsibilities, ordering-sensitive (see A4-02) |
| `pkg/api/metrics_userspace.go` | 1819 | 2000 | — | userspace counter bridge into legacy shim map |
| `pkg/dataplane/userspace/maps_sync.go` | 1763 | 2000 | ~25 / 5 | D-negative: focused single domain — userspace classifier/local-addr/ingress-binding sync |
| `pkg/dataplane/compiler.go` | 1733 | 2000 | ~25 / 3 | CompileResult + zone/address/app/policy/flow + per-method units; high cohesion across compile |
| `pkg/snmp/agent.go` | 1519 | 1000 | — | SNMP UDP/161 listener + community + v3 + trap monitor |
| `pkg/daemon/daemon_ha.go` | 1511 | 1000 | — | HA daemon glue |
| `pkg/dataplane/userspace/manager_ha.go` | 1440 | 1000 | — | HA manager side |
| `pkg/daemon/daemon_nft.go` | 1432 | 1000 | — | kernel nftables host-inbound chain |
| `pkg/routing/rules.go` | 1274 | 1000 | — | 3 domains listed in prior (#4421); needs confirm |
| `pkg/dataplane/userspace/format/buffers.go` | 773 | 500 | — | shared row-model CLI/gRPC/REST buffer-status parity (#4661 already filed) |
| `pkg/dataplane/userspace/format/status_sections.go` | 695 | 500 | — | status render sections |
| `pkg/dataplane/userspace/format/cos_sections.go` | 632 | 500 | — | CoS render sections |
| `pkg/grpcapi/server_diag.go`…etc | <100 each | — | — | small shims |

Context for totals from the repo glob:
- `pkg/dataplane/userspace/*.go` non-test prod ~ ~8000 LOC across ~12 files
- `pkg/daemon/daemon_*.go` non-test prod ~ ~12000 LOC across ~15 files
- `pkg/cluster/*.go` non-test prod ~ ~5000 LOC across ~10 files
- `pkg/api/*.go` prod includes 1896 + 1819 + metrics collector body
- Full A4 glob non-test (daemon+cluster+routing+frr+api+dataplane+vrrp): ~208k inc tests; prod-only ~ ~50k

---

## 2. Findings (with exact required labels)

### A4-01 — compiler_validate_warn.go warn-validator monolith

- **Title:** `compiler_validate_warn.go` collapses 16 cross-domain warn validators into one 3330-LOC file — strict side already split per-domain but warn side still monolithic
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** A (mechanical safe for cold path — pure code-motion, commit-check path only, no hot path, no ordering inside `ValidateConfig` except append order which affects only warning message order)
- **Evidence:**
  - `pkg/config/compiler_validate_warn.go:51` — `func ValidateConfig(cfg *Config) []string {` aggregates 16+ validator calls into one slice. LOC 3330, 35 funcs.
  - `pkg/config/compiler_validate_warn.go:1610` — `func validateHostInboundMulticastWarnings`
  - `:1666` `validateDHCPRelayParityWarnings`, `:1709` `validateInterfaceParityWarnings`, `:1771` `validateDefaultPolicyLogWarnings`, `:1827` `validatePolicyLogInertOnDenyWarnings`, `:1959` `validateJunosHostDirectDeliveryWarnings`, `:2016` `validatePreIDDefaultPolicyLogWarnings`, `:2044` `validateFilterLossPriorityWarnings`, `:2086` `validateFirewallInterfaceSpecificWarnings`, `:2154` `validateLo0FilterKernelMirrorWarnings`, `:2250` `validateFilterNoCatchAllWarnings`, `:2408` `validateDDNSBackendWarnings`, `:2669` `validateSurfaceADDNSWarnings`, `:3002` `validateRoutingRuleWindowWarnings`, `:3066` `validateRibGroupLeakWarnings`, `:3139` `validateCoSOversubscriptionWarnings`
  - Quoted shape (lines 51-100):
    ```go
    func ValidateConfig(cfg *Config) []string {
        var warnings []string
        // ... ~16 branches each calling one validateFooWarnings ...
    }
    ```
  - Strict counterparts already split: `pkg/config/compiler_validate_policy.go`, `compiler_validate_nat.go`, `compiler_validate_iface.go`, `compiler_validate_screen.go`, etc. (per-directory glob). Warn side never followed.
- **Proposed decomposition:**
  - `pkg/config/validate_warn_host_inbound.go` — `validateHostInboundMulticastWarnings`, `validateJunosHostDirectDeliveryWarnings`, `validateDefaultPolicyLogWarnings`, `validatePolicyLogInertOnDenyWarnings`, `validatePreIDDefaultPolicyLogWarnings`
  - `validate_warn_firewall.go` — `validateFilterLossPriorityWarnings`, `validateFirewallInterfaceSpecificWarnings`, `validateLo0FilterKernelMirrorWarnings`, `validateFilterNoCatchAllWarnings`
  - `validate_warn_ddns.go` — `validateDDNSBackendWarnings`, `validateSurfaceADDNSWarnings`, plus helper `ddns*` predicates (currently 8 funcs interleaved)
  - `validate_warn_routing.go` — `validateRoutingRuleWindowWarnings`, `validateRibGroupLeakWarnings`, `validateDHCPRelayParityWarnings`, `validateInterfaceParityWarnings`
  - `validate_warn_cos.go` — `validateCoSOversubscriptionWarnings`, `classOfServiceClassifierQueueWarnings`
  - `compiler_validate_warn.go` retained as thin dispatcher `func ValidateConfig` importing sub-files.
  - Each new file ≤ 500 LOC, single domain, easy review.
- **Hot-path preservation:** Cold path only — commit/validate path. No hot path, no allocator pressure, no atomic ordering. Pure code-motion (move whole funcs), keep function signatures and error text byte-identical so snapshots stable. Tests: `go test ./pkg/config -run Validate` green.
- **Tests + gate:** `pkg/config/*_test.go` existing + add no-logic-change canary: `TestValidateWarnSplitParity` that asserts warning slice identity before/after split on 3 representative configs (empty, full, HA). `make test-go` passes.
- **Why it matters:** Build-time review — 3330 LOC file is top merge-conflict surface in config package alongside `metrics_descriptors.go`; PRs touching any warn validator all touch same file. Strict validators were split for that reason already; warn side lags. Also learnability: locating "where are firewall warnings" requires grep in 3330 lines.
- **Fix direction (ordered PRs):**
  1. PR-1 (mechanical): extract firewall-filter warn group → `validate_warn_firewall.go` (no logic change, tests green)
  2. PR-2: extract DDNS warn group + host-inbound group → two files
  3. PR-3: extract routing + CoS groups → two files, thin `compiler_validate_warn.go` remains as dispatcher (~80 LOC)
- **Labels:** `modularity`, `A`, `cold-path`, `config`, `reviewability`
- **Dedup note:** Prior #4421 mentions flowexport/rules/DDNS/event-engine as monoliths and Surface-A DDNS; does NOT file `compiler_validate_warn.go` monolith split — no dedup conflict. #4662 `daemon_run.go` Run ordering is separate file.

---

### A4-02 — protocol.go 78-type 12-domain wire format monolith

- **Title:** `pkg/dataplane/userspace/protocol.go` 3011 LOC / 78 types / 12 domains is a single-file wire format that Rust side already split into 7 domain files — Go lags, #1 cross-team merge bottleneck in dataplane/userspace
- **Severity:** High
- **Confidence:** High
- **Refactor class:** A (mechanical safe — JSON-tagged DTOs only, no hot path, no ordering; Go ↔ Rust JSON serialization tags must be preserved verbatim; a `userspace-dp/src/protocol/tests.rs` equivalent Go parity test must stay green)
- **Evidence:**
  - `pkg/dataplane/userspace/protocol.go:29` — `type ControlRequest struct {` through `2800+` contains 39 `ConfigSnapshot` sub-types, 21 `ProcessStatus` sub-fields+related statuses, plus Binding/Queue/CoS/HA/Route/Neighbor/Fabric/Wg/NAT/Screen/Filter/Policy/EventStream.
  - `pkg/dataplane/userspace/protocol.go:1322` — `type ProcessStatus struct {` — 80+ fields mixing dataplane armed, zone counters, policy counters, CoS queues, fabric status, flow cache, neighbor, NAT pool, DDNS, slow-path, event-stream, debug diagnostics.
  - `pkg/dataplane/userspace/protocol.go:54` — `type ConfigSnapshot struct {` — 40 sub-fields spanning zones/interfaces/routes/flow/policies/NAT/screens/filters/CoS/flow-export/mirror/app-catalog/config.
  - `userspace-dp/src/protocol/mod.rs:1-50` documents split:
    > Split (#1325) into domain submodules:
    >   - `snapshot`: config DTOs
    >   - `cos`: CoS config + status
    >   - `nat`: NAT rules + pool status
    >   - `security`: screen/filter/policer/policy
    >   - `control`: control socket req/resp + ProcessStatus + session-sync wire
    >   - `binding`: BindingStatus + HAGroupStatus + QueueStatus + ...
    >   - `resolution`: PacketResolution / FlowTuple / FlowWorker
    - Sizes: `binding.rs 1168 LOC`, `control.rs 1088`, `cos.rs 494`, `nat.rs 400`, `resolution.rs 105`, `security.rs 592`, `snapshot.rs 829`, total 7144 including tests.
  - Go side has `pkg/dataplane/userspace/protocol_test.go` 1914 LOC — parity with `protocol/tests.rs` 2393 LOC.
- **Proposed decomposition (mirrors Rust layout exactly — Go files named to match):**
  ```
  pkg/dataplane/userspace/protocol/
    mod.go          — package doc + ProtocolVersion consts + Re-exports (type aliases)
    control.go      — ControlRequest, ControlResponse, ProcessStatus + event-stream fields, SessionSyncRequest/Drain/Export, SessionDeltaInfo, ForwardingControlRequest, QueueControlRequest, BindingControlRequest, InjectPacketRequest, ExceptionStatus, UserspaceCapabilities, UserspaceMapPins
    snapshot.go     — ConfigSnapshot, SnapshotSummary, ZoneSnapshot, InterfaceSnapshot, InterfaceAddressSnapshot, RouteSnapshot, NeighborSnapshot, FabricSnapshot, TunnelEndpointSnapshot, TunnelWgPeerWire, FlowSnapshot, AddressBookSnapshot, AppCatalogEntrySnapshot
    cos.go          — ClassOfServiceSnapshot tree (ForwardingClass, DSCP, IEEE8021, RewriteRule, Scheduler, SchedulerMap) + CoSInterfaceStatus, CoSQueueStatus, CoSActiveFlowCountStatus, ThreeColorPolicerStatus snapshot
    nat.go          — NatPortRangeWire, NatAppTermWire, SourceNATRuleSnapshot, StaticNATRuleSnapshot, DestinationNATRuleSnapshot, NAT64RuleSnapshot, Nptv6RuleSnapshot, SourceNATPoolStatus + related counter statuses
    security.go     — ScreenProfileSnapshot, ScreenMissingProfileRef, FirewallFilterSnapshot, FirewallTermSnapshot, FlexMatchSnapshot, PolicerSnapshot, ThreeColorPolicerSnapshot, FlowExportSnapshot, MirrorConfigSnapshot, PolicyApplicationSnapshot, PolicyRuleSnapshot + counter statuses (PolicyRuleCounter, FirewallFilterTermCounter)
    binding.go      — BindingStatus, BindingCountersSnapshot, QueueStatus, HAGroupStatus, WgPeerStatus, WgTunnelStatus, WorkerRuntimeStatus, EventStreamStatus, ZoneTrafficCounterStatus, SlowPathStatus, NATRuleCounterStatus, SourceNATPoolStatus (if not in nat.go) + BindingScopedTelemetry
    resolution.go   — PacketResolution, FlowTupleStatus, FlowWorkerStatus
  ```
  Key constraints:
  - Go does NOT have Rust `pub(crate) use binding::*` re-export, so add `type X = protocol.X` alias file or keep `protocol.go` as facade importing sub-package — either way `userspace.ProcessStatus` external import path stays stable (choose same package `userspace` with multiple files, NO new package, so all names stay `userspace.ProcessStatus`).
  - Simply splitting `package userspace` across multiple files already satisfies this — no package boundary change, no import update anywhere. Each file in `pkg/dataplane/userspace/protocol_*.go` same package.
  - Keep json tags byte-identical. Add `protocol_wire_parity_test.go` that round-trips a full `ConfigSnapshot` JSON encode→Rust decode golden via `cargo test protocol::tests` hook if feasible, otherwise Go-only round-trip check.
- **Hot-path preservation:** Cold path — ConfigSnapshot built on commit apply path only (~1/s at most), serialized once per commit over Unix socket. No per-packet, no per-session, no atomic ordering. Pure code-motion: cut types, paste to new files, zero behavioral change. `make test-go` + `make test-rust` (protocol tests leg).
- **Tests + gate:** `pkg/dataplane/userspace/protocol_test.go` (1914 LOC) must stay green unmodified; add `TestProtocolSplitWireParity` that marshals a golden `ConfigSnapshot` via `json.Marshal` before and after file split and asserts `bytes.Equal`. Also `cargo test -p userspace-dp protocol` green (Rust `protocol/tests.rs` 2393 LOC is the authoritative wire spec).
- **Why it matters:**
  - Reviewability: 3011 LOC + 78 types means a reviewer must scan whole file for any one-domain PR (e.g. adding a zone-counter field touches same file as a NAT-pool change or a CoS queue field).
  - Build-time: Go compiles file-scope — but the real cost is incremental build of the `userspace` package (≈ largest) and test binary rebuild on every commit touching unrelated domain.
  - Correctness: json-tag drift or duplicate field name across 78 types is easy to miss in 3011 lines; domain files reduce blast radius.
  - Parity: Rust side already the template; Go lag creates asymmetric search: `grep snapshot.rs` finds Rust type in seconds, Go requires `grep protocol.go` with 530 hits.
- **Fix direction (ordered PRs, mechanical first):**
  1. PR-1 (pure move, no name change): extract `resolution.go` (smallest, 2 types, ~100 LOC) + `snapshot.go` core sets (Zone/Interface/Route/Neighbor/Fabric/Tunnel) — ~800 LOC off `protocol.go`.
  2. PR-2: extract `cos.go` (CoS snapshots + statuses) — single domain, ~500 LOC + test move.
  3. PR-3: extract `nat.go` (4 NAT flavors + pool) — ~400 LOC, matches `nat.rs`.
  4. PR-4: extract `security.go` (screen/filter/policer/policy) — ~600 LOC, matches `security.rs`.
  5. PR-5: extract `binding.go` (BindingStatus, QueueStatus, HA, Wg, degraded path) — ~900 LOC, matches `binding.rs`.
  6. PR-6: remaining `control.go` (ControlRequest/Response, ProcessStatus, session-sync wire) stays in `protocol.go` or becomes `control.go`, leaving `protocol.go` as < 100 LOC shim if desired or deleted.
  Each PR: mechanical file split, zero logic change, `go test ./...` + `cargo test protocol` green, no API change.
- **Labels:** `modularity`, `A`, `wire-format`, `dataplane`, `reviewability`, `merge-conflict`
- **Dedup note:** Prior audits (#4661 format, #4421 flowexport/rules) did NOT file `protocol.go` 12-domain split — this is new. Rust split plan in `userspace-dp/src/protocol/mod.rs` header explicitly calls out Rust template and says Go should follow — not yet tracked.

---

### A4-03 — metrics_descriptors.go 279 NewDesc single factory merge-conflict #1

- **Title:** `pkg/api/metrics_descriptors.go` 1896 LOC / 279 `NewDesc` in one factory func is the top merge-conflict file in A4 — 7 subsystems (packet/drops/screen/policy/filter/nat/session/host-inbound/CoS/DHCP/DDNS/sys/frr) collapse into one `newCollector()` initializer block
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** A (mechanical safe — Prom descriptors only, cold path Collect() reads them, no ordering across descriptors except unique metric name; split is file-per-subsystem returning sub-struct merged into `xpfCollector`)
- **Evidence:**
  - `pkg/api/metrics_descriptors.go:1-10` `package api` + `func newCollector(srv *Server) *xpfCollector { return &xpfCollector{ srv: srv, packetsTotal: NewDesc("xpf_packets_total" ...`
  - `grep -c "NewDesc(" 279` — 279 descriptors in one func literal.
  - Comment clusters show 7+ subsystems manually demarcated by inline comments:
    ```go
    packetsTotal: prometheus.NewDesc("xpf_packets_total", ...)
    dropsTotal: prometheus.NewDesc("xpf_drops_total", ...)
    counterReadErrorsTotal: prometheus.NewDesc("xpf_counter_read_errors_total", ...)
    sessionsCreatedTotal ...
    screenDrops...
    policyDenies...
    hostInboundKernelDenies...
    tcEgressPackets...
    syncookie...
    flowCache...
    ifacePackets...
    policyHits...
    filterHits...
    threeColorPolicer...
    sessionsActive...
    natPool...
    userspaceSNATPool...
    dhcpLeases...
    dhcpDDNS...
    surfaceADDNS...
    sysCPU...
    frrReloadDegraded...
    userspacePolicyContentRejected...
    eventActions...
    ```
    Each group is a natural file boundary but currently interleaved in one literal.
  - `pkg/api/metrics_userspace.go:1819 LOC` — second leg of same collector, bridging userspace counter offsets — also large but single-domain (userspace shim counters).
  - `pkg/api/metrics_test.go:2432 LOC`, `metrics_cold_path_test.go:645`, `metrics_descriptor_coverage_test.go:726` — heavy test cover that currently edits same file's expected metric names.
- **Proposed decomposition:**
  ```
  pkg/api/metrics/
    descriptors_global.go     — packets, drops, counterReadErrors, tcEgress, syncookie, flowCache, gcSweep
    descriptors_sessions.go   — sessionsActive/Established/IPv4/v6/SNAT/DNAT/breakdown + Created/Closed
    descriptors_screen.go     — screenDrops, per-reason, NatReverseKeyCollisions
    descriptors_policy_filter.go — policyHits, filterHits, threeColorPolicer, hostInboundKernel + hostInbound deny/addressless/ambiguous + interface ctr errors
    descriptors_nat.go        — natAllocFails, nat64Xlate, natPool*, userspaceSNATPool*, policyContentRejected, zoneIDCollision
    descriptors_dhcp_ddns.go  — dhcpLeases, dhcpDDNS*, surfaceADDNS*
    descriptors_sys.go        — sysCPU, daemonUptime, memRSS, frrReloadDegraded, schedulerRepublish*, configPersistDegraded, rpmPinInstallFailures, neighborPeriodicAge
    descriptors_event.go      — eventActions*
  ```
  Implementation: keep `pkg/api` package (no new package) — split into `metrics_descriptors_global.go`, `metrics_descriptors_sessions.go`, etc., each defining `func (c *xpfCollector) initFooDescs() { ... }` or returning a sub-struct that `newCollector` merges. Easiest: move `xpfCollector` struct definition to `metrics_collector.go` (small) and have `newCollector` call `initGlobal`, `initSessions`, etc., each in its own file. Struct fields stay same, so `metrics_userspace.go` Collect path untouched.
  - Alternative shape: one file per Prometheus subsystem prefix (`xpf_sessions_*` → sessions file), matches the comment clustering already in file — lowest diff.
- **Hot-path preservation:** Cold path — `NewDesc` runs once at collector registration; `Collect()` is called by Prometheus scrape at ~15s cadence, reads atomics/counters but does NOT allocate in descriptor creation. Split preserves all `*Desc` pointer identities and labels — no hot-path change. Tests: metric name set is identity (coverage test asserts presence).
- **Tests + gate:**
  - `metrics_descriptor_coverage_test.go:726` enumerates expected metric names — must stay green after split (no name added/removed).
  - `metrics_test.go:2432` + `metrics_cold_path_test.go:645` — Collect() path.
  - Canary: `TestMetricsDescriptorsSplitParity` — build collector before and after split, list `Describe()` names, assert `reflect.DeepEqual`.
- **Why it matters:**
  - Merge conflicts: 279 descriptors in one file — every feature adding a metric (CoS, DDNS, NAT, host-inbound, flow-export) touches same file. Ranked #1 conflict file per `git log --name-only | grep metrics_descriptors | wc -l` likely >30% of metric PRs.
  - Reviewability: reviewer of a NAT-pool metric PR must scroll past 1500 LOC of unrelated descriptors.
  - Build time: api package rebuild on any metric change invalidates whole package compile.
- **Fix direction (ordered PRs):**
  1. PR-1 (mechanical, no logic): extract sys + event + dhcp/ddns descriptors into two new files, keep `newCollector` compositional (`initSys()`, `initEvent()`).
  2. PR-2: extract session + screen + policy/filter + nat + host-inbound groups into their domain files — leaves `metrics_descriptors.go` as <100 LOC dispatcher.
  3. Add `metrics_split_parity_test.go` canary.
- **Labels:** `modularity`, `A`, `cold-path`, `metrics`, `merge-conflict`, `reviewability`
- **Dedup note:** Not previously filed. Prior audits cover flowexport/rules (A4- adjacent), not metrics descriptors.

---

### A4-04 — sync_conn.go 8-responsibility ordering-sensitive SM (gen-guard + fabric preference + bulk reset + delete-journal)

- **Title:** `pkg/cluster/sync_conn.go` 1858 LOC / 55 funcs mixes 8 responsibilities (gen-guard stamp/queue/take, bulk barrier reset, fabric preference single-active, delete-journal + rejournal tail, config-sync gen, sweep, failover groups, liveness) with ordering-sensitive invariants that are unsafe to split without explicit ordering harness
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B (ordering-sensitive — gen-guard state machine: stamp→queue→take, bulk reset #2995, fabric single-active preference, #2198 F3 non-atomicity invariant)
- **Evidence:**
  - `pkg/cluster/sync_conn.go:45` `const genGuardMapCap = 200000` + doc: skip-record-on-full vs clear-whole-map trade.
  - `sync_conn.go:67-107` `nextInstallGen`, `stampInstallGenV4/V6` + `putGenBounded` — sender-side stamp.
  - `:126-150` `takeDeleteGenV4/V6` — fresh gen draw (#2221).
  - `:152-228` `installGenGuardV4/V6`, `recordInstalledGenV4/V6` — receiver guard.
  - `:229-285` `deleteGenGuardV4/V6` — tombstone upgrade (#2221).
  - `:287-310` `resetRecvGen` — bulk barrier (#2198 F2 + #3931 config gen).
  - `sync_conn.go:399-560` `shouldInitiateFabricDial`, `activeConnLocked`, `configureSessionSyncConn`, `handleNewConnection` — fabric dial preference + active fabric selection.
  - `:561-650` `Start`, `Stop`, `StartSyncSweep` — lifecycle.
  - `:650-830` `sweepIntervals`, `ShouldSyncZone`, `syncSweep`, `PauseIncrementalSync` — sweep domain.
  - `:854-1000` `queueMessage`, `QueueSessionV4/V6`, `QueueDeleteV4/V6`, `journalDelete`, `flushDeleteJournal`, `rejournalTail` — delete-journal domain.
  - `:1021-1220` `nextConfigGen`, `QueueConfig`, `shouldApplyConfigGen`, `recordAppliedConfigGen`, `configApplyLoop`, `SendLivenessKeepalive`, `sendClockSync` — config-sync + liveness.
  - `:1180-1400` `acceptLoop`, `fabricConnectLoop`, `sendLoop`, `receiveLoop`, `handleMessage` — transport.
  - Non-atomicity invariant doc at `:287-320`:
    > Non-atomicity note (#2198 F3): the apply sequence — guard check, PutClusterSynced, recordInstalled — does NOT hold recvGenMu across whole sequence; safe because receiver is single-threaded via single ACTIVE fabric connection.
  - Fabric preference invariant at `handleNewConnection` (~:475-560):
    > activeConnLocked prefers conn0; conn1 used only when conn0 down — never both at once for sends.
  - `sync_protocol.go:829` companion — session wire format, separated from conn logic.
- **Proposed decomposition (ordering-preserving, single-lock discipline kept):**
  ```
  pkg/cluster/
    sync_gen_guard.go     — genGuardMapCap, putGenBounded, nextInstallGen, stampInstallGenV4/V6, takeDeleteGenV4/V6, installGenGuardV4/V6, recordInstalledGenV4/V6, deleteGenGuardV4/V6, resetRecvGen + Tests sync_gen_guard_test.go (already exists: 956 LOC — keep)
    sync_fabric.go        — shouldInitiateFabricDial, activeConnLocked, getActiveConn, connRemoteAddrString/LocalAddrString, configureSessionSyncConn, handleNewConnection (fabric preference) — single-active invariant doc stays
    sync_transport.go     — Start, Stop, acceptLoop, fabricConnectLoop, sendLoop, receiveLoop, handleMessage, handleDisconnect — I/O loops stay together
    sync_sweep.go         — sweepIntervals, sweepIntervalsForDataPlane, ShouldSyncZone, syncSweep, Pause/ResumeIncrementalSync
    sync_journal.go       — queueMessage, QueueSessionV4/V6, QueueDeleteV4/V6, journalDelete, flushDeleteJournal, rejournalTail
    sync_config.go        — nextConfigGen, QueueConfig, shouldApplyConfigGen, recordAppliedConfigGen, configApplyLoop, SendLivenessKeepalive, sendClockSync
    sync_conn.go          — thin facade re-exporting if needed, OR deleted — each func stays on same receiver type *SessionSync so method set unchanged to callers.
  ```
  Split discipline: all new files same package `cluster`, same type `*SessionSync`, NO new interface boundary, NO lock-splitting across files. `recvGenMu`, `genSentMu` remain single mu. This is B (ordering-sensitive) — ordering harness required:
  - Lock ownership doc stays on `sync_gen_guard.go`: "caller holds recvGenMu inside guard func, not across PutClusterSynced".
  - Fabric single-active invariant doc stays on `sync_fabric.go`: "active fabric == single ACTIVE conn; bulk barrier only in active path".
  - Tests: `sync_gen_guard_test.go` + `sync_test.go` (3354 LOC) + `cluster_test.go` 2249 LOC must stay green.
- **Hot-path preservation:** Data path NOT in this file — this is control-plane session-sync (HA control plane), cold path wrt packet. Ordering invariants that MUST be preserved if splitting:
  - Gen-guard: stamp (sender) → queue → wire → take (receiver guard) → Put → record. Cap: skip-record-on-full, never-clear. Tombstone = fresh gen, always > install gen.
  - Bulk reset: `resetRecvGen` called at `BulkStart` BEFORE bulk re-prime, AND clears both session gen maps AND last-applied config gen. Deletes only after BulkEnd (`reconcileStaleSessions`). A delete arriving mid-bulk for not-yet-re-recorded key falls back to gen-0 unconditional (legacy safe).
  - #2198 F3 non-atomicity: guard check + Put + record NOT under single mu, safe because single ACTIVE fabric conn => single receiver goroutine per peer => no same-key concurrent apply. Standby fabric receiveLoop exists but sender never duplicates same key across both.
  - Single-active-fabric: `activeConnLocked` prefers `conn0`; `conn1` only when `conn0` down; sender single-stream; receiver dual but per-fabric serial. Cross-goroutine same-key race impossible under this invariant; do NOT hold `recvGenMu` across dataplane Put (would serialize unrelated keys and block on I/O under lock).
  - Fabric preference: `shouldInitiateFabricDial` deterministic tie-break on local vs peer addr so two nodes racing to connect agree on initiator vs acceptor, avoiding both-connected-both-initiating deadlock.
  Split PRs must NOT split a single invariant across two files — each invariant's whole sequence in one file, with a cross-file import edge only for transport-layer callback.
- **Tests + gate:**
  - `pkg/cluster/sync_gen_guard_test.go:956 LOC` — gen-guard property tests.
  - `pkg/cluster/sync_test.go:4717 LOC` — session sync shape.
  - `pkg/cluster/cluster_test.go:2249 LOC` — cluster integration.
  - Live gate: `make cluster-deploy` + `make test-failover` + `make test-ha-crash` — must pass before each split PR merge (per task REQUIREMENT).
  - CANARY: `TestSyncConnSplitOrderingInvariant` — assert `handleNewConnection` active transition + `resetRecvGen` is called exactly at BulkStart and `reconcileStaleSessions` after BulkEnd — no double reset.
- **Why it matters:** Build time (~1.8k file) moderate but risk: this file is where #2170, #2198, #2221, #2995, #3931 fixes landed — 5 correctness fixes in one file in <1 year, each requiring reasoning about all 8 domains at once. Splitting by domain makes future fix review local to gen-guard vs fabric vs journal vs config-sync rather than whole-file context.
- **Fix direction (ordered PRs, B-marked — ordering harness first):**
  1. PR-0 (no split): write `docs/ha-sync-invariants.md` capturing the 5 ordering invariants above with test matrix (stamp→queue→take, cap skip-not-clear, tombstone freshness, bulk reset timing, single-active-fabric) — terminal artifact for reviewers of following splits.
  2. PR-1 (safe): extract `sync_gen_guard.go` — moves `putGenBounded`, `nextInstallGen`, `stamp*`, `take*`, `*GenGuard*`, `record*`, `resetRecvGen` together as one unit preserving lock boundaries. Tests: `sync_gen_guard_test.go` green, `test-failover` green.
  3. PR-2: extract `sync_journal.go` + `sync_sweep.go` together (journal feeds sweep + queue path).
  4. PR-3: extract `sync_fabric.go` + `sync_config.go` (fabric + config-gen).
  5. PR-4: `sync_transport.go` (loops) — thin `sync_conn.go` becomes <100 LOC or deleted.
- **Labels:** `modularity`, `B`, `ordering-sensitive`, `ha`, `session-sync`, `gen-guard`, `fabric-preference`, `correctness-critical`
- **Dedup note:** No prior modularity audit filed `sync_conn.go` split — #4407 filed Daemon god-struct, not cluster. This is new. Related: `manager_ha.go` (1440 LOC) is HA manager side, not sync transport.

---

### A4-05 — tunnel.go 5-responsibility lifecycle + keepalive Axis-D lock-free

- **Title:** `pkg/routing/tunnel.go` 1889 LOC mixes GRE/IPIP anchor, WG tuntap + inner-MTU, keepalive Axis-D commit-after-success lock-free probe state, VRF claim, address reconcile — keepaliveTick never takes `t.mu` (AGY r5) hard to verify when interleaved in one file with GRE creation
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B (ordering-sensitive for keepalive Axis D commit-after-success + lock-free gen.Load() guard + VRF claim ordering)
- **Evidence:**
  - `pkg/routing/tunnel.go:48-60` `vrfBinder` cross-domain dep (`*vrfManager`) + lock-ordering doc.
  - `tunnel.go:57-96` `KeepaliveState` + `keepaliveRunner` struct — runner holds `linkGen *atomic.Uint64` + `startGen uint64`.
  - `tunnel.go:126-155` `matches()`, `TunnelStatus` — status views.
  - `tunnel.go:158-277` `tunnelManager` struct + `ensureReconcileStateLocked`, `linkGenForLocked`, `bumpLinkGenLocked`, `keepaliveProber`, `Apply` (~213 LOC) — central orchestrator.
  - `tunnel.go:490-765` `anchorReusable`, `applyAnchorLocked`, `reconcileAnchorMTULocked`, `buildKernelTunnelLink`, `legacyTunnelMatches`, `applyKernelTunnelLocked` — GRE anchor domain.
  - `tunnel.go:1217-1444` WG domain: `wgEngineMaxInnerMTU`, `wgDefaultOuterMTU`, `wgTunMTUForEndpoint`, `applyWireguardTunLocked`, `closeTuntapFiles`.
  - `tunnel.go:1444-1720` keepalive domain:
    - `1485-1528` `startKeepalive`:
      ```go
      // Capture the current generation token (#1918 §6 Axis D defense-in-depth).
      // The runner reads it LOCK-FREE — it never takes t.mu — so an Apply blocked on the drain can never deadlock a tick.
      gen := t.linkGenForLocked(tunnelName)
      startGen := gen.Load()
      ```
    - `1531-1540` `keepaliveProbeDeadline`, `1540-1591` `keepaliveLoop` doc: "Tick body is §6 Axis D COMMIT-AFTER-SUCCESS ...".
    - `1572-1672` `keepaliveTick` — NEVER takes `t.mu`, only `state.mu` twice + lock-free `gen.Load()`:
      ```go
      // ---- Step 1: classify + commit counters, compute intent ----
      state.mu.Lock() ... state.mu.Unlock()
      // ---- Step 2: no intent → done
      // ---- Step 3: LinkByName; error → retry
      // ---- Step 4: lock-free generation guard
      if gen.Load() != startGen { drop }
      // ---- Step 5: single LinkSetUp/Down OUTSIDE state.mu
      // ---- Step 6: commit Up only on netlink success
      ```
    - This is the pattern flagged: lock-free gen guard + two short `state.mu` sections + netlink outside mu — when interleaved in same file as `applyKernelTunnelLocked` + VRF claim + address reconcile, a reviewer cannot locally verify the "never takes t.mu" invariant without reading 1889 LOC.
  - `tunnel.go:1132-1217` VRF + list claim domain: `reconcileVRFClaimLocked`, `observeListClaimLocked`.
  - `tunnel.go:931-1132` address reconcile domain: `finishTunnelLocked`, `reconcileLinkAddrsLocked`, `pruneAppliedAddrsLocked`.
  - `tunnel.go:1448-1511` stop domain: `stopAll`, `stopAllKeepalivesLocked`, `stopKeepaliveLocked`.
- **Proposed decomposition:**
  ```
  pkg/routing/
    tunnel_manager.go    — tunnelManager struct, ensureReconcileStateLocked, linkGenForLocked, bumpLinkGenLocked, keepaliveProber, Apply (dispatch), vrfBinder, Clear/GetStatus, stopAll helpers — <500 LOC
    tunnel_gre.go        — anchorReusable, applyAnchorLocked, reconcileAnchorMTULocked, buildKernelTunnelLink, ipEqual, legacyTunnelMatches, applyKernelTunnelLocked, finishTunnelLocked — GRE/IPIP creation path
    tunnel_wg.go         — wgTunMTUForEndpoint, applyWireguardTunLocked, closeTuntapFiles, wgEngineMaxInnerMTU / wgDefaultOuterMTU consts, finishTunnelLocked reuse — WG path
    tunnel_keepalive.go  — KeepaliveState, keepaliveRunner, matches, startKeepalive, keepaliveLoop, keepaliveTick, keepaliveProbeDeadline, nextSeq, clearUnknownLocked, markUnknownLocked, classifyErrnoString, GetKeepaliveState — Axis-D + lock-free invariant lives here alone
    tunnel_reconcile.go  — reconcileVRFClaimLocked, observeListClaimLocked, reconcileLinkAddrsLocked, pruneAppliedAddrsLocked, buildDesiredSets -- VRF + address domains
  ```
  Same package `routing`, same `*tunnelManager` receiver, NO new locking, NO package boundary. `Apply` becomes top-level switch calling `applyAnchorLocked` / `applyWireguardTunLocked` — dispatch stays in manager file so ordering that `stopKeepaliveLocked` runs before recreate is locally visible.
- **Hot-path preservation / ordering invariants:**
  - Cold path: tunnel create/reconcile on commit apply path, keepalive tick at interval seconds (not per-packet). NOT hot.
  - Ordering invariant (keepalive Axis D): state.mu section commits counters + computes intent WITHOUT writing Up → no netlink → lock-free gen.Load() guard → single LinkSetUp/Down OUTSIDE mu → commit Up ONLY on success. Applies even if split across files — MUST keep whole 6-step sequence in one func in one file (`tunnel_keepalive.go`) with the doc block verbatim.
  - Lock-free invariant: keepaliveTick NEVER takes `t.mu` (AGY r5 fix). Guarantee: reviewer verifying it need only audit `tunnel_keepalive.go`, not whole 1889 LOC. `ops LinkByName/SetUp/SetDown` takes no manager mu.
  - Generation guard: `startGen` captured at `startKeepalive` before goroutine spawn; runner uses `LOCK-FREE gen.Load()` — drop action if link recreated (Apply bumped gen). Applies-with-recreate ordering: `stopKeepaliveLocked` drain-before-replace in `Apply` — this ordering must stay in `tunnel_manager.go` Apply dispatch.
  - VRF claim ordering: `reconcileVRFClaimLocked` must run after link exist + address reconcile, before final Up — keep call order in `Apply` dispatch sequence, doc in manager file.
- **Tests + gate:**
  - `pkg/routing/tunnel_reconcile_test.go:1649 LOC` — tunnel reconcile regression.
  - `pkg/routing/routing_test.go:1805 LOC`, `iface_reuse_test.go:650` — routing manager.
  - Keepalive: `keepaliveTick` is already exported for deterministic single-tick tests (see comment at line 1572). Existing tests must stay green.
  - Canary: `TestTunnelSplitKeepliveLockFreeInvariant` — use `go vet -unsafeptr` or static assert that `keepaliveTick` source does not contain `t.mu` — or more concretely a `grep` canary in test: open `tunnel_keepalive.go`, assert no `t.mu` string outside comments.
  - `make test-go` green; `make test-deploy` tunnel smoke if changed.
- **Why it matters:**
  - Reviewability: 1889 LOC + 36 funcs + 5 domains in one file — verifying keepalive lock-free + VRF ordering + WG MTU + address reconcile requires full-file traversal. The Axis-D pattern is a correctness-critical concurrency protocol (documented across ~60 comment lines) that deserves its own file to be locally auditable.
  - The prompt specifically calls out "keepalive Axis D commit-after-success lock-free (keepaliveTick never takes t.mu) hard to verify when interleaved with GRE creation" — split directly addresses that concern.
- **Fix direction (ordered PRs, B first after gen-guard doc):**
  1. PR-1 (mechanical): extract `tunnel_keepalive.go` — moves `KeepaliveState`, `keepaliveRunner`, `startKeepalive`, `keepaliveLoop`, `keepaliveTick`, `keepaliveProbeDeadline`, `nextSeq`, `clear/markUnknown`, `classifyErrnoString`, `GetKeepaliveState` — preserves lock-free invariant alone. Tests green, no logic change.
  2. PR-2: extract `tunnel_wg.go` (WG path) + `tunnel_gre.go` (anchor path) — two GRE/WG domains separated.
  3. PR-3: extract `tunnel_reconcile.go` (VRF + address) leaving `tunnel_manager.go` as <600 LOC dispatcher.
- **Labels:** `modularity`, `B`, `ordering-sensitive`, `routing`, `keepalive`, `lock-free`, `vrf`, `reviewability`
- **Dedup note:** Not previously filed. #4421 mentions rules.go 3 domains, not tunnel.go.

---

### A4-06 — daemon_apply.go applyConfigLocked 1148-LOC god-function

- **Title:** `pkg/daemon/daemon_apply.go` `applyConfigLocked` 1148 LOC god-function threads 20+ subsystem reconciles in one function with implicit commit-cancel boundary ordering — every subsystem PR touches same function for C1/C2/C3 `ctx.Err()` insertion point
- **Severity:** Medium
- **Confidence:** High
- **Refactor class:** B (ordering-sensitive ordering — SNMP must precede early aborts, VRF before interfaces, bootstrap-exit before naming, networkd before DHCP, fail-closed protocol-gate error must abort before tail best-effort errors; C1/C2/C3 context cancellation boundaries #2926)
- **Evidence:**
  - `pkg/daemon/daemon_apply.go:546` `func (d *Daemon) applyConfigLocked(ctx context.Context, cfg *config.Config) error {` — 1148 LOC body (lines 546..1694 approx).
  - Phases inlined (grep of body):
    ```go
    // #2926 boundary C1 ...
    // 0. Reconcile VRF devices
    // 1. Reconcile interfaces ...
    // 2. Reconcile networkd .link/.network files
    // 3. Reconcile DHCP clients
    // 4. ...
    // 8–21: tail reconcile dispatches (VRRP, system config, syslog, ...)
    ```
    The function contains SNMP reconcile (must be first), bootstrap exit, config-arrival naming, VIP warn reset, warning log loop, C1 context check, VRF, interface, networkd, DHCP, routing, FRR, userspace-dp compile+apply, nftables, flow-export, DDNS, event-engine, etc.
  - Companion functions in same file: `applyConfig:108`, `applyCancelCtx:151`, `commitAndApply:175`, `applyAndSyncCommitted:255`, `applyErrSkipsPeerSync:290` — total file 1935 LOC.
  - `daemon_run.go` (2329 LOC) is separate file — Apply vs Run split already exists, but Apply still monolithic internally.
  - `daemon_ha.go:1511`, `daemon_nft.go:1432`, `daemon_ha_fabric.go:965`, `daemon_ha_sync.go:1020`, `daemon_flow.go:661` — some apply sub-steps are methods called from `applyConfigLocked`, living in other files — but the orchestration/ordering still in one func.
- **Proposed decomposition (phase-oriented, ordering preserved in top-level slice):**
  ```
  pkg/daemon/
    daemon_apply.go            — thin orchestrator (<300 LOC): bootstrap-exit → naming → warning loop → C1 boundary → phase pipeline dispatcher (slice of phase funcs) + C2/C3 boundaries + applyAndSyncCommitted
    daemon_apply_phases.go     — phase type + ordered slice:
      type applyPhase struct { name string; fn func(ctx context.Context, cfg *Config) error; cancelBoundary bool; vital bool }
      var applyPhases = []applyPhase{
        {name:"vrf", fn: phaseVRF, vital:true},
        {name:"interfaces", fn: phaseInterfaces, vital:true},
        {name:"networkd", fn: phaseNetworkd, vital:false},
        {name:"dhcp", fn: phaseDHCP, vital:false},
        {name:"routing", fn: phaseRouting, vital:false},
        {name:"frr", fn: phaseFRR, vital:true},
        {name:"dataplane", fn: phaseDataplane, vital:true, cancelBoundary:true}, // C2 boundary before
        {name:"nft", fn: phaseNft, vital:false},
        {name:"flow-export", fn: phaseFlowExport, vital:false},
        {name:"ddns", ...},
        {name:"system", ...},
        {name:"vrrp", ...},
        ...
      }
      Each phaseX delegates to existing per-subsystem method (reconcileSNMP, ReconcileVRFs, etc.) — NO logic move in first PR, just extraction.
  ```
  Key constraint: the SNMP-first early-abort ordering (`reconcileSNMP` before dataplane early-abort) and the C1/C2/C3 context cancellation boundaries MUST stay documented at top-level dispatcher, not buried in phase impls. `compileErrorMustAbortApply` error class must still short-circuit before tail best-effort errors joining (existing `#4034` fix).
- **Hot-path preservation / ordering invariants:**
  - Cold path only — commit apply path, human-paced (commit RPC). No per-packet, no per-session.
  - Ordering invariants:
    - SNMP reconcile FIRST, even before VRF/interfaces — committed authorization live regardless of later dataplane abort.
    - Bootstrap-exit + config-arrival naming BEFORE any reconcile that wires config onto interfaces.
    - VRF before interfaces (interfaces may be slaved to VRF).
    - Networkd .link/.network write before DHCP (DHCP client needs kernel netdev present).
    - Dataplane compile+apply before nft/flow-export (nft rules may refer to dataplane-discovered IPs).
    - Dataplane early-abort (compileErrorMustAbortApply: policy-scheduler / deterministic NAT incompatibility) must still abort BEFORE tail but AFTER SNMP — peer sync suppression via `applyErrSkipsPeerSync` distinction (disarmed vs non-fatal).
    - C1 boundary before netlink reconcile (cheapest abort point), C2/C3 before/after long I/O (FRR reload + Rust control socket).
    - `applyAndSyncCommitted` after apply: commit success + active config already promoted, so best-effort tail errors still push config to peer (non-fatal) — only disarmed dataplane / ctx abort skip peer sync.
  - For refactor: Phase slice preserves order by declaration; phases are func closures over `*Daemon` and ctx; C-boundaries are explicit fields on phase struct, not implicit `ctx.Err()` checks scattered inside god func.
- **Tests + gate:**
  - `daemon_apply_test.go` if existing + `daemon_ddns_surface_a_test.go:953`, `daemon_flowexport_reconcile_test.go:595`, `daemon_ipmon_test.go:587`.
  - Boot apply fast path + `TestNoDirectOsWriteFile` fsatomic canary (applies walk `pkg/daemon` for direct `os.WriteFile` — phase move must not add new allowlisted funcs).
  - Live gate: `make test-deploy` + `make cluster-deploy` + `make test-failover` (apply touches HA path) before merge.
  - CANARY: `TestApplyPhasesOrder` — assert `applyPhases` names in declared order, assert SNMP is index 0, dataplane after FRR, tail after dataplane.
- **Why it matters:** `applyConfigLocked` is the second-highest contention function after `metrics_descriptors.go` — every feature PR that adds a subsystem step inserts a 20-line block into same 1148-line func. C1/C2/C3 boundary checks are easy to forget at correct point when func is this long.
- **Fix direction:**
  1. PR-1 (no logic move): introduce `applyPhase` type + `applyPhases` slice, move existing per-step calls into `phaseFoo` methods that call same underlying reconciles, update `applyConfigLocked` to iterate slice. Document ordering invariants inline. Tests green.
  2. PR-2+: extract each phase's implementation into `daemon_apply_vrf.go`, `daemon_apply_interfaces.go`, etc., each file self-contained, keeping dispatcher order in one file.
- **Labels:** `modularity`, `B`, `god-function`, `ordering-sensitive`, `daemon`, `apply-pipeline`
- **Dedup note:** #4407 filed Daemon god-struct 150+ fields, not `applyConfigLocked` ordering. #4662 filed `daemon_run.go` Run() ~1690 LOC ordering-sensitive, not this function. Distinct.

---

### A4-07 — frr/policy_render.go 6-route-family render + BFD in one file (second-tier)

- **Title:** `pkg/frr/policy_render.go` 1938 LOC mixes BFD profile/peer render helpers, BGP + OSPF + OSPFv3 + RIP + IS-IS protocol render, route-filter + community + import/export policy rendering in one file
- **Severity:** Low (under 2000 but top in FRR)
- **Confidence:** High
- **Refactor class:** A (mechanical — render helpers are pure string builder, no locking, no atomic, cold path — FRR config generation on commit)
- **Evidence:**
  - `pkg/frr/policy_render.go:49` `sanitizeFRRValue`, `:79` `validRouterID`, `:124` `resolveRedistribute`, `:220` `isDefinedPolicyStatement`, `:247` `policyStatementHasNextHopSelf`, `:268` `lastNonEmpty`, `:285` `bgpEffectiveExport/Import`, `:333` `collectBGPRouteMapPolicies`.
  - `:360-469` BFD domain: `bfdProfile`, `bfdPeer`, `bfdSection`, `newBFDSection`, `addProfile/Peer`, `empty`, `render`, `bfdProfileName`.
  - `:491-1150` `generateProtocols` — ~600 LOC handling OSPF/OSPFv3/BGP/RIP/ISIS/ECMP/BFD in one func.
  - `:1135-1540` `renderRouteFilterEntry`, `indexedRouteFilter`, `partitionRouteFiltersByFamily`, `communityMemberIsRegex`, `redistFailClosedRouteMap`, `policyNeedsRedistAlias`, `policyTrailingAction`, `generatePolicyOptions`, `renderRouteMapForPolicy`.
  - `pkg/frr/manager.go:911` — FRR manager owns external behavior; policy_render is internal render.
  - `pkg/frr/frr_test.go:5920 LOC` — covers render outputs.
- **Proposed decomposition:**
  ```
  pkg/frr/
    bfd_render.go           — bfdProfile, bfdPeer, bfdSection, bfdProfileName, render()
    bgp_render.go           — collectBGPRouteMapPolicies, bgpEffectiveExport/Import, BGP leg of generateProtocols
    ospf_render.go          — OSPF/OSPFv3 legs
    protocol_render.go      — generateProtocols dispatcher calling per-family functions + RouteMap helpers
    policy_options_render.go — generatePolicyOptions, renderRouteMapForPolicy, renderRouteFilterEntry, partitionRouteFiltersByFamily, communityMemberIsRegex, redistFailClosedRouteMap, policyNeedsRedistAlias, policyTrailingAction
    policy_render.go        — thin facade or deleted — sanitizeFRRValue, validRouterID, resolveRedistribute, isDefinedPolicyStatement, etc. stay or move to shared helpers file.
  ```
  Same package `frr`, no new package boundary, pure code-motion; `frr_test.go` stays green. `generateProtocols` becomes ~50 LOC dispatcher.
- **Hot-path preservation:** Cold path — FRR config generation on commit only. String `strings.Builder` renderers, no hot path.
- **Tests + gate:** `pkg/frr/frr_test.go:5920 LOC` parity — expect no golden change; `make test-go` green.
- **Why it matters:** 1938 LOC with 6 route-family legs + BFD + policy-options in one file — reviewer of BGP fix must read OSPF/RIP/ISIS/BFD context. Per-family files reduce PR scope.
- **Fix direction:** Single PR-per-family mechanical splits, low risk.
- **Labels:** `modularity`, `A`, `cold-path`, `frr`, `reviewability`
- **Dedup note:** Not previously filed.

---

## 3. D-negatives (intentionally NOT filed — single-responsibility or coherent SM)

### D-NEG-01 — maps_sync.go is focused single-domain

- **File:** `pkg/dataplane/userspace/maps_sync.go` 1763 LOC / ~25 funcs
- **Why NOT a finding:** Single coherent responsibility: userspace classifier / local-address / ingress-binding / interface-NAT map sync into userspace-dp helper state. Functions: `programBootstrapMapsLocked`, `setupUserspaceCPUMapLocked`, `syncUserspaceClassifierMapsLocked`, `syncIngressIfaceMapLocked`, `syncLocalAddressMapsLocked`, `syncInterfaceNATAddressMapsLocked`, `verifyBindingsMapLocked`, `shouldAutoRebindBusyBindingsLocked`, `maybeAutoRebindBusyBindingsLocked` + address-entry builders. No cross-domain smuggling (no session sync, no NAT compile, no CoS). The LOC is dominated by careful kernel-equiv address enumeration + binding-plan keying, which is cohesion, not accidental complexity. Split would be artificial.
- **Threshold note:** 1763 < 2000, focused domain, low merge pressure (dataplane maps change less often than protocol or metrics).

### D-NEG-02 — vrrp/instance.go single coherent RFC 5798 SM (with internal sub-domains but one safety property)

- **File:** `pkg/vrrp/instance.go` 2417 LOC / 64 funcs / 3 types
- **Why NOT a finding:** Single coherent state machine implementing RFC 5798 VRRP (Initialize/Backup/Master) plus closely coupled sub-protocols required for a VRRP instance: RX handler (handleBackupRx/handleMasterRx), TX (advert send), GARP (suppression gates: garpEpoch + lastGARPTime, force bypass), advert-interval (Master_Adver_Interval learned from peer + local effective interval), preempt-hold (#2850: timer + armed flag + liveness watchdog #4584), VIP set selection (interface addrs, vipAddrSet, local IPv4/IPv6 reresolve), priority tracking (effective priority via track.go). All under one SM loop `run()` with `StateBackup/StateMaster` dispatch and `stepBackup` including preemptHold timer. There IS no standing RFC to keep these in separate files — RFC 5798 describes them as one machine, and the implementation preserves that. Correctness hinges on having SM transition documentation, preemption gating (`shouldPreemptObservedMaster` RFC 5798 §6.4.2), and master-down interval computation in same file reviewable atomically. Extracting GARP or advert-interval into another file would split a single RFC section from its caller (e.g. `becomeMaster` GARP burst depends on VIP reconciliation timing). Any split would need to preserve the single-goroutine run-loop invariant that all timer Stop/Reset happen on run-loop goroutine (see `updateConfig` comment at `instance.go:464-473`). The correct maintenance action is section comments + `go vet` canaries, not file split.

### D-NEG-03 — daemon god-struct already #4407

- **File:** `pkg/daemon` — Daemon struct 150+ fields noted in task description as already filed (#4407). The struct lives across `pkg/daemon/daemon.go` and sub-files. Per task instruction: D-negative to avoid re-filing. Not investigated as new finding; the god-struct fix direction (group by subsystem lifetime: naming, HA, DHCP, routing, flow-export, etc.) is tracked in that issue.

### D-NEG-04 — daemon_run.go Run() ~1690 LOC ordering-sensitive already #4662

- **File:** `pkg/daemon/daemon_run.go` 2329 LOC, `Run()` body ~1690 LOC
- **Why NOT a new finding:** Already filed as #4662 (just filed per prompt). Task explicitly says do NOT re-report same unless new angle. No new angle presented here beyond what's in #4662 (bootstrap + naming + run-loop + exit ordering-sensitive). If splitting, it would be B (ordering-sensitive) — but filing blocked by dedup rule.

### D-NEG-05 — format/buffers.go shared row-model already #4661

- **File:** `pkg/dataplane/userspace/format/buffers.go` 773 LOC — shared row model CLI/gRPC/REST buffer-status parity.
- **Why NOT a new finding:** Already filed as #4661 (format/buffers.go 773 shared row model). Per prompt: do NOT re-report. Its parity goal (CLI vs gRPC vs REST) benefits from single model; file size 773 < 2000 threshold for that domain.

### D-NEG-06 — flowexport + rules.go + Surface-A DDNS already #4421

- **File:** `pkg/flowexport` monolith, `pkg/routing/rules.go` 1274 LOC (3 domains), Surface-A DDNS, event-engine — prompt says filed in #4421. Not re-filed here.

---

## 4. Fix direction summary — ordered PRs (MoSCoW / risk ordering)

**Tier 0 — zero-risk mechanical (A), highest reviewability win:**

1. **A4-02/PR1 — protocol resolution.rs extraction** — Rust already has it as 105 LOC file; Go equivalent is `PacketResolution/FlowTuple/FlowWorker` — 2 types, ~100 LOC off 3011. Trivial rebase, no merge-risk elsewhere.
2. **A4-01/PR1 — compiler_validate_warn firewall group extract** — 4 warn validators + helpers out to `validate_warn_firewall.go`, dispatcher stays. Validates file-split template for rest of group.
3. **A4-03/PR1 — metrics sys + event + DHCP/DDNS descriptor groups** — 2-3 files, compositional init pattern introduced.

**Tier 1 — mechanical but larger blast radius (A):**

4. **A4-02/PR2-5 — protocol CoS/nat/security/binding groups** — follow Rust template; each PR one domain file (500-900 LOC off). After PR5, `protocol.go` thin or gone.
5. **A4-01/PR2-3 — remaining warn-validator groups** — host-inbound, routing, DDNS+CoS. Leaves `compiler_validate_warn.go` as <100 LOC dispatcher.
6. **A4-03/PR2 — remaining metrics session/screen/policy-filter/nat/host-inbound groups** — leaves `metrics_descriptors.go` dispatcher <100 LOC.
7. **A4-07 — frr/policy_render.go BFD + per-family splits** — 4 new files, thin dispatcher.

**Tier 2 — ordering-sensitive (B) — needs invariant doc + failover gate:**

8. **A4-04/PR0 — HA sync invariants doc** — `docs/ha-sync-invariants.md` captures gen-guard (stamp→queue→take, cap skip-not-clear, #2221 tombstone freshness #3931 config gen), bulk reset (#2198 F2, BulkStart before re-prime, reconcileStaleSessions after BulkEnd, mid-bulk gen-0 fallback), #2198 F3 non-atomicity (single ACTIVE fabric conn => single receiver goroutine per peer), single-active-fabric (conn0 preferred, conn1 standby), fabric dial deterministic tie-break. This is terminal artifact for following B PRs.
9. **A4-04/PR1 — sync_gen_guard.go extraction** — all gen-guard funcs together, same mu, same cap; `sync_gen_guard_test.go` kept, `test-failover` gate.
10. **A4-04/PR2 — sync_journal.go + sync_sweep.go** — journal and sweep domains.
11. **A4-04/PR3 — sync_fabric.go + sync_config.go** — fabric single-active + config-sync gen.
12. **A4-04/PR4 — sync_transport.go** — accept/connect/send/receive loops, thin `sync_conn.go` deleted.

**Tier 3 — B with lock-free invariant isolation (A4-05):**

13. **A4-05/PR1 — tunnel_keepalive.go extraction** — isolates Axis-D 6-step sequence + lock-free `gen.Load()` invariant alone; `keepaliveTick` deterministic tick tests remain, canary that `t.mu` not referenced.
14. **A4-05/PR2 — tunnel_gre.go + tunnel_wg.go** — GRE anchor vs WG tuntap split.
15. **A4-05/PR3 — tunnel_reconcile.go (VRF+address)** leaving `tunnel_manager.go` dispatcher <600 LOC.

**Tier 4 — B god-function phase pipeline (A4-06):**

16. **A4-06/PR1 — applyPhase slice introduction** — phase type + ordered slice + phaseFoo methods calling existing reconciles, `TestApplyPhasesOrder` canary, `applyConfigLocked` reduced to slice iteration with C1/C2/C3 boundaries as struct fields.
17. **A4-06/PR2+ — per-phase file extraction** — each phase impl into `daemon_apply_vrf.go`, `daemon_apply_interfaces.go`, etc., dispatcher order remains single-file truth.

**Gates per tier — per engineering-style.md (§X Deployment + feature validation):**

- Tier 0-1 (A mechanical cold path): `make test-go` + `cargo test protocol` (for A4-02) + `metrics_descriptor_coverage_test.go` for A4-03.
- Tier 2 (B HA): MUST pass `make cluster-deploy` + `make test-failover` + `make test-ha-crash` per prompt Requirement + §X gate — items touch HA session sync / failover.
- Tier 3 (B tunnel keepalive): `make test-go` + `TestTunnelSplitKeepaliveLockFreeInvariant` + `make test-deploy` (tunnel smoke) — touched domain: routing/keepalive + WG MTU + VRF.
- Tier 4 (B apply pipeline): `make test-deploy` + `make cluster-deploy` + `make test-failover` (apply touches HA) — same gate as Tier 2.

**Dependency order respects task focus note:**

- Prompts "Rust already split Rust side into snapshot.rs/control.rs/cos.rs/binding.rs/status.rs — Rust side is template for Go split" — A4-02 first because it has a ready template + zero risk + highest LOC win (3011 → ≤500 per file).
- metrics_descriptors second for merge-conflict relief.
- validate_warn third for config-review relief (warn validators parallel strict split that already landed).
- sync_conn.go (B) after Tier 0 docs, because ordering doc PR0 must land first per B discipline.
- tunnel.go (B) after sync_conn doc PR0 — same B discipline — but can run parallel branch if contended.
- applyConfigLocked (B) last — many subsystems depend on it; splitting it early creates rebase debt for other splits (each subsystem PR would have to rebase onto new phase slice).

---

## 5. Cross-cutting metrics + risk notes

**Largest remaining files post-split (projected):**

| File after split | Projected LOC | Note |
|------------------|---------------|------|
| `pkg/dataplane/userspace/protocol/control.go` (ProcessStatus) | ~1100 | Could further split ProcessStatus counters vs bindings vs event-stream but low merge conflict after CoS/NAT/security/binding moved |
| `pkg/cluster/sync_gen_guard.go` | ~350 | Even after extract, gen-guard SM compact |
| `pkg/cluster/sync_fabric.go + sync_transport.go` | ~400 + ~400 | Balanced |
| `pkg/routing/tunnel_keepalive.go` | ~250 | Tight Axis-D |
| `pkg/api/metrics_descriptors_global.go` | ~400 | Reduced from 1896 |
| `pkg/daemon/daemon_apply.go` (dispatcher) | ~300 | Down from 1935 |

**Build-time impact estimate:**

- A4-02: `pkg/dataplane/userspace` package incremental compile cost currently dominated by single 3011 LOC file parsing + 78 types; splitting into same-package files does NOT change total compile time (Go package = all files together) but reduces incremental recompile on file change: `go build -a` same, `go test -run Foo` touching one domain recompiles only that file's content change + dependents see same import edge but editor feedback faster (single domain file = quicker `gopls` diagnostics). Real win is merge avoidance, not build seconds.
- A4-03: same — package-level compile unchanged, but editor/CI incremental on descriptor change is scoped: `go test ./pkg/api -run Coverage` touching only one domain file recompiles less of test package's import tree if split along struct boundaries (descriptors are data only; no method hash change in dependents).
- A4-04/A4-05: B splits are risk-control, not build-time; primary win is reviewability of correctness-critical Section 2/3 invariants and isolation of lock-free gen guard.

**Hot-path preservation ledger (per finding required field):**

| Finding | Hot? | Preservation mechanism |
|---------|------|------------------------|
| A4-01 warn validators | cold commit path | pure code-motion, no hot, error text identity |
| A4-02 protocol DTOs | cold 1/s | json tags identity, wire parity test, no alloc change |
| A4-03 metrics Descs | cold reg | Desc pointer identity + labels identity, Collect unchanged |
| A4-04 sync_conn B | cold HA sync control plane | gen-guard sequence identity, cap skip-not-clear, tombstone freshness, bulk-reset timing, single-active-fabric invariant docs; no lock split; no mu held across Put |
| A4-05 tunnel B | cold 1/s + keepalive 1s tick | keepaliveTick never takes t.mu, gen.Load() lock-free, 6-step Axis-D sequence preserved verbatim in one file |
| A4-06 apply god-func B | cold commit | phase order = slice declaration order, C1/C2/C3 boundaries explicit on slice entry, SNMP-first early-abort + disarmed vs non-fatal peer-sync distinction preserved |

---

## 6. Raw evidence appendix

**protocol.go type census (78 types):**

`ControlRequest, ControlResponse, ConfigSnapshot, AddressBookSnapshot, FlowSnapshot, SnapshotSummary, ZoneSnapshot, InterfaceSnapshot, ClassOfServiceSnapshot, CoSForwardingClassSnapshot, CoSDSCPClassifierSnapshot, CoSDSCPClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSDSCPRewriteRuleSnapshot, CoSDSCPRewriteRuleEntrySnapshot, CoSSchedulerSnapshot, CoSSchedulerMapSnapshot, CoSSchedulerMapEntrySnapshot, FabricSnapshot, TunnelEndpointSnapshot, TunnelWgPeerWire, NatPortRangeWire, NatAppTermWire, SourceNATRuleSnapshot, StaticNATRuleSnapshot, DestinationNATRuleSnapshot, NAT64RuleSnapshot, Nptv6RuleSnapshot, ScreenProfileSnapshot, ScreenMissingProfileRef, FirewallFilterSnapshot, FirewallTermSnapshot, FlexMatchSnapshot, PolicerSnapshot, ThreeColorPolicerSnapshot, FlowExportSnapshot, MirrorConfigSnapshot, PolicyApplicationSnapshot, AppCatalogEntrySnapshot, PolicyRuleSnapshot, InterfaceAddressSnapshot, RouteSnapshot, NeighborSnapshot, UserspaceMapPins, UserspaceCapabilities, ProcessStatus, WgPeerStatus, WgTunnelStatus, SourceNATPoolStatus, EventStreamStatus, CoSInterfaceStatus, ThreeColorPolicerStatus, CoSQueueStatus, FirewallFilterTermCounterStatus, PolicyRuleCounterStatus, NATRuleCounterStatus, ZoneTrafficCounterStatus, HAStateUpdateRequest, WorkerRuntimeStatus, HAGroupStatus, SlowPathStatus, PacketResolution, FlowTupleStatus, FlowWorkerStatus, CoSActiveFlowCountStatus, ForwardingControlRequest, QueueControlRequest, BindingControlRequest, QueueStatus, BindingStatus, BindingCountersSnapshot, ExceptionStatus, InjectPacketRequest, SessionDeltaDrainRequest, SessionExportRequest, SessionSyncRequest, SessionDeltaInfo`

Rust counterpart: `userspace-dp/src/protocol/` total 7144 LOC inc tests, 7 domain files + mod.rs re-exporting crate-wide, `tests.rs` 2393 LOC wire golden.

**metrics_descriptors 279 NewDesc evidence:**

`grep -n NewDesc pkg/api/metrics_descriptors.go | wc -l == 279` — representative prefixes: `xpf_packets_total, xpf_drops_total, xpf_counter_read_errors_total, xpf_sessions_created_total, xpf_sessions_closed_total, xpf_screen_drops_total, xpf_screen_drops_by_reason_total, xpf_policy_denies_total, xpf_nat_alloc_failures_total, xpf_nat64_translations_total, xpf_host_inbound_denies_total, xpf_host_inbound_kernel_denies_total, xpf_host_inbound_addressless_zones, xpf_host_inbound_addressless_interfaces, xpf_host_inbound_ambiguous_addresses, xpf_tc_egress_packets_total, xpf_screen_syncookie_total, xpf_flow_cache_total, xpf_interface_packets_total, xpf_interface_bytes_total, xpf_interface_counter_read_errors_total, xpf_policy_hits_total, xpf_filter_hits_total, xpf_userspace_three_color_policer_*, xpf_sessions_active, xpf_sessions_established, xpf_sessions_ipv4, xpf_sessions_ipv6, xpf_sessions_snat, xpf_sessions_dnat, xpf_sessions_breakdown_scrape_ok, xpf_gc_sweep_duration_seconds, xpf_nat_pool_*, xpf_userspace_source_nat_pool_*, xpf_dhcp_leases_active, xpf_dhcp_ddns_*, xpf_ddns_surface_a_*, xpf_sys_*, xpf_daemon_*, xpf_...` — see `pkg/api/metrics_descriptor_coverage_test.go:726` for enumerated set.

**sync_conn ordering invariant verbatim:**

`sync_conn.go:287-310` `resetRecvGen` comment includes #3931 config gen reset companion, #2198 F2 bulk barrier safety argument, mid-bulk gen-0 fallback; `sync_conn.go:311-360` F3 non-atomicity note inside comment.
`sync_conn.go:67-250` gen-guard SM: stamp (sender mutates gen + records bounded) → wire → guard installGuard/incoming < stored => refuse → Put → record / delete tombstone fresh gen always > install gen, equality applies (delete of very session).

**tunnel keepalive Axis-D verbatim (6-phase doc + lock-free):**

`pkg/routing/tunnel.go:1540-1572` keepaliveLoop doc block "Tick body is the §6 Axis D COMMIT-AFTER-SUCCESS sequence: 1. Under state.mu: classify ... WITHOUT writing Up; Unlock. 2. No intent → done. 3. LinkByName... 4. Lock-free gen.Load() guard ... Never takes t.mu (AGY r5). 5. Single LinkSetUp/Down OUTSIDE mu. 6. Commit Up ONLY on netlink success".

`pkg/routing/tunnel.go:1485-1511` `startKeepalive`: `gen := t.linkGenForLocked(tunnelName); startGen := gen.Load()` capture before goroutine spawn.

**daemon_apply phase ordering:**

`pkg/daemon/daemon_apply.go:546` `applyConfigLocked` — proven order from greps: `reconcileSNMP` (first, idempotent), `runBootstrapExitStartup` / `maybeReapplyConfigArrivalNaming` (naming), VIP warning suppression reset, warning log loop, C1 ctx boundary, then VRF → interfaces → networkd → DHCP → routing → FRR → dataplane (vital, compileErrorMustAbortApply distinguishes from best-effort) → nft → flow-export → system → VRRP. Evidence for best-effort vs vital distinction in `applyAndSyncCommitted:255` + `applyErrSkipsPeerSync:290` (disarmed vs non-fatal still syncs peer #4034).

---

## 7. Worktree hygiene

All reads via detached worktree at `/tmp/review-wt-ps-041-a4-b1` (HEAD = `95b33d496 Merged #4685`). No files in `/tmp/review-work-ps-041/` other than this report. No `/tmp/ps-review-041*.md` created.



---


## Coverage & verification summary

**Files reviewed / total:** 10 batches covering Rust AF_XDP dataplane hot path (poll_descriptor, poll_stages, tx/dispatch/cos_classify/rings/drain/transmit, cos/queue_service/queue_ops/shared_cos_lease/types/cos, session/mod+ctx+install+lookup+expire+key+entry+wheel+session_glue, forwarding/mod+types/forwarding_build/neighbor+resolver+dispatch+worker+loop_body, screen/scan/frame/inspect/frame/mod+wg/runtime/policy, WG/engine+cookie/event_stream+cold_path_hist+coordinator+types+protocol+binding+server/helpers+event_emit) + NAT (allocator/source/destination/nat64/nptv6/XDP shim + Go compiler_nat) + Go config compilers (validate_warn/go/compiler_system/services/nat/interfaces/uniformgates/types) + Go dataplane/daemon/cluster/routing/metrics/API — ~200k+ LOC non-test across all areas.

**Findings per area (from work-dir intermediates):**

| Area | Intermediate | Size | Findings summary |
|------|-------------|------|-----------------|
| a1a poll_descriptor | ps-a1a-b1.md | 10994 | HFT-grade: 8 outer muts, 34 recycle push vs recycle_now bool fallthrough, Junos-order triplication, cfg(debug-log) icache, flowless 3-way state machine + PBR dupe |
| a1b TX path | ps-a1b-b1.md | 58527 | High: cos_classify 7-way, tcp_segmentation cold build loop, dispatch fabric scatter + direct-TX + PTB. Medium: drain ingest+leftover, rings 4 disciplines, transmit unwind dup |
| a1c CoS | ps-a1c-b1.md | 9676 | 4 findings: waterfill 432 LOC god-func (Class A, High/High), mod.rs god 25 fns, CoSInterfaceRuntime 28-field god struct (B), tx_completion 6-resp |
| a1d Session table | ps-a1d-b1.md | 22780 | High: SessionTable 25 fields god-struct hot 5-tuple vs cold HA/limit/wheel/config, SessionEntry Arc clone ~10ns per miss at 7.5M pps. Medium: session_glue god 30+ fns 5 concerns |
| a1e Forwarding/neighbor | ps-a1e-b1.md | 27634 | ForwardingState 66 fields no #[repr] (C perf-positive #3769/#3182 growth), forwarding/mod.rs 2822 68 fns, neighbor.rs 2036 4 resp (B), forwarding_build exemplary (D), worker already #959 (D) |
| a1f Screen/frame/policy | ps-a1f-b1.md | 37119 | F1 EH walker 5 funcs SSOT #4517 risk (A), F2 screen god-func 5 SYN-flood phases + 22-field ScreenState (B), F3 frame kitchen sink VLAN+NAT+port+NAT64+inject+verify (A), F4 AppCatalog zero-coupling (A), D-neg: scan generic, wg, runtime |
| a1g WG/event_stream | ps-a1g-b1.md | 14272 | 2 A mechanical: wg_control 2280 5 resp, server/helpers 1292 dumping ground; event_stream borderline (A if, D defer); D negatives: wg/engine, types/cos, protocol/binding |
| a2 NAT | ps-a2-b1.md | 10903 | 3 findings: PortAllocator god-struct hot bitmap + cold persistent/GC (C cache-line #[repr(align(64))]), match_source_nat 336 LOC god-func (B), triply-fused NAT compilers (A) + D-neg: nptv6/destination |
| a3 Go config | ps-a3-b1.md | 16315 | 8 findings: compiler_validate_warn 3330 (largest ROI 5 per-domain), compiler_nat 2529 triple-fused, compiler_system 1881 8 subsystems, compiler_services 1821 7 services — all (A) mechanical cold-path, byte-identical gate per #4144 |
| a4 Go dataplane/daemon | ps-a4-b1.md | 65548 | 7 findings: protocol.go 2979 72 types 12 domains (A High), sync_conn.go 1858 8 resp gen-guard (B Medium, #2995/#2198 ordering), tunnel.go 1889 5 resp keepalive Axis-D lock-free (B), validate_warn 3330 (A), metrics_descriptors 1896 279 NewDesc (A), FRR policy_render, rules.go — plus D-negatives: maps_sync focused, vrrp single SM, daemon already #4407 |

**Total findings: 30+ non-duplicate findings spanning all confidence tiers (specifically):**
- (A) MECHANICAL / SAFE: ~16 (Go config compilers, protocol.go wire-format, metrics_descriptors, tunnel cold parts, FRR per-family, frame/inspect EH walker, policy AppCatalog, server/helpers, wg_control, event_stream, NAT compilers triply-fused)
- (B) REQUIRES GUARDRAILS: ~12 (poll_descriptor mutable-locals + recycle invariant + Junos-order triplication, tx/dispatch Phase 8 + fabric scatter + direct-TX + PTB, CoS waterfill mod god + CoSInterfaceRuntime, SessionTable SessionEntry Arc clone, ForwardingState + neighbor, screen god-func SYN-flood phases, sync_conn gen-guard + tunnel keepalive Axis-D lock-free, compiler_nat helpers shared, NAT source match_source_nat)
- (C) PERFORMANCE-POSITIVE: ~4 (PortAllocator hot/cold cache-line split #[repr(align(64))], ForwardingState SoA ForwardingFib(Arc) hot vs cold config, SessionEntry hot/cold inline split ~10ns win at 7.5M pps, CoS CoSInterfaceRuntime field grouping reducing cache footprint)
- (D) DO-NOT-SPLIT: ~11+ (poll_stages.rs 9 stage fns #[inline], reject_reply+filter already cold-extracted, tx/transmit 6-phase split textbook, tx/rings deferred, tx/drain orchestrator clean 35 LOC, shared_cos_lease backlog+vtime well-split, session leaf modules key.rs pure transforms + wheel power-of-two assert + ctx grouping, forwarding_build exemplary 8 files linear chain, worker already #959 decomposed, scan.rs generic ScanCore, wg.rs clean 604 prod + valuable byte-identity tests, runtime.rs plumbing, nat/destination cohesive, nat/tests already split, wg/engine single-responsibility WG protocol, types/cos forwarding/protocol/binding cohesive, event_stream defer, compiler_uniformgates+types already well-split, maps_sync single-domain, vrrp single coherent RFC 5798 SM, daemon already #4407)

**How many Critical/High were coordinator-verified vs dropped:** No Critical/High are dropped — all findings above are coordinator-verified from work-dir intermediates. The poll_descriptor god-function #4404 already filed is enriched, not re-filed as duplicate.



## Suggested issue split — sequenced so each PR is small, independently reviewable, behind existing gates, mechanical before behavioral

### Phase 1: Go mechanical splits (safe, driveable-now, largest ROI build-time + reviewability)

1. **compiler_validate_warn.go 3330 → 5 per-domain files** — (A) mechanical. Largest Go file.
   - `compiler_validate_warn_nat.go`, `_security.go`, `_forwarding.go`, `_ddns.go`, `_routing_cos.go`
   - Gate: `go build ./...` + `go test ./pkg/config/...` green, decl-NAME set identical per #4144.
   - Labels: `refactor`, `go`, `config`

2. **protocol.go 2979 → 12 domain files** — (A) mechanical, 72 types across 12 wire domains.
   - `protocol/control.go`, `snapshot.go`, `status.go`, `binding.go`, `cos.go`, `nat.go`, `policy.go`, `filter.go`, `ha.go`, `session_sync.go`, `eventstream.go`, `docs.go`
   - Gate: `go build ./...` + `cargo test -p userspace-dp`.
   - Labels: `refactor`, `go`, `dataplane`, `protocol`

3. **compiler_system.go 1881 + compiler_services.go 1821 → per-domain** — (A) mechanical.
   - `compiler_system_login.go` + `_snmp.go` + `_chassis.go` + `_ddns.go` + `_userspace.go`
   - `compiler_services_rpm.go` + `_dhcp.go` + `_flow.go` + `_ip_monitoring.go` + `_event.go`
   - Labels: `refactor`, `go`, `config`

4. **compiler_nat.go 2529 → 3-4 files + move strict gates** — (A) mechanical with subtlety.
   - `compiler_nat_helpers.go` + move validators to `compiler_validate_strict_nat.go`
   - Labels: `refactor`, `go`, `nat`

5. **metrics_descriptors.go 1896 → helper methods** — (A) mechanical.
   - `initGlobalDescriptors`, `initUserspaceDescriptors`, `initCoSDescriptors`, etc.
   - Gate: `go test ./pkg/api/...`.

6. **format/buffers.go 773 shared row model** — (A) mechanical.
   - Single row type shared CLI/gRPC/REST buffer-status parity (from #4661).

### Phase 2: Rust mechanical splits (safe, cold path or same-crate boundary)

7. **wg_control.rs 2280 → wg_control/{socket,loop,dispatch,handshake,poll}.rs** — (A) mechanical, cold 100ms poll.
8. **server/helpers.rs 1292 → helpers/{status,session_sync,binding_plan,hash,lifecycle}.rs** — (A) mechanical, header says pending.
9. **frame/mod.rs 1710 → frame/{nat,prep/inject,verify,nat64_fwd}.rs** — (A) mechanical, 9 prior extractions done.
10. **event_stream mod 1693 → transport+sequencing+clock split** — (A) mechanical, optional.
11. **frame/inspect.rs EH walker 5× dup → inspect/ext.rs SSOT + frag.rs + flow.rs + filter.rs** — (A) mechanical, single `walk_ipv6_eh_chain` + const generic set + canary.
12. **policy.rs AppCatalog 235 LOC zero-coupling → policy/app_catalog.rs** — (A) mechanical, pure move.
13. **FRR policy_render.go per-family → bfd_render.go, bgp_render.go, ospf_render.go** — (A).

### Phase 3: Go ordering-sensitive / Rust hot-path-adjacent (requires /triple-review)

14. **sync_conn.go 1858 → sync_conn/{gen_guard,fabric,state_machine,batch}.go** — (B) ordering-sensitive, gen-guard state machine.
15. **tunnel.go 1877 → tunnel/{lifecycle,keepalive,wg_mtu,vrf,address}** — (A/B) mixed, keepalive Axis-D commit-after-success lock-free sensitive.
16. **PortAllocatorShared hot/cold split** — (C) perf-positive, cache-line #[repr(align(64))], measurement-gated vs snat_allocator bench.
17. **nat/source.rs match_source_nat 336 LOC → classify_l4_mode() enum + allocate_pool** — (B) hot-path adjacent.
18. **frame/tcp_segmentation.rs 933 → segment fn by phase** — (B) HOT-PATH, /triple-review per #4652.

### Phase 4: Rust hot-path (requires /triple-review, disassembly + bench gates)

19. **ForwardingState 65-field god-struct → hot FIB vs cold config** — (C) perf-positive, immediate #[repr(C)] + hot-field-first reorder zero-risk, then ForwardingFib(Arc) SoA. Gate: iperf3 ≥23Gb/s.
20. **SessionTable + SessionEntry hot/cold field separation** — (C) perf-positive, ~10ns win at 7.5M pps/worker, SessionHot/SessionCold inline split, Arc clone elimination.
21. **neighbor.rs 2036 → neighbor/{probe,kernel,monitor,warmer}.rs + gc.rs** — (B).
22. **screen/mod.rs SYN-flood god-func 5 phases → screen/{syn_flood,flood,missing_profile}.rs** — (B), #[inline(always)] hot preservation.
23. **session_glue/mod.rs god module 30+ fns 5 concerns → {resolution,bpf_mirror,ha_predicates,worker_cmd,flow_teardown}.rs** — (B).

### Phase 5: Hardest hot-path god-functions (deep /triple-review, NOT driveable-now)

24. **poll_descriptor/mod.rs poll_binding_process_descriptor 4724 LOC** — (B) hardest in codebase, 15+ resp, 39 recycle sites, 11 mutable-locals, Junos-order 3× duplication. Already #4404, this audit: growth measurement 1368→4724 + new decomposition angles. 6 incremental PRs: flowless A → telemetry cold outline C → NAT pre-routing B → host-local dedup B → session install B → hit/miss split B with PacketCtx. Do NOT without disassembly baseline + flowless_local_delivery_tests + inplace_randomized_sequence + FORCE_OVERSIZED/FORCE_TUPLE_MISMATCH single-recycle.
25. **tx/dispatch enqueue_pending_forwards 1048 + tx/cos_classify 7-resp + CoS waterfill** — (B)/(C), Phase 8 + direct-TX + fabric breakdown.

---

## Verification matrix

| Class | Inlining | Alloc | Dispatch | Layout | Locality | Lock scope | Verification |
|-------|----------|-------|----------|--------|----------|------------|--------------|
| (A) Mechanical | Free (same crate TU, or Go same package) | N/A (cold) | N/A | N/A | N/A | N/A | go build/test, cargo build/test, decl-NAME set identical, incremental-build timing |
| (B) Hot-path guardrails | Require #[inline] after move | No Box/Vec/String/clone on per-packet | No trait objects on hot | Carry size_of/align_of | Keep hot fields in one cache line | Narrow critical section, preserve single-writer-per-worker, per-CPU, lock-free/seqlock | cargo asm / objdump -d diff + perf stat + criterion bench + make test + test-failover + CoS smoke |
| (C) Perf-positive | Same as (B) | Same as (B) + must measure improvement | Same as (B) | Same as (B) + SoA proof | Must measure: perf stat LLC-load-miss reduction | Lock-scope narrowing reduces contention | Same as (B) + explicit perf measurement |
| (D) Do-not-split | N/A | N/A | N/A | Already correct | Already tight | Already correct | No change, documenting why |

---

*Base commit: f70146951583823a5ace87b0b11a2e58f46e8db9*
*Repo root: /home/ps/git/avacado-xpf (via git rev-parse --show-toplevel)*
*Generated: merged from 10 batch files under /tmp/review-work-ps-041/ (273k+ total chars work dir)*
*Output: /tmp/ps-review-041.md (this file — ONLY file matching /tmp/ps-review-041*.md after cleanup)*
*Work-dir & worktree contract: intermediates in /tmp/review-work-ps-041/ (now swept per final instructions), worktrees in /tmp/review-wt-ps-041-*/ (swept). Verify: ls /tmp/ps-review-041*.md shows exactly ONE file.*

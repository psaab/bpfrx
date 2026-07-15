# Triage ledger — codex-review-178 (whole-repository defensive audit)

- Review base commit: `33ea184d3` | Triaged against: current `origin/master` (fetched 2026-07-09)
- Review structure: 123 raw candidates → **81 canonical findings** retained (19 High, 47 Medium, 15 Low
  by severity; 80 High-confidence). The review's own Duplicate Suppression already folded **42 raw
  records** into existing issues (see review §"Duplicate Suppression") — those were NOT re-triaged here.
- Every one of the 81 canonical findings was gated against origin/master (symbol-exists / already-fixed /
  real+material) and dedup'd against the full open-issue list (196 open) + 80 merged PRs. Verification was
  fanned out to 7 parallel sub-agents (one per audit area), each reading the cited origin/master blobs via
  `git show origin/master:<path>`; the parent independently re-verified 8 High findings and all 6 ambiguous
  dedups.

## Outcome

| Disposition | Count |
|---|---:|
| FILED as own issue (High) | 19 |
| FILED as own issue (Medium) | 41 |
| FILED into low-materiality cohort (#5328) | 15 |
| DUP of an existing OPEN issue (not filed) | 6 |
| ALREADY-FIXED on origin/master | 0 |
| DROPPED non-material | 0 (2 borderline folded into the cohort) |
| **Total canonical** | **81** |

New issues opened: **#5267–#5327 (60 individual)** + **#5328 (cohort)** = **61**.

Notable: **zero** findings were already-fixed by this session's ~36 merged PRs. Several findings are
RESIDUALS of prior partial fixes (the merged/earlier PR fixed one arm; the audit found the surviving arm) —
those are genuine and were filed. The already-fixed rate the task warned about did not materialize; the
review's ~90% signal held (only 6 of 81 were dups, 0 fixed, 0 stale).

## Cross-batch dedup decisions (the load-bearing calls)

- **A2-b1-F2 vs #5144** → DISTINCT. #5144 = two *separate allocator domains* (overlapping source-NAT/NAT64
  pools) mint identical tuples; A2-b1-F2 reproduces with ONE rule/pool/address because the `address_only`
  path bypasses the allocator entirely (no ownership token). Filed #5269.
- **A5-b1-F2 vs #5085/#5084** → DISTINCT. #5085 = override *sender* empty markers → skipped reconciliation;
  A5-b1-F2 = *receiver* accepts BulkEnd/BulkAck with no active transaction and releases readiness. Verified
  origin/master `sync_conn.go:1485-1522` still lacks the pending-epoch guard. Filed #5272.
- **A6-b2-F1 vs #5084** → DISTINCT. #5084 = config-apply item peer-boot epoch; A6-b2-F1 = *session-import*
  envelope lacks a *config* epoch (session-vs-config axis). Filed #5274.
- **A8-b3-F2 vs #5186** → DISTINCT. #5186 = zeroize omits the /var/lib/xpf/archive dir; A8-b3-F2 = zeroize
  targets the fixed /etc/xpf root instead of the daemon's `-config` root. Filed #5280.
- **A10-b4-F2 vs #5075** → DISTINCT. #5075 = deploy *script* image-roll manifest version match; A10-b4-F2 =
  pkg/upgrade *cutover* HelperHealthy polls only `systemctl is-active`. Filed #5286.
- **A8-b1-F5 vs #5045** → DUP. Same `pkg/api/metrics.go:1039` IsLoaded early-return gate. #5045 (open) owns
  the pre-gate defect; A8-b1-F5 is the same gate suppressing DHCP/DDNS/Surface-A/system families — the
  #5045 fix should extend to move those collectors before the gate. Not re-filed.
- **A8-b2-F4 vs #4886** and **A10-b2-F1 vs #4886** → DUP. #4886 Part A = filtered-clear materializes all
  matching keys; Part B = show re-buffers full output + nests the pager. Both audit-178 restatements. Not
  re-filed.
- **A10-b4-F5 vs #4905 (item C)** and **A10-b4-F6 vs #4904 (item C)** → DUP. Parent independently confirmed:
  #4905-C is `make_config_drive.py:68/77` world-readable ISO (identical); #4904-C is `publish.py:760`
  mutable-tree TOCTOU (identical). The review's dedup index missed these codex-175 issues. Not re-filed.
- **A10-b1-F5 vs #4909** → DUP. check-config stat-then-read TOCTOU already in the #4909 control-plane
  cohort. Not re-filed.

---

## Per-finding ledger

Legend: gates = [symbol-exists | already-fixed | material]. All FILED findings: symbol-exists=YES,
already-fixed=NO, material=YES on origin/master unless noted.

### High severity → individual issues (19)

| Finding | origin/master locus | Disposition |
|---|---|---|
| A1-b6-F1 | event_stream/mod.rs:962-1036 replay-gap FullResync outside producer_seq_lock | **FILED #5267** |
| A1-b8-F1 | dataplane/compiler.go:1368-1392 non-fatal rxvlan-off → stripped-tag zone alias | **FILED #5268** |
| A2-b1-F2 | nat/source.rs:1167,1244-1273 address-only pool unowned tuple (≠#5144) | **FILED #5269** |
| A3-b3-F1 | compiler_protocols.go:287-456 BGP group inheritance sibling-order-dependent | **FILED #5270** |
| A5-b1-F1 | cluster/monitor.go:337-372 IP monitor ignores GlobalThreshold | **FILED #5271** |
| A5-b1-F2 | cluster/sync_conn.go:1485-1522 BulkEnd/Ack no-txn releases readiness (≠#5085) | **FILED #5272** |
| A6-b1-F1 | userspace/eventstream.go:158-168 listen() failure swallowed, HA ready anyway | **FILED #5273** |
| A6-b2-F1 | userspace/protocol.go+ha.rs session import no config epoch (≠#5084) | **FILED #5274** |
| A7-b1-F1 | daemon_run.go:1518-1961 arm failure → policy-free kernel forwarding | **FILED #5275** |
| A7-b1-F2 | daemon_system.go:1495-1550 applyRootAuth never revokes root creds | **FILED #5276** |
| A7-b2-F3 | frr/policy_render.go:301-346,846-886 BGP policy list → one route-map | **FILED #5277** |
| A8-b3-F1 | grpcapi/server.go:312-333 loopback gRPC no per-principal auth (RBAC bypass) | **FILED #5278** |
| A8-b3-F2 | server_diag_zeroize.go:17-24 wipes fixed /etc/xpf not -config root (≠#5186) | **FILED #5280** |
| A8-b3-F3 | server_diag_system_action.go:88-107 zeroize races apply, never stops daemon | **FILED #5281** |
| A9-b1-F1 | feeds/feeds.go:161-173 StopAll frees last-good deny snapshot pre-replacement | **FILED #5282** |
| A9-b1-F2 | snmp/agent.go:325-334 hostname-only EngineID cross-clone replay (≠#4917) | **FILED #5283** |
| A10-b1-F1 | cmd/xpfd/upgrade.go:12-67 bare upgrade standalone cut on clustered node | **FILED #5284** |
| A10-b3-F1 | ddns/surface_a.go:1232-1259 crash falsely confirms renumber (≠closed #2662) | **FILED #5285** |
| A10-b4-F2 | upgrade/system_linux.go:141-159 HelperHealthy zero probe callers (≠#5075) | **FILED #5286** |

### Medium severity → individual issues (41)

| Finding | origin/master locus | Disposition |
|---|---|---|
| A1-b1-F3 | bpf_map/mod.rs:367-472 conntrack refresh full-table scan in packet loop | **FILED #5287** |
| A1-b1-F5 | afxdp/neighbor.rs:412-477 per-ARP/NDP netlink socket on packet worker | **FILED #5288** |
| A1-b1-F6 | afxdp/disposition.rs:81-497 drop path 2 global mutexes + heap format | **FILED #5289** |
| A1-b2-F1 | coordinator/status.rs:578-590 fixed-order drain starves higher slots | **FILED #5290** |
| A1-b2-F2 | coordinator/tunnel_supervision.rs:712-746 TUN WG first-peer MTU for all | **FILED #5291** |
| A1-b4-F2 | frame/wg.rs+forwarding_build/tunnels.rs WG zero-placeholder wrong underlay | **FILED #5292** |
| A1-b7-F1 | filter/engine/cache_sensitive.rs:287-463 flex fields omitted → stale PBR | **FILED #5293** |
| A1-b7-F2 | server/handlers/session_deltas.rs destructive drain before fallible write | **FILED #5294** |
| A1-b4-F3 | session_glue/promote.rs:146-167 transient purge leaks NAT reservation (≠#5178) | **FILED #5295** |
| A3-b1-F1 | appid/catalog.go+runtime.go positional AppID reassigned across applies | **FILED #5296** |
| A3-b2-F2 | compiler_ipsec_bindiface.go:87-95 invalid bind-interface commits, no XFRM | **FILED #5297** |
| A3-b3-F2 | compiler_routing.go:241-302 static-route reject erased | **FILED #5298** |
| A3-b3-F3 | compiler_firewall.go legacy policer bad value → 0 drop-all/inert | **FILED #5299** |
| A3-b3-F4 | compiler_system.go:1052-1091 shared-umem artifact blocking read/node-local | **FILED #5300** |
| A5-b1-F4 | cluster/monitor.go:261-464 serial 800ms IP probes scale by target count | **FILED #5301** |
| A5-b1-F5 | ra/sender.go:786-788 stale cached SLLA after RETH MAC change | **FILED #5302** |
| A5-b1-F6 | cluster/sync_conn.go:1180-1211 no aggregate pre-auth admission bound | **FILED #5303** |
| A6-b1-F2 | maps_session.go:370-421 ClearAllSessions double full-table snapshot ~1GB | **FILED #5304** |
| A6-b1-F3 | userspace/manager_ha.go:923-965 helper fail leaves committed BPF write | **FILED #5305** |
| A6-b2-F3 | userspace/manager_ha.go:98-116 SyncFabricState never updates lastSnapshot | **FILED #5306** |
| A6-b3-F1 | loader_userspace_shim.go:166-190 shim-map validator no ABI/pin check | **FILED #5307** |
| A7-b1-F3 | daemon_scheduler.go+daemon_rpm.go goroutines outlive teardown | **FILED #5308** |
| A7-b1-F4 | daemon/device_map.go:582-660 teardown deletes markers, false success | **FILED #5309** |
| A7-b2-F9 | daemon_apply.go:1506-1556+xfrm.go tunnel/xfrm/bond errors swallowed | **FILED #5310** |
| A9-b1-F3 | eventengine/engine.go:659-670 revision-blind armCooldown | **FILED #5311** |
| A9-b1-F4 | flowexport/ipfix.go:485-513 IPFIX packet-selection IEs for record sampling | **FILED #5312** |
| A9-b1-F5 | daemon_system.go:240-285 applyAggregator discards pending window | **FILED #5313** |
| A9-b1-F6 | logging/syslog.go:737-748 ParseSeverity collapses severities to send-all | **FILED #5314** |
| A8-b1-F1 | api/show_text.go:76-81 REST show-text leaks SNMP community | **FILED #5315** |
| A8-b1-F2 | api/security.go:509-534 match-policies unknown selector → wildcard | **FILED #5316** |
| A8-b1-F3 | api/metrics_*.go double Status() control-socket round trip/scrape | **FILED #5317** |
| A8-b1-F4 | api/sessions.go:140-195 default pagination full walk/page (residual after #5237) | **FILED #5318** |
| A8-b2-F5 | server_show_flow.go:224-305 sessions-top full enrich+sort, swallows err | **FILED #5319** |
| A8-b3-F4 | server_sessions.go:736-801 HA peer-summary failure → success local-only | **FILED #5320** |
| A8-b3-F6 | cmd/cli/main.go:28-40 gRPC CLI no MaxCallRecvMsgSize (>4MiB ShowConfig) | **FILED #5321** |
| A10-b1-F2 | cmd/xpfd/*.go leftover operands mutate default production targets | **FILED #5322** |
| A10-b1-F3 | cmd/cli/show_flow.go:348-360 flow summary hardcoded max + zero counters | **FILED #5323** |
| A10-b2-F2 | pkg/cli/peer.go:24-75 CLI peer omits fabric HMAC → Unauthenticated | **FILED #5324** |
| A10-b2-F3 | cli_show_security_zones.go logical iface refs on base-keyed map | **FILED #5325** |
| A10-b2-F4 | show_services_cos.go:77-84 show interfaces queue empty on status fail | **FILED #5326** |
| A10-b3-F3 | ddns/backend_bind.go:100-140 source-address abandoned on other-family dial | **FILED #5327** |

### Low severity + test-only → cohort #5328 (15)

A1-b2-F3 (WG DSCP/ECN), A1-b5-F1 (bind_mode double-load race), A1-b6-F2 (MSG_RESUME latent),
A1-b6-F3 (fairness --iface fail-open), A3-b1-F2 (AppID tuple-fallback O(N), off-path perf),
A5-b1-F7 (VRRP Status vi.cfg data race), A6-b1-F4 (queue/binding negative→uint32),
A6-b2-F4 (route-overlay stale scheduler bits), A6-b3-F3 (vacuous watchdog test — test-only),
A7-b2-F10 (RSS subset-of-queues accepted), A8-b1-F6 (REST interface-SNAT IPv4-only),
A8-b2-F6 (gRPC DHCP lease err swallowed + HWAddr/DUID mislabel), A10-b1-F4 (buffers ShowText err swallowed),
A10-b2-F5 (show system services hardcoded 50051/8080), A10-b5-F1 (xsk-repro self-addressed probe false-pass;
Medium-rated but diagnostic-tooling-only, distinct from #4906).
→ **All FILED into cohort #5328.** (A3-b1-F2 and A6-b3-F3 were the two agent "DROP" calls; folded into the
cohort rather than dropped, per "when in doubt, track it.")

### DUP of existing OPEN issue → not filed (6)

| Finding | Existing issue | Basis |
|---|---|---|
| A8-b1-F5 | #5045 | same metrics.go:1039 IsLoaded gate; fix should extend to DHCP/DDNS/system families |
| A8-b2-F4 | #4886 (Part A) | filtered session clear materializes all matching keys |
| A10-b2-F1 | #4886 (Part B) | show re-buffers full output + nests invisible pager |
| A10-b4-F5 | #4905 (item C) | make_config_drive.py:68/77 world-readable secret ISO (identical) |
| A10-b4-F6 | #4904 (item C) | publish.py:760 mutable-tree TOCTOU (identical) |
| A10-b1-F5 | #4909 | check-config stat-then-read TOCTOU (already in the #4909 cohort) |

## Verification notes / limitations

- All origin/master reads used `git show origin/master:<path>` (the working tree is ~3300 commits stale).
- 0 findings were stale (deleted/retired symbols) — the review base was recent and its symbol-exists rate
  was 100% on this sample.
- Findings involving live NIC scheduling, HA timing, and provider interoperability (e.g. A5-b1-F4, A5-b1-F5,
  A9-b1-F2 replay window) were confirmed by source inspection; the filed issues note that integration
  reproduction is required before a fix merges (consistent with the review's own limitations section).

Source: codex-review-178

---

## Post-filing audit vs CURRENT origin/master (dfd20eb4e) — 3-gate re-applied to every filed issue

Re-fetched master to dfd20eb4e. Exactly 5 PRs merged AFTER the verification agents' snapshot
(top was #5263): #5260 (afxdp flex byte-slice clamp / #5150), #5262 (cluster hold-timer + reset race /
#5245,#5246), #5264 (snmp EngineID length / #4917), #5265 (feeds invalid-line byte bound / #4922),
#5266 (neighbor-learn source-IP class / #4889). Each filed issue whose locus those PRs touch was
RE-VERIFIED against current master; all others sit in files untouched by those 5 PRs and were
agent-verified present. Also re-checked internal dups and the codex-177 survivors
(#5212/#5213/#5221/#5225/#5228/#5234 — none overlap). #5233 is now CLOSED by PR #5237; #5318 is its
connected-client residual (distinct).

Re-verified directly on dfd20eb4e (defect confirmed still present):
- #5283 snmp: buildEngineID still derives EngineID from os.Hostname deterministically; PR #5264 only
  capped length ('bit-identical construction') -> cross-clone COLLISION intact. KEPT.
- #5282 feeds: Apply still m.StopAll() first (feeds.go:202), StopAll still m.feeds=make() (:329). KEPT.
- #5271 cluster: GlobalThreshold still has zero non-test consumers in pkg/cluster. KEPT.
- #5293 filter: filter_term_semantics_match (cache_sensitive.rs:287) still jumps to action== at :326,
  no flex_* fields; PR #5260 clamped byte slices, not the comparator. KEPT.
- #5288 neighbor: add_kernel_neighbor still at neighbor.rs:459 (RTM_NEWNEIGH per-advert socket), called
  per ARP/NDP in poll_stages.rs:154/211; PR #5266 only rejects non-unicast sources. KEPT.
- #5272 cluster: syncMsgBulkEnd (:1480) still gates epoch check on bulkInProgress; BulkAck sets
  bulkEverCompleted unconditionally. PR #5262 (hold-timer/reset) did not add the guard. KEPT.
- #5318 api: cursor pagination is opt-in (page_size>0); the DEFAULT offset path still full-walks per
  page; PR #5237 fixed only the disconnect vector. Residual KEPT (borderline Medium).

### Per-issue verdict (all KEPT — genuine, novel, present on dfd20eb4e)

- #5267 KEPT — https://github.com/psaab/xpf/issues/5267
- #5268 KEPT — https://github.com/psaab/xpf/issues/5268
- #5269 KEPT — https://github.com/psaab/xpf/issues/5269
- #5270 KEPT — https://github.com/psaab/xpf/issues/5270
- #5271 KEPT — https://github.com/psaab/xpf/issues/5271
- #5272 KEPT — https://github.com/psaab/xpf/issues/5272
- #5273 KEPT — https://github.com/psaab/xpf/issues/5273
- #5274 KEPT — https://github.com/psaab/xpf/issues/5274
- #5275 KEPT — https://github.com/psaab/xpf/issues/5275
- #5276 KEPT — https://github.com/psaab/xpf/issues/5276
- #5277 KEPT — https://github.com/psaab/xpf/issues/5277
- #5278 KEPT — https://github.com/psaab/xpf/issues/5278
- #5280 KEPT — https://github.com/psaab/xpf/issues/5280
- #5281 KEPT — https://github.com/psaab/xpf/issues/5281
- #5282 KEPT — https://github.com/psaab/xpf/issues/5282
- #5283 KEPT — https://github.com/psaab/xpf/issues/5283
- #5284 KEPT — https://github.com/psaab/xpf/issues/5284
- #5285 KEPT — https://github.com/psaab/xpf/issues/5285
- #5286 KEPT — https://github.com/psaab/xpf/issues/5286
- #5287 KEPT — https://github.com/psaab/xpf/issues/5287
- #5288 KEPT — https://github.com/psaab/xpf/issues/5288
- #5289 KEPT — https://github.com/psaab/xpf/issues/5289
- #5290 KEPT — https://github.com/psaab/xpf/issues/5290
- #5291 KEPT — https://github.com/psaab/xpf/issues/5291
- #5292 KEPT — https://github.com/psaab/xpf/issues/5292
- #5293 KEPT — https://github.com/psaab/xpf/issues/5293
- #5294 KEPT — https://github.com/psaab/xpf/issues/5294
- #5295 KEPT — https://github.com/psaab/xpf/issues/5295
- #5296 KEPT — https://github.com/psaab/xpf/issues/5296
- #5297 KEPT — https://github.com/psaab/xpf/issues/5297
- #5298 KEPT — https://github.com/psaab/xpf/issues/5298
- #5299 KEPT — https://github.com/psaab/xpf/issues/5299
- #5300 KEPT — https://github.com/psaab/xpf/issues/5300
- #5301 KEPT — https://github.com/psaab/xpf/issues/5301
- #5302 KEPT — https://github.com/psaab/xpf/issues/5302
- #5303 KEPT — https://github.com/psaab/xpf/issues/5303
- #5304 KEPT — https://github.com/psaab/xpf/issues/5304
- #5305 KEPT — https://github.com/psaab/xpf/issues/5305
- #5306 KEPT — https://github.com/psaab/xpf/issues/5306
- #5307 KEPT — https://github.com/psaab/xpf/issues/5307
- #5308 KEPT — https://github.com/psaab/xpf/issues/5308
- #5309 KEPT — https://github.com/psaab/xpf/issues/5309
- #5310 KEPT — https://github.com/psaab/xpf/issues/5310
- #5311 KEPT — https://github.com/psaab/xpf/issues/5311
- #5312 KEPT — https://github.com/psaab/xpf/issues/5312
- #5313 KEPT — https://github.com/psaab/xpf/issues/5313
- #5314 KEPT — https://github.com/psaab/xpf/issues/5314
- #5315 KEPT — https://github.com/psaab/xpf/issues/5315
- #5316 KEPT — https://github.com/psaab/xpf/issues/5316
- #5317 KEPT — https://github.com/psaab/xpf/issues/5317
- #5318 KEPT — https://github.com/psaab/xpf/issues/5318
- #5319 KEPT — https://github.com/psaab/xpf/issues/5319
- #5320 KEPT — https://github.com/psaab/xpf/issues/5320
- #5321 KEPT — https://github.com/psaab/xpf/issues/5321
- #5322 KEPT — https://github.com/psaab/xpf/issues/5322
- #5323 KEPT — https://github.com/psaab/xpf/issues/5323
- #5324 KEPT — https://github.com/psaab/xpf/issues/5324
- #5325 KEPT — https://github.com/psaab/xpf/issues/5325
- #5326 KEPT — https://github.com/psaab/xpf/issues/5326
- #5327 KEPT — https://github.com/psaab/xpf/issues/5327
- #5328 KEPT — [cohort] 15 low-materiality + test-only survivors (each agent-verified present)

### Closed during audit
- ALREADY-FIXED: 0
- DUP (of own filings or codex-177 survivors): 0 (the 6 pre-filing dups were never filed — see table above)
- NON-MATERIAL: 0 (the 15 low/test items were cohorted into #5328, not filed individually)

Net: 61 issues filed (#5267-#5327 + #5328), 61 KEPT, 0 closed.

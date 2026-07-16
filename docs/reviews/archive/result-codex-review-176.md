# Triage result — codex-review-176 (Codex Refactor Audit 176)

**Review:** `/tmp/codex-review-176.md` (3,526 lines, 47 canonical findings).
**Audit base:** `23eb4506` — verified 101 commits behind **origin/master `38af2cdce`** (those
101 commits are the codex-175 correctness cohort #4857–#4926 + earlier; none overlaps the
module-ownership/hot-path ground this refactor audit covers, so the duplicate rate is genuinely low).
**Method:** every finding verified against `git show origin/master:<path>` (never the ~3,300-commit-stale
working tree). 7 parallel subagent batches by subsystem + parent first-hand corroboration of the HIGH
findings (networkd/RA/proxy-arp/device-map/config-lenient/HA/shim-map symbols).

## Tally
- **FILED: 26** → #4952–#4977
- **REJECTED/immaterial: 19**
- **ALREADY-FIXED: 1** (R7B2-HC-003)
- **DUP / folds into existing backlog: 1** (R4B2-01 → #4421)
- No finding was a pure DUP of a specific already-filed issue (the audit had already dedup'd against
  the codex-175 corpus and refactor trackers #4404/#4407/#4408/#4409/#4421/#4662).

## FILED (26)

| # | Codex ID | Issue | Sev | Class | Evidence (origin/master) |
|---|----------|-------|-----|-------|--------------------------|
| 36 | S1-RUST-RUNTIME-B2-01 | #4952 | High | correctness/fail-open | bringup.rs: post-teardown pthread_create failure swallowed, stage overwritten, ok=true+persist → silent forwarding outage |
| 13 | R5B1-GATE-01 | #4953 | High | availability | compiler_dispatch.go:31 passes no opts; compiler_firewall.go:277 + compiler_class_of_service.go:151 hard-fail CompileConfigLenient → boot blackout/HA-sync loop |
| 27 | R8B2-NETWORKD-01 | #4954 | High | fail-open reconcile | networkd.go:74/169/241/658 — identical retry after failed `networkctl reload` returns nil |
| 38 | S2GDPB2-01 | #4955 | High | security/reconcile | proxyarp.go:185 managedSet from cfg only + daemon_proxyarp.go:107 hasEntries skip → orphan NTF_PROXY never NeighDel'd |
| 39 | S2GDPB2-02 | #4956 | High | fail-open | device_map.go:132 returns nil on swallowed rename/reload; daemon_run.go:2059 consumes retry marker; daemon_apply.go:613 ignores bool |
| 16 | R6-b1-01 | #4957 | High | HA correctness | store.go:544 promotes before daemon_apply.go:349; daemon_ha_sync.go:368-375 active-text shortcut advances high-water on unapplied config |
| 17 | R6-b1-02 | #4958 | High | HA race | daemon_ha_sync.go:551-560 goroutine writes d.sessionSync no mutex/gen; stopClusterComms nils w/o join → nil-deref/stale-overwrite |
| 19 | R6B2-01 | #4959 | High | fail-open publication | maps_sync.go:1515 samePlanRefresh mutates classifier maps then apply_snapshot reject leaves maps NEW/ctrl enabled/no restore |
| 20 | R6B2-02 | #4960 | High | partial actuation | compiler.go:216 compileZones destructive netlink before later-phase error; loader.go:186 live path; no undo |
| 25 | R8-B1-02 | #4961 | High | HA/IPv6 | ra.go:69 global epoch; WithdrawInterfaces([B]) :507 cancels A restart releaseDrain :189-197 → no sender+no tombstone |
| 26 | R8-B1-03 | #4962 | Med | HA concurrency | sync_conn.go:475 async accept; wasDisconnected used post-unlock → aborts bulk + drops cold-prime |
| 28 | R9B2-001 | #4963 | Med | telemetry lifecycle | daemon_flowexport.go:465 callback loads old bundle → ExportSessionClose after retire final flush → stranded record |
| 18 | R6-b1-04 | #4964 | Med | resource leak | daemon_system.go:230 AddCallback per apply (ringbuf.go:305 append-only); canceled aggregator keeps HandleEvent→Add |
| 1 | R1B2-02 | #4965 | Med | correctness | frame/mod.rs:519 prep mutates UMEM before fallible None; flow_cache_hit.rs:411 .or_else over shifted frame → corruption |
| 14 | R5B1-DIAG-02 | #4966 | Med | observability | compiler_validate_warn.go:1201 mutates SurplusSharing (non-idempotent); 4 alarm surfaces recompute vs cfg.Warnings |
| 22 | R7B2-HC-001 | #4967 | Med | parity bug | cmdtree tree.go:570/221 advertise `show bgp`/`firewall effective`; remote cmd/cli/show.go lacks bgp + firewall effective→raw |
| 23 | R7B2-HC-002 | #4968 | Med | parity+resource | cmd/cli/shared.go:141 io.ReadAll + case-insensitive match; local cli_dispatch.go:100 case-sensitive+streamed |
| 46 | R3B2-SCREEN-01 | #4969 | Med | fail-open+perf | screen/mod.rs:162 ~13 parallel FxHashMap; refresh-drift → fail-open limiter + per-packet redundant hashes |
| 40 | S2B3-COMPLETE-03 | #4970 | Low | correctness/unicode | cmd/cli/shared.go:534 rune-index Pos; server_cluster.go:429 slices bytes → corrupts non-ASCII; Tab vs ? differ |
| 7 | R2-b2-02 | #4971 | Med | hot-path perf | tx/transmit/mod.rs:16 String retry alloc + phase_backup.rs last_error lock on backpressure |
| 35 | R2-b2-03 | #4972 | Med | hot-path perf | tx/dispatch/cos.rs:36 + tx_completion.rs:441/836/950 + queue_service:270 per-packet Arc clones + settlement Vec |
| 3 | R2-B1-01 | #4973 | Med | hot-path perf | queue_service/mod.rs:1801/1855 VecDeque::new per shaped-TX batch |
| 12 | R4B2-02 | #4974 | Low-Med | perf O(n²) | event_stream/mod.rs:1126 write_buf.drain(..n) quadratic on slow consumer |
| 10 | R4-b1-04 | #4975 | Low | perf O(n²) | coordinator/mod.rs:133 retain+Vec::contains O(entries×drop_keys), bounded 131072 |
| 6 | R2-b2-01 | #4976 | High | memory-safety hardening | xsk_ffi.rs:17 Rust mirror of libxdp ring structs, build.rs no sizeof/offsetof check → dep-upgrade silent corruption |
| 30 | R10-B1-003 | #4977 | Med | supply-chain | userspace_xdp_rust.go:11 go:embed tracked .o; no source→object freshness gate; stale shim ships green |

## REJECTED / not-filed (21)

| # | Codex ID | Verdict | Reason |
|---|----------|---------|--------|
| 2 | R1B2-04 | REJECT | No current bug — #2449 made both `term_match_extra` builders byte-identical; drift-risk only (pure dedup). |
| 4 | R2-B1-04 | REJECT | Test-only — `select_cos_guarantee_batch`/`legacy_guarantee_rr` are `#[cfg(test)]`; deleting a test scheduler. |
| 5 | R2-B1-05 | REJECT | Privacy-only refactor — `epoch_carry_bytes` already `pub(super)` + grep-guarded; zero correctness/perf/safety impact. |
| 8 | R2-b2-04 | REJECT | Intentional-documented (#715 drop-newest) + API naming; the `Result` is misleading but the drop path is correct. |
| 9 | R4-b1-03 | REJECT | Cold-path micro-opt — pending-neigh key Vec allocates only during rare unresolved-hop condition (doc says "tiny"). |
| 11 | R4B2-01 | REJECT (→#4421) | Single-packet transient, self-healing behind worker-local SessionTable + NAT re-learn/TCP retransmit; remedy is a 7-lock→1 consolidation with its own risk. Folds into modularity backlog #4421, not an independent correctness issue. |
| 15 | R5B2-IPMON-01 | REJECT | Marginal — the PreferredRoute mutation has no runtime effect (cfg discarded on error); availability claim unproven (no legacy-accepted value). Residual = nondeterministic error-message order (cosmetic). |
| 21 | R6B2-04 | REJECT | Test-only guardrail — no concrete current Go↔Rust wire mismatch; the DTO split it gates is already tracked (Fable-173 A7-F6 / #4421). |
| 24 | R7B2-HC-003 | ALREADY-FIXED | Concrete selector bugs fixed by #3696 (strict-parse) + #3709 (dup-selector last-win + comma/equals fail-closed guard, main.go:467); residual is a speculative protobuf-oneof refactor, wire limit handled fail-closed by design. |
| 29 | R10-B1-001 | REJECT | Dead-header cleanup, intentionally retained by #1476; headers are live-consumed (MAX_INTERFACES + parity tests) and compile to no object — no shipped code executes them. |
| 31 | R10-B1-004 | REJECT | Tooling modularity — xpf-deploy.py (1805 LOC) operator cold-path split; benefit is hypothetical, no current bug. |
| 32 | R10-B1-005 | REJECT | Test-tool modularize — cold-path-flooder (2170 LOC); the "dangling msg_name" is a refactor risk, current code correct. |
| 33 | R10-B1-006 | REJECT | Test split + self-test discovery gap (fairness suite); test-tooling only, no production impact. |
| 34 | R10-B1-007 | REJECT | Meta tooling — refactoring-heatmap gate; staleness already known (#1661 item 8 / PR #1671). |
| 37 | S1-RUST-RUNTIME-B2-03 | REJECT | Pure decomposition of `flush_session_deltas` (byte-for-byte behavior preserved); no correctness/perf/safety impact. |
| 41 | S2B3-NEIGH-04 | REJECT | Marginal — read-only `show arp`/`ipv6-neighbors` row-order nondeterminism + dup LinkByIndex; no state/forwarding/security impact. |
| 42 | S3B1-IPERF-03 | REJECT | Test-harness fail-open — real (`recent_interval_metric <=0.0`, success/0 on unparseable) but lives entirely in the HA *validation* harness, not the production dataplane. |
| 43 | S4LTB1-OWNER-03 | REJECT | Test-file relocation (cluster_test.go co-location) following closed #1541/PR #1575; no production impact. |
| 44 | R2-b2-06 | REJECT | Latent guardrail — audit itself: "no live omission found"; all current callers pass the recycle sink. Not a reachable current defect (hardening only). |
| 45 | R2-b2-07 | REJECT | Latent guardrail — audit itself: "no active reuse found"; all callers commit/release-then-drop. Not a reachable current defect (type-state hardening only). |
| 47 | S1-RUST-RUNTIME-B2-04 | REJECT | Bench-only + doc-nit — approved scope is only "correct the 96→496-byte stale comment + add a benchmark"; no production layout change, perf benefit unmeasured/speculative. |

## Gate notes
- **Hard cut applied at ~26:** the four latent/immaterial findings above (R2-b2-06/07 "no live omission/reuse
  found", R5B2-IPMON-01 no-runtime-effect determinism, S2B3-NEIGH-04 presentation ordering) fail the
  "material + reachable current defect" gate and were cut despite being genuine code smells.
- **Scope corrections carried into filed issues:** #4953 dropped the finding's deterministic-NAT sub-claim
  (the cited NAT comment concerns pool-utilization alarm, not the det-NAT block — legacy-accepted value unproven).
- This is a **refactor audit**, so the yield skews toward hot-path allocation / ownership / fail-open-reconcile
  findings that the codex-175 correctness cohort did not cover; the higher-than-typical genuine count
  (vs the ~10-20 heuristic) reflects audit type + the audit's own pre-dedup to 47 canonical findings, each
  re-verified here against origin/master and confirmed novel.

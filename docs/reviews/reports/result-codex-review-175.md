# Triage result — codex-review-175 (Paladin Full-Tree Defensive Review — Codex)

**Base commit:** `385f940b7` (BEHIND current master — base-lag noted). Triaged
against current `origin/master` (the fragments were verified across
`29a046ec5`..`90af98b9d` as master advanced during the run).

**Reviewer:** Codex (high-signal, ~90%). **Fork tell:** none — every cited
symbol verified present on master (0 confabulated).

## Consolidated bucket tally (authoritative)

- **146 non-duplicate findings → 69 new issues.**
- **GENUINE:** 129 findings → 69 issues (near-identical items grouped into cohorts)
- **ALREADY-FIXED:** 7
- **DELIBERATE:** 4
- **NOT-MATERIAL:** 7
- **CONFABULATED:** 0

Triaged in 3 parallel area slices:
- **A1-A5** — 18 issues
- **A6-A9** — 27 issues
- **A10** — 24 issues

---

## Area A1-A5 — Codex-175 triage (base 385f940b7 → current master 90af98b9d)

Buckets: **GENUINE/filed 18 · ALREADY-FIXED 4 · DELIBERATE 3 · NOT-MATERIAL 5 · CONFABULATED 0** (30 total).

### GENUINE → filed

- **C175-HC-004 (A3-b3) → #4862** — `pkg/config/parser.go:40-44` `Parse()` never asserts EOF; `parseStatements()` (line 145) breaks on top-level `TokenRBrace` exactly like EOF. A stray unmatched `}` returns a truncated tree with **zero** `ParseError`s; callers check only `len(errs)`, so all trailing config (security policies, default-policy) is silently dropped. parser.go unchanged since base. Fail-open config acceptance → labeled `bug`+`security`.

- **C175-HC-033 (A2-b1) → #4863** — `userspace-dp/src/nat/allocator.rs:291-323` `deterministic_indices_v6` checks only `src_word`/`base_word`+`host_count`, never `src_octets[..off] == host_base[..off]`. An out-of-prefix IPv6 source sharing the subscriber word (e.g. `2001:db9:0:5::` vs base `2001:db8::`, /32) is accepted into the in-prefix subscriber's block; `reverse_deterministic_v6` (334-370) reconstructs from `host_base` → lying reverse map. Bug in #4559's impl (not a dup). allocator.rs has no source-prefix fix since base.

- **C175-HC-006 (A4-b1) → #4864** — `pkg/configstore/db.go` `DeleteConfirm` = plain `os.Remove`, no `fsatomic.SyncDir`; `store_commit.go` `removeConfirmState` logs on failure. `WriteConfirm` IS durable but the delete is not directory-synced → after a crash the stale `confirm.json` replays and `store_persist.go` `recoverPendingConfirmLocked` reverts an already-confirmed config (HA re-divergence on demotion). Distinct from HC-005 (this is durable-delete, not failure-handling). Only unrelated commit `a63534951` touched these files since base.

- **C175-HC-003 (A3-b1) → #4865** — `pkg/appid/catalog.go:93-103` and `runtime.go:210-222` deref an `*Application` from a nil map value. `config.ResolveApplication` (`predefined.go:190`) returns `(nil,true)` for a present nil value, so `if !found {continue}` doesn't guard; `catalogProtocolNumber(app.Protocol)` and (after the nil-guarded `icmpTypeConstrained`) `matchTuple(...,app.Protocol,...)` panic. `#3494` test documents `"zz-nil-app": nil` as a tolerated shape. catalog.go/runtime.go unchanged since base. Control-plane panic on HA-synced/tolerant-loaded config.

- **C175-HC-039 (A3-b1) → #4866** — `pkg/cmdtree/tree.go:256,269,826,845,1016,1045,1059` iterate `cfg.RoutingInstances` / `cfg.Chassis.Cluster.RedundancyGroups` and deref `ri.Name` / `rg.ID` with no nil guard; #3494 documents nil entries as tolerated; existing cmdtree nil tests (#3476/#3493) cover only zone/policy. tree.go changed only via #4422 (unrelated). Completion/help panic (SSOT for local/remote/gRPC). Sibling of HC-003.

- **C175-HC-044 (A5-b1) → #4867** — `pkg/cluster/election.go:334-342` emits the `DualActiveWin` reaffirm via an inline `select{... default:}` that drops on a full `eventCh` AND skips `m.onEventDrop()` (which `manager.go` `sendEvent` calls → `triggerReconcile`). `daemon_ha.go:185` only then calls `scheduleDirectAnnounce`. On backpressure the post-split-brain GARP/NA is lost with no reconcile fallback → blackhole. election.go unchanged (merges only).

- **C175-HC-034 (A3-b4) → #4877** — `pkg/config/schema_validators.go` `ValidatePercent` uses `strconv.ParseFloat` + `<`/`>` only; `NaN` bypasses both. Wired to CoS `guarantee-rate` (`schema_cos.go`); compiler clamp `f<0`/`f>1` also bypassed → `NaN` stored → `process_control.go` `json.Marshal` fails at apply. CoS-specific validators already reject non-finite; the generic one is the hole.

- **C175-HC-035 (A3-b4) → #4878** — `schema_security.go:977-978` DPD `interval`/`threshold` are `args:1` with no validator (closed-world guards keywords, not the value on the same line); `compiler_ipsec.go:241-250` ignores `Atoi` errors → silent default; `ike.go`/`policy.go` overflow (`delay*threshold`) drops `dpd_timeout`. Config-fidelity (safe-default) gap.

- **C175-HC-036 (A3-b3) → #4879** — `schema_security.go:1194-1195` dynamic-address `update-interval`/`hold-interval` untyped; `compiler_services.go:716-726` ignores `Atoi` errors → runtime defaults (3600s / retain-forever). Stale-feed fidelity for allowlist feeds.

- **C175-HC-040 (A3-b4) → #4880** — packed hierarchical `node 0 priority 999;` bypasses `ValidateInteger(1,254)` (`schema_chassis.go`; contract-pin test `..._PackedOneLinerBypassesGate`); `compiler_system.go:1770-1782` stores it unchecked; no strict `NodePriorities` range validator exists (`compiler_validate_strict_chassis.go` checks count/ID only); `vrrp/instance.go` casts `uint8(priority)` → election(999) vs wire(231) split. Documented-but-unbackstopped dual-shape gap.

- **C175-HC-038 (A3-b2) → #4881** — `compiler_nat.go:1838-1846` OR-expands mixed scope kinds (`from zone`+`from interface`) via the #3096 Cartesian into separate rule-sets, contradicting the line 1042-1044 comment's "AND-ed fail-closed"; `compiler_prewalk.go:247` confirms the old scope-reject gate was removed; schema declares kinds as independent `multi:true`. Fail-open NAT-scope widening + false safety comment (esoteric trigger → Low).

- **C175-HC-030 (A1-b2) → #4882** — `userspace-dp/src/afxdp/bpf_map/metrics.rs:136,153-154` `core::ptr::read` (needs align 2) from `vec![0u8;..]` (align 1); `UserspaceSessionMapKey` is `repr(C)` with `u16` fields; crate already uses `read_unaligned` in `frame/inspect.rs`. Genuine UB, `debug-log`-gated + practically-aligned allocations → Low.

- **C175-MC-002 (A3-b1) → #4887** — `catalog.go:389-391` `catalogProtocolNumber` drops `ProtocolNumber`'s `ok`; fan-out (198-205) emits a `Protocol:0` row for a non-empty unrepresentable protocol; lenient load (`compiler_application_specs_test.go:454`) keeps bad protocols. False AppID label (protocol-0/HOPOPT) → log integrity, Low.

- **C175-MC-003 (A4-b1) → #4888** — `configstore/crypto.go` `unmarshalEnvelope` returns `(ok=false,err=nil)` for an envelope-shaped body with unknown `format`; `db.go:270-278` then decodes it as `ConfigTree` (unknown fields ignored) → empty tree, no error. Inner-envelope fail-closed gap; outer `#xpf-config-envelope` gate mitigates most cases (crypto.go's 3 post-base commits are HC-043/#4579/master-password, none address this). Low-Med.

- **C175-MC-007 (A1-b2) → #4889** — `neighbor_dispatch.rs:475-501` `learn_dynamic_neighbor` rejects only own-IP, missing the `neighbor_ip_is_learnable` (`frame/inspect.rs:964`) class check the ARP/NDP paths use → loopback/multicast/broadcast source IPs pollute `dynamic_neighbors`. Userspace-cache-only (no kernel-neighbor write) → Low defensive.

- **C175-MC-001 (A1-b4) → #4890** — `screen/scan.rs` `evict_stalest_in_zone` samples a fixed global prefix (`iter().take(EVICT_SCAN_LIMIT)`) where non-target-zone entries consume the budget; a saturated zone with no entry in the prefix skips a fresh scanner (`skipped_pressure`), evading scan detection — contradicting the module doc's "fresh real scanner always admissible." Residual of closed #2234 (distinct from least-suspicious-victim choice). Med-confidence, IDS-detection only → Low.

- **C175-MC-009 (A4-b1) → #4891** — `store_commit.go:93-128` stores commit `description` uncapped; `journal/journal.go` marshals the full entry (168-178) and `Tail` discards lines > `maxTailLineBytes` (16 MiB, line 391) → an oversized valid commit comment allocates proportional mem/disk then vanishes from bounded audit views; rotation checks old segment size only. Audit-integrity, Low.

- **C175-MC-010 (A5-b1) → #4892** — `cluster/sync_protocol.go` `putLeaseString` writes `uint16(len(s))` but appends full string → >64 KiB field silently misframes a lease record on the peer. Near-zero reachability (DHCP fields bounded, local-Kea-sourced) but genuine silent-misframe wire codec (should fail closed). Low defensive.

### ALREADY-FIXED

- **C175-HC-002 (A3-b3)** — address-set bracket-list members after first dropped. FIXED by **#4791**: `pkg/config/compiler_security_addressbook.go` `addressSetMemberValues` reads `member.Keys[1:]` AND children (comment lines 263-267 name the pre-#4791 `Keys[1]` bug). Base predates #4791.
- **C175-HC-041 (A3-b3)** — repeated hierarchical `address-set` blocks replace vs merge. FIXED by **#4706**: `parseAddressBookEntries` `case "address-set"` (compiler_security_addressbook.go:306-324) now `as := ab.AddressSets[name]` merge-by-name + `appendUniqueString`.
- **C175-HC-037 (A3-b2)** — inverted NAT dest-port range degrades silently. FIXED by commit **`8febce63b`** ("reject reversed NAT destination-port ranges"): `parseDNATPortList` now returns `reversed`, populates `Match.ReversedDestinationPortRanges` (compiler_nat.go:1774-1775,1986-1987), strict validator rejects.
- **C175-HC-043 (A4-b1)** — malformed AES-GCM nonce length panics. FIXED by **#4793** (commit `6eade5f9f`): `configstore/crypto.go:167-173` `if len(nonce) != gcm.NonceSize() { return ... }` before `gcm.Open`.

### DELIBERATE (documented tradeoff)

- **C175-HC-005 (A4-b1)** — `CommitConfirmed` returns success when `WriteConfirm` fails. `store_commit.go` `writeConfirmState` comment explicitly: "Best-effort: a failure is logged, not fatal — the in-memory timer still covers the no-crash case (the **#1799 degrade-not-fail** doctrine)." Documented design choice; won't file. (Its distinct sibling — durable-delete gap — IS filed as HC-006/#4864.)
- **C175-HC-042 (A4-b1)** — master-password doesn't encrypt rollback/rescue/archive. `store_commit.go:750-752` documents it: "Owner-only 0600 (**#4056**): the rollback slots (xpf.conf.N) hold the full committed config TEXT ... Format() does not [redact]"; `file_perms_4056_test.go` intentionally proves cleartext+0600. Rollback/rescue need restorable secrets → perms, not encryption, is the deliberate mitigation. Product-scope question, not a novel bug.
- **C175-HC-105 (A1-b3)** — WG data/cookie parsers accept non-canonical reserved bytes. `wg/framing.rs:79` comment: "We accept non-zero values here for interoperability robustness"; the finding itself concedes "This does not allow unauthenticated payload forgery" (reserved bytes are outside the AEAD AAD and mac1 covers them on handshake). Documented interop leniency, no security impact → not filed.

### NOT-MATERIAL

- **C175-HC-031 (A1-b1)** — bench "gates" (`tx_kick_latency.rs`, `session_table.rs`, `snat_allocator.rs`) print but don't fail CI. Test/CI-enforcement quality, no runtime bug; out of scope for a defensive correctness/security triage.
- **C175-HC-032 (A1-b1)** — `benches/snat_allocator.rs` models a pre-#2852 allocator vs the shipped lock-free one (`nat/allocator.rs` comment acknowledges the microbench cap model differs). Bench drift, not a production defect.
- **C175-HC-103 (A1-b2)** — `afxdp/gre.rs` per-packet `Vec` alloc on GRE encap/decap. Self-described "reported as concrete performance debt, not a correctness or memory-safety bug." Perf-debt, not a defensive-review bug.
- **C175-HC-104 (A1-b1)** — `benches/prefix_set_lookup.rs` gates IPv4 trie build only, not lookup/V6 (both the bench and `prefix_set.rs:27-32` doc the scope). Bench-coverage drift, no runtime failure.
- **C175-MC-008 (A2-b1)** — `nat/static_nat.rs:780-804` `external_ips[_scoped]` publishes only `block.external.base` (vs DNAT's `MAX_LOCAL_PREFIX_HOSTS` host expansion). The finding concedes routed traffic to non-base addresses still translates; `static_nat.rs` comment documents base-only publication to avoid unbounded blow-up. A proxy-ARP/local-delivery parity ENHANCEMENT for directly-connected small blocks, not a translation/security failure → not filed.

### CONFABULATED
None. Every cited symbol/file resolved on current master.
## Area A6-A9

Triage of codex-review-175 (base `385f940b7`) against current `origin/master` `90af98b9d`.
35 findings across A6 (dataplane Go manager), A7 (daemon/host integration), A8 (APIs), A9 (observability).

Buckets: **30 GENUINE** (filed as 27 new issues — 3 issue-pairs merged), **3 ALREADY-FIXED**, **2 NOT-MATERIAL**, 0 CONFABULATED.

---

### GENUINE — filed

**C175-HC-007 (A6, High) → #4894** — `pkg/dataplane/userspace/maps_sync.go` L696/L730/L1230/L1278 compute `idx = ifindex*bindingQueuesPerIface(16) + QueueID` and only guard `idx >= BindingArrayMaxEntries`; no `QueueID < 16` bound. Rust `helpers.rs replan_bindings_from_candidates` emits `queue_id in 0..queue_count` uncapped (`queue_count = min(rx)`). On a >16-RX-queue NIC, queue 16 on ifindex N aliases `(N+1)*16+0` → wrong XSK slot / cross-interface misdelivery / masked HA readiness. Latent on the 6-queue mlx5 test VFs; real on throughput NICs. Sev High (fail-open dataplane isolation, bounded by hardware queue count). Not a dup of the #814 ifindex cap.

**C175-HC-008 (A7, High/security) → #4895** — `reconcileSudoers` (`daemon_system.go:898`) runs unconditionally (`daemon_apply.go:1614-1621`), writes a grant for every `Class==super-user` user gating only on `Name != ""`/`!= "root"` (no account-existence gate); `writeSudoersGrant` (L943-945) formats the raw key into `%s ALL=(ALL) NOPASSWD: ALL\n`. `compiler_system.go:118-119` copies the keyed username verbatim; schema has no username validator; the lexer decodes quoted `\n`. Crafted username → injected extra sudoers directive that passes `visudo`. CWE-74, fail-open to root. Distinct from #3889/#1944/#4598.

**C175-HC-010 (A9, High) → #4896** — `netflow.go recordSize` (L230-238) pads each record to 4B; v4 field sum = 61 → padded 64, v6 = 109 → padded 112 (verified by summing `netflowTemplateFieldsV4/V6`); `encodeRecordV4/V6` return `startOff + recSize` (L427/L497), packing records at padded stride while the template advertises the unpadded width. Per RFC 3954 only the FlowSet gets terminal padding → every record after the first misdecodes on a multi-record close burst. IPFIX sibling uses exact lengths. Distinct from #2613/#3740/#2866.

**C175-HC-012 (A9, High/security) → #4897** — `v3.go:255` verifies auth only `if msgFlags&msgFlagAuth != 0` and decrypts only `if msgFlags&msgFlagPriv != 0`; no per-user minimum security level. An authPriv-configured user queried with flags=0 (noAuthNoPriv) is served plaintext. `snapshotV3User` only rejects unknown usernames. Distinct from #2681 (the inverse noAuthPriv case, fixed) and #2611 (context).

**C175-HC-009 + C175-HC-046 (A7, both High/Medium) → #4898 (merged)** — `ipsec/manager.go`: `clearConfig` (L162-169) does `_ = m.reload(); return nil` (swallows reload error on empty-config/last-VPN-delete branch, asymmetric with `applyConfig` which propagates per the #4433 test); and `Apply` (L104-122) calls `swapConnNames` (promotes `prevConnNames` before reload) then `terminateRemovedConns` unconditionally after `applyErr` (terminates removed SAs even on failed reload). Both are manager-internal reload-error/ordering bugs; combined into one issue (unified two-phase fix). Follow-up to #4433.

**C175-HC-045 (A7, Medium) → #4899** — `daemon_dhcp.go:123-137 reapplyIPsecForLeaseChange` calls `d.ipsec.Apply` and only `slog.Warn`s the error — no retry/dirty/health. Runtime DHCP-lease rebind bypasses the commit fail-closed contract; a reload failure leaves strongSwan on the stale `local_addrs` with no operator signal. Follow-up to #2884/#4433.

**C175-HC-047 (A7, Medium) → #4900** — `networkd.go:172-181` stale-file `os.Remove` failure is warn-only and not added to `writeErrs` (L225-231); if no other file changed, `Apply` returns nil. A stale `10-xpf-*.network` can resurrect removed addresses/VRF/bond/bridge/rename. Distinct from #2987 (write-failure) / #2988 (empty-set skip).

**C175-HC-048 (A7, Medium) → #4901** — `xfrm.go deleteLocked`, `bond.go clearLocked`, `tunnel.go clearLocked` log failed `LinkDel`, then drop the object from tracking and `return nil`. Orphaned link + lost ownership + success reported; violates the Apply-path retention invariant. Verified still present (bond/probe-pin got #6678/#4822 but the teardown paths did not).

**C175-HC-049 + C175-MC-011 (A7, Medium/Low) → #4902 (merged)** — unvalidated system string leaves rendered verbatim into root-owned host config: `renderChronySources` (`daemon_system.go:291-300`), `buildSSHDConfig` KexAlgorithms/Ciphers/MACs (L1204-1234), syslog file/user (L669-695), and DNS `Domains=`/`search` (`system/dns.go:56-61,118-123`). Schema types `name-server` but not these leaves; lexer decodes quoted `\n` → directive injection / reload failure. Same root/fix locus (validators + control-char reject), merged. CWE-74.

**C175-HC-050 (A7, Medium/security) → #4903** — `daemon_cluster_bind.go:60-66 hostIsLoopback("")` returns true; `SplitHostPort(":8080")` yields empty host, so `clampBindToLoopback` treats `:8080` as loopback and does not clamp. `xpfd --api-addr :8080` with no api-auth binds all interfaces unauthenticated (`0.0.0.0:8080` is correctly clamped). Distinct from #4047/F-155.

**C175-HC-051 (A8, Medium) → #4910** — `grpcapi/server.go:254-257,309-310` call `srv.GracefulStop()` with no timeout/`Stop()` fallback; `server_diag_monitor.go:416-465 MonitorInterface` streams forever watching only `stream.Context()`. A held stream blocks daemon shutdown/failover indefinitely.

**C175-HC-053 (A8, Medium) → #4911** — filtered `ClearSessions` (`server_sessions.go:977-1030`) and `cli_clear.go:191-238` append every matching forward/reverse/NAT key to slices before deleting; shim maps sized `userspaceShimMaxSessions=10_000_000` (`loader_userspace_shim.go:312-332`). A broad filtered clear on a large table → control-daemon OOM. Merged gRPC+CLI (same root; A10 component included).

**C175-HC-055 (A9, Medium) → #4912** — `rpm.go:747-754 probeHTTP` allocates a fresh `http.Transport` per probe, no `DisableKeepAlives`/`CloseIdleConnections`, `IdleConnTimeout==0`. A bodyless (204) response returns the conn to an unreferenced idle pool → fd/goroutine leak per attempt.

**C175-HC-056 (A9, Medium) → #4913** — `feeds.go:173` iterates `daCfg.FeedServers` (map, nondeterministic); workers keyed `m.feeds[fe.Name]=fs` (L~37). Two servers with the same feed name → later assignment overwrites, orphaning the first cancel; `StopAll` (L239-240) cancels only the survivor. Nondeterministic provider + goroutine leak until shutdown; validator does not reject cross-server name collisions.

**C175-HC-057 (A9, Medium) → #4914 (residual of #4796)** — #4796 fixed only the standard slog `policy_id`. Still broken: `formatBinaryRecord` (`ringbuf.go:1277-1310`, called L738/L783 with the close-zeroed `evt`) encodes `evt.PolicyID`(=0) and `evt.Action`(=0→deny); and the generic slog SESSION_CLOSE branch (L695) still emits `action=actionName(0)="deny"`. Binary consumers read policy 0 + deny; slog reads deny for normal closes.

**C175-HC-058 (A9, Medium) → #4915** — `ringbuf.go:621` sets `rec.SessionID = atomic.AddUint64(&er.sessionSeq,1)` per event; `eventbuf.go:61` surfaces it as "unique session identifier". Create/close get different IDs → cannot correlate; raw wire carries no session identity. Distinct from #3337 (which plumbed the field to APIs) and #3056/#3395 (policy_id).

**C175-HC-059 (A9, Medium) → #4916** — `agent.go:504-513 Stop` only sets `stopped` + closes conn; does not cancel the `<-ctx.Done()` watcher (L471-474, ctx stays live on day-2 disable), close/drain the trap queue, or wait for `trapWorker`. Leaks goroutines per enable/disable and can deliver queued traps to a removed target/community. Distinct from #3967 (reconcile).

**C175-HC-060 (A9, Medium) → #4917** — `agent.go:295-303 initEngine` appends the full OS hostname (6-byte prefix + hostname) with no cap; SnmpEngineID max is 32 octets, so a hostname >26 bytes → invalid EngineID and all SNMPv3 breaks (v2c unaffected), no diagnostic. Distinct from #2611/#2649/#2610.

**C175-HC-011 (A9, High→Medium residual of #2612) → #4918** — `agent.go handleGet` (L697-718) and `handleGetNext` (L722-743) end with `buildResponse` directly (no `trimToFit`) → oversized GET/GETNEXT responses; only `handleGetBulk` (L802) trims. Plus `trimToFit` is decrement-and-rebuild (O(n^2)) and GETBULK still materializes `len(oids)*maxRepetitions`. #2612 bounded GETBULK output only; residual scoped down to Medium.

**C175-MC-004 + C175-MC-005 (A7, Medium) → #4919 (merged)** — `policy_render.go:682` renders `bgp cluster-id %s` with no validator **and no `sanitizeFRRValue`** (unlike router-id's `validRouterID` guard L678) → reload-poison + newline injection; L1834 `set origin %s` is sanitized but not enum-validated → reload-poison on an invalid token (e.g. `igpp`). Schema leaves untyped. Merged (same FRR validation fix locus). cluster-id injection distinct from the #4482/#4498 set-clause belt.

**C175-MC-006 (A8, Medium) → #4920** — `api/sessions.go:344-368 peerSessionsRequest` forwards `limit` but not cursor-mode `page_size` as `PageSize`; a cursor-mode REST caller (`page_size=1000`, no limit) → peer request `Limit=0,PageSize=0` → gRPC defaults peer to 100 (`server_sessions.go:588`). Peer undercount. Distinct from #350 (gRPC-layer PageToken) / #3423.

**C175-HC-110 (A8, Low) → #4921** — `server_show_routes_text.go:191-210 showTestRouting` has no `seen` map; a repeated `dest=`/`instance=` silently last-wins, unlike `test-policy` (#3709 `server_show_firewall.go:226`). Diagnostic answers a different query than typed.

**C175-HC-111 (A9, Low) → #4922** — `feeds.go` `maxInvalidSample=5` bounds count but not bytes; `maxLineBytes=1<<20`, so up to ~5 MiB verbatim retained/copied/logged per degraded feed (L518). Bounded by the 32-MiB fetch cap.

**C175-HC-112 (A9, Low) → #4923** — `flowexport/manager.go:829` fallback `rec.Time.Add(-estimateSessionDuration(SessionPkts, proto))` overflows signed `time.Duration` above ~92.2B TCP pkts → negative duration → StartTime after EndTime; the real-created branch (L820-826) clamps, the fallback does not.

**C175-HC-113 (A9, Low) → #4924** — `agent.go:1236-1245 berEncodeTimeTicks` strips leading zeros but omits the high-bit leading-zero prepend that Counter32 (~L1221/L1343) does; at 0x80000000 hundredths (248.55 days) sysUpTime/traps encode non-canonical/negative.

**C175-HC-106 (A6, Low) → #4925** — `userspace/nat.go:50-68 resolveNATAddressNamePrefixes` uses the static (feed-unaware) `resolveUserspaceAddressBookEntry` for nested sets; an address-set with a feed-backed member resolves no feed prefixes (fail-closed: SNAT→raw token, DNAT→no row), diverging from the feed-aware policy path (#3294). Documented in-source as a tracked residual but with no dedicated issue → filed as an untracked vSRX/policy parity gap. Distinct from #3303 (direct feed) / #3418.

**C175-MC-012 (A8, Low) → #4926** — `security.go:419` parses `limit` via lenient `queryInt` (`api.go:146`, malformed/negative → default 50), while the same handler's `zone` filter fails closed with 400. Fail-open scoping inconsistency (limit is not an authz predicate).

---

### ALREADY-FIXED — not filed

**C175-HC-052 (A8, Medium)** — chunked DHCP identifier clear wiping all DUIDs: **fixed by #4794**. `api/dhcp.go:65-95` now gates on `if r.ContentLength != 0` (not `> 0`) and decodes chunked (`ContentLength == -1`) bodies, tolerating `io.EOF`. Proving line: `dhcp.go` `// #4794: gate on ContentLength != 0`.

**C175-HC-054 (A9, Medium)** — syslog client `Close` non-terminal / post-close reconnect: **fixed by #4806**. `syslog.go` added a mu-guarded `closed` flag; `Close` sets `closed=true` and nils `conn`; `Send`/`SendBinary` return `errSyslogClientClosed` before touching `conn`/reconnect. (The secondary `WithAttrs` derived-handler stale-registry note is a minor design nuance, not a distinct filed bug.)

**C175-HC-109 (A7, Low)** — RPM probe-pin band `clear` dropping errors and always returning nil: **fixed by #4822**. `routing/probe_pin.go:257-291 clear()` now aggregates `RuleList`/`RouteListFiltered` dump failures via `errors.Join` and returns them (per-item `RuleDel`/`RouteDel` stay Debug best-effort by documented design, with the next band clear as backstop).

---

### NOT-MATERIAL — not filed

**C175-HC-107 (A6+A8, Low)** — negative userspace queue/binding/inject IDs wrap to uint32 at the Go boundary (`control.go:33/41/48/56` `strconv.Atoi`→`uint32(...)`; same in `server_diag_system_action.go`). Disproving mechanism: the Rust helper handlers (`server/handlers/queue.rs`) look up queues/bindings by u32 and reject unknown IDs — a `-1`→4294967295 input **fails closed today** with no wrong output/state mutation. The review itself rates it Low precisely because it fails closed; it is defensive hygiene, not a current defect (latent only if the helper ever switches to index math). Not filed.

**C175-HC-108 (A7, Low)** — `session_sync_readiness_test.go:148-190 TestReconnectAfterBulkPreservesPrimedState` is named as testing warm-reconnect but only exercises cold-start/no-panic (cannot set `BulkEverCompleted` from the daemon package). This is a **test-coverage gap, not a production defect** — the finding explicitly states "the gap survives as daemon-layer coverage, not as a production defect claim" (`daemon_ha_sync.go:54-64,106-114` behavior is correct; the cluster-level `bulkEverCompleted` persistence is separately tested). No runtime wrong-output to trace. Not filed as a bug.
# Area A10 triage — Codex review 175

Base review commit `385f940b7` (behind master). Triaged against current master
`29a046ec5` (fetched/re-checked mid-run; advanced 90af98b9d -> 29a046ec5). Scope: A10
findings = Services, policy simulator, CLI/show, build/deploy tooling. 81 high-confidence
(C175-HC) + 1 medium-confidence (C175-MC-013) findings tagged to A10-b1..b4.

## Bucket summary
- CONFABULATED: 0 (every cited symbol was present on current master).
- ALREADY-FIXED: 0 (base lag did not fix any A10 finding; verified each cited region).
- DELIBERATE / NOT-MATERIAL (not filed): 1 — HC-066.
- GENUINE + material/novel (filed): 81, consolidated into 24 new issues (grouped tight
  cohorts per triage guidance; each root traced individually below).

Every cited symbol verified live via `git show origin/master:<path>` + grep. Dedup:
`gh issue list --state all` on keywords for each individual/security finding — no existing
issue matched; did not touch #4839/4840/4845/4846.

## New issues filed
- #4857 security — HC-020 DHCP ClearDUID path traversal / arbitrary root unlink
- #4858 security — HC-022 `request system zeroize` leaves `.configdb` + master.key
- #4859 security — HC-014 operator RBAC gap (forwarding/queue/binding/ISSU disarm)
- #4860 security — HC-099 view-only `show log` reads arbitrary /var/log files
- #4861 security — HC-074 DDNS credentialed HTTP plaintext + redirect downgrade
- #4868 — HC-024+HC-115+HC-067 CLI commit/rollback grammar + int32 narrowing fail-open
- #4869 — HC-015 `xpfd upgrade` positional arg -> uncoordinated standalone cut
- #4870 — HC-016+HC-071 dhcpserver apply/lifecycle fail-open
- #4871 — HC-021 HA DHCP lease lifetimes stop aging on standby -> dup allocation
- #4872 — HC-018+HC-100+HC-068+HC-131 pkg/upgrade kernel-roll/self-recover fail-open cohort
- #4873 — HC-019+HC-076+HC-027 DDNS durability/ownership cohort
- #4874 — HC-078+HC-079 DHCP client expired-binding retention + zero-lifetime PD
- #4875 — HC-098 fwdstatus false-Online (no heartbeat / future ts)
- #4876 — HC-062 publish-generation destructive GC on unreadable journal
- #4883 — HC-061+HC-064+HC-065+HC-075+HC-089 CLI command fail-open/footgun cohort
- #4884 — HC-086+HC-087+HC-088 interface/device-map identity cohort
- #4885 — HC-102 zone-detail wildcard omission/misorder
- #4886 — HC-053+HC-093+HC-094 control-plane unbounded-memory cohort
- #4904 security — HC-013+HC-028+HC-023 supply-chain signing/publication cohort
- #4905 — HC-017+HC-097+HC-096+HC-085 deploy/image tooling filesystem-safety cohort
- #4906 — HC-001+HC-025+HC-069+HC-081+HC-090+HC-091+HC-095+HC-101 test/xsk-repro cohort
- #4907 — HC-026+HC-029+HC-070+HC-072+HC-083+HC-084+HC-092+HC-128+HC-130+HC-132 perf-analysis cohort
- #4908 — HC-063+HC-073+HC-077+HC-080+HC-082+HC-116+HC-121+HC-122+HC-125+HC-126+HC-129 CLI display cohort
- #4909 — HC-114+HC-117+HC-118+HC-119+HC-120+HC-123+HC-124+HC-127+HC-133+MC-013 low control-plane correctness cohort

## Per-finding disposition

### High / Critical
- HC-001 (Crit) GENUINE -> #4906. `test/xsk-repro/libbpf_xsk_test.c:232` unchecked `fork()`;
  `:273` unconditional `kill(child,9)`. `fork()==-1` -> `kill(-1,SIGKILL)` signals every
  process root may signal. Test-tooling but root-run against live iface -> can kill daemon/
  host. Filed in xsk-repro cohort (grouped, not standalone Critical, because test-only).
- HC-013 (High) GENUINE -> #4904. `scripts/image/bake.py:470` `--skip-validate` returns then
  `finalize_artifacts:526` signs; publish sees a valid-looking signed set. Supply-chain
  fail-open; build-time only.
- HC-014 (High) GENUINE -> #4859. `pkg/cli/permissions.go:175` gates only system reboot/halt/
  power-off/zeroize + chassis failover; `cli_request_chassis.go:180-206` reaches
  `SetForwardingArmed/SetQueueState`/binding teardown under PermControl (operator has it).
  Security/availability; verified handler + LoginClassPermissions on master.
- HC-015 (High) GENUINE -> #4869. `cmd/xpfd/upgrade.go` no `fs.NArg()` check; `upgrade rolling`
  positional leaves `*rolling=false` -> `r.Run` standalone cut on clustered node.
- HC-016 (High) GENUINE -> #4870. `pkg/dhcpserver/dhcpserver.go:60` `out,_ := cmd.Output()`
  discards error; `ApplyClusterCommit` -> `apply(...,false)` -> query failure skips restart,
  gen advances, commit returns nil. Fail-open.
- HC-017 (High) GENUINE -> #4905. `scripts/deploy/xpf-deploy.py:1256-1264` empty `_running_kernel`
  (wrapper `:1086` discards exit status) sets `rebooted=True`; `finally` skips rejoin ->
  node stranded ForceSecondary. Deploy orchestration; observability fail-open.
- HC-018 (High) GENUINE -> #4872. `pkg/upgrade/kernel_run.go:359-363` on `BootCurrent()` error
  runs `cleanupAlreadyOnKnownGood`->`PruneInactiveSlot:501` before checking `RunningKernel`
  (:377) -> deletes running candidate's packages/modules/boot files. Destructive fail-open.
- HC-019 (High) GENUINE -> #4873. `pkg/ddns/manager.go:320` + `state.go:366` quarantine renames
  bad file, in-memory `degraded` only; `state.go:326` next boot returns empty store, no
  restart scan for `.corrupt-*` (grep confirmed none). Fail-open across restart.
- HC-020 (High) GENUINE -> #4857. `pkg/dhcp/dhcp.go:613` `duidPath` joins raw ifaceName;
  `:527` `os.Remove`; `pkg/api/dhcp.go:95` forwards `req.Interface` unvalidated (no
  net.InterfaceByName / containment on this path). `../../../etc/passwd` -> root unlink.
  Security; loopback-API bounded.
- HC-021 (High) GENUINE -> #4871. `pkg/dhcpserver/lease_sync.go:253-262` computes Remaining
  once, no sample epoch; `:525-527` re-anchors + floors 0->1; `pkg/cluster/sync.go`
  PeerDHCPLeases store value copy, no receipt time. Stale-partition takeover revives leases.
- HC-022 (High) GENUINE -> #4858. `pkg/cli/cli_request_system.go:57` zeroize loop removes only
  `.conf`/`rollback*`; no `.configdb`/`.config.journal` removal (grep confirmed);
  `configstore.New`/`Load` reload from `.configdb`. Security/data-remanence.
- HC-023 (High) GENUINE -> #4904. `scripts/dist/publish.py:760` gates mutable `dist`; `:695`
  dispatch hands same path to backend, no snapshot -> post-gate replacement uploaded. TOCTOU.
- HC-024 (High) GENUINE -> #4868. `cmd/cli/main.go:214` handleCommit: unknown modifier falls to
  permanent `Commit`; `strconv.Atoi`+`int32(v)` narrows `4294967297`->1. Verified full body.
- HC-025 (High) GENUINE -> #4906. `test/xsk-repro/main.rs:250` + `libbpf_xsk_test.c:48` fixed
  `/tmp/xdp_pass_redirect.o` write/load; symlink clobber + no inode check. Test-tooling.
- HC-026 (High) GENUINE -> #4907. `test/incus/step2-sched-switch-reduce.py:417` closes off-CPU
  interval on `sched_wakeup`; no `next_pid` parse -> involuntary preemption unmeasurable.
  Evidence-integrity, test-only.
- HC-027 (High) GENUINE -> #4873. `pkg/ddns/manager.go:620-634` withdraw guard substitutes single
  IPv4-first `m.updater` for either family -> AAAA delete sent to v4 provider. Cross-family.
- HC-028 (High) GENUINE -> #4904. `scripts/image/bake.py:208-224` image + SHA256SUMS from same
  base_url, no signed checksum/pinned digest; XPF then signs. Supply-chain provenance.
- HC-029 (High) GENUINE -> #4907. `test/incus/mouse_latency_aggregate.py:388` `return 0 if verdict
  in ("PASS","FAIL")` -> FAIL is green. Test-gate false-pass.

### Medium
- HC-053 GENUINE -> #4886. `pkg/grpcapi/server_sessions.go:975+` / `pkg/cli/cli_clear.go:191+`
  filtered clear snapshots every matching key before delete; maps up to 10M entries -> OOM.
  (A8-b2+A10-b2 merged finding; filed once under A10 memory cohort covering both surfaces.)
- HC-061 GENUINE -> #4883. `pkg/cli/monitor_traffic.go:62/76/108` empty/unknown `matching` ->
  unfiltered tcpdump. Confidentiality footgun.
- HC-062 GENUINE -> #4876. `cmd/xpfd/publish_generation.go:71-88` journal read error leaves
  `protected` empty, GC runs anyway (documented "best-effort", but crashed-cut source can be
  GC'd -> unrecoverable). Fail-open despite the comment's rationale.
- HC-063 GENUINE -> #4908. `pkg/cli/cli_show_security_log.go:180/196` cumulative screen drops
  labeled "currently active". Display-misleading.
- HC-064 GENUINE -> #4883. `pkg/cli/monitor.go` writeLine error goroutine returns without
  clearing active/cancel/sub -> permanently reported Active. Verified region.
- HC-065 GENUINE -> #4883. `cmd/cli/request.go` missing node value still sends `cluster-failover:1`
  -> untargeted ManualFailover.
- HC-066 DELIBERATE (NOT FILED). `pkg/dhcpserver/ddns_leases.go:127` returns `nil,nil` for a
  MISSING memfile as an INTENTIONAL trusted-empty, documented at lines 127-160 ("A genuinely
  MISSING file ... is a legitimate trusted-empty", #1387 + Codex r4). The team hardened
  headerless/mangled-header cases to fail-safe but deliberately kept ENOENT=empty. The
  reviewer's mount-loss concern is arguable but contradicts an explicit reviewed design
  decision; not filed as a new bug.
- HC-067 GENUINE -> #4868. `cmd/cli/shared.go:438` `int` `4294967296`->`int32(0)`; server
  treats rollback 0 as reset-to-active -> discards candidate. Novel #3447 residual.
- HC-068 GENUINE -> #4872. `pkg/upgrade/kernel_selfrecover.go:151/159` JSON `{}` -> NodeID=0/
  expired -> ResetFailover on node 0 breaks a maintenance drain.
- HC-069 GENUINE -> #4906. `test/xsk-repro/libbpf_xsk_test.c:177` / `main.rs:180` recycle frames
  without preserving received UMEM addrs (RX vs comp ring). Test-tooling.
- HC-070 GENUINE -> #4907. `step2-sched-switch-reduce.py:492` empty perf -> 12 zero blocks;
  classify -> definitive OUT, exit 0. Test evidence-integrity.
- HC-071 GENUINE -> #4870. `pkg/dhcpserver/dhcpserver.go:296/365/374` async apply drops transient
  failures permanently, no convergence retry. Fail-open.
- HC-072 GENUINE -> #4907. `test/incus/cold-path-flooder/src/main.rs:9/1101` 131,072-tuple space
  collides -> warm hits measured as install cost. Test-tooling.
- HC-073 GENUINE -> #4908. `pkg/cli/cli_show_flow.go:505/719` peer summary unfiltered; filtered
  detail prints `Total sessions: -1`. Display.
- HC-074 GENUINE -> #4861. `pkg/ddns/backend_{dyndns2,cloudflare,http}.go` accept plaintext
  http:// + follow redirect downgrade -> credential exposure. Security.
- HC-075 GENUINE -> #4883. `cmd/cli/main.go:391` readline interrupt/read error -> partial
  `load ... terminal` applied.
- HC-076 GENUINE -> #4873. `pkg/ddns/state.go:395` + `fsatomic.go:150` plain MkdirAll parent, no
  fsync -> write-ahead state can vanish on power loss during first dir creation.
- HC-077 GENUINE -> #4908. `cmd/cli/show_nat.go:207` DNAT joins by translated IP not pool name
  -> named-pool hits show zero. Display/counter.
- HC-078 GENUINE -> #4874. `pkg/dhcp/dhcp.go:825/834/1246` expired v4 addr/PD not removed after
  T2 failure before reacquire -> duplicate addr/stale route.
- HC-079 GENUINE -> #4874. `pkg/dhcp/dhcp.go:1606/1615` zero-lifetime IA_PD stored;
  `ra/sender.go:747` defaults omitted lifetimes to 30d/7d -> re-advertises reclaimed prefix.
- HC-080 GENUINE -> #4908. `pkg/cli/show_services_dhcp.go:265` prints HWAddress under DUID header.
- HC-081 GENUINE -> #4906. `test/xsk-repro/libbpf_xsk_test.c:243/273` uninitialized rx1/rx2 on
  early failure -> can return PASS.
- HC-082 GENUINE -> #4908. `pkg/cli/cli_show_flow.go:213` all sessions labeled from RG0 not owning
  RG. Display; corrupts failover diagnosis.
- HC-083 GENUINE -> #4907. `mouse_latency_orchestrate.py:630/642` `|| true` swallows failed RG
  polls -> failover-in-gap passes stable. Test.
- HC-084 GENUINE -> #4907. `fairness_multi_sample.py:180/353` accepts rc=1 + PASS JSON. Test.
- HC-085 GENUINE -> #4905. `scripts/image/validate.py:193/229` deletes fixed Incus alias/instances
  with no lock/ownership -> destroys unrelated VMs.
- HC-086 GENUINE -> #4884. `pkg/cli/session_filter.go:317/200` one-interface-per-zone map ->
  session filter/clear targets wrong interface.
- HC-087 GENUINE -> #4884. `pkg/cli/cli_show_interfaces*.go` authored/logical/kernel name mixing
  -> hides devices, fabricates VLAN addrs.
- HC-088 GENUINE -> #4884. `pkg/devicemap/devicemap.go:20/270` non-PCI MAC-only NIC skipped before
  netlink MAC read -> stranded interface.
- HC-089 GENUINE -> #4883. `cmd/cli/clear.go:239` malformed interface DUID clear -> empty request
  -> ClearAllDUIDs.
- HC-090 GENUINE -> #4906. `test/xsk-repro/libbpf_xsk_test.c:254`/`main.rs:63` rebind proceeds even
  if link cycle failed. Test.
- HC-091 GENUINE -> #4906. `test/xsk-repro/main.rs:195/122` munmap UMEM while owners alive. Test.
- HC-092 GENUINE -> #4907. `step2-sched-switch-classify.py:39/285` duty /60 while blocks span
  [1,30]s. Test.
- HC-093 GENUINE -> #4886. `pkg/cli/cli_dispatch.go:53/62/127/135` show re-buffers full output +
  nests invisible pager. Memory/UX.
- HC-094 GENUINE -> #4886. `pkg/dhcpserver/ddns_leases.go:136` ReadAll entire Kea history per
  reconcile -> O(history) mem/latency.
- HC-095 GENUINE -> #4906. `libbpf_xsk_shared_test.c:143/187` secondary socket never polled; PASS
  on owner rx only. Test.
- HC-096 GENUINE -> #4905. `scripts/image/make_config_drive.py:68/77` secret ISO world-readable
  (deploy path already 0600). Security-ish tooling.
- HC-097 GENUINE -> #4905. `scripts/deploy/xpf-deploy.py:213/559` name/image `..` escapes managed
  dirs; sudo write/delete sinks. Reproduced containment failure.
- HC-098 GENUINE -> #4875. `pkg/fwdstatus/builder.go` `allHeartbeatsFresh` empty-slice=true +
  future-ts=true -> default Online. Verified switch has no empty-case branch.
- HC-099 GENUINE -> #4860. `pkg/cli/cli_show_system.go` `show log <name>` tails any /var/log child
  (Base only, no allowlist) under PermView. Security. Verified region + permissions.go.
- HC-100 GENUINE -> #4872. `pkg/upgrade/kernel_linux.go:314/484` Arm/DisarmWatchdog errors
  swallowed even under StrictWatchdog.
- HC-101 GENUINE -> #4906. `test/xsk-repro/main.rs:285/77` zero attach flags replace+detach live
  XDP program. Test but touches live iface.
- HC-102 GENUINE -> #4885. `pkg/policymatch/zone_detail_summary.go:107` + `policymatch.go:883`
  zone detail omits wildcard zone-pair/any->any + wrong sub-tier order vs runtime. Policy
  simulator fidelity.

### Low
- HC-114 GENUINE -> #4909. `pkg/dhcp/dhcp.go:540/548` ClearAllDUIDs clears only in-process, ignores
  delete errors.
- HC-115 GENUINE -> #4868. `pkg/cli/cli_config.go:213` + `store_commit.go:264` local commit
  confirmed defaults malformed durations + overflow.
- HC-116 GENUINE -> #4908. `pkg/cli/cli_show_cluster.go:223` cluster status drops VRRP rows for
  logical zone refs.
- HC-117 GENUINE -> #4909. `pkg/ddns/backend_cloudflare.go:177/186` single unpaginated record
  lookup.
- HC-118 GENUINE -> #4909. `pkg/cli/peer.go:49` IPv6 peer endpoint missing brackets.
- HC-119 GENUINE -> #4909. `pkg/natpoolalarm/natpoolalarm.go:171/178` concurrent Stop double-close
  panic.
- HC-120 GENUINE -> #4909. `pkg/ddns/state.go:350` + `manager.go:1166` validates JSON not record
  semantics; drops ownership without wire delete.
- HC-121 GENUINE -> #4908. `pkg/cli/show_services_dhcp.go:235` lease read failure -> clean empty
  table.
- HC-122 GENUINE -> #4908. `pkg/dhcprelay/relay.go:1161` counts relayed even when all sends fail.
- HC-123 GENUINE -> #4909. `pkg/dhcp/dhcp.go:598` DUID-LLT generation continues after persist
  failure -> ephemeral identity.
- HC-124 GENUINE -> #4909. `pkg/fwdstatus/builder.go:230` + `sampler.go:212` tick*1e9 overflow
  before divide (~33d/64 cores).
- HC-125 GENUINE -> #4908. `pkg/lldp/lldp.go:512/593` TTL=0 shutdown frames learned as neighbors.
- HC-126 GENUINE -> #4908. `cmd/cli/show_security.go:28` + `cli_show_security_dispatch.go:80` loose
  inventory parser drops malformed zone selectors (local+remote merged).
- HC-127 GENUINE -> #4909. `pkg/natshow/persistent.go:15` + `persistent_nat.go:125/171` `All`
  returns mutable pointers -> show/refresh data race on LastSeen.
- HC-128 GENUINE -> #4907. `step1-rate-spread-analysis.py:54/131` threshold from partial cells/
  streams. Test.
- HC-129 GENUINE -> #4908. `pkg/cli/cli_show_routing.go:1029` next-table static route counted but
  no row emitted.
- HC-130 GENUINE -> #4907. `step1-rss-multinomial.py:71` retains every trial (~GB at 10M). Test.
- HC-131 GENUINE -> #4872. `pkg/upgrade/kernel_selfrecover.go:194-219` observation errors don't
  reset drainedSince -> premature grace expiry.
- HC-132 GENUINE -> #4907. `step1-histogram-classify.py:484/535` skips failed/missing cells, exits
  0. Test.
- HC-133 GENUINE -> #4909. `cmd/cli/main.go:40` GetStatus before dispatch -> offline WG keygen
  unreachable when xpfd down.

### Medium-confidence (section 7)
- MC-013 (Low) GENUINE -> #4909. `cmd/xpfd/main.go:172` check-config Stat-then-ReadFile TOCTOU;
  bounded by normally-read-only config drive. Grouped in low cohort.

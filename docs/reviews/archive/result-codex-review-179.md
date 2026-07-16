# Triage Ledger: codex-review-179

Base (review): 9bfd48226 | Verified against: origin/master
Started appending per-finding verdicts below.


## PASS: High-severity (44 findings) — triage against origin/master 92bc6186e

- C179-004 [A1-C004] Runtime reset strands legacy shared CoS credits for non-exact queues — REJECTED-duplicate #5156. token_bucket.rs:430 filter `queue.config.exact && queue.hot.tokens>0` confirmed on origin/master; #5156 explicitly covers "teardown (release filter is exact-only)". Same root.
- C179-008 [A1-C008] TCP segmentation promotes bytes beyond IP-declared datagram — REJECTED-duplicate #5141. tcp_segmentation.rs:70 `payload=&frame[l3..]`, no total_len clamp; #5141 verbatim ("no total_len clamp").
- C179-015 [A1-C015] Deferred/disarmed changed-plan snapshots accepted without full forwarding validation — REJECTED-duplicate #5171. snapshot.rs:200 defer_workers branch skips reconcile_status_bindings; #5171 same locus (snapshot.rs:182-236), same fix.
- C179-028 [A2-C001] NPTv6 drops rule-set scope / globally applies / rejects multi-scope — REJECTED-duplicate #5176. All three sub-parts covered by #5176 (from_zone drop + translate-from-every-zone + global overlap blocks split-horizon).
- C179-029 [A2-C002] HA import does not reserve address-only source-NAT reverse identity — REJECTED-duplicate #5338. Same standby address-only reservation gap.
- C179-102 [A7-C013] Bond partial member failure recorded as completed signature — REJECTED-duplicate #5261. adopt path tracks full desired bondSig despite partial members.
- C179-116 [A8-C012] gRPC zeroize ignores daemon's active custom config path — REJECTED-duplicate #5280. server_diag_zeroize.go configured -config root not wiped.
- C179-005 [A1-C005] Reconcile acks worker/helper spawn failure with phantom lifecycle state — REJECTED-duplicate #4952 (OPEN). bringup.rs Err arm removes only worker_panics, leaves live/identity (lines 65/73) + aux .ok(); #4952 covers exactly the post-teardown spawn-failure-swallowed → Ok reconcile → persisted snapshot at same bringup.rs locus.
- C179-007 [A1-C007] Non-transactional in-place descriptor rewrite corrupts fallback frame — FILED #5466. rewrite_prepare_eth_from_parts (frame/mod.rs:520) writes eth + copy_within memmove BEFORE the fragment/port None gates in apply_rewrite_descriptor (rewrite/mod.rs:53); .or_else generic fallback (flow_cache_hit.rs:411) reprocesses mutated frame. DRIVEABLE-dataplane.
- C179-008 [A1-C008] TCP segmentation beyond IP-declared datagram — REJECTED-duplicate #5141.
- C179-011 [A1-C011] Flowless TX bypasses every output filter — FILED #5467. cos_classify.rs:404 flowless else-branch returns drop:false/reject:false before output-filter eval. DRIVEABLE-dataplane.
- C179-012 [A1-C012] Lossless HA retry stalls worker past heartbeat — FILED #5468. LOSSLESS_QUEUE_TIMEOUT=5s == HEARTBEAT_STALE_AFTER=5s; push_delta_lossless retry-loop on worker (flush_session_deltas). DRIVEABLE-dataplane.
- C179-015 [A1-C015] Deferred changed-plan snapshot no full build — REJECTED-duplicate #5171.
- C179-016 [A1-C016] write_state holds ServerState lock across serialize+fsync — FILED #5469 (perf). helpers.rs:1283. DRIVEABLE-dataplane.
- C179-027 [A10-C007] Non-positive HA roll lease TTL immediately reclaimable — FILED #5470. xpf-deploy.py --lease-ttl unconstrained type=int; 0/neg → lease expires now → two orchestrators drain both nodes. DRIVEABLE-NOW (deploy script).
- C179-035 [A3-C004] MaxInt singleton member-range wraps induction var — REJECTED-already-fixed (#5373). origin/master iterates `for k:=0;k<=n;k++` on bounded count; comment cites the #5373 infinite-loop fix.
- C179-036 [A3-C005] Literal DDNS URL userinfo bypasses plaintext credential gate — FILED #5471. compiler_ddns_tls.go generic case checks only typed/%u/%p, misses literal user:pass@ → cleartext creds. DRIVEABLE-NOW. Distinct from #5458 (redaction).
- C179-039 [A3-C009] BGP neighbor policy override aliases group slice — REJECTED-already-fixed (#5277). compiler_protocols.go sets `neighbor.Export=nil` before append on first override; no shared-backing mutation.
- C179-040 [A3-C010] Static-route reject accepted then erased — REJECTED-already-fixed (#5298). StaticRoute.Reject field exists (types_routing.go:234), compiler sets it, FRR renders it (README #5298).
- C179-041 [A3-C011] Duplicate SNMP community erases clients allowlist — FILED #5472. compiler_system.go:1284 overwrites Communities[name] with no merge/dup-guard → empty-clients block → AllowsSource allow-all. DRIVEABLE-NOW.
- C179-052 [A4-C001] Confirm resolution deletes recovery intent after failed writeActive — FILED #5473. store_commit.go removeConfirmState() unconditional after possibly-failed writeActive → crash loses rollback target. DRIVEABLE-NOW.
- C179-054 [A4-C003] JSON null active body decodes as empty config — FILED #5474. db.go:293 json.Unmarshal("null") → zero ConfigTree, no error → boots policy-absent. DRIVEABLE-NOW.
- C179-055 [A4-C004] Zeroize omits fsatomic temp remnants — FILED #5475 (narrowed). archive omission already fixed by #5186; residual .<base>.tmp-* top-level sweep gap is genuine. DRIVEABLE-NOW.
- C179-062 [A5-C001] Heartbeat anti-replay accepts session rollback (A→B→A) — FILED #5477 (security). heartbeat.go:492 single-session watermark, no retired-set/epoch. DRIVEABLE-NOW (Go; lab test-failover).
- C179-063 [A5-C002] Missing local interface monitor retains healthy weight — FILED #5478. monitor.go:292 continue without SetMonitorWeight. DRIVEABLE-NOW.
- C179-066 [A5-C005] Failed peer failover has no remote abort — FILED #5479. failover.go:339 abort restores only local; no abort sync msg. DRIVEABLE-NOW.
- C179-067 [A5-C006] Event-stream bulk markers overtake queued sessions / empty authoritative set — REJECTED-duplicate #5085. #5085 fix-direction covers both empty-marker reconcile skip AND on-stream ordering barrier.
- C179-068 [A5-C007] Survivor does not re-prime rebooted peer — FILED #5480. sync_conn.go:538 sticky coldStart, no peer-incarnation. DRIVEABLE-NOW.
- C179-071 [A5-C010] VRRP accepts failed required IPv6 advert socket as ready — FILED #5481. instance.go:437 warn+return nil; RGVRRPReady map-presence. DRIVEABLE-NOW.
- C179-072 [A5-C011] VRRP emits role without verified VIP ownership — FILED #5482. becomeMaster addVIPs void, errors swallowed. DRIVEABLE-NOW.
- C179-078 [A6-C001] Malformed session frame cumulatively ACKed away — FILED #5483 (security). eventstream.go:396 decode-fail continue, not a sync break; telemetry advances watermark. DRIVEABLE-NOW (Go; lab HA verify).
- C179-079 [A6-C002] Shim ABI preflight omits shared/replacement maps — FILED #5484. loader_userspace_shim.go:404 inventory omits sessions_v6/dnat_table_v6/HA maps. DRIVEABLE-NOW (Go; upgrade lab verify).
- C179-082 [A6-C005] XDP attach/detach before apply_snapshot, no rollback — FILED #5485. manager_compile.go:184/209. DRIVEABLE-NOW (Go; lab verify).
- C179-083 [A6-C006] Void ctrl-disable swallows errors before teardown — FILED #5486. process_linkcycle.go:14. DRIVEABLE-NOW (Go; lab verify).
- C179-084 [A6-C007] Standalone HA-clear failure no retry/debt — FILED #5487. manager_compile.go:360. DRIVEABLE-NOW (Go; lab verify).
- C179-086 [A6-C009] Invalid static-NAT host ports widen to whole-address — REJECTED-duplicate #5101. Same clampPort→0→whole-address (nat_static.go + static_nat.rs:422).
- C179-087 [A6-C010] Same-version old helper narrows multi-zone global deny — FILED #5488 (security). policies_lower.go:208 additive plural fields, version still 3. DRIVEABLE-NOW.
- C179-088 [A6-C011] Exact-unit host-inbound merges cross-zone (no owner guard) — FILED #5489 (security). zones_override.go:133. DRIVEABLE-NOW.
- C179-090 [A7-C001] Tagged RETH services resolve unit suffix not vlan-id netdev — REJECTED-duplicate #5107. Same ResolveReth-vs-ResolveKernelIfName + Units[vlan] root (broader call-site scope noted; fix = ResolveKernelIfName, same as #5107).
- C179-091 [A7-C002] Device-map preflight fails open on enum error — FILED #5490. device_map.go:473 return nil skips strand check. DRIVEABLE-NOW.
- C179-095 [A7-C006] Passwd read error abandons removed-user revocation — FILED #5493 (security). login_password.go:296 removes marker on !uidOK (passwd read err = false); sibling shadow path fail-closes. DRIVEABLE-NOW.
- C179-096 [A7-C007] Day-2 HA changes leave stale strict VIP ownership — REJECTED-false-positive. strictVIPOwnershipByDefault = (EffectiveType != userspace); dataplane is userspace-only (#1373/#1525 ebpf/dpdk hard-rejected at commit), so it is ALWAYS false → target==default==false, day-2 reconcile gap is inert (dual-ownership/blackhole impacts both require strict to vary). Distinct from #3917 (fence reads current config, still merged/present).
- C179-100 [A7-C011] Unrenderable VPN retains established IPsec SAs — FILED #5494 (security; design-tension noted). ipsec/manager.go:218 name-keyed diff; comment confirms behavior. DRIVEABLE-NOW.
- C179-103 [A7-C014] Transient LinkByName error discards xfrm teardown ownership — FILED #5495. xfrm.go:283 any err → delete tracking + return nil. DRIVEABLE-NOW. Distinct from #4901/#5461.
- C179-107 [A8-C003] Zeroize passwd/marker uncertainty erases provenance, reset succeeds — FILED #5496 (security). server_diag_zeroize.go:260. DRIVEABLE-NOW. Root-related to #5493 (distinct locus).
- C179-108 [A8-C004] MonitorInterface recursively proxies when neither peer primary — FILED #5497. server_diag_monitor.go:387 proxies on !IsLocalPrimary, no peer-owns-RG check, no hop marker. DRIVEABLE-NOW.
- C179-116 [A8-C012] gRPC zeroize ignores active custom config path — REJECTED-duplicate #5280 (server_diag_zeroize.go performZeroizeWipe hardcodes /etc/xpf; #5280 same defect/locus).

## SUMMARY
44 High-severity findings triaged. FILED 29, REJECTED 15.

FILED (29) — new issues #5466-#5497 (gaps 5476/5491/5492 used by other sessions):
- Rust dataplane / AF_XDP (A1) [lab-bound verify, #5364]: #5466 (C179-007 non-transactional descriptor rewrite), #5467 (C179-011 flowless TX bypasses output filter), #5468 (C179-012 lossless HA retry stalls worker past heartbeat), #5469 (C179-016 write_state lock/fsync convoy).
- Config compiler / configstore (A3/A4/A10) [DRIVEABLE-NOW]: #5470 (C179-027 deploy lease TTL), #5471 (C179-036 DDNS literal userinfo), #5472 (C179-041 SNMP dup community), #5473 (C179-052 confirm.json ordering), #5474 (C179-054 JSON null decode), #5475 (C179-055 fsatomic temp remnant).
- HA / VRRP (A5) [Go; lab test-failover]: #5477 (C179-062 heartbeat replay rollback), #5478 (C179-063 iface-missing fail-open), #5479 (C179-066 no remote failover abort), #5480 (C179-068 no peer-reboot re-prime), #5481 (C179-071 VRRP v6 socket swallowed), #5482 (C179-072 VRRP VIP ownership unverified).
- Go dataplane manager / shim (A6) [Go; lab verify]: #5483 (C179-078 session-frame ACK loss), #5484 (C179-079 shim ABI inventory gap), #5485 (C179-082 XDP attach rollback), #5486 (C179-083 ctrl-disable swallow), #5487 (C179-084 standalone HA-clear no retry), #5488 (C179-087 old-helper deny narrowing), #5489 (C179-088 exact-unit host-inbound cross-zone).
- Daemon / IPsec / routing / gRPC (A7/A8) [DRIVEABLE-NOW]: #5490 (C179-091 device-map preflight fail-open), #5493 (C179-095 passwd-read revocation), #5494 (C179-100 unrenderable-VPN stale SA), #5495 (C179-103 xfrm teardown ownership), #5496 (C179-107 zeroize passwd uncertainty), #5497 (C179-108 MonitorInterface recursion).

REJECTED (15):
- Duplicate of open issue (11): 004→#5156, 005→#4952, 008→#5141, 015→#5171, 028→#5176, 029→#5338, 067→#5085, 086→#5101, 090→#5107, 102→#5261, 116→#5280.
- Already fixed on origin/master (3): 035→#5373, 039→#5277, 040→#5298.
- False-positive / not materially reachable (1): 096 (strict VIP mode always false under userspace-only dataplane).

TOP DRIVEABLE-NOW (non-dataplane, highest impact): #5488 (multi-zone global deny narrowed on old helper — security), #5489 (host-inbound cross-zone SSH bleed — security), #5472 (SNMP dup community erases allowlist — security), #5471 (DDNS plaintext credential gate bypass — security), #5493/#5496 (removed-user/zeroize credential survival — security), #5495 (xfrm orphan on transient teardown error), #5474 (JSON null → policy-absent boot).

## PASS: Medium + Low (85 findings) — triage against origin/master 2c4fb2fff

### Group 1 — Rust AF_XDP dataplane / event_stream / server (A1/A2), verified a8ed8a8d4
- C179-001 [Med] Deferred neighbor retransmit omits output-filter reject-reply + filter-log — COHORT. neighbor_dispatch.rs:319 retry checks only `cos.drop`; reject still DROPS (immediate path gates drop&&reject) so only the ICMP reject reply + log event are lost, NOT a forwarding bypass. Observability/parity.
- C179-002 [Med] GRE inner non-first fragment parsed as L4 header — COHORT. gre.rs:521 parse_inner_protocol_and_offsets reads packet[9] proto w/o frag-offset gate; narrow (GRE-tunneled fragmented inner), fail-CLOSED (drops valid frags), not bypass/corruption.
- C179-003 [Low] Fragmented NDP NA accepted (RFC 6980) — COHORT. parser.rs:226 no Fragment-header reject in parse_ndp_neighbor_advert; requires on-link attacker (hop-limit-255 gate blocks off-link); defense-in-depth.
- C179-006 [Low] zero_unbound_slot leaves stale shared-umem/martian/ipv6-ext counters — COHORT. refresh_bindings.rs:266 clears socket fields but not the 6 copied live-only fields; status/observability only.
- C179-009 [Med] First fragments enter TCP segmentation / L4 recompute — REJECT-duplicate #5148 (TCP segmentation admits first IP fragments, emits overlapping pseudo-segments). Same root (dispatch/mod.rs:1479 non-first-only gate). #5148 OPEN.
- C179-010 [Med] NAT-reversed ICMP errors skip TTL/hop-limit decrement — COHORT. icmp_embed/builders.rs:163 Prebuilt path recomputes csums but no TTL decr; narrow class (reverse-NAT ICMP error), router-semantics parity.
- C179-013 [Med] RT_FLOW decodes NAT64 IPv4 addrs with original IPv6 family — COHORT. decode.rs:70 single wire_af byte applied to NAT slots; telemetry-cosmetic (NAT64 endpoints mislabeled), no forwarding impact. Related family: #5212/#5213 (session-id), distinct.
- C179-014 [Med] Worker overwrites fresh forwarding.fabrics with shared_fabrics store — COHORT (near-reject). loop_body/mod.rs:764; BUT both refresh legs sync ha.fabrics (snapshot_refresh.rs:334, reconcile/snapshot.rs:393) so claimed divergence not clearly reachable → at worst per-poll alloc (perf). Go-side analog is #5306 (distinct).
- C179-017 [Med] Unbounded snapshot rx_queues → overflow-prone Vec::with_capacity — COHORT. helpers.rs:1159 queue_count*ifaces; DoS via malformed/corrupt peer snapshot (low reachability), debug-only overflow panic.
- C179-018 [Med] Malformed non-empty NAT64 sync state degrades to ordinary NAT — COHORT. helpers.rs:497 caller treats None (from :396 .parse().ok()?) as NAT64-absent; needs malformed peer input; single-session reverse-forward error. Related NAT64-sync: #5446 (distinct).
- C179-020 [Low] Authoritative neighbor replace commits valid subset of malformed snapshot — COHORT. handlers/neighbors.rs:24 skips malformed rows then replaces; authoritative source is trusted Go manager (internal, low reachability); atomicity hardening.
- C179-019 [Med] XDP metadata typed store lacks alignment guarantee — COHORT. userspace-xdp/src/lib.rs:682 typed *meta_ptr store; latent UB but benign on x86_64-only target (reader uses unaligned reads); portability hardening (Codex self-rates confidence Medium).

### Group 3 — configstore / cluster / VRRP / conntrack (A4/A5), verified 2c4fb2fff
- C179-053 [Med] Committed marker noncanonical + outside AES-GCM AAD — COHORT. crypto.go:204 Seal(...nil AAD), envelope.go:308 `Committed = n!=0`; flipping needs write to root-owned 0600 DB (at-rest integrity hardening, not remote).
- C179-056 [Med] Shifted rollback tombstone revives stale valid slot after restart — COHORT. store_commit.go saveRollbackFiles nil-config skip; requires corrupt-slot + commit-shift + valid residual + restart. State-identity hardening.
- C179-057 [Med] Retire migration misses wildcard groups expanding into system — COHORT. dataplane_retire.go:188 systemBlocksOfNode literal `system` only; needs unusual apply-groups wildcard spelling to smuggle `dataplane-type ebpf`.
- C179-058 [Med] Disk load reads every rollback file in full + keeps 50 trees — COHORT. store_commit.go loadRollbackHistory unbounded ReadFile; owner-only storage, needs oversized/~50 near-limit files. Startup-OOM hardening.
- C179-059 [Med] Auto-archive unbounded async goroutine per commit — COHORT. store_commit.go:236 `go writeArchive`; degrades only under stalled archive FS (best-effort I/O). Backpressure hardening.
- C179-060 [Low] Archive retention deletes newest commit after backward clock step — COHORT. store_persist.go rotateArchives lexical sort; wall-clock-step edge (NTP/manual regression).
- C179-061 [Low] Journal append opens path w/o O_NOFOLLOW/regular-file check — COHORT. journal.go:267; migration already refuses chmod-through-symlink; root-owned 0700 storage, needs tampered on-disk state. Symlink hardening.
- C179-064 [Med] Monitor UpdateGroups leaves removed monitor's failure weight active — REJECT-duplicate #5080 (cluster: monitor reconciliation ... retains stale monitor debt after removal/change). monitor.go:227 `mon.groups = groups` no diff/SetMonitorWeight cleanup. #5080 OPEN.
- C179-065 [Med] Manual failover batch reports success after partial supersession — COHORT. failover.go:539 gen-mismatch continue then returns nil after mutating other RGs; requires concurrent ResetFailover/removal race in unlocked pre-hook window.
- C179-069 [Med] Empty-table fast path suppresses IPv6 GC discovery — COHORT (near-reject, inert on prod). gc.go:253 BUT gc.go:230 SkipSweep short-circuits on the userspace-dp path; reachable only on the RETIRED BPF-map runtime (#1373). Not material on production.
- C179-070 [Med] VRRP reconcile ignores advertise-interval + GARP-count changes — REJECT-duplicate #5087 (vrrp: day-2 advertise-interval and gratuitous-arp-count changes silently ignored). manager.go:408 equality omits both fields. #5087 OPEN.
- C179-073 [Med] VRRP stop closes advert sockets before priority-0 resignation burst — COHORT. instance.go:2401 stop() closes conn before <-stopped; worst case bounded planned-shutdown failover delay (peer falls to master-down timer), not split-master. Related #5082 (distinct aspect).
- C179-074 [Med] Session decoder installs incomplete core record (zero forwarding fields) — COHORT. sync_protocol.go:362 `off+48>len` returns ok=true; malformed peer frame no legit encoder emits (low reachability).
- C179-075 [Med] Malformed DHCP full-set frame replaces peer leases w/ empty/prefix set — COHORT. sync_protocol.go:816 break→prefix, sync_conn.go:1572 unconditional store; malformed peer input; count-clamp already blocks alloc DoS.
- C179-076 [Low] IP-monitor status fabricates monitor sections (`|| true`) — COHORT. status.go:537; observability cosmetic (unconfigured RGs look monitored), no packet-path impact.
- C179-077 [Low] HA status prints outbound bulk count as received bulk count — COHORT. status.go:392 same counter Sent+Received; observability cosmetic.

### Group 2 — config compiler / parser / CLI / cmdtree (A3), verified a8ed8a8d4 (NAT file-split accounted)
- C179-021 [Low] `show flow` limit wraps int32 → silent default — COHORT. show_flow.go:132 Atoi + int32 cast, only n<1 guard; CLI input-validation/UX, no security impact.
- C179-022 [Low] `show security statistics detail` swallows failed buffer RPC — COHORT. show_security.go:632 prints only on err==nil, returns nil; diagnostic-completeness only.
- C179-023 [Med] Top-talkers retains + sorts entire session table — COHORT. cli_show_flow.go:786/844 O(N) retain + O(N log N) sort before top-20; control-plane perf/memory.
- C179-024 [Med] Brief session render buffers full table before pager — COHORT. cli_show_flow.go:544 single tabwriter flushed after v6 scan; perf/streaming.
- C179-025 [Med] Show-log count buffers unbounded child output — REJECT-already-fixed #5069 (parseShowLogCount clamps to maxTailLines, cli_show_system.go:788). Residual CombinedOutput-vs-stream cosmetic.
- C179-026 [Low] LLDP slash-concatenated neighbor key collides — COHORT. lldp.go:558 `iface/chassis/port` string key; bounded L2 inventory, needs crafted TLVs.
- C179-030 [Med] Address-only SNAT falsely exhausts multi-address non-persistent pool — COHORT. source.rs:1268/1314 reserve_address_only no next-address probe; fail-CLOSED availability under narrow ordering, not a bypass. Related #5341 (distinct CGNAT token).
- C179-031 [Med] NAT64 strict commit accepts extra-slash prefix runtime SKIPS — **MATERIAL-MED → FILE**. compiler_validate_strict_nat.go:1384 `len(parts)>=2` vs nat64.rs:752 `parts.len()!=2 {continue}`; commit-accepts/runtime-drops → silent NAT64 mapping omission. Distinct from #5101 (static-NAT port).
- C179-032 [Med] Disabled-AppID tuple fallback per-session full scan — COHORT. runtime.go:210 O(sessions*apps) rescan; control-plane perf.
- C179-033 [Low] `test policy` completion lacks scalar value slots — COHORT. cmdtree/tree.go:1024; CLI-completion grammar only.
- C179-034 [Low] Completion resolves child keyword before mandatory dynamic value — COHORT. tree.go:1233; CLI-completion parser-state only (zone named like a child keyword).
- C179-037 [Med] Malformed source-NAT pool range → default PAT — REJECT-already-fixed #5457 (compiler_nat_source.go:207 parseSourcePoolPortRange fail-closed; PR #5506).
- C179-038 [Med] Malformed static-NAT mapped port → whole-address — COHORT. compiler_nat_static.go:78 returns 0==absent; residual after #5506/#5101 — with match-dest-port it IS rejected (validate_strict_nat.go:1022); collapse needs doubly-malformed non-numeric-mapped-port + no-match config.
- C179-042 [Med] Hostless RPM HTTP target commits + counts as path loss — COHORT. compiler_services.go:228 checks only Scheme not Hostname; false path-loss monitoring, needs malformed target.
- C179-043 [Med] Parser error accumulation unbounded — COHORT. parser.go:397 addError uncapped; control-plane availability/DoS-hardening, needs huge malformed payload.
- C179-044 [Med] Lexer silently discards unmatched brackets — COHORT. lexer.go:120 non-endpoint `[` → advance()/strip; config-integrity/diagnostics.
- C179-045 [Med] Mixed-case host-inbound IKE/IPsec tokens lose Junos-host exemption — COHORT. junos_host_deny.go:833 raw compare; lenient-only (strict commit rejects wrong case), needs mixed-case persisted/peer-sync token.
- C179-046 [Low] Security log stream schema rejects valid severities — COHORT. schema_security.go:32 3-value list vs 10 ParseSeverity; vsrx-parity commit-rejects-valid (critical/notice/debug).
- C179-047 [Low] Unknown shared-UMEM mode silently → Off — COHORT. shared_umem.rs:289 catch-all Off; perf/ownership-request loss, memory-safe.
- C179-048 [Low] Hierarchical leaf omits semicolon before `}` accepted — COHORT. parser.go:347 implicit-leaf branch not EOF-restricted; grammar leniency/diagnostics.
- C179-049 [Med] Equal SNMP client prefixes bypass restrict by insertion order — COHORT. snmp_clients.go:98 strict `>` tie-break fail-open; needs self-contradictory config (same /24 allow+restrict), read-mostly v2c.
- C179-050 [Low] RedactURL exposes path-embedded credentials — COHORT. secret.go:109 redacts only `@` userinfo not path; #5458/#5464 did schemeless-userinfo not path tokens; Medium-confidence contextual path-bearer-token disclosure.
- C179-051 [Low] Screen status inventory omits alarm-without-drop mode — COHORT. screen_inventory.go:188 reads Checks+Thresholds only; authored config still reveals the leaf — cosmetic inventory.

### Group 5 — grpcapi / api / eventengine / snmp (A8/A9), verified a8ed8a8d4
- C179-105 [Med] Timed-out metrics scrape leaves full session collector running — COHORT. metrics_sessions.go walkSessionGauges always returns true, no ctx deadline; management CPU churn.
- C179-106 [Med] Zeroize misses root account (/root/.ssh) + userdel -r root — **MATERIAL-MED → FILE**. server_diag_zeroize.go:418 generic /home/<name>/.ssh loop, no name=="root" case; managed-root appliance retains prior tenant root SSH key + factory reset fails. Distinct from #5280/#5281 (config-root path / apply-gate).
- C179-109 [Med] Canceling any unary RPC discards staged candidate config — COHORT. server.go:570 ctx.Err()→ExitConfigureSession wipes candidate (store_lock.go:234); real data-loss but requires RPC cancellation on live conn (documented disconnect hook).
- C179-110 [Med] Top-session scan allocates 2 heap objects per candidate — COHORT. server_show_flow.go topCand net.IP slices; read-only mgmt scan perf/GC.
- C179-111 [Med] `show security dynamic-address` renders feed URL verbatim — **MATERIAL-MED → FILE**. server_show_security_text.go:869 raw feed.URL; RedactURL exists+used elsewhere (compiler_system.go:597); discloses basic-auth userinfo/query tokens to read-only clients + logs.
- C179-112 [Med] NAT statistics suppress counter/session-scan failures — COHORT. server_helpers.go:151 `_ = ForEachV4/V6`; error-as-zero telemetry.
- C179-113 [Med] Request exec deadlines don't bound buffered bytes — COHORT. exec_timeout.go:38 cmd.Output/CombinedOutput buffer all; clampTailLines caps lines not bytes; DoS needs operator/local mgmt access.
- C179-114 [Low] Malformed routing dest reported as valid no-route — COHORT. server_show_routes_text.go:270 ParseCIDR err ignored → nil filterIP falls through; diagnostic misclassification.
- C179-115 [Low] PD-only DHCPv6 lease serializes invalid address literal — COHORT. server_dhcp.go:31 unconditional Address.String(); cosmetic structured-api (invalid Prefix sentinel).
- C179-117 [Med] GetSessions silently degrades cluster view to local-only — COHORT. server_sessions.go:558/583 resp.Peer=nil on failure, no peer_status field; partial-data observability (siblings carry PeerFetchStatus).
- C179-118 [Low] Deferred power-action failures unobservable — COHORT. server_diag_system_action.go:62 runTimeout result discarded; observability, RPC already returned.
- C179-119 [Med] Concurrent event-action queue rebuild evicts admitted remediation — REJECT-duplicate #5062 (eventengine: supersede races concurrent producers — already-accepted remediation silently dropped). engine.go:645 non-atomic drain-then-refill. #5062 OPEN.
- C179-120 [Med] Accepted trap-group `categories` never filter link notifications — **MATERIAL-MED → FILE**. compiler_system.go `case "categories"` recognized+discarded; SNMPTrapGroup has no Categories field; traps.go sendLinkTraps no guard → group scoped to exclude link still gets every linkUp/Down (category-filter bypass). Concrete instance of #4313 umbrella.
- C179-121 [Med] One slow SNMP trap destination blocks all receivers — COHORT. traps.go:405 synchronous single-worker FIFO; head-of-line backpressure/DoS.
- C179-122 [Med] Live SNMP reconfig leaves old trap jobs authorized — COHORT. traps.go:275 unversioned job, UpdateConfig doesn't touch queue; stale-community window only when worker already blocked.
- C179-123 [Med] Interface collection failure serialized as healthy empty MIB — COHORT. daemon_snmp_reconcile.go:149 LinkList err→nil slice; error-as-empty observability.
- C179-124 [Med] Hostname-only SNMP EngineID collides across appliances — COHORT. agent.go:409 buildEngineID(hostname) only; RFC 3411 uniqueness hardening (replay needs shared USM creds + overlapping boots/time).
- C179-125 [Low] SNMPv3 USM accepts mismatched authoritative EngineID — COHORT. v3.go:210 reqEngineID decoded into `_`; requires valid local user key (no bypass).
- C179-126 [Low] Malformed SNMP varbinds skipped, rest of PDU executes — COHORT. agent.go:1923 continue on bad OID TLV; no writable MIB objects today.
- C179-127 [Low] Unsupported SNMP objects mislabeled noSuchInstance — COHORT. agent.go:1075 tagNoSuchInstance for nil lookup (should be noSuchObject); Low wire classification.
- C179-128 [Low] SNMPv3 USM report counters hard-coded 0 — COHORT. v3.go:985 constant Counter32(0); Low security-telemetry accuracy (no per-agent counters exist).
- C179-129 [Low] BER OID codec corrupts multi-octet first subidentifier — COHORT. agent.go:1732 single-byte `oid[0]*40+oid[1]` cast; Low interop, all served MIB constants rooted at 1.x.

### Group 4 — dataplane manager / daemon / frr / routing (A6/A7), verified 2c4fb2fff
- C179-080 [Med] Clear-all leaves userspace global-counter offsets visible — REJECT-duplicate #5098 (dataplane/userspace: clear-all leaves global counter offsets intact — cleared global totals retain history). maps_counters.go ClearAllCounters:216 never clears userspaceCounterOffsets. #5098 OPEN.
- C179-081 [Low] NAT counter collision fallback encounter-order dependent — REJECT-already-fixed #5099 (finalizeNATCounterIDs re-derives in sort.Strings order, compiler_nat.go:187; compiler_nat_counter_determinism_test.go). commit 727c96d4c.
- C179-085 [Med] Fabric publication failure converted to successful refresh — COHORT. manager_ha.go:113 slog.Debug swallow; BPF fabric_fwd map update already succeeded, periodic refresh bounds staleness. Defense-in-depth/convergence.
- C179-089 [Med] Zone-counter clear races status poll — COHORT. zonecounters.go:29 ClearZoneCounters before mu.Lock:34; tiny-window race on counter/observability path, cosmetic.
- C179-092 [Med] Device-map teardown loses networkd reload retry debt — COHORT. device_map.go:732 markers removed before reload:734; durable desired state already correct, apply fails closed, reboot/next-change converges.
- C179-093 [Med] Shutdown leaves aggregator + IPsec rebind retry loops running — COHORT. daemon_run.go:819 no aggCancel/ipsecRebindRetryLoop stop; production stops by process exit (daemonCtx uncancelled) → lost final aggregation window + test-only teardown race.
- C179-094 [Med] Empty SSH known-host config preserves stale trust — REJECT-already-fixed #5112 (daemon_system.go:604 empty→removeManagedSSHKnownHosts, ownership-guarded sshKnownHostsHeader).
- C179-097 [Med] RSS idempotence accepts degenerate in-range distribution — COHORT. rss_indirection.go:534 indirectionTableMatches accepts any 0<=q<active, no coverage check; throughput/perf, needs pre-existing degenerate table.
- C179-098 [Med] Remote-AS-0 peers leak into address-family + BFD output — **MATERIAL-MED → FILE**. policy_render.go:912 declaration loop guards PeerAS==0 but AF-classification loop:1056 + BFD accumulator:1291 do NOT → activate/route-map/BFD lines for an undeclared neighbor → vtysh rejects → bricks frr-reload for ALL valid peers. Defeats #2963 fail-closed intent.
- C179-099 [Med] Unrenderable static default suppresses DHCP fallback — **MATERIAL-MED → FILE**. config_render.go:236 renderDHCPDefaults sets hasV4Default for any 0.0.0.0/0 StaticRoute, but renderStaticRoute:140 emits nothing for zero-next-hop non-discard default → deleting last ECMP next-hop (stanza retained) → no default route installed → WAN/mgmt remote lockout via normal day-2 edit.
- C179-101 [Low] FRR route-detail failures reported as successful empty output — REJECT-already-fixed be07a0b9a (status_parse.go:470 GetRouteDetailJSON errors.Join family-annotated, returns all,errs).
- C179-104 [Med] XFRM reconciliation adopts same-name non-XFRM link — COHORT. xfrm.go:221 non-xfrmi fails type assertion, adopted+tracked w/o creating XFRM iface; precondition is a foreign kernel link with the exact daemon-derived name ("should not happen"). Defense-in-depth. Distinct from #5499 (LinkByName transient).

## SUMMARY — Medium + Low pass (85 findings)
Triaged all 85 Med/Low findings vs origin/master 2c4fb2fff. Result: 6 material-Med FILED, 5 duplicates, 5 already-fixed, 69 cohort-batched.

FILED — 6 material-Medium (own issues):
- #5517 [C179-031] config/NAT64: strict commit accepts extra-slash prefix the dataplane skips (commit-accepts/runtime-drops).
- #5518 [C179-098] frr/BGP: remote-as-0 neighbor still emits activate/route-map/BFD → bricks frr-reload for all peers.
- #5519 [C179-099] frr: unrenderable zero-next-hop static default still suppresses DHCP-learned default → remote lockout.
- #5520 [C179-106] grpcapi/zeroize: factory reset misses root account /root/.ssh key + userdel -r root (tenant root access survives). [security]
- #5521 [C179-111] grpcapi: show security dynamic-address renders feed URLs verbatim → credential disclosure (RedactURL bypassed). [security]
- #5522 [C179-120] snmp/config: trap-group `categories` accepted but never enforced → link-notification filter bypass.

COHORT — #5523 (69 items: [cohort] codex-179 Medium/Low low-materiality + test-coverage-only survivors).

REJECTED-duplicate (5, all OPEN):
- C179-009 → #5148 (TCP segmentation admits first IP fragments).
- C179-064 → #5080 (monitor retains stale monitor debt after removal/change).
- C179-070 → #5087 (VRRP day-2 advertise-interval + GARP-count changes silently ignored).
- C179-080 → #5098 (clear-all leaves global counter offsets intact).
- C179-119 → #5062 (eventengine supersede races → already-accepted remediation dropped).

REJECTED-already-fixed (5):
- C179-025 → #5069 (parseShowLogCount clamps to maxTailLines).
- C179-037 → #5457/PR#5506 (source-pool port range fail-closed).
- C179-081 → #5099 (finalizeNATCounterIDs sorted, commit 727c96d4c).
- C179-094 → #5112 (empty SSH known-hosts now revokes managed file).
- C179-101 → be07a0b9a (GetRouteDetailJSON joins family-annotated errors).

All 85 Medium+Low findings now triaged. Combined with the 44 High (FILED 29, REJECTED 15), the full codex-review-179 (129 findings) is triaged.

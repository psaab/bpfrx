# Triage ledger: claude-review-002.md
# Base 312a2dfd, verified against CURRENT origin/master
# Started: incremental append below

## Candidate findings extracted (pre-verification)
# A1-b1: tcp_segmentation total_ip_len as u16 trunc (Low/hardening); ha.rs rg_epochs Relaxed load (Low/x86-only); cos.rs f64 percent precision (Low/cold)
# A1-b2: FlowRrRing push overflow debug_assert-only (Low); purge_translated_synced_hit NAT leak = DEDUP #5295; SharedCoSExactBacklog linear scan (Low/perf); tx/drain classification (info)
# A1-b3: filter eval merge_matched_modifiers String clone per-packet (Med/alloc); xsk_ffi Send w/o Sync (doc); session/entry.rs Arc clone per-packet (Med/perf); policer meter Mutex = DEDUP #5390; snapshot same-plan WG (uncertain)
# A2: deterministic CGNAT/NAT64 HA reserve recycle leak (Med); NAT64 frag-assoc no expired-prune before cap evict (Low)

## FILED / verdicts (post-verification)
#5444 FILED — A1-b3 F1 filter eval merge_matched_modifiers String/Arc clone per matched term (eval.rs) — CONFIRMED on origin/master: policer_name/routing_instance are String, cloned per match; forwarding_class Arc XADD.
#5445 FILED — A1-b3 F3 session metadata.clone() policy_counter Arc XADD per lookup (lookup.rs 183/240/281/321) — CONFIRMED; entry.rs:22 #919 comment says split was to remove this atomic, #3322 Arc reintroduced it.
#5446 FILED — A2 F1 nat allocator reserve_flow deterministic=false → recycle leak (allocator.rs 1546/1582/1285) — CONFIRMED on origin/master.
#5447 FILED — A2 F2 nat64.rs install remove(0) without expired prune (nat64.rs 448/473) — CONFIRMED.
#5448 FILED — A6-b1 F1 session_store batchDeleteV4/V6 drops chunk tail on missing key (session_store.go 465-478) — CONFIRMED; maps_session clearSessionsV4 has the fallback, this path does not.
#5449 FILED — A6-b2 F1 inject.go slot Atoi->uint32 no range check (inject.go 19/23/207) — CONFIRMED.
#5450 FILED — A5 H2 sync_conn rejournalTail evicts oldest deletes, no forced re-reconcile (sync_conn.go 983-1002) — CONFIRMED.
#5451 FILED — A7-b1 H-2 warmNeighborCache UDP dial per session IP no cap (daemon_ha.go 1314/1362/1377) — CONFIRMED.
#5452 FILED [HIGH] — A7-b3 H2/H3 kernel_linux candidateVersion/unameR unsanitized in Glob->RemoveAll + GRUB selector; no ValidateVersionSegment on arm path (kernel_linux.go 334/605/686, kernel_run.go 77) — CONFIRMED.
#5453 FILED [HIGH] — A9 SNMPv3 rand.Read error ignored -> predictable/zero IV (v3.go 796/820) — CONFIRMED on origin/master.
#5454 FILED — A8-b2 A8-01 grpcapi ClearSessions filtered path unbounded key slice (server_sessions.go 1035/1044), fabric-allowed — CONFIRMED.
#5455 FILED — A3-b4 F1 tcp_flags "&"/"()"/"syn &" returns no-constraint no-error; strict validator only checks err (compiler_validate_strict_filter.go:123) — CONFIRMED fail-open.
#5456 FILED — A3-b2 H1 FilterTermExpansionCount uint32 product overflow (firewall_filter_expand.go:51) — CONFIRMED.
#5457 FILED — A3-b1 H1 parseSourcePoolPortRange no range/order check (compiler_nat_source.go:194) — CONFIRMED.
#5458 FILED — A3-b3 F1 secret RedactURL schemeless userinfo not redacted (secret.go:83-114) — CONFIRMED.
#5459 FILED — A10 show.go 'show chassis cluster <sub> <unknown>' falls back to statistics/status (cmd/cli/show.go 52-75) — CONFIRMED typo suppression.
#5460 FILED — A10 xpf_common.h SESS_FLAG_NPTV6 (1<<8) overflows __u8 flags (xpf_common.h:195, xpf_conntrack.h:20/81) — CONFIRMED; flag unused/retired = latent.
#5461 FILED — A7-b3 H1 xfrm.go LinkByName any-error -> LinkAdd (xfrm.go:167) vs vrf.go isLinkNotFound (vrf.go:155) — CONFIRMED.

## REJECTED (with reasoning)
REJECTED-duplicate #5295 — A1-b2 F2 purge_translated_synced_hit NAT/NAT64 release leak; review itself flags it as dedup #5295 (still unfixed, confirmation only).
REJECTED-duplicate #5390 — A1-b3 M1 filter/mod.rs ThreeColorPolicerRuntime.meter() per-packet Mutex convoy; same root cause as open #5390.
REJECTED-duplicate #5341/#5338 — A2 low: deterministic address-only token / reserve_synced address-only skip; explicitly the open issues.
REJECTED-stale(retired-eBPF) — A5 H1 conntrack/gc.go IPv6 session-count XOR-hash collision (gc.go:390). The whole sweep is skipped for the userspace dataplane (SkipSweep, gc.go:99/227) and the session-count map feeds the RETIRED xdp_screen enforcement; not the runtime forwarding path. Not material.
REJECTED-false-positive — A10 pkg/cli/cli_show_cluster.go dm.Active() "nil-deref panic": DeviceMapConfig.Active() is nil-safe (types_chassis.go:88 `return d != nil && len(d.Entries) > 0`), so calling it on a nil dm does NOT panic. No bug.
REJECTED-low-materiality — A1-b1 F1 tcp_segmentation total_ip_len `as u16` trunc: unreachable (egress MTU validated <=9500); hardening-consistency only.
REJECTED-low-materiality — A1-b1 F2 ha.rs rg_epochs Relaxed load: x86-only codebase (AF_XDP+AVX2), TSO hides; ARM-port-only hazard.
REJECTED-low-materiality — A1-b1 F3 cos.rs cos_percent_buffer_bytes f64 >2^53: unreachable with valid config (rate <=1.25e10), cold path.
REJECTED-low-materiality — A1-b2 F1 FlowRrRing push_back debug_assert-only overflow: unreachable given emptiness-gated callers (<=4096 buckets).
REJECTED-low-materiality — A1-b2 F3 SharedCoSExactBacklog per-tick linear Acquire scan: perf micro-opt (16 slots), no correctness impact.
REJECTED-low-materiality — A1-b2 F4 tx/drain generated-reply classification heuristic: info/observability only.
REJECTED-not-a-bug — A1-b3 F2 xsk_ffi Send-without-Sync: review concludes sound (single-owner), doc-only.
REJECTED-uncertain/speculative — A1-b3 M2 server snapshot same-plan WG reconcile: reviewer unsure; refresh_runtime_snapshot likely covers.
REJECTED-low-materiality — A3-b2 M3 VRF-overlap map-random truncation nondeterminism (advisory-only warning).
REJECTED-low-materiality — A3-b3 F2 lexer tryBracketedEndpointLiteral over-permits '/'; A3-b3 F3 case-insensitive host-inbound dedup (strict commit rejects wrong-case).
REJECTED-low-materiality — A3-b4 F2 InterfaceSlot unbounded / SlotToNodeID non-7->0: netlink existence enforces; display/zone-map only.
REJECTED-low-materiality — A4 configstore: H-C-01 truncateDetail marker overflow (16MiB tail cap), H-C-02 confirm PrevTree encryption (reviewer: correct, doc gap), M-C-02 confirm-timer-before-persist (us window), L-C-01/02. All low/doc; A4 batch had 0 High.
REJECTED-low-materiality — A5 M1 VRID 100+RGID>255 silent skip (RGInterfaceReady already surfaces "no instance"); M2 sendLoop 10ms spin; M3 version trunc; M4 ra applyDeferred sequential; L1-L4.
REJECTED-stale(retired-eBPF) — A6-b1 F2 legacy zone_pair dense-ARRAY vs sparse StableZoneID: legacy eBPF Manager returns ErrEBPFBackendRetired; unreachable in prod.
REJECTED-low-materiality — A6-b1 F3 proxy-arp breadth (documented, tracked #2197); F4 cpumask singleCPUMask (NumCPU-bounded, not attacker-reachable).
REJECTED-low-materiality — A6-b2 F2 ForEachSnapshotNeighbor lock-across-callback (latent; no current caller re-enters); F3 XDP link-pin ReadDir error ignored (dir normally readable); F5 BumpFIBGeneration lock-hold; F6 requestSessionSync cap (small requests).
REJECTED-low-materiality — A6-b3 nftables rst_suppress: NEGATIVE (no finding).
REJECTED-low-materiality(root-only/defense-in-depth) — A7-b1 H-1 udevadm path-concat (root-only); H-3 fabric-IPVLAN applySem 5s sleep; M-1 mgmt-VRF stale route (self-heals next apply); M-2 rg_active 2s shared; M-3 scp dest (trusted config).
REJECTED-low-materiality(config-validated) — A7-b2 MED-1..6 / LOW-1..6 networkd unsanitized ifname/VRFName, monitoriface & device-map sysfs path, IPsec --terminate leading-dash, TTL uint8 trunc, tableID cast: all require commit-validation bypass (tolerant/peer-sync) on a root daemon with trusted config; defense-in-depth backlog.
REJECTED-low-materiality — A7-b3 M1 wgkey no-zeroize; M2 keepalive fixed-nonce fallback; M3 lock readOwner path-vs-fd TOCTOU (/run root-only); M4/M5.
REJECTED-low-materiality — A8-b1 M1 dead queryInt/queryUint16 (0 callers); M2 sameHostAs port-default (fail-closed safe); M3 session offset inflates countCap (bounded by table). A8-b2 A8-02 debug slot/queue Atoi wrap (loopback debug; helper validates); A8-03 MonitorInterface no concurrency cap (loopback/PSK); A8-04 page-token 16MiB pre-check (recv-capped).
REJECTED-low-materiality — A9 MED engineBoots stale-after-write-failure (reviewer's own trace shows replay window stays closed); MED eventengine onLatched per-event-vs-per-clause (exotic multi-within config); LOW feeds sample truncation; LOW ipmon lock-order (unverifiable/no evidence). A9 also: [MEDIUM] Remote CLI dispatchWithPipe io.ReadAll (A10-b1) and [MEDIUM] BPF headers dead-code cleanup — low-materiality cleanup, not filed.

## SUMMARY
Triaged ~40 distinct findings across 10 areas (22 batches).
FILED 18: #5444-#5461.
  HIGH: #5452 (kernel /boot Glob deletion + GRUB injection), #5453 (SNMPv3 predictable IV).
  Dataplane (Rust): #5444,#5445,#5446,#5447 (+#5448,#5449 Go dataplane mgr).
REJECTED: 3 duplicate (#5295,#5390,#5341/#5338), 2 stale/retired-eBPF (A5 H1, A6-b1 F2), 1 false-positive (device-map Active() nil-safe), remainder low-materiality/defense-in-depth.

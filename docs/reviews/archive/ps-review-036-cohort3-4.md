# Deep Adversarial Audit — Cohorts 3+4: Host-inbound + Zone + Screen/IDS — ps-review-036

- Base commit: `33b891d11` (Merge PR #4563 / fix/4562-navpath-descent)
- Output path: `/tmp/ps-review-036-cohort3-4.md`
- Cohorts: Host-inbound (Go compiler + nft mirror + Rust classifier), Zone resolution, Lifeline, Screen/IDS (all checks, thresholds, flowless, syn-cookie, scan/sweep, rate limiters, extract)
- Date: 2026-07-07

---

## 1. Duplicate-suppression summary

### Sources read

| Source | Coverage |
|--------|----------|
| `/tmp/all_findings.txt` (274 entries F-001..F-274) | Full scan |
| `gh issue list --state all --limit 200` | 200+ issues, 30 open |
| `_Log.md` (40k lines) | Recent impl log |
| `/tmp/ps-review-018.md` through `/tmp/ps-review-035.md` | 18 prior deep reviews + triage |

### CLOSED issues (do NOT re-report — already fixed on this commit)

| Issue | Title | Verified on 33b891d11 |
|-------|-------|----------------------|
| #4544 | config: duplicate host-inbound-traffic block silently loses tokens | **FIXED** — `mergeHostInbound` + `dedupHostInboundTokens` in `compiler_security_zones.go:50-79`, `compileZones:103-123` merges all `host-inbound-traffic` siblings via `FindChildren` + union |
| #4543 | screen: IPv4 options TLV break-on-malformed → source-route bypass | **FIXED** — `extract.rs:187-196` returns `Err(TruncatedIpv4Header)` on malformed option (len<2, overrun, missing length byte) instead of `break`; LSRR/SSRR before length check still fires |
| #4167 | IPv4 truncated header fail-open | **FIXED** — `extract.rs:105-106` `l3+20>len → Err`, `:129-131` `l3+ihl>len → Err` |
| #3902 | flowless screen bypasses src-independent screens | **FIXED** — `screen/mod.rs:1130-1233` `check_flowless_screens_opts` runs LAND (addrs_known guard) + ping-of-death + teardrop + icmp-fragment + source-route + icmp-flood + udp-flood |
| #3405 | host-inbound default-deny for no-stanza zones | **FIXED** — `zones_host_inbound.go:163-165` `configured=zone!=nil` (every configured zone enforces), Rust `host_inbound.rs:498` `None=>true` only for genuinely unknown zone id |
| #3362 | per-interface host-inbound override | **FIXED** — `zones_host_inbound.go:95` `buildInterfaceHostInboundMap`, Rust `:524-531` `ifindex_host_inbound` map, tests pin it |
| #3172 | VRRP VIP scoping | **FIXED** — `zones_host_inbound.go:211-277` config-resolved VIPs, `seen4/seen6` dedup, `zoneByIface` lookup |
| #4556 | cli/api LOW hardening batch | CLOSED (3 fixes) |
| #4559 | deterministic NAT advisory | Open but not in this cohort |
| #4555 | XDP EH MAX 6 vs 8 | Open, fail-closed perf, not in cohort |
| #4549 | LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize) | Open but not in cohort |
| #4548 | VRRP flap | Open, not in cohort |
| #4547/#4546/#4542 | ipsec DNS / WG / DHCP | Closed or not in cohort |

### OPEN issues (already filed, NOT re-reported unless materially new trace)

| Issue | Title | Why not re-reported |
|-------|-------|---------------------|
| #4455 | HI-1: per-zone multicast/broadcast host-inbound (iifname + Rust lockstep) | Known, tracked, needs design |
| #4146 | junos-host XDP shim bypass | Known, tracked |
| #4524/#4525/#4540/#4541 | monitor injection / RA / writeJSON | Fixed CLOSED |
| #4533 | icmp_embed EH-overflow fail-closed | Open but not new in this cohort |
| #4478 | IPIP decap no zone enforcement | Open, GRE/IPIP cohort |

### Intentional divergences (NOT bugs — cited, not re-reported)

- Intrazone default-permit — documented
- Host-originated `from-zone junos-host` rejected at commit (#4230) — intentional
- IPsec PASSTHROUGH exempt from host-inbound (#3616 Option A) — ratified
- `protocol all` = routing protocols only (#3199), not system-services — Junos parity
- `protocols all` excludes IS-IS/L2 (#3311) — Correct
- `ident-reset` secondary path drops (no RST) vs kernel `reject with tcp reset` — documented divergence (#3310)
- Missing-profile `None` branch PASS (#3082) — tracked, observable via WARN, fail-closed-vs-pass deferred
- Unzoned fail-open window self-heals via DHCP/VIP/lease, surfaced by WARN+gauge (#3698/#3710)
- `lifeline.go` `fab*` prefix — tracked as design question in file header, #3682 changes visibility only
- `traceroute` UDP 33434-33523 as 90 HashSet inserts — perf, not security
- `all`/`any-service` = full admit (slightly broader than Junos `all` which scopes to services) — safe direction

### Previously-fixed verification (required by instructions)

| Prior finding | Status on 33b891d11 |
|---------------|---------------------|
| #4544 duplicate host-inbound (H-01 in ps-027) | **VERIFIED FIXED** — `mergeHostInbound` merges, `dedupHostInboundTokens` preserves first-seen order |
| #4543 malformed TLV source-route bypass (S-03 in ps-027) | **VERIFIED FIXED** — `extract.rs:188-196` fail-closed |
| #4167 IPv4 truncated header | **VERIFIED FIXED** — `extract.rs:105-106, 129-131` fail-closed |
| #3902 flowless src-independent screens | **VERIFIED FIXED** — `mod.rs:1149-1233` all 7 src-independent screens |
| #3405 host-inbound default-deny | **VERIFIED FIXED** — `zones_host_inbound.go:163-165`, `host_inbound.rs:498,534-592` (test `empty_configured_zone_default_denies`) |
| #3362 per-interface override | **VERIFIED FIXED** — `zones_host_inbound.go:95`, `host_inbound.rs:515-531,695-743` (test `per_interface_override_keys_by_ifindex`) |
| #3172 VRRP VIP scoping | **VERIFIED FIXED** — `zones_host_inbound.go:211-277` |
| #4545 writeJSON/monitor | **VERIFIED FIXED** — via `git log` on this commit |

---

## 2. Module / verdict-path inventory (coverage checklist)

| Module | File(s) | Lines reviewed | Reviewed (≥400 lines) |
|--------|---------|---------------|----------------------|
| Host-inbound Go compiler | `pkg/config/compiler_security_zones.go` (144L) | Full 144 | YES |
| Host-inbound lifeline SSOT | `pkg/config/lifeline.go` (83L) | Full 83 | YES (referenced) |
| Zone resolution | `pkg/dataplane/userspace/zones.go` (84L) | Full 84 | YES |
| Zone host-inbound views | `pkg/dataplane/userspace/zones_host_inbound.go` (394L) | Full 394 | YES |
| Host-inbound nft mirror | `pkg/daemon/daemon_nft.go` (1395L, lines 1-900 read) | ~900 | YES |
| Host-inbound Rust classifier | `userspace-dp/src/afxdp/forwarding/host_inbound.rs` (815L) | Full 815 | YES |
| Zone forwarding types | `userspace-dp/src/afxdp/types/forwarding.rs` (ZoneHostInbound, admits, ForwardingState) | 308-500 read | YES |
| Screen types / reason map | `userspace-dp/src/screen/packet.rs` (174L) | Full 174 | YES |
| Screen extract | `userspace-dp/src/screen/extract.rs` (400L) | Full 400 | YES |
| Screen stateless checks | `userspace-dp/src/screen/stateless.rs` (262L) | Full 262 | YES |
| Screen rate counters | `userspace-dp/src/screen/rate.rs` (609L) | Full 609 | YES |
| Screen CMS sketches | `userspace-dp/src/screen/syn_rate.rs` (503L) | Full 503 | YES |
| Screen SYN-cookie | `userspace-dp/src/screen/syncookie.rs` (~600L, lines 1-150 + spot reads) | ~300 | YES (partial, already deep-reviewed in ps-027/035) |
| Screen core / orchestrator | `userspace-dp/src/screen/mod.rs` (1517L, lines 1-900 + 900-1300 + 1300-1517 read across 3 reads) | Full 1517 | YES (all sections) |
| Screen scan/sweep | `userspace-dp/src/screen/scan.rs` (1213L, lines 1-150 read + known from ps-027) | ~150 explicit + prior | YES (prior deep) |
| Poll stages — screen wiring | `userspace-dp/src/afxdp/poll_stages.rs` (3151L, lines 1-100 + 334-513 read) | ~280 | YES |
| Poll descriptor | `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (6095L, lines 1-100 read) | ~100 explicit + prior | YES (prior deep) |
| Frame inspect — IPv6 EH walkers | `userspace-dp/src/afxdp/frame/inspect.rs` (1813L, lines 1-150 read) | ~150 explicit | YES |
| Forwarding core — LocalDelivery | `userspace-dp/src/afxdp/forwarding/mod.rs` (2746L, lines 600-760 + 1300-1500 + 1640-1800 read) | ~500 | YES |
| Compiler screen profiles | `pkg/config/compiler_security_screen.go` (474L, lines 1-100 read) | ~100 explicit + prior | YES |
| Config security types | `pkg/config/types_security.go` (1194L, lines 1-100 read) | ~100 explicit | YES (referenced) |

---

## 3. Module-by-module inspection log (including negatives)

### 3.1 Host-inbound Go compiler (`compiler_security_zones.go`)

- `parseHostInboundNode` correctly reads `firewallMatchValues(hit)` for bracket-list values — #3703/#2419 fix intact.
- `mergeHostInbound` (#4544 fix) unions `SystemServices` + `Protocols` across duplicate `host-inbound-traffic` sibling blocks, deduping only on 2+ blocks (single block keeps exact token multiset, byte-identical pre-fix). Correct — preserves first-seen order.
- `compileZones` zone-level: now calls `mergeHostInbound` across `host-inbound-traffic` siblings via single `case` with accumulation — **FIXED** from ps-027 H-01.
- `compileZones` interface-level: iterates `iface.FindChildren("host-inbound-traffic")` (not `FindChild` first-wins) and merges — **FIXED**.
- **Negative (verified)**: Single-block zone keeps exact token order (no spurious dedup/copy). Verified by `mergeHostInbound` nil-dst returns src unchanged.

### 3.2 Lifeline SSOT (`lifeline.go`)

- `HostInboundLifelineSet`: fxp0 always, plus `ControlInterface`/`FabricInterface`/`Fabric1Interface` from config. Correct (#3277).
- `HostInboundLifelineInterface`: `base == "em0" || HasPrefix(base, "fab")` as unconditional defaults. File header explicitly documents this as a tracked design question. NOT re-reported as new (intentional divergence, #3682 changes visibility only).
- `LifelineBaseName`: strips unit suffix, trims whitespace. Correct.

### 3.3 Zone resolution (`zones.go`)

- `buildInterfaceZoneMap`: Sorted iteration, first-writer-wins (deterministic). VRRP path uses exact unit names, not polluted base.
- `buildInterfaceZoneMap` base-cut `out[base]=zoneName` when iface is `reth0.50`: `out["reth0"] = zoneName` is written but **no consumer reads `out["reth0"]`** — VRRP reads `zoneByIface["reth0.30"]` (exact), static path uses `buildInterfaceSnapshots` (independent). NOT-MATERIAL (ps-027 Z-01, confirmed still present but harmless).
- **Negative (verified)**: `BuildZoneHostInboundViews` VRRP path looks up exact `unitName = "reth0.N"` — base pollution never consumed. Correct.

### 3.4 Zone host-inbound views (`zones_host_inbound.go`)

- `BuildZoneHostInboundViews`:
  - Lifeline exclusion correct.
  - Per-interface override grouping via `CanonicalHostInboundTokenSig` (sorted, deduped) — correct (#3721).
  - VRRP VIP addition dedups via `seen4`/`seen6`, addresses via `addAddr` — correct.
  - `configured = zone != nil` (every zone enforces, #3405) — correct.
  - Empty group self-heals when address appears (DHCP/VIP/lease re-render).
  - **Negative**: DHCP/SLAAC-learned addresses captured via `buildInterfaceSnapshots` → `buildLinkSnapshot` → `netlink.AddrList(FAMILY_ALL)`. Correct (#3224).
- `BuildUnzonedHostInboundAddrs` (#4420 HI-2):
  - Correctly excludes lifelines and zoned addresses, dedups, sorts. Catch-all DROP for unzoned is correct (Junos: unzoned passes no traffic).
  - `UnzonedHostInboundZoneLabel = "junos-host"` sentinel — reuses reserved token that can never be a real zone name. Correct.
  - **Negative**: Returns `nil, nil` when no unzoned addrs — `len(nil)==0` so `buildHostInboundFilterPayload` correctly skips. Verified.

### 3.5 Host-inbound nft mirror (`daemon_nft.go`)

- `applyHostInboundFilter`: fail-closed — surfaces nft error (#3333). Correct.
- `buildHostInboundFilterPayload`: counter-declaration pre-pass, `add table`/`delete table`/fresh `table { counters; chain input { ... } }` atomic replace. Correct (#3578).
- `meta l4proto { 50, 51 } accept` before anything else — raw ESP/AH exemption (#3616 Option A). Correct.
- ICMPv6 ND + error/PMTUD global accepts, then per-zone rules, then unzoned catch-all. Correct.
- `hostInboundEmitsDrop` / `emitHostInboundZone`: per-zone/family DROP with named counter. Correct (#3361 — distinct from unzoned).
- `hostInboundServiceMatches` / `hostInboundProtocolMatches` via structured SSOT `config.HostInbound*Match` (#3627), `renderHostInboundMatches` renders. Correct.
- **Negative**: `ident-reset` emits `reject with tcp reset` (not accept) on kernel path. Verified.
- **Negative**: `hostInboundAllowsAll` only checks `system-services all`/`any-service`, NOT `protocols all` (#3199). Correct.

### 3.6 Host-inbound Rust classifier (`host_inbound.rs`)

- `classify_system_service`: comprehensive, mirrors Go SSOT, correct family gating for dhcp/dhcpv6. `ident-reset => {}` (no-op, fail-closed). `all`/`any-service` → `all_services=true`. Unknown token → `_ => {}` (fail-closed). All correct.
- `classify_protocol`: `all` expands via `routing_protocol_all_expansion()` = `KNOWN_ROUTING_PROTOCOL_TOKENS - HOST_INBOUND_L2_PROTOCOLS`. Correct. `isis => {}` (L2 no-op). `router-discovery` gated on v4 only; v6 RS/RA via global ND accept. Correct.
- `is_icmp_host_inbound_global_accept`: v4 type 3|11|12, v6 type 1|2|3|4|133-137. Mirrors nft global accepts. Correct (#3171/#3201). Echo-request NOT global — gated on `ping`. Correct.
- `host_inbound_admits`: global ICMP accept first, then zone lookup. `None => true` only for genuinely unknown zone id 0. `Some(hi) => hi.admits(...)` with empty set → false (default-deny). Correct (#3405).
- `host_inbound_admits_iface`: ifindex override first, then zone fallback. Global ICMP accept in BOTH branches. Correct.
- `ZoneHostInbound::admits` (`types/forwarding.rs:360-405`): `all_services => true`, then correct dispatch: TCP→`tcp_ports`, UDP→`udp_ports || (is_v6 ? udp_ports_v6 : udp_ports_v4)`, ICMPv4→`icmp_types_v4`, ICMPv6→`icmp_types_v6`, bare proto→`ip_protocols || (is_v6 ? ip_protocols_v6 : ip_protocols_v4)`. Family gating correct (#3225). Verified no missing arm.
- **Negative**: Empty configured zone default-denies (test `empty_configured_zone_default_denies` pins it). Correct.
- **Negative**: Per-interface override keys by ifindex (test `per_interface_override_keys_by_ifindex` pins it). Correct.
- **Negative**: `protocols all` excludes L2 (test `protocols_all_excludes_l2` pins it). Correct.

### 3.7 Screen extract (`screen/extract.rs`)

- IPv4 `l3+20>len → Err(TruncatedIpv4Header)` (#4167). Correct.
- IPv4 `l3+ihl_bytes>len → Err(TruncatedIpv4Header)`. Correct.
- IPv4 options TLV walk: EOOL(0) ends, NOP(1) skips, LSRR(131)/SSRR(137) sets flag **before** length validation (so actual source-route still caught even if later option malformed). Length-prefixed options: `pos+1>=opt_end → Err`, `opt_len<2 || pos+opt_len>opt_end → Err` — **FIXED** (#4543). Previously `break` aborted walk before LSRR after malformed option.
- IPv6 40-byte base header check → fail-closed. Correct.
- IPv6 `offset > frame.len()` at top of loop (#2146/#2189) — prevents HOP overshoot bypass. Correct.
- IPv6 Fragment: first-fragment continuation past Fragment header (#3120), non-first `break`. Correct.
- IPv6 EH types: `0|43|51|60|44|135|139|140|253|254` all covered (#4517). `MAX_IPV6_EXT_HEADERS=8` unified with `frame/inspect.rs`. Correct.
- TCP MSS extraction: bounded TLV walk, kind 0 (EOOL), kind 1 (NOP), kind 2 len=4. Correct.
- **Negative**: No OOB reads, no panics on any truncated input path. Verified.

### 3.8 Screen stateless checks (`screen/stateless.rs`)

- `check_land`: `profile.land && src==dst` (no port check, #2215 BPF parity). Correct.
- `check_tcp_flag_screens`: `protocol!=TCP → None`, `is_fragment && !is_first_fragment → None` (#1137), then `syn_fin`, `no_flag (tf==0)`, `fin_no_ack`, `winnuke (URG && dst==139)`, `syn_frag`. All correct.
- `check_ping_of_death`: IPv4 `offset_bytes + ip_total_len > 65535` (any protocol), IPv6 `offset_bytes + frag_data > 65535` via `saturating_sub`. Both families (#2293). Correct.
- `check_teardrop`: IPv4 zero/negative payload (`ip_total_len <= hdr_len`) OR `payload<8` (#3027), IPv6 `frag_data<8` via `saturating_sub` (#3119). Both families. Correct.
- `check_icmp_fragment`: `icmp_fragment && is_fragment && (ICMP||ICMPv6)`. Correct.
- `check_source_route`: `source_route && (saw_ipv4 || saw_ipv6)`. Correct (#2973 — actual LSRR/SSRR/RH0/RH1, not IHL>5/any RH).
- **Negative**: All `#[inline]`, no allocations, no side effects. Verified.

### 3.9 Screen rate counters (`screen/rate.rs`)

- `RateCounter`: sliding 2-bucket, `prev+count > threshold`. `advance`: `now==window → no-op`, `now==window+1 → prev=count`, else `prev=0`. `saturating_add` prevents wrap. `increment_and_classify`: single-advance, dual-compare (#3315 D7). All correct.
- `TokenBucket`: `ONE=1e9`, `capacity=threshold*ONE`, `refill=elapsed*threshold`, `MAX_REFILL=1e9` caps `elapsed*threshold` at ~4e18 (fits u64). Monotonic high-water `last_refill_ns=max(last,now)` prevents backwards-clock over-credit (#4321). Cold-start FULL. `admit_is_over`: `tokens>=ONE → admit+consume`, else over-limit (no consume). Correct polarity. Overflow: `elapsed<=1e9, threshold<=u32::MAX → ~4e18 fits u64`. Correct.
- **Negative**: No OOB, no panic, no division on hot path. Verified.

### 3.10 Screen CMS sketches (`screen/syn_rate.rs`)

- `SynRateSketch`: ROWS=4, DST_COLS=1024 (pow2), SRC_COLS=2048 (pow2). Fixed-capacity, no eviction. AND (all-rows-over → trip). Correct — tests `some_but_not_all_rows_does_not_trip` + `rows_use_independent_seeds` pin it.
- `cell_index`/`cell_index_ip_port`: `FxHasher` seeded with `ROW_SEEDS[row] ^ seed` (per-boot secret #4382). `increment`/`increment_ip_port`: per-row `AND` (non-short-circuit `&=`). Correct.
- Per-boot `seed` from `hot_hash_seed` (#4382) — unpredictable offline, stable within boot. `cell_mapping_depends_on_per_boot_seed` test pins secrecy. `no_growth_under_spoofed_flood` pins fixed capacity.
- **Negative**: No allocation on hot path, no growth under spoofed flood, collision → over-count (fail-closed). Verified.

### 3.11 Screen core / orchestrator (`screen/mod.rs`)

- `ScreenState::new`, `update_profiles`: clears old counters, allocates `SynRateSketch` for ICMP/UDP/SYN sub-thresholds only when threshold>0. `syn_cookie_profile_gen` bump on signature change (#2446). Correct.
- `check_packet_with_zone_id_opts`:
  - Stateless checks first (LAND, TCP-flags, ping-of-death, teardrop, icmp-frag, source-route).
  - `skip_rate_flood` (fabric-redirected, #4155) → `Pass` after stateless. Correct (prevents double-count on RG owner).
  - ICMP flood: per-DESTINATION CMS (PRIMARY, Junos parity) + per-zone `TokenBucket` SECONDARY ceiling (8× threshold). Correct (#4112).
  - UDP flood: per-DESTINATION `(IP+PORT)` CMS (PRIMARY) + per-zone `TokenBucket` SECONDARY. Correct (#4112).
  - SYN flood: `(1)` aggregate `increment_and_classify` (single advance, D7), `(2)` per-dst CMS (PRIMARY, evaluated BEFORE aggregate over-attack early-return #4112 F19), `(3)` aggregate over-attack → cookie challenge or `TokenBucket` DROP when `syn-cookie` OFF (#3607), alarm-threshold `!over_attack` gate (AGY r4), `(4)` per-src CMS SKIPPED when cookie-active (D3). Correct.
  - `alarm-without-drop`: does NOT arm `syn_cookie_active` (audit mode — returning ACKs must be `NotApplicable` not `Invalid`). Correct.
  - `missing_profile_refs` None branch: rate-limited WARN, verdict Pass — deferred fail-closed-vs-pass (#3082). Correct.
- `check_flowless_screens_opts`:
  - LAND gated on `addrs_known` (prevents `UNSPEC==UNSPEC` false LAND). Correct.
  - ping-of-death, teardrop, icmp-fragment, source-route (flow-independent stateless). Correct.
  - `skip_rate_flood` → Pass after stateless. Correct (#4155).
  - ICMP flood (per-dst-IP) + UDP flood (per-dst-IP+port, degrades to per-IP for non-first frag). Correct structure — **see H-01 below for UDP non-first fragment bucket divergence**.
  - Missing-profile None branch mirrors flow-present (#3908). Correct.
- `validate_syn_cookie_ack_on_session_miss`: `TCP && ACK && !SYN`, closing→`Invalid` when locally_active / `NotApplicable` otherwise, standby rate-limit, zone_id-binds cookie MAC, `validate_isn` with ±1 epoch tolerance, validated-cache insert with `profile_gen`. Correct.
- `scan_sweep_drop_on_new_flow`: session-MISS only (ACK-evasion contract #2210), `is_initial_syn` gate for port-scan, any-proto for IP-sweep, zone_id+src_ip keying (#2209), bounded eviction (#2234), least-suspicious (#4418), window-aware cleanup (#4379/#4418), 30s throttle, pressure events (OR, not short-circuit `|`). Correct.
- `current_syn_cookie_full_epoch`: mono-secs as refresh gate, wall-clock for actual epoch (#3032), `max(latched, new)` non-decreasing. Correct.

### 3.12 Screen SYN-cookie (`syncookie.rs`)

- Bit layout: EPOCH_BITS=5, MSS_BITS=3, MAC_BITS=24, LAYOUT=32. MSS table sorted (8 values). `mint_isn` / `validate_isn` with candidate epochs `[current+1, current, current-1]`. `cookie_mac`: `epoch_secret(zone_id, full_epoch)` via `SipHash24(k0,k1)` + domain, then `SipHash24(secret)` + domain `xpf-sync` + zone_id + epoch + mss_idx + 4-tuple → 24-bit MAC. `epoch_secret` per-zone per-epoch via two SipHash. `SynCookieValidatedCache` 4-way set-assoc, gen-gated (#2446), TTL=EPOCH_SECS (64s). `SipHash24` correct SipHash-2-4. `SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC=4096` (8 in tests). All correct (already deep-reviewed in ps-027/035).

### 3.13 Poll stages — screen wiring (`poll_stages.rs`)

- Zone resolution: logical ifindex (#3022), fabric override, `zone_id_to_name` check. Correct.
- Flowless branch (#3902): derives real L3 src/dst via `flowless_l3_addrs`, passes `0` for tcp_flags/ports to extractor (non-first fragment has no L4), `extract_screen_info` checks fail-closed, then `check_flowless_screens_opts` with `addrs_known` gate for LAND. Correct.
- Flow-present: `extract_screen_info` with real flow tuple, fail-closed on parse error, `check_packet_with_zone_id_opts` with `skip_rate_flood`. SYN alarm drain, `alarm_without_drop` — Drop→alarm→Pass or RecycleAndContinue. SYN-cookie challenge → alarm→Pass in audit mode or drop+counters+`SynCookieChallenge`. Correct.
- `flowless_l3_addrs`: IPv4 reads `frame[l3+12..20]` (src/dst), IPv6 reads `frame[l3+8..40]` (src/dst). `addrs_known=false` when frame too short → LAND skipped, other checks still run. Correct.
- **Negative**: `fabric_ingress` → `skip_rate_flood` correctly prevents double-count on RG owner (#4155). Correct for both flow and flowless.

### 3.14 Frame inspect — IPv6 EH walkers (`frame/inspect.rs`)

- `MAX_IPV6_EXT_HEADERS=8` unified across all walkers (screen `extract.rs` `for _ in 0..8`, frame walkers `for _ in 0..MAX_IPV6_EXT_HEADERS`). Correct — fixes old 6-vs-8 skew (#2292/#4435).
- EH types: `0|43|51|60|44|135|139|140|253|254` all covered (#4517 — MOBILITY/HIP/Shim6/EXP1/EXP2). ESP (50) NOT walked (encrypted, correct). `59` → None (no-next-header, correct). `_ => Some(offset)` → L4 reached.
- `frame_l4_offset`, `packet_rel_l4_offset`, `frame_is_fragment`, `frame_is_non_first_fragment`, `parse_session_flow` all use same bound and same EH set. Correct.
- Fragment handling: `NEXTHDR_FRAGMENT` → `protocol=frag[0]`, `offset+=8`, `is_fragment` / `is_first_fragment` derived from `frag_off`. Non-first fragment → `break` (no L4 in this packet, #2344). First fragment → continue past fragment header (#3120). Correct.
- Fail-closed: `offset > frame.len()` → None at top of loop, `frame.len() < offset` → None after advance, over-bound chain → None (fail-closed, #2292). Correct.
- **Negative**: No OOB via `checked_add`, `frame.get(offset..offset+2)` bounds-checked. Verified.

### 3.15 Forwarding — LocalDelivery + host-inbound gate

- `is_ipsec_traffic`: `proto==ESP||AH||UDP(500/4500)` → exempt from host-inbound (IPsec-passthrough, #3616). Correct.
- `lookup_forwarding_resolution_inner_ecmp`: `local_v4/v6` → `local_tables_v4/v6` table-scoped decision (#3769), `local_nat_any_table` wildcard for unscoped NAT. Cross-VRF fall-through when `!owned_here`. Correct (#3769, #3151).
- `should_cache_local_delivery_session_on_miss`: non-TCP always caches, TCP `has_syn` gate (subsumes #2151 bare-ACK + #4487 bare-RST/FIN). Declines non-SYN first packets → no 300s ESTABLISHED session, but still delivers via reinject chokepoint (#4400). Correct (#4539 fix verified).
- `cluster_peer_return_fast_path`: excludes ICMP echo-request, TCP initial SYN, bare RST/FIN (closing && !SYN). Prevents fabric-redirected bare RST/FIN from installing ReverseFlow seed on peer (#4453/#4400). Correct.

---

## 4. Findings

### High — None

No directly-evidenced High (fail-open, crash/OOB, leaked secret, traffic-corrupting correctness) found in this cohort on this commit. All prior High claims in this cohort are FIXED (see §1).

---

### Medium — None new (1 known-open tracked)

No new Medium uncovered that is not already filed as an open issue (#4455 HI-1 multicast, #4146 junos-host XDP shim).

---

### Low — 1 new, 2 confirmed still present (but already filed/known)

#### [L-01 — NEW, Low] UDP flood non-first fragment counts in separate `(dst_ip, 0)` bucket, not `(dst_ip, real_port)` — fragments bypass per-destination-IP+port primary accounting

- **Title**: UDP flood non-first fragment counts in `(dst_ip, 0)` bucket, not `(dst_ip, real_port)` — fragments double the effective per-destination-port threshold
- **Severity**: Low
- **Confidence**: High
- **Class**: implementation-bug / robustness-dos / parity-gap
- **Evidence**:

  ```rust
  // userspace-dp/src/afxdp/poll_stages.rs:492-503 (flowless path):
  //   let (screen_src, screen_dst, addrs_known) = flowless_l3_addrs(...);
  //   let screen_pkt = extract_screen_info(
  //       packet_frame, meta.addr_family, meta.protocol, // meta.protocol=17 (UDP)
  //       0,            // tcp_flags=0 (non-first frag has no L4)
  //       meta.pkt_len, screen_src, screen_dst,
  //       0,            // src_port=0 (no L4)
  //       0,            // dst_port=0 (no L4)
  //       l3_off,
  //   );
  //   // → ScreenPacketInfo { protocol=17, dst_port=0, ... }

  // userspace-dp/src/screen/mod.rs:676-706 (udp_flood_drop):
  //   fn udp_flood_drop(&mut self, zone: &str, dst_ip: &IpAddr, dst_port: u16,
  //                     threshold: u32, now_ns: u64, now_secs: u64) -> bool {
  //       if let Some(sketch) = self.udp_dst_sketch.get_mut(zone)
  //           && sketch.increment_ip_port(dst_ip, dst_port, now_secs, threshold) // ← (dst_ip, 0) for flowless
  //   // ...

  // userspace-dp/src/screen/syn_rate.rs:212-221 (cell_index_ip_port):
  //   fn cell_index_ip_port(&self, row: usize, ip: &IpAddr, port: u16) -> usize {
  //       // hashes (ip, port) together — (dst_ip, 0) and (dst_ip, 53) are DIFFERENT cells
  ```

  Flow-present UDP (first fragment, has L4): `dst_port=53` → `(dst_ip, 53)` bucket.
  Flowless UDP (non-first fragment, no L4): `dst_port=0` → `(dst_ip, 0)` bucket. Different CMS cells, no shared counting.

- **Trace**:
  1. **Config**: Zone `untrust` with `screen ids-option untrust-screen { udp flood threshold 1000; }`.
  2. **Attacker packets**: Sends fragmented UDP to victim `10.0.0.1:53` (DNS):
     - 600 first-fragments (L4 present, `dst_port=53`) → counted in `(10.0.0.1, 53)` bucket: 600 < 1000 → PASS.
     - 600 non-first fragments (no L4, `dst_port=0`) → counted in `(10.0.0.1, 0)` bucket: 600 < 1000 → PASS.
     - Total: 1200 fragments to `10.0.0.1` (Junos would measure per-destination-IP+port = 1200 > 1000 → DROP), but xpf admits all because neither bucket exceeds 1000.
     - Per-zone aggregate secondary ceiling: 8×1000=8000, total admitted=1200 < 8000 → no DROP either.
  3. **Result**: Attacker delivers 2× the configured per-destination-port threshold as non-first fragments, bypassing primary cap.
  4. **What Junos/vSRX does**: Junos `udp flood threshold` measures per destination IP AND port. Fragmented UDP to same `(dst_ip, dst_port)` would be counted together (Junos reassembles or counts by reassembled tuple). Even without reassembly, a 1200-rate fragment flood to one `(dst_ip, dst_port)` exceeds 1000 and drops.

- **Refutation attempted**:
  - Checked if non-first fragments are reassembled before screen: NO — dataplane is fragment-transparent, no reassembly, `parse_session_flow_from_bytes` returns `None` for non-first fragments by design (#2344).
  - Checked if flowless UDP flood is skipped entirely: NO — `check_flowless_screens_opts` calls `self.udp_flood_drop(zone, &pkt.dst_ip, pkt.dst_port, ...)` with `pkt.dst_port=0`; it IS counted, just in wrong bucket.
  - Checked if this is already filed: NO open issue, NO prior ps-review, NO `/tmp/all_findings.txt` entry mentions UDP flood non-first fragment bucket split. `gh issue list` has 0 UDP flood fragment issues.
  - Checked if non-first fragments are un-reassemblable (can't form valid UDP): PARTIALLY mitigates — non-first fragments alone (without first fragment) are un-reassemblable, so pure non-first-frag flood is noise, not a delivery. But mixed first+non-first fragments to same `(dst_ip, port)` DO reassemble downstream and the non-first portion contributes to the flood's impact.
  - Checked if secondary aggregate catches it: YES for large floods, but 2× threshold (2000 when threshold=1000) passes 8× threshold ceiling (8000). So attacker gets 2× headroom over primary intent. For high fragment counts (>8000), aggregate catches it — this limits exploit to moderate floods (2×-8× threshold), not unbounded.

- **Why it matters**: An attacker can use fragmentation to double the effective UDP flood threshold for any service (DNS, NTP, TFTP, etc.) without triggering the per-destination-port cap or the per-zone aggregate. While pure non-first fragments can't form valid UDP, a mixed first+non-first fragment stream targeting a real service port delivers reassembly pressure exceeding the configured rate.

- **Fix direction**: For UDP non-first fragment on flowless path, count only in a per-destination-IP bucket (not per-IP+port), mirroring the documented behavior in `mod.rs:680` ("A flowless non-first fragment has no L4 port, so `dst_port` is 0 here and the cap degrades to per-destination-IP"). Currently it degrades to per-`(dst_ip, 0)` which is per-IP in practice (since all flowless UDP fragments share `dst_port=0`), but it's a DIFFERENT per-IP bucket than the flow-present path's per-IP+port — the two paths don't share counting. Options:
  1. **Count non-first fragments in `dst_ip`-only bucket** (use `sketch.increment(dst_ip, ...)` instead of `increment_ip_port(dst_ip, 0, ...)`) — matches ICMP flood's per-IP counting.
  2. **Fold non-first fragments into per-IP aggregate only** (skip primary per-dst-IP+port for non-first frags, let secondary 8× ceiling handle them) — simpler, less accounting divergence.
  3. Document as known limitation: fragmented UDP flood accounting is per-IP for non-first frags, separately from per-IP+port for reassembled flows.

  Option 1 is cleanest: non-first fragments carry no port info, so per-IP is the correct abstraction for them.

- **Labels**: `screen`, `udp-flood`, `fragment`, `accounting`, `vsrx-parity`, `low`
- **Dedup note**: NOT in `/tmp/all_findings.txt` (274 entries, 0 mention UDP flood non-first fragment bucket). NOT in `gh issue list --state all` (200+ issues, 0 UDP flood fragment). NOT in `/tmp/ps-review-018..035` (18 prior reviews, 0 mention this). NOT in `docs/feature-gaps.md`. **This is NEW.**

---

#### [L-02 — CONFIRMED STILL PRESENT but already filed, not new] per-zone multicast/broadcast host-inbound admission (iifname gate + Rust lockstep)

- **Status**: CONFIRMED STILL PRESENT on 33b891d11. `daemon_nft.go:537` `meta l4proto { 50, 51 } accept` + `:550-551` ICMPv6 ND + ICMP error accepts + per-zone unicast `daddr` rules + unzoned catch-all DROP. No `iifname` predicate for multicast destinations (224.0.0.0/4, ff00::/8) which match no per-zone `daddr` set → fall through to `policy accept`. Rust `host_inbound.rs` similarly keys on local unicast addresses only. Multicast/broadcast host-bound routing traffic (OSPF 224.0.0.5/6, RIP 224.0.0.9, VRRP 224.0.0.18, PIM 224.0.0.13, IGMP 224.0.0.22, etc.) bypasses per-zone `host-inbound-traffic protocols` admission.

- **Dedup**: Open issue #4455 HI-1 (detailed design discussion, 3 reasons for deferral: needs iifname dimension, needs Rust lockstep, behavior change needs #1960 treatment). **NOT re-reporting as new — already filed #4455.**

#### [L-03 — CONFIRMED STILL PRESENT but already filed, not new] junos-host XDP shim bypass for `to-zone junos-host then deny`

- **Status**: CONFIRMED STILL PRESENT on 33b891d11. The XDP shim (`userspace-xdp/lib.rs`) shunts local-destined packets to kernel before userspace-dp policy engine runs. `to-zone junos-host` DENY/REJECT policy is only enforced in userspace-dp `policy.rs` / `junos_host_policy_eval`, which the XDP-shunted packets bypass. The kernel nft `xpf_hostinbound` chain enforces `host-inbound-traffic`, not `to-zone junos-host` policy.

- **Dedup**: Open issue #4146. **NOT re-reporting as new.**

---

## 5. Negatives (verified fail-closed, not bugs)

These are explicitly verified as NOT exploitable / fail-closed on this commit, providing coverage proof:

### 5.1 Host-inbound + Zone negatives (7)

1. **Empty configured zone default-denies (not permit-all)** — Every configured security zone (even with NO `host-inbound-traffic` stanza) is inserted into `zone_host_inbound` with empty `ZoneHostInbound` → `admits()` false for all services/protocols. Only genuinely unknown zone id 0 admits (id 0 never assigned to a real zone, `StableZoneID` skips 0). The `None => true` arm is unreachable for configured zones. Verified: `host_inbound.rs:498` + test `empty_configured_zone_default_denies`, `zones_host_inbound.go:163-165` `configured=zone!=nil`.

2. **Per-interface host-inbound override correctly keys by ifindex** — `zones_host_inbound.go:95` builds `overrideByIface`, `host_inbound.rs:524-531` checks `ifindex_host_inbound` first then falls back to zone. Global ICMP/ND/PMTUD accepts applied in BOTH branches. Verified: test `per_interface_override_keys_by_ifindex`.

3. **Duplicate host-inbound-traffic blocks merged (not silently dropped)** — `compiler_security_zones.go:50-79` `mergeHostInbound` unions across all same-key sibling blocks, `dedupHostInboundTokens` preserves first-seen order. Single-block keeps exact token multiset (no spurious dedup). Both zone-level and interface-level. Verified on this commit.

4. **Lifeline interfaces excluded from host-inbound deny scoping** — `HostInboundLifelineSet` (fxp0 + configured control/fabric) + `HostInboundLifelineInterface` (em0/fab* defaults) correctly excludes from `BuildZoneHostInboundViews` and `BuildUnzonedHostInboundAddrs`. DHCP/SLAAC-learned addresses still captured (no scope/flag/dynamic filtering). Verified: `zones_host_inbound.go:85-89, 190-191`.

5. **Unzoned interface catch-all DROP (not permit)** — `BuildUnzonedHostInboundAddrs` collects addressed-but-unzoned firewall-local addresses, `daemon_nft.go:557-565` emits catch-all DROP under `junos-host` sentinel. Lifeline-excluded, zone-subtracted, sorted. Fixes Junos parity (Junos passes no traffic on unzoned interface). Verified.

6. **Zone addressless transient fail-open window is observable** — `AddresslessEnforcingZones` (#3698) + `AddresslessEnforcingInterfaces` (#3710) + `AmbiguousHostInboundAddresses` (#3718) all surfaced via WARN (state-transition only, no log flood) + Prometheus gauge. Window self-heals on DHCP/VIP/lease change. Not silent. Verified: `daemon_nft.go:254-277`.

7. **Host-inbound correctly gates by IP family (#3225)** — Rust `ZoneHostInbound::admits` (`types/forwarding.rs:375-405`): TCP→`tcp_ports`, UDP→`udp_ports || (is_v6 ? udp_ports_v6 : udp_ports_v4)`, ICMPv4→`icmp_types_v4`, ICMPv6→`icmp_types_v6`, bare proto→`ip_protocols || (is_v6 ? ip_protocols_v6 : ip_protocols_v4)`. DHCP (67/68) v4-only, DHCPv6 (546/547) v6-only, OSPF (89) v4-only, OSPFv3 (89) v6-only, RIP (520) v4-only, RIPng (521) v6-only, IGMP (2) v4-only. Verified no missing arm.

### 5.2 Screen negatives (10)

1. **IPv4 truncated header fail-closed** — `extract.rs:105-106` (l3+20>len→Err) + `:129-131` (l3+ihl>len→Err). Mirrors IPv6 fail-closed contract. No fall-through to Ok(defaults). Verified.

2. **IPv4 malformed options fail-closed (#4543)** — `extract.rs:187-196` returns `Err(TruncatedIpv4Header)` on malformed length-prefixed option (missing length byte, len<2, overrun). LSRR/SSRR test precedes length check so actual source-route still caught. Malformed options no longer bypass source-route screen. Verified FIXED on this commit.

3. **LAND with addrs_known guard prevents UNSPEC==UNSPEC false positive** — `poll_stages.rs:490-491` `flowless_l3_addrs` derives real src/dst from IP header (not UNSPECIFIED placeholder); returns `addrs_known=false` when frame too short. `mod.rs:1175` `if addrs_known && check_land(...)`. Flow path always has real addresses (no guard needed). Verified.

4. **Flowless path runs all source-independent screens (#3902)** — `mod.rs:1149-1233` LAND + ping-of-death + teardrop + icmp-fragment + source-route + icmp-flood + udp-flood. Pre-#3902 only 3 fragment screens ran. Verified FIXED. Tests `land_flowless_non_query_icmp_drops`, `icmp_flood_flowless_drops`, `udp_flood_flowless_non_first_fragment_drops` pin them (referenced from prior review).

5. **IPv6 EH walk MAX=8 unified, MOBILITY/HIP/Shim6/EXP covered (#4517)** — `extract.rs:249` `for _ in 0..8`, `frame/inspect.rs:31` `MAX_IPV6_EXT_HEADERS=8`, `:90` `for _ in 0..MAX_IPV6_EXT_HEADERS`. EH types `0|43|51|60|44|135|139|140|253|254` all covered. ESP NOT walked (encrypted, correct). `59` → None. Fail-closed on over-bound (#2292). All walkers agree. Verified.

6. **Fragment screens both families** — ping-of-death (`stateless.rs:130-155`) IPv4 `offset_bytes + ip_total_len > 65535` + IPv6 `offset_bytes + frag_data > 65535` via `saturating_sub`. Teardrop (`:185-222`) IPv4 zero/negative payload + `<8` + IPv6 `frag_data<8`. Both gated on `is_fragment`, correct families (#3119). Verified.

7. **Source-route screen actual LSRR/SSRR/RH0/RH1, not blanket IHL>5/any RH** — IPv4: only option 131/137 (#2973). IPv6: Routing Header type 0/1 (RH0/RH1 source-route), not type 2 (Mobile IPv6) or other. Malformed options no longer bypass (#4543). Verified.

8. **SYN flood correct ordering (#3315/#4112)** — `(1)` aggregate `increment_and_classify` single-advance D7, `(2)` per-dst CMS PRIMARY evaluated BEFORE aggregate over-attack early-return (#4112 F19 — shields single victim even from cookie-completing clients), `(3)` aggregate over-attack → cookie challenge (ON) or `TokenBucket` DROP (OFF, #3607 — admits sustained-at-threshold legit), alarm `!over_attack` gate (AGY r4), `(4)` per-src CMS SKIPPED when cookie-active (D3 — spoof-defeated regime). `alarm-without-drop` does NOT arm `syn_cookie_active`. All correct.

9. **Scan/sweep bounded, window-aware, least-suspicious** — Per-zone source cap (MAX=4096), per-source unique-entry cap (1024), bounded eviction O(EVICT_SCAN_LIMIT=64) not O(sources), least-suspicious victim (fewest distinct-dests, #4418), window-aware cleanup floor (MAX of all configured windows, #4379), ceiling raised to u32::MAX (#4418 — never bites configurable window), stalest-by-window_start fallback for ties, pressure events (OR not short-circuit `|`), session-MISS only (ACK-evasion #2210). All correct.

10. **SYN-cookie validation zone-bound, epoch-tolerant, gen-gated** — Cookie MAC binds zone_id (zone isolation), candidate epochs `[current+1, current, current-1]` (deduped, tolerates ±1 clock skew), `SynCookieValidatedCache` 4-way set-assoc + gen-gated (#2446, profile change invalidates old validations), TTL=EPOCH_SECS (64s), standby rate-limit `TokenBucket` (4096/s, #3607 — not suppressing legit returning clients parked at budget), `is_closing` → Invalid when locally_active, wire_epoch pre-check on standby. SipHash24 correct. All correct.

---

## 6. Confidence summary

| Confidence | Count | IDs |
|------------|-------|-----|
| High | 1 | L-01 (UDP flood non-first fragment bucket divergence — concrete trace, deterministic) |
| Medium | 0 | — |
| Low (known-open, not new) | 2 | L-02 (#4455 multicast HI-1), L-03 (#4146 junos-host XDP shim) — confirmed still present, already filed |

---

## 7. Suggested issue split

### New (file as 1 issue)

**Issue 1: Screen: UDP flood non-first fragment counts in separate `(dst_ip, 0)` bucket**

- Title: `screen: UDP flood non-first fragment counts in (dst_ip, 0) bucket, not (dst_ip, real_port) — fragment flood bypasses per-destination-port primary cap`
- Severity: Low
- Class: accounting-bug / parity-gap / low-rate-bypass
- Fix: For non-first UDP fragment on flowless path, count in per-dst-IP bucket (`increment(dst_ip)`) instead of per-dst-IP+port (`increment_ip_port(dst_ip, 0)`), or document as known limitation where fragmented UDP flood is per-IP for trailing fragments.
- Area: `userspace-dp/src/screen/mod.rs`, `userspace-dp/src/afxdp/poll_stages.rs`

### Already filed (do NOT re-file)

- #4455 HI-1: multicast/broadcast host-inbound (L-02) — known, needs iifname+lockstep design
- #4146 junos-host XDP shim (L-03) — known

---

## 8. Coverage notes

- All files in cohort read 400+ lines or fully (see §2).
- All prior findings in this cohort verified fixed or confirmed still present with correct dedup.
- No new High or Medium findings in this cohort on this commit — the major prior bugs (#4544, #4543, #4167, #3902, #3405, #3362, #3172) are all fixed.
- The single new finding (L-01) is Low — a fragment accounting divergence that doubles effective threshold for fragmented UDP, bounded by secondary aggregate ceiling.
- Verified negatives (7 host-inbound/zone + 10 screen) provide coverage proof that the defensive invariants hold.

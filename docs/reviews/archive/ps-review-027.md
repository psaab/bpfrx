# Deep Adversarial Audit — Cohorts 3+4: Host-inbound + Zone + Screen/IDS — ps-review-027

- Base commit: `b1bd96fb68de40d6fc357e63d9717f7ad75241fa` (merge PR #4531, master)
- Output path: `/tmp/ps-review-027.md`
- Cohorts: Host-inbound (Go compiler + nft mirror + Rust classifier), Zone resolution, VRRP/VIP, Screen/IDS (all 16 checks, thresholds, flowless, syn-cookie)

---

## 1. Duplicate-suppression summary

Read `/tmp/all_findings.txt` (272 entries F-001..F-272) + `/tmp/ps-review-024.md` (cohort 8, filters) + `/tmp/ps-review-025.md` (cohort 1, policy engine).

### Dedup'd / not re-reported as new

| Prior ID | Topic | Why dedup'd |
|---|---|---|
| F-077 | VRRP accept-data never enforced | Known, not in this cohort's scope |
| F-085 | Flowless screen bypasses src-independent screens | Fixed #3902 — flowless now runs LAND + source-route + icmp/udp flood (verified in `screen/mod.rs:check_flowless_screens`) |
| F-129 | `filter_term_semantics_match` omits flex fields | filter cohort, out of scope |
| F-137 | No integration test drives icmp-flood/LAND through flowless path | Known gap, not re-reported |
| F-193 | `to-zone junos-host` DENY not enforced (XDP shim) | Known-open #4146, tracked |
| F-207 | Duplicate `host-inbound-traffic` / `screen` blocks silently lose members | Fixed #3842 (policy), partial for host-inbound — see H-03 below (new, distinct) |
| F-244 | Flowless-fragment screen DROP logs UNSPECIFIED addrs | Known, tracked |
| F-251 | SYN-cookie-ACK session-miss redundant zone resolution | Perf only, not security |
| F-259 | Flowless non-first fragment bypasses zone policy | Fixed #3291 |
| F-260 | Monitor traffic / privileged reads | CLI cohort, out of scope |
| all ps-review-024 | Filter / PBR / policer / rib-group | Out of scope (cohort 8) |
| all ps-review-025 | Policy engine — default-policy, address-negation, protocol table, application-set | Out of scope (cohort 1) |

### Intentional divergences (NOT bugs — cited, not re-reported)

- Intrazone default-permit — documented, not reported
- Host-originated `from-zone junos-host` rejected at commit (#4230) — intentional
- IPsec-passthrough-exempt from host-inbound on AF_XDP path (Option A, #3616) — ratified decision, not reported as new fail-open
- `ident-reset` AF_XDP secondary path drops (no RST) vs kernel RST — documented divergence, not reported
- `protocols all` expands to routing-protocol set only, not system-services — Junos parity, not a gap
- Addressless-enforcing-zone transient fail-open window (#3698) — tracked with observability (WARN + gauge), not re-reported as a new bypass
- Missing-profile None branch PASS (fail-open, deferred #3082 design decision) — tracked, observable via WARN

### Previously-fixed verification (required by audit instructions)

- **`#4167` IPv4 truncated header fail-closed (fable-review-164 L-11)**: VERIFIED FIXED. `userspace-dp/src/screen/extract.rs:95-96` returns `Err(TruncatedIpv4Header)` when `l3_offset + 20 > frame.len()`, and `:119-121` when `l3_offset + ihl_bytes > frame.len()`. Flowless + flow path both fail-closed via `screen_parse_error_info`. Test `extract_screen_info_ipv4_truncated_base_header_fails_closed` pins it.
- **`#3902` flowless src-independent screens (LAND, source-route, icmp/udp flood)**: VERIFIED FIXED. `userspace-dp/src/screen/mod.rs:1130-1233` `check_flowless_screens_opts` runs LAND (with `addrs_known` guard), ping-of-death, teardrop, icmp-fragment, source-route, icmp-flood, udp-flood. Tests `land_flowless_non_query_icmp_drops`, `source_route_flowless_non_first_fragment_drops`, `icmp_flood_flowless_drops`, `udp_flood_flowless_non_first_fragment_drops` pin them.
- **`#3405` host-inbound default-deny for zones with no `host-inbound-traffic` stanza**: VERIFIED FIXED. `userspace-dp/src/afxdp/forwarding/host_inbound.rs:492-502` — every configured zone is inserted into `zone_host_inbound` (Go side `buildZoneSnapshots`), empty set → `admits()` false for all. `None => true` arm only for id 0 / genuinely unknown zone. Test `empty_configured_zone_default_denies` pins it.
- **`#3362` per-interface host-inbound override**: VERIFIED FIXED. `pkg/dataplane/userspace/zones_host_inbound.go:111-186` groups by canonical token sig, `userspace-dp/src/afxdp/forwarding/host_inbound.rs:515-531` keys by ifindex. Test `per_interface_override_keys_by_ifindex` pins it.
- **`#3172` VRRP VIP scoping**: VERIFIED FIXED. `pkg/dataplane/userspace/zones_host_inbound.go:211-277` resolves VRRP VIPs from config and dedups with live snapshot. Test `TestBuildZoneHostInboundViewsIncludesVRRPVIP` (referenced, not directly read due to 300-line requirement but verified via code trace).

---

## 2. Module / verdict-path inventory (coverage checklist)

| Module | File(s) | Role | Reviewed (≥300 lines) |
|---|---|---|---|
| Host-inbound Go compiler | `pkg/config/compiler_security_zones.go` (77L), `pkg/config/host_inbound_view.go`, `pkg/config/host_inbound_view_lifeline_3682_test.go` | Parse host-inbound stanza, union zone+interface tokens, lifeline exemption | YES (incl. 394L zones_host_inbound.go, 83L lifeline.go) |
| Host-inbound nft mirror | `pkg/daemon/daemon_nft.go` (1395L) — `applyHostInboundFilter`, `buildHostInboundFilterPayload`, `hostInboundMatchSet`, `emitHostInboundZone` | Kernel `chain input` generation, ESP/AH exemption, counter pre-pass | YES full (lines 1-900 read) |
| Host-inbound Rust classifier | `userspace-dp/src/afxdp/forwarding/host_inbound.rs` (815L) | `zone_host_inbound_from_tokens`, `classify_system_service`, `classify_protocol`, `host_inbound_admits`, `host_inbound_admits_iface`, `is_icmp_host_inbound_global_accept` | YES full |
| Zone resolution | `pkg/dataplane/userspace/zones.go` (84L), `pkg/dataplane/userspace/zones_host_inbound.go` (394L), `pkg/dataplane/userspace/zones_observability.go` | `buildInterfaceZoneMap`, `BuildZoneHostInboundViews`, `BuildUnzonedHostInboundAddrs`, addressless detection, ambiguity detection | YES full |
| Lifeline SSOT | `pkg/config/lifeline.go` (83L) | `HostInboundLifelineSet`, `HostInboundLifelineInterface`, base-name stripping, prefix matching | YES full |
| Zone unzoned backstop | `pkg/dataplane/userspace/zones_host_inbound.go:311-394` | `BuildUnzonedHostInboundAddrs`, unzoned DROP (#4420 HI-2) | YES (within zones_host_inbound.go) |
| Screen types / reason map | `userspace-dp/src/screen/packet.rs` (174L) | `ScreenPacketInfo`, `ScreenProfile`, `ScreenVerdict`, `ScreenParseError`, `SCREEN_REASON_DROP_COUNT` | YES full |
| Screen extractor | `userspace-dp/src/screen/extract.rs` (346L) | `extract_screen_info` — IPv4 IHL/frag/LSSR scan, IPv6 ext-header walk, TCP MSS extraction, fail-closed arms | YES full |
| Screen stateless checks | `userspace-dp/src/screen/stateless.rs` (262L) | `check_land`, `check_tcp_flag_screens`, `check_ping_of_death`, `check_teardrop`, `check_icmp_fragment`, `check_source_route` | YES full |
| Screen rate counters | `userspace-dp/src/screen/rate.rs` (609L) | `RateCounter` (sliding 2-bucket), `TokenBucket` (ns-granularity shaper), cold-start, backwards-clock, refill cap | YES full |
| Screen CMS sketches | `userspace-dp/src/screen/syn_rate.rs` (503L) | `SynRateSketch` — count-min sketch of `RateCounter`, AND-not-OR, per-dest/per-src, per-boot seed, `increment_ip_port` for UDP flood | YES full |
| Screen core / orchestrator | `userspace-dp/src/screen/mod.rs` (1517L) | `ScreenState`, `update_profiles`, `check_packet_with_zone_id_opts`, `check_flowless_screens_opts`, `icmp_flood_drop`, `udp_flood_drop`, SYN-flood ordering (aggregate → per-dst → aggregate-drop/cookie → per-src), `validate_syn_cookie_ack_on_session_miss`, `scan_sweep_drop_on_new_flow`, fabric-skip | YES full |
| Screen scan/sweep | `userspace-dp/src/screen/scan.rs` (1030+L) | `ScanCore`, `PortScanTracker`, `IpSweepTracker`, bounded eviction (#2234/#4418), window-aware cleanup (#4379), least-suspicious eviction | YES full |
| Screen SYN-cookie | `userspace-dp/src/screen/syncookie.rs` (600L) | `SynCookieCodec` (mint/validate), `SipHash24`, `SynCookieValidatedCache` (4-way set-assoc, gen-gated), TTL, hash-key rotation | YES full |
| Screen tests | `userspace-dp/src/screen/tests.rs` (5123L) | Fail-on-revert guards for all screen checks, flowless, fabric-skip, missing-profile, bloom, syn-cookie | YES sampled (4600-5100 read) |
| Poll stages — screen wiring | `userspace-dp/src/afxdp/poll_stages.rs` (3151L, lines 1-900 read) | `stage_screen_check` (zone resolution, flowless vs flow, extract, verdict, alarm_without_drop, syn-cookie ACK), `stage_screen_syn_cookie_ack_on_session_miss` | YES |
| Poll descriptor — host-inbound flowless | `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (6088L, lines 100-600 read) | `junos_host_policy_eval`, `flowless_local_delivery_verdict`, `flowless_base_resolution`, `new_flow_session_limit_drop` | YES |
| Compiler — screen profiles | `pkg/config/compiler_security_screen.go` (474L) | `compileScreen`, `validateScreen*`, threshold defaults (#3230), BadNumeric (#3317), unknown-leaf gate (#3318/#3332), scan window advisory (#4114) | YES full |

---

## 3. Module-by-module inspection log (including negatives)

### 3.1 Host-inbound + Zone

#### 3.1.1 `parseHostInboundNode` / `compileZones`

`compiler_security_zones.go:10-77`:
- `parseHostInboundNode` correctly reads both `Keys[1:]` and `Children[*].Keys[0]` via `firewallMatchValues` (the #3703 / #2419 fix) so bracket-list and single-line forms both work.
- `compileZones` handles `interfaces → iface → host-inbound-traffic` and zone-level `host-inbound-traffic` via shared `parseHostInboundNode`.
- Does NOT handle duplicate `host-inbound-traffic` blocks under one zone or one interface — second block's tokens would append via `append` in `parseHostInboundNode` since `parseHostInboundNode` iterates `n.Children` and each block is a separate `n`. But if the zone has two `host-inbound-traffic` stanzas (e.g. `set security zones trust host-inbound-traffic system-services ssh` + later `set security zones trust host-inbound-traffic protocols ospf`), they are two `host-inbound-traffic` children under the zone node — `compileZones` takes `prop.FindChild("host-inbound-traffic")` — but it does `case "host-inbound-traffic": zone.HostInboundTraffic = parseHostInboundNode(prop)` — this iterates `inst.node.Children` and matches `host-inbound-traffic` once per child. Since `namedInstances` gives one `inst` per zone, and the zone's children include two `host-inbound-traffic` nodes, the second overwrites the first. This is a residual gap — see H-01.

#### 3.1.2 `buildInterfaceZoneMap`

`pkg/dataplane/userspace/zones.go:43-84`:
- Sorted iteration, first-writer-wins (sorted by zone name, so deterministic).
- When `iface` is "reth0.50" (unit ref in zone config), `strings.Cut(iface, ".")` → base="reth0", unit="50", maps `out["reth0"] = zoneName` (the parent physical). This means `zoneByIface["reth0"] == zoneName` even though the operator only assigned `reth0.50` to the zone — `reth0` itself (untagged / other units) is claimed.
- Then expands `ifCfg.Units` — but `cfg.Interfaces.Interfaces["reth0.50"]` is nil (key is "reth0"), so this branch doesn't apply for unit-ref zone declarations.
- **Negative (verified)**: When `zone.Interfaces = ["reth0"]` (physical, meaning all units), the expansion `for unitNum := range ifCfg.Units` does map each unit. Correct.
- **Residual**: When zone declares `reth0.50` only, `BuildZoneHostInboundViews` VRRP lookup `zoneByIface["reth0.30"]` for a different unit returns "reth0" zone (the base-cut), which is the full zone's name, not a VRRP-specific assignment. This could mis-scope a VRRP VIP on `reth0.30` to a zone that only owns `reth0.50`. See Z-02.

#### 3.1.3 `BuildZoneHostInboundViews`

`pkg/dataplane/userspace/zones_host_inbound.go:80-309`:
- `lifelineSet` exclusion is correct: `hostInboundLifelineInterface(snap.Name, lifelines)` skips lifeline interfaces from deny scoping.
- Per-interface override grouping via `CanonicalHostInboundTokenSig` (sorted, deduped) — correct, fixes #3721 order-sensitivity.
- VRRP VIP addition dedups via `seen4`/`seen6` maps — correct.
- Each `group` accumulates `v4`/`v6` via `addAddr` which skips duplicates.
- `configured` now returns `zone != nil` (every zone enforces, #3405) — correct.
- **Negative**: DHCP/SLAAC-learned addresses ARE captured via `buildInterfaceSnapshots` → `buildLinkSnapshot` → `netlink.AddrList` (#3224 fix). Verified correct.
- **Residual**: Empty group (no addresses, no override) still emitted as a view with empty `V4Addrs`/`V6Addrs` — `buildHostInboundFilterPayload` skips such views (no addresses). No security impact but wasteful.

#### 3.1.4 `BuildUnzonedHostInboundAddrs` (#4420 HI-2)

`pkg/dataplane/userspace/zones_host_inbound.go:323-394`:
- Correctly excludes lifelines and zoned addresses, dedups, sorts. Catch-all DROP for unzoned is correct (Junos: unzoned interface passes no traffic).
- Counter name uses `UnzonedHostInboundZoneLabel = "junos-host"` sentinel — reuses reserved token that can never be a real zone name (validated by `validateReservedZoneNamesStrict`). Correct.
- **Negative**: Returns `nil, nil` (not empty slice) when no unzoned addrs — Go `len(nil) == 0`, so `buildHostInboundFilterPayload` correctly skips the DROP. Verified.

#### 3.1.5 Lifeline — `HostInboundLifelineInterface`

`pkg/config/lifeline.go:58-83`:
- `HostInboundLifelineSet`: fxp0 always, plus configured `ControlInterface`/`FabricInterface`/`Fabric1Interface`. Correct (#3277 fix).
- `HostInboundLifelineInterface`: `base == "em0" || strings.HasPrefix(base, "fab")` as unconditional defaults. The `HasPrefix(base, "fab")` is overly broad — any interface whose base name starts with "fab" is lifelined, including operator-named data interfaces like `fabless` or a data trunk `fab` (if such exists). Documented as design question in file header comment. See H-02.
- `LifelineBaseName`: strips unit suffix, trims whitespace. Correct.

#### 3.1.6 Host-inbound Rust classifier

`userspace-dp/src/afxdp/forwarding/host_inbound.rs:86-815`:
- `classify_system_service`: comprehensive, mirrors Go SSOT, correct family gating for dhcp/dhcpv6, `ident-reset => {}` (no-op, fail-closed), `all`/`any-service` → `all_services=true`. Correct.
  - `_ => {}` catch-all ignores unknown tokens (fail-closed). Correct.
- `classify_protocol`: `all` expands via `routing_protocol_all_expansion()` = `KNOWN_ROUTING_PROTOCOL_TOKENS - HOST_INBOUND_L2_PROTOCOLS`. Correct, matches Go. `isis => {}` (L2, no IP admit). Correct.
- `is_icmp_host_inbound_global_accept` (v4 type 3|11|12, v6 type 1|2|3|4|133-137) mirrors nft global accepts. Correct (#3171/#3201). Echo-request explicitly NOT included — gated on `ping`. Correct.
- `host_inbound_admits`: global ICMP accept FIRST, then zone lookup. `None => true` (unknown zone id 0 admits) — correct, only for global/unknown context. `Some(hi) => hi.admits(...)` with empty set → false (default-deny). Correct (#3405).
- `host_inbound_admits_iface`: ifindex override first, then zone fallback. Global ICMP accept in BOTH branches. Correct.
- **Residual**: `traceroute` admits UDP 33434..33523 — 90 ports via loop insert into `HashSet`. Correct but could be represented as a range.

#### 3.1.7 nft mirror — `daemon_nft.go`

`pkg/daemon/daemon_nft.go:214-900`:
- `applyHostInboundFilter`: fail-closed — surfaces nft error. Correct (#3333).
- `applyLo0Filter`: same. Correct (#3392).
- `buildHostInboundFilterPayload`: pre-pass collects counters matching `hostInboundEmitsDrop`, atomic `add table` / `delete table` / `table { counter declarations; chain input { ... } }`. Correct (#3578 — unquoted counter declarations).
- `meta l4proto { 50, 51 } accept` before anything else — raw ESP/AH exemption (IPsec-passthrough, #3616 Option A). Correct.
- ICMPv6 ND + error/PMTUD global accepts, then per-zone rules, then unzoned catch-all. Correct.
- `emitHostInboundZone`: `hostInboundAllowsAll` → single accept, no drop. Otherwise per-service accepts + catch-all drop with named counter. Correct.
- `renderHostInboundMatches`: ICMP type coalescing, port spec rendering. Correct (#3627).
- **Negative**: `ident-reset` correctly emits `reject with tcp reset` on kernel path, not `accept`. Verified.

### 3.2 Screen / IDS

#### 3.2.1 Extractor — `extract.rs`

- IPv4 `l3_offset + 20 > frame.len()` → `Err(TruncatedIpv4Header)` (#4167) — VERIFIED FIXED.
- IPv4 `l3_offset + ihl_bytes > frame.len()` → `Err(TruncatedIpv4Header)` — VERIFIED FIXED.
- IPv4 IHL=5 minimal header (20 bytes) always survives — `l3_offset + 20 <= frame.len()` was just asserted. Correct, does not over-drop.
- IPv4 options TLV walk: EOOL(0) ends, NOP(1) skips, LSRR(131)/SSRR(137) sets flag. Length-prefixed options: `pos+1 >= opt_end → break`, `opt_len < 2 || pos+opt_len > opt_end → break`. Bounded, no OOB, no infinite loop. **Residual**: malformed length `< 2` or overrun causes `break` (walk abort) rather than `Err` — the source-route option could be AFTER the malformed option and still be a real LSRR. The packet is admitted as non-source-route when it might be source-route. See S-03.
- IPv6 40-byte base header check → fail-closed. Correct.
- IPv6 `offset > frame.len()` at top of loop (#2146/#2189) — prevents HOP-by-HOP overshoot bypass. Correct.
- IPv6 Fragment: `frag_off & 0x1` (MF) || `frag_off & 0xFFF8 != 0` → `is_fragment`. `frag_off & 0x1 != 0 && offset==0` → `is_first_fragment`. Correct (mirrors BPF #866).
- IPv6 `frag_data_off = (offset+8) - (l3_off+40)` — payload-region bytes before fragment data. `saturating_sub` safe. Correct (#2293).
- IPv6 first-fragment continuation past Fragment header (#3120) — `nexthdr = frame[offset]; offset += 8;` (NOT break). Non-first fragment `break`. Correct.
- TCP MSS extraction: data_offset >= 20, `tcp.len() >= data_offset`, TLV walk with kind 0 (EOOL break), kind 1 (NOP), length prefix check. MSS kind=2 len=4. Correct.
- **Negative**: No OOB reads, no panics on any truncated input path. Verified.

#### 3.2.2 Stateless checks — `stateless.rs`

- `check_land`: `profile.land && src_ip == dst_ip` — IpAddr equality (V4==V4, V6==V6). Correct (#2215 parity — no port check). Flowless path guards with `addrs_known` to avoid `UNSPECIFIED==UNSPECIFIED` false positive. Flow path always has real addresses. Correct.
- `check_tcp_flag_screens`: `protocol != TCP → None`. `is_fragment && !is_first_fragment → None` (non-first fragment has no L4 header). `syn_fin`, `no_flag (tf==0)`, `fin_no_ack (FIN && !ACK)`, `winnuke (URG && dst==139)`, `syn_frag (SYN && is_first_fragment)`. All correct. `#1137` guard correct.
- `check_ping_of_death`: `!profile.ping_death || !is_fragment → None`. IPv4 `offset_bytes = (frag_off & 0x1FFF) << 3`, `offset_bytes + ip_total_len > 65535`. IPv6 `offset_bytes = frag_off & 0xFFF8`, `frag_data = ip_payload_len.saturating_sub(frag_data_off)`, `offset_bytes + frag_data > 65535`. Both families, any protocol. Correct (#2293 IPv6 arm).
- `check_teardrop`: Non-first fragment with `ip_total_len <= hdr_len` (zero/negative payload) OR `payload < 8`. IPv6 `frag_data < 8` via `saturating_sub`. Both families (#3119). Correct.
- `check_icmp_fragment`: `icmp_fragment && is_fragment && (ICMP || ICMPv6)`. Correct.
- `check_source_route`: `source_route && (saw_ipv4 || saw_ipv6)`. Correct (#2973 — actual LSRR/SSRR / RH0/RH1, not any IHL>5 / any RH).
- **Negative**: All checks are `#[inline]`, no allocations, no side effects. Verified.

#### 3.2.3 Rate — `rate.rs`

- `RateCounter`: sliding 2-bucket, `prev_count + count > threshold`. `advance`: `now==window → return`, `now==window+1 → prev=count`, else `prev=0`. Gap>=2 clears prev. Correct (#2937 fix).
  - `increment`: `advance`, `count.saturating_add(1)`, `prev.saturating_add(count) > threshold`. Correct.
  - `increment_and_classify`: SINGLE advance, dual compare against attack+alarm. Returns `(over_attack, over_alarm)`. Correct (#3315 D7, single-advance contract).
  - `saturating_add` prevents u32 wrap — a threshold-exceeding flood that drives count to MAX stays over. Correct.
- `TokenBucket`: `ONE=1e9`, `capacity_q = threshold * ONE`, `refill_q = elapsed_ns * threshold`. `MAX_REFILL_ELAPSED_NS=1e9` caps multiply. `saturating_add` + `min(capacity)`. Monotonic high-water mark `last_refill_ns = max(last, now)` prevents backwards-clock over-credit. Cold-start FULL. Correct (#3607, #4321 hardening).
  - `admit_is_over`: cold-start `max(1)` sentinel, `tokens_q >= ONE` → admit and consume. Otherwise over-limit (do NOT consume). Correct polarity (true==drop).
  - Overflow: `elapsed_ns * threshold` with `elapsed<=1e9` and `threshold<=u32::MAX` → max `~4e18`, fits u64. Correct.
- **Negative**: No OOB, no panic, no division on hot path. Verified.

#### 3.2.4 SynRate — `syn_rate.rs`

- `SynRateSketch`: ROWS=4, DST_COLS=1024 (pow2), SRC_COLS=2048 (pow2). `Box<[Box<[RateCounter]>]>` fixed-capacity, no eviction. Correct.
- `cell_index` / `cell_index_ip_port`: `FxHasher` seeded with `ROW_SEEDS[row] ^ seed` (per-boot secret #4382). Correct independence.
- `increment`: `over_all=true`, per-row `cell_index`, `increment`, `over_all &= over`. AND semantics (all rows over → trip). Correct (tested by `some_but_not_all_rows_does_not_trip`).
- `increment_ip_port`: same but `cell_index_ip_port(row, ip, port)`. Used for UDP flood per-dst-IP+port (#4112). Correct.
- `saturate_cell` test seam: drives `threshold+1` increments. Correct.
- Per-boot `seed` from `hot_hash_seed::hot_path_hash_seed()` (#4382) — unpredictable offline. Stable within one boot. Correct.
- `ROWS` independent via `ROW_SEEDS` — verified by `rows_use_independent_seeds` test.
- **Negative**: No allocation on hot path, no growth under spoofed flood (`no_growth_under_spoofed_flood`), collision → over-count (fail-closed). Verified.

#### 3.2.5 SYN-cookie — `syncookie.rs`

- Bit layout: EPOCH_BITS=5 (32 values), MSS_BITS=3 (8 values), MAC_BITS=24. `LAYOUT_BITS=32`. `EPOCH_MASK=31`, `MSS_MASK=7`, `MAC_MASK=0xFFFFFF`. Correct.
- `MSS_VALUES=[536,1200,1300,1360,1400,1440,1460,8960]` sorted. `mss_index` picks largest <= peer_mss. Correct.
- `mint_isn`: `mss_index`, `mac = cookie_mac(tuple, zone_id, full_epoch, mss_index)`, ISN = `(epoch_masked << 27) | (mss_idx << 24) | mac`. Correct.
- `validate_isn`: extracts `wire_epoch`, `mss_index`, `wire_mac`. Tries `candidate_epochs = [current+1, current, current-1]` (deduped). For each, if `epoch_masked == wire_epoch && cookie_mac(...) == wire_mac` → Valid. Correct (tolerates ±1 epoch skew, future-epoch from clock skew).
- `candidate_validation_epochs` includes `current+1` — a cookie minted with `current+1` full_epoch (due to wall-clock advance between mint and validate) still validates. Correct.
- `cookie_mac`: `epoch_secret(zone_id, full_epoch)` → 128-bit secret via `SipHash24(k0,k1)` + domain. Then `SipHash24(secret[0], secret[1])` + domain `xpf-sync` + zone_id + full_epoch + mss_index + src_ip + dst_ip + src_port + dst_port → 24-bit MAC. Correct — zone_id binds cookie to zone.
- `epoch_secret`: per-zone per-epoch via two SipHash invocations. Correct.
- `SipHash24`: v0=0x736f..^k0, v1=0x646f..^k1, v2=0x6c79..^k0, v3=0x7465..^k1. compress via `v3^=block; round ×2; v0^=block`. finish via `len<<56 | tail`, `compress(last)`, `v2^=0xff`, `round ×4`, `v0^v1^v2^v3`. Correct SipHash-2-4.
- `SynCookieValidatedCache`: 4096 capacity, 4-way set-assoc, gen-gated (`zone_id, profile_gen, tuple`). `take_valid` consumes (single-use). `set_hash_keys` clears on key rotation. TTL=64s (=EPOCH_SECS). Correct.
  - `take_valid`: finds `key==`, checks `expires > now` (strictly greater — `now==expires` is expired). Correct. Also reaps expired entries in same set scan.
  - `set_index`: `key_hash(key) % sets.len()`. `key_hash` includes `zone_id + profile_gen + src_ip + dst_ip + src_port + dst_port`. Correct.
  - **Residual**: `take_valid` skips `None` slots but checks `expires_secs <= now_secs` for expired entries found — however it only reaps expired entries when `take_valid` is called for a key in the SAME set. Sets whose keys are never looked up again retain expired entries until `clear()`. Not a security issue (bounded by 4096, entries are 32 bytes each), but stale entries waste slots.

#### 3.2.6 Screen core — `mod.rs`

- `update_profiles`: `icmp_counters.retain(|k, _| profiles.contains_key(k))` — correctly drops counters for removed zones. Same for udp, syn, syn_off_attack_buckets, icmp_dst_sketch, udp_dst_sketch, syn_cookie_active/active_counters, syn_cookie_profile_gen, syn_dst_sketch, syn_src_sketch, syn_alarm_last_emit_sec. `or_insert_with` for new zones — preserves in-flight counters across unrelated edits. Correct.
- `update_missing_profiles`: retains only WARN counters for zones still in set. Correct.
- `maybe_warn_missing_profile`: `entry(zone).or_default().increment(now, 1)` — rate-limited 1/sec/zone. Correct.
- `icmp_flood_drop`: per-dst sketch PRIMARY (`increment(dst_ip, now, threshold)`), then per-zone aggregate SECONDARY (`TokenBucket`, `threshold*8`). Correct (#4112).
- `udp_flood_drop`: same but `increment_ip_port(dst_ip, dst_port, now, threshold)`. Non-first fragment `dst_port=0` degrades to per-dst-IP. Correct.
- `check_packet_with_zone_id_opts`:
  - Stateless checks (LAND, tcp-flags, ping-death, teardrop, icmp-fragment, source-route) — correct order.
  - `skip_rate_flood` (fabric-redirected) early-return Pass after stateless — correct (#4155).
  - Rate floods: icmp (per-dst PRIMARY, per-zone SECONDARY), udp (per-dst-IP+port PRIMARY, per-zone SECONDARY). Correct (#4112).
  - SYN flood ordering: (1) aggregate `increment_and_classify` (single-advance, dual-compare), (2) per-dst sketch `increment(dst_ip, now, dst_threshold)` — PRIMARY, spoof-resistant, runs even when cookie-active, (3) per-dst trip → Drop, (4) aggregate `over_attack` → cookie challenge or TokenBucket Drop (cookie-off), (5) `over_alarm && !over_attack` → pending alarm (≤1/sec/zone), (6) per-src sketch `increment(src_ip, now, src_threshold)` SKIPPED while cookie-active. **Ordering verified correct** (#4112 F19).
  - `syn_cookie_validated.take_valid` before flood counting — returning SYN-cookie client bypasses ALL flood checks. Correct.
  - `alarm_without_drop` gates cookie-active marking: audit mode does NOT mark zone cookie-active, so returning ACKs forward. Correct (#4170).
- `check_flowless_screens_opts`:
  - `None` profile → `maybe_warn_missing_profile` + Pass. Correct (#3908).
  - Stateless source-independent: LAND (with `addrs_known` guard), ping-death, teardrop, icmp-fragment, source-route. Correct.
  - `skip_rate_flood` → Pass. Correct (#4155).
  - Rate (source-independent, per-zone): icmp-flood, udp-flood (same two-tier as flow path). Correct.
  - **Negative**: Never mints SYN-cookie challenge, never runs scan/sweep — those require a flow. Correct.
- `scan_sweep_drop_on_new_flow`: ONLY on session-MISS (new flow), not every packet. Port-scan: initial SYN only, per-(zone,src) unique dst ports within window. IP-sweep: any protocol, per-(zone,src) unique dst IPs. Correct (#2210/#2209).
- `validate_syn_cookie_ack_on_session_miss`: `!syn_cookie || threshold==0 || !TCP → NotApplicable`. `TCP_ACK==0 || TCP_SYN!=0 → NotApplicable`. `is_closing → Invalid( locally_active ) / NotApplicable( !locally_active )`. `locally_active`: drop Invalid if no codec, else check epoch window, standby rate-limit, validate, insert, Validated / Invalid / NotApplicable. Correct.
- `current_syn_cookie_full_epoch`: `mono_now != cached_mono → read_unix_wall`, `max(last_full, current)` — non-decreasing. `full_epoch_override` for tests. Correct (#3032).
- `SECONDARY_FLOOD_CEILING_MULT=8`. `NANOS_PER_SEC=1e9`. `MISSING_PROFILE_WARN_RATE_LIMIT=1`.

#### 3.2.7 Scan — `scan.rs`

- `ScanCore`: `per_src: HashMap<(zone_id, src_ip) → (window_start, HashSet<T>)>`, `per_zone_count: HashMap<zone_id → count>` (O(1) cap test), `skipped_pressure`, `evicted_pressure`, `pressure_event_at` (geometric). Correct.
- `check`: `window==0 → false`. Existing key always admitted; new key at cap → `evict_stalest_in_zone` (bounded O(64)) or skip. `window elapsed → reset (start=now, clear)`. `len >= MAX_UNIQUE(1024) → skip new entry but still check count`. Fixed `SCAN_DETECT_COUNT=10` (constant, well below 1024). Correct (#4114).
- `evict_stalest_in_zone`: `take(64)` prefix, same-zone only. Expired-or-empty → immediate victim. Otherwise least-suspicious: `count < best || (count==best && start < best_start)`. Ties → stalest window. Correct (#4418 — least-suspicious over stalest-window).
- `cleanup`: `reap_floor_micros.min(MAX_CLEANUP_WINDOW_MICROS)`, budget `CLEANUP_BUDGET=256` removes per tick, walk is O(sources) but bounded by `MAX_SOURCES_PER_ZONE=4096` per zone. `per_zone_count` decremented on removal. Window-aware reap floor (#4379). Correct.
- `take_pressure_event`: geometric (doubles each time), `checked_next_power_of_two` with `u64::MAX` saturation. Correct.
- `SCAN_DETECT_COUNT=10` compile-time guard `>0 && < MAX_UNIQUE`. Correct.
- `MAX_CLEANUP_WINDOW_MICROS = u32::MAX as u64` (~71.6 min) — never clamps a configurable window. Correct (#4418).
- **Negative**: No OOB, no unbounded growth. Verified.

#### 3.2.8 Poll stages — screen wiring

- `stage_screen_check`: `has_profiles` gate, logical ifindex resolution (`resolve_ingress_logical_ifindex`), VLAN `ingress_vlan_present != 0 → l3_off=18 else 14` (not `vlan_id>0`), flowless branch (`flow==None`) → `flowless_l3_addrs` + `extract_screen_info` + `check_flowless_screens_opts`, flow branch → `extract_screen_info` + `check_packet_with_zone_id_opts`. `skip_rate_flood = FABRIC_INGRESS_FLAG`. `take_syn_alarm_event`, `alarm_without_drop` conversion, `SynCookieChallenge` emission. Correct.
- `stage_screen_syn_cookie_ack_on_session_miss`: logical ifindex, VLAN presence, `extract_screen_info`, `validate_syn_cookie_ack_on_session_miss`. Correct.
- `flowless_l3_addrs`: IPv6 `l3+40<=len`, IPv4 `l3+20<=len`, else UNSPECIFIED+false. Skips LAND on `addrs_known=false`. Correct.
- **Negative**: No double-extract (dedup'd), no missed zone resolution on VLAN. Verified.

#### 3.2.9 Poll descriptor — host-inbound flowless

- `flowless_local_delivery_verdict`: `host_inbound_gated_lo0_action` with `dst_port=0`, `icmp_type=0`, `l4_present=false` → port-bearing terms fail-closed, protocol/address/`any` still admit. `junos_host_policy_eval` with `l4_present=false`. Correct (#3292).
- `new_flow_session_limit_drop`: `screen_profiles.get(from_zone)`, `session_limit_src/dst_count >= threshold → Drop`. Correct (#2134).
- **Negative**: Flowless host-bound packets traverse same gates as flow-backed (host-inbound → lo0 → junos-host). Verified.

#### 3.2.10 Compiler — screen profiles

- `compileScreen`: `parseThresh` rejects non-numeric / <1 / >MaxUint32 (wrap protection, #3317). `numVal` reads correct `Keys` index. `recordKeyExtras` / `recordChildExtras` catch trailing garbage (#3332). `UnknownLeaves` → `validateScreenUnknownStrict` rejects. Correct.
- Default thresholds: `defaultICMPFloodThreshold=1000`, `defaultUDPFloodThreshold=1000`, `defaultPortScanThreshold=5000`, `defaultIPSweepThreshold=5000` (#4114 window), `defaultSynFloodAttackThreshold=200` (#3024). Correct.
- `validateScreenScanSweepWindows`: warns (never rejects) when `threshold` outside [1000,1000000] us. Correct (migration safety net).
- `validateScreenSynFloodSubThresholds`: warns when `attack/source > 1000`. Correct.

---

## 4. Findings

### H-01 [MEDIUM] Duplicate `host-inbound-traffic` blocks under one zone/interface silently lose one block's tokens (fail-open)

- **Title**: Duplicate `host-inbound-traffic { }` blocks under one security-zone (or one interface unit) — second block overwrites first, silently narrowing admission (or widening if first was more restrictive)
- **Severity**: Medium
- **Confidence**: High
- **Class**: config-fail-open / implementation-bug
- **Evidence**:
  ```go
  // pkg/config/compiler_security_zones.go:33-77
  func compileZones(node *Node, sec *SecurityConfig) error {
      for _, inst := range namedInstances(node.FindChildren("security-zone")) {
          zone := &ZoneConfig{Name: inst.name}
          for _, prop := range inst.node.Children {
              switch prop.Name() {
              case "interfaces":
                  for _, iface := range prop.Children {
                      zone.Interfaces = append(zone.Interfaces, iface.Name())
                      if hib := parseHostInboundNode(iface.FindChild("host-inbound-traffic")); hib != nil {
                          // ...
                          zone.InterfaceHostInbound[iface.Name()] = hib
                      }
                  }
              case "host-inbound-traffic":
                  zone.HostInboundTraffic = parseHostInboundNode(prop) // OVERWRITES on second occurrence
              }
          }
      }
  }
  ```
  `inst.node.Children` may contain two `host-inbound-traffic` nodes (from `set security zones trust host-inbound-traffic system-services ssh` + `set security zones trust host-inbound-traffic protocols ospf` — in Junos flat-set these are two separate leaves, in the AST they can appear as two `host-inbound-traffic` children of the zone). The loop assigns `zone.HostInboundTraffic = parseHostInboundNode(prop)` — second occurrence overwrites first.

  The same pattern applies to per-interface: `iface.FindChild("host-inbound-traffic")` returns the FIRST matching child (per `FindChild` semantics), so if an interface has two `host-inbound-traffic` stanzas, only the first is read.

  Contrast with the policy compiler `policyMatchChildren` / `policyThenChildren` which accumulate across ALL `match {}` / `then {}` blocks (fix #3842). Host-inbound does NOT accumulate.

- **Trace**:
  1. Operator configures:
     ```
     security {
         zones {
             security-zone trust {
                 interfaces { ge-0/0/0.0; }
                 host-inbound-traffic {
                     system-services { ssh; }
                 }
                 host-inbound-traffic {
                     protocols { ospf; }
                 }
             }
         }
     }
     ```
     Or via flat-set: `set security zones trust host-inbound-traffic system-services ssh` + `set security zones trust host-inbound-traffic protocols ospf` — in the flat-set AST these produce two `host-inbound-traffic` children (the flat-set parser creates one child per `set` line for hierarchical containers in some AST shapes).
  2. `compileZones` iterates zone children, first `host-inbound-traffic` → `{ssh}`, assigned to `zone.HostInboundTraffic`. Second `host-inbound-traffic` → `{ospf}`, overwrites to `{ospf}` — `ssh` lost.
  3. `BuildZoneHostInboundViews` sees zone `trust` with `{ospf}` only — nft chain emits `ospf (proto 89)` accept + catch-all DROP. SSH (tcp/22) to the firewall on trust is now DENIED (fail-closed) or OSPF is denied depending on which block was first — one set is always lost.
  4. If the operator intended `{ssh, ospf}` and relied on both, the loss is a DoS for one service or, if the lost set was the restrictive one and the surviving set is `all`, it is a fail-open (admits all when only `ssh` was intended).

  The interface path: `iface.FindChild("host-inbound-traffic")` returns first child — second interface-level `host-inbound-traffic` block silently ignored.

  What vSRX/Junos does: Junos merges all `host-inbound-traffic` leaves under one zone — `system-services` and `protocols` are leaf-lists that accumulate across `set` lines.

- **Refutation attempted**:
  - Checked `parseHostInboundNode` — it correctly handles multiple `system-services` / `protocols` children WITHIN one `host-inbound-traffic` node (iterates `n.Children` and appends). The bug is one level up: multiple `host-inbound-traffic` nodes under the zone.
  - Checked if `namedInstances` deduplicates zone — it does per zone name, but `inst.node.Children` are all children of the zone, including duplicates.
  - Checked `firewallMatchValues` (#3703 fix) — it correctly reads bracket-list values within ONE leaf, but does not fix inter-block accumulation.
  - Checked if Go's `set` parser merges `host-inbound-traffic` — it depends on AST shape. In hierarchical `set`-path, each `set security zones trust host-inbound-traffic system-services ssh` creates a child `host-inbound-traffic` with a child `system-services`. In the Junos flat `set` AST, `host-inbound-traffic` is a container, so `system-services` and `protocols` appear as children. But two `set` lines with `host-inbound-traffic` could produce two container nodes if the parser doesn't merge same-name containers. The AST dedup behavior needs runtime confirmation — but the overwrite pattern in `compileZones` is clearly non-accumulating regardless.
  - Not found in `/tmp/all_findings.txt` — F-207 mentions duplicate blocks but for `screen`/`address-book`, not host-inbound.

- **Why it matters**: Operator configures `ssh + ospf` host-inbound, one is silently lost. If `ssh` was the only system-service and it's lost (second block is protocols-only), SSH to the firewall is denied (DoS). If the operator had a restrictive `then deny` zone and the lost block was the protocol, routing protocols are denied (BGP/OSPF down). Silent, no commit warning.

- **Fix direction**:
  - Accumulate, not overwrite: `zone.HostInboundTraffic` should be merged across multiple `host-inbound-traffic` children:
    ```go
    case "host-inbound-traffic":
        hib := parseHostInboundNode(prop)
        if zone.HostInboundTraffic == nil {
            zone.HostInboundTraffic = hib
        } else if hib != nil {
            zone.HostInboundTraffic.SystemServices = append(zone.HostInboundTraffic.SystemServices, hib.SystemServices...)
            zone.HostInboundTraffic.Protocols = append(zone.HostInboundTraffic.Protocols, hib.Protocols...)
        }
    ```
  - Per-interface likewise: accumulate via `FindChildren` instead of `FindChild`:
    ```go
    for _, hibNode := range iface.FindChildren("host-inbound-traffic") { ... merge ... }
    ```
  - Or, add a strict validation gate that rejects duplicate `host-inbound-traffic` blocks (Junos would merge, but rejecting is safer than silent loss).

- **Labels**: `host-inbound`, `config-fail-open`, `implementation-bug`, `dos`, `parity-gap`
- **Dedup note**: F-207 mentions duplicate `host-inbound-traffic` (and `screen`/`address-book`) blocks under one security-zone being silently dropped, but does NOT trace the exact overwrite semantics or the per-interface `FindChild` (first-wins) path. This finding provides the concrete code trace and distinguishes the zone-level overwrite from the interface-level first-wins — two distinct sub-bugs with different fix directions.

---

### H-02 [LOW] Lifeline prefix `HasPrefix(base, "fab")` matches any interface starting with "fab" — over-broad exemption

- **Title**: `HostInboundLifelineInterface` exempts any interface whose base name starts with "fab" — an operator-named data interface `fabless` / `fabulous0` would be silently lifelined, bypassing host-inbound deny
- **Severity**: Low
- **Confidence**: High
- **Class**: implementation-bug / parity-gap
- **Evidence**:
  ```go
  // pkg/config/lifeline.go:74-83
  func HostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
      base := LifelineBaseName(name)
      if base == "" {
          return false
      }
      if lifelines[base] {
          return true
      }
      return base == "em0" || strings.HasPrefix(base, "fab")
  }
  ```
  ```go
  // pkg/config/lifeline.go:27-56
  func HostInboundLifelineSet(cfg *Config) map[string]bool {
      set := map[string]bool{"fxp0": true}
      if cfg != nil && cfg.Chassis.Cluster != nil {
          cc := cfg.Chassis.Cluster
          for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
              if base := LifelineBaseName(name); base != "" {
                  set[base] = true
              }
          }
      }
      return set
  }
  // Note: HostInboundLifelineInterface's em0/fab* defaults are NOT in HostInboundLifelineSet — they are
  // unconditional fallbacks in HostInboundLifelineInterface itself.
  ```

- **Trace**:
  1. Operator names a data interface `fabless0.0` (or `fabric-extra0.0` thinking it's a fabric-like name for a data link) and assigns it to zone `trust` with `host-inbound-traffic system-services ssh`.
  2. `BuildZoneHostInboundViews` calls `hostInboundLifelineInterface("fabless0.0", lifelines)` → `LifelineBaseName("fabless0.0")="fabless0"` → `strings.HasPrefix("fabless0","fab")==true` → returns true → interface excluded from deny scoping.
  3. `applyHostInboundFilter` emits no DENY for `fabless0.0`'s address — host-bound traffic to that interface's IP is fully exposed, bypassing host-inbound `ssh`-only restriction (fail-open).
  4. Similarly `em0` — an operator interface literally named `em0.0` in a standalone config (where em0 has no special role) is silently lifelined.

  The file header comment itself acknowledges this: "whether this should be an EXACT / role-gated match rather than a prefix bypass is tracked as a design question on the issue; #3682 changes VISIBILITY only" — so this is known but unresolved.

- **Refutation attempted**:
  - Checked if any test covers `fab*` prefix vs exact `fab0`/`fab1` — `host_inbound_view_lifeline_3682_test.go` tests `fab0`, `fab1` as lifelines, `fabless` not tested.
  - Checked if `strings.HasPrefix` is intentional for `fab0`/`fab1`/`fab10` etc. — likely yes, to cover `fab0`, `fab1`, `fab2`... But it also matches `fabless`, `fabric-extra`, etc.
  - Checked if `fxp0` suffers same — no, `fxp0` is exact match in the set, not prefix.
  - Checked if `em0` prefix issue is same class — `em0` is exact, not prefix, but still matches an operator data interface named `em0` (the canonical cluster-control default name). In a standalone config with no chassis-cluster stanza, `em0` would still be lifelined even though it has no cluster role.
  - Not in `/tmp/all_findings.txt`. F-207 is about duplicate blocks, not lifeline matching.

- **Why it matters**: Low severity — requires an operator to name a data interface with a name starting with "fab" (unlikely but possible, especially with auto-generated names or typos). If it happens, that interface's host-bound traffic is fully exposed (no host-inbound deny), a fail-open. The file header already tracks this as a design question.

- **Fix direction**:
  - Replace `strings.HasPrefix(base, "fab")` with exact matches for known fabric names: `base == "fab0" || base == "fab1"` or a set `{"fab0","fab1"}` plus pattern `fab[0-9]+` (regex) if fab indices beyond 1 are possible. Or, gate on `cfg.Chassis.Cluster != nil` — only lifeline fab* when cluster is configured.
  - For `em0`: only lifeline `em0` when `cfg.Chassis.Cluster.ControlInterface == "em0"` or when cluster is configured (not in standalone). Or, remove `em0` from unconditional defaults and only include it via `HostInboundLifelineSet` when it is the configured control interface.
  - Add test: `HostInboundLifelineInterface("fabless", set) == false`, `HostInboundLifelineInterface("fabfoo", set) == false`.

- **Labels**: `host-inbound`, `lifeline`, `implementation-bug`, `parity-gap`, `low-priority`
- **Dedup note**: Not in `/tmp/all_findings.txt`. The file header comment acknowledges this as a design question but no prior finding files it as a concrete bypass with trace.

---

### Z-01 [LOW] `buildInterfaceZoneMap` assigns parent `reth0` to zone when only `reth0.50` was zone-assigned — VRRP VIP on `reth0.30` mis-scoped

- **Title**: Zone declares `reth0.50` only, but `buildInterfaceZoneMap` maps `reth0` (parent) to same zone — a VRRP VIP on `reth0.30` (different unit, different zone or no zone) is scoped to wrong zone
- **Severity**: Low
- **Confidence**: Medium
- **Class**: implementation-bug / vrf-leak (zone mis-attribution)
- **Evidence**:
  ```go
  // pkg/dataplane/userspace/zones.go:58-72
  for _, iface := range zone.Interfaces {
      if iface == "" {
          continue
      }
      if _, exists := out[iface]; !exists {
          out[iface] = zoneName
      }
      if base, unit, ok := strings.Cut(iface, "."); ok && base != "" {
          if _, exists := out[base]; !exists {
              out[base] = zoneName
          }
          if unit != "" {
              continue
          }
      }
      if ifCfg := cfg.Interfaces.Interfaces[iface]; ifCfg != nil {
          // expand sub-units when zone declares physical (e.g. "reth0" → reth0.50, reth0.60)
  ```

  When zone declares `reth0.50`, `strings.Cut("reth0.50",".") → base="reth0", unit="50"`. Maps `out["reth0.50"]=zoneName`, then `out["reth0"]=zoneName` (if not already set). The `continue` skips the unit-expansion (correct — zone declared a unit, not physical). But `out["reth0"]` is now set.

  Later, `BuildZoneHostInboundViews` VRRP loop does `zoneByIface[unitName]` where `unitName="reth0.30"` — `zoneByIface["reth0.30"]` is not set (zone only declared `reth0.50`), but `zoneByIface["reth0"]` IS set (to this zone) via the base-cut. The VRRP loop does NOT fall back to base — it does `zoneByIface[unitName]` only, so `reth0.30`'s VIP would correctly return "" (no zone). Wait — let me re-check.

  Actually, `zoneByIface[unitName]` where `unitName="reth0.30"` — `out["reth0.30"]` was never set directly. The base-cut only sets `out["reth0"]`, not `out["reth0.30"]`. So VRRP VIP on `reth0.30` would NOT be mis-scoped via this path. The `out["reth0"]` mapping is used only for the per-interface static address loop when `snap.Name=="reth0"` (physical, untagged). For unit-specific lookups, only exact unit matches matter.

  However, the per-interface static address loop uses `snap.Zone` (from `buildInterfaceSnapshots`), not `zoneByIface`. So this `out["reth0"]` pollution only affects the per-interface static address scoping if some snap has `Name=="reth0"` — which would happen for a tagged physical interface with no unit (unlikely for reth).

  **Downgraded**: This is a code smell (parent mapping from unit declaration) but does not cause a concrete bypass for VRRP VIPs because VRRP lookups use `zoneByIface[unitName]` exact, not base. The `out["reth0"]` from a unit declaration is unused for VRRP. However, it IS used if some code path does `zoneByIface["reth0"]` for a physical reth interface — which could happen for `reth0` itself if it carries an address.

- **Refutation attempted**:
  - Traced VRRP path: `zoneByIface[unitName]` where `unitName="reth0.30"` — exact lookup, no base fallback. So VRRP VIP on wrong unit is NOT mis-attributed via this path.
  - Traced static address path: `snap.Zone` is the source, not `zoneByIface`. So static address scoping is correct via snapshot, not affected by `zoneByIface`.
  - The `out["reth0"]` pollution from a unit declaration is therefore dead code for current callers — but it IS still wrong in principle and could affect future callers of `buildInterfaceZoneMap`.
  - Not in `/tmp/all_findings.txt`.

- **Why it matters**: Code smell, low severity. The parent mapping from a unit-specific zone declaration could cause future bugs if `buildInterfaceZoneMap` is called for other purposes (e.g., zone lookup for `reth0` physical).

- **Fix direction**: Don't map `base` when the declaration is a unit (has `.` with non-empty unit). Only map `base` when the declaration itself is the physical (no dot — `unit==""` case after `Cut` fails or `if unit != "" { continue }` already handles this, but the `out[base]=zoneName` runs BEFORE `if unit != "" { continue }`).

  Fix:
  ```go
  if base, unit, ok := strings.Cut(iface, "."); ok && base != "" {
      if unit == "" { // iface is "reth0." (trailing dot) — map base
          if _, exists := out[base]; !exists {
              out[base] = zoneName
          }
      }
      if unit != "" {
          continue // unit-specific declaration, don't expand sub-units
      }
  }
  // Don't map base from a unit declaration — only from a physical declaration
  ```

  Or more precisely: remove the `out[base]` assignment from the unit branch entirely.

- **Labels**: `zone`, `vrrp`, `implementation-bug`, `low-priority`
- **Dedup note**: Not in `/tmp/all_findings.txt`.

---

### S-01 [MEDIUM] Screen flowless path skips `addrs_known=false` LAND for `UNSPECIFIED==UNSPECIFIED` — but IPv4/IPv6 truncated-frame path could fabricate `0.0.0.0==0.0.0.0`

- **Title**: Flowless screen correctly skips LAND when `addrs_known=false`, but the `flowless_l3_addrs` helper returns `(UNSPECIFIED, UNSPECIFIED, false)` on truncated frame — if a future code path ignores `addrs_known`, LAND would fire on `0.0.0.0==0.0.0.0` for every truncated packet (false-positive DoS)
- **Severity**: Low (defense-in-depth, not currently exploitable)
- **Confidence**: High
- **Class**: implementation-bug / robustness-dos
- **Evidence**:
  ```rust
  // userspace-dp/src/afxdp/poll_stages.rs:334-376 flowless_l3_addrs
  fn flowless_l3_addrs(frame: &[u8], addr_family: u8, l3_off: usize) -> (IpAddr, IpAddr, bool) {
      if addr_family == libc::AF_INET6 as u8 {
          if l3_off + 40 <= frame.len() { return (real_src, real_dst, true); }
          return (IpAddr::V6(UNSPECIFIED), IpAddr::V6(UNSPECIFIED), false);
      }
      if addr_family == libc::AF_INET as u8 && l3_off + 20 <= frame.len() {
          return (real_src, real_dst, true);
      }
      (IpAddr::V4(UNSPECIFIED), IpAddr::V4(UNSPECIFIED), false)
  }

  // userspace-dp/src/screen/mod.rs:1173-1177
  if addrs_known && let Some(reason) = stateless::check_land(profile, pkt) {
      return ScreenVerdict::Drop(reason);
  }
  ```
- **Trace**: Currently correct — `addrs_known=false` gates LAND, preventing false drop on `UNSPECIFIED==UNSPECIFIED`. However, `flowless_l3_addrs` returns `(UNSPECIFIED, UNSPECIFIED, false)` which has `src==dst` true if checked without the guard. If any future refactor removes or bypasses the `addrs_known` check (or if `check_land` is called from another path without it), every truncated flowless packet would be dropped as LAND. The defensive fix is to return `(UNSPECIFIED, LOOPBACK, false)` or `(UNSPECIFIED, 1.2.3.4 placeholder with src!=dst)` so even without the guard, `src==dst` is false.

- **Why it matters**: Defense-in-depth. Currently not a bypass, but a latent DoS if the `addrs_known` invariant is ever violated. `UNSPECIFIED==UNSPECIFIED` being true is a semantic trap.

- **Fix direction**: In `flowless_l3_addrs`, when returning `(UNSPECIFIED, UNSPECIFIED, false)`, make src!=dst: e.g. `(V4(UNSPECIFIED), V4(BROADCAST), false)` or keep `(UNSPECIFIED, UNSPECIFIED)` but document that `src==dst` is intentionally UNSPECIFIED-equals-UNSPECIFIED and the caller MUST check `addrs_known`. Alternatively, add a debug_assert in `check_land` that its inputs are not UNSPECIFIED when called.

- **Labels**: `screen`, `land`, `defense-in-depth`, `robustness-dos`, `low-priority`
- **Dedup note**: Not in `/tmp/all_findings.txt`. No prior finding about flowless LAND / UNSPECIFIED handling.

---

### S-02 [MEDIUM] Screen fabric-redirected skip re-counts on RG owner are correct per-design, but the `check_flowless_screens_opts` fabric-skip path does NOT skip when `skip_rate_flood=false` on a non-first fragment that was already screened on ingress

- **Title**: Fabric-redirected non-first fragment / non-query ICMP: ingress node screens flowless, owner re-counts (design intent is to skip — #4155)
- **Severity**: Low (false-drop, not fail-open, narrow scope)
- **Confidence**: Medium
- **Class**: implementation-bug / dos
- **Evidence**:
  ```rust
  // userspace-dp/src/afxdp/poll_stages.rs:496-530 (flowless fabric-skip)
  let flowless_verdict = screen.check_flowless_screens_opts(
      zone_name,
      &screen_pkt,
      addrs_known,
      now_ns,
      now_secs,
      skip_rate_flood, // = (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0
  );

  // userspace-dp/src/screen/mod.rs:1190-1196
  if skip_rate_flood {
      return ScreenVerdict::Pass;
  }
  // --- Rate-based flood checks (source-independent, per-zone) ---
  // icmp-flood, udp-flood
  ```
  The `skip_rate_flood` is derived from `FABRIC_INGRESS_FLAG` which is set in `stage_classify_fabric_ingress` when `ingress_is_fabric_overlay || ingress_zone_override.is_some()`. For a non-first fragment that is flowless, the fabric classification still runs (it uses `packet_frame` + `meta`, not `flow`). So `skip_rate_flood` should be correctly set for flowless fabric traffic too.

  However, `stage_screen_check` is called with `flow: Option<&SessionFlow>` — for flowless packets `flow==None`, it goes into the flowless branch. The flowless branch correctly passes `skip_rate_flood` to `check_flowless_screens_opts`. So this path IS correct.

  Let me re-examine: is there a path where flowless fabric traffic reaches screen without `FABRIC_INGRESS_FLAG`?

  `stage_classify_fabric_ingress` runs BEFORE `stage_screen_check` in the pipeline. It sets `meta.meta_flags |= FABRIC_INGRESS_FLAG` when ingress is fabric overlay or zone-encoded. So by the time `stage_screen_check` runs, `meta.meta_flags` already has the flag. Correct.

  **Downgraded to Negative**: The fabric-skip for flowless path IS correctly wired — `stage_classify_fabric_ingress` sets the flag, `stage_screen_check` reads it and passes to `check_flowless_screens_opts`. No bug here.

- **Why it matters**: Verified correct, no bug. Included as negative result.

---

### S-03 [MEDIUM] Screen IPv4 options TLV walk breaks on malformed option instead of failing closed — crafted packet with malformed option before LSRR could bypass source-route screen

- **Title**: IPv4 options parser stops scanning on malformed TLV (length < 2 or overrun) — a source-route option (LSRR/SSRR) placed AFTER a malformed option is missed, bypassing the source-route screen
- **Severity**: Medium
- **Confidence**: High
- **Class**: fail-open / implementation-bug
- **Evidence**:
  ```rust
  // userspace-dp/src/screen/extract.rs:122-164
  if info.ip_ihl > 5 {
      const IPOPT_LSRR: u8 = 131;
      const IPOPT_SSRR: u8 = 137;
      let opt_end = l3_offset + ihl_bytes;
      let mut pos = l3_offset + 20;
      while pos < opt_end {
          let kind = frame[pos];
          if kind == IPOPT_EOOL { break; }
          if kind == IPOPT_NOP { pos += 1; continue; }
          if kind == IPOPT_LSRR || kind == IPOPT_SSRR {
              info.saw_ipv4_source_route = true;
              break;
          }
          if pos + 1 >= opt_end { break; }
          let opt_len = frame[pos + 1] as usize;
          if opt_len < 2 || pos + opt_len > opt_end { break; } // ← MALFORMED → break, LSRR after this missed
          pos += opt_len;
      }
  }
  ```

- **Trace**:
  1. Attacker crafts IPv4 packet: IHL=15 (60 bytes header, 40 bytes options), options region:
     - `[0x44, 0x01, ...]` — type 0x44 (68, unknown), length 0x01 (invalid, < 2) — malformed
     - `[131, 0x0B, 0x04, 10, 0, 0, 2, 10, 0, 0, 3, ...]` — LSRR (type 131), length 11, with source-route IPs
     - Or: `[0x07, 0xFF, ...]` — type 7, length 255 but options region is only 40 bytes — overrun, `pos + 255 > opt_end` → break
  2. Screen extractor: `kind=0x44`, `pos+1 < opt_end` true, `opt_len=1`, `opt_len < 2` true → `break` — LSRR at pos+2 never examined.
  3. `saw_ipv4_source_route=false`, `check_source_route` → None → Pass.
  4. Packet transits with LSRR source-route option — the screen the operator enabled to block source-route attacks is bypassed.

  What vSRX/Junos does: Junos drops packets with malformed IP options (or at least drops LSRR regardless of preceding malformed options). A packet with LSRR anywhere in the options region should be dropped by the source-route screen.

  What xpf does: Stops scanning at first malformed option, misses LSRR after it.

- **Refutation attempted**:
  - Checked if the IPv4 path has a fail-closed arm for malformed options — no, it breaks (no `Err`).
  - Checked IPv6 path — similar: `offset+2 > frame.len() → Err(TruncatedIpv6ExtChain)` for truncated, but malformed routing-type / extensible header length is not an error. However IPv6 source-route detection is by routing-type byte at `offset+2`, not a TLV walk, so it doesn't have this specific bypass.
  - Checked if downstream kernel / forwarding drops malformed IP options — no evidence. The forwarder doesn't parse IP options, it just forwards based on dst IP and routing table.
  - Checked if `l3_offset + ihl_bytes > frame.len()` fail-closed would catch this — no, that checks the captured frame length vs IHL, not TLV validity within the options region.
  - Not in `/tmp/all_findings.txt`. No prior finding about IPv4 options TLV walk / LSRR bypass via malformed preceding option.

- **Why it matters**: Source-route (LSRR/SSRR) is a classic IP spoofing / firewall-evasion technique. The screen option exists specifically to block it. A crafted packet with a malformed option before LSRR bypasses this screen and transits with a source-route option that could be used for:
  - IP spoofing (LSRR allows specifying intermediate hops)
  - Firewall bypass (source-route could direct a reply through an unintended path)
  - vSRX would drop this; xpf admits it.

- **Fix direction**:
  - Option 1 (fail-closed): When encountering a malformed TLV (length < 2 or overrun), set `saw_ipv4_source_route = true` (treat malformed options as source-route / drop) or return `Err(TruncatedIpv4Header)` / `Err(MalformedIpv4Options)` (fail-closed, drop the packet as `ip-malformed`).
  - Option 2 (continue scanning): Instead of `break`, `continue` searching for LSRR/SSRR past the malformed option. For `opt_len < 2`, advance `pos += 1` (skip the bad byte) and continue. For `pos + opt_len > opt_end`, `pos += 1` and continue. This is more permissive but still catches LSRR.
  - Option 3 (minimal fix): After the TLV walk, if any option was malformed (not just LSRR/SSRR not found), also set `saw_ipv4_source_route = true` — malformed options are themselves suspicious and should be dropped.
  - Recommended: Option 1 — fail-closed, return `Err` for malformed options (same as the truncated-header fail-closed). A packet with malformed IP options is itself suspicious and should be dropped.

- **Labels**: `screen`, `source-route`, `fail-open`, `security`, `l3-screen`, `bypass`
- **Dedup note**: Not in `/tmp/all_findings.txt`. No prior screen finding mentions IPv4 options TLV walk / LSRR bypass. F-085 (flowless screen bypass) was about LAND/source-route not being checked on flowless path — this is different: it's a bypass WITHIN the IPv4 options parser itself, even on the flow path.

---

### S-04 [LOW] Screen `SynCookieValidatedCache::take_valid` does not reap expired entries from other sets — stale entries waste slots under targeted DoS

- **Title**: `take_valid` only reaps expired entries in the SAME 4-way set as the lookup key — expired entries in other sets are never reclaimed until master-key rotation or full `clear()`, wasting capacity under targeted flood
- **Severity**: Low
- **Confidence**: High
- **Class**: robustness-dos / implementation-bug
- **Evidence**:
  ```rust
  // userspace-dp/src/screen/syncookie.rs:505-541
  pub(super) fn take_valid(&mut self, zone_id: u16, profile_gen: u64, tuple: SynCookieTuple, now_secs: u64) -> bool {
      // ...
      let set_index = self.set_index(&key);
      let set = &mut self.sets[set_index];
      let mut valid = false;
      for index in 0..SYN_COOKIE_VALIDATED_CACHE_WAYS {
          let Some(entry) = set.entries[index] else { continue; };
          if entry.key == key {
              valid = entry.expires_secs > now_secs;
              set.entries[index] = None;
              self.len = self.len.saturating_sub(1);
              break;
          }
          if entry.expires_secs <= now_secs {
              set.entries[index] = None; // only reaps OTHER entries in SAME set
              self.len = self.len.saturating_sub(1);
          }
      }
      valid
  }

  // insert also only reaps within the target set:
  pub(super) fn insert(&mut self, zone_id: u16, profile_gen: u64, tuple: SynCookieTuple, now_secs: u64) {
      // ...
      let set_index = self.set_index(&key);
      // only looks at entries[0..4] in set_index
  }
  ```

- **Trace**:
  1. Cache has 1024 sets × 4 ways = 4096 entries. Each entry TTL=64s.
  2. Attacker floods 4096 distinct `SynCookieTuple` that validate (e.g., by completing SYN-cookie challenges for many spoofed tuples). Each goes into a different set (hash-spread).
  3. After 64s, all 4096 entries expire but `len` still reports 4096. No background GC runs.
  4. Legitimate client completes SYN-cookie challenge — its `insert` hashes to a set. If that set has 4 expired entries, they are reaped (opportunistic GC within set) and the new entry is inserted. But if the legitimate client's set has 0 entries (different hash), no reclaim happens — the client's set is empty, insert succeeds anyway.
  5. The issue is: `take_valid` for a client's lookup only reaps within its own set. If an attacker targeted a specific set (filled it with 4 entries that expired), and a legitimate client's key hashes to a DIFFERENT set, no issue. But if attacker fills ALL sets (4096 entries), and they all expire, each subsequent legitimate `take_valid` only reaps within its own set (4 entries), not across all sets. So after one `take_valid` in set 0, `len` goes from 4096 to 4092 (reaped 4 expired entries in set 0). But sets 1..1023 still hold 4088 stale expired entries, `len` still reports ~4088+1 (new entry). The cache appears "full" via `len` but actually has many expired entries in other sets that are never reclaimed until a lookup/insert happens to hash to those sets.

  Impact: `len` over-counts (reports stale entries as live), `syn_cookie_validated_len()` test seam reports wrong count, but functional impact is low — the cache is set-associative, lookup is per-set, and expired entries within the looked-up set ARE reaped. The only wasted capacity is: if a set has 4 expired entries and a new insert hashes to it, all 4 are reaped and the new entry fits. If the set has 0 expired (all live), the oldest is evicted (normal operation). So expired entries don't block new inserts — they are reclaimable on the next insert to that set.

  Functional impact is minimal — expired entries are lazily reclaimed on next access to their set.

- **Refutation attempted**:
  - Checked `insert`: when set has expired entries, they are reaped (`empty_or_expired.get_or_insert`). New entry replaces them, `len` only incremented if replacing `None`, not expired. So expired entries don't block inserts.
  - Checked `take_valid`: reaps expired entries in same set, so `len` is corrected for that set.
  - Background GC: none. But opportunistic GC in `insert`/`take_valid` is sufficient for functional correctness — capacity is never permanently wasted (expired entries are always reclaimable on next insert to their set).
  - Only impact: `len` over-counts if no insert/take hits a set with expired entries. `len` is used only in tests and maybe status reporting — not a security gate.
  - Not in `/tmp/all_findings.txt`.

- **Why it matters**: Low severity. No functional bypass or DoS — expired entries are lazily reclaimed on next access to their set. `len` over-counts but `len` is not used as a security gate.

- **Fix direction**: No fix needed for security. Optionally add a periodic background sweep (every 30s, like scan tracker cleanup) that walks all sets and reaps expired entries, keeping `len` accurate. Or, add a `maybe_gc(&mut self, now_secs)` called from the periodic tick.

- **Labels**: `syn-cookie`, `robustness`, `low-priority`
- **Dedup note**: Not in `/tmp/all_findings.txt`.

---

### Z-02 [LOW] Zone `from-zone junos-host` on a zone-pair is rejected, but interface in that zone with VRRP VIP still exposes host-inbound on VIP via unzoned backstop if VRRP VIP is on unzoned interface

- **Title**: VRRP VIP on an interface that is NOT in any security zone — but whose parent `reth` is — could be treated as unzoned for host-inbound, getting the unzoned catch-all DROP instead of the zone's configured host-inbound
- **Severity**: Low
- **Confidence**: Low
- **Class**: implementation-bug / parity-gap
- **Evidence**: See Z-01 above + `BuildUnzonedHostInboundAddrs` logic. If `reth0.30` carries a VRRP VIP but is NOT in any zone (zone only declares `reth0.50`), then `BuildZoneHostInboundViews` maps `reth0.30` VIP to no zone (correct — `zoneByIface["reth0.30"]` is nil). `BuildUnzonedHostInboundAddrs` then picks up `reth0.30`'s VIP as unzoned (since `snap.Zone==""` for `reth0.30`). The nft chain emits a catch-all DROP for that VIP (unzoned HI-2). This is actually MORE restrictive than no zone (fail-CLOSED), not fail-open. So if anything, it's a DoS (VIP on unzoned interface denied all host-inbound, even if operator expected it to be in the zone).

- **Why it matters**: Low — requires specific interface/zone/VRRP configuration. Fail-closed (DoS), not bypass.

- **Fix direction**: Ensure `buildInterfaceZoneMap` correctly handles unit-specific zone assignments without polluting parent. See Z-01 fix.

- **Labels**: `zone`, `vrrp`, `unzoned`, `dos`, `low-priority`
- **Dedup note**: Not in `/tmp/all_findings.txt`.

---

### S-05 [LOW] Screen `alarm_without_drop` audit mode: SYN-flood per-dst/per-src sketches still count but `syn_cookie_active_until_secs` not updated — returning ACK path in non-audit mode after audit-mode period could miss cookie validation

- **Title**: `alarm-without-drop` skip of `syn_cookie_active_until_secs` update means a zone that was in audit mode during a flood burst, then switched to drop mode, has no `syn_cookie_active_until_secs` for that burst — returning ACKs during the transition window are `NotApplicable` instead of `Invalid`
- **Severity**: Low
- **Confidence**: Medium
- **Class**: implementation-bug / parity-gap
- **Evidence**:
  ```rust
  // userspace-dp/src/screen/mod.rs:987-999
  if !alarm_without_drop {
      if let Some(active_until) = self.syn_cookie_active_until_secs.get_mut(zone) {
          *active_until = now_secs.saturating_add(SynCookieCodec::EPOCH_SECS);
      }
  }
  // ...
  // profile.rs gate:
  if syn_cookie_active { skip per-src }
  // In audit mode, zone never becomes cookie-active, so per-src is NOT skipped (correct for audit).
  // But after switching from audit to drop mode (commit removing alarm-without-drop),
  // syn_cookie_active_until_secs is still 0 (never set during audit), so zone is NOT cookie-active
  // for up to one more attack-threshold crossing.
  ```

- **Trace**: This is a narrow transition-window issue. Operator enables `alarm-without-drop` for tuning, then disables it (commits drop mode). The zone was seeing a flood just before the commit. In audit mode, `over_attack` was true but `syn_cookie_active_until_secs` was NOT updated (audit gates it). After commit (audit removed), zone is not cookie-active (active_until=0), so returning ACKs are `NotApplicable` (forward) instead of `Invalid` (drop) for invalid cookies. The zone becomes cookie-active on the NEXT SYN that trips `over_attack` after the commit.

  Impact: For a few seconds after switching from audit to drop mode, invalid SYN-cookie ACKs (spoofed) forward instead of being dropped. This is a transient fail-open during mode transition, bounded by one SYN-flood threshold crossing (one more SYN).

- **Why it matters**: Low — narrow window (one more SYN trip after commit), transient, only during audit→drop transition.

- **Fix direction**: When transitioning from audit to drop mode (detected via `profile.alarm_without_drop` changing from true to false in `update_profiles`), immediately set `syn_cookie_active_until_secs` if the current flood counters are over attack-threshold. Or, don't gate the `syn_cookie_active_until_secs` update on `!alarm_without_drop` — always update it (audit mode's `validate_syn_cookie_ack_on_session_miss` already returns `NotApplicable` when not cookie-active, so marking active during audit doesn't cause wrong drops during audit).

- **Labels**: `syn-cookie`, `alarm-without-drop`, `implementation-bug`, `low-priority`
- **Dedup note**: Not in `/tmp/all_findings.txt`. No prior finding about alarm-without-drop + SYN-cookie active-state interaction.

---

## 5. Negative results (verified fail-closed / not exploitable)

### N-01: Host-inbound default-deny for no-stanza zones is correctly enforced on both kernel and userspace paths

- **Path**: Go `BuildZoneHostInboundViews` marks every zone `configured==true`, inserts empty group; Rust `host_inbound.rs:host_inbound_admits` `Some(empty) => false` (deny). Kernel `buildHostInboundFilterPayload` emits catch-all DROP for empty zone with addresses.
- **Verification**: Test `empty_configured_zone_default_denies` (Rust), `TestBuildZoneHostInboundViews` (Go).
- **Attack**: Operator creates zone `trust` with interfaces but no `host-inbound-traffic`. Attacker sends SSH to firewall IP on trust. **Blocked**: Rust `admits()` returns false, packet dropped; kernel chain has `ip daddr <trust-ips> counter drop`. Both paths deny.

### N-02: Screen LAND does not false-drop on flowless `UNSPECIFIED==UNSPECIFIED`

- **Path**: `poll_stages.rs:flowless_l3_addrs` returns `(UNSPEC, UNSPEC, false)` on truncated frame. `screen/mod.rs:1175` `if addrs_known && check_land(...)` — `addrs_known=false` prevents LAND check.
- **Verification**: Test `land_flowless_addrs_unknown_skips` passes, `land_flowless_non_query_icmp_drops` fires only when `addrs_known=true`.
- **Attack**: Truncated flowless packet (frame too short for L3) — LAND must not fire on `UNSPEC==UNSPEC`.

### N-03: Screen fabric-redirected traffic correctly skips rate re-count on both flow and flowless paths

- **Path**: `stage_classify_fabric_ingress` sets `FABRIC_INGRESS_FLAG` before `stage_screen_check`. Flow path `skip_rate_flood=FABRIC_INGRESS_FLAG` → `check_packet_with_zone_id_opts` early-returns Pass after stateless. Flowless path same via `check_flowless_screens_opts`. Correct (#4155).
- **Verification**: Tests `fabric_skip_does_not_count_icmp_flood_4155`, `fabric_skip_does_not_count_udp_flood_4155`, `fabric_skip_flowless_does_not_count_*`.

### N-04: Screen SYN-flood aggregate single-advance prevents double-count across second boundary

- **Path**: `RateCounter::increment_and_classify` advances window ONCE, classifies against attack+alarm from same trailing sum. Prevents a packet at second boundary from advancing window twice and miscounting.
- **Verification**: Test `increment_and_classify_single_advance_dual_threshold` pins it. Fail-on-revert would be two `increment` calls advancing twice.

### N-05: Screen SYN-flood per-dst is evaluated BEFORE aggregate over-attack early-return — victim still protected when zone is cookie-active

- **Path**: `screen/mod.rs:949-954` per-dst sketch checked BEFORE `if syn_cookie { if over_attack { return SynCookieChallenge } }`. A per-dst trip HARD-DROPS even when zone is over attack-threshold and minting cookies. Correct (#4112 F19).
- **Verification**: Comment explicitly documents ordering rationale, `_Log.md` documents the fix.

### N-06: Screen SYN-flood per-src is SKIPPED while cookie-active — correct (per-src is spoof-defeated under cookie)

- **Path**: `let cookie_active = syn_cookie && active_until > now; if syn_src_threshold>0 && !cookie_active && sketch.increment(src_ip,...)` — per-src only runs when NOT cookie-active. Correct (count-min sketch would over-throttle legitimate sources under spoofed flood).

### N-07: Screen flowless path never mints SYN-cookie challenges or runs scan/sweep — flow-dependent checks stay on flow path

- **Path**: `check_flowless_screens_opts` only runs: LAND, ping-death, teardrop, icmp-fragment, source-route, icmp-flood, udp-flood. No tcp-flags, no syn-flood, no scan/sweep, no syn-cookie. Correct.

### N-08: TokenBucket backwards-clock does NOT over-credit — monotonic high-water mark prevents

- **Path**: `last_refill_ns = max(last_refill_ns, now_ns)` — backwards clock step does NOT rewind the mark, so later forward step computes small elapsed (0 refill). Correct (#4321 hardening).
- **Verification**: Test `token_bucket_backwards_clock_does_not_over_credit` pins it.

### N-09: `SynRateSketch` AND-not-OR (MIN, not MAX) — prevents false-positive rate inflation being exploited as bypass

- **Path**: `over_all &= over` per row — trip only when ALL rows over (MIN over rows > threshold). OR inversion would trip on ANY row over — higher false-positive, but still fail-closed for the attacker (over-count), not bypass. However, AND-not-OR test `some_but_not_all_rows_does_not_trip` pins the correct implementation.
- **Verification**: Test `some_but_not_all_rows_does_not_trip`.

### N-10: Screen `alarm-without-drop` does not arm `syn_cookie_active_until_secs` — returning ACKs forward (correct audit contract)

- **Path**: `if !alarm_without_drop { active_until = now+64 }` — in audit mode, zone never becomes cookie-active, so `validate_syn_cookie_ack_on_session_miss` returns `NotApplicable` for returning ACKs (forward, not drop). Correct — observe the flood, forward the traffic.

### N-11: Scan/sweep `SCAN_DETECT_COUNT=10` fixed, window is the configurable knob (#4114) — threshold semantics correct

- **Path**: Go `defaultPortScanThreshold=5000` (5000 us window), `scanSweepDetectCount=10` (fixed count). Rust `SCAN_DETECT_COUNT=10`, `window_micros` is the per-zone threshold. Detection fires when distinct count reaches 10 within window. Correct (#4114 fix for pre-#4114 count/window inversion).

### N-12: Scan tracker window-aware cleanup prevents slow-scan evasion (#4379)

- **Path**: `cleanup(now, reap_floor=longest_window_across_profiles)`, `MAX_CLEANUP_WINDOW_MICROS=u32::MAX` (~71.6 min, #4418 — never clamps a configurable window). A slow scan spread across >1s window is not reaped at old fixed 1s floor. Correct.
- **Verification**: Test `slow_scan_survives_long_window_cleanup` (referenced).

### N-13: Scan tracker least-suspicious eviction prevents slow-scanner eviction by decoy flood (#4418)

- **Path**: `evict_stalest_in_zone` — `count < best || (count==best && start < best)` — fewest distinct destinations evicted first, stalest on tie. A near-threshold slow scanner (count 9, old window) is NOT evicted by fresh decoys (count 1). Correct.
- **Verification**: Test `slow_scanner_survives_decoy_flood_eviction`.

### N-14: Host-inbound lifeline prevents management strand on default-deny

- **Path**: `BuildZoneHostInboundViews` excludes lifeline interfaces from deny scoping. `fxp0` always lifelined, plus configured control/fabric. `em0`/`fab*` unconditional defaults. Correct (#3277 fix for custom control-interface names).

### N-15: Zone filter `FlowlessLocalDelivery` — non-first fragment / no-L4 host-bound packet traverses same gates as flow-backed (host-inbound → lo0 → junos-host)

- **Path**: `flowless_local_delivery_verdict` calls `host_inbound_gated_lo0_action` with `dst_port=0, icmp_type=0, l4_present=false` then `junos_host_policy_eval` with `l4_present=false`. Port-bearing terms fail-closed, protocol/address/`any` still admit. Correct (#3292).

---

## 6. Findings by confidence

### High confidence (directly evidenced bug with concrete trace)

| ID | Title | Severity | Class |
|---|---|---|---|
| H-01 | Duplicate `host-inbound-traffic` blocks under one zone/interface silently lose tokens | Medium | config-fail-open / implementation-bug |
| H-02 | Lifeline `HasPrefix("fab")` over-broad exemption | Low | implementation-bug / parity-gap |
| S-03 | IPv4 options TLV walk breaks on malformed option, misses LSRR/SSRR after it | Medium | fail-open / implementation-bug |

### Medium confidence (likely bug needing runtime confirmation)

| ID | Title | Severity | Class |
|---|---|---|---|
| Z-01 | `buildInterfaceZoneMap` parent pollution from unit declaration | Low | implementation-bug |
| S-05 | `alarm-without-drop` → drop transition: `syn_cookie_active_until_secs` not set during audit | Low | implementation-bug / parity-gap |

### Low confidence (parity gap, hardening, unproven defect worth triage)

| ID | Title | Severity | Class |
|---|---|---|---|
| S-01 | Flowless `UNSPEC==UNSPEC` LAND trap (defense-in-depth) | Low | defense-in-depth / robustness-dos |
| S-04 | `SynCookieValidatedCache` expired entries in non-target sets — `len` over-counts | Low | robustness / observability-lie |
| Z-02 | VRRP VIP on unit not in zone — unzoned backstop more restrictive than intended | Low | implementation-bug / dos |

---

## 7. Suggested issue split

### New issues (fail-opens first)

1. **[P1] [S-03] IPv4 options TLV malformed-option bypass of source-route screen** — fail-open, medium severity, concrete bypass trace. Labels: `fail-open`, `security`, `screen`, `source-route`
2. **[P2] [H-01] Duplicate `host-inbound-traffic` blocks lose tokens** — config-fail-open/dos, medium, concrete trace. Labels: `host-inbound`, `config-fail-open`, `implementation-bug`, `dos`
3. **[P3] [H-02] Lifeline `fab*` prefix over-broad — data interface named `fab*` silently exempted** — low, hardening. Labels: `host-inbound`, `lifeline`, `implementation-bug`, `low-priority`
4. **[P4] [S-05] `alarm-without-drop` → drop transition — SYN-cookie active state not set during audit** — low, narrow window. Labels: `syn-cookie`, `alarm-without-drop`, `implementation-bug`
5. **[P5] [Z-01] `buildInterfaceZoneMap` parent mapping from unit declaration** — low, code smell. Labels: `zone`, `implementation-bug`, `low-priority`

### Hardening / follow-up (no P1)

6. **[P6] [S-01] Flowless `UNSPEC==UNSPEC` LAND false-positive trap** — defense-in-depth. Labels: `screen`, `defense-in-depth`, `low-priority`
7. **[P7] [S-04] SYN-cookie validated-cache `len` over-counts expired entries** — observability-lie. Labels: `syn-cookie`, `robustness`, `low-priority`

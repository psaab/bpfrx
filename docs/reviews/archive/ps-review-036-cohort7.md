# xpf firewall deep security audit — cohort 7: forwarding core — master 33b891d11

## 1. Base commit reviewed

```
33b891d11 (HEAD, master) Merge pull request #4560 from psaab/fix/4557-4558-tests-nits
```

## 2. Output path

`/tmp/ps-review-036-cohort7.md`

## 3. Duplicate-suppression summary

### Sources read for dedup

| Source | Count | Coverage |
|--------|-------|----------|
| `/tmp/all_findings.txt` | 274 entries (F-001..F-274) | All titles + traces checked |
| `gh issue list --state all` | 200+ (30 OPEN, ~200 CLOSED) | Every finding checked against open + closed issue titles |
| `/tmp/ps-review-018..035` | 18 prior deep reviews | Every finding checked against prior cohort findings + triage |
| `_Log.md` | ~40k lines | Fix verification |

### CLOSED issues — do NOT re-report (per task list)

| Issue(s) | Title | Verified |
|----------|-------|----------|
| #4562 | navigatePath intermediate multi-key | CLOSED |
| #4559 | deterministic NAT advisory | OPEN (advisory only), not re-report |
| #4556 | cli/api LOW batch | CLOSED |
| #4555 | XDP EH 6 vs 8 | OPEN LOW (fail-closed parity, not bypass) — see §5/§6 |
| #4549 | LOW batch (cluster/vrrp/ipsec) | OPEN LOW |
| #4548 | VRRP flap (MaxAdverInt clamp) | OPEN LOW |
| #4547 | ipsec DNS stall | OPEN LOW (not cohort 7) |
| #4546 | WG peer_has_confirmed_session | OPEN LOW |
| #4544 | host-inbound dup block (load override) | CLOSED |
| #4543 | screen TLV walk (LSRR/SSRR after bad TLV) | CLOSED |
| #4541 | writeJSON header-before-encode | CLOSED |
| #4540 | monitor traffic keyword | CLOSED |
| #4539 | session should_cache_local_delivery non-handshake | CLOSED |
| #4535 | three-color policer color-mode | CLOSED |
| #4534 | PBR routing-instance + discard/reject | CLOSED |
| #4526 | DHCP renewalTimers overflow | CLOSED |
| #4525 | RA randomAdvInterval 0 | CLOSED |
| #4524 | monitor traffic injection | CLOSED |
| #4517 | IPv6 EH walkers MOBILITY/HIP/Shim6 | CLOSED (userspace fixed) |
| #4514 | single-rate policer unenforced | CLOSED |
| #4533 | icmp_embed EH-overflow (6 vs 8) | OPEN (not cohort 7, ps-033 NEW-01) |
| #4487/#4453/#4400 | RST/FIN session-miss | CLOSED |
| #4399/#4438 | NAT 1:N multimap | CLOSED |
| #4393 | dnat_table secondary HA-sync | CLOSED |
| #4392 | PBR reject/discard FORWARDS | CLOSED |
| #4388 | NAT pool port reservation HA | CLOSED |
| #4384 | TCP checksum dead code | CLOSED |
| #4380 | forward/reverse idle timers | CLOSED |
| #3864 | deterministic NAT flat-set parse | CLOSED (parse fix, enforcement still #4559 OPEN) |
| #3776 | flow-cache NAT reuse / session expiry | OPEN MED-HIGH |
| #2387 | bare 5-tuple VLAN/zone/VRF | OPEN P0 |

### OPEN issues — NOT re-report unless materially new trace

| Issue | Title | Cohort 7 relevance |
|-------|-------|-------------------|
| #4555 | XDP MAX_EXT_HDRS=6 vs userspace 8 | XDP shim — STILL PRESENT, LOW (fail-closed parity, not bypass) |
| #4549 | LOW batch (VRRP hop-limit, HA IPv4-only, PSK zeroize) | Not cohort 7 |
| #4548 | VRRP MaxAdverInt no clamp | Not cohort 7 |
| #4547 | ipsec DNS stall | Not cohort 7 |
| #4546 | WG peer_has_confirmed_session | Not cohort 7 |
| #4533 | icmp_embed: parse_embedded_v6_l4 EH-overflow fail-closed | OPEN, includes 6-vs-8 on embedded path |
| #4515 | config 2 warn-only gaps | Not cohort 7 |
| #4512 | NAT64 HA-sync translated port | Not cohort 7 (NAT) |
| #2387 | bare 5-tuple VLAN/zone/VRF — cross-context session reuse | P0, session/flow-cache/VLAN |
| #4146 | junos-host XDP shim bypass | Host-inbound, not forwarding |
| #4478 | IPIP decap no zone enforcement | Tunnel decap, not generic forwarding |
| #3776 | flow-cache NAT reuse / session expiry | OPEN MED-HIGH — flow-cache |
| #4498 | FRR sanitize-belt residual | Not cohort 7 |
| #4499 | test-coverage follow-ups | Not security |

### STILL PRESENT (known-open, already filed — confirmed, NOT re-reported as new)

| Issue | Finding | Status |
|-------|---------|--------|
| #2387 | V-01 Flow-cache VLAN confusion via bare set_index(physical_ifindex) | STILL PRESENT |
| #2387 | S-001 cross-zone bare 5-tuple session reuse | STILL PRESENT |
| #3776 | N-01 Flow-cache NAT port reuse after session expiry | STILL PRESENT |
| #4555 | M-02 XDP EH 6 vs 8 — 7+ EH IPv6 misses fast path | STILL PRESENT (LOW, fail-closed parity) |
| #4533 | parse_embedded_v6_l4 EH 6 vs 8 — embedded path | STILL PRESENT (OPEN, #4533) |

---

## 4. Module / verdict-path inventory (cohort 7 coverage checklist)

| File | LOC | What it does | Reviewed |
|------|-----|-------------|----------|
| `userspace-dp/src/afxdp/poll_descriptor/mod.rs` | 6095 | Per-packet hot path, session-miss, fragment handling, policy verdict, NAT, flow-cache, ICMP embed, DNAT table, session install, strict SYN check | Deep |
| `userspace-dp/src/afxdp/poll_stages.rs` | ~1200 | Stage 5-11: link-layer classify, GRE decap, parse flow + learn, fabric-ingress, screen, IPsec passthrough, SYN-cookie ACK | Deep |
| `userspace-dp/src/afxdp/forward_request.rs` | 310 | Build live forward request, TX CoS/classify, filter output | Deep |
| `userspace-dp/src/afxdp/poll_descriptor/*.rs` | 6 files | filter, flow_cache_hit, nat_exception, reject_reply, rx_telemetry, cookie_reply | Deep |
| `userspace-dp/src/afxdp/forwarding/mod.rs` | 2741 | FIB lookup, NAT scope, zone-pair, HA enforcement, fabric redirect, MTU/MSS, tunnel outer MTU | Deep |
| `userspace-dp/src/afxdp/forwarding/host_inbound.rs` | 815 | Host-inbound admission (system-services, protocols) | Spot-checked (not primary cohort) |
| `userspace-dp/src/afxdp/frame/mod.rs` | 1303 | Frame build/rewrite, NAT apply, VLAN push/pop, TTL, checksum, MSS clamp, DSCP | Deep |
| `userspace-dp/src/afxdp/frame/build/mod.rs` + ipv4.rs + ipv6.rs | ~370 | Per-family build orchestrator | Deep |
| `userspace-dp/src/afxdp/frame/rewrite/mod.rs` + ipv4.rs + ipv6.rs | ~370 | Descriptor fast-path rewrite | Deep |
| `userspace-dp/src/afxdp/frame/inspect.rs` | 1813 | Header inspection, EH walkers (8 bound), fragment detection, declared_l3_end, L3/L4 offset | Deep |
| `userspace-dp/src/afxdp/frame/checksum.rs` | 911 | Incremental + full checksum, AVX2 path, zero-canonicalization | Deep |
| `userspace-dp/src/afxdp/frame/tcp.rs` | 680 | TCP flag inspection, MSS clamp, RST/reject synthesis | Deep |
| `userspace-dp/src/afxdp/frame/headers.rs` | 338 | Ethernet/IP/UDP header writers, TxVlanTag | Deep |
| `userspace-dp/src/afxdp/frame/byte_writes.rs` | 81 | Unconditional byte-write kernels | Deep |
| `userspace-dp/src/afxdp/flow_cache.rs` | 1000 | 4-way set-associative flow cache, packet_eligible, should_cache, set_index, RW validation | Deep |
| `userspace-dp/src/afxdp/checksum.rs` | 411 | compute_ip_csum_delta, compute_l4_csum_delta, dnat_table helpers | Deep |
| `userspace-dp/src/afxdp/icmp_embed/parse.rs` | 398 | Embedded IPv4/IPv6 parse, EH walk (6 bound), fragment guards | Deep |
| `userspace-dp/src/afxdp/icmp_embed/mod.rs` + builders.rs | ~550 | Embedded NAT reversal, ICMP error rebuild | Deep |
| `userspace-dp/src/afxdp/icmp_ptb.rs` | 547 | PTB/PMTU decision, DF check, error suppression, PTB builders | Deep |
| `userspace-xdp/src/lib.rs` | 1541 | XDP shim, MAX_EXT_HDRS=6, session-map steer, is_local_destination, EH walk, DNAT, WG steer | Deep |

---

## 5. Module-by-module inspection log, including negatives

### 5.1 poll_descriptor/mod.rs — the per-packet hot path (6088 LOC)

**Fragment handling — flowless path (non-first fragments):**

Non-first fragments are detected via `frame_is_non_first_fragment()` → `parse_session_flow_from_bytes()` returns `None` → fragment becomes flowless. Flowless packets traverse:
1. Input filter with `is_fragment=true`, `l4_present=false` — `is-fragment` terms match, tcp-flags/icmp-type terms fail closed
2. PBR `then routing-instance` with flowless predicate
3. Zone security policy via `evaluate_policy_result_l3_aware` with ports=0, `l4_present=false` — port-bearing app terms fail, address/protocol/`any` terms match
4. Flowless LocalDelivery enforcement (host-inbound + lo0 + junos-host) — same l4_absent semantics

**Inspected for NEW fragment evasion:**

- `declared_l3_end` / `ipv4_declared_l3_end` / `ipv6_declared_l3_end` (#2361) correctly bounds port reads by IP-declared length, not backing buffer — prevents trailing-slack port fabrication. Verified present and used in all `parse_flow_ports` call sites.
- `frame_is_non_first_fragment` correctly detects IPv4 non-first (frag_off low 13 bits != 0) and IPv6 non-first (fragment header present AND offset != 0). Verified.
- `ipv4_is_non_first_fragment` / `ipv6_is_non_first_fragment` / `is_non_first_fragment` predicates used consistently in NAT leaves (#1852), policy, filter, CoS.
- NAT leaves skip L4 (port/checksum) on non-first fragments while still rewriting IP addresses — correct per RFC (every fragment carries IP header, only first has L4).
- **NEW finding below:** non-first fragment L4-present=false fail-closed on port-bearing DENY + later PERMIT-any chain = fail-open (F-001 in §6).

**Session-miss path — strict SYN check:**

- `strict_syn_check_drops_new_flow` = `is_closing && !has_syn` — only drops RST/FIN without SYN. Bare ACK, PSH+ACK, PSH-only, null are NOT dropped. This is intentional (asymmetric mid-stream pickup).
- Applied to transit `ForwardCandidate | MissingNeighbor` only, exempting LocalDelivery (host-bound). Correct per #4400.
- Verified: no new RST/FIN bypass beyond known #4400 fix.

**Session-miss — policy evaluation:**

- Post-translation destination (DNAT/static-DNAT/NPTv6/NAT64) used for policy: `policy_dst_ip = effective_resolution_target`, `policy_dst_port = rewritten or original`. Correct per Junos order (translation before policy).
- NAT64 cross-family (V6 src → V4 dst) handled via dedicated `try_match_rule` arm. Verified present.

**Flow-cache population:**

- `FlowCacheEntry::should_cache` = `packet_eligible && is TCP/UDP && !NAT64 && disposition.is_cacheable()`. `packet_eligible` = `is_ack_only || UDP`. TCP with SYN/FIN/RST excluded from cache (prevents TCP state confusion). Verified.
- `from_forward_decision` captures `neighbor_mac_epoch` pre-resolve (TOCTOU fix #3918). Verified.
- Seed constructors leave `policy_id=0`, `log_*=false` for transit (real metadata stamped at install site). Correct.

**Flowless transit — flowless LocalDelivery:**

- `flowless_local_delivery_verdict` enforces host-inbound → lo0 filter → junos-host. `l3_session_flow_from_meta` creates L3-only flow (ports=0). Verified gated correctly.
- `flowless_base_resolution` tries ingress-local + interface-NAT local before PBR override table. Correct per #3292/#3600.

### 5.2 poll_stages.rs

- Stage 6 GRE decap: `try_native_gre_decap_from_frame` → `stage_native_gre_decap` — rebinds meta + owned frame. Correct.
- Stage 9 fabric-ingress: sets `FABRIC_INGRESS_FLAG`, returns zone override. Must run before screen/IPsec/flow-cache. Verified ordering.
- Stage 10 screen: flowless branch runs `check_flowless_screens_opts` (LAND, ip-source-route, icmp-flood, udp-flood, ip-fragment screens) — stateless/source-independent screens on flowless path. Flow-present path runs full screen including TCP flags, SYN-flood, scan/sweep. Correct per #3902.
- Stage 11 IPsec passthrough: ESP/AH/IKE reinject via slow-path TUN. Exempt from host-inbound gate by design (#3616 Option A). Correct.
- SYN-cookie ACK on session-miss: validates cookie, mints RST + validated-client cache. Verified.

### 5.3 forwarding/mod.rs (2741 LOC)

- `zone_pair_ids_for_flow_with_override` — zero-allocation u16 zone-pair via logical ifindex. Verified.
- `nat_scope_ctx_for_flow` — resolves interface config-name + routing-instance for NAT scope. Verified.
- `cluster_peer_return_fast_path` — excludes initial SYN, ICMP echo, bare RST/FIN (#4453), non-TCP/UDP/ICMP (#4439). Verified complete.
- `tunnel_outer_mtu` — SSOT resolver for outer MTU, falls back 1500 when all lookups miss. Never returns 0 (filter + unwrap_or). Verified.
- `native_gre_inner_mtu` / `tunnel_tcp_mss` / `select_tcp_mss` — GRE/WG overhead-aware MTU/MSS. Verified chain.
- `post_transform_inner_mtu` — NAT64 GRE/WG inner MTU for PMTUD. Verified.
- `should_cache_local_delivery_session_on_miss` — single `has_syn` predicate (subsumes #2151 bare ACK + #4487 RST/FIN). `has_syn` for TCP, always true for non-TCP. Verified correct — this is the host-local cache gate, NOT the session ESTABLISHED/OPENING gate (session/mod.rs).

### 5.4 flow_cache.rs (1000 LOC)

- **STILL PRESENT (known-open, NOT new):** `set_index` uses `key + physical_ingress_ifindex` only — no VLAN, no zone/VRF. Bare 5-tuple key (`SessionKey`) — no zone/VRF. Cross-VLAN same-phys-ifindex aliasing, cross-zone/VRF session reuse. Root cause of #2387. Confirmed `flow_cache.rs:759-780` still `set_index(key, ingress_ifindex)`, `FlowCacheLookup::for_packet` still physical ifindex. Dedup: #2387 OPEN P0. **NOT re-reporting as new — CONFIRMED STILL PRESENT.**

- **STILL PRESENT (known-open, NOT new):** Flow-cache outlives idle-reaped session — reused 5-tuple served dead flow's `RewriteDescriptor` (including NAT `rewrite_src_port`). No session-epoch invalidation, no NAT port-epoch. Root cause of #3776. Confirmed `FlowCacheEntry` stamp only has `config_generation`, `fib_generation`, `owner_rg_id/epoch/lease`, `neighbor_mac_epoch` — no session GC epoch, no NAT allocator epoch. Dedup: #3776 OPEN MED-HIGH. **NOT re-reporting as new — CONFIRMED STILL PRESENT.**

- **STILL PRESENT (known-open, LOW, NOT new):** `FLOW_CACHE_SETS`, `FLOW_WORKER_MAP_MAX`, `ACTIVE_WINDOW_EPOCHS` — `lease_until` checked on lookup, `neighbor_mac_epoch` checked, `rg_epoch` checked, `config_generation` + `fib_generation` checked. But no session-alive check, no NAT-port-liveness check. This is #3776.

- `packet_eligible` = `is_ack_only(tcp_flags) || UDP` — only established TCP (pure ACK, PSH+ACK included per `is_ack_only` ignoring PSH/URG) + UDP cacheable. Correct per #2151.
- `should_cache` = `packet_eligible && TCP|UDP && !NAT64 && disposition.is_cacheable()` — NPTv6 IS cacheable (checksum-neutral), NAT64 excluded (header rebuild). Correct per #2652.
- `nat_family_matches_addr_family` — rejects AF mismatch descriptors. Verified.
- DSCP-sensitive filter → no cache. Verified.
- Per-packet L4 filter (tcp-flags/is-fragment/icmp-type) → no cache. Verified (#2362).

### 5.5 frame/inspect.rs (1813 LOC) — extension headers, fragment detection, declared_l3_end

- **MAX_IPV6_EXT_HEADERS = 8** — matches screen/extract.rs bound. All walkers in this file use 8. Verified.
- Walkers include MOBILITY(135)/HIP(139)/Shim6(140)/experimental(253/254) per #4517. Verified in all 6 walker sites.
- Overshoot at bound → fail-closed (None, not Some with EH type as bogus L4). Per #2292. Verified all 6 sites return None.
- `ipv4_is_non_first_fragment` / `ipv6_is_non_first_fragment` / `is_non_first_fragment` / `ipv4_is_any_fragment` / `ipv6_is_any_fragment` / `is_any_fragment` — all bounded, with correct masks. Verified.
- `declared_l3_end` / `ipv4_declared_l3_end` / `ipv6_declared_l3_end` — bounds port reads by IP-declared length. Panic-safety guard (`ihl < 20 || frame.len() < l3 + ihl → None` before `clamp(min=l3+ihl, max=frame.len())`). Verified per #2361 fix (commit 8a2d4f365 context).
- `term_match_extra_from_frame` — non-first fragment: tcp_flags=icmp_type=icmp_code=0, l4_present=false, is_fragment=true. Truncated ICMP: icmp_type_code fail-closed (l4_present=false). Verified per #2449.
- `frame_is_non_first_fragment` — resolves L3 via meta.l3_offset when plausible, else `frame_l3_offset`. Version-nibble + family match before fragment test — prevents garbage-frame misclassification. Verified.

### 5.6 frame/checksum.rs (911 LOC)

- `checksum16_add_bytes` — short-circuit <32B → scalar, else AVX2 if available → scalar remainder. Bit-identical per differential tests. Verified.
- `checksum16_finish` — carry fold loop. Verified standard.
- `checksum16_adjust` — RFC 1624 `~(old) + new` delta. Verified.
- `l4_checksum_field_delta_v4` — TCP +16, UDP +6, ICMP/ICMPv6/unknown → None (no-op). No ICMPv6 arm for v4 — correct (IPv4 packets never carry ICMPv6). Verified.
- `l4_checksum_field_delta_v6` — TCP +16, UDP +6, ICMPv6 +2. Verified.
- `l4_udp_checksum_optional` — V4 UDP only (RFC 768 "no checksum" is v4-only). Verified per #1840.
- `adjust_zero_checksum_illegal` — V4: UDP only; V6: UDP + ICMPv6 (RFC 8200 §8.1). Verified per #1839.
- `adjust_l4_checksum_ipv4_src/dst/words` — optional-checksum skip (stored 0 on v4 UDP), computed-zero → 0xFFFF for v4 UDP. Verified.
- `adjust_l4_checksum_ipv6_words/addr_bytes` — computed-zero → 0xFFFF for v6 UDP+ICMPv6. Verified.
- `recompute_l4_checksum_ipv4` — zero_offset param (UDP 0→0xFFFF), TCP never canonicalizes 0. Verified.
- `recompute_l4_checksum_ipv6` — UDP + ICMPv6 computed-zero → 0xFFFF, TCP never. Verified per #1839.
- Incremental-port adjust tests: proto-58 no-op, overflow → None for recognized. Verified.

### 5.7 frame/tcp.rs (680 LOC)

- `frame_has_tcp_rst` — ext-aware via `packet_rel_l4_offset_and_protocol`, not fixed L3+40. Verified per #2148.
- `extract_tcp_flags_and_window` / `extract_tcp_window` — ext-aware. Verified.
- `clamp_tcp_mss` — SYN-only, MSS option walk, RFC 1624 incremental checksum `old_csum + old_val + ~new_val`. Fragment-aware (non-first → no clamp). Verified.
- `tcp_segment_consumed_len` — SYN(1) + FIN(1) + payload_len. IPv6 ext-aware: uses `frame_l4_offset` for TCP start, not fixed 40. Correct per v6 ext fix. Verified.
- `build_reject_rst_frame` — L2 group/broadcast suppression, RST-storm prevention (no reply to inbound RST), no-ACK→(0, seq+len, RST|ACK), ACK→(ack, 0, RST). Verified.
- `build_syn_cookie_syn_ack_frame` / `build_syn_cookie_ack_rst_frame` — correct flag/seq/ack/MSS. Verified.

### 5.8 frame/headers.rs (338 LOC)

- `TxVlanTag` —TPID, TCI (PCP+DEI+VID), present flag. `From<u16>`: vid & 0x0FFF, present=vid>0, TPID=0x8100. `emits()` = present && tci!=0. `header_len()` = emits?18:14. `write_eth_header_slice_tagged` — priority-tagged VLAN-0 (VID 0, PCP!=0) serialized when TxVlanTag carries PCP. Verified.

### 5.9 frame/byte_writes.rs (81 LOC)

- `write_ipv4_src/dst`, `write_ipv6_src/dst` — NO length guard (caller must validate). Correct — callers validate `packet.len() >= ip+20/40` before calling.
- `write_l4_src/dst_port` — bounds-checked (`packet.len() >= l4+2/+4`). Correct.
- `#[inline(always)]` on all helpers. Verified.

### 5.10 frame/mod.rs — frame build/rewrite, NAT apply, VLAN, port enforcement

- `rewrite_prepare_eth_from_parts` — `vlan_id > 0 → 18 else 14` for eth_len. Uses `TxVlanTag::from(vlan_id)` via `write_eth_header_slice` which is `write_eth_header_slice_tagged(buf, ..., TxVlanTag::from(vlan_id), ...)`. Since `TxVlanTag::from(vlan_id)` has `present = vid>0`, and bare `vlan_id > 0` also means `present = true`, the eth_len check and the TxVlanTag check agree. **No bug for pure VID.** Priority-tagged VLAN-0 on egress (VID=0, PCP!=0) would need a full TxVlanTag with PCP — but egress `tx_vlan_id` is a bare u16 VID from EgressInterface, not carrying PCP. PCP on egress comes from CoS via `dscp_rewrite` / `cos_queue_id`, not from VLAN tag PCP bits. Working as designed.
- `rewrite_apply_v4` / `rewrite_apply_v6` — TTL<=1 → None (fail-closed for TTL expiry). Non-first fragment: IP rewrite still runs, L4 skip. Verified.
- `apply_nat_ipv4` / `apply_nat_ipv6` — IP rewrite + L4 port/identifier + checksum. Non-first fragment: IP still, L4 skip. NPTv6 skip_l4_csum when only NPTv6. Verified.
- `apply_nat_port_rewrite` — `has_l4_ports(protocol)` gate (TCP/UDP only), skips GRE/ESP/AH. Verified per #3111.
- `apply_nat_icmp_identifier_rewrite` — `icmp_identifier_bearing` gate (echo/timestamp/info only), not error types. Verified per #4074.
- `enforce_expected_ports` — expects ports from meta/frame, fails back to recompute. Non-first fragment → no enforce. Verified.

### 5.11 flow_cache.rs / checksum.rs — flow-cache + NAT checksum deltas

- `compute_ip_csum_delta` — `~old_w + new_w` for each changed IPv4 word. Fold at end. Verified RFC 1624.
- `compute_l4_csum_delta` — NPTv6 pure (only src or only dst) → 0 (checksum-neutral). Compose (both src+dst, NPTv6+DNAT) → fall through, NPTv6 term naturally nets zero, DNAT term applied. Verified per #3121.
- `nat_family_matches_addr_family` — rejects AF mismatch. Verified per #963 PR-A.

### 5.12 icmp_embed/parse.rs + builders.rs

- `parse_embedded_v4` — non-first fragment guard (frag_off & 0x1FFF != 0 → None). Verified per #1852.
- `parse_embedded_v6_l4` — `for _ in 0..6` with Mobility/HIP/Shim6, fragment-aware. **BUT:** 6 iterations vs canonical 8. Fallthrough returns `Some((offset, protocol))` where protocol may still be an EH type (the 7th EH). See findings.
- `parse_embedded_v6` — calls `parse_embedded_v6_l4`, reads ports/ident from L4 offset. Correct when walk succeeds.
- `build_nat_reversed_icmp_error_v4` / `v6` — outer IP rewrite + embedded IP+port reversal + checksum recompute. Non-first fragment skip for embedded L4. Verified.

### 5.13 icmp_ptb.rs (547 LOC)

- `forwarded_egress_mtu_decision` — IP-declared length (`ip_declared_l3_len`: total_len for v4, 40+payload_len for v6, clamped to buffer) vs egress MTU. Non-DF oversized v4 → Forward (don't PTB-storm). IPv6 always PTB. Floor at protocol minimum (1280 v6, 68 v4). Verified per #2301/#2783.
- `ipv4_df_set` — bit 14 of flags+frag_off (0x4000). Correct.
- `ptb_reply_suppressed` — L2 group/broadcast, non-first fragment, bad source (unspecified/loopback/multicast/broadcast), directed-broadcast source/dest, inbound ICMP error (no error-of-error). All verified per #2325/#2367/#2487/#2314/#2411.
- `build_frag_needed_v4` / `build_packet_too_big_v6` — L2 reflect, ingress-sourced outer IP, MTU in next-hop field, quote, checksum. Verified.
- `post_transform_inner_mtu` — NAT64/WG/GRE inner MTU for PMTUD. Verified per #2330/#2684.

### 5.14 userspace-xdp/src/lib.rs (1541 LOC)

- `MAX_EXT_HDRS = 6` vs userspace `MAX_IPV6_EXT_HEADERS = 8`. **STILL PRESENT (known-open, NOT new):** XDP shim walks max 6 EHs. A 7-EH or 8-EH packet is handled as: if 7th header is an EH type that the match doesn't enumerate, `parse_ipv6` breaks with `protocol = <7th EH type>` as if it were L4. Then `parse_l4` reads at offset past 6 EHs and tries to parse what is actually the 7th EH as TCP/UDP/ICMP → wrong flow tuple or parse failure. Result: XDP fast-path MISS → userspace slow path (no bypass, no fail-open, just perf). If `_ => break` fires on the 7th EH (an L4 type like TCP=6), it correctly identifies the L4 protocol and 5-tuple. So 7-EH packet with TCP as 8th next-header: 6 EHs consumed, 7th EH's type (e.g., 60=DestOpt) treated as "protocol" → wrong steer. MISS. Dedup: #4555 OPEN LOW. **CONFIRMED STILL PRESENT — NOT re-reporting as new.**

- EH types enumerated: `HOP(0) | ROUTING(43) | DEST(60) | AUTH(51) | FRAGMENT(44) | NONE(59)`. Missing: Mobility(135)/HIP(139)/Shim6(140)/experimental(253/254) per #4517 userspace fix. XDP shim still 6 types. Same perf-only (not bypass) reasoning. Dedup: #4517 CLOSED for userspace, XDP shim residual is #4555. **NOT new.**

- `is_local_destination` — checks `LOCAL_V4/V6` but NOT `INTERFACE_NAT_V4/V6` first (those return false → not local). Verified per #2406.
- `is_icmp_to_interface_nat_local` — echo request(8)/reply(0) for v4, 128/129 for v6 to interface-NAT. Verified.
- `is_interface_nat_destination` — excludes ICMP error types (3/11/4/12 for v4, 1-4 for v6) so embedded-ICMP goes to userspace. Verified.
- `wg_steer_to_kernel` — gated on WG_RX flag, checks UDP + wg_port + is_local_destination. Verified per #1432.
- `should_fallback_early` — broadcast/multicast/link-local → pass to kernel. Verified.

---

## 6. Findings

### 6.1 High confidence — NEW (not in any prior source)

#### [F-001] [MEDIUM] Non-first fragment bypasses port-bearing DENY policy when later PERMIT-any rule exists

- **Title**: Non-first IPv4/IPv6 fragment bypasses a port-bearing `then deny` security policy rule when a later `then permit any` rule exists in the same zone-pair — fail-open
- **Severity**: Medium
- **Confidence**: High
- **Class**: fail-open / implementation-bug
- **Evidence**:

  ```rust
  // userspace-dp/src/afxdp/poll_descriptor/mod.rs:3433-3590 — flowless transit path

  // Stage 7: parse_session_flow_from_bytes returns None for non-first fragment
  // frame_is_non_first_fragment(frame, meta) → true → parse_session_flow_from_bytes → None
  // → flow = None, l3_session_flow_from_meta(meta) → Some(ports=0)

  // Stage 12 (flowless transit, ~L3433):
  let l3_ctx = l3_session_flow_from_meta(meta);
  // (1) input filter ... (2) PBR ... (3) zone policy:

  // userspace-dp/src/afxdp/poll_descriptor/mod.rs:3586-3646
  if final_resolution.disposition == ForwardingDisposition::ForwardCandidate
      && let Some(l3_flow) = l3_ctx.as_ref()
  {
      let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(...);
      let policy_icmp = policy_packet_icmp(packet_frame, meta); // None for fragment
      let policy_result = crate::policy::evaluate_policy_result_l3_aware(
          &worker_ctx.forwarding.policy,
          from_zone_id, to_zone_id,
          l3_flow.src_ip,
          l3_flow.dst_ip,
          meta.protocol,        // e.g., 6 (TCP)
          0, 0,                 // ports = 0 — no L4 header
          policy_icmp,          // None — no ICMP type/code
          desc.len as u64,
          false,                // l4_present = false
      );
      if !matches!(policy_result.action, PolicyAction::Permit) {
          // deny → emit event, recycle, continue (DROP) — correct
      }
      // ← if Permit, falls through to FORWARD — bug when deny was skipped
  }

  // userspace-dp/src/policy.rs (try_match_rule / evaluate_policy_result_l3_aware):
  // With l4_present=false, dst_port=0:
  //   - Application term junos-https (tcp/443) → requires dst_port 443
  //     → l4_present=false → application fails → rule does NOT match → next rule
  //   - Application term any (no port) → matches on address/protocol alone
  //     → rule matches → Permit → forward
  ```

- **Trace**:

  Config:
  ```
  set security zones security-zone trust interfaces ge-0/0/1.0
  set security zones security-zone untrust interfaces ge-0/0/2.0
  set security policies from-zone trust to-zone untrust policy block-https
      match source-address 10.0.0.0/8
      match destination-address any
      match application junos-https
      then deny
  set security policies from-zone trust to-zone untrust policy permit-rest
      match source-address any
      match destination-address any
      match application any
      then permit
  set security policies default-policy deny-all
  ```

  Attacker packet: `10.0.1.100 → 203.0.113.50 TCP`, fragmented into 2 fragments:
  - Fragment 1: offset=0, MF=1, carries TCP header (src=54321, dst=443) → `parse_session_flow_from_bytes` succeeds → flow with ports → `evaluate_policy_result_with_icmp` with `l4_present=true`, dst_port=443 → matches `block-https` (src 10.0.0.0/8, app junos-https=443) → **DENY** → dropped. Correct.
  - Fragment 2: offset=185 (non-zero), MF=0, no L4 header (payload bytes at post-IP offset) → `frame_is_non_first_fragment` → `parse_session_flow_from_bytes` → `None` → flowless → `l3_session_flow_from_meta` (ports=0) → `evaluate_policy_result_l3_aware` with `l4_present=false`, ports=0:
    - Rule `block-https`: src 10.0.0.0/8 ✓, dst any ✓, app junos-https needs dst_port 443 but ports=0, l4_present=false → **rule does NOT match** → next rule
    - Rule `permit-rest`: src any ✓, dst any ✓, app any ✓ (no port needed) → **PERMIT** → **FORWARDED** — **FAIL-OPEN**

  vSRX behavior: Junos buffers the first fragment and associates non-first fragments with it (fragment cache), or applies the same policy decision as the first fragment. A denied flow's fragments are all dropped. xpf's flowless path makes a fresh, L4-absent policy decision that diverges from the first fragment's decision.

- **Refutation attempted**:

  1. "Non-first fragments are useless without the first fragment" — The first fragment IS dropped (policy deny), but the non-first fragment is still forwarded to the destination host. While it cannot form a valid TCP stream, it can:
     - Cause reassembly confusion on the destination (if the destination reassembles fragments from multiple sources)
     - Be used for overlapping fragment attacks (teardrop, etc.) against the destination
     - Consume destination reassembly buffer (DoS)
     - The principle is: if policy says DENY a flow, NO packet of that flow should be forwarded, including fragments.

  2. "The code documents this as a known limitation (deferred fragment-association-cache)" — The comment at `poll_descriptor/mod.rs:3448-3450` says "L4-specific-PERMITTED fragmented flows are the deferred fragment-association-cache stage — until then their non-first fragments fall to the default policy". This documents the PERMIT→default-deny case (fail-CLOSED for permitted flows — availability issue). It does NOT document the DENY→permit-any fail-OPEN case, which is a different direction of failure (security, not availability).

  3. "Is this reachable? Non-first fragments go through MissingNeighbor path?" — No. Non-first fragments with `flow=None` go through the flowless transit path at `poll_descriptor/mod.rs:3433` (when `flow` is None). They do NOT go through the session-miss path (which requires `Some(flow)`). The flowless transit path is reachable for any non-first fragment arriving on an AF_XDP port. The XDP shim does NOT drop non-first fragments (it parses them, extracts src/dst from IP header even for fragments).

  4. "Does XDP shim drop non-first fragments before userspace?" — Checked `userspace-xdp/src/lib.rs:parse_ipv4` and `parse_ipv6`: the shim reads protocol, ports from the frame. For IPv4 fragments: `parse_ipv4` reads `flow_src_port`/`flow_dst_port` from bytes after the IP header — for a non-first fragment, these bytes are payload, not ports, but the shim doesn't validate fragment offset. The packet still reaches userspace with `meta.flow_src_port/flow_dst_port` potentially containing garbage (payload bytes misread as ports), but `parse_session_flow_from_bytes` in userspace correctly detects non-first fragment and returns None (flowless). The packet reaches the flowless path.

  5. "Does the screen path drop non-first fragments first?" — No. `stage_screen_check` flowless branch runs screen checks (ping-of-death, teardrop, icmp-fragment, LAND) but does NOT drop based on policy. A non-first fragment passes screen (unless it's a teardrop/ping-of-death fragment) and continues to the policy stage.

  Path is reachable from production caller (`poll_binding_process_descriptor` → flow=None → flowless transit at L3433).

- **Why it matters**: A configured DENY policy for a specific application (e.g., block HTTPS from a subnet) is silently bypassed for non-first fragments when any later PERMIT-any rule exists. While individual non-first fragments cannot form a valid TCP stream without their first fragment, they still reach the destination host and can contribute to reassembly attacks, buffer exhaustion, or bypass monitoring. More fundamentally, the firewall violates its configured policy — the operator believes "10.0.0.0/8 cannot reach untrust on HTTPS" but fragments from that subnet do reach untrust. This is a fail-open.

- **Fix direction**: Two options:
  1. **Fail-closed for non-first fragments on DENY-rule skip** (simplest, most secure): When `l4_present=false` and the policy engine skips a DENY rule because a port-bearing application term failed, track that a DENY was L4-skipped. If the final verdict would be PERMIT (from a later any-rule), override to DENY. This ensures a DENY that matched on L3 (address/protocol) is never bypassed by a later PERMIT just because the fragment lacks L4.
  2. **Fragment-to-first-fragment association cache** (the deferred #3291 plan): Cache the first fragment's verdict and apply it to all fragments of the same IP ID + src/dst. This is the principled fix (matches Junos behavior) but more complex.

  Option 1 is the minimal fix. Option 2 is the long-term fix.

  Alternatively, as an interim hardening: if default-policy is NOT deny (i.e., there's a permit-any), non-first fragments should be dropped when they match a DENY rule on L3 (address/protocol) even if the L4 application check fails.

- **Labels**: `fail-open`, `security`, `fragment-evasion`, `policy-bypass`, `forwarding-core`, `medium`
- **Dedup note**: NOT in `/tmp/all_findings.txt` (274 entries — no non-first-fragment DENY→permit-any fail-open described). NOT in `gh issue list --state all` (no non-first-fragment policy-bypass fail-open — #2387 covers bare 5-tuple cross-zone/VLAN/VRF session/flow-cache confusion, not fragment-specific policy fallthrough; #4533 covers EH-overflow for fail-closed, not fragment fail-open). NOT in `/tmp/ps-review-018..035` — ps-035 §5 Cohort 7 says "H-02 tiny fragment port evasion — ... port-bearing deny fail-closed via l4_present=false" but only considers a single-DENY or default-deny case (fail-closed), not a DENY + later PERMIT-any chain. The existing analysis incorrectly concludes "verified NOT exploitable" by checking only "port-bearing deny fail-closed" without considering fallthrough to a permissive later rule. This is NEW — a distinct policy-rule-ordering interaction not previously identified.

---

### 6.2 Medium confidence — NEW (needs runtime confirmation or is a narrow edge case)

#### [F-002] [MEDIUM] `parse_embedded_v6_l4` 6-iteration bound returns garbage protocol when 7+ extension headers — embedded NAT/session match reads EH bytes as L4 ports

- **Title**: `parse_embedded_v6_l4` uses 6-iteration EH walk vs 8-iteration canonical — 7+ EH quoted packet causes wrong L4 parse, breaks embedded NAT reversal
- **Severity**: Medium
- **Confidence**: High
- **Class**: implementation-bug / protocol-corruption / correctness
- **Evidence**:

  ```rust
  // userspace-dp/src/afxdp/icmp_embed/parse.rs:108-158
  pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6_l4(packet: &[u8]) -> Option<(usize, u8)> {
      if packet.len() < 40 { return None; }
      let mut protocol = *packet.get(6)?;
      let mut offset = 40usize;
      for _ in 0..6 {  // ← 6, not 8
          match protocol {
              0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => { /* advance 8 */ }
              51 => { /* advance (len+2)*4 */ }
              44 => { /* fragment check */ }
              59 => return None,
              _ => return Some((offset, protocol)),
          }
      }
      Some((offset, protocol))  // ← fallthrough: protocol may still be an EH type!
  }

  // Compare with canonical walker:
  // userspace-dp/src/afxdp/frame/inspect.rs:31
  pub(crate) const MAX_IPV6_EXT_HEADERS: usize = 8;
  // userspace-dp/src/afxdp/frame/inspect.rs:90
  for _ in 0..MAX_IPV6_EXT_HEADERS { // 8 iterations
      // ... same match ...
  }
  // At bound → None (fail-closed), not Some with EH type:
  // frame/inspect.rs:123-129
  // #2292: still on an extension header at the bound — fail CLOSED
  None
  ```

- **Trace**:

  Config: SNAT pool for v6 clients, PMTUD (Packet Too Big) triggered by oversized TCP to server.

  - Client `2001:db8::1:54321` → server `2001:db8::2:443` via xpf SNAT to `2001:db8:ffff::1:60001`.
  - Server sends ICMPv6 Packet Too Big (type 2) quoting the original TCP packet.
  - Quoted (embedded) packet is `2001:db8::1` → `2001:db8::2` with 7 extension headers: `HbH(0) → DestOpt(60) → Routing(43) → HbH(0) → DestOpt(60) → HbH(0) → DestOpt(60)` → TCP(6), ports 54321→443.
  - `parse_embedded_v6_l4` walks 6 EHs (consumes HbH/Routing/DestOpt × 6), remaining `protocol = 60` (7th DestOpt), `offset` = past 6th EH. Loop exhausts → `Some((offset, 60))` — returns DestOpt as "L4 protocol" with offset pointing at DestOpt's bytes.
  - `parse_embedded_v6` reads `proto=60`, tries `matches!(proto, TCP|UDP)` → no → `matches!(proto, ICMPv6)` → no → `(src_port, dst_port)=(0,0)`.
  - `embedded_reply_key` with ports 0,0 does NOT match the session (which has src_port=54321, dst_port=443) → **no NAT reversal** → PMTUD back to client fails → client's TCP stalls on oversized packets → **PMTUD blackhole**.

  Compare with canonical path (8 iterations): would consume all 7 EHs in 7 iterations, return `Some((offset, 6))` (TCP), ports correctly 54321→443, session matches, NAT reversal works, PMTUD succeeds.

  Or with fail-closed at bound: 7+ EHs at 6-iteration bound → `None` → embedded NAT match skipped → same PMTUD blackhole (but at least consistent with canonical path when it has 9+ EHs).

- **Refutation attempted**:

  1. "7+ EH packets are vanishingly rare" — True in practice (real-world packets rarely have more than 2-3 EHs). But the fix is trivial (change 6→8 + fail-closed at bound), and the inconsistency between canonical (8) and embedded (6) is a correctness bug that any EH-tolerant scanner could trigger.

  2. "This is already tracked as #4533 or #4555" — #4555 tracks XDP shim (6 vs 8, XDP fast-path miss → slow-path, perf only, LOW). #4533 tracks `parse_embedded_v6_l4` EH-overflow fail-closed alignment (OPEN, ps-033 NEW-01, not cohort 7). This finding IS #4533's embedded path — but #4533 was filed as a general "align EH-overflow to fail-closed None" without specifically identifying the 6-iteration bound vs 8, and without a concrete trace showing wrong-protocol return. This provides the concrete 7-EH trace + wrong-protocol evidence. Since #4533 is OPEN and covers this, **this is a materially improved trace for #4533, not a separate NEW issue.**

- **Why it matters**: Embedded IPv6 extension-header chain handling for ICMPv6 error NAT reversal is inconsistent with the canonical forwarding path (6 vs 8 bound). A 7-EH quoted packet returns the wrong L4 protocol and garbage ports, causing PMTUD to silently fail for that flow. While 7-EH packets are rare, the fix is one-line and eliminates a class of silent PMTUD blackholes.

- **Fix direction**: Change `for _ in 0..6` → `for _ in 0..MAX_IPV6_EXT_HEADERS` (or `for _ in 0..8`). Add `None` fallthrough instead of `Some((offset, protocol))` at loop exhaustion to fail-closed (consistent with canonical walkers). Import `MAX_IPV6_EXT_HEADERS` from `crate::afxdp::frame::inspect`.

- **Labels**: `protocol-corruption`, `ipv6-extension-headers`, `icmp-embed`, `pmtud-blackhole`, `medium`, `forwarding-core`
- **Dedup note**: OVERLAPS with #4533 OPEN ("icmp_embed: align parse_embedded_v6_l4 EH-overflow to fail-closed None (matches inspect/nat64 #2292/#4435)") — #4533 already tracks EH-overflow fail-closed for parse_embedded_v6_l4. This finding provides a concrete 7-EH trace showing not just fail-open-to-wrong-match but specifically wrong-protocol return (DestOpt=60 returned as "L4 protocol"). The 6-vs-8 bound discrepancy is the root cause, same as #4533. **This is a materially improved trace for #4533 (embedded path), not a separate NEW issue — do NOT file separately unless #4533 is closed without fixing the 6→8 bound.**

---

### 6.3 Low confidence — hardening / parity / design smell

#### [F-003] [LOW] VLAN tag `vlan_id > 0` bare check in `frame/mod.rs` in-place rewrite vs `TxVlanTag::emits()` — no security impact, parity with build path

- **Title**: `frame/mod.rs:505` `eth_len = if params.vlan_id > 0 { 18 } else { 14 }` uses bare VID check while `TxVlanTag::emits()` checks `present && tci!=0` — no security impact
- **Severity**: Low
- **Confidence**: Medium
- **Class**: hardening / implementation-bug (cosmetic)
- **Evidence**:

  ```rust
  // userspace-dp/src/afxdp/frame/mod.rs:505 — in-place rewrite prep
  let eth_len = if params.vlan_id > 0 { 18usize } else { 14usize };
  // Called from rewrite/mod.rs:80-84 with rd.tx_vlan_id (bare u16 VID)

  // userspace-dp/src/afxdp/frame/headers.rs:112-119 — TxVlanTag::emits
  pub(in crate::afxdp) fn emits(&self) -> bool { self.present && self.tci != 0 }
  // From<u16> for TxVlanTag: present = vid > 0, tci = vid, TPID = 0x8100
  impl From<u16> for TxVlanTag { fn from(vid: u16) -> Self { TxVlanTag { tpid: 0x8100, tci: vid & 0x0FFF, present: vid > 0 } } }

  // write_eth_header_slice uses TxVlanTag::from(vlan_id) → same bare VID>0 logic
  // So eth_len and write_eth_header_slice agree — no mismatch.
  ```

- **Trace**: N/A — no divergent behavior for pure VID. `vlan_id > 0` and `TxVlanTag::from(vlan_id).emits()` are equivalent (both: present iff vid>0, no PCP/DEI). The `emits()` extra check (`tci != 0`) is moot when tci==vid and vid>0 → tci!=0.

  Priority-tagged VLAN-0 (VID=0, PCP!=0) on egress would need a full TxVlanTag with PCP — but egress `tx_vlan_id` is a bare VID from EgressInterface (no PCP), and PCP on egress comes from CoS `dscp_rewrite` / `cos_queue_id`, not VLAN tag PCP bits. Working as designed.

- **Refutation**: Traced `tx_vlan_id` source — `EgressInterface.vlan_id` (bare VID), set in `forwarding_build/interfaces.rs` from interface config `vlan_id`. No PCP/TPID carried on egress VLAN tag (by design — PCP is CoS, not interface VLAN). Both checks (eth_len bare + TxVlanTag::from) agree for bare VID.

- **Why it matters**: No security impact. Could be a code clarity issue (one site uses bare check, other uses TxVlanTag abstraction, but they're equivalent). Not worth filing.

- **Fix direction**: If this were to be fixed: use `TxVlanTag::from(params.vlan_id).header_len()` consistently instead of bare `vlan_id > 0`. Cosmetic cleanup only.

- **Labels**: `hardening`, `vlan`, `cosmetic`, `low`
- **Dedup note**: NOT in any open issue or prior finding. NOT a security bug — cosmetic. **Not filing.**

---

## 7. Verified negatives (paths confirmed fail-closed — coverage proof)

These are high-value "this does NOT bypass" results:

### NAT / NAT64 — fail-closed

- **N-01**: NAT64 no-pool / pool-exhaustion → drop (not route as synthetic IPv6). `nat64_match: MatchUnavailable → counters.nat64_no_source_pool +=1, recycle, continue`. Verified in `poll_descriptor/mod.rs:1527-1535`.
- **N-02**: NAT64 port allocator exhaustion on admitted flow → drop (not collide). `allocate_source() Err → record_nat64_source_failure, recycle, continue`. Verified in `poll_descriptor/mod.rs:2639-2677`.
- **N-03**: Pool-mode SNAT non-first fragment → no pool-mode allocation (leaks port, corrupts payload). `snat_non_first_fragment = is_non_first_fragment(...)` → `match_source_nat_result_for_tuple(..., non_first_fragment, ...)` with gate. Verified.

### Fragment handling — fail-closed (except F-001 above)

- **N-04**: `declared_l3_end` bounds port reads by IP-declared length, not backing buffer. Slack/padding bytes never parsed as ports. Verified — all `parse_flow_ports` sites pass `declared_end`.
- **N-05**: Non-first fragments → flowless → no session install, no flow-cache seed. Verified — `parse_session_flow_from_bytes → None → flow=None → flowless path`.
- **N-06**: NAT leaves skip L4 on non-first fragments (port/checksum/ICMP-ident), but still rewrite IP. Verified — every `apply_nat_ipv4/ipv6` and `apply_nat_port_rewrite` / `apply_nat_icmp_identifier_rewrite` gate on `non_first_fragment`.
- **N-07**: `term_match_extra_from_frame` non-first fragment: tcp_flags=icmp_type=icmp_code=0, l4_present=false, is_fragment=true. Per-packet L4 terms (tcp-flags, icmp-type, icmp-code) fail closed; is-fragment term matches. Verified.
- **N-08**: Flowless MissingNeighbor: zone policy enforced before neg-cache/NAT/probe/buffer. `l3_session_flow_from_meta` → policy check — DENY → drop before side-effects. Verified (#4024).

### IPv6 extension headers — bounded + fail-closed

- **N-09**: All 6 userspace walker sites use `0..MAX_IPV6_EXT_HEADERS` (8), include Mobility(135)/HIP(139)/Shim6(140)/experimental(253/254), fail-closed (None) at bound. Verified in inspect.rs.
- **N-10**: XDP shim 6 vs 8: 7+ EH packet → wrong steer or parse-fail, but NOT bypass — XDP miss → userspace slow path re-parses with 8 bound → correct verdict (or fail-closed). Fail-closed parity, not bypass. Verified.

### VLAN / zone / interface — correct (within #2387 caveat)

- **N-11**: `resolve_ingress_logical_ifindex` correctly maps physical+VLAN → logical unit for zone lookup, NAT scope, screen zone, host-inbound. Non-VLAN ports: physical==logical. Verified.
- **N-12**: `flowless_base_resolution` tries ingress-local + interface-NAT local before PBR override table. Host-bound flowless not PBR-steered. Verified per #3292/#3600.
- **N-13**: `host_inbound_gated_lo0_action` → host-inbound DENY is silent drop with NO lo0 side-effects. Verified per #3485.

### Checksum — RFC 1624 correct

- **N-14**: `compute_ip_csum_delta` / `compute_l4_csum_delta` correctly implement RFC 1624 incremental update: `~old + new` per word, fold, complement. NPTv6 pure→0, compose→DNAT only. Verified.
- **N-15**: IP header checksum TTL-1 delta `0xFEFF` constant is correct (TTL byte is high byte of `TTL<<8|proto` word, decrement by 1<<8 = 0x0100, delta = `~old + new` = `0xFEFF`). Verified.
- **N-16**: UDP checksum 0x0000 handling: v4 UDP 0 = "no checksum" (skip adjust), v6 UDP 0 = malformed (adjust like any value), computed-zero canonicalization: v4 UDP only → 0xFFFF, v6 UDP+ICMPv6 → 0xFFFF, TCP never. Verified per #1839/#1840.

### ICMP / PTB / PMTU — correct suppression + fail-closed

- **N-17**: `ptb_reply_suppressed` — L2 group/broadcast, non-first fragment, bad source (unspec/loopback/mcast/bcast), directed-broadcast src/dst, inbound ICMP error. All verified per #2325/#2367/#2487/#2314/#2411.
- **N-18**: `forwarded_egress_mtu_decision` — IP-declared length (not buffer), non-DF v4 → Forward (don't PTB-storm), IPv6 always PTB, floor at protocol minimum. Verified.
- **N-19**: ICMP type/code for policy: `policy_packet_icmp` returns None for truncated/non-first/error packets → icmp-type-constrained terms fail closed. Verified per #3020/#2449.

### Flow-cache / session — correct (within #2387/#3776 caveat)

- **N-20**: `FlowCacheEntry::packet_eligible` = `is_ack_only || UDP` — SYN/FIN/RST never cacheable. `is_ack_only` = `(flags & 0x17) == 0x10` (ACK set, FIN/SYN/RST clear, PSH/URG ignored). Verified per #2151.
- **N-21**: `FlowCacheEntry::should_cache` = `packet_eligible && TCP|UDP && !NAT64 && is_cacheable()`. NPTv6 IS cacheable, NAT64 excluded. Verified per #2652.
- **N-22**: `nat_family_matches_addr_family` — AF mismatch → None (don't cache mismatched descriptor). Verified per #963 PR-A.

---

## 8. Suggested issue split — NEW only

### Fail-opens first

| # | Title | Severity | Confidence | Finding |
|---|-------|----------|------------|---------|
| 1 | Non-first fragment bypasses port-bearing DENY when later PERMIT-any exists | Medium | High | F-001 (§6.1) |

### Protocol / correctness

| # | Title | Severity | Confidence | Finding |
|---|-------|----------|------------|---------|
| 2 | parse_embedded_v6_l4 6-iteration bound — concrete 7-EH wrong-protocol trace (improved evidence for #4533) | Medium | High | F-002 (§6.2) — **do NOT file separately, attach to #4533** |

### Already filed — confirmed still present (do NOT file again)

| Issue | Finding | Status |
|-------|---------|--------|
| #2387 | V-01 Flow-cache + session VLAN confusion — bare 5-tuple, bare set_index(physical_ifindex) | STILL PRESENT |
| #2387 | S-001 cross-zone bare 5-tuple session reuse — session/key.rs bare 5-tuple | STILL PRESENT |
| #3776 | N-01 Flow-cache NAT port reuse — no session-epoch/NAT-epoch in FlowCacheStamp | STILL PRESENT |
| #4555 | M-02 XDP EH 6 vs 8 — parse_ipv6 for _ in 0..MAX_EXT_HDRS(6) vs userspace 8 | STILL PRESENT (LOW, fail-closed parity) |
| #4533 | parse_embedded_v6_l4 EH 6 vs 8 — for _ in 0..6 returns Some(EH_type) | STILL PRESENT (OPEN, improved trace in F-002) |

---

## 9. Coverage summary

- All cohort 7 files read (14 files, ~15000 LOC total)
- 1 NEW Medium fail-open found (F-001: non-first fragment → port-bearing DENY skip → PERMIT-any)
- 1 improved trace for existing OPEN issue #4533 (F-002: parse_embedded_v6_l4 6-vs-8 → wrong protocol)
- 4 known STILL PRESENT issues confirmed (not re-filed)
- 22 verified negatives (fail-closed proofs)
- 0 LOW hardening issues filed (1 cosmetic VLAN noted, not filed)
- No NEW fragment evasion beyond F-001
- No NEW flow-cache bypass beyond #2387/#3776
- No checksum errors found (RFC 1624 correct)
- No MTU/MSS/TTL/DF/hop-limit math errors found
- VLAN tag push/pop correct (TxVlanTag + bare VID equivalent for pure VID)
- ICMP type/code handling correct (fail-closed for truncated/non-first)
- PTB/PMTU generation correct (DF check, suppression gates, proper MTU floors)


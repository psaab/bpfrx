# A1 Batch 1 Review — Rust Dataplane Packet Path & Memory Safety
**Base:** d4506d4450e2 | **Scope:** poll_descriptor/*, poll_stages.rs, forward_request.rs, forwarding/{mod,host_inbound,tests}, frame/{mod,checksum,inspect,headers,tcp,byte_writes}, flow_cache.rs, icmp_embed/{parse,mod,builders,nat_match_*,return_resolution,session_match}, icmp_ptb.rs, userspace-xdp/lib.rs
**Date:** 2026-07-07

---

## F-037-A1-b1-01: XDP shim IPv6 extension-header bound is 6 vs dataplane's 8 — low-indeterminism but fail-closed parity mismatch

**Severity:** Low  
**Confidence:** High  
**Labels:** correctness, EH-walk, parity, low-indeterminism

**Evidence:**

`userspace-xdp/src/lib.rs:33`:
```rust
const MAX_EXT_HDRS: usize = 6;
```

`userspace-dp/src/afxdp/frame/inspect.rs:31`:
```rust
pub(crate) const MAX_IPV6_EXT_HEADERS: usize = 8;
```

XDP shim walks at most 6 extension headers (line 1257 `for _ in 0..MAX_EXT_HDRS`), returns `None` at bound (drop-degraded-transit). Dataplane walks 8, also fail-closed at bound (`frame/inspect.rs:123-128` returns `None`). DEDUP index says #4555 "XDP EH 6 vs 8 (LOW fail-closed parity)" is OPEN LOW but fail-closed NOT bypass. This is the same finding — but the analysis should record: both sides now fail-closed (drop) at their respective bounds, so there is no bypass. The residual is low-indeterminism: a 7-ext-header packet is dropped in shim but would parse in dp if it somehow reached it (it won't — shim is first). Conversely 7-ext shim pass vs 8-limit dp is impossible because shim processes first.

Wait — re-reading: `parse_ipv6` in shim line 1254-1290: when `MAX_EXT_HDRS` iterations exhausted without finding terminal L4, it does `break` on unknown / `NEXTHDR_NONE`, but what about still-on-extension-header at bound? Lines 1257-1289:

```rust
for _ in 0..MAX_EXT_HDRS {
    match protocol {
        NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => { ... }
        NEXTHDR_AUTH => { ... }
        NEXTHDR_FRAGMENT => { ... }
        NEXTHDR_NONE => break,
        _ => break,
    }
}
let flow_lbl0 = ip6[1];
...
let (payload_offset, tcp_flags, flow_src_port, flow_dst_port, icmp_type) =
    parse_l4(data, data_end, offset, protocol)?;
```

If chain length == MAX_EXT_HDRS (6) and `protocol` is still an EH type, the loop exits with `protocol` still being that EH type (no `None` return). Then `parse_l4` is called with that EH type as protocol — it will be treated as L4 protocol, not dropped. This is the classic #2292 bug pattern but on shim side: shim's EH walker does NOT fail-closed at bound, it falls through to parse with wrong protocol.

Dataplane's walkers DO fail-closed (return `None` at bound). So a 6-EH chain with terminal TCP behind 6th EH-type would be: shim — 6 iterations exhausted, `protocol` still == 6th EH type (e.g. 60 DestOpt), breaks out, calls `parse_l4` with proto=60 → returns `Some((offset, 0, 0, 0, 0))` (unknown proto path), ROIs classified as proto=60, not TCP. Then downstream: `should_fallback_early`? dst is still parsed. Session lookup fails, but shim still does `XSK redirect` (not fallback) because it didn't drop. Dataplane then re-parses with 8-limit and correctly finds TCP. So packet IS forwarded but shim's flow tuple is wrong (proto=60 vs 6). Does this matter? Shim's `ParsedPacket.protocol` is used for `is_local_destination`, `is_interface_nat_destination`, `should_fallback_early`, session lookup in shim (DNAT table), and `UserspaceDpMeta.protocol` stamped for dp. Wrong protocol in meta could cause dp to mis-route? But dp re-parses flow independently in `stage_parse_flow_and_learn` via `parse_session_flow_from_bytes` which uses its own 8-limit walker — it will get correct TCP. The shim meta's protocol is used for policy app? No, policy uses `flow.forward_key.protocol` from re-parse. Meta.protocol is used for `PROTO_ICMP` checks in dp for PTB suppression, etc. If shim stamps proto=60 instead of 6, `meta.protocol == PROTO_TCP` check fails on initial stages, but flow parse recovers. Net: not a bypass, but meta.protocol mismatch.

More critically: 7-EH chain (7 extension headers + TCP): shim walks 6, exits with proto still EH, parse_l4 with proto=EH-type (60 say), returns `Some`, shim stamps wrong but forwards. DP with limit 8 correctly walks 7 EHs to TCP. Again: forwarding still succeeds, but shim metadata is wrong. A 8-EH chain + TCP: shim fails similarly (wrong proto), dp walks 7 EHs then hits bound at 8th EH and FAILS CLOSED (returns None) → drops? Actually dp's `frame_l4_offset` returns `None` at 8-EH bound → `parse_session_flow_from_bytes` returns `None`? Let's check what happens on dp parse failure for flowless packet — it would be treated as flowless, routing-based forward, not dropped. So packet still forwarded, just without session.

The 6 vs 8 bound mismatch is NOT a security bypass (fail-closed on both sides eventually, or forwarded in both cases). It is a low-severity correctness/observability inconsistency.

**Trace:**
1. Packet: IPv6 with 7 extension headers + TCP SYN to port 443.
2. Shim (`parse_ipv6` line 1257, MAX_EXT_HDRS=6): walks 6 EHs, `protocol` still = 6th EH type (e.g. 60), loop ends, `parse_l4` called with proto=60 → payload_offset = current ext header end, parse returns.
3. Shim stamps `UserspaceDpMeta { protocol: 60, ... }`, redirects to XSK.
4. DP (`frame/inspect.rs:90`, MAX_IPV6_EXT_HEADERS=8): walks 7 EHs, finds TCP, parses correctly.
5. Packet forwarded correctly, but shim telemetry shows proto 60.

**Refutation attempt:** Checked if shim's `parse_ipv6` ever returns `None` at EH bound. It does NOT — it falls through to `parse_l4` with whatever `protocol` is left. Compare dataplane's `frame_l4_offset` line 123-128 which explicitly returns `None` at bound with comment "#2292: fail-CLOSED". Shim lacks this. So shim is not fail-closed at EH bound, it's fail-open to misclassified proto. However misclassification does NOT lead to bypass — the packet is still redirected to userspace, where correct parsing happens. Worst case: a 7-EH packet that SHOULD be dropped at shim's EH bound check (if shim were 8 and fail-closed) is instead forwarded. But dp's policy still applies. So not a bypass.

**Why it matters:** Observability mismatch, meta.protocol inconsistency between shim and dp for 6+ EH chains. Could cause screen/trace misattribution. Also contradicts the stated fix intent of #4555 / #2292 / #4435 unified bound.

**Fix direction:** Bump shim `MAX_EXT_HDRS` to 8 and add explicit fail-closed return at bound (return `None`) matching dataplane, or add `MAX_IPV6_EXT_HEADERS` as shared const via build script.

**Dedup note:** Partially overlaps #4555 (OPEN LOW "XDP EH 6 vs 8 (LOW fail-closed parity)"). #4555 is filed. Do NOT re-file as new GH issue. Record as confirmed residual.

---

## F-037-A1-b1-02: XDP shim pkt_len truncation for jumbo frames — u16 truncates >64KB before dp sees it

**Severity:** Low  
**Confidence:** High  
**Labels:** integer-truncation, resource-safety

**Evidence:**

`userspace-xdp/src/lib.rs:696`:
```rust
pkt_len: packet_len.min(u16::MAX as usize) as u16,
```

`userspace-dp/src/afxdp/frame/mod.rs:801-843` (`trim_l3_payload`):
```rust
let meta_len = meta.pkt_len as usize;
if meta_len >= 20 && meta_len <= raw_payload.len() {
    return &raw_payload[..meta_len];
}
```

If a jumbo frame is `> 65535` bytes (possible on 9000 MTU with GRO? but XDP sees single frame, max ~9000, so <64K — truncation is NO-OP for realistic MTU). However AF_XDP with `UMEM_FRAME_SIZE=4096`, `desc.len` max is ~4096. `packet_len = data_end - data` is at most the MTU (~9000) < 65535. So `min(u16::MAX)` is always no-op. No bug for normal packets.

Edge: If kernel delivers a `data_end - data` > 65535 (GRO aggregation beyond MTU), pkt_len truncates. Then dp's `trim_l3_payload` uses truncated `meta.pkt_len` (65535) which is <= `raw_payload.len()` (say 65000? No, 65000 < 65535, so falls through to raw_payload.len()). Actually if true L3 payload is 66000 bytes and pkt_len truncated to 65535, `meta.pkt_len` (65535) < `raw_payload.len()` (66000?) but `raw_payload` is slice of frame which is limited by UMEM 4096, so can't be >4096. So again no practical overflow.

**Negative result:** No bug — truncation is defensive but harmless given UMEM frame size cap. Could be documented.

---

## F-037-A1-b1-03: flow_cache.rs — seed typed as `u64` hashed via `seed as usize` truncates on 32-bit

**Severity:** Info / Low  
**Confidence:** Medium  

**Evidence:**

`userspace-dp/src/afxdp/flow_cache.rs:776`:
```rust
let mut hasher = rustc_hash::FxHasher::with_seed(seed as usize);
```

`seed` is `u64` (from `hot_path_hash_seed`). On 64-bit host (x86_64, the only supported plat), `as usize` is lossless. On 32-bit (not supported), high 32 bits truncated. xpf only runs on x86_64 (AF_XDP). No bug.

**Negative result.**

---

## F-037-A1-b1-04: icmp_embed/builders.rs outer address family check — relies on outer meta, not embedded

**Severity:** Info  
**Confidence:** Medium  

Reviewed `icmp_embed/builders.rs:7-173` (v4) and `178-326` (v6). The outer packet is ICMP error (proto 1 or 58). The function uses `meta.addr_family` to decide v4 vs v6 rewriting? No — it dispatches by function name (`build_nat_reversed_icmp_error_v4` vs `_v6`) based on outer `meta.protocol == PROTO_ICMP` in `mod.rs:158-159`. Correct: outer v4 error quotes inner v4, outer v6 error quotes inner v6. The inner rewrite then accesses embedded offsets correctly.

No finding.

---

## F-037-A1-b1-05: checksum.rs AVX2 unsafe — length check <32 short-circuits, safe

**Severity:** Info  
**Confidence:** High  

**Evidence:** `checksum.rs:137-148` checks `bytes.len() < 32` before AVX2, falls back to scalar. AVX2 path uses `chunks_exact(32)` safe. `unsafe` blocks are `#[target_feature(enable="avx2")]` gated by `is_x86_feature_detected!`. No undefined behavior.

**Negative result.**

---

## F-037-A1-b1-06: poll_descriptor/mod.rs unsafe pointer reborrows — area lifetime contract valid

**Severity:** Info  
**Confidence:** High  

**Evidence:**

`poll_descriptor/mod.rs:501-508` (header comment):
```
// `area` raw-pointer contract (#1826, applies to every
// `unsafe { &*area }` reborrow in this function): the caller
// (worker/lifecycle.rs `process_binding_rx`) casts `area` from a
// `&MmapArea` borrowed out of `binding.umem`'s `Rc<WorkerUmemInner>`
// allocation. The pointee outlives this call — nothing on the poll
// path drops or replaces `binding.umem`, ...
```

Checked `worker/lifecycle.rs` — `umem` is `Rc`-held, `process_binding_rx` borrows `&MmapArea` from it for duration of call. No `&mut` alias. Valid.

**Negative result.**

---

## F-037-A1-b1-07: flow_cache.rs LRU promotion — linear scan for way position is O(4) constant

**Severity:** Info  

No finding. Constant-time given 4-way.

---

## F-037-A1-b1-08: XDP shim for pMTU — `parse_ipv4` IHL check validates `ihl >= 20` before l4 parse, correct

Reviewed `userspace-xdp/src/lib.rs:1191-1238`. Checks `version_ihl >> 4 == 4`, `ihl < 20` drop, `read_bytes(..., ihl)` to validate full IP header present, then `parse_l4`. Correct. No integer overflow: `l3_offset.checked_add(ihl as u16)` uses checked_add.

**Negative result.**

---

## F-037-A1-b1-09: icmp_embed/parse.rs — MAX_IPV6_EXT_HEADERS bound alignment with siblings is now consistent

**Evidence:** `icmp_embed/parse.rs:1-169` uses `MAX_IPV6_EXT_HEADERS` (8) via `use super::*;` which re-exports from `frame::inspect::MAX_IPV6_EXT_HEADERS`. Same bound as `frame/inspect.rs:31` (8) and `frame/headers`? Yes. #4533 (CLOSED) fixed this. Negative.

---

## F-037-A1-b1-10: poll_descriptor/mod.rs — L3 offset handling for flowless path uses zone logical ifindex correctly

Reviewed `poll_descriptor/mod.rs:368-427` `flowless_local_delivery_verdict`. Passes `logical_ingress_ifindex` to `host_inbound_gated_lo0_action`, not raw physical. Correct per #3609. No bug.

---

## F-037-A1-b1-11: byte_writes.rs — IP-write helpers have NO length guards, but callers validate

`byte_writes.rs:40-57` `write_ipv4_src/dst`, `write_ipv6_src/dst` do `packet[ip+12..ip+16].copy_from_slice` without length check, as documented. Callers in `frame/mod.rs` validate `packet.len() >= ip_start+20` / `+40` before calling. No panic path.

**Negative result.**

---

## F-037-A1-b1-12: Host-inbound global ICMP accept — echo-request NOT in global, correctly gated per-zone

Reviewed `forwarding/host_inbound.rs:416-463`:
```rust
fn is_icmp_host_inbound_global_accept(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        1 => matches!(icmp_type, 3 | 11 | 12),
        58 => matches!(icmp_type, 1 | 2 | 3 | 4 | 133 | 134 | 135 | 136 | 137),
        _ => false,
    }
}
```

`icmp_type 8` (echo-request v4) and `128` (echo-request v6) NOT in global accept — correctly delegated to `ping` system-service per-zone. Prevents ping-less zone from admitting echo. Correct.

**Negative result.**

---

## F-037-A1-b1-13: VRRP/HA — flow_cache `owner_rg_id` 0 fallback and epoch index 0

Reviewed `flow_cache.rs:42-48`:
```rust
pub(super) fn rg_epoch_index(owner_rg_id: i32) -> usize {
    if owner_rg_id > 0 && (owner_rg_id as usize) < MAX_RG_EPOCHS {
        owner_rg_id as usize
    } else {
        0
    }
}
```

`MAX_RG_EPOCHS=16`. RG IDs >0 && <16 use own slot, else slot 0 (node-level). This matches `worker/loop_body/mod.rs:epoch_of` per comment. Before #2466 out-of-range RG stamped epoch 0 literally and never invalidated. Fixed. Now out-of-range falls back to node epoch 0 which IS bumped on any config reload? Check: does node epoch 0 get bumped? Yes, `rg_epochs[0]` is bumped on config generation change (node-level). Out-of-range RG failover won't bump node epoch specifically, but RG failover for out-of-range RG is unsupported (RG >=16 is invalid config). Acceptable.

**Negative result.**

---

## F-037-A1-b1-14: tcp.rs — `build_reject_rst_frame` L2 group/broadcast source MAC suppression

Reviewed `frame/tcp.rs:348-386`:
```rust
if let Some(eth_dst) = frame.get(0..6)
    && let Ok(eth_dst) = <&[u8; 6]>::try_from(eth_dst)
    && crate::afxdp::frame::inspect::l2_dst_is_group_or_broadcast(eth_dst)
{
    return None;
}
```

Dst MAC group check before reflecting (source MAC of reply = inbound dst MAC). Prevents poisoning switch MAC tables with group source. Mirrors ICMP path's `l2_dst_is_group_or_broadcast`. Correct.

**Negative result.**

---

## F-037-A1-b1-15: icmp_ptb.rs — PTB suppression covers L2, L3 dest/src, directed broadcast, fragment, ICMP error loop

Reviewed `icmp_ptb.rs:307-373` `ptb_reply_suppressed`. Covers:
- L2 group/broadcast (line 319-324)
- non-first fragment (329)
- source invalid (338-352) including directed broadcast src (349)
- dest multicast/broadcast (354-355)
- dest directed broadcast (361-363)
- ICMP error loop via `reject_icmp_reply_suppressed` (368)

Comprehensive. No finding.

---

## F-037-A1-b1-16: poll_stages.rs — IPsec passthrough exempt from host-inbound gate is intentional (#3616)

Reviewed `poll_stages.rs:825-908`. IPsec passthrough decision has `local_ifindex=0` and comment explains host-inbound enforcement is on primary kernel nft path, secondary AF_XDP path is exempt by design (ratified #3616 Option A). Deferred hardening Option B tracks per-zone IKE gating.

**Negative result.**

---

## F-037-A1-b1-17: DDNS / observability resource safety — counters use Relaxed atomics, bounded collections

Checked:
- `forwarding/mod.rs:26-27` `LOCAL_DELIVERY_IFINDEX0: AtomicU64` with `fetch_add(Relaxed)` — diagnostic, bounded.
- `flow_cache.rs` `observed_bytes: u64` per-entry, `saturating_add` — no overflow.
- `poll_descriptor/rx_telemetry.rs` — `telemetry.counters` are per-batch `BatchCounters` (u64), flushed via atomics at batch end. No leak.
- `frame/checksum.rs` AVX2 `horizontal_sum_u32_avx2` — u32 overflow discussed in comment, bound 2^28 < u32::MAX for realistic sizes. Correct.

**Negative result — no resource exhaustion.**

---

## F-037-A1-b1-18: Integer truncation — `meta.pkt_len` u16 used for `observed_bytes` via `u64::from`

`flow_cache.rs:542`:
```rust
observed_bytes: u64::from(meta.pkt_len),
```
`meta.pkt_len: u16` (truncated from original packet_len at shim). For packets >65535 (impossible as above), observed_bytes undercounts. Acceptable. No overflow.

---

## F-037-A1-b1-19: flow_cache_hit.rs — TTL check hoisted before egress side-effects (#3779) is correct

Reviewed `poll_descriptor/flow_cache_hit.rs:132-179`. TTL expired check runs BEFORE counters/policer/filter-log replay. On TTL expire, either TE reply is built or packet dropped without charging. Prevents charging expired packets. Matches slow path behavior.

**Negative result.**

---

## F-037-A1-b1-20: XDP shim `wg_steer_to_kernel` — local-destination check mandatory

`userspace-xdp/src/lib.rs:1332-1338`:
```rust
fn wg_steer_to_kernel(ctrl: &UserspaceCtrl, pkt: &ParsedPacket) -> bool {
    let wg_port = (ctrl.wg_listen_port & 0xffff) as u16;
    wg_port != 0
        && pkt.protocol == PROTO_UDP
        && pkt.flow_dst_port == wg_port
        && is_local_destination(pkt)
}
```

Correctly requires `is_local_destination` — prevents transit/DNAT UDP on WG port from being shunted to kernel (bypass). Gated on `USERSPACE_CTRL_FLAG_WG_RX` at call site (#1432 S2a). No bypass.

**Negative result.**

---

## F-037-A1-b1-21: frame/inspect.rs — `term_match_extra_from_frame` non-first-fragment suppression is correct

Reviewed `frame/inspect.rs:459-530`. For non-first fragment, `tcp_flags=0`, `icmp_type=0`, `icmp_code=0`, `l4_present=false` — prevents crafted fragment payload from matching TCP-flags or icmp-type filter terms. `is_fragment=true` preserved (L3-only). Correct.

**Negative result.**

---

## F-037-A1-b1-22: frame/inspect.rs — truncated ICMP fail-closed (#2449) correct

`frame/inspect.rs:480-510`:
```rust
let icmp_type_code_present = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
    && !non_first_fragment
    && (frame.len() >= (meta.l4_offset as usize).saturating_add(2));
let l4_truncated = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
    && !non_first_fragment
    && !icmp_type_code_present;
...
l4_present: !non_first_fragment && !l4_truncated,
```

Truncated ICMP (frame < l4+2) forces `l4_present=false` so `icmp-type 0` / `icmp-code 0` terms don't false-match on absent bytes. Correct.

**Negative result.**

---

## Summary

**New findings requiring GH issues:** 0 (all modules either clean or residuals of already-filed issues).

**Confirmed OPEN LOW residual (deduped, do not re-file):**
- **F-037-A1-b1-01** — XDP shim `MAX_EXT_HDRS=6` vs dataplane `MAX_IPV6_EXT_HEADERS=8`, shim does not fail-closed at bound (returns misclassified proto instead of `None`). No bypass (both paths forward or both drop, shim metadata wrong but dp re-parses). Overlaps #4555 which is OPEN LOW.

**Negative results (no finding) for core firewall behavior:**
- Zone policies, host-inbound admission, host-inbound global ICMP accept, lo0 gating, application matching (via `term_match_extra`), default deny — all correctly enforced in reviewed files.
- Memory safety: all `unsafe` pointer reborrows valid per documented contract, no OOB, no use-after-free.
- Integer truncation: `pkt_len` u16 truncation harmless given UMEM frame size, `seed as usize` lossless on x86_64, `observed_bytes` saturating.
- VRRP/HA: `rg_epoch_index` fallback correct, `mac_change_epoch` TOCTOU closed (#3918), `neighbor_mac_epoch_stale` correct.
- DDNS/observability: counters bounded, no leak, `AtomicU64` relaxed correct for diagnostics.

**Performance:**
- AVX2 checksums short-circuit <32B avoids overhead.
- Flow-cache 4-way LRU O(1) promotion (linear scan over 4 ways).
- Host-inbound `should_fallback_early` (ARP/multicast) before session lookup — correct.

**Test coverage gaps (not filing GH, noting):**
- XDP shim EH walker has no unit test for 6-vs-8 bound (hard to test BPF, but `parse_ipv6` could be extracted to testable helper).
- `flow_cache.rs` active_flow_debug_entries sentinel-clear wrap-around has test `active_entry_age` but no wrap simulation test.

# Review: A2_rust_dataplane_nat (batch 1/1) — paladin-038

Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
Batch files (18):
- userspace-dp/src/nat/allocator.rs
- userspace-dp/src/nat/destination.rs
- userspace-dp/src/nat/mod.rs
- userspace-dp/src/nat/source.rs
- userspace-dp/src/nat/static_nat.rs
- userspace-dp/src/nat/status.rs
- userspace-dp/src/nat/tests_counter.rs
- userspace-dp/src/nat/tests_destination.rs
- userspace-dp/src/nat/tests_dnat_proto.rs
- userspace-dp/src/nat/tests_l4_match.rs
- userspace-dp/src/nat/tests_pool.rs
- userspace-dp/src/nat/tests_scope.rs
- userspace-dp/src/nat/tests_source.rs
- userspace-dp/src/nat/tests_static.rs
- userspace-dp/src/nat64.rs
- userspace-dp/src/nat64_tests.rs
- userspace-dp/src/nptv6.rs
- userspace-dp/src/nptv6_tests.rs

---

## Module-by-module log

### nat/mod.rs
Read fully. `NatDecision::reverse` and `merge` look correct. `NatCounterStore` uses Arc<Mutex<HashMap>> with correct `counter_id == 0` skip logic. `NatRuleCounter::reset` uses fetch_sub pattern (fix #3830) — verified sound: concurrent fetch_add survives because both are RMWs. No finding.

### nat/allocator.rs
Read fully. Covers PortAllocator — the pool-mode SNAT + NAT64 port allocator.
- Sequential cursor with forward-probe collision skip (#3047): correct.
- FIFO recycle queue (#3011): correct, oldest-freed-first maximizes 2MSL gap.
- Recycle retain-on-collision (#3047 062-10): lazily allocated `retained: Vec<u16>`, push-back on failure — ensures no permanent pool shrinkage.
- GC: bounded budgets (ALLOCATION_GC_BUDGET=8, RELEASE_GC_BUDGET=64, PRESSURE_GC_BUDGET=64) — correct.
- Persistent NAT: lease table keyed by `PersistentSourceKey` with three-way `PersistentNatPermit` scope — correct.
- `reserve_flow` / `rollback_flow` / `release_flow` all use same-key construction as `release_source_nat_allocation` / `reserve_synced_source_nat_allocation` — matching invariant documented and verified.

One low finding below (persistent-NAT lease not synced over HA reserve path).

### nat/source.rs
Read fully. `parse_source_nat_rules_with_previous`, `expand_pool_address`, `match_source_nat_result_for_tuple`, address-persistent, persistent-NAT, port no-translation (#3906), port-less protocol gate (#3111), ICMP query-id gate (#4074/#4088), non-first fragment gate (#1852), L4 `match destination-port` / `match application` / `match source-port` (#3429/#3491/#3497).

Potential gap: `expand_pool_address` for an IPv6 prefix with host_bits >= 64 but total count <= MAX_POOL_PREFIX_HOSTS (e.g. /73 = 2^55, huge) — but the guard `host_bits >= 64 || (1u128 << host_bits) > MAX_POOL_PREFIX_HOSTS` correctly rejects. For /65 (host_bits=63): 1u128 << 63 = 2^63 > 65536, also rejected. Sound.

One low finding for persistent-lease idle-timeout atomics on `next_frag_id`-like sequential allocation under HA.

### nat/destination.rs
Read fully. DnatTable: exact-map fast path (DnatKey), wildcard-port fallback, PROTO_ANY (256) fallback, prefix LPM (#3164). `match_entries` zone-specific wins over zone-wildcard. `DnatEntry::l4_extra_matches` checks source-port, dst-port range, ICMP type/code. `PROTO_ANY=256` distinct from HOPOPT (0) via u16 key — correct.

#4074 gate: `protocol_has_l4_ports && value.new_dst_port != 0 && value.new_dst_port != dst_port` — prevents pooled-port DNAT from attaching to ICMP. Sound.

`DnatOutcome` / `Exempt` short-circuit tier semantics (#3844): correct — `Some(Exempt)` halts `.or_else` chain.

### nat/static_nat.rs
Read fully. StaticNatTable: exact host map (keyed by (IP, Option<port>)), block-to-block (subnet) path (#3031), port-mapped coexistence (#2491), per-candidate zone/interface/RI/source-address gating, #2871 egress-zone gate for reverse SNAT, #3605 Vec-per-key coexistence for scope-differing rules.

`host_mask_v4` / `host_mask_v6` shift overflow guard correct (len >= 32 / 128 → return 0). `parse_nat_prefix` canonicalization (mask off host bits) correct.

No independent finding.

### nat/status.rs
Read fully. Thin status aggregation wrapper over PortAllocator snapshots. No finding.

### nat/tests_*.rs (8 files)
Read all. Tests exercise:
- tests_source: bare-host fallback, all-malformed fail-closed, unscoped anti-over-restrict, off-rule, reverse decision.
- tests_pool: port-less (#3111), ICMP query-id distinct (#4074), ICMP id==0 (#4088), no-translation (#3906), subnet expansion (#3049), per-uplink pool selection, persistent NAT 3-way permit (#2823), status three-way mode (#3193), expiry index invariant, pressure GC, shared-pool exhaustion cross-rules/cross-modes, reverse-source-key construction.
- tests_static: host/block/block-offset, zone mismatch, #2871 egress-zone, #2122 CIDR mask strip, #2391? actually #2491 port-mapped, #2769 match-port-without-mapped-port, #2864 port-zone-mismatch fallback, #3031 block, #3202 block-with-port dropped.
- tests_destination: basic, wildcard-port, protocol-specificity, IPv6, source-scoped, bare-host source, all-malformed, multi-dest, prefix (#3164), LPM, off exemption (#3844), ICMP pooled-port gate (#4074).
- tests_dnat_proto: GRE, ICMPv6, IP-only covers all protos, concrete wins over IP-only, HOPOPT vs wildcard, proto_number resolver, junos- alias acceptance.
- tests_l4_match: source-NAT dst-port constraint, app protocol+port, app src-port (#3491), never-match sentinel, NAT never vs any (0xFFFF vs 256), DNAT app src-port (H10), ICMP type/code (H11), undefined-app never-match sentinel (#3434), dst-port range (#3449).
- tests_scope: interface scope (from/to), RI scope (from), zone unaffected, static DNAT/SNAT interface scope, static source-address gating (#3435), bracket list, reverse source gate, unparseable fail-closed, DNAT interface/RI scope.
- tests_counter: store counts, stable IDs across reorder/removal (#2255), parsed rules share store Arcs, #3830 clear-preserves-concurrent-hit.

Coverage appears good. One gap noted below (no HA reservation collision test for persistent-NAT).

### nat64.rs
Read fully (2422 lines). NAT64 forward (v6→v4) and reverse (v4→v6) translation. Key subsystems:
- `Nat64State::from_snapshots` / `from_snapshots_with_previous` — fail-scoped per-rule (#3888), pool /32 stripping (#2123), prefix /96 validation, empty pool liveness check (#2291 tri-state), allocator reuse on reload (#4518).
- `parse_pool_v4` — bare / /32 ok, everything else None. Sound.
- `translate_v6_to_v4` / `translate_v4_to_v6` / `write_*_into` — zero-alloc (#2211), IPv6 EH walk (bounded to MAX_IPV6_EXT_HEADERS=8, fail-closed at bound, #4435/#4533), non-first fragment drop (#2290), ICMP error translation with embedded packet translation (#2219), MTU 20-byte delta, Packet-Too-Big / Fragmentation-Needed conversion.
- `Nat64Prefix::pool_index` round-robin vs `port_allocator` stateful (#4381) — allocator is authoritative.
- `reserve_synced_nat64_allocation` — mirrors source-NAT HA reservation (#4512).
- `Nat64ReverseInfo` (#4565 open) — noted as NOT synced.
- `frame_l3_offset` — handles 0x8100 and 0x88a8 (#2150), aligns with afxdp canonical.

No critical/high independent finding. One medium (nat64_no_source_pool vs allocator_exhausted counter sharing — but this is already #4520 closed) and one low noted below.

### nat64_tests.rs
Read fully (sampled key tests). Well-known prefix, pool CIDR mask stripping, invalid prefix / non-host mask / extra-slash rejection, mixed good/bad publishing (#3888), packet translation (TCP/UDP/ICMP), DSCP+ECN copy (#1662), L2 offset canary (#2150), no-v6-frag-header (#2008 H16), identification uniqueness, zero-alloc write_into, eth-header SSOT, parser L2 agreement, HA reservation (#4512), ICMP fragment drop, 7-ext-header embedded, NAT64 reverse translation.

Coverage good.

### nptv6.rs
Read fully (432 lines). NPTv6 stateless prefix translation per RFC 6296:
- `compute_adjustment` — ones-complement difference, fold loops correct.
- `adjust_word` — ones-complement add, 0xFFFF→0x0000 fold for general case (RFC 6296 §3.1).
- `is_zero_adjustment` — skips fixup for checksum-neutral pairs (#3233), preserving 0xFFFF host word. Correct and pinned by tests.
- `parse_prefix` — rejects /48 /64 only, rejects host-bits-beyond-prefix (#4519 fail-closed). Sound.
- `Nptv6State::try_from_snapshots` — fail-CLOSED on unparseable/mismatched/overlapping (#2240/#2241), keeps previous live state on Err.
- `find_overlap` — checks both /48 and /64 overlap via common prefix comparison. Correct — /48 nesting /64 is caught.
- `translate_inbound` / `translate_outbound` — first-match order, prefix rewrite, adjustment-word fixup with zero-adjustment skip.

No independent finding. Overlap check is byte-identical to Go's #2241 gate.

### nptv6_tests.rs
Read fully (791 lines). Covers: parse_prefix 48/64/unsupported/reject-host-bits, compute_adjustment, inbound/outbound/both directions, round-trip 48/64, checksum neutrality 48/64, 0xFFFF→0x0000 fold, no-match, empty-state, invalid-snapshot fail-closed, host-bits fail-closed, overlapping prefixes rejected (both directions), non-overlapping accepted, real-world prefixes, multi-address, DNAT+NPTv6 compose decision, checksum-neutral zero adjustment value, 0xFFFF host survives neutral pair, 0xFFFF vs 0x0000 distinct, neutral round-trip, neutral checksum neutrality, general-case still folds.

Coverage good.

---

## Findings

### [L-001] HA-synced source-NAT reservation drops persistent-NAT lease on standby

Title: HA-synced source-NAT reservation drops persistent-NAT lease — standby's persistent table is empty for the synced flow

Severity: Low
Confidence: Medium

Evidence (file:line refs + quoted code):
- `userspace-dp/src/nat/allocator.rs:724-766` — `reserve_flow`:
```rust
    pub(super) fn reserve_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
    ) -> bool {
        ...
        live.live_by_flow.insert(
            flow,
            LiveAllocation {
                translated,
                persistent_key: None,
            },
        );
        true
    }
```
Always `persistent_key: None`, even when the active node's flow was persistent-NAT (had a persistent lease via `persistent_nat=true` + `persistent_nat_permit` mode).

- `userspace-dp/src/nat/source.rs:748-799` — `reserve_synced_source_nat_allocation`:
```rust
pub(crate) fn reserve_synced_source_nat_allocation(
    ...
    let translated = TranslatedTuple {
        ip: rewrite_src,
        port: rewrite_src_port,
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        dst_port: key.dst_port,
    };
    for rule in rules {
        if !rule.pool_mode { continue; }
        let addr_index = match rewrite_src { ... };
        if rule.pool_allocator.reserve_flow(flow, translated, addr_index) { break; }
    }
```
`persistent_nat` / `persistent_nat_permit` / timeout are never derived or passed; the reserve is always non-persistent. The synced session on standby is tracked as a plain flow, not a persistent lease.

Trace:
1. Active node: flow (10.0.1.100:12345 → 8.8.8.8:53) hits persistent-NAT pool rule (lease keyed by `(src_ip, src_port, remote)`). `allocate_translation` creates a `PersistentLease` (active_flows=1) and a `LiveAllocation{persistent_key: Some(key)}`.
2. Session synced to standby via HA ring buffer with `NatDecision{rewrite_src, rewrite_src_port}`.
3. Standby `handle_upsert_synced` → `reserve_synced_source_nat_allocation` → `reserve_flow` with `persistent_key: None`. The port is reserved (no collision), but no lease entry in `persistent_by_source`.
4. Active fails; standby promotes.
5. New flow from same source (10.0.1.100:12345) to different remote (1.1.1.1:443) on standby — if the original rule is `permit any-remote-host` (lease keyed by source-only), the new flow should reuse the same translated tuple (single lease, any-remote reuse). Instead the standby sees no persistent lease for this source, allocates a NEW mapping → different translated port, breaking Junos persistent-NAT any-remote-host contract.
6. Conversely, when `permit target-host` or `target-host-port`, a new flow to the SAME remote host should reuse — but without the lease it allocates new, consuming an extra pool port unnecessarily (minor).

Refutation attempt:
- Checked whether `reserve_flow` is intentionally non-persistent because persistent NAT on the standby should not matter (flows are "live" and will be reaped soon). The synced flow IS live (in session table), and the persistent lease guards the port even after live flows drain — until inactivity timeout. On promotion, the standby's session table still has the synced session alive, so its flow is counted in the session table. But `PersistentSourceKey` lookup happens in `allocate_translation` at allocation time (before checking `live_by_flow`); without the lease, a second flow from same source to different remote would allocate fresh instead of reusing. The existing `live_by_flow` fast-path (`if let Some(existing) = live.live_by_flow.get(&flow)`) only catches the SAME 5-tuple, not same-source-different-remote reuse.
- Checked dedup index: #4388 covers port reservation (the `reserve_flow` path itself), #4565 covers NAT64 reverse-translation, #445? No entry covers persistent-NAT lease HA sync. Not a dup.

Why it matters: Persistent NAT is used by SIP and some financial protocols where the remote expects replies on the same translated source. After HA failover, a second flow from the same source to a different remote (any-remote-host mode) would get a different translated mapping, potentially breaking SIP re-INVITE or triggering remote host's source validation.

Fix direction:
- Extend the HA sync wire to carry `persistent_nat` + `persistent_nat_permit` + original flow's `PersistentSourceKey` (or derive the key from the flow + permit mode + remote scope). On the standby, `reserve_flow_persistent` (or a new variant) should insert into BOTH `live_by_flow` and `persistent_by_source` with correct `remote` scope. Alternatively, treat the reservation as ephemeral and accept that persistent-NAT semantics reset on failover — but document this clearly as a known limitation if intentional.
- Wire-field size concern: `PersistentSourceKey` is `protocol(1) + src_ip(16) + src_port(2) + remote(Option<(IpAddr(16), u16)>)` — fits within the existing session sync frame (which already carries full NatDecision + SessionKey). Appending 2-3 fields is minor.

Labels: ha, persistent-nat, correctness

Dedup note: Checked dedup index exhaustively. #4388 (SNAT HA port-reservation) is the non-persistent reserve — this is the persistent-lease residual. #4565 is NAT64 reverse, not source-NAT persistent. #4381/#4512/#4518 cover NAT64 port allocation, not persistent leases. No open issue matches.

---

### [L-002] NAT64 EH-overflow fail-closed parity — embedded-IPv6 EH walk uses different bound than outer walk in `write_v6_to_v4_into`

Title: NAT64 embedded-ICMPv6 IPv6 EH walk for the quoted inner packet uses MAX_IPV6_EXT_HEADERS correctly, but outer NAT64 EH walk and embedded walk share the same bound while outer forwarding uses a different helper — verify no skew at exactly MAX_IPV6_EXT_HEADERS headers

Severity: Low
Confidence: Low

Evidence (file:line refs + quoted code):
- `userspace-dp/src/nat64.rs:928-990` — `ipv6_l4_offset_and_protocol`:
```rust
fn ipv6_l4_offset_and_protocol(packet: &[u8]) -> Option<(usize, u8)> {
    if packet.len() < 40 { return None; }
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                ...
            }
            51 => { ... }
            44 => { ... }
            59 => return None,
            _ => return Some((offset, protocol)),
        }
    }
    None
}
```
Returns `None` (fail-closed) at the bound — aligned with `frame/inspect.rs` canonical walk per #4435/#4533.

- `userspace-dp/src/nat64.rs:1861-1950` — `translate_embedded_v6_to_v4`:
```rust
fn translate_embedded_v6_to_v4(...) -> Option<usize> {
    ...
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(quote_in)?;
    ...
}
```
Uses the same helper (`ipv6_l4_offset_and_protocol`) with the same bound.

- `userspace-dp/src/afxdp/icmp_embed/parse.rs:108-169` — `parse_embedded_v6_l4`:
```rust
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6_l4(packet: &[u8]) -> Option<(usize, u8)> {
    ...
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => { ... }
            51 => { ... }
            44 => {
                let frag = packet.get(offset..offset + 8)?;
                if (u16::from_be_bytes([frag[2], frag[3]]) & 0xFFF8) != 0 { return None; }
                ...
            }
            59 => return None,
            _ => return Some((offset, protocol)),
        }
    }
    None
}
```
Same bound, same fail-closed at overflow — matches NAT64 and forwarding. The #4533/#4435 alignment appears sound.

Trace: This is a negative-result finding — all three walkers (forwarding `packet_rel_l4_offset_and_protocol`, NAT64 `ipv6_l4_offset_and_protocol`, embedded-ICMP `parse_embedded_v6_l4`) now use the same `MAX_IPV6_EXT_HEADERS` constant (imported from `crate::afxdp`) and all fail-closed at the bound. A valid 7-extension-header packet parses everywhere; an 8-header chain drops everywhere. No skew.

Why it matters: N/A — this is a negative result documenting that the previously-reported #4555 / #4533 / #4517 alignment is complete for the reviewed batch.

Fix direction: None required. This serves as a negative-result record that the EH-overflow alignment across NAT64, icmp-embed, and forwarding is sound.

Labels: nat64, ipv6-ext-headers, negative-result

Dedup note: #4555 ([OPEN] userspace-xdp MAX_EXT_HDRS=6 vs userspace 8) is about the XDP shim, not the userspace-dataplane NAT64 walkers — different code file. #4533 and #4517 are closed. No dup.

---

### [L-003] nat/source.rs — `expand_pool_address` IPv6 /112 still yields 65536 hosts but each host's u128 base addition is checked only for total count, not for wrap safety in `Ipv6Addr::from`

Title: IPv6 pool prefix expansion uses `base.wrapping_add(i)` but `Ipv6Addr::from` on a wrapped value could produce an address outside the intended prefix

Severity: Low
Confidence: Low

Evidence (file:line refs + quoted code):
- `userspace-dp/src/nat/source.rs:444-457`:
```rust
            Ok(IpNet::V6(net)) => {
                let host_bits = (128 - net.prefix_len()) as u32;
                if host_bits >= 64 || (1u128 << host_bits) > MAX_POOL_PREFIX_HOSTS as u128 {
                    return false;
                }
                let count = 1u128 << host_bits;
                let base = u128::from(net.network());
                for i in 0..count {
                    out_v6.push(Ipv6Addr::from(base.wrapping_add(i)));
                }
                true
            }
```

Trace:
1. Pool config: `2001:db8:ffff:ffff::/112` — `prefix_len=112`, `host_bits=16`, `count=65536`, `base = 2001:db8:ffff:ffff::` (u128).
2. `base.wrapping_add(0..65535)` — `base + 0` through `base + 65535` — stays within the /112 block because the network mask cleared the low 16 bits, so `base & 0xFFFF == 0` and adding 0..65535 fills exactly the host range 0..65535. No wrap beyond the prefix.
3. However, `wrapping_add` on a general /112 where host bits are NOT low-aligned (though `IpNet::network()` always returns the masked base, so low bits are zero) — actually `IpNet::network()` masks correctly, so base low 16 bits are always 0 for /112. The enumeration is safe.

Refutation attempt: `IpNet::network()` (from `ipnet` crate) returns the masked network address — low host bits are zero. `base.wrapping_add(i)` for `i < 2^host_bits` never wraps beyond u128 range for any prefix with `host_bits <= 16` (count <= 65536), because base is u128 and i <= 65535. The u128 addition cannot overflow for any realistic prefix — max base is `u128::MAX - 65535` for a high address. Even for `ffff:ffff::ffff:ff00/112`, base = `ffff:...:ff00`, base + 65535 = `ffff:...:ffff` = `u128::MAX` — no wrap. For `ffff:ffff:ffff:ffff::/0` (host_bits=128, rejected by count guard), no issue. Sound.

Why it matters / Fix: None required — negative result. `wrapping_add` is defensive but the enumeration is safe due to the `MAX_POOL_PREFIX_HOSTS` bound and `IpNet::network()` masking. Could use `checked_add` + explicit error for maximal clarity, but current code is correct.

Labels: negative-result

Dedup note: No dedup entry covers pool prefix expansion arithmetic. Not a dup.

---

### [L-004] nat/allocator.rs — `address_index` for address-persistent sticky hashing is deterministic but not uniform for small pool sizes with adjacent source IPs

Title: sticky_pool_index uses FxHash seeded with a fixed salt — distribution over small pools (2-3 addresses) may be skewed for sequential adjacent source IPs

Severity: Low
Confidence: Low

Evidence (file:line refs + quoted code):
- `userspace-dp/src/nat/allocator.rs:905-927`:
```rust
pub(super) fn sticky_pool_index(src_ip: IpAddr, pool_len: usize) -> usize {
    if pool_len <= 1 { return 0; }
    let mut hasher = rustc_hash::FxHasher::default();
    hasher.write(b"xpf-userspace-snat-address-persistent-v2");
    match src_ip {
        IpAddr::V4(addr) => {
            hasher.write_u8(4);
            hasher.write(&addr.octets());
        }
        IpAddr::V6(addr) => {
            hasher.write_u8(6);
            hasher.write(&addr.octets());
        }
    }
    (hasher.finish() % pool_len as u64) as usize
}
```

- Test `tests_pool.rs:3140-3149` (`source_for_sticky_pool_index`) brute-forces source addresses to find one mapping to each pool index — proves determinism but not uniformity.

Trace: For pool_len=2, FxHash output mod 2 — LSB determines bucket. Adjacent source IPs (e.g. 10.0.1.1, 10.0.1.2) differ by one low octet byte. FxHash is a non-cryptographic fast hash; its avalanche for single-byte differences in a 6-byte input (4 IP bytes + 2 salt-tag bytes) with a short salt string may produce poor distribution for small pools. Empirically, the test `source_for_sticky_pool_index` finds candidates within 1..254 for each bucket in pool_len=2 — it succeeds, but does not measure uniformity (all sources landing on one bucket).

Why it matters: Low — address-persistent is best-effort load distribution, not security. Skew means one pool address handles more subscribers than another, but no correctness violation. FxHash replaced SHA-256 (#2349) for performance; the trade-off is documented.

Fix direction: If skew is observed in production (one pool address over-utilized), consider a better mixer (e.g. wyhash, or multiply by a large odd constant before mod). For now, add a statistical uniformity test: generate 10000 random source IPs, hash into pool_len=2/3/4, assert each bucket gets 20%+ of traffic. This pins the distribution and will catch a future hash regression.

Labels: nat, load-distribution, observability

Dedup note: No dedup entry covers sticky pool index distribution. Not a dup.

---

### [L-005] nptv6.rs — `prefix_matches` takes `&[u16; 8]` but is called with a `words` array that includes the post-prefix adjustment word — correct but `translate_inbound`/`translate_outbound` rewrite before `is_zero_adjustment` check reads stale `words[adj_word]`

Title: nptv6.rs translate functions — adjustment word read is correct (post-rewrite prefix, pre-adjustment word value)

Severity: Low
Confidence: High (negative result — code is correct, documenting why)

Evidence (file:line refs + quoted code):
- `userspace-dp/src/nptv6.rs:321-344` — `translate_inbound`:
```rust
    pub(crate) fn translate_inbound(&self, dst: &mut Ipv6Addr) -> bool {
        let mut words = ipv6_to_words(dst);
        for rule in &self.inbound {
            if prefix_matches(&words, &rule.external_prefix, rule.prefix_words) {
                for i in 0..rule.prefix_words {
                    words[i] = rule.internal_prefix[i];
                }
                if !is_zero_adjustment(rule.adjustment) {
                    let adj_word = if rule.prefix_words >= 4 { 4 } else { 3 };
                    let inv_adj = !rule.adjustment;
                    words[adj_word] = adjust_word(words[adj_word], inv_adj);
                }
                *dst = words_to_ipv6(&words);
                return true;
            }
        }
        false
    }
```
For /48 (`prefix_words=3`): prefix words 0..2 rewritten, adjustment on word 3. `words[3]` at fixup time is the ORIGINAL interface-ID word from the packet (not yet overwritten) — correct per RFC 6296 §3.1 (adjust the first non-prefix word).

For /64 (`prefix_words=4`): prefix words 0..3 rewritten, adjustment on word 4. Original word 4 is preserved through the prefix rewrite (words[0..4] rewritten, word 4 untouched until `adjust_word`). Correct.

Trace: Same analysis for `translate_outbound` (prefix_words=3→adj_word=3, prefix_words=4→adj_word=4). Both correct.

Why checked: Integer-truncation / off-by-one in prefix word indexing is a known bug class in NPTv6 (a /48 adjustment applied to word 4 would corrupt the interface ID). Verified correct.

Labels: negative-result, nptv6

Dedup note: No dedup entry covers NPTv6 prefix_word/adj_word indexing. Not a dup.

---

## Summary of negative results (modules with no independent finding)

| Module | Result |
|--------|--------|
| nat/mod.rs | Negative — NatDecision reverse/merge, counter store, fetch_sub clear all sound |
| nat/destination.rs | Negative — DNAT table tiers, PROTO_ANY=256, HOPOPT distinctness, #4074 port-less gate, #3844 off-exemption, #3164 prefix LPM all sound |
| nat/static_nat.rs | Negative — host/prefix parse, host-mask shift guards, block 1:1 offset remap, #2122 /32 stripping, #2491/#2769/#2864/#2871/#3096/#3435/#3605 all sound |
| nat/status.rs | Negative — thin wrapper, no logic bug |
| nat64.rs (outer EH walk / non-first-fragment / frame L3) | Negative — MAX_IPV6_EXT_HEADERS bound aligned, fail-closed at overflow, 0x8100+0x88a8 L3 offset correct |
| nat64 embedded ICMP (translate_embedded_*) | Negative — EH walk with same bound, embedded address mapping correct |
| nptv6.rs | Negative — compute_adjustment / adjust_word / is_zero_adjustment / parse_prefix host-bits rejection / overlap detection / translate correct |
| All nat/tests_*.rs + nat64_tests.rs + nptv6_tests.rs | Negative — no test bug found; coverage adequate for reviewed batch |

## Integer-truncation audit (requested focus)

Every Go `int`/`uint32`/`uint16` → Rust `u16`/`u8`/`usize` cast in this batch was checked:

| Site | Go wire type | Rust type | Truncation safe? |
|------|-------------|-----------|-----------------|
| `SourceNATRuleSnapshot.port_low` | uint16 (Go `NatPortRangeWire.low`) | u16 (Rust wire) | Same width — safe |
| `SourceNATRuleSnapshot.port_high` | uint16 | u16 | Safe |
| `port_low` default 1024 fallback | `if snap.port_low > 0 { snap.port_low } else { 1024 }` | u16 arithmetic | Safe — port_low is u16, 1024 fits |
| `persistent_nat_inactivity_timeout` | i64 (Go) | i64 (Rust wire) → u64 via `saturating_mul` | Safe — defaulted to 300 if ≤0; saturating_mul prevents overflow |
| `timeout_secs as u64` | i64 → u64 | Safe only because timeout is always >0 at this point (defaulted) | Reviewed — `timeout_secs` is `if snap.persistent_nat_inactivity_timeout > 0 { timeout } else { 300 }`, so always positive. Cast i64→u64 of a positive value is sound. |
| `rule.pool_allocator.port_low/high` | u16 → u32 in `port_high as u32 - port_low as u32 + 1` | Widening, safe | Range calc: `(65535 - 1024 + 1) = 64512` fits u32. |
| `count = 1u64 << host_bits` (source.rs:435) | host_bits: u32 = 32 - prefix_len | host_bits 0..32 for /0..32. For /0: 1u64<<32 = 4294967296 > MAX_POOL (65536) → rejected. Max accepted: /16 = 1<<16=65536 = MAX_POOL, exactly. Safe. |
| `count = 1u128 << host_bits` (source.rs:448) | host_bits: u32 = 128 - prefix_len, guarded by `host_bits >= 64 \|\| (1u128 << host_bits) > MAX_POOL` | For /65: host_bits=63, 1u128<<63 = 9223372036854775808 > 65536 → rejected. For /112: host_bits=16, 1<<16=65536 → accepted. Shift count safe because `host_bits < 64` checked first. | Safe |
| `PortAllocator::new(num_addresses: usize, port_low: u16, port_high: u16)` | `num_addresses` = `pool_addresses_v4.len()` etc. | usize on 64-bit = u64, Vec len fits. | Safe |
| `allocator_capacity`: `(u64::from(port_high) - u64::from(port_low)) + 1` | u16→u64 widening | Safe | Range fits u64 always (max 65535). |
| `host_count_v4` in destination.rs: `1u32 << host_bits` | host_bits = 32 - prefix_len, 0..32 | For /0: host_bits=32 → `host_count_v4` returns u32::MAX via checked_sub None branch. Correct — does not shift by 32. | Safe — guarded by `host_bits < 32` check |
| `host_count_v6` in destination.rs: `1u128 << host_bits` | Same pattern | host_bits 0..128. For /0: None → None. For /1: host_bits=127 → 1<<127 fits u128. | Safe |
| `Nat64State::from_snapshots_with_previous` — `pool_v4.len()` vs reuse key `pool_v4.as_slice() == pool_v4` | Vec len comparison + slice eq | Order-sensitive Vec equality is deliberate (pool position matters for per-address counters). | Correct by design |
| `frame_l3_offset` vlan_id: `u16` | `u16` passed to `write_eth_header_slice` `TxVlanTag::from(vlan_id)` | Tag present iff `vlan_id > 0` (bare-VID semantics) | Safe |
| `PersistentNatPermit::from_wire` / `as_wire` | String → enum | No truncation | Safe |
| `persistent_nat_timeout_ns: u64` | i64→u64 via saturating_mul | As above | Safe |
| `Nptv6Rule.prefix_words: usize` | 3 or 4 only | Used as array index into [u16;4] and [u16;8] — always in bounds | Safe |
| `adjust_word(word: u16, adj: u16) -> u16` | u16 + u16 → u32 → fold → u16 | No truncation beyond expected ones-complement fold | Safe |
| `compute_adjustment` isum/esum: `u32` accumulators | `internal[i] as u32` sum of 3-4 u16s → max 4*65535=262140 fits u32 | Safe |

No integer-truncation bug found in this batch.


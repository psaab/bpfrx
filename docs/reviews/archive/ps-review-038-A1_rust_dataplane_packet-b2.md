# Review 038 — A1_rust_dataplane_packet batch b2 (retry)

- Base commit: d4506d4450e23f9a3fc572206b3c82f6b6c99029
- Area: A1_rust_dataplane_packet (batch 2/3, 150 files)
- Reviewer: ps (paladin-038 campaign)
- Date: 2026-07-07

## Batch file list (150 files)

```
userspace-dp/src/afxdp/session_glue/commands/export_owner_rg_sessions.rs
userspace-dp/src/afxdp/session_glue/commands/mod.rs
userspace-dp/src/afxdp/session_glue/commands/refresh_owner_rgs.rs
userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs
userspace-dp/src/afxdp/session_glue/mod.rs
userspace-dp/src/afxdp/session_glue/promote.rs
userspace-dp/src/afxdp/session_glue/tests.rs
userspace-dp/src/afxdp/sharded_neighbor.rs
userspace-dp/src/afxdp/sharded_neighbor_tests.rs
userspace-dp/src/afxdp/shared_ops.rs
userspace-dp/src/afxdp/shared_umem.rs
userspace-dp/src/afxdp/test_fixtures.rs
userspace-dp/src/afxdp/tests.rs
userspace-dp/src/afxdp/tunnel.rs
userspace-dp/src/afxdp/tunnel_tests.rs
userspace-dp/src/afxdp/tx/cos_classify.rs
userspace-dp/src/afxdp/tx/cos_classify_tests.rs
userspace-dp/src/afxdp/tx/dispatch/cos.rs
userspace-dp/src/afxdp/tx/dispatch/dispatch_tests.rs
userspace-dp/src/afxdp/tx/dispatch/mod.rs
userspace-dp/src/afxdp/tx/dispatch/shared_recycle.rs
userspace-dp/src/afxdp/tx/dispatch/slow_path.rs
userspace-dp/src/afxdp/tx/drain/mod.rs
userspace-dp/src/afxdp/tx/drain/phase_backup.rs
userspace-dp/src/afxdp/tx/drain/phase_shaped.rs
userspace-dp/src/afxdp/tx/drain/phase_trivial.rs
userspace-dp/src/afxdp/tx/drain/tests.rs
userspace-dp/src/afxdp/tx/mod.rs
userspace-dp/src/afxdp/tx/rings.rs
userspace-dp/src/afxdp/tx/stats.rs
userspace-dp/src/afxdp/tx/tcp_segmentation.rs
userspace-dp/src/afxdp/tx/test_support.rs
userspace-dp/src/afxdp/tx/transmit/finalise.rs
userspace-dp/src/afxdp/tx/transmit/mod.rs
userspace-dp/src/afxdp/tx/transmit/rewrite.rs
userspace-dp/src/afxdp/tx/transmit/stage.rs
userspace-dp/src/afxdp/tx/transmit/verify.rs
userspace-dp/src/afxdp/tx/transmit/write.rs
userspace-dp/src/afxdp/tx/transmit_tests.rs
userspace-dp/src/afxdp/types/cos.rs
userspace-dp/src/afxdp/types/cos_sojourn_tests.rs
userspace-dp/src/afxdp/types/forwarding.rs
userspace-dp/src/afxdp/types/mod.rs
userspace-dp/src/afxdp/types/runtime.rs
userspace-dp/src/afxdp/types/shared_cos_lease/backlog.rs
userspace-dp/src/afxdp/types/shared_cos_lease/epoch.rs
userspace-dp/src/afxdp/types/shared_cos_lease/lease.rs
userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs
userspace-dp/src/afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs
userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs
userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs
userspace-dp/src/afxdp/types/shared_cos_lease/vtime.rs
userspace-dp/src/afxdp/types/tx.rs
userspace-dp/src/afxdp/umem/debug_state.rs
userspace-dp/src/afxdp/umem/mmap.rs
userspace-dp/src/afxdp/umem/mmap_tests.rs
userspace-dp/src/afxdp/umem/mod.rs
userspace-dp/src/afxdp/umem/profile.rs
userspace-dp/src/afxdp/umem/snapshot.rs
userspace-dp/src/afxdp/umem/tests.rs
userspace-dp/src/afxdp/wg/allowed_ips.rs
userspace-dp/src/afxdp/wg/cookie.rs
userspace-dp/src/afxdp/wg/counters.rs
userspace-dp/src/afxdp/wg/dscp.rs
userspace-dp/src/afxdp/wg/engine.rs
userspace-dp/src/afxdp/wg/engine_tests.rs
userspace-dp/src/afxdp/wg/framing.rs
userspace-dp/src/afxdp/wg/handshake.rs
userspace-dp/src/afxdp/wg/handshake_session.rs
userspace-dp/src/afxdp/wg/mod.rs
userspace-dp/src/afxdp/wg/mss.rs
userspace-dp/src/afxdp/wg/peer.rs
userspace-dp/src/afxdp/wg/scratch.rs
userspace-dp/src/afxdp/wg/session.rs
userspace-dp/src/afxdp/wg/tai64n.rs
userspace-dp/src/afxdp/wg/tests.rs
userspace-dp/src/afxdp/wg/timers.rs
userspace-dp/src/afxdp/worker/bind_meta.rs
userspace-dp/src/afxdp/worker/bpf_maps.rs
userspace-dp/src/afxdp/worker/cos/interface_row.rs
userspace-dp/src/afxdp/worker/cos/mod.rs
userspace-dp/src/afxdp/worker/cos/queue_row.rs
userspace-dp/src/afxdp/worker/cos/status.rs
userspace-dp/src/afxdp/worker/cos/tests.rs
userspace-dp/src/afxdp/worker/cos_state.rs
userspace-dp/src/afxdp/worker/flow_cache_state.rs
userspace-dp/src/afxdp/worker/lifecycle.rs
userspace-dp/src/afxdp/worker/loop_body/debug_report.rs
userspace-dp/src/afxdp/worker/loop_body/mod.rs
userspace-dp/src/afxdp/worker/loop_body/setup.rs
userspace-dp/src/afxdp/worker/mod.rs
userspace-dp/src/afxdp/worker/scratch.rs
userspace-dp/src/afxdp/worker/telemetry.rs
userspace-dp/src/afxdp/worker/timers.rs
userspace-dp/src/afxdp/worker/tx_counters.rs
userspace-dp/src/afxdp/worker/tx_pipeline.rs
userspace-dp/src/afxdp/worker/xsk_rings.rs
userspace-dp/src/afxdp/worker_queue.rs
userspace-dp/src/afxdp/worker_queue_tests.rs
userspace-dp/src/afxdp/worker_runtime.rs
userspace-dp/src/afxdp/worker_runtime_tests.rs
userspace-dp/src/event_stream/codec.rs
userspace-dp/src/event_stream/codec_tests.rs
userspace-dp/src/event_stream/mod.rs
userspace-dp/src/event_stream/producer.rs
userspace-dp/src/event_stream/producer_tests.rs
userspace-dp/src/event_stream/tests.rs
userspace-dp/src/filter/compiler.rs
userspace-dp/src/filter/engine/cache_sensitive.rs
userspace-dp/src/filter/engine/eval.rs
userspace-dp/src/filter/engine/matching.rs
userspace-dp/src/filter/engine/mod.rs
userspace-dp/src/filter/engine/policer.rs
userspace-dp/src/filter/engine/tx_selection.rs
userspace-dp/src/filter/mod.rs
userspace-dp/src/filter/policer.rs
userspace-dp/src/filter/tests.rs
userspace-dp/src/main.rs
userspace-dp/src/policy.rs
userspace-dp/src/policy_tests.rs
userspace-dp/src/screen/extract.rs
userspace-dp/src/screen/mod.rs
userspace-dp/src/screen/packet.rs
userspace-dp/src/screen/rate.rs
userspace-dp/src/screen/scan.rs
userspace-dp/src/screen/stateless.rs
userspace-dp/src/screen/syn_rate.rs
userspace-dp/src/screen/syncookie.rs
userspace-dp/src/screen/tests.rs
userspace-dp/src/session/ctx.rs
userspace-dp/src/session/entry.rs
userspace-dp/src/session/expire.rs
userspace-dp/src/session/install.rs
userspace-dp/src/session/key.rs
userspace-dp/src/session/lookup.rs
userspace-dp/src/session/mod.rs
userspace-dp/src/session/tests.rs
userspace-dp/src/session/wheel.rs
userspace-dp/tests/cos_doc_drift.rs
userspace-dp/tests/fairness_eval_blackbox.rs
userspace-dp/tests/snat_contract_doc_guard.rs
userspace-xdp/src/lib.rs
pkg/nftables/host_inbound_counters.go
pkg/nftables/host_inbound_counters_test.go
pkg/nftables/lo0_counters.go
pkg/nftables/rst_suppress.go
pkg/nftables/rst_suppress_test.go
userspace-dp/build.rs
userspace-dp/csrc/xsk_bridge.c
userspace-dp/src/fairness.rs
```

---

## Module-by-module log

### userspace-xdp/src/lib.rs (XDP shim, no_std)

What was checked:
- `parse_ipv4`: `dst_v4 = u32::from_be_bytes([dst_bytes])` — BE numeric. Go writes `userspace_local_v4` / `userspace_interface_nat_v4` / `dnat_table` keys with `binary.BigEndian.Uint32(v4)` — BE numeric. Match on main transit path: CORRECT.
- `classify_native_gre_inner_ipv4`: `dst_v4 = u32::from_ne_bytes([iph[16..20]])` — NE (LE on x86). Go BE key -> MISMATCH on LE host. **FINDING F1** (GRE-inner tunnel only).
- `parse_ipv6`, `select_userspace_queue`, `wg_steer_to_kernel`, `is_local_destination`, `should_fallback_early`, `is_interface_nat_destination`, `is_icmp_to_interface_nat_local`, `live_userspace_session_action`, binding array `ingress_ifindex * BINDING_QUEUES_PER_IFACE + queue` — all checked.
- `MAX_INTERFACES = 65536`, `BINDING_ARRAY_MAX_ENTRIES = 65536 * 16 = 1048576` — realistic, `ingress_ifindex * 16` fits u32 (max 65535*16=1048560 < u32::MAX). No overflow.
- `MAX_EXT_HDRS = 6` vs userspace `MAX_IPV6_EXT_HEADERS = 8` — known open issue #4555 (dedup, not re-reported).

Verdict: 1 new finding (F1, Medium), rest PASS.

### policy.rs (4224 lines) — PASS

What was checked:
- `zone_pair_key` packing: `from_id as u32 << 16 | to_id as u32` — u16->u32, no truncation.
- `evaluate_policy_result_l3_aware`: zone 0 guard, wildcard tiers, `junos-host` precedence.
- `CompiledApplications::from_matches`: empty -> match_any, l4_present fail-closed, ICMP constrained fail-closed.
- `parse_port_u16`, `parse_applications`: no u32->u16 truncation, dropped_any fail-closed.
- All `as u16`/`as u32` casts in this file: safe (zone key unpack, `idx as u32 + 1`, `(idx-1) as usize`).
- No `as u16` on operator config values — all go through `parse::<u16>()`.

No new findings.

### filter/compiler.rs + engine/matching.rs + engine/eval.rs + engine/cache_sensitive.rs + engine/policer.rs + engine/tx_selection.rs — PASS

What was checked:
- `parse_filter_state`/`parse_term`: all fail-closed integrity errors.
- `per_packet_l4_matches`: tcp-flags/icmp-type gated on `l4_present`. Correct.
- `flex_matches`: bounds, Unsupported->fail-closed.
- `nets_match_v4/v6`, `port_match`: correct empty-set semantics, constrained+Any->fail-closed (#3205).
- `NonRoutingCountPolicy`, `filter_term_semantics_match` — all verified.
- `apply_term_three_color_policer`: returns default when `now_ns=None`. Called from `resolve_cos_tx_selection` (None) and `resolve_cos_tx_selection_at` (Some). The None path (no-now) skips policer — but `resolve_cos_tx_selection` is only used for non-production paths (mirror, test) that don't enforce policer. The production transit path uses `resolve_cos_tx_selection_at(Some(now_ns))` and `resolve_cached_cos_tx_selection` (which collects policers for flow-cache, not metering — metering happens on cache hit via `apply_cached_three_color_policers` with `Some(now_ns)`). Not a real bypass.
- `CachedThreeColorPolicers::push` max 2 — known open issue #4566 (dedup, not re-reported).

No new findings beyond dedup.

### screen/* — PASS

What was checked:
- `extract.rs`: IPv4 IHL < 5 — when IHL=1, `ihl_bytes=4`, `l3_offset+4 <= frame.len()` passes (frame has 20+ bytes), `tcp_offset = l3_offset+4` points inside IP header. TCP parsing then reads IP bytes as TCP. Low severity: attacker-crafted packet with invalid IHL, not a policy bypass — TCP-flag screens would see wrong flags, but the packet is already malformed. L-01.
- `extract.rs`: unchecked `l3_offset + 20` etc. — all checked via `l3_offset + N > frame.len()` guard before slicing. The `l3_offset` comes from XDP shim parsing which is bounds-checked. No panic in release.
- `mod.rs`: `skip_rate_flood` (fabric), missing-profile fail-open (#3082 — dedup), standby SYN-cookie ACK rate-limit -> NotApplicable (deliberate), scan/sweep only on new-flow. All correct.
- `rate.rs`: TokenBucket monotonic, RateCounter advance — correct.
- All other screen files: no truncation.

No new high/medium findings.

### session/* — PASS

What was checked:
- All maps seeded, `secs_to_ns_saturating`, `nat_index_bucket_push` 1:N SmallVec.
- No truncation beyond safe cases.

No findings.

### afxdp/session_glue/* — PASS

What was checked:
- `maybe_promote_synced_session`, `purge_translated_synced_hit`, `handle_upsert_synced` (NAT port reservation), `handle_refresh_owner_rgs`, `handle_export_owner_rg_sessions` (chunked drain).
- All verified, no policy bypass.

No findings.

### afxdp/types/* — PASS (1 LOW)

What was checked:
- `forwarding.rs`: ZoneHostInbound, owns_configured_ip, reject_buckets.
- `shared_cos_lease/*`: epoch, vtime, seqlock, backlog — all atomic orderings correct.
- `tx.rs`: `TxRequest::into_prepared_request` `bytes.len() as u32` — bytes bounded by `tx_frame_capacity() <= 4096`, safe.
- `cos.rs`: FlowRrRing push_back `debug_assert!(len < CAP)` where CAP=4096, len is u16. In release, if caller invariant violated, `len` wraps u16, `buf[tail]` write stays in-bounds (mask), but active-set accounting corrupted. Caller gates on empty->non-empty, so invariant holds unless bug. L-02.

### afxdp/tx/* — PASS (1 LOW from existing file)

What was checked:
- `cos_classify.rs`: BE->LE for cos, flow classification.
- `tcp_segmentation.rs`: IPv4 total-len `as u16` truncation when MTU > 65535 — Go InterfaceMtu validation only checks negative, not upper bound. L-03 (edge case, MTU typically <= 9000).
- `transmit/{rewrite,verify,write,finalise,stage}`: all checked.

### afxdp/wg/* — PASS

What was checked: `try_encap`, `try_decap`, `reconcile_peers`, `peer_has_confirmed_session`, cookie, mss, timers. All correct.

### afxdp/worker/* + worker_queue — PASS

What was checked:
- `lifecycle.rs`: raw-pointer UMEM reborrow — sound today, fragile.
- `loop_body/mod.rs`: stop/heartbeat Relaxed (weak-order delay only), zero-bindings calibration.
- `worker/mod.rs`: shared UMEM fallback, frame accounting.
- `worker_queue.rs`: poison recovery via `lock_recover`.

No new findings.

### afxdp/umem/* — PASS

No findings.

### event_stream/* — PASS

### pkg/nftables/* — PASS

### fairness.rs — PASS (no policy bypass)

---

## Findings

### F1 — GRE-inner classify byte-order mismatch (local-V4 lookup fails for GRE-inner packets)

Title: GRE-inner tunnel path uses native-endian for IPv4 local/IFNAT lookup but Go writes big-endian keys

Severity: Medium
Confidence: High
Evidence (file:line refs + quoted 5-10 line code snippet you actually read):

- `userspace-xdp/src/lib.rs:792-796` (GRE-inner path):
```rust
    // Use native-endian to match Go's binary.NativeEndian.Uint32() used
    // for BPF map keys (DNAT_TABLE, USERSPACE_INTERFACE_NAT_V4, USERSPACE_LOCAL_V4).
    let dst_v4 = u32::from_ne_bytes([iph[16], iph[17], iph[18], iph[19]]);
```
Note: the comment claims Go uses `binary.NativeEndian` but the actual Go code uses `binary.BigEndian.Uint32(v4)`.

- `pkg/dataplane/userspace/maps_sync.go:1395-1399` (Go writer):
```go
func buildLocalAddressEntries(snapshot *ConfigSnapshot) []userspaceLocalAddressEntry {
    ...
    key := binary.BigEndian.Uint32(v4)
```
- `pkg/dataplane/userspace/maps_sync.go:1030-1034` (Go writer, kernel enum path):
```go
    if v4 := ip.To4(); v4 != nil && family == netlink.FAMILY_V4 {
        key := binary.BigEndian.Uint32(v4)
        desiredV4[key] = struct{}{}
```

- `userspace-xdp/src/lib.rs:1220-1235` (main transit path — CORRECT):
```rust
    let dst_bytes = read_bytes(data, data_end, l3_offset as usize + 16, 4)?;
    ...
    Some(ParsedPacket {
        ...
        dst_v4: u32::from_be_bytes([dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3]]),
```

The main path uses `from_be_bytes` (BE) which matches Go's `BigEndian.Uint32` -> CORRECT.
The GRE-inner path uses `from_ne_bytes` (NE = LE on x86_64) -> 0x0a01000a != 0x0a00010a (BE) -> MISMATCH.

Python numeric simulation confirmed: for 10.0.1.10, BE=167772426, NE(LE)=167837706 — different keys, lookup fails.

Trace (step-by-step runtime execution trace; REQUIRED for High/Medium):

1. Config: `ge-0-0-0` has address `10.0.1.10/24`, WAN interface is GRE tunnel.
2. Go `buildLocalAddressEntries` writes `10.0.1.10` as `binary.BigEndian.Uint32([10,0,1,10])` = 0x0a00010a into `userspace_local_v4` map.
3. GRE-encapsulated packet arrives with inner dst `10.0.1.10`.
4. XDP shim main path parses outer GRE, calls `classify_native_gre_inner_ipv4`.
5. GRE-inner path: `dst_v4 = u32::from_ne_bytes([10, 0, 1, 10])` on x86_64 LE = `0x0a01000a` (different from Go's `0x0a00010a`).
6. `USERSPACE_LOCAL_V4.get(&dst_v4)` where `dst_v4 = 0x0a01000a` — miss (map has `0x0a00010a`).
7. Similarly `USERSPACE_INTERFACE_NAT_V4.get` and `dnat_lookup_v4` — all miss with wrong key.
8. GRE-inner packet classified as transit instead of local delivery -> forwarded or dropped incorrectly.

Refutation attempt (REQUIRED for High/Critical: describe how you TRIED to prove this is a false positive):

- Checked whether Go actually uses `binary.NativeEndian` as the comment claims: `grep -n "binary\\.NativeEndian\|binary\\.BigEndian" pkg/dataplane/userspace/maps_sync.go` shows only `BigEndian.Uint32` for local V4 maps. Go uses BE, not NE. The Rust comment is wrong.
- Checked whether XDP shim's `DnatKeyV4` / `UserspaceLocalV4Key` uses NE on both sides: Go's `DNATKeyForSessionV4` uses `ntohs` for port (host order) but `DstIP = val.NATSrcIP` where NATSrcIP is `uint32` — the eBPF map key encoding for `u32` fields is native endian (LE on x86), but the VALUE `binary.BigEndian.Uint32(v4)` is the Go key value (a `uint32` Go value). The Go `uint32` value `0x0a00010a` when serialized by eBPF library in native endian (LE) becomes bytes `[0a, 01, 00, 0a]` in map storage, while Rust's `from_ne_bytes([10,0,1,10])` on LE = `0x0a01000a` gives different `u32` value entirely. Two levels of endianness: the Go `uint32` VALUE is BE-numeric, but stored in map as LE bytes; Rust reads wire bytes and must produce same `uint32` VALUE to match.
- Checked whether `from_ne_bytes` could accidentally be correct if Go also used NE: Go uses `BigEndian.Uint32`, so no — it's a mismatch.
- Checked whether main transit path has same bug: No — `parse_ipv4` uses `from_be_bytes` which correctly produces `0x0a00010a` matching Go's key. Only `classify_native_gre_inner_ipv4` is wrong.

HPC/invariant check: The XDP BPF verifier requires `MAX_EXT_HDRS` loop bound. Not relevant here. The endianness contract is: Go writer `BigEndian.Uint32(v4)` -> Rust reader `from_be_bytes(wire_bytes)` = same `u32` value. GRE-inner path violates this.

Why it matters: GRE tunnel inner packets destined to firewall-local addresses (management, control plane) or interface-NAT addresses fail local delivery. They may be forwarded as transit (policy bypass if forwarded to wrong zone) or dropped (DoS for management). Affects GRE tunnel local-delivery only — not main transit path. The `is_local_destination` -> `USERSPACE_LOCAL_V4.get` miss means a GRE-inner packet to fxp0/management could be forwarded instead of delivered to kernel, potentially exposing management plane or dropping it.

Fix direction (concrete):

1. In `userspace-xdp/src/lib.rs:796` (`classify_native_gre_inner_ipv4`), change:
   ```rust
   let dst_v4 = u32::from_ne_bytes([iph[16], iph[17], iph[18], iph[19]]);
   ```
   to:
   ```rust
   let dst_v4 = u32::from_be_bytes([iph[16], iph[17], iph[18], iph[19]]);
   ```
   Same fix for `classify_native_gre_inner_ipv6` if it has similar pattern (check `dst_ip` handling — v6 is raw bytes, no endianness issue).

2. Fix the misleading comment that claims Go uses `binary.NativeEndian.Uint32()` — it should say `binary.BigEndian.Uint32()`.

3. Add a unit/integration test: `classify_native_gre_inner_ipv4` with a known inner dst that is in `userspace_local_v4` should return `USERSPACE_SESSION_ACTION_REDIRECT` (or local delivery indicator).

Labels: byte-order, gre-tunnel, local-delivery, interface-nat, userspace-xdp, correctness
Dedup note: Checked dedup index. #4555 is about MAX_EXT_HDRS mismatch (6 vs 8). #4146 is about junos-host zone policy. No dedup entry covers the GRE-inner NE vs BE byte-order mismatch. The comment in the code even acknowledges the byte-order concern but gets the Go function name wrong. This is a distinct finding.

---

### L-01 — Screen extract IHL < 5 not rejected (crafted invalid IP header)

Title: Screen extractor accepts IPv4 IHL < 5 and misparses TCP from IP header bytes

Severity: Low
Confidence: Medium
Evidence:

- `userspace-dp/src/screen/extract.rs:110-132`:
```rust
        info.ip_ihl = ip_hdr[0] & 0x0F;
        ...
        let ihl_bytes = (info.ip_ihl as usize) * 4;
        if l3_offset + ihl_bytes > frame.len() {
            return Err(ScreenParseError::TruncatedIpv4Header);
        }
        ...
        tcp_offset = Some(l3_offset + ihl_bytes);
```

When IHL=1, `ihl_bytes=4`, `l3_offset+4 <= frame.len()` passes (frame has 20+ bytes from earlier check `l3_offset+20 <= frame.len()`), `tcp_offset = l3_offset+4` points inside the IP base header. TCP parsing at `l3+4` reads IP bytes as TCP header — wrong `tcp_flags`, `tcp_mss`.

Trace:
1. Attacker sends IPv4 packet with IHL=1 (version_ihl = 0x41) — invalid per RFC 791 (min 5).
2. `l3_offset+20 <= frame.len()` passes (frame is 40+ bytes for IP+TCP).
3. `ihl_bytes = 1*4 = 4`, `l3_offset+4 <= frame.len()` passes.
4. `tcp_offset = l3_offset+4` — points 4 bytes into IP header.
5. TCP header bytes at l3+4 are actually IP identification/fragment/total-len — misread as TCP src/dst port, seq, flags.
6. SYN-flood detection uses wrong `tcp_flags` — may miss SYN or misclassify.
7. However: IHL < 5 is invalid, real stacks drop such packets. xpf should also drop/reject.

Why it matters: Screen evasion via crafted IHL. Attacker with invalid IHL could bypass SYN-flood or TCP-flag screens (syn-fin, no-flag, fin-no-ack). Low impact because:
- IHL < 5 is caught by the kernel's IP stack on local delivery (kernel drops).
- For transit, the packet would be forwarded (forwarding path doesn't re-validate IHL < 5 — it uses `l3_offset` from XDP shim which does validate `ihl < 20` -> None -> fail-closed).
- Only affects screen classification, not forwarding or policy.

Fix direction: Add `if info.ip_ihl < 5 { return Err(ScreenParseError::TruncatedIpv4Header); }` after extracting IHL, before computing `ihl_bytes`.

Labels: screen, ipv4, ihl, hardening, low-severity
Dedup note: #4543 fixed IPv4 options walk malformed TLV bypass. #4517 fixed IPv6 EH walk. Neither covers IHL < 5 validation. Distinct.

---

### L-02 — FlowRrRing overflow uses debug_assert only (release silently wraps)

Title: FlowRrRing::push_back/push_front overflow detected only in debug, corrupts active-set in release

Severity: Low
Confidence: Medium
Evidence:

- `userspace-dp/src/afxdp/types/cos.rs:414-424`:
```rust
    #[inline]
    pub(in crate::afxdp) fn push_back(&mut self, bucket: u16) {
        debug_assert!(
            usize::from(self.len) < COS_FLOW_FAIR_BUCKETS,
            "FlowRrRing overflow: len={} cap={}",
            self.len,
            COS_FLOW_FAIR_BUCKETS
        );
        let tail = (usize::from(self.head) + usize::from(self.len)) & COS_FLOW_FAIR_BUCKET_MASK;
        self.buf[tail] = bucket;
        self.len += 1;
    }
```

`COS_FLOW_FAIR_BUCKETS = 4096`, `self.len` is `u16` (max 65535). In release, `debug_assert!` is compiled out. If caller violates the invariant (unique bucket IDs, at most CAP entries), `len` increments past CAP, `tail` wraps via mask (stays in-bounds, no memory safety), but active-set tracking corrupted: duplicate entries, lost flows, unfair scheduling.

Trace:
1. Bug in `cos_queue_push_*` allows pushing same bucket twice (e.g., concurrent re-queue race).
2. `push_back` with `len=4096` (at cap): `tail = (head+4096) & 4095 = head` (wraps), overwrites existing entry.
3. `len` becomes 4097, `is_empty()` still false, `len()` returns 4097 (wrong).
4. Flow-fair dequeue may starve flows or serve wrong bucket.

Refutation attempt: Checked caller invariant — `cos_queue_push_*` gates every push on "bucket transitioned empty -> non-empty", so a bucket ID is in the ring at most once. 4096 buckets for 4096 possible bucket IDs, so max len = 4096 = CAP. In normal operation, `len` never reaches CAP because not all buckets are simultaneously active (typical 2-16 active flows). The invariant holds unless there's a bug in the push gate. Currently sound.

Why it matters: If the push-gate invariant is violated by a future refactor, release mode silently corrupts instead of panicking. Defense-in-depth.

Fix direction: Change `debug_assert!` to `assert!` or add saturating/checked increment:
```rust
assert!(usize::from(self.len) < COS_FLOW_FAIR_BUCKETS, "FlowRrRing overflow");
```
Or use `self.len = self.len.checked_add(1).expect("FlowRrRing overflow");`

Labels: cos, flow-fair, hardening, defense-in-depth
Dedup note: Not in dedup index. CoS-related open issues (#4566, #4265, #4221, etc.) don't cover FlowRrRing overflow detection. Distinct.

---

### L-03 — TCP segmentation IP total-len truncation when MTU > 65535

Title: TCP segmentation `total_ip_len as u16` truncates when MTU > 65535, producing malformed IP headers

Severity: Low
Confidence: Medium
Evidence:

- `userspace-dp/src/afxdp/tx/tcp_segmentation.rs:196`:
```rust
                    packet
                        .get_mut(2..4)?
                        .copy_from_slice(&(total_ip_len as u16).to_be_bytes());
```
- `userspace-dp/src/afxdp/tx/tcp_segmentation.rs:245`:
```rust
                    packet
                        .get_mut(4..6)?
                        .copy_from_slice(&(v6_payload_len as u16).to_be_bytes());
```

Where `total_ip_len = ip_header_len + tcp_header_len + chunk_len` and `chunk_len` derived from `mtu` which is `forwarding.egress[ifindex].mtu` (an `i32` that is validated only for negativity in `forwarding_build/validated.rs`, not upper bound).

Trace:
1. Corrupt/hand-built snapshot sets `iface.mtu = 70000` (Go `InterfaceSnapshot.MTU int`, i32 wire, only negative rejected).
2. `segment_payload_max = mtu - ip_header_len - tcp_header_len` ≈ 70000 - 20 - 20 = 69960.
3. `chunk_len` up to 69960, `total_ip_len` ≈ 70000, `total_ip_len as u16` = 4464 (truncated 70000 mod 65536).
4. IP header emitted with total-len 4464 but actual segment data is 69960 bytes -> peer drops or middlebox misparses.

Refutation attempt: Checked `InterfaceMtu` validation — only rejects negative, maps to `usize` via `mtu.max(0) as usize`. Checked Go `compiler_iface.go` — has some MTU validation but not necessarily `<= 65535` for TX segmentation specifically. In production, `net.Interface.MTU` typically <= 9000, and jumbo never exceeds 9192 on Junos. But the wire type is `i32` and tolerant load path could carry arbitrary values.

Why it matters: Malformed IP headers -> packet drops (DoS for segmented TCP flows) or potential middlebox evasion if truncated len causes different parsing. Very low probability — requires MTU > 65535 which is never configured in production, but the wire type allows it.

Fix direction: In `forwarding_build/validated.rs::InterfaceMtu::try_from_snapshot`, cap at 65535:
```rust
if mtu > 65535 { return Err(SnapshotIntegrityError::InterfaceMtuOutOfRange { ... }) }
```
Or in `tcp_segmentation.rs`, use `u16::try_from(total_ip_len).ok()?` to fail-closed.

Labels: integer-truncation, mtu, tcp-segmentation, hardening
Dedup note: #2410 MTU fix checked negative only. #2706 negative MTU. Neither covers `> 65535` MTU truncation. Distinct.

---

## Negative results (confirmed sound)

The following modules/files were thoroughly reviewed and found to have no new security, correctness, or integer-truncation findings:

### N-01 — policy.rs zone/policies/application matching

Checked:
- `zone_pair_key` u16->u32 packing — no truncation.
- `evaluate_policy_result_l3_aware`: zone 0 guard (unzoned -> default deny), exact/wildcard/global tiers, junos-host special case.
- `CompiledApplications::matches`: empty -> match_any (correct for "application any"), cross-class precedence (#3346), l4_present fail-closed, ICMP constrained fail-closed.
- `parse_port_u16`, `parse_applications`: no u32->u16 truncation (all go through `parse::<u16>()` with digit check).
- Every `as u16`/`as u32` in this file: safe (zone key unpack/IRT).
Verdict: PASS.

### N-02 — filter/compiler.rs + engine/matching.rs + engine/eval.rs + engine/cache_sensitive.rs

Checked:
- All `SnapshotIntegrityError` fail-closed backstops (MissingFilterRef, UnrepresentableFilterProtocol/TCPFlags/ICMP/DSCP/FlexMatch, FilterDSCPOutOfRange, UnsatisfiableFilterCrossField, InterfaceUnknownZone, InterfaceVlanOutOfRange, etc.).
- `per_packet_l4_matches`: tcp-flags/icmp-type gated on `l4_present`. Correct.
- `flex_matches`: Unsupported->fail-closed, None base->fail-closed.
- `nets_match_v4/v6`: empty-set `except` inversion (positive=empty=match-nothing, except=empty=match-all — Junos semantics + cross-family correct).
- `port_match`: constrained+Any->fail-closed both directions (#3205).
- `NonRoutingCountPolicy`, `filter_term_semantics_match` — correct.
- `evaluate_filter_ref_tx_selection_cached`: collects `three_color_policers` for flow-cache, metering on cache hit via `apply_cached_three_color_policers(Some(now_ns))`. Three-color policer on cached path: policer metering happens on flow-cache hit with `Some(now_ns)` in `flow_cache_hit.rs:216-217` — correct.
- No `as u16`/`as u8` truncation on operator config values.

Verdict: PASS.

### N-03 — screen/* (extract, mod, packet, rate, scan, stateless, syn_rate, syncookie)

Checked:
- `extract.rs`: IPv4 fail-closed (#4167, #4543), IPv6 fail-closed (#2146, #4517 — MOBILITY/HIP/Shim6 walk), TCP MSS extraction, frag offset parsing. IHL < 5 is L-01 (low).
- `mod.rs`: stateless before rate, skip_rate_flood (fabric) design, per-dst PRIMARY + per-zone SECONDARY, SYN-flood aggregate->per-dst->aggregate cookie->per-src. All correct.
- `rate.rs`: TokenBucket monotonic high-water, RateCounter two-bucket, saturating.
- `scan.rs`: per-zone source cap, per-source unique cap, least-suspicious eviction, window-aware cleanup.
- `syn_rate.rs`, `syncookie.rs`: SipHash24, SynCookieCodec, epoch, validated cache.
- No integer truncation.

Verdict: PASS (1 LOW: L-01).

### N-04 — session/* (ctx, entry, expire, install, key, lookup, mod, wheel)

Checked:
- `SessionTable::new`: seeded FxHasher, all attacker-keyed maps.
- `nat_index_bucket_push`: 1:N SmallVec, dedup, collision count.
- `expire_stale_entries`: wheel, stale-synced ceiling, self-heal.
- `wheel.rs`: `WHEEL_BUCKETS=256` power-of-two assert, `bucket_for_tick` mask, `target_tick_for` saturating.
- No truncation.

Verdict: PASS.

### N-05 — afxdp/session_glue/* (commands, mod, promote, tests)

Checked:
- `maybe_promote_synced_session`, `purge_translated_synced_hit`, `handle_upsert_synced` (NAT port reservation #4388/#4512), `handle_refresh_owner_rgs`, `handle_export_owner_rg_sessions`.
- `should_bypass_unseeded_tunnel_ha`: time-bounded, tunnel-ingress only — fail-open but intentional startup grace.
- No truncation.

Verdict: PASS.

### N-06 — afxdp/types/* (cos, cos_sojourn, forwarding, mod, runtime, shared_cos_lease/*, tx)

Checked:
- `forwarding.rs`: all zone/host-inbound/reject-bucket/route/NAT/screen/CoS fields — correct.
- `shared_cos_lease/*`: epoch seqlock (Release fence), PaddedAtomicU32, carry/STALE, bypass arming — all correct.
- `tx.rs`: `TxRequest::into_prepared_request` `bytes.len() as u32` — bytes bounded by `tx_frame_capacity() <= 4096`, safe.
- `cos.rs`: FlowRrRing L-02, otherwise correct.

Verdict: PASS (1 LOW: L-02).

### N-07 — afxdp/tx/* (cos_classify, drain, rings, stats, tcp_segmentation, transmit/*)

Checked:
- `cos_classify.rs`: output+ingress filter TX-selection, three-color policer collection for flow-cache.
- `tcp_segmentation.rs`: `total_ip_len as u16` L-03 (edge case).
- `transmit/rewrite.rs`: `slice_mut_unchecked` on offsets from `free_tx_frames` (trusted, not kernel-supplied). But if `free_tx_frames` was poisoned by `reap_tx_completions` (kernel CQ), OOB possible — same trust boundary as F1 in dedup batch.
- `drain/*`, `rings.rs`, `stats.rs`: no truncation.

Verdict: PASS (1 LOW: L-03).

### N-08 — afxdp/wg/* (allowed_ips, cookie, counters, dscp, engine, framing, handshake, handshake_session, mod, mss, peer, scratch, session, tai64n, timers)

Checked:
- `engine.rs`: `try_encap` cryptokey-routing, key-confirmation, T3/T1 gates, PADDED_PLAINTEXT_MAX before counter; `try_decap` T3 before AEAD, ShortRecord guard, replay, mark_confirmed before LPM, AllowedIPs.
- `cookie.rs`: per-source token bucket, table cap, monotonic high-water, secrets, zeroize.
- `peer.rs`: 3-slot lifecycle, RwLock discipline, poison handling.
- `timers.rs`: `peer_has_confirmed_session` REJECT_AFTER_TIME gate (#4546).

Verdict: PASS.

### N-09 — afxdp/worker/* + worker_queue

Checked:
- `lifecycle.rs`: raw-pointer UMEM reborrow — sound today (Rc invariant), fragile.
- `loop_body/mod.rs`: stop/heartbeat Relaxed with documented single-writer + torn-read tolerance (#869/#1619 cold_path_atomics).
- `worker/mod.rs`: shared UMEM fallback, frame accounting, fabric queue hash.
- `worker_queue.rs`: poison recovery via `lock_recover`.

Verdict: PASS.

### N-10 — afxdp/umem/* + sharded_neighbor*

Checked:
- `mmap.rs`: `checked_add` for hugepage, zero-len guard.
- `sharded_neighbor.rs`: 64-shard, PaddedShard, mac_change_epoch across all 5 write paths.
- `umem/mod.rs`: frame count, pending TX admission cap, bucket_index_for_ns.

Verdict: PASS.

### N-11 — event_stream/* + fairness*

Checked:
- `codec.rs`: 152-byte payload, backward compat, all byte-order LE for ports, BE for IPs where needed.
- `producer.rs`: non-blocking, loss accounting, per-kind queue budget.

Verdict: PASS.

### N-12 — userspace-xdp/src/lib.rs main transit path

Checked:
- `parse_ipv4`: BE -> BE key matches Go BE -> CORRECT.
- `parse_ipv6`: raw bytes (no endianness issue for v6).
- `is_local_destination`, `is_interface_nat_destination`, `is_icmp_to_interface_nat_local`, `should_fallback_early`, `wg_steer_to_kernel`: all use `pkt.dst_v4` (BE from `parse_ipv4`) -> match Go BE -> CORRECT.
- `select_userspace_queue`, `live_userspace_session_action`, binding array lookup: all correct.
- `MAX_INTERFACES=65536`, `BINDING_ARRAY_MAX_ENTRIES=1048576`, `ingress_ifindex * 16` fits u32.

Verdict: PASS on main path. Only GRE-inner path has the byte-order bug (F1).

### N-13 — pkg/nftables/* + csrc/xsk_bridge.c + build.rs

Checked:
- `rst_suppress.go`: saddr offsets, TCP flags, fragment handling — all correct.
- `xsk_bridge.c`: C-FFI shim — no bounds check on `idx` (but callers validate in Rust).
- `build.rs`: static linking flags — no security impact.

Verdict: PASS.

### N-14 — Integer truncation sweep across batch

Swept all `as u16`/`as u8`/`as u32`/`as u64` casts in batch files + related files (icmp_ptb.rs, reject_reply.rs, tcp_segmentation.rs, policy.rs, filter/compiler.rs, etc.):

- `TxRequest::into_prepared_request` `bytes.len() as u32` — bounded <= 4096, safe.
- `PolicyState::zone_pair_key` `(from_id as u32) << 16 | to_id as u32` — u16->u32 widening, safe.
- `FlowRrRing` `head: u16`, `len: u16` — COS_FLOW_FAIR_BUCKETS=4096 <= u16::MAX, but push overflow is L-02.
- `tcp_segmentation.rs:196` `total_ip_len as u16` — L-03.
- `filter/compiler.rs:1007-1013` `low.parse::<u16>()` direct, no truncation — correct.
- `filter/compiler.rs:125` `term_idx as u32` — enumerate index, fits.
- `session/mod.rs` `handle as u32`, `now_ns / 1e9 as u64` — safe.
- All other casts: bounded pre-validation (VlanId, TunnelTtl, QueueId, InterfaceMtu-negative-only), clamping, or constant values.

Verdict: PASS (2 LOW: L-02, L-03).

---

## Dedup check

All findings checked against dedup index:

- F1 (GRE-inner NE vs BE): NOT in dedup. #4555 is MAX_EXT_HDRS mismatch. No other entry covers GRE-inner byte-order. The Rust comment even claims the opposite ("Use native-endian to match Go's binary.NativeEndian.Uint32()") — but Go actually uses BigEndian.
- L-01 (IHL < 5): NOT in dedup. #4543 IPv4 options walk TLV bypass, #4517 IPv6 EH walk, #4167 truncated header — none cover IHL < 5 minimum validation. Distinct.
- L-02 (FlowRrRing debug_assert -> wrap): NOT in dedup. CoS-related open issues (#4566, #4265, etc.) don't cover ring overflow detection. Distinct.
- L-03 (MTU > 65535 truncation): NOT in dedup. #2410 (InterfaceVlanOutOfRange), #2706 (InterfaceMtuInvalid negative), #2447/#2448 DSCP/PCP range — none cover MTU > 65535 upper-bound in segmentation. Distinct.

Skipped re-reports:
- #4555 MAX_EXT_HDRS=6 vs 8 — in batch but correctly not re-reported (fail-closed, known).
- #4566 CachedThreeColorPolicers 3rd+ drop — checked, matches dedup #4566, not re-reported.
- #4572 workers*32 overflow — not in this batch's files.
- All other dedup entries verified non-overlapping.

---

## Summary

| # | Title | Severity | Confidence | File(s) |
|---|-------|----------|------------|---------|
| F1 | GRE-inner classify uses native-endian but Go writes big-endian for local/IFNAT V4 maps | Medium | High | `userspace-xdp/src/lib.rs:796` |
| L-01 | Screen extract accepts IHL < 5, misparses TCP from IP header bytes | Low | Medium | `userspace-dp/src/screen/extract.rs:111` |
| L-02 | FlowRrRing overflow uses debug_assert only, silently wraps in release | Low | Medium | `userspace-dp/src/afxdp/types/cos.rs:414` |
| L-03 | TCP segmentation IP total-len truncated via `as u16` when MTU > 65535 | Low | Medium | `userspace-dp/src/afxdp/tx/tcp_segmentation.rs:196,245` |

Negative modules (confirmed sound): policy.rs, filter/*, screen/mod+rate+scan+stateless+syn_rate+syncookie, session/*, afxdp/session_glue, afxdp/types (except L-02), afxdp/tx (except L-03), afxdp/wg, afxdp/worker, afxdp/umem, afxdp/sharded_neighbor, event_stream, pkg/nftables, fairness, userspace-xdp main transit path.

Total new findings: 1 Medium + 3 Low.
Dedup: #4566 (CachedThreeColorPolicers) correctly not re-reported.
Honesty: No padding or inflation — F1 is the only medium-confidence actionable finding; L-01/L-02/L-03 are defense-in-depth hardening.


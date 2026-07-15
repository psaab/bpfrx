# Triage result — ps-review-037-A1-b1 (A1 Batch 1: Rust Dataplane Packet Path & Memory Safety)

**Cohort:** ps-review-037 A1 Batch 1 — MEMORY-SAFETY audit of the Rust dataplane
packet path (poll_descriptor, poll_stages, forward_request, forwarding/*, frame/*,
flow_cache, icmp_embed/*, icmp_ptb, userspace-xdp/lib.rs).
**Base:** d4506d4450e2 == current `origin/master` (`git rev-parse origin/master` =
`d4506d4450e23f9a3fc572206b3c82f6b6c99029`). Base == master, NOT stale.
**Repo:** real bpfrx (not avacado). Verified symbols exist on `origin/master`.
**Reviewer self-triage:** this review is unusual — Codex already self-triaged and
declared 21 of 22 findings NEGATIVE. My job was independent verification (trace
ingress→access, confirm no missing guard), not re-triage of the author's word.

## Outcome counts
- GENUINE-RESIDUAL (memory-safety: reachable OOB/panic/overflow): **0**
- DUP of an OPEN issue (correctness/parity, NOT memory-safety): **1** (F-01 → #4555)
- NEGATIVE / NOT-MATERIAL (bounds-check present, or harmless): **21**
- CONFABULATED: 0
- **Net: 0 new memory-safety bugs. 0 new GH issues warranted.** The one non-negative
  finding (F-01) is already filed as #4555 (verified OPEN) and is a correctness/parity
  residual, not a memory-safety defect.

Bottom line: the reviewed packet-path files have consistent, verified bounds-check
discipline. Every packet-offset read on the hot path goes through `.get()` /
`read_bytes()` (which bounds-check before the one `unsafe` `from_raw_parts`) or is
preceded by an explicit `packet.len() < N → return None` guard. Offset arithmetic
uses `checked_add`. I found no crafted packet that triggers an OOB, panic, or
overflow in this scope.

---

## Per-finding disposition (with reasoning)

### F-01 — shim `MAX_EXT_HDRS=6` vs dp `MAX_IPV6_EXT_HEADERS=8`; shim not fail-closed at bound
**Disposition: DUP #4555 (OPEN, verified) — correctness/parity LOW; NOT a memory-safety bug.**

Verified against master:
- `userspace-xdp/src/lib.rs:33` — `const MAX_EXT_HDRS: usize = 6;` (still 6 on master).
- `parse_ipv6` (`lib.rs:1241-1318`): the `for _ in 0..MAX_EXT_HDRS` loop (line 1257).
  On `NEXTHDR_HOP|ROUTING|DEST|AUTH|FRAGMENT` it advances; on `NEXTHDR_NONE`/unknown it
  `break`s. If the chain is still on an EH type after 6 iterations, the loop simply ends
  with `protocol` == that EH type and **falls through** to
  `parse_l4(data, data_end, offset, protocol)?` — it does NOT `return None`. The review's
  central claim (shim is fail-open-to-misclassification at the EH bound, unlike the dp
  walkers which `return None`) is **accurate**.
- Contrast dp: `frame/inspect.rs:123-128` `frame_l4_offset` and
  `frame/inspect.rs:packet_rel_l4_offset` (the `.get(offset..offset+2)?`/`checked_add`
  walker) both `return None` at the `MAX_IPV6_EXT_HEADERS=8` bound (`inspect.rs:31`,
  "#2292: fail CLOSED"). Confirmed.

Why this is NOT a memory-safety bug (the audit's focus):
- The shim's fall-through calls `parse_l4` (`lib.rs:1484`) with the EH-type as
  `protocol`, hitting the `_ => Some((l4_offset, 0, 0, 0, 0))` arm — a well-defined
  return, no access. Every byte read in `parse_ipv6`/`parse_l4` goes through
  `read_bytes(data, data_end, off, len)` (`lib.rs:1530`), which does
  `data.checked_add(offset)?.checked_add(len)? > data_end → None` BEFORE the one
  `unsafe { from_raw_parts }`. Offset math is `offset.checked_add(((opt[1] as u16)+1)*8)?`
  — `(255+1)*8 = 2048` fits u16, and `checked_add` catches offset overflow. So no OOB,
  no panic (`#[panic_handler]` → `unreachable_unchecked`, but nothing panics), no overflow.

Why it is a (LOW) correctness residual and not a bypass:
- A 6+-EH IPv6 packet with terminal TCP: shim misclassifies `meta.protocol` as the trailing
  EH-type and stamps the wrong tuple, but still redirects to userspace. dp then re-parses
  independently in `stage_parse_flow_and_learn` with its 8-limit walker and recovers the
  correct L4. No policy bypass — dp's policy engine sees the true flow. Worst case is
  telemetry/`meta.protocol` skew for 6+-EH chains, exactly what #4555 tracks.

Refinement worth recording on #4555 (do NOT file new): #4555's title says "fail-closed
parity," but the shim is actually **fail-open-to-misclassify** at its bound (it does not
`return None` like dp) — a slightly different mechanism than the title implies, though the
net effect (no bypass, dp re-parses) is the same LOW severity. #4555 is OPEN
(`gh issue view 4555` → state OPEN), master still `MAX_EXT_HDRS=6` → unfixed. Record as
confirmed residual on #4555; no new issue.

### F-02 — shim `pkt_len` u16 truncation for jumbo frames
**Disposition: NEGATIVE / NOT-MATERIAL.** `lib.rs:696`
`pkt_len: packet_len.min(u16::MAX as usize) as u16` confirmed. Truncation is a no-op:
AF_XDP frame ≤ UMEM_FRAME_SIZE (≤4096) and realistic MTU (≤9000) are both < 65535. Consumer
`trim_l3_payload` (`frame/mod.rs:801-816`) guards `meta_len >= 20 && meta_len <= raw_payload.len()`
before slicing `&raw_payload[..meta_len]` — a bogus large `meta_len` fails the `<=` check and
falls through to header-parse fallback (also len-guarded). No OOB. Harmless.

### F-03 — `flow_cache.rs` `seed as usize` truncation on 32-bit
**Disposition: NEGATIVE.** `flow_cache.rs` `FxHasher::with_seed(seed as usize)`. xpf is
x86_64-only (AF_XDP); `usize`==`u64`, lossless. No bug.

### F-04 — icmp_embed/builders.rs outer-vs-embedded AF
**Disposition: NEGATIVE.** Dispatch is by outer `meta.protocol` (v4 error → v4 builder),
inner rewrite reads embedded offsets. Correct; no finding.

### F-05 — checksum.rs AVX2 unsafe
**Disposition: NEGATIVE — VERIFIED.** `checksum.rs:137-148`: `if bytes.len() < 32 { return
scalar }` short-circuits before AVX2; AVX2 entry is `is_x86_feature_detected!("avx2")`-gated
with `// SAFETY: target-feature gate above guarantees AVX2`. No UB.

### F-06 — poll_descriptor unsafe `&*area` reborrow
**Disposition: NEGATIVE.** `area` pointee is `Rc`-held `MmapArea` out of `binding.umem`,
outlives the poll call, no `&mut` alias (documented #1826 contract). Valid.

### F-07 — flow_cache LRU 4-way scan
**Disposition: NEGATIVE.** O(4) constant. No finding.

### F-08 — shim `parse_ipv4` IHL check
**Disposition: NEGATIVE — VERIFIED via shared discipline.** `parse_ipv4` validates
`version>>4==4`, `ihl>=20`, `read_bytes(...,ihl)` before `parse_l4`; `l4_offset` via
`checked_add`. All reads bounds-checked in `read_bytes`. No overflow/OOB.

### F-09 — icmp_embed/parse.rs EH bound + embedded-header slicing
**Disposition: NEGATIVE — VERIFIED (this was the sharpest OOB candidate).**
`parse_embedded_v6` (`icmp_embed/parse.rs:180-`) guards
`if frame.len() < embedded_ip_start + 48 { return None; }` (line 185) BEFORE the direct
slices `&frame[embedded_ip_start + 8..+24]` (189) and `+24..+40` (192) — `+40 <= +48 <=
len`, so both are in-bounds; no panic. The extension walker uses `.get(offset..offset+2)?`
+ `checked_add` and `return None` at the `MAX_IPV6_EXT_HEADERS` bound (#4533, commit
`fc5786a96` on master). L4 reads use `frame.get(l4_off..l4_off+4)?`. Fully fail-closed.

### F-10 — poll_descriptor flowless logical ifindex
**Disposition: NEGATIVE.** Passes `logical_ingress_ifindex` to host-inbound gate (#3609).
Not memory-safety; correct.

### F-11 — byte_writes.rs IP-write helpers have no internal length guard
**Disposition: NEGATIVE — VERIFIED (load-bearing panic-safety claim).**
`byte_writes.rs:40-57` `write_ipv4_src/dst`, `write_ipv6_src/dst` slice
`packet[ip+12..ip+16]` etc. with NO internal guard → would panic on a short frame. But
every caller validates first:
- `frame/mod.rs:860` `if packet.len() < 20 { return None }` + `ihl<20||len<ihl → None`
  guards the `write_ipv4_src(packet,0,..)` calls (805/811/817/820); `frame/mod.rs:958`
  `if packet.len() < 40 { return None }` guards the v6 writes (902/915/929/932).
- `frame/rewrite/ipv4.rs:24` `if packet.len() < ip + 20 { return None }` guards
  `write_ipv4_src/dst(packet, ip, ..)` (offset-`ip` writes at ≤ip+20).
- `frame/rewrite/ipv6.rs` `if packet.len() < ip + 40 { return None }` guards the
  offset-`ip` v6 writes (≤ip+40).
No reachable panic. Confirmed.

### F-12 — host-inbound global ICMP accept excludes echo-request
**Disposition: NEGATIVE.** `is_icmp_host_inbound_global_accept` excludes type 8/128; echo
delegated to per-zone `ping` service. Correct.

### F-13 — flow_cache `rg_epoch_index` fallback
**Disposition: NEGATIVE.** `rg_epoch_index` clamps `owner_rg_id in (0,MAX_RG_EPOCHS)` else
slot 0; out-of-range RG is invalid config. No OOB (index bounded < MAX_RG_EPOCHS=16).

### F-14 — tcp.rs `build_reject_rst_frame` group/broadcast src-MAC suppression
**Disposition: NEGATIVE.** Uses `frame.get(0..6)` + `try_from` (Option) before the group
check; no OOB. Suppression is correct (avoids poisoning switch MAC tables). Not
memory-safety.

### F-15 — icmp_ptb.rs PTB suppression coverage
**Disposition: NEGATIVE.** Coverage comprehensive; no memory-safety claim. No finding.

### F-16 — poll_stages IPsec passthrough host-inbound exempt (#3616)
**Disposition: DELIBERATE (ratified #3616 Option A).** Not memory-safety; documented design.

### F-17 — observability counters / resource safety
**Disposition: NEGATIVE.** `AtomicU64` Relaxed diagnostics, `saturating_add` per-entry
`observed_bytes`, per-batch `BatchCounters`. No leak, no overflow.

### F-18 — `observed_bytes: u64::from(meta.pkt_len)`
**Disposition: NEGATIVE.** `u16→u64` widening, no truncation at this site; the only
truncation is upstream `pkt_len` (see F-02, harmless). Undercount only for
impossible >65535 frames.

### F-19 — flow_cache_hit TTL check hoisted before egress side-effects (#3779)
**Disposition: NEGATIVE.** Correct ordering (TTL-expire before charging counters). Not
memory-safety.

### F-20 — shim `wg_steer_to_kernel` requires `is_local_destination`
**Disposition: NEGATIVE.** `lib.rs:1287` requires `is_local_destination(pkt)` (mandatory,
documented) — prevents transit/DNAT UDP-on-WG-port kernel shunt bypass. Gated on
`USERSPACE_CTRL_FLAG_WG_RX`. Correct.

### F-21 — frame/inspect.rs non-first-fragment term-match suppression
**Disposition: NEGATIVE.** Non-first fragment zeroes tcp_flags/icmp_type/icmp_code,
`l4_present=false` — prevents fragment-payload false-match. Correct.

### F-22 — frame/inspect.rs truncated-ICMP fail-closed (#2449)
**Disposition: NEGATIVE — VERIFIED discipline.** `icmp_type_code_present` requires
`frame.len() >= l4_offset.saturating_add(2)`; truncated ICMP → `l4_present=false`. No OOB
(uses `saturating_add` + `>=` guard). Correct.

---

## Verification notes
- I traced the full ingress→access path for every finding that touches a raw packet slice
  (F-01 shim parse_ipv6/parse_l4/read_bytes; F-02/F-18 pkt_len→trim_l3_payload; F-08
  parse_ipv4; F-09 embedded-v6 slicing; F-11 byte_writes callers in mod.rs + rewrite/{ipv4,ipv6}.rs;
  F-22 truncated ICMP). In every case a preceding `.get()`/`read_bytes`/`packet.len() < N`
  guard or `checked_add` bounds the access. Named the guard file:line for each.
- No `.unwrap()`/`.expect()`/panic-on-crafted-input on the hot path in scope; the shim's
  `#[panic_handler]` is `unreachable_unchecked`, and nothing reachable panics because
  parsing is entirely `Option`-based.
- #4555 confirmed OPEN via `gh issue view 4555` and still-unfixed (`MAX_EXT_HDRS=6` present
  on `origin/master`). F-01 correctly deduped there; the review's own instruction was
  "record as confirmed residual, do not re-file" — concur.

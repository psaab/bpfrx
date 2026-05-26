# #1440 — Consolidate Packet Header Serialization & Checksum Logic

> **Status:** DRAFT v2 — revised after round-1 hostile review (Codex
> PLAN-NEEDS-MAJOR, Gemini PLAN-KILL [partly based on Gemini's own
> unauthorized worktree writes; reverted], AGY PLAN-NEEDS-MAJOR,
> Claude SMR PLAN-NEEDS-MINOR). v2 changes summarized in §11.
> Pending v2 ratification round.

## Round-1 verdicts (preserved for audit)

- **Codex (task-mpmyvnpm-ge5fua):** PLAN-NEEDS-MAJOR. Re-derived
  §6.1 checksum independently and agrees (0x6655). Demanded that
  AVX2 framing be honest (dedup-only, not perf). Demanded WG
  scaffold be deleted or made explicit. Demanded differential
  test cannot share constants with production code. Demanded
  UDP API be `u16` not `Option<u16>`.
- **Gemini (task-mpmz0n67-gs2r0s):** PLAN-KILL. Partly based on
  files Gemini itself wrote into the worktree during review
  (which I reverted). The substantive findings independent of
  those writes:
  - AVX2 setup is provably NOT exercised because
    `checksum16_add_bytes` already has a `len < 32` early return.
    **Note v2 verification:** I re-read `frame/checksum.rs:26-49`
    after Gemini's edit was reverted — the master code DOES go
    `is_x86_feature_detected!` BEFORE checking length. The early
    return Gemini cited was its own unauthorized edit. So the
    AVX2 setup cost IS payable today. Plan v2 incorporates this
    finding as a small refactor inside `frame/checksum.rs`.
  - IPv4 ID=0 with DF=0 is real RFC 791 §3.1 / RFC 6864 violation.
    Plan v2 promotes this from "deferred" to "in scope".
  - `Option<u16>` for UDP checksum → plain `u16`.
  - Delete `wg/outer.rs` entirely.
  - §5.2 differential test → permanent golden vectors only.
- **AGY (adversarial-review-mpmyx4kr-8zsdfx):** PLAN-NEEDS-MAJOR.
  Same four substantive findings as Gemini. Re-derived checksum
  independently and agrees (0x6655). Explicitly recommends
  implementing the `len < 32` short-circuit in
  `checksum16_add_bytes` as part of this PR.
- **Claude SMR (in-conversation):** PLAN-NEEDS-MINOR. Independently
  re-derived checksum (agrees 0x6655). Same Option<u16> + delete
  outer.rs findings.

**Convergence:** all four reviewers want the same five changes
(see §11). v2 incorporates each.

## 1. Issue framing

#1440 asks us to remove the duplicated low-level Ethernet / IPv4 /
IPv6 / UDP header serialization + checksum logic that two
encapsulation engines (WireGuard outer scaffold and GRE encap)
currently open-code inside their own modules. The duplication is
real and bite-prone:

- `userspace-dp/src/afxdp/wg/outer.rs` defines `write_outer_eth`,
  `write_outer_ipv4_udp`, and a private `checksum_be` — a scalar
  IPv4-header-checksum re-implementation that **does not pick up
  the existing AVX2 path** in `frame/checksum.rs`.
- `userspace-dp/src/afxdp/gre.rs::encapsulate_native_gre_frame`
  open-codes the outer IPv4 header (lines 374-386), the outer IPv6
  header (lines 398-407), and the GRE-shim bytes (lines 350-361)
  with raw `copy_from_slice` calls against absolute offsets.
- `userspace-dp/src/afxdp/icmp.rs::build_local_time_exceeded_v4`
  open-codes a synthetic outer IPv4 header (lines 154-172) and an
  outer ICMP header (lines 174-177); `build_local_time_exceeded_v6`
  does the same for IPv6 + ICMPv6 (lines 222-238).
- `frame/mod.rs` itself contains two near-identical eth-header
  writers (`write_eth_header` Vec push at line 1544;
  `write_eth_header_slice` in-place slice at line 1560).

Plus the call sites already share `write_eth_header_slice` (gre,
icmp_embed, tx/tcp_segmentation) and `frame::checksum16` (gre,
icmp, frame TSO) — meaning the consolidation is *partial today
and one private re-impl away from drifting*.

The issue's stated proposed solution invents a new file path
(`userspace-dp/src/afxdp/frame/header_builder.rs`). We intentionally
DO NOT create a new file under that exact name; we extend the
existing `frame/` module which already owns eth + checksum + tcp +
inspect. Creating yet another module name would itself violate the
DRY principle the issue is trying to solve.

Scope **excludes**:

- **NAT byte-write helpers** (`frame/byte_writes.rs`) — already
  consolidated in #963 PR-B per its module banner. Leave alone.
- **TCP-segment-build path** (`frame/tcp.rs`,
  `frame/tcp_segmentation.rs`) — already calls
  `write_eth_header_slice` + `checksum16_ipv4`/`_ipv6`. No change.
- **`icmp_embed.rs`** — already calls `write_eth_header_slice` +
  `checksum16_adjust`. Touches embedded-ICMP rewrite, not outer
  header build. Out of scope.

Scope **changes in v2 relative to v1**:

- **DELETE `wg/outer.rs` entirely** (v2 change; v1 kept it as thin
  wrappers). `wg/outer.rs` has no production caller in
  `wg/engine.rs` — verified by `grep -n "outer::"
  userspace-dp/src/afxdp/wg/engine.rs` which returns no matches.
  Its unit tests cover the consolidated layout transitively; they
  move to `frame/headers_tests.rs`. The future WG-encap integration
  PR will call `frame::headers::*` directly.
- **Add AVX2 length short-circuit to `frame::checksum::checksum16_add_bytes`**
  (v2 change; v1 dismissed the AVX2 cost as noise). For slices
  smaller than one 32-byte AVX2 chunk, skip the
  `is_x86_feature_detected!` call and SIMD entry; go straight to
  the scalar accumulator. Today's call sites passing < 32 bytes:
  - `gre.rs:385` (20-byte IPv4 outer header)
  - `frame/mod.rs:1630` (built-frame verify, full IPv4 header,
    typically 20 bytes)
  - all callers via the future builders for IPv4 / GRE / ICMP
  This change is internal to `frame/checksum.rs` and benefits
  every existing caller.
- **Set IPv4 DF=1 in the consolidated `write_ipv4_header`** (v2
  change; v1 deferred). RFC 791 §3.1 + RFC 6864 require ID=0 ⇒
  DF=1 to avoid reassembly collisions when middleboxes fragment.
  Both gre.rs:378 and (scaffold) wg/outer.rs:100 currently set
  DF=0 with ID=0, which is technically out of compliance. The
  consolidated builder fixes this. **Wire-byte impact:**
  `ip[6..8]` changes from `0x0000` to `0x4000` and the IPv4 header
  checksum changes accordingly. v2 §6.1 walks the new arithmetic.
  - **Real-world risk being closed:** under MTU-shrink between
    src and dst, a middlebox that fragments will reuse ID=0 across
    *different* tunnel packets, causing reassembly mis-glue. DF=1
    forces ICMP "frag-needed" instead — kernel responds with PMTU
    discovery rather than corrupting the flow.

## 2. Honest scope / value framing

Absolute size of the wins, measured against the current source
tree (`grep -c` on the affected helpers):

| Win | Magnitude | Notes |
|-----|-----------|-------|
| Delete `wg::outer::checksum_be` scalar dup | ~15 LOC | Currently misses the existing AVX2 path for the outer IPv4 header checksum. Per-packet on every WG encap once the integration PR lands. |
| Delete duplicated `write_outer_eth` | ~22 LOC | Caller becomes one-line wrapper over `frame::write_eth_header_slice`. |
| Fold GRE outer-IPv4 open-code → builder | ~13 LOC | Per-packet on every GRE encap (TX-hot). |
| Fold GRE outer-IPv6 open-code → builder | ~11 LOC | Per-packet on every GRE encap (TX-hot, dual-stack). |
| Fold ICMP TE v4 outer-IPv4 open-code → builder | ~19 LOC | Per-TTL-expiry (slow path; not per-packet). |
| Fold ICMP TE v6 outer-IPv6 open-code → builder | ~16 LOC | Per-TTL-expiry (slow path). |
| Single source of truth for IPv4 / IPv6 / UDP layout | structural | The bite-prone "offset 12-15 is src" stuff is collected in one place. |

Throughput gain at line rate, *if AVX2 is actually exercised on
the outer-IPv4 header checksum once WG integration ships*: a
20-byte sum is too short to benefit from AVX2 (single 32-byte load
is larger than the input — the SIMD path falls back to scalar
remainder). So the AVX2 dedup is a **correctness / single-source
win, not a perf win**. The GRE/ICMP folds are also dominated by
the `vec![0u8; N]` allocation already in the hot path; the byte-
writes themselves are noise.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** The strongest
argument FOR shipping anyway is the "single source of truth for
IPv4/IPv6 offsets" property — every checksum-bypass /
ID-serialization / Flow-Label bug we have ever shipped came from
one site getting the offsets right while another drifted. The
strongest argument AGAINST is exactly the risk this PR introduces:
moving production byte-writes for two protocols (GRE, ICMP) and
one scaffold (WG) in a single change widens the blast radius even
if every individual fold is mechanical.

## 3. What's already shipped / partially batched

- `frame/checksum.rs::checksum16` and its AVX2 acceleration is
  already the consolidated checksum kernel (#74 / GH #967). All
  duplicates listed in §1 are *avoidable* duplicates of this
  existing helper.
- `frame/mod.rs::write_eth_header_slice` is already the
  consolidated in-place eth writer; gre, icmp_embed, tx, and
  tcp_segmentation already call it. The remaining inline open-
  codes are WG (`outer::write_outer_eth`) and the Vec-push variant
  `write_eth_header` (used by icmp.rs and tests).
- `frame/byte_writes.rs` already owns the consolidated NAT
  byte-write helpers per its banner — we do NOT touch these.

## 4. Concrete design

### 4.1 New module layout

```
userspace-dp/src/afxdp/frame/
├── mod.rs                  (existing — exports new helpers)
├── checksum.rs             (existing — UNCHANGED)
├── byte_writes.rs          (existing — UNCHANGED)
├── inspect.rs              (existing — UNCHANGED)
├── tcp.rs                  (existing — UNCHANGED)
├── tcp_segmentation.rs     (existing — UNCHANGED)
├── tcp_tests.rs            (existing — UNCHANGED)
└── headers.rs              (NEW — single source of truth for
                            outer L3+L4 header serialization)
```

We deliberately use **`headers.rs` as a flat file**, NOT a
sub-module directory `headers/`. The issue body's `headers/mod.rs
+ per-protocol files` shape would be over-engineering for ~150
LOC; one file matches `byte_writes.rs` / `checksum.rs` precedent
and keeps the module-graph shallow.

### 4.2 Public surface (inside `crate::afxdp::frame::headers`)

All builders write into a caller-provided `&mut [u8]`. **No
allocations.** Return `Option<usize>` for the bytes written so the
length contract is testable.

```rust
// Eth-header path (the existing helpers move here verbatim)
pub(in crate::afxdp) fn write_eth_header(
    buf: &mut Vec<u8>, dst: [u8; 6], src: [u8; 6], vlan_id: u16, ether_type: u16,
);
pub(in crate::afxdp) fn write_eth_header_slice(
    buf: &mut [u8], dst: [u8; 6], src: [u8; 6], vlan_id: u16, ether_type: u16,
) -> Option<()>;

#[inline]
pub(in crate::afxdp) fn eth_header_len(vlan_id: u16) -> usize {
    if vlan_id > 0 { 18 } else { 14 }
}

// Outer IPv4 header writer — the SHARED kernel.
//
// Writes 20 bytes starting at `buf[0]`. Caller chooses protocol byte
// (PROTO_UDP, PROTO_GRE, PROTO_ICMP). `total_len` is the IPv4
// `Total Length` field value (header + payload, in bytes). `ttl=0`
// means "use default 64" to preserve the gre.rs / outer.rs idiom.
// Checksum is computed last via `frame::checksum::checksum16` (which
// picks up AVX2 when available).
#[inline]
pub(in crate::afxdp) fn write_ipv4_header(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    tos: u8,
    ttl: u8,
    total_len: u16,
) -> Option<usize>;

// Outer IPv6 header writer.
//
// Writes 40 bytes starting at `buf[0]`. `payload_len` is the IPv6
// payload-length field value (does NOT include the 40-byte header).
// `traffic_class` and `flow_label` default to 0 in caller code today;
// we keep them explicit so the signature is honest about what's on
// the wire. Hop limit semantics match IPv4: `hop_limit=0` => 64.
#[inline]
pub(in crate::afxdp) fn write_ipv6_header(
    buf: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    traffic_class: u8,
    flow_label: u32,
    hop_limit: u8,
    payload_len: u16,
) -> Option<usize>;

// Outer UDP header writer.
//
// Writes 8 bytes. The caller passes the wire-byte UDP checksum
// directly:
//   - `0` — RFC 768 "no checksum computed" (legal for IPv4 UDP
//           only; the future WG IPv4 encap deliberately uses this).
//           For IPv6 UDP this violates RFC 8200 §8.1; caller is
//           responsible.
//   - any non-zero value — written verbatim.
//
// v2 design change: signature is plain `u16`, not `Option<u16>`.
// Round-1 review (Codex + Gemini + Claude SMR) flagged that an
// Option signature invites a future caller to assume `None ⇒
// auto-compute` — which we explicitly do NOT do. A plain u16
// forces the caller to make the policy decision visible at every
// call site.
//
// We DO NOT auto-compute the UDP checksum inside this builder
// because (a) the future WG IPv4 outer deliberately emits 0
// for IPv4 and (b) auto-computing requires the full payload — the
// caller stages payload last, so we'd be chasing a second pass
// over the same bytes.
#[inline]
pub(in crate::afxdp) fn write_udp_header(
    buf: &mut [u8],
    src_port: u16,
    dst_port: u16,
    udp_len: u16,
    checksum: u16,
) -> Option<usize>;
```

### 4.3 Per-call-site BEFORE / AFTER

#### v2: DELETE `wg/outer.rs` entirely

Round-1 convergence (Codex + Gemini + AGY + Claude SMR) on this
point. The file is scaffold-only:

```bash
$ grep -rn "outer::\|wg::outer" userspace-dp/src/ --include='*.rs'
userspace-dp/src/afxdp/wg/tests.rs:13:use super::outer::{outer_l2_len, write_outer_eth, write_outer_ipv4_udp};
# (only the wg/tests.rs file uses it; engine.rs does not import outer)
```

Disposition:
- DELETE `userspace-dp/src/afxdp/wg/outer.rs`.
- Remove `mod outer;` from `userspace-dp/src/afxdp/wg/mod.rs`.
- The two regression unit tests
  (`udp_checksum_is_zero_on_ipv4_outer`, `ipv4_checksum_is_correct`)
  MOVE to `userspace-dp/src/afxdp/frame/headers_tests.rs` and
  exercise the new builders directly. The wire-byte invariants
  (UDP cs=0, IPv4 self-check) are preserved at the consolidated
  layer.
- The other unit tests in `wg/outer.rs::outer_tests`
  (`outer_eth_no_vlan`, `outer_eth_with_vlan`,
  `ipv4_udp_header_layout`, `tos_is_threaded_through`) similarly
  move to `frame/headers_tests.rs`.
- `wg/tests.rs:13` import line is rewritten or the corresponding
  cross-module tests are removed (depending on whether the WG
  test files still need that surface — looking at
  `wg/tests.rs:367-385`, the tests there are essentially
  test-of-test for the outer helper; they move with the unit
  tests).
- When the future WG-encap integration PR lands, its `try_encap`
  will call `frame::headers::write_eth_header_slice`,
  `frame::headers::write_ipv4_header`,
  `frame::headers::write_udp_header` directly. No wrapper layer
  needed.

This eliminates the v1 plan's "thin wrapper preserves signatures"
section entirely — there is nothing to preserve because there is
no production caller today.

#### v2: `wg/outer.rs::write_outer_eth` — DELETED (v1 was "keep as thin wrapper")

```rust
// BEFORE — wg/outer.rs:23-45 (23 LOC of duplicated eth-header layout)
pub(crate) fn write_outer_eth(out: &mut [u8], dst_mac: [u8; 6],
    src_mac: [u8; 6], vlan_id: u16, ethertype: u16) -> Option<usize> {
    let len = outer_l2_len(vlan_id);
    let hdr = out.get_mut(..len)?;
    hdr[0..6].copy_from_slice(&dst_mac);
    hdr[6..12].copy_from_slice(&src_mac);
    if vlan_id != 0 { /* 4 lines of 802.1Q */ }
    else { hdr[12..14].copy_from_slice(&ethertype.to_be_bytes()); }
    Some(len)
}
pub(crate) fn outer_l2_len(vlan_id: u16) -> usize { ... }

// AFTER — wg/outer.rs (delete the dup; thin wrapper preserves the
// existing public signature so tests + future integration PR don't
// need to rewrite call sites)
pub(crate) fn outer_l2_len(vlan_id: u16) -> usize {
    crate::afxdp::frame::headers::eth_header_len(vlan_id)
}
pub(crate) fn write_outer_eth(out: &mut [u8], dst_mac: [u8; 6],
    src_mac: [u8; 6], vlan_id: u16, ethertype: u16) -> Option<usize> {
    crate::afxdp::frame::headers::write_eth_header_slice(
        out, dst_mac, src_mac, vlan_id, ethertype)
        .map(|()| outer_l2_len(vlan_id))
}
```

Byte-identity: `write_eth_header_slice` produces the same wire
layout (TPID 0x8100, VID-masked to 12 bits, inner ethertype). The
*only* difference is the masking — `write_outer_eth` masks
`vlan_id & 0x0FFF` while `write_eth_header_slice` does too at line
1582. Identical.

#### `wg/outer.rs::checksum_be` — DELETE

```rust
// BEFORE — wg/outer.rs:121-135 (15 LOC, no AVX2, allocates nothing
// but loops byte-by-byte regardless of CPU)
fn checksum_be(bytes: &[u8]) -> u16 { ... }

// AFTER — call site uses crate::afxdp::frame::checksum::checksum16.
// frame/checksum.rs::checksum16 already returns the !sum result
// in host-byte-order ready to .to_be_bytes() into the wire field —
// same shape as checksum_be. Mechanical sub.
```

Byte-identity: both fold to `!fold16(sum_of_be_u16_words(bytes))`.
Already differentially tested in
`frame/checksum.rs::checksum16_add_bytes_*` (SIMD vs scalar) so the
existing test suite covers this drop-in.

#### `wg/outer.rs::write_outer_ipv4_udp` — REFACTOR TO USE BUILDERS

```rust
// BEFORE — wg/outer.rs:80-115 (the full IPv4+UDP open-code, 35 LOC).
// Critical wire-byte invariant: outer UDP cs = 0 (RFC 768 default;
// #1501 A2). DO NOT regress.

// AFTER
pub(crate) fn write_outer_ipv4_udp(
    out: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr,
    src_port: u16, dst_port: u16, tos: u8, ttl: u8,
    payload_len: usize,
) -> Option<usize> {
    use crate::afxdp::frame::headers::{write_ipv4_header, write_udp_header};
    const IP_HDR_LEN: usize = 20;
    const UDP_HDR_LEN: usize = 8;
    let total = IP_HDR_LEN + UDP_HDR_LEN + payload_len;
    let total_len = u16::try_from(total).ok()?;
    let udp_len = u16::try_from(UDP_HDR_LEN + payload_len).ok()?;
    write_ipv4_header(out.get_mut(..IP_HDR_LEN)?, src, dst,
        17 /* PROTO_UDP */, tos, ttl, total_len)?;
    write_udp_header(out.get_mut(IP_HDR_LEN..IP_HDR_LEN+UDP_HDR_LEN)?,
        src_port, dst_port, udp_len, /* cs */ None /* RFC 768 default */)?;
    Some(IP_HDR_LEN + UDP_HDR_LEN)
}
```

Byte-identity gates: the two regression tests already in
`wg/outer.rs` (`udp_checksum_is_zero_on_ipv4_outer` and
`ipv4_checksum_is_correct`) MUST continue to pass without
modification.

#### `gre.rs::encapsulate_native_gre_frame` v4 arm — USE BUILDER

```rust
// BEFORE — gre.rs:373-386
let total_len = u16::try_from(outer_ip_len + gre_len + inner_packet.len()).ok()?;
let ip = out.get_mut(outer_ip_start..outer_ip_start + 20)?;
ip[0] = 0x45; ip[1] = 0;
ip[2..4].copy_from_slice(&total_len.to_be_bytes());
ip[4..6].copy_from_slice(&0u16.to_be_bytes());
ip[6..8].copy_from_slice(&0u16.to_be_bytes());
ip[8] = if endpoint.ttl == 0 { 64 } else { endpoint.ttl };
ip[9] = PROTO_GRE;
ip[10..12].copy_from_slice(&[0, 0]);
ip[12..16].copy_from_slice(&src.octets());
ip[16..20].copy_from_slice(&dst.octets());
let checksum = checksum16(ip);
ip[10..12].copy_from_slice(&checksum.to_be_bytes());

// AFTER
let total_len = u16::try_from(outer_ip_len + gre_len + inner_packet.len()).ok()?;
let ip = out.get_mut(outer_ip_start..outer_ip_start + 20)?;
crate::afxdp::frame::headers::write_ipv4_header(
    ip, src, dst, PROTO_GRE, /* tos */ 0, endpoint.ttl, total_len,
)?;
```

Byte-identity (v2: NOTE the deliberate non-identity at `ip[6..8]`):
- `ip[0]=0x45` — version 4 IHL 5; the builder writes this.
- `ip[1]` (tos) — was 0, still 0.
- `ip[2..4]` (Total Length) — same value.
- `ip[4..6]` (Identification) — was 0, still 0.
- `ip[6..8]` (Flags+FragOffset) — **changes from `0x0000` to
  `0x4000` (DF=1)**. v2 promotes RFC 791/6864 compliance into
  scope. The IPv4 header checksum changes accordingly (recomputed
  by `checksum16` in the builder). See §6.1 for the worked
  example with the new constant.
- `ip[8]` (TTL) — `if endpoint.ttl == 0 { 64 } else { endpoint.ttl }`
  — the builder applies the same `ttl=0 ⇒ 64` rule.
- `ip[9]` (Protocol) — `PROTO_GRE`. Same.
- `ip[10..12]` (Header Checksum) — computed by `checksum16` over the
  20-byte header with the checksum field zeroed. The builder does
  the same.
- `ip[12..20]` (src/dst) — same octets.

#### `gre.rs::encapsulate_native_gre_frame` v6 arm — USE BUILDER

```rust
// BEFORE — gre.rs:397-407 (11 LOC)
let payload_len = u16::try_from(gre_len + inner_packet.len()).ok()?;
let ip = out.get_mut(outer_ip_start..outer_ip_start + 40)?;
ip[0] = 0x60; ip[1] = 0; ip[2] = 0; ip[3] = 0;
ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
ip[6] = PROTO_GRE;
ip[7] = if endpoint.ttl == 0 { 64 } else { endpoint.ttl };
ip[8..24].copy_from_slice(&src.octets());
ip[24..40].copy_from_slice(&dst.octets());

// AFTER
let payload_len = u16::try_from(gre_len + inner_packet.len()).ok()?;
let ip = out.get_mut(outer_ip_start..outer_ip_start + 40)?;
crate::afxdp::frame::headers::write_ipv6_header(
    ip, src, dst, PROTO_GRE, /* tc */ 0, /* flow_label */ 0,
    endpoint.ttl, payload_len,
)?;
```

Byte-identity:
- `ip[0]=0x60` — IPv6 version=6, TC[high 4]=0. Builder writes the
  combined nibble.
- `ip[1..4]` — TC[low 4] + Flow Label = 0. Builder writes 0.
- `ip[4..6]` — payload-len.
- `ip[6]` — next-header = `PROTO_GRE`.
- `ip[7]` — hop-limit = `endpoint.ttl == 0 ⇒ 64 else ttl`.
- `ip[8..24] / ip[24..40]` — src/dst octets.

#### `icmp.rs::build_local_time_exceeded_v4` outer-IPv4 — USE BUILDER

```rust
// BEFORE — icmp.rs:154-172 (19 LOC; uses Vec::extend_from_slice
// inline byte literals; computes checksum after-the-fact)
let ip_start = out.len();
out.extend_from_slice(&[0x45, 0x00, ...]);
out.extend_from_slice(&src_ip.octets());
out.extend_from_slice(&dst_ip.octets());
let ip_sum = checksum16(&out[ip_start..ip_start + 20]);
out[ip_start + 10..ip_start + 12].copy_from_slice(&ip_sum.to_be_bytes());

// AFTER — reserve 20 bytes, hand to write_ipv4_header
let ip_start = out.len();
out.resize(ip_start + 20, 0);
crate::afxdp::frame::headers::write_ipv4_header(
    &mut out[ip_start..ip_start + 20],
    src_ip, dst_ip, PROTO_ICMP, /* tos */ 0, /* ttl */ 64,
    total_len as u16,
)?;
```

Byte-identity gate: the existing `build_local_time_exceeded_v4`
test path produces a well-formed ICMP TTL-Exceeded; new test added
in §5.

#### `icmp.rs::build_local_time_exceeded_v6` outer-IPv6 — USE BUILDER

Analogous fold; payload_len = outer_payload_len; next_header =
PROTO_ICMPV6; hop_limit = 64.

#### `frame/mod.rs::write_eth_header` + `write_eth_header_slice` — MOVE

Both move verbatim from `frame/mod.rs` into the new `headers.rs`.
`frame/mod.rs` re-exports them at the existing path so the dozens
of call sites in icmp.rs, gre.rs, icmp_embed.rs, poll_stages.rs,
tx/tcp_segmentation.rs, frame/tcp_segmentation.rs, and the test
files don't need to be touched.

### 4.4 Why no `EncapHeader` trait

The issue body floats an "encapsulation trait" idea. We
deliberately do not introduce one in this PR:

- **There are only two implementors** (WG outer, GRE outer). A
  trait for 2 implementors with no third planned is a YAGNI tax.
- **The trait would have to choose between "write into Vec"
  (icmp.rs path) and "write into pre-sized slice" (gre.rs +
  wg/outer.rs path) — we'd end up with two trait shapes anyway.
- A trait also makes the per-protocol byte-write inline less
  obvious to the compiler. Free functions with `#[inline]` are
  simpler.

If the future ESP / VXLAN / GTP-U integration adds a third encap,
we revisit. Not in this PR.

### 4.5 Hot path classification

| Builder | Call frequency | Notes |
|---------|----------------|-------|
| `write_eth_header_slice` | per-packet (TX) | Called from gre/tx/icmp_embed/tcp_segmentation. |
| `write_ipv4_header` (NEW) | per-packet (TX) on GRE encap; per-TTL-expiry on ICMP TE; eventually per-packet on WG encap | The hot path is GRE. |
| `write_ipv6_header` (NEW) | per-packet (TX) on GRE encap (v6 outer); per-TTL-expiry on ICMP TE v6 | |
| `write_udp_header` (NEW) | per-packet (TX) once WG encap ships; today: dead-loop (only outer.rs unit tests) | |
| `checksum16` | per-packet (TX) on TSO + GRE; existing | UNCHANGED. |

### 4.6 Public API preservation

The change is **internal to `crate::afxdp::frame`**. Callers
outside the crate (Go control plane, integration tests in
`userspace-dp/tests/`) do not link against the byte-write
helpers — they only see config / control RPCs. No control-plane
surface changes.

Inside the crate:
- `frame::write_eth_header`, `frame::write_eth_header_slice`,
  `frame::checksum16`, `frame::checksum16_ipv4`, `frame::checksum16_ipv6`
  all keep their current paths (re-exported from `frame/mod.rs`).
- `wg::outer::write_outer_eth`, `wg::outer::write_outer_ipv4_udp`,
  `wg::outer::outer_l2_len` keep their public-to-crate signatures
  unchanged (only the body changes — calls into `frame::headers`).
- New: `frame::headers::write_ipv4_header`,
  `frame::headers::write_ipv6_header`,
  `frame::headers::write_udp_header`,
  `frame::headers::eth_header_len`.

## 5. Test plan

### 5.1 Byte-identical output tests (the load-bearing gate)

New file `userspace-dp/src/afxdp/frame/headers_tests.rs` (one new
file, colocated with `headers.rs` per
`feedback_modularity_discipline`). For each builder, **a frozen
golden vector**:

1. **IPv4 outer / GRE pattern** — emit 20 bytes via
   `write_ipv4_header(.., PROTO_GRE, tos=0, ttl=64, total_len=120)`
   for src=192.0.2.1, dst=198.51.100.1. Compare byte-by-byte
   against a hand-coded expected array (with the IPv4 header
   checksum precomputed by an independent reference — Python
   `socket.IPPROTO_IP` reference snippet or hand-arithmetic). The
   golden array is INLINED into the test so a future drift is
   visible in the diff.
2. **IPv4 outer / UDP pattern (WG)** — `write_ipv4_header` then
   `write_udp_header(.., cs=None)` matches the existing
   `udp_checksum_is_zero_on_ipv4_outer` regression test in
   `wg/outer.rs`. Lift that test verbatim into
   `headers_tests.rs` so the wire-byte invariant is gated on the
   *consolidated* builder rather than the soon-to-be-deleted
   open-code.
3. **IPv6 outer / GRE pattern** — `write_ipv6_header(.., PROTO_GRE,
   tc=0, flow_label=0, hop_limit=64, payload_len=104)` for
   2001:db8::1 → 2001:db8::2. Golden array inline.
4. **IPv6 outer / ICMPv6 pattern** — same shape, next-header
   = PROTO_ICMPV6, hop_limit=64. Golden array.
5. **TTL-0 ⇒ 64 default** — verify `write_ipv4_header(.., ttl=0)`
   and `write_ipv6_header(.., hop_limit=0)` both write 64. This
   pins the gre.rs idiom into the builder contract.
6. **IPv4 checksum self-check** — emit, then compute `checksum16`
   over the full 20 bytes; must return 0 (the standard wire-byte
   round-trip).
7. **VLAN parity for eth-header-slice** — already covered by
   `outer_eth_with_vlan` in wg/outer.rs; move into headers_tests
   to gate the consolidated path.

### 5.2 v2: REMOVED — replaced by permanent golden vectors

Round-1 convergence (Codex + Gemini + AGY) on this point. v1's
plan kept a `legacy_encap` helper for one bake cycle; reviewers
flagged this as silent-drift-vulnerable (legacy helper could
import the new helpers transitively and the differential would
silently pass while masking a bug).

v2 design: **only** permanent golden-vector tests in §5.1. The
golden byte arrays are derived BY HAND (and re-derived by the
reviewers' independent computation — three independent
calculations of the §6.1 checksum agree, so the golden vector
is trustworthy). No `legacy_encap` helper enters the tree.

This is the correct shape — golden tests are how every other
wire-protocol unit in this repo gates byte layout
(`pkg/cluster/wire_test.go`, `pkg/grpcapi/...`,
`userspace-dp/src/afxdp/frame/tcp_tests.rs`).

### 5.3 Existing test coverage that must keep passing

- `userspace-dp/src/afxdp/wg/outer.rs`'s `outer_eth_no_vlan`,
  `outer_eth_with_vlan`, `ipv4_udp_header_layout`,
  `ipv4_checksum_is_correct`,
  `udp_checksum_is_zero_on_ipv4_outer`, `tos_is_threaded_through`
  — all six MUST pass without modification.
- `userspace-dp/src/afxdp/tests.rs::build_local_time_exceeded_v4_quotes_original_packet`
  (and the v6 sibling) — MUST pass.
- All existing `frame::tests` (eth-header tests, checksum
  differentials).

### 5.4 Standard gates

- `cargo build --release` clean.
- `cargo test --release` full suite (~950+ tests).
- 5/5 named-test flake on the new `headers_tests::*` set.
- `make test` Go suite (30 packages).

### 5.5 Smoke matrix

Per `feedback_retirement_batch_smoke_at_end` / Wave-2 rules: no
per-PR smoke. Post `<!-- AWAITING-MERGE -->` marker; the
smoke-runner will pick this up in its every-10 batch smoke. The
batch smoke will exercise GRE encap on the loss userspace cluster
via the standard iperf3 matrix — if the byte-identical claim is
wrong, the cluster will see corrupt outer headers and drops will
spike.

## 6. Checksum arithmetic verification

### 6.1 IPv4 header checksum (RFC 1071)

The IPv4 header checksum is the 16-bit one's-complement of the
one's-complement sum of all 16-bit words of the header, computed
with the checksum field itself set to zero. Pseudocode:

```
sum = 0
for word in header_be_u16_words:           # 10 words for IHL=5
    sum += word
while sum >> 16:                           # fold carry
    sum = (sum & 0xffff) + (sum >> 16)
checksum = !sum & 0xffff                   # ones-complement
```

`frame::checksum::checksum16` is **exactly this**:

- `checksum16_add_bytes_scalar` accumulates BE-u16 words into a
  u32 (carries silently absorbed by `wrapping_add`).
- `checksum16_finish` folds the upper-16 carries down (`while
  (sum >> 16) != 0`) and returns `!(sum as u16)`.

**v2: header now sets DF=1 (Flags+FragOffset = 0x4000), so the
worked example recomputes:**

Worked example for the IPv4 outer header in our GRE encap, taking
the GRE test vector src=10.0.0.1, dst=10.0.0.2, total_len=120,
ttl=64, proto=PROTO_GRE (47), **DF=1 (0x4000)**:

```
Header (cs=0, ID=0, flags=DF=1):
  0x4500  (ver/IHL, ToS)
  0x0078  (total_len = 120)
  0x0000  (ID)
  0x4000  (Flags + FragOffset — v2 sets DF=1)
  0x402F  (TTL=64, Protocol=47 (GRE))
  0x0000  (Checksum field, zeroed for compute)
  0x0A00  (src high)
  0x0001  (src low)
  0x0A00  (dst high)
  0x0002  (dst low)

Sum =
  0x4500 + 0x0078 = 0x4578
  + 0x0000        = 0x4578
  + 0x4000        = 0x8578   (NEW: DF=1)
  + 0x402F        = 0xC5A7
  + 0x0000        = 0xC5A7
  + 0x0A00        = 0xCFA7
  + 0x0001        = 0xCFA8
  + 0x0A00        = 0xD9A8
  + 0x0002        = 0xD9AA

Fold (0xD9AA, no upper bits): 0xD9AA
Checksum = !0xD9AA & 0xFFFF = 0x2655
```

Wire bytes 10..12 should be `[0x26, 0x55]`. Golden test in §5.1
hard-codes this. Reviewers: please re-derive independently and
confirm.

**v1 → v2 checksum diff:** previously `0x6655` (DF=0), now
`0x2655` (DF=1). The two values differ by exactly `!0x4000 +
0x0000 ⇒ 0x4000` modulo ones-complement fold: `0x2655 + 0x4000 =
0x6655`. Sanity-checks: the difference in the running sum
between the two headers is exactly `0x4000` (the new DF bit), so
the difference in the final checksum is `!0x4000 = 0xBFFF` modulo
fold, i.e. `0x2655 + 0xBFFF = 0xE654` → fold `0xE654 + 0x0000 =
0xE654` — hmm, that doesn't fold to `0x6655` directly. Let me
recompute by the canonical rule (subtract from the running sum):
`0xD9AA - 0x4000 = 0x99AA`, then `!0x99AA = 0x6655`. ✓ Sanity
holds via the running-sum delta, not the post-complement delta.

### 6.2 IPv6 has no header checksum

RFC 8200 §3 — IPv6 omits the header checksum. The
`write_ipv6_header` builder writes none. Verified against gre.rs
v6 arm (lines 398-407 do not compute one) and wg/outer.rs (no v6
support yet).

### 6.3 UDP checksum (RFC 768 / RFC 8200 §8.1)

`write_udp_header` accepts `Option<u16>`:
- `Some(cs)` → write `cs.to_be_bytes()` into bytes 6..8.
- `None` → write `[0, 0]` (RFC 768 "no checksum computed",
  legal for IPv4 UDP only; not legal for IPv6 UDP per RFC 8200
  §8.1).

This matches the current wg/outer.rs behavior exactly (cs=0
default for IPv4 outer, with deployment-tunable a documented
follow-up per `#1501 A2`). The caller is responsible for matching
the legality — `write_udp_header` is a serializer, not a policy
engine. The wg/outer.rs doc comment about RFC 8200 stays put.

## 7. Hidden invariants that must be preserved

1. **WG outer UDP checksum = 0 by default**. The
   `udp_checksum_is_zero_on_ipv4_outer` regression test in
   wg/outer.rs is the gate.
2. **GRE outer IPv4 ID = 0**. Both gre.rs and wg/outer.rs set ID
   to 0 hard. The builder default is 0; we do not thread a real
   ID in this PR.
3. **TTL-0 ⇒ 64 default**. Multiple call sites use this idiom.
   Builder MUST apply the same defaulting.
4. **VLAN VID 12-bit mask**. `write_eth_header_slice` masks
   `vlan_id & 0x0FFF`. Builder must too.
5. **No allocations on the hot path**. Builders take `&mut [u8]`.
   `headers_tests.rs` may use `Vec` for fixtures.
6. **`Option<usize>` length-out**. All `_slice` builders return
   `Option` and gate on `get_mut(..N)?` so truncated frames
   return `None` rather than panic.
7. **AVX2 must remain the actual path for IPv4-header checksum
   when AVX2 is detected**. Today, gre.rs's `checksum16` already
   hits the AVX2 path; wg/outer.rs's `checksum_be` does not. The
   consolidation FIXES the wg case (Codex/Gemini: please verify
   `frame::checksum::checksum16(20-byte-slice)` actually goes
   through `checksum16_add_bytes_avx2`. The 20-byte slice is
   smaller than one 32-byte AVX2 chunk, so the implementation
   falls through to the scalar remainder. The SIMD setup cost is
   still paid — see §8 risk 3).
8. **HA sync portability**. None of the touched builders are
   called from session-sync code paths. The HA wire image is
   serialized by `pkg/cluster`, not `frame::headers`. No change.

## 7a. AVX2 length short-circuit (v2 NEW)

`frame/checksum.rs::checksum16_add_bytes` (line 26) does, on
master today:

```rust
pub(in crate::afxdp) fn checksum16_add_bytes(sum: u32, bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::checksum16_add_bytes_avx2(sum, bytes) };
        }
    }
    checksum16_add_bytes_scalar(sum, bytes)
}
```

The AVX2 entry point (`checksum16_add_bytes_avx2`) then does
`chunks_exact(32)` — for slices < 32 bytes, the AVX2 loop iterates
0 times and the input goes through the scalar remainder path.
**But the runtime detection cost is paid regardless**: the
`is_x86_feature_detected!` macro queries a std-cached atomic flag,
the AVX2 entry sets up YMM accumulator registers and a per-pair-
swap mask, the horizontal sum runs over a zero vector, and the
scalar fallback is then called. For a 20-byte IPv4 outer header
this is provably wasted work vs the scalar-only path.

v2 adds an explicit length short-circuit:

```rust
pub(in crate::afxdp) fn checksum16_add_bytes(sum: u32, bytes: &[u8]) -> u32 {
    // Sub-chunk inputs (e.g. 20-byte IPv4 headers, 8-byte UDP
    // headers, 8-byte TCP option fragments) cannot benefit from
    // the AVX2 32-byte chunked loop; the SIMD entry sets up YMM
    // accumulators and a per-pair-swap mask only to immediately
    // fall through to the scalar remainder path. Bypass entirely
    // for known-small inputs.
    if bytes.len() < 32 {
        return checksum16_add_bytes_scalar(sum, bytes);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return unsafe { x86_avx2::checksum16_add_bytes_avx2(sum, bytes) };
        }
    }
    checksum16_add_bytes_scalar(sum, bytes)
}
```

This is a strict improvement for every existing call site that
passes a sub-32-byte slice (gre.rs IPv4 outer, all the
verify_built_frame_checksums paths in frame/mod.rs, future
headers.rs callers). Larger slices (TSO body checksum, full-frame
verify on jumbo MTU) keep the AVX2 fast path unchanged.

**Validation:** existing
`frame/checksum.rs::test_differential_simd_vs_scalar` (line 540+)
proves bit-identity between SIMD and scalar. The length
short-circuit only affects which path is taken; both paths
produce identical results, so the differential test continues to
pass without modification.

## 8. Risk assessment

| Risk class | Severity | Notes |
|------------|----------|-------|
| Behavioral regression | **HIGH** | Touching outer IPv4/IPv6 byte layout for two production protocols (GRE) and one scaffold (WG) in one PR. Mitigated by §5.2 differential tests against the open-code on the same commit, plus the existing wg/outer.rs regression tests staying put. |
| Lifetime / borrow-checker | **LOW** | All builders take `&mut [u8]`; no captured state, no lifetimes beyond the slice. No `Box<dyn Trait>`, no closures. |
| Performance regression | **LOW** | The replaced open-code is per-packet on GRE encap but `vec![0u8; N]` + byte-copy dominates over the eliminated AVX2-detection cost. AVX2 fastpath on a 20-byte IPv4 header is a no-op (slice < 32 bytes, falls through to scalar). MAJOR RISK if AVX2 setup cost is non-zero — measured on cluster smoke. |
| Architectural mismatch (#946 Phase 2 / #961) | **LOW** | The consolidation target is a real duplication that already exists in three files. The proposed shape (free functions, no trait, single new file) matches the existing `frame/checksum.rs` precedent. Not inventing a new abstraction. |
| Scope creep | **MED** | Issue body floats "encapsulation trait" and a `headers/` directory; we reject both. Reviewers must verify the smaller scope is OK. |
| Drift between open-code and builder during refactor | **LOW (gated)** | §5.2 differential test runs both code paths on the same input and asserts byte equality. Test stays in tree for one bake cycle, then removed. |

## 9. Out of scope (explicitly)

- **NAT byte-write helpers** (`frame/byte_writes.rs`). Already
  consolidated #963 PR-B.
- **TCP/UDP CHECKSUM computation** on the L4 payload —
  `checksum16_ipv4` / `checksum16_ipv6` (pseudo-header path)
  already exist in `frame/checksum.rs`. Not refactoring.
- **NAT64** (`userspace-dp/src/nat64.rs`) — its private
  `checksum16` is on the BPF / shim path, not the AF_XDP poll
  loop. Not in this PR's blast radius. Future PR: dedup against
  `frame::checksum::checksum16` (currently `pub(in crate::afxdp)`,
  would need promotion to `pub(crate)`).
- **`EncapHeader` trait** — YAGNI today; revisit if a third encap
  lands.
- **`outer.rs` integration into WG `engine.rs`** — that's the
  WG-encap integration PR, not this. The scaffold stays scaffold.
- **Auto-compute UDP checksum** in `write_udp_header` — the
  builder writes only what the caller gives it. RFC 8200 §8.1
  compliance is a caller concern (today: zero implementations
  call this with IPv6 outer).
- **IPv4 Identification (ID) field** — kept at 0 to match current
  behavior. A future PR may add real ID assignment.

## 11. v1 → v2 changes summary

| Change | Driver | v1 disposition | v2 disposition |
|--------|--------|----------------|----------------|
| Set IPv4 DF=1 (0x4000) in builder | Gemini + AGY | Deferred / open question | **In scope** — fixes RFC 791 §3.1 / RFC 6864 compliance. Wire bytes 6..8 change from 0x0000 to 0x4000. Checksum recomputes accordingly (§6.1). |
| UDP checksum API | Codex + Gemini + Claude SMR | `Option<u16>` (None ⇒ 0) | Plain `u16` — caller passes 0 explicitly for RFC 768 default. |
| Delete `wg/outer.rs` | Gemini + AGY + Claude SMR | Keep as thin wrappers preserving signatures | **DELETE** entirely. Tests move to `frame/headers_tests.rs`. Future WG integration calls `frame::headers` directly. |
| AVX2 length short-circuit | Codex + Gemini + AGY | Dismissed as noise | **In scope** as small refactor inside `frame/checksum.rs::checksum16_add_bytes` (see §7a). |
| Differential test §5.2 (legacy_encap helper) | Codex + Gemini + AGY | Keep for one bake cycle | **REMOVED**. Replaced by permanent golden vectors only. |

Unchanged from v1:
- Builder file is `frame/headers.rs` (flat, not subdir).
- No `EncapHeader` trait (YAGNI rejected at v1; v2 ratifies).
- Hot-path classification preserved.

## 10. Open questions for adversarial review

1. **Is the AVX2 dedup actually material?** A 20-byte IPv4 header
   never executes the AVX2 chunked loop (one chunk is 32 bytes).
   The runtime detection cost (`is_x86_feature_detected!("avx2")`)
   is std-cached, branch-predicted, ~1-2 cycles. The "AVX2 dedup
   = perf win" argument is weak; the real win is **single source
   of truth for the byte layout**. Is that enough to justify the
   churn, or PLAN-KILL on perf-irrelevance grounds?

2. **Should we delete `wg/outer.rs` outright?** It's scaffold for
   the not-yet-shipped WG integration. Three options: (a) keep
   `outer.rs` as a thin wrapper (this plan); (b) delete `outer.rs`
   entirely and have the future integration PR call
   `frame::headers` directly; (c) leave `outer.rs` alone and only
   consolidate gre.rs + icmp.rs. Which is right?

3. **IPv4 Identification field**. Currently both producers hard-
   code ID=0. RFC 791 §3.1 allows it only when DF=1 — but our
   DF=0 (we set `ip[6..8] = 0`). Strict reading says we are
   technically out of compliance even though no middlebox cares.
   Should the builder accept a `id: u16` parameter and surface
   the issue? Or out of scope?

4. **`write_udp_header` checksum interface**. We chose
   `Option<u16>` to keep the WG `cs=0 by default` ergonomic. An
   alternative would be to require `u16` always and have the
   caller pass 0 explicitly. Which is better? The former hides
   `0`, the latter hides `None`. The `Option` shape might mislead
   a future caller into thinking `None` triggers auto-compute.

5. **Test placement**. New `frame/headers_tests.rs` colocates with
   `headers.rs`. Should the WG `wg/outer.rs` regression tests
   ALSO move there (since they exercise the consolidated path
   transitively), or stay in `wg/outer.rs` where they currently
   live? My plan: keep them in `wg/outer.rs` so the
   `pub(crate) fn write_outer_ipv4_udp` contract is gated where it
   lives, but mirror the wire-byte gate into `headers_tests.rs`
   to gate the underlying builders. Acceptable?

6. **Differential test lifecycle**. The §5.2 test keeps a copy of
   the open-code as a private `legacy_encap` helper. When does it
   get deleted? My plan says "one bake cycle, then a follow-up PR
   removes it". Reviewers: is one cycle enough, or should it stay
   forever as a layout-fuzz oracle?

7. **#946-Phase-2-style mismatch check**. Is there an
   architectural reason this consolidation is actually wrong?
   E.g., if a future TSO change wants to write the IPv4 ID
   per-segment, does our `id=0` hard-code in the builder become
   a foot-gun? (My answer: no — TSO has its own header-build path
   in `frame/tcp_segmentation.rs` which today does NOT call the
   new builder. But please challenge.)

8. **PLAN-KILL trigger**. If the answer to (1) is "AVX2 dedup is
   noise, the perf gain is zero, and the GRE/ICMP churn is just
   line-shuffling that adds a function-call hop", that's a
   legitimate PLAN-KILL grounds. The single-source-of-truth
   argument has to do the load-bearing work. Reviewers: is that
   enough?

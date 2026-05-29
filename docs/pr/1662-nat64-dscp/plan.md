# #1662 — NAT64 must copy traffic class (DSCP+ECN) across translation

**Status:** PLAN-READY v1 — Codex PLAN-READY (task-mpraygb5-6rk1v9), AGY
PLAN-READY (adversarial-review-mpraypis-m3213h), Claude SMR PLAN-READY. One
non-blocking Codex nit adopted: `((tos & 0x0f) << 4)` mirrors frame/mod.rs:134.

## Issue framing

`userspace-dp/src/nat64.rs` zeroes the IP DSCP/ECN field in **both**
translation directions instead of copying it across the translation.
Packets traversing the NAT64 path lose all QoS marking, which is wrong
for any DiffServ-aware downstream and breaks CoS classification on the
far side. Junos NAT64 preserves the DiffServ codepoint by default.

Concrete evidence (origin/master @ da88f1ab):

- v6→v4 (`translate_v6_to_v4`): `nat64.rs:149` computes
  `_traffic_class` then discards it; `nat64.rs:174` hard-sets the IPv4
  TOS byte to `0` with a `// TODO: copy from traffic class` comment.
- v4→v6 (`translate_v4_to_v6`): `nat64.rs:259` leaves the IPv6 traffic
  class octet (low nibble of byte 0 + high nibble of byte 1) at zero;
  the IPv4 source TOS is never read.

This is a distinct, still-open gap from #1641 (NAT64 reverse-path
Ethernet-padding trim) — that fixed length/padding; this is the
traffic-class copy.

## Honest scope / value framing

This is a small, isolated, design-blessed correctness fix: two byte
manipulations plus reads, no new types, no control-flow change, no hot
path restructuring. The win is real but narrow — QoS/DiffServ marking
preservation across NAT64 (a parity gap vs Junos and vs xpf's own
DiffServ claims) and end-to-end ECN survival across the translator.
NAT64 is not the saturating fast path; this does not move iperf3
numbers. **If reviewers conclude the perf gain is too small to justify
the churn, PLAN-KILL is an acceptable verdict** — but the value here is
correctness/parity, not perf, so that bar is about churn risk, and the
churn is ~6 lines.

## Correctness contract (RFC + in-tree consistency)

**RFC 7915 (SIIT, the current revision of RFC 6145) §4 (v4→v6) and §5
(v6→v4) IP header translation:**

- **DSCP**: the 6 DiffServ bits are copied between the IPv4 TOS byte
  (bits 7:2) and the IPv6 Traffic Class field (bits 7:2 of the 8-bit
  TC). This is the default; an operator-configured DSCP mapping is the
  only thing that would diverge, and xpf has no such NAT64 DSCP-map
  config, so default = copy.
- **ECN**: RFC 7915 copies the 2-bit ECN field verbatim in both
  directions by default. (RFC 6040 governs ECN propagation across
  *encapsulating* tunnels — inner/outer header interaction — which is a
  different operation from NAT64 *translation*, where there is exactly
  one IP header in and one IP header out and no nesting.)

**Decision: full 8-bit traffic-class copy (DSCP+ECN together).** Because
the entire 8-bit field maps 1:1 between IPv4 TOS and IPv6 Traffic Class
(both are `DSCP[7:2] | ECN[1:0]`), and RFC 7915's default is "copy DSCP,
copy ECN verbatim," a straight full-byte copy is exactly the RFC 7915
default behavior with no DSCP mapping configured. This is simpler and
less error-prone than splitting DSCP-only + a separate ECN path, and it
is correct: it preserves both the DiffServ codepoint and the ECN
congestion signal end-to-end.

**Why this differs from `afxdp/wg/dscp.rs` (which clears ECN):** that
module builds a tunnel **outer** header from a 6-bit DSCP value during
WireGuard **encapsulation** — there is no inner ECN byte being copied
through at that call site, ECN propagation for that encap path is the
tracked RFC 6040 follow-up noted in `wg/dscp.rs:8`. NAT64 is translation
(1 header in → 1 header out), so the full-byte copy is the right model
and is *more* faithful than the encap path, not divergent from it. The
relevant in-tree consistency anchor is instead
`afxdp/frame/mod.rs:102-139` `apply_dscp_rewrite_to_frame`, which uses
the identical IPv6 TC extract/insert bit layout this fix will use.

## Bit layout (verified against `afxdp/frame/mod.rs:128-134`)

IPv4 TOS = `out[1]` = full 8 bits = `DSCP[7:2] | ECN[1:0]`.

IPv6 Traffic Class straddles bytes 0-1:
- extract: `tc = ((b[0] & 0x0f) << 4) | (b[1] >> 4)`
  (exactly what nat64.rs:149 already computes)
- insert : `b[0] = (b[0] & 0xf0) | (tc >> 4)`
           `b[1] = ((tc & 0x0f) << 4) | (b[1] & 0x0f)`
- Version nibble `b[0][7:4] = 6` and flow-label nibble `b[1][3:0]` must
  be preserved. The insert masks (`& 0xf0` on b[0], `& 0x0f` on b[1])
  preserve them; flow label stays 0 as today.

## Concrete design

### v6→v4 (`translate_v6_to_v4`, ~line 149 + 174)

Rename `_traffic_class` → `traffic_class` (value already correct: full
8-bit TC extracted from the IPv6 header). Then:

```rust
out[1] = traffic_class; // copy DSCP+ECN (RFC 7915 §5 default)
```

The IPv4 header checksum is computed *after* this (`out[10..12]` from
`checksum16(&out[..20])` at line ~198), so it already covers the new
TOS byte. No checksum-adjust needed. L4 checksums (TCP/UDP) do not cover
the IP TOS byte, so they are unaffected.

### v4→v6 (`translate_v4_to_v6`, ~line 258)

Read the IPv4 TOS byte from the source packet (`packet[1]`) and place it
into the IPv6 traffic-class field, preserving the version nibble:

```rust
let tos = packet[1]; // IPv4 DSCP+ECN
out[0] = 0x60 | (tos >> 4);            // version=6 + TC[7:4]
out[1] = (out[1] & 0x0f) | (tos << 4); // TC[3:0] | flow-label nibble (0)
```

`out[1]` is freshly zeroed (`vec![0u8; ...]`), so `out[1] & 0x0f == 0`;
the `& 0x0f` mask is defensive/explicit and documents that the low
nibble is the flow-label high nibble we intend to leave at 0. IPv6 has
no header checksum, so nothing else changes. L4 checksums use the IPv6
pseudo-header (addresses, length, next-header) — not the TC — so they
are unaffected.

## Public API preservation

No signature changes. `translate_v6_to_v4`, `translate_v4_to_v6`,
`build_nat64_v6_to_v4_frame`, `build_nat64_v4_to_v6_frame` all keep
identical signatures and return types. Pure value-level change inside
two function bodies.

## Hidden invariants the change must preserve

1. **IPv4 header checksum** must still verify after writing the TOS
   byte. Preserved: header checksum is computed last, over `out[..20]`,
   which includes `out[1]`.
2. **IPv6 version nibble** (`out[0][7:4] = 6`) must survive the TC
   insert. Preserved by `0x60 | (tos >> 4)` (tos>>4 is ≤ 0x0f).
3. **Flow label** stays 0. Preserved: only the high nibble of byte 1
   (TC[3:0]) is written; bytes 2-3 (rest of flow label) untouched.
4. **L4 checksums** must not be invalidated. Preserved: neither IPv4 TOS
   nor IPv6 TC participates in the TCP/UDP/ICMP pseudo-header or L4
   checksum, so the existing recompute logic is unaffected.
5. **No new allocation / no hot-path change.** Two byte writes + one
   read; no Vec growth, no branch added to a per-packet loop beyond what
   already runs.
6. **ICMP error embedded-packet translation:** out of scope — current
   code only handles ICMP echo request/reply (other ICMP types return
   `None`), so there is no embedded inner-header TOS to translate. No
   regression introduced.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Only the TOS/TC byte changes; was hard-zero, now copied. Checksums verified above. |
| Lifetime / borrow-checker | NONE | No borrows change; `out` already `&mut`; `packet` already read. |
| Performance regression | NONE | 2 writes + 1 read, no alloc, no branch in saturating path (NAT64 is slow path). |
| Architectural mismatch | NONE | Not a rearchitecture; this is the TODO the original author left at nat64.rs:174. |

## Test plan (mandatory fail-before / pass-after)

Add to `nat64_tests.rs`:

1. `translate_v6_to_v4_copies_traffic_class` — build an IPv6 TCP packet
   with TC = `(46<<2)|0b10` (DSCP EF + ECN ECT(0)), translate, assert
   `out[1] == 0xBA` exactly (`46<<2 = 0xB8`, `| 0b10 = 0xBA`), and
   assert IPv4 header checksum still verifies (`checksum16(&out[..20]) == 0`).
2. `translate_v4_to_v6_copies_traffic_class` — build an IPv4 TCP packet
   with TOS = `0xBA`, translate, assert the reconstructed TC byte
   `((out[0] & 0x0f) << 4) | (out[1] >> 4) == 0xBA`, assert
   `out[0] >> 4 == 6` (version preserved), assert flow label bytes
   (`out[1] & 0x0f`, `out[2]`, `out[3]`) are 0.
3. `nat64_traffic_class_round_trips` — v4→v6→v4 (and v6→v4→v6) of a
   marked packet preserves the exact byte both ways.
4. Reuse a non-trivial ECN value (`0b10`) so a DSCP-only implementation
   that drops ECN would fail the assertion.

**Fail-before/pass-after demonstration:** revert the two edits (restore
`out[1] = 0` and the zero TC) → the three new tests must fail; reapply →
pass. 5/5 flake on the named tests. Full `cargo test --release`.

Go suite is unaffected (Rust-only change) — will run it to confirm.

Smoke (parent runs it per the work order): NAT64 is not on the iperf3
saturating path, but per the smoke matrix the parent will run v4+v6 ×
push+reverse × CoS-off/on. This change cannot regress the best-effort or
CoS fast path (it only touches the NAT64 translation functions, which
the iperf3 path does not invoke).

## Docs

No dedicated NAT64 DSCP doc exists (`grep -rn nat64 docs/` shows only the
retired DPDK milestone list and unrelated plan docs). The behavior is
captured in code comments + this plan + the issue. No module doc update
required; will state this explicitly in the PR review notes.

## Out of scope (explicitly)

- ICMP error / embedded-packet inner-header translation (current code
  only handles echo request/reply).
- Operator-configurable NAT64 DSCP remapping (no such config exists; RFC
  default copy is correct).
- RFC 6040 ECN-on-encapsulation for the WG/GRE tunnel path (tracked
  separately at `wg/dscp.rs:8`).
- Flow-label synthesis (left 0, as today).

## Open questions for adversarial review

1. Is full-byte (DSCP+ECN) copy the right call vs DSCP-only + RFC 6040
   ECN? (Plan argues: NAT64 is translation not encap, RFC 7915 default
   is verbatim ECN copy, full-byte copy = that default.) Invite KILL if
   wrong.
2. Bit layout: is `out[1] = (out[1] & 0x0f) | (tos << 4)` correct for
   the IPv6 TC low nibble, and does `0x60 | (tos >> 4)` correctly place
   TC[7:4] without clobbering version? Cross-check against
   `frame/mod.rs:133-134`.
3. Does any checksum (IPv4 header, L4 pseudo-header) actually cover the
   TOS/TC byte such that the existing recompute order matters? (Plan
   says IPv4 header checksum covers TOS and is computed last; L4 does
   not.) Verify.
4. Could the v4→v6 `tos << 4` ever set bits in `out[1][3:0]`
   (flow-label nibble)? (`tos << 4` keeps only low nibble of tos in
   bits 7:4; bits 3:0 are 0 — verify the truncation semantics on u8.)
5. Is there any HA session-sync / conntrack state that snapshots the
   TOS/TC and would now diverge? (Believed none — translation is
   stateless w.r.t. TC.) Invite a counter-example.
6. Architectural mismatch (#961 / #946-Phase-2 pattern): is this the
   wrong target entirely? (No — it's the literal TODO at nat64.rs:174.)

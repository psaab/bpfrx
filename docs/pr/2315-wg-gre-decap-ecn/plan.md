# #2315 — WG/GRE outer→inner ECN handling at DECAP (RFC 6040 §4.2)

## Problem

PR #2307 (#2303) added the encap-side inner→outer DSCP+ECN COPY (RFC
2983 uniform DSCP + RFC 6040 normal-mode *ingress*). The `gre.rs`
`inner_tos_byte` rustdoc over-claims that "a CE mark applied by a
congested router on the OUTER path can be reflected back to the inner
endpoints at decap" — but there is **no decap-side RFC 6040 ECN combine**
implemented. Issue #2315 asks to either implement the decap-side combine
or correct the doc.

## RFC 6040 §4.2 decapsulation combine table

Resulting *inner* ECN as a function of (arriving inner, arriving outer):

| Inner ↓ \ Outer → | Not-ECT(00) | ECT(0)(10) | ECT(1)(01) | CE(11) |
|---|---|---|---|---|
| Not-ECT(00)       | Not-ECT     | Not-ECT    | Not-ECT    | **drop** |
| ECT(0)(10)        | ECT(0)      | ECT(0)     | ECT(1)     | CE     |
| ECT(1)(01)        | ECT(1)      | ECT(1)     | ECT(1)     | CE     |
| CE(11)            | CE          | CE         | CE         | CE     |

- The only mutation that ever happens: outer CE upgrades a non-CE,
  ECN-capable inner to CE (loss-free congestion signalling). Outer
  ECT(1) over inner ECT(0) → ECT(1) (the §4.2 "MAY" left as the upgrade
  variant; matches Linux). Everything else leaves the inner unchanged.
- The illegal combination outer=CE + inner=Not-ECT is **dropped**
  (a congested router CE-marked a packet whose endpoints never
  negotiated ECN — never legitimate; §4.2). We bump a counter and drop.

## Scope decision

**Hybrid.** Two decap surfaces:

1. **GRE decap** — `try_native_gre_decap_from_frame` in `gre.rs`
   operates on the FULL AF_XDP frame: the outer IP header (with outer
   ECN) is present at `meta.l3_offset`, and we build a synthetic inner
   frame we fully own. The combine is a few bit-ops on the inner TOS
   byte plus an IPv4 inner-header-checksum recompute. **Implement.**

2. **WireGuard decap** — `coordinator/wg_control.rs` `dispatch_inbound`
   reads the WG record from a plain `UdpSocket::recv_from`. The kernel
   has ALREADY stripped the outer IP header before the datagram reaches
   userspace, so the outer ECN is GONE at this layer. Recovering it
   needs `IP_RECVTOS` / `IPV6_RECVTCLASS` socket options + a switch from
   `recv_from` to `recvmsg` control-message parsing in the recv loop,
   then plumbing the outer TOS through `dispatch_inbound` → combine
   before the `tun.write_all`. That is a meaningfully larger/riskier
   recv-loop subsystem change. **Defer to a follow-up issue; correct the
   doc to scope the WG claim to encap-copy only.**

## Why GRE checksum handling is narrow

- IPv4 inner: changing the TOS byte changes the IPv4 **header**
  checksum → recompute the 20-byte (IHL-based) header checksum. The L4
  (TCP/UDP) checksum does NOT cover the IPv4 TOS byte, so it is
  untouched.
- IPv6 inner: there is NO IP header checksum, and the L4 pseudo-header
  covers src/dst/length/next-header only — NOT the Traffic Class field.
  So setting the inner CE bit needs no checksum work at all.

## Files touched

- `userspace-dp/src/afxdp/gre.rs`
  - `outer_ecn_bits(frame, meta)` — read the 2-bit outer ECN from the
    outer IP header (v4 octet 1 low 2 bits; v6 (b0<<6)&... → TC low 2).
  - `rfc6040_combine_inner_ecn(inner_ecn, outer_ecn) -> Decap6040`
    enum {Keep, SetCe, Drop} — pure table, unit-tested over all 16.
  - `apply_decap_ecn_combine(inner_packet: &mut [u8], inner_family,
    outer_ecn) -> bool` — mutate inner ECN in place + recompute IPv4
    header checksum; return false = DROP (illegal combo).
  - Wire into `try_native_gre_decap_from_frame`: compute outer ECN,
    apply to the synthetic inner before flow parse; on Drop, bump
    `gre_decap_ecn_illegal_drops` counter and return None.
  - Correct the `inner_tos_byte` rustdoc (encap is a copy; decap combine
    now exists for GRE).
- `userspace-dp/src/afxdp/wg/dscp.rs` — doc note: WG decap combine is a
  follow-up (#NNNN), socket-option blocked.
- Counter: add `gre_decap_ecn_illegal_drops` to the forwarding /
  dataplane counter surface used by gre decap.
- `userspace-dp/src/afxdp/tunnel_tests.rs` — RFC 6040 table tests +
  end-to-end GRE decap CE-propagation + illegal-drop + IPv4 checksum
  validity + fail-on-revert.
- `docs/wireguard-interop.md` — scope the ECN claim; note GRE decap
  combine landed, WG decap deferred.

## Test strategy

- `rfc6040_combine_inner_ecn` over all 16 (inner×outer) → exact table.
- `apply_decap_ecn_combine`:
  - outer CE + inner ECT(0) → inner CE, IPv4 checksum valid.
  - outer CE + inner Not-ECT → returns false (drop).
  - outer Not-ECT + inner ECT(0) → inner unchanged, checksum unchanged.
  - IPv6 inner CE set, no checksum field touched.
- End-to-end through `try_native_gre_decap_from_frame`: an outer-CE GRE
  frame with an ECT inner emerges with inner CE set and a valid inner
  IPv4 header checksum; an outer-CE + Not-ECT inner is dropped (None).
- Fail-on-revert: assert the inner CE bit is SET (the exact behavior the
  pre-fix copy-only path could never produce).

# #1885 — local-delivery TUN mis-slice: corrected analysis + fix plan

## Issue framing vs verified root cause

The issue (filed from #1881 live validation) framed the defect as
"extraction uses eth-header-length where the VLAN-tagged l3 offset was
needed" and pointed at `extract_l3_packet_with_nat`
(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`).

**That framing is wrong in a load-bearing way.** The extraction helper
is meta-driven and correct: `extract_l3_packet_from_frame` slices at
`meta.l3_offset`, and the XDP shim (`userspace-xdp/src/lib.rs`,
`parse_l2`) is VLAN-aware — a tagged frame arrives with
`l3_offset = 18`, untagged with `14`. Single-tag only; QinQ is not
parsed by the shim (`parse_l2` consumes exactly one `VlanHdr`), so a
QinQ ingress pin is unreachable.

The real defect is a **frame/meta pairing bug in the caller**, in the
non-forward disposition leg of `poll_binding_process_descriptor`
(`userspace-dp/src/afxdp/poll_descriptor/mod.rs`, LocalDelivery arm):

```text
stage_native_gre_decap (poll_stages.rs)
  -> meta REBOUND to the inner meta   (l3_offset = 14, relative to the
                                       14-byte synthetic decap frame)
  -> owned_packet_frame = synthetic   (the decapped inner frame)
...
LocalDelivery arm (mod.rs:2157)
  -> maybe_reinject_slow_path(area, desc, meta, ...)
         ^^^^^^^^^^  desc still points at the ORIGINAL UMEM frame
                     (the VLAN-tagged GRE OUTER frame on reth0.80)
```

So the slice is `outer_frame[14..]` while the inner meta describes the
synthetic frame. On a VLAN-tagged underlay the outer frame's L3 is at
18, and `outer_frame[14..]` starts with the dot1q TCI tail + ethertype
(`00 50 86 dd ...` in the strace — TCI 0x0050 = VLAN 80) → the TUN
write fails `EINVAL` (IFF_NO_PI requires the IP version nibble first).

## Blast radius (verified, every path through the buggy slice)

1. **GRE-decapped LocalDelivery, tagged underlay** (the issue): every
   GRE-to-self packet produces a mis-sliced delivery →
   `write_local_tunnel_delivery:EINVAL` per packet (thread-fatal
   pre-#1887; per-packet drop + exception post-#1887).
2. **GRE-decapped LocalDelivery, untagged underlay**: `outer_frame[14..]`
   IS the outer L3 packet (starts with a valid 4/6 nibble) — the TUN
   write *succeeds* but delivers the still-encapsulated OUTER packet to
   the gr-/slow-path TUN. Silent content-wrong delivery, no exception.
3. **Non-decapped LocalDelivery (any underlay): latent DOUBLE delivery.**
   The arm's in-line `maybe_reinject_slow_path` call is fully redundant:
   the same leg unconditionally ends at a decap-aware chokepoint
   (`maybe_reinject_slow_path_from_frame(packet_frame, meta, ...)`,
   mod.rs:2778, where `packet_frame = owned_packet_frame.as_deref()
   .unwrap_or(raw_frame)`), and BOTH calls pass the
   LocalDelivery/NoRoute/MissingNeighbor/NextTableUnsupported
   disposition filter. Every first-of-flow host-bound packet is
   enqueued twice (subsequent packets bypass userspace via the BPF
   session map, which is why this stayed invisible). For the decapped
   GRE case this is also why post-#1887 the inner packet *may* still
   limp through: garbage copy EINVALs, correct copy follows.
4. **NoRoute / MissingNeighbor / NextTableUnsupported** dispositions
   reach ONLY the trailing chokepoint (no in-arm call) — already
   decap-correct. Not affected.
5. **dispatch/mod.rs fabric fallback + handle_forward_build_failure**:
   pair `Owned` frames with their meta correctly. Not affected.
6. **SAME-CLASS DEFECT, out of scope here (follow-up issue)**: the
   MissingNeighbor `pending_neigh` buffer stores `desc` (original outer
   frame) + post-decap `meta`; `retry_pending_neigh`
   (neighbor_dispatch.rs) later does
   `rewrite_forwarded_frame_in_place(area, pkt.desc, pkt.meta, ...)` and
   TXes — for a GRE-decapped inner packet whose (non-tunnel,
   `tunnel_endpoint_id == 0`) forward decision hits a cold inner-egress
   neighbor, the retry would rewrite/TX the OUTER frame with inner-meta
   offsets. The #1873 R-E gate only covers tunnel-MARKED (encap)
   decisions, not decap-INBOUND ones. Filed separately — the fix needs
   an owned-frame-aware admission gate, a different mechanism from this
   PR.

## Fix

Delete the in-arm `maybe_reinject_slow_path(area, desc, …)` call from
the LocalDelivery arm (keep `telemetry.dbg.local += 1` and
`recycle_now = true`). The leg's existing trailing
`maybe_reinject_slow_path_from_frame(packet_frame, meta, …)` chokepoint
becomes the SINGLE delivery point; it is decap-aware by construction
(`packet_frame` is the synthetic frame when the packet was decapped,
the raw frame otherwise, and `meta` always describes it).

One change fixes all three affected behaviors: tagged mis-slice (1),
untagged content-wrong delivery (2), and the duplicate enqueue (3).
No new hot-path cost — this is the `#[cold]` exception leg, and the
change removes work.

`extract_l3_packet*` is untouched, so the #1842 property harness over
shared extraction is unchanged by construction (noted per process; the
harness still runs in the full-suite gate).

## Tests (deterministic pins, tests.rs harness)

- `gre_to_self_vlan_tagged_local_delivery_is_inner_packet_exactly_once`
  — end-to-end through `poll_binding_process_descriptor`: VLAN-tagged
  GRE outer frame in UMEM (shim-style meta, l3_offset 18) + gr endpoint
  + inner dst = gr local address + registered tunnel delivery channel.
  Asserts the channel receives EXACTLY ONE packet, byte-identical to
  the inner L3 packet (and therefore starting with the IP version
  nibble — the #1887 TUN-write observable).
- `gre_to_self_untagged_local_delivery_is_inner_packet_exactly_once` —
  same with untagged ingress (l3_offset 14); pins blast-radius case 2
  (byte-equality rules out the outer-packet misdelivery, which a
  nibble-only check would pass).
- `unencapsulated_local_delivery_to_tunnel_address_delivers_exactly_once`
  — non-decapped frame destined to the gr-local address; pins the
  duplicate-enqueue removal (blast-radius case 3) at the same channel.
- `native_gre_decap_tagged_ingress_yields_self_consistent_frame_meta` —
  decap-level pin: tagged outer frame → synthetic frame + inner meta
  are mutually consistent (`synthetic[meta.l3_offset..] == inner`).

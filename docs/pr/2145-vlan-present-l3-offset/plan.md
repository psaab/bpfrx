# #2145 — screen/SYN-cookie L3 offset on tag-presence, not VID>0

Status: IMPLEMENTED — narrow correctness fix (point fix per issue
disposition ENGINEER-NOW; broader L2-centralization is #2150).

## Issue framing

The userspace screen stage and the SYN-cookie-ACK stage compute the
L3 offset with `if meta.ingress_vlan_id > 0 { 18 } else { 14 }`
(`userspace-dp/src/afxdp/poll_stages.rs:276` and `:377`). 802.1p
priority-tagged frames carry a *real* 802.1Q tag (TPID 0x8100, PCP
bits) but with VID 0. For such a frame the shim sets
`ingress_vlan_present = 1` and `ingress_vlan_id = 0`, so the VID-based
test picks offset 14 (untagged) and `extract_screen_info` reads the
IP header from the tag's TPID/TCI bytes instead of the real header.
Consequences: LAND / SYN-frag / flood misclassification, and the
SYN-cookie challenge skipped or computed from corrupted bytes.

The codebase already has the correct signal: `ingress_vlan_present`,
which the CoS path uses (`tx/cos_classify.rs:152/401` —
`vlan_present != 0`), and the production frame parser
`frame_l3_offset` already keys on the TPID (0x8100/0x88a8), returning
18 regardless of VID.

## Fix (narrow correctness)

1. Replace `meta.ingress_vlan_id > 0` with
   `meta.ingress_vlan_present != 0` at both offset-decision sites in
   `poll_stages.rs` (screen + SYN-cookie). These are the only two
   `vlan_id > 0` L3-offset decisions on the ingress screen path. The
   many other `vlan_id > 0` sites are egress frame builders
   (`egress.vlan_id`, `write_eth_header`, etc.) where VID 0 ==
   untagged is the correct, intended semantic — out of scope.

2. Property-strategy extension (issue's "if feasible"): decouple tag
   presence from VID in the frame builders so the
   `present=true, vid=0, pcp>0` shape is generatable:
   - `PacketSpec` gains `vlan_present: bool` and `pcp: u8`.
   - `build_valid_frame` emits the 802.1Q tag on `vlan_present` (not
     `vlan_id != 0`) and sets `ingress_vlan_present`/`ingress_pcp`.
   - new `arb_vlan_tag()` generates untagged, normal-tagged, and
     priority-tagged-VID-0 cases. The egress `arb_vlan()` keeps its
     `u16` return (egress VID-0 == untagged is correct there).

## Tests

- `poll_stages::tests::priority_tagged_vlan0_screen_stage_parses_l3_at_offset_18`
  — drives `stage_screen_check` (ip-source-route fires only if the
  IHL byte is read at offset 18) and
  `stage_screen_syn_cookie_ack_on_session_miss` (cookie ACK validates
  only if `tcp_ack` is read at offset 18), with an untagged control.
  Proven to FAIL with the fix reverted.
- `frame::prop_tests::inspect::pin_priority_tagged_vlan0_frame_parses_l3_at_offset_18`
  — frame-level pin: priority-tagged VID-0 frame → `frame_l3_offset`
  == 18, `ingress_vlan_present` == 1, flow parses through the tag.
- The existing `parse_valid_round_trip` property now also exercises
  priority-tagged VID-0 frames via `arb_vlan_tag()`.

## Out of scope

- The `afxdp/l2` model / `L2Tag` / `l3_offset_from_meta` centralization
  refactor — tracked as #2150.
- Egress / frame-build `vlan_id > 0` sites (correct as-is).

## Validation

cargo build + cargo test clean; full release suite; new tests
fail-pre-fix. Smoke (hot-path/security) deferred to the parent.

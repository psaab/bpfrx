# #6458/#6478 — fabric zone-encoded src-MAC trust validation + peer-return fast-path removal

## Problem

A zone-encoded synthetic source MAC (`02:bf:72:fe:<hi>:<lo>`) stamped on a
fabric-ingress frame picks the ingress ZONE for new-flow policy, screen
profile, syn-cookie, IKE admission, and host-inbound evaluation on the
receiving node (#6458). The receive-side decode
(`parse_zone_encoded_fabric_ingress_from_frame`) validates only fabric
ingress + magic bytes + zone-id existence, and every session-MISS consumer
prefers the override over the interface-derived zone. An L2-adjacent host on
the fabric segment computes `StableZoneID("lan")`/`("mgmt")` offline and
drives new-flow admission under an attacker-chosen zone.

`cluster_peer_return_fast_path` (#6478) additionally fast-paths forgeable
TCP SYN-ACK / ACK / ICMP echo-reply forms from fabric ingress into a
NAT-less reverse-session seed, gated only on the same forgeable stamp.

## Why not the issue's option (a) verbatim

Option (a) ("never let a zone-encoded frame drive NEW-flow policy") breaks a
load-bearing legitimate case the issue under-scopes: whenever a flow's
ingress-RG primary and egress-RG primary differ (split-RG active/active
steady state, plus every asymmetric failover window), the ingress node punts
the raw first packet to the egress RG owner and the owner admits it under
the stamped zone. Removing the override on miss makes those flows evaluate
under the fabric interface's zone (default-deny) permanently, not just for a
"failover-lag". The stamp is the only carrier of the true ingress zone on
the receiver, so any fix that keeps split-RG working must VALIDATE the
stamp, not delete it.

## Fix shape (this PR chain)

### PR1 (#6458) — validate the stamp against fabric identity + live RG state

A zone-encoded stamp is honored only when ALL of these hold:

- **V0 (existing)** ingress is a fabric link, magic bytes match, zone id
  != 0, zone id exists.
- **V1a (new)** the frame's destination MAC equals the matched fabric
  link's `local_mac` — the legitimate sender always unicasts the redirect
  to the peer's fabric MAC (`resolve_fabric_redirect_from_list` sets
  `neighbor_mac = fabric.peer_mac`; the receiver's `FabricLink.local_mac`
  is the same IPVLAN-shared MAC). Kills broadcast/multicast/off-target
  sprays and forces unicast targeting of the firewall's own fabric MAC.
- **V1b (new, RG-binding)** the claimed zone has at least one RG-bound
  member interface (new `ForwardingState.zone_to_rgs`, built from
  `ifindex_to_zone_id` x `EgressInterface.redundancy_group`) and NONE of
  its bound RGs is forwarding-active LOCALLY. A legitimate stamp means
  "this packet ingressed the PEER in this zone"; when the claimed zone's
  RG is primary on the RECEIVER the packet would have ingressed locally.
  Zones with no RG-bound members (`mgmt`/fxp0, `control`/em0+fab, empty
  zones) can never be legitimately stamped — this kills the host-inbound
  variant's mgmt stamp. Applied at stage 9 (classification), so screens,
  syn-cookie, and IKE admission consume only validated zones.
- **V2 (new, owner binding)** at every session-MISS zone-pair computation
  (flow-backed, flowless transit, flowless local-delivery, MissingNeighbor
  arm) the validated override is honored only when the resolution's owner
  RG (`owner_rg_for_resolution`) is forwarding-active locally — the peer
  punts a new flow to us only because WE own its egress RG.

Net effect:

- Single-primary cluster (normal mode): the primary rejects every stamp
  (V1b: all RGs local); the backup rejects every stamp for new-flow
  purposes (V2: no RG locally active). Both nodes fail closed.
- Split-RG active/active: exactly the stamp shapes matching the live RG
  split (claimed-zone RG remote + egress RG local) are honored — the
  legitimate punt keeps working. On a SHARED fabric segment an attacker
  can clone that shape; this is the irreducible residual of trusting L2
  frames at all, documented in `docs/fabric-cross-chassis-fwd.md` with the
  direct-attached/MACsec requirement.
- A rejected stamp degrades the frame to today's UNSTAMPED fabric-frame
  posture (fabric interface's own zone), never below it.

### PR2 (#6478) — delete the cluster-peer return fast path

Remove `cluster_peer_return_fast_path` and its call site. Session-less
fabric-ingress packets (including sync-lag return traffic) fall through to
the normal miss path: policy under the PR1-validated zone, NAT applied,
FORWARD session if permitted — the standard Junos no-syn-check
asymmetric-pickup posture (#3152) — instead of an unauthenticated NAT-less
reverse seed. The sync-race sub-window the fast path covered reverts to a
bounded drop (<= the 1 s incremental sync sweep), which the #6478 verifier
explicitly prefers over unauthenticated seeding.

## Files touched (PR1)

- `userspace-dp/src/afxdp/types/forwarding.rs` — `zone_to_rgs` field.
- `userspace-dp/src/afxdp/forwarding_build/interfaces.rs` (+mod order) —
  populate `zone_to_rgs` after `populate_egress`.
- `userspace-dp/src/afxdp/forwarding/fabric.rs` —
  `fabric_for_ingress`, `zone_encoded_fabric_stamp_valid` (V1a+V1b),
  `gate_fabric_zone_override_on_owner_rg` (V2).
- `userspace-dp/src/afxdp/frame/inspect.rs` —
  `parse_zone_encoded_fabric_ingress_from_frame` gains
  `ha_state` + `now_secs` and runs the V1 validation.
- `userspace-dp/src/afxdp/poll_stages.rs` — stage 9 threads `now_secs`.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — V2 gate at the four
  miss-path zone-pair sites.
- tests: `forwarding/tests.rs` (fixture updates + new fail-on-revert),
  `forwarding_build/tests.rs` (zone_to_rgs), poll-loop fail-on-revert in
  `tests_embedded_poll_filter.rs`-style harness.
- `docs/fabric-cross-chassis-fwd.md` — trust model + validation + residual.

## Files touched (PR2)

- `userspace-dp/src/afxdp/forwarding/fabric.rs` — delete
  `cluster_peer_return_fast_path`.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — delete the call-site
  block.
- tests: delete the fn's guard tests; add poll-loop fail-on-revert that a
  fabric-ingress session-less SYN-ACK / echo-reply installs no session and
  takes the policy path.
- `docs/fabric-cross-chassis-fwd.md` — fast-path removal note.

## Hot-path shape

Non-fabric packets: zero added cost (V1 lives behind the existing
`ingress_is_fabric` early-return). Stamped fabric-ingress packets: one
6-byte compare + one `zone_to_rgs` hash lookup + 1-2 `ha_state` BTreeMap
lookups (~15 ns). Session-miss zone-pair sites: one
`owner_rg_for_resolution` (already computed nearby) + one BTreeMap lookup,
miss path only. No allocations, no atomics, no new locks.

## Test strategy

Fail-on-revert (RED on the pre-fix code):

1. stamped frame, valid magic/zone, dst MAC != fabric local_mac -> override
   rejected.
2. claimed zone whose only RG is forwarding-active locally -> rejected.
3. claimed zone with no RG-bound members (mgmt-like) -> rejected.
4. V2: validated stamp + resolution owner RG not locally active -> zone
   pair falls back to the fabric interface zone.
5. Poll-loop: forged stamp claiming `lan` with RG2 locally active -> no
   session, no forward (pre-fix: lan->wan session install).
6. PR2: fabric-ingress session-less SYN-ACK / echo-reply -> no reverse
   seed, policy-path handling (pre-fix: `Some(seed)` + forward).

Preservation pins (GREEN before and after):

7. legit split-RG stamp (claimed-zone RG remote, dst MAC = local_mac,
   egress RG local) -> override honored; existing
   `new_flow_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect` and
   session-hit fabric redirect tests keep passing.
8. `zone_to_rgs` build contents.

## Deferred

- Prometheus/status surfacing of a "stamp rejected" counter needs proto +
  Go status plumbing; out of scope. The forged packet's eventual policy
  deny is already accounted on existing policy-deny paths.
- MACsec / cryptographic fabric-frame authentication (the only full
  closure of the shared-segment split-RG clone residual) is a design
  topic, cross-referenced with #4107 (fabric control-plane auth).

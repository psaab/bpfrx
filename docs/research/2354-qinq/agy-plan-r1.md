# AGY adversarial plan review r1 — #2354 QinQ transit

Job adversarial-review-mr0z4yi0-l3rsnp (succeeded). Plan v1 @ 903f2d2bb.
Full artifact (AGY-local): brain/6f42fcdd-.../adversarial_plan_review.md.

## Verdict: PLAN-DEFER

Gap verifications (AGY walked parse_l2, dispatch, UserspaceDpMeta, InnerVlanID,
ethernet_l3 QinQ rejection + ecn_tests, TxVlanTag From<u16>, networkd VLAN
handling, compiler_iface VLAN creation, tx/transmit write path, EgressInterface,
RewriteEthParams/InPlaceL2Rewrite, UMEM headroom): all CONFIRMED accurate.

Key open questions / findings AGY raised:
1. FIREWALL BYPASS in PR-A — staging systemd-networkd nested VLAN config in PR-A
   without the PR-B shim updates creates a state where nested-VLAN traffic
   bypasses userspace policy and routes silently through the kernel slow path.
   Reorder PR sequencing to eliminate this window. [matches Codex #5 + Claude SMR #1]
2. WILDCARD COLLISION (inner==0) — using inner=0 as outer-only wildcard creates a
   security-boundary leak where untagged / nested packets can match a parent
   single-tag interface and leak traffic into its zone. Enforce strict tag counts
   in the lookup. [matches Codex #3 precedence pin]
3. STACKED NETDEV CREATION STRATEGY — single-tag VLANs are created via netlink
   (compiler_iface.go ensureVLANSubInterface) while the plan proposes stacked
   VLANs via systemd-networkd. Unify under one layer (netlink) to prevent
   race conditions between two device-creation mechanisms.
4. HEADER REWRITE CORRUPTION — the TX serialization path
   (rewrite_prepare_eth_from_parts / InPlaceL2Rewrite, frame/mod.rs:372,397)
   assumes a max L2 length of 18 bytes. Transiting a 22-byte double-tagged frame
   shifts the payload upstream and corrupts the IP header; the classifier must be
   extended to a 22-byte target length (and UMEM headroom path checked,
   umem/mod.rs in_place_vlan_push_no_headroom_packets).

FINAL VERDICT: PLAN-DEFER.

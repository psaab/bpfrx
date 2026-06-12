# #1902 — pending_neigh buffers the un-decapped OUTER frame with the post-decap INNER meta

Sibling of #1885 (PR #1901): the same frame/meta pairing defect class,
in the MissingNeighbor retry mechanism instead of LocalDelivery.

## Defect (verified on master @ b9a976417)

`stage_native_gre_decap` (poll_descriptor entry, mod.rs:126) rebinds
`meta` to the INNER meta (`l3_offset = 14`, describing the synthetic
heap frame in `owned_packet_frame`) while `desc` keeps pointing at the
ORIGINAL UMEM frame — the GRE OUTER frame, VLAN-tagged on the live
reth0.80 underlay.

The MissingNeighbor arm (mod.rs:~2696) admits
`PendingNeighPacket { desc, meta, decision, .. }` into
`binding.pending_neigh` keyed by `(egress_ifindex, next_hop)` (#1771
§2.2). For a decap-INBOUND packet whose inner forward decision is
non-tunnel (`tunnel_endpoint_id == 0`) with a cold inner-egress
neighbor, the buffered pairing is OUTER frame + INNER meta + INNER
decision.

When the neighbor resolves, `retry_pending_neigh`
(neighbor_dispatch.rs:85) does
`rewrite_forwarded_frame_in_place(area, pkt.desc, pkt.meta, &decision, ..)`
and TXes the UMEM frame — i.e. it MAC/VLAN/NAT/TTL-rewrites the
still-encapsulated OUTER GRE packet at INNER-meta offsets (4 bytes
early on a tagged underlay; "right" offsets but wrong HEADERS on an
untagged one) and transmits it toward the inner next-hop. A corrupt
transmit, not a drop.

The #1873 R-E admission gate (`tunnel_endpoint_id == 0`) only excludes
tunnel-MARKED (encap-bound) decisions; decap-INBOUND decisions are
plain forwards and pass it.

## Which pairing does the retry need? (adjudication)

The retry path is built entirely around the UMEM frame: in-place
rewrite inside the UMEM area, `PreparedTxRequest` whose recycle is
`fill_on_slot(.., pkt.desc.addr)`, and the mirror clone reads
`area.slice(pkt.desc.addr, pkt.desc.len)`. Three candidate pairings:

1. **Inner frame + inner meta** — the packet the decision describes,
   but the synthetic decap frame is a heap `Vec`, NOT UMEM-resident.
   TXing it needs a new TX-frame acquire + copy mechanism in the retry
   path (the issue's option (b)). Structural change to a cold path for
   the benefit of ONE buffered packet per cold (hop, ifindex).
2. **Outer frame + outer meta** — self-consistent bytes, but the
   stored `decision` is the INNER forward decision (inner NAT, inner
   next-hop). Rewriting the outer header with it is equally corrupt;
   making it correct means re-running decap + the full pipeline at
   retry time. Not what the mechanism is.
3. **Copy the inner frame INTO the UMEM frame at admission** — keeps
   the retry mechanism unchanged, but mutates the UMEM frame while
   shared borrows of it (`raw_frame`) are live in the descriptor loop
   (aliasing hazard) for the same marginal benefit as (1).

None justifies the cost: the buffered packet is only ever the FIRST
packet of a flow hitting a cold neighbor, the kernel ARP/NDP probe has
already fired by the time admission runs, the leg's trailing
`maybe_reinject_slow_path_from_frame(packet_frame, meta, ..)`
chokepoint (decap-aware since #1901) still hands the correctly-paired
INNER packet to the kernel slow path for delivery, and the #1769
resolver + retransmission recover the flow. So:

**Fix = issue option (a): gate pending_neigh admission on
`owned_packet_frame.is_none()`** — a decapped packet is never buffered
for in-place retry (mirrors the #1873 R-E shape). Count refusals in a
new `pending_neigh_decap_drops` per-binding counter so the live gate
is observable.

## Change list

- `afxdp/poll_descriptor/mod.rs` — MissingNeighbor arm: admission
  requires `owned_packet_frame.is_none()`; decapped candidates count
  `pending_neigh_decap_drops` and fall through (recycle_now stays
  true; trailing slow-path chokepoint unchanged).
- `afxdp/umem/mod.rs` — `BindingLiveState::pending_neigh_decap_drops`.
- `afxdp/coordinator/status.rs` — `pending_neigh_decap_drops_total()`.
- `server/lifecycle.rs` + `server/helpers.rs` +
  `protocol/control.rs` — additive wire field
  `pending_neigh_decap_drops_total` (serde `default` for back-compat).
- `pkg/dataplane/userspace/protocol.go` — Go wire field (both-sides
  rule).
- `pkg/api/metrics_descriptors.go`, `pkg/api/metrics_userspace.go`,
  coverage test — Prometheus
  `xpf_userspace_pending_neigh_decap_drops_total`.
- `docs/userspace-dataplane-architecture.md` — pending_neigh contract
  note (frame/meta pairing invariant).

## Blast radius — every pending_neigh producer/consumer audited

Producers (`pending_neigh.insert`):
- `poll_descriptor/mod.rs:2734` — THE production site (this fix).
- `neighbor_dispatch.rs` `push_pending` — test-only seeding helper.

Consumers:
- `retry_pending_neigh` (neighbor_dispatch.rs) — rewrite+TX; the
  defect's trigger. After the fix it can only see UMEM-paired entries.
- timeout/neg-cache branch in the same sweep — recycles by `pkt.addr`;
  pairing-agnostic.
- worker stop/drain (`worker/lifecycle.rs`) + debug depth
  (`umem/debug_state.rs`, resolver depth gauge) — recycle/len only;
  pairing-agnostic.

#1771 §2.2 invariants preserved: admission still flows through the
pure `pending_neigh_admission` (keep-oldest, ≤1 frame per key, cap);
the new gate runs BEFORE admission like the seed-refusal and
tunnel-marked gates, so Buffer/DuplicateDrop/CapacityDrop semantics
and the N1 invariant tests are untouched. The decap gate cannot starve
the probe clock: the kernel probe fires before admission regardless,
and a later NON-decap packet to the same hop still buffers normally.

Defense-in-depth in `retry_pending_neigh` (like #1873 R-E's drop) was
considered and rejected: a stored entry carries no "decapped" marker
and the untagged-outer case is byte-indistinguishable from a valid
frame (`frame[14]` has a valid version nibble), so a partial detector
would be false confidence. The single production insert site + the
admission gate + the end-to-end pins below are the contract.

## Tests (deterministic pins, tests.rs)

- `txn_decapped_missing_neighbor_not_buffered_tagged` /
  `_untagged` — VLAN-tagged (l3 at 18, the #1885 parity) and untagged
  GRE-to-self outer frame whose INNER dst forwards out a plain
  interface with a cold neighbor; run through
  `poll_binding_process_descriptor`, then resolve the neighbor and run
  `retry_pending_neigh`. Asserts: nothing admitted to pending_neigh,
  `pending_neigh_decap_drops == 1`, frame recycled, and NO prepared TX
  exists after retry. Pre-fix both FAIL with the mismatch signature:
  the buffered entry retries into `pending_tx_prepared` whose bytes
  are the GRE OUTER frame rewritten at inner offsets.
- `txn_non_decap_missing_neighbor_buffers_and_retries_correctly` —
  the non-decap regression pin: a plain UMEM frame with a cold
  neighbor IS buffered (decap counter stays 0), and after resolution
  `retry_pending_neigh` produces a prepared TX whose bytes are the
  correctly rewritten ORIGINAL packet (resolved dst MAC, decision src
  MAC, IP payload byte-identical at the right offsets).

## Validation

- `cargo build --release`; FULL `cargo test --release` (awk-aggregated
  over all "test result" lines; known ledger flakes standalone-proven
  5x); `go test ./...`.
- Live (loss userspace cluster, lock protocol): the #1885 GRE lane,
  decap-then-forward variant — flush the inner-egress neighbor, drive
  inner traffic through the tunnel, prove no corrupt TX on the wire
  (tcpdump on the inner egress), `pending_neigh_decap_drops_total`
  increments, flow recovers after resolution; plus a non-decap cold
  neighbor still resolves via the buffered retry path.

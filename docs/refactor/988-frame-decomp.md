# #988 — Decompose `frame.rs` (7,646 LOC → `frame/{...}.rs`)

## Why

`userspace-dp/src/afxdp/frame.rs` is the largest file in the
crate at 7,646 LOC and 76 fns. It mixes parsing, building,
mutation, checksum arithmetic, and NAT rewriting. Per the new
"Modularity discipline" section in `docs/engineering-style.md`
(>~2,000 LOC is a smell, >~3,000 splits before adding logic),
this is the highest-priority monolith left after #984 closed.

## Cluster boundaries (proposed)

Surveyed all 76 fn declarations; natural responsibility clusters
are visible in the function-name patterns. The proposed layout:

| New file | LOC est. | Functions |
|----------|---------:|-----------|
| `frame/mod.rs` | ~50 | module declarations + re-exports |
| `frame/inspect.rs` | ~1,200 | parse / inspect: `live_frame_ports*`, `parse_session_flow*`, `extract_tcp_flags*`, `extract_tcp_window`, `frame_l3_offset`, `frame_l4_offset`, `packet_rel_l4_offset*`, `parse_flow_ports`, `parse_zone_encoded*`, `parse_packet_destination*`, `metadata_tuple_complete`, `frame_has_tcp_rst`, `decode_frame_summary`, `tcp_flags_str`, `authoritative_forward_ports`, `forward_tuple_mismatch_reason`, `try_parse_metadata` |
| `frame/build.rs` | ~1,100 | construct: `build_injected_packet`, `build_injected_ipv4`, `build_injected_ipv6`, `build_nat64_forwarded_frame`, `build_forwarded_frame*`, `segment_forwarded_tcp_frames*`, `write_eth_header*` |
| `frame/rewrite.rs` | ~700 | mutation: `rewrite_prepare_eth`, `rewrite_apply_v4`, `rewrite_apply_v6`, `rewrite_forwarded_frame_in_place`, `trim_l3_payload`, `apply_rewrite_descriptor`, `apply_dscp_rewrite_to_frame` |
| `frame/nat.rs` | ~300 | NAT helpers: `apply_nat_ipv4`, `apply_nat_ipv6`, `apply_nat_port_rewrite`, `adjust_l4_checksum_port`, `enforce_expected_ports*`, `restore_l4_tuple_from_meta` |
| `frame/checksum.rs` | ~600 | checksum arithmetic: `checksum16*`, `ipv4_words`, `ipv6_words*`, `adjust_ipv4_header_checksum`, `checksum16_ipv4`, `checksum16_ipv6`, `adjust_l4_checksum_*` (12 fns), `recompute_l4_checksum_*`, `verify_built_frame_checksums` |

Total budget: ~3,950 LOC across 6 files vs 7,646 in one. Each
file lands well under the 2,000 LOC threshold.

## Phasing

**Phase 0** — convert `frame.rs` → `frame/mod.rs` (directory
module), no body changes. Mechanical move only.

**Phase 1** — extract `frame/checksum.rs`. This is the lowest-
coupled cluster (pure arithmetic, no shared mutable state, no
circular deps). Smallest blast radius, validates the pattern.

**Phase 2** — extract `frame/inspect.rs` (parse / read-only).
No mutation, only reads frame bytes; should be straightforward.

**Phase 3** — extract `frame/nat.rs`. Depends on
`frame/checksum.rs` (NAT rewrites adjust checksums), which is
already extracted by Phase 1.

**Phase 4** — extract `frame/build.rs`. Depends on `inspect`,
`checksum`, `nat`. Larger cluster, may itself need sub-phases
(e.g., split injected vs forwarded vs NAT64 build paths if it
runs over 1,500 LOC after the move).

**Phase 5** — extract `frame/rewrite.rs`. Last; the most
intricate (in-place mutation), so its tests stay close to the
moved fns.

Each phase is a single PR. Tests colocate with their
production fns per the #984 P3 pattern (`mod tests` in each new
file). Hot-path cluster smoke (per-CoS iperf3 + RG1 cycled-twice
failover, per `feedback_cos_iperf3_per_class.md`) is required
before merging Phase 1 because the checksum helpers are on the
NAT path.

## Open questions

- `try_parse_metadata` lives at line 3,187 with `MmapArea` /
  `XdpDesc` as inputs. It feels like an inspect fn but reads
  packet bytes via `MmapArea::slice` — confirm it lands in
  `inspect.rs` and not somewhere driver-specific.
- `verify_built_frame_checksums` is in checksum-territory but
  uses both build and inspect paths — Phase 4 may want to keep
  it in `build.rs` instead.

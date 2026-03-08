## Next Feature: IPv6 Session Fast Path

Date: 2026-03-06  
Status: Phases 1-3 implemented in stacked perf PRs

## Problem

IPv6 throughput is close to IPv4, but CPU cost is materially higher.

The simplistic explanation, "IPv6 headers are bigger and the hash key is bigger",
is directionally true but incomplete. The current hot path makes IPv6 session
handling more expensive than it needs to be.

The real steady-state cost for long-running TCP traffic is concentrated in:

1. IPv6 session-table lookup in [`xdp_zone.c`](/home/ps/git/codex-bpfrx/bpf/xdp/xdp_zone.c)
2. Larger IPv6 session keys and values in [`bpfrx_conntrack.h`](/home/ps/git/codex-bpfrx/bpf/headers/bpfrx_conntrack.h)
3. IPv6 header parsing in [`bpfrx_helpers.h`](/home/ps/git/codex-bpfrx/bpf/headers/bpfrx_helpers.h)

For established flows, policy lookups are usually not the bottleneck. The zone
stage already fast-paths established sessions and bypasses the full policy path.

## Goal

Reduce established IPv6 TCP packet cost without changing HA, NAT, or session
semantics in unsafe ways.

## Non-goals

1. No DPDK parity in phase 1.
2. No new behavior for control packets (`SYN`, `FIN`, `RST`).
3. No caching for NAT64, ALG, or predicted sessions.

## Optimization Plan

### Phase 1: Per-CPU IPv6 established-flow cache

Implemented in [`xdp_zone.c`](/home/ps/git/codex-bpfrx/bpf/xdp/xdp_zone.c).

Design:

1. Add a small per-CPU direct-mapped cache in XDP zone stage.
2. Cache only exact IPv6 TCP 5-tuples for steady-state established traffic.
3. Store the hot forwarding metadata needed to skip the `sessions_v6` hash lookup:
   - `fwd_ifindex`
   - `egress_vlan_id`
   - `egress_zone`
   - cached MACs
   - NAT source rewrite for the current direction
   - `policy_id`
   - tail-call target (`forward` or `nat`)
4. Batch write back counters and `last_seen` to the real `sessions_v6` map:
   - every `256` packets, or
   - once per second
5. Invalidate/fallback immediately if:
   - FIB generation changed
   - RG ownership is no longer active locally
   - the backing session disappeared
   - the backing session left `ESTABLISHED`
6. Flush/invalidate the cached entry before falling back on non-cacheable TCP control packets for the same flow.

Safety constraints:

1. Only TCP packets with `ACK` set and no `SYN/FIN/RST` are cache-eligible.
2. Only `SESS_STATE_ESTABLISHED` sessions are cached.
3. `NAT64`, `ALG`, and predicted sessions are excluded.
4. Any cache ambiguity falls back to the existing session lookup path.

Tradeoff:

Counters and `last_seen` are no longer updated on every established IPv6 packet.
They are updated in bounded batches instead. That is the core performance win.

### Phase 2: Compact IPv6 session key

Implemented in [`xdp_zone.c`](/home/ps/git/codex-bpfrx/bpf/xdp/xdp_zone.c).

The established-flow cache no longer uses the full 40-byte IPv6 5-tuple as the
map key. It now uses a compact 128-bit lookup key to choose a small per-CPU
cache set, and keeps the full tuple in the cached value for verification.

Collision safety:

1. Cache lookup verifies the embedded full 5-tuple before use.
2. Any compact-key collision inside the selected set falls back to the
   authoritative `sessions_v6` map path.
3. The real session map layout, GC behavior, and HA/session-sync semantics stay
   anchored on the unchanged full `sessions_v6` key/value state.

### Phase 3: Split hot and cold IPv6 session state

Implemented in [`xdp_zone.c`](/home/ps/git/codex-bpfrx/bpf/xdp/xdp_zone.c).

This phase does not rewrite the public `sessions_v6` map format. Instead it
splits the hot established-flow lookup state into the front-side IPv6 flow
cache and leaves the colder accounting / GC / HA state in `sessions_v6`.

The hot cache now carries only the fields needed on the steady-state fast path:

1. compact lookup key + verified full tuple
2. forwarding metadata (`fwd_ifindex`, VLAN, zone, MACs)
3. current-direction source rewrite state
4. policy ID
5. batched packet/byte counters and `last_seen`

That means established IPv6 TCP cache hits no longer need to pull the full
`session_value_v6` object into the hottest path.

### Phase 4: IPv6 parser fast path

Implemented in [`parse_ipv6hdr()`](/home/ps/git/codex-bpfrx/bpf/headers/bpfrx_helpers.h).

The parser now returns immediately for the common case where the IPv6 base
header directly names the upper-layer protocol, and only falls back to the
generic extension-header walker when the packet actually contains extension
headers.

### Phase 5: Narrower IPv6 NAT rewrite path

Implemented in [`nat_rewrite_v6()`](/home/ps/git/codex-bpfrx/bpf/headers/bpfrx_nat.h).

The IPv6 NAT path now specializes work based on:

1. protocol (`TCP`, `UDP`, `ICMPv6`, other)
2. actual direction of rewrite (`SNAT`, `DNAT`, or both)

This removes repeated protocol branching and avoids touching source/destination
fields that are not changing for the current packet.

## Phase 1 Notes

Current implementation details:

1. Cache map: per-CPU array of `2048` two-way cache sets (`4096` total slots).
2. Placement: XDP zone stage, before `sessions_v6` lookup.
3. Entry lifetime: set-associative replacement with flush-before-overwrite.
4. Loader keeps the cache map FD alive via [`loader_ebpf.go`](/home/ps/git/codex-bpfrx/pkg/dataplane/loader_ebpf.go).
5. Batch threshold is `256` packets, chosen to reduce steady-state session-map pressure while keeping accounting drift bounded.
6. Cache hits with current-direction IPv6 TCP source rewrite now patch the
   packet inline and tail-call straight to `xdp_forward`, bypassing `xdp_nat`.

Why zone stage:

The zone stage already owns the established-session fast path and cached FIB
reuse. Adding the cache there avoids duplicating another lookup path in
`xdp_conntrack`.

## Risks

1. Batched `last_seen` updates slightly relax session freshness granularity.
2. Compact-key set collisions can increase fallback pressure under adversarial flow mixes.
3. XDP-only for now; DPDK remains on the old path.

## Acceptance Criteria

1. `bpfrxd` loads all eBPF programs with the cache enabled.
2. `go test ./...` remains green.
3. Long-running IPv6 TCP flows stay functionally correct.
4. `perf` on IPv6 shows lower `htab_map_hash` / `lookup_nulls_elem_raw` pressure.
5. Throughput at equal topology is not worse than baseline.

## Next Issues

1. Add observability counters for IPv6 cache hit/flush/fallback.
2. Reduce remaining IPv6 checksum-partial detection cost in `xdp_main`.

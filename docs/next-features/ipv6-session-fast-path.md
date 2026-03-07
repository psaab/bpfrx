## Next Feature: IPv6 Session Fast Path

Date: 2026-03-06  
Status: Phase 1 implemented in `perf-ipv6-flow-cache`

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
   - every `32` packets, or
   - once per second
5. Invalidate/fallback immediately if:
   - FIB generation changed
   - RG ownership is no longer active locally
   - the backing session disappeared
   - the backing session left `ESTABLISHED`

Safety constraints:

1. Only TCP packets with `ACK` set and no `SYN/FIN/RST` are cache-eligible.
2. Only `SESS_STATE_ESTABLISHED` sessions are cached.
3. `NAT64`, `ALG`, and predicted sessions are excluded.
4. Any cache ambiguity falls back to the existing session lookup path.

Tradeoff:

Counters and `last_seen` are no longer updated on every established IPv6 packet.
They are updated in bounded batches instead. That is the core performance win.

### Phase 2: Compact IPv6 session key

Current IPv6 session lookups use a 40-byte key. That is expensive to hash and
compare.

Follow-on work:

1. Evaluate a compact hashed key design for IPv6 sessions.
2. Preserve collision safety with an explicit secondary tag or cold-path verify.
3. Revisit session sync and GC implications before changing map layout.

This is higher-risk than phase 1, but likely the next largest win.

### Phase 3: Split hot and cold IPv6 session state

`session_value_v6` is large because it mixes:

1. hot forwarding fields
2. counters
3. timestamps
4. reverse key
5. NAT metadata
6. cached FIB metadata

Follow-on work:

1. Move cold/logging/GC data out of the hottest lookup value.
2. Keep the lookup-time value as small as possible.

### Phase 4: IPv6 parser fast path

Add a cheap no-extension-header fast path in [`parse_ipv6hdr()`](/home/ps/git/codex-bpfrx/bpf/headers/bpfrx_helpers.h), then fall back to the current generic extension-header walker only when needed.

## Phase 1 Notes

Current implementation details:

1. Cache map: per-CPU array, `256` slots.
2. Placement: XDP zone stage, before `sessions_v6` lookup.
3. Entry lifetime: replaced on collision, with flush-before-replace.
4. Loader keeps the cache map FD alive via [`loader_ebpf.go`](/home/ps/git/codex-bpfrx/pkg/dataplane/loader_ebpf.go).

Why zone stage:

The zone stage already owns the established-session fast path and cached FIB
reuse. Adding the cache there avoids duplicating another lookup path in
`xdp_conntrack`.

## Risks

1. Direct-mapped cache means collision eviction under many concurrent IPv6 flows.
2. Batched `last_seen` updates slightly relax session freshness granularity.
3. XDP-only for now; DPDK remains on the old path.

## Acceptance Criteria

1. `bpfrxd` loads all eBPF programs with the cache enabled.
2. `go test ./...` remains green.
3. Long-running IPv6 TCP flows stay functionally correct.
4. `perf` on IPv6 shows lower `htab_map_hash` / `lookup_nulls_elem_raw` pressure.
5. Throughput at equal topology is not worse than baseline.

## Next Issues

1. Add observability counters for IPv6 cache hit/flush/fallback.
2. Compact IPv6 session key.
3. Split hot/cold IPv6 session state.
4. Add IPv6 parser no-extension fast path.

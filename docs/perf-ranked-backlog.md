# Ranked Performance Backlog

This document is historical and primarily describes the older eBPF/XDP
performance backlog. It is not the primary plan for the current Rust AF_XDP
userspace dataplane. Use
[userspace-performance-plan.md](../docs/userspace-performance-plan.md)
for current userspace optimization work.

Date: 2026-03-07
Baseline perf snapshot: `/tmp/perf-results.md`
Current code baseline: `master` at `1cedfc7`

## Current read

Recent perf runs show the remaining IPv6 throughput gap is mostly in three areas:

1. `xdp_main_prog`
2. IPv6 session-table hash/value cost
3. `xdp_nat_prog`

The report is directionally right, but not every proposed fix is equally good:

- `xdp_screen` is already mostly bypassed for the common case, so inlining it is not a top-priority win by itself.
- The bigger remaining `xdp_main` cost is still ingress-stage metadata setup and parse work.
- Compile-time checksum deltas are not a general answer for dynamic/interface-mode NAT.

## Landed in the current PR

The current optimization slice precomputes effective ingress `screen_flags` into `iface_zone_map`.

That removes extra `zone_configs` and `screen_configs` lookups from `resolve_ingress_xdp_target()` in `xdp_main` / `xdp_cpumap`, while keeping `xdp_screen` behavior unchanged when the packet really needs screening.

This is a targeted reduction in ingress hot-path cost, not a protocol behavior change.

## Ranked backlog

### 1. Compact IPv6 session key

Issue: #168

Why it is first:
- `htab_map_hash` remains one of the largest IPv6-only penalties.
- The current IPv6 session key is 40 bytes, versus 16 bytes for IPv4.
- This cost applies across the steady-state established-flow path, not just a corner case.

Risk:
- medium/high
- collision-safe redesign required
- touches eBPF, Go dataplane tooling, and DPDK shared structures

### 2. Split hot and cold IPv6 session state

Issue: #166

Why it is second:
- the lookup penalty is not just the key size
- `session_value_v6` is also hot and large
- reducing value footprint should help cache behavior even after key compaction

Risk:
- high
- broad data-structure churn
- needs careful HA/session-sync compatibility review

### 3. Reduce remaining `xdp_main` metadata-init and parse overhead

Issue: #180

Why it is third:
- `xdp_main_prog` is still the single largest hot symbol in the recent runs
- the new `screen_flags` shortcut removes one slice of that cost, but not the whole problem
- likely wins remain in `pkt_meta` init and common-case parse setup

Risk:
- medium
- easy to regress IPv6 forwarding/NAT if this is done with unsafe parser shortcuts

### 4. Reduce IPv6 NAT rewrite cost

Issue: #179

Why it is fourth:
- `xdp_nat_prog` still shows a clear IPv6 delta
- correctness was fixed recently, but the hot path is still heavier than it needs to be
- a common-case SNAT specialization should be possible without redesigning the full NAT model

Risk:
- medium
- checksum/offload handling must be preserved

### 5. Validate cpumap only as a measured follow-up

No issue yet.

Why it is lower:
- cpumap is disabled by default
- docs and code already note that it is usually a loss on virtio-heavy VMs
- this is worth benchmarking explicitly on mlx5/native-XDP paths, but it is not a better first move than the open dataplane issues above

## Non-priorities

These should not be mistaken for top wins right now:

- inlining `xdp_screen` by itself
- chasing host/KVM tuning before the in-guest dataplane hotspots
- generic checksum “precompute everything” work that ignores dynamic NAT behavior

## Suggested execution order

1. Merge the ingress `screen_flags` fast-path PR.
2. Do #168 next if the goal is highest likely CPU win.
3. Do #166 after that if the hash/value footprint is still dominant.
4. Use #180 and #179 as the next contained XDP slices if a safer, incremental series is preferred over another table redesign.

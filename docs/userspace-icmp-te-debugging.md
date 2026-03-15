# Userspace Dataplane: ICMP Error NAT Reversal — Debugging Notes

Last updated: 2026-03-15 04:30 UTC

## Problem

`mtr` from `cluster-userspace-host` through the userspace firewall shows `???` for all intermediate hops but the final destination works:

```
HOST: cluster-userspace-host      Loss%   Snt
  1.|-- ???                       100.0
  ...
 11.|-- one.one.one.one            0.0%
```

## Root Cause

ICMP Time Exceeded (type 11) from intermediate routers arrives at the firewall's SNAT'd address (e.g. `172.16.80.8`). The userspace DP needs to:
1. Parse the embedded packet in the ICMP error
2. Find the matching forward session via NAT reverse index
3. Rewrite the outer ICMP destination from SNAT'd IP → original client IP
4. Rewrite the embedded packet's source from SNAT'd → original
5. Recompute all checksums (outer IP, outer ICMP, embedded IP)
6. Forward the rewritten ICMP error to the original client

## What's Implemented (commit `d892376`)

### NAT Reversal Logic — WORKING (unit tested)

- `EmbeddedIcmpMatch` struct returns NAT info + original client IP + forwarding resolution
- `try_embedded_icmp_nat_match()` looks up session via NAT reverse index, resolves FIB toward original client
- `build_nat_reversed_icmp_error_v4()` — rewrites outer dst + embedded src/port, recomputes all checksums
- `build_nat_reversed_icmp_error_v6()` — same for IPv6/ICMPv6
- `PendingForwardRequest.prebuilt_frame` — carries pre-built frames for direct TX
- 5 unit tests passing (IPv4 TE, port SNAT, dest unreach, IPv6 TE, no-match)

### Live TX Path — NOT WORKING

The prebuilt ICMP error frames are being created but not transmitted. Evidence:
- slot 0 (ge-0-0-1 q0): rx=93, tx=0, miss=93, slow=93 — all going to slow-path
- slot 3 (ge-0-0-2 q3): rx=4, tx=42 — WAN transmits work fine
- LAN TX is zero — the reversed ICMP errors aren't reaching the wire

### Suspected Issue: Binding Selection for Prebuilt Frames

The `enqueue_pending_forwards()` function dispatches each `PendingForwardRequest` to the correct egress binding based on `target_ifindex`. For prebuilt frames, the binding selection may fail because:

1. The `target_ifindex` in the `PendingForwardRequest` might not match any binding's ifindex
2. The prebuilt frame path in `enqueue_pending_forwards` might skip the frame entirely
3. The TX ring on the LAN binding might not be available (fill ring exhaustion)

### How to Debug Next

1. Add `eprintln!` in `enqueue_pending_forwards()` when a `prebuilt_frame.is_some()` request arrives — log the target_ifindex and whether a matching binding was found
2. Check if the `EmbeddedIcmpMatch.resolution` has the correct `egress_ifindex` and `tx_ifindex` pointing to the LAN interface
3. Verify the prebuilt frame path in `enqueue_pending_forwards` actually writes to the TX ring
4. Check if the frame is being written but the TX completion isn't happening (sendto/kick needed)

## Separate Issue: GRE Tunnel Return Traffic (10.255.192.41)

The ping to `10.255.192.41` via the GRE tunnel fails because the **outer GRE reply packets never reach the firewall's physical NIC** (ge-0-0-2). The outbound GRE requests leave fine, but zero reply packets arrive on the wire. This is a network-level issue (upstream routing) — not a BPF or userspace DP bug.

Evidence:
- `tcpdump -i ge-0-0-2 "src host 2602:ffd3:0:2::7"` → 0 packets captured
- Remote tcpdump shows replies being sent
- Outbound GRE visible on ge-0-0-2

## Current State (c5cb982)

The XDP shim now starts with `xdp_main_prog` and swaps to `xdp_userspace_prog` when `forwarding_armed` transitions to true. When armed and primary, ICMP TE from intermediate routers reaches the userspace DP but the session-miss debug log (`/tmp/icmp_te_debug.log`) is NEVER created. This means either:

1. The ICMP TE packets hit an existing session (session hit path, bypass session-miss entirely)
2. The ICMP TE packets take a different code path before reaching the session-miss block
3. The Rust child process can't write to `/tmp/` (permissions/namespace issue)

Next debugging step: add debug logging to the session HIT path to see if ICMP TE matches an established session. Also verify `/tmp/` is writable from the Rust worker threads.

Key finding: when forwarding is NOT armed (HA secondary), `xdp_main_prog` runs and the eBPF embedded ICMP handler works correctly. When forwarding IS armed, the userspace shim redirects ICMP TE to userspace where the NAT reversal doesn't work (per-worker session isolation + cross-worker shared session lookup issue).

## XDP Shim Fixes Applied

1. **GRE/ESP XDP_PASS** (`7af4829`): GRE (proto 47) and ESP (proto 50) use `cpumap_or_pass()` directly instead of `fallback_to_main()` tail-call, which was silently failing (XDP_DROP fallthrough).

2. **Removed ICMP fallback** (`13241e7`): ICMP/ICMPv6 now goes to userspace DP natively instead of falling back to eBPF.

3. **Removed mid-stream TCP fallback** (gate-fixes merge): All TCP goes to userspace, not just SYN.

4. **Tail-call issue discovered**: `fallback_to_main()` uses `USERSPACE_FALLBACK_PROGS.tail_call()` which silently fails in the aya-ebpf framework, causing XDP_DROP instead of eBPF pipeline processing. GRE/ESP now bypass this entirely with XDP_PASS.

## TC Conntrack Fix

`bpf/tc/tc_conntrack.c`: Added session creation for outer GRE/ESP tunnel-encapsulated packets (ingress_ifindex != 0 path). Previously these were passed through without session creation, preventing XDP ingress from matching the reverse entry. However, the XDP conntrack still shows 0 reverse-hit packets — this needs further investigation but is moot since GRE replies don't reach the NIC (network issue).

## ip rule Route Leaking

`pkg/dataplane/userspace/manager.go`: Added synthetic routes from `ip rule` entries to the userspace route snapshot. When `ip rule add to <prefix> lookup <table>` exists (from rib-group or next-table leaking), a `RouteSnapshot` with `NextTable` is added so the userspace FIB can cross-reference VRF tables.

## Tunnel Slow-Path Routing

`userspace-dp/src/afxdp.rs`: When FIB resolves to a tunnel interface (GRE/ip6gre/XFRM), the forwarding disposition is overridden to `MissingNeighbor` which routes through the kernel slow-path. The kernel handles GRE encapsulation; the userspace DP cannot TX directly to tunnel AF_XDP sockets.

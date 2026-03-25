# XSK Zero-Copy Rebind Test

Status: Inconclusive — cannot isolate from bpfrxd daemon.

## What we proved so far:

1. Zero-copy works on initial bind (WAN interface, ifindex 6, rx=228 in helper)
2. Zero-copy fails after link DOWN/UP (LAN interface, ifindex 5, rx=0 after failover)
3. NIC counters: rx_xsk_xdp_redirect increments but rx_xsk_packets does not
4. rx_xsk_congst_umr non-zero on affected interface (UMR congestion)
5. The issue is NOT our NAPI bootstrap (tested with 200ms delay, UMR congestion didn't recur)

## Current focus:

A standalone test with its own XDP program (not bpfrxd's XDP shim) to:
- Confirm the current libxdp FFI wrapper works at all on this NIC
- Confirm whether link DOWN/UP breaks the receive path
- Compare the userspace wrapper against the direct libbpf/libxdp C repros

The current test binary coexists with bpfrxd but the daemon's status
loop overwrites the xskmap and bindings entries, invalidating results.

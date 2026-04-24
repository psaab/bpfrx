# PR F: Infra fixes (#854, #855, #864)

Three unrelated infra bugs from `mythos.md` security audit.

## #854 — TC port-mirror broken

`tc_main` partial-memsets `meta` past offset 32, wiping
`mirror_ifindex`/`mirror_rate` before `tc_forward` reads them.
`pkt_meta_scratch` is PERCPU so cross-CPU XDP→TC handoff under
XPS/RPS is unreliable regardless.

**Fix**: `tc_forward_prog` now does its own `mirror_config` HASH
lookup keyed on `skb->ingress_ifindex`. `xdp_forward_prog` drops
the meta writes. Pre-existing Go-plumbing gap: `mirror_config` map
wasn't in `m.maps` or `MapReplacements` — fixed so
`SetMirrorConfig`/`ClearMirrorConfigs` hit the same map instance
XDP/TC read. This bug was dormant because the TC side read meta
instead of the map.

## #855 — DPDK fwd_ifindex==0 collides with port 0

`forward_packet` used `fwd_ifindex == 0` as the host-inbound
sentinel. DPDK port IDs start at 0 → transit on port 0 was
silently freed as host-inbound.

**Fix**: add `uint8_t fib_resolved` to `struct pkt_meta`
(`dpdk_worker/shared_mem.h`). `zone_lookup` sets it on FIB hit.
`forward_packet` gates BOTH host-inbound check AND MAC rewrite on
`fib_resolved`. Conntrack session restore sets `fib_resolved=1`
when cache is valid; cache writer changed to gate on
`meta->fib_resolved`; `fib_gen` store guarded to never land on 0
(which is the "no cache" sentinel on the restore side).

## #864 — Silent native-XDP fallback + stale IFACE_FLAG_NATIVE_XDP

`compiler.go` logged fallback at `slog.Info`. `loader.go::AttachXDP`
reused pinned links without checking attach mode — a boot that fell
back to generic pinned a generic-mode link; the next boot's native
attach reused it via `Update()`, and `IFACE_FLAG_NATIVE_XDP`
stayed true in `iface_zone_map` for an interface actually running
generic.

**Fix**: (a) raise fallback log to `slog.Warn` with impact
description. (b) add `xdpAttachModeMatches(ifindex, wantGeneric)`
helper that queries `LinkByIndex.Attrs().Xdp.AttachMode`
(`XDP_ATTACHED_SKB == 2` = generic). If the pinned link's mode
differs from requested, remove the pin and fall through to fresh
attach.

## Files touched

- `bpf/tc/tc_forward.c`, `bpf/xdp/xdp_forward.c` — mirror rewiring.
- `dpdk_worker/shared_mem.h` — `fib_resolved` field (replaces 2 pad bytes).
- `dpdk_worker/zone.c` — set `fib_resolved=1` on FIB hit.
- `dpdk_worker/forward.c` — gate on `fib_resolved` for both host-inbound AND MAC rewrite.
- `dpdk_worker/conntrack.c` — session restore sets `fib_resolved=1`; cache writer gates on `fib_resolved`; `fib_gen` avoids zero sentinel.
- `pkg/dataplane/compiler.go` — `slog.Warn` + impact msg.
- `pkg/dataplane/loader.go` — `xdpAttachModeMatches` helper + mode-mismatch path.
- `pkg/dataplane/loader_ebpf.go` — wire `mirror_config`/`mirror_counter` into `m.maps` + `MapReplacements`.

## Codex review

MERGE NO → address 3 HIGHs (private mirror_config map, MAC rewrite
still used `fwd_ifindex==0`, conntrack session restore didn't set
`fib_resolved`) and 1 MED (cache writer used `fwd_ifindex!=0`) →
expect MERGE YES on re-review.

Dead fields `pkt_meta.mirror_ifindex` and `pkt_meta.mirror_rate`
left in place to avoid cross-dataplane struct-layout churn
(DPDK + Rust mirror pkt_meta). Flag for later cleanup.

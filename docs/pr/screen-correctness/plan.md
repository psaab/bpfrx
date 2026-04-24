# PR D: Screen correctness (#853, #856, #860)

## Bug summaries + fixes

### #853 — TCP fragment + SCREEN_TCP_NO_FLAG false drop; SCREEN_SYN_FRAG dead code

`bpf/tc/tc_main.c` partial-memsets `tcp_flags` to 0 and skips `parse_l4hdr` for fragments. Then `tc_screen_egress.c:140-141` matches `tf == 0 → SCREEN_TCP_NO_FLAG` on every TCP fragment. Simultaneously `tc_screen_egress.c:154-156` requires `(tf & 0x02) && is_fragment`, which is mutually exclusive given tf is always 0 on fragments — dead code.

**Fix**: guard the whole TCP-flags block in `tc_screen_egress_prog` with `&& !meta->is_fragment`, mirroring the L4-parse gate in `tc_main`. Remove the unreachable `SCREEN_SYN_FRAG` check (or rewrite to actually key off something parse-able — but that's a bigger change; keep narrow: remove, since it's dead).

Actually, drop the "remove dead code" choice — keep `SCREEN_SYN_FRAG` gated the same way so the intent is preserved, but have the outer `!is_fragment` guard ensure it's only reached on non-fragments. Then it's dead-but-intentionally-unreachable, which is fine.

Actually the simpler, correct fix: for fragments, skip the entire TCP-flag block. If we want SYN_FRAG detection later it needs a different implementation (the first fragment's L4 header). File that as a follow-up.

### #856 — resolve_ingress_xdp_target skips xdp_screen for NULL scans

`bpf/headers/xpf_helpers.h::resolve_ingress_xdp_target` returns `XDP_PROG_ZONE` (skips `xdp_screen`) for non-fragment TCP packets lacking SYN/FIN/RST/URG **when** `SCREEN_LAND_ATTACK` is off and (not v4 or `SCREEN_IP_SOURCE_ROUTE` off). NULL scans (tf==0) and ACK sweeps satisfy this and bypass screen.

**Fix**: tighten the predicate. Fast-path applies only when
- `(tf & ACK) != 0` (reject tf==0)
- AND `!(screen_flags & (SCREEN_TCP_NO_FLAG | SCREEN_IP_SWEEP))`

This matches audit remediation. Preserves the optimization for established TCP ACKs without screen-relevant flags set.

### #860 — SCREEN_PING_OF_DEATH dead code

`meta->pkt_len` is `__u16` in `bpf/headers/xpf_common.h`. `pkt_len > 65535` is trivially false. Dead branch in both `xdp_screen.c:xdp_screen_prog` and `tc_screen_egress.c:tc_screen_egress_prog`.

**Fix**: narrow — widen `pkt_len` to `__u32`. Per audit, the IPv6 parser path (`meta->pkt_len = bpf_ntohs(payload_len) + 40`) can wrap a u16 for payloads > 65495, so the widening fixes a second bug for free. Verify nothing else depends on the u16 layout (callers, serializations, bpf2go bindings).

Extended check: "ping of death" classically means fragment-reassembly-size, not single-packet length. Real implementation would track aggregate reassembly size across fragments — but that's a different issue. Widen first; filed as a follow-up for the real fix.

## Files touched

- `bpf/headers/xpf_common.h` — widen `pkt_len` to `__u32`.
- `bpf/headers/xpf_helpers.h` — tighten `resolve_ingress_xdp_target`.
- `bpf/tc/tc_screen_egress.c` — guard TCP block on `!is_fragment`.
- `bpf/xdp/xdp_screen.c` — no code change for #860 (the dead check works once `pkt_len` widens, but it still never fires until a real aggregate size tracker is added; leave as-is).

Widening `pkt_len` affects any Go bpf2go-generated struct + any Rust userspace-dp mirror — audit bindings and mirror structs before committing.

## Risk

- `resolve_ingress_xdp_target` change: established TCP fast-path narrows. Any established connection where `SCREEN_TCP_NO_FLAG` or `SCREEN_IP_SWEEP` is configured now hits `xdp_screen` on every packet. Perf cost: one extra map lookup per-packet on screen-enabled zones. Measurable but non-regressive for non-screen zones.
- `pkt_len` widening: struct-size change. `pkt_meta` is per-CPU scratch so not on the hot path persistently. Need to confirm no callers rely on exact offsets (the `tc_main.c:28` partial memset assumes offset 32 for non-`src/dst_ip` fields — verify layout post-widening).
- TCP-flags block guard: no perf change (same number of branches, just an added `&& !is_fragment` gate).

## Test plan

1. BPF verifier: `make generate && make build` — all 14 programs load.
2. Unit tests: `make test`.
3. Functional:
   - **Fragment forwarding**: send fragmented TCP through the firewall with `SCREEN_TCP_NO_FLAG` enabled on the egress zone; verify packets PASS (currently: dropped).
   - **NULL scan detection**: send TCP packet flags=0x00 with `SCREEN_TCP_NO_FLAG` enabled; verify `GLOBAL_CTR_SCREEN_TCP_NO_FLAG` increments and packet is dropped (currently: silently passes screen).
   - **ACK sweep detection**: rapid ACK-only packets to distinct dsts with `SCREEN_IP_SWEEP`; verify sweep triggers.
   - **Regular forwarding**: cluster-lan-host + cluster-userspace-host → WAN ping + iperf3.
4. Performance: `iperf3 -P 16 -t 60` — compare pre/post.
5. Sustained: 10-min run.

## Scope / out of scope

- In: #853, #856, #860 narrow fixes.
- Out: proper ping-of-death reassembly-size check (follow-up issue). Proper SYN_FRAG detection keyed on first-fragment L4 (follow-up).

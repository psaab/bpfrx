# PR: #871 VLAN tag push on REJECT replies — stack-budget refactor

## Goal

Push the 802.1Q tag on the four explicit-REJECT reply builders in
`bpf/xdp/xdp_policy.c`:

- `send_tcp_rst_v4` (line 711)
- `send_tcp_rst_v6` (line 838)
- `send_icmp_unreach_v4` (line 957)
- `send_icmp_unreach_v6` (line 1068)

Without this, REJECT silently degrades to DROP on VLAN sub-interface
clients — the reply lands on the native VLAN and never reaches the
client. PR #868 fixed the SYN-cookie path; #871 covers the policy
REJECT path.

## Why a refactor is needed

The four builders sit at ~500 bytes of stack baseline (large `iphdr`,
`ipv6hdr`, `tcphdr`, `icmphdr` structs + pseudo-header + csum state).
Adding `xdp_vlan_tag_push(ctx, meta->ingress_vlan_id)` directly pushes
combined-stack past the 512-byte verifier limit (verified during
PR #868).

## Approach — option 4: post-build push at caller

(Codex round-1 review killed pre-push: the builders write IP/L4 at
`data + sizeof(struct ethhdr)` — a FIXED offset — not at
`meta->l3_offset`. A pre-pushed VLAN tag would land at offset 14 and
the builder's IP header write would clobber it.)

| # | Option | Selected? | Why not |
|---|---|---|---|
| 1 | Move builder locals to per-CPU scratch maps | No | High maintenance cost; csum rewrite invasive |
| 2 | Tail-call to a VLAN-push wrapper program | No | Adds tail-call hop; new prog slot; not needed |
| 3 | Pre-push VLAN before builder | **No (broken)** | Builder writes at fixed `sizeof(eth)` offset; pre-pushed tag overwritten |
| 4 | **Post-build push at caller** | **Yes** | Builder produces untagged frame; caller pushes tag after builder returns. Builders unchanged. Push frame is in a different call chain than builder frame, so verifier-stack budget for the new code path is just `caller + push_helper`, not `caller + builder + push_helper`. |

### Mechanism

The caller (`xdp_policy_prog`) currently does
`return send_tcp_rst_v4(ctx, meta);`. Change to:

```c
__u32 ret = send_tcp_rst_v4(ctx, meta);
if (ret == XDP_TX && meta->ingress_vlan_present) {
    if (xdp_vlan_tag_push(ctx, meta->ingress_vlan_id) < 0) {
        bump_global_counter(GLOBAL_COUNTER_VLAN_PUSH_FAIL);
        return XDP_DROP;  // adjust_head failed; can't deliver tagged reply
    }
}
return ret;
```

The builder runs unchanged, rebuilds the untagged eth+IP+L4 frame.
On its return, the caller checks `XDP_TX && vlan_present` and pushes
the tag using `xdp_vlan_tag_push` (`bpf/headers/xpf_helpers.h:125`).
The helper extends head by 4 bytes, memmoves the eth header right,
inserts the 802.1Q tag at offset 12. The frame is now properly
tagged for the egress VLAN sub-interface.

### Stack-budget reality check

Codex round-1 also flagged that the plan must validate stack budget
against actual verifier output, not by visual inspection. The four
builders are already `static __noinline` (verified at xdp_policy.c
lines 710-711, 837-838, 956-957, 1067-1068). The combined stack
budget for `xdp_policy_prog → builder` already compiles today, so
that chain is under 512B.

The new code path adds a separate call chain `xdp_policy_prog →
xdp_vlan_tag_push`. That helper is a static inline (per
`xpf_helpers.h:125`) with a small frame. The new chain stack is
caller + helper, smaller than the existing caller + builder chain —
**should NOT trip the 512B limit**.

**Validation gate**: `make generate` must compile cleanly. If it
fails with `combined stack ... too large`, the plan falls back to
option 2 (tail-call wrapper). Do not ship without verifier proof.

### All caller dispatch sites

Codex round-1 flagged that the plan named the 1875-1910 range but
missed dispatches at lines 1950 and 1952. Full audit needed. Every
`return send_tcp_rst_v*` and `return send_icmp_unreach_v*` in
xdp_policy.c gets the wrap. Likely 6 sites total — confirm by grep
during code phase.

### Push-failure counter

Per Codex round-1 push-failure-silent concern: bump a new global
counter (`GLOBAL_COUNTER_VLAN_PUSH_FAIL`) before XDP_DROP so
operators can see how often vlan-push-on-REJECT failed. Existing
counters bump pattern at xdp_policy.c:1226, :1491.

### Files touched

| File | Change |
|---|---|
| `bpf/xdp/xdp_policy.c` | Wrap each `return send_*_reject_builder(...)` with the post-call VLAN push (6 sites). REJECT builders unchanged. |
| `bpf/headers/common.h` (or wherever counter enum lives) | Add `GLOBAL_COUNTER_VLAN_PUSH_FAIL` constant. |
| `pkg/dataplane/maps.go` (or counter-name table) | Surface the counter name for operator visibility. |

### Test strategy

1. **Verifier**: `make generate` succeeds. No `combined stack ... too
   large` errors. If it fails, the plan switches to option 2.
2. **Functional**: in test VM, deploy with a policy that REJECTs TCP
   on a VLAN-tagged client. Use `tcpdump -i <vlan> tcp[tcpflags] &
   tcp-rst` on the client side to verify RST arrives with VLAN tag.
   Repeat for ICMP unreach (UDP REJECT, ping6 REJECT).
3. **Negative**: same test on non-VLAN interface — RST still works
   (no regression).
4. **Forwarding baseline**: `iperf3 -P 8 -t 30` after deploy — no
   regression (REJECT-path code shouldn't affect forwarding hot path).

### Deploy + validation

Standalone `bpfrx-fw` for VLAN REJECT verification (has a VLAN-tagged
zone setup). Cluster check optional — REJECT path is identical on
both nodes.

## Refs

Closes #871. Follows up #857 / PR #868 (SYN-cookie VLAN push).

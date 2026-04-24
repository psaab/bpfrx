# PR C: VLAN hwaccel (#851, #857)

## #851 — tc_main reads wrong VLAN on hwaccel
`tc_main_prog` read VLAN only from inline 802.1Q in `skb->data`. On
mlx5 with `NETIF_F_HW_VLAN_CTAG_TX`, the kernel strips the tag from
`skb->data` and places it in `skb->vlan_tci`. TCX egress on the
parent reads `vlan_id=0`, `iface_zone_map` returns the native-VLAN
zone — screen/filter/flood apply to the wrong zone.

**Fix**: `skb->vlan_present` is the primary source; fall back to
inline parse for software-tagged frames.

## #857 — XDP_TX reply builders omit VLAN tag
`xdp_main_prog` strips the 802.1Q tag before the pipeline via
`xdp_vlan_tag_pop`. Every `XDP_TX` reply builder rebuilds an
untagged Ethernet frame. Reply lands on the native VLAN, never
reaches VLAN clients. SYN-cookie becomes self-DoS.

**Fix**: push back the tag via `xdp_vlan_tag_push(ctx, meta->ingress_vlan_id)`
when `meta->ingress_vlan_present`, at all 8 XDP_TX reply sites:
- `xdp_screen.c`: `send_syncookie_synack_v4/v6`, `validate_syncookie_v4/v6`.
- `xdp_policy.c`: `send_tcp_rst_v4/v6`, `send_icmp_unreach_v4/v6`.

Codex initial review found 4 xdp_policy sites missed; all fixed.

## Files

- `bpf/tc/tc_main.c` — hwaccel-first VLAN read.
- `bpf/xdp/xdp_screen.c` — 4 push sites.
- `bpf/xdp/xdp_policy.c` — 4 push sites (missed in first pass).

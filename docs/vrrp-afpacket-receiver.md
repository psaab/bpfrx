# VRRP AF_PACKET receiver — multicast membership

The native VRRPv3 state machine (`pkg/vrrp`) receives advertisements through a
per-instance `AF_PACKET` `SOCK_RAW` socket opened by `openAfPacketReceiver`
(`pkg/vrrp/manager.go`). This socket is used on VLAN sub-interfaces (e.g.
`reth0.50`, `reth0.80`) and in generic-XDP environments where a raw IP socket
(`IPPROTO_VRRP = 112`) does not reliably receive multicast: the AF_PACKET tap
fires before generic XDP in the kernel receive path, so it always sees the
frame.

The socket binds the **VLAN sub-interface ifindex** (`vi.iface.Index`), so it
observes de-tagged frames; the cBPF program attached to it accepts both
untagged and 802.1Q-tagged VRRP for IPv4 and IPv6 and is the precise delivery
gate.

## Membership: ALLMULTI, not PROMISC (#2870)

The receiver must put the NIC into a mode that delivers VRRP's multicast
advertisements. Historically it requested `PACKET_MR_PROMISC` (full
promiscuous mode). That delivered the adverts, but it also disabled the NIC's
hardware unicast MAC filter, so on a data-bearing RETH VLAN the NIC copied
**every** unicast frame on the segment to the host CPU (the cBPF then dropped
the non-VRRP ones). Two problems:

- **Performance**: all segment unicast/broadcast/multicast is DMA'd to the host
  and walked by the BPF filter instead of being dropped in hardware.
- **Isolation**: other tenants' unicast traffic on the shared L2 domain is
  exposed to a raw socket held by the control plane.

The receiver now requests **`PACKET_MR_ALLMULTI`** (receive-all-multicast). The
membership request is built by the testable helper `buildAfPacketMembership`.

### Why ALLMULTI is correct and non-regressive

VRRP advertisements are **always** sent to a multicast destination MAC:

| Family | Multicast IP | Ethernet destination MAC |
| ------ | ------------ | ------------------------ |
| IPv4   | 224.0.0.18   | `01:00:5e:00:00:12`      |
| IPv6   | ff02::12     | `33:33:00:00:00:12`      |

(See `vrrpGroupMACv4` / `vrrpGroupMACv6` in `manager.go`.)

ALLMULTI delivers every frame with a multicast destination MAC. Therefore every
VRRP advert frame that PROMISC delivered is also delivered under ALLMULTI — the
only frames no longer delivered are unicast frames not addressed to our own MAC,
which is exactly the leak being closed. The cBPF filter is unchanged.

Crucially, on a VLAN sub-interface both PROMISC and ALLMULTI propagate to the
physical parent device through the **same** kernel path —
`vlan_dev_change_rx_flags` calls `dev_set_promiscuity` / `dev_set_allmulti` on
the real device. So the propagation mechanism that made PROMISC work on the
mlx5 SR-IOV VFs makes ALLMULTI work identically. This makes ALLMULTI provably
non-regressive for advert reception relative to PROMISC.

### Why not specific-group `PACKET_MR_MULTICAST`

Joining only the two VRRP group MACs via `PACKET_MR_MULTICAST` (hardware
filtering to just the group instead of all multicast) is the theoretical
optimum and would be a further improvement. It is **not** used yet because it
routes through a different propagation path
(`dev_mc_add` → `dev_mc_sync` → the VF's `ndo_set_rx_mode` programming) whose
reliability on the mlx5 SR-IOV VFs under a VLAN sub-interface has not been
confirmed on the loss userspace HA cluster (`reth0.50` / `reth0.80`). A silent
multicast-filter miss there would drop adverts and cause split-brain, so the
conservative ALLMULTI membership is used. A future change may switch to
specific-group membership once it is live-validated that `PACKET_MR_MULTICAST`
delivers VRRP adverts on those VLAN sub-interfaces/VFs (and `test/failover`
still passes). The group-MAC constants are already in place for that work.

## Validation

- Unit: `TestAfPacketMembershipUsesAllmultiNotPromisc` asserts the membership is
  `PACKET_MR_ALLMULTI` (not `PACKET_MR_PROMISC`); `TestVRRPGroupMACsAreCorrect`
  pins the two group MACs. Fail-on-revert verified.
- Live: `make test-failover` on the loss userspace cluster must continue to show
  VRRP adverts arriving and zero-drop failover — a broken receiver means no
  failover. This is the gating check before merge.

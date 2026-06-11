# WireGuard interop — status and validation

Tracking doc for the #1703 WireGuard interop umbrella (interop with kernel
WireGuard, UniFi Network 10.4+, EdgeOS/EdgeRouter, UDM/UDM-Pro — all of which
run reference-compliant kernel WireGuard).

WireGuard is a fixed protocol: a byte-compliant implementation interoperates
with any other compliant implementation regardless of vendor. The work is
therefore staged by capability, not by vendor.

## Status by stage

| Stage | Scope | State |
|-------|-------|-------|
| S1 (#1709) | Wire-protocol compliance: TAI64N + handshake framing (msg type 1/2, MAC1) on build + parse, both roles | **DONE (this PR)** — validated by spec known-answer vectors + an xpf↔xpf framed-handshake regression. **NOT yet validated against an independent peer** (see "honesty note" below). |
| S2 | Dataplane activation (AF_XDP hot-path encap/decap) **+ the live kernel-WireGuard-on-a-VM interop test** | pending |
| S4 | Non-zero pre-shared key (PSK) plumbing | pending |
| S5 | Persistent-keepalive + REKEY/REJECT-AFTER timers + endpoint roaming + empty-record (keepalive/key-confirm) handling + TAI64N disk persistence | pending |
| S6 | Junos config surface (grammar + compiler + snapshot population, base64↔hex keys) | pending |
| S7 | Type-3 CookieReply + MAC2 generation/verification + IPv6 outer encap + DSCP/ECN | pending |
| S8 | HA RG WG-session migration | pending |

## What S1 delivers

S1 makes xpf's WireGuard **handshake bytes** standards-compliant:

- **TAI64N timestamp** (`userspace-dp/src/afxdp/wg/tai64n.rs`): a 12-byte
  big-endian `0x400000000000000a + unix_secs` (the `+10` is the 1970-epoch
  TAI−UTC leap offset, matching kernel WireGuard and wireguard-go) followed by
  whitened nanoseconds (`& 0xFF000000`). The clock is strictly monotonic
  in-process so xpf never DoSes its own re-handshakes with a backwards
  timestamp. Carried as the encrypted Noise payload of message 1.
- **Handshake framing** (`userspace-dp/src/afxdp/wg/handshake.rs`): the WG
  type-1 MessageInitiation (148 bytes) and type-2 MessageResponse (92 bytes)
  on-wire framing — type byte, reserved, sender/receiver index, and
  `MAC1 = keyed-BLAKE2s-128(BLAKE2s-256("mac1----" || recipient_static_pub),
  msg[0..offsetof(mac1)])`. MAC2 is emitted as zeros (cookie handling is S7)
  and skip-verified on parse.
- **Engine orchestration**
  (`userspace-dp/src/afxdp/wg/handshake_session.rs`): `create_initiation`,
  `consume_response`, and `consume_initiation_create_response` compose snow +
  the framing + the TAI64N clock into the full handshake in both roles, with a
  two-phase index reservation (reserve before send, at most one pending per
  peer) so a completed handshake's session is never blackholed by an index
  collision. Handshake construction runs on the control thread only — never
  the AF_XDP poll worker.

## Honesty note (S1/S2 boundary)

**S1 is NOT yet proven to interoperate with an independent WireGuard peer.**
Its in-tree gate is spec known-answer vectors (the WG construction hashes, the
MAC1 keyed-BLAKE2s-128 construction, the TAI64N encoding, and full byte-exact
msg1/msg2 wire images) plus an xpf-against-xpf framed-handshake round-trip.
Those pin every framing/MAC1/TAI64N byte to the canonical construction, but a
symmetric build/parse bug shared by both xpf roles would pass them. The
independent-peer proof — a live handshake against the **Linux kernel
WireGuard** module — lands in S2 alongside the dataplane/UDP wiring it shares.
Do not claim "xpf interoperates with WireGuard / UniFi" on the basis of S1
alone.

## S2 live kernel-WireGuard interop recipe (reference; built in S2)

The independent reference is the Linux kernel WireGuard module running on a
real incus **virtual machine** (never a container — containers share the host
kernel and cannot use the WG module or create `type wireguard` links). This is
byte-identical to what UniFi / EdgeOS / UDM run.

```sh
# On a Debian-13 VM peer (root; install wireguard-tools if absent):
ip link add wgref type wireguard
wg set wgref private-key <ref.priv> listen-port <P> \
   peer <xpf.pub> allowed-ips 0.0.0.0/0 endpoint <xpf_vm_ip>:<Q>
ip addr add <wg-overlay>/24 dev wgref
ip link set wgref up

# Direction A: xpf create_initiation -> UDP <peer_vm_ip>:<P>; kernel wg
#   verifies MAC1 + decrypts the TAI64N + replies type-2; xpf
#   consume_response derives the session. Assert via `wg show wgref`
#   (peer-side cross-check) and `show security wireguard` on xpf
#   (#1865 — local handshake counters are the primary oracle).
# Direction B: kernel wg initiates (persistent-keepalive 1); xpf
#   consume_initiation_create_response replies; assert `wg show` completes.
```

The peer VM attaches to the same SR-IOV LAN segment as the cluster host
(`mlx1` / VLAN 3667 on the loss userspace cluster); S2 must verify a free VF
exists before launching the peer, or reuse an existing real VM on that segment.

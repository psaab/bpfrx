# WireGuard clean-room dataplane termination — plan

Status: WIP. Tracks #1492's architectural failures and rebuilds from
origin/master without reusing code from #1492 (`cleanroom/wireguard`)
or #1433 (`feature/wireguard-support`).

## Why a clean room

The 33+ CRIT findings against PR #1492 collapse into a small set of
root causes that are architectural, not local:

1. **Hidden state machine in boringtun.** boringtun's `Tunn` queues
   handshake material internally and surfaces it via successive
   `update_timers` / `decapsulate` calls. The #1492 author filtered
   "non-data" outputs out of the encapsulate path and never drained
   the queues, so handshakes silently stalled.
2. **Cryptokey-routing security flaw.** The forwarding decision tells
   the dataplane "send to tunnel-endpoint K via peer pubkey P". #1492
   ignored P and re-derived the peer via AllowedIPs longest-prefix
   match. With overlapping AllowedIPs across peers, this routes
   plaintext to the wrong peer's session keys — a textbook WG
   cryptokey-routing misuse.
3. **Stale crypto via boringtun 0.6.0.** Pulls a vulnerable `ring`
   (RUSTSEC-2025-0010) and `curve25519-dalek` (RUSTSEC-2024-0344).
4. **Aliasing UB in the poll path.** Held `&mut [u8]` over the same
   UMEM region as a live `&[u8]`.
5. **`getrandom` on the hot path.** Per-handshake ephemerals
   generated under the worker's poll loop.
6. **`vec![]` per packet** in encap/decap.
7. **Hardcoded L2 dst/src MACs** in the outer encap.
8. **GRE-overhead MSS clamp reused for WG.** Off by 48–68 bytes.
9. **DSCP wiring confused 6-bit vs 8-bit TOS placement.**
10. **VLAN-unsafe encap** — outer L2 emitted without the binding's
    `tx_vlan_id` even when set.
11. **Bare `continue;` in drop paths** leaked ingress UMEM frames.
12. **Silent drops on enqueue-fail** with no exception counter bump.
13. **Replay-window wipes on control-plane restart.**
14. **No cookie/rate-limit reply path** when the engine is under load.

Items 1–6 are foundational. They have to be designed out before any
wiring touches the dispatch / poll fast path. Items 7–14 are
integration-level and tracked as IN/OUT scope below.

## Architecture

### Crypto: snow, not boringtun

Use [`snow`](https://crates.io/crates/snow) for Noise IK with PSK2
(`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` — see `WG_NOISE_PATTERN` in
`userspace-dp/src/afxdp/wg/mod.rs`). The PSK2 step matches WireGuard's
on-wire framing: WG always feeds an all-zero 32-byte PSK in the PSK2
position when no explicit pre-shared key is configured. The earlier
draft of this section listed `Noise_IK_25519_ChaChaPoly_BLAKE2s` (no
PSK2); that did not match the implementation and would have failed
to interoperate with kernel WireGuard / wireguard-go. snow has:

- Explicit state machine — no hidden output queues.
- Caller-driven I/O: `read_message` / `write_message` return exactly
  the bytes they produce. There is nothing to "drain".
- Audited core (snow has been independently audited and is widely
  used).
- `ring 0.17.x` is pulled in transitively via snow's resolver. (The
  earlier draft of this section claimed "no `ring` dependency on the
  default feature set"; that was wrong — `Cargo.lock` shows `ring
  0.17.14` reachable through snow.) `ring 0.17.x` is not the
  RUSTSEC-2025-0010 version that boringtun 0.6.0 dragged in via
  pre-0.17 ring; the current `ring 0.17.x` line is clean of open
  RustSec advisories as of 2026-05-24. The dalek crates also resolve
  to a non-RUSTSEC-2024-0344-vulnerable version. The vulnerability
  story from PR #1492 (root cause 3 above) is therefore addressed
  by snow's choice of vetted crypto crates, not by avoiding `ring`
  outright.

WireGuard's transport-data record format (4-byte type, 4-byte
receiver index, 8-byte counter, encrypted payload || 16-byte Poly1305
tag) is implemented directly on top of snow's transport session — it
maps 1:1 to snow's `into_transport_mode()` `StatelessTransportState`.
We do not depend on snow doing any WG framing for us.

### Engine keying

The forwarding decision is the **sole** source of truth for which
peer to encrypt to on egress. The engine exposes:

```rust
// Engine-level API as actually shipped in this PR.
pub(crate) fn try_encap(
    &self,
    peer_pubkey: &[u8; 32], // explicit; from the forwarding decision
    inner_ip: &[u8],        // inner IP packet
    out: &mut [u8],         // caller's pre-sized scratch (NOT Vec — no realloc allowed)
) -> Result<EncapOutcome, EncapError>;
```

The integration PR will thread `virtual_ifindex` through a wrapper at
the dispatch call site — the engine itself does not need it because
peer selection is by `peer_pubkey` alone. The earlier draft of this
section included `virtual_ifindex` and used `&mut Vec<u8>`; that
was the original integration-layer sketch, not the engine's contract.
The engine takes `&mut [u8]` precisely so the hot path never has the
opportunity to realloc.

The control plane delivers `peer_pubkey` via a new field on
`TunnelEndpointSnapshot` (`wg_peer_pubkey`). AllowedIPs is **only**
consulted on the decap path to gate inbound plaintext — "is this src
IP in AllowedIPs for the session's peer?" — never to choose a peer
on egress.

On ingress the engine demuxes by `receiver_index` alone, extracted
from the WG transport header (`sessions_by_local_index` in
`engine.rs`). The receiver index is chosen by the local side at
handshake time, so it identifies the session unambiguously without
depending on a tuple-match — listen-port selection happens one
layer up in the integration PR's UDP-socket dispatch.

### Pump pattern

snow has no hidden output queue. The pattern is strictly:

```
loop {
    // Hot path: try transport-mode read/write. If the session is
    // not yet in transport mode, fall to the slow path.
}
```

Handshake transitions happen entirely on the slow path:

- Initiator: build `MessageInitiation` (snow `write_message(b"", out)`),
  send on the outer UDP socket, wait for `MessageResponse`, finalize
  with `into_stateless_transport_mode`.
- Responder: receive `MessageInitiation`, `read_message`, produce
  `MessageResponse` via `write_message(b"", out)`, finalize.

There is no third state. Every transition has exactly one input
message and at most one output message. Nothing to "drain".

### Hot-path layout

- Worker holds a `WgWorkerScratch` with `encap_out: RefCell<Vec<u8>>`
  and `decap_out: RefCell<Vec<u8>>` (see `scratch.rs:17-21`), each
  sized to `MAX_FRAME` at startup. Separate per-direction buffers
  with `RefCell` interior mutability — never reallocated; the cells
  are entered exclusively per packet because each worker is
  single-threaded inside its poll loop.
- Engine peer routing (peers vec + pubkey→index map + AllowedIPs)
  lives in a single `ArcSwap<PeerTable>` (`engine.rs:258`) so the
  hot path observes the three sub-fields as one atomic snapshot
  (`peer_arc` does an `ArcSwap::load` only — no lock). Per-peer
  session state (`peer.current` / `peer.previous`) is
  `RwLock<Option<Arc<WgSession>>>` and ingress demux
  (`sessions_by_local_index`) is `RwLock<FxHashMap<u32, Arc<WgSession>>>`,
  so encap takes one `RwLock::read` on `peer.current`
  (`engine.rs:499-503`) and decap takes one `RwLock::read` on
  `sessions_by_local_index` (`engine.rs:636-642`). Both are
  uncontended in steady state (single-writer at slow-path session
  install / rotate), but they ARE RwLock reads, not lock-free. The
  earlier draft of this bullet claimed "never under a lock on the
  hot path"; that overstated the invariant — the lock-free property
  applies to the peer-table snapshot via `ArcSwap`, not to the
  per-session current/previous slots or the inbound demux map.
- Replay windows are per-session, tracked by a `ReplayState`
  (single counter + 64-bit sliding bitmap, RFC 6479) guarded by a
  `std::sync::Mutex` on the session. Encap is lock-free on the
  replay path — the owning worker is the only producer and bumps a
  separate `AtomicU64` tx counter. Decap takes the per-session
  replay mutex twice per packet: a pre-AEAD precheck
  (`definitely_out_of_window`) so a hostile flood cannot burn the
  snow ChaCha20-Poly1305 cost on counters that are already
  provably stale, and a post-AEAD `check_and_update` to commit the
  authenticated counter into the window. Contention is bounded
  because each session is demuxed onto a single worker — the mutex
  is effectively a per-session-per-worker SPSC lock with no
  cross-worker traffic. The earlier draft of this bullet described
  the lock as `parking_lot::Mutex` taken "only on the
  duplicate/out-of-window arms"; that did not match the
  implementation (`session.rs:72` — `std::sync::Mutex<ReplayState>`,
  `engine.rs:671-676` — unconditional pre-AEAD precheck-lock; and
  `engine.rs:695` onward — post-AEAD update-lock that calls
  `replay.check_and_update`).
- Ephemerals: handshakes are slow-path only — snow's `Builder`
  generates the ephemeral keypair inside `build_initiator_handshake`
  / `build_responder_handshake`, which the engine deliberately
  reserves for the control thread. The hot encap/decap paths never
  build a `HandshakeState` and never call `getrandom`. The
  originally-planned SPSC pre-generation ring is not implemented in
  this PR (and not needed while handshakes stay off the worker poll
  loop); revisit if a future profile shows handshake-driven
  getrandom contention on slow path.

### Replay window

Single-counter sliding bitmap, 64 bits, RFC 6479 algorithm. Stored
on the session as `replay: std::sync::Mutex<ReplayState>`, where
`ReplayState` carries the highest accepted counter and a 64-bit
bitmap (see `session.rs`). Encap bumps a separate `AtomicU64`
`tx_counter` field — the encap path never touches the replay
mutex. Decap takes the mutex twice per packet: an unconditional
pre-AEAD `definitely_out_of_window` precheck to skip snow's AEAD
for provably stale counters, and a post-AEAD `check_and_update`
that commits an authenticated counter into the window or returns
`ReplayDuplicate` / `ReplayOutOfWindow`. The earlier draft of
this section described the storage as
`(highest: AtomicU64, bitmap: AtomicU64)` with a CAS loop /
brief lock; the implementation is the mutex-guarded `ReplayState`
described above.

### Replay-state across restart

Out of scope for this PR. Documented: when the userspace helper
restarts, in-flight sessions are torn down by the engine init path,
and the responder will renegotiate within `REKEY_TIMEOUT`. A future
PR will persist (counter, bitmap) per session in the slow-path
control socket so we survive restart without rekey.

## Integration

Two call sites. Both are **clearly marked WIP** in this PR and
**do not** activate in production paths.

### Encap call site: tx/dispatch.rs

The tunnel-endpoint branch at `dispatch.rs:430` (`uses_native_tunnel
= tunnel_endpoint_id != 0`) is the only egress encap point. Today it
unconditionally calls `encapsulate_native_gre_frame`. The change is
small and local:

```rust
let endpoint = forwarding.tunnel_endpoints.get(&id)?;
let bytes = match endpoint.mode.as_str() {
    "wireguard" => wg_engine.try_encap(...)?,
    _ => encapsulate_native_gre_frame(...)?,
};
```

This PR does NOT make that call. It lands the engine + tests + the
protocol extension and stops there. Wiring is the next PR — gated
behind a thorough triple-review of the engine as-is.

### Decap call site: poll_descriptor.rs

WG ingress is `UDP/<listen_port>` on any RG-aware ifindex. The
decap point sits in the ingress packet classifier (poll_descriptor)
where we already strip outer L2/L3/L4 to expose payload. The same
"wire it up later" comment applies — engine builds and tests in this
PR; activation lands separately.

### Protocol extension

Add to `TunnelEndpointSnapshot` (both `userspace-dp/src/protocol.rs`
and `pkg/dataplane/userspace/protocol.go`):

- `wg_listen_port: u16` — UDP port for inbound demux.
- `wg_local_privkey_hex: String` — our static X25519 private key as
  hex (64 chars). `#[serde(skip_serializing)]` so it never lands in
  the persisted state file; the custom `Debug` impl on
  `TunnelEndpointSnapshot` redacts it.
- `wg_peer_pubkey_hex: String` — peer's static X25519 public key as
  hex. The engine uses THIS as the encap key, not AllowedIPs LPM.
- `wg_allowed_ips: Vec<String>` — allowed-IPs CIDRs.
- `wg_endpoint: String` — optional peer endpoint for initiator role.
- `wg_keepalive_secs: u16` — optional persistent keepalive.

Field names match the as-shipped types in `protocol.rs:417-450`
(`wg_local_privkey_hex` / `wg_peer_pubkey_hex` — hex strings, not
`[u8; 32]`). The runtime `TunnelEndpoint` in
`afxdp/types/forwarding.rs:129-140` is NOT extended in this PR;
the integration PR will mirror the snapshot fields onto the
runtime type alongside the dispatch/poll wiring (see the "What's
IN this PR" deferred-to-integration bullet for the explicit
boundary). The earlier draft claimed the snapshot mirrored into
`TunnelEndpoint` in this PR; that was the original integration
sketch, not the engine PR's contract.

We do NOT (yet) extend the Go control plane to populate these from
Junos config. That's a follow-up PR. For now the fields exist on
the wire and are populated only by tests.

## MSS clamp

WG-specific overhead, per draft-ietf-wireguard / the WG whitepaper:

- IPv4 outer: 20 (outer IP) + 8 (UDP) + 4 (type+reserved) + 4
  (receiver index) + 8 (counter) + 16 (Poly1305 tag) = **60 bytes**.
- IPv6 outer: 40 (outer IP) + 8 (UDP) + 4 + 4 + 8 + 16 = **80 bytes**.

WG §5.4.6 also requires the inner-IP plaintext to be zero-padded
to a 16-byte multiple before AEAD. That adds **0..15** bytes per
data record on top of the fixed transport overhead. `wg_tcp_mss`
therefore subtracts an additional 15 bytes (worst-case padding)
so that a sender advertising the clamp can never produce an outer
frame larger than the MTU, regardless of how the inner segment's
total length lands modulo 16. See `mss.rs` for the byte table.

Note: the task brief gave 68/88 by counting "WG type 4 hdr (16)"
which already includes type+reserved+receiver+counter. The numbers
agree once you don't double-count. I'm using the byte-exact
breakdown: **60 / 80** plus the **15** padding allowance.

This engine PR ships `wg_tcp_mss` as a standalone helper in
`afxdp/wg/mss.rs` (signature
`fn wg_tcp_mss(outer_family: i32, inner_family: i32, mtu: usize) -> u16`)
alongside the existing `native_gre_tcp_mss` in
`afxdp/forwarding/mod.rs:751`. The dispatch-side wiring — branching
`forwarded_tcp_may_need_segmentation` at
`afxdp/tx/dispatch.rs:1458` on `endpoint.mode` so WG endpoints
read `wg_tcp_mss` while GRE endpoints keep `native_gre_tcp_mss`
— is deferred to the integration PR (the current call site at
`dispatch.rs:1458-1459` short-circuits TCP segmentation for ANY
`tunnel_endpoint_id != 0`, so no MSS path is hit yet). No GRE
clamp is reused; the byte table lives in `mss.rs`.

## DSCP and ECN

`meta.dscp` is 6-bit right-justified. Outer TOS byte:

```rust
let outer_tos = (meta.dscp & 0x3F) << 2; // ECN bits 0 (cleared)
```

ECN propagation per RFC 6040 is a follow-up. For this PR we clear
the ECN bits and document it as a known gap with a tracking issue.

## VLAN safety

VLAN-aware outer L2 is built by `outer.rs::write_outer_eth(out,
dst_mac, src_mac, vlan_id, ethertype)` (see `outer.rs:23-45` — the
destination MAC is the second argument, source MAC the third,
matching the on-wire Ethernet header order): an 18-byte 802.1Q tagged
header when `vlan_id != 0`, otherwise the 14-byte untagged
Ethernet header. `outer_l2_len(vlan_id)` returns the matching
length so the caller can size its scratch correctly. `try_encap`
itself takes only `(peer_pubkey, inner_ip, out)` and writes the
WG transport record (header + ciphertext + Poly1305 tag) into
`out[0..]` — outer L2 / L3 / L4 are entirely the integration
caller's responsibility and use `outer.rs` to stay VLAN-safe. The
neighbor MAC is supplied by the caller (resolved by the existing
FIB/neighbor pipeline before the encap call). Engine does NOT do
its own neighbor lookup.

## Recycle discipline

Every drop path in the eventual integration must recycle the
ingress UMEM frame. This PR does not touch dispatch/poll, so there
is no recycle code here. The integration PR will follow the
existing pattern of `recycle_ingress_frame(...)` before every
`continue;` — encap is just one more arm of the existing match.

## What's IN this PR

- `userspace-dp/src/afxdp/wg/` new module:
  - `mod.rs` — public API + `WgEngine`
  - `engine.rs` — engine state, peer table, session table
  - `peer.rs` — peer state + AllowedIPs
  - `session.rs` — transport session + replay window
  - `allowed_ips.rs` — AllowedIPs lookup as a flat sorted-by-
    prefix-length-descending `Vec<Entry>` (in-tree, no extra deps).
    Linear-scan LPM; reconciled at config-commit time, not on the
    hot path, so the linear scan is fine and cache-friendly. The
    earlier draft labelled this an "LPM trie"; the implementation is
    a sorted Vec.
  - `framing.rs` — WG transport-data record encode/decode
  - `mss.rs` — WG MSS arithmetic
  - `dscp.rs` — DSCP→TOS shifting
  - `outer.rs` — outer IPv4/UDP/L2 (+VLAN) header builder
  - `scratch.rs` — preallocated worker scratch type
  - `tests.rs` — unit tests
- `userspace-dp/Cargo.toml` — adds `snow` and supporting crates.
- `userspace-dp/src/protocol.rs` — adds WG fields to
  `TunnelEndpointSnapshot`. Backward-compatible (all new fields are
  `#[serde(default)]`). The `wg_local_privkey_hex` field is
  `#[serde(skip_serializing)]` so it never lands in the persisted
  state file; a manual `Debug` impl on the snapshot redacts the
  private key.
- (Deferred to integration PR) `userspace-dp/src/afxdp/types/forwarding.rs`
  — extend the runtime `TunnelEndpoint` with WG fields. This PR
  intentionally lands the wire surface (`TunnelEndpointSnapshot`)
  without the runtime mirror; the integration PR will wire the
  reconcile path from snapshot into the runtime `TunnelEndpoint` and
  the WG hot path at the same time so the runtime type stays out of
  the dataplane until it is actually consumed. Codex final pre-merge
  finding 4 flagged the earlier plan text that claimed both landed
  here.
- (Deferred to integration PR) `userspace-dp/src/afxdp/forwarding_build.rs`
  — propagation from snapshot to the runtime `TunnelEndpoint`. Lands
  alongside the runtime type extension above, in the integration PR.
- `pkg/dataplane/userspace/protocol.go` — Go-side mirror.
- Unit tests: handshake roundtrip, encap matches snow output,
  decap recovers plaintext, replay window in-order / repeat /
  out-of-window / gap-fill, AllowedIPs LPM, MSS clamp math, VLAN
  outer L2, DSCP propagation, peer-pubkey gate (cryptokey routing).
- `userspace-dp/src/afxdp/mod.rs` — `mod wg;` declaration.

### On-wire handshake framing scope (explicit boundary)

This engine does NOT build or parse the WireGuard handshake message
on-wire framing (type-1 MessageInitiation, type-2 MessageResponse,
type-3 CookieReply, MAC1/MAC2 fields, the TAI64N timestamp slot, the
encrypted-static and encrypted-identity blocks that surround the
Noise IK sub-message). The engine only:

- Builds and consumes the snow `HandshakeState` Noise sub-message
  bytes via `read_message` / `write_message`, with the WG prologue
  mixed into the transcript hash.
- Builds and consumes the WG transport-data record on the wire (see
  `framing.rs`): 4-byte type + 4-byte reserved + 4-byte
  receiver_index + 8-byte counter + ciphertext || Poly1305 tag.

The integration PR will add a layer that wraps the engine's Noise
sub-message bytes inside the WG handshake outer framing (with MAC1
over a hash of the responder's static pubkey, MAC2 cookie-reply
under load, and TAI64N replay protection inside the identity
payload). A reader of this engine alone should not conclude the
handshake on-wire framing is "almost done" — `framing.rs` covers the
data record only.

## What's OUT (tracked as follow-ups)

- Activation in `tx/dispatch.rs` and `poll_descriptor.rs`. Engine
  exists and is tested but is not on the hot path yet.
- WG handshake outer-framing layer (MessageInitiation/MessageResponse
  outer bytes around the Noise sub-message, MAC1/MAC2, TAI64N).
  Engine ships the Noise sub-message bytes only; the integration
  PR will wrap them.
- Go control-plane mapping from Junos `set security ipsec ...` /
  `set interfaces st0...` to WG snapshot fields.
- HA / RG-aware session migration on failover.
- FIB/neighbor lookup hint for outer next-hop MAC (caller-supplied
  in this PR).
- RFC 7901-style cookie / rate-limit DoS reply path.
- IPv6 outer encap (engine supports v4 outer only in this PR;
  framing is family-agnostic but `outer.rs` builds v4 headers only).
- Persistent replay window across control-plane restart.
- RFC 6040 ECN propagation (cleared today).
- Cluster smoke matrix.

## Validation in this PR

- `cargo build --release` clean.
- `cargo test --release` for new tests clean.
- `go test ./pkg/...` clean (protocol.go round-trip).
- No changes to existing tests; no changes to existing hot paths.

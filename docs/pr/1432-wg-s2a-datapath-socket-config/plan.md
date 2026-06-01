# #1432 / #1703 S2a — WireGuard datapath bring-up: engine instantiation + kernel-socket WG RX/TX (ESP precedent) + egress encap call site + runtime TunnelEndpoint hydration + Go DTO population + minimal config

Status: **PLAN-READY v3-final — round-3 adversarial review CONVERGED.** Round 3:
AGY (`adversarial-review-mpuh8tsf-qvo8cp`) **PLAN-READY**; Codex
(`wg-s2a-plan-r3-1780274137`) **PLAN-NEEDS-MINOR** (the single MTU fold, now
applied). Both confirmed the two r2 majors resolved. v3-final folds the round-3
items: persistent `wgN` TUN (no reload flap), `wgN` MTU cap + exact pad-aware
encap MTU guard in BOTH directions, telemetry double-count consolidation, and
the DNAT-to-WG-port known-limitation note. **Cleared to implement.** See §11c.

History: v3 (74fce808c) round-2 CONVERGED (Codex MAJOR → shim `is_local_destination`
+ TUN-vs-policy reinject; AGY MINOR); v2 (c841cdb29) round-1 CONVERGED
PLAN-NEEDS-MAJOR (RX ownership + reload, both resolved); DRAFT v1 (019e713f1).
Full per-round detail in §11 / §11b / §11c.

Issue: #1432 (re-scoped to #1703 S2). This PR is **S2a** — datapath + socket +
config bring-up. **S2b** (live kernel-WG-on-VM interop test + smoke) is #1736,
DEFERRED to a follow-up PR. Foundation: S1 (#1709, PR #1716, MERGED) +
consolidation research (`research/1432-wg-s2-consolidation`, PLAN-READY).

> If reviewers conclude the wiring is architecturally wrong (the control-thread
> UDP/handshake model is unsound, the encap/decap call-site gating regresses the
> non-WG fast path, the UMEM integration is unsafe, or the engine cannot be
> driven from the coordinator without violating the S1 control-thread-only
> invariant), **PLAN-KILL is an acceptable verdict.** This is new datapath code
> adjacent to security-critical crypto; a wrong gate is a silent black-hole or a
> hot-path regression.

---

## 1. Issue framing (in my words)

S1 made xpf's `userspace-dp` WireGuard engine **wire-compliant** but left it
**dead code** — instantiated nowhere outside tests, with `try_encap`/`try_decap`
having zero call sites, no UDP socket, and the Go control plane never populating
the `Wg*` snapshot DTO fields. S2a wires that engine into the live AF_XDP
datapath for **one tunnel**, initiator-capable, so that:

- The Go control plane compiles a `mode == "wireguard"` tunnel endpoint and
  populates the `Wg*` DTO fields (listen-port, local privkey, peer pubkey,
  allowed-ips, endpoint, keepalive).
- The Rust runtime hydrates a `TunnelEndpoint` with those fields, instantiates a
  `WgEngine` per WG endpoint, and reconciles its peer set.
- A **control-thread** UDP socket binds `wg_listen_port` and drives the S1
  handshake methods (`create_initiation` / `consume_response` /
  `consume_initiation_create_response`). **WG datagrams reach this socket via
  the kernel** — the XDP shim passes local-destination UDP (which WG-to-firewall
  is) to the kernel stack via `cpumap_or_pass`, the same path ESP/IPsec already
  rides (§3.4, §4.3). S2a adds a one-line shim early-return so WG-port UDP is
  steered to the kernel deterministically (mirroring the ESP/GRE local-delivery
  branches), then a real `UdpSocket` does both RX and TX. No hot-path decap
  stage and no worker→control channel in S2a.
- **A `wgN` TUN netdev** is the inner interface (the IPsec/GRE-local-origin
  precedent — `tunnel.rs:36 open_tun`). The kernel routes inner traffic to/from
  it; xpf does not re-implement inner routing/policy in S2a.
- **Egress encap**: inner IP packets the kernel routes to the `wgN` TUN are read
  by the control thread, encapped via `wg_engine.try_encap(...)`, and sent on the
  `UdpSocket`. Transit traffic the AF_XDP forwarding decision targets at the WG
  tunnel endpoint also encaps at `frame/mod.rs:237` (a `mode=="wireguard"`
  branch beside the GRE call) — both the transit and locally-originated egress
  sites get the mode branch, mirroring how GRE wires both.
- **Ingress decap**: WG transport records arrive on the control-thread
  `UdpSocket` (kernel-delivered via `cpumap_or_pass`, §3.4); the thread calls
  `wg_engine.try_decap(...)`, AllowedIPs-gates the inner src, and **writes the
  plaintext inner IP to the `wgN` TUN** — the kernel then routes/firewalls it
  (the same re-entry IPsec inner traffic uses via XFRM). This is **kernel/TUN
  delivery, NOT the AF_XDP policy engine** (Codex r2): xpf policy on the decapped
  inner is a later enhancement; the AllowedIPs gate is S2a's inner-src control.
  Pushing transport decap onto the AF_XDP hot path (`stage_wg_decap`, with inner
  traffic staying on the userspace policy engine) is the Option-B perf path,
  **deferred to a post-S2 follow-up** — it needs a shim steering change (WG-port
  → XSK) and the channel/gating complexity both reviewers flagged.

S2a ends at **unit-tested wiring + a fast-path no-regress smoke**. The live
kernel-WG interop proof is S2b (#1736).

## 2. Honest scope / value framing

This is not a perf change; the value is **binary feature enablement**: today
xpf cannot pass a single packet over WireGuard despite a complete, spec-validated
engine. After S2a it can encap/decap on the AF_XDP path (proven by unit tests +
self-loopback), with S2b adding the independent-peer proof. The cost is the
integration plumbing (~600–900 LOC Rust + ~150 LOC Go + config) across the
coordinator (new aux thread), the encap/decap call sites, and the snapshot
hydration. The honest risk is a **hot-path regression on the non-WG fast path**
(the encap branch must be a single cheap predicate that the GRE/plain path never
pays) and a **silent black-hole** if decap demux or the handshake reservation is
mis-wired. If reviewers judge the integration too risky to land without the live
proof, splitting further or holding for S2b co-development is acceptable — but
the engine is dead until something wires it, and the wiring is gated.

## 3. What's already shipped / proven (compose with, do not rebuild)

Verified against `origin/master` @ c9e552689 in this worktree.

### 3.1 The S1 engine (complete, control-thread handshake API)
- `WgEngine::new(WgEngineConfig)` (`engine.rs:313`), `local_public_key()`
  (`:334`), `listen_port()` (`:338`), `reconcile_peers(&[WgPeerConfig])`
  (`:360`), `install_session(...)` (`:506`).
- **Hot-path** (data-thread-safe — takes only `RwLock::read` on `peer.current`
  / `sessions_by_local_index`): `try_encap(peer_pubkey, inner_ip, out) ->
  EncapOutcome` (`:582`), `try_decap(wg_record, out) -> DecapOutcome` (`:715`).
  `try_encap` gates on `session.is_confirmed()` (responder key-confirmation),
  bound-checks `out` BEFORE any side effect, pads to 16 (WG §5.4.6), and returns
  `{len, receiver_index, counter}`. `try_decap` rejects `counter >=
  REJECT_AFTER_MESSAGES` pre-AEAD, demuxes on `receiver_index`, has a
  truncated-record guard.
- **Control-thread handshake** (`handshake_session.rs`): `create_initiation`
  (`:265`), `consume_response` (`:353`), `consume_initiation_create_response`
  (`:434`) — two-phase index reservation, at-most-one-pending-per-peer DoS
  bound, all completion under `reconcile_lock`. These are explicitly NOT
  hot-path safe (they build snow `HandshakeState`).
- `wg/mss.rs` MSS clamp (correct, unwired), `wg/dscp.rs`, `wg/allowed_ips.rs`
  LPM trie (decap inner-src gate), `wg/framing.rs` transport-record header,
  `wg/scratch.rs` `WgWorkerScratch` (`RefCell<Vec<u8>>` reusable buffers — the
  no-hot-path-alloc discipline lives here).
- `mod.rs` constants: `WG_OVERHEAD_V4/V6`, `WG_TYPE_INITIATION/RESPONSE/
  COOKIE/DATA`, `WG_MSG_INIT_LEN`/`WG_MSG_RESPONSE_LEN`.

### 3.2 The dead DTO + runtime gap (the S2a surface)
- `TunnelEndpointSnapshot` (`protocol/snapshot.rs:309`) HAS the `Wg*` fields
  (`wg_listen_port`, `wg_local_privkey_hex` [skip_serializing + redacted Debug],
  `wg_peer_pubkey_hex`, `wg_allowed_ips`, `wg_endpoint`, `wg_keepalive_secs`),
  all `#[serde(default)]` for wire-compat.
- Go `TunnelEndpointSnapshot` (`protocol.go:290-314`) HAS the matching `Wg*`
  fields with `omitempty` JSON tags. **Never populated** — `tunnels.go:73`
  builds GRE endpoints only.
- Runtime `TunnelEndpoint` (`types/forwarding.rs:156`, `#[allow(dead_code)]`):
  fields are gre-only (`mode`, `outer_family`, `source`, `destination`, `key`,
  `ttl`, `transport_table`). **No `Wg*` fields.** Built from snapshot at
  `forwarding_build/tunnels.rs:36-49` — drops the `Wg*` DTO fields on the floor.
- `snapshotHasNativeGRE` (`maps_sync.go:1500`) matches `"", "gre", "ip6gre"` —
  no `"wireguard"` case.

### 3.3 The egress encap call sites (already pin-pointed)
- `tx/dispatch/mod.rs:416` computes `uses_native_tunnel =
  tunnel_endpoint_id != 0`; the copy-path (`:606`) and the in-place-rewrite
  guard (`:443` `&& !uses_native_tunnel`) route tunneled frames to the copy
  builder.
- `frame/mod.rs:237`: `return encapsulate_native_gre_frame(&out, meta, decision,
  forwarding);` — the **primary copy-path encap site**. This is where the
  `match endpoint.mode { "wireguard" => wg encap, _ => gre }` branch goes.
- `frame/tcp_segmentation.rs:309`: TSO path GRE encap (per-segment).
- `tunnel.rs:189`: local-origination GRE encap (the aux tunnel-source thread).

### 3.4 The WG RX model — ESP/IPsec precedent (Claude-SMR finding, v2)

The XDP shim does NOT capture all WG ingress. WG-to-firewall is
**local-destination UDP** (dst = a firewall WAN address, dst_port =
`wg_listen_port`), and the shim passes local-destination traffic to the KERNEL:
- `userspace-xdp/src/lib.rs:532 is_local_destination(&parsed)` →
  `:543 return Ok(cpumap_or_pass(ctrl))`; and the session-hit local-delivery
  branch (`:500-515`) does the same.
- `cpumap_or_pass` (`:1006-1016`) is **kernel delivery** ("Deliver IP packets to
  the kernel"): cpumap redirect → kernel stack, else `XDP_PASS` → kernel stack.
- **The decisive precedent**: ESP rides exactly this path —
  `:469 if parsed.protocol == PROTO_ESP { return Ok(cpumap_or_pass(ctrl)); }`
  with the comment *"ESP still relies on the kernel XFRM path... delivers to the
  kernel stack reliably"*; non-native GRE the same at `:473`. IPsec's userspace
  (strongSwan IKE on UDP/500/4500) and XFRM both work because `cpumap_or_pass`
  reaches kernel-bound sockets. **A kernel `UdpSocket` bound on `wg_listen_port`
  therefore CAN receive WG datagrams.** Both round-1 reviewers over-stated "the
  kernel socket sees nothing" — that is true only if WG were steered to XSK,
  which it is not today.

S2a follows the ESP precedent: add one early-return in the shim
(`PROTO_UDP && dst_port == wg_listen_port → cpumap_or_pass`, mirroring `:469`)
so WG-port UDP is steered to the kernel **deterministically** (independent of
session/local-address state), and the control thread's `UdpSocket` does both RX
and TX. The decap happens in the control thread (slow path), then the plaintext
inner IP is re-injected into forwarding.

The Option-B AF_XDP-hot-path decap (`stage_wg_decap` on the poll worker, steer
WG-port → XSK) is the eventual perf win but needs a shim **steering** change and
the channel/gating/flood machinery both reviewers flagged; it is **deferred to a
post-S2 perf follow-up**, gated on a measured bottleneck (the #966–#969
precedent). S2a's RX is the proven IPsec-style kernel path.

### 3.5 The coordinator aux-thread template
- `coordinator/mod.rs:339 spawn_local_tunnel_sources` spawns one
  `spawn_supervised_aux` thread per GRE endpoint, holding `forwarding`,
  `worker_commands`, an mpsc `delivery_tx`, etc. The WG control thread is a
  direct analogue: one supervised aux thread owning the `WgEngine` + `UdpSocket`,
  with an inbound-handshake channel and a TX-inject path to worker command
  queues.

## 4. Concrete design

### 4.1 Go: populate the `Wg*` DTO + recognize `mode == "wireguard"`

Minimal generic config surface (the #1703-plan "generic stanza"), NOT the full
Junos `wireguard` grammar (that is S6). The config lives under the existing
tunnel-interface path so `buildTunnelEndpointSnapshots` can emit it.

- Extend `config.TunnelConfig` (`types_interfaces.go`) with WG fields:
  `WgListenPort uint16`, `WgLocalPrivkeyHex string`, `WgPeerPubkeyHex string`,
  `WgAllowedIPs []string`, `WgEndpoint string`, `WgKeepaliveSecs uint16`, set
  when `Mode == "wireguard"`.
- `tunnels.go addEndpoint`: when `tunnel.Mode == "wireguard"`, copy the `Wg*`
  fields into the emitted `TunnelEndpointSnapshot`. (Source/Destination optional
  for WG — `wg_endpoint` carries the peer; gate the `Source/Destination == ""`
  early-return so a WG endpoint with only `wg_endpoint` is not dropped.)
- `snapshotHasNativeGRE` stays GRE-only; add a parallel `snapshotHasWireGuard`
  if the maps_sync path needs to know (likely not for S2a — the Rust side keys
  off `mode`).
- **Go creates the persistent `wgN` netdev** (networkd or `ip tuntap add ... mode
  tun` with persist) BEFORE the Rust thread attaches, sets its MTU to
  `outer_mtu - WG_OVERHEAD - 15`, assigns the inner address, and installs the
  inner route via it (FRR/networkd) — so a reload does not flap the netdev
  (AGY r3 Hazard B) and the kernel has a route to write decapped inner onto.
- **Config grammar**: minimal — reuse the existing `set interfaces <wg-if>
  tunnel mode wireguard` + new `wireguard { listen-port; private-key; peer { ...
  public-key; allowed-ips; endpoint; } }` leaves, OR (simpler for S2a) a flat
  `tunnel wireguard-*` attribute set. **Decision deferred to plan-review Q1** —
  the minimal surface that compiles to the DTO without committing to the S6
  grammar.

### 4.2 Rust: runtime TunnelEndpoint hydration + WgEngine instantiation

- Add `Wg*` fields to runtime `TunnelEndpoint` (`types/forwarding.rs:156`):
  `wg_listen_port: u16`, `wg_local_privkey: [u8;32]` (decoded from hex; zeroed +
  redacted Debug), `wg_peer_pubkey: [u8;32]`, `wg_allowed_ips: Vec<IpNet>`,
  `wg_endpoint: Option<SocketAddr>`, `wg_keepalive_secs: u16`. Populate in
  `forwarding_build/tunnels.rs` when `endpoint.mode == "wireguard"` (hex-decode
  with validation; skip endpoint on bad key length).
- `ForwardingState` gains `wg_engines: FastMap<u16, Arc<WgEngine>>` keyed by
  tunnel_endpoint_id, plus a `has_wg_tunnels: bool` (§4.5).
- **Engine reload stability — RESOLVED (v2, both reviewers' blocker #2).** A
  fresh `WgEngine` per reload resets the TAI64N clock to a new instance
  (`engine.rs:319` constructs a new `Tai64nClock`) and drops live sessions; a
  kernel peer rejects any TAI64N `<=` the last it accepted (`tai64n.rs:5`), so a
  fresh engine on every commit causes a re-handshake storm and can permanently
  black-hole a tunnel. Fix: `build_forwarding_state_with_policy_counters_and_previous`
  already threads `previous: Option<&ForwardingState>` (`forwarding_build/mod.rs:131`).
  For each `mode == "wireguard"` endpoint:
  - **Identity-stable reuse**: if `previous.wg_engines` holds an engine for the
    same `(id, listen_port, local_privkey, peer_pubkey, allowed_ips, endpoint,
    keepalive)` tuple, **clone the existing `Arc<WgEngine>` and do NOT call
    `reconcile_peers`** (avoids mutating shared engine state that old
    `ForwardingState` Arcs still held by workers across reload would observe —
    `worker/loop_body/mod.rs:98` holds the old Arc until `:406` refreshes it).
  - **Config-changed**: construct a fresh `WgEngine` but **seed its TAI64N
    high-water** from the previous engine via the S1 `seed_high_water` hook
    (`tai64n.rs:48` — already exists for exactly this) so monotonicity survives
    the rebuild. Then `reconcile_peers` on the fresh engine only.
  This keeps engine mutation OUT of the shared-Arc cross-reload window and
  preserves TAI64N monotonicity. (Live transport sessions are dropped on a real
  config change — acceptable: a config change re-handshakes once, seeded above
  so the peer accepts it. S5 adds session migration if needed.)

### 4.3 Rust: the WG control thread (UDP socket + handshake driver)

A new `coordinator` aux thread (one per WG endpoint, modeled on
`spawn_local_tunnel_sources`), `wg_control_loop` in a new
`coordinator/wg_control.rs`. The thread owns three handles: the `WgEngine`
(`Arc`), a `UdpSocket` (outer transport, RX+TX), and the `wgN` **TUN** (inner).
**RX model RESOLVED (v2, both reviewers' blocker #1) via the ESP precedent
(§3.4): the kernel delivers WG-port UDP to a real socket; the thread reads it
directly. No worker→control packet channel in S2a.**

- Open the `wgN` TUN (`open_tun`, `slowpath.rs:349`), non-blocking. **The `wgN`
  netdev MUST be PERSISTENT** (`TUNSETPERSIST`, or pre-created via `ip tuntap add
  dev wgN mode tun` by the Go control plane / networkd before the Rust thread
  attaches) — AGY r3 Hazard B. A transient TUN fd is deleted on close, so a
  config reload (which stops/joins aux threads, `coordinator/mod.rs:209`) would
  otherwise destroy `wgN` and its addresses + FRR routes every reload. The Go
  side creates + addresses + routes the persistent `wgN` (networkd, like other
  tunnel interfaces) so the kernel has an inner route via it.
- **`wgN` MTU** (AGY r3 Hazard A / Codex r3): the Go side sets the `wgN` MTU to
  `outer_mtu - WG_OVERHEAD - 15` (worst-case pad) — e.g. 1420 for v4-outer,
  1400 for v6-outer at a 1500 outer MTU — so the kernel never writes a
  plaintext packet that, once encapped, exceeds the outer MTU and forces outer
  IP fragmentation. The TUN-read encap path ALSO enforces an exact guard:
  `WG_DATA_HEADER_LEN + pad_to_16(inner.len()) + POLY1305_TAG_LEN + outer_l3l4
  <= outer_mtu` → else drop + `wg_mtu_drops` (symmetric with the transit-encap
  guard, §7; the existing `wg/mss.rs:48,59,92` already reserves worst-case pad
  for TCP MSS).
- Bind `UdpSocket` to `:wg_listen_port` (v4 + v6). If a host kernel WireGuard
  interface already claims the port, the bind fails `EADDRINUSE` — surface a
  clear error + counter; userspace-WG and kernel-WG on the same port are
  mutually exclusive (AGY r2). Set a read timeout; poll with a stop flag.
  Because the shim early-return (§4.5) steers WG-port **local-destination** UDP
  to `cpumap_or_pass` (kernel), this socket receives ALL inbound WG datagrams —
  handshake AND transport.
- **TUN-read egress**: inner IP packets the kernel routes onto `wgN` are read
  from the TUN, `try_encap`'d, and sent on the `UdpSocket` to the peer endpoint.
  This is the locally-originated + kernel-routed egress (mirrors the GRE
  local-origin TUN-read loop, `tunnel.rs:72-89`). The transit AF_XDP egress
  (§4.4) is the other encap site.
- **Inbound** datagram, dispatch on the WG type byte:
  - type 1 (initiation) → `engine.consume_initiation_create_response(msg, out)`
    → `socket.send_to(out, peer)` (the response). Promotes a responder session.
  - type 2 (response) → `engine.consume_response(msg)` → completes the
    initiator session.
  - type 3 (cookie) → drop + counter (S7).
  - type 4 (transport) → `engine.try_decap(record, scratch)` → AllowedIPs
    inner-src gate (`allowed_ips.rs`) → **write the plaintext inner IP to the
    `wgN` TUN** (`tun.write_all`, the same fd `tunnel.rs:56` writes
    `local_tunnel_deliveries` packets to). The kernel then routes/firewalls the
    inner packet. Decap is slow-path (control thread), NOT the AF_XDP hot path;
    inner traffic re-enters via the kernel (TUN), not the AF_XDP policy engine
    (Codex r2). The perf-relevant transit egress stays on the dataplane (§4.4).
- **Initiator bring-up**: if `wg_endpoint` is configured, on thread start (and
  on a coarse session-absent timer) call `engine.create_initiation(peer_pubkey,
  out)` + `socket.send_to(out, wg_endpoint)`. (Persistent-keepalive + REKEY
  timers are S5 — S2a does the initial handshake + re-init-if-no-session.)
- **Egress NoSession trigger**: when the TX encap path (§4.4) hits
  `EncapError::NoSession`, it signals this thread to initiate a handshake. To
  avoid a NoSession packet stream flooding the signal, the trigger is an
  **atomic rate-limiter** (a `last_init_ns` `AtomicU64` on the engine's per-peer
  state, checked with a coarse interval) — the worker does a single relaxed
  atomic compare, never builds handshake state (control-thread-only invariant
  preserved, §6). This is the ONLY worker→control coupling in S2a and it carries
  no packet data, just a debounced "please initiate" edge.

### 4.4 Rust: egress encap call sites (gated, fast-path-zero-cost)

Two encap sites get the WG mode branch in S2a: the **transit copy path**
(`frame/mod.rs:237`, for forwarded traffic) and the **TUN-read local-origin
path** (`tunnel.rs:189`'s `encapsulate_native_gre_frame` call, reached only by
the WG control thread's TUN read, §4.3). TSO is excluded (returns false for
tunnels, `tx/dispatch/mod.rs:1026`), and the GRE coordinator local-origin
spawner is GRE-only (`coordinator/mod.rs:342`) — the WG control thread is its
own TUN-read loop, so no change there. At `frame/mod.rs:237` replace the
unconditional GRE call with:

```rust
let endpoint = forwarding.tunnel_endpoints.get(&id)?;
match endpoint.mode.as_str() {
    "wireguard" => wg_encap_frame(&out, meta, decision, forwarding, endpoint),
    _ => encapsulate_native_gre_frame(&out, meta, decision, forwarding),
}
```

The non-WG path pays only the `match` on a `&str` already loaded (the endpoint
is already fetched for GRE) — **no new branch on the plain-forward fast path**,
which never enters this function (`uses_native_tunnel == false` short-circuits
at `tx/dispatch/mod.rs:443`). `wg_encap_frame` looks up
`forwarding.wg_engines.get(&id)`, calls `engine.try_encap(peer_pubkey,
inner_ip, scratch)`, and writes the UDP/WG outer via
`frame::headers::{write_eth_header_slice, write_ipv4_header, write_udp_header}`
(per the `mod.rs:46-53` note). On `EncapError::NoSession` (handshake not yet
complete) → drop the packet + a **rate-limited atomic** edge to the control
thread (§4.3, `last_init_ns` AtomicU64 — one relaxed atomic, no handshake state
on the worker) + counter. Reuses `WgWorkerScratch` — **no per-packet alloc**.

### 4.5 Rust: ingress RX gating — shim early-return, NOT a hot-path decap stage

v2 has **no `stage_wg_decap` on the poll worker** (decap is in the control
thread, §3.4/§4.3). Ingress WG is gated in two cheap places, both zero-cost for
non-WG traffic:

1. **`userspace-xdp` shim early-return** (the §3.4 ESP-precedent steering): one
   branch beside `:469 PROTO_ESP` / `:473 PROTO_GRE`. **It MUST require
   `is_local_destination` (both reviewers r2, mandatory)** — a port-only check
   would steal transit/DNAT UDP that happens to use the WG port and shunt it to
   the kernel, **bypassing the userspace policy engine** (a security/policy
   bypass if host IP-forwarding is on):
   ```rust
   if parsed.protocol == PROTO_UDP && ctrl.wg_rx
       && is_local_destination(&parsed)        // MANDATORY — not transit
       && is_wg_listen_port(&parsed) {
       return Ok(cpumap_or_pass(ctrl)); // WG → kernel → control-thread socket
   }
   ```
   `ctrl.wg_rx` is a per-CPU control flag (0 when no WG tunnel is configured →
   the branch is a single predicate the compiler folds away the body of); the
   port check reads the WG listen port from the control block. Non-WG UDP never
   pays more than the `ctrl.wg_rx` test. `is_local_destination` is the existing
   `USERSPACE_LOCAL_V4/V6` check (`lib.rs:1211`) that already gates local
   delivery (`lib.rs:532`) — reusing it keeps transit on the policy engine and
   makes WG RX deterministic regardless of session state.
2. **`has_wg_tunnels: bool` on `ForwardingState`** — any userspace path that
   would consult WG state short-circuits on this single bool when false. No
   `FastSet<u16>` probe on the per-packet UDP path (round-1 reviewers'
   minor #4): the shim handles steering; the userspace dataplane never inspects
   the WG port per packet in S2a.

### 4.6 What S2a does NOT touch
- No persistent-keepalive emit, no REKEY/REJECT-AFTER timer scheduling, no
  endpoint roaming (S5).
- No multi-engine port demux map / multiple WG interfaces (#1434/S6).
- No Junos `wireguard` grammar finalization / base64↔hex CLI (S6).
- No live VM interop (S2b/#1736).
- No PSK config (S4), no cookie/MAC2/IPv6-outer/DSCP (S7), no HA migration (S8).

## 5. Public API preservation

All S1 `pub(crate)` engine signatures unchanged
(`try_encap`/`try_decap`/`create_initiation`/`consume_response`/
`consume_initiation_create_response`/`install_session`/`reconcile_peers`/
`local_public_key`/`listen_port`). The `Wg*` DTO field names + JSON tags
unchanged (wire-compat). New code only ADDS: runtime `TunnelEndpoint` `wg_*`
fields, `ForwardingState.wg_engines` + `has_wg_tunnels`, `coordinator/
wg_control.rs`, the gated egress encap branch, and the `userspace-xdp` shim
WG-port early-return. GRE path byte-for-byte unchanged; the shim non-WG UDP
path pays only the `ctrl.wg_rx` predicate (0 when no WG configured).

## 6. Hidden invariants the change must preserve

- **Handshake crypto is control-thread only** (S1 §7). The egress encap on the
  poll worker takes only `RwLock::read` on `peer.current` — it NEVER builds a
  `HandshakeState`. The control thread owns all
  `create_initiation`/`consume_*`/`try_decap` calls. The worker→control NoSession
  signal is a single relaxed atomic carrying no packet data (§4.3).
- **No hot-path allocation** (#1207/#946). Egress encap reuses `WgWorkerScratch`;
  no `vec![]` per packet. (Decap is control-thread, off the hot path.)
- **Non-WG fast-path zero-cost** (#1183/#1545). The egress encap branch is inside
  the already-tunneled copy path (plain forward never reaches it,
  `tx/dispatch/mod.rs:443`); the ingress shim early-return pays only the
  `ctrl.wg_rx` predicate (0 when no WG configured); the userspace dataplane does
  NO per-packet WG port probe (§4.5). Smoke must show best-effort line rate
  unchanged with a WG endpoint configured.
- **Engine reload stability** (§4.2, RESOLVED) — identity-stable reuse of
  `Arc<WgEngine>` from `previous` (no `reconcile_peers` on the shared Arc); on
  config change, fresh engine seeded from the prior TAI64N high-water.
- **Cryptokey-routing**: encap keys on `wg_peer_pubkey` (forwarding decision),
  NOT AllowedIPs LPM; decap AllowedIPs-gates the inner src. S2a must not invert
  this.
- **Privkey hygiene**: `wg_local_privkey_hex` stays `skip_serializing` +
  redacted Debug end-to-end; the runtime `wg_local_privkey` must not leak via
  `{:?}` or the on-disk state snapshot.
- **TAI64N restart** (S1 §5.2): in-process only until S6; S2b runbook flushes
  the peer on xpf restart.

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (non-WG fast path) | **MED** | Egress branch lives only in the already-tunneled copy path; ingress shim early-return pays only `ctrl.wg_rx`; no per-packet WG port probe in the userspace DP (§4.5). Smoke proves CoS-off + CoS-on line rate unchanged with WG configured. PLAN-KILL if a reviewer shows a gate touches the plain-forward path. |
| Lifetime / borrow-checker | **MED** | New aux thread owns `Arc<WgEngine>` + `UdpSocket`; the encap scratch is `RefCell` (single-threaded worker). Reinject reuses the `local_tunnel_deliveries` `SyncSender<Vec<u8>>` shape. |
| Silent black-hole / mis-demux | **MED** | Decap demux on `receiver_index` is S1-tested; RX-via-kernel-socket is the ESP precedent (§3.4). Tests: encap→decap round-trip; NoSession atomic fires once per interval; shim steers WG-port to kernel. |
| Engine reload churn (TAI64N/sessions) | **LOW** | RESOLVED §4.2 — identity reuse + high-water seed. |
| Architectural mismatch (#961/#946-P2) | **LOW** | Aux-thread + egress-encap-branch + kernel-socket-RX templates all already exist (GRE local-origination, ESP/IKE). Composition, not new architecture. |
| WG RX delivery (kernel socket vs AF_XDP) | **LOW** | RESOLVED §3.4 — WG-to-firewall is local-destination UDP, passed to kernel via `cpumap_or_pass` (ESP precedent `lib.rs:469`); kernel socket receives it. Shim early-return makes it deterministic. |
| UMEM / MTU on encap (both r3) | **MED** | WG outer adds `WG_OVERHEAD_V4=60`/`V6=80` (`mod.rs:138-141`) **+ ≤15 B pad** (`pad_to_16`). `try_encap` bound-checks before side effects (`engine.rs:627-633`). BOTH encap paths (transit copy + TUN-read) enforce the exact guard `WG_DATA_HEADER_LEN + pad_to_16(inner.len()) + POLY1305_TAG_LEN + outer_l3l4 <= outer_mtu` → drop + `wg_mtu_drops` (no userspace reassembly, no descriptor overflow). The Go side caps `wgN` MTU at `outer_mtu - WG_OVERHEAD - 15` so the kernel never hands oversized inner that would force outer IP fragmentation (AGY r3 Hazard A). `wg/mss.rs:48,59,92` already reserves worst-case pad for TCP MSS. |
| Telemetry double-count (AGY r3 Hazard C) | **LOW** | Consolidate bytes/packets counters across the transit-encap (`frame/mod.rs:237`) and TUN-read-encap sites so WG egress is not under/over-reported. Test asserts a single round-trip increments the WG egress counter exactly once. |
| Kernel `rp_filter` silent drop (AGY r2) | **MED** | WG outer datagrams pass to the kernel; if strict `rp_filter` is on and the kernel routing table (userspace-managed by xpf/FRR) lacks a route back to the peer's public IP, the kernel silently drops inbound WG. Runbook (§8) must set `net.ipv4.conf.<wan>.rp_filter=0/2` or ensure a kernel route to the peer exists. The `wgN` TUN gives the kernel an inner route; the outer-peer route is the gap. |
| Transit/DNAT UDP-on-WG-port policy bypass (both r2, RESOLVED) | **LOW** | The shim early-return requires `is_local_destination` (§4.5) so only WG-to-firewall is shunted to the kernel; transit stays on the policy engine. Test `shim_transit_udp_on_wg_port_stays_on_dataplane`. |
| Kernel-WG port conflict (AGY r2) | **LOW** | `UdpSocket` bind fails `EADDRINUSE` if a kernel `wgX` claims the port; surfaced as a clear error + counter; userspace-WG and kernel-WG on the same port are mutually exclusive (documented). |

## 8. Test plan

- `cargo build` clean; `cargo test --release` full suite (current count +
  new wiring tests).
- New unit/integration tests:
  - `wg_encap_then_decap_roundtrip` — encap an inner IPv4 frame through a live
    session (TX path), decap it back through the control-thread `try_decap`,
    assert byte-identical inner.
  - `wg_encap_no_session_triggers_single_init_per_interval` — first packet with
    no session drops + the `last_init_ns` atomic fires exactly once per interval
    under a packet flood (proves the rate-limiter bounds the signal).
  - `wg_control_loop_dispatch` — type-1 → response sent; type-2 → session
    completes; type-3 → dropped+counted; type-4 → decap + AllowedIPs gate +
    reinject. (Drives `wg_control_loop` against an in-memory socket double.)
  - `wg_reload_reuses_engine_when_identity_unchanged` + `..._seeds_high_water_on_change`
    — the §4.2 reload contract: unchanged endpoint reuses the same `Arc`
    (pointer-eq) without `reconcile_peers`; a changed endpoint gets a fresh
    engine whose TAI64N high-water ≥ the prior engine's.
  - `wg_encap_mtu_oversize_drops_not_corrupts` — a non-TCP inner exceeding
    `MTU - WG_OVERHEAD` is dropped + `wg_mtu_drops` incremented, UMEM frame
    untouched.
  - `shim_steers_wg_listen_port_to_kernel` — the `userspace-xdp` early-return
    returns `cpumap_or_pass` for **local-destination** `UDP/listen_port` and is
    inert (`ctrl.wg_rx == 0`) otherwise.
  - `shim_transit_udp_on_wg_port_stays_on_dataplane` — a TRANSIT (non-local-dst)
    UDP packet on `wg_listen_port` is NOT shunted to the kernel (the
    `is_local_destination` guard, §4.5) — it stays on the XSK/policy path.
  - Go: `buildTunnelEndpointSnapshots` populates `Wg*` for a `mode=wireguard`
    tunnel; `mode=gre` unchanged.
  - Go: privkey not serialized into the state snapshot.
- 5/5 flake check on `wg_encap_then_decap_roundtrip`.
- Go suite: all packages.
- **Smoke (S2a — fast-path no-regress only; live WG interop is S2b):** deploy on
  loss userspace cluster with a WG endpoint configured (responder, no live peer
  — proves the gate is installed and inert for non-WG traffic). Run the full
  matrix: Pass A CoS-disabled v4+v6 push+reverse + 12-stream reverse reproducer;
  Pass B CoS-enabled per-class 5201-5206. **Required: best-effort + per-class
  numbers identical to a no-WG baseline (0 retrans, line rate on the multi-
  stream reverse).** This is the #1183/#1545 fast-path guard.
- **Deploy/runbook notes:** (a, AGY r2) WG outer datagrams transit the kernel;
  the deploy must ensure inbound WG is not `rp_filter`-dropped — set
  `net.ipv4.conf.<wan>.rp_filter` to 0/2, or ensure the kernel routing table has
  a route to the peer's public IP. (b, AGY r2) the WG `listen-port` must not
  collide with a host kernel `wgX` (bind `EADDRINUSE`). (c, AGY r3) the `wgN` TUN
  is persistent + MTU-capped (§4.3). (d, AGY r3) **DNAT-to-WG-port limitation**:
  if AF_XDP DNAT rules forward inbound WG-port traffic targeting a host public
  IP to an internal host, the `is_local_destination` shim guard still steals it
  to the kernel (dst is locally-owned) — documented as a known limitation; a
  non-issue for the standard topology where the xpf host IS the VPN terminator.
  (Carried into the S2b live-interop runbook, #1736.)
- `make audit-check`.
- `make test-failover` only if S2a touches HA/bringup. **Assertion: it does
  NOT** — single-tunnel S2a adds a WG endpoint + aux thread but does not change
  RG/VRRP/session-sync/failover code. To be confirmed at implement time; if the
  WG engine ends up in the RG-epoch-stamped forwarding rebuild path, run it.

## 9. Out of scope (explicit)
S2b live interop (#1736); S4 PSK; S5 timers/keepalive/roaming/TAI64N-persist;
S6 Junos grammar + CLI + multi-instance (#1434); S7 cookie/MAC2/IPv6-outer/DSCP;
S8 HA migration; post-S2 perf benchmarking.

## 10. Questions — resolutions after round 1 (Codex + AGY + Claude-SMR)

1. **Config surface (§4.1).** RESOLVED: minimal `tunnel mode wireguard` + flat
   `wg_*` attributes; compiles to the DTO without committing to S6 grammar. Both
   reviewers agreed (Codex finding 6, AGY).
2. **Engine reload stability (§4.2).** RESOLVED (both reviewers' blocker #2):
   identity-stable `Arc<WgEngine>` reuse from `previous` (no `reconcile_peers` on
   the shared Arc, avoiding mutation of state old worker Arcs observe); on config
   change, fresh engine seeded from the prior TAI64N high-water.
3. **WG RX delivery (§3.4/§4.3).** RESOLVED (both reviewers' blocker #1, refined
   by Claude-SMR): WG-to-firewall is local-destination UDP → kernel via
   `cpumap_or_pass` (ESP precedent `lib.rs:469`); a kernel `UdpSocket` receives
   it. S2a adds a deterministic shim early-return and keeps RX on the kernel
   socket (Option A). The AF_XDP-hot-path decap (Option B) needs a shim steering
   change and is deferred to a post-S2 perf follow-up. This removes the
   `stage_wg_decap` hot-path stage + worker→control packet channel entirely.
4. **Fast-path cost (§4.5).** RESOLVED: no `FastSet<u16>` per-packet probe; the
   shim early-return pays only `ctrl.wg_rx`, and the userspace DP carries a
   single `has_wg_tunnels` bool. Both reviewers' minor #4 folded.
5. **Encap UMEM/MTU (§7).** RESOLVED: copy path sizes for `inner + WG_OVERHEAD`;
   non-TCP >MTU → explicit drop + `wg_mtu_drops` (no userspace reassembly), no
   descriptor overflow. `try_encap` bound-checks before side effects
   (`engine.rs:627-633`).
6. **S2a/S2b split soundness.** RESOLVED: sound (Codex finding 3, AGY). S2a lands
   ONLY as gated wiring + no-regress smoke; it is NOT advertised as "WG works"
   until S2b's live interop passes. The plan and PR will state this explicitly.
7. **Encap sites.** RESOLVED: S2a wires the transit copy path
   (`frame/mod.rs:237`) and the WG control thread's own TUN-read egress (§4.3,
   reusing the `tunnel.rs:189` encap with a mode branch). TSO is not live for
   tunnels (`tx/dispatch/mod.rs:1026` returns false; `tx/tcp_segmentation.rs:21`
   returns `None`), and the GRE coordinator local-origin spawner stays GRE-only
   (`coordinator/mod.rs:342`). (Codex r1 finding 6 / r2.)

## 11. v2 convergence (round 1)

- **Codex** (`wg-s2a-plan-r1-1780272812`): **PLAN-NEEDS-MAJOR.** Two blockers:
  (1) WG RX ownership "internally contradictory and not implementable as
  written"; (2) reload-stable engine reuse mandatory but the v1 "reuse +
  reconcile" was snapshot-unsafe. Minors: ingress probe not zero-cost; UMEM/MTU
  needs explicit drop tests; only the primary encap site is required;
  control-thread-only invariant OK if NoSession is a bounded signal.
- **AGY** (`adversarial-review-mpugg9lm-mlr55n`): **PLAN-NEEDS-MAJOR.** Same two
  blockers + the same minors (asymmetric UDP model, `previous`-state engine
  carry, `has_wg_tunnels` + bitmask gating, worker→control rate-limit, MTU
  drop-not-corrupt). (AGY edited the plan during review per the known pattern;
  the edit was REVERTED — AGY is review-only — and its sound resolutions folded
  here by hand.)
- **Claude-SMR** (this thread): independently verified the code. **Key
  correction to BOTH reviewers' shared premise**: a kernel `UdpSocket` on
  `wg_listen_port` CAN receive WG datagrams, because the shim passes
  local-destination UDP to the kernel via `cpumap_or_pass` — the exact ESP/IPsec
  path (`lib.rs:467-475`). This makes Option A (kernel-socket RX, no shim
  steering rewrite, no hot-path decap stage) the lowest-risk S2a, dissolving
  blocker #1 into a one-line shim early-return rather than a full AF_XDP demux
  redesign. Both blockers are resolved in v2 (§3.4, §4.2, §4.3, §4.5).

All round-1 findings folded.

## 11b. v3 convergence (round 2 — confirming the RX-model pivot)

- **Codex** (`wg-s2a-plan-r2-1780273508`): **PLAN-NEEDS-MAJOR.** Confirmed the
  ESP-precedent RX claim, the reload fix, and egress placement as sound. Two NEW
  majors v2 introduced: (1) the shim early-return was too broad — port-only
  steering steals transit/DNAT UDP on the WG port and shunts it to the kernel,
  bypassing policy; must require `is_local_destination`. (2) The decap reinject
  via `local_tunnel_deliveries` writes to a **TUN fd** (`tunnel.rs:52`,
  kernel delivery), NOT the AF_XDP policy pipeline — v2's "runs normal policy"
  claim was wrong; needs an explicit kernel-TUN-delivery scoping or a real
  control→forwarding injection design. Minor: stale "TSO + local-origination"
  parenthetical.
- **AGY** (`adversarial-review-mpugvd7u-fp5fma`): **PLAN-NEEDS-MINOR.** Same
  mandatory edit (shim must require `is_local_destination` — flagged as a
  security/policy-bypass CAUTION). Plus two operational hazards: kernel
  `rp_filter` silently drops inbound WG when the userspace-managed kernel
  routing table lacks a route to the peer's public IP (runbook `sysctl` note);
  and `EADDRINUSE` if a kernel `wgX` claims the port. Confirmed reload, egress
  zero-cost, NoSession atomic, and the S2a/S2b split as sound.
- **Claude-SMR** (this thread): verified Codex's TUN finding (`tunnel.rs:36
  open_tun`, `:56 tun.write_all`) — the `local_tunnel_deliveries` path IS the
  TUN, so v3 adopts the coherent **`wgN` TUN model** end-to-end (kernel-routed
  inner both directions, control thread owns UdpSocket + TUN + engine), the
  exact IPsec/GRE-local-origin precedent. This makes Codex's blocker #2 a
  deliberate, honest design choice (inner re-enters via the kernel, not the
  AF_XDP policy engine; AllowedIPs is the S2a inner-src control) rather than a
  defect, and resolves both r2 majors.

v3 folds: the mandatory `is_local_destination` shim guard (§4.5), the explicit
TUN model (§1, §3.4, §4.3), the `rp_filter` + port-conflict hazards (§7, §8),
and the encap-sites cleanup (§4.4, §10.7).

## 11c. v3-final convergence (round 3 — PLAN-READY)

- **AGY** (`adversarial-review-mpuh8tsf-qvo8cp`): **PLAN-READY.** Confirmed the
  `wgN` TUN model coherent, the `is_local_destination` guard sufficient, no
  double-encap. Surfaced three folds: **(A) `wgN` MTU** must be capped at
  `outer_mtu - WG_OVERHEAD - 15` or the kernel hands oversized inner that forces
  outer IP fragmentation; **(B) TUN persistence** — a transient TUN fd is
  deleted on close, so a config reload (`coordinator/mod.rs:209` stops/joins aux
  threads) would flap `wgN` and destroy its addresses + FRR routes every reload;
  use `TUNSETPERSIST` / pre-create; **(C) telemetry** — consolidate byte/packet
  counters across the transit-encap + TUN-read-encap sites. Plus a DNAT-to-WG-
  port known-limitation note.
- **Codex** (`wg-s2a-plan-r3-1780274137`): **PLAN-NEEDS-MINOR.** Both r2 majors
  confirmed resolved (explicit TUN/kernel delivery; shim no longer port-only).
  One minor: the TUN-read MTU handling was underspecified — require the exact
  `WG_OVERHEAD + pad_to_16(inner.len()) <= outer_mtu` guard (pad-aware, not just
  `inner + WG_OVERHEAD`) in BOTH the transit and TUN-read directions; `wg/mss.rs`
  already reserves worst-case pad. No-double-encap, shim guard, and engine-reuse-
  vs-TUN-reload all confirmed sound.
- **Claude-SMR** (this thread): folded all three AGY items + Codex's pad-aware
  MTU guard into §4.1 (Go creates persistent MTU-capped `wgN`), §4.3 (persistent
  TUN + exact MTU guard), §7 (MTU + telemetry rows), §8 (DNAT runbook note).

**Converged PLAN-READY** (AGY READY, Codex MINOR fully folded, Claude-SMR
agree). All findings across 3 rounds are folds of the reviewers' own prescribed
fixes — no open architectural question. **Cleared to implement S2a.**

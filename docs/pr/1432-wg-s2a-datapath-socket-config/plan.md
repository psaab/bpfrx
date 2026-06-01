# #1432 / #1703 S2a — WireGuard AF_XDP datapath wiring: engine instantiation + UDP socket + encap/decap call sites + runtime TunnelEndpoint hydration + Go DTO population + minimal config

Status: **DRAFT v1 — pending adversarial plan review** (Codex + AGY + Claude-SMR,
maximally hostile: new datapath + crypto-adjacent + UMEM + hot-path cost).

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
- A **control-thread** UDP socket binds `wg_listen_port`, drives the S1
  handshake methods (`create_initiation` / `consume_response` /
  `consume_initiation_create_response`), and transmits/receives WG datagrams.
- **Egress encap**: forwarding decisions that target a WG tunnel endpoint encap
  the inner IP via `wg_engine.try_encap(...)` and emit a UDP/WG outer datagram.
- **Ingress decap**: inbound `UDP/<listen_port>` WG transport records are
  decapped via `wg_engine.try_decap(...)`, AllowedIPs-gated on the inner src,
  and re-injected as plaintext into the normal forwarding pipeline; WG handshake
  datagrams (type 1/2/3) are handed to the control thread.

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

### 3.4 The ingress decap model (GRE analogue)
- `poll_stages.rs:142 stage_native_gre_decap` calls
  `try_native_gre_decap_from_frame(raw_frame, meta, forwarding)` and returns
  `(new_meta, Option<Vec<u8>>)` — the decapped inner frame flows on as the
  active slice. WG decap follows the same stage shape (`UDP/<listen_port>` →
  `wg_engine.try_decap` → inner IP frame).
- `poll_stages.rs:425 stage_ipsec_passthrough_check` is the **control-thread
  handoff template**: a `LocalDelivery` `SessionDecision` +
  `maybe_reinject_slow_path_from_frame` reinjects ESP/IKE to the kernel.
  WG **handshake** datagrams (type 1/2/3) use the same handoff to the WG
  control thread (not the kernel TUN — an in-process channel to the aux thread).

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
  tunnel_endpoint_id. Built in `build_forwarding_state` after tunnel population:
  for each `mode == "wireguard"` endpoint, `WgEngine::new(WgEngineConfig {
  local_private_key, listen_port, ... })` + `reconcile_peers(&[WgPeerConfig{
  pubkey, allowed_ips, endpoint, keepalive }])`.
- **Engine reuse across config reloads** is a hazard (a fresh `WgEngine` per
  reload drops the in-process TAI64N high-water + live sessions → re-handshake
  storm / monotonicity regression). **Decision: S2a keeps the engine in a
  reload-stable holder** (an `ArcSwap`/map carried across
  `build_forwarding_state` so an unchanged WG endpoint keeps its engine), OR
  documents the re-handshake-on-reload limitation as an S2a-accepted cost with
  an S5 fix. **Plan-review Q2** — this is the highest-risk decision.

### 4.3 Rust: the WG control thread (UDP socket + handshake driver)

A new `coordinator` aux thread (one per WG endpoint, modeled on
`spawn_local_tunnel_sources`), `wg_control_loop` in a new
`coordinator/wg_control.rs`:

- Bind `UdpSocket` to `0.0.0.0:wg_listen_port` (+ v6) on the **transport_table /
  outer interface** — set non-blocking, `recv_from` in a poll loop with a stop
  flag.
- **Inbound** datagram: peek WG type byte.
  - type 1 (initiation) → `engine.consume_initiation_create_response(msg, out)`
    → `socket.send_to(out, peer)` (the response). Promotes a responder session.
  - type 2 (response) → `engine.consume_response(msg)` → completes the
    initiator session.
  - type 3 (cookie) → drop (S7).
  - type 4 (transport) → this should normally arrive on the AF_XDP datapath
    (decap stage), NOT the control socket. If it arrives here (e.g. kernel
    delivered it), it is the slow-path fallback: `engine.try_decap` + inject the
    plaintext to the kernel/forwarding. **S2a: drop type-4 on the control socket
    with a counter** (the datapath path is the supported one); document.
- **Initiator bring-up**: if `wg_endpoint` is configured, on thread start (and
  on a session-absent timer) call `engine.create_initiation(peer_pubkey, out)`
  + `socket.send_to(out, wg_endpoint)`. (Persistent-keepalive + REKEY timers are
  S5 — S2a does the initial handshake + a coarse re-init-if-no-session.)
- **Handshake datagrams from the datapath**: the ingress decap stage hands WG
  type-1/2/3 datagrams to this thread via an mpsc channel (the §3.4 handoff),
  because the listen-port UDP socket on the kernel side will NOT see datagrams
  that the AF_XDP program already consumed. **Plan-review Q3** — does the kernel
  UDP socket actually receive the handshake (AF_XDP steers only steered queues),
  or must ALL WG datagrams (handshake + transport) come through the AF_XDP
  ingress and be demuxed there? This determines whether the control thread reads
  a real `UdpSocket` or only an in-process channel fed by the datapath.

### 4.4 Rust: egress encap call site (gated, fast-path-zero-cost)

At `frame/mod.rs:237` (and the TSO + local-origination sites), replace the
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
complete) → drop the packet + trigger a handshake init via the control thread
(channel signal) + counter. Reuses `WgWorkerScratch` — **no per-packet alloc**.

### 4.5 Rust: ingress decap stage (gated)

A new `stage_wg_decap` in `poll_stages.rs`, modeled on `stage_native_gre_decap`,
placed in the same stage region. Gate: only enters when the parsed outer is
`UDP && dst_port == any configured wg_listen_port` (a cheap set membership; the
common case is a miss and falls through with zero cost). On a WG `UDP` match:
- type 4 (transport) → `engine.try_decap(record, scratch)` → AllowedIPs inner-
  src gate (`allowed_ips.rs`) → return the inner IP frame as the decap `Vec<u8>`
  (same `(meta, Option<Vec<u8>>)` shape).
- type 1/2/3 (handshake) → hand to the control thread via mpsc + recycle the
  frame (no forwarding). Same `RecycleAndContinue` shape as IPsec passthrough.

The listen-port set is precomputed in `ForwardingState` (a small
`FastSet<u16>`) so the gate is one hash probe; non-WG traffic (the overwhelming
majority) never touches the engine.

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
fields, `ForwardingState.wg_engines` + `wg_listen_ports`, `coordinator/
wg_control.rs`, the gated encap/decap branches. GRE path byte-for-byte
unchanged.

## 6. Hidden invariants the change must preserve

- **Handshake crypto is control-thread only** (S1 §7). The encap/decap on the
  poll worker take only `RwLock::read` on `peer.current` /
  `sessions_by_local_index` — they NEVER build a `HandshakeState`. The control
  thread owns all `create_initiation`/`consume_*` calls.
- **No hot-path allocation** (#1207/#946). Encap/decap reuse `WgWorkerScratch`;
  no `vec![]` per packet.
- **Non-WG fast-path zero-cost** (#1183/#1545). The encap branch is inside the
  already-tunneled copy path (plain forward never reaches it); the decap gate is
  one `FastSet<u16>` probe that misses for all non-WG traffic. Smoke must show
  best-effort line rate unchanged with a WG endpoint configured.
- **Engine reload stability** — an unchanged WG endpoint must KEEP its engine
  across config reloads (TAI64N high-water + live sessions), or the
  re-handshake-on-reload cost must be explicitly accepted + documented (§4.2).
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
| Behavioral regression (non-WG fast path) | **MED→HIGH** | The encap/decap gating is the crux. Mitigation: branch lives only in the already-tunneled copy path; decap gate is a single hash probe; smoke proves CoS-off + CoS-on line rate unchanged with WG configured. PLAN-KILL if a reviewer shows the gate touches the plain-forward path. |
| Lifetime / borrow-checker | **MED** | New aux thread shares `Arc<WgEngine>` + forwarding; the encap scratch is `RefCell` (single-threaded worker). The decap `Option<Vec<u8>>` shape mirrors GRE. |
| Silent black-hole / mis-demux | **MED** | Decap demux on `receiver_index` is S1-tested; the handshake handoff channel + `create_initiation`-on-NoSession is new. Tests: encap→decap self-loopback round-trip; NoSession triggers init exactly once. |
| Engine reload churn (TAI64N/sessions) | **MED** | §4.2 Q2 — the open decision. |
| Architectural mismatch (#961/#946-P2) | **LOW** | The aux-thread + decap-stage + encap-branch templates already exist (GRE/IPsec). This is composition, not a new architecture. |
| AF_XDP-vs-kernel-UDP handshake delivery | **MED** | §4.3 Q3 — whether handshake datagrams reach a kernel `UdpSocket` or must be demuxed off the AF_XDP path. Wrong assumption = handshake never completes. Must be resolved before implement. |
| UMEM integration on encap | **MED** | The WG outer datagram is larger than inner (overhead 60–80 B); the copy path must size the UMEM frame for `inner + WG_OVERHEAD`. MSS clamp (`wg/mss.rs`) bounds inner TCP; non-TCP >MTU is the no-reassembly S2b case. |

## 8. Test plan

- `cargo build` clean; `cargo test --release` full suite (current count +
  new wiring tests).
- New unit/integration tests:
  - `wg_encap_then_decap_roundtrip` — encap an inner IPv4 frame through a live
    session, decap it back, assert byte-identical inner.
  - `wg_decap_gate_misses_non_wg_udp` — a non-listen-port UDP frame falls
    through `stage_wg_decap` untouched.
  - `wg_encap_no_session_triggers_single_init` — first packet with no session
    drops + signals exactly one handshake init.
  - `wg_handshake_datagram_routed_to_control_thread` — type-1/2 on the decap
    stage is handed off + recycled, not forwarded.
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
- `make audit-check`.
- `make test-failover` only if S2a touches HA/bringup. **Assertion: it does
  NOT** — single-tunnel S2a adds a WG endpoint + aux thread but does not change
  RG/VRRP/session-sync/failover code. To be confirmed at implement time; if the
  WG engine ends up in the RG-epoch-stamped forwarding rebuild path, run it.

## 9. Out of scope (explicit)
S2b live interop (#1736); S4 PSK; S5 timers/keepalive/roaming/TAI64N-persist;
S6 Junos grammar + CLI + multi-instance (#1434); S7 cookie/MAC2/IPv6-outer/DSCP;
S8 HA migration; post-S2 perf benchmarking.

## 10. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Config surface (§4.1).** Is a minimal `tunnel mode wireguard` + flat `wg_*`
   attributes the right S2a surface, or does even the minimal config force the
   S6 grammar decision now? Kill/redirect if the config can't compile to the DTO
   without committing to S6.
2. **Engine reload stability (§4.2).** Must S2a carry the `WgEngine` across
   config reloads (reload-stable holder), or is re-handshake-on-reload an
   acceptable S2a cost? A fresh engine per reload drops TAI64N high-water +
   sessions → re-handshake storm + monotonicity regression against a peer that
   still holds the old high-water. **Highest-risk decision.**
3. **Handshake datagram delivery (§4.3/§4.5).** Do WG handshake datagrams (and
   transport) reach a kernel `UdpSocket` bound on `wg_listen_port`, or does the
   AF_XDP program consume ALL ingress on the steered queues so EVERYTHING must
   be demuxed off the datapath and fed to the control thread via channel? This
   determines whether the control thread owns a real socket for RX or only TX.
   Wrong = handshake never completes. **Must be resolved before implement.**
4. **Fast-path cost (§4.4/§4.5).** Is the decap gate (`FastSet<u16>` probe on
   every ingress UDP) truly zero-cost for non-WG traffic at line rate, or does
   adding a probe to the UDP ingress path regress best-effort? Kill if the probe
   can't be hoisted to a per-binding precomputed flag.
5. **Encap UMEM sizing (§7).** Does the copy path correctly size the UMEM frame
   for `inner + WG_OVERHEAD`, and what happens to a non-TCP inner packet that
   exceeds `MTU - WG_OVERHEAD` (no userspace reassembly)? S2a must drop-not-
   corrupt; confirm the buffer math.
6. **S2a/S2b split soundness.** Is shipping datapath wiring WITHOUT the live
   interop proof acceptable, given the wiring is unit-tested + self-loopback +
   fast-path-no-regress smoke? Or must S2a and S2b co-ship? I argue the split is
   sound (the engine is dead until wired; the wiring is gated + inert for non-WG;
   the live proof is a separable VM-harness surface per consolidation Q4). Kill
   the split if a half-wired datapath is judged unshippable.
7. **Is `frame/mod.rs:237` the only encap site that matters for S2a**, or do the
   TSO (`tcp_segmentation.rs:309`) + local-origination (`tunnel.rs:189`) sites
   ALSO need WG wiring for a minimally-functional single tunnel, or can they
   return a "WG-unsupported-on-this-path" drop in S2a and land in a follow-up?

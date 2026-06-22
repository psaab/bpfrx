# #1434 — Multi-Tunnel WireGuard: Go config-model refactor for N peers per tunnel

**Status: REV v1.2 (research, plan-of-action only — NO code, NO PR, NO production source touched)**

Plan-of-action only. Claude SMR r1 (hostile, `claude-smr-plan-r1.md`) AND Codex
r1 (hostile, `codex-plan-r1.md`) have run; both converged on the central
finding — the WG dataplane is multi-peer on RX/decap but SINGLE-peer on the
whole EGRESS machinery (encap, control-thread TUN egress + roaming, keepalive
timers) via `first_peer_pubkey` (§5.0.1). SMR MAJOR-1 (PSK self-catch, §6.3),
MINOR-1/2/3, NIT-2 and the egress re-scope are folded. AGY hostile review
in flight (prior run infra-timed-out, retried). Every load-bearing claim is
verified against `origin/master` at HEAD `cf9ccd3ac` and the pinned snow
0.10.0 source.

This plan covers the **multi-PEER-per-tunnel** axis of #1434. It is distinct
from the prior `research/1434-wireguard-multitunnel` plan, which covered the
**multi-INTERFACE / shim-port-steering** axis (Increment 2, DEFERRED-needs-lab).
The two are orthogonal. §1.1 disambiguates.

---

## 1. Issue framing and the two-axis disambiguation

Issue #1434 ("Implement Multi-Tunnel WireGuard Support") is a stale umbrella.
Its literal task list (move WG config off the global ConfigSnapshot; index a
WG-engine map by port; RX/TX engine lookup by port) **already shipped** under
#1432 S2a and follow-ups — the data plane is per-tunnel-endpoint, keyed by id,
config lives on `TunnelEndpointSnapshot`, and `show security wireguard
public-key` + `request security wireguard generate-private-key` shipped via
PR #2048. Implementing the literal list verbatim would be a regression.

Because the umbrella is stale, "multi-tunnel" has been split into two
genuinely different work axes:

### 1.1 The two axes

- **Axis A — multiple WG INTERFACES (one peer each, different listen ports).**
  Operator wants `gr-0-0-0` on UDP 51820 and `gr-0-0-1` on UDP 51821, each a
  separate WG tunnel to a separate hub. The blocker is the AF_XDP shim:
  `snapshotWgListenPort` (`pkg/dataplane/userspace/maps_sync.go:1547`) returns
  the FIRST WG port only, and `wg_steer_to_kernel`
  (`userspace-xdp/src/lib.rs`) matches that single port — a second tunnel's
  inbound transport UDP is never steered to its kernel socket and is silently
  dead. Fixing this touches the BPF-verifier-gated shim (`make generate`,
  pinned toolchain, ABI bump) and needs the loss cluster + perf +
  `make test-failover`. **This is the prior plan's Increment 2 —
  DEFERRED-needs-lab. NOT this plan.**

- **Axis B — multiple PEERS on ONE WG INTERFACE (one listen port).**
  Operator wants `gr-0-0-0` on UDP 51820 with peer X owning `10.1.0.0/16` and
  peer Y owning `10.2.0.0/16` — classic WireGuard hub-with-many-spokes, or a
  single interface terminating multiple site-to-site peers. All peers share
  ONE listen port, so the shim steering problem of Axis A **does not apply**.
  The blocker is purely the Go config model: `TunnelConfig` holds ONE scalar
  peer. **This is what this plan addresses.** The Rust engine peer TABLE
  already supports N peers natively (RX/decap is multi-peer); the egress
  machinery is single-peer and is generalized in B1b (§5.0/§5.0.1). The
  config + RX slice (B1a) is driveable now without the shim or the lab; the
  egress completion (B1b) is lab-recommended but still shim-free.

The user directive for this research is Axis B. Axis A stays deferred to the
prior plan / lab. The interop LAB (live multi-peer handshake against a real
peer) defers to #1703.

### 1.2 Why Axis B is the correct, driveable-now slice

The Rust WG engine is **already fully multi-peer** (verified at HEAD):

- `WgEngineConfig.peers: Vec<WgPeerConfig>` —
  `userspace-dp/src/afxdp/wg/engine.rs:190`.
- `WgPeerConfig` carries per-peer `pubkey`, `endpoint`,
  `persistent_keepalive`, `allowed_ips: Vec<ipnet::IpNet>` — engine.rs:178.
- `PeerTable` indexes peers by pubkey (`peer_index_by_pubkey`) and routes
  decap by an AllowedIPs LPM trie spanning ALL peers (`allowed_ips`) —
  engine.rs:244.
- `reconcile_peers(&[WgPeerConfig])` (engine.rs:507) reconciles an N-peer set,
  reuses existing `Peer` Arcs by pubkey (so live sessions survive a commit),
  drains removed peers' sessions + pending reservations, and publishes one
  atomic `ArcSwap<PeerTable>`. It already `debug_assert`s on duplicate pubkeys
  and documents "the Go control plane is supposed to reject duplicate pubkeys
  at config validation" (engine.rs:541-553) — a contract THIS plan must honour.

The peer-TABLE collapse to one peer is the build path: `populate_wg_engines`
(`userspace-dp/src/afxdp/forwarding_build/wg.rs:48-72`) constructs exactly one
`WgPeerConfig` from the scalar snapshot fields and does `peers: vec![peer]`. The
scalar snapshot fields, in turn, come from the scalar Go `TunnelConfig` and the
scalar Go→Rust wire DTO. **But that is only the RX-feeding collapse** — the
EGRESS paths additionally collapse to peer[0] via `first_peer_pubkey`
independently of the table (§5.0.1), so widening the build path alone does NOT
make TX multi-peer.

So the RX half of Axis B is a clean "widen the pipe" change: Go config slice →
wire slice → Rust build-path slice → `peers: Vec<...>` (which the engine
already wants). The TX/egress half is NOT a pure widen — the encap + control
thread + timers select a single peer via `first_peer_pubkey` and must be
generalized (§5.0/§5.0.1). The hostile review's central output is making this
RX-vs-TX asymmetry explicit; do not let the "engine already multi-peer" framing
hide the egress work.

---

## 2. Honest scope and value

**Value.** Hub-and-spoke and multi-site-to-site WireGuard are standard
real-world topologies. Today an operator can terminate exactly one peer per WG
interface — an arbitrary ceiling on an otherwise complete, wire-compliant WG
subsystem (snow IKpsk2, MAC1/MAC2 cookie, Tai64N, AllowedIPs cryptokey
routing, MSS clamp, DSCP). The marginal code is moderate for the RX/config
slice (a Go slice + schema named-instance + compiler loop + wire DTO + the Rust
build-path loop + per-peer status) and larger for the egress generalization
(encap LPM + per-peer control-thread egress + per-peer keepalive timers,
§5.0.1). It removes a real product limitation and unlocks the engine capability
that is already paid for.

**PSK gap (orthogonal but in scope per directive).** The engine hardcodes
`.psk(2, &WG_ZERO_PSK)` in BOTH `build_initiator_handshake` (engine.rs:1161)
and `build_responder_handshake` (engine.rs:1184). There is NO per-peer PSK
field on `WgPeerConfig` at all. Per-peer PSK is a real Ubiquiti/standard-WG
interop knob (#1703 RQ2). §6 Path-PSK analyses it as a SEPARATE, optionally-
deferrable sub-increment because the responder PSK ordering is a genuine snow
API subtlety (§6.3) — NOT a free rider on the slice.

**Scope reality (what is already done, do NOT redo):**
- Per-tunnel-endpoint engine map keyed by id — `forwarding_build/wg.rs`,
  `types/forwarding.rs:31`. (#1432 S2a)
- Per-endpoint WG control thread + kernel UDP socket on its `wg_listen_port` —
  `coordinator/tunnel_supervision.rs`, `coordinator/wg_control.rs`.
- WG config on `TunnelEndpointSnapshot`, not global — protocol.go:273.
- `show security wireguard [detail] public-key` + `request ...
  generate-private-key` + `local_pubkey_hex` telemetry. (PR #2048)
- Identity-stable engine reuse + TAI64N high-water seeding across reload —
  `wg.rs:54-80`.
- AllowedIPs LPM, per-peer keepalive, endpoint roaming fields — all already
  per-peer in the engine.

**Out of scope (this plan):**
- Axis A shim multi-PORT steering (prior plan Increment 2, DEFERRED-needs-lab).
- Live multi-peer handshake interop lab (#1703).
- Full Junos `wireguard` grammar S6 (this stays the minimal generic stanza).
- Per-peer MSS/DSCP overrides (engine MSS/DSCP are tunnel-level today; not a
  multi-peer requirement — note as a follow-on if demand appears).

---

## 3. Current state — verified citations (HEAD cf9ccd3ac)

### 3.1 Go config model (scalar, single peer)

`pkg/config/types_routing.go:325-335` — `TunnelConfig` WG fields are ALL
scalar / single-peer:
```
WgListenPort      uint16   // tunnel-level (correct, stays)
WgLocalPrivkeyHex string   // tunnel-level (correct, stays)
WgPeerPubkeyHex   string   // <-- PEER: scalar, last-wins
WgAllowedIPs      []string // <-- PEER: belongs to the one peer
WgEndpoint        string   // <-- PEER: scalar
WgKeepaliveSecs   uint16   // <-- PEER: scalar
```
`TunnelConfig.String()` (types_routing.go:341) redacts the privkey; it
formats the scalar peer fields and must be updated to format the slice.

### 3.2 Schema (no multi on peer)

`pkg/config/schema_interfaces.go:378-392` — the `peer` node is a plain
container, NO `multi`, NO `wildcard`, NO named-instance key:
```
"peer": {desc: "WireGuard peer", children: map[string]*schemaNode{
    "public-key":  {...},
    "allowed-ips": {... multi: true ...},   // multi WITHIN one peer (stays)
    "endpoint":    {...},
    "persistent-keepalive": {...},
}},
```
A second `peer { ... }` block today is structurally accepted by the parser but
collapses (last-wins) in the compiler — there is no instance identity.

### 3.3 Compiler (last-wins single peer)

`pkg/config/compiler_interfaces.go:684-726` — `parseTunnelWireguard` calls
`parseTunnelWireguardPeer(tc, prop)` for EACH `case "peer"`; the peer parser
writes the SAME scalar `tc.WgPeerPubkeyHex/WgEndpoint/WgKeepaliveSecs` and
APPENDS to the single `tc.WgAllowedIPs`. Two peer blocks → second pubkey/
endpoint/keepalive overwrite the first; their allowed-ips merge into one bag
(wrong cryptokey routing). So multi-peer is silently mis-compiled today.

### 3.4 Go→Rust wire DTO (scalar)

`pkg/dataplane/userspace/protocol.go:295-319` — `TunnelEndpointSnapshot` WG
fields mirror the scalar Go config (`WgPeerPubkeyHex string`,
`WgAllowedIPs []string`, `WgEndpoint string`, `WgKeepaliveSecs uint16`).

`pkg/dataplane/userspace/tunnels.go:122-129` — the snapshot builder copies the
scalar fields 1:1 from `TunnelConfig`.

`userspace-dp/src/protocol/snapshot.rs:341-374` — the Rust `TunnelEndpoint
Snapshot` deserialize side mirrors the scalar wire shape
(`wg_peer_pubkey_hex: String`, `wg_allowed_ips: Vec<String>`, `wg_endpoint:
String`, `wg_keepalive_secs: u16`). `wg_local_privkey_hex` is
`skip_serializing` (privkey hygiene, #1432 S2a) — the slice change MUST
preserve that.

### 3.5 Rust build path (the RX-feeding collapse point)

`userspace-dp/src/afxdp/forwarding_build/wg.rs:48-72` —
`populate_wg_engines` builds `peers: vec![peer]` from the scalar endpoint
fields. Widening THIS to a loop makes the engine peer TABLE multi-peer (and so
RX/decap multi-peer). `wg_identity_unchanged` (wg.rs:87-94) compares the scalar
fields for engine reuse and must compare the slice instead (order-stable since
the Go builder sorts by pubkey — §5.4). **This is necessary but NOT sufficient
for TX** — see §5.0.1 for the egress sites that also collapse to peer[0].

### 3.6 Rust engine peer TABLE (already multi-peer — table needs no change)

Confirmed in §1.2. The engine peer-table API (`WgEngineConfig.peers: Vec<...>`,
`reconcile_peers`, `PeerTable` + AllowedIPs LPM) needs NO change to HOLD N
peers. The table-feeding Rust edits are (a) the build-path loop, (b) the
snapshot DTO widening, (c) `wg_identity_unchanged` slice comparison. **However**
B1b adds a small engine method to EXPOSE an encap-side `inner_dst → peer`
lookup over the existing PeerTable+LPM (today the LPM is wired to RX only), and
the timer/control-thread egress paths must iterate peers instead of
`first_peer_pubkey` (§5.0.1). So "engine untouched" holds for the TABLE but not
for the egress-selection surface.

### 3.7 Wire fixture

`userspace-dp/tests/fixtures/protocol_wire_v1.json` carries a WG endpoint row
with scalar `wg_peer_pubkey_hex`/`wg_endpoint`/`wg_keepalive_secs` +
`wg_allowed_ips: []`. The fixture pins the Go↔Rust wire contract; changing the
wire shape requires REGENERATING it (§7) and confirming the Rust
`protocol/tests.rs` round-trip still passes.

---

## 4. Design — data-model shape (Path Options)

The peer set needs a representation in three layers (Go config, wire DTO, Rust
build path). The engine layer (`Vec<WgPeerConfig>`) is fixed. Two viable Go
data-model shapes:

### Path A — peer as an ordered slice `[]WgPeerConfig` (RECOMMENDED)

Add a Go struct mirroring the engine's per-peer fields and hold a slice on
`TunnelConfig`:
```go
// WgPeerConfig is one WireGuard peer on a WG tunnel (#1434).
type WgPeerConfig struct {
    PublicKeyHex   string   // peer static X25519 public key (hex, 64 chars)
    AllowedIPs     []string // this peer's AllowedIPs (CIDR) — cryptokey routing
    Endpoint       string   // optional peer endpoint IP:port (initiator role)
    KeepaliveSecs  uint16   // optional persistent-keepalive seconds
    PresharedKeyHex string  // optional per-peer PSK (hex, 64 chars); "" = zero PSK  [PSK sub-increment]
}
// On TunnelConfig:
WgPeers []WgPeerConfig  // replaces the scalar Wg{PeerPubkeyHex,AllowedIPs,Endpoint,KeepaliveSecs}
```
Schema: `peer <public-key>` becomes a **named-instance container** keyed by the
pubkey (model on `vrrp-group <id>` `args:1` container, schema_interfaces.go:135;
or `wildcard` like `routing-instances <name>`, schema_routing.go:295). The
pubkey is the natural identity. `allowed-ips`/`endpoint`/`persistent-keepalive`
(+ `preshared-key`) become CHILDREN of the instance. Compiler iterates the peer
instances appending one `WgPeerConfig` each. Wire DTO carries `wg_peers:
[]TunnelWgPeerWire`. Build path loops the slice.

- **Pros:** mirrors the engine exactly (engine takes `Vec`, order preserved →
  stable `peer_index`). Minimal mental translation. The schema named-instance
  pattern is well-trodden (vrrp-group, address, unit). Order-stable wire shape.
- **Cons:** identity is the pubkey but Go holds an ordered slice, so the
  compiler must dedup pubkeys itself (engine `debug_assert`s; production must
  hard-reject at commit — §5.5). A slice tolerates dup pubkeys structurally;
  the validation layer is load-bearing.

### Path B — peer as a map keyed by pubkey `map[string]WgPeerConfig`

Hold `WgPeers map[string]WgPeerConfig` (key = pubkey hex). Schema identical
(named-instance keyed by pubkey). Compiler keys the map by pubkey.

- **Pros:** dup-pubkey is structurally impossible (map collapses) — the
  engine's "Go rejects dups" contract is satisfied by construction.
- **Cons:** Go maps have NON-DETERMINISTIC iteration order. The wire DTO and
  `peer_index` assignment MUST be deterministic for (a) HA both-nodes-identical
  snapshot equality, (b) the wire fixture, (c) `wg_identity_unchanged` reuse,
  (d) reconcile_peers stable indexing. So a map forces an explicit sort on
  every serialize — re-introducing an ordering decision the slice gets for
  free. A silent map collapse also HIDES an operator's duplicate-pubkey typo
  instead of rejecting it (worse operator UX than a commit error). Map also
  diverges from every other repeatable Junos stanza in this codebase (all
  slices: StaticRoutes, vrrp-groups-as-slice, etc.).

### Decision: Path A (ordered slice) + explicit commit-time dup-pubkey reject.

Path A matches the engine's `Vec`, matches the codebase's slice convention for
repeatable stanzas, and gives deterministic order for free (sorted by pubkey
at the snapshot builder for HA determinism — §5.4). The dup-pubkey case is
handled by an explicit, loud commit-time validator (better operator feedback
than a silent map collapse), satisfying the engine contract at the right
layer.

---

## 5. Implementation plan (Path A) — file-by-file, no code yet

> **Increment split (REVISED after the SMR hot-path audit, §5.0).** The naive
> "B1 = config slice, lab-free" framing was too coarse: the WG dataplane is
> already multi-peer on RX/decap but single-peer on TX/encap. The honest split:
> - **B1a — config + RX (decap) multi-peer + status:** the Go config slice,
>   wire DTO slice, build-path loop feeding the engine N peers, the per-peer
>   status row, commit-time validators. With this, INBOUND from N peers is
>   already correctly demuxed + AllowedIPs-gated by the existing engine
>   (RX/decap is already multi-peer). `make test` + `cargo test`; lab-free.
> - **B1b — TX (encap) cryptokey routing:** the encap path must select the peer
>   by the inner-destination AllowedIPs LPM (today it uses the single scalar
>   peer). New engine encap-peer-selection + `frame/wg.rs` change. Hot-path-
>   adjacent; SHOULD be validated with real two-peer traffic — lab-RECOMMENDED.
> - **B2 — per-peer PSK:** §6 (snow ordering RESOLVED via `set_psk`). Engine
>   field + plumbing + secret hygiene. May ride B1; split on heavy hygiene.
>
> The live multi-peer handshake interop (Ubiquiti etc.) stays #1703.

### 5.0 Hot-path audit — RX is multi-peer, TX is NOT (the real scope split)

Verified at HEAD:
- **RX / decap is already multi-peer.** `try_decap` demuxes by the per-session
  `receiver_index` and gates the inner src-IP against THAT peer's AllowedIPs;
  the engine doc states the AllowedIPs LPM is used "ONLY for inbound src-IP
  gate" (engine.rs:6, :138). So N inbound peers on one listen port already
  resolve correctly — B1a just has to FEED the engine N peers
  (`populate_wg_engines` loop). No encap-path change for inbound.
- **TX / encap is single-peer.** Routing resolves a frame to ONE
  `tunnel_endpoint_id` (one WG interface), not to a specific peer
  (`forwarding/mod.rs:270-273`, :739-744). The encap path then calls
  `engine.try_encap(&endpoint.wg_peer_pubkey, ...)` (`frame/wg.rs:108`) and
  uses the SCALAR `endpoint.wg_endpoint` as the outer destination + family
  (frame/wg.rs:64, :80, :142). There is NO inner-destination → peer
  AllowedIPs lookup on the OUTBOUND side. So with N peers, the encap path has
  no way to pick which peer to send a given inner packet to — it would always
  encap toward peer[0]. The AllowedIPs LPM (`allowed_ips.rs:101` `lookup →
  peer_index`) EXISTS but is only wired to RX today.
- **B1b is therefore a genuine new mechanism, not config widening.** The encap
  caller must: LPM-lookup the inner dst → `peer_index` → that peer's pubkey +
  endpoint, then `try_encap(&that_peer_pubkey, ...)` to that peer's endpoint.
  This needs a small engine API (expose an encap-side dst→peer lookup, e.g.
  `peer_for_dest(inner_dst) -> Option<(pubkey, endpoint)>` over the existing
  PeerTable+LPM) + the `frame/wg.rs` rewrite. It is hot-path-adjacent (the WG
  transit encap site, per-packet for WG egress). Validate with real two-peer
  traffic: a packet to peer-X's AllowedIPs reaches X, a packet to peer-Y's
  reaches Y. That is best proven on the loss cluster → **B1b is lab-RECOMMENDED**
  (not strictly lab-blocked — a Rust integration test that drives
  `wg_encap_frame` with a two-peer engine and asserts the chosen
  pubkey/endpoint per inner-dst gives high confidence without the cluster; the
  lab is the belt-and-braces for line-rate + real handshake).

**Driveable-now without the lab: B1a** (config + RX + status + validators).
**Lab-recommended: B1b** (TX cryptokey routing). **B2** (PSK) rides whichever
PR fits given secret hygiene.

#### 5.0.1 Full single-peer-site inventory (Codex + SMR convergent — the egress machinery is single-peer)

Beyond `populate_wg_engines`, the egress/timer/control machinery selects a
SINGLE peer via `engine.first_peer_pubkey()` (engine.rs:443-444 = `peers.first()`).
The decode/decap RX path is the ONLY genuinely multi-peer-ready path. The
complete inventory of single-peer assumptions B1b must generalize:

| Site | File:line | What it assumes | B1b action |
|------|-----------|-----------------|-----------|
| Encap peer selection | `frame/wg.rs:108` `try_encap(&endpoint.wg_peer_pubkey,…)` + scalar endpoint :64/:80/:142 | one peer / one outer endpoint | LPM `inner_dst → peer` then encap to that peer |
| WG control thread egress | `coordinator/wg_control.rs:303` `first_peer_pubkey()` | TUN-read egress + re-init drive peer[0] only | per-peer egress (route inner via LPM to the right peer's session) + per-peer endpoint roaming |
| Endpoint roaming | `wg_control.rs:305-311` `effective_endpoint` | one learned endpoint | per-peer `effective_endpoint` (engine `Peer` already has per-peer endpoint state) |
| Keepalive/rekey timers | `wg/timers.rs:250` `first_peer_pubkey()`; timers.rs:107 "Per-ENGINE (single peer in S2a); per-peer generalization rides with #1434/S6" | only peer[0] gets persistent-keepalive + T-timer servicing | iterate ALL peers each timer tick (the per-peer T6/T7/T8 atomics already exist on `Peer`) |
| Status row | `coordinator/status.rs:707-717` scalar `endpoint.wg_peer_pubkey` | one peer per row | per-peer status (§5.8) |
| Live reconcile | `populate_wg_engines` rebuilds engine on identity change; `reconcile_peers` is only called from `WgEngine::new` (engine.rs:389) in production | a per-peer add/remove = full engine rebuild (drops sessions) | acceptable for B1 (a config change re-handshakes, TAI64N-seeded); NOTE it, do not wire live in-place reconcile unless session-preservation across peer add is required (S5) |

**Honest consequence:** "multi-peer" is NOT just RX + a config slice. The
egress side (encap + control-thread TUN egress + endpoint roaming + keepalive
timers) is uniformly single-peer via `first_peer_pubkey`. B1b is therefore a
real dataplane generalization touching the WG control thread + timer module +
encap frame builder — each per-packet/per-tick for WG. The `Peer` struct
already holds the per-peer state these need (per-peer session, endpoint,
T6/T7/T8 atomics, AllowedIPs via the PeerTable LPM), so the work is "iterate
peers / LPM-select peer" rather than new per-peer state — but it is genuine
hot-path-adjacent code. **This is why B1b is lab-RECOMMENDED, not lab-free.**
The timers.rs comment already names #1434 as the owner of this generalization.

### 5.1 Go config types — `pkg/config/types_routing.go`
- Add `WgPeerConfig` struct (§4 Path A). Add `WgPeers []WgPeerConfig` to
  `TunnelConfig`. Remove the scalar `WgPeerPubkeyHex/WgAllowedIPs/WgEndpoint/
  WgKeepaliveSecs` (keep `WgListenPort`/`WgLocalPrivkeyHex` — tunnel-level).
- Update `TunnelConfig.String()` to format `WgPeers` (count + per-peer redacted
  summary; NEVER log a PSK — add `PresharedKeyHex` to the redaction set, mirror
  the existing privkey `<redacted>` treatment).
- Migration: search all readers of the removed scalar fields (see §5.7) — every
  one moves to `WgPeers[i]` or `WgPeers[0]`.

### 5.2 Schema — `pkg/config/schema_interfaces.go`
- Convert `peer` to a named-instance container keyed by the pubkey:
  `"peer": {desc:"WireGuard peer", args:1, placeholder:"<public-key>",
  keyValueType: ValueAny-or-typed, children: {allowed-ips(multi), endpoint,
  persistent-keepalive[, preshared-key]}}`. Drop the `public-key` CHILD
  (identity moves to the instance arg) — OR keep `public-key` as a child and
  make `peer` a wildcard with a synthetic identity; §5.6 picks. Recommended:
  identity-as-arg (`peer <pubkey> { ... }`) matches Junos `peer <name>` /
  the named-instance contract and avoids an identity-vs-child ambiguity.
- Every new node carries a `desc:` (help-text discipline, config-schema.md:154).
- `allowed-ips` stays `multi: true` WITHIN a peer (it already is).

### 5.3 Compiler — `pkg/config/compiler_interfaces.go`
- Rewrite `parseTunnelWireguardPeer` to parse ONE peer instance node into a
  `WgPeerConfig` (read pubkey from the instance identity arg; allowed-ips/
  endpoint/keepalive[/preshared-key] from children) and APPEND to `tc.WgPeers`.
- `parseTunnelWireguard` `case "peer"` appends per instance (handle BOTH AST
  shapes: hierarchical `peer X { ... }` and flat `set ... peer X allowed-ips
  ...` — the dual-AST gotcha). **Concrete model:** mirror the proven
  `vrrp-group` named-instance handling — `namedInstances(node.FindChildren(
  "peer"))` collapses both AST shapes into one instance list (see
  `compiler_iface*.go` ~L341-358 `namedInstances(addrInst.node.FindChildren(
  "vrrp-group"))`), then read the pubkey from the instance identity and the
  leaves from its children. `vrrp-group` is `args:1` with a child block and is
  the closest existing analog (a repeatable instance under an interface unit).
- Honour the existing silent-bounds → typed-leaf-reject migration for
  keepalive (schema validator already enforces 0..65535).

### 5.4 Wire DTO — `pkg/dataplane/userspace/protocol.go` + `tunnels.go`
- Replace the scalar `Wg*` peer fields on `TunnelEndpointSnapshot` with
  `WgPeers []TunnelWgPeerWire` (new struct: `WgPeerPubkeyHex`,
  `WgAllowedIPs []string`, `WgEndpoint`, `WgKeepaliveSecs`[, `WgPresharedKeyHex
  json:"wg_preshared_key_hex,omitempty"`]). Keep `WgListenPort`/
  `WgLocalPrivkeyHex` (the latter stays `skip_serializing` on the Rust side).
- `tunnels.go` snapshot builder (line ~122): copy `tunnel.WgPeers` → snapshot,
  **sorted by pubkey hex** so both HA nodes serialize byte-identical snapshots
  (HA determinism — §8) and the wire fixture is stable.
- The outer-family heuristic (tunnels.go:93) currently sniffs `tunnel.
  WgEndpoint`; with multiple peers there may be mixed v4/v6 endpoints. Decision:
  outer family is a TUNNEL-level property (the kernel UDP socket binds one
  family). §5.6 — derive from the FIRST peer with an endpoint, or from an
  explicit tunnel-level hint; document the constraint that all peers on one WG
  interface share the outer transport family (true for WireGuard — one UDP
  socket). Add a commit-time check if peers mix families.

### 5.5 Commit-time validation — `pkg/config/schema_walk.go` / compiler
- **Dup-pubkey reject:** two `peer` instances with the same pubkey on one WG
  tunnel = hard commit error (satisfies the engine `debug_assert` contract,
  engine.rs:541). Loud, not silent.
- **Pubkey format:** 64-hex (32-byte X25519). Validate at commit (typed leaf or
  compiler check) — the engine `from_hex`s it; a bad key today fails silently
  at the dataplane.
- **Zero-peer = REJECT (LOCKED, SMR MINOR-3).** A WG tunnel with zero peers
  can never handshake; xpf has no dynamic peer learning (peers are
  config-static), so zero-peer is always an operator mistake.
  `reconcile_peers(&[])` is valid-but-useless (empty PeerTable). Hard
  commit-reject with a clear message ("wireguard tunnel <if> has no peer").
- **Mixed peer endpoint family = REJECT (LOCKED, SMR MINOR-2).** One WG
  interface = one kernel UDP socket = one outer transport family. If peers on
  one tunnel declare endpoints of mixed v4/v6 family, the outer-family sniff
  (`tunnels.go:93`) and outer-MTU calc (`pkg/routing/tunnel.go:1152`) cannot
  pick a single correct value and forwarding half-breaks silently. Make this a
  NAMED commit-time validator, not just documentation. (Peers with NO endpoint
  — responder-only — do not constrain the family; the family is set by the
  peer(s) that DO declare an endpoint, and they must all agree.)
- **AllowedIPs overlap across peers:** the engine LPM tolerates overlap
  (allowed_ips.rs:144 documents "overlap across peers"); LAST-inserted wins per
  the trie. Do NOT hard-reject overlap (valid WG configs overlap, e.g. a
  catch-all peer); optionally WARN. Document the longest-prefix-match decap
  routing semantics.

### 5.6 Design decisions — LOCKED by the review rounds
- (a) **Schema = identity-as-arg** (`peer <pubkey> { allowed-ips … }`), modeled
  on `vrrp-group` (`namedInstances` dual-AST). LOCKED.
- (b) **Outer-family: one family per WG interface; mixed peer-endpoint family =
  commit REJECT** (one UDP socket = one outer family). Family derived from the
  peer(s) that declare an endpoint; they must agree. LOCKED (§5.5).
- (c) **Zero-peer = commit REJECT** (xpf has no dynamic peer learning; a
  peerless WG tunnel can never handshake). LOCKED (§5.5, SMR MINOR-3).
- (d) **PSK (B2): may ride the B1 PR** — §6.3 RESOLVED via snow `set_psk`, no
  ordering blocker; split to a follow-on ONLY if the secret-hygiene review (R3)
  proves heavy. LOCKED disposition (§10).

### 5.7 Migration sweep (callers of the removed scalar fields)
Confirmed readers to migrate, scoped to the main checkout at HEAD cf9ccd3ac
(grep `Wg(PeerPubkeyHex|AllowedIPs|Endpoint|KeepaliveSecs)` over `pkg/ cmd/
userspace-dp/`, worktrees excluded):
- `pkg/config/types_routing.go` — `String()` (rewrite to format the slice +
  redact privkey AND any PSK).
- `pkg/config/compiler_interfaces.go` — the parser (rewritten, §5.3).
- `pkg/dataplane/userspace/tunnels.go` — snapshot builder (line ~122) +
  outer-family sniff (line ~93, reads `tunnel.WgEndpoint`) + GRE source/dest
  gate (line 58-64, keys on `isWireguard`/`tunnel.WgEndpoint`).
- `pkg/dataplane/userspace/protocol.go` — the wire DTO (§5.4).
- **`pkg/routing/tunnel.go:1152`** — the WG outer-MTU calc reads
  `tc.WgEndpoint` to size IPv4-vs-IPv6 outer overhead. With multi-peer this is
  a TUNNEL-level decision (one UDP socket, one outer family — §5.4/5.6b);
  migrate to read the tunnel's resolved outer family, not a per-peer endpoint.
  (This site was found only by the scoped sweep — call it out explicitly.)
- Tests touching these fields: `pkg/config/parser_routing_test.go`,
  `pkg/dataplane/userspace/{tunnels_test.go,manager_test.go}`,
  `pkg/daemon/tunnel_anchor_test.go` — update to the slice shape.

**Confirmed NOT readers of the scalar peer fields (no migration needed):**
- The `show security wireguard` CLI renderer reads from the DATAPLANE STATUS
  (`pkg/cli/cli_show_security_wireguard.go` → `provider.Status()` →
  `dpuserspace.FormatWireguardStatus`), NOT the config scalar.
  **CLI-peer-cardinality — RESOLVED to MANDATORY B1 scope (was SMR MINOR-1).**
  Verified: the status row is one-peer-shaped AND reads the scalar snapshot
  fields B1 deletes, so it is a forced migration site, not an optional display
  improvement. See §5.8 "Status row is a MANDATORY migration site". The
  renderer (`FormatWireguardStatus` in `wgfmt.go`) + Go `WgTunnelStatus` mirror
  (`protocol.go:752`) are widened to per-peer in B1.
- `logWgEndpointSetTransitionLocked` / its summary (`tunnels.go:212`) formats
  only `ep.WgListenPort` (tunnel-level) — unaffected.
- `pkg/daemon/daemon_run.go:141` is a COMMENT, not a read — unaffected.

### 5.8 Rust changes (B1a table-feeding + status; B1b egress — see §5.0.1)
- `userspace-dp/src/protocol/snapshot.rs:341-374` — replace scalar WG peer
  fields on `TunnelEndpointSnapshot` with `wg_peers: Vec<TunnelWgPeerSnapshot>`
  (new serde struct mirroring the Go wire DTO; keep `wg_listen_port`/
  `wg_local_privkey_hex(skip_serializing)` tunnel-level).
- `userspace-dp/src/afxdp/forwarding_build/wg.rs:48-72` — loop
  `endpoint.wg_peers` building one `WgPeerConfig` each; `peers: <the vec>`.
- `wg.rs:87-94` `wg_identity_unchanged` — compare the peer slices
  (order-stable, since the Go builder sorts by pubkey). If the slice differs,
  rebuild (engine seeds TAI64N high-water as today).
- **(B1b) `frame/wg.rs:44-142` `wg_encap_frame`** — replace the scalar
  `endpoint.wg_peer_pubkey` / `endpoint.wg_endpoint` reads with an
  inner-destination → peer selection (engine LPM lookup over the PeerTable),
  then `try_encap(&selected_peer_pubkey, ...)` toward the selected peer's
  endpoint + that endpoint's outer family. This is the encap migration AND the
  new cryptokey-routing mechanism (§5.0). It is ALSO a migration site (it reads
  the removed scalar) — so B1a, if shipped before B1b, must keep the encap path
  compiling: B1a can either retain `WgPeers[0]`'s pubkey/endpoint at the encap
  site as an interim (single-peer encap, RX multi-peer) or B1a+B1b ship
  together. Recommend B1a+B1b in ONE PR so "multi-peer" is end-to-end (in AND
  out) in a single reviewed change; the encap test is a Rust integration test
  (lab-recommended, not lab-blocked — §5.0).
- Confirm `endpoint.wg_local_privkey` / `wg_listen_port` paths unchanged.
- NO engine, NO reconcile_peers, NO PeerTable change for B1.

**Status row is a MANDATORY migration site (escalated from SMR MINOR-1 —
verified, NOT optional).** `coordinator/status.rs:655-717`
(`wg_tunnel_statuses`) builds a `WgTunnelStatus` per ENDPOINT, reading the
SCALAR `endpoint.wg_peer_pubkey` / `endpoint.wg_endpoint` and
`peer_has_confirmed_session(&endpoint.wg_peer_pubkey)`. B1 removes those scalar
snapshot fields, so this code WILL NOT COMPILE unless updated. The
`WgTunnelStatus` struct (`protocol/snapshot.rs` + Go mirror
`protocol.go:752`, scalar `PeerPubkeyHex`/`PeerEndpoint`) and the
`FormatWireguardStatus` renderer (`pkg/dataplane/userspace/wgfmt.go:33-38`, scalar `t.PeerPubkeyHex`/`t.PeerEndpoint` per row) are ALL one-peer-shaped. B1 must reshape the
status row to per-peer (e.g. `WgTunnelStatus { ..., peers: Vec<WgPeerStatus> }`
where `WgPeerStatus` carries `pubkey_hex`, `endpoint`, `has_confirmed_session`,
per-peer handshake/rekey counters) and update the Go mirror + renderer to
iterate. This is REAL B1 scope (Rust status + Go protocol + Go renderer + the
`show security wireguard` golden output), not a follow-on. It does NOT need the
lab — it is config/telemetry plumbing, gated by `cargo test` + `make test` +
the existing CLI render test. The engine already exposes per-peer state
(`peer_has_confirmed_session` is per-pubkey; the engine iterates its
PeerTable), so the data is available — only the status DTO is too narrow.

---

## 6. Path-PSK — per-peer preshared key (sub-increment B2)

### 6.1 Why it is harder than the slice (but NOT a blocker)
PSK is mixed into the Noise IKpsk2 transcript at message 2 (psk index 2). The
engine sets the PSK at snow **Builder** time today (`.psk(2, &WG_ZERO_PSK)`),
but snow 0.10.0 ALSO supports `set_psk` AFTER build (§6.3), so the responder's
"identify peer, then pick PSK" ordering is solvable. For the INITIATOR it is
trivially easy — we know the peer (and its PSK) before building
(`build_initiator_handshake(&peer_pubkey)`, engine.rs:1145), so the initiator
path selects the peer's PSK instead of `WG_ZERO_PSK`. The responder is the only
subtlety, and §6.3 resolves it. The remaining cost is an engine field +
plumbing + secret hygiene — NOT a protocol-ordering blocker.

### 6.2 Initiator path (easy)
`build_initiator_handshake` already takes `peer_pubkey`; look up the peer's PSK
from the PeerTable and pass `.psk(2, &peer_psk)`. One-line conditional.

### 6.3 Responder path (RESOLVED — `set_psk` mid-handshake, version-confirmed)
`build_responder_handshake` (engine.rs:1177) builds the snow responder state
with `.psk(2, &WG_ZERO_PSK)` BEFORE reading msg1. But the peer identity is only
known AFTER `read_message(msg1)` via `get_remote_static`
(`handshake_session.rs:465-477`). The PSK belongs to the identified peer, so it
must be set AFTER identification but BEFORE `write_message(msg2)`.

**VERIFIED against the pinned snow 0.10.0 (`userspace-dp/Cargo.lock`):**
- In `IKpsk2`, the `Psk(2)` token is appended to the END of the SECOND message
  pattern: `apply_psk_modifier(n=2)` does `patterns.get_mut(n-1=1)` (the 2nd
  message) `.push(Token::Psk(2))` —
  `snow-0.10.0/src/params/patterns.rs:533-545`. So the PSK is mixed
  (`mix_key_and_hash`) only while message 2 is processed — i.e. during the
  responder's `write_message(msg2)`
  (`handshakestate.rs:262-266`/`396-401`), AFTER `read_message(msg1)`.
- snow `HandshakeState` exposes a PUBLIC `set_psk(location, key)`
  (`handshakestate.rs:457`) usable AFTER construction, mid-handshake.

**Resolution (B2-ii, clean — no rebuild, no re-read):** the responder builds
its state, `read_message(msg1)`, `get_remote_static` → peer, looks up the
peer's PSK, calls `state.set_psk(2, peer_psk)`, then `write_message(msg2)`
which mixes the now-correct PSK. The initiator already knows the peer at build
time (§6.2) and can either `.psk(2, peer_psk)` at Builder time or `set_psk`
after build — symmetric. **No "rebuild + re-read msg1" fallback is needed.**
(The DRAFT-v1 of this plan proposed that conservative B2-i fallback under the
false premise that snow could not set PSK mid-handshake; the source check
refutes that premise — see the Claude SMR self-catch.)

**Bound on engine API change:** B2 still requires a NEW per-peer
`preshared_key: [u8;32]` on the engine's `WgPeerConfig` + plumbing into the two
handshake builders + the `set_psk` call site. That is a real (small) ENGINE
change, distinct from B1 which touches NO engine code. The B1/B2 gate is
therefore secret-hygiene (R3) and the engine-edit blast radius, NOT a snow
ordering blocker. **B2 can ride B1's PR** given §6.3 resolves cleanly (it
does); split B2 only if the secret-hygiene review (R3) proves non-trivial.

### 6.4 PSK data-model wiring (if B2 in scope)
- Go: `WgPeerConfig.PresharedKeyHex string` (§4). Schema: `preshared-key`
  child of `peer`. Compiler: parse + 64-hex validate. Redact in String().
- Wire: `wg_preshared_key_hex` on the per-peer wire struct, `omitempty` +
  `skip_serializing`-equivalent hygiene (PSK is a SECRET — must NEVER hit a
  status snapshot, a log, or the wire fixture in cleartext; mirror the privkey
  `skip_serializing` on the STATE-snapshot path while still delivering it on
  the CONFIG-snapshot path the engine consumes — verify the two snapshot paths
  are distinct, as privkey already is).
- Rust: `WgPeerConfig.preshared_key: [u8;32]` (NEW engine field — this IS an
  engine change, unlike B1) wired into both handshake builders (§6.2/6.3).
- Secret hygiene is the dominant review surface for B2.

---

## 7. Wire fixture + test strategy

### 7.1 Wire fixture regen
- `userspace-dp/tests/fixtures/protocol_wire_v1.json` MUST be regenerated: the
  WG endpoint row changes from scalar `wg_peer_pubkey_hex/wg_endpoint/
  wg_keepalive_secs/wg_allowed_ips` to `wg_peers: [ { ... } ]`. Per project
  memory (Campaign-2 lesson) a wire-field PR MUST regen the fixture and any
  `protocol_wire_v1.json`-pinning round-trip test.
- Regen mechanism CONFIRMED: the fixture is a golden pinned by
  `userspace-dp/src/protocol/tests.rs` (load + compare, ~line 1063-1196).
  Regenerate by running that test with `XPF_PROTOCOL_WIRE_REGEN=1`, then review
  the diff and commit it. No separate generator binary — the test IS the
  generator.
- Add a TWO-PEER fixture row (or a dedicated dual-peer fixture) so the wire
  shape is pinned with N>1.

### 7.2 Go tests
- `parseTunnelWireguard` single-peer compile (regression — existing config
  still compiles to `WgPeers[0]`).
- Dual-peer compile (hierarchical AST) → `len(WgPeers)==2`, per-peer fields
  correct, allowed-ips NOT merged across peers.
- Flat `set` dual-peer (`ParseSetCommand` + `SetPath` loop — NEVER NewParser,
  per the dual-AST gotcha) → same result.
- Dup-pubkey → commit error. Bad-hex pubkey → commit error. Zero-peer →
  commit error (or allow, per §5.6c).
- Snapshot builder: `TunnelConfig{WgPeers:[2]}` → `TunnelEndpointSnapshot{
  WgPeers:[2]}` sorted by pubkey (HA-determinism assertion: two builds of the
  same config produce byte-identical JSON).
- HA config-sync round-trip: a dual-peer config survives forward + reverse
  sync (the config text is shipped, not the compiled form — §8).

### 7.3 Rust tests
- `snapshot.rs` deserialize: `wg_peers: [ {...}, {...} ]` round-trips.
- `populate_wg_engines`: a two-peer endpoint builds one engine with a
  two-entry PeerTable (extend the existing `two_tunnel_snapshot` family with a
  genuine TWO-WG-PEER fixture — note the existing one is GRE+WG, not two
  peers).
- `wg_identity_unchanged`: peer-slice add/remove/reorder triggers/avoids
  rebuild correctly.
- B2 (if in scope): initiator + responder PSK handshake unit test (two engines,
  matching PSK → handshake succeeds; mismatched PSK → fails). This is a UNIT
  test (no kernel WG) and is in scope; the LIVE kernel-WG / Ubiquiti interop
  stays in #1703.

### 7.4 Lab gating per sub-increment (corrected by §5.0)
- **B1a (config + RX + status): no smoke / no lab.** Config-model + wire +
  build-path + per-peer status; RX/decap is already multi-peer so inbound is
  exercised by feeding the engine N peers. Does NOT touch the verifier-gated
  shim or `make generate`. `make test` + `cargo test` + CLI render test are the
  gates.
- **B1b (TX encap cryptokey routing): lab-RECOMMENDED.** The encap peer
  selection is hot-path-adjacent. A Rust integration test that drives
  `wg_encap_frame` with a two-peer engine and asserts the chosen
  pubkey/endpoint per inner-dst gives high confidence WITHOUT the cluster; a
  loss-cluster two-peer traffic run is the line-rate/real-handshake
  belt-and-braces (recommend, not block). NO `make generate` (the shim/listen
  port is unchanged — Axis A's shim work is NOT in play).
- The live multi-peer handshake VERIFICATION (Ubiquiti / kernel-WG) is
  explicitly the #1703 lab. (Contrast Axis A, which DOES need shim + lab.)

---

## 8. HA config-sync impact
HA config sync ships the **full config TEXT** to the peer
(`pkg/cluster/sync_conn.go:566` `QueueConfig sends the full config text`), not
the compiled snapshot. So a multi-peer WG stanza syncs as text and is
re-compiled identically on the peer — no new sync wire format. The load-bearing
requirement is COMPILE DETERMINISM: both nodes must compile the same text to
byte-identical snapshots, which the §5.4 sort-by-pubkey guarantees. Add the
HA-determinism assertion to the test set (§7.2). The `${node}` variable
quoting and reverse-sync-on-reconnect paths are unaffected (WG peer fields are
not node-scoped). No `pkg/cluster` code change expected — confirm in round 1.

---

## 9. Risk register
- **R1 — wire ABI bump.** Changing the snapshot WG shape is a Go↔Rust wire
  break. Both sides ship together (single PR, both binaries). The fixture regen
  catches drift. Mitigation: keep `wg_peers` additive-shaped and confirm the
  daemon+helper are version-locked (they are — same build/deploy). Verify no
  stored-config compat issue (config is TEXT, recompiled — a stored single-peer
  config still parses into `WgPeers[0]`; the SNAPSHOT is transient, not
  persisted). CONFIRMED at HEAD: `ConfigSnapshot` has no `json.Marshal`+
  `WriteFile`/`os.Create`/`Save`/`Encode`-to-disk site in `pkg/` — it is built
  per-apply and pushed over the control socket, never written to the config DB.
  So there is NO on-disk snapshot migration. (Stored config is TEXT, recompiled
  — a single-peer stored config recompiles into `WgPeers[0]`.)
- **R2 — dup-pubkey silent mis-route.** Engine only `debug_assert`s; release
  builds would mis-index. Mitigation: §5.5 commit-time hard reject (the engine
  contract's named owner). Load-bearing — test it.
- **R3 — PSK secret leak (B2).** A PSK in a log/status-snapshot/fixture is a
  security defect. Mitigation: §6.4 hygiene mirrors the proven privkey
  `skip_serializing` + String() redaction; the secret-redaction review is the
  B2 gate. If hygiene is non-trivial, B2 splits.
- **R4 — responder PSK ordering (B2). RETIRED.** §6.3 — snow 0.10.0 `set_psk`
  resolves it cleanly (responder reads msg1, identifies the peer, `set_psk(2,
  peer_psk)`, then `write_message(msg2)` mixes it). No rebuild, no re-read. The
  draft's B2-i fallback is unnecessary (SMR MAJOR-1). Residual risk is only the
  small engine-field plumbing, folded into R3.
- **R5 — outer-family with mixed-endpoint peers.** §5.4/5.6b — constrain to one
  family per WG interface (true for one UDP socket); commit-reject mixed.
- **R6 — HA non-determinism from unsorted peers.** §5.4 sort-by-pubkey;
  asserted in tests (§7.2). A map (Path B) would have made this worse — another
  reason for Path A.
- **R7 — scope creep into Axis A / S6 grammar.** Explicitly out of scope (§2);
  the plan stays the minimal generic stanza.

## 10. Disposition / recommendation
**PLAN-READY** (B1 as a whole; the increment scope is corrected by the §5.0 /
§5.0.1 hot-path audit, which is the substantive output of this review).

> Headline correction vs the parent framing: this is NOT "just a Go config
> slice". The Go config model IS the operator-facing blocker, but the dataplane
> is multi-peer only on RX/decap; the entire EGRESS machinery (encap peer
> selection, the WG control-thread TUN egress + endpoint roaming, and the
> keepalive/rekey timers) is single-peer via `first_peer_pubkey`
> (§5.0.1 table). A faithful "configure N peers per WG interface" feature must
> generalize that egress machinery. The config slice unblocks the operator
> surface; B1b finishes the dataplane.

- **B1a (driveable-now, lab-free) — config + RX multi-peer + status, egress
  pinned to peer[0] as an explicit INTERIM.** Go config slice (Path A) + schema
  named-instance (`peer <pubkey>`, vrrp-group model) + compiler loop +
  commit-time validators (dup-pubkey / bad-hex / zero-peer / mixed-family all
  REJECT) + wire DTO slice + build-path loop feeding the engine N peers +
  per-peer status row (Rust+Go+renderer) + fixture regen. RX/decap is ALREADY
  multi-peer, so inbound-from-N-peers works. **This is a PARTIAL feature:
  inbound from N peers works, outbound still goes to peer[0]
  (`first_peer_pubkey`).** Honest, useful for "many spokes initiate to one
  hub" (the spokes drive egress; the hub mostly responds on the session the
  spoke established — verify this covers the common topology before shipping
  B1a alone). Gated by `make test` + `cargo test` + CLI render test. No shim,
  no `make generate`, no lab. **Only ship B1a standalone if a partial
  (RX-multi/TX-peer[0]) feature is explicitly acceptable; otherwise B1a is the
  first commit of the B1a+B1b PR, not a release.**

- **B1b (lab-RECOMMENDED) — egress generalization.** Encap peer selection by
  inner-dst AllowedIPs LPM (`frame/wg.rs` + a small engine lookup) + WG
  control-thread per-peer TUN egress & endpoint roaming
  (`coordinator/wg_control.rs`) + per-peer keepalive/rekey timers
  (`wg/timers.rs`, iterate all peers). The `Peer` struct already holds the
  per-peer state; the work is "LPM-select / iterate peers", but it is genuine
  hot-path-adjacent code. Rust two-peer integration tests give high confidence;
  the loss cluster two-peer traffic + keepalive run is the
  line-rate/real-behavior belt-and-braces. **Recommend B1a+B1b in ONE PR** so
  "multi-peer" is end-to-end (in AND out, with per-peer keepalive); split only
  if the egress change wants its own perf pass.

- **B2 (per-peer PSK):** in scope per directive. §6.3 RESOLVED — snow 0.10.0
`set_psk` mid-handshake lets the responder pick the peer's PSK after
`get_remote_static`, so there is NO snow-ordering blocker (the draft's
rebuild-and-re-read fallback was unnecessary; SMR MAJOR-1 self-catch). B2 adds
a per-peer engine `preshared_key` field + plumbing into both handshake builders
+ the `set_psk` call site + secret hygiene (R3). It MAY ride B1's PR; split to
a focused follow-on ONLY if the secret-hygiene review (R3) proves heavy. R4
(responder ordering) is retired by the §6.3 resolution.

**Deferred (NOT this plan):** Axis A shim multi-PORT steering (prior plan
Increment 2 / lab); live multi-peer handshake + Ubiquiti interop (#1703);
full Junos `wireguard` S6 grammar; per-peer MSS/DSCP.

## 11. Verification plan (what `/engineer` must produce)
1. **B1a — `make test` green** incl. new single+dual-peer compile, dup-pubkey /
   bad-key / zero-peer / mixed-family REJECT, snapshot-builder HA-determinism
   (two builds byte-identical), HA config-sync round-trip (dual-peer text
   survives forward+reverse sync). Migrate `pkg/{config,dataplane/userspace,
   daemon}` tests off the scalar fields.
2. **B1a — `cargo test` green** incl. snapshot dual-peer round-trip,
   `populate_wg_engines` two-peer PeerTable, `wg_identity_unchanged` slice
   cases, per-peer status row (`wg_tunnel_statuses` emits N rows).
3. **B1a — regenerated `protocol_wire_v1.json`** with a dual-peer WG row whose
   source peers are AUTHORED out of pubkey-sort order but appear SORTED in the
   golden (exercises the §5.4 sort-by-pubkey determinism). Rust round-trip
   passes via `XPF_PROTOCOL_WIRE_REGEN=1` then commit.
4. **B1b — `cargo test` green** incl. a `wg_encap_frame` two-peer integration
   test: inner pkt to peer-X's AllowedIPs encaps to X's pubkey+endpoint, inner
   to peer-Y's encaps to Y; a timer-tick test asserting BOTH peers get
   keepalive servicing (not just `first_peer_pubkey`).
5. **B1b — loss-cluster two-peer traffic + keepalive run (lab-recommended)**:
   two peers on one WG interface, traffic both directions to each peer's
   AllowedIPs, per-peer keepalive observed. NOT strictly a merge gate if the
   integration tests + parent review are strong, but recommended belt-and-braces.
6. `TunnelConfig.String()` redacts privkey AND (if B2) PSK — a test that FAILS
   if the redaction is removed (per the durability-test-must-fail-if-effect-
   removed lesson).
7. Doc updates: `docs/config-schema.md` (the `peer <pubkey>` named-instance +
   typed leaves), the WG operator/protocol doc, `pkg/dataplane/userspace`
   README if it documents the WG snapshot shape, and `_Log.md`. Note the
   single-peer→multi-peer egress generalization in the WG design doc.
8. Quad review (Codex + AGY + Claude SMR + Copilot) on the implementation PR;
   merge on 4-of-4 (Copilot-infra exception per project rules). Any change
   touching the WG control thread / timers / encap is hot-path-adjacent —
   re-confirm no per-packet allocation regression (engineering-style hot-path
   rules).
9. Live multi-peer handshake against kernel-WG / Ubiquiti remains the #1703 lab
   — NOT a B1 merge gate.

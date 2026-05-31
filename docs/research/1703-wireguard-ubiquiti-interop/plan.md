# #1703 — WireGuard interop with Ubiquiti (UniFi Network 10.4+, EdgeOS, UDM): research plan

Revision: r1 (DRAFT for 3-way hostile review — Codex + AGY + Claude-SMR)
Branch: `research/1703-wireguard-ubiquiti-interop`
Scope: `/research` only. No production code, no PR. Deliverable = converged
plan-of-action + 3-reviewer verdicts + issue comment. Implementation gated on
`/engineer`.

---

## 1. Problem statement

Can xpf establish a WireGuard tunnel to a Ubiquiti router — primarily **UniFi
Network 10.4+** WireGuard VPN (server and client/site-to-site), secondarily
EdgeOS/EdgeRouter `wireguard` and UDM/UDM-Pro? WireGuard is a fixed protocol:
a byte-compliant implementation interoperates with any other compliant
implementation regardless of vendor. So the question decomposes into two
independent gates:

1. **Wire compliance** — does xpf put the exact WireGuard bytes on the wire
   (handshake messages type 1–4, MAC1/MAC2, TAI64N timestamp, transport-record
   framing, the `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` construction + the
   `WireGuard v1 zx2c4 Jason@zx2c4.com` identifier)?
2. **Operator config + dataplane activation** — can an operator actually
   *configure* a WG peer (local privkey, peer pubkey, endpoint, allowed-ips,
   keepalive, PSK, MTU) through the Junos-style config, and does the dataplane
   actually *run* the engine on the hot path?

The recon in the issue suspected a config-surface gap. Walking the code shows
the gap is **much larger than config**: the WG engine is a self-contained,
well-tested crypto/replay/AllowedIPs library that is **(a) not wired into the
dataplane hot path at all, (b) does not build the WireGuard handshake on-wire
framing or the TAI64N timestamp, (c) cannot be configured with a non-zero PSK,
and (d) has no Junos config surface and no Go control-plane population path.**

This is a **NOT-YET-INTEROPERABLE** verdict. The deliverable is a staged
build-out plan, not an interop test.

---

## 2. Evidence: what xpf's WireGuard actually is today

All paths relative to repo root; line numbers as of `origin/master`
(`c0352c273`).

### 2.1 The engine is a tested library that is NOT on the hot path

- `userspace-dp/src/afxdp/mod.rs:127-129`: the ONLY production reference to the
  module is `#[path = "wg/mod.rs"] mod wg;`, immediately preceded by the comment
  *"Engine + tests only in this PR; hot-path activation lands in a follow-up."*
- `userspace-dp/src/afxdp/wg/mod.rs:28`: `#![allow(dead_code)] // Most of this
  module is not yet wired into the hot path.`
- `userspace-dp/src/afxdp/wg/mod.rs:5-9`: *"Hot-path activation in
  `tx/dispatch.rs` and `poll_descriptor.rs` is intentionally deferred."*
- `grep -rn "WgEngine::new" userspace-dp/src/` returns **only `tests.rs` and
  `engine.rs` test modules** — `WgEngine` is never constructed in any
  production code path. The dispatch encap sites
  (`afxdp/frame/mod.rs:212`, `afxdp/frame/tcp_segmentation.rs:309`,
  `afxdp/tunnel.rs:189`) unconditionally call `encapsulate_native_gre_frame`;
  none branch on a WireGuard mode. The ingress classifier
  (`poll_descriptor.rs`) has no WG decap point.

Conclusion: **even if every byte were perfect, no packet would ever reach the
engine.** Interop is impossible today regardless of correctness.

### 2.2 The on-wire HANDSHAKE framing does not exist (interop-blocking)

The engine deliberately builds only the *Noise sub-message bytes*, not the
WireGuard handshake messages. This is stated as an explicit out-of-scope
boundary in three places:

- `userspace-dp/src/afxdp/wg/engine.rs:26-35`: *"Out of scope for this engine
  (integration PR owns these): Building / parsing the on-wire WG handshake
  framing (MessageInitiation/MessageResponse: MAC1 over a hash of the
  responder's public key, MAC2 cookie reply when under load, TAI64N timestamp
  inside the IK payload)."*
- `docs/pr/wireguard-clean/plan.md:432-456` ("On-wire handshake framing scope")
  spells it out: *"This engine does NOT build or parse the WireGuard handshake
  message on-wire framing (type-1 MessageInitiation, type-2 MessageResponse,
  type-3 CookieReply, MAC1/MAC2 fields, the TAI64N timestamp slot ...)."*
- `docs/pr/wireguard-clean/plan.md:467-470` lists *"WG handshake outer-framing
  layer (MessageInitiation/MessageResponse outer bytes around the Noise
  sub-message, MAC1/MAC2, TAI64N)"* under "What's OUT".

What the WireGuard spec requires for a type-1 initiation
(https://www.wireguard.com/protocol/, verified 2026-05-30):

```
u8  message_type = 1
u8  reserved_zero[3]
u32 sender_index
u8  unencrypted_ephemeral[32]
u8  encrypted_static[AEAD_LEN(32)]      <- Noise 's' token
u8  encrypted_timestamp[AEAD_LEN(12)]   <- TAI64N, as the Noise PAYLOAD
u8  mac1[16]
u8  mac2[16]
```

- `mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(mac1)])`
  with `LABEL_MAC1 = "mac1----"`.
- `mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(mac2)])` or zeros.
- The TAI64N timestamp is carried as `encrypted_timestamp`, i.e. it is the
  **Noise payload of message 1**.

What xpf produces: `engine.build_initiator_handshake(...)` returns a snow
`HandshakeState`; the caller (today only tests) does
`init_hs.write_message(&[], &mut buf)` — `tests.rs:79`, `:281`, `:306`, `:577`,
`:866`, `:890`. This yields ONLY the Noise IK message-1 bytes
(`unencrypted_ephemeral || encrypted_static || encrypted_timestamp-slot`), and:

- **No `message_type` byte, no `reserved_zero[3]`, no `sender_index`.** A real
  WG peer parses byte 0 as the type and demuxes on `sender_index`; xpf's bytes
  start at the ephemeral, so a UniFi/kernel peer rejects the datagram as
  malformed before any crypto.
- **No `mac1`/`mac2` trailer.** Kernel WG and UniFi (which sits on the kernel WG
  data path) silently drop any handshake whose `mac1` does not verify against
  `HASH("mac1----" || our_pubkey)`. This is a hard gate, not advisory.
- **Empty Noise payload ⇒ no TAI64N timestamp.** `write_message(&[], ...)` sends
  a zero-length payload, so `encrypted_timestamp` is absent/empty. A compliant
  responder needs a monotonic TAI64N to run its anti-replay-on-handshake check;
  kernel WG treats a missing/short timestamp as a malformed initiation.

The Noise *transcript init* IS correct: snow computes
`h = HASH(protocol_name)` (37-byte `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
> 32 ⇒ hashed) then `MixHash(prologue)` = `HASH(h || prologue)`, and
`WG_PROTOCOL_ID_BYTES = "WireGuard v1 zx2c4 Jason@zx2c4.com"`
(`wg/mod.rs:82`) is the exact IDENTIFIER. This reproduces WG's
`Ci = HASH(CONSTRUCTION); Hi = HASH(HASH(Ci||IDENTIFIER)||responder.static)`.
So the **inner Noise crypto is spec-correct; the missing layer is purely the
WG outer framing + MAC + timestamp**, which the plan doc itself scopes out.

### 2.3 The transport-DATA record framing IS spec-compliant

`wg/framing.rs:42-98` + `wg/mod.rs:84-105`: type=4, 3 reserved bytes,
little-endian `receiver_index` u32, little-endian `counter` u64, ciphertext ||
16-byte Poly1305 tag. Nonce = `[0,0,0,0] || counter_LE` (`framing.rs:19-38`,
matching snow's resolver and WG whitepaper §5.4.6). §5.4.6 16-byte padding is
applied on encap (`engine.rs:530-552`) and trimmed on decap
(`engine.rs:842-889`). Replay window is RFC 6479 64-bit
(`session.rs:177-256`); `REJECT_AFTER_MESSAGES = u64::MAX - 2^13`
(`session.rs:28`, test `:350`). This layer would interoperate **if** a session
ever got established — but it can't, because the handshake never completes.

### 2.4 PSK is hardcoded to all-zero (config-blocking for PSK peers)

`wg/engine.rs:800` and `:823`: both `build_initiator_handshake` and
`build_responder_handshake` call `.psk(2, &WG_ZERO_PSK)?`. `WG_ZERO_PSK` is
`[0u8; 32]` (`wg/mod.rs:69`). There is **no parameter, field, or code path** to
supply a non-zero preshared key. `grep -rn "psk" wg/` finds only the
all-zero constant and its three uses.

UniFi exposes an optional PSK
(https://help.ui.com/.../WireGuard-VPN-Server — the generated client config
contains a `PresharedKey` line; third-party guides confirm UniFi recommends
enabling it). If a UniFi peer is configured with a PSK, the IKpsk2 `psk2` mix
differs and the handshake **fails the AEAD tag on message 2**. xpf cannot match
a PSK peer today. (When the UniFi peer has NO PSK, the all-zero PSK is correct
and this is a non-issue — but the operator has no way to turn it on.)

### 2.5 No Junos config surface, no Go control-plane population

- `git grep -il wireguard pkg/config/` → **empty**. `git grep -il wireguard
  pkg/cmdtree/` → **empty**. `pkg/compiler` does not exist; the compiler lives
  in `pkg/config/compiler*.go` and has no WG handling.
- `pkg/config/types.go:1909-1921` — `TunnelConfig.Mode` is documented `// "gre"
  or "ipip"`. There is no WireGuard mode, no peer pubkey, no private key, no
  allowed-ips, no keepalive, no PSK field anywhere in the config types.
- `pkg/dataplane/userspace/tunnels.go:73-90` builds `TunnelEndpointSnapshot`
  from `config.TunnelConfig` and sets `Mode: tunnel.Mode` plus GRE fields
  (Source/Destination/Key/TTL). It **never sets any `Wg*` field.**
- The wire DTO `Wg*` fields exist on BOTH sides but are dead:
  - Go: `pkg/dataplane/userspace/protocol.go:298-314`
    (`WgListenPort`, `WgLocalPrivkeyHex`, `WgPeerPubkeyHex`, `WgAllowedIPs`,
    `WgEndpoint`, `WgKeepaliveSecs`).
  - Rust: `userspace-dp/src/protocol/snapshot.rs:341-374` (matching `wg_*`
    fields; `wg_local_privkey_hex` is `skip_serializing` + redacted Debug).
  - `git grep "WgPeerPubkeyHex" pkg/ | grep -v _test.go` shows the field is
    referenced **only in its own struct definition** — nothing populates it.
- The runtime `TunnelEndpoint` (`afxdp/types/forwarding.rs`) is NOT extended
  with WG fields (plan doc:413-421 confirms this was deliberately deferred), so
  even the wire DTO cannot reach the runtime forwarding type.

So the chain `Junos config → typed Go struct → snapshot DTO → Rust runtime
→ engine` is **broken at every single link** for WireGuard.

### 2.6 persistent-keepalive, endpoint roaming, MTU/MSS — state of each

- **persistent-keepalive**: `peer.rs:60` has an `AtomicU16 persistent_keepalive`
  field and `WgPeerConfig.persistent_keepalive` (`engine.rs:166`), but `peer.rs`
  has the explicit `TODO(#1499 r4 / timers)` (`:49-59`): *"the engine has zero
  time-based state ... the integration PR will introduce a coordinator-side
  ticker."* No keepalive packet is ever emitted; no REKEY/REJECT-AFTER-TIME
  timer exists. UniFi behind NAT needs ~25 s keepalive
  (https://www.wireguard.com/quickstart/ confirms 25 s NAT-keepalive default).
- **endpoint roaming**: `peer.rs:34-43` `TODO(#1499 r4 / roaming)`: the spec
  mandates updating the peer endpoint when an authenticated packet arrives from
  a new src; *"the data path to invoke it requires the integration layer."* Not
  implemented. UniFi/EdgeOS often use DDNS endpoints; xpf has no re-resolve or
  roam.
- **MTU / MSS**: `wg/mss.rs:80` `wg_tcp_mss(outer_family, inner_family, mtu)` is
  correct and tested (v4 overhead 60 B, v6 80 B, +15 B worst-case §5.4.6
  padding ⇒ MSS 1385 at MTU 1500; tests `:105-183`). But the call site
  (`tx/dispatch.rs:1458`) short-circuits TCP segmentation for ANY
  `tunnel_endpoint_id != 0` (plan doc:338-349), so the WG MSS path is never
  hit. UniFi default tunnel MTU is 1420; the math is compatible, but unwired.
- **AllowedIPs**: `wg/allowed_ips.rs` is a sorted-by-prefix-len Vec used ONLY on
  the decap src-IP gate (cryptokey-routing-safe; egress peer is chosen by
  explicit pubkey, not LPM — `engine.rs:506-509`). Supports v4+v6 and
  `0.0.0.0/0` (`ipnet::IpNet`). Multiple allowed-ips per peer is supported
  (`WgPeerConfig.allowed_ips: Vec<IpNet>`). This layer is fine; it just has no
  config feed.

### 2.7 IPv6 outer encap not built; cookie/rate-limit reply absent

- plan doc:477-478 — IPv6 OUTER encap is out of scope (engine is
  family-agnostic but the outer-header builder was v4-only; note `outer.rs` was
  since deleted in #1440, `wg/mod.rs:35-42`, so the integration must use
  `frame/headers.rs`). UniFi WG VPN listens on UDP and accepts v4 or v6 outer;
  v4 outer is the common case, so this is a secondary gap.
- plan doc:476 — RFC 7901 cookie/rate-limit reply path (type-3 CookieReply) is
  OUT. This only matters under load/DoS; not interop-blocking for a quiet
  tunnel, but a UniFi peer under load WILL send cookie replies and xpf must at
  least not wedge.

---

## 3. The 8 issue questions answered (with code evidence)

| # | Question | Verdict | Evidence |
|---|----------|---------|----------|
| 1 | Wire compliance (msg 1–4, MAC1/MAC2, TAI64N, identifier) | **WIRE GAP** — data record (type 4) compliant; handshake (type 1/2) framing, MAC1/MAC2, sender_index, type byte, and TAI64N timestamp all ABSENT. Noise transcript init + identifier correct. | §2.2, §2.3; `engine.rs:26-35`; `framing.rs`; protocol spec |
| 2 | PSK configurable? | **CONFIG/CODE GAP** — hardcoded `WG_ZERO_PSK`; no non-zero path. Correct only for no-PSK peers. | §2.4; `engine.rs:800,823`; `mod.rs:69` |
| 3 | persistent-keepalive exposed? | **CODE GAP** — field exists, no timer emits keepalives; no config feed. | §2.6; `peer.rs:49-60` |
| 4 | MTU / MSS interop | **UNWIRED (math correct)** — `wg_tcp_mss` correct + tested; call site short-circuited; UniFi 1420 MTU compatible. | §2.6; `mss.rs`; plan doc:338-349 |
| 5 | AllowedIPs / cryptokey routing (multi, v4+v6, 0.0.0.0/0) | **WORKS (engine), UNFED (config)** — supports all; decap-only gate; no config source. | §2.6; `allowed_ips.rs`; `engine.rs:506-509` |
| 6 | Endpoint roaming + DDNS | **CODE GAP** — TODO only; no re-resolve/roam. | §2.6; `peer.rs:34-43` |
| 7 | Config surface gap | **TOTAL GAP** — no Junos grammar, no typed struct, no compiler, no snapshot population; wire DTO fields are dead. | §2.5 |
| 8 | Ubiquiti specifics | UniFi 10.4+ WG VPN: server + client/site-to-site (S2S done via server-on-one-side + client-on-other); default UDP 51820 (operator-changeable, 51xxx range encouraged); optional base64 PSK; generated client config carries PrivateKey/PublicKey/PresharedKey/Endpoint/AllowedIPs/DNS; MTU/keepalive use WG defaults (1420 / 25 s). | §5; cited URLs |

**Overall interop verdict: NOT-YET-INTEROPERABLE.** Three independent
interop-blockers (handshake framing+TAI64N, dataplane not wired, no config
surface) plus two correctness/feature gaps (PSK, keepalive/roaming timers).

---

## 4. Gap classification

- **(c) wire/crypto gap — interop-blocking:**
  - C1: WG handshake outer framing (type byte, reserved, sender/receiver index,
    mac1, mac2) for message types 1 and 2.
  - C2: TAI64N timestamp as the Noise payload of message 1 (+ responder-side
    monotonic-timestamp anti-replay check).
  - C3: PSK plumbing (allow a non-zero psk2; only blocks PSK-enabled peers).
- **(b) config-surface gap — engine supports it, config doesn't expose it:**
  - B1: Junos config grammar + typed struct for a WG interface/peer
    (local privkey, listen-port, peer pubkey, endpoint, allowed-ips, keepalive,
    PSK, MTU).
  - B2: compiler + `tunnels.go` (or a new path) populating the `Wg*` snapshot
    fields.
  - B3: runtime `TunnelEndpoint` extension + reconcile from snapshot.
- **(a) already-works (engine-level, pending a feed):** data-record framing,
  replay window, AllowedIPs (v4+v6+default), MSS math, DSCP shift, cryptokey-
  routing safety, peer reconcile, session rotation.
- **(d) Ubiquiti-quirk to accommodate:**
  - D1: cookie-reply (type 3) handling under UniFi load (at minimum don't wedge;
    ideally MAC2 retry).
  - D2: endpoint may be DDNS ⇒ periodic re-resolve.
  - D3: keepalive 25 s expected for the firewall-behind-NAT direction.

---

## 5. Ubiquiti research (UniFi Network 10.4+ primary; EdgeOS/UDM secondary)

Sources (verified 2026-05-30; ui.com help articles 403 to automated fetch —
values cross-checked against third-party guides + the WireGuard project):

- UniFi WG VPN runs on the gateway's Linux kernel WireGuard, so it is
  **reference-compliant**: it WILL reject any handshake with a bad/missing
  `mac1` or a missing TAI64N. There is no "UniFi-lenient" parser.
- **Modes:** UniFi Network 10.x exposes a WireGuard **VPN Server** and a
  WireGuard **VPN Client**. Native site-to-site is done by running a Server on
  one site and a Client on the other (manual routes), per Ubiquiti help + 2024
  third-party guides. For xpf-to-UniFi, the realistic shape is **xpf as WG
  client (initiator) to a UniFi WG Server**, OR **xpf as WG server to a UniFi
  WG client**. Both require xpf to build/parse handshake messages in both roles
  — i.e. C1/C2 cover initiator AND responder.
- **Defaults / knobs (UniFi-generated client config):** `PrivateKey`,
  `Address`, `DNS`, `[Peer] PublicKey`, optional `PresharedKey` (base64),
  `AllowedIPs`, `Endpoint` (public IP or DDNS hostname), `PersistentKeepalive`.
  Default listen UDP port 51820 (operator-changeable; UniFi guides encourage a
  51xxx port). MTU/keepalive follow WG defaults (1420 / 25 s) unless overridden.
  Keys are base64-encoded 32-byte Curve25519 — xpf stores hex
  (`wg_local_privkey_hex`/`wg_peer_pubkey_hex`), so the config layer must accept
  the base64 the operator copies from UniFi and convert to the engine's
  `[u8;32]` (a 44-char base64 → 32-byte decode).
- **EdgeOS/EdgeRouter** `wireguard` (vyatta-wireguard) and **UDM/UDM-Pro**: same
  kernel-WG semantics; base64 keys; `persistent-keepalive`, `preshared-key`,
  `allowed-ips`, `endpoint` knobs. Secondary targets — if UniFi 10.4+ interop
  is proven, EdgeOS/UDM follow for free (same protocol).

Sources:
- UniFi Gateway WireGuard VPN Server / Client — help.ui.com (403 to bot; URLs:
  /hc/en-us/articles/115005445768 and /hc/en-us/articles/16357883221015)
- WunderTech UniFi WireGuard guide — https://www.wundertech.net/how-to-set-up-wireguard-on-unifi-devices/
- LazyAdmin UniFi WireGuard (Network 10.0.1) — https://lazyadmin.nl/home-network/unifi-wireguard/
- WireGuard protocol spec — https://www.wireguard.com/protocol/
- WireGuard quickstart (25 s keepalive, NAT) — https://www.wireguard.com/quickstart/
- WireGuard whitepaper — https://www.wireguard.com/papers/wireguard.pdf
- Arch Wiki WireGuard (1420 MTU, base64 keys) — https://wiki.archlinux.org/title/WireGuard

---

## 6. Multiple Path Options

### Path A — Interop-test-harness FIRST, then build to green (recommended)

Stand up an automated interop test against a **real kernel WireGuard /
wireguard-go peer** (a perfect stand-in for UniFi's kernel WG — same parser,
same MAC gate, same TAI64N check). Use `wg`/`wg-quick` in a netns or a
`wireguard-go` userspace peer on the loss userspace cluster (which already
carries the engine). The harness drives xpf as initiator and as responder and
asserts a completed handshake + bidirectional transport. This is the
**falsifiable acceptance gate** for every wire-level claim, and it converts
"we think it's compliant" into "wireguard-go authenticated our mac1 and
decrypted our data record."

Then build the missing layers in dependency order, each gated by the harness:
1. C1+C2 handshake framing + TAI64N (initiator first, then responder) — the
   single biggest interop-blocker; nothing else matters until a handshake
   completes against wireguard-go.
2. Dataplane wiring (encap at `frame/mod.rs:212` etc.; decap in
   `poll_descriptor.rs`; runtime `TunnelEndpoint` extension B3).
3. C3 PSK plumbing (parameterize psk2).
4. Keepalive + REKEY/REJECT-AFTER timers (D3) and endpoint roaming/DDNS (D2).
5. B1+B2 Junos config surface + compiler + snapshot population (base64→hex key
   decode).
6. D1 cookie-reply handling; IPv6 outer encap.

Pros: every step is provably interoperable before the next; the hardest risk
(C1/C2) is retired first; config work (most LOC, least risk) lands last against
a known-good engine. Cons: handshake-framing PR is large and security-critical;
needs the full quad-review.

### Path B — Config-surface-only (minimal, EXPLICITLY INSUFFICIENT)

Ship only B1/B2/B3 (Junos grammar + compiler + snapshot population), assuming
the engine "already works." **This does not produce interop** — the handshake
framing (C1/C2) is absent, so no tunnel ever establishes. Documented here only
to be rejected: any plan that treats #1703 as "just expose the config" is wrong
per §2.2. A reviewer proposing this must first refute the missing-mac1/TAI64N
evidence with a passing wireguard-go handshake.

### Path C — Full-knob parity in one mega-PR

Build C1–C3 + B1–B3 + D1–D3 in a single change. Rejected: the
security-critical handshake/MAC/timestamp code must be reviewed in isolation
(this is exactly why PR #1492 collapsed under 33 CRIT findings — see
`docs/pr/wireguard-clean/plan.md:9-42`). Bundling config churn with crypto
framing hides the framing bugs.

**Recommendation: Path A.** The interop harness against wireguard-go is the
load-bearing artifact; it makes the whole effort falsifiable and orders the
work by risk. UniFi hardware is NOT required to prove wire compliance —
wireguard-go/kernel WG is byte-identical to what UniFi runs.

---

## 7. Proposed sub-issue decomposition (for /engineer, post-approval)

1. **#1703-S1 (test harness):** wireguard-go/kernel-WG interop test fixture +
   CI/cluster runner. Drives xpf engine through a real WG peer. (No production
   code; enables all later gates.)
2. **#1703-S2 (handshake framing + TAI64N):** build/parse WG msg type 1/2,
   mac1/mac2, sender/receiver index, TAI64N payload + responder monotonic check.
   Gated by S1 green (initiator + responder). Quad-review, security-critical.
3. **#1703-S3 (dataplane activation):** encap/decap call sites + runtime
   `TunnelEndpoint` + reconcile; recycle discipline on every drop path.
4. **#1703-S4 (PSK):** parameterize psk2 end-to-end.
5. **#1703-S5 (timers):** persistent-keepalive emit + REKEY/REJECT-AFTER-TIME +
   endpoint DDNS re-resolve/roam.
6. **#1703-S6 (config surface):** Junos grammar (`setSchema`) + typed struct +
   compiler + `tunnels.go` population + base64↔hex key handling +
   `SchemaValidate` (reject dup pubkeys per `engine.rs:347-359`).
7. **#1703-S7 (cookie reply + IPv6 outer):** type-3 handling under load; v6
   outer encap.

S2 is the critical path; S6 is the largest but lowest-risk and lands last.

---

## 8. Interop TEST plan (the falsifiable gate)

- **Stand-in for UniFi:** `wireguard-go` (userspace) or kernel `wg` in a
  network namespace. Byte-identical handshake/parser/MAC/TAI64N to UniFi's
  kernel WG. Generate a keypair with `wg genkey | tee priv | wg pubkey`.
- **Test 1 (xpf initiator → wg responder):** configure xpf with the wg peer's
  pubkey + endpoint; assert (a) wg `latest handshake` becomes non-zero, (b) a
  ping/iperf inner flow round-trips, (c) `wg show` counters increment. FAILS
  today: wg drops the initiation (no mac1/type/TAI64N).
- **Test 2 (wg initiator → xpf responder):** wg initiates; assert xpf parses
  msg 1, replies with a valid msg 2 (mac1 over wg's pubkey), and transport
  flows. FAILS today (xpf cannot parse/emit handshake outer framing).
- **Test 3 (PSK on):** repeat with `PresharedKey` set on both ends; assert
  handshake completes. FAILS today (hardcoded zero PSK).
- **Test 4 (keepalive/NAT):** xpf behind a NAT netns, 25 s keepalive; assert the
  mapping stays open and the responder can initiate to xpf after idle.
- **Test 5 (MSS/MTU):** TCP iperf through the tunnel at MTU 1420; assert no
  fragmentation and MSS clamp = `wg_tcp_mss` value.
- **Cluster smoke:** on `loss:xpf-userspace-fw0/fw1`, run the dual-stack
  v4+v6 × push/-R × CoS-on/off matrix once S3 lands, with a wireguard-go peer on
  the WAN path. UniFi hardware optional; if available, a final manual interop
  against a real UniFi Network 10.4+ Gateway closes the issue.

A passing Test 1 + Test 2 against wireguard-go is the definition of "wire
compliant" and is the minimum bar before any UniFi claim.

---

## 9. Risks / unknowns

- **TAI64N source:** needs a monotonic 12-byte TAI64N clock; must survive
  control-plane restart without going backwards (kernel WG rejects non-monotonic
  timestamps ⇒ handshake DoS against ourselves). Tie to wall clock + persisted
  high-water mark.
- **mac1 cost on hot path:** mac1 is keyed-BLAKE2s over the handshake message;
  handshakes are slow-path only, so no hot-path cost — but the cookie/mac2 path
  (S7) touches the load-shed path.
- **snow handshake-message extraction:** S2 must wrap snow's `write_message`
  output with the WG framing; confirm snow exposes `sender_index`-free Noise
  bytes cleanly (it does — the engine already round-trips them in tests). The
  `into_stateless_transport_mode` boundary is proven.
- **Key encoding:** UniFi gives base64; engine wants hex `[u8;32]`. S6 must
  decode 44-char base64 → 32 bytes and reject malformed keys at commit.
- **Config grammar shape:** Junos models WG as `set interfaces wg0 ...` (vendor
  style) vs `set security ...`. Needs a decision in S6; out of scope for this
  research verdict.

## 10. Documentation contract

S2–S7 each update: `docs/pr/wireguard-clean/plan.md` (flip the OUT items to
DONE as they land), a new `docs/wireguard-interop.md` (operator-facing config +
UniFi how-to + the wireguard-go test recipe), and `pkg/config` schema docs
(`docs/config-schema.md`) for S6. The CLAUDE.md feature-coverage list gains a
WireGuard line only after S3 (engine actually on the hot path).

## 11. Recommendation summary

NOT-YET-INTEROPERABLE. The engine is a solid, well-reviewed crypto/replay/
AllowedIPs library, but it is unwired, lacks WG handshake framing + TAI64N,
hardcodes a zero PSK, and has zero config surface. Recommend **Path A**: build
an interop harness against wireguard-go FIRST (falsifiable gate, no UniFi
hardware needed), then deliver S2→S7 in risk order. This is a multi-PR
engineering effort, NOT a test-only closeout — so this research converges
**PLAN-READY** as a staged build-out plan (not PLAN-KILL, and emphatically not
the config-only Path B).

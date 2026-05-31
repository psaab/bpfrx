# #1709 — WireGuard S1: wire-protocol compliance (TAI64N + handshake framing) validated vs wireguard-go reference

Status: **DRAFT v1 — pending adversarial plan review** (Codex + AGY + Claude-SMR)

Issue: #1709 (part of #1703 umbrella). Branch:
`refactor/1709-wireguard-s1-wire-protocol-compliance`.

Research source: `docs/research/1703-wireguard-ubiquiti-interop/plan.md`
(branch `research/1703-wireguard-ubiquiti-interop` @ 8ed3d49e), §2.2, §6
Path A, §7 S1+S2, §8 Test 1a/2a.

> If reviewers conclude the design is wrong (snow cannot produce
> byte-exact WG handshake bytes, the harness does not prove independent
> interop, or the TAI64N/MAC1 construction diverges from the spec),
> **PLAN-KILL is an acceptable verdict.** This is the highest-stakes
> correctness domain in the project; a wrong byte means a silent
> handshake drop.

---

## 1. Issue framing (in my words)

xpf's `userspace-dp/src/afxdp/wg/` engine drives a Noise_IKpsk2 handshake
through `snow`, but it emits **only the raw Noise sub-message bytes** — it
does NOT build the WireGuard on-wire handshake framing (message type byte,
reserved, sender/receiver index, MAC1, MAC2) and it sends an **empty Noise
payload** instead of the **TAI64N timestamp** that WG carries as the
encrypted payload of message 1. A standards-compliant peer (wireguard-go,
kernel `wg`, UniFi's kernel WG) silently drops xpf's handshake before any
crypto: it parses byte 0 as the type (xpf's first byte is the ephemeral),
demuxes on `sender_index` (absent), and rejects any datagram whose MAC1 does
not verify against `BLAKE2s-keyed(HASH("mac1----" || our_static_pub), msg)`.

**S1 scope** (this PR — note #1709 folds research-plan S1 *and* S2 into one
deliverable, since the issue title is "wire-protocol compliance … validated
vs wireguard-go reference"):

1. **TAI64N timestamp** — a monotonic 12-byte TAI64N clock, carried as the
   Noise payload of WG message 1 (encrypted_timestamp), persisted so it never
   regresses across control-plane restart.
2. **WG handshake framing** (message types 1 & 2) on **build + parse** paths:
   type byte, `reserved_zero[3]`, sender/receiver index, MAC1, MAC2 (zeros
   until a cookie is observed), wrapping snow's Noise body.
3. **Initiator path first** (xpf emits a valid msg1, consumes a valid msg2,
   derives a transport session), **then responder path** (xpf parses a peer
   msg1, replies with a valid msg2).
4. **Automated interop harness vs wireguard-go** that completes a full
   handshake **both directions** against the independent reference and asserts
   matching transport-key derivation. **This harness is the success
   criterion**; an xpf-against-itself test is explicitly insufficient.

**Out of scope** (later #1703 S-steps): dataplane hot-path encap/decap wiring
(S3 / research-plan S3), keepalive + REKEY/REJECT-AFTER timers + endpoint
roaming (S5), non-zero PSK config plumbing (S4), Junos config surface (S6),
cookie-reply (type-3) generation + IPv6 outer + DSCP/ECN (S7), HA RG session
migration (S8). Transport-flow over the AF_XDP worker (Test 1b/2b) stays out;
S1 proves **handshake-message validity + session derivation** only.

---

## 2. Honest scope / value framing

This is not a perf change — there is no cycle/MB/retransmit win to weigh. The
value is **binary interop**: today xpf cannot complete a WireGuard handshake
with any compliant peer; after S1 it provably can, against the reference
implementation, in both roles. The cost is ~400–600 LOC of
security-critical crypto framing plus a Go interop harness. The honest risk
is that the framing has a byte-level bug that the harness must catch — which
is exactly why the harness against an **independent** reference (wireguard-go,
not xpf's own snow round-trip) is the load-bearing artifact.

If the framing were judged not worth the security-review burden in isolation,
the right call is PLAN-KILL — but the research plan already converged
PLAN-READY 3-of-3 on Path A with this as the critical-path first build step,
and the feasibility probes below show the design is byte-exact-achievable with
the deps already in the tree.

---

## 3. What's already shipped / proven (compose with, do not rebuild)

The engine (`wg/engine.rs`, 1725 LOC, WATCH-tier) is a reviewed
crypto/replay/AllowedIPs library:

- `build_initiator_handshake` / `build_responder_handshake` build a snow
  `HandshakeState` with `.prologue(WG_PROTOCOL_ID_BYTES)` +
  `.psk(2, &WG_ZERO_PSK)`. The **Noise transcript init is already
  spec-correct** (research §2.2: `Ci=HASH(CONSTRUCTION)`,
  `Hi=HASH(HASH(Ci||IDENTIFIER)||responder.static)`,
  `IDENTIFIER="WireGuard v1 zx2c4 Jason@zx2c4.com"`). I do not touch the
  prologue or pattern.
- `WgSession` / `install_session` / `try_encap` / `try_decap` /
  `reconcile_peers` are done. Transport-DATA framing (`framing.rs`, type 4) is
  spec-compliant. The replay window is RFC 6479.
- snow's `HandshakeState::write_message(payload, msg)` writes the **complete
  Noise message body** and accepts a caller payload; `read_message(msg,
  payload)` consumes it. `into_stateless_transport_mode()` yields the
  `StatelessTransportState`.

### 3.1 Feasibility probes run before writing this plan (evidence)

- **snow IK msg1 body == WG msg1 inner bytes.** snow IK message-1 writes `e[32]
  || encrypted_s[32+16] || encrypted_payload`. WG msg1 inner =
  `unencrypted_ephemeral[32] || encrypted_static[48] || encrypted_timestamp[12+16]`.
  Passing the 12-byte TAI64N as the snow `payload` makes
  `encrypted_payload == encrypted_timestamp` byte-for-byte. snow msg2 body =
  `e[32] || encrypted_empty[16]` == WG msg2 `Ephemeral[32] || Empty[16]`.
- **wireguard-go is fetchable + buildable in this sandbox.** `go run` against
  `golang.zx2c4.com/wireguard@v0.0.0-20260522210424-ecfc5a8d5446` succeeds;
  `tai64n.Now()` returns 12 bytes; `device` exports
  `MessageInitiationSize=148`, `MessageResponseSize=92`,
  `MessageInitiationType=1`, `MessageResponseType=2`, and the struct layouts
  match the spec (`Type,Sender,Ephemeral[32],Static[48],Timestamp[28],
  MAC1[16],MAC2[16]` = 148). `tun/netstack` (gvisor, **no root**) +
  `conn.NewDefaultBind` (real UDP socket) both build — so a full wireguard-go
  `Device` can run in-process over loopback UDP with no TUN/root requirement.
- **`blake2 0.10.6` is already in `Cargo.lock`** (transitive via snow) — MAC1
  keyed-BLAKE2s needs no new direct dependency beyond promoting `blake2` to a
  direct `Cargo.toml` entry (same locked version, no tree change).
- **`wg` / `wireguard-go` binaries are NOT installed**; `wireguard-tools` is
  apt-candidate only. The harness therefore uses the **wireguard-go Go module
  as a library** (vendored via `go.mod`, already in the module cache), NOT a
  system `wg` binary. This is documented as the chosen approach (issue asks to
  "install/vendor it or use kernel `wg` — document the approach").

---

## 4. The WireGuard spec — byte-exact, both sides cited

Per the WireGuard protocol page (https://www.wireguard.com/protocol/) and the
whitepaper §5.4 (https://www.wireguard.com/papers/wireguard.pdf), cross-checked
against the wireguard-go reference `device/noise-protocol.go` +
`device/cookie.go` (module version above) AND xpf's `wg/framing.rs` for the
data-record analogue:

### 4.1 Message 1 — Handshake Initiation (148 bytes)

```
offset size field
  0     1   message_type = 1
  1     3   reserved_zero  = {0,0,0}
  4     4   sender_index   (LE u32, initiator-chosen)
  8    32   unencrypted_ephemeral        ─┐
 40    48   encrypted_static (32+16 tag)  ├─ snow IK msg1 body (write_message)
 88    28   encrypted_timestamp (12+16)  ─┘   payload = 12-byte TAI64N
116    16   mac1
132    16   mac2
```

- `mac1 = MAC(key = HASH(LABEL_MAC1 || responder.static_public),
              input = msg[0 .. 116])` where `LABEL_MAC1 = b"mac1----"` (8
  bytes) and `MAC = Keyed-BLAKE2s` with a **16-byte output**
  (`blake2s.Size128`). *Keyed-BLAKE2s, NOT HMAC* (research §7 SMR r1 #3;
  wireguard-go `cookie.go:CheckMAC1` uses `blake2s.New128` with the key).
- `mac2 = MAC(key = last_received_cookie, input = msg[0 .. 132])`, or **all
  zeros** when no cookie has been received (the quiet-tunnel case). S1 always
  emits zeros (cookie handling is S7).
- `encrypted_timestamp` is the Noise **payload** of msg1: the 12-byte TAI64N
  encrypted by snow's `write_message(tai64n, ...)`.

### 4.2 Message 2 — Handshake Response (92 bytes)

```
offset size field
  0     1   message_type = 2
  1     3   reserved_zero  = {0,0,0}
  4     4   sender_index   (LE u32, responder-chosen)
  8     4   receiver_index (LE u32, echoes msg1.sender_index)
 12    32   unencrypted_ephemeral       ─┐ snow IK msg2 body (write_message,
 44    16   encrypted_nothing (0+16 tag) ┘  payload = &[] empty)
 60    16   mac1
 76    16   mac2
```

- `mac1 = MAC(HASH(LABEL_MAC1 || initiator.static_public), msg[0 .. 60])`.
  (Responder's mac1 keys on the **initiator's** static pub — the recipient of
  msg2.) `mac2` zeros in S1.

### 4.3 TAI64N (12 bytes)

TAI64N label = `(2^62) + unix_seconds` as a big-endian u64 (8 bytes) followed
by a big-endian u32 nanoseconds (4 bytes) = 12 bytes (whitepaper §5.4.2;
wireguard-go `tai64n/tai64n.go`, `tai64n.Now()` returned 12 bytes in the
probe). **Monotonicity invariant (research §9, SMR r1 #1):** kernel WG rejects
a msg1 whose TAI64N is `<=` the last one it accepted from that peer — so xpf
MUST emit a strictly increasing TAI64N or it DoSes its own re-handshakes.
S1 ties the value to the wall clock AND a persisted high-water mark (see §5.4).

### 4.4 Construction / identifier (already correct — do NOT change)

`WG_PROTOCOL_ID_BYTES = b"WireGuard v1 zx2c4 Jason@zx2c4.com"` is already mixed
as the snow prologue (`wg/mod.rs:82`, `engine.rs:796-801`). The
LABEL_MAC1 = `b"mac1----"` and LABEL_COOKIE = `b"cookie--"` constants are NEW
(used only for MAC1; cookie is S7). Confirmed against wireguard-go
`device/cookie.go` Init().

---

## 5. Concrete design

### 5.1 New module `wg/handshake.rs` (NOT in engine.rs)

engine.rs is WATCH-tier at 1725 LOC; adding framing there risks crossing the
2000-LOC [REFACTOR] threshold and bloats the most security-sensitive file. All
new framing lives in a new `wg/handshake.rs` (registered in `wg/mod.rs`). The
engine gains only thin slow-path entry points that delegate to it.

```rust
// wg/handshake.rs

pub(crate) const WG_MSG1_LEN: usize = 148;
pub(crate) const WG_MSG2_LEN: usize = 92;
const MAC_LEN: usize = 16;
const LABEL_MAC1: &[u8; 8] = b"mac1----";

// snow body offsets within each message (after the framed prefix).
const MSG1_PREFIX_LEN: usize = 1 + 3 + 4;       // type+reserved+sender = 8
const MSG1_NOISE_LEN: usize  = 32 + 48 + 28;    // 108 (e + enc_s + enc_ts)
const MSG2_PREFIX_LEN: usize = 1 + 3 + 4 + 4;   // type+reserved+sender+receiver = 12
const MSG2_NOISE_LEN: usize  = 32 + 16;         // 48

/// Compute mac1 = keyed-BLAKE2s-128(HASH("mac1----"||peer_static_pub),
/// msg[0..mac1_offset]). `peer_static_pub` is the static public key of the
/// message RECIPIENT (responder for msg1, initiator for msg2).
fn compute_mac1(peer_static_pub: &[u8; 32], msg_up_to_mac1: &[u8]) -> [u8; 16];

/// Build a WG type-1 initiation around a snow msg1 body.
/// `noise_body` is exactly what snow `write_message(tai64n, ..)` produced
/// (must be MSG1_NOISE_LEN bytes). `sender_index` is initiator-chosen.
/// `responder_static_pub` keys mac1. mac2 is zeros (S1).
pub(crate) fn build_initiation(
    out: &mut [u8],                 // >= WG_MSG1_LEN
    sender_index: u32,
    noise_body: &[u8],              // MSG1_NOISE_LEN
    responder_static_pub: &[u8; 32],
) -> Result<usize, FramingError>;

/// Parse a WG type-1 initiation. Verifies length, type byte, and (when
/// `our_static_pub` is Some) mac1 against HASH("mac1----"||our_pub). Returns
/// the sender_index and a borrow of the noise body to feed snow read_message.
pub(crate) fn parse_initiation<'a>(
    msg: &'a [u8],
    our_static_pub: &[u8; 32],
) -> Result<ParsedInitiation<'a>, FramingError>;

pub(crate) struct ParsedInitiation<'a> {
    pub sender_index: u32,
    pub noise_body: &'a [u8],       // 108 bytes -> snow read_message
}

// Symmetric build_response / parse_response for type-2 (carry receiver_index).
```

`FramingError` is a small `#[derive(Debug,Clone,PartialEq,Eq)]` enum:
`TooShort`, `BadType`, `Mac1Mismatch`, `BadNoiseLen`. Parse returns
`Mac1Mismatch` BEFORE handing bytes to snow (cheap reject, matches kernel WG
which drops on mac1 before crypto).

**mac2 on parse:** S1 does not verify mac2 (we never send cookies, so a
compliant peer sends mac2 = zeros; verifying it would require cookie state).
We parse-skip it. Documented; S7 adds verification.

### 5.2 New `wg/tai64n.rs`

```rust
/// Monotonic TAI64N clock. 12 bytes: BE u64 (2^62 + unix_secs) || BE u32 nanos.
pub(crate) struct Tai64nClock { last: Mutex<[u8; 12]> }

impl Tai64nClock {
    /// Returns a TAI64N strictly greater than every prior return value
    /// from this clock (monotonic). Derived from `SystemTime::now()` but
    /// clamped up to `last + 1ns` if the wall clock went backwards.
    pub(crate) fn now(&self) -> [u8; 12];
    /// Seed from a persisted high-water mark (control-plane restart).
    pub(crate) fn seed_high_water(&self, hw: [u8; 12]);
    pub(crate) fn high_water(&self) -> [u8; 12];
}
```

Monotonicity is enforced by byte-comparing the freshly-computed TAI64N against
`last` (TAI64N big-endian layout is monotonic under lexicographic byte
compare) and bumping the nanos field if not strictly greater. Persistence
(write `high_water()` to disk / HA-replicate) is the **control plane's**
responsibility; S1 provides `seed_high_water`/`high_water` and wires an
in-memory clock into the engine. **Cross-restart persistence to a file is
deferred to S5/S6 control-plane work** — S1 documents the hook and proves
monotonicity within a process; the harness does not restart xpf. (Flagged as
an open question for review: is in-process monotonicity + a documented persist
hook sufficient for S1, or must S1 land the disk persist? The research plan
§9 ties persistence to S2; I argue the disk write belongs with the config
surface in S6 since there is no daemon integration in S1.)

### 5.3 Engine slow-path entry points (thin, in engine.rs — small delta)

The engine already holds the local private key and the snow builders. Add four
slow-path methods that compose snow + handshake.rs + the TAI64N clock. These
run on the **control/coordinator thread only** (AGY r1 #2 boundary — never the
poll worker; the engine's hot encap/decap never build a HandshakeState):

```rust
impl WgEngine {
    /// Full initiator step: build snow msg1 with a TAI64N payload, frame it
    /// as a WG type-1 with mac1 over the peer pubkey. Returns the wire bytes
    /// + the in-progress HandshakeState (caller drives msg2 next) + the
    /// locally-chosen sender_index.
    pub(crate) fn create_initiation(&self, peer_pubkey: &[u8;32], out: &mut [u8])
        -> Result<InitiationBuilt, HandshakeError>;

    /// Consume a peer's type-2 response against the pending HandshakeState,
    /// derive the StatelessTransportState. Verifies framing + receiver_index.
    pub(crate) fn consume_response(&self, hs: HandshakeState, msg: &[u8])
        -> Result<WgSession-ish, HandshakeError>;

    /// Responder: parse a peer type-1, run snow read_message (recovering the
    /// peer's TAI64N + static pub), identify the peer, build a framed type-2.
    pub(crate) fn consume_initiation_create_response(&self, msg: &[u8], out: &mut [u8])
        -> Result<ResponseBuilt, HandshakeError>;
}
```

Exact return shapes (whether to expose `HandshakeState` across the boundary or
keep it engine-internal) are an implementation detail resolved in Step 5; the
existing tests already pass `HandshakeState` around, so the boundary is proven.
Sender/receiver index allocation reuses the existing demux discipline
(`install_session` already enforces global `local_index` uniqueness).

### 5.4 Interop harness — `userspace-dp/tests/wg_interop/` + Go reference

**Architecture (decided after probing wireguard-go's API):**

1. A **Rust integration test** (`userspace-dp/tests/wg_interop.rs`) that builds
   a `WgEngine` and exercises `create_initiation` / `consume_response` /
   `consume_initiation_create_response`, exchanging raw bytes with the Go
   reference over a **loopback UDP socket**.
2. The **independent reference** is a small Go program
   (`test/wg-interop-peer/`, its own `go.mod` pinning
   `golang.zx2c4.com/wireguard`) that stands up a real wireguard-go `Device`
   with a `tun/netstack` TUN (no root) + `conn.NewDefaultBind` UDP socket,
   configured via `IpcSet` (private key, peer pubkey, allowed-ips, endpoint =
   the Rust test's UDP socket). The Rust test spawns this peer as a subprocess,
   reads its chosen UDP port + public key from stdout, and drives the exchange.

   - **Direction A (xpf initiator → wireguard-go responder):** Rust
     `create_initiation` → send UDP datagram to the Go peer → the Go Device's
     real receive path runs `CheckMAC1` + `ConsumeMessageInitiation` (verifies
     mac1 against xpf's framing, decrypts the TAI64N, checks monotonicity) →
     Go emits a real type-2 → Rust `consume_response` derives the transport
     session. **Assert:** Go accepted msg1 (no drop — observable because it
     sends a msg2; we parse the type-2 we receive) AND xpf derived a session
     whose transport key matches (proven by a subsequent transport-record
     round-trip below).
   - **Direction B (wireguard-go initiator → xpf responder):** configure the Go
     peer with `PersistentKeepalive`/an endpoint so it initiates; Rust receives
     the UDP datagram, `consume_initiation_create_response` parses + replies;
     Go consumes the type-2 and the handshake completes on the Go side.
     **Assert:** xpf parsed a real wireguard-go msg1 (mac1 verified, TAI64N
     decrypted) and emitted a msg2 that wireguard-go accepted.
   - **Key-confirmation / matching transport keys:** after each direction, send
     ONE WireGuard transport DATA record (type 4) carrying a tiny inner IP
     packet from xpf's `try_encap` and assert the Go peer decrypts it
     (delivers to its netstack TUN), and vice-versa. This is the
     "derives matching transport keys" proof the task demands. *(This is a
     transport record, not the AF_XDP datapath — it uses the existing
     spec-compliant `framing.rs` over the loopback UDP socket, NOT
     `poll_descriptor.rs`. So it stays within S1's "no datapath change"
     boundary while still proving end-to-end key agreement.)*

3. **Self-contained build:** the Go reference is built by the test via
   `go build` (module cache already populated; documented `go.mod`). If the
   Go toolchain or network is unavailable, the interop test is gated behind a
   `WG_INTEROP=1` env / a `#[ignore]`-with-reason so `cargo test` stays green
   on a bare box, BUT the gate is **on by default in the dev/CI path** and the
   PR's acceptance requires it green. (Open question for review: ignore-by-
   default vs hard-required — I lean "required, with a clear skip message if
   `go` is absent, and run it explicitly in the gate.")

### 5.5 Files touched

- NEW `userspace-dp/src/afxdp/wg/handshake.rs` (~250 LOC + unit tests)
- NEW `userspace-dp/src/afxdp/wg/tai64n.rs` (~120 LOC + unit tests)
- EDIT `userspace-dp/src/afxdp/wg/mod.rs` (register modules, add consts
  LABEL_MAC1; ~10 LOC)
- EDIT `userspace-dp/src/afxdp/wg/engine.rs` (4 thin slow-path methods +
  TAI64N clock field; target delta < ~150 LOC to stay well under 2000)
- EDIT `userspace-dp/Cargo.toml` (promote `blake2` to a direct dep at the
  already-locked 0.10.6)
- NEW `userspace-dp/tests/wg_interop.rs` (Rust harness driver)
- NEW `test/wg-interop-peer/{go.mod,go.sum,main.go}` (wireguard-go reference)
- EDIT `docs/wireguard-interop.md` (NEW: harness recipe + wire-compliance
  status) and flip the relevant OUT items in `docs/pr/wireguard-clean/plan.md`
  to DONE for handshake framing + TAI64N.

---

## 6. Public API preservation

No existing public (`pub(crate)`) signature changes. `build_initiator_handshake`
/ `build_responder_handshake` / `try_encap` / `try_decap` / `install_session` /
`reconcile_peers` keep their exact signatures — the new `create_initiation`
etc. are additive. The 30+ existing engine/session/framing tests must still
pass unchanged.

---

## 7. Hidden invariants the change must preserve

- **Noise transcript unchanged.** The prologue + pattern + zero-PSK are
  untouched; only the payload of msg1 (now TAI64N instead of `&[]`) and the
  outer framing change. snow still computes the same `h`/`ck` chain.
- **Slow-path-only crypto.** Handshake construction + MAC1 keyed-BLAKE2s run on
  the control thread; the AF_XDP poll worker never calls the new methods
  (AGY r1 #2). No new hot-path allocation.
- **Index uniqueness.** sender/receiver indices flow into the existing
  `install_session` global-uniqueness check; no new demux race.
- **TAI64N monotonicity.** Strictly increasing per clock, enforced under a
  mutex; never regresses within a process. Cross-restart persistence hook
  exposed but disk-write deferred (S5/S6) — documented.
- **mac1 keys on the RECIPIENT's static pub** (responder for msg1, initiator
  for msg2) — the most common framing bug; the harness against wireguard-go is
  what catches a swapped key.
- **No mac2/cookie state** in S1 — emit zeros, skip-verify on parse; a peer
  under load that sends a type-3 cookie reply is out of scope (S7) and must not
  wedge — but S1's harness runs a quiet tunnel, so no cookie is sent.
- **zeroize discipline** preserved for any new key-material copies (MAC1 key is
  derived from a public key + public label — not secret — so no zeroize
  needed there; the TAI64N is not secret either).

---

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (existing engine) | **LOW** | Additive; existing tests unchanged; Noise transcript untouched. |
| Lifetime / borrow-checker | **LOW** | Framing is byte-shuffling over caller slices; `ParsedInitiation` borrows the input like `framing.rs::ParsedDataHeader` already does. |
| Wire-correctness (byte-level) | **HIGH** | The whole point. Mitigated by the wireguard-go harness (independent reference) — a wrong byte ⇒ Go drops ⇒ test fails. This is the gate. |
| TAI64N monotonicity / self-DoS | **MED** | Mitigated by mutex-guarded strictly-increasing clock + harness re-handshake. Cross-restart persistence deferred (documented). |
| Architectural mismatch (#961/#946-P2 dead-end) | **LOW** | Design matches snow's proven `write_message(payload)` boundary; not a speculative rearchitecture. The research plan already validated Path A 3-of-3. |
| Harness flakiness (subprocess/UDP) | **MED** | Loopback UDP + spawned Go peer can race on startup; mitigated by reading the peer's ready-line from stdout before driving, bounded timeouts, and the 5×flake gate. |

---

## 9. Test plan

- `cargo build` clean (release).
- `cargo test --release` full suite — all existing + new unit tests
  (handshake framing round-trip, mac1 key-on-recipient, TAI64N monotonic,
  TooShort/BadType/Mac1Mismatch arms).
- **Interop harness** `cargo test --release --test wg_interop` (both
  directions vs wireguard-go) — **the success criterion**.
- **5× flake** on the two interop tests (`wg_interop_xpf_initiator` and
  `wg_interop_xpf_responder`) — must be 5/5.
- Go suite `go test ./...` (30 packages) — the new `test/wg-interop-peer/` is
  its own module so it does not pollute the main Go build; confirm the main
  suite is unaffected.
- `make audit-check` — confirm engine.rs stays < 2000 LOC and the new files
  are registered; regen `docs/refactoring-audit-current.txt` if a wg file
  crosses 1500.
- **NO cluster smoke for S1.** This is handshake/wire-protocol + an
  integration test, **not a datapath change** (no encap/decap on the AF_XDP
  hot path — that is S3). The CoS/iperf3 matrix exercises the AF_XDP fast path,
  which S1 does not touch. Stated explicitly per the task. The cluster smoke
  belongs to research-plan S3 when the engine goes on the hot path.

---

## 10. Out of scope (explicit, deferred to later #1703 steps)

- AF_XDP hot-path encap/decap wiring + runtime `TunnelEndpoint` extension (S3).
- Non-zero PSK config plumbing (S4).
- persistent-keepalive emit, REKEY/REJECT-AFTER-TIME timers, endpoint
  roaming/DDNS, empty-record (keepalive/key-confirm) acceptance (S5).
- TAI64N disk persistence + HA replication (S5/S6 control plane).
- Junos config grammar + compiler + snapshot population + base64↔hex (S6).
- Cookie-reply (type-3) generation/verification, IPv6 outer encap, DSCP/ECN
  (S7). mac2 verification on parse (S7).
- HA RG WG-session migration (S8).
- Transport-flow over the AF_XDP worker (Test 1b/2b) — S1 proves a single
  transport record over the harness UDP socket only, to confirm key agreement.

---

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **snow payload == WG encrypted_timestamp, byte-exact?** I claim snow IK
   msg1 `write_message(tai64n_12b, out)` produces `e[32] || enc_s[48] ||
   enc_ts[28]` identical to WG msg1 inner. Is there any snow-side framing
   (length prefix, extra MixHash of the payload at a different point) that
   diverges from kernel WG's `encrypt(timestamp)` so the harms only surface as
   a tag-verify failure on the Go side? (Probe says lengths match; demand the
   harness prove the AEAD verifies, not just the length.)
2. **mac1 = keyed-BLAKE2s-128, not HMAC.** Confirm against wireguard-go
   `cookie.go` that it's `blake2s.New128(key)` keyed (not HMAC-BLAKE2s), key =
   `BLAKE2s-256(LABEL_MAC1 || recipient_static_pub)` (32-byte hash used as the
   16-output keyed-BLAKE2s key). Wrong hash width or HMAC vs keyed ⇒ silent
   drop. Is my "HASH = BLAKE2s-256, MAC = keyed-BLAKE2s-128" reading correct?
3. **Is in-process TAI64N monotonicity + a deferred persist hook acceptable
   for S1**, or must S1 land disk persistence (research §9 ties it to S2)? I
   argue persistence belongs with daemon/config integration (S6) since S1 has
   no daemon wiring. Kill the deferral if a reviewer shows S1's harness can
   regress the clock.
4. **Is the wireguard-go-as-library harness a sufficient independent
   reference**, or does the task's intent require the kernel `wg` /
   `wg-quick` path (apt-install in the env)? wireguard-go is byte-identical to
   kernel WG (same author, same protocol) and needs no root via `netstack`;
   kernel `wg` needs root + a netns + module load. I claim wireguard-go is the
   stronger, more portable independent reference. Refute if the loopback-UDP +
   netstack peer is not a faithful stand-in.
5. **Index allocation / receiver_index echo.** msg2 must echo msg1's
   sender_index as its receiver_index, and the responder's own sender_index
   must be installed for inbound demux. Does the existing `install_session`
   uniqueness discipline compose cleanly with framing-chosen indices, or is
   there a race when the harness drives both roles in one process?
6. **Harness `go test` / cargo boundary.** Is spawning a Go subprocess from a
   Rust integration test the right seam, or should the harness be a Go test
   that shells out to a tiny xpf framing CLI? I chose Rust-drives-Go because
   the security-critical bytes are xpf's and must be asserted in xpf's test;
   the reference is the dependency. Is the subprocess/UDP harness too flaky to
   be a merge gate (the 5×flake gate is meant to answer this)?

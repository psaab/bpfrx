# #1709 — WireGuard S1: wire-protocol compliance (TAI64N + handshake framing) validated by spec known-answer vectors (live kernel-WireGuard interop = S2)

Status: **PLAN-READY v3** — round-1 plan review complete: Codex
(task-mpt6qx4i-i04py6) PLAN-NEEDS-MAJOR, AGY (adversarial-review-mpt6r70o-ebe5a4)
PLAN-NEEDS-MAJOR, Claude-SMR PLAN-NEEDS-MINOR. v3 addresses ALL major findings
(see §v3-convergence). v2→v3: TAI64N epoch offset corrected to
`0x400000000000000a` + nanos whitening (AGY-2); two-phase index reservation to
close the blackhole race (AGY-1/Codex-4); `local_public_key` added for inbound
MAC1 (Codex-2); TAI64N persistence story reconciled (Codex-3); S1 gate
strengthened to require FULL byte-exact msg1/msg2 KATs (Codex-1/SMR-2);
S1/S2 boundary ratified Option (b+). v2→v1: dropped wireguard-go; reference =
kernel WireGuard on a real VM (never a container); spec-KAT in-tree gate.

> Pending a confirming round-2 from Codex + AGY on v3 before code lands.

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
deliverable: "wire-protocol compliance — TAI64N + handshake framing —
validated vs a WireGuard reference"; the reference is now kernel WireGuard,
and the live interop test is recommended to land in S2, see §5.4/Q7):

1. **TAI64N timestamp** — an **in-process strictly-monotonic** 12-byte TAI64N
   clock (epoch base `0x400000000000000a`, whitened nanos — §4.3), carried as
   the Noise payload of WG message 1 (encrypted_timestamp). S1 guarantees
   monotonicity *within a process*; cross-restart disk persistence is deferred
   to the control-plane integration (S6) and exposed here only as a
   `seed_high_water`/`high_water` hook — S1 has no daemon to persist from
   (Codex-3 inconsistency fixed in v3; §4.3, §5.2).
2. **WG handshake framing** (message types 1 & 2) on **build + parse** paths:
   type byte, `reserved_zero[3]`, sender/receiver index, MAC1, MAC2 (zeros
   until a cookie is observed), wrapping snow's Noise body.
3. **Initiator path first** (xpf emits a valid msg1, consumes a valid msg2,
   derives a transport session), **then responder path** (xpf parses a peer
   msg1, replies with a valid msg2).
4. **Spec known-answer vector tests (in-tree gate)** that pin the WG
   construction hashes (InitialChainKey/InitialHash), the MAC1 keyed-BLAKE2s
   construction, and the TAI64N encoding to authoritative reference values —
   self-contained, no external peer, runs in plain `cargo test` anywhere.
5. **Live kernel-WireGuard interop (on a real VM peer)** — xpf's Rust
   handshake completes **both directions** against a **Linux kernel WireGuard**
   peer (`ip link add wgX type wireguard` + `wg set`), asserting matching
   transport-key derivation. Reference peer = **kernel WireGuard running on an
   actual incus VIRTUAL-MACHINE** (DECIDED by the user) — never a container
   (containers share the host kernel and cannot independently use the WG
   module). Byte-identical to what UniFi / EdgeOS / UDM run; no Go toolchain.
   **This live test is the ultimate interop proof**; an xpf-against-itself test
   is explicitly insufficient. Because the live test now requires a dedicated
   VM peer + UDP-reachability wiring between the xpf VM and the peer VM (a
   non-trivial harness), **the recommended S1/S2 boundary is: S1 = framing +
   spec-vector unit tests (provable by `cargo test` anywhere, no peer/VM); the
   live kernel-wg-on-VM interop test moves to S2 alongside the datapath/UDP
   wiring.** Plan-review (Codex+AGY+SMR) must ratify this boundary — see §5.4(b)
   and Q7.

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
is exactly why the gate is built from **canonical spec known-answer vectors**
(independent of xpf's own code), with the live test against an **independent**
reference (kernel WireGuard on a VM, not xpf's own snow round-trip) as the
S2-opening artifact.

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
- **WG message layouts are byte-confirmed against the spec.** WG msg1 =
  `Type(1)+reserved(3)+Sender(4)+Ephemeral(32)+Static(48)+Timestamp(28)+
  MAC1(16)+MAC2(16)` = 148; msg2 =
  `Type(1)+reserved(3)+Sender(4)+Receiver(4)+Ephemeral(32)+Empty(16)+
  MAC1(16)+MAC2(16)` = 92 (whitepaper §5.4; cross-checked against the
  canonical layout). snow's IK msg1/msg2 bodies occupy the
  `Ephemeral..Timestamp` (108 B) and `Ephemeral..Empty` (48 B) middles exactly.
- **KAT oracle values are precomputed (offline).** The canonical construction
  constants (InitialChainKey, InitialHash, MAC1 key, keyed-BLAKE2s-128) were
  computed offline once and are baked as hex literals into the unit tests
  (§5.4a). **No Go toolchain, no wireguard-go, no network at test time** — the
  vectors are static.
- **`blake2 0.10.6` is already in `Cargo.lock`** (transitive via snow) — MAC1
  keyed-BLAKE2s needs no new locked dependency beyond promoting `blake2` to a
  direct `Cargo.toml` entry (same locked version, no tree change).
- **Kernel WireGuard is available on the loss VM (verified).** On
  `loss:xpf-userspace-fw0`: `modinfo wireguard` →
  `/lib/modules/7.0.0-rc7+/.../wireguard.ko.xz`; `ip link add wgX type
  wireguard` succeeds (CREATE_OK). `ip` is present; **`wg`/`wg-quick`
  userspace tools are NOT yet installed** (only the kernel module + `ip`), so
  the live harness must either `apt-get install wireguard-tools` on the VM or
  configure the reference interface via netlink/`ip`. This is the reference
  peer for the live interop test (DECIDED).

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

### 4.3 TAI64N (12 bytes) — CORRECTED in v3 per AGY-2

TAI64N label = **`0x400000000000000a + unix_seconds`** (= `2^62 + 10 +
unix_seconds`) as a big-endian u64 (8 bytes), followed by a big-endian u32
nanoseconds (4 bytes) = 12 bytes. **The `+ 10` is the leap-second offset (TAI
was 10 s ahead of UTC at the 1970 epoch) and is MANDATORY** — kernel WG uses
`ktime_get_real_seconds() + 0x400000000000000aULL` and wireguard-go
`tai64n/tai64n.go` uses `base = uint64(0x400000000000000a)`. v1/v2's plain
`2^62` was wrong by 10 s (AGY plan-review finding 2); a strict peer with a
narrow handshake-replay window could drop it as stale.

**Nanos whitening (NEW in v3, not flagged by reviewers — found while verifying
AGY-2 against `tai64n.go`):** the reference masks the low 24 bits of the nanos
field: `nano = uint32(t.Nanosecond()) &^ (0x1000000 - 1)` (i.e.
`nano & 0xFF000000`). This whitens the sub-~16 ms component to avoid leaking a
fine-grained clock. xpf MUST apply the same `&^ 0x00FFFFFF` mask to be
byte-identical to the reference and avoid the timing side-channel. (A peer does
not *require* it — it only byte-compares — but matching the reference is the
S1 contract.)

**Carry / monotonicity spec (NEW in v3 per Codex-3):** the monotonic clock
returns `max(now_tai64n, last + 1_whitened_tick)`. Because nanos are whitened
to a `0x1000000`-ns (~16.7 ms) granularity, the monotonic "+1" increment is one
whitened tick = `0x1000000` ns; on nanos overflow past `0xFF000000` the carry
rolls into the seconds field (`secs += 1; nanos = 0`). Stored as the 12-byte
big-endian value so lexicographic byte-compare == numeric compare (matches
`tai64n.go`'s `bytes.Compare`).

**Monotonicity invariant (research §9, SMR r1 #1):** kernel WG rejects a msg1
whose TAI64N is `<=` the last one it accepted from that peer — so xpf MUST emit
a strictly increasing TAI64N or it DoSes its own re-handshakes. S1 enforces
in-process strict monotonicity via a `Mutex<[u8;12]>`; cross-restart disk
persistence is deferred (see §5.2 — reconciled in v3 per Codex-3).

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
/// In-process strictly-monotonic TAI64N clock. 12 bytes:
/// BE u64 (0x400000000000000a + unix_secs) || BE u32 (nanos &^ 0x00FFFFFF).
pub(crate) struct Tai64nClock { last: Mutex<[u8; 12]> }

impl Tai64nClock {
    /// Returns a TAI64N strictly greater than every prior return value
    /// from this clock. Computes the whitened TAI64N from
    /// `SystemTime::now()`; if that is `<= last`, returns
    /// `last + one whitened tick` (carry into seconds on nanos overflow
    /// past 0xFF000000). Big-endian layout ⇒ byte-compare == numeric.
    pub(crate) fn now(&self) -> [u8; 12];
    /// Seed from a persisted high-water mark (control-plane restart, S6).
    pub(crate) fn seed_high_water(&self, hw: [u8; 12]);
    pub(crate) fn high_water(&self) -> [u8; 12];
}
```

Monotonicity is enforced by byte-comparing the freshly-computed (whitened)
TAI64N against `last`; on `<=`, advance by one whitened tick (`0x1000000` ns),
carrying into the seconds field on overflow (§4.3 carry spec). The big-endian
layout makes lexicographic byte-compare equal numeric compare (matches
`tai64n.go`'s `bytes.Compare`).

**Persistence — reconciled in v3 (Codex-3):** S1 guarantees only *in-process*
monotonicity. The `seed_high_water`/`high_water` hooks exist so a future
control-plane (S6) can persist + HA-replicate the high-water mark, but **S1
does NOT write to disk** — and that is correct, not a gap, because **S1 has no
daemon**: an unintegrated engine with no reloaded state cannot regress a clock
it never reloads (SMR-4). The earlier §1 "persisted so it never regresses"
wording was inconsistent with this deferral and is fixed in v3. AGY's
operational note (an NTP step-back or rapid restart of an *integrated* xpf
could silently wedge a peer that still holds the old high-water mark) is real
and is captured as an **S2 testing runbook item**: when restarting xpf during
S2 VM interop, flush the peer's WG state (`ip link del wgref; ip link add
wgref type wireguard`) to clear its in-memory per-peer TAI64N high-water. The
durable fix (disk persist) lands in S6.

### 5.3 Engine slow-path entry points (thin, in engine.rs — small delta)

**Local public key (NEW in v3, Codex-2 — REQUIRED).** Parsing an inbound
msg1/msg2 MAC1 requires xpf's OWN static public key (the recipient key for
inbound messages). Today `WgEngineConfig`/`WgEngine` store only
`local_private_key` (`engine.rs:173`, `:256`). v3 adds a `local_public_key:
[u8; 32]` derived ONCE at `WgEngine::new` from the private key
(X25519 base-point mult via `curve25519-dalek` — already in `Cargo.lock` at
4.1.3 — or snow's `Builder::generate_keypair` is NOT it; use the dalek
`x25519(secret, basepoint)` clamp). Storing it avoids re-deriving per parse and
prevents the "private-key-as-public" / swapped-key class of bug under
implementation pressure. A unit test asserts `local_public_key` equals snow's
notion of our static pub for the same private key.

The engine already holds the local private key and the snow builders. Add four
slow-path methods that compose snow + handshake.rs + the TAI64N clock. These
run on the **control/coordinator thread only** (AGY r1 #2 boundary — never the
poll worker; the engine's hot encap/decap never build a HandshakeState):

```rust
impl WgEngine {
    /// Full initiator step: RESERVE a fresh local sender_index in the demux
    /// map FIRST (two-phase, see below), then build snow msg1 with a TAI64N
    /// payload, frame it as a WG type-1 with mac1 over the peer pubkey.
    pub(crate) fn create_initiation(&self, peer_pubkey: &[u8;32], out: &mut [u8])
        -> Result<InitiationBuilt, HandshakeError>;

    /// Consume a peer's type-2 response against the pending HandshakeState,
    /// derive the StatelessTransportState, and PROMOTE the reserved index to
    /// a live session. Verifies framing + that receiver_index == our reserved
    /// sender_index.
    pub(crate) fn consume_response(&self, msg: &[u8])
        -> Result<DerivedSession, HandshakeError>;

    /// Responder: parse a peer type-1 (mac1 over OUR local_public_key), run
    /// snow read_message (recovering the peer's TAI64N + static pub), identify
    /// the peer, RESERVE our responder sender_index, build a framed type-2
    /// whose receiver_index echoes msg1.sender_index.
    pub(crate) fn consume_initiation_create_response(&self, msg: &[u8], out: &mut [u8])
        -> Result<ResponseBuilt, HandshakeError>;
}
```

**Two-phase index reservation (NEW in v3 — AGY-1 / Codex-4, the blackhole
race).** The v2 plan's "allocate then `install_session`" is unsafe: a responder
that transmits msg2 carrying sender_index `R` and only *afterward* calls
`install_session` can lose the `R` slot to a concurrent handshake, fail the
install with `LocalIndexCollision`, and then **silently blackhole** the
initiator's data records (they demux to `UnknownSession`). The fix: a
**reservation** invariant — the local index MUST be inserted into a
reservation set / `sessions_by_local_index` (as a pending placeholder) **before
the handshake message carrying it is written to `out`/sent on the wire**. On
reservation collision, regenerate the index and retry BEFORE transmission.
`consume_response` / `consume_initiation_create_response` then *promote* the
reserved index to a live `WgSession` (never a fresh insert that could collide).
This means:
  - `install_session`'s existing global-uniqueness check (`engine.rs:437-491`)
    is necessary but NOT sufficient — it guards completed installs, not pending
    reservations. v3 adds a pending-index reservation layer in front of it.
  - The reservation must be released on handshake failure/timeout so a dropped
    handshake does not leak the index forever (mirrors the
    `reconcile_peers` drain discipline for dropped sessions).
  - Tests: `reserve_before_send_then_promote`, and a concurrent-reservation
    test proving two in-flight handshakes never both claim the same index and
    no completed handshake is left un-demuxable.

Exact return shapes keep `HandshakeState` engine-internal where possible
(SMR-6): the engine holds the pending `HandshakeState` keyed by the reserved
sender_index, so the four methods trade only `[u8;32]` / byte slices, not snow
types. Resolved concretely in Step 5.

### 5.4 Verification: spec KAT vectors (in-tree gate) + deferred live harness

**(a) Spec known-answer vector tests — the buildable-now, self-contained gate.**
These pin xpf's framing to authoritative WireGuard reference values with NO
external peer, so they run in plain `cargo test` on any box. The values below
were computed offline from the canonical WG construction (BLAKE2s over the
documented labels/identifier; an offline BLAKE2s oracle produced the expected
hex). Per Q6, the tests should ALSO re-derive these from raw `blake2` calls in
the same test so neither a transcription typo nor an implementation bug can
pass alone. No runtime external dependency is introduced:

- `InitialChainKey = BLAKE2s-256("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")`
  = `60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36`
- `InitialHash = BLAKE2s-256(InitialChainKey || "WireGuard v1 zx2c4 Jason@zx2c4.com")`
  = `2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3`
- MAC1 key for recipient pubkey `0x42`×32
  = `BLAKE2s-256("mac1----" || pubkey)`
  = `172c34d6807bd7acef1a2471f20e928626c23ce0b9f90b326cf5f82d12480a4e`
- `keyed-BLAKE2s-128(MAC1key, b"abc")`
  = `78df3b0a90577688ce9d272d04a8fb90`

Test suite (`wg/handshake.rs` + `wg/tai64n.rs` `#[cfg(test)]`). **Per SMR-1,
every KAT below is DUAL-SOURCE: assert against BOTH the baked hex literal AND
an in-test re-derivation from raw `blake2` calls — a transcription typo fails
the re-derivation, an implementation bug fails the baked vector.** (I verified
all four §5.4a vectors reproduce from `blake2 0.10` first-principles — see
SMR-R1.)
  - `construction_hashes_match_spec` — assert xpf's computed InitialChainKey /
    InitialHash equal the hex above (independently re-derives what snow's
    prologue already mixes, proving the framing layer agrees with the engine).
  - `mac1_keyed_blake2s_128_kat` — assert the keyed-BLAKE2s-128 vector above
    (proves keyed-BLAKE2s via `Blake2sMac<U16>`, NOT HMAC, and the 16-byte
    output width — the research §7 SMR r1 #3 hazard).
  - `mac1_keys_on_recipient_static_pub` — build msg1 toward responder R; assert
    mac1 verifies under `HASH("mac1----"||R_pub)` and FAILS under a different
    pubkey (catches the swapped-key bug).
  - **`msg1_full_kat_fixed_ephemeral` (SMR-2, REQUIRED)** — with a pinned
    local-static + ephemeral (snow `fixed_ephemeral`) + a fixed TAI64N, assert
    the entire deterministic 148-byte msg1 and its 16-byte mac1 over
    `msg[0..116]`. This is the one test that catches an offset/endianness bug
    in the framing *assembly* that per-field KATs miss. (If a fixed-ephemeral
    builder is not cleanly reachable, fall back to asserting mac1 over a
    captured msg-prefix — still catches the offset bug.)
  - `msg1_layout_byte_offsets` / `msg2_layout_byte_offsets` — assert the
    148/92-byte total, type byte = 1/2, reserved zeros, LE indices at the right
    offsets, snow body at offset 8/12, mac1/mac2 at the tail.
  - **`parse_initiation_accepts_nonzero_mac2` (SMR-5, REQUIRED)** — parse must
    accept a msg with mac2 != 0 (a peer that holds our cookie sets it); mac2 is
    skip-verified in S1, NOT treated as malformed. Cookie generation is S7.
  - `tai64n_encoding_kat` — assert the 12-byte layout (BE u64
    `0x400000000000000a + secs` || BE u32 `nanos &^ 0x00FFFFFF`) for a fixed
    `(secs, nanos)`, including the **`+10` epoch offset** (AGY-2) and the
    **nanos whitening** (v3); `tai64n_strictly_monotonic` (N calls strictly
    increase by byte-compare even with a frozen/backwards clock, with the
    one-whitened-tick carry into seconds on nanos overflow — §4.3);
    **`tai64n_concurrent_monotonic` (SMR-4)** (N threads calling `now()` yield
    N strictly-ordered distinct values).
  - `framing_roundtrip` — `build_initiation` then `parse_initiation` recovers
    the sender_index + noise body; `parse` rejects TooShort / BadType /
    Mac1Mismatch.
  - `engine_self_handshake_with_framing` — drive both engine roles through the
    NEW framed `create_initiation`/`consume_initiation_create_response`/
    `consume_response` path (not just raw snow) and assert both sides derive a
    transport session that encrypts/decrypts a record. *This is xpf-against-xpf
    and is explicitly NOT sufficient as the interop proof — it is a regression
    guard for the engine integration; the LIVE harness in (b) is the interop
    gate.*

**(b) Live kernel-WireGuard interop (on a real VM peer) — reference DECIDED,
S1/S2 boundary RECOMMENDED = defer to S2, to be RATIFIED in plan-review.**
The ultimate interop proof uses an *independent* reference = the **Linux
kernel WireGuard** module on a real incus VM (never a container — containers
share the host kernel and cannot use the WG module / create `type wireguard`
links). Either launch a dedicated lightweight Debian-13 VM
(`incus launch images:debian/13 <name> --vm`) or reuse an existing real VM
(e.g. `bpfrx-fw`), attach it to a network the xpf VM (`xpf-userspace-fw0`,
itself a VM) can reach, and configure kernel `wg`:

```
# on the PEER VM (root; wireguard-tools installed via apt if absent):
ip link add wgref type wireguard
wg set wgref private-key <ref.priv> listen-port <P> \
   peer <xpf.pub> allowed-ips 0.0.0.0/0 endpoint <xpf_vm_ip>:<Q>
ip addr add 10.<x>.<y>.1/24 dev wgref; ip link set wgref up
# Direction A: xpf create_initiation -> UDP <peer_vm_ip>:<P>; kernel wg
#   verifies mac1 + decrypts TAI64N + replies type-2; xpf consume_response
#   derives the session. Assert via `wg show wgref` (latest-handshake / rx
#   counters) AND xpf-side session derivation + a transport-record round-trip.
# Direction B: kernel wg initiates (persistent-keepalive 1); xpf
#   consume_initiation_create_response replies; assert `wg show` completes.
```

**The load-bearing sequencing question (the user flagged it; plan-review MUST
ratify):** a *live* handshake requires (i) xpf to actually send/receive the
handshake UDP datagrams and (ii) a dedicated VM peer + UDP reachability wiring
between the two VMs. The AF_XDP datapath wiring is research-plan S3. Two
options:

- **Option (a) — minimal test-only UDP socket harness in S1.** Add a small
  test/ops-only `std::net::UdpSocket` (control thread, NOT the AF_XDP worker)
  that pumps S1's bytes to/from the kernel-wg VM endpoint, plus the incus VM
  provisioning + cross-VM network wiring under `test/incus/`. Proves wire
  compliance against a real kernel peer without touching the hot path — but the
  VM provisioning + cross-VM reachability harness is now non-trivial
  (a new VM lifecycle + network attach), which is real surface to build and
  maintain inside a security-critical framing PR.
- **Option (b) — S1 = framing + spec-vector unit tests; live kernel-wg-on-VM
  interop → S2 (RECOMMENDED).** Keep S1 self-contained and provable by
  `cargo test` anywhere (no peer, no VM, no network). The live kernel-wg-VM
  interop test lands in S2 alongside the datapath/UDP wiring it naturally
  shares (the same UDP send/recv plumbing serves both the live test and the
  datapath). This gives a clean, reviewable S1 (pure wire-protocol correctness)
  and avoids bolting a VM-lifecycle + cross-VM-network harness onto the
  crypto-framing PR.

**RATIFIED in v3 — Option (b+), all three reviewers concur.** Codex
(PLAN-NEEDS-MAJOR), AGY (PLAN-NEEDS-MAJOR), and Claude-SMR all recommend
**Option (b)** for development isolation — the live test now needs a real VM
peer + cross-VM SR-IOV UDP reachability, meaningfully more harness than a
loopback socket and better built once in S2 next to the datapath UDP plumbing
— **but with a strict governance condition (the "+"):**

> **The S1 framing+TAI64N code MUST NOT be claimed as "interop-capable" in any
> operator doc / CLAUDE.md feature line, and S1's branch should land such that
> the independent-peer proof is enforced before any production interop claim.**
> Codex: "If full byte-exact msg1/msg2 KATs are not added, choose Option (a)."
> AGY: "do not present S1 in isolation as interop; the live VM test is the
> absolute gate." SMR-3: same honesty condition.

So S1's gate is **strengthened**: the §5.4a suite is NOT merely
construction/MAC/layout KATs + a self-handshake — it MUST include the
**full deterministic byte-exact msg1 AND msg2 KATs** (fixed static + fixed
ephemeral + fixed TAI64N → exact 148/92-byte wire image + mac1), which is the
only in-tree test that catches a symmetric build/parse bug (e.g. wrong index
endianness) that the self-handshake would pass. With those full-message KATs,
(b+) is a legitimate S1 crypto gate; the live kernel-wg-on-VM test (S2) is the
independent-peer confirmation. **Reference peer is kernel WireGuard on a real
VM, never a container.**

Per the task: S1 needs **no CoS/iperf cluster smoke** (no datapath change).

### 5.4c S2 live-interop peer-VM spec (NOT built in S1 — recorded for S2)

The user pinned the S2 reference-peer wiring; recorded here so the S2 plan
inherits it. The kernel-wg peer is a Debian-13 incus **VM** on the **same LAN
segment** as `loss:cluster-userspace-host`, mirroring its SR-IOV device so xpf
reaches it identically:

```
incus launch images:debian/13 wg-kpeer --vm
incus config device add wg-kpeer eth0 nic nictype=sriov parent=mlx1 vlan=3667
# static LAN config inside the VM:
#   IPv4 10.0.61.103/24      (next free; .102 = cluster-userspace-host, .1 = xpf reth1 VIP)
#   IPv6 2001:559:8585:ef00::103/64
#   default route via 10.0.61.1
# then kernel wg (VM ⇒ real kernel, module loads):
ip link add wgref type wireguard
wg set wgref private-key <ref.priv> listen-port <P> \
   peer <xpf.pub> allowed-ips 0.0.0.0/0 endpoint 10.0.61.1:<Q>
ip addr add <wg-overlay>/24 dev wgref; ip link set wgref up
```

Direction A: xpf initiates to `10.0.61.103:<P>`. Direction B: kernel wg
initiates (persistent-keepalive 1) to xpf's WG UDP endpoint at the LAN VIP.

**SR-IOV VF availability constraint (verified, must re-check at S2 provision
time):** `mlx1` already backs `cluster-userspace-host` (VF id 2) and
`cluster-lan-host` (VF id 3); the cluster also consumes mlx0/mlx1 VFs for the
fw0/fw1 dataplane. Mellanox PFs typically expose ≥8 VFs so a free VF (id ≥4) is
expected, but the host `sriov_numvfs` was not enumerable from the worktree
shell. **S2 must verify a free VF on `mlx1` exists before launching `wg-kpeer`;
if none is free, document the constraint and either bump `sriov_numvfs` or
reuse an existing spare real VM (`bpfrx-fw`) attached to the same VLAN-3667
segment.**

### 5.5 Files touched

- NEW `userspace-dp/src/afxdp/wg/handshake.rs` (~250 LOC + unit tests)
- NEW `userspace-dp/src/afxdp/wg/tai64n.rs` (~120 LOC + unit tests)
- EDIT `userspace-dp/src/afxdp/wg/mod.rs` (register modules, add consts
  LABEL_MAC1; ~10 LOC)
- EDIT `userspace-dp/src/afxdp/wg/engine.rs` (4 thin slow-path methods +
  TAI64N clock field + `local_public_key` field/derivation + pending-index
  reservation layer; target delta < ~150 LOC to stay well under 2000 — AGY
  re-confirmed ~1846 LOC, well under threshold)
- EDIT `userspace-dp/Cargo.toml` (promote `blake2` to a direct dep at the
  already-locked 0.10.6; `curve25519-dalek` 4.1.3 is already in `Cargo.lock`
  for the X25519 `local_public_key` derivation — promote if needed)
- (Option a only, if ratified) NEW `test/incus/wg-interop.sh` + a `make`
  target that provisions a Debian-13 `--vm` kernel-wg peer, wires cross-VM UDP
  reachability, and drives the test-only UDP socket harness. NOT built under
  Option (b) — the live kernel-wg-VM interop test moves to S2.
- EDIT `docs/wireguard-interop.md` (NEW: wire-compliance status + the
  kernel-wg-on-VM interop recipe, marked S2 under Option b) and flip the
  relevant OUT items in `docs/pr/wireguard-clean/plan.md` to DONE for handshake
  framing + TAI64N.
- NO `test/wg-interop-peer/` Go module, NO `golang.zx2c4.com/wireguard`
  dependency — wireguard-go is rejected; the reference is kernel WireGuard on a
  real VM.

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
  for msg2) — the most common framing bug; the `mac1_keys_on_recipient_static_pub`
  KAT test (and, in S2, the live kernel-wg peer) is what catches a swapped key.
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
| Wire-correctness (byte-level) | **HIGH** | The whole point. Mitigated by spec KAT vectors pinning construction hashes / MAC1 / TAI64N / message layouts to canonical values (§5.4a); the independent-peer proof against kernel WireGuard is S2 (Option b) — a wrong byte ⇒ KAT mismatch ⇒ test fails, and in S2 ⇒ kernel wg drops. |
| TAI64N monotonicity / self-DoS | **MED** | Mitigated by mutex-guarded strictly-increasing clock + the `tai64n_strictly_monotonic` test. Cross-restart persistence deferred (documented). |
| Architectural mismatch (#961/#946-P2 dead-end) | **LOW** | Design matches snow's proven `write_message(payload)` boundary; not a speculative rearchitecture. The research plan already validated Path A 3-of-3. |
| S1/S2 boundary mis-scope | **MED** | If the live interop test belongs in S1 (Option a) but is deferred, S1 ships an unproven-against-peer framing. Mitigated by the KAT vectors (canonical, independent of xpf) + plan-review's explicit (a)/(b) ratification. |

---

## 9. Test plan

- `cargo build` clean (release).
- `cargo test --release` full suite — all existing + new unit tests
  (handshake framing round-trip, mac1 key-on-recipient, TAI64N monotonic,
  TooShort/BadType/Mac1Mismatch arms).
- **Spec KAT vector tests** (§5.4a) — **the S1 success criterion** under
  Option (b): `construction_hashes_match_spec`, `mac1_keyed_blake2s_128_kat`,
  `mac1_keys_on_recipient_static_pub`, `msg1/msg2_layout_byte_offsets`,
  `tai64n_encoding_kat`, `tai64n_strictly_monotonic`, `framing_roundtrip`,
  `engine_self_handshake_with_framing`.
- **5× flake** on the framing tests (esp. `engine_self_handshake_with_framing`
  and `tai64n_strictly_monotonic`) — must be 5/5.
- Go suite `go test ./...` (30 packages) — confirm unaffected (no Go code added
  in S1; the kernel-wg harness, if Option a, is shell + incus, not Go).
- `make audit-check` — confirm engine.rs stays < 2000 LOC and the new files
  are registered; regen `docs/refactoring-audit-current.txt` if a wg file
  crosses 1500.
- **(Option a only)** live kernel-wg-on-VM interop, run on the cluster via
  `test/incus/wg-interop.sh` — both directions handshake-complete against a
  real Debian-13 `--vm` kernel WireGuard peer. Under the RECOMMENDED Option (b)
  this moves to S2.
- **NO CoS/iperf cluster smoke for S1.** This is handshake/wire-protocol, **not
  a datapath change** (no encap/decap on the AF_XDP hot path — that is S3). The
  CoS/iperf3 matrix exercises the AF_XDP fast path, which S1 does not touch.
  Stated explicitly per the task. The CoS/iperf cluster smoke belongs to
  research-plan S3 when the engine goes on the hot path.

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
   diverges from kernel WG's `encrypt(timestamp)` so the harm only surfaces as
   a tag-verify failure on the peer side? (Probe says lengths match; the S2
   live kernel-wg test is the ultimate proof — but does S1 need a stronger
   in-tree assertion than length, e.g. a KAT for the full msg1 against a
   pinned ephemeral?)
2. **mac1 = keyed-BLAKE2s-128, not HMAC.** Confirm against the canonical WG
   construction that it's keyed-BLAKE2s (`blake2s` with the key param, NOT
   HMAC-BLAKE2s), key = `BLAKE2s-256(LABEL_MAC1 || recipient_static_pub)`
   (32-byte hash used as the keyed-BLAKE2s key, 16-byte output). The KAT vector
   in §5.4a (`78df3b0a90577688ce9d272d04a8fb90` for key over 0x42×32 pubkey,
   message `b"abc"`) pins this. Wrong hash width or HMAC vs keyed ⇒ silent drop.
   Is my "HASH = BLAKE2s-256, MAC = keyed-BLAKE2s-128" reading correct?
3. **Is in-process TAI64N monotonicity + a deferred persist hook acceptable
   for S1**, or must S1 land disk persistence (research §9 ties it to S2)? I
   argue persistence belongs with daemon/config integration (S6) since S1 has
   no daemon wiring. Kill the deferral if a reviewer shows S1 can ship a
   handshake path that regresses the clock.
4. **Are the spec KAT vectors (§5.4a) a sufficient S1 merge gate** with the
   live kernel-wg-on-VM test deferred to S2 (Option b)? The KAT vectors pin the
   framing/MAC1/TAI64N bytes to the canonical construction (independent of
   xpf's own code), but they do not prove an independent kernel peer accepts
   the datagram. Is "KAT vectors green + engine self-handshake-with-framing
   green" enough to merge S1? (Tied to Q7.)
5. **Index allocation / receiver_index echo.** msg2 must echo msg1's
   sender_index as its receiver_index, and the responder's own sender_index
   must be installed for inbound demux. Does the existing `install_session`
   uniqueness discipline compose cleanly with framing-chosen indices, or is
   there a race when both roles are driven in one process?
6. **Are the precomputed KAT hex values trustworthy** given they were generated
   from an offline oracle (the canonical BLAKE2s construction)? Should the test
   instead re-derive them from first principles (raw `blake2` calls in the
   test) so the test does not depend on a transcribed magic constant — i.e.
   assert xpf's framing-layer hash == an independently-computed
   `blake2s::Blake2s256` call in the same test, rather than a baked hex string?
   (I lean: do BOTH — bake the hex AND re-derive — so a transcription typo and
   an implementation bug can't both pass.)
7. **S1/S2 boundary: (a) test-only UDP socket + VM-peer harness in S1, or (b)
   defer the live kernel-wg-on-VM interop to S2?** (See §5.4b.) I recommend (b):
   the live test now needs a dedicated VM peer + cross-VM UDP reachability, a
   non-trivial harness better built once in S2 next to the datapath UDP
   plumbing; S1 stays a clean, `cargo test`-provable wire-protocol-correctness
   PR. PLAN-review MUST return an explicit (a)/(b) verdict. Reference peer =
   kernel WireGuard on a real VM regardless. PLAN-KILL if neither boundary
   gives a coherent S1.

---

## SMR-R1 — Claude domain-SMR hostile plan review (round 1)

Reviewer: Claude (in-conversation), acting as crypto/protocol + CPU-arch +
SW-design SMR per the triple-review-includes-Claude-SMR rule. Stance: hostile;
PLAN-KILL is on the table for wire/crypto work. Findings are grounded in
independent verification I ran before writing this (not just reading the plan).

### Independent verification performed (evidence, not assertion)

1. **snow IK msg1 byte-layout is byte-exact for WG msg1 inner — VERIFIED.**
   Read `snow-0.10.0/src/handshakestate.rs:223-322` (`_write_message`)
   end-to-end. The token loop writes `E` → 32-byte ephemeral (`message[..32]`,
   `mix_hash(pubkey)`), then `S` → `encrypt_and_mix_hash(self.s.pubkey(), ..)`
   = 48 bytes. **Then, unconditionally after the loop**
   (`handshakestate.rs:315-317`):
   `encrypt_and_mix_hash(payload, &mut message[byte_index..])`. So msg1 body =
   `e[32] || enc_s[48] || enc_payload[len+16]`. Passing the 12-byte TAI64N as
   `payload` yields `e[32]||enc_s[48]||enc_ts[28]` = 108 bytes — **identical to
   WG msg1 inner**, and the timestamp IS mix-hashed into the transcript exactly
   as kernel WG does (`ConsumeMessageInitiation` mix-hashes `msg.Timestamp`).
   Q1 is **RESOLVED**: there is no snow-side length prefix or extra MixHash;
   the payload is the last AEAD chunk. (Caveat held for S2: this is a
   structural proof; the live kernel-wg test still must verify the AEAD tag.)

2. **KAT vectors reproduce from Rust `blake2` first-principles — VERIFIED.**
   I wrote a throwaway Rust bin using `blake2 0.10` (the locked version) and
   recomputed all four §5.4a vectors. All four match the plan's hex AND the Go
   oracle byte-for-byte: ICK `60e26d..cd36`, IH `2211b3..9ef3`, MAC1 key
   `172c34..0a4e`, MAC1("abc") `78df3b0a90577688ce9d272d04a8fb90`. Critically,
   the MAC is `Blake2sMac<U16>` via `KeyInit::new_from_slice(key)` —
   **keyed-BLAKE2s-128, NOT HMAC** — and it produces the correct value, so the
   `blake2` crate is the right primitive and the implementation is feasible
   with a locked dep. Q2 is **RESOLVED** (keyed-BLAKE2s-128, key =
   BLAKE2s-256("mac1----"||recipient_pub)); the plan's reading is correct.

### Findings

- **SMR-1 (MINOR, accept): make the KAT tests dual-source (Q6).** Per my own
  verification path, the strongest test is BOTH a baked hex literal AND an
  in-test re-derivation from raw `blake2` — a transcription typo fails the
  re-derivation, an implementation bug fails the baked vector. The plan §5.4a
  now says this; keep it as a hard requirement, not a "should".

- **SMR-2 (MINOR, accept): add a full-msg1 KAT against a pinned ephemeral.**
  The construction-hash + MAC1 KATs are necessary but not sufficient — they do
  not exercise the *assembly* of the 148-byte msg1. snow's `Builder` supports
  a fixed ephemeral (`fixed_ephemeral` path seen in `_write_message:236`); with
  pinned local-static + ephemeral + a fixed TAI64N, the entire 148-byte msg1
  (and the 16-byte mac1 over `msg[0..116]`) is deterministic and can be a KAT.
  This is the single test that would catch an offset/endianness bug in the
  framing assembly that the per-field KATs miss. Add it to §5.4a. (If snow does
  not cleanly expose a fixed-ephemeral builder at the engine layer, fall back to
  asserting the mac1 over a captured msg-prefix — still catches the offset bug.)

- **SMR-3 (S1/S2 boundary, Q7 — CONCUR with (b), with a condition).** I agree
  the live kernel-wg-on-VM interop belongs in S2: it now needs a VM peer +
  cross-VM UDP reachability + (likely) `apt install wireguard-tools` on the
  peer, which is real harness surface that does not belong bolted onto a
  security-critical framing PR. BUT the condition: S1 must NOT claim "interop"
  in any operator-facing doc or the CLAUDE.md feature list — S1 ships
  "wire-protocol framing + TAI64N, spec-vector-validated; independent-peer
  interop proven in S2." The research plan §10 already gates the feature-list
  line on S3; keep S1's claim honest. With that, (b) is the right call.

- **SMR-4 (MED, must-address-in-impl): TAI64N monotonicity is necessary but
  the plan understates the within-process race.** The clock is a
  `Mutex<[u8;12]>` returning strictly-increasing values — fine. But the WG
  self-DoS hazard is per *remote peer*, and kernel WG compares the new
  timestamp against the **last accepted** one *for that peer*. A single global
  monotonic clock is sufficient (any strictly-increasing source works — WG does
  not require wall-clock accuracy, only monotonicity), so the global clock is
  correct. The real S1 risk is narrower: if two initiations to the *same* peer
  are built concurrently, both must get distinct, ordered TAI64Ns — which the
  mutex guarantees. No KILL; flag for the impl to add a test that N concurrent
  `now()` calls yield N strictly-ordered values. Deferring disk-persistence to
  S6 is acceptable **because S1 has no daemon** — a process with no persisted
  state cannot regress a clock it never reloads. Concur with the deferral.

- **SMR-5 (MINOR): mac2 skip-on-parse must be explicit and tested.** S1 emits
  mac2 = zeros and does not verify inbound mac2. A compliant quiet-tunnel peer
  sends mac2 = zeros, so this interops; but the parse path must *accept*
  non-zero mac2 (a peer that has issued us a cookie would set it) without
  treating it as malformed — i.e. parse must not reject on mac2 != 0. Add a
  `parse_initiation_accepts_nonzero_mac2` test. (Cookie *generation* is S7.)

- **SMR-6 (design, LOW): the four engine entry points should not leak
  `HandshakeState` across the engine boundary if avoidable.** §5.3 sketches
  `consume_response(hs: HandshakeState, ..)`. Passing the in-progress snow
  state out and back in is the pattern the existing tests use, but it widens
  the engine's public surface with a snow type. Prefer the engine holding the
  pending `HandshakeState` in a small slow-path map keyed by sender_index (the
  initiator chose it; the responder echoes it), so the API trades only
  `[u8;32]`/byte-slices. Not a KILL — but resolve the boundary shape in Step 5
  and prefer the narrower one. (This also pre-stages the S3 integration where
  the coordinator thread owns pending handshakes.)

### Verdict

**PLAN-NEEDS-MINOR.** The architecture is sound and the two highest-risk wire
claims (snow byte-exactness; keyed-BLAKE2s-128 MAC1 + the KAT vectors) are
**independently verified by me**, not merely asserted. The design correctly
isolates framing into new modules (engine.rs stays WATCH-tier), preserves the
slow-path-only-crypto boundary, and the snow payload==timestamp mapping is
exact. Minor items SMR-1/-2/-5 tighten the test gate; SMR-4/-6 are impl-time
notes; SMR-3 ratifies S1/S2 boundary Option (b) with an honesty condition on
the interop claim. **No KILL.** Proceed to implement once Codex + AGY converge
(both must also ratify (a)-vs-(b)); fold SMR-1/-2/-5 into §5.4a as hard test
requirements before coding.

---

## v3-convergence — round-1 plan-review findings + dispositions

Three independent hostile reviews of plan v2 (@ `2b51e4b4d` / `14ce2c020`):

- **Codex** (`task-mpt6qx4i-i04py6`): **PLAN-NEEDS-MAJOR**. Independently
  recomputed the MAC1 KAT (and showed HMAC gives a different value —
  `778123b8...`), confirmed snow IK byte-layout + prologue/psk transcript,
  confirmed the recipient-key direction. Recommended Option (b) strengthened.
- **AGY** (`adversarial-review-mpt6r70o-ebe5a4`): **PLAN-NEEDS-MAJOR**.
  Independently recomputed the MAC1 KAT via a Python BLAKE2s oracle (match),
  confirmed snow byte-exactness + prologue + psk2, re-confirmed engine.rs stays
  ~1846 LOC. Found the TAI64N epoch-offset bug and the index blackhole race.
  Recommended Option (b+).
- **Claude-SMR**: **PLAN-NEEDS-MINOR** (see §SMR-R1). Independently verified
  snow `_write_message` payload handling end-to-end and recomputed all four KAT
  vectors from the Rust `blake2` crate first-principles.

All three converged: design is sound (no KILL), snow byte-exactness holds, MAC1
is keyed-BLAKE2s-128, S1/S2 boundary = Option (b+).

| # | Finding | Source | Severity | Disposition in v3 |
|---|---|---|---|---|
| 1 | TAI64N epoch offset must be `0x400000000000000a` (= `2^62 + 10`), not `2^62` | AGY-2 | MAJOR | FIXED §4.3 + corrected `tai64n_encoding_kat`. Verified against `tai64n.go` `base`. |
| 2 | Nanos must be whitened `&^ 0x00FFFFFF` to match the reference | Claude (found verifying AGY-2) | MED | ADDED §4.3 + test asserts whitening. |
| 3 | Index-allocation blackhole race — reserve index BEFORE sending msg | AGY-1 / Codex-4 | CRITICAL | FIXED §5.3 two-phase reservation layer + release-on-fail + concurrent test. |
| 4 | `local_public_key` missing — inbound MAC1 parse needs OUR static pub | Codex-2 | MAJOR | ADDED §5.3 — derive once at `new`, store, test vs snow. |
| 5 | TAI64N persistence story inconsistent (§1 "persisted" vs §5.2 deferred); specify nanos carry | Codex-3 | MAJOR | FIXED §1 + §5.2 — in-process monotonic only; disk persist = S6; carry spec'd §4.3. |
| 6 | S1 KAT too weak — need full deterministic msg1/msg2 wire-body KATs | Codex-1 / SMR-2 | MAJOR | REQUIRED §5.4a `msg1_full_kat_fixed_ephemeral` (+ msg2). |
| 7 | KAT tests must be dual-source (baked hex AND in-test re-derive) | SMR-1 | MINOR | REQUIRED §5.4a. |
| 8 | `parse` must accept non-zero mac2 (skip-verify, not malformed) | SMR-5 | MINOR | REQUIRED §5.4a `parse_initiation_accepts_nonzero_mac2`. |
| 9 | Concurrent-TAI64N-monotonic test | SMR-4 | MINOR | REQUIRED §5.4a. |
| 10 | NTP step-back / restart self-DoS during integrated testing | AGY-3 | DOC | S2 runbook item (flush peer WG state); durable fix = S6 disk persist. |
| 11 | Keep `HandshakeState` engine-internal (narrow boundary) | SMR-6 | LOW | §5.3 — engine holds pending HS keyed by reserved index. |
| 12 | Option (b+): don't claim operator-facing interop until S2 proves it | Codex/AGY/SMR-3 | GOVERNANCE | §5.4b — strengthened S1 gate (full KATs) + honesty condition. |
| 13 | S2 peer-VM SR-IOV wiring (mlx1/vlan3667, 10.0.61.103) + free-VF check | user | INFO | RECORDED §5.4c for the S2 plan. |

All MAJOR/CRITICAL findings are addressed in v3. Remaining work is a confirming
round-2 (Codex + AGY) on v3, then implement per §5 with the strengthened
§5.4a gate.

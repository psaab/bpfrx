# Claude-SMR HOSTILE plan-review r1 — #1703 WireGuard/Ubiquiti interop

Reviewer posture: domain SMR (HPC networking + crypto protocols + CPU/arch +
SW design). HOSTILE per `feedback_triple_review_includes_claude_smr` — I am
trying to break this plan, not bless it.

## Verdict: PLAN-READY (as a staged build-out plan, Path A)

The plan's central verdict (NOT-YET-INTEROPERABLE) survives hostile scrutiny.
I tried four kill-shots and none landed. Findings below are nits/sharpenings,
not blockers.

## Kill-shots attempted (all failed → claim stands)

### KS1 — "the engine IS secretly wired; the plan over-claims a dead module."
Refuted. `grep -rn "WgEngine::new" userspace-dp/src/` returns only `tests.rs`
and `engine.rs` test fns (lines 1006/1016/.../1680 are all inside
`#[cfg(test)]`). The only non-test reference to the module is `mod wg;` at
`afxdp/mod.rs:129`, carrying `#[allow(dead_code)]` (`wg/mod.rs:28`). The three
encap call sites named in the plan (`frame/mod.rs:212`,
`frame/tcp_segmentation.rs:309`, `tunnel.rs:189`) call
`encapsulate_native_gre_frame` with no WG branch. KS1 dead.

### KS2 — "snow's IK msg1 already contains the type byte / index / mac, so the
framing isn't really missing." Refuted. snow implements the Noise framework,
not WireGuard. Noise IK message 1 = `e, es, s, ss` + payload =
`unencrypted_ephemeral(32) || encrypted_static(48) || encrypted_payload`. It
contains NO `message_type`, NO `sender_index`, and NO `mac1`/`mac2` — those are
WireGuard-specific fields the spec layers AROUND the Noise message
(www.wireguard.com/protocol, msg type 1 has `mac1[16]` + `mac2[16]` as the last
32 bytes; the type byte + reserved + sender_index are the first 8). The engine
itself documents this exclusion at `engine.rs:26-35`. And the callers pass an
EMPTY payload (`write_message(&[], ...)` — `tests.rs:79,281,306,577,866`), so
the TAI64N timestamp that WG carries as msg1's payload is absent. KS2 dead — the
gap is real and interop-blocking.

### KS3 — "the Noise transcript-init is subtly WRONG so even the data path
won't interop." Refuted, but it makes the OPPOSITE point: the transcript init
is CORRECT. For BLAKE2s (HASHLEN=32) and a 37-byte protocol name, Noise sets
`h = HASH(protocol_name)` (name > HASHLEN ⇒ hashed, not zero-padded), then
`MixHash(prologue)` ⇒ `h = HASH(h || prologue)`. With
`prologue = WG_PROTOCOL_ID_BYTES = "WireGuard v1 zx2c4 Jason@zx2c4.com"`
(`wg/mod.rs:82`) this equals WG's `Ci = HASH(CONSTRUCTION)`,
`Hi-inner = HASH(Ci || IDENTIFIER)`. The remaining `MixHash(responder.static)`
is performed by snow's IK `rs` setup. So the inner crypto transcript matches
kernel WG byte-for-byte. The plan states this correctly (§2.2) and does NOT
mis-attribute the gap to the crypto. Good — a sloppier plan would have claimed
"the handshake crypto is broken"; this one correctly isolates the gap to the
OUTER framing + timestamp.

### KS4 — "Path A is fantasy: you can't prove UniFi interop without UniFi
hardware." Refuted. UniFi Network's WG VPN runs on the gateway's Linux kernel
WireGuard module (Ubiquiti ships standard kernel WG, not a fork). wireguard-go
and kernel `wg` implement the identical wire protocol with the identical strict
mac1/TAI64N gates. A handshake that wireguard-go authenticates is, by the
protocol's construction, one a UniFi gateway authenticates. The plan correctly
caveats that a FINAL manual run against real UniFi 10.4+ hardware closes the
issue (§8), but the falsifiable wire-compliance gate is wireguard-go. KS4 dead.

## Findings (nits / sharpenings)

1. **[minor] TAI64N monotonicity is under-specified as a risk, not a design.**
   §9 flags it, but S2 will live-or-die on it: kernel WG rejects an initiation
   whose TAI64N is ≤ the greatest previously seen from that peer. If xpf's
   clock is non-monotonic across restart (or two RG nodes disagree), xpf
   DoSes its OWN handshakes. S2 must specify a persisted per-(local,peer)
   high-water mark and an HA-replicated timestamp floor. Recommend promoting
   this from "risk" to an explicit S2 acceptance criterion. Not a blocker for a
   /research verdict.

2. **[minor] HA/RG interaction omitted from the sub-issue list.** The loss
   userspace cluster is RG-aware; a WG session and its replay window must
   migrate (or deliberately re-handshake) on failover. plan doc:473 lists
   "HA / RG-aware session migration" as OUT of the engine PR; #1703's S-list
   (§7) doesn't carry it forward. Add an S8 (or fold into S5) so failover
   doesn't silently black-hole the tunnel. Worth a line; not a blocker.

3. **[minor] mac1 keyed-hash detail.** §2.2 says mac1 = `MAC(HASH("mac1----" ||
   responder.static_public), msg[0:mac1])`. Correct, but note the MAC is
   keyed-BLAKE2s (BLAKE2s with the 32-byte key), not HMAC. S2 must use the
   keyed variant; the engine's `snow`/`blake2` deps already expose it. Flag for
   S2 so an implementer doesn't reach for HMAC-BLAKE2s.

4. **[trivial] base64 vs hex key path is the only "config" subtlety worth
   pre-flagging in S6** and the plan does (§9). Confirm: UniFi emits 44-char
   base64; engine wants 64-char hex. Decode at commit, reject malformed. Fine.

5. **[trivial] "EdgeOS/UDM follow for free" is true at the protocol layer but
   EdgeOS exposes `route-allowed-ips` / firewall-marking quirks** that are
   config-ergonomics, not interop. The plan correctly scopes them secondary.

## Why not PLAN-KILL

A PLAN-KILL would require either (a) the engine is already interoperable (KS1/2
refuted — it is not on the hot path and lacks handshake framing+TAI64N), or
(b) the work is pure test (false — §2.2/§2.4/§2.5 show three independent
build-outs are required). Neither holds. The plan is also NOT the rejected
config-only Path B; it correctly identifies the handshake-framing work as the
critical path. This is a legitimate multi-PR plan with a falsifiable gate.

## Why not PLAN-NEEDS-MAJOR

The evidence is both-sides-grounded (code line refs AND protocol-spec quotes
per `feedback_wire_protocol_both_sides`), the gap classification is sound, the
path options are real with an explicit rejection of the tempting-but-wrong Path
B, and the test plan is falsifiable without vendor hardware. The findings are
all additive (promote TAI64N risk to S2 criterion; add HA sub-issue); none
invalidate the verdict or reorder the critical path.

PLAN-READY. Recommend the author fold findings 1–3 into the plan before
/engineer, and add an HA sub-issue (S8).

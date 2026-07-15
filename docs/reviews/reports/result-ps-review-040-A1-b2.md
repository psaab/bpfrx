# Triage Result — ps-review-040-A1-b2

- **Subsystem**: Area A1 Batch 2 — `userspace-dp/src/afxdp/*` sweep (115 files), Antigravity module-by-module audit
- **Base == current master?**: Yes — triaged against `origin/master`
- **Master SHA**: `95b33d49634d56086269a62a92e213dae7926f88` (fetched at triage time)
- **Repo**: real bpfrx (`/home/ps/git/bpfrx`) — no avacado-xpf fork paths cited
- **Outcome counts**: 1 finding total → 0 GENUINE-RESIDUAL, 1 NOT-MATERIAL (correct-by-design / documented+tested). The report is ~110 "No findings" module-sweep entries plus this single Low finding.

---

## Finding 1 — WireGuard responder builds with zero PSK before peer lookup (Low, design-hygiene)

**Cited**: `userspace-dp/src/afxdp/wg/engine.rs:1650-1659`, `build_responder_handshake` pre-mixing `WG_ZERO_PSK` via `.psk(2, &WG_ZERO_PSK)`.

**Disposition: NOT-MATERIAL** (correct-by-design; also DELIBERATE — the documented, tested IKpsk2 responder ordering).

### Symbol existence / line drift
`build_responder_handshake` EXISTS on current master, but at **line 1692**, not the cited 1650 (line drift from the audited snapshot). The `.psk(2, &WG_ZERO_PSK)?` call is at line 1699. `WG_ZERO_PSK` is defined `wg/mod.rs:136` = `[0u8; 32]`. Not confabulated.

### Why it is not a bug — the IKpsk2 mechanics
The Noise pattern is `WG_NOISE_PATTERN = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"` (`wg/mod.rs:132`). The `psk2` token means the PSK is mixed at **token position 2, which lives in the SECOND handshake message (msg2, the response WRITE)** — not in msg1 (the initiation READ). Therefore the zero PSK the builder pre-sets is **inert during `read_message(msg1)`**: reading the initiation does not consume the PSK at all, so any placeholder value is equivalent.

The sole production consumer, `wg/handshake_session.rs` `consume_initiation_*` (line 541), executes the correct "identify-then-key" ordering that IKpsk2 responders require:
1. `build_responder_handshake()` → placeholder zero PSK (line 541-542)
2. `state.read_message(noise_body, &mut ts_sink)` reads msg1 — PSK not yet used (line 549)
3. `state.get_remote_static()` recovers the initiator static key → identifies the peer (line 553-561)
4. `peer_config(&peer_pubkey)` lookup; unknown peer → `UnknownInitiator` (line 562-564)
5. #4092 TAI64N anti-replay `check_and_update_tai64n` before any expensive work (line 578-581)
6. `state.set_psk(2, &psk)` installs the identified peer's real PSK **before** msg2 (line 592-594)
7. `state.write_message(&[], msg2)` — the Psk(2) token is mixed HERE with the correct key (line 608)

So by the time the PSK actually affects the transcript (msg2 write), the real per-peer PSK is in place. A peer with no configured PSK keeps `WG_ZERO_PSK` = pre-#1434 behavior, bit-for-bit.

### The "relies on snow's mutable set_psk / if snow changes" concern
This is the finding's entire "Why it matters", and it is speculative-future hygiene, not a defect on current master. It is guarded three ways today:
- **Explicitly documented** at `engine.rs:1666-1671` (initiator) and `handshake_session.rs:583-593` (responder) — comments spell out that PSK is mixed at msg2 and must be set before the write.
- **Directly tested**: `wg/engine_tests.rs:982-1045` `per_peer_psk_handshake_roundtrip` exercises the exact "set_psk-after-msg1" responder path — matching PSKs complete the handshake, and a mismatched PSK **fails the msg2 AEAD** (`init_hs.read_message(msg2).is_err()`), proving the PSK is genuinely enforced (not merely no-op'd).
- **Single production path**: `git grep build_responder_handshake` shows only `handshake_session.rs:541` in production; every other caller is a `_tests.rs`/`tests.rs` fixture. There is no second consumer that could forget the override, so the finding's own fix-direction ("enforce override in all consumer paths") is already satisfied — there is one path and it overrides.

### Severity justification
The finding self-rates Low and admits the override exists (`consume_initiation_create_response_inner` overrides via `set_psk`). There is no input that produces a wrong output on current master: no PSK-mismatch bypass (msg2 AEAD fails), no unknown-initiator acceptance (`UnknownInitiator` guard), no replay acceptance (#4092 gate). The residual TODO at `engine.rs:1681-1691` (`TODO(#1499 r4`) is about surfacing a convenience helper API, not a correctness gap. Not filing as a residual.

---

## Module sweep (lines 35-496)
~110 "No findings" entries across the `afxdp/` tree (icmp*, mirror, neighbor*, parser, poll_descriptor/*, session_glue/*, tx/*, types/*, umem/*, wg/*, worker/*). No claims to triage — negative results only, consistent with a heavily-hardened codebase (ps-038 core scopes yielded ~0 residuals; the #4517-#4685 hardening range covers WG anti-replay, IKE gate, nat64, VRRP, zeroize, CoS lease, etc.). Nothing actionable.

## Conclusion
0 genuine residuals. The single finding is a correct-by-design, documented, and unit-tested IKpsk2 responder ordering — the zero PSK is a mandatory pre-msg1 placeholder that is provably inert until overwritten with the real per-peer PSK before the msg2 write. Expected outcome for this well-hardened area.

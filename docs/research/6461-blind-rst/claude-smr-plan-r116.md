# Claude SMR hostile plan-review — round 116 (v10.31.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-sixth
pass; I authored the v10.31.0 fold of Codex r115's 7B/1H/1M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r115-1 (B — the site-2b OPENING-proof bypass).** The round's real
new attack surface, and verified: the synth installer computes
`established = !(PROTO_TCP && is_initial_syn(tcp_flags))`
(`install.rs:157-180`) — every non-initial-SYN TCP packet, including
a blind reverse SYN-ACK, installs ESTABLISHED with no proof — and the
fresh reverse entry can retain the OPENING forward half through
companion retention (`expire.rs:296-320`, `:468-523`). The fold:
when the driving packet is a SYN-ACK, the synth runs the same strong
OPENING proof the §5.5 promote uses; a proof-FAILING SYN-ACK skips
the install entirely (the site-2b refuse precedent:
`created=false, install_failed=true`, no cache insert, packet
forwarded, the next legitimate packet re-synthesizes). Non-SYN-ACK
synths keep master's #3152 mid-stream-pickup established seed
(deliberate asymmetric-routing preservation; its blind-spoof residual
is pre-existing master behavior). Self-attack: (i) does the proof
break a legitimate asymmetric pickup? A pickup's first packet is
data/ACK, not a SYN-ACK — unaffected. (ii) Does the skip break a
legitimate delayed SYN-ACK? The packet is forwarded; the endpoint
retransmits the SYN-ACK if needed; the next transit re-synthesizes
with the proof re-run. (iii) The proof itself is the §5.5 strong
OPENING proof, already reviewed for nine rounds.

**r115-2/3 (B — producer contract + final identity).** Every
successful install/adopt path now returns its FINAL token: the fresh
ForwardFlow install gains an OUT (it returns only `bool` and creates
its epoch internally today, `install.rs:139-152`,
`poll_descriptor/mod.rs:2449-2458`); the reverse synthesis returns it
(currently `(SessionLookup, bool)`, `shared_ops.rs:824-895`); the
forward-wire match carries the matched entry's epoch
(`lookup.rs:258-292`, `entry.rs:208-213`); the materialize returns
the installed identity; and the resolved result carries the FINAL
post-promotion identity (the promotion advances `install_epoch` and
can change NAT/orientation, `session/mod.rs:1344-1397`, and runs
before the resolved result is constructed,
`session_glue/mod.rs:1157-1261` — the promote's OUT reports the final
identity and the constructor uses THAT).

**r115-4/5/6 (B/B/H — compare helper, family binding, eviction).**
The dedicated atomic compare-then-mutate helper (compare canonical
key/NAT/orientation/epoch FIRST, mutate only on agreement) covers the
commit-hook path AND `touch_if_stale` (`flow_cache_hit.rs:295-301`,
`session/mod.rs:1118-1133`); the token binds the FAMILY — the
reverse→forward hop re-verifies the forward entry's identity before
writing the anchor sample (in the stale-R1/replacement-K2 state,
R1's sample can never land on K2); and a cache-hit token mismatch
EVICTS the descriptor and falls through to a fresh resolution (the
intentional `None` purged/sessionless parity class stays distinct).

**r115-7 (B).** Already folded in v10.30.1 (the review was cut
against v10.30.0); verified the current text reads five consumers.

**r115-8 (M).** §8 now carries the token's footprint (~48 B on the
~96 B entry × 4,096 entries ≈ +192 KiB per worker,
`flow_cache.rs:5-14`, `:201-224`); §9's pending-path text is aligned
with §5.2's full rule.

## 2. Consistency sweep

Assertion-checked replacements; the token contract now names every
producer, the final-identity rule, the compare helper, the family
binding, and the eviction semantics identically in the SSOT and §9.
The gate (§5.1–§5.4, §5.7) is untouched for the thirty-first
consecutive round.

## 3. Bottom line

PLAN YES for v10.31.0.

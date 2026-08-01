# Claude SMR hostile plan-review — round 118 (v10.33.0 → v10.33.1)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-
eighth pass; I completed the interrupted v10.33.0 fold of Codex r117's
3B/3H/1M (findings 6-7 were unfolded at session boundary; findings 1-5
were folded) and then attacked the result. Verdict: **PLAN NO — one
MEDIUM, folded in-revision as v10.33.1** (the uncounted per-cache-hit
identity probe). Everything else in Codex r117 verifies folded and
code-accurate.

## 1. Fold verification (Codex r117, 3B/3H/1M)

**r117-1 (B — token provenance).** Folded: `MatchedToken { key, nat,
is_reverse, install_epoch, provenance }` with `MatchProvenance ::=
Canonical | ReverseTranslated | ForwardWire | FreshInstall |
Materialized | Promoted`; the forward-wire no-anchor-learn rule reads
`provenance == ForwardWire`. Premise code-verified: resolution does
collapse a `ForwardSessionMatch` into ordinary canonical handling with
no source discriminator retained (`lookup.rs:253-292`,
`shared_ops.rs:507-560`), so the tuple type genuinely could not carry
the marker.

**r117-2 (B — companion-epoch lifecycle).** Folded with a
representation improvement: `fwd_companion_epoch: u64` with 0 =
UNBOUND, not `Option<u64>`. Verified the sentinel is free:
`epoch_counter` starts at 0 and pre-increments
(`session/mod.rs:737`, `:762-763`), so every allocated install epoch is
>= 1 and 0 never denotes a live epoch; this keeps the field at 8 B and
preserves the v10.31.1 footprint claim (see r117-6). The lifecycle is
the one Codex specified: explicit F-epoch carriage on the positional
fresh-flow reverse install (`SessionInstall` is indeed absent on that
path — `install_with_protocol_with_origin`'s signature,
`install.rs:113-152`, has no such carrier; `ctx.rs:8-17` confirmed);
UNBOUND at HA import (F can refuse while R succeeds,
`session_import.rs:215-223`, `install.rs:310-323`); bind on first
reciprocity-passing verification; suppress-never-rebind on mismatch;
atomic rebind only on proven same-family transitions
(`session/mod.rs:1384-1397`, `:1642-1665`). I probed the lazy-bind
choice hostilely: binding on key+NAT agreement admits a same-tuple+NAT
replacement — but that is §5.5's own packet-indistinguishable stance
(exact tuple+NAT reuse needs no generation token), so the lazy bind is
consistent with the family-identity model the plan converged on in
rounds 114-116, not a new hole.

**r117-3 (B — ACK-knowledge proof).** Folded at all FOUR normative
homes, not just site 2b: the strong-OPENING-proof definition itself
(§5.2 — "ANY ACK-bearing segment (SYN-ACK or an exact-proving
ACK/PSH-ACK) whose ack proves this way authenticates the WHOLE
segment"), the site-2b rule (§5.6), the accept split's establishment
clause ("PROOF-PASSING non-closing synth"), and the §9 (ix-c9) matrix
row. Two SYN-ACK-only stragglers found and fixed in-revision (§9
(ix-c9) phrasing; the accept-split "SYN-ACK synth" clause). The
asymmetric-SYN-ACK repair case Codex raised (repeated reverse ACKs
neither installing R nor touching F, F expiring on its OPENING clock) is
closed by the fold: an exact-proving ACK/PSH-ACK is accepted, installs
R, and applies the flag-only establishment to F.

**r117-4 (H — Shared rows).** Folded as the complete (scope, state,
flags) table: (Local, OPENING, non-closing) proof-gated; (Local,
ESTABLISHED, non-closing) master-verbatim; (Shared, any, non-closing)
master-verbatim install with the anchor UNTRUSTED per the
absorbing-state rule; (any, any, closing) §5.4. Premise code-verified:
`SyncedSessionEntry` carries no `established` field and no OPENING
timing state (`worker/mod.rs:375-401`), so a proof gate keyed on state
the shared row does not have would be unimplementable; the chosen row
(master-verbatim install, untrusted anchor) is the only consistent
reading and preserves master's non-closing repair behavior.

**r117-5 (H — capacity-refused close transaction).** Folded: the
forward mutation (close mark on accept; flag-only establishment on
proof-pass) is explicitly independent of the reverse install's success
boolean; publication still rides `installed`; a proof-passing,
install-refused packet contributes NO anchor sample (no entry exists to
hang it on). Premise code-verified: the capacity return fires before
any mutation (`install.rs:113-125` — `create_drops` bump and `false`
with no entry write).

**r117-6 (H — footprint).** Folded AND corrected against the ABI
myself: `SessionKey` = 40 B (u8 + u8 + u16 + u16 + 2 x `IpAddr` at
17 B each, align 2 — `key.rs:9-17`); `NatDecision` = 44 B (2 x
`Option<IpAddr>` niche-packed at 17 B each + 2 x `Option<u16>` at 4 B +
2 bool — `nat/mod.rs:90-103`); `MatchedToken` = 96 B (8 + 40 + 44 + 1 +
1, align-8 padded; the `Option` niche-fills on the 6-variant provenance
enum). Cache cost = 96 x 4,096 = 393,216 B = +384 KiB per binding, not
192 KiB. Entry cost = 49 B (40 anchor + 1 probation + 8
companion-epoch-sentinel) = 6,422,528 B = 6.1 MiB/worker at the
131,072 cap, 36.7 MiB at 6 workers. The overview (5.2 MiB), §5.1
(48 B), §5.8, §8 (6.3 MiB / 48 B / 192 KiB / "No FlowCacheEntry
change"), §6 hot-path bullet, and the §9 layout line are now mutually
consistent, and §9 gates the claims with compile-time `size_of`
assertions on all four types (`TcpSeqAnchor` == 40, `MatchedToken` ==
96, `SessionEntry` delta <= 56, `FlowCacheEntry` delta <= 104).

**r117-7 (M — cache telemetry ordering).** Folded as the scoped promise
(Codex's option b): `lookup_counted`'s bookkeeping (LRU promote,
`hits += 1`, `last_used_epoch` stamp, `observed_bytes` add —
`flow_cache.rs:1023-1039`) fires before the identity check exactly as
it fires before master's validity checks; an identity mismatch takes
the master validity-failure path VERBATIM (`invalidate_slot` +
`FallThrough`, `flow_cache_hit.rs:115-133`), so telemetry moves
bit-identically to a master validity failure and the exact guarantee is
"no cached-decision consumer runs." §9 gained the crafted-mismatch
telemetry test pinning the shape.

## 2. The one new finding (folded v10.33.1)

**MEDIUM — the early identity check's session-table probe was not in
the per-packet cost accounting.** The v10.32.0 ordering puts an
identity-ONLY check immediately after cache validity
(`flow_cache_hit.rs:~133`) and the compare-then-mutate at final
admission; the epoch operand can only come from the session table, so
every session-backed cache hit gains a `key_to_handle` probe. §8 and
the §6 hot-path bullet counted only "one extra probe per closing
segment" + "8-byte read + <=2 gated stores." Fold: the probe is
same-key with the two probes master ALREADY does on every hit
(`touch_if_stale` + `account_packet`, `flow_cache_hit.rs:295-317` —
master's own comment calls the second "warm — `touch_if_stale` just
probed the same key"); the gate's probe becomes the packet's first
session-table touch and master's two ride it warm; the final-admission
compare-then-mutate re-validates on the same warm line — I code-verified
the no-interleaving-mutation premise (no `sessions.`/`account_packet`/
`touch_if_stale` call exists between `:133` and `:295`; the region runs
TTL/TE, filter counters, policers, logs, BA reclassify only). Net new
cost: one warm-cache probe + ~93 B of L1 compares per session-backed
hit. §8 and §6 now state it; §9's pps gate measures it.

## 3. Bottom line

v10.33.1 = Codex r117 (3B/3H/1M) + SMR r118 (1M), all folded and
code-verified. The gate (§5.1-§5.4, §5.7) is untouched for the
thirty-third consecutive round. PLAN YES for v10.33.1 as the round-118
review basis.

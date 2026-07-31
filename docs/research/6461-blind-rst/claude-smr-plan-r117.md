# Claude SMR hostile plan-review — round 117 (v10.32.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-
seventh pass; I authored the v10.32.0 fold of Codex r116's 4B/2H/2M.
Verdict: **PLAN YES**.

## 1. Fold verification

**r116-1 (B — state-keyed proof).** Verified the trace: the installer
computes `established = !(PROTO_TCP && is_initial_syn)`
(`install.rs:157-180`), so a bare ACK/PSH-ACK synth against an
OPENING forward bypassed my v10.31.0 SYN-ACK-only gate — the
bare-reverse-ACK pin (`lookup.rs:129-146` prevents exactly this on
the normal lookup path). The fold keys the proof requirement on the
FORWARD ENTRY'S STATE: any non-closing reverse synth against an
OPENING forward entry requires the strong OPENING proof (a SYN-ACK
proves by its ack against the forward SYN's interval; a bare ACK has
no proof to give and skips the install — the site-2b refuse
precedent), while an ESTABLISHED forward (incl. a #3152 pickup or an
import — no OPENING proof interval exists) keeps master's behavior
verbatim, so the legitimate-repair case is not rejected.

**r116-2 (B — family generation).** The reverse entry's
`fwd_companion_epoch` (v10.31.1) is now recorded from the forward
entry's epoch CARRIED on the match/install structs
(`entry.rs:208-213` gains it) at install and refreshed at each
committed hop; the compare is always against the RECORDED companion
epoch (forward and reverse installs allocate their own epochs —
comparing R's own epoch against F would fail by construction). The
§5.5 "exact tuple+NAT reuse needs no generation token" statement is
qualified: the reciprocity identity check stands for the
mark-propagation target; the epoch binding covers the ABA replacement
case.

**r116-3 (B — single token carrier).** One per-descriptor
`matched_token` slot on the dispatch context: initialized empty per
descriptor, set from EITHER the final resolved token (hit/materialize
paths) OR the fresh forward install's OUT (the fresh-miss path has no
`ResolvedFlowSessionDecision`, `poll_descriptor/mod.rs:2449-2458`,
`:3900-3959`), and a later reverse-companion install's token NEVER
overwrites it.

**r116-4 (B — safe ordering).** The identity-only check runs
immediately after the existing cache validity evaluation (ends
~`flow_cache_hit.rs:133`) and BEFORE any cached-decision consumer
(TTL, filter/policy counters, policers, logs, reject synthesis, the
terminal drop — `:94-180`, `:189-271`); a mismatch EVICTS and falls
through there (never double-accounts); the atomic compare-then-mutate
runs at final admission; the `None` class keeps master's query-key
touch parity, and authority mutations require `Some(token)` with
identity agreement.

**r116-5 (H — the site-2b establishment transaction).** A
proof-passing SYN-ACK synth applies the forward companion's flag-only
establishment update (the `session/mod.rs:1243-1252` companion
semantics — flag only, absolute opening deadline preserved); a
capacity-REFUSED reverse install still applies it (the proof passed;
the reverse re-synths on the next packet); a SYN-ACK+FIN/RST
validates the close (§5.4) but never establishment-promotes (rule 5).

**r116-6 (H — forward-wire marker).** The forward-wire match's token
carries the no-anchor-learn marker (the class's anchors advance from
the reverse mutable-alias direction only; the commit hook's anchor
write is suppressed for forward-wire-produced tokens; the resolution
currently collapses the class into ordinary `Canonical` without a
source discriminator, so the token carries the provenance
explicitly).

**r116-7/8 (H/M).** §8's performance row now carries the 49 B/entry
slab growth AND the per-binding cache token cost (~48 B × 4,096 ≈
+192 KiB per binding, `worker/flow_cache_state.rs:26-35`,
`worker/mod.rs:196-201`); §9 gained the full matrix (ix-c9).

## 2. Consistency sweep

Assertion-checked replacements; the contract block was re-read
top-to-bottom after the pass — the producer list (lookup / fresh
install OUT / reverse synth OUT / forward-wire match /
materialize / promote OUT) and the consumer ordering (early identity
check → consumers → final-admission compare-then-mutate) read
monotonically. The gate (§5.1–§5.4, §5.7) is untouched for the
thirty-second consecutive round.

## 3. Bottom line

PLAN YES for v10.32.0.

# Claude SMR hostile plan-review — round 113 (v10.28.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-third
pass; I authored the v10.28.0 fold of Codex r112's 1B/1H/2M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r112-1 (B — the direct-local-hit hole).** This was the round's real
catch and it is real: a canonical packet finds the probation entry K
LOCALLY (`shared_ops.rs:594-635` local-first), so no materialization
runs (`session_glue/mod.rs:1092-1121` requires `shared_entry`), the
report is `MaterializeReport::NONE`, and the
`effective_transition != Some(OverdueSkipped)` test passes — a
committed non-close would clear/restamp an overdue K to the ordinary
timeout, defeating the never-refresh guarantee (reachable because
expiry is strict and the GC periodic, `expire.rs:130-168`). The fold
adds the DIRECT matched-entry test at the commit hook:
`entry.probation && entry.last_seen_ns.saturating_add(
entry.expires_after_ns) <= now_ns` suppresses the clear+refresh on
ANY path — the guard now lives against the entry itself, not the
dispatch outcome, which is where it belonged all along (the dispatch
outcome covers the materialize path; the matched-entry test covers
the direct-hit path). §9 gains the phase-shifted direct-local-hit
regression (ix-d0).

**r112-2 (H — the buffered SYN-ACK promote).** Verified the mechanism:
the retry path carries no `SessionTable`
(`neighbor_dispatch.rs:272`-class), and the next packet (forward
ACK/data) is not `is_syn_ack`, so without a mechanism the forward
half could linger OPENING (`session/mod.rs:2135`) — and an
arbitrary-ACK promote would reintroduce the #4109 half-open pin. The
fold: the establishment promote fires at the packet's ADMISSION
commit point — for a buffered packet the pending-queue ENQUEUE (the
commit-to-deliver event) — with the proof evaluated at arrival. A
SYN-ACK dropped before admission never promotes (stricter than
master's in-borrow promote, which precedes the TTL check —
fail-conservative; the flow recovers on the SYN-ACK retransmit, which
IS `is_syn_ack`). The §5.2 retry-path claim is corrected (the promote
is the admission exception; the anchor update and probation clear
still wait for the next unbuffered packet).

**r112-3 (M — total invariant).** Normative and tested: `site=None →
effective_transition=None`; legal site-2c `T → Some(T)`; invalid
site-2c → `Some(OverdueSkipped)`; `Some(TransitionResult::None)`
never occurs; the refusal promotion gate is site-qualified (a
malformed `site=None, validation=Some(Refused)` report follows
master's dispatch).

**r112-4 (M — anchor claims).** §5.2 and §9 now carry the
`OverdueSkipped`/`UpsertRefused` anchor-commit suppression.

## 2. Consistency sweep

Assertion-checked replacements; the commit-hook guard now has two
explicit halves (dispatch outcome + matched-entry test) stated
identically in the SSOT and §9. The gate (§5.1–§5.4, §5.7) is
untouched for the twenty-eighth consecutive round.

## 3. Bottom line

PLAN YES for v10.28.0.

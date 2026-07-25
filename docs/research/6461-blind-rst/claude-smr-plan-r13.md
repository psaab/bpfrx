# Claude SMR hostile plan review — round 13 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v9/v9.1
(@ 968bc1d4a/57ba440ce), Codex r13 verdict (PLAN NO, 2B/5H/2M), AGY r13
verdict (PLAN YES, 3 LOW + 1 MEDIUM, all accepted residuals).

**The headline: Codex r13 conceded the gate itself.** Its bottom line:
"Part A's refusal gate has converged — no refused/no-baseline/
out-of-window live-session close path was found that promotes, marks,
or accelerates reap — and Phase 2 may remain a separate research track."
That is the issue's fix, converged after thirteen rounds. The remaining
PLAN NO attached only to Part B (the cleanup machinery), and every one
of those findings folds without touching the gate.

**Verdict: PLAN NO for v9/v9.1 as a whole (v9.2 required for Part B);
the gate (Part A) is declared converged by all three reviewers.**

## Adjudication of Codex r13 (all Part B)

1. **BLOCKER — stale E1 Close erases replacement E2 locally: CONFIRMED
   (the loop_body:811 → :887 → :970 trace is real).** A reaped E1 queues
   its Close; packets processed before the drain can install same-key
   E2; the drained stale Close then key-deletes E2's
   BPF/conntrack/DNAT/aliases/replicas. v9.2: EVERY local mutation
   driven by a Close delta is incarnation-conditional on the delta's
   `flow_incarnation_id` (queued packet drops are tuple-scoped and safe;
   state deletes compare first). Uniform, small, no protocol.

2. **BLOCKER — commit guard covers materialization only: CONFIRMED.**
   v9.2 extends the recheck to every shared-decision consumer:
   materialize, reverse-synth (`lookup_forward_nat_across_scopes` →
   `install_reverse_session_from_forward_match`), icmp_embed
   (`nat_match_v4.rs:41`, `nat_match_v6.rs:66`), and the asynchronous
   upsert/prewarm command consumption (prewarm clones at
   `shared_ops.rs:304/:357`, replication clones at
   `session_glue/mod.rs:838`, install at `upsert_synced.rs:64`). Every
   install/publish path now REQUIRES its NAT reserve to succeed
   (`upsert_synced.rs:80` no longer ignores failure and publishes at
   :112 — failure discards and re-resolves).

3. **HIGH — absolute phrasing: RESOLVED in v9.1** (before Codex's run
   finished): the claim everywhere is now the precise one — a blind
   close can mark only inside the acceptance window (~1/2^12–1/2^14 per
   blind packet) and every such mark was validated against observed flow
   state. Codex's own text confirms the equivalence: "The correct claim
   is probabilistic reduction from one-packet-anytime to sustained
   window guessing." Its sweep of the mark paths found NO ungated path
   from a refused/out-of-window/no-baseline close to a mark — the
   load-bearing confirmation.

4. **HIGH — retain probe has no atomic lifetime contract; #6522
   confirmed: the probe is deleted, not fixed.** The incarnation compare
   is the whole fence: E2's republish changes the alias id (compare
   fails); E1's purge removes the record (compare fails). The
   re-resolve then makes its own fresh reservation — correct for
   whichever flow the packet actually belongs to (a stray E1 retransmit
   becomes a fresh mid-stream pickup; E2's traffic continues
   undisturbed). No reservation-lifetime token needed.

5. **HIGH — queued UpsertSynced detached clones: CONFIRMED, folded with
   finding 2 (the command-consumption recheck + required reserve).**

6. **HIGH — expires_after_ns doesn't follow OPENING→ESTABLISHED:
   CONFIRMED.** A SYN publishes the 20 s opening timeout; the handshake
   later gives the entry the established timeout; a quiet established
   flow could be swept at K × opening (80 s) while its worker entry
   lives at 300 s. v9.2: the timeout is copied at publish AND refreshed
   on every stamp (the promote re-publish updates it; the 30 s batched
   push carries both `last_touch_ns` and the worker entry's current
   `expires_after_ns`, each incarnation-conditional); an explicit
   OPENING→ESTABLISHED sweep test is mandatory.

7. **HIGH — non-NAT stale authorization indefinitely renewable:
   CONFIRMED, and it's my v8.3 install-alive rule's cost.** A refused
   closing materialize installed alive at full timeout, stamped the
   clock, and could be renewed every 300 s with one blind close.
   v9.2: the refused materialize installs at the PROBATIONARY
   opening-window timeout (zombie ≤ 20 s) and closing-flagged
   materializes never stamp the family clock (only committed non-close
   packets and non-close events stamp). The sustain cost rises to
   1 packet/20 s for a zombie that forwards nothing new (the decision
   is stale by construction) — bounded and honest.

8. **MEDIUM — reverse-synth text/test disagreement: CONFIRMED.**
   The accept path now applies the FULL mark semantics atomically
   (sticky bits, reset-before-timeout recompute, `last_seen_ns`
   refresh, wheel push) on the matched entry AND the forward family in
   hand; the stale reverse-only/next-hit text and tests are aligned.

9. **MEDIUM — contract consistency: CONFIRMED.** The family now names
   the `dnat_table` side effect (`session_import.rs:122/:273`); the
   additive schema list includes `expires_after_ns`; the spray-duration-
   plus-one-timeout bound is aligned everywhere (the walk's non-close
   packets refresh `last_seen` — not a new pin primitive, since a plain
   keep-alive spray buys the same at identical guess cost); the
   "LocalDelivery bare-close seed" residual is corrected (LocalDelivery
   caches TCP only with SYN, `local_delivery.rs:20` — the actual
   residual is SYN|RST invented-tuple self-anchoring, master parity);
   the test contract is rewritten for Part B with Phase-2 items
   explicitly deferred to the brief.

## AGY r13 (PLAN YES) — dispositions

Its verdict covers the issue's harm correctly: Part A + Part B
"fully neutralize issue #6461's actual harm." Its three LOWs
(post-failover lingering, split-steering soft-refuse, re-import trust
reset) and one MEDIUM (#6522 isolated by the v9 sweep) are all
documented, bounded, and either accepted or separately filed. First
PLAN YES from any reviewer in thirteen rounds.

## Bottom line

Thirteen rounds, one clear endpoint. **Part A (the demote gate) is
converged by all three reviewers**: Codex found no ungated close-to-mark
path; AGY says PLAN YES on the issue's harm; my own re-trace across
twelve rounds of folded findings finds the gate's invariants intact.
**Part B is now uniformly fenced** (incarnation-conditional local
consumption, all-consumer commit rechecks, required reserves,
timeout-propagating liveness clock, probationary refused materialize).
**Phase 2 stays in its own track** (phase2-brief.md), and **#6522 is
filed** for the pre-existing NAT release bug. The residual inventory is
five named, bounded, documented items. My verdict on v9.2: PLAN-READY
modulo the final confirmation round — which should be scoped to
verifying the v9.2 fences hold, not reopening settled design.

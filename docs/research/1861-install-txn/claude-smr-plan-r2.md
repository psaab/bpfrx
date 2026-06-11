# #1861 Claude SMR hostile plan review — round 2 (plan v3)

**Reviewer:** Claude (domain SMR)
**Target:** plan v3 (folds Codex r1 C1-C4, AGY r1 F1, SMR r1 F1-F6)
**Stance:** hostile re-read of the v3 deltas against source.

## Verdict: PLAN-READY (one engineer-phase note, no plan-level objection)

Re-verification of the round-1 folds:

1. **C1 fold verified end-to-end.** The repaired-reply cache insertion is
   real: `resolve_flow_session_decision` returns `created: true` from the
   repair arm (`session_glue/mod.rs:1086`), control reaches the forwarding
   block, and `mod.rs:1995-2016` inserts the reply-direction decision with
   no install-success knowledge. The §5.4 gate (thread `install_failed`
   through `ResolvedFlowSessionDecision` to the cache-population `if`) is
   the minimal correct fix and restores the below-cap self-heal property.
   Hostile check on the gate's cost: the flag is `false` on every hit path
   and every successful install — one register-held bool test on the
   cache-population branch (cold path); no warm-path effect.
2. **C2 fold verified.** `allocate_v4_source` (`nat64.rs:97-105`) is a
   stateless round-robin pick — `fetch_add` on an index, no reservation,
   nothing to roll back; I14's "no persistent leak" column is correct, and
   `should_cache`'s `!decision.nat.nat64` (`flow_cache.rs:229`) excludes
   the cache-persistence face. Path A's refusal arm covers the
   one-translated-packet forward.
3. **C3 disposition is the right scope call.** Narrow-scope rule
   (engineering-style "Bug fix and behaviour choice do not ride in the
   same PR"); the I13 apply-side fix requires choosing semantics for the
   whole uncapped sync/replica family (I11). Follow-up issue + verbatim
   signoff line in the converged comment satisfies "explicit user
   signoff".
4. **Residual-arm consistency (engineer-phase note, not a plan defect):**
   the §5.2 release residual arms (impossible-by-construction
   post-preflight failures) should ALSO set `install_failed` so the
   tolerate-in-release path never caches a partially-installed flow's
   decision. The plan's §5.2 "forward residual" already drops the packet
   (no cache); the REVERSE residual keeps the forward and continues — that
   arm must set the flag. One-line detail; called out so the /engineer
   diff includes it and a pin covers it.

No new findings. The interleaving map now covers all production install
sites (`forwarding/mod.rs:1099` guarded, `session_glue/mod.rs:560`
UpsertLocal = I13, `shared_ops.rs:729` repair = I4/I5, poll_descriptor
:479/:1275/:1436/:2448, NAT64 = I14; `icmp_embed` verified read-only;
`promote.rs:99-110` guarded update-only — cannot grow the table).

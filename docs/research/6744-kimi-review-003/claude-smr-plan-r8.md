# Claude SMR plan review - round 8

Target commit: `bebffd32c7a0c2956a7eabbf584a92c6604ec5b2`

## Reviewer availability

The Claude Code CLI process session `4248` failed before analysis with the
account monthly-spend-limit error. No Anthropic-model verdict exists for this
round. The findings below are from an independent SMR-method fallback and are
not represented as a Claude model review.

Fallback reviewer session: `019fc83c-f89b-7493-b8bc-c47473cf6dd8`

## Verbatim fallback verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. `BulkStart` reset is nontransactional and not incarnation-qualified. It
   destroys per-key and full-set high-water before a bulk is known valid, so a
   delayed lower-generation frame can regress state even when the bulk aborts.
2. Config queue entries have no connection incarnation. Pre-disconnect queued
   work or an in-flight old callback can establish a post-reconnect baseline
   and reject the rebooted peer's lower current generation.
3. Type-29 state has an ABA race and no qualifying-bulk identity. A delayed
   completion can mutate a retry, and a bulk that began before the request can
   falsely discharge debt.
4. A new sender-only barrier does not make an old sender's mixed-version bulk
   authoritative. Capability negotiation or an explicit upgrade restriction is
   required, together with exact overflow/abort transitions.
5. `ReconcileClusterBulk` errors are logged but the current receive path still
   ACKs and releases readiness. Reconcile failure must make the bulk fail.
6. The proposed SNMP observation identity/path can expose a community secret,
   and the no-secret-hash statement contradicts the credential-aware private
   reconcile hash needed for rotations.
7. DDNS claim-only co-owner release mutates memory before the end-of-pass save.
   The plan needs classified pre/post-rename save ordering, rollback/convergence,
   and crash/reload tests before the lock-free claim snapshot drops the row.

All session-sync tests must enter through encoded production receive paths and
the real config queue; direct helper tests cannot prove the races closed.

## Accepted portions

The fallback accepted the AST-equivalent SNMP compatibility decision,
structured `clients restrict` deny-wins reduction, constructor-selected DDNS
surfaces and canonical equivalence, RG definition/owner separation and honest
preflight, RG clear-before-publish intent, `ReadConfirm` nested-tree validation,
the #6548 boundary, and A/B/D/F/G/H/J/K/L/M.

## Optional polish

Add explicit state-transition tables and counters for invalid-bulk reasons,
repair-debt age, and mixed-version authoritative-bulk refusal.

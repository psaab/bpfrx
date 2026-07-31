# Claude SMR hostile plan-review — round 103 (v10.19.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-third
pass; I authored the v10.19.0 fold of Codex r102's 5B/2H/2M. Verdict:
**PLAN YES**.

## 0. Process note (the honest one)

Codex r102's headline finding — "the normative contract is still
absent" — traced to my own fold process: the v10.17.0/v10.18.0
contract edits had partially silent-missed (python `str.replace`
no-ops against drifted target text), so the contract lived in summary
paragraphs while the §5.8 outcome list never gained it. v10.19.0 was
folded with assertion-checked replacements (every replacement verified
against the live text), and the whole contract now exists exactly
once, as the §5.8 SSOT bullet.

## 1. Fold verification

**r102-1/2 (contract + composition normative).** The §5.8 contract
bullet now defines: the `MaterializeOutcome` enum (definition site
named); the producer signature (`materialize_shared_session_hit`
returns `(SessionLookup, MaterializeOutcome)`, computed at the
materialize site — before the promotion attempt at
`session_glue/mod.rs:1235-1253`); the field with BOTH constructor
initializations (`:1254-1261`, `:1330-1344`); the poller carriage
(`:509` hoist, dispatch-context survival past `:883`); the five
consumers with the teardown guards at all three sites named; and the
composition (`OverdueSkipped` + MissingNeighbor → live-backed
ExistingResolved buffer-only) INSIDE the normative outcome list.
Self-attack: the constructor sites and the promotion ordering were
re-verified against the code (promotion runs at
`session_glue/mod.rs:1235-1253`, before the first constructor at
`:1254-1261` — the producer-computed-at-materialize rule is what
makes the outcome available to it).

**r102-3 (typed producer/carrier for the displaced set).** The set is
now `displaced: BoundedIdentitySet` — fixed-capacity,
construction-time-preallocated (the `WorkerScratch` `with_capacity`
pattern, `worker/scratch.rs:19-32`; bounded 3 families × the
64-descriptor batch, `afxdp/mod.rs:278-281`) — with the two new OUT
parameters named (the placeholder substitution at
`shared_ops.rs:602-628`; the upsert at `install.rs:295-322`) and the
resolved-result carrier.

**r102-4 (EMPTY-set unsoundness).** The distinction is now explicit:
`ValidatorRefused` (the site-2c refuse-install CAN displace a
canonical predecessor — its set carries that family), `UpsertRefused`
(displaces nothing at install, but the same resolve's promote can
overwrite a non-peer predecessor — `SharedPromote` is non-peer,
`entry.rs:245-253`, `update_session` accepts and reindexes,
`session/mod.rs:1350-1370`/`:1373-1475` — so the promote step records
its displacement into the same set); only `OverdueSkipped` and a
no-predecessor refusal carry EMPTY.

**r102-5 (realizable timing).** The accumulator lives on
`WorkerScratch`; the current-binding drain runs at the poller after
each descriptor's resolution, before every early exit/insert/next
descriptor; the sibling fan-out runs at the `poll_binding` level over
`left + right` (`worker/lifecycle.rs:53-55`, `:209-225`) before the
next RX batch — and the reap routine is explicitly NOT the carrier
(it includes the current binding and does NAT/BPF teardown,
`worker/loop_body/mod.rs:1481-1521`).

**r102-6 (zero-alloc).** Covered by the `with_capacity` sizing rule.

**r102-7/8/9 (text).** The close→close chain carries the
warm/lapsed-seed qualification in §5.6, §9, and §7; the §3.1 "only
install point" is corrected; §10.6.2's "neither worsens" is replaced
by the honest engage-but-cannot-prevent statement with the
lengthened-exposure cost; the four unscoped claims (overview,
§7-emission, §9-emission, §2-linger) all carry the gate-effects scope
with the purge exemption stated.

## 2. Consistency sweep

The contract exists exactly once; every prior summary paragraph
superseded by name; grep-verified. The gate (§5.1–§5.4, §5.7) is
untouched for the eighteenth consecutive round.

## 3. Bottom line

PLAN YES for v10.19.0.

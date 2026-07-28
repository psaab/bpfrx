# Claude SMR hostile plan-review — round 83 (v10.0.1 @ terminal cut)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I authored the
v10 terminal cut; this pass attacks it, with special attention to what the
cut may have re-opened (the machinery it killed was closing real traces)
and to the two NEW simplifications v10 introduces (probation without the
family clock; pending-neighbor always-re-resolve). Verdict: **PLAN NO for
v10.0.1** — one LOW (the probation-clear's target store is unwired) plus
five precision nits. The gate mechanics (§5.1–§5.4, §5.7) survive attack
unchanged; the cut's re-scope dispositions (§10.6) verify against the
code.

## What I verified holds (attacked and survived)

- **The §5.4 rule-3 chain stays dead with master's emission gate
  UNCHANGED.** The v9.x `owner_rg_active` predicate's loss does not
  re-open the post-failover kill: refuse-demote (no mark) + rule 5 (no
  closing-packet origin flip) + probation suppression (no blind promote
  of a materialized zombie) cover the three steps of the traced chain
  (`promote.rs:86-90` → `update_session` retag → `expire.rs:342-350`
  emit). Verified the gate's actual code shape:
  `!metadata.is_reverse && !removed.origin.is_peer_synced() &&
  !removed.origin.is_transient_local_seed()` (`expire.rs:342-346`).
- **#6522 re-scope is honest.** `worker/loop_body/mod.rs:1491-1498`
  releases NAT state on EVERY expired entry; `nat/allocator.rs:1318`
  `release_flow` carries no replica refcount; the fan-out is
  `replicate_session_upsert` (`poll_descriptor/mod.rs:2612, :2918`).
  Part A creates no replicas and adds no reap path — the "neither fixes
  nor worsens" claim verifies.
- **Emission completeness survives the machinery cut.** Zero-producer:
  the reverse-synth accept marks the forward family at resolve (§5.6) —
  one producer; hit-path accept marks + propagates (#4109) — one
  producer; refused close — no mark, master's ordinary semantics.
  Duplicate-producer: the accepted-close→failover→reimport window loses
  the prompt delete (documented, telemetry-only; the downstream delete
  fan-out is idempotent).
- **Split-steering reverse closes remain toothless** (B's replica
  untrusted → refuse; B's entries are peer-synced/is_reverse-silent →
  no delta; master's outcome for A's authoritative entry is identical).
- **The anchor-poisoning channels stay closed:** commit-point-only
  learning, geometry-hoisted, selective no-learn, closing-never-update,
  `seg_len>0` slide gate, `has_ack` slide gate, pre-packet `wnd`,
  replacement-not-merge, no fabric-transport authority.

## Finding 1 (LOW — the probation-clear's target store and hook are unwired)

§5.5/§5.6 give the probation flag's lifecycle as "clears on the first
COMMITTED non-close packet, which also refreshes the entry to its
ordinary established timeout" — but never say WHERE the clear runs or on
WHICH store. The only commit-hook machinery in the plan is the anchor's
(§5.2), and the anchor hops reverse→forward to the canonical forward
entry. The probation flag does NOT live on the canonical forward entry —
it lives on the MATERIALIZED entry the packet matched, which may be a
reverse-key entry. An implementer wiring the clear through the §5.2
anchor hook will clear the wrong entry's state (or no entry's): a
reverse-direction committed packet would leave the materialized forward
zombie on probation forever — promotion/Open/replication suppressed for
a genuinely live flow, 20 s re-materialize churn indefinitely, and the
§9 two-branch test as written does not pin direction. One sentence fixes
it: the clear+refresh runs at the MATCHED entry's own commit arm (the
entry the packet hit), independent of the anchor's forward hop; the §9
probation test covers both directions.

## Finding 2 (nit — the probation timeout ignores shorter per-app values)

§5.6 installs the refused materialize at "the probationary opening-window
timeout" (20 s) flat. #3227 re-applies per-application idle timeouts on
refresh (`lookup.rs:157-163`), and a synced import carries the admitting
application's value — which can be SHORTER than 20 s. As written the
zombie can outlive the flow's own configured timeout (table-pressure
inversion, bounded at 20 s). State the bound as
`min(TCP_OPENING_TIMEOUT_NS, the imported entry's own expires_after_ns)`.

## Finding 3 (nit — TFO retransmit seed-variance is an unstated OPENING residual)

§5.4 rule 2's immutable interval seeds `[isn+1, isn+SEG.LEN]` from the
FIRST SYN. A TFO client that retransmits its SYN with a different data
length (or whose first SYN was truncated in transit) can produce a legit
SYN-ACK acking beyond `open_ack_hi` — the strong proof fails, the
establishment promote never fires, and the ack side stays untrusted for
the entry's life (closes refuse; the flow idles out at the OPENING/
ordinary timeout). This is the same bounded absorbing class as §2's
documented residuals, but rule 2's residual list names only
"sent-data-then-abort". Add the TFO-reseed case to the stated residuals
so the field report doesn't read as a bug.

## Finding 4 (nit — site 2b "atomically in the same resolve" overstates the mechanism)

§5.6's accept case marks "the FORWARD family atomically in the same
resolve", but `install_reverse_session_from_forward_match` holds a CLONE
(`shared_ops.rs:638-665` clone the match) — the forward family mark is a
SECOND `&mut` probe of the local forward entry, sequential with the
reverse install. There is no cross-worker observer (worker-owned
tables), so "atomic" is doing no work and misleads the implementer about
what to write; say "two sequential same-worker writes in the same
resolve: install the reverse companion, then mark the probed forward
entry" and pin that the SHARED-match case never reaches the mark
(no-anchor → refuse).

## Finding 5 (nit — "exactly one producer" needs its scope qualifier)

§11 Q3 and §5.6 state the reverse-synth accept gives "exactly one
producer on the owner's forward entry". Read against §5.5's promote
path, a same-node cross-worker promoted copy (SharedPromote after a
committed non-close) is ALSO a legitimate emitter — on master today as
well (dedup is the existing delete fan-out, `session_delta.rs:436,
:453` → `delete_synced.rs:16`). The claim is true only for the
mark-creation sites; say so, or a reviewer/implementer reads a global
single-emitter invariant the design does not have (and does not need).

## Finding 6 (nit — citation drift from the loop_body move)

§7's pre-existing-race (a) cites `worker/loop_body/mod.rs:682` — the
v9.x arc's citation was `loop_body/mod.rs:682` before the file moved
under `worker/`; line drift is likely. Re-verify the
publish-before-command line against the current tree (the
`state.rs:72` half verifies). §10.6.1's `worker/loop_body/mod.rs:1491-1498`
verifies as the unconditional release call site.

## Bottom line

The terminal cut is the right shape: seventy rounds of machinery findings
with zero gate findings is a real signal, and the cut's dispositions
verify against the code. Finding 1 is the round's substantive item — it
is the kind of unwired rule that produces a subtly wrong implementation
that compiles, ships, and only misbehaves on reverse-direction traffic
through a materialized entry. Fold it (one sentence + one test
direction) and the nits (each one sentence), and I expect to converge.

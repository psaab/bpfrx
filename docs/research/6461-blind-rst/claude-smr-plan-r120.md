# Claude SMR hostile plan-review — round 120 (v10.36.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — fortieth
pass; I authored the v10.36.0 fold of Codex r120's 11B/1H/1M/1L.
Verdict: **PLAN YES** (fold verification + hostile sweep below).

## 1. Fold verification (Codex r120)

**r120-1 (B — the dominant success arm).** Code-verified against
`flow_cache_hit.rs:427-555`: the in-place rewrite arm enqueues
`pending_tx_prepared` and clears `recycle_now` at `:444-497`, SKIPPING
the fallback request block (`:498-548`); a double-failure keeps
`recycle_now` set and recycles at `:549-552`. The fold puts the anchor
apply at the common postblock gated on `!recycle_now` — both arms
covered, a construction-failed packet never applies. The plan's text
now names both arms and the flag.

**r120-2 (B — two handles).** The family hop's second lookup exists on
master (`session/mod.rs:1183-1205` — read: reverse packet → derive
`fwd_key` → `entry_by_key_mut(&fwd_key)`). The carrier now holds
`family_handle` + (reverse-direction) `matched_handle`; §8/§6 carry
the one-probe-forward/two-probe-reverse accounting. Codex's own
confirming trace (the `:295-317` calls mutate only timing/counters) is
recorded in the ordering text.

**r120-3 (B — precedence).** The fold: every install/upsert/overwrite
at key K invalidates K's exact-query-key cache slot (existing helper
`flow_cache.rs:1105-1120` + the v10.22.0 sibling fan-out). The
direct-primary-outranks-alias order is code-verified
(`lookup.rs:62-68`); the UpsertSynced no-invalidation gap is
code-verified (`upsert_synced.rs:64-120`). The identity check retains
the non-precedence ABA guard.

**r120-4 (B — carried expected id, adjacency retracted).** Verified the
synthesis point: `synthesized_synced_reverse_entry`
(`shared_ops.rs:750-785`) builds the reverse FROM the forward
`SyncedSessionEntry` with `entry.session_id` in hand and discards it
(`session_id: 0`). Verified the adjacency-breakers:
prewarm (`shared_ops.rs:345-418`) and singleton replicas
(`session_glue/mod.rs:838-848`). The fold stamps `expected_fwd_id`
from the forward row at synthesis — uniform across all three paths,
in-memory + worker-command carriage only (the reverse never rides the
cross-node wire as a separate record — the import path synthesizes it
helper-side, `session_import.rs:205-223`).

**r120-5 (B — classification + reinit).** The (nat, is_reverse)
snapshot compare rides the snapshot `update_session` already takes
(`session/mod.rs:1398-1453`); inequality → remove+install (re-mint +
zeroed anchor + gated seed + cleared probation/companion binding), so
K's authority state cannot ride onto S2; equality → same-family
in-place refresh. The discriminator is defined, not "undefined
'proven same-family'".

**r120-6 (B — zero always mints).** The preserve clause is retracted;
the upsert's remove-then-select order (`install.rs:295-344`) and the
command's evidence-free shape (`upsert_synced.rs:64-79`) are as Codex
traced. Fail-closed on legacy peers only; same-version pairs always
carry the real id after the r119-5a completion.

**r120-7 (B — node-bit producer).** `set_identity(worker_id, node_id)`
with the physical `/etc/xpf/node-id` (not role state) threaded through
`worker/loop_body/setup.rs:131-135`; the only hi-word decoders are the
two test assertion blocks (`session/tests.rs:366-374`, `:394-448` —
grep-verified no production decoder).

**r120-8 (H — tunnel path).** Verified: `tunnel.rs:563-615` constructs
F/R with `session_id: 0` before any worker entry exists; publishes
first (`:691-730`); then queues `UpsertLocal` (`:732-745`) where each
worker's table mints independently. No single real id exists at
publish time → the class carries `expected_fwd_id = 0` →
UNBOUND-absorbing, stated as the fail-closed firewall-local posture.

**r120-9/10 (B — close→close retries + materialize merge).** The merge
now covers every synth against a marked family (RST→FIN and FIN→RST
both merge to closing+reset) AND the sibling's shared-hit
materialization (`session_glue/mod.rs:1092-1115` — verified it seeds
from the new packet's raw flags today) merges the replica's carried
close bits.

**r120-11/12 (B/M — the accounting chain).** Full chain now specified:
typed `Site2bOutcome`, `Option<ValidatedTarget>` (Some only on
accepted-close + CapacityRefused), the resolution fallback field
(`shared_ops.rs:563-578`), poller init+hoist (`:509`, `:883`),
`account_packet -> bool`, and the mutually exclusive chokepoint branch
(`:3478-3503`); the one-charge invariant scoped to
ForwardCandidate/FabricRedirect.

**r120-13 (L).** The overview cost line now carries the identity-probe
accounting and the stable-id field name; §8/§6 reconciled (one probe
forward / two reverse; the postblock cite).

## 2. Hostile sweep of v10.36.0

- The `expected_fwd_id` never crosses the cross-node wire: the reverse
  is synthesized helper-side from the forward delta content — verified
  at `session_import.rs:205-223` (the reverse is built locally, then
  queued). Part A's no-wire-change constraint holds.
- The postblock apply's "enqueued == committed" semantics match
  master's own admission boundary for forwards (the
  `pending_tx_prepared`/`scratch_forwards` push is the point of no
  return for the descriptor); telemetry parity is untouched because
  `account_packet` stays at `:295-317`.
- The precedence invalidation's cost is per-install (rare), riding the
  existing exact-key helper — no per-hit cost added.
- The tunnel UNBOUND-absorbing class is firewall-local flows only;
  their forward-direction validation is unaffected; documented as the
  §2 imported-class posture.

## 3. Bottom line

PLAN YES for v10.36.0 as the round-121 review basis. The gate
(§5.1–§5.4, §5.7) is untouched for the thirty-fifth consecutive round.

# Claude SMR hostile plan-review — round 96 (v10.12.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — sixteenth
pass; I authored the v10.12.0 fold of Codex r95's 5B/1M/1L. Verdict:
**PLAN YES**.

## 1. Fold verification

**r95-1 (B — purged cold-neighbor path was not master-verbatim).**
Verified at the base: the purge releases P1 (`promote.rs:181-207` —
`release_source_nat_allocation`); master's arm runs the seed
transaction for the retained hit with a cold next hop
(`poll_descriptor/mod.rs:4662`, `:4745-4761`, `:4780-4795`,
`:4811-4889`); the transient `MissingNeighborSeed` cannot emit Open
(`entry.rs:272-274`, `install.rs:225-260`). The v10.11.0
"ExistingResolved-with-retained-decision, buffer-only" classification
would have buffered the RELEASED P1 — the same use-after-release class
as round-91's freed-tuple race. The fold replaces the classification
with master's own split: warm next hop → retained-lookup forward, no
install; cold → `SeedInstalled` (master's seed transaction, correct
here because nothing live remains for a raw-flags seed to replace —
the r83-87 buffer-only rule stays scoped to LIVE backing). The
ForwardFlow install + Open land on the later clean miss on both
master and plan. Self-attack: (i) does routing the purged case to
`SeedInstalled` re-open the r83-87 live-replacement defect? No — the
defect required a live/marked entry for the seed to displace; the
purge removed it; the arm's `remove_entry` finds nothing live.
(ii) Does the seed's raw-flags closing seed matter for a purged
NON-close packet? The packet is non-close by definition (closes never
purge); the seed inherits non-closing flags. (iii) Master's own
released-P1 forward window (warm path) is master's own micro-race,
unchanged, now stated.

**r95-2 (B — retention bound not bounded by expiry).** Verified:
`SyncedSessionEntry` has no timing fields (`worker/mod.rs:375-401`);
local expiry of a peer-synced entry emits no Close and no shared
delete (`expire.rs:342-344`); shared removal needs the synchronized
delete or a purge (`session_import.rs:243-320`). The §7 residual now
states the exact bound — retention ends at the first non-close purge
or the peer's synchronized delete (the peer-side lifetime of the
corrupted row) — and states the trade against master explicitly
(master converts the spray into one forwarded close plus
#4400-drops-or-FreshPrimary-kill; the plan forwards retained closes
with conflicted P1 for the peer-side lifetime; both reachable only
after the #6600 race).

**r95-3 (B — close→ACK cache pin).** Verified the mechanism: the ACK
purges, retains the decision, and caches the sessionless descriptor
(`poll_descriptor/mod.rs:3900-3959`); cache consultation precedes
session resolution (`:298-327`); no idle TTL. The fold documents the
end-state equivalence: master's ACK-first case produces the same
cached-stale-P1 end-state; the plan's retention changes which packet
purges, not the end-state's nature. No cache-suppression rule is
added (that was the v10.10.0 divergence r94-3 killed) — the pin
family is pre-existing and now documented.

**r95-4 (B — overdue-K in-place adopt needs an index-safe
transaction).** Verified: `refresh_for_ha_transition` removes/adds the
forward-NAT and owner-RG index parts atomically
(`session/mod.rs:1627-1663`); removal asserts against aliases using
the NEW fields (`:1750-1805`); shared publication can replace
decision/metadata wholesale (`shared_ops.rs:897-916`); origin controls
promotability/emission (`entry.rs:242-269`). The fold specifies the
adopt as the atomic-reindex shape with the exhaustive field contract
(decision/metadata ← S2; origin/session-id/epoch/counters/hold ← K;
timing verbatim; no re-queue) and the §9 test asserts the index swap
and the field split.

**r95-5 (B — mutually exclusive live requirements).** The §5.8/§11/§3
stragglers were folded in v10.11.1 (AGY r94's four); the cache
contradiction resolves via master-parity + the r95-3 documentation.
Grep-verified no live alternatives remain.

**r95-6 (M — retained closes still run accounting).** Verified:
`account_packet` advances counters and ORs `observed_tcp_flags`
(`session/mod.rs:1177-1210`). The inertness claim is now scoped: no
lifetime/ownership/anchor/emission mutation; the #2501 accounting may
advance (telemetry-only; master's purge skips it by deleting the row
first — stated as the telemetry delta).

**r95-7 (L — one-decision claim).** Scoped to the retained dispatch;
master's outer/pending split on the ordinary seed path is noted
pre-existing.

## 2. Consistency sweep

§5.2 (iv), §5.8 clause, site-9 row, §5.6 site-3/site-2c, §7 residuals,
§9 tests, §11(e), and the header all carry the master-split +
scoped-claims text with matching names. The gate (§5.1–§5.4, §5.7) is
untouched for the eleventh consecutive round. The plan's full
departure list on the purge path is now: the close-aware purge gate
(retention), plus documentation of every pre-existing corner the
retention interacts with.

## 3. Bottom line

The last three rounds each found a real defect in my previous fold
(install-free's unowned allocation; master-verbatim's cold-path
misclassification; the retention's wrong bound). v10.12.0's shapes are
master's own dispatch plus one predicate, with every residual
quantified rather than asserted away. PLAN YES for v10.12.0.

# Claude SMR hostile plan-review — round 73 (v9.9.54.27 @ edaa09ad1)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.27 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.27-as-committed** — six precision pins (1 LOW, 5 nit; no new
design defect found). All seven r72 Codex folds and the AGY r72
traces are operative; the two visibility classes, the durable-local
fence, and the exact-list frame 41 verify against the code citations.

## Finding 1 (LOW — the successor-authority snapshot has no trust anchor: a fence B presents itself is worthless, and a fresh successor can neither keep nor legitimately clear a fence)

The B2 fold's lift rule (c) is "an authenticated complete fence
snapshot from a successor authority". Walk the trust chain: the
fence record lives in A's durable journal; a SAME-BOX restarted A
has it; a FRESH-BOX successor (replacement hardware — exactly the
ISSU/permanent-loss scenario the disruptive path serves) has an
empty one, and rule (c) as written says a fence absent from the
snapshot is released — so a fresh successor releases every fence by
default, including the retirement the operator drove because B was
misbehaving. The retired peer's own presentation can't anchor it (B
omitting the fence gets B exactly what it wants). The anchor that
actually exists: the retirement is an OPERATOR ACTION — it belongs
in the cluster config-sync state (the same channel that carries
`${node}`-qualified config), not only in A's journal. State: the
retirement record is cluster-config-carried state (config-sync
reconstructs it on a successor); rule (c)'s snapshot is the
successor's RECONSTRUCTED state (its own journal + config sync);
and a fresh-box successor whose config-sync has not completed holds
the revalidation gate — the retired peer's quiesced revalidation
requires the successor's confirmation before election-eligibility,
so an un-synced successor can neither keep B out by omission nor
clear B by default (the gate holds until the sync completes and the
operator re-confirms or clears).

## Finding 2 (nit — the receiver-ahead-of-epoch case needs the exact-set display rule)

The B1 fold parks over-set configs, but never says what happens to
RGs the receiver ALREADY has beyond the transmitted list (it is
config-ahead). By the exact-set construction they are OUTSIDE the
retirement — and that is the correct semantics, because the
operator's disruptive confirmation binds the EXACT RG set (it always
did: "bound to the exact RG set and generations"). State it: the
operator's confirmation displays and binds the exact transmitted
set; an operator who means "everything" confirms the authority's
full current set; a receiver-ahead excess RG CONTINUES (never
fenced by implication), and the fence display shows it as
continuing — no silent ALL-by-proxy.

## Finding 3 (nit — the cell/value publication ordering and the read-side guard)

The H3 fold's generation-stamped values + global cell never states
the ordering. State it: publication is values-THEN-cell (every
value update call completes before the cell update call begins —
program order on the publisher, with the map's per-element
atomicity giving cross-CPU coherence per element); the read rule is
cell-THEN-value, and even a torn read fails CLOSED (a value whose
generation exceeds the cell is hidden — the guard is the value's
own stamp, so no barrier-less interleave can expose a
not-yet-committed cohort).

## Finding 4 (nit — the co-holder count is derived from receipts, never an independent counter)

The H4 fold's co-holder count can phantom-pin a tuple if it is a
stored counter that a crash can desynchronize. State the
construction: the count is DERIVED — the number of live durable
receipts referencing the tuple (a holder IS a receipt); the port
frees when the live-receipt set referencing it is empty; no
independent counter exists to phantom (rehydration rebuilds the set
from the receipts, and a receipt is the only way to hold).

## Finding 5 (nit — the pending NOTICE's freshness at activation)

The H5 fold keeps a durable NOTICE pending while BIT 6 is inactive,
but never says what happens when BIT 6 activates incarnations
later. State the freshness rule: at activation the NOTICE's
`(target incarnation, retirement generation)` must be current — a
NOTICE whose target has since restarted (new incarnation) or been
re-retired under a newer generation is STALE and discarded (a newer
retirement supersedes; a restarted target was never retired); only
a NOTICE whose target incarnation and generation are still the
latest activates.

## Finding 6 (nit — the retirement queue is operator-visible)

The M6 fold's queue is invisible to the operator driving a staged
migration. State: the retirement queue and pending summaries are
operator-visible (`show cluster retirement-queue` plus an alarm
while any summary is pending past its heartbeat interval), and the
per-retirement CONFIRMATION the operator's script consumes IS the
summary's activation (never the API return).

## Bottom line

The v9.9.54.27 fold set closes the r72 set in the prescribed
direction, and the three reviewers' traces were again the same set
(Codex H4 = AGY T1 = SMR F1 on the two visibility classes; Codex B2
= AGY T2 on the fence's durability). Finding 1 is the pin with
teeth: the successor-snapshot rule as written hands fence-clearing
to whoever shows up fresh — and the scenario the fence exists for
(permanent peer loss) is exactly the scenario that produces fresh
successors.

# Claude SMR hostile plan-review — round 72 (v9.9.54.26 @ 7e4d5ec97)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.26 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.26-as-committed** — three precision pins (1 LOW, 2 nit; no
new design defect found). All four r71 Codex folds and the AGY r71
traces are operative; the construction-level invisibility, the
liveness-bound fence, and the class-conditional markers verify
against the code citations.

## Finding 1 (LOW — the staging construction never says how a second same-tuple admission behaves, and the obvious reading double-allocates the NAT tuple)

The B1 fold stages every domain's state in "a STAGING key namespace
no canonical lookup can match". Walk a second admission for the SAME
tuple arriving while the first is still staged: its dedup lookup
searches the canonical space, finds nothing (the first admission's
state is staged-invisible), and allocates its OWN translated tuple
for the same flow — the exact double-allocation the shared map
exists to prevent, now reachable in the mint→commit window on every
churn-heavy flow (retransmitted SYNs race exactly this way). The
construction already contains the answer but never says it: there
are TWO visibility classes, not one. The tuple-level INTENT record
(the NAT reservation) is ADMISSION-VISIBLE from mint — it lives in
the allocator's tuple registry (`allocator.rs:1664, :1682`'s
occupied-tuple checks), where a second same-tuple admission finds it
and chains onto the same cohort (or queues behind it); the
PACKET-VISIBLE state (session rows, aliases, fragment associations,
flow-cache state) is what stages hidden until the commit. State the
two classes explicitly: the intent/reservation is visible to
admission paths from mint (dedup works), and only packet-visible
state rides the staging namespace (packets never match). Without
the sentence, an implementer staging the reservation with everything
else recreates the double-allocation window the whole exercise was
meant to close.

## Finding 2 (nit — the fence's liveness-bound drop has a partition-semantics paragraph due, and the connected-but-incomplete operator escape is unnamed)

The B2 fold drops the fence on authority loss — but authority loss
and fabric loss are the same signal at the receiver (heartbeat
threshold 5×200ms = 1s). So: a fabric partition longer than 1s
drops the fence everywhere it was held, the retired peer (or the
minority side) re-enters election, and the backstop is VRRP's own
deterministic priority resolution — which is the same honest
accounting round-67 SMR F1 demanded for the partitioned-peer case,
and it should be stated here too (the fence's real protection is
the CONNECTED case — retiring a reachable-but-undesired peer — and
the RETURN case — quiesced revalidation; the partition case
degrades to VRRP by design, never to deadlock). And for the
connected-but-incomplete case (authority alive and asserting, the
NOTICE's sync channel down, the fence global-ineligible), the
escape is the same operator-confirmed clear as `CommitUncertain`'s
peer-absent clear (named, audited, alarming) — name it for the
fence explicitly.

## Finding 3 (nit — the two-summary queue's drain and durability rules)

The H3 fold queues further retirements at the authority past the
two-summary bound without the drain rule: a newer retirement of the
same target SUPERSEDES a queued older one (the generation's
uniqueness makes them orderable; the operator's latest intent
wins), a clearance drains the matching pending summary, and the
queue persists across authority restart with the same write-ahead
discipline as the NOTICE (an authority restart must not silently
drop a retirement the operator confirmed).

## Bottom line

The v9.9.54.26 fold set closes the r71 set in the prescribed
direction, and the round's overlap was again exact (Codex B1 =
AGY T1 = SMR F1 on the rollback-delete orphan; Codex B2 = AGY T2 on
the fence's causal completeness). Finding 1 is the pin with teeth:
the mint→commit window exists on every flow, and the fold currently
reads as if everything — including the tuple reservation — goes
into the packet-invisible staging namespace; the two-visibility-class
rule is one paragraph and is the difference between the construction
closing the window and relocating it.

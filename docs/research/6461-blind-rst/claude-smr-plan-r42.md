# Claude SMR hostile plan-review — round 42 (v9.9.29 @ f56228be9)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.29 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.29-as-committed** — six fine-grained implementation-contract pins
(all LOW; no design defect found this round). The v9.9.29 mechanisms
verify sound in direction against code; these are the remaining "say it or
a hostile implementer guesses wrong" items.

## Finding 1 (nit — the max-silence teardown vs quiet-but-valid)

State why the absolute silence teardown cannot kill a quiet-but-valid
connection: heartbeat REQUESTS are outbound and the peer's ACK is an
inbound frame that resets the silence clock, so an idle-but-alive
connection always answers when asked (the existing heartbeat-request
mechanism); silence = no inbound frames at all, including ACKs = dead or
partitioned. One sentence.

## Finding 2 (nit — connection_generation namespace)

The publication revalidation compares `connection_generation`; that
generation must be PER-PEER monotonic (a per-peer install counter bumped
at every `installConn`), never per-connection — two simultaneous
connections sharing a generation value would let a pre-cutoff handler's
mutation pass the fence on the sibling connection. State it.

## Finding 3 (nit — hold-cell swap vs canonical CAS ordering and undo)

State the ordering and the cell-aware undo: the hold-cell swap is
COUNT-PRESERVING across variants (direct 1 → group 1); the canonical
version/CAS runs after the allocator section releases (per the
no-nesting rule); a reap landing between them decrements the CELL (the
single counter — order-safe); a CAS failure swaps the cell back (a no-op
if the cell already released). With the cell, the `Converted(old_state)`
undo IS the swap-back — never a variant-specific decrement.

## Finding 4 (nit — shadow memory + RCU reads)

State: the invisible shadow costs at most one additional configured
table's memory during a repair (accepted — repairs are rare and the
budget is capacity-based, so the shadow is bounded by the same
capacity); the visibility switch is an RCU-style root/epoch swap, so
in-flight lookups holding the old root complete safely.

## Finding 5 (nit — sender-incarnation change supersedes obligations)

State: a sender crash/restart between bulk commit and JOURNAL-END leaves
the obligation undischarged BY DESIGN — and the sender's new incarnation
(new `origin_process_nonce`) supersedes every outstanding repair
obligation from the old incarnation (repair epochs are
`(sender_incarnation, bulk_epoch)`); the new incarnation's cold-prime
bulk IS the new repair, so no protocol-level recovery path is needed for
the half-flushed journal.

## Finding 6 (nit — cleanup retry queue lifecycle)

State: the cleanup retry queue drains from the coordinator side (the
same drain context as the deferred-release queue), deduped by family key
(a family re-quarantined while queued updates in place).

## Verified sound this round (my own re-trace)

- r41-B1 fold: absolute silence teardown + one s.mu domain closes the
  pre-ACK and mid-barrier-install schedules (with Finding 1's caveat).
- r41-B2 fold: publication-point revalidation is the right fence for
  decoded handlers (with Finding 2's namespace pin).
- r41-B3 fold: the hold cell ends the publication-gap race (with
  Finding 3's ordering pin).
- r41-B4/H5/H6 folds: shadow commit, journal marker, cleanup wakeup all
  coherent (with Findings 4-6).

## Verdict

**PLAN NO for v9.9.29** — fold Findings 1-6 as v9.9.30 (precision pins;
no design change). Part A remains converged and untouched.

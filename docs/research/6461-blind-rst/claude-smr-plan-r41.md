# Claude SMR hostile plan-review — round 41 (v9.9.27 @ 1088547db)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.27 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.27-as-committed** — four state-it-explicitly nits (no design defect
found this round; each is an implementability pin a hostile reader needs).
All seven r40 folds verify sound in direction against code.

## Finding 1 (nit — the barrier generation needs its accept-side companion and storage pinned)

The fold fences `installConn` with the barrier generation but does not say:
(a) the ACCEPT side checks the barrier BEFORE admission (so no new setup
even starts during the barrier — the generation recheck then only needs to
catch setups already in flight at the bump); and (b) the generation is a
per-peer atomic whose bump and whose comparison both happen under `s.mu`
(the same lock as the slot registry), so a setup racing the bump cannot
slip an install between the bump and the fence arming. State both.

## Finding 2 (nit — the blackholed-non-survivor straggler case needs the in-order argument stated)

The fold's receiver fence (repair-ID + generation) is sufficient, but the
reason is subtle and must be written: the receiver's own `close()` of a
reset stream discards its kernel receive buffer, so only
application-accepted stragglers exist; those were accepted in stream order
BEFORE the repair, and the armed-repair freeze routes them to the freeze
buffer — they flush AFTER the repair's `BulkEnd`, which is the correct
recency. A straggler cannot masquerade as a repair member (different
message type + the ID echo). One sentence.

## Finding 3 (nit — the conversion recheck's version is `install_epoch`)

The versioned identity/origin recheck needs a single per-entry version
covering origin and identity mutations: that is `install_epoch`
(worker-local mutation counter, rewritten on update AND promotion,
`session/mod.rs:761, :1384` — the same field the plan already excluded as
the ADMISSION generation). The conversion records `(install_epoch,
SessionIdentity)` at reserve and re-reads both at commit inside the
entry's table critical section. State it (otherwise an implementer
reaches for `admission_config_version`, which is wrong for this purpose).

## Finding 4 (nit — the chunked-commit partial visibility residual)

The shadow-chunked commit exposes an intermediate state: members
installed, generation-map not yet committed. State the residual and why it
is the safe direction: the dataplane never consults the gen map for
forwarding (it is the sync protocol's stale detector); a crash mid-commit
leaves some keys' gen records OLDER than their installed state, so a
subsequent stale-generation message for such a key is REFUSED (fail toward
retention) until the next resend carries the fresh generation — never a
wrong delete. The post-cut journal's replay is recency-correct by
construction (journal frames post-date the sender cutoff; they replay
after the repair's BulkEnd on the same stream, in queue order).

## Verified sound this round (my own re-trace)

- r40-B1 fold: the earliest-of-three teardown bounds plus the generation
  fence closes the pre-ACK and async-setup schedules.
- r40-B2 fold: primary path immune by construction; request-path reset +
  fence sufficient per Finding 2.
- r40-B3 fold: `Converted(old_state)` resolves the receipt-contract
  contradiction; the undo is the exact inverse.
- r40-H4/H5 folds: bounded journal + gated discharge + table-derived
  staging + shadow-chunked commit are coherent.

## Verdict

**PLAN NO for v9.9.27** — fold Findings 1-4 as v9.9.28 (precision pins;
no design change). Part A remains converged and untouched.

# Claude SMR hostile plan-review — round 66 (v9.9.54.20 @ 6d9c35405)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.20 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.20-as-committed** — eight precision pins (2 LOW, 6 nit; no new
design defect found). All eight r65 folds are operative; the corrected
class-commit premise (the CONFIRM IS the record on v1-proof), the
local-journal watermark, and the crash-durable receipt verify against
the code citations.

## Finding 1 (LOW — the recovery transaction's complete-A's-transfer leg can promote a state-less B)

The B3 fold's new-incarnation recovery transaction "atomically
restores B's lease OR completes A's transfer, exactly one". The
complete leg can run against a B that restarted EMPTY (receipt-absent,
maps recreated at `manager.go:372, :386`) — completing the transfer
promotes B with an incomplete table, re-creating exactly the
incomplete-takeover the entire plan exists to prevent, now laundered
through the recovery path. The complete leg must be gated on B's
completeness: the forced-repair → `JOURNAL_END` sequence runs FIRST
(B proves the five-class predicate), and only then does the transfer
complete; otherwise the recovery restores B's lease (A keeps
ownership). One sentence, but it is the difference between the
recovery closing the crash window and re-opening it.

## Finding 2 (LOW — the bounded-retry exhaustion path for a pathologically-skewed CONFIRM is unstated)

The B1 fold's close-and-retry is correct against the class split, but
the exhaustion case is not: a v1-capable peer whose CONFIRM
persistently arrives just past the zero-byte window (timer skew under
load) loops close+retry forever — and unlike a baseline peer it never
sends an ordinary frame to escape through. State the ladder: the
inner bounded backoff hands off to the outer 1s session-sync connect
loop (never fatal, operator-visible after N failures), and a COMPLETE
late CONFIRM is honored on the FRESH stream of a retry (only ignored
on the stream that already timed out) — so a skewed-but-healthy peer
always connects within a few retry cycles.

## Finding 3 (nit — the final fence's per-protocol dataplane behavior is unnamed)

The B2 fold's final admission fence "stops NEW dataplane
admissions/publishes" for the seal→barrier→demote window. A new SYN
hitting the fence must be DROPPED WITHOUT RST (an RST kills the flow
outright; a drop lets the client's retransmit land after the fence
lifts — on B, which is then primary); UDP/ICMP first packets dropped
in the window rely on application retry. Both behaviors are right for
a millisecond fence and both need stating — an implementer who
refuses-with-RST or installs-not-journaled recreates the r65-B2 gap.

## Finding 4 (nit — the re-drive's idempotence rests on unconditional writes; say so)

The B3 fold re-drives a receipt-present/state-absent commit
"idempotently". That is true for the commit's stages only because
becoming secondary is a state SET and the lease clear is an
UNCONDITIONAL delete (`daemon_ha_sync.go:1045`,
`clearRemoteTransferOutLeaseLocked`) — set/delete-twice are no-ops.
State the rule: every commit stage is an unconditionally-written value
(set/delete), never a counter or a conditional mutation — the same
discipline v9.9.54.11 pinned for the executor's effect set.

## Finding 5 (nit — the queued reconciliation must diff the LATEST desired set, not the queued snapshot)

The H5 fold has config apply under the permit QUEUE the
reconciliation. Two queued passes coalesce; the drainer must re-read
the desired set at DRAIN time (the queue carries a generation marker,
never a desired-set snapshot), or a stale queued pass diffs against
superseded desired state and re-applies it.

## Finding 6 (nit — the retirement is not signaled to the returning peer)

The H6 fold's peerless PONR retires the missing peer incarnation and
fences it pending authoritative reseed; the quiesced-restart rule
(v9.9.54.18) already prevents the returner advertising mastership on
startup (sync-hold, `preempt=false`). But the revalidation's ANSWER
format never says how the returner LEARNS its old incarnation was
retired: the surviving node must name the retired incarnation in the
revalidation exchange (the returner then re-seeds rather than
re-asserts). One sentence.

## Finding 7 (nit — CAPABILITY_DECISION's unreceivability on v1 needs the defense-in-depth sentence)

The M7 fold makes the decision frame unsendable at min()=v1 by
construction. Defense in depth: a buggy or malicious peer that sends
`CAPABILITY_DECISION` on a v1 connection hits the allowlisted
decision-phase reader (round-58), whose class-scoped allowlist on a
v1 connection EXCLUDES decision frames — the frame is a protocol
violation and closes the connection. State the class-scoping.

## Finding 8 (nit — the 'no local-disk write on the failover critical path' invariant now has two named exceptions; reconcile the text)

The v9.9.54.18 PONR fold says the peer-as-durable-store avoids "a
local-disk write on the failover critical path". v9.9.54.20 adds TWO
local persists (the crash-durable applied receipt; the peerless
operator intent) — both correctly justified as OFF the failover
critical path (commit path / operator path). The invariant's text
should name its two exceptions so a future reader does not cite it
against the receipts.

## Bottom line

The v9.9.54.20 fold set closes all eight r65 findings in the
prescribed direction, and the corrected class-commit premise (zero
bytes = record absence = close+retry, never a class commit) is the
right shape. Finding 1 is the pin with teeth: the recovery path's
complete leg, as written, can promote an empty B — the exact failure
class the plan exists to kill, reachable only after a double crash,
but real.

# Claude SMR hostile plan-review — round 67 (v9.9.54.21a @ f4832b493)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.21 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.21a-as-committed** — seven precision pins (1 LOW, 6 nit; no new
design defect found). All eight r66 folds are operative; the two-path
v0 commit, the RW-fence cutoff, the two-state receipt, and the
owner-echo class commit verify against the code citations. The
frame-ID headroom rationale was wrong in v9.9.54.21 (AUTH frames
occupy 27-28, `sync_auth.go:60-65`) and is corrected in v9.9.54.21a
before either external reviewer could cite it.

## Finding 1 (LOW — the external-fencing story for a partitioned-but-alive peer is thinner than the fold admits)

The B4 fold says "a STILL-LIVE partitioned owner requires EXTERNAL
fencing (the operator's disruptive confirmation names it — the
surviving node advertises the retirement so the partitioned owner
demotes itself on sight)". Walk the cases honestly: (a) B runs the
new build and its partition heals — it sees the retirement
advertisement and self-demotes: fine. (b) B runs an OLD build (a
rolling-upgrade window — the exact deployment the disruptive ISSU
path serves) — the retirement rides a NEW additive heartbeat field
the old build ignores; B runs election believing itself legitimate
while A treats B as liveness-only: dual master on the wire until
heal, bounded by VRRP's own deterministic priority resolution, not
by the fence. (c) B is permanently partitioned but alive — nothing
in the protocol demotes it. The fold's "external fencing" is (a) +
hope for (b)/(c). State it plainly: the peerless PONR's operator
confirmation ASSERTS the peer is dead (not merely unreachable), a
partitioned-but-alive peer is an operator error the mode cannot
fence (VRRP priority resolution bounds the window), and the
retirement advertisement is for the RETURNING peer's revalidation,
not for reaching a live partitioned one.

## Finding 2 (nit — the v0 class must gate only the repair machinery, not the additive tails)

The v0 definition says "NO repair protocol runs — completion is the
current `BulkEnd`/`BulkAck` and nothing else". A recorded-v0 peer
(all repair bits zero) can still negotiate identity-enforcement and
lease-input (bits 0/1) — the additive identity tails ride
INSTALL/Open/DELETE independently of the repair protocol. "And
nothing else" reads as killing them. State: the v0 class gates ONLY
the repair/reset/decision machinery; the additive identity/lease
tails negotiate and run independently on a v0 connection (their
CONFIRM discipline is the same v1-proof rule).

## Finding 3 (nit — the peer-side class install is provisional until the connection survives the ACK window)

The owner installs at ACK-receipt, the peer at ACK-send; an ACK lost
after the peer installed leaves the peer holding a class on a
connection the owner never confirmed. It is connection-scoped and
dies with the connection, but the peer can slot-install and dispatch
in the RTT window. State: the peer-side install is PROVISIONAL —
frames dispatched in the ACK window are valid only if the connection
survives (a close invalidates the class and every dispatch derived
from it), and no cross-connection state may derive from a
provisional install.

## Finding 4 (nit — the read permit's topology is unstated, and the wrong topology is a hot-path regression)

The B2 fold gives every admission a read permit. At 100k+ new
sessions/second across six workers, a GLOBAL rwlock read-side is a
contention point on the hottest path in the dataplane. State the
topology: the permit is PER-WORKER (each worker's read side is
uncontended), and the fence's write side is an ALL-WORKERS drain
bounded by the slowest in-flight admission's publish + journal
receipt (which the millisecond fence deadline caps).

## Finding 5 (nit — the fence deadline's expiry must be a fence FAILURE, not a silent proceed)

The H5 fold releases the fence "IMMEDIATELY on connection,
repair-generation, or barrier failure" but never says what the
millisecond deadline's own expiry does. If expiry releases the fence
and the cutoff proceeds unsealed, the r65-B2 gap re-opens under
load. One sentence: fence-deadline expiry is a fence FAILURE — the
transaction aborts (ownership retained, operator-visible), and the
cutoff NEVER proceeds unsealed.

## Finding 6 (nit — the Prepared replay's lease re-arm and its consistency with A are unstated)

The B3 fold replays a Prepared commit before any election, but B's
restoration lease clock (`daemon_ha_sync.go:999`) ran while B was
down. State: the replay re-arms the lease with a FRESH expiry (the
lease's purpose — auto-restore on an incomplete transfer — is live
until the Prepared resolves), and A's view is consistent because A's
`CommitUncertain` claim retains until the definitive answer the
replay's resolution provides (replayed-applied → `Applied` persists
→ A completes; replay-failed → A aborts pre-PONR).

## Finding 7 (nit — the post-release await must be generation-checked at completion)

The H6 fold has the caller await the config-generation result AFTER
releasing the permit. Between release and result, another promotion
can start. The await must re-check at COMPLETION: the result's
generation must equal the awaited generation AND the caller's
transition must still be current — a superseded await returns
stale/superseded, never 'applied'.

## Bottom line

The v9.9.54.21 fold set closes all eight r66 findings in the
prescribed direction; the declaration-removal (deterministic min() +
owner-echo validation) is a genuine simplification, not just a
patch. Finding 1 is the pin with operational weight: the
external-fencing claim for a live partitioned peer currently
over-promises — what the protocol actually provides is
self-demotion on heal, VRRP priority resolution in the window, and
an operator assertion that the peer is dead.

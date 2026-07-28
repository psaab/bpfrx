# Claude SMR hostile plan-review — round 78 (v9.9.54.32 @ e9f54f778)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.32 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.32-as-committed** — six precision pins (1 LOW, 5 nit; no new
design defect found). All seven r77 Codex folds are operative; the
root_id triple + staging reservation, the bit-7 frame split, the
consistent incarnation, and the PREPARED(G) receipt verify against
the code citations.

## Finding 1 (LOW — the rg_incarnation's mint authority is unstated, and the natural reading forks it across the pair)

The B3 fold makes the incarnation "minted at RG creation by the
config-authoring daemon" and "CARRIED IN THE SYNCED CONFIG". The
synced config is `${node}`-qualified — both nodes carry config —
so both nodes' daemons can mint an incarnation for the same logical
RG (each from its own config view), and the two values DIFFER: the
ledger's `(rg_id, rg_incarnation)` then means different things on
the two nodes, and every mechanism the incarnation was added to
protect (the fence's instance identity, the union merge, the
high-water ACK vector) silently forks. The fold must name ONE mint
authority: the incarnation is minted ONLY by the authoritative
config source (the node whose config is the forward-sync origin),
is carried UNMODIFIED by both sync directions (reverse-sync
preserves, never re-mints), and a config replace re-mints only at
the authority (a replace on the non-authoritative node cannot
change it — its RG definitions are overridden by the authoritative
config anyway). Without the sentence, the field exists but means
nothing shared.

## Finding 2 (nit — the PREPARING reservation needs a deadline and a worker-liveness reclaim)

The B1 fold's staging reservation (mutex or
`PREPARING(owner, candidate, unique-shadow)` CAS) is held across
multiple maps, the durable journal append, and possibly a Go
round-trip — unbounded under load. State: the reservation is
deadline-bounded (expiry aborts the staging — rollback, safe
pre-publication); the `PREPARING` record carries the owner's
worker identity; and a dead owner's reservation is reclaimed by
any worker observing the death via worker-liveness (the same
discipline as the executor's per-ticket workers), with the
reclaim cleaning the dead candidate's unique shadow space
candidate-conditionally (never the winner's).

## Finding 3 (nit — the v1 fallback's in-flight replacement at downgrade needs its completion rule)

The B2 fold's total fallback never says what happens to a
replacement that was mid-flight when the connection dropped and
re-negotiated at extension-v1 (F2 applied, T(F1) pending — frames
42/43 and the supersedes semantics are now illegal). State: the
receiver holds the UNION of F1 and F2 (safe), the union is
operator-visible in the fence display as a pending replacement,
the durable notice store re-drives the completion when the
extension re-negotiates v2, and the escape while it is pending is
the same operator-confirmed clear as `CommitUncertain`'s
peer-absent clear.

## Finding 4 (nit — the materialize path's drain-generation check lives inside its admission serialization)

The H4 fold's "reactive materialization declines during the proof"
never says where the check executes. State:
`materialize_shared_session_hit` (`session_glue/mod.rs:1092-1118`)
consults the excess-RG drain state BEFORE creating any state —
the check is inside the worker's own admission serialization (a
worker processes its queue serially, so the check is atomic with
the materialization within the worker), and the cross-worker case
is covered by the helper-side conditional commit's generation CAS
(a materialization that slipped the check invalidates the lift's
CAS and the drain restarts).

## Finding 5 (nit — the seqlock's writer-intent flag makes new readers take the slow path, never drop)

The H5 fold's seqlocked root table can starve its writer under
continuous hits. State the priority rule: during a flip the writer
sets a writer-intent flag and NEW readers take the slow path
(fail-closed is never a DROP for a stateful flow — the miss
handler re-looks-up after the flip; the window is the flip's
duration, sub-microsecond; the fast path resumes on the next
packet).

## Finding 6 (nit — the replay floor never crosses authorities)

The M7 fold's floors need one sentence: a floor record covers ONLY
its own authority's retirements — A1's replay after a restart
replays A1's floor and can never touch A2's namespace (a
successor's retirements are the successor's own records, protected
by the same per-authority high-water vector as the ledger).

## Bottom line

The v9.9.54.32 fold set closes the r77 set in the prescribed
direction; the staging reservation is the first fold in the arc
that makes mixed-cohort publication impossible by construction
rather than by ordering. Finding 1 is the pin with teeth: the
incarnation is the identity the whole ledger hangs on, and
"minted by the config-authoring daemon" leaves TWO daemons free
to mint — a field both nodes carry but neither shares.

# #7212 — revalidate established sessions against a changed STATIC input filter

Successor to #5858. The mechanism was decided in the issue; this plan records
how it lands in this tree, what turned out to be already-solved, and what is
deliberately left out.

## Goal

A purely STATIC (address / protocol / port) interface INPUT filter that is
attached or tightened after a session was created must revoke that session on
its next packet. A session the new filter still PERMITS must not be touched —
that is the whole reason the #5858 family purge was rejected (a purged permitted
SNAT flow reinstalls on a different translated port and breaks).

## Mechanism (from the issue, not re-litigated)

Lazy per-tuple revalidation, stamped by generation:

* stamp each session entry with the config generation its input-filter verdict
  was computed under;
* on an established-session HIT whose stamp is older than the live snapshot,
  re-derive the STATIC verdict ONCE, side-effect free, and re-stamp;
* revoke the session only when the new verdict is DENY.

For a static filter the verdict is a pure function of
`(ingress interface, family, 5-tuple)` — every input is constant for the life of
one direction of a session — so one evaluation per session per generation is
exact, not an approximation.

## What the tree already provides (verified at origin/master)

Four of the six things the issue lists are already load-bearing mechanisms here,
which is why this lands as one PR rather than a multi-PR feature:

1. **Per-direction ingress identity.** Forward and reverse are SEPARATE session
   entries. Stamping the entry gives per-direction revalidation for free, and
   the ingress interface each direction is evaluated against is the one the
   packet in hand actually arrived on (`meta.ingress_ifindex` resolved through
   `resolve_ingress_logical_ifindex`) — an OBSERVATION, never a prediction. No
   stored ingress ifindex is needed, and the reverse companion's deliberate
   `ingress_ifindex = 0` (#4983) stays untouched.
2. **Pair-aware teardown.** `delete_terminal_filtered_session` (#5622) already
   deletes forward + reverse, releases the source-NAT / NAT64 reservation
   exactly once via the forward entry, and emits the FORWARD close delta even
   when the reverse half is the one that hit the terminal action.
3. **Coherent `(validation, forwarding)`.** #6592 publishes both halves in ONE
   `RuntimeView`, so the "one-iteration flow-cache bypass" the issue attributes
   to two independent `ArcSwap`s is not reachable any more.
4. **Flow-cache generation stamping.** `FlowCacheStamp.config_generation` is
   already re-checked on every lookup, so a commit invalidates every flow-cache
   entry on every binding of every worker by construction — the revalidation
   cannot be bypassed by a cached descriptor for the generation that introduced
   the deny.

## What this PR adds

### Rust dataplane

* `SessionEntry.filter_revalidated_gen: u64` — node-local derived state on the
  ENTRY, not on `SessionMetadata`: it is per-node, never on the HA wire, and
  never part of session identity. Two construction sites.
* `SessionTable::{set_filter_revalidation_gen, filter_revalidation_stale,
  mark_filter_revalidated}` — the table carries the live generation the same way
  it carries `timeouts` / `opening_overrides`.
* A peer-SYNCED import stamps generation `0`, which is never a live generation,
  so a promoted session revalidates against THIS node's filter state on its
  first local packet. That is the failover fence (issue item 6), obtained from
  the import default rather than from new cross-node plumbing.
* `NonRoutingCountPolicy::Never` — the SIDE-EFFECT-FREE verdict. This is the
  same walk the counted evaluator runs, with counting suppressed on both its
  arms, so the two can never drift: `Never`'s action is `Always`'s action by
  construction. `then log` is DATA in `FilterResult` (the caller emits), and the
  three-color policer is not metered by this walk at all (`now_ns = None`,
  #5857), so suppressing the counter is all that is needed.
* `interface_input_filter_static_verdict` — the `&Filter`-core entry point.
* `evaluate_input_filter_on_session_hit` (poll_descriptor/filter.rs) folds the
  #1430/#2362 per-packet gate and the new #7212 static gate onto ONE
  `iface_filter_v{4,6}_fast` lookup. With no input filter on the ingress
  interface — the overwhelmingly common case — the cost is exactly the ONE
  FxHashMap lookup the pre-#7212 gate already paid.
* Two-phase on a stale stamp: the side-effect-free walk first. On ACCEPT
  (every permitted session, on every commit) nothing is counted, nothing is
  logged, and the session is simply re-stamped. Only on DENY does the ordinary
  counted evaluation run, so the revoking packet is counted, logged and
  rejected exactly as a session-MISS packet would be — and only then.
* Revocation invalidates the forward AND reverse flow-cache slots on every
  binding of this worker, in the SAME poll tick, via a new scratch vector
  drained in `worker/lifecycle.rs` (which holds the `left`/`current`/`right`
  split borrow of all bindings). Sibling WORKERS are covered by the existing
  `replicate_session_delete` -> `DeleteSynced` -> `#6457` eviction.

### Go control plane

* `pkg/daemon/daemon_filter_invalidate_5858.go` and its test are DELETED. The
  advisory says "ESTABLISHED sessions are NOT revoked"; once the revocation
  ships that sentence is FALSE, and a false operator-facing warning is worse
  than none. `reportSessionAuthorizationChanges` keeps its policy half.

## Deliberately NOT in scope

* Issue item 5, the authoritative HA resync (a real ring-occupancy overflow
  predicate + a `SessionSync.BulkSync` fallback). It was raised against the
  FAMILY PURGE, which revokes a whole address family in one sweep. Lazy
  per-tuple revalidation revokes one session per arriving packet, so the denied
  set reaches the Close ring at the rate denied flows send packets rather than
  as one burst of up to 131072. The overflow predicate is still worth having and
  stays #7212's open successor work; the PR states the limitation.
* Cross-WORKER flow-cache eviction is next-tick, not same-tick — the same
  promptness `clear security flow session` and HA `DeleteSynced` already have
  (#6457). Same-worker, same-tick coverage is added here.

## Test strategy

* The pinned acceptance case: a PERMITTED SNAT session on the same interface as
  a revoked one keeps its translated port across the revocation.
* Static `then discard` revokes: v4 + v6, forward + reverse direction, VLAN
  logical interface, term reorder, `except` match, attach and detach.
* `Never` counts nothing while `Always` counts, and both return the same action.
* A stale stamp on a session whose filter still permits leaves every counter at
  zero and the session installed.
* The revoked flow's forward + reverse flow-cache slots are gone on every
  binding in the same tick.
* Go: the advisory is gone and nothing calls it.

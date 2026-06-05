# #1769 reviewer task IDs + verdicts

## Round 1 (head aab6f895f)

- **Codex** (foreground companion): NEEDS-CHANGES.
  - Critical: epoch guard not race-safe — monitor mutates-then-bumps
    (neighbor.rs parse before fetch_add) and a DELNEIGH for an
    already-absent key did not bump at all, so a late confirmed GET could
    resurrect a stale MAC.
  - High: resolver could mutate shared state after stop/reconcile (aux
    thread detached, no join, no stop re-check before the post-GET
    mutation).
  - Medium: hot-path `String::clone()` of the iface name per fast-failed
    packet even when the queue is full.
  - Minor: queue_depth gauge transient-negative drift; sendto not
    SOCK_NONBLOCK (recv is bounded by SO_RCVTIMEO).
  - Validated: rate-limit no-storm, netlink seq/key strictness, counter
    plumbing.
- **Gemini** (gemini-3.1-pro-preview, background): NEEDS-CHANGES (KILL on
  hot-path alloc). Agreed epoch guard "conservative" but MISSED the
  monitor mutate-then-bump ordering Codex caught. Flagged the same
  queue_depth drift and the `String::clone()` hot-path alloc.
- **Claude SMR** (in-conversation): concurred with Codex's Critical;
  designed the bump-first + in-lock epoch re-check fix.

## Round-1 fixes

- Critical: monitor bumps generation `Release` BEFORE mutating
  (bump-first, unconditional per RTMGRP_NEIGH recv batch); resolver
  confirmed insert via `ShardedNeighborMap::insert_confirmed_if_unchanged`
  which re-reads the generation INSIDE the shard lock against the pre-GET
  snapshot. Closes the resurrect-stale-MAC race incl. the absent-key case.
- High: resolver re-checks `stop` after the GET, before any map mutation.
- Medium: per-binding `resolver_enqueue_throttle` (100 ms) gates the
  iface-name clone + try_send so a storm no longer allocates per packet;
  bounded like the negative cache.
- Minor: enqueue increments queue_depth BEFORE try_send and decrements on
  send failure (no transient-negative drift).

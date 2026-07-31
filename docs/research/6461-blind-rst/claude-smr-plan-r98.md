# Claude SMR hostile plan-review — round 98 (v10.14.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — eighteenth
pass; I authored the v10.14.0 fold of Codex r97's 3B/3H/1M/1L.
Verdict: **PLAN YES**.

## 1. Fold verification

**r97-1 (B — history-blind suppression).** Verified: the purge
predicate (`promote.rs:48-59`) has no prior-close history and
`SyncedSessionEntry` (`worker/mod.rs:375-401`) carries only
install-time fields, so the v10.13.0 unconditional suppression hit
ACK-first flows (master caches the retained decision there and never
installs — Codex's round-94-3 point) while helping close→ACK. The
fold adds the historical state as data: the close-aware gate marks the
retained shared row with a sticky **close-retained marker**, and the
purge-dispatch cache-insert suppression fires ONLY for marker-bearing
rows. ACK-first flows are now master-verbatim (no marker → master's
cache escape, no forced install — the r94-3 acceleration stays dead);
close→ACK converges to master's close-first end-state at one extra
packet (3 vs 2 — the documented price of retention). The marker is a
`SyncedSessionEntry` field — internal shared-map value, never on the
HA wire (§6's no-wire-change claim is untouched). Self-attack: the
re-import republication cycle (r97-4's livelock vector) self-limits
because republication can drop the marker, restoring master's cache
escape — stated in the rule.

**r97-2 (B — remove-locally destroyed probation pre-admission).**
Verified: materialize runs before the input filter
(`session_glue/mod.rs:1092-1119` vs `poll_descriptor/mod.rs:592-638`),
so the v10.13.0 removal could fire on a packet that never commits,
breaking the commit-point discipline the whole plan is built on, and
the next non-close would ordinary-upsert a full-timeout entry (not a
fresh probation clock). The fold reverts to skip-wholesale PLUS the
guard the earlier skip lacked: the commit-hook clear+refresh NEVER
applies to an overdue probation entry (so the stale S1 cannot be
resurrected for a full timeout — the r94-5 residual), and the S1/S2
split-brain window is bounded by the GC lag and stated. All three
prior shapes (skip-wholesale, in-place adopt, remove-locally) and
their fatal flaws are now in the audit trail; the surviving rule has
no pre-admission mutation and no re-queue.

**r97-3 (B — sessionless cache entry).** The removal that enabled the
trace is gone. The residual claim ("next packet re-materializes") is
corrected: the forwarded decision MAY be cached (master's rule), and
later packets then forward sessionless — a master-reachable state (no
idle eviction, `flow_cache.rs:962-1039`) reached sooner under the
probation bound; timing delta stated in §7.

**r97-4 (H — no parity / no livelock-free guarantee).** Folded into
the marker rule's text: the 3-vs-2 packet cost is stated; the
reverse-policy-denial and capacity-drop cases are master-shared; the
re-import cycle self-limits via marker loss.

**r97-5 (H — conflicted state reachable via #6522).** Verified:
sibling expiry releases the shared unrefcounted token
(`allocator.rs:742-745`, `:1318-1332`, `:1664-1674`,
`worker/loop_body/mod.rs:1490-1505`). §7 now names both pre-existing
paths (#6600 import race, #6522 sibling release).

**r97-6 (M — cold path hits the seed; resource delta understated).**
Verified: the cold seed publishes shared/BPF state
(`poll_descriptor/mod.rs:4811-4888`) and packet two hits it. The
texts now say so, with the 10×/150× transient-placeholder retention
delta stated.

**r97-7 (H — live contradictions).** "byte-identical" and "ONLY
departure" are gone; the departure list is explicit (gate + marker +
marker-conditioned suppression); the overdue-branch leftovers are
excised.

**r97-8 (L — D == now).** Stated as a deliberate one-instant
shortening (strict expiry hasn't fired at equality,
`expire.rs:166-168`).

## 2. Consistency sweep

§5.6 site-3 supplement (marker rule), §5.8 (marker signature), §7
(both conflicted-state paths, the sessionless timing delta, the cache
corner), §9 (overdue-K skip+guard test, cache-may-apply note), §11(e),
and the header all name the same mechanisms. The gate (§5.1–§5.4,
§5.7) is untouched for the thirteenth consecutive round.

## 3. Bottom line

The departure list is now three small items, each with its cost stated
(packet count, marker stickiness, timing deltas) rather than asserted
away. PLAN YES for v10.14.0.

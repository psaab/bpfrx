# AGY plan-review r1 (adversarial-review-mqfnzlwk-gu7f3v) — plan @ 96eee9025

**Verdict: PLAN-NEEDS-MAJOR**

NOTE: AGY ACCEPTED the all-or-nothing-gate diagnosis ("unarmed surplus
bindings holding down the gates") — which Codex REFUTED with source
(armed != bind success, helpers.rs:487). Codex wins; AGY propagated the plan's
error here. AGY's other findings are correct and valuable:

1. Confirmed ring-mismatch refutation (queueCountFromBindings = maxQueueID+1 = 4).
2. EBUSY stale-socket race: Path A (bind 0..workers-1) is INSUFFICIENT alone — if
   EBUSY is a stale-socket race (async xsk_pool teardown) it recurs on queue 0
   on helper restart / same-plan rebind. The busy-bindings watchdog
   (maps_sync.go:1285) has a BLIND SPOT: if queue 0 fails to bind so
   registeredArmed==0, the watchdog won't trigger.
3. `ethtool -L` async-teardown race: running it right after helper stop can fail
   because the kernel asynchronously tears down ZC socket contexts — needs
   wait/retry.
4. Platform hazards: many VF drivers don't support `ethtool -L` (must be
   non-fatal); applying it on a fabric/generic parent (ge-0-0-0 xdpgeneric)
   resets the iface → packet loss + VRRP/control disruption on IPVLAN children,
   and may EBUSY.

Required by AGY: exclude fabric/generic parents from -L; ethtool failures
non-fatal (don't fail-close the dataplane); retry/delay after helper shutdown;
harden the auto-rebind watchdog for partial-bind wedges.

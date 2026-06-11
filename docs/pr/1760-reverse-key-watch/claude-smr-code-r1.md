# Claude SMR hostile code review — PR #1862, round 1 (tree @ post-fix)

**Verdict: MERGE-READY** (after the r1 fixes; one self-caught defect fixed
in this pass).

## Hostile checks performed

1. **Codex F1 (alias false positive)** — verified the Go dual-queue myself
   (`daemon_ha_userspace.go:742-750` queues canonical + wire-alias with the
   same value under `FabricRedirect && !FabricIngress`; `reverse_wire_key`
   maps both to the same K since `rewrite_src` substitution is the wire
   form's identity). AGY's contrary claim ("fabric placeholder carries the
   same forward key") is refuted by that source. The fix's asymmetric
   alias test relies on `forward_wire_key` idempotence — verified: every
   rewrite substitutes (never composes), so wire(wire(k)) == wire(k).
   Hostile probe of the fix for false NEGATIVES: genuine interface-SNAT,
   pool, DNAT-shared-backend, and NAT64 canonical pairs all still count
   (their canonical keys are internal forms, never each other's wire
   form); the accepted standby under-count (wire-FORM synced entries) is
   documented and owner-side counting covers the pair. Regression test
   added (canonical↔alias churn counts zero).
2. **Self-caught harness defect**: my F3 fix appended `; true` to the cold
   reachability preflight command string, making its FAIL branch
   unreachable. Fixed (bare `timeout 5 bash -c 'exec 3<>/dev/tcp/...'`).
   This is exactly the class of "validation that cannot fail" the
   harness exists to avoid.
3. **W1 pending-retry**: traced A-loses-CAS-to-B: A's prevs unchanged →
   retried next tick → wins a later window. First-60s suppression covered
   by the same pending mechanism. Multi-worker duplicate warns for one
   shared increment are bounded by the global 60s window (≤1/min
   process-wide) and carry distinct per-worker locals — acceptable.
4. **Lock hold time**: alias exclusion adds at most two stack
   `SessionKey` constructions + compares under the held mutex, install
   slow path only, and only on the displacement path (`existing.key !=
   entry.key` short-circuits first). No allocation (IpAddr is Copy;
   SessionKey construction is stack-only).
5. **Behavior neutrality**: re-diffed the full PR — no forwarding /
   install / HA decision change; counters, logs, tests, harness, docs
   only.
6. **Gates**: release build clean; full suite blocked only by the
   documented base flake (`worker_queue concurrent_recovery`, untouched
   module, 5/5 standalone); Go suite clean.

## Residual notes (non-blocking)
- The per-worker #1762 counter retains the alias false-positive shape on
  standbys (wire-alias `UpsertSynced` replicas displace canonical K in
  worker tables). Out of scope here (per-packet-path entry comparison);
  the updated help text now points operators at the shared counter, and
  the watch trigger remains valid (alias churn requires fabric-redirect
  sessions, which the lab smoke does not exercise at steady state).
  Recorded for the issue.

---

# SMR final addendum (tree @ c8de0cc267a6)

**Verdict: MERGE-READY.**

The displacement predicate went through three Codex-driven refinements
(r1 alias exclusion → r2 NAT-equality → r3 origin gate → r4 sync-derived
origin gate). I independently traced all four coverage shapes through the
final predicate before accepting:
alias churn (SyncImport) excluded; promote churn (SharedPromote, both
orders) excluded; DNAT-vs-direct genuine counted; local ext-IP owner
corner counted. The two accepted residual under-counts (sync-derived
wire-FORM entries on a standby; pathological ext-IP-sourced local flow vs
sync-derived wire-form entry) are documented in the helper docs and
covered by owner-side counting. Behavior neutrality re-verified after
each round (counter/log/test-only diffs). Gates at head: release build
clean, full Rust suite 1942/0, Go clean.

Copilot: 4 documented quota-blocked attempts → 3-of-4 fallback
(Codex task-mq94hky1-wpanh3 MERGE-READY, AGY
adversarial-review-mq94nusk-ha5g1h MERGE-READY, Claude SMR MERGE-READY).

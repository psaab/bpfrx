# Claude SMR — HOSTILE plan review r1 (#4960 + #4959 apply transaction)

Plan under review: `docs/research/4960-apply-txn/plan.md` @ `ad4ae4dacac6`.
Posture: adversarial. I read the source, not just the plan's self-summary.

## Verdict

**VERDICT: PLAN-NEEDS-MAJOR**

The architecture (one shared invariant, two coordinated mechanisms) is sound and
the #4959 root-cause framing (samePlanRefresh is the DESIRED path; the bug is its
fail-open, not the path selection) is correct and well-argued. But r1 has a
**wrong load-bearing claim in its own Open Questions (OQ-2)**, **three
under-specified call sites**, and an **unresolved scope decision presented as a
question rather than a recommendation**. These must be fixed in v2 before this is
PLAN-READY. First-pass "the plan looks right" is exactly the yellow flag the SMR
discipline warns about — and grounding OQ-2 in code flips its premise.

## Findings (must-fix for v2)

### F1 — OQ-2 premise is FALSE: the `!samePlanRefresh` path is fail-CLOSED, not fail-open. [CORRECTNESS of the plan's own analysis]

The plan hypothesizes (OQ-2) that the full-restart path "may be a second instance
of the #4959 bug" when the helper process is reused. **It is not**, and the plan
must correct this or it mis-scopes the fix.

Traced against source:
- `manager_compile.go:304-308`: on `!samePlanRefresh`, `programBootstrapMapsLocked(snap, ucfg)`
  runs FIRST (line 305), THEN `ensureProcessLocked` (309), THEN `apply_snapshot` (332).
- `programBootstrapMapsLocked` (`maps_sync.go:163-176`) sets `ctrl` with
  `Enabled: 0` and writes it, then `clearAllBindingRowsLocked()` (line 179)
  zeroes every binding row. So **ctrl is disabled and all bindings are cleared
  BEFORE the publish**. On an `apply_snapshot` reject, ctrl stays 0 → the shim
  drops transit and passes only proven local/control → **fail-closed**.
- Contrast the `samePlanRefresh` leg (line 300-303): it calls
  `syncUserspaceClassifierMapsFailClosedLocked` directly and NEVER touches ctrl
  or bindings (unless a map op itself errors). ctrl stays **enabled** → the
  #4959 fail-open. **This is precisely why the two legs differ**, and it
  strengthens the plan's "don't expand the plan key" argument — but the plan
  never states it.

**However**, F1 uncovers a real, distinct wrinkle the plan must acknowledge
(see F2), so OQ-2 should be rewritten from "is the restart path fail-open?" (no)
to "is the restart path's fail-CLOSED behavior acceptably non-disruptive?" (see F2).

### F2 — Reused-process bootstrap teardown: an iface-binding-only change blackholes a HEALTHY helper. [SCOPE / severity]

`configEqual` (`process.go:269-277`) compares only Binary/ControlSocket/EventSocket/
StateFile/Workers/RingEntries/PollMode — **NOT interface bindings.** So a plan-key
change driven purely by an interface-binding delta (a new interface added to a
zone, same worker/ring count) yields `!samePlanRefresh` **with `configEqual==true`**
→ `ensureProcessLocked` reuses the running process (pings, returns at line 26).

But `programBootstrapMapsLocked` already ran (line 305, before `ensureProcessLocked`)
and clobbered the LIVE healthy helper: ctrl→0, all bindings cleared. So:
- On success: transit is blackholed for the bootstrap window, then re-enabled by
  `applyHelperStatusLocked` — a momentary outage on a config change that never
  needed a restart.
- On reject: the healthy helper is left fenced (ctrl=0, bindings cleared) with the
  new maps and old snapshot — fail-closed but a **full transit outage** on what
  was a forwarding-fine dataplane.

This is fail-CLOSED (safe) but availability-destructive, and it is arguably a
SEPARATE latent issue from #4959/#4960. The plan must: (a) state whether the
reused-process bootstrap teardown is in-scope for this transaction (I lean
OUT-of-scope — it is fail-closed, so it does not create the security mismatch
this issue targets — but it MUST be named and deferred with a reason, not left
implicit); (b) fix OQ-2's framing per F1.

### F3 — Three call sites of `syncUserspaceClassifierMapsFailClosedLocked`, the plan transactionalizes one. [COMPLETENESS]

`syncUserspaceClassifierMapsFailClosedLocked` is called from THREE places:
1. `manager_compile.go:301` — the `samePlanRefresh` leg (the plan's focus).
2. `manager_compile.go:264` — the **`pendingXSKStartup` deferred-publish leg**.
   This syncs the classifier maps, then RETURNS at line 298 **without calling
   `apply_snapshot`** (publish is deferred to a later `syncSnapshotLocked` in
   `process.go`). So the maps are advanced to the new plan while the helper has
   NOT yet received the snapshot — and the deferred publish can later be rejected.
   Is this a fourth fail-open window? The plan does not mention it.
3. `programBootstrapMapsLocked:194` — the `!samePlanRefresh` leg (fail-closed per F1).

The plan's tx wrapper (§4.2) covers only site 1. v2 must state, for EACH of the
three sites, whether it is already fail-closed (site 3), needs the tx (site 1),
or needs a deferred-publish-reject guard (site 2 — the resume path in
`process.go` `syncSnapshotLocked` must restore/fence if the deferred publish is
rejected). Site 2 is the sharpest gap: an address-only commit that lands during
the XSK-startup deferral window takes this leg.

### F4 — The map "rollback" is a re-reconcile, not a byte-exact restore — say so. [CORRECTNESS / OQ-6]

§4.2 B1 proposes restoring maps by re-running `syncUserspaceClassifierMapsLocked(oldSnap)`.
But `buildDesiredLocalAddressSets` (`maps_sync.go:1080-1122`) folds **current
kernel addresses (VRRP VIPs) enumerated live via `AddrList`** into the desired
set. So the "restore" produces `oldSnap.config-derived keys ∪ current-kernel-VIPs`,
NOT the exact map contents that existed before the failed apply. In the normal
case this is fine (VIPs are authoritative live state and adds only widen), but:
- It must inherit the #3924 `enumComplete` skip-prune guard, or a rollback during
  a partial `AddrList` dump prunes live VIP/local keys → the exact blackhole #3924
  fixed. The plan mentions #3924 in §6 but does not wire it into the rollback path
  explicitly.
- The plan should rename "rollback"/"restore" to "re-reconcile to previous-good
  config + current kernel state" so no reader expects snapshot-exact bytes, and
  OQ-6 should be answered (it is safe BECAUSE local adds only widen and the prune
  is enumComplete-guarded), not left open.

### F5 — Recommendation hedges the one decision the operator needs made. [PLAN DISCIPLINE]

§8 recommends "Path C floor + Path A facet-B B1 map rollback, defer full host
rollback journal" but then routes the actual decision back to reviewers (OQ-1,
OQ-7). For a `/research` deliverable whose entire purpose is to let the operator
pick a path at `/engineer` time, the plan must commit to a concrete acceptance
criterion for "is validate-first + fence sufficient for #4960's host facet, or is
the journal required?" My read: **validate-first + fence IS sufficient** for the
host facet, because (a) the pure-planning pass moves the realistic failures
(missing screen profile, unresolved refs, parse errors) BEFORE any netlink write,
and (b) post-reorder the actuate step's residual failure surface is transient
netlink EBUSY, which fence covers fail-closed. The journal is a nice-to-have, not
a correctness requirement. v2 should SAY this and demote OQ-1/OQ-7 to "we
recommend X; PLAN-KILL if you disagree" rather than genuinely-open questions.

### F6 — `attachUserspaceShimXDP` failure under host-first ordering is unhandled. [COMPLETENESS]

§4.4 recommends host-actuate-then-publish. Between them sits
`attachUserspaceShimXDP` (`loader.go:197`, called inside `CompileUserspaceShim`).
If host actuation succeeds but the XDP (re)attach fails (native→generic fallback
is handled, but a hard generic-attach error returns at `loader.go:249`), the host
is mutated, the shim may be detached (the pins were removed at
`manager_compile.go:168-176`), and no publish runs. The plan's host-first ordering
must state the fence/rollback behavior for an attach failure specifically — it is
a distinct failure point from "a later compile phase" and from "helper publish
reject."

## Smaller notes (should-fix)

- N1: §4.3 step 2 claims Phases 3-11 are "pure with respect to host netlink." Verify
  this is literally true — grep for netlink/os.WriteFile in `compileAddressBook`,
  `compileNAT`, `compileFirewallFilters`, etc. If any late phase touches host
  state, the reorder premise weakens. (I spot-checked compiler.go and the mutators
  are concentrated in compileZones/compiler_iface.go, but the plan should assert
  this with a grep result, not an assumption.)
- N2: The plan's test plan should include a test that the `pendingXSKStartup`
  deferred-publish leg (F3 site 2) fails closed on a rejected resume publish.
- N3: OQ-4 (peer-sync suppression) is a genuine #2138-vs-#4034 tension. The plan
  should pick a DEFAULT for `/engineer` (I recommend: a FENCED apply — ctrl
  disabled — joins `applyErrSkipsPeerSync` like the required-protocol-gate class,
  because pushing a config that fenced the local dataplane to the standby is the
  #2138 "don't propagate a disarm" case; a cleanly ROLLED-BACK apply (B1 success)
  is NOT fenced and should still sync, since the local dataplane is coherent on the
  old config which the peer already has). State this split explicitly.

## What's right (keep)

- The #4959 framing (don't expand the plan key; transactionalize the in-place
  path) is correct — F1 strengthens it.
- Composing with #5680 / #2138 / #3924 / #3789 / #4952 is the right set of
  precedents and they are cited accurately.
- Three path options with an honest complexity/transactionality tradeoff is the
  right structure for a research doc.
- The invariant statement in §4.1 is the durable contract and survives regardless
  of which path ships.

VERDICT: PLAN-NEEDS-MAJOR — the architecture and #4959 framing are sound, but the
plan's own OQ-2 premise is falsified by the code (the restart path is fail-closed,
not fail-open), two more `syncUserspaceClassifierMapsFailClosedLocked` call sites
(the deferred-publish leg especially) are un-transactionalized, and the map
"rollback" semantics + the central path decision must be stated, not deferred.

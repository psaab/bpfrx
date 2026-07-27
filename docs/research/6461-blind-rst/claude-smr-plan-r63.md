# Claude SMR hostile plan-review — round 63 (v9.9.54.17a @ 04b4ab4c0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.17 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.17a-as-committed** — seven precision pins (3 LOW, 4 nit; no new
design defect found). The seven r62 folds are all operative, the
superseded-text sweep verifies clean (every grep class survives only
inside explicit retraction notes), and the intra-fold run-loop/permit
phrasing was repaired in v9.9.54.17a before either external reviewer
could cite it. The pins below are the folds' own under-specifications.

## Per-finding disposition notes on the r62 set

All seven r62 findings have operative folds in the prescribed direction:
B1 (unconditional advertise + post-exchange min + decode rule + table
repair + straggler sweep), B2 (stage ledger + PONR + dual-secondary
abort + consumption-clause retraction), B3 (completes-first retracted,
fence re-coverage, versioned wakeup delivered into the permit-held
validation), B4 (barrier-only retracted; bounded all-RG transaction),
H5 (PromotionPermit named with lock order), M6 (postconditions +
never-safe-report), L7 (§9 d13 + d11/d12 amendments). The pins:

## Finding 1 (LOW — the permit fold does not exempt becomeMaster from vrrp.Manager.mu, so the UpdateInstances/vi.stop cycle survives)

The r62-H5 trace: `UpdateInstances` holds `m.mu` across the removal
loop and calls `vi.stop()` inside it (`vrrp/manager.go:433-436, :449`),
which joins the instance run loop (`instance.go:1382`). The SMR r61 F2
serialization rule says the ownership commit revalidates the readiness
generation under `Manager.mu` — so a run loop mid-`becomeMaster` waits
for `Manager.mu` while `UpdateInstances` holds it waiting for that run
loop: AB-BA, independent of the permit. The v9.9.54.17 permit fold sits
ABOVE this cycle (`PromotionPermit` is outermost) and says "never hold
`Manager.mu` while joining a run loop that may need the permit" — but
the run loop doesn't take the permit (the fold says so); it takes
`Manager.mu` for the revalidation. The cycle's other edge is
`Manager.mu` itself, which the fold never removes from `becomeMaster`'s
commit path. State it: the generation revalidation under the permit
does NOT acquire `vrrp.Manager.mu` — the readiness generation lives in
the CLUSTER manager's domain (its own lock), and `becomeMaster`'s
VRRP-side reads (`ownerGen` at `instance.go:1305`) take instance locks
only. Without that sentence the named permit is decoration on a live
deadlock.

## Finding 2 (LOW — the operator force path's claim is undefined)

The B3 fold versions the queued promotion: `(claim, generation)`
delivered into `becomeMaster`'s permit-held validation, stale
discarded. `ForceRGMaster` (force=true) and priority-0 takeover are
today's ungated paths (the existing exemption class the plan preserves
— they bypass the sync-hold preempt gate). Under the fold, either (a)
an operator force carries NO claim and must be exempted from the
validation BY NAME — an exemption the fold never states, re-opening
the fence Codex closed if read generously, or (b) it must mint an
operator claim — an availability regression if read strictly (the
operator's force is discarded for want of a transaction). One sentence:
the operator-exemption class carries an operator-minted claim (named,
audited) OR is exempt by name with its own fencing. Pick one; today's
text picks neither.

## Finding 3 (LOW — the disruptive-mode fence has no lift path for a permanently lost peer)

The M6 fold fences subsequent transfers "until a current full repair
completes through `JOURNAL_END`". The repair protocol is peer-to-peer:
a full repair of the receiver's table requires the old owner alive. If
the disruptive transfer happened because the old owner is permanently
gone (hardware loss — the mode's raison d'être), no `JOURNAL_END` can
ever complete, the degraded latch never lifts, and every subsequent
transfer stays fenced forever — including the replacement node's
eventual safe takeover after re-sync. (A returning peer's bulk sync
does complete a `JOURNAL_END` and lift it — that path works.) Name
the permanent-loss lift: an operator reset (the `ManualFailover`-reset
analog) that clears the latch after the receiver's table is
authoritatively re-seeded from the surviving cluster state.

## Finding 4 (nit — v0 is named but never defined)

"ONE cumulative v0/v1/v2 state machine" and "(v1 if either lacks v2)"
— v0 appears only in the machine's name. A record-less peer (a
pre-repair-machinery build — the capability record rides the
post-v1-proof authenticated connection, which a v0 peer never
completes) has no `peer_max` to min() against. State: a missing
capability record min()s as v0, and v0 means no repair protocol at
all — the pure legacy buffered path, which the existing
zero-byte-timeout legacy latch already covers.

## Finding 5 (nit — crash reconstruction's PONR side is unstated)

A crash BETWEEN the VIP publish (wire-visible) and the stage-ledger
record restarts with no kernel VIPs and no ledger — reconstruction
reads "pre-PONR" for a transition that already emitted advertisements.
The compensation that follows is cluster-local (override removal,
election reversion) and lands dual-secondary — conservative, and the
stale network belief expires with the advert interval (~97ms
masterDownInterval) — so the mis-classification is SAFE, but the plan
never says reconstruction ALWAYS lands pre-PONR-conservative and why
that is safe. One sentence.

## Finding 6 (nit — the permit's hold-duration bound is unstated)

The permit is held "from generation validation THROUGH the final
ownership publication", and publication includes the advert emission
(`instance.go:1330` socket write) and the direct-mode publish
(`daemon_ha_vip.go:166`, netlink address operations). While held, ALL
promotions across BOTH modes serialize. A blocking netlink call or a
stalled socket write starves every other pending promotion. State the
bound (publication steps are nonblocking/deadline-bounded) or the
permit's abandonment-on-deadline behavior.

## Finding 7 (nit — every `-vN` bit needs the version machine, and §9 keeps one vague "same lock domain")

Two housekeeping pins: (a) bit 3 is `reset-vN` — the same versioned
naming as `repair-vN`; the fold says the intersection governs
"non-versioned remaining bits" without naming which those are. State
the general rule: every `-vN` capability bit follows the version
machine (base bit = v1, future extension bits = higher versions,
min() governs); plain flags follow the intersection — so a future
reset-v2 doesn't re-open the r61/r62 class. (b) The §9 d12 line still
says the commit revalidates "under the same lock domain" (line 5702)
— the vague phrasing r61-H4 killed; amend to "under the
`PromotionPermit` (with the `Manager.mu` serialization of the
revalidation, round-61 SMR F2)".

## Bottom line

The v9.9.54.17 fold set is the first round in this arc where all three
reviewers' findings were identical and every fold landed with its
superseded text excised. The seven pins are under-specifications of the
new folds — none resurrects a killed mechanism, and Finding 1 is the
only one with a live code-level trace (the `Manager.mu`/run-loop cycle
the permit was supposed to kill and didn't).

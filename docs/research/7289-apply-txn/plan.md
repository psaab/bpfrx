# Plan: converge-forward apply for the Phase-2 host mutation (#7289)

**Status:** DRAFT v1 — awaiting r1 hostile review (Claude SMR + Codex + AGY).
This is a `/research` deliverable. It STOPS at PLAN-READY / PLAN-KILL /
PLAN-DEFER. No production code.

**Verified against:** `origin/master` `f32aacbac`. Every premise is measured;
the measurements and the four claims that did NOT survive contact with master
are in `premise-check.md` beside this file, and the 23-site mutation inventory
they rest on is in §4.1.

**Relationship to the stranded plan.** `origin/research/4960-apply-txn`
(`ad300b881`, two rounds PLAN-NEEDS-MAJOR) is reused as a source of ARGUMENTS,
not of facts: its §4.4 carries a "(verified r1 N1)" annotation on a claim that
was false at its own merge base (premise-check §B). Where this plan leans on it,
it re-derives.

---

## 1. Issue framing

`CompileConfig` Phase 2 (`compileZones`) mutates live host state. Steps after it
can fail. There is no undo. The apply returns an error, the snapshot is never
published, and the box is left with:

- **host** on the NEW topology,
- **dataplane** armed and forwarding on the **OLD** policy,
- **transit barrier** open, because nothing unarmed,
- **configstore** with the new config promoted and persisted, commit reported
  failed.

The hazard is not an outage. It is **enforcement of old policy over new
topology while the operator has been told the commit failed**. A tightening
commit is the sharp case — the same case #5679 names for its own half.

## 2. Honest scope / value framing

Reachability is real but narrow: the one reachable trigger is
`attachUserspaceShimXDP` failing on a driver that refuses the attach
(`compiler_iface.go:191` says so, and `runPostMutationSteps` exists because of
it). `preflightCheckIfindexCaps` is a second, rarer one. Everything else in
`CompileConfig` after Phase 2 is effectively unreachable on the live shim path
because `userspaceShimCompileDataplane`'s methods are no-ops (`loader.go:500+`).

So this is a **low-frequency, high-consequence** defect. That shapes the
recommendation: the fix must not cost hitlessness or add a failure mode to the
99.99% path that never aborts.

## 3. What is already shipped, and must be composed with rather than replaced

Four mechanisms already exist. The stranded plan composes with none of them,
which is the likeliest reason it took two PLAN-NEEDS-MAJOR rounds.

| shipped | what it gives | cite |
|---|---|---|
| #6894 `validateBeforeMutate` | fallible host-pure phases validated BEFORE the first mutation | `compiler.go:371` |
| #5679 / #5646 | ordinary apply failure defers the commit error and does NOT disarm; an identical re-apply "self-heals" | `daemon_apply_dataplane.go:176-191` |
| #5275 / #7191 | fail-closed transit barrier gated on `dataplaneArmed`, management preserved, #1960 analysis DONE | `daemon_transit_gate.go:25-55` |
| #7288 | the abort error names what already moved | `compiler_hostmutation_4960.go:99` |

**The codebase has therefore already chosen clause 2's option (c) as its
doctrine for this failure class.** #7289's residual is that Phase 2's host
mutation sits outside that guarantee.

## 4. The measurement that decides clause 2

### 4.1 The mutation inventory — 23 write sites, all in Phase 2

Full table in the r1 investigation record; the shape is what matters:

- **20 sites are already idempotent** by presence check or read-compare-write.
  `ensureVLANSubInterface` returns early on an existing child
  (`compiler_iface.go:203-207`); `planAddressReconcile` is a PURE planner whose
  converged input yields an EMPTY plan (`:392`, and `AddrAdd` absorbs an
  "exists" race at `:360`); every MTU/txqlen/ring/rxvlan write is
  read-compare-write.
- **2 correctness gaps** stop "converges regardless of where it aborted":
  - **M3** `accept_ra=0` (`compiler_iface.go:268`) is written **only on the
    create path**. A re-drive takes the adopt branch and returns at `:238`
    before reaching it. If the create succeeded and this failed, nothing ever
    retries it.
  - **`errVLANAdoptRefused`** (`:210`) is a **soft skip**, not a failure. An
    aborted apply can leave a device that later fails the adoption predicate,
    and the re-drive then reports SUCCESS while converging to a *different*
    end state.
- **3 classes are not re-drivable at all**, and they are exactly the ones with
  **no `markHostMutated` coverage today**:
  - **M21** `netlink.LinkDel` on a `*netlink.Bond` (`:1593`). xpf-owned bonds
    are recoverable (`ApplyBonds` runs at `daemon_apply.go:420`, BEFORE the
    strip at `:442`). A **foreign** bond is gone for good.
  - **M22** `AddrDel` on unmanaged NICs (`:1616`) — addresses on a NIC that is
    not in the config, which therefore no apply re-adds.
  - **one-way ratchets**: `rxvlan off`, ring buffers to max, RSS hash key
    overwritten with a literal, txqlen raised, rps/xps/flow-cnt, and
    `accept_ra`. None captured before writing; `applyEthtool` early-returns
    when the new config sets nothing, so dropping `speed 10g` does not restore
    autonegotiation.

### 4.2 The abort prefix is NONDETERMINISTIC

`programZoneMaps` ranges a Go **map** over zones (`compiler_iface.go:450-462`).
Which zone mutated before the abort is not fixed run-to-run. Any design must
assume an **arbitrary interior prefix** of the mutation set landed — not a
deterministic one. This alone kills a positional/journal-replay design.

### 4.3 There is no re-drive engine, and this is the load-bearing gap

`applyActiveConfigResult` re-enters `CompileConfig` and therefore Phase 2, so
the mechanism exists. Its triggers are a feed refetch (`daemon_feeds.go:57`),
bringup, and a DHCP lease. **All event-driven, none unconditional.** The 1s
`statusLoop` is level-triggered but explicitly scoped to manager↔helper state
and never touches the compiler (`process_status.go:186-193`).

And the failure record is **ephemeral**: `runPostMutationSteps` returns a
string; the abort path never reaches `recordApplyResult` or `lastCompile`
(`loader.go:329-334`). Nothing durable says "this apply aborted mid-mutation".

### 4.4 What this does NOT prescribe

The issue's clause 1 is "split pure planning from host+shim actuation". **This
plan does not prescribe that split**, and the reason is measured rather than
preferred: the snapshot must be built from POST-actuation live state
(`buildInterfaceSnapshots` reads live child ifindex/MTU/MAC/addrs and the
binding plan key includes the live ifindex) — the stranded plan's r1 6.1 found
this and it still holds. An ordering diagnosis is not a prescription to swap.

## 5. Path options

**(a) Undo log / restore.** Write an undo record before each netlink call, and
replay on abort. **Rejected.** The undo can itself fail, on a box whose
interfaces may have been renamed underneath it; the abort prefix is
nondeterministic (§4.2); and it is the model the stranded plan already dropped
as unsound — "a journal cannot make netlink writes invisible". It is also the
largest of the three.

**(b) Unarm and hold.** On a post-Phase-2 abort, `setDataplane(nil)` and let
the shipped #5275/#7191 barrier drop transit while management survives.
**Rejected as the primary answer, kept as a sub-option.** It is far cheaper
than the issue implies — the mechanism and its #1960 analysis are already
shipped — but it converts a policy-staleness window into a forwarding outage
for a failure whose most likely cause (a driver refusing an XDP attach) is
persistent, so the box would stay down until an operator intervenes. That is
the trade #1960 argues against for an already-committed config.

**(c) Converge forward.** Make Phase 2 idempotent under re-entry and re-drive
the SAME config until it converges. **Recommended, but not free** — §6.

**(d) Hybrid: converge forward + an ownership ledger for the three
non-re-drivable classes.** **This is the actual recommendation.** (c) alone
cannot handle M21/M22/the ratchets, because no re-application of any config
reconstructs state the config never described.

## 6. Recommendation — (d), and what it honestly costs

Four pieces, in dependency order. None requires a fence, a transaction, or a
reordering of the compiler.

**P1 — close the two idempotence gaps (§4.1).** Move M3 out of the create-only
branch so a re-drive reaches it; make `errVLANAdoptRefused` fail rather than
soft-skip *when the device was created by a prior aborted apply of this same
config*. Small, local, and independently valuable.

**P2 — make the abort durable.** Record "aborted after host mutation, at
config generation N" somewhere that survives the failed apply. Today nothing
does. This is the prerequisite for any retry, and it is also the thing that
makes the acceptance criterion testable at all.

**P3 — give the re-drive a trigger.** Not a timer. The in-repo pattern is
`pkg/daemon/released_nic_tunables.go`: an ownership set, a level-triggered
`owned - current` reconcile, and retry debt dropped only on success, with no
timer. Its own header states the invariant this generalises: *"Every host/NIC
mutation must be reverted when the interface leaves xpf ownership — not only
when the process exits."*

**P4 — an ownership ledger for M21/M22/the ratchets.** Only these three
classes, and only their pre-state. This IS an undo log — but for 3 write
classes rather than 23, for state the config cannot describe, and it is the
same ledger shape already shipped in `released_nic_tunables.go`.

**Sub-option (b) as the bounded fallback:** if P2 records an abort and P3's
re-drive fails to converge after a bounded number of attempts, THEN unarm and
engage the shipped barrier. That makes (b) the terminal state of a failed
convergence rather than the first response to a single attach failure.

## 7. Public API preservation

No gRPC/REST/CLI signature changes. `ApplyResult` gains the abort record (P2);
`ApplyResultFromCompileResult` (`apply.go:210-229`) currently drops
`hostMutations` entirely, which is why nothing durable exists today.

## 8. Hidden invariants the change must preserve

- The snapshot is built from POST-actuation live state (§4.4).
- Management must survive any fail-closed step (#1960).
- `compileErrorMustAbortApply` vs the ordinary class is an EXISTING split; P2/P3
  must key on it rather than inventing a parallel taxonomy.
- Hitless address-only commits (`samePlanRefresh`) must not regress.
- `markHostMutated`'s three coarse strings currently miss the most destructive
  writes; P4 must not inherit that blind spot.

## 9. Test plan — the controlling distinctions

- **Idempotence, per site, from an arbitrary prefix.** Drive Phase 2, abort at
  site *k*, re-drive, assert convergence — for *k* across the set, not for one
  *k*. §4.2 means a single-*k* test proves nothing about the others.
- **The M3 gap must RED before the fix.** A test that creates the child, fails
  before `accept_ra`, re-drives, and asserts `accept_ra == 0`.
- **The adopt-refusal gap must RED before the fix**: assert the re-drive FAILS
  rather than reporting success with an `UnarmedSurface` record.
- **A no-op re-drive changes nothing** — the control that stops P3 from
  becoming a mutation source of its own.
- **P4 ledger**: assert the pre-state is captured BEFORE the write, since a
  ledger written after is exactly the race it exists to close.
- Every one of these is a claim a test can red. The premise-check records three
  in-tree comments this week whose claims no test held; this plan should not
  add a fourth.

## 10. Out of scope (explicitly)

- The clause-1 planning/actuation split (§4.4 — measured as constrained, not
  deferred by preference).
- The fence-first model of the stranded plan.
- #7078, #7079 (landed), the classifier-map generation coordination of clause 3
  — clause 3 is a separate cut and this plan does not close it.

## 11. Open questions for adversarial review

**OQ-1.** Is (d)'s P4 ledger just (a) wearing a smaller hat? It is an undo log
for 3 write classes. If a reviewer thinks the boundary is unstable — that P4
grows to cover all 23 — then (d) collapses into (a) and should be judged as (a).

**OQ-2.** Is P3's trigger sound without a timer? `released_nic_tunables.go` has
an event that reliably re-fires. Does the abort path have one? If not, P3 needs
a timer and the "no timer" discipline it copies does not transfer.

**OQ-3.** §4.2's nondeterministic prefix — does it also break the *test* plan?
Testing "abort at site k" requires injecting a failure at k, and 23 seams may
not all be injectable without production hooks.

**OQ-4.** Should clause 3 (publication generation ↔ classifier-map transaction)
be a blocker? This plan says no. If a reviewer says a partial apply must be
DETECTABLE by the next apply for P3 to be safe, clause 3 becomes a prerequisite
and the scope roughly doubles.

**OQ-5.** Is sub-option (b)-as-terminal-state right, or does any unarm on a
committed config violate #1960 regardless of how many retries preceded it?

**OQ-6.** Reachability: is one driver-refuses-attach failure worth P1-P4? A
reviewer arguing PLAN-KILL would say ship P1+P2 (small, local, testable) and
leave P3/P4, accepting that the operator re-commits. That is a coherent
position and this plan does not dismiss it.

## 12. Revision log

### v1 (this revision)
Initial draft. Premises measured at `f32aacbac`; four stale claims corrected in
`premise-check.md`; recommendation is (d), with (a) rejected on the
nondeterministic-prefix finding and (b) retained only as a bounded terminal
state.

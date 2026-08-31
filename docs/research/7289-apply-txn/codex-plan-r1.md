# Codex hostile plan review r1 — #7289

## Review basis

This review fails the proposed option (d). The 23 syntactic host-write call
expressions are real, but the claimed 20/2/3 semantic split is not. More
importantly, identical re-application is not convergent for configurations the
current tree accepts, P2 cannot observe or carry the proposed debt, P3 has
neither a trigger nor a stable generation/success contract, and P4 is an
undefined rollback/ownership journal whose boundary has already escaped the
claimed three classes.

I audited production source byte-identical to the requested `f32aacbac` base.
The checked-out branch advanced through documentation-only commits while this
review ran; `git diff --name-only f32aacbac..HEAD` contained only files under
`docs/research/7289-apply-txn/`. I read the required plan, premise check, stranded
4960 plan, and both Codex review rounds. `gh issue view 7289` was attempted twice
but the sandbox denied the GitHub connection (`socket: operation not permitted`),
so the issue body remains **unverified**. No finding below is inferred from that
unavailable issue text.

## Findings

1. **[CRITICAL] P3 has no fixed point: an identical config can alternate MTU forever.**

   **Confirmed from code.** For an untagged interface carrying interface MTU
   `X` and unit MTU `Y`, `mapZoneInterface` obtains one cached `netlink.Link`,
   compares its cached MTU, and writes `X` (`pkg/dataplane/compiler_iface.go:874-887`).
   It later obtains the same cached object by name and compares it before the
   unit override to `Y` (`pkg/dataplane/compiler_iface.go:992-1004`). The name
   and index caches deliberately cross-populate the same object
   (`pkg/dataplane/compiler.go:147-176`), and both MTU leaves are accepted
   configuration (`pkg/config/schema_interfaces.go:46-62,179-190`).

   The pinned dependency is `vishvananda/netlink v1.3.1` (`go.mod:14`). Its
   `LinkSetMTU` sends `RTM_SETLINK` but does not update `link.Attrs().MTU`
   (`/home/ps/go/pkg/mod/github.com/vishvananda/netlink@v1.3.1/link_linux.go:434-450`).
   Starting live at `Y`, the first apply writes `X` and then skips `Y` against
   the stale cached attribute, ending at `X`. A fresh retry starts at `X`, skips
   `X`, and writes `Y`. Subsequent identical retries alternate. This alone
   falsifies both “20 sites are already idempotent” (`plan.md:71-76`) and P3's
   convergence guarantee.

2. **[CRITICAL] The nondeterministic zone order can select different final host state, not merely different abort prefixes.**

   **Confirmed from code and the existing test.** Strict validation explicitly
   accepts two distinct units of one physical interface in different zones
   (`pkg/config/compiler_validate_strict_zones.go:187-193,250-253`), and the
   committed test does so without assigning either unit a VLAN ID
   (`pkg/config/zone_interface_membership_test.go:97-111`). I ran that exact test;
   it passed. Unless a unit has a positive VLAN ID or tunnel, both references
   resolve to the same physical netdev with `vlanID == 0`
   (`pkg/dataplane/compiler_iface.go:123-138`).

   `programZoneMaps` then ranges the zone map nondeterministically
   (`pkg/dataplane/compiler_iface.go:614-658`). Each unit asks the generic
   compiler dataplane to write the same `{physIfindex, 0}` zone key
   (`pkg/dataplane/compiler_iface.go:839-843`) and independently reconciles that
   one physical link to its own exact addresses and unit MTU
   (`pkg/dataplane/compiler_iface.go:964-1004`; address delete/add loop at
   `:344-369`). The userspace shim no-ops the zone-map call, but it does not
   no-op those host writes. The last random zone wins the host state. An
   identical apply can therefore flip addresses and MTU even when every syscall
   succeeds. Section 4.2 is load-bearing against P3 itself: the plan has not
   proved confluence and current accepted input supplies a counterexample.

3. **[CRITICAL] The 20/2/3 classification is not a real partition and omits actual non-reconstructible state.**

   **Confirmed from code.** There are exactly 23 syntactic Phase-2 host-write
   expressions:

   - `pkg/dataplane/compiler_iface.go:228,248,262,268,348,359,769,880,917,925,996,1593,1616,1621`
   - `pkg/dataplane/compiler.go:1607,1694,1763,1777,1795,1798,1804,1811,1829`

   That count does not support the asserted split:

   - `errVLANAdoptRefused` is control flow, not a write site. It is declared at
     `pkg/dataplane/compiler_iface.go:178`, tested at `:215-217`, and soft-skipped
     at `:711-733`.
   - `accept_ra` appears both as the M3 “gap” and inside the “three” ratchet
     class (`plan.md:77-97`), so the categories overlap.
   - Speed/duplex is not read-compare-write; a fresh `CompileResult` issues
     `ethtool -s` again (`pkg/dataplane/compiler.go:1677-1702`; the cache is
     newly allocated at `pkg/dataplane/compiler_validate_4960.go:488-505`).
     RFS/RPS/XPS and RSS are unconditional writes
     (`pkg/dataplane/compiler.go:1795-1811,1825-1833`). Literal state
     idempotence is not the plan's claimed presence/read-compare proof and does
     not imply operationally side-effect-free retries.
   - The unmanaged-NIC `LinkSetDown` immediately adjacent to M22
     (`pkg/dataplane/compiler_iface.go:1608-1623`) loses prior administrative
     state just as surely as `AddrDel` loses prior addresses. Networkd then
     persists `ActivationPolicy=always-down`
     (`pkg/networkd/networkd.go:797-811`). M23 meets the plan's own
     “current config cannot reconstruct it” test but is missing from P4.

   M3 itself is real: `accept_ra` is create-only at
   `pkg/dataplane/compiler_iface.go:266-270`, while the adoption branch returns
   at `:237`. But another real gap is omitted: a newly created child's
   `LinkSetUp` error returns `created=true` (`:253-264`) and is then turned into a
   successful soft skip (`:692-733`); an existing child's `LinkSetUp` error is
   only warned and returns success (`:219-237`). The inventory counts syntax,
   not recovery semantics.

4. **[CRITICAL] The “one reachable trigger” premise is false by inspection, and the actual failure set crosses multiple commit stages.**

   **Confirmed from code.** Phase 2 itself can hard-abort after an arbitrary
   earlier-zone prefix. A later VLAN `LinkAdd` refusal is deliberately fatal
   (`pkg/dataplane/compiler_iface.go:142-157,248-250,690-710`). A failure to
   disable RX-VLAN offload on a configured VLAN parent is also fatal
   (`pkg/dataplane/compiler.go:1553-1615,1640-1670`; caller at
   `pkg/dataplane/compiler_iface.go:858-871`) after the same interface's VLAN
   child/address work may already have run. The userspace shim only no-ops
   `DataPlane` methods (`pkg/dataplane/loader.go:496-570`); it does not neutralize
   these real netlink/ethtool paths.

   After Phase 2, two fallible bpffs cleanup functions return before the
   `runPostMutationSteps` wrapper (`pkg/dataplane/loader.go:301-318`). Snapshot
   construction then remains fallible (`pkg/dataplane/userspace/manager_compile.go:244-260`),
   including live route/rule enumeration
   (`pkg/dataplane/userspace/builder.go:54-82`). Bootstrap/classifier map
   programming, process startup, protocol checks, and publication can all fail
   afterward (`pkg/dataplane/userspace/manager_compile.go:409-445`).

   The plan's named “driver refuses attach” is also misstated: native refusal is
   warned and falls back to generic (`pkg/dataplane/loader.go:343-367`); only the
   generic attach failure returns (`:374-377`). The source's own #6894 scope
   comment already lists attach, preflight, and snapshot construction as
   uncovered (`pkg/dataplane/compiler_validate_4960.go:40-65`). Section 2's
   reachability and OQ-6 cost calculation are therefore based on a false
   denominator.

5. **[CRITICAL] The exact attach-abort path is unadjudicated transit, contradicting the plan's old-policy-only hazard and #7191 composition claim.**

   **Confirmed from code.** On normal boot the runtime is marked armed as soon
   as `Start` succeeds, before the first per-interface attach
   (`pkg/daemon/daemon_run_bringup.go:594-626`). `DataplaneArmed` explicitly does
   not cover that later per-interface boundary
   (`pkg/daemon/daemon_transit_gate.go:140-153`). A generic attach failure returns
   from `CompileUserspaceShim` before `ProveArmCoverage` publishes the new report
   (`pkg/dataplane/loader.go:309-330`). The apply tail then disarms only for an
   already-published incomplete report; unknown or a stale previous complete
   report does nothing (`pkg/daemon/daemon_arm_coverage_7191.go:89-111`).

   #7191's own invariant says a generic attach failure must disarm and that the
   coverage gate is one-way until restart
   (`pkg/daemon/daemon_arm_coverage_7191.go:8-37`). On a fresh boot there can be
   an armed/open kernel transit path and an interface with no shim at all. That
   is not merely “OLD policy over NEW topology” (`plan.md:22-34`); it is the
   policy-free-router state #7191 was intended to prevent. P3's “retry several
   times, then unarm” prolongs this security hole. The generic-attach class must
   close transit immediately, irrespective of whether a separate convergence
   retry is later designed.

6. **[CRITICAL] P2 cannot be implemented as an `ApplyResult` field, and one abort bit cannot describe the real authority state.**

   **Confirmed from code.** A `compileZones` error discards the partially filled
   `CompileResult` (`pkg/dataplane/compiler.go:376-380`), and
   `CompileUserspaceShim` propagates `(nil, error)`
   (`pkg/dataplane/loader.go:262-265`). Userspace `ApplyConfig` likewise returns
   `(nil, error)` for every compile failure
   (`pkg/dataplane/userspace/manager.go:468-477`). `ApplyResultFromCompileResult`
   is reached only on success (`pkg/dataplane/apply.go:210-229`), and both
   userspace result records are success-side (`pkg/dataplane/userspace/manager_compile.go:392-407,512-515`).
   Returning a non-nil ordinary `ApplyResult` on error is not an innocuous API
   tweak: daemon consumers treat it as authoritative input for session-sync zone
   maps and networkd (`pkg/daemon/daemon_apply_dataplane.go:227-230,272-297`).

   Worse, after `apply_snapshot` succeeds, the new snapshot becomes retained
   authority and generation/hash state advances
   (`pkg/dataplane/userspace/manager_compile.go:444-469`), but helper-status, HA,
   and forwarding synchronization may still return errors (`:470-510`). Those
   errors leave the **new**, not old, dataplane policy live. “Aborted after host
   mutation” cannot distinguish pre-publication old-authority, ambiguous
   publication, and accepted-with-post-commit-error. P2 needs a separate typed
   phase/publication outcome available on every return, not a success-result
   boolean.

   “Config generation N” is also undefined. `ApplyResult.Generation` advances
   only when a successful result is recorded (`pkg/dataplane/apply.go:305-328`),
   while the userspace snapshot generation is allocated only after
   `CompileUserspaceShim` succeeds (`pkg/dataplane/userspace/manager_compile.go:244-258`).
   A Phase-2 abort has neither. The store already has an active-text convergence
   digest (`pkg/configstore/store.go:875-924`), but the plan neither selects an
   identity nor defines its lifecycle.

7. **[CRITICAL] Even a redesigned P2 cannot currently tell whether Phase 2 converged; most mutations and write failures are invisible.**

   **Confirmed from code.** Production `markHostMutated` calls exist only for
   VLAN creation and the two configured-address reconcile classes
   (`pkg/dataplane/compiler_iface.go:697,760,989`). The record deliberately
   coalesces all objects to a coarse action string
   (`pkg/dataplane/compiler_hostmutation_4960.go:47-60`). It does not cover MTU,
   link state, ethtool, procfs/sysfs, foreign-bond deletion, or unmanaged-NIC
   stripping.

   More fundamentally, write failures are routinely swallowed: `accept_ra`
   (`pkg/dataplane/compiler_iface.go:268-270`), configured address operations
   (`:346-369`), all three MTU paths (`:765-776,877-887,992-1004`), configured
   UP/DOWN (`:913-929`), unmanaged deletion/down (`:1586-1623`), and the tuning
   group (`pkg/dataplane/compiler.go:1761-1819`). The proc/sysfs writes ignore
   their errors, and the tuning group marks itself applied at `:1819` even after
   earlier failures. An attach can then succeed and an apply can return success
   while host writes remain unapplied. P3 has no success predicate unless these
   operations gain per-object outcomes or readback; adding that evidence is not
   the plan's small P2.

8. **[CRITICAL] P4 is option (a) with an unstable boundary, and the plan never defines its state machine.**

   **Confirmed from code.** P4's pre-state is irrelevant to re-driving the same
   config: a deleted bond/address or applied ratchet is already at that config's
   target. Pre-state matters only for rollback, supersession, or ownership
   release. Once that invariant is adopted, it applies beyond the named three
   classes. Removing an MTU leaf provides no inverse because all three writers
   are gated on `MTU > 0` (`pkg/dataplane/compiler_iface.go:765-776,877-887,992-1004`).
   The same is true of pre-existing non-desired addresses deleted by exact
   reconcile (`:344-369`), UP/DOWN state
   (`:913-929`), created VLANs (`:203-276`), and unmanaged admin state (`:1608-1623`).
   The cited model itself states the universal invariant: every host/NIC
   mutation must be reverted when ownership ends
   (`pkg/daemon/released_nic_tunables.go:22-32`). That rule expands P4 toward an
   object-level Phase-2 journal.

   P4 says only “capture pre-state.” It never says whether restoration occurs on
   first abort, after retry exhaustion, on rollback/supersession, or at shutdown;
   whether successful convergence commits/forgets the record; or how partial
   restore retains debt. Without a restore transition the ledger changes no
   outcome. Restore-on-abort is the rejected undo design and races the forward
   retry; retaining it requires commit/transfer/CAS semantics the plan omits.

   The borrowed host-tunables ledger is explicitly memory-only and deliberately
   loses pre-state across crash (`pkg/daemon/host_tunables.go:530-551,682-700`).
   That simplification may be acceptable for stable literal tunables; it cannot
   reconstruct a deleted external object. Persistence before mutation would be
   a write-ahead undo journal. OQ-1 is answered: the boundary is already unstable
   and option (d) collapses into the architecture the plan rejects.

9. **[CRITICAL] The foreign-bond class demonstrates that P4 is the wrong remedy, not merely an undersized one.**

   **Confirmed from code.** `stripUnmanagedInterfaces` claims a bond is
   “daemon-created” but proves only that the unconfigured link's Go type is
   `*netlink.Bond`; it then deletes it
   (`pkg/dataplane/compiler_iface.go:1586-1598`). There is no xpf provenance
   check. Exact restoration of an arbitrary foreign bond would require its
   options, enslaved members, addresses, routes, qdisc/dependent state, and
   conflict handling if another owner recreated or changed it after the abort.

   The correct bond owner already exists upstream: it deletes only names in its
   tracked set and retains failed deletes for retry
   (`pkg/routing/bond.go:542-609`), and it is wired on every interface reconcile
   (`pkg/daemon/daemon_apply_interfaces.go:424-439`). The defensible fix is to
   stop the type-only sweep from deleting unowned bonds, not to snapshot and
   recreate arbitrary foreign networking state. The same authority/CAS problem
   applies to an unmanaged address that DHCP or an operator changes after
   capture.

10. **[CRITICAL] P3 has no reliable trigger, retry classification, success predicate, or supersession rule.**

   **Confirmed from code.** `released_nic_tunables` retains failed ownership for
   “the next reconcile”; it does not emit or schedule that reconcile
   (`pkg/daemon/released_nic_tunables.go:56-62,126-142`). Its production wire
   point is the full apply tail (`pkg/daemon/daemon_apply_tail.go:443-446`). The
   available full-reapply events are boot, a qualifying DHCP lease change, and a
   feed update (`pkg/daemon/daemon_run_bringup.go:536-541`;
   `pkg/daemon/daemon_dhcp.go:73-102`; `pkg/daemon/daemon_feeds.go:36-57`). None
   reliably follows an ordinary local abort. With no timer, zero future attempts
   is valid; synchronous attempts can block/hot-loop. Therefore “bounded retries
   then unarm” is not bounded in wall time and may never reach its terminal
   safety state.

   `applyActiveConfigResult` reruns the entire daemon reconcile, not Phase 2
   (`pkg/daemon/daemon_apply.go:166-182`). Its return joins unrelated networkd,
   Kea, credentials, routing, VRRP, and other failures
   (`pkg/daemon/daemon_apply_tail.go:448-464`). Clearing debt only on full `nil`
   can repeatedly retry and eventually unarm an already-converged dataplane due
   to an unrelated persistent tail error; clearing on dataplane success requires
   the typed outcome missing from P2. `compileErrorMustAbortApply` is not a
   retryability taxonomy; it recognizes only required-protocol sentinels
   (`pkg/daemon/daemon_apply.go:548-569`).

   Finally, P3 promises generation N, but background apply deliberately re-reads
   the **current** active config after acquiring `applySem` to prevent stale
   replay (`pkg/daemon/daemon_apply.go:105-127,166-182`). If N+1 supersedes N,
   replaying N violates #6716; applying N+1 is not “retry N” and leaves N's P4
   record needing an undefined restore/transfer. The plan specifies no
   cancellation, handoff, or commit/forget transition.

11. **[MAJOR] The four shipped mechanisms do not compose into the doctrine claimed in section 3.**

   **Confirmed from code.** The plan overreads each mechanism:

   - #5679 does not install convergence. It records an ordinary error while
     retaining the old dataplane and explicitly names an operator re-commit or
     feed update as the future attempt
     (`pkg/daemon/daemon_apply_dataplane.go:175-193`). That is fail-stale plus a
     conditional external event, not an autonomous converge-forward doctrine.
   - #6894 explicitly documents its uncovered post-mutation failures
     (`pkg/dataplane/compiler_validate_4960.go:40-65`); the two bpffs cleanups at
     `pkg/dataplane/loader.go:301-305` add paths outside even that list.
   - #5275/#7191 intends generic attach failure to disarm, while P3 delays
     disarming and the current call order fails to publish the proof (Finding 5).
   - #7288 wraps only the preflight/attach closures in `runPostMutationSteps`
     (`pkg/dataplane/compiler_hostmutation_4960.go:95-129`) and observes only the
     three coarse mutation actions in Finding 7. It misses in-Phase-2 failures,
     cleanup failures, snapshot-build failures, and most actual writes.

   Section 3's conclusion that the codebase already chose option (c) for “this
   failure class” (`plan.md:61-63`) is therefore false. P3 would be a new retry
   subsystem with new ownership and safety contracts, not composition glue.

12. **[MAJOR] The map-order observation is real, but it does not kill a real journal and it does break the proposed test plan.**

   **Confirmed from code.** The actual map range is
   `pkg/dataplane/compiler_iface.go:614`, not the plan's `:450-462`. A runtime
   write-ahead journal records the operations/pre-state that actually occurred
   in their actual order; it does not infer them from a stable zone ordinal.
   Nondeterminism kills rollback reconstructed from “site k,” not option (a) as
   the plan defines it (“write an undo record before each netlink call,”
   `plan.md:129-134`). Undo can still be rejected for restoration failure,
   authority races, and breadth, but section 4.2's stated load-bearing reason is
   logically invalid and self-defeating: P4 would also have to journal runtime
   operations before each destructive write.

   OQ-3 is fatal to section 9 as written. One syntactic address site loops over
   arbitrary addresses (`pkg/dataplane/compiler_iface.go:344-369`), unmanaged
   sites loop over interfaces/addresses (`:1561-1624`), and queue sites loop over
   runtime queue files (`pkg/dataplane/compiler.go:1796-1812`). Those loops can
   leave an interior per-object prefix, so “23 sites” is not the runtime
   cardinality. Most calls are direct and have no named per-site injection seam
   (examples at `pkg/dataplane/compiler_iface.go:228,248,268,348,769,1593`), and
   many errors are swallowed rather than aborting. A global `k` also changes
   meaning with zone-map iteration. The proposed test cannot prove arbitrary
   prefix convergence without named per-object operations or a privileged,
   deterministic harness.

13. **[MAJOR] HA ordering is an unaddressed failure mode in the terminal-unarm design.**

   **Confirmed from code.** Ordinary dataplane errors remain peer-sync eligible;
   after the local apply error, the commit path still pushes the new active
   config (`pkg/daemon/daemon_apply_commit.go:255-318,321-341`). `QueueConfig`
   establishes only that bytes were written to the peer connection, not that the
   peer applied the config (`pkg/cluster/sync_conn_config.go:259-325`). P3 can
   therefore reach terminal local disarm/demotion before peer acceptance is
   known. The local box may stop carrying transit while the peer still enforces
   old policy or has also failed its apply.

   This is aggravated by #7191's one-way gate: once coverage disarms, recovery
   requires process restart (`pkg/daemon/daemon_arm_coverage_7191.go:32-37`), and
   `markDataplaneArmFailed` immediately closes transit and lowers HA eligibility
   (`pkg/daemon/daemon_transit_gate.go:206-223`). The plan gives no peer-ACK,
   role-specific retry, failover-readiness, or re-arm ordering. That silence can
   turn a local convergence problem into a cluster outage.

14. **[MAJOR] The conditional adopt-refusal half of P1 is neither causal nor “small and local”; it adds another durable ledger class.**

   **Confirmed from code.** A successful `LinkAdd` constructs exactly a VLAN
   carrying the requested parent and VID (`pkg/dataplane/compiler_iface.go:240-250`).
   The retry's adoption predicate verifies kind, namespace, the same VID, and the
   same parent (`pkg/dataplane/vlan_provenance_6916.go:84-106`). Absent an
   external delete/recreate/retune, a child created by the aborted attempt passes
   that predicate. The plan has not demonstrated its claimed causal path from
   “aborted create” to “later adopt refused.” A hard failure detects external
   divergence; it does not converge it.

   P1 nevertheless requires the caller to know that this **particular** child
   “was created by a prior aborted apply of this same config” (`plan.md:158-161`).
   Current evidence is intentionally action-class-only, not per-interface or
   per-generation (`pkg/dataplane/compiler_hostmutation_4960.go:47-60`; call at
   `pkg/dataplane/compiler_iface.go:692-698`). Implementing the condition requires
   durable per-resource/config provenance—a fourth P4 class—or else hard-fails
   all adoption refusals and materially changes existing semantics. Only moving
   `accept_ra` onto the create-and-adopt path is the small independent P1 slice.

15. **[LOW] The stranded-plan false-fact accusation is substantively correct, but its attribution is itself inaccurate; several current citations are also stale at the claimed base.**

   **Independently confirmed.** The stranded plan labels §4.4 “verified r1 N1”
   and calls `compilePortMirroring` host-destructive
   (`origin/research/4960-apply-txn:docs/research/4960-apply-txn/plan.md:207-216`).
   At its own merge base, the function only cleared/set `DataPlane` mirror
   configuration (`c7ed438e0:pkg/dataplane/compiler.go:1704-1748`); its cited
   `:1758/:1811` lines were read-only link lookups in unrelated helpers. Current
   code has the same non-host-mutating shape
   (`pkg/dataplane/compiler.go:1868-1903`). The accusation in `plan.md:12-16` is
   therefore correct.

   However, Claude r1 N1 merely requested verification
   (`origin/research/4960-apply-txn:docs/research/4960-apply-txn/claude-smr-plan-r1.md:135-140`);
   Codex r1 did not verify this claim, and Codex r2 explicitly refuted it
   (`origin/research/4960-apply-txn:docs/research/4960-apply-txn/codex-plan-r2.md:544`).
   `premise-check.md:35-38` should say the **plan author self-marked** it verified,
   not that a hostile review marked it verified.

   Citation drift is not isolated: the zone-map range is at
   `pkg/dataplane/compiler_iface.go:614-658`, not `:450-462`; adoption refusal is
   at `:178/:215-217/:711-733`, not `:210`; and `ApplyBonds` is at
   `pkg/daemon/daemon_apply_interfaces.go:424-439`, not `daemon_apply.go:420`.
   These were verified at the exact production base the plan claims to cite.

## Direct disposition of the open questions

- **OQ-1:** Yes. P4 is an undo/ownership journal with an already-expanding
  boundary and no state machine. Kill it as proposed.
- **OQ-2:** Fatal to P3. No event reliably re-fires, so “bounded attempts” has no
  wall-clock meaning.
- **OQ-3:** Yes. Nondeterministic global order, per-site loops, direct calls, and
  swallowed failures make the stated `k` test non-controlling.
- **OQ-4:** Some typed publication/authority outcome is a prerequisite. The next
  apply cannot safely act on a single “host mutated” bit when failures span
  pre-publication, ambiguous publication, and post-publication states.
- **OQ-5:** Generic attach failure must unarm immediately because a surface is
  unadjudicated. For other classes, unarm policy requires an explicit typed
  safety classification; retry count is not that classification.
- **OQ-6:** P1-P4 is not proportionate. The `accept_ra` re-drive correction is
  independently defensible. A typed, phase-aware P2 is also defensible as
  operator evidence and as a prerequisite to any future recovery design. The
  conditional adoption rule, P3, and P4 are not ready to ship. A future retry
  proposal must first classify measured transient errors, supply a real
  scheduler/backoff and supersession model, define its success predicate, and
  prove a fixed point.

The current recommendation is not repairable with nits. P3/P4 must be removed
and the failure/authority model re-derived before another convergence proposal
can be reviewed. This is a failed plan, not a request for implementation detail.

VERDICT: PLAN-NEEDS-MAJOR

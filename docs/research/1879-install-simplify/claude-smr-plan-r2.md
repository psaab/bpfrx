# Claude SMR hostile plan review — #1879 round 2

Plan reviewed: DRAFT v2 @ `20ae36be7`. Round-1 SMR verdict was
PLAN-NEEDS-REVISION (S0-S7); this round verifies the v2 dispositions
and hostile-checks the NEW v2 mechanisms.

## Round-1 finding dispositions (verified against v2 text)

- S0 (service-mode rollback no-op) — ADDRESSED. §4.6 states both
  holes with citations (cli.go:289 registration; store.go:1151
  `prevCfg != nil` skip); SAFE-BOOTSTRAP step 0 makes them named M1b
  prerequisites (daemon-side handler wired to `d.applyConfig`;
  synthesized-bootstrap rollback target); §9 adds the service-mode
  rollback unit test and T1 integration test. The plan no longer
  claims commit-confirmed works off-the-shelf.
- S1 (bootstrap mode undefined; cost) — ADDRESSED. Step 3 defines the
  mode by enumerated suppressions (no rename, no link cycle, no
  networkd takeover beyond lifeline, no AF_XDP/dataplane, no FRR
  managed-section writes) with a single exit point; M1a/M1b cost
  split (3-5 days / 1-2 weeks) in §5 Path D; §3 carries the "M1b is
  NOT small" framing.
- S2 (protected designation vs rollback) — ADDRESSED. Step 1 places
  the enforced protected set (leaf ∪ fxp0 ∪ lifeline-record at
  /etc/xpf/lifeline-interface) in the reconcile/strip paths, explicitly
  config-independent; invariant 3 pins it; AGY's compiler_iface.go
  evidence is incorporated.
- S3 (postinst failure modes + cleanup discrepancy) — ADDRESSED.
  Consequences (a)-(c) stated incl. the dpkg wedge + recovery;
  cleanup-on-upgrade is asserted decommissioning-only with the
  loader.go:1160 citation AND converted to tested contract (T2) with
  a stated fallback if the test refutes it. This is the right
  epistemic posture.
- S4 (CPU discipline) — ADDRESSED. `xpf-upgrade` carries the full
  nice+taskset port (incl. the offline-CPU false-reject guard);
  postinst gets nice-only with the ~17s/one-core cost stated.
- S5 (cloud-init network manager conflict) — ADDRESSED. C.1.3 ships
  `network: {config: disabled}`; §9 image tests verify it.
- S6 (/usr/local shadowing) — ADDRESSED (postinst removal list,
  mirrors the bpfrxd migration precedent).
- S7 (hosting limits as assumptions) — ADDRESSED (M2 spike measures;
  M3 verifies repo limits).

## New-mechanism hostile checks (v2-only)

### N1 (MED, specification gap) — "rollback restores bootstrap state" overstates: renames persist

SAFE-BOOTSTRAP step 4 says confirm-timeout rollback "restores
bootstrap state with the lifeline `.network` intact". Not exactly:
the rename pass (and `.link` files) executed at takeover are NOT
reverted by a config rollback — `.link` files and kernel names
persist. The design still holds (the lifeline `.network` matches
`Name=fxp0`, which is the post-rename name, so management addressing
survives), but the plan must say "post-rollback bootstrap state =
renamed NICs + lifeline `.network` + zero dataplane/config claims;
renames are deliberately not reverted" — otherwise the /engineer
phase will either over-build rename-reversal (risky, link cycles on
a degraded box) or discover the wording was wrong. One clarifying
sentence in step 4 + T1's assertion list should check the
post-rollback state by reachability + no-claims, not by
name-restoration.

### N2 (LOW-MED, specification gap) — dataplane/VRRP/FRR state after rollback-to-bootstrap needs one sentence

The synthesized-bootstrap target is applied through `d.applyConfig`
full reconcile. For the safety property (mgmt reachability) the
protected set suffices regardless. But the plan should state what
happens to the already-loaded dataplane, any VRRP instances, and the
FRR managed section written by the unconfirmed commit: the expected
semantics is "reconcile-to-empty removes config-driven claims
(bindings, VRRP instances, FRR section) but does NOT attempt full
dataplane unload / return to literal pre-takeover process state".
If reconcile-to-empty cannot shrink some subsystem to zero, that
subsystem's residue must be enumerated at /engineer time. One
sentence + an /engineer-phase checklist item; not a design flaw —
the mgmt-reachability invariant does not depend on it.

### N3 (LOW) — predicate case "committed-empty → NOT bootstrap" interacts with the gate's purpose

An operator can `commit no-confirm` an empty config (or commit empty
confirmed + confirm) and thereby exit bootstrap mode forever while
never having taken over anything; a later interface-claiming commit
then needs no confirm gate. That's consistent with Junos behavior
(commit-confirmed is operator discipline after the first commit) and
the protected set still shields mgmt, so I do not block on it — but
OQ-7's answer should note the gate is strictly "first commit on a
fresh system", not "first takeover", and accept that explicitly.

## Checks performed without findings

- The five-case predicate matrix is correct against the actual load
  path (`Load()` then `bootstrapFromFile()`, daemon_run.go /
  daemon_apply.go) and the failed-import case is a strict improvement
  over today's behavior (verified: today a failed import leaves an
  empty store and takeover proceeds).
- The dependency matrix matches the exec inventory I independently
  generated (systemctl/ip/chronyc/vtysh/swanctl/ethtool/nft/
  networkctl/ss/...); levels are policy-defensible.
- xpf-upgrade-as-primary resolves the #1869-equivalence problem
  honestly; the postinst tier's stated consequences are accurate
  dpkg behavior.
- Path C v2 no longer assumes qcow2-under-the-hood; the spike-first
  gate is the correct cheap-falsification ordering; cost raised to
  2-3 weeks, which I find realistic.
- HA mixed-version policy correctly builds on existing
  protocol-version machinery (protocol.go:10, manager.go:119,
  daemon_ha_userspace.go:902) rather than asserting compatibility.

## Verdict

PLAN-NEEDS-REVISION (minor) — two required clarifications, no
design changes:

1. N1: one sentence in SAFE-BOOTSTRAP step 4 defining post-rollback
   bootstrap state (renames persist; reachability-based T1
   assertions).
2. N2: one sentence on reconcile-to-empty subsystem semantics +
   /engineer-phase residue checklist note.
3. (N3 optional) Note in OQ-7 that the gate is "first commit on a
   fresh system", not "first takeover".

With these folded in, my verdict is PLAN-READY.

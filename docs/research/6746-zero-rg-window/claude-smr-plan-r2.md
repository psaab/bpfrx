# Claude SMR hostile plan-review — #6746 round 2 (plan v2 @ 12182118f)

**Verdict: PLAN-READY** — all five r1 folds verified present AND accurate
against source; both new attack surfaces assigned this round
(reth-sub-unit egress RG, post-liveness operator arm) traced to a close
with fresh evidence; no remaining findings. Path A recommendation stands:
close #6746 as falsified, land the regression pin, file the tri-state
hardening as a follow-up.

## Fold verification (each checked against the v2 text AND re-opened in source)

- **MAJOR-1 (owner_rg>0 premise) — PRESENT-AND-ACCURATE.** v2 §3.1 now
  carries the three-link chain: `forwarding/nat.rs:137-160`
  (`interface_nat_local_resolution` maps dst → owning ifindex),
  `forwarding_build/interfaces.rs:157` (`interface_nat_v4.insert(
  v4.addr(), iface.ifindex)`), `forwarding_build/interfaces.rs:334`
  (egress row `redundancy_group: iface.redundancy_group`). All three line
  anchors re-verified at base. The `owner_rg_id <= 0` design-permit
  boundary (`ha.rs:86-94` permits node-local LocalDelivery regardless of
  map contents) is now stated explicitly with its blast-radius meaning.
  The §9.2 owner_rg==1 guard arm is present.
- **MINOR-1 (deferred path) — PRESENT-AND-ACCURATE.** v2 §3.4 first
  bullet traces the `pendingXSKStartup` first-RG commit: boot apply always
  runs the HA block (`publishedSnapshot == 0` ⇒ not pending), phantoms
  persist, `syncSnapshotLocked` publishes no HA state, poll re-fabricates
  before the tail arm (`process_status.go:211-212`, `:243`). Line anchors
  verified.
- **MINOR-2 (empty-sender audit) — PRESENT-AND-ACCURATE.** v2 §3.1 final
  bullet names `clearHelperHAStateLocked` as the only empty sender with
  all three `!m.clusterHA` gates (`manager_compile.go:391`, `:296`;
  `manager_ha.go:145` — all re-verified), plus the helper-side facts
  (`rg_runtime` constructed once at `coordinator/ha_state.rs:39`, stored
  only from `ha/state.rs:4`; `apply_snapshot` never mutates it).
- **MINOR-3 (operator arm) — PRESENT-AND-ACCURATE.** v2 §3.4 covers
  `cli_request_chassis.go:151-158` and `server_diag_system_action.go:
  395-415`; the close argument (M1's non-empty map + ctrl gate with 15s
  `clusterHA` prewarm, `maps_sync.go:420-424`) is correct as far as it
  goes, and this round's attack (b) below covers the post-liveness case
  the paragraph does not reach.
- **NIT-1 / AGY-r1-MINOR (§9 pins) — PRESENT-AND-ACCURATE.** §9.1 now
  asserts `desiredForwardingArmedLocked()==false` before AND after the
  zero-RG apply, adds the no-empty-`update_ha_state`-while-clusterHA
  session assertion and the deferred-path variant; §9.2 adds the
  owner_rg==1 propagation guard.

## New attacks this round (assigned to AGY as well; traced independently here)

**(a) RETH VLAN sub-unit egress RG.** Could `interface_nat_v4` key an
RG-owned address to a reth SUB-UNIT ifindex (e.g. `reth1.50`) whose egress
row is missing or `redundancy_group=0`, which would permit LocalDelivery
on every standby at all times — a worse live defect than the framed
window? **CLOSED.** The Go snapshot builder assigns every unit row
`RedundancyGroup: rg` with the parent's resolved RG
(`pkg/dataplane/userspace/interfaces.go:302`, comment "inherit resolved
RG (RETH parent or own)"; the base-interface resolution at `:215-218` is
`iface.RedundancyGroup` else `rethRG[name]`, emitted at `:230`). This
includes bondless-RETH VLAN units on synthetic logical ifindexes
(`shouldUseLogicalOnlyParentBoundRethVLAN` path, `:270-295`): the
`continue` on synthetic-ifindex exhaustion skips the unit entirely rather
than emitting an rg=0 row (#5557), so no address can key to a missing
egress row via that path either. The Rust build copies
`iface.redundancy_group` into the egress row unconditionally
(`forwarding_build/interfaces.rs:334`). An interface-NAT address on any
reth unit therefore resolves `owner_rg = parent RG > 0`. No permit hole.

**(b) Operator arm after XSK liveness/prewarm already elapsed.** The v2
paragraph leans on the 15s `clusterHA` prewarm; what if the operator arms
when prewarm no longer applies? **CLOSED, but the load-bearing leg is M1,
not the ctrl gate.** On a zero-RG node the helper is never armed
(desired=false), so ctrl never opens and `neighborsPrewarmed` never runs;
an operator `forwarding arm` then goes through the FIRST-prewarm path
unconditionally (`!m.neighborsPrewarmed` → `m.clusterHA` → 15s
`ctrlEnableAt` delay, `maps_sync.go:404-424`). Even in the adversarial
ordering (operator arms, 15s elapses, THEN the first-RG commit lands), the
helper's `ha_state` still holds the boot-published `{0..15 inactive}`
phantoms — the operator verb does not clear `rg_runtime`, and §3.1's
empty-sender audit shows nothing else can. The framed RG1 LocalDelivery
then resolves owner_rg=1 → phantom inactive → `HAInactive`. M1 is
sufficient alone; the ctrl gate is a second belt, never the only one.

## Re-examination of the r1 break attempts

Re-ran the r1 break list against v2 (empty-sender audit, helper-side
reset, arming authorities, sub-apply paths, deferred resume, anchor
spot-check — now 14 anchors). No new surface found. The falsification's
two conjuncts (C1 armed, C2 empty map) remain jointly unreachable on a
clustered node at `ad9591177`.

## Residual position

- The falsification is complete and self-contained at v2: M1 (phantom
  fabrication + empty-sender audit + owner_rg chain), M2 (zero-RG
  desired-disarm), M3 (publish-before-arm), each independent, each
  evidenced, each with a §9 pin.
- Path A is the correct terminal disposition for #6746; Path B
  (tri-state) is honestly framed as hardening against the accidental
  invariant, correctly deferred to a follow-up issue so it can ride a
  future phantom-fabrication cleanup rather than landing as un-motivated
  packet-path churn.
- Codex remains infra-blocked (account usage cap to Aug 10; two
  documented r1 retries, one more due before the final comment). The
  codex-infra-blocked exception (2-of-3: SMR + AGY) applies; a Codex
  post-hoc review when the cap lifts is a cheap way to reopen if it finds
  something both of us missed.

**Convergence recommendation: PLAN-READY at v2, Path A.**

# #1373 Phase 0 Tracker: Retire Legacy eBPF Dataplane

Phase 0 is a documentation and audit PR for #1373. It announces that new
dataplane development targets `userspace-dp`, refreshes the userspace gap audit,
and records the feature-gap blockers that have since closed before later
retirement phases remove legacy eBPF code.

No BPF source is removed in Phase 0. The `bpf/` tree, bpf2go-generated Go
bindings, eBPF loader, legacy test targets, and BPF-backed CLI surfaces remain
present until later phase PRs.

## Feature Gap Closeout

The original #1374-#1381 Phase 0 blocker set is closed. This tracker keeps the
closeout state visible because the detailed plan files still define important
runtime contracts, but those issues are no longer the active source-removal
backlog.

| Issue | Disposition |
|-------|-------------|
| #1374 | SYN-cookie runtime support is implemented; final source-removal evidence belongs with #1477 if required. |
| #1375 | The admitted userspace three-color policer slice is implemented; future hardening is production follow-up work. |
| #1376 | Userspace port mirroring runtime support is implemented; final mirror evidence belongs with #1477 if required. |
| #1377 | Userspace-v1 address-persistent SNAT selection, fail-closed pool runtime, helper-local per-pool `persistent-nat`, live-port exhaustion observability, and allocator counters are implemented. #1448, #1449, and #1450 are closed as documented helper-restart, HA-gate, and cross-backend selector contracts, not active #1373/#1451 blockers. |
| #1378 | Scheduler state, counter survival, strict missing-scheduler behavior, deterministic evidence validation, and live HA artifact capture are complete for userspace. |
| #1379 | Policy-deny, screen-drop, filter-log, source-disambiguated FILTER_LOG syslog, and deterministic fanout coverage now emit from userspace. |
| #1380 | Userspace `show system buffers` renders helper status; Rust-owned session and flow-cache denominators are helper-published, and neighbor entries remain counters until Rust owns a bounded neighbor-cache capacity. |
| #1381 | The blocking interface split is closed; remaining runtime/operator surface migration is tracked by #1451. |

## Current Removal Trackers

| Issue | Scope |
|-------|-------|
| #1451 | Move remaining runtime and operator callers off the legacy eBPF-shaped dataplane surfaces before source/generated artifact deletion. |
| #1473 | Split the retained userspace XDP shim from legacy `xdp_main_prog` fallback. |
| #1476 | Remove legacy BPF source, generated artifacts, and build hooks after migration blockers close. |
| #1477 | Publish final userspace-only validation artifacts for the exact source-removal candidate. |

#1474 is closed: omitted `system dataplane-type` selects userspace, while
explicit `system dataplane-type ebpf` remains temporary warned compatibility
until legacy source removal.

## Recommended Order

1. Land #1451 first so remaining runtime and operator surfaces no longer depend
   on the legacy eBPF-shaped `dataplane.DataPlane` contract.
2. Land #1473 before source deletion so the retained userspace shim is
   explicit and separate from legacy `xdp_main_prog` fallback.
3. Land #1476 as the source/generated-artifact removal PR after those blockers
   close.
4. Attach #1477 validation artifacts to the exact #1476 candidate.

## Phase Boundaries

- Phase 0: docs and audit only; no BPF source removal.
- Phase 1: broad documentation migration. Historical PR-plan docs are preserved
  as history; add banners only where needed instead of rewriting old plans.
- Phase 2: test environment consolidation.
- Phase 3: runtime and operator surface migration under #1451.
- Phase 4: BPF source removal under #1476, only after #1451, #1473, and
  the required #1477 validation artifacts are ready.
- Phase 5: CLI and observability cleanup. The current #1380 helper-status
  contract is closed; future neighbor-cache fill-percentage rows need
  helper-owned denominators before they can enter the utilization table.

## Phase 0 Exit Criteria

Phase 0 is complete only when:

- the userspace gap audit is verified against current code and explicitly calls
  out fix-forward PR dependencies such as #1385 and #1386 instead of implying
  they have already landed;
- the blocker list here and the #1384 blocker-plan bundle have the same scope
  for #1374, #1375, #1376, #1377, #1378, #1379, #1380, and #1381;
- active docs are reconciled with the current userspace runtime instead of
  preserving stale "not implemented" claims for features already implemented in
  Rust;
- rollback remains documented as the legacy eBPF dataplane staying present and
  explicitly selectable until later phases; and
- no BPF source, generated bindings, loader code, legacy tests, or CLI surfaces
  are removed by the Phase 0 PR.

## Rollback Path

The Phase 0 rollback path is deliberately simple because this PR is docs/audit
only:

1. keep the legacy eBPF backend in the tree and in build/test targets;
2. set `system dataplane-type ebpf` where an explicit legacy backend is
   required, acknowledging the compile warning emitted for that temporary
   compatibility selection;
3. restart/re-apply `xpfd` so the manager selects the eBPF backend and legacy
   XDP/TC programs; and
4. do not remove existing BPF pins or source until the later retirement phases
   have their own tested rollback plans.

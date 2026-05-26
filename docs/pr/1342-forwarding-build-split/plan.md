# #1342 — Split `forwarding_build.rs` by entity kind (plan v1)

Status: DRAFT v1 — pending adversarial plan review (Codex + AGY).

## Issue framing

`userspace-dp/src/afxdp/forwarding_build.rs` is 1162 production LOC.
The two top-level builders — `build_forwarding_state` (469-LOC body
at line 84..596) and `build_cos_state` (312-LOC body at line
598..920) — are both >3x the engineering-style.md "no god functions"
100-LOC soft cap and 1.5x the Tier-1 200-LOC refresh-audit
threshold.

`build_forwarding_state` is a linear orchestrator that translates a
`ConfigSnapshot` into `ForwardingState` by walking zones, tunnel
endpoints, interfaces (twice — once for addresses/MAC/zone, once
for egress-binding/MAC resolution), routes (v4 + v6), neighbors,
fabrics, then attaches policy/NAT/screen/MSS/filter/CoS/flow-
export/mirror state. It also installs nftables RST suppression.

`build_cos_state` is a linear builder that resolves CoS classifiers,
schedulers, scheduler-maps, and rewrite-rules into per-interface
`CoSInterfaceConfig` entries with a "useful CoS state" gate that
fixes the f0e364d7 cross-binding-redirect regression (#1183).

Both functions are called from exactly one site inside
`build_forwarding_state` (for `build_cos_state`) and from
configuration-snapshot ingestion (for the public
`build_forwarding_state_*` family). They are pure functions of
`ConfigSnapshot` (+ `PolicyCounterStore` + optional `previous` for
diff-friendly state carry).

The issue body proposes splitting by entity kind:

```
forwarding_build/
├── mod.rs                  // orchestrator + small builders + reexports
├── zones.rs                // populate_zones
├── tunnels.rs              // populate_tunnel_endpoints
├── interfaces.rs           // populate_interface_state + egress pass
├── fib.rs                  // populate_fib (routes v4/v6) +
│                           //   neighbors + fabrics
└── cos.rs                  // build_cos_state + cos helpers
```

The wave-2 layout convention is `forwarding_build/mod.rs` slim
orchestrator plus sibling files in the directory — NOT
`forwarding_build_iface.rs` flat siblings. The parent module
include changes from `#[path = "forwarding_build.rs"] mod
forwarding_build` to a plain `mod forwarding_build` (which
auto-resolves to `forwarding_build/mod.rs`).

## Honest scope/value framing

This is **pure code motion**. Zero behaviour change. Zero hot-path
impact (the config-apply path runs only on commit, not per-packet).
The win is reviewability and modularity — `build_forwarding_state`
at 469 LOC and `build_cos_state` at 312 LOC both exceed
engineering-style.md's "Tier-1 hard hit" >200 LOC threshold for
refresh audits, and the file as a whole at 1162 LOC exceeds the
soft cap.

Total LOC delta: ~zero (perhaps +30 LOC from `mod.rs` re-export and
helper context struct boilerplate). No new allocations on the
config-apply path. No new abstractions inside the hot path
because the hot path doesn't run this code.

**If reviewers conclude the churn isn't justified, PLAN-KILL is an
acceptable verdict.** Refactor backlog issues are routinely killed
when the cost-benefit isn't there. See `project_966_killed.md` etc.

## What's already shipped / partially batched

- Test extraction to `forwarding_build_tests.rs` (1768 LOC) via
  `#[cfg(test)] #[path = "forwarding_build_tests.rs"] mod tests;`
  is already done. No inline test block to migrate.
- The "useful CoS state" gate (#1183 fix at f0e364d7) — preserved
  exactly. Its rationale comment (lines 696..743) moves verbatim
  with `build_cos_state` to `cos.rs`.
- `nat_translated_local_exclusions` and
  `install_kernel_rst_suppression` already live in `rst.rs` as
  `pub(super)` helpers. Stays put.
- `parse_policy_state_with_counters` lives in `crate::policy`.
  Stays put.
- Sibling refactors in flight on the wave-2 backlog
  (#1325/#1326/#1327/#1328/#1345 etc.) use the same `mod.rs` slim
  + per-entity sibling-file layout — this is the codified pattern.

## Concrete design

### Directory shape

```
userspace-dp/src/afxdp/forwarding_build/
├── mod.rs    // orchestrator: build_forwarding_state{,_with_*}, small
│             //   helpers (build_screen_profiles,
│             //   parse_syn_cookie_master_key), test mod include
├── zones.rs        // populate_zones(snapshot, state)
├── tunnels.rs      // populate_tunnel_endpoints(snapshot, state)
├── interfaces.rs   // populate_interfaces + populate_egress(...) +
│                   //   pick_interface_v4/_v6
├── fib.rs          // populate_routes + populate_neighbors +
│                   //   populate_fabrics + resolve_route_target_v4/_v6 +
│                   //   parse_route_next_hop{,_v6} + resolve_ifindex +
│                   //   infer_connected_route_target_v4/_v6
└── cos.rs          // build_cos_state + build_cos_dscp_queue_table +
                    //   build_cos_ieee8021_queue_table +
                    //   default_cos_burst_bytes +
                    //   cos_scheduler_buffer_bytes +
                    //   cos_percent_buffer_bytes +
                    //   cos_surplus_weight + cos_priority_rank
```

### Visibility

Every helper currently `pub(super)` (visible to `afxdp::mod`) stays
`pub(super)` so re-exports via `use self::forwarding_build::*;`
in `afxdp/mod.rs` continue to work unchanged. Helpers that the
orchestrator calls but external callers don't reach become
`pub(super)` inside the new dir module (still re-exported one level
up via `pub(super) use` in `forwarding_build/mod.rs`).

Free functions that don't need cross-module visibility (e.g.
`parse_syn_cookie_master_key` only called from
`build_forwarding_state_with_policy_counters_and_previous`) move
alongside their caller. They stay private to the new sub-module.

### Orchestrator shape (after split)

```rust
// forwarding_build/mod.rs (sketch — final code follows the existing
// control-flow ordering exactly)

pub(super) fn build_forwarding_state(snapshot: &ConfigSnapshot)
    -> ForwardingState
{
    build_forwarding_state_with_policy_counters(snapshot,
        &PolicyCounterStore::default())
}

pub(super) fn build_forwarding_state_with_policy_counters(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
) -> ForwardingState {
    build_forwarding_state_with_policy_counters_and_previous(
        snapshot, policy_counters, None)
}

pub(super) fn build_forwarding_state_with_policy_counters_and_previous(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
    previous: Option<&ForwardingState>,
) -> ForwardingState {
    let mut state = ForwardingState::default();
    let (excluded_local_v4, excluded_local_v6) =
        nat_translated_local_exclusions(snapshot);

    zones::populate_zones(snapshot, &mut state);
    tunnels::populate_tunnel_endpoints(snapshot, &mut state);

    let iface_ctx = interfaces::populate_interfaces(
        snapshot,
        &mut state,
        &excluded_local_v4,
        &excluded_local_v6,
    );
    interfaces::populate_egress(snapshot, &mut state, &iface_ctx);

    fib::sort_connected(&mut state);
    fib::populate_routes(snapshot, &mut state, &iface_ctx);
    fib::populate_neighbors(snapshot, &mut state);
    fib::populate_fabrics(snapshot, &mut state, &iface_ctx);

    state.policy = parse_policy_state_with_counters(
        &snapshot.default_policy,
        &snapshot.policies,
        &state.zone_name_to_id,
        policy_counters,
    );
    // flow / NAT / screen / MSS / filter / CoS / flow-export / mirror
    // (same lines as today — pure attach-only, kept inline because
    //  each is a single struct-field assignment).
    ...
    state.cos = cos::build_cos_state(snapshot);
    ...
    install_kernel_rst_suppression(&state);
    state
}
```

### Typed context for the interfaces → fib data flow

`build_forwarding_state` builds three local `BTreeMap`s
(`name_to_ifindex`, `linux_to_ifindex`, `mac_by_ifindex`) during
the interfaces walk, then reuses them for the egress walk, the
routes walk, and the fabrics walk. Currently they are local
variables passed by reference into helpers via 4-7 positional
arguments. To stay under the 8-param cap and keep call sites
readable, introduce a small `IfaceIndex` context struct in
`interfaces.rs`:

```rust
pub(super) struct IfaceIndex {
    pub name_to_ifindex: BTreeMap<String, i32>,
    pub linux_to_ifindex: BTreeMap<String, i32>,
    pub mac_by_ifindex: BTreeMap<i32, [u8; 6]>,
}
```

`populate_interfaces` returns this; the egress / route / fabric
walks borrow it. Zero new allocations — the maps already exist in
the current code as locals.

### `cos.rs` internal shape

`build_cos_state` is itself ~300 LOC and could split further into
`build_cos_classifier_tables`, `build_cos_iface_queues`, and the
`useful_cos_state` gate. **Out of scope for v1.** The win from
moving the whole function into `cos.rs` (so `mod.rs` becomes a
slim orchestrator) is already the primary deliverable. Further
internal decomposition stays for a follow-up issue if the new
file is still tier-1-hot.

If review pressure says "split cos.rs too", the natural cleavage
is:
- `build_cos_classifier_tables(cos)` — class_to_queue,
  dscp_classifiers, ieee8021_classifiers, dscp_rewrite_rules
- `build_cos_iface(...)` — the per-interface loop body with the
  gate
- `build_cos_state(snapshot)` — the orchestrator

I will accept that as a v1 deliverable if reviewers insist; the
plan's preference is to defer.

## Public API preservation

All `pub(super)` symbols re-exported via
`use self::forwarding_build::*;` in `afxdp/mod.rs` keep their
existing names and signatures. The complete list (from
`grep -n "pub(super)" forwarding_build.rs`):

- `build_screen_profiles`
- `build_forwarding_state`
- `build_forwarding_state_with_policy_counters`
- `build_forwarding_state_with_policy_counters_and_previous`
- `pick_interface_v4`
- `pick_interface_v6`
- `resolve_route_target_v4`
- `resolve_route_target_v6`
- `parse_route_next_hop`
- `parse_route_next_hop_v6`
- `resolve_ifindex`
- `infer_connected_route_target_v4`
- `infer_connected_route_target_v6`

`build_cos_state` is currently private to the file but referenced
by the test module via `super::*;` — keep it `pub(super)` to
preserve test imports.

The test module include (`#[cfg(test)] #[path =
"forwarding_build_tests.rs"] mod tests;`) moves into
`forwarding_build/mod.rs`. The test file itself stays at
`afxdp/forwarding_build_tests.rs` (or moves to
`afxdp/forwarding_build/tests.rs` — see Open Q1).

## Hidden invariants the change must preserve

1. **Side-effect ordering.** `build_forwarding_state` runs:
   zones → tunnels → interfaces (addresses pass) → interfaces
   (egress pass) → sort connected → routes → sort routes →
   neighbors → fabrics → policy → flow knobs → NAT tables →
   screens → MSS → filter → CoS → flow-export → mirror →
   static-NAT local-delivery → DNAT local-delivery → install RST
   suppression. The orchestrator must preserve this order — `cos`
   depends on `filter_state` being populated (for the
   `has_cos_interfaces || filter_state.has_*` gate downstream), and
   the static-NAT/DNAT local-delivery passes write back into
   `state.local_v4` / `state.local_v6` AFTER all other writers.
2. **`mac_by_ifindex` carry.** The interfaces (egress) pass and the
   fabrics pass both read `mac_by_ifindex` populated by the
   interfaces (addresses) pass. Must remain available across all
   three.
3. **`tunnel_endpoint_by_ifindex` carry.** Populated by the tunnels
   pass; read by the interfaces (addresses) pass for
   `ConnectedRouteV4/V6.tunnel_endpoint_id`. Order matters.
4. **`zone_name_to_id` carry.** Populated by the zones pass; read
   by interfaces (addresses), interfaces (egress), and
   parse_policy_state_with_counters.
5. **Allocations on the config-apply path.** This is control plane,
   but a re-build per commit. The current code allocates the three
   `BTreeMap`s as locals; the `IfaceIndex` struct preserves that
   exactly (move, not clone). No new `Vec`/`String`/`HashMap`
   allocations.
6. **`useful_cos_state` gate semantics.** The interface-by-interface
   gate at `build_cos_state` lines 856..864 must be preserved bit
   for bit. Its rationale is the #1183 cross-binding-redirect
   regression. The code-motion must not alter the gate logic, the
   ordering of the five inputs, or the early-`continue`.
7. **`debug-log` cfg-feature block.** The `#[cfg(feature =
   "debug-log")]` block at the end of `build_forwarding_state`
   stays attached to the orchestrator, not pushed into sub-modules.
8. **`#[cold]` annotation policy.** None of these are hot paths,
   so `#[cold]` is not appropriate here.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioural regression | LOW | Pure code motion. Tests cover all builders. |
| Lifetime / borrow-checker | LOW-MED | `IfaceIndex` is a moved struct (no shared borrows across mutations). The current code uses three local maps; moving them into a struct is mechanical. |
| Performance regression | LOW | Config-apply path only. The `IfaceIndex` struct field accesses are the same MOV/LEA the compiler emits for the existing locals. |
| Architectural mismatch (#946-Phase-2 / #961) | LOW | This isn't a pipeline / data-structure change — it's file-layout. The decomposition lines up cleanly with `ForwardingState` field groups (zones, tunnels, interfaces/egress, FIB, CoS). |

## Test plan

- `cargo build --release` clean (no warnings introduced).
- `cargo test --release` — full suite passes. The
  `forwarding_build_tests.rs` file references `build_cos_state`,
  `build_forwarding_state`, `default_cos_burst_bytes`,
  `parse_syn_cookie_master_key` via `super::*` — these must remain
  callable from the test module's location.
- 5/5 flake check on
  `build_forwarding_state_prefers_logical_unit_for_ingress_lookup`
  (touches the interfaces pass).
- 5/5 flake check on
  `build_cos_state_translates_scheduler_map_entries` (touches the
  cos pass).
- Go suite `go test ./...` — no changes there but run for parity.
- **Refactor batch — no per-PR smoke per the wave-2 mandate.**
  Post `<!-- AWAITING-BATCH-MERGE -->` marker after 4-of-4
  attestation. Smoke is batched at the wave end.

## Out of scope (explicitly)

- Further internal decomposition of `cos.rs` (build_cos_classifier_tables /
  build_cos_iface / orchestrator split). Tracked separately if
  cos.rs ends up >300 LOC after this PR.
- Any change to the gate semantics from #1183.
- Any change to `nat_translated_local_exclusions` or
  `install_kernel_rst_suppression` (live in `rst.rs`, untouched).
- Any change to `parse_policy_state_with_counters` (lives in
  `crate::policy`).
- Renaming the public functions or changing signatures.
- Moving the test file. Stays at the path it's at.

## Open questions for adversarial review

1. **Test file path.** Keep `afxdp/forwarding_build_tests.rs` with
   the existing `#[path = ...]` include relocated into
   `forwarding_build/mod.rs`, or move the file to
   `afxdp/forwarding_build/tests.rs` and drop the explicit `#[path]`?
   The wave-2 colocation convention (per
   feedback_refactor_module_dir_layout) favours the in-dir path —
   confirm or reject. **Tentative answer**: move into the dir as
   `forwarding_build/tests.rs` to match the convention; the include
   becomes `#[cfg(test)] mod tests;` (no `#[path]`). PLAN-KILL if
   this is wrong.

2. **`IfaceIndex` worth it?** The current call sites pass 2-3
   `BTreeMap`s by reference. Three named-borrow params is under the
   8-param cap. Is the struct overkill? Counter-argument: the
   route walker also reads `state` and writes to it, pushing the
   shadow param count back up. The struct keeps the orchestrator
   readable.

3. **Order-sensitivity of the move.** Did I miss any field on
   `ForwardingState` that's read by an *earlier* sub-builder than
   the one that writes it? (e.g. `state.cos.interfaces.is_empty()`
   feeds `tx_selection_enabled_v[46]` AFTER filter_state — chain
   already correct, but the orchestrator's call-order has to be
   verified line-by-line.)

4. **Scope-creep guard.** Is `cos.rs` at ~300 LOC after the move
   too big to leave un-split? Or is the v1 "move whole function as
   a unit" the right increment? My read: leave it for a follow-up
   because the win from extracting to a sibling file is already
   the primary deliverable, and an internal cos split adds risk
   without clear payoff.

5. **Layout-convention check.** Wave-2 says `mod.rs` + siblings,
   NOT `forwarding_build_zones.rs` flat. Confirm the
   directory-module form is the correct target here vs the
   alternative.

6. **`build_screen_profiles` placement.** It's a small builder
   (~30 LOC) currently in `forwarding_build.rs`. Move it to a new
   `screens.rs` sibling for symmetry, or leave it in `mod.rs`
   since it's tiny and used only by the orchestrator? Tentative:
   leave in `mod.rs`. If reviewers want symmetry, split.

7. **`parse_syn_cookie_master_key` placement.** Same question.
   Tentative: leave in `mod.rs` (it's parser glue, not a real
   builder). If reviewers want symmetry, move to a new
   `syn_cookie.rs`.

## Methodology rounds

- Round 1: this draft. Codex + AGY parallel adversarial review.
- Round N+1: address findings, re-dispatch until both reviewers
  PLAN-READY (or PLAN-NEEDS-MINOR with minors addressed in
  implementation).
- Implement → 4-of-4 code review (Codex + AGY + Copilot + Claude
  SMR).
- Post `<!-- AWAITING-BATCH-MERGE -->` marker. Smoke batched at
  end of wave-2.

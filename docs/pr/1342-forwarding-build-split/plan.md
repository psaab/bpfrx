# #1342 — Split `forwarding_build.rs` by entity kind (plan v1)

Status: v2 — addresses Codex r1 PLAN-NEEDS-MAJOR + AGY r1
PLAN-NEEDS-MINOR. Pending r2 adversarial review.

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

### Visibility (revised after Codex r1 finding #1)

`pub(super) use foo::bar` of a `pub(super) bar` item triggers
**E0364** — see `userspace-dp/src/afxdp/tx/mod.rs:38-41` for the
documented precedent (`drain.rs` reaches `enqueue_prepared_into_cos`
through `use super::*;` precisely because of this).

Correct visibility rules for this PR:

| Symbol class | Where it lives | Visibility | How `afxdp/mod.rs` reaches it |
|---|---|---|---|
| Helpers re-exported via `use self::forwarding_build::*;` in `afxdp/mod.rs` (today `pub(super)`) | sibling file (e.g. `fib.rs`) | `pub(in crate::afxdp)` | Through a `pub(in crate::afxdp) use` line in `forwarding_build/mod.rs` |
| Helpers called only inside the orchestrator (`build_cos_state`, sub-builders, gate evaluation) | sibling file (e.g. `cos.rs`) | `pub(super)` in the sibling | `use cos::{build_cos_state, ...};` (plain private `use`, NOT a `pub use`) in `forwarding_build/mod.rs` |
| Helpers only used inside their own sibling file | sibling file | private (`fn`) | Not exported |
| Tiny orchestrator-local helpers (`build_screen_profiles`, `parse_syn_cookie_master_key`) | `forwarding_build/mod.rs` itself | `pub(super)` if external use, else private | Reached via `use self::forwarding_build::*;` for `pub(super)` items |

Explicit list of items moved that **must** be `pub(in crate::afxdp)`
in their new sibling (these are reached by sibling modules of
`forwarding_build` through `use self::forwarding_build::*;` in
`afxdp/mod.rs`):

- `pick_interface_v4`, `pick_interface_v6` (in `interfaces.rs`)
- `resolve_route_target_v4`, `resolve_route_target_v6` (in `fib.rs`)
- `parse_route_next_hop`, `parse_route_next_hop_v6` (in `fib.rs`)
- `resolve_ifindex` (in `fib.rs`)
- `infer_connected_route_target_v4`,
  `infer_connected_route_target_v6` (in `fib.rs`)

`forwarding_build/mod.rs` then writes:

```rust
mod zones;
mod tunnels;
mod interfaces;
mod fib;
mod cos;

#[cfg(test)]
mod tests;

// Re-exports for cross-afxdp-sibling consumers reached via
// `use self::forwarding_build::*;` in afxdp/mod.rs.
pub(in crate::afxdp) use interfaces::{pick_interface_v4, pick_interface_v6};
pub(in crate::afxdp) use fib::{
    infer_connected_route_target_v4, infer_connected_route_target_v6,
    parse_route_next_hop, parse_route_next_hop_v6,
    resolve_ifindex,
    resolve_route_target_v4, resolve_route_target_v6,
};

// Plain (private) `use` for orchestrator-local symbols. NOT a
// `pub(super) use` of a `pub(super)` item — that triggers E0364.
use cos::build_cos_state;
use interfaces::IfaceIndex;
```

`build_cos_state` is brought in via private `use`, NOT made
`pub(super)`. This preserves its current "module-private,
test-reachable via `super::*`" surface. (Codex r1 finding #3.)

Free functions that don't need cross-module visibility (e.g.
`parse_syn_cookie_master_key`) stay in `forwarding_build/mod.rs`
alongside their caller. They stay private to the file.

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
    // (Codex r1 finding #2) explicit sort step preserves the
    // forwarding_build.rs:345-350 sort-after-populate ordering.
    fib::sort_routes(&mut state);
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

### `cos.rs` internal shape (revised after AGY r1 finding #6 + Codex r1 finding #5)

Both r1 reviewers correctly pushed back on deferring the internal
cos decomposition. AGY: "Moving this 312-LOC function intact into
cos.rs sweeps the god-function violation under the rug rather than
resolving it." Codex: "Either split it now or explicitly track it
as follow-up."

**v2 decision: split `build_cos_state` internally inside `cos.rs`.**

Three sub-100-LOC helpers (modulo the inevitable comment block on
the gate):

1. **`build_cos_classifier_tables(cos) -> ClassifierTables`** —
   class_to_queue (forwarding_classes → queue u8),
   dscp_classifiers (name → CoSDSCPClassifierConfig),
   ieee8021_classifiers (name → CoSIEEE8021ClassifierConfig),
   dscp_rewrite_rules (name → CoSDSCPRewriteRuleConfig),
   schedulers / scheduler_maps name-keyed lookup maps. Returns a
   plain struct `ClassifierTables { class_to_queue, dscp_classifiers,
   ieee8021_classifiers, dscp_rewrite_rules, schedulers,
   scheduler_maps }` owned by the orchestrator.

2. **`build_cos_iface_config(iface, &ClassifierTables) ->
   Option<CoSInterfaceConfig>`** — per-interface loop body. Returns
   `Some(config)` if the `useful_cos_state` gate admits the
   interface, `None` if not. Internally:
   - Resolves scheduler-map queues into `Vec<CoSQueueConfig>`.
   - Computes `iface_queue_ids`, `iface_classes`.
   - Evaluates the 5-input gate (early `return None`).
   - Builds the synthetic best-effort fallback if `queues.is_empty()`.
   - Sorts queues by `queue_id`.
   - Builds `queue_by_forwarding_class` map.
   - Selects `default_queue`.
   - Constructs the `CoSInterfaceConfig`.
   - **Returns**. The orchestrator does the `state.interfaces.insert`.

   This contains the #1183 fix. **The gate evaluation happens
   inside `build_cos_iface_config` immediately after queue
   resolution and BEFORE the synthetic best-effort fallback.** (AGY
   r1 finding #5.)

3. **`build_cos_state(snapshot) -> CoSState`** — orchestrator. Slim:

   ```rust
   pub(super) fn build_cos_state(snapshot: &ConfigSnapshot)
       -> CoSState
   {
       let Some(cos) = snapshot.class_of_service.as_ref() else {
           return CoSState::default();
       };
       let tables = build_cos_classifier_tables(cos);
       let mut state = CoSState::default();
       for iface in &snapshot.interfaces {
           if iface.ifindex <= 0 { continue; }
           if let Some(cfg) =
               build_cos_iface_config(iface, &tables)
           {
               state.interfaces.insert(iface.ifindex, cfg);
           }
       }
       state.dscp_classifiers = tables.dscp_classifiers;
       state.ieee8021_classifiers = tables.ieee8021_classifiers;
       state.dscp_rewrite_rules = tables.dscp_rewrite_rules;
       state
   }
   ```

   Under 30 LOC. The whole orchestrator's structure is now visible
   at a glance, and the per-iface logic + the #1183 gate are
   isolated in `build_cos_iface_config` where they can be reasoned
   about independently.

`ClassifierTables` is a private struct inside `cos.rs`. Lifetime
is straightforward: the orchestrator owns `tables`, the helper
borrows `&tables` and `iface`. `schedulers` and `scheduler_maps`
inside `tables` borrow from `cos` via `&CoSSchedulerSnapshot`
references — same as today's locals. The struct holds those
references explicitly:

```rust
struct ClassifierTables<'a> {
    class_to_queue: FastMap<String, u8>,
    dscp_classifiers: FastMap<String, CoSDSCPClassifierConfig>,
    ieee8021_classifiers: FastMap<String, CoSIEEE8021ClassifierConfig>,
    dscp_rewrite_rules: FastMap<String, CoSDSCPRewriteRuleConfig>,
    schedulers: FastMap<String, &'a CoSSchedulerSnapshot>,
    scheduler_maps: FastMap<String, &'a CoSSchedulerMapSnapshot>,
}
```

The lifetime `'a` ties the struct to the `cos:
&ClassOfServiceSnapshot` borrow. No new allocations beyond what
the current code already makes (same four owned maps, plus two
borrow-only maps that exist today too — the current code spells
them inline as `cos.schedulers.iter()...collect::<FastMap<_, &_>>()`).

## Public API preservation (revised after Codex r1 finding #3)

All `pub(super)` symbols re-exported via
`use self::forwarding_build::*;` in `afxdp/mod.rs` keep their
existing external visibility unchanged. The complete list and
required `forwarding_build/mod.rs` re-export visibility:

| Symbol | Today | After PR | Re-export in mod.rs |
|---|---|---|---|
| `build_screen_profiles` | `pub(super)` in `forwarding_build.rs` | `pub(super)` in `mod.rs` (stays) | n/a, lives in mod.rs |
| `build_forwarding_state` | `pub(super)` | `pub(super)` in mod.rs | n/a, lives in mod.rs |
| `build_forwarding_state_with_policy_counters` | `pub(super)` | `pub(super)` in mod.rs | n/a |
| `build_forwarding_state_with_policy_counters_and_previous` | `pub(super)` | `pub(super)` in mod.rs | n/a |
| `pick_interface_v4` | `pub(super)` | `pub(in crate::afxdp)` in `interfaces.rs` | `pub(in crate::afxdp) use interfaces::pick_interface_v4;` |
| `pick_interface_v6` | `pub(super)` | `pub(in crate::afxdp)` in `interfaces.rs` | `pub(in crate::afxdp) use interfaces::pick_interface_v6;` |
| `resolve_route_target_v4` | `pub(super)` | `pub(in crate::afxdp)` in `fib.rs` | `pub(in crate::afxdp) use fib::resolve_route_target_v4;` |
| `resolve_route_target_v6` | `pub(super)` | `pub(in crate::afxdp)` in `fib.rs` | `pub(in crate::afxdp) use fib::resolve_route_target_v6;` |
| `parse_route_next_hop` | `pub(super)` | `pub(in crate::afxdp)` in `fib.rs` | `pub(in crate::afxdp) use fib::parse_route_next_hop;` |
| `parse_route_next_hop_v6` | `pub(super)` | `pub(in crate::afxdp)` in `fib.rs` | `pub(in crate::afxdp) use fib::parse_route_next_hop_v6;` |
| `resolve_ifindex` | `pub(super)` | `pub(in crate::afxdp)` in `fib.rs` | `pub(in crate::afxdp) use fib::resolve_ifindex;` |
| `infer_connected_route_target_v4` | `pub(super)` | `pub(in crate::afxdp)` in `fib.rs` | `pub(in crate::afxdp) use fib::infer_connected_route_target_v4;` |
| `infer_connected_route_target_v6` | `pub(super)` | `pub(in crate::afxdp)` in `fib.rs` | `pub(in crate::afxdp) use fib::infer_connected_route_target_v6;` |
| `build_cos_state` | **private** (file-local) | `pub(super)` in `cos.rs` | **plain `use cos::build_cos_state;`** — NOT `pub use`. Test module reaches it via `super::*` from `forwarding_build/tests.rs` because `use` brings it into scope of `forwarding_build/mod.rs`. |

`build_cos_state` widening was a v1 mistake (Codex r1 #3). v2
keeps it module-private to `forwarding_build/mod.rs` exactly as
today: not exported beyond that module, but reachable from
`tests.rs` via the parent's namespace.

**Test file relocation.** The test file moves from
`afxdp/forwarding_build_tests.rs` to
`afxdp/forwarding_build/tests.rs`. The include in
`forwarding_build/mod.rs` becomes:

```rust
#[cfg(test)]
mod tests;
```

(no `#[path]` attribute). This matches the wave-2 colocation
convention (`session_glue/tests.rs`, `forwarding/tests.rs`,
`umem/tests.rs`, `frame/tests.rs`, `wg/tests.rs` precedents, all
verified by AGY r1).

## Hidden invariants the change must preserve

1. **Side-effect ordering.** `build_forwarding_state` runs (line
   refs are forwarding_build.rs):
   - zones (106-137) → tunnels (139-175) → interfaces addresses
     (177-254) → interfaces egress (256-299) → sort connected
     (301-306) → routes (308-344) → sort routes (345-350) →
     neighbors (352-365) → fabrics (366-395) → policy (396-401) →
     flow knobs / NAT tables / screens / MSS / filter (402-432) →
     **CoS (433)** → tx_selection_v[46] derivation (434-450) →
     flow_export (452-462) → mirror (463-474) → **static-NAT
     local-delivery (476-487)** → **DNAT local-delivery (489-500)**
     → debug-log block (502-583) → install RST suppression (593).
   - The orchestrator MUST preserve this order. Three load-bearing
     ordering rules:
     - **`state.cos` must populate before `tx_selection_v[46]`** is
       computed (433 vs 434-450). The boolean derivation reads
       `state.cos.interfaces.is_empty()`.
     - **`state.static_nat` / `state.dnat_table` must populate
       before static-NAT/DNAT local-delivery** (413-414 vs
       476-500). The local-delivery passes call
       `state.static_nat.external_ips()` and
       `state.dnat_table.destination_ips()`.
     - **`state.local_v4` / `state.local_v6` writes split into
       early (interfaces 232/244) and late (static-NAT 478-486,
       DNAT 491-499) phases.** AGY r1 finding #2 flagged the risk
       that a developer might move the late phases into
       `interfaces.rs` "because they touch local_v[46]" — this
       would empty NAT tables before insertion and silently break
       inbound NAT delivery. **The static-NAT and DNAT local-
       delivery loops MUST stay inside `forwarding_build/mod.rs`
       at the late position. They are explicitly NOT moved to a
       sibling file.**
2. **`mac_by_ifindex` carry.** The interfaces (egress) pass and the
   fabrics pass both read `mac_by_ifindex` populated by the
   interfaces (addresses) pass. Held by `IfaceIndex`.
3. **`tunnel_endpoint_by_ifindex` carry.** Populated on `state` by
   the tunnels pass; read by the interfaces (addresses) pass for
   `ConnectedRouteV4/V6.tunnel_endpoint_id`. Lives on `state`, not
   `IfaceIndex` — already correct.
4. **`zone_name_to_id` carry.** Populated on `state` by the zones
   pass; read by interfaces (addresses), interfaces (egress), and
   `parse_policy_state_with_counters`. Lives on `state`.
5. **Allocations on the config-apply path.** This is control plane,
   but a re-build per commit. The current code allocates the three
   `BTreeMap`s as locals; the `IfaceIndex` struct preserves that
   exactly (move, not clone). No new `Vec`/`String`/`HashMap`
   allocations. `ClassifierTables<'a>` in `cos.rs` mirrors the same
   pattern (owned maps + borrow-only schedulers/scheduler_maps).
6. **`useful_cos_state` gate semantics.** The interface-by-interface
   gate at `build_cos_state` lines 856..864 must be preserved bit
   for bit. Its rationale is the #1183 cross-binding-redirect
   regression that caused ~10x reverse-throughput collapse. The
   code-motion must not alter the gate logic, the ordering of the
   five inputs, or the early-`continue`.
   - **Gate ordering invariant** (AGY r1 finding #5): the gate
     consumes `scheduler_map_resolved_to_queues`,
     `iface_queue_ids`, `iface_classes`, and reads
     `dscp_classifier`/`ieee8021_classifier`/`dscp_rewrite_rule`
     from the classifier tables. ALL of these must be computed
     INSIDE the per-iface helper BEFORE the gate runs, and the
     gate runs BEFORE the synthetic best-effort fallback. The
     v2 helper layout (`build_cos_iface_config`) encodes this
     ordering as straight-line code: resolve queues → compute
     iface_queue_ids/iface_classes → gate → fallback → finalize.
7. **`debug-log` cfg-feature block.** The `#[cfg(feature =
   "debug-log")]` block at the end of `build_forwarding_state`
   (lines 502-583) stays attached to the orchestrator in
   `forwarding_build/mod.rs`, NOT pushed into sub-modules. The
   block reads `state.policy`, `state.local_v4`,
   `state.interface_nat_v4`, etc., which only exist on the fully-
   assembled `state`.
8. **`install_kernel_rst_suppression` placement.** Final call (line
   593) before `state` is returned. Stays at the end of
   `forwarding_build/mod.rs`. Lives in `rst.rs` already; the
   orchestrator's call site moves to mod.rs but the implementation
   does not change.
9. **`#[cold]` annotation policy.** None of these are hot paths,
   so `#[cold]` is not appropriate here. Per CLAUDE.md wave-2 rule:
   "`#[cold]` on rare paths" — but config-apply runs ON commit,
   which is rare per-process but not "rare path" in the per-tick
   sense. Skip `#[cold]`. (Will reject if a reviewer requests it.)

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

- Any change to the gate semantics from #1183 (preserved bit-for-bit).
- Any change to `nat_translated_local_exclusions` or
  `install_kernel_rst_suppression` (live in `rst.rs`, untouched).
- Any change to `parse_policy_state_with_counters` (lives in
  `crate::policy`).
- Renaming the public functions or changing signatures.
- Splitting `build_forwarding_state` orchestrator further beyond
  the per-entity helper calls. The orchestrator stays linear and
  readable as a checklist.

**Brought INTO scope after r1 review:**
- Internal split of `build_cos_state` into
  `build_cos_classifier_tables` + `build_cos_iface_config` +
  orchestrator (AGY r1 finding #6, Codex r1 finding #5).
- Relocation of `forwarding_build_tests.rs` to
  `forwarding_build/tests.rs` (Codex r1 finding #4, AGY r1
  finding #7).

## Open questions for adversarial review (v2)

r1 closed Q1, Q4, Q5, Q6, Q7 of the v1 list. Remaining and new:

1. **`IfaceIndex` worth it after CoS internal split?** Three named
   borrow params is still under the 8-param cap. But because
   `populate_interfaces` now returns an `IfaceIndex` and three
   passes consume it, the struct is clearly worth it (avoids
   re-computing the maps; the maps are needed by every downstream
   pass). Tentative: keep as planned.

2. **`ClassifierTables<'a>` lifetime annotation drag.** The struct
   needs a lifetime parameter for the `&'a CoSSchedulerSnapshot`
   borrows of `schedulers` / `scheduler_maps`. If a reviewer
   prefers the borrow-eliminated form (clone the snapshots into
   the table) the cost is two extra `clone()` calls per scheduler-
   map / scheduler entry on config-apply. **Tentative**: keep the
   lifetime to match current code exactly (it already builds
   borrow-only tables today). Reject the suggestion to clone
   unless a reviewer cites a concrete compile/maintenance benefit.

3. **`build_screen_profiles` final placement.** v1 left it in
   `mod.rs`. r1 both reviewers accepted that — leaving in mod.rs.

4. **`parse_syn_cookie_master_key` final placement.** v1 left it
   in `mod.rs`. r1 both reviewers accepted that — leaving.

5. **Is there a hidden field on `ForwardingState` that a sub-
   builder writes which another sub-builder reads *before* it
   exists?** Walk the orchestrator one more time. Risk area:
   `tx_selection_enabled_v[46]` reads `state.cos`,
   `state.filter_state`. `state.cos = build_cos_state(snapshot)`
   at line 433. `state.filter_state = parse_filter_state_with_*`
   at 424-432. tx_selection block at 435-450 reads BOTH. So
   filter MUST run before cos, AND cos MUST run before tx_selection.
   Current order: filter (424-432) → cos (433) → tx_selection
   (435-450). Plan preserves this. ✓

6. **Wave-2 module dir convention crosscheck.** AGY r1 cited
   `session_glue/`, `wg/`, `frame/`, `forwarding/`, `umem/`. Codex
   r1 cited `server/handlers/mod.rs`, #1325 `protocol/mod.rs`,
   #1327 `poll_descriptor/mod.rs`, #1328 `coordinator/reconcile/`.
   All wave-2. Layout is the right target.

## Methodology rounds

- Round 1: this draft. Codex + AGY parallel adversarial review.
- Round N+1: address findings, re-dispatch until both reviewers
  PLAN-READY (or PLAN-NEEDS-MINOR with minors addressed in
  implementation).
- Implement → 4-of-4 code review (Codex + AGY + Copilot + Claude
  SMR).
- Post `<!-- AWAITING-BATCH-MERGE -->` marker. Smoke batched at
  end of wave-2.

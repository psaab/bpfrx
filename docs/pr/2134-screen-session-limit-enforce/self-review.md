# Claude SMR self-review — #2134 screen session-limit enforcement

Scope: wire the per-IP screen session-limit lifecycle into the userspace
dataplane so `limit-session source-ip-based <n>` / `destination-ip-based
<n>` actually enforces, and make the count read non-mutating (closing
#2128 by construction). One PR, `userspace-dp` only — no Go, no eBPF.
Implements the converged r3 plan
(`docs/research/2128-2134-screen-session-limit/plan.md`, Path B).

## What was broken

`SessionLimitTracker::check_src`/`check_dst` compared a per-IP count
against the configured limit, but **nothing in production ever
incremented that count** — `session_created`/`session_expired` were
called only from screen tests. The production count was always 0, so
`0 >= limit` was always false: the (limit+1)-th session was never
rejected. An operator who configured `limit-session` got zero
protection. (#2159 had already made the read path read-only, fixing the
phantom-zero leak surface; this PR wires the actual enforcement.)

## Design (Path B)

The count moves OUT of `ScreenState` and INTO `SessionTable`, because the
count must track the real session lifecycle and `SessionTable` is the
choke point every create/remove already passes through.

- **Increment** at the fresh-install choke point
  (`install_with_protocol_with_origin`, next to the Open-delta push) and
  the in-place HA promote (`update_session` promote branch).
- **Decrement** at the sole removal sink (`remove_entry` success path —
  covers expire / clear / RST / fabric-cancel / take_synced_local) and
  the in-place HA demote (`demote_owner_rg`, before the origin flip).
- All four sites share the counted-class predicate `!is_reverse &&
  !origin.is_peer_synced() && !origin.is_transient_local_seed()` — the
  same predicate that gates the HA Open delta.
- Evict-on-zero (`saturating_sub` then remove at 0) keeps the maps
  bounded by distinct IPs with ≥1 live counted session — the #2128 fix.
- **Check** relocated to the new-flow / session-MISS decision in
  `poll_descriptor` (`new_flow_session_limit_drop`), NOT the per-packet
  screen stage. This is the r2 BLOCKER fix: the screen stage runs on
  every data packet before the session lookup, so a `count >= limit`
  check there would self-drop an established flow at the limit boundary.
  The new-flow check fires once per new flow, before its session exists,
  via a non-mutating query, and emits the `session-limit-{src,dst}`
  screen-drop event + counter.
- **OFF-gate + clear-on-disable**: `set_session_limit_active` driven from
  the applied screen-profile snapshot (startup + runtime reload). OFF =
  zero maintenance cost. ON→OFF clears the maps so a re-enable can't
  resume from stale over-counted values (reviewer-B r2 MAJOR).

## Hot-path shape

- Feature OFF (~99% of deployments): one `bool` branch in
  `session_limit_inc`/`_dec` short-circuits — no map ops on install /
  remove. The new-flow check short-circuits on the per-zone profile map
  probe + `session_limit_{src,dst} > 0`.
- Feature ON, per new install/remove: two `FxHashMap` upserts/removes
  (src + dst), same cost class as the Open-delta push already on that
  path. No new lock (`SessionTable` is single-worker-owned).
- Per new flow (check): two `FxHashMap::get`s. Cold path — session miss
  only, never per data packet.
- No allocation on the steady-state hot path. `saturating_add`/`_sub`
  (branchless, never wraps) per the overflow policy.

## Counter-factual test strength

Every load-bearing test FAILS if its mechanism is reverted:

- `new_flow_session_limit_drop` under/at/over-limit (poll_descriptor
  tests) — FAILS if the check returns a never-drop no-op (the #2134 bug).
- `session_limit_count_increments_on_forward_install_src_and_dst` —
  FAILS if the install-site increment is removed (count stays 0).
- `session_limit_count_unchanged_by_established_flow_packets` — drives
  200 rounds of session-HIT lookups/touches over n live flows; FAILS if
  the count is maintained per-packet or the check is left in the screen
  stage (the r2 BLOCKER regression).
- `session_limit_decrements_and_evicts_on_expire` / `..._on_explicit_delete`
  — FAIL if the `remove_entry` decrement is removed; assert evict-at-0
  (#2128).
- `session_limit_ha_import_promote_demote_count` — FAILS if either
  in-place HA increment/decrement is omitted; asserts SyncImport does NOT
  count locally.
- `session_limit_excludes_reverse_and_seed_installs` — predicate guard.
- `session_limit_idempotent_reinstall_nets_to_one` — pre-clear
  self-cancel.
- `session_limit_counts_match_live_counted_entries_invariant` — the
  strongest guard: after install/expire/delete/promote/demote/refresh,
  the per-IP count EQUALS the live counted-entry count (iterated via
  `iter_with_origin`), and map sizes equal the distinct counted-IP sets.
  Catches any missed transition site.
- `session_limit_clear_on_disable` — FAILS if clear-on-disable is
  omitted.
- `session_limit_off_gate_skips_all_maintenance` — OFF = zero cost.
- `read_only_check_never_creates_phantom_entry` — 1000 over-limit checks
  for a never-installing IP leave the maps empty (#2128).

The obsolete `ScreenState`-resident session-limit tests (which manually
called the now-retired `session_created`/`session_expired` — exactly the
no-op the issue named) were removed. The one cookie test that proved
"a validated SYN still runs later screen checks" via the session-limit
drop was rewritten to prove the same property via the port-scan check
(still in the screen stage).

## Residual / accepted

- Per-worker scoping (worst-case N×limit dilution when one IP spreads
  across N RX queues) — pre-existing, same under the eBPF per-CPU map.
- OFF→ON re-enable does not back-count pre-existing live sessions —
  benign, Junos-approximate (documented in `session/README.md`).
- Global per-IP (not per-zone-per-IP) — matches Junos per-IP counting.

## Validation

- `cargo build --release` clean (baseline 140 warnings, no new ones).
- `cargo test --release` — full suite green (see PR test plan).
- Live screen/flood smoke on the loss userspace cluster (per-reason
  enforcement + RSS-stability under distinct-IP spray + established-flow
  line-rate + `make test-failover`) is run centrally by the parent —
  PENDING-PARENT at PR-open time.

## Files

- `session/mod.rs` — count maps + OFF-gate flag on `SessionTable`;
  `set_session_limit_active` (clear-on-disable); `session_limit_inc/dec`;
  non-mutating `session_limit_{src,dst}_count`; decrement in
  `remove_entry`; increment in `update_session` promote branch.
- `session/install.rs` — increment in `install_with_protocol_with_origin`;
  decrement in `demote_owner_rg`.
- `screen/mod.rs` — removed the per-packet session-limit sub-check; added
  `any_session_limit_configured`; retired the dead
  `session_created`/`session_expired` wrappers + `SessionLimitTracker`
  field; deleted `screen/session_limit.rs`.
- `afxdp/poll_descriptor/mod.rs` — `new_flow_session_limit_drop` + the
  new-flow check on the miss path (dominates both LocalMiss + ForwardFlow
  installs) + unit tests.
- `afxdp/worker/loop_body/{setup.rs,mod.rs}` — drive the OFF-gate at
  startup + runtime reload.
- `session/tests.rs`, `afxdp/poll_descriptor/mod.rs` tests, `screen/tests.rs`.
- Docs: `session/README.md`, `docs/feature-gaps.md`.

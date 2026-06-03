# #1752 Path E — session refresh in-place mutation

**Status: DRAFT v1 — pending adversarial plan review (Codex + Gemini)**

Implements Path E from the converged research plan
(`docs/research/1752-cpu-headroom/plan.md`, PLAN-READY @ 0fdda93f0): eliminate
the per-packet `remove_entry`+`restore_entry` index teardown/rebuild in
`SessionTable::update_session` (the established-flow refresh path), replacing it
with in-place `get_mut` slab mutation that touches secondary indices only when a
key-relevant input actually changes.

## 1. Issue framing

`update_session` (session/mod.rs:803) is the unified refresh path
(`refresh_local`, `promote_synced_with_origin`, `refresh_for_ha_activation` all
route through it). For **every packet of an established flow** it currently:
`remove_entry(key)` → mutate ~7 fields → `restore_entry(key, entry)`. That tears
down and rebuilds the full index set (`key_to_handle` map remove+insert, slab
remove+insert with a *new* handle, `nat_reverse_index`/`forward_wire_index`/
`reverse_translated_index`/`owner_rg_sessions` value-guarded remove+re-add) plus
~3 `SessionMetadata` clones — just to bump `last_seen_ns`/`expires_after_ns`.

Live `-P48 5210` flat profile (#1752): `remove_entry` 2.73% + slab `insert`
1.72% self ≈ **~4.5% of total CPU**, all of it index churn on flows whose
key/NAT-mapping/owner-RG never change.

## 2. Why in-place is correct (the index-input invariant)

The four secondary indices are derived **only** from
`(key, decision.nat, metadata.is_reverse, metadata.owner_rg_id)`:
- `index_forward_nat_key` (:1204) and `remove_forward_nat_index` (:1240) compute
  their keys from `key` + `decision.nat` (via `translated_session_key`,
  `reverse_wire_key`, `reverse_canonical_key`, `forward_wire_key`), branch on
  `metadata.is_reverse`, and add to `owner_rg_sessions` iff
  `metadata.owner_rg_id > 0`.
- `key_to_handle` is keyed on `key`.

In `update_session` **`key` is invariant** (it is the lookup key) and, with
in-place mutation, **the slab handle is invariant** (no insert → no new handle).
Therefore the index entries are unchanged **unless** `decision.nat`,
`metadata.is_reverse`, or `metadata.owner_rg_id` differs between the stored entry
and the incoming update. On the steady-state refresh path all three are
identical → **zero index operations**.

## 3. Honest scope/value framing

Target ~4.5% CPU on the saturated 6/6 cluster — directly recoverable, isolated
to one function, no architectural premise. Secondary win: removes ~3
`SessionMetadata` clones per refresh and the per-call `no_index_points_at` debug
scan. *If reviewers conclude the perf gain is too small to justify the churn, or
that the in-place reindex predicate cannot be made provably complete, PLAN-KILL
is an acceptable verdict.*

## 4. What's already shipped

#964 Step 1 introduced the slab + `key_to_handle` + handle-valued secondary
indices and the `remove_entry`/`restore_entry` pair (kept "for API compatibility
with the prior FxHashMap shape" — restore_entry doc comment). This plan replaces
the remove+restore *inside refresh paths only*; install/synced-upsert/GC paths
keep remove_entry (they legitimately change identity or remove).

## 5. Concrete design

New private helper `refresh_in_place` + rewrite `update_session` to use it.

```
pub fn update_session(&mut self, req: SessionUpdate<'_>, ha_activation: bool) -> bool {
    let SessionUpdate { key, decision, metadata, origin, now_ns, protocol, tcp_flags } = req;
    let Some(&handle) = self.key_to_handle.get(key) else { return false };

    // Snapshot the index-relevant + collision-relevant OLD state (all Copy
    // except we avoid cloning metadata on the hot path).
    let (old_origin, old_nat, old_is_reverse, old_owner_rg) = {
        let r = &self.entries[handle as usize];
        (r.entry.origin, r.entry.decision.nat, r.entry.metadata.is_reverse,
         r.entry.metadata.owner_rg_id)
    };

    // Collision rules — IDENTICAL to current semantics, but reject is now a
    // pure early return (no remove+restore round-trip).
    if !ha_activation {
        let new_peer = origin.is_peer_synced();
        if old_origin.is_peer_synced() && !new_peer { /* promote: allow */ }
        else if old_origin.is_peer_synced() && new_peer { return false; }
        else if !old_origin.is_peer_synced() && new_peer { return false; }
        // both local: allow
    }

    // Reindex predicate — complete per §2 (key + handle invariant).
    let reindex = old_nat != decision.nat
        || old_is_reverse != metadata.is_reverse
        || old_owner_rg != metadata.owner_rg_id;

    if reindex {
        // Tear down OLD secondary indices (value-guarded; key + handle same).
        // Need an old-metadata shim carrying is_reverse + owner_rg_id; build a
        // minimal one or pass fields. (impl detail: small owned snapshot.)
        self.remove_forward_nat_index(key, handle, old_decision, &old_md_shim);
        remove_owner_rg_index_entry(&mut self.owner_rg_sessions, old_owner_rg, handle);
    }

    let epoch = self.next_epoch();
    {
        let r = &mut self.entries[handle as usize];   // get_mut, scoped
        r.entry.decision = decision;
        r.entry.metadata = metadata.clone();           // single clone (parity)
        r.entry.origin = origin;
        r.entry.install_epoch = epoch;
        r.entry.last_seen_ns = now_ns;
        r.entry.expires_after_ns = session_timeout_ns(protocol, tcp_flags, &self.timeouts);
        r.entry.closing = matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN|TCP_RST)) != 0;
    }
    if reindex {
        self.index_forward_nat_key(key, handle, decision, &metadata);
    }

    self.push_to_wheel(key, now_ns);
    if old_origin.is_peer_synced() && !origin.is_peer_synced() && !metadata.is_reverse {
        self.push_delta(SessionDelta { kind: Open, key: key.clone(), decision, metadata, origin, fabric_redirect_sync: false });
    }
    true
}
```

Borrow shape: `next_epoch`/`remove_*`/`index_*`/`push_*` all take `&mut self`;
the `get_mut` borrow is scoped to the field-write block so it never overlaps
them. The old-decision/old-metadata snapshot for the reindex-teardown is taken
*before* the field write (impl: capture `old_decision` = `r.entry.decision` and
an owned `SessionMetadata` shim with old `is_reverse`/`owner_rg_id` in the
snapshot block; only built when `reindex` is true to keep the hot path
clone-free).

`refresh_for_ha_transition` (:918) gets the same treatment (it also removes +
restores, no collision rules, never changes nat/owner_rg in practice but apply
the same reindex predicate for safety).

## 6. Public API preservation

No public signature changes. `update_session`, `refresh_local`,
`refresh_for_ha_activation`, `refresh_for_ha_transition`,
`promote_synced_with_origin` keep identical signatures + return semantics.
`remove_entry`/`restore_entry` stay (still used by install/upsert/GC/lookup).

## 7. Hidden invariants the change must preserve

1. **Collision semantics**: the 4 branches (ha_activation; peer→local promote;
   peer→peer reject; local←peer reject; local→local refresh) must behave
   identically. In-place makes reject a no-op early return — observably
   identical to remove+restore-then-return-false (net state unchanged).
2. **Index completeness**: reindex predicate must catch every case where a
   secondary-index key changes. Proven by §2 (indices depend only on key+nat+
   is_reverse+owner_rg; key & handle invariant). **This is the #1 review target.**
3. **Wheel**: `push_to_wheel(key, now_ns)` unchanged; entry's `wheel_tick`
   field is preserved across in-place mutation (we do NOT reset it to 0, unlike
   install which sets wheel_tick:0). Current remove+restore preserves wheel_tick
   too (restore_entry keeps the passed entry's wheel_tick). Parity holds.
4. **Open-delta emission**: identical condition (was_peer_synced &&
   !new_peer && !is_reverse).
5. **install_epoch** bumped via next_epoch() — identical.
6. **No stale handle**: handle stays valid (never freed); on reject we never
   touched it.
7. **HA paths**: refresh_for_ha_activation/transition go through the same code;
   owner_rg reindex on a genuine owner_rg change (RG failover re-resolve) must
   still move the handle between owner_rg sets — covered by the reindex branch.

## 8. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression | MED | collision + reindex semantics must match exactly; differential test gates it |
| Lifetime / borrow-checker | LOW-MED | get_mut borrow scoped away from &mut self index calls; snapshot-before-mutate |
| Performance regression | LOW | strictly fewer ops; worst case (reindex every time) equals today |
| Architectural mismatch | LOW | localized to refresh paths; install/GC unchanged |

## 9. Test plan

- `cargo build` + full `cargo test --release` (1763+ lib tests) clean.
- **Differential test (new, the gate)**: for each branch (local refresh, peer→
  local promote, peer→peer reject, local←peer reject, ha_activation, nat change,
  owner_rg change, is_reverse entry), assert the in-place result is
  byte-identical (entry fields + all four index maps + key_to_handle + deltas) to
  the old remove+restore implementation. Implement by keeping a reference
  remove+restore helper in the test module and comparing table snapshots.
- 5×flake on the differential test + the heaviest existing session test.
- Go suite (30 pkgs).
- Smoke matrix on loss userspace cluster: Pass A (CoS off) v4+v6 push+`-R` +
  `-P12 -R` line-rate; Pass B per-class 5201-5206 v4+v6 push+`-R`.
- Perf re-profile `-P48 5210`: confirm `remove_entry`/slab `insert` self-time
  drops and aggregate Gb/s rises (CoS-off and CoS-on).
- `make test-failover` (touches session-sync/HA refresh paths — required by
  CLAUDE.md for any HA-adjacent change).

## 10. Out of scope

- Path A (CoS hot-path reduction), Path B (crypto DEK trace), Path C/D — separate.
- `install_with_protocol_with_origin` / `upsert_synced_with_origin` keep
  remove_entry (they change identity / may replace a different session; in-place
  there is a measurable but smaller win — deferred, noted as a follow-up).
- GC / `lookup_and_remove` / terminal paths — unchanged.

## 11. Open questions for adversarial review

1. Is the reindex predicate (`old_nat != nat || old_is_reverse != is_reverse ||
   old_owner_rg != owner_rg`) provably complete, or is there an index whose key
   depends on a field not in that set? (Walk `index_forward_nat_key` +
   `remove_forward_nat_index` + the `*_key` helpers and try to break it.)
2. Does making "reject" a pure early return (vs remove+restore-then-false) change
   any observable state or side effect? (e.g. does today's reject path mutate
   wheel/epoch/deltas? It does not — restore_entry re-adds verbatim and returns
   false. Confirm.)
3. Borrow-checker: can the old-metadata teardown snapshot + the scoped get_mut +
   the &mut self index calls coexist without a clone on the no-reindex hot path?
4. HA owner_rg transition: when `refresh_for_ha_activation` re-resolves a session
   whose owner_rg_id changed, does the reindex branch correctly move the handle
   between `owner_rg_sessions` sets (remove old set entry, add new)? 
5. `wheel_tick` preservation: in-place keeps the existing `wheel_tick`; is there
   any path where remove+restore's behavior (also preserves it) differs such
   that parity breaks?
6. Is the differential-test strategy (reference remove+restore impl in tests +
   full table-snapshot compare) sufficient to catch a divergence, or is a
   property/fuzz test over random update sequences needed?

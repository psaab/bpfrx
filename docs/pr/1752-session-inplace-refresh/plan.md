# #1752 Path E — session refresh in-place mutation

**Status: v3 — folds Codex r2 (PLAN-NEEDS-MAJOR, reject-path re-assert) + Gemini r2 (PLAN-READY). Re-dispatched for r3.**

v2 changes: (a) secondary-index **adds are always re-asserted** (matches today's
unconditional `index_forward_nat_key` insert exactly, incl. the
collision-displacement re-win case Codex flagged) — only the value-guarded
*removes* are gated on `reindex`; (b) restore the stale-handle + primary-key
guard (`entries.get` + `record.key == *key`, return false) that v1's pseudocode
dropped; (c) private index helpers take `NatDecision`/`is_reverse`/owner fields
directly (no metadata shim); (d) expanded differential + collision + randomized
test plan; (e) honest value revised to ~3–3.5% (re-assert retained).

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

Target **~3–3.5% CPU** on the saturated 6/6 cluster (revised down from a naive
~4.5%: v2 retains the 4 secondary-index re-assert inserts for exact-parity, so
the win is the eliminated slab remove+insert (the measured 1.72% `insert` + the
slab part of `remove_entry`'s 2.73%), the `key_to_handle` remove+insert, 2 of 3
`SessionMetadata` clones, the value-guarded *removes* on the hot path, and the
`no_index_points_at` debug scan). Isolated to one function, no architectural
premise. *If reviewers conclude the perf gain is too small to justify the churn,
or that the in-place change cannot preserve secondary-index semantics exactly,
PLAN-KILL is an acceptable verdict.* (Full skip of the re-assert inserts — the
remaining ~1% — is an explicit out-of-scope follow-up gated on a proven
secondary-key uniqueness invariant + property test; see §10/§11.)

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

    // STALE-HANDLE + PRIMARY-KEY GUARD (parity with remove_entry:1127/1144 and
    // record_by_key_mut:314): never index the slab raw — a stale key_to_handle
    // could point at a vacant or reused slot.
    let Some(record) = self.entries.get(handle as usize) else { return false };
    if record.key != *key { return false; }

    // Snapshot OLD index-relevant + collision-relevant state (all Copy).
    let old_origin = record.entry.origin;
    let old_nat = record.entry.decision.nat;
    let old_is_reverse = record.entry.metadata.is_reverse;
    let old_owner_rg = record.entry.metadata.owner_rg_id;
    // (immutable borrow of `record` ends here)

    // Collision rules — IDENTICAL to current semantics. NOTE (Codex r2): today's
    // reject path does remove_entry THEN restore_entry THEN returns false, and
    // restore_entry's unconditional index_forward_nat_key RE-ASSERTS this entry's
    // own secondary ADDS even on reject. To stay byte-identical, the reject
    // branches must re-assert too (parts-based, zero-clone) before returning.
    if !ha_activation {
        let new_peer = origin.is_peer_synced();
        let reject = (old_origin.is_peer_synced() && new_peer)      // peer→peer
                  || (!old_origin.is_peer_synced() && new_peer);     // local←peer
        if reject {
            // Re-assert OLD secondary ADDS (entry unchanged), then bail — matches
            // restore_entry's re-assert on the current reject path exactly.
            self.index_forward_nat_key_parts(key, handle, old_nat, old_is_reverse, old_owner_rg);
            return false;
        }
        // else: peer→local promote, or local→local refresh: fall through to accept.
    }

    // Reindex predicate — complete per §2 (key + handle invariant). Gates only
    // the value-guarded REMOVES of the OLD secondary keys.
    let reindex = old_nat != decision.nat
        || old_is_reverse != metadata.is_reverse
        || old_owner_rg != metadata.owner_rg_id;

    if reindex {
        // Tear down OLD secondary keys. Helpers take the OLD nat/is_reverse/
        // owner fields directly (no metadata shim, no clone).
        self.remove_forward_nat_index_parts(key, handle, old_nat, old_is_reverse);
        remove_owner_rg_index_entry(&mut self.owner_rg_sessions, old_owner_rg, handle);
    }

    let epoch = self.next_epoch();
    {
        let r = self.entries.get_mut(handle as usize).expect("handle validated above");
        r.entry.decision = decision;
        r.entry.metadata = metadata.clone();           // single clone (parity)
        r.entry.origin = origin;
        r.entry.install_epoch = epoch;
        r.entry.last_seen_ns = now_ns;
        r.entry.expires_after_ns = session_timeout_ns(protocol, tcp_flags, &self.timeouts);
        r.entry.closing = matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN|TCP_RST)) != 0;
        // entry.wheel_tick deliberately preserved (parity with restore_entry).
    }

    // ALWAYS re-assert the secondary ADDS — byte-identical to today's
    // unconditional index_forward_nat_key insert in restore_entry. For the
    // no-reindex case the keys are unchanged so this re-inserts key→same handle
    // (idempotent when unique; re-wins when a collision displaced us — exactly
    // today's behavior). For the reindex case it installs the NEW keys after the
    // removes above. This is what preserves the unconditional-insert /
    // value-guarded-remove collision semantics Codex flagged.
    self.index_forward_nat_key(key, handle, decision, &metadata);

    self.push_to_wheel(key, now_ns);
    if old_origin.is_peer_synced() && !origin.is_peer_synced() && !metadata.is_reverse {
        self.push_delta(SessionDelta { kind: Open, key: key.clone(), decision, metadata, origin, fabric_redirect_sync: false });
    }
    true
}
```

Borrow shape (confirmed feasible by both reviewers): the immutable `get`
snapshot drops before any `&mut self` call; `next_epoch`/`remove_*`/`index_*`/
`push_*` take `&mut self`; the `get_mut` borrow is scoped to the field-write
block. Zero clones on the hot path beyond the single mandatory
`metadata.clone()` into the entry. **Impl note:** add a private
`remove_forward_nat_index_parts(key, handle, nat, is_reverse)` (the existing
`remove_forward_nat_index` re-derived these from a `&SessionMetadata`; the new
variant takes the parts so the reindex teardown needs no old-metadata shim).
`refresh_for_ha_transition` (:918) gets the identical treatment.

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
2. **Index semantics (v3)**: secondary ADDS are always re-asserted (parity with
   today's unconditional `index_forward_nat_key` in `restore_entry`) on BOTH the
   accept path AND the reject path (Codex r2: today's reject = remove+restore+
   false, and restore re-asserts). A new private `index_forward_nat_key_parts(key,
   handle, nat, is_reverse, owner_rg)` re-asserts from Copy parts (zero clone) on
   the reject path; the accept path uses the full `index_forward_nat_key` with the
   new metadata in hand. The `reindex` predicate gates only the value-guarded
   REMOVES of the OLD keys; it is complete per §2 (indices depend only on
   key+nat+is_reverse+owner_rg; key & handle invariant). **#1 review target.**
2b. **Stale-handle / primary-key guard**: `entries.get(handle)` + `record.key ==
   *key` before any mutation; mismatch → return false (no-op), matching
   `remove_entry`'s release-mode guards. Never `entries[handle]` (panic/corrupt).
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
- **Differential test (new, the gate)**: keep a reference remove+restore helper
  in the test module; assert the in-place result is byte-identical (entry fields
  + all four index maps + `key_to_handle` + `owner_rg_sessions` + deltas + wheel
  state) to the reference across ALL of:
  - local refresh, peer→local promote, peer→peer reject, local←peer reject,
    ha_activation refresh;
  - `reindex` triggers: NAT mapping change, owner_rg `0→>0`, `>0→0`, `>0→>0'`,
    is_reverse toggle, NAT64 / NPTv6 decisions;
  - **secondary-index collision** (Codex Major #1): two live sessions whose
    derived secondary key collides — refresh one, assert the in-place table
    matches the reference (the re-assert re-wins identically);
  - **reject-path collision re-assert** (Codex r2): a displaced-collision session
    hit with a REJECTED update (peer→peer AND local←peer) must re-win its
    secondary key identically to today's remove+restore-then-false;
  - **stale/wrong-key guard**: stale `key_to_handle` → vacant slot, and reused
    slot holding a different `record.key` → both return false, no mutation;
  - `refresh_for_ha_transition` liveness parity;
  - a bounded **randomized update-sequence** property test (random installs +
    refreshes + promotes + owner_rg flips) comparing in-place vs reference table
    snapshots each step.
- 5×flake on the differential + randomized tests + the heaviest existing
  session test.
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
- **Full skip of the secondary re-assert inserts** (the remaining ~1%):
  deferred follow-up, gated on a *proven* secondary-key uniqueness invariant
  across all live sessions (incl. the transient NAT-port-reuse / not-yet-GC'd
  window) + a property test. v2 keeps the re-assert for exact parity.

## 11. Open questions for adversarial review

**r1 resolutions (v2):** Q1 predicate completeness — confirmed by both reviewers
(indices depend only on key+nat+is_reverse+owner_rg; key & handle invariant);
**but** Codex's deeper point (unconditional-insert collision re-assert) is now
handled by always re-asserting the ADDS, so v2 no longer depends on a uniqueness
proof. Q2 reject-early-return net-neutral — confirmed by both. Q3 borrow/zero-clone
hot path — confirmed feasible. Q4 owner_rg transition — works via reindex branch;
added owner_rg `0↔>0`/`>0→>0'` + ha_transition tests. Q5 wheel_tick parity —
confirmed. Q6 differential sufficiency — added collision + stale-handle +
randomized property tests (Codex wanted them; cheap insurance). **r2 resolution (v3):** Gemini r2 PLAN-READY. Codex r2 NEEDS-MAJOR — accepted-
path re-assert was correct but the REJECT branches returned before re-asserting,
diverging from today's restore-on-reject. v3 re-asserts on reject via
`index_forward_nat_key_parts` and adds reject-path collision tests. Remaining:

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

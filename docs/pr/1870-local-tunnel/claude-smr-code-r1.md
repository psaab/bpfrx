# Claude SMR hostile code review — PR #1877 (#1870), round 1

**Reviewer:** Claude (domain SMR: session tables, HA replication, Rust)
**Head:** `f21255768` (3 commits over origin/master `9a536f810`)
**Stance:** hostile-verify against the converged plan
(`research/1870-local-tunnel-pair` plan v5) and the code itself.

## Worked trace 1 — the exact at-cap UpsertLocal interleaving through the fixed arm

Preconditions: worker table at `max_sessions` (`len() == cap`), local TUN
endpoint active, tunnel resolution `ForwardCandidate`.

1. TUN read → `build_local_origin_tunnel_tx_request` → plan with
   `session_entry` (origin `SyncImport`, `NatDecision::default()`) and
   synthesized reverse (`is_reverse`, `SyncImport`).
2. `maybe_enqueue_local_tunnel_session`: per-key window check passes →
   `publish_shared_session` ×2 (shared maps + owner-RG indexes hold both) →
   `UpsertLocal(forward)`, `UpsertLocal(reverse)` pushed to every worker
   queue → 1 ms drain wait.
3. Worker tick, `apply_worker_commands` pops `UpsertLocal(forward)`:
   - `debug_assert!(entry.origin.is_peer_synced())` — true (`SyncImport`),
     and it executes BEFORE the field-by-field move of `entry` into
     `SessionInstall` (no use-after-move; release builds compile both
     asserts out).
   - `upsert_synced_with_origin(…, true)`: the local-clobber guard
     (`session/mod.rs:855-860`) is bypassed by the flag; `remove_entry`
     (no-op for a fresh key, replace for same-key); `next_epoch`; record
     with identical `closing`/timeout/wheel fields as the old install;
     slab insert; `key_to_handle`; `index_forward_nat_key` (owner-RG index
     yes — `owner_rg_id == 1`-style metadata; NO forward-wire alias since
     default NAT ⇒ `wire_key == key`, `session/mod.rs:1478-1481`);
     `push_to_wheel`; returns `true`. `len() == cap + 1`.
4. `UpsertLocal(reverse)`: same; `len() == cap + 2`. No `create_drops`, no
   `admission_refused`, no deltas (`upsert` path pushes none; the old
   install would also have suppressed them for peer-synced origin).
5. Drain wait returns with the prewarm actually in place; the first reply
   hits the worker table directly — no shared-mutex traversal, no
   reactive materialization needed.
6. Convergence: entries expire via the wheel like any session; peer-synced
   expiry emits no Close delta (`session/mod.rs:524` guard) — unchanged.
   `max_sessions` remains the new-flow admission bound via the #1871
   `can_admit` preflight, which this PR does not touch.

Pinned end-to-end by `upsert_local_pair_installs_at_cap` (and the cap-1 /
two-worker variants). Trace verified against the diff: PASS.

## Worked trace 2 — the HA variant

- **Standby / inactive RG:** `build_local_origin_tunnel_tx_request` errors
  unless the (HA-enforced) tunnel resolution is `ForwardCandidate`
  (`tunnel.rs:171-175`), so the producer does not run and the arm is never
  reached — except the deliberate `allow_unseeded_tunnel_local` prewarm
  window, where the entries are still locally generated and replace-local
  remains correct (no peer-vs-local arbitration exists for data this node
  authored).
- **Failover (RG demote/refresh):** `demote_owner_rg` skips already
  peer-synced entries; `RefreshOwnerRGs` re-resolves them
  origin-preserving. Identical handling to the pre-change healed end-state
  (where the reverse sat as `SharedMaterialize` — residency-equivalent,
  verified in plan rounds 2-3 by all three reviewers).
- **HA sync surfaces:** `push_delta` suppressed for `SyncImport` in BOTH
  the old and new install paths; owner-RG bulk export skips
  `is_peer_synced()` origins (`session_glue/mod.rs:439-441`) — now pinned
  non-vacuously: the entries ARE in the owner-RG index (`owner_rg_id = 1`
  via `index_forward_nat_key`), so `export_forward_sessions_for_owner_rgs`
  visits and origin-skips them; the pin would fail if either the indexing
  or the skip changed.

No HA-visible state transition differs from pre-change behavior. PASS.

## Hostile checks on the implementation details

- **Fixture collision audit:** filler keys (`src_port 40000+i`, src
  `10.0.61.102` → dst `172.16.80.200:5201`) collide with neither the
  forward key (`src_port 55068`) nor the reverse key (src/dst swapped:
  src `172.16.80.200:5201` → dst `10.0.61.102:55068` — different src IP
  entirely). PASS.
- **Producer audit for the origin assert:** the only production
  `UpsertLocal` producer is `maybe_enqueue_local_tunnel_session`
  (`tunnel.rs:329-331`), whose entries are `SyncImport` (forward,
  `tunnel.rs:202`) and the synthesized reverse (`shared_ops.rs:668`).
  No other producer exists (grep). The debug assert cannot fire today.
  PASS.
- **Plan conformance:** arm matches plan §4 Path A field-for-field (key,
  decision, metadata, origin, now_ns, protocol, tcp_flags;
  `allow_replace_local=true`; both asserts). Test 1 uses exact
  forward-key lookups, not `find_forward_wire_match`, per the plan-v4
  correction. Two-worker fan-out pin present. Tests use `assert!` on
  outcomes (AGY plan r1 finding). PASS.
- **Docs:** README list drops "UpsertLocal replica sites"; new #1870
  subsection records the family move + I11 centralization; descriptor
  help-text updated with no series/label change (`prometheus.NewDesc`
  name and label set untouched). Grep finds no remaining in-tree claim
  that UpsertLocal contributes to `create_drops`. PASS.
- **`_Log.md`:** not updated in this PR by design — it lives dirty in the
  main checkout across concurrent sessions and would conflict; the PR
  docs trail (plan + reviewer docs) is the durable record.

## Verdict

**MERGE-READY** — no findings. The change is the plan's Path A verbatim,
the seven pins cover every interleaving the five plan rounds surfaced, and
both worked traces pass through the fixed code without a behavioral
surprise.

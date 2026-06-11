# PR #1871 Claude SMR hostile code review — round 1 (head 816460efe939)

**Reviewer:** Claude (domain SMR: dataplane/session-table/NAT/observability)
**Stance:** hostile self-review against the converged plan
(`docs/research/1861-install-txn/plan.md` v4) and the source, not the
commit messages.

## Verdict: MERGE-READY

## Worked trace 1 — the exact reported interleaving (forward ok at cap-1, reverse hits max_sessions)

Pre-conditions: per-worker table `len == max_sessions - 1`; NAT'd TCP SYN,
policy permit, `track_in_userspace == true`, `install_local_reverse == true`.

1. SNAT decision allocated (pool mode reserves a tuple;
   `source_nat_release_key = Some(...)`).
2. `needed_sessions = 1 + 1 = 2` (`mod.rs`, refusal arm).
   `can_admit(2)` → `(max-1) + 2 > max` → **false**.
3. Refusal arm: `note_admission_refused()` (counter +1),
   `rollback_source_nat_allocation(..., source_nat_release_key.as_ref()
   .unwrap_or(&flow.forward_key), ...)` — byte-identical call shape to
   the pre-existing failure arm — then `scratch_recycle.push(desc.addr);
   continue;`.
4. **Nothing was committed**: no forward install (so no BPF entry, no
   `publish_shared_session`, no replica fan-out, no HA Open delta), no
   reverse attempt, no forwarding, no flow-cache entry. Table still at
   `max-1`. The pre-fix outcome (forward fully committed + reverse
   refused + one-sided session) is unconstructible: the reverse install
   is additionally gated on `forward_installed`, and the only way past
   the preflight is `len ≤ max-2`, at which point BOTH installs succeed
   (cap is the only failure mode; single-writer table; GC/worker
   commands run between poll phases — verified `worker/loop_body/mod.rs:
   495/567/631` ordering unchanged by this diff).
5. Client retransmits; once `len ≤ max-2` the pair installs and the flow
   proceeds normally. Operator sees
   `xpf_userspace_session_install_admission_refused_total` advance.

Pinned by `txn_pair_admitted_at_cap_minus_two_refused_at_cap_minus_one`
(phase 2 fails on pre-fix code: forward would install, len would reach 3).

## Worked trace 2 — HA-sync variant (peer-synced forward-only state at cap)

1. HA sync imports a forward session via `upsert_synced_with_origin`
   (deliberately uncapped — unchanged by this PR, documented I11) and
   indexes it under its reverse wire key (`index_forward_nat_key`).
   Assume the reverse companion is absent (synthesis returned None or
   the delta carried forward-only).
2. A reply arrives while the local table is at cap: BPF miss →
   userspace → `lookup_session_across_scopes` miss →
   `lookup_forward_nat_across_scopes` finds the synced forward →
   `install_reverse_session_from_forward_match` builds the reverse,
   install **fails at cap**, returns `(reverse, false)`.
3. New behavior: `created: false` (no `session_creates` over-count, no
   `publish_bpf_conntrack_entry` for a session that does not exist) and
   `install_failed: true` → `flow_cache_install_failed = true` → the
   reply IS forwarded (decision returned regardless) but its decision is
   **not** flow-cached.
4. Every subsequent reply repeats the repair attempt (slow path at cap —
   intended degradation) until the table drops below cap, at which point
   the reverse installs, BPF-publishes, shared-publishes, replicates —
   and the shim fast path resumes. Pre-fix, step 3 cached the
   sessionless decision and the repair never re-fired (standing
   one-sided `show security flow session` + embedded-ICMP blind spot).

Pinned by `txn_failed_reply_repair_forwards_uncached_then_self_heals_below_cap`
(both phases fail on pre-fix code: phase 1 via `session_creates == 0` and
cache-empty; phase 2 via `len == 2` — pre-fix the cached entry suppresses
the repair so len stays 1).

## Hostile checks performed (no findings)

1. **`needed_sessions` arithmetic per flow class**: tracked pair → 2;
   `install_local_reverse == false` (FabricRedirect, non-fabric-ingress)
   → 1 (forward-only is intended, not a failure); `dns_fastpath_admit` /
   `LocalDelivery` → `track_in_userspace == false` → 0 → preflight
   skipped, structurally untouched; NAT64 → tracked pair → 2 (pinned by
   `txn_nat64_refusal_at_cap_drops_translated_packet`).
2. **Flag scoping**: `flow_cache_install_failed` and
   `seed_install_refused` are `let mut` bindings inside the
   per-descriptor `while let` iteration — they cannot carry across
   descriptors in a batch. Assignment sites: resolved-hit propagation,
   reverse residual, seed else-arm — exhaustive.
3. **Residual arms vs #1855**: both `debug_assert!(false)` arms are
   unreachable on reachable state (cap is the only failure mode and the
   preflight excludes it within the same `&mut` scope); release
   degradation is count + drop (forward) / count + keep-committed-forward
   + cache-suppress (reverse). No assert can fire at the reachable
   refusal (counter-only arm).
4. **Descriptor lifecycle**: the refusal arms use the exact
   recycle+`continue` shape of the adjacent SNAT-failure arm
   (`record_source_nat_failure` arm) — recycle exactly once, no
   `recycle_now` double-handling.
5. **`created == installed` consumers**: the only consumer of `created`
   is the telemetry + `publish_bpf_conntrack_entry` block at
   `mod.rs:273-286` — both WANT the actual outcome (AGY research-r1 F1).
   The hit path sets `install_failed: false` explicitly.
6. **Counter plumbing field-by-field**: SessionTable accessors →
   `loop_body` writes → atomics publish/snapshot → `status.rs` literal →
   `binding.rs`/`control.rs` serde → `helpers.rs` sums → `protocol.go` →
   `pkg/api` descriptors/Describe/Collect/tests. Wire keys identical on
   both sides (`session_create_drops`, `session_install_admission_refused`,
   `session_install_partial`); fixture diff is exactly 6 additive
   zero-value keys; key-absent pins both sides.
7. **Scope vs plan**: every diff hunk maps to plan §5.1-§5.4/§7/§12; no
   unauthorized changes. Plan-required items all present, including the
   reverse-residual `install_failed` flag (plan v4 fold of Codex r2) and
   the seed gate (§5.3).
8. **Test strength**: each txn_ pin fails on pre-fix code (trace above;
   I1 via `dbg.tx == 0` + cache-empty, I6 via `pending_neigh.is_empty`,
   pool pin via cache-empty — the allocator-rollback half existed
   pre-fix and is an anchor, not the regression guard).

## Notes for other reviewers

- `scratch_forwards` is drained into the TX pipeline inside the call, so
  the pins assert on the per-call `dbg.tx` counter instead — this is a
  harness property, not a behavior change.
- The else-arm rollback at the old forward-failure site is retained but
  now only reachable for `track_in_userspace == false`; the comment
  documents the narrowed reachability. Behavior-preserving for that
  class (rollback is a no-op for the DNS fast-path, which requires no
  NAT).

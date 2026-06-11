Task b8b32547-bf70-4385-a545-320b174c1684/task-88 has completed.
Task status: completed
Task output:
...
test afxdp::session_glue::tests::purge_sessions_for_input_dscp_filter_revalidation_removes_family ... ok
test afxdp::session_glue::tests::cached_session_resolution_skips_fabric_redirect ... ok
test afxdp::session_glue::tests::maybe_promote_synced_session_skips_worker_local_import ... ok
test afxdp::session_glue::tests::resolve_flow_session_decision_promotes_stale_fabric_shared_hit_to_local_owner_path ... ok
test afxdp::session_glue::tests::lookup_forward_nat_across_scopes_returns_shared_nat_entry ... ok
test afxdp::session_glue::tests::lookup_session_across_scopes_returns_shared_forward_wire_entry ... ok
test afxdp::session_glue::tests::session_key_has_lo0_filter_matches_packet_family ... ok
test afxdp::session_glue::tests::republish_local_delivery_sessions_for_lo0_filter_selects_existing_hits ... ok
test afxdp::session_glue::tests::lookup_session_across_scopes_returns_shared_entry ... ok
test afxdp::session_glue::tests::lookup_session_across_scopes_preserves_local_synced_origin ... ok
test afxdp::session_glue::tests::lookup_session_across_scopes_preserves_local_forward_wire_synced_origin ... ok
test afxdp::session_glue::tests::lookup_session_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder ... ok
test afxdp::session_glue::tests::lookup_forward_nat_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder ... ok
test afxdp::session_glue::tests::upsert_local_at_cap_replaces_existing_local_entry_without_growth ... ok
test afxdp::session_glue::tests::upsert_local_below_cap_replaces_existing_local_entry ... ok
test afxdp::session_glue::tests::upsert_local_entries_stay_out_of_owner_rg_bulk_export ... ok
test afxdp::session_glue::tests::upsert_local_fanout_diverged_workers_converge ... ok
test afxdp::session_glue::tests::upsert_local_pair_installs_at_cap ... ok
test afxdp::session_glue::tests::upsert_local_pair_no_partial_at_cap_minus_one ... ok
test afxdp::worker_runtime_tests::tests::local_tunnel_prewarm_is_not_prevented_by_worker_max_sessions ... ok
test session::tests::upsert_synced_allow_replace_is_infallible_at_cap ... ok
test session::tests::admission_refused_and_install_partial_counters_accumulate ... ok

test result: ok. 217 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.05s

   Doc-tests userspace-dp

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
### Finding 1 (Low): Exact Alignment of `WorkerCommand::UpsertLocal` with Path A
The implementation of the `WorkerCommand::UpsertLocal` arm in [userspace-dp/src/afxdp/session_glue/mod.rs:586-597](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/mod.rs#L586-L597) matches Section 4 Path A of the converged plan exactly:
```rust
586:                 let installed = sessions.upsert_synced_with_origin(
587:                     SessionInstall {
588:                         key: entry.key,
589:                         decision: entry.decision,
590:                         metadata: entry.metadata,
591:                         origin: entry.origin,
592:                         now_ns,
593:                         protocol: entry.protocol,
594:                         tcp_flags: entry.tcp_flags,
595:                     },
596:                     /* allow_replace_local = */ true,
597:                 );
```
No fields are lost during construction. All seven fields defined in the `SessionInstall` struct at [userspace-dp/src/session/ctx.rs:31-39](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/ctx.rs#L31-L39) (`key`, `decision`, `metadata`, `origin`, `now_ns`, `protocol`, `tcp_flags`) are mapped directly from the received command payload.

### Finding 2 (Low): Below-Cap Behavioral Identity Verified
Comparing the capped install path at [userspace-dp/src/session/mod.rs:748-806](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/mod.rs#L748-L806) against the new uncapped `upsert_synced_with_origin` path at [userspace-dp/src/session/mod.rs:834-883](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/mod.rs#L834-L883) confirms they are behaviorally identical below capacity limit for `SyncImport` entries:
- Below cap, the capacity check at line `758` is bypassed.
- Passing `allow_replace_local = true` bypasses the local-clobber guard at line `850`.
- Both paths perform the exact same mutations: key removal (`remove_entry`), epoch generation, `SessionRecord`/`SessionEntry` initialization (matching closing/timeout/tick defaults), slab insertion, handle map indexing (`index_forward_nat_key`), and wheel scheduling (`push_to_wheel`).
- Because `SyncImport` returns `true` for `origin.is_peer_synced()`, both paths skip delta pushing (line `795` condition evaluates to `false`).

### Finding 3 (Low): Producer Origin Sanity Guard
All production commands for `UpsertLocal` are generated within `maybe_enqueue_local_tunnel_session` in [userspace-dp/src/afxdp/tunnel.rs:329-331](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/tunnel.rs#L329-L331). The entries are constructed in `build_local_origin_tunnel_tx_request` (lines `191` and `212`) and carry `SessionOrigin::SyncImport` (as defined in [userspace-dp/src/afxdp/tunnel.rs:202](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/tunnel.rs#L202) and [userspace-dp/src/afxdp/shared_ops.rs:668](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/shared_ops.rs#L668)). 
`SyncImport` correctly satisfies `entry.origin.is_peer_synced()`. Thus, no current producer path can violate the safety constraint and trigger the `debug_assert!` at [userspace-dp/src/afxdp/session_glue/mod.rs:580](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/mod.rs#L580) in debug builds.

### Finding 4 (Low): Robustness of Test Fixtures and Assertions
The test fixtures and assertions have been validated to ensure they are non-vacuous and enforce the contract:
- **Port Collisions:** Filler key ports generated in `rig_capped_table` start at `40_000 + i` ([userspace-dp/src/afxdp/session_glue/tests.rs:4421](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/tests.rs#L4421)) and only span `40000 - 40007`. These are disjoint from the forward key's `55068` ([userspace-dp/src/afxdp/session_glue/tests.rs:319](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/tests.rs#L319)) and the reverse key's `5201`, ensuring no false collisions occur.
- **Bulk-Export Verification:** The bulk-export exclusion test is non-vacuous because the forward entry's metadata carries `owner_rg_id: 1` and is successfully indexed under RG 1 in the session table. The only reason it is excluded from export is the explicit origin check in `export_forward_sessions_for_owner_rgs` at [userspace-dp/src/afxdp/session_glue/mod.rs:440](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/afxdp/session_glue/mod.rs#L440).
- **Assertions:** The new tests in both `session_glue/tests.rs` and `session/tests.rs` exclusively use release-effective `assert!` and `assert_eq!`. There are no `debug_assert!` macros used for test outcomes.

### Finding 5 (Low): Docs and Metric Alignment
Documentation accuracy has been corrected to reflect that `UpsertLocal` no longer contributes to `create_drops`:
- The README in [userspace-dp/src/session/README.md:95](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/userspace-dp/src/session/README.md#L95) was modified to remove `UpsertLocal` from the list of capped install sites.
- The Prometheus help-text descriptor at [pkg/api/metrics_descriptors.go:558](file:///home/ps/git/bpfrx/.claude/worktrees/1870-engineer/pkg/api/metrics_descriptors.go#L558) was updated to explicitly document that `UpsertLocal replicas moved to the uncapped sync-family install in #1870 and no longer contribute.`
- Both Go and Rust test suites pass cleanly.

***

### Verdict
MERGE-READY

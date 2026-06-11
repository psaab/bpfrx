# PR #1858 — hostile Claude SMR code review (round 1)

Reviewer: Claude (domain SMR: session-table data structures, Rust test
semantics, HA dataplane). Head reviewed: f9311e5976e9.

## Worked trace — what each test rigs and what each profile does

### Stale rig (`rig_stale_handle_table`)
Installs `key` (v4) → slab handle `h_k`, `other` (v6) → `h_o`, then sets
`key_to_handle[key] = h_o`: a stale mapping onto a LIVE, REUSED slot.

- `update_session(key)`: map lookup → `h_o`; `entries.get(h_o)` →
  `Some(record_for_other)`; `record.key != *key` → the PRIMARY-KEY arm
  (`mod.rs:869` post-PR numbering, message
  `"update_session: stale key_to_handle for {:?}"`).
  - debug: panics — `inplace_stale_handle_asserts_in_debug` expects
    `"update_session: stale key_to_handle"`, which the vacant-arm
    message (`"update_session: key_to_handle had stale handle ..."`)
    does NOT contain. Unambiguous.
  - release: the arm `return false`s IMMEDIATELY with zero mutation
    (no index re-assert happens on this arm — that only occurs on the
    later `should_reject_update` path, which is unreachable here), so
    `other.last_seen_ns` is untouched. Asserted by the release test.
- `refresh_for_ha_transition(key)` (release test extension, AGY r1):
  same lookup → `h_o` → key mismatch → its primary-key arm
  (`"refresh_for_ha_transition: stale key_to_handle"`), immediate
  `return false`, no mutation. The first failed `update_session` call
  mutated nothing, so the table state at the second call is the rig
  state — the trace above applies verbatim. `other` re-checked
  unchanged after both calls.

### Vacant rig (`rig_vacant_handle_table`)
Fresh table, `key_to_handle[key] = 9999`, slab empty.

- `update_session(key)`: lookup → 9999; `entries.get(9999)` → `None` →
  the VACANT arm (`"update_session: key_to_handle had stale handle"`).
  debug: panic (variant expected substring matches this arm only);
  release: `return false`, no state to corrupt.
- `refresh_for_ha_transition(key)`: `None` → vacant arm
  (`"refresh_for_ha_transition: stale handle"`). Substring check: NOT
  contained in the sibling message `"refresh_for_ha_transition: stale
  key_to_handle"` (no space-h-a-n-d-l-e after "stale "). Unambiguous.

Four arms, four debug variants, 1:1, each test fires exactly one panic.

## Why this is the right production posture
Release returning false on a corrupted mapping means: the refresh of an
established flow's timestamps is dropped for that packet; the session
either gets refreshed by the next packet (if the bug is transient) or
ages out via the GC wheel — degraded but safe. The alternative
(proceeding on a mismatched record) would rewrite ANOTHER session's
decision/NAT state — cross-flow corruption. The alternative (panicking
in release) would take down a per-worker dataplane thread for a state
that cannot occur absent a logic bug. Debug panicking preserves the
loud detector for tests/CI. This is byte-for-byte the `remove_entry`
#964 contract; no divergence introduced.

## Mechanical checks
- mod.rs delta: verified comments-only — `git diff origin/master...HEAD
  -- userspace-dp/src/session/mod.rs` has zero non-`//` changed lines.
  Zero production-code delta in the PR (tests.rs + README + docs).
- cfg-gating: rig helpers are used by 1 release-gated + 2 debug-gated
  tests each → no dead-code warning in either profile (confirmed: both
  full-suite builds completed warning-clean for session files).
- No `[profile.*]` override in `userspace-dp/Cargo.toml`: release has
  `debug-assertions = false`, `panic = "unwind"` default — required for
  `should_panic` (debug) and assert-compiled-out (release).
- Gates re-run by author: debug full 1856/0 (the previously-red gate),
  release full 1855/0, named tests 5×/profile (10/10 + 20/20), `go test
  ./...` green. The one release full-run flake
  (`worker_queue::concurrent_recovery_processes_each_command_exactly_once`)
  is the load flake documented in #1855 itself; standalone-green and a
  full rerun green.
- README claims audited: install/remove pairing and `no_index_points_at`
  scan match `mod.rs`; ownership wording now matches
  `afxdp/worker/loop_body/setup.rs:40` per-worker by-value ownership.

## Verdict
MERGE-READY.

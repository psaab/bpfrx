# #1638 — remove dead parallel-prefix scaffolding (BookEntry + PolicyRule)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)

## 1. Issue framing

PR #1624 (`#1609 STAGED Step 1`) and PR #1632 (`#1623 Path B narrow`)
merged STAGED "parallel-prefix" scaffolding into `userspace-dp/src/policy.rs`
to feed a future Multi-Book-LPM / JIT-DAG consumer (#1605 / #1609 / #1623).

All three consumer issues are now **CLOSED**:
- #1605 — CLOSED (`plan-kill`, `no-longer-relevant`)
- #1609 — CLOSED
- #1623 — CLOSED (`needs-work`)

No consumer shipped or will ship from this design. The scaffolding is
therefore dead, yet it still runs and allocates on every config apply and
every HA re-parse, and structurally re-introduces the exact per-rule prefix
duplication that #1606 was built to delete (`Arc<[Prefix]>` materialized per
rule per side per family = the union of the rule's literals **plus every cited
book's entire prefix list** = O(rule_count × book_size) blow-up).

This PR removes the dead in-memory scaffolding and restores the #1606
`book_count`-bounded dedup state.

## 2. Honest scope/value framing

- **Memory:** removes 4 `Option<Arc<[Prefix]>>` per `PolicyRule` + 2
  `Arc<[Prefix]>` per `BookEntry`, each materialized eagerly per rule/book
  for the lifetime of every `PolicyState`. At the #1606-targeted 10K-rule ×
  1K-book × 100K-prefix scale this is the same order of magnitude (tens of GB)
  of duplication #1606's dedup-by-construction was meant to remove. At
  realistic deployment scale (hundreds of rules) the absolute win is small but
  non-zero, and the *structural* regression (O(rule×book) duplication for data
  nothing reads) is the real defect.
- **CPU:** removes 4 `Arc<[T]>` allocations per rule + 2 per book + 2
  `Vec::clone()` per rule (the `parse_v3_literal_set_capture` clones) on every
  config apply and **every HA failover re-parse** (failover critical path).
  Not packet-hot-path.
- **Maintainability:** deletes dead scaffolding toward a plan-killed design
  whose `Clone` impl silently propagates it; future readers cannot tell it is
  dead. This is the #1622-class "scaffolding toward a dead consumer" pattern.

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (Counter-argument: this is dead-code
deletion that restores a prior invariant, not a speculative new optimization —
the churn is negative LOC, and the structural-duplication argument stands
independent of absolute byte counts.)

## 3. Grep-proven dead-ness (origin/master @ 6bdf9d73e)

### 3.1 In-memory Rust fields — the scaffolding to remove

`userspace-dp/src/policy.rs`:

- `BookEntry.prefixes_v4: Arc<[PrefixV4]>` (line 74)
- `BookEntry.prefixes_v6: Arc<[PrefixV6]>` (line 76)
- `PolicyRule.source_prefixes_v4: Option<Arc<[PrefixV4]>>` (line 182)
- `PolicyRule.source_prefixes_v6` (183)
- `PolicyRule.destination_prefixes_v4` (184)
- `PolicyRule.destination_prefixes_v6` (185)

Populated at:
- `BookEntry`: policy.rs:533-539 (`Arc::from(v4.as_slice())` per book).
- `PolicyRule`: policy.rs:624-647 via `build_rule_side_arc` (per rule per side
  per family).

### 3.2 Proof nothing reads them at runtime

`try_match_rule` (policy.rs:926-984) — the sole runtime policy-evaluation
path — matches via `source_literal_v4` + `source_book_idxs` +
`*_match_any` flags + `state.books[].v4/v6` PrefixSets. It **never** touches
any `*_prefixes_*` field. Verified by reading the entire function body
(`feedback_verify_whole_function_body`).

Whole-crate grep (`grep -rn 'prefixes_v4|prefixes_v6|source_prefixes|
destination_prefixes|build_rule_side_arc' userspace-dp/src/`):
- **Outside `policy.rs`/`policy_tests.rs`: ZERO references** to the in-memory
  scaffolding fields.
- Inside `policy.rs`: only write-sites (Default ctor, Clone impl propagation,
  the build sites above). No read-sites.
- Inside `policy_tests.rs`: two dedicated scaffolding test modules
  (BookEntry parallel-prefix tests ~lines 1015-1239, PolicyRule
  parallel-prefix tests ~1245-1870) that assert the scaffolding shape and
  nothing else. These are removed with the fields.

### 3.3 The wire protocol is NOT touched (critical distinction)

`feedback_wire_protocol_both_sides` — grepped BOTH sides:

- **Rust:** `protocol/security.rs:221-224` — `AddressBookSnapshot.prefixes_v4
  /v6: Vec<String>`.
- **Go:** `pkg/dataplane/userspace/protocol.go:93-94` — `AddressBookSnapshot.
  PrefixesV4/V6 []string`. Populated at `policies.go:258-259`.

These are the **#1606 address-book CONTENT wire fields** — the dedup'd book
prefix lists. They are **LIVE**: `security.rs:507-514` parses
`snap.prefixes_v4/v6` into `BookEntry.v4/v6` PrefixSets, which `try_match_rule`
reads on the hot path. They are NOT scaffolding and are **not removed**.

The dead scaffolding is purely the **derived in-memory** copies:
`BookEntry.prefixes_v4/v6` is a redundant `Arc<[PrefixV4]>` snapshot of the
SAME `v4`/`v6` Vec used to build the PrefixSet (a parse-time-only duplicate),
and the `PolicyRule.*_prefixes_*` arrays are per-rule unions of those.

**Conclusion: this PR makes ZERO wire-protocol change.** No
`protocol.rs`/`protocol.go` edit, no serde field touched, no version bump, no
cross-language lockstep. Old↔new compat is a non-issue because the wire schema
is byte-identical before and after.

## 4. Concrete design (pure deletion + revert-to-pre-scaffolding)

### 4.1 `BookEntry` (policy.rs)
- Drop fields `prefixes_v4`, `prefixes_v6`.
- Drop the doc paragraph (lines ~40-64) describing the parallel fields.
- In the book-build loop (policy.rs:497-544): drop the
  `let prefixes_v4 = Arc::from(...)` / `prefixes_v6` capture (533-539) and the
  two struct-literal fields. The `v4`/`v6` Vecs are then moved straight into
  `from_v3_literals(v4)` / `from_v3_literals(v6)` (no `as_slice()` capture
  before move).

### 4.2 `PolicyRule` (policy.rs)
- Drop fields `source_prefixes_v4/v6`, `destination_prefixes_v4/v6`.
- Drop the long `#1623 Path B narrow` doc block (lines ~150-181).
- `Default` impl: drop the four `*_prefixes_* : None` lines.
- `Clone` impl: drop the four `*_prefixes_*: self....clone()` lines.
- Struct literal in `parse_policy_state_with_counters` (659-684): drop the
  four field assignments. The explicit field-by-field literal (no
  `..default()` tail) introduced by #1632 is **kept** — it is a legitimate
  hardening (forces compile error on future field additions, per AGY r2 D).

### 4.3 Parse helpers (policy.rs)
- Replace `parse_v3_literal_set_capture` (returns 4-tuple incl. the captured
  `Vec<PrefixV{4,6}>`) with the pre-#1632 `parse_v3_literal_set` (returns
  `(PrefixSetV4, PrefixSetV6)`). Exact pre-scaffolding form recovered from
  `d339b69f8~1:userspace-dp/src/policy.rs:539-568`: `from_v3_literals(v4)` /
  `from_v3_literals(v6)` instead of `(v4.clone())`/`(v6.clone())`.
- In the rule-build block (555-590): revert both sides to the pre-#1632
  2-tuple form. Non-v3-shaped branch reverts `from_prefixes(v4.clone())` →
  `from_prefixes(v4)` and drops the `, v4, v6` capture tail.
- Delete `build_rule_side_arc` entirely (770-792).

### 4.4 Tests (policy_tests.rs)
- Delete the two scaffolding test modules + their `const _` size guards
  (1678-1681) + the `v3_rule_full` helper used only by those tests. Range:
  lines 1015 → EOF (1870).
- **Keep** the `book()` builder's `prefixes_v4/v6` arguments (686-687) — that
  builds the live `AddressBookSnapshot` wire field, not the dead scaffolding.
- Keep `address_book_test.go` (Go) untouched — it tests the live wire field.

## 5. Public API preservation

No public/exported API changes. `BookEntry` and `PolicyRule` are
`pub(crate)`. `parse_policy_state_with_counters` signature unchanged.
`evaluate_policy` / `try_match_rule` behavior unchanged (they never read the
removed fields). No `proto/` change. No CLI/gRPC surface change.

## 6. Hidden invariants the change must preserve

- **Side-effect ordering:** book-build loop and rule-build loop ordering
  unchanged; only the dead-array materialization is excised. `from_v3_literals`
  / `from_prefixes` / `resolve_book_idxs` / `*_match_any` computation are all
  untouched.
- **Allocation rules:** removal strictly reduces allocations (parse path only;
  not hot path). No new allocations introduced.
- **HA sync portability:** wire schema byte-identical (see §3.3) — synced
  snapshots serialize/deserialize identically; a peer on old or new code reads
  the same JSON. No HA compat hazard.
- **Borrow-checker shape:** moving `v4`/`v6` Vecs directly into
  `from_v3_literals` (instead of `.clone()` + capture) is the pre-#1632 shape
  that compiled cleanly; no new borrow.
- **Stale-handle hazard:** none — `Arc` fields are dropped, not aliased.

## 7. Risk assessment

| Risk class | Level | Rationale |
|---|---|---|
| Behavioral regression | LOW | Removed fields are never read at runtime (proven §3.2). Reverts to a state that shipped on master pre-#1624/#1632. |
| Lifetime / borrow-checker | LOW | Reverts to the pre-#1632 move-not-clone shape that already compiled. |
| Performance regression | NONE | Strictly removes parse-path allocations; no hot-path touch. |
| Architectural mismatch | NONE | This IS the de-scaffolding; the consumer architecture was already plan-killed. |
| Wire / cross-language | NONE | No wire field touched (§3.3). |

## 8. Test plan

- `cargo build --release` clean (no `dead_code` warnings for the removed items
  since they're gone).
- `cargo test --release` — full userspace-dp suite green (was 952+).
- 5/5 flake check on the most-affected surviving test
  (`policy` evaluate tests, e.g. a representative `test_policy_*` that
  exercises `try_match_rule`).
- Go suite: `go test ./...` (30 packages) — must stay green; the Go-side
  `AddressBookSnapshot.PrefixesV4/V6` is untouched, `address_book_test.go`
  continues to pass.
- **No cross-language parity run needed** — wire schema unchanged (§3.3).

## 9. Cluster / smoke

This is **pure dead-field removal with no behavior change on any admitted
path**. `evaluate_policy` / `try_match_rule` are byte-for-byte equivalent in
behavior (they never read the removed fields). The wire protocol is unchanged.

Argument: **no smoke required** — unit (Rust + Go) + parity-by-construction
(no wire change) suffice. Will request a parent batch-smoke only if a reviewer
identifies an admitted-path touch I missed. Marker:
`<!-- AWAITING-PARENT-MERGE-1638 -->` with grep-proven-dead evidence +
wire-compat note + test results.

## 10. Out of scope (explicitly)

- Any revival of Multi-Book-LPM / JIT-DAG (#1605/#1609/#1623 — closed). If
  revived, the array must be built lazily at compile time from `books[]` +
  literals, never eagerly per rule.
- Touching the live `AddressBookSnapshot` wire fields or the #1606 dedup
  machinery.
- Touching `protocol.rs` / `protocol.go`.

## 11. Open questions for adversarial review

1. **Is anything I classified as "wire content" actually scaffolding, or
   vice-versa?** I assert `AddressBookSnapshot.prefixes_v4/v6` (Rust
   security.rs + Go protocol.go) is LIVE #1606 book content and the in-memory
   `BookEntry.prefixes_v4/v6` + `PolicyRule.*_prefixes_*` are dead. Verify by
   independent grep that no read-site exists for the in-memory fields.
2. **Does `try_match_rule` truly never read the removed fields?** I read the
   whole body (926-984). Confirm no other evaluation entry point
   (`evaluate_policy`, global-rule path, fabric path) reads them.
3. **HA re-parse compat:** is there any serialized-to-disk or
   snapshot-to-peer path that persists the in-memory `PolicyRule`/`BookEntry`
   (not the wire `*Snapshot`)? If a synced/persisted blob carries these Arc
   fields, removal could break decode. I believe HA syncs the `*Snapshot` wire
   types only, not the compiled `PolicyState` — verify.
4. **Is reverting `parse_v3_literal_set_capture` → `parse_v3_literal_set`
   semantically identical?** The capture variant clones `v4`/`v6` before
   `from_v3_literals`; the revert moves them. `from_v3_literals` takes the Vec
   by value either way — confirm the clone was purely to feed the dead arrays.
5. **Should this even be done now, or is PLAN-KILL right** because the absolute
   memory/CPU win at realistic scale is tiny? Counter: it's negative-LOC
   dead-code deletion restoring a #1606 invariant, not a speculative add.
6. **Test deletion safety:** does removing `test_policy_rule_legacy_source_
   addresses_path` (and the rest of the block) drop coverage of any live
   behavior, or are all those tests purely scaffolding-shape assertions? I
   claim the legacy `source_addresses` path is independently covered by the
   evaluate-policy tests in the kept range.

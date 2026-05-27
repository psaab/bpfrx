# Claude SMR code review — round 1 (PR #1610)

**SHA reviewed**: `0018eb42e237` (initial implementation push).
**Verdict before Codex code review**: PLAN-FOLLOWS-CLEAN.
**Verdict after Codex code review**: NEEDS-MAJOR (convergent w/
Codex F1).

## Code-level concerns I audited

1. **Per-rule v3-shaped predicate** (`policy.rs` line ~423):
   `source_is_v3_shaped = !snap.source_book_ids.is_empty() || !snap.source_literals.is_empty()`. Correct, per-side, matches the
   plan v8.

2. **MatchNone variant on PrefixSetV4 / PrefixSetV6**: implemented.
   `is_match_any()`, `is_match_none()`, `contains() -> false` for
   MatchNone, new `from_v3_literals` constructor, legacy
   `from_prefixes` unchanged. All paths walked.

3. **Hard-fail integrity errors**: id=0, duplicate book IDs,
   unknown rule book references all return `SnapshotIntegrityError`
   variants. Verified.

4. **Preflight in `refresh_runtime_snapshot`**: moved to the top of
   the function before any state mutation. Uses
   `self.forwarding.zone_name_to_id` (existing, so no new
   side-effect).

5. **Flat-index hot path**: `try_match_rule` walks
   `rule.source_book_idxs.iter().any(|&i| state.books[i as usize].
   v4.contains(src))`. Zero Arc deref. Precomputed `_match_any`
   flags. Verified.

6. **HA snapshot sync**: `address_books` field travels in the
   same `ConfigSnapshot` envelope. No new lock acquisitions on the
   hot path. Verified by walking
   `worker/loop_body/mod.rs:58` (pin Arc<ForwardingState>) and
   `worker/mod.rs:976` (load_arc_if_changed).

7. **Go-side determinism**: book names iterated in lex sorted
   order (`sort.Strings(allNames)` at line ~166 of policies.go).
   Buckets sorted by `(hash64, canonical_bytes)`. Linear-probe is
   deterministic given sorted input. Verified.

## What Codex found that I missed

### Codex F1 [MAJOR]: Bare IP values dropped from book table

I implemented `expandBookNameToCIDRs` to only handle CIDR strings
and "any". Junos syntactically allows `set security address-book
global address host1 10.0.0.1` — a bare IP value. Legacy
`expandUserspacePolicyAddresses` (in manager.go) accepts bare IPs
via `net.ParseIP` and normalizes them to the string form. My new
path dropped these silently.

A rule citing a book with bare IPs becomes v3-shaped (cited a
book) → empty literal set → MatchNone → fails closed on traffic
that would have matched before.

**Fix applied**: `expandBookNameToCIDRs` now falls through to
`net.ParseIP` and emits the IP as a /32 or /128 CIDR. New test
`TestAddressBookContainingBareIPNormalizesToSlash32Or128`.

### Codex F2 [MEDIUM]: refresh_runtime_snapshot preflight pollutes counter store

The preflight call to `parse_policy_state_with_counters` passed
the live `&self.policy_counters`. If validation succeeded, those
entries would be re-inserted by the actual build that follows
(idempotent). If validation FAILED mid-build (some rules processed
before the unknown-book-id rule), the counter store retains stale
entries until the next successful reconcile purges them via
`PolicyCounterStore::reconcile_rules`.

**Fix applied**: preflight uses a scratch
`PolicyCounterStore::default()` so the live store is untouched on
failed validation.

Note: the reconcile path's "preflight" IS the actual build (single
build, with Result propagation), so the same concern there is
self-bounded: a failed build leaves transient stale entries, but
the next successful reconcile purges them via `reconcile_rules`.
This is documented as acceptable (no separate fix needed).

### Codex F3 [MINOR]: CIDR sets not deduped before content hashing

Two books with identical effective CIDR set but different multiset
content (e.g. one has a duplicate member entry from an
address-set membership cycle) would hash to different canonical
bytes and not share an ID.

**Fix applied**: `dedupSortedStrings` helper called after sorting
each family list. New test `TestAddressBookDedupsCIDRSetByContent`.

## What I'd reject in r2

- Re-introducing the bare-IP drop.
- Reverting the scratch counter store.
- Letting CIDR lists carry duplicates.

None of these are present after the fix push.

## Final verdict on the SHA after fixes

If the fix-push tests pass (1453 Rust + Go userspace pass) AND
Codex r2 confirms F1/F2/F3 cleanly resolved AND no new findings,
this should be MERGE-READY pending Copilot + smoke matrix.

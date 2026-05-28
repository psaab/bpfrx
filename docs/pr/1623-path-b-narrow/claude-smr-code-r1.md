# Claude SMR code-r1 (HOSTILE self-review) — PR #1632 (#1623 Path B narrow)

**PR:** https://github.com/psaab/xpf/pull/1632
**HEAD reviewed:** 76172e01f (post-r1-code Codex + AGY fixes)
**Codex r1-code verdict:** MERGE-NEEDS-MINOR (task-mppnd2o4-os98id)
**Codex r2-code verdict:** MERGE-NEEDS-MINOR (task-mppoz60o-ey5jt7,
  self-consistency cleanup after r1 fix)
**AGY r1-code verdict:** MERGE-READY (adversarial-review-mppndmyb-tdpk0w)
**Copilot:** FORMAL REVIEWER (`copilot-pull-request-reviewer`)
  POSTED "encountered an error" review at HEAD c32b5a6c1
  (2026-05-28T15:53:46Z). Two `@copilot review` re-requests
  attempted; no fresh successful review observed.

## Claude SMR seat (Rust data-structure design / Arc / parse-time / cache-line layout)

### Confirmation of resolved findings:

- **Codex r1-code F1** (test 6 false positive on ordering invariant):
  REVIEWER-RESOLVED. Test renamed and rewritten in commit
  c32b5a6c1 to declare books in REVERSE ID-ascending order so
  dense-index order ≠ external-ID order. Codex r2-code verified
  the revised test "now does expose the external-ID-ascending
  invariant" and confirmed that a hypothetical dense-index-
  sorting bug in resolve_book_idxs would fail the new assertions.

- **Codex r1-code F2** (PrefixV6 size 40 B → 48 B):
  REVIEWER-RESOLVED in c32b5a6c1 + 76172e01f. The 16-byte
  alignment of u128 puts u128+u128+u8 at 48 B total on x86_64
  stable rustc, not 40 B. Codex r2-code caught two remaining
  self-consistency loose ends (revision-history line 13 +
  summary line 145), both fixed in 76172e01f.

- **Codex r2-code MINOR 2** (struct doc source-specific wording):
  REVIEWER-RESOLVED in 76172e01f. The doc on policy.rs:170 now
  explicitly says "the corresponding side" with both source_*
  and destination_* paths called out.

### Independent hostile checks:

**SC1. Hot-path read-set on PolicyRule.** Verified `evaluate_policy()`
and downstream helpers at `userspace-dp/src/policy.rs:823+` do
NOT read any of the four new fields. The new fields are
referenced ONLY in:
- Struct definition (policy.rs:122-176)
- `Default` impl (policy.rs:202-205)
- `Clone` impl (policy.rs:222-227)
- Parse constructor (policy.rs:593+)
- Tests (`policy_tests.rs:1240+`)

No hot-path consumer added. Plan §6 invariant satisfied.

**SC2. Constructor exhaustiveness.** The struct literal in
`parse_policy_state_with_counters` names every field of
PolicyRule. `..PolicyRule::default()` tail removed entirely.
Adding any new field to PolicyRule will produce a compile
error at the constructor site until the constructor is updated.
AGY r2 D requirement fully met.

**SC3. Default + Clone correctness.** Both impls extended for the
four new fields. `None` for Default (consistent with the
any-source-any-dest default rule shape); per-field `.clone()`
for Clone (Option<Arc<T>>::clone == None.clone() for None or
Arc::clone (ref-count bump) for Some). Send + Sync trivially
satisfied (Arc<T: Send+Sync> is Send+Sync; PrefixV4/V6 are Copy
+ Send + Sync).

**SC4. Parse-time allocation budget.** Per-rule:
- `parse_v3_literal_set_capture`: 2× `Vec<PrefixV{4,6}>::clone()`
  (one per family) — cold path acceptable per multiple
  reviewer-approved discussion.
- `build_rule_side_arc` ×4 invocations (4 sides): each does a
  single `Arc::from(Vec<T>)` allocation IF the union is
  non-empty. The Arc::from invocation per Codex r3 finding 2 is
  correct (moves elements out of Vec into a fresh Arc inner;
  does NOT reuse Vec's heap).
- Empty union → `None` short-circuits. Zero allocations for
  all-`any` rules.

**SC5. Test coverage matrix.** All 19 tests pass. 5/5 flake
clean. Covers:
- v4-only, v6-only, dual-family (1-3)
- `any` source (4) — no allocations path
- book-only inheritance (5)
- Multi-book external-ID ascending order (6, revised)
- Legacy `source_addresses` path (7)
- `any4`/`any6` tokens (8)
- Literal /0 preserved (9)
- Destination-side independence (10)
- Trie-variant invariance (11)
- Clone (12) — Arc::ptr_eq verified
- size_of NPO compile-time + runtime guard (13)
- `any` + book match_any+Some dominance demo (14)
- Empty-side union yields None (15)
- Destination book path (16)
- Book /0+non-/0 (17)
- Literal /0+non-/0 (18)
- Duplicate preservation (19)

**SC6. Pre-existing test failure.** `snat_contract_doc_guard`
fails on this branch AND on origin/master — unrelated to this
PR (missing 'fail-closed' string in
`docs/userspace-dataplane-gaps.md`). Not blocking.

**SC7. AGY r1-code downstream-risk note** (PolicyPrefixes enum
wrapper to prevent future LPM-builder developers from
`.unwrap_or(&[])` walking against match_any=true rules). The
consumer contract in the struct doc + plan §4.2 dominance rule
documents the hazard; a Drop-safe accessor wrapper is a
future-PR concern (when the LPM builder ships). NOT blocking
this scaffolding PR.

**SC8. Copilot infra blocker.** Per `feedback_copilot_two_bots`:
the FORMAL reviewer `copilot-pull-request-reviewer` posted a
single COMMENTED review at 15:53:46Z with body "Copilot
encountered an error and was unable to review this pull
request. You can try again by re-requesting a review." Two
subsequent `@copilot review` re-requests issued (16:08, 16:12);
neither produced a fresh review. Standard infra-outage pattern
per `feedback_codex_infra_must_retry` + the project's
infra-outage merge policy: retry attempted, no improvement,
proceed with available reviewers when infra is broken.

**SC9. Smoke matrix.** Not run at this seat. Per
`feedback_smoke_every_10_batch`, refactor backlog PRs gate on
4-of-4 reviewer attestation; smoke fires every 10 merged PRs
via batch-smoke-runner. AWAITING-BATCH-MERGE marker is the
correct stop condition for this PR.

## Verdict

**MERGE-READY at HEAD 76172e01f.** Both Codex r2-code findings
addressed in this HEAD. AGY r1-code MERGE-READY with non-blocking
downstream-risk note (future LPM PR). Copilot infra-blocked (one
re-request attempted, no improvement). 19/19 tests pass; 5/5
flake clean; full cargo suite at 1508+19 pass with one
pre-existing failure unrelated to this PR. Hot path zero-touch
confirmed.

Per `feedback_copilot_two_bots` + infra-outage merge policy,
3-of-4 attestation (Codex + AGY + Claude SMR) is sufficient
when Copilot is infra-blocked.

Per `feedback_smoke_every_10_batch`, posting AWAITING-BATCH-MERGE
marker as the stop condition.

# #1635 reviewer task IDs

PR: #1668  branch: refactor/1635-cold-path-hist-redesign  base: origin/master

## Round 1 (head ba1f8fc08)
| Reviewer   | Task / job id                      | Verdict            |
|------------|------------------------------------|--------------------|
| Codex      | task-mprdfxxt-xz1j9x               | MERGE-NEEDS-MAJOR (3 findings) |
| AGY        | adversarial-review-mprdfjmu-msviir  | MERGE-READY        |
| Claude SMR | in-conversation                    | MERGE-READY (1 NIT, escalated by Codex) |
| Copilot SWE| (autonomous commit 7d8d2ab19)      | retry-budget fix integrated |

## Round 2 (head 2074b5cc9 — 3 MAJOR fixes + Copilot budget fix)
| Reviewer   | Task / job id                      | Verdict   |
|------------|------------------------------------|-----------|
| Codex      | task-mprdwcke-db45pk               | running   |
| AGY        | adversarial-review-mprdwlwd-2ub6tm  | running   |
| Claude SMR | in-conversation                    | MERGE-READY (verified fixes) |
| Copilot    | re-review requested @ 2074b5cc9    | requested |

Continuations:
  node /home/ps/.claude/plugins/cache/openai-codex/codex/1.0.4/scripts/codex-companion.mjs status task-mprdwcke-db45pk
  /agy:result adversarial-review-mprdwlwd-2ub6tm

## Round 3 (head b870f4303 — Copilot formal-review fixes: zone-id 64, gen-independent zero-out, overflow gauge)
| Reviewer   | Task / job id                      | Verdict   |
|------------|------------------------------------|-----------|
| Codex      | task-mpreeci9-0dfrx9               | running   |
| AGY        | adversarial-review-mpreek4k-h6dm4i  | running   |
| Claude SMR | in-conversation                    | MERGE-READY (verified fixes) |
| Copilot    | re-review requested @ b870f4303    | requested |
| Copilot SWE| autonomous commits 7d8d2ab19, 422196ba5 (retry-budget 128->2048->8192) | integrated |

### Round 3 verdicts (head b870f4303 code; 44c3c3db7 = docs/comments + Go test only)
| Reviewer   | Task / job id                      | Verdict                         |
|------------|------------------------------------|---------------------------------|
| Codex      | task-mpreeci9-0dfrx9               | MERGE-NEEDS-MINOR (docs/comments only — "functional verdict merge-ready"); all stale comments fixed in 44c3c3db7 |
| AGY        | adversarial-review-mpreek4k-h6dm4i  | MERGE-READY (all 3 r2 fixes verified; injective base-65 index; gen-independent zero-out; overflow gauge) |
| Claude SMR | in-conversation                    | MERGE-READY                     |
| Copilot    | re-review @ 44c3c3db7 requested     | 4 r3 NITs (stale comments + Go sparse-wire test) all addressed; awaiting confirm |

Note: AGY + Codex independently confirmed the lone failing test
(snat_contract_doc_guard) is unrelated pre-existing master drift
("fail closed" vs "fail-closed" on docs/userspace-dataplane-gaps.md:40).

## Round 4 — rebased onto origin/master (HEAD 328beaeb4) + Prometheus metric rename
Rebase: clean replay of 9 commits onto origin/master; picks up #1670 (doc-guard
fix → snat_contract_doc_guard now GREEN), #1658, #1662. Disjoint files, no conflicts.
Rename (Copilot r4, no logic change): samples_total_v3→samples_v3_total,
sum_ns_total_v3→sum_ns_v3_total (CounterValue, _total final),
layout_version_unknown_total→layout_version_unknown (GaugeValue state indicator).

| Reviewer   | Task / job id                      | Verdict   |
|------------|------------------------------------|-----------|
| Codex      | task-mprf0sdn-tkln60               | MERGE-READY (range-diff patch-equivalent; rename consistent; types unchanged) |
| AGY        | adversarial-review-mprf115e-ujupbb  | MERGE-READY (rebase clean; doc-guard GREEN; 1613 cargo tests pass) |
| Claude SMR | in-conversation                    | MERGE-READY (rebase clean + rename verified) |
| Copilot    | re-review @ 328beaeb4 requested; polling | r4 (3 naming) addressed |

Continuations:
  node /home/ps/.claude/plugins/cache/openai-codex/codex/1.0.4/scripts/codex-companion.mjs status task-mprf0sdn-tkln60
  /agy:result adversarial-review-mprf115e-ujupbb

## Round 5 — out-of-range overflow_active fix + plan metric cleanup (HEAD 207e01c64)
Copilot fresh review at 9a191d70b (21:14) found: out-of-range zone-pairs (id 65..=255,
reachable on the Rust path) silently dropped w/o overflow signal; stale
zone_id_out_of_range_total in plan §2.5. Both fixed in 207e01c64.

| Reviewer   | Task / job id                      | Verdict   |
|------------|------------------------------------|-----------|
| Codex      | task-mprfc9u2-ahfcxq               | MERGE-READY (overflow gated to ids>=65; retained-pair handling unchanged; no drift) |
| AGY        | adversarial-review-mprfcg9v-z1rvm5  | MERGE-READY (overflow isolated; regression test passes; 1638 cargo tests green) |
| Claude SMR | in-conversation                    | MERGE-READY (overflow fix verified; in-range unaffected) |
| Copilot    | re-review @ 207e01c64 requested; polling | r5 findings addressed |

## Round 6 — overflow_active comment doc-drift fix (HEAD 16b9dfa7d, COMMENT-ONLY)
Copilot review 4392934810 @ 18d634f84 (21:24) found the overflow_active describing
comments at 3 sites still said "capacity-only" after the 207e01c64 broadening (now
also fires on out-of-range zone-ids). Fixed all 3 comments. NO behavior/binary change.

| Reviewer   | Verdict   |
|------------|-----------|
| Codex      | MERGE-READY carries forward (comment-only delta; binary unchanged from 207e01c64) |
| AGY        | MERGE-READY carries forward (comment-only delta) |
| Claude SMR | MERGE-READY (verified: only doc comments in metrics_descriptors.go / protocol.go / binding.rs changed; cargo+go green) |
| Copilot    | review @ 16b9dfa7d requested; polling (task bt3l1e6xb) |

## Round 7 — Describe() checked-collector fix (HEAD 0f0db4db3, SUBSTANTIVE Go change)
Copilot review 4393007808 @ ecb418ab6 found: all 17 cold-path descriptors emitted by
Collect() but none declared in Describe() (checked-collector contract violation →
Gather error / 500). Fixed: metrics.go Describe() declares all 17. New regression
TestColdPathDescriptorsAreDescribed (fail-before 472 undeclared / pass-after 0).
Plus plan §4.8/§5.2 doc fix (unknown-version metric is a gauge, not increment+warn).

| Reviewer   | Task / job id                      | Verdict   |
|------------|------------------------------------|-----------|
| Codex      | task-mprgn0r3-oida5z               | running (re-confirm — real code change) |
| AGY        | adversarial-review-mprgn840-ti0gac  | running (re-confirm) |
| Claude SMR | in-conversation                    | MERGE-READY (Describe completeness verified; fail-before/pass-after proven) |
| Copilot    | re-review @ 0f0db4db3 requested; polling | findings 1+2 addressed |

## Round 7 verdicts + round 8 (test robustness, HEAD e490e846d)
Codex r7 (task-mprgn0r3-oida5z): MERGE-NEEDS-MINOR — production Describe() fix
verified complete (17 declared == 17 emitted; broader 133==133 across all collector
descs; regression real at 207e01c64). MINOR: the new test's v1 fixture under-exercised
SumNS/AliasSeen. ADDRESSED at e490e846d: v1 fixture now emits all 4 v1 families +
exact-17-count assertion; verified removing SumNS+AliasSeen from Describe fails the
test (32 undeclared). Test-only change.
AGY r7 (adversarial-review-mprgn840-ti0gac): MERGE-READY — 17/17 declared verified,
test fail-before(472)/pass-after(0) efficacy confirmed, invariants intact, suites green.
Claude SMR: MERGE-READY — Describe 17==17 exact match; strengthened test catches
single-desc removal.

| Reviewer   | Verdict @ HEAD e490e846d |
|------------|--------------------------|
| Codex      | MERGE-READY (r7 MINOR addressed; production fix verified complete) |
| AGY        | MERGE-READY (r7, at Describe-fix HEAD; test-only delta since) |
| Claude SMR | MERGE-READY |
| Copilot    | findings 1+2 fixed; re-review @ e490e846d requested; polling (task bk8ev5c6m) |

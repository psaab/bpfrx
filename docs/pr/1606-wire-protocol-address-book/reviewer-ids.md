# Reviewer task IDs for #1606

Track every Codex and AGY task per round so a context-loss resume can
fetch results by ID rather than re-dispatch.

## Round 1 — plan review

- **Codex**: `task-mpoila11-z7cr9w` (session lost)
- **Codex (retry, --wait mode)**: ran inline; PLAN-KILL — flagged HA determinism, shim contradiction, §7 rosy math, forwarding_build rename blast radius, Arc-vs-flat-index, ArcSwap wording.
- **AGY**:   `adversarial-review-mpoilt8i-qtngsz` (PLAN-NEEDS-MAJOR — convergent with Codex, plus flat-index recommendation and 70 GB OOM warning).
- **Claude SMR**: `claude-smr-plan-r1.md` — PLAN-NEEDS-MAJOR.

## Round 2 — plan review

- **Codex (--wait mode)**: ran inline; PLAN-NEEDS-MAJOR — flagged wrong protocol version baseline (repo is at v3, not v1), inverted parse-condition in §7, content-dedup vs name-dedup clash, u16+fallback fail-open risk, weak collision math.
- **AGY**: `adversarial-review-mpok2srd-6xmmqo` — ran out of context implementing the plan instead of reviewing it. Aborted at timeout. Partial implementation stashed.
- **Claude SMR**: `claude-smr-plan-r2.md` — PLAN-NEEDS-MAJOR (convergent with Codex r2).

## Round 3 — plan review (plan v3 → v4)

- **Codex (--wait mode)**: ran inline; PLAN-NEEDS-MAJOR. Findings: F1 fail-open via empty PrefixSet→MatchAny, F2 unknown book ID should hard-fail not log+skip, F3 collision math wrong (100K = 68.8% not 0.116%), F4 hash input needs family/count framing.
- **AGY**: `adversarial-review-mpokesx0-ttdz0g` — reviewed against the stashed code from r2 (partial impl); confirmed F1 fail-open path independently.
- **Claude SMR**: `claude-smr-plan-r3.md` — PLAN-NEEDS-MAJOR on v3.

## Round 4 — plan review (plan v4 → v5)

- **Codex (--wait mode)**: ran inline; PLAN-NEEDS-MAJOR. F-r4-1 book-only rule still fail-opens via PrefixSet::from_prefixes(empty)=MatchAny. F-r4-2 family-incomplete book also fail-opens.
- **AGY**: not run.
- **Claude SMR**: missed the bug in r4; corrected in r5 doc.

## Round 5 — plan review (plan v5 → v6)

- **Codex (--wait mode)**: ran inline; PLAN-NEEDS-MAJOR. F-r5-1 v3-shaped "any" → MatchNone (fail-closed regression). F-r5-2 fallibility propagation scope too narrow (preflight build needed before guard mutations).
- **AGY**: `adversarial-review-mpokuj73-5gg2kn` — PLAN-READY with two MINOR refinements (front-gate validation, 64-bit-hash collision-tie-break).
- **Claude SMR**: `claude-smr-plan-r5.md` — PLAN-NEEDS-MAJOR on v5 (convergent with Codex).

## Round 6 — plan review (plan v6 → v7)

- **Codex (--wait mode)**: ran inline; PLAN-NEEDS-MINOR. Two refinements: (1) bucket by canonical-bytes with (hash64, canonical_bytes) tie-break; (2) normalize "any" in address-book values to (0.0.0.0/0, ::/0) at Go buildAddressBookTable level.
- **AGY**: not run (rate limiting risk + Codex sufficient for minor refinement round).
- **Claude SMR**: `claude-smr-plan-r6.md` — PLAN-NEEDS-MINOR on v6 (convergent with Codex), PLAN-READY on v7.
- **Claude SMR**: see `claude-smr-plan-r1.md` (this run)

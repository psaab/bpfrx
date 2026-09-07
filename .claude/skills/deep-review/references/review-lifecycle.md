# Repeat-safe review intake and progress

Use this contract before selecting or researching source-review reports, including
direct `/research <report>` calls. It defines records a future processing loop can
consume; loading the skill does not start a loop, schedule or background worker.
It tracks processing of a report, not proof that its code is correct or fixed.

## Paths and selection

| Location | Role |
| --- | --- |
| `/var/tmp/deep-review-reports/` | Initial publication of source reviews and research results; only original source-review finals are automatic new-work candidates |
| `/var/tmp/deep-review-work/` | Owned run directories, checkpoints, shared indexes, locks and state |
| `/var/tmp/deep-review-finished/` | Completed originals and results, read for history/deduplication, never a new-work queue |
| Legacy `/tmp/` artifacts | Read for reconciliation; investigate as inputs only when explicitly selected or included in the caller's configured scope; never write new output here |

Exclude drafts, `report-`/`result-` derivatives and research-result artifact kinds
from new-work selection even when their names contain `-review`. Resolve a
derivative input to its original source. Scan complete source finals as well as
state: publication may have succeeded just before registration crashed. Do not
treat filename matches, title indexes or `.researched-*` markers as completion.

## One state record per source identity

Write `/var/tmp/deep-review-work/state/reviews/<review-key>.json` using the
canonical report-lock digest in [the shared contract](review-contract.md#shared-filing-coordination):
repository key plus stable original run identity, with the recorded legacy input
hash fallback. Reuse that key across names, copies, research attempts and archival;
neither the researcher nor the result filename creates a new source identity.

The version-1 JSON record has these fields:

- `schema_version`: `1`; `review_key`, `repository_key`, `original_report_identity`.
- `source`: `sha256`, `original_path`, `current_path`, `aliases` and the bound
  per-finding `origins`. This is an object; `aliases` is a path array and `origins`
  maps original finding IDs to their attribution. Paths locate data;
  identities/hashes establish it.
- `status`: `PENDING`, `IN_PROGRESS`, `BLOCKED`, `FINALIZING` or `DONE` for the
  latest attempt; `current_attempt_id` (null before the first attempt) and
  `updated_at` (UTC). A newly registered source has `attempts: []`.
- `attempts`: an array of objects with unique `attempt_id`, immutable request
  identity,
  `workflow`, `requirements` (claim scope, review gate, pinned evidence/comparison
  revisions, filing mode, requested plan and required outputs), `run_dir`,
  `owner` (host and actual task/process identities), `status`, and timestamps.
  `resume_history` preserves earlier owners/run directories on a handoff.
  Keep completed attempts frozen; update only the active attempt's checkpoints.
- Per-attempt `checkpoints`: an object keyed by claim/subclaim ID, containing
  disposition, actual reviewer
  tasks/results and covered revision, evidence locators/hashes, remaining work and
  exact next phase. Keep original claim keys and independent-review coverage.
- Per-attempt `outputs`: an array of scoped/aggregate result objects with paths,
  hashes, covered source
  keys, publication status and `archive_ledger` references. Record aggregate
  dependencies explicitly; one source result cannot complete another input.
- Per-attempt `filing`: an object with actual issue URLs, opened versus linked
  status, expected
  and verified origin labels, uncertain creation and pending actions. Link the
  retained filing ledger; do not replace it with an issue count.
- Per-attempt `blocked_on`: an array of objects naming affected checkpoint,
  prerequisite/retry condition,
  last observed prerequisite state and continuation phase, or an empty list.

Use real directories and regular state files, never substituted symlinks. Update
the record atomically under the processing claim below: stage complete JSON in
the owned run, verify same-filesystem placement, then replace only this exact
owned state file after verifying its key/repository/source identity. Preserve
attempt history. A registration write uses the producer's
owned run; a new/resumed investigation allocates its run only after claiming and
rechecking intake. A read-only skip needs no new scratch directory or state write.

Changed source bytes under an existing key require provenance reconciliation,
not an automatic new attempt or discovery. Check known paths/aliases and prior
ledgers even for legacy hash-derived keys, so editing a copy cannot evade lineage.
Missing, malformed or unsupported-version state is `RECONCILE`, not proof of
unreviewed work: inspect source/result hashes, reviewer coverage, filing and archive
ledgers first. Reconstruct verified completion/checkpoints where possible. Set a
genuinely new source to `PENDING` only after this history check; unavailable history
remains a named gap. Do not silently discard a corrupt record or reset it to empty.

This registry applies to resolved source reports. General questions and issue-only
research keep their ordinary run manifests. Unresolved repository/source identity
does not forbid manual investigation, but cannot claim repeat-safe queue ownership
or completion; keep it out of automatic processing until identity is reconciled.
State lives outside disposable run directories, but `/var/tmp` is not a backup:
lost state must be reconstructed from retained evidence, not guessed.

## Claim before dispatching work

Research, triage and standalone archival share an exclusive OS `flock` at
`/var/tmp/deep-review-work/locks/processing-<review-key>.lock`. Every consumer
acquires it nonblockingly before work; contention returns `SKIP_BUSY` regardless
of recorded status, including stale `PENDING` or active `FINALIZING`. Do not wait
while holding unrelated claims. Hold it for the
whole attempt, including reviewer tasks and finalization. A live coordinator or
owned lock-holder must actually retain the lock; file existence, stored PID or
timestamp is not ownership. Read-only history/cached-result inspection needs no
processing claim. A discovery producer registering a published source claims it
nonblockingly; if another consumer already owns it, leave that consumer's state
alone and report the registration handoff, never reset it to `PENDING`.

For multiple inputs, acquire processing locks nonblockingly in sorted key order
before repository filing mutexes and canonical per-report locks. If any is busy,
release this acquisition attempt's claims and defer the shared operation; process
independent inputs separately when their scope allows it. Declare a cohort or
aggregate's full source set before claiming it. Never acquire another processing
lock while holding lower-ranked locks; release/replan and reconcile if scope grows.
The order is **processing locks → repository mutexes → per-report locks**. Reuse
the caller's held processing claim during archival rather than reacquiring it.
Hold repository mutexes only for the existing filing/publication critical sections,
not across the expensive investigation.

After obtaining the claim, reread the record and artifacts before dispatch. All
writers must use compatible claims in the same filesystem/host coordination
domain; coordinate older consumers before enabling concurrent processing. If
ownership or cross-host coordination is uncertain, block rather than assume safety.
After a crash, reconcile saved reviewer task IDs and actual task state before
submitting replacements. Still-running tasks are reused/waited on, not duplicated;
unavailable task status is a blocker, not evidence the tasks finished or died.

## Reuse, resume and completion

An intake match includes source hash **and required work**, not just source name.
A triage result without research's three passes cannot satisfy a research request.
A report-only result can satisfy its completed investigation but not newly enabled
filing. Changed display names or a new caller model do not require re-research.
Stored authorization never grants writes forbidden by the current request.

| State after reconciliation | Next action |
| --- | --- |
| `PENDING` | Claim, allocate an owned run, record requirements/owner, enter `IN_PROGRESS` and perform required research |
| `IN_PROGRESS`, live claim owner | `SKIP_BUSY`; return owner and existing progress/result locators, with no new attempt |
| `IN_PROGRESS`, owner ended | Reconcile tasks/checkpoints; resume only missing or invalidated work |
| `BLOCKED`, prerequisite unchanged | `SKIP_BLOCKED`; return exact blocker/next condition, no repeated reviewers or new result |
| `BLOCKED`, recorded prerequisite changed within the same request | Recheck it under the claim and resume the recorded phase; do not broaden scope or authority |
| `FINALIZING` | Resume pending filing/tagging, result publication or archival; do not restart completed research merely because a file move or tag failed |
| `DONE`, required work covered and artifacts verified | `SKIP_DONE`; return `ALREADY_RESEARCHED`, existing results and their assessment revision |

Persist checkpoints after completed claim/reviewer work, issue readback, publication
and archival, and before releasing an attempt. Work on unrelated ready claims
continues when one claim is blocked. Mark the attempt `BLOCKED` only when no
eligible remaining step can proceed. Enter `FINALIZING` after required investigation
is accounted for. If freshness preflight invalidates evidence, return only affected
claims to `IN_PROGRESS`; old agreement cannot validate changed relevant code.
Successful creation with missing tags remains finalization work, never a second
create. Every attempted create still follows uncertain-response reconciliation.

Set `DONE` only when the required workflow/claim coverage, enabled filing/tagging,
verified outputs and applicable finished-archive move have completed. The separate
archive ledger is the proof of destinations/removals; a lifecycle flag cannot
substitute for it. Recover crashes between these steps from the actual artifacts.
A completed claim may remain `NEEDS_VALIDATION` with a precise next check under
the existing completion gate; `DONE` does not mean fixed or resolved. Such a claim
does not automatically cycle back to research on each sweep.

An explicitly requested fresh assessment (`--revalidate` or equivalent framing),
changed scope or requested verification revision creates a new recorded attempt
under the same source key, preserving history. A new branch tip by itself does not
requeue every completed review. Reuse still-valid evidence; recheck the requested
delta and relevant dependencies without fabricating current-tip verification.
Honor an explicit request for fresh independent reviewer passes as a requirement;
past passes alone do not discharge it.
Newly enabled filing resumes from prior validated evidence subject to freshness
preflight, rather than treating it as a new discovery. Cache reuse produces no
new reviewer dispatch, scratch run or duplicate report. It returns a historical
assessment, not a claim that GitHub or the code was freshly checked.

Expose the review key, state, action (`PROCESS`, `RESUME`, `RECONCILE`, `SKIP_DONE`,
`SKIP_BUSY` or `SKIP_BLOCKED`), source/result locators and remaining phase in the
handoff. A caller can advance to other eligible reviews, stop when none remain,
or wait through its authorized monitoring mechanism. Do not busy-loop on an
unchanged blocker, launch an unsolicited schedule, or create compatibility copies
to manufacture new queue entries.

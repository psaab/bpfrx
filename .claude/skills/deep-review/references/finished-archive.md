# Completed deep-review archive

After research finishes processing a deep-review, move its source report and
completed research result together into `/var/tmp/deep-review-finished/`, preserving
their basenames. This is the completed-history root, not a new watcher queue.
All staging remains under the owned `/var/tmp/deep-review-work/` run. Read archived
source reports for deduplication and their research results for evidence-backed
dispositions, actual issue URLs and origin tags. Reserve archived sequence numbers.

## Completion gate and exact scope

Archive a source only after every claim is accounted for, required reviewer passes
have completed, its result is published and verified, and enabled filing/tagging
obligations are satisfied or explicitly disabled by the user. Missing reviewer
output, blocked creation/tagging, CREATE_UNCERTAIN or incomplete publication keeps
that source active. Three completed passes can legitimately leave a claim at
NEEDS_VALIDATION with a reason and next check; finished research does not mean the
claim was refuted or its defect fixed. Archival is not permanent dismissal.

List exact source/result paths from the run manifest, not a glob. Include the
source's completed prior result snapshots outside the finished root when recorded
in its lineage. Verify already-archived sources/results in place; exclude them
from the move/removal set. A shared multi-input aggregate moves only after all
of its input processing and output
obligations are complete; one ready pair does not complete the other inputs.
For a remote source, archive the completed local result using a local-only move
set. Record the original URL/attachment identity and content hash in the ledger
as an external source, excluded from local removal. Return the archived result
path and say that the original remains remote; never claim a downloaded evidence
copy is the archived original or that both files moved. An unresolved source
identity remains a blocker, not an automatic remote-source exemption.

## Verified, resumable move

Use the shared repository mutex and canonical per-report locks defined in the
review contract, in that order. Hold them through archival reconciliation and
removal, including report-only research. Coordinate incompatible older writers
before proceeding; inability to establish ownership is a blocker, not permission
to race another worker. No GitHub mutation is implied by acquiring a local lock.

1. Ensure the finished root is a real directory, creating it if absent. Every
   file in the local move set must be an exact identified regular file, never a
   symlink or directory. Verify repository/run/source identities and content hashes against
   the completed result and manifest. Do not move an already-finished artifact again.
2. Record a relocation ledger under
   `/var/tmp/deep-review-work/state/archive-<report-lock-digest>.json`, using
   atomic state updates while holding the locks. Include source identity, all
   original/current/archive paths, SHA-256 hashes, expected source file identities,
   publication snapshots, per-file destination verification/removal state and
   overall completion. Preserve previous relocation entries, not just this retry.
3. Prepare complete byte-identical staged copies of the exact move set inside
   the owned work run; verify them and keep them frozen. Legacy inputs may be read
   from another device, but no staging is written beside them or under `/tmp`.
   Verify that the staging and finished directories share a filesystem. If not,
   retain drafts and report the blocker; no alternate-root fallback.
4. Publish each archive destination atomically create-if-absent with
   `ln -T -- <staged-copy> <archive-path>`. An existing file is reusable only after
   its complete bytes and source identity match the expected ledger entry. An
   unrelated file, directory or symlink is a blocker. Never overwrite, silently
   rename around a collision or edit a published report/header.
5. Verify the entire archive set before removing any active original. Persist
   verified destinations in the relocation ledger first. Immediately before each
   removal, recheck that exact original's file identity and hash are unchanged.
   Remove only that regular file, never a directory, symlink, changed file or an
   already-finished path. Record each successful removal. On failure, retain the
   remaining originals and report incomplete archival; do not broaden cleanup.
6. Mark the local move set complete only after every intended archive destination
   verifies and every intended active original has been removed. Return both the
   archived source and result locations, or the explicit external-source exception
   above, with the retained staging/ledger for recovery.

This is a recoverable multi-file move, not an atomic two-file rename. After a
crash, reconcile the ledger, hashes and actual paths before continuing. A file
already in the archive or an already-absent original is not by itself proof of a
completed pair. Resume the same move set; do not file issues again or create new
discovery IDs. If an original changed or removal permissions are unavailable,
leave the pair explicitly incomplete and preserve both verifiable copies.

## Reader behavior and later research

Published headers remain immutable: their output paths describe initial
publication. Resolve current paths through the identity/hash-verified relocation
ledger; validate basename/model/run identity without requiring an archived file to
remain at its original pathname. Reconcile temporary active+finished duplicates
by original repository/run/finding identity, not by counting filenames.

Discovery/triage inspect active, finished and legacy history before deduplication
or numbering. Read both archived originals and `report-`/`result-` derivatives,
but never enqueue finished history or derivatives as fresh discoveries. Cached
indexes are leads and must not hide archived-only findings or current issue state.

Explicit re-research of an archived source reads it in place, creates any new
result in the active reports root, and archives that new result when ready. Keep
the original and prior snapshots in the archive; do not move them back, create
compatibility aliases, or treat a new research run as a new discovery.

# Research report and workspace storage

Every research run publishes its evidence, dispositions, three-reviewer coverage
and actual issue/tagging ledger. Classify inputs by reconciled provenance, not by
the substring `-review`. A `research-result`, `report-` or `result-` derivative is
prior validation evidence, not a new deep-review discovery.

All new final reports are initially published in `/var/tmp/deep-review-reports/`.
Completed deep-review sources and their research results then move to
`/var/tmp/deep-review-finished/` through
[finished-review archival](../../deep-review/references/finished-archive.md).
All new working files and worktrees use an owned run under
`/var/tmp/deep-review-work/`. This applies
to general questions, external reviews, deep-review validation, legacy inputs,
mixed-input aggregates and solution planning. `/tmp` is compatibility input only,
never a new output, workspace or staging destination. The archival procedure may
remove exact verified legacy originals after their archive copies are complete.

## Output names and coverage

For a deep-review input, the first result is named **`report-<original filename>`**
under the new reports root, keeping the original extension once. It is adjacent
when the source is already there. Legacy and other out-of-root inputs stay where
they are during investigation; the new result records that source-to-output mapping
instead of writing beside them or copying the source into the discovery directory.
Only completed-research archival subsequently relocates the exact source/result set.

| Deep-review input | First research result |
| --- | --- |
| `/var/tmp/deep-review-reports/gpt-5.6-sol-review-ha-001.md` | `/var/tmp/deep-review-reports/report-gpt-5.6-sol-review-ha-001.md` |
| `/tmp/muse-spark-review-009.md` | `/var/tmp/deep-review-reports/report-muse-spark-review-009.md` |

The path inherits the source filename; it does **not** identify the researcher.
Record the researching model's real `MODEL_RAW`, `MODEL_SOURCE`, `MODEL_HOST` and
`WHOAMI` in the header/manifest, separately from original finding/discoverer IDs.
Verify the result basename against the source, not against the researcher's model.

For multiple deep-review inputs, publish one self-contained scoped result per
distinct source in the new reports root. Include every claim's disposition and
evidence, reviewer coverage and actual issue URLs. Retain a common research run ID,
cross-source finding/issue mappings and other output locators; shared findings are
not filed again. Reconcile copies by source identity instead of inventing discoveries.

General research and non-deep-review inputs use
`/var/tmp/deep-review-reports/result-<WHOAMI>-research-<RESEARCH_SLUG>-NNN.md`.
A mixed-input run also writes this aggregate result for the complete investigation,
linking the scoped
per-source reports so external-review claims/general answers are not lost. Prior
research derivatives link back to their original inputs; never recursively publish
`report-report-*` as a new discovery result. If researching one again, reconcile
its original source for the next snapshot, or use the standard result when that
source cannot be resolved and record the limitation.

Never overwrite a previous result. Reconcile existing results and filing history
in the active root, finished archive and legacy locations before naming a new
snapshot. If a verified result for this source already exists, a later run publishes an immutable
snapshot in `/var/tmp/deep-review-reports/` named
`report-<source-stem>-research-<WHOAMI>-<RESEARCH_SLUG>-NNN.md`, choosing the next
unused number across matching active/finished/legacy basenames and linking prior snapshots.
Use that same read-only sequence reconciliation for standard research results.
The stem omits only the last `.md`.
An unrelated file, directory or symlink at the first result path is a blocker,
not a report to reuse or overwrite. Concurrent collisions require the same check.

## Owned scratch and atomic publication

For every research run, allocate
`mktemp -d /var/tmp/deep-review-work/research-work.XXXXXXXXXX`, after ensuring the
parent is a real directory. Keep all worktrees (including documentation/plan
worktrees), drafts, reviewer outputs, manifests, evidence and staging inside this
owned run directory. Set task-local `TMPDIR` and applicable build/cache outputs
there; no tool-default or legacy-input exception may scatter work into `/tmp`
or the control checkout.

Ensure the reports root is a real directory and check its device identity against
the owned draft directory. Every output, including results for legacy inputs and
mixed-input aggregates, goes to this root; the input's device is irrelevant to
publication. If the two configured roots differ in filesystem or are unavailable,
retain the complete draft and report the blocker. Do not fall back to `/tmp`,
another scratch root, or visible staging files beside the final reports.

Check the source identity and exact output path in the manifest/header, ensure the
destination parent is a real directory, freeze the complete draft, then publish
atomically create-if-absent using `ln -T -- <draft> <final>`. No symlink following,
replacing copy or partial final pathname. Inspect any collision/ambiguous failure
before retrying; verify the exact final bytes/header and never edit a linked draft.
Keep completed per-source reports immutable if another output fails. A later immutable
aggregate or run ledger records the final per-output status.

For remote/attached inputs, retain the original URL/attachment identity and content
hash. For a deep-review, an established original report filename permits `report-` naming
in the reports root; without one, use the standard research result and state the
naming/provenance limitation instead of inventing a source path. A downloaded
scratch copy is not the user's original location. An unwritable source directory
does not prevent publication to the configured reports root. If that destination
is unavailable, retain the complete draft and the exact publication blocker;
publication failure must never trigger duplicate issue creation.

Return every source/output pair, the standard/aggregate path when applicable,
prior snapshots and exact pending publications. Both `report-` and `result-`
outputs carry `Artifact kind: research-result` and are excluded from new-discovery
selection in both directory scans and cached indexes. They remain readable for
reconciliation; do not write `.researched-` markers merely because research ended.
After completed deep-review processing, return the source/result paths in the
finished archive, resolving initial publication locations through its relocation
ledger. Do not claim an archive move for a remote original that remains remote.

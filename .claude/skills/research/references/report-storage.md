# Research results beside deep-review inputs

Every research run publishes its evidence, dispositions, three-reviewer coverage
and actual issue/tagging ledger. Classify inputs by reconciled provenance, not by
the substring `-review`. A `research-result`, `report-` or `result-` derivative is
prior validation evidence, not a new deep-review discovery.

## Output names and coverage

For a local deep-review input, the first result is **in the same directory** and
is named **`report-<original filename>`**, keeping the original extension once:

| Deep-review input | First research result |
| --- | --- |
| `/var/tmp/deep-review-reports/gpt-5.6-sol-review-ha-001.md` | `/var/tmp/deep-review-reports/report-gpt-5.6-sol-review-ha-001.md` |
| `/tmp/muse-spark-review-009.md` | `/tmp/report-muse-spark-review-009.md` |

The path inherits the source filename; it does **not** identify the researcher.
Record the researching model's real `MODEL_RAW`, `MODEL_SOURCE`, `MODEL_HOST` and
`WHOAMI` in the header/manifest, separately from original finding/discoverer IDs.
Verify the sibling basename against the source, not against the researcher's model.

For multiple deep-review inputs, publish one self-contained scoped result beside
each distinct source. Include every claim from that source, its disposition and
evidence, reviewer coverage and actual issue URLs. Retain a common research run ID,
cross-source finding/issue mappings and other output locators; shared findings are
not filed again. Reconcile copies by source identity instead of inventing discoveries.

General research and non-deep-review inputs retain the standard
`/tmp/result-<WHOAMI>-research-<RESEARCH_SLUG>-NNN.md` result. A mixed-input run also
writes this aggregate result for the complete investigation, linking the scoped
sibling reports so external-review claims/general answers are not lost. Prior
research derivatives link back to their original inputs; never recursively publish
`report-report-*` as a new discovery result. If researching one again, reconcile
its original source for the next snapshot, or use the standard result when that
source cannot be resolved and record the limitation.

Never overwrite a previous result. If the exact first name already contains a
verified result for this source, reconcile its lineage and filings. A later run
publishes an adjacent immutable snapshot named
`report-<source-stem>-research-<WHOAMI>-<RESEARCH_SLUG>-NNN.md`, choosing the next
unused number and linking prior snapshots. The stem omits only the last `.md`.
An unrelated file, directory or symlink at the first result path is a blocker,
not a report to reuse or overwrite. Concurrent collisions require the same check.

## Owned scratch and atomic publication

For runs consuming deep-review inputs, normally allocate
`mktemp -d /var/tmp/deep-review-work/research-work.XXXXXXXXXX`, after ensuring the
parent is a real directory. Keep drafts, reviewer outputs, manifests, evidence
and task-local temp/build/cache outputs inside this owned run directory.
Legacy-only root-`/tmp` inputs and standalone research may use the established
`mktemp -d /tmp/research-work.XXXXXXXXXX` layout.

Check the device identity of the owned draft directory and **each** destination.
For mixed `/var/tmp` and legacy `/tmp` outputs, allocate an additional owned
`/tmp/research-work.XXXXXXXXXX` staging directory for the `/tmp` outputs and record
it under the same run ID. Prepare complete drafts there before publication. These
are staging paths, not extra discoveries or compatibility aliases. Do not create
visible scratch files beside the final reports. For another mount, require a
verified owned same-device staging location or retain the draft with an explicit
blocker; `/tmp` and `/var/tmp` are not assumed to share a filesystem.

Check the source identity and exact output path in the manifest/header, ensure the
destination parent is a real directory, freeze the complete draft, then publish
atomically create-if-absent using `ln -T -- <draft> <final>`. No symlink following,
replacing copy or partial final pathname. Inspect any collision/ambiguous failure
before retrying; verify the exact final bytes/header and never edit a linked draft.
Keep completed siblings immutable if another output fails. A later immutable
aggregate or run ledger records the final per-output status.

For a remote/attached deep-review input without an established local source path, or an
unwritable sibling destination, retain the complete draft and report the missing
publication prerequisite. A downloaded scratch copy is not silently treated as
the user's original location. Continue the investigation and account for valid
filings; publication failure must never trigger duplicate issue creation.

Return every source/output pair, the standard/aggregate path when applicable,
prior snapshots and exact pending publications. Both `report-` and `result-`
outputs carry `Artifact kind: research-result` and are excluded from new-discovery
selection in both directory scans and cached indexes. They remain readable for
reconciliation; do not write `.researched-` markers merely because research ended.

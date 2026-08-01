# Refactoring Audit

Tracking the modularity-discipline rule from `docs/engineering-style.md`:

- **Files >= 2000 LOC are refactor candidates.**
- Files 1500-1999 LOC are **watch-list** — flag in code review when adding to them.

## How it's measured

`scripts/refactoring-audit.sh` produces a deterministic, sorted list of
`[REFACTOR]` and `[WATCH]` entries. Output is committed to
`docs/refactoring-audit-current.txt` and regenerated periodically — and
at PR time whenever a file crosses a tier boundary (see [Drift
guard](#drift-guard); in-band LOC churn does not require a
regeneration).

LOC is total file LOC for non-test, non-generated files. The script covers
three language families:

- **Go** — `pkg/`, `cmd/`
- **Rust** — `userspace-dp/src/`, `userspace-xdp/src/`
- **BPF C programs** — `bpf/xdp/*.c`, `bpf/tc/*.c` (not headers;
  shared header size is an include-time artifact, not a per-program
  refactor unit). These roots were deleted in #1476 and are currently
  absent; the script tolerates that (a no-op) and will pick them up
  again if the directories ever return.

Test files and generated code are excluded by name pattern. The
classifier (skip regex) and the LOC measurement live in one place —
`scripts/refactoring-audit-lib.sh` — so the generator, `make
audit-check`, and the enforcement fixtures all classify a path
identically.

**Rust test-only filename shapes (#6232).** All four are excluded:

| Shape         | Example                       | Purpose                        |
|---------------|-------------------------------|--------------------------------|
| `tests.rs`    | `screen/tests.rs`             | exact catch-all sibling        |
| `*_tests.rs`  | `policy_tests.rs`             | per-subsystem suffix split     |
| `tests_*.rs`  | `nat/tests_pool.rs`           | per-subsystem prefix split (#4840/#4409) |
| `test_*.rs`   | `test_fixtures.rs`, `test_support.rs`, `test_alloc.rs` | fixtures / support helpers |

Before #6232 only `tests.rs`, `*_tests.rs`, and three hand-listed
`test_*.rs` files were excluded, so the `tests_*.rs` / generic
`test_*.rs` sibling `#[path] mod` test modules the #4840/#4409 test
splits introduced were miscounted as production and produced false
`[REFACTOR]`/`[WATCH]` rows (e.g. an 8k-LOC `tests_pool.rs`). The
patterns are anchored to the basename, so a production file that merely
*contains* "test" — `attestation.rs`, `latest_state.rs`, `contest.rs` —
is still counted.

Go tests (`*_test.go`) and generated code (`*.pb.go`, `*_grpc.pb.go`,
`*_bpfel.go`, `*_bpfeb.go`, `zz_generated_*`) are also excluded, along
with `target/`, `vendor/`, `*.lock`, retired plan retrospectives
(`_KILLED` / `_WITHDRAWN`), and `docs/pr/*/findings` evidence artifacts.

BPF C programs appear in the output with the same `[REFACTOR]`/`[WATCH]`
tags, but the refactoring mechanic is different: verifier constraints
(512-byte stack, no unbounded loops) mean splitting means tail-call
decomposition or moving helpers to shared headers, not ordinary function
extraction. `>2000 L` in a single BPF program file is also a verifier
complexity hazard independent of the modularity concern.

This audit deliberately does NOT strip inline `#[cfg(test)] mod tests`
blocks. Earlier `awk` approaches were fragile (the `EOF` keyword bug
silently erased production code following an inline test block, per
Gemini round-1 review of #1208's plan). The measurement stays a plain
raw line count (`audit_loc` in `scripts/refactoring-audit-lib.sh`) so
that failure mode is structurally impossible; the
`TestInlineTestBlockNotStripped` fixture in
`pkg/refactoraudit/audit_canary_test.go` pins it (a fixture file with
production code after an inline test block must report its full LOC).
The #1034 colocated-tests refactor moved most inline test blocks to
`tests.rs` siblings anyway; remaining inline cases are rare and the
modest over-count is acceptable at the 1500-2000 thresholds. Only
whole-file test *modules* (the four filename shapes above) are
excluded — a filename classifier cannot safely strip inline syntax, so
it does not try.

## Regeneration

```bash
cd $(git rev-parse --show-toplevel)
bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt
```

The script sorts deterministically with `LC_ALL=C sort -k2,2nr -k3,3`
(descending LOC, ascending path), emits no timestamps, and tolerates
absent source roots (e.g. `bpf/xdp`/`bpf/tc` after #1476), so repeated
runs produce byte-identical output.

## Drift guard

### What is gated, and what is advisory

The gate is on the heatmap's **content**: which files are audited, and
at which tier. That is what the project's rules act on, and it only
changes when a file actually crosses 1500 or 2000 LOC — a real, rare,
actionable event.

The **LOC column is an advisory snapshot.** It is not gated, and the
tree is expected to outrun it between regenerations. How far it can
drift depends on the tier, and the asymmetry is worth stating plainly
rather than implying a uniform bound:

- A `[WATCH]` number is bounded on both sides — the band is 1500-1999,
  so it cannot be more than ~500 lines wrong before a crossing fails
  the gate and forces a regeneration that refreshes every number.
- A `[REFACTOR]` number is bounded only from below. The band is
  "2000 or more" and is **open above**, so a file already over 2000 can
  grow without limit and no gate fires. This artifact contains its own
  example: `userspace-dp/src/afxdp/worker/loop_body/mod.rs` drifted
  2119 -> 2448 (+329) with no signal.

That is acceptable because the number is advisory and the tier is what
the project's rules act on — a file over 2000 is already `[REFACTOR]`
and stays `[REFACTOR]` however much it grows, so the actionable fact
does not go stale even when the number does. But do not read a
`[REFACTOR]` LOC as current; regenerate before using one to compare
two candidates against each other.

**Why the LOC column cannot be gated (#6617).** It used to be — the
canary compared the artifact byte-for-byte — and that criterion could
not hold. The heatmap is a repo-*global* snapshot: its LOC column
depends on every audited file in the tree, not just the ones a PR
touches. Under parallel merges, a PR that regenerates the artifact
correctly at its own base still lands stale, because a sibling PR grew a
different file in between. Measured over the 40 first-parent commits
ending at `b4605ea9d`, `master` was byte-stale in **26** of them; #6602
and #6613 each regenerated the artifact at their own base and
each *still* landed red, both disagreeing only on `pkg/snmp/agent.go`, a
file neither PR touched. A gate that fails when the author did
everything right is noise — and the noise is what let real staleness sit
22 rows deep for 21 consecutive commits before anyone looked.

### The two surfaces

1. **`make test` (required, automatic).** The `pkg/refactoraudit`
   canary (`TestHeatmapNotStale`) regenerates the heatmap and asserts
   the audited file set and each file's tier match the committed
   `docs/refactoring-audit-current.txt`. Because it is an ordinary Go
   test it runs under `go test ./...` — part of the single pre-commit
   aggregate `make test` — so audit content **cannot** silently drift on
   `master` the way it did before #6232 (62 generated rows vs 16
   committed). It fails with the specific files that entered, left, or
   changed tier, not a dump of both artifacts. Sibling tests pin the
   artifact's internal coherence (`TestHeatmapArtifactWellFormed` — every
   row's LOC agrees with its own tier tag and the rows are still in
   generator order, so a hand edit cannot pass), generator determinism
   (`TestGeneratorDeterministic`), the classifier
   (`TestClassifierFilenameShapes`), the >=2000 LOC production sentinel
   (`TestProductionSentinelVisible`), and the raw-LOC / no-inline-strip
   invariant (`TestInlineTestBlockNotStripped`).

2. **`make audit-check` (#1661 item 8, standalone convenience).**
   Regenerates the heatmap to a temp file, prints the exact `diff`, and
   classifies it so its verdict always agrees with the canary:

   | Diff | Verdict | Exit |
   |------|---------|------|
   | none | up to date | 0 |
   | LOC column only (same files, same tiers) | `ADVISORY` — refresh when convenient | 0 |
   | a file entered / left / changed tier | `ERROR` — `TestHeatmapNotStale` will fail | 1 |

   Run it after any change that adds, deletes, or resizes a `>=1500` LOC
   source file, and regenerate when it says `ERROR`.

Both paths share the classifier and measurement in
`scripts/refactoring-audit-lib.sh`, so they can never disagree about
what counts as production LOC. To refresh the artifact — after a tier
crossing, or any time you want the numbers current:

```bash
bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt
```

## When to refactor a candidate

- A change adds >100 LOC to a `[REFACTOR]`-tier file: split before landing.
- A change pushes a `[WATCH]`-tier file past 2000 LOC: same.
- The file's responsibilities can be cleanly separated into multiple
  cohesive modules: refactor opportunistically.

## When NOT to refactor

- The file is high-touch and the split would create review friction
  that exceeds the modularity gain.
- The file is provably going to be replaced (e.g., a temporary shim
  awaiting a different architecture).
- LOC is dominated by one cohesive function/struct that genuinely
  belongs in one place (e.g., a large schema definition).

In those cases, document the decision in a comment at the top of the
file or in a `docs/pr/` plan and stop arguing about it.

## Historical context

This file replaces an older `refactoring-audit.md` (generated
2026-04-03) that listed individual files with bespoke remediation
notes. That format went stale within weeks of every refactor. The
generated heatmap captures current state automatically.

The 18-PR refactor stream that landed in early 2026 (closing #985,
#988, #986, #1034, #1035, #957) drove most of the userspace-dp Rust
production tree below the 2000 threshold. Since then the tree has moved
on: the legacy `bpf/xdp/*.c` and `bpf/tc/*.c` programs were deleted in
#1476, and `pkg/dataplane/dpdk/dpdk_cgo.go` was deleted with the rest of
the DPDK dataplane in #1525/#1528 — so the old narrative's per-file
candidate lists are no longer current. **Do not read specific file names
out of this section; it is historical.** The committed heatmap is the
single source of truth for which files are `[REFACTOR]`/`[WATCH]` tier.

See `docs/refactoring-audit-current.txt` for the current heatmap, and
run `make audit-check` to confirm it is in sync with the tree. Its LOC
column is an advisory snapshot; the tier each file is filed under is
gated and always current.

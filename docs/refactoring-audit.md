# Refactoring Audit

Tracking the modularity-discipline rule from `docs/engineering-style.md`:

- **Files >= 2000 LOC are refactor candidates.**
- Files 1500-1999 LOC are **watch-list** — flag in code review when adding to them.

## How it's measured

`scripts/refactoring-audit.sh` produces a deterministic, sorted list of
`[REFACTOR]` and `[WATCH]` entries. Output is committed to
`docs/refactoring-audit-current.txt` and regenerated periodically (and at
PR time when adding to a flagged file).

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

The committed heatmap is enforced two ways:

1. **`make test` (required, automatic).** The `pkg/refactoraudit`
   canary (`TestHeatmapNotStale`) regenerates the heatmap and asserts it
   byte-for-byte matches the committed
   `docs/refactoring-audit-current.txt`. Because it is an ordinary Go
   test it runs under `go test ./...` — part of the single pre-commit
   aggregate `make test` — so the artifact **cannot** silently drift on
   `master` the way it did before #6232 (62 generated rows vs 16
   committed). Sibling tests pin the classifier (`TestClassifierFilenameShapes`),
   the >=2000 LOC production sentinel (`TestProductionSentinelVisible`),
   and the raw-LOC / no-inline-strip invariant
   (`TestInlineTestBlockNotStripped`).

2. **`make audit-check` (#1661 item 8, standalone convenience).**
   Regenerates the heatmap to a temp file and `diff`s it against the
   committed artifact, printing the exact drift and the one-line
   regenerate command. Run this after any change that adds, deletes, or
   resizes a `>=1500` LOC source file to see and fix the drift *before*
   `make test` fails, then commit the regenerated artifact.

Both paths share the classifier and measurement in
`scripts/refactoring-audit-lib.sh`, so they can never disagree about
what counts as production LOC. To refresh the artifact after a
legitimate resize:

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
run `make audit-check` to confirm it is in sync with the tree.

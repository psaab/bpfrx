# shellcheck shell=bash
# Shared classifier + measurement for the modularity audit (#6232).
#
# This is the SINGLE SOURCE OF TRUTH for two decisions the heatmap
# depends on:
#
#   1. Which paths are EXCLUDED from the audit (test/generated/vendored).
#   2. How a file's production LOC is measured.
#
# Both the generator (scripts/refactoring-audit.sh) and the enforcement
# fixtures (pkg/refactoraudit/audit_canary_test.go via the thin CLI
# scripts/refactoring-audit-classify.sh) source this file, so the gate
# and the doc can never classify a path two different ways. Sourcing
# this file has no side effects — it only defines variables/functions.

# Exclusion regex (extended POSIX). A path matching this is NOT counted.
#
#  - target/, vendor/                build artifacts
#  - zz_generated_*                  generated code
#  - *_bpfel.go / *_bpfeb.go         bpf2go output
#  - *.pb.go / *_grpc.pb.go          generated protobuf/gRPC
#  - Go tests:   *_test.go
#  - Rust tests: every test-only filename shape (#6232). Before #6232
#    only `tests.rs`, `*_tests.rs`, and three hand-listed `test_*.rs`
#    files were excluded, so the sibling `#[path] mod` test modules the
#    #4840/#4409 test splits introduced — `tests_pool.rs`,
#    `tests_support.rs`, `tests_destination.rs`, ... — were counted as
#    production and produced false [REFACTOR]/[WATCH] rows. The four
#    Rust test filename shapes are:
#        tests.rs            exact catch-all sibling
#        *_tests.rs          per-subsystem suffix split
#        tests_*.rs          per-subsystem prefix split (#4840/#4409)
#        test_*.rs           fixtures / support / alloc helpers
#    The `tests_*`/`test_*` patterns subsume the old hand-listed
#    test_support.rs / test_fixtures.rs / test_zone_ids.rs exceptions.
#    All are anchored to the basename ((^|/) or a suffix) so a
#    production file that merely CONTAINS "test" — attestation.rs,
#    latest_state.rs, contest.rs — is still counted.
#  - _KILLED / _WITHDRAWN            retired plan retrospectives
#  - docs/pr/*/findings              large review evidence artifacts
#  - *.lock                          lockfiles
AUDIT_SKIP_RE='(^|/)(target|vendor)/'
AUDIT_SKIP_RE+='|/zz_generated'
AUDIT_SKIP_RE+='|_bpfel\.go$|_bpfeb\.go$'
AUDIT_SKIP_RE+='|\.pb\.go$|_grpc\.pb\.go$'
AUDIT_SKIP_RE+='|_test\.go$'
AUDIT_SKIP_RE+='|(^|/)tests\.rs$|_tests\.rs$'
AUDIT_SKIP_RE+='|(^|/)tests_[^/]*\.rs$'
AUDIT_SKIP_RE+='|(^|/)test_[^/]*\.rs$'
AUDIT_SKIP_RE+='|/_KILLED|/_WITHDRAWN'
AUDIT_SKIP_RE+='|docs/pr/[^/]+/findings'
AUDIT_SKIP_RE+='|\.lock$'

# audit_is_excluded <path>
# Exit 0 (true) if the path is excluded from the heatmap, 1 otherwise.
audit_is_excluded() {
    printf '%s\n' "$1" | grep -qE "$AUDIT_SKIP_RE"
}

# audit_loc <path>
# Print the file's production LOC. We deliberately count RAW file LOC
# and do NOT strip inline `#[cfg(test)]` blocks. An earlier awk
# range-stripper silently erased production code that FOLLOWED an inline
# test block (see docs/refactoring-audit.md); keeping this a plain line
# count makes that failure mode structurally impossible. The regression
# is pinned by TestInlineTestBlockNotStripped in
# pkg/refactoraudit/audit_canary_test.go. The modest over-count from the
# few remaining inline test blocks is accepted at the 1500/2000
# thresholds.
audit_loc() {
    wc -l < "$1"
}

# ---------------------------------------------------------------------
# Audited roots and thresholds (#7253)
#
# These were literals inside scripts/refactoring-audit.sh until the
# touched-file gate needed the same "would the generator measure this
# path?" answer for an arbitrary path coming out of `git diff`. Two
# copies of a root list drift, so the generator now word-splits these
# variables and scripts/refactoring-audit-touched.sh asks
# audit_is_audited_path. pkg/refactoraudit binds the agreement
# behaviourally (TestAuditedPathPredicateAgreesWithGenerator: every path
# the generator emitted must satisfy the predicate) and pins the floors
# against the Go constants (TestShellFloorsMatchGoConstants).

# LOC at which a file enters the heatmap, and at which it is promoted to
# [REFACTOR]. Mirrored by auditFloor / refactorFloor in
# pkg/refactoraudit/audit_canary_test.go.
# shellcheck disable=SC2034 # consumed by sourcing scripts, not here.
AUDIT_FLOOR=1500
# shellcheck disable=SC2034 # consumed by sourcing scripts, not here.
AUDIT_REFACTOR_FLOOR=2000

# Audited roots, per language. A path is audited only if it lives under
# one of the roots for ITS extension — pkg/x.rs and userspace-dp/src/x.go
# are both uninteresting — and is not excluded by AUDIT_SKIP_RE.
#
# bpf/xdp and bpf/tc were deleted in #1476 and are currently absent; the
# generator tolerates that (audit_existing_dirs) and the predicate below
# answers for them the same way it always would, so the two agree if the
# roots ever return.
AUDIT_ROOTS_RS="userspace-dp/src userspace-xdp/src"
AUDIT_ROOTS_GO="pkg cmd"
AUDIT_ROOTS_C="bpf/xdp bpf/tc"

# audit_is_audited_path <path>
# Exit 0 (true) if the generator would measure <path> — i.e. it is a
# repo-relative path under one of its language's audit roots and is not
# excluded as test/generated/vendored code. Files below the LOC floor
# still answer true here: this is "is this path in the audited
# population", not "is it in the heatmap".
audit_is_audited_path() {
    local p="$1" roots root
    case "$p" in
        *.rs) roots="$AUDIT_ROOTS_RS" ;;
        *.go) roots="$AUDIT_ROOTS_GO" ;;
        *.c)  roots="$AUDIT_ROOTS_C" ;;
        *)    return 1 ;;
    esac
    # Root test first: it is a shell builtin, while audit_is_excluded
    # spawns a grep. A caller feeds this every untracked path in the tree
    # (`git ls-files --others`), most of which live nowhere near an audit
    # root, so the cheap test has to be the one that rejects them.
    for root in $roots; do
        case "$p" in
            "$root"/*)
                audit_is_excluded "$p" && return 1
                return 0
                ;;
        esac
    done
    return 1
}

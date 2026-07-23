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

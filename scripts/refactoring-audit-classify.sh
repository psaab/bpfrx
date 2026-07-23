#!/usr/bin/env bash
# Thin CLI over the audit classifier (#6232), used by the enforcement
# fixtures in pkg/refactoraudit/audit_canary_test.go. It lets the Go
# canary exercise the SAME classifier the generator uses, so the two can
# never drift.
#
# Usage:
#   refactoring-audit-classify.sh classify <path>...
#       Print one line per path: "SKIP <path>" (excluded) or
#       "SOURCE <path>" (counted).
#   refactoring-audit-classify.sh loc <path>
#       Print the raw production LOC the audit would attribute to <path>.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/refactoring-audit-lib.sh
. "$here/refactoring-audit-lib.sh"

cmd="${1:-}"
shift || true
case "$cmd" in
    classify)
        [ "$#" -ge 1 ] || { echo "usage: classify <path>..." >&2; exit 2; }
        for p in "$@"; do
            if audit_is_excluded "$p"; then
                printf 'SKIP %s\n' "$p"
            else
                printf 'SOURCE %s\n' "$p"
            fi
        done
        ;;
    loc)
        [ "$#" -eq 1 ] || { echo "usage: loc <path>" >&2; exit 2; }
        audit_loc "$1"
        ;;
    *)
        echo "usage: $(basename "$0") {classify <path>...|loc <path>}" >&2
        exit 2
        ;;
esac

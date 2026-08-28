#!/usr/bin/env bash
# Struct-heterogeneity audit (#6937): list structs whose DISTINCT FIELD
# TYPE count is at or above AUDIT_STRUCT_FLOOR, sorted desc with category
# tags ([REFACTOR] at AUDIT_STRUCT_REFACTOR_FLOOR, [WATCH] below it).
#
# Complements scripts/refactoring-audit.sh, which measures file LOC and
# therefore cannot see field accretion: `Daemon` reached 255 fields inside
# a 1167-LOC file, legitimately under the [WATCH] floor, and would still be
# invisible if it doubled (#6937).
#
# The measurement lives in Go (pkg/refactoraudit) because it needs go/ast:
# a regex counter descends into anonymous nested structs and inflates the
# count. Exclusions and roots are PASSED IN from refactoring-audit-lib.sh
# rather than reimplemented, so that file stays the single source of truth.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
# shellcheck source=scripts/refactoring-audit-lib.sh
source scripts/refactoring-audit-lib.sh

exec go run ./pkg/refactoraudit/structaudit \
    -skip "$AUDIT_SKIP_RE" \
    -go-roots "$AUDIT_ROOTS_GO" \
    -rs-roots "$AUDIT_ROOTS_RS" \
    "$@"

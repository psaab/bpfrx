#!/usr/bin/env bash
# Upgrade/install docs canary (#2001).
#
# A small fail-closed guard against the two upgrade-install doc phrasings
# that repeatedly mislead the next maintainer once the hardened model
# (#1964 versioned-runtime seed, #1982 manifest SSOT, #1983 reject-non-
# default endpoint) landed:
#
#   1. "symlinks into the staging path" — the live /usr/local/sbin/*
#      symlinks resolve THROUGH versions/current on a normal first install
#      (xpfd seed-runtime); they point straight at staged/* ONLY in the
#      degraded direct-staged FALLBACK when seeding fails. So this phrase
#      must never describe the normal install layout. install-images.md is
#      the install-layout doc; the phrase is banned there outright (the
#      fallback is documented without the misleading literal).
#
#   2. `manifest.Managed` — that symbol does NOT exist. The managed-binary
#      SSOT is the UNEXPORTED `managed` slice in
#      pkg/upgrade/manifest/manifest.go, reachable only via the exported
#      accessors All() / Names() / LockstepNames(). Docs that tell a
#      maintainer to edit `manifest.Managed` send them to a phantom symbol.
#      Banned across all of docs/.
#
# This is a docs-only grep guard, deliberately standalone (run via
# `make docs-check`) and NOT wired into `make test` — same posture as the
# audit-check drift guard. Exit non-zero if either phrase reappears.

set -euo pipefail

# Resolve repo root from this script's location so the canary works from
# any CWD (Makefile target, CI, manual run).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
cd "$repo_root"

status=0

# Phrase 1: banned in the install-layout doc. The direct-staged fallback
# is documented in install-images.md WITHOUT this literal, so any
# occurrence is the stale pre-#1964 layout language.
phrase_staging="symlinks into the staging path"
doc_install="docs/install-images.md"
if [ ! -f "$doc_install" ]; then
	echo "ERROR: $doc_install not found — install-layout canary is vacuous." >&2
	echo "       If the file was renamed, update this script's doc_install variable." >&2
	status=1
elif grep -nF -- "$phrase_staging" "$doc_install" >&2; then
	echo "ERROR ($doc_install): the literal \"$phrase_staging\" describes the" >&2
	echo "       pre-#1964 layout. On a normal install the sbin symlinks resolve" >&2
	echo "       THROUGH versions/current (xpfd seed-runtime); only the degraded" >&2
	echo "       fallback points at staged/*. Reword without this literal." >&2
	status=1
fi

# Phrase 2: banned across all docs. manifest.Managed is a phantom symbol;
# the SSOT is the unexported `managed` slice + All()/Names()/LockstepNames().
phrase_symbol="manifest.Managed"
if [ ! -d "docs" ]; then
	echo "ERROR: docs/ directory not found at $(pwd)/docs — manifest-symbol canary is vacuous." >&2
	echo "       If the directory was moved, update this script's repo_root detection." >&2
	status=1
elif grep -rnF -- "$phrase_symbol" docs/ >&2; then
	echo "ERROR (docs/): \"$phrase_symbol\" does not exist. The managed-binary" >&2
	echo "       SSOT is the unexported \`managed\` slice in" >&2
	echo "       pkg/upgrade/manifest/manifest.go; callers use the exported" >&2
	echo "       accessors All() / Names() / LockstepNames()." >&2
	status=1
fi

if [ "$status" -eq 0 ]; then
	echo "check-upgrade-docs: upgrade/install docs are clean"
fi
exit "$status"

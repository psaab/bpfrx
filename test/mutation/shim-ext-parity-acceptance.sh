#!/usr/bin/env bash
#
# #4555 acceptance harness: prove the IPv6 extension-header parity guards
# actually fire, by mutating the shim's walk and observing the corpus red.
#
# Committed deliberately. The mutation rows in the PR body and _Log.md are only
# evidence if the procedure that produced them can be audited — ordering, return
# codes, restore verification and signal handling all change what the rows mean.
# Prose describing a harness is not a harness.
#
# Three properties, each learned from a failure of an earlier version of this
# script:
#
#   1. EXCLUSIVE LOCK. Two concurrent runs mutate the same file and interleave
#      their restores. One run's row then describes the other run's tree.
#   2. GREEN BASELINE SELF-CHECK (row 0). If the tree is not clean before the
#      first mutation, every later row is void. An earlier run was killed
#      mid-mutation, the next run captured the mutated tree as its "pristine"
#      copy, and reported a clean tree as failing. Refusing to start is better
#      than emitting confident false rows.
#   3. RESTORE ON EXIT/INT/TERM. A trap cannot catch SIGKILL, so the trap is not
#      the safety property — property 2 is. The trap narrows the window; the
#      baseline check is what makes a poisoned tree non-fatal.
#
# Usage:  test/mutation/shim-ext-parity-acceptance.sh
# Requires: cargo + the pinned toolchain; no root, no cluster, no network.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WALK="${REPO}/userspace-xdp/src/ipv6_ext_walk.rs"
GOLD="$(mktemp -t ipv6_ext_walk.gold.XXXXXX)"
LOCK="${TMPDIR:-/tmp}/xpf-4555-acceptance.lock"
: "${CARGO_TARGET_DIR:=/dev/shm/cargo-4555-acceptance}"
export CARGO_TARGET_DIR
export TMPDIR="${TMPDIR:-/tmp}"

exec 9>"${LOCK}"
flock -n 9 || { echo "another acceptance run holds ${LOCK}; refusing to interleave"; exit 1; }

cp "${WALK}" "${GOLD}"
trap 'cp "${GOLD}" "${WALK}"; rm -f "${GOLD}"' EXIT INT TERM

build_log="$(mktemp)"; test_log="$(mktemp)"
run() {
  ( cd "${REPO}/userspace-dp" && cargo build --release ) >"${build_log}" 2>&1
  local brc=$?
  if [ $brc -ne 0 ]; then
    printf '%-54s BUILD rc=%d  <-- FALSE RED, not an assertion\n' "$1" "$brc"
    grep -m2 -E '^error' "${build_log}" | sed 's/^/      /'
    return 1
  fi
  ( cd "${REPO}/userspace-dp" && cargo test --release --bin xpf-userspace-dp tests_shim_ext_parity ) >"${test_log}" 2>&1
  local trc=$?
  r() { grep -E "tests_shim_ext_parity::$1 \.\.\." "${test_log}" | grep -oE '(ok|FAILED)' | head -1; }
  printf '%-54s build=0 rc=%-3d | corpus=%-6s facts=%-6s CONTROL=%s/%s\n' "$1" "$trc" \
    "$(r shim_walk_and_userspace_walk_agree_over_a_corpus)" \
    "$(r shim_ipv6_ext_walk_matches_userspace_walker)" \
    "$(r shim_walk_corpus_negative_control)" \
    "$(r shim_ext_parity_negative_control_unchanged_classifications)"
  grep -m1 -oE '[A-Za-z0-9 ()=,>-]+: shim=[A-Za-z0-9(), ]+ userspace=[A-Za-z0-9(), ]+' "${test_log}" \
    | sed 's/^/      first divergence: /'
  return $trc
}

echo "=== #4555 acceptance: mutate the shim walk, the corpus must red ==="
if ! run "0. GREEN [baseline self-check]"; then
  echo "ABORT: baseline is not green. The tree is dirty or a previous run was"
  echo "       killed mid-mutation; every row after this would be meaningless."
  exit 1
fi

mutate_generic_advance() { sed -i 's|+ 1) \* 8)?;|+ 1) * 16)?;|' "${WALK}"; }
mutate_drop_generic_revalidation() {
  python3 - "${WALK}" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = """                offset = offset.checked_add(((opt[1] as u16) + 1) * 8)?;
                read_bytes(
                    data,
                    data_end,
                    l3_offset as usize,
                    (offset - l3_offset) as usize,
                )?;"""
assert s.count(old) == 1, "generic arm not found in its expected shape"
open(p, 'w').write(s.replace(old, "                offset = offset.checked_add(((opt[1] as u16) + 1) * 8)?;"))
PY
}
mutate_statement_outside_match() {
  python3 - "${WALK}" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = "    for _ in 0..MAX_EXT_HDRS {\n"
assert s.count(a) == 1
open(p, 'w').write(s.replace(a, a + "        if offset > 200 {\n            break;\n        }\n"))
PY
}
mutate_auth_advance() { sed -i 's|+ 2) \* 4)?;|+ 2) * 8)?;|' "${WALK}"; }

rc=0
for spec in \
  "mutate_generic_advance|1. generic advance *8 -> *16" \
  "mutate_drop_generic_revalidation|2. generic post-advance revalidation DELETED (security)" \
  "mutate_statement_outside_match|3. statement inside the loop, outside the match" \
  "mutate_auth_advance|4. AUTH advance *4 -> *8"; do
  fn="${spec%%|*}"; label="${spec#*|}"
  cp "${GOLD}" "${WALK}"
  "${fn}"
  if run "${label}"; then
    echo "      ^^ MUTATION SURVIVED — the guard does not bind this edit"
    rc=1
  fi
done

cp "${GOLD}" "${WALK}"
run "5. RESTORED" || rc=1
rm -f "${build_log}" "${test_log}"
echo "=== acceptance $([ $rc -eq 0 ] && echo PASS || echo FAIL) ==="
exit $rc

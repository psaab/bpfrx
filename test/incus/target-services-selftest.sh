#!/usr/bin/env bash
#
# #8040 — hermetic self-test for test/incus/target-services.sh.
#
# The subject is a diagnosis tool, and a diagnosis tool that reports the wrong
# thing is worse than none: a runner acts on it. The three properties that
# matter, and the failure each one guards:
#
#   1. `check <ports>` exits NON-ZERO when any named port is closed, and ZERO
#      when they are all open. A gate that always passes is the state before
#      #8040 — every harness discovered the missing listener itself, after
#      spending a deploy and the shared cluster lock.
#   2. `check` is SCOPED: a closed port that the caller did not name must not
#      fail it. Requiring all 24 would be an over-rejection that blocks a
#      two-port smoke on an unrelated class, and a gate people learn to skip
#      is a gate that is not there.
#   3. When it DOES fail, it names every missing port — not just the first.
#      Failing on the first hole is exactly the rediscovery loop this replaces:
#      fix one port, re-run, find the next.
#
# Hermetic: `incus` is replaced by a stub on PATH that answers from a scripted
# port table, so nothing here touches a cluster.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SCRIPT_DIR}/target-services.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

# The stub answers two shapes the subject uses: `incus list ...` (target
# instance discovery) and `incus exec ... -- bash -c <script>` / `-- ping`.
# OPEN_PORTS in the environment is the scripted truth.
make_stub() {
    cat > "${TMP}/incus" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  list) exit 0 ;;                       # no instance holds the target IP
esac
# incus exec <remote>:<inst> -- <cmd...>
for a in "$@"; do shift; [[ "$a" == "--" ]] && break; done
case "${1:-}" in
  ping) exit 0 ;;                       # target answers ICMP
esac
# bash -c "<probe loop>" — re-derive the port list from the script text and
# answer from OPEN_PORTS rather than actually dialling anything.
script="${3:-}"
for p in $(grep -oE '\b[0-9]{4}\b' <<< "$script" | sort -u); do
  if [[ " ${OPEN_PORTS:-} " == *" $p "* ]]; then echo "$p open"; else echo "$p closed"; fi
done
STUB
    chmod +x "${TMP}/incus"
}
make_stub
export PATH="${TMP}:${PATH}"
# Force the direct-incus branch of incus_run: `id -nG` must appear to include
# incus-admin, or the stub is invoked through `sg` and never seen.
id() { if [[ "${1:-}" == "-nG" ]]; then echo "incus-admin"; else command id "$@"; fi; }
export -f id

run_check() {
    local open="$1"; shift
    OPEN_PORTS="$open" bash "$SUBJECT" check "$@" 2>&1
}
rc_of() {
    local open="$1"; shift
    OPEN_PORTS="$open" bash "$SUBJECT" check "$@" > /dev/null 2>&1
    echo $?
}

ALL="5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211 6200 6201 6202 6203 6204 6205 6206 6207 6208 6209 6210 6211"

# --- 1. the predicate ---------------------------------------------------
if [[ "$(rc_of "$ALL" 5202 6200)" != "0" ]]; then
    fail "check exits non-zero when every named port is OPEN — the gate would " \
         "block a healthy target and get skipped"
else
    pass "all-open named ports => rc 0"
fi

if [[ "$(rc_of "5200 5201" 5202 6200)" == "0" ]]; then
    fail "check exits ZERO with both named ports CLOSED. This is the state" \
         "before #8040: every harness rediscovers the missing listener itself," \
         "after spending a build, a deploy and the shared cluster lock"
else
    pass "named ports closed => rc 1"
fi

# The MIDDLE row: one of two named ports open. A gate that only fires when
# EVERYTHING is down passes cell 1 and cell 2 above and is still broken.
if [[ "$(rc_of "5202" 5202 6200)" == "0" ]]; then
    fail "check exits ZERO when ONE of two named ports is closed; a partially" \
         "provisioned target must fail, that is the case #8040 was filed about"
else
    pass "one of two named ports closed => rc 1"
fi

# --- 2. scoping ---------------------------------------------------------
# Everything EXCEPT 5207 is up; a caller naming 5202/6200 must pass.
NOT_5207="${ALL/5207 /}"
if [[ "$(rc_of "$NOT_5207" 5202 6200)" != "0" ]]; then
    fail "an unrelated closed port (5207) failed a check for 5202/6200." \
         "Requiring all 24 blocks a two-port smoke on a class it never sends" \
         "to, and a gate that over-rejects is one runners learn to skip"
else
    pass "unrelated closed port does not fail a scoped check"
fi

# The control for scoping: with NO arguments the predicate IS all 24, so the
# same target must fail. Without this, "scoped" could mean "checks nothing".
if [[ "$(rc_of "$NOT_5207")" == "0" ]]; then
    fail "a bare check passed with 5207 closed; the no-argument predicate must" \
         "be all 24 ports, or the scoping cell above is satisfied by a gate" \
         "that checks nothing at all"
else
    pass "bare check still fails on any closed port"
fi

# --- 3. the diagnosis ---------------------------------------------------
out="$(run_check "5200 5201 5202" 5203 5204 5205)"

# THE ASSERTION IS SCOPED TO THE ABORT LINE, and that is not a detail.
#
# A first version grepped the WHOLE output for "5203 5204 5205". It passed
# against a subject mutated to stop at the first missing port — because
# cmd_status's remediation hint prints
#
#     for p in 5200 5201 5202 5203 5204 5205 ...; do iperf3 -s -p $p -D; done
#
# which contains that exact substring no matter what the ABORT line says. The
# cell was satisfied by a line with nothing to do with the property, so the
# one mutation it existed to catch escaped it. Ask what an instrument would
# report if the thing were FALSE, and it reported the same thing.
abort_line="$(grep '^ABORT:' <<< "$out" | head -1)"
if [[ -z "$abort_line" ]]; then
    fail "no ABORT line in the failure output at all:
$out"
else
    for want in 5203 5204 5205; do
        grep -q "$want" <<< "$abort_line" \
            || fail "the ABORT line does not name missing port ${want}. Failing" \
                    "on the first hole is the rediscovery loop this replaces:" \
                    "fix one port, re-run, find the next. line was: ${abort_line}"
    done
    # And the negative half: it must not name a port that IS up, or a runner
    # restarts listeners that were never down.
    for open_port in 5200 5201 5202; do
        grep -q "$open_port" <<< "$abort_line" \
            && fail "the ABORT line names ${open_port}, which is OPEN: ${abort_line}"
    done
fi
[[ $fails -eq 0 ]] && pass "abort names every missing port and no open one"

# The full grid must appear on failure even though only three ports were
# NAMED — the predicate is narrow, the report is wide.
grep -q '6211' <<< "$out" \
    || fail "the failure report does not include the whole 24-port grid; a
runner fixes one port at a time instead of seeing every hole:
$out"

# --- summary ------------------------------------------------------------
if [[ $fails -eq 0 ]]; then
    echo "target-services selftest: all checks passed"
    exit 0
fi
echo "target-services selftest: ${fails} check(s) FAILED" >&2
exit 1

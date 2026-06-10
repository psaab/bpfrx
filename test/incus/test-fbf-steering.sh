#!/usr/bin/env bash
#
# #1827 PR-2 — two-upstream FBF steering smoke (loss userspace cluster).
#
# Applies test/incus/fbf-two-upstream-config.set atomically on the RG0
# primary, validates the filter-based-forwarding composition end to end
# at the observable surfaces, then restores the pre-test config via
# `rollback 1 | commit`.
#
# What it verifies:
#   1. commit accepts the FBF composition (forwarding instance + FBF
#      filter + ip-monitoring preferred-route INTO the forwarding
#      instance — the PR-1b rejection lifted in PR-2);
#   2. kernel side of the divergence fix: the ISP-B kernel table
#      (discovered from the PBR ip-rule band 31000+) contains the
#      instance default — before PR-2 that table was EMPTY and the
#      instance static leaked into the main table;
#   3. main table is NOT polluted by the ISP-B default;
#   4. steering: DSCP-af31 pings from the LAN host hit the steering
#      term (xpf_filter_hits_total{filter="fbf-steer",term="to-isp-b"}
#      delta > 0) while unmarked pings do not;
#   5. `show services ip-monitoring status` lists the fbf-fallback
#      policy (PASS while the ISP-B gateway answers).
#
# What it does NOT prove (single-provider lab, plan §9): true
# dual-provider failure modes, dual-public-IP SNAT, throughput under
# genuine dual-path load. Path-divergence under uplink failure is the
# smoke-runner's manual step: blackhole 172.16.80.1 upstream and watch
# the fbf-fallback policy repoint ISP-B.inet.0 at 172.16.50.1.
#
# Usage:
#   ./test/incus/test-fbf-steering.sh [loss:xpf-userspace-fw0]
#   FBF_ISP_B_GW4=172.16.80.200 ./test/incus/test-fbf-steering.sh
#     (override when 172.16.80.1 is not a live router — any live
#      VLAN-80 address works as the steering next-hop)
#   FBF_LAN_HOST=loss:cluster-userspace-host  # LAN traffic source
#
set -euo pipefail

TARGET="${1:-loss:xpf-userspace-fw0}"
[[ $# -le 1 ]] || { shift; echo "unexpected extra arguments: $*" >&2; exit 2; }
LAN_HOST="${FBF_LAN_HOST:-loss:cluster-userspace-host}"
ISP_B_GW4="${FBF_ISP_B_GW4:-172.16.80.1}"
# Any destination beyond the firewall works: the steering term matches
# on DSCP, not destination. Default to the ISP-A gateway so the control
# (unmarked) ping also has a live responder.
PING_DST="${FBF_PING_DST:-172.16.50.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/fbf-two-upstream-config.set"
REMOTE_SETS="/tmp/fbf-two-upstream.set"
CLI=/usr/local/sbin/cli

info() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -f "$CONFIG_FILE" ]] || fail "cannot find $CONFIG_FILE"

cleanup_files=()
trap 'rm -f "${cleanup_files[@]}"' EXIT

SETS_TMP="$(mktemp)"
cleanup_files+=("$SETS_TMP")
grep -E '^set ' "$CONFIG_FILE" > "$SETS_TMP"
if [[ "$ISP_B_GW4" != "172.16.80.1" ]]; then
    info "Overriding ISP-B v4 gateway: 172.16.80.1 -> $ISP_B_GW4"
    sed -i "s/172\.16\.80\.1\b/${ISP_B_GW4}/g" "$SETS_TMP"
fi

restore() {
    info "Restoring pre-test config (rollback 1 + commit)..."
    incus exec "$TARGET" -- "$CLI" <<EOF || echo "WARNING: rollback failed — inspect $TARGET manually" >&2
configure
rollback 1
commit
exit
quit
EOF
}

metric_value() {
    # xpf_filter_hits_total{family="inet",filter="fbf-steer",term="to-isp-b"}
    incus exec "$TARGET" -- sh -c \
        "curl -s 127.0.0.1:8080/metrics | grep 'xpf_filter_hits_total{' | grep 'filter=\"fbf-steer\"' | grep 'term=\"to-isp-b\"' | awk '{print \$NF}'" \
        | head -1
}

# ---- Phase 1: atomic apply (commit check, then commit) ----
incus exec "$TARGET" -- rm -f "$REMOTE_SETS" >/dev/null 2>&1 || true
incus file push --mode 0644 "$SETS_TMP" "${TARGET}/${REMOTE_SETS}" >/dev/null

CHECK_OUT="$(mktemp)"; cleanup_files+=("$CHECK_OUT")
info "commit check on $TARGET..."
if ! incus exec "$TARGET" -- "$CLI" > "$CHECK_OUT" 2>&1 <<EOF
configure
load merge ${REMOTE_SETS}
commit check
exit
quit
EOF
then
    cat "$CHECK_OUT" >&2
    fail "commit check failed (candidate invalid; live state unchanged)"
fi

APPLY_OUT="$(mktemp)"; cleanup_files+=("$APPLY_OUT")
info "committing FBF two-upstream fixture..."
if ! incus exec "$TARGET" -- "$CLI" > "$APPLY_OUT" 2>&1 <<EOF
configure
load merge ${REMOTE_SETS}
commit
exit
quit
EOF
then
    cat "$APPLY_OUT" >&2
    fail "commit failed after commit-check passed"
fi
# From here on, always restore on exit.
trap 'restore; rm -f "${cleanup_files[@]}"' EXIT
sleep 3

# ---- Phase 2: kernel side of the divergence fix ----
info "Discovering ISP-B kernel table from the PBR ip-rule band..."
PBR_TABLE="$(incus exec "$TARGET" -- sh -c \
    "ip rule show | awk -F'lookup ' '\$1 ~ /^31[0-9][0-9][0-9]:/ {print \$2; exit}'" | tr -d '[:space:]')"
[[ -n "$PBR_TABLE" ]] || fail "no PBR ip rule in the 31000+ band (FBF kernel rule missing)"
info "PBR rule -> table $PBR_TABLE"

ROUTES="$(incus exec "$TARGET" -- ip route show table "$PBR_TABLE")"
echo "$ROUTES" | grep -q "default via ${ISP_B_GW4}" \
    || fail "ISP-B kernel table $PBR_TABLE lacks 'default via ${ISP_B_GW4}' — FRR table rendering broken (pre-PR-2 divergence): ${ROUTES:-<empty>}"
info "ISP-B table $PBR_TABLE holds the instance default (divergence fix OK)"

MAIN_DEFAULTS="$(incus exec "$TARGET" -- sh -c "ip route show default | grep -c 'via ${ISP_B_GW4}'" || true)"
[[ "${MAIN_DEFAULTS:-0}" -eq 0 ]] \
    || fail "ISP-B default leaked into the MAIN table (pre-PR-2 pollution)"

# ---- Phase 3: steering counter ----
BEFORE="$(metric_value)"; BEFORE="${BEFORE:-0}"
info "Steering-term hits before: $BEFORE"

info "Sending 5 DSCP-af31 pings (tos 0x68) from $LAN_HOST to $PING_DST..."
incus exec "$LAN_HOST" -- ping -c 5 -W 2 -Q 0x68 "$PING_DST" >/dev/null 2>&1 || true
info "Sending 5 unmarked control pings..."
incus exec "$LAN_HOST" -- ping -c 5 -W 2 "$PING_DST" >/dev/null 2>&1 || true
sleep 2

AFTER="$(metric_value)"; AFTER="${AFTER:-0}"
info "Steering-term hits after: $AFTER"
DELTA="$(awk -v a="$AFTER" -v b="$BEFORE" 'BEGIN{print a-b}')"
awk -v d="$DELTA" 'BEGIN{exit !(d >= 5)}' \
    || fail "steering counter delta $DELTA < 5 — af31 traffic not hitting the FBF term"
awk -v d="$DELTA" 'BEGIN{exit !(d <= 9)}' \
    || fail "steering counter delta $DELTA > 9 — unmarked control traffic also steered"
info "Steering counter delta $DELTA (marked traffic only) OK"

# ---- Phase 4: ip-monitoring composition ----
STATUS="$(incus exec "$TARGET" -- "$CLI" -c "show services ip-monitoring status" 2>/dev/null || true)"
echo "$STATUS" | grep -q "fbf-fallback" \
    || fail "fbf-fallback policy missing from 'show services ip-monitoring status':
$STATUS"
info "ip-monitoring fbf-fallback policy present:"
echo "$STATUS" | sed 's/^/    /'

info "PASS: FBF two-upstream steering smoke complete (config will be rolled back)"

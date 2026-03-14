#!/usr/bin/env bash
# Analyze bpfrxd journal output from the userspace dataplane helper.
#
# Parses periodic "DBG wN:" worker stats, RST_DETECT, STALL_*, OVERSIZED_RX,
# BUILT_ETH, POISON_DETECTED, TX errors, and frame accounting lines emitted
# by the bpfrx-userspace-dp Rust helper to stderr (captured by journald).
#
# Usage:
#   ./test/incus/analyze-userspace-traces.sh [instance] [since]
#   ./test/incus/analyze-userspace-traces.sh bpfrx-userspace-fw0 "10 minutes ago"
#   REMOTE=loss ./test/incus/analyze-userspace-traces.sh

set -euo pipefail

INSTANCE="${1:-bpfrx-userspace-fw1}"
SINCE="${2:-5 minutes ago}"
REMOTE="${REMOTE:-loss}"

# ── Color helpers ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { printf "${GREEN}OK${RESET}: %s\n" "$*"; }
warn() { printf "${YELLOW}WARN${RESET}: %s\n" "$*"; }
err()  { printf "${RED}ERROR${RESET}: %s\n" "$*"; }
hdr()  { printf "\n${BOLD}${CYAN}=== %s ===${RESET}\n" "$*"; }
sub()  { printf "  ${BOLD}%s${RESET}\n" "$*"; }
note() { printf "  %s\n" "$*"; }
flag() { printf "  ${RED}!! %s${RESET}\n" "$*"; }
star() { printf "  ${YELLOW}** %s${RESET}\n" "$*"; }

# ── Pull journal ──────────────────────────────────────────────────────
TMPFILE=$(mktemp /tmp/bpfrx-trace-XXXXXX.log)
trap 'rm -f "$TMPFILE"' EXIT

echo "Pulling journal from ${REMOTE}:${INSTANCE} (since \"${SINCE}\")..."
if ! incus exec "${REMOTE}:${INSTANCE}" -- journalctl -u bpfrxd --since "$SINCE" --no-pager > "$TMPFILE" 2>/dev/null; then
    err "Failed to pull journal from ${REMOTE}:${INSTANCE}"
    echo "Hint: ensure the instance is running and accessible."
    exit 1
fi

TOTAL_LINES=$(wc -l < "$TMPFILE")
if [ "$TOTAL_LINES" -eq 0 ]; then
    err "No journal output found for bpfrxd since \"${SINCE}\""
    exit 1
fi
echo "Captured ${TOTAL_LINES} journal lines."

# ── Pre-extract commonly used data ───────────────────────────────────
LAST_WORKER_LINE=$(grep 'DBG w[0-9]*:' "$TMPFILE" | tail -1 || true)

# ── Helper: extract timestamp from a journal line ─────────────────────
# Journal format: "Mar 13 10:36:45 hostname bpfrxd[PID]: ..."
# We extract the time portion.
extract_time() {
    echo "$1" | awk '{print $3}'
}

# ═══════════════════════════════════════════════════════════════════════
# Section 1: Worker Activity Summary
# ═══════════════════════════════════════════════════════════════════════
hdr "Worker Activity Summary"

# Parse all "DBG wN:" lines.
# Format: DBG w0: 1.0s rx=1241 tx=1241 fwd=1241 local=0 sess_hit=... no_route=... miss_neigh=...
#         pol_deny=... ha_inact=... no_egress=... build_fail=... tx_err=... meta_err=... other=...
#         DIR:trust_rx=.../wan_rx=.../t2w=.../w2t=...
#         RST:rx=.../tx=...
#         TCP_FWD:fin=.../rst=.../zwin=...
#         bindings: [...]

WORKER_LINES=$(grep -c 'DBG w[0-9]*:' "$TMPFILE" 2>/dev/null || echo 0)

if [ "$WORKER_LINES" -eq 0 ]; then
    note "No worker stat lines found."
else
    # For each worker, find peak rx, detect stalls, flag errors.
    # Collect unique worker IDs.
    WORKER_IDS=$(grep -oP 'DBG w\K[0-9]+' "$TMPFILE" | sort -un)

    for WID in $WORKER_IDS; do
        # Extract all lines for this worker with timestamps
        WLINES=$(grep "DBG w${WID}:" "$TMPFILE")

        # Find peak rx
        PEAK_RX=0
        PEAK_RX_TIME=""
        PEAK_FWD=0
        PEAK_TX=0
        TOTAL_TRUST_RX=0
        TOTAL_WAN_RX=0
        TOTAL_POL_DENY=0
        TOTAL_NO_ROUTE=0
        TOTAL_MISS_NEIGH=0
        TOTAL_HA_INACT=0
        TOTAL_BUILD_FAIL=0
        TOTAL_TX_ERR=0
        TOTAL_META_ERR=0
        TOTAL_RX=0
        TOTAL_FWD=0
        HAS_TRAFFIC=0
        STALL_DETECTED=0
        PREV_FWD=0
        STALL_TIME=""

        while IFS= read -r line; do
            TSTAMP=$(extract_time "$line")

            # Extract counters using parameter expansion and sed
            RX=$(echo "$line" | sed -n 's/.* rx=\([0-9]*\) .*/\1/p')
            TX=$(echo "$line" | sed -n 's/.* tx=\([0-9]*\) .*/\1/p')
            FWD=$(echo "$line" | sed -n 's/.* fwd=\([0-9]*\) .*/\1/p')
            TRUST_RX=$(echo "$line" | sed -n 's/.*trust_rx=\([0-9]*\).*/\1/p')
            WAN_RX=$(echo "$line" | sed -n 's/.*wan_rx=\([0-9]*\).*/\1/p')
            POL_DENY=$(echo "$line" | sed -n 's/.*pol_deny=\([0-9]*\).*/\1/p')
            NO_ROUTE=$(echo "$line" | sed -n 's/.*no_route=\([0-9]*\).*/\1/p')
            MISS_NEIGH=$(echo "$line" | sed -n 's/.*miss_neigh=\([0-9]*\).*/\1/p')
            HA_INACT=$(echo "$line" | sed -n 's/.*ha_inact=\([0-9]*\).*/\1/p')
            BUILD_FAIL=$(echo "$line" | sed -n 's/.*build_fail=\([0-9]*\).*/\1/p')
            TX_ERR=$(echo "$line" | sed -n 's/.*tx_err=\([0-9]*\).*/\1/p')
            META_ERR=$(echo "$line" | sed -n 's/.*meta_err=\([0-9]*\).*/\1/p')

            RX=${RX:-0}; TX=${TX:-0}; FWD=${FWD:-0}
            TRUST_RX=${TRUST_RX:-0}; WAN_RX=${WAN_RX:-0}
            POL_DENY=${POL_DENY:-0}; NO_ROUTE=${NO_ROUTE:-0}
            MISS_NEIGH=${MISS_NEIGH:-0}; HA_INACT=${HA_INACT:-0}
            BUILD_FAIL=${BUILD_FAIL:-0}; TX_ERR=${TX_ERR:-0}; META_ERR=${META_ERR:-0}

            TOTAL_RX=$((TOTAL_RX + RX))
            TOTAL_FWD=$((TOTAL_FWD + FWD))
            TOTAL_TRUST_RX=$((TOTAL_TRUST_RX + TRUST_RX))
            TOTAL_WAN_RX=$((TOTAL_WAN_RX + WAN_RX))
            TOTAL_POL_DENY=$((TOTAL_POL_DENY + POL_DENY))
            TOTAL_NO_ROUTE=$((TOTAL_NO_ROUTE + NO_ROUTE))
            TOTAL_MISS_NEIGH=$((TOTAL_MISS_NEIGH + MISS_NEIGH))
            TOTAL_HA_INACT=$((TOTAL_HA_INACT + HA_INACT))
            TOTAL_BUILD_FAIL=$((TOTAL_BUILD_FAIL + BUILD_FAIL))
            TOTAL_TX_ERR=$((TOTAL_TX_ERR + TX_ERR))
            TOTAL_META_ERR=$((TOTAL_META_ERR + META_ERR))

            if [ "$RX" -gt 0 ] || [ "$FWD" -gt 0 ]; then
                HAS_TRAFFIC=1
            fi

            if [ "$RX" -gt "$PEAK_RX" ]; then
                PEAK_RX=$RX
                PEAK_RX_TIME=$TSTAMP
            fi
            if [ "$FWD" -gt "$PEAK_FWD" ]; then
                PEAK_FWD=$FWD
            fi
            if [ "$TX" -gt "$PEAK_TX" ]; then
                PEAK_TX=$TX
            fi

            # Stall detection: previous interval had fwd > 10 but now fwd=0
            if [ "$PREV_FWD" -gt 10 ] && [ "$FWD" -eq 0 ] && [ "$STALL_DETECTED" -eq 0 ]; then
                STALL_DETECTED=1
                STALL_TIME=$TSTAMP
            fi
            PREV_FWD=$FWD

        done <<< "$WLINES"

        if [ "$HAS_TRAFFIC" -eq 0 ]; then
            note "Worker ${WID}: idle (no traffic)"
            continue
        fi

        sub "Worker ${WID}: peak rx=${PEAK_RX}/s at ${PEAK_RX_TIME}, fwd=${PEAK_FWD}/s, tx=${PEAK_TX}/s, trust_rx=${TOTAL_TRUST_RX}, wan_rx=${TOTAL_WAN_RX}"

        if [ "$STALL_DETECTED" -eq 1 ]; then
            star "STALL at ${STALL_TIME}: fwd dropped to 0 after ${PREV_FWD}/s"
        fi

        # Flag error counters
        if [ "$TOTAL_POL_DENY" -gt 0 ]; then
            note "  pol_deny=${TOTAL_POL_DENY}"
        fi
        if [ "$TOTAL_NO_ROUTE" -gt 0 ]; then
            warn "  no_route=${TOTAL_NO_ROUTE}"
        fi
        if [ "$TOTAL_MISS_NEIGH" -gt 0 ]; then
            warn "  miss_neigh=${TOTAL_MISS_NEIGH}"
        fi
        if [ "$TOTAL_HA_INACT" -gt 0 ]; then
            warn "  ha_inact=${TOTAL_HA_INACT}"
        fi
        if [ "$TOTAL_BUILD_FAIL" -gt 0 ]; then
            err "  build_fail=${TOTAL_BUILD_FAIL}"
        fi
        if [ "$TOTAL_TX_ERR" -gt 0 ]; then
            err "  tx_err=${TOTAL_TX_ERR}"
        fi
        if [ "$TOTAL_META_ERR" -gt 0 ]; then
            err "  meta_err=${TOTAL_META_ERR}"
        fi
    done
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 2: Binding State
# ═══════════════════════════════════════════════════════════════════════
hdr "Binding State"

# Parse binding detail from the last DBG wN: line (most recent snapshot).
# Binding format inside brackets:
#   [0:if5q3 pfill=... fring=... rxring=... free_tx=... otx=... ifl=... scr=... ptxp=... ptxl=...
#    total=.../... fill_ok=... polls=... bp=... rx_empty=... wake=...
#    TX:ring_sub=.../ring_full=.../compl=.../sendto=.../err=.../eagain=.../enobufs=.../overflow=.../rst=...
#    xsk:drop=.../inv=.../rfull=.../fempty=.../tinv=.../tempty=...
#    RAW:rxP=.../rxC=.../frP=.../frC=.../txP=.../txC=.../crP=.../crC=...
#    FRAME_LEAK:N]

if [ -n "$LAST_WORKER_LINE" ]; then
    LAST_TIME=$(extract_time "$LAST_WORKER_LINE")

    # Extract all binding blocks: [N:ifXqY ...]
    # Each binding is enclosed in brackets. Extract them.
    BINDINGS=$(echo "$LAST_WORKER_LINE" | grep -oP '\[\d+:if\d+q\d+[^\]]*\]' || true)

    if [ -z "$BINDINGS" ]; then
        note "No binding details in last worker line."
    else
        ANY_BP=0
        ANY_LEAK=0
        ANY_XSK_DROP=0
        ANY_ENOBUFS=0
        ANY_EAGAIN=0
        ANY_OVERFLOW=0

        while IFS= read -r binding; do
            # Parse binding identity
            BIND_ID=$(echo "$binding" | grep -oP '\d+:if\d+q\d+')
            IFNUM=$(echo "$BIND_ID" | grep -oP 'if\K\d+')
            QNUM=$(echo "$BIND_ID" | grep -oP 'q\K\d+')

            # Determine trust vs WAN side
            SIDE=""
            if [ "$IFNUM" -le 5 ]; then
                SIDE="(trust-side)"
            else
                SIDE="(WAN-side)"
            fi

            # Extract key metrics
            BP=$(echo "$binding" | grep -oP 'bp=\K[0-9]+' || echo 0)
            TOTAL=$(echo "$binding" | grep -oP 'total=\K[0-9]+/[0-9]+' || echo "?/?")
            TOTAL_ACTUAL=$(echo "$TOTAL" | cut -d/ -f1)
            TOTAL_EXPECTED=$(echo "$TOTAL" | cut -d/ -f2)

            # XSK stats
            XSK_DROP=$(echo "$binding" | grep -oP 'xsk:drop=\K[0-9]+' || echo 0)
            XSK_RFULL=$(echo "$binding" | grep -oP 'rfull=\K[0-9]+' || echo 0)
            XSK_FEMPTY=$(echo "$binding" | grep -oP 'fempty=\K[0-9]+' || echo 0)

            # TX errors
            TX_EAGAIN=$(echo "$binding" | grep -oP 'eagain=\K[0-9]+' || echo 0)
            TX_ENOBUFS=$(echo "$binding" | grep -oP 'enobufs=\K[0-9]+' || echo 0)
            TX_OVERFLOW=$(echo "$binding" | grep -oP 'overflow=\K[0-9]+' || echo 0)
            TX_ERR=$(echo "$binding" | grep -oP 'TX:ring_sub=[0-9]*/ring_full=[0-9]*/compl=[0-9]*/sendto=[0-9]*/err=\K[0-9]+' || echo 0)

            # RAW ring state
            RAW_RXP=$(echo "$binding" | grep -oP 'RAW:rxP=\K[0-9]+' || echo "?")
            RAW_RXC=$(echo "$binding" | grep -oP 'rxC=\K[0-9]+' || echo "?")
            RAW_FRP=$(echo "$binding" | grep -oP 'frP=\K[0-9]+' || echo "?")
            RAW_FRC=$(echo "$binding" | grep -oP 'frC=\K[0-9]+' || echo "?")
            RAW_TXP=$(echo "$binding" | grep -oP 'txP=\K[0-9]+' || echo "?")
            RAW_TXC=$(echo "$binding" | grep -oP 'txC=\K[0-9]+' || echo "?")

            # Frame leak
            FRAME_LEAK=$(echo "$binding" | grep -oP 'FRAME_LEAK:\K-?[0-9]+' || echo "")

            # SO_ERROR
            SO_ERR=$(echo "$binding" | grep -oP 'SO_ERR=\K[0-9]+' || echo "")

            # Display binding summary
            sub "[if${IFNUM}q${QNUM}] ${SIDE} total=${TOTAL} RAW:rxP=${RAW_RXP} frP=${RAW_FRP} txP=${RAW_TXP}"

            # Flag issues
            if [ "$BP" -gt 0 ]; then
                flag "Backpressure events: ${BP}"
                ANY_BP=1
            fi

            if [ -n "$FRAME_LEAK" ]; then
                flag "Frame leak detected: ${FRAME_LEAK} frames"
                ANY_LEAK=1
            fi

            if [ "$XSK_DROP" -gt 0 ] || [ "$XSK_RFULL" -gt 0 ] || [ "$XSK_FEMPTY" -gt 0 ]; then
                flag "XSK drops: drop=${XSK_DROP} rfull=${XSK_RFULL} fempty=${XSK_FEMPTY}"
                ANY_XSK_DROP=1
            fi

            if [ "$TX_ENOBUFS" -gt 0 ]; then
                flag "ENOBUFS errors: ${TX_ENOBUFS}"
                ANY_ENOBUFS=1
            fi

            if [ "$TX_EAGAIN" -gt 0 ]; then
                note "  EAGAIN: ${TX_EAGAIN} (normal for MSG_DONTWAIT)"
            fi

            if [ "$TX_OVERFLOW" -gt 0 ]; then
                flag "Pending overflow drops: ${TX_OVERFLOW}"
                ANY_OVERFLOW=1
            fi

            if [ "$TX_ERR" -gt 0 ]; then
                flag "TX sendto errors: ${TX_ERR}"
            fi

            if [ -n "$SO_ERR" ]; then
                flag "Socket error (SO_ERROR): ${SO_ERR}"
            fi

        done <<< "$BINDINGS"

        # Summary line for binding health
        echo ""
        if [ "$ANY_LEAK" -eq 0 ]; then
            ok "No frame leaks (all bindings total=${TOTAL_ACTUAL}/${TOTAL_EXPECTED})"
        fi
        if [ "$ANY_BP" -eq 0 ]; then
            ok "No backpressure events"
        fi
        if [ "$ANY_XSK_DROP" -eq 0 ]; then
            ok "No XSK drops"
        fi
        if [ "$ANY_ENOBUFS" -eq 0 ]; then
            ok "No ENOBUFS errors"
        fi
        if [ "$ANY_OVERFLOW" -eq 0 ]; then
            ok "No pending overflow drops"
        fi
    fi
else
    note "No worker stat lines found — cannot show binding state."
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 3: Binding State Over Time
# ═══════════════════════════════════════════════════════════════════════
# Track RAW ring rxP changes across intervals to detect frozen RX.

hdr "RAW Ring Tracking (rxP changes)"

# Extract RAW:rxP values per binding across time from all worker lines.
# We look for patterns like [0:if5q3 ... RAW:rxP=N...]
RAW_TRACKING=$(grep 'DBG w[0-9]*:' "$TMPFILE" | grep -oP '\[\d+:if\d+q\d+[^\]]*RAW:rxP=\d+[^\]]*\]' || true)

if [ -z "$RAW_TRACKING" ]; then
    note "No RAW ring data found."
else
    # Collect unique binding identifiers
    BIND_IDS=$(echo "$RAW_TRACKING" | grep -oP '\d+:if\d+q\d+' | sort -u)

    for BID in $BIND_IDS; do
        # Get all rxP values for this binding
        RXP_VALUES=$(echo "$RAW_TRACKING" | grep "$BID" | grep -oP 'RAW:rxP=\K[0-9]+')
        FIRST_RXP=$(echo "$RXP_VALUES" | head -1)
        LAST_RXP=$(echo "$RXP_VALUES" | tail -1)
        NUM_SAMPLES=$(echo "$RXP_VALUES" | wc -l)

        if [ "$FIRST_RXP" = "$LAST_RXP" ] && [ "$NUM_SAMPLES" -gt 1 ]; then
            IFNUM=$(echo "$BID" | grep -oP 'if\K\d+')
            if [ "$IFNUM" -le 5 ]; then
                SIDE="Trust-side"
            else
                SIDE="WAN-side"
            fi
            flag "[${BID}] rxP frozen at ${FIRST_RXP} across ${NUM_SAMPLES} samples -- ${SIDE} RX may be stalled"
        else
            DELTA=$((LAST_RXP - FIRST_RXP))
            note "[${BID}] rxP: ${FIRST_RXP} -> ${LAST_RXP} (delta=${DELTA} over ${NUM_SAMPLES} samples)"
        fi
    done
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 4: RST Analysis
# ═══════════════════════════════════════════════════════════════════════
hdr "RST Analysis"

RX_RST_COUNT=$(grep -c 'RST_DETECT RX\[' "$TMPFILE" 2>/dev/null || echo 0)
TX_RST_COUNT=$(grep -c 'RST_DETECT TX\[' "$TMPFILE" 2>/dev/null || echo 0)
PREP_TX_RST_COUNT=$(grep -c 'RST_DETECT PREP_TX\[' "$TMPFILE" 2>/dev/null || echo 0)
TOTAL_TX_RST=$((TX_RST_COUNT + PREP_TX_RST_COUNT))

if [ "$RX_RST_COUNT" -eq 0 ] && [ "$TOTAL_TX_RST" -eq 0 ]; then
    ok "No RST packets detected"
else
    # Count RX RSTs by interface/queue
    if [ "$RX_RST_COUNT" -gt 0 ]; then
        note "RX RSTs: ${RX_RST_COUNT}"
        RX_RST_BY_IF=$(grep 'RST_DETECT RX\[' "$TMPFILE" | grep -oP 'if=\d+ q=\d+' | sort | uniq -c | sort -rn)
        while IFS= read -r ifline; do
            note "  ${ifline}"
        done <<< "$RX_RST_BY_IF"

        # Show first 3 RST summaries
        note ""
        note "First RX RSTs:"
        grep 'RST_DETECT RX\[' "$TMPFILE" | head -3 | while IFS= read -r line; do
            # Strip journal prefix, show just the RST_DETECT part
            RST_PART=$(echo "$line" | grep -oP 'RST_DETECT RX\[.*')
            TSTAMP=$(extract_time "$line")
            note "  ${TSTAMP} ${RST_PART}"
        done
    fi

    if [ "$TOTAL_TX_RST" -gt 0 ]; then
        note ""
        note "TX RSTs: ${TOTAL_TX_RST} (TX=${TX_RST_COUNT}, PREP_TX=${PREP_TX_RST_COUNT})"
        TX_RST_BY_IF=$(grep -E 'RST_DETECT (TX|PREP_TX)\[' "$TMPFILE" | grep -oP 'if=\d+ q=\d+' | sort | uniq -c | sort -rn || true)
        if [ -n "$TX_RST_BY_IF" ]; then
            while IFS= read -r ifline; do
                note "  ${ifline}"
            done <<< "$TX_RST_BY_IF"
        fi

        # Show first 3 TX RST summaries
        note ""
        note "First TX RSTs:"
        grep -E 'RST_DETECT (TX|PREP_TX)\[' "$TMPFILE" | head -3 | while IFS= read -r line; do
            RST_PART=$(echo "$line" | grep -oP 'RST_DETECT (TX|PREP_TX)\[.*')
            TSTAMP=$(extract_time "$line")
            note "  ${TSTAMP} ${RST_PART}"
        done
    fi

    # Check for TCP_FWD:rst=0 mismatch
    if [ "$TOTAL_TX_RST" -gt 0 ]; then
        # Look in the last worker line for TCP_FWD:rst=
        FWD_RST=$(echo "$LAST_WORKER_LINE" | grep -oP 'TCP_FWD:fin=\d+/rst=\K\d+' || echo "?")
        if [ "$FWD_RST" = "0" ]; then
            flag "TX RSTs detected (${TOTAL_TX_RST}) but TCP_FWD:rst=0 -- RSTs not from forward path"
        elif [ "$FWD_RST" != "?" ]; then
            note "TCP_FWD:rst=${FWD_RST}"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 5: Stall Detection
# ═══════════════════════════════════════════════════════════════════════
hdr "Stall Detection"

STALL_DETECTED_COUNT=$(grep -c 'STALL_DETECTED' "$TMPFILE" 2>/dev/null || echo 0)
STALL_BINDING_COUNT=$(grep -c 'STALL_BINDING' "$TMPFILE" 2>/dev/null || echo 0)
STALL_SESSION_COUNT=$(grep -c 'STALL_SESSIONS' "$TMPFILE" 2>/dev/null || echo 0)

if [ "$STALL_DETECTED_COUNT" -eq 0 ]; then
    ok "No stalls detected"
else
    err "${STALL_DETECTED_COUNT} stall event(s) detected"

    # Show stall details
    grep 'STALL_DETECTED' "$TMPFILE" | while IFS= read -r line; do
        TSTAMP=$(extract_time "$line")
        STALL_DETAIL=$(echo "$line" | grep -oP 'STALL_DETECTED:.*')
        flag "${TSTAMP} ${STALL_DETAIL}"
    done

    # Show stall binding state
    if [ "$STALL_BINDING_COUNT" -gt 0 ]; then
        note ""
        note "Stall binding state:"
        grep 'STALL_BINDING' "$TMPFILE" | while IFS= read -r line; do
            BIND_DETAIL=$(echo "$line" | grep -oP 'STALL_BINDING\[.*')
            note "  ${BIND_DETAIL}"
        done
    fi

    # Show sessions at stall time
    if [ "$STALL_SESSION_COUNT" -gt 0 ]; then
        note ""
        note "Sessions at stall time:"
        grep 'STALL_SESSIONS' "$TMPFILE" | head -3 | while IFS= read -r line; do
            SESS_DETAIL=$(echo "$line" | grep -oP 'STALL_SESSIONS:.*')
            note "  ${SESS_DETAIL}"
        done
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 6: Oversized Frames
# ═══════════════════════════════════════════════════════════════════════
hdr "Oversized Frames"

OVERSIZED_COUNT=$(grep -c 'OVERSIZED_RX' "$TMPFILE" 2>/dev/null || echo 0)

if [ "$OVERSIZED_COUNT" -eq 0 ]; then
    ok "No oversized frames"
else
    warn "${OVERSIZED_COUNT} oversized frame log entries"

    # Also check the SIZE: counters in the last worker line for total count
    RX_OVER=$(echo "$LAST_WORKER_LINE" | grep -oP 'rx_over=\K\d+' || echo "?")
    if [ "$RX_OVER" != "?" ] && [ "$RX_OVER" != "0" ]; then
        note "Last interval rx_over=${RX_OVER}"
    fi

    # Show first 5 oversized entries
    note ""
    note "First oversized frames:"
    grep 'OVERSIZED_RX' "$TMPFILE" | head -5 | while IFS= read -r line; do
        TSTAMP=$(extract_time "$line")
        DETAIL=$(echo "$line" | grep -oP 'OVERSIZED_RX\[.*')
        note "  ${TSTAMP} ${DETAIL}"
    done
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 7: Frame Build Debug
# ═══════════════════════════════════════════════════════════════════════
hdr "Frame Build Debug"

BUILT_COUNT=$(grep -c 'DBG BUILT_ETH' "$TMPFILE" 2>/dev/null || echo 0)
BUILD_FAIL_COUNT=$(grep -c 'DBG BUILD_FAIL' "$TMPFILE" 2>/dev/null || echo 0)

if [ "$BUILT_COUNT" -eq 0 ] && [ "$BUILD_FAIL_COUNT" -eq 0 ]; then
    ok "No frame build debug entries"
else
    if [ "$BUILT_COUNT" -gt 0 ]; then
        note "${BUILT_COUNT} BUILT_ETH log entries"
        note ""
        note "First built frames:"
        grep 'DBG BUILT_ETH' "$TMPFILE" | head -5 | while IFS= read -r line; do
            TSTAMP=$(extract_time "$line")
            DETAIL=$(echo "$line" | grep -oP 'BUILT_ETH\[.*')
            note "  ${TSTAMP} ${DETAIL}"
        done
    fi

    if [ "$BUILD_FAIL_COUNT" -gt 0 ]; then
        err "${BUILD_FAIL_COUNT} BUILD_FAIL entries"
        grep 'DBG BUILD_FAIL' "$TMPFILE" | head -5 | while IFS= read -r line; do
            TSTAMP=$(extract_time "$line")
            DETAIL=$(echo "$line" | grep -oP 'BUILD_FAIL:.*')
            note "  ${TSTAMP} ${DETAIL}"
        done
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 8: Poison Detection
# ═══════════════════════════════════════════════════════════════════════
hdr "Poison Detection"

POISON_COUNT=$(grep -c 'POISON_DETECTED' "$TMPFILE" 2>/dev/null || echo 0)

if [ "$POISON_COUNT" -eq 0 ]; then
    ok "No poisoned frames detected"
else
    err "${POISON_COUNT} poisoned frame(s) detected -- kernel recycled descriptor without writing data"
    grep 'POISON_DETECTED' "$TMPFILE" | head -5 | while IFS= read -r line; do
        TSTAMP=$(extract_time "$line")
        DETAIL=$(echo "$line" | grep -oP 'POISON_DETECTED:.*')
        flag "${TSTAMP} ${DETAIL}"
    done
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 9: TX Pipeline Errors
# ═══════════════════════════════════════════════════════════════════════
hdr "TX Pipeline Errors"

ENOBUFS_COUNT=$(grep -c 'TX_ENOBUFS' "$TMPFILE" 2>/dev/null || echo 0)
RST_CORRUPT_COUNT=$(grep -c 'BUILD_RST_CORRUPT' "$TMPFILE" 2>/dev/null || echo 0)

if [ "$ENOBUFS_COUNT" -eq 0 ] && [ "$RST_CORRUPT_COUNT" -eq 0 ]; then
    ok "No TX pipeline errors"
else
    if [ "$ENOBUFS_COUNT" -gt 0 ]; then
        err "${ENOBUFS_COUNT} ENOBUFS events (kernel TX drops)"
        grep 'TX_ENOBUFS' "$TMPFILE" | head -3 | while IFS= read -r line; do
            TSTAMP=$(extract_time "$line")
            DETAIL=$(echo "$line" | grep -oP 'TX_ENOBUFS:.*')
            note "  ${TSTAMP} ${DETAIL}"
        done
    fi

    if [ "$RST_CORRUPT_COUNT" -gt 0 ]; then
        err "${RST_CORRUPT_COUNT} RST corruption events (frame build introduced RST)"
        grep 'BUILD_RST_CORRUPT' "$TMPFILE" | head -3 | while IFS= read -r line; do
            TSTAMP=$(extract_time "$line")
            DETAIL=$(echo "$line" | grep -oP 'BUILD_RST_CORRUPT.*')
            note "  ${TSTAMP} ${DETAIL}"
        done
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 10: TCP Events
# ═══════════════════════════════════════════════════════════════════════
hdr "TCP Events"

ZERO_WIN_COUNT=$(grep -c 'RX_TCP_ZERO_WIN' "$TMPFILE" 2>/dev/null || echo 0)

if [ -n "$LAST_WORKER_LINE" ]; then
    TCP_RX_FIN=$(echo "$LAST_WORKER_LINE" | grep -oP 'TCP_RX:fin=\K\d+' || echo "0")
    TCP_RX_SYNACK=$(echo "$LAST_WORKER_LINE" | grep -oP 'synack=\K\d+' | head -1 || echo "0")
    TCP_RX_ZWIN=$(echo "$LAST_WORKER_LINE" | grep -oP 'TCP_RX:fin=\d+/synack=\d+/zwin=\K\d+' || echo "0")
    TCP_FWD_FIN=$(echo "$LAST_WORKER_LINE" | grep -oP 'TCP_FWD:fin=\K\d+' || echo "0")
    TCP_FWD_RST=$(echo "$LAST_WORKER_LINE" | grep -oP 'TCP_FWD:fin=\d+/rst=\K\d+' || echo "0")
    TCP_FWD_ZWIN=$(echo "$LAST_WORKER_LINE" | grep -oP 'TCP_FWD:fin=\d+/rst=\d+/zwin=\K\d+' || echo "0")

    note "Last interval: TCP_RX: fin=${TCP_RX_FIN} synack=${TCP_RX_SYNACK} zwin=${TCP_RX_ZWIN}"
    note "Last interval: TCP_FWD: fin=${TCP_FWD_FIN} rst=${TCP_FWD_RST} zwin=${TCP_FWD_ZWIN}"
fi

if [ "$ZERO_WIN_COUNT" -gt 0 ]; then
    warn "${ZERO_WIN_COUNT} zero-window TCP events"
    grep 'RX_TCP_ZERO_WIN' "$TMPFILE" | head -3 | while IFS= read -r line; do
        TSTAMP=$(extract_time "$line")
        DETAIL=$(echo "$line" | grep -oP 'RX_TCP_ZERO_WIN\[.*')
        note "  ${TSTAMP} ${DETAIL}"
    done
else
    ok "No zero-window TCP events"
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 11: Checksum Verification
# ═══════════════════════════════════════════════════════════════════════
hdr "Checksum Verification"

if [ -n "$LAST_WORKER_LINE" ]; then
    CSUM_VERIFIED=$(echo "$LAST_WORKER_LINE" | grep -oP 'CSUM:verified=\K\d+' || echo "0")
    CSUM_BAD_IP=$(echo "$LAST_WORKER_LINE" | grep -oP 'bad_ip=\K\d+' || echo "0")
    CSUM_BAD_L4=$(echo "$LAST_WORKER_LINE" | grep -oP 'bad_l4=\K\d+' || echo "0")

    note "Last interval: verified=${CSUM_VERIFIED} bad_ip=${CSUM_BAD_IP} bad_l4=${CSUM_BAD_L4}"
    if [ "$CSUM_BAD_IP" -gt 0 ] || [ "$CSUM_BAD_L4" -gt 0 ]; then
        err "Checksum errors detected: bad_ip=${CSUM_BAD_IP} bad_l4=${CSUM_BAD_L4}"
    else
        ok "No checksum errors"
    fi
else
    note "No worker stats available for checksum data."
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 12: Session BPF Sync
# ═══════════════════════════════════════════════════════════════════════
hdr "Session BPF Sync"

if [ -n "$LAST_WORKER_LINE" ]; then
    SESS_VERIFY_OK=$(echo "$LAST_WORKER_LINE" | grep -oP 'SESS_BPF:verify_ok=\K\d+' || echo "0")
    SESS_VERIFY_FAIL=$(echo "$LAST_WORKER_LINE" | grep -oP 'verify_fail=\K\d+' || echo "0")
    SESS_BPF_ENTRIES=$(echo "$LAST_WORKER_LINE" | grep -oP 'bpf_entries=\K\d+' || echo "0")

    note "Last interval: verify_ok=${SESS_VERIFY_OK} verify_fail=${SESS_VERIFY_FAIL} bpf_entries=${SESS_BPF_ENTRIES}"
    if [ "$SESS_VERIFY_FAIL" -gt 0 ]; then
        warn "Session BPF verify failures: ${SESS_VERIFY_FAIL}"
    else
        ok "No session BPF verify failures"
    fi
else
    note "No worker stats available for session BPF data."
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 13: Error Summary
# ═══════════════════════════════════════════════════════════════════════
hdr "Error Summary"

# Aggregate all error-related counters from ALL worker lines (not just last)
if [ "$WORKER_LINES" -gt 0 ]; then
    # Sum up all error counters across all worker lines
    ALL_BUILD_FAIL=$(grep -oP 'build_fail=\K[0-9]+' "$TMPFILE" | awk '{s+=$1} END {print s+0}')
    ALL_TX_ERR=$(grep -oP ' tx_err=\K[0-9]+' "$TMPFILE" | awk '{s+=$1} END {print s+0}')
    ALL_META_ERR=$(grep -oP 'meta_err=\K[0-9]+' "$TMPFILE" | awk '{s+=$1} END {print s+0}')
    ALL_NO_ROUTE=$(grep 'DBG w[0-9]*:' "$TMPFILE" | grep -oP ' no_route=\K[0-9]+' | awk '{s+=$1} END {print s+0}')
    ALL_MISS_NEIGH=$(grep -oP 'miss_neigh=\K[0-9]+' "$TMPFILE" | awk '{s+=$1} END {print s+0}')
    ALL_HA_INACT=$(grep -oP 'ha_inact=\K[0-9]+' "$TMPFILE" | awk '{s+=$1} END {print s+0}')
    ALL_POL_DENY=$(grep -oP 'pol_deny=\K[0-9]+' "$TMPFILE" | awk '{s+=$1} END {print s+0}')
    ALL_NO_EGRESS=$(grep -oP 'no_egress=\K[0-9]+' "$TMPFILE" | awk '{s+=$1} END {print s+0}')

    HAVE_ERRORS=0

    if [ "$ALL_BUILD_FAIL" -gt 0 ]; then
        err "build_fail: ${ALL_BUILD_FAIL} (frame build failures)"
        HAVE_ERRORS=1
    fi
    if [ "$ALL_TX_ERR" -gt 0 ]; then
        err "tx_err: ${ALL_TX_ERR} (TX errors)"
        HAVE_ERRORS=1
    fi
    if [ "$ALL_META_ERR" -gt 0 ]; then
        err "meta_err: ${ALL_META_ERR} (metadata parsing errors)"
        HAVE_ERRORS=1
    fi
    if [ "$ALL_NO_ROUTE" -gt 0 ]; then
        warn "no_route: ${ALL_NO_ROUTE} (no route found)"
        HAVE_ERRORS=1
    fi
    if [ "$ALL_MISS_NEIGH" -gt 0 ]; then
        warn "miss_neigh: ${ALL_MISS_NEIGH} (neighbor resolution miss)"
        HAVE_ERRORS=1
    fi
    if [ "$ALL_HA_INACT" -gt 0 ]; then
        warn "ha_inact: ${ALL_HA_INACT} (HA inactive drops)"
        HAVE_ERRORS=1
    fi
    if [ "$ALL_POL_DENY" -gt 0 ]; then
        note "pol_deny: ${ALL_POL_DENY} (policy denies -- may be expected)"
    fi
    if [ "$ALL_NO_EGRESS" -gt 0 ]; then
        warn "no_egress: ${ALL_NO_EGRESS} (no egress binding found)"
        HAVE_ERRORS=1
    fi

    if [ "$ENOBUFS_COUNT" -gt 0 ]; then
        err "ENOBUFS events: ${ENOBUFS_COUNT}"
        HAVE_ERRORS=1
    fi
    if [ "$POISON_COUNT" -gt 0 ]; then
        err "Poison frames: ${POISON_COUNT}"
        HAVE_ERRORS=1
    fi
    if [ "$OVERSIZED_COUNT" -gt 0 ]; then
        warn "Oversized frames: ${OVERSIZED_COUNT}"
        HAVE_ERRORS=1
    fi
    if [ "$STALL_DETECTED_COUNT" -gt 0 ]; then
        err "Stall events: ${STALL_DETECTED_COUNT}"
        HAVE_ERRORS=1
    fi
    if [ "$RST_CORRUPT_COUNT" -gt 0 ]; then
        err "RST corruption: ${RST_CORRUPT_COUNT}"
        HAVE_ERRORS=1
    fi

    if [ "$HAVE_ERRORS" -eq 0 ]; then
        ok "No errors detected across ${WORKER_LINES} stat intervals"
    fi
else
    note "No worker stats lines found — cannot produce error summary."
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 14: BPF Fallback Stats
# ═══════════════════════════════════════════════════════════════════════
hdr "BPF Fallback Stats"

# Check if bpftool is available on the instance
if incus exec "${REMOTE}:${INSTANCE}" -- which bpftool >/dev/null 2>&1; then
    # Try to dump the userspace_fallback_stats map
    FALLBACK_OUT=$(incus exec "${REMOTE}:${INSTANCE}" -- bpftool map dump pinned /sys/fs/bpf/bpfrx/userspace_fallback_stats 2>/dev/null || echo "")
    if [ -n "$FALLBACK_OUT" ] && [ "$FALLBACK_OUT" != "" ]; then
        note "BPF fallback stats map:"
        echo "$FALLBACK_OUT" | head -30 | while IFS= read -r line; do
            note "  ${line}"
        done
    else
        note "Fallback stats map not available or empty."
    fi

    # Check userspace_ctrl map for enabled/disabled state
    CTRL_OUT=$(incus exec "${REMOTE}:${INSTANCE}" -- bpftool map dump pinned /sys/fs/bpf/bpfrx/userspace_ctrl 2>/dev/null || echo "")
    if [ -n "$CTRL_OUT" ]; then
        note ""
        note "Userspace control map:"
        echo "$CTRL_OUT" | head -10 | while IFS= read -r line; do
            note "  ${line}"
        done
    else
        note "Userspace control map not available."
    fi
else
    note "bpftool not available on ${INSTANCE} — skipping BPF map dump."
fi

# ═══════════════════════════════════════════════════════════════════════
# Section 15: Daemon Errors
# ═══════════════════════════════════════════════════════════════════════
hdr "Daemon Errors (Go side)"

# Look for Go-side userspace errors in the journal
DAEMON_ERRS=$(grep -i 'userspace.*\(error\|fail\|unhealthy\)' "$TMPFILE" 2>/dev/null | grep -v 'DBG\|RST_DETECT\|STALL_\|OVERSIZED\|BUILT_ETH\|POISON\|TX_ENOBUFS\|BUILD_FAIL' || true)

if [ -z "$DAEMON_ERRS" ]; then
    ok "No daemon-side userspace errors"
else
    DAEMON_ERR_COUNT=$(echo "$DAEMON_ERRS" | wc -l)
    warn "${DAEMON_ERR_COUNT} daemon-side userspace messages"
    echo "$DAEMON_ERRS" | head -10 | while IFS= read -r line; do
        TSTAMP=$(extract_time "$line")
        # Trim to the relevant part
        MSG=$(echo "$line" | sed 's/^.*bpfrxd\[[0-9]*\]: //')
        note "  ${TSTAMP} ${MSG}"
    done
fi

echo ""
echo "Analysis complete. ${TOTAL_LINES} journal lines from ${REMOTE}:${INSTANCE}."

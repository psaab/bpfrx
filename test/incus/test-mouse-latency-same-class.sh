#!/usr/bin/env bash
#
# #929: same-class iperf-b wrapper for the mouse-latency tail
# measurement. Routes mice into the SAME CoS class (iperf-b) as
# the elephants, exercising the same-class HOL gate that
# #913/#918/#914/#920 target. The default cross-class invocation
# (mice in best-effort port 7) remains unchanged via the bare
# test-mouse-latency-matrix.sh wrapper.
#
# Mice still target port 7 (the operator's existing echo daemon —
# no second listener required), but the --same-class CoS fixture
# loaded automatically when MOUSE_CLASS=iperf-b adds a term that
# classifies port 7 traffic as iperf-b instead of best-effort.
#
# Prerequisites (see docs/pr/929-same-class-harness/plan.md §3.3):
#   - Echo daemon running on 172.16.80.200:7 (TCP) — same as
#     the cross-class default
#   - apply-cos-config.sh --same-class loads the term-4 mapping
#     port 7 → iperf-b automatically (per MOUSE_CLASS=iperf-b)
#
# CONCURRENCY: this wrapper and the cross-class matrix MUST NOT run
# simultaneously. test-mouse-latency-matrix.sh enforces a flock-based
# mutex; concurrent invocations fail fast.
#
# Usage:
#   ./test/incus/test-mouse-latency-same-class.sh <out_root>
#

set -euo pipefail

exec env \
    ELEPHANT_PORT=5202 \
    MOUSE_PORT=7 \
    MOUSE_CLASS=iperf-b \
    SHAPER_BPS=$((10 * 1000 * 1000 * 1000)) \
    "$(dirname "$0")/test-mouse-latency-matrix.sh" "$@"

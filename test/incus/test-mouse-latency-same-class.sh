#!/usr/bin/env bash
#
# #929: same-class iperf-b wrapper for the mouse-latency tail
# measurement. Routes mice into the SAME CoS class (iperf-b) as
# the elephants, exercising the same-class HOL gate that
# #913/#918/#914/#920 target. The default cross-class invocation
# (mice in best-effort port 7) remains unchanged via the bare
# test-mouse-latency-matrix.sh wrapper.
#
# Prerequisites (see docs/pr/929-same-class-harness/plan.md §3.3):
#   - Echo daemon running on 172.16.80.200:5212 (TCP)
#   - apply-cos-config.sh --same-class loads the term-4 mapping
#     port 5212 → iperf-b automatically (per MOUSE_CLASS=iperf-b)
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
    MOUSE_PORT=5212 \
    MOUSE_CLASS=iperf-b \
    SHAPER_BPS=$((10 * 1000 * 1000 * 1000)) \
    "$(dirname "$0")/test-mouse-latency-matrix.sh" "$@"

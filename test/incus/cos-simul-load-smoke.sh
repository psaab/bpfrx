#!/usr/bin/env bash
# #1614 simul-load smoke harness — run all 11 CoS classes in parallel for
# 30 s, then reduce per-class achievement / CoV / retrans against the v5
# acceptance criteria (plan.md §7 gates 1, 2, 3, 8), as re-scoped by
# #1691 / #1614 §3.A: under full-11 simul the ~22-24 G C_phys push
# ceiling divides among the backlogged classes, so push gate 1 is a
# DIVIDED-CEILING REGRESSION FLOOR, not the >=95% guarantee (which is
# SOLO-only via #1630 cos-gate1-small-four-alone.sh). See
# docs/fairness-regimes.md "Aggregate push ceiling C_phys".
#
# Usage:
#   ./test/incus/cos-simul-load-smoke.sh [push|reverse]   # default push
#
# Expects the loss userspace cluster to be deployed and the
# cos-iperf-config.set fixture applied:
#   sg incus-admin -c "./test/incus/cluster-setup.sh deploy all"
#   sg incus-admin -c "./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0"
#
# Direction default is push (the regression direction). Pass "reverse"
# explicitly to run the Phase 0 / R8 sanity check that determines whether
# the firewall or the generator is the bottleneck. See plan.md §7 gate 8.

set -euo pipefail

DIRECTION="${1:-push}"
DURATION="${DURATION:-30}"
STREAMS="${STREAMS:-12}"
TARGET_V4="${TARGET_V4:-172.16.80.200}"
HOST="${HOST:-loss:cluster-userspace-host}"
ART="${ART:-/tmp/cos-simul-load-$(date +%s)}"

# Port → class-name map (matches test/incus/cos-iperf-config.set).
declare -a PORTS=(5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211)
declare -A CLASS_NAME=(
  [5201]=iperf-100m
  [5202]=iperf-1g
  [5203]=iperf-3g
  [5204]=iperf-6g
  [5205]=iperf-9g
  [5206]=iperf-12g
  [5207]=iperf-15g
  [5208]=iperf-18g
  [5209]=iperf-21g
  [5210]=iperf-24g
  [5211]=iperf-uncapped
)
declare -A SHAPE_GBPS=(
  [5201]=0.1
  [5202]=1.0
  [5203]=3.0
  [5204]=6.0
  [5205]=9.0
  [5206]=12.0
  [5207]=15.0
  [5208]=18.0
  [5209]=21.0
  [5210]=24.0
  [5211]=0     # uncapped → priority-low; gate 2 is ≥ 5% of ceiling
)

mkdir -p "$ART"
echo "#1614 simul-load smoke: direction=$DIRECTION duration=${DURATION}s streams=$STREAMS host=$HOST art=$ART"

REV_FLAG=""
if [ "$DIRECTION" = "reverse" ]; then
  REV_FLAG="-R"
fi

# Launch generator-side mpstat in parallel for the R8 check; we always
# capture it because generator CPU evidence is cheap and useful.
sg incus-admin -c "incus exec $HOST -- mpstat -P ALL 1 $DURATION" > "$ART/mpstat.txt" 2>&1 &
MPSTAT_PID=$!

# Launch the 11 iperf3 senders in parallel.
declare -a IPERF_PIDS=()
for port in "${PORTS[@]}"; do
  (
    sg incus-admin -c "incus exec $HOST -- iperf3 -c $TARGET_V4 -P $STREAMS -t $DURATION -p $port $REV_FLAG --json" \
      > "$ART/sim_${port}.json" 2>"$ART/sim_${port}.err" || true
  ) &
  IPERF_PIDS+=($!)
done

# Wait for all senders, then mpstat.
for pid in "${IPERF_PIDS[@]}"; do
  wait "$pid"
done
wait "$MPSTAT_PID" 2>/dev/null || true

# Reduce verdict.
python3 - <<'PYEOF' "$ART" "$DIRECTION"
import json, os, statistics, sys

art_dir = sys.argv[1]
direction = sys.argv[2]
ports = [5201, 5202, 5203, 5204, 5205, 5206, 5207, 5208, 5209, 5210, 5211]
class_names = {
    5201: "iperf-100m", 5202: "iperf-1g", 5203: "iperf-3g",
    5204: "iperf-6g", 5205: "iperf-9g", 5206: "iperf-12g",
    5207: "iperf-15g", 5208: "iperf-18g", 5209: "iperf-21g",
    5210: "iperf-24g", 5211: "iperf-uncapped",
}
shape_gbps = {
    5201: 0.1, 5202: 1.0, 5203: 3.0, 5204: 6.0, 5205: 9.0,
    5206: 12.0, 5207: 15.0, 5208: 18.0, 5209: 21.0, 5210: 24.0,
    5211: 0.0,
}

rows = []
total_recv = 0.0
total_retr = 0
priority_low_gbps = 0.0
for port in ports:
    f = os.path.join(art_dir, f"sim_{port}.json")
    try:
        with open(f) as fh:
            d = json.load(fh)
    except Exception as e:
        rows.append({"port": port, "class": class_names[port], "error": str(e)})
        continue
    streams = d.get("end", {}).get("streams", [])
    rates = []
    for s in streams:
        ss = s.get("sender", {})
        bps = ss.get("bits_per_second", 0)
        if bps > 0:
            rates.append(bps / 1e9)
    # Codex code-r1 #5 fix: read throughput from sum_received
    # (the actual landed bytes) but retransmits from sum_sent
    # (where the sender-side retransmit counter lives — sum_received
    # is always zero for the retransmit field in iperf3 JSON).
    sum_received = d.get("end", {}).get("sum_received") or {}
    sum_sent = d.get("end", {}).get("sum_sent") or {}
    recv_gbps = (sum_received.get("bits_per_second") or
                 sum_sent.get("bits_per_second") or 0) / 1e9
    retr = sum_sent.get("retransmits", 0) or 0
    cov = (statistics.stdev(rates) / statistics.mean(rates) * 100) if len(rates) > 1 and statistics.mean(rates) > 0 else 0
    spread = (max(rates) / min(rates)) if rates and min(rates) > 0 else float("inf")
    shape = shape_gbps[port]
    rows.append({
        "port": port,
        "class": class_names[port],
        "shape_gbps": shape,
        "recv_gbps": round(recv_gbps, 3),
        "cov_pct": round(cov, 1),
        "spread": round(spread, 2) if spread != float("inf") else None,
        "retransmits": retr,
    })
    total_recv += recv_gbps
    total_retr += retr
    if port == 5211:
        priority_low_gbps = recv_gbps

print(f"\n#1614 simul-load smoke ({direction})")
print(f"{'port':<6} {'class':<16} {'shape':>7} {'recv_G':>7} {'%shape':>7} {'CoV%':>6} {'retr':>6}")
for r in rows:
    if "error" in r:
        print(f"{r['port']:<6} {r['class']:<16} ERROR: {r['error']}")
        continue
    pct = (r["recv_gbps"] / r["shape_gbps"] * 100) if r["shape_gbps"] > 0 else 0
    print(f"{r['port']:<6} {r['class']:<16} {r['shape_gbps']:>6.2f}G {r['recv_gbps']:>6.2f}G {pct:>6.1f}% {r['cov_pct']:>5.1f}% {r['retransmits']:>6}")
print(f"{'':<6} {'Sum':<16} {'':>7} {total_recv:>6.2f}G")

# Gate verdict.
verdict = {"direction": direction, "aggregate_gbps": round(total_recv, 3), "rows": rows}
gates = {}
if direction == "reverse":
    # Phase 0 / R8 gate 8: aggregate ≥ 22 G means firewall (not generator) is the bottleneck.
    gates["gate_8_reverse_simul_22g"] = total_recv >= 22.0
else:
    # Push direction gates (plan.md §7, re-scoped by #1691 / #1614 §3.A).
    # Gate 1 — DIVIDED-CEILING REGRESSION FLOOR (NOT the >=95% guarantee).
    #
    # This harness runs ALL 11 classes in parallel. Under full-11 simul
    # the ~22-24 G push ceiling C_phys (#1578) divides among the
    # backlogged classes, so even the smallest classes land far below
    # their solo rates: research #1614 §2.1 measured 100m=86%, 1g=63%,
    # 3g=43%, 6g=41% of shape. The >=95% small-class GUARANTEE is a SOLO
    # / few-competitor property and is asserted by the separate #1630
    # harness cos-gate1-small-four-alone.sh, NOT here. Asserting >=95%
    # on the full-11 run is structurally unsatisfiable for every class
    # incl 1g (#1691 / docs/fairness-regimes.md "Aggregate push ceiling
    # C_phys is the per-class denominator").
    #
    # We keep ALL four small classes (5201-5204) gated against a relaxed
    # per-class floor calibrated below today's measured full-11 value so
    # a COLLAPSE (e.g. starve-to-zero regression) still trips, while
    # normal ceiling-division does not. The 3g/6g >=95% guarantee under
    # multi-class contention is a confirmed-but-unresolved defect tracked
    # in #1692; this floor is a regression guard, not that guarantee.
    SIMUL_FLOOR_PCT = {5201: 0.60, 5202: 0.40, 5203: 0.25, 5204: 0.25}
    gate1_classes = []
    for r in rows:
        if "error" in r:
            continue
        if r["port"] in SIMUL_FLOOR_PCT:
            floor = SIMUL_FLOOR_PCT[r["port"]]
            target = r["shape_gbps"] * floor
            gate1_classes.append({
                "class": r["class"],
                "floor_pct": round(floor * 100),
                "target": target,
                "actual": r["recv_gbps"],
                "pass": r["recv_gbps"] >= target,
            })
    gates["gate_1_small_class_divided_ceiling_floor"] = {
        "semantics": ("divided-ceiling regression floor under full-11 simul, "
                      "NOT the >=95% guarantee (SOLO-only via #1630 "
                      "cos-gate1-small-four-alone.sh; 3g/6g guarantee = #1692)"),
        "classes": gate1_classes,
        "pass": all(c["pass"] for c in gate1_classes),
    }
    # Gate 2: priority-low ≥ 5% of cluster ceiling.
    ceiling = 18.0
    gates["gate_2_priority_low_min_share"] = {
        "target": ceiling * 0.05,
        "actual": priority_low_gbps,
        "pass": priority_low_gbps >= ceiling * 0.05,
    }
    # Gate 3: per-class retrans ≤ 100/30s.
    high_retr = [r for r in rows if "error" not in r and r["retransmits"] > 100]
    gates["gate_3_retrans_floor"] = {
        "high_retr_classes": [{"class": r["class"], "retr": r["retransmits"]} for r in high_retr],
        "pass": len(high_retr) == 0,
    }
verdict["gates"] = gates

verdict_path = os.path.join(art_dir, "verdict.json")
with open(verdict_path, "w") as f:
    json.dump(verdict, f, indent=2)
print(f"\nVerdict written: {verdict_path}")
print(json.dumps(gates, indent=2))
PYEOF

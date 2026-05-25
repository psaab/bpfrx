# #1477 Final Userspace-Only Validation Runbook

This runbook is the capstone validation procedure for the eBPF retirement
umbrella #1373. It is run against the exact source-removal candidate commit
(the merge SHA of the PR that closes #1476) and produces the artifact bundle
required by #1477's acceptance criteria.

It does not duplicate the per-gate smoke procedure already captured in
[`docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`](../1373-retire-ebpf-dataplane/smoke-gates.md);
it composes those gates plus the dedicated #1374 SYN-cookie proof, #1376
port-mirror fidelity proof, and the fallback-exclusion proof, into a single
operator runbook with the file layout that the structural checker enforces
(see [`docs/pr/1373-retire-ebpf-dataplane/final-validation/README.md`](../1373-retire-ebpf-dataplane/final-validation/README.md)
and `test/incus/retire_ebpf_artifact_schema.py`).

Phase A (pre-merge) draft. The operator runs this only when #1476 has merged
to `master`.

---

## 0. Pre-flight

### 0.1 Confirm the candidate commit

```bash
cd /home/ps/git/bpfrx
git fetch origin master
git checkout master
git pull --ff-only origin master
CANDIDATE_COMMIT="$(git rev-parse HEAD)"
git log -1 --format='%H %s' "$CANDIDATE_COMMIT"
```

The candidate commit MUST be the merge SHA of the PR that closes #1476
(legacy BPF source removal). Confirm with:

```bash
gh issue view 1476 --json state,closedAt,timelineItems --jq \
  '{state, closedAt, closedBy: (.timelineItems[] | select(.__typename=="ClosedEvent") | .closer.title)}'
gh pr list --search "closed:>$(date -u -d '7 days ago' +%Y-%m-%d) 1476" \
  --state merged --json number,mergeCommit,title
```

If `master` HEAD is NOT the #1476 merge SHA, abort and report.

### 0.2 Cluster gate

All cluster operations run on `loss:xpf-userspace-fw0/fw1`
(per `feedback_smoke_loss_userspace_only`). Confirm singleton smoke-runner
queue is drained before starting:

```bash
gh issue view 1373 --json comments --jq \
  '.comments[] | select(.body | test("AWAITING-SMOKE|AWAITING-VALIDATION"))' \
  | head -20
```

If any `AWAITING-SMOKE` marker is unresolved, wait. If you intend to use the
shared smoke-runner for the matrix, post `<!-- AWAITING-VALIDATION -->` and
let it run. Otherwise SendMessage smoke-runner first.

### 0.3 Artifact root

```bash
ARTIFACT_ROOT="docs/pr/1373-retire-ebpf-dataplane/evidence-1477-source-removal-$(date -u +%Y%m%d)-${CANDIDATE_COMMIT:0:12}"
mkdir -p "$ARTIFACT_ROOT"/{metadata,cos-off,screen-flood,syn-cookie,cos-on-5200-5211-push,cos-on-5200-5211-reverse,echo-6200-6211,userspace-ha-failover,fallback-exclusion,port-mirror}
export ARTIFACT_ROOT
export BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
```

The root name MUST match the regex in `retire_ebpf_artifact_schema.py` and
embed the full 40-char SHA's prefix. The checker re-validates this at the end.

---

## 1. Build the source-removal candidate

Pass criteria: `make` targets complete with exit 0; resulting binaries hash
match the values recorded under `metadata/`.

```bash
cd /home/ps/git/bpfrx
make clean
make generate           # MUST succeed without referencing legacy bpf/ source
make build
make build-ctl
make build-userspace-dp
make test 2>&1 | tee "$ARTIFACT_ROOT/metadata/make-test.log"
```

Capture binary hashes (these go into `manifest.json`):

```bash
sha256sum bin/xpfd bin/cli userspace-dp/target/release/xpf-userspace-dp \
  > "$ARTIFACT_ROOT/metadata/binary-sha256.txt"
```

If `make generate` or `make build` reference any of the deleted paths from
`docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md`
(e.g. `bpf/xdp/*.c`, `bpf/tc/*.c`, generated `*_bpf*.go`), STOP and report a
blocker.

### 1.1 Static fallback exclusion

The retained Rust XDP shim is allowed; the legacy BPF program tree must not
build or load:

```bash
{
  echo "## bpf/ tree presence"
  if [ -d bpf ]; then
    find bpf -type f \( -name '*.c' -o -name '*.h' -o -name '*.go' \) \
      | grep -v 'bpf/userspace_shim/' || true
  else
    echo "bpf/ tree absent: PASS"
  fi
  echo "## bpf2go generated artefacts"
  find . -name '*_bpf*.go' -not -path './userspace-xdp/*' || true
  echo "## xdp_main_prog references"
  grep -RIn 'xdp_main_prog' --include='*.go' --include='*.rs' pkg cmd userspace-dp \
    | grep -v -- '-decoupled' || true
} > "$ARTIFACT_ROOT/fallback-exclusion/legacy-map-counter-audit.txt"
```

Expected content of `legacy-map-counter-audit.txt`: only the retained shim
under `bpf/userspace_shim/` (or its post-rename location) may appear. Any
reference to `xdp_main_prog`, `xdp_conntrack`, `xdp_forward`, etc. outside
the shim is a blocker.

---

## 2. Deploy to the userspace HA cluster

```bash
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./test/incus/cluster-setup.sh deploy all \
  2>&1 | tee "$ARTIFACT_ROOT/metadata/deploy.log"

git rev-parse HEAD > "$ARTIFACT_ROOT/metadata/git-rev-parse-head.txt"
git status --short > "$ARTIFACT_ROOT/metadata/git-status-short.txt"
cp test/incus/loss-userspace-cluster.env "$ARTIFACT_ROOT/metadata/cluster-env.txt"
cp docs/ha-cluster-userspace.conf "$ARTIFACT_ROOT/metadata/ha-cluster-userspace.conf"

# Confirm both peers report the deployed candidate SHA.
for node in xpf-userspace-fw0 xpf-userspace-fw1; do
  sg incus-admin -c "incus exec loss:${node} -- /usr/local/sbin/xpfd --version" \
    > "$ARTIFACT_ROOT/metadata/${node}-version.txt" 2>&1
  sg incus-admin -c "incus exec loss:${node} -- sha256sum /usr/local/sbin/xpfd /usr/local/sbin/xpf-userspace-dp /usr/local/bin/cli" \
    >> "$ARTIFACT_ROOT/metadata/binary-sha256.txt"
done
```

Pass criteria: deploy returns 0; both peers report a `xpfd --version` line
containing `CANDIDATE_COMMIT`; deployed binary hashes match the locally built
hashes (deduplicated lines in `binary-sha256.txt`).

### 2.1 Router-advertisement gate

Cluster userspace host MUST gain its IPv6 default route from the dataplane's
RA emitter (no kernel `radvd`, no fallback). Required by #1477 acceptance.

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- ip -6 route show default" \
  > "$ARTIFACT_ROOT/metadata/cluster-userspace-host-ipv6-route.txt"
grep -q ' via fe80::' "$ARTIFACT_ROOT/metadata/cluster-userspace-host-ipv6-route.txt" \
  || { echo "FAIL: no link-local default route from RA"; exit 1; }
```

---

## 3. Gate 1 — CoS-Off IPv4/IPv6 push and reverse

Pass criteria: each of `v4-push`, `v4-reverse`, `v6-push`, `v6-reverse`
records `avg_gbps >= MIN_GBPS`, zero retransmits, no collapse, `completed=true`
in the parsed metrics JSON.

Capture format (per cell): raw iperf JSON, stderr, and
`*.metrics.json` with the receiver-side throughput summary
(`scripts/iperf-json-metrics.py`).

Run the exact block under "Gate 1" in `smoke-gates.md` with
`ARTIFACT_ROOT="$ARTIFACT_ROOT"`. Required final state:

```text
$ARTIFACT_ROOT/cos-off/{v4-push,v4-reverse,v6-push,v6-reverse}.{json,stderr,metrics.json}
```

Targets: `V4_TARGET=172.16.80.200`, `V6_TARGET=2001:559:8585:80::200`.
Defaults: `PARALLEL=6`, `DURATION=10`, `MIN_GBPS=18.0`, `MAX_RETRANS=0`.

The Python validator at the end of the block MUST print
`PASS cos-off v4/v6 push+reverse`. Any FAIL line is a blocker for #1477.

---

## 4. Gate 2 — Screen/flood baseline (LAND, SYN-flood, ICMP-flood, UDP-flood)

Pass criteria: for each of LAND, SYN-flood, ICMP-flood, UDP-flood, the
aggregate `Total screen drops` counter strictly increases between
`*-before.txt` and `*-after.txt`.

Run the block under "Gate 2" in `smoke-gates.md`. The final state of the
artifact tree is:

```text
$ARTIFACT_ROOT/screen-flood/{land,syn,icmp,udp}-{before,after}.txt
$ARTIFACT_ROOT/screen-flood/{land,syn,icmp,udp}-configure.{stdout,stderr}
$ARTIFACT_ROOT/screen-flood/restore.{stdout,stderr}
```

This is plumbing-only. SYN-cookie semantics are validated in Gate 3.

---

## 5. Gate 3 — Dedicated #1374 SYN-cookie proof

Pass criteria (all required by #1374's "Exact Tests" integration row):

1. Flood SYN traffic causes the dataplane to send SYN-ACK challenge replies
   (`syn_cookie_syn_acks_sent` advances).
2. A returning valid ACK (carrying the encoded ISN) triggers a RST reply,
   not a session install (`syn_cookie_valid_acks` and
   `syn_cookie_ack_rsts_sent` advance; no new session entry).
3. The retransmitted SYN from the same validated tuple admits normally via
   the `SynCookieBypass` single-use cache (`syn_cookie_bypasses` advances by
   1, then session is installed).
4. Random ACKs from the same source IP but with wrong ISN are dropped and
   `syn_cookie_invalid_acks` advances; no session installed.
5. Reply-budget exhaustion is observable: when SYN rate exceeds the binding
   reserve, `syn_cookie_reply_budget_drops` advances and forwarding TX is
   unaffected (Gate 1 push/reverse still passes after the storm).
6. RG failover during the active flood window leaves cookies minted by the
   former active node acceptable on the new active node within the
   current/previous/next-epoch tolerance.

Required artifacts (per `final-validation/README.md`):

```text
$ARTIFACT_ROOT/syn-cookie/
  summary.md
  applied-config.txt
  challenge-hping3.{stdout,stderr}
  challenge-tcpdump.txt
  challenge-counters-{before,after}.txt
  valid-ack-rst-tcpdump.txt
  valid-ack-rst-counters-{before,after}.txt
  random-ack-drop-tcpdump.txt
  random-ack-drop-counters-{before,after}.txt
  retransmitted-syn-admission-tcpdump.txt
  retransmitted-syn-admission-counters-{before,after}.txt
  reply-budget-counters.txt
  failover-before-cluster-status.txt
  failover-after-cluster-status.txt
  failover-cookie-ack-tcpdump.txt
  failover-counters-node1.txt
  cleanup.{stdout,stderr}
  final-cluster-status.txt
```

### 5.1 Apply the SYN-cookie profile

```bash
mkdir -p "$ARTIFACT_ROOT/syn-cookie"
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli" \
  >"$ARTIFACT_ROOT/syn-cookie/applied-config.txt" 2>&1 <<'EOF'
configure
set security flow syn-flood-protection-mode syn-cookie
set security screen ids-option pr1477-sync tcp syn-flood attack-threshold 100
set security screen ids-option pr1477-sync tcp syn-flood source-threshold 50
set security screen ids-option pr1477-sync tcp syn-flood destination-threshold 50
set security zones security-zone untrust screen pr1477-sync
commit
exit
EOF
```

Confirm the daemon admitted the profile (no `secret-unavailable` reason
listed in `show security screen status` for `pr1477-sync`).

### 5.2 Counter snapshot helper

```bash
snapshot_synpx_counters() {
  local out=$1
  sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show security screen status'" >"$out"
  sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- curl -s http://127.0.0.1:8080/metrics" \
    | grep -E '^xpf_userspace_(syn_cookie|screen_)' >>"$out"
}
```

### 5.3 Challenge: SYN flood ⇒ SYN-ACK

```bash
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/challenge-counters-before.txt"

sg incus-admin -c "incus exec loss:cluster-userspace-host -- timeout 5 tcpdump -i any -nn -c 200 -w -" tcp \
  > "$ARTIFACT_ROOT/syn-cookie/challenge-tcpdump.pcap" 2>/dev/null &
TCPDUMP_PID=$!

sg incus-admin -c "incus exec loss:cluster-userspace-host -- hping3 -S -p 5201 --flood -c 5000 172.16.80.200" \
  >"$ARTIFACT_ROOT/syn-cookie/challenge-hping3.stdout" \
  2>"$ARTIFACT_ROOT/syn-cookie/challenge-hping3.stderr" || true

wait $TCPDUMP_PID 2>/dev/null || true
sg incus-admin -c "incus exec loss:cluster-userspace-host -- tcpdump -r - -nn" \
  < "$ARTIFACT_ROOT/syn-cookie/challenge-tcpdump.pcap" \
  > "$ARTIFACT_ROOT/syn-cookie/challenge-tcpdump.txt"

snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/challenge-counters-after.txt"
```

Expected delta: `syn_cookie_challenges_selected` and
`syn_cookie_syn_acks_sent` increase. `challenge-tcpdump.txt` shows
firewall-sourced SYN-ACK frames whose destination port matches the flood
source ports.

### 5.4 Valid-ACK ⇒ RST proof (carry the encoded ISN)

Use `scripts/cookie-replay.py` (helper to be authored — captures one
SYN-ACK from the previous step, swaps src/dst, ACKs the ISN+1). If the
script is not yet in-tree, capture this as a test gap and use a hand-crafted
scapy run; record the script source under `syn-cookie/cookie-replay.py`.

```bash
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/valid-ack-rst-counters-before.txt"
# replay produces ONE valid ACK derived from a captured SYN-ACK
sg incus-admin -c "incus exec loss:cluster-userspace-host -- python3 /tmp/cookie-replay.py --mode valid" \
  > "$ARTIFACT_ROOT/syn-cookie/valid-ack-rst-tcpdump.txt" 2>&1
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/valid-ack-rst-counters-after.txt"
```

Expected delta: `syn_cookie_valid_acks` += 1, `syn_cookie_ack_rsts_sent` += 1;
no new entry in `show security flow session`.

### 5.5 Retransmitted-SYN admission via single-use bypass

```bash
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/retransmitted-syn-admission-counters-before.txt"
sg incus-admin -c "incus exec loss:cluster-userspace-host -- python3 /tmp/cookie-replay.py --mode retransmit-syn" \
  > "$ARTIFACT_ROOT/syn-cookie/retransmitted-syn-admission-tcpdump.txt" 2>&1
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/retransmitted-syn-admission-counters-after.txt"
```

Expected delta: `syn_cookie_bypasses` += 1; a new session installed; the SAME
client tuple resending another SYN immediately after consumes the bypass
exactly once (subsequent SYNs go through normal policy).

### 5.6 Random-ACK drop

```bash
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/random-ack-drop-counters-before.txt"
sg incus-admin -c "incus exec loss:cluster-userspace-host -- python3 /tmp/cookie-replay.py --mode random-ack --count 500" \
  > "$ARTIFACT_ROOT/syn-cookie/random-ack-drop-tcpdump.txt" 2>&1
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/random-ack-drop-counters-after.txt"
```

Expected delta: `syn_cookie_invalid_acks` += 500 (approx); session table size
unchanged.

### 5.7 Reply-budget exhaustion

Drive flood at a rate higher than the per-binding reply budget; confirm
`syn_cookie_reply_budget_drops` advances while Gate 1 re-run still passes:

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- hping3 -S -p 5201 --flood -c 200000 -d 0 172.16.80.200" \
  >/dev/null 2>&1 || true
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/reply-budget-counters.txt"
```

### 5.8 Failover acceptance within epoch window

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show chassis cluster status'" \
  > "$ARTIFACT_ROOT/syn-cookie/failover-before-cluster-status.txt"

# Capture a fresh SYN-ACK on fw0, then force RG0 to fw1, then replay the ACK
# against the new active node.
sg incus-admin -c "incus exec loss:cluster-userspace-host -- python3 /tmp/cookie-replay.py --mode capture-cookie" \
  > /tmp/cookie-token.txt
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'request chassis cluster failover redundancy-group 0 node 1'" \
  >/dev/null
sleep 2
sg incus-admin -c "incus exec loss:xpf-userspace-fw1 -- cli -c 'show chassis cluster status'" \
  > "$ARTIFACT_ROOT/syn-cookie/failover-after-cluster-status.txt"
sg incus-admin -c "incus exec loss:cluster-userspace-host -- python3 /tmp/cookie-replay.py --mode replay --token-file /tmp/cookie-token.txt" \
  > "$ARTIFACT_ROOT/syn-cookie/failover-cookie-ack-tcpdump.txt" 2>&1
snapshot_synpx_counters "$ARTIFACT_ROOT/syn-cookie/failover-counters-node1.txt"
```

Expected: replay on fw1 records `syn_cookie_valid_acks += 1` (cluster-synced
master key + bounded wall-clock skew makes cookie minted on fw0 acceptable
on fw1 within the current/previous/next epoch).

### 5.9 Cleanup

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli" \
  >"$ARTIFACT_ROOT/syn-cookie/cleanup.stdout" 2>"$ARTIFACT_ROOT/syn-cookie/cleanup.stderr" <<'EOF'
configure
delete security zones security-zone untrust screen pr1477-sync
delete security screen ids-option pr1477-sync
delete security flow syn-flood-protection-mode
commit
exit
EOF
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show chassis cluster status'" \
  > "$ARTIFACT_ROOT/syn-cookie/final-cluster-status.txt"
```

### 5.10 syn-cookie/summary.md

Write a short `$ARTIFACT_ROOT/syn-cookie/summary.md` with one row per
sub-gate: counter-delta observed, expected delta, verdict.

---

## 6. Gate 4 — CoS-On per-class 5200-5211 (push + reverse)

Pass criteria: every class q0..q11 has positive `samples/summary.json`
throughput, no collapse, equal-flow CoV within the structural ceiling
documented in `docs/pr/1219-fairness-harness/` (≤ Cstruct + 0.05).

Run the "Gate 3" block in `smoke-gates.md` exactly. Resulting tree:

```text
$ARTIFACT_ROOT/cos-on-5200-5211-push/{summary.tsv,summary.md,dataplane/,equal-flow-summary.tsv,q0-best-effort-root/...,q11-iperf-uncapped-root/...}
$ARTIFACT_ROOT/cos-on-5200-5211-reverse/{...same shape...}
```

Each class directory MUST contain `wrapper.stdout`, `wrapper.stderr`,
`samples/summary.json`, `equal-flow/summary.json`,
`dataplane/status-before.json`, `dataplane/status-after.json`
(required by the schema checker).

---

## 7. Gate 5 — TCP echo 6200-6211 latency probe

Pass criteria: each of ports 6200..6211 returns PASS with a numeric
`latency_ns` value. Any FAIL is a blocker.

Run the "Gate 4" block in `smoke-gates.md`. Final tree:

```text
$ARTIFACT_ROOT/echo-6200-6211/{summary.tsv,latency-summary.tsv,6200..6211.{stdout,stderr}}
```

---

## 8. Gate 6 — Steady-state deploy/readiness matrix

Pass criteria: `userspace-phase-cycle.sh` prints
`smoke matrix complete: 8/8 cells passed` and exits 0.

```bash
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./scripts/userspace-phase-cycle.sh \
  2>&1 | tee "$ARTIFACT_ROOT/userspace-phase-cycle.log"
```

The 8 cells exercised are: `cos-off-{v4,v6}-{push,reverse}` followed by
`cos-on-{v4,v6}-{push,reverse}`.

---

## 9. Gate 7 — Port-mirroring fidelity (#1376)

Pass criteria (per #1376 plan integration row):

1. Configured ingress mirror copies full L2 frames (Ethernet + VLAN + IP
   payload) to the output binding.
2. Sample ratio is approximately 1-in-N per binding (counters
   `mirrored_packets` increases by ~total_packets / N).
3. Primary forwarding survives mirror pressure: Gate 1 push throughput
   re-runs at ≥ MIN_GBPS during a high-rate mirror.

Required artifacts:

```text
$ARTIFACT_ROOT/port-mirror/
  applied-config.txt
  mirror-output-tcpdump.pcap
  mirror-output-tcpdump.txt
  counters-before.txt
  counters-after.txt
  pressure-iperf.json
  pressure-iperf.metrics.json
  cleanup.{stdout,stderr}
```

### 9.1 Apply mirror config

```bash
mkdir -p "$ARTIFACT_ROOT/port-mirror"
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli" \
  >"$ARTIFACT_ROOT/port-mirror/applied-config.txt" 2>&1 <<'EOF'
configure
set forwarding-options port-mirroring instance pr1477-mirror input rate 1
set forwarding-options port-mirroring instance pr1477-mirror family inet output interface ge-0-0-3
set interfaces ge-0-0-1 unit 0 family inet port-mirror-instance pr1477-mirror
commit
exit
EOF
```

### 9.2 Capture mirror output + counters

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- curl -s http://127.0.0.1:8080/metrics" \
  | grep -E '^xpf_userspace_mirror_' \
  > "$ARTIFACT_ROOT/port-mirror/counters-before.txt"

sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- timeout 10 tcpdump -i ge-0-0-3 -nn -c 500 -w -" \
  > "$ARTIFACT_ROOT/port-mirror/mirror-output-tcpdump.pcap" 2>/dev/null &
TCPDUMP_PID=$!

# Drive iperf3 push through ge-0-0-1 to generate mirror traffic.
sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -J --forceflush -c 172.16.80.200 -P 4 -t 8" \
  > "$ARTIFACT_ROOT/port-mirror/pressure-iperf.json"
./scripts/iperf-json-metrics.py "$ARTIFACT_ROOT/port-mirror/pressure-iperf.json" \
  > "$ARTIFACT_ROOT/port-mirror/pressure-iperf.metrics.json"

wait $TCPDUMP_PID 2>/dev/null || true
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- tcpdump -r - -nn -e -v" \
  < "$ARTIFACT_ROOT/port-mirror/mirror-output-tcpdump.pcap" \
  > "$ARTIFACT_ROOT/port-mirror/mirror-output-tcpdump.txt"

sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- curl -s http://127.0.0.1:8080/metrics" \
  | grep -E '^xpf_userspace_mirror_' \
  > "$ARTIFACT_ROOT/port-mirror/counters-after.txt"
```

### 9.3 Verify full-L2 fidelity + survival

Inline checks (record verdict in summary.md):

- `mirror-output-tcpdump.txt` lines include Ethernet src/dst MACs and any
  configured VLAN tag (i.e. tcpdump `-e` output is non-empty and VLAN
  field present where applicable).
- `mirrored_packets` delta (after - before) ≥ approximate sampled count.
- `pressure-iperf.metrics.json` reports `avg_gbps >= MIN_GBPS` with zero
  retransmits.
- `mirror_drops_queue_full` and `mirror_drops_no_frame` may be > 0 (lossy
  is allowed); `mirror_drops_no_binding` MUST be 0.

### 9.4 Cleanup

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli" \
  >"$ARTIFACT_ROOT/port-mirror/cleanup.stdout" 2>"$ARTIFACT_ROOT/port-mirror/cleanup.stderr" <<'EOF'
configure
delete interfaces ge-0-0-1 unit 0 family inet port-mirror-instance
delete forwarding-options port-mirroring instance pr1477-mirror
commit
exit
EOF
```

---

## 10. Gate 8 — HA failover acceptance (strict, RG-movement)

Pass criteria (per #1477 acceptance HA row): zero stream-level zero intervals,
zero retransmits, TOTAL_CYCLES=2 completes cleanly.

```bash
ARTIFACT_DIR="$ARTIFACT_ROOT/userspace-ha-failover" \
TOTAL_CYCLES=2 \
MAX_ZERO_INTERVALS=0 \
MAX_STREAM_ZERO_INTERVALS=0 \
MAX_RETRANSMITS=0 \
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./scripts/userspace-ha-failover-validation.sh \
  2>&1 | tee "$ARTIFACT_ROOT/userspace-ha-failover.log"
```

The resulting tree under `userspace-ha-failover/` is enumerated in the schema:
`iperf3.log`, `iperf3.metrics.json`, `before-{source,target}-status.txt`,
plus per-cycle `cycle*-{failover,failback}-*-dp-{stats,interfaces}.txt`.

---

## 11. Gate 9 — Destructive HA regression (Makefile gates)

Operator-handoff only. These gates reboot, force-stop, fail over, or restart
services and are run AFTER Gate 8 collects strict-acceptance evidence.

```bash
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" make test-failover \
  2>&1 | tee "$ARTIFACT_ROOT/ha-test-failover.log"
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" make test-ha-crash \
  2>&1 | tee "$ARTIFACT_ROOT/ha-test-ha-crash.log"
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" make test-restart-connectivity \
  2>&1 | tee "$ARTIFACT_ROOT/ha-test-restart-connectivity.log"
```

Pass criteria: each command exits 0. Loss-window/takeover-time warnings are
recorded in `summary.md` as exceptions but do not block #1477 (Gate 8 is the
strict acceptance gate).

---

## 12. Gate 10 — Fallback exclusion (runtime)

Pass criteria: no legacy `xdp_main_prog` or BPF map counter is loaded on
either firewall peer; userspace-dp is the only dataplane path.

```bash
for node in xpf-userspace-fw0 xpf-userspace-fw1; do
  short=${node#xpf-userspace-}
  sg incus-admin -c "incus exec loss:${node} -- ip -details link show" \
    > "$ARTIFACT_ROOT/fallback-exclusion/${short}-ip-link.txt"
  sg incus-admin -c "incus exec loss:${node} -- cli -c 'show chassis cluster data-plane statistics'" \
    > "$ARTIFACT_ROOT/fallback-exclusion/${short}-dp-stats.txt"
  sg incus-admin -c "incus exec loss:${node} -- cat /run/xpf/userspace-dp.json" \
    > "$ARTIFACT_ROOT/fallback-exclusion/${short}-userspace-dp.json"
done
```

Audit checks (record verdict in `summary.md`):

- `*-ip-link.txt` MUST NOT show `xdp/id` for `xdp_main_prog` on any data
  interface. The retained Rust shim ID (whatever the post-#1473 build
  produces) is acceptable; any of the deleted legacy program names
  (`xdp_main`, `xdp_conntrack`, `xdp_forward`, `xdp_nat`, `xdp_policy`,
  `xdp_screen`, `xdp_zone`, `xdp_nat64`, `xdp_cpumap`) is a blocker.
- `*-dp-stats.txt` MUST report dataplane = userspace. Counters historically
  bound to legacy BPF maps (e.g. those backed by `GLOBAL_CTR_*` BPF map)
  may still be present as helper-sourced values — record their source.
- `*-userspace-dp.json` MUST contain `cos_interfaces`, `bindings`, and any
  other fields the helper publishes; absence of this file is a blocker.
- `legacy-map-counter-audit.txt` (already produced in §1.1) closes the
  static side of this gate.

---

## 13. Assembly: summary.md + manifest.json

Required `summary.md` sections (per
`docs/pr/1373-retire-ebpf-dataplane/final-validation/README.md`):

```text
## Candidate
## Cluster And Binaries
## CoS-Off IPv4/IPv6 Push And Reverse
## Screen/Flood Baseline
## SYN-Cookie Proof
## CoS 5200-5211 Sweeps
## TCP Echo 6200-6211
## HA Gates
## Fallback Exclusion
## Command Exit Status
## Remaining Exceptions
```

Each section names the artifact paths it derives from, the observed values
(throughput, retransmits, counter deltas, loss windows), and the verdict.

The `manifest.json` MUST conform to
`docs/pr/1373-retire-ebpf-dataplane/final-validation/manifest.schema.json`
and embed the full 40-character `CANDIDATE_COMMIT`.

---

## 14. Structural check

```bash
python3 test/incus/retire_ebpf_artifact_schema.py \
  "$ARTIFACT_ROOT" \
  --candidate-commit "$CANDIDATE_COMMIT"
```

Expected output: `STRUCTURE_OK`. Any other output is a blocker — fix and
re-run before posting.

`STRUCTURE_OK` is a names/sections/JSON-parseability gate. The live-result
PASS verdict is made by an operator reading `summary.md`.

---

## 15. Posting the artifact set

After all gates pass and `STRUCTURE_OK` is printed:

1. Commit the artifact directory to a branch off the source-removal candidate
   commit (do NOT amend the candidate). Reference the artifact root in the
   #1477 closing comment.
2. Post a comment on #1477 listing:
   - Candidate commit SHA (full 40-char).
   - Cluster: `loss:xpf-userspace-fw0/fw1`.
   - Artifact root path.
   - Binary SHA-256s.
   - One-line PASS verdict per gate 1..10.
   - Link to `summary.md`.
3. Close #1477 after operator review confirms PASS.
4. Close umbrella #1373 once #1477 is closed and all sub-issues in
   `docs/pr/1373-retire-ebpf-dataplane/README.md` are closed.

The author always decides on merges and umbrella closure
(per `feedback_no_autonomous_merge`). The operator runs this runbook and
posts evidence; an autonomous closure step is NOT part of this runbook.

---

## 16. Open follow-ups recorded in this runbook (not blockers for #1477)

- `scripts/cookie-replay.py` referenced by §5 must be authored alongside the
  source-removal candidate or as part of #1374's final evidence slice.
  Record the script source under `syn-cookie/cookie-replay.py` in the
  artifact bundle so the evidence is reproducible.
- The port-mirror tcpdump field-coverage check (§9.3) is currently visual;
  if a structured fidelity checker is added (e.g. PCAP byte-equality vs the
  ingress stream), wire it into `port-mirror/` and reference it from
  `summary.md`.

# #1477 Final Userspace-Only Validation Artifacts

This directory defines the artifact contract for #1477. Do not populate the
final evidence bundle until the exact #1476 source-removal candidate exists.
The structural checker below is a completeness gate only: it verifies names,
sections, JSON parseability, and commit binding. It does not decide whether the
live cluster results are acceptable.

## Candidate Binding

Create the final artifact root from the source-removal candidate commit:

```bash
CANDIDATE_COMMIT="$(git rev-parse HEAD)"
ARTIFACT_ROOT="docs/pr/1373-retire-ebpf-dataplane/evidence-1477-source-removal-$(date +%Y%m%d)-${CANDIDATE_COMMIT:0:12}"
mkdir -p "$ARTIFACT_ROOT"
```

The root name, `manifest.json`, `metadata/git-rev-parse-head.txt`, and
`summary.md` must all name the same full 40-character commit SHA. The bundle is
not reusable across rebases or amended source-removal candidates.

## Required Top-Level Files

- `manifest.json`: machine-readable run manifest matching
  [manifest.schema.json](manifest.schema.json).
- `summary.md`: human-readable report with these required `##` sections:
  `Candidate`, `Cluster And Binaries`,
  `CoS-Off IPv4/IPv6 Push And Reverse`, `Screen/Flood Baseline`,
  `SYN-Cookie Proof`, `CoS 5200-5211 Sweeps`, `TCP Echo 6200-6211`,
  `HA Gates`, `Fallback Exclusion`, `Command Exit Status`, and
  `Remaining Exceptions`.
- `metadata/`: exact commit, dirty status, cluster env, config, IPv6 RA route
  proof, and binary SHA-256 hashes.

## Required Artifact Layout

```text
cos-off/
  v4-push.json
  v4-push.stderr
  v4-push.metrics.json
  v4-reverse.json
  v4-reverse.stderr
  v4-reverse.metrics.json
  v6-push.json
  v6-push.stderr
  v6-push.metrics.json
  v6-reverse.json
  v6-reverse.stderr
  v6-reverse.metrics.json
screen-flood/
  land-before.txt
  land-after.txt
  land-configure.stdout
  land-configure.stderr
  syn-before.txt
  syn-after.txt
  syn-configure.stdout
  syn-configure.stderr
  icmp-before.txt
  icmp-after.txt
  icmp-configure.stdout
  icmp-configure.stderr
  udp-before.txt
  udp-after.txt
  udp-configure.stdout
  udp-configure.stderr
  restore.stdout
  restore.stderr
syn-cookie/
  summary.md
  applied-config.txt
  challenge-hping3.stdout
  challenge-hping3.stderr
  challenge-tcpdump.txt
  challenge-counters-before.txt
  challenge-counters-after.txt
  valid-ack-rst-tcpdump.txt
  valid-ack-rst-counters-before.txt
  valid-ack-rst-counters-after.txt
  random-ack-drop-tcpdump.txt
  random-ack-drop-counters-before.txt
  random-ack-drop-counters-after.txt
  retransmitted-syn-admission-tcpdump.txt
  retransmitted-syn-admission-counters-before.txt
  retransmitted-syn-admission-counters-after.txt
  reply-budget-counters.txt
  failover-before-cluster-status.txt
  failover-after-cluster-status.txt
  failover-cookie-ack-tcpdump.txt
  failover-counters-node1.txt
  cleanup.stdout
  cleanup.stderr
  final-cluster-status.txt
cos-on-5200-5211-push/
cos-on-5200-5211-reverse/
  summary.tsv
  summary.md
  dataplane/status-before.json
  dataplane/status-after.json
  dataplane/counter-delta.json
  dataplane/journal-since.txt
  dataplane-summary.tsv
  equal-flow-summary.tsv
  q0-best-effort-root/... q11-iperf-uncapped-root/...
echo-6200-6211/
  summary.tsv
  latency-summary.tsv
  6200.stdout
  6200.stderr
  ...
  6211.stdout
  6211.stderr
userspace-phase-cycle.log
userspace-ha-failover.log
userspace-ha-failover/
  iperf3.log
  iperf3.metrics.json
  before-source-status.txt
  before-target-status.txt
  cycle*-failover-*-dp-stats.txt
  cycle*-failback-*-dp-stats.txt
  cycle*-failover-*-dp-interfaces.txt
  cycle*-failback-*-dp-interfaces.txt
ha-test-failover.log
ha-test-ha-crash.log
ha-test-restart-connectivity.log
fallback-exclusion/
  fw0-ip-link.txt
  fw1-ip-link.txt
  fw0-dp-stats.txt
  fw1-dp-stats.txt
  fw0-userspace-dp.json
  fw1-userspace-dp.json
  legacy-map-counter-audit.txt
```

Each CoS sweep class directory must preserve `wrapper.stdout`,
`wrapper.stderr`, `samples/summary.json`, `equal-flow/summary.json`,
`dataplane/status-before.json`, and `dataplane/status-after.json` for every
canonical class from `q0-best-effort-root` through `q11-iperf-uncapped-root`.

## Structural Check

After copying the final live artifacts into the root:

```bash
python3 test/incus/retire_ebpf_artifact_schema.py \
  "$ARTIFACT_ROOT" \
  --candidate-commit "$CANDIDATE_COMMIT"
```

The command prints `STRUCTURE_OK` only when required artifacts and sections are
present. A structural success is not a live-result PASS. The final #1477 report
still needs a human review of throughput, retransmits, screen deltas,
SYN-cookie packet captures, HA loss windows, fallback exclusion text, and any
exceptions listed in `summary.md`.

## Metadata Capture Checklist

Record these before running destructive HA gates:

```bash
git rev-parse HEAD >"$ARTIFACT_ROOT/metadata/git-rev-parse-head.txt"
git status --short >"$ARTIFACT_ROOT/metadata/git-status-short.txt"
cp test/incus/loss-userspace-cluster.env "$ARTIFACT_ROOT/metadata/cluster-env.txt"
cp docs/ha-cluster-userspace.conf "$ARTIFACT_ROOT/metadata/ha-cluster-userspace.conf"
```

Record binary hashes from both userspace firewalls and the helper binary paths
actually deployed. Save the cluster host IPv6 default route after the
router-advertisement gate in `metadata/cluster-userspace-host-ipv6-route.txt`.

## Fallback Exclusion Checklist

Capture both firewall peers after the source-removal candidate is deployed:

- `ip -details link show` for the data interfaces.
- `show chassis cluster data-plane statistics`.
- `/run/xpf/userspace-dp.json`.
- A short legacy map-counter audit explaining why no legacy BPF map counter
  source is present in the source-removal candidate.

The checker requires those files so a report cannot claim a userspace-only
run while omitting the status needed to rule out `xdp_main_prog` or legacy
counter fallback.

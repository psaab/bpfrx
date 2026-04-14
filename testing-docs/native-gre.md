# Native GRE Tests

## Overview

These tests validate the native userspace GRE dataplane on the physical WAN
path. The goal is to prove that transit GRE works without depending on kernel
GRE forwarding for dataplane traffic.

Use this document when the change touches:

- native GRE decap / encap
- tunnel handoff
- GRE failover / failback
- firewall-originated GRE traffic
- GRE-specific throughput or traceroute behavior

## Environment

- Cluster: `loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1`
- Host: `loss:cluster-userspace-host`
- GRE target: `10.255.192.41`
- Default TCP probe target: `10.255.192.41:22`
- Default `iperf3` target: `10.255.192.41:5201`
- Outer GRE remote: `2602:ffd3:0:2::7`
- Logical anchor: `gr-0-0-0`

Important:

- The logical tunnel interface may still exist on the firewall, but transit GRE
  should stay on the physical WAN path.
- If you need endpoint-side evidence, use the gRPC capture service documented
  in `~/README.md`.

## Clean Start

Before GRE validation:

```bash
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh refresh-vfs

BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

If the test is supposed to run with a particular active node, pin the RGs
before starting:

```bash
PREFERRED_ACTIVE_NODE=1 \
PREFERRED_ACTIVE_RGS="1 2" \
scripts/userspace-ha-validation.sh
```

## Test 1: Steady GRE Transit

**What it tests**: Basic ICMP and TCP transit over native GRE.

```bash
scripts/userspace-native-gre-validation.sh
```

**Pass criteria**:

- GRE ICMP to `10.255.192.41` succeeds
- TCP connect to the GRE target succeeds
- transit stays on the WAN path
- transit is not forwarded through kernel GRE dataplane

## Test 2: GRE Throughput

**What it tests**: Long-lived GRE TCP traffic remains healthy.

```bash
scripts/userspace-native-gre-validation.sh --iperf
```

**Pass criteria**:

- `iperf3` completes
- no zero-throughput collapse
- average throughput stays above the configured minimum

If you need to tune thresholds for a specific run:

```bash
GRE_IPERF_DURATION=30 \
GRE_IPERF_PARALLEL=1 \
GRE_IPERF_MIN_GBPS=1.0 \
scripts/userspace-native-gre-validation.sh --iperf
```

## Test 3: GRE UDP + Traceroute

**What it tests**: UDP and traceroute-style probes over the native GRE path.

```bash
scripts/userspace-native-gre-validation.sh --udp --traceroute
```

**Pass criteria**:

- UDP burst reaches the GRE target path
- traceroute / `mtr` style probing succeeds
- transit still stays on the WAN path

## Test 4: GRE Failover / Failback

**What it tests**: Native GRE traffic survives ownership changes.

```bash
scripts/userspace-native-gre-validation.sh --failover --iperf --udp --traceroute --count 3
```

**Pass criteria**:

- pre-failover steady state is healthy
- failover completes
- no zero-throughput collapse during the failover window
- post-failover ICMP / TCP / `iperf3` / UDP / traceroute still pass

## Test 5: Host-Origin GRE Traffic

**What it tests**: Firewall-originated traffic still works without kernel GRE
transit forwarding.

```bash
GRE_VALIDATE_HOST_PROBES=1 \
scripts/userspace-native-gre-validation.sh --iperf --udp --traceroute --failover --count 2
```

**Pass criteria**:

- active firewall-originated GRE ping works
- active firewall-originated TCP connect works
- active firewall-originated `iperf3` works
- post-failover host-origin probes still work

## Test 6: Real Endpoint Capture

When GRE looks wrong, capture at the actual endpoint instead of inferring too
much from firewall-side state.

Typical workflow:

```bash
capture-client \
  -server <capture-server>:50051 \
  -interface <endpoint-interface> \
  -filter "host 10.255.192.41 or proto gre" \
  -duration 30 \
  -text \
  -no-resolve
```

Use this to answer:

- did the GRE packet leave the firewall?
- did the decapsulated packet reach the endpoint?
- did replies leave the endpoint?
- did only some `iperf3` streams collapse?

## Common Failure Modes

1. Transit leaks back to kernel GRE.
- Symptom: traffic shows up on the logical tunnel dataplane path when it should
  stay on the WAN path.

2. Failover zero-throughput interval.
- Symptom: `iperf3` survives but reports one or more zero intervals during RG
  ownership change.

3. Host-origin path broken.
- Symptom: transit GRE works, but firewall-generated ping/TCP/`iperf3` fails.

4. Wrong target capture assumptions.
- Symptom: testing uses the wrong host instead of the real GRE endpoint or the
  real `.200` / `::200` target.

## Acceptance Bar

Do not call native GRE healthy until all of these are true:

- steady-state ICMP and TCP pass
- `iperf3` stays up without zero-throughput collapse
- UDP and traceroute probes pass
- failover/failback stays green
- host-origin probes pass if that path is affected

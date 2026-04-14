---
name: iperf-grpc-tcpdump
description: Run synchronized iperf3 tests from the isolated userspace client while capturing server-side tcpdump over the gRPC capture service and simultaneous LAN/WAN tcpdumps on the active userspace firewall. Use this when debugging throughput collapse, TCP resets, or tuple corruption on the userspace dataplane.
---

# iperf3 + gRPC tcpdump

Use this skill when the task is to reproduce or debug userspace dataplane
forwarding failures with synchronized captures.

This skill targets the isolated `loss` userspace lab:
- client: `loss:cluster-userspace-host`
- firewalls: `loss:xpf-userspace-fw0`, `loss:xpf-userspace-fw1`
- server capture gRPC endpoint: `172.16.80.200:50051`

The helper script:
- detects the active firewall automatically
- starts server-side capture through `grpcurl`
- starts LAN and WAN `tcpdump` on the active firewall
- runs `iperf3` from `cluster-userspace-host`
- saves artifacts under `/tmp`

Run:

```bash
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 4
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 6
```

Useful options:

```bash
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 4 --parallel 4 --duration 8
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 6 --parallel 1 --duration 5 --cport 55340
```

Artifacts:
- `server-grpc.txt`
- `fw-lan.txt`
- `fw-wan.txt`
- `fw-stats-before.txt`
- `fw-stats-after.txt`
- `iperf.json`
- `summary.txt`

Workflow:

1. Run the helper script for the family and stream count you want.
2. Read `summary.txt` first.
3. If throughput collapses after a strong first interval:
   - compare `fw-wan.txt` and `server-grpc.txt`
   - look for port drift, duplicate tuples, RSTs, or missing replies
4. Use `fw-stats-before.txt` and `fw-stats-after.txt` to confirm whether the
   active firewall actually traversed the userspace dataplane.

Assumptions:
- `grpcurl`, `incus`, and `iperf3` are installed locally
- the isolated userspace cluster already exists
- the server-side gRPC capture service is reachable on `172.16.80.200:50051`

Do not use this skill to change cluster config or rebuild VMs. It is for
repeatable capture and analysis only.

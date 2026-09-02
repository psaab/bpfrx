# Comprehensive xpf Dataplane Firewall Test & Failure Injection Harness
## Architectural Design Specification & Verification Framework

- **Document Version:** `1.0.0-PROPOSED`
- **Target System:** `gemini-xpf` (Userspace AF_XDP Dataplane & Go Control Plane)
- **Base Kernel Requirements:** Linux `>= 6.18` (AF_XDP verifier floor, `init_on_alloc=0`, 2MB Hugepages)
- **Author:** Systems Architect & HPC Dataplane Specialist (Gemini/Antigravity)
- **Reviewer:** Adversarial Design Reviewer (`AGENTS.md` Mandate)
- **Status:** Under Review (Requesting Feedback)

---

## 1. Executive Summary & Design Philosophy

The `gemini-xpf` firewall operates in an extreme networking envelope: 100GbE line-rate throughput, sub-microsecond transit latency, and zero-allocation fast-path processing using an AF_XDP userspace architecture in Rust coordinated with an asynchronous Go control plane. 

Testing a carrier-grade firewall cannot rely on superficial "ping and iperf" smoke checks. A firewall failure is catastrophic in two distinct modalities:
1. **Performance Failure (Soft Failure):** Lock contention, cache bouncing, UMEM ring exhaustion, or timer-wheel stalls causing multi-gigabit flows to collapse to zero throughput or introduce severe jitter to interactive traffic.
2. **Security & Correctness Failure (Hard Failure / Fail-Open):** A malformed packet bypassing security zones, an uninstalled NAT rule appearing active in telemetry, a policy simulator reporting `PERMIT` when the dataplane drops with `DENY`, an integer truncation wrapping packet lengths on the wire, or a daemon crash converting an edge firewall into an open Linux transit router.

This document specifies the complete design for a production-grade, automated test harness that exercises both extremes:
- **High-Throughput & Flow Density:** Driving 100,000 to 10,000,000 concurrent stateful flows across multi-worker AF_XDP queues at line rate (14.88 Mpps to 148.8 Mpps) to evaluate RSS distribution, conntrack lock-free scalability, and Class of Service (CoS) pacing.
- **Bit-Exact Correctness:** Injecting malformed, out-of-order, fragmented, and adversarial packets to verify that every security policy, screen, and translation (SNAT, DNAT, Twice-NAT, NAT64, NPTv6) operates strictly according to specification.
- **Adversarial Chaos & Failure Injection:** Provoking control-plane crashes, conntrack exhaustion, port depletion, link flaps, split-brain cluster states, and asymmetric routing to guarantee fail-closed enforcement and sub-second recovery.
- **Observability Truthfulness:** Eliminating "observability lies" by auditing CLI, REST, gRPC, and Prometheus telemetry against actual wire packet capture truth.

---

## 2. Testbed Topology & Spin-up Architecture

To support both rapid developer iteration and full-scale 100G validation, the test harness is architected into three distinct environment tiers sharing an identical logical topology:

```
                                +-----------------------------------+
                                |     Test Orchestrator & Driver    |
                                |   (Python / Scapy / TRex / mtr)   |
                                +-----------------+-----------------+
                                                  |
                     +----------------------------+----------------------------+
                     |                            |                            |
       +-------------+-------------+  +-----------+-----------+  +-------------+-------------+
       |   Client: trust-host     |  |   Target: untrust-host|  |    Server: dmz-host       |
       |  10.0.1.100 / 2001:db8:1::|  |10.0.2.100/ 2001:db8:2:|  | 10.0.30.100/ 2001:db8:30: |
       +-------------+-------------+  +-----------+-----------+  +-------------+-------------+
                     | eth0                       | eth0                       | eth0
                     | (10.0.1.100)               | (10.0.2.100)               | (10.0.30.100)
                     v                            v                            v
               +-----------+                +-----------+                +-----------+
               | xpf-trust |                |xpf-untrust|                |  xpf-dmz  |
               |  bridge   |                |  bridge   |                |  bridge   |
               +-----+-----+                +-----+-----+                +-----+-----+
                     |                            |                            |
                     | ge-0-0-0 (10.0.1.10)       | ge-0-0-1 (10.0.2.10)       | ge-0-0-2 (10.0.30.10)
                     +----------------------------+----------------------------+
                                                  |
                               +------------------v------------------+
                               |         xpf Dataplane Router        |
                               |    (DUT: xpfd + xpf-userspace-dp)   |
                               |                                     |
                               |  fxp0: mgmt (10.0.100.10)           |
                               |  em0:  cluster fabric (192.168.1.1) |
                               |  ge-0-0-3: wan pf (172.16.50.5)     |
                               |  ge-0-0-4: loss/chaos pf            |
                               +-------------------------------------+
```

### 2.1 Environmental Deployment Tiers

1. **Tier 1 (CI Fast Sandbox - Network Namespaces):**
   - Implemented via lightweight Linux network namespaces (`ip netns`) interconnected with veth pairs.
   - Used for unit/functional testing of packet transformations, screen defenses, and policy evaluation.
   - Runs in unprivileged or standard CI runner environments without hardware requirements.
2. **Tier 2 (Virtual Appliance Lab - Incus Containers & QEMU VMs):**
   - High-fidelity virtualization matching the production appliance image (`Ubuntu 26.04`, Linux kernel `>= 6.18`).
   - VirtIO-net network adapters attached to dedicated Linux bridges (`xpf-trust`, `xpf-untrust`, `xpf-dmz`).
   - Emulates full systemd lifecycle, `networkd`, FRR routing daemon, and multi-core AF_XDP dispatch.
3. **Tier 3 (Bare-Metal HPC Cluster - SR-IOV / Hardware NICs):**
   - Intel E810 / Mellanox ConnectX-6 Dual-Port 100GbE PCIe Gen4 NICs.
   - Zero-copy hardware UMEM (`XDP_ZERO_COPY`), hugepages (2MB/1GB), and hardware flow steering.
   - Target for maximum multi-flow saturation, microsecond latency profiling, and line-rate pacing.

### 2.2 Invariant Enforcement: DUT Isolation (#1992 / #1961)
When testing dataplane forwarding, multiple firewall instances attached to shared gateway bridges (`xpf-trust` and `xpf-untrust`) will both answer ARP requests for the static gateway IPs (`10.0.1.10` and `10.0.2.10`). This causes non-deterministic ARP flipping, intermittent packet blackholing, and false "virtio-net NAPI queue stall" readings.
- **Mandate:** The test harness MUST enforce single-DUT ownership before launching any test.
- **Mechanism:** Inspect bridge membership across `xpf-trust` and `xpf-untrust`. If any secondary instance is attached to both bridges, the harness must refuse execution or force teardown via `XPF_FORCE_TEARDOWN_PEERS=1`.

### 2.3 Automated Spin-Up & Provisioning Runbook

```bash
#!/usr/bin/env bash
# Step 1: System Level Tuning on DUT Host
sysctl -w net.core.bpf_jit_enable=1
sysctl -w net.core.bpf_jit_harden=0
sysctl -w vm.nr_hugepages=2048                # 4GB in 2MB hugepages for UMEM
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.accept_ra=0

# Step 2: Initialize Incus Environment & Isolated Networks
incus network create xpf-trust ipv4.address=none ipv6.address=none
incus network create xpf-untrust ipv4.address=none ipv6.address=none
incus network create xpf-dmz ipv4.address=none ipv6.address=none

# Step 3: Launch xpf-fw Router Instance
incus launch images:ubuntu/26.04/cloud xpf-fw --vm \
  -c limits.cpu=8 -c limits.memory=8GB \
  -d root,size=20GB
# Attach Dataplane Interfaces
incus config device add xpf-fw eth1 nic network=xpf-trust name=enp7s0
incus config device add xpf-fw eth2 nic network=xpf-untrust name=enp8s0
incus config device add xpf-fw eth3 nic network=xpf-dmz name=enp9s0

# Step 4: Launch Test Hosts (Clients & Servers)
for host in trust-host untrust-host dmz-host; do
  incus launch images:ubuntu/26.04 $host
done
incus config device add trust-host eth0 nic network=xpf-trust name=eth0
incus config device add untrust-host eth0 nic network=xpf-untrust name=eth0
incus config device add dmz-host eth0 nic network=xpf-dmz name=eth0

# Step 5: Configure Host Addressing & Default Routes
incus exec trust-host -- ip addr add 10.0.1.100/24 dev eth0
incus exec trust-host -- ip addr add 2001:db8:1::100/64 dev eth0
incus exec trust-host -- ip route add default via 10.0.1.10
incus exec trust-host -- ip -6 route add default via 2001:db8:1::10

incus exec untrust-host -- ip addr add 10.0.2.100/24 dev eth0
incus exec untrust-host -- ip addr add 2001:db8:2::100/64 dev eth0
incus exec untrust-host -- ip route add default via 10.0.2.10
incus exec untrust-host -- ip -6 route add default via 2001:db8:2::10

incus exec dmz-host -- ip addr add 10.0.30.100/24 dev eth0
incus exec dmz-host -- ip addr add 2001:db8:30::100/64 dev eth0
incus exec dmz-host -- ip route add default via 10.0.30.10

# Step 6: Deploy xpf Binaries & Initial Firewall Configuration
scp xpfd xpf-userspace-dp cli xpf-fw:/usr/local/sbin/
scp test/incus/xpf-test.conf xpf-fw:/etc/xpf/xpf.conf
incus exec xpf-fw -- systemctl restart xpfd
```

---

## 3. Dual-Engine Test Harness Architecture

To guarantee both wire-level micro-correctness and multi-gigabit macro-scalability, the test harness is decoupled into two complementary execution engines:

```
                       +---------------------------------------------------+
                       |              xpf-test-harness Controller          |
                       +-------------------------+-------------------------+
                                                 |
                   +-----------------------------+-----------------------------+
                   |                                                           |
+------------------v--------------------+                 +--------------------v--------------------+
|  Engine A: Deterministic Correctness  |                 |     Engine B: High-Throughput / Scale   |
|         (Scapy / Raw AF_PACKET)       |                 |        (TRex / MoonGen / DPDK / iperf3) |
+---------------------------------------+                 +-----------------------------------------+
| • Bit-exact packet injection/capture  |                 | • 100k - 10M concurrent 5-tuple flows   |
| • Checksum & length invariant verify  |                 | • Elephant vs mouse flow contention     |
| • Asymmetric & malformed packet fuzz  |                 | • Line-rate saturation (14.88M - 148Mpps)|
| • State machine edge transitions      |                 | • Nanosecond pacing & jitter validation |
| • NAT64/NPTv6/Twice-NAT transforms   |                 | • Cache miss, IPC & UMEM exhaustion     |
+---------------------------------------+                 +-----------------------------------------+
```

### 3.1 Engine A: Deterministic Packet Correctness Engine
- **Tooling:** Python 3.13, Scapy, `pytest`, Linux AF_PACKET raw sockets with Fanout mode.
- **Responsibility:** Injects specifically crafted packets at ingress interfaces and sniffs corresponding egress interfaces with millisecond timeouts.
- **Verification Assertions:**
  - Bit-exact header rewrites (IPv4 TTL, IPv6 Hop Limit, MAC address updates).
  - Accurate L3/L4 checksum recalculations (RFC 1624 incremental updates).
  - Exact IP and port mappings under all NAT flavors.
  - Zero packet leakage (asserting 0 packets emerge on egress when a packet is dropped by policy or screen).
  - Proper ICMP error emissions (TTL Expired, Fragmentation Needed with correct next-hop MTU, Port Unreachable).

### 3.2 Engine B: High-Throughput & Multi-Flow Scale Engine
- **Tooling:** TRex Stateful/Stateless Traffic Generator, MoonGen (Lua/DPDK), `iperf3 -P N`.
- **Responsibility:** Pushes hardware to its physical boundaries across thousands to millions of active flows.
- **Metrics Collected:**
  - **PPS & Throughput Ceilings:** 64B, 128B, 512B, 1500B, and 9000B Jumbo frame curves.
  - **New-Flow Connection Rate (CPS):** Stressing the session-table allocation and SYN-ACK fast path.
  - **Flow Concurrency:** Scaling active flows from 10k to 10M, measuring conntrack hash bucket distribution and cache misses (`perf stat -e L1-dcache-load-misses,LLC-load-misses`).
  - **Mouse Latency Under Elephant Contention:** Measuring p50, p99, and p99.99 round-trip latency of 64-byte probe packets while 4 x 25Gbps UDP elephant flows fully saturate the link, validating the MQFQ scheduler and deficit round-robin pacing.

---

## 4. Comprehensive Feature Validation Matrix

The test harness exercises the entire breadth of firewall functionality through parameterized test plans:

### 4.1 Security Policies & Zone Evaluation

```
+----------------------------------------------------------------------------------------------------+
|                                    SECURITY POLICY MATRIX                                          |
+-------------+-------------+---------------------+-------------------+------------------------------+
| Ingress     | Egress      | Policy Action       | Test Packet       | Expected Behavior            |
+-------------+-------------+---------------------+-------------------+------------------------------+
| trust       | untrust     | permit              | TCP SYN (80, 443) | PERMIT: Session created, ACK |
| trust       | untrust     | permit              | UDP (53, 123)     | PERMIT: Bi-directional flow  |
| untrust     | trust       | default-deny        | Any Inbound       | DENY: Silent drop, 0 egress  |
| untrust     | trust       | reject              | TCP SYN (22)      | REJECT: TCP RST emitted      |
| untrust     | trust       | reject              | UDP (161)         | REJECT: ICMP Unreachable em. |
| trust       | dmz         | permit (HTTP only)  | TCP SYN (80)      | PERMIT: Allowed              |
| trust       | dmz         | permit (HTTP only)  | TCP SYN (22)      | DENY: Dropped by rule filter |
| unzoned     | untrust     | default-policy: any | Any Inbound       | DENY: #6682 unconditional    |
|             |             |                     |                   | drop of unzoned ingress      |
+-------------+-------------+---------------------+-------------------+------------------------------+
```

#### Test Execution Protocol:
1. **Bidirectional State Tracking:** Send TCP SYN from `10.0.1.100` -> `10.0.2.100`. Verify session appears in `show security flow session`. Verify return TCP SYN-ACK from `10.0.2.100` -> `10.0.1.100` is permitted automatically without requiring an untrust->trust rule.
2. **First-Packet Non-SYN Drop:** Transmit raw TCP ACK or FIN without a prior session. Verify the packet is dropped immediately and does not create an embryonic session.
3. **Application Identification (AppID):** Transmit SSH payload over port 80. Verify that dynamic application matching reclassifies the session from `junos-http` to `junos-ssh` and enforces the SSH policy rule.
4. **Host-Inbound Protection:** Probe router's own interfaces (`10.0.1.10` on trust, `10.0.2.10` on untrust). Verify SSH is permitted on trust (where configured) and denied on untrust. Verify BGP (port 179) is accepted only from configured BGP neighbor IPs.

---

### 4.2 Comprehensive NAT Matrix

```
                                  NAT TOPOLOGY & TRANSFORMS
      [trust-host]                                                            [untrust-host]
     10.0.1.100:50000 ------------------------------------------------------> 10.0.2.100:80
                                              xpf-fw
      (Source NAT)               Ingress: ge-0-0-0 -> Egress: ge-0-0-1
                                 Rewrites Source: 10.0.1.100:50000 -> 10.0.2.10:25432
                                 Packet Wire: 10.0.2.10:25432 ---------> 10.0.2.100:80

      (Dest NAT)                 Ingress: ge-0-0-1 (Target VIP: 10.0.2.10:8080)
                                 Rewrites Dest:   10.0.2.10:8080 ------> 10.0.30.100:80
                                 Packet Wire: 10.0.2.100:43210 --------> 10.0.30.100:80

      (NAT64)                    Ingress: ge-0-0-0 (IPv6: 2001:db8:64::10)
                                 Target:  64:ff9b::198.51.100.1
                                 Rewrites to IPv4: 172.16.50.5:12000 --> 198.51.100.1:80
```

1. **Source NAT (Interface & Pool Modes):**
   - Verify port overloading: 1,000 internal IPs multiplexed onto 1 public IP across disjoint source ports.
   - Verify deterministic CGNAT (RFC 6431): Subscriber IP `10.0.1.X` maps to a mathematically pre-allocated block of 64 ports on public IP `198.51.100.Y`. Verify port parity preservation (even source port maps to even external port for RTP/RTCP).
   - Verify `then source-nat off`: Traffic to partner VPN subnets bypasses translation and preserves private IPs.
2. **Destination NAT & Hairpinning (Reflection):**
   - Port Forwarding: Inbound request to `10.0.2.10:80` translates destination to DMZ host `10.0.30.100:80`.
   - Hairpinning / Reflection: A trust client (`10.0.1.100`) sends traffic to the public VIP (`10.0.2.10:80`) to access the DMZ server. Verify the firewall applies *both* DNAT (destination becomes `10.0.30.100`) and SNAT (source becomes `10.0.1.10` or trust gateway) so the return traffic routes back through the firewall.
3. **Twice NAT (Source + Destination Simultaneous):**
   - Incoming packet has both source and destination rewritten to prevent address overlapping in multi-tenant cloud interconnects.
4. **NAT64 / DNS64 (RFC 6146 / RFC 7915):**
   - Pure IPv6 host sends packets to IPv4-embedded IPv6 address `64:ff9b::c633:6401` (`198.51.100.1`).
   - Verify full header synthesis: IPv6 40-byte header stripped, IPv4 20-byte header generated, L4 TCP/UDP checksum recalculated taking into account the IPv4 pseudo-header.
   - Guarding against integer truncation (Finding 19): Transmit IPv6 jumbogram/fragment with payload > 65,515 bytes. Verify `xpf-userspace-dp` does not wrap `as u16` and cleanly drops or clamps with RFC 7915 ICMPv6 Packet Too Big.
5. **NPTv6 (RFC 6296 - IPv6-to-IPv6 Network Prefix Translation):**
   - 1:1 translation between internal ULA (`fd00:1::/48`) and external GUA (`2001:db8:cafe::/48`).
   - Verify checksum-neutral translation: assert that L4 TCP/UDP checksums remain valid *without* modifying the L4 header bytes, proving correct 16-bit 1s-complement checksum adjustment in the prefix.

---

### 4.3 Stateless Screen Engine & Attack Mitigation

The harness runs automated fuzzing scripts against the stateless screen pipeline:
- **SYN Flood Protection:** Blast 500,000 SYN packets/sec from randomized spoofed IPs. Assert that `xpf-userspace-dp` engages drop thresholds or SYN-cookies without depleting the session table for legitimate trust traffic.
- **TCP Land Attack:** Transmit packets where `src_ip == dst_ip` and `src_port == dst_port`. Assert 100% drop on ingress descriptor.
- **Teardrop & Overlapping Fragment Attack:** Send fragmented IP packets with overlapping byte offsets (`frag1: 0..36`, `frag2: 24..60`). Assert immediate drop.
- **Malformed IPv4 Header Bounds (Finding 09 Guard):** Inject IPv4 packets with `IHL = 4` (16 bytes, `< 5`). Assert that `extract_screen_info` rejects the frame and does not miscalculate the L4 offset.
- **Ping of Death:** Transmit fragmented ICMP echo whose reassembled size exceeds 65,535 bytes. Assert drop.

---

## 5. Adversarial Failure Injection & Chaos Engineering Suite

The core value of this test harness lies in its ability to execute systematic failure injection during live, saturated forwarding.

```
                                  CHAOS INJECTION MATRIX
+------------------------+------------------------------------+--------------------------------------+
| Failure Scenario       | Fault Injected                     | Pass/Fail Criteria                   |
+------------------------+------------------------------------+--------------------------------------+
| Control Daemon Kill    | `pkill -9 xpfd` while at 40G load  | Dataplane continues forwarding with  |
|                        |                                    | 0 packet loss; active sessions stay. |
+------------------------+------------------------------------+--------------------------------------+
| Dataplane Crash        | `pkill -9 xpf-userspace-dp`        | Supervisor respawns; transit gate    |
|                        |                                    | forces fail-closed (no open route).  |
+------------------------+------------------------------------+--------------------------------------+
| Toxic Configuration    | Push malformed crypto envelope     | Commit rejected; daemon preserves    |
|                        | or undefined zone reference        | existing live config (no wipe).      |
+------------------------+------------------------------------+--------------------------------------+
| Conntrack Exhaustion   | Flood 10,000,000 embryonic SYNs    | Established connections unaffected;  |
|                        |                                    | LRU reclaims stale SYNs; no OOM.     |
+------------------------+------------------------------------+--------------------------------------+
| Port Exhaustion        | 64,512 flows on single NAT IP      | Clean drop / ICMP Unreachable;       |
|                        |                                    | zero port aliasing / cross-talk.     |
+------------------------+------------------------------------+--------------------------------------+
| UMEM Ring Starvation   | Inject 148Mpps 64B burst on 100G   | Packets drop at ring; zero leak;     |
|                        |                                    | instant recovery when rate drops.    |
+------------------------+------------------------------------+--------------------------------------+
| Link Carrier Flap      | `ip link set dev enp7s0 down/up`   | Dataplane unbinds/rebinds XSK;       |
|                        |                                    | ARP flushes and resolves cleanly.    |
+------------------------+------------------------------------+--------------------------------------+
| HA Sudden Node Death   | `echo c > /proc/sysrq-trigger`     | Peer promotes in <1s; GARP sent;     |
|                        | on active cluster master           | 0 dropped TCP streams in iperf3.     |
+------------------------+------------------------------------+--------------------------------------+
| Split-Brain Heartbeat  | Sever cluster heartbeat VLAN       | Fence isolates backup; lifeline IP   |
|                        |                                    | withheld; no dual-master collisions. |
+------------------------+------------------------------------+--------------------------------------+
| Asymmetric Routing     | Forward via Node 0, Return Node 1  | Inter-chassis fabric redirects flow; |
|                        |                                    | session state synchronized.          |
+------------------------+------------------------------------+--------------------------------------+
| MTU Path Blackhole     | 1500B DF packet into 1420B tunnel  | Emits ICMP Type 3 Code 4 containing  |
|                        |                                    | accurate next-hop MTU 1420.          |
+------------------------+------------------------------------+--------------------------------------+
```

### 5.1 Automated Chaos Test Execution Architecture

The chaos harness is driven by an automated Python supervisor utilizing `asyncio` and SSH/REST APIs:

```python
import asyncio
import pytest
from harness.traffic import TrafficGenerator, iperf3_stream
from harness.dut import XpfDUT

@pytest.mark.chaos
async def test_control_plane_crash_during_saturation(dut: XpfDUT, traffic: TrafficGenerator):
    """
    Validates that a fatal crash of the Go control plane (xpfd) does not disrupt
    live forwarding or drop existing TCP connections in the Rust dataplane.
    """
    # 1. Establish 100 concurrent stateful iperf3 streams across zones (Trust -> Untrust)
    async with iperf3_stream(parallel=100, duration=60) as session:
        await asyncio.sleep(5)
        initial_rate = await session.get_aggregate_gbps()
        assert initial_rate > 10.0, f"Expected >10 Gbps, got {initial_rate}"

        # 2. Inject Chaos: Hard-kill the Go daemon
        await dut.ssh("killall -9 xpfd")
        await asyncio.sleep(5)

        # 3. Assert Dataplane Resilience
        mid_rate = await session.get_aggregate_gbps()
        assert mid_rate >= (initial_rate * 0.95), "Throughput dropped >5% during control plane death!"
        assert await session.get_retransmits() == 0, "Packet drops or retransmits detected!"

        # 4. Restart Control Plane and verify session re-attachment
        await dut.ssh("systemctl start xpfd")
        await asyncio.sleep(3)
        assert await dut.is_service_active("xpfd")
        
        # Verify socket IPC re-attached without resetting conntrack
        sessions_count = await dut.cli("show security flow session summary")
        assert sessions_count >= 100, "Conntrack state was wiped on daemon restart!"
```

---

## 6. Observability & Anti-Lying Verification Framework

A major source of latent production failure identified in prior audits is **Observability Drift**: management planes displaying stale, idealized, or unverified status while live dataplane forwarding is degraded or blackholed.

The test harness embeds a continuous **Cross-Surface Triangulation Gate**:
1. **Wire Reality:** Capture pcap on target ingress and egress interfaces using hardware timestamps or `tcpdump -j adapter_unsynced`.
2. **Dataplane Reality:** Query userspace socket `/run/xpf/dataplane.sock` to read raw atomic counters and session table snapshots.
3. **Telemetry Presentation:** Query local CLI, remote CLI, REST API (`/api/v1/security/*`), gRPC endpoints (`GetNATRules`, `GetVRRPStatus`), and Prometheus `/metrics`.

### 6.1 Automated Observability Integrity Assertions:
- **Disarmed NAT Rules (Finding 03 & 11):** When a NAT pool is configured but missing or out of budget, the harness asserts that `show security nat source` and REST `/api/v1/security/nat/rules` explicitly display `NOT INSTALLED` and `missing_pool` rather than showing the rule as active with 0 hits.
- **Forwarding StatusParity (Finding 04):** When a dataplane write fails or is unapplied, `show chassis cluster status` must report `Forwarding: degraded / unapplied`, never falsely stating `consistent (rg-active=true)`.
- **Prometheus Health During Degraded Boot (Finding 14):** When the dataplane is in config-only mode or unloaded, the harness asserts that system CPU, memory, daemon uptime, and DHCP lease metrics continue scraping successfully from `/metrics`.
- **Parity with Policy Simulator (Finding 02):** The harness runs differential assertions comparing `show security match-policies` against actual packet evaluation in `policy.rs`. If `match-policies` returns `PERMIT` for unzoned traffic, the harness fails immediately.

---

## 7. Test Harness Implementation Roadmap & Deliverables

```
                                  EXECUTION TIMELINE
       Week 1                    Week 2                    Week 3                    Week 4
+-------------------+     +-------------------+     +-------------------+     +-------------------+
| Phase 1: Base     | --> | Phase 2: Correct  | --> | Phase 3: Scale &  | --> | Phase 4: Chaos &  |
| Topology & Netns  |     | Engine (Scapy)    |     | Perf (TRex/100G)  |     | CI Gating         |
+-------------------+     +-------------------+     +-------------------+     +-------------------+
| • Setup scripts   |     | • Zone policy     |     | • 10M flow scale  |     | • Daemon kills    |
| • DUT isolation   |     | • Full NAT matrix |     | • CoS pacing/MQFQ |     | • HA split-brain  |
| • Incus VM profile|     | • Screen fuzzing  |     | • Cache misses    |     | • Zero-loss gate  |
+-------------------+     +-------------------+     +-------------------+     +-------------------+
```

### Deliverable Artifacts:
1. `test/harness/topology/`: Incus, VM, and netns provisioning scripts with automated DUT isolation guards.
2. `test/harness/correctness/`: Modular `pytest` suites covering policies, SNAT, DNAT, Twice-NAT, NAT64, NPTv6, screens, and ALGs.
3. `test/harness/scale/`: TRex stateless and stateful traffic profiles for multi-million flow saturation and CoS latency verification.
4. `test/harness/chaos/`: Automated fault-injection engines exercising daemon crashes, buffer exhaustion, and cluster failover.
5. `test/harness/audit/`: Telemetry vs wire parity checkers validating CLI, REST, gRPC, and Prometheus honesty.

---

## 8. Adversarial Design Review Critique & Refutation

In accordance with `AGENTS.md` and the rigorous HPC persona mandated by `GEMINI.md`, the following critique was conducted by the Design Reviewer:

### Reviewer Challenge 1: VirtIO-Net vs AF_XDP Native Divergence
* **Objection:** Testing on Incus VMs using VirtIO-Net (`XDP_DRV` / generic mode) does not replicate bare-metal hardware behavior. Intel E810 and Mellanox ConnectX-6 use zero-copy UMEM (`XDP_ZERO_COPY`) with hardware descriptor rings and hardware RSS hashing. A test harness validated solely on VirtIO will completely miss hardware cache-line bouncing, PCIe backpressure, and zero-copy buffer recycling bugs.
* **Architect Resolution:** The harness architecture explicitly mandates a three-tier model. While Tier 1 (netns) and Tier 2 (Incus) are used for functional correctness and CI pull-request gating, Tier 3 (Bare-Metal HPC Cluster) with dedicated SR-IOV VFIO passthrough on E810/CX6 is required for all scale, performance, and memory-barrier gates. Tier 3 includes hardware-level counters (`ethtool -S`, `perf stat` for PCIe stall cycles and LLC misses).

### Reviewer Challenge 2: Test Flakiness Under Asynchronous HA Failover
* **Objection:** In HA cluster testing, testing rapid failover with `CYCLE_INTERVAL=5` while asserting "zero dropped packets" on TCP streams is physically impossible without lossless MPSC queue synchronization and instant peer GARP processing. Network bridges take up to 50ms to update FDB tables on MAC movement. The harness will generate massive false-positive CI failures due to bridge learning latency rather than dataplane bugs.
* **Architect Resolution:** The harness explicitly decouples L2 bridge convergence from firewall dataplane convergence:
  1. For bridge-based virtual testing, test hosts use static ARP entries pointing to the cluster RETH virtual MAC, and the harness monitors GARP arrival at the bridge rather than TCP retransmission timeouts.
  2. The acceptance criterion during failover is strictly pinned: 0 broken TCP sessions (`RST` count == 0), retransmits bounded by the L2 failover window (< 200ms), and 0 permanent stalls. On bare-metal Tier 3 (using direct L2 switches with fast MAC learning), sub-50ms cutover is enforced.

### Reviewer Challenge 3: Resource Starvation in Multi-Flow Scale Tests
* **Objection:** Pushing 10,000,000 active concurrent flows requires over 1.28 GB of RAM solely for the conntrack table (`128B * 10M`), plus UMEM descriptors. If the test runner host runs the TRex generator on the same physical box, CPU core contention between TRex worker threads and `xpf-userspace-dp` polling threads will invalidate all latency and jitter measurements.
* **Architect Resolution:** The specification strictly mandates **Physical Core Isolation**. TRex or MoonGen MUST run on a dedicated generator machine connected via dual 100GbE DAC cables, or on strictly partitioned NUMA nodes with pinned isolcpus (`isolcpus=24-47` for DUT, `0-23` for traffic gen). No test runner threads are permitted on the cores assigned to AF_XDP worker threads.

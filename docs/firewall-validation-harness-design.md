# Dataplane Firewall Validation: Harness Gap Analysis & Verification Specification

- **Document Version:** `2.0.0-PROPOSED`
- **Target System:** `xpf` (Userspace AF_XDP Dataplane & Go Control Plane)
- **Base Kernel Requirements:** Linux `>= 6.18` (AF_XDP verifier floor, `init_on_alloc=0`, 2MB Hugepages)
- **Status:** Revised per PR #8302 Review Feedback

---

## 1. Context & Scope: Distinguishing What Ships from What is Missing

The `xpf` repository already contains a mature testing foundation:
- **Unit & In-Process Tests:** Over 5,200 unit tests (`cargo test` and `go test`), 149 packet-injection call sites, `BPF_PROG_TEST_RUN` integration, and a proptest harness (#1838–#1840).
- **Environment & Lifecycle Management:** `test/incus/setup.sh` owns container/VM provisioning, packaging, kernel tuning, and DUT gateway isolation (`assert_sole_dataplane_owner()`, #1992/#1961). Binary deployment is strictly governed by `deploy-lib.sh` (#1864/#1869 verify-dataplane gate).
- **Cluster & HA Validation:** `scripts/userspace-ha-validation.sh`, `test/incus/test-connectivity.sh`, `test/incus/test-failover.sh`, and `test/incus/test-ha-crash.sh` validate steady-state reachability, RETH virtual IPs, and active-passive / active-active transitions under cluster lock (#1875/#4020).
- **In-Tree Traffic Generators:** `iperf3` for bulk throughput; `test/incus/cold-path-flooder/` (Rust, AF_PACKET + `sendmmsg`, #1607/#1611); and `test/incus/newflow-gen/` (Rust connection-rate generator, #4800, paired with `test/incus/newflow_ceiling_analyze.py`).

**The Goal of this Document:** Rather than duplicating existing lifecycle scripts or proposing retired dependencies (DPDK-based TRex/MoonGen retired in #1525/#1527), this specification defines a focused **Gap Analysis and Verification Plan** covering **four missing out-of-process wire capabilities** and **one owed in-tree benchmark**.

---

## 2. Invariants, Ceilings, and Falsifiability Discipline

### 2.1 The #68 Fail-Closed Contract (Correcting C1)
- **Architectural Mandate:** `xpf` is an enterprise security gateway. Its contract is strictly **#68 Fail-Closed**:
  - In HA clusters (`test/incus/test-ha-crash.sh:381`), stopping or killing `xpfd` on the primary node MUST immediately clear `rg_active`, tear down BPF maps, halt forwarding on that node, and force the backup node to take over.
  - In standalone mode, if `xpfd` or `xpf-userspace-dp` crashes or is stopped, the kernel transit gate and BPF redirect MUST halt transit traffic. Traffic must NEVER bypass firewall inspection to flow directly via the Linux kernel.
- **Falsifiability Rule:** A test that asserts traffic continues forwarding through a dead or stopped daemon is asserting a critical fail-open regression. Correct execution asserts traffic drops instantly on daemon stop until peer promotion or clean restart.

### 2.2 Clustering Cold-Boot Overlap (Correcting C2)
- **Architectural Mandate:** As documented in `pkg/cluster/README.md:3383` and `README.md:393`, a 10–15 second dual-active overlap during simultaneous cold boot is **intentional and accepted**.
- **Falsifiability Rule:** The harness does not assert immediate mutual exclusion during boot. It asserts that after the 15-second heartbeat convergence window, the lower-priority node demotes cleanly to backup without flapping.

### 2.3 Measured Ceilings & Scale Bounds
All test bounds must match empirical code invariants on `origin/master`:
- **Session Table Capacity:** Per-worker capacity is `DEFAULT_MAX_SESSIONS = 131,072` (`session_manager.rs:107`, `session/mod.rs:78`). On the 6-worker cluster, the logical capacity is `6 * 131,072 = 786,432` sessions; the aggregate entry ceiling is `2 * worker_count * DEFAULT_MAX_SESSIONS = 1,572,864` entries. The session table enforces a hard cap (`len() >= max_sessions -> false`, #1861); LRU eviction applies exclusively to the per-worker `FlowCache`, not the stateful session table.
- **Throughput & PPS Limits:** Virtio standalone forwarding caps at `~2 Gbit/s`. The cold-path flooder in container virtio environments caps at `~870 Kpps` (#1615). Measured 6-worker cluster hardware ceiling is `C_phys ~= 22–24 Gbit/s` (`docs/fairness-regimes.md`).
- **Core Allocation:** CPU pinning must use standard worker thread affinity; whole-system `isolcpus` was plan-killed (#739, #1756) due to softirq distribution across all cores.

### 2.4 Falsifiability & Gate Result Discipline
Every verification gate must distinguish three outcomes:
1. `PASS`: Explicit positive evidence collected (e.g., exact frame rewrite observed on peer, counter increment verified).
2. `FAIL`: Invariant violated, false-green suppressed, or unexpected drop. Emits exit code `1`, logs counter state, and saves pcap.
3. `SKIP`: Explicit precondition missing (e.g., remote peer container offline). Emits `SKIP: <reason>` and exits `0` without incrementing PASS count. A skip NEVER masquerades as a pass (#6567, #4907, #8244, #8277).

---

## 3. The Five Missing Verification Gaps

```
+----------------------------------------------------------------------------------------------------+
|                                    VERIFICATION GAP MATRIX                                         |
+-----+-------------------------------+-------------------------+------------------------------------+
| Gap | Focus                         | Target Script           | Underlying Invariant Tested        |
+-----+-------------------------------+-------------------------+------------------------------------+
| 1   | Wire-Level Packet Properties  | test-wire-properties.sh | PMTUD ICMP reflection, L4 offload  |
| 2   | Five-Surface Parity Audit     | test-surface-parity.sh  | Wire truth vs socket/CLI/API/stats |
| 3   | Link Carrier Flap Recovery    | test-carrier-flap.sh    | XSK unbind/rebind, no stall/leak   |
| 4   | NAT Port Exhaustion (Single)  | test-nat-exhaustion.sh  | 64,512 flows, zero cross-talk      |
| 5   | Owed Connection-Rate (CPS)    | newflow-ceiling-harness | SNAT & cross-worker lock bottlenecks|
+-----+-------------------------------+-------------------------+------------------------------------+
```

### Gap 1: Out-of-Process On-Wire Properties (`test/incus/test-wire-properties.sh`)
*Extends: `test/incus/test-connectivity.sh`*
- **The Blind Spot:** In-process unit tests (`cargo test`) verify algorithm transforms in memory, but cannot verify real kernel-to-wire interactions:
  1. **Path MTU Discovery (PMTUD, RFC 1191/1981):** When a 1500-byte frame with DF=1 enters an interface with MTU 1420 (e.g., WireGuard/GRE encapsulation), the dataplane must drop the frame and reflect an ICMP Type 3 Code 4 (Fragmentation Needed) datagram containing the exact next-hop MTU (1420).
  2. **NIC Checksum Offload vs Software Recalculation:** Verifying that checksum-neutral translations (NPTv6 RFC 6296) and incremental updates (RFC 1624) arrive intact at the remote host without corruption by kernel offload layers.
- **Harness Implementation:** Executed between `trust-host` and `untrust-host` using Python raw sockets (`unittest_shim.py`).
- **Falsifiability & Negative Verification:**
  - *Failure Condition:* If oversized DF=1 packets are silently dropped without ICMP reflection, or if reflected MTU does not match 1420, gate emits `FAIL: PMTUD reflection missing or incorrect MTU`.

---

### Gap 2: Live Five-Surface Observability Parity (`test/incus/test-surface-parity.sh`)
*Extends: `pkg/api/` telemetry endpoints and operational show commands*
- **The Blind Spot:** Solving **XDP tcpdump blindness** (`docs/phases.md:3007`, `docs/log/7770.md:36`). On native AF_XDP interfaces, packets are consumed before `sk_buff` allocation, meaning local `tcpdump` on the DUT drops 4–14 out of 15 frames. Prior audits revealed "observability lies" where APIs reported rules armed that were disarmed in the dataplane (#7473), or reported forwarding active when unapplied (#7367).
- **Harness Implementation (Peer-Side Capture):**
  1. Capture frames **peer-side** on `untrust-host` where standard kernel networking operates.
  2. Read raw dataplane counters via the UNIX control socket `/run/xpf/dataplane.sock`.
  3. Triangulate simultaneously against:
     - Peer-side wire capture (actual frames received).
     - Dataplane domain socket counters (`forward_packets`, `drop_packets`).
     - CLI operational state (`show security flow session summary`, `show security policies hit-count`).
     - REST API (`/api/v1/security/policies`, `/api/v1/security/nat/rules`).
     - Prometheus metrics (`/metrics`).
- **Falsifiability & Negative Verification:**
  - *Failure Condition:* Any discrepancy $> \epsilon$ between peer-side wire count and dataplane socket count, or any endpoint reporting disarmed rules as active, causes the gate to emit `FAIL: surface drift detected` with a complete five-surface diff.

---

### Gap 3: Live Link Carrier Flap Recovery (`test/incus/test-carrier-flap.sh`)
*Extends: `test/incus/setup.sh` interface lifecycle*
- **The Blind Spot:** What happens when an operational link experiences carrier bounce (`ip link set dev <iface> down` followed by `up`) during live forwarding. The AF_XDP worker must cleanly unbind its XSK socket, drain pending descriptors, and rebind upon carrier recovery without leaking UMEM frames or entering a persistent NAPI stall (#1961).
- **Harness Implementation:**
  1. Start sustained `iperf3` transit flow between `trust-host` and `untrust-host`.
  2. Toggle carrier: `incus exec xpf-fw -- ip link set dev enp7s0 down && sleep 2 && ip link set dev enp7s0 up`.
  3. Monitor socket reconnect and ARP re-resolution.
- **Falsifiability & Negative Verification:**
  - *Failure Condition:* If forwarding fails to recover within 3 seconds of carrier restore, or if `xpf_userspace_umem_empty_drops` increments post-recovery (indicating ring leak), the gate emits `FAIL: carrier bounce stall / UMEM leak`.

---

### Gap 4: Single-IP NAT Port Exhaustion Under Load (`test/incus/test-nat-exhaustion.sh`)
*Extends: `pkg/config/` and `userspace-dp` NAT unit tests*
- **The Blind Spot:** While the SNAT allocator is unit-tested in isolation, full saturation of all 64,512 source ports on a single external IP has never been validated against a running dataplane.
- **Harness Implementation:**
  1. Using `test/incus/cold-path-flooder/`, drive 64,512 unique concurrent flows from `10.0.1.100` targeting diverse public destinations via a single SNAT IP (`10.0.2.10`).
  2. Assert that all 64,512 mappings are uniquely established with zero port aliasing or cross-session payload leakage.
  3. Transmit the 64,513th flow: verify clean drop with ICMP Destination Unreachable / Port Unreachable, zero kernel panic, and zero table corruption.
  4. Cease traffic and verify that sessions age out per configured idle timeouts, returning the allocation pool to full availability.
- **Falsifiability & Negative Verification:**
  - *Failure Condition:* Port collision between distinct flows, daemon crash on pool saturation, or failure to reclaim ports after timeout emits `FAIL: NAT exhaustion invariant violated`.

---

### Gap 5: The Owed Connection-Rate Benchmark (`docs/userspace-newflow-ceiling.md`)
*Status: In-tree code shipped; cluster execution OWED*
- **The Blind Spot:** Bulk throughput (`iperf3`) puts near-zero pressure on the stateful session installation path. As documented in `docs/userspace-newflow-ceiling.md`, every new transit flow synchronizes across three potential lock sites:
  1. SNAT pool allocator `live` mutex (per pool).
  2. `publish_shared_session` process-wide shared session maps.
  3. `replicate_session_upsert` sibling worker command-queue mutexes.
- **Harness Implementation:**
  - Run `test/incus/newflow-gen/` from the LAN client against `xpf-userspace-fw0` on the loss cluster.
  - Run `test/incus/newflow_ceiling_analyze.py` to process the try-lock contention counters added to `userspace-dp`.
  - Record the true, measured Connections Per Second (CPS) ceiling and identify which synchronization point saturates first.
- **Falsifiability & Negative Verification:**
  - *Failure Condition:* Benchmark aborts on zero-sample capture or exit without contention breakdown, failing with `FAIL: newflow ceiling measurement incomplete`.

---

## 4. Integration into Existing Tooling

To ensure maintainability and prevent test census failures (`run-selftests.sh` checks that ran == on-disk):
- **Test Runner Integration:** All Python scripts must be placed under `test/incus/` using standard `unittest` and `test/incus/unittest_shim.py` (avoiding rejected pytest patterns per #8136).
- **Execution Guard:** Tests must acquire `/var/lock/xpf-cluster.lock` via `test/incus/cluster-lock.sh` (#1875/#4020) to prevent collisions with active developer runs.
- **Standard Makefile Targets:**
  - `make test-wire-properties` -> executes Gap 1.
  - `make test-surface-parity` -> executes Gap 2.
  - `make test-carrier-flap` -> executes Gap 3.
  - `make test-nat-exhaustion` -> executes Gap 4.
  - `make test-newflow-ceiling` -> executes Gap 5 on cluster.

# Dataplane Firewall Validation: Harness Gap Analysis & Falsifiability Specification

- **Document Version:** `3.0.0-PROPOSED`
- **Target System:** `xpf` (Userspace AF_XDP Dataplane & Go Control Plane)
- **Base Kernel Requirements:** Linux `>= 6.18` (AF_XDP verifier floor, `init_on_alloc=0`, 2MB Hugepages)
- **Status:** Revised per PR #8302 Falsifiability Audit

---

## 1. Context & Architectural Invariants

The `xpf` repository already maintains over 5,200 in-process unit tests (`cargo test` and `go test`), 149 packet-injection call sites, and cluster orchestration tooling (`test/incus/setup.sh`, `scripts/userspace-ha-validation.sh`, `test/incus/cluster-lock.sh`). 

This document defines an implementation specification for **four missing out-of-process wire verification gates** and **one owed in-tree benchmark**, grounded strictly in the architectural invariants of `origin/master`:

### 1.1 The #68 Fail-Closed Mandate
- In high-availability clusters (`test/incus/test-ha-crash.sh:381`), stopping or killing `xpfd` on the primary node MUST immediately clear `rg_active`, tear down BPF maps, halt transit forwarding on that node, and trigger backup takeover.
- In standalone deployments, if `xpfd` or `xpf-userspace-dp` crashes or terminates, kernel transit forwarding and BPF redirection MUST halt. Transit traffic must NEVER bypass firewall inspection to flow uninspected through the Linux kernel. A test that asserts traffic continues forwarding through a stopped daemon is asserting a critical fail-open regression.

### 1.2 Clustering Cold-Boot Overlap
- Per `pkg/cluster/README.md:3383` and `README.md:393`, a 10–15 second dual-active overlap during simultaneous cold boot is **intentional and accepted** while heartbeat and VRRP converge. The harness asserts clean, stable priority-based demotion after the 15-second window, not immediate mutual exclusion during boot.

### 1.3 Grounded Capacity & Performance Ceilings
- **Session Table:** Per-worker capacity is `DEFAULT_MAX_SESSIONS = 131,072` (`session_manager.rs:107`, `session/mod.rs:78`). On the 6-worker cluster, the logical capacity is `6 * 131,072 = 786,432` sessions; the entry ceiling is `2 * worker_count * DEFAULT_MAX_SESSIONS = 1,572,864` entries. The session table enforces a hard cap (`len() >= max_sessions -> false`, #1861); LRU eviction applies exclusively to the per-worker `FlowCache`.
- **Forwarding Limits:** Virtio standalone forwarding caps at `~2 Gbit/s`. The cold-path flooder in container virtio environments caps at `~870 Kpps` (#1615). Measured 6-worker cluster hardware ceiling is `C_phys ~= 22–24 Gbit/s` (`docs/fairness-regimes.md`).
- **Core Allocation:** Dataplane workers use standard thread affinity; whole-system `isolcpus` was plan-killed (#739, #1756) due to softirq distribution across all cores.

---

## 2. The Falsifiability & Positive-Evidence Discipline

A test that cannot return a distinguishable negative provides no engineering signal (#6567, #4907, #7424, #8244, #8277). To eliminate meaningless greens, every gate in this harness MUST adhere to the following rules:

1. **The Positive-Evidence Precondition:** *Every gate must assert positive evidence that the mechanism under test executed before evaluating its invariant.*
   - A carrier flap gate must observe the interface state transition to `DOWN` and verify throughput drops to zero *before* asserting recovery.
   - A NAT exhaustion gate must observe active session allocations climb above a floor *before* asserting collision-free translation.
   - A wire property gate must observe ingress frame arrival on the DUT *before* asserting reflection.
   - If positive evidence is zero, the gate MUST FAIL or ABORT, never report PASS.
2. **Tri-State Exit Discipline:**
   - `PASS` (Exit `0`): Positive evidence verified AND invariant held.
   - `FAIL` (Exit `1`): Invariant violated, fault failed to land, or positive execution evidence missing. Dumps diagnostic context, counters, and pcap.
   - `SKIP / VOID` (Exit `77`): Reserved preflight abort code (#8244). Triggered when environment prerequisites are missing (e.g., endpoint container down). In `make`, preflight aborts are distinct from zero-exit passes; a test run where executed tests == 0 fails the build.

---

## 3. Specification of the Five Verification Gates

```
+----------------------------------------------------------------------------------------------------+
|                                    VERIFICATION GATE MATRIX                                        |
+-----+-------------------------------+-------------------------+------------------------------------+
| Gate| Focus                         | Target Script           | Underlying Invariant Tested        |
+-----+-------------------------------+-------------------------+------------------------------------+
| 1   | Wire-Level Packet Properties  | test-wire-properties.sh | PMTUD ICMP reflection, L4 offload  |
| 2   | Two-Plane Surface Parity      | test-surface-parity.sh  | Wire truth vs socket/CLI/API/stats |
| 3   | Link Carrier Flap Recovery    | test-carrier-flap.sh    | XSK unbind/rebind, no leak/stall   |
| 4   | NAT Port Exhaustion (Single)  | test-nat-exhaustion.sh  | 64,512 flows, zero cross-talk      |
| 5   | Owed Connection-Rate (CPS)    | newflow-ceiling-harness | SNAT & cross-worker lock ceilings  |
+-----+-------------------------------+-------------------------+------------------------------------+
```

### Gate 1: Out-of-Process On-Wire Properties (`test/incus/test-wire-properties.sh`)
*Extends: `test/incus/test-connectivity.sh`*
- **Tested Invariant:** Path MTU Discovery (PMTUD, RFC 1191/1981) and NPTv6 (RFC 6296) checksum neutrality on actual wire.
- **Positive Execution Evidence:** Ingress counter `ReadGlobalCounter(dataplane.GlobalCtrRxPackets)` increments on the DUT.
- **Verification Logic:**
  1. **PMTUD Reflection:** Transmit a 1500-byte frame with DF=1 from `trust-host` targeting an egress path clamped to MTU 1420 (e.g. WireGuard/GRE encapsulation).
     - *FAIL Condition:* If the oversized packet emerges on `untrust-host` (leak), OR if dropped silently without an ICMP Type 3 Code 4 (Fragmentation Needed) datagram arriving back at `trust-host` within 500ms, OR if the reflected ICMP next-hop MTU does not equal 1420, gate emits `FAIL: PMTUD reflection violated`.
  2. **NPTv6 Checksum Neutrality:** Transmit IPv6 TCP/UDP datagrams with ULA source prefixes translated to GUA via NPTv6.
     - *FAIL Condition:* If peer-side packet capture on `untrust-host` detects that the L4 checksum field was mutated in the packet header, OR if the receiver kernel drops the packet due to a bad L4 checksum, gate emits `FAIL: NPTv6 checksum neutrality corrupted`.

---

### Gate 2: Two-Plane Observability Parity & Anti-Ghosting (`test/incus/test-surface-parity.sh`)
*Extends: `pkg/api/` telemetry endpoints and operational show commands*
- **The Data Plane Reality:** CLI (`cli_show_flow.go`), gRPC (`server_show_flow.go`), REST (`api.go`), and Prometheus (`metrics_counters.go:390`) all call `ReadGlobalCounter(idx)` on the same underlying dataplane interface. The five surfaces represent **two independent data planes**:
  1. **Surface 1 (Wire Truth):** Captured **peer-side** on `untrust-host` where standard kernel networking operates (addressing XDP tcpdump blindness on the DUT, `docs/phases.md:3007`, `docs/log/7770.md:36`, and noting `docs/testing.md:427` that peer firewall interfaces share this blindness).
  2. **Surface 2 (Control Surface Presentation):** The underlying dataplane counter source exposed via CLI, REST, gRPC, and Prometheus.
- **Positive Execution Evidence:** Peer-side capture on `untrust-host` receives $\ge 100$ verified transit packets.
- **Verification Logic:**
  1. **Cross-Plane Counter Agreement:** Compare peer wire packet count against `ReadGlobalCounter(dataplane.GlobalCtrTxPackets)`.
     - *FAIL Condition:* Divergence between wire received count and dataplane TX counter $> \pm 1\%$ emits `FAIL: wire vs dataplane counter divergence`.
  2. **Anti-Ghosting Assertion (#7473, #7367):** Configure an uninstalled NAT rule (e.g., missing pool reference).
     - *FAIL Condition:* If CLI (`show security nat source`) or REST (`/api/v1/security/nat/rules`) reports the rule as active rather than explicitly outputting `NOT INSTALLED` with reason `missing_pool`, gate emits `FAIL: disarmed rule ghosting detected`.
  3. **Hit-Count Safety:** Adheres to `docs/testing.md:425` and #7770/#7776: does NOT use `show security policies hit-count` for transit verification (which reports 0/0 on live policies). Uses `show security flow session summary` and global counters.

---

### Gate 3: Live Link Carrier Flap Recovery (`test/incus/test-carrier-flap.sh`)
*Extends: `test/incus/setup.sh` interface lifecycle*
- **Tested Invariant:** Clean XSK socket unbind, descriptor ring drain, and carrier recovery without UMEM frame leaks or persistent NAPI driver stalls (#1961).
- **Target Interface:** Uses the live vSRX name assigned at startup (`pkg/daemon/linksetup.go:51`), `ge-0-0-0` (or `ge-0-0-1`), NOT raw PCI names (`enp7s0`).
- **Fault Injection & Positive Execution Evidence:**
  1. Start sustained `iperf3` transit flow between `trust-host` and `untrust-host`.
  2. Issue fault: `incus exec xpf-fw -- ip link set dev ge-0-0-0 down`.
  3. **Assert Fault Landed:** Poll `ip link show dev ge-0-0-0` to confirm `state DOWN` or `NO-CARRIER` AND assert that `iperf3` throughput drops to 0 Gbit/s. If throughput remains $> 0$ or device is missing, gate emits `FAIL: carrier down fault did not land`.
- **Recovery & Invariant Check:**
  1. Issue recovery: `incus exec xpf-fw -- ip link set dev ge-0-0-0 up`.
  2. Poll `ip link show dev ge-0-0-0` to confirm `state UP`.
- **Falsifiability & FAIL Conditions:**
  - *FAIL Condition 1:* Throughput fails to recover to $\ge 80\%$ of baseline within 3 seconds -> emit `FAIL: carrier bounce forwarding stall`.
  - *FAIL Condition 2 (Descriptor Leak):* Query `show system buffers` (or REST `/api/v1/system/buffers`) and verify `UmemInflightFrames` returns to baseline ($\pm 4$ frames). If inflight frames remain permanently elevated, gate emits `FAIL: UMEM descriptor leak on carrier cycle`.
  - *FAIL Condition 3:* Dataplane counter read errors: verify `xpf_counter_read_errors_total` does not increment post-recovery.

---

### Gate 4: Single-IP NAT Port Exhaustion Under Load (`test/incus/test-nat-exhaustion.sh`)
*Extends: `pkg/config/` and `userspace-dp` NAT unit tests*
- **Addressing & Fixture:** Configures a dedicated, non-overlapping pool IP (e.g. `172.16.50.200/32` or `198.51.100.200/32`), avoiding `10.0.2.10` which is reserved for `interface;` mode and would trigger `iface_snat_egress_overlap -> pool_unusable` (#290).
- **Traffic Generation:** Multi-stream stateful client running on `trust-host` establishing bidirectional TCP connections to distinct destination ports on `untrust-host`.
- **Positive Execution Evidence:** Monitor active NAT sessions via `show security flow session summary` and assert active allocations climb past $1,000$ toward capacity. If allocated sessions == 0, gate emits `FAIL: NAT pool quarantined or not armed`.
- **Falsifiability & FAIL Conditions:**
  - *FAIL Condition 1 (Port Collision):* Verify all active flows on `untrust-host` have distinct external source ports. Any collision or cross-session payload leakage emits `FAIL: NAT port collision detected`.
  - *FAIL Condition 2 (Saturation & Fail-Closed):* Upon reaching pool capacity (64,512 allocated ports), the next connection attempt must be dropped cleanly, incrementing `ReadGlobalCounter(dataplane.GlobalCtrNATAllocFail)` with zero daemon crash and zero kernel panic. If flow 64,513 transits un-NAT'd (fail-open), gate emits `FAIL: NAT allocation fail-closed violation`.
  - *FAIL Condition 3 (Reclaim Leak):* Terminate all client connections. After configured idle timeouts, active NAT session count must return to 0. If sessions remain leaked, gate emits `FAIL: NAT session table leak`.

---

### Gate 5: Owed Connection-Rate Benchmark (`test/incus/newflow-ceiling-harness.sh`)
*Extends: `docs/userspace-newflow-ceiling.md`*
- **Contract:** Executes the owed benchmark from `docs/userspace-newflow-ceiling.md` using in-tree tooling: `test/incus/newflow-gen/` (Rust, #4800) and analyzer `test/incus/newflow_ceiling_analyze.py` on the `loss-userspace-cluster`.
- **Positive Execution Evidence:** At least $N \ge 1,000$ connections attempted and captured.
- **Falsifiability & FAIL Conditions:**
  - *FAIL Condition 1 (Measurement Void):* Zero connections completed, or script aborts without capturing try-lock contention counters -> emits `FAIL: newflow capture void`.
  - *FAIL Condition 2 (Contention Analysis Incomplete):* The analyzer must report contention ratios across all three synchronization sites:
    1. SNAT pool allocator `live` mutex.
    2. `publish_shared_session` process-wide shared session maps.
    3. `replicate_session_upsert` sibling worker command-queue mutexes.
    If any site's contention attribution is missing, gate emits `FAIL: contention attribution incomplete`.
  - *FAIL Condition 3 (Rate Regression):* Measured Connections Per Second (CPS) must exceed the baseline floor established for the cluster hardware. Any regression below floor emits `FAIL: connection rate below baseline floor`.

---

## 4. Integration into Existing Tooling

- **Test Placement & Census:** All test scripts reside in `test/incus/` using standard Python `unittest` (`test/incus/unittest_shim.py`) and standard Bash wrappers. All scripts are registered with `run-selftests.sh` to ensure `ran == on-disk` (#4210, #8136).
- **Cluster Mutex:** Tests running against shared cluster nodes MUST acquire the flock at `/tmp/xpf-cluster.lock` (with metadata in `/tmp/xpf-cluster.owner`) via `test/incus/cluster-lock.sh` (#1875/#4020).
- **Standard Makefile Targets:**
  - `make test-wire-properties` -> executes Gate 1.
  - `make test-surface-parity` -> executes Gate 2.
  - `make test-carrier-flap` -> executes Gate 3.
  - `make test-nat-exhaustion` -> executes Gate 4.
  - `make test-newflow-ceiling` -> executes Gate 5 on the cluster.

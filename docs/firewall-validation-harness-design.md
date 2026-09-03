# Dataplane Firewall Validation: Agentic Feature & Wire Verification Specification

## 1. Purpose
This specification defines an agentic validation harness for the `xpf` firewall dataplane. While the repository carries 5,225 in-process unit tests proving that isolated functions (e.g. `evaluate_policy`) compute correct verdicts in memory, unit tests structurally cannot prove that a live daemon configured through CLI/REST enforces those verdicts on the wire. This harness enables autonomous agents to drive deterministic, falsifiable verification on running systems, producing definitive `PASS`, `FAIL`, or `VOID` verdicts recorded directly in `test/results/ledger.jsonl` via `test/incus/harness-result.sh` (#8332).

## 2. Feature Validation Matrix
The primary deliverable is out-of-process wire verification across live Incus endpoints (`trust-host`, `untrust-host`, `dmz-host`). Every row requires positive execution evidence before checking invariants and defines an explicit observable failure:

| Feature | Running System Exercise | Wire / Dataplane Assertion | What It Reports When Broken | Ledger Gate |
|---|---|---|---|---|
| **Zone Policy (Deny)** | Ingress probe on untrust (`10.0.2.102`) targeting trust (`10.0.1.102`) without permit rule | 100% frame drop on wire; `GlobalCtrPolicyDeny` increments on DUT | `FAIL: policy_leak (traffic transited without rule)` | `wire_policy_deny` |
| **Zone Policy (Permit)** | Ingress probe on trust targeting untrust matching explicit permit rule | 0% loss; bidirectional session created; `GlobalCtrSessionsNew` increments | `FAIL: policy_drop (permitted flow dropped)` | `wire_policy_permit` |
| **Source NAT (Pool)** | Stateful TCP from trust via dedicated pool `172.16.50.200/32` (#8329) | Source rewritten to pool VIP; unique non-colliding L4 ports; return path intact | `FAIL: snat_untranslated` or `FAIL: snat_collision` | `wire_nat_snat` |
| **Destination NAT** | External ingress targeting VIP `10.0.2.10` port 8080 | Destination rewritten to DMZ host `10.0.30.101`; session conntrack armed | `FAIL: dnat_untranslated (VIP drop or un-NAT transit)` | `wire_nat_dnat` |
| **IPv6 Dual-Stack Transit** | Ingress IPv6 probe on trust targeting untrust (`2001:559:8585:bf02::102`) | 0% loss; bidirectional IPv6 flow conntrack entry established | `FAIL: ipv6_transit_drop (IPv6 transit unreachable)` | `wire_ipv6_transit` |
| **Stateless Screens** | Ingress SYN flood / ICMP sweep / IP spoofing on untrust | `GlobalCtrScreenDrops` increments; zero frame emergence on protected zone | `FAIL: screen_leak (screen bypassed)` | `wire_screen_drop` |
| **Tunnels (WG/GRE)** | Encapsulated packet transit across `wg0` or `gre0` | Payload emerges decapped/decrypted at peer container | `FAIL: tunnel_transit_fail (decap error/drop)` | `wire_tunnel_transit` |
| **CoS & Pacing** | Concurrent high-priority (voice) and best-effort elephants | High-priority preserves latency floor; best-effort throttles under contention | `FAIL: cos_starvation (best-effort HoL blocking)` | `wire_cos_fairness` |

## 3. Adversarial Fault Injection & Landing Witnesses
Only faults with an observable *landing witness* are admitted. Invariants are evaluated strictly after the fault is proven to have landed:

- **Live Link Carrier Flap:**
  - *Fault & Landing Witness:* `ip link set dev ge-0-0-0 down` (live vSRX name, `linksetup.go:51`). Witness: `ip link show dev ge-0-0-0` reports `NO-CARRIER` AND iperf3 throughput drops to 0 Gbit/s.
  - *Recovery Assertion:* `ip link set dev ge-0-0-0 up` restores >=80% baseline within 3s without NAPI stall (#1961). Memory check: `UmemInflightFrames` in `show system buffers` returns to baseline (+/- 4 frames) without descriptor leaks.
  - *VOID Condition:* Device missing, or baseline traffic is 0 before fault. Emits ledger gate: `fault_carrier_flap`.
- **Single-IP NAT Saturation:**
  - *Fault & Landing Witness:* 64,512 concurrent stateful flows driven via pool `172.16.50.200/32`. Witness: active sessions reach 64,512.
  - *Saturation Assertion:* Flow 64,513 dropped cleanly with `GlobalCtrNATAllocFail` increment and zero daemon crash (#68 fail-closed). Ceasing traffic reclaims all 64,512 ports.
  - *VOID Condition:* Pool quarantined (`pool_unusable`) or active flows < 1,000. Emits ledger gate: `fault_nat_exhaustion`.

*Existing Owned Chaos Pointers (do not re-specify):*
Daemon crash fail-closed (#68): `test/incus/test-ha-crash.sh` Phase 2. Supervisor respawn: `pkg/dataplane/userspace/process_supervisor.go`. High-churn conntrack eviction: `test/incus/cold-path-flooder --cohort=bounded`. Cluster boot overlap (10-15s accepted window, no fencing): `pkg/cluster/README.md:3383`, `test/incus/test-double-failover.sh`. Private RG election: `test/incus/test-private-rg.sh`. Asymmetric routing: `test/incus/test-active-active.sh`. PMTUD reflection: `userspace-dp/src/afxdp/icmp_ptb.rs`.

## 4. Cross-Surface Parity
- **The Platform Reality:** On native/zero-copy XDP, packets are processed before `sk_buff` allocation (`docs/phases.md:3007`, `docs/log/7770.md:36`). Capturing on DUT or peer firewall interfaces yields frame drops (`docs/testing.md:427`). Capture MUST be performed **peer-side** on endpoint containers (`trust-host` / `untrust-host`).
- **Telemetry Parity:** CLI (`cli_show_flow.go`), gRPC (`server_show_flow.go`), REST (`api.go`), and Prometheus (`metrics_counters.go:390`) all read the same `ReadGlobalCounter(idx)` source. Parity compares **Wire Truth** (peer pcap received count) against **Control Presentation** (`GlobalCtrTxPackets` via domain socket `/run/xpf/dataplane.sock`). Divergence > +/- 1% emits `FAIL: counter_divergence`.
- **Anti-Ghosting (#7473, #8334):** A rule naming an uninstalled pool must explicitly report `NOT INSTALLED / missing_pool`, never active with 0 hits. Hit-count is not used for transit validation (`docs/testing.md:425` / #7770). Ledger gate: `parity_wire_vs_control`.

## 5. Grounded Infrastructure & Tooling
- **Deterministic Provisioning:** `test/incus/setup.sh up` provisions Layer 2 bridges (`xpf-trust`, `xpf-untrust`, `xpf-dmz`) and endpoints (`trust-host`, `untrust-host`, `dmz-host`), enforcing DUT isolation via `assert_sole_dataplane_owner()` (#1992/#1961).
- **Cluster Mutex:** Destructive runs serialize under flock `/tmp/xpf-cluster.lock` via `test/incus/cluster-cell.sh` (#1875/#4020).
- **Ledger Recording:** Gate executions record structured envelopes in `test/results/ledger.jsonl` using `test/incus/harness-result.sh run` (#8332).
- **Census Enforcement:** Every harness must classify as `reached` under `make harness-census` (#8330).
- **Owed Benchmark:** Connection-rate CPS ceiling is measured by `test/incus/newflow-ceiling-harness.sh` using in-tree `newflow-gen` (#4800) and `newflow_ceiling_analyze.py`.

## 6. Not-Now Appendix (Hardware & Infrastructure Bounded Scope)
- **Scale Ceilings:** The 100GbE line-rate (148.8 Mpps) and 10M-flow targets from early drafts require specialized physical lab hardware not present in the current Incus test environment. Current environment bounds: virtio standalone caps at ~2 Gbit/s, flooder container caps at ~870 Kpps (#1615), physical cluster hardware caps at ~22-24 Gbit/s (`docs/fairness-regimes.md`), and logical session capacity is 786,432 (6 * DEFAULT_MAX_SESSIONS 131,072 per `session_manager.rs:107`). The 10M figure originated from #5323 as a closed observability display bug, not measured hardware capacity.
- **NAT64 & NPTv6 Wire Probing:** While firewall configuration in `xpf-test.conf` and `xpf-cluster-fw0.conf` supports stateful NAT64 (`64:ff9b::/96`) and stateless NPTv6 (RFC 6296), live wire validation of these translations is deferred until dedicated peer probers (`nat64-host` and `nptv6-host`) are provisioned in `test/incus/setup.sh`. Running these test rows against an environment without peer probers produces permanent VOID verdicts.

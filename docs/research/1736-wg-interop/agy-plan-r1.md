# Adversarial Review: #1736 Live Kernel-WireGuard Interop Plan

## Verdict: **PLAN-KILL**

Based on a rigorous analysis of the codebase, the shipped S2a engine is not ready for live interop validation. Building the proposed test harness is premature because the engine contains structural protocol defects and specifications violations that will guarantee test failures and system instability. 

We recommend killing the plan in its current shape, filing the blocker issues detailed below, and resolving them before attempting live interop tests.

---

## Findings and Evidence

### Finding 1: Permanent Rekey Deadlock on Egress (Attack 1)
* **Status**: **FATAL / STRUCTURAL BLOCKER**
* **Code Evidence**:
  - [engine.rs:704-722](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/engine.rs#L704-L722) (`try_encap` key confirmation gate)
  - [handshake_session.rs:524-531](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/handshake_session.rs#L524-L531) (`consume_initiation_create_response` session installation)
  - [peer.rs:68](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/peer.rs#L68) (unused `previous` session field)
  - [wg_control.rs:486-490](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L486-L490) (`encap_and_send` handling of `NoSession`)

#### Analysis:
The plan assumes in P4 that when the kernel peer acts as the responder and initiates a rekey at ~165 seconds, the session will be successfully rotated and survive. However, the engine's implementation violates the WireGuard specification regarding key confirmation:
1. When the kernel peer initiates a rekey, it sends an initiation packet. xpf consumes it via `consume_initiation_create_response` and installs the new session (S2) into `peer.current` as **unconfirmed**.
2. Per the WireGuard protocol, a responder must continue using the *previous* session key (S1) to encrypt outgoing data packets until it receives the first encrypted data packet from the initiator on the new session (confirming the new session).
3. However, xpf's `try_encap` only references `peer.current`. If `peer.current` is unconfirmed, it unconditionally rejects the egress packet with `EncapError::NoSession` and drops the packet. It never falls back to the valid confirmed session in `peer.previous`.
4. Under any one-way traffic originating from xpf to the peer, xpf will drop the next outbound packet due to `NoSession`. Because this packet is dropped, the peer never receives it and never replies. S2 is never confirmed, and the tunnel enters a **permanent deadlock** where no further egress can ever be sent.

---

### Finding 2: 100% Failure Rate of Outer Fragmented IP Packets (Attack 2)
* **Status**: **FATAL / STRUCTURAL BLOCKER**
* **Code Evidence**:
  - [lib.rs:1116-1117](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1116-L1117) (`parse_ipv4` calling `parse_l4` directly on L3 offset)
  - [lib.rs:1197-1198](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1197-L1198) (`parse_ipv6` calling `parse_l4` directly)
  - [lib.rs:1410-1419](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1410-L1419) (`parse_l4` for `PROTO_UDP`)
  - [lib.rs:1236-1242](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1236-L1242) (`wg_steer_to_kernel` port and destination check)
  - [lib.rs:378-380](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L378-L380) / [lib.rs:974-981](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L974-L981) (`drop_degraded_transit` XDP_DROP)

#### Analysis:
The plan's P5 phase assumes that outer IP fragments will land in the kernel for reassembly. This is structurally impossible with the current XDP shim:
1. When a UDP packet fragments, the non-first fragments **do not contain a UDP header** (only the IP header followed by raw payload bytes).
2. The shim's `parse_ipv4` and `parse_ipv6` functions ignore fragmentation offset flags. For `protocol == PROTO_UDP`, they unconditionally call `parse_l4`, which reads the first 8 bytes of the payload as if it were a UDP header.
3. The parsed `flow_dst_port` is therefore populated with random payload bytes. Since this random value will almost never match `wg_listen_port`, `wg_steer_to_kernel` returns `false`.
4. As a result, non-first fragments are never steered to the kernel via `cpumap_or_pass`. If the fragment is shorter than 8 bytes, `parse_l4` returns `None` and the packet is dropped via `XDP_DROP`. If it is 8 bytes or longer, it is steered to the XSK redirect path where it fails lookup.
5. Because the kernel never receives the non-first fragments, outer IP reassembly fails 100% of the time. The entire WireGuard record is dropped.

---

### Finding 3: HA Node Mutual Interference and Flapping (Attack 3)
* **Status**: **OPERATIONAL HAZARD**
* **Code Evidence**:
  - [wg_control.rs:288-293](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L288-L293) (`bind_wg_socket` binding)
  - [wg_control.rs:252-256](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L252-L256) (initiator re-init loop)

#### Analysis:
The plan states that the secondary node `fw1` holds no LAN address and its initiator timer is "harmless noise" that cannot reach the peer. This is false:
1. `fw1` binds its socket to `0.0.0.0` / `[::]` and has a local IP address on the shared LAN/VLAN interface.
2. The control thread on `fw1` will successfully run and send handshake initiations (msg1) to the peer endpoint. The Linux kernel will route these out of the shared interface using `fw1`'s local IP as the source.
3. Because both nodes share the identical WireGuard private key config, the peer will receive handshake initiations from both `fw0` and `fw1`. This will trigger constant endpoint flapping on the peer due to roaming.
4. Crucially, the two nodes will compete on the TAI64N timestamp high-water mark. Whichever node has a slightly faster clock (or is ahead in TAI64N) will set the high-water mark on the peer. The peer will then reject all handshake initiations from the other node as replays. If `fw1` sets a higher high-water mark, the primary active firewall `fw0` will be blocked from ever establishing a session.

---

### Finding 4: Total Telemetry Blindness on Egress/Ingress Drops (Attack 4)
* **Status**: **HARNESS LIMITATION**
* **Code Evidence**:
  - [wg_control.rs:400](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L400) (debug logs only)
  - [wg_control.rs:435](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L435) (debug logs only)
  - [wg_control.rs:492](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L492) (debug logs only)

#### Analysis:
The lack of telemetry on the xpf side is a major blocker for harness reliability. Because `debug_log!` compiles out in release builds, there are absolutely no logs or metrics indicating why packets are dropped (e.g. key rotation failures, AllowedIPs mismatch, or decrypto failure). The harness would be operating blindly, relying only on peer-side state which cannot distinguish between xpf-side drop reasons and networking drops.

---

### Finding 5: High Risk in Path A Choice (Attack 5)
* **Status**: **INFRASTRUCTURE RISK**

#### Analysis:
Path A provisions a VM on a shared cluster, risking VF leaks, VM leaks, and MAC/IP address conflicts if a test run crashes or fails to execute its teardown trap cleanups. 
The justification for Path A (needed to run the fast-path smoke) is flawed. The fast-path smoke can be executed against a dummy WG tunnel (unreachable peer) on the `loss` cluster to prove no-regress. The correctness and interop validation (handshake, rekey, MTU) should be performed on Path B (isolated local incus pair) to eliminate shared-cluster risks.

---

## Action Plan to Unblock

To make this plan ready, we must file the following blocking engine issues:
1. **Blocker 1 (Rekey Egress Fallback)**: Modify `try_encap` in [engine.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/engine.rs) to encrypt outbound traffic using the confirmed previous session (if valid and active) while the current session is still unconfirmed.
2. **Blocker 2 (Shim Fragment Identification)**: Modify the XDP parser in [lib.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs) to detect the fragmentation offset and M-flag in IPv4/IPv6 headers. Non-first fragments must bypass L4 parsing and be passed directly to the kernel via `cpumap_or_pass` if they belong to a local-destination flow.
3. **Blocker 3 (HA Control Thread Suppression)**: Update the control plane or [wg_control.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs) to inhibit the initiator timer on the secondary node unless it is in the active VRRP state.

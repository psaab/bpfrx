I will first locate and view the relevant files in `docs/research/1736-wg-interop/` to read the v2 plan and the round 1 plans, and read `userspace-xdp/src/lib.rs` around lines 505-590 as requested.
I will first search for the workspace directory using `run_command` to print the current working directory, which will help us locate the target files in the working tree.
I will list the contents of the `/home/ps` directory to locate the repository or workspace folder containing the code and the target documentation.
I will search for the file `plan.md` in `/home/ps/` or its subdirectories to locate the exact path of the working tree.
I will list the files in `/home/ps/git/avacado-xpf/docs/research/1736-wg-interop/` to see the plan (v2) and round 1 plans.
I will search for any directory matching `1736-wg-interop` under the `/home/ps/` directory.
I will check the status of the find command task to see if it has finished executing.
I will list the files in `/home/ps/git/bpfrx/.claude/worktrees/1736-research/docs/research/1736-wg-interop` to see what plan files are available.
I will read the contents of `/home/ps/git/bpfrx/.claude/worktrees/1736-research/docs/research/1736-wg-interop/plan.md` to review the full v2 plan.
I will read the contents of `/home/ps/git/bpfrx/.claude/worktrees/1736-research/docs/research/1736-wg-interop/claude-smr-plan-r1.md`.
I will read the contents of `/home/ps/git/bpfrx/.claude/worktrees/1736-research/docs/research/1736-wg-interop/agy-plan-r1.md`.
I will read the contents of `/home/ps/git/bpfrx/.claude/worktrees/1736-research/docs/research/1736-wg-interop/codex-plan-r1.md`.
I will read `/home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs` from lines 505 to 590 end-to-end to verify the shim steering behavior on session-table misses.
I will search for the definition of `is_local_destination` to see how it decides if a packet is destined locally.
I will view the definition of `is_local_destination` starting from line 1250.
I will view the `parse_ipv4` implementation in `userspace-xdp/src/lib.rs` to see what it does when encountering IP fragments.
I will view `parse_ipv4` implementation in `userspace-xdp/src/lib.rs`.
I will search for `fn parse_l4` to locate its line number in the source file.
I will view the `parse_l4` implementation to see how L4 headers are parsed.
I will search for occurrences of `parse_ipv4` in the source file to trace what happens when `parse_ipv4` returns `None`.
I will view lines 360 to 395 of `userspace-xdp/src/lib.rs` to see how parser failures are handled.
I will search for `drop_degraded_transit` in `userspace-xdp/src/lib.rs` to see what action it returns.
I will view the `drop_degraded_transit` implementation.
I will view the middle section of `try_xdp_userspace` (lines 396 to 504) to see the rest of the parsing and steering pipeline.
I will search for `wg_steer_to_kernel` to find its definition.
I will view the definition of `wg_steer_to_kernel`.
I will search for `parse_ipv6` to see how it handles IPv6 extension headers, particularly fragmentation.
I will view the `parse_ipv6` implementation in `userspace-xdp/src/lib.rs`.
I will search for the file `engine.rs` in the worktree.
I will search for `try_encap` inside `engine.rs` to locate its exact lines.
I will view `userspace-dp/src/afxdp/wg/engine.rs` from lines 690 to 760.
I will find the file `peer.rs` in the worktree.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/peer.rs` to inspect the `Peer` struct.
I will search for the WireGuard kernel/reference implementation behavior upon handshake completion to see if the initiator immediately transmits a keepalive or queued packets.
I will search for the source code or details of the `wg_packet_send_staged_packets` implementation in the Linux kernel to check what it does when the queue of staged packets is empty.
I will search for occurrences of `keepalive` inside the WireGuard Linux implementation of `wg_packet_send_staged_packets` or surrounding code to see if a keepalive packet is sent when there are no staged packets.
I will search for the specific interaction between handshake completion and sending queued packets or keepalives in the WireGuard Linux driver.
I will search for the implementation of `wg_noise_handshake_begin_session` in `wireguard-linux` to verify exactly what it does on handshake completion.
I will search for the calling sites of `wg_packet_send_staged_packets` in the WireGuard Linux driver to understand what triggers them.
I will search for the callers of `wg_packet_send_staged_packets` inside the WireGuard repository to verify if it is called when a handshake is completed or when a packet is staged.
I will search for the callers of `wg_packet_send_staged_packets` within all `.c` files in the WireGuard driver directory.
I will search for `wg_timers_handshake_complete` references to see where it is called.
I will search for `wg_timers_handshake_complete` call sites in `receive.c` to see the exact context in which it runs.
I will search for references to `tai64` or `timestamp` in the `userspace-dp` folder to see how TAI64N is implemented and why it might lack monotonicity across restarts.
I will view the first 150 lines of `userspace-dp/src/afxdp/wg/tai64n.rs` to understand the `Tai64nClock` implementation.
I will view lines 150 to 195 of `userspace-dp/src/afxdp/wg/tai64n.rs` to see how the clock is initialized.
I will view the `reviewer-ids.md` file to see the context of previous reviews.
I will view `userspace-dp/src/afxdp/forwarding_build/wg.rs` to verify how endpoint removal triggers a session-tearing rebuild.
# Hostile Plan Re-Review: #1736 S2b Live Interop (v2)

## Verdict: **PLAN-READY**

Having completed a rigorous end-to-end code walkthrough and matched the WireGuard specification and Linux kernel implementation details, the v2 plan has successfully resolved all structural and operational concerns. The Round 1 `PLAN-KILL` verdict is revoked. The plan is now **ready for execution**.

---

## 1. Verification of v2 Refutations

### Finding 1: try_encap Unconfirmed-Gate (Refuted with Code & Kernel Evidence)
* **Status**: **REFUTED** (Corrected to ms-scale transient drop window).
* **Walkthrough**: 
  - On xpf, a handshake response (msg 2) installs the new session in `peer.current` as unconfirmed ([engine.rs:720](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/engine.rs#L720)).
  - Per the `wireguard-linux` kernel implementation in `receive.c`, when the initiator processes a valid `MESSAGE_HANDSHAKE_RESPONSE`, it calls `wg_timers_handshake_complete(peer)`. 
  - The kernel's timers/send logic mandates that `wg_timers_handshake_complete` either sends any queued staged packets or immediately transmits an empty authenticated keepalive packet to confirm the session.
  - Consequently, the window during which xpf holds an unconfirmed responder session is bounded by the round-trip time (ms-scale) before the kernel’s first encrypted packet arrives and confirms the session. The risk of permanent deadlock is absent.

### Finding 2: non-first fragment steering (Refuted with Code & Math)
* **Status**: **REFUTED** (Expected success via the local-destination fallback).
* **Walkthrough**:
  - In [lib.rs:567-579](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L567-L579), the XDP shim provides a general local-destination fallback. If a packet misses the session table but matches `is_local_destination(&parsed)`, it returns `Ok(cpumap_or_pass(ctrl))` to steer it to the kernel.
  - For non-first fragments of a UDP packet, the IP protocol remains `PROTO_UDP`. The shim’s `parse_ipv4` unconditionally calls `parse_l4` ([lib.rs:1117](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1117)), which attempts to read the first 8 bytes of the fragment's payload as a fake UDP header.
  - *Mathematical certainty of length:* Since WireGuard payloads (ciphertext + authentication tags) are always padded to a multiple of 16 bytes, the outer IP payload is always `8 + 16 * k` bytes. The path MTU (e.g. 1500) forces the first fragment payload to be a multiple of 8 (1480). Thus, the second fragment payload `(8 + 16 * k) - 1480` is mathematically guaranteed to be a multiple of 8. Because it is non-empty, the second fragment must be $\ge 8$ bytes.
  - This ensures `read_bytes` in `parse_l4` ([lib.rs:1411](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1411)) never returns `None` (which would trigger `XDP_DROP`). Instead, it parses successfully with garbage ports, misses the session table, matches `is_local_destination`, and is correctly delivered to the kernel for IP reassembly.

---

## 2. Review of the Full v2 Plan

### P4a/P4b Rekey Dynamics vs. Kernel Timers
* **Status**: **CORRECT**
* **Verification**: In `wireguard-linux`, both `keep_key_fresh` sites gate on `keypair->i_am_the_initiator`. The responder never time-rekeys. 
  - **P4a (Expiry-driven)**: Since xpf lacks timers, it will continue using the expired key. However, the kernel peer (acting as responder of the first session) will invalidate the keypair at `REJECT_AFTER_TIME` (180 s). Because the harness maintains continuous 1 s bidirectional pings, the kernel's next send will find no valid key, stage the packet, and initiate a handshake. A short $\le 10\text{ s}$ traffic gap is expected and handled.
  - **P4b (Seamless rekey)**: On a kernel-initiated session, the kernel (initiator) will time-rekey seamlessly at 120 s.

### P3 Session-Tearing Rebuild
* **Status**: **CORRECT**
* **Verification**: Removing `endpoint` alters the identity tuple checked in `wg_identity_unchanged` ([wg.rs:85-94](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/forwarding_build/wg.rs#L85-L94)), causing the engine to be rebuilt and the control thread restarted. Asserting session loss followed by a peer-initiated handshake is the correct behavior.

### Path A Choice and Secondary Suppression
* **Status**: **CORRECT & SECURE**
* **Verification**: Group-scoping the `wg0` stanza under `groups node0` ensures only `fw0` compiles it. This completely prevents `fw1` from starting the control thread, binding port 51820, or sending handshakes. This resolves the TAI64N-poisoning class of operational hazards. Post-commit assertions on `fw1` check for the absence of `wg0` netdev, port binding, and thread execution to guarantee safety.

---

## 3. Recommended Revisions / Observations for Implementer

1. **P6 Monotonicity Expectation**:
   - In P6, the negative control is expected to succeed (i.e. not be rejected by the peer) if `fw0`'s wall clock continues to flow forward monotonically. The TAI64N replay protection only triggers a rejection if the clock regresses or if the high-water mark was poisoned by a clock running ahead on `fw1` (which is now prevented by `node0` scoping). The test output should document this distinction.
2. **Telemetry follow-up discipline**:
   - Ensure the follow-up issue for S6 includes exposing the unconfirmed-drop reasons to `RecentExceptions` so that future operators do not have to perform blind network-level debugging of the transient drop window.

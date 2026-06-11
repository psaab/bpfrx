I will run a command to locate the files in the workspace and understand the repository layout.
I will search the parent directory or common project locations to locate the source code files.
I will check the status of the find command to see if it has finished executing.
I will run a command to list all git worktrees in `/home/ps/git/bpfrx` to find the correct worktree path.
I will run a command to verify if `docs/research/1736-wg-interop/plan.md` exists in that worktree and display its location.
I will read the plan file in full to understand the planned implementation.
I will view the contents of the `wg_control.rs` file to analyze the control thread implementation.
I will view the `peer.rs` file to check the session/rekey timers and logic.
I will search for key functions and session management logic in `engine.rs` to locate relevant portions of the code.
I will view the peer checking and handshake requesting methods in `engine.rs` to verify their logic.
I will view the beginning of `engine.rs` to see the constants and imports.
I will view `try_encap` and `try_decap` in `engine.rs` to inspect the encryption/decryption paths and AllowedIPs validation.
I will search for `wg_steer` or `is_local` inside `userspace-xdp/src/lib.rs` to locate the shim redirect logic.
I will view the `wg_steer_to_kernel` function in `userspace-xdp/src/lib.rs` to examine how the shim routes packets to the kernel.
I will view the rest of the `is_local_destination` function in `userspace-xdp/src/lib.rs`.
I will view where `wg_steer_to_kernel` is called in `userspace-xdp/src/lib.rs` to analyze the exact packet processing flow in the shim.
I will search for `applyWireguard` or other WireGuard references in `pkg/routing/tunnel.go` to find where the virtual network interface configuration is handled.
I will view the `applyWireguardTunLocked` function in `pkg/routing/tunnel.go` to understand how Go handles TUN creations, MTU allocations, and interface management.
I will view the MTU calculation function and address reconciliation details in `pkg/routing/tunnel.go`.
I will search for `wgTunMTU` to find the exact MTU calculation function.
I will view the `wgTunMTUForEndpoint` function in `pkg/routing/tunnel.go`.
I will search for `wgOverhead` and `wgPadWorst` to check the exact overhead constants used in Go.
I will view the constant definitions in `pkg/routing/tunnel.go`.
I will search for `consume_initiation_create_response` in `engine.rs` to see how xpf installs sessions when acting as a responder.
I will search for `consume_init` in `engine.rs` to locate the handshake consumption code.
I will list the files in the `userspace-dp/src/afxdp/wg/` directory to see the other files in the WireGuard implementation.
I will search for `consume_initiation_create_response` across the WireGuard module files.
I will view the `consume_initiation_create_response` implementation in `handshake_session.rs` to analyze what happens when xpf consumes a handshake initiation and responds.
I will view the rest of `consume_initiation_create_response` in `handshake_session.rs`.
I will view the `install_session` and `install_session_locked` methods in `engine.rs` to understand how new sessions are installed into the engine's active/previous maps and demux index.
I will search for `frag` or `fragment` in `userspace-xdp/src/lib.rs` to see how IP fragmentation is handled.
I will search for `parse_ipv4` in `userspace-xdp/src/lib.rs` to find where IPv4 header fields (specifically fragmentation flags) are parsed.
I will view the `parse_ipv4` function in `userspace-xdp/src/lib.rs`.
I will search for `fn parse_l4` in `userspace-xdp/src/lib.rs` to see how it extracts L4 information.
I will view the `parse_l4` function in `userspace-xdp/src/lib.rs` to analyze its behavior on UDP packets.
I will view the `ParsedPacket` struct or struct definitions around line 255 to see how `frag_off` is defined.
I will search for `fn read_bytes` to see how it accesses packet data safely.
I will view `parse_ipv6` to see if IPv6 fragmentation headers are parsed or handled.
I will search for `parse_ipv4` call site in `userspace-xdp/src/lib.rs`.
I will view the packet parsing and dispatch logic in `userspace-xdp/src/lib.rs` around line 374.
I will search for `drop_degraded_transit` in `userspace-xdp/src/lib.rs` to see what happens when parsing fails.
I will view `drop_degraded_transit` implementation in `userspace-xdp/src/lib.rs`.
I will write the hostile adversarial review of the WireGuard interop plan, detailing the structural failures and deadlocks uncovered in the codebase. I will save this as an artifact.
I have performed a hostile review of the live kernel-WireGuard interop plan, verifying it against the codebase. 

### Verdict: **PLAN-KILL**

The S2a engine is structurally not ready for live interop validation. Building a live test harness at this stage is premature, as it will fail on multiple blocking protocol bugs and SPEC violations.

I have documented the full findings, code evidence, and an action plan to unblock in the artifact:
* [adversarial_review.md](file:///home/ps/.gemini/antigravity-cli/brain/171740f7-7821-4617-84e8-440dfc8f715a/adversarial_review.md)

### Key Blockers Identified:
1. **Rekey Egress Deadlock**: [try_encap](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/engine.rs#L694) unconditionally rejects egress traffic if the current session is unconfirmed, and the engine lacks a fallback to the confirmed previous session (stored in [peer.previous](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/peer.rs#L68)). This causes a permanent protocol deadlock under one-way egress traffic.
2. **Outer Fragment Hijacking**: The XDP shim ([parse_ipv4](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1095) / [parse_ipv6](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1145)) ignores IP fragment offsets and parses raw payload bytes of non-first fragments as UDP headers. This prevents non-first fragments from matching [wg_steer_to_kernel](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs#L1236), causing a 100% outer packet reassembly failure.
3. **HA Node Interference**: The socket bound in [bind_wg_socket](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L288) listens on `0.0.0.0`, allowing the standby node `fw1` to actively send initiations that reach the peer. This causes endpoint flapping on the peer and TAI64N high-water mark race conditions that can block the active `fw0` primary.
I have completed the adversarial review of the WireGuard interop plan in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/docs/research/1736-wg-interop/plan.md) and saved the findings to the artifact [adversarial_review.md](file:///home/ps/.gemini/antigravity-cli/brain/171740f7-7821-4617-84e8-440dfc8f715a/adversarial_review.md).

### Summary of Completed Work:
- **Verified Codebases**: Checked the control thread [wg_control.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/coordinator/wg_control.rs), engine [engine.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/engine.rs), peer state [peer.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/peer.rs), XDP shim [lib.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-xdp/src/lib.rs), and TUN config [tunnel.go](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/pkg/routing/tunnel.go).
- **Proved Rekey Deadlock**: Demonstrated that [try_encap](file:///home/ps/git/bpfrx/.claude/worktrees/1736-research/userspace-dp/src/afxdp/wg/engine.rs#L694) will drop all outbound packets while the newly rotated session is unconfirmed, deadlocking one-way egress traffic.
- **Proved Fragment Drops**: Demonstrated that the XDP parser parses fake UDP headers from non-first fragments, causing them to fail steering to the kernel socket and resulting in a 100% outer reassembly failure rate.
- **Identified HA Node Flapping**: Proved that `fw1` binds the listen port on wildcard addresses and triggers endpoint learning/TAI64N high-water mark conflicts on the peer.
- **Verdict**: **PLAN-KILL** issued due to these fundamental engine blocker bugs.

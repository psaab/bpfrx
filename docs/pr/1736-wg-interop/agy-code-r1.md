# PR #1868 Adversarial Code Review Report
**Target Branch**: `engineer/1736-wg-interop`  
**Verdict**: **NEEDS-CHANGES**

---

## 1. Go Routing-Side Exemption

### Exemption Scope & sourceless-GRE Screen
In [pkg/daemon/daemon_run.go](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/pkg/daemon/daemon_run.go#L90-L108), the condition inside [collectAppliedTunnels](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/pkg/daemon/daemon_run.go#L83) was modified:

```go
if ifc.Tunnel != nil && (ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard") {
```

- **Analysis**: This exemption is strictly gated by `ifc.Tunnel.Mode == "wireguard"`. For GRE/IPIP or other tunnel modes, the first part of the OR expression (`ifc.Tunnel.Source != ""`) must still evaluate to `true` for the interface to be collected.
- **Exemption Weakening**: The exemption **does not** weaken the sourceless-GRE screen. Any configured GRE stanza with no source (`Source == ""`) will fail both `ifc.Tunnel.Source != ""` and `ifc.Tunnel.Mode == "wireguard"`, and will correctly be dropped/screened as before.
- **Regression Test Coverage**: This behavior is correctly pinned in [pkg/daemon/tunnel_anchor_test.go](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/pkg/daemon/tunnel_anchor_test.go#L75-L109) by `TestCollectAppliedTunnelsKeepsWireguardWithoutSource`, which asserts that a sourceless GRE stanza is still screened out.

---

## 2. Rust Datapath (wg_control.rs) Review

### Endpoint Learning & Sending Composition
- **Inbound Learning**: When an inbound packet arrives on the dual-stack socket, the kernel reports its source address. For IPv4 peers, this is reported as an IPv6-mapped IPv4 address (`::ffff:a.b.c.d`).
- **Canonicalization**: [canonicalize_endpoint](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs#L353-L364) parses this, checks if it is v4-mapped, and extracts the canonical `SocketAddr::V4`.
- **Egress Mapping**: When sending back to the peer, [wg_send_to](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs#L365-L393) maps the canonical `SocketAddr::V4` back to its IPv6-mapped form *only* if `socket_is_v6` is `true`. On a fallback v4 socket (`socket_is_v6 = false`), it leaves the `SocketAddr::V4` untouched and transmits it natively.
- **Composition**: The logic correctly unmaps on RX and re-maps on TX for the v6 socket. It avoids passing raw `AF_INET` targets directly to the `AF_INET6` socket's `send_to`, which previously returned `EINVAL` on Linux.

### MTU Guard Logical Family
- In [encap_and_send](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs#L515-L553), `outer_v6` is computed using `endpoint.is_ipv6()`.
- Since `endpoint` is `effective_endpoint`, which was unmapped to canonical v4, `endpoint.is_ipv6()` returns `false` for IPv4 peers.
- This ensures [wg_encapped_size](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs#L61) charges the 20-byte IPv4 outer IP overhead rather than the 40-byte IPv6 overhead, preventing false drops of inner packets sized 1409–1425 bytes.

### Inbound Dispatch Response (from)
- [dispatch_inbound](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs#L439-L510) uses the raw `from` address returned by `recv_from`.
- On a v6 dual-stack socket:
  - For v4-mapped peers, `from` is `SocketAddr::V6` containing the mapped address. It hits the `other` branch in `wg_send_to`, sending back to the mapped address.
  - For native v6 peers, `from` is `SocketAddr::V6` containing a native v6 address. It hits `other`, sending back natively. Native v6 is unaffected.
- On a fallback v4 socket:
  - `from` is `SocketAddr::V4`. It hits `other` (since `socket_is_v6` is `false`), sending natively.
- **Composition Verdict**: The bidirectional mapping logic is robust and correct.

### Plumbing & Hot-Path Cost
- `socket_is_v6` is correctly plumbed through [drive_initiation](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs#L394-L438), `dispatch_inbound`, and `encap_and_send`.
- The loops inside [wg_control_loop](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/coordinator/wg_control.rs#L80) invoke the send helpers with the correct parameters.
- **Performance**: The control socket and TUN read/write loop run in a dedicated supervised background thread (`xpf-wg-control-<name>`), meaning there is zero overhead on the packet-forwarding hot-path (AF_XDP workers).

---

## 3. Test Harness Correctness & Resilience Findings

While the harness in [test/incus/wg-interop.sh](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/test/incus/wg-interop.sh) is highly robust and recovers from several daemon and cluster failure states, there are two high-confidence issues that must be addressed:

### Finding 1: Lack of `set -e` in VM Shell Execution
- **File & Lines**: [test/incus/wg-interop.sh:284-295](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/test/incus/wg-interop.sh#L284-L295) (inside `peer_wg_setup`) and other multi-command `ish` calls.
- **Description**: `peer_wg_setup` sends a multi-line string to `ish` (which executes `sh -c` inside the container/VM):
  ```bash
  ish "${PEER}" "ip link del ${WG_KERNEL_IFACE} 2>/dev/null || true
      ip link add ${WG_KERNEL_IFACE} type wireguard
      wg set ${WG_KERNEL_IFACE} private-key /tmp/wgkeys/peer.priv ...
      ..."
  ```
  Since `sh` inside the VM is not run with `set -e`, if `wg set` fails (e.g. because key generation or file copy failed), the shell does not abort. It proceeds to run the remaining commands (`ip addr add`, `ip link set ... up`). The function may return `0` (success) if the final command succeeds, hiding critical configuration failures.
- **Remediation**: Explicitly prepend `set -euo pipefail` inside the multi-line `ish` script snippets, e.g.:
  ```bash
  ish "${PEER}" "set -euo pipefail
      ip link del ${WG_KERNEL_IFACE} 2>/dev/null || true
      ..."
  ```

### Finding 2: Permissive Teardown Error Handling
- **File & Lines**: [test/incus/wg-interop.sh:613-640](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/test/incus/wg-interop.sh#L613-L640) (inside `teardown`).
- **Description**: During `teardown`, the script attempts to delete the wireguard configuration stanza:
  ```bash
  fw0_cli > "${EVID}/teardown-commit.txt" 2>&1 <<EOF
  configure
  delete groups node0 interfaces wg0
  commit
  exit
  quit
  EOF
  ```
  The check for this commit is:
  ```bash
  grep -qE "commit complete|path not found" "${EVID}/teardown-commit.txt" \
      || warn "teardown commit output unexpected: $(cat "${EVID}/teardown-commit.txt")"
  ```
  If this commit fails (for example, if the current node is not primary for RG0, which was observed during the live runs in `/tmp/wg-teardown/summary.txt` returning `node is not primary for RG0`), it only prints a `warn` and proceeds to exit successfully, reporting `PASS: teardown (both nodes clean)`.
  This allows a failed teardown to go unnoticed, leaving a dirty, active configuration on the nodes that poisons subsequent runs.
- **Remediation**: If the teardown commit fails, the function must call `fail` or exit with a non-zero code to ensure the operator is notified of a failed teardown, rather than reporting a false `PASS`.

---

## 4. Documentation & runbook.md Accuracy
- **Runbook**: [docs/wg-interop-runbook.md](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/docs/wg-interop-runbook.md) is highly accurate.
- It correctly describes the TAI64N flush procedure, node0 scoping, known S-step limitations (like lacking keepalive TX and xpf-initiated rekey), and the P5 fragmented-outer logic.
- The fragmentation explanation (using the Miss/local destination pass-to-kernel fallback) matches the Rust datapath implementation.

---

## 5. 'Part of #1736' vs 'Closes' Verdict

### Is 'Part of #1736' the right call?
**Yes.** This is the correct designation.

1. **Evidence Gap**: The checked-in evidence files in the PR only contain results for P1 ([p1-wire-capture.txt](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/docs/pr/1736-wg-interop/p1-wire-capture.txt)) and P4a ([p4a-handshakes.txt](file:///home/ps/git/bpfrx/.claude/worktrees/1736-engineer/docs/pr/1736-wg-interop/p4a-handshakes.txt)). There is no checked-in evidence for P2, P3, P4b, P5, P6, or P7.
2. **Infrastructure Failures**: The actual execution runs of the test harness on the shared loss cluster (recorded in `/tmp/wg-final/summary.txt` and `/tmp/wg-ev/summary.txt`) failed to complete a full run due to HA cluster issues (e.g. node0 not regaining primary status after recovery restarts). 
3. **Known Holes**: Major protocol timers and features (rekey initiation, keepalive TX, cookie consume, and PSK) are still stubbed out as out-of-scope for S2b and scheduled for S4–S7.
Because a clean run of the entire suite could not be completed and many engine features are intentionally deferred, marking this PR as `Part of #1736` (leaving the main issue open for subsequent S-steps) is the correct and honest path.

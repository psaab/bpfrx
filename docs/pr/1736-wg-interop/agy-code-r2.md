I will search for `wg-interop.sh` in the codebase to find its location and start investigating the changes.
I will list the current permission grants to see what directories I can access in this environment.
I will list the contents of `/home/ps/.gemini/antigravity-cli/worktrees` to see if our target working tree is located there.
I will list the contents of `/home/ps/.gemini/antigravity-cli/scratch` to locate the codebase.
I will run a command to find the root of the git repository or where the workspace files are located.
I will run a command to find any `.git` directories under `/home/ps` to locate the git repository for PR #1868.
I will run a command to find the file `wg-interop.sh` under `/home/ps/git` to verify which repository it belongs to.
I will check the git HEAD commit and status of the repository at `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer` to see if it matches `32f692e4b`.
I will ask for read permissions for the target worktree at `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer` to explore the code using the file tools.
I will run `git show` on the HEAD commit to inspect the changes made in this PR.
I will run a command to list the recent commits in the worktree to understand how the findings from round 1 were folded.
I will show the changes made in the commit `7a339321a` where AGY round-1 findings were addressed.
I will show the changes made in the commit `41d40a71f` where Codex round-1 findings were addressed.
I will run `git show --name-only 41d40a71f` to see all the files modified in the commit that folded Codex round-1 findings.
I will inspect the diff for `docs/wg-interop-runbook.md` in commit `41d40a71f` to verify runbook changes.
I will search for the definition of `wg_identity_unchanged` to see where it lives and verify how it behaves with the canonicalization changes.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/forwarding_build/wg.rs` around line 87 to inspect `wg_identity_unchanged`.
I will search for the definition of `struct TunnelEndpoint` to understand the type of `wg_endpoint`.
I will search for `struct TunnelEndpoint` in the workspace.
I will view the definition of `TunnelEndpoint` in `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/types/forwarding.rs` to see its fields.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/forwarding_build/tunnels.rs` to inspect the endpoint hydration and the parsing logic.
I will search for all occurrences of `wg_endpoint` in the codebase to make sure the endpoint isn't modified or set elsewhere without canonicalization.
I will view the tests in `userspace-dp/src/afxdp/forwarding_build/tests.rs` around line 1916 to see how `wg_endpoint` hydration is tested.
I will view the rest of the tests in `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/forwarding_build/tests.rs` to see if there are additional wireguard hydration tests.
I will search for `outer_family` or endpoint family logic in `userspace-dp/src/afxdp/frame/wg.rs` to see how transit outer-family selection works.
I will view the contents of `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/frame/wg.rs`.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` around line 350 to see the implementation of `wg_send_to` and `canonicalize_endpoint` there.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` from lines 451 to 530 to trace how inbound packets are processed and where learning happens.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` from lines 531 to 600 to see where endpoint learning occurs.
I will search for all calls of `canonicalize_endpoint` to see where it gets invoked in the coordinator code.
I will view the endpoint update block in `userspace-dp/src/afxdp/coordinator/wg_control.rs` around line 182.
I will search for `ish ` (remote shell runner calls) in the test script `test/incus/wg-interop.sh` to see where remote commands are run and verify their exit conditions.
I will view lines 125-150 and 260-310 in `test/incus/wg-interop.sh` to check the changes in `gen_keys`, `provision`, and `peer_wg_setup` and make sure they don't break on any intermediate steps.
I will view lines 260-315 of `test/incus/wg-interop.sh` to check `provision` and `peer_wg_setup`.
I will view the beginning of `test/incus/wg-interop.sh` to check the shell settings.
I will search for `set -eu` in `test/incus/wg-interop.sh` to confirm exactly where it is used.
I will view the `teardown` function in `test/incus/wg-interop.sh` from line 620 to 655 to verify how it handles RG0 mastership waiting and non-clean commit failures.
I will search for `wait_node0_primary` to see its definition and verify that it acts as expected.
I will view the definition of `wait_node0_primary` in `test/incus/wg-interop.sh` to ensure it works correctly and has proper timeouts.
I will search for `fw0_cli` to see its definition.
I will search for all occurrences of the `TAINTS` variable in `test/incus/wg-interop.sh` to confirm where it is incremented and processed.
I will view the end of `test/incus/wg-interop.sh` to confirm the exit logic when taints are present.
I will view the rest of the unit tests in `userspace-dp/src/afxdp/coordinator/wg_control.rs` from line 601 to 642 to see if there are any other test verification items.
I will search for `send_to` calls in `userspace-dp/src/afxdp/coordinator/wg_control.rs` to ensure there are no un-mapped raw `send_to` calls in the production code path.
I will run a command to list all files modified in the PR branch to ensure we have a complete list of what we're reviewing.
I will check the diff for the environment file `test/incus/wg-interop.env`.
I will view the git diff of `test/incus/wg-interop.sh` to inspect all harness changes.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1736-engineer/userspace-dp/src/afxdp/wg/mod.rs` to make sure it is completely clean.
I will search for the definition of `xpf_wg_commit` to check its error handling and ensure it fails on bad commits.
I will view the definition of `xpf_wg_commit` in `test/incus/wg-interop.sh` to verify its error handling.
# AGY Adversarial Review (Round 2 Verification)

**Verdict: MERGE-READY**

Following a read-only code review of the working tree at HEAD `32f692e4b`, all Round 1 findings from AGY and Codex have been correctly and robustly addressed. Below is the verification breakdown:

---

### 1. AGY Finding 1: Strict Remote Snippets (`set -eu`)
- **Verified Files**:
  - `test/incus/wg-interop.sh:134-138` (inside `gen_keys`)
  - `test/incus/wg-interop.sh:272-280` (inside `provision`)
  - `test/incus/wg-interop.sh:298-305` (inside `peer_wg_setup`)
- **Analysis**: Multi-command mutating remote snippets executed via `ish` now run under `set -eu` so that intermediate failures (e.g. `wg set` failures or directory creation errors) correctly abort the remote shell instead of being masked. 
  - **No Fatal Intermediate Failures**: The shell logic is safe. For example, in `gen_keys` (`[ -s file ] || wg genkey`), the `||` operator prevents shell exit under `set -e` if the file is missing/empty, letting the right-hand command run. In `peer_wg_setup`, `ip link del ... || true` keeps the snippet tolerant of the interface's non-existence.
  - **Tolerant Cleanups**: Probe and cleanup command snippets (e.g., `teardown` checking `ip link show wg0`) do not use `set -eu` and remain appropriately tolerant.

---

### 2. AGY Finding 2: Fail-Closed Teardown & RG0 Mastership
- **Verified Files**:
  - `test/incus/wg-interop.sh:632-641` (inside `teardown`)
- **Analysis**:
  - Before committing, `teardown` calls `wait_node0_primary 36` (line 632) to wait for node0 to hold RG0 mastership, preventing config commit refusals.
  - The commit output check is updated at line 640 to:
    ```bash
    grep -qE "commit complete|path not found" "${EVID}/teardown-commit.txt" \
        || fail "teardown commit failed: $(tail -3 "${EVID}/teardown-commit.txt")"
    ```
    Any failure to commit (including a "node is not primary" error) triggers `fail`, preventing dirty configuration leakages from being falsely reported as `PASS`.

---

### 3. Codex Finding 1: Canonicalization & Identity Stability
- **Verified Files**:
  - `userspace-dp/src/afxdp/wg/mod.rs:83-90` (definition of `canonicalize_endpoint`)
  - `userspace-dp/src/afxdp/forwarding_build/tunnels.rs:78-87` (hydration)
  - `userspace-dp/src/afxdp/forwarding_build/wg.rs:87-94` (identity comparison)
  - `userspace-dp/src/afxdp/frame/wg.rs:54` and `wg.rs:70` (transit outer-family selection)
- **Analysis**:
  - `canonicalize_endpoint` is correctly extracted to `afxdp::wg` and applied at hydration in `tunnels.rs` (lines 78-87) to unmap IPv4-mapped IPv6 literals (`::ffff:a.b.c.d`).
  - **Identity Stability**: In `forwarding_build/wg.rs:87-94`, `wg_identity_unchanged` compares `prev.wg_endpoint == next.wg_endpoint`. Because both are parsed and canonicalized at hydration, comparing configured mapped-literals stays stable across reloads.
  - **Transit Benefits**: In `frame/wg.rs:70`, the transit path evaluates `peer_endpoint.is_ipv6()`. Without hydration canonicalization, a configured mapped-literal would incorrectly evaluate to `true` (building an IPv6 outer header structure for an IPv4 peer). Now, it evaluates to `false` and selects the correct v4 OUTER path.

---

### 4. Codex Finding 2: Taint Accounting
- **Verified Files**:
  - `test/incus/wg-interop.sh:56` (initialization)
  - `test/incus/wg-interop.sh:376` and `wg-interop.sh:400` (increments)
  - `test/incus/wg-interop.sh:685-688` (exit check)
- **Analysis**: Any fallback to recovery restarts (leaked control thread or wedged apply) increments `TAINTS`. At the end of the `all` runner, the script issues a warning and exits with code `2` if `TAINTS` > 0. This prevents recovered runs from falsely passing merge verification.

---

### 5. Codex Finding 3: iperf Unit Scaling
- **Verified Files**:
  - `test/incus/wg-interop.sh:109-114` (inside `iperf_mbps`)
- **Analysis**: The scaled arithmetic in the awk script:
  ```awk
  if (u == "Gbits/sec") v *= 1000
  else if (u == "Kbits/sec") v /= 1000
  else if (u == "bits/sec") v /= 1000000
  ```
  properly normalizes all units to Mbps. A stall generating `60 bits/sec` will correctly compute to `0 Mbps`, preventing low-throughput failures from beating the performance floor check.

---

### 6. Codex Finding 4: Socket Unit Tests
- **Verified Files**:
  - `userspace-dp/src/afxdp/coordinator/wg_control.rs:594-599` (skips)
  - `userspace-dp/src/afxdp/coordinator/wg_control.rs:618-628` (native v4 test)
- **Analysis**:
  - `wg_send_to_maps_v4_target_on_v6_socket` now skips safely (`return;`) when dual-stack IPv6 socket binding is unsupported on the test host.
  - A new native IPv4 loopback round-trip test (`wg_send_to_native_v4_socket_roundtrip`) runs unconditionally to verify the unmapped fallback socket path.

---

### Minor Code Observation
In `test/incus/wg-interop.sh` line 108:
```awk
for (i = 1; i <= NF; i++) if ($(i+1) ~ /bits\/sec/) { v = $i; u = $(i+1) }
```
When `i == NF`, the check accesses `$(NF+1)`. While both POSIX and GNU `awk` permit this and return an empty string (failing the regex match as expected without an error), checking `i < NF` is technically cleaner. Since this is non-breaking, it does not block the merge.

**Conclusion**: The implementation direction is sound, the verification folds are stable, and the changes are ready to land.

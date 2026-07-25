### Design Review Verdict: **PLAN YES**

#### Verification of v9.9.4 Additions

1. **Policy-Invalidation Config-Epoch Cut**:
   - **Monotonic Commit Counters**: Usable monotonic counters exist today in `pkg/configstore` (`candidateGen` and `confirmGen` `uint64` tokens in [store.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/configstore/store.go#L88)), which advance monotonically on config commits and can be read by the helper.
   - **`SessionEntry` Layout Consistency**: `SessionEntry` ([mod.rs](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L344)) is an in-memory Rust struct in `SessionTable` that already carries `install_epoch: u64` ([mod.rs#L348](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs#L348)). Because helper-authoritative selection operates on helper-owned Rust session aliases rather than BPF map ABI values (`bpf_session_value.go`), stamping the admission epoch on `SessionEntry` adds no BPF layout constraints and is fully consistent with current memory layout rules.

2. **Cluster-Bulk Commit-Time Candidate Re-Validation**:
   - **Mid-Bulk Flip Window Closure**: Re-validating candidate status (`peer-owned AND locally absent`) under the canonical alias lock within the single per-operation mutation span (`lock -> re-read source alias -> delete -> unlock`) protects against stale deletions.
   - **Residual Analysis**: Any concurrent local publication (E2) must acquire the same canonical alias lock. No local primary publication can intervene between candidate re-validation and deletion within that lock-guarded span. The residual is zero inside the lock transaction span, completely closing the mid-bulk secondary→primary flip window.

3. **Claim-Permit Claimed→Abandoned Transition & Recheck**:
   - **Ordering Safety**: If a permit expires immediately after the recheck but before the install commit, `Claimed → Abandoned` releases the keeper escrow.
   - **Clean Failure via Verify-and-Retain**: The install commit's `verify-and-retain` inspects allocation state under the `PortAllocator` lock. If the allocation was released or reallocated, `verify-and-retain` detects the handle mismatch/absence and aborts the install cleanly without corrupting port holds or reusing stale state.

VERDICT: PLAN-READY

FINDINGS:

1. **MINOR**: *Plan should explicitly require pinning `desiredForwardingArmedLocked()` disarm state in the Go ordering test suite to prevent future disarm regression.*
   - **Claim**: The plan's test plan (§9.1) focuses primarily on HA-publish-before-arm ordering. However, mechanism M2 (`desiredForwardingArmedLocked() == false` on zero-RG cluster nodes) is an essential independent closing mechanism.
   - **Evidence**: [manager_ha.go:363-389](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha.go#L363-L389) evaluates `desiredForwardingArmedLocked()`. The test plan should explicitly assert that `desiredForwardingArmedLocked()` returns `false` both before apply and after a zero-RG cluster apply, as pinned in [manager_ha_test.go:800-802](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha_test.go#L800-L802).

2. **NIT**: *Verified line anchors across Go control plane and Rust dataplane.*
   - **Claim**: Anchors cited in the plan match the repository state at commit `ad9591177`.
   - **Evidence**: Spot-checked 12 key anchors in source:
     - `loader_userspace_shim.go:670` (`arrayMapSpec("rg_active", ...)`): [loader_userspace_shim.go:670](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/loader_userspace_shim.go#L670)
     - `types.go:1005` (`MaxRedundancyGroups = 16`): [types.go:1005](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/types.go#L1005)
     - `manager_ha.go:37` (`syncHAStateLocked` `len==0` early return): [manager_ha.go:37](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha.go#L37)
     - `manager_ha.go:257` (`refreshHAStateFromMapsLocked`): [manager_ha.go:257](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha.go#L257)
     - `manager_ha.go:363` (`desiredForwardingArmedLocked`): [manager_ha.go:363](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha.go#L363)
     - `manager_compile.go:383-388` (`if m.clusterHA` HA refresh & sync): [manager_compile.go:383-388](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_compile.go#L383-L388)
     - `process_status.go:211-212` (`m.refreshHAStateFromMapsLocked()` in status poll): [process_status.go:211-212](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/process_status.go#L211-L212)
     - `forwarding/ha.rs:80` (`LocalDelivery && ha_state.is_empty()`): [ha.rs:80](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/ha.rs#L80)
     - `forwarding/ha.rs:83-100` (`owner_rg_for_resolution` & `owner_rg_id <= 0`): [ha.rs:83-100](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/ha.rs#L83-L100)
     - `forwarding/nat.rs:137-160` (`interface_nat_local_resolution`): [nat.rs:137-160](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/nat.rs#L137-L160)
     - `manager_ha_test.go:544` (`TestMergeHAStateFromMapsFabricatesGroupsFromArrayMap`): [manager_ha_test.go:544](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha_test.go#L544)
     - `manager_ha_test.go:786` (`TestDesiredForwardingArmedRequiresDataRGOrActiveLocalOnlyGroup`): [manager_ha_test.go:786](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha_test.go#L786)

---

### ANSWERS TO ATTACK SURFACES 1-7

**1. Reachable Armed + Empty State Path Check**
CONFIRMED-CLOSED. Direct code tracing across all sub-apply paths ([manager_overlay.go:236](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_overlay.go#L236), [manager_worker_arm_5134.go:76](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_worker_arm_5134.go#L76)), helper startup/restart ([manager_compile.go:255-266](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_compile.go#L255-L266)), status poll deferred snapshots ([process_status.go:211-243](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/process_status.go#L211-L243)), process respawn ([process.go:18](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/process.go#L18)), and `UpdateRGActive` interleavings confirms that every clustered apply/poll path executes `refreshHAStateFromMapsLocked()` before any status check or arming operation. No execution path leaves a clustered node's helper armed with an empty `ha_state`.

**2. Robustness of Mechanism M1 (Phantom Fabrication)**
CONFIRMED-CLOSED. `refreshHAStateFromMapsLocked()` ([manager_ha.go:257](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha.go#L257)) returns an explicit `error` if BPF map iteration fails, which immediately aborts `ApplyConfig` at [manager_compile.go:384-386](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_compile.go#L384-L386) and fails closed. `rg_active` is explicitly configured as an eBPF `ARRAY` of size 16 ([loader_userspace_shim.go:670](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/loader_userspace_shim.go#L670), [types.go:1005](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/types.go#L1005)), guaranteeing all 16 slots are returned on iteration. Furthermore, `seedHAGroupInventoryLocked` runs under `m.mu` during `ApplyConfig` and is immediately followed by `refreshHAStateFromMapsLocked`, repopulating phantom keys 0..15 before `syncHAStateLocked` publishes the state.

**3. Arming Authority and Operator Override Check (Mechanism M2)**
CONFIRMED-CLOSED. `desiredForwardingArmedLocked()` ([manager_ha.go:363](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha.go#L363)) is the sole arming authority evaluated by `syncDesiredForwardingStateLocked` ([manager_ha.go:605](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/manager_ha.go#L605)). Operator gRPC/CLI requests pass through `SetForwardingArmed` / `SyncDesiredForwardingState`, which re-evaluate `desiredForwardingArmedLocked()`. Even if an operator could force-arm a zero-RG node, M1 guarantees `ha_state` contains `{0..15 inactive phantoms}`, resolving any RG-owned address to `HAInactive` (drop).

**4. RG0-Primary Node Publish Window Check (Mechanism M3)**
CONFIRMED-CLOSED. On an RG0-primary node (armed, `ha_state={0:active, 1..15: inactive phantoms}`), `ha_state.is_empty()` is false. During the publish window of a first-data-RG commit, any packet targeting an RG1-owned address evaluates `owner_rg_for_resolution(...) = 1`. Line 101 of [forwarding/ha.rs](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/ha.rs#L101) fetches key 1 from `ha_state`, sees `active = false`, and returns `HAInactive` (drop). `cached_flow_decision_valid` invokes `enforce_ha_resolution_snapshot`, which returns `false` (invalidating the cache entry) whenever the disposition transitions to `HAInactive`.

**5. Dataplane State Decoupling and Atomic Read Pairing**
CONFIRMED-CLOSED. Inspection of `server/handlers/snapshot.rs` and `afxdp/coordinator` confirms `apply_snapshot` updates `ForwardingState` via `ArcSwap` and never clears `rg_runtime` or `ha_state`. If an AF_XDP worker thread evaluates a packet using a NEW `ForwardingState` (containing a newly bound RG1 interface) alongside an OLD `ha_state` (containing phantom RG1-inactive), `owner_rg_for_resolution` returns 1, `ha_state.get(&1)` yields the inactive entry, and the packet is dropped as `HAInactive`.

**6. Independent Resolution Trace & Non-RG Local Delivery Check**
CONFIRMED-CLOSED. `enforce_ha_resolution_snapshot` at [forwarding/ha.rs:88-99](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/ha.rs#L88-L99) returns `resolution` unchanged for `owner_rg_id <= 0` because non-RG interfaces (management, loopback, non-clustered interfaces) are node-local and not subject to HA failover. For an RG-owned interface (the exact scenario framed by issue #6746), `owner_rg_for_resolution` returns `owner_rg_id > 0` (e.g., 1). Line 89 (`owner_rg_id <= 0`) evaluates false, and line 101 checks key 1 against `ha_state` (which M1 guarantees contains an inactive phantom), yielding `HAInactive`. The framed window does not exist under any reading.

**7. Assessment of Plan Recommendation (Path A vs Path B)**
CONFIRMED-CLOSED. Because all attack vectors confirm that the fail-open window is structurally closed by M1, M2, and M3 at commit `ad9591177`, Path A (closing issue #6746 as falsified, landing Go ordering assertions and Rust phantom unit tests, and filing the tri-state HA representation as follow-up hardening) is the correct engineering decision.

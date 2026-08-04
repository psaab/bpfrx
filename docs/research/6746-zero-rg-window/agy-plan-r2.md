VERDICT: PLAN-READY

FOLD VERIFICATION:
- MAJOR-1: PRESENT-AND-ACCURATE — Evidenced in §3.1 (lines 114-139) with `nat.rs:137-160`, `interfaces.rs:157`, `interfaces.rs:334`, and `ha.rs:86-94`. Verified against source.
- MINOR-1: PRESENT-AND-ACCURATE — Traced in §3.4 (lines 207-226) for `pendingXSKStartup` deferral (`manager_compile.go:272-314`, `process_status.go:185-189`, `211-212`, `240`). Verified against source.
- MINOR-2: PRESENT-AND-ACCURATE — Audited in §3.1 (lines 140-150) for empty `update_ha_state` call sites (`manager_compile.go:391`, `:296`, `manager_ha.go:145`). Verified against source.
- MINOR-3: PRESENT-AND-ACCURATE — Documented in §3.4 (lines 238-247) covering operator-arm CLI/gRPC entrypoints (`cli_request_chassis.go:151-158`, `server_diag_system_action.go:395-415`, `maps_sync.go:420-424`). Verified against source.
- NIT-1: PRESENT-AND-ACCURATE — Pinned in §9.1 (lines 417-428) with before/after disarm assertion, no-empty-publish assertion, and deferred-path variant. Verified against source.
- AGY r1 MINOR: PRESENT-AND-ACCURATE — Pinned in §9.1 (lines 417-428) asserting `desiredForwardingArmedLocked() == false` both before and after zero-RG apply. Verified against source.

NEW ATTACKS:
- (a) **Reth sub-unit egress-RG trace result**:
  Traced RETH VLAN sub-units (e.g. `reth1.50`) end-to-end across Go snapshot compilation and Rust egress/NAT map building:
  1. In Go [`interfaces.go:214-218, 302`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/pkg/dataplane/userspace/interfaces.go#L214-L218), each sub-unit `InterfaceSnapshot` resolves its RG from its own configuration or inherits its parent RETH's `RedundancyGroup` (e.g., `rg = 1`), emitting `RedundancyGroup: 1` on `reth1.50`.
  2. In Rust [`interfaces.rs:157`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding_build/interfaces.rs#L157), `interface_nat_v4` maps configured excluded IP addresses to the sub-unit's logical `ifindex`.
  3. In Rust [`interfaces.rs:326-338`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding_build/interfaces.rs#L326-L338), `populate_egress` inserts an `EgressInterface` row keyed by `iface.ifindex` (the sub-unit's logical `ifindex`) carrying `redundancy_group: 1`.
  4. At packet resolution in [`nat.rs:137-160`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/nat.rs#L137-L160) and [`ha.rs:8-41`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/ha.rs#L8-L41), `interface_nat_local_resolution` sets `egress_ifindex` to the sub-unit's `ifindex`, and `owner_rg_for_resolution` looks up that `ifindex` in `egress`, returning `owner_rg = 1`.
  5. [`enforce_ha_resolution_snapshot`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/forwarding/ha.rs#L83-L113) sees `owner_rg_id = 1 > 0`, checks `ha_state.get(&1)`, and resolves to `HAInactive` (drop) on standby nodes and zero-RG phantom nodes.
  *Result: No hole exists for RETH VLAN sub-units; the evidence chain holds.*

- (b) **Post-liveness operator-arm trace result**:
  Traced an operator executing `request chassis ... forwarding arm` (`cli_request_chassis.go:151-158`) AFTER XSK liveness is already proven (15s prewarm elapsed):
  1. Operator arming sets `m.forwardingArmed = true`, defeating M2 (`desiredForwardingArmedLocked`).
  2. On the next status tick, `ctrl.Enabled` transitions to `1`, allowing packet delivery to userspace workers.
  3. However, M1 (`refreshHAStateFromMapsLocked`) ran during the boot apply at t=0s (`manager_compile.go:384`), populating `m.haGroups` with 16 phantom inactive groups `{0..15}` and publishing them to Rust `rg_runtime`.
  4. Per the MINOR-2 empty-sender audit, no path on a clustered node ever empties `rg_runtime`.
  5. Therefore, at t > 15s, when `ctrl.Enabled` opens, `ha_state` is already populated with phantom inactive entries `{0..15}`. An RG1 interface-NAT `LocalDelivery` resolution hits `owner_rg = 1` -> phantom entry 1 inactive -> `HAInactive` (drop).
  *Result: M1 fully covers the post-liveness operator-arm scenario.*

- (c) **Additional probes**:
  1. Verified `refreshHAStateFromMapsLocked()` failure handling: an error in `manager_compile.go:384` fails the apply immediately, preventing snapshot publication or arming.
  2. Verified Rust `rg_runtime` state updates in [`afxdp/ha/state.rs:4-25`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6746-research-zero-rg-window/userspace-dp/src/afxdp/ha/state.rs#L4-L25): `update_ha_state` replaces the map atomically with supplied groups and has no side-channel map clearing.

FINDINGS:
None.

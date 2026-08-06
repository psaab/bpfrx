### Hostile Adversarial Plan Review (v6-r7)

---

### A. The Ifindex Axis (§7a)
- **Key Space Divergence Verified:** Confirmed at `userspace-dp/src/afxdp/forwarding/mod.rs:114` (`resolve_ingress_logical_ifindex` taking `(ingress_ifindex, ingress_vlan_id)`), `poll_descriptor/prerouting_scope.rs:32-59` (`meta.ingress_ifindex` is physical, sub-interfaces map only to parent's first unit), and `forwarding_build/interfaces.rs:56` (`ifindex_to_routing_instance` keyed by logical unit `iface.ifindex`).
- **Test Axis Claim Verified:** On untagged physical ports, `resolve_ingress_logical_ifindex` falls back to physical ifindex (`logical == physical`), so a fixture varying two physical ports on separate NICs evaluates correctly even under the broken naive lookup. Only a fixture varying VLAN units on one shared parent NIC forces `physical != logical` and binds the fix.
- **Coverage:** Tunnel logicals (`gre.rs:760`), local-origin TUN (`tunnel.rs:344-381`), and fabric ingress (`packet_fabric_ingress` exemption) are accounted for.

---

### B. The Version Path (§4.3b)
- **Claims (i) & (ii) Verified:** `MinCompatHAProtocolVersion` is exported at `cmd/xpfd/main.go:195`, parsed at `pkg/upgrade/imageversions.go:70`, and enforced as a floor in `GateMixedBaseSwap` (`imageversions.go:156`) and `xpf-deploy.py:2142`. `SessionSyncWireVersion` is exact-matched at `imageversions.go:170` and `xpf-deploy.py:2150`.
- **Claim (iii) Refuted (FATAL DEFECT):** The claim that pinning `SessionSyncWireVersion` while bumping `CurrentHAProtocolVersion` requires "no changes to `parseHAProtocolCompatible`" is false:
  1. `pkg/upgrade/cluster_cli.go:253` (`parseHAProtocolCompatible`) is invoked by `cl.HAProtocolCompatible()` in `pkg/upgrade/rolling.go:141`. `parseHAProtocolCompatible` enforces exact equality `local == peer` (`pkg/upgrade/cluster_cli.go:274`). If `CurrentHAProtocolVersion` moves to 2, `rolling.go` aborts the rolling upgrade stating the release is NOT rolling-upgradable (`rolling.go:145`).
  2. `pkg/cluster/peer_state.go:107` (`HAProtocolVersionMismatch`) is invoked by `userspaceTransferReadiness` in `pkg/daemon/daemon_ha_userspace_readiness.go:115`. It also enforces `local != peer` (`peer_state.go:115`), causing transfer readiness to report unready (`"ha protocol mismatch local=2 peer=1"`).
  3. Decoupling `SessionSyncWireVersion` is necessary but insufficient; `CurrentHAProtocolVersion` exact-equality checks in `parseHAProtocolCompatible` and `HAProtocolVersionMismatch` must still be updated to respect `MinCompatHAProtocolVersion`.

---

### C. The Provenance Redesign (§4.3c)
- **Race Elimination:** Per-entry provenance set at admission avoids mutable global state checks and eliminates the four races.
- **BulkEnd Flush Atomicity & Posture:**
  1. Iterate-and-delete flushing over Rust `SessionTable` is not an atomic single-instruction swap with respect to fast-path worker threads unless executed under a global table write-lock, allowing packets mid-flush to observe a partially-flushed table.
  2. If the peer never upgrades or the first v2 bulk sync fails mid-transfer before sending `BulkEnd` (`sync_conn_read.go:205`), `bulkEverCompleted` is never set and non-authoritative rows remain in the table indefinitely. For a security flaw (cross-tenant session hijack), an unbounded-if-bulk-fails window makes the fail-open posture unbounded in practice.

---

### D. Newly Wrong / Inconsistencies in v6-r7
- **Plan Inconsistency:** Line 837 still states *"plus the parseHAProtocolCompatible change (§4.3b)"* while lines 531, 985, and 1122 claim `parseHAProtocolCompatible` is not touched.

---

VERDICT: PLAN-NEEDS-REVISION

While §7a's ifindex derivation and §4.3c's per-entry provenance correctly eliminate the physical/logical mapping defect and global-state races, §4.3b's assertion that `parseHAProtocolCompatible` can remain untouched is false and breaks both rolling upgrades (`pkg/upgrade/rolling.go:141`) and transfer readiness (`pkg/daemon/daemon_ha_userspace_readiness.go:115`). Additionally, §4.3c's BulkEnd flush leaves non-authoritative rows in an unbounded fail-open state if the initial bulk fails to complete, and line 837 contradicts lines 531/985/1122 regarding `parseHAProtocolCompatible`.

1. **Fix §4.3b Rolling Upgrade Gates:** Update `parseHAProtocolCompatible` (`pkg/upgrade/cluster_cli.go:253`) and `HAProtocolVersionMismatch` (`pkg/cluster/peer_state.go:107`) to evaluate compatibility against the `MinCompatHAProtocolVersion` floor (`peer >= minCompat && peer <= current`) rather than exact equality (`local == peer`), ensuring rolling upgrades and transfer readiness succeed when `CurrentHAProtocolVersion` is bumped.
2. **Reconcile Plan Inconsistency:** Resolve the contradiction between line 837 and lines 531/985/1122 regarding changes to `parseHAProtocolCompatible`.
3. **Address §4.3c Flush Boundary & Atomicity:** Specify atomic locking/sharding semantics for the `BulkEnd` provenance flush in `SessionTable`, and define an explicit TTL or timeout bound for non-authoritative entries when the initial v2 bulk fails or the peer remains on v1.

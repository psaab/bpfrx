# Codex hostile impl-review #1959 r1

Session: 019ed6c6-55f6-7361-89ea-3da4636619ee
Verdict: NEEDS-MAJOR (2 HIGH, 0 CRITICAL) — both fixed.

## HIGH-1 — pkg/devicemap/devicemap.go: topology-change refusal bypassable by MAC-first key order
The PCI mismatch refusal fired only inside the PCI leg. A `mac-then-pci`
(MAC-first) entry reached the MAC leg first and could bind decisively there,
skipping the slot-swap check. The "PCI hit + perm-MAC mismatch => REFUSE"
invariant must hold regardless of key order.
FIX: order-INDEPENDENT pre-check in Resolve() — when an entry has BOTH pci and
mac (non-RETH) and a present NIC at that PCI has a mismatching perm-MAC, REFUSE
before the key loop. Test: TestResolve... (mac-then-pci slot swap).

## HIGH-2 — pkg/daemon/device_map.go: lockout check skips entries when the live NIC has not yet been renamed
deviceMapStrandsManagement located the protected NIC by current-name ==
protected-name, so on first boot (mgmt still enp5s0, not fxp0) it found no NIC
named fxp0, skipped the loop, and allowed another NIC to claim fxp0.
FIX: the function now takes lifelineCurrentName (resolved by the persisted
identity via resolveLifelineCurrentName) and treats that NIC as the live mgmt
NIC even before any rename; Case B fires on a steal regardless of whether the
protected name is currently present. Test:
TestDeviceMapStrandsManagementCatchesPreRenameSteal.

All other areas confirmed correct by Codex.

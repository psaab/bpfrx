# Adversarial Review (Round 2): Bare-Metal Device-Map (PR #1959)

**Verdict**: `MERGE-READY` (All items, including the critical unmapped lockout gap, are now fully resolved and verified)

---

## 🚨 RESOLVED: Unmapped Management Interface Immediate Lockout / Stranding

> [!NOTE]
> **Vulnerability Type**: Management Lockout / Immediate Network Disconnect (Resolved)
> **Files**: [pkg/daemon/device_map.go:L321-348](file:///home/ps/git/bpfrx/pkg/daemon/device_map.go#L321-L348), [pkg/daemon/device_map_test.go:L213-260](file:///home/ps/git/bpfrx/pkg/daemon/device_map_test.go#L213-L260)

### Resolution
We implemented **Case C** inside [deviceMapStrandsManagement](file:///home/ps/git/bpfrx/pkg/daemon/device_map.go#L258) to check if the configured management interface name (`prot`) is left unmapped in the device-map.
If the live management NIC (`lm`) is left unmapped:
1. Under `leave-alone`, it will be renamed back to its predictable name (`pred`).
2. If `pred != prot` and `lm != prot` (i.e. the NIC's predictable name and current name are both different from the target management interface name), it will not match the network configuration on next boot/apply.
3. This is now caught and rejected as a commit-time stranding error.

We added two new unit tests to [device_map_test.go](file:///home/ps/git/bpfrx/pkg/daemon/device_map_test.go):
- `TestDeviceMapStrandsManagementUnmappedMgmtLocksOut` checks that a lockout rejection fires when the unmapped management NIC's predictable name mismatches the protected interface.
- `TestDeviceMapStrandsManagementUnmappedMgmtOKIfPredictableMatches` ensures that if the predictable name matches the protected interface name, it is accepted as safe.

All tests compile and pass successfully.

---

## 🔍 Status of Round 1 Focus Items

### 1. HIGH-1 MAC format: `compileDeviceMap` normalization
- **Status**: **RESOLVED**
- **Evidence**:
  - `pkg/config/compiler_chassis.go:41` compiles the configured MAC with `normalizeMAC`, which uses `net.ParseMAC` and returns a standard colon-separated lowercase format (`hw.String()`).
  - `pkg/devicemap/devicemap.go:93` builds `byPermMAC` using `strings.ToLower(n.PermMAC)`. `n.PermMAC` is populated using `a.PermHWAddr.String()` which strictly returns the same colon-separated lowercase format.
  - The lookup at `devicemap.go:145` uses `strings.ToLower(e.MAC)`. Mismatch checks use `strings.EqualFold(pm[0].PermMAC, e.MAC)`. String format drift is eliminated.
  - Grep search confirms no other raw MAC comparisons are performed in the device-map resolver scope.

### 2. HIGH-2 pre-flight context: `protectedForConfig`
- **Status**: **RESOLVED**
- **Evidence**:
  - `pkg/daemon/daemon_apply.go:147` and `L250` call `deviceMapCommitPreflight` passing `candidate` and the respective rollback target configs.
  - `pkg/daemon/device_map.go:355` evaluates using `protectedForConfig(candidate)` and `protectedForConfig(rollbackTarget)` which retrieves the specific configuration's management interface leaf and lifeline record. This successfully prevents active-vs-candidate config drift.

### 3. MEDIUM-3 EEXIST: `freeTempName` collisions
- **Status**: **RESOLVED**
- **Evidence**:
  - `pkg/daemon/device_map.go:104-116` pre-populates `inUse` with all present NIC names and marks candidates `xpf-tmp-k` as `inUse` before returning them. This prevents collisions with leftover temp names from crashed daemon runs or other interfaces.
  - A failure of `renameInterface` during the break-collision Phase 1 will log a warning and continue. It does not deadlock the daemon; it results in a clean `EEXIST` when Phase 2 renames the target interface, which is safely logged.

### 4. MEDIUM-4 ambiguous PCI: `byPCI` slice-valued
- **Status**: **RESOLVED**
- **Evidence**:
  - `pkg/devicemap/devicemap.go:84` declares `byPCI` as `map[string][]*PresentNIC`.
  - `devicemap.go:128` checks `if len(pm) > 1` and immediately returns `BindRefusedAmbig`. This removes all dependency on non-stable slice sort order for duplicate PCI addresses, making it completely deterministic.

### 5. MINOR-5: passive alarm warning
- **Status**: **RESOLVED**
- **Evidence**:
  - `pkg/daemon/daemon_apply.go:219-221` logs a warning via `slog.Warn` on `enumeratePresentNICs()` failure rather than exiting silently, alerting the operator that the synced configuration could not be checked.

---

## 🛡️ Verification of Codex HIGH Fixes

### 1. Order-independent topology-change pre-check (`devicemap.Resolve`)
- **Status**: **RESOLVED**
- **Evidence**:
  - `pkg/devicemap/devicemap.go:115-122` runs the mismatch check on the slot's permanent MAC before entering the key loop:
    ```go
    if pm := byPCI[strings.ToLower(e.PCIAddr)]; len(pm) == 1 &&
        pm[0].PermMAC != "" && !strings.EqualFold(pm[0].PermMAC, e.MAC) {
        rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
        out = append(out, rb)
        continue
    }
    ```
  - This guarantees that a card swap in a pinned slot will immediately trigger `BindRefusedAmbig` even if the key order evaluates `MAC` first, preventing bypasses.

### 2. Pre-rename steal catch via `lifelineCurrentName`
- **Status**: **RESOLVED**
- **Evidence**:
  - `deviceMapStrandsManagement` pre-populates `liveMgmt` using `lifelineCurrentName` (resolved by its PCI/MAC identity via `resolveLifelineCurrentName`).
  - Case B check (`devicemap.go:314-320`) triggers if any other NIC is mapped to the protected interface name, successfully catching steals on first boot when the live management NIC still wears its kernel-assigned name (e.g., `enp5s0` instead of `fxp0`).

# Adversarial Review: Bare-Metal Device-Map (PR #1959)

This review pressure-tests the design and implementation of the bare-metal `device-map` topology-change protection, rename pipeline, and pre-flight validation gates in the `engineer/1956-device-map` branch.

---

## 1. Identity Resolver MAC Format Mismatch (Silent Unbound & Commit Rejections)

> [!CRITICAL]
> **Vulnerability Type**: Configuration Parsing & Runtime Resolver Divergence
> **Files**: [pkg/config/schema_validators.go](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/config/schema_validators.go#L491-L514), [pkg/devicemap/devicemap.go](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/devicemap/devicemap.go#L110-L115)

### Findings
`ValidateMAC` in `schema_validators.go:491` delegates to `net.ParseMAC`, which is highly lenient. It successfully parses and accepts MAC addresses formatted with hyphens (e.g., `00-11-22-33-44-55`), periods (e.g., `0011.2233.4455`), or as bare hex strings.

However, neither the compiler nor the device-map resolver normalizes the configured `e.MAC` string to the standard colon-separated lowercase representation before lookup or comparison. This introduces two severe issues:

1. **False-Positive Commit Rejection (PCI with MAC Cross-Check)**:
   In `devicemap.go:111`, the cross-check compares the host NIC's permanent MAC against the configured MAC:
   ```go
   if strings.EqualFold(nic.PermMAC, e.MAC) { ... }
   ```
   `nic.PermMAC` is retrieved via `net.HardwareAddr.String()`, which strictly returns a colon-separated lowercase format (e.g., `"00:11:22:33:44:55"`). If the operator configured the MAC as `"00-11-22-33-44-55"`, this comparison yields `false` and hits the mismatch branch:
   ```go
   rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
   ```
   During a commit, this triggers a `BindRefusedAmbig` status. The pre-flight check `deviceMapStrandsManagement` interprets this as a hostile topology swap and **hard-rejects the commit** with a misleading error, preventing configuration updates.

2. **Silent Unbound Interfaces (MAC-only Key)**:
   If using the `mac` key order, `Resolve` in `devicemap.go:121` looks up:
   ```go
   matches := byPermMAC[strings.ToLower(e.MAC)]
   ```
   Since `byPermMAC` is keyed exclusively by colon-separated strings, a hyphenated or dot-separated configured MAC fails to match and returns `nil`. The interface remains silently `BindUnbound`.

### Recommended Fix
Normalize all MAC addresses to colon-separated lowercase format inside `compiler_chassis.go` at compile-time, or parse both MACs to `net.HardwareAddr` objects prior to performing the comparison.

---

## 2. Candidate Context Mismatch in `deviceMapCommitPreflight` (Management Lockout)

> [!WARNING]
> **Vulnerability Type**: Privilege Escalation / Management Stranding Bypass
> **Files**: [pkg/daemon/device_map.go](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/device_map.go#L308-L344)

### Findings
During a commit, `deviceMapCommitPreflight` validates the candidate configuration against a set of protected interfaces:
```go
329: 	protected := d.resolveProtectedInterfaces()
330:
331: 	if reason := deviceMapStrandsManagement(candidate, nics, protected); reason != "" {
```
The helper `d.resolveProtectedInterfaces()` resolves the protected set using the **currently active** configuration:
```go
583: 	if cfg := d.store.ActiveConfig(); cfg != nil {
584: 		mgmtLeaf = cfg.System.ManagementInterface
585: 	}
```
This causes a critical mismatch when the candidate configuration modifies the management interface:

1. **Silent Lockout (False Negative)**:
   If the active configuration uses `fxp0` for management, but the candidate moves management to `ge-0-0-1` (`system management-interface ge-0-0-1`) and simultaneously introduces an invalid `device-map` that mis-pins or renames `ge-0-0-1` away, the pre-flight check only protects `fxp0`. The candidate's `ge-0-0-1` is not verified. The commit succeeds, applying the bad map, and next boot/apply completely strands the management session.

2. **Commit Denial (False Positive)**:
   Conversely, if an operator attempts to migrate the management interface away from `fxp0` to another interface and re-assigns the physical NIC currently named `fxp0` via `device-map`, the pre-flight check evaluates the candidate against the active config's `protected` set (which still requires `fxp0` to be untouched). The check will reject the commit as a lockout, preventing legitimate migrations.

### Recommended Fix
Modify `deviceMapCommitPreflight` to resolve the protected interfaces relative to the configuration being verified rather than the active store config:
```go
func (d *Daemon) resolveProtectedInterfacesForConfig(cfg *config.Config) map[string]bool {
	mgmtLeaf := ""
	if cfg != nil {
		mgmtLeaf = cfg.System.ManagementInterface
	}
	return protectedInterfaces(mgmtLeaf)
}
```

---

## 3. Temp-Rename Collision EEXIST Deadlock

> [!IMPORTANT]
> **Vulnerability Type**: State Machine Race / Deadlock
> **File**: [pkg/daemon/device_map.go](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/device_map.go#L91-L127)

### Findings
In Phase 1 of `enumerateAndRenameMapped`, colliding NICs are moved to temp names `xpf-tmp-%d` starting with index `0`.
If a temp interface `xpf-tmp-0` from a previous failed rename run or unmanaged stranding is already present in the kernel, the rename command `renameInterface(n.Name, tmpName)` fails with `EEXIST`.

The code logs a warning and proceeds with the loop:
```go
109: 		if err := renameInterface(n.Name, tmpName); err != nil {
110: 			slog.Warn("device-map: temp-rename to break collision failed",
111: 				"from", n.Name, "to", tmpName, "err", err)
112: 			continue
113: 		}
```
However:
- The colliding interface is **not** renamed out of the way.
- In Phase 2, when the resolver attempts to rename the correct interface to the desired target name, it will fail with `EEXIST` because the colliding interface is still occupying it.
- This leads to a partial/deadlocked rename sequence where multiple interfaces end up with wrong or temporary names.

### Recommended Fix
Verify that the generated `xpf-tmp-%d` interface name does not already exist in the kernel before attempting the rename, or handle temp-rename failures by rolling back rather than continuing blindly.

---

## 4. Non-Deterministic Resolution on Duplicate PCI Addresses

> [!WARNING]
> **Vulnerability Type**: Non-Deterministic Behavior & Interface Hijacking
> **Files**: [pkg/devicemap/devicemap.go](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/devicemap/devicemap.go#L84-L95), [pkg/devicemap/devicemap.go#L230](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/devicemap/devicemap.go#L230)

### Findings
In virtualized setups, hypervisor configurations (such as SR-IOV VFs or partitioned NICs), multiple network interfaces can share the exact same PCI address (e.g., same slot/function but different MACs).

`EnumeratePresentNICs` populates a slice of NICs and sorts it using `sort.Slice`:
```go
230: 	sort.Slice(nics, func(i, j int) bool { return nics[i].PCIAddr < nics[j].PCIAddr })
```
`sort.Slice` is not stable. The relative order of interfaces sharing the same PCI address depends on the traversal order returned by `os.ReadDir("/sys/class/net")`, which is non-deterministic.

In `Resolve`, `byPCI` map construction overwrites duplicate keys:
```go
88: 		if n.PCIAddr != "" {
89: 			byPCI[strings.ToLower(n.PCIAddr)] = n
90: 		}
```
If two NICs share the same PCI address, only the last one sorted will be present in `byPCI`. Because the sorting is unstable, this index varies non-deterministically across reboots or reload cycles, causing the logical name mapping to flap or silently bind to the wrong physical interface.

### Recommended Fix
1. Use `sort.SliceStable` to ensure stability.
2. In `Resolve`, detect when multiple present interfaces share a single PCI address. If a duplicate is detected, treat it as ambiguous/refused (`BindRefusedAmbig`) rather than silently overwriting the map and choosing one at random.

---

## 5. Silent Admission Alarm Bypass on Passive Node SyncApply

> [!NOTE]
> **Vulnerability Type**: Silent Safety Gate Bypass
> **File**: [pkg/daemon/daemon_apply.go](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/daemon_apply.go#L210-L224)

### Findings
`deviceMapPassiveAdmissionAlarm` is responsible for checking if a peer-synced configuration would strand the local standby node's management interface. If a problem is found, it raises a loud error to alert the operator.
However, if `enumeratePresentNICs` returns an error (e.g., due to temporary netlink errors or sysfs lockups), the check silently exits:
```go
214: 	nics, err := enumeratePresentNICs()
215: 	if err != nil {
216: 		return
217: 	}
```
No alarm or warning is logged. The standby node silently admits the configuration without checking if the next reboot will strand its management access.

### Recommended Fix
Log a warning if `enumeratePresentNICs` fails during passive node sync validation to explicitly alert the operator that the safety gate could not be checked:
```go
	nics, err := enumeratePresentNICs()
	if err != nil {
		slog.Warn("HA CONFIG-SYNC WARNING: failed to enumerate local hardware for device-map check; "+
			"admission validation skipped.", "err", err)
		return
	}
```

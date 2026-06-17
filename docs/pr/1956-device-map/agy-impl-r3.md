# AGY Adversarial Review: Bare-Metal Device-Map

**Target:** `branch diff origin/master...HEAD` (`origin/engineer/1956-device-map`)  
**Verdict:** **NEEDS-MAJOR**

This document evaluates the device-map implementation changes introduced in branch `origin/engineer/1956-device-map` against the round-3 feedback and security invariants. It specifically targets the safety of management lifelines, lockouts, topology changes, peer-sync admission safety, and predictable-name recovery.

---

## 1. Executive Summary

While the PR branch correctly resolves several issues from prior rounds (e.g., preventing duplicate PCI claims via order-independent checks, preventing key-mac/reth mismatches, and providing passive-node sync alarms), it introduces **one CRITICAL lockout path** and **two MAJOR regressions/flaws**:
1. **[CRITICAL] Configuration Apply Sweeps Protected Interface Configs:** The active management interface (e.g., `fxp0`) is deleted from systemd-networkd configuration during a config apply commit if it is left out of the interfaces configuration, leading to an immediate lockout on reload.
2. **[MAJOR] Unmapped Protected Interfaces Collide on Reboot:** If a mapped logical name matches a protected interface name that is currently assigned to a different physical interface, a udev name collision occurs on reboot, causing renaming failures.
3. **[MAJOR] Broken `OriginalName=` Matching on Fresh Boxes:** Fallback name derivation uses hardcoded PCI-to-`enp` calculations, which overrides the actual naming scheme (e.g., `ens3` for virtio) on fresh boxes, permanently breaking interface renaming on reboot.

---

## 2. Hostile Verification of User Focus Questions

### (a) Does any commit/boot/sync path still tear down or scrub a protected mgmt interface?

**Yes (CRITICAL).** While `teardownUnmappedManaged` explicitly skips protected interfaces, `networkd.Apply` immediately afterwards deletes them at runtime.

* **The Mechanism:**
  1. In [daemon_apply.go:L700](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/daemon_apply.go#L700), `teardownUnmappedManaged` runs. It reads `10-xpf-*.link` and `.network` files, and correctly skips deleting `fxp0` because it is in `protected`.
  2. In [daemon_apply.go:L705](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/daemon_apply.go#L705), `d.networkd.Apply(applyResult.ManagedInterfaces)` runs.
  3. Because `fxp0` is unmapped (absent from the device-map) and unconfigured (absent from the `interfaces` section), the dataplane compiler in [compiler_iface.go:L1154](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/dataplane/compiler_iface.go#L1154) skips it (due to `daemonOwned[name] = true` at L1127). Thus, it is **never** added to `applyResult.ManagedInterfaces`.
  4. In [networkd.go:L134-145](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/networkd/networkd.go#L134-L145), the networkd manager builds `expected` files from `ManagedInterfaces`. Since `fxp0` is absent, its files are not expected.
  5. The manager performs a glob scrub: `filepath.Glob(filepath.Join(m.networkDir, "10-xpf-*"))`.
  6. It finds `10-xpf-fxp0.link` and `10-xpf-fxp0.network` and deletes them via `os.Remove(path)`.
  7. On networkd reload, the management interface loses its IP and gateway configuration, causing an **instant operator lockout**.

---

### (b) Can the Case A / Case B strand logic now MISS a real lockout (false negative)?

**Yes (MAJOR).** The validation logic misses rename collisions and suffers from false negatives/positives when the lifeline record is absent.

* **Issue B.1: Collision with Unmapped Protected Interface (False Negative)**
  * Suppose `fxp0` and `ge-0/0/3` are protected management interfaces.
  * In the device-map, the operator maps the NIC currently named `fxp0` to `ge-0/0/3`, and leaves the NIC currently named `ge-0/0/3` unmapped.
  * In [device_map.go:L342-358](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/device_map.go#L342-L358):
    * Case B loops over `finalByCurrent` and checks if `final == prot && !liveMgmt[current]`.
    * For the entry mapping `fxp0` to `ge-0/0/3`, `current = "fxp0"`, `final = "ge-0/0/3"`.
    * Since `fxp0` is in `liveMgmt`, `liveMgmt[current]` is `true`, and Case B skips it.
    * The commit is allowed.
  * **Result:** On reboot, the mapped NIC is renamed to `ge-0/0/3` via udev. However, the unmapped-but-protected NIC also keeps its `.link` rule targeting `ge-0/0/3`. Udev experiences a name collision, locking out management on reboot.

* **Issue B.2: Bypassed/Absent Lifeline Record (False Negative & False Positive)**
  * If the lifeline record `/etc/xpf/lifeline-interface` is missing or lifeline detection was skipped, `lifelineCurrentName` resolves to `""`.
  * **Case A False Negative:** If a fresh box has not yet renamed its NICs, the live mgmt NIC is named `enp5s0`, but `liveMgmt` contains only `fxp0`. The operator maps `enp5s0` to a non-management name (e.g., `ge-0/0/0`). Case A does not check `enp5s0` because it's not in `liveMgmt`, failing to reject the lockout.
  * **Case B False Positive:** The operator maps `enp5s0` to `fxp0`. Case B evaluates `final == "fxp0" && !liveMgmt["enp5s0"]` as `true` (since `liveMgmt` only contains `fxp0`). The commit is rejected even though the remap is legitimate.

---

### (c) Is the `deriveKernelName` fallback correct for a fresh box with no prior `.link`?

**No (MAJOR).** The derivation fallback overrides correct names with incorrect `enp` names, breaking rename persistence on boot.

* **The Mechanism:**
  1. On a fresh box, `recoverOriginalName(b.CurrentNIC)` returns the live interface name, e.g., `"ens3"` (for a virtio interface).
  2. In [device_map.go:L85](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/device_map.go#L85), `orig == b.CurrentNIC` evaluates to `true` (both are `"ens3"`).
  3. The code calls `deriveKernelNameFn("ens3")`, which inspects sysfs and formats the name based on PCI slot/bus: `"enp0s3"`.
  4. The code overrides `orig` to `"enp0s3"`.
  5. The `.link` file is written with `OriginalName=enp0s3`.
  6. On reboot, the kernel/udev names the interface `"ens3"`. The udev match against `OriginalName=enp0s3` fails, and the interface is **never renamed**, breaking the device-map.
  7. **Brittle Naming Scheme:** Hardcoding PCI-to-`enp` calculations in `deriveKernelName` is fragile. The daemon already defines `predictableName(presentNIC)` which queries `udevadm info` (using properties `ID_NET_NAME_ONBOARD`, `ID_NET_NAME_SLOT`, etc.). Overriding it with `deriveKernelName` ignores udev's actual naming scheme.

---

## 3. High-Confidence Code Analysis & Line Citations

### 3.1 The `networkd.Apply` Clean-Up Bug
* File and Line: [pkg/networkd/networkd.go:L134-145](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/networkd/networkd.go#L134-L145)
* Context:
  ```go
	// Remove stale xpf-managed files
	matches, _ := filepath.Glob(filepath.Join(m.networkDir, filePrefix+"*"))
	for _, path := range matches {
		base := filepath.Base(path)
		if !expected[base] {
			if err := os.Remove(path); err != nil {
				slog.Warn("failed to remove stale networkd file", "path", path, "err", err)
			} else {
				slog.Info("removed stale networkd file", "path", path)
				changed = true
			}
		}
	}
  ```
  Since `Apply` is called with the compiled `applyResult.ManagedInterfaces`, any unconfigured/unmapped interfaces (including the protected ones) are absent. This glob cleanup unconditionally deletes their configurations.

### 3.2 The `OriginalName` Fallback Overwrite
* File and Line: [pkg/daemon/device_map.go:L85-98](file:///home/ps/git/bpfrx/.claude/worktrees/1956-eng/pkg/daemon/device_map.go#L85-L98)
* Context:
  ```go
			orig := recoverOriginalName(b.CurrentNIC)
			if orig == b.CurrentNIC {
				// recoverOriginalName found no existing .link for this name.
				// The NIC may already carry its final logical name (second+ boot
				// with device-map) but the .link was absent. Derive the true
				// pre-rename kernel name (e.g. enp9s0) from sysfs so the .link
				// is written with the correct OriginalName= that udev will match
				// on next boot, not the logical name that udev would never see.
				if dk := deriveKernelNameFn(b.CurrentNIC); dk != "" {
					orig = dk
				}
			}
  ```
  On fresh boxes, `b.CurrentNIC` is already the original kernel name (e.g., `ens3`). Overriding it with `deriveKernelNameFn` breaks the boot-time match.

---

## 4. Recommended Fixes

1. **Fix `networkd.Apply` scrubbing:**
   Introduce the `protected` interface set to the `networkd.Manager` (or pass it to `Apply`) so that `expected` maps are populated for protected interfaces even if they are not in the compiled config's interface list.
2. **Improve `deviceMapStrandsManagement` Case B Collision Checking:**
   Check if any mapped final name `final` matches a protected name `prot` AND the NIC currently carrying `prot` is NOT mapped to a different name (meaning two NICs would claim `prot` on reboot).
3. **Correct `OriginalName` Derivation on Fresh Boxes:**
   Only call `deriveKernelName` if `b.CurrentNIC` matches a logical name (e.g., `desiredNames[b.CurrentNIC] == true`) or if we use the robust `udevadm`-based `predictableName` query instead of hardcoding `enp` strings.

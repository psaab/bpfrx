# Plan Review (Round 2) — #1943 Ubuntu Test Environment Realignment

This document details the Round 2 review of the plan defined in [plan.md](file:///.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md).

---

## 1. Auditing Round 1 Findings

### [Finding 1] `linux-modules-extra` gap breaks SR-IOV/passthrough NICs
* **Status:** **RESOLVED**
* **Evidence:**
  * Section 6.3, lines 173-178:
    > `- **ADD linux-modules-extra-$(uname -r)** (AGY r1 #1 + Codex r1 #2 — HIGH; SMR r2 N4 refines the exact name). Ubuntu splits NIC drivers (mlx5_core, i40e, ixgbe) into linux-modules-extra, NOT the base kernel package. Both test envs need physical PCI passthrough (setup.sh WAN/loss PF) or SR-IOV VFs (cluster-setup.sh mlx5 VFs). Without it those interfaces never bind → total test failure.`
  * Section 8, step 3 (lines 345-349):
    > `confirm /lib/modules/$(uname -r)/kernel/drivers/net/ethernet/{mellanox,intel} exist ... Without this both test envs fail to bring up dataplane NICs.`

---

### [Finding 2] Dropped reboot breaks `init_on_alloc=0`
* **Status:** **RESOLVED**
* **Evidence:**
  * Section 6.2, lines 148-154:
    > `**KEEP the reboot step (AGY r1 #2 — HIGH).** Removing the kernel *install* does NOT remove the need for a reboot: the init_on_alloc=0 grub change (below) only takes effect after a reboot. If the reboot is dropped, the VM runs all subsequent tests with init_on_alloc=1 → the ~20% virtio-net XDP CPU regression the tuning exists to avoid.`
  * Section 9, line 390:
    > `| init_on_alloc=0 inactive — dropped reboot OR cloudimg override | Med | keep a post-grub reboot (AGY #2); grub.d drop-in form; §8 step-4 verify /proc/cmdline on the actual V1 image (SMR F1) |`

---

### [Finding 3] Rollback env-override fallacy
* **Status:** **RESOLVED**
* **Evidence:**
  * Section 10, lines 403-410:
    > `**Rollback is git revert of the setup-script + CLAUDE.md diff — NOT a runtime env-override (r1 fallacy, AGY #3 + SMR).** Once the scripts carry Ubuntu package names (linux-headers-generic, linux-modules-extra-generic, linux-tools-generic) and drop the Debian-unstable kernel dance, IMAGE_VM=images:debian/13 make test-vm would FAIL: those package names don't exist on Debian, and Debian 13's stock kernel is < 6.18 so the AF_XDP shim verifier floor (pkg/dataplane/verify_userspace_shim.go) rejects the dataplane.`

---

### [Finding 4] EFI varstore destroyed on VM recreate breaks MOK/boot-path
* **Status:** **RESOLVED**
* **Evidence:**
  * Section 6.4, lines 253-259:
    > `**EFI varstore lifecycle footgun (AGY r1 #4 + SMR F4 — MEDIUM):** incus VM EFI vars persist across *soft reboots* ... BUT make test-destroy && make test-vm deletes the instance's nvram/varstore on the host, wiping any enrolled MOK and the registered A/B Boot#### entries. The plan must: - Document that A4 boot-path runs happen within ONE VM lifetime (don't destroy/recreate mid-test)`
  * Section 8, step 8 (lines 371-372):
    > `Done WITHIN ONE VM LIFETIME (destroy wipes the varstore — §6.4).`

---

### [Finding 5] Drop redundant `golang`
* **Status:** **RESOLVED**
* **Evidence:**
  * Section 6.3, lines 188-190:
    > `- **DROP golang** (AGY r1 #5 + SMR F5). The VM never compiles Go — make build runs on the HOST and test-deploy pushes the binary (setup.sh:376-401). golang is ~500 MB of pure provisioning waste.`

---

## 2. New Findings and Realignment Risks (introduced in r2)

While the r2 plan successfully addresses all previous findings, it introduces a few minor inconsistencies and technical risks regarding package naming and Ubuntu kernel package availability:

### [NEW-1] Plan text inconsistency on `linux-modules-extra` package naming
* **Finding:** There is a direct contradiction between the package specification in Section 6.3 and the test validation steps in Section 8.3:
  * **Section 6.3 (line 178-180):** Specifies the version-exact package `linux-modules-extra-$(uname -r)` and explicitly cautions *against* using the generic metapackage.
  * **Section 8.3 (line 347):** Instructs the tester to verify drivers exist `after installing linux-modules-extra-generic`.
* **Impact:** Confuses the implementor on which package strategy to apply.
* **Mitigation:** Unify the terminology. The script should use the exact design choice decided in Section 6.3.

### [NEW-2] Package availability risk for version-exact `linux-modules-extra-$(uname -r)`
* **Finding:** Ubuntu's standard package repositories (`-updates` and `-security`) routinely deprecate and remove older kernel package versions as new security updates are rolled out. If the VM image `images:ubuntu/26.04/cloud` is slightly aged, the kernel version it booted (e.g., `6.18.0-11-generic`) may no longer have its matching `linux-modules-extra-6.18.0-11-generic` package published in the repository after running `apt-get update`. This will cause the `apt-get install` step to fail with a package-not-found error.
* **Impact:** High risk of VM provisioning failure on standard base images over time.
* **Mitigation:** Upgrade the kernel dynamically during VM setup to the latest repository package. Install the metapackages `linux-image-generic`, `linux-headers-generic`, `linux-tools-generic`, and `linux-modules-extra-generic`, and then perform a reboot. This guarantees all components are present, matching, and successfully resolved.

### [NEW-3] Mismatched kernel headers/tools vs. running stock kernel
* **Finding:** Section 6.3 specifies installing `linux-headers-generic` and `linux-tools-generic` (which are metapackages that pull the latest version in the repository) without upgrading the kernel itself (the plan drops the kernel-install dance). If the repository has a newer kernel version than the stock image booted, the installed headers and tools will mismatch `$(uname -r)`.
* **Impact:** Compilers inside the VM and diagnostic tools like `perf` (which is highly version-sensitive on Ubuntu and maps to specific `perf_$(uname -r)` executables) will fail or print warnings.
* **Mitigation:** Same as `NEW-2`: upgrade the kernel image, headers, tools, and extra modules together using the `-generic` metapackages, then reboot the VM.

---

## 3. Final Verdict

### **PLAN-READY**

The core plan is sound, robustly structured, and addresses all five findings from Round 1. The new findings listed above are implementation-level details and edge cases that can be easily addressed during the implementation phase by upgrading all kernel components to the latest `-generic` metapackage and rebooting. No structural blockers remain.

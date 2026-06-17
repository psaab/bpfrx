# Adversarial Review: Standalone Test Env Parity Plan (#1943)

This document presents a hostile, pressure-testing review of the research plan doc at [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md) which outlines the realignment of the Incus test VMs from Debian 13 to Ubuntu 26.04.

---

## Verdict: `PLAN-NEEDS-WORK`

While the plan correctly identifies core issues such as the Ubuntu `grub.d` override footgun and the path to align with `bake.py`'s production base, it contains high-risk gaps in driver packaging, boot configuration requirements, and contains a severe logic fallacy regarding runtime rollback. It must not proceed to implementation as-is.

---

## High-Confidence Findings & Risks

### 1. The `linux-modules-extra` Gap (Breaks physical/SR-IOV networks)
* **Finding**: The plan proposes installing only `linux-headers-generic` on the target Ubuntu test VMs. However, Ubuntu separates hardware drivers (including Mellanox `mlx5_core` and Intel `i40e`/`ixgbe` drivers) into a separate `linux-modules-extra-generic` (or `linux-modules-extra-$(uname -r)`) package.
* **Impact**: Both standalone [setup.sh:211-226](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/test/incus/setup.sh#L211-L226) and cluster [cluster-setup.sh:345-382](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/test/incus/cluster-setup.sh#L345-L382) require physical PCI passthrough or SR-IOV VFs. Without `linux-modules-extra`, these interfaces will not be recognized by the guest kernel. The test environment will fail to build networking, causing complete test failure.
* **Evidence**:
  * The production image builder [bake.py:227-228](file:///home/ps/git/bpfrx/scripts/image/bake.py#L227-L228) explicitly asserts that this directory is present:
    ```python
    'test -d "/lib/modules/$(ls /lib/modules | sort -V | tail -1)/kernel/drivers/net/ethernet/mellanox" || '
    '{ echo "FATAL: linux-modules-extra missing (mlx5/i40e)" >&2; exit 1; }'
    ```
  * Yet, [plan.md:150-151](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md#L150-L151) only lists:
    ```markdown
    - `linux-image-amd64 linux-headers-amd64` → `linux-headers-generic` (headers
      for the running `-generic` kernel; the image already has the kernel).
    ```
* **Resolution**: Explicitly add `linux-modules-extra-generic` to the list of apt packages installed inside the VM during provisioning.

### 2. Reboot Removal Breaks `init_on_alloc=0` Mitigation
* **Finding**: The plan proposes removing the kernel reboot loop when dropping the Debian-unstable kernel dance since the base kernel version is already $\ge$ 6.18.
* **Impact**: Changing the kernel command-line variables (specifically adding `init_on_alloc=0` via a `/etc/default/grub.d/99-xpf.cfg` drop-in) **requires a reboot to take effect**. If the reboot loop is deleted, the VM will boot, apply the drop-in, but run its subsequent verification and performance tests with the original command-line active (`init_on_alloc=1`). This causes a ~20% CPU performance regression in the virtio-net XDP path during active test runs.
* **Evidence**:
  * [plan.md:130-132](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md#L130-L132) states:
    ```markdown
    If the probe shows `images:ubuntu/26.04` ships >= 6.18 (expected):
    **delete** the Debian-unstable repo + pin + `linux-image-amd64` install + the
    dedicated kernel-reboot loop (`setup.sh:287-300`).
    ```
* **Resolution**: Keep a reboot step in both `setup.sh` and `cluster-setup.sh` to ensure grub command-line drop-in changes are loaded into kernel state before running the daemon.

### 3. Fallacy in Rollback Capability Wording
* **Finding**: The plan states that rollback is a "one-liner at runtime" via `IMAGE_VM=images:debian/13 make test-vm` because the image is env-overridable.
* **Impact**: This is false. If the scripts are updated to replace package lists and remove kernel upgrade logic (as Debian 13 VM ships with a kernel version $< 6.18$ and needs the unstable dance to satisfy the verifier floor), running with `IMAGE_VM=images:debian/13` will immediately crash because `linux-headers-generic` does not exist on Debian, and the resulting kernel will be blocked by the `VerifyEmbeddedUserspaceShim` floor gate.
* **Evidence**:
  * [plan.md:283-284](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md#L283-L284) states:
    ```markdown
    diff, or even simpler at runtime: `IMAGE_VM=images:debian/13 make test-vm`
    (image is env-overridable in the proposed design).
    ```
* **Resolution**: Clarify that rollback is a full `git revert` of the setup tooling changes, or retain conditional logic branch code inside the provisioning scripts for handling package deltas and kernel dances depending on OS identity.

### 4. VM Lifecycle Destroys UEFI Varstore (Breaks boot-path testing)
* **Finding**: The plan asserts that "EFI varstore persistence is automatic for incus VMs" to test the #1930 MOK boot-path.
* **Impact**: While variables persist across soft reboots of the QEMU guest, running `make test-destroy && make test-vm` (a standard development cycle) destroys the Incus instance, deleting its nvram/varstore file on the host. This wipes any enrolled MOK keys or custom variables, requiring manual re-enrollment/reconfiguration on every VM provisioning cycle.
* **Evidence**:
  * [plan.md:175-177](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/docs/research/1943-ubuntu-test-env-parity/plan.md#L175-L177) states:
    ```markdown
    - Persist EFI vars (incus VM root disk includes the OVMF varstore by default —
      confirm A/B ESP slot writes + `grub-reboot` survive a reboot, which is the
      whole point of the #1930 channel).
    ```
* **Resolution**: Explicitly note this lifecycle limitation in the plan and document how to script automated key/variable injection (or verify that they survive VM recreations by using custom profiles/templates).

### 5. Redundant Package Cleanup (Golang)
* **Finding**: The package lists in [setup.sh:281](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/test/incus/setup.sh#L281) and [cluster-setup.sh:459](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/test/incus/cluster-setup.sh#L459) contain `golang`.
* **Impact**: The Go binaries are compiled on the host and pushed to the guest. No Go compilation happens on the guest. Installing Go (~500MB download and disk write) is a redundant operation that slows down VM provisioning.
* **Evidence**:
  * [setup.sh:376-401](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/test/incus/setup.sh#L376-L401) shows the host compiling and pushing the binary:
    ```bash
    make -C "$PROJECT_ROOT" build build-ctl
    ...
    incus file push "$PROJECT_ROOT/xpfd" "$INSTANCE_NAME/usr/local/sbin/xpfd"
    ```
* **Resolution**: Drop `golang` / `golang-go` from the target VM package lists.

---

## Detailed Check Verification

### (1) Kernel $\ge 6.18$ verifier-floor gating when dropping Debian-unstable kernel dance
* **Verified**: Gating is present via pre-flight checks ([cluster-setup.sh:805-848](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/test/incus/cluster-setup.sh#L805-L848)) and runtime verification ([verify_userspace_shim.go:54-63](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/pkg/dataplane/verify_userspace_shim.go#L54-L63)).
* **Issue**: Dropping the dance is safe, but skipping the reboot breaks the grub settings (see High-Confidence Finding #2).

### (2) Debian $\to$ Ubuntu package-name deltas
* **Verified**:
  * `linux-image-amd64` $\to$ already installed in base image.
  * `linux-headers-amd64` $\to$ must be renamed to `linux-headers-generic` or `linux-headers-$(uname -r)` (Ubuntu).
  * `linux-perf` $\to$ must be `linux-tools-generic` to match running kernel.
  * `golang` $\to$ should be removed completely (see High-Confidence Finding #5).
  * **Gap**: `linux-modules-extra-generic` must be added (see High-Confidence Finding #1).

### (3) Ubuntu cloudimg grub.d override footgun
* **Verified**: The plan correctly calls out that `/etc/default/grub.d/50-cloudimg-settings.cfg` overrides default grub settings. Seding `/etc/default/grub` is lost. Writing `/etc/default/grub.d/99-xpf.cfg` is correct.

### (4) Secure-Boot profile enabling #1930 A4 boot-path validation + Secure-Boot break on AF_XDP load
* **Verified**:
  * Secure Boot does **not** break `AF_XDP` shim load. Standard kernels in `integrity` lockdown mode restrict tracing/kprobe eBPF, but allow `BPF_PROG_TYPE_XDP` and socket filters which the shim relies on.
  * The UEFI varstore lifecycle (surviving a destroy-recreate loop) is a gap (see High-Confidence Finding #4).

### (5) Cluster realign scope vs smoke-gating-env risk
* **Verified**: Changing `cluster-setup.sh` affects the shared loss cluster where developers run remote smoke tests. If the align process is botched, it blocks the team. A sequential approach (land standalone PR, verify, then cluster) is correct, but the rollback plan is fallacious (see High-Confidence Finding #3).

### (6) Production code assuming Debian
* **Verified**: Checked the entire `pkg/`, `cmd/`, and `debian/` structure. Production code is distro-agnostic. The install script [install.sh:75-78](file:///home/ps/git/bpfrx/.claude/worktrees/1943-research-ubuntu-parity/scripts/dist/install.sh#L75-L78) accepts `*debian*|*ubuntu*`. No other Debian-specific gates exist in production source.

I will view the contents of the target plan document `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md` to analyze the proposed upgrades and verify the resolution of the five specific blockers.
I will view the rest of the file to check if there are any remaining details or sections at the end.
I will list the contents of the research directory to see if there are any other files or drafts for this change.
I will view `agy-r3.md` to see the detailed context of the blockers we identified in Round 3.
PLAN-NEEDS-REVISION (remaining blockers)

***

## Executive Verdict
While the Revision 6 plan successfully integrates the solutions for the five major operational blockers identified in Round 3, it introduces **critical internal contradictions** regarding file paths and contains a **dangerous loophole in the GRUB fallback design**. Specifically, stale references to `/usr/local/lib/xpf/<version>/` remain in several key implementation sections, directly contradicting the new staging path `/usr/local/share/xpf/staged/`. Additionally, the GRUB recovery mechanism fails to guard against `GRUB_SAVEDEFAULT=true`, which would brick the system.

Below is a detailed verification of the five blockers, followed by the remaining gaps and internal contradictions that must be resolved before the plan is marked `PLAN-READY`.

---

## 1. Verification of the Five Round-3 Blockers

### Blocker 1: Daemon Startup Lenient on Config-DB Parse Error
*   **Resolution Status:** **Correctly & Completely Resolved.**
*   **Verification:** §6.3b and §8 correctly mandate that any configuration database parse error (excluding a clean `os.IsNotExist` check, which triggers a factory bootstrap) must cause `xpfd` to fail-closed and exit immediately. 
*   **New Defects Introduced:** None. While a corrupted database will now prevent the daemon from starting entirely, this is the correct behavior for a high-availability network appliance, preventing it from running silently unconfigured or wiping the configuration on disk.

### Blocker 2: `dpkg` Deletes Versioned Directory on Upgrade
*   **Resolution Status:** **Conceptually Resolved, but introduces Internal Contradictions.**
*   **Verification:** The design in §6.1/§6.3c correctly separates the `dpkg`-managed staging directory (`/usr/local/share/xpf/staged/`) from the runtime execution directory (`/var/lib/xpf/versions/<version>/`). Since `/var/lib/xpf/` is not tracked by the Debian package database, `dpkg` will not delete active or rollback versions.
*   **New Defects / Contradictions Introduced:** Several stale path references to the deprecated `/usr/local/lib/xpf/<version>/` staging model were left in the text (see Section 2).

### Blocker 3: `needrestart` Service Interruption
*   **Resolution Status:** **Correctly & Completely Resolved.**
*   **Verification:** §6.3c addresses this via two layers:
    1. Shipping `/etc/needrestart/conf.d/xpf.conf` to blacklist `xpfd.service` and the binary paths from automatic service restarts.
    2. The static-staging change from Blocker 2 ensures that the active binary `/var/lib/xpf/versions/<version>/xpfd` is never deleted or replaced by `dpkg` during the transaction, meaning `needrestart` will not detect it as a deleted binary.
*   **New Defects Introduced:** None.

### Blocker 4: `softdog` Insufficient for Early-Boot Protection
*   **Resolution Status:** **Correctly & Completely Resolved.**
*   **Verification:** §6.7 correctly mandates the use of a hardware or hypervisor-level watchdog (`/dev/watchdog` or systemd `RuntimeWatchdogSec`) and explicitly documents that a software watchdog (`softdog`) is insufficient because it cannot catch crashes or hangs during early kernel decompression or initialization (before the module is loaded).
*   **New Defects Introduced:** None. The plan honestly scopes this as a hard hardware/hypervisor dependency for the "never-brick" guarantee.

### Blocker 5: `grub-reboot` Requires `GRUB_DEFAULT=saved`
*   **Resolution Status:** **Resolved, but requires critical configuration safeguarding.**
*   **Verification:** §6.3c/§6.7 correctly mandate setting `GRUB_DEFAULT=saved` in the GRUB configuration.
*   **New Defects / Gaps Introduced:** The plan mentions `+ GRUB_SAVEDEFAULT handling` in §6.3c but does not explicitly specify that **`GRUB_SAVEDEFAULT` must be set to `false` or disabled**. If `GRUB_SAVEDEFAULT=true` is active on the system, GRUB will save the candidate kernel as the permanent default *at the moment it boots*, defeating the one-shot fallback of `grub-reboot` if the candidate kernel subsequently hangs or fails verification.

---

## 2. Internal Contradictions (Stale Path References)

The move to the static staging path (`/usr/local/share/xpf/staged/`) and the runtime versioned path (`/var/lib/xpf/versions/`) is contradicted by several stale references to `/usr/local/lib/xpf/<version>/` in the plan text:

*   **[Line 239](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L239-L244):** 
    > *"binaries install to a versioned dir /usr/local/lib/xpf/\<version\>/; ... dpkg only \*stages\* the new versioned dir..."*
    *   **Correction needed:** Update to reflect that binaries are staged in `/usr/local/share/xpf/staged/` and copied to `/var/lib/xpf/versions/\<version\>/` by `xpf-upgrade`.
*   **[Line 277](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L277-L281):**
    > *"After apt upgrade stages N+1 under /usr/local/lib/xpf/\<N+1\>/, the live /usr/local/sbin/xpf-upgrade symlink still points at N..."*
    *   **Correction needed:** The staged path is `/usr/local/share/xpf/staged/xpf-upgrade`.
*   **[Line 341](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L341-L343):**
    > *"...binaries install ONLY to /usr/local/lib/xpf/\<version\>/; the cut is the atomic symlink flip owned by xpf-upgrade..."*
    *   **Correction needed:** Align with the staging/runtime separation.
*   **[Line 618](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L618-L619):**
    > *"Assert the staged /usr/local/lib/xpf/\<N+1\>/xpf-upgrade is the binary that runs the cut..."*
    *   **Correction needed:** Change to `/usr/local/share/xpf/staged/xpf-upgrade`.
*   **[Risk 9 (Line 577)](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/docs/research/1917-deb-inplace-upgrade/plan.md#L577):**
    > *"...blacklist xpfd.service / the /usr/local/lib/xpf/ paths from auto-restart"*
    *   **Correction needed:** The paths to blacklist from needrestart are `/usr/local/share/xpf/staged/` and `/var/lib/xpf/versions/`.

---

## 3. Remaining Operational Gaps

### Gap A: `GRUB_SAVEDEFAULT` Must Be Explicitly Disabled
If `GRUB_SAVEDEFAULT=true` is defined in `/etc/default/grub`, GRUB automatically saves the currently selected menu entry as the default for subsequent boots. 
*   **The Hazard:** During `grub-reboot <candidate>`, GRUB loads the candidate entry. If `GRUB_SAVEDEFAULT` is active, it writes the candidate entry to the `grubenv` as the permanent default. If the candidate kernel panics or fails verification, the watchdog resets the system, but the bootloader will try to load the bad candidate kernel again (causing a boot loop or permanent brick).
*   **Mitigation:** The plan must explicitly mandate that `GRUB_SAVEDEFAULT` is set to `false` or completely commented out in `/etc/default/grub`.

### Gap B: Disk Space Accumulation in `/var/lib/xpf/versions/`
Since `dpkg` does not manage `/var/lib/xpf/versions/<version>/`, successive upgrades will continuously write new directories here.
*   **The Hazard:** Without an automated pruning mechanism, the host’s `/var` partition can run out of disk space over multiple upgrade cycles.
*   **Mitigation:** Define a retention policy in `xpf-upgrade` (e.g., keep the current active version, the staged candidate version, and the immediate rollback version, then prune all others).

### Gap C: HA Session-Sync Protocol Backwards Compatibility
During a rolling HA upgrade, Node A runs N+1 and Node B runs N.
*   **The Hazard:** While §8 states that the HA protocol mismatch check blocks transfer readiness if there is an incompatibility, the plan does not define compatibility requirements for the session-sync protocol itself. If the sync protocol changes formatting in version N+1, Node A will be unable to synchronize states with Node B. This makes a rolling upgrade impossible without session drops.
*   **Mitigation:** Mandate that if the session-sync protocol changes, it must remain backwards-compatible for at least one release (N+1 must accept and parse version N sync frames) to allow transient rolling upgrades.

### Gap D: Test Plan Inaccuracy for HA Mismatch
In **§10 Test Plan (HA rolling upgrade)**, the text states:
> *"Negative: protocol-version mismatch between staged xpfd and the peer's running helper -> assert safe full-cycle fallback..."*
*   **The Hazard:** `xpfd` on Node A does not communicate with the helper on Node B. It communicates with its local helper, or with `xpfd` on Node B.
*   **Mitigation:** Clarify this test case to state either *"protocol-version mismatch between Node A's xpfd and Node B's xpfd"* (HA level) or *"protocol-version mismatch between local xpfd and local helper during hot-restart"* (M-mech-2 level).

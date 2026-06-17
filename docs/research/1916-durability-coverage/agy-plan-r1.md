I have conducted a hostile, code-grounded adversarial review of the design proposed in `docs/research/1916-durability-coverage/plan.md`.

Based on this analysis, the verdict is **`PLAN-NEEDS-REVISION`**. Below are the concrete, high-confidence structural findings, Counter-Examples, and recommendation points.

---

### Verdict: PLAN-NEEDS-REVISION

---

### Finding 1: Transient/Durable Root Ownership Lockout on `authorized_keys`
* **Severity:** High (Security Posture and Availability defect)
* **File & Line Reference:** [pkg/daemon/daemon_system.go:724-730](file:///home/ps/git/bpfrx/pkg/daemon/daemon_system.go#L724-L730), [pkg/daemon/daemon_system.go:899-902](file:///home/ps/git/bpfrx/pkg/daemon/daemon_system.go#L899-L902), [pkg/fsatomic/fsatomic.go:208-291](file:///home/ps/git/bpfrx/pkg/fsatomic/fsatomic.go#L208-L291)

#### Analysis
The plan proposes migrating the user and root SSH `authorized_keys` updates to use `fsatomic.WriteFileDurable`. 
`WriteFileDurable` works by creating a new temporary file in the target directory (e.g. `/home/<user>/.ssh/.authorized_keys.tmp-xxxxx` or `/root/.ssh/.authorized_keys.tmp-xxxxx`), writing data to it, setting permissions (`0600`), performing `fsync`, and then executing `rename` to overwrite the target path.

Because the daemon runs as `root`, the temporary file is created with `root:root` ownership. The `rename(2)` system call preserves this ownership. Therefore, immediately after the rename, `/home/<user>/.ssh/authorized_keys` is owned by `root:root`.

The daemon subsequently runs an asynchronous or synchronous `chown -R` command to fix the directory and file ownership back to `<user>:<user>` (line 730). This introduces two critical vulnerabilities:

1. **Transient Lockout Window**: In modern SSH (such as OpenSSH), when `StrictModes yes` is active (the default), `sshd` drops privileges to the target user before opening and reading `authorized_keys`. During the window between `rename` and the completion of `chown -R`, the file `/home/<user>/.ssh/authorized_keys` is owned by `root` with `0600` permissions. If an SSH connection attempt occurs in this window, the unprivileged `sshd` child will receive `EACCES` (Permission Denied), causing the authentication attempt to fail.
2. **Durable Lockout Window (Crash Hole)**: If a power cut, kernel panic, or daemon crash occurs after `WriteFileDurable` successfully flushes and renames the file, but *before* the `chown -R` is executed or completed, the file is durably written to the filesystem as `root:root`. On the next boot, the user will be completely locked out of SSH access until the daemon starts and runs a new configuration reconcile pass (or permanently if the boot-loop is caused by the daemon itself).

#### Recommendation
We cannot rely on a post-write `chown -R`. The filesystem writes should set correct ownership *prior* to namespace exposure. Since `fsatomic` currently only has `WithPreserveExisting()`, which behaves as a no-op on first-write when no existing target is found, `fsatomic` needs to be extended to support a `WithOwnership(uid, gid)` option that executes `fchown` on the open temp file descriptor prior to closing and renaming it. The plan must specify this helper extension.

---

### Finding 2: AST Canary Path A Will Fail on Missed `os.WriteFile` Calls
* **Severity:** Medium (Build Break / Coverage Gap)
* **File & Line Reference:** [pkg/dataplane/compiler_iface.go:139](file:///home/ps/git/bpfrx/pkg/dataplane/compiler_iface.go#L139), [pkg/dataplane/userspace/process.go:160](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/process.go#L160), [pkg/dataplane/compiler.go:1484-1500](file:///home/ps/git/bpfrx/pkg/dataplane/compiler.go#L1484-L1500), [pkg/ra/sender.go:389-395](file:///home/ps/git/bpfrx/pkg/ra/sender.go#L389-L395)

#### Analysis
The plan proposes Decision D1 -> Path A (writer-class repo-wide scanner), which walks all production Go source code under `pkg/` (and optionally `cmd/`) to verify that no direct `os.WriteFile` selectors are called unless they are explicitly allowlisted in `allowedFunctions`.

However, the plan's list of `BestEffortKernelKnob` functions in §2 and Step 5 ONLY enumerates functions within `pkg/daemon` (specifically `applyKernelTuning` and other procfs tunables in daemon). It completely misses several legitimate `BestEffortKernelKnob` procfs/sysfs writers located in other packages:
1. `pkg/dataplane/compiler_iface.go:139` inside `createVLANSubInterface` (disabling `accept_ra`).
2. `pkg/dataplane/userspace/process.go:160` inside `tuneSocketBuffers` (rmem/wmem socket buffers tuning).
3. `pkg/dataplane/compiler.go:1484, 1487, 1493, 1500` inside `CompileResult.tuneInterfaceBuffers` (RPS/XPS configurations: `rps_sock_flow_entries`, `rps_cpus`, `rps_flow_cnt`, `xps_cpus`).
4. `pkg/ra/sender.go:389, 395` inside `ensureLinkLocal` (disabling `accept_dad`, configuring `addr_gen_mode`).

If Path A is implemented as currently planned, the AST canary test will fail the build immediately because these production `os.WriteFile` calls are not migrated and are not allowlisted.

#### Recommendation
The plan must explicitly enumerate these functions (`createVLANSubInterface`, `tuneSocketBuffers`, `CompileResult.tuneInterfaceBuffers`, and `ensureLinkLocal`) as `BestEffortKernelKnob` writers and seed them in the new canary test's allowlist.

---

### Finding 3: Misclassification of Timezone Persistence (`/etc/timezone`)
* **Severity:** Low (Performance/Complexity overhead)
* **File & Line Reference:** [pkg/daemon/daemon_system.go:510](file:///home/ps/git/bpfrx/pkg/daemon/daemon_system.go#L510), [docs/engineering-style.md:268-270](file:///home/ps/git/bpfrx/docs/engineering-style.md#L268-L270)

#### Analysis
The plan proposes classifying `/etc/timezone` as `DurableState` (`fsatomic.WriteFileDurable`), paying the price of an `fsync` of the file and the parent directory `/etc`.
However:
1. The timezone configuration is fully derived from `cfg.System.TimeZone` which is already stored in `.configdb` (the source of truth, which is durable). If `/etc/timezone` is lost during a power cut, it will be automatically regenerated on the next boot when the daemon reconciles the configuration.
2. The actual timezone setup is paired with the symlink `/etc/localtime` (line 504), which is updated using raw `os.Remove` and `os.Symlink` without any durability or fsync.

Classifying `/etc/timezone` as `DurableState` is a misclassification under `docs/engineering-style.md` §"Persistence classes". Paying the cost of fsyncing `/etc` on timezone changes is not justified when the main linkage `/etc/localtime` is not sync'd, and the state is fully regenerable on boot.

#### Recommendation
Reclassify `/etc/timezone` as `AtomicGeneratedConfig` (`fsatomic.WriteFileAtomic`), matching its companion system configurations.

---

### Finding 4: Mismatch Window Order Invariant Over-Claim (TLS Generation)
* **Severity:** Low (Incorrect assertion in design rationale)
* **File & Line Reference:** [pkg/api/server.go:327](file:///home/ps/git/bpfrx/pkg/api/server.go#L327), [pkg/api/server.go:363-366](file:///home/ps/git/bpfrx/pkg/api/server.go#L363-L366)

#### Analysis
In §5 Step 1, the plan claims:
> "writing the key first ... then the cert ... means a crash between them leaves key-without-cert, which tls.LoadX509KeyPair rejects -> clean regen, no mismatch. Rationale for order: a half-written pair is the bad state; by making each file individually atomic (temp+rename) AND ordering them, the only crash-visible states are {neither}, {key only}, {both matching} — never {mismatched cert+key}."

This is an over-claim. If a previous valid matching pair (`Cert-A`, `Key-A`) exists on disk, and a regeneration event is triggered (for instance, if loading fails due to file corruption or manual modification of one of the files), the daemon will write `Key-B` first. 
If the daemon crashes *after* `Key-B` is written but *before* `Cert-B` is written, the files on disk will be:
- `cert.pem` containing `Cert-A` (old)
- `key.pem` containing `Key-B` (new)

This is a **mismatched cert+key pair**. The assertion that the mismatch state is "never" crash-visible is false.
However, `tls.LoadX509KeyPair` *does* verify if the public key of the private key matches the public key in the certificate and returns an error on mismatch, which ensures the system still self-heals by running regeneration again on next boot. 

#### Recommendation
Update the design commentary to acknowledge that a mismatched pair is still transiently crash-visible on disk when replacing an existing pair, but clarify that self-healing is guaranteed by `tls.LoadX509KeyPair`'s internal validation.

---

### Finding 5: Unjustified Waiver of `make test-failover`
* **Severity:** Medium (Operational Validation Defect)
* **File & Line Reference:** [pkg/daemon/daemon_reth.go:26](file:///home/ps/git/bpfrx/pkg/daemon/daemon_reth.go#L26), [docs/engineering-style.md:102](file:///home/ps/git/bpfrx/docs/engineering-style.md#L102)

#### Analysis
The plan states in §8:
> "No failover test required — nothing here touches cluster/VRRP/ session-sync/failover code paths ... waiving the make test-failover gate is consciously waived as not-applicable."

This is incorrect. The plan proposes migrating `daemon_reth.go:26` (`fixRethLinkFile`) to `fsatomic.WriteFileAtomic`. 
`fixRethLinkFile` manages the `.link` configurations for Redundant Ethernet (RETH) member interfaces. RETH interfaces are the core physical and virtual link redundancy mechanism used in HA clustering and VRRP failover in this codebase. If there is a regression in how `.link` files are written, rewritten, or parsed (which can prevent networkd from mapping link names correctly on reboot or state change), the RETH interface will fail to converge. 

Since RETH interfaces are the direct transport for HA session sync and VRRP check-heartbeats, a regression here directly compromises cluster failover. Waiving the HA/failover tests is therefore not justified.

#### Recommendation
Remove the waiver. The validation plan must include running `make test-failover` to prove that the `.link` file migration does not regress clustering/failover capabilities.

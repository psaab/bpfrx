# Verdict: PLAN-NEEDS-REVISION

We have performed a hostile design review of `docs/research/1916-durability-coverage/plan.md` (revision r2) in the worktree `/home/ps/git/bpfrx/.claude/worktrees/1916-research-durability-coverage`. While r2 represents a substantial hardening step over r1, we have identified key operational loopholes and code consistency risks that must be resolved before implementation.

---

## 1. SSH Authorized Keys Ownership (`WithOwner` implementation)

**Status:** Resolved in Principle (requires minor implementation refinement in Step 0).

- **Correctness and Sufficiency:** The proposed `fsatomic.WithOwner(uid, gid)` option is correct and sufficient. Setting the owner on the open temporary file descriptor using `fchown` (reusing the `chownTemp` test seam) BEFORE the rename ensures that the file is written to the destination namespace with the correct owner and permissions atomically. This completely avoids the post-rename `chown` race and is correct for both first-write (no existing file) and re-write scenarios.
- **Seam Compatibility:** The current `chownTemp` seam in `pkg/fsatomic/fsatomic.go:87` has the signature `func(f *os.File, uid, gid int) error`. This perfectly supports calling `chownTemp(tmp, uid, gid)` on the active file descriptor prior to close/rename.

> [!CAUTION]
> Avoid importing standard library `"os/user"` to resolve the UID/GID (see Section 6 for details on maintaining the codebase's CGO-free passwd parsing approach).

---

## 2. AST Canary & `os.WriteFile` Inventory Exhaustiveness

**Status:** Resolved with minor omissions (missing `/etc/timezone` in table).

- **Inventory Verification:** We executed a comprehensive `git grep -n "os.WriteFile" -- '*.go' ':!*_test.go'` across the codebase. The results match the plan's list in §2.C and §2.D exactly.
- **Refactoring Verification:**
  - `pkg/daemon/daemon_apply.go` contains exactly three `os.WriteFile` calls at lines 646, 652, and 701. Extracting these into `setRethIPv6Knobs` and `setVLANSubAddrGenMode` will completely clear `applyConfigLocked` of direct `os.WriteFile` calls.
  - `pkg/daemon/daemon_ipmon.go` contains exactly one `os.WriteFile` call at line 180. Extracting it to `setFibMultipathHashPolicy` will leave `applyFRRConfig` with no direct `os.WriteFile` calls.
  - This ensures no false-negative bypass hole exists for those large functions.
- **Omission in Inventory Table:** `/etc/timezone` (`pkg/daemon/daemon_system.go:510`) is scheduled for migration to `WriteFileAtomic` in §5 Step 2b, but it is **missing** from the inventory tables in §2.B. The author must add it to the table for completeness.

---

## 3. Timezone Consistency and Crash Recovery Loophole

**Status:** UNRESOLVED / UNSOUND (presents a persistent out-of-sync state).

While classifying `/etc/timezone` as `AtomicGeneratedConfig` is correct, the proposed sequence is **unsound** due to a crash recovery loophole in the early-return logic of `applyTimezone` in `pkg/daemon/daemon_system.go`:

```go
func (d *Daemon) applyTimezone(cfg *config.Config) {
    ...
    current, _ := os.Readlink("/etc/localtime")
    target := "/usr/share/zoneinfo/" + cfg.System.TimeZone
    if current == target {
        return // Early return
    }
    ...
    os.Remove("/etc/localtime")
    os.Symlink(target, "/etc/localtime")
    os.WriteFile("/etc/timezone", []byte(cfg.System.TimeZone+"\n"), 0644)
}
```

### The Loophole
1. A timezone change is triggered.
2. The daemon deletes and updates the `/etc/localtime` symlink.
3. A power cut occurs immediately after the symlink is updated, but **before** `/etc/timezone` is written (or before the write is flushed to disk).
4. On reboot, the daemon parses config and invokes `applyTimezone`.
5. The daemon reads the symlink: `current` matches `target` (since `/etc/localtime` was successfully updated before the crash).
6. The function **returns early** (lines 492-494).
7. `/etc/timezone` is **never updated**, leaving the system with a mismatched/stale timezone configuration indefinitely until the next time the timezone configuration is changed by the operator.

### Required Resolution
The plan must modify the early return condition to verify both the symlink target AND `/etc/timezone` content. For example:
```go
current, _ := os.Readlink("/etc/localtime")
target := "/usr/share/zoneinfo/" + cfg.System.TimeZone
tzContent, _ := os.ReadFile("/etc/timezone")
expectedTzContent := cfg.System.TimeZone + "\n"

if current == target && string(tzContent) == expectedTzContent {
    return
}
```
Alternatively, reversing the order of updates (writing `/etc/timezone` first, then updating `/etc/localtime` symlink) would also allow the system to self-heal on the next boot. Checking both is the most robust solution.

---

## 4. TLS Cert/Key Ordered Write & Crash Window

**Status:** Resolved.

- **Mismatched-Pair Prevention:** By deleting both the cert and the key first, performing a `SyncDir` on the directory, and then writing the key (durable) and cert (atomic) in order, r2 successfully eliminates the risk of an on-disk mismatch between a stale cert/key and a newly generated key/cert.
- **Residual Window:** If a crash happens after the key is written but before the cert is written, only the key exists on disk. On the subsequent boot, `tls.LoadX509KeyPair` fails because the cert is missing, which triggers another regeneration cycle and a clean delete-then-write sequence.
- **Implementation Precaution:** The implementation of the write sequence must abort early if any step in the sequence fails. If the deletion, the directory sync, or the key write returns an error, the daemon must log it and immediately return the in-memory key pair, **skipping the subsequent file writes** to prevent writing a partial/mismatched set of files to disk.

---

## 5. Failover / HA Validation

**Status:** Resolved.

- **Adequacy:** Running `make test-failover` and `make test-ha-crash` is adequate and correct. Since RETH member interface configuration and naming properties (`.link` files) are cluster-adjacent and trigger during HA transitions, integration validation of the failover suite is required.

---

## 6. New Problems & Style Risks Introduced in r2

We identified the following new issues introduced in r2:

### A. CGO-free Style Guideline Risk via `os/user`
- **Issue:** §4 D7-a proposes: *"Resolve `uid/gid` via `user.Lookup(user.Name)` once."*
- **Risk:** The codebase deliberately avoids importing Go's standard library `"os/user"` (which can pull in CGO/nsswitch dynamically-linked dependencies) and instead implements a cgo-free custom parser `lookupUID` in [login_password.go](file:///home/ps/git/bpfrx/.claude/worktrees/1916-research-durability-coverage/pkg/daemon/login_password.go#L115-L137) that parses `/etc/passwd` directly. Introducing `"os/user"` violates this design pattern and could break static binary constraints.
- **Resolution:** The plan must be revised to extend the custom `/etc/passwd` parser in `login_password.go` to return both UID and GID (index 2 and 3 of `/etc/passwd` fields) rather than introducing `"os/user"`.

### B. AST Canary Method-Receiver Mapping Discrepancy
- **Issue:** In Step 6, the allowed functions list keys on receiver-bound methods such as `daemon::(realHostTunableFS).writeFile`.
- **Risk:** The current AST canary only retrieves the bare method name `fn.Name.Name` (which is `"writeFile"`). Without modifying the AST parser to format the receiver, keys containing `(realHostTunableFS).writeFile` will fail to match, causing false positive canary errors.
- **Resolution:** The plan should clarify if the canary is to be extended with AST receiver-formatting helper code, or if allowed functions should be keyed simply by `<pkg-relpath>::<funcName>` (e.g. `daemon::writeFile`) since function/method names are currently unique within their packages anyway.

PLAN-NEEDS-REVISION

## Findings

### [HIGH] TLS ordering claim is false when stale cert material already exists

Plan section: §5 "Step 1 — TLS persistence (`pkg/api/server.go`)".

Quoted line: "the only crash-visible states are {neither}, {key only}, {both matching} — never {mismatched cert+key}."

Plan section: §7 "Risks & mitigations".

Quoted line: "Intentional: `tls.LoadX509KeyPair` fails on key-only → clean regen. The eliminated state is *mismatched pair*"

`tls.LoadX509KeyPair` does reject true key-only cleanly: Go 1.24 reads `certFile` first and returns the read error before looking at the key. That does not rescue the proposed order. Counter-example: disk starts with a stale cert-only file from the current bug, or with an already-mismatched pair. The regen path writes the new key first; until the cert rename happens, disk contains stale cert + new key. A crash there leaves exactly the mismatched pair the plan claims is impossible.

Fix shape: either weaken the claim to "only avoids mismatch from a clean no-existing-pair state" or actually eliminate stale cert before key promotion. A real fix needs a durable unlink/dir-sync of `certPath` before durable key replacement, then cert write, or a single-versioned bundle/pointer design. Add tests for stale-cert-only and stale-mismatched starting states with injected failure after key write.

### [HIGH] TLS cert is misclassified if cert stability is a requirement

Plan section: §2 "`pkg/api/server.go`".

Quoted line: "`/etc/xpf/tls/<cert>` (`certPath`) | **AtomicGeneratedConfig** | Regenerable (self-signed, regenerated if load fails). Torn cert unacceptable; lost-on-power-cut acceptable"

Plan section: §1 "Problem statement".

Quoted line: "cert churn → clients that pinned the previous self-signed cert break"

Those two statements cannot both be true. `WriteFileAtomic` explicitly allows the cert update to vanish after power loss. If the key survives but the cert does not, the next boot regenerates a new cert and breaks cert-pinning clients, which §1 names as the operator-visible harm.

Fix shape: classify both cert and key as `DurableState` if pinned self-signed cert stability matters. If the product position is that cert loss after power loss is acceptable, delete the cert-pinning harm from the problem statement and validation criteria. Do not call the cert both "acceptable to lose" and "operator-stable."

### [HIGH] authorized_keys ownership handling is not safe enough for inode replacement

Plan section: §5 "Step 2 — `pkg/daemon/daemon_system.go` migrations".

Quoted line: "The existing `chown -R` after the write still fixes ownership, so behavior is preserved"

Plan section: §7 "Risks & mitigations".

Quoted line: "`WriteFileDurable` replaces the inode (root-owned temp); user can't read own keys. | Keep the existing `chown -R user:user sshDir` after the write (preserved)."

This is not behavior-preserving. Existing `os.WriteFile` over an existing user-owned `authorized_keys` preserves the inode owner. `WriteFileDurable` replaces it with a root-owned temp. If the post-rename `chown -R` fails or is delayed, an existing good user-owned file has been replaced by root-owned `0600` content. That is an ownership regression precisely in the management-access file the plan is trying to harden; the plan cannot hand-wave it as "fixed after" when the failure happens after the old inode is gone.

Fix shape: set final ownership before rename, not after. Either add/use an fsatomic owner option that `fchown`s the temp fd before rename, or preserve existing owner with `WithPreserveExisting()` and separately solve first-write ownership before exposing the file. The plan also needs validation that checks `stat` owner/mode on `/home/<user>/.ssh`, `/home/<user>/.ssh/authorized_keys`, and root's file, not only "ssh works once."

### [HIGH] Path A canary inventory is incomplete and one proposed allowlist entry would be dangerously broad

Plan section: §4 "Decision D1 — Canary scope model".

Quoted line: "scan of **all** production `.go` under `pkg/` ... flagging every direct `os.WriteFile` EXCEPT functions named in `allowedFunctions`"

Plan section: §5 "Step 5 — BestEffortKernelKnob allowlist seeding".

Quoted line: "Add to `allowedFunctions` ... `applyKernelTuning`, the RETH procfs writers in `daemon_apply.go` (their enclosing function — likely `applyClusterReth` or similar; **confirm enclosing func name in impl**)"

`rg -n "os\\.WriteFile" pkg --glob '*.go' --glob '!**/*_test.go'` shows legitimate procfs/sysfs writers outside the plan's inventory:

- `pkg/ra/sender.go::ensureLinkLocal` writes `addr_gen_mode` and `accept_dad`.
- `pkg/dataplane/compiler.go::tuneInterfaceBuffers` writes RPS/RFS/XPS procfs/sysfs knobs.
- `pkg/dataplane/compiler_iface.go::ensureVLANSubInterface` writes `accept_ra`.
- `pkg/dataplane/userspace/process.go::tuneSocketBuffers` writes socket buffer sysctls.
- `pkg/networkd/networkd.go::restoreSlowPathRPFilter` must remain explicitly carried into the new relpath key.

Also, the daemon RETH writes are not in a small `applyClusterReth` function; they are inside `applyConfigLocked`, a giant apply function. Allowlisting `pkg/daemon/daemon_apply.go::applyConfigLocked` would create a huge false-negative hole: any future durable writer added anywhere in that function would bypass the canary.

Fix shape: make the plan's allowlist table exhaustive from the grep above, and refactor the three `daemon_apply.go` procfs writes into tiny helpers before allowlisting. The DNS fallback-helper recommendation is the right pattern; apply the same discipline to RETH procfs writes.

### [MEDIUM] The sshd and timezone persistence classifications are internally inconsistent/incomplete

Plan section: §2 "`pkg/daemon/daemon_system.go`".

Quoted line: "`/etc/ssh/sshd_config.d/xpf.conf` | **AtomicGeneratedConfig** | Regenerated from config; reload sshd after."

Plan section: §4 "Decision D2 — sshd drop-in class".

Quoted line: "**Recommendation: C-durable for sshd drop-in.**"

Plan section: §5 "Step 2 — `pkg/daemon/daemon_system.go` migrations".

Quoted line: "Per D2 recommendation, sshd drop-in (844) → `WriteFileDurable`."

The plan has two different classes for the same file. That is not a reviewer decision left open in one place; it is an implementation ambiguity. Fix shape: settle D2 in the plan revision and make §2, §5, docs, and tests say the same class.

Plan section: §2 "`pkg/daemon/daemon_system.go`".

Quoted line: "`/etc/timezone` | **DurableState** | Identity-ish; paired with `/etc/localtime` symlink."

If timezone is DurableState because the timezone identity must survive power loss, then the paired `/etc/localtime` symlink update is part of the same state. Current code does `os.Remove("/etc/localtime")` then `os.Symlink(...)` with no atomic replacement and no directory sync. Making only `/etc/timezone` durable can still leave `/etc/localtime` missing or stale after a crash.

Fix shape: either include durable symlink replacement + parent-dir sync for `/etc/localtime`, or demote `/etc/timezone` to generated/apply-time state and stop claiming DurableState semantics for the pair.

### [MEDIUM] The failover waiver is not justified by the touched files

Plan section: §8 "Validation plan".

Quoted line: "**No failover test required** — nothing here touches cluster/VRRP/session-sync/failover code paths"

Plan section: §6 "Files touched (estimate)".

Quoted line: "`pkg/daemon/daemon_reth.go`, `linksetup.go`, `bootstrap.go`, `login_password.go` — Step 3."

That waiver is false as written. `fixRethLinkFile` is called from the cluster RETH path inside `applyConfigLocked` when `cfg.Chassis.Cluster != nil`, and the `.link` files determine post-reboot interface naming for RETH members. `linksetup.go` also has cluster-mode naming behavior. This is not session-sync code, but it is HA/cluster convergence surface.

Fix shape: either run `make test-failover`/`make test-ha-crash`, or narrow the plan so RETH/linksetup/bootstrap network files are not changed in this PR. If the team still waives failover, the waiver must say "we touched cluster-adjacent RETH boot naming, but validated it with X instead" rather than claiming no cluster path is touched.

### [MEDIUM] DNS B-route is directionally right but underspecified enough to regress bind mounts

Plan section: §5 "Step 4 — `pkg/daemon/daemon_dns.go` (D3 = B-route)".

Quoted line: "Replace `atomicWrite`'s temp+rename happy path with `fsatomic.WriteFileAtomic(r.resolvConfPath, []byte(content), 0644)`."

Quoted line: "Keep the EXDEV/EBUSY in-place fallback as the **only** direct `os.WriteFile`"

This preserves semantics only if the implementation checks `isCrossDeviceOrBusy(err)` on the error returned by `fsatomic.WriteFileAtomic` and then runs the in-place fallback. A naive route-through implementation that simply returns the fsatomic error breaks the current bind-mounted `/etc/resolv.conf` case. Also do not pass `WithResolveSymlinks`; current DNS behavior intentionally renames over the symlink itself.

Fix shape:

```go
err := fsatomic.WriteFileAtomic(r.resolvConfPath, []byte(content), 0644)
if err == nil {
    return nil
}
if isCrossDeviceOrBusy(err) {
    slog.Warn("DNS: rename onto /etc/resolv.conf failed (likely bind mount); writing in place", "err", err)
    return writeResolvConfBindMountFallback(r.resolvConfPath, content)
}
return err
```

`errors.Is` should still work through fsatomic's `%w` wrapping; make that explicit and test the fallback.

## Bottom line

Do not implement r1 as written. The plan is salvageable, but it overclaims TLS safety, under-specifies ownership-preserving writes, misses repo-wide canary entries, and waives HA validation on files that do feed cluster/RETH boot behavior.

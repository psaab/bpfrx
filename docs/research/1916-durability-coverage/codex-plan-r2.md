PLAN-NEEDS-REVISION

## Findings

### [HIGH] D5 still does not specify a safe unlink contract before key promotion

Plan section: §4 D5.

Quoted line: "remove stale cert + key if present (best-effort `os.Remove`; then one `fsatomic.SyncDir(\"/etc/xpf/tls\")` to make the unlinks durable)"

Quoted line: "Claim in the plan is now: \"no crash-visible *mismatched* pair, given the stale-pair removal in step 2.\""

The ordering is correct only after the cert and key unlinks are known to have succeeded and the directory sync is known to have succeeded. The word "best-effort" destroys that invariant. Counter-example: a stale cert remains because `os.Remove(certPath)` returns a non-ENOENT error that is ignored; the plan then writes the new durable key; a crash before the cert write leaves stale-cert + new-key, exactly the mismatch D5 claims is gone.

Fix shape: spell out the unlink contract. Ignore only `os.IsNotExist`; on any other remove error, or on `SyncDir` error, do not write the new key or cert. Log/surface the persistence error and return the in-memory certificate. Add tests for remove failure and dir-sync failure before the key write. The current "remove stale pair + SyncDir, then key-durable, then cert-atomic" design eliminates the new mismatched-pair window only under that stricter contract.

### [HIGH] The supposedly exhaustive inventory still misses `/etc/timezone`

Plan section: §2.

Quoted line: "**This is the exhaustive inventory**"

Quoted line: "`grep -rn 'os\\.WriteFile' pkg/ --include= '*.go' | grep -v _test.go` (40 hits; the 3 in `pkg/fsatomic/fsatomic.go` are COMMENTS, not calls)"

`rg -n "os\\.WriteFile" pkg --glob '*.go' --glob '!**/*_test.go'` still shows `pkg/daemon/daemon_system.go:510: os.WriteFile("/etc/timezone", ...)`. It is not listed in §2.A, §2.B, §2.C, or §2.D. Step 2b later classifies it as AtomicGeneratedConfig, but the inventory table is still false and the class is absent from the canonical classification section.

Also, the hit accounting is still sloppy: the grep output has four non-call comment hits, not three (`pkg/frr/manager.go:502` plus the three fsatomic comments), leaving 36 real production calls. Fix shape: add `daemon/daemon_system.go:510 | applyTimezone | /etc/timezone` to §2.B as AtomicGeneratedConfig and correct the count.

### [MEDIUM] TLS "surface errors but still start HTTPS" is not wired through the caller

Plan section: §4 D5.

Quoted line: "on ANY error in 2-4: `slog.Error(...)` with path+err, still return the in-memory `tls.X509KeyPair(certPEM, keyPEM)` so the server starts."

Plan section: §5 Step 1.

Quoted line: "`generateSelfSignedCertAt(certPath, keyPath string) (tls.Certificate, error)`"

The plan adds an error-returning helper and says persistence errors should be surfaced while HTTPS still starts. Current `pkg/api/server.go` only configures `s.httpsServer` in the `else` branch when `generateSelfSignedCert()` returns nil error. Unless the plan explicitly changes the caller to use a non-zero cert even with a persistence error, the implementation can satisfy the helper tests while disabling HTTPS on disk-write failure.

Fix shape: add a Step 1 caller requirement: if certificate generation succeeds but persistence fails, log the persistence error and still install the returned cert in `TLSConfig`. Add a server-level test or explicit assertion for that behavior.

### [MEDIUM] D1 is still not settled for method allowlist keys

Plan section: §4 D1.

Quoted line: "Path A (writer-class repo-wide scanner), keyed by `relpath::funcName`. SETTLED."

Plan section: §5 Step 6.

Quoted line: "Method receivers: the canary keys on `fn.Name.Name` today, which is the bare method name"

Plan section: §10.

Quoted line: "Canary method-receiver keying: confirm the AST keys method writers by bare method name under `relpath::`; if collisions remain, key by `relpath::recv.method`."

This is not settled. `relpath::funcName` fixes cross-package collisions, but it still allowlists every same-named method/function in the same package directory. The immediate risky entry is `daemon::writeFile` for `realHostTunableFS.writeFile`; a future `writeFile` in `pkg/daemon` would inherit the knob exemption. That is smaller than r1's package allowlist hole, but it is still a false-negative mechanism in the new canary.

Fix shape: settle this now as receiver-aware keys for methods, e.g. `daemon::realHostTunableFS.writeFile` and `dataplane::CompileResult.tuneInterfaceBuffers`, or file-relpath plus receiver plus function. Do not leave it as an implementation-time open question in a plan whose core deliverable is the canary policy.

### [LOW] `WithOwner` is correct for authorized_keys, but option precedence is unspecified

Plan section: §5 Step 0.

Quoted line: "Add `func WithOwner(uid, gid int) Option` + an `owner *ownerIDs` field on `options`; in `writeFile`, after `chmodTemp`, if `WithOwner` set, `chownTemp(tmp, uid, gid)` before the durable sync/close/rename."

I checked `pkg/fsatomic/fsatomic.go`: the existing `chownTemp` seam is in the right place, after `chmodTemp` and before sync/close/rename. Adding `WithOwner` there is sufficient for both first-write and re-write of user `authorized_keys`.

The remaining plan gap is interaction with `WithPreserveExisting`. Define precedence or reject the combination. The least surprising contract is: `WithPreserveExisting` may preserve mode, but explicit `WithOwner` wins ownership. This is not what blocks the plan by itself, but it should be nailed down while adding the option.

## Re-check of r1 findings

- TLS stale-pair ordering: improved, but not resolved until "best-effort remove" is replaced with a precise non-ENOENT/error-stop contract.
- TLS cert class vs pinning harm: resolved. D6 now consistently drops the pinning harm and keeps cert as AtomicGeneratedConfig.
- authorized_keys ownership: resolved in design. The `chownTemp` seam supports D7-a before rename.
- Path A inventory and applyConfigLocked hole: helper extraction is the right fix and the three helpers are the right ones, but the inventory is still not exhaustive because `/etc/timezone` is missing. The plan correctly keeps `applyConfigLocked` and `applyFRRConfig` out of the allowlist after extraction.
- sshd/timezone classes: sshd is now internally consistent. Timezone is consistently AtomicGeneratedConfig in Step 2b/§12/docs, but it is missing from §2's class table.
- failover waiver: resolved. D8 and §8 require `make test-failover` and `make test-ha-crash`.
- DNS B-route: resolved. The plan gives the correct error-routing shape, says not to use `WithResolveSymlinks`, and the current helper already uses `errors.Is`.

## Bottom line

r2 is close, but not ready. Fix the TLS unlink contract, put `/etc/timezone` into the actual exhaustive inventory, wire TLS persistence errors through the server caller without disabling HTTPS, and settle receiver-aware canary keys.

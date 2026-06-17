PLAN-NEEDS-REVISION

Review target: r3 `plan.md` as read from HEAD `25d79470c` at review start.
The worktree later showed an unowned r4 edit to `plan.md`; this file remains
the requested r3 review.

## Blocking finding

### MEDIUM: Step 2b can regress a correct `/etc/localtime` when only `/etc/timezone` is stale

Section: `plan.md` Section 5 Step 2b.

Quoted plan lines:
- `plan.md:402`: "Change the early-return guard to"
- `plan.md:403`: "require BOTH `/etc/localtime` target matches AND `/etc/timezone` content"
- `plan.md:404`: "matches before skipping; otherwise fall through and (re)write"
- `plan.md:405`: "`/etc/timezone`. (Leave the `os.Remove`+`os.Symlink` localtime logic"
- `plan.md:406`: "otherwise unchanged — out of scope.)"

Counterexample:
1. Crash-recovery state is exactly the one Step 2b is trying to repair:
   `/etc/localtime -> /usr/share/zoneinfo/America/Los_Angeles` is already correct,
   but `/etc/timezone` is missing or stale.
2. The revised guard does not return, because both values do not match.
3. Because the plan says to "fall through" and leave the existing localtime
   mutation logic unchanged, execution reaches the current code path:
   - `pkg/daemon/daemon_system.go:492`: `if current == target {`
   - `pkg/daemon/daemon_system.go:493`: `return`
   - `pkg/daemon/daemon_system.go:503`: `os.Remove("/etc/localtime")`
   - `pkg/daemon/daemon_system.go:504`: `if err := os.Symlink(target, "/etc/localtime"); err != nil {`
   - `pkg/daemon/daemon_system.go:510`: `os.WriteFile("/etc/timezone", []byte(cfg.System.TimeZone+"\n"), 0644)`
4. A crash or symlink failure after `os.Remove("/etc/localtime")` but before
   the `/etc/timezone` write turns a state with correct localtime plus stale
   timezone into a state with missing/broken localtime plus stale timezone.

Required revision:
Do not re-run the localtime remove/symlink sequence when `current == target`.
Split the cases:
- if localtime target matches and `/etc/timezone` content matches, return;
- if localtime target does not match, perform the existing remove/symlink path;
- always write `/etc/timezone` with `WriteFileAtomic` when its content does not
  match, including the case where localtime was already correct.

This preserves the AGY early-return fix without adding a new crash window to
the already-correct symlink case.

## R2 finding verification

### HIGH#1: resolved

D5 now has the strict unlink contract I asked for. Section `plan.md` Section 4 D5:
- `plan.md:251`: "ignore ONLY `os.IsNotExist`; on ANY other remove error OR on `SyncDir`"
- `plan.md:252`: "error, do NOT proceed to write the new key/cert"
- `plan.md:256`: "`os.Remove(certPath)` then `os.Remove(keyPath)`: `os.IsNotExist` ="
- `plan.md:257`: "success; ANY other error -> abort to step 5 (do NOT write). Then"
- `plan.md:258`: "`fsatomic.SyncDir(\"/etc/xpf/tls\")`; on error -> abort to step 5."

That is sufficient to prove the clean `{neither}` start for the subsequent
key/cert writes: writes only begin after both stale paths were removed and the
directory unlink state was synced. On remove/sync failure, the helper may still
serve the in-memory cert, but it does not create the stale-cert/new-key mismatch
window.

### HIGH#2: resolved

`/etc/timezone` is now present in Section 2.B:
- `plan.md:111`: "`daemon/daemon_system.go:510` | `applyTimezone` | `/etc/timezone`"

I re-ran:

```text
rg --stats --glob '*.go' --glob '!**/*_test.go' "os\.WriteFile" pkg
```

The scan reports 40 production `.go` matches. Four are comment-only hits
(`pkg/frr/manager.go:502` and three in `pkg/fsatomic/fsatomic.go`), leaving 36
real production calls, matching the plan's corrected accounting at:
- `plan.md:89`: "(40 hits total; **4 are non-call comment hits**"
- `plan.md:90`: "plus the 3 in `pkg/fsatomic/fsatomic.go` — leaving **36 real production"

No generated `.pb.go` file contains a real `os.WriteFile` hit.

### MED#1: resolved

D5 and Step 1 now define the nil-error contract needed by the existing caller:
- `plan.md:263`: "Error handling + caller wiring (Codex r2 MED#1)."
- `plan.md:265`: "in-memory `tls.X509KeyPair(certPEM, keyPEM)` with a **nil** error for"
- `plan.md:267`: "failed). A non-nil error is returned ONLY for a true *generation*"
- `plan.md:381`: "confirm `pkg/api/server.go:264-277`"
- `plan.md:383`: "nil-error-on-persistence-failure contract the existing `else` branch is"

That is coherent with current `pkg/api/server.go`:
- `pkg/api/server.go:264`: `if cfg.TLS && cfg.HTTPSAddr != "" {`
- `pkg/api/server.go:265`: `tlsCert, err := generateSelfSignedCert()`
- `pkg/api/server.go:266`: `if err != nil {`
- `pkg/api/server.go:268`: `} else {`
- `pkg/api/server.go:269`: `s.httpsServer = &http.Server{`

If persistence failure returns a usable cert with nil error, the existing
else-branch installs `httpsServer`. HTTPS is not disabled by disk persistence
failure.

### MED#2: resolved

D1 and Step 6 now make allowlist keys receiver-aware:
- `plan.md:187`: "a `*ast.FuncDecl` with a non-nil `Recv`"
- `plan.md:188`: "is keyed `relpath::RecvType.MethodName` (strip a leading `*`)"
- `plan.md:433`: "Extend the AST keyer to be receiver-aware"
- `plan.md:435`: "`<pkg-relpath>::<RecvType>.<MethodName>`"
- `plan.md:447`: "(Receiver-aware keying closes the residual same-package-same-name hole"

This closes the same-package same-name hole. The concrete receiver cases in
the current allowlist are implementable with a small AST type formatter:
- `pkg/dataplane/compiler.go:1444`: `func (r *CompileResult) tuneInterfaceBuffers(link netlink.Link) {`
- `pkg/daemon/host_tunables.go:81`: `func (realHostTunableFS) writeFile(path string, data []byte) error {`

A future `pkg/daemon` plain `writeFile` or a method on another receiver would
not inherit `daemon::realHostTunableFS.writeFile`'s exemption.

### LOW: resolved

`WithOwner` precedence is now explicit:
- `plan.md:320`: "`WithOwner` vs `WithPreserveExisting` precedence (Codex r2 LOW)."
- `plan.md:321`: "Define: `WithPreserveExisting` may lift mode from an existing target,"
- `plan.md:322`: "but an explicit `WithOwner` always WINS ownership"
- `plan.md:323`: "If both are passed, owner = `WithOwner`'s, mode"
- `plan.md:324`: "= preserved-existing's. Unit-test this precedence."

That is implementable against current `pkg/fsatomic/fsatomic.go`: mode and
owner are already separate pre-rename fd operations (`chmodTemp`, `chownTemp`).

## New r3 change review

### D6 cert = DurableState: accepted

D6 reverses r2 on real code evidence:
- `plan.md:283`: "D6 — TLS cert class = DurableState (r3 CORRECTION)."
- `plan.md:286`: "`pkg/daemon/daemon_run.go:1093-1099`: `system services web-management"
- `plan.md:287`: "https interface <if>` binds the HTTPS API to a **non-loopback** address"
- `plan.md:289`: "remote TOFU pins / triggers browser warnings — a real regression."
- `plan.md:290`: "BOTH cert and key are DurableState"

The code supports the premise:
- `pkg/daemon/daemon_run.go:1093`: `httpsBindIP := "127.0.0.1"`
- `pkg/daemon/daemon_run.go:1094`: `if wm.HTTPSInterface != "" {`
- `pkg/daemon/daemon_run.go:1095`: `httpsBindIP = resolveInterfaceAddr(wm.HTTPSInterface, "127.0.0.1")`
- `pkg/daemon/daemon_run.go:1099`: `apiCfg.HTTPSAddr = httpsBindIP + ":8443"`

I accept cert as DurableState.

### Step 2b timezone: not accepted as written

See blocking finding above. The classification of `/etc/timezone` as
AtomicGeneratedConfig is fine; the control flow around an already-correct
`/etc/localtime` is not.

### Step 0b cgo-free lookupUIDGID: accepted

The plan keeps the repo's existing parser style:
- `plan.md:365`: "Step 0b — cgo-free uid/gid resolver"
- `plan.md:367`: "`lookupUIDGID(name) (uid, gid int, ok bool)`"
- `plan.md:368`: "`/etc/passwd` fields 2 (uid) and 3 (gid) in the same scan."
- `plan.md:369`: "Do NOT introduce `os/user`"

That matches `/etc/passwd` zero-based field positions and current code:
- `pkg/daemon/login_password.go:124`: `fields := strings.Split(line, ":")`
- `pkg/daemon/login_password.go:125`: `if len(fields) < 3 {`
- `pkg/daemon/login_password.go:129`: `uid, err := strconv.Atoi(fields[2])`

Extending this to require `len(fields) >= 4` and parse `fields[3]` for the
primary GID is correct and avoids `os/user`.

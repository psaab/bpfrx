# Verdict: PLAN-READY

We have performed a hostile design review of `docs/research/1916-durability-coverage/plan.md` (revision r3) in the worktree `/home/ps/git/bpfrx/.claude/worktrees/1916-research-durability-coverage`.

Revision r3 successfully addresses all previously identified findings from r2. The newly introduced design modifications—specifically, the classification of the TLS certificate as `DurableState`, the implementation of a strict unlink-and-sync contract prior to writing the keys, and the error-routing caller wiring—are operationally sound and crash-safe.

---

## 1. Resolution of r2 Findings

### Finding 1: Timezone Early-Return Crash Loophole (Step 2b)
- **Status:** **Resolved.**
- **Verification:** In the previous code ([pkg/daemon/daemon_system.go:490-494](file:///home/ps/git/bpfrx/.claude/worktrees/1916-research-durability-coverage/pkg/daemon/daemon_system.go#L490-L494)), `applyTimezone` returned early based solely on whether `/etc/localtime`'s target matched:
  ```go
  current, _ := os.Readlink("/etc/localtime")
  target := "/usr/share/zoneinfo/" + cfg.System.TimeZone
  if current == target {
      return
  }
  ```
  This allowed a crash between the symlink update and the writing of `/etc/timezone` to permanently leave `/etc/timezone` missing or stale.
- **r3 Design:** Step 2b changes the early-return guard to require *both* the `/etc/localtime` target link *and* the contents of `/etc/timezone` to match. If a crash leaves `/etc/timezone` missing or stale, the mismatch will trigger a fall-through on the next boot to rewrite both files. This successfully closes the crash loophole.

### Finding 2: CGO-Free UID/GID Resolution (Step 0b)
- **Status:** **Resolved.**
- **Verification:** In `pkg/daemon/login_password.go:115-137`, `/etc/passwd` is parsed directly via `lookupUID` to avoid importing `"os/user"` (which pulls in CGO/nsswitch dependencies).
- **GID Column Verification:** In a standard `/etc/passwd` file, the columns are colon-separated:
  `name : password : UID : GID : GECOS : directory : shell`
  Under the 0-indexed split `fields := strings.Split(line, ":")` at [login_password.go:124](file:///home/ps/git/bpfrx/.claude/worktrees/1916-research-durability-coverage/pkg/daemon/login_password.go#L124), the fields map to:
  - `fields[0]`: name
  - `fields[1]`: password (usually 'x')
  - `fields[2]`: UID
  - `fields[3]`: GID
  So GID is indeed at index/field `3` (the 4th column). Extending the parser to parse `strconv.Atoi(fields[3])` is correct and cgo-free.

### Finding 3: Canary Method-Receiver Keying (D1 / Step 6)
- **Status:** **Resolved.**
- **Verification:** Revision r3 settles the AST canary keying policy by extending the AST keyer to format the receiver type for methods (strip leading `*` from `fn.Recv.List[0].Type` and format as `relpath::RecvType.MethodName`), while plain functions remain `relpath::FuncName`.
- **Hole Closure:** This completely closes the same-package-same-name hole. In r2, allowlisting `daemon::writeFile` would have exempted both a method on a specific struct and any plain `writeFile` helper. Now, a struct-specific method like `realHostTunableFS.writeFile` is keyed uniquely as `daemon::realHostTunableFS.writeFile`, preventing other methods/functions in the same package from inheriting the exemption.

### Finding 4: Timezone Missing from Table
- **Status:** **Resolved.**
- **Verification:** `/etc/timezone` is now listed in the Section 2 Table B (AtomicGeneratedConfig) at line 111:
  `| daemon/daemon_system.go:510 | applyTimezone | /etc/timezone (Step 2b; early-return fix — AGY r2 #3) |`

---

## 2. Review of New r3 Changes & Invariants

### 5. D6 Reversal: Cert Classified as DurableState
- **Status:** **Accepted.**
- **Verification:** We verified `pkg/daemon/daemon_run.go:1093-1099`. When web-management is configured with an HTTPS interface (`wm.HTTPSInterface`), the bind IP is resolved via:
  ```go
  httpsBindIP = resolveInterfaceAddr(wm.HTTPSInterface, "127.0.0.1")
  ```
  This binds the HTTPS API to a non-loopback management address.
- **Pinning Stability:** Because the HTTPS API is exposed to remote management clients, a power loss that results in a lost or corrupted cert file would trigger a regeneration. The resulting new certificate will cause TOFU (Trust On First Use) warnings or client-side trust errors. Classifying both the certificate and key as `DurableState` (`fsatomic.WriteFileDurable`) ensures they are synced and survive power loss together. The performance overhead of one extra fsync during certificate regeneration is negligible since this only occurs upon initial setup or rare rotations.

### 6. D5 Strict Unlink Contract & the {neither} Start Invariant
- **Status:** **Accepted / Sound.**
- **Verification:** Step 2 of the D5 sequence is:
  > `os.Remove(certPath)` then `os.Remove(keyPath)`: `os.IsNotExist` = success; ANY other error → abort to step 5 (do NOT write). Then `fsatomic.SyncDir("/etc/xpf/tls")`; on error → abort to step 5.
- **Invariant Proof:** If `os.Remove` succeeds (or returns `ENOENT`) and `SyncDir` completes successfully, the physical removal of both files from the parent directory is durably committed. At this point, the on-disk state is provably `{neither}`.
- **Crash Safety:**
  - If a crash occurs *before* or *during* the unlinks, the system remains in its prior state (`{both-matching}` or whatever was pre-existing).
  - If a crash occurs *after* the unlinks are synced but *before* writing the key, the state is `{neither}`.
  - If a crash occurs *after* writing the key (durable) but *before* writing the cert, the state is `{key-only}`.
  - On the next boot, any state other than `{both-matching}` will cause `tls.LoadX509KeyPair` to fail, trigger a regeneration, and cleanly reset the sequence. No mismatched or torn key/cert state is ever loaded or exposed.
- **Hole Analysis:** There are no security or operational holes in this sequence. Read-only filesystem conditions will fail the `os.Remove` step with `EROFS` (or fail write steps), causing a clean abort without writing partial states.

### 7. D5 / Step 1 Caller Wiring & Error Handling
- **Status:** **Accepted / Sound.**
- **Verification:** `pkg/api/server.go:264-277` handles the server creation:
  ```go
  tlsCert, err := generateSelfSignedCert()
  if err != nil {
      slog.Warn("failed to generate self-signed certificate", "err", err)
  } else {
      s.httpsServer = &http.Server{ ... }
  }
  ```
  If a disk write fails, the strict D5 sequence aborts and returns the generated in-memory certificate with a `nil` error (only logging the persistence error). Because `err` is `nil`, the caller correctly falls into the `else` branch and configures the `httpsServer` using the in-memory key pair. This prevents a disk issue (e.g. read-only file system or disk full) from silently disabling HTTPS.

---

## 3. Conclusion

All findings from the previous round have been successfully integrated and resolved. The design is tight, correct, and ready for implementation.

# Plan of action — #1916: fsatomic durability coverage gap (canary scope + TLS persistence)

- **Issue**: #1916 — Durability coverage gap: fsatomic canary excludes
  `pkg/daemon` + `pkg/api`; TLS cert/key persisted non-atomically with
  ignored errors.
- **Revision**: r2 (addresses all r1 convergent findings: Claude SMR +
  Codex + AGY all PLAN-NEEDS-REVISION). Changelog at §12.
- **Branch**: `research/1916-durability-coverage`
- **Base**: `origin/master` @ `26e4a112d` (post-#1944 #1949 merge, post-#1950)
- **Scope class**: bug / durability hardening + test-coverage extension.
  NOT a hot path. NOT a forwarding/dataplane change.

---

## 1. Problem statement

#1894 landed the right primitive — `pkg/fsatomic` with three write
classes (`WriteFileDurable` = DurableState, `WriteFileAtomic` =
AtomicGeneratedConfig, direct `os.WriteFile` = BestEffortKernelKnob) —
plus an AST canary (`pkg/fsatomic/canary_test.go`
`TestNoDirectOsWriteFileInMigratedPackages`). The canary parses
production `.go` sources with `go/ast` and flags any direct
`os.WriteFile` selector in a **package allowlist** (`migratedPackages =
configstore, frr, ipsec, dhcpserver, networkd, dhcp`), with a
per-function escape hatch (`allowedFunctions`, currently only
`restoreSlowPathRPFilter` in `pkg/networkd/networkd.go:221`).

The gap is **scope, not mechanism**:

1. **The canary does not scan `pkg/daemon` or `pkg/api`.** Both write
   persistent / generated system files with raw `os.WriteFile`. The
   allowlist gives *false coverage confidence*.

2. **`pkg/api/server.go:363-366` (TLS cert/key) is the sharpest live
   defect.** `os.MkdirAll` + two bare `os.WriteFile` (errors ignored),
   then `tls.X509KeyPair(certPEM, keyPEM)` returns the in-memory pair
   regardless. Failure modes:
   - **Silent persistence failure**: a write error (disk full, RO fs)
     is swallowed; the server runs this boot with the in-memory cert,
     but **every future boot regenerates a new cert**. The operator has
     no signal that persistence failed.
   - **Mismatch window**: a crash between the two writes can leave a
     cert/key pair on disk that does not match (the order makes this
     worse when a stale pair pre-exists — see §4 D5).

   **Cert-pinning harm — settled (Codex HIGH#2 / D6):** the self-signed
   cert is generated for the HTTP REST API on 127.0.0.1:8080 (loopback).
   It is NOT distributed to remote clients that pin it; the only consumer
   is local. We therefore **DROP the "clients that pinned the previous
   cert break" harm** from the problem statement — it was speculative and
   contradicted the cert's AtomicGeneratedConfig classification. The real,
   operator-visible harm is the **silent persistence failure** (operator
   believes the cert persisted; it did not) and the **cosmetic cert churn
   on every boot** if the key fails to persist. This resolves the Codex
   HIGH#2 "cannot both be true" contradiction in favor of "cert loss after
   power cut is acceptable; silent failure is not."

3. **`pkg/daemon/daemon_system.go` writes management-critical files**
   raw: `/etc/hostname`, rsyslog drop-ins, `/etc/sudoers.d/xpf-<user>`,
   per-user + root `~/.ssh/authorized_keys`, sshd drop-in, ssh_known_hosts,
   `/etc/timezone`. A torn sudoers / authorized_keys / sshd drop-in
   affects **management access** (lockout risk).

4. **`pkg/daemon` also writes `.link`/`.network` files** bypassing the
   migrated `pkg/networkd` writer path (`daemon_reth.go`, `linksetup.go`,
   `bootstrap.go`), plus the lifeline record and provisioned-users marker.

### 1.5 Refuted / out-of-scope from the same audit

- **AGY-009 Part I.2 ("missing dir sync on rollback rotation")** is
  **stale** — `pkg/configstore/store.go` `saveRollbackFiles` already does
  write-slots → `cleanupRollbackFiles` → one trailing
  `fsatomic.SyncDir`. **Not touched.**
- **Issue §3 (journal `ReadAt` torn-tail check)** is LOW, explicitly "not
  a live bug." Carried as optional D4; recommendation = **defer** (see §4).

---

## 2. Complete repo-wide `os.WriteFile` inventory (verified against base)

**This is the exhaustive inventory** (r1 missed 7 sites — Claude C1 /
AGY#2 / Codex#4). Verified via `grep -rn 'os\.WriteFile' pkg/ --include=
'*.go' | grep -v _test.go` (40 hits; the 3 in `pkg/fsatomic/fsatomic.go`
are COMMENTS, not calls — the AST canary correctly ignores them).
Classified by `docs/engineering-style.md` §"Persistence classes (#1894)".

### A. To migrate — DurableState → `fsatomic.WriteFileDurable`
| File:line | Enclosing func | File | Notes |
|---|---|---|---|
| `api/server.go:366` | `generateSelfSignedCert` | TLS key | secret; D5 ordering |
| `daemon/daemon_system.go:219` | `applyHostname` | `/etc/hostname` | identity |
| `daemon/daemon_system.go:707` | `applySystemLogin` | sudoers | security-critical |
| `daemon/daemon_system.go:724` | `applySystemLogin` | user authorized_keys | **needs owner fix, D7** |
| `daemon/daemon_system.go:899` | `applyRootAuth` | root authorized_keys | root mgmt access |
| `daemon/bootstrap.go:259` | `writeLifelineRecordAt` | lifeline record | #1922 survive-rollback |
| `daemon/login_password.go:156` | `markProvisioned` | provisioned-users marker | #1944 §5.4 |

### B. To migrate — AtomicGeneratedConfig → `fsatomic.WriteFileAtomic`
| File:line | Enclosing func | File |
|---|---|---|
| `api/server.go:365` | `generateSelfSignedCert` | TLS cert (D6: regenerable, loopback) |
| `daemon/daemon_system.go:304` | `reconcileManagedFile` | chrony drop-in |
| `daemon/daemon_system.go:476` | `applySSHKnownHosts` | ssh_known_hosts (D2b) |
| `daemon/daemon_system.go:636` | `applySystemSyslog` | rsyslog drop-in |
| `daemon/daemon_system.go:844` | `applySSHConfig` | sshd drop-in (D2: settled AtomicGeneratedConfig) |
| `daemon/daemon_reth.go:26` | `fixRethLinkFile` | RETH `.link` |
| `daemon/linksetup.go:283` | `writeLinkFile` | `.link` |
| `daemon/linksetup.go:313` | `writeBootstrapFxp0Network` | `.network` |
| `daemon/bootstrap.go:558` | (bootstrap fxp0 `.network` func) | `.network` |
| `daemon/daemon_dns.go:249` | `atomicWrite` happy path | resolv.conf (D3 B-route; fallback stays direct) |

### C. KEEP direct (BestEffortKernelKnob) — allowlist, keyed by `relpath::func`
procfs/sysfs — rename(2) impossible by construction. **Complete list**
(r1 missed the dataplane/ra/userspace ones — Codex#4):
| File:line | Enclosing func | Knob |
|---|---|---|
| `daemon/daemon_system.go:399,414,427` | `applyKernelTuning` | sysctls |
| `daemon/daemon_run.go:1518` | `enableForwarding` | sysctl bundle |
| `daemon/host_tunables.go:85` | `realHostTunableFS.writeFile` | sysfs governor/neigh |
| `ra/sender.go:389,395` | `ensureLinkLocal` | addr_gen_mode / accept_dad |
| `dataplane/compiler.go:1484,1487,1493,1500` | `tuneInterfaceBuffers` | RPS/RFS/XPS |
| `dataplane/compiler_iface.go:139` | `ensureVLANSubInterface` | accept_ra |
| `dataplane/userspace/process.go:160` | `tuneSocketBuffers` | socket sysctls |
| `networkd/networkd.go:227` | `restoreSlowPathRPFilter` | rp_filter (EXISTING entry; re-key) |
| `daemon/daemon_dns.go` | `writeResolvConfBindMountFallback` (NEW helper) | bind-mount fallback (D3) |

### D. Procfs knobs embedded in BIG multi-purpose functions — EXTRACT to helpers first (Codex#4 false-negative hole)
These procfs writes currently live inside large apply functions.
Allowlisting the whole enclosing function would let any *future* durable
writer added to that function silently escape the canary. **Refactor each
into a tiny single-purpose helper, then allowlist the helper:**
| File:line | Currently inside | Extract to (helper) |
|---|---|---|
| `daemon/daemon_apply.go:646,652` | `applyConfigLocked` (giant) | `setRethIPv6Knobs` (accept_dad, addr_gen_mode) |
| `daemon/daemon_apply.go:701` | `applyConfigLocked` (giant) | `setVLANSubAddrGenMode` |
| `daemon/daemon_ipmon.go:180` | `applyFRRConfig` | `setFibMultipathHashPolicy` |

After extraction, allowlist `setRethIPv6Knobs`, `setVLANSubAddrGenMode`,
`setFibMultipathHashPolicy` (each procfs-only, single write). This keeps
`applyConfigLocked`/`applyFRRConfig` OUT of the allowlist so a future
durable write there is still caught.

> Note: the `daemon_system.go` DurableState writers (sudoers/keys at
> 707/724/899) live in `applySystemLogin` / `applyRootAuth`, which contain
> NO procfs knobs — they are migrated wholesale to fsatomic, so those
> functions are never allowlisted (good: no hole).

---

## 3. Goals / non-goals

**Goals**
1. Close the false-coverage gap: the canary covers EVERY production
   `os.WriteFile` under `pkg/`, permitting only named knob helpers.
2. Migrate every in-scope direct write to the correct fsatomic class.
3. Make the TLS cert/key write atomic, ordered, and **surface errors**.
4. Add regression tests for the TLS persistence failure modes.
5. Preserve `authorized_keys` ownership correctly across inode
   replacement (D7).

**Non-goals**
- No new `pkg/systemfiles/` owner package (heavier audit option).
- No behavior change to *what*/*when* is written.
- No change to procfs/sysfs/bind-mount semantics beyond allowlisting +
  the three helper extractions (which are pure refactors).

---

## 4. Settled decisions (r1 left these open; reviewers required closure)

- **D1 — canary scope: Path A (writer-class repo-wide scanner), keyed by
  `relpath::funcName`.** SETTLED. Removes the recurring "new package
  escapes" failure mode. The `relpath::func` key avoids the global-name
  collision the old bare-name map risked (now multiple packages
  contribute knob helpers). Path B (extend package allowlist) remains a
  strictly-smaller fallback if review re-opens, but all three reviewers
  accepted A in principle once the inventory is complete (§2).
- **D2 — sshd drop-in = AtomicGeneratedConfig.** SETTLED (was internally
  inconsistent in r1 — Codex MEDIUM). Rationale: it is regenerated from
  config on every apply and reloaded immediately; a power-cut loss
  reverts `PermitRootLogin` to the *base-image* default until the next
  apply, which the daemon performs on boot. The base image default is
  `prohibit-password` (not "yes"), so the loss window FAILS SAFE (more
  restrictive, never more permissive). No fsync needed. §2, §5, docs, and
  tests all now say AtomicGeneratedConfig — single class.
  - **D2b — ssh_known_hosts = AtomicGeneratedConfig.** Regenerated from
    declarative config; governs *outbound* host-key verification only,
    does not grant access TO the box; torn/lost file re-renders next apply.
- **D3 — DNS `atomicWrite` = B-route, with the EXACT error-routing Codex
  specified.** SETTLED. Replace the happy-path hand-roll with
  `fsatomic.WriteFileAtomic`; on `isCrossDeviceOrBusy(err)` run the
  extracted `writeResolvConfBindMountFallback` (the sole allowlisted
  direct write). **Do NOT pass `WithResolveSymlinks`** — current DNS
  behavior intentionally renames over the symlink itself (fsatomic's
  default replaces the link with a regular file, matching the current
  hand-rolled rename-over-symlink semantics; verify in impl that the
  default does NOT follow the link — fsatomic.go default `target = path`,
  no resolution → correct). Code shape:
  ```go
  err := fsatomic.WriteFileAtomic(r.resolvConfPath, []byte(content), 0644)
  if err == nil { return nil }
  if isCrossDeviceOrBusy(err) { // errors.Is through %w wrapping
      slog.Warn("DNS: rename onto /etc/resolv.conf failed (likely bind mount); writing in place", "err", err)
      return writeResolvConfBindMountFallback(r.resolvConfPath, content)
  }
  return err
  ```
  **Verify** `isCrossDeviceOrBusy` matches through `fmt.Errorf("rename ...:
  %w", err)` wrapping (it uses `errors.Is`/syscall comparison — confirm in
  impl; if it currently `==`-compares the bare error, switch to
  `errors.Is`).
- **D4 — journal `ReadAt` hardening = DEFER.** SETTLED. It is explicitly
  "not a live bug" and orthogonal to the daemon/api coverage theme. File a
  LOW follow-up issue rather than diluting this PR. (Was include in r1;
  reviewers split, deferring for tight scope.)
- **D5 — TLS write ordering + mismatch claim.** SETTLED (Codex HIGH#1 /
  AGY#4). The r1 "never mismatched" claim was **false** when a stale or
  mismatched pair pre-exists (writing new key first over a stale cert
  leaves stale-cert + new-key during the window). **Fix:** before writing
  the new pair, **durably remove any existing cert AND key** (so the
  starting state is {neither}), THEN write key (durable), THEN cert
  (atomic). With a clean {neither} start, the only crash-visible states
  are {neither}, {key-only}, {both-matching}. `tls.LoadX509KeyPair` reads
  the cert first and errors on key-only → clean regen. Sequence:
  1. `fsatomic.MkdirAllDurable("/etc/xpf/tls", 0700)`
  2. remove stale cert + key if present (best-effort `os.Remove`; then one
     `fsatomic.SyncDir("/etc/xpf/tls")` to make the unlinks durable)
  3. `fsatomic.WriteFileDurable(keyPath, keyPEM, 0600)`
  4. `fsatomic.WriteFileAtomic(certPath, certPEM, 0644)`
  5. on ANY error in 2-4: `slog.Error(...)` with path+err, still return the
     in-memory `tls.X509KeyPair(certPEM, keyPEM)` so the server starts.
  Claim in the plan is now: "no crash-visible *mismatched* pair, given the
  stale-pair removal in step 2." This is honest and testable (D5 tests in
  §5 Step 7 cover stale-cert-only and stale-mismatched starts).
  - **Alternative considered & rejected**: a versioned single-bundle
    pointer (write `tls/v<N>/` then atomic-symlink swap). Heavier; the
    remove-then-ordered-write achieves the same crash-safety for a
    loopback self-signed cert. Documented for the record.
- **D6 — TLS cert class = AtomicGeneratedConfig; cert-pinning harm
  DROPPED.** SETTLED (Codex HIGH#2). See §1 item 2. The key is
  DurableState; the cert is AtomicGeneratedConfig. The contradiction is
  resolved by removing the (incorrect, loopback) pinning harm. **Open
  micro-question for reviewers:** if any reviewer asserts the cert IS
  consumed by a non-loopback pinner, promote cert to DurableState too
  (cheap; one fsync on the rare regen path). Default: AtomicGeneratedConfig.
- **D7 — authorized_keys ownership across inode replacement.** SETTLED
  (Codex HIGH#3 / AGY#1). The r1 "keep `chown -R` after" is **NOT
  behavior-preserving**: `os.WriteFile` over an existing user-owned file
  preserves the inode owner; `WriteFileDurable` replaces it with a
  root-owned temp, so a crash/delay between rename and the post-rename
  `chown -R` leaves root-owned `0600` keys → sshd drops to the user and
  gets EACCES → lockout. **Fix:** set ownership on the temp fd BEFORE the
  rename. Two viable mechanisms:
  - **D7-a (recommended): add `fsatomic.WithOwner(uid, gid int) Option`**
    that `fchown`s the temp fd before close/rename (mirrors the existing
    `chownTemp` seam used by `WithPreserveExisting`). Call sites:
    `WriteFileDurable(keysFile, content, 0600, fsatomic.WithOwner(uid,
    gid))`. Resolve `uid/gid` via `user.Lookup(user.Name)` once. The
    user/dir already exists (created earlier in `applySystemLogin`), so the
    UID is resolvable. This makes the rename atomically install a
    correctly-owned file — no post-rename chown race. Keep a
    `chown` of the *.ssh dir* (the dir is created by `os.MkdirAll` as root;
    fix it once, idempotent) — but the *file* is correctly-owned at rename.
  - **D7-b (fallback): `WithPreserveExisting()`** — lifts the existing
    file's owner. Correct on *re-writes* but NOT first-write (no existing
    file → temp stays root-owned). Would still need an explicit owner set
    on first write, so D7-a is strictly cleaner.
  **Recommendation: D7-a (add `WithOwner`).** It is a small, well-scoped
  addition to fsatomic (one Option + one fchown call, reusing the existing
  `chownTemp` seam) and is the only mechanism that is correct on BOTH
  first-write and re-write. Root's keys (`/root/.ssh/authorized_keys`,
  uid 0) need no chown but using `WithOwner(0,0)` is harmless/explicit.
  Validation MUST `stat` owner+mode on the user `.ssh` dir, the user
  `authorized_keys`, and root's file (not just "ssh works once").
- **D8 — failover validation.** SETTLED (Codex MEDIUM / AGY#5). The r1
  blanket waiver was **false**: `fixRethLinkFile` (`daemon_reth.go`) and
  the cluster-mode naming in `linksetup.go` feed **RETH member post-reboot
  interface naming** — cluster/HA convergence surface (called from
  `applyConfigLocked` when `cfg.Chassis.Cluster != nil`). **Decision: run
  `make test-failover` (and `make test-ha-crash`).** Do NOT waive. The
  change is mechanism-only (atomic vs raw write of the SAME `.link`
  content), so failover is expected green, but it MUST be run because the
  touched files are cluster-adjacent. The PR description states "RETH
  `.link` write mechanism changed; validated with `make test-failover`"
  rather than claiming no cluster path is touched.

---

## 5. Implementation plan

### Step 0 — fsatomic `WithOwner` option (D7-a)
- Add `func WithOwner(uid, gid int) Option` + an `owner *ownerIDs` field
  on `options`; in `writeFile`, after `chmodTemp`, if `WithOwner` set,
  `chownTemp(tmp, uid, gid)` before the durable sync/close/rename. Reuses
  the existing `chownTemp` test seam. Unit test: temp fd owned as
  requested before rename (inject `chownTemp` to assert call order).
- Document the new option in `pkg/fsatomic/fsatomic.go` header +
  `pkg/fsatomic/README.md`.

### Step 1 — TLS persistence (`pkg/api/server.go`) — D5 + D6
- Refactor to a path-parameterized inner func
  `generateSelfSignedCertAt(certPath, keyPath string) (tls.Certificate,
  error)`; the existing entry delegates with the package paths. (Test seam
  per D-test; avoids a `const`→`var` global-race — Claude M3.)
- Implement the D5 sequence (MkdirAllDurable → remove stale pair +
  SyncDir → key durable → cert atomic → log errors, return in-memory pair).

### Step 2 — `pkg/daemon/daemon_system.go` migrations
- DurableState → `WriteFileDurable`: hostname (219), sudoers (707), user
  keys (724, **+ `WithOwner(uid,gid)`** D7-a), root keys (899, optionally
  `WithOwner(0,0)`).
- AtomicGeneratedConfig → `WriteFileAtomic`: chrony (304), ssh_known_hosts
  (476), rsyslog (636), sshd drop-in (844).
- timezone (510): **D-decision below.**

### Step 2b — timezone (D from r1 §10 + AGY#3 + Codex MEDIUM)
r1 classified `/etc/timezone` DurableState, but it is paired with the
`/etc/localtime` symlink which is updated NON-atomically
(`os.Remove`+`os.Symlink`, no dir sync). Making only `/etc/timezone`
durable leaves the pair inconsistent after a crash. **SETTLED:** classify
`/etc/timezone` as **AtomicGeneratedConfig** (`WriteFileAtomic`). The
timezone is re-derived and re-applied on every boot from the active
config, so a power-cut loss of either half self-heals on next apply; there
is no need to pay DurableState + a symlink-durability redesign for a file
the daemon regenerates. (Leave the `/etc/localtime` symlink logic
unchanged — out of scope; it is regenerated on apply.)

### Step 3 — `pkg/daemon` networkd / lifeline / marker
- AtomicGeneratedConfig → `WriteFileAtomic`: `fixRethLinkFile` (reth 26),
  `writeLinkFile` (linksetup 283), `writeBootstrapFxp0Network` (313),
  bootstrap fxp0 `.network` (bootstrap 558).
- DurableState → `WriteFileDurable`: `writeLifelineRecordAt` (259, with
  `MkdirAllDurable` for the lifeline dir — #1922 survive-rollback),
  `markProvisioned` (login_password 156, with `MkdirAllDurable` for
  provisioned-users dir — #1944 §5.4 survive-reboot).

### Step 4 — `pkg/daemon/daemon_dns.go` (D3 B-route)
- Extract `writeResolvConfBindMountFallback(path, content string) error`
  (the in-place `os.WriteFile` fallback). Route the happy path through
  `fsatomic.WriteFileAtomic` with the exact error-check shape in D3.
  Confirm `isCrossDeviceOrBusy` uses `errors.Is` (switch if needed).

### Step 5 — Procfs helper extractions (D §2.D — Codex#4 hole)
- Extract `setRethIPv6Knobs(iface string)` (accept_dad + addr_gen_mode),
  `setVLANSubAddrGenMode(iface string)`, `setFibMultipathHashPolicy()`
  from `applyConfigLocked` / `applyFRRConfig`. Pure refactor — same calls,
  named home. Allowlist these three helpers.

### Step 6 — Canary rewrite (Path A, `relpath::func` keys)
- Replace `migratedPackages` walk with `filepath.WalkDir("../", ...)` over
  all `pkg/**/*.go` (skip `_test.go`; verify no generated `.pb.go` contains
  a real `os.WriteFile` call — none do per grep).
- Key `allowedFunctions` by `<pkg-relpath>::<funcName>` computed from the
  fileset position. Seed it with the COMPLETE §2.C + §2.D list:
  `daemon::applyKernelTuning`, `daemon::enableForwarding`,
  `daemon::(realHostTunableFS).writeFile`, `ra::ensureLinkLocal`,
  `dataplane::(*CompileResult).tuneInterfaceBuffers`,
  `dataplane::ensureVLANSubInterface`,
  `dataplane/userspace::tuneSocketBuffers`,
  `networkd::restoreSlowPathRPFilter`,
  `daemon::writeResolvConfBindMountFallback`, `daemon::setRethIPv6Knobs`,
  `daemon::setVLANSubAddrGenMode`, `daemon::setFibMultipathHashPolicy`.
  (Method receivers: the canary keys on `fn.Name.Name` today, which is the
  bare method name — confirm whether `(realHostTunableFS).writeFile` /
  `(*CompileResult).tuneInterfaceBuffers` resolve to `writeFile` /
  `tuneInterfaceBuffers`; key accordingly. The `relpath::` prefix
  disambiguates same-named methods across packages.)
- Keep the existing dot-import / alias resolution (correct).
- **Self-test guard**: `t.Logf("scanned %d files", n)` and
  `if n == 0 { t.Fatal(...) }` so a future zero-glob bug is caught.
- **M1 (Claude)**: add a doc comment asserting every newly-scanned
  non-daemon/api site was verified as a procfs/sysfs/bind-mount knob, none
  durable.

### Step 7 — TLS persistence regression tests (`pkg/api`)
Using `generateSelfSignedCertAt(certPath, keyPath)`:
- **Happy path**: both files written, owner/mode correct, returned cert
  matches on-disk.
- **Failed cert write**: unwritable cert path (or inject) → still returns
  usable cert AND surfaces error (assert log/err, no silent success).
- **Failed key write**: same for key.
- **Pre-existing mismatched pair** (D5): seed cert from key-A + key from
  key-B → assert regen produces a *matching* pair on disk (not the broken
  one).
- **Stale cert-only / crash-after-key** (D5): seed cert-only, simulate
  failure after key write → assert next call yields a matching pair (no
  durable mismatch).

### Step 8 — Docs
- `docs/engineering-style.md` §"Persistence classes" examples: add TLS key
  + hostname + authorized_keys + sudoers (DurableState); TLS cert + sshd /
  rsyslog / chrony / networkd drop-ins + timezone (AtomicGeneratedConfig);
  note `WithOwner`.
- `pkg/fsatomic/README.md`: writer-class repo-wide canary + `relpath::func`
  key + `WithOwner` option.
- `_Log.md` per the project logging rule for each Write/Edit.

### Dir durability
DurableState files in maybe-absent dirs (`/etc/xpf/tls`, lifeline,
provisioned-users) use `fsatomic.MkdirAllDurable` so the dir entry itself
survives a power cut (fsatomic.go:126-167 rationale).

---

## 6. Files touched (estimate)

- `pkg/fsatomic/fsatomic.go` (+ `_test.go`) — `WithOwner` (Step 0).
- `pkg/fsatomic/canary_test.go` — rewrite (Step 6).
- `pkg/api/server.go` (+ `server_test.go` new/extended) — Steps 1, 7.
- `pkg/daemon/daemon_system.go` — Steps 2, 2b.
- `pkg/daemon/daemon_reth.go`, `linksetup.go`, `bootstrap.go`,
  `login_password.go` — Step 3.
- `pkg/daemon/daemon_dns.go` — Step 4.
- `pkg/daemon/daemon_apply.go`, `daemon_ipmon.go` — Step 5 (helper
  extraction).
- `docs/engineering-style.md`, `pkg/fsatomic/README.md`, `_Log.md` —
  Step 8.

`pkg/dataplane/*`, `pkg/ra/*`, `pkg/dataplane/userspace/*`,
`pkg/networkd/*` — **allowlist entries only, NO code change** (their
writes stay direct knobs). No proto, no Rust, no HA-timing logic.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| authorized_keys root-owned after inode replace → sshd EACCES lockout (AGY#1/Codex#3) | D7-a `WithOwner` sets owner on temp fd BEFORE rename; file is correctly-owned atomically. Validation stats owner+mode on user/root keys. |
| TLS mismatched pair from stale-pair start (Codex#1/AGY#4) | D5: durably remove stale pair (+SyncDir) before ordered key→cert write; start state is {neither}. Tests cover stale-cert-only + mismatched starts. |
| Canary Path A noisy/incomplete (Claude C1/AGY#2/Codex#4) | §2.C/§2.D exhaustive inventory; seed all knob helpers; extract embedded procfs writes so big functions are never allowlisted. Run `go test ./pkg/fsatomic/` green before commit. |
| Allowlisting `applyConfigLocked`/`applyFRRConfig` = false-negative hole (Codex#4) | Extract 3 tiny helpers (Step 5); allowlist helpers only. |
| RETH `.link` mechanism change is cluster-adjacent (Codex/AGY#5) | D8: run `make test-failover` + `make test-ha-crash`; mechanism-only change, expected green. |
| DNS B-route breaks bind-mount (Codex MEDIUM) | D3 exact error-routing; confirm `isCrossDeviceOrBusy` uses `errors.Is`; test the fallback. No `WithResolveSymlinks`. |
| timezone/localtime pair inconsistency (AGY#3/Codex) | Step 2b: timezone = AtomicGeneratedConfig (regenerated on boot); leave localtime logic unchanged. |
| `WithOwner` regression in fsatomic | Unit-test temp owned-before-rename via the `chownTemp` seam; existing fsatomic tests unaffected. |

---

## 8. Validation plan

- `make test` — full Go suite. Rewritten canary must pass (proves every
  in-scope writer migrated or allowlisted) + the new scanned-file-count
  guard.
- `pkg/api` TLS tests (Step 7): happy, failed-cert, failed-key,
  mismatched-start, stale-cert/crash-after-key.
- `pkg/fsatomic` `WithOwner` unit test (owner set before rename).
- `go vet ./...`, `gofmt` clean on touched files.
- **`make test-failover` + `make test-ha-crash`** (D8) — RETH `.link`
  write mechanism is cluster-adjacent; not waived.
- **Smoke on loss userspace cluster**: commit exercising hostname / login
  user with SSH key / sudoers / sshd root-login → verify files land
  correct, `stat` shows user-owned 0600 authorized_keys, `ssh user@fw`
  works; verify `https://127.0.0.1:8080` serves and `/etc/xpf/tls/*`
  persist across daemon restart with correct owner/mode (no churn).
- `make build` + `make build-userspace-dp` compile clean (no Rust change).

---

## 9. Rollout / backout

- Pure mechanism change (+ one fsatomic Option + three pure refactors)
  behind existing apply/boot paths; no schema, wire-protocol, or
  migration. Backout = `git revert`.
- The canary rewrite is test-only; revertible independently of the writer
  migrations (migrations are strictly-better even without it).

---

## 10. Remaining open questions for reviewers (all majors settled in §4)

1. **D6 micro**: is the self-signed cert EVER consumed by a non-loopback
   pinner? If yes, promote cert to DurableState. Default = AtomicGeneratedConfig.
2. **D7 method**: `WithOwner` (new fsatomic Option) vs reusing
   `WithPreserveExisting` + a first-write owner set? Plan recommends
   `WithOwner` (correct on both first-write and re-write).
3. **Canary method-receiver keying**: confirm the AST keys method writers
   by bare method name under `relpath::`; if collisions remain, key by
   `relpath::recv.method`.

---

## 11. Reviewer convergence ledger

See `reviewer-ids.md`. Convergence requires Claude SMR + Codex + AGY to
re-review the FINAL revision (r2) and reach PLAN-READY.

---

## 12. r1 → r2 changelog (every convergent finding mapped)

- **C1 / AGY#2 / Codex#4 (incomplete inventory)** → §2 now exhaustive
  repo-wide (added dataplane/ra/userspace knobs); §2.D extracts embedded
  procfs writes so big functions are never allowlisted; corrected
  `restoreSlowPathRPFilter` location to `pkg/networkd/networkd.go`.
- **AGY#1 / Codex#3 (authorized_keys ownership)** → D7-a: new
  `fsatomic.WithOwner`, set owner on temp fd before rename; validation
  stats owner/mode.
- **AGY#4 / Codex#1 (TLS over-claim)** → D5: remove stale pair + SyncDir
  before ordered key→cert; claim weakened to "no mismatch given clean
  start"; stale-start tests added.
- **Codex#2 (cert class vs pinning harm)** → D6: cert =
  AtomicGeneratedConfig; loopback pinning harm DROPPED from §1.
- **Codex MEDIUM (sshd class inconsistency)** → D2: settled
  AtomicGeneratedConfig (fail-safe loss window) across §2/§5/docs/tests.
- **AGY#3 / Codex MEDIUM (timezone)** → Step 2b: AtomicGeneratedConfig
  (regenerated on boot), localtime logic unchanged.
- **AGY#5 / Codex MEDIUM (failover waiver)** → D8: run
  `make test-failover` + `make test-ha-crash`; PR states cluster-adjacent.
- **Codex MEDIUM (DNS B-route)** → D3: exact error-routing,
  `isCrossDeviceOrBusy` via `errors.Is`, no `WithResolveSymlinks`.
- **Claude M3 (test seam race)** → Step 1: parameterized
  `generateSelfSignedCertAt`, no `const`→`var` global.
- **D4 (journal ReadAt)** → deferred to a LOW follow-up issue.

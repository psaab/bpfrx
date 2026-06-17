# Plan of action — #1916: fsatomic durability coverage gap (canary scope + TLS persistence)

- **Issue**: #1916 — Durability coverage gap: fsatomic canary excludes
  `pkg/daemon` + `pkg/api`; TLS cert/key persisted non-atomically with
  ignored errors.
- **Revision**: r1 (initial draft for 3-way hostile review)
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
`restoreSlowPathRPFilter`).

The gap is **scope, not mechanism**:

1. **The canary does not scan `pkg/daemon` or `pkg/api`.** Both write
   persistent / generated system files with raw `os.WriteFile`. The
   allowlist gives *false coverage confidence*: someone reading the
   canary believes the durability discipline is enforced repo-wide when
   it is enforced for six packages only.

2. **`pkg/api/server.go:363-366` (TLS cert/key) is the sharpest live
   defect.** `os.MkdirAll` + two bare `os.WriteFile` (errors ignored),
   then `tls.X509KeyPair(certPEM, keyPEM)` returns the in-memory pair
   regardless. Two real failure modes:
   - **Mismatch window**: a crash between the cert write and the key
     write leaves a cert/key pair on disk that does not match. It
     self-heals (next boot regenerates because `tls.LoadX509KeyPair`
     fails), but until then any external reader of the files gets a
     broken pair.
   - **Silent persistence failure**: a write error (disk full, RO fs,
     missing dir) is swallowed; the server runs fine this boot with the
     in-memory cert, but **every future boot regenerates a new cert**
     (cert churn → clients that pinned the previous self-signed cert
     break, operators believe the cert is stable). The operator has no
     signal that persistence failed.

3. **`pkg/daemon/daemon_system.go` writes management-critical files**
   raw: `/etc/hostname`, rsyslog drop-ins, `/etc/sudoers.d/xpf-<user>`,
   per-user + root `~/.ssh/authorized_keys`, sshd drop-in
   (`/etc/ssh/sshd_config.d/xpf.conf`), `/etc/ssh/ssh_known_hosts`,
   `/etc/timezone`. A torn sudoers / authorized_keys / sshd drop-in
   affects **management access** (lockout risk); a torn `.link` file
   affects **boot-time interface convergence**. These are not cosmetic.

4. **`pkg/daemon` also writes `.link`/`.network` files** that bypass the
   already-migrated `pkg/networkd` writer path:
   `daemon_reth.go:26` (`fixRethLinkFile`), `linksetup.go:283,313`
   (`writeLinkFile` / `writeBootstrapFxp0Network`), `bootstrap.go:259`
   (`writeLifelineRecordAt`), `bootstrap.go:558` (bootstrap fxp0
   `.network`).

### 1.5 Refuted / out-of-scope from the same audit

- **AGY-009 Part I.2 ("missing directory sync on rollback rotation")** is
  **stale** — `pkg/configstore/store.go` `saveRollbackFiles` already does
  write-slots → `cleanupRollbackFiles` → one trailing
  `fsatomic.SyncDir(filepath.Dir(s.filePath))`. Verified at
  `store.go` in the current base. **Not touched by this plan.**
- **Issue §3 (journal `ReadAt` `err == nil` torn-tail check)** is
  **LOW and explicitly "not a live bug"** (correct on `os.File`/Linux;
  fragile only against mocks/virtfs). Carried as an *optional* hardening
  in Path A only; see §4 Path Options.

---

## 2. Full inventory of `os.WriteFile` in scope (verified against base)

Classified by the project's three persistence classes
(`docs/engineering-style.md` §"Persistence classes (#1894)").

### `pkg/api/server.go`
| Line | File written | Proposed class | Notes |
|---|---|---|---|
| 365 | `/etc/xpf/tls/<cert>` (`certPath`) | **AtomicGeneratedConfig** | Regenerable (self-signed, regenerated if load fails). Torn cert unacceptable; lost-on-power-cut acceptable (regenerated next boot). |
| 366 | `/etc/xpf/tls/<key>` (`keyPath`) | **DurableState** | Private key — losing it after a power cut means cert churn + any external pinner breaks. Treat as state/secret (issue text says key=DurableState). |

### `pkg/daemon/daemon_system.go`
| Line | File | Proposed class | Rationale |
|---|---|---|---|
| 219 | `/etc/hostname` | **DurableState** | Identity; read at early boot before xpfd re-applies. |
| 304 | chrony `sources.d` / `conf.d` drop-in (`reconcileManagedFile`) | **AtomicGeneratedConfig** | Regenerated from config each apply. |
| 476 | `/etc/ssh/ssh_known_hosts` (`applySSHKnownHosts`) | **AtomicGeneratedConfig** | Regenerated from config; torn file unacceptable. |
| 510 | `/etc/timezone` | **DurableState** | Identity-ish; paired with `/etc/localtime` symlink. Low rewrite rate. |
| 636 | rsyslog drop-in (`applySystemSyslog`) | **AtomicGeneratedConfig** | Regenerated; restart rsyslog after. |
| 707 | `/etc/sudoers.d/xpf-<user>` | **DurableState** | Security-critical; a torn sudoers line is parsed by sudo at next invocation (lockout / privilege defect). Durable + atomic. |
| 724 | `/home/<user>/.ssh/authorized_keys` | **DurableState** | Management access; torn keys = SSH lockout. |
| 844 | `/etc/ssh/sshd_config.d/xpf.conf` | **AtomicGeneratedConfig** | Regenerated from config; reload sshd after. (Torn file = sshd reload fail, but regenerated next apply; not lost-key-class.) See §4 Path C tradeoff — could argue DurableState. |
| 899 | `/root/.ssh/authorized_keys` | **DurableState** | Root management access; torn = root SSH lockout. |

### `pkg/daemon` — networkd-class files (bypass migrated `pkg/networkd`)
| Line | File | Proposed class |
|---|---|---|
| `daemon_reth.go:26` (`fixRethLinkFile`) | `.link` | **AtomicGeneratedConfig** |
| `linksetup.go:283` (`writeLinkFile`) | `.link` | **AtomicGeneratedConfig** |
| `linksetup.go:313` (`writeBootstrapFxp0Network`) | `.network` | **AtomicGeneratedConfig** |
| `bootstrap.go:558` (bootstrap fxp0 `.network`) | `.network` | **AtomicGeneratedConfig** |
| `bootstrap.go:259` (`writeLifelineRecordAt`) | lifeline record (outside `.configdb`, survives rollback) | **DurableState** — #1922 invariant says it must survive restart/rollback. |

### `pkg/daemon` — provenance marker
| Line | File | Proposed class |
|---|---|---|
| `login_password.go:156` (`markProvisioned`) | `/var/lib/xpf/provisioned-users/<name>` | **DurableState** — #1944 §5.4: marker must survive reboot to drive D2-lock; a torn/lost marker mis-classifies an account. Small, operator-paced. |

### `pkg/daemon` — BestEffortKernelKnob (KEEP direct; allowlist with justification)
procfs/sysfs writes — rename(2) impossible by construction:
- `daemon_system.go:399,414,427` (`applyKernelTuning` sysctls)
- `daemon_apply.go:646,652,701` (accept_dad / addr_gen_mode procfs)
- `daemon_ipmon.go:180` (`fib_multipath_hash_policy`)
- `daemon_run.go:1518` (sysctl bundle)
- `host_tunables.go:85` (`realHostTunableFS.writeFile` — sysfs/proc
  governor/neigh knobs)

### `pkg/daemon/daemon_dns.go:249` — special case
`atomicWrite` already hand-rolls temp+rename with a **documented
EXDEV/EBUSY bind-mount fallback** to in-place `os.WriteFile`. This is a
legitimate `BestEffortKernelKnob`-adjacent fallback (the bind-mount case
cannot be renamed onto). **Decision (see §4 Path B):** either (a) leave
`atomicWrite` as-is and allowlist its function, OR (b) replace the happy
path with `fsatomic.WriteFileAtomic` and keep the bind-mount fallback as
the allowlisted direct write. `/etc/resolv.conf` is regenerated each DNS
reconcile → AtomicGeneratedConfig for the happy path.

---

## 3. Goals / non-goals

**Goals**
1. Close the false-coverage gap: the canary must cover the
   management-critical writers in `pkg/daemon` + `pkg/api`.
2. Migrate every in-scope direct `os.WriteFile` to the correct fsatomic
   class (DurableState / AtomicGeneratedConfig), keeping only justified
   BestEffortKernelKnob writes direct.
3. Make the TLS cert/key write atomic, ordered (key durable first or
   cert+key both succeed), and **surface the error** so the operator
   learns persistence failed (log at minimum; the function already
   returns the in-memory pair so the server still starts).
4. Add a regression test for the TLS persistence failure modes
   (failed cert write, failed key write, pre-existing mismatched pair).

**Non-goals**
- No new `pkg/systemfiles/` owner package (the audit's heavier option).
  This plan takes the **thinner pass** (route existing writers through
  `fsatomic` + extend the canary). See §4 Path Options for the rejected
  alternative.
- No behavior change to *what* gets written, *when*, or the
  reconcile/skip-if-unchanged logic. Only the write mechanism changes.
- No change to procfs/sysfs/bind-mount knobs beyond allowlisting them.
- No dataplane / forwarding / HA-timing impact (none of these paths are
  hot; all are operator-paced apply/boot).

---

## 4. Multiple Path Options (design decisions for the operator to pick)

### Decision D1 — Canary scope model: writer-CLASS scanner vs package-allowlist extension

- **Path A (writer-class repo-wide scanner)** — replace
  `migratedPackages` with a scan of **all** production `.go` under
  `pkg/` (and optionally `cmd/`), flagging every direct `os.WriteFile`
  EXCEPT functions named in `allowedFunctions` (the BestEffortKernelKnob
  allowlist). This is the issue's preferred shape ("replace the package
  allowlist with a repo-wide production-source scanner that permits only
  named BestEffortKernelKnob functions").
  - **Pro**: no future package can silently escape; matches the
    "writer-class based, not package-allowlist based" framing.
  - **Con**: larger allowlist to seed (every legitimate knob function
    across the repo, e.g. `restoreSlowPathRPFilter` + the daemon
    sysctl/sysfs functions + the DNS bind-mount fallback). Risk of an
    initially-noisy test; must enumerate all knob functions up front.
    Function-name keying is **global** (collision risk if two packages
    have a same-named function — current map is unqualified). Mitigation:
    key by `pkg-relative-path::funcName` or accept the small collision
    surface and document it.
- **Path B (extend the package allowlist to add `daemon` + `api`)** —
  add `../daemon` and `../api` to `migratedPackages`, seed
  `allowedFunctions` with the daemon knob functions.
  - **Pro**: minimal change, mirrors existing design exactly, lower risk
    of accidental over-broad failures.
  - **Con**: leaves the same false-coverage shape for any *future*
    package; the issue explicitly calls the allowlist model out as the
    defect.

  **Recommendation: Path A (writer-class scanner), keyed by
  `relpath::funcName` to avoid the global-name collision.** It is the
  issue's stated goal and removes the recurring "new package escapes"
  failure mode permanently. If review judges the up-front allowlist
  enumeration too risky, fall back to Path B as a strictly-smaller
  increment (the migration work in §5 is identical either way; only the
  test changes).

### Decision D2 — sshd drop-in class: AtomicGeneratedConfig vs DurableState

`/etc/ssh/sshd_config.d/xpf.conf` is regenerated from config each apply
(AtomicGeneratedConfig by the rulebook). BUT a torn drop-in causes
`systemctl reload sshd` to fail, and on a power cut the drop-in could be
lost, reverting `PermitRootLogin` to the base-image default until the
next apply — a *security posture* regression window.
- **Path C-atomic**: classify as AtomicGeneratedConfig (rulebook-literal:
  regenerated on apply). Simpler, no fsync on the apply path.
- **Path C-durable**: classify as DurableState (security posture should
  survive power loss). Costs one fsync on an operator-paced SSH-config
  apply (rare) — acceptable per the "fsync on operator-paced paths only"
  rule.

  **Recommendation: C-durable for sshd drop-in.** Same reasoning makes
  sudoers + authorized_keys DurableState (already proposed). Consistency:
  every *access-control* file is DurableState; every *service render*
  that is purely cosmetic-on-loss (rsyslog, chrony, ssh_known_hosts,
  networkd `.link`/`.network`) is AtomicGeneratedConfig. This is a clean
  operator-legible rule. **Open for review** — a reviewer may argue
  ssh_known_hosts is also security-relevant (it is, for host-key
  verification of *outbound* connections from the box); if so promote it
  to DurableState too. Default: keep ssh_known_hosts AtomicGeneratedConfig
  (it is regenerated from declarative config and a torn/lost file just
  re-renders next apply; it does not grant access TO the box).

### Decision D3 — DNS `atomicWrite` handling

- **Path B-leave**: allowlist `atomicWrite` (it already hand-rolls
  temp+rename + a justified bind-mount fallback). Zero code change.
- **Path B-route**: replace the happy-path hand-roll with
  `fsatomic.WriteFileAtomic`, keep the EXDEV/EBUSY fallback as the single
  allowlisted direct `os.WriteFile`.

  **Recommendation: B-route** — collapses a second hand-rolled
  temp+rename into the single fsatomic SSOT (the engineering-style doc
  says "Do not hand-roll it; pick a class"), and the only remaining
  direct write is the genuinely-unrenameable bind-mount fallback, which
  is allowlisted with a comment. Net: one fewer hand-rolled writer, and
  the canary then *catches* the fallback line as a named exception rather
  than missing it. Lower-risk alternative B-leave is acceptable if review
  wants to minimize touch.

### Decision D4 — journal `ReadAt` hardening (issue §3, LOW)

- **Path-include**: fold the `n==1 && (err==nil||err==io.EOF)` hardening
  into this PR (it is one line + a comment, in `pkg/configstore/journal`,
  already a migrated package so no canary change).
- **Path-defer**: leave it; it is explicitly "not a live bug". File a
  LOW follow-up or carry in a `// TODO`.

  **Recommendation: Path-include** — it is one line, in-theme
  (durability robustness), costs nothing, and removes a documented
  spec-fragility. If review prefers tight scope, defer it.

---

## 5. Implementation plan (the recommended path: A + C-durable + B-route + D4-include)

### Step 1 — TLS persistence (`pkg/api/server.go`) — the sharpest item
- Replace the `os.MkdirAll` + 2× `os.WriteFile` block:
  - `fsatomic.MkdirAllDurable("/etc/xpf/tls", 0700)` (the dir must
    survive too — see §"Durability of the dir").
  - Write the **key first** with `fsatomic.WriteFileDurable(keyPath,
    keyPEM, 0600)`, then the **cert** with
    `fsatomic.WriteFileAtomic(certPath, certPEM, 0644)` (cert is
    regenerable, so AtomicGeneratedConfig is sufficient; but writing it
    *after* the key means a crash between them leaves key-without-cert,
    which `tls.LoadX509KeyPair` rejects → clean regen, no *mismatch*).
    Rationale for order: a half-written *pair* is the bad state; by
    making each file individually atomic (temp+rename) AND ordering them,
    the only crash-visible states are {neither}, {key only}, {both
    matching} — never {mismatched cert+key}.
  - **Surface errors**: if either write fails, `slog.Error` (or
    `slog.Warn`) with the path + err, and still return the in-memory pair
    (current behavior — server must start). Optionally return the error
    up if the caller can log it; minimum bar is a non-silent log.
- **Concern (review to confirm)**: are cert+key individually atomic
  enough, or do we need both-or-neither? A true transaction would write
  both temps, fsync, then rename both — but two renames are not atomic
  together. The ordered-individual-atomic approach above eliminates the
  *mismatch* state (the issue's stated harm) without a 2-phase commit.
  Document this explicitly.

### Step 2 — `pkg/daemon/daemon_system.go` migrations
Per the §2 table:
- DurableState → `fsatomic.WriteFileDurable`: `/etc/hostname` (219),
  `/etc/timezone` (510), sudoers (707), user authorized_keys (724), root
  authorized_keys (899).
  - **authorized_keys ownership**: currently `os.WriteFile(...,0600)`
    then `chown -R user:user sshDir`. `WriteFileDurable` *replaces the
    inode* (new temp file owned by root). The existing `chown -R` after
    the write still fixes ownership, so behavior is preserved — but note
    the temp file is created in `sshDir` (owned by the user after
    `MkdirAll`+chown on first run). **Confirm**: temp create in a
    user-owned dir by a root process succeeds (it does; root can create
    anywhere). Keep the `chown -R` after. Alternatively use
    `WithPreserveExisting()` so the new inode lifts the existing file's
    mode/owner — but on *first* write there is no existing file, so the
    explicit `chown -R` is still needed. **Decision: keep the explicit
    chown; do not rely on WithPreserveExisting for first-write.**
- AtomicGeneratedConfig → `fsatomic.WriteFileAtomic`: chrony drop-in
  (`reconcileManagedFile`, 304), ssh_known_hosts (476), rsyslog drop-in
  (636), sshd drop-in (844) **[unless D2 → C-durable, then Durable]**.
  - Per D2 recommendation, sshd drop-in (844) → `WriteFileDurable`.
- BestEffortKernelKnob → keep direct + allowlist the enclosing
  functions: `applyKernelTuning` (399/414/427).

### Step 3 — `pkg/daemon` networkd / lifeline / marker
- AtomicGeneratedConfig → `fsatomic.WriteFileAtomic`: `fixRethLinkFile`
  (reth 26), `writeLinkFile` (linksetup 283), `writeBootstrapFxp0Network`
  (linksetup 313), bootstrap fxp0 `.network` (bootstrap 558).
- DurableState → `fsatomic.WriteFileDurable`: `writeLifelineRecordAt`
  (bootstrap 259) — #1922 invariant; `markProvisioned`
  (login_password 156) — #1944 invariant. Both use
  `MkdirAllDurable` for the parent dir if the dir must also survive
  (lifeline dir + provisioned-users dir). **Confirm dir-durability need**
  per #1922/#1944 invariants in review.

### Step 4 — `pkg/daemon/daemon_dns.go` (D3 = B-route)
- Replace `atomicWrite`'s temp+rename happy path with
  `fsatomic.WriteFileAtomic(r.resolvConfPath, []byte(content), 0644)`.
- Keep the EXDEV/EBUSY in-place fallback as the **only** direct
  `os.WriteFile`, allowlisted (`atomicWrite` in `allowedFunctions` with a
  "bind-mount fallback — rename impossible" justification) — OR refactor
  the fallback into a tiny named helper `writeResolvConfBindMountFallback`
  and allowlist that, so the main `atomicWrite` body has no direct write.
  **Recommendation: extract the fallback helper** → narrowest allowlist
  surface.

### Step 5 — BestEffortKernelKnob allowlist seeding
Add to `allowedFunctions` (Path A keying = `relpath::func`, or bare func
name if Path B): `applyKernelTuning`, the RETH procfs writers in
`daemon_apply.go` (their enclosing function — likely `applyClusterReth`
or similar; **confirm enclosing func name in impl**), `runIPMonitoring`
(or the enclosing func at ipmon 180), the sysctl bundle func at
daemon_run 1518, `realHostTunableFS.writeFile` (host_tunables 85), and
the DNS bind-mount fallback helper. Each entry carries a one-line
procfs/sysfs/bind-mount justification.

### Step 6 — Canary rewrite (Path A)
- Replace `migratedPackages` walk with a walk of all `pkg/**/*.go`
  (skip `_test.go`, skip generated `.pb.go` if any contain WriteFile —
  verify none do).
- Key `allowedFunctions` by `relpath::funcName` (compute relpath from the
  fileset position) to avoid global-name collisions; update the existing
  `restoreSlowPathRPFilter` entry accordingly.
- Keep the existing dot-import / alias resolution logic (it is correct).
- **Self-test**: the test must currently PASS after Steps 1-5 migrate
  everything. Add a `t.Log` count of scanned files so a future
  zero-files glob bug (the kind #1894 guards against) is visible.

### Step 7 — TLS persistence regression test (`pkg/api`)
New `pkg/api/server_test.go` (or extend existing) cases:
- **Failed cert write**: point `certPath`/`keyPath` at an unwritable dir
  (or inject via a test seam) → assert the function still returns a
  usable cert AND logs/returns an error (no silent success).
- **Failed key write**: same for key.
- **Pre-existing mismatched pair**: write a cert from one key and a key
  from another into the paths → assert `generateSelfSignedCert`
  regenerates a *matching* pair (does not return the broken on-disk pair
  as durable success) — i.e. `tls.LoadX509KeyPair` rejects, regen path
  runs, new files match.
- **Note**: `certPath`/`keyPath` are package-level constants
  (`pkg/api/server.go`); the test needs a seam (var instead of const, or
  a helper that takes paths). **Confirm in impl**: minimal refactor to
  make paths injectable for the test (change `const` → `var`, or add a
  path-parameterized inner function). Prefer a path-parameterized
  `generateSelfSignedCertAt(certPath, keyPath string)` with the existing
  exported entry delegating to it.

### Step 8 — Docs
- Update `docs/engineering-style.md` §"Persistence classes" examples
  table to include the daemon/api writers now covered (hostname, TLS
  key, authorized_keys, sudoers as DurableState; sshd/rsyslog/networkd
  drop-ins as AtomicGeneratedConfig).
- Update `pkg/fsatomic/README.md` to describe the canary's new
  writer-class repo-wide scope (Path A) and the `relpath::func`
  allowlist key.
- `_Log.md` entries per the project logging rule for each Write/Edit.

### Durability of the dir
Several DurableState files live in dirs that may not exist
(`/etc/xpf/tls`, provisioned-users, lifeline dir). Use
`fsatomic.MkdirAllDurable` for those so the dir entry survives a power cut
too (the WriteFileDurable parent-dir fsync persists the *file's* entry in
the dir, not the *dir's* entry in its parent — that is exactly the
`MkdirAllDurable` rationale in fsatomic.go:126-167).

---

## 6. Files touched (estimate)

- `pkg/api/server.go` — TLS persistence (Step 1) + test seam (Step 7).
- `pkg/api/server_test.go` (new or extended) — Step 7.
- `pkg/daemon/daemon_system.go` — Steps 2, 5.
- `pkg/daemon/daemon_reth.go`, `linksetup.go`, `bootstrap.go`,
  `login_password.go` — Step 3.
- `pkg/daemon/daemon_dns.go` — Step 4.
- `pkg/daemon/daemon_apply.go`, `daemon_ipmon.go`, `daemon_run.go`,
  `host_tunables.go` — Step 5 allowlist only (no code change if Path A
  keys by func; the writes stay direct).
- `pkg/fsatomic/canary_test.go` — Step 6 (the rewrite).
- `pkg/configstore/journal/journal.go` — Step D4 (optional, one line).
- `docs/engineering-style.md`, `pkg/fsatomic/README.md`, `_Log.md` —
  Step 8.

No production source outside `pkg/daemon`, `pkg/api`, `pkg/configstore`
(D4 only), `pkg/fsatomic` (test). No proto, no dataplane, no HA-timing.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| **authorized_keys inode replacement breaks ownership** — `WriteFileDurable` replaces the inode (root-owned temp); user can't read own keys. | Keep the existing `chown -R user:user sshDir` after the write (preserved). Verify in impl that sshd reads keys 0600-root? No — sshd requires keys owned by the user (or root) and 0600; the existing chown fixes it. Add a test/manual smoke that `ssh user@box` still works after a config-driven key change. |
| **sudoers torn-write locks out sudo** — but we are *fixing* exactly this with atomic write. | Atomic temp+rename means sudo never sees a partial line. `visudo`-style validation is out of scope (behavior unchanged); only the write mechanism hardens. |
| **Canary Path A becomes noisy / flaky** if a legitimate knob func is missed. | Seed `allowedFunctions` exhaustively from the §2 BestEffortKernelKnob list; run `go test ./pkg/fsatomic/` until green BEFORE committing; the test failure message already names the exact file:line+func to allowlist. |
| **`relpath::func` keying regression** vs existing bare-name map. | Migrate the one existing entry (`restoreSlowPathRPFilter` in `pkg/dhcp` or wherever) to the new key; unit-prove the keyer with a table test. |
| **TLS test needs path injection** — touching a package const. | `const`→`var` or a path-parameterized inner func is a trivially-reviewable seam (mirrors fsatomic's own test seams). |
| **MkdirAllDurable on `/etc/xpf/tls` perms** — 0700 vs existing. | Pass 0700 (matches current `os.MkdirAll(...,0700)`); degrades to plain MkdirAll (no fsync) when the path already exists. |
| **Power-cut between key (durable) and cert (atomic) write** leaves key-only. | Intentional: `tls.LoadX509KeyPair` fails on key-only → clean regen. The eliminated state is *mismatched pair*, which is the issue's stated harm. Documented in code comment. |
| **Bootstrap path runs before fsync-able fs is ready?** | Bootstrap writes happen post-mount on a normal rootfs; no earlier than current `os.WriteFile`. AtomicGeneratedConfig (no fsync) for `.link`/`.network` keeps bootstrap cost identical. |

---

## 8. Validation plan

- `make test` — full Go suite (640+ tests). The rewritten canary must
  pass (proves every in-scope writer migrated or allowlisted).
- New `pkg/api` TLS persistence tests (Step 7) — the three failure modes.
- New/extended `pkg/fsatomic` canary self-checks (Step 6) — scanned-file
  count > 0 (guards the zero-glob bug).
- `go vet ./...`, `gofmt` clean on touched files.
- **Smoke on loss userspace cluster** (`make cluster-deploy` + sanity):
  config commit that exercises hostname / login user with SSH key /
  sudoers / sshd root-login → verify the files land correct and
  `ssh user@fw` works; verify TLS endpoint (`https://127.0.0.1:8080`)
  still serves and `/etc/xpf/tls/*` persist across a daemon restart
  (cert stable = no churn). This is the operator-believable proof that
  the migration changed mechanism, not behavior.
- **No failover test required** — nothing here touches cluster/VRRP/
  session-sync/failover code paths (the §6 file list is config-apply +
  boot + TLS only). State this explicitly in the PR so the
  `make test-failover` gate is consciously waived as not-applicable.
- `make build` + `make build-userspace-dp` compile clean (no Rust change
  expected; confirm).

---

## 9. Rollout / backout

- Pure mechanism change behind existing apply/boot paths; no schema, no
  wire-protocol, no migration. Backout = `git revert` of the PR.
- The canary change is test-only; if it proves too strict it can be
  reverted independently of the writer migrations (the migrations are
  strictly-better even without the canary).

---

## 10. Open questions for reviewers (D-decisions to ratify)

1. **D1**: Path A (writer-class repo-wide scanner) vs Path B (extend
   package allowlist)? Plan recommends A; B is the smaller fallback.
2. **D2**: sshd drop-in = AtomicGeneratedConfig or DurableState? Plan
   recommends DurableState (security posture survives power loss).
3. **D2b**: ssh_known_hosts — keep AtomicGeneratedConfig or promote to
   DurableState? Plan keeps it AtomicGeneratedConfig (does not grant
   access TO the box).
4. **D3**: DNS `atomicWrite` — route happy path through fsatomic
   (B-route, recommended) or leave + allowlist (B-leave)?
5. **D4**: journal `ReadAt` one-line hardening — include or defer? Plan
   recommends include.
6. **TLS ordering**: is ordered-individual-atomic (key-durable then
   cert-atomic, eliminating the mismatch state) sufficient, or does
   review want a stricter both-or-neither (which two renames cannot give
   atomically anyway)?
7. **Dir durability**: confirm `/etc/xpf/tls`, provisioned-users, and
   lifeline dirs each warrant `MkdirAllDurable` vs plain MkdirAll.

---

## 11. Reviewer convergence ledger

See `reviewer-ids.md` for task IDs. Convergence requires all three of
Claude SMR + Codex + AGY to re-review the FINAL revision and reach
PLAN-READY (or PLAN-KILL). Per-round verdicts recorded in
`claude-smr-plan-r<N>.md`, `codex-plan-r<N>.md`, `agy-plan-r<N>.md`.

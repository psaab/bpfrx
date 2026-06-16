# #1917 — In-place xpf upgrade (new xpfd + userspace-dp without re-imaging)

- **Revision:** 6
- **Status:** PLAN-REVISED (round 3 → round 4 confirmation). Round-1: all three
  reviewers PLAN-NEEDS-REVISION (no KILL; composed A+B+C endorsed). Round-2: Codex 3
  blockers (fixed v4), Claude SMR premature-READY (self-corrected), AGY 4 blockers
  (incorporated). Round-3: Codex confirmed 1+3, refined blocker 2 (stop-before-flip,
  fixed v5) + scrubbed stale alias; AGY surfaced FIVE new operational blockers
  (daemon-not-fail-closed, dpkg-deletes-versioned-dir, needrestart, softdog-early-
  boot, GRUB_DEFAULT=saved) — all confirmed against code and folded into v6.
  Awaiting round-4 confirmation for PLAN-READY.
- **Branch:** `research/1917-deb-inplace-upgrade`
- **Scope:** RESEARCH ONLY. No production source touched. Deliverable is this plan
  + three reviewer verdicts + an issue comment. Implementation is a separate
  `/engineer 1917` after manual approval.

---

## 1. Status

Research/plan round. The operator's leading framing — *"ship everything as Debian
packages, let the base Ubuntu OS self-update via apt, and narrow xpf's own upgrade
concern to upgrading xpfd + the dataplane"* — is evaluated hostilely against two
alternatives. The plan must converge a recommended path and surface the hard HA /
protocol / state-compat hazards before any code is written.

## 2. Issue framing

#1917 asks for an **in-place** binary upgrade path (push new `xpfd` +
`xpf-userspace-dp` + the AF_XDP shim object into a running appliance and cut over)
to complement the **replace-image** path that #1879 already shipped. The issue
proposes:

- `verify-dataplane`-before-cut ordering (the #1869 invariant).
- A control-plane-only `xpfd` hot-restart (zero dataplane gap) **vs** a full
  dataplane cycle (a packet gap = a *failover* under HA, not a local restart).
- Protocol-version gating between new `xpfd` and the running helper.
- Atomic binary swap + automatic rollback (`pkg/fsatomic`).
- A `.deb` carrying the binaries/shim/units with a `postinst` that does
  verify-before-cut, fronted by an `xpf-upgrade` (vSRX `request system software
  add`-style) operator command.

The operator adds, as the **leading design to evaluate**: package *all* of xpf
(xpfd, cli, userspace-dp, shim `.o`, units, day-0 loader, initial configs) as
Debian package(s); base OS self-updates via Ubuntu apt channels; xpf's upgrade
concern narrows to the xpf package(s).

## 3. Honest scope and value

**Value is real but bounded, and the issue conflates three separable things:**

1. **Packaging** (how artifacts are delivered: `--copy-in` raw binaries today vs a
   `.deb`). This is #1923 (M1a) + #1924 (M3 signing/hosting). Low risk, high
   hygiene value, mostly mechanical.
2. **In-place runtime swap mechanism** (how a *running* appliance moves from
   binary set N to N+1 without reboot). This is the genuinely hard part #1917
   names, and it is **gated on daemon work that does not exist today** (see §9 the
   "xpfd cannot re-attach to a running helper" invariant).
3. **Base-OS self-update via apt** (kernel + userspace CVEs flow from Ubuntu).
   This has a sharp, under-appreciated edge: an apt-driven **kernel** bump can move
   the running kernel out from under a shim `.o` that was verifier-gated against a
   *different* kernel, and can reboot the box — which is the replace-image blast
   radius the issue tried to avoid. apt self-update of the *base* is not free of
   the dataplane-gap problem.

**The honest verdict to test in review:** the all-`.deb` framing is correct and
desirable for **packaging and distribution** (it subsumes #1923/#1924 cleanly),
but it is **not, by itself, an in-place-upgrade mechanism**. `dpkg`'s
`postinst`/`restart-on-upgrade` model gives you "unpack new files + `systemctl
restart`," which for xpf is a **full dataplane cycle** (a packet gap on a
standalone box; a required *failover* under HA). The `.deb` is the delivery
vehicle; #1917's hard core (control-plane-only hot restart, rolling HA failover,
protocol/state-compat gating, rollback) is **daemon + tooling work that a
`postinst` must *call into*, not re-implement.** A plan that says "ship a `.deb`
and you're done" should be PLAN-KILLed.

## 4. What is already shipped / filed (reconcile)

- **#1879 (merged, PR #1906):** vSRX-style appliance images. `scripts/image/bake.py`
  builds one offline qcow2 + incus image from the latest Ubuntu cloudimg and
  **`virt-customize --copy-in`s the raw binaries** (`xpfd`, `cli`,
  `xpf-userspace-dp`, `xpf-day0-config`) plus `test/incus/xpfd.service` directly
  (bake.py:204-216). It embeds the #1864 tracked shim (no `make generate`),
  installs runtime packages via apt, pins exactly one kernel ≥ 6.18 (the verifier
  floor), and runs an in-guest `verify-dataplane` gate (`validate.py`).
  `scripts/deploy/xpf-deploy.py` is the replace-image deployer; day-0 config drive
  via `make_config_drive.py`. **This is the status quo the `.deb` replaces.**
- **#1923 (M1a, open):** policy-correct `.deb` + `xpf-upgrade` verify-before-unpack
  wrapper; bake consumes the `.deb` instead of `--copy-in`. **#1917 §6 packaging
  IS #1923.** This plan recommends #1917 *subsumes* #1923 as its packaging layer.
- **#1924 (M3, open):** signed, hosted distribution — minisign-signed qcow2/incus
  metadata, Tailscale-style `install.sh`, **signed apt repo**. **#1917's
  "base-OS self-updates via apt" and "signed apt repo for xpf packages" IS #1924.**
  This plan recommends #1917's distribution requirements *defer to / sequence
  after* #1924, and that #1917 not re-invent signing.
- **#1922 (M1b, open):** SAFE-BOOTSTRAP daemon work (bootstrap mode, five-case boot
  predicate, PCI-keyed lifeline, protected-set: never bring down mgmt). **This is a
  hard prerequisite for the "mgmt never stranded" invariant** of any in-place
  upgrade on a non-appliance / foreign host, and for the apt-base-update story (an
  apt action that perturbs interfaces must not strand the lifeline). #1917 should
  declare #1922 a dependency for the foreign-host case and for protected-set.

**Reconciliation summary:** #1917 = the *runtime upgrade mechanism + the operator
workflow + HA rolling story*. It **consumes** #1923 (packaging), **defers to**
#1924 (signing/hosting/apt-repo), and **depends on** #1922 (protected-set / mgmt
lifeline) for the strand-safety invariant. #1917 should be re-scoped as the
umbrella that sequences these, not a parallel fourth effort.

## 5. Multiple path options

### Path A — All-xpf-as-`.deb` + apt-base-OS-updates + xpf-package upgrades (operator's lead)

Package xpf as Debian package(s); base Ubuntu OS self-updates via apt; xpf upgrades
are `apt install xpf=N+1` (or `xpf-upgrade`).

- **Pros:** one delivery format; dependency/version tracking via dpkg; `postinst`
  hook is a natural place for verify-before-cut; subsumes #1923/#1924 cleanly;
  operators get apt familiarity; base CVEs flow automatically.
- **Cons / hostile points:**
  - `apt upgrade` on the **base OS** can pull a **new kernel** and **reboot** — that
    is the replace-image blast radius (NIC re-attach, HA re-sync, day-0 not re-run
    but a reboot gap), *not* low-touch in-place. The shim `.o` is verifier-gated
    against a *specific* kernel floor (≥6.18); an unattended kernel bump can land a
    kernel the tracked `.o` has never been verified against → boot-time
    `verify-dataplane` must gate, and a fail = no dataplane. **Unattended apt of the
    base kernel is unsafe for an appliance** unless gated.
  - `postinst restart xpfd` = **full dataplane cycle** = packet gap (standalone) /
    must-be-failover (HA). dpkg has no concept of "drain RG to peer, upgrade
    passive node, fail back." The rolling-HA choreography cannot live in a
    `postinst` alone.
  - dpkg unpack is **not** atomic across the binary set in the #1917 sense (it
    writes files then runs maintainer scripts); rollback is `apt install
    xpf=N` (the old `.deb` must be retained/pinned) — workable but coarser than a
    staged verify-then-rename with auto-revert.
  - **Recommended refinement:** keep the `.deb` as the *packaging+distribution*
    layer (A is right for that), but the `postinst` must **delegate** the cut-over
    to `xpf-upgrade`/xpfd, which owns verify-before-cut, the control-plane-only vs
    full-cycle decision, and the HA rolling drive. Pin the **base kernel** (hold
    `linux-*` or use a dedicated, tested kernel meta-package channel) so base apt
    updates cannot silently move the verifier floor. This is "A for packaging, with
    the hard mechanism delegated, and the kernel held."

### Path B — Binary-swap `xpf-upgrade` wrapper, no `.deb`

`xpfd upgrade --stage <dir>` / a Python tool consistent with #1879 deploy tooling:
stage new binaries to a temp path → run new `xpfd verify-dataplane` against the
running kernel → atomic rename via `pkg/fsatomic` → control-plane-only restart or
full cycle → automatic rollback on verify/health failure. HA = rolling failover.

- **Pros:** maximal control over the cut-over choreography; no dpkg semantics to
  fight; the staged-verify-then-rename-with-auto-revert is exactly #1917's ask;
  reuses #1869 verify gate, VRRP/session-sync failover, `pkg/fsatomic`.
- **Cons:** reinvents versioning/dependency tracking that dpkg gives for free; no
  standard distribution channel (must build #1924-equivalent anyway); harder for
  operators who expect apt; the binaries-on-disk are unmanaged by the package DB
  (drift, no `dpkg -V`).

### Path C — Image-replace only (status quo for the appliance)

Do nothing new; #1879 replace-image is the only upgrade path. Build a new image,
deploy a new VM, copy `xpf.conf`/`node-id`, swap traffic (HA re-sync).

- **Pros:** kernel + userspace move as one tested, verifier-gated unit; zero new
  code; highest confidence per upgrade.
- **Cons:** highest blast radius and operator effort for a one-line xpfd bugfix;
  NIC re-attach; HA re-sync; not "low-touch." Fails the issue's stated goal for the
  common case.

### Recommended path: **A (packaging) + B (mechanism), composed; C retained as the heavy-release path.**

The `.deb` (Path A, subsuming #1923; distribution via #1924) is the right delivery
and version-management layer. The **in-place cut-over mechanism is Path B** — a
staged-verify-then-atomic-swap with control-plane-only vs full-cycle modes and
HA-rolling-failover drive — owned by `xpfd`/`xpf-upgrade`, and **invoked from the
`.deb` `postinst`**. The **base kernel is held/pinned** so apt base-updates can't
move the verifier floor; kernel bumps go through Path C (image replace), the tested
unit. This composition is what the rest of this plan designs.

## 6. Concrete design for the recommended path

### 6.1 Package layout (Path A subsuming #1923)

**The shim is EMBEDDED, not a file (round-1 correction).**
`pkg/dataplane/userspace_xdp_rust.go:11` is `//go:embed userspace_xdp_bpfel.o`;
`verify-dataplane` → `VerifyEmbeddedUserspaceShim` (verify_userspace_shim.go:50)
and the production loader `loadRustUserspaceXDP()` (loader_userspace_shim.go:82)
both consume the *embedded* bytes. A `.deb` shipping a separate `.o` file is dead
weight nobody loads, and a drift hazard. **The shim therefore travels inside the
`xpfd` binary; no separate shim file is packaged.**

One binary package + one metapackage (round-1: two-package split bought nothing
once the shim is embedded — the protocol pair is enforced by *versioned immutable
paths*, §6.3a, not by dpkg `Depends:` metadata which an old xpfd can ignore):

- **`xpf`** — the `.deb` installs the binary set to a **dpkg-static staging path**
  `/usr/local/share/xpf/staged/{xpfd,xpf-userspace-dp,cli,xpf-day0-config,xpf-upgrade}`
  (NOT a versioned dir — see §6.3c: dpkg deleting an old versioned dir would destroy
  the rollback target). `xpf-upgrade` copies the staged set into a
  **non-dpkg-managed runtime versioned dir** `/var/lib/xpf/versions/<version>/` and
  the live symlinks point THERE. Plus `xpfd.service`, `xpf-day0-config.service`, the
  `needrestart` override (`/etc/needrestart/conf.d/xpf.conf`), and the GRUB
  `GRUB_DEFAULT=saved` drop-in (§6.3c). The live
  paths `/usr/local/sbin/{xpfd,cli,...}` are **symlinks** into the active
  versioned dir, flipped atomically by `xpf-upgrade` (§6.3a) — NOT written
  directly by dpkg. xpfd and the helper ship and move as one matched-protocol
  unit (so `ProtocolVersion` cannot split in the common upgrade).
- **`xpf-appliance`** (metapackage) — pulls `xpf` + runtime deps (frr, strongswan,
  kea, chrony, …, the current `RUNTIME_PACKAGES` set) + a **held/pinned kernel
  channel** (§6.7). This is what the bake installs.

**Initial/default config:** ship **no** operator `xpf.conf` in the `.deb`
(`conffiles` would fight day-0 and commit/rollback). The factory bootstrap (fxp0
DHCP) + day-0 config drive (#1879) remain the config-injection path. The `.deb`
ships only *non-operator* defaults (the units, sysctl drop-in, sshd factory
posture, grub `init_on_alloc=0` drop-in) — and even those should be plain package
files, not `conffiles`, where a commit/day-0 flow owns the live value. **State in
`/etc/xpf/.configdb` and `/etc/xpf/node-id` is NOT package-owned** (it's runtime
state) — `dpkg` must never touch it; `postrm purge` must not delete it.

### 6.2 systemd unit ownership

`xpfd.service` becomes package-owned (moves out of `test/incus/` into the package,
with the test env consuming the packaged unit). Add to the unit:

- `ExecStartPre=/usr/local/sbin/xpfd verify-dataplane` (the #1869 gate at every
  start — a verifier-failing shim never reaches `ExecStart`). Exit 3 = REJECT.
- Keep `Restart=on-failure`, `RestartSec=1`, `TimeoutStopSec=20`, `LimitMEMLOCK=infinity`.
- The helper is **not** a separate unit (it is an xpfd child today, process.go:76);
  the package does not add a `xpf-userspace-dp.service`. (Whether to *split* the
  helper into its own unit so it can outlive an xpfd restart is the §6.4 daemon
  question — out of scope for packaging, in scope for the mechanism.)

### 6.3a Versioned immutable paths + atomic-symlink flip (round-1 blocking fix)

dpkg metadata (`Depends: = same version`) does NOT prevent an old `xpfd` from
respawning whatever helper is on the live path (`findBinary`/`exec.Command`,
process.go:168/76), so it cannot by itself guarantee a matched protocol pair, and
a naive in-place file overwrite can leave a half-swapped set serving traffic. The
plan therefore mandates: **binaries install to a versioned dir
`/usr/local/lib/xpf/<version>/`; the running paths are symlinks; the cut-over is a
single atomic symlink flip owned by `xpf-upgrade` after verify PASS.** dpkg only
*stages* the new versioned dir; it never touches the live symlink. This makes the
"never serve a half-swapped set" and "matched protocol pair" invariants
structural, not advisory.

**The symlink flip alone is NOT sufficient — the running daemon must be pinned or
stopped before the flip (round-3 Codex refinement).** Deleting the live-overwrite
form does not by itself close the old-xpfd-respawns-new-helper window: the running
`xpfd.service` uses `ExecStart=/usr/local/sbin/xpfd` and `findBinary` searches
`filepath.Dir(os.Args[0])` then PATH (process.go:168), so if the live
`/usr/local/sbin` symlink is flipped *while the old daemon is up*, that old daemon
can resolve and respawn the NEW helper (protocol mismatch). The mechanism MUST
therefore enforce ONE of: (a) **stop-before-flip ordering** — `xpf-upgrade` stops
the old `xpfd` (standalone: the bounded full-cycle gap; HA: after the RG drain to
peer) BEFORE flipping the symlink, then starts the new daemon; OR (b) **versioned
`ExecStart` + helper config** — `xpfd.service` `ExecStart` and the helper
`--dataplane binary` config point at the *versioned* path, and `xpf-upgrade`
rewrites them + `daemon-reload`s as part of the atomic cut, so no process ever
straddles two versions via the live symlink. The plan recommends (a) for the
common full-cycle path (it is the simplest correct ordering and the gap is already
accepted) and (b) for the M-mech-2 future hot-restart path. Either way the
invariant is: **no running daemon resolves a binary of a different version than
the one it was started with.**

**`dh_installsystemd` auto-restart MUST be disabled (round-2 AGY blocker).** The
default Debian helper appends a `systemctl try-restart xpfd.service` block to the
generated `postinst` on upgrade — which would fire a full dataplane cycle on *any*
`apt upgrade xpf`, defeating the "dpkg only stages" design even though our custom
`postinst` never flips the symlink. `debian/rules` MUST call
`dh_installsystemd --no-stop-on-upgrade` (NOT `--restart-after-upgrade`; prefer
`--no-stop-on-upgrade` since `--no-restart-on-upgrade` is a documented *deprecated
alias*, round-2 Codex note) and pin the `debhelper-compat` level explicitly so the
helper's restart-class behavior is stable across debhelper versions. The live
restart happens ONLY when `xpf-upgrade` explicitly drives it after a verify PASS.

**Run the NEWLY-STAGED orchestrator, not the live symlink (round-2 AGY blocker).**
After `apt upgrade` stages N+1 under `/usr/local/lib/xpf/<N+1>/`, the live
`/usr/local/sbin/xpf-upgrade` symlink still points at N, which may lack the N+1
protocol/orchestration logic. The `postinst` and the operator runbook MUST invoke
the *staged* `/usr/local/lib/xpf/<N+1>/xpf-upgrade cut-over` to drive the cut,
never the live-symlink path. The staged orchestrator owns the verify, the symlink
flip, and (standalone) the restart.

### 6.3b Daemon MUST fail-closed on a config-DB parse error (round-3 AGY blocker — critical)

The old-reader-rejecting envelope (§8) makes binary N's `db.ReadActive` *return an
error* on N+1 state — but that is necessary, NOT sufficient, because the daemon
startup is currently LENIENT. Verified: `store.New` fails closed only when the
`.configdb` directory is unusable (store.go:104); but `Store.Load()` returning a
*parse* error is handled by the caller in `daemon_run.go` by **logging a warning
and proceeding** — then, because `ActiveConfig()` is nil, it calls
`bootstrapFromFile()` (daemon_apply.go:32) which `Commit()`s `/etc/xpf/xpf.conf`
and **overwrites the unparseable `active.json`**, erasing the DB; absent that file
it starts with empty config. So the min-reader gate is defeated at the daemon
layer. **The mechanism MUST change daemon startup so a config-DB parse error
(anything except `os.IsNotExist`) is FATAL — exit immediately, do NOT bootstrap or
run unconfigured.** This is a small daemon change that #1917 owns (it is the
enforcement half of the manifest gate). Test: binary N handed an N+1 envelope
exits non-zero and leaves `active.json` byte-for-byte unchanged.

### 6.3c dpkg-static staging vs runtime versioned dirs + needrestart + GRUB (round-3 AGY blockers)

Three packaging hazards that defeat the "dpkg only stages, never cuts" design and
the kernel-fallback, all confirmed real:

- **dpkg deletes the old versioned dir on upgrade.** If the package installs
  binaries directly to `/usr/local/lib/xpf/<version>/`, upgrading N→N+1 makes dpkg
  remove `/usr/local/lib/xpf/<N>/` — destroying the rollback target AND any binary
  a still-running N daemon might re-exec mid-transaction. **Fix:** separate
  dpkg-owned *staging* from runtime: the `.deb` installs to a STATIC path
  (`/usr/local/share/xpf/staged/`); `xpf-upgrade` copies the staged set into a
  **non-dpkg-managed** runtime versioned dir (`/var/lib/xpf/versions/<version>/`)
  and the live symlink points there. dpkg never deletes a runtime version; rollback
  retains N+ the previous known-good.
- **`needrestart` will restart the daemon regardless of `dh_installsystemd`.**
  Ubuntu server installs `needrestart` by default; at the end of an apt transaction
  it scans for processes running *deleted* binaries and auto-restarts them —
  cutting the dataplane mid-`apt` even with `--no-stop-on-upgrade`. **Fix:** ship
  `/etc/needrestart/conf.d/xpf.conf` blacklisting `xpfd.service` / the xpf binary
  paths from auto-restart. (The dpkg-static-staging fix above also helps: if the
  *running* binary's path is never deleted, needrestart has nothing to trigger on.)
- **`grub-reboot` requires `GRUB_DEFAULT=saved`.** The §6.7 one-shot kernel boot
  silently no-ops (or boot-loops) if the appliance image hardcodes `GRUB_DEFAULT=0`.
  **Fix:** the bake / package postinst must set `GRUB_DEFAULT=saved` (+
  `GRUB_SAVEDEFAULT` handling) and `update-grub`; `xpf-upgrade kernel` asserts it
  before arming a one-shot boot.

### 6.3 The `.deb` `postinst` — verify-before-cut, delegating the mechanism

`postinst configure` must NOT naively `systemctl restart xpfd`. It must:

1. Run the **new** `xpfd verify-dataplane` against the **running** kernel. On exit
   3 (verifier REJECT) or 1 (error): **abort the cut-over** (the package files are
   staged under the versioned dir; the live symlink is NOT flipped), surface the
   exit code, and leave the running set serving traffic. **There is exactly ONE
   install form (round-2 Codex blocker — the "simplest dpkg-native install to
   /usr/local/sbin" alternative is DELETED):** binaries install ONLY to
   `/usr/local/lib/xpf/<version>/`; the cut is the atomic symlink flip owned by
   `xpf-upgrade` (§6.3a). A live `/usr/local/sbin` overwrite is forbidden because
   the running xpfd resolves the helper from its own dir / PATH
   (`findBinary`, process.go:168) and would respawn a newly-unpacked helper before
   the intended cut — reopening the protocol-mismatch window. The staged
   orchestrator MUST launch the staged `xpfd`/helper by **absolute versioned
   path**, never via PATH or the live symlink.
2. Detect **HA vs standalone** (presence of `/etc/xpf/node-id`). Standalone: do the
   verified cut (control-plane-only if eligible, else full cycle with a bounded,
   measured gap + auto-rollback on post-cut health failure). HA: **do not cut
   locally**; print/log that the operator (or `xpf-upgrade --rolling`) must drive
   the rolling failover (drain this node's RGs to the peer, restart here, fail
   back, then repeat on the peer). A `postinst` cannot safely orchestrate a
   two-node rolling upgrade by itself.

### 6.4 The xpfd + dataplane upgrade / restart / HA-rolling story (the hard core — Path B mechanism)

**Critical invariant discovered (see §9):** today **xpfd cannot re-attach to a
still-running helper.** The helper is spawned as an `exec.Command` child and its
`*exec.Cmd` is held in xpfd process memory (`m.proc`, process.go:24-86). A new xpfd
process starts with `m.proc == nil`; the *first* thing it does on bind is
`stopLocked()` any prior helper it knows about and **spawn a fresh helper**, which
**clears the XSKMAP** (process.go:64-71, dead socket fds) and loses all in-process
session + CoS-timer-wheel state. **Therefore "control-plane-only xpfd hot-restart
with ZERO dataplane gap" is NOT achievable with the current architecture** — it is
new daemon work, not a packaging concern. This plan must say so plainly; a reviewer
treating the issue's "Acceptance: standalone xpfd-only restart with zero dataplane
gap" as already-feasible is wrong.

Two sub-mechanisms, sequenced:

- **M-mech-1 (full dataplane cycle, achievable now):** stage → verify → cut →
  `systemctl restart xpfd` → fresh helper → snapshot republish → session re-sync.
  Standalone: bounded packet gap (measure it; ~the helper 3s NAPI bootstrap window
  is the floor, process.go:108-112 — that is a *seconds* gap, not milliseconds; the
  acceptance bar of "brief outage" must be quantified honestly). HA: this gap is
  unacceptable under live traffic, so it MUST be a failover — drain RGs to peer
  first (`cluster.Manager.ForceSecondary()` sets RG weights 0 → VRRP demote → peer
  primary in ~60ms), restart the now-passive node, restore weights, repeat on peer.
  This reuses the `make test-failover` path exactly.
- **M-mech-2 (control-plane-only hot restart, FUTURE daemon work, gated):** to get
  a true zero-gap xpfd restart, the helper must be **decoupled from xpfd's process
  lifecycle** — either (a) split `xpf-userspace-dp` into its own systemd unit that
  outlives xpfd and is connected-to (not spawned-by) over the control socket, with
  xpfd re-attaching by reading the PID/socket from `/run/xpf/userspace-dp.json` and
  *not* clearing the XSKMAP / not stopping a healthy helper on reconnect; or (b)
  socket-activation / fd-passing. This is a substantial daemon change with its own
  protocol-stability contract (the running helper must speak the new xpfd's
  protocol — §6.5) and its own `/research`+`/engineer`. **#1917 should explicitly
  scope M-mech-2 as a follow-up** and ship M-mech-1 (full cycle + HA rolling) first.

### 6.5 Wire/protocol compatibility

`ProtocolVersion = 3` (protocol.go:11) is embedded in every `ConfigSnapshot`; the
Rust side declares the matching `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 3`
(control.rs); mismatch is a hard reject in version-sensitive ops. Because the `xpf`
package `Depends:` on `xpf-dataplane (= same version)` (§6.1), the **common**
upgrade moves both in lockstep → no live mismatch. The dangerous window is
**M-mech-2 only** (xpfd restarts while a helper of a different version stays up):
there the new xpfd must gate on a protocol-version match read from the running
helper's `ping`/status, and **force a full dataplane cycle (M-mech-1) on
mismatch** rather than attempt a hot re-attach. The `XPF_PROTOCOL_WIRE_REGEN`
fixtures + key-absent pins are the compatibility test surface to extend with a
"new-xpfd vs old-running-helper protocol-gate" case.

### 6.7 The held/verify-gated kernel channel (resolves the Path-A contradiction)

The operator premise "base OS self-updates via apt" is **partially self-defeating**
because the shim is verifier-gated to a kernel floor (≥6.18), so an unattended
kernel bump can land a kernel the embedded `.o` has never been verified against.
The honest restatement: **userspace self-updates freely via apt; the KERNEL does
NOT free-update.** The plan offers a *verify-gated kernel channel* rather than a
permanent blanket hold:

- `linux-*` is held by default (`apt-mark hold`), so unattended `apt upgrade`
  cannot move the floor.
- A kernel bump is an explicit operator action (`xpf-upgrade kernel <ver>`).
  **`verify-dataplane` cannot validate an unbooted kernel (round-2 AGY blocker):**
  the BPF verifier is kernel-space — `ebpf.NewCollection` (verify_userspace_shim.go)
  loads the spec into the *running* kernel, so the candidate kernel must actually
  be running to be verified. The mechanism is therefore a **one-shot boot +
  watchdog fallback, NOT a verify-then-set-default**: install the candidate kernel,
  `grub-reboot <candidate>` (boot it exactly once without changing the default),
  on that boot a oneshot unit runs `verify-dataplane` + a health check; on PASS it
  promotes the candidate via `grub-set-default`. **The no-show/boot-hang fallback
  needs a watchdog ARMED BEFORE the reboot (round-2 Codex blocker), or the "never
  brick" claim is overstated.** Concretely: arm a **HARDWARE / hypervisor-level
  watchdog** (`/dev/watchdog`, systemd `RuntimeWatchdogSec`) such that if the
  candidate kernel never reaches the promotion oneshot (early-boot hang, no
  `systemd`), the watchdog resets the box. **`softdog` is INSUFFICIENT (round-3 AGY
  blocker):** a kernel software watchdog cannot fire if the candidate kernel hangs
  in decompression / early init *before* the softdog module + systemd load and arm
  it — that path bricks. The HW/hypervisor watchdog fires independently of the
  candidate kernel reaching userspace. Because GRUB's *default* was never changed
  (`grub-reboot` is one-shot, and REQUIRES `GRUB_DEFAULT=saved` — §6.3c), the reset
  boots the OLD default. The promotion oneshot must (a) run early enough to
  pet/disarm the watchdog only AFTER a `verify-dataplane` PASS + health beacon,
  (b) write a durable promotion marker, (c) within a bounded deadline. **Honest
  bound:** with a HW/hypervisor watchdog this is brick-proof against boot hangs;
  with only `softdog` or pure `grub-reboot` the GRUB default is preserved but an
  early-boot hang needs external/operator recovery — the plan REQUIRES the
  HW/hypervisor watchdog for the "never brick" guarantee. HA: do the
  one-shot kernel boot on the drained/secondary node only, sequenced inside the
  rolling drive so both nodes never reboot together.
- Heavy/uncertain kernel moves still go through Path C (image-replace), the
  fully-tested unit.

This converts "hold the kernel forever" (which guts Path A's value) into "the
kernel updates through a tested gate," which preserves the appliance's verifier
invariant without abandoning kernel CVE remediation.

### 6.6 How the bake consumes the `.deb` (replaces `--copy-in`)

`bake.py` `virt_customize()` drops the 6 `--copy-in` lines for the xpf binaries +
units and instead: build the `.deb`s in the artifact step → `--copy-in` the `.deb`
files into the image once → `--run-command "apt-get install -y
./xpf-appliance_<ver>.deb"` (or from the #1924 signed local apt repo). The kernel
pin / one-kernel assert / verify-dataplane gate logic in bake.py is unchanged; the
`xpf-appliance` metapackage just becomes the thing installed. The embedded-shim /
`make generate`-skip behavior is preserved because the shim ships *inside* the
`xpf-dataplane` package built from the same tracked `.o`.

## 7. Preserved interfaces (must not change)

- `xpfd verify-dataplane` exit-code contract (0 PASS / 3 REJECT / 1 error) — bake,
  postinst, and ExecStartPre all depend on it.
- The control-socket JSON protocol (`ping`/status, `apply_snapshot`, session sync)
  and `ProtocolVersion = 3` semantics.
- `pkg/fsatomic` `WriteFileDurable` / `WriteFileAtomic` / `MkdirAllDurable`
  semantics (the swap+rollback primitives).
- The day-0 config drive + fxp0 DHCP factory bootstrap (#1879) — config injection
  path; the `.deb` must not ship an operator `xpf.conf` that fights it.
- `/etc/xpf/.configdb`, `/etc/xpf/node-id`, `master.key` — runtime state, never
  package-owned, never removed by `postrm`.
- The HA failover/drain path (`ForceSecondary`/`ManualFailover`, VRRP demote,
  session-sync) reused verbatim for rolling upgrade.
- The #1864 shim-verifier gate + the pinned kernel floor (≥6.18).

## 8. Hidden invariants

- **xpfd cannot re-attach to a running helper (§6.4)** — zero-gap xpfd-only restart
  is future daemon work, NOT a packaging deliverable. THE load-bearing invariant.
- **Config-DB version compatibility (configstore):** `active.json` is a marshaled
  `config.ConfigTree` unmarshaled by the *current* binary; rollback slots are
  re-parsed text; **no on-disk manifest records writer/min-reader version**
  (confirmed: db.go has no version field). An upgrade that changes accepted/emitted
  config syntax can make the *rollback* binary fail to parse on-disk state — a
  split-brain hazard under HA rolling (node A writes new-syntax state, node B old
  binary can't parse after failover). **The issue's own codex-review-010 comment
  already demands a `.configdb/manifest.json` (writer version, AST/schema version,
  min-reader version, rollback-slot format version, journal schema version) +
  startup validation + gating auto-rollback on "state-format floor not advanced."
  This plan adopts that requirement verbatim as a §6 deliverable.**
  **First-upgrade chicken-and-egg, resolved (round-1):** absence of a manifest is
  NOT corruption. The manifest's job is *forward*-gating (an old binary refusing
  too-new state), not backward corruption detection. The N→N+1 boot defines these
  no-manifest cases explicitly: (a) **fresh install** — no `active.json`, no
  manifest → start clean, write a manifest on first commit; (b) **legacy
  parseable state** — `active.json` present, no manifest → treat as
  schema-version-0, parse normally, write a manifest on first successful load;
  (c) **missing active**, rollback slots present → existing boot fallback,
  manifest-version-0; (d) **corrupt/truncated active** — caught by the existing
  `json.Unmarshal` error path independent of the manifest, so manifest absence
  never masks corruption; (e) **encrypted active with/without `master.key`** —
  the manifest version is readable pre-decrypt so a min-reader gate fires before a
  decrypt failure is misread as corruption. Only once a manifest EXISTS does its
  `min_reader_version` gate a too-old binary. This makes the manifest purely
  additive and safe for the very first upgrade.
  **The manifest must NOT be a second file (round-2 AGY blocker):** writing
  `manifest.json` separately from `active.json` opens a crash-consistency gap (a
  power cut between the two leaves a mismatched DB). Embed the version metadata IN
  `active.json` so the existing single-file `fsatomic.WriteFileDurable` rename
  stays the atomic unit.
  **The envelope MUST use an old-reader-REJECTING encoding (round-2 Codex
  blocker — critical).** A naive object envelope
  `{ "manifest": ..., "tree": <ConfigTree> }` is UNSAFE: `config.ConfigTree` has
  only a `Children` field (ast.go:98) and Go's `json.Unmarshal` *silently ignores
  unknown object fields*, so old binary N would parse the envelope object into an
  **empty tree** instead of failing closed — defeating the `min_reader` gate and
  booting/rolling into empty config. The encoding must therefore be one that the
  legacy `json.Unmarshal(data, *ConfigTree)` at db.go:124 *rejects with an error*:
  e.g. a **magic line-prefix header** (`# xpf-configdb v=<n> min_reader=<n>\n` then
  the JSON body — a leading `#` makes the whole blob invalid JSON to an old reader,
  which fails closed), or a top-level JSON **array** `[manifest, tree]` (an old
  reader unmarshaling an array into a struct errors). The same prefix/array wraps
  the encrypted form so the version is readable pre-decrypt. The new reader strips
  the header (or reads element 0), gates on `min_reader`, then parses the body; a
  **bare object with no header = legacy schema-0** (case (b)). **A
  legacy-reader test is mandatory: prove binary N fails closed (errors), NOT
  empty-loads, when handed an N+1 envelope.** Alternatively ship one
  compatibility release that can *read* envelopes before any release *writes* one.
- **Shim verifier gate must hold post-cut and post-kernel-bump:** ExecStartPre
  verify on every start; bake-time assert one kernel ≥6.18; **base apt kernel
  updates HELD by default** and only moved through the §6.7 verify-gated kernel
  channel (verify the embedded shim against the candidate kernel before making it
  boot default) or a tested image-replace. The operator premise is restated:
  **userspace self-updates via apt; the kernel does NOT free-update** (RISK #2).
- **HA auto-rollback is unsafe mid-rolling (round-1, RISK #7):** heartbeat already
  carries the software version (`heartbeat.go:66`) but it is *surfaced, not gated*
  (`status.go:34`); only HA-protocol mismatch blocks transfer readiness
  (`daemon_ha_userspace.go:930`). So **auto-rollback is standalone-only**; in HA a
  node that fails post-cut health stays drained/secondary and ALERTS rather than
  auto-reverting into a version-split cluster. A future enhancement may *gate*
  takeover on a software-version transaction, but #1917 ships operator-driven HA
  rollback.
- **Honest dataplane gap (round-1, RISK #1/#6):** a standalone full cycle is a
  **measured multi-second outage**, not "brief": helper respawn has a 3s NAPI
  bootstrap window (process.go:98), ctrl-enable adds 3s standalone / 15s HA
  (maps_sync.go:370/392), and XSK liveness can run up to 10s (maps_sync.go:482).
  The plan commits to *measuring* it; if the number is unacceptable for a
  standalone box, that box should use image-replace (Path C), and the issue's
  "zero dataplane gap" standalone acceptance is **unmeetable without the future
  M-mech-2 decoupled-helper work**.
- **Mgmt never stranded:** a cut-over / apt action must not bring down fxp0 or the
  lifeline NIC. This is #1922's protected-set; #1917 depends on it for foreign-host
  / non-appliance installs and for any apt action that perturbs interfaces.
- **HA rolling = exactly one node down at a time**, never both; sync-hold and
  session re-sync must complete before failing the second node (else connection
  loss). Reuse the `preempt=false` sync-hold release path.
- **Deploy-wipes-CoS-style gotcha:** any restart drops the CoS timer-wheel + the
  per-flow CoS state; an in-place full cycle has the same "re-apply CoS after
  deploy" footgun the cluster runbook calls out. The upgrade tooling must
  re-publish CoS config post-cut (or document the re-apply step), or fairness
  silently regresses to default.
- **`postinst` must be idempotent + fail-closed:** a failed verify must leave the
  *running* dataplane untouched (no half-swapped binary set serving traffic).

## 9. Risk table (4 classes)

| # | Risk | Class | Likelihood | Impact | Mitigation |
|---|------|-------|-----------|--------|------------|
| 1 | Operator/plan assumes zero-gap xpfd-only restart exists → ships a "hot restart" that actually full-cycles the dataplane (seconds gap) | Correctness/Design | High | High | §6.4: state plainly it does NOT exist; scope M-mech-2 as future daemon work; ship M-mech-1 (full cycle + HA rolling) honestly with a *measured* gap |
| 2 | apt base-OS update pulls a new kernel out from under the verifier-gated shim `.o` → dataplane fails verify at boot, box has no dataplane | Availability | Med | Critical | Hold/pin `linux-*`; kernel bumps go through image-replace (Path C); boot ExecStartPre verify fails closed; document the held-kernel channel |
| 3 | Config-DB / rollback-slot format drift across versions → rollback binary or HA peer can't parse on-disk state (split-brain) | Data/Correctness | Med | High | `.configdb/manifest.json` (writer/min-reader/AST/rollback/journal versions) + startup validation + gate auto-rollback on state-floor advance (codex-review-010) |
| 4 | `postinst restart` on an HA node cuts traffic instead of failing over (no rolling orchestration in dpkg) | Availability | High | High | `postinst` detects `/etc/xpf/node-id`, refuses local cut on HA, requires `xpf-upgrade --rolling`; reuse `ForceSecondary`/VRRP drain |
| 5 | Protocol-version mismatch during an M-mech-2 hot re-attach (new xpfd ↔ old helper) | Correctness | Low (lockstep `Depends:`) | High | `Depends: xpf-dataplane (= same version)`; gate on `ping` protocol version; force full cycle on mismatch; extend WIRE_REGEN fixtures |
| 6 | Half-unpacked binary set serves traffic if `postinst` aborts mid-way | Correctness/Availability | Med | High | Versioned install paths + atomic-symlink flip owned by `xpf-upgrade`; running paths unchanged until verify passes |
| 7 | `postrm purge` deletes `/etc/xpf/.configdb`/`node-id`/`master.key` | Data loss | Med | Critical | Explicitly exclude runtime state from package ownership; `postrm` never touches `/etc/xpf` |
| 8 | CoS / per-flow state silently lost after an in-place full cycle (deploy-wipes-CoS gotcha) | Perf/Fairness | High | Med | Re-publish CoS config post-cut in `xpf-upgrade`; document re-apply; add a post-cut CoS-present check |
| 9 | `dh_installsystemd` auto-appends `try-restart` to `postinst` → any `apt upgrade xpf` cuts the dataplane | Availability | High | High | `debian/rules`: `dh_installsystemd --no-stop-on-upgrade` + pinned debhelper-compat; live restart only via `xpf-upgrade` post-verify (§6.3a) |
| 10 | Verify-gated kernel channel tries to verify an *unbooted* kernel (impossible — verifier is in the running kernel) → bad kernel could brick the node | Availability | Med | Critical | One-shot `grub-reboot` + boot-watchdog auto-fallback to old default; promote only on a PASS health beacon (§6.7) |
| 11 | Non-atomic manifest: power cut between `active.json` and a separate `manifest.json` → mismatched DB | Data/Correctness | Med | High | Embed manifest IN `active.json` (envelope/header), keep the single-file `fsatomic` rename atomic (§8) |
| 12 | Rolling upgrade driven by the *old* `xpf-upgrade` symlink (N) lacking N+1 orchestration logic | Correctness | Med | High | `postinst`/runbook exec the *staged* `/usr/local/share/xpf/staged/xpf-upgrade` (§6.3a/§6.3c) |
| 13 | Binary N can't parse N+1 envelope but daemon LOGS-AND-PROCEEDS → bootstrapFromFile overwrites active.json or runs empty (min-reader gate defeated at daemon layer) | Data/Availability | Med | Critical | Make config-DB parse error (non-IsNotExist) FATAL at startup — no bootstrap, no unconfigured run (§6.3b, daemon_run.go fix) |
| 14 | dpkg deletes old `/usr/local/lib/xpf/<N>/` on upgrade → rollback target + mid-txn re-exec binary gone | Availability | High | High | dpkg installs to static `/usr/local/share/xpf/staged/`; `xpf-upgrade` copies to non-dpkg `/var/lib/xpf/versions/<ver>/` (§6.1/§6.3c) |
| 15 | `needrestart` (default on Ubuntu server) auto-restarts xpfd running a deleted binary → cuts dataplane mid-apt regardless of dh flags | Availability | High | High | Ship `/etc/needrestart/conf.d/xpf.conf` blacklist; static staging means running path is never deleted (§6.3c) |
| 16 | `softdog` can't catch a candidate-kernel early-boot hang (loads after the hang) → brick | Availability | Med | Critical | Require HW/hypervisor `/dev/watchdog`, not softdog, for the never-brick guarantee (§6.7) |
| 17 | `grub-reboot` no-ops / boot-loops if image hardcodes `GRUB_DEFAULT=0` | Availability | Med | High | Set `GRUB_DEFAULT=saved` in bake/postinst; `xpf-upgrade kernel` asserts it before arming (§6.3c/§6.7) |

## 10. Test plan

**Standalone in-place upgrade (M-mech-1):**
- Build the `xpf` (+ `xpf-appliance`) `.deb` at commit N and N+1 (single binary
  package — shim embedded, §6.1).
- On the standalone test VM (`make test-deploy` env): `apt install xpf=N`, establish
  iperf3 + long-lived sessions, `apt install xpf=N+1`, assert: verify-dataplane ran
  and passed before cut; **measure and bound the dataplane gap** (iperf3 retr +
  drop window); sessions re-establish; CoS re-applied; `dpkg -V xpf` clean.
- Negative: stage a `.deb` whose shim fails verify (e.g., built against a stale
  header) → assert the cut is REFUSED, old dataplane keeps forwarding, exit 3
  surfaced, auto-rollback restores binary N.

**HA rolling upgrade:** on `loss:xpf-userspace-fw0/fw1`: `make cluster-deploy` at N,
run the `failover-test` iperf3 harness, drive `xpf-upgrade --rolling` to N+1
(drain fw0 RGs → peer, upgrade fw0, fail back, then fw1). **Acceptance = zero
connection loss**, `make test-failover`-equivalent evidence (0-retr / 0-drop across
the two node cuts). Negative: protocol-version mismatch between staged xpfd and the
peer's running helper → assert safe full-cycle fallback, no split-brain.

**Base-OS apt update does not break xpf:** on the appliance image, `apt update &&
apt upgrade` with `linux-*` HELD → assert: no kernel change, xpfd/helper unaffected,
verify-dataplane still passes, dataplane uninterrupted. Then explicitly *unhold* and
bump the kernel in a throwaway VM → assert boot ExecStartPre verify GATES (PASS on a
≥6.18 tested kernel; REJECT path leaves no dataplane but a recoverable box via
console). Confirms the "hold the kernel" mitigation is load-bearing.

**Packaging guards (round-2):** assert the built `.deb`'s generated `postinst`
contains NO `systemctl ... restart`/`try-restart` block (grep the maintainer
script) — proves `--no-stop-on-upgrade` took (no restart/try-restart block emitted). Assert `apt upgrade xpf` on a
running standalone box does NOT bounce the daemon until `xpf-upgrade` is invoked.
Assert the staged `/usr/local/lib/xpf/<N+1>/xpf-upgrade` is the binary that runs
the cut (not the live symlink). Negative kernel test: `grub-reboot` a deliberately
verifier-failing candidate kernel → assert the box auto-falls-back to the old
default and the old default stays the boot default (no brick).

**Config-DB compat:** write `active.json` + rollback slot with binary N+1 that
emits a new leaf; attempt to boot binary N → assert binary N **exits non-zero**
(daemon fail-closed, §6.3b) and leaves `active.json` byte-for-byte unchanged (NOT
a silent bootstrap-overwrite or degraded empty load); assert auto-rollback is
refused when the state floor advanced. Also assert the old-reader-rejecting
encoding: feed binary N an N+1 envelope directly to `db.ReadActive` → error, not an
empty `ConfigTree`.

**Packaging hazards (round-3):** assert dpkg upgrade N→N+1 does NOT delete the
running version's binaries (static staging + runtime versioned dir); assert
`needrestart` does not bounce `xpfd` during the apt transaction (override present +
running path not deleted); assert `GRUB_DEFAULT=saved` is set so `grub-reboot`
works; assert local rollback still has the previous version's binaries on disk.

## 11. Out of scope

- M-mech-2 (decoupled-helper zero-gap xpfd-only hot restart) — scoped as a follow-up
  daemon `/research`; #1917 ships M-mech-1.
- Artifact signing, minisign, hosted apt repo, `install.sh` — that is **#1924**;
  #1917 defers to it and does not re-invent signing.
- SAFE-BOOTSTRAP daemon hardening (bootstrap mode, five-case predicate, PCI-keyed
  lifeline, protected-set) — that is **#1922**, a declared dependency for the
  mgmt-never-stranded invariant on foreign hosts, not re-implemented here.
- Kernel upgrades as an in-place operation — kernel bumps go through Path C
  (image-replace), the tested unit.
- RPM / non-Debian packaging.

## Hostile open questions (each invitable to PLAN-KILL)

> **Round-1 resolution status (v2):** Q1 resolved → re-scope #1917 to
> mechanism+HA-rolling consuming #1923 (§4). Q2 resolved → §6.7 verify-gated
> kernel channel + restated premise (RISK #2). Q3 resolved → honest measured
> multi-second gap, M-mech-1 not zero-gap (§8/RISK #1). Q5 resolved → manifest
> first-upgrade five-case enumeration (§8). Q6 resolved → embedded shim, no file
> packaged (§6.1). Q7 resolved → HA auto-rollback operator-driven (§8/RISK #7).
> Q4 (postinst safe on HA?) resolved → versioned immutable paths + symlink flip
> + HA-refuse (§6.3a). Remaining live for round-2 review: whether the residual
> M-mech-2 follow-up scoping and the kernel-channel implementability hold up.

1. **Does the `.deb` framing actually buy anything #1917 needs that Path B alone
   doesn't?** If the hard mechanism (verify/cut/rollback/HA-rolling) lives in
   `xpf-upgrade`/xpfd regardless, is the `.deb` just #1923 wearing #1917's hat?
   Could a reviewer argue #1917 should be *closed as a duplicate of #1923 + a new
   "HA-rolling-upgrade" issue*, making this whole plan a re-scope rather than a
   build? (PLAN-KILL the "build #1917 as written" if so.)
2. **Is the held-kernel requirement a contradiction of the operator's premise?** The
   operator wants "base OS self-updates via apt." But the verifier-gated shim forces
   us to HOLD the kernel — so the base does *not* freely self-update; the most
   security-relevant component (the kernel) is exactly the one we pin. Does that
   gut the value proposition of Path A?
3. **What is the actual standalone dataplane gap of M-mech-1, and is "brief outage"
   honest?** The helper has a 3s NAPI bootstrap window (process.go:108). If the
   real gap is multiple seconds of total packet loss on a standalone box, does
   #1917's standalone acceptance ("brief outage") survive contact with the number,
   or must standalone *also* be image-replace?
4. **Can a `postinst` ever be safe on an HA node, or must HA upgrades bypass
   apt/dpkg entirely?** If `apt upgrade xpf` on a clustered node is always wrong
   (it would cut traffic), is shipping a `.deb` actively dangerous for the HA
   deployment without an `xpf-upgrade`-mandatory guard — and can dpkg even be
   made to refuse?
5. **Does config-DB manifest versioning have a chicken-and-egg problem?** The first
   binary to write a manifest is N+1; binary N never wrote one and never reads the
   journal at boot. How does N+1 safely distinguish "no manifest = legacy N state
   (parse it)" from "no manifest = corruption"? Is the codex-review-010 design
   under-specified for the N→N+1 *first* upgrade?
6. **Embedded shim vs file shim:** the verify path consumes an *embedded* shim
   (`go:embed`), but the issue and #1864 talk about a "git-tracked `.o`." If the
   shim is embedded in the xpfd binary, the `xpf-dataplane` package shipping a
   separate `.o` is dead weight / a divergence hazard. Which is the real artifact,
   and does the package layout in §6.1 ship a file nobody reads?
7. **Auto-rollback under HA:** if node A's post-cut health check fails and it
   auto-rolls-back to binary N *while* node B is already at N+1 mid-rolling, what
   state is the cluster in? Is auto-rollback even safe mid-rolling-upgrade, or must
   rollback be operator-driven for HA?

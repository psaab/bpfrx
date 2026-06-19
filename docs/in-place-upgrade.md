# In-place upgrade mechanism (#1917)

The `pkg/upgrade` package implements the verified, atomic,
rollback-capable in-place upgrade cut-over for xpfd + the AF_XDP
dataplane helper. It is invoked as `xpfd upgrade [--rolling]` and from
the `.deb` postinst.

This doc is the module contract for `pkg/upgrade`, the `xpfd upgrade`
subcommand, the postinst HA-mode contract, and the dogfood deploy.

## Layout

```
/usr/local/share/xpf/staged/          dpkg-static staging (increment A) — apt's write target
/var/lib/xpf/versions/<ver>/          non-dpkg runtime version dirs (retain N=3); maintainer-script-managed, NEVER in dpkg's file list (#1964) — seeded at first install
/var/lib/xpf/versions/current -> <ver># bookkeeping pointer (the verified-live version)
/usr/local/sbin/{xpfd,cli,...} -> versions/current/<bin>   live + operator links (resolve THROUGH current, #1964)
/var/lib/xpf/upgrade.state            crash-safe state-machine journal
/etc/systemd/system/xpfd.service.d/10-xpf-version.conf     ExecStart pinned to the CONCRETE version
```

### Managed-binary manifest (single source of truth, #1982)

The set of binaries the upgrade treats as a version-locked unit —
`xpfd`, `cli`, `xpf-userspace-dp`, `xpf-day0-config` — is declared ONCE
in `pkg/upgrade/manifest` (`manifest.Managed` / `manifest.Names()`).
Everything that touches the set derives from it:

- the cut machine (`pkg/upgrade`, `managedBins = manifest.Names()`) —
  copy, flip, verify, GC; its pre-start completeness check
  (`versionDirComplete`) derives the lockstep subset
  (`xpfd`, `xpf-userspace-dp`) from `manifest.LockstepNames()`;
- the first-install seed (`pkg/upgrade/runtime`, same derivation);
- the maintainer scripts (`debian/xpf.{preinst,postinst,postrm}`) and
  `debian/rules` keep a self-contained `BINS="..."` literal / install
  set (no build-time mutation of tracked files — a sed-into-the-checkout
  step would dirty git and double-edit on re-run);
- the shell test fixtures under `test/debian/`.

A Go drift canary (`pkg/upgrade/manifest`'s
`TestManagedBinaryDriftCanary`) parses every shell site and FAILS the
suite if any list diverges from `manifest.Names()`, fail-closed (a site
that drops its `BINS=` literal trips the canary rather than passing
vacuously). To add a managed binary: edit `manifest.Managed`, then
update each shell site to match — the canary tells you which ones.

## State machine (`pkg/upgrade`)

```
STAGED -> PREFLIGHT -> COPIED -> VERIFIED -> STOPPED -> FLIPPED -> STARTED -> COMMITTED
```

Each transition is journaled (temp+fsync+rename) so a crash is
recoverable and idempotent — re-running `xpfd upgrade` resumes from the
journal. The ONLY live-state mutations are STOP and FLIP-then-START;
PREFLIGHT / COPY / VERIFY are pure and abortable (a failure there leaves
the running daemon and config untouched).

- **PREFLIGHT** — check `/var` free ≥ staged size + config-DB snapshot
  size + margin; GC eligible versions if short; take the pre-upgrade
  config-DB snapshot (`.partial`+rename, never torn) for rollback.
- **COPY** — `staged/` → `.<ver>.partial/` + checksum + atomic rename to
  `versions/<ver>/`. A crash never leaves a half-populated version dir;
  stray `.partial` dirs are swept on re-run, and the sweep fsyncs the
  parent `versions/` dir so the unlink cannot be resurrected by a crash
  before the next parent fsync (#1967 C4). The version key (`<ver>`) comes
  from `staged/xpfd version` and is validated as a safe single path segment
  (no `/`, `..`, leading dot, whitespace, control/high bytes) — a corrupt
  binary or a benign `version`-format drift hard-fails the cut rather than
  keying `versions/` by garbage (#1967 C1; `BinaryVersion` never falls back
  to the raw output).
- **VERIFY** — `versions/<ver>/xpfd verify-dataplane` against the running
  kernel with throwaway socket/state/pin env paths. A REJECT aborts with
  the live dataplane untouched. On a verify failure the just-copied
  `versions/<ver>/` is removed and the journal is rewound below COPIED, so
  a same-version retry (operator drops a corrected binary into `staged/`)
  RE-copies and re-verifies rather than re-verifying the stale failing copy
  (#1967). Two guards: the cleanup NEVER deletes the active or rollback
  version dir (only when `<ver>` is neither `current` nor PreviousVersion),
  and the journal is rewound BELOW PREFLIGHT (with the stale DB-snapshot
  fields cleared and the snapshot removed) so the retry takes a FRESH
  config-DB snapshot and recopies — the daemon stays live across a verify
  failure, so a config change before the retry must not be captured by the
  pre-failure snapshot (a later rollback would otherwise lose it).
- **STOP → FLIP → START** — stop the old daemon (closes the
  respawn-mismatch race: no live process can re-resolve the flipped
  helper), flip `current` + the `/usr/local/sbin` links + the unit
  ExecStart drop-in, then start the new daemon. Before START a diagnostic
  check confirms `versions/<ver>/{xpfd,xpf-userspace-dp}` still exist
  (a concurrent GC/disk event in the FLIP→START window) — a missing binary
  fails fast with a clear cause and routes through the same START-failure
  auto-rollback (#1967 C3, diagnostic only; the outcome was already covered
  by the START-failure rollback).

### Respawn-mismatch closure (two structural guards)

1. **STOP-before-FLIP** — no live old xpfd exists to respawn a helper
   after the unit is stopped.
2. **Concrete-version ExecStart** — the FLIP templates the unit
   `ExecStart`/`ExecStartPre` to the literal `/var/lib/xpf/versions/<ver>/xpfd`
   path (NOT the `current` symlink — systemd does NOT symlink-resolve
   `argv[0]`). So `dir(os.Args[0])` is the matching-version dir and even
   a transient respawn resolves the matching-version `xpf-userspace-dp`,
   never the shared `/usr/local/sbin` link.

### Rollback (binary + DB atomic)

Standalone auto-rollback (on an unhealthy post-start helper) and operator
rollback both restore the config DB BEFORE re-flipping the binary:

```
stop -> restore config-DB snapshot (PREFLIGHT) -> re-flip current/sbin/unit to previous -> start
```

This is mandatory because the N+1 daemon writes `active.json` in the
config compatibility envelope (see below); a bare binary re-flip to N
would boot an N daemon that fatal-rejects the N+1 envelope DB (a brick).
The HA path disables auto-rollback — HA rollback is operator-driven (an
auto re-flip mid-rolling un-coordinates the cluster).

## First-install seed + legacy migration + refuse-before-STOP (#1964)

The cut needs a real, immutable rollback target. Before #1964 the very
first `.deb` install seeded none: the first (or legacy-migration) upgrade
had `PreviousVersion==""` and `rollback()` hard-refused — but dpkg had
already overwritten the old binary in `staged/`, so there was no recovery
path. #1964 closes this with three composed mechanisms (A/B/C) and one
layout invariant.

**Layout invariant:** `versions/<ver>/` and the `current` symlink are
runtime state OWNED BY THE MAINTAINER SCRIPTS, never in dpkg's file list.
dpkg only ever writes `staged/`. `/usr/local/sbin/*` resolve THROUGH
`versions/current`. Consequence: dpkg can never clobber a versioned
rollback target on a later unpack, because it does not know those paths
exist.

- **A — first-install seed (`xpfd seed-runtime`, `pkg/upgrade/runtime`).**
  On first install (`$2` empty) the postinst runs `seed-runtime` AFTER
  unpack but BEFORE `#DEBHELPER#` starts the unit: copy `staged/*` →
  `versions/<v>/`, set `versions/current → <v>`, repoint sbin through
  `versions/current`. No cut/verify/stop. Idempotent + crash-safe (`.partial`
  + atomic rename; symlinks via temp+rename; a re-run converges). If
  seeding fails the postinst falls back to legacy direct-staged links (the
  next upgrade migrates) and never fails the install.
- **B — legacy-migration snapshot (`debian/xpf.preinst`, self-contained
  shell).** A host installed BEFORE this layout has sbin → `staged/` and no
  `versions/current`. On its next upgrade the preinst — running BEFORE
  unpack, so the new Go-seed-capable `xpfd` is not on disk yet — snapshots
  the OLD `staged/*` into `versions/<oldver>/`, sets `current`, and
  repoints sbin, all in the SAME `upgrade` case as the #1965 lock gate,
  AFTER that gate passes. Idempotency: no-op the copy when `current` exists;
  ALWAYS (idempotently) complete the sbin repoint (a crash after `current`
  but before sbin still completes on retry). Rename-collision retry: if
  `versions/<oldver>` already exists, skip copy+rename and jump to creating
  `current` (avoid ENOTEMPTY blocking apt). Atomic symlink repoint via
  `ln -sf … .tmp && mv -f` (NOT `ln -sfnT`, which unlinks-then-creates).
  `<oldver>` is `staged/xpfd version` (validated a safe path segment),
  falling back to a sanitized dpkg `$2` if the old binary won't exec; never
  fails the transaction. Writes NO upgrade journal.
- **C — refuse-before-STOP (unconditional pre-STOP invariant).** The cut
  NEVER calls `StopUnit` unless a restorable target exists
  (`PreviousVersion != ""`) OR it is an explicitly sanctioned no-rollback
  first cut (`Options.AllowNoRollbackFirstCut`). With A/B this is
  unreachable in the field (`current` always exists), so the refusal fires
  only on an unexpected loss of the rollback target — exactly when a blind
  STOP would brick the daemon. On a flip failure AFTER STOP (the unit is
  already down), `recoverFromFlipFailure` rolls back to the previous
  version, or — for a sanctioned first cut — restarts the first-install
  binary from `versions/current`; it always returns a non-nil error so a
  flip failure is never reported as success.

Version strings that key `versions/<ver>` are validated as safe single path
segments (`ValidateVersionSegment`: no `/`, `..`, leading dot, whitespace,
or control chars — but `+`/`:`/`~`/`-` are allowed, so Debian/semver
versions pass).

**Lifecycle (`debian/xpf.postrm`):** remove/purge remove sbin links that
resolve through `versions/current` (in addition to legacy direct-staged
links), only when owned, AND remove the runtime unit drop-in
`/etc/systemd/system/xpfd.service.d/10-xpf-version.conf` + rmdir the now-empty
`.service.d` dir + boot-guarded `daemon-reload` (#1967) — otherwise systemd is
left with a drop-in whose ExecStart pins a deleted `versions/<ver>/xpfd`. The
drop-in removal is safe on legacy/never-seeded hosts (absent file) and leaves a
non-empty `.service.d` (a foreign operator drop-in) intact. `versions/` is left
on `remove` (a reinstall reuses it) and removed on `purge` (it is copied
binaries, not operator config — Policy §6.8). A downgrade to a package
predating this layout repoints sbin back to `staged/` atomically, deletes
`versions/current`, then removes the runtime unit drop-in + boot-guarded
`daemon-reload` (shared helper) — so the downgraded binaries actually take
effect.

### Downgrade detection is exec-free and version-keyed (#1985)

The postrm must decide whether the package being installed predates the #1964
hardened layout (and so the lingering `versions/current` + drop-in must be torn
down). It originally did this by EXECUTING the staged binary
(`"$STAGED/xpfd" seed-runtime --capability-check`) and treating any non-zero
exit as "pre-hardened, tear the layout down". That conflated two different
things: a binary that genuinely lacks the subcommand, and a binary that cannot
EXEC AT ALL (dynamic-link error during unpack, corruption, libc/ABI conflict,
architecture mismatch). On a genuine UPGRADE where the new staged `xpfd`
happened to be non-execable, the `&&` short-circuited to false and the
destructive branch ran — deleting `versions/current`, repointing sbin to
`staged/`, and removing the drop-in — breaking the daemon on next boot.

The decision is now keyed on the dpkg-supplied INCOMING version (`$2`), which
is exec-free and has no staleness hazard:

```sh
if incoming_predates_hardened_layout "$2" \
   && { [ -L "$CURRENT" ] || [ -e "$CURRENT" ]; }; then
    ... tear down ...
fi
# incoming_predates_hardened_layout: dpkg --compare-versions "$2" lt FLOOR
```

`HARDENED_LAYOUT_FLOOR` is `0.0.4104` — the `.deb` version
(`0.0.<commit-count>+g<sha>`, `Makefile` `DEB_VERSION`) of commit `ef9525e70`,
the first package whose postrm manages the versioned-runtime layout on
downgrade and whose `xpfd` answers `seed-runtime --capability-check` — i.e.
the first package classifiable as hardened by this teardown contract. (Earlier
#1964 commits added the postinst seed at count 4102 and the preinst migration
at 4103; the postrm downgrade handling this floor protects landed at 4104.)
Any incoming version `< 0.0.4104` predates the contract and is a genuine
pre-#1964 downgrade; `>= 0.0.4104` (upgrade OR hardened->hardened downgrade,
including the floor version `0.0.4104+g<sha>` which sorts above the bare
`0.0.4104` floor) leaves the layout alone. The floor is a HISTORICAL fixed
point (the contract already shipped), not a per-release value — it is
never bumped.

- The teardown runs ONLY when `$2` is a confirmed pre-#1964 version AND a
  hardened layout is present (`versions/current`).
- An empty or unparsable `$2` (`dpkg --compare-versions` exits 2) leaves the
  layout intact — the safe default, never a teardown on ambiguity. This
  mirrors the sibling `preinst migrate_legacy_layout` posture
  (skip-don't-destroy). The verify-dataplane cut gate / refuse-before-STOP
  guard (`pkg/upgrade/cutover.go`) is the backstop for a hardened-but-
  unrunnable staged binary.

A presence-only file marker (a sentinel the hardened package ships) was
considered and REJECTED: dpkg removes a file present ONLY in the old package
AFTER the old-postrm runs (Debian Policy 6.6 unpack order), so a marker shipped
by the hardened package LINGERS on disk at old-postrm time during a genuine
pre-#1964 downgrade and would mis-signal "incoming is hardened", skipping the
teardown the downgrade needs. The version argument has no such staleness.

**One-time buggy->fixed exposure.** dpkg runs the OLD package's `postrm
upgrade <new>` during an upgrade. Upgrading FROM a pre-#1985 (exec-probe)
package therefore still runs that OLD buggy postrm; the version-floor gate
cannot protect its own rollout for that single hop — the fix cannot run
before it is installed. The exposure fires ONLY if, at OLD-postrm time, the
new staged `xpfd` is non-execable AND `versions/current` exists. The realistic
trigger is an OS/libc bump in the SAME apt transaction making the new binary
temporarily unloadable; stage xpf upgrades separately from OS/libc bumps.
**Recovery** if the old postrm did tear the layout down: re-run `xpfd
seed-runtime` (or reinstall the package) to rebuild `versions/current` + the
unit drop-in before the next cut.

## HA rolling upgrade (`xpfd upgrade --rolling`)

Cuts the LOCAL clustered node with a controlled drain so the cluster
keeps forwarding. Run on each node in turn (the deploy driver sequences
both); exactly one node is primary throughout.

1. assert peer alive + session sync established + HA protocol compatible
   (`CurrentHAProtocolVersion`) — else ABORT to image-replace (Path C),
   never drop connections.
2. **peer-takeover-ready precheck BEFORE demoting** — demoting a node
   whose peer cannot take over strands VIPs.
3. `ForceSecondary()` to start the drain.
4. **strong drain predicate** — peer owns the RGs, local VRRP BACKUP with
   no VIPs, `rg_active` false, sync clean (NOT merely "weight 0 set" — an
   RG keeps forwarding while VRRP is still MASTER). On timeout: fail back
   and ABORT WITHOUT cutting (node still forwarding — no harm).
5. single-node cut (auto-rollback disabled).
6. wait for session sync to re-establish, bounded by `RejoinDeadline`
   (60s default). The cut just restarted xpfd, so the local gRPC socket
   refuses connections for the first few seconds — that `connection
   refused` is the EXPECTED transient, treated as "not ready yet" and
   re-polled until the deadline (NOT a hard abort on the first dial
   error). Only the deadline aborts, surfacing the last observed error;
   the node is then left secondary for the operator to inspect.
7. `ResetFailover()` to rejoin election; forward-verify is the natural
   post-promotion check (`make test-failover`) — a passive node
   structurally cannot forward, so it is never "verified while passive".

### `--unit` and the cluster control endpoint (#1983)

`--unit <name>` (default `xpfd`) selects the systemd unit the
stop/start/flip actions target. The cluster control RPCs the rolling
driver uses — `PeerAlive` / `SyncEstablished` / `DrainComplete` /
`ForceSecondary` / `ResetFailover`, and the same RPCs in `xpfd upgrade
kernel drain`/`rejoin` — all dial a single hard-coded LOCAL endpoint,
`127.0.0.1:50051`. There is no unit→endpoint mapping yet, so a
non-default `--unit` would cut ONE daemon (systemd actions honor the
unit) while driving cluster failover against ANOTHER (the default daemon
on `127.0.0.1:50051`) — wrong-daemon control.

To keep that contract honest, `upgrade.NewCLICluster` — the single
construction chokepoint for all three callers — REJECTS any unit other
than the default (`xpfd`) with a clear error rather than silently
dialing the default endpoint. `--unit` takes the BARE unit name; the
systemd layer appends `.service` itself, so `--unit xpfd.service` is a
non-default spelling and is rejected. Mapping a selected unit to its own
control endpoint (so an alternate unit can be driven safely, e.g. for
integration tests, with an explicit `--grpc-addr` override) is a tracked
follow-up enhancement (#1983 §4.2 / a future `pkg/upgrade/clusterclient`)
— not implemented here. This is a CLI control-TARGET + validation change
only; it does not alter VRRP / session-sync / cluster RUNTIME behavior.

## Config compatibility envelope (D1, `pkg/configstore`)

`active.json` carries a magic header LINE
(`#xpf-config-envelope v=1 writer=.. ast=.. min-reader=.. rollback-fmt=..`)
prepended to the (possibly-encrypted) JSON body. The leading `#` makes a
pre-floor reader's `json.Unmarshal` ERROR (fail closed) instead of
empty-loading a wrapping object and silently wiping config. A too-new
`min-reader` is rejected. A present-but-unreadable DB is tagged
`ErrConfigDBUnreadable` and made FATAL at startup (daemon_run.go) — never
silently overwritten by a blind bootstrap. A pre-floor (no-envelope) DB
still reads, so upgrading TO the floor is non-destructive.

`mgmt-never-stranded`: on the appliance the day-0 + protected-set lifeline
covers a fail-closed boot; #1922 hardens the foreign/non-appliance host
case (NOT implemented here — see #1922).

## postinst HA-mode contract

- FIRST install (`$2` empty, any node type): the postinst runs `xpfd
  seed-runtime` (#1964 mechanism A) — seed the versioned runtime + sbin
  links, NO cut. The daemon comes up resolving `versions/current` with a
  real rollback target in place.
- STANDALONE node (no `/etc/xpf/node-id`), UPGRADE: the postinst invokes
  `xpfd upgrade` (verified single-node cut). `XPF_NO_POSTINST_CUT=1`
  suppresses it. The cut's refuse-before-STOP guard (#1964 mechanism C)
  keeps the daemon up if no rollback target exists (e.g. a host where
  seeding/migration was skipped) — the postinst logs the non-zero cut and
  leaves the old daemon running.
- CLUSTERED node (node-id present), UPGRADE: STAGE-ONLY. Cut ONLY via
  `xpfd upgrade --rolling`. Keyed on node-id ALONE so a degraded-HA node
  never falls through to an uncoordinated standalone cut.

## Dogfood deploy

`XPF_DEPLOY_DEB=1 make cluster-deploy` builds the `.deb` (outside the
#1875 cluster lock), `apt install`s it (stage-only on the clustered
nodes), and drives `xpfd upgrade --rolling` secondary-first. The default
raw push+restart path (and `XPF_DEPLOY_FAST`) is unchanged for the dev
inner loop. The deb path is opt-in until validated live; it then becomes
the CI/smoke default.

## Host-wide upgrade lock (#1965)

Every MUTATING upgrade operation on a host takes one host-wide advisory
lock — `/run/xpf/upgrade.lock`, a non-blocking exclusive `flock(2)`
(`pkg/upgrade/lock`). It serializes the standalone binary cut
(`xpfd upgrade`), the rolling driver (`xpfd upgrade --rolling`), the
postinst auto-cut, and the mutating `xpfd upgrade kernel`
sub-verbs (`arm`/`promote`/`drain`/`rejoin`). Without it two mutators
silently corrupt the crash-safe journal: both load the same snapshot,
modify independent copies, and last-write-wins, losing the rollback
target. Read-only status (`xpfd upgrade kernel status`) stays lock-free.

- `/run` is tmpfs and reboot-clearing — exactly right: the lock guards
  CONCURRENT mutators, while crash recovery stays journal-driven (the
  durable journal lives under `/var/lib/xpf`). A reboot mid-upgrade
  leaves no stale lock; the resume reads the journal, not the lock.
  `mkdir -p /run/xpf` runs before every acquire (a fresh boot's tmpfs may
  lack the dir).
- Owner metadata (PID, subcommand, target, start time) is written into
  the lock file after the flock succeeds, so a busy acquirer's error
  NAMES the current owner.
- The lock is released on every exit path (normal/error/panic) via defer;
  the kernel also drops the flock on process exit, so a crashed holder
  never wedges the host.
- **Rolling re-entrancy:** `RunRolling` takes the lock at entry and holds
  it through rejoin (covering the peer-check + `ForceSecondary` + drain
  window, not just the inner cut). The inner `r.Run()` runs with
  `Options{LockAlreadyHeld: true}` so it does NOT re-flock the same file
  (a second flock on a fresh fd of the same path returns `EWOULDBLOCK`
  and would abort the rolling upgrade).
- **Lock ordering vs the `/tmp/xpf-cluster.lock` deploy lock (#1875):**
  the cluster/deploy lock is taken OUTSIDE, the host upgrade lock INSIDE.
  No deadlock — the two never nest in the opposite order.
- **dpkg-vs-operator staged-source race — CLOSED by immutable versioned
  staging (#1981 Option B).** The cut no longer reads the dpkg-owned
  `staged/` path directly. `debian/xpf.preinst` still `flock`-gates the
  package op (fail-loud if an operator cut already holds the lock), but
  that was only a partial backstop — the preinst fd dies at preinst exit
  so the lock is NOT held during dpkg's per-file unpack, and a cut
  landing inside the unpack window could read a half-unpacked `staged/`
  that mixes binaries from two dpkg generations. #1981 closes it by
  construction; see "Immutable versioned staging" below.

## Immutable versioned staging (#1981 Option B)

dpkg unpacks the managed binaries into `staged/` one file at a time, so
across an `apt upgrade` unpack window `staged/` holds a MIX of old and
new binaries. A cut that copied directly from `staged/` could publish a
`versions/<ver>` mixing two dpkg generations — a torn set whose
`verify-dataplane` gate (xpfd+shim only) cannot detect a mismatched
`xpf-userspace-dp` (a lockstep-cut dataplane binary). #1981 closes that
window for ALL FOUR managed binaries:

- **Publish after a complete unpack.** `postinst configure` (which runs
  AFTER a complete unpack while the dpkg frontend lock serializes apt
  transactions) runs `xpfd publish-generation`: it copies the staged set
  into an immutable `staged-gen/<genid>/` (via `.partial` + atomic rename
  + dir-fsync) and atomically repoints a `staged-gen/current-gen` symlink
  (temp-symlink + rename, never `ln -sf`). `<genid>` is a zero-padded
  nanosecond wall-clock timestamp (`time.Now().UnixNano()`) + random
  suffix, so a same-version reinstall gets a distinct generation. The
  timestamp is NOT strictly monotonic (an NTP step can move the wall
  clock backward), so it is treated only as a generation key + a stable
  GC ordering hint; correctness never depends on `genid` ordering — GC
  protects `current-gen` and journal-referenced generations explicitly,
  so a backward clock step at most affects which NON-protected, non-live
  generation is reaped first, never the active source.
- **The cut reads the PINNED generation, never live `staged/`.** `Run`
  resolves `current-gen` ONCE at INIT and records the genid in
  `Journal.SourceGeneration`; `copyStaged` copies from
  `staged-gen/<SourceGeneration>/` — the resolved DIRECTORY, never
  re-reading the symlink — so a concurrent publish that advances
  `current-gen` cannot redirect an in-flight cut. The source is a
  generation dpkg is NOT touching, so it is internally a single
  generation by construction.
- **No published generation ⇒ refuse pre-PREFLIGHT.** A fresh cut with
  `current-gen` absent refuses at INIT with NO journal written and NO DB
  snapshot taken (the daemon is untouched). It never reads a torn
  `staged/`.
- **`staged-gen/` is maintainer-script-managed runtime state** under
  `/var/lib/xpf` (a sibling of `versions/`), NEVER a dpkg payload file —
  so dpkg never writes or removes it on unpack. The postrm removes it on
  `purge` and on a downgrade to ANY package below the #1981
  staged-generation floor (`STAGED_GEN_FLOOR`, a SEPARATE, HIGHER floor
  than the #1964 layout floor — so a post-#1964-but-pre-#1981 downgrade
  still removes `staged-gen/` even though it keeps the #1964
  versioned-runtime layout intact). The downgraded package never learns
  about `staged-gen/`, so leaving it would leak permanently; the pre-B
  cut reads live `staged/` as its only source, so removing `staged-gen/`
  strips nothing it can use.
- **GC retention N=2** (current + 1 prior — a superseded generation is
  never read again, so keeping 3 is pure disk waste). GC orders valid
  generation dirs by `genid` NAME (the zero-padded timestamp prefix makes
  name order chronological and mtime-independent) and keeps the newest N
  PLUS, ADDITIVELY, the explicitly-resolved `current-gen` generation AND
  any genid an active/resumable journal references (the GC-vs-resume race
  — a journal-pinned OLD generation never evicts an in-window generation,
  and `current-gen` is never reaped even if it is not the newest by name
  or mtimes are perturbed). It ignores (never counts, never deletes) any
  directory whose name is not a valid `genid`, and sweeps `.partial`
  orphans.
- **Same-version replacement (B-P3b OPT1).** `versions/<ver>` carries a
  `.srcgen` stamp; the copy-skip is generation-aware. A same-version
  re-stage with NEW bytes (a new generation) RE-COPIES a stale, non-live
  `versions/<ver>` (reusing the proven guarded-delete), or REFUSES
  pre-PREFLIGHT if `versions/<ver>` is the live `current`/rollback target
  (cannot safely mutate a live version dir mid-cut). Recovery on a
  refusal: re-stage under a distinct version tag, or `dpkg-reconfigure
  xpf` to realign the generation.
- **Crash-safety.** A crash before the `staged-gen/<genid>` rename leaves
  a `.partial` (pre-swept on the next publish); a crash after the dir
  rename but before the `current-gen` repoint leaves a
  complete-but-unreferenced generation (the PRIOR `current-gen` stays
  valid; a re-publish is idempotent). An aborted/failed unpack publishes
  NO new generation, so the prior generation stays the cut source — there
  is NO permanent-wedge class.
- **Deferred-publish recovery.** If the publish defers because the
  host-wide upgrade lock is busy (another upgrade in progress), the
  postinst drops `/run/xpf/upgrade-deferred`, skips the cut, and the
  operator recovers with `xpfd publish-generation && xpfd upgrade`
  (`dpkg-reconfigure xpf` is equivalent). A bare `xpfd upgrade` alone
  would re-read the OLD `current-gen` and no-op, so the recovery MUST
  publish first.
- **Disk budget.** Each binary set is ~50-70 MB (dominated by `xpfd`
  embedding the kernel-verified shim + `xpf-userspace-dp`). Steady-state
  copies: `staged/` (1) + `staged-gen/` current+1 (2) + `versions/`
  current+N=3 (4) ≈ **7 copies ≈ 350-490 MB**. A constrained appliance
  `/var` MUST size for this; the publish's own GC + the `versions/` GC
  bound it.
- **One-time first-deploy bootstrap caveat (intrinsic).** #1981 only
  protects cuts performed by a B-aware `xpfd`. During the very upgrade
  that INSTALLS the first B-aware binary, the operator-visible
  `xpfd upgrade` is still the OLD (pre-B) binary, which reads live
  `staged/` — the fix cannot run before it is installed. That single hop
  is covered by the existing backstops (the #1965 preinst lock gate +
  the `verify-dataplane` gate against the copied xpfd + "do not run
  `xpfd upgrade` during `apt upgrade`"). From the first B-aware version
  onward the window is closed by construction. This is a documented,
  bounded, one-time exposure, NOT a residual hole in the steady-state
  guarantee.

## Peer-takeover-readiness is best-effort; DrainComplete is authoritative

The local control socket renders the LOCAL node's view, so the
pre-demotion `PeerTakeoverReady` check cannot directly read the PEER's
takeover-readiness — it requires the peer alive and no LOCAL takeover
blocker. The AUTHORITATIVE guard is `DrainComplete`, which AFTER demotion
confirms the peer ACTUALLY holds primary for EVERY RG; if it does not
within the deadline, the rolling driver fails back and ABORTS WITHOUT
cutting. A peer that cannot take over therefore never leads to a cut — at
worst the drain times out and the local node is restored to forwarding.

## Rolling protocol-bump limitation

`HAProtocolCompatible` compares the RUNNING local daemon's HA protocol
version against the peer's. It cannot see the STAGED version's protocol
before the cut. So if a release BUMPS `CurrentHAProtocolVersion`, the
first node's precheck passes (running N vs peer N), it cuts to N+1, and
then the SECOND node's precheck fails (running N vs peer N+1) and aborts —
leaving a mixed-version cluster. This is the "not rolling-upgradable"
outcome the plan flags (Path C image-replace), but it is detected on the
second node, not pre-emptively. Operators MUST treat a protocol bump as a
non-rolling release (image-replace both nodes). A pre-emptive guard would
require the staged binary to report its protocol version to the driver
before the first cut (future work).

## Honest limits

- **No true zero-gap standalone restart.** The helper is an `exec.Command`
  child held in xpfd memory; a fresh xpfd spawns a NEW helper and clears
  the XSKMAP. Standalone cut-over is a bounded, MEASURED multi-second gap
  (the ~3s NAPI bootstrap window is the floor). True zero-gap
  (decoupled-helper re-attach) is future M-mech-2. The HA path masks the
  gap with a single ~60ms VRRP failover per node.
- Kernel/OS upgrades are #1930; a signed/hosted apt repo is #1924.

## LANE-1 HA kernel roll (#1930 INC-2)

A kernel bump can't be cut over in place (the running kernel can't be
swapped while live), so the kernel channel uses a fixed A/B UEFI boot
slot pair. `xpfd upgrade kernel` arms the INACTIVE slot's selector at the
candidate kernel and reboots one-shot (`efibootmgr --bootnext`, which the
firmware clears on the next boot — the loop-safety floor). On the
candidate boot, `xpf-kernel-promote.service` runs the kernel-space
`verify-dataplane` gate plus a forward beacon; on success it promotes
(non-destructive `BootOrder` front), on failure it reverts (bounded by
`maxPromoteAttempts`, then `restoreKnownGood`). The journal at
`/var/lib/xpf/kernel-upgrade.state` makes the trial crash-safe and
idempotent across the reboot.

In a cluster the roll is driven ONE NODE AT A TIME by the external
orchestrator (`scripts/deploy/xpf-deploy.py kernel-roll`): drain
secondary-first (`xpfd upgrade kernel drain`, which confirms the peer
holds every RG before returning), arm+reboot into the candidate, poll
until `status` reports `promoted=<ver>` AND `uname -r` matches, then
`rejoin` (which confirms sync re-established before touching the peer).
A reverted node boots the OLD kernel and reports `promoted!=<ver>` → the
driver STOPS and never touches the peer (never-both-down).

Three independent safety nets keep an UNVERIFIED candidate from ever
carrying traffic:

1. **Election hold (`kernelUpgradeHold`).** A candidate boot sets an
   unconditional SECONDARY hold in `pkg/cluster` election BEFORE
   `cluster.Start()` (the orchestrator's in-memory `ForceSecondary` drain
   is lost across the reboot, and `peerAlive` is still false at boot so a
   ForceSecondary call would be a no-op). Unlike `ManualFailover` this
   hold is NOT auto-cleared for an isolated node — a candidate with a
   broken dataplane stays secondary even if it can't see the peer. It is
   set BEFORE `cluster.UpdateConfig` (which itself runs the first
   election) — not merely before `Start()` — so a candidate can never win
   even the initial single-node election. `SetKernelUpgradeHold` also
   DEMOTES any already-primary group as defense in depth. The hold is
   released only when the candidate is affirmatively VERIFIED+PROMOTED:
   the promotion gate runs in a SEPARATE process
   (`xpf-kernel-promote.service`, `After=xpfd`) and writes a durable
   promotion marker for the running kernel, so the daemon reconciles the
   hold on a 5s cadence and releases it only once the marker NAMES THE
   RUNNING KERNEL. A bare "no longer armed" test would be unsafe on the
   revert path: `revert()` clears the journal and THEN reboots, so a
   not-armed test could release the hold while the broken candidate is
   still running (transient split-brain) — the marker test fails safe (a
   reverted node reboots to known-good, where the hold is never set).
   On a gate HANG/timeout the unit's `OnFailure=` triggers
   `xpf-kernel-promote-failed.service`, which reboots once to known-good
   (the firmware-cleared BootNext + un-reordered BootOrder land it there)
   so a hung verify never leaves the node held secondary forever.
2. **Lease-suppressed self-recovery.** If the orchestrator CRASHES while a
   node is drained+rebooting, the node would sit passive forever. The
   bounded local self-recovery (`pkg/upgrade/KernelSelfRecovery`,
   30s safety-net loop) auto-rejoins ONLY on the unambiguous crashed-roll
   fingerprint: an EXPIRED roll lease naming this node
   (`/var/lib/xpf/kernel-roll.lease`), a drained local node, and a
   healthy primary peer, held continuously for the grace window. A
   manually drained node or a #1917 binary-rolling drain never wrote a
   kernel-roll lease (`leaseNone`) and is left alone.
3. **Still-armed gate.** Self-recovery refuses to rejoin while the kernel
   journal is still ARMED even if the lease has expired — a legitimately
   long-hanging roll (one that outran its lease TTL) is still a trial in
   flight; the promote/revert oneshot owns the resolution, and the
   election hold keeps the node secondary meanwhile.

### Persistence precondition

The kernel channel REQUIRES `/var/lib/xpf` to be PERSISTENT across
reboots. The candidate journal (`kernel-upgrade.state`) is the only
record that a boot is a candidate trial; if it were on tmpfs/volatile
storage it would vanish on the candidate reboot, the election hold would
not be set (the node would not know it is a candidate), and an unverified
candidate could become primary. The journaled state machine for the
#1917 binary roll has the same requirement. This is a platform invariant
of the appliance image (`docs/install-images.md`), not a tunable.

## Kernel / OS upgrade lanes (#1930)

A kernel or base-OS move picks a lane by how big the change is:

| Change | Lane | Mechanism |
|---|---|---|
| Same kernel SERIES, in-place (verified shim already passes) | LANE 1 | `xpfd upgrade kernel` A/B UEFI boot channel (above) |
| New kernel SERIES, or kernel arriving with a base bump | LANE 2 | image-replace (`xpf-deploy.py image-roll`) |
| Base-OS major version (Ubuntu N → N+1) | LANE 3 | image-replace ONLY (the new kernel rides inside the image) |

The decision rule is **series change ⇒ LANE 2**: the AF_XDP shim's
kernel verifier (#1864) has only been proven against the kernel baked
into the image, so a new series goes through the fully-tested image
substrate (`bake.py` builds it, `validate.py` boot-gates it) rather than
the in-place channel.

### LANE 2 — rolling image-replace (`xpf-deploy.py image-roll`)

There is **no in-place base-OS swap**. `image-roll` recreates each HA
node from a new baked image ONE AT A TIME (built on the existing per-node
`launch` + day-0 re-apply), so the peer keeps forwarding:

1. **Mixed-base gate (before the FIRST swap).** After node[0] is replaced
   it runs the NEW image while node[1] still runs the OLD one — a
   *mixed-base* cluster. Sessions survive that window only if the new
   image's HA + session-sync protocols are back-compatible with the
   still-running peer. The driver reads the new image's
   `xpf-<ver>.manifest` (the `ha-protocol-version` /
   `ha-protocol-min-compat` / `session-sync-protocol-version` fields the
   bake records from `xpfd protocol-versions`) and the running peer's live
   `xpfd protocol-versions`, and applies `upgrade.GateMixedBaseSwap`
   (mirrored in the driver, unit-tested in Go): sessions survive **iff**
   the peer's HA protocol is within the new image's
   `[min-compat, version]` window AND the session-sync protocol matches
   exactly. It is **fail-closed** — any missing field, any out-of-window
   peer, any session-sync mismatch STOPS the roll with
   "re-image both nodes (sessions drop)". `--allow-session-drop` proceeds
   node-by-node anyway (sessions drop at the failover).
2. **drain** node[0] → peer (confirmed; the INC-2 `xpfd upgrade kernel
   drain` verb, never recreate an undrained primary).
3. **recreate** node[0] from the new image via the operator's
   `--recreate-hook` (backend-specific destroy+launch+day-0; the
   sequencing + never-both-down stays in the driver while the recreate
   mechanics stay environment-specific). The node boots the new base,
   factory-bootstraps its config DB from the day-0 text, verifies the
   dataplane.
4. **poll** until it is back (xpfd answers `protocol-versions`), then
   **rejoin** + confirm sync BEFORE touching node[1] (never-both-down;
   the INC-2 `rejoin` verb). Repeat for node[1].

When draining node[1] (the SECOND node), its peer is the already-rolled
NEW image, so the drain's exact-equality HA precheck is relaxed with
`xpfd upgrade kernel drain --allow-mixed-ha` (the gate already validated
window-compat). node[1] is still on the OLD image at that point, so the
driver **feature-detects** `--allow-mixed-ha` on node[1]'s running binary
(`drain --help`) and only passes it when supported — an image rolled FROM
a pre-INC-3 release has no such flag and would otherwise abort on it. When
the flag is absent the driver falls back to the OLD binary's exact-equality
precheck, which is correct whenever old/new advertise the same HA version
(the only in-window case a same-version roll produces); a genuine
in-window protocol *difference* cannot be relaxed by an OLD binary, so the
operator must re-image both nodes together.

Scope note (Codex): `--allow-mixed-ha` relaxes ONLY the drain's
exact-equality *HA-protocol* precheck (`HAProtocolCompatible`). The drain's
`PeerTakeoverReady` / transfer-readiness check is still enforced, and on a
real HA mismatch the peer reports `Transfer ready: no`
(`daemon_ha_userspace.go`), which still aborts the drain. So neither
`--allow-mixed-ha` nor `--allow-session-drop` is a blanket "drain under any
HA skew" bypass — a genuinely HA-skewed peer is still refused at the
transfer-readiness gate. This is dormant in practice today because the HA /
session-sync protocol versions are pinned exact-version, so the only
in-window cases that reach the relaxed precheck advertise equal HA versions;
the scope matters for any future release that widens the HA compat window.

**Standalone** is a documented reboot/recreate gap (image swap + factory
boot + day-0 re-apply); there is no zero-gap standalone image replace.

### LANE 3 — base-OS major upgrade: image-replace only

**Default and ONLY supported path: image-replace (LANE 2).** A baked N+1
image carries the new kernel, glibc, systemd, FRR, strongSwan, kea, and
chrony as one `validate.py`-gated unit.

**State carries as TEXT config, not the encrypted DB.** The portable
artifact is `/etc/xpf/xpf.conf` (+ `/etc/xpf/node-id` for HA identity),
re-applied via the day-0 drive; the freshly-imaged node factory-bootstraps
`.configdb` from the text on first boot. `master.key` is RE-GENERATED on
the new image, NOT carried — do not attempt to carry `.configdb`/
`master.key` across a fresh image (the new key cannot decrypt a carried
DB). (For an *in-place* #1917 upgrade the DB persists; image-replace
re-bootstraps from text — different paths.)

**In-place `do-release-upgrade` is UNSUPPORTED.** It modifies the entire
userspace in-place and irreversibly (no rollback if the new userspace
fails to forward); constrained with `apt-mark hold linux-*` it leaves the
release half-upgraded; it can leave N+1 userspace on the old N kernel
where the shim may not verify; and it cannot be CI-tested. Operators who
run it anyway do so at their own risk and should re-image afterward.

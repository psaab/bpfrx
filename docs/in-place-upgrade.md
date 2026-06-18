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
/var/lib/xpf/versions/<ver>/          non-dpkg runtime version dirs (retain N=3)
/var/lib/xpf/versions/current -> <ver># bookkeeping pointer (the verified-live version)
/usr/local/sbin/{xpfd,cli,...} -> versions/current/<bin>   operator-tool links
/var/lib/xpf/upgrade.state            crash-safe state-machine journal
/etc/systemd/system/xpfd.service.d/10-xpf-version.conf     ExecStart pinned to the CONCRETE version
```

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
  stray `.partial` dirs are swept on re-run.
- **VERIFY** — `versions/<ver>/xpfd verify-dataplane` against the running
  kernel with throwaway socket/state/pin env paths. A REJECT aborts with
  the live dataplane untouched.
- **STOP → FLIP → START** — stop the old daemon (closes the
  respawn-mismatch race: no live process can re-resolve the flipped
  helper), flip `current` + the `/usr/local/sbin` links + the unit
  ExecStart drop-in, then start the new daemon.

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

- STANDALONE node (no `/etc/xpf/node-id`): the postinst invokes
  `xpfd upgrade` (verified single-node cut). `XPF_NO_POSTINST_CUT=1`
  suppresses it.
- CLUSTERED node (node-id present): STAGE-ONLY. Cut ONLY via
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
- **dpkg-vs-operator staged-source race:** `debian/xpf.preinst` runs
  BEFORE unpack and `flock -n /run/xpf/upgrade.lock`-gates the package
  operation, failing apt loudly (non-zero, system untouched) if an
  operator upgrade already holds the lock. This is a fail-loud gate, not
  full unpack serialization: a preinst fd dies at preinst exit, so the
  lock is not held DURING dpkg's unpack. The torn-binary backstop is the
  `verify-dataplane` kernel gate the cut runs against the COPIED binary
  before `StopUnit`. The postinst standalone path re-checks the lock and,
  on the narrow TOCTOU residual, drops `/run/xpf/upgrade-deferred`, logs
  loudly, and exits 0 (a non-zero postinst leaves dpkg half-configured).
  Operator guidance: do not run `xpfd upgrade` during `apt upgrade`.

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

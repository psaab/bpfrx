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
6. wait for session sync to re-establish.
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

## Honest limits

- **No true zero-gap standalone restart.** The helper is an `exec.Command`
  child held in xpfd memory; a fresh xpfd spawns a NEW helper and clears
  the XSKMAP. Standalone cut-over is a bounded, MEASURED multi-second gap
  (the ~3s NAPI bootstrap window is the floor). True zero-gap
  (decoupled-helper re-attach) is future M-mech-2. The HA path masks the
  gap with a single ~60ms VRRP failover per node.
- Kernel/OS upgrades are #1930; a signed/hosted apt repo is #1924.

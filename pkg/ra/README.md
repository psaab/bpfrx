# pkg/ra

Embedded IPv6 Router Advertisement sender. Replaces external `radvd`
with per-interface goroutines built on `mdlayher/ndp`. Handles startup
burst, goodbye RAs, and re-burst recovery after RETH MAC link-cycle.

## Shutdown contract (single-owner + draining tombstone, #2033)

The lifetime-zero **goodbye** RA (router withdraw) MUST be the last RA on
the wire for an interface — otherwise a host keeps a dead default route
after HA failover. To make that **structural**, not flag-defended:

- **Single-owner emission.** Per interface, exactly ONE goroutine
  (`sender.run`) writes the NDP connection — startup burst, periodic RAs,
  RS-triggered replies AND the goodbye. No other goroutine calls
  `conn.WriteTo` or `conn.Close`. `ResendBurst` routes the re-burst
  through the owner via a buffered `burstCh` (no second writer).
- **Goodbye is owner-emitted on exit.** Shutdown is signalled via
  `signalStop(mode)`: it publishes an atomic `shutdownMode`
  (`hard`/`graceful`), then closes `stopCh` once (`sync.Once`). The owner
  wakes, leaves the loop, and in `finishShutdown` (the ONLY place a
  goodbye is sent and the ONLY place the conn is closed) emits the
  lifetime-zero goodbye as its FINAL write when the mode is graceful,
  then closes the conn. A normal RA can never follow the goodbye because
  the goodbye is emitted structurally after the loop.
- **Graceful upgrades hard, with a standalone-goodbye backstop (exactly one
  goodbye per withdrawn interface).** In cluster mode RA
  `Apply`/`Withdraw`/`Clear` for the same sender are serialized ONLY by the
  manager mutex (no `applySem`). A graceful withdraw beats a racing hard
  `Clear`: `signalStop` stores graceful unconditionally and hard only via
  compare-and-swap from "none" — never a downgrade. The manager records the
  graceful intent ATOMICALLY: `Withdraw`/`WithdrawInterfaces` install the
  tombstone AND call `signalStop(modeGraceful)` under the SAME lock that
  bumps the epoch and snapshots, so a racing `Clear` cannot slip a hard stop
  into a gap. If a `Clear` (or a changed-config restart) got there first, the
  `Withdraw` finds the sender in the draining map and UPGRADES it to graceful
  (the draining map stores the `*sender`, nil only for a `WithdrawOnce`
  claim). BUT an "upgrade" only works while the owner is still alive — once a
  sender has run `finishShutdown` (read modeHard, emitted no goodbye, exited)
  it is DEAD and cannot be resurrected. So the withdrawal guarantee is
  decoupled from the live-sender lifecycle: each `sender` records whether
  `finishShutdown` actually emitted a goodbye (`goodbyeEmitted`), and after
  the owner joins, the manager checks that fact. If a goodbye was owed (a
  graceful withdrawal was intended) but the owner emitted none — it lost the
  upgrade race, or it was already a stopped Clear / changed-config-restart
  tombstone — the manager emits a STANDALONE goodbye via the WithdrawOnce
  mechanism (`sendOneGoodbye`: open conn, 3× lifetime-0 RA, close; no burst,
  no link toggle). This yields **exactly one goodbye per withdrawn
  interface**: the owner's if the upgrade landed, otherwise a standalone; the
  standalone is suppressed if the owner already emitted one
  (`goodbyeEmitted`) or if a LIVE sender has since re-claimed the interface (a
  new MASTER `Apply` won it back — do not clobber it with a lifetime-0 RA).
  A pure changed-config replace (no withdraw) emits ZERO goodbyes (the router
  is not going away). Because the owner closes the conn AFTER its goodbye, a
  racing hard close cannot suppress it.
- **Draining tombstone — one live conn per interface, including replaces.**
  Every transition that removes OR replaces a sender installs a
  per-interface DRAINING tombstone under the manager mutex BEFORE releasing
  it, stops the old sender (closing its conn) OUTSIDE the lock, and only
  THEN opens any replacement conn. A changed-config `Apply` is a hard
  replace (no goodbye — the router is not going away) but still goes
  stop-old → start-new with the tombstone covering the whole window — it
  never opens the replacement while the old conn is live. While the
  tombstone is present the interface is NOT absent: a concurrent `Apply` or
  `WithdrawOnce` treats it as a claim and defers. This guarantees **at most
  one live NDP conn per interface** at any time (no `ndp.Listen` collision,
  no goodbye-after-new-burst inversion).
- **Deferred / restart Apply is epoch-guarded.** An `Apply` start that
  waits behind a tombstone (a pre-existing drain, or its own changed-config
  stop) captures the manager epoch; if a newer `Withdraw`/`Clear`/`Apply`
  bumped the epoch in the interim, the deferred/restart start is aborted
  (it must not re-arm RA on a node that has since transitioned to BACKUP).
- **Bounded writes.** Every owner `WriteTo` sets a 1 s write deadline so a
  stuck socket cannot wedge withdrawal; the owner always returns promptly,
  which is what makes owner-performs-the-close safe for both modes.
- **rsReceiver backoff.** The RS receiver polls with a read deadline and
  backs off on a persistent non-deadline read error (so it cannot
  hot-loop at 100% CPU if the interface dies while `stopCh` is still
  open). It is a detached goroutine unblocked by the owner's `conn.Close`.

`WithdrawOnce` (boot-as-secondary stale-route withdraw) uses a
goodbye-ONLY path (`sendGoodbyeStandalone`) that never launches an owner
or a startup burst (so it cannot re-advertise the router it withdraws)
and never toggles the link (no `ensureLinkLocal` link-cycle on a demoting
interface — if no usable link-local exists the goodbye is skipped
best-effort).

## Entry points

- `Manager` — `ra.go`.
- `New()` — `ra.go`.
- `Apply(configs []*config.RAInterfaceConfig) error` — `ra.go`.
  Starts/stops per-interface senders; defers + retries (epoch-guarded)
  any interface that is currently draining.
- `Withdraw() error` — `ra.go`. Graceful goodbye + stop on every sender.
- `ResendBurst()` — `ra.go`. Re-sends the startup burst (used after a
  link cycle) on every active sender, via the owner goroutine.
- `WithdrawInterfaces(names []string)` — `ra.go`. Graceful goodbye + stop
  by interface name.
- `WithdrawOnce(configs []*config.RAInterfaceConfig)` — `ra.go`.
  Goodbye-only (no burst, no link toggle); skips busy interfaces.
- `Clear() error` — `ra.go`. Hard stop (no goodbye) of every sender.
- `Status()` — `ra.go`. Per-interface `SenderInfo`. A running sender has
  `State == "active"`; an interface whose sender is tearing down /
  emitting its goodbye is reported with `State == "draining"` (distinct
  from active, so a withdrawing router is neither read as still
  advertising nor silently invisible).

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Link DOWN→UP during a RETH MAC cycle kills the AF_PACKET socket.
  `ResendBurst()` is what closes that gap — without it, hosts see an RA
  outage from the moment of the link cycle until the next periodic RA.
- The goodbye RA carries router lifetime 0, telling hosts to drop this
  router as default gateway. Send one when explicitly withdrawing a zone
  or shutting down. It is emitted by the per-interface owner goroutine as
  its last write (see the shutdown contract above) so a normal RA can
  never follow it on the wire.
- IPv6 NODAD is set on the per-instance NDP socket so it doesn't fight
  the kernel's own duplicate-address detection on the link-local
  address.
- `ensureLinkLocal` (`sender.go`) guarantees a link-local exists for the
  NDP socket. RETH members run with `addr_gen_mode=1` (set by the daemon's
  `setRethIPv6Knobs`) to suppress kernel EUI-64 auto-generation and its
  MLDv2 noise, so a member may have no link-local when the sender starts.
  When one is missing the sender adds the EUI-64 `fe80::/64` directly via
  `netlink.AddrAdd` with `IFA_F_NODAD` — the same primitive the daemon uses
  in `ensureRethLinkLocal` / `addStableLLToInterface`. It does **not** mutate
  `addr_gen_mode` and does **not** cycle the link (#2034): `addr_gen_mode=1`
  is a contract the apply path sets deliberately, and an out-of-band link
  DOWN/UP from inside the RA manager would un-reconcile VIPs / stable LLAs
  and race the AF_XDP dataplane rebind. An interface with no usable 6-byte
  MAC degrades to a soft-logged warning (the caller only `slog.Warn`s the
  error); the explicit `source-link-local` config and the `start()` retry
  loop are the recovery path.
- Per RFC 5798, `AdvertiseInterval` is stored in milliseconds but goes
  on the wire in centiseconds. Don't double-convert.

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
- **The draining tombstone is the single atomic claim-and-hold for the
  goodbye (exactly one per withdrawn interface).** In cluster mode RA
  `Apply`/`Withdraw`/`Clear` for the same sender are serialized ONLY by the
  manager mutex (no `applySem`). Each draining interface has ONE `drainEntry`
  in `m.draining` (all fields read/written only under `m.mu`), owned by
  exactly ONE goroutine — the one that joins its sender (or the
  `WithdrawOnce`/standalone claimant). That single owner is the SOLE emitter
  of any standalone goodbye and HOLDS the entry across the whole emit. This
  makes "this interface owes a goodbye" a state CLAIMED ONCE and HELD, so
  there is no check-then-act anywhere:
    - **Graceful intent is atomic.** A graceful withdraw beats a racing hard
      `Clear`: `signalStop` stores graceful unconditionally and hard only via
      compare-and-swap from "none" — never a downgrade. `Withdraw`/
      `WithdrawInterfaces` install the entry (active-sender case) or flip
      `goodbyeWanted` on an existing one, AND `signalStop(modeGraceful)`,
      under the SAME lock that bumps the epoch — a racing `Clear` cannot slip
      a hard stop into a gap.
    - **An upgrade only works while the owner is alive.** Once a sender has
      run `finishShutdown` (read modeHard, emitted no goodbye, exited) it is
      DEAD and cannot be resurrected. So the guarantee is decoupled from the
      live-sender lifecycle: each `sender` records `goodbyeEmitted` (set in
      `finishShutdown` before `close(stopped)`). The entry's single owner, in
      `releaseDrain`, JOINS the sender (`<-stopped`, which orders the
      `goodbyeEmitted` read) and then, UNDER `m.mu`, takes the goodbye
      EXACTLY ONCE (`!goodbyeClaimed` → set it) if one is wanted and the
      owner emitted none.
    - **Claim-once (closes the concurrent-Withdraw double-send):** only the
      one owner releases the entry; concurrent Withdraws merely flip
      `goodbyeWanted`. `goodbyeClaimed` under `m.mu` ensures a single emit.
    - **Held-across-emit (closes the live-sender clobber):** the owner keeps
      the entry in `m.draining` for the ENTIRE standalone emit (open conn → 3×
      lifetime-0 RA → close), removing it only afterward. A concurrent `Apply`
      sees the tombstone and DEFERS — no new sender starts during the emit, so
      the standalone never clobbers a re-claimed master and ≤1 live conn holds.
      The tombstone IS the mutual exclusion; there is no separate check-then-act
      on `m.senders`.
    - **Timeout never emits AND never starts a replacement (closes the
      happens-before break AND the ≤1-conn break on the restart path):**
      `releaseDrain` reads `goodbyeEmitted` ONLY after a successful `<-stopped`.
      If the join times out (`claimWaitTimeout` — pathological, since owner
      writes are bounded by `SetWriteDeadline`), it does NOT emit a standalone
      (the read would be unordered; the owner may be live) AND does NOT start
      the changed-config replacement (the old conn may still be live → would
      break ≤1-conn). It LEAVES the tombstone held — so any future
      `Apply`/reconcile defers, never opening a second conn — and detaches a
      reclaimer that removes the tombstone once the wedged owner finally exits.
      The safe degraded state is "old sender lingers, no replacement, tombstone
      held," never two conns and never an unordered emit.
  Net: EXACTLY ONE goodbye per withdrawn interface — the owner's if the
  upgrade landed, otherwise one standalone — and ZERO for a pure changed-config
  replace. Because the owner closes the conn AFTER its goodbye, a racing hard
  close cannot suppress it.
- **Single stop-then-act path (round-4 unification).** `releaseDrain` is the
  SOLE owner of "stop the old sender (join-or-timeout) → optionally emit
  exactly-once → optionally start a replacement on PROVEN-close → release
  tombstone." `Withdraw`, `WithdrawInterfaces`, `Clear` and `Apply` (both the
  removal and the changed-config **restart**) all route through it. The restart
  passes an `onProvenClose` callback that opens the replacement conn — it runs
  ONLY on the proven-closed (`<-stopped`) arm, under `m.mu`, with the tombstone
  still held, and only if no graceful withdraw superseded the replace (epoch
  unchanged AND no goodbye wanted). There is no divergent inline copy of these
  rules, so the timeout / happens-before / ≤1-conn class cannot reappear in a
  third path.
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

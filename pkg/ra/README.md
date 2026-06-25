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
  still held, and only if no graceful withdraw superseded the replace. There is
  no divergent inline copy of these rules, so the timeout / happens-before /
  ≤1-conn class cannot reappear in a third path.
- **Replacement decision is atomic under the act-lock (round-5).** The
  "start the replacement?" test (epoch still `startEpoch` AND `!goodbyeWanted`)
  is re-evaluated against the LIVE tombstone under the SAME lock hold that
  performs the start — never a boolean computed before an unlock and trusted
  after. `goodbyeWanted` is monotonic (false→true) and `epoch` only increases,
  so a "start" decision observed under the act-lock cannot be invalidated while
  the lock is held; a racing `Withdraw`/`Clear` that lands before the act-lock
  is seen (decision aborts, the withdraw's goodbye is emitted), and one that
  lands after is harmless (no supersession existed at the act moment). The only
  unlock inside `releaseDrain` is for the blocking standalone-goodbye send; the
  loop re-acquires and re-evaluates fresh state before touching the replacement.
  NOTE: `onProvenClose` calls `startLocked` under `m.mu`. As of #2453 that is
  cheap: `startLocked` only does the synchronous `InterfaceByName` check and the
  `m.senders` bookkeeping, then launches the owner goroutine and returns. The
  socket open — `ensureLinkLocal` + the `ndp.Listen` bind RETRY that sleeps up
  to ~2s while a settling/RETH link-local appears — now runs in the owner
  goroutine's `openConn()` BEFORE its main loop, NOT under `m.mu` (see "Bind
  retry runs unlocked" below). The tombstone (held) still provides mutual
  exclusion for the start.
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
- **Make-before-break on a changed-config replace (#2834).** The ≤1-conn
  rule above means the old conn is PROVEN closed before the replacement is
  started — but `start()` opens the new conn ASYNCHRONOUSLY in the owner
  goroutine (the `openConn` bind retry must not run under `m.mu`; see "Bind
  retry runs unlocked"). So between `startLocked` returning and the owner's
  `openConn` completing there is a brief window with ZERO live conns — an
  IPv6-RA outage after a config change (hosts could lose the default route /
  RDNSS). On the changed-config restart path ONLY, `Apply` therefore waits —
  UNLOCKED, after `releaseDrain` returns — on the replacement sender's
  `connReady` signal (closed by the owner once `openConn` resolves), bounded
  by `claimWaitTimeout`. `Apply` returns only once the replacement RA conn is
  LIVE, so the live-conn count goes 1 → (briefly 0, internal) → 1 with no
  observable 0-conn window for callers, and never momentarily 2 (the old conn
  is gone first). This applies ONLY to a replace — it is NOT a withdrawal, so
  it still emits no goodbye; a genuine `Withdraw`/`Clear`/removal keeps its
  existing lifetime-0-goodbye + go-down behavior. The sender exposes
  `waitConnReady(timeout) bool`; the owner calls `signalConnReady(opened)`
  after `openConn` so a failed/pre-empted open releases the waiter promptly
  rather than blocking the full timeout on a sender that will never serve.
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
  Goodbye-only (no burst, no link toggle); skips busy interfaces. The
  busy-check and the claim-and-hold tombstone install are performed
  ATOMICALLY under `m.mu` by `claimWithdrawOnceLocked` (#2272): holding the
  lock across BOTH closes the check-and-act window in which a concurrent
  `Apply`/`WithdrawOnce` could otherwise start a competing sender between
  the check and the claim (two owners on one link, or a sender racing the
  goodbye — the #2033 blackhole class). The tombstone is then HELD across
  the goodbye emit, so the busy state — and thus the mutual exclusion —
  extends over the whole operation, not just the install instant.
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
- Prefix lifetimes are clamped to satisfy RFC 4861 §4.6.2 (#2271):
  `buildRA` (`sender.go`) clamps each PrefixInformation's preferred
  lifetime DOWN to its valid lifetime (`if prefLife > validLife`). A pair
  where preferred > valid is malformed and a conforming host (RFC 4862
  §5.5.3) ignores the prefix, so an operator that types
  `preferred-lifetime` larger than `valid-lifetime` (or a 0-defaulted
  valid life paired with a large explicit preferred life) would otherwise
  silently lose SLAAC on every host. The clamp is never the reverse —
  extending validity would advertise a longer-lived prefix than configured.
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
  error); the explicit `source-link-local` config and the `listen()` retry
  loop (now in the owner goroutine, see below) are the recovery path.
- **Bind retry runs UNLOCKED, in the owner goroutine (#2453).** `start()` no
  longer opens the NDP conn synchronously. It just launches `run()` and returns,
  so `Manager.startLocked` holds `m.mu` only for the cheap `InterfaceByName`
  check plus the `m.senders` bookkeeping. The socket open — `ensureLinkLocal`
  plus the `ndp.Listen` bind retry, which sleeps up to ~2s (10 × 200 ms) while a
  settling/RETH link-local appears — runs in the owner goroutine's `openConn()`
  before its main loop, with NO lock held. Before this, a slow/settling
  link-local on one interface stalled EVERY other RA manager op (a VRRP-failover
  `Withdraw`, or an `Apply` on a different interface) for up to ~2s, because they
  all contend `m.mu`. The bind retry is now interruptible by `stopCh`: a withdraw
  signalled mid-retry aborts the sleep instead of running the full ~2s.
  Consequences for the single-owner / #2033 invariants: `s.conn` is still opened,
  used, and closed solely by the owner goroutine. If the bind ultimately fails
  (or a stop lands before/during the retry) `openConn` returns false and `run`
  goes straight to `finishShutdown`, which tolerates a nil conn — no goodbye is
  written and `goodbyeEmitted` stays false, so the manager's release-time
  backstop (`sendOneGoodbye` on a FRESH conn) still emits a standalone goodbye if
  a graceful withdraw owed one. `start()` therefore never returns a listen error
  (the open is async); the only caller cost is that an unreachable interface is
  logged by the owner instead of surfaced as an `Apply` error — and every `Apply`
  call site already only `slog.Warn`s that error. `srcAddr` is now written by the
  owner goroutine and read by `Status` under `m.mu`, so it carries its own
  `srcMu` guard (`getSrcAddr`/`setSrcAddr`).
- Per RFC 5798, `AdvertiseInterval` is stored in milliseconds but goes
  on the wire in centiseconds. Don't double-convert.

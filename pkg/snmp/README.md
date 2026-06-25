# pkg/snmp

SNMPv2c and SNMPv3 agent. Responds to GET / GETNEXT / GETBULK on
ifTable, ifXTable, and a small set of system OIDs. Also sends link-up /
link-down traps. ASN.1 BER encoding is hand-coded, no external library.

## Community authorization (SET access control)

A v2c community carries an `authorization` level (`read-only` /
`read-write`, default `read-only`). `getCommunity` resolves the community
struct; SET requests (`pduSetRequest`, 0xa3) are gated on it:

- A community without `read-write` authorization is denied with `noAccess`
  (RFC 3416 error-status 6) before any write is attempted — this is the
  security boundary set by `set snmp community <name> authorization
  read-write`.
- A `read-write` community passes the gate, but the agent exposes only
  read-only MIB objects, so the write is refused per-varbind with
  `notWritable` (17). No served object is mutable, so a SET never succeeds;
  the read-only vs read-write distinction is enforced and observable in the
  response error-status.

SNMPv3 SET requests are uniformly refused with `notWritable` (the USM users
in this config carry no read-write authorization).

## SNMPv3 contexts (RFC 3412 §4.1, RFC 3413 §3)

The agent serves a single MIB view in the **default context** (empty
`contextName`). It does NOT model per-VRF / per-routing-instance context
views. The scopedPDU `contextEngineID` and `contextName` are decoded and the
`contextName` is honored when dispatching the request:

- **Default context** (empty `contextName`): served exactly as before —
  Get / GetNext / GetBulk return the real MIB objects. No behavior change.
- **Non-default context** (any non-empty `contextName`): there is no MIB view
  for that context, so per RFC 3413 the request yields no matching objects.
  Rather than leaking default-context data (an information-exposure /
  operator-confusion bug, #2611), the agent returns the **empty-view**
  exceptions: `noSuchInstance` for every Get varbind and `endOfMibView` for
  every GetNext / GetBulk varbind. SET is refused with `notWritable` as in any
  context. This is fail-closed: a manager addressing an unknown context never
  receives default-context values.
- The response **echoes the requested `contextName`** back in the scopedPDU
  (empty for the default context), so the manager sees the response is bound to
  the context it addressed. `contextEngineID` in the response is our own engine
  ID (we are the authoritative engine).

This is the empty-view route (RFC 3413), chosen over an `authorizationError` /
`snmpUnknownContexts` report because it is the standard, simplest result for a
single-context agent and needs no new error-counter MIB objects.

## SNMPv3 security levels (RFC 3414 §5)

RFC 3414 defines exactly three USM security levels, encoded in the two
low `msgFlags` bits:

- **noAuthNoPriv** — both flags clear (`0x00`): no HMAC, no encryption.
- **authNoPriv** — auth flag set (`0x01`): HMAC-verified, plaintext PDU.
- **authPriv** — both flags set (`0x03`): HMAC-verified and encrypted.

The fourth bit combination — privacy set, authentication clear
(`msgFlags = 0x02`, "noAuthPriv") — is **not a valid level**: an
encrypted message must be authenticated. `handleV3Packet` rejects it
**before** any authentication, decryption, or PDU execution. The agent
**drops** the message (returns nothing) rather than emitting a report,
because with no authentication it cannot produce an authenticated reply
at the requested security level and an unauthenticated report would
itself be unverifiable (#2681). Accepting noAuthPriv would let a sender
who can supply a decryptable PDU bypass HMAC and timeliness verification
entirely — its scopedPDU would be decrypted and executed with no auth.
The three valid levels are unaffected.

## SNMPv3 USM timeliness and replay protection (RFC 3414 §3.2)

Authenticating a request proves the sender holds the user's key; it does
**not** prove the message is fresh. Without a timeliness check an on-path
attacker can replay a captured authenticated PDU verbatim. The agent enforces
the RFC 3414 §3.2 timeliness window as the authoritative engine:

- After `verifyAuth` succeeds, `checkTimeliness(reqBoots, reqTime)` compares the
  request's `msgAuthoritativeEngineBoots`/`msgAuthoritativeEngineTime` against
  the agent's own `engineBoots`/`engineTime()`. A request is in the window only
  when our boots counter is below the RFC ceiling (`2147483647`), the request's
  boots equals ours, and the request's time is within ±150 seconds of ours.
- A request outside the window gets an **authenticated** Report PDU carrying
  `usmStatsNotInTimeWindows` (`1.3.6.1.6.3.15.1.1.2.0`) plus the agent's current
  boots/time, never a data response. A manager whose cached boots/time drifted
  (the legitimate case, e.g. after our restart bumped boots) reads the report
  and resynchronizes; a replay simply gets nothing useful.
- The engineID discovery handshake (empty `userName` →
  `usmStatsUnknownEngineIDs`, `1.3.6.1.6.3.15.1.1.4.0`) is unaffected: a manager
  still learns our engineID and current boots/time before its first
  authenticated request, so a freshly-discovered, timely request is accepted.

### Privacy (encryption) IV: RFC 3826 §3.1.2.1

For an `authPriv` request the scopedPDU is encrypted; the agent must rebuild the
exact IV the manager used. Per RFC 3826 §3.1.2.1 the AES-128-CFB IV is
`authoritativeEngineBoots(4) || authoritativeEngineTime(4) || privParams(8)`,
where boots/time are the values **carried in the message** — the boots/time the
sender learned about us via discovery, not our local clock at receive time.

- **Request decrypt** uses the RECEIVED `reqBoots`/`reqTime`
  (`msgAuthoritativeEngineBoots`/`...Time` from the request USM parameters),
  threaded `handleV3Packet → decryptPDU → decryptAES128`. `checkTimeliness`
  runs first and (for an authenticated request) bounds `reqBoots == engineBoots`
  and `reqTime` within ±150 s, but `reqTime` can still differ from the agent's
  *current* `engineTime()` by up to the window. Building the IV from the local
  clock instead (the #2640 bug) corrupted the CFB keystream and silently dropped
  every encrypted query made while the manager's cached time drifted from ours —
  the normal steady state under clock advance.
- **Response encrypt** uses the agent's *current* `engineBoots`/`engineTime()`
  (`encryptPDU → encryptAES128`), and the same values are written into the
  response's `msgAuthoritativeEngineBoots`/`...Time`. We are the authoritative
  engine for our own reply, so the IV and the header boots/time agree by
  construction and a manager decrypts the response using the boots/time it reads
  from our header. This path is unchanged by the #2640 fix.
- DES (`decryptDES`/`encryptDES`, RFC 3414 §8) derives its IV from `privParams`
  XOR the pre-IV salt alone, so boots/time do not enter the DES IV.

### engineBoots persistence

`engineBoots` is loaded, incremented, and persisted once at agent construction
so `(engineBoots, engineTime)` is monotonic across daemon restarts, as RFC 3414
requires of an authoritative engine:

- State file: `/var/lib/xpf/snmp-engineboots` (a single decimal integer). The
  path is injectable via `NewAgentWithBootsPath` — the test seam used to assert
  the load/increment/persist cycle without touching real state.
- First boot (file missing): `engineBoots` starts at `1` and the file is
  created. Each subsequent start reads the prior value, increments it, and
  persists the new value (1 → 2 → 3 …). `engineTime()` then counts from *this*
  boot (`startTime`), so the pair advances monotonically.
- A corrupt/unreadable counter, a value already at the RFC ceiling, an
  increment that would reach the ceiling, or a failed durable write all **fail
  closed** by pinning `engineBoots` to the ceiling (`engineBootsMax`) rather
  than restarting at `1` (#2649). RFC 3414 §2.2 requires `engineBoots` to be
  monotonic for the authoritative engine; resetting to a low value while the
  deterministic engineID is unchanged re-opens the replay window — a captured
  authenticated request from a prior low-boots epoch could become timely again.
  At the ceiling `checkTimeliness` rejects every authenticated request (§3.2
  step 7), so managers must re-discover and the engineID must be reconfigured
  to recover. The agent still starts and answers discovery/report (no SNMP
  DoS), but no replayed low-boots packet is serveable while the counter is
  corrupt, maxed, or unpersistable. First boot (missing file) still legitimately
  starts at `1` — that is a genuinely new epoch, not a reuse of a low value.
- The persist uses `fsatomic.WriteFileDurable` (fsync-on-write); the directory
  is created with `fsatomic.MkdirAllDurable`. This is slow-path (once per start),
  so per-write durability is affordable.

## Live reconfigure (commit-time reconcile)

The agent is created once at daemon startup and keeps serving on UDP/161.
`UpdateConfig(cfg *config.SNMPConfig)` swaps the live authorization/identity
config and rederives the USM v3 user table in place, so a commit that changes
community authorization (`read-write` -> `read-only`, or a deleted community)
or the v3 user set reaches the running agent without a restart — restarting
would drop the UDP listener and interrupt in-flight polls. The daemon calls it
from `applyConfigLocked` (guarded on a non-nil agent; enabling SNMP for the
first time still requires a restart, like the other start-once subsystems).

The reconcile runs **early** in `applyConfigLocked` — before the dataplane
apply, which can abort the reconcile pipeline early (it returns on
`ErrPolicySchedulerProtocolIncompatible`). `Store.Commit()` has already
promoted and persisted the compiled config by the time `applyConfigLocked`
runs, so the committed authorization is live regardless of whether the later
dataplane apply succeeds. Reconciling only at the tail would let an
early-aborting apply leave a committed-downgraded community still serving the
old (read-write) SET gate. The daemon-package test
`TestApplyConfigLockedReconcilesSNMPBeforeDataplaneAbort` pins this ordering
(it drives `applyConfigLocked` with a dataplane that returns the aborting
sentinel and asserts the live gate still reflects the downgrade).

Concurrency: `cfg` and the derived `v3Users` are guarded by `cfgMu`
(`sync.RWMutex`). The request-serving goroutine reads them through
`snapshotCfg` / `snapshotV3User` / `hasV3Users` under `RLock`; `UpdateConfig`
swaps both under `Lock`, so a request never observes a half-applied config
(new community map with stale v3 users, or vice versa). `engineID` /
`engineBoots` / `startTime` are the agent's stable identity and are never
swapped. A `nil` cfg (the whole `snmp` stanza removed) disables the agent's
authorization surface: every request is dropped because no community matches.

## Entry points

- `Agent` — `agent.go`.
- `IfData` — `agent.go`. Per-interface metrics (name, MTU, speed,
  admin/oper status, octets, errors, drops).
- `V3UserDisplay` — `v3.go`.
- `NewAgent(cfg *config.SNMPConfig) *Agent` — `agent.go`.
- `Start(ctx context.Context) error` — `agent.go`. Blocks until ctx cancelled.
- `Stop()` — `agent.go`.
- `SetIfDataFn(fn)` — `agent.go`. Caller-supplied accessor for live
  interface data.
- `NotifyLinkUp` / `NotifyLinkDown` — `traps.go`.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## ASN.1 specifics

- Tag constants used: Counter32 (0x41), Gauge32 (0x42), Counter64 (0x46).
- Exception values: `noSuchObject` (0x80), `noSuchInstance` (0x81),
  `endOfMibView` (0x82) — emitted for missing OIDs in walks.
- GETNEXT walking order is driven by a static OID list; it must stay in
  ascending order.

## Gotchas

- Maximum response packet size is 4096 bytes. GETBULK may legitimately
  require multiple responses.
- **GETBULK response size is bounded (RFC 3416 §4.2.3).** The agent caps
  `maxRepetitions` at 100 (defense in depth) *and* bounds the fully-encoded
  response to an effective maximum size. For v3 that effective size is
  `min(request msgMaxSize, 4096)` with `msgMaxSize` clamped up to the RFC
  484-byte floor (a bogus/tiny advertised value cannot starve the response);
  v2c carries no per-request `msgMaxSize` on the wire, so the effective size is
  the local 4096-byte maximum. During expansion the response is built and then
  trimmed: trailing varbinds are dropped until the encoded message (including
  the v3 USM/scopedPDU and any auth/priv overhead) fits. Trimming — not
  `tooBig` — is the normal outcome; the manager continues the walk with a
  follow-up GETBULK from the last returned OID. `tooBig` (with an empty varbind
  list) is returned only in the pathological case where not even a single
  varbind fits. This prevents emitting an oversized UDP datagram that the peer
  or the network would fragment or drop. See `effectiveMaxSize` / `trimToFit`
  in `agent.go`.
- **Trap delivery is asynchronous and bounded (#2991).** Link-state traps
  are emitted from the daemon's netlink link-monitor goroutine.
  `sendLinkTraps` builds the packet on the caller's goroutine (cheap) and
  enqueues one job per target onto a bounded channel
  (`trapQueueDepth = 256`) drained by a single worker goroutine; the
  blocking `net.DialTimeout` (and DNS resolution for an FQDN target) runs
  on the worker, NOT on the link monitor. A dead or slow target therefore
  cannot stall link-state processing. The queue is started lazily (works
  for both `NewAgent` and bare-struct test agents). When the queue is full
  the trap is DROPPED and `trapsDropped` is incremented rather than
  blocking the caller — dropping is the correct backpressure when targets
  are not draining. The delivery is replaceable through the `trapSender`
  package var (the seam tests use to inject a slow sender). Before #2991
  delivery was synchronous and inline, so an unreachable trap target (or a
  hung DNS lookup for an FQDN target) blocked link-state processing for up
  to the 2s dial timeout × target count.
- **The v2c trap community is selected deterministically (#2989).**
  `selectTrapCommunity` picks the lexicographically-first configured
  community (falling back to `public` when none is configured). The old
  code ranged the `Communities` map and broke on the first entry, which —
  because Go map iteration is randomized — picked a different community per
  run when more than one was configured, so a collector accepting only one
  community saw flaky traps and a less-privileged community could leak
  through the wrong credential boundary. Trap groups are likewise iterated
  in sorted order so dispatch and log output are reproducible.
- Don't add a third BER library to this package. The hand-coded encoder
  is intentional; keeping the surface small avoids bringing in an SNMP
  framework with its own poll loop and threading model.

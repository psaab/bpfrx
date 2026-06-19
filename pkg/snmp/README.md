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
- Traps fire immediately on link-state change — they aren't queued, so
  back-to-back link flaps produce back-to-back traps.
- Don't add a third BER library to this package. The hand-coded encoder
  is intentional; keeping the surface small avoids bringing in an SNMP
  framework with its own poll loop and threading model.

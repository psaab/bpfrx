# #5883 — Caller-controlled forwarded metadata suppresses HA peer actions

**Status:** PLAN-READY (research only — no production code changed)
**Severity:** HIGH (security, audit)
**Base:** `origin/master` @ `13fad1d31`
**Branch:** `research/5883-peer-forward-trust`

## 1. Problem restated

Several gRPC handlers decide "is this an internal peer-forwarded request?" by
reading a **caller-supplied gRPC metadata header** (`x-peer-forwarded`, and the
sibling `xpf-no-peer`). The predicate `peerForwardedFromContext`
(`pkg/grpcapi/server_helpers.go:374`) checks only metadata **presence**:

```go
func peerForwardedFromContext(ctx context.Context) bool {
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok { return false }
    return len(md.Get("x-peer-forwarded")) > 0
}
```

Any caller who can set that header is treated as the peer node. The marker is
used both as a **recursion guard** (A→B must not fan back to A) *and* as a
**trust signal** that suppresses mandatory HA work. Conflating the two is the
bug: a non-peer caller that sets the header makes a "cluster-wide" clear run
**only locally**, leaving the peer's sessions to survive a failback; makes an
`include_peer` summary silently return **local-only** data; and gates
cross-node **SystemAction** (failover) proxying.

## 2. Blast radius — inventory of every recursion/proxy marker

Two reserved metadata keys are used as caller-visible recursion/trust markers.
Both are read directly from inbound metadata with no channel/identity check.

### Marker A — `x-peer-forwarded` (action + summary suppression)

| Site | File:line | What it currently trusts | Impact if forged |
|---|---|---|---|
| Clear-all recursion guard | `server_sessions.go:1087-1088` | inbound md presence → `forwarded` | **Peer clear suppressed** → sessions survive on peer (HIGH) |
| Filtered clear peer fan-out | `server_sessions.go:1172` (`if !forwarded`) | same `forwarded` var | Peer clear suppressed (HIGH) |
| Zone-pair summary fan-out | `server_sessions.go:941` (`!peerForwardedFromContext`) | inbound md | Local-only summary reported as cluster (MED) |
| Session summary fan-out | `server_sessions.go:634` region (`proxyPeerSessionSummary`) | inbound md | Local-only summary (MED) |
| SystemAction cross-node | `server_diag_system_action.go:374,451` | `peerForwardedFromContext` | Suppress/steer failover proxy (HIGH) |
| Outbound stamp (clear) | `server_sessions.go:1046,1533` | — (sender side) | — |
| Outbound stamp (sysaction) | `server_diag_system_action.go:25` | — (sender side) | — |
| Predicate | `server_helpers.go:374-379` | — (the shared reader) | — |

### Marker B — `xpf-no-peer` (a.k.a. `monitorNoPeerMarker`) (monitor/show one-hop)

| Site | File:line | Trusts | Impact |
|---|---|---|---|
| MonitorInterface one-hop | `server_diag_monitor.go:334,346` | inbound md presence | Suppress monitor peer-proxy (LOW/MED) |
| Cluster show one-hop | `server_show_cluster_text.go:35-36` | inbound md presence | Suppress peer show (LOW) |
| Outbound stamp (monitor) | `server_diag_monitor.go:592` | — | — |
| Outbound stamp (forwarding show) | `server_show_forwarding.go:85` | — | — |

### REST bridge (`pkg/api`)

REST cluster calls (`clearSessionsHandler`, `sessionSummaryHandler`,
`sessionZonePairHandler`) invoke the gRPC service **in-process** with the HTTP
request context, e.g. `svc.ClearSessions(r.Context(), …)`
(`pkg/api/sessions.go:465,735,785,972`). `r.Context()` carries **no gRPC
incoming metadata**, so `metadata.FromIncomingContext` returns `ok=false` and
the marker cannot currently be injected through REST. **This safety is
incidental, not enforced** — any future change that bridges HTTP headers into
gRPC metadata (or a gateway that does) reintroduces the hole. The design must
strip defensively so REST safety is a guarantee, not an accident.

### Not a marker (the solution side)

`xpf-fabric-auth` (`fabric_auth.go`) is the #4107 control-link PSK **auth
token**, not a trust-suppression marker. It is the existing authenticated-peer
mechanism this design builds on. Config-sync / IPsec-SA-sync use `SyncApply`
over the fabric, not a metadata recursion marker — out of scope.

## 3. How peer-forward actually works today (the trust anchor)

This is the decisive finding: **an authenticated cross-node channel already
exists.**

- **Two listeners.** `Server.Run()` binds the **loopback** listener
  (`127.0.0.1:50051`); a non-loopback bind is **clamped back to loopback**
  (`clampGRPCBindToLoopback`, #5035) because it is *unauthenticated, full
  service*. `RunFabricListener` binds a **separate fabric listener** on the
  cluster control IP (`fab0`/`fab1`, port 50051) — the **only** network-exposed
  gRPC surface.
- **The fabric listener is authenticated + allowlisted.**
  `buildFabricServer()` (`server.go:491`) installs, in order:
  1. `fabricAuth*` (#4107) — verifies the control-link PSK (time-windowed
     HMAC `xpf-fabric-auth`); rejects unauthenticated callers with
     `Unauthenticated`. Dual-accept grace for unkeyed/rolling-upgrade.
  2. `fabricAllowlist*` (#4122) — permits only the peer-proxied RPCs
     (`fabricAllowedUnaryMethods`: GetSessions, **ClearSessions**,
     GetSessionSummary, GetZonePairSummary, cross-node failover SystemAction;
     `fabricAllowedStreamMethods`: MonitorInterface). Everything else →
     `PermissionDenied`.
  The **loopback listener installs neither** — it is the trusted-local surface.
- **A real peer-forward always arrives on the fabric listener, authenticated.**
  `Server.dialPeer()` (`server_diag.go:22`) dials the **peer's fabric IP**
  (`<peerIP>:50051`) with `fabricAuthCreds` attaching the PSK token. There is no
  path by which a genuine peer-forward lands on the loopback listener.

**Therefore the authenticated fabric channel is the trust anchor.** "Is this a
peer-forwarded request?" is answerable as: *did this call arrive on the fabric
listener and pass fabric-auth?* — a property the server knows for itself and a
caller cannot forge. The `x-peer-forwarded` metadata is redundant with (and
strictly weaker than) that channel identity.

Residual in the existing PSK (already documented in `fabric_auth.go`): the token
is `HMAC(PSK, time-window)` — replayable within its ~30–90 s window and **not
bound to method or request identity**. That is the #4107 replay residual and the
seam for the issue's "bind hop markers to method + request identity."

## 4. Design options

### Option A — Channel-derived in-process capability (recommended)

Make the authenticated fabric channel the sole trust anchor; strip the wire
marker on ingress everywhere.

1. **Ingress strip.** Add a small interceptor (unary + stream) on **both**
   servers that deletes the reserved keys (`x-peer-forwarded`, `xpf-no-peer`)
   from inbound metadata before any handler runs. A client-supplied marker is
   now unconditionally ignored.
2. **Fabric sets an unforgeable capability.** In `fabricAuth*` (which already
   runs first on the fabric listener), after admission, attach a **private
   typed context value** — `context.WithValue(ctx, peerCallKey{}, peerCap{…})`
   — recording "authenticated peer, one hop, method = M". `peerCallKey` is an
   unexported type so no other package (and nothing off-process) can set it.
   Streams carry it via a wrapped `ServerStream`.
3. **Rewire the predicates.** `peerForwardedFromContext` and the `xpf-no-peer`
   reader read **only** the in-process capability (and check its method matches
   the current method — one-hop, method-bound). The loopback path never has the
   capability → always "not forwarded" → always fans out (correct for a local
   operator/CLI/REST clear).
4. **Keep outbound stamping for one release** (mixed-version): the sender still
   sets `x-peer-forwarded`/`xpf-no-peer` on the outbound dial so an **old** peer
   that still reads metadata keeps its recursion guard. A **new** receiver
   ignores the metadata and uses the capability. Drop the outbound stamp in a
   later cleanup once both nodes are ≥ this release.

*Security properties:* trust is derived from an authenticated channel +
in-process capability that cannot cross a process boundary; the marker is
stripped on every untrusted ingress; one-hop and method-bound by construction
(the capability is minted per inbound fabric call and never propagates
outbound). *Cost:* ~2 small interceptors + a context key + rewiring 6 read
sites. No proto change, no new socket, no cert lifecycle. *Migration:* clean —
new node interoperates with old node in both directions during rollout.

*Grace-window nuance:* set the capability only when the fabric call is
**authenticated** (PSK `tokenOK`), not merely grace-admitted. In an **unkeyed**
cluster (no `authentication-key`) the fabric listener already grace-accepts any
on-segment caller for *all* allowlisted RPCs (it can flush this node's sessions
directly), so the incremental "suppress peer fan-out" risk is subsumed by the
pre-existing "set the PSK" posture (#4107). Treating a tokenless grace call as
**non-peer** (fan out) is the safe default: over-fanning is at most one bounded,
idempotent extra hop (the old-peer metadata guard or the new-peer capability
stops the third hop), never a storm.

### Option B — Signed one-hop hop-token (method + request-id bound)

Replace the bare marker with a capability token = `HMAC(PSK, method ‖
request-id ‖ hop=1 ‖ window)` carried in metadata; the receiver verifies it and
refuses `hop>1`. This **hardens the wire token** to the issue's "bind to method
+ request identity + one hop," closing the #4107 replay-to-another-method
window.

*Pros:* strongest wire-level binding; defeats cross-method replay even by a
PSK-holder. *Cons:* still fundamentally a bearer token on the wire (replayable
within its window unless a nonce/state is added — which the connectionless
interceptor model makes expensive, per the #4107 note); more moving parts;
needs the request-id plumbed. Best framed as a **Phase-2 hardening of the
fabric PSK token itself**, layered under Option A rather than instead of it.

### Option C — Dedicated internal-only listener / socket for peer-forward

Serve peer-forwarded RPCs on a distinct listener (separate port, or a
Unix-domain socket with `SO_PEERCRED`, or mTLS with per-node certs); the
external listeners strip the marker entirely and never treat any call as
forwarded.

*Pros:* cleanest separation; with mTLS/UDS the peer identity is
transport-authenticated (no bearer replay). *Cons:* the fabric listener **is
already** the dedicated internal listener — Option C's value reduces to
"upgrade the fabric auth from PSK to mTLS/UDS," which is the deferred #4047
convergence and a much larger change (cert provisioning/rotation across nodes).
High cost, and orthogonal to the immediate "stop trusting a user header" fix.

## 5. Recommendation

**Adopt Option A now; layer Option B as Phase 2; keep Option C (mTLS) as the
deferred #4047 end-state.**

Rationale: the authenticated fabric channel already exists and is the correct
trust anchor. Option A converts the bug from "trust a user header" to "trust an
authenticated channel + unforgeable in-process capability" — exactly the issue's
required invariant — with a small, proto-free, migration-clean change. Options
B/C harden the wire token and the transport respectively but are not needed to
close the HIGH hole and carry materially more cost.

### Phased plan

**Phase 1 (minimal high-value first increment) — close the forgery:**
- Add the ingress-strip interceptor for `x-peer-forwarded` + `xpf-no-peer` on
  both the loopback and fabric servers.
- In `fabricAuth*`, on **authenticated** admission, set the private one-hop,
  method-bound in-process capability.
- Rewire `peerForwardedFromContext` and the `xpf-no-peer` reader to the
  capability only.
- Keep outbound stamping for mixed-version interop.
- Tests: external metadata injection on the loopback listener must **not**
  suppress the peer clear (fan-out still happens); an authenticated fabric call
  is treated as forwarded (no re-fan / no storm); a grace-window tokenless
  fabric call fans out safely; REST clear always fans out; replay of the marker
  to another method is inert (capability is method-bound / absent).

**Phase 2 — bind the fabric token to method + request-id + one hop** (Option B
layered on the #4107 token), closing the replay-to-another-method residual.

**Phase 3 — mTLS/per-node-cert fabric auth** (#4047), removing the bearer
replay horizon entirely.

### UX sub-goal (issue invariant: explicit peer completeness/failure status)

Independent of the trust fix, the fan-out paths should return **explicit peer
completeness** rather than silently suppressing work. `ClearSessions` already
carries `Failures`/`FailureSummary` (#2468/#5882) and the summary paths carry a
`peer_status` (#5320) — extend these so a caller can always distinguish
"cluster-wide, both nodes done" from "local-only (peer unreachable / not
attempted)". This is a small additive change, best folded into Phase 1's tests
so a suppressed peer action is observable, never silent.

## Validation matrix (for the eventual implementation)

- Inject `x-peer-forwarded`/`xpf-no-peer` over loopback gRPC → peer work still
  performed (RED on the current code).
- Authenticated fabric call → treated as forwarded, no re-fan, no storm.
- Unkeyed-cluster grace fabric call → fans out safely (bounded).
- Proxied one-hop call cannot replay to a different method.
- Mixed-version: new↔old in both forward directions keep their recursion guard.
- REST clear/summary always fan out; a suppressed peer action is reported via
  completeness status, never silent.

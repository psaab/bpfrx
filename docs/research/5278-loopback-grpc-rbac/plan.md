# #5278 — Server-side per-principal auth/authz for the loopback gRPC control plane

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)
**Issue:** #5278 (codex-review-178 A8-b3-F1). Severity: High (privilege escalation / RBAC bypass).
**Base:** origin/master `0ab8a90a8`.

## 1. Issue framing

The primary gRPC listener (`Server.Run`, `pkg/grpcapi/server.go:352-359`) binds
TCP `127.0.0.1:50051` and installs ONLY `configLockInterceptor` + a max-recv
size — **no authentication, no authorization**. Its documented contract is
"gRPC is loopback-only and every RPC is inherently trusted." That assumption is
**false on this appliance**: the daemon provisions every non-super login-class
user (`read-only`, `operator`, custom `#4304` classes) with a real
`useradd -m -s /bin/bash` account (`pkg/daemon/daemon_system.go`). Such a user
can run a 3-line `insecure` gRPC client to `127.0.0.1:50051` (exactly like
`cmd/cli/main.go:46` does) and invoke `SystemAction{zeroize|reboot|power-off}`,
`Commit`, `Delete`, `Rollback` — executed as root. The CLI's RBAC
(`checkPermission` → `requiredPermission`, `pkg/cli/permissions.go`, gated on
`c.userClass`) is **client-side only**; the server never sees it. Loopback
location + client-side RBAC are not identity boundaries.

## 2. Honest scope / value framing

This closes a **real local privilege-escalation** on a multi-user appliance
(the whole point of Junos login classes is that `read-only`/`operator` users
CANNOT zeroize/reboot/commit). The blast radius of the FIX is moderate: a
transport and interceptor change on the one local control-plane listener, plus
a server-side method→permission table. It is NOT a crypto/wire-flag-day like
#5078 — the fabric listener (network-exposed, node-to-node) already
authenticates (#4107) + allowlists (#4122) and is UNCHANGED here. *If reviewers
conclude the transport flag-day churn outweighs the risk on single-user
deployments, a narrower Path (C) or PLAN-KILL-with-mitigation is an acceptable
verdict.*

## 3. What's already shipped / relevant

- **Fabric listener auth (#4107) + allowlist (#4122):** `server.go:477-480`
  chains `fabricAuthUnaryInterceptor` + `fabricAllowlistUnaryInterceptor`. This
  is the EXISTING, reviewed pattern for server-side gRPC gating — the local fix
  mirrors it with a per-principal (not per-node) identity source.
- **Bind clamp (#5035/#5170/#5215):** `clampGRPCBindToLoopback` guarantees the
  primary listener is loopback-only. #5209 enforces the config-lock HOLDER.
  None of these establish per-principal identity — that is exactly the gap.
- **Config RBAC model (#4304 S-2):** `system login user <name> class <class>`
  (`compiler_system.go:120` `LoginUser`) + predefined + custom `system login
  class <name>` definitions give a **username → class → permissions** mapping
  the daemon ALREADY holds in `ActiveConfig`.
- **Permission table:** `pkg/cli/permissions.go` `requiredPermission(parts)` maps
  a COMMAND to `config.PermView|PermControl|PermMaint|PermAll`; `checkPermission`
  verifies the class. This is command-string-based (client-side); the server
  sees gRPC METHODS, so a method→permission table is the new artifact.
- **Redaction already server-consulted per class (#4099/#4111):** show-config
  redaction already keys on `userClass` — precedent that class-based server-side
  decisions exist; but redaction is applied where the class is PASSED IN by the
  (trusted) CLI, which is exactly what an untrusted raw client bypasses.

## 4. Threat model (what the fix must stop)

A local OS user with a provisioned shell whose login class is NOT super-user
runs a raw gRPC client to the primary listener and invokes a privileged method.
The fix must make the SERVER derive the caller's principal (unspoofably) and
DENY (codes.PermissionDenied) a method the caller's class lacks permission for —
without trusting any client-supplied identity. Out of scope: a super-user /
root shell (already fully privileged); the fabric path (separately authed);
network attackers (bind is loopback-only).

## 5. Design — the two required pieces

**Piece 1 — an unspoofable local principal.** The server must learn the
connecting user's UID from the KERNEL, not the client.
**Piece 2 — server-side method authorization.** An interceptor on the primary
listener maps UID → OS username → login class → permission set, looks up the
called method's required permission in a server-side table, and allows/denies.

Piece 2 is identical across all paths; the paths differ only in Piece 1.

### Multiple Path Options for Piece 1 (unspoofable identity)

**Path A (RECOMMENDED) — Unix-domain socket + SO_PEERCRED.**
Move the primary listener from `net.Listen("tcp", 127.0.0.1:50051)` to a Unix
socket (e.g. `/run/xpf/grpc.sock`, dir `0750 root:xpf-cli`, socket `0660`).
grpc-go exposes the peer's `*unix.Ucred` via a custom `credentials.TransportCredentials`
(or a wrapping `net.Listener` that stashes `SO_PEERCRED` into the conn, read in
the interceptor via `peer.FromContext`). UID → `user.LookupId` → username →
class.
- **Pro:** OS-enforced, unspoofable, zero token lifecycle; filesystem perms are
  defense-in-depth; no secret at rest.
- **Con:** transport **flag-day** — `cmd/cli/main.go` + any local tooling must
  dial `unix:///run/xpf/grpc.sock`; `show system` help text updates; the many
  tests that dial `127.0.0.1:50051`/bufconn need a socket or a peer-cred fake.
- **Compat:** the primary listener is LOCAL-only (loopback-clamped) — a Unix
  socket serves exactly the same reachability set, so no remote consumer is lost.

**Path B — TCP loopback + bearer token.**
Keep TCP; issue a per-login token (a setuid/PAM hook or a per-user
`0600 $HOME/.xpf/token`), client sends it in metadata, an interceptor validates
→ class.
- **Con:** token issuance + rotation + revocation infra; a token file is
  exfiltratable and is a secret at rest; weaker than kernel-enforced creds; more
  code. NOT recommended.

**Path C — TCP loopback + kernel peer lookup (no transport change).**
Derive the peer PID/UID by matching the connection 4-tuple in `/proc/net/tcp{,6}`
→ socket inode → `/proc/<pid>` owner.
- **Con:** inherently **racy/TOCTOU** (PID reuse, the peer can exit/exec between
  accept and lookup), fragile across kernels, and 4-tuple→inode→pid is not
  atomic. A security identity built on this is unsound. Rejected on correctness.

**Recommendation:** **Path A.** SO_PEERCRED on a Unix socket is the only
unspoofable, race-free, secret-less option and matches how privileged local
daemons universally authenticate local clients.

### Piece 2 — server-side authz interceptor (all paths)

- New `principalAuthUnaryInterceptor` + stream variant on the primary listener,
  chained BEFORE `configLockInterceptor` (mirrors the fabric chain
  `server.go:479`).
- `methodPermission(fullMethod string) config.Permission`: a server-side table
  mapping each gRPC method to its minimum permission. Default-DENY-privileged:
  the SystemAction/Commit/Delete/Rollback/config-mutating/maintenance methods
  require `PermControl`/`PermMaint`; read-only Get/Show/List require `PermView`.
  **A method absent from the table defaults to the STRICTEST (PermMaint/PermAll)
  — fail-closed**, so a newly-added privileged RPC is not silently open.
- Principal→class: UID → `user.LookupId` → username → `ActiveConfig` `system
  login user <name> class` (super-user if root/uid 0; the daemon's own
  in-process CLI path is exempt — it never crosses the socket).
- Authz: `classHasPermission(class, methodPermission(method))` reusing the SAME
  permission-evaluation logic as `pkg/cli/permissions.go` (factor the class→perm
  evaluation into a shared package so client + server cannot drift — a drift is
  the #2419-class trap). Deny → `status.Error(codes.PermissionDenied, ...)`,
  logged with method + uid + class (no secrets).
- The interceptor is installed ONLY on the primary listener; the fabric listener
  keeps its node-auth chain (a fabric peer is a node, not a login user).

## 6. Public API / compat preservation

- gRPC service definitions UNCHANGED (no proto change). Only interceptors + the
  listener transport change.
- `cmd/cli` dials the new endpoint; behavior for a super-user is identical.
- A non-super class calling a privileged method now gets `PermissionDenied` — a
  BEHAVIOR CHANGE that is the fix (previously it wrongly succeeded).

## 7. Hidden invariants the change must preserve

1. **The in-process interactive CLI must not be locked out.** `cli.New(d.store)`
   runs IN the daemon (root) and does NOT cross the socket — it must keep full
   access; only cross-socket callers are authz'd. Verify the in-process path
   never hits the interceptor.
2. **Super-user parity.** uid 0 / super-user class retains PermAll — no
   regression to legitimate admin tooling.
3. **No drift between client-side and server-side RBAC.** Factor class→perm
   evaluation into ONE shared function; a server that denies what the CLI allows
   (or vice-versa) is a correctness bug.
4. **Fail-closed on unknown identity.** UID with no mapped username, or a
   username with no class, → deny privileged (treat as least privilege), never
   default-allow.
5. **Startup ordering / socket lifecycle.** Socket created 0660 under a dir only
   the xpf-cli group can traverse; removed on restart (stale socket unlink);
   never world-writable.
6. **The fabric path is untouched** (#4107/#4122 invariants intact).

## 8. Risk assessment

| Risk | Level | Note |
|------|-------|------|
| Behavioral regression (lock out a legit user/tool) | MED | mitigated by super-user parity + in-process exemption + a broad test matrix per class × method |
| Transport flag-day breakage (Path A) | MED | every 50051 dial site (cmd/cli + ~N tests) must move to the socket in the SAME change |
| Client/server RBAC drift | MED | mitigated by a single shared class→perm evaluator |
| SO_PEERCRED plumbing in grpc-go | LOW-MED | well-trodden pattern (custom creds/listener); needs a careful unit test with a real socketpair |
| Security incompleteness (a privileged method missed in the table) | MED | mitigated by fail-closed default = strictest |

## 9. Test plan

- Unit: `methodPermission` table (every registered method has an explicit entry;
  a test enumerates the service descriptor and FAILS if any method is unmapped —
  prevents a future privileged RPC defaulting open).
- Unit: `principalAuth` interceptor over a real `socketpair`/Unix listener with a
  faked `SO_PEERCRED` uid → asserts super-user allowed, read-only DENIED on
  SystemAction/Commit, read-only ALLOWED on a Get. RED-on-revert (drop the
  interceptor → the read-only-denied test fails).
- Unit: class→perm shared evaluator parity — a table test that the server
  decision == the CLI `checkPermission` decision for the same (class, method↔cmd).
- Integration: the in-process CLI path retains full access (no socket).
- No dataplane/cluster smoke (control-plane only); NO test-failover (no
  session-sync/failover/VRRP code touched — the fabric path is untouched).

## 10. Out of scope (explicitly)

- Fabric/cluster auth (already #4107/#4122).
- Remote-over-network CLI to a different node (not served by the primary
  listener; loopback-clamped).
- Rewriting the CLI permission table semantics (#4304) — reuse it.
- HTTP REST/Prometheus on :8080 (separate surface; if it exposes privileged
  mutations, file a SEPARATE issue — note in the plan whether it does).

## 11. Open questions for adversarial review

1. **Path A vs B vs C** — is the Unix-socket flag-day acceptable, or is there a
   deployment that needs TCP 50051 (external tooling, a monitoring probe)? If a
   TCP consumer exists, does it need privileged methods (then it needs a
   principal too) or only reads (then a read-only-over-TCP compat listener could
   remain — but that re-opens the hole for privileged methods unless the authz
   interceptor is on BOTH)?
2. **Is SO_PEERCRED sufficient**, or must we also pin the socket's dir/mode to a
   dedicated `xpf-cli` group so only provisioned login users (not arbitrary
   local processes) can even connect? (Defense in depth vs. authz-anyway.)
3. **Method→permission table completeness** — is enumerating the service
   descriptor at test time enough to guarantee no privileged method defaults
   open, or do we need a compile-time/registration-time assertion?
4. **Client/server RBAC single-source** — where should the shared evaluator live
   (`pkg/config` permissions? a new `pkg/rbac`?) so both `pkg/cli` and
   `pkg/grpcapi` consume it without an import cycle?
5. **Is a phased rollout wanted** — ship the server-side authz interceptor FIRST
   on a Unix socket while KEEPING the TCP listener authz'd too (belt and
   suspenders) for one release, then drop TCP? Or hard-cut? (Hard-cut is simpler
   and closes the hole immediately; a dual-listener transition doubles the
   attack surface during the window.)
6. **Does the HTTP REST :8080 surface expose the same privileged mutations** and
   thus need the same principal check (or is it read-only/metrics only)? If it
   mutates, this issue is incomplete without it — decide scope now.

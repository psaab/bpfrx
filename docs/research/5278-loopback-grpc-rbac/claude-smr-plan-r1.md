# Claude SMR — hostile plan review r1 — #5278

**Reviewing:** `docs/research/5278-loopback-grpc-rbac/plan.md` @ `96022a955`.
**Stance:** hostile. The core architecture (Unix socket + SO_PEERCRED + a
server-side method→permission authz interceptor) is SOUND and is the right
answer. But the plan ships two factually-wrong premises and understates the
flag-day. **Verdict: PLAN-NEEDS-MINOR** (core survives; revise premises + scope).

## F1 (MAJOR premise error) — the "in-process CLI never crosses the socket" invariant is FALSE
Plan §7.1 and §10 assert the in-process interactive CLI (`cli.New(d.store, …)`,
daemon_run.go:677) is exempt because it "never crosses the socket." **It does.**
`pkg/cli` self-dials gRPC for a large fraction of commands:
`session_filter.go:438,518` (`pb.NewBpfrxServiceClient(conn)`), `cli_clear.go:354`
(ClearSessions), `cli_show_chassis.go:122`, etc. So the interactive CLI is itself
a gRPC CLIENT of the local server.
**Impact + fix:** this does NOT break the architecture — it improves it. Drop the
"exemption." The console CLI runs in the daemon as **root (uid 0)**; under
SO_PEERCRED it authenticates as uid 0 → super-user → PermAll. So the console
keeps full access *by authenticating*, not by bypassing. The plan must:
(a) replace the exemption with "console = uid 0 → super-user"; (b) RESOLVE how
the in-process CLI's `conn` is built — if it is a real dial to the listener,
SO_PEERCRED applies cleanly (peer = root); **if it is an in-memory bufconn, there
is no Unix peer cred and the interceptor must have an explicit in-process trust
tag** (an AuthInfo the bufconn path sets). This is a concrete design item the
plan currently hand-waves. VERIFY the conn construction before implementation.

## F2 (MAJOR scope error) — the flag-day is bigger than stated
Plan §5 Path A and §8 scope the transport flag-day to "cmd/cli + ~N tests."
Wrong: **every `pb.NewBpfrxServiceClient(conn)` dial site in `pkg/cli` must also
move** to `unix:///run/xpf/grpc.sock` (or the shared dial helper must). Enumerate
ALL dial sites (grep `NewBpfrxServiceClient` across pkg/cli + cmd/cli) and route
them through ONE dial helper so the transport is changed in exactly one place.
The plan must list this helper as the single cut-point and count the true dial
surface, not undercount it.

## F3 (MINOR, resolved) — shared evaluator location is decided, not open
Plan open-Q4 asks where the shared class→perm evaluator lives. It's answered by
the code: `pkg/config` already holds the `Perm*` constants + the class→permission
mapping (`compiler_system.go:913`, `LoginClass.MappedPermissions`,
`login_custom_class_4304`), and `pkg/grpcapi` ALREADY imports `pkg/config`
(server.go:24). So: put `classHasPermission(class, Permission) bool` (or reuse
the existing evaluator) in `pkg/config`; both `pkg/cli` and `pkg/grpcapi` consume
it — no import cycle. Only the **method→required-permission** table is new and
belongs server-side in `pkg/grpcapi`. Close open-Q4 with this.

## F4 (MAJOR completeness) — #5278 is INCOMPLETE without the :8080 REST sibling
The HTTP REST surface on :8080 exposes `POST /api/v1/config/load` (pkg/api/api.go:86)
— a privileged config mutation with the SAME loopback-trust gap. An attacker
denied on gRPC simply uses :8080 instead. Fixing gRPC alone is a partial
mitigation that a hostile reviewer must reject as "moves the hole, doesn't close
it." REQUIRED: either (a) expand #5278 to apply the same principal check to the
:8080 mutating endpoints, or (b) file a SEPARATE tracked issue for :8080 NOW and
state in the plan that #5278 is explicitly the gRPC leg of a 2-surface fix. Do
not leave :8080 as an "open question" — it's a known live hole.

## F5 (MINOR) — SO_PEERCRED/grpc-go mechanism must be specified concretely
Plan §5 Path A says "grpc-go exposes the peer's Ucred via custom creds or a
wrapping listener" — too vague for a plan the reviewers must bless. Specify: a
`credentials.TransportCredentials` whose `ServerHandshake(conn)` type-asserts
`conn.(*net.UnixConn)`, calls `unix.GetsockoptUcred(fd, SOL_SOCKET, SO_PEERCRED)`,
and returns an `AuthInfo` carrying the `*unix.Ucred`; the interceptor reads it via
`peer.FromContext(ctx).AuthInfo`. Note the fd must be extracted via
`SyscallConn().Control(...)` (not a bare `.File()` which dups + can race). Pin
this so the reviewers can judge feasibility (it is feasible; it must be explicit).

## F6 (MINOR, keep) — fail-closed default is right; note the availability tradeoff
The method→permission table defaulting an unmapped method to strictest is
correct (a new privileged RPC never defaults open). Note the tradeoff: a new
READ RPC left unmapped is wrongly DENIED to read-only users until mapped — an
availability regression, not a security one. Mitigate with the
enumerate-the-service-descriptor test that FAILS on any unmapped method, so the
map is never silently incomplete in EITHER direction. Keep.

## Verdict
**PLAN-NEEDS-MINOR** — the Unix-socket + SO_PEERCRED + method-authz architecture
is the right, unspoofable design and should proceed. But r2 MUST: fix the
in-process-CLI self-dial premise (F1) + resolve the bufconn-vs-socket conn; count
the true flag-day surface via a single dial helper (F2); close open-Q4 to
pkg/config (F3); decide :8080 scope NOW — expand or file-a-sibling (F4); specify
the SO_PEERCRED grpc-go hook concretely (F5). None of these change the core
approach; all are premise/scope corrections. Not PLAN-READY until F1/F2/F4 are
resolved in the doc.

# #2084 — `--` end-of-options separator for ping/traceroute argv

Status: IMPLEMENTED — control-plane hardening (no smoke). Pending
hostile review (2× Claude + Claude SMR) + Copilot.

## Issue framing

The ping/traceroute exec sites build an `argv` slice and run it with
`exec.CommandContext` (no shell), so there is **no shell/argument
injection**. The real, lower-severity issue is **option-confusion**: a
`-`-prefixed target string (e.g. `-oProxyCommand=...`-style or a bare
`-foo`) is interpreted by `ping`/`traceroute` as a flag rather than a
destination. The endpoints are loopback-API gated. This is a hardening
fix, not a security-critical injection bug.

The fix per the triage re-scope: insert a `--` end-of-options separator
immediately before the user-supplied target at the affected exec sites.

## Affected exec sites (the argv builders)

Six target-append points across three builder families (all build the
argv that `exec.CommandContext` runs):

| File | Function | Current append |
|------|----------|----------------|
| `pkg/grpcapi/server_diag.go` | `Ping` | `args = append(args, req.Target)` |
| `pkg/grpcapi/server_diag.go` | `Traceroute` | `args = append(args, req.Target)` |
| `pkg/api/system.go` | `pingHandler` | `args = append(args, req.Target)` |
| `pkg/api/system.go` | `tracerouteHandler` | `args = append(args, req.Target)` |
| `pkg/cli/cli_request.go` | `handlePing` | `cmdArgs = append(cmdArgs, target)` |
| `pkg/cli/cli_request.go` | `handleTraceroute` | `cmdArgs = append(cmdArgs, target)` |

The remote CLI (`cmd/cli/main.go` `handlePing`/`handleTraceroute`)
builds a protobuf request, NOT an argv — it routes to the server-side
`grpcapi.Ping`/`Traceroute`, so it inherits the server fix. No change
needed there.

`pkg/upgrade/kernel_linux.go:445` runs `ping -c 3 -w N <target>` where
`<target>` is a daemon-internal kernel-promote gateway address, not a
user-supplied string — out of scope (no untrusted input).

## `--` placement semantics

The `--` must be consumed by `ping`/`traceroute`, not by the
`ip vrf exec` wrapper. `ip vrf exec <vrf> <cmd> <cmd-args...>` treats
everything after the vrf name as the command and its arguments, so a
`--` appended right before the target lands in the inner command's argv:

```
ip vrf exec vrf-foo ping -c 5 -- <target>
                    └─── inner cmd argv: ping -c 5 -- <target> ──┘
```

`--` after the last option but before the operand is the standard
end-of-options marker honored by util-linux `ping`/`traceroute` and
inetutils. It makes a `-`-prefixed `<target>` an operand.

## Design: extract pure argv builders + unit-test them

The argv-construction logic is currently inline inside handlers that do
I/O (`exec`, HTTP, gRPC stream). To get a deterministic unit test that
asserts `--` precedes the target WITHOUT spawning a process, extract the
slice-building into small pure helpers that return `[]string`:

- `pkg/grpcapi/server_diag.go`: `buildPingArgv(req)` / `buildTracerouteArgv(req)`
- `pkg/api/system.go`: `buildPingArgv(req)` / `buildTracerouteArgv(req)`
- `pkg/cli/cli_request.go`: `buildPingArgv(target, count, source, size, vrf)` /
  `buildTracerouteArgv(target, source, vrf)`

Each handler calls its builder, then execs the returned slice. The
builders append `--` then the target last. Each is byte-for-byte
identical to today's inline logic except for the inserted `--`.

This is a minimal-surface refactor: the handler bodies shrink to
`cmd := buildXArgv(...)`, the exec/stream/timeout logic is untouched.

## Public API preservation

No exported signatures change. `grpcapi.Server.Ping/Traceroute`,
`api` handlers, and `cli.CLI.handlePing/handleTraceroute` keep their
signatures. The new builders are unexported package-level helpers.

## Hidden invariants preserved

- **Arg ordering** unchanged except the inserted `--` immediately before
  the target. `-c`, `-I`/`-s`, `-s` (size) all still precede `--`.
- **VRF wrapping** (`ip vrf exec vrf-<name>`) prefix unchanged; `--`
  goes to the inner command.
- **Timeouts / WaitDelay / ctx** logic untouched (the exec scaffolding
  stays in the handler).
- **Empty-target rejection** still happens in the handler before the
  builder is reached (`req.Target == ""` guards remain).

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | `--` is a no-op for normal targets; only changes interpretation of `-`-prefixed targets (the intended fix). |
| Lifetime / borrow | N/A | Go, no borrow checker. |
| Performance | NONE | One extra slice append on a human-driven diag path. |
| Architectural mismatch | LOW | Pure local refactor; no cross-cutting state. |

## Test plan

- `GOCACHE=/dev/shm/cache go build ./...` clean.
- New unit tests, one per builder family, asserting:
  1. `--` is present in the argv.
  2. `--` is immediately followed by the target (index of target ==
     index of `--` + 1).
  3. `--` appears after all options (no option after `--`).
  4. A `-`-prefixed target (`-foo`) lands as the operand after `--`.
  5. VRF variant still wraps with `ip vrf exec vrf-<name>` and the `--`
     is in the inner command, after `ping`/`traceroute`.
- `go test ./pkg/grpcapi/ ./pkg/api/ ./pkg/cli/` green.
- Control-plane only — NO dataplane smoke (per #2084 re-scope).

## Docs

`pkg/api/README.md` and `pkg/grpcapi/README.md` describe the
ping/traceroute exec scaffolding. Add a one-line note that the target is
passed after a `--` end-of-options separator (option-confusion
hardening, #2084).

## Out of scope

- `pkg/upgrade/kernel_linux.go` ping (daemon-internal target).
- Any input validation/allow-listing of the target string (separate
  concern; `--` is the minimal, standard fix).

## Open questions for adversarial review

1. Is appending `--` after the wrapper-prefixed `ip vrf exec` correct,
   i.e. does the `--` reliably reach the inner `ping`/`traceroute`?
2. Does util-linux `traceroute` (and the busybox/inetutils variants
   that might be installed) honor `--`? If any installed variant does
   NOT, does the change break normal targets? (`--` before an operand is
   POSIX-standard; verify no regression for the common case.)
3. Is extracting builders worth it vs. a literal one-line
   `append(args, "--", target)` inline with no test? (Trade-off:
   testability vs. churn. Plan favors testable builders.)
4. Any site missed? (cmd/cli, kernel_linux, monitor traffic tcpdump —
   tcpdump filter is not a target and not `-`-confusable the same way;
   confirm scope.)
5. Could `--` itself ever be a problem if the target is legitimately
   empty? (Guarded: empty target rejected before builder.)

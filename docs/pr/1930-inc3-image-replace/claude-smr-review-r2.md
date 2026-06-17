# #1930 INC-3 — Claude SMR re-review (round 2, rev ca6b493f0)

Verifying the fixes for the r1 findings (AGY CRITICAL + Codex 2 HIGH + 1 LOW).

## AGY CRITICAL — --allow-mixed-ha forward-compat — FIXED
`_node_drain_supports_mixed_ha` (xpf-deploy.py) probes
`xpfd upgrade kernel drain --help 2>&1` and the drain appends the flag only
when the running binary lists it. Verified locally: the probe returns a
match against the NEW binary (flag present on merged stderr — Go's flag
package writes usage to stderr, so the `2>&1` merge is required and present).
`drain --help` exits via `flag.ErrHelp` → `os.Exit(1)` BEFORE the drain
switch, so the probe never performs a drain. On a pre-INC-3 binary the
probe returns no match → flag omitted + warning → falls back to the OLD
binary's exact-equality precheck (correct when old/new advertise the same
HA version, the only in-window case a same-version roll produces). No
unknown-flag abort.

## Codex HIGH-1 — Go/Python parity — FIXED
`session-sync-protocol-version` / `configdb-envelope-version` /
`configdb-min-reader-version` now parse via `strconv.ParseUint(v,10,16)`
(stored as `int(n)`), matching Python `_u16`. A negative or
out-of-uint16-range value is rejected at parse → required key absent →
gate fails closed, identical to Python. Locked by
`TestParseImageVersions_NegativeSessionSync_FailsClosed` (peer -1 and
70000 both fail closed). The exact-match `peerSessionSync != SessionSync`
can no longer be reached with a stored negative on both sides.

## Codex HIGH-2 — cross-orchestrator never-both-down — FIXED
`cmd_image_roll` now sets `completed=True` only after a clean per-node roll
(or dry-run) and the `finally` clears the leases only when `completed`. On
a mid-roll abort the leases are HELD until TTL, blocking a second
orchestrator from draining the still-primary peer. The drain verb's
`PeerAlive`/`PeerTakeoverReady` precheck (kernel_drain.go:24-54) remains the
hard backstop: a down/unrejoined node makes the peer not-alive/not-ready, so
the second node's drain refuses regardless of lease state. Lease-hold is
defense-in-depth, recovery is operator-gated.

Minor (non-blocking): a pure pre-flight gate-FAIL (before any drain) also
holds the lease until TTL — slightly conservative for an untouched cluster,
but safe (the abort path), and the warning explains it.

## Codex LOW-1 — bake.py message — FIXED
The warning now states the manifest will OMIT the protocol-version fields
and the gate will FAIL CLOSED (re-bake or `--allow-session-drop`); no
nonexistent staged-binary re-run fallback claimed.

## Verdict: MERGE-READY
`go build ./...` + `go test ./...` clean; `py_compile` clean; new parity
regression test passes; feature-probe verified against the live binary.

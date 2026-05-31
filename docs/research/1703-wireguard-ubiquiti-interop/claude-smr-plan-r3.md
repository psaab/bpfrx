# Claude-SMR plan-review r3 — #1703

Posture: HOSTILE. Verdict: **PLAN-READY**.

## Codex r2 finding disposition

Codex r2 caught a residual contradiction I introduced in r2: S2's acceptance
("flip Test 1/Test 2 green") required ping/iperf transport, but the production
encap/decap hot path is implemented in S3 — so S2 could not satisfy its own
acceptance without pulling S3 forward or building a throwaway test-only
transport path.

r3 fix (verified): the test plan (§8) now splits each direction into a
**handshake** sub-test (1a/2a) and a **transport-flow** sub-test (1b/2b).
S2 (§7) acceptance is HANDSHAKE-ONLY (valid msg1/msg2, mac1 verifies, TAI64N
monotonic, peer `latest handshake` non-zero) and explicitly does NOT assert
transport. S3 acceptance flips the transport-flow xfails green on the REAL
AF_XDP hot path. The empty-keepalive test is now 2c (xfail until C4/S5).

This is internally consistent: a handshake can complete through a
control-thread harness (no worker data path), which is exactly what S2 builds;
the worker carries data only after S3 wires the call sites. No throwaway
transport path is implied. CLOSED.

## Hostile re-check

- No new contradiction: S1 (xfail harness) → S2 (handshake green, transport
  still xfail) → S3 (transport green) is a strictly monotone gate sequence; each
  sub-issue flips exactly the xfails it implements.
- The "S2 may complete a handshake through a thin control-thread harness" line
  does not reopen the test-only-framing ban — the framing CODE is production
  (in S2); only the data-carrying loop is stubbed, and S3 replaces the stub
  with the real worker. Consistent with Codex's own recommendation.

All r1 + r2 findings from all three reviewers remain closed. Central verdict
(NOT-YET-INTEROPERABLE, Path A, S1→S8) unchanged. PLAN-READY.

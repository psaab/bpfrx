# Claude-SMR plan-review r4 — #1703

Posture: HOSTILE. Verdict: **PLAN-READY**.

## Codex r3 finding disposition

Codex r3 caught a genuine WireGuard-correctness subtlety: kernel WG's
`wg_timers_handshake_complete` marks a handshake "complete" (and updates the
`latest handshake` field shown by `wg show`) for a RESPONDER only after it
receives the first authenticated data/keepalive (key-confirmation) packet —
sending msg2 alone merely derives the session. Likewise, in Test 1a (xpf is
initiator, wg is responder) wg's `latest handshake` will not flip until wg
receives xpf's first key-confirmation record. So an S2 acceptance criterion
that asserts the peer's `latest handshake` would transitively require the
zero-length key-confirmation send — which is C4/S5 work — re-creating the
test-only-path risk in a subtler form.

I verified this against the WireGuard timers state machine: yes, this is
correct. `wg_packet_handshake_receive` derives keypairs; the handshake-complete
timer fires on first authenticated transport-data receipt (the responder path)
or on response receipt (the initiator path). The `latest handshake` operator
field tracks the completion event, not session derivation.

r4 fix (verified): S2 (§7) acceptance now asserts **handshake-MESSAGE validity
+ session derivation** (valid msg1/msg2, mac1 verifies, monotonic TAI64N, xpf
derives a transport session) and explicitly **forbids depending on the peer's
`latest handshake`**, deferring key-confirmation observability to C4/S5. §8
Test 1a is reworded to assert via wireguard-go's msg1-authenticated/msg2-sent
log + xpf-side session derivation, NOT `latest handshake`. CLOSED.

## Hostile re-check

- The S1→S2→(C4/S5)→S3 gate sequence is now correct against the actual WG
  timer semantics: S2 proves the bytes are right and a session derives; C4/S5
  adds key-confirmation + keepalive (which is when `latest handshake` flips);
  S3 proves bulk transport on the real worker. No criterion depends on work
  from a later sub-issue.
- No throwaway transport shim is implied: S2's handshake harness exchanges
  messages and derives a session (production framing code), nothing more.

All findings from all three reviewers across r1–r3 are closed. The central
verdict (NOT-YET-INTEROPERABLE, Path A, S1→S8) is unchanged and now rests on a
WG-timer-accurate acceptance ladder. PLAN-READY.

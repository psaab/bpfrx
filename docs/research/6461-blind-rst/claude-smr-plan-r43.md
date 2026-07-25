# Claude SMR hostile plan-review — round 43 (v9.9.31 @ ede76685f)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.31 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.31-as-committed** — six precision pins (all LOW; no design defect
found this round). The v9.9.31 mechanisms verify sound in direction.

## Finding 1 (nit — the RESET handshake's channel and dual case)

The fold never says WHERE RESET_GEN/RESET_ACK travel (both fabrics are
closed at that point). State: the exchange rides the NEXT connection's
handshake (B dials after its drain; the handshake carries `RESET_GEN(g)`;
A quiesces dialers + rejects other inbound, records both slots empty, and
answers `RESET_ACK(g)` in the handshake response; the connection then
cold-primes). And the dual-simultaneous case: the two directions are
INDEPENDENT barriers (A's barrier governs the B→A repair, B's barrier the
A→B repair) — each node processes the peer's GEN on its own connection;
the generations are node-scoped, so there is no tie to break.

## Finding 2 (nit — token revocation catches in-flight handlers at publication; minting is monotone)

State: the canonical publication check revalidates the presented token
ATOMICALLY, so a handler paused with a then-valid token whose connection
is revoked mid-handler is discarded AT PUBLICATION (never at handle
time); and token minting is monotone never-reused (a per-node u64 — no
ABA after revocation).

## Finding 3 (nit — the row version is per-ENTRY, not global)

State: the canonical row version is PER-ENTRY (a global counter would
serialize unrelated conversions and become an availability hazard);
unrelated entries' conversions never contend; the CAS domain ordering
follows the no-nesting rule (the cell swap's allocator section completes
first, then the row-version CAS).

## Finding 4 (nit — rebuild quiesce serialization + merge precedence)

State: the quiesced rebuild and the migration gate's quiesce serialize on
the coordinator's single-threaded lifecycle (only one quiesced operation
at a time — no deadlock possible); and the merge's precedence is
locally-authoritative-wins: the shadow carries only peer-owned state, so
a locally-authoritative E2 admitted after shadow creation is preserved,
and any shadow row aliasing its tuple is discarded by the
incarnation/identity fence.

## Finding 5 (nit — marker validation is idempotent against ACK loss)

State: the JOURNAL-END ACK is receiver→sender; on ACK loss the sender's
OUTBOUND obligation persists and re-kicks the repair (obligation
durability); the receiver's marker validation is IDEMPOTENT — a
duplicate repair with the same repair ID validates and re-ACKs without
side effects (the bulk is loss-free and already committed).

## Finding 6 (nit — quarantine is incarnation-scoped)

State: the quarantine flag and the retry entry carry the family's
`SessionIdentity`; a new import with a DIFFERENT identity is a new family
epoch and installs normally (stage 2 proceeds against the old identity
only — no resurrection of the new epoch's state by the old cleanup); a
SAME-identity re-import cancels the quarantine.

## Verified sound this round (my own re-trace)

- r42-B1 fold: RESET handshake + capability scoping closes the endpoint
  race and the legacy regression (with Finding 1's channel pin).
- r42-B2/B3 folds: slot token + single-counter cell + row-version CAS
  are coherent (with Findings 2-3).
- r42-B4 fold: capacity readiness + quiesced rebuild + local merge are
  coherent (with Finding 4).
- r42-H5/H6 folds: marker discharge + arm-then-recheck are coherent
  (with Findings 5-6).

## Verdict

**PLAN NO for v9.9.31** — fold Findings 1-6 as v9.9.32 (precision pins;
no design change). Part A remains converged and untouched.

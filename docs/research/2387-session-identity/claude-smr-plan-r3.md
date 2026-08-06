# Claude SMR — hostile plan review r3 of `plan.md` v6-r3 (#2387)

Reviewed at `e80db2eae`. r2's SMR-7/8/9 were folded (allocate-once invariant, per-path
matching obligations, Q2 landed). This round has **one MAJOR**, found by attacking my
own r2 remedy: §4.3b's version gate is necessary but **not sufficient**.

## SMR-10 — MAJOR. The version gate fixes the steady state and leaves the transitions open.

§4.3b resolves AGY r2's fail-open by gating enforcement on the peer's advertised
`HAProtocolVersion`. That is the right mechanism, but the plan specifies it only as a
steady-state predicate ("enforce when peer >= 2"). A gate on a *peer state that
changes over time* has three transitions, and the plan addresses none of them.

### (a) The unknown-version default is unspecified — and the wrong choice is fail-open

On a fresh boot, or after a heartbeat gap, the peer's version is **not yet known**. The
plan does not say what happens then. If the node defaults to *enforcing*, it enforces
against sessions whose domain it has no basis to trust; if it defaults to *not
enforcing*, it is bit-identical to today. **The default must be explicitly
NOT-ENFORCING on unknown**, and the plan must say so, because "unknown" is
indistinguishable from "legacy peer" and the safe reading of a legacy peer is exactly
the one §4.3b already argues for.

Note this is the opposite of the usual fail-closed instinct, which is why leaving it
implicit is dangerous: a reviewer or implementer reaching for "fail closed on unknown"
would produce the self-DoS variant, and one reaching for "enforce by default" would
produce the fail-open variant. Neither is right by accident.

### (b) The carried-forward sessions — this is the real hole

**Sessions imported from the peer while it was still v1 do not disappear when the peer
upgrades.** They sit in the session table carrying `routing_domain = 0` — a value that
was never sent and never meant anything. The moment the peer advertises v2 and
enforcement flips on, those sessions become live domain-0 entries, and AGY r2's
original refuted trace runs again in full: a genuine default-VRF flow with a matching
5-tuple hits a session that actually belongs to tenant-a.

The version gate does not close this, because the gate is evaluated per-packet against
the *peer's current* version, while the poisoned sessions were admitted under the
*previous* one. **State admitted under the old regime is carried forward into the new
one.** This is the classic populated-then-excluded transition, and static reasoning
about the steady state cannot see it.

**Required:** flipping enforcement from off to on must be a **transition with an
action**, not just a predicate flip. Concretely, one of:

- **flush** all peer-imported sessions that were admitted while the peer was < v2 (the
  simple, obviously-correct option — the cost is one bulk resync, which the cluster
  already does on connect); or
- **mark** each imported session at admission time with whether its domain was
  authoritative, and treat non-authoritative entries as exempt from domain comparison
  for their lifetime (cheaper, no resync, but adds a per-session bit and a second code
  path that must itself be tested).

I would ship the flush: the window is an upgrade, a bulk resync is already the
cluster's normal recovery behaviour, and a per-session exemption bit is a second
mechanism to get wrong. But the plan must pick one and say why.

### (c) Version regression / flapping

If the peer's advertised version goes 2 → 1 (rollback, or a flapping peer whose
heartbeats are lost and re-established), enforcement must turn **off** and the same
carried-forward problem applies in reverse: sessions admitted *with* an authoritative
domain are now being matched under a no-enforcement regime, which is harmless
(matching only widens back to today's behaviour), but the subsequent re-upgrade
re-opens case (b). The plan should state that the flush obligation applies on **every**
off→on transition, not only the first.

## SMR-11 — MINOR. §4.3b's scope claim should be tested, not asserted.

§4.3b says changing `parseHAProtocolCompatible` to a declared-floor comparison is "what
the unused constant was written for". I verified `MinCompatHAProtocolVersion` has no
non-test consumer, so the constant is genuinely vestigial — but "written for this" is
an inference from its doc comment, not a fact. The plan should say *"its doc comment
describes exactly this use; no consumer exists, so adopting it is a new contract, not
a restoration of an old one."* The distinction matters because it determines whether
the change needs its own design justification (it does).

## Verdict

The chain finding, the Path D withdrawal, the allocate-once invariant and the
version-gate mechanism are all correct and the plan is now substantially stronger than
v6-r1. But §4.3b as written closes the steady-state fail-open while leaving the
off→on transition open, and that transition re-runs the exact trace the section was
written to fix. This is a hole in the fix, not in the analysis, and it is the third
consecutive round in which the defect has been in a remedy rather than in the original
diagnosis — which is itself worth noting about the shape of this problem.

**VERDICT: PLAN-NEEDS-REVISION**

Required for r4:
1. State the unknown-peer-version default explicitly as NOT-ENFORCING, with the
   reasoning for why the fail-closed instinct is wrong here.
2. Make the off→on enforcement flip a transition with a defined action — flush
   peer-imported pre-v2 sessions (recommended) or carry an authoritative-domain bit —
   and say why the chosen one. Apply it to every off→on transition, not just the first.
3. Soften the `MinCompatHAProtocolVersion` claim from "written for this" to "documented
   for this but never wired", and note that adopting it is a new contract requiring its
   own justification.

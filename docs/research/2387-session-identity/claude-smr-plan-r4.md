# Claude SMR — hostile plan review r4 of `plan.md` v6-r4 (#2387)

Reviewed at `e80db2eae`. r4 adopted AGY's pure-function derivation and added §4.3c.
Two findings, and **the first reverses a choice I made one round ago**.

## SMR-12 — MAJOR. §4.3c chooses FLUSH. That is the wrong choice, and I chose it.

§4.3c resolves the carried-forward-session hole by flushing every peer-imported session
admitted while the peer was < v2, and explicitly rejects the marking alternative as "a
second mechanism to get wrong". I wrote that. It does not survive scrutiny.

**FLUSH opens an availability hole precisely where the risk is highest.** The flush
happens during a rolling upgrade — which is exactly the window in which nodes are being
rebooted and a failover is *most* likely, not least. Between the flush and the
completion of the bulk resync, the node holds **no peer-imported sessions at all**. A
failover in that window drops every established flow. That is the exact failure mode
HA session sync exists to prevent, and #2387 is a niche correctness bug — trading a
guaranteed availability window during every upgrade for it is a bad trade.

**Marking is also the choice that respects an invariant this plan already names.** §7
lists the #3096 coherence invariant: *a cached fast-path decision must only be reused
for a flow in the same scope it was admitted under.* A pre-v2 session was admitted
under a 5-tuple-only regime. Matching it under a 5-tuple-only regime for the remainder
of its life is **coherent** — it is the same regime it was admitted under. Flushing it
is not more correct; it just destroys it. Marking is the option that actually honours
§7, and I argued against it without noticing that.

**The residual is bounded and strictly smaller than the flush cost:** marked sessions
are exempt from domain comparison, so the fail-open persists only for sessions that
already existed, only in an overlapping-VRF config, and only until they age out — a
bounded, self-clearing window measured in session lifetimes rather than a guaranteed
outage window on every upgrade.

**Required for r5:** reverse the choice. Mark peer-imported sessions at admission with
whether their domain was authoritative; exempt non-authoritative entries from domain
comparison for their lifetime; state the residual explicitly as a documented, bounded,
self-clearing exposure. Keep the flush available only as an operator-invoked action,
not as automatic behaviour on the transition. The "every off→on transition" and
dampener requirements still apply, and marking makes both cheaper — there is nothing to
re-do on a re-transition because the bit is per-session and already set.

## SMR-13 — MODERATE. Do not reuse the table-id VALUE; reuse the METHOD.

§5's C-P0 now says to derive `routing_domain` by "reusing the existing stable-id
machinery". If that is read as *use `StableRoutingInstanceTableID(name)`'s return value
as the domain*, it inherits a constraint sized for a different purpose:

`RoutingInstanceTableIDBase = 100000`, `RoutingInstanceTableIDSpan = 900000`
(`pkg/config/routinginstanceid.go:22-23`), so the id space is **900,000 values, not
2^32**. Birthday collision probability is roughly N²/1.8M — about 0.55% at 100
routing-instances and material at four digits. The commit gate makes those collisions
**loud** (a rejected commit) rather than silent, so this is not a security fault — but
it makes an operator's config **rejected** because of an unrelated table-id band sized
for kernel routing tables.

It also **couples session identity to the kernel table-id space**: a future change to
the band or span, made for routing reasons, would silently change every session's
domain.

**Required for r5:** state that C-P0 reuses the *method* — FNV-1a of the RI name, and
the existing collision-gate pattern — deriving into its **own full `u32` space**, not
the 900k table-id band, and not the table id's value. All the properties that made
AGY's finding valuable (pure function ⇒ cluster agreement, restart persistence,
rollback coherence, no renumbering) are properties of the *method*, and none of them
require the table-id value.

## What I am NOT re-raising

The chain position (§2.5), the reachability proof (§4.1-4.2), the wire additivity
(§4.3), the polarity split (§4.3a), the version gate (§4.3b), the 1:1 map argument, the
byte budget and the §7a inventory have each now been confirmed by at least two
independent reviewers and I have verified them first-hand. They are settled.

## Verdict

r4's adoption of the pure-function derivation is a genuine, large improvement and it
came from a reviewer refuting me. But §4.3c's flush choice — mine, one round old — is
wrong in a way that would cost availability on every upgrade, and the "reuse the
machinery" wording admits an implementation that inherits a 900k id band. Both are
small edits; neither is a redesign.

**VERDICT: PLAN-NEEDS-REVISION**

Required for r5:
1. Reverse §4.3c from FLUSH to MARK, with the availability and §7-coherence reasoning
   stated; keep flush as an operator action only.
2. Say C-P0 reuses the *method* (FNV-1a + the collision-gate pattern) into its own full
   `u32` space — explicitly not the `StableRoutingInstanceTableID` return value and not
   the 900k band.

**Assessment of terminal state:** after those two edits I judge this plan
implementable. The one thing that would still justify PLAN-KILL is a maintainer
decision that relaxing `parseHAProtocolCompatible` (§3a) is not worth it for a niche
config — a risk-appetite call, not a technical defect.

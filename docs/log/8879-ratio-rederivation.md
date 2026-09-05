# #8879 — re-deriving the headline ratio, and the control that did not dissolve

- **Timestamp**: 2026-09-05
- **Action**: re-derive the issue's headline ratio at current master; re-establish
  its negative control
- **File(s)**: `pkg/config/elision_admissions_8879_test.go`

## The control did NOT dissolve — and the reason matters more than the result

#8879's body justified "at least 37 of 38" by pointing at `system login` and
`interfaces xpfname` reading STRICT-REJECTS: *"they are the reason the other
rows mean something."* #8917 reclassified both — `system login` to
BOTH-ARMS-REJECTED, `interfaces xpfname` to LEAF-CONTINGENT — which reads as
the control having dissolved.

Re-asked with a **hand-written** fixture:

    system { login { user u1 { class super-user; } } }    strict ACCEPTED  users=1
    system login   { user u1 { class super-user; } }      strict REFUSED

**The asymmetry is intact.** BOTH-ARMS-REJECTED is a statement about the
*synthesized leaf*, not about the pair — the leaf-contingency lesson pointed in
the opposite direction from where this campaign has been applying it. A
reclassification to BOTH-ARMS-REJECTED is evidence the sweep **cannot tell**,
not evidence the asymmetry is absent.

`interfaces <name>` genuinely is not a control: measured in batch 3, both arms
accept with a real leaf. So of the two controls the issue named, **one survives
and one never was one**.

`TestRejectedPairStaysUnadmitted8879` previously asserted only that the elided
spelling is refused. That half alone is consistent with the stanza being invalid
for reasons unrelated to elision — precisely the state #8917 found the sweep's
fixture in. It now asserts **both halves**, so no future reader has to take the
sweep's word in either direction.

## The re-derived ratio

**33 of 36 adjudicated drops lose a value something reads; 3 lose only an
advisory.**

The three, named rather than counted (a bare count is satisfied by any three
rows going inert, silently swapping one finding for another):

| pair | why nothing reads it |
|---|---|
| `forwarding-options family` | `inet6 mode packet-based` is accepted-only; the dataplane is flow-based |
| `class-of-service rewrite-rules` | `exp` rewrite is inert; the dataplane rewrites dscp on egress only |
| `security pre-id-default-policy` | pre-id session logging is inert; no pre-identification admit path exists |

This is **not** the issue's 37/38 restated — the population moved as admissions
landed, and it is measured over the 36 fixtures the guards actually assert on.

## The bound, stated because it runs one way

The signal is the compiler's own accepted-but-inert advisories. **Absence of an
advisory is weaker evidence than presence of one**: a stanza that is inert and
says nothing would be counted READ. The project enforces advisory-firing only
for class-of-service (#6850), so outside CoS this is an **UPPER bound on READ** —
the true figure could be below 33, never above.

Six READ rows were additionally confirmed by hand to have consumers outside
`pkg/config`: `PolicyStatsEnabled`, `Protocols.LLDP`, `UserspaceDataplane`,
`FairnessExpectations`, `IPMonitoring`, `SSHKnownHosts` — reaching daemon,
grpcapi, cli and the userspace dataplane.

## One source of fixtures

The fixture table was hoisted to a package-level `admittedElisionCases8879` so
the guard and the ratio measure the SAME fixtures. A second copy would drift,
and a ratio derived from a drifted copy is a claim about the copy.

## Mutations

| mutant | result |
|---|---|
| blind the detector to the `accepted-only` marker | KILLED `:599` — `forwarding-options family` reported as no longer inert |
| drop one known NOT-READ registration | KILLED `:590` — membership change caught even though the total held |
| **production**: widen the #6662 gate to reject the braced spelling | KILLED `:502` — the control going vacuous is detected |

**A fourth mutant was a NO-OP and is recorded as such.** Changing the braced
fixture's class to a bogus value did not make it refuse — login classes are not
validated against a closed set at `CompileConfig`, which does not run
`SchemaValidate` at all. The assertion never got a chance to fire, so its
survival said nothing. Replacing it with a production mutation is what actually
tested the guard.

## Corpus

Unchanged; this is a test-only change.

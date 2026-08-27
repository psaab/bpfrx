// Package zonecounters carries the single canonical operator-facing wording for
// a security zone whose per-zone traffic counters are unavailable.
//
// IT IS A DEPENDENCY-FREE LEAF ON PURPOSE (#6895). Three surfaces print this
// state — the local CLI (pkg/cli), the gRPC text renderer (pkg/grpcapi) and the
// remote cli binary (cmd/cli) — and the natural home would be pkg/dataplane,
// beside the ErrCounterNotPopulated sentinel these sentences describe. But the
// #1451 retirement-boundary canary deliberately keeps cmd/cli free of root
// pkg/dataplane: the remote cli speaks gRPC and must not link the dataplane.
// Adding an allowlist entry to share two strings would weaken an intentional
// architectural boundary for a presentation concern, so the wording lives in a
// leaf all three may import and the boundary stays as designed.
package zonecounters

// The wording below is the rendering of dataplane.ErrCounterNotPopulated for a
// security zone.
//
// SINGLE-SOURCED ON PURPOSE (#6895). Three surfaces report this same state --
// the local CLI (pkg/cli), the gRPC text renderer (pkg/grpcapi) and the remote
// cli binary (cmd/cli) -- and before #6895 the generic sentence was duplicated
// verbatim in two of them with no test binding the agreement. They describe ONE
// dataplane condition, so a divergence between them is always a bug: an
// operator comparing two surfaces would reasonably read different wording as
// different states.
//
// Checking that agreement is also what surfaced a real gap: the local CLI had
// the #6845 overflow specialisation and the gRPC text renderer did NOT, so the
// same cluster reported slot exhaustion on one surface and the generic
// three-cause line on the other. Routing every surface through UnavailableLine
// fixes that by construction.
//
// WHY THE GENERIC LINE STAYS AMBIGUOUS. ReadZoneCounters returns
// ErrCounterNotPopulated for a pre-#3651 helper, a zone past the helper's
// hot-path slot capacity, AND a merely idle zone, because the helper's status
// snapshot is sparse and omits all-zero rows. Those three are genuinely
// indistinguishable at this layer and naming one would be a guess. The overflow
// line is different: when the helper reports its slot table has overflowed, that
// cause is KNOWN, it is the only one of the three that needs action, and traffic
// really is going uncounted.
const (
	unavailableGeneric = "  Traffic statistics: not available " +
		"(no per-zone volume published for this zone: helper predates " +
		"per-zone accounting, the zone exceeded the dataplane's " +
		"hot-path slot capacity, or the zone is idle)"

	unavailableOverflow = "  Traffic statistics: not available " +
		"(the dataplane's per-zone hot-path slot capacity is " +
		"EXHAUSTED, so this zone's traffic is not being counted " +
		"at all; reduce the number of configured zones or accept " +
		"that zones past the capacity go uncounted)"
)

// UnavailableLine returns the single canonical "not available" line
// every operator surface prints for a zone with no published per-zone volume.
//
// overflowActive selects the #6845 specialisation: pass the dataplane's
// reported slot-overflow bit. When it is true the cause is known and actionable;
// when false the three causes remain ambiguous and the generic line says so
// rather than guessing.
//
// It carries NO trailing newline, so callers that print a line and callers that
// assemble a buffer both use it unchanged.
func UnavailableLine(overflowActive bool) string {
	if overflowActive {
		return unavailableOverflow
	}
	return unavailableGeneric
}

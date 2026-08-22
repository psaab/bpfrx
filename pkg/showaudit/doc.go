// Package showaudit hosts the cross-cutting gate for #6534: a config
// object the userspace snapshot builder REFUSES to install must not be
// rendered by an operator surface as though it were enforced.
//
// It contains no runtime code. Like pkg/refactoraudit it exists only to
// give `go test ./...` a home for a source-level property that no single
// package can assert, because the two halves of this property live in
// different packages by construction: the builder decides, and five
// unrelated surfaces render.
//
// # Why a gate rather than more per-site fixes
//
// #6534's own history is the argument. Each fail-closed hardening fix
// added a builder exclusion and, reviewed on its own, looked complete;
// the surface that rendered the same object from configuration was in
// another package and nobody looked. #7330 (NAT), #7348 (CoS) and #7354
// (port-mirroring) closed three families of this by hand. Each landed
// with an agreement test for its own family, and each of those tests is
// blind to the next family — so the next fail-closed fix would have
// minted instance number four with the suite green.
//
// The gate is the part that generalises. It does not know what a NAT
// rule is. It knows two things:
//
//   - which pkg/config drop predicates the snapshot builder consults,
//     and refuses to let a NEW one appear without a registry row
//     (TestEveryBuilderDropPredicateIsRegistered6534); and
//   - for each registered family, which functions in the surface
//     packages iterate that family's config collection and emit output,
//     and whether each of them reaches the family's drop predicate
//     (TestSurfaceAnnotationCensusIsExact6534).
//
// # What is proved, and what is not
//
// Two different closure properties are at work here and they do not
// compose the same way, so the registry states which one each family
// gets:
//
//   - EXISTENCE closure — "some surface consults the predicate". Cheap,
//     transitive, and nearly worthless on its own: it is exactly the
//     property that held while cli.showForwardingOptions was lying,
//     because two OTHER port-mirroring renderers annotated correctly.
//   - GUARDEDNESS closure — "EVERY surface that renders this object
//     consults the predicate". Not transitive, has to be re-established
//     whenever a renderer is added, and is the property the operator
//     actually depends on.
//
// TestSurfaceAnnotationCensusIsExact6534 asserts guardedness for every
// family, and expresses the families that are not yet closed as an
// explicit census of the render functions that still do not annotate.
// That census is asserted EXACTLY, in both directions: a new unannotated
// renderer reds, and so does an entry that has since been fixed. The
// list can therefore never decay into a permanent allowlist — the only
// way to keep the suite green is to keep it true.
//
// # Scope, stated honestly
//
// The gate covers exclusions the builder decides by calling a shared
// pkg/config predicate. It does NOT see a fail-closed drop written
// inline in the builder with no predicate at all; such a drop has no
// symbol for the scan to key on and no verdict a renderer could consult
// even if it wanted to. Routing every builder exclusion through a shared
// predicate is what makes it visible here, and that convention is what
// this package enforces rather than assumes.
//
// See surface_gate_6534_test.go, pkg/config/mirror_exclusion_reason.go,
// pkg/config/nat_exclusion_reason.go, pkg/config/cos_exclusion_reason.go
// and pkg/config/nptv6_scope.go.
package showaudit

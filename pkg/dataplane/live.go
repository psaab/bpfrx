package dataplane

import "errors"

// ErrNotPublished is returned by a live-indirection adapter (see
// LiveUnwrapper) when the owner's runtime cell is empty at call time — the
// daemon has disowned the backend, so there is nothing to dispatch into.
//
// It is exported so the management servers can distinguish "no dataplane
// right now" from a genuine backend failure: pkg/grpcapi maps it to
// codes.Unavailable, matching the code its own `dp == nil || !IsLoaded()`
// pre-checks already return, rather than reporting the daemon's own
// lifecycle state as codes.Internal.
var ErrNotPublished = errors.New("dataplane not published")

// LiveUnwrapper is implemented by an adapter that does not itself hold a
// backend but resolves one PER CALL from an owner-controlled cell — today
// pkg/daemon's liveDataPlane (#2114).
//
// Such an adapter exists to stop a backend handle escaping into a
// long-lived consumer field, but it pays for that with a hard Go
// limitation: a hand-written adapter's method set is exactly the methods
// it declares. Every OPTIONAL capability the consumers reach by asserting
// on `any` — LastApplyResult, Sessions, Telemetry, Status, AppliedNATView,
// cursor iteration, the userspace controls — is ERASED by the adapter,
// because the adapter does not declare it. On a perfectly healthy
// deployment that silently downgrades NAT-pool metrics to nothing,
// userspace metric families to nothing, and session paging to the O(N^2)
// fallback.
//
// Unwrap closes that gap without reintroducing the escape: it hands back
// the backend published AT THE MOMENT OF THE CALL, for the caller to
// assert against and use immediately. The resolution window is exactly the
// window an explicit forwarder has (resolve, then call); what it must
// never do is hand back something the owner has already disowned, which is
// why implementations resolve fresh and return nil on an empty cell rather
// than caching.
type LiveUnwrapper interface {
	// Unwrap returns the backend currently published by the adapter's
	// owner, or nil if none is. It must not cache across calls.
	Unwrap() any
}

// unwrapDepth bounds the resolution chain so a pathological adapter that
// unwraps to another adapter (or to itself) cannot spin. Nothing in tree
// nests adapters; the bound is a safety belt, not a supported topology.
const unwrapDepth = 4

// Unwrap resolves provider to the value that OPTIONAL capability
// assertions must be made against.
//
// For a plain backend (the shape every test and every pre-#2114 caller
// passes) it returns provider unchanged, so this is transparent. For a
// LiveUnwrapper it returns the currently published backend, or nil when
// the owner's cell is empty — an assertion against a nil `any` fails, so
// a disowned backend degrades to "capability unavailable" rather than
// staying reachable.
func Unwrap(provider any) any {
	for range unwrapDepth {
		u, ok := provider.(LiveUnwrapper)
		if !ok {
			return provider
		}
		provider = u.Unwrap()
		if provider == nil {
			return nil
		}
	}
	return provider
}

// #6743 r2-B6: a `Published(provider any) bool` predicate used to live
// here, as the answer to "the pre-#2114 code asked `dp == nil`, what does
// it ask now?". It was DELETED rather than re-wired, and deliberately not
// reintroduced, because r7 established the stronger rule that supersedes
// it: ONE resolution feeds every decision in a render.
//
// Published(p) was exactly `Unwrap(p) != nil`, so a site that asked
// Published(dp) and then probed dpProbe() resolved the cell TWICE — and a
// setDataplane(nil) landing between the two re-created the very confusion
// the publication check existed to prevent (the check passed against
// backend A; the probe then resolved nil; the render described neither).
// The surviving sites therefore bind `backend := Unwrap(dp)` to a local
// and make BOTH the publication decision and every capability assertion
// against that single value — see showBuffers (pkg/grpcapi), the CLI peer
// (pkg/cli/cli_show_system.go), the WireGuard renders (r2-B4) and
// forwardingStatusDataplane (r2-B7).
//
// Restoring the predicate would re-offer the two-resolution shape at every
// new call site, which is the regression r7 removed; a reviewer measured it
// at zero callers before this deletion.

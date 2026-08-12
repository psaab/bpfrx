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

// Published reports whether provider currently resolves to a backend.
//
// Consumers use it where the pre-#2114 code asked `dp == nil`: with a live
// indirection the handle is permanently non-nil, so `dp != nil` no longer
// means "a dataplane exists" and a render keyed on it would report a
// backend-shaped answer ("No BPF maps available") for a daemon that has no
// backend at all ("Dataplane not loaded").
func Published(provider any) bool {
	return Unwrap(provider) != nil
}

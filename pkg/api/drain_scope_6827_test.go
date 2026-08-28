package api

import (
	"testing"
	"time"
)

// #6827 round 8: a guard over the SCOPE of drainLeg's promise, as opposed to
// its behaviour. It exists because the promise is stated in three places
// (listenerLeg.drained, Server.HTTPSLegDrainedForTest, pkg/api/README.md) and a
// stated invariant with nothing holding it is how a later change inherits a
// guarantee that was never true.

// TestLegDrainTimeoutDefault_6827 pins the SHIPPED graceful-drain deadline.
//
// legDrainTimeout is a var so a test can reach the deadline arm cheaply, and a
// var is assignable: a cell that forgot to restore it, or an edit that "tuned"
// it, would change production behaviour with every existing test still green
// (they either set their own value or never reach the deadline). This asserts
// the value the daemon actually ships with.
func TestLegDrainTimeoutDefault_6827(t *testing.T) {
	if legDrainTimeout != 5*time.Second {
		t.Fatalf("the shipped graceful-drain deadline changed to %v; production never assigns "+
			"legDrainTimeout, so if this moved it moved because a test leaked its override or "+
			"someone retuned it without saying so (#6827 round 8)", legDrainTimeout)
	}
}

// TestNoHijackerInThisPackage_6827 WAS HERE, and #7011 deleted it rather than
// re-keyed it.
//
// It maintained a map of hijacking types and asserted none was reachable from
// this package, so drainLeg's guarantee could carry a "modulo hijacked
// connections" caveat. The enumeration was defeated three times —
// golang.org/x/net/websocket (round 8), http2/h2c (round 9), and net/rpc, a
// STANDARD LIBRARY hijacker. The last one is why re-keying was not the answer:
// the hijacker set is a function of the TOOLCHAIN, not of go.mod, so the corpus
// the map was derived over moved with nothing in the repository changing, and
// the `go list -deps` closure fallback would have missed net/rpc too unless
// written to include the stdlib.
//
// The caveat is gone instead. drainLeg now closes hijacked connections itself
// (listener_hijack_drain.go), so there is nothing for a tripwire to defend, and
// the property is asserted DIRECTLY against a real hijacking handler in
// listener_hijack_drain_7011_test.go rather than proxied through type names.
// Restoring a name-based enumeration here would be re-adding a claim nobody can
// keep true; if the drain's coverage is in doubt, add a case that hijacks.

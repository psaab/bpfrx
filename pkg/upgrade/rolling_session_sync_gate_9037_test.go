package upgrade

import (
	"errors"
	"strings"
	"testing"
)

// errSyncWireProbe9037 models a transport failure reading the peer's wire
// version — distinct from a KNOWN incompatibility, and it must abort too.
var errSyncWireProbe9037 = errors.New("dial peer gRPC: connection refused")

// #9037: binary rolling declared SessionSyncWireCompatible on its own cluster
// interface, documented it as "the session-sync half is
// SessionSyncWireCompatible below", and never called it. Only the kernel-drain
// sibling gated on it.
//
// A drain hands the RGs to the peer. If the peer cannot decode this node's
// session frames, that handover drops every established flow while heartbeat,
// election and failover all keep working — the cluster looks healthy and the
// loss is discovered at the failover, not at the upgrade.
//
// THESE CELLS BIND THE WIRING, NOT THE FUNCTION, and for this issue that is
// the whole point: the function EXISTED, was implemented, was tested, and was
// correct. Deleting its body proves nothing about a caller that never called
// it. Each cell below drives runRollingWith and fails if the CALL is removed.
//
// The `forced` assertion is the load-bearing half. A gate that runs AFTER
// ForceSecondary has already cut the connections it exists to protect, so
// "aborted" is not sufficient — it must abort with the demotion NOT performed.
func TestRollingGatesOnSessionSyncWire9037(t *testing.T) {
	t.Run("incompatible wire aborts before demoting", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		cl := &fakeCluster{
			peerAlive: true, synced: true, compatible: true, peerReady: true,
			drainAfter: 2,
			// The ONLY unhealthy input. Everything else is the happy path, so a
			// failure here cannot be attributed to any other precheck.
			syncWireIncompat: true,
		}

		err := runRollingWith(r, cl, fastRC())
		if err == nil {
			t.Fatal("rolling proceeded with an INCOMPATIBLE session-sync wire: the peer " +
				"cannot decode this node's sessions, so the drain drops every " +
				"established flow (#9037)")
		}
		if !strings.Contains(err.Error(), "session-sync") {
			t.Errorf("abort reason = %q, want it to name the session-sync wire — an "+
				"operator told only 'rolling aborted' will retry into the same "+
				"handover (#9037)", err)
		}
		// THE ASSERTION THAT MAKES THIS A GATE RATHER THAN A REPORT.
		if cl.forced {
			t.Error("ForceSecondary was called despite the incompatible wire: the check " +
				"ran AFTER the demotion, so the connections it exists to protect were " +
				"already handed to a peer that cannot decode them (#9037)")
		}
		if fs.dropinContent != "" {
			t.Error("the cut happened despite an incompatible session-sync wire (#9037)")
		}
		if cl.syncWireChecks == 0 {
			t.Error("SessionSyncWireCompatible was never consulted — the interface " +
				"declares it and the comment promises it; this is the defect (#9037)")
		}
	})

	// Transport failure is NOT the same as incompatibility, and both must
	// abort. A check that treats an unreachable peer as compatible fails open
	// on exactly the path where the peer's state is unknown.
	t.Run("transport error aborts before demoting", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		cl := &fakeCluster{
			peerAlive: true, synced: true, compatible: true, peerReady: true,
			drainAfter:  2,
			syncWireErr: errSyncWireProbe9037,
		}

		err := runRollingWith(r, cl, fastRC())
		if err == nil {
			t.Fatal("rolling proceeded despite being UNABLE to check the session-sync " +
				"wire: unknown is not compatible (#9037)")
		}
		if cl.forced {
			t.Error("ForceSecondary was called after a session-sync wire probe FAILURE " +
				"(#9037)")
		}
	})

	// THE MUTANT THAT MUST SURVIVE. Without it, a "fix" that aborted every
	// rolling upgrade — or that hard-wired syncOK=false — passes both cells
	// above while making binary rolling impossible.
	t.Run("compatible wire still completes the roll", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		cl := &fakeCluster{
			peerAlive: true, synced: true, compatible: true, peerReady: true,
			drainAfter: 2,
		}
		if err := runRollingWith(r, cl, fastRC()); err != nil {
			t.Fatalf("a COMPATIBLE session-sync wire must not block the roll: %v (#9037)", err)
		}
		if !cl.forced {
			t.Error("ForceSecondary not called on the healthy path")
		}
		if cl.syncWireChecks == 0 {
			t.Error("the healthy path never consulted SessionSyncWireCompatible either — " +
				"the gate is absent, not merely lenient (#9037)")
		}
		if fs.dropinContent == "" {
			t.Error("no cut happened on the healthy path (#9037)")
		}
	})
}

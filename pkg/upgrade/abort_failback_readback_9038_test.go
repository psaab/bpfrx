package upgrade

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// #9038: a nil ResetFailover on the abort path was treated as confirmed
// failback, while RejoinAndConfirm in the same package says it is not.
//
// REACHABILITY, MEASURED ON THE REAL cluster.Manager rather than argued:
//
//	peer alive, peer OWNS the RG at the stronger position
//	  ResetFailover()   -> nil
//	  IsLocalPrimary()  -> false
//
// `ResetFailover` clears ManualFailover and re-runs the election. Whether this
// node reclaims the RG depends on the PEER's position, so a healthy peer
// legitimately holding it means a nil ACK and a still-secondary node. That is
// not an exotic shape — it is what a completed drain leaves behind, and it is
// what the failover smoke asserts as correct ("fw0 rejoined as secondary for
// every redundancy group (no auto-preempt)").
//
// So the defect is not the STATE, which is correct HA behaviour. It is the
// abort path's CLAIM about the state: "aborted WITHOUT cutting (node still
// forwarding)" when the node is not forwarding for at least one RG.
//
// The fix reads back with the SAME predicate the rejoin path already trusts,
// once and without polling: an abort must not become slower or able to hang.
func TestAbortFailbackIsReadBackNotAssumed9038(t *testing.T) {
	t.Run("rolling: nil reset that did NOT restore is reported, not claimed", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		cl := &fakeCluster{
			peerAlive: true, synced: true, compatible: true, peerReady: true,
			// drain never completes -> abort branch
			drainAfter: 1 << 30,
			// ResetFailover ACKs (resetErr nil) but the node has NOT resumed
			// ownership: exactly the measured real-Manager shape.
			rejoinIncomplete: true,
		}

		err := runRollingWith(r, cl, RollingConfig{
			DrainDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond,
		})
		if err == nil {
			t.Fatal("rolling did not abort on an incomplete drain (#9038)")
		}
		if !cl.resetCalled {
			t.Fatal("ResetFailover was not attempted on the abort path (#9038)")
		}
		if strings.Contains(err.Error(), "node still forwarding") {
			t.Errorf("abort claims the node is STILL FORWARDING while it has not resumed "+
				"ownership of every RG: %v\nA nil ResetFailover is an acknowledgement, "+
				"not an observation — RejoinAndConfirm in this same package already "+
				"says so (#9038)", err)
		}
		if !strings.Contains(err.Error(), "NOT resumed ownership") {
			t.Errorf("abort error = %v, want it to say the failback was acknowledged but "+
				"ownership was not resumed, so an operator knows to look (#9038)", err)
		}
	})

	t.Run("rolling: a readback ERROR is not silently optimistic", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		cl := &fakeCluster{
			peerAlive: true, synced: true, compatible: true, peerReady: true,
			drainAfter: 1 << 30,
			rejoinErr:  errors.New("dial xpfd gRPC: connection refused"),
		}
		err := runRollingWith(r, cl, RollingConfig{
			DrainDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond,
		})
		if err == nil {
			t.Fatal("rolling did not abort (#9038)")
		}
		if strings.Contains(err.Error(), "node still forwarding") {
			t.Errorf("abort claims the node is still forwarding when the readback FAILED: "+
				"%v — unknown is not confirmed (#9038)", err)
		}
	})

	// THE MUTANT THAT MUST SURVIVE. When the failback genuinely restored the
	// node, the abort must still say so — otherwise every aborted roll reports
	// a stranded node and the signal is worthless.
	t.Run("rolling: a nil reset that DID restore still reports forwarding", func(t *testing.T) {
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		seedInitialCurrent(t, r, cfg, "1.0.0")
		cl := &fakeCluster{
			peerAlive: true, synced: true, compatible: true, peerReady: true,
			drainAfter: 1 << 30,
			// rejoinIncomplete defaults false: the node DID resume ownership.
		}
		err := runRollingWith(r, cl, RollingConfig{
			DrainDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond,
		})
		if err == nil {
			t.Fatal("rolling did not abort on an incomplete drain (#9038)")
		}
		if !strings.Contains(err.Error(), "node still forwarding") {
			t.Errorf("abort error = %v, want the 'still forwarding' claim RETAINED when "+
				"the readback CONFIRMS it — a fix that reports every abort as stranded "+
				"is as useless as one that reports none (#9038)", err)
		}
	})

	t.Run("kernel drain: same defect, same fix", func(t *testing.T) {
		cl := &fakeCluster{
			peerAlive: true, synced: true, compatible: true, peerReady: true,
			drainAfter:       1 << 30,
			rejoinIncomplete: true,
		}
		err := DrainAndConfirm(cl, 20*time.Millisecond, false)
		if err == nil {
			t.Fatal("DrainAndConfirm did not abort (#9038)")
		}
		if strings.Contains(err.Error(), "failed back)") ||
			strings.Contains(err.Error(), "failed back;") {
			t.Errorf("kernel-drain abort claims 'failed back' while ownership was not "+
				"resumed: %v (#9038)", err)
		}
		if !strings.Contains(err.Error(), "NOT resumed ownership") {
			t.Errorf("kernel-drain abort = %v, want the acknowledged-but-unconfirmed "+
				"wording (#9038)", err)
		}
	})
}

package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #6871 round 6: the link-cycle lease is renewed once per RETH member.
//
// The lease's TTL used to have to cover the WHOLE of step 2.6's rethToPhys loop,
// and no constant can: only a member that actually cycles re-arms the lease
// (PrepareLinkCycle takes it), so the exposure is the tail of members visited
// after the last cycling one; `reth-count` is operator-settable to 128
// (pkg/config/schema_chassis.go); and the per-member `ethtool -K rxvlan off` has
// a 20s hard ceiling (externalCommandTimeout 15s + the 5s WaitDelay in
// exec_timeout.go). Four wedging members in that tail already exceed a 60s TTL.
// Because rethToPhys is a Go MAP, which members land in that tail differs
// between runs — so the same config passes or fails at random, which is the
// worst shape a defect can have and the one a larger constant hides.
//
// The renewal lives in programRethMemberMAC rather than inline in the loop for
// the reason that function exists at all (see its doc comment): inline, it was
// reachable only through applyDataplaneAndHACore, which needs a live cluster
// manager, a wired dataplane, a networkd writer and real netlink members — so
// the only available guard would have been a structural canary, and a structural
// canary is satisfied by an assignment that is unreachable, shadowed or jumped
// over. Here the renewal is driven against the same fake link seam and fake
// dataplane the rest of the #5103 suite uses, and reth_hook_wired_5103_test.go
// separately pins that step 2.6 reaches the wrapper through exactly one
// programRethMemberMAC call site — which together is what makes "once per
// member" true rather than asserted.

// TestRethMemberMACRenewsTheLinkCycleLease_6871 is the fail-on-revert guard.
//
// It walks every outcome a member can have, because the whole point is that the
// renewal is NOT conditional on this member cycling: the member that keeps the
// lease alive for the loop's tail is precisely the one that did nothing.
//
// RED-on-revert: delete the `d.dp.Link().RenewLinkCycle()` call from
// programRethMemberMAC and every subtest fails at "did not renew the link-cycle
// lease".
func TestRethMemberMACRenewsTheLinkCycleLease_6871(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ops        rethLinkOps
		prepareErr error
	}{
		{
			// The common case, and the one that matters most: this member's MAC
			// went in live, so it neither takes nor re-arms a lease — but an
			// EARLIER member may have taken one, and this member's `ethtool`
			// still burns up to 20s of it.
			name: "live_set_no_cycle",
			ops:  newRecordingRethOps(t, new([]string), curMAC5103, false),
		},
		{
			name: "cycle_completed",
			ops:  newRecordingRethOps(t, new([]string), curMAC5103, true),
		},
		{
			// The member is gone by the time programRethMAC looks it up. Warn-only,
			// and it never reaches the cycle path — but the loop still walks on to
			// the next member, so the lease still needs the time.
			name: "ordinary_lookup_failure",
			ops:  ordinaryFailureRethOps(),
		},
		{
			name:       "cycle_aborted_on_failed_hook",
			ops:        newRecordingRethOps(t, new([]string), curMAC5103, true),
			prepareErr: errors.New("stop_workers: helper did not respond"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withRethOps(t, tc.ops)
			d, lc := newAbortRecoveryDaemon(tc.prepareErr)

			d.programRethMemberMAC("ge-0-0-1", virtMAC5103, nil, false)

			if lc.renewCalls != 1 {
				t.Errorf("RenewLinkCycle calls = %d, want 1: this member did not renew the "+
					"link-cycle lease. Every member's turn must touch it, including the ones "+
					"that need no cycle — those are exactly the members whose `ethtool` (20s "+
					"hard ceiling) burns down a lease an EARLIER member took. Without the "+
					"renewal the 60s TTL has to cover the whole rethToPhys loop, which "+
					"`reth-count` lets an operator take to 128 members, and the loop is a Go "+
					"map range so the overrun is nondeterministic between runs (#6871)",
					lc.renewCalls)
			}
		})
	}
}

// TestRethMemberMACSkipsRenewWithNoDataplane_6871 is the over-reach guard for the
// nil check. A daemon with no dataplane wired has no lease and no Link()
// controller to reach; renewing there would panic on the nil deref, which is a
// crash introduced by a fix for a suppression race.
//
// It stays GREEN under the revert above (no call, no panic either way), so it is
// a control rather than a restatement.
func TestRethMemberMACSkipsRenewWithNoDataplane_6871(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))
	d := &Daemon{} // d.dp is nil

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("programRethMemberMAC panicked with no dataplane wired: %v. The "+
				"renewal must be behind the same nil guard as the rest of the dataplane "+
				"work on this path", r)
		}
	}()
	got, needRecovery := d.programRethMemberMAC("ge-0-0-1", virtMAC5103, errPriorCommit5103, false)
	if got != errPriorCommit5103 {
		t.Errorf("commit error = %v, want the prior error passed through unchanged: with no "+
			"dataplane the hook never runs, so this member cannot enter the fail-closed "+
			"escalation class", got)
	}
	// The link really was cycled — the hook is a no-op with no dataplane, but
	// programRethMAC still takes its DOWN/set/UP fallback — so the recovery gate
	// must report that honestly. Step 2.6b2 is separately gated on d.dp != nil,
	// which is what keeps an armed gate from dereferencing a nil dataplane.
	if !needRecovery {
		t.Error("the link WAS cycled, so the recovery gate must be armed; suppressing it " +
			"here would hide a real cycle from a caller that later acquires a dataplane")
	}
}

// #6871 round 6: the RETH MAC live-set failure reason must reach the journal.
//
// programRethMAC attempts the live MAC set first and falls back to a link cycle
// on ANY error. Before the previous round the error was scoped to the `if`, so
// the fallback log spent its one diagnostic slot asserting a driver capability
// it had not observed ("driver does not support live change") while DISCARDING
// the actual reason — and the fallback swallows it, so the journal was the only
// place it could have survived.
//
// The fix hoisted the error to liveSetErr and attached it to the log. Nothing
// bound that: deleting the `"err", liveSetErr` attribute left both pkg/daemon
// and pkg/dataplane/userspace green, so the recovered reason could be lost again
// silently. This is that binding.

// captureRethSlog installs a text handler over slog's default logger for the
// duration of the test and returns the buffer. Restores the previous default.
func captureRethSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// errLiveSetRefused6871 is deliberately distinctive: the assertion below matches
// its text, so a log line that merely mentions "err" cannot satisfy it.
var errLiveSetRefused6871 = errors.New("EBUSY: device busy, resource in use by another consumer")

// TestRethMACFallbackLogsTheLiveSetError_6871 is the fail-on-revert guard.
//
// RED-on-revert: drop the `"err", liveSetErr` attribute from the
// "RETH MAC live set refused" slog.Info in daemon_reth.go and this fails at
// "the live-set failure reason never reached the journal".
func TestRethMACFallbackLogsTheLiveSetError_6871(t *testing.T) {
	buf := captureRethSlog(t)

	var events []string
	ops := newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */)
	// Substitute a rejection reason of our own, keeping the fixture's event
	// recording intact. The assertion is then about THIS error travelling to the
	// journal, not about any error being present — a log line that happened to
	// carry some other text could not satisfy it.
	inner := ops.setHardwareAddr
	ops.setHardwareAddr = func(l netlink.Link, mac net.HardwareAddr) error {
		if err := inner(l, mac); err != nil {
			return errLiveSetRefused6871
		}
		return nil
	}
	withRethOps(t, ops)

	linkCycled, err := programRethMAC("ge-0-0-1", virtMAC5103, nil)
	if err != nil || !linkCycled {
		t.Fatalf("programRethMAC = (%v, %v), want (true, nil): the fixture must take the "+
			"fallback and complete it, or the log line under test never runs",
			linkCycled, err)
	}

	out := buf.String()
	if !strings.Contains(out, "RETH MAC live set refused") {
		t.Fatalf("the fallback log line is missing entirely; got:\n%s", out)
	}
	if !strings.Contains(out, "resource in use by another consumer") {
		t.Errorf("the live-set failure reason never reached the journal. programRethMAC "+
			"SWALLOWS this error — it falls back and returns nil — so the log is the only "+
			"place it survives, and without it an operator sees only that a cycle happened "+
			"and not why. A busy mlx5 VF and a driver with no ndo_set_mac_address produce "+
			"the same line, which is the wrong diagnosis on the hardware this cluster runs "+
			"(#6871). Log was:\n%s", out)
	}
	if strings.Contains(out, "does not support live change") {
		t.Errorf("the log still asserts a driver capability it did not observe. "+
			"dev_set_mac_address refuses a live set for a busy or absent device and for a "+
			"notifier rejection just as readily as for a missing ndo_set_mac_address, so "+
			"this branch cannot conclude anything about IFF_LIVE_ADDR_CHANGE. Log was:\n%s",
			out)
	}
}

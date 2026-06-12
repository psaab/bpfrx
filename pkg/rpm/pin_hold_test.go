// pin_hold_test.go — #1895: a next-hop-pinned test whose kernel pin
// failed to install must NOT probe (an unbacked SO_MARK falls through
// to the main table and measures the default path → false PASS); it
// holds state via ErrProbeSetup until the pin install recovers.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// pinnedTest returns an icmp-ping test carrying a next-hop pin.
func pinnedTest() *config.RPMTest {
	return &config.RPMTest{
		Name: "t", Target: "192.0.2.10",
		NextHop: "10.0.0.1", DestinationInterface: "ge-0/0/2",
	}
}

func TestExecuteProbeFailedPinIsSetupErrorAndSendsNothing(t *testing.T) {
	var listens atomic.Int32
	target := net.ParseIP("192.0.2.10")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	inner := m.icmpListen
	m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
		listens.Add(1)
		return inner(network, laddr, opts)
	}
	m.marks = map[string]uint32{"WAN/t": uint32(config.ProbeFwmarkBase)}
	m.SetPinInstallResults(map[string]error{"WAN/t": fmt.Errorf("egress interface missing")})

	_, err := m.executeProbe(context.Background(), pinnedTest(), "WAN/t")
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("failed pin not classified ErrProbeSetup: %v", err)
	}
	if n := listens.Load(); n != 0 {
		t.Fatalf("probe opened %d sockets despite failed pin, want 0", n)
	}
	if len(conn.sent) != 0 {
		t.Fatalf("probe sent %d packets despite failed pin, want 0", len(conn.sent))
	}

	// Recovery: clearing the install failure lets the probe run.
	m.SetPinInstallResults(nil)
	if _, err := m.executeProbe(context.Background(), pinnedTest(), "WAN/t"); err != nil {
		t.Fatalf("probe after pin recovery: %v", err)
	}
	if listens.Load() != 1 || len(conn.sent) != 1 {
		t.Fatalf("recovered probe did not send: listens=%d sent=%d",
			listens.Load(), len(conn.sent))
	}
}

func TestExecuteProbeUnassignedPinSlotIsSetupError(t *testing.T) {
	// Belt-and-braces: a next-hop test with NO mark assigned at all
	// (band exhaustion — commit validation caps this on the strict
	// path) must hold state rather than probe unpinned.
	m, conn := newFakeManager(nil)
	_, err := m.executeProbe(context.Background(), pinnedTest(), "WAN/t")
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("unassigned pin slot not classified ErrProbeSetup: %v", err)
	}
	if len(conn.sent) != 0 {
		t.Fatalf("probe sent %d packets without a pin slot, want 0", len(conn.sent))
	}
}

func TestExecuteProbeUnpinnedTestUnaffectedByOtherFailures(t *testing.T) {
	target := net.ParseIP("192.0.2.20")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	// Another test's pin failed; this plain (no next-hop) test must
	// probe normally.
	m.SetPinInstallResults(map[string]error{"WAN/other": fmt.Errorf("boom")})
	plain := &config.RPMTest{Name: "p", Target: "192.0.2.20"}
	if _, err := m.executeProbe(context.Background(), plain, "WAN/p"); err != nil {
		t.Fatalf("unpinned test must be unaffected: %v", err)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("unpinned test sent %d packets, want 1", len(conn.sent))
	}
}

func TestRunSingleTestFailedPinHoldsState(t *testing.T) {
	m, conn := newFakeManager(nil)
	m.marks = map[string]uint32{"WAN/t": uint32(config.ProbeFwmarkBase)}
	m.SetPinInstallResults(map[string]error{"WAN/t": fmt.Errorf("rule add: EBUSY")})

	var transitions atomic.Int32
	m.SetTransitionCallback(func(Transition) { transitions.Add(1) })
	var events atomic.Int32
	m.SetEventCallback(func(Event) { events.Add(1) })

	// Seed a passing result (the state the test held before the pin
	// broke) and run a full test cycle.
	m.results["WAN/t"] = &ProbeResult{
		ProbeName: "WAN", TestName: "t", ProbeType: "icmp-ping",
		Target: "192.0.2.10", LastStatus: "pass",
	}
	m.runSingleTest(context.Background(), "WAN", pinnedTest(), "WAN/t", 3, 0, 2)

	r := m.results["WAN/t"]
	if r.TotalSent != 0 || r.SuccFail != 0 || r.LastStatus != "pass" || !r.LastProbeAt.IsZero() {
		t.Fatalf("state not held on failed pin: %+v", r)
	}
	if transitions.Load() != 0 || events.Load() != 0 {
		t.Fatalf("failed pin fired transitions=%d events=%d, want 0/0",
			transitions.Load(), events.Load())
	}
	if len(conn.sent) != 0 {
		t.Fatalf("failed pin sent %d probes, want 0", len(conn.sent))
	}
}

func TestRunSingleTestPinRecoveryResumesProbing(t *testing.T) {
	target := net.ParseIP("192.0.2.10")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	m.marks = map[string]uint32{"WAN/t": uint32(config.ProbeFwmarkBase)}
	m.SetPinInstallResults(map[string]error{"WAN/t": fmt.Errorf("link missing")})
	m.results["WAN/t"] = &ProbeResult{
		ProbeName: "WAN", TestName: "t", ProbeType: "icmp-ping",
		Target: "192.0.2.10", LastStatus: "unknown",
	}

	transition := make(chan Transition, 4)
	m.SetTransitionCallback(func(tr Transition) { transition <- tr })

	// Held cycle: nothing counted.
	m.runSingleTest(context.Background(), "WAN", pinnedTest(), "WAN/t", 1, 0, 2)
	if r := m.results["WAN/t"]; r.TotalSent != 0 || r.LastStatus != "unknown" {
		t.Fatalf("state not held while pin failed: %+v", r)
	}

	// Pin recovers (daemon retry succeeded): the next cycle probes and
	// transitions to pass without any probe restart.
	m.SetPinInstallResults(nil)
	m.runSingleTest(context.Background(), "WAN", pinnedTest(), "WAN/t", 1, 0, 2)
	r := m.results["WAN/t"]
	if r.TotalSent != 1 || r.TotalRecv != 1 || r.LastStatus != "pass" {
		t.Fatalf("probing did not resume after pin recovery: %+v", r)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("sent %d probes after recovery, want 1", len(conn.sent))
	}
	select {
	case tr := <-transition:
		if tr.Status != "pass" || tr.ProbeName != "WAN" || tr.TestName != "t" {
			t.Fatalf("unexpected transition: %+v", tr)
		}
	case <-time.After(time.Second):
		t.Fatal("no pass transition after pin recovery")
	}
}

func TestPinInstallFailureCount(t *testing.T) {
	m := New()
	if m.PinInstallFailureCount() != 0 {
		t.Fatal("fresh manager must report 0 failed pins")
	}
	m.SetPinInstallResults(map[string]error{
		"WAN/a": fmt.Errorf("x"), "WAN/b": fmt.Errorf("y"),
	})
	if got := m.PinInstallFailureCount(); got != 2 {
		t.Fatalf("PinInstallFailureCount = %d, want 2", got)
	}
	m.SetPinInstallResults(nil)
	if got := m.PinInstallFailureCount(); got != 0 {
		t.Fatalf("PinInstallFailureCount after clear = %d, want 0", got)
	}
}

package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #7367: bind the WIRING, not just the function it calls.
//
// rgForwardingStatus can be perfectly correct and never reach the render if the
// SetRGForwardingFunc call is dropped. A test that only exercises
// rgForwardingStatus directly stays green through exactly that deletion, so it
// would certify a feature the operator cannot see.
func TestRGForwardingHookIsWiredIntoClusterManager7367(t *testing.T) {
	d := &Daemon{
		cluster:  cluster.NewManager(0, 1),
		rgStates: map[int]*rgStateMachine{0: newRGStateMachine()},
	}
	d.cluster.UpdateConfig(&config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})
	for i := 0; i < 4; i++ {
		select {
		case <-d.cluster.Events():
		default:
		}
	}
	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)

	// Before wiring, the render must carry no forwarding term at all.
	if got := forwardingLineOf7367(d.cluster.FormatStatus()); got != "" {
		t.Fatalf("unwired manager already renders a forwarding line %q — the "+
			"assertion below could then pass without the wiring under test", got)
	}

	// nil SessionSync: every use of it in this function is a method VALUE,
	// which is legal to take on a nil pointer and is never called here.
	d.wireClusterPeerFailoverHooks(nil)

	line := forwardingLineOf7367(d.cluster.FormatStatus())
	if line == "" {
		t.Fatal("after wiring, `show chassis cluster status` still renders no " +
			"Forwarding: line — SetRGForwardingFunc is not being called, so the " +
			"#7367 divergence stays invisible to the operator")
	}
	if !strings.Contains(line, "rg-active=") {
		t.Errorf("forwarding line %q carries no rg-active term", line)
	}
}

// The read-only contract: a `show` must not create a state machine, and a group
// with none must report ok=false so the render omits the line rather than
// asserting "not forwarding" about an unknown.
func TestRGForwardingStatusIsReadOnlyAndAbsentForUnknownRG7367(t *testing.T) {
	d := &Daemon{rgStates: map[int]*rgStateMachine{}}
	if _, ok := d.rgForwardingStatus(7); ok {
		t.Error("reported forwarding state for an RG with no state machine")
	}
	if len(d.rgStates) != 0 {
		t.Errorf("a show-path lookup CREATED an rg state machine (len=%d) — "+
			"an operator command must not mutate daemon state", len(d.rgStates))
	}
}

func forwardingLineOf7367(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "Forwarding:") {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

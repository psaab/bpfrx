package cluster

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// #8206: run the REAL shell parsers against REAL FormatStatus output.
//
// `make test-deploy-lib` runs 48 assertions over `deploy_rolling_secondary_node`
// and `deploy_reassert_node0_primary_ok`, and every one of them parses a string
// literal defined inside deploy-lib-selftest.sh. So it proves the parsers still
// work ON THE FIXTURES and says nothing about whether the fixtures still
// resemble what the daemon prints. They already do not: FormatStatus emits a
// `Forwarding:` sub-line (#7367) that appears in no fixture.
//
// The failure mode is specific. `deploy_rolling_secondary_node` defaulting to
// the wrong node makes a rolling deploy restart the PRIMARY first — the #4009
// regression the function exists to prevent — and a drifted fixture would let
// that ship with `make test-deploy-lib` green, with only the cluster noticing.
//
// WHY THIS SHELLS OUT RATHER THAN REIMPLEMENTING THE PARSERS. The property is
// what awk does with this text, and a Go paraphrase of `$1 == "node0"` /
// `/^node0[[:space:]]/` is a second implementation that can drift from the
// first — which is the exact class of bug this issue is about, one level up. A
// test that runs the shipped function cannot disagree with the shipped
// function.
//
// The invariants being pinned are SHAPE, not content:
//   - `$3` of the `Redundancy group:` header is the RG id;
//   - the node row's `$1` is the node token and `$3` is the status;
//   - every sub-line is INDENTED, so it can match neither `$1 == "node0"` nor
//     the column-0-anchored `/^node0[[:space:]]/`.
//
// The last one is what a new sub-line breaks, and it is the reason
// `Forwarding:` had to be indented (#7367).

// runDeployLibFn pipes `status` through one function from deploy-lib.sh and
// returns its stdout and exit code.
func runDeployLibFn(t *testing.T, fn, status string) (string, int) {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	lib := filepath.Join(filepath.Dir(self), "..", "..", "test", "incus", "deploy-lib.sh")
	if _, err := os.Stat(lib); err != nil {
		t.Fatalf("deploy-lib.sh not found at %s: %v — this test exists to bind "+
			"that file's parsers, so a missing path is a broken test, not a skip", lib, err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skipf("awk not available: %v", err)
	}
	cmd := exec.Command("bash", "-c", ". \""+lib+"\" >/dev/null 2>&1; "+fn)
	cmd.Stdin = strings.NewReader(status)
	out, err := cmd.Output()
	code := 0
	if ee, isExit := err.(*exec.ExitError); isExit {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %s: %v", fn, err)
	}
	return strings.TrimSpace(string(out)), code
}

// withLivePeer8206 makes the PEER node row render.
//
// Without it FormatStatus emits only the local node row, and every positional
// assertion below runs against half the layout — which is the same
// "assertion ran against almost nothing" failure the fixtures already have.
func withLivePeer8206(m *Manager, peerState NodeState, peerPriority int) *Manager {
	m.mu.Lock()
	// peerNodeID is what names the PEER row, and NewManager's second argument
	// is the CLUSTER id, not the peer node id. Leaving it at 0 renders BOTH
	// rows as `node0` — a shape that would defeat both parsers, and which cost
	// a false "the reassert accepts a secondary node0" finding until it was
	// traced to the fixture rather than the product.
	m.peerNodeID = 1
	m.peerEverSeen = true
	m.peerAlive = true
	m.peerGroups[0] = PeerGroupState{
		GroupID:  0,
		Priority: peerPriority,
		Weight:   255,
		State:    peerState,
	}
	m.mu.Unlock()
	return m
}

// TestRealFormatStatusDrivesTheShellParsersCorrectly8206 is the cell the
// self-test's 48 fixture-based assertions cannot be: real output, real parsers.
func TestRealFormatStatusDrivesTheShellParsersCorrectly8206(t *testing.T) {
	// node0 PRIMARY for RG0. A rolling deploy must restart the SECONDARY
	// (node1) first, so deploy_rolling_secondary_node must print 1.
	primary := withLivePeer8206(primaryManagerWithForwarding7367(t, RGForwarding{
		Active: true, AllVRRPMaster: true, AnyVRRPMaster: true,
	}), StateSecondary, 100)
	out := primary.FormatStatus()

	// FIXTURE PREMISE, and it is the whole point of using real output: the
	// render must actually carry the sub-lines the hand-written fixtures lack.
	// Without this the cell degrades into the fixture test it exists to
	// replace.
	if !strings.Contains(out, "Forwarding:") {
		t.Fatalf("real FormatStatus output carries no `Forwarding:` sub-line, so this "+
			"cell is not exercising the layout the shell parsers must survive:\n%s", out)
	}

	got, _ := runDeployLibFn(t, "deploy_rolling_secondary_node", out)
	if got != "1" {
		t.Errorf("deploy_rolling_secondary_node = %q, want \"1\" (node0 is PRIMARY for "+
			"RG0, so node1 is the secondary and must be restarted first). A wrong "+
			"answer here restarts the PRIMARY first — the #4009 regression.\n"+
			"parsed output was:\n%s", got, out)
	}

	// The post-deploy reassert must accept this output: node0 IS primary for
	// every RG present.
	if _, code := runDeployLibFn(t, "deploy_reassert_node0_primary_ok", out); code != 0 {
		t.Errorf("deploy_reassert_node0_primary_ok exited %d on real output where node0 "+
			"is primary for every RG; it must accept.\noutput was:\n%s", code, out)
	}
}

// The CONTROL. Without it the cell above passes for a parser that prints "1"
// unconditionally — which is exactly the #4009 defect, since the legacy pattern
// never matched and ALWAYS fell through to the default of 1.
func TestRealFormatStatusSecondaryNode0IsDetected8206(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 100, 1: 200})))
	drainEvents(m, 4)
	m.SetGroupStateForTesting(0, StateSecondary)
	withLivePeer8206(m, StatePrimary, 200)
	if got := m.GroupStates()[0].State; got != StateSecondary {
		t.Fatalf("fixture must hold RG0 as SECONDARY, got %v — otherwise this "+
			"control cannot distinguish a real detection from the default", got)
	}
	out := m.FormatStatus()

	got, _ := runDeployLibFn(t, "deploy_rolling_secondary_node", out)
	if got != "0" {
		t.Errorf("deploy_rolling_secondary_node = %q, want \"0\" (node0 is SECONDARY for "+
			"RG0). Printing 1 here is the #4009 fall-through: the parser matched "+
			"nothing and defaulted, which is indistinguishable from a correct answer "+
			"when node0 happens to be primary.\noutput was:\n%s", got, out)
	}

	// And the reassert must REFUSE this output — node0 is not primary.
	if _, code := runDeployLibFn(t, "deploy_reassert_node0_primary_ok", out); code == 0 {
		t.Errorf("deploy_reassert_node0_primary_ok ACCEPTED output where node0 is "+
			"secondary for RG0; it must refuse.\noutput was:\n%s", out)
	}
}

// TestNoFormatStatusSubLineParsesAsANodeRow8206 generalises the #7367 guard
// from the one line it was written for to EVERY line real output emits.
//
// #7367 pinned that `Forwarding:` is not parseable as a node row. Nothing pins
// the same for `Takeover ready:` / `Transfer ready:` / `Held secondary:` or for
// whatever is added next, and the row layout as a whole is unpinned — which is
// what #8206 is about.
func TestNoFormatStatusSubLineParsesAsANodeRow8206(t *testing.T) {
	m := withLivePeer8206(primaryManagerWithForwarding7367(t, RGForwarding{
		Active: false, AllVRRPMaster: false, AnyVRRPMaster: false,
	}), StateSecondary, 100)
	out := m.FormatStatus()

	var nodeRows, subLines int
	var nodeTokens []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		isNodeToken := fields[0] == "node0" || fields[0] == "node1"
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")

		if isNodeToken {
			nodeRows++
			nodeTokens = append(nodeTokens, fields[0])
			// A node row must NOT be indented, or the column-0-anchored
			// `/^node0[[:space:]]/` in deploy_reassert_node0_primary_ok stops
			// seeing it and the reassert silently passes on zero rows.
			if indented {
				t.Errorf("node row is INDENTED, so /^node0[[:space:]]/ cannot match it: %q", line)
			}
			// $3 must be the status, which is what both parsers read.
			if len(fields) < 3 {
				t.Errorf("node row has %d fields, need >= 3 so $3 is the status: %q",
					len(fields), line)
			}
			continue
		}

		if indented {
			subLines++
			// The load-bearing invariant. An UNINDENTED sub-line whose first
			// field happened to be a node token would be read as a node row by
			// both parsers; an indented one cannot be, because awk strips
			// leading blanks for $1 but /^node0/ is anchored at column 0.
			// Assert the stronger property directly: no sub-line may begin
			// with a node token at all.
			if fields[0] == "node0" || fields[0] == "node1" {
				t.Errorf("sub-line's first field is a node token, so `$1 == \"node0\"` "+
					"reads it as a node row: %q", line)
			}
		}
	}

	// NON-VACUITY, both halves. A render with no node rows would satisfy every
	// assertion above; so would one with no sub-lines, which is precisely the
	// stale-fixture state this issue is about.
	// The node tokens must be DISTINCT. Two rows both reading `node0` would let
	// deploy_reassert_node0_primary_ok match the PEER row and accept a state in
	// which the local node is secondary — verified by hitting exactly that from
	// a fixture that left peerNodeID unset.
	if len(nodeTokens) == 2 && nodeTokens[0] == nodeTokens[1] {
		t.Errorf("both node rows carry the same token %q; the parsers cannot tell the "+
			"local node from the peer:\n%s", nodeTokens[0], out)
	}
	// EXACTLY two, not "at least two", and the difference is the whole cell.
	//
	// `>= 2` was the first version and a mutation walked straight through it:
	// un-indenting the `Forwarding:` sub-line to `node0 Forwarding: ...` gives
	// it a node token in $1, so the loop above CLASSIFIED it as a legitimate
	// node row and every per-row assertion passed. The count simply went to 3
	// and nothing looked at it.
	//
	// A render has exactly one row per node. A third line that parses as a node
	// row IS the defect — some sub-line acquired node-row shape — and the count
	// is the only thing that can see it, because each such line is individually
	// well-formed.
	if nodeRows != 2 {
		t.Fatalf("found %d line(s) parseable as a node row; expected exactly 2 (one per "+
			"node). More than 2 means a sub-line acquired node-row shape and the "+
			"positional parsers will read it as one; fewer means the assertions above "+
			"ran against almost nothing:\n%s", nodeRows, out)
	}
	if subLines == 0 {
		t.Fatalf("found NO indented sub-lines in real output. Either FormatStatus "+
			"stopped emitting them or the scan is broken — either way the sub-line "+
			"assertions above proved nothing, which is the exact blindness #8206 "+
			"reports in the shell fixtures:\n%s", out)
	}
}

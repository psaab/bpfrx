package cluster

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8206: FormatStatus has a LAYOUT contract that two shell smokes parse
// positionally, and until this file nothing asserted it.
//
//   - test/incus/deploy-lib.sh (deploy_rolling_secondary_node and friends) awk
//     on `$1 == "node0"` inside a "Redundancy group: N" block and read `$3` as
//     the status, so the node token must be field 1 and the state field 3;
//   - test/incus/test-failover.sh does
//     `grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"`, so the
//     local node row must be the FIRST line after the header — the -A1 window
//     is exactly one line wide.
//
// status.go documents both constraints in three separate comments (the
// "Held secondary:" placement at :57, the #7367 "Forwarding:" placement at
// :157) and every sub-line added so far has respected them. Nothing enforced
// that. The existing TestFormatStatus is entirely strings.Contains, which
// survives an arbitrary line being inserted between the header and the node
// row, and survives a column being added before the node token — it cannot see
// layout at all. Three sub-lines (Takeover ready, Transfer ready, Forwarding)
// were added under it and passed because they happened to be placed correctly,
// not because anything checked.
//
// The failure this prevents is specific and expensive: deploy_rolling_secondary
// _node defaulting to the wrong node makes a rolling cluster deploy restart the
// PRIMARY first, which is the #4009 regression that function exists to prevent.
// It would ship with `make test-deploy-lib` green, because that self-test runs
// the real parsers against FROZEN captured fixtures which a renderer change does
// not touch. Only the cluster would notice.

// statusLayoutViolations returns a human-readable violation for every breach of
// the positional contract in a rendered `show chassis cluster status`.
//
// EXTRACTED rather than inlined into the test so the guard itself is testable:
// TestStatusLayoutContractDetectsAViolation feeds it a synthetic bad render and
// requires it to complain. A contract check that has only ever been run against
// correct input is indistinguishable from one that always returns nil.
func statusLayoutViolations(out string) []string {
	var v []string
	lines := strings.Split(out, "\n")

	firstRGHeader := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "Redundancy group:") {
			if firstRGHeader < 0 {
				firstRGHeader = i
			}
			if i+1 >= len(lines) {
				v = append(v, fmt.Sprintf("line %d: %q is the last line; no node row follows it", i+1, l))
				continue
			}
			row := lines[i+1]
			f := strings.Fields(row)
			if len(f) < 3 {
				v = append(v, fmt.Sprintf("line %d: the line after %q is %q, which has %d fields; deploy-lib.sh reads $1 and $3",
					i+2, l, row, len(f)))
				continue
			}
			if !strings.HasPrefix(f[0], "node") {
				v = append(v, fmt.Sprintf("line %d: the line after %q starts with %q, not a node token — "+
					"test-failover.sh's `grep -A1` window is one line wide, so this line consumes it and the node row is never seen",
					i+2, l, f[0]))
			}
			if f[2] == "" {
				v = append(v, fmt.Sprintf("line %d: node row %q has an empty field 3 (status)", i+2, row))
			}
		}
	}

	// "Held secondary:" must sit ABOVE every RG header, so no RG is in scope
	// when awk reads it, and its first field must not be mistakable for a node
	// token (status.go:57, #4009).
	for i, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), "Held secondary:") {
			continue
		}
		if firstRGHeader >= 0 && i > firstRGHeader {
			v = append(v, fmt.Sprintf("line %d: %q sits BELOW the first \"Redundancy group:\" header (line %d), "+
				"so awk reads it with an RG in scope", i+1, l, firstRGHeader+1))
		}
		if f := strings.Fields(l); len(f) > 0 && strings.HasPrefix(f[0], "node") {
			v = append(v, fmt.Sprintf("line %d: %q has a node token as field 1", i+1, l))
		}
	}
	return v
}

func TestFormatStatusHonoursTheShellParsersLayoutContract_8206(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(
		makeRG(0, true, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	))
	// Drive the #7367 sub-line too: it is the most recent addition and the one
	// whose placement the contract was nearly broken by.
	m.SetRGForwardingFunc(func(rgID int) (RGForwarding, bool) {
		return RGForwarding{Active: true, AllVRRPMaster: true, AnyVRRPMaster: true}, true
	})

	out := m.FormatStatus()
	if !strings.Contains(out, "Redundancy group: 0") {
		t.Fatalf("fixture did not render an RG block, so this cell measured nothing:\n%s", out)
	}
	if !strings.Contains(out, "Forwarding:") {
		t.Fatalf("fixture did not render the #7367 sub-line, so the cell is not exercising "+
			"the placement it exists to check:\n%s", out)
	}
	if v := statusLayoutViolations(out); len(v) > 0 {
		t.Errorf("FormatStatus broke the layout contract that test/incus/deploy-lib.sh and "+
			"test-failover.sh parse positionally:\n  %s\n\nrendered:\n%s",
			strings.Join(v, "\n  "), out)
	}
}

// The guard must be able to fail. A synthetic render with one line inserted
// between the header and the node row is exactly the change status.go's
// comments warn against, and it is what a future sub-line placed one line too
// early would produce.
func TestStatusLayoutContractDetectsAViolation_8206(t *testing.T) {
	good := "Redundancy group: 0 , Failover count: 0\n" +
		"node0   200       primary        no       no       None\n"
	if v := statusLayoutViolations(good); len(v) != 0 {
		t.Fatalf("the guard rejected a CORRECT render, so a real violation could not be "+
			"distinguished from a false alarm: %v", v)
	}

	bad := "Redundancy group: 0 , Failover count: 0\n" +
		"  Forwarding: active\n" +
		"node0   200       primary        no       no       None\n"
	v := statusLayoutViolations(bad)
	if len(v) == 0 {
		t.Fatal("the guard passed a render with a sub-line between the header and the node " +
			"row — the exact breakage it exists to detect, and the one that would send a " +
			"rolling deploy at the PRIMARY first (#4009)")
	}
	if !strings.Contains(v[0], "Forwarding:") {
		t.Errorf("the guard fired but did not name the offending line; a violation report "+
			"that does not say WHICH line moved cannot be acted on: %v", v)
	}

	held := "Redundancy group: 0 , Failover count: 0\n" +
		"node0   200       primary        no       no       None\n" +
		"Held secondary: kernel promote\n"
	if v := statusLayoutViolations(held); len(v) == 0 {
		t.Error("the guard passed a \"Held secondary:\" line placed BELOW an RG header, " +
			"which awk reads with an RG in scope (#4009, status.go:57)")
	}
}

var _ = config.ClusterConfig{}

package nftables

import (
	"strings"
	"testing"
)

// #9072: an lo0 `reject` term with an EXPLICIT protocol emitted a dead rule.
//
// `applyMatches` latches `l4Val` from the term's own protocol, so
// `needL4proto(protoTCP)` on a non-TCP term saw `l4Val != 6` and appended a
// SECOND, contradictory `meta l4proto` compare — `l4proto==11 && l4proto==06`.
// Dead by construction, and operator-visible in `nft list ruleset`, where a
// self-contradictory rule invites misdiagnosis.
//
// ENFORCEMENT WAS NEVER AFFECTED, which is the half worth asserting rather than
// asserting away: the icmpx rule always carried the correct family-agnostic
// reject for the specified protocols in every case, including the mixed
// `[tcp udp]` one. The cells below therefore check BOTH that the dead rule is
// gone AND that a live reject for each named protocol survives — a fix that
// dropped a needed rule would satisfy the first alone.
//
// The pre-#9072 goldens are SILENT here, not contrary: TestGoldenRejectTermPair
// and the `reject-term` scenario both pin a term with NO Protocols, and
// netlink_lo0_proto_icmp_6806_test.go never touches reject. That no-protocol
// case is unchanged, and a cell below pins it so the fix cannot drift into it.

func rejectRules9072(t *testing.T, protos ...string) string {
	t.Helper()
	p := newBuildPlan(t, "xpf_9072", lo0FilterPriority)
	buildLo0TermNetlink(p, Lo0FilterTerm{
		Name: "r", Action: "reject", Protocols: protos,
	}, famV4)
	if p.err != nil {
		t.Fatalf("build error for protocols %v: %v", protos, p.err)
	}
	return canonRules(p)
}

// The l4proto compare against TCP, as canonRules renders it.
const tcpCompare9072 = "cmp(op=0,reg=1,06)"

// countCompares9072 counts `meta l4proto` compares in ONE rule line — the
// signature of the defect is TWO of them in a single rule.
func countCompares9072(rule string) int {
	return strings.Count(rule, "cmp(op=0,reg=1,")
}

func TestRejectTermEmitsNoContradictoryRule9072(t *testing.T) {
	for _, tc := range []struct {
		name   string
		protos []string
	}{
		{"udp", []string{"udp"}},
		{"icmp", []string{"icmp"}},
		{"udp+icmp", []string{"udp", "icmp"}},
		{"tcp", []string{"tcp"}},
		{"tcp+udp", []string{"tcp", "udp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rejectRules9072(t, tc.protos...)
			for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
				if line == "" {
					continue
				}
				// A single rule carrying two l4proto compares is the dead rule:
				// two different protocol values can never both hold.
				if n := countCompares9072(line); n > 1 {
					t.Errorf("#9072: protocol %v emitted a rule with %d contradictory "+
						"`meta l4proto` compares — dead by construction, and visible in "+
						"`nft list ruleset` where it invites misdiagnosis:\n  %s",
						tc.protos, n, line)
				}
			}
		})
	}
}

// ENFORCEMENT UNCHANGED — the half the dead-rule assertion cannot see.
//
// A "fix" that simply stopped emitting rules would satisfy the cell above
// completely. Each case must still produce a live reject.
func TestRejectTermStillRejectsEveryNamedProtocol9072(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protos    []string
		wantRules int
		wantTCP   bool // a tcp-reset rule must be present
		wantICMPX bool // the family-agnostic icmpx rule must be present
	}{
		// No protocol: BOTH rules, byte-identical to the pre-#9072 golden.
		{"none", nil, 2, true, true},
		// TCP is not among the protocols: only the icmpx reject is reachable.
		{"udp", []string{"udp"}, 1, false, true},
		{"icmp", []string{"icmp"}, 1, false, true},
		{"udp+icmp", []string{"udp", "icmp"}, 1, false, true},
		// TCP only: the tcp-reset rule matches everything the icmpx rule could.
		{"tcp", []string{"tcp"}, 1, true, false},
		// Mixed: both are reachable — tcp-reset for TCP, icmpx for UDP.
		{"tcp+udp", []string{"tcp", "udp"}, 2, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rejectRules9072(t, tc.protos...)
			lines := strings.Split(strings.TrimSpace(got), "\n")
			if len(lines) == 1 && lines[0] == "" {
				lines = nil
			}
			if len(lines) != tc.wantRules {
				t.Errorf("#9072: protocol %v emitted %d rules, want %d:\n%s",
					tc.protos, len(lines), tc.wantRules, got)
			}
			hasTCPReset := strings.Contains(got, "reject(type=1,code=0)")
			hasICMPX := strings.Contains(got, "reject(type=2,code=3)")
			if hasTCPReset != tc.wantTCP {
				t.Errorf("#9072: protocol %v tcp-reset rule present=%v, want %v. "+
					"Dropping a REACHABLE reject would change enforcement, which "+
					"this issue explicitly does not do:\n%s",
					tc.protos, hasTCPReset, tc.wantTCP, got)
			}
			if hasICMPX != tc.wantICMPX {
				t.Errorf("#9072: protocol %v icmpx rule present=%v, want %v:\n%s",
					tc.protos, hasICMPX, tc.wantICMPX, got)
			}
		})
	}
}

// The no-protocol case must stay BYTE-IDENTICAL to the pre-#9072 golden. That
// case is the one the existing goldens pin, and a fix that drifted it would be a
// behaviour change smuggled in beside a cosmetic one.
func TestRejectTermWithNoProtocolIsUnchanged9072(t *testing.T) {
	got := rejectRules9072(t)
	want := "r00: meta(key=16,reg=1) " + tcpCompare9072 + " reject(type=1,code=0)\n" +
		"r01: reject(type=2,code=3)\n"
	if got != want {
		t.Errorf("#9072: the no-protocol reject pair changed. It is what "+
			"TestGoldenRejectTermPair pins and it must not move:\n  got:  %q\n  want: %q",
			got, want)
	}
}

// An UNRESOLVABLE protocol token must fail the plan CLOSED (#6806) and must not
// be quietly narrowed by the new emission decision. The reach predicate returns
// "reachable, not TCP-only" for that case precisely so the failure comes from
// applyMatches rather than from a silently smaller ruleset here.
func TestRejectTermWithUnresolvableProtocolStillFailsClosed9072(t *testing.T) {
	p := newBuildPlan(t, "xpf_9072", lo0FilterPriority)
	buildLo0TermNetlink(p, Lo0FilterTerm{
		Name: "r", Action: "reject", Protocols: []string{"not-a-protocol"},
	}, famV4)
	if p.err == nil {
		t.Error("#9072: an unresolvable protocol token must fail the plan CLOSED " +
			"(#6806). Deciding rule emission on a protocol set that could not be " +
			"resolved would reason from a value the caller is about to reject")
	}
}

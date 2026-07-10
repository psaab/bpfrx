package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5277: an ordered BGP `import`/`export [ A B C ]` policy list is a Junos CHAIN
// — each policy evaluated in order, first terminal action (accept/reject) wins,
// fall through to the next if none. The pre-#5277 renderer collapsed the list to
// the LAST policy (lastNonEmpty), silently dropping a leading reject/attribute
// policy so a route it would reject was advertised/accepted (a security-relevant
// vSRX-parity gap). These tests assert the composed single-route-map that
// preserves the chain, per-neighbor AND global, import AND export.

// mustContain fails the test if got does not contain want.
func mustContain5277(t *testing.T, got, want, why string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("%s: missing %q in:\n%s", why, want, got)
	}
}

// mustPrecede fails if first does not appear strictly before second in got.
func mustPrecede5277(t *testing.T, got, first, second, why string) {
	t.Helper()
	i, j := strings.Index(got, first), strings.Index(got, second)
	if i < 0 || j < 0 {
		t.Errorf("%s: both entries must be present (%q@%d, %q@%d) in:\n%s", why, first, i, second, j, got)
		return
	}
	if i >= j {
		t.Errorf("%s: %q (@%d) must precede %q (@%d) in:\n%s", why, first, i, second, j, got)
	}
}

// blockPrivateAllowCustomerPO builds the canonical issue example: BLOCK-PRIVATE
// rejects RFC1918, ALLOW-CUSTOMER permits everything. Chained as [ BLOCK-PRIVATE
// ALLOW-CUSTOMER ], BLOCK-PRIVATE MUST run first.
func blockPrivateAllowCustomerPO() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"BLOCK-PRIVATE": {Name: "BLOCK-PRIVATE", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: []string{"rfc1918"}, Action: "reject"},
			}},
			"ALLOW-CUSTOMER": {Name: "ALLOW-CUSTOMER", Terms: []*config.PolicyTerm{
				{Name: "t1", Action: "accept"},
			}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"rfc1918": {Name: "rfc1918", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
}

// TestBGPExportChainComposedPerNeighbor is the core export-side fix. A neighbor
// export `[ BLOCK-PRIVATE ALLOW-CUSTOMER ]` must apply BOTH policies in order —
// the leading BLOCK-PRIVATE reject BEFORE ALLOW-CUSTOMER's permit — not just the
// last policy.
//
// RED-on-revert: reverting to the lastNonEmpty single-render makes the neighbor
// reference `route-map ALLOW-CUSTOMER out`, emits NO composed route-map, and
// BLOCK-PRIVATE's reject never renders — so the composed-name reference, the
// `deny 10` BLOCK-PRIVATE sequence, and the deny-before-permit ordering all
// disappear → this test fails.
func TestBGPExportChainComposedPerNeighbor(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: blockPrivateAllowCustomerPO(),
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"BLOCK-PRIVATE", "ALLOW-CUSTOMER"}},
			},
		},
	}
	got := New().buildManagedSection(fc)

	const composed = "BLOCK-PRIVATE-ALLOW-CUSTOMER-xpf-chain"
	// The neighbor references the COMPOSED route-map, not just the last policy.
	mustContain5277(t, got, "neighbor 10.0.2.1 route-map "+composed+" out\n", "neighbor must reference the composed chain route-map")
	if strings.Contains(got, "neighbor 10.0.2.1 route-map ALLOW-CUSTOMER out") {
		t.Errorf("neighbor must NOT reference only the last policy (the #5277 drop), got:\n%s", got)
	}
	// BLOCK-PRIVATE's reject renders as `deny 10` with its RFC1918 match, and
	// runs BEFORE ALLOW-CUSTOMER's `permit 20` (ordering + first-terminal-wins).
	mustContain5277(t, got, "route-map "+composed+" deny 10\n match ip address prefix-list rfc1918\n", "BLOCK-PRIVATE reject must render first in the composed map")
	mustContain5277(t, got, "route-map "+composed+" permit 20\n", "ALLOW-CUSTOMER accept must render after BLOCK-PRIVATE")
	mustPrecede5277(t, got, "route-map "+composed+" deny 10", "route-map "+composed+" permit 20", "leading reject must precede the trailing permit")
	// Fall-off-the-end of the whole chain → Junos BGP default-accept permit.
	mustContain5277(t, got, "route-map "+composed+" permit 30\n", "chain must end in a BGP default-accept permit")
}

// TestBGPImportChainComposedThreePolicies proves a 3-policy inbound chain
// composes all three in order. B is a non-terminating set-only policy (bumps
// local-pref, falls through), so the chain must be A(reject) → B(set, fall
// through) → C(accept), each preserved.
func TestBGPImportChainComposedThreePolicies(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {Name: "A", Terms: []*config.PolicyTerm{{Name: "t", PrefixList: []string{"bogons"}, Action: "reject"}}},
			"B": {Name: "B", Terms: []*config.PolicyTerm{{Name: "t", HasLocalPreference: true, LocalPreference: 200}}},
			"C": {Name: "C", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"bogons": {Name: "bogons", Prefixes: []string{"192.0.2.0/24"}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"A", "B", "C"}},
			},
		},
	}
	got := New().buildManagedSection(fc)

	const composed = "A-B-C-xpf-chain"
	mustContain5277(t, got, "neighbor 10.0.2.1 route-map "+composed+" in\n", "neighbor must reference the 3-policy composed chain")
	// A rejects bogons first.
	mustContain5277(t, got, "route-map "+composed+" deny 10\n match ip address prefix-list bogons\n", "A (reject) must render first")
	// B is non-terminating: it sets local-preference and falls through (on-match next).
	mustContain5277(t, got, "route-map "+composed+" permit 20\n set local-preference 200\n on-match next\n", "B (set-only) must render second with on-match next")
	// C accepts.
	mustContain5277(t, got, "route-map "+composed+" permit 30\n", "C (accept) must render third")
	// Strict order A < B < C.
	mustPrecede5277(t, got, composed+" deny 10", composed+" permit 20", "A before B")
	mustPrecede5277(t, got, composed+" permit 20", composed+" permit 30", "B before C")
}

// TestBGPSinglePolicyByteIdenticalNoComposed pins the common case: a
// single-policy list references the standalone per-policy route-map and emits NO
// composed `-xpf-chain` object, byte-identical to the pre-#5277 render.
func TestBGPSinglePolicyByteIdenticalNoComposed(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"ONLY-OUT": {Name: "ONLY-OUT", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"ONLY-OUT"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	mustContain5277(t, got, "neighbor 10.0.2.1 route-map ONLY-OUT out\n", "single-policy export must reference the standalone route-map")
	if strings.Contains(got, ReservedChainSuffix) {
		t.Errorf("a single-policy chain must NOT emit a composed %q route-map, got:\n%s", ReservedChainSuffix, got)
	}
}

// TestBGPExplicitRejectDefaultTerminatesChain: a policy with an explicit
// policy-level `then reject` default terminates the chain — a match-all deny
// after its terms — so a following policy is unreachable (Junos: the default
// action is terminating). The composed map must render FIRST's terms, then a
// blanket deny, and the SECOND policy's accept must NOT appear.
func TestBGPExplicitRejectDefaultTerminatesChain(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			// FIRST matches customer routes (accept) then defaults to REJECT.
			"FIRST": {Name: "FIRST", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "t", PrefixList: []string{"cust"}, Action: "accept"},
			}},
			"SECOND": {Name: "SECOND", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"cust": {Name: "cust", Prefixes: []string{"203.0.113.0/24"}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"FIRST", "SECOND"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	const composed = "FIRST-SECOND-xpf-chain"
	mustContain5277(t, got, "neighbor 10.0.2.1 route-map "+composed+" out\n", "neighbor references composed chain")
	// FIRST's accept term, then FIRST's explicit reject default (blanket deny).
	mustContain5277(t, got, "route-map "+composed+" permit 10\n match ip address prefix-list cust\n", "FIRST's customer accept term")
	mustContain5277(t, got, "route-map "+composed+" deny 20\n", "FIRST's explicit reject default terminates the chain with a blanket deny")
	// The chain terminated at FIRST's default, so there is no seq-30 permit for
	// SECOND, and no trailing default beyond the deny.
	if strings.Contains(got, "route-map "+composed+" permit 30") {
		t.Errorf("SECOND must be unreachable after FIRST's terminating reject default, got:\n%s", got)
	}
}

// TestBGPGlobalExportChainComposed proves the GLOBAL loop is fixed too: a
// neighbor with NO own export inherits `protocols bgp export [ G-BLOCK G-ALLOW ]`
// as a composed chain, in order.
//
// RED-on-revert: the pre-#5277 global loop kept only the last defined export, so
// the neighbor referenced `route-map G-ALLOW out` and G-BLOCK's reject vanished.
func TestBGPGlobalExportChainComposed(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"G-BLOCK": {Name: "G-BLOCK", Terms: []*config.PolicyTerm{{Name: "t", PrefixList: []string{"rfc1918"}, Action: "reject"}}},
			"G-ALLOW": {Name: "G-ALLOW", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"rfc1918": {Name: "rfc1918", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Export: []string{"G-BLOCK", "G-ALLOW"},
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true},
			},
		},
	}
	got := New().buildManagedSection(fc)
	const composed = "G-BLOCK-G-ALLOW-xpf-chain"
	mustContain5277(t, got, "neighbor 10.0.2.1 route-map "+composed+" out\n", "family-less neighbor must inherit the global export chain")
	mustPrecede5277(t, got, "route-map "+composed+" deny 10", "route-map "+composed+" permit 20", "global chain preserves order (G-BLOCK before G-ALLOW)")
}

// TestBGPComposedChainCollisionFailsClosed: if an operator policy-statement is
// literally named like a chain's composed name, FRR would merge the two
// same-named route-maps. bgpComposedChainCollision must reject the config so
// ApplyFull fails the apply CLOSED rather than emitting a fused route-map.
func TestBGPComposedChainCollisionFailsClosed(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {Name: "A", Terms: []*config.PolicyTerm{{Name: "t", Action: "reject"}}},
			"B": {Name: "B", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
			// Operator policy whose name collides with composedChainName([A B]).
			"A-B-xpf-chain": {Name: "A-B-xpf-chain", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"A", "B"}},
			},
		},
	}
	if err := bgpComposedChainCollision(fc); err == nil {
		t.Errorf("expected a fail-closed collision error when a composed chain name collides with an operator policy-statement, got nil")
	}
}

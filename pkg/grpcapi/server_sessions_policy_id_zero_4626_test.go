package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #4626 L01, gRPC half. sessionEntryV4/V6 resolved PolicyName by indexing the
// compiled policyNames map directly, and `policy_id` 0 is BOTH the first
// configured policy's id and the value stamped on every session no policy
// admitted (host-inbound, neighbor-seed, fabric, tunnel, pre-#3056, and every
// session synced from an older HA peer during a rolling upgrade). Structured
// consumers of GetSessions were told a specific rule admitted traffic that rule
// never saw.
//
// These drive the real entry builders. Re-inlining `policyNames[val.PolicyID]`
// at either site turns them RED.

// policyNames4626 is the fixture that matters: id 0 is OCCUPIED by a real
// policy, exactly as compilePolicies emits it. A fixture without an entry at 0
// would pass against the unfixed code.
func policyNames4626() map[uint32]string {
	return map[uint32]string{
		0:                                 "trust-to-untrust/allow-web",
		1:                                 "trust-to-untrust/allow-dns",
		dataplane.DefaultPolicySentinelID: dataplane.DefaultPolicyName,
	}
}

func entryV4_4626(t *testing.T, policyID uint32) *pbSessionEntryShim {
	t.Helper()
	se := sessionEntryV4(
		dataplane.SessionKey{Protocol: 6},
		dataplane.SessionValue{State: 1, PolicyID: policyID, IngressZone: 1, EgressZone: 2,
			Created: 100, LastSeen: 100},
		200,
		map[uint16]string{1: "trust", 2: "untrust"},
		policyNames4626(),
		map[uint16][]string{},
		map[sessionEgressKey]string{},
		true,
	)
	return &pbSessionEntryShim{PolicyName: se.PolicyName, PolicyID: se.PolicyId}
}

// pbSessionEntryShim narrows the protobuf entry to the two fields under test,
// so the assertions do not depend on the rest of the generated struct.
type pbSessionEntryShim struct {
	PolicyName string
	PolicyID   uint32
}

func TestSessionEntryV4PolicyIDZeroNotFirstPolicy_4626(t *testing.T) {
	names := policyNames4626()
	got := entryV4_4626(t, 0)

	if got.PolicyName == names[0] {
		t.Fatalf("gRPC session entry reports policy_name=%q for a policy_id 0 session — that "+
			"is the FIRST configured policy, which never admitted it. A host-inbound, fabric, "+
			"tunnel or older-peer-synced session carries id 0 (#4626)", got.PolicyName)
	}
	if got.PolicyName != dataplane.UnattributedPolicyName {
		t.Errorf("policy_name = %q, want %q", got.PolicyName, dataplane.UnattributedPolicyName)
	}
	if got.PolicyID != 0 {
		t.Errorf("policy_id = %d, want 0 — the raw wire value must still be surfaced", got.PolicyID)
	}
}

func TestSessionEntryV6PolicyIDZeroNotFirstPolicy_4626(t *testing.T) {
	names := policyNames4626()
	se := sessionEntryV6(
		dataplane.SessionKeyV6{Protocol: 6},
		dataplane.SessionValueV6{State: 1, PolicyID: 0, IngressZone: 1, EgressZone: 2,
			Created: 100, LastSeen: 100},
		200,
		map[uint16]string{1: "trust", 2: "untrust"},
		names,
		map[uint16][]string{},
		map[sessionEgressKey]string{},
		true,
	)

	if se.PolicyName == names[0] {
		t.Fatalf("gRPC IPv6 session entry reports policy_name=%q for a policy_id 0 session — "+
			"the first configured policy never admitted it (#4626)", se.PolicyName)
	}
	if se.PolicyName != dataplane.UnattributedPolicyName {
		t.Errorf("policy_name = %q, want %q", se.PolicyName, dataplane.UnattributedPolicyName)
	}
}

// Over-rejection guard: a session a real policy DID admit must keep reporting
// that policy, and the #3057 default-policy sentinel must keep its rendering. A
// fix that blanked every name would pass the tests above and gut the surface.
func TestSessionEntryRealPolicyStillResolves_4626(t *testing.T) {
	names := policyNames4626()

	if got := entryV4_4626(t, 1); got.PolicyName != names[1] {
		t.Errorf("v4 policy_name = %q, want %q — an admitted session must still name its "+
			"policy", got.PolicyName, names[1])
	}
	if got := entryV4_4626(t, dataplane.DefaultPolicySentinelID); got.PolicyName != dataplane.DefaultPolicyName {
		t.Errorf("default-sentinel policy_name = %q, want %q (#3057 must not regress)",
			got.PolicyName, dataplane.DefaultPolicyName)
	}

	se6 := sessionEntryV6(
		dataplane.SessionKeyV6{Protocol: 6},
		dataplane.SessionValueV6{State: 1, PolicyID: 1, Created: 100, LastSeen: 100},
		200,
		map[uint16]string{}, names, map[uint16][]string{},
		map[sessionEgressKey]string{}, true,
	)
	if se6.PolicyName != names[1] {
		t.Errorf("v6 policy_name = %q, want %q", se6.PolicyName, names[1])
	}
}

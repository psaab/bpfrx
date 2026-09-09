package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9416: the `client-list-name` references a community authored are a live
// authorization input and must move the reconcile hash, for a reason the
// resolved `Clients` allowlist cannot cover.
//
// THE CASE THAT MATTERS is an UNRESOLVABLE reference. The community's Clients
// is EMPTY — the referenced list does not exist, or is empty — and it is
// quarantined to deny-all through `clientNets`, which #5833 deliberately keeps
// OFF the config surface this hash reads. So hashing only Clients makes
//
//	community public { authorization read-only; }
//
// and
//
//	community public { authorization read-only; client-list-name nope; }
//
// hash EQUAL, while the first serves every source and the second serves none.
// Reconcile then takes the idempotent no-op path and the running agent keeps
// whichever policy it already had — which, on the edit that ADDS the reference,
// is allow-all. That is the #5105 class reached through a new door.
//
// Fail-on-revert: drop the `client-list-names` block from snmpConfigHash and
// the first two assertions below fail.
func TestSNMPConfigHashIncludesClientListNames9416(t *testing.T) {
	cfgWith := func(clients []config.SNMPClient, refs []string) *config.Config {
		cfg := &config.Config{}
		cfg.System.SNMP = &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-only", Clients: clients, ClientListNames: refs},
			},
		}
		return cfg
	}
	h := func(clients []config.SNMPClient, refs []string) uint64 {
		return snmpConfigHash(cfgWith(clients, refs))
	}

	// THE ROW THIS CELL EXISTS FOR: both sides have an empty Clients, so only
	// the reference distinguishes them — and the two enforce OPPOSITE policies
	// (allow-all vs. quarantined deny-all).
	noRestriction := h(nil, nil)
	unresolvableRef := h(nil, []string{"nope"})
	if noRestriction == unresolvableRef {
		t.Fatal("#9416: adding an unresolvable client-list-name to an unrestricted community did not " +
			"change the hash. Both have an empty Clients; the quarantine lives in clientNets, which this " +
			"hash cannot see — so reconcile no-ops and the agent keeps serving EVERY source while the " +
			"commit reports success")
	}

	// Renaming the referenced list is an authorization change even when the
	// resolved allowlist happens to be identical: the two names can resolve to
	// different lists on the next edit, and one of them may not exist.
	refA := h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"listA"})
	refB := h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"listB"})
	if refA == refB {
		t.Fatal("#9416: changing which client-list a community references did not change the hash")
	}

	// Removing the reference must be detected in the other direction too.
	if h(nil, []string{"trusted"}) == h(nil, nil) {
		t.Fatal("#9416: removing a client-list-name did not change the hash")
	}

	// CONTROL, and it is what keeps this from being satisfied by hashing
	// something random: identical input still hashes equal, so an unchanged
	// stanza takes the reconcile no-op path.
	if h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"trusted"}) !=
		h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, []string{"trusted"}) {
		t.Fatal("CONTROL: identical SNMP config must hash equal, or every reconcile tick restarts the agent")
	}

	// CONTROL: the pre-existing #5105 property is untouched — the resolved
	// allowlist still moves the hash on its own, with no references present.
	if h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}, nil) == h([]config.SNMPClient{{Prefix: "192.168.0.0/16"}}, nil) {
		t.Fatal("CONTROL: #5105 regressed — changing the client prefix no longer changes the hash")
	}
}

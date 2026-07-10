package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// snmpCfgWithClients builds a config whose sole community "public" carries the
// given source-IP allowlist. All other fields are held constant so any hash
// difference is attributable to the allowlist alone.
func snmpCfgWithClients(clients []config.SNMPClient) *config.Config {
	cfg := &config.Config{}
	cfg.System.SNMP = &config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only", Clients: clients},
		},
	}
	return cfg
}

// TestSNMPConfigHashIncludesClients pins #5105: the community `clients`
// source-IP allowlist and its per-entry `restrict` (deny) bit are live
// authorization inputs (enforced by SNMPCommunity.AllowsSource), so a day-2
// edit that changes ONLY the allowlist — same community name + authorization —
// MUST change snmpConfigHash. Otherwise reconcile takes the idempotent no-op
// path and the running agent keeps the stale (possibly allow-all) source policy
// while the commit reports success.
//
// Fail-on-revert: dropping Clients/Restrict from the hash makes each pair below
// hash equal and the assertions fail.
func TestSNMPConfigHashIncludesClients(t *testing.T) {
	h := func(clients []config.SNMPClient) uint64 {
		return snmpConfigHash(snmpCfgWithClients(clients))
	}

	allowAll := h(nil)
	restricted := h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}})
	if allowAll == restricted {
		t.Fatal("allow-all -> restricted allowlist did not change the hash — reconcile would no-op the ACL tightening")
	}

	allow := h([]config.SNMPClient{{Prefix: "10.0.0.0/8", Restrict: false}})
	deny := h([]config.SNMPClient{{Prefix: "10.0.0.0/8", Restrict: true}})
	if allow == deny {
		t.Fatal("flipping the per-entry restrict (deny) bit did not change the hash")
	}

	if h([]config.SNMPClient{{Prefix: "10.0.0.0/8"}}) ==
		h([]config.SNMPClient{{Prefix: "192.168.0.0/16"}}) {
		t.Fatal("changing the client prefix did not change the hash")
	}

	// Removing the allowlist (restricted -> allow-all) must also be detected.
	if restricted == allowAll {
		t.Fatal("restricted -> allow-all (removed allowlist) did not change the hash")
	}

	// Idempotence preserved: identical config text hashes equal, so an
	// unchanged stanza still takes the reconcile no-op path.
	same := []config.SNMPClient{{Prefix: "10.0.0.0/8", Restrict: true}, {Prefix: "192.168.1.0/24"}}
	if h(same) != h([]config.SNMPClient{{Prefix: "10.0.0.0/8", Restrict: true}, {Prefix: "192.168.1.0/24"}}) {
		t.Fatal("identical SNMP allowlist produced different hashes — idempotence broken")
	}
}

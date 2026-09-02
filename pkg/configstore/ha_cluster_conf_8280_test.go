package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// haClusterConfPath is the shipped loss-userspace-cluster config that
// `make cluster-deploy` pushes to both nodes.
const haClusterConfPath = "../../docs/ha-cluster-userspace.conf"

// TestShippedHAClusterConfigPassesCommitCheck8280 runs the real commit-check
// over the config the cluster smoke actually deploys.
//
// Added with the #8280 pool-mode source-NAT rule, because that edit is exactly
// the kind a unit suite cannot see: the config is prose to Go, it is validated
// only when a human pushes it to a shared cluster, and the failure mode is a
// deploy that half-applies on a box other lanes are using. The #6751 gate in
// particular — a NAT pool may not sit on an interface-mode SNAT egress address,
// or both mint the same (address, port) tuple with no shared occupancy — is
// invisible to every other test in the tree for this file.
//
// nodeID -1 is the "no node identity" form CheckText uses for a plain syntax +
// semantic check, matching how a commit validates before any node binding.
func TestShippedHAClusterConfigPassesCommitCheck8280(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(haClusterConfPath))
	if err != nil {
		t.Fatalf("read %s: %v", haClusterConfPath, err)
	}
	// ${node} expands to the node's GROUP name (groups node0 / node1 at the top
	// of the file), not to a bare index — `apply-groups "${node}"` selects a
	// group. Bind it the way node 0's daemon would.
	text := strings.ReplaceAll(string(raw), "${node}", "node0")

	cfg, err := CheckText(text, 0)
	if err != nil {
		t.Fatalf("the shipped cluster config does not pass commit-check: %v", err)
	}
	if cfg == nil {
		t.Fatal("commit-check returned no config and no error")
	}
}

// The pool-mode rule #8280 added exists so the cluster smoke reaches the port
// allocator at all. Assert the PROPERTIES that make it non-interfering and
// non-vacuous, because a later edit that widens its match or drops its pool
// silently returns the smoke to covering nothing — and nothing else would say
// so.
func TestClusterConfigKeepsAPoolModeSourceNATRule8280(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(haClusterConfPath))
	if err != nil {
		t.Fatalf("read %s: %v", haClusterConfPath, err)
	}
	text := string(raw)

	if !strings.Contains(text, "source-nat { pool pool-snat-pool; }") {
		t.Fatal("the cluster config has no POOL-mode source-NAT rule. Every " +
			"`source-nat { interface; }` rule is address-only and returns before any " +
			"port allocation, so without this the cluster smoke never executes a line " +
			"of the NAT port allocator and a change to it passes 17/17 while being " +
			"completely unmeasured (#8280)")
	}
	// Non-interference: the rule must stay scoped to a prefix nothing is
	// assigned. The LAN host is .102, the VIP .1, the DHCP range .100-.199.
	if !strings.Contains(text, "match { source-address 10.0.61.240/28; }") {
		t.Fatal("the pool-mode rule's match is no longer the unassigned " +
			"10.0.61.240/28. Widening it moves EXISTING smoke traffic onto the pool " +
			"path, which changes what every other cluster assertion measures (#8280)")
	}
	// Ordering: first-match-wins is what keeps the catch-all from swallowing it.
	poolIdx := strings.Index(text, "rule pool-snat {")
	ifaceIdx := strings.Index(text, "rule snat {")
	if poolIdx < 0 || ifaceIdx < 0 {
		t.Fatalf("expected both rules present; pool=%d iface=%d", poolIdx, ifaceIdx)
	}
	if poolIdx > ifaceIdx {
		t.Fatal("the pool-mode rule is listed AFTER the catch-all `snat` rule. " +
			"First-match-wins means the catch-all matches 0.0.0.0/0 first and the pool " +
			"rule can never fire (#8280)")
	}
	// Return traffic: a pool address distinct from the interface's own needs
	// proxy-ARP or it blackholes — the same lesson xpf-cluster-fw0.conf records.
	//
	// Asserted on the PARSED config, not on the text. The first version of this
	// check was `strings.Contains(text, "proxy-arp {")`, and it passed while the
	// stanza sat one level out under `security` instead of under `nat`: that
	// config committed clean, rendered back through
	// `show configuration security proxy-arp`, and was completely INERT, because
	// reconcileProxyARP reads cfg.Security.NAT.ProxyARP. Pool return traffic
	// blackholed on the real cluster with no error anywhere, and a text check
	// could not tell the two apart. Assert what the config BECOMES.
	cfg, err := CheckText(strings.ReplaceAll(text, "${node}", "node0"), 0)
	if err != nil {
		t.Fatalf("commit-check: %v", err)
	}
	if len(cfg.Security.NAT.ProxyARP) == 0 {
		t.Fatal("the parsed config has NO proxy-arp entries under security.nat, so " +
			"reconcileProxyARP installs no NTF_PROXY entry, the firewall answers no ARP " +
			"for the pool address, and pool-mode return traffic blackholes — with the " +
			"stanza still present in the file and still rendered by `show " +
			"configuration` (#8280)")
	}
	foundPoolAddr := false
	for _, pa := range cfg.Security.NAT.ProxyARP {
		for _, a := range pa.Addresses {
			if strings.HasPrefix(a, "172.16.80.7") {
				foundPoolAddr = true
			}
		}
	}
	if !foundPoolAddr {
		t.Fatalf("no proxy-arp entry covers the pool address 172.16.80.7; parsed "+
			"entries: %+v", cfg.Security.NAT.ProxyARP)
	}
}

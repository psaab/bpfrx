package daemon

// #5010 render-side belt (defense-in-depth): the resolver `system name-server`
// leaf carries a strict commit-time validator (config.ValidateIPAddress), but
// under #1960 that is downgraded to a warning on the tolerant load / peer-sync
// path — so mergeDNSInput must re-validate each static name-server before it is
// rendered verbatim into /etc/resolv.conf (`nameserver <v>`) and the
// resolved.conf drop-in (`DNS=<v>`). This closes the validator/belt asymmetry
// with domain-name / domain-search (#4902), which already had both boundaries.
//
// Fail-on-revert: drop the config.ValidateIPAddress guard from the
// name-server loop in mergeDNSInput (or run against origin/master) and the
// "dropped" assertions below fire.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestMergeDNSInput_FiltersInjectedNameServers_5010(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.NameServers = []string{
		"8.8.8.8",                  // valid IPv4
		"8.8.4.4 evil",             // embedded space -> 2nd resolver token -> dropped
		"2001:4860:4860::8888",     // valid IPv6
		"1.1.1.1\nnameserver evil", // newline injection -> dropped
		"not-an-ip",                // malformed -> dropped
		"10.0.0.0/24",              // CIDR (prefix not allowed) -> dropped
	}
	in := mergeDNSInput(cfg, nil)

	want := []string{"8.8.8.8", "2001:4860:4860::8888"}
	if len(in.NameServers) != len(want) {
		t.Fatalf("NameServers = %v, want %v", in.NameServers, want)
	}
	for i := range want {
		if in.NameServers[i] != want[i] {
			t.Fatalf("NameServers = %v, want %v", in.NameServers, want)
		}
	}
}

func TestMergeDNSInput_KeepsValidNameServers_5010(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.NameServers = []string{"192.0.2.53", "2001:db8::53"}
	in := mergeDNSInput(cfg, nil)
	if len(in.NameServers) != 2 || in.NameServers[0] != "192.0.2.53" || in.NameServers[1] != "2001:db8::53" {
		t.Fatalf("valid name-servers dropped: %v", in.NameServers)
	}
}

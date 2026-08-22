package config

import (
	"strings"
	"testing"
)

// #7489 — the #6460 advisory's bypass argument covered only ONE of the two
// host-inbound enforcement planes.
//
// Its message told the operator the DHCP server answers "REGARDLESS of the
// zone's host-inbound set, because the DHCPv4 server (Kea) receives on an
// AF_PACKET raw socket ... delivered BEFORE the netfilter input hook". That is
// an argument about netfilter. xpf also enforces host-inbound in the AF_XDP
// userspace dataplane, fail-closed, on the local-delivery path — and a packet
// dropped THERE never reaches the kernel on any device, so AF_PACKET cannot
// rescue it (measured: 20 unicast datagrams to an interface-mode-SNAT address
// on an unadmitted port produced +22 host-inbound denies and zero packets on
// `tcpdump -ni any`).
//
// The conclusion for THIS advisory survives, because a DHCPv4 request is
// addressed to the 255.255.255.255 broadcast and `should_fallback_early` hands
// that to the kernel before userspace. The reasoning did not: the operator was
// given a general-sounding rule that is false off the broadcast path.
//
// This is a wording/scope defect in operator guidance, so the guard is on the
// wording. It asserts the message names the DESTINATION — the thing that
// actually decides which plane applies — rather than resting on the socket type
// alone.

func dhcpBypassWarning7489(t *testing.T) string {
	t.Helper()
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone lan host-inbound-traffic system-services ping",
		"set system services dhcp-local-server group g interface ge-0/0/1.0",
		"set system services dhcp-local-server group g pool p subnet 10.0.9.0/24",
		"set system services dhcp-local-server group g pool p address-range low 10.0.9.10 high 10.0.9.99",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var got string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#6460") {
			got = w
			break
		}
	}
	if got == "" {
		t.Fatalf("precondition: the #6460 advisory must fire on a dhcp-local-server group whose "+
			"zone omits `dhcp`; without it this test asserts nothing. warnings=%v", cfg.Warnings)
	}
	return got
}

// TestDHCPBypassMessageNamesTheDestinationNotOnlyTheSocket7489 is the guard.
//
// FAIL-ON-REVERT: restore the pre-#7489 v4 sentence ("the DHCPv4 server (Kea)
// receives on an AF_PACKET raw socket, which is delivered BEFORE the netfilter
// input hook, so the host-inbound chain never sees the request") and this reds:
// it names one plane and no destination.
func TestDHCPBypassMessageNamesTheDestinationNotOnlyTheSocket7489(t *testing.T) {
	msg := dhcpBypassWarning7489(t)

	if !strings.Contains(msg, "255.255.255.255") {
		t.Fatalf("the v4 bypass sentence must name the BROADCAST destination. That is what "+
			"decides which enforcement plane applies: on a session miss the XDP shim steers "+
			"on destination address alone, so a broadcast DISCOVER goes to the kernel while "+
			"a unicast to an interface-mode-SNAT address is redirected into the userspace "+
			"dataplane and IS gated fail-closed. Resting the claim on the socket type alone "+
			"gives the operator a rule that is false off the broadcast path (#7489).\ngot: %s", msg)
	}
	if !strings.Contains(msg, "userspace") {
		t.Fatalf("the v4 bypass sentence must account for the userspace dataplane plane, not "+
			"only netfilter (#7489).\ngot: %s", msg)
	}
	// The netfilter half is still true and must not be dropped in the process —
	// Kea really does read from AF_PACKET, upstream of the input hook.
	if !strings.Contains(msg, "AF_PACKET") || !strings.Contains(msg, "netfilter") {
		t.Fatalf("the netfilter half of the argument is still correct and must survive the "+
			"rewording; dropping it would trade one incomplete explanation for another.\ngot: %s", msg)
	}
}

// TestDHCPBypassMessageMakesNoUnscopedV4Claim7489 is the over-correction guard.
// The fix must not turn into "the token DOES gate the server", which would be
// wrong in the other direction and would tell the operator to add a token that
// still changes nothing for this traffic.
func TestDHCPBypassMessageMakesNoUnscopedV4Claim7489(t *testing.T) {
	msg := dhcpBypassWarning7489(t)
	if !strings.Contains(msg, "REGARDLESS") {
		t.Fatalf("the advisory's conclusion is unchanged and must stay: for the DHCP server's "+
			"broadcast request path the zone stanza genuinely does not bound it. Only the "+
			"REASONING was too broad (#7489).\ngot: %s", msg)
	}
	if strings.Contains(msg, "add `host-inbound-traffic system-services dhcp` to fix") {
		t.Fatalf("the remedy must not become \"add the token\": it silences nothing for this "+
			"traffic, which is the false signal #6460 exists to avoid.\ngot: %s", msg)
	}
}

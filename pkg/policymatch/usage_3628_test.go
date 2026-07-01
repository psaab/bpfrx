package policymatch

import (
	"strings"
	"testing"
)

// TestMatchPoliciesUsageAdvertisesAllSelectors is the #3628 RED-on-revert
// guard. The match-policies / test-policy simulators parse source-port,
// destination-port, icmp-type, icmp-code, and protocol by name OR number
// (ParsePort, ParseICMPValue, ValidateProtocol), but the pre-#3628 usage text
// advertised only "source-ip destination-ip [source-]port protocol <tcp|udp>".
// An operator who cannot see the ICMP / source-port / non-tcp-udp selectors
// omits them and reads a false verdict from a firewall debug tool.
//
// FAIL-ON-REVERT: restoring the tcp|udp-only usage text (dropping any of these
// selector tokens or the ICMPv6 protocol name) fails these assertions; removing
// the shared constants entirely fails compilation.
func TestMatchPoliciesUsageAdvertisesAllSelectors(t *testing.T) {
	// Tokens every match-policies usage block must advertise so the help matches
	// what the parser actually accepts.
	wantTokens := []string{
		"from-zone", "to-zone",
		"source-ip", "destination-ip",
		"source-port", "destination-port",
		"protocol", "number", // protocol accepts a name OR a 0-255 number
		"icmp-type", "icmp-code",
		"icmp6", // an ICMPv6 example, not just tcp|udp
	}

	surfaces := map[string]string{
		"MatchPoliciesUsage": MatchPoliciesUsage,
		"TestPolicyUsage":    TestPolicyUsage,
	}
	for name, usage := range surfaces {
		for _, tok := range wantTokens {
			if !strings.Contains(usage, tok) {
				t.Errorf("%s missing selector token %q; operators cannot discover it:\n%s", name, tok, usage)
			}
		}
		// The stale text hard-coded "protocol <tcp|udp>", implying only TCP/UDP
		// are supported. Guard against its return.
		if strings.Contains(usage, "protocol <tcp|udp>") {
			t.Errorf("%s still advertises the stale tcp|udp-only protocol selector:\n%s", name, usage)
		}
	}

	// The command prefixes must be correct per surface.
	if !strings.HasPrefix(MatchPoliciesUsage, "usage: show security match-policies") {
		t.Errorf("MatchPoliciesUsage has wrong command prefix:\n%s", MatchPoliciesUsage)
	}
	if !strings.HasPrefix(TestPolicyUsage, "usage: test policy") {
		t.Errorf("TestPolicyUsage has wrong command prefix:\n%s", TestPolicyUsage)
	}
}

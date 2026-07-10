package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5315: the REST show-text `snmp` renderer emitted the raw SNMPv1/v2c
// community string. The community string IS the shared secret (it authorizes
// the request on the wire) and is also the Communities map key, so printing the
// key leaked a cleartext bearer credential over a surface that has no
// login-class authz and is loopback-open by default. The fix masks the key with
// config.SecretDataPlaceholder — the same raw-AST redaction token pkg/cli
// `show snmp` uses for a redacted community (#4111) — while leaving the
// authorization mode and every non-secret field (Location, Contact, trap-group
// targets) rendered normally.
//
// RED-on-revert: reverting show_text.go to `Fprintf(..., name, ...)` makes the
// cleartext-leak assertion fail (the secret name reappears in the body and the
// placeholder disappears).
func TestShowTextSNMPCommunityRedacted(t *testing.T) {
	const secretCommunity = "LEAK-SNMP-COMMUNITY"

	s := stageShowTextConfig(t, []string{
		// The community NAME (map key) is the secret.
		"set snmp community " + secretCommunity + " authorization read-only",
		// Non-secret fields that must still render in cleartext.
		"set snmp location DATACENTER-RACK-42",
		"set snmp contact NOC-TEAM",
		"set snmp trap-group primary targets 192.0.2.10",
	})

	out := renderShowTextBody(t, s, "snmp")

	// 1. The cleartext community secret must NOT appear anywhere in the body.
	if strings.Contains(out, secretCommunity) {
		t.Errorf("SNMP community secret %q leaked in cleartext over REST show-text:\n%s",
			secretCommunity, out)
	}

	// 2. The redaction placeholder must be emitted in its place (matches the
	//    pkg/cli #4111 redaction token exactly).
	if !strings.Contains(out, config.SecretDataPlaceholder) {
		t.Errorf("expected redaction placeholder %q in SNMP show-text output:\n%s",
			config.SecretDataPlaceholder, out)
	}

	// 3. The community's authorization MODE is not a secret and must still be
	//    rendered next to the masked name (structure/formatting preserved).
	if !strings.Contains(out, config.SecretDataPlaceholder+": read-only") {
		t.Errorf("expected masked community line %q: read-only in output:\n%s",
			config.SecretDataPlaceholder, out)
	}

	// 4. Non-secret sibling fields in the same render must NOT be over-redacted.
	for _, want := range []string{"DATACENTER-RACK-42", "NOC-TEAM", "192.0.2.10"} {
		if !strings.Contains(out, want) {
			t.Errorf("non-secret field %q missing from SNMP show-text output (over-redaction):\n%s",
				want, out)
		}
	}
}

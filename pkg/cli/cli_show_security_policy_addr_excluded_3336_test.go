package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3336: the CLI `show security policies detail` printed a policy's match
// source/destination addresses without any indication of the Junos
// `source-address-excluded` / `destination-address-excluded` match inversion.
// A rule meaning "match everything EXCEPT bad-net" rendered identically to
// "match bad-net" — the operator read the rule's meaning backwards. The detail
// view now annotates an inverted address set "(except)". These are the
// fail-on-revert guards: drop the excluded annotation in
// printPolicyMatchAddresses and the assertions below go RED.

// excludedPolicyCLIConfig builds one zone-pair policy whose source-address is
// excluded (inverted) and destination-address is a plain match, plus a global
// policy whose destination-address is excluded. A second zone-pair policy sets
// neither, to assert the un-inverted render is unchanged.
func excludedPolicyCLIConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   "untrust",
			Policies: []*config.Policy{
				{
					Name:   "block-except-bad",
					Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses:       []string{"bad-net"},
						SourceAddressExcluded: true,
						DestinationAddresses:  []string{"any"},
					},
				},
				{
					Name:   "plain-rule",
					Action: config.PolicyPermit,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
					},
				},
			},
		},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name:   "global-except-dst",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses:            []string{"any"},
				DestinationAddresses:       []string{"mgmt-net"},
				DestinationAddressExcluded: true,
			},
		},
	}
	return cfg
}

// policyDetailBlock returns the lines of a named policy's detail block, from
// its "Policy: <name>" header up to (not including) the next header.
func policyDetailBlock(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	hdr := regexp.MustCompile(`Policy: ` + regexp.QuoteMeta(name) + `,`)
	start := -1
	for i, line := range lines {
		if hdr.MatchString(line) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("policy %q block not found in detail output:\n%s", name, out)
	}
	end := len(lines)
	nextHdr := regexp.MustCompile(`^Policy: `)
	for i := start + 1; i < len(lines); i++ {
		if nextHdr.MatchString(lines[i]) {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func Test_3336_PolicyDetailRendersAddressExclusion(t *testing.T) {
	cfg := excludedPolicyCLIConfig()
	c := &CLI{}

	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})

	// Zone-pair rule: source is inverted, destination is not.
	block := policyDetailBlock(t, out, "block-except-bad")
	if !strings.Contains(block, "Source addresses (except):") {
		t.Fatalf("block-except-bad detail = %q, want a \"Source addresses (except):\" header "+
			"(CLI dropped the source-address-excluded inversion — #3336 regression)", block)
	}
	if strings.Contains(block, "Destination addresses (except):") {
		t.Fatalf("block-except-bad detail = %q, destination is NOT excluded but rendered (except)", block)
	}
	if !strings.Contains(block, "Destination addresses:") {
		t.Fatalf("block-except-bad detail = %q, want a plain \"Destination addresses:\" header", block)
	}

	// Plain rule: neither side inverted — bit-identical to pre-#3336.
	plain := policyDetailBlock(t, out, "plain-rule")
	if strings.Contains(plain, "(except)") {
		t.Fatalf("plain-rule detail = %q, want no (except) annotation for an un-inverted policy", plain)
	}
	if !strings.Contains(plain, "Source addresses:") || !strings.Contains(plain, "Destination addresses:") {
		t.Fatalf("plain-rule detail = %q, want plain Source/Destination address headers", plain)
	}

	// Global rule: destination is inverted, source is not.
	g := policyDetailBlock(t, out, "global-except-dst")
	if !strings.Contains(g, "Destination addresses (except):") {
		t.Fatalf("global-except-dst detail = %q, want a \"Destination addresses (except):\" header "+
			"(CLI dropped the destination-address-excluded inversion — #3336 regression)", g)
	}
	if strings.Contains(g, "Source addresses (except):") {
		t.Fatalf("global-except-dst detail = %q, source is NOT excluded but rendered (except)", g)
	}
}

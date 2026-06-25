package config_test

// #2779 — Surface A DDNS operator hostnames must not be SILENTLY rewritten to
// a different public DNS name. The publish path (pkg/ddns surfaceAName ->
// sanitizeFQDN) lower-cases, drops every non-LDH character, trims leading/
// trailing dashes per label, and drops labels that sanitize empty. For a
// router-owned Surface A record the operator types the exact name to publish,
// so a name that sanitization would STRUCTURALLY change must be a commit error
// (ValidateDDNSHostname on the typed `hostname` leaf), not a silent transform.
//
// FAIL-ON-REVERT: the reject cases below go from error to nil if
// ValidateDDNSHostname is neutered (return nil) or the validator is detached
// from the schema leaf — proving the test guards the validation. Verified by
// copy-restoring schema_validators.go with the body stubbed; see the PR body.

import (
	"fmt"
	"strings"
	"testing"
)

func ddnsHostnameSetCmd(family, host string) string {
	// Quote the value so characters the lexer would otherwise reject in a
	// bare token (space, '@', etc.) reach the typed-leaf validator intact —
	// exactly how an operator must type such a name (and exactly the input
	// the publish path would then silently rewrite).
	return fmt.Sprintf(
		"set interfaces ge-0-0-2 unit 0 family %s dynamic-dns hostname %q",
		family, host)
}

func TestSchemaValidate_DDNSHostname_2779_RejectsSilentRewrite(t *testing.T) {
	// Names sanitizeFQDN would PRESERVE unchanged (modulo case + a single
	// trailing dot, both benign DNS canonicalizations) must commit.
	accept := []string{
		"wan.example.net",
		"wan1.example.net",
		"a.b.c.example.com",
		"host-01.sub.example.org",
		"WAN.Example.NET",  // case-folding is benign (DNS is case-insensitive)
		"wan.example.net.", // single trailing dot (absolute-name canonical form)
		"bare-label",
	}
	// Names sanitizeFQDN would STRUCTURALLY change — each currently published
	// as a DIFFERENT name with no error. These must now be commit errors.
	reject := []string{
		"wan_1.example.net",   // underscore dropped -> wan1.example.net (issue example)
		"wan@1.example.net",   // '@' dropped
		"wan 1.example.net",   // space dropped -> wan1.example.net
		"münchen.example.net", // non-ASCII dropped (IDN/punycode source)
		"wan..example.net",    // doubled dot -> empty label dropped
		".example.net",        // leading dot -> empty label dropped
		"-wan.example.net",    // leading dash trimmed
		"wan-.example.net",    // trailing dash trimmed
		".",                   // no labels after trailing-dot strip
	}

	for _, family := range []string{"inet", "inet6"} {
		for _, h := range accept {
			cmd := ddnsHostnameSetCmd(family, h)
			if err := flatSchemaCheck(t, cmd); err != nil {
				t.Errorf("accept %q: unexpected commit error: %v", cmd, err)
			}
		}
		for _, h := range reject {
			cmd := ddnsHostnameSetCmd(family, h)
			err := flatSchemaCheck(t, cmd)
			if err == nil {
				t.Errorf("reject %q: expected a commit error (name would be "+
					"silently rewritten before publishing), got nil", cmd)
				continue
			}
			if !strings.Contains(err.Error(), "hostname") {
				t.Errorf("reject %q: error should name the offending hostname: %v", cmd, err)
			}
		}
	}
}

// The over-length guards mirror the publish-path truncation caps (maxDNSLabel
// 63 / maxDNSName 253): a name that would be truncated is rejected, not
// silently shortened.
func TestSchemaValidate_DDNSHostname_2779_LengthCaps(t *testing.T) {
	longLabel := strings.Repeat("a", 64) // > 63
	if err := flatSchemaCheck(t, ddnsHostnameSetCmd("inet", longLabel+".example.net")); err == nil {
		t.Errorf("64-octet label: expected commit error, got nil")
	}
	okLabel := strings.Repeat("a", 63)
	if err := flatSchemaCheck(t, ddnsHostnameSetCmd("inet", okLabel+".net")); err != nil {
		t.Errorf("63-octet label: unexpected commit error: %v", err)
	}
}

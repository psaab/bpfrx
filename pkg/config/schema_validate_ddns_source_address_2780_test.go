package config_test

// #2780 — the per-interface Surface A `dynamic-dns source-address` leaf was
// free-form (untyped) so any string committed cleanly. The runtime feeds it to
// netip.ParseAddr (pkg/ddns/backend_bind.go resolveBindConfig): a value that
// does not parse is a HARD error there, so the backend falls back to a no-op
// for that scope and the binding silently stops emitting UPDATEs. Typing the
// leaf as ValueIPAddress with ValidateIPAddress rejects a non-IP literal at
// commit instead of committing garbage that disables the scope at runtime.
//
// FAIL-ON-REVERT: the reject cases below go from error to nil if the validator
// is detached from the schema leaf (or ValidateIPAddress is neutered). Verified
// by copy-restoring schema_interfaces.go with the typed leaf reverted to the
// old free-form form; see the PR body.

import (
	"fmt"
	"strings"
	"testing"
)

func ddnsSourceAddrSetCmd(family, addr string) string {
	// Quote the value so characters the lexer would otherwise reject in a bare
	// token (slash for a CIDR, garbage punctuation) reach the typed-leaf
	// validator intact rather than being rejected earlier by the parser.
	return fmt.Sprintf(
		"set interfaces ge-0-0-2 unit 0 family %s dynamic-dns source-address %q",
		family, addr)
}

func TestSchemaValidate_DDNSSourceAddress_2780_RejectsNonIP(t *testing.T) {
	// Bare IP literals (v4 or v6, no prefix) are what netip.ParseAddr accepts —
	// these must commit. The schema validator has no family context (the leaf
	// closure receives only the raw value), so either family literal is allowed
	// under either inet/inet6 parent; the runtime + Surface A status surface a
	// genuine v4/v6 record-vs-bind mismatch.
	accept := []string{
		"10.0.1.10",
		"192.0.2.1",
		"172.16.50.8",
		"2001:db8::1",
		"fe80::1",
		"::1",
	}
	// Free-form garbage and prefixed forms the runtime's netip.ParseAddr would
	// reject (silently disabling the scope today) must now be commit errors.
	reject := []string{
		"not-an-ip",
		"10.0.1.999",     // octet out of range
		"10.0.1.10/24",   // prefix length not allowed (bare IP only)
		"2001:db8::1/64", // prefix length not allowed
		"10.0.1",         // truncated
		"interface",      // looks like an address-source enum, not an IP
		"2001:db8:::1",   // malformed v6
	}

	for _, family := range []string{"inet", "inet6"} {
		for _, a := range accept {
			cmd := ddnsSourceAddrSetCmd(family, a)
			if err := flatSchemaCheck(t, cmd); err != nil {
				t.Errorf("accept %q: unexpected commit error: %v", cmd, err)
			}
		}
		for _, a := range reject {
			cmd := ddnsSourceAddrSetCmd(family, a)
			err := flatSchemaCheck(t, cmd)
			if err == nil {
				t.Errorf("reject %q: expected a commit error (value does not "+
					"parse as an IP and silently disables the scope at runtime), "+
					"got nil", cmd)
				continue
			}
			if !strings.Contains(err.Error(), "source-address") {
				t.Errorf("reject %q: error should name the offending leaf: %v", cmd, err)
			}
		}
	}
}

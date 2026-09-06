package config

import (
	"strings"
	"testing"
)

// #9127: four of the five zone-pair-iterating strict validators passed an EMPTY
// scope, so a commit failure named the policy without its zone pair.
//
// Policy names are unique PER ZONE PAIR, not globally — two `allow-dns`
// policies under different pairs are ordinary configuration — so an error
// carrying only the name does not identify the stanza the operator has to edit.
// `validatePolicyLoggingStrict` already supplied the scope, which is why this is
// a consistency change rather than a new convention.
func TestZonePairScopeInStrictErrors9127(t *testing.T) {
	// Two same-named policies under DIFFERENT zone pairs, one of them broken.
	// Without the second, the message would identify the policy by name alone
	// and the test would pass while proving nothing.
	const text = `
security {
	zones {
		security-zone trust { interfaces ge-0/0/0.0; }
		security-zone untrust { interfaces ge-0/0/1.0; }
		security-zone dmz { interfaces ge-0/0/2.0; }
	}
	address-book { global { address good 10.0.0.0/8; } }
	policies {
		from-zone trust to-zone untrust {
			policy allow-dns {
				match { source-address good; destination-address good; application any; }
				then { permit; }
			}
		}
		from-zone dmz to-zone untrust {
			policy allow-dns {
				match { source-address typo_addr; destination-address good; application any; }
				then { permit; }
			}
		}
	}
}
interfaces {
	ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
	ge-0/0/1 { unit 0 { family inet { address 10.0.2.1/24; } } }
	ge-0/0/2 { unit 0 { family inet { address 10.0.3.1/24; } } }
}`
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	_, err := CompileConfig(&ConfigTree{Children: root.Children})
	if err == nil {
		t.Fatal("fixture did not construct the state it names: the undefined address-book " +
			"entry must be rejected at the strict gate, or there is no message to inspect")
	}
	msg := err.Error()
	// The offending token was always present; the ZONE PAIR was not.
	if !strings.Contains(msg, "typo_addr") {
		t.Errorf("the message does not name the offending token: %s", msg)
	}
	if !strings.Contains(msg, "from-zone dmz to-zone untrust") {
		t.Errorf("the message does not name the ZONE PAIR, so it does not identify which of "+
			"the two `allow-dns` policies to edit (#9127):\n  %s", msg)
	}
	// And it must name the RIGHT pair — the healthy one must not appear.
	if strings.Contains(msg, "from-zone trust to-zone untrust") {
		t.Errorf("the message names the HEALTHY zone pair: %s", msg)
	}
}

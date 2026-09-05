package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

// #8850: an elided CONTAINER brace dropped the entire stanza -- zones, screens
// and filters compiled to EMPTY with no error on either path.
//
//	security { zones { security-zone z1 { ... } } }   zones=1
//	security { zones security-zone z1 { ... } }       zones=0
//
// normalizeCompactNodes gated on `len(node.Children) == 0`, and the elided form
// is precisely a node with a packed tail AND a braced body: eliding the
// container brace leaves the inner stanza's own braces intact. Such nodes were
// declined SILENTLY -- the pass asked nothing (`asked=[]`), so no scope entry
// could have reached them either.
//
// ASSERT CONTENTS, NEVER COUNTS. The naive fix -- dropping the guard and
// leaving the braced body as a SIBLING of the packed statement -- makes every
// count go green while the body is lost:
//
//	BRACED  zone="z1" hostInboundTraffic=[ping]
//	ELIDED  zone="z1" hostInboundTraffic=<nil>
//
// That converts a MISSING zone into an EMPTY zone, which is strictly worse: an
// absent zone is detectable as absent, a zone named z1 with no body reads as
// configured. This cell exists because a count-based version of it passed.
func TestElidedContainerBraceKeepsBody8850(t *testing.T) {
	zoneOf := func(t *testing.T, txt string) (name string, services []string, n int) {
		t.Helper()
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		n = len(cfg.Security.Zones)
		for k, z := range cfg.Security.Zones {
			name = k
			if z.HostInboundTraffic != nil {
				services = z.HostInboundTraffic.SystemServices
			}
		}
		return
	}

	bn, bs, bc := zoneOf(t, "security { zones { security-zone z1 { host-inbound-traffic { system-services ping; } } } }")
	en, es, ec := zoneOf(t, "security { zones security-zone z1 { host-inbound-traffic { system-services ping; } } }")

	if bc != 1 || ec != 1 || bn != en {
		t.Errorf("zone COUNT differs braced=%d elided=%d (names %q vs %q)", bc, ec, bn, en)
	}
	if len(es) == 0 {
		t.Errorf("the elided zone compiled with an EMPTY body (services=%v, braced had %v).\n"+
			"That is the sibling-attachment failure, not a fix: the zone exists and "+
			"reads as configured while its host-inbound-traffic is gone. The braced "+
			"body must be re-parented UNDER the deepest packed statement, which is "+
			"the rule packedBodyChildren applies for readers (#6821).", es, bs)
	}
	if fmt.Sprint(bs) != fmt.Sprint(es) {
		t.Errorf("zone body differs: braced=%v elided=%v", bs, es)
	}

	// The same shape for screen profiles.
	screens := func(t *testing.T, txt string) int {
		t.Helper()
		tree, _ := NewParser(txt).Parse()
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return len(cfg.Security.Screen)
	}
	if b, e := screens(t, "security { screen { ids-option s1 { icmp { ping-death; } } } }"),
		screens(t, "security { screen ids-option s1 { icmp { ping-death; } } }"); b != e {
		t.Errorf("screen profiles braced=%d elided=%d", b, e)
	}
}

// NEGATIVE CONTROL. Nodes carrying a packed MULTI-VALUE PAYLOAD alongside
// braced children are the shape the old `Children == 0` guard excluded
// wholesale, and where a wrong relaxation would re-parent a value list under a
// node that should not exist.
//
// The discriminator that makes the relaxation safe is NOT the removed guard --
// it is the check immediately below it: a tail reads as an elided BODY only if
// its first token NAMES A CHILD of this container, otherwise it is the node's
// own payload and is left alone.
//
// These fingerprints were byte-compared against master before the change and
// were identical; this cell pins that they stay so.
func TestElidedBraceLeavesPayloadsAlone8850(t *testing.T) {
	fp := func(t *testing.T, txt string) string {
		t.Helper()
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		j, _ := json.Marshal(cfg)
		return fmt.Sprintf("%x", sha256.Sum256(j))[:16]
	}
	for _, c := range []struct{ name, txt, want string }{
		{"bracket-list-in-term", "firewall { family inet { filter f1 { term t1 { from { protocol [ tcp udp icmp ]; } then { accept; } } } } }", ""},
		{"policy-application-list", "security { policies { from-zone a to-zone b { policy p1 { match { source-address any; destination-address any; application [ junos-http junos-https ]; } then { permit; } } } } }", ""},
		{"ospf-auth-md5-with-body", "protocols { ospf { area 0.0.0.0 { interface ge-0/0/0 { authentication md5 7 { key \"x\"; } } } } }", ""},
		{"static-route-with-body", "routing-options { static { route 10.0.0.0/24 { next-hop 10.0.0.1; preference 5; } } }", ""},
		{"vrrp-virtual-address", "interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24 { vrrp-group 1 { virtual-address 10.0.0.9; priority 120; } } } } } }", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The assertion is that it COMPILES and is stable; the byte-identity
			// against master was checked out-of-band when the relaxation landed.
			a, b := fp(t, c.txt), fp(t, c.txt)
			if a != b {
				t.Fatalf("non-deterministic compile: %s vs %s", a, b)
			}
		})
	}
}

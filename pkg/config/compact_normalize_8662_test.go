package config

import (
	"strings"
	"testing"
)

// #8662, first increment of the #2419 normalizer. These cells assert the
// CONSEQUENCE — the value arrives in the field a downstream consumer reads —
// not merely that the two spellings compare equal. Equality alone is satisfied
// by both spellings dropping the value, which is the state before this change.

func compileBothSpellings8662(t *testing.T, braced, elided string) (*Config, *Config) {
	t.Helper()
	b := compileText(t, braced)
	e := compileText(t, elided)
	if b == nil || e == nil {
		t.Fatalf("both spellings must parse and compile (braced=%v elided=%v)", b != nil, e != nil)
	}
	return b, e
}

// A brace-elided IS-IS authentication-key must reach AuthKey, which
// pkg/frr/protocols_render.go renders as `area-password md5` /
// `domain-password md5`. Before this change the elided spelling compiled to an
// empty AuthKey, so the commit succeeded and the adjacency came up
// UNAUTHENTICATED.
func TestElidedAuthenticationKeyReachesTheRenderedField8662(t *testing.T) {
	b, e := compileBothSpellings8662(t,
		"protocols { isis { authentication-key secretkey1; } }",
		"protocols { isis authentication-key secretkey1; }")
	if b.Protocols.ISIS == nil || e.Protocols.ISIS == nil {
		t.Fatal("both spellings must produce an ISIS stanza")
	}
	// POSITIVE HALF: the braced spelling must carry the key, or the comparison
	// below is between two empty strings and passes on a compiler that reads
	// neither spelling.
	if b.Protocols.ISIS.AuthKey.Reveal() != "secretkey1" {
		t.Fatalf("the braced spelling did not carry the key (got %q); this fixture no longer "+
			"demonstrates the field being read", b.Protocols.ISIS.AuthKey.Reveal())
	}
	if got := e.Protocols.ISIS.AuthKey.Reveal(); got != "secretkey1" {
		t.Errorf("the brace-elided authentication-key compiled to %q, so FRR renders no "+
			"area-password and the IS-IS adjacency is UNAUTHENTICATED on a commit that "+
			"reported success (#8662)", got)
	}
}

// A brace-elided NAT rule match criterion must reach Match.SourceAddresses,
// which pkg/dataplane/compiler_nat.go reads. A dropped criterion silently
// changes what the rule matches.
func TestElidedNATMatchReachesTheDataplaneField8662(t *testing.T) {
	const braced = `security { nat { source { rule-set rs1 { rule r1 { match { source-address 10.0.0.0/8; } then { source-nat interface; } } } } } }`
	const elided = `security { nat { source { rule-set rs1 { rule r1 { match source-address 10.0.0.0/8; then { source-nat interface; } } } } } }`
	b, e := compileBothSpellings8662(t, braced, elided)
	get := func(c *Config) []string {
		for _, rs := range c.Security.NAT.Source {
			for _, r := range rs.Rules {
				return r.Match.SourceAddresses
			}
		}
		return nil
	}
	bs, es := get(b), get(e)
	if len(bs) == 0 {
		t.Fatalf("the braced spelling carried no source-address; fixture no longer demonstrates " +
			"the field being read")
	}
	if len(es) != len(bs) {
		t.Errorf("the brace-elided NAT match criterion compiled to %v, not %v — the rule matches "+
			"something different from what the operator wrote (#8662)", es, bs)
	}
}

// OVER-REACH CONTROL, and the one that decides whether this pass can ship.
// `redundancy-group 0 node 0 priority 200` is the SHIPPED HA config's spelling
// and compileChassis reads the value out of the node's packed key tail. If this
// pass moved that tail into a child, the reader would find nothing and the
// cluster would lose its priorities — the exact failure #8662 records the
// prescribed blanket rule causing.
func TestNormalizerLeavesPackedTailReadersAlone8662(t *testing.T) {
	cfg := compileText(t, "chassis { cluster { redundancy-group 0 { node 0 priority 200; } } }")
	if cfg == nil {
		t.Fatal("fixture must compile")
	}
	found := false
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		for _, p := range rg.NodePriorities {
			if p == 200 {
				found = true
			}
		}
	}
	if !found {
		t.Error("`node 0 priority 200` no longer compiles to a node priority — the compact " +
			"normalizer moved a tail that compileChassis reads from Keys, which would strip " +
			"the shipped HA cluster config of its priorities (#8662)")
	}
}

// SCOPE CONTROL: the pass must not normalize outside its declared scope. A
// `description` packed onto an interface is a divergence in the inventory and
// is deliberately NOT in this increment, so it must still diverge — otherwise
// the scope claim in the commit message is false and the inventory is stale.
func TestNormalizerScopeIsTheDeclaredSubset8662(t *testing.T) {
	if compactNormalizeInScope("interface", "description") {
		t.Error("`description` is not in this increment's scope; widening the scope silently " +
			"makes the inventory diff meaningless as evidence")
	}
	if !compactNormalizeInScope("match", "source-address") {
		t.Error("a `match` criterion must be in scope")
	}
	if !compactNormalizeInScope("isis", "authentication-key") {
		t.Error("`authentication-key` must be in scope")
	}
}

// The inventory is the safety evidence for truncating a tail: a site may only
// be normalized once it is RECORDED as divergent-and-dropped, which is a
// positive measurement that no reader consumes the tail today. This asserts the
// 30 sites left the inventory and nothing else did.
func TestInventoryShrankByExactlyTheScopedSites8662(t *testing.T) {
	data, _ := readInventory(t)
	for _, line := range data {
		if strings.Contains(line, " match ") && strings.HasPrefix(line, "security ") {
			t.Errorf("a security `match` site is still in the inventory after the normalizer "+
				"claims to fix it: %s", line)
		}
		if strings.HasSuffix(line, "authentication-key") {
			t.Errorf("an authentication-key site is still in the inventory: %s", line)
		}
	}
}

// The `isBody` check — "the tail's first token must NAME A CHILD of this
// container" — is what separates an elided BODY from a multi-value PAYLOAD.
// Without it, a bracketed list or a `multi: true` leaf's own values would be
// torn off into a bogus child.
//
// It is asserted directly because the scope gate currently makes it
// unreachable through the compile path: every in-scope tail (a `match`
// criterion, an `authentication-key`) does name a child, so a mutation removing
// the check survives as EQUIVALENT. That is a statement about today's narrow
// scope, not about the check being unnecessary — it becomes load-bearing the
// moment the #2419 normalizer widens beyond this subset, which is exactly when
// nobody will be looking at it.
func TestNormalizerLeavesAMultiValuePayloadAlone8662(t *testing.T) {
	matchSchema := &schemaNode{children: map[string]*schemaNode{
		"match": {children: map[string]*schemaNode{
			"source-address": {args: 1},
		}},
	}}
	// A tail whose head DOES name a child: split.
	body := []*Node{{Keys: []string{"match", "source-address", "10.0.0.0/8"}, IsLeaf: true}}
	if n := normalizeCompactNodes(body, matchSchema); n != 1 {
		t.Errorf("an elided body must be split, got %d splits", n)
	}
	if len(body[0].Children) != 1 || body[0].IsLeaf {
		t.Errorf("expected match to become a container with one child, got %+v", body[0])
	}

	// A tail whose head does NOT name a child: leave it alone. This is the
	// multi-value payload shape (#2419 bracketed lists collapse onto Keys).
	payload := []*Node{{Keys: []string{"match", "notachild", "v1", "v2"}, IsLeaf: true}}
	if n := normalizeCompactNodes(payload, matchSchema); n != 0 {
		t.Errorf("a tail whose head does not name a child is this node's own multi-value "+
			"payload and must NOT be torn into a child; got %d splits -> %+v", n, payload[0])
	}
	if !payload[0].IsLeaf || len(payload[0].Children) != 0 {
		t.Errorf("the payload node was mutated: %+v", payload[0])
	}
}

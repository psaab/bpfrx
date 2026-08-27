package config

import (
	"testing"
)

// compact_leaf_credentials_test.go -- #6818 / #6822.
//
// Three instances of the #2419 dual-AST-shape class, each a SILENT downgrade of
// a security control. In every case the block spelling compiled correctly and
// the compact spelling -- equally legal Junos -- dropped the value with no error
// and ZERO warnings, on the STRICT commit path.
//
// The fourth filed instance, #6817 (`system login user ... authentication`), is
// deliberately NOT fixed here: its compact spelling is rejected at commit by the
// #6662 packed-login-body gate and warned about on the tolerant load path, so it
// is neither silent nor accidental. See filedByDesign in
// compact_block_equivalence_2419_test.go.
//
// The census in that file already asserts the two spellings AGREE. These cells
// assert what it cannot: that the value which survives is the RIGHT one. Two
// spellings that both drop a credential also "agree", so equivalence alone would
// go green on a config that authenticates nobody.

// compileBothSpellings compiles the compact and block forms of one stanza
// through the STRICT path -- the path an operator's commit takes -- and returns
// both typed configs.
func compileBothSpellings(t *testing.T, compact, block string) (compactCfg, blockCfg *Config) {
	t.Helper()
	for _, c := range []struct {
		name string
		src  string
		out  **Config
	}{
		{"compact", compact, &compactCfg},
		{"block", block, &blockCfg},
	} {
		p := NewParser(c.src)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("%s spelling failed to PARSE: %v\n%s", c.name, errs, c.src)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("%s spelling failed to COMPILE: %v\n%s", c.name, err, c.src)
		}
		*c.out = cfg
	}
	return compactCfg, blockCfg
}

// TestOSPFInterfaceAuthCompactSpelling_6818 pins that an OSPF interface's
// authentication survives the compact spelling.
//
// This is the sharpest of the three: with AuthType and AuthKey empty the
// adjacency forms UNAUTHENTICATED, and nothing reports it. An operator who
// configured authentication and watched the neighbour come up would read that
// as success.
//
// FAIL-ON-REVERT: restore `prop.Children` in compiler_protocols.go and the
// compact sub-tests RED with an empty AuthType.
func TestOSPFInterfaceAuthCompactSpelling_6818(t *testing.T) {
	const secret = "ospf-shared-secret"
	compact, block := compileBothSpellings(t,
		`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication simple-password "`+secret+`"; } } } }`,
		`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { simple-password "`+secret+`"; } } } } }`)

	for name, cfg := range map[string]*Config{"compact": compact, "block": block} {
		iface := ospfIface6818(t, cfg, name)
		if iface.AuthType != "simple" {
			t.Errorf("%s spelling: AuthType = %q, want \"simple\" -- the adjacency would "+
				"form UNAUTHENTICATED", name, iface.AuthType)
		}
		if string(iface.AuthKey) != secret {
			t.Errorf("%s spelling: AuthKey = %q, want %q", name, string(iface.AuthKey), secret)
		}
	}
}

// TestOSPFInterfaceMD5CompactSpelling_6818 covers the md5 form, which nests one
// level deeper than the others: the block spelling carries the key in an md5
// CHILD, so a single-level rebuild of the flattened chain would leave the key
// dropped.
//
// It is here because it is the cell that justifies using packedBodyChildren
// rather than a hand-rolled one-level expander. packedBodyChildren consumes the
// tail through consumeNodeKeys -- the same primitive SchemaValidate uses -- so
// it rebuilds `md5 7 { key "..." }` as the CHAIN the grammar describes. A
// hand-rolled expander gets the simple-password case right and this one wrong,
// which is exactly the kind of divergence a second implementation introduces.
func TestOSPFInterfaceMD5CompactSpelling_6818(t *testing.T) {
	const secret = "md5-key-material"
	compact, block := compileBothSpellings(t,
		`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication md5 7 key "`+secret+`"; } } } }`,
		`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 7 { key "`+secret+`"; } } } } } }`)

	for name, cfg := range map[string]*Config{"compact": compact, "block": block} {
		iface := ospfIface6818(t, cfg, name)
		if iface.AuthType != "md5" {
			t.Errorf("%s spelling: AuthType = %q, want \"md5\"", name, iface.AuthType)
		}
		if iface.AuthKeyID != 7 {
			t.Errorf("%s spelling: AuthKeyID = %d, want 7", name, iface.AuthKeyID)
		}
		if string(iface.AuthKey) != secret {
			t.Errorf("%s spelling: AuthKey = %q, want %q -- md5 nests deeper than the "+
				"other forms and the key is the part that gets lost",
				name, string(iface.AuthKey), secret)
		}
	}
}

// TestSNMPv3CredentialCompactSpelling_6822 pins that an SNMPv3 user's auth and
// privacy passwords survive the compact spelling.
//
// The failure mode here is the nastiest of the three because it is not a
// skipped user: the PROTOCOL comes from the case label, so the user was
// registered as requiring SHA-256 and AES-128 with EMPTY credentials for both.
func TestSNMPv3CredentialCompactSpelling_6822(t *testing.T) {
	// `usm { local-engine { ... } }` fully nested on purpose: `usm local-engine {`
	// is ITSELF the compact spelling one level up, a separate site in this same
	// class, and using it here would make the cell fail for a reason other than
	// the leaf it names.
	compact, block := compileBothSpellings(t,
		`snmp { v3 { usm { local-engine { user ops { authentication-sha256 authentication-password "s3cret"; privacy-aes128 privacy-password "p4ssphrase"; } } } } }`,
		`snmp { v3 { usm { local-engine { user ops { authentication-sha256 { authentication-password "s3cret"; } privacy-aes128 { privacy-password "p4ssphrase"; } } } } } }`)

	for name, cfg := range map[string]*Config{"compact": compact, "block": block} {
		if cfg.System.SNMP == nil {
			t.Fatalf("%s spelling: no SNMP config compiled at all", name)
		}
		u := cfg.System.SNMP.V3Users["ops"]
		if u == nil {
			t.Fatalf("%s spelling: SNMPv3 user ops missing entirely", name)
		}
		if u.AuthProtocol != "sha256" {
			t.Errorf("%s spelling: AuthProtocol = %q, want \"sha256\"", name, u.AuthProtocol)
		}
		if string(u.AuthPassword) != "s3cret" {
			t.Errorf("%s spelling: AuthPassword = %q, want \"s3cret\" -- the user is "+
				"registered as REQUIRING SHA-256 with an empty credential",
				name, string(u.AuthPassword))
		}
		if u.PrivProtocol != "aes128" {
			t.Errorf("%s spelling: PrivProtocol = %q, want \"aes128\"", name, u.PrivProtocol)
		}
		if string(u.PrivPassword) != "p4ssphrase" {
			t.Errorf("%s spelling: PrivPassword = %q, want \"p4ssphrase\"",
				name, string(u.PrivPassword))
		}
	}
}

// TestLoginPackedAuthStillRejected_6817 is the counter-cell.
//
// #6817 is the fourth filed instance of this class and is NOT fixed here. This
// pins WHY: the compact spelling is rejected at commit by #6662. Without this
// cell, a later reader working through the #2419 inventory would see the login
// entries sitting next to the ones just fixed and "finish the job", silently
// reversing a decision and changing RBAC across an HA sync.
func TestLoginPackedAuthStillRejected_6817(t *testing.T) {
	src := `system { login { user ops { class super-user; authentication encrypted-password "$6$abc"; } } }`
	p := NewParser(src)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("the packed `system login ... authentication` body COMPILED. It must be " +
			"rejected at commit by the #6662 gate; if that gate was removed or this " +
			"stanza was routed through packedBodyChildren, the credential now takes " +
			"effect on the tolerant peer-sync path too, which changes RBAC between " +
			"cluster nodes running different binaries (#1960)")
	}
}

// ospfIface6818 resolves the single OSPF interface under area 0.0.0.0, failing
// if the render produced anything other than exactly one. "Exactly one" is part
// of the claim: with two, an assertion could not say which it read.
func ospfIface6818(t *testing.T, cfg *Config, spelling string) *OSPFInterface {
	t.Helper()
	if cfg.Protocols.OSPF == nil {
		t.Fatalf("%s spelling: no OSPF config compiled at all", spelling)
	}
	var ifaces []*OSPFInterface
	for _, a := range cfg.Protocols.OSPF.Areas {
		ifaces = append(ifaces, a.Interfaces...)
	}
	if len(ifaces) != 1 {
		t.Fatalf("%s spelling: expected exactly one OSPF interface, got %d", spelling, len(ifaces))
	}
	return ifaces[0]
}

// secLogStream6821 resolves a security-log stream by name.

// TestPackedTailAttachesOnlyWhereTheGrammarPermitsABody_6818 pins the guard on
// packedBodyChildren's deep attachment, by calling the HELPER DIRECTLY.
//
// The helper attaches a node's real children UNDER the deepest node of the
// expanded packed tail, which is what the grammar means for
// `authentication md5 7 { key "x"; }`. It is NOT what the grammar means when
// the terminal is a LEAF: `stanza leaf value { body }` describes no nesting the
// schema has, and attaching there would invent one.
//
// # Why this drives the helper rather than a compile
//
// It used to go through CompileConfig on a packed source, which made it a test
// of "does this packed config compile correctly" rather than of the helper's
// contract. That is the wrong subject twice over:
//
//   - it tested the guard only via whichever callers happen to reach it today,
//     so a new direct caller of packedBodyChildren was never covered;
//   - and it is fragile to anything that rewrites the tree BEFORE the compiler
//     runs. #2419's whole-tree normalizer does exactly that, and with it in
//     place the compiler never sees a packed tail at all — the cell would pass
//     while testing nothing, or fail for a reason unrelated to the guard.
//
// The guard is a property of packedBodyChildren. Test it there, and it holds
// for every caller regardless of what runs upstream.
func TestPackedTailAttachesOnlyWhereTheGrammarPermitsABody_6818(t *testing.T) {
	t.Run("terminal PERMITS a body: the block attaches UNDER it", func(t *testing.T) {
		// `authentication md5 7 { key "k"; }` -- a packed tail AND a nested
		// block on one node, which the parser does produce.
		node := &Node{
			Keys:     []string{"authentication", "md5", "7"},
			Children: []*Node{{Keys: []string{"key", "k"}}},
		}
		got := packedBodyChildren(node,
			schemaForPath("protocols", "ospf", "area", "interface", "authentication"))

		if len(got) != 1 {
			t.Fatalf("expected ONE synthesized child (the md5 chain head), got %d: %+v",
				len(got), got)
		}
		md5 := got[0]
		if md5.Name() != "md5" {
			t.Fatalf("synthesized head = %q, want md5", md5.Name())
		}
		// The nested block must be UNDER md5, not beside it. Beside is what
		// compiled an MD5 adjacency with an EMPTY key.
		if len(md5.Children) != 1 || md5.Children[0].Name() != "key" {
			t.Errorf("md5 children = %+v, want the `key` block attached BENEATH it. "+
				"Returning it as a SIBLING is what dropped the key.", md5.Children)
		}
	})

	t.Run("terminal is a LEAF: the body is NOT attached, tail unexpanded", func(t *testing.T) {
		// `protocol` is a scalar leaf under `transport`; it takes no body, so
		// `transport protocol tcp { protocol tls; }` describes no nesting the
		// schema has. The helper must decline rather than invent one.
		node := &Node{
			Keys:     []string{"transport", "protocol", "tcp"},
			Children: []*Node{{Keys: []string{"protocol", "tls"}}},
		}
		got := packedBodyChildren(node,
			schemaForPath("security", "log", "stream", "transport"))

		if len(got) != 1 || got[0].Name() != "protocol" {
			t.Fatalf("expected the node's own children returned unexpanded, got %+v", got)
		}
		// The real child, unexpanded -- NOT a synthesized `protocol tcp` with
		// the block hung underneath it.
		if len(got[0].Children) != 0 {
			t.Errorf("the helper attached a body under a LEAF terminal: %+v. That invents "+
				"a nesting level the schema does not have.", got[0].Children)
		}
	})

	// A schema path that does not resolve makes packedBodyChildren a NO-OP --
	// its first guard returns the node's children when the schema is nil. So a
	// cell that passes a wrong path tests nothing and passes. This one nearly
	// did: `schemaForPath("firewall","family","filter",...)` omits the address
	// family and returns nil, and the cell below was green against it while the
	// helper never ran. Assert the path RESOLVES before using it.
	t.Run("the schema paths these cells use actually resolve", func(t *testing.T) {
		for _, p := range [][]string{
			{"protocols", "ospf", "area", "interface", "authentication"},
			{"security", "log", "stream", "transport"},
			{"firewall", "family", "inet", "filter", "term", "from"},
		} {
			if schemaForPath(p...) == nil {
				t.Errorf("schemaForPath(%v) is nil — packedBodyChildren short-circuits on a "+
					"nil schema, so every cell using this path is a no-op that passes", p)
			}
		}
	})

	t.Run("three-level chain: attaches at the DEEPEST node", func(t *testing.T) {
		// Chain LENGTH was never the question; whether the terminal holds a
		// body is. `range r` does, so the block belongs beneath it.
		node := &Node{
			Keys:     []string{"from", "flexible-match-range", "range", "r"},
			Children: []*Node{{Keys: []string{"byte-offset", "9"}}},
		}
		got := packedBodyChildren(node,
			schemaForPath("firewall", "family", "inet", "filter", "term", "from"))
		if len(got) != 1 {
			t.Fatalf("expected one chain head, got %+v", got)
		}
		// Walk to the deepest synthesized node and require the block there.
		deepest := got[0]
		depth := 1
		for len(deepest.Children) == 1 && deepest.Children[0].Name() != "byte-offset" {
			deepest = deepest.Children[0]
			depth++
		}
		if depth < 2 {
			t.Errorf("the tail expanded to depth %d; it should be a CHAIN, not one level", depth)
		}
		if len(deepest.Children) != 1 || deepest.Children[0].Name() != "byte-offset" {
			t.Errorf("deepest node %q children = %+v, want the byte-offset block",
				deepest.Name(), deepest.Children)
		}
	})

	t.Run("no packed tail: the children are returned untouched", func(t *testing.T) {
		// The identity case, and the control for all three above: a node with
		// no tail must come back exactly as it went in. Without this, a helper
		// that synthesized something for EVERY node would satisfy the shapes
		// above and corrupt every block-spelled config.
		child := &Node{Keys: []string{"md5", "7"}}
		node := &Node{Keys: []string{"authentication"}, Children: []*Node{child}}
		got := packedBodyChildren(node,
			schemaForPath("protocols", "ospf", "area", "interface", "authentication"))
		if len(got) != 1 || got[0] != child {
			t.Errorf("a node with no packed tail must return its own children unchanged, "+
				"got %+v", got)
		}
	})
}

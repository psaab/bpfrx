package config

import (
	"encoding/json"
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
// packedBodyChildren's deep attachment.
//
// The helper attaches a node's real children UNDER the deepest node of the
// expanded packed tail, which is what the grammar means for
// `authentication md5 7 { key "x"; }`. It is NOT what the grammar means when
// the terminal is a LEAF: `stanza leaf value { body }` describes no nesting the
// schema has, and attaching there would invent one.
//
// Both directions matter, so both are cells. Without the permits-a-body case,
// a guard that refused every attachment would pass the refusal case and
// silently reintroduce the empty-MD5-key defect; without the refusal case, the
// guard could be deleted with nothing noticing.
func TestPackedTailAttachesOnlyWhereTheGrammarPermitsABody_6818(t *testing.T) {
	t.Run("terminal PERMITS a body: the block attaches under it", func(t *testing.T) {
		// `md5 7` takes a `key` child, so the nested block belongs under it.
		compact, block := compileBothSpellings(t,
			`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication md5 7 { key "k"; } } } } }`,
			`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 7 { key "k"; } } } } } }`)
		for name, cfg := range map[string]*Config{"packed": compact, "nested": block} {
			iface := ospfIface6818(t, cfg, name)
			if string(iface.AuthKey) != "k" {
				t.Errorf("%s: AuthKey = %q, want \"k\" — the guard must not refuse an "+
					"attachment the grammar allows, or the empty-MD5-key defect returns",
					name, string(iface.AuthKey))
			}
		}
	})

	t.Run("three-level chain still attaches", func(t *testing.T) {
		// `from flexible-match-range range r { byte-offset 9; }` expands through
		// three levels and its terminal does take a body. Chain LENGTH was never
		// the question; whether the terminal holds a body is.
		compact, block := compileBothSpellings(t,
			`firewall { family inet { filter f { term t { from flexible-match-range range r { byte-offset 9; } } } } }`,
			`firewall { family inet { filter f { term t { from { flexible-match-range { range r { byte-offset 9; } } } } } } }`)
		if !cfgEqualFirewall6818(compact, block) {
			t.Error("the packed three-level chain compiled differently from the fully " +
				"nested spelling; the guard is refusing an attachment the grammar allows")
		}
	})
}

// cfgEqualFirewall6818 compares the compiled firewall section of two configs.
func cfgEqualFirewall6818(a, b *Config) bool {
	ja, errA := json.Marshal(a.Firewall)
	jb, errB := json.Marshal(b.Firewall)
	return errA == nil && errB == nil && string(ja) == string(jb)
}

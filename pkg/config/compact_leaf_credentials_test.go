package config

import (
	"testing"
)

// compact_leaf_credentials_test.go -- #6818 / #6821 / #6822.
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

// TestSecurityLogTransportCompactSpelling_6821 pins that a security-log
// stream's TLS profile survives the compact spelling.
//
// With TLSProfile empty the stream ships audit records over an unprotected
// transport. The operator configured TLS; the box did not use it; nothing said
// so.
func TestSecurityLogTransportCompactSpelling_6821(t *testing.T) {
	// The leaf under test is `protocol`, not `tls-profile`. tls-profile is
	// already rejected at commit on its own grounds -- xpf has no TLS profile
	// definition to resolve the name against, so the stanza is fail-closed
	// before this class ever applies. `protocol` strict-compiles with ZERO
	// warnings and is where the silent drop actually lived.
	compact, block := compileBothSpellings(t,
		`security { log { mode stream; stream audit { host 192.0.2.10; transport protocol tls; } } }`,
		`security { log { mode stream; stream audit { host 192.0.2.10; transport { protocol tls; } } } }`)

	for name, cfg := range map[string]*Config{"compact": compact, "block": block} {
		st := secLogStream6821(t, cfg, "audit", name)
		if st.Transport.Protocol != "tls" {
			t.Errorf("%s spelling: Transport.Protocol = %q, want \"tls\" -- the stream "+
				"falls back to plain transport and ships audit records unprotected",
				name, st.Transport.Protocol)
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
func secLogStream6821(t *testing.T, cfg *Config, name, spelling string) *SyslogStream {
	t.Helper()
	st := cfg.Security.Log.Streams[name]
	if st == nil {
		t.Fatalf("%s spelling: security-log stream %q missing entirely (streams: %d)",
			spelling, name, len(cfg.Security.Log.Streams))
	}
	return st
}

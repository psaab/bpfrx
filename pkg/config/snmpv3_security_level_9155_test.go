package config

import (
	"strings"
	"testing"
)

// snmpv3_security_level_9155_test.go — #9155.
//
// #7530 rejected a protocol with no key material. Two ordinary commits get past
// it and still produce a user served BELOW its configured security level.
//
// The acceptance table the issue asks for, over
// {no auth, unknown auth spelling, auth only, priv only, auth+priv}, asserting
// the COMMIT VERDICT here and the derived key nil-ness in pkg/snmp.

func compile9155(t *testing.T, body string) error {
	t.Helper()
	src := `snmp { v3 { usm { local-engine { ` + body + ` } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	_, err := CompileConfig(tree)
	return err
}

// compile9155Flat drives the FLAT-SET channel, where the run packs onto the
// user node's own Keys instead of becoming a child. A gate that checks only one
// spelling covers the spelling its author happened to test with — and the two
// put the keyword in different places.
func compile9155Flat(t *testing.T, lines ...string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("parse set %q: %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", ln, err)
		}
	}
	_, err := CompileConfig(tree)
	return err
}

func TestSNMPv3SecurityLevelCommitTable9155(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantReject string // substring; "" means MUST COMMIT
	}{
		{
			name: "no auth, no priv — a genuine noAuthNoPriv user is legitimate",
			body: `user ops { }`,
		},
		{
			name: "auth only — authNoPriv is legitimate",
			body: `user ops { authentication-sha256 { authentication-password "s3cretpass"; } }`,
		},
		{
			name: "auth + priv — authPriv, the fully configured case",
			body: `user ops { authentication-sha256 { authentication-password "s3cretpass"; } privacy-aes128 { privacy-password "p4ssphrase"; } }`,
		},
		{
			// HOLE A. #7530 cannot see this: the unknown spelling leaves
			// AuthProtocol EMPTY, so "protocol named but no password" is false.
			name:       "unknown auth spelling — silently dropped the whole stanza",
			body:       `user eve { authentication-sha512 { authentication-password "s3cretpass"; } }`,
			wantReject: "unknown authentication protocol",
		},
		{
			name:       "unknown privacy spelling",
			body:       `user eve { authentication-sha256 { authentication-password "s3cretpass"; } privacy-aes256 { privacy-password "p4ssphrase"; } }`,
			wantReject: "unknown privacy protocol",
		},
		{
			// HOLE B. #7530's privacy arm requires PrivPassword == "" and a
			// password IS present, so it does not fire.
			name:       "priv only — USM has no privacy-only level",
			body:       `user eve { privacy-aes128 { privacy-password "p4ssphrase"; } }`,
			wantReject: "no authentication protocol",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := compile9155(t, tc.body)
			if tc.wantReject == "" {
				if err != nil {
					t.Fatalf("a legitimate configuration was REJECTED: %v\n\n"+
						"This gate is reject-only; a false rejection here is the failure "+
						"mode it was designed to make loud rather than silent.", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("committed clean, want rejection containing %q — the user is "+
					"served BELOW its configured security level", tc.wantReject)
			}
			if !strings.Contains(err.Error(), tc.wantReject) {
				t.Errorf("rejected for the wrong reason.\n got: %v\nwant substring: %q\n\n"+
					"A gate that fires on the right input via the wrong branch reads as "+
					"a working guard.", err, tc.wantReject)
			}
		})
	}
}

// The flat-set channel is how an operator actually types this, and it packs the
// run onto the user node's Keys rather than making it a child. The issue
// measured Hole A through `Store.Set` + `Store.Commit`, i.e. this shape.
func TestUnknownSpellingIsRejectedOnTheFlatSetChannel9155(t *testing.T) {
	err := compile9155Flat(t,
		`set snmp v3 usm local-engine user eve authentication-sha512 authentication-password X9155pass`)
	if err == nil {
		t.Fatal("the flat-set spelling committed clean; the braced spelling is " +
			"rejected, so the gate covers one AST shape and not the one operators type")
	}
	if !strings.Contains(err.Error(), "unknown authentication protocol") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}

	// REFERENCE ARM: the KNOWN spelling must still commit on this same channel.
	// Without it, the assertion above is satisfied by a gate that rejects every
	// flat-set SNMPv3 user — consistency achieved by levelling down.
	if err := compile9155Flat(t,
		`set snmp v3 usm local-engine user ops authentication-sha256 authentication-password X9155pass`); err != nil {
		t.Errorf("the KNOWN spelling was rejected on the flat-set channel: %v", err)
	}
}

// The tolerant ingress must still ACCEPT, with a warning — #1960 no-brick. A
// persisted pre-gate config has to boot. What makes that safe is the runtime
// floor in pkg/snmp, fixed in the same change to key on configured intent, so
// the agent refuses to serve the user even though the config loaded.
func TestTolerantIngressWarnsRatherThanBricking9155(t *testing.T) {
	src := `snmp { v3 { usm { local-engine { user eve { authentication-sha512 { authentication-password "s3cretpass"; } } } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path REJECTED a persisted config: %v — an already-committed "+
			"config must still boot (#1960)", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "snmpv3 security keyword") {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path accepted the config with no warning; the downgrade "+
			"must be visible or it is indistinguishable from a config with no defect.\n"+
			"warnings: %v", cfg.Warnings)
	}
}

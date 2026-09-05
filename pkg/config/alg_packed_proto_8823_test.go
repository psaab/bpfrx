package config

import (
	"fmt"
	"testing"
)

// TestALGDisableSurvivesEverySpelling8823 asserts the VALUE — that the ALG is
// actually disabled — never that the commit succeeded.
//
// #8823: `security { alg ftp disable; }` compiled to FTPDisable=FALSE on a
// clean commit. All four wired protos measured false in that spelling, so an
// operator disabling an ALG got a success and an ALG still ENABLED.
//
// WHY THE VALUE AND NOT THE COMMIT. Every broken cell committed cleanly —
// `CompileConfig` returned nil for all twelve. A cell asserting "commit
// succeeded" passes on all of them, which is the definition of vacuous here.
//
// The spellings differ in where the proto and its body live:
//
//	alg { ftp { disable; } }   alg has child ftp, ftp has child disable
//	alg { ftp disable; }       alg has child ftp, ftp carries disable in Keys
//	alg ftp disable;           alg carries BOTH in Keys, no children
//	alg ftp { disable; }       alg carries the proto in Keys, disable is a child
//
// The last two are the broken pair, and the fourth was found by testing an
// adjacent spelling neither the issue nor the report listed.
func TestALGDisableSurvivesEverySpelling8823(t *testing.T) {
	get := map[string]func(*Config) bool{
		"dns":  func(c *Config) bool { return c.Security.ALG.DNSDisable },
		"ftp":  func(c *Config) bool { return c.Security.ALG.FTPDisable },
		"sip":  func(c *Config) bool { return c.Security.ALG.SIPDisable },
		"tftp": func(c *Config) bool { return c.Security.ALG.TFTPDisable },
	}
	spellings := []struct{ name, tmpl string }{
		{"fully braced", `security { alg { %s { disable; } } }`},
		{"singly elided", `security { alg { %s disable; } }`},
		{"doubly elided", `security { alg %s disable; }`},
		{"mixed", `security { alg %s { disable; } }`},
	}
	for _, proto := range []string{"dns", "ftp", "sip", "tftp"} {
		for _, sp := range spellings {
			t.Run(proto+"/"+sp.name, func(t *testing.T) {
				text := fmt.Sprintf(sp.tmpl, proto)
				tr, perrs := NewParser(text).Parse()
				if len(perrs) > 0 {
					t.Fatalf("fixture must parse: %v", perrs)
				}
				cfg, err := CompileConfig(tr)
				if err != nil {
					t.Fatalf("strict compile: %v", err)
				}
				if !get[proto](cfg) {
					t.Errorf("%s ALG is still ENABLED after `%s`. The commit SUCCEEDED, so "+
						"nothing tells the operator their disable did not take — the "+
						"configuration does not mean what it says (#8823)", proto, text)
				}
			})
		}
	}
}

// TestALGUnsupportedProtoAdvisorySurvivesPacking8823 pins the #4232 advisory,
// which #8823 silenced in one spelling and made WRONG in another.
//
// The advisory exists to report a `security alg <proto>` the dataplane does not
// wire. Measured before the fix:
//
//	alg { h323 { gatekeeper; } }   unsupported=[h323]        correct
//	alg h323 gatekeeper;           unsupported=[]            SILENT
//	alg h323 { gatekeeper; }       unsupported=[gatekeeper]  WRONG NAME
//
// The wrong-name case is worse than the silent one: it names a sub-statement as
// though it were a protocol, and a reader acting on it looks for an ALG that
// does not exist. An advisory built to catch silent drops was itself both
// silent and misleading, in different spellings of the same stanza.
func TestALGUnsupportedProtoAdvisorySurvivesPacking8823(t *testing.T) {
	for _, c := range []struct{ name, text string }{
		{"fully braced", `security { alg { h323 { gatekeeper; } } }`},
		{"doubly elided", `security { alg h323 gatekeeper; }`},
		{"mixed", `security { alg h323 { gatekeeper; } }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, perrs := NewParser(c.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			cfg, err := CompileConfig(tr)
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}
			got := cfg.Security.ALG.UnsupportedProtos
			if len(got) != 1 || got[0] != "h323" {
				t.Errorf("UnsupportedProtos=%v, want [h323] for `%s`.\n"+
					"An empty list is the advisory going SILENT; any other name is the "+
					"advisory naming a sub-statement as a protocol, which sends a reader "+
					"looking for an ALG that does not exist (#8823)", got, c.text)
			}
		})
	}
}

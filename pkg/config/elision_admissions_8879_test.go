package config

import (
	"fmt"
	"testing"
)

// #8879 batch 1: four pairs admitted to compactNormalizeInScope, each after
// measuring that its elided spelling was SILENT.
//
// THE ADMISSION RULE IS PER PAIR AND THE GATE COLUMN DECIDES IT:
//
//	elided spelling REJECTED at strict  -> do NOT admit; the operator is already
//	                                      told, and admitting makes it quiet
//	elided spelling WARNS on lenient    -> same reasoning, weaker signal
//	elided spelling SILENT              -> admit; a silent drop becomes a
//	                                      correct compile
//
// #8868 is why the first row is not a formality: admitting `system login` would
// convert a LOUD #6662 commit rejection into a silent acceptance — a regression
// wearing the shape of a fix.
//
// Measured before admission, with these fixtures rather than the sweep's
// synthesized ones:
//
//	protocols bgp    braced as=65001 rid=10.0.0.1  ->  elided <nil>
//	security ike     braced proposals=1            ->  elided 0
//	security nat     braced pools=1                ->  elided 0
//	system syslog    braced hosts=1                ->  elided <nil>
//
// all four with strict accepting and lenient not warning on either arm: the
// whole stanza dropped, silently.
//
// Shipped-config sweep after the batch: 9 pass / 5 fail, identical to the
// pre-batch baseline and failing for the same pre-existing reasons (four
// historical evidence configs with no cluster authentication-key, one node-id
// mismatch). Confirming a rule catches its target says nothing about what else
// it catches, so the corpus is swept per batch rather than per campaign.
func TestAdmittedPairsCompileLikeBraced8879(t *testing.T) {
	for _, c := range []struct {
		pair, braced, elided string
		get                  func(*Config) string
	}{
		{"protocols bgp",
			`protocols { bgp { local-as 65001; router-id 10.0.0.1; } }`,
			`protocols bgp { local-as 65001; router-id 10.0.0.1; }`,
			func(c *Config) string {
				if c.Protocols.BGP == nil {
					return "<nil>"
				}
				return fmt.Sprintf("as=%d rid=%s", c.Protocols.BGP.LocalAS, c.Protocols.BGP.RouterID)
			}},
		{"security ike",
			`security { ike { proposal pr { authentication-method pre-shared-keys; } } }`,
			`security ike { proposal pr { authentication-method pre-shared-keys; } }`,
			func(c *Config) string { return fmt.Sprintf("proposals=%d", len(c.Security.IPsec.IKEProposals)) }},
		{"security nat",
			`security { nat { source { pool P { address 10.0.0.1/32; } } } }`,
			`security nat { source { pool P { address 10.0.0.1/32; } } }`,
			func(c *Config) string { return fmt.Sprintf("pools=%d", len(c.Security.NAT.SourcePools)) }},
		// #8879 batch 2. Values are chosen NOT to equal any compiled default:
		// a fixture whose value IS the fallback reads CLEAN WHILE BROKEN, because
		// losing the value and keeping it produce the same compiled result. That
		// trap is invisible in exactly the way a dead reference arm is, and the
		// braced arm is LIVE throughout it.
		{"security address-book",
			`security { address-book { global { address a1 203.0.113.0/24; } } }`,
			`security address-book { global { address a1 203.0.113.0/24; } }`,
			func(c *Config) string {
				if c.Security.AddressBook == nil {
					return "<nil>"
				}
				return fmt.Sprintf("addrs=%d", len(c.Security.AddressBook.Addresses))
			}},
		{"protocols ospf",
			`protocols { ospf { area 0.0.0.7 { interface ge-0/0/0.0 { metric 42; } } } }`,
			`protocols ospf { area 0.0.0.7 { interface ge-0/0/0.0 { metric 42; } } }`,
			func(c *Config) string {
				if c.Protocols.OSPF == nil {
					return "<nil>"
				}
				return fmt.Sprintf("areas=%d", len(c.Protocols.OSPF.Areas))
			}},
		{"chassis device-map",
			`chassis { device-map { interface ge-0/0/5 { pci 0000:07:00.3; } } }`,
			`chassis device-map { interface ge-0/0/5 { pci 0000:07:00.3; } }`,
			func(c *Config) string {
				if c.Chassis.DeviceMap == nil {
					return "<nil>"
				}
				return fmt.Sprintf("entries=%d", len(c.Chassis.DeviceMap.Entries))
			}},
		{"system ntp",
			`system { ntp { server 198.51.100.23; } }`,
			`system ntp { server 198.51.100.23; }`,
			func(c *Config) string { return fmt.Sprintf("servers=%d", len(c.System.NTPServers)) }},
		{"system syslog",
			`system { syslog { host 10.0.0.9 { any any; } } }`,
			`system syslog { host 10.0.0.9 { any any; } }`,
			func(c *Config) string {
				if c.System.Syslog == nil {
					return "<nil>"
				}
				return fmt.Sprintf("hosts=%d", len(c.System.Syslog.Hosts))
			}},
	} {
		t.Run(c.pair, func(t *testing.T) {
			read := func(txt string) string {
				tree, perrs := NewParser(txt).Parse()
				if len(perrs) > 0 {
					t.Fatalf("fixture must parse (%q): %v", txt, perrs[0])
				}
				cfg, err := CompileConfigLenient(tree)
				if cfg == nil {
					t.Fatalf("fixture must compile (%q): %v", txt, err)
				}
				return c.get(cfg)
			}
			// LIVENESS, fatal: the braced reference must DELIVER something, or
			// "elided == braced" is agreement between two empty results.
			// LIVENESS, fatal — this is a FIXTURE check, not a property
			// assertion, so a fatal is correct here: nothing below can mean
			// anything if the reference delivered nothing.
			//
			// Asserted against an EMPTY config rather than merely non-nil. A
			// fixture whose value equals the compiled DEFAULT is live, its
			// comparison is real, and the row still reads clean while broken —
			// losing the value produces the same result as keeping it. The
			// values above are chosen so that cannot happen.
			braced := read(c.braced)
			if braced == "<nil>" || braced == "" {
				t.Fatalf("braced reference delivered %q — the comparison below "+
					"would be vacuous", braced)
			}
			if empty, _ := CompileConfigLenient(&ConfigTree{}); empty != nil && c.get(empty) == braced {
				t.Fatalf("%s: the braced reference compiles to %q, which is what an "+
					"EMPTY config produces. Losing the value would give the same "+
					"answer as keeping it, so this row cannot detect the drop it "+
					"exists to detect — pick a value that is not the default.",
					c.pair, braced)
			}
			if elided := read(c.elided); elided != braced {
				t.Errorf("%s: elided compiles to %q but braced compiles to %q. "+
					"The pair is admitted to compactNormalizeInScope, so the two "+
					"spellings must agree; a difference means the fold no longer "+
					"reaches this pair (#8879).", c.pair, elided, braced)
			}
		})
	}
}

// THE NEGATIVE CONTROL, and it is what makes the admissions above a measurement
// rather than an assertion. A pair whose elided spelling is ALREADY REJECTED
// must stay unadmitted: admitting it would silence a signal the operator gets
// today. `system login` is the #6662 case #8868 established.
//
// This cell fails if someone admits it — including as part of a "sweep the
// remaining rows" batch, which is exactly how a loud rejection becomes quiet.
func TestRejectedPairStaysUnadmitted8879(t *testing.T) {
	// Errorf, not Fatalf: a fatal here would stop the property assertion below
	// from running at all, so a mutant admitting the pair would prove only that
	// THIS assertion fires and leave the other untested.
	if compactNormalizeInScope("system", "login") {
		t.Errorf("`system login` has been ADMITTED to compactNormalizeInScope. " +
			"Its elided spelling is REJECTED at strict commit today (#6662), so " +
			"admitting it converts a loud rejection into a silent acceptance — a " +
			"regression wearing the shape of a fix (#8868). Admit only pairs whose " +
			"elided spelling is measured SILENT.")
	}
	// And the property behind the flag: the elided spelling must still be
	// refused. Asserting the flag alone would pass if the rejection moved.
	txt := `system login { user u1 { class super-user; } }`
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("the elided `system login` spelling is no longer refused at strict " +
			"commit. If that rejection was removed deliberately this cell should " +
			"move; if not, the operator has lost a signal (#8868).")
	}
}

// The tolerant ingress must accept everything it accepts today. It DOES
// schema-validate and downgrade to a warning, so the property is "no new
// REJECTION", not "no new validation".
func TestAdmissionsIntroduceNoNewRejection8879(t *testing.T) {
	for _, txt := range []string{
		`protocols bgp { local-as 65001; router-id 10.0.0.1; }`,
		`security ike { proposal pr { authentication-method pre-shared-keys; } }`,
		`security nat { source { pool P { address 10.0.0.1/32; } } }`,
		`system syslog { host 10.0.0.9 { any any; } }`,
	} {
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse (%q): %v", txt, perrs[0])
		}
		if cfg, err := CompileConfigLenient(tree); err != nil || cfg == nil {
			t.Errorf("the tolerant ingress must still accept %q: %v — a config "+
				"already on disk must keep loading (#1960 no-brick)", txt, err)
		}
	}
}

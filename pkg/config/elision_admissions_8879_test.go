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
		// #8879 batch 3, chosen to SPAN MODES: four subsystems and four
		// different compiled shapes — a pointer struct (`isis`), a slice
		// (`generate`), a scalar string (`license`) and a struct-of-scalars
		// (`log`). Picking the top four rows of the sweep table would have
		// sampled one region of the schema; picking the four most
		// consequential would have sampled the regions with the MOST
		// downstream validators, which is bias toward being caught rather
		// than bias toward being representative.
		//
		// `security log` is the shape that most needs the empty-config
		// liveness check below: Security.Log is a VALUE, not a pointer, so
		// the elided arm yields a zero struct rather than nil and a
		// nil-check would have called that "no drop".
		{"protocols isis",
			`protocols { isis { net 49.0001.1921.6800.1001.00; } }`,
			`protocols isis { net 49.0001.1921.6800.1001.00; }`,
			func(c *Config) string {
				if c.Protocols.ISIS == nil {
					return "<nil>"
				}
				return "net=" + c.Protocols.ISIS.NET
			}},
		{"routing-options generate",
			`routing-options { generate { route 203.0.113.0/24 { discard; } } }`,
			`routing-options generate { route 203.0.113.0/24 { discard; } }`,
			func(c *Config) string {
				return fmt.Sprintf("gen=%d", len(c.RoutingOptions.GenerateRoutes))
			}},
		{"system license",
			`system { license { autoupdate { url https://lic.example.invalid/x; } } }`,
			`system license { autoupdate { url https://lic.example.invalid/x; } }`,
			func(c *Config) string { return "url=" + c.System.LicenseAutoUpdate }},
		{"security log",
			`security { log { mode event; format binary; } }`,
			`security log { mode event; format binary; }`,
			func(c *Config) string {
				return fmt.Sprintf("mode=%s/fmt=%s", c.Security.Log.Mode, c.Security.Log.Format)
			}},
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

// TestInstanceNamePairCannotBeAdmitted8879 records the one DECLINE in #8879
// batch 3, and records it for the reason that is actually true.
//
// `interfaces <name>` appears in the sweep as a CANDIDATE-DROP whose elided
// arm STRICT-REJECTS, which reads like "declined because the drop is loud".
// It is not that. With a hand-written leaf (`unit 0 family inet address ...`)
// BOTH arms compile strictly clean and both yield one interface, so that
// row's gate verdict is a property of the single synthesized leaf the sweep
// happened to pick, not of the pair. A per-row verdict derived from one
// synthesized leaf does not generalise to the pair it names.
//
// The real reason this pair is declined is STRUCTURAL and holds for every
// leaf: compactNormalizeInScope is keyed on a (container, head) pair of
// literal keywords, and here the head is an INSTANCE NAME chosen by the
// operator. There is no string to admit. This is a permanent bound of the
// pair-keyed design, not a backlog item, and it is asserted rather than
// written down so that a future redesign which removes the bound also
// removes this cell.
func TestInstanceNamePairCannotBeAdmitted8879(t *testing.T) {
	// The bound: an instance-named head is not a fixed keyword, so no
	// admission list can name it. Two arbitrary interface names must be
	// treated identically by the predicate — if they ever differ, the
	// predicate has started keying on instance names and this whole cell,
	// plus the reasoning above, needs revisiting.
	a := compactNormalizeInScope("interfaces", "ge-0/0/0")
	b := compactNormalizeInScope("interfaces", "xe-7/1/3")
	if a != b {
		t.Errorf("compactNormalizeInScope treats `interfaces ge-0/0/0` (%v) "+
			"differently from `interfaces xe-7/1/3` (%v). The predicate is "+
			"keyed on literal keyword pairs, so an instance-named head must "+
			"be indistinguishable from any other (#8879).", a, b)
	}
	if a {
		t.Errorf("`interfaces <name>` is reported IN SCOPE. An instance name " +
			"cannot be a literal admission key, so this can only mean the " +
			"predicate matched something it should not have (#8879).")
	}
	// And the property the sweep's verdict was mistaken about: with a real
	// leaf, the elided spelling is NOT refused. Asserting this keeps the
	// decline honest — if someone later reads the sweep row and concludes
	// "declined because loud", this cell contradicts them.
	txt := `interfaces ge-0/0/0 { unit 0 { family inet { address 10.9.9.1/24; } } }`
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("the elided `interfaces <name>` spelling is now refused at "+
			"strict commit (%v). If that is deliberate the decline reason in "+
			"this cell should move to the gate; as measured for #8879 it was "+
			"accepted, and the decline rests on the instance-name bound "+
			"instead.", err)
	}
}

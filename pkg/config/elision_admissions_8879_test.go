package config

import (
	"encoding/json"
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
		// #8879 batch 7. THE FIRST TWO ARE A CORRECTION OF MY OWN BATCH-5
		// WORK. Batch 5 re-checked the sweep's SAME rows by hand and cleared
		// `class-of-service classifiers` and `class-of-service rewrite-rules`
		// as "genuinely SAME". That was true of the ONE leaf I tried (`dscp`)
		// and false of the pair: via `inet-precedence` and `exp` both drop.
		//
		// It is precisely the error I had diagnosed in the sweep one batch
		// earlier -- a verdict derived from a single leaf, reported about the
		// pair -- committed by the person who wrote the diagnosis. The
		// fixtures below therefore use the DROPPING leaf, not the convenient
		// one.
		{"class-of-service classifiers",
			`class-of-service { classifiers { inet-precedence cl2 { forwarding-class expedited-forwarding { loss-priority low code-points 101; } } } }`,
			`class-of-service classifiers { inet-precedence cl2 { forwarding-class expedited-forwarding { loss-priority low code-points 101; } } }`,
			func(c *Config) string {
				return fmt.Sprintf("prec=%d", len(c.ClassOfService.INetPrecedenceClassifierDefs))
			}},
		// SEVERITY NOTE, so this row is not read as worse than it is: the
		// braced arm raises "rewrite-rules exp is accepted for compatibility
		// but inert" -- the value has no runtime effect either way. What the
		// elision actually costs here is the ADVISORY, not the behaviour. The
		// operator writing the elided spelling gets neither the (inert)
		// config nor the notice telling them it is inert.
		{"class-of-service rewrite-rules",
			`class-of-service { rewrite-rules { exp rw2 { forwarding-class expedited-forwarding { loss-priority low code-point 101; } } } }`,
			`class-of-service rewrite-rules { exp rw2 { forwarding-class expedited-forwarding { loss-priority low code-point 101; } } }`,
			func(c *Config) string {
				return fmt.Sprintf("exp=%d", len(c.ClassOfService.EXPRewriteRules))
			}},
		{"protocols lldp",
			`protocols { lldp { interface ge-0/0/6.0; transmit-interval 47; } }`,
			`protocols lldp { interface ge-0/0/6.0; transmit-interval 47; }`,
			func(c *Config) string {
				if c.Protocols.LLDP == nil {
					return "<nil>"
				}
				return fmt.Sprintf("if=%d/int=%d",
					len(c.Protocols.LLDP.Interfaces), c.Protocols.LLDP.Interval)
			}},
		// Same severity note as `rewrite-rules exp`: the braced arm warns that
		// pre-id session logging is inert in the userspace dataplane, so the
		// loss is the advisory rather than a live behaviour.
		{"security pre-id-default-policy",
			`security { pre-id-default-policy { then { log { session-init; } } } }`,
			`security pre-id-default-policy { then { log { session-init; } } }`,
			func(c *Config) string {
				if c.Security.PreIDDefaultPolicy == nil {
					return "<nil>"
				}
				return fmt.Sprintf("init=%v/close=%v",
					c.Security.PreIDDefaultPolicy.LogSessionInit,
					c.Security.PreIDDefaultPolicy.LogSessionClose)
			}},
		// #8879 batch 6. Read `routing-options forwarding-table` twice: the
		// elision was not only dropping a value, it was SUPPRESSING A COMMIT
		// CHECK. See TestElisionSuppressedAValidation8879 below.
		{"forwarding-options dhcp-relay",
			`forwarding-options { dhcp-relay { group g1 { active-server-group sg1; interface ge-0/0/4.0; } } }`,
			`forwarding-options dhcp-relay { group g1 { active-server-group sg1; interface ge-0/0/4.0; } }`,
			func(c *Config) string {
				if c.ForwardingOptions.DHCPRelay == nil {
					return "<nil>"
				}
				return fmt.Sprintf("groups=%d", len(c.ForwardingOptions.DHCPRelay.Groups))
			}},
		{"protocols rip",
			`protocols { rip { neighbor ge-0/0/5.0; redistribute static; } }`,
			`protocols rip { neighbor ge-0/0/5.0; redistribute static; }`,
			func(c *Config) string {
				if c.Protocols.RIP == nil {
					return "<nil>"
				}
				return fmt.Sprintf("if=%d/redist=%d",
					len(c.Protocols.RIP.Interfaces), len(c.Protocols.RIP.Redistribute))
			}},
		// The export policy is DEFINED in both arms on purpose. With an
		// undefined one the braced arm is rejected and the elided arm is not,
		// which is a real asymmetry but a different one -- it would make this
		// row measure the dangling-reference check rather than the drop.
		{"routing-options forwarding-table",
			`policy-options { policy-statement ecmp-policy-7717 { then accept; } } routing-options { forwarding-table { export ecmp-policy-7717; } }`,
			`policy-options { policy-statement ecmp-policy-7717 { then accept; } } routing-options forwarding-table { export ecmp-policy-7717; }`,
			func(c *Config) string { return "fte=" + c.RoutingOptions.ForwardingTableExport }},
		// #8879 batch 5. TWO OF THESE FOUR WERE PUBLISHED AS BENIGN.
		//
		// `class-of-service fairness` and `security policy-stats` came out of
		// the sweep's SAME column, not its SILENT column — the instrument
		// reported "elided delivers what braced delivers" for both. That
		// verdict was true of the single leaf the instrument synthesised and
		// false of the pair. With a hand-written fixture `fairness` drops its
		// entire expectation list and `policy-stats` silently flips
		// PolicyStatsEnabled from true to FALSE, which turns a security
		// feature off without telling anyone.
		//
		// Kept here as provenance, because it is the part that generalises: a
		// per-pair verdict derived from one synthesised leaf is a claim about
		// that leaf, and a SAME verdict is the one place where being wrong is
		// invisible — nobody re-opens a row the instrument already cleared.
		{"class-of-service fairness",
			`class-of-service { fairness { rss-expectation { interface ge-0/0/1 { queue 3 { at-least-active-workers 4; } } } } }`,
			`class-of-service fairness { rss-expectation { interface ge-0/0/1 { queue 3 { at-least-active-workers 4; } } } }`,
			func(c *Config) string {
				return fmt.Sprintf("fair=%d", len(c.ClassOfService.FairnessExpectations))
			}},
		{"security policy-stats",
			`security { policy-stats { system-wide enable; } }`,
			`security policy-stats { system-wide enable; }`,
			func(c *Config) string {
				return fmt.Sprintf("stats=%v", c.Security.PolicyStatsEnabled)
			}},
		{"security ipsec",
			`security { ipsec { proposal ip1 { encryption-algorithm aes-256-gcm; } } }`,
			`security ipsec { proposal ip1 { encryption-algorithm aes-256-gcm; } }`,
			func(c *Config) string {
				return fmt.Sprintf("ipsecprop=%d", len(c.Security.IPsec.Proposals))
			}},
		// The braced arm needs probe-type AND target to pass STRICT commit.
		// A reference that fails strict compile would put this row in the
		// same unanswerable third state the batch-4 cell exists to resolve.
		{"services rpm",
			`services { rpm { probe pr1 { test t1 { probe-type icmp-ping; target address 198.51.100.9; probe-count 7; } } } }`,
			`services rpm { probe pr1 { test t1 { probe-type icmp-ping; target address 198.51.100.9; probe-count 7; } } }`,
			func(c *Config) string {
				if c.Services.RPM == nil {
					return "<nil>"
				}
				return fmt.Sprintf("rpm=%d", len(c.Services.RPM.Probes))
			}},
		// #8879 batch 4. Mode-spanning again — a pointer struct reached
		// through a keyed sub-map (`sampling`), a slice
		// (`router-advertisement`), a map (`snmp v3`), and a struct whose
		// every OTHER field is a default (`archival`).
		//
		// `system archival` is the reason the liveness check compares against
		// an empty config rather than against nil: TransferOnCommit,
		// ArchiveDir and MaxArchives all come back at their defaults here, so
		// only TransferInterval carries the fixture's signal. Reading the
		// whole struct and asking "is it non-empty" would have been satisfied
		// entirely by defaults.
		{"forwarding-options sampling",
			`forwarding-options { sampling { instance si1 { input { rate 7717; } } } }`,
			`forwarding-options sampling { instance si1 { input { rate 7717; } } }`,
			func(c *Config) string {
				if c.ForwardingOptions.Sampling == nil {
					return "<nil>"
				}
				return fmt.Sprintf("inst=%d", len(c.ForwardingOptions.Sampling.Instances))
			}},
		{"protocols router-advertisement",
			`protocols { router-advertisement { interface ge-0/0/7.0 { link-mtu 1444; } } }`,
			`protocols router-advertisement { interface ge-0/0/7.0 { link-mtu 1444; } }`,
			func(c *Config) string {
				return fmt.Sprintf("ra=%d", len(c.Protocols.RouterAdvertisement))
			}},
		{"snmp v3",
			`snmp { v3 { usm { local-engine { user u7717 { authentication-sha { authentication-password sekritpw; } } } } } }`,
			`snmp v3 { usm { local-engine { user u7717 { authentication-sha { authentication-password sekritpw; } } } } }`,
			func(c *Config) string {
				if c.System.SNMP == nil {
					return "<no-snmp>"
				}
				return fmt.Sprintf("v3users=%d", len(c.System.SNMP.V3Users))
			}},
		{"system archival",
			`system { archival { configuration { transfer-interval 77; } } }`,
			`system archival { configuration { transfer-interval 77; } }`,
			func(c *Config) string {
				if c.System.Archival == nil {
					return "<nil>"
				}
				return fmt.Sprintf("interval=%d", c.System.Archival.TransferInterval)
			}},
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
	// Two containers, not one: `interfaces <name>` and `routing-instances
	// <name>` are BOTH instance-named heads in the #8879 population, and a
	// bound demonstrated on a single container is a claim about that
	// container. Asserting both makes it a claim about the shape.
	for _, ct := range []struct{ container, n1, n2 string }{
		{"interfaces", "ge-0/0/0", "xe-7/1/3"},
		{"routing-instances", "vrf-blue", "vrf-green"},
	} {
		a := compactNormalizeInScope(ct.container, ct.n1)
		b := compactNormalizeInScope(ct.container, ct.n2)
		if a != b {
			t.Errorf("compactNormalizeInScope treats `%s %s` (%v) differently "+
				"from `%s %s` (%v). The predicate is keyed on literal keyword "+
				"pairs, so an instance-named head must be indistinguishable "+
				"from any other (#8879).", ct.container, ct.n1, a, ct.container, ct.n2, b)
		}
		if a {
			t.Errorf("`%s <name>` is reported IN SCOPE. An instance name "+
				"cannot be a literal admission key, so this can only mean the "+
				"predicate matched something it should not have (#8879).",
				ct.container)
		}
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

// TestSweepUnanswerableRowIsNotADefect8879 adjudicates the #8879 population's
// one NO-REFERENCE row, `firewall three-color-policer <name>`.
//
// The sweep reports it as "braced form does not compile — fixture cannot
// answer", which is an honest THIRD STATE rather than a verdict: the
// instrument is saying it did not measure, not that there is nothing to
// measure. That distinction is easy to lose, and a row parked in it is
// indistinguishable from an adjudicated one on any count of remaining work.
//
// Re-asked with a hand-written fixture the row answers cleanly. The
// synthesized fixture failed a COMPILER VALIDATION, not the elision:
// `three-color-policer requires positive excess-burst-size`. Supply one and
// both spellings compile strictly clean AND produce byte-identical configs.
//
// The reason they agree is NOT that the pair is naturally equivalent. It is
// that `firewall three-color-policer` is ALREADY ADMITTED to
// compactNormalizeInScope — this is the FOLD DOING THE WORK, which is a
// different label from "no defect here" and must not be recorded as the
// latter. Verified two-sided on sibling pairs: removing the admission for
// `firewall policer` and `snmp community` makes their two spellings DIFFER,
// so agreement in this family is caused by the admission rather than by the
// shape.
//
// The pair therefore needs no NEW admission, which is why it is a decline —
// but a reader must not conclude the elision is harmless here. The assertion
// below pins the actual cause, so the reason cannot rot into the wrong one.
func TestSweepUnanswerableRowIsNotADefect8879(t *testing.T) {
	const body = `single-rate { committed-information-rate 40m; ` +
		`committed-burst-size 100k; excess-burst-size 200k; } ` +
		`then { loss-priority high; }`
	braced := "firewall { three-color-policer tcp1 { " + body + " } }"
	elided := "firewall three-color-policer tcp1 { " + body + " }"

	dig := func(txt string) string {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs[0])
		}
		// LIVENESS, fatal: if the reference stops compiling, this cell has
		// fallen back into exactly the unanswerable state it exists to
		// resolve, and every comparison below would be vacuous.
		if _, err := CompileConfig(tr); err != nil {
			t.Fatalf("fixture no longer compiles at STRICT commit (%v). This "+
				"cell adjudicates a row the sweep could not answer because "+
				"its fixture did not compile; if this one stops compiling "+
				"too, the row is unadjudicated again rather than clean.", err)
		}
		c, err := CompileConfigLenient(tr)
		if err != nil || c == nil {
			t.Fatalf("lenient compile failed: %v", err)
		}
		c.Warnings = nil
		b, _ := json.Marshal(c)
		return string(b)
	}

	// The CAUSE, pinned. If this pair ever leaves the admission list, the
	// identity asserted below would break for a reason the comment above
	// would no longer explain.
	if !compactNormalizeInScope("firewall", "three-color-policer") {
		t.Errorf("`firewall three-color-policer` is no longer admitted to " +
			"compactNormalizeInScope. This cell records the pair as declined " +
			"BECAUSE the fold already handles it; with the admission gone " +
			"that reason is false and the row needs re-adjudicating rather " +
			"than staying declined (#8879).")
	}
	if len(dig(braced)) == 0 {
		t.Fatal("braced reference produced nothing to compare")
	}
	if got, want := dig(elided), dig(braced); got != want {
		t.Errorf("`firewall three-color-policer <name>` was adjudicated NOT A "+
			"DEFECT for #8879 on the strength of the two spellings compiling "+
			"IDENTICALLY, and they no longer do (%d vs %d bytes). Either a "+
			"real drop has appeared here, or the decline recorded in this "+
			"cell is now wrong -- it must not stay declined by inertia.",
			len(got), len(want))
	}
}

// TestElisionSuppressedAValidation8879 pins the most consequential thing found
// in the whole #8879 population: an elision that did not merely lose a value
// but SUPPRESSED THE COMMIT CHECK that would have reported the loss.
//
// `routing-options forwarding-table export <policy>` is validated at strict
// commit -- naming an undefined policy-statement is refused, and the error says
// why it matters ("the expected ECMP / consistent-hash load-balancing would be
// silently disabled"). Before this pair was admitted, the ELIDED spelling
// dropped the export leaf before that check ran, so:
//
//	braced, undefined policy   -> REJECTED at commit (correct)
//	elided, undefined policy   -> COMMITTED CLEAN     (fail-open)
//
// The operator who wrote the elided spelling got no value AND no complaint.
// That is the worst of the three shapes this issue found: a silent drop is bad,
// a silent drop that also disarms its own detector is worse, and it inverts the
// usual intuition that the stricter-looking spelling is the risky one.
//
// Measured two-sided when it was found: removing the admission restores the
// fail-open, so the admission is what closes it.
func TestElisionSuppressedAValidation8879(t *testing.T) {
	const undefined = "no-such-policy-7717"
	refused := func(txt string) bool {
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs[0])
		}
		_, err := CompileConfig(tree)
		return err != nil
	}
	braced := `routing-options { forwarding-table { export ` + undefined + `; } }`
	elided := `routing-options forwarding-table { export ` + undefined + `; }`

	// LIVENESS, fatal: if the braced arm stops being refused, the check this
	// cell is about no longer exists and the comparison below is vacuous --
	// it would pass trivially with both arms accepting.
	if !refused(braced) {
		t.Fatalf("the braced spelling with an UNDEFINED export policy is no " +
			"longer refused at strict commit. This cell asserts that the " +
			"elided spelling is refused TOO; with the check gone it would " +
			"pass for the wrong reason.")
	}
	if !refused(elided) {
		t.Error("the elided `routing-options forwarding-table export " +
			"<undefined>` spelling COMMITS CLEAN. The elision is dropping the " +
			"export leaf before the dangling-reference check can see it, so " +
			"the operator gets neither the load-balancing policy nor the " +
			"error explaining why -- ECMP is silently disabled (#8879).")
	}
}

// TestSystemServicesStaysUnadmitted8879 records the #8879 batch-6 DECLINE, and
// the way it was found matters more than the decline itself.
//
// `system services` measures like a textbook admission candidate: gate SILENT,
// zero warnings, both spellings accepted at strict commit, braced arm live
// against an empty config, elided arm dropping the whole stanza. Every column
// this issue adjudicates on said "admit it". It was admitted, and the FULL
// package suite -- not the scoped run, not the #8879 cells -- went red on
// TestPackedLoginBehindAnotherSystemStatementIsRejected_6966.
//
// The reason: with `system services` folded, `system services ssh login user
// alice class ops;` parses into the services container, `login` is not a child
// of `ssh`, and the stanza is dropped -- but strict commit now ACCEPTS it.
// That is #6966 re-opened: the CLI then runs with an empty class. Admitting
// this pair converts a loud rejection into a silent acceptance, which is the
// #8868 shape exactly, and no measurement taken on the pair ITSELF could have
// seen it because the damage is to a DIFFERENT statement that happens to pack
// behind it.
//
// The general lesson, worth more than this one pair: a pair's own before/after
// columns cannot see a regression in a sibling statement. Only the whole suite
// can, which is why #8879 batches gate on the full package rather than on the
// cells they add.
func TestSystemServicesStaysUnadmitted8879(t *testing.T) {
	// Errorf, not Fatalf: the property assertion below must still run so a
	// mutant admitting the pair is caught by both, not just by this one.
	if compactNormalizeInScope("system", "services") {
		t.Errorf("`system services` has been ADMITTED to " +
			"compactNormalizeInScope. It measures like a clean silent-drop " +
			"candidate, but folding it makes `system services ssh login user " +
			"<u> class <c>;` strict-ACCEPT while still dropping the login " +
			"stanza, re-opening #6966 (the CLI runs with an empty class). " +
			"Admitting it trades a loud rejection for a silent acceptance " +
			"(#8868).")
	}
	// The property behind the flag. Asserting the flag alone would pass if the
	// rejection moved somewhere else or disappeared entirely.
	txt := `system services ssh login user alice class ops;`
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("`system services ssh login user alice class ops;` is now " +
			"ACCEPTED at strict commit. The login stanza is not modelled " +
			"there, so it is dropped and the CLI runs with an empty class -- " +
			"the operator must be told, not silently obeyed (#6966/#8879).")
	}
}

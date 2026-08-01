package config

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// Tests for #6673: EMPTY authored values on the multi-value leaves #6659
// widened.
//
// WHY THIS FILE EXISTS SEPARATELY FROM compiler_multivalue_leaf_failopen_6659_test.go.
// That file sweeps each widened arm across the single, bracket, repeated and
// hierarchical-block spellings and compares them — a real matrix, and it found
// nothing wrong here. It never constructed a shape containing an EMPTY VALUE, so
// every divergence below was invisible to it BY CONSTRUCTION. A shape-matrix
// check only covers the shapes it enumerates; the omission is not visible in its
// results, which all pass. Every test here therefore names the empty spelling it
// exercises: `[ "" x ]`, `[ ]`, a bare `""`, and an empty value in a NON-FIRST
// slot, on BOTH the strict commit path and the tolerant load path.
//
// THE RULE THE ARMS FOLLOW, because it is not uniform and the non-uniformity is
// deliberate:
//
//   - A SELECTION leaf (`routing-options forwarding-table export`, `security nat
//     static ... match destination-address`) reads ONE value into a scalar that
//     installs, plus a list that only validators and diagnostics consume. Here
//     an empty value is MEANINGFUL: nodeVal selects it, and selecting an empty
//     value is how an operator blanks the rule. Both mechanisms keep it
//     (multiLeafAuthoredValues), so the list always contains what installs.
//   - A SET leaf (`security flow traceoptions flag`, `security nat proxy-arp ...
//     address`) installs every value it reads. An empty value is not a
//     selection, it is nothing, and the pre-#6659 compiler skipped it. Both
//     keep skipping it (firewallMatchValues / proxyARPAddressValues).
//   - A VALIDATED-LIST leaf (`event-options ... attributes-match`) is consumed
//     downstream by a checker that REJECTS a malformed entry. The pre-#6659
//     compiler kept empty entries here and the checker rejected them; dropping
//     them would silently convert a fail-CLOSED gate into a fail-OPEN one.
//   - A REPORTED-LIST leaf (`event-options ... then change-configuration
//     commands`) LOOKS like the previous category and is not. Nothing rejects an
//     empty command: eventengine.classifyPlan trims and SKIPS it, so the
//     remediation batch is identical either way and master never declined it
//     (pinned by TestClassifyPlan6673SkipsAnEmptyCommand in pkg/eventengine).
//     Its empty entry is kept for OUTPUT PARITY — the compiled list is hashed
//     into policySemanticRevision and printed verbatim by `show event-options`.
//
// Each test states which category its arm is in and what master did, because the
// justification for keeping an empty value and the justification for dropping
// one are both "match the pre-#6659 behaviour" and they point opposite ways.

// --- the invariant the selection arms rest on -------------------------------

// TestMultiLeafAuthoredValues6673MirrorsNodeVal pins the property that makes the
// scalar and the list agree: element 0 of the list is ALWAYS exactly what
// nodeVal selects, for every node shape.
//
// This is the direct guard for the drift Codex found. firewallMatchValues drops
// empty values while nodeVal selects them, so the two disagreed about which
// values exist: `destination-address 192.0.2.1/32` followed by
// `destination-address [ ]` left Match = "" while MatchAddresses held
// ["192.0.2.1/32"] — the installed value was absent from the list every
// validator and diagnostic reads. The invariant below makes that shape
// impossible to reconstruct rather than testing one instance of it.
func TestMultiLeafAuthoredValues6673MirrorsNodeVal(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *Node
		want []string
	}{
		{"packed single", &Node{Keys: []string{"export", "p1"}}, []string{"p1"}},
		{"packed bracket", &Node{Keys: []string{"export", "p1", "p2"}}, []string{"p1", "p2"}},
		{"packed empty first", &Node{Keys: []string{"export", "", "p1"}}, []string{"", "p1"}},
		{"packed empty last", &Node{Keys: []string{"export", "p1", ""}}, []string{"p1", ""}},
		{"packed bare empty", &Node{Keys: []string{"export", ""}}, []string{""}},
		{"no value slot at all", &Node{Keys: []string{"export"}}, []string{""}},
		{"block", &Node{Keys: []string{"export"}, Children: []*Node{
			{Keys: []string{"p1"}}, {Keys: []string{"p2"}},
		}}, []string{"p1", "p2"}},
		{"block empty first", &Node{Keys: []string{"export"}, Children: []*Node{
			{Keys: []string{""}}, {Keys: []string{"p1"}},
		}}, []string{"", "p1"}},
		{"block empty last", &Node{Keys: []string{"export"}, Children: []*Node{
			{Keys: []string{"p1"}}, {Keys: []string{""}},
		}}, []string{"p1", ""}},
		// A child with NO keys at all. nodeVal reads Children[0].Name(), which
		// is "" for it, so the reader must emit a value for it too — skipping
		// it would promote the keyed sibling into slot 0 and break the
		// invariant on exactly the shape nodeVal treats as empty.
		{"block keyless child first", &Node{Keys: []string{"export"}, Children: []*Node{
			{}, {Keys: []string{"p1"}},
		}}, []string{"", "p1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := multiLeafAuthoredValues(tc.node)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("multiLeafAuthoredValues = %q, want %q", got, tc.want)
			}
			if len(got) == 0 {
				t.Fatal("reader returned no values; the invariant needs a slot 0")
			}
			if got[0] != nodeVal(tc.node) {
				t.Fatalf("INVARIANT BROKEN: values[0] = %q but nodeVal = %q — "+
					"the scalar installs a value the list does not contain, so "+
					"every validator and diagnostic reading the list describes "+
					"a rule that is not the one in effect",
					got[0], nodeVal(tc.node))
			}
		})
	}
}

// TestNonEmptyValues6673 pins the cardinality helper: an empty slot is a
// selection, not an additional authored policy/prefix, so gates that reject a
// multi-valued list must not count it.
func TestNonEmptyValues6673(t *testing.T) {
	for _, tc := range []struct {
		in, want []string
	}{
		{[]string{""}, nil},
		{[]string{"", "p1"}, []string{"p1"}},
		{[]string{"p1", ""}, []string{"p1"}},
		{[]string{"p1", "p2"}, []string{"p1", "p2"}},
		{nil, nil},
	} {
		if got := nonEmptyValues(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("nonEmptyValues(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- SELECTION arm 1: routing-options forwarding-table export ---------------

const ftPolicies6673 = `policy-options {
    policy-statement p1 { term t { then { load-balance per-packet; accept; } } }
    policy-statement p2 { term t { then { load-balance consistent-hash; accept; } } }
}
`

// TestForwardingTableExport6673EmptyValueDoesNotChangeSelection is the direct
// guard for the reported defect.
//
// The scalar ForwardingTableExport is the ONLY renderer input — pkg/frr
// (resolveECMP) and pkg/daemon derive ECMP / consistent-hash from exactly this
// one policy name. An intermediate revision derived it from
// ForwardingTableExports[0] over an empty-FILTERED list, which silently promoted
// the next policy into the selected slot: `export [ "" p1 ];` selected NO policy
// before #6659 and selected p1 after, ENABLING an ECMP policy the operator had
// deliberately blanked. The scalar is back to the verbatim pre-#6659 statement
// (FindChild + nodeVal).
//
// Every case below is checked on BOTH paths. The tolerant path is where this
// actually bites: strict commit rejects a two-value list, but a restart or a
// peer config-sync only warns and loads, so a persisted config carrying an empty
// slot renders on whatever the scalar says.
func TestForwardingTableExport6673EmptyValueDoesNotChangeSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want string
	}{
		{"bracket, empty in FIRST slot", hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export [ "" p1 ]; } }`), ""},
		{"empty bracket then a policy", hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export [ ]; export p1; } }`), ""},
		{"bare empty value", hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export ""; } }`), ""},
		{"block, empty in FIRST slot", hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export { ""; p1; } } }`), ""},
		// Empty in a NON-first slot: the selected value is unaffected, which is
		// the control that says the guard above is about SELECTION and not
		// about empty values being rejected wholesale.
		{"bracket, empty in a NON-FIRST slot", hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export [ p1 "" ]; } }`), "p1"},
		{"policy then a bare empty sibling", hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export p1; export ""; } }`), "p1"},
		// GREEN CONTROL.
		{"single policy, no empty value", hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export p1; } }`), "p1"},
		// Flat set: two `set` lines, the first blanking the export.
		{"flat set, empty then a policy", setTree6659(t,
			`set policy-options policy-statement p1 term t then load-balance per-packet`,
			`set policy-options policy-statement p1 term t then accept`,
			`set routing-options forwarding-table export ""`,
			`set routing-options forwarding-table export p1`), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			strict, err := CompileConfig(tc.tree)
			if err != nil {
				t.Fatalf("strict compile: %v (none of these shapes authors two "+
					"policies, so the cardinality gate must not fire)", err)
			}
			if got := strict.RoutingOptions.ForwardingTableExport; got != tc.want {
				t.Fatalf("STRICT ForwardingTableExport = %q, want %q — the FRR "+
					"renderer installs exactly this policy", got, tc.want)
			}
			lenient, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			if got := lenient.RoutingOptions.ForwardingTableExport; got != tc.want {
				t.Fatalf("TOLERANT ForwardingTableExport = %q, want %q", got, tc.want)
			}
			// The list must contain the installed value, empty or not.
			exports := lenient.RoutingOptions.ForwardingTableExports
			if !containsValue6673(exports, tc.want) {
				t.Fatalf("ForwardingTableExports = %q does not contain the "+
					"installed policy %q; validators reading the list would "+
					"describe a policy that is not in effect", exports, tc.want)
			}
		})
	}
}

// TestForwardingTableExport6673RepeatedRootKeepsLastWins covers the other way
// the scalar can drift from element 0: compiler_dispatch.go calls
// compileRoutingOptions once per top-level `routing-options` root (the parser
// keeps repeated same-key blocks as separate siblings, a `load override`
// artifact), and the scalar assignment re-runs per root so the LAST root wins.
// The list APPENDS across roots, so element 0 is the FIRST root's policy.
//
// Selecting p1 here would swap consistent-hash for per-packet load balancing on
// a config that has been loading as p2 since before #6659.
func TestForwardingTableExport6673RepeatedRootKeepsLastWins(t *testing.T) {
	tree := hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export p1; } }
routing-options { forwarding-table { export p2; } }`)

	lenient, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got := lenient.RoutingOptions.ForwardingTableExport; got != "p2" {
		t.Fatalf("TOLERANT ForwardingTableExport = %q, want %q (LAST root wins, "+
			"as it did before #6659); element 0 of the list is %q and using it "+
			"here would render a different policy",
			got, "p2", lenient.RoutingOptions.ForwardingTableExports[0])
	}
	// Strict rejects the ambiguity, and the message must name the policy that
	// would actually render — not element 0.
	_, err = CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted two export policies across two " +
			"routing-options roots; the cardinality gate must see the list")
	}
	if !strings.Contains(err.Error(), `"p2"`) {
		t.Fatalf("strict rejection = %q; it must name %q, the policy that would "+
			"take effect, otherwise it sends the operator to the wrong line",
			err.Error(), "p2")
	}
}

// --- SELECTION arm 2: security nat static match destination-address ---------

// TestStaticNATMatch6673EmptyValueStaysInTheList is the direct guard for the
// scalar/list drift.
//
// The two mechanisms disagreed about whether an empty value exists: nodeVal
// selects it (leaving Match = "", an inert rule — exactly what the pre-#6659
// compiler did) while firewallMatchValues dropped it, so MatchAddresses could
// show an earlier prefix that is NOT the one installed. Everything that reads
// MatchAddresses is a validator or a diagnostic describing what installs, so a
// list missing the installed value makes all of them wrong at once.
//
// The assertion is the invariant, not one instance: Match must always appear in
// MatchAddresses.
func TestStaticNATMatch6673EmptyValueStaysInTheList(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tree      *ConfigTree
		wantMatch string
	}{
		// The reported repro: a valid prefix, then a statement that blanks it.
		{"flat set: valid prefix then an empty bracket", setTree6659(t,
			`set security nat static rule-set rs1 from zone untrust`,
			`set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32`,
			`set security nat static rule-set rs1 rule r1 match destination-address [ ]`,
			`set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32`), ""},
		{"flat set: valid prefix then a bare empty value", setTree6659(t,
			`set security nat static rule-set rs1 from zone untrust`,
			`set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32`,
			`set security nat static rule-set rs1 rule r1 match destination-address ""`,
			`set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32`), ""},
		{"bracket, empty in FIRST slot", hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ "" 192.0.2.1/32 ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`), ""},
		{"bracket, empty in a NON-FIRST slot", hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 192.0.2.1/32 "" ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`), "192.0.2.1/32"},
		{"block, empty in FIRST slot", hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address { ""; 192.0.2.1/32; } }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`), ""},
		{"bare empty value only", hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address ""; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`), ""},
		// GREEN CONTROL.
		{"single valid prefix", setTree6659(t,
			`set security nat static rule-set rs1 from zone untrust`,
			`set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32`,
			`set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32`), "192.0.2.1/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []struct {
				name    string
				compile func(*ConfigTree) (*Config, error)
			}{
				{"strict", CompileConfig},
				{"tolerant", CompileConfigLenient},
			} {
				cfg, err := path.compile(tc.tree)
				if err != nil {
					t.Fatalf("%s compile: %v (none of these shapes authors two "+
						"prefixes — an empty slot is a selection, not a second "+
						"prefix — so the cardinality gate must not fire)",
						path.name, err)
				}
				rule := cfg.Security.NAT.Static[0].Rules[0]
				if rule.Match != tc.wantMatch {
					t.Fatalf("%s: Match = %q, want %q — this is the only value "+
						"lowered to the dataplane (ExternalIP)",
						path.name, rule.Match, tc.wantMatch)
				}
				if !containsValue6673(rule.MatchAddresses, rule.Match) {
					t.Fatalf("%s: DRIFT — Match = %q is absent from "+
						"MatchAddresses = %q. Every consumer of MatchAddresses "+
						"is a validator or diagnostic describing what installs, "+
						"so a list without the installed value makes the "+
						"cardinality gate name a prefix that is not in effect "+
						"and makes the prefix loops 'cover' a value never "+
						"selected", path.name, rule.Match, rule.MatchAddresses)
				}
			}
		})
	}
}

// TestStaticNATMatch6673EmptySlotIsNotASecondPrefix pins that keeping empty
// values in the list did not invent a rejection. The cardinality gate counts
// only non-empty values, so a config that blanks a prefix still commits exactly
// as it did before #6659 — while a genuine two-prefix list is still rejected.
func TestStaticNATMatch6673EmptySlotIsNotASecondPrefix(t *testing.T) {
	blanked := setTree6659(t,
		`set security nat static rule-set rs1 from zone untrust`,
		`set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32`,
		`set security nat static rule-set rs1 rule r1 match destination-address [ ]`,
		`set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32`)
	if _, err := CompileConfig(blanked); err != nil {
		t.Fatalf("strict compile rejected a BLANKED single prefix: %v — an "+
			"empty slot is a selection, not a second authored prefix", err)
	}

	twoReal := setTree6659(t,
		`set security nat static rule-set rs1 from zone untrust`,
		`set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32`,
		`set security nat static rule-set rs1 rule r1 match destination-address 198.51.100.1/32`,
		`set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32`)
	err := CompileConfigMustFail6673(t, twoReal)
	if !strings.Contains(err.Error(), "198.51.100.1/32") {
		t.Fatalf("two-prefix rejection = %q; it must name the prefix that would "+
			"take effect (the LAST authored statement's value)", err.Error())
	}
}

// TestForwardingTableExport6673EmptySlotIsNotASecondPolicy is the export-arm
// sibling of the test above.
func TestForwardingTableExport6673EmptySlotIsNotASecondPolicy(t *testing.T) {
	blanked := hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export [ "" p1 ]; } }`)
	if _, err := CompileConfig(blanked); err != nil {
		t.Fatalf("strict compile rejected a single policy with a blanked slot: "+
			"%v — an empty slot is a selection, not a second authored policy", err)
	}

	twoReal := hierTree6659(t, ftPolicies6673+`
routing-options { forwarding-table { export [ p1 p2 ]; } }`)
	err := CompileConfigMustFail6673(t, twoReal)
	if !strings.Contains(err.Error(), `"p1"`) {
		t.Fatalf("two-policy rejection = %q; it must name %q, the policy the "+
			"renderer installs for this shape", err.Error(), "p1")
	}
}

// --- SET arms: flow trace flags and proxy-ARP addresses ---------------------

// TestFlowTraceFlags6673EmptyValueIsSkippedNotSuppressing proves this arm IS
// reachable with an empty value and that dropping it is correct here — the
// opposite call from the selection arms above, for a stated reason.
//
// Flags is a SET: every value it holds is installed, none of them is "selected",
// so an empty entry cannot express a choice and the pre-#6659 compiler skipped
// it (`if v := nodeVal(flagNode); v != ""`). What the pre-#6659 compiler ALSO
// did was let an empty value in the first slot suppress the WHOLE leaf, because
// nodeVal only ever looked at slot 0 — `flag [ "" session ];` enabled no tracing
// at all. That is the #6659 defect, and recovering `session` here is the fix
// working, not a selection change.
func TestFlowTraceFlags6673EmptyValueIsSkippedNotSuppressing(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{"bracket, empty in FIRST slot", hierTree6659(t, `
security { flow { traceoptions { file flow.log; flag [ "" session ]; } } }`), []string{"session"}},
		{"bracket, empty in a NON-FIRST slot", hierTree6659(t, `
security { flow { traceoptions { file flow.log; flag [ session "" ]; } } }`), []string{"session"}},
		{"block, empty in FIRST slot", hierTree6659(t, `
security { flow { traceoptions { file flow.log; flag { ""; session; } } } }`), []string{"session"}},
		{"empty bracket then a flag", hierTree6659(t, `
security { flow { traceoptions { file flow.log; flag [ ]; flag session; } } }`), []string{"session"}},
		{"bare empty value only", hierTree6659(t, `
security { flow { traceoptions { file flow.log; flag ""; } } }`), nil},
		{"single flag (CONTROL)", hierTree6659(t, `
security { flow { traceoptions { file flow.log; flag session; } } }`), []string{"session"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []struct {
				name    string
				compile func(*ConfigTree) (*Config, error)
			}{
				{"strict", CompileConfig},
				{"tolerant", CompileConfigLenient},
			} {
				cfg, err := path.compile(tc.tree)
				if err != nil {
					t.Fatalf("%s compile: %v (an empty flag value is not an "+
						"unknown flag and must not be rejected)", path.name, err)
				}
				got := cfg.Security.Flow.Traceoptions.Flags
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%s: Flags = %q, want %q", path.name, got, tc.want)
				}
				for _, f := range got {
					if f == "" {
						t.Fatal("an empty flag reached Flags; pkg/logging/trace.go " +
							"would treat the leaf as carrying an implemented flag " +
							"and skip installing the defaults")
					}
				}
			}
		})
	}
}

// TestProxyARPAddresses6673EmptyValueIsSkippedNotSuppressing is the proxy-ARP
// sibling: also a SET leaf, same call, same pre-#6659 first-slot suppression.
// An empty entry must not reach Addresses — proxyarp.go would build "/32" from
// it and log a bounded parse warning on every apply.
func TestProxyARPAddresses6673EmptyValueIsSkippedNotSuppressing(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{"bracket, empty in FIRST slot", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address [ "" 192.0.2.1 ]; } } } }`),
			[]string{"192.0.2.1/32"}},
		{"bracket, empty in a NON-FIRST slot", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address [ 192.0.2.1 "" ]; } } } }`),
			[]string{"192.0.2.1/32"}},
		{"block, empty in FIRST slot", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address { ""; 192.0.2.1; } } } } }`),
			[]string{"192.0.2.1/32"}},
		{"empty bracket then an address", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address [ ]; address 192.0.2.1; } } } }`),
			[]string{"192.0.2.1/32"}},
		{"bare empty value only", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address ""; } } } }`), nil},
		{"single address (CONTROL)", hierTree6659(t, `
security { nat { proxy-arp { interface ge-0/0/0 { address 192.0.2.1; } } } }`),
			[]string{"192.0.2.1/32"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []struct {
				name    string
				compile func(*ConfigTree) (*Config, error)
			}{
				{"strict", CompileConfig},
				{"tolerant", CompileConfigLenient},
			} {
				cfg, err := path.compile(tc.tree)
				if err != nil {
					t.Fatalf("%s compile: %v (an empty address value is not a "+
						"malformed address and must not be rejected)", path.name, err)
				}
				got := cfg.Security.NAT.ProxyARP[0].Addresses
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%s: Addresses = %q, want %q", path.name, got, tc.want)
				}
				for _, a := range got {
					if a == "" || a == "/32" {
						t.Fatalf("an empty address reached Addresses as %q; the "+
							"proxyarp installer would fail netip.ParsePrefix and "+
							"log a warning on every apply", a)
					}
				}
			}
		})
	}
}

// --- VALIDATED-LIST arms: event-options ------------------------------------

// TestEventAttributesMatch6673EmptyExprStaysRejected is a regression guard, not
// a new gate.
//
// Before #6659 the block spelling appended strings.Join(amChild.Keys, " ")
// UNCONDITIONALLY, so `attributes-match { ""; e1.owner matches X; }` produced an
// "" entry and validateEventAttributesMatch hard-rejected it at strict commit.
// Skipping empty expressions in the widened reader silently ACCEPTED that same
// config — a fail-CLOSED commit gate turned fail-OPEN, which is precisely the
// defect class this arm was widened to fix. An event policy whose constraints
// are silently discarded fires on every occurrence of the event.
//
// The packed spelling is now rejected too. That is DELIBERATE and is the parity
// this helper exists for: the two spellings of one leaf must not disagree about
// whether a config is valid. Before #6659 the packed spelling compiled to
// nothing at all, so it had no behaviour worth preserving. The tolerant load /
// peer-sync path downgrades both to a warning and still boots.
func TestEventAttributesMatch6673EmptyExprStaysRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"block, empty in FIRST slot", hierTree6659(t, `
event-options { policy pA { events e1; attributes-match { ""; e1.test-owner matches Comcast; } } }`)},
		{"block, empty in a NON-FIRST slot", hierTree6659(t, `
event-options { policy pA { events e1; attributes-match { e1.test-owner matches Comcast; ""; } } }`)},
		{"packed, bare empty value", hierTree6659(t, `
event-options { policy pA { events e1; attributes-match ""; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(tc.tree); err == nil {
				t.Fatal("strict commit ACCEPTED an empty attributes-match " +
					"expression; before #6659 the block spelling was rejected " +
					"as a malformed match expression, and dropping the empty " +
					"entry converts that fail-closed gate into a fail-open one " +
					"— the policy then fires on every occurrence of the event")
			}
			lenient, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("tolerant compile must still boot: %v", err)
			}
			if !anyWarningContains6673(lenient, "attributes-match") {
				t.Fatalf("tolerant path produced no attributes-match warning; "+
					"warnings = %q", lenient.Warnings)
			}
		})
	}

	// GREEN CONTROLS: a leaf carrying no value slot at all is "no constraint
	// authored", not an empty expression, and must stay acceptable.
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"no value slot at all", hierTree6659(t, `
event-options { policy pA { events e1; attributes-match; } }`)},
		{"well-formed expression", hierTree6659(t, `
event-options { policy pA { events e1; attributes-match e1.test-owner matches Comcast; } }`)},
	} {
		t.Run(tc.name+" (CONTROL)", func(t *testing.T) {
			if _, err := CompileConfig(tc.tree); err != nil {
				t.Fatalf("strict commit rejected a valid config: %v", err)
			}
		})
	}
}

// TestEventChangeConfigCommands6673EmptyCommandStaysInTheBatch is the sibling
// regression guard — but it guards OUTPUT PARITY, not a fail-closed gate, and
// the distinction is deliberate.
//
// Before #6659 the block spelling appended cmdChild.Name() unconditionally, so
// `commands { ""; "set system host-name foo"; }` compiled to ["", "set system
// host-name foo"]. This test pins that list. Unlike attributes-match, no
// downstream checker rejects the empty entry: eventengine.classifyPlan trims
// and SKIPS an empty command (it has since the engine's first commit), so the
// remediation batch runs identically either way. What filtering would change is
// the compiled policy itself — policySemanticRevision hashes every
// ThenCommands entry, and `show event-options` prints the list verbatim — so
// the reader reports what was authored and leaves the judgement to the
// consumer that already makes it.
//
// The packed spelling now behaves the same way, which is the parity this helper
// exists for; before #6659 it compiled to nothing.
func TestEventChangeConfigCommands6673EmptyCommandStaysInTheBatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{"block, empty in FIRST slot", hierTree6659(t, `
event-options { policy pA { events e1; then { change-configuration {
    commands { ""; "set system host-name foo"; } } } } }`),
			[]string{"", "set system host-name foo"}},
		{"block, empty in a NON-FIRST slot", hierTree6659(t, `
event-options { policy pA { events e1; then { change-configuration {
    commands { "set system host-name foo"; ""; } } } } }`),
			[]string{"set system host-name foo", ""}},
		{"packed bracket, empty in FIRST slot", hierTree6659(t, `
event-options { policy pA { events e1; then { change-configuration {
    commands [ "" "set system host-name foo" ]; } } } }`),
			[]string{"", "set system host-name foo"}},
		{"packed, bare empty value", hierTree6659(t, `
event-options { policy pA { events e1; then { change-configuration {
    commands ""; } } } }`), []string{""}},
		{"single command (CONTROL)", hierTree6659(t, `
event-options { policy pA { events e1; then { change-configuration {
    commands "set system host-name foo"; } } } }`),
			[]string{"set system host-name foo"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []struct {
				name    string
				compile func(*ConfigTree) (*Config, error)
			}{
				{"strict", CompileConfig},
				{"tolerant", CompileConfigLenient},
			} {
				cfg, err := path.compile(tc.tree)
				if err != nil {
					t.Fatalf("%s compile: %v", path.name, err)
				}
				got := cfg.EventOptions[0].ThenCommands
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("%s: ThenCommands = %q, want %q — an empty entry "+
						"must survive so the compiled policy stays identical "+
						"to master's (semantic revision + show event-options); "+
						"the engine skips it either way",
						path.name, got, tc.want)
				}
			}
		})
	}
}

// --- diagnostics describe what actually installs ---------------------------

// TestStaticNATMatch6673TailWarningDoesNotClaimTheRuleDropped guards the
// tolerant-path suffix.
//
// The shared `emit` helper appends "(ignored: rule dropped by dataplane until
// corrected)". That is true when the offending value is the one the compiler
// SELECTED — the dataplane cannot parse it and the whole rule disappears. It is
// FALSE for any other authored value: only rule.Match is ever lowered
// (nat_static.go sets ExternalIP from it), so a malformed value in a
// non-selected slot never reaches the dataplane, nothing is dropped, and the
// rule keeps translating. Telling an operator their published service is down
// when it is up is the same class of defect as the silence #6659 removed.
func TestStaticNATMatch6673TailWarningDoesNotClaimTheRuleDropped(t *testing.T) {
	// `[ good bogus ]` — one node, so nodeVal selects the FIRST value and the
	// rule installs on it. Strict rejects the two-value list first, so the tail
	// complaint is reachable only on the tolerant path, which is exactly where
	// the operator reads it.
	tolerant := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 192.0.2.1/32 not-an-address ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
	cfg, err := CompileConfigLenient(tolerant)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].Match; got != "192.0.2.1/32" {
		t.Fatalf("Match = %q, want %q — the premise of this test is that the "+
			"VALID value is the one installed", got, "192.0.2.1/32")
	}
	// Key on the PREFIX-VALIDITY message specifically. Several warnings mention
	// "not-an-address" — the cardinality gate lists the whole MatchAddresses
	// slice — and that one legitimately carries no dataplane-effect suffix, so
	// matching on the value alone would pass no matter what this loop emits.
	w := findWarning6673(t, cfg, "not-an-address", "is not a valid IP address or CIDR prefix")
	if strings.Contains(w, "rule dropped by dataplane") {
		t.Fatalf("tolerant warning for a NON-SELECTED value claims the rule was "+
			"dropped:\n  %s\nThe rule installs on %q and keeps translating; only "+
			"the unused value is ignored.", w, "192.0.2.1/32")
	}
	if !strings.Contains(w, `"192.0.2.1/32"`) {
		t.Fatalf("tolerant warning does not name the value that IS installed:\n  %s", w)
	}

	// The mirror case: when the malformed value is the SELECTED one, the rule
	// really is dropped and the warning must still say so.
	selected := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address not-an-address; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
	cfg2, err := CompileConfigLenient(selected)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	w2 := findWarning6673(t, cfg2, "not-an-address", "is not a valid IP address or CIDR prefix")
	if !strings.Contains(w2, "rule dropped by dataplane") {
		t.Fatalf("tolerant warning for the SELECTED malformed value must still "+
			"say the rule is dropped, because it is:\n  %s", w2)
	}
}

// TestStaticNATMatch6673NonHostTailWarningDoesNotClaimTheRuleDropped is the
// same guard for the host-mask loop, which shares the suffix helper.
func TestStaticNATMatch6673NonHostTailWarningDoesNotClaimTheRuleDropped(t *testing.T) {
	tolerant := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 192.0.2.1/32 198.51.100.0/24 ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
	cfg, err := CompileConfigLenient(tolerant)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].Match; got != "192.0.2.1/32" {
		t.Fatalf("Match = %q, want %q", got, "192.0.2.1/32")
	}
	// Key on the HOST-ROUTE message specifically, for the same reason as above.
	w := findWarning6673(t, cfg, "198.51.100.0/24", "must be a host route")
	if strings.Contains(w, "rule dropped by dataplane") {
		t.Fatalf("tolerant warning for a NON-SELECTED non-host prefix claims the "+
			"rule was dropped:\n  %s\nThe rule installs on %q.", w, "192.0.2.1/32")
	}
	if !strings.Contains(w, `"192.0.2.1/32"`) {
		t.Fatalf("tolerant warning does not name the value that IS installed:\n  %s", w)
	}

	// Mirror: when the non-host prefix is the SELECTED value the rule really is
	// dropped, and the message must still say so.
	selected := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address 198.51.100.0/24; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
	cfg2, err := CompileConfigLenient(selected)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	w2 := findWarning6673(t, cfg2, "198.51.100.0/24", "must be a host route")
	if !strings.Contains(w2, "rule dropped by dataplane") {
		t.Fatalf("tolerant warning for the SELECTED non-host prefix must still "+
			"say the rule is dropped, because it is:\n  %s", w2)
	}
}

// TestStaticNATMatch6673EmptySelectionSuffixDoesNotClaimAnActiveRule guards the
// third branch of emitMatchAddr.
//
// The "not the one the rule installs — %q is, and it stays active" wording
// assumes the SELECTED value is a real prefix. It need not be: an authored blank
// can be the selection (`destination-address [ "" bogus ]` — nodeVal takes the
// leading empty slot), and the message then renders as `"" is, and it stays
// active`, which translates nothing and reassures the operator about a rule that
// does not exist. rule.Match == "" lowers ExternalIP: "" and the Rust
// parse_nat_prefix("") returns None, so from_snapshots drops the whole mapping.
func TestStaticNATMatch6673EmptySelectionSuffixDoesNotClaimAnActiveRule(t *testing.T) {
	tolerant := hierTree6659(t, `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ "" not-an-address ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`)
	cfg, err := CompileConfigLenient(tolerant)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got := cfg.Security.NAT.Static[0].Rules[0].Match; got != "" {
		t.Fatalf("Match = %q, want %q — the premise of this test is that the "+
			"SELECTED value is the authored blank", got, "")
	}
	w := findWarning6673(t, cfg, "not-an-address", "is not a valid IP address or CIDR prefix")
	if strings.Contains(w, "stays active") {
		t.Fatalf("tolerant warning tells the operator a rule stays active when "+
			"the selected match destination-address is EMPTY and the rule is "+
			"dropped:\n  %s", w)
	}
	if !strings.Contains(w, "EMPTY") {
		t.Fatalf("tolerant warning does not say the selection is empty:\n  %s", w)
	}
}

// TestStaticNATMatch6673NonSelectedSuffixChecksTheSelectedValueToo guards the
// mirror of the branch above: emitMatchAddr's "%q is, and it stays active" said
// the rule keeps translating without ever checking that the SELECTED value would
// itself install.
//
// With two malformed `destination-address` siblings the two loops contradicted
// each other on the SAME rule — the warning for bad-old announced that
// bad-selected "stays active", and the very next warning, for bad-selected (the
// value that IS selected), correctly said the dataplane drops the rule. Only one
// of those can be true. rule.Match lowers to StaticNATRuleSnapshot.ExternalIP,
// so when it does not parse the whole mapping is dropped and NOTHING stays
// active.
// selectedInstalls has THREE legs — the literal-address parse, the block-pair
// exemption, and the host-mask rule — and every one is exercised here. Covering
// only the parse leg leaves the other two free to misword: the host-mask leg
// would claim "stays active" about a selected value the dataplane drops for a
// non-host mask, and dropping the block-pair exemption would claim "invalid too"
// about a legal subnet 1:1 that installs perfectly well.
func TestStaticNATMatch6673NonSelectedSuffixChecksTheSelectedValueToo(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cfg          string
		wantSelected string
		// old/sel are the substrings that identify each value's own warning.
		oldSub, selSub string
		// selectedStaysActive inverts the assertion: the selected value is
		// installable, so the non-selected complaint SHOULD say it stays
		// active and the selected value earns no complaint of its own.
		selectedStaysActive bool
	}{
		{
			// Parse leg: neither value is a literal address.
			name: "selected value does not parse",
			cfg: `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address bad-old; destination-address bad-selected; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`,
			wantSelected: "bad-selected",
			oldSub:       `destination-address "bad-old" is not a valid`,
			selSub:       `destination-address "bad-selected" is not a valid`,
		},
		{
			// Host-mask leg: both values parse but neither is a host route,
			// and neither forms a block pair with the /32 `then` prefix — so
			// the dataplane drops the rule on the SELECTED one all the same.
			name: "selected value parses but is a non-host mask",
			cfg: `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address 198.51.100.0/24; destination-address 203.0.113.0/24; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`,
			wantSelected: "203.0.113.0/24",
			oldSub:       `destination-address "198.51.100.0/24" must be a host route`,
			selSub:       `destination-address "203.0.113.0/24" must be a host route`,
		},
		{
			// Block-pair leg (CONTROL, opposite direction): the selected value
			// is a non-host mask that DOES form a legal equal-length subnet 1:1
			// with the `then` prefix (#3031), so the dataplane installs it and
			// the non-selected complaint must still say it stays active.
			// Without the exemption this case would be mis-worded the other
			// way, telling the operator a working rule is dropped.
			name: "selected value is a legal block pair and does install",
			cfg: `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address 203.0.113.0/25; destination-address 198.51.100.0/24; }
              then { static-nat prefix 10.0.0.0/24; } } } } } }`,
			wantSelected:        "198.51.100.0/24",
			oldSub:              `destination-address "203.0.113.0/25" must be a host route`,
			selectedStaysActive: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(hierTree6659(t, tc.cfg))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.Match != tc.wantSelected {
				t.Fatalf("Match = %q, want %q — the premise of this case is that "+
					"the LAST authored sibling is selected", rule.Match, tc.wantSelected)
			}
			wOld := findWarning6673(t, cfg, tc.oldSub)
			if tc.selectedStaysActive {
				if !strings.Contains(wOld, "stays active") {
					t.Fatalf("the selected value %q is a legal block pair with the "+
						"`then` prefix and installs, so the complaint about the "+
						"non-selected value must say it stays active:\n  %s",
						rule.Match, wOld)
				}
				if strings.Contains(wOld, "invalid too") {
					t.Fatalf("the complaint about the non-selected value calls the "+
						"selected value %q invalid, but it is a legal subnet 1:1 "+
						"that the dataplane installs:\n  %s", rule.Match, wOld)
				}
				return
			}
			if strings.Contains(wOld, "stays active") {
				t.Fatalf("the warning for the NON-selected value says the rule "+
					"stays active on %q, but that value is invalid too and the "+
					"dataplane drops the rule — the two warnings on this rule "+
					"contradict each other:\n  %s", rule.Match, wOld)
			}
			if !strings.Contains(wOld, "invalid too") {
				t.Fatalf("the warning for the NON-selected value does not say "+
					"the selected value is invalid too:\n  %s", wOld)
			}
			// The selected value's OWN warning is unchanged: it really does drop
			// the rule. Select it by its OPERAND — the non-selected warning
			// above also quotes the selected value, in its suffix.
			wSel := findWarning6673(t, cfg, tc.selSub)
			if !strings.Contains(wSel, "(ignored: rule dropped by dataplane until corrected)") {
				t.Fatalf("the warning for the SELECTED value must still say the "+
					"rule is dropped, because it is:\n  %s", wSel)
			}
		})
	}
}

// TestCardinalityGates6673EmptySelectionSaysNoneTakesEffect guards both
// multi-value cardinality gates against an authored blank in the SELECTED slot.
//
// Each gate counts only NON-EMPTY values (so `[ "" p1 ]` stays acceptable) and
// then names the selected scalar. Those two rules combine badly: `[ "" p1 p2 ]`
// counts two, trips the gate, and the scalar is the blank — so the message read
// `only "" would take effect`, naming a policy/prefix that does not exist and
// implying one of the two is still honoured. Neither is: an empty
// forwarding-table export renders no ECMP policy at all, and an empty
// ExternalIP makes the Rust parse drop the whole static-NAT mapping. The
// tolerant wrappers said "exactly ONE"/"only ONE" for the same reason.
func TestCardinalityGates6673EmptySelectionSaysNoneTakesEffect(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cfg        string
		wantSubs   []string
		rejectSubs []string
	}{
		{
			name: "forwarding-table export",
			cfg: `
policy-options { policy-statement p1 { then accept; } policy-statement p2 { then accept; } }
routing-options { forwarding-table { export [ "" p1 p2 ]; } }`,
			wantSubs:   []string{"selected value is EMPTY", "NONE of them takes effect"},
			rejectSubs: []string{`only "" would take effect`},
		},
		{
			name: "static NAT match destination-address",
			cfg: `
security { nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ "" 192.0.2.1/32 198.51.100.1/32 ]; }
              then { static-nat prefix 10.0.0.1/32; } } } } } }`,
			wantSubs:   []string{"selected value is EMPTY", "NONE of them takes effect", "drops the rule"},
			rejectSubs: []string{`only "" would take effect`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CompileConfigMustFail6673(t, hierTree6659(t, tc.cfg))
			got := err.Error()
			for _, sub := range tc.wantSubs {
				if !strings.Contains(got, sub) {
					t.Fatalf("strict error does not contain %q:\n  %s", sub, got)
				}
			}
			for _, sub := range tc.rejectSubs {
				if strings.Contains(got, sub) {
					t.Fatalf("strict error contains %q — it names a value that "+
						"does not exist and implies one of the listed values is "+
						"still honoured:\n  %s", sub, got)
				}
			}
			// The tolerant wrapper must not re-assert "exactly/only ONE" either.
			cfg, lerr := CompileConfigLenient(hierTree6659(t, tc.cfg))
			if lerr != nil {
				t.Fatalf("tolerant compile: %v", lerr)
			}
			w := findWarning6673(t, cfg, "LIST FORM IS NOT SUPPORTED")
			for _, wrong := range []string{"exactly ONE policy", "only ONE prefix is honoured"} {
				if strings.Contains(w, wrong) {
					t.Fatalf("tolerant wrapper claims %q while the error it wraps "+
						"says NONE takes effect:\n  %s", wrong, w)
				}
			}
		})
	}
}

// TestForwardingTableExport6673TolerantWarningDoesNotNameTheWrongSlot guards the
// wrapper text against the error it wraps.
//
// The wrapper used to open "only the FIRST policy is honoured by the ECMP
// render". The renderer uses the SELECTED policy, and across two top-level
// `routing-options` roots the last root wins — so for `export p1` then
// `export p2` the wrapper claimed p1 while the very error it embeds correctly
// says only "p2" would take effect. One warning, two answers.
func TestForwardingTableExport6673TolerantWarningDoesNotNameTheWrongSlot(t *testing.T) {
	tolerant := hierTree6659(t, `
policy-options { policy-statement p1 { then accept; } policy-statement p2 { then accept; } }
routing-options { forwarding-table { export p1; } }
routing-options { forwarding-table { export p2; } }`)
	cfg, err := CompileConfigLenient(tolerant)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got := cfg.RoutingOptions.ForwardingTableExport; got != "p2" {
		t.Fatalf("ForwardingTableExport = %q, want %q — the premise of this "+
			"test is that the LAST root wins", got, "p2")
	}
	w := findWarning6673(t, cfg, "LIST FORM IS NOT SUPPORTED")
	if !strings.Contains(w, `"p2"`) {
		t.Fatalf("tolerant warning does not name the policy that actually "+
			"renders:\n  %s", w)
	}
	for _, wrong := range []string{"FIRST policy", "first policy"} {
		if strings.Contains(w, wrong) {
			t.Fatalf("tolerant warning claims %q while the error it wraps says "+
				"only %q takes effect — the wrapper must not name a slot:\n  %s",
				wrong, "p2", w)
		}
	}
}

// TestForwardingTableExport6673DanglingRefNamesThePerValueConsequence guards
// #6715.
//
// #6659 widened this gate from the rendering scalar to EVERY authored value, so
// a NON-rendering token can now reach it. The consequence text did not widen
// with it: `export [ p1 nosuch ]` reported that "the expected ECMP /
// consistent-hash load-balancing would be silently disabled" while p1 renders
// and ECMP resolves fine. Master could not produce that message because it only
// ever passed the scalar. Same fix as the static-NAT side (emitMatchAddr):
// decide which value the reference is before naming the consequence.
func TestForwardingTableExport6673DanglingRefNamesThePerValueConsequence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cfg        string
		wantSubs   []string
		rejectSubs []string
	}{
		{
			name: "dangling value is NOT the one that renders",
			cfg: `
policy-options { policy-statement p1 { then accept; } }
routing-options { forwarding-table { export [ p1 nosuch ]; } }`,
			wantSubs:   []string{`"nosuch"`, `"p1" is, and it still resolves`},
			rejectSubs: []string{"silently disabled"},
		},
		{
			name: "dangling value IS the one that renders",
			cfg: `
routing-options { forwarding-table { export nosuch; } }`,
			wantSubs:   []string{`"nosuch"`, "silently disabled"},
			rejectSubs: []string{"still resolves"},
		},
		{
			name: "dangling value with an EMPTY selection",
			cfg: `
routing-options { forwarding-table { export [ "" nosuch ]; } }`,
			wantSubs:   []string{`"nosuch"`, "EMPTY"},
			rejectSubs: []string{"silently disabled", "still resolves"},
		},
		{
			name: "two roots — the LAST root's dangling policy is the one that renders",
			cfg: `
policy-options { policy-statement p1 { then accept; } }
routing-options { forwarding-table { export p1; } }
routing-options { forwarding-table { export nosuch; } }`,
			wantSubs:   []string{`"nosuch"`, "silently disabled"},
			rejectSubs: []string{"still resolves"},
		},
		{
			// #6673: the "still resolves" branch ASSUMED the selected policy
			// resolves without checking it. The loop reports whichever value it
			// reaches first, and that is usually NOT the selected one: here the
			// plural is [missing-old, missing-selected] and the scalar is
			// missing-selected, so the diagnostic for missing-old reassured the
			// operator that missing-selected "still resolves" — while it is
			// undefined too and ECMP is disabled. The verdict was already right
			// (strict rejects, tolerant warns); the stated consequence was
			// backwards, and on the tolerant path the consequence is all the
			// operator gets.
			name: "BOTH the reported value and the selected policy are undefined",
			cfg: `
routing-options { forwarding-table { export missing-old; } }
routing-options { forwarding-table { export missing-selected; } }`,
			wantSubs: []string{
				`"missing-old"`,
				`"missing-selected" is, but that policy is UNDEFINED as well`,
				"silently disabled",
			},
			rejectSubs: []string{"still resolves"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CompileConfigMustFail6673(t, hierTree6659(t, tc.cfg))
			got := err.Error()
			for _, sub := range tc.wantSubs {
				if !strings.Contains(got, sub) {
					t.Fatalf("strict error does not contain %q:\n  %s", sub, got)
				}
			}
			for _, sub := range tc.rejectSubs {
				if strings.Contains(got, sub) {
					t.Fatalf("strict error contains %q, which is false for this "+
						"shape:\n  %s", sub, got)
				}
			}
		})
	}
}

// --- normalisation: the readers report what was authored --------------------

// TestEventOptions6673ValuesAreStoredVerbatim guards the deliberate absence of
// strings.TrimSpace in both event-options readers.
//
// The lexer preserves whitespace INSIDE a quoted token, so master compiled the
// padded string and so must this. Trimming here is invisible to the matcher
// (ParseEventAttributesMatch trims every field it splits out) and to the engine
// (classifyPlan trims each command), which is exactly what makes it easy to add
// by accident. #6673: what it changes is NOT the persisted config — configstore
// writes the AST candidate tree, and these readers return new strings without
// touching the node — but the COMPILED policy and its consumers: the policy's
// semantic revision, and what `show event-options` prints back at the operator.
func TestEventOptions6673ValuesAreStoredVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      string
		wantAM   []string
		wantCmds []string
	}{
		{
			name: "block spelling",
			cfg: `
event-options { policy pA { events e1;
    attributes-match { "  e1.test-owner matches Comcast  "; }
    then { change-configuration { commands { "  set system host-name foo  "; } } } } }`,
			wantAM:   []string{"  e1.test-owner matches Comcast  "},
			wantCmds: []string{"  set system host-name foo  "},
		},
		{
			name: "packed spelling",
			cfg: `
event-options { policy pA { events e1;
    attributes-match "  e1.test-owner matches Comcast  ";
    then { change-configuration { commands "  set system host-name foo  "; } } } }`,
			wantAM:   []string{"  e1.test-owner matches Comcast  "},
			wantCmds: []string{"  set system host-name foo  "},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(hierTree6659(t, tc.cfg))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			ep := cfg.EventOptions[0]
			if !reflect.DeepEqual(ep.AttributesMatch, tc.wantAM) {
				t.Fatalf("AttributesMatch = %q, want %q — the reader must not "+
					"normalise an authored expression; master stored it verbatim",
					ep.AttributesMatch, tc.wantAM)
			}
			if !reflect.DeepEqual(ep.ThenCommands, tc.wantCmds) {
				t.Fatalf("ThenCommands = %q, want %q — the reader must not "+
					"normalise an authored command; classifyPlan trims it itself",
					ep.ThenCommands, tc.wantCmds)
			}
		})
	}
}

// TestProxyARPAddresses6673MalformedRangeInstallsExactlyWhatMasterInstalled
// binds the acceptance criterion this arm is actually held to: not "does the
// compiler return the same VERDICT as master" but "does the DATAPLANE install
// the same set of proxy addresses as master".
//
// A malformed range — a `to` that neither of the caller's two range branches
// consumed — falls through to the value reader. The first spelling of this fold
// merely skipped the `to` TOKEN there, which kept the compile verdict identical
// to master and was verified on that basis alone. It was still a runtime
// regression: dropping the keyword PROMOTED the range's surviving endpoint to a
// standalone proxy address. `address [ to 192.0.2.1 ]` compiled ["to/32"] on
// master, which netip.ParsePrefix rejects at pkg/dataplane/proxyarp.go, so
// master installed NOTHING; the token-skip spelling compiled ["192.0.2.1/32"],
// and the installer then added an NTF_PROXY neighbour and enabled the interface
// proxy responder. The appliance answered ARP for the orphan high endpoint of a
// broken range — traffic drawn to this box that master never claimed.
//
// wantInstalled below is therefore MASTER's installed set, measured against
// origin/master with the installer's own netip.ParsePrefix gate, and the test
// asserts the installed set as well as the compiled list. The `to` at a
// non-range slot cases (`[ .1 .2 to .9 ]`) are the same defect one step further
// out: the token-skip spelling installed .2 AND .9 on top of master's .1.
//
// Both directions matter, so the corpus keeps the shapes where master DID
// install (`[ .1 to ]`, `{ .5; to; }`): going inert there would be the opposite
// regression, dropping an address master answered for. And the strict verdict is
// asserted alongside, because the other failure mode is an invented rejection —
// materialising "to/32" makes validateProxyARPAddressesStrict hard-reject a
// config master accepted.
func TestProxyARPAddresses6673MalformedRangeInstallsExactlyWhatMasterInstalled(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
		want []string // compiled ProxyARPEntry.Addresses
		// wantInstalled is what origin/master's compiled output survives
		// netip.ParsePrefix to install. It must match head's exactly.
		wantInstalled []string
	}{
		{"bracket leading with the keyword", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ to 192.0.2.1 ]; } } } }`,
			nil, nil},
		{"block with a keyword-only child", `
security { nat { proxy-arp { interface ge-0-0-0 { address { to; 192.0.2.5; } } } } }`,
			nil, nil},
		{"keyword-only block", `
security { nat { proxy-arp { interface ge-0-0-0 { address { to; } } } } }`,
			nil, nil},
		{"bare keyword", `
security { nat { proxy-arp { interface ge-0-0-0 { address to; } } } }`,
			nil, nil},
		{"keyword ahead of a CIDR", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ to 192.0.2.0/30 ]; } } } }`,
			nil, nil},
		{"keyword past the range slot", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ 192.0.2.1 192.0.2.2 to 192.0.2.9 ]; } } } }`,
			[]string{"192.0.2.1/32"}, []string{"192.0.2.1/32"}},
		{"keyword further past the range slot", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ 192.0.2.1 192.0.2.2 192.0.2.3 to 192.0.2.9 ]; } } } }`,
			[]string{"192.0.2.1/32"}, []string{"192.0.2.1/32"}},
		{"dangling trailing keyword still installs the low endpoint", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ 192.0.2.1 to ]; } } } }`,
			[]string{"192.0.2.1/32"}, []string{"192.0.2.1/32"}},
		{"block address then dangling keyword still installs", `
security { nat { proxy-arp { interface ge-0-0-0 { address { 192.0.2.5; to; } } } } }`,
			[]string{"192.0.2.5/32"}, []string{"192.0.2.5/32"}},
		{"well-formed sibling beside a malformed range", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ to 192.0.2.1 ]; address 192.0.2.9; } } } }`,
			[]string{"192.0.2.9/32"}, []string{"192.0.2.9/32"}},
		{"well-formed range still expands (CONTROL)", `
security { nat { proxy-arp { interface ge-0-0-0 { address 192.0.2.1 to 192.0.2.3; } } } }`,
			[]string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"},
			[]string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"}},
		{"plain list keeps the #6659 widening (CONTROL)", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ 192.0.2.1 192.0.2.2 ]; } } } }`,
			[]string{"192.0.2.1/32", "192.0.2.2/32"},
			[]string{"192.0.2.1/32", "192.0.2.2/32"}},
		{"plain block keeps the #6659 widening (CONTROL)", `
security { nat { proxy-arp { interface ge-0-0-0 { address { 192.0.2.1; 192.0.2.2; } } } } }`,
			[]string{"192.0.2.1/32", "192.0.2.2/32"},
			[]string{"192.0.2.1/32", "192.0.2.2/32"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// STRICT: the keyword must never reach
			// validateProxyARPAddressesStrict, or the widened read invents a
			// commit rejection master never made.
			cfg, err := CompileConfig(hierTree6659(t, tc.cfg))
			if err != nil {
				t.Fatalf("strict compile rejected a config master accepted: %v\n"+
					"the `to` token is grammar, not an address; letting it "+
					"materialise as \"to/32\" makes the proxy-ARP validator "+
					"reject it", err)
			}
			var got []string
			for _, e := range cfg.Security.NAT.ProxyARP {
				got = append(got, e.Addresses...)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Addresses = %q, want %q", got, tc.want)
			}
			// The claim this test exists for: what the DATAPLANE installs.
			// installedProxyARP6673 applies the installer's own gate, so a
			// compiled value that promotes a malformed range's endpoint shows
			// up here as an address master never answered ARP for.
			if inst := installedProxyARP6673(got); !reflect.DeepEqual(inst, tc.wantInstalled) {
				t.Fatalf("dataplane would install %q, but origin/master installed %q\n"+
					"pkg/dataplane/proxyarp.go adds an NTF_PROXY neighbour and enables "+
					"the interface proxy responder for every address that survives "+
					"netip.ParsePrefix; a malformed range must not promote its "+
					"surviving endpoint into that set, and must not drop an endpoint "+
					"master did install", inst, tc.wantInstalled)
			}
		})
	}
}

// installedProxyARP6673 returns the subset of compiled proxy-ARP addresses that
// pkg/dataplane/proxyarp.go would actually install — it applies that installer's
// own netip.ParsePrefix gate, the one that makes "to/32" inert.
func installedProxyARP6673(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if _, err := netip.ParsePrefix(a); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// --- helpers ---------------------------------------------------------------

func containsValue6673(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func anyWarningContains6673(cfg *Config, sub string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// findWarning6673 returns the single tolerant warning containing EVERY
// substring. Matching on all of them is deliberate: several warnings quote the
// offending value (the cardinality gate prints the whole MatchAddresses slice),
// and one of those legitimately carries no dataplane-effect suffix — so a
// value-only match would satisfy a "does not claim the rule dropped" assertion
// no matter what the loop under test emits, and the guard would never fire.
func findWarning6673(t *testing.T, cfg *Config, subs ...string) string {
	t.Helper()
	var hits []string
	for _, w := range cfg.Warnings {
		all := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				all = false
				break
			}
		}
		if all {
			hits = append(hits, w)
		}
	}
	if len(hits) == 0 {
		t.Fatalf("no tolerant warning contains all of %q; warnings = %q", subs, cfg.Warnings)
	}
	if len(hits) > 1 {
		t.Fatalf("%d tolerant warnings contain all of %q, expected exactly one: %q",
			len(hits), subs, hits)
	}
	return hits[0]
}

// CompileConfigMustFail6673 asserts strict compilation rejects tree and returns
// the error.
func CompileConfigMustFail6673(t *testing.T, tree *ConfigTree) error {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted a genuinely multi-valued list; the " +
			"cardinality gate must still fire on real values")
	}
	return err
}

package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #8768: a container that opts into packedStatements must compile the PACKED
// and BRACED spellings identically for EVERY ORDERED PAIR of its admitted
// leaves — not for the one pair whoever opted it in happened to measure.
//
// THE JUSTIFICATION IS A PRIORI, NOT A COUNTER-EXAMPLE, and an earlier version
// of this comment claimed otherwise. Opting a container in is a claim about
// EVERY admitted leaf — that each survives the packed spelling — so every pair
// has to be compared for the claim to be tested. That argument needs no
// observed defect and does not weaken without one.
//
// THE MECHANISM THIS ORIGINALLY CITED WAS RETRACTED. It said `snmp community`
// showed a leaf-level reader ignoring a correctly-split tail. It does not:
// `snmp community` does not fold at all, because ("community","authorization")
// is not in the scope list, so there is no split structure and no reader
// ignoring one. Its lost `clients` is an ordinary drop at an unadmitted site
// (#8778). NO per-leaf reader divergence has ever been demonstrated, and the
// 18-of-18 EQUAL measured here is entirely consistent with none existing.
//
// The retraction is recorded rather than deleted because the cell's assertions
// were never affected by it — only the story about why they matter. A guard
// whose stated reason is a phantom still passes review, and the next person to
// read it inherits the phantom.
//
// "Multi-ness is not the discriminator" is likewise NOT asserted here. It was
// supported by `snmp community clients` diverging, and that divergence is not a
// fold divergence, so the evidence is gone even though the claim may still be
// true. `snmp trap-group targets` is multi and fine, which is one half and not
// a discriminator.
//
// THE REGISTRY IS ASSERTED AGAINST THE SCHEMA IN BOTH DIRECTIONS. A container
// that opts in without adding fixtures here reds, because otherwise this cell
// would silently cover only the containers someone remembered — the same
// accumulating-registry failure the #8690 buckets were built to avoid.
type packedOptInCase8768 struct {
	prefix string            // text before the container statement
	open   string            // the container statement itself, e.g. `trap-group tg1`
	closer string            // text after
	stmts  map[string]string // admitted leaf -> a REAL statement for it
	// second holds a DIFFERENT instance of the same leaf, for the same-leaf
	// comparison below. Required for every admitted leaf that is `multi: true`
	// or `args >= 2`; see the same-leaf loop for why that is the population.
	second map[string]string
	read   func(*Config) string
}

func packedOptInCases8768() map[string]packedOptInCase8768 {
	// A SECOND declared proposal, so `proposals pr2` in the same-leaf fixture
	// references something real. Pointing the second instance at pr1 would make
	// the two statements identical, and a same-leaf comparison built from two
	// identical statements cannot tell a split from a swallow.
	const ikeProp2 = "proposal pr2 { authentication-method pre-shared-keys; " +
		"dh-group group14; authentication-algorithm sha1; " +
		"encryption-algorithm aes-128-cbc; }"
	const ikeProp = "proposal pr1 { authentication-method pre-shared-keys; dh-group group14; " +
		"authentication-algorithm sha1; encryption-algorithm aes-128-cbc; }"
	return map[string]packedOptInCase8768{
		// #8781-follow-up: the IKE gateway opted in so a packed body carries
		// `local-identity`/`remote-identity`. The schema declares the container
		// TWICE — under `security ike` and under `security ipsec` — and this
		// guard requires a case for each, so an opt-in cannot ship exercised on
		// one spelling and unmeasured on the other.
		"security/ike/gateway": {
			prefix: "security { ike { " + ikeProp + " policy pol1 { proposals pr1; pre-shared-key ascii-text \"s\"; } ",
			open:   "gateway gw1",
			closer: " } }",
			stmts: map[string]string{
				"address":             "address 192.0.2.1",
				"local-address":       "local-address 192.0.2.2",
				"ike-policy":          "ike-policy pol1",
				"external-interface":  "external-interface ge-0/0/0",
				"local-certificate":   "local-certificate cert1",
				"version":             "version v2-only",
				"nat-traversal":       "nat-traversal disable",
				"no-nat-traversal":    "no-nat-traversal",
				"local-identity":      "local-identity hostname foo",
				"remote-identity":     "remote-identity hostname bar",
				"dead-peer-detection": "dead-peer-detection",
				"dynamic":             "dynamic hostname peer.example",
			},
			second: map[string]string{
				"local-identity":  "local-identity hostname foo2",
				"remote-identity": "remote-identity hostname bar2",
			},
			read: func(c *Config) string {
				out := ""
				for _, g := range c.Security.IPsec.Gateways {
					out += fmt.Sprintf("addr=%q la=%q pol=%q ext=%q cert=%q ver=%q nat=%q local=%q/%q remote=%q/%q",
						g.Address, g.LocalAddress, g.IKEPolicy, g.ExternalIface,
						g.LocalCertificate, g.Version, g.NATTraversal,
						g.LocalIDType, g.LocalIDValue, g.RemoteIDType, g.RemoteIDValue)
				}
				if out == "" {
					return "<no gateway>"
				}
				return out
			},
		},
		"security/ipsec/gateway": {
			prefix: "security { ipsec { ",
			open:   "gateway gw1",
			closer: " } }",
			stmts: map[string]string{
				"address":             "address 192.0.2.1",
				"local-address":       "local-address 192.0.2.2",
				"ike-policy":          "ike-policy pol1",
				"external-interface":  "external-interface ge-0/0/0",
				"local-certificate":   "local-certificate cert1",
				"version":             "version v2-only",
				"nat-traversal":       "nat-traversal disable",
				"no-nat-traversal":    "no-nat-traversal",
				"local-identity":      "local-identity hostname foo",
				"remote-identity":     "remote-identity hostname bar",
				"dead-peer-detection": "dead-peer-detection",
				"dynamic":             "dynamic hostname peer.example",
			},
			second: map[string]string{
				"local-identity":  "local-identity hostname foo2",
				"remote-identity": "remote-identity hostname bar2",
			},
			read: func(c *Config) string {
				out := ""
				for _, g := range c.Security.IPsec.Gateways {
					out += fmt.Sprintf("addr=%q la=%q pol=%q ext=%q cert=%q ver=%q nat=%q local=%q/%q remote=%q/%q",
						g.Address, g.LocalAddress, g.IKEPolicy, g.ExternalIface,
						g.LocalCertificate, g.Version, g.NATTraversal,
						g.LocalIDType, g.LocalIDValue, g.RemoteIDType, g.RemoteIDValue)
				}
				if out == "" {
					return "<no gateway>"
				}
				return out
			},
		},
		"snmp/trap-group": {
			prefix: "snmp { ",
			open:   "trap-group tg1",
			closer: " }",
			stmts: map[string]string{
				"targets":    "targets 10.0.0.1",
				"version":    "version v2",
				"categories": "categories authentication",
			},
			second: map[string]string{
				"targets":    "targets 10.0.0.2",
				"categories": "categories link",
			},
			read: func(c *Config) string {
				if c.System.SNMP == nil {
					return "<no snmp>"
				}
				out := ""
				for _, g := range c.System.SNMP.TrapGroups {
					out += fmt.Sprintf("targets=%v version=%q cats=%v", g.Targets, g.Version, g.Categories)
				}
				return out
			},
		},
		"security/ipsec/vpn/vpn-monitor": {
			prefix: "security { ipsec { vpn v1 { ",
			open:   "vpn-monitor",
			closer: " } } }",
			stmts: map[string]string{
				"destination-ip":   "destination-ip 1.2.3.4",
				"source-interface": "source-interface ge-0/0/0",
			},
			read: func(c *Config) string {
				out := ""
				for _, v := range c.Security.IPsec.VPNs {
					out += fmt.Sprintf("mon=%v src=%q dst=%q",
						v.VPNMonitor, v.VPNMonitorSourceInterface, v.VPNMonitorDestinationIP)
				}
				return out
			},
		},
		"security/ike/proposal": {
			prefix: "security { ike { ",
			open:   "proposal pr1",
			closer: " } }",
			stmts: map[string]string{
				"authentication-algorithm": "authentication-algorithm sha1",
				"authentication-method":    "authentication-method pre-shared-keys",
				"description":              "description hello",
				"dh-group":                 "dh-group group14",
				"encryption-algorithm":     "encryption-algorithm aes-128-cbc",
				"lifetime-seconds":         "lifetime-seconds 3600",
			},
			read: func(c *Config) string {
				out := ""
				for _, p := range c.Security.IPsec.IKEProposals {
					out += fmt.Sprintf("auth=%q meth=%q dh=%d enc=%q life=%d",
						p.AuthAlg, p.AuthMethod, p.DHGroup, p.EncryptionAlg, p.LifetimeSeconds)
				}
				return out
			},
		},
		"security/ipsec/proposal": {
			prefix: "security { ipsec { ",
			open:   "proposal ip1",
			closer: " } }",
			stmts: map[string]string{
				"authentication-algorithm": "authentication-algorithm hmac-sha-256-128",
				"description":              "description hello",
				"dh-group":                 "dh-group group14",
				"encryption-algorithm":     "encryption-algorithm aes-128-cbc",
				"lifetime-kilobytes":       "lifetime-kilobytes 100000",
				"lifetime-seconds":         "lifetime-seconds 3600",
				"protocol":                 "protocol esp",
			},
			read: func(c *Config) string {
				out := ""
				for _, p := range c.Security.IPsec.Proposals {
					out += fmt.Sprintf("proto=%q auth=%q dh=%d enc=%q life=%d",
						p.Protocol, p.AuthAlg, p.DHGroup, p.EncryptionAlg, p.LifetimeSeconds)
				}
				return out
			},
		},
		"security/ike/gateway/dead-peer-detection": {
			prefix: "security { ike { gateway g1 { ",
			open:   "dead-peer-detection",
			closer: " } } }",
			stmts: map[string]string{
				"interval":  "interval 10",
				"threshold": "threshold 3",
			},
			read: func(c *Config) string {
				out := ""
				for _, g := range c.Security.IPsec.Gateways {
					out += fmt.Sprintf("dpdOn=%v mode=%q int=%d thr=%d",
						g.DPDEnable, g.DeadPeerDetect, g.DPDInterval, g.DPDThreshold)
				}
				return out
			},
		},
		// #8850 opted both address books in so a packed run of entries splits
		// per statement instead of folding into one and swallowing every entry
		// after the first. Both admitted leaves are compared, per this cell's
		// own contract that opting a container in is a claim about ALL of them.
		"security/zones/security-zone/address-book": {
			prefix: "security { zones { security-zone trust { ",
			open:   "address-book",
			closer: " } } }",
			stmts: map[string]string{
				"address":     "address a1 10.0.0.1/32",
				"address-set": "address-set s1 { address a1; }",
			},
			second: map[string]string{
				"address": "address a2 10.0.0.2/32",
			},
			read: func(c *Config) string {
				for _, z := range c.Security.Zones {
					if z.AddressBook == nil {
						return "<no book>"
					}
					var names []string
					for k := range z.AddressBook.Addresses {
						names = append(names, k)
					}
					for k := range z.AddressBook.AddressSets {
						names = append(names, "set:"+k)
					}
					sort.Strings(names)
					return strings.Join(names, ",")
				}
				return "<no zone>"
			},
		},
		"security/address-book/global": {
			prefix: "security { address-book { ",
			open:   "global",
			closer: " } }",
			stmts: map[string]string{
				"address":     "address a1 10.0.0.1/32",
				"address-set": "address-set s1 { address a1; }",
			},
			second: map[string]string{
				"address": "address a2 10.0.0.2/32",
			},
			read: func(c *Config) string {
				if c.Security.AddressBook == nil {
					return "<no book>"
				}
				var names []string
				for k := range c.Security.AddressBook.Addresses {
					names = append(names, k)
				}
				for k := range c.Security.AddressBook.AddressSets {
					names = append(names, "set:"+k)
				}
				sort.Strings(names)
				return strings.Join(names, ",")
			},
		},
		"security/ike/policy": {
			prefix: "security { ike { " + ikeProp + " " + ikeProp2 + " ",
			open:   "policy p1",
			closer: " } }",
			stmts: map[string]string{
				"mode":           "mode main",
				"pre-shared-key": "pre-shared-key ascii-text SEKRIT",
				"proposals":      "proposals pr1",
				"proposal-set":   "proposal-set standard",
			},
			second: map[string]string{
				"pre-shared-key": "pre-shared-key ascii-text SEKRIT2",
				"proposals":      "proposals pr2",
			},
			read: func(c *Config) string {
				out := ""
				for _, p := range c.Security.IPsec.IKEPolicies {
					// PSK BY LENGTH, NOT BY VALUE. The type redacts itself under
					// %q (`<redacted>`), so `psk=%q` renders every distinct
					// secret identically -- which made `pre-shared-key`
					// unobservable in every comparison in this cell, not just
					// the two-instance one. Length distinguishes the fixtures
					// without printing the secret into a failure message.
					out += fmt.Sprintf("mode=%q psklen=%d props=%v pset=%q",
						p.Mode, len(p.PSK), p.Proposals, p.ProposalSet)
				}
				return out
			},
		},
	}
}

func TestPackedOptInHoldsForEveryLeafPair8768(t *testing.T) {
	// Find every container in the schema that has opted in.
	// KEYED BY SCHEMA PATH, not by container name. Names repeat: `proposal`
	// exists under both `ike` and `ipsec`, and `dead-peer-detection` under both
	// too. A name-keyed registry does not fail on that — it silently holds
	// whichever node the walk reached last and enumerates the WRONG container's
	// leaves while reading as coverage for the one someone opted in.
	//
	// The earlier version refused when two names collided, which was correct
	// and blocked three containers from opting in. A path is unique by
	// construction, so the refusal is replaced by an address that cannot be
	// ambiguous. Wildcard levels render as `*`, matching how the schema
	// addresses an instance rather than a keyword.
	optedIn := map[string]*schemaNode{}
	canonical := map[*schemaNode]string{}
	var walk func(n *schemaNode, path string, depth int)
	walk = func(n *schemaNode, path string, depth int) {
		if n == nil || depth > 12 {
			return
		}
		if n.packedStatements && path != "" {
			// THE SAME NODE IS REACHABLE BY TWO PATHS. Junos `groups` mirrors
			// the entire schema, so every container also has a
			// `groups/*/<path>` address pointing at the identical node. Keying
			// on the raw path would list each opted-in container twice and
			// demand two identical fixture sets.
			//
			// Dedupe by node IDENTITY and keep the shortest path as the
			// canonical address — which is the non-groups one, because the
			// mirror only ever adds a prefix.
			if prev, seen := canonical[n]; !seen || len(path) < len(prev) {
				canonical[n] = path
			}
		}
		for cn, ch := range n.children {
			next := cn
			if path != "" {
				next = path + "/" + cn
			}
			walk(ch, next, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, path+"/*", depth+1)
		}
	}
	walk(setSchema, "", 0)
	for n, path := range canonical {
		optedIn[path] = n
	}

	if len(optedIn) == 0 {
		t.Fatal("no container declares packedStatements, so this cell asserts " +
			"nothing — either the flag was removed or the walk lost reach (#8768)")
	}

	cases := packedOptInCases8768()

	// BOTH DIRECTIONS. An opted-in container with no fixtures is unverified; a
	// fixture for a container that no longer opts in is stale.
	var unfixtured, stale []string
	for name := range optedIn {
		if _, ok := cases[name]; !ok {
			unfixtured = append(unfixtured, name)
		}
	}
	for name := range cases {
		if _, ok := optedIn[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(unfixtured)
	sort.Strings(stale)
	if len(unfixtured) > 0 {
		t.Errorf("%d container(s) declare packedStatements with NO fixtures here: %v.\n"+
			"Opting a container in is a claim that every admitted leaf survives the "+
			"packed spelling, and every one has to be COMPARED for that claim to "+
			"be tested. Add real statements for each admitted leaf (#8768).",
			len(unfixtured), unfixtured)
	}
	if len(stale) > 0 {
		t.Errorf("%d fixture set(s) name a container that no longer opts in: %v.\n"+
			"Remove them; a registry that only grows stops being a measurement.",
			len(stale), stale)
	}

	compile := func(txt string, read func(*Config) string) string {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			return "<parse err>"
		}
		cfg, err := compileConfigWithOpts(tr, lenientCompileOpts())
		if err != nil || cfg == nil {
			return fmt.Sprintf("<err %v>", err)
		}
		return read(cfg)
	}

	// A packed run whose head is a CONTAINER (a schema node with children) is a
	// NESTED elision, not a leaf spelling: the container's own body has no
	// terminator inside the run, so `splitPackedStatements8768` cannot know where
	// it ends. `consumeNodeKeys` consumes the container's arity, the remainder
	// fails to split, and the tail is returned whole -- the container's multi
	// leaf then absorbs every following statement.
	//
	// MEASURED AT origin/master c6c5a8b3c, BEFORE address-book was opted in, so
	// this divergence is NOT caused by the opt-in -- the opt-in is what made this
	// cell look at it:
	//
	//	packed  address-book address-set s1 address a1 address a2 10.0.0.2/32;
	//	          -> set:s1(a1|address|a2|10.0.0.2/32)      (master AND here)
	//	braced  address-book { address-set s1 address a1; address a2 ...; }
	//	          -> a2, set:s1(a1)                          (master AND here)
	//
	// Registering it is NOT a waiver: an entry here must STILL DIVERGE or the
	// cell fails on the stale registration below, and any divergence that is not
	// registered still fails. Nested elision is owned by the #8850 d2 work, not
	// by the opt-in; when that lands, these entries must be deleted, not updated.
	divergesByNestedElision := map[string]bool{
		"security/zones/security-zone/address-book address-set+address": true,
		"security/address-book/global address-set+address":              true,
	}
	sawDivergence := map[string]bool{}

	// Two instances of one leaf that legitimately do NOT split, with the reason
	// MEASURED rather than assumed. Same contract as the map above: an entry
	// that stops diverging fails as stale, and an unadjudicated divergence still
	// fails. Empty until a measurement puts something here.
	sameLeafAdjudicated := map[string]string{}
	sawSameLeaf := map[string]bool{}

	checked := 0
	for name, node := range optedIn {
		c, ok := cases[name]
		if !ok {
			continue
		}
		// Every ADMITTED leaf must have a statement: a leaf admitted to the
		// scope but missing here is exactly the leaf whose packed spelling was
		// never compared.
		//
		// The scope predicate takes the container KEYWORD, which is the last
		// non-wildcard segment of the path — `security/ike/gateway/*/dead-peer-
		// detection` asks about `dead-peer-detection`, not about `*`.
		kw := containerKeywordOfPath8768(name)
		var leaves []string
		for leaf := range node.children {
			if !compactNormalizeInScope(kw, leaf) {
				continue
			}
			if _, ok := c.stmts[leaf]; !ok {
				t.Errorf("container %q admits leaf %q with no fixture statement, so "+
					"its packed spelling is never compared against its braced one "+
					"(#8768)", name, leaf)
				continue
			}
			leaves = append(leaves, leaf)
		}
		sort.Strings(leaves)
		for _, a := range leaves {
			for _, b := range leaves {
				if a == b {
					continue
				}
				packed := c.prefix + c.open + " " + c.stmts[a] + " " + c.stmts[b] + ";" + c.closer
				braced := c.prefix + c.open + " { " + c.stmts[a] + "; " + c.stmts[b] + "; }" + c.closer
				got, want := compile(packed, c.read), compile(braced, c.read)
				checked++
				if got != want {
					key := name + " " + a + "+" + b
					if divergesByNestedElision[key] {
						sawDivergence[key] = true
						continue
					}
					t.Errorf("%s: packed and braced DIFFER for %q + %q (#8768)\n"+
						"  packed %s\n  braced %s\n"+
						"MEASURED, NOT DIAGNOSED: this cell knows the two spellings "+
						"disagree and nothing more. Do not assume a reader defect — no "+
						"per-leaf reader divergence has ever been observed, and the "+
						"likelier causes are the fold declining to split (a token "+
						"outside the modelled grammar, so the tail returns whole) or an "+
						"arity the schema under-declares, which was the #8777 case. "+
						"Establish which before changing anything; the container must "+
						"not stay opted in on the strength of a different pair.",
						name, a, b, got, want)
				}
			}
		}
	}
	// SAME-LEAF PAIRS: two instances of ONE leaf.
	//
	// The loop above compares DISTINCT leaves and opens with `if a == b { continue }`,
	// so a leaf was never compared against itself. That skip is exactly the
	// defect class this guard exists for: one instance proves the statement is
	// REACHABLE, and only two prove the RUN IS SPLIT. It is why this cell stayed
	// green on both address books through the whole window in which they were
	// folding a two-entry run into one and silently keeping only the first --
	// it was measuring the axis that already worked.
	//
	// POPULATION: leaves that are `multi: true` or `args >= 2`. A leaf with
	// args==1 and no multi consumes a fixed two tokens, so its boundary is not
	// in question; the hazard is a multi leaf ABSORBING what follows it, or a
	// wider arity making the boundary non-obvious to a one-instance fixture.
	// Measured at the time of writing: 10 such leaves across 6 of the 10
	// opted-in containers, out of 46 admitted leaves.
	//
	// A leaf in that population with no `second` fixture REDS, on the same terms
	// as a missing `stmts` entry -- otherwise the population silently shrinks to
	// whatever someone remembered.
	sameChecked := 0
	for name, node := range optedIn {
		c, ok := cases[name]
		if !ok {
			continue
		}
		kw := containerKeywordOfPath8768(name)
		var leaves []string
		for leaf := range node.children {
			if !compactNormalizeInScope(kw, leaf) {
				continue
			}
			leaves = append(leaves, leaf)
		}
		sort.Strings(leaves)
		for _, leaf := range leaves {
			ln := node.children[leaf]
			if ln == nil || (!ln.multi && ln.args < 2) {
				continue
			}
			first, ok := c.stmts[leaf]
			if !ok {
				continue // already reported by the loop above
			}
			sec, ok := c.second[leaf]
			if !ok {
				t.Errorf("container %q admits %q, which is multi/args>=2, but has "+
					"no `second` fixture, so the packed spelling is only ever "+
					"compared at ONE instance -- the spelling that cannot "+
					"distinguish a split run from a swallowed one (#8768)",
					name, leaf)
				continue
			}
			packed := c.prefix + c.open + " " + first + " " + sec + ";" + c.closer
			braced := c.prefix + c.open + " { " + first + "; " + sec + "; }" + c.closer
			got, want := compile(packed, c.read), compile(braced, c.read)
			sameChecked++

			// LIVENESS, and it is not optional here. `got == want` is satisfied
			// perfectly by BOTH arms failing, and by a second instance the
			// reader never surfaces. Either makes this comparison green while
			// measuring nothing -- the same both-arms-empty trap that makes a
			// braced-vs-elided cell read as "no defect" or "value lost"
			// depending only on how the assertion is phrased.
			if strings.HasPrefix(want, "<") {
				t.Errorf("container %q: the BRACED reference for two instances of "+
					"%q did not compile (%s), so comparing it against the packed "+
					"spelling proves nothing (#8768)", name, leaf, want)
				continue
			}
			// The second instance must MOVE the reader's output. If one instance
			// and two produce the same string, the fixture cannot distinguish a
			// split run from a swallowed one no matter what the packed arm does.
			bracedOne := c.prefix + c.open + " { " + first + "; }" + c.closer
			if one := compile(bracedOne, c.read); one == want {
				t.Errorf("container %q: adding a SECOND instance of %q changes "+
					"nothing the reader reports (%s), so this comparison is "+
					"degenerate -- it would stay green if the packed spelling "+
					"swallowed the second statement entirely. Give %q a second "+
					"instance the reader distinguishes, or widen the reader "+
					"(#8768)", name, leaf, one, leaf)
				continue
			}
			if got == want {
				continue
			}
			key := name + " " + leaf + "+" + leaf
			if reason, ok := sameLeafAdjudicated[key]; ok {
				sawSameLeaf[key] = true
				t.Logf("#8768: %s two-instance divergence is ADJUDICATED: %s", key, reason)
				continue
			}
			t.Errorf("%s: packed and braced DIFFER for TWO INSTANCES of %q (#8768)\n"+
				"  packed %s\n  braced %s\n"+
				"A one-instance fixture cannot see this. If only the FIRST "+
				"instance survives the packed spelling, the container folds a "+
				"multi-statement run into one; if the two spellings disagree in "+
				"some other way, establish WHICH before changing anything and "+
				"record it in sameLeafAdjudicated with the measurement.",
				name, leaf, got, want)
		}
	}
	for key, reason := range sameLeafAdjudicated {
		if !sawSameLeaf[key] {
			t.Errorf("%q is adjudicated as a two-instance divergence (%s) but the "+
				"two spellings now AGREE, so the entry is stale and is hiding a "+
				"comparison nothing checks. Delete it (#8768)", key, reason)
		}
	}

	for key := range divergesByNestedElision {
		if !sawDivergence[key] {
			t.Errorf("%q is registered as diverging by NESTED ELISION but the two "+
				"spellings now AGREE, so the registration is stale and is now "+
				"hiding a pair nothing checks. Delete the entry -- a registration "+
				"that outlives its reason is indistinguishable from coverage "+
				"(#8768)", key)
		}
	}
	if checked == 0 {
		t.Fatal("no leaf pair was compared, so this cell passed without measuring " +
			"anything (#8768)")
	}
	t.Logf("#8768: %d opted-in container(s), %d ordered leaf pairs compared, "+
		"%d registered as diverging by nested elision; %d same-leaf (two-instance) "+
		"comparisons, %d adjudicated as correctly not splitting", len(optedIn), checked,
		len(divergesByNestedElision), sameChecked, len(sameLeafAdjudicated))
}

// containerKeywordOfPath8768 returns the keyword the scope predicate is asked
// about for a schema path: the last segment that is not a wildcard.
func containerKeywordOfPath8768(path string) string {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "*" && segs[i] != "" {
			return segs[i]
		}
	}
	return ""
}

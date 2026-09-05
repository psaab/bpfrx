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
	read   func(*Config) string
}

func packedOptInCases8768() map[string]packedOptInCase8768 {
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
		"security/ike/policy": {
			prefix: "security { ike { " + ikeProp + " ",
			open:   "policy p1",
			closer: " } }",
			stmts: map[string]string{
				"mode":           "mode main",
				"pre-shared-key": "pre-shared-key ascii-text SEKRIT",
				"proposals":      "proposals pr1",
				"proposal-set":   "proposal-set standard",
			},
			read: func(c *Config) string {
				out := ""
				for _, p := range c.Security.IPsec.IKEPolicies {
					out += fmt.Sprintf("mode=%q psk=%q props=%v pset=%q",
						p.Mode, p.PSK, p.Proposals, p.ProposalSet)
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
	if checked == 0 {
		t.Fatal("no leaf pair was compared, so this cell passed without measuring " +
			"anything (#8768)")
	}
	t.Logf("#8768: %d opted-in container(s), %d ordered leaf pairs compared", len(optedIn), checked)
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

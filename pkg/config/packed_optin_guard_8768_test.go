package config

import (
	"fmt"
	"sort"
	"testing"
)

// #8768: a container that opts into packedStatements must compile the PACKED
// and BRACED spellings identically for EVERY ORDERED PAIR of its admitted
// leaves — not for the one pair whoever opted it in happened to measure.
//
// lane-8526 established why the container is the wrong unit. The divergence it
// found under `snmp community` is not in the fold: the splitter produces a
// correct two-statement structure and the `clients` READER does not take its
// value from it, while `authorization` in the same tail does. So whether a
// packed tail survives is a property of each leaf's reader, and a container is
// safe only if every one of them agrees.
//
// Multi-ness is NOT the discriminator, which is worth recording because it is
// the obvious wrong answer: `snmp trap-group targets` is multi and fine, and
// `snmp community clients` is multi and diverges.
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
		"trap-group": {
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
		"vpn-monitor": {
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
		"policy": {
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
	optedIn := map[string]*schemaNode{}
	var collisions []string
	seenCollision := map[string]bool{}
	var walk func(n *schemaNode, name string, depth int)
	walk = func(n *schemaNode, name string, depth int) {
		if n == nil || depth > 12 {
			return
		}
		if n.packedStatements && name != "" {
			if prev, dup := optedIn[name]; dup && prev != n && !seenCollision[name] {
				seenCollision[name] = true
				collisions = append(collisions, name)
			}
			optedIn[name] = n
		}
		for cn, ch := range n.children {
			walk(ch, cn, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, name, depth+1)
		}
	}
	walk(setSchema, "", 0)

	// NAME COLLISIONS ARE FATAL, because this registry is keyed by container
	// NAME and schema names repeat: `proposal` exists under both `ike` and
	// `ipsec`, and `dead-peer-detection` under both too. If two nodes of one
	// name opt in, the map holds whichever the walk reached last and the leaf
	// enumeration silently describes the wrong container — a guard that reports
	// on a node nobody opted in. Refuse rather than guess; keying by path is
	// the real fix and is deliberately left until a second node needs it.
	if len(collisions) > 0 {
		sort.Strings(collisions)
		t.Fatalf("%d container name(s) opt in at MORE THAN ONE schema position: %v.\n"+
			"This registry is keyed by name, so it cannot tell them apart and would "+
			"enumerate the leaves of whichever the walk reached last. Key it by "+
			"schema path before opting in a second node of the same name (#8768).",
			len(collisions), collisions)
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
			"packed spelling, and that claim is per-leaf-READER rather than "+
			"per-container. Add real statements for each admitted leaf (#8768).",
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
		// scope but missing here is exactly the untested reader.
		var leaves []string
		for leaf := range node.children {
			if !compactNormalizeInScope(name, leaf) {
				continue
			}
			if _, ok := c.stmts[leaf]; !ok {
				t.Errorf("container %q admits leaf %q with no fixture statement — "+
					"that leaf's reader is unverified against the packed spelling (#8768)",
					name, leaf)
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
						"One of those leaves' readers does not take its value from the "+
						"split structure. The container must not stay opted in on the "+
						"strength of a different pair.", name, a, b, got, want)
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

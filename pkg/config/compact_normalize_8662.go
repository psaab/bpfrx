package config

// Brace-elided ("compact") statement normalization — #8662, first increment of
// the #2419 normalizer.
//
// Junos accepts a stanza's body without braces:
//
//	match { source-address a1; }     the braced form
//	match source-address a1;         the same statement, braces elided
//
// The parser represents them differently. Braced gives a container node with a
// child; elided packs the whole tail onto the container's own Keys:
//
//	BLOCK    Keys=[match]                   children=[ Keys=[source-address a1] ]
//	COMPACT  Keys=[match source-address a1] children=[]
//
// A compiler stanza that reads only `prop.Children` — which most do — therefore
// sees nothing in the elided form, and the statement is silently dropped on a
// commit that reports success. `pkg/config/testdata/compact_block_divergences_2419.txt`
// is the measured inventory of that: 433 sites, of which 414 compile the elided
// spelling to a config identical to an EMPTY stanza.
//
// This pass rewrites the packed form into the braced form so both spellings
// compile identically. It is deliberately SCOPED for this increment (see
// compactNormalizeInScope) rather than applied to all 433: the full sweep is
// the #2419 normalizer proper, whose stated goal in
// compact_block_inventory_regen_2419_test.go is to "drive this file to zero
// data lines".
//
// WHY TRUNCATING THE TAIL IS SAFE HERE, and why that is not a general licence.
// Some containers DO read their packed tail — `redundancy-group 0 node 0
// priority 200` is the shipped HA config's spelling, and compileChassis reads
// the value straight out of the node's key tail (see the `packedTail` opt-in in
// schema.go). Moving such a tail into a child would BREAK those readers.
//
// Every site in scope here is one the inventory records as DIVERGENT with the
// elided form compiling to the empty stanza — which is a positive measurement
// that the tail is currently ignored at that container. So there is nothing to
// break: the value reaches no reader today. The inventory is the safety
// evidence, and a site may only be added to this pass's scope once it appears
// there.
func normalizeCompactStanzas(tree *ConfigTree) int {
	if tree == nil {
		return 0
	}
	return normalizeCompactNodes(tree.Children, setSchema)
}

// compactNormalizeInScope reports whether a packed tail at `container` whose
// first token is `head` is in this increment's scope.
//
// #8662 scope: the 24 `match` criteria under security NAT and security policies,
// and the 6 `authentication-key` leaves under the routing protocols. Chosen
// because that is where a silent drop is a SECURITY outcome rather than a
// cosmetic one — a dropped match criterion silently changes what a rule
// matches, and a dropped authentication key silently changes what authenticates.
func compactNormalizeInScope(containerKeyword, head string) bool {
	if head == "authentication-key" {
		return true
	}
	if containerKeyword == "match" {
		return true
	}
	// #8690, second increment: the CREDENTIAL family. Chosen on consequence
	// rather than on count — each of these is a token whose silent drop leaves
	// something authenticating (or authorizing) with NOTHING, on a commit that
	// reports success. That is the failure #8689 demonstrated on its own
	// `authentication-key` above: the brace-elided spelling compiled to an
	// empty AuthKey, rendered as `area-password md5`, and the IS-IS adjacency
	// came up unauthenticated.
	//
	// EVERY ENTRY BELOW WAS MEASURED, not reasoned about. The rule is that a
	// site may enter this pass only once the census shows its elided spelling
	// compiling identically to the EMPTY stanza — a positive measurement that
	// no reader consumes the packed tail today, so moving it cannot break one.
	// `TestCompactNormalizeScopePreservesCompiledResult8690` re-derives that for
	// every admitted site on each run, against the same census machinery the
	// inventory uses, so this list cannot drift from its own justification.
	//
	// The measurement also EXCLUDED members of the family, and NEITHER exclusion
	// came from empty-equivalence — see the two notes below. Membership is by
	// measurement rather than by name, and the measurement that matters is not
	// always the one the rule names.
	//
	// EXCLUDED BY DESIGN, and this is not the empty-equivalence rule — it is a
	// second gate that behaviour measurement cannot see. `system login user
	// <u> authentication <leaf>` measures empty-equivalent (nothing reads the
	// tail), and normalizing it would still be wrong: the compact spelling is
	// REJECTED at commit by the #6662 packed-login-body gate, and on the
	// tolerant load / peer-sync path it is warned and left inert on purpose, so
	// a peer-synced config behaves exactly as the binary that accepted it did
	// (#1960). Compiling the value there would change RBAC across an HA sync,
	// silently, between nodes on different binaries.
	//
	// `filedByDesign` in compact_block_equivalence_2419_test.go is the registry,
	// and its tripwire is what caught this: the empty-equivalence probe said
	// "safe" for all four leaves, because the probe measures whether a reader
	// consumes the tail and cannot see a decision that it SHOULD NOT be read.
	//
	// `user` is excluded too, and the registry does NOT list it — that was
	// found by measuring the gate rather than by reading the registry. The
	// normalizer runs at compiler.go:210 and the #6662 gate at :349, so a
	// rewritten tree reaches the gate already un-packed. Measured before and
	// after admitting `user`/`class`:
	//
	//	before: `system login user u1 class super-user;` -> REJECTED at commit
	//	        ("the account resolves to the fail-closed `unauthorized` class
	//	         ... on a binary before #6701 it instead reached the legacy
	//	         no-RBAC allow-everything mode")
	//	after:  compiles clean
	//
	// Normalizing it does not merely change a spelling: it converts a loud
	// commit-time rejection into a silent acceptance, and makes an RBAC class
	// compile on this binary that a peer on an older one still drops. The
	// registry lists the four `authentication` leaves; the GATE governs the
	// whole packed login body. Only the before/after comparison shows the
	// difference, so the exclusion is by container, not by the registry.
	if containerKeyword == "authentication" || containerKeyword == "user" {
		return false
	}
	if compactCredentialHeads[head] {
		return true
	}
	// `key` is too generic to admit unqualified — it appears on containers that
	// read their tail — so it is scoped to the containers that measured safe.
	// (`class` was scoped here too, under `user`; that branch is gone because
	// the container exclusion above already made it unreachable, and leaving a
	// dead branch would misdescribe the scope to the next reader.)
	//
	// Stated as an `if` rather than a `switch` on containerKeyword so a
	// non-matching head under `tunnel`/`md5` FALLS THROUGH to the pair switch
	// below instead of returning false early. The two families are independent
	// and neither may silently shadow the other.
	if (containerKeyword == "tunnel" || containerKeyword == "md5") && head == "key" {
		return true
	}
	// #8690 family 2: the POLICY-ENFORCEMENT surface — security zones and
	// security policies. 20 sites left the inventory and none entered it, and
	// every one of the 20 was recorded with drop shape "empty": the
	// measurement that no reader consumes the tail today, and therefore that
	// truncating it takes nothing away.
	//
	// 20 rather than the 17 zones+policies sites the pairs were chosen for.
	// Three came along because they share a pair: `security address-book global
	// address-set <s> {address,address-set}` and `security pre-id-default-policy
	// then log`. They are the same shape and the same consequence class, so they
	// are in scope deliberately rather than tolerated — but they are named here
	// because "the diff is bigger than the families I listed" is exactly the
	// sentence a reviewer should be able to check.
	//
	// `security policies from-zone <a> <b> <c> policy` is NOT covered: its pair
	// is `from-zone policy`, which is not listed, so the bare policy instance
	// remains in the inventory. Left out rather than added quietly, so the
	// inventory diff continues to equal the declared scope.
	//
	// The consequential members are not the descriptions:
	//
	//	security-zone <z> screen <profile>      the zone's IDS screen binding
	//	security-zone <z> host-inbound-traffic  what the box itself accepts there
	//	security-zone <z> interfaces <if> ...   per-interface admission
	//	policy <p> then log                     session logging for the policy
	//
	// A brace-elided `screen` leaves the zone with no screen profile applied,
	// on a commit that reports success — the same shape as #8689's IS-IS
	// authentication key, one layer up.
	//
	// SCOPED BY (container, head) PAIR RATHER THAN BY CONTAINER KEYWORD, and
	// the difference is load-bearing. `then` is not specific enough: the
	// `then log` sites here are shape "empty", but
	// `policy-options policy-statement <p> term <t> then <action>` is shape
	// "partial" for eight actions — something DOES consume part of that tail,
	// so truncating it could remove a value that is currently read. A
	// containerKeyword == "then" rule would have crossed into them silently.
	//
	// That is why the widening rule is per SITE rather than per family: a
	// family label is not a safety property, and this is the case that proves
	// it. TestNormalizerScopeNeverCoversAPartialSite8690 binds it mechanically
	// so the next widening cannot make the same mistake by inspection.
	// #8690 family 3: policy-options. Taken PER SITE rather than as a family
	// sweep, because this is the family where a family sweep is actively
	// harmful: of its 17 inventory sites, 9 are drop shape "empty" and 8 are
	// "partial" — and all 8 partials sit under `then`.
	//
	//	policy-statement <p> term <t> from community <c>   empty    admitted
	//	policy-statement <p> term <t> then community <c>   partial  NOT admitted
	//
	// The same head, one token apart, on opposite sides of the safety rule.
	// That pair is the clearest argument in the tree for scoping on
	// (container, head) rather than on either token alone: a head-only rule
	// admits both, and a container-only rule on `then` admits all eight
	// partials. Both mistakes were available and neither is visible by reading.
	//
	// Every one of the 9 below was checked individually against the inventory's
	// drop shape, and TestNormalizerScopeNeverCoversAPartialSite8690 re-checks
	// the whole set against the LIVE normalizer rather than against my reading
	// of it.
	switch containerKeyword + " " + head {
	case "policy-options community",
		"policy-options policy-statement",
		"policy-options prefix-list",
		"community members",
		"policy-statement term",
		"from as-path",
		"from community",
		"from prefix-list":
		return true
	}

	switch containerKeyword + " " + head {
	case "zones security-zone",
		"security-zone screen",
		"security-zone description",
		"security-zone interfaces",
		"security-zone address-book",
		"security-zone host-inbound-traffic",
		"host-inbound-traffic protocols",
		"host-inbound-traffic system-services",
		"address-set address",
		"address-set address-set",
		"address-book address-set",
		"policies default-policy-log",
		"policies from-zone",
		"policies global",
		"policy description",
		"policy then",
		"then log",
		"global policy":
		return true
	}

	// #8690 family 3: the FORWARDING-BEHAVIOUR surface — class-of-service,
	// forwarding-options and firewall. 52 inventory sites, every one recorded
	// with drop shape "empty": the positive measurement that no reader consumes
	// the tail today, so truncating it takes nothing away.
	//
	// SCOPED ON PAIRS, NEVER ON A CONTAINER KEYWORD ALONE — and here that is
	// the difference between correct and destructive, not a style preference.
	// `then` is shared. These families need (then, {count, dscp,
	// forwarding-class, loss-priority, policer, routing-instance,
	// traffic-class}); `policy-options policy-statement <p> term <t> then`
	// carries EIGHT sites with drop shape "partial" — as-path-prepend,
	// community, load-balance, local-preference, metric, metric-type, next-hop,
	// origin. "partial" means something ALREADY CONSUMES part of that tail, so
	// normalizing it removes a value that is read today while the config still
	// commits clean. A scope written as `containerKeyword == "then"` would have
	// swallowed all eight. The two head sets are disjoint, which is what makes
	// the pairs below safe and the keyword unsafe.
	//
	// `group` is shared the same way: (group, interface) is wanted here for
	// dhcp-relay, while `protocols bgp group <g>` uses the same container and
	// holds `neighbor <n> peer-as` — one of the sites where widening DISARMS a
	// commit gate despite measuring empty-equivalent. Admitting the pair rather
	// than the keyword leaves bgp untouched.
	//
	// THE PAIRS WERE MEASURED, NOT READ OFF THE INVENTORY PATH. Production
	// passes kw = node.Keys[0] and head = node.Keys[1+args], so the `xpfarg` in
	// an inventory line is the node's ARG, not its container keyword. Deriving
	// pairs by reading the path yields a predicate that silently UNDER-reports
	// — the #8708 method note, where `system login user` was asked about as
	// ("xpfarg", "class") and matched nothing. These came from running the pass
	// with an instrumented gate and recording what it encountered.
	//
	// THREE SITES OUTSIDE THE THREE FAMILIES COME ALONG because they share a
	// pair. Named here, because "the diff is bigger than the families I listed"
	// is exactly the sentence a reviewer should be able to check:
	//
	//	policy-options policy-statement <p> term <t> from protocol  (from protocol)
	//	system services dhcp-local-server group <g> interface       (group interface)
	//	system services dhcpv6-local-server group <g> interface     (group interface)
	//
	// All three are recorded "empty", so the same safety measurement covers
	// them. The policy-options member is a `from` site, NOT one of the eight
	// forbidden `then` partials — the distinction the pair scoping exists to
	// preserve.
	switch containerKeyword + " " + head {
	// class-of-service: 49 pairs.
	case "buffer-size temporal",
		"class-of-service interfaces",
		"class-of-service scheduler-maps",
		"class-of-service schedulers",
		"class-of-service traffic-control-profiles",
		"classifiers dscp",
		"classifiers ieee-802.1",
		"classifiers inet-precedence",
		"dscp forwarding-class",
		"exp forwarding-class",
		"forwarding-class loss-priority",
		"forwarding-class scheduler",
		"ieee-802.1 forwarding-class",
		"inet-precedence forwarding-class",
		"interface queue",
		"interfaces output-traffic-control-profile",
		"interfaces priority-low-min-share",
		"interfaces scheduler-map",
		"interfaces shaping-rate",
		"interfaces unit",
		"loss-priority code-point",
		"loss-priority code-points",
		"oversubscription-policy guarantee-rate",
		"queue active-workers",
		"queue at-least-active-workers",
		"queue cstruct",
		"queue cstruct-max",
		"queue max-worker-flow-share",
		"rewrite-rules dscp",
		"rewrite-rules exp",
		"rewrite-rules ieee-802.1",
		"rewrite-rules inet-precedence",
		"rss-expectation interface",
		"scheduler-maps forwarding-class",
		"schedulers buffer-size",
		"schedulers codel-target",
		"schedulers equal-flow-target-policy",
		"schedulers priority",
		"schedulers transmit-rate",
		"shaping-rate burst-size",
		"traffic-control-profiles delay-buffer-rate",
		"traffic-control-profiles guaranteed-rate",
		"traffic-control-profiles scheduler-map",
		"traffic-control-profiles shaping-rate",
		"transmit-rate percent",
		"unit output-traffic-control-profile",
		"unit priority-low-min-share",
		"unit scheduler-map",
		"unit shaping-rate":
		return true
	// forwarding-options: 16 pairs.
	case "dhcp-relay group",
		"dhcp-relay server-group",
		"flow-server port",
		"flow-server source-address",
		"flow-server version-ipfix-template",
		"flow-server version9-template",
		"group active-server-group",
		"group interface",
		"inet6 mode",
		"input rate",
		"output flow-server",
		"output source-address",
		"overrides maximum-hop-count",
		"overrides maximum-packet-rate",
		"port-mirroring instance",
		"sampling instance":
		return true
	// firewall: 34 pairs.
	case "filter term",
		"firewall policer",
		"firewall three-color-policer",
		"flexible-match-range range",
		"from destination-address",
		"from destination-port",
		"from destination-port-except",
		"from dscp",
		"from icmp-code",
		"from icmp-type",
		"from protocol",
		"from source-address",
		"from source-port",
		"from source-port-except",
		"from tcp-flags",
		"from traffic-class",
		"if-exceeding bandwidth-limit",
		"if-exceeding burst-size-limit",
		"inet filter",
		"inet6 filter",
		"single-rate committed-burst-size",
		"single-rate committed-information-rate",
		"single-rate excess-burst-size",
		"then count",
		"then dscp",
		"then forwarding-class",
		"then loss-priority",
		"then policer",
		"then routing-instance",
		"then traffic-class",
		"two-rate committed-burst-size",
		"two-rate committed-information-rate",
		"two-rate peak-burst-size",
		"two-rate peak-information-rate":
		return true
	}
	return false
}

// compactCredentialHeads are the #8690 credential leaves whose heads are
// distinctive enough to admit without qualifying the container. Each was
// measured empty-equivalent; see compactNormalizeInScope.
var compactCredentialHeads = map[string]bool{
	"encrypted-password":       true,
	"ssh-dsa":                  true,
	"ssh-rsa":                  true,
	"ssh-ed25519":              true,
	"pre-shared-key":           true,
	"preshared-key":            true,
	"private-key":              true,
	"authentication-type":      true,
	"authentication-algorithm": true,
	"authentication-method":    true,
	"pseudorandom-function":    true,
}

func normalizeCompactNodes(nodes []*Node, schema *schemaNode) int {
	if schema == nil {
		return 0
	}
	n := 0
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		kw := node.Keys[0]
		child := schema.children[kw]
		if child == nil {
			child = schema.wildcard
		}
		if child == nil {
			continue
		}
		// The node's own identity is its keyword plus its declared args.
		identity := 1 + child.args
		if len(node.Keys) > identity && len(node.Children) == 0 {
			head := node.Keys[identity]
			// The tail only reads as an elided BODY if its first token names a
			// child of this container. Otherwise it is this node's own
			// multi-value payload (a bracketed list, a multi: true leaf) and
			// must be left alone.
			if _, isBody := child.children[head]; isBody && compactNormalizeInScope(kw, head) {
				tail := append([]string(nil), node.Keys[identity:]...)
				node.Keys = append([]string(nil), node.Keys[:identity]...)
				node.IsLeaf = false
				node.Children = append(node.Children, &Node{Keys: tail, IsLeaf: true})
				n++
			}
		}
		n += normalizeCompactNodes(node.Children, child)
	}
	return n
}

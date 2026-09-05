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
	// NOTE: this exclusion PRE-EMPTS every pair below. With the rules now
	// pair-scoped it is no longer load-bearing for the credential heads --
	// no pair names `authentication` or `user` as its container -- but it is
	// kept as the explicit record of the #6662 decision, and because it also
	// guards anything added above it later.
	//
	// Its cost, stated so it is not rediscovered: a pair naming
	// `authentication` or `user` as its container would silently never fire.
	// A rule that cannot match reads like coverage and passes review, which is
	// the same trap as the wildcard-container site in #8719. If a future family
	// needs one, delete this and re-derive the exclusion as pairs rather than
	// adding an unreachable case below.
	if containerKeyword == "authentication" || containerKeyword == "user" {
		return false
	}
	// EVERY RULE HERE IS SCOPED BY (container, head) PAIR. None matches a head
	// alone or a container alone, and that is a deliberate change from how the
	// first two increments were written.
	//
	// WHY: a head-only rule is safe only for as long as no container acquires
	// that head with a tail somebody reads, and a container-only rule is safe
	// only for as long as no head appears under it that somebody reads. Both
	// make the predicate's correctness contingent on the CURRENT INVENTORY
	// rather than on the rule. The inventory moves — this sweep moves it — so
	// such a rule fails at the moment a family lands, inside someone else's
	// merge conflict, which is the worst possible place to be redesigning a
	// predicate.
	//
	// The measured case for the container-only direction: `containerKeyword ==
	// "match"` was written for security policies and NAT rule-sets, and it also
	// admitted `services ip-monitoring policy <p> match rpm-probe` — a
	// different feature in a different subtree, reached only because it happens
	// to spell its criteria block `match`. It is in scope below because it
	// measured safe, not because the rule intended it.
	//
	// The head-only direction is the same defect mirrored, and is the one
	// lane-8526's illustration names: `term <t> from community <c>` is shape
	// `empty` and admissible while `term <t> then community <c>` is `partial`
	// and must never be admitted. Same head, one token apart, opposite sides of
	// the safety rule.
	//
	// These 32 pairs are exactly what the three former rules admitted, measured
	// at the production call site rather than derived from the schema — so this
	// is a restatement of the existing scope, not a widening. The admitted-site
	// count and the inventory are unchanged by it.
	switch containerKeyword + " " + head {
	case
		// #8689: the authentication-key family, formerly `head ==
		// "authentication-key"` unqualified.
		"cluster authentication-key",
		"group authentication-key",
		"interface authentication-key",
		"isis authentication-key",
		"neighbor authentication-key",
		"rip authentication-key",
		"vrrp-group authentication-key",
		// #8689: the security match family, formerly `containerKeyword ==
		// "match"` unqualified. `match rpm-probe` is the ip-monitoring site
		// noted above.
		"match application",
		"match destination-address",
		"match destination-address-excluded",
		"match destination-address-name",
		"match destination-port",
		"match from-zone",
		"match protocol",
		"match rpm-probe",
		"match source-address",
		"match source-address-excluded",
		"match source-address-name",
		"match to-zone",
		// #8708: the credential family, formerly a head-only map lookup.
		"interface authentication-type",
		"isis authentication-type",
		"manual authentication-algorithm",
		"master-password pseudorandom-function",
		"peer preshared-key",
		"proposal authentication-algorithm",
		"proposal authentication-method",
		"rip authentication-type",
		"root-authentication encrypted-password",
		"root-authentication ssh-dsa",
		"root-authentication ssh-ed25519",
		"root-authentication ssh-rsa",
		"policy pre-shared-key",
		"vpn pre-shared-key",
		"vrrp-group authentication-type",
		"wireguard private-key",
		// #8708: `key`, already container-scoped, restated in the same form.
		"tunnel key",
		"md5 key":
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
	// #8690 family 5: applications, services, snmp, event-options. 30 sites,
	// every one drop shape "empty" in the inventory.
	//
	// PROVISIONAL until the disarm arm has run over them: the drop shape
	// answers a question about READERS and does not see commit gates. lane-8388
	// established that `system login` sites measure "empty" while the #6662
	// packed-login-body gate makes normalizing them unsafe, and flagged
	// `snmp trap-group <t> targets` as one of the same class. I am not taking
	// that on trust either way — the pairs go in, the disarm guard runs, and
	// anything it flags gets classified by hand rather than assumed.
	switch containerKeyword + " " + head {
	case "applications application",
		"applications application-set",
		"application alg",
		"application description",
		"application destination-port",
		"application icmp-code",
		"application icmp-type",
		"application inactivity-timeout",
		"application protocol",
		"application source-port",
		"application term",
		"application timeout",
		"event-options policy",
		"policy within",
		"version-ipfix template",
		"version9 template",
		"template flow-active-timeout",
		"template flow-inactive-timeout",
		"template-refresh-rate seconds",
		"rpm probe",
		"snmp community",
		"snmp trap-group",
		"community clients",
		"trap-group categories",
		"trap-group targets",
		"trap-group version",
		"local-engine user":
		return true
	}

	// #8690 family 4: interfaces. 15 sites, every one drop shape "empty".
	//
	// Measured, not taken from the brief: the family was described to me as
	// 18 empty / 8 partial for interfaces plus 0/2 for bridge-domains. The
	// inventory says 15 empty / 10 partial across the two. The file is the
	// instrument.
	//
	// The same head-on-both-sides shape as family 3 appears here too:
	//
	//	interfaces <if> tunnel destination <addr>                     empty
	//	interfaces <if> tunnel routing-instance destination <ri>      partial
	//
	// so `destination` is admitted under `tunnel` and not under
	// `routing-instance`. A head-only rule would take both.
	//
	// The other ten partials — `interfaces <if> {description,duplex,mtu,speed,
	// unit,...}` and the two bridge-domains sites — fold at the INSTANCE level,
	// where production passes the instance name (`ge-0-0-0`) as the container
	// keyword. No static pair can match them, so they are safe from a pair rule
	// by construction rather than by being listed. That is worth knowing before
	// someone "simplifies" this to a head-only match: it is exactly the rule
	// shape those ten are NOT protected from.
	//
	// bridge-domains has ZERO admissible sites — both of its inventory entries
	// are partial — so there is nothing to normalize there and its verdict is
	// recorded rather than left looking unstarted.
	switch containerKeyword + " " + head {
	//
	// `lacp periodic` was withheld in #8721 because it was one of the census's
	// two hand-verified known-true anchors, and normalizing it blinded the
	// instrument. It is admitted now: the anchor moved to a PARTIAL site
	// (`interfaces <if> mtu`), which no scope may ever cover, so the control no
	// longer depends on leaving a defect unfixed. The withheld site cost one
	// increment; the structural fix ends the recurrence.
	case "aggregated-ether-options link-speed",
		"aggregated-ether-options minimum-links",
		"lacp periodic",
		"gigether-options 802.3ad",
		"gigether-options redundant-parent",
		"tunnel destination",
		"tunnel source",
		"tunnel mode",
		"tunnel ttl",
		"tunnel keepalive-retry",
		"wireguard listen-port",
		"wireguard peer",
		"peer allowed-ips",
		"peer endpoint",
		"peer persistent-keepalive":
		return true
	}

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

	// #8690, the SYSTEM surface — 44 sites out of the 61 the census
	// lists under `system`. Scoped by (container, head) PAIR per family 2's
	// rule, and the 17 exclusions are the whole point of this increment.
	//
	// WHAT WAS EXCLUDED, AND WHY THE INVENTORY MARKER COULD NOT SAY SO:
	//
	// 15 sites are GATE-DISARMING — compiled through the strict path with this
	// pass disabled they are REJECTED, and with it enabled they are ACCEPTED.
	// That is the whole `system login` subtree (`class` and its six children,
	// `user`, the four `authentication` leaves, `class`, `uid`) plus
	// `dhcp-local-server ... static-binding <b> fixed-address`. Every one of
	// them measures `empty`, so the inventory marker calls them safe: it
	// records whether a READER consumes the packed tail, and these are held by
	// a GATE that refuses the packed spelling. The pass runs before the commit
	// gates, so a rewritten tree reaches them with nothing left to refuse.
	//
	// 1 site is UNMEASURABLE rather than safe:
	// `dhcpv6-local-server ... static-binding <b> fixed-address`. Its census
	// fixture supplies an IPv4 literal, so with the pass enabled it fails a
	// DIFFERENT validator ("is not an IPv6 address") instead of compiling. A
	// two-state safe/unsafe test reads that as "no gate was disarmed", which is
	// the fixture answering rather than the site. It shares its pair with the
	// v4 site above, so excluding that pair covers both.
	//
	// 1 site is UNREACHABLE by a pair rule at all:
	// `services web-management api-auth user <name> password`. Its container is
	// WILDCARD-NAMED, so production passes the actual username as the container
	// keyword -- `("alice", "password")`, never a fixed token. A pair rule for
	// it would be dead code that reads like coverage. Admitting it needs a
	// head-only rule, which is a different safety argument than this increment
	// makes, so it stays out.
	//
	// The pairs below were MEASURED by instrumenting the production call site,
	// not reconstructed from the inventory path. Those disagree: the path
	// carries a schema placeholder where production passes the stanza keyword,
	// so `system login class <c> allow-commands` is ("class", "allow-commands")
	// to production and ("xpfarg", "allow-commands") to a path reader.
	switch containerKeyword + " " + head {
	case
		"api-auth api-key",
		"autoupdate url",
		"coalescence adaptive",
		"coalescence rx-usecs",
		"coalescence tx-usecs",
		"configuration archive-sites",
		"configuration transfer-interval",
		"dataplane binary",
		"dataplane claim-host-tunables",
		"dataplane cpu-governor",
		"dataplane netdev-budget",
		"dataplane poll-mode",
		"dataplane ring-entries",
		"dataplane state-file",
		"dataplane workers",
		"dhcp-local-server group",
		"dhcpv6-local-server group",
		"group interface",
		"group pool",
		"http interface",
		"https interface",
		"ntp server",
		"ntp threshold",
		"pool dns-server",
		"pool static-binding",
		"shared-umem artifact-file",
		"shared-umem interface",
		"shared-umem mode",
		"shared-umem phase0-artifact-file",
		"ssh client-alive-count-max",
		"ssh client-alive-interval",
		"ssh connection-limit",
		"ssh key-exchange",
		"ssh root-login",
		"static-binding host-name",
		"system backup-router",
		"system domain-search",
		"system name-server",
		"system time-zone":
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

	// #8690 family 4: the ROUTING surface — protocols, routing-instances and
	// routing-options. 80 inventory sites, every one recorded "empty".
	//
	// THESE THREE CANNOT BE SPLIT, and that is a measured fact rather than a
	// convenience. `routing-instances <n> protocols ospf ...` and
	// `routing-instances <n> routing-options static ...` are the SAME GRAMMAR
	// re-hosted under an instance, so they resolve to the same (container, head)
	// pairs as their top-level spellings. Admitting `routing-instances` alone
	// necessarily admits the matching `protocols` and `routing-options` sites;
	// the pair set is only closed over all three. Splitting them into separate
	// increments would have produced an inventory diff much larger than each
	// increment declared, which is precisely the thing a reviewer is asked to
	// check.
	//
	// `protocols` was deliberately EXCLUDED from family 3 because it holds
	// `protocols bgp group <g> neighbor <n> peer-as`, one of the sites where a
	// widening DISARMS a commit gate while measuring empty-equivalent — so the
	// inventory marker is necessary but not sufficient evidence there. It is
	// admitted here on a different basis: arm 2 of the widening rule
	// (TestCompactNormalizeScopePreservesCompiledResult8690) compiles every
	// admitted site through the strict path with the pass disabled and compares
	// acceptance, which is the check the marker cannot perform. That guard runs
	// over whatever scope is current, so it adjudicates these sites rather than
	// a list adjudicating them.
	//
	// ONE PAIR REACHES OUTSIDE the three families: (route, next-hop) is also
	// used by `services ip-monitoring policy <p> then preferred-route route
	// <r>`. That site is NOT in the inventory, which is NOT evidence that it
	// conserves — a site the census cannot see is absent for the same reason a
	// safe site is. It is admitted on arm 2's verdict, not on its absence.
	//
	// Pairs measured by running the pass with an instrumented gate, not derived
	// from inventory paths (the path carries the schema arg placeholder where
	// production passes node.Keys[0]).
	//
	// ("neighbor", "peer-as") IS DELIBERATELY ABSENT, and arm 2 is what removed
	// it rather than a list. Admitting it made
	// TestCompactNormalizeScopePreservesCompiledResult8690 report:
	//
	//	1 site(s) in the normalizer's scope are REJECTED at strict commit with
	//	the pass disabled and ACCEPTED with it enabled:
	//	[protocols bgp group xpfarg neighbor xpfarg peer-as]
	//
	// That is the gate-disarm failure the "empty" marker cannot see: the site
	// measures empty-equivalent (no reader consumes the tail) AND a commit gate
	// rejects the packed spelling, so normalizing it would make a configuration
	// that is refused today start committing clean. `protocols bgp group <g>
	// neighbor <n> peer-as` therefore stays in the inventory. Retiring its gate
	// is a separate, deliberate decision — not a side effect of a family sweep.
	switch containerKeyword + " " + head {
	case "area interface",
		"area virtual-link",
		"authentication md5",
		"authentication simple-password",
		"bfd-liveness-detection minimum-interval",
		"bfd-liveness-detection multiplier",
		"bgp cluster-id",
		"bgp export",
		"bgp group",
		"bgp import",
		"bgp local-as",
		"bgp router-id",
		"damping half-life",
		"damping max-suppress",
		"damping reuse",
		"damping suppress",
		"forwarding-table export",
		"generate route",
		"group authentication-key",
		"group description",
		"group export",
		"group hold-time",
		"group import",
		"group local-address",
		"group local-as",
		"group loops",
		"group multihop",
		"group neighbor",
		"group peer-as",
		"interface authentication-key",
		"interface authentication-type",
		"interface cost",
		"interface dead-interval",
		"interface default-lifetime",
		"interface dns-server-address",
		"interface hello-interval",
		"interface interface-type",
		"interface level",
		"interface link-mtu",
		"interface max-advertisement-interval",
		"interface metric",
		"interface min-advertisement-interval",
		"interface nat-prefix",
		"interface nat64prefix",
		"interface preference",
		"interface prefix",
		"interface priority",
		"interface reachable-time",
		"interface retransmit-interval",
		"interface retransmit-timer",
		"isis authentication-key",
		"isis authentication-type",
		"isis export",
		"isis interface",
		"isis is-type",
		"isis level",
		"isis net",
		"lldp hold-multiplier",
		"lldp interface",
		"lldp transmit-interval",
		"md5 key",
		"nat-prefix lifetime",
		"nat64prefix lifetime",
		"neighbor authentication-key",
		"neighbor description",
		"neighbor export",
		"neighbor hold-time",
		"neighbor import",
		"neighbor local-address",
		"neighbor local-as",
		"neighbor loops",
		"neighbor multihop",
		"next-hop interface",
		"ospf area",
		"ospf export",
		"ospf reference-bandwidth",
		"ospf router-id",
		"ospf3 area",
		"ospf3 export",
		"ospf3 router-id",
		"prefix preferred-lifetime",
		"prefix valid-lifetime",
		"prefix-limit maximum",
		"qualified-next-hop interface",
		"qualified-next-hop metric",
		"qualified-next-hop preference",
		"rib-group inet",
		"rib-group inet6",
		"rip authentication-key",
		"rip authentication-type",
		"rip group",
		"rip neighbor",
		"rip passive-interface",
		"rip redistribute",
		"route next-hop",
		"route next-table",
		"route policy",
		"route preference",
		"route qualified-next-hop",
		"router-advertisement interface",
		"routing-options autonomous-system",
		"routing-options rib",
		"routing-options rib-groups",
		"static route",
		"virtual-link transit-area":
		return true
	}
	return false
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

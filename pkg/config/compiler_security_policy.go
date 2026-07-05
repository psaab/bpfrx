package config

func compilePolicies(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		if child.Name() == "default-policy" {
			var policyStr string
			if len(child.Keys) >= 2 {
				// Flat form: default-policy deny-all;
				policyStr = child.Keys[1]
			} else if len(child.Children) > 0 {
				// Hierarchical form: default-policy { deny-all; }
				policyStr = child.Children[0].Name()
			}
			switch policyStr {
			case "permit-all":
				sec.DefaultPolicy = PolicyPermit
			case "deny-all":
				sec.DefaultPolicy = PolicyDeny
			case "reject-all":
				// #3065: reject-all is valid Junos; previously it fell
				// through this switch and left the (now deny) default
				// untouched. Map it to PolicyReject so the dataplane
				// no-match verdict sends an ICMP/RST reject instead of a
				// silent drop.
				sec.DefaultPolicy = PolicyReject
			}
			continue
		}
		// #3534 (split from #3363 Part 2): `default-policy-log
		// session-init|session-close` requests RT_FLOW session logging for the
		// implicit default-policy verdict. Mirrors the per-policy `then log`
		// selection (#2508) — the flags are stamped onto the Rust default-verdict
		// result and, for a default-PERMIT verdict, onto the installed session so
		// it emits RT_FLOW_SESSION_CREATE/CLOSE like a named policy. The flag
		// lives in a sibling container because the `default-policy` enum leaf
		// cannot carry `then` children (schema.go typed-leaf invariant).
		if child.Name() == "default-policy-log" {
			// #3703: multi-value session-log list leaf. Read every mode via the
			// firewallMatchValues SSOT (Keys[1:] AND/OR one-per-child) so a
			// bracket / single-line `default-policy-log [ session-init
			// session-close ]` keeps BOTH flags; the prior FindChild lookups
			// missed session-close when the bracket tail mis-nested it under
			// session-init (the #2419 collapse bug). Unknown tokens are rejected
			// at commit by SchemaValidate (the enum leaf validator).
			for _, mode := range firewallMatchValues(child) {
				switch mode {
				case "session-init":
					sec.DefaultPolicyLogSessionInit = true
				case "session-close":
					sec.DefaultPolicyLogSessionClose = true
				}
			}
			continue
		}
		// "global { policy ... }" - global policies applied to all zone pairs
		if child.Name() == "global" {
			for _, polInst := range namedInstances(child.FindChildren("policy")) {
				pol := compilePolicy(polInst)
				sec.GlobalPolicies = append(sec.GlobalPolicies, pol)
			}
			continue
		}
		// "from-zone trust to-zone untrust { ... }"
		if child.Name() == "from-zone" {
			type zonePair struct {
				from, to   string
				policyNode *Node
			}
			var pairs []zonePair

			if len(child.Keys) >= 4 {
				// Hierarchical: Keys=["from-zone", "trust", "to-zone", "untrust"]
				pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
			} else {
				// Flat set: from-zone → <name> → to-zone → <name> → policy ...
				for _, fzSub := range child.Children {
					tzNode := fzSub.FindChild("to-zone")
					if tzNode == nil {
						continue
					}
					for _, tzSub := range tzNode.Children {
						pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
					}
				}
			}

			for _, zp := range pairs {
				zpp := &ZonePairPolicies{
					FromZone: zp.from,
					ToZone:   zp.to,
				}

				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
					zpp.Policies = append(zpp.Policies, compilePolicy(polInst))
				}

				sec.Policies = append(sec.Policies, zpp)
			}
		}
	}
	return nil
}

// normalizePolicyAddrToken rewrites the Junos wildcard policy-match
// address keywords `any-ipv4` and `any-ipv6` into their concrete CIDR
// equivalents (`0.0.0.0/0` and `::/0`). Without this rewrite the
// tokens reach the dataplane as opaque strings that fail CIDR parsing
// and are silently dropped, so a policy keyed on `any-ipv4` would
// never match v4 traffic (#2008 H11). The plain `any` keyword is left
// intact — the dataplane already treats it as match-any on both
// families. All other tokens (address-book names, literal CIDRs) pass
// through unchanged.
func normalizePolicyAddrToken(tok string) string {
	switch tok {
	case "any-ipv4":
		return "0.0.0.0/0"
	case "any-ipv6":
		return "::/0"
	default:
		return tok
	}
}

func normalizePolicyAddrTokens(toks []string) []string {
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		out = append(out, normalizePolicyAddrToken(t))
	}
	return out
}

// policyMatchChildren returns the children of EVERY `match {}` block under a
// security-policy term, flattened in declaration order. #3842: a policy
// loaded via `load merge` / `load override` (or a hierarchical config that
// authors two blocks) carries DUPLICATE inner `match {}` blocks as SEPARATE
// children — parseStatements APPENDS a repeated block, it does not merge it
// (parser.go) — and Junos merges duplicate match blocks. Reading only the
// first via FindChild("match") silently DROPS the second block's constraints,
// WIDENING the policy with a clean commit (a security fail-open) AND hiding
// the second block from the strict match gates. The compiler (compilePolicy)
// and the strict match gates (validatePolicyMatchLeavesStrict #3113/#3142/
// #3673, validatePolicyRequiredMatchStrict #3044) all accumulate over this
// helper so every match block is both enforced and validated. #3562/#3377
// closed the top-level duplicate-`security`/`policies` and duplicate-action-
// node cases; this closes the duplicate inner match/then blocks under one
// term.
func policyMatchChildren(polNode *Node) []*Node {
	var out []*Node
	for _, mn := range polNode.FindChildren("match") {
		out = append(out, mn.Children...)
	}
	return out
}

// policyThenChildren is the `then {}` sibling of policyMatchChildren (#3842):
// the children of EVERY `then {}` block under a policy term, flattened in
// order. compilePolicy accumulates the terminal action / log / count over all
// then blocks, so a second `then { reject; }` after a first `then { permit; }`
// contributes a SECOND terminal action that the #3043 conflicting-terminal-
// action gate rejects at commit (the fail-closed floor) instead of being
// silently dropped into a fail-open permit.
func policyThenChildren(polNode *Node) []*Node {
	var out []*Node
	for _, tn := range polNode.FindChildren("then") {
		out = append(out, tn.Children...)
	}
	return out
}

// policyThenActionNodes returns every `then` action node named `action`
// (permit / deny / reject) across ALL `then {}` blocks under a policy term.
// The then-action reject gates (validatePolicyThenPermitStrict #3114,
// validatePolicyThenRejectStrict #3115, validatePolicyThenDenyStrict #3141)
// use it so a modifier carried by a DUPLICATE `then {}` block is inspected,
// not only the first block's action nodes (#3842). It composes with the
// existing per-then-block FindChildren(action) two-node handling (#3377).
func policyThenActionNodes(polNode *Node, action string) []*Node {
	var out []*Node
	for _, tn := range polNode.FindChildren("then") {
		out = append(out, tn.FindChildren(action)...)
	}
	return out
}

// compilePolicy extracts a Policy from a named policy instance.
func compilePolicy(polInst struct {
	name string
	node *Node
}) *Policy {
	pol := &Policy{Name: polInst.name}

	// #3842: accumulate across ALL `match {}` blocks (policyMatchChildren) —
	// a duplicate inner match block must contribute its constraints, never be
	// silently dropped by a FindChild-first read (a fail-open widening).
	matchChildren := policyMatchChildren(polInst.node)
	if len(matchChildren) > 0 {
		for _, m := range matchChildren {
			switch m.Name() {
			case "source-address":
				// #4121: read BOTH Keys[1:] AND Children via the
				// firewallMatchValues SSOT — the SAME reader the strict match
				// gates (validatePolicyMatchLeavesStrict) use — so the compiler
				// and gates can never diverge on a dual-AST shape (the #2419
				// bracketed-list class). The prior either/or read
				// (`if len(Keys)>=2 { Keys[1:] } else { Children }`) was correct
				// for every shape the parser actually produces (bracket/inline →
				// Keys, block → Children, repeated → sibling nodes, all mutually
				// exclusive), but a `source-address a1 { a2; }` node carrying
				// members in BOTH slots dropped the child members. Reading both
				// removes that divergence and shares one reader with the gates.
				pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, normalizePolicyAddrTokens(firewallMatchValues(m))...)
			case "destination-address":
				// #4121: read BOTH slots via the firewallMatchValues SSOT (see
				// the source-address arm).
				pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, normalizePolicyAddrTokens(firewallMatchValues(m))...)
			case "source-address-excluded":
				pol.Match.SourceAddressExcluded = true
			case "destination-address-excluded":
				pol.Match.DestinationAddressExcluded = true
			case "from-zone":
				// #3148: global-policy from-zone match context. The schema
				// exposes this leaf only under `security policies global
				// policy <p> match`; for zone-pair policies the zones come
				// from the surrounding from-zone/to-zone stanza so this case
				// is never reached. Empty stays "all zones".
				if len(m.Keys) >= 2 {
					pol.Match.FromZone = m.Keys[1]
				} else if len(m.Children) > 0 {
					pol.Match.FromZone = m.Children[0].Name()
				}
			case "to-zone":
				// #3148: global-policy to-zone match context (see from-zone).
				if len(m.Keys) >= 2 {
					pol.Match.ToZone = m.Keys[1]
				} else if len(m.Children) > 0 {
					pol.Match.ToZone = m.Children[0].Name()
				}
			case "application":
				// #4121: read BOTH slots via the firewallMatchValues SSOT (see
				// the source-address arm).
				pol.Match.Applications = append(pol.Match.Applications, firewallMatchValues(m)...)
			}
		}
	}

	// #3842: accumulate across ALL `then {}` blocks (policyThenChildren) so a
	// duplicate inner then block's terminal action / log / count is enforced.
	// Two terminal actions from two then blocks feed pol.terminalActions and
	// are rejected by the #3043 conflicting-terminal-action gate at commit
	// (fail-closed) rather than the second being silently dropped (fail-open).
	thenChildren := policyThenChildren(polInst.node)
	if len(thenChildren) > 0 {
		for _, t := range thenChildren {
			switch t.Name() {
			case "permit":
				pol.Action = PolicyPermit
				pol.terminalActions = append(pol.terminalActions, PolicyPermit)
			case "deny":
				pol.Action = PolicyDeny
				pol.terminalActions = append(pol.terminalActions, PolicyDeny)
				// #3141: a flat-set `then deny log session-init` collapses the
				// log/count modifier onto the deny node
				// (Keys=["deny","log","session-init",...], no children) instead
				// of nesting it as a sibling `then log` node. The deny arm used
				// to read only t.Name() and silently dropped the collapsed
				// modifier, so deny-with-logging committed but never logged.
				// Wire the collapsed log/count modifier here so deny+log works
				// in BOTH the flat-collapsed and the separate-node
				// (`then { deny; log session-init; }`, handled by the `log` arm)
				// forms — matching the standalone `then log`/`then count` arms.
				// validatePolicyThenDenyStrict rejects any OTHER (non-log,
				// non-count) collapsed deny modifier at commit (#3141).
				applyCollapsedDenyModifiers(pol, t)
			case "reject":
				pol.Action = PolicyReject
				pol.terminalActions = append(pol.terminalActions, PolicyReject)
			case "log":
				// #3703: `then log` is a multi-value session-log list leaf. A
				// bracket / single-line list (`then log [ session-init
				// session-close ]`) carries the modes as Keys[1:] AND/OR
				// one-per-child; read BOTH via the firewallMatchValues SSOT so
				// session-close is not dropped when it trails session-init in a
				// bracket list (the #2419 collapse bug). Unknown tokens are
				// rejected at commit by SchemaValidate (the enum leaf validator);
				// a bare `then log` (no mode) is rejected by
				// validatePolicyLogActionStrict (#3060). ACCUMULATE (create once,
				// never reset): a multi-value leaf whose values arrive on SEPARATE
				// flat-set lines (`then log session-init` + `then log
				// session-close`) produces TWO sibling `log` leaves, so resetting
				// pol.Log per node would drop the earlier flag.
				if pol.Log == nil {
					pol.Log = &PolicyLog{}
				}
				for _, mode := range firewallMatchValues(t) {
					switch mode {
					case "session-init":
						pol.Log.SessionInit = true
					case "session-close":
						pol.Log.SessionClose = true
					}
				}
			case "count":
				pol.Count = true
			}
		}
	}

	// #3043 fail-closed default: a policy with NO explicit terminal action
	// (a log-only / count-only stanza, or a typo'd `then`) must NOT inherit
	// PolicyPermit (the PolicyAction zero value) — that was a silent
	// fail-OPEN. Default the runtime action to DENY so the tolerant
	// load / HA-sync path (which only WARNS, see
	// validatePolicyTerminalActionStrict + lenientPolicyTerminalAction)
	// fails closed; the strict commit path rejects the actionless policy
	// outright (terminalActions is empty). Conflicting actions keep the
	// pre-existing last-wins runtime value so a leniently-loaded config
	// still boots; the strict gate rejects the conflict at commit.
	if len(pol.terminalActions) == 0 {
		pol.Action = PolicyDeny
	}

	if descNode := polInst.node.FindChild("description"); descNode != nil {
		pol.Description = nodeVal(descNode)
	}
	if snNode := polInst.node.FindChild("scheduler-name"); snNode != nil {
		pol.SchedulerName = nodeVal(snNode)
	}

	// #4232 (fable-167 P-4b): record any DIRECT child of `policy <name>` whose
	// keyword the compiler does not read. match/then/description/scheduler-name
	// are the recognized leaves; anything else (a typo like `descripton`, or an
	// unimplemented policy option) was silently dropped. Recording it lets the
	// compiler emit an accepted-but-inert / probable-typo advisory. Iterate in
	// config order for a deterministic warning.
	for _, child := range polInst.node.Children {
		switch child.Name() {
		case "match", "then", "description", "scheduler-name":
			// recognized above
		default:
			pol.UnknownChildren = append(pol.UnknownChildren, child.Name())
		}
	}

	return pol
}

// recognizedCollapsedDenyToken reports whether tok is a token that
// applyCollapsedDenyModifiers acts on inside a FLAT-collapsed `then deny`
// sequence — the `log`/`count` modifiers plus log's session-init/
// session-close sub-tokens. On the flat path the lexer flattens a modifier
// and its sub-tokens into a single Keys slice (e.g.
// Keys=["deny","log","session-init","count"]), so the validator cannot tell
// a modifier from a sub-token positionally; it accepts exactly the tokens
// the wiring consumes and rejects anything else. This is the single source
// of truth shared by applyCollapsedDenyModifiers (the wiring) and
// validatePolicyThenDenyStrict (the reject gate) so they never disagree on
// what is a supported token vs an unsupported modifier that would be
// silently dropped (#3141).
func recognizedCollapsedDenyToken(tok string) bool {
	switch tok {
	case "log", "session-init", "session-close", "count":
		return true
	default:
		return false
	}
}

// applyCollapsedDenyModifiers wires a `log`/`count` action modifier that a
// flat-set `then deny <modifier>` collapsed onto the deny node, so deny+log
// (and deny+count) work in the flat form exactly as they do as separate
// `then` siblings (#3141). The modifier appears in TWO AST shapes:
//   - Flat set `then deny log session-init` collapses the whole tail onto
//     the deny node: Keys=["deny","log","session-init"] (no children).
//     Keys[0] is "deny"; Keys[1:] carry the modifier and its sub-tokens.
//   - A hierarchical `then { deny { log { session-init; } } }` (non-canonical
//     but parseable) nests the modifier as a child node of deny.
//
// Only `log` (with session-init/session-close sub-tokens) and `count` are
// recognized — the exact set the standalone `then log`/`then count` arms
// support. Any OTHER collapsed deny modifier is left untouched here and
// rejected at commit by validatePolicyThenDenyStrict, mirroring the #3114/
// #3115 then-permit/then-reject reject-at-commit gates.
func applyCollapsedDenyModifiers(pol *Policy, denyNode *Node) {
	apply := func(tok string) {
		switch tok {
		case "log":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
		case "session-init":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
			pol.Log.SessionInit = true
		case "session-close":
			if pol.Log == nil {
				pol.Log = &PolicyLog{}
			}
			pol.Log.SessionClose = true
		case "count":
			pol.Count = true
		}
	}
	// Flat-collapsed tail: Keys[1:] (Keys[0] == "deny").
	if len(denyNode.Keys) >= 2 {
		for _, k := range denyNode.Keys[1:] {
			apply(k)
		}
	}
	// Hierarchical children (non-canonical shape).
	var walk func(n *Node)
	walk = func(n *Node) {
		for _, k := range n.Keys {
			apply(k)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range denyNode.Children {
		walk(c)
	}
}

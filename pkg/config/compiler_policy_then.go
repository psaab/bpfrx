package config

import "fmt"

// compiler_policy_then.go carries the #3114 reject-at-commit gate for a
// security-policy `then permit` action arm that carries an UNSUPPORTED
// child (e.g. `application-services`, firewall-authentication, tunnel
// ipsec-vpn).
//
// The defect: Junos SRX `then permit` accepts a rich set of action
// modifiers that turn a bare permit into a permit-with-inspection or a
// permit-into-tunnel — `application-services { utm-policy X; idp; }`,
// `firewall-authentication`, `tunnel ipsec-vpn`, `destination-address`,
// SSL-proxy / AppFW / SecIntel attachments, etc. xpf's policy compiler
// (compilePolicy in compiler_security.go) handles the `then` arm by
// switching only on the terminal/modifier tokens it implements —
// `permit`, `deny`, `reject`, `log`, `count`. The `permit` arm sets
// `pol.Action = PolicyPermit` and NEVER inspects `t.Children`. Any child
// under `then permit` falls out with NO error and is SILENTLY DROPPED. The
// set-schema (schema_security.go) does not list those children and
// schema_walk.go returns nil for unknown keywords by design, so nothing
// rejects them either.
//
// Why that is dangerous: dropping a `then permit application-services`
// (or any inspection/authentication modifier) turns a permit-only-with-
// inspection rule into an UNCONDITIONAL permit. An operator who writes
// `then permit application-services utm-policy strict-web` believes the
// traffic is UTM/IDP/SSL-proxy inspected; xpf forwards it without the
// service chain. Enforcement is weaker than the committed config — a
// direct security fail-OPEN. Surfacing it (reject at commit) is the safe
// choice.
//
// Full support for the `then permit` service chain (typed service-chain
// model + userspace capability gate + Rust enforcement) is a substantial,
// separate feature. Until it lands the SAFE behaviour is to REJECT an
// unsupported `then permit` child at commit rather than silently strip it
// — mirroring the campaign's reject-at-commit pattern for unsupported-but-
// parsed stanzas (#3113 unsupported policy `match` leaf, #3079 NAT
// rule-set scope, #3055 reserved zone names, #3060 bare `then log`). Same
// #1960 strict-with-lenient doctrine.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf, and not a
// typed-Config validator) for the same two reasons validatePolicyMatch-
// LeavesStrict (#3113) is — the dropped child is gone from the typed
// *Config by compile time (only the raw AST still carries it), and
// SchemaValidate returns nil for unknown keywords so it cannot REJECT.
// The walk runs on the group-expanded, inactive-pruned tree, so an
// apply-groups-inherited `then permit` child is caught and an `inactive:`
// policy is ignored for free.
//
// Both zone-pair (`from-zone`/`to-zone`) and `global` policies are
// covered.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// child is a hard compile error naming the policy scope, the policy, and
// the unsupported child, and directing the operator to remove it.
//
// Lenient path (load / peer-sync, lenient=true): every offending child is
// returned as a warning and compilation continues — an already-persisted
// or peer-synced config that an older binary silently accepted still
// BOOTS (#1960 fail-closed-on-load class). The child is NOT removed from
// the tree; it stays dropped by the compiler exactly as before this gate.

// supportedPolicyThenPermitChildren is the EXACT set of `then permit`
// children the policy compiler (compilePolicy in compiler_security.go)
// enforces. The `permit` arm sets pol.Action = PolicyPermit and reads NO
// children, so today the supported set is EMPTY — any child under
// `then permit` is silently dropped and is rejected by
// validatePolicyThenPermitStrict. Keep this in lockstep with compilePolicy's
// `then` switch: if the compiler ever learns to enforce a `then permit`
// modifier (e.g. a typed service chain), add it here so it is no longer
// rejected.
var supportedPolicyThenPermitChildren = map[string]bool{}

// validatePolicyThenPermitStrict walks the `security policies` subtree of
// the group-expanded AST and rejects any policy whose `then permit` action
// arm carries a child the compiler does not enforce (see file header).
// Covers both zone-pair and global policies.
func validatePolicyThenPermitStrict(nodes []*Node, lenient bool) ([]string, error) {
	var security *Node
	for _, n := range nodes {
		if n.Name() == "security" {
			security = n
			break
		}
	}
	if security == nil {
		return nil, nil
	}
	policies := security.FindChild("policies")
	if policies == nil {
		return nil, nil
	}

	var warnings []string
	emit := func(scope, policyName, child string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then permit %q is not supported "+
				"(xpf permits or denies on L3/L4 only; it does not implement "+
				"the permit service chain — application-services (UTM/IDP/"+
				"AppFW/SSL-proxy), firewall-authentication, or tunnel — and an "+
				"unsupported then-permit child is silently dropped, turning a "+
				"permit-with-inspection rule into an UNCONDITIONAL permit the "+
				"operator did not intend — a fail-open) — remove the %q "+
				"modifier under then permit (#3114)",
			scope, policyName, child, child,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkPolicy := func(scope, policyName string, polNode *Node) error {
		thenNode := polNode.FindChild("then")
		if thenNode == nil {
			return nil
		}
		permitNode := thenNode.FindChild("permit")
		if permitNode == nil {
			return nil
		}
		// A bare `then permit` (flat-set: a `permit` node with Keys=["permit"]
		// and no children; hierarchical: an empty `permit` block) is fully
		// supported. Only `then permit <modifier>` carries an unsupported
		// child. The modifier appears in TWO AST shapes, mirroring the
		// dual-shape handling the compiler must do everywhere:
		//   - Flat set `then permit application-services utm-policy X` collapses
		//     the whole tail onto the permit node: Keys=["permit",
		//     "application-services","utm-policy","X"]. The unsupported modifier
		//     is Keys[1]; Keys[2:] are its arguments.
		//   - Hierarchical `then { permit { application-services {...} } }`
		//     nests the modifier as a child node of permit.
		// Report the first offending modifier in either shape.
		if len(permitNode.Keys) >= 2 {
			child := permitNode.Keys[1]
			if !supportedPolicyThenPermitChildren[child] {
				if err := emit(scope, policyName, child); err != nil {
					return err
				}
			}
		}
		for _, c := range permitNode.Children {
			child := c.Name()
			if supportedPolicyThenPermitChildren[child] {
				continue
			}
			if err := emit(scope, policyName, child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, child := range policies.Children {
		switch child.Name() {
		case "global":
			for _, polInst := range namedInstances(child.FindChildren("policy")) {
				if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
					return nil, err
				}
			}
		case "from-zone":
			// Mirror compilePolicies' two AST shapes.
			type zonePair struct {
				from, to   string
				policyNode *Node
			}
			var pairs []zonePair
			if len(child.Keys) >= 4 {
				// Hierarchical: Keys=["from-zone","trust","to-zone","untrust"]
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
				scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
					if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return warnings, nil
}

// supportedPolicyThenRejectChildren is the EXACT set of `then reject`
// children the policy compiler (compilePolicy in compiler_security.go)
// enforces. The `reject` arm sets pol.Action = PolicyReject and reads NO
// children, so today the supported set is EMPTY — any child under
// `then reject` (a Junos reject-profile `profile <name>`, a packet-type
// reject like `tcp-reset`, or any other modifier) is silently dropped and
// is rejected by validatePolicyThenRejectStrict. Keep this in lockstep
// with compilePolicy's `then` switch `reject` arm: if the compiler ever
// learns to enforce a `then reject` modifier (a synthesized reject
// response or a per-packet-type reset), add it here so it is no longer
// rejected.
var supportedPolicyThenRejectChildren = map[string]bool{}

// validatePolicyThenRejectStrict walks the `security policies` subtree of
// the group-expanded AST and rejects any policy whose `then reject` action
// arm carries a child the compiler does not enforce — the #3115 sibling of
// validatePolicyThenPermitStrict (#3114).
//
// The defect: compilePolicy's `then` switch `reject` arm sets
// `pol.Action = PolicyReject` and NEVER inspects `t.Children`. A
// `then reject profile <name>` (a custom reject-response profile) or a
// `then reject tcp-reset` (a packet-type reject) therefore commits cleanly
// but has its profile / packet-type SILENTLY DROPPED — the dataplane emits
// generic reject behaviour regardless of what the operator configured. The
// set-schema (schema_security.go) does not list `reject` children and
// schema_walk.go returns nil for unknown keywords, so nothing rejects them
// either. The configured wire-contract / blocked-content semantics are
// lost without any commit-time signal: the operator cannot tell the
// profile is inert.
//
// Unlike #3114 (a dropped `then permit application-services` turns a
// permit-with-inspection rule into an UNCONDITIONAL permit — a fail-open)
// this is not a fail-open: reject still rejects. But it is a wire-contract
// and operator-observability divergence — until reject profiles / packet-
// type rejects are implemented the SAFE behaviour is to REJECT an
// unsupported `then reject` child at commit rather than silently strip it.
// A bare `then reject` (no child) is fully supported and commits.
//
// Same AST-pre-walk rationale, dual-shape (flat-set Keys[1] + hierarchical
// Children) handling, both-scope (zone-pair + global) coverage, and
// #1960 strict-with-lenient doctrine as validatePolicyThenPermitStrict.
func validatePolicyThenRejectStrict(nodes []*Node, lenient bool) ([]string, error) {
	var security *Node
	for _, n := range nodes {
		if n.Name() == "security" {
			security = n
			break
		}
	}
	if security == nil {
		return nil, nil
	}
	policies := security.FindChild("policies")
	if policies == nil {
		return nil, nil
	}

	var warnings []string
	emit := func(scope, policyName, child string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then reject %q is not supported "+
				"(xpf emits a generic reject only; it does not implement "+
				"reject profiles or per-packet-type reject responses such as "+
				"tcp-reset — an unsupported then-reject child is silently "+
				"dropped, so the configured custom reject response is inert and "+
				"the operator cannot tell from commit that it has no effect) — "+
				"remove the %q modifier under then reject (a bare then reject "+
				"still works) (#3115)",
			scope, policyName, child, child,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkPolicy := func(scope, policyName string, polNode *Node) error {
		thenNode := polNode.FindChild("then")
		if thenNode == nil {
			return nil
		}
		rejectNode := thenNode.FindChild("reject")
		if rejectNode == nil {
			return nil
		}
		// A bare `then reject` (flat-set: a `reject` node with
		// Keys=["reject"] and no children; hierarchical: an empty `reject`
		// block) is fully supported. Only `then reject <modifier>` carries
		// an unsupported child, in TWO AST shapes:
		//   - Flat set `then reject profile blocked-web` collapses the tail
		//     onto the reject node: Keys=["reject","profile","blocked-web"].
		//     The unsupported modifier is Keys[1]; Keys[2:] are its args.
		//   - Hierarchical `then { reject { profile {...} } }` nests the
		//     modifier as a child node of reject.
		// Report the first offending modifier in either shape.
		if len(rejectNode.Keys) >= 2 {
			child := rejectNode.Keys[1]
			if !supportedPolicyThenRejectChildren[child] {
				if err := emit(scope, policyName, child); err != nil {
					return err
				}
			}
		}
		for _, c := range rejectNode.Children {
			child := c.Name()
			if supportedPolicyThenRejectChildren[child] {
				continue
			}
			if err := emit(scope, policyName, child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, child := range policies.Children {
		switch child.Name() {
		case "global":
			for _, polInst := range namedInstances(child.FindChildren("policy")) {
				if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
					return nil, err
				}
			}
		case "from-zone":
			// Mirror compilePolicies' two AST shapes.
			type zonePair struct {
				from, to   string
				policyNode *Node
			}
			var pairs []zonePair
			if len(child.Keys) >= 4 {
				pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
			} else {
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
				scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
					if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return warnings, nil
}

// supportedPolicyThenDenyChildren is the EXACT set of collapsed `then deny`
// modifiers the policy compiler enforces. Unlike the then-permit (#3114) and
// then-reject (#3115) arms — whose supported sets are EMPTY because no
// permit/reject modifier is implemented — `then deny` legitimately combines
// with the observability modifiers `log` (with session-init/session-close)
// and `count`, which the standalone `then log`/`then count` arms already
// implement. compilePolicy's `deny` arm wires these collapsed modifiers via
// applyCollapsedDenyModifiers (#3141), so they are SUPPORTED here. Any OTHER
// collapsed deny modifier is silently dropped by the compiler and is rejected
// by validatePolicyThenDenyStrict. Keep this in lockstep with
// applyCollapsedDenyModifiers: if the compiler learns to enforce a new
// collapsed `then deny` modifier, add it here so it is no longer rejected.
var supportedPolicyThenDenyChildren = map[string]bool{
	"log":   true,
	"count": true,
}

// validatePolicyThenDenyStrict walks the `security policies` subtree of the
// group-expanded AST and rejects any policy whose `then deny` action arm
// carries a collapsed modifier the compiler does not enforce — the #3141
// sibling of validatePolicyThenPermitStrict (#3114) and
// validatePolicyThenRejectStrict (#3115). Covers both zone-pair and global
// policies.
//
// The defect (codex-review-068 finding 068-01): compilePolicy's `then`
// switch `deny` arm set `pol.Action = PolicyDeny` and NEVER inspected the
// collapsed tail. A flat-set `then deny log session-init` collapses
// `log session-init` onto the deny node (Keys=["deny","log","session-init"])
// rather than nesting it as a sibling `then log` node, so the deny arm
// dropped it — the policy denied traffic but `pol.Log` was never set and the
// configured audit logging was silently inert (a deny-rule observability /
// compliance failure, not a packet fail-open). #3141 fixes the LEGITIMATE
// deny+log/deny+count case by wiring those collapsed modifiers in the
// compiler (applyCollapsedDenyModifiers). This validator is the safety net
// for the REMAINING collapsed modifiers the compiler still cannot enforce:
// they are rejected at commit rather than silently stripped.
//
// Same AST-pre-walk rationale, dual-shape (flat-set Keys[1] + hierarchical
// Children) handling, both-scope (zone-pair + global) coverage, and #1960
// strict-with-lenient doctrine as validatePolicyThenPermitStrict. A bare
// `then deny`, and a `then deny log`/`then deny count` (now wired), commit.
func validatePolicyThenDenyStrict(nodes []*Node, lenient bool) ([]string, error) {
	var security *Node
	for _, n := range nodes {
		if n.Name() == "security" {
			security = n
			break
		}
	}
	if security == nil {
		return nil, nil
	}
	policies := security.FindChild("policies")
	if policies == nil {
		return nil, nil
	}

	var warnings []string
	emit := func(scope, policyName, child string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then deny %q is not supported "+
				"(xpf denies on L3/L4 and supports only the log "+
				"(session-init/session-close) and count modifiers under "+
				"then deny — an unsupported then-deny modifier is silently "+
				"dropped, so the configured behavior is inert and the operator "+
				"cannot tell from commit that it has no effect) — remove the "+
				"%q modifier under then deny (a bare then deny, then deny log, "+
				"or then deny count still works) (#3141)",
			scope, policyName, child, child,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// #3374: session-init/session-close are LOG sub-options, valid ONLY when
	// a `log` token accompanies them in the same collapsed action. A flat-set
	// `then deny session-init` (no `log`) collapses to
	// Keys=["deny","session-init"]; recognizedCollapsedDenyToken accepts the
	// bare sub-token (it cannot tell a sub-token from a top-level modifier
	// positionally), so the gate above let it through and
	// applyCollapsedDenyModifiers silently wired session-init logging for a
	// form Junos rejects. emitOrphanLogSub flags a session-init/session-close
	// sub-token that has no `log` parent in the collapsed tail.
	emitOrphanLogSub := func(scope, policyName, tok string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q then deny %q is not valid without "+
				"a log token — session-init/session-close are sub-options of "+
				"then deny log (or the standalone then log), not bare deny "+
				"modifiers, so a collapsed then deny %s silently wires logging "+
				"for syntax Junos rejects — use then deny log %s (or then log "+
				"%s) instead (#3374)",
			scope, policyName, tok, tok, tok, tok,
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkPolicy := func(scope, policyName string, polNode *Node) error {
		thenNode := polNode.FindChild("then")
		if thenNode == nil {
			return nil
		}
		denyNode := thenNode.FindChild("deny")
		if denyNode == nil {
			return nil
		}
		// A bare `then deny` (flat-set: a `deny` node with Keys=["deny"] and
		// no children; hierarchical: an empty `deny` block) is fully
		// supported. Only `then deny <modifier>` carries a collapsed child,
		// in TWO AST shapes:
		//   - Flat set `then deny log session-init count` collapses the WHOLE
		//     tail onto the deny node:
		//     Keys=["deny","log","session-init","count"]. EVERY token in
		//     Keys[1:] is a flattened modifier or modifier sub-token; they
		//     must ALL be recognized. Checking only Keys[1] missed a
		//     supported-leads / unsupported-trails sequence like
		//     `then deny count evilmod`, which slipped through and was
		//     silently dropped — exactly the failure mode this gate prevents
		//     (#3141 review fold). The recognized set
		//     (recognizedCollapsedDenyToken) is the EXACT set
		//     applyCollapsedDenyModifiers acts on — the `log`/`count`
		//     modifiers plus log's session-init/session-close sub-tokens — so
		//     the validator and the wiring agree on what is a modifier vs a
		//     sub-token. Report the first unrecognized token.
		//   - Hierarchical `then { deny { profile {...} } }` nests the
		//     modifier as a DIRECT child node of deny; the modifier's own
		//     sub-tokens nest deeper, so a direct child must be a top-level
		//     modifier — checked against supportedPolicyThenDenyChildren
		//     ({log, count}).
		tail := denyNode.Keys[1:]
		hasLog := false
		for _, tok := range tail {
			if tok == "log" {
				hasLog = true
				break
			}
		}
		for _, tok := range tail {
			if !recognizedCollapsedDenyToken(tok) {
				if err := emit(scope, policyName, tok); err != nil {
					return err
				}
				continue
			}
			// #3374: a recognized session-init/session-close sub-token is
			// valid only with a `log` token in the same collapsed tail.
			if (tok == "session-init" || tok == "session-close") && !hasLog {
				if err := emitOrphanLogSub(scope, policyName, tok); err != nil {
					return err
				}
			}
		}
		for _, c := range denyNode.Children {
			child := c.Name()
			if supportedPolicyThenDenyChildren[child] {
				continue
			}
			if err := emit(scope, policyName, child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, child := range policies.Children {
		switch child.Name() {
		case "global":
			for _, polInst := range namedInstances(child.FindChildren("policy")) {
				if err := checkPolicy("global", polInst.name, polInst.node); err != nil {
					return nil, err
				}
			}
		case "from-zone":
			// Mirror compilePolicies' two AST shapes.
			type zonePair struct {
				from, to   string
				policyNode *Node
			}
			var pairs []zonePair
			if len(child.Keys) >= 4 {
				pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
			} else {
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
				scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
				for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
					if err := checkPolicy(scope, polInst.name, polInst.node); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return warnings, nil
}

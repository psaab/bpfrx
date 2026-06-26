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

package config

import "fmt"

// compiler_nat_scope.go carries the #3079 reject-at-commit gate for a NAT
// rule-set whose `from`/`to` clause scopes traffic by `interface` or
// `routing-instance` instead of (the only enforced) `zone`.
//
// The defect: Junos NAT rule-sets scope matched traffic with a
// `from`/`to` clause that takes one of `zone | interface |
// routing-instance`. xpf's compiler only ever extracted the `zone`
// children (parseZoneList, compiler_nat.go) — an `interface`- or
// `routing-instance`-scoped rule-set COMMITTED cleanly, but the scope
// was SILENTLY DISCARDED: every caller (compileNATSource /
// compileNATDestination / compileNATStatic) falls back to the match-any
// wildcard `[]string{""}` when the returned zone list is empty. So a
// rule-set the operator meant to restrict to one interface or one VRF
// instead applied GLOBALLY — translated sessions leaked across the
// routing boundary the operator drew. That is a security / isolation
// failure (silent over-application of NAT), not a cosmetic gap.
//
// Full interface- / routing-instance-scoped matching in the NAT match
// path is a substantial dataplane change (preserve the scope on the typed
// NATRuleSet and enforce it per-flow). Until that lands, the SAFE
// behaviour is to REJECT these scopes at commit rather than silently
// widen them to match-any — surfacing the misconfiguration instead of
// quietly forwarding it as global NAT. This mirrors the campaign's
// reject-at-commit pattern for unsupported-but-parsed stanzas
// (#3018 wildcard from/to-zone, #3055 reserved zone names,
// #3060 bare `then log`). Full enforcement is the deferred follow-up.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf, and not a
// typed-Config validator) for two reasons:
//
//   - The scope keyword is the very thing the compiler drops, so by the
//     time the typed *Config exists the `interface`/`routing-instance`
//     information is already gone — only the raw AST still carries it.
//   - SchemaValidate is opt-in per known leaf and returns nil for unknown
//     keywords by design (schema_walk.go), so it cannot REJECT
//     `from interface ...`. Every other reject-at-commit-for-unsupported
//     gate (validateUnsupportedInterfaceStanzasAST,
//     validateVRRPTrackInterfaceAST, validateTCPMSSRanges) is likewise an
//     AST pre-walk in compileExpanded. The walk runs on the
//     group-expanded, inactive-pruned tree, so an apply-groups-inherited
//     scope is caught and an `inactive:` scope is ignored for free.
//
// The from/to `zone` scope (the supported case) and a rule-set with no
// from/to clause at all (the legitimate global case) are accepted — only
// `interface` and `routing-instance` are rejected.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// scope is a hard compile error naming the NAT kind, rule-set, direction,
// the unsupported keyword, and its value.
//
// Lenient path (load / peer-sync, lenient=true): every offending scope is
// returned as a warning and compilation continues — an already-persisted
// or peer-synced config that an older binary silently accepted still BOOTS
// (#1960 fail-closed-on-load class). The scope is NOT removed from the
// tree; the rule-set keeps applying globally exactly as it did before this
// gate (the pre-existing behaviour), now flagged. Mirrors
// validateUnsupportedInterfaceStanzasAST's no-prune lenient handling.

// natRuleSetScopeKinds is the set of NAT kinds whose rule-sets carry a
// from/to clause that the compiler reads via parseZoneList. nat64 uses a
// different match model and is intentionally out of scope here.
var natRuleSetScopeKinds = []string{"source", "destination", "static"}

// natUnsupportedScopeKeywords are the from/to scope keywords xpf parses
// but does not enforce in the NAT match path. `zone` is supported and is
// deliberately absent.
var natUnsupportedScopeKeywords = map[string]bool{
	"interface":        true,
	"routing-instance": true,
}

// validateNATRuleSetScopeAST walks the `security nat {source|destination|
// static}` subtree of the group-expanded AST and rejects any rule-set
// whose `from`/`to` clause scopes traffic by `interface` or
// `routing-instance` (see file header).
func validateNATRuleSetScopeAST(nodes []*Node, lenient bool) ([]string, error) {
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
	nat := security.FindChild("nat")
	if nat == nil {
		return nil, nil
	}

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	for _, kind := range natRuleSetScopeKinds {
		kindNode := nat.FindChild(kind)
		if kindNode == nil {
			continue
		}
		for _, rs := range namedInstances(kindNode.FindChildren("rule-set")) {
			for _, dir := range []string{"from", "to"} {
				for _, clause := range rs.node.FindChildren(dir) {
					for _, kw := range scopeKeywordsUnsupported(clause) {
						if err := emit(
							"security nat %s rule-set %q %s %s %q scope is not "+
								"supported (xpf only enforces `from`/`to` `zone` "+
								"for NAT rule-sets; an %s-scoped rule-set would be "+
								"silently applied to ALL traffic, leaking "+
								"translated sessions across the routing boundary) "+
								"— use `%s zone <zone>` or remove the scope (#3079)",
							kind, rs.name, dir, kw.keyword, kw.value, kw.keyword, dir,
						); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// scopeKeyword pairs an unsupported scope keyword with its configured
// value (for the operator-facing error/warning message).
type scopeKeyword struct {
	keyword string
	value   string
}

// scopeKeywordsUnsupported returns the unsupported (`interface` /
// `routing-instance`) scope keywords carried by a from/to clause node, in
// both AST shapes parseZoneList handles:
//
//   - flat-set: each scope is a child leaf, Keys=["interface", <val>] or
//     Keys=["routing-instance", <val>] (the shape ParseSetCommand +
//     SetPath produces and the shape verified in
//     compiler_nat_scope_3079_test.go).
//   - hierarchical / inline: the clause node carries the scope inline on
//     its own Keys, e.g. Keys=["from","interface",<val>] — symmetric with
//     parseZoneList's `node.Keys[1] == "zone"` inline branch.
func scopeKeywordsUnsupported(clause *Node) []scopeKeyword {
	var out []scopeKeyword
	// Inline shape: `from`/`to` node carries the scope on its own Keys.
	if len(clause.Keys) >= 2 && natUnsupportedScopeKeywords[clause.Keys[1]] {
		val := ""
		if len(clause.Keys) >= 3 {
			val = clause.Keys[2]
		}
		out = append(out, scopeKeyword{keyword: clause.Keys[1], value: val})
	}
	// Child-leaf shape: one child per scope token.
	for _, child := range clause.Children {
		kw := child.Name()
		if !natUnsupportedScopeKeywords[kw] {
			continue
		}
		val := ""
		if len(child.Keys) >= 2 {
			val = child.Keys[1]
		}
		out = append(out, scopeKeyword{keyword: kw, value: val})
	}
	return out
}

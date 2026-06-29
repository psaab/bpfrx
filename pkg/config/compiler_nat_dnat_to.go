package config

import "fmt"

// compiler_nat_dnat_to.go carries the #3444 reject-at-commit gate for a
// destination-NAT rule-set `to` scope.
//
// A Junos destination-NAT rule-set has only a `from` clause (zone |
// interface | routing-instance). DNAT translates the destination address on
// the inbound packet, so there is no egress / `to` context yet — only source
// NAT (which has both `from` and `to`) and the routed forward path can scope
// by an egress context. xpf's setSchema briefly advertised a `to` scope under
// `security nat destination rule-set`, and compileNATDestination
// Cartesian-expanded the collected `to` scopes onto each NATRuleSet
// (ToZone/ToInterface/ToRoutingInstance). But the userspace snapshot builder
// (pkg/dataplane/userspace/nat.go buildDestinationNATSnapshots) and the Rust
// DNAT runtime (userspace-dp/src/nat/destination.rs) model ONLY the `from`
// clause for DNAT — the DestinationNATRuleSnapshot wire struct intentionally
// has no `to_*`. So a configured `to zone|interface|routing-instance` was
// silently dropped: the translation applied regardless of the operator's
// declared destination context, and the operator got no error. Admitting a
// `to` scope that the running firewall does not enforce is a silent
// functional lie, so this gate hard-rejects it at commit / commit-check and
// warns (does not fail) on the tolerant load / peer-sync paths per the #1960
// fail-closed-on-load doctrine.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) because
// SchemaValidate is opt-in per known leaf and returns nil for unknown
// keywords by design (schema_walk.go) — it cannot REJECT a stanza, and the
// `to` keyword itself is legitimate elsewhere (source NAT rule-sets). The
// `to` subtree has also been removed from the DNAT rule-set setSchema so the
// CLI no longer offers it in completion; this gate covers the runtime
// reject + the already-persisted lenient-load path. Detection is scoped to
// `security nat destination rule-set` so the source-NAT `to` clause (a real
// feature) is never touched. The walk runs on the group-expanded,
// inactive-pruned tree (compileConfigWithOpts / compileConfigForNodeWithOpts
// strip inactive subtrees and expand groups before compileExpanded), so an
// apply-groups-inherited `to` is caught and an `inactive:` rule-set is
// ignored for free.

// validateDNATRuleSetToScopeAST walks the `security nat destination
// rule-set` subtree of the group-expanded AST and rejects any rule-set
// carrying a `to` scope.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// rule-set is a hard compile error, naming the exact rule-set.
//
// Lenient path (load / peer-sync, lenient=true): every offending rule-set is
// returned as a warning and compilation continues. The `to` subtree is NOT
// pruned — compileNATDestination no longer reads it (collectNATScopes with
// wantTo=false), so leaving it in the cloned tree is harmless and the warning
// is the operator signal.
func validateDNATRuleSetToScopeAST(nodes []*Node, lenient bool) ([]string, error) {
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
	natNode := security.FindChild("nat")
	if natNode == nil {
		return nil, nil
	}
	dstNode := natNode.FindChild("destination")
	if dstNode == nil {
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

	for _, rs := range namedInstances(dstNode.FindChildren("rule-set")) {
		if rs.node.FindChild("to") == nil {
			continue
		}
		if err := emit(
			"security nat destination rule-set %q: a `to` scope is not "+
				"supported on a destination-NAT rule-set (Junos DNAT has only "+
				"a `from` clause — the destination is translated on inbound, so "+
				"there is no egress context; the `to` scope was silently ignored "+
				"and the translation applied regardless of it) — remove it (#3444)",
			rs.name); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

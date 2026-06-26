package config

import (
	"fmt"
	"strings"
)

// compiler_policy_missing_match.go carries the #3044 reject-at-commit gate
// for a security policy whose `match` clause is MISSING one of the three
// mandatory Junos match dimensions — source-address, destination-address,
// or application — or that omits the `match` block entirely.
//
// The defect: Junos/vSRX requires every security policy `match` to specify
// all three core dimensions (source-address, destination-address, and
// application); a policy missing any of them is rejected at commit. xpf's
// policy compiler (compilePolicy in compiler_security.go) instead treats
// the whole `match` block — and every leaf within it — as OPTIONAL: the
// fields are filled only when matchNode != nil, and an absent
// source-address / destination-address / application simply leaves the
// corresponding slice empty. The userspace dataplane then interprets an
// empty slice as match-ANY (capabilities.go returns a nil app-term list
// for "no apps"; userspace-dp/src/policy.rs compiles an empty app list as
// match_any:true and defaults source/destination_*_match_any to true when
// the literal+book sets are empty). No commit-time validation requires the
// three dimensions.
//
// Why that is dangerous: a partial policy is SILENTLY BROADER than typed.
// `match source-address corp; then permit` permits `corp -> any:any`
// (every destination, every application); a policy with no `match` block
// at all becomes a zone-pair-wide permit (or deny). A single dropped line
// in an automation template widens a narrow rule to all traffic — a
// fail-OPEN for a permit policy, an over-broad block for a deny policy.
// On Junos this configuration cannot commit; on xpf it commits and ships
// a wildcard. Surfacing it (reject at commit) restores Junos parity and is
// the safe choice.
//
// Contract (Junos parity): the three dimensions are REQUIRED, and a
// missing dimension is treated DIFFERENTLY from an explicit wildcard. An
// operator who wants any-source / any-destination / any-application must
// write it explicitly — `match { source-address any; destination-address
// any; application any; }` — exactly as Junos demands. Only the absence of
// the leaf is rejected; `any` (or `any-ipv4` / `any-ipv6`, an address
// book name, a literal CIDR, a named application / application-set) all
// satisfy the requirement. `source-address-excluded` /
// `destination-address-excluded` are MODIFIERS of source/destination-
// address, not substitutes, so they do not by themselves satisfy the
// source-address / destination-address requirement (Junos requires the
// base address leaf alongside the excluded modifier).
//
// This is an AST pre-walk (not a SchemaValidate typed leaf, and not a
// typed-*Config validator) for the same reasons the #3113 unsupported-
// match-leaf gate (validatePolicyMatchLeavesStrict) is: a missing leaf
// leaves no trace in the typed *Config (the empty slice is
// indistinguishable from an explicit-any that also resolves to match-any),
// and SchemaValidate is opt-in per known leaf and cannot REJECT an absence.
// The walk runs on the group-expanded, inactive-pruned tree, so an
// apply-groups-inherited match dimension counts toward the requirement and
// an `inactive:` policy is ignored for free.
//
// Both zone-pair (`from-zone`/`to-zone`) and `global` policies are covered.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// policy is a hard compile error naming the policy scope, the policy, and
// every missing dimension, directing the operator to add it (write `any`
// for an intentional wildcard).
//
// Lenient path (load / peer-sync, lenient=true): every offending policy is
// returned as a warning and compilation continues — an already-persisted
// or peer-synced config that an older binary silently accepted still BOOTS
// (#1960 fail-closed-on-load class). The policy keeps its pre-existing
// match-any-for-missing compilation exactly as before this gate, now
// flagged. Same doctrine as validatePolicyMatchLeavesStrict.

// requiredPolicyMatchLeaves are the three Junos-mandatory match dimensions
// every active security policy must specify. Kept in declaration order so
// the error message lists missing dimensions deterministically.
var requiredPolicyMatchLeaves = []string{
	"source-address",
	"destination-address",
	"application",
}

// validatePolicyRequiredMatchStrict walks the `security policies` subtree of
// the group-expanded AST and rejects any policy whose `match` clause omits a
// required dimension (source-address, destination-address, application) or
// omits the `match` block entirely. Covers both zone-pair and global
// policies. See the file header for the contract and rationale.
func validatePolicyRequiredMatchStrict(nodes []*Node, lenient bool) ([]string, error) {
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
	emit := func(scope, policyName string, missing []string) error {
		msg := fmt.Sprintf(
			"security policies %s policy %q match is missing required "+
				"criterion %s (Junos requires every security policy to specify "+
				"source-address, destination-address, AND application; a missing "+
				"dimension is silently compiled as match-ANY, WIDENING the policy "+
				"to traffic the operator did not intend — a fail-open for permit, "+
				"an over-broad block for deny) — add the missing criterion, using "+
				"the explicit `any` keyword for an intentional wildcard (#3044)",
			scope, policyName, strings.Join(quoteAll(missing), ", "),
		)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkPolicy := func(scope, policyName string, polNode *Node) error {
		present := map[string]bool{}
		if matchNode := polNode.FindChild("match"); matchNode != nil {
			for _, m := range matchNode.Children {
				present[m.Name()] = true
			}
		}
		var missing []string
		for _, req := range requiredPolicyMatchLeaves {
			if !present[req] {
				missing = append(missing, req)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		return emit(scope, policyName, missing)
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

// quoteAll wraps each token in %q-style quotes for the error message.
func quoteAll(toks []string) []string {
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		out = append(out, fmt.Sprintf("%q", t))
	}
	return out
}

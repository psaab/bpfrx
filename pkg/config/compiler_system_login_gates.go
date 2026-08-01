package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_system_login_packed.go carries the #6662 commit-side gate for a
// `system login` body written on the statement line rather than in a nested
// block. Junos accepts both spellings; xpf compiles only the block (and the
// equivalent flat-`set`) form, so the packed spelling commits an EMPTY object:
//
//	system { login { user alice { class ops; } } }      -> Class = "ops"
//	system { login { user alice class ops; } }          -> Class = ""      <- dropped
//	system { login { class ops { permissions [ view configure ]; } } }
//	                                                    -> Permissions = [view configure]
//	system { login { class ops permissions [ view configure ]; } }
//	                                                    -> Permissions = []  <- dropped
//	system { login { user alice { authentication ssh-rsa "..."; } } }
//	                                                    -> SSHKeys = []      <- dropped
//
// The mechanism is the one documented in docs/config-schema.md ("Packed
// statements"): `namedInstances` resolves the instance NAME across both AST
// shapes (it reads Keys[1]) but hands the node back with the body still on
// Keys, and the login compiler then walks `.Children`, which is empty. One
// level down, `authentication` is the only login body statement the compiler
// reads exclusively through `.Children`, so its inline spelling drops the same
// way. Flat-set (`ParseSetCommand` + `SetPath`) is unaffected in every case:
// the schema consumes exactly the instance name as the keyed arg and hangs the
// rest off as children. The exposure is hand-authored hierarchical config text
// and `load override` — precisely how a vSRX config is migrated.
//
// WHY REJECT RATHER THAN UNPACK. Every downstream safety net in this stanza is
// guarded on NON-EMPTINESS, so an empty compile silences the whole belt:
//
//   - an empty user class means pkg/cli's `c.userClass == ""`, which is the
//     DELIBERATE legacy "no RBAC configured" shortcut — checkPermission returns
//     nil (allow everything) and showConfigRedacted returns false (cleartext
//     PSKs, SNMP communities, authentication-keys). The shortcut is correct;
//     the defect is that a config WITH RBAC configured reaches it. That
//     compounds with the #6701 identity fix in the permissive direction, which
//     is why the two ship together;
//   - an empty class permission set maps to the coarse `{none}` bucket, and the
//     `deny-commands` / `deny-configuration` advisory at
//     loginClassAdvisoryWarnings is guarded on `lc.DenyCommands != ""` — the
//     very warning that tells the operator the class is MORE PERMISSIVE than
//     the Junos source never fires, because the field the bug dropped is the
//     one the guard reads;
//   - a dropped `authentication` block leaves the account with no key and no
//     password.
//
// Unpacking would have to be exactly right for every leaf to avoid minting a
// wrong-but-non-empty class, which is worse than an empty one. Rejecting is
// unambiguous and both accepted spellings (nested block, flat `set`) already
// work, so the operator has a mechanical rewrite.
//
// Strictness follows the sibling AST gates: hard-reject at commit /
// commit-check, downgrade to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (#1960 no-brick) so a node that persisted such a config under
// an older binary still BOOTS — leniently loaded, the stanza stays as inert as
// it already was, now with the drop stated.
//
// BOTH-NODE EVALUATION (#6706 review blocker). Both gates below run
// PRE-EXPANSION and evaluate the effective view of EVERY cluster node (the
// node0 AND node1 `${node}`/apply-groups expansions), exactly like the sibling
// union gates validateQinQVLANStackAST (#5879) and validateVLANMapAST (#6178).
// Evaluating only the committing node's view left both gates fully bypassable:
//
//	groups {
//	    node1 { system { login {
//	        class super-user { permissions view; }
//	        user bob { class super-user; }
//	    } } }
//	}
//	apply-groups "${node}";
//
// Committed on node 0, the node-1 body is stripped by ExpandGroupsWithVars
// before either gate sees anything, so strict commit-check passes. The peer
// then ingests the config through Store.SyncApply, which is the TOLERANT path
// (compileTreeLenient) and only warns. On node 1 the stanza is live, and
// pkg/cli resolveClassPerms resolves the built-in `super-user` first — bob
// holds PermAll, and the authored `permissions view` narrowing that the
// operator read as restrictive never applied on either node. The origin commit
// is the only strict check the peer view ever gets, so it has to run here; that
// is the same argument compiler_peer_effective_snat.go makes for source NAT
// (#5876), applied at the AST layer these gates live in rather than on a
// compiled *Config.
//
// Only the two per-node effective views are unioned — deliberately NOT the
// pre-expansion all-groups "View 1" that the COLLISION-shaped union gates
// (validateZoneIDCollisionAST, validateInterfaceUnitAliasCollisionsAST #5878)
// also fold in. Both login gates trip on a SINGLE property, so a View-1 union
// would additionally reject a packed or shadowing body staged in a group that
// no `apply-groups` references — inert dead config that renders on no node.
// TestLoginPackedInsideAppliedGroupRejected_6662 pins that unapplied groups
// stay inert.

// loginInstanceKeywords is the set of `system login` NAMED INSTANCES, i.e. the
// keywords under `login` that take an identity argument and a body. It is the
// full child set of the `login` schema node (schema_system.go); `login` has no
// other children, so the enumeration below is the whole stanza.
//
// Kept in step with the schema by TestLoginInstanceKeywordsMatchSchema_6662.
var loginInstanceKeywords = []string{"class", "user"}

// loginBlockOnlyStatements enumerates, per login instance keyword, the body
// statements whose value the compiler reads ONLY through `node.Children` — so
// writing the body inline on the statement line drops it.
//
// Derived by reading compiler_system.go's `login` arm against the `login`
// schema node, statement by statement. The full body vocabulary and its
// classification:
//
//	class <name>:
//	  permissions          multi-value leaf -> firewallMatchValues reads Keys[1:]
//	                       AND Children and accumulates (#2419) — inline is FINE
//	  idle-timeout         leaf -> nodeVal handles both shapes — FINE
//	  allow-commands       leaf -> nodeVal — FINE
//	  deny-commands        leaf -> nodeVal — FINE
//	  allow-configuration  leaf -> nodeVal — FINE
//	  deny-configuration   leaf -> nodeVal — FINE
//	  login-alarms         flag, no compiler arm at all in EITHER shape (a
//	                       pre-existing accept-but-ignore gap, not a packed
//	                       drop) — not this gate's business
//	  login-tip            flag, same as login-alarms
//
//	user <name>:
//	  uid                  leaf -> nodeVal — FINE
//	  class                leaf -> nodeVal — FINE
//	  authentication       BLOCK ONLY -> the compiler ranges over prop.Children
//	                       for encrypted-password / ssh-ed25519 / ssh-rsa /
//	                       ssh-dsa and never looks at Keys — inline DROPS
//
// So `authentication` is the only entry. It is a map rather than a hardcoded
// check so adding a block-bodied login statement is a one-line change here, and
// TestLoginBlockOnlyStatementsAreSchemaChildren_6662 fails if a name listed
// here is not a real schema child (a typo would silently disable the gate).
//
// The VALUE is the statement's ARITY: how many tokens after the keyword
// legitimately belong to its key rather than being a packed body. `authentication`
// takes none, so anything after the keyword is a packed body. A future
// block-bodied statement that DOES take an argument (`foo <name> { ... }`,
// schema `args: 1`) would carry that argument on Keys in the correct nested
// spelling too, so the packed test has to be `len(Keys) > 1 + arity` rather
// than `> 1` — otherwise the gate would reject the very spelling it is meant to
// accept. Recording the arity here keeps that correct by construction instead of
// leaving an args-bearing block statement outside the guard's scope (#6701
// MINOR-4).
var loginBlockOnlyStatements = map[string]map[string]int{
	"user": {"authentication": 0},
}

// loginPackedConsequence renders the stanza-specific consequence clause of the
// instance-line rejection so the operator is told what the drop actually costs,
// not merely that something was dropped.
func loginPackedConsequence(keyword string) string {
	switch keyword {
	case "user":
		// The consequence is stated as it stands AFTER #6701. A matched
		// non-root account carrying an empty class resolves to the fail-closed
		// `unauthorized` class (cli.ResolveLoginClass decision 3), so the drop
		// now costs the operator the class they wrote, not a promotion. It DID
		// promote before #6701 — an empty class is still pkg/cli's legacy
		// no-RBAC allow-everything shortcut, reached whenever no `system login
		// user` matches — which is why the two ship together and why the
		// warning still names that mode as the older behaviour.
		return "the user compiles with NO login class, so the class the operator wrote is " +
			"silently discarded and the account resolves to the fail-closed `unauthorized` " +
			"class instead of the one named (on a binary before #6701 it instead reached the " +
			"legacy no-RBAC allow-everything mode: allow every command, render secrets in " +
			"cleartext)"
	case "class":
		return "the class compiles with NO permissions and NO allow/deny regexes, so it " +
			"grants nothing and the commit advisory that would flag a dropped deny-commands " +
			"as MORE PERMISSIVE than the source config never fires"
	}
	return "the instance compiles with an EMPTY body"
}

// validateLoginPackedStatementsAST walks the `system login` subtree and reports
// every instance whose body is packed onto the instance line, plus every
// block-only body statement whose block is packed onto the statement line.
//
// It reproduces `namedInstances`' own two-shape branch rather than calling it,
// because the gate needs the number of leading IDENTITY keys and that helper
// discards it:
//
//	len(child.Keys) >= 2  -> the node ITSELF; Keys[0] is the keyword, Keys[1]
//	                         the instance name                     -> identity 2
//	otherwise             -> a `sub` CHILD of a bare `user { }` container,
//	                         whose Keys[0] IS the instance name    -> identity 1
//
// Branching on the shape (rather than sniffing Keys[0] against the keyword)
// keeps it correct for an instance literally NAMED `user` or `class`.
//
// Returns (warnings, nil) when lenient, (nil, error) on the first offender when
// strict.
func validateLoginPackedStatementsAST(tree *ConfigTree, lenient bool) ([]string, error) {
	var f loginFindings
	forEachClusterNodeView(tree, func(view *ConfigTree) {
		collectLoginPackedFindings(view.Children, &f)
	})
	return f.verdict(lenient)
}

// collectLoginPackedFindings records every packed-body offender under one
// already-expanded node view.
func collectLoginPackedFindings(nodes []*Node, f *loginFindings) {
	_ = forEachChild(nodes, "system", func(sys *Node) error {
		return forEachChild(sys.Children, "login", func(login *Node) error {
			for _, keyword := range loginInstanceKeywords {
				for _, container := range login.FindChildren(keyword) {
					if len(container.Keys) >= 2 {
						checkLoginInstancePacked(keyword, container.Keys[1], container, 2, f)
						continue
					}
					for _, sub := range container.Children {
						checkLoginInstancePacked(keyword, sub.Name(), sub, 1, f)
					}
				}
			}
			return nil
		})
	})
}

// checkLoginInstancePacked reports the packed body of ONE login instance:
// first the instance line itself, then any block-only body statement written
// inline. identityKeys is how many leading Keys name the instance.
//
// Every name and body token is rendered through quoteKey, the same round-trip
// renderer Node.KeysString / Format use. The rewrite suggestions are meant to
// be PASTED, and the lexer keeps a quoted string as one token: rendering
// `class "noc ops" deny-commands "request system zeroize";` with a bare
// strings.Join produced `class noc ops { deny-commands request system
// zeroize; }`, which preserves neither token boundary and is a different
// (invalid) configuration. Quoting restores both.
func checkLoginInstancePacked(keyword, name string, inst *Node, identityKeys int, f *loginFindings) {
	qname := quoteKey(name)
	if len(inst.Keys) > identityKeys {
		body := quoteKeys(inst.Keys[identityKeys:])
		f.add(fmt.Sprintf(
			"system login %s %s: body `%s` is written on the instance line, but xpf "+
				"compiles a `%s` body only from a nested block or a `set` statement — every "+
				"statement written there is SILENTLY DROPPED and %s (#6662). Rewrite as "+
				"`%s %s { %s; }` or `set system login %s %s %s`.",
			keyword, qname, body, keyword, loginPackedConsequence(keyword),
			keyword, qname, body, keyword, qname, body))
	}
	blockOnly := loginBlockOnlyStatements[keyword]
	if blockOnly == nil {
		return
	}
	for _, prop := range inst.Children {
		stmt := prop.Name()
		arity, isBlockOnly := blockOnly[stmt]
		if !isBlockOnly {
			continue
		}
		// Keys[0] is the statement; the next `arity` tokens are legitimately
		// part of its key. Anything beyond that is a packed body.
		if len(prop.Keys) <= 1+arity {
			continue
		}
		body := quoteKeys(prop.Keys[1+arity:])
		f.add(fmt.Sprintf(
			"system login %s %s %s: body `%s` is written on the statement line, but xpf "+
				"compiles `%s` only from a nested block or a `set` statement — the key or "+
				"password written there is SILENTLY DROPPED and the account is left with no "+
				"usable authentication method (#6662). Rewrite as `%s { %s; }` or "+
				"`set system login %s %s %s %s`.",
			keyword, qname, stmt, body, stmt, stmt, body, keyword, qname, stmt, body))
	}
}

// quoteKeys renders a run of AST keys as pasteable configuration text, quoting
// each token that would not read back as itself (quoteKey, ast.go).
func quoteKeys(keys []string) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = quoteKey(k)
	}
	return strings.Join(parts, " ")
}

// loginFindings accumulates gate messages across the per-node views, dropping a
// finding already recorded by an earlier view. Insertion order is preserved so
// the strict first-offender is the first in SOURCE order of the node-0 view —
// identical to the pre-#6706 single-view behaviour for every non-cluster
// config, and deterministic (node 0 then node 1) for a cluster one.
type loginFindings struct {
	seen  map[string]bool
	order []string
}

func (f *loginFindings) add(msg string) {
	if f.seen == nil {
		f.seen = make(map[string]bool)
	}
	if f.seen[msg] {
		return
	}
	f.seen[msg] = true
	f.order = append(f.order, msg)
}

// verdict renders the collected findings: strict returns the first as an
// error, lenient returns all as warnings (#1960 no-brick).
func (f *loginFindings) verdict(lenient bool) ([]string, error) {
	if len(f.order) == 0 {
		return nil, nil
	}
	if !lenient {
		return nil, fmt.Errorf("%s", f.order[0])
	}
	return f.order, nil
}

// forEachClusterNodeView calls fn with the candidate tree expanded for each
// chassis-cluster node id, so a gate sees what EVERY node will actually render
// — including a `groups nodeN` body that `apply-groups "${node}"` selects only
// on the peer.
//
// Mirrors collectQinQFindingsForNode / collectVLANMapFindingsForNode: clone,
// expand for the node, read the AST. It never calls CompileConfig* (which
// would re-enter the gate). A view that fails to expand contributes nothing —
// a config defining only `groups node1` + `${node}` does not expand for node 0,
// and the real per-node compile path already rejects that on the affected
// node, while the OTHER view still sees the body hidden in the group.
func forEachClusterNodeView(tree *ConfigTree, fn func(*ConfigTree)) {
	if tree == nil {
		return
	}
	for _, nodeID := range []int{0, 1} {
		clone := tree.Clone()
		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
		if err := clone.ExpandGroupsWithVars(vars); err != nil {
			continue
		}
		fn(clone)
	}
}

// loginBlockOnlyStatementNames returns the flattened `<keyword> <statement>`
// enumeration of loginBlockOnlyStatements in deterministic order. Used by the
// schema-drift guard so a failure names exactly which entry is wrong.
func loginBlockOnlyStatementNames() []string {
	var out []string
	for keyword, stmts := range loginBlockOnlyStatements {
		for stmt := range stmts {
			out = append(out, keyword+" "+stmt)
		}
	}
	sort.Strings(out)
	return out
}

// loginBlockOnlyArity returns the recorded arity for a `<keyword> <statement>`
// entry, and whether it is listed at all. Used by the schema-drift guards so
// they check the SAME arity the gate applies.
func loginBlockOnlyArity(keyword, stmt string) (int, bool) {
	stmts, ok := loginBlockOnlyStatements[keyword]
	if !ok {
		return 0, false
	}
	arity, ok := stmts[stmt]
	return arity, ok
}

// validateLoginClassShadowsBuiltinAST rejects a `system login class <name>`
// whose name is one of the SYSTEM-DEFINED classes.
//
// Found while sweeping the #6701 fail-open for siblings: it is the same defect
// thesis one layer down from the packed drop above — an operator's configured
// restriction silently absent in the PERMISSIVE direction — reached without any
// packing at all.
//
//	system login class super-user { permissions view; }
//	system login user bob { class super-user; }
//
// compiles cleanly, records MappedPermissions=[PermView], and the commit
// advisory even reports "mapped to xpf coarse permissions {view}" — telling the
// operator the narrowing took effect. At runtime it does not: pkg/cli
// resolveClassPerms consults config.LoginClassPermissions FIRST, so `super-user`
// resolves to the BUILT-IN [PermAll] and bob holds every permission including
// destructive maintenance. The custom definition is entirely inert and the only
// operator-visible signal says the opposite.
//
// Built-in-first precedence is itself the SAFE ordering and is deliberately not
// changed here: inverting it would let `class read-only { permissions all; }`
// ESCALATE the built-in, which is strictly worse. The defect is the silence, so
// the fix is to refuse the shadowing definition and name the collision.
//
// Both accepted alternatives are one edit away: pick a distinct class name, or
// assign the built-in directly if the built-in semantics are what was wanted.
//
// Strict at commit / commit-check; warn on the tolerant load / peer-sync path
// (#1960) — leniently loaded the definition stays exactly as inert as it
// already was, now stated.
func validateLoginClassShadowsBuiltinAST(tree *ConfigTree, lenient bool) ([]string, error) {
	var f loginFindings
	forEachClusterNodeView(tree, func(view *ConfigTree) {
		collectLoginClassShadowFindings(view.Children, &f)
	})
	return f.verdict(lenient)
}

// collectLoginClassShadowFindings records every built-in-shadowing class
// definition under one already-expanded node view.
func collectLoginClassShadowFindings(nodes []*Node, f *loginFindings) {
	report := func(name string) {
		if _, builtin := LoginClassPermissions[name]; !builtin {
			return
		}
		f.add(fmt.Sprintf(
			"system login class %s: %q is a SYSTEM-DEFINED login class, and the built-in "+
				"definition always wins at runtime (pkg/cli resolveClassPerms consults the "+
				"built-in table first) — this definition is INERT, so any narrowing it "+
				"expresses is silently not applied while the commit advisory reports that it "+
				"was (#6701). Choose a distinct class name, or reference the built-in %q "+
				"directly from `system login user <name> class %s`.",
			name, name, name, name))
	}

	_ = forEachChild(nodes, "system", func(sys *Node) error {
		return forEachChild(sys.Children, "login", func(login *Node) error {
			for _, container := range login.FindChildren("class") {
				if len(container.Keys) >= 2 {
					report(container.Keys[1])
					continue
				}
				for _, sub := range container.Children {
					report(sub.Name())
				}
			}
			return nil
		})
	})
}

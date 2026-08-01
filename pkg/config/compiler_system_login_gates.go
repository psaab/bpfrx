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
		return "the user compiles with NO login class, which routes the CLI into the " +
			"legacy no-RBAC allow-everything mode (empty class = allow every command and " +
			"render secrets in cleartext)"
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
func validateLoginPackedStatementsAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string

	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	walkErr := forEachChild(nodes, "system", func(sys *Node) error {
		return forEachChild(sys.Children, "login", func(login *Node) error {
			for _, keyword := range loginInstanceKeywords {
				for _, container := range login.FindChildren(keyword) {
					if len(container.Keys) >= 2 {
						if err := checkLoginInstancePacked(
							keyword, container.Keys[1], container, 2, emit); err != nil {
							return err
						}
						continue
					}
					for _, sub := range container.Children {
						if err := checkLoginInstancePacked(
							keyword, sub.Name(), sub, 1, emit); err != nil {
							return err
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

// checkLoginInstancePacked reports the packed body of ONE login instance:
// first the instance line itself, then any block-only body statement written
// inline. identityKeys is how many leading Keys name the instance.
func checkLoginInstancePacked(keyword, name string, inst *Node, identityKeys int, emit func(string) error) error {
	if len(inst.Keys) > identityKeys {
		body := strings.Join(inst.Keys[identityKeys:], " ")
		return emit(fmt.Sprintf(
			"system login %s %s: body %q is written on the instance line, but xpf "+
				"compiles a `%s` body only from a nested block or a `set` statement — every "+
				"statement written there is SILENTLY DROPPED and %s (#6662). Rewrite as "+
				"`%s %s { %s; }` or `set system login %s %s %s`.",
			keyword, name, body, keyword, loginPackedConsequence(keyword),
			keyword, name, body, keyword, name, body))
	}
	blockOnly := loginBlockOnlyStatements[keyword]
	if blockOnly == nil {
		return nil
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
		body := strings.Join(prop.Keys[1+arity:], " ")
		if err := emit(fmt.Sprintf(
			"system login %s %s %s: body %q is written on the statement line, but xpf "+
				"compiles `%s` only from a nested block or a `set` statement — the key or "+
				"password written there is SILENTLY DROPPED and the account is left with no "+
				"usable authentication method (#6662). Rewrite as `%s { %s; }` or "+
				"`set system login %s %s %s %s`.",
			keyword, name, stmt, body, stmt, stmt, body, keyword, name, stmt, body)); err != nil {
			return err
		}
	}
	return nil
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
func validateLoginClassShadowsBuiltinAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string

	emit := func(msg string) error {
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	report := func(name string) error {
		if _, builtin := LoginClassPermissions[name]; !builtin {
			return nil
		}
		return emit(fmt.Sprintf(
			"system login class %s: %q is a SYSTEM-DEFINED login class, and the built-in "+
				"definition always wins at runtime (pkg/cli resolveClassPerms consults the "+
				"built-in table first) — this definition is INERT, so any narrowing it "+
				"expresses is silently not applied while the commit advisory reports that it "+
				"was (#6701). Choose a distinct class name, or reference the built-in %q "+
				"directly from `system login user <name> class %s`.",
			name, name, name, name))
	}

	walkErr := forEachChild(nodes, "system", func(sys *Node) error {
		return forEachChild(sys.Children, "login", func(login *Node) error {
			for _, container := range login.FindChildren("class") {
				if len(container.Keys) >= 2 {
					if err := report(container.Keys[1]); err != nil {
						return err
					}
					continue
				}
				for _, sub := range container.Children {
					if err := report(sub.Name()); err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}

package cmdtree

import (
	"strings"
	"testing"
)

// #9064: `pkg/cmdtree/tree.go` is the declared SSOT for the operational tree, and
// the console RBAC canonicalizer fails CLOSED on anything it cannot resolve.
// Several leaves that take real arguments were declared as BARE leaves, so a
// restricted login class was refused commands the CLI's own `usage:` strings
// document — measured at 11 of 21.
//
// The commands below are taken verbatim from those `usage:` strings. This is a
// COMPLETENESS gate rather than a regression cell for seven declarations:
// #8304 fixed two members of this family and its own test file says "the class
// is wider than both", which is how the remaining nine survived.
func TestDocumentedConsoleCommandsCanonicalize9064(t *testing.T) {
	// Every one of these was REFUSED before this change.
	wasRefused := []string{
		"ping 1.1.1.1 count 5",
		"ping 1.1.1.1 source 10.0.0.1",
		"ping 1.1.1.1 size 1400",
		"traceroute 1.1.1.1 source 10.0.0.1",
		"show system rollback 1",
		"show system rollback compare 1",
		"show configuration groups",
		"show configuration apply-groups",
		"clear dhcp client-identifier interface ge-0/0/0",
		"show security nat source rule-set rs1",
		"show security nat destination rule-set rs1",
	}
	// CONTROLS that already resolved. They are here because a change that made
	// the canonicalizer permissive — returning OK for everything — would
	// satisfy every row above while destroying the gate, and these cannot
	// distinguish it. The refusal rows below are what do that.
	alreadyResolved := []string{
		"show route",
		"ping 1.1.1.1",
		"show configuration security zones",
		"show log messages 50",
		// The report claimed these two were broken. They are not — the
		// DynamicFn admits the trailing word — and asserting them keeps a
		// future "fix" from adding a redundant AcceptsArgs that would mask a
		// real regression in the dynamic path.
		"ping 1.1.1.1 routing-instance vrf1",
		"traceroute 1.1.1.1 routing-instance vrf1",
	}

	for _, cmd := range append(append([]string{}, wasRefused...), alreadyResolved...) {
		t.Run(cmd, func(t *testing.T) {
			_, res := Canonicalize(OperationalTree, strings.Fields(cmd))
			if res != CanonicalOK {
				t.Errorf("%q canonicalizes as %v, so a restricted login class is "+
					"REFUSED a command the CLI's own usage string documents "+
					"(permissions_regex.go accepts only CanonicalOK)", cmd, res)
			}
		})
	}
}

// NARROWNESS, and it is what stops the fix from being "declare AcceptsArgs
// everywhere". The gate must still refuse a command WORD that is not in the
// tree — that refusal is what the console RBAC check is.
//
// It must NOT assert anything about unknown ARGUMENTS. `AcceptsArgs` means
// exactly that trailing words are arguments the canonicalizer does not
// validate; `show configuration firewall anything at all` has canonicalized OK
// since #8304 and that is the shipped design, with argument validation left to
// the dispatcher. Measured on master before this change:
//
//	ping 1.1.1.1 nonsense 5                  -> OK   (already, not this change)
//	show configuration firewall anything      -> OK   (the #8304 semantics)
//
// My first version of this case asserted both should be refused. The first was
// never true, and the second would have required un-declaring the very leaves
// this issue is about. Asserting them would have been asserting a contract the
// tree does not have.
func TestUnknownCommandsAreStillRefused9064(t *testing.T) {
	for _, cmd := range []string{
		"show nonsense",
		"clear nonsense",
		"show system nonsense",
		"show security nat nonsense",
		"show configuration nonsense-stanza",
		"frobnicate",
		"nonsense 1.1.1.1 count 5",
	} {
		t.Run(cmd, func(t *testing.T) {
			if _, res := Canonicalize(OperationalTree, strings.Fields(cmd)); res == CanonicalOK {
				t.Errorf("%q canonicalized OK; the console RBAC gate fails CLOSED on "+
					"what it cannot resolve, and a tree that resolves every command "+
					"word admits everything", cmd)
			}
		})
	}
}

// And the newly-declared leaves must not have widened their PARENTS. Declaring
// `rollback` as arg-accepting must not make `show system <anything>` resolve —
// that would turn one leaf's fix into a hole one level up.
func TestNewlyDeclaredLeavesDidNotWidenTheirParents9064(t *testing.T) {
	for _, cmd := range []string{
		"show system nonsense 1",
		"show security nat source nonsense rs1",
		"clear dhcp nonsense interface ge-0/0/0",
		// NOT `ping` / `traceroute` alone: a bare command node is a valid tree
		// path and resolves OK, which is correct -- whether it is USABLE with no
		// arguments is the dispatcher's question, not the RBAC gate's. My first
		// version listed them and was asserting a contract the tree does not have.
	} {
		t.Run(cmd, func(t *testing.T) {
			if _, res := Canonicalize(OperationalTree, strings.Fields(cmd)); res == CanonicalOK {
				t.Errorf("%q canonicalized OK; a leaf declaring AcceptsArgs must not "+
					"make its PARENT accept unknown children", cmd)
			}
		})
	}
}

package config

// natMatchAddressValues returns EVERY prefix a NAT `match source-address` /
// `match destination-address` leaf carries, across BOTH AST slots (#6693).
//
// THE DEFECT IT REPLACES. Five arms — source-NAT source/destination, dest-NAT
// destination/source, static-NAT source — read the node with an either/or:
//
//	if len(m.Keys) >= 2 {
//	    vals = append(vals, m.Keys[1:]...)
//	} else if len(m.Children) > 0 {
//	    for _, child := range m.Children { vals = append(vals, child.Name()) }
//	}
//
// which is correct for every spelling that puts the whole list in ONE slot —
// a bracket list, a compact tail, a block, or repeated sibling statements — and
// wrong for the one spelling that uses both. A value in the identifier slot
// BESIDE a block:
//
//	match { source-address 10.0.0.0/8 { 192.0.2.0/24; } }
//	  -> Keys=["source-address","10.0.0.0/8"], Children=[["192.0.2.0/24"]]
//
// takes the first branch, so the `else if` is structurally unreachable and
// every prefix past the first is dropped. It commits CLEAN: these leaves are
// untyped (`args: 1, multi: true, children: nil`, no validator) and sit in an
// open-world subtree, so the schema walker has nothing to reject.
//
// This is the #4121 defect — fixed there for `security policies … match` — at
// five NAT sites that were not swept at the time. The four SIBLING arms in the
// same switch (`source-address-name`, `destination-address-name`, `protocol`,
// `application`) already read both slots.
//
// WHY NOT firewallMatchValues, which is what the siblings use. It DROPS empty
// tokens, and here an authored empty is not absence: `match source-address ""`
// must reach the compiled list so validateStaticNATSelectedMatchAddressStrict
// (#7216) can reject a rule that would lower an empty prefix and be dropped
// wholesale by the Rust `parse_nat_prefix`. Measured: switching these five arms
// to firewallMatchValues turned five #7216 subtests from reject to
// commit-clean — a fail-open introduced by the fix for a fail-closed drop.
//
// WHY NOT multiLeafAuthoredValues, the #6673 reader that does keep empties. It
// synthesizes ONE empty value for a node with no value slot at all, to keep
// `multiLeafAuthoredValues(n)[0] == nodeVal(n)` total for a SELECTION leaf.
// These arms have no such scalar invariant, and a bare `source-address;` would
// then compile to [""] — which makes the Rust `source_constrained` flag true
// over a prefix that parses as nothing, so the rule matches NOTHING instead of
// leaving the criterion absent.
//
// So: accumulate both slots, keep empties, synthesize nothing.
//
// It reads every KEY of each child rather than child.Name(), so
// `source-address { 10.0.0.0/8 192.0.2.0/24; }` — two tokens on one statement
// inside a block — yields both. That is the #6714 rule: the same token sequence
// must not read differently depending on which side of the AST it landed on.
func natMatchAddressValues(child *Node) []string {
	if child == nil {
		return nil
	}
	var vals []string
	if len(child.Keys) > 1 {
		vals = append(vals, child.Keys[1:]...)
	}
	for _, vn := range child.Children {
		if vn == nil {
			continue
		}
		vals = append(vals, vn.Keys...)
	}
	return vals
}

package cmdtree

// modifier_split.go — the position-independent split of an operational
// command's trailing words into declared MODIFIER keywords and the operator's
// SELECTOR value (#9065).
//
// THE CLASS THIS EXISTS TO CLOSE. `cmd/cli` dispatched operational commands
// with hand-rolled positional ladders — `if args[1] == "detail"` — which decide
// what a word MEANS from where it sits. A selector is not positional: the tree
// declares a value slot at a node and a set of keyword children beside it, and
// `show interfaces ge-0/0/1 extensive` and `show interfaces extensive` differ
// by which words are keywords, not by length or index. A ladder that branches
// before extracting therefore binds the modifier as the selector (or drops the
// selector entirely), and every ladder has this bug at whichever token it did
// not enumerate — which is why fixing members one at a time re-opens the class
// at the next word. Measured over the tree: 15 nodes declare a value slot
// beside keyword children.
//
// The tree is the authority on which is which. Deriving the split from it,
// rather than from a hand-kept list of modifier spellings per call site, is
// what makes a newly declared child correct at the dispatcher for free instead
// of silently becoming the next member.
//
// PREFIX RESOLUTION IS THE SAME RULE THE REST OF THE TREE USES. A modifier may
// be abbreviated exactly as any other keyword may (`show interfaces ge-0/0/1
// ext`), so this routes through resolveTreeWord rather than an equality test.
// An AMBIGUOUS abbreviation is reported, not silently treated as a selector:
// binding `show security zones det` as a zone named "det" is precisely the
// silent mis-binding this file exists to prevent.

// ModifierSplit is the partition of one node's trailing words.
type ModifierSplit struct {
	// Modifiers are the declared keyword children present, in the CANONICAL
	// spelling (an abbreviation is expanded), in the order typed.
	Modifiers []string
	// Selector is the single operator-supplied value, or "" when absent.
	Selector string
	// Extra holds any further non-keyword words beyond the first. A caller
	// that does not model a second value must refuse rather than drop them —
	// silently discarding an operand is the defect this type reports.
	Extra []string
	// Ambiguous holds words that are a prefix of more than one declared child.
	// They are neither a modifier nor a selector: the operator meant a keyword
	// and did not say which one.
	Ambiguous []string
}

// Has reports whether the canonical modifier m is present.
func (s ModifierSplit) Has(m string) bool {
	for _, got := range s.Modifiers {
		if got == m {
			return true
		}
	}
	return false
}

// SplitModifiersAt partitions args against the declared children of the node at
// path, which is a full operational command path from the root
// (e.g. []string{"show", "interfaces"}).
//
// ok=false means path names no node, which is a programming error at the call
// site rather than operator input — a caller must not fall back to positional
// parsing on it, because that reinstates the bug.
func SplitModifiersAt(path []string, args []string) (ModifierSplit, bool) {
	node, ok := nodeAtPath(path)
	if !ok {
		return ModifierSplit{}, false
	}
	return SplitModifiers(node.Children, args), true
}

// SplitModifiers is SplitModifiersAt against an already-resolved child map.
func SplitModifiers(children map[string]*Node, args []string) ModifierSplit {
	var out ModifierSplit
	for _, w := range args {
		if w == "" {
			continue
		}
		name, _, matches, ok := resolveTreeWord(children, w)
		switch {
		case ok:
			out.Modifiers = append(out.Modifiers, name)
		case len(matches) > 1:
			out.Ambiguous = append(out.Ambiguous, w)
		case out.Selector == "":
			out.Selector = w
		default:
			out.Extra = append(out.Extra, w)
		}
	}
	return out
}

// nodeAtPath walks the operational tree to path, resolving each word with the
// same prefix rule the dispatcher uses.
func nodeAtPath(path []string) (*Node, bool) {
	current := OperationalTree
	var node *Node
	for _, w := range path {
		_, n, _, ok := resolveTreeWord(current, w)
		if !ok || n == nil {
			return nil, false
		}
		node, current = n, n.Children
	}
	if node == nil {
		return nil, false
	}
	return node, true
}

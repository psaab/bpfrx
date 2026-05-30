package config

import (
	"fmt"
	"strings"
)

// SchemaValidate is the #1319 typed-leaf gate that runs at commit-check
// time, BEFORE the existing compiler. It walks the AST against setSchema
// — the SAME tree the live config-mode `set` completer walks — and, for
// every typed leaf (schemaNode.valueType != ValueAny with a validator),
// invokes the validator on the leaf's value token(s).
//
// Why pre-compile? parseBandwidthLimit / parseBurstSizeLimit silently
// return 0 on garbage input, so `set class-of-service schedulers x
// transmit-rate asd` would otherwise compile to zero bps and commit
// silently. SchemaValidate fails the commit with a human-readable error
// before the compiler ever sees the bad string.
//
// The walker is generic: it descends setSchema recursively against the
// AST and is a no-op for any subtree with no typed leaves. Untyped leaves
// (valueType == ValueAny) are not validated — the gate is opt-in per leaf,
// so the compiler keeps full responsibility for everything not yet typed.
// This is the property that lets per-subsystem typing land incrementally
// (#1319 PR 2..N) without touching this file.
//
// SchemaValidate lives in pkg/config (re-homed from pkg/cmdtree in #1319
// PR 1) because it now walks the pkg/config-owned setSchema. cmdtree no
// longer carries a config-mode typed-leaf overlay.

// SchemaValidate walks the AST against setSchema and invokes each typed
// leaf's validator on its value. It returns the FIRST error encountered
// (matching how the existing compiler surfaces commit-check failures).
// cfg may be nil — none of the PR-1 schedulers validators need it, but the
// signature reserves room for future cross-reference validators (e.g.
// "forwarding-class X must exist").
//
// The tree passed in MUST already be apply-groups-expanded (configstore
// expands before calling), so group bodies are inlined before the walk.
func SchemaValidate(tree *ConfigTree, cfg *Config) error {
	if tree == nil {
		return nil
	}
	return walkSchemaChildren(tree.Children, setSchema, nil, cfg)
}

// walkSchemaChildren validates a slice of AST sibling nodes against the
// schema level `parent`. Siblings are processed together so a typed leaf's
// modifier-only sibling (e.g. flat-set `transmit-rate exact` next to
// `transmit-rate 1g`) can be recognized as valid only when a sibling
// supplies the value.
func walkSchemaChildren(nodes []*Node, parent *schemaNode, path []string, cfg *Config) error {
	if parent == nil {
		return nil
	}
	// First, gather "packed leftover" leaves grouped by the container
	// identity they hang off (e.g. two sibling nodes
	// `schedulers be transmit-rate 1g` + `schedulers be transmit-rate exact`
	// both produce a leftover leaf under the same `schedulers be` identity).
	// These leftover leaves must see EACH OTHER as siblings so the typed
	// leaf's cross-sibling split-modifier rule works (Codex r3 minor). We
	// validate each identity group's leftover leaves together, then walk the
	// rest of each node normally with the leftover stripped.
	leftoverGroups := map[string][]*Node{}
	groupSchema := map[string]*schemaNode{}
	groupPath := map[string][]string{}
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		id, descendSchema, idPath, leaf := packedLeftoverLeaf(node, parent, path)
		if leaf != nil {
			leftoverGroups[id] = append(leftoverGroups[id], leaf)
			groupSchema[id] = descendSchema
			groupPath[id] = idPath
		}
	}
	for id, leaves := range leftoverGroups {
		// Validate the group's leftover leaves as mutual siblings. Recurse
		// through walkSchemaChildren (NOT walkSchemaNode per leaf) so a
		// synthesized leaf that is ITSELF a container with further packed
		// leftover (the multi-level packed chain
		// `class-of-service schedulers be transmit-rate asd` as one node)
		// re-enters the leftover-group pass and is not dropped (Codex r4).
		// walkSchemaChildren also threads `leaves` as the sibling set, so the
		// split-modifier cross-sibling rule still sees peers.
		if err := walkSchemaChildren(leaves, groupSchema[id], groupPath[id], cfg); err != nil {
			return err
		}
	}

	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		if err := walkSchemaNode(node, parent, path, cfg, nodes); err != nil {
			return err
		}
	}
	return nil
}

// packedLeftoverLeaf reports whether `node`, resolved against `parent`, is a
// container that packs a leaf into its leftover Keys (the
// `schedulers be transmit-rate asd` single-node shape). It returns a group
// id (the consumed identity path joined), the child schema to validate the
// leaf at, the consumed identity path, and the synthesized leaf node (nil
// if there is no leftover or the node is not such a container).
func packedLeftoverLeaf(node *Node, parent *schemaNode, path []string) (string, *schemaNode, []string, *Node) {
	childSchema := resolveSchemaChild(parent, node.Keys[0])
	if childSchema == nil {
		return "", nil, nil, nil
	}
	// Typed leaves are not containers; their value lives in Keys[1:] and is
	// handled directly by walkSchemaNode.
	if childSchema.isTypedLeaf() {
		return "", nil, nil, nil
	}
	declaredKeyTokens := 1 + childSchema.args
	consumed, descendSchema := consumeNodeKeys(node.Keys, childSchema)
	// Only the fully-supplied-identity shape packs a leftover leaf here; the
	// instance-name-as-nested-child shape is handled by descendInstanceLevels.
	if declaredKeyTokens-consumed > 0 && !childSchema.compoundKey {
		return "", nil, nil, nil
	}
	leftover := node.Keys[consumed:]
	if len(leftover) == 0 {
		return "", nil, nil, nil
	}
	idPath := append(append([]string(nil), path...), node.Keys[:consumed]...)
	leaf := &Node{Keys: leftover, IsLeaf: node.IsLeaf, Children: node.Children}
	return strings.Join(idPath, "\x00"), descendSchema, idPath, leaf
}

// walkSchemaNode matches a single AST node against the current schema
// level (parent), validates it if it resolves to a typed leaf, then
// recurses into its children.
//
//   - node:     the AST node. node.Keys packs flat-set tokens
//     (e.g. ["from-zone","trust","to-zone","untrust"] or
//     ["transmit-rate","1g"]); node.Children holds nested AST.
//   - parent:   the schema level node.Keys[0] is looked up in.
//   - path:     consumed keyword path for error context.
//   - siblings: the AST nodes at this level (for cross-sibling
//     modifier-only recognition).
func walkSchemaNode(node *Node, parent *schemaNode, path []string, cfg *Config, siblings []*Node) error {
	keyword := node.Keys[0]

	// Resolve the schema child for this keyword. Exact match first, then
	// wildcard (instance-name slot). Unknown keywords are not our concern —
	// the gate is opt-in; leave reporting to the compiler.
	childSchema := resolveSchemaChild(parent, keyword)
	if childSchema == nil {
		return nil
	}

	if childSchema.isTypedLeaf() && childSchema.validator != nil {
		// Typed leaf: node.Keys[1:] are the value/modifier tokens. The leaf
		// keyword is the only identity token.
		if err := validateTypedLeaf(node, childSchema, path, siblings, cfg); err != nil {
			return err
		}
		// Validate modifier CHILDREN. The flat-set grouping and hierarchical
		// blocks both nest trailing modifier tokens as children
		// (`transmit-rate 1g { exact; }` → child Keys=["exact"];
		// `transmit-rate 1g exact bogus` → child exact → child bogus). Each
		// modifier child must be a known modifier keyword with NO extra
		// tokens packed in its Keys and NO unexpected descendants.
		leafPath := append(append([]string(nil), path...), keyword)
		for _, c := range node.Children {
			if err := validateModifierChild(c, childSchema, leafPath, cfg); err != nil {
				return err
			}
		}
		return nil
	}

	// Container / untyped leaf: consume this node's identity tokens
	// (keyword + args + compoundKey) and recurse into its children at the
	// resolved child schema level.
	declaredKeyTokens := 1 + childSchema.args
	consumed, descendSchema := consumeNodeKeys(node.Keys, childSchema)
	newPath := append(append([]string(nil), path...), node.Keys[:consumed]...)

	// Dual AST shape: a schema node with args>0 packs the instance name(s)
	// into Keys in flat-set form (`schedulers be` → Keys=["schedulers",
	// "be"]) but presents them as nested AST children in hierarchical form
	// (`schedulers { be { ... } }` → node Keys=["schedulers"], child
	// Keys=["be"]). When fewer key tokens were available than the schema
	// declares, the missing instance-name args are supplied by nested AST
	// children: descend through those name levels (still at the same
	// schema node) before reaching the leaves. compoundKey already
	// advanced descendSchema, so only the plain-args shortfall is handled
	// here.
	missingArgs := declaredKeyTokens - consumed
	if missingArgs > 0 && !childSchema.compoundKey {
		// Peel the missing instance-name level(s) off each child, then group
		// the resulting instance CONTENTS by their fully-resolved identity
		// path and walk each group together. Grouping is what gives sibling
		// nodes under the same instance (e.g.
		// `schedulers { be transmit-rate 1g; be transmit-rate exact; }`)
		// mutual visibility for the split-modifier rule (Codex r3 minor).
		groups := map[string][]*Node{}
		gp := map[string][]string{}
		for _, c := range node.Children {
			collectInstanceContents(c, missingArgs, newPath, groups, gp)
		}
		for id, contents := range groups {
			if err := walkSchemaChildren(contents, childSchema, gp[id], cfg); err != nil {
				return err
			}
		}
		return nil
	}

	// Leftover Keys beyond this container's identity form a packed leaf
	// (the `schedulers be transmit-rate asd` single-node shape). That leaf —
	// and its block children — are validated by walkSchemaChildren's
	// leftover-group pass (which gives peer leftover leaves mutual sibling
	// visibility for the split-modifier rule), so we must NOT also walk
	// node.Children here: those children belong to the synthesized leaf, not
	// to this container. Returning leaves them to the group pass.
	if len(node.Keys[consumed:]) > 0 {
		return nil
	}

	return walkSchemaChildren(node.Children, descendSchema, newPath, cfg)
}

// validateModifierChild validates one AST child of a typed leaf (e.g.
// `exact` under `transmit-rate 1g`). A modifier is presence-only: it must
// be a known child keyword of the leaf, carry NO extra tokens in its Keys
// (`exact bogus` → leftover `bogus` is unknown), and have NO unexpected
// descendants of its own (`exact { bogus; }`). Modifiers themselves carry
// no typed value, so we only assert the keyword is recognized and nothing
// trails it.
func validateModifierChild(node *Node, leafSchema *schemaNode, leafPath []string, cfg *Config) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	mod := node.Keys[0]
	if leafSchema.children == nil {
		return typedLeafErrorf(leafPath, "unknown modifier %q", mod)
	}
	modSchema, ok := leafSchema.children[mod]
	if !ok {
		return typedLeafErrorf(leafPath, "unknown modifier %q", mod)
	}
	// No tokens may trail the modifier keyword in its Keys.
	if len(node.Keys) > 1 {
		return typedLeafErrorf(leafPath, "unknown modifier %q", node.Keys[1])
	}
	// No descendants may hang off a presence-only modifier.
	modPath := append(append([]string(nil), leafPath...), mod)
	for _, c := range node.Children {
		if len(c.Keys) == 0 {
			continue
		}
		// If the modifier schema itself declares children (future nested
		// modifiers), recurse; otherwise any descendant is unknown.
		if modSchema != nil && modSchema.children != nil {
			if err := validateModifierChild(c, modSchema, modPath, cfg); err != nil {
				return err
			}
			continue
		}
		return typedLeafErrorf(modPath, "unknown modifier %q", c.Keys[0])
	}
	return nil
}

// collectInstanceContents peels `remaining` instance-name level(s) off the
// hierarchical AST (where a named container's instance name(s) appear as
// nested AST child nodes rather than packed into the container's Keys) and
// accumulates the instance's CONTENT nodes into per-identity groups so the
// caller can walk each group as a mutual-sibling set.
//
// "Content" is either a leaf synthesized from leftover Keys packed onto the
// instance node — the parser folds `schedulers { be transmit-rate asd; }`
// into one node Keys=["be","transmit-rate","asd"] — or the instance node's
// block children. Grouping by the resolved identity path gives sibling
// nodes under one instance (e.g.
// `schedulers { be transmit-rate 1g; be transmit-rate exact; }`) mutual
// visibility for the typed leaf's split-modifier rule (Codex r3 minor).
func collectInstanceContents(node *Node, remaining int, path []string, groups map[string][]*Node, gp map[string][]string) {
	if node == nil || len(node.Keys) == 0 {
		return
	}
	consume := len(node.Keys)
	if consume > remaining {
		consume = remaining
	}
	newPath := append(append([]string(nil), path...), node.Keys[:consume]...)
	if stillMissing := remaining - consume; stillMissing > 0 {
		// This node supplied only part of the name; keep peeling from its
		// children (a value-less name level continues nesting).
		for _, c := range node.Children {
			collectInstanceContents(c, stillMissing, newPath, groups, gp)
		}
		return
	}
	id := strings.Join(newPath, "\x00")
	gp[id] = newPath
	// Leftover Keys beyond the names form a packed leaf for this instance.
	if leftover := node.Keys[consume:]; len(leftover) > 0 {
		groups[id] = append(groups[id], &Node{Keys: leftover, IsLeaf: node.IsLeaf, Children: node.Children})
		return
	}
	// Otherwise the instance's block children are its content.
	groups[id] = append(groups[id], node.Children...)
}

// resolveSchemaChild returns the schema node for keyword under parent:
// an exact child match, else the wildcard (dynamic instance name slot),
// else nil.
func resolveSchemaChild(parent *schemaNode, keyword string) *schemaNode {
	if parent.children != nil {
		if s, ok := parent.children[keyword]; ok {
			return s
		}
	}
	return parent.wildcard
}

// consumeNodeKeys computes how many leading tokens of keys belong to a
// non-typed node's identity (keyword + args, plus a compoundKey
// sub-token). It returns that count and the possibly-refined child schema
// (compoundKey descends one level). midKeyword sits within the arg span
// and is consumed there, so it needs no separate accounting. This is only
// used for container/untyped nodes; typed leaves treat Keys[1:] as value.
func consumeNodeKeys(keys []string, childSchema *schemaNode) (int, *schemaNode) {
	consumed := 1 + childSchema.args
	if consumed > len(keys) {
		consumed = len(keys)
	}
	// Compound key: the next token is part of this node's key and selects
	// a sub-child (e.g. "family inet6" → consume "inet6", descend into it).
	if childSchema.compoundKey && consumed < len(keys) {
		if sub, ok := childSchema.children[keys[consumed]]; ok {
			consumed++
			return consumed, sub
		}
	}
	return consumed, childSchema
}

// validateTypedLeaf validates the value token(s) of a typed leaf.
//
// Value/modifier tokens come from node.Keys[1:] (flat-set + hierarchical
// `keyword value` both pack the value into Keys[1]) plus, for the
// hierarchical `keyword value { modifier; }` shape, the value is still in
// Keys[1] and the modifier is an AST child (not a value).
//
// Contract (mirrors the schema-feature→AST-match table in the #1319 plan):
//   - standard typed leaf: the FIRST token is the value → run validator on
//     it; any subsequent token must match a child keyword (e.g. `exact`).
//   - multi && children==nil value-tail/range: every value token is
//     validated; a fixed mid-token (`to`) is a separator, so
//     `destination-port 20000 to 20003` validates 20000 and 20003.
//   - modifier-only sibling: a flat-set leaf carrying ONLY a known modifier
//     (e.g. `transmit-rate exact`) is accepted IFF a sibling node supplies
//     a valid value (`transmit-rate 1g`); otherwise it fails. This
//     preserves the pre-#1319 schedulerHasTypedTransmitRate behaviour.
//   - missing value: a typed leaf with no value token fails.
//   - unknown modifier: a non-value token matching no child keyword fails.
func validateTypedLeaf(node *Node, leafSchema *schemaNode, parentPath []string, siblings []*Node, cfg *Config) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)
	values := node.Keys[1:]

	// Range / value-tail leaf: multi with no schema children. Validate
	// every value token; treat a known fixed mid-token (`to`) as a
	// separator.
	if leafSchema.multi && leafSchema.children == nil {
		if len(values) == 0 {
			return typedLeafErrorf(path, "missing value")
		}
		validatedAny := false
		lastWasSeparator := false
		for _, tok := range values {
			if tok == "to" {
				if !validatedAny || lastWasSeparator {
					return typedLeafErrorf(path, "missing value")
				}
				lastWasSeparator = true
				continue
			}
			if err := leafSchema.validator(tok, cfg); err != nil {
				return typedLeafInvalidErrorf(path, tok, err)
			}
			validatedAny = true
			lastWasSeparator = false
		}
		if !validatedAny || lastWasSeparator {
			return typedLeafErrorf(path, "missing value")
		}
		return nil
	}

	if len(values) == 0 {
		return typedLeafErrorf(path, "missing value")
	}

	first := values[0]

	// Modifier-only line: the sole token is a known child keyword (e.g.
	// `transmit-rate exact`). Accept only if a sibling supplies a valid
	// value; else fail. This is the cross-sibling rule from the plan.
	if len(values) == 1 && leafSchema.children != nil {
		if _, isMod := leafSchema.children[first]; isMod {
			if siblingSuppliesTypedValue(siblings, leafName, leafSchema, cfg) {
				return nil
			}
			return typedLeafErrorf(path, "modifier %q requires a value (e.g. a sibling %s <value>)", first, leafName)
		}
	}

	// Standard typed leaf: first token is the value.
	if err := leafSchema.validator(first, cfg); err != nil {
		return typedLeafInvalidErrorf(path, first, err)
	}
	// Remaining tokens must be known child-keyword modifiers (e.g. `exact`).
	for _, tok := range values[1:] {
		if leafSchema.children == nil {
			return typedLeafErrorf(path, "unknown modifier %q", tok)
		}
		if _, ok := leafSchema.children[tok]; !ok {
			return typedLeafErrorf(path, "unknown modifier %q", tok)
		}
	}
	return nil
}

// siblingSuppliesTypedValue reports whether any sibling node with the same
// leaf keyword carries a value token that the leaf's validator accepts.
// Used to allow a flat-set modifier-only line (`transmit-rate exact`) when
// the rate is set on a separate sibling node.
func siblingSuppliesTypedValue(siblings []*Node, leafName string, leafSchema *schemaNode, cfg *Config) bool {
	for _, s := range siblings {
		if s == nil || len(s.Keys) == 0 || s.Keys[0] != leafName {
			continue
		}
		for _, tok := range s.Keys[1:] {
			// Skip known modifier keywords; only a real value counts.
			if leafSchema.children != nil {
				if _, isMod := leafSchema.children[tok]; isMod {
					continue
				}
			}
			if leafSchema.validator(tok, cfg) == nil {
				return true
			}
		}
	}
	return false
}

// typedLeafErrorf builds a commit-check error scoped to the leaf's
// consumed config path, e.g. "class-of-service schedulers be
// transmit-rate: missing value". path already includes the leaf keyword.
func typedLeafErrorf(path []string, format string, args ...interface{}) error {
	return fmt.Errorf("%s: %s", strings.Join(path, " "), fmt.Sprintf(format, args...))
}

// typedLeafInvalidErrorf builds the "invalid value" variant which quotes
// the offending token and the validator's own message.
func typedLeafInvalidErrorf(path []string, tok string, err error) error {
	return fmt.Errorf("%s: invalid value %q: %v", strings.Join(path, " "), tok, err)
}

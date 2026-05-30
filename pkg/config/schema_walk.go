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

	// Container / named-instance node. Consume this node's identity tokens
	// (keyword + args + compoundKey), then validate its BLOCK CHILDREN at the
	// resolved child schema.
	//
	// Compiler-faithful model (verified against compileClassOfService +
	// namedInstances): a named-instance container is compiled by reading its
	// instance node's CHILDREN as leaves. Tokens packed into the instance
	// node's own Keys BEYOND the identity (e.g. the `transmit-rate 1g` in
	// `schedulers { be transmit-rate 1g; }`, or a stray `surplus-sharing` /
	// `extra` token) are NOT compiled as leaves — the per-instance compiler
	// never inspects them — so the gate must NOT validate them either, and
	// crucially must NOT mis-attribute the block children to such a token.
	// We therefore IGNORE leftover Keys here and always walk node.Children at
	// the child schema. (The flat-set `set ... transmit-rate asd` shape lands
	// the typed leaf as a CHILD of `schedulers be`, where it IS compiled and
	// IS validated by the typed-leaf branch above.)
	declaredKeyTokens := 1 + childSchema.args
	consumed, descendSchema := consumeNodeKeys(node.Keys, childSchema)
	newPath := append(append([]string(nil), path...), node.Keys[:consumed]...)

	// Dual AST shape: a schema node with args>0 packs the instance name(s)
	// into Keys in flat-set form (`schedulers be` → Keys=["schedulers",
	// "be"]) but presents them as nested AST children in hierarchical form
	// (`schedulers { be { ... } }` → node Keys=["schedulers"], child
	// Keys=["be"]). When fewer key tokens were available than the schema
	// declares, the missing instance-name args are supplied by nested AST
	// children: peel those name levels (the compiler's namedInstances does
	// the same) and validate each instance's children at the child schema.
	missingArgs := declaredKeyTokens - consumed
	if missingArgs > 0 && !childSchema.compoundKey {
		for _, c := range node.Children {
			if err := walkInstanceChildren(c, childSchema, missingArgs, newPath, cfg); err != nil {
				return err
			}
		}
		return nil
	}

	return walkSchemaChildren(node.Children, descendSchema, newPath, cfg)
}

// walkInstanceChildren peels the missing instance-name level(s) off a
// hierarchical named-instance node and validates the instance's block
// children at the container schema. It mirrors the compiler's namedInstances
// + per-instance child walk: the instance name comes from the node's leading
// Keys; the leaves are the node's CHILDREN. Any extra tokens packed into the
// instance node's Keys beyond the name are ignored (the compiler does not
// compile them; see walkSchemaNode's container comment, Codex r7).
func walkInstanceChildren(node *Node, containerSchema *schemaNode, remaining int, path []string, cfg *Config) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	consume := len(node.Keys)
	if consume > remaining {
		consume = remaining
	}
	newPath := append(append([]string(nil), path...), node.Keys[:consume]...)
	if stillMissing := remaining - consume; stillMissing > 0 {
		// This node supplied only part of the name; keep peeling.
		for _, c := range node.Children {
			if err := walkInstanceChildren(c, containerSchema, stillMissing, newPath, cfg); err != nil {
				return err
			}
		}
		return nil
	}
	// Name fully consumed. The instance's leaves are its block children;
	// any leftover Keys past the name are not compiled and are ignored.
	return walkSchemaChildren(node.Children, containerSchema, newPath, cfg)
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
		// Non-empty separator-only tails like ["to"] or ["to", "to"] reach
		// here with no validated value tokens.
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

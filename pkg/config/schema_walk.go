package config

import (
	"fmt"
	"strconv"
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
//
// cfg is ALWAYS nil in production: both call sites
// (configstore.compileTree / compileTreeLenient via
// schemaValidateExpandedTree, pkg/configstore/store.go) run the gate
// BEFORE the compiler, so no *Config exists yet. Validators must not
// depend on it. Cross-reference validation is TREE-based instead: the
// walk pre-collects referenceable definitions from the candidate tree
// itself into schemaRefs (collectSchemaRefs below) and hands them to
// treeValidator leaves — atomicity-correct, because a definition and its
// reference added in the same commit validate against the same tree.
// Removing the cfg parameter outright is a possible follow-up once we
// are confident no post-compile consumer will ever appear; it is kept
// for now because the LeafValidator signature is mirrored in cmdtree.
//
// The tree passed in MUST already be apply-groups-expanded (configstore
// expands before calling), so group bodies are inlined before the walk.
func SchemaValidate(tree *ConfigTree, cfg *Config) error {
	if tree == nil {
		return nil
	}
	vc := &walkContext{cfg: cfg, refs: collectSchemaRefs(tree)}
	return walkSchemaChildren(tree.Children, setSchema, nil, vc)
}

// walkContext carries the per-walk validation inputs: the (always-nil in
// production) cfg pointer for the legacy LeafValidator signature, and
// the tree-derived cross-reference sets for treeValidator leaves.
type walkContext struct {
	cfg  *Config
	refs *schemaRefs
}

// config / collectedRefs are nil-receiver-safe accessors: the white-box
// walker tests drive walkSchemaNode with a nil context, matching the
// production reality that cfg is nil anyway.
func (vc *walkContext) config() *Config {
	if vc == nil {
		return nil
	}
	return vc.cfg
}

func (vc *walkContext) collectedRefs() *schemaRefs {
	if vc == nil {
		return nil
	}
	return vc.refs
}

// treeLeafValidator is the TREE-based counterpart of LeafValidator for
// cross-reference leaves: instead of the (always-nil in production)
// *Config it receives the definitions collected from the candidate tree
// by collectSchemaRefs, so a definition and its reference added in the
// same commit validate atomically.
type treeLeafValidator func(raw string, refs *schemaRefs) error

// checkValue returns the per-token validation function for a typed
// leaf: the scalar validator when set, else the tree-based
// cross-reference validator bound to the walk's collected refs. A typed
// leaf sets exactly one of the two (walkSchemaNode gates on either).
func (n *schemaNode) checkValue(vc *walkContext) func(string) error {
	if n.validator != nil {
		return func(tok string) error { return n.validator(tok, vc.config()) }
	}
	if n.treeValidator != nil {
		return func(tok string) error { return n.treeValidator(tok, vc.collectedRefs()) }
	}
	return func(string) error { return nil }
}

// schemaRefs holds the referenceable definitions collected from the
// candidate tree before the walk (#1319 PR 3). Extend with new sets as
// more cross-reference validators land.
type schemaRefs struct {
	// forwardingClasses are the names defined via `class-of-service
	// forwarding-classes queue <n> <name>` anywhere in the tree —
	// including group bodies, applied or not. Collecting from group
	// definitions errs permissive: after apply-groups expansion the
	// applied bodies are inlined at top level anyway, and a reference
	// satisfied only by an UN-applied group must not be rejected (the
	// compiler ignores both the definition and any reference inside
	// that group, and node0/node1-variable configs legitimately keep
	// peer-node definitions un-applied locally).
	forwardingClasses map[string]struct{}
}

// collectSchemaRefs walks the tree for cross-referenceable definitions.
// The forwarding-class collection mirrors compileClassOfService exactly
// (compiler_class_of_service.go:82-89): `queue` leaves under a
// `forwarding-classes` node, Keys = ["queue", <int>, <name>]; entries
// whose queue number does not parse are skipped, as the compiler skips
// them.
func collectSchemaRefs(tree *ConfigTree) *schemaRefs {
	refs := &schemaRefs{forwardingClasses: map[string]struct{}{}}
	if tree == nil {
		return refs
	}
	var collectCoS func(node *Node)
	collectCoS = func(node *Node) {
		fcNode := node.FindChild("forwarding-classes")
		if fcNode == nil {
			return
		}
		for _, queueNode := range fcNode.FindChildren("queue") {
			if len(queueNode.Keys) < 3 {
				continue
			}
			if _, err := strconv.Atoi(queueNode.Keys[1]); err != nil {
				continue
			}
			refs.forwardingClasses[queueNode.Keys[2]] = struct{}{}
		}
	}
	for _, top := range tree.Children {
		if top == nil || len(top.Keys) == 0 {
			continue
		}
		switch top.Name() {
		case "class-of-service":
			collectCoS(top)
		case "groups":
			for _, group := range top.Children {
				if group == nil {
					continue
				}
				if cos := group.FindChild("class-of-service"); cos != nil {
					collectCoS(cos)
				}
			}
		}
	}
	return refs
}

// walkSchemaChildren validates a slice of AST sibling nodes against the
// schema level `parent`. Siblings are processed together so a typed leaf's
// modifier-only sibling (e.g. flat-set `transmit-rate exact` next to
// `transmit-rate 1g`) can be recognized as valid only when a sibling
// supplies the value.
func walkSchemaChildren(nodes []*Node, parent *schemaNode, path []string, vc *walkContext) error {
	if parent == nil {
		return nil
	}
	for _, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		if err := walkSchemaNode(node, parent, path, vc, nodes); err != nil {
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
func walkSchemaNode(node *Node, parent *schemaNode, path []string, vc *walkContext, siblings []*Node) error {
	keyword := node.Keys[0]

	// Resolve the schema child for this keyword. Exact match first, then
	// wildcard (instance-name slot). Unknown keywords are not our concern —
	// the gate is opt-in; leave reporting to the compiler.
	childSchema := resolveSchemaChild(parent, keyword)
	if childSchema == nil {
		return nil
	}

	if childSchema.isTypedLeaf() && (childSchema.validator != nil || childSchema.treeValidator != nil) {
		// Multi value-tail leaf (`multi && children == nil`): values can
		// live in the packed Keys (`name-server 1.1.1.1`, bracketed
		// lists, `destination-port 20000 to 20003`) AND/OR one-per-child
		// in the hierarchical block-list shape (`name-server { 1.1.1.1;
		// 8.8.8.8; }`, `virtual-address { a; b; }`) — the compilers read
		// both (compiler_system.go name-server, compiler_interfaces.go
		// virtual-address). Children here are VALUES, not modifiers, so
		// this path replaces both validateTypedLeaf and the modifier
		// loop below.
		if childSchema.multi && childSchema.children == nil {
			return validateMultiValueLeaf(node, childSchema, path, vc)
		}
		// Typed leaf: node.Keys[1:] are the value/modifier tokens. The leaf
		// keyword is the only identity token.
		if err := validateTypedLeaf(node, childSchema, path, siblings, vc); err != nil {
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
			if err := validateModifierChild(c, childSchema, leafPath, vc); err != nil {
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

	// Typed KEY slot (#1319 PR 3): a named-instance container with a
	// keyValidator validates the identity arg token(s) packed into this
	// node's Keys (e.g. the 10.0.1.10/24 in `address 10.0.1.10/24 {
	// primary; }`). Only the declared arg span is validated — a compound
	// sub-token is a keyword, not a value, and tokens past the identity
	// are ignored per the compiler-faithful contract.
	if childSchema.keyValidator != nil {
		argEnd := declaredKeyTokens
		if argEnd > len(node.Keys) {
			argEnd = len(node.Keys)
		}
		keyPath := append(append([]string(nil), path...), keyword)
		for _, tok := range node.Keys[1:argEnd] {
			if err := childSchema.keyValidator(tok, vc.config()); err != nil {
				return typedLeafInvalidErrorf(keyPath, tok, err)
			}
		}
	}

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
			if err := walkInstanceChildren(c, childSchema, missingArgs, newPath, vc); err != nil {
				return err
			}
		}
		return nil
	}

	return walkSchemaChildren(node.Children, descendSchema, newPath, vc)
}

// walkInstanceChildren peels the missing instance-name level(s) off a
// hierarchical named-instance node and validates the instance's block
// children at the container schema. It mirrors the compiler's namedInstances
// + per-instance child walk: the instance name comes from the node's leading
// Keys; the leaves are the node's CHILDREN. Any extra tokens packed into the
// instance node's Keys beyond the name are ignored (the compiler does not
// compile them; see walkSchemaNode's container comment, Codex r7).
func walkInstanceChildren(node *Node, containerSchema *schemaNode, remaining int, path []string, vc *walkContext) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	consume := len(node.Keys)
	if consume > remaining {
		consume = remaining
	}
	// Typed KEY slot (#1319 PR 3): the peeled tokens ARE the instance
	// name the compiler reads (namedInstances handles this nested shape
	// too), so a key-typed container validates them here as well.
	if containerSchema.keyValidator != nil {
		for _, tok := range node.Keys[:consume] {
			if err := containerSchema.keyValidator(tok, vc.config()); err != nil {
				return typedLeafInvalidErrorf(path, tok, err)
			}
		}
	}
	newPath := append(append([]string(nil), path...), node.Keys[:consume]...)
	if stillMissing := remaining - consume; stillMissing > 0 {
		// This node supplied only part of the name; keep peeling.
		for _, c := range node.Children {
			if err := walkInstanceChildren(c, containerSchema, stillMissing, newPath, vc); err != nil {
				return err
			}
		}
		return nil
	}
	// Name fully consumed. The instance's leaves are its block children;
	// any leftover Keys past the name are not compiled and are ignored.
	return walkSchemaChildren(node.Children, containerSchema, newPath, vc)
}

// validateModifierChild validates one AST child of a typed leaf (e.g.
// `exact` under `transmit-rate 1g`). A modifier is presence-only: it must
// be a known child keyword of the leaf, carry NO extra tokens in its Keys
// (`exact bogus` → leftover `bogus` is unknown), and have NO unexpected
// descendants of its own (`exact { bogus; }`). Modifiers themselves carry
// no typed value, so we only assert the keyword is recognized and nothing
// trails it.
func validateModifierChild(node *Node, leafSchema *schemaNode, leafPath []string, vc *walkContext) error {
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
			if err := validateModifierChild(c, modSchema, modPath, vc); err != nil {
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
//   - multi && children==nil value-tail/range leaves are NOT handled
//     here — walkSchemaNode dispatches them to validateMultiValueLeaf,
//     which also accepts the hierarchical block-list spelling.
//   - modifier-only sibling: a flat-set leaf carrying ONLY a known modifier
//     (e.g. `transmit-rate exact`) is accepted IFF a sibling node supplies
//     a valid value (`transmit-rate 1g`); otherwise it fails. This
//     preserves the pre-#1319 schedulerHasTypedTransmitRate behaviour.
//   - missing value: a typed leaf with no value token fails.
//   - unknown modifier: a non-value token matching no child keyword fails.
func validateTypedLeaf(node *Node, leafSchema *schemaNode, parentPath []string, siblings []*Node, vc *walkContext) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)
	values := node.Keys[1:]
	check := leafSchema.checkValue(vc)

	if len(values) == 0 {
		return typedLeafErrorf(path, "missing value")
	}

	first := values[0]

	// Modifier-only line: the sole token is a known child keyword (e.g.
	// `transmit-rate exact`). Accept only if a sibling supplies a valid
	// value; else fail. This is the cross-sibling rule from the plan.
	if len(values) == 1 && leafSchema.children != nil {
		if _, isMod := leafSchema.children[first]; isMod {
			if siblingSuppliesTypedValue(siblings, leafName, leafSchema, vc) {
				return nil
			}
			return typedLeafErrorf(path, "modifier %q requires a value (e.g. a sibling %s <value>)", first, leafName)
		}
	}

	// Standard typed leaf: first token is the value.
	if err := check(first); err != nil {
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

// validateMultiValueLeaf validates a `multi && children == nil` typed
// leaf (the value-tail/range row of the walker contract). Value tokens
// come from BOTH spellings the compilers read:
//
//   - packed Keys (`name-server 1.1.1.1`, bracketed `[ a b ]` lists,
//     and ranges where the fixed mid-token `to` is a separator:
//     `destination-port 20000 to 20003`), and
//   - the hierarchical block-list shape, one child node per value
//     (`name-server { 1.1.1.1; 8.8.8.8; }`). Only each child's FIRST
//     token is validated — the compilers read exactly that
//     (compiler_system.go name-server reads ns.Keys[0],
//     compiler_interfaces.go virtual-address reads child.Name()) and
//     the compiler-faithful contract forbids validating tokens the
//     compiler ignores.
//
// A leaf with no value in either position fails, as do dangling /
// separator-only tails (["to"], ["20000","to"]).
func validateMultiValueLeaf(node *Node, leafSchema *schemaNode, parentPath []string, vc *walkContext) error {
	leafName := node.Keys[0]
	path := append(append([]string(nil), parentPath...), leafName)
	check := leafSchema.checkValue(vc)

	validatedAny := false
	lastWasSeparator := false
	for _, tok := range node.Keys[1:] {
		if tok == "to" {
			if !validatedAny || lastWasSeparator {
				return typedLeafErrorf(path, "missing value")
			}
			lastWasSeparator = true
			continue
		}
		if err := check(tok); err != nil {
			return typedLeafInvalidErrorf(path, tok, err)
		}
		validatedAny = true
		lastWasSeparator = false
	}
	if lastWasSeparator {
		return typedLeafErrorf(path, "missing value")
	}

	// Block-list children: one value per child, first token only.
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		if err := check(c.Keys[0]); err != nil {
			return typedLeafInvalidErrorf(path, c.Keys[0], err)
		}
		validatedAny = true
	}

	if !validatedAny {
		return typedLeafErrorf(path, "missing value")
	}
	return nil
}

// siblingSuppliesTypedValue reports whether any sibling node with the same
// leaf keyword carries a value token that the leaf's validator accepts.
// Used to allow a flat-set modifier-only line (`transmit-rate exact`) when
// the rate is set on a separate sibling node.
func siblingSuppliesTypedValue(siblings []*Node, leafName string, leafSchema *schemaNode, vc *walkContext) bool {
	check := leafSchema.checkValue(vc)
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
			if check(tok) == nil {
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

package config

// schema.go owns the config-mode `set`/`delete`/`show`/`edit` grammar
// definition — the single source of truth (SSOT) for the Junos
// configuration hierarchy. It defines the `schemaNode` container type and
// the `setSchema` literal that drives four things off one tree: structural
// completion, flat-set token grouping (SetPath, ast_edit.go), value-slot
// `?` completion (schema_complete.go), and commit-check typed-leaf
// validation (SchemaValidate, schema_walk.go). See docs/config-schema.md.
//
// This file was split out of ast.go in #1699: the AST node types and tree
// navigation (the parser's data model) stay in ast.go; the grammar SSOT
// lives here alongside the rest of the schema_* family (schema_walk.go,
// schema_validators.go, value_type.go); the procedural completion / path
// resolution helpers live in schema_complete.go.
//
// #1891 domain split: schema.go keeps the schemaNode type, the setSchema
// root composition, and the groups-wildcard init() wiring; the per-domain
// subtrees live in sibling aspect files in this package — NOT a
// subpackage, because setSchema is unexported and consumed in-package by
// schema_complete.go / schema_walk.go (two-SSOT doctrine, #1319):
//
//	schema_security.go    security, applications
//	schema_interfaces.go  interfaces (+ tunnel/wireguard constructors)
//	schema_routing.go     routing-options, policy-options, protocols,
//	                      forwarding-options, bridge-domains,
//	                      routing-instances
//	schema_system.go      system, services, snmp, event-options
//	schema_chassis.go     chassis
//	schema_cos.go         class-of-service, firewall

// schemaNode defines a container keyword in the Junos config hierarchy.
// It tells SetPath how to group flat path tokens into the correct tree structure.
type schemaNode struct {
	args         int                    // extra tokens consumed as part of this node's key
	children     map[string]*schemaNode // known container children
	wildcard     *schemaNode            // matches any keyword not in children (for dynamic names)
	multi        bool                   // true = multiple leaf values allowed (e.g. source-address); false = replace on set
	valueHint    ValueHint              // hint for dynamic value completion (when args > 0)
	desc         string                 // description shown in completion help
	placeholder  string                 // Junos-style placeholder (e.g., "<interface-name>")
	midKeyword   string                 // fixed keyword in the middle of args (e.g., "to-zone")
	midKeywordAt int                    // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
	compoundKey  bool                   // children form compound key (e.g., "family inet6" → Keys=["family","inet6"])

	// Typed-leaf metadata (#1319). The zero value (valueType==ValueAny,
	// validator==nil) is the legacy behaviour: any string accepted, no
	// schema-time validation, no value-slot examples in `?` completion.
	// Setting valueType to a non-ValueAny value opts this leaf in to both
	// the completion path (CompleteSetPathWithValues surfaces valueDesc +
	// valueExamples + the placeholder) and the validation path
	// (SchemaValidate invokes validator at commit-check time). Because the
	// completion path and the validation path read the SAME node, the two
	// cannot drift — that is the central design property of Option A.
	//
	// IMPORTANT: adding these fields is additive and does not affect
	// SetPath grouping, which keys only on args/children/compoundKey/multi
	// (ast_edit.go). A schemaNode MUST NOT gain a children map purely to
	// carry typed-leaf metadata: SetPath's replace-vs-container decision
	// keys on children==nil (ast_edit.go:196), so flipping a leaf to a
	// container is a grouping regression. Type the value via these fields,
	// not via new children.
	valueType     ValueType     // non-ValueAny marks a typed value slot
	valueDesc     string        // one-line value-slot description for `?` help
	valueExamples []string      // illustrative values surfaced in `?` help
	validator     LeafValidator // commit-check validator for the value slot

	// treeValidator is the TREE-based cross-reference alternative to
	// validator (#1319 PR 3): it validates the value against
	// definitions collected from the candidate tree itself
	// (collectSchemaRefs → schemaRefs), because SchemaValidate's cfg is
	// always nil in production — validation runs BEFORE compile. A
	// typed leaf sets EITHER validator OR treeValidator, never both.
	treeValidator treeLeafValidator

	// Typed KEY slot (#1319 PR 3). A named-instance CONTAINER (args > 0
	// with a children map, e.g. `family inet address <cidr> { primary; }`)
	// carries its value in the IDENTITY token, not in a leaf value slot —
	// the walker consumes identity tokens without validation by default
	// (the compiler-faithful contract from PR 2). Setting keyValidator
	// opts the identity arg token(s) in to commit-check validation, and
	// keyValueType/keyValueDesc/keyValueExamples surface in `?` completion
	// for the empty key slot. The regular valueType/validator fields MUST
	// stay unset on such a node: setting valueType would flip the walker
	// into the typed-LEAF branch, which treats children as modifiers and
	// would mis-validate the container's real block children. Not
	// supported on midKeyword nodes (no current need).
	keyValueType     ValueType     // non-ValueAny marks a typed identity-arg slot
	keyValueDesc     string        // one-line key-slot description for `?` help
	keyValueExamples []string      // illustrative key values surfaced in `?` help
	keyValidator     LeafValidator // commit-check validator for identity arg tokens
}

// isTypedLeaf reports whether the node carries typed-value metadata
// (a non-default valueType), i.e. it expects exactly one typed value at
// its first non-modifier slot.
func (n *schemaNode) isTypedLeaf() bool {
	return n != nil && n.valueType != ValueAny
}

// setSchema defines the Junos configuration tree structure.
// Keywords present in the schema at a given depth are treated as containers.
// Keywords NOT in the schema become leaf nodes (all remaining tokens form the leaf's Keys).
var setSchema = &schemaNode{children: map[string]*schemaNode{
	"groups":             {desc: "Configuration groups", wildcard: &schemaNode{desc: "Group name", placeholder: "<group-name>"}}, // wildcard children set in init()
	"apply-groups":       {desc: "Groups from which to inherit configuration data", args: 1, multi: true, placeholder: "<group-name>", children: nil},
	"security":           schemaSecurity,
	"interfaces":         schemaInterfaces,
	"applications":       schemaApplications,
	"routing-options":    schemaRoutingOptions,
	"snmp":               schemaSNMP,
	"policy-options":     schemaPolicyOptions,
	"protocols":          schemaProtocols,
	"event-options":      schemaEventOptions,
	"chassis":            schemaChassis,
	"class-of-service":   schemaClassOfService,
	"firewall":           schemaFirewall,
	"system":             schemaSystem,
	"services":           schemaServices,
	"forwarding-options": schemaForwardingOptions,
	"bridge-domains":     schemaBridgeDomains,
	"routing-instances":  schemaRoutingInstances,
}}

func init() {
	// Wire groups wildcard to mirror top-level schema children.
	// This allows "set groups <name> security ..." etc. to parse correctly.
	groupWild := setSchema.children["groups"].wildcard
	groupWild.children = make(map[string]*schemaNode)
	for k, v := range setSchema.children {
		if k == "groups" || k == "apply-groups" {
			continue
		}
		groupWild.children[k] = v
	}
}

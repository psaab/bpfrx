package config

// ValueType classifies the value a typed-leaf node accepts. #1319.
//
// The zero value, ValueAny, is the legacy behaviour: any string is accepted
// and no schema-time validation runs. Specifying a non-zero ValueType opts
// the leaf in to:
//   - `?` completion surfacing ValueDesc + ValueExamples for the value slot;
//   - SchemaValidate invoking the leaf's Validator at commit check, so
//     garbage like `transmit-rate asd` fails loud at commit time instead of
//     silently zeroing out the rate inside the compiler.
//
// ValueType lives in pkg/config (not pkg/cmdtree) so the config-grammar
// schema (setSchema, the live config-mode `set` completion + validation
// tree) can carry typed-leaf metadata directly. pkg/cmdtree already imports
// pkg/config, so the type cannot live in cmdtree without an import cycle;
// cmdtree re-exports it via `type ValueType = config.ValueType` aliases for
// its operational-tree leaves. See #1319 plan §5 ("Type ownership").
//
// Add new types here only when we're prepared to wire validators for every
// leaf that adopts them — IP/CIDR/MAC/duration are deliberately deferred
// (see issue #1319) until their subsystem PRs land.
type ValueType int

const (
	// ValueAny is the legacy default: any string accepted, no validation.
	ValueAny ValueType = iota
	// ValueRate is a Junos bandwidth value (bits/sec) with k/m/g suffix.
	// Examples: "100k", "10m", "1g". Accepts plain integers.
	ValueRate
	// ValueByteSize is a byte-count value with k/m/g suffix.
	// Examples: "16k", "1m", "256m".
	ValueByteSize
	// ValueByteSizeOrPercent is a scheduler buffer size: byte-count with
	// k/m/g suffix, or percent with an explicit % suffix.
	ValueByteSizeOrPercent
	// ValuePercent is a percent value in the range [0, 100] (no suffix).
	ValuePercent
	// ValueInteger is a bare integer. Range is enforced by the leaf's
	// Validator (callers use ValidateInteger(min,max) to bound it).
	ValueInteger
	// ValueIdentifier is a bare Junos identifier (no spaces, no quotes).
	ValueIdentifier
	// ValueEnumOf is one of a fixed set of names. The allowed set lives
	// in the leaf's Validator closure (ValidateEnum).
	ValueEnumOf
	// ValueBool is "true" or "false".
	ValueBool
)

// Placeholder returns the angle-bracket placeholder name shown in `?`
// completion for an unfilled value slot of this type.
func (v ValueType) Placeholder() string {
	switch v {
	case ValueRate:
		return "<rate>"
	case ValueByteSize:
		return "<bytes>"
	case ValueByteSizeOrPercent:
		return "<bytes|percent>"
	case ValuePercent:
		return "<percent>"
	case ValueInteger:
		return "<integer>"
	case ValueIdentifier:
		return "<name>"
	case ValueEnumOf:
		return "<value>"
	case ValueBool:
		return "<true|false>"
	}
	return ""
}

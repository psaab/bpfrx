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
	// ValueIPAddress is an IP address without a prefix length. The
	// accepted family (v4, v6, or either) is enforced by the leaf's
	// validator (ValidateIPAddress / ValidateIPv4Address). #1319 PR 3.
	ValueIPAddress
	// ValueCIDR is an IP address WITH a prefix length (e.g.
	// 10.0.1.10/24, 2001:db8::1/64). The accepted family is enforced by
	// the leaf's validator (ValidateIPv4CIDR / ValidateIPv6CIDR).
	ValueCIDR
	// ValueCryptHash is a crypt(3) modular password hash (e.g.
	// $6$salt$checksum) or an explicit lock sentinel (*, !, !!). The
	// leaf's validator (ValidateCryptHash) rejects plaintext at commit
	// check so an operator cannot paste cleartext into an
	// encrypted-password directive. #1944.
	ValueCryptHash
	// ValuePCIAddr is a PCI bus address (DDDD:BB:DD.F, e.g.
	// 0000:09:00.0), the #1956 device-map primary identity key. Validated
	// by ValidatePCIAddr.
	ValuePCIAddr
	// ValueMAC is a MAC address (xx:xx:xx:xx:xx:xx), the #1956 device-map
	// permanent-MAC fallback identity key. Validated by ValidateMAC.
	ValueMAC
	// ValueDHGroup is an IKE/IPsec Diffie-Hellman group as either a bare
	// positive integer ("14") or the Junos "group<N>" spelling
	// ("group14"). Both spellings compile; validated by ValidateDHGroup.
	ValueDHGroup
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
	case ValueIPAddress:
		return "<address>"
	case ValueCIDR:
		return "<address/prefix-length>"
	case ValueCryptHash:
		return "<crypt-hash>"
	case ValuePCIAddr:
		return "<pci-address>"
	case ValueMAC:
		return "<mac-address>"
	case ValueDHGroup:
		return "<dh-group>"
	}
	return ""
}

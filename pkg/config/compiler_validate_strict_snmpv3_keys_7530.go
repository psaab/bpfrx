package config

import (
	"fmt"
	"sort"
)

// compiler_validate_strict_snmpv3_keys_7530.go — #7530.
//
// An SNMPv3 user configured with an auth or privacy PROTOCOL but without the
// corresponding key material committed clean and then served at a LOWER
// security level than configured.
//
// WHY IT DEGRADES SILENTLY. pkg/snmp/v3.go derives the per-user floor from KEY
// PRESENCE, not from configured intent:
//
//	if user.authKey != nil && msgFlags&msgFlagAuth == 0 { drop }
//	if user.privKey != nil && msgFlags&msgFlagPriv == 0 { drop }
//
// and authKey is derived only when the password is non-empty. So a user naming
// `authentication-sha256` with no `authentication-password` has authKey == nil,
// the floor does not apply, and a noAuthNoPriv request naming that user is
// answered -- in plaintext, unauthenticated. Naming `privacy-aes128` without a
// privacy-password degrades authPriv to authNoPriv the same way: the response
// is not encrypted.
//
// That floor is CORRECT as written -- it is the #4897 bypass gate and must stay
// keyed on what the agent can actually verify. The defect is upstream: the
// configuration should never have produced a user whose stated protocol has no
// material behind it. Enforce the configured INTENT at commit rather than
// degrading at serve time.
//
// Reject-only: nothing that compiled before compiles differently. A bug here is
// a loud false rejection caught by the positive controls, never a silently
// weaker agent.
//
// A user with auth and no privacy is LEGITIMATE (authNoPriv), so the gate fires
// on a named protocol missing its own material, never on an absent protocol.
func validateSNMPv3UserKeyMaterialStrict(cfg *Config) error {
	if cfg == nil || cfg.System.SNMP == nil {
		return nil
	}
	// Sorted for a deterministic first-error message; the user map's iteration
	// order is otherwise random, and a gate whose message changes between runs
	// on one config is one nobody can write a test against.
	names := make([]string, 0, len(cfg.System.SNMP.V3Users))
	for name := range cfg.System.SNMP.V3Users {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		u := cfg.System.SNMP.V3Users[name]
		if u == nil {
			continue
		}
		if u.AuthProtocol != "" && string(u.AuthPassword) == "" {
			return fmt.Errorf("snmp v3 usm local-engine user %q names authentication "+
				"protocol %q but carries no authentication-password. The agent derives "+
				"its per-user minimum security level from the DERIVED KEY, so a user with "+
				"no key material has no floor: a noAuthNoPriv request naming %q is "+
				"answered unauthenticated and in plaintext, which is exactly the level "+
				"the configuration was written to prevent. Add "+
				"`authentication-password`, or remove the protocol to configure a "+
				"genuinely noAuthNoPriv user (#7530)",
				name, u.AuthProtocol, name)
		}
		// #9155 Hole B: privacy without authentication. USM has no privacy-only
		// level -- RFC 3414 defines noAuthNoPriv, authNoPriv and authPriv, and
		// there is no noAuthPriv -- and key derivation for BOTH keys is gated on
		// the AUTH hash function, so this user derives no privacy key either.
		// The arm below cannot catch it: a privacy-password IS present, so
		// `PrivPassword == ""` is false. The result is an authPriv-looking
		// configuration served with an unencrypted scopedPDU.
		if u.PrivProtocol != "" && u.AuthProtocol == "" {
			return fmt.Errorf("snmp v3 usm local-engine user %q names privacy protocol %q "+
				"with no authentication protocol. USM has no privacy-only security level "+
				"(RFC 3414 defines noAuthNoPriv, authNoPriv and authPriv -- there is no "+
				"noAuthPriv), and this agent derives the privacy key with the AUTHENTICATION "+
				"hash, so %q gets NO privacy key and its scopedPDU is answered UNENCRYPTED "+
				"while the configuration reads authPriv. Add an `authentication-*` protocol "+
				"and password, or remove the privacy protocol (#9155)",
				name, u.PrivProtocol, name)
		}
		if u.PrivProtocol != "" && string(u.PrivPassword) == "" {
			return fmt.Errorf("snmp v3 usm local-engine user %q names privacy protocol %q "+
				"but carries no privacy-password. With no privacy key the agent applies no "+
				"privacy floor, so an authNoPriv request naming %q is answered with an "+
				"UNENCRYPTED scopedPDU while the configuration says authPriv. Add "+
				"`privacy-password`, or remove the protocol to configure a genuinely "+
				"authNoPriv user (#7530)",
				name, u.PrivProtocol, name)
		}
	}
	return nil
}

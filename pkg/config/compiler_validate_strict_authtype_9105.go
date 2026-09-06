package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// #9105: AN `authentication-key` WITH NO `authentication-type` IS NOT A
// PLAINTEXT PREFERENCE, and until this gate it was treated as one.
//
// At the pkg/frr render sites an ABSENT type and a CHOSEN plaintext type are
// the same state — both render `area-password clear` / `ip rip authentication
// mode text`, with the operator's key in cleartext in every PDU. `simple`
// taking that path is CORRECT; the empty string taking it is a silent
// downgrade, and no care at the render site could separate them because the
// information was destroyed before the renderer ran.
//
// The downgrade is quiet in the worst way: authentication stays ON, adjacencies
// still come up and still authenticate, and `show configuration` echoes back
// whatever the operator wrote. A dropped-authentication defect is noisy —
// adjacencies fail. This one succeeds.
//
// SO THE FIX IS SPLIT, exactly as auth_type.go's own doctrine states for the
// unrecognized case: "The commit gate stops every NEW instance; the warning at
// the render site tells the operator about the existing one."
//
//   - HERE, strict: refuse a key with no type, so the operator states their
//     intent. `authentication-type simple` remains available and is accepted —
//     this gate asks for a decision, it does not forbid plaintext.
//   - pkg/frr, always: warn when rendering plaintext for an absent type, which
//     covers a config already persisted or arriving over HA sync.
//
// LENIENT WARNS RATHER THAN REJECTS (#1960). A config an older binary accepted
// must still boot; refusing it here would turn a silent downgrade into a
// failure to load, on the path whose whole purpose is that a persisted config
// still comes up.
func validateAuthTypePresenceStrict(cfg *Config, lenient bool) ([]string, error) {
	var warnings []string
	report := func(scope string) error {
		msg := fmt.Sprintf("%s: `authentication-key` is configured with no "+
			"`authentication-type`, which renders the key in PLAINTEXT on the wire in every "+
			"PDU. An absent type is not a plaintext choice: set `authentication-type md5` to "+
			"authenticate with a digest, or `authentication-type simple` to state plaintext "+
			"deliberately (accepted: %s) (#9105)",
			scope, strings.Join(AuthTypeSpellings(), ", "))
		if lenient {
			slog.Warn("config: authentication-key with no authentication-type renders PLAINTEXT",
				"scope", scope, "issue", "#9105")
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	if r := cfg.Protocols.RIP; r != nil && r.AuthKey.Reveal() != "" && AuthTypeAbsent(r.AuthType) {
		if err := report("protocols rip"); err != nil {
			return warnings, err
		}
	}
	if i := cfg.Protocols.ISIS; i != nil {
		if i.AuthKey.Reveal() != "" && AuthTypeAbsent(i.AuthType) {
			if err := report("protocols isis"); err != nil {
				return warnings, err
			}
		}
		for _, iface := range i.Interfaces {
			if iface == nil || iface.AuthKey.Reveal() == "" || !AuthTypeAbsent(iface.AuthType) {
				continue
			}
			if err := report("protocols isis interface " + iface.Name); err != nil {
				return warnings, err
			}
		}
	}
	return warnings, nil
}

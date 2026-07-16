package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestReservedApplicationNameMatchesUnknownSentinel is a cross-package drift
// canary for the #5821 reservation. pkg/config reserves an application /
// application-set name equal to config.ReservedApplicationName out of the user
// namespace at commit, precisely so that a real catalog application can never
// alias the AppID "no known application" sentinel that ResolveSessionName
// returns and SessionMatches filters on (appid.Unknown, this package).
//
// pkg/config cannot import pkg/appid (appid imports config — an import cycle),
// so the reserved literal is duplicated in config.ReservedApplicationName rather
// than referencing appid.Unknown. This canary asserts the two stay equal: if a
// future edit changes appid.Unknown without updating the reservation (or vice
// versa), the reservation would stop protecting the sentinel it guards and this
// test goes RED.
func TestReservedApplicationNameMatchesUnknownSentinel(t *testing.T) {
	if config.ReservedApplicationName != Unknown {
		t.Fatalf("config.ReservedApplicationName = %q but appid.Unknown = %q — the "+
			"#5821 reservation has drifted away from the sentinel it protects; keep "+
			"them equal (or wire a shared source)",
			config.ReservedApplicationName, Unknown)
	}
}

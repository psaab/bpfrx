package config

import (
	"strings"
	"testing"
)

// compiler_warn_checkip_redaction_6545_test.go: the commit-time malformed
// checkip-url warning must not echo the operator's credential (#6545 review,
// security MINOR — same leak class as the runtime one in pkg/ddns).
//
// validateSurfaceADDNSWarnings interpolated p.CheckIPURL RAW while the sibling
// url-template warning three lines above it already went through RedactURL. A
// commit warning is printed to the operator's terminal AND logged, so a
// checkip-url carrying an API key in its query put that key in both.

// checkIPWarnCredential is planted where an operator's key goes.
const checkIPWarnCredential = "COMMITWARN-CHECKIP-KEY-MUST-NOT-LOG"

// TestCheckIPURLWarningRedactsCredential is the fail-on-revert gate: restore the
// raw p.CheckIPURL and this fails by assertion naming the leaked sentinel.
func TestCheckIPURLWarningRedactsCredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"key in query", "ftp://checkip.example/?apikey=" + checkIPWarnCredential},
		{"key in userinfo", "ftp://user:" + checkIPWarnCredential + "@checkip.example/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set system services dynamic-dns provider bad backend dyndns2",
				"set system services dynamic-dns provider bad server dyn.example",
				// Quoted: the set-command lexer treats a bare '?' as the help
				// token and '@' as punctuation, exactly as an operator must
				// quote a credentialed URL at the CLI.
				`set system services dynamic-dns provider bad checkip-url "` + tc.url + `"`,
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			joined := strings.Join(validateSurfaceADDNSWarnings(cfg), "\n")

			// Not vacuous: the warning must have fired at all.
			if !strings.Contains(joined, `provider "bad" checkip-url`) {
				t.Fatalf("no malformed-checkip-url warning was emitted for %q; got:\n%s\n"+
					"the redaction assertion below would be vacuous", tc.url, joined)
			}
			if strings.Contains(joined, checkIPWarnCredential) {
				t.Fatalf("the commit-time checkip-url warning echoed the credential in "+
					"cleartext:\n%s\nit must contain %q nowhere — the warning is shown to the "+
					"operator and written to the log. Run p.CheckIPURL through RedactURL, as the "+
					"url-template warning beside it already does.", joined, checkIPWarnCredential)
			}
		})
	}
}

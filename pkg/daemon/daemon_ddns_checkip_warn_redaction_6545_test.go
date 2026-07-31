package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// daemon_ddns_checkip_warn_redaction_6545_test.go: the checkip probe warning
// #6545 added must not write the provider's credential to the journal (#6545
// review, security MINOR).
//
// The sibling file's tests prove the warning FIRES and is deduped, but they use
// credential-free malformed URLs ("ftp://checkip.example/"), and
// recordingSlogHandler records only slog.Record.Message — not the attrs. The
// leak lives in the attrs: slog.Warn(..., "err", cerr), where cerr used to be
// "ddns checkip: url \"ftp://checkip.example/?apikey=SECRET\" must be http(s)".
// So this file renders the WHOLE record (message + attrs) the way a real handler
// does and asserts on the bytes an operator would actually see in journald.
//
// It also asserts the second half Codex called out: the same string is the
// checkIPProbeWarned dedup map KEY, so a leaked credential would sit in daemon
// memory for the process lifetime even with logging turned down.

// checkIPWarnSentinel is planted where an operator's API key goes. Distinct from
// any host/scheme below so a hit is unambiguous.
const checkIPWarnSentinel = "CHECKIP-APIKEY-MUST-NOT-REACH-JOURNALD"

// captureRenderedWarnings installs a real slog TEXT handler over a buffer, so
// attributes are rendered exactly as a production handler renders them, and
// returns the buffer.
func captureRenderedWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestCheckIPProbeWarnRedactsCredential is the fail-on-revert gate. Restore the
// raw URL in pkg/ddns validateCheckIPURL and this fails by assertion, printing
// the journal line that carries the key.
func TestCheckIPProbeWarnRedactsCredential(t *testing.T) {
	// Each case is a malformed checkip-url with the credential in the position
	// an operator would put it, exercising a different validator branch.
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"bad scheme, key in query", "ftp://checkip.example/?apikey=" + checkIPWarnSentinel},
		{"no host, key in query", "http://?apikey=" + checkIPWarnSentinel},
		{"unparseable, key in query", "http://[::1/?apikey=" + checkIPWarnSentinel},
		{"bad scheme, key in userinfo", "ftp://user:" + checkIPWarnSentinel + "@checkip.example/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureRenderedWarnings(t)
			d := newCheckIPObserverDaemon(t)
			obs := d.surfaceAObserver(&config.Config{})
			scope := checkIPScope(&config.DDNSProvider{
				Name: "prov", Backend: "duckdns", CheckIPURL: tc.url,
			})

			if _, ok := obs(context.Background(), scope); ok {
				t.Fatalf("a malformed checkip-url must not yield an observation")
			}

			out := buf.String()
			// Not vacuous: the warning must actually have fired, or "no
			// sentinel in the output" would pass for the wrong reason.
			if !strings.Contains(out, "checkip probe failed") {
				t.Fatalf("the checkip probe warning did not fire; captured log:\n%s\n"+
					"the redaction assertion below would be vacuous", out)
			}
			if strings.Contains(out, checkIPWarnSentinel) {
				t.Fatalf("the checkip probe warning wrote the provider credential to the log "+
					"in cleartext:\n%s\nit must contain %q nowhere — checkip-url query/userinfo "+
					"carries the endpoint API key and this line goes to journald (and to any "+
					"configured remote syslog). Redact the URL in the pkg/ddns error that feeds "+
					"the \"err\" attribute.", out, checkIPWarnSentinel)
			}

			// The SAME string is retained as the dedup map key, so a leak here
			// outlives the log line. Walk the map and assert directly.
			var leaked []string
			d.surfaceA.checkIPProbeWarned.Range(func(k, _ any) bool {
				if s, isStr := k.(string); isStr && strings.Contains(s, checkIPWarnSentinel) {
					leaked = append(leaked, s)
				}
				return true
			})
			if len(leaked) > 0 {
				t.Fatalf("the checkIPProbeWarned dedup map retains the provider credential as a "+
					"KEY for the lifetime of the process: %q\nthe key is built from the probe "+
					"error text, so the pkg/ddns error must be credential-free at the source",
					leaked)
			}
		})
	}
}

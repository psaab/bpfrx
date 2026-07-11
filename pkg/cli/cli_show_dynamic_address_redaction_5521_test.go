// RED-on-revert test for #5521 (third surface from the #5528 review): the
// on-box interactive `show security dynamic-address` renderer
// (CLI.showDynamicAddress, cli_show_security_objects.go) must route each feed's
// URL through config.RedactURL. Dynamic-address feeds routinely carry per-tenant
// bearer tokens in the URL, so printing it raw discloses the credential into the
// console operator's terminal scrollback / support bundles — the same class as
// the primary gRPC/REST bug already fixed in this PR.
//
// Reverting cli_show_security_objects.go back to `fmt.Printf("    URL: %s\n",
// fs.URL)` makes this test go RED: the raw userinfo + query tokens reappear.
package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func newCLIFeedURLStore(t *testing.T, feedURL string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(`set security dynamic-address feed-server tenant-feed url "` + feedURL + `"`); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return store
}

// TestShowDynamicAddressCLIRedactsFeedURLCredentials pins the on-box CLI render.
func TestShowDynamicAddressCLIRedactsFeedURLCredentials(t *testing.T) {
	const (
		userInfoToken = "s3cr3t-token"
		queryToken    = "sup3r-secret"
	)
	feedURL := "https://user:" + userInfoToken + "@feeds.example.com/blocklist?apikey=" + queryToken

	store := newCLIFeedURLStore(t, feedURL)
	c := &CLI{store: store}

	out := captureStdout(t, func() {
		if err := c.showDynamicAddress(); err != nil {
			t.Fatalf("showDynamicAddress(): %v", err)
		}
	})

	if strings.Contains(out, userInfoToken) {
		t.Errorf("basic-auth userinfo token %q leaked into on-box CLI output:\n%s", userInfoToken, out)
	}
	if strings.Contains(out, queryToken) {
		t.Errorf("query-string credential %q leaked into on-box CLI output:\n%s", queryToken, out)
	}
	// The non-credential structure (host) must still be shown so the console
	// operator can identify the feed.
	if !strings.Contains(out, "feeds.example.com") {
		t.Errorf("redacted URL dropped the host; operator can no longer identify the feed:\n%s", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Errorf("expected redaction sentinel <redacted> in on-box CLI output:\n%s", out)
	}
	if !strings.Contains(out, "Feed Server: tenant-feed") {
		t.Errorf("feed-server name label missing from output:\n%s", out)
	}
}

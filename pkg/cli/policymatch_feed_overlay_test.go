package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// newFeedPolicyCLI builds a committed store with an address-book name
// ("bad-actors") referenced by an untrust->trust deny policy. Its STATIC
// content (198.51.100.0/24) deliberately EXCLUDES the IP the test queries
// (203.0.113.7); only the live feed overlay carries the 203.0.113.0/24 prefix
// that makes the query match. This mirrors policymatch's
// TestFeedOverlayResolvesFeedBackedName but exercises the on-box CLI surfaces
// (showMatchPolicies / testPolicy) and isolates the overlay contribution: a
// match on 203.0.113.7 can ONLY come from the feed prefixes the overlay adds.
func newFeedPolicyCLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address bad-actors 198.51.100.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone untrust to-zone trust {
            policy block-feed {
                match { source-address bad-actors; destination-address any; application any; }
                then { deny; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store}
}

// TestPolicyMatchAppliesFeedOverlay proves the local CLI policy simulators
// (#3105) now resolve a feed-backed address-name through the live feed overlay,
// so they agree with the REST/gRPC simulators and the AF_XDP dataplane. An
// in-feed source matches the deny rule when the overlay is supplied; with no
// overlay (the pre-#3105 behavior, or a CLI spawned outside the daemon) the
// feed-backed name resolves to nothing and no policy matches.
//
// FAIL-ON-REVERT: dropping `FeedOverlay: c.feedOverlay()` from either
// showMatchPolicies or testPolicy makes the "with overlay" assertions go RED —
// the in-feed source no longer matches block-feed and the output reverts to
// "No matching policy" / "Default ...".
func TestPolicyMatchAppliesFeedOverlay(t *testing.T) {
	c := newFeedPolicyCLI(t)
	c.feedOverlayFn = func() map[string][]string {
		return map[string][]string{"bad-actors": {"203.0.113.0/24"}}
	}
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}

	// An in-feed source IP must now match the feed-backed deny rule.
	inFeed := []string{"from-zone", "untrust", "to-zone", "trust", "source-ip", "203.0.113.7"}

	out := captureStdout(t, func() {
		if err := c.showMatchPolicies(cfg, inFeed); err != nil {
			t.Fatalf("showMatchPolicies error = %v", err)
		}
	})
	if !strings.Contains(out, "block-feed") {
		t.Fatalf("show match-policies with overlay: want block-feed match, got:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := c.testPolicy(inFeed); err != nil {
			t.Fatalf("testPolicy error = %v", err)
		}
	})
	if !strings.Contains(out, "block-feed") {
		t.Fatalf("test policy with overlay: want block-feed match, got:\n%s", out)
	}

	// Without an overlay provider the feed-backed name resolves to nothing, so
	// the rule does not match — exactly the pre-#3105 behavior. nil provider
	// must not panic.
	c.feedOverlayFn = nil

	out = captureStdout(t, func() {
		if err := c.showMatchPolicies(cfg, inFeed); err != nil {
			t.Fatalf("showMatchPolicies (no overlay) error = %v", err)
		}
	})
	if strings.Contains(out, "block-feed") {
		t.Fatalf("show match-policies without overlay: feed-backed name should not match, got:\n%s", out)
	}
	if !strings.Contains(out, "No matching policy") {
		t.Fatalf("show match-policies without overlay: want no-match, got:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := c.testPolicy(inFeed); err != nil {
			t.Fatalf("testPolicy (no overlay) error = %v", err)
		}
	})
	if strings.Contains(out, "block-feed") {
		t.Fatalf("test policy without overlay: feed-backed name should not match, got:\n%s", out)
	}
}

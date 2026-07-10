package config

import (
	"strings"
	"testing"
)

// buildTree5183 compiles a set-command list into a ConfigTree using
// ParseSetCommand + SetPath (never NewParser, which merges newlines into one
// node — see docs/config-schema.md).
func buildTree5183(t *testing.T, setCommands []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestFeedServerMalformedURLRejected is the #5183 RED-on-revert proof.
//
// A non-empty but MALFORMED feed-server base url clears the emptiness gate but
// is not constructible as the request feeds.Manager.readFeed issues
// (http.NewRequestWithContext), so the feed registers no content and any
// address-name / deny policy bound to it enforces an empty (match-nothing) set
// — a policy fail-open. Strict commit must reject it; the tolerant load /
// peer-sync path downgrades to a warning (#1960). Reverting the malformed-url
// gate turns the strict sub-tests RED (the garbage url compiles clean).
func TestFeedServerMalformedURLRejected(t *testing.T) {
	// Each case is a full feed-server + a binding so the whole dynamic-address
	// subtree is exercised the way a real config would present it.
	malformed := map[string]string{
		"percent escape (issue repro)": "http://%",
		"missing scheme":               "feeds.example.com/list.txt",
		"scheme only, no host":         "https://",
	}

	for label, badURL := range malformed {
		t.Run("commit rejects "+label, func(t *testing.T) {
			tree := buildTree5183(t, []string{
				"set security dynamic-address feed-server threat url " + badURL,
				"set security dynamic-address address-name bad profile feed-name threat",
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig should reject malformed feed-server url %q", badURL)
			}
			if !strings.Contains(err.Error(), "threat") {
				t.Fatalf("error should name the feed-server, got: %v", err)
			}
			if !strings.Contains(err.Error(), "malformed") {
				t.Fatalf("error should explain the url is malformed, got: %v", err)
			}
		})
	}

	// A malformed hostname (resolveBaseURL prepends https://) is equally
	// unconstructible and must reject on the same path.
	t.Run("commit rejects malformed hostname", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat hostname bad%host",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("CompileConfig should reject a feed-server whose hostname yields a malformed https:// url")
		}
	})

	// Tolerant load / peer-sync must NOT brick — it downgrades to a warning so
	// an already-persisted config still boots (the runtime is fail-closed
	// match-none for the dead feed).
	t.Run("tolerant load downgrades to warning", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat url http://%",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient should NOT reject a malformed feed url (warn, not brick): %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "malformed") && strings.Contains(w, "threat") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("tolerant load should surface a malformed-feed-url warning, got warnings: %v", cfg.Warnings)
		}
	})

	// Regression guard: a well-formed url must still compile clean.
	t.Run("commit accepts a valid url", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name threat path /list.txt",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("valid feed-server url must compile, got: %v", err)
		}
	})
}

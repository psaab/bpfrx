package config

import (
	"strings"
	"testing"
)

// buildTree3300 compiles a set-command list into a ConfigTree for the
// #3300 dynamic-address feed cross-reference tests. Uses ParseSetCommand
// + SetPath (never NewParser, which merges newlines into one node).
func buildTree3300(t *testing.T, setCommands []string) *ConfigTree {
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

// TestValidateDynamicAddressFeedReferences covers #3300: a
// `security dynamic-address address-name <addr> profile feed-name <feed>`
// binding whose feed-name resolves to no declared feed must be rejected at
// commit (strict). Before the fix the typo compiled clean and armed a
// silent match-none address book (a feed-backed deny policy then denied
// nothing). Valid references and the tolerant-load downgrade still work.
func TestValidateDynamicAddressFeedReferences(t *testing.T) {
	// The exact reproduction from the issue: a feed-server declaring feed
	// "malware", an address-name binding with the typo "malwrae".
	bogusBinding := []string{
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name bad-actors profile feed-name malwrae",
	}

	t.Run("commit rejects typo'd feed-name", func(t *testing.T) {
		tree := buildTree3300(t, bogusBinding)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig should reject address-name referencing undefined feed %q", "malwrae")
		}
		if !strings.Contains(err.Error(), "malwrae") {
			t.Fatalf("error should name the undefined feed-name, got: %v", err)
		}
		if !strings.Contains(err.Error(), "bad-actors") {
			t.Fatalf("error should name the offending address-name, got: %v", err)
		}
	})

	t.Run("commit accepts feed entry reference", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("correctly-referenced feed-entry should compile, got: %v", err)
		}
	})

	t.Run("commit accepts single-feed reference by feed-name", func(t *testing.T) {
		// Single-feed server (no per-feed entries): the feed is keyed by
		// its FeedName. A binding may reference that name.
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name solo",
			"set security dynamic-address address-name bad-actors profile feed-name solo",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("single-feed-name reference should compile, got: %v", err)
		}
	})

	t.Run("commit accepts reference to server name when no feed-name set", func(t *testing.T) {
		// A feed-server with neither per-feed entries nor an explicit
		// feed-name is keyed by the server name (feeds.Manager fallback).
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address address-name bad-actors profile feed-name threat",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("server-name fallback reference should compile, got: %v", err)
		}
	})

	t.Run("lenient load downgrades typo to warning", func(t *testing.T) {
		tree := buildTree3300(t, bogusBinding)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile should not fail on undefined feed-name, got: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "malwrae") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient compile should record a warning naming the bad feed, warnings=%v", cfg.Warnings)
		}
	})
}

// TestValidateDynamicAddressFeedServerEndpoint covers the #3300 residual: a
// feed-server with neither url nor hostname is SKIPPED by feeds.Manager.Apply
// (resolveBaseURL == "") and registers no feeds, so an address-name bound to
// it resolves to a match-nothing book. Such a server must be rejected at
// commit (strict); a server with a url or a hostname is accepted; the
// tolerant load path downgrades to a warning.
func TestValidateDynamicAddressFeedServerEndpoint(t *testing.T) {
	t.Run("commit rejects feed-server with no url or hostname", func(t *testing.T) {
		// A feed-server that declares a feed-name but no endpoint: it
		// registers nothing at runtime, so the bound address-name is a
		// silent match-none — the same #3300 fail-open at the server root.
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig should reject feed-server with no url/hostname")
		}
		if !strings.Contains(err.Error(), "threat") {
			t.Fatalf("error should name the endpoint-less feed-server, got: %v", err)
		}
	})

	t.Run("commit accepts feed-server with url", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("feed-server with url should compile, got: %v", err)
		}
	})

	t.Run("commit accepts feed-server with hostname only", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat hostname feeds.example.com",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("feed-server with hostname should compile, got: %v", err)
		}
	})

	t.Run("lenient load downgrades endpoint-less server to warning", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile should not fail on endpoint-less server, got: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "threat") && strings.Contains(w, "feed-server") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient compile should record a feed-server endpoint warning, warnings=%v", cfg.Warnings)
		}
	})
}

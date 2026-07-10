package config

import (
	"strings"
	"testing"
)

// dynamic_address_feed_dup_name_4913_test.go: #4913 — feeds.Manager keys its
// worker map + enforcement snapshot by the effective feed name, so two
// feed-servers declaring the SAME effective name orphan a refresh loop
// (goroutine leak) and back enforcement with a nondeterministic provider. The
// strict compile gate must reject a globally-duplicate feed name at commit /
// commit-check and downgrade to a warning on the tolerant load / peer-sync
// path. Reverting the validateDynamicAddressFeedNameUniquenessStrict wiring
// makes the "commit rejects" subtests accept the duplicate — RED.

func buildTree4913(t *testing.T, setCommands []string) *ConfigTree {
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

func TestValidateDynamicAddressFeedNameUniqueness(t *testing.T) {
	// Two feed-servers each declare a per-feed entry named "malware" — the
	// duplicate would overwrite m.feeds["malware"] and orphan one refresh loop.
	t.Run("commit rejects nested-entry name collision across servers", func(t *testing.T) {
		tree := buildTree4913(t, []string{
			"set security dynamic-address feed-server aaa url https://a.example/list.txt",
			"set security dynamic-address feed-server aaa feed-name malware path /m1.txt",
			"set security dynamic-address feed-server bbb url https://b.example/list.txt",
			"set security dynamic-address feed-server bbb feed-name malware path /m2.txt",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject a feed name declared by two feed-servers")
		}
		if !strings.Contains(err.Error(), "malware") {
			t.Fatalf("error should name the duplicated feed, got: %v", err)
		}
		if !strings.Contains(err.Error(), "aaa") || !strings.Contains(err.Error(), "bbb") {
			t.Fatalf("error should name both declaring servers, got: %v", err)
		}
	})

	// The subtle case (#4913 "nested-entry vs single-feed-fallback collision"):
	// a feed-server with neither feed-name nor entries keys on its SERVER name,
	// which collides with another server's per-feed entry of the same name.
	t.Run("commit rejects server-name-fallback vs nested-entry collision", func(t *testing.T) {
		tree := buildTree4913(t, []string{
			"set security dynamic-address feed-server malware url https://a.example/list.txt",
			"set security dynamic-address feed-server threat url https://b.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /m.txt",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("CompileConfig should reject a server-name key colliding with another server's feed entry")
		}
	})

	// A single-feed FeedName colliding with another server's server-name key.
	t.Run("commit rejects single-feed-name vs server-name collision", func(t *testing.T) {
		tree := buildTree4913(t, []string{
			"set security dynamic-address feed-server alpha url https://a.example/list.txt",
			"set security dynamic-address feed-server alpha feed-name shared",
			"set security dynamic-address feed-server shared url https://b.example/list.txt",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("CompileConfig should reject a single-feed FeedName colliding with a server-name key")
		}
	})

	// No false positives: distinct feed names across servers compile clean.
	t.Run("commit accepts distinct feed names", func(t *testing.T) {
		tree := buildTree4913(t, []string{
			"set security dynamic-address feed-server aaa url https://a.example/list.txt",
			"set security dynamic-address feed-server aaa feed-name malware path /m1.txt",
			"set security dynamic-address feed-server bbb url https://b.example/list.txt",
			"set security dynamic-address feed-server bbb feed-name spyware path /m2.txt",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("distinct feed names should compile, got: %v", err)
		}
	})

	// Two entries with the same name WITHIN one server are still a collision
	// (same worker-map key). Flat-set merges duplicate `feed-name malware`
	// nodes into one entry, so this shape is only reachable via a hierarchical
	// parse / direct struct — validate the gate directly on a built *Config.
	t.Run("validator rejects duplicate entry names within one server", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.DynamicAddress.FeedServers = map[string]*FeedServer{
			"aaa": {
				Name: "aaa",
				URL:  "https://a.example/list.txt",
				FeedEntries: []FeedEntry{
					{Name: "malware", Path: "/m1.txt"},
					{Name: "malware", Path: "/m2.txt"},
				},
			},
		}
		if err := validateDynamicAddressFeedNameUniquenessStrict(cfg); err == nil {
			t.Fatal("validator should reject two same-named entries within one feed-server")
		}
	})

	// Tolerant load / peer-sync: a persisted duplicate must not brick the load
	// — it downgrades to a warning (the runtime de-dups deterministically).
	t.Run("lenient load downgrades duplicate to warning", func(t *testing.T) {
		tree := buildTree4913(t, []string{
			"set security dynamic-address feed-server aaa url https://a.example/list.txt",
			"set security dynamic-address feed-server aaa feed-name malware path /m1.txt",
			"set security dynamic-address feed-server bbb url https://b.example/list.txt",
			"set security dynamic-address feed-server bbb feed-name malware path /m2.txt",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile should not fail on a duplicate feed name, got: %v", err)
		}
		var found bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "feed name") && strings.Contains(w, "malware") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient compile should record a duplicate-feed-name warning, warnings=%v", cfg.Warnings)
		}
	})
}

package snmp

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestSelectTrapCommunity_Deterministic is the fail-on-revert guard for #2989.
// With more than one community configured, the trap community MUST be selected
// deterministically (lexicographically-first), not by ranging the Go map and
// breaking on a random first entry. Reverting selectTrapCommunity to the
// map-range-break form makes this flaky/failing: repeated selection over a
// multi-entry map would not be guaranteed to return the same name, and would
// not return the sorted-first name.
func TestSelectTrapCommunity_Deterministic(t *testing.T) {
	cfg := &config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"zulu":   {Name: "zulu", Authorization: "read-write"},
			"alpha":  {Name: "alpha", Authorization: "read-only"},
			"mike":   {Name: "mike", Authorization: "read-only"},
			"bravo":  {Name: "bravo", Authorization: "read-only"},
			"oscar":  {Name: "oscar", Authorization: "read-only"},
			"delta":  {Name: "delta", Authorization: "read-only"},
			"golf":   {Name: "golf", Authorization: "read-only"},
			"hotel":  {Name: "hotel", Authorization: "read-only"},
			"india":  {Name: "india", Authorization: "read-only"},
			"juliet": {Name: "juliet", Authorization: "read-only"},
		},
	}

	// The lexicographically-first name is the documented stable selection.
	const want = "alpha"

	// Run many times: Go map iteration order is randomized per-range, so a
	// map-range-break implementation would, with very high probability, return
	// a non-"alpha" name within these iterations. A deterministic sorted pick
	// returns "alpha" every time.
	for i := 0; i < 200; i++ {
		if got := selectTrapCommunity(cfg); got != want {
			t.Fatalf("selectTrapCommunity() = %q, want deterministic %q (iteration %d)", got, want, i)
		}
	}

	// No communities configured falls back to the v2c default.
	if got := selectTrapCommunity(&config.SNMPConfig{}); got != "public" {
		t.Fatalf("selectTrapCommunity(empty) = %q, want %q", got, "public")
	}
	if got := selectTrapCommunity(nil); got != "public" {
		t.Fatalf("selectTrapCommunity(nil) = %q, want %q", got, "public")
	}
}

// TestSelectTrapCommunity_UsedByLinkTrap proves the deterministic community
// actually reaches the wire-built packet, not just the helper. It builds a trap
// and asserts the on-wire community octet-string equals the sorted-first
// community.
func TestSelectTrapCommunity_UsedByLinkTrap(t *testing.T) {
	cfg := &config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"zulu":  {Name: "zulu"},
			"alpha": {Name: "alpha"},
			"mike":  {Name: "mike"},
		},
	}
	agent := &Agent{startTime: time.Now()}
	community := selectTrapCommunity(cfg)
	if community != "alpha" {
		t.Fatalf("community = %q, want alpha", community)
	}
	pkt := agent.buildLinkTrap(community, true, 1, "ge-0-0-0")
	if !containsBytes(pkt, []byte("alpha")) {
		t.Fatalf("built trap packet does not carry community %q", community)
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

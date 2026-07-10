package main

import "testing"

// TestIsLocalOnlyCommand pins #4909: the offline WireGuard key generator is a
// local-only verb that main() must dispatch BEFORE the GetStatus reachability
// probe, so it works when xpfd is down (recovery/bootstrap). Daemon-backed
// verbs must NOT be classified local-only (they still require a reachable
// daemon and its status probe).
//
// RED on revert: drop isLocalOnlyCommand / the pre-probe dispatch gate and the
// generate-private-key case is no longer treated as local-only (the helper is
// gone → the test fails to build, or, kept but always-false, the true case
// fails).
func TestIsLocalOnlyCommand(t *testing.T) {
	local := []string{
		"request security wireguard generate-private-key",
		"  request security wireguard generate-private-key  ",
	}
	for _, cmd := range local {
		if !isLocalOnlyCommand(cmd) {
			t.Errorf("isLocalOnlyCommand(%q) = false, want true (offline keygen)", cmd)
		}
	}

	daemon := []string{
		"show interfaces",
		"request security ipsec sa clear",
		"show security wireguard public-key",
		"request system reboot",
		"request security wireguard", // incomplete: falls through to help/daemon
		"",
	}
	for _, cmd := range daemon {
		if isLocalOnlyCommand(cmd) {
			t.Errorf("isLocalOnlyCommand(%q) = true, want false (needs daemon)", cmd)
		}
	}
}

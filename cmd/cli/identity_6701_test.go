package main

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/osident"
)

// spoofedUSER6701 is a sentinel no real passwd account can carry, so an
// assertion against it is never satisfied by coincidence on whatever uid runs
// the suite.
const spoofedUSER6701 = "xpf-spoofed-6701"

// TestResolveUsernameIgnoresUSEREnv_6701 covers the cmd/cli site
// (main.go, formerly `username := os.Getenv("USER")` with a "remote" fallback).
//
// The invariance assertion is the mutation-sensitive one. The pre-fix code
// returned `$USER` when set and "remote" when unset, so it VARIED with the
// environment; a bare `!= spoofedUSER6701` would be satisfied by any hardcoded
// fallback, including the old "remote".
func TestResolveUsernameIgnoresUSEREnv_6701(t *testing.T) {
	t.Setenv("USER", spoofedUSER6701)
	t.Setenv("LOGNAME", spoofedUSER6701)
	spoofed := resolveUsername()

	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "")
	unset := resolveUsername()

	if spoofed == spoofedUSER6701 {
		t.Fatalf("resolveUsername() = %q: the prompt identity came from $USER", spoofed)
	}
	if spoofed != unset {
		t.Fatalf("resolveUsername() varies with the environment: $USER set -> %q, $USER unset -> %q",
			spoofed, unset)
	}
	if spoofed == "remote" && osident.Current().String() != "remote" {
		t.Fatalf("resolveUsername() = %q: that is the pre-#6701 hardcoded fallback, not the "+
			"OS credential %q", spoofed, osident.Current().String())
	}
	if want := osident.Current().String(); spoofed != want {
		t.Fatalf("resolveUsername() = %q, want the OS credential %q", spoofed, want)
	}
	if spoofed == "" {
		t.Fatal("resolveUsername() is empty — the prompt would render `@host>`")
	}
}

// TestResolveUsernameRendersUnresolvedAsUID_6701 pins the no-passwd-entry
// rendering: an unidentified caller must show as `uid-<n>`, never as a
// plausible-looking account name a reader would trust.
func TestResolveUsernameRendersUnresolvedAsUID_6701(t *testing.T) {
	got := resolveUsername()
	if got == "" {
		t.Fatal("resolveUsername() returned empty")
	}
	if !strings.HasPrefix(got, "uid-") && got != osident.Current().Name {
		t.Fatalf("resolveUsername() = %q: neither the passwd name %q nor a uid-<n> rendering",
			got, osident.Current().Name)
	}
}

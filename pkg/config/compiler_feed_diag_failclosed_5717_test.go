package config

import (
	"strings"
	"testing"
)

// #5717 / codex-182 C3: after #5645 the runtime is fail-CLOSED for an
// unresolvable dynamic-address feed binding — the name is omitted, lowers to
// the __unsupported_address__ sentinel, and the userspace snapshot preflight
// REJECTS the whole publication so the dataplane retains previous-good or
// fresh-boot default-deny. The strict commit diagnostics, however, still told
// the operator the OPPOSITE failure mode ("would resolve to an empty address
// set — a feed-backed policy would silently match nothing", i.e. fail-open).
// That stale explanation can drive the wrong remediation during a rejected
// commit or feed-outage investigation.
//
// These assertions pin the corrected #5645 fail-closed wording so a future
// posture change that reverts a diagnostic back to the fail-open framing (or
// forgets to update it alongside the enforcement path) fails loudly here.
//
// RED-on-revert: restore any of the pre-#5645 "silently match nothing" /
// "resolve to an empty address set" fail-open error strings and the
// fails-CLOSED / sentinel substring assertions below fail.

func TestFeedDiagnosticsAreFailClosed_5717(t *testing.T) {
	// The strict feed-name cross-reference diagnostic (undefined feed-name).
	t.Run("undefined-feed-name", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			// Typo: references "malwrae", which no server declares.
			"set security dynamic-address address-name bad-actors profile feed-name malwrae",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject an undefined feed-name reference")
		}
		assertFailClosedFeedDiag_5717(t, err.Error())
	})

	// The strict feed-server endpoint diagnostic (endpoint-less server: a
	// bound address-name is unresolvable because the server registers no feed).
	t.Run("endpoint-less-server", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			// No url and no hostname => resolveBaseURL == "" => server skipped.
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject an endpoint-less feed-server")
		}
		assertFailClosedFeedDiag_5717(t, err.Error())
	})

	// The strict feed-server MALFORMED-url diagnostic (#5183 gate): a non-empty
	// but unconstructible base url (`http://%`) clears the emptiness gate, so a
	// bound address-name is unresolvable and must be reported fail-closed. Before
	// this fold the malformed-url wording had no regression binding — reverting
	// it to the fail-open framing left the suite green.
	t.Run("malformed-url-server", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			"set security dynamic-address feed-server threat url http://%",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject a malformed feed-server url")
		}
		assertFailClosedFeedDiag_5717(t, err.Error())
	})
}

// assertFailClosedFeedDiag_5717 verifies a feed diagnostic describes the #5645
// fail-closed enforcement path and NOT the pre-#5645 fail-open framing.
func assertFailClosedFeedDiag_5717(t *testing.T, msg string) {
	t.Helper()
	// Must describe fail-closed enforcement.
	for _, want := range []string{"fails CLOSED", "__unsupported_address__", "#5645"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("feed diagnostic must describe the #5645 fail-closed path; missing %q in:\n%s", want, msg)
		}
	}
	// Must NOT assert the stale fail-open framing. "silently match nothing"
	// alone is the pre-#5645 wording; the corrected text only ever uses it
	// under an explicit "not"/"NOT" negation, so a bare occurrence is stale.
	if idx := strings.Index(msg, "silently match nothing"); idx >= 0 {
		pre := msg[:idx]
		if !strings.Contains(pre, "NOT ") && !strings.Contains(pre, "not ") {
			t.Fatalf("feed diagnostic still asserts the stale fail-open 'silently match nothing' framing:\n%s", msg)
		}
	}
	if strings.Contains(msg, "silently matches nothing") || strings.Contains(msg, "resolve to an empty address set") {
		t.Fatalf("feed diagnostic still uses stale fail-open framing:\n%s", msg)
	}
}

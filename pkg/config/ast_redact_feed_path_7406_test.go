package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// #7406: `security dynamic-address feed-server <s> feed-name <f> path <p>` is a
// URL-BEARING leaf. resolveBaseURL (pkg/feeds) joins it onto the feed-server's
// url/hostname, so the leaf carries a URL tail and `?token=SECRET` is the
// common feed-provider shape — FeedEntry.MarshalJSON has redacted it on the
// JSON config-read route since #6703.
//
// The AST route (RedactedClone, behind `show configuration` and the config
// export) did NOT: urlLeafIndices had no `path` case, so the same token that
// the REST route redacted rendered VERBATIM on the CLI. The two surfaces
// disagreed about one leaf.
//
// These tests assert the AGREEMENT rather than pinning either side to a
// literal, because the literal would encode which surface is trusted — and the
// AST side was the wrong one.

// redactedFeedPath7406 drives the real AST redaction surface end to end and
// returns the rendered value of the per-feed `path` leaf.
func redactedFeedPath7406(t *testing.T, rawPath string) string {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range []string{
		`set security dynamic-address feed-server et url https://feeds.example.com/base`,
		`set security dynamic-address feed-server et feed-name bad path "` + rawPath + `"`,
	} {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", c, err)
		}
	}
	got, ok := findFeedPathLeaf7406(tree.RedactedClone().Children)
	if !ok {
		t.Fatalf("no `path` leaf in the redacted clone for %q", rawPath)
	}
	return got
}

// findFeedPathLeaf7406 returns the value token of the `path` leaf.
func findFeedPathLeaf7406(nodes []*Node) (string, bool) {
	for _, n := range nodes {
		if len(n.Keys) >= 2 && n.Keys[0] == "path" {
			return strings.Join(n.Keys[1:], " "), true
		}
		if v, ok := findFeedPathLeaf7406(n.Children); ok {
			return v, true
		}
	}
	return "", false
}

// jsonFeedPath7406 renders the same value through the JSON config-read route.
func jsonFeedPath7406(t *testing.T, rawPath string) string {
	t.Helper()
	b, err := json.Marshal(&FeedEntry{Name: "bad", Path: rawPath})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct{ Path string }
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return got.Path
}

// A subscription token in the per-feed path's QUERY must not survive the AST
// render, and the AST render must match what the JSON route produces.
func TestFeedPathQueryTokenIsRedactedOnBothSurfaces7406(t *testing.T) {
	const raw = "/sub/list.txt?token=SECRETTOKEN7406"

	ast := redactedFeedPath7406(t, raw)
	js := jsonFeedPath7406(t, raw)

	if strings.Contains(ast, "SECRETTOKEN7406") {
		t.Errorf("feed path query token survived the AST redaction surface: %q", ast)
	}
	if strings.Contains(js, "SECRETTOKEN7406") {
		t.Errorf("feed path query token survived the JSON surface: %q", js)
	}
	if ast != js {
		t.Errorf("config-read surfaces disagree on the same feed path\n  AST  = %q\n  JSON = %q", ast, js)
	}
}

// Over-reach control: a credential-free path keeps its diagnostic payload, and
// the two surfaces still agree. Without this, "redact the whole leaf" would
// pass the test above while destroying the value operators read.
func TestFeedPathWithoutCredentialIsUnchanged7406(t *testing.T) {
	const raw = "/sub/list.txt"

	ast := redactedFeedPath7406(t, raw)
	js := jsonFeedPath7406(t, raw)

	if ast != raw {
		t.Errorf("credential-free feed path was altered on the AST surface: got %q want %q", ast, raw)
	}
	if js != raw {
		t.Errorf("credential-free feed path was altered on the JSON surface: got %q want %q", js, raw)
	}
}

// The boundary this fix deliberately does NOT cross. A key that IS a path
// SEGMENT is indistinguishable from an ordinary segment, so no string rule
// redacts it without redacting every feed path. Both surfaces render it, and
// they render it the SAME way — pinning that here keeps a future "fix" from
// closing it on one surface only, which is the defect #7406 actually found.
// Documented for operators in pkg/feeds/README.md.
func TestFeedPathSegmentSecretIsRenderedOnBothSurfaces7406(t *testing.T) {
	const raw = "/SEGMENTKEY7406/list.txt"

	ast := redactedFeedPath7406(t, raw)
	js := jsonFeedPath7406(t, raw)

	if ast != js {
		t.Errorf("surfaces disagree on a path-segment secret\n  AST  = %q\n  JSON = %q", ast, js)
	}
	if !strings.Contains(ast, "SEGMENTKEY7406") {
		t.Logf("path-segment secret is now redacted (%q) — if that is intended, "+
			"update pkg/feeds/README.md, which tells operators it is NOT", ast)
	}
}

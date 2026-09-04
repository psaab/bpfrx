package daemon

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestTransientLocalSeedOriginsLockstepWithRust7770 pins
// `transientLocalSeedOrigins` to the set the helper actually classifies as a
// transient local seed.
//
// WHY THIS EXISTS RATHER THAN A LIST OF LITERALS. The behavioural test
// (`TestShouldSyncUserspaceDeltaSkipsTransientLocalSeeds`) drives the list, so
// it is a tautology over its own input: deleting `fabric_punt_seed` from the
// slice deletes the assertion about it and the test stays GREEN. Measured, not
// assumed — that is how this cell came to be written. A per-member check cannot
// see a MISSING member; only a comparison against an independent source can.
//
// And restating the two strings here would not be independent either: a
// constant written down twice is two constants, and the failure they guard
// against is SILENT. The helper's `SessionOrigin::as_str` is what lands in
// `SessionDeltaInfo.Origin` on the wire, so a Go list that spells an origin
// differently — or omits one the helper added — filters nothing, and the delta
// it should have dropped reaches `QueueSessionV4` looking entirely ordinary.
//
// So the set is PARSED from the Rust source: the variants named by
// `is_transient_local_seed`, resolved to their wire strings through the same
// `as_str` arms that produce them. Either side changing alone reds this.
func TestTransientLocalSeedOriginsLockstepWithRust7770(t *testing.T) {
	// Test cwd is pkg/daemon.
	path := filepath.Join("..", "..", "userspace-dp", "src", "session", "entry.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(src)

	// The `matches!(self, Self::A | Self::B)` body of is_transient_local_seed.
	seedFn := regexp.MustCompile(
		`fn is_transient_local_seed\(self\) -> bool \{\s*matches!\(self,([^)]*)\)`)
	m := seedFn.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("could not find `is_transient_local_seed`'s matches! body in %s. "+
			"The helper is the authority for this set; if its shape changed, this "+
			"test must be retaught rather than deleted", path)
	}
	variantRe := regexp.MustCompile(`Self::(\w+)`)
	var variants []string
	for _, v := range variantRe.FindAllStringSubmatch(m[1], -1) {
		variants = append(variants, v[1])
	}
	if len(variants) == 0 {
		t.Fatalf("parsed no Self:: variants out of %q — the pattern matched "+
			"something, but not the arm list, so this cell would pass vacuously", m[1])
	}

	// Resolve each variant to the wire string `as_str` emits for it.
	asStrRe := regexp.MustCompile(`Self::(\w+) => "([a-z_]+)",`)
	wire := map[string]string{}
	for _, a := range asStrRe.FindAllStringSubmatch(text, -1) {
		wire[a[1]] = a[2]
	}
	var want []string
	for _, v := range variants {
		s, ok := wire[v]
		if !ok {
			t.Fatalf("SessionOrigin::%s is classified as a transient local seed but has "+
				"no `as_str` arm, so nothing can be filtered by its wire spelling", v)
		}
		want = append(want, s)
	}

	got := append([]string(nil), transientLocalSeedOrigins...)
	for i := range got {
		got[i] = strings.ToLower(got[i])
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("transientLocalSeedOrigins = %v, but the helper classifies %v as "+
			"transient local seeds (userspace-dp/src/session/entry.rs). A member the "+
			"helper seeds and this list omits is a delta that reaches the peer: a "+
			"#7770 punt seed carries a FabricRedirect disposition and no NAT, and "+
			"#6599 measured that such an Open overwrites the owner's authoritative "+
			"session family under latest-generation-wins", got, want)
	}
}

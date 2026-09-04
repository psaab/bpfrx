package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

// #8597 K83: `runtime_delta.go` maps an unknown event to the FAIL-OPEN member.
//
//	runtimeSessionDeltaReason: default -> SessionDeltaReasonOpen
//	runtimeSessionFamily:      default -> dpruntime.SessionFamilyInet
//
// Neither default is reachable today, and the row says so: the helper's
// producer is an exhaustive match over a TWO-variant enum, and the binary leg
// in eventstream.go overwrites Event unconditionally anyway. So the finding is
// latent, and the question is what a useful remedy looks like for a hazard that
// cannot fire yet.
//
// A counter or a log would be INERT until the day the hazard ships, and on that
// day it reports the misclassification AFTER it has already happened in
// production — a v6 session recorded as inet, or a close recorded as an open.
// The risk is entirely "a future producer gains a third variant", so the useful
// place to catch it is the build, not the runtime.
//
// This binds the Go consumer to the Rust producer's variant set. Add
// `SessionDeltaKind::Update` on the helper side and this goes RED, naming the
// consumer that would otherwise map it silently to Open. That converts a silent
// runtime fail-open into a loud build failure, before it can ship.
//
// It is deliberately NOT a test of `runtimeSessionDeltaReason`'s current
// behaviour: unit-testing a default arm that nothing can reach asserts the
// mapping is what it is, which no change can ever contradict.

// sessionDeltaKindVariants extracts the variant names of the helper's
// SessionDeltaKind enum from the Rust source.
func sessionDeltaKindVariants(t *testing.T) []string {
	t.Helper()
	// The Go package sits at pkg/dataplane/userspace; the helper crate is a
	// sibling of the repo root.
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "session", "entry.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — this guard binds the Go consumer to the Rust "+
			"producer, so it cannot silently pass when it cannot see the producer", path, err)
	}
	body := regexp.MustCompile(`(?s)enum SessionDeltaKind\s*\{(.*?)\}`).FindSubmatch(src)
	if body == nil {
		t.Fatal("could not locate `enum SessionDeltaKind` in userspace-dp/src/session/entry.rs. " +
			"If it moved or was renamed, RE-POINT this guard rather than deleting it: " +
			"its whole job is to notice a change on the producer side")
	}
	var out []string
	for _, line := range strings.Split(string(body[1]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#[") {
			continue
		}
		out = append(out, strings.TrimSuffix(line, ","))
	}
	return out
}

func TestRuntimeDeltaReasonCoversEveryProducerVariant8597K83(t *testing.T) {
	variants := sessionDeltaKindVariants(t)

	// DEGENERATE-FAILURE CONTROL. An extraction that silently returned nothing
	// would make the loop below vacuous and this guard would pass forever while
	// seeing no producer at all.
	if len(variants) < 2 {
		t.Fatalf("extracted %d SessionDeltaKind variants (%v); the producer has at "+
			"least Open and Close, so the extraction is broken and every assertion "+
			"below would be vacuous", len(variants), variants)
	}

	// The consumer's mapping, keyed by the lowercased Rust variant name — which
	// is exactly what `session_delta_event` puts on the wire.
	handled := map[string]bool{}
	for _, w := range []string{"open", "close", "closed", "delete", "deleted", "update", "updated"} {
		handled[w] = true
	}
	for _, v := range variants {
		wire := strings.ToLower(v)
		if !handled[wire] {
			t.Fatalf("#8597 K83: the helper emits SessionDeltaKind::%s (wire %q) and "+
				"runtimeSessionDeltaReason has no arm for it, so it falls to the "+
				"`default: return SessionDeltaReasonOpen` fail-open member — a "+
				"session teardown would be recorded as a session OPEN, silently. "+
				"Add the arm in runtime_delta.go rather than relaxing this guard.",
				v, wire)
		}
	}
}

// The same binding for the family axis. The helper emits libc AF values;
// runtimeSessionFamily maps 6 and 10 to inet6 and EVERYTHING ELSE — including
// an absent 0 — to inet. A v6 session recorded as v4 is the fail-open
// direction, so the set of values the producer can emit must stay inside what
// the consumer distinguishes.
func TestRuntimeSessionFamilyHandlesTheProducersAFValues8597K83(t *testing.T) {
	// AF_INET (2) must map to inet, AF_INET6 (10) to inet6. These are the only
	// two the helper emits (session/tests.rs), and this pins that the consumer
	// separates them rather than collapsing both into the fail-open member.
	if got := runtimeSessionFamily(2); got != dpruntime.SessionFamilyInet {
		t.Fatalf("AF_INET (2) mapped to %v, want inet", got)
	}
	if got := runtimeSessionFamily(10); got != dpruntime.SessionFamilyInet6 {
		t.Fatalf("AF_INET6 (10) mapped to %v, want inet6 — collapsing v6 into the "+
			"inet default is the fail-open direction K83 names", got)
	}
	// CONTROL on the discriminator itself: a mapping that returned inet6 for
	// everything would pass the second assertion and fail this one.
	if runtimeSessionFamily(2) == runtimeSessionFamily(10) {
		t.Fatal("the family mapping does not distinguish AF_INET from AF_INET6 at all")
	}
}

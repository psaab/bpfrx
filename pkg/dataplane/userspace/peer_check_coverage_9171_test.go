package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9171: five of six socket legs verified their peer and the sixth did not —
// the helper's event-stream CLIENT simply connected. That gap plus a
// runtime-dir trust check testing only S_IWOTH made local takeover of the
// session-delta stream reachable, and each half had been dismissed by assuming
// the other held.
//
// This is a COVERAGE table over the legs themselves, not over one leg's
// behaviour. It exists because the sixth leg was missed by reading: nothing
// enumerated the set, so nothing could notice one member was unlike the others.
// A seventh leg added without a check fails this.
//
// NOTE ON THE ISSUE'S CITATIONS: #9171 lists `pkg/daemon/boot_probe.go`, which
// does not exist — the file is `pkg/dataplane/userspace/boot_probe.go`. It also
// describes three separately-checked Go dials; they in fact share one choke
// point. The finding is right and its map was not, which is why this table was
// built by enumerating the tree rather than by transcribing the issue.
//
// It asserts on SOURCE because that is where the property lives — "this call
// site verifies its peer" is a statement about the code, and the alternative
// (standing up six real sockets across two languages) would test the fixture.
func TestEverySocketLegVerifiesItsPeer9171(t *testing.T) {
	root := repoRootFor9171(t)

	for _, leg := range []struct {
		file    string
		anchor  string // the connect/accept whose peer must be checked
		checker string // the verification that must appear near it
		why     string
	}{
		{
			// The Go dials share ONE choke point. That is better than three
			// separate checks and is why they were never the defective leg:
			// boot_probe.go and both process_control.go sites call this, so a
			// fourth caller inherits the check instead of having to remember it.
			file:    "pkg/dataplane/userspace/socket_trust_9003.go",
			anchor:  "func dialTrustedHelperSocket",
			checker: "verifyUnixPeerIsPrivileged",
			why:     "the shared Go dial choke point (3 call sites)",
		},
		{
			file:    "pkg/dataplane/userspace/eventstream.go",
			anchor:  "listener.Accept()",
			checker: "verifyUnixPeerIsPrivileged",
			why:     "Go event stream accept",
		},
		{
			file:    "userspace-dp/src/server/lifecycle.rs",
			anchor:  "accept()",
			checker: "reject_unprivileged_peer",
			why:     "helper control accepts",
		},
		{
			// THE SIXTH. Before #9171 this file contained no checker at all.
			file:    "userspace-dp/src/event_stream/connection.rs",
			anchor:  "UnixStream::connect",
			checker: "reject_unprivileged_peer",
			why:     "helper event-stream CLIENT — a client must authenticate the server it streams session state to",
		},
	} {
		t.Run(leg.why, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(root, leg.file))
			if err != nil {
				t.Fatalf("read %s: %v", leg.file, err)
			}
			src := string(b)
			// PRECONDITION: the anchor must still be present, or this row is
			// asserting about a file that no longer opens the socket and would
			// pass VACUOUSLY after a refactor moved it.
			if !strings.Contains(src, leg.anchor) {
				t.Fatalf("%s no longer contains %q — this row cannot see its subject "+
					"and would pass for the wrong reason", leg.file, leg.anchor)
			}
			if !strings.Contains(src, leg.checker) {
				t.Errorf("%s (%s) opens a socket and never calls %q.\n\n"+
					"Every sibling leg verifies its peer. A leg that does not is how "+
					"#9171 happened: combined with a runtime directory an attacker can "+
					"write, it hands the live session-delta stream to whoever bound the "+
					"path.", leg.file, leg.why, leg.checker)
			}
		})
	}
}

// The helper the client now reuses must remain reachable from it. Reuse rather
// than a second implementation is deliberate: two readings of one syscall are
// how they drift apart, and a drifted copy fails in the quiet direction.
func TestClientReusesTheSharedPeerCheck9171(t *testing.T) {
	root := repoRootFor9171(t)
	b, err := os.ReadFile(filepath.Join(root, "userspace-dp/src/server/lifecycle.rs"))
	if err != nil {
		t.Fatalf("read lifecycle.rs: %v", err)
	}
	if !strings.Contains(string(b), "pub(crate) fn reject_unprivileged_peer") {
		t.Error("reject_unprivileged_peer is no longer crate-visible; the event-stream " +
			"client cannot reuse it and would need a second copy of the SO_PEERCRED read")
	}
	c, err := os.ReadFile(filepath.Join(root, "userspace-dp/src/event_stream/connection.rs"))
	if err != nil {
		t.Fatalf("read connection.rs: %v", err)
	}
	// Look for the SYSCALL, not the NAME. My first version matched the string
	// "SO_PEERCRED" and tripped on this file's own DOC COMMENT explaining why
	// the helper is reused — an assertion that matches prose rather than code,
	// which is the literal-grep trap in miniature.
	if strings.Contains(string(c), "libc::getsockopt") {
		t.Error("the event-stream client reads the peer credentials itself instead of " +
			"calling the shared helper — that is the second implementation this reuse " +
			"exists to avoid, and two readings of one syscall are how they drift")
	}
}

func repoRootFor9171(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the repo root (no go.mod found walking up)")
	return ""
}

// The checker must be on the SUCCESS PATH, not merely present in the file.
//
// A mutation adding a bare `Ok(stream) => return Some(stream)` ahead of the
// verified arm SURVIVED both the coverage table above and the Rust decision
// table: the checker's name was still in the file, and the decision function
// still behaved. Presence is not reachability.
//
// So this asserts the shape of the defect directly — a connect whose success
// arm hands back the stream without passing through the check. That is narrow
// on purpose: it is the failure mode, not a transcription of the current code,
// so an honest refactor that keeps the check on the success path still passes.
func TestEventStreamClientHasNoUncheckedSuccessPath9171(t *testing.T) {
	root := repoRootFor9171(t)
	b, err := os.ReadFile(filepath.Join(root, "userspace-dp/src/event_stream/connection.rs"))
	if err != nil {
		t.Fatalf("read connection.rs: %v", err)
	}
	src := string(b)

	// PRECONDITION: the connect must still be here, or this asserts nothing.
	if !strings.Contains(src, "UnixStream::connect") {
		t.Fatal("connection.rs no longer connects; this cell cannot see its subject")
	}
	if strings.Contains(src, "=> return Some(stream)") {
		t.Error("the event-stream client has a success path that returns the stream " +
			"WITHOUT verifying the peer. The checker being present elsewhere in the " +
			"file does not help: #9171 is that this client streams the session table " +
			"— addresses, ports and zone identity — to whoever is bound to the path.")
	}
}

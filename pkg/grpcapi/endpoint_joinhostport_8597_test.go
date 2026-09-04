package grpcapi

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #8597 (muse-spark-review-004 K29 and its unnamed siblings): a dial or listen
// target must be built with `net.JoinHostPort`, never with `%s:<port>`.
//
// An IPv6 literal formatted the second way yields `2001:db8::2:50051`, which is
// not an address at all — `grpc.NewClient` and `net.Listen` both parse it as a
// bogus host:port. On an IPv6-only fabric the peer dial silently fails and the
// fabric gRPC listener silently never binds, and both present as "the peer is
// unreachable" rather than as a formatting bug.
//
// #4909 already fixed this shape once, in `pkg/cli/peer.go`, and that fix's
// comment names this exact string. What it did not do is sweep the class: the
// review named ONE site (`grpcapi/server_diag.go`, a DIAL) and the sweep found
// TWO more (`daemon/daemon_ha_comms_wiring.go`, both LISTEN addresses). A
// reviewer's enumeration is a floor.
//
// THE DISCRIMINATOR, and why this census is not over-broad: a HARDCODED PORT
// LITERAL in a `%s:` format is an endpoint. Rendering a packet's port for
// display uses `%s:%d` with a variable, and there are ~15 of those in the tree
// that are legitimately not endpoints (session tables, log lines, flow output).
// Matching only the literal-port form separates the two exactly.

var sprintfEndpointRe = regexp.MustCompile(`Sprintf\("%s:[0-9]+"`)

func TestNoSprintfBuiltEndpoints_8597(t *testing.T) {
	var hits []string
	var scanned int
	for _, root := range []string{filepath.Join("..", ".."), ""} {
		if root == "" {
			continue
		}
		for _, sub := range []string{"pkg", "cmd"} {
			err := filepath.Walk(filepath.Join(root, sub), func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
					strings.HasSuffix(path, "_test.go") {
					return nil
				}
				scanned++
				src, rerr := os.ReadFile(path)
				if rerr != nil {
					return rerr
				}
				if sprintfEndpointRe.Match(src) {
					hits = append(hits, path)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk %s: %v", sub, err)
			}
		}
	}

	// POSITIVE CONTROL. A census that scanned nothing finds nothing and passes
	// forever, and the census is what you would consult to discover that.
	if scanned < 300 {
		t.Fatalf("the census scanned only %d non-test Go files under pkg/ and cmd/; the walk "+
			"is not reaching the tree it claims to cover, so its empty result is not evidence",
			scanned)
	}
	// SECOND CONTROL, on the PATTERN rather than the walk: the regex must still
	// match the shape it is looking for. Without this, a typo in the pattern
	// leaves a green test asserting nothing about a class it no longer sees.
	if !sprintfEndpointRe.MatchString(`fmt.Sprintf("%s:50051", ip)`) {
		t.Fatal("the endpoint pattern no longer matches the string it exists to find; it has " +
			"rotted and this census is asserting nothing")
	}

	if len(hits) != 0 {
		t.Errorf("#8597: %d file(s) build a network endpoint with a hardcoded-port Sprintf "+
			"instead of net.JoinHostPort: %v.\nAn IPv6 literal becomes `2001:db8::2:50051`, "+
			"which is not an address — the dial or bind fails and reports itself as an "+
			"unreachable peer. #4909 fixed this shape in pkg/cli/peer.go; see that comment.",
			len(hits), hits)
	}
}

// TestJoinHostPortBracketsIPv6_8597 pins the property the census protects, so
// the census cannot be satisfied by a helper that is equally broken. Without
// this, "nobody uses Sprintf" and "the replacement works" are separate claims
// and only one of them is asserted.
func TestJoinHostPortBracketsIPv6_8597(t *testing.T) {
	if got := net.JoinHostPort("2001:db8::2", "50051"); got != "[2001:db8::2]:50051" {
		t.Fatalf("JoinHostPort(v6) = %q, want a bracketed literal", got)
	}
	if got := net.JoinHostPort("10.0.0.1", "50051"); got != "10.0.0.1:50051" {
		t.Fatalf("JoinHostPort(v4) = %q, want the plain form unchanged", got)
	}
	// And the shape that motivated the fix: the old spelling is NOT parseable.
	if _, _, err := net.SplitHostPort("2001:db8::2:50051"); err == nil {
		t.Fatal("PREMISE: the unbracketed IPv6 endpoint must be unparseable — if it round-" +
			"tripped, the defect this census guards would be cosmetic")
	}
}

package ddns

import (
	"errors"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

// errtree_bound_after_as_6635_test.go: #6635. errTreeWithinBound validated the
// error tree AS PRESENTED at the public entry point, and that is not the tree
// the stdlib ends up walking. errors.As dispatches to an As(any) bool method the
// CALLER defines, and that method hands back a value of the caller's choosing —
// so an error with a one-node tree (guard passes) can install a fresh
// *url.Error whose Err self-unwraps, and the very next errors.As spins forever.
//
// THE FAILURE MODE IS A HANG, so the test RETURNING is the signal. Every cell
// runs the scrubber on a goroutine with a deadline: without the fix the cell
// times out; with it, it returns. A plain call would wedge the whole package
// run instead of failing, which is why none of these call the scrubber directly.
//
// REACHABILITY, stated so nobody reads this as a live DoS. The bypass needs a Go
// error VALUE with hostile methods. Production builds its own client
// (newProviderHTTPClient → newHTTPClientBound); ensureProviderHTTPClient does
// accept a caller-supplied *http.Client, but the only production caller is the
// Surface A reconcile path passing its own cached client, and every error on
// these paths originates in net/http or the stdlib. A provider can choose BYTES
// over the wire; it cannot choose a Go type. This is robustness and
// model-consistency, not a reachable denial of service.

// scrubDeadline is generous: the cells that pass return in microseconds, and the
// ones that would fail do not return at all, so a large value costs nothing on a
// green run and only bounds how long a red takes to report.
const scrubDeadline = 5 * time.Second

// selfUnwrapping's Unwrap returns ITSELF, which makes any stdlib traversal
// (errors.Is, errors.As, errors.Unwrap in a loop) spin forever.
type selfUnwrapping struct{}

func (selfUnwrapping) Error() string   { return "self-unwrapping" }
func (s selfUnwrapping) Unwrap() error { return s }

// selfCycleMulti is the Unwrap() []error form: it recurses until the STACK
// overflows, which is a `fatal error` recover() cannot catch — strictly worse
// than a hang.
type selfCycleMulti struct{}

func (selfCycleMulti) Error() string     { return "self-cycle-multi" }
func (s selfCycleMulti) Unwrap() []error { return []error{s} }

// asInstallsHostileSubtree has a benign tree AS PRESENTED — one node, no Unwrap
// at all — so the entry guard passes. Its As then installs a *url.Error whose
// Err is a subtree that was never walked. This is the exact bypass #6635
// describes.
type asInstallsHostileSubtree struct{ inner error }

func (asInstallsHostileSubtree) Error() string { return "as-installer" }
func (a asInstallsHostileSubtree) As(target any) bool {
	if p, isURLErr := target.(**url.Error); isURLErr {
		*p = &url.Error{Op: "Get", URL: "https://prov.example/upd", Err: a.inner}
		return true
	}
	return false
}

// runWithDeadline runs f on a goroutine and reports whether it returned in time.
// The goroutine is deliberately NOT waited on when it times out: it may never
// return, which is the defect.
func runWithDeadline(t *testing.T, f func() string) (string, bool) {
	t.Helper()
	done := make(chan string, 1)
	go func() { done <- f() }()
	select {
	case s := <-done:
		return s, true
	case <-time.After(scrubDeadline):
		return "", false
	}
}

func TestScrubbersBoundASubtreeInstalledByACustomAs_6635(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inner error
		// via is the public entry point under test. Both are exercised: the
		// bypass is reachable through either, because scrubInnerErrorAt and
		// scrubURLErrorAt are mutually recursive.
		via func(error) string
	}{
		{
			name:  "self_unwrapping_via_scrubURLError",
			inner: selfUnwrapping{},
			via:   scrubURLError,
		},
		{
			name:  "self_unwrapping_via_scrubInnerError",
			inner: selfUnwrapping{},
			via:   scrubInnerError,
		},
		{
			name:  "unwrap_slice_cycle_via_scrubURLError",
			inner: selfCycleMulti{},
			via:   scrubURLError,
		},
		{
			name:  "unwrap_slice_cycle_via_scrubInnerError",
			inner: selfCycleMulti{},
			via:   scrubInnerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostile := asInstallsHostileSubtree{inner: tc.inner}

			// THE PRECONDITION that makes this a bypass and not a re-test of the
			// round-11 guard. If the entry guard rejected this tree the cell
			// would prove nothing about what a custom As installs.
			if !errTreeWithinBound(hostile) {
				t.Fatal("the tree AS PRESENTED must pass the entry guard — it is a single node " +
					"with no Unwrap. If it does not, this cell is testing the old guard, not " +
					"the subtree a custom As installs.")
			}

			got, returned := runWithDeadline(t, func() string { return tc.via(hostile) })
			if !returned {
				t.Fatalf("HUNG: the scrubber did not return within %s. A custom As installed a "+
					"subtree the entry guard never walked, and the next stdlib traversal spins "+
					"on it. Re-run errTreeWithinBound at every entry to the depth-carrying "+
					"scrubbers, not only at the public one.", scrubDeadline)
			}
			// WHAT IT BECAME. Returning is necessary but not sufficient: a
			// scrubber that returned the caller's own text would also "return".
			//
			// CONTAINS, not equality, and the difference is the point. On the
			// scrubURLError path the As hands back a *url.Error whose URL field
			// it also chose, and that field is still rendered — through
			// safeURLTarget's closed grammar, which reduces it to
			// scheme://host and drops the path. So the expected result is the
			// safe target PLUS a withheld inner cause, not a bare constant.
			// Requiring equality would have been an assertion about the round-8
			// URL grammar, not about this fix.
			if !strings.Contains(got, string(transportWithheld)) {
				t.Errorf("the unbounded subtree must be WITHHELD, not rendered; got %q, want it "+
					"to contain %q", got, string(transportWithheld))
			}
			// And nothing from the hostile subtree's own Error() may appear.
			if strings.Contains(got, tc.inner.Error()) {
				t.Errorf("the hostile subtree's own text reached the render: %q", got)
			}
		})
	}
}

// TestNestedHostileSubtreeIsBoundAtDepth_6635 pushes the installed subtree one
// level deeper — a *url.Error wrapping the installer — so the bypass is entered
// through the recursive path rather than at depth 0. A fix that guarded only the
// public entry point, or only the first level, passes the cells above and fails
// here.
func TestNestedHostileSubtreeIsBoundAtDepth_6635(t *testing.T) {
	hostile := &url.Error{
		Op:  "Get",
		URL: "https://prov.example/upd",
		Err: asInstallsHostileSubtree{inner: selfUnwrapping{}},
	}
	if !errTreeWithinBound(hostile) {
		t.Fatal("the presented tree is two nodes and must pass the entry guard")
	}
	got, returned := runWithDeadline(t, func() string { return scrubURLError(hostile) })
	if !returned {
		t.Fatalf("HUNG at depth: the guard must run at EVERY entry to the depth-carrying "+
			"scrubbers, not only the first. (%s deadline)", scrubDeadline)
	}
	if !strings.Contains(got, string(transportWithheld)) {
		t.Errorf("the unbounded subtree must be withheld somewhere in the render; got %q", got)
	}
}

// TestOrdinaryErrorsStillClassifyNormally_6635 is the over-reach guard. Adding a
// guard at every recursion entry must not start withholding ordinary errors:
// this package's whole diagnostic value is the transport classification, and a
// fix that withheld everything would satisfy every hang test above.
func TestOrdinaryErrorsStillClassifyNormally_6635(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{
			name: "wrapped_connection_refused",
			err: &url.Error{Op: "Get", URL: "https://prov.example/upd",
				Err: syscall.ECONNREFUSED},
			want: string(transportConnRefused),
		},
		{
			name: "deeply_but_finitely_wrapped",
			// Ten ordinary %w layers: well inside the budget, and the shape a
			// real error actually has.
			err:  wrapN(&url.Error{Op: "Get", URL: "https://prov.example/upd", Err: syscall.ECONNRESET}, 10),
			want: string(transportConnReset),
		},
		{
			name: "plain_transport_error",
			err:  syscall.ETIMEDOUT,
			want: string(transportConnTimedOut),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, returned := runWithDeadline(t, func() string { return scrubURLError(tc.err) })
			if !returned {
				t.Fatalf("an ORDINARY error must not hang the scrubber (%s deadline)", scrubDeadline)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("the transport classification must survive the re-guard — withholding "+
					"everything passes every hang test and destroys the diagnostic.\n"+
					"  got:  %q\n  want to contain: %q", got, tc.want)
			}
			if strings.Contains(got, string(transportWithheld)) {
				t.Errorf("an ordinary error must NOT be withheld; got %q", got)
			}
		})
	}
}

// wrapN wraps err in n ordinary fmt-style layers.
func wrapN(err error, n int) error {
	for i := 0; i < n; i++ {
		err = &wrapped{err}
	}
	return err
}

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "layer: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }

// TestErrTreeBoundStillRejectsAPresentedCycle_6635 keeps the round-11 property
// from silently regressing while the call sites move: the guard must still
// reject a cycle presented DIRECTLY, not only one installed behind an As.
func TestErrTreeBoundStillRejectsAPresentedCycle_6635(t *testing.T) {
	if errTreeWithinBound(selfUnwrapping{}) {
		t.Error("a directly-presented Unwrap() self-cycle must still be rejected")
	}
	if errTreeWithinBound(selfCycleMulti{}) {
		t.Error("a directly-presented Unwrap() []error self-cycle must still be rejected")
	}
	if !errTreeWithinBound(errors.New("plain")) {
		t.Error("a plain error must pass the bound")
	}
	if !errTreeWithinBound(wrapN(errors.New("plain"), 10)) {
		t.Error("an ordinary ten-layer wrap must pass the bound")
	}
}

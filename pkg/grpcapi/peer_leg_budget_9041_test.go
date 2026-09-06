package grpcapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// #9041 part 2: the four full session fan-out handlers must not hold the LOCAL
// session-walk slot across the peer RTT.
//
// MaxConcurrentSessionWalks is 4 and the worst case per request is dialPeer 2s
// x N fabric addresses (4s dual-fabric) plus the peer RPC (3s, 5s for the
// clear), so four concurrent requests saturated the budget below 1 rps and
// GetStatus and other genuine LOCAL scans answered ResourceExhausted — while
// the local table was untouched. That is the exact wrong #7294 item 3 fixed for
// the peer-ONLY paths; these four are the paths it did not reach.
//
// Two halves are bound separately below: the handoff itself (behavioural, on
// beginPeerLeg) and the WIRING (structural, because binding it behaviourally
// needs a live cluster.Manager with PeerAlive plus a real authenticated peer
// dial — the same limit clear_peer_ctx_9041_test.go and
// peer_fanout_attach_6851_test.go both state for this area).

// drainRemote frees n remote slots, restoring global limiter state.
func drainRemote(t *testing.T, rels []func()) {
	t.Helper()
	for _, r := range rels {
		r()
	}
	if got := diagcmd.RemoteWalkLimiter.InFlight(); got != 0 {
		t.Fatalf("remote limiter not drained: %d in flight", got)
	}
}

// ── the handoff ──

func TestPeerLegReleasesTheLocalWalkSlot9041(t *testing.T) {
	if got := diagcmd.SessionWalkLimiter.InFlight(); got != 0 {
		t.Fatalf("precondition: local limiter dirty (%d in flight)", got)
	}
	release, err := diagcmd.SessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if got := diagcmd.SessionWalkLimiter.InFlight(); got != 1 {
		t.Fatalf("precondition: expected 1 local slot held, got %d", got)
	}

	ctx := withLocalWalkRelease(context.Background(), release)
	_, done, err := beginPeerLeg(ctx)
	if err != nil {
		t.Fatalf("beginPeerLeg: %v", err)
	}

	if got := diagcmd.SessionWalkLimiter.InFlight(); got != 0 {
		t.Errorf("#9041: the LOCAL session-walk slot is still held across the peer "+
			"leg (%d in flight). A slow peer then pins a local scan slot for up to "+
			"~7s, and four concurrent requests refuse GetStatus while the local "+
			"table is untouched", got)
	}
	if got := diagcmd.RemoteWalkLimiter.InFlight(); got != 1 {
		t.Errorf("#9041: the peer leg is not charged to the REMOTE budget "+
			"(%d in flight). Releasing the local slot without taking a remote one "+
			"would make the peer fan-out unbounded, which is a loosening, not a fix", got)
	}
	done()
	if got := diagcmd.RemoteWalkLimiter.InFlight(); got != 0 {
		t.Errorf("#9041: the remote slot leaked after the peer leg (%d in flight)", got)
	}
	release() // sync.Once-guarded; the handler's own defer does this too
	if got := diagcmd.SessionWalkLimiter.InFlight(); got != 0 {
		t.Errorf("#9041: double release over-credited the local budget (%d in flight)", got)
	}
}

func TestPeerLegKeepsTheLocalSlotWhenTheRemoteBudgetIsFull9041(t *testing.T) {
	// Order matters: releasing the local slot and THEN failing to take a remote
	// one would drop the slot for a leg that never runs — the caller would have
	// given up its admission for nothing.
	var rels []func()
	for i := 0; i < diagcmd.MaxConcurrentRemoteWalks; i++ {
		r, err := diagcmd.RemoteWalkLimiter.Acquire()
		if err != nil {
			t.Fatalf("saturating remote budget: %v", err)
		}
		rels = append(rels, r)
	}
	t.Cleanup(func() { drainRemote(t, rels) })

	release, err := diagcmd.SessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)

	ctx := withLocalWalkRelease(context.Background(), release)
	_, done, err := beginPeerLeg(ctx)
	if err == nil {
		done()
		t.Fatal("#9041: a full remote budget must refuse the peer leg")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("#9041: a refused peer leg must be ResourceExhausted so "+
			"peerFetchErrorStatus classifies it BUSY and the peer result is "+
			"reported as refused rather than silently absent (#8306); got %v", err)
	}
	if got := diagcmd.SessionWalkLimiter.InFlight(); got != 1 {
		t.Errorf("#9041: the local slot was released for a peer leg that never "+
			"ran (%d in flight) — the caller gave up its admission for nothing", got)
	}
}

func TestPeerLegRefusalIsReportedAsBusy9041(t *testing.T) {
	// The refusal has to travel through the EXISTING classifier, or the peer
	// block goes silently absent instead of visibly refused.
	err := status.Error(codes.ResourceExhausted, "peer session fan-out concurrency limit reached")
	if got := peerFetchErrorStatus(err); got != pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY {
		t.Errorf("#9041: a refused peer leg classified as %v, not BUSY — an operator "+
			"cannot tell a busy fan-out from an unreachable peer", got)
	}
}

func TestPeerLegDoesNotFreeAnAncestorsLease9041(t *testing.T) {
	// #5880: a descendant that reuses an ancestor's lease gets a no-op release.
	// It must NOT free the ancestor's slot — the ancestor may still walk locally
	// after the descendant returns.
	outerRel, leased, err := diagcmd.SessionWalkLimiter.AcquireCtx(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(outerRel)
	innerRel, _, err := diagcmd.SessionWalkLimiter.AcquireCtx(leased)
	if err != nil {
		t.Fatalf("a leased re-acquire must reuse, not refuse: %v", err)
	}
	if got := diagcmd.SessionWalkLimiter.InFlight(); got != 1 {
		t.Fatalf("precondition: lease reuse should hold exactly 1 slot, got %d", got)
	}

	_, done, err := beginPeerLeg(withLocalWalkRelease(leased, innerRel))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if got := diagcmd.SessionWalkLimiter.InFlight(); got != 1 {
		t.Errorf("#9041: the peer handoff freed an ANCESTOR's session-walk slot "+
			"(%d in flight). The ancestor may still walk after this returns, so "+
			"its admission is not the descendant's to give away", got)
	}
}

// ── the wiring ──

// peerFanOutHelpers are the four helpers that perform a peer RTT on the full
// session surface. Keyed by name: a rename must bring the guard along rather
// than silently disarm it.
var peerFanOutHelpers = []string{
	"fetchPeerSessions",
	"proxyPeerSessionSummary",
	"proxyPeerZonePairSummary",
	"clearPeerSessions",
}

func TestPeerFanOutHandsOffBeforeDialing9041(t *testing.T) {
	const file = "server_sessions.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	byName := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			byName[fd.Name.Name] = fd
		}
	}
	for _, name := range peerFanOutHelpers {
		fn, ok := byName[name]
		if !ok {
			t.Errorf("%s not found in %s — this guard is keyed by name", name, file)
			continue
		}
		var handoff, dial token.Pos
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch c := call.Fun.(type) {
			case *ast.Ident:
				if c.Name == "beginPeerLeg" && !handoff.IsValid() {
					handoff = call.Pos()
				}
			case *ast.SelectorExpr:
				if c.Sel.Name == "dialPeer" && !dial.IsValid() {
					dial = call.Pos()
				}
			}
			return true
		})
		if !dial.IsValid() {
			t.Errorf("%s no longer dials the peer — if the fan-out moved, move this "+
				"guard with it rather than leaving it green over nothing", name)
			continue
		}
		if !handoff.IsValid() {
			t.Errorf("#9041: %s dials the peer without handing off to the remote "+
				"budget, so it holds the LOCAL session-walk slot across the RTT — "+
				"the defect #7294 item 3 fixed for the peer-only paths", name)
			continue
		}
		if handoff > dial {
			t.Errorf("#9041: %s hands off to the remote budget AFTER dialPeer. The "+
				"dial is 2s per fabric address (4s dual-fabric) and is the larger "+
				"half of the tail, so a handoff below it leaves the defect in place",
				name)
		}
	}
}

func TestSessionWalkHandlersPublishTheirRelease9041(t *testing.T) {
	// The handoff can only happen if the handler published its release. A
	// handler that acquires the local budget and does not publish keeps the old
	// behaviour SILENTLY — nothing fails, the slot is simply held across the RTT.
	const file = "server_sessions.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	found := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		var acquires, publishes bool
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch c := call.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := c.X.(*ast.Ident); ok && id.Name == "sessionWalkLimiter" &&
					(c.Sel.Name == "Acquire" || c.Sel.Name == "AcquireCtx") {
					acquires = true
				}
			case *ast.Ident:
				if c.Name == "withLocalWalkRelease" {
					publishes = true
				}
			}
			return true
		})
		if !acquires {
			continue
		}
		found++
		if !publishes {
			t.Errorf("#9041: %s acquires the local session-walk budget but never "+
				"publishes its release, so its peer fan-out cannot hand off and "+
				"holds the slot across the RTT — and does so silently", fn.Name.Name)
		}
	}
	// Guard the guard: an enumeration that finds nothing passes vacuously.
	if found != 4 {
		t.Errorf("#9041: expected the 4 known session-walk handlers, found %d. If a "+
			"handler was added or removed, this count is the thing that noticed", found)
	}
}

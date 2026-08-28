package api

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
)

// authz_peerdone_slot_6977_test.go — #6977, the p.done / admission-token
// ordering.
//
// connContext starts the peer lookup in a goroutine that holds one token from
// the process-global admission pool. Defers run LIFO, so the goroutine's two
// deferred statements decide what `p.done` MEANS:
//
//	defer func() { <-peerLookupSlots }()   // registered 1st -> runs LAST
//	defer close(p.done)                    // registered 2nd -> runs FIRST
//
// In that order — the order that shipped — a caller that joins on p.done
// returns while the token is still out. `done` then means "the lookup
// finished", not "the lookup finished and its slot is back", and a case that
// immediately fills the pool observes a preceding lookup's transient token and
// fails on its own precondition. Every case near the pool carries a waitSlots
// precondition to absorb exactly that.
//
// Registering them the other way round makes the name true. The receive cannot
// block: the goroutine's own token is in the buffer.
//
// HOW THIS IS BOUND, stated rather than implied. The property is a
// happens-before with no deterministic behavioural seam: with the shipped order
// the token is USUALLY back by the time an observer looks, so a behavioural
// probe reds only sometimes, and a cell that reds sometimes is not a guard. The
// structural cell below is therefore the one that reds on the mutation, and the
// behavioural cell states the invariant in executable form — it passes
// deterministically with the fix and is not claimed as the detector.

// TestPeerDoneMeansTheSlotIsBack_6977 is the invariant in executable form: with
// the pool otherwise full, a token must be immediately available the moment
// p.done is observed closed.
func TestPeerDoneMeansTheSlotIsBack_6977(t *testing.T) {
	waitSlots(t, 0, "the lookup pool never returned to zero occupancy before this case started")

	// Fill the pool to capacity-1 by hand, so the lookup below takes the LAST
	// token and its return is the only thing that can free one.
	held := 0
	defer func() {
		for i := 0; i < held; i++ {
			<-peerLookupSlots
		}
	}()
	for i := 0; i < maxConcurrentPeerLookups-1; i++ {
		select {
		case peerLookupSlots <- struct{}{}:
			held++
		default:
			t.Fatalf("the pool refused token %d of %d before the case started; another case "+
				"is still holding one and this cell cannot pin occupancy",
				i+1, maxConcurrentPeerLookups-1)
		}
	}

	s := &Server{}
	s.peerLookupFn = func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{UID: 0, OK: true, Local: true}
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ctx := s.connContext(context.Background(), c1)
	p, ok := ctx.Value(peerIdentityKey{}).(*pendingPeer)
	if !ok || p == nil {
		t.Fatal("connContext did not attach a pendingPeer; this cell is not observing the " +
			"path it names")
	}
	// The lookup took the last token, so the pool is full while it runs.
	select {
	case peerLookupSlots <- struct{}{}:
		held++
		t.Fatal("a token was still available while the lookup was in flight — the lookup did " +
			"not take one, so the release this cell is about never happens")
	default:
	}

	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the peer lookup never finished")
	}

	// THE INVARIANT: p.done is closed, so the token is back — no polling.
	select {
	case peerLookupSlots <- struct{}{}:
		held++
	default:
		t.Fatalf("p.done was closed while the lookup still held its admission token "+
			"(%d/%d in use). `done` must mean the slot is back as well as that the lookup "+
			"finished, or every caller that joins on it has to carry a waitSlots "+
			"precondition to absorb the difference (#6977)",
			PeerLookupSlotsInUseForTest(), maxConcurrentPeerLookups)
	}
}

// TestPeerDoneIsClosedAfterTheSlotIsReturned_6977 is the cell that reds on the
// mutation: it asserts the SOURCE ORDER of the two defers, which is what
// decides the LIFO run order and therefore the meaning of p.done.
//
// Parsed with parser.ParseFile(..., 0), so comments are discarded before
// matching — the commentary in authz.go that quotes the shipped order cannot
// satisfy it.
func TestPeerDoneIsClosedAfterTheSlotIsReturned_6977(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	path := filepath.Join(filepath.Dir(self), "authz.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var closeAt, releaseAt token.Pos
	var found bool
	for _, d := range f.Decls {
		fd, isFunc := d.(*ast.FuncDecl)
		if !isFunc || fd.Body == nil || fd.Name.Name != "connContext" {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ds, isDefer := n.(*ast.DeferStmt)
			if !isDefer {
				return true
			}
			// `defer close(p.done)`
			if id, isIdent := ds.Call.Fun.(*ast.Ident); isIdent && id.Name == "close" {
				if !closeAt.IsValid() {
					closeAt = ds.Pos()
				}
				return true
			}
			// `defer func() { <-peerLookupSlots }()`
			ast.Inspect(ds.Call, func(m ast.Node) bool {
				u, isUnary := m.(*ast.UnaryExpr)
				if !isUnary || u.Op != token.ARROW {
					return true
				}
				if id, isIdent := u.X.(*ast.Ident); isIdent && id.Name == "peerLookupSlots" {
					if !releaseAt.IsValid() {
						releaseAt = ds.Pos()
					}
				}
				return true
			})
			return true
		})
	}

	if !found {
		t.Fatal("connContext is gone from pkg/api/authz.go; this guard is not reading the " +
			"function it claims to audit")
	}
	if !closeAt.IsValid() {
		t.Fatal("no `defer close(...)` found in connContext — the pendingPeer is no longer " +
			"completed by a deferred close, so re-derive what p.done now promises (#6977)")
	}
	if !releaseAt.IsValid() {
		t.Fatal("no deferred `<-peerLookupSlots` found in connContext — the admission token " +
			"is no longer returned by a defer in the lookup goroutine, so re-derive the " +
			"ordering this guard pins (#6977)")
	}
	// Defers run LIFO: the one registered FIRST runs LAST. For p.done to be
	// closed after the token is back, `defer close(p.done)` must appear FIRST.
	if closeAt >= releaseAt {
		t.Fatalf("`defer close(p.done)` is registered at or after the token release "+
			"(close pos %d, release pos %d). Defers run LIFO, so in that order the close runs "+
			"FIRST and p.done is observable while the slot is still out — which is what makes "+
			"every caller that joins on it need a waitSlots precondition, and what made a case "+
			"that fills the pool see a preceding lookup's transient token (#6977)",
			closeAt, releaseAt)
	}
}

package dataplane

// #7149 (split from #4960): CompileConfig's post-recompile FIB generation bump
// used to be a bare `dp.BumpFIBGeneration()`, discarding both results.
//
// Two guards, because neither subsumes the other and each catches an escape the
// other is blind to:
//
//   - TestFailedFIBBumpIsReported_7149 binds the BEHAVIOUR: a failing bump
//     produces a WARN carrying the error. Gutting the body to a bare call reds
//     it. It cannot see the CALL SITE — replacing
//     `bumpFIBGenerationAfterRecompile(dp)` in CompileConfig with the old
//     `dp.BumpFIBGeneration()` leaves it green, because the helper is still
//     there and still correct.
//   - TestCompilerNeverDiscardsTheFIBBumpError_7149 binds the SITE, as a source
//     property rather than as a call trace: no production file in this package
//     may call BumpFIBGeneration and drop its error. That is what reds on the
//     revert. It cannot see whether the error is then USEFULLY handled — an
//     `if err != nil {}` with an empty body satisfies it — which is what the
//     behavioural half is for.
//
// The call site itself cannot be driven from a unit test: CompileConfig reaches
// the bump only after compileZones completes, and compileZones' tail
// (stripUnmanagedInterfaces) does netlink.LinkDel / LinkSetDown on every
// unmanaged link on the host. Every other CompileConfig test in this package
// stops on the errStopBeforeHostReconcile tripwire for that reason. A source
// property is what remains available, so it is used deliberately and its limit
// is stated rather than papered over.
//
// The WARN's wording is deliberately NOT asserted. Recording that the prose must
// contain a phrase is what produced wrong-but-green rounds elsewhere in this
// package; what is asserted is the LEVEL and that the injected error VALUE
// reaches the record.

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
)

// fibBumpDP answers BumpFIBGeneration with a scripted result and counts calls.
// It embeds a NIL DataPlane on purpose: any other method the code under test
// reaches panics instead of silently succeeding.
type fibBumpDP struct {
	DataPlane
	err   error
	calls int
}

func (d *fibBumpDP) BumpFIBGeneration() (uint32, error) {
	d.calls++
	return 7, d.err
}

func TestFailedFIBBumpIsReported_7149(t *testing.T) {
	sentinel := errors.New("xpf-7149-sentinel: fib_gen_map write refused")

	t.Run("failure is reported", func(t *testing.T) {
		buf := captureWarnSlog(t)
		dp := &fibBumpDP{err: sentinel}

		bumpFIBGenerationAfterRecompile(dp)

		if dp.calls != 1 {
			t.Fatalf("want exactly 1 BumpFIBGeneration call, got %d — the helper "+
				"no longer performs the bump at all", dp.calls)
		}
		warns := warnLines(buf)
		if len(warns) == 0 {
			t.Fatalf("a FAILED FIB generation bump produced no WARN record.\n\n"+
				"captured log:\n%s\n\n"+
				"The bump is the only compiler dataplane call that is not a shim "+
				"no-op on the live userspace path, and (*Manager).BumpFIBGeneration's "+
				"not-armed branch returns ErrDataplaneNotArmed WITHOUT logging. If "+
				"this site drops it too, a recompile publishes a snapshot carrying "+
				"the previous FIB generation and established flows keep a stale "+
				"next-hop, with nothing in the journal saying so (#7149).", buf.String())
		}
		// The error VALUE must reach the record — a WARN that announces trouble
		// without carrying which failure it was is not a report.
		joined := strings.Join(warns, "\n")
		if !strings.Contains(joined, "xpf-7149-sentinel") {
			t.Errorf("the WARN does not carry the bump error.\ngot:\n%s", joined)
		}
	})

	// Control. Without this the assertion above is satisfied by a helper that
	// warns unconditionally, which would be a false alarm on every successful
	// recompile — CLAUDE.md's logging rules exist precisely against that.
	t.Run("success is silent", func(t *testing.T) {
		buf := captureWarnSlog(t)
		dp := &fibBumpDP{err: nil}

		bumpFIBGenerationAfterRecompile(dp)

		if dp.calls != 1 {
			t.Fatalf("want exactly 1 BumpFIBGeneration call, got %d", dp.calls)
		}
		if warns := warnLines(buf); len(warns) != 0 {
			t.Errorf("a SUCCESSFUL FIB generation bump emitted %d WARN record(s); "+
				"the helper warns unconditionally:\n%s", len(warns), strings.Join(warns, "\n"))
		}
	})
}

// captureWarnSlog redirects the default logger into a buffer at WARN level for
// the duration of the test. Same idiom as captureSlog in
// compiler_prepass_logging_4960_test.go, narrowed to WARN so an unrelated INFO
// record cannot be mistaken for a report.
func captureWarnSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func warnLines(buf *bytes.Buffer) []string {
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "level=WARN") {
			out = append(out, line)
		}
	}
	return out
}

// TestCompilerNeverDiscardsTheFIBBumpError_7149 walks this package's production
// source and fails on any call to BumpFIBGeneration that drops its error —
// either as a bare expression statement (`dp.BumpFIBGeneration()`, the exact
// pre-#7149 shape) or as an assignment that blanks the error slot
// (`_, _ = dp.BumpFIBGeneration()`, the shape a bare-statement-only check would
// wave through).
//
// Scoped to pkg/dataplane, non-recursively: pkg/dataplane/userspace has its own
// deliberate discards, documented at (*Manager).BumpFIBGeneration's error
// contract in manager_generation.go, and this guard has no business ruling on
// them.
func TestCompilerNeverDiscardsTheFIBBumpError_7149(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse pkg/dataplane: %v", err)
	}

	var (
		calls    int
		offences []string
	)
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch stmt := n.(type) {
				case *ast.ExprStmt:
					if isFIBBumpCall(stmt.X) {
						calls++
						offences = append(offences, fmt.Sprintf(
							"%s:%d: result discarded (bare call statement)",
							path, fset.Position(stmt.Pos()).Line))
					}
				case *ast.AssignStmt:
					if len(stmt.Rhs) != 1 || !isFIBBumpCall(stmt.Rhs[0]) {
						return true
					}
					calls++
					// The error is the LAST result.
					if len(stmt.Lhs) == 0 {
						return true
					}
					if id, ok := stmt.Lhs[len(stmt.Lhs)-1].(*ast.Ident); ok && id.Name == "_" {
						offences = append(offences, fmt.Sprintf(
							"%s:%d: error assigned to _",
							path, fset.Position(stmt.Pos()).Line))
					}
				}
				return true
			})
		}
	}

	// FLOOR. Without it a rename, a file move, or a broken walk empties the
	// scan and this passes having proven nothing.
	if calls == 0 {
		t.Fatalf("the walk found NO call to BumpFIBGeneration in pkg/dataplane's " +
			"production source. CompileConfig is supposed to make one on recompile, " +
			"so either the bump was removed outright or this guard has stopped " +
			"reaching the source it is meant to police.")
	}

	if len(offences) > 0 {
		t.Errorf("BumpFIBGeneration's error is discarded at:\n  %s\n\n"+
			"On the live userspace path this is the only compiler dataplane call "+
			"that is not a shim no-op, so it is the only one that can really fail, "+
			"and (*Manager).BumpFIBGeneration's not-armed branch returns "+
			"ErrDataplaneNotArmed without logging. Dropping it publishes a snapshot "+
			"carrying the PREVIOUS FIB generation — the helper's session.fib_gen "+
			"comparison still matches and established flows keep a next-hop the "+
			"recompile may have just invalidated, with the apply reporting success "+
			"(#7149, #4960).\n\nReport it (see bumpFIBGenerationAfterRecompile); do "+
			"NOT return it — this site runs after compileZones has mutated the host, "+
			"so propagating manufactures the half-applied shape #4960 exists to "+
			"prevent.", strings.Join(offences, "\n  "))
	}
}

func isFIBBumpCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "BumpFIBGeneration"
}

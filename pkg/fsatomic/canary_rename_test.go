package fsatomic

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedRenameFunctions are production functions permitted to keep a bare
// os.Rename with no directory fsync, keyed exactly like allowedFunctions
// (`<pkg-relpath>::[RecvType.]func`, #1916 D1).
//
// Every entry is a case where the namespace change is NOT the durable artifact
// — a staged promotion whose durability is owned elsewhere, or a move whose
// loss is recoverable by construction. A rotation site must never be added
// here: rotation IS the namespace mutation, which is the whole point of #9057.
var allowedRenameFunctions = map[string]string{
	// The fsync is deliberately performed by the CALLER (Journal.Log) with
	// j.mu RELEASED. Doing it here would reintroduce #4829, where a Tail
	// reader blocks for the writer's entire fsync duration — the rename must
	// happen under the lock and the fsync must not. #9057 made that caller-side
	// SyncDir unconditional (it used to sit behind an early return on a
	// file-sync failure), and TestJournalRotateSyncsDirEvenWhenFileSyncFails
	// pins it, which is what keeps this exemption honest.
	"configstore/journal::Journal.maybeRotateLocked": "fsync is in the caller with the lock released (#4829)",
	// A one-shot quarantine move of a corrupt state file, not a generational
	// set. Losing the move across an unclean shutdown re-quarantines on the
	// next read, so the namespace change is not the durable artifact.
	"ddns::quarantineBadState": "one-shot quarantine move, idempotent on retry",
}

// TestNoUnsyncedRename is the #9057 sibling of TestNoDirectOsWriteFile.
//
// # WHY A SECOND CANARY RATHER THAN A WIDER FIRST ONE
//
// The #1894 persistence taxonomy is defined over REPLACE-A-FILE writes, and
// TestNoDirectOsWriteFile enforces exactly that. Rotating a generation set
// (x -> x.1 -> x.2) is a different operation on a different object: it mutates
// the DIRECTORY. Four sites did it by hand and all four omitted the directory
// fsync — not because four authors were careless, but because the operation
// had no row in the taxonomy and no primitive to reach for. Two of the four
// were in no review report at all; they were found by sweeping the OPERATION
// rather than by reading the file a finding pointed at.
//
// # THE RULE, and why it is not a path allowlist
//
// A bare os.Rename is accepted when the enclosing function ALSO reaches a
// durability primitive (fsatomic.SyncDir or fsatomic.RenameDurable). That is
// what a correct rotation looks like: N renames into one directory, then ONE
// SyncDir. Keying on the function's own behaviour rather than on a list of
// blessed paths means the rule cannot rot as files move, and a new rotation
// site is caught the day it is written rather than the day someone sweeps.
//
// The allowlist above exists only for renames whose namespace change is not
// the durable artifact, or where the fsync provably lives elsewhere for a
// stated reason. It is SHORT on purpose: every pkg/upgrade staged-promotion
// rename already calls fsatomic.SyncDir in its own function and therefore
// needs no entry at all. An allowlist that had to name them would have been a
// list of paths to maintain; keying on behaviour means the correct sites pass
// because they are correct.
func TestNoUnsyncedRename(t *testing.T) {
	var violations []string
	scanned, renameSites, allowedHits := 0, 0, 0

	root := ".." // pkg/ (this test lives in pkg/fsatomic)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// fsatomic itself IS the primitive layer.
		if strings.HasPrefix(filepath.ToSlash(path), "../fsatomic/") {
			return nil
		}
		scanned++

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		osName := ""
		for _, imp := range f.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			if ip != "os" {
				continue
			}
			osName = "os"
			if imp.Name != nil {
				osName = imp.Name.Name
				if osName == "." {
					violations = append(violations,
						fmt.Sprintf("%s: dot-import of os defeats the Rename canary", path))
				}
			}
		}
		if osName == "" || osName == "_" || osName == "." {
			return nil
		}

		pkgRel := pkgRelKey(path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var renames []token.Pos
			syncs := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch {
				case pkgIdent.Name == osName && sel.Sel.Name == "Rename":
					renames = append(renames, call.Pos())
				case pkgIdent.Name == "fsatomic" &&
					(sel.Sel.Name == "SyncDir" || sel.Sel.Name == "RenameDurable"):
					syncs = true
				}
				return true
			})
			if len(renames) == 0 {
				continue
			}
			renameSites += len(renames)
			if syncs {
				continue
			}
			if reason, allowed := allowedRenameFunctions[funcKey(pkgRel, fn)]; allowed {
				allowedHits++
				_ = reason
				continue
			}
			for _, pos := range renames {
				violations = append(violations, fmt.Sprintf(
					"%s: bare os.Rename in %s with no fsatomic.SyncDir / RenameDurable "+
						"in the same function", fset.Position(pos), funcKey(pkgRel, fn)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// FIXTURE CHECKS FIRST. An empty sweep, or a sweep that found no renames
	// at all, would report a clean board over a population it never examined —
	// which is the #9052 shape and exactly what this canary is for.
	if scanned == 0 {
		t.Fatal("#9057: the canary scanned ZERO files; it is asserting nothing")
	}
	if renameSites == 0 {
		t.Fatalf("#9057: the canary found NO os.Rename call sites in %d files. "+
			"The tree has them; the matcher or the walk is broken, and a green "+
			"verdict here would be a clean board over an unexamined population.", scanned)
	}
	if allowedHits == 0 {
		t.Errorf("#9057: no allowlist entry matched (%d rename sites over %d files). "+
			"Either the allowlist keys have rotted — a renamed function silently stops "+
			"being exempt AND stops being checked — or every exempt site has been "+
			"fixed and the list should shrink.", renameSites, scanned)
	}
	if len(violations) > 0 {
		t.Errorf("#9057: %d bare os.Rename site(s) with no directory fsync.\n"+
			"A rename is atomic for the ENTRY, but the entry is not durable until the "+
			"containing directory is fsynced. Rotate the generations, then call "+
			"fsatomic.SyncDir(filepath.Dir(path)) ONCE — or use fsatomic.RenameDurable "+
			"for a single rename. If the namespace change is genuinely not the durable "+
			"artifact, add the function to allowedRenameFunctions WITH A REASON.\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

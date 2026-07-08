package config

import (
	"strings"
	"testing"
)

// #4589 A7 F-02: an `archive-sites` URL is passed verbatim to
// `scp <src> <dest>` at transfer-on-commit time. A leading-dash value
// (`-oProxyCommand=...`) is never a valid scp destination and, before the
// `--` end-of-options separator was added to the scp argv, was parsed by
// scp's getopt as an OPTION — CWE-88 argv injection running as the xpfd
// root user. Reject a leading-dash archive-site at commit in BOTH parse
// shapes (flat-set and hierarchical).
//
// RED-on-revert: without the compiler guard the leading-dash site compiles
// clean (CompileConfig returns nil).
func TestArchivalLeadingDashSiteRejectedFlatSet(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		`set system archival configuration transfer-on-commit`,
		`set system archival configuration archive-sites "-oProxyCommand=x"`,
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a leading-dash archive-site; expected rejection")
	}
	if !strings.Contains(err.Error(), "must not begin with '-'") {
		t.Errorf("error %q missing the leading-dash reason", err.Error())
	}
}

func TestArchivalLeadingDashSiteRejectedHierarchical(t *testing.T) {
	input := `
system {
    archival {
        configuration {
            transfer-on-commit;
            archive-sites {
                "-oProxyCommand=x";
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a leading-dash archive-site (hierarchical); expected rejection")
	}
}

// A normal scp URL is still accepted — the guard does not false-positive on
// legitimate archive sites.
func TestArchivalValidSiteAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		`set system archival configuration transfer-on-commit`,
		`set system archival configuration archive-sites "scp://backup@10.0.0.1:/configs"`,
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid archive-site: %v", err)
	}
	if cfg.System.Archival == nil || len(cfg.System.Archival.ArchiveSites) != 1 {
		t.Fatalf("valid archive-site not compiled: %+v", cfg.System.Archival)
	}
}

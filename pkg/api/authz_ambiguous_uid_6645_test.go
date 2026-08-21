package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/osident"
)

// authz_ambiguous_uid_6645_test.go binds the ONE property that made a duplicate
// UID a privilege escalation: the REST gate and the CLI must answer the same
// question about the same caller the same way.
//
// The defect (#6645 MAJOR-1) was a merge interaction, not a coding slip.
// pkg/osident arrived on master with an explicit rule — an ambiguous uid is
// refused, because naming it "whichever passwd row came first" hands
// `system login user admin class super-user` to bob, which is privilege
// escalation BETWEEN TWO LEGITIMATE ACCOUNTS. This PR's REST surface carried
// its own passwd scanner that did exactly that. Neither package was wrong on
// its own terms and both suites were green; nothing compared them, so the
// divergence was invisible.
//
// Measured before the fix, through the production chain below: uid 4242 shared
// by `admin` and `bob`, with only `admin` granted super-user, got
// `POST /api/v1/config/enter` -> 200 and `POST /api/v1/config/set` -> 200
// `{"success":true}`, and the candidate carried the edit. The CLI denied the
// same uid as `unauthorized`.
//
// Both halves are driven from production entry points — real HTTP through
// buildHTTPServer, and cli.ResolveLoginClass on an osident.Identity produced by
// the real resolver — so the test cannot pass by agreeing with a helper that
// re-implements either rule.

// ambiguousUIDPasswd gives ONE uid to two accounts. `useradd -o`, a hand-edited
// passwd file, or a directory service that aliases all produce this.
const ambiguousUIDPasswd = `root:x:0:0:root:/root:/bin/bash
admin:x:4242:4242::/home/admin:/bin/bash
bob:x:4242:4242::/home/bob:/bin/bash
soleuser:x:4250:4250::/home/soleuser:/bin/bash
`

// ambiguousUIDConfig grants super-user to `admin` only. `bob` is not a login
// user at all, which is what makes the first-row answer an escalation rather
// than a mere inaccuracy — and `soleuser` is granted the same class so the
// control below proves the denial is about AMBIGUITY, not about the class.
const ambiguousUIDConfig = `
system {
    host-name authz-ambiguous;
    login {
        user admin {
            class super-user;
        }
        user soleuser {
            class super-user;
        }
    }
}
`

// useAmbiguousPasswd points the SHARED resolver at the fixture. authz's seam
// forwards to osident's, so this moves both surfaces at once — which is itself
// part of the contract: a fixture that moved only one would recreate the split.
func useAmbiguousPasswd(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(ambiguousUIDPasswd), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// TestRESTAndCLIAgreeOnAnAmbiguousUID_6645 is the fail-on-revert binding.
//
// Restoring a first-matching-row scanner in pkg/authz (the pre-#6645 shape)
// turns the ambiguous case RED here — REST admits — while every other case in
// this package stays green, because no other fixture has a duplicate uid.
func TestRESTAndCLIAgreeOnAnAmbiguousUID_6645(t *testing.T) {
	useAmbiguousPasswd(t)

	const ambiguous = 4242
	const unambiguous = 4250

	// --- the CLI's answer, from its production entry point ---
	store := authzStore(t, ambiguousUIDConfig)
	login := store.ActiveConfig().System.Login

	ambiguousID := osident.ForUID(ambiguous)
	if ambiguousID.Resolved() {
		t.Fatalf("osident named an ambiguous uid %q — the whole premise of this test is "+
			"that it refuses to pick between admin and bob", ambiguousID.Name)
	}
	cliClass, cliReason := cli.ResolveLoginClass(login, ambiguousID)
	if cliClass != cli.ClassUnidentified {
		t.Errorf("CLI class for the ambiguous uid = %q, want %q (reason: %s)",
			cliClass, cli.ClassUnidentified, cliReason)
	}

	// --- the REST gate's answer, over real HTTP through buildHTTPServer ---
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        store,
		PeerLookupFn: fixedPeerUID(ambiguous),
	})
	status, errStr := postRoute(t, base, "POST /api/v1/config/enter", nil)
	if status == http.StatusOK {
		t.Fatalf("REST ADMITTED an ambiguous uid: POST /api/v1/config/enter -> 200. "+
			"uid %d is shared by admin and bob; only admin is granted super-user, so "+
			"admitting on the first passwd row hands admin's class to bob — privilege "+
			"escalation between two legitimate accounts. The CLI denied the same caller "+
			"as %q.", ambiguous, cliClass)
	}
	if status != http.StatusForbidden {
		t.Errorf("REST denied for the wrong reason: got %d %q, want 403", status, errStr)
	}

	// --- the property that actually matters: they agree ---
	restDenied := status != http.StatusOK
	cliDenied := cliClass == cli.ClassUnidentified
	if restDenied != cliDenied {
		t.Errorf("the two surfaces DISAGREE on uid %d: REST denied=%v, CLI denied=%v. "+
			"One kernel credential must not mean two different principals depending on "+
			"which interface the operator reached for", ambiguous, restDenied, cliDenied)
	}

	// --- control: the denial is about AMBIGUITY, not about the class ---
	//
	// Without this, "REST refused 4242" is equally explained by "4242 is not a
	// configured login user". soleuser holds the SAME super-user class through
	// the SAME config and the SAME passwd file, differing only in being named
	// by exactly one row — so if this arm also denied, the assertion above
	// would be measuring the wrong thing.
	soleID := osident.ForUID(unambiguous)
	if !soleID.Resolved() || soleID.Name != "soleuser" {
		t.Fatalf("control fixture broken: uid %d resolved to %+v, want soleuser", unambiguous, soleID)
	}
	if class, reason := cli.ResolveLoginClass(login, soleID); class != "super-user" {
		t.Fatalf("control: CLI class for the unambiguous uid = %q, want super-user (%s)", class, reason)
	}
	_, ctrlBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, ambiguousUIDConfig),
		PeerLookupFn: fixedPeerUID(unambiguous),
	})
	if ctrlStatus, ctrlErr := postRoute(t, ctrlBase, "POST /api/v1/config/enter", nil); ctrlStatus != http.StatusOK {
		t.Fatalf("control: REST refused the UNAMBIGUOUS super-user caller (%d %q) — the "+
			"denial above cannot then be attributed to ambiguity", ctrlStatus, ctrlErr)
	}
}

// TestAmbiguousUIDDenialNamesTheRealReason_6645 pins the operator-facing text.
//
// "Permission denied" alone sends an operator to check the login config, where
// they will find a perfectly good `user admin { class super-user; }` and no
// explanation. The refusal is about the passwd database, so the message has to
// say so — this is the one signal that an aliased uid exists at all.
func TestAmbiguousUIDDenialNamesTheRealReason_6645(t *testing.T) {
	useAmbiguousPasswd(t)

	id := osident.ForUID(4242)
	_, reason := cli.ResolveLoginClass(authzStore(t, ambiguousUIDConfig).ActiveConfig().System.Login, id)
	for _, want := range []string{"4242", "more than one"} {
		if !strings.Contains(reason, want) {
			t.Errorf("denial reason %q does not contain %q — an operator cannot tell an "+
				"aliased uid from an unconfigured one", reason, want)
		}
	}
}

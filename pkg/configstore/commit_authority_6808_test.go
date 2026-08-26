package configstore

import (
	"errors"
	"path/filepath"
	"testing"
)

// #6808: the commit paths verified the config-lock holder and then promoted
// through a callback carrying NO identity, so the lock could turn over in
// between and the in-flight commit would promote the NEW holder's candidate
// under the ORIGINAL holder's authorization.
//
// These are the ENFORCEMENT cells — that the store refuses a promotion whose
// authority no longer holds. The WIRING cells (that each transport actually
// mints a bound authority and hands it over) live in pkg/api and pkg/grpcapi,
// because a store that refuses correctly proves nothing if a handler passes
// InternalCommitter() instead.

// authTestStore returns a store in config mode held by sessionID, with one
// staged edit so the candidate is non-empty and a promotion has something to do.
func authTestStore(t *testing.T, sessionID string) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigureSession(sessionID); err != nil {
		t.Fatalf("EnterConfigureSession(%s): %v", sessionID, err)
	}
	if err := s.SetAs(sessionID, []string{"system", "host-name", sessionID + "-host"}); err != nil {
		t.Fatalf("SetAs(%s): %v", sessionID, err)
	}
	return s
}

// hostName reads the committed host-name so a cell can assert WHOSE candidate
// was promoted, not merely that some promotion happened.
func hostName(t *testing.T, s *Store) string {
	t.Helper()
	active := s.ActiveConfig()
	if active == nil {
		return ""
	}
	return active.System.HostName
}

// TestCommitAuthorityZeroValueIsRejected_6808 pins the fail-CLOSED zero value.
//
// The tempting design is to let the zero CommitAuthority mean "internal
// committer, skip the holder check". That puts the god-mode capability at
// exactly the value a forgotten field, a zero-initialised slot, or a
// `CommitAuthority{}` written in good faith already produces — so the explicit
// parameter would catch OMISSION (it would not compile) while silently
// admitting a wrong-but-compiling zero that reads as deliberate in review.
//
// FAIL-ON-REVERT: change verifyCommitAuthorityLocked's `default` arm to return
// nil (i.e. treat an unset authority as a bypass) and this REDS.
func TestCommitAuthorityZeroValueIsRejected_6808(t *testing.T) {
	s := authTestStore(t, "owner")
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}

	_, err = s.CommitWithDescriptionGenAs(CommitAuthority{}, "", gen)
	if !errors.Is(err, ErrCommitAuthorityMissing) {
		t.Errorf("CommitWithDescriptionGenAs(zero authority) = %v, want ErrCommitAuthorityMissing. "+
			"A zero authority means the caller never stated whose authority the commit runs "+
			"under; treating it as an internal committer hands it the bypass (#6808)", err)
	}
	if got := hostName(t, s); got != "" {
		t.Errorf("a zero-authority commit PROMOTED (host-name=%q); it must not mutate store state", got)
	}

	_, err = s.CommitConfirmedGenAs(CommitAuthority{}, 5, gen)
	if !errors.Is(err, ErrCommitAuthorityMissing) {
		t.Errorf("CommitConfirmedGenAs(zero authority) = %v, want ErrCommitAuthorityMissing", err)
	}

	// Paired control: the EXPLICIT internal authority is accepted, on the same
	// store and the same generation. Without it, "reject everything" passes the
	// assertions above — and rejecting every internal commit would break the HA
	// config-sync apply, the event engine, and the local shell.
	if _, err := s.CommitWithDescriptionGenAs(InternalCommitter(), "", gen); err != nil {
		t.Fatalf("CommitWithDescriptionGenAs(InternalCommitter) = %v, want nil — "+
			"an explicit internal committer must still be able to commit", err)
	}
	if got := hostName(t, s); got != "owner-host" {
		t.Errorf("host-name after internal commit = %q, want %q — the control must actually "+
			"reach promotion, or it cannot distinguish 'accepted' from 'never got there'", got, "owner-host")
	}
}

// TestHolderEpochAdvancesOnAcquireAndRelease_6808 pins the epoch itself.
//
// The epoch is what lets a stale authority be detected: the session id alone
// cannot, because the same id can legitimately release and re-acquire, and
// configLockAt is a wall-clock stamp that cannot tell a held lock from a
// re-taken one.
//
// FAIL-ON-REVERT: delete any single `s.holderEpoch++` in store_lock.go and the
// corresponding row REDS.
func TestHolderEpochAdvancesOnAcquireAndRelease_6808(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	step := func(name string, fn func()) uint64 {
		before := s.HolderEpoch()
		fn()
		after := s.HolderEpoch()
		if after == before {
			t.Errorf("%s did not advance the holder epoch (still %d); a commit authorized "+
				"before it would still verify, and the lock changed hands (#6808)", name, before)
		}
		return after
	}

	step("EnterConfigureSession", func() {
		if err := s.EnterConfigureSession("a"); err != nil {
			t.Fatalf("enter: %v", err)
		}
	})
	step("ExitConfigureSession", func() {
		if !s.ExitConfigureSession("a") {
			t.Fatal("exit returned false")
		}
	})
	step("EnterConfigureExclusive", func() {
		if err := s.EnterConfigureExclusive("x"); err != nil {
			t.Fatalf("enter exclusive: %v", err)
		}
	})
	step("ForceExitConfigure", func() { s.ForceExitConfigure() })
	step("re-enter", func() {
		if err := s.EnterConfigureSession("b"); err != nil {
			t.Fatalf("re-enter: %v", err)
		}
	})
	step("ExitConfigure", func() { s.ExitConfigure() })

	// Control: a SAME-SESSION re-entry is not a turnover — the lock never left
	// that session — so it must NOT advance the epoch and must not invalidate an
	// authority already minted for it. Without this row, "bump on every call"
	// passes every row above while needlessly failing a legitimate re-entrant
	// commit.
	if err := s.EnterConfigureSession("c"); err != nil {
		t.Fatalf("enter c: %v", err)
	}
	before := s.HolderEpoch()
	if err := s.EnterConfigureSession("c"); err != nil {
		t.Fatalf("re-enter c: %v", err)
	}
	if got := s.HolderEpoch(); got != before {
		t.Errorf("same-session re-entry advanced the holder epoch (%d -> %d); the lock did "+
			"not change hands, so an authority minted for that session must stay valid", before, got)
	}
}

// TestCommitRefusedAfterHolderTurnover_6808 is the core cell: the exact
// substitution R69 describes, driven through the store.
//
// Session A is authorized to commit. Before the promotion lands, the lock turns
// over — A releases (explicitly, or by disconnect, or by idle-lease reclaim) and
// B enters and stages DIFFERENT work. A's promotion must be REFUSED, and B's
// host-name must not become active under A's authorization.
//
// The fixture stages a distinguishable edit per session deliberately: asserting
// only "an error came back" would pass against a store that refuses everything,
// and asserting only "something was promoted" cannot tell A's work from B's.
//
// FAIL-ON-REVERT: delete the verifyCommitAuthorityLocked call from
// CommitWithDescriptionGenAs and this REDS — the generation check alone accepts
// the promotion, because after the turnover the generation is perfectly
// consistent; it just describes B's candidate.
func TestCommitRefusedAfterHolderTurnover_6808(t *testing.T) {
	s := authTestStore(t, "sessionA")

	authority, err := s.AuthorizeCommit("sessionA")
	if err != nil {
		t.Fatalf("AuthorizeCommit(sessionA): %v", err)
	}

	// --- the turnover, in the window between authorization and promotion ---
	if !s.ExitConfigureSession("sessionA") {
		t.Fatal("ExitConfigureSession(sessionA) returned false")
	}
	if err := s.EnterConfigureSession("sessionB"); err != nil {
		t.Fatalf("EnterConfigureSession(sessionB): %v", err)
	}
	if err := s.SetAs("sessionB", []string{"system", "host-name", "sessionB-host"}); err != nil {
		t.Fatalf("SetAs(sessionB): %v", err)
	}

	// A now snapshots and promotes, exactly as the daemon would.
	_, gen, cerr := s.CompileCandidateGen()
	if cerr != nil {
		t.Fatalf("CompileCandidateGen: %v", cerr)
	}
	_, err = s.CommitWithDescriptionGenAs(authority, "", gen)

	if !errors.Is(err, ErrConfigHolderTurnover) {
		t.Fatalf("commit after holder turnover = %v, want ErrConfigHolderTurnover. "+
			"Session A's authorization promoted session B's candidate — the substitution "+
			"#6808 closes", err)
	}
	if got := hostName(t, s); got == "sessionB-host" {
		t.Fatalf("session B's candidate was PROMOTED under session A's authority "+
			"(host-name=%q)", got)
	}
	if got := hostName(t, s); got != "" {
		t.Fatalf("host-name = %q, want empty: a refused commit must not promote anything", got)
	}
}

// TestTurnoverSentinelIsNotGenerationConflict_6808 pins the two sentinels apart.
//
// This matters more than it looks. The daemon's commitWithGenBinding RETRIES on
// ErrCandidateGenerationConflict by design — it re-snapshots and re-promotes
// against the fresh generation. If a holder turnover were reported as a
// generation conflict, that retry would re-snapshot the NEW holder's candidate
// and promote it under the OLD holder's authority: the retry loop would perform
// the substitution automatically, on every turnover, with no race needed.
//
// FAIL-ON-REVERT: make verifyCommitAuthorityLocked return a wrapped
// ErrCandidateGenerationConflict and this REDS.
func TestTurnoverSentinelIsNotGenerationConflict_6808(t *testing.T) {
	s := authTestStore(t, "sessionA")
	authority, err := s.AuthorizeCommit("sessionA")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	if !s.ExitConfigureSession("sessionA") {
		t.Fatal("exit returned false")
	}
	if err := s.EnterConfigureSession("sessionB"); err != nil {
		t.Fatalf("enter B: %v", err)
	}
	_, gen, _ := s.CompileCandidateGen()

	_, err = s.CommitWithDescriptionGenAs(authority, "", gen)
	if !errors.Is(err, ErrConfigHolderTurnover) {
		t.Fatalf("want ErrConfigHolderTurnover, got %v", err)
	}
	if errors.Is(err, ErrCandidateGenerationConflict) {
		t.Error("a holder turnover is reported as a candidate-GENERATION conflict. " +
			"commitWithGenBinding retries that sentinel by design, so the retry would " +
			"re-snapshot and promote the NEW holder's candidate under the OLD holder's " +
			"authority — the retry loop would automate the substitution (#6808)")
	}
}

// TestCommitConfirmedRefusedAfterHolderTurnover_6808 is the commit-confirmed
// half. It is the higher-consequence one: a substituted commit-confirmed both
// applies work its author never approved AND arms an auto-rollback timer against
// it, so the authorized operator is left with a revert pending that they did not
// schedule.
//
// FAIL-ON-REVERT: delete the verifyCommitAuthorityLocked call from
// CommitConfirmedGenAs and this REDS. It is a SEPARATE cell from the plain-commit
// one deliberately — the two entry points have independent checks, and a single
// cell covering only one would report the other as guarded when it is not.
func TestCommitConfirmedRefusedAfterHolderTurnover_6808(t *testing.T) {
	s := authTestStore(t, "sessionA")
	authority, err := s.AuthorizeCommit("sessionA")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	if !s.ExitConfigureSession("sessionA") {
		t.Fatal("exit returned false")
	}
	if err := s.EnterConfigureSession("sessionB"); err != nil {
		t.Fatalf("enter B: %v", err)
	}
	if err := s.SetAs("sessionB", []string{"system", "host-name", "sessionB-host"}); err != nil {
		t.Fatalf("SetAs(B): %v", err)
	}
	_, gen, _ := s.CompileCandidateGen()

	_, err = s.CommitConfirmedGenAs(authority, 5, gen)
	if !errors.Is(err, ErrConfigHolderTurnover) {
		t.Fatalf("commit-confirmed after turnover = %v, want ErrConfigHolderTurnover", err)
	}
	if s.IsConfirmPending() {
		t.Error("a REFUSED commit-confirmed armed the auto-rollback timer; the operator " +
			"now has a revert pending against a commit that never happened (#6808)")
	}
	if got := hostName(t, s); got == "sessionB-host" {
		t.Fatalf("session B's candidate was promoted+armed under session A's authority")
	}
}

// TestUnchangedHolderStillCommits_6808 is the control the whole set depends on:
// a commit whose holder has NOT turned over must still succeed, through the
// authority-bound entry points, and must actually PROMOTE.
//
// Without it, "refuse every authority" satisfies every refusal cell above — and
// refusing every commit is a total configuration outage, a far worse failure
// than the one being fixed. The host-name assertion is what makes it real: a
// control that only checked `err == nil` would pass against a fixture that never
// reached promotion at all.
func TestUnchangedHolderStillCommits_6808(t *testing.T) {
	s := authTestStore(t, "sessionA")
	authority, err := s.AuthorizeCommit("sessionA")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	if authority.IsInternal() {
		t.Fatal("the holder's authority came back INTERNAL; it would then satisfy every " +
			"turnover check and this control would pass without testing anything")
	}
	_, gen, cerr := s.CompileCandidateGen()
	if cerr != nil {
		t.Fatalf("CompileCandidateGen: %v", cerr)
	}
	if _, err := s.CommitWithDescriptionGenAs(authority, "", gen); err != nil {
		t.Fatalf("commit with an UNCHANGED holder = %v, want nil — the fix must not "+
			"refuse legitimate commits", err)
	}
	if got := hostName(t, s); got != "sessionA-host" {
		t.Fatalf("host-name after the control commit = %q, want %q — the control must reach "+
			"promotion, or it cannot tell 'accepted' from 'never got there'", got, "sessionA-host")
	}
}

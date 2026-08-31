package configstore

import "testing"

// #7635: every path that LEAVES config mode must clear BOTH holder fields.
//
// ExitConfigure cleared only exclusiveHolder, so a shared-mode lock taken by
// EnterConfigureSession("X") left configHolder == "X" behind after the exit,
// and the public ConfigHolder() accessor reported that stale string. Its three
// siblings — ExitConfigureSession, ForceExitConfigure and the
// reclaimStaleLockLocked re-acquire — all clear both, so they are the
// specification and this test binds ExitConfigure to it.
//
// THE FIXTURE IS THE POINT, so it is spelled out rather than left implicit.
// The state that makes the bug observable is a NON-EMPTY configHolder, and only
// EnterConfigureSession with a non-empty session id produces one. A fixture
// built on EnterConfigure() — the unsessioned local path, which is what every
// in-tree caller of ExitConfigure actually pairs with — sets configHolder to ""
// on the way IN, so the post-exit assertion reads "" whether or not the fix is
// present and the cell passes vacuously. That is why each row below enters with
// a session id and asserts the entered state first: the control line proves the
// fixture reached the state under test, so a green result means the clear
// happened rather than that the field was never dirty.
//
// The assertion is on the PUBLIC ConfigHolder() rather than on the private
// field, because that accessor is where the staleness escaped the package. Its
// three consumers (pkg/cli/cli_clear.go, pkg/api/system.go,
// pkg/grpcapi/server_diag_system_action.go) each check the returned locked bool
// first and so never rendered the stale name — the leak was latent, not
// operator-visible — but that is a property of today's callers, not of the
// accessor's contract.
//
// FAIL-ON-REVERT: delete `s.configHolder = ""` from any of the exits below and
// that row goes RED with the stale holder in the message.
func TestEveryConfigModeExitClearsBothHolders_7635(t *testing.T) {
	const holder = "session-A"

	cases := []struct {
		name string
		exit func(t *testing.T, s *Store)
	}{
		{
			name: "ExitConfigure",
			exit: func(t *testing.T, s *Store) { s.ExitConfigure() },
		},
		{
			name: "ExitConfigureSession",
			exit: func(t *testing.T, s *Store) {
				if !s.ExitConfigureSession(holder) {
					t.Fatal("ExitConfigureSession returned false; the fixture never left config mode")
				}
			},
		},
		{
			name: "ForceExitConfigure",
			exit: func(t *testing.T, s *Store) { s.ForceExitConfigure() },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)

			// Enter with a NON-EMPTY session id: this is what dirties
			// configHolder. Without it the whole cell is vacuous.
			if err := s.EnterConfigureSession(holder); err != nil {
				t.Fatalf("EnterConfigureSession(%q): %v", holder, err)
			}

			// Control: the fixture actually reached the state under test.
			if got, locked := s.ConfigHolder(); !locked || got != holder {
				t.Fatalf("after enter, ConfigHolder() = (%q, %v), want (%q, true); "+
					"the fixture did not reach a dirty-holder state, so the "+
					"post-exit assertion below would pass vacuously", got, locked, holder)
			}

			tc.exit(t, s)

			if got, locked := s.ConfigHolder(); got != "" || locked {
				t.Fatalf("after %s, ConfigHolder() = (%q, %v), want (\"\", false); "+
					"a holder field survived the exit", tc.name, got, locked)
			}
		})
	}
}

// TestExitConfigureClearsHolderAfterExclusiveEnter_7635 covers the other enter
// shape. EnterConfigureExclusive records the holder in exclusiveHolder and
// leaves configHolder empty (#3979), so this row would pass even before the
// fix — it is here as the paired control that keeps the sibling row above
// honest: it proves ConfigHolder() reports "" after an exit for a reason other
// than the one under test, so the two rows together distinguish "the clear
// works" from "this accessor always returns empty after an exit".
func TestExitConfigureClearsHolderAfterExclusiveEnter_7635(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigureExclusive("session-B"); err != nil {
		t.Fatalf("EnterConfigureExclusive: %v", err)
	}
	if got, locked := s.ConfigHolder(); !locked || got != "session-B" {
		t.Fatalf("after exclusive enter, ConfigHolder() = (%q, %v), want (\"session-B\", true)", got, locked)
	}
	s.ExitConfigure()
	if got, locked := s.ConfigHolder(); got != "" || locked {
		t.Fatalf("after ExitConfigure, ConfigHolder() = (%q, %v), want (\"\", false)", got, locked)
	}
}

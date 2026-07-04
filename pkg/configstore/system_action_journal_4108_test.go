package configstore

import "testing"

// TestLogSystemAction_WritesJournalEntry pins #4108 F8: a destructive
// maintenance verb (reboot/halt/power-off/zeroize) writes a fsynced
// `system_action` audit entry to the commit journal, so a durable,
// attributable record survives even when the action wipes the config or takes
// the box down. RED on revert: making Store.LogSystemAction a no-op (or
// dropping the s.logSystemAction call in the SystemAction handler) leaves the
// journal empty and this test fails.
func TestLogSystemAction_WritesJournalEntry(t *testing.T) {
	s := newTestStore(t)

	for _, action := range []string{"reboot", "halt", "power-off", "zeroize"} {
		s.LogSystemAction(action)
	}

	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatalf("journal.Tail: %v", err)
	}

	got := map[string]bool{}
	for _, e := range entries {
		if e.Action != "system_action" {
			continue
		}
		if e.Timestamp.IsZero() {
			t.Errorf("system_action entry %q has zero timestamp (want stamped)", e.Detail)
		}
		got[e.Detail] = true
	}

	for _, action := range []string{"reboot", "halt", "power-off", "zeroize"} {
		if !got[action] {
			t.Errorf("no system_action journal entry for %q (want one)", action)
		}
	}
}

// TestLogSystemAction_ExcludedFromCommitHistory asserts the maintenance record
// does NOT leak into `show system commit` (ListCommitHistory), which filters to
// commit/commit_confirmed/auto_rollback — a reboot is not a config commit, so
// journaling it must not pollute the commit history view.
func TestLogSystemAction_ExcludedFromCommitHistory(t *testing.T) {
	s := newTestStore(t)
	s.LogSystemAction("zeroize")

	commits, err := s.ListCommitHistory(0)
	if err != nil {
		t.Fatalf("ListCommitHistory: %v", err)
	}
	for _, e := range commits {
		if e.Action == "system_action" {
			t.Fatalf("system_action leaked into ListCommitHistory (%q)", e.Detail)
		}
	}
}

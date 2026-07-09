package configstore

import "testing"

// #4868: the store bounds the commit-confirmed window so
// `time.Duration(minutes)*time.Minute` cannot overflow int64 nanoseconds into
// a wrapped/negative deadline that fires an immediate/wrong auto-rollback after
// the candidate has already been promoted. An over-max value is rejected with
// no promotion / no armed timer; the max boundary is accepted.
func TestCommitConfirmedRejectsOverMax_4868(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CommitConfirmed(MaxCommitConfirmedMinutes + 1); err == nil {
		t.Fatalf("CommitConfirmed(%d) accepted; want rejection over max %d",
			MaxCommitConfirmedMinutes+1, MaxCommitConfirmedMinutes)
	}
	if s.IsConfirmPending() {
		t.Fatal("an over-max CommitConfirmed must NOT arm a confirm window")
	}
	if !s.IsDirty() {
		t.Fatal("an over-max CommitConfirmed must NOT promote the candidate")
	}

	// The max boundary is accepted.
	if _, err := s.CommitConfirmed(MaxCommitConfirmedMinutes); err != nil {
		t.Fatalf("CommitConfirmed(%d) at the max boundary should succeed: %v",
			MaxCommitConfirmedMinutes, err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("a max-boundary CommitConfirmed should arm a confirm window")
	}
}

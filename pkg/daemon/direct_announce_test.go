package daemon

import (
	"testing"
	"time"
)

func TestScheduleDirectAnnounceRepeatsWhileRGActive(t *testing.T) {
	state := newRGStateMachine()
	state.SetCluster(true)
	d := &Daemon{
		rgStates:               map[int]*rgStateMachine{1: state},
		directAnnounceSchedule: []time.Duration{0, 5 * time.Millisecond, 15 * time.Millisecond},
	}

	calls := make(chan int, 8)
	d.directSendGARPsFn = func(rgID int) {
		calls <- rgID
	}

	d.scheduleDirectAnnounce(1, "test")

	deadline := time.After(250 * time.Millisecond)
	seen := 0
	for seen < 3 {
		select {
		case rgID := <-calls:
			if rgID != 1 {
				t.Fatalf("unexpected rg id: %d", rgID)
			}
			seen++
		case <-deadline:
			t.Fatalf("timed out waiting for announce burst %d", seen+1)
		}
	}
}

func TestScheduleDirectAnnounceSendsImmediateBurstInline(t *testing.T) {
	state := newRGStateMachine()
	state.SetCluster(true)
	d := &Daemon{
		rgStates:               map[int]*rgStateMachine{1: state},
		directAnnounceSchedule: []time.Duration{0, 25 * time.Millisecond},
	}

	calls := make(chan int, 4)
	d.directSendGARPsFn = func(rgID int) {
		calls <- rgID
	}

	d.scheduleDirectAnnounce(1, "test")

	select {
	case rgID := <-calls:
		if rgID != 1 {
			t.Fatalf("unexpected rg id: %d", rgID)
		}
	default:
		t.Fatal("expected immediate announce burst before scheduleDirectAnnounce returns")
	}
}

func TestCancelDirectAnnounceStopsFutureBursts(t *testing.T) {
	state := newRGStateMachine()
	state.SetCluster(true)
	d := &Daemon{
		rgStates:               map[int]*rgStateMachine{1: state},
		directAnnounceSchedule: []time.Duration{0, 30 * time.Millisecond, 60 * time.Millisecond},
	}

	calls := make(chan int, 8)
	d.directSendGARPsFn = func(rgID int) {
		calls <- rgID
	}

	d.scheduleDirectAnnounce(1, "test")

	select {
	case <-calls:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for first announce burst")
	}

	d.cancelDirectAnnounce(1)

	select {
	case rgID := <-calls:
		t.Fatalf("unexpected extra announce after cancel for rg %d", rgID)
	case <-time.After(120 * time.Millisecond):
	}
}

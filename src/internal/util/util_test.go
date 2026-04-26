package util

import (
	"testing"
	"time"
)

func TestFailureTracker_TripsAtThreshold(t *testing.T) {
	tr := NewFailureTracker(3, time.Minute)
	now := time.Now()

	if tripped := tr.Record(now); tripped {
		t.Fatalf("first failure should not trip")
	}
	if tripped := tr.Record(now.Add(1 * time.Second)); tripped {
		t.Fatalf("second failure should not trip")
	}
	if tripped := tr.Record(now.Add(2 * time.Second)); !tripped {
		t.Fatalf("third failure within window should trip")
	}
}

func TestFailureTracker_ResetsAfterTrip(t *testing.T) {
	tr := NewFailureTracker(2, time.Minute)
	now := time.Now()

	_ = tr.Record(now)
	if tripped := tr.Record(now); !tripped {
		t.Fatalf("expected trip on second failure")
	}
	// Subsequent failure is the start of a new window — should not trip again
	// until threshold is reached anew.
	if tripped := tr.Record(now.Add(time.Second)); tripped {
		t.Fatalf("post-trip first failure must not re-trip")
	}
}

func TestFailureTracker_SlidingWindow(t *testing.T) {
	tr := NewFailureTracker(3, 10*time.Second)
	t0 := time.Now()

	// Two failures, then long gap, then one — should NOT trip because the
	// first two are outside the window when the third arrives.
	_ = tr.Record(t0)
	_ = tr.Record(t0.Add(1 * time.Second))
	if tripped := tr.Record(t0.Add(60 * time.Second)); tripped {
		t.Fatalf("failures outside the window must not be counted")
	}
}

func TestFailureTracker_ResetClearsState(t *testing.T) {
	tr := NewFailureTracker(2, time.Minute)
	now := time.Now()

	_ = tr.Record(now)
	tr.Reset()
	// After Reset, a single failure must not trip.
	if tripped := tr.Record(now.Add(time.Second)); tripped {
		t.Fatalf("Reset must drop earlier failures")
	}
}

func TestFailureTracker_ThresholdOneIsFailFast(t *testing.T) {
	tr := NewFailureTracker(1, time.Minute)
	if tripped := tr.Record(time.Now()); !tripped {
		t.Fatalf("threshold=1 must trip immediately (legacy behaviour)")
	}
}

<!-- docdaemon ts:2026-10-09T01:40:21Z hash:21faa033a3830551 model:openrouter/qwen/qwen3.7-flash -->
## TL;DR
This file contains unit tests for the `FailureTracker` type, verifying its sliding window logic, reset behavior, and threshold triggering.

## Purpose
The `util_test.go` file ensures the reliability of the failure tracking mechanism used to detect repeated errors within a specific time window. It validates that the tracker correctly counts failures, resets state, and respects the configured threshold.

## Key Test Scenarios

### Threshold Triggering
- **`TestFailureTracker_TripsAtThreshold`**: Verifies that the tracker trips exactly when the number of recorded failures reaches the configured limit within the time window.
- **`TestFailureTracker_ThresholdOneIsFailFast`**: Confirms that a threshold of 1 causes an immediate trip on the first failure.

### State Management
- **`TestFailureTracker_ResetsAfterTrip`**: Ensures that after tripping, subsequent failures start a new counting window rather than immediately re-tripping.
- **`TestFailureTracker_ResetClearsState`**: Validates that calling `Reset()` clears all internal state, allowing fresh counting from zero.

### Sliding Window Logic
- **`TestFailureTracker_SlidingWindow`**: Checks that failures occurring outside the current time window are not counted towards the threshold, ensuring only recent failures trigger alerts.
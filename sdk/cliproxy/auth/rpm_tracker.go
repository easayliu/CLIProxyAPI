package auth

import (
	"sync"
	"time"
)

// GlobalRPMTracker is the package-level RPM tracker shared between the selector
// (for load-aware auth picking) and the executor (for rate limit enforcement).
var GlobalRPMTracker = &RPMTracker{
	requests: make(map[string][]time.Time),
}

// RPMTracker tracks per-auth request timestamps in a sliding window.
type RPMTracker struct {
	mu       sync.Mutex
	requests map[string][]time.Time // authID -> timestamps within the last minute
}

// Record registers a request for the given auth at the current time.
func (t *RPMTracker) Record(authID string) {
	if authID == "" {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requests[authID] = append(t.pruned(authID, now), now)
}

// CurrentRPM returns the number of requests made by the given auth in the last minute.
func (t *RPMTracker) CurrentRPM(authID string) int {
	if authID == "" {
		return 0
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	valid := t.pruned(authID, now)
	t.requests[authID] = valid
	return len(valid)
}

// WaitForSlot blocks until the auth's RPM drops below the given limit.
// Returns false if the context-derived timeout expires before a slot opens.
// The caller should pass a deadline-bounded context or maxWait duration.
func (t *RPMTracker) WaitForSlot(authID string, limit int, maxWait time.Duration) bool {
	if authID == "" || limit <= 0 {
		return true
	}
	deadline := time.Now().Add(maxWait)
	for {
		now := time.Now()
		if now.After(deadline) {
			return false
		}

		t.mu.Lock()
		valid := t.pruned(authID, now)
		t.requests[authID] = valid
		count := len(valid)
		var waitDur time.Duration
		if count >= limit && len(valid) > 0 {
			// Wait until the oldest request falls out of the 1-minute window.
			waitDur = valid[0].Add(time.Minute).Sub(now)
			if waitDur < 10*time.Millisecond {
				waitDur = 10 * time.Millisecond
			}
		}
		t.mu.Unlock()

		if count < limit {
			return true
		}

		// Cap wait to remaining deadline.
		remaining := time.Until(deadline)
		if waitDur > remaining {
			waitDur = remaining
		}
		if waitDur <= 0 {
			return false
		}
		time.Sleep(waitDur)
	}
}

// pruned returns only timestamps within the last minute. Must be called with t.mu held.
func (t *RPMTracker) pruned(authID string, now time.Time) []time.Time {
	cutoff := now.Add(-time.Minute)
	timestamps := t.requests[authID]
	// Find the first timestamp that is within the window via linear scan.
	// Timestamps are appended in order so we can skip from the front.
	start := 0
	for start < len(timestamps) && !timestamps[start].After(cutoff) {
		start++
	}
	if start == 0 {
		return timestamps
	}
	if start >= len(timestamps) {
		delete(t.requests, authID)
		return nil
	}
	// Compact: copy valid entries to the front to reduce allocation over time.
	valid := make([]time.Time, len(timestamps)-start)
	copy(valid, timestamps[start:])
	return valid
}

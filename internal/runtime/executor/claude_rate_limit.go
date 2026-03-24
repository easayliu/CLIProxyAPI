package executor

import (
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	// rpmWaitTimeout is the maximum time to block waiting for an RPM slot.
	// Claude Code streaming requests can be long-lived, so 30s is reasonable
	// for the client to wait before we give up.
	rpmWaitTimeout = 30 * time.Second
)

// checkClaudeRateLimit enforces per-auth RPM (requests per minute) limit.
// Instead of returning 429 (which triggers cooldown cascades in the conductor),
// it blocks until a slot opens within the sliding window.
// Returns nil when the request may proceed, or a context-style error on timeout.
//
// The request is recorded in the global RPM tracker so that the RPM-aware
// selector can see real-time load when picking the next auth.
func checkClaudeRateLimit(auth *cliproxyauth.Auth) error {
	if auth == nil {
		return nil
	}

	authID := auth.EnsureIndex()
	if authID == "" {
		return nil
	}

	rpm := auth.RPMLimit()
	if rpm <= 0 {
		// No explicit RPM limit configured — still record for selector awareness.
		cliproxyauth.GlobalRPMTracker.Record(authID)
		return nil
	}

	// Block until a slot opens (or timeout).
	if !cliproxyauth.GlobalRPMTracker.WaitForSlot(authID, rpm, rpmWaitTimeout) {
		log.Warnf("claude rate limit: auth %s still at %d rpm after %s wait, proceeding anyway", authID, rpm, rpmWaitTimeout)
		// Proceed anyway instead of returning 429 — let upstream decide.
		// This avoids triggering the conductor cooldown spiral that causes
		// cascading account bans.
	}

	// Record this request.
	cliproxyauth.GlobalRPMTracker.Record(authID)
	return nil
}

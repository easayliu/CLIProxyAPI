package executor

import (
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	// defaultRPM is the default RPM limit per auth when not configured.
	// A real CLI user averages ~0.5 RPM with bursts up to 4-6 during retries.
	// Setting 2 allows normal usage while preventing detectable high-frequency patterns.
	// Override via auth file metadata "rpm" for higher throughput.
	defaultRPM = 2
)

// checkClaudeRateLimit enforces per-auth RPM (requests per minute) limit.
// Defaults to 2 RPM when not configured, matching real CLI usage patterns.
// Returns 429 immediately when exceeded so the conductor can failover
// to the next auth without delay.
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
		rpm = defaultRPM
	}

	// Non-blocking check: if at limit, return 429 immediately for fast failover.
	// Use 1ms timeout to allow a single check iteration without actual waiting.
	if !cliproxyauth.GlobalRPMTracker.WaitForSlot(authID, rpm, time.Millisecond) {
		log.Debugf("claude rate limit: auth %s at %d rpm, failing over", authID, rpm)
		return statusErr{code: 429, msg: "rate limit exceeded for this auth"}
	}

	cliproxyauth.GlobalRPMTracker.Record(authID)
	return nil
}

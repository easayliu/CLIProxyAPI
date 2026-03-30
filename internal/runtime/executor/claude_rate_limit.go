package executor

import (
	"fmt"
	"math"
	"net/http"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	// defaultRPM is the default RPM limit per auth when not configured.
	// Override via auth file metadata "rpm" for custom throughput.
	defaultRPM = 10
)

// checkClaudeRateLimit enforces per-auth RPM (requests per minute) limit and
// upstream error cooldown. If the auth is in a cooldown period (set after a
// 500/502/503/504 upstream error), returns 503 immediately so the client backs
// off instead of hammering the upstream again.
func checkClaudeRateLimit(auth *cliproxyauth.Auth) error {
	if auth == nil {
		return nil
	}

	authID := auth.EnsureIndex()
	if authID == "" {
		return nil
	}

	// Check auth-level cooldown (set after upstream 5xx errors).
	now := time.Now()
	if !auth.NextRetryAfter.IsZero() && auth.NextRetryAfter.After(now) {
		retryIn := int(math.Ceil(auth.NextRetryAfter.Sub(now).Seconds()))
		log.Debugf("claude rate limit: auth %s in cooldown, retry in %ds", authID, retryIn)
		return &upstreamCooldownErr{retryAfterSeconds: retryIn}
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

// upstreamCooldownErr is returned when the auth is in a post-5xx cooldown period.
// It surfaces as 503 to the client with a Retry-After header.
type upstreamCooldownErr struct {
	retryAfterSeconds int
}

func (e *upstreamCooldownErr) Error() string {
	return fmt.Sprintf("upstream error cooldown, retry after %ds", e.retryAfterSeconds)
}

func (e *upstreamCooldownErr) StatusCode() int {
	return http.StatusServiceUnavailable
}

func (e *upstreamCooldownErr) Headers() http.Header {
	h := make(http.Header)
	h.Set("Retry-After", fmt.Sprintf("%d", e.retryAfterSeconds))
	return h
}

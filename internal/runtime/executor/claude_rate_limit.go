package executor

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// claudeRateLimiter tracks request timestamps per auth for RPM limiting.
var claudeRateLimiter = struct {
	sync.Mutex
	requests map[string][]time.Time // authID -> request timestamps
}{
	requests: make(map[string][]time.Time),
}

// checkClaudeRateLimit enforces per-auth RPM (requests per minute) limit.
// The RPM value is read from auth metadata ("rpm" or "rpm_limit").
// Returns nil if allowed, or a statusErr with 429 and retryAfter if rate limited.
func checkClaudeRateLimit(auth *cliproxyauth.Auth) error {
	if auth == nil {
		return nil
	}

	rpm := auth.RPMLimit()
	if rpm <= 0 {
		return nil
	}

	authID := auth.EnsureIndex()
	if authID == "" {
		return nil
	}

	now := time.Now()
	windowStart := now.Add(-time.Minute)

	claudeRateLimiter.Lock()
	defer claudeRateLimiter.Unlock()

	// Filter timestamps within the sliding window
	timestamps := claudeRateLimiter.requests[authID]
	var valid []time.Time
	for _, ts := range timestamps {
		if ts.After(windowStart) {
			valid = append(valid, ts)
		}
	}

	// Prune empty entries
	if len(valid) == 0 {
		delete(claudeRateLimiter.requests, authID)
	}

	// Check if limit exceeded
	if len(valid) >= rpm {
		oldest := valid[0]
		retryAfter := oldest.Add(time.Minute).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		retryAfterSec := int(retryAfter.Seconds())
		log.Debugf("claude rate limit: auth %s exceeded %d rpm, retry after %ds", authID, rpm, retryAfterSec)
		return statusErr{
			code:       http.StatusTooManyRequests,
			msg:        fmt.Sprintf(`{"type":"error","error":{"type":"rate_limit_error","message":"Rate limit exceeded: %d requests/minute, retry after %ds"}}`, rpm, retryAfterSec),
			retryAfter: &retryAfter,
		}
	}

	// Record this request
	valid = append(valid, now)
	claudeRateLimiter.requests[authID] = valid
	return nil
}

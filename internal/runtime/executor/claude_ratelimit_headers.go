package executor

import (
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// updateAuthRateLimit extracts Anthropic unified rate limit headers from the
// upstream response and updates the auth's RateLimit state in-place.
// Safe to call with nil auth or empty headers.
func updateAuthRateLimit(auth *cliproxyauth.Auth, headers http.Header) {
	if auth == nil || headers == nil {
		return
	}

	// Only update if we see at least one rate limit header.
	if headers.Get("Anthropic-Ratelimit-Unified-Status") == "" {
		return
	}

	rl := cliproxyauth.RateLimitState{
		OrganizationID:        headers.Get("Anthropic-Organization-Id"),
		FiveHourUtilization:   parseFloat(headers.Get("Anthropic-Ratelimit-Unified-5h-Utilization")),
		FiveHourStatus:        headers.Get("Anthropic-Ratelimit-Unified-5h-Status"),
		FiveHourReset:         parseInt(headers.Get("Anthropic-Ratelimit-Unified-5h-Reset")),
		SevenDayUtilization:   parseFloat(headers.Get("Anthropic-Ratelimit-Unified-7d-Utilization")),
		SevenDayStatus:        headers.Get("Anthropic-Ratelimit-Unified-7d-Status"),
		SevenDayReset:         parseInt(headers.Get("Anthropic-Ratelimit-Unified-7d-Reset")),
		UnifiedStatus:         headers.Get("Anthropic-Ratelimit-Unified-Status"),
		UnifiedReset:          parseInt(headers.Get("Anthropic-Ratelimit-Unified-Reset")),
		RepresentativeClaim:   headers.Get("Anthropic-Ratelimit-Unified-Representative-Claim"),
		FallbackPercentage:    parseFloat(headers.Get("Anthropic-Ratelimit-Unified-Fallback-Percentage")),
		OverageStatus:         headers.Get("Anthropic-Ratelimit-Unified-Overage-Status"),
		OverageDisabledReason: headers.Get("Anthropic-Ratelimit-Unified-Overage-Disabled-Reason"),
		UpdatedAt:             time.Now(),
	}

	auth.RateLimit = rl

	log.Infof("[rate-limit] auth=%.16s org=%s 5h=%.2f%% (%s) 7d=%.2f%% (%s) unified=%s claim=%s",
		auth.ID, rl.OrganizationID,
		rl.FiveHourUtilization*100, rl.FiveHourStatus,
		rl.SevenDayUtilization*100, rl.SevenDayStatus,
		rl.UnifiedStatus, rl.RepresentativeClaim)
}

func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func parseInt(s string) int64 {
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

package executor

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// RateLimitSnapshot is a point-in-time rate limit state for one auth.
type RateLimitSnapshot struct {
	AuthID                string  `json:"auth_id"`
	OrganizationID        string  `json:"organization_id,omitempty"`
	FiveHourUtilization   float64 `json:"five_hour_utilization"`
	FiveHourStatus        string  `json:"five_hour_status,omitempty"`
	FiveHourReset         int64   `json:"five_hour_reset,omitempty"`
	SevenDayUtilization   float64 `json:"seven_day_utilization"`
	SevenDayStatus        string  `json:"seven_day_status,omitempty"`
	SevenDayReset         int64   `json:"seven_day_reset,omitempty"`
	UnifiedStatus         string  `json:"unified_status,omitempty"`
	UnifiedReset          int64   `json:"unified_reset,omitempty"`
	RepresentativeClaim   string  `json:"representative_claim,omitempty"`
	FallbackPercentage    float64 `json:"fallback_percentage,omitempty"`
	OverageStatus         string  `json:"overage_status,omitempty"`
	OverageDisabledReason string  `json:"overage_disabled_reason,omitempty"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// rateLimitStore is an in-memory store keyed by auth ID.
var (
	rateLimitStore   = make(map[string]*RateLimitSnapshot)
	rateLimitStoreMu sync.RWMutex
)

// updateAuthRateLimit extracts Anthropic unified rate limit headers from the
// upstream response and stores them in memory keyed by auth ID.
// Safe to call with nil auth or empty headers.
func updateAuthRateLimit(auth *cliproxyauth.Auth, headers http.Header) {
	if auth == nil || headers == nil {
		return
	}

	// Only update if we see at least one rate limit header.
	if headers.Get("Anthropic-Ratelimit-Unified-Status") == "" {
		return
	}

	rl := &RateLimitSnapshot{
		AuthID:                auth.ID,
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

	rateLimitStoreMu.Lock()
	rateLimitStore[auth.ID] = rl
	rateLimitStoreMu.Unlock()

	log.Infof("[rate-limit] auth=%.16s org=%s 5h=%.2f%% (%s) 7d=%.2f%% (%s) unified=%s claim=%s",
		auth.ID, rl.OrganizationID,
		rl.FiveHourUtilization*100, rl.FiveHourStatus,
		rl.SevenDayUtilization*100, rl.SevenDayStatus,
		rl.UnifiedStatus, rl.RepresentativeClaim)
}

// GetRateLimitSnapshots returns all stored rate limit snapshots.
func GetRateLimitSnapshots() []*RateLimitSnapshot {
	rateLimitStoreMu.RLock()
	defer rateLimitStoreMu.RUnlock()

	result := make([]*RateLimitSnapshot, 0, len(rateLimitStore))
	for _, rl := range rateLimitStore {
		cp := *rl
		result = append(result, &cp)
	}
	return result
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

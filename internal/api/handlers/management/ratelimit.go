package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// rateLimitEntry is the JSON response for a single auth's rate limit state.
type rateLimitEntry struct {
	AuthID       string  `json:"auth_id"`
	AuthLabel    string  `json:"auth_label,omitempty"`
	FileName     string  `json:"file_name,omitempty"`
	Provider     string  `json:"provider"`
	Disabled     bool    `json:"disabled"`
	OrgID        string  `json:"organization_id,omitempty"`
	FiveHourUtil float64 `json:"five_hour_utilization"`
	FiveHourStat string  `json:"five_hour_status,omitempty"`
	FiveHourReset int64  `json:"five_hour_reset,omitempty"`
	SevenDayUtil float64 `json:"seven_day_utilization"`
	SevenDayStat string  `json:"seven_day_status,omitempty"`
	SevenDayReset int64  `json:"seven_day_reset,omitempty"`
	UnifiedStat  string  `json:"unified_status,omitempty"`
	UnifiedReset int64   `json:"unified_reset,omitempty"`
	Claim        string  `json:"representative_claim,omitempty"`
	Fallback     float64 `json:"fallback_percentage,omitempty"`
	OverageStat  string  `json:"overage_status,omitempty"`
	OverageReason string `json:"overage_disabled_reason,omitempty"`
	UpdatedAt    string  `json:"updated_at,omitempty"`
}

// GetRateLimits returns the latest rate limit state for all Claude auth entries.
func (h *Handler) GetRateLimits(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusOK, gin.H{"rate_limits": []rateLimitEntry{}})
		return
	}

	auths := h.authManager.List()
	var entries []rateLimitEntry
	for _, a := range auths {
		rl := a.RateLimit
		// Skip auths that have never received rate limit headers.
		if rl.UpdatedAt.IsZero() {
			continue
		}
		entries = append(entries, rateLimitEntry{
			AuthID:       a.ID,
			AuthLabel:    a.Label,
			FileName:     a.FileName,
			Provider:     a.Provider,
			Disabled:     a.Disabled,
			OrgID:        rl.OrganizationID,
			FiveHourUtil: rl.FiveHourUtilization,
			FiveHourStat: rl.FiveHourStatus,
			FiveHourReset: rl.FiveHourReset,
			SevenDayUtil: rl.SevenDayUtilization,
			SevenDayStat: rl.SevenDayStatus,
			SevenDayReset: rl.SevenDayReset,
			UnifiedStat:  rl.UnifiedStatus,
			UnifiedReset: rl.UnifiedReset,
			Claim:        rl.RepresentativeClaim,
			Fallback:     rl.FallbackPercentage,
			OverageStat:  rl.OverageStatus,
			OverageReason: rl.OverageDisabledReason,
			UpdatedAt:    rl.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	if entries == nil {
		entries = []rateLimitEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"rate_limits": entries})
}

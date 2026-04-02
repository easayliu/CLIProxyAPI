package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
)

// rateLimitEntry enriches a snapshot with auth metadata for the API response.
type rateLimitEntry struct {
	*executor.RateLimitSnapshot
	AuthLabel string `json:"auth_label,omitempty"`
	FileName  string `json:"file_name,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Disabled  bool   `json:"disabled"`
}

// GetRateLimits returns the latest in-memory rate limit state for all Claude auth entries.
// Data is populated from upstream response headers, never persisted to disk.
func (h *Handler) GetRateLimits(c *gin.Context) {
	snapshots := executor.GetRateLimitSnapshots()

	entries := make([]rateLimitEntry, 0, len(snapshots))
	for _, rl := range snapshots {
		e := rateLimitEntry{RateLimitSnapshot: rl}
		if h.authManager != nil {
			if a, ok := h.authManager.GetByID(rl.AuthID); ok {
				e.AuthLabel = a.Label
				e.FileName = a.FileName
				e.Provider = a.Provider
				e.Disabled = a.Disabled
			}
		}
		entries = append(entries, e)
	}

	c.JSON(http.StatusOK, gin.H{"rate_limits": entries})
}

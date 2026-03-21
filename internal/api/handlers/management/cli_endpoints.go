// Package management provides the management API handlers and middleware
// for configuring the server and managing auth files.
package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// --- OAuth / account endpoints ---

// CLIAccountSettings handles GET /api/oauth/account/settings
// Returns managed/organization settings for the CLI.
func (h *Handler) CLIAccountSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"settings": gin.H{},
	})
}

// CLIClientData handles GET /api/oauth/claude_cli/client_data
// Returns client configuration data for the CLI session.
func (h *Handler) CLIClientData(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"client_data": gin.H{},
	})
}

// --- Claude Code feature flags ---

// CLICodeSettings handles GET /api/claude_code/settings
// Returns organization-level Claude Code settings.
func (h *Handler) CLICodeSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"settings": gin.H{},
	})
}

// CLIPolicyLimits handles GET /api/claude_code/policy_limits
// Returns organization-level policy restrictions for Claude Code.
func (h *Handler) CLIPolicyLimits(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"restrictions": gin.H{},
	})
}

// CLIPenguinMode handles GET /api/claude_code_penguin_mode
// Returns penguin mode (extra usage) status.
func (h *Handler) CLIPenguinMode(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled":         false,
		"disabled_reason": "extra_usage_disabled",
	})
}

// CLIGrove handles GET /api/claude_code_grove
// Returns grove (usage tracking / billing) status.
func (h *Handler) CLIGrove(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"grove_enabled":             true,
		"domain_excluded":           false,
		"notice_is_grace_period":    false,
		"notice_reminder_frequency": 0,
	})
}

// CLIMetricsEnabled handles GET /api/claude_code/organizations/metrics_enabled
// Returns whether organization-level metrics logging is enabled.
func (h *Handler) CLIMetricsEnabled(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"metrics_logging_enabled": true,
	})
}

// --- Remote MCP servers ---

// CLIMCPServers handles GET /v1/mcp_servers
// Returns the list of remote MCP servers configured for the account.
func (h *Handler) CLIMCPServers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"data":      []any{},
		"next_page": nil,
	})
}

// --- Telemetry sinks ---

// featureFlagEntry represents a single feature flag returned by the eval SDK.
type featureFlagEntry struct {
	Value            any    `json:"value"`
	On               bool   `json:"on"`
	Off              bool   `json:"off"`
	Source           string `json:"source"`
	Experiment       any    `json:"experiment"`
	ExperimentResult any    `json:"experimentResult"`
	RuleID           any    `json:"ruleId"`
}

// defaultFeatureFlag returns a simple boolean flag with the given value.
func defaultFeatureFlag(val any) featureFlagEntry {
	on := true
	off := false
	if b, ok := val.(bool); ok && !b {
		on = false
		off = true
	}
	return featureFlagEntry{
		Value:  val,
		On:     on,
		Off:    off,
		Source: "defaultValue",
	}
}

// CLIEvalSDK handles POST /api/eval/sdk-*
// Returns feature flags that control CLI behavior. The response mirrors
// the real Statsig/LaunchDarkly format the CLI expects.
func (h *Handler) CLIEvalSDK(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"features": map[string]featureFlagEntry{
			// Enable Datadog telemetry logging
			"tengu_log_datadog_events": defaultFeatureFlag(true),
			// Keybinding customization
			"tengu_keybinding_customization_release": defaultFeatureFlag(true),
			// Various feature flags the CLI checks
			"tengu_collage_kaleidoscope": defaultFeatureFlag(true),
			"tengu_turtle_carbon":        defaultFeatureFlag(true),
			"tengu_birch_mist":           defaultFeatureFlag(true),
			"tengu_bramble_lintel":       defaultFeatureFlag(1),
			"tengu_cobalt_raccoon":       defaultFeatureFlag(false),
			"tengu_post_compact_survey":  defaultFeatureFlag(false),
			"tengu_onyx_plover": defaultFeatureFlag(map[string]any{
				"enabled":     false,
				"minHours":    24,
				"minSessions": 3,
			}),
		},
	})
}

// CLIEventLogging handles POST /api/event_logging/v2/batch
// Accepts telemetry event batches and returns accepted/rejected counts.
func (h *Handler) CLIEventLogging(c *gin.Context) {
	var req struct {
		Events []any `json:"events"`
	}
	// BindJSON would abort with 400 on malformed input; use
	// ShouldBindJSON and ignore errors so we always return 200.
	_ = c.ShouldBindJSON(&req)
	c.JSON(http.StatusOK, gin.H{
		"accepted_count": len(req.Events),
		"rejected_count": 0,
	})
}

// CLIMetrics handles POST /api/claude_code/metrics
// Accepts Claude Code usage metrics (OTLP-style) and acknowledges them.
func (h *Handler) CLIMetrics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"accepted_count": 1,
		"rejected_count": 0,
	})
}

// CLIDatadogLogs handles POST /api/v2/logs
// Simulates the Datadog log ingestion endpoint that the CLI sends
// telemetry events to (tengu_exit, tengu_api_error, etc.).
// The real endpoint is http-intake.logs.us5.datadoghq.com; this stub
// is only reached when the proxy intercepts all traffic (HTTP_PROXY mode).
func (h *Handler) CLIDatadogLogs(c *gin.Context) {
	c.JSON(http.StatusAccepted, gin.H{})
}

// Package management provides the management API handlers and middleware
// for configuring the server and managing auth files.
package management

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
)

// --- Connectivity check ---

// CLIHello handles GET /api/hello
// Returns a simple connectivity check response.
func (h *Handler) CLIHello(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "hello",
	})
}

// --- OAuth / account endpoints ---

// CLIAccountSettings handles GET /api/oauth/account/settings
// Returns account-level settings. The real API returns a flat object
// with feature flags and preferences (grove_enabled, tool_search_mode, etc.).
func (h *Handler) CLIAccountSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"grove_enabled":                    true,
		"grove_notice_viewed_at":           nil,
		"has_finished_claudeai_onboarding": true,
		"has_started_claudeai_onboarding":  true,
		"onboarding_use_case":              "personal",
		"tool_search_mode":                 "auto",
		"paprika_mode":                     "off",
		"enabled_web_search":               true,
		"enabled_artifacts_attachments":     false,
		"dismissed_saffron_themes":          true,
	})
}

// CLIClientData handles GET /api/oauth/claude_cli/client_data
// Returns client configuration data for the CLI session.
func (h *Handler) CLIClientData(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"client_data": gin.H{},
	})
}

// CLIOAuthProfile handles GET /api/oauth/profile
// Returns account, application, and organization info consistent with
// the cloaked identity derived from the authenticated API key.
func (h *Handler) CLIOAuthProfile(c *gin.Context) {
	apiKey, accountUUID, orgUUID := h.cliIdentity(c)
	email := deriveEmail(apiKey)

	c.JSON(http.StatusOK, gin.H{
		"account": gin.H{
			"created_at":     "2025-01-01T00:00:00.000000Z",
			"display_name":   email,
			"email":          email,
			"full_name":      email,
			"has_claude_max": true,
			"has_claude_pro":  false,
			"uuid":           accountUUID,
		},
		"application": gin.H{
			"name": "Claude Code",
			"slug": "claude-code",
			"uuid": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
		},
		"organization": gin.H{
			"billing_type":             "stripe_subscription",
			"has_extra_usage_enabled":  false,
			"name":                     email + "'s Organization",
			"organization_type":        "claude_max",
			"rate_limit_tier":          "default_claude_max_20x",
			"subscription_created_at":  "2025-01-01T00:00:00.000000Z",
			"subscription_status":      "active",
			"uuid":                     orgUUID,
		},
	})
}

// CLIOAuthRoles handles GET /api/oauth/claude_cli/roles
// Returns organization role info for the authenticated user.
func (h *Handler) CLIOAuthRoles(c *gin.Context) {
	_, _, orgUUID := h.cliIdentity(c)

	c.JSON(http.StatusOK, gin.H{
		"organization_name": "Organization",
		"organization_role": "admin",
		"organization_uuid": orgUUID,
		"workspace_name":    nil,
		"workspace_role":    nil,
		"workspace_uuid":    nil,
	})
}

// CLIFirstTokenDate handles GET /api/organization/claude_code_first_token_date
// Returns the date of the first API token usage for this organization.
func (h *Handler) CLIFirstTokenDate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"first_token_date": time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
	})
}

// CLIReferralEligibility handles GET /api/oauth/organizations/:uuid/referral/eligibility
// Returns guest pass referral eligibility status.
func (h *Handler) CLIReferralEligibility(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"eligible":              false,
		"referral_code_details": nil,
		"referrer_reward":       nil,
		"remaining_passes":      nil,
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
	// ShouldBindJSON ignores errors so we always return 200.
	_ = c.ShouldBindJSON(&req)
	c.JSON(http.StatusOK, gin.H{
		"accepted_count": len(req.Events),
		"rejected_count": 0,
	})
}

// CLIEventLoggingLegacy handles POST /api/event_logging/batch
// Legacy event logging endpoint used during first-time CLI setup.
func (h *Handler) CLIEventLoggingLegacy(c *gin.Context) {
	var req struct {
		Events []any `json:"events"`
	}
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

// --- Identity helpers ---

// cliIdentity extracts the API key from the gin context and derives
// stable device_id, account_uuid, and organization_uuid using the same
// derivation functions as the cloaking layer. This ensures all stub
// endpoints return identity data consistent with v1/messages metadata.
func (h *Handler) cliIdentity(c *gin.Context) (apiKey, accountUUID, orgUUID string) {
	if v, ok := c.Get("apiKey"); ok {
		apiKey, _ = v.(string)
	}
	if apiKey == "" {
		apiKey = "default"
	}
	accountUUID = executor.DeriveAccountUUID(apiKey)
	orgUUID = executor.DeriveOrganizationUUID(apiKey)
	return
}

// deriveEmail generates a stable, plausible email from the API key.
func deriveEmail(apiKey string) string {
	h := sha256.Sum256([]byte("email:" + apiKey))
	tag := hex.EncodeToString(h[:4])
	return fmt.Sprintf("user_%s@claude.ai", tag)
}

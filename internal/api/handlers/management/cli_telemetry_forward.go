// Package management provides the management API handlers and middleware
// for configuring the server and managing auth files.
package management

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	claude "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// telemetryForwarder holds the HTTP client and upstream target for forwarding telemetry.
type telemetryForwarder struct {
	client   *http.Client
	upstream string // "https://api.anthropic.com"
}

// defaultTelemetryForwarder is the package-level forwarder instance.
var defaultTelemetryForwarder = &telemetryForwarder{
	client: &http.Client{
		Timeout: 5 * time.Second,
	},
	upstream: "https://api.anthropic.com",
}

// getUpstreamAuth selects an upstream OAuth auth from the auth manager.
// Returns the upstream API key (for identity derivation), the auth record,
// and whether a suitable auth was found.
// The returned apiKey is the UPSTREAM auth's key (not the client's proxy key),
// ensuring identity derivation matches the cloaking layer in v1/messages.
func (h *Handler) getUpstreamAuth(c *gin.Context) (upstreamKey string, auth *coreauth.Auth, ok bool) {
	// Check if the client is authenticated at all
	if _, exists := c.Get("apiKey"); !exists {
		return "", nil, false
	}

	if h.authManager == nil {
		return "", nil, false
	}

	auths := h.authManager.List()
	for _, a := range auths {
		if a.Disabled || a.Unavailable {
			continue
		}
		// Extract the upstream API key from the auth record,
		// using the same logic as claudeCreds() in the executor.
		key := extractUpstreamKey(a)
		if key == "" {
			continue
		}
		return key, a, true
	}
	return "", nil, false
}

// extractUpstreamKey gets the upstream API key from an auth record,
// mirroring the claudeCreds() logic in the executor package.
func extractUpstreamKey(a *coreauth.Auth) string {
	if a.Attributes != nil {
		if k := strings.TrimSpace(a.Attributes["api_key"]); k != "" {
			return k
		}
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// forwardTelemetry sends the request body to the upstream Anthropic API after
// replacing identity fields. The forwarding is done asynchronously in a goroutine
// so it does not block the client response.
func (h *Handler) forwardTelemetry(c *gin.Context, upstreamPath string, body []byte, upstreamAuth *coreauth.Auth) {
	// Build Authorization header
	var authHeader string
	if upstreamAuth.Storage != nil {
		// OAuth token: extract access_token from the ClaudeTokenStorage
		if cts, ok := upstreamAuth.Storage.(*claude.ClaudeTokenStorage); ok && cts.AccessToken != "" {
			authHeader = "Bearer " + cts.AccessToken
		}
	}
	if authHeader == "" && upstreamAuth.Attributes != nil {
		if ak := upstreamAuth.Attributes["api_key"]; ak != "" {
			authHeader = "x-api-key " + ak
		}
	}
	if authHeader == "" {
		log.Printf("[telemetry-forward] no credentials available for upstream auth %s, skipping", upstreamAuth.ID)
		return
	}

	targetURL := defaultTelemetryForwarder.upstream + upstreamPath

	// Collect headers to forward
	contentType := c.GetHeader("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	userAgent := c.GetHeader("User-Agent")
	anthropicBeta := c.GetHeader("Anthropic-Beta")
	anthropicVersion := c.GetHeader("Anthropic-Version")
	xServiceName := c.GetHeader("X-Service-Name")

	go func() {
		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[telemetry-forward] failed to create request for %s: %v", upstreamPath, err)
			return
		}

		// Set authorization
		if strings.HasPrefix(authHeader, "Bearer ") {
			req.Header.Set("Authorization", authHeader)
		} else if strings.HasPrefix(authHeader, "x-api-key ") {
			req.Header.Set("x-api-key", strings.TrimPrefix(authHeader, "x-api-key "))
		}

		// Copy relevant headers
		req.Header.Set("Content-Type", contentType)
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		if anthropicBeta != "" {
			req.Header.Set("Anthropic-Beta", anthropicBeta)
		}
		if anthropicVersion != "" {
			req.Header.Set("Anthropic-Version", anthropicVersion)
		}
		if xServiceName != "" {
			req.Header.Set("X-Service-Name", xServiceName)
		}

		resp, err := defaultTelemetryForwarder.client.Do(req)
		if err != nil {
			log.Printf("[telemetry-forward] failed to forward to %s: %v", upstreamPath, err)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 400 {
			log.Printf("[telemetry-forward] upstream %s returned status %d", upstreamPath, resp.StatusCode)
		}
	}()
}

// replaceEventLoggingIdentity replaces identity fields in an event_logging batch body.
// Body format: {"events": [{"event_data": {"device_id": "...", "session_id": "...", "additional_metadata": "base64..."}, ...}]}
// Replaces device_id, session_id, and the rh field inside additional_metadata.
func replaceEventLoggingIdentity(body []byte, apiKey string) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}

	events, ok := parsed["events"].([]any)
	if !ok {
		return body
	}

	derivedDeviceID := executor.DeriveDeviceID(apiKey)
	derivedSessionID := executor.PickSessionID(apiKey)
	derivedRH := executor.DeriveRH(apiKey)

	for i, ev := range events {
		evMap, ok := ev.(map[string]any)
		if !ok {
			continue
		}
		eventData, ok := evMap["event_data"].(map[string]any)
		if !ok {
			continue
		}

		// Replace device_id and session_id
		if _, exists := eventData["device_id"]; exists {
			eventData["device_id"] = derivedDeviceID
		}
		if _, exists := eventData["session_id"]; exists {
			eventData["session_id"] = derivedSessionID
		}

		// Replace rh inside additional_metadata (base64 encoded JSON)
		if amRaw, exists := eventData["additional_metadata"]; exists {
			if amStr, ok := amRaw.(string); ok && amStr != "" {
				decoded, err := base64.StdEncoding.DecodeString(amStr)
				if err == nil {
					var amData map[string]any
					if json.Unmarshal(decoded, &amData) == nil {
						if _, rhExists := amData["rh"]; rhExists {
							amData["rh"] = derivedRH
						}
						reEncoded, err := json.Marshal(amData)
						if err == nil {
							eventData["additional_metadata"] = base64.StdEncoding.EncodeToString(reEncoded)
						}
					}
				}
			}
		}

		evMap["event_data"] = eventData
		events[i] = evMap
	}

	parsed["events"] = events
	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

// replaceEvalSDKIdentity replaces identity fields in an eval/sdk body.
// Body format: {"attributes": {"deviceID": "...", "accountUUID": "...", "email": "...", ...}}
// Replaces deviceID, id, accountUUID, organizationUUID, email, and sessionId.
func replaceEvalSDKIdentity(body []byte, apiKey string, email string) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}

	attrs, ok := parsed["attributes"].(map[string]any)
	if !ok {
		return body
	}

	derivedDeviceID := executor.DeriveDeviceID(apiKey)

	if _, exists := attrs["deviceID"]; exists {
		attrs["deviceID"] = derivedDeviceID
	}
	if _, exists := attrs["id"]; exists {
		attrs["id"] = derivedDeviceID
	}
	if _, exists := attrs["accountUUID"]; exists {
		attrs["accountUUID"] = executor.DeriveAccountUUID(apiKey)
	}
	if _, exists := attrs["organizationUUID"]; exists {
		attrs["organizationUUID"] = executor.DeriveOrganizationUUID(apiKey)
	}
	if _, exists := attrs["email"]; exists {
		attrs["email"] = email
	}
	if _, exists := attrs["sessionId"]; exists {
		attrs["sessionId"] = executor.PickSessionID(apiKey)
	}

	parsed["attributes"] = attrs
	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

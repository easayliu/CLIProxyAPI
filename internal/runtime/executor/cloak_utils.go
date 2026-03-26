package executor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// userIDPayload is the JSON structure for Claude Code 2.1.79+ metadata.user_id.
// The field is serialized as a JSON string (not an object) inside metadata.user_id.
type userIDPayload struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id"`
}

// generateFakeUserID generates a fake user ID in Claude Code 2.1.79+ JSON format.
// Format: {"device_id":"<64-hex>","account_uuid":"<UUID>","session_id":"<UUID>"}
func generateFakeUserID() string {
	hexBytes := make([]byte, 32)
	_, _ = rand.Read(hexBytes)
	payload := userIDPayload{
		DeviceID:    hex.EncodeToString(hexBytes),
		AccountUUID: uuid.New().String(),
		SessionID:   uuid.New().String(),
	}
	data, _ := json.Marshal(payload)
	return string(data)
}

// isValidUserID checks if a user ID matches Claude Code format.
// Supports both the new JSON format (2.1.79+) and the legacy flat string format.
func isValidUserID(userID string) bool {
	// New JSON format: {"device_id":"...","account_uuid":"...","session_id":"..."}
	if strings.HasPrefix(userID, "{") {
		var p userIDPayload
		if err := json.Unmarshal([]byte(userID), &p); err == nil {
			return len(p.DeviceID) == 64 && p.AccountUUID != "" && p.SessionID != ""
		}
	}
	// Legacy format: user_[64-hex]_account_[UUID]_session_[UUID]
	return strings.HasPrefix(userID, "user_") && strings.Contains(userID, "_account_") && strings.Contains(userID, "_session_")
}

// shouldCloak determines if request should be cloaked based on config and client User-Agent.
// Returns true if cloaking should be applied.
func shouldCloak(cloakMode string, userAgent string) bool {
	switch strings.ToLower(cloakMode) {
	case "always":
		return true
	case "never":
		return false
	default: // "auto" or empty
		// If client is Claude Code, don't cloak
		return !strings.HasPrefix(userAgent, "claude-cli")
	}
}

// isClaudeCodeClient checks if the User-Agent indicates a Claude Code client.
func isClaudeCodeClient(userAgent string) bool {
	return strings.HasPrefix(userAgent, "claude-cli")
}

// supportsAdaptiveThinking returns true if the model supports thinking:{type:"adaptive"}.
// Only Claude 4.6 models (opus-4-6, sonnet-4-6) support adaptive thinking.
// Older models like sonnet-4, claude-3-5-sonnet, haiku etc. do not.
func supportsAdaptiveThinking(model string) bool {
	return strings.Contains(model, "opus-4-6") || strings.Contains(model, "sonnet-4-6")
}

// thinkingToEffort converts a client's thinking configuration to the equivalent
// output_config.effort level. Real CLI 2.1.84 never sends thinking; it only uses
// effort. This mapping preserves the client's intent when cloaking removes thinking.
//
// Mapping:
//
//	thinking.type = "disabled"  → "low"   (minimal thinking)
//	thinking.type = "adaptive"  → "medium" (default CLI behavior)
//	thinking.type = "enabled" with budget_tokens:
//	  budget <= 4096   → "low"
//	  budget <= 16384  → "medium"
//	  budget <= 32768  → "high"
//	  budget > 32768   → "high"
//	no thinking / unknown → "medium" (default)
func thinkingToEffort(payload []byte) string {
	t := gjson.GetBytes(payload, "thinking.type").String()
	switch t {
	case "disabled":
		return "low"
	case "adaptive":
		return "medium"
	case "enabled":
		budget := gjson.GetBytes(payload, "thinking.budget_tokens").Int()
		switch {
		case budget <= 4096:
			return "low"
		case budget <= 16384:
			return "medium"
		default:
			return "high"
		}
	default:
		return "medium"
	}
}

// extractFieldFromUserID extracts a named field from a JSON-format user_id string.
// Returns empty string if parsing fails or the field is missing.
func extractFieldFromUserID(userID string, field string) string {
	if !strings.HasPrefix(userID, "{") {
		return ""
	}
	var p userIDPayload
	if err := json.Unmarshal([]byte(userID), &p); err != nil {
		return ""
	}
	switch field {
	case "device_id":
		return p.DeviceID
	case "account_uuid":
		return p.AccountUUID
	case "session_id":
		return p.SessionID
	default:
		return ""
	}
}

package executor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
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

// generateCCH generates a 5-char hex hash for the billing header cch field.
// In Claude Code 2.1.79+ this is derived from session-specific data.
// We generate a random value since the exact derivation is internal to Claude Code.
func generateCCH() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:5]
}

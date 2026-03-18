package executor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// userIDStruct matches the real Claude Code metadata.user_id JSON format.
type userIDStruct struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id"`
}

// generateFakeUserID generates a fake user ID matching real Claude Code format.
// Real format: JSON string {"device_id":"64hex","account_uuid":"uuid","session_id":"uuid"}
func generateFakeUserID() string {
	hexBytes := make([]byte, 32)
	_, _ = rand.Read(hexBytes)
	uid := userIDStruct{
		DeviceID:    hex.EncodeToString(hexBytes),
		AccountUUID: uuid.New().String(),
		SessionID:   uuid.New().String(),
	}
	b, _ := json.Marshal(uid)
	return string(b)
}

// isValidUserID checks if a user ID matches Claude Code format.
// Accepts both the new JSON object format and the legacy string format.
func isValidUserID(userID string) bool {
	// New format: JSON object with device_id, account_uuid, session_id
	if strings.HasPrefix(userID, "{") {
		var uid userIDStruct
		if err := json.Unmarshal([]byte(userID), &uid); err == nil {
			return uid.DeviceID != "" && uid.AccountUUID != "" && uid.SessionID != ""
		}
	}
	return false
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

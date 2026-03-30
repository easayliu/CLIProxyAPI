package executor

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// randomCCH generates a random 5-char hex string, used once per session slot.
func randomCCH() string {
	b := make([]byte, 3)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)[:5]
}

// DeriveDeviceID generates a stable device_id (64-hex) from the API key.
// Real Claude Code CLI generates this once per device and persists it.
func DeriveDeviceID(apiKey string) string {
	h := sha256.Sum256([]byte("device:" + apiKey))
	return hex.EncodeToString(h[:])
}

// DeriveAccountUUID generates a stable account_uuid from the API key.
// Real Claude Code CLI gets this from the OAuth account info and it never changes.
func DeriveAccountUUID(apiKey string) string {
	h := sha256.Sum256([]byte("account:" + apiKey))
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(h[0:4]),
		hex.EncodeToString(h[4:6]),
		hex.EncodeToString(h[6:8]),
		hex.EncodeToString(h[8:10]),
		hex.EncodeToString(h[10:16]),
	)
}

// DeriveOrganizationUUID generates a stable organization_uuid from the API key.
func DeriveOrganizationUUID(apiKey string) string {
	h := sha256.Sum256([]byte("organization:" + apiKey))
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(h[0:4]),
		hex.EncodeToString(h[4:6]),
		hex.EncodeToString(h[6:8]),
		hex.EncodeToString(h[8:10]),
		hex.EncodeToString(h[10:16]),
	)
}

// DeriveRH generates a stable 16-hex-char rh value from the API key.
// Used in telemetry events' additional_metadata.rh field.
func DeriveRH(apiKey string) string {
	h := sha256.Sum256([]byte("rh:" + apiKey))
	return hex.EncodeToString(h[:8])
}

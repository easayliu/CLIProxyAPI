package executor

import (
	"encoding/json"
	"testing"
)

func resetSessionPool() {
	sessionPoolsMu.Lock()
	sessionPools = make(map[string]*sessionPool)
	sessionPoolsMu.Unlock()
}

func TestCachedUserID_ReusesWithinPool(t *testing.T) {
	resetSessionPool()

	first := cachedUserID("api-key-1", "", "")
	if first == "" {
		t.Fatal("expected generated user_id to be non-empty")
	}

	// Multiple calls should produce valid user_ids (may differ due to pool rotation)
	for i := 0; i < 5; i++ {
		id := cachedUserID("api-key-1", "", "")
		if id == "" {
			t.Fatalf("iteration %d: expected non-empty user_id", i)
		}
	}
}

func TestCachedUserID_PoolUsesMultipleSessions(t *testing.T) {
	resetSessionPool()

	seen := make(map[string]bool)
	// With 2-4 pool slots, after enough requests we should see multiple session_ids.
	for i := 0; i < 100; i++ {
		id := cachedUserID("api-key-multi", "", "")
		sid := extractSessionID(id)
		if sid == "" {
			t.Fatalf("iteration %d: empty session_id", i)
		}
		seen[sid] = true
	}

	if len(seen) < 2 {
		t.Fatalf("expected multiple session_ids from pool, got %d unique", len(seen))
	}
	t.Logf("saw %d unique session_ids across 100 requests", len(seen))
}

func TestCachedUserID_IsScopedByAPIKey(t *testing.T) {
	resetSessionPool()

	first := cachedUserID("api-key-1", "", "")
	second := cachedUserID("api-key-2", "", "")

	if first == second {
		t.Fatalf("expected different API keys to have different user_ids, got %q", first)
	}
}

func TestCachedUserID_StableDeviceAndAccount(t *testing.T) {
	resetSessionPool()

	// device_id and account_uuid should be stable across calls for the same API key.
	var deviceIDs, accountIDs []string
	for i := 0; i < 10; i++ {
		id := cachedUserID("api-key-stable", "", "")
		var p userIDPayload
		if err := json.Unmarshal([]byte(id), &p); err != nil {
			t.Fatalf("failed to parse user_id: %v", err)
		}
		deviceIDs = append(deviceIDs, p.DeviceID)
		accountIDs = append(accountIDs, p.AccountUUID)
	}

	for i := 1; i < len(deviceIDs); i++ {
		if deviceIDs[i] != deviceIDs[0] {
			t.Fatalf("device_id changed: %q vs %q", deviceIDs[0], deviceIDs[i])
		}
		if accountIDs[i] != accountIDs[0] {
			t.Fatalf("account_uuid changed: %q vs %q", accountIDs[0], accountIDs[i])
		}
	}
}

func TestCachedUserID_UsesRealDeviceID(t *testing.T) {
	resetSessionPool()

	realDevice := "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd"
	id := cachedUserID("api-key-real", realDevice, "")

	var p userIDPayload
	if err := json.Unmarshal([]byte(id), &p); err != nil {
		t.Fatalf("failed to parse user_id: %v", err)
	}
	if p.DeviceID != realDevice {
		t.Fatalf("expected device_id=%q, got %q", realDevice, p.DeviceID)
	}
}

func TestCachedUserID_UsesRealAccountUUID(t *testing.T) {
	resetSessionPool()

	realAccount := "12345678-1234-1234-1234-123456789abc"
	id := cachedUserID("api-key-real", "", realAccount)

	var p userIDPayload
	if err := json.Unmarshal([]byte(id), &p); err != nil {
		t.Fatalf("failed to parse user_id: %v", err)
	}
	if p.AccountUUID != realAccount {
		t.Fatalf("expected account_uuid=%q, got %q", realAccount, p.AccountUUID)
	}
}

// extractSessionID parses the session_id from a cached user_id JSON string.
func extractSessionID(userID string) string {
	var p userIDPayload
	if err := json.Unmarshal([]byte(userID), &p); err != nil {
		return ""
	}
	return p.SessionID
}

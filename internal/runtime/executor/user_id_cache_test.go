package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func resetSessionIDCache() {
	sessionIDCacheMu.Lock()
	sessionIDCache = make(map[string]sessionIDCacheEntry)
	sessionIDCacheMu.Unlock()
}

func sessionCacheKey(apiKey string) string {
	key := sha256.Sum256([]byte("session:" + apiKey))
	return hex.EncodeToString(key[:])
}

func TestCachedUserID_ReusesWithinTTL(t *testing.T) {
	resetSessionIDCache()

	first := cachedUserID("api-key-1", "", "")
	second := cachedUserID("api-key-1", "", "")

	if first == "" {
		t.Fatal("expected generated user_id to be non-empty")
	}
	if first != second {
		t.Fatalf("expected cached user_id to be reused, got %q and %q", first, second)
	}
}

func TestCachedUserID_ExpiresAfterTTL(t *testing.T) {
	resetSessionIDCache()

	expiredID := cachedUserID("api-key-expired", "", "")
	cacheKey := sessionCacheKey("api-key-expired")
	sessionIDCacheMu.Lock()
	sessionIDCache[cacheKey] = sessionIDCacheEntry{
		sessionID: "",
		expire:    time.Now().Add(-time.Minute),
	}
	sessionIDCacheMu.Unlock()

	newID := cachedUserID("api-key-expired", "", "")
	if newID == expiredID {
		t.Fatalf("expected expired session to produce different user_id, got %q", newID)
	}
	if newID == "" {
		t.Fatal("expected regenerated user_id to be non-empty")
	}
}

func TestCachedUserID_IsScopedByAPIKey(t *testing.T) {
	resetSessionIDCache()

	first := cachedUserID("api-key-1", "", "")
	second := cachedUserID("api-key-2", "", "")

	if first == second {
		t.Fatalf("expected different API keys to have different user_ids, got %q", first)
	}
}

func TestCachedUserID_RenewsTTLOnHit(t *testing.T) {
	resetSessionIDCache()

	key := "api-key-renew"
	id := cachedUserID(key, "", "")
	cacheKey := sessionCacheKey(key)

	soon := time.Now()
	sessionIDCacheMu.Lock()
	sessionIDCache[cacheKey] = sessionIDCacheEntry{
		sessionID: extractSessionID(id),
		expire:    soon.Add(2 * time.Second),
	}
	sessionIDCacheMu.Unlock()

	if refreshed := cachedUserID(key, "", ""); refreshed != id {
		t.Fatalf("expected cached user_id to be reused before expiry, got %q", refreshed)
	}

	sessionIDCacheMu.RLock()
	entry := sessionIDCache[cacheKey]
	sessionIDCacheMu.RUnlock()

	if entry.expire.Sub(soon) < 30*time.Minute {
		t.Fatalf("expected TTL to renew, got %v remaining", entry.expire.Sub(soon))
	}
}

func TestCachedUserID_UsesRealDeviceID(t *testing.T) {
	resetSessionIDCache()

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
	resetSessionIDCache()

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

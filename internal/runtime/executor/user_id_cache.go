package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// sessionIDCacheEntry caches only the session_id component, which rotates per session.
// device_id and account_uuid are derived deterministically from the API key and never change.
type sessionIDCacheEntry struct {
	sessionID string
	expire    time.Time
}

var (
	sessionIDCache            = make(map[string]sessionIDCacheEntry)
	sessionIDCacheMu          sync.RWMutex
	sessionIDCacheCleanupOnce sync.Once
)

const (
	sessionIDTTL             = time.Hour
	sessionIDCacheCleanup    = 15 * time.Minute
)

func startSessionIDCacheCleanup() {
	go func() {
		ticker := time.NewTicker(sessionIDCacheCleanup)
		defer ticker.Stop()
		for range ticker.C {
			purgeExpiredSessionIDs()
		}
	}()
}

func purgeExpiredSessionIDs() {
	now := time.Now()
	sessionIDCacheMu.Lock()
	for key, entry := range sessionIDCache {
		if !entry.expire.After(now) {
			delete(sessionIDCache, key)
		}
	}
	sessionIDCacheMu.Unlock()
}

// deriveDeviceID generates a stable device_id (64-hex) from the API key.
// Real Claude Code CLI generates this once per device and persists it.
func deriveDeviceID(apiKey string) string {
	h := sha256.Sum256([]byte("device:" + apiKey))
	return hex.EncodeToString(h[:])
}

// deriveAccountUUID generates a stable account_uuid from the API key.
// Real Claude Code CLI gets this from the OAuth account info and it never changes.
func deriveAccountUUID(apiKey string) string {
	h := sha256.Sum256([]byte("account:" + apiKey))
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(h[0:4]),
		hex.EncodeToString(h[4:6]),
		hex.EncodeToString(h[6:8]),
		hex.EncodeToString(h[8:10]),
		hex.EncodeToString(h[10:16]),
	)
}

// cachedSessionID returns a session_id that rotates every hour (simulating CLI restarts).
func cachedSessionID(apiKey string) string {
	key := sha256.Sum256([]byte("session:" + apiKey))
	cacheKey := hex.EncodeToString(key[:])
	now := time.Now()

	sessionIDCacheMu.RLock()
	entry, ok := sessionIDCache[cacheKey]
	valid := ok && entry.sessionID != "" && entry.expire.After(now)
	sessionIDCacheMu.RUnlock()
	if valid {
		sessionIDCacheMu.Lock()
		entry = sessionIDCache[cacheKey]
		if entry.sessionID != "" && entry.expire.After(now) {
			entry.expire = now.Add(sessionIDTTL)
			sessionIDCache[cacheKey] = entry
			sessionIDCacheMu.Unlock()
			return entry.sessionID
		}
		sessionIDCacheMu.Unlock()
	}

	newSessionID := uuid.New().String()

	sessionIDCacheMu.Lock()
	entry, ok = sessionIDCache[cacheKey]
	if !ok || entry.sessionID == "" || !entry.expire.After(now) {
		entry.sessionID = newSessionID
	}
	entry.expire = now.Add(sessionIDTTL)
	sessionIDCache[cacheKey] = entry
	sessionIDCacheMu.Unlock()
	return entry.sessionID
}

// cachedUserID builds a complete user_id with stable device_id/account_uuid
// and a rotating session_id. This matches real Claude Code CLI behavior where
// device_id and account_uuid are permanent, but session_id changes per CLI launch.
// If realDeviceID or realAccountUUID is provided (from persisted OAuth auth file),
// it is used instead of the derived value for maximum authenticity.
func cachedUserID(apiKey string, realDeviceID string, realAccountUUID string) string {
	return cachedUserIDWithSession(apiKey, realDeviceID, realAccountUUID, "")
}

// cachedUserIDWithSession is like cachedUserID but allows preserving a client-provided
// session_id. When clientSessionID is non-empty, it is used directly instead of the
// cached/generated value, matching real Claude Code CLI behavior where the client
// maintains its own session_id across requests within the same CLI session.
func cachedUserIDWithSession(apiKey string, realDeviceID string, realAccountUUID string, clientSessionID string) string {
	if apiKey == "" {
		return generateFakeUserID()
	}

	sessionIDCacheCleanupOnce.Do(startSessionIDCacheCleanup)

	deviceID := deriveDeviceID(apiKey)
	if realDeviceID != "" {
		deviceID = realDeviceID
	}

	accountUUID := deriveAccountUUID(apiKey)
	if realAccountUUID != "" {
		accountUUID = realAccountUUID
	}

	sessionID := cachedSessionID(apiKey)
	if clientSessionID != "" {
		sessionID = clientSessionID
	}

	payload := userIDPayload{
		DeviceID:    deviceID,
		AccountUUID: accountUUID,
		SessionID:   sessionID,
	}
	data, _ := json.Marshal(payload)
	return string(data)
}

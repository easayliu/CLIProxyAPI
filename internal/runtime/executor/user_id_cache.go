package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
)

// sessionSlot represents one "terminal window" — a single CLI session with its own
// session_id, lifetime, and request budget.
type sessionSlot struct {
	sessionID string
	expire    time.Time
	requests  int // requests served so far
	maxReqs   int // per-slot cap (randomized)
}

// sessionPool holds multiple concurrent session slots for one API key,
// simulating a developer with several terminal windows open.
type sessionPool struct {
	slots []sessionSlot
}

var (
	sessionPools         = make(map[string]*sessionPool)
	sessionPoolsMu       sync.Mutex
	sessionPoolCleanOnce sync.Once
)

const (
	// Session slot lifetime: each slot lives 40–80 minutes (randomized, fixed at creation).
	sessionSlotBaseTTL  = 40 * time.Minute
	sessionSlotJitter   = 40 * time.Minute

	// Per-slot request cap: 20–49 requests before the slot retires.
	sessionSlotBaseReqs  = 20
	sessionSlotReqJitter = 30

	// Pool size: 2–4 concurrent "terminal windows" per API key.
	sessionPoolMinSlots = 2
	sessionPoolMaxSlots = 4

	// Cleanup interval for expired pools.
	sessionPoolCleanupInterval = 15 * time.Minute
)

func randomSlotTTL() time.Duration {
	return sessionSlotBaseTTL + time.Duration(rand.Int64N(int64(sessionSlotJitter)))
}

func randomSlotMaxReqs() int {
	return sessionSlotBaseReqs + rand.IntN(sessionSlotReqJitter)
}

func randomPoolSize() int {
	return sessionPoolMinSlots + rand.IntN(sessionPoolMaxSlots-sessionPoolMinSlots+1)
}

func newSessionSlot() sessionSlot {
	return sessionSlot{
		sessionID: uuid.New().String(),
		expire:    time.Now().Add(randomSlotTTL()),
		requests:  0,
		maxReqs:   randomSlotMaxReqs(),
	}
}

func startSessionPoolCleanup() {
	go func() {
		ticker := time.NewTicker(sessionPoolCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			purgeExpiredPools()
		}
	}()
}

func purgeExpiredPools() {
	now := time.Now()
	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()
	for key, pool := range sessionPools {
		allDead := true
		for _, s := range pool.slots {
			if s.expire.After(now) && s.requests < s.maxReqs {
				allDead = false
				break
			}
		}
		if allDead {
			delete(sessionPools, key)
		}
	}
}

// pickSessionID selects a session_id from the pool for this API key.
// It picks a random live slot and increments its request counter, simulating
// a developer switching between terminal windows.
// Expired or exhausted slots are lazily replaced with fresh ones.
func pickSessionID(apiKey string) string {
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])
	now := time.Now()

	sessionPoolCleanOnce.Do(startSessionPoolCleanup)

	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()

	pool, ok := sessionPools[cacheKey]
	if !ok {
		pool = &sessionPool{slots: make([]sessionSlot, randomPoolSize())}
		for i := range pool.slots {
			pool.slots[i] = newSessionSlot()
		}
		sessionPools[cacheKey] = pool
	}

	// Refresh any dead slots.
	for i := range pool.slots {
		s := &pool.slots[i]
		if !s.expire.After(now) || s.requests >= s.maxReqs {
			*s = newSessionSlot()
		}
	}

	// Pick a random live slot (all slots are guaranteed live after refresh above).
	idx := rand.IntN(len(pool.slots))
	pool.slots[idx].requests++
	return pool.slots[idx].sessionID
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

// cachedUserID builds a complete user_id with stable device_id/account_uuid
// and a session_id picked from a pool of concurrent sessions.
// If realDeviceID or realAccountUUID is provided (from persisted OAuth auth file),
// it is used instead of the derived value for maximum authenticity.
func cachedUserID(apiKey string, realDeviceID string, realAccountUUID string) string {
	return cachedUserIDWithSession(apiKey, realDeviceID, realAccountUUID, "")
}

// cachedUserIDWithSession is like cachedUserID but allows preserving a client-provided
// session_id. When clientSessionID is non-empty, it is used directly instead of the
// pool-selected value.
func cachedUserIDWithSession(apiKey string, realDeviceID string, realAccountUUID string, clientSessionID string) string {
	if apiKey == "" {
		return generateFakeUserID()
	}

	deviceID := deriveDeviceID(apiKey)
	if realDeviceID != "" {
		deviceID = realDeviceID
	}

	accountUUID := deriveAccountUUID(apiKey)
	if realAccountUUID != "" {
		accountUUID = realAccountUUID
	}

	sessionID := pickSessionID(apiKey)
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

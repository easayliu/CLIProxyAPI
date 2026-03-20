package executor

import (
	crand "crypto/rand"
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
	cch       string // stable per-session billing hash (5-char hex)
	createdAt time.Time
	expire    time.Time
	requests  int // requests served so far
	maxReqs   int // per-slot cap (randomized)
}

// sessionPool holds concurrent session slots for one API key.
// The number of active slots adapts to request frequency: low RPM uses 1 slot
// (like a single terminal), high RPM grows up to maxSlots (multiple terminals).
type sessionPool struct {
	slots []sessionSlot

	// Adaptive sizing: track request rate over a sliding window.
	windowStart time.Time // start of the current measurement window
	windowReqs  int       // requests in the current window
}

var (
	sessionPools         = make(map[string]*sessionPool)
	sessionPoolsMu       sync.Mutex
	sessionPoolCleanOnce sync.Once

	// lastPickedCCH stores the cch from the most recently picked session slot
	// per API key (keyed by pool cache key). Used by generateCCH() to return
	// a session-stable value instead of a random one.
	lastPickedCCH   = make(map[string]string)
	lastPickedCCHMu sync.RWMutex
)

const (
	// Session slot lifetime: each slot lives 1–3 hours (randomized, fixed at creation).
	// Real developers keep a terminal open for extended periods.
	sessionSlotBaseTTL = 1 * time.Hour
	sessionSlotJitter  = 2 * time.Hour // total range: 1–3 hours

	// Per-slot request cap: 80–200 requests before the slot retires.
	// A real CLI session easily does 100+ requests in a long coding session.
	sessionSlotBaseReqs  = 80
	sessionSlotReqJitter = 120 // total range: 80–199

	// Adaptive pool sizing thresholds.
	// Below rpmThreshold1, use 1 slot (single terminal).
	// Between rpmThreshold1 and rpmThreshold2, use 2 slots.
	// Above rpmThreshold2, use 3 slots.
	rpmThreshold1 = 10 // RPM > 10 → 2 slots
	rpmThreshold2 = 25 // RPM > 25 → 3 slots

	// RPM measurement window.
	rpmWindowDuration = 5 * time.Minute

	// Cleanup interval for expired pools.
	sessionPoolCleanupInterval = 15 * time.Minute
)

func randomSlotTTL() time.Duration {
	return sessionSlotBaseTTL + time.Duration(rand.Int64N(int64(sessionSlotJitter)))
}

func randomSlotMaxReqs() int {
	return sessionSlotBaseReqs + rand.IntN(sessionSlotReqJitter)
}

func newSessionSlot() sessionSlot {
	now := time.Now()
	return sessionSlot{
		sessionID: uuid.New().String(),
		cch:       randomCCH(),
		createdAt: now,
		expire:    now.Add(randomSlotTTL()),
		requests:  0,
		maxReqs:   randomSlotMaxReqs(),
	}
}

// randomCCH generates a random 5-char hex string, used once per session slot.
func randomCCH() string {
	b := make([]byte, 3)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)[:5]
}

func (s *sessionSlot) alive(now time.Time) bool {
	return s.expire.After(now) && s.requests < s.maxReqs
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
			if s.alive(now) {
				allDead = false
				break
			}
		}
		if allDead {
			delete(sessionPools, key)
		}
	}
}

// desiredSlots returns how many concurrent slots this pool should have
// based on recent request frequency.
func (p *sessionPool) desiredSlots(now time.Time) int {
	// Estimate RPM from the measurement window.
	elapsed := now.Sub(p.windowStart)
	if elapsed < 30*time.Second {
		// Not enough data yet — keep current size.
		return len(p.slots)
	}
	rpm := float64(p.windowReqs) / elapsed.Minutes()

	if rpm > float64(rpmThreshold2) {
		return 3
	}
	if rpm > float64(rpmThreshold1) {
		return 2
	}
	return 1
}

// recordRequest updates the RPM measurement window.
func (p *sessionPool) recordRequest(now time.Time) {
	// Reset window if it has expired.
	if now.Sub(p.windowStart) > rpmWindowDuration {
		p.windowStart = now
		p.windowReqs = 0
	}
	p.windowReqs++
}

// pickSessionID selects a session_id from the pool for this API key.
// At low RPM (<= 10), it behaves like a single terminal: one session_id that
// lives for 1-3 hours. At higher RPM, additional "terminals" are opened to
// spread the load, like a developer working in multiple terminal windows.
func pickSessionID(apiKey string) string {
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])
	now := time.Now()

	sessionPoolCleanOnce.Do(startSessionPoolCleanup)

	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()

	pool, ok := sessionPools[cacheKey]
	if !ok {
		pool = &sessionPool{
			slots:       []sessionSlot{newSessionSlot()},
			windowStart: now,
		}
		sessionPools[cacheKey] = pool
	}

	// Record this request for RPM tracking.
	pool.recordRequest(now)

	// Refresh any dead slots.
	for i := range pool.slots {
		if !pool.slots[i].alive(now) {
			pool.slots[i] = newSessionSlot()
		}
	}

	// Adapt pool size based on request frequency.
	desired := pool.desiredSlots(now)
	for len(pool.slots) < desired {
		pool.slots = append(pool.slots, newSessionSlot())
	}
	// Shrink: only remove excess slots that are dead (don't kill active sessions).
	if len(pool.slots) > desired {
		live := pool.slots[:0]
		for i := range pool.slots {
			if len(live) < desired || pool.slots[i].requests > 0 {
				live = append(live, pool.slots[i])
			}
		}
		// Keep at least desired slots.
		for len(live) < desired {
			live = append(live, newSessionSlot())
		}
		pool.slots = live
	}

	// Pick a random live slot.
	idx := rand.IntN(len(pool.slots))
	pool.slots[idx].requests++

	// Cache the selected slot's cch for generateCCH() to pick up.
	lastPickedCCHMu.Lock()
	lastPickedCCH[cacheKey] = pool.slots[idx].cch
	lastPickedCCHMu.Unlock()

	return pool.slots[idx].sessionID
}

// getLastPickedCCH returns the cch associated with the most recently picked
// session slot for the given API key. Falls back to a random cch if no session
// has been picked yet (e.g., cloaking is off or apiKey is empty).
func getLastPickedCCH(apiKey string) string {
	if apiKey == "" {
		return randomCCH()
	}
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])

	lastPickedCCHMu.RLock()
	cch, ok := lastPickedCCH[cacheKey]
	lastPickedCCHMu.RUnlock()
	if ok && cch != "" {
		return cch
	}
	return randomCCH()
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
// and a session_id picked from an adaptive pool of concurrent sessions.
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

package executor

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
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
	busy      bool // true while a request is in-flight
}

// sessionPool holds concurrent session slots for one API key.
type sessionPool struct {
	slots []sessionSlot
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

	// Default number of concurrent session slots when RPM is not configured.
	defaultSlotCount = 10

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


// pickSessionID selects a session_id from the pool for this API key.
// slotCount determines the number of concurrent slots; 0 uses defaultSlotCount.
func pickSessionID(apiKey string, slotCount int) string {
	if slotCount <= 0 {
		slotCount = defaultSlotCount
	}
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])
	now := time.Now()

	sessionPoolCleanOnce.Do(startSessionPoolCleanup)

	sessionPoolsMu.Lock()

	pool, ok := sessionPools[cacheKey]
	if !ok {
		slots := make([]sessionSlot, slotCount)
		for i := range slots {
			slots[i] = newSessionSlot()
		}
		pool = &sessionPool{
			slots: slots,
		}
		sessionPools[cacheKey] = pool
	}

	// Refresh any dead slots.
	for i := range pool.slots {
		if !pool.slots[i].alive(now) {
			pool.slots[i] = newSessionSlot()
		}
	}

	// Adapt pool size.
	desired := slotCount
	for len(pool.slots) < desired {
		pool.slots = append(pool.slots, newSessionSlot())
	}
	// Shrink: only remove excess slots that are not busy.
	if len(pool.slots) > desired {
		live := pool.slots[:0]
		for i := range pool.slots {
			if len(live) < desired || pool.slots[i].busy {
				live = append(live, pool.slots[i])
			}
		}
		for len(live) < desired {
			live = append(live, newSessionSlot())
		}
		pool.slots = live
	}

	// Pick an idle slot. Collect all idle indices and pick randomly.
	var idle []int
	for i := range pool.slots {
		if !pool.slots[i].busy {
			idle = append(idle, i)
		}
	}
	if len(idle) == 0 {
		// All slots busy — wait for one to become available (timeout 10s).
		slotCount := len(pool.slots)
		sessionPoolsMu.Unlock()
		log.Warnf("[session-pool] key=%.16s all %d slots busy, waiting...", cacheKey, slotCount)
		deadline := time.Now().Add(10 * time.Second)
		for {
			time.Sleep(100 * time.Millisecond)
			sessionPoolsMu.Lock()
			idle = nil
			for i := range pool.slots {
				if !pool.slots[i].busy {
					idle = append(idle, i)
				}
			}
			if len(idle) > 0 {
				break // lock held
			}
			if time.Now().After(deadline) {
				log.Errorf("[session-pool] key=%.16s timeout after 10s, all %d slots busy", cacheKey, slotCount)
				sessionPoolsMu.Unlock()
				return ""
			}
			sessionPoolsMu.Unlock()
		}
	}
	// Lock is held here.
	idx := idle[rand.IntN(len(idle))]
	pool.slots[idx].busy = true
	pool.slots[idx].requests++

	// Log all session IDs in this pool for auditing.
	var sids []string
	for i, s := range pool.slots {
		marker := " "
		if i == idx {
			marker = "*"
		}
		status := "idle"
		if s.busy {
			status = "busy"
		}
		sids = append(sids, fmt.Sprintf("[%s%s %s reqs=%d]", marker, s.sessionID, status, s.requests))
	}
	log.Infof("[session-pool] key=%.16s slots=%d picked=%d sessions=%s", cacheKey, len(pool.slots), idx, strings.Join(sids, ", "))

	// Cache the selected slot's cch for generateCCH() to pick up.
	lastPickedCCHMu.Lock()
	lastPickedCCH[cacheKey] = pool.slots[idx].cch
	lastPickedCCHMu.Unlock()

	sid := pool.slots[idx].sessionID
	sessionPoolsMu.Unlock()
	return sid
}

// ReleaseSessionSlot marks the slot that owns sessionID as idle so it can
// accept new requests. Call this when the upstream response finishes.
func ReleaseSessionSlot(apiKey string, sessionID string) {
	if apiKey == "" || sessionID == "" {
		return
	}
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])

	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()

	pool, ok := sessionPools[cacheKey]
	if !ok {
		return
	}
	for i := range pool.slots {
		if pool.slots[i].sessionID == sessionID {
			pool.slots[i].busy = false
			return
		}
	}
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

// PickSessionID returns a session_id from the pool without marking the slot as busy.
// Used for session init and telemetry where no slot reservation is needed.
func PickSessionID(apiKey string) string {
	if apiKey == "" {
		return uuid.New().String()
	}
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])

	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()

	pool, ok := sessionPools[cacheKey]
	if !ok {
		return uuid.New().String()
	}
	// Return the first alive slot's sessionID without marking busy.
	now := time.Now()
	for _, s := range pool.slots {
		if s.alive(now) {
			return s.sessionID
		}
	}
	return uuid.New().String()
}

// cachedUserID builds a complete user_id with stable device_id/account_uuid
// and a session_id picked from an adaptive pool of concurrent sessions.
// If realDeviceID or realAccountUUID is provided (from persisted OAuth auth file),
// it is used instead of the derived value for maximum authenticity.
func cachedUserID(apiKey string, realDeviceID string, realAccountUUID string, slotCount int) (string, string) {
	return cachedUserIDWithSession(apiKey, realDeviceID, realAccountUUID, "", slotCount)
}

// cachedUserIDWithSession is like cachedUserID but allows preserving a client-provided
// session_id. When clientSessionID is non-empty, it is used directly instead of the
// pool-selected value.
// cachedUserIDWithSession returns the JSON user_id string and the pool-picked sessionID
// so callers can release the slot after the request completes.
func cachedUserIDWithSession(apiKey string, realDeviceID string, realAccountUUID string, clientSessionID string, slotCount int) (string, string) {
	if apiKey == "" {
		return generateFakeUserID(), ""
	}

	deviceID := DeriveDeviceID(apiKey)
	if realDeviceID != "" {
		deviceID = realDeviceID
	}

	accountUUID := DeriveAccountUUID(apiKey)
	if realAccountUUID != "" {
		accountUUID = realAccountUUID
	}

	sessionID := pickSessionID(apiKey, slotCount)
	if sessionID == "" && clientSessionID == "" {
		// Pool timeout — no slot available.
		return "", ""
	}
	if clientSessionID != "" {
		sessionID = clientSessionID
	}

	payload := userIDPayload{
		DeviceID:    deviceID,
		AccountUUID: accountUUID,
		SessionID:   sessionID,
	}
	data, _ := json.Marshal(payload)
	return string(data), sessionID
}

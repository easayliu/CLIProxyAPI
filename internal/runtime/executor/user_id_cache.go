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
	sessionID   string
	deviceID    string // per-slot device identity (64-hex), simulates different machines
	cch         string // stable per-session billing hash (5-char hex)
	createdAt   time.Time
	expire      time.Time
	requests    int  // requests served so far
	maxReqs     int  // per-slot cap (randomized)
	busy        bool // true while a request is in-flight
	initialized bool // true after session init has been fired for this sessionID
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
	// Session slot lifetime: each slot lives 6–12 hours (randomized, fixed at creation).
	// Real developers keep a terminal open for an entire work day. Must align with
	// SessionInitEmitter TTL (also 6-12h) so a slot does not expire and get replaced
	// while the init emitter still thinks the old sessionID is valid.
	sessionSlotBaseTTL = 6 * time.Hour
	sessionSlotJitter  = 6 * time.Hour // total range: 6–12 hours

	// Per-slot request cap: 200–500 requests before the slot retires.
	// A real CLI session in a long coding day easily does 300+ requests.
	sessionSlotBaseReqs  = 200
	sessionSlotReqJitter = 300 // total range: 200–499

	// Default number of concurrent session slots when RPM is not configured.
	// Real users typically run 1-3 terminal windows on a single device.
	// Higher values (e.g. 10) create a detectable fingerprint.
	defaultSlotCount = 3

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

// newSessionSlotWithDevice creates a session slot with a deterministic per-slot deviceID
// derived from the pool's base seed and the slot index.
func newSessionSlotWithDevice(baseSeed string, slotIndex int) sessionSlot {
	s := newSessionSlot()
	s.deviceID = deriveSlotDeviceID(baseSeed, slotIndex)
	return s
}

// deriveSlotDeviceID generates a stable device_id for a specific slot.
// Each slot gets its own device identity to simulate different machines.
func deriveSlotDeviceID(baseSeed string, slotIndex int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("slot-device:%s:%d", baseSeed, slotIndex)))
	return hex.EncodeToString(h[:])
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


// pickSessionID selects a session_id and its per-slot deviceID from the pool for this API key.
// slotCount determines the number of concurrent slots; 0 uses defaultSlotCount.
// Returns (sessionID, deviceID). deviceID is the per-slot 64-hex device identity.
func pickSessionID(apiKey string, slotCount int) (string, string) {
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
			slots[i] = newSessionSlotWithDevice(cacheKey, i)
		}
		pool = &sessionPool{
			slots: slots,
		}
		sessionPools[cacheKey] = pool
	}

	// Refresh any dead slots.
	for i := range pool.slots {
		if !pool.slots[i].alive(now) {
			pool.slots[i] = newSessionSlotWithDevice(cacheKey, i)
		}
	}

	// Adapt pool size.
	desired := slotCount
	for len(pool.slots) < desired {
		pool.slots = append(pool.slots, newSessionSlotWithDevice(cacheKey, len(pool.slots)))
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
			live = append(live, newSessionSlotWithDevice(cacheKey, len(live)))
		}
		pool.slots = live
	}

	// Pick an idle + initialized slot. Only slots that have been through
	// session init are eligible for actual requests.
	var idle []int
	for i := range pool.slots {
		if !pool.slots[i].busy && pool.slots[i].initialized {
			idle = append(idle, i)
		}
	}
	if len(idle) == 0 {
		// No initialized+idle slots — wait for one to become available (timeout 10s).
		slotCount := len(pool.slots)
		sessionPoolsMu.Unlock()
		log.Warnf("[session-pool] key=%.16s no initialized+idle slots (%d total), waiting...", cacheKey, slotCount)
		deadline := time.Now().Add(10 * time.Second)
		for {
			time.Sleep(100 * time.Millisecond)
			sessionPoolsMu.Lock()
			idle = nil
			for i := range pool.slots {
				if !pool.slots[i].busy && pool.slots[i].initialized {
					idle = append(idle, i)
				}
			}
			if len(idle) > 0 {
				break // lock held
			}
			if time.Now().After(deadline) {
				log.Errorf("[session-pool] key=%.16s timeout after 10s, no initialized+idle slots", cacheKey)
				sessionPoolsMu.Unlock()
				return "", ""
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
		sids = append(sids, fmt.Sprintf("[%s%s dev=%.8s %s reqs=%d]", marker, s.sessionID, s.deviceID, status, s.requests))
	}
	log.Infof("[session-pool] key=%.16s slots=%d picked=%d sessions=%s", cacheKey, len(pool.slots), idx, strings.Join(sids, ", "))

	// Cache the selected slot's cch for generateCCH() to pick up.
	lastPickedCCHMu.Lock()
	lastPickedCCH[cacheKey] = pool.slots[idx].cch
	lastPickedCCHMu.Unlock()

	sid := pool.slots[idx].sessionID
	did := pool.slots[idx].deviceID
	sessionPoolsMu.Unlock()
	return sid, did
}

// EnsureSessionPool creates the session pool for the given key if it doesn't
// exist yet, so that subsequent PickSessionID calls return a pool-backed
// sessionID instead of a random UUID. Must be called before PickSessionID
// on the first request for a given key.
func EnsureSessionPool(apiKey string, slotCount int) {
	if apiKey == "" {
		return
	}
	if slotCount <= 0 {
		slotCount = defaultSlotCount
	}
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])

	sessionPoolCleanOnce.Do(startSessionPoolCleanup)

	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()

	if _, ok := sessionPools[cacheKey]; ok {
		return // already exists
	}
	slots := make([]sessionSlot, slotCount)
	for i := range slots {
		slots[i] = newSessionSlotWithDevice(cacheKey, i)
	}
	sessionPools[cacheKey] = &sessionPool{slots: slots}
	log.Infof("[session-pool] key=%.16s pre-initialized %d slots", cacheKey, slotCount)
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

// pickSpecificSessionID finds the slot with the given sessionID, marks it busy,
// increments its request count, and returns (sessionID, deviceID).
// Returns ("", "") if the slot is not found, not alive, not initialized, or busy.
// Used to ensure the request body uses the same slot (and deviceID) as session init.
func pickSpecificSessionID(apiKey string, targetSessionID string) (string, string) {
	if apiKey == "" || targetSessionID == "" {
		return "", ""
	}
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])

	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()

	pool, ok := sessionPools[cacheKey]
	if !ok {
		return "", ""
	}

	now := time.Now()
	for i := range pool.slots {
		if pool.slots[i].sessionID == targetSessionID {
			if !pool.slots[i].alive(now) || !pool.slots[i].initialized || pool.slots[i].busy {
				return "", ""
			}
			pool.slots[i].busy = true
			pool.slots[i].requests++

			// Update cch cache so billing header stays consistent.
			lastPickedCCHMu.Lock()
			lastPickedCCH[cacheKey] = pool.slots[i].cch
			lastPickedCCHMu.Unlock()

			return pool.slots[i].sessionID, pool.slots[i].deviceID
		}
	}
	return "", ""
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

// PickSessionID returns a (sessionID, deviceID) from the pool without marking the slot as busy.
// Prioritizes uninitialized alive slots so that session init can be triggered for them.
// If all alive slots are initialized, returns the first alive slot (init will be skipped).
func PickSessionID(apiKey string) (string, string) {
	if apiKey == "" {
		return uuid.New().String(), ""
	}
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])

	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()

	pool, ok := sessionPools[cacheKey]
	if !ok {
		return uuid.New().String(), ""
	}
	now := time.Now()
	// Prefer the first uninitialized alive slot (needs init).
	for _, s := range pool.slots {
		if s.alive(now) && !s.initialized {
			return s.sessionID, s.deviceID
		}
	}
	// All alive slots are initialized; return the first alive one.
	for _, s := range pool.slots {
		if s.alive(now) {
			return s.sessionID, s.deviceID
		}
	}
	return uuid.New().String(), ""
}

// MarkSessionInitialized marks the slot with the given sessionID as initialized.
// Called after EmitSessionInit completes so the slot becomes eligible for requests.
func MarkSessionInitialized(apiKey string, sessionID string) {
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
			pool.slots[i].initialized = true
			return
		}
	}
}

// cachedUserID builds a complete user_id with stable device_id/account_uuid
// and a session_id picked from an adaptive pool of concurrent sessions.
// If realDeviceID or realAccountUUID is provided (from persisted OAuth auth file),
// it is used instead of the derived value for maximum authenticity.
func cachedUserID(apiKey string, realDeviceID string, realAccountUUID string, slotCount int) (string, string) {
	return cachedUserIDWithSession(apiKey, realDeviceID, realAccountUUID, "", slotCount)
}

// cachedUserIDWithSession is like cachedUserID but allows preserving a client-provided
// session_id. When clientSessionID is non-empty, the function first tries to lock
// that specific slot (to keep deviceID consistent with session init). If the slot is
// unavailable, it falls back to picking a random idle+initialized slot.
// cachedUserIDWithSession returns the JSON user_id string and the pool-picked sessionID
// so callers can release the slot after the request completes.
func cachedUserIDWithSession(apiKey string, realDeviceID string, realAccountUUID string, clientSessionID string, slotCount int) (string, string) {
	if apiKey == "" {
		return generateFakeUserID(), ""
	}

	accountUUID := DeriveAccountUUID(apiKey)
	if realAccountUUID != "" {
		accountUUID = realAccountUUID
	}

	var sessionID, slotDeviceID string
	if clientSessionID != "" {
		// Try to lock the specific slot that was used for session init,
		// so deviceID in the request body matches the session init deviceID.
		sessionID, slotDeviceID = pickSpecificSessionID(apiKey, clientSessionID)
	}
	if sessionID == "" {
		// No hint, or the hinted slot was unavailable — pick any idle slot.
		sessionID, slotDeviceID = pickSessionID(apiKey, slotCount)
		if sessionID == "" {
			return "", ""
		}
	}

	// Per-slot deviceID takes priority over account-level or real deviceID.
	deviceID := slotDeviceID
	if deviceID == "" {
		deviceID = DeriveDeviceID(apiKey)
		if realDeviceID != "" {
			deviceID = realDeviceID
		}
	}

	payload := userIDPayload{
		DeviceID:    deviceID,
		AccountUUID: accountUUID,
		SessionID:   sessionID,
	}
	data, _ := json.Marshal(payload)
	return string(data), sessionID
}

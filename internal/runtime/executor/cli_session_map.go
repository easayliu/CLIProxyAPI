package executor

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// cliSessionSlot is a lightweight session slot for CLI client session mapping.
// Unlike the full sessionSlot in user_id_cache.go, this has no busy/initialized
// tracking because multiple CLI clients can share the same mapped session.
type cliSessionSlot struct {
	sessionID string
	expireAt  time.Time
}

// cliSessionPool holds a fixed number of session slots per auth.
type cliSessionPool struct {
	slots []cliSessionSlot
}

var (
	cliSessionPools   = make(map[string]*cliSessionPool)
	cliSessionPoolsMu sync.Mutex
)

const (
	// cliSessionDefaultSlots is the default number of session slots per auth.
	// Simulates a user with 3 terminal windows open — common for developers.
	cliSessionDefaultSlots = 3

	// cliSessionBaseTTL + jitter gives each slot a 6–12 hour lifetime,
	// matching realistic CLI session durations (a work day).
	cliSessionBaseTTL    = 6 * time.Hour
	cliSessionJitterSecs = 6 * 60 * 60 // 6 hours in seconds
)

func newCLISessionSlot() cliSessionSlot {
	jitter := time.Duration(rand.Int64N(int64(cliSessionJitterSecs))) * time.Second
	return cliSessionSlot{
		sessionID: uuid.New().String(),
		expireAt:  time.Now().Add(cliSessionBaseTTL + jitter),
	}
}

// MapCLISessionID maps a client's session_id to a pooled session_id for the
// given auth key. The mapping is consistent: the same clientSessionID always
// maps to the same pool slot (via hash). Expired slots are refreshed lazily.
//
// Parameters:
//   - authKey: stable auth identifier (e.g. auth.ID or stablePoolKey)
//   - clientSessionID: the session_id from the CLI client's request
//   - slotCount: number of pool slots (0 uses default)
//
// Returns the mapped pool session_id.
func MapCLISessionID(authKey string, clientSessionID string, slotCount int) string {
	if authKey == "" || clientSessionID == "" {
		return clientSessionID
	}
	if slotCount <= 0 {
		slotCount = cliSessionDefaultSlots
	}

	cliSessionPoolsMu.Lock()
	defer cliSessionPoolsMu.Unlock()

	pool, ok := cliSessionPools[authKey]
	if !ok {
		pool = &cliSessionPool{
			slots: make([]cliSessionSlot, slotCount),
		}
		for i := range pool.slots {
			pool.slots[i] = newCLISessionSlot()
		}
		cliSessionPools[authKey] = pool
		log.Infof("[cli-session-map] auth=%.16s initialized %d slots", authKey, slotCount)
	}

	// Adapt pool size if config changed.
	for len(pool.slots) < slotCount {
		pool.slots = append(pool.slots, newCLISessionSlot())
	}

	// Refresh expired slots.
	now := time.Now()
	for i := range pool.slots {
		if now.After(pool.slots[i].expireAt) {
			pool.slots[i] = newCLISessionSlot()
		}
	}

	// Consistent hash: same clientSessionID always picks the same slot.
	h := sha256.Sum256([]byte(clientSessionID))
	idx := int(binary.BigEndian.Uint32(h[:4])) % len(pool.slots)

	mapped := pool.slots[idx].sessionID
	log.Debugf("[cli-session-map] auth=%.16s client=%s -> slot[%d]=%s", authKey, clientSessionID, idx, mapped)
	return mapped
}

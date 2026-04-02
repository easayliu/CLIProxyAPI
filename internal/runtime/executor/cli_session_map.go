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

// ---------------------------------------------------------------------------
// Legacy fixed-slot pool — used by applyCloaking for non-CLI clients.
// ---------------------------------------------------------------------------

// cliSessionSlot is a lightweight session slot for CLI client session mapping.
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
	cliSessionDefaultSlots = 3
	cliSessionBaseTTL      = 6 * time.Hour
	cliSessionJitterSecs   = 6 * 60 * 60 // 6 hours in seconds
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
// This is used by applyCloaking for non-CLI clients. CLI clients use
// AcquireCLISession instead.
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

	for len(pool.slots) < slotCount {
		pool.slots = append(pool.slots, newCLISessionSlot())
	}

	now := time.Now()
	for i := range pool.slots {
		if now.After(pool.slots[i].expireAt) {
			pool.slots[i] = newCLISessionSlot()
		}
	}

	h := sha256.Sum256([]byte(clientSessionID))
	idx := int(binary.BigEndian.Uint32(h[:4])) % len(pool.slots)

	mapped := pool.slots[idx].sessionID
	log.Debugf("[cli-session-map] auth=%.16s client=%s -> slot[%d]=%s", authKey, clientSessionID, idx, mapped)
	return mapped
}

// ---------------------------------------------------------------------------
// Single rotating session — used by CLI clients.
//
// Real Claude Code shares one session_id across the main agent and all
// subagents. The session rotates periodically (30–45 min) to avoid
// long-lived sessions that look abnormal.
// ---------------------------------------------------------------------------

const (
	// primarySessionBaseTTL + jitter = 30–45 min per session.
	primarySessionBaseTTL = 30 * time.Minute
	primarySessionJitter  = 15 * time.Minute
)

type authSession struct {
	sessionID string
	expireAt  time.Time
}

type authSessionPool struct {
	mu      sync.Mutex
	current *authSession
}

var (
	authSessionPools   = make(map[string]*authSessionPool)
	authSessionPoolsMu sync.Mutex
)

func getOrCreateAuthPool(authKey string) *authSessionPool {
	authSessionPoolsMu.Lock()
	defer authSessionPoolsMu.Unlock()
	pool, ok := authSessionPools[authKey]
	if !ok {
		pool = &authSessionPool{}
		authSessionPools[authKey] = pool
	}
	return pool
}

func newAuthSession() *authSession {
	jitter := time.Duration(rand.Int64N(int64(primarySessionJitter)))
	return &authSession{
		sessionID: uuid.New().String(),
		expireAt:  time.Now().Add(primarySessionBaseTTL + jitter),
	}
}

// noopRelease is a no-op release function for callers that don't acquire a session.
func noopRelease() {}

// AcquireCLISession returns the current session_id for the given auth,
// rotating to a new one when the TTL expires. All concurrent requests
// (including subagent requests) share the same session_id, matching real
// Claude Code behavior.
//
// The returned release function is currently a no-op but kept in the
// interface for future extensibility.
func AcquireCLISession(authKey string) (string, func()) {
	if authKey == "" {
		return "", noopRelease
	}

	pool := getOrCreateAuthPool(authKey)
	pool.mu.Lock()
	defer pool.mu.Unlock()

	now := time.Now()
	if pool.current == nil || now.After(pool.current.expireAt) {
		pool.current = newAuthSession()
		log.Infof("[cli-session] auth=%.16s new session %s (expires %s)",
			authKey, pool.current.sessionID[:8], pool.current.expireAt.Format("15:04:05"))
	}

	return pool.current.sessionID, noopRelease
}

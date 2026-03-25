package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

const (
	sessionSigTTL     = 4 * time.Hour
	sessionSigCleanup = 15 * time.Minute
	sessionSigHashLen = 16
)

var (
	sessionSigMu          sync.RWMutex
	sessionSigStore       = make(map[string]*sessionSigCache)
	sessionSigCleanupOnce sync.Once
)

// sessionSigCache holds thinking-block signatures for a single session.
type sessionSigCache struct {
	mu      sync.RWMutex
	entries map[string]string // textHash → signature
	updated time.Time
}

func hashThinkingText(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])[:sessionSigHashLen]
}

// sigCacheKey combines sessionID and poolKey so that when auth changes
// (e.g. token refresh to a different account), cached signatures from
// the old auth are not reused — they are session-bound and invalid.
func sigCacheKey(sessionID, poolKey string) string {
	return sessionID + "|" + poolKey
}

func cacheSessionSignature(sessionID, poolKey, thinkingText, signature string) {
	if sessionID == "" || thinkingText == "" || signature == "" || len(signature) < 50 {
		return
	}

	sessionSigCleanupOnce.Do(startSessionSigCleanup)

	key := sigCacheKey(sessionID, poolKey)
	textHash := hashThinkingText(thinkingText)

	sessionSigMu.RLock()
	sc, ok := sessionSigStore[key]
	sessionSigMu.RUnlock()

	if !ok {
		sessionSigMu.Lock()
		sc, ok = sessionSigStore[key]
		if !ok {
			sc = &sessionSigCache{entries: make(map[string]string)}
			sessionSigStore[key] = sc
		}
		sessionSigMu.Unlock()
	}

	sc.mu.Lock()
	sc.entries[textHash] = signature
	sc.updated = time.Now()
	sc.mu.Unlock()
}

func getSessionSignature(sessionID, poolKey, thinkingText string) string {
	if sessionID == "" || thinkingText == "" {
		return ""
	}

	key := sigCacheKey(sessionID, poolKey)
	textHash := hashThinkingText(thinkingText)

	sessionSigMu.RLock()
	sc, ok := sessionSigStore[key]
	sessionSigMu.RUnlock()

	if !ok {
		return ""
	}

	sc.mu.RLock()
	sig := sc.entries[textHash]
	sc.mu.RUnlock()
	return sig
}

func startSessionSigCleanup() {
	go func() {
		ticker := time.NewTicker(sessionSigCleanup)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			sessionSigMu.Lock()
			for k, sc := range sessionSigStore {
				sc.mu.RLock()
				expired := now.Sub(sc.updated) > sessionSigTTL
				sc.mu.RUnlock()
				if expired {
					delete(sessionSigStore, k)
				}
			}
			sessionSigMu.Unlock()
		}
	}()
}

// streamSignatureObserver observes SSE stream lines and caches thinking
// signatures per session. It is safe for concurrent use within a single
// stream (one goroutine writes).
type streamSignatureObserver struct {
	sessionID string
	poolKey   string
	blocks    map[int]*thinkingAccumulator
}

type thinkingAccumulator struct {
	text      strings.Builder
	signature string
}

func newStreamSignatureObserver(sessionID, poolKey string) *streamSignatureObserver {
	return &streamSignatureObserver{
		sessionID: sessionID,
		poolKey:   poolKey,
		blocks:    make(map[int]*thinkingAccumulator),
	}
}

// ObserveLine parses an SSE line and caches any thinking signature found.
func (o *streamSignatureObserver) ObserveLine(line []byte) {
	if o.sessionID == "" {
		return
	}

	s := string(line)
	if !strings.HasPrefix(s, "data: ") {
		return
	}
	data := s[6:]

	eventType := gjson.Get(data, "type").String()
	switch eventType {
	case "content_block_start":
		blockType := gjson.Get(data, "content_block.type").String()
		if blockType == "thinking" {
			idx := int(gjson.Get(data, "index").Int())
			o.blocks[idx] = &thinkingAccumulator{}
		}
	case "content_block_delta":
		idx := int(gjson.Get(data, "index").Int())
		acc, ok := o.blocks[idx]
		if !ok {
			return
		}
		deltaType := gjson.Get(data, "delta.type").String()
		switch deltaType {
		case "thinking_delta":
			acc.text.WriteString(gjson.Get(data, "delta.thinking").String())
		case "signature_delta":
			acc.signature = gjson.Get(data, "delta.signature").String()
		}
	case "content_block_stop":
		idx := int(gjson.Get(data, "index").Int())
		acc, ok := o.blocks[idx]
		if !ok {
			return
		}
		if acc.text.Len() > 0 && acc.signature != "" {
			cacheSessionSignature(o.sessionID, o.poolKey, acc.text.String(), acc.signature)
		}
		delete(o.blocks, idx)
	}
}

// extractSessionSignature extracts thinking signature from a non-streaming
// JSON response body and caches it.
func extractSessionSignature(sessionID, poolKey string, body []byte) {
	if sessionID == "" {
		return
	}
	content := gjson.GetBytes(body, "content")
	if !content.IsArray() {
		return
	}
	for _, block := range content.Array() {
		if block.Get("type").String() != "thinking" {
			continue
		}
		text := block.Get("thinking").String()
		sig := block.Get("signature").String()
		if text != "" && sig != "" {
			cacheSessionSignature(sessionID, poolKey, text, sig)
		}
	}
}

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func resetSessionPool() {
	sessionPoolsMu.Lock()
	sessionPools = make(map[string]*sessionPool)
	sessionPoolsMu.Unlock()
}

// releaseAll marks all slots in the pool as idle.
func releaseAll(apiKey string) {
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])
	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()
	if pool, ok := sessionPools[cacheKey]; ok {
		for i := range pool.slots {
			pool.slots[i].busy = false
		}
	}
}

// initializeAll marks all slots in the pool as initialized so they become
// eligible for pickSessionID selection. In production this is done by
// MarkSessionInitialized after session init telemetry completes.
func initializeAll(apiKey string) {
	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])
	sessionPoolsMu.Lock()
	defer sessionPoolsMu.Unlock()
	if pool, ok := sessionPools[cacheKey]; ok {
		for i := range pool.slots {
			pool.slots[i].initialized = true
		}
	}
}

// ensurePoolAndInit creates the pool and marks all slots as initialized.
// Convenience wrapper for tests that need a ready-to-use pool.
func ensurePoolAndInit(apiKey string) {
	EnsureSessionPool(apiKey, 0)
	initializeAll(apiKey)
}

func TestCachedUserID_ReusesWithinPool(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-1")

	first, _ := cachedUserID("api-key-1", "", "", 0)
	if first == "" {
		t.Fatal("expected generated user_id to be non-empty")
	}
	releaseAll("api-key-1")

	// Multiple calls should produce valid user_ids (may differ due to pool rotation)
	for i := 0; i < 5; i++ {
		id, _ := cachedUserID("api-key-1", "", "", 0)
		if id == "" {
			t.Fatalf("iteration %d: expected non-empty user_id", i)
		}
		releaseAll("api-key-1")
	}
}

func TestCachedUserID_PoolUsesMultipleSessions(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-multi")

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, _ := cachedUserID("api-key-multi", "", "", 0)
		sid := extractSessionID(id)
		if sid == "" {
			t.Fatalf("iteration %d: empty session_id", i)
		}
		seen[sid] = true
		releaseAll("api-key-multi")
	}

	if len(seen) < 2 {
		t.Fatalf("expected multiple session_ids from pool, got %d unique", len(seen))
	}
	t.Logf("saw %d unique session_ids across 100 requests", len(seen))
}

func TestCachedUserID_DefaultFiveSlots(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-five")

	// First call uses the pre-initialized pool.
	_, _ = cachedUserID("api-key-five", "", "", 0)
	releaseAll("api-key-five")

	h := sha256.Sum256([]byte("session-pool:api-key-five"))
	cacheKey := hex.EncodeToString(h[:])
	sessionPoolsMu.Lock()
	pool := sessionPools[cacheKey]
	slotCount := len(pool.slots)
	sessionPoolsMu.Unlock()

	if slotCount != defaultSlotCount {
		t.Fatalf("expected %d slots, got %d", defaultSlotCount, slotCount)
	}
}

func TestCachedUserID_IsScopedByAPIKey(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-1")
	ensurePoolAndInit("api-key-2")

	first, _ := cachedUserID("api-key-1", "", "", 0)
	releaseAll("api-key-1")
	second, _ := cachedUserID("api-key-2", "", "", 0)
	releaseAll("api-key-2")

	if first == second {
		t.Fatalf("expected different API keys to have different user_ids, got %q", first)
	}
}

func TestCachedUserID_StableAccountUUID(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-stable")

	// account_uuid should be stable across calls for the same API key.
	// device_id varies per slot (per-slot deviceID), so we only check account_uuid stability.
	var accountIDs []string
	for i := 0; i < 10; i++ {
		id, _ := cachedUserID("api-key-stable", "", "", 0)
		var p userIDPayload
		if err := json.Unmarshal([]byte(id), &p); err != nil {
			t.Fatalf("failed to parse user_id: %v", err)
		}
		accountIDs = append(accountIDs, p.AccountUUID)
		releaseAll("api-key-stable")
	}

	for i := 1; i < len(accountIDs); i++ {
		if accountIDs[i] != accountIDs[0] {
			t.Fatalf("account_uuid changed: %q vs %q", accountIDs[0], accountIDs[i])
		}
	}
}

func TestCachedUserID_PerSlotDeviceIDTakesPriority(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-real")

	// With per-slot deviceID, the slot's deviceID takes priority over realDeviceID.
	realDevice := "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd" + "aabbccdd"
	id, _ := cachedUserID("api-key-real", realDevice, "", 0)
	releaseAll("api-key-real")

	var p userIDPayload
	if err := json.Unmarshal([]byte(id), &p); err != nil {
		t.Fatalf("failed to parse user_id: %v", err)
	}
	if p.DeviceID == realDevice {
		t.Fatalf("expected per-slot deviceID to take priority over realDeviceID, but got realDeviceID")
	}
	if len(p.DeviceID) != 64 {
		t.Fatalf("expected 64-char hex deviceID, got %d chars: %q", len(p.DeviceID), p.DeviceID)
	}
}

func TestCachedUserID_UsesRealAccountUUID(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-real")

	realAccount := "12345678-1234-1234-1234-123456789abc"
	id, _ := cachedUserID("api-key-real", "", realAccount, 0)
	releaseAll("api-key-real")

	var p userIDPayload
	if err := json.Unmarshal([]byte(id), &p); err != nil {
		t.Fatalf("failed to parse user_id: %v", err)
	}
	if p.AccountUUID != realAccount {
		t.Fatalf("expected account_uuid=%q, got %q", realAccount, p.AccountUUID)
	}
}

func TestCachedUserID_BusySlotsNotReused(t *testing.T) {
	resetSessionPool()
	ensurePoolAndInit("api-key-busy")

	// Acquire all slots without releasing.
	sids := make(map[string]bool)
	for i := 0; i < defaultSlotCount; i++ {
		_, sid := cachedUserID("api-key-busy", "", "", 0)
		if sid == "" {
			t.Fatalf("slot %d: expected non-empty sessionID", i)
		}
		sids[sid] = true
	}
	// All 5 should be unique (each picked an idle slot).
	if len(sids) != defaultSlotCount {
		t.Fatalf("expected %d unique session_ids, got %d", defaultSlotCount, len(sids))
	}
	releaseAll("api-key-busy")
}

// TestPerSlotDeviceID verifies that each slot in a pool gets a unique, stable,
// 64-char hex deviceID derived from the pool seed and slot index.
func TestPerSlotDeviceID(t *testing.T) {
	resetSessionPool()

	const apiKey = "api-key-per-slot-device"
	const slotCount = 3
	EnsureSessionPool(apiKey, slotCount)

	h := sha256.Sum256([]byte("session-pool:" + apiKey))
	cacheKey := hex.EncodeToString(h[:])

	// Collect deviceIDs from all slots.
	sessionPoolsMu.Lock()
	pool := sessionPools[cacheKey]
	if pool == nil {
		sessionPoolsMu.Unlock()
		t.Fatal("pool not created")
	}
	deviceIDs := make([]string, len(pool.slots))
	for i, s := range pool.slots {
		deviceIDs[i] = s.deviceID
	}
	sessionPoolsMu.Unlock()

	if len(deviceIDs) != slotCount {
		t.Fatalf("expected %d slots, got %d", slotCount, len(deviceIDs))
	}

	// Each slot should have a different deviceID.
	seen := make(map[string]bool)
	for i, did := range deviceIDs {
		if len(did) != 64 {
			t.Fatalf("slot %d: expected 64-char hex deviceID, got %d chars: %q", i, len(did), did)
		}
		// Verify it's valid hex.
		if _, err := hex.DecodeString(did); err != nil {
			t.Fatalf("slot %d: deviceID is not valid hex: %v", i, err)
		}
		if seen[did] {
			t.Fatalf("slot %d: duplicate deviceID %q", i, did)
		}
		seen[did] = true
	}

	// Verify stability: recreating a pool with same key should produce same deviceIDs.
	resetSessionPool()
	EnsureSessionPool(apiKey, slotCount)

	sessionPoolsMu.Lock()
	pool2 := sessionPools[cacheKey]
	deviceIDs2 := make([]string, len(pool2.slots))
	for i, s := range pool2.slots {
		deviceIDs2[i] = s.deviceID
	}
	sessionPoolsMu.Unlock()

	for i := range deviceIDs {
		if deviceIDs[i] != deviceIDs2[i] {
			t.Fatalf("slot %d: deviceID not stable across pool recreations: %q vs %q", i, deviceIDs[i], deviceIDs2[i])
		}
	}
}

// TestPickSessionID_ReturnsDeviceID verifies that PickSessionID returns the
// per-slot deviceID along with the sessionID.
func TestPickSessionID_ReturnsDeviceID(t *testing.T) {
	resetSessionPool()

	const apiKey = "api-key-pick-device"
	EnsureSessionPool(apiKey, 3)

	sid, did := PickSessionID(apiKey)
	if sid == "" {
		t.Fatal("expected non-empty sessionID")
	}
	if did == "" {
		t.Fatal("expected non-empty deviceID from PickSessionID")
	}
	if len(did) != 64 {
		t.Fatalf("expected 64-char hex deviceID, got %d chars: %q", len(did), did)
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

// TestConcurrent10Requests simulates 10 concurrent requests with default 10 slots.
// Each "request" holds a slot for 500ms (simulating upstream latency), then releases.
// All 10 should acquire a slot immediately without waiting.
func TestConcurrent10Requests(t *testing.T) {
	resetSessionPool()

	const numReqs = 10
	const apiKey = "api-key-concurrent"
	EnsureSessionPool(apiKey, numReqs)
	initializeAll(apiKey)

	var wg sync.WaitGroup
	results := make([]string, numReqs) // collected session IDs
	errors := make([]error, numReqs)
	start := make(chan struct{}) // synchronize goroutine start

	for i := 0; i < numReqs; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // wait for all goroutines to be ready

			uid, sid := cachedUserID(apiKey, "", "", numReqs)
			if uid == "" {
				errors[idx] = fmt.Errorf("goroutine %d: got empty uid (timeout)", idx)
				return
			}
			results[idx] = sid

			// Simulate upstream request latency
			time.Sleep(500 * time.Millisecond)

			// Release slot
			ReleaseSessionSlot(apiKey, sid)
		}(i)
	}

	// Fire all goroutines at once
	t0 := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(t0)

	// Check errors
	for i, err := range errors {
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}

	// All 10 should have gotten a slot (non-empty session ID)
	sids := make(map[string]int)
	for i, sid := range results {
		if sid == "" {
			t.Fatalf("request %d: empty session ID", i)
		}
		sids[sid]++
	}

	t.Logf("10 concurrent requests completed in %v, used %d unique sessions", elapsed, len(sids))

	// Should complete in ~500ms (parallel), not ~5s (serial).
	// Allow generous 2s margin for CI slowness.
	if elapsed > 2*time.Second {
		t.Fatalf("expected ~500ms (parallel), took %v — slots may be blocking", elapsed)
	}

	// With 10 slots and 10 concurrent requests, each should get a unique slot.
	if len(sids) != numReqs {
		t.Logf("session distribution: %v", sids)
		t.Fatalf("expected %d unique sessions, got %d", numReqs, len(sids))
	}
}

// TestConcurrent15Requests_10Slots simulates 15 concurrent requests with 10 slots.
// First 10 should acquire immediately, remaining 5 must wait for a release.
func TestConcurrent15Requests_10Slots(t *testing.T) {
	resetSessionPool()

	const numReqs = 15
	const apiKey = "api-key-overflow"
	EnsureSessionPool(apiKey, 10)
	initializeAll(apiKey)

	var wg sync.WaitGroup
	results := make([]string, numReqs)
	errors := make([]error, numReqs)
	start := make(chan struct{})

	for i := 0; i < numReqs; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start

			uid, sid := cachedUserID(apiKey, "", "", 10)
			if uid == "" {
				errors[idx] = fmt.Errorf("goroutine %d: got empty uid (timeout)", idx)
				return
			}
			results[idx] = sid

			// First batch holds for 300ms, then releases
			time.Sleep(300 * time.Millisecond)
			ReleaseSessionSlot(apiKey, sid)
		}(i)
	}

	t0 := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(t0)

	for i, err := range errors {
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
	}

	// All 15 should succeed (5 waited for release, then got a slot)
	for i, sid := range results {
		if sid == "" {
			t.Fatalf("request %d: empty session ID", i)
		}
	}

	// Should take ~600ms (two waves), not 10s+ (serial timeout)
	if elapsed > 3*time.Second {
		t.Fatalf("expected ~600ms (two waves), took %v", elapsed)
	}

	t.Logf("15 requests with 10 slots completed in %v", elapsed)
}

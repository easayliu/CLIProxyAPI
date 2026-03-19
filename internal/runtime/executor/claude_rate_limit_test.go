package executor

import (
	"net/http"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

// resetClaudeRateLimiter clears the global rate limiter state between tests.
func resetClaudeRateLimiter() {
	claudeRateLimiter.Lock()
	defer claudeRateLimiter.Unlock()
	claudeRateLimiter.requests = make(map[string][]time.Time)
}

func makeAuthWithRPM(id string, rpm int) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:       id,
		Provider: "claude",
		Metadata: map[string]any{"rpm": rpm},
	}
}

func TestCheckClaudeRateLimit_NilAuth(t *testing.T) {
	resetClaudeRateLimiter()
	if err := checkClaudeRateLimit(nil); err != nil {
		t.Fatalf("expected nil error for nil auth, got %v", err)
	}
}

func TestCheckClaudeRateLimit_NoRPMSet(t *testing.T) {
	resetClaudeRateLimiter()
	auth := &cliproxyauth.Auth{
		ID:       "test-no-rpm",
		Provider: "claude",
		Metadata: map[string]any{},
	}
	if err := checkClaudeRateLimit(auth); err != nil {
		t.Fatalf("expected nil error when rpm not set, got %v", err)
	}
}

func TestCheckClaudeRateLimit_AllowsWithinLimit(t *testing.T) {
	resetClaudeRateLimiter()
	auth := makeAuthWithRPM("test-within-limit", 5)

	for i := 0; i < 5; i++ {
		if err := checkClaudeRateLimit(auth); err != nil {
			t.Fatalf("request %d should be allowed, got %v", i+1, err)
		}
	}
}

func TestCheckClaudeRateLimit_BlocksOverLimit(t *testing.T) {
	resetClaudeRateLimiter()
	auth := makeAuthWithRPM("test-over-limit", 3)

	// First 3 should succeed
	for i := 0; i < 3; i++ {
		if err := checkClaudeRateLimit(auth); err != nil {
			t.Fatalf("request %d should be allowed, got %v", i+1, err)
		}
	}

	// 4th should be blocked
	err := checkClaudeRateLimit(auth)
	if err == nil {
		t.Fatal("expected rate limit error on 4th request, got nil")
	}

	se, ok := err.(cliproxyexecutor.StatusError)
	if !ok {
		t.Fatalf("expected StatusError, got %T: %v", err, err)
	}
	if se.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", se.StatusCode())
	}
}

func TestCheckClaudeRateLimit_RecoverAfterWindow(t *testing.T) {
	resetClaudeRateLimiter()
	auth := makeAuthWithRPM("test-recover", 2)

	// Fill up the limit
	for i := 0; i < 2; i++ {
		if err := checkClaudeRateLimit(auth); err != nil {
			t.Fatalf("request %d should be allowed, got %v", i+1, err)
		}
	}

	// Should be blocked
	if err := checkClaudeRateLimit(auth); err == nil {
		t.Fatal("expected rate limit error, got nil")
	}

	// Manually expire timestamps by shifting them back > 1 minute
	authIndex := auth.EnsureIndex()
	claudeRateLimiter.Lock()
	for i := range claudeRateLimiter.requests[authIndex] {
		claudeRateLimiter.requests[authIndex][i] = time.Now().Add(-2 * time.Minute)
	}
	claudeRateLimiter.Unlock()

	// Should be allowed again after timestamps expired
	if err := checkClaudeRateLimit(auth); err != nil {
		t.Fatalf("expected nil error after window expiry, got %v", err)
	}
}

func TestCheckClaudeRateLimit_IsolatedPerAuth(t *testing.T) {
	resetClaudeRateLimiter()
	auth1 := makeAuthWithRPM("test-auth-1", 2)
	auth2 := makeAuthWithRPM("test-auth-2", 2)

	// Fill up auth1
	for i := 0; i < 2; i++ {
		if err := checkClaudeRateLimit(auth1); err != nil {
			t.Fatalf("auth1 request %d should be allowed, got %v", i+1, err)
		}
	}

	// auth1 should be blocked
	if err := checkClaudeRateLimit(auth1); err == nil {
		t.Fatal("auth1 should be rate limited")
	}

	// auth2 should still be allowed
	if err := checkClaudeRateLimit(auth2); err != nil {
		t.Fatalf("auth2 should not be affected by auth1 limit, got %v", err)
	}
}

func TestCheckClaudeRateLimit_RPMLimitFromMetadata(t *testing.T) {
	resetClaudeRateLimiter()

	// Test "rpm_limit" key as alternative
	auth := &cliproxyauth.Auth{
		ID:       "test-rpm-limit-key",
		Provider: "claude",
		Metadata: map[string]any{"rpm_limit": 1},
	}

	if err := checkClaudeRateLimit(auth); err != nil {
		t.Fatalf("first request should be allowed, got %v", err)
	}

	if err := checkClaudeRateLimit(auth); err == nil {
		t.Fatal("second request should be blocked with rpm_limit=1")
	}
}

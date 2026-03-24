package executor

import (
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func makeAuthWithRPM(id string, rpm int) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:       id,
		Provider: "claude",
		Metadata: map[string]any{"rpm": rpm},
	}
}

func TestCheckClaudeRateLimit_NilAuth(t *testing.T) {
	if err := checkClaudeRateLimit(nil); err != nil {
		t.Fatalf("expected nil error for nil auth, got %v", err)
	}
}

func TestCheckClaudeRateLimit_NoRPMSet(t *testing.T) {
	auth := &cliproxyauth.Auth{
		ID:       "test-no-rpm",
		Provider: "claude",
		Metadata: map[string]any{},
	}
	if err := checkClaudeRateLimit(auth); err != nil {
		t.Fatalf("expected nil error when rpm not set, got %v", err)
	}
}

func TestCheckClaudeRateLimit_NeverReturns429(t *testing.T) {
	// The new rate limiter should NEVER return an error (it blocks or proceeds).
	// This prevents conductor cooldown spirals.
	auth := makeAuthWithRPM("test-never-429", 1000)
	for i := 0; i < 10; i++ {
		if err := checkClaudeRateLimit(auth); err != nil {
			t.Fatalf("request %d: rate limiter should never return error, got %v", i+1, err)
		}
	}
}

func TestCheckClaudeRateLimit_RecordsToGlobalTracker(t *testing.T) {
	auth := makeAuthWithRPM("test-records-tracker", 1000)
	authID := auth.EnsureIndex()

	before := cliproxyauth.GlobalRPMTracker.CurrentRPM(authID)
	_ = checkClaudeRateLimit(auth)
	after := cliproxyauth.GlobalRPMTracker.CurrentRPM(authID)

	if after <= before {
		t.Fatalf("expected RPM to increase after request, before=%d after=%d", before, after)
	}
}

func TestCheckClaudeRateLimit_RecordsEvenWithoutRPMLimit(t *testing.T) {
	// Even without an explicit RPM limit, requests should be recorded
	// so the RPM-aware selector can see the load.
	auth := &cliproxyauth.Auth{
		ID:       "test-no-limit-records",
		Provider: "claude",
		Metadata: map[string]any{},
	}
	authID := auth.EnsureIndex()

	before := cliproxyauth.GlobalRPMTracker.CurrentRPM(authID)
	_ = checkClaudeRateLimit(auth)
	after := cliproxyauth.GlobalRPMTracker.CurrentRPM(authID)

	if after <= before {
		t.Fatalf("expected RPM to increase even without limit, before=%d after=%d", before, after)
	}
}

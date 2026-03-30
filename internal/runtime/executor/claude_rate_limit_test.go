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

func TestCheckClaudeRateLimit_DefaultRPM(t *testing.T) {
	// Without explicit rpm, defaultRPM (10) applies.
	auth := &cliproxyauth.Auth{
		ID:       "test-default-rpm",
		Provider: "claude",
		Metadata: map[string]any{},
	}
	// First defaultRPM requests should pass.
	for i := 0; i < defaultRPM; i++ {
		if err := checkClaudeRateLimit(auth); err != nil {
			t.Fatalf("request %d: expected pass within default RPM, got %v", i+1, err)
		}
	}
	// Next should be rejected immediately.
	if err := checkClaudeRateLimit(auth); err == nil {
		t.Fatalf("expected 429 after exceeding default RPM")
	}
}

func TestCheckClaudeRateLimit_Returns429OnExceed(t *testing.T) {
	auth := makeAuthWithRPM("test-429-exceed", 3)
	for i := 0; i < 3; i++ {
		if err := checkClaudeRateLimit(auth); err != nil {
			t.Fatalf("request %d: expected pass, got %v", i+1, err)
		}
	}
	// 4th request should be rejected immediately (non-blocking).
	err := checkClaudeRateLimit(auth)
	if err == nil {
		t.Fatalf("expected 429 after exceeding RPM limit")
	}
	if se, ok := err.(statusErr); !ok || se.code != 429 {
		t.Fatalf("expected statusErr with code 429, got %v", err)
	}
}

func TestCheckClaudeRateLimit_RecordsToGlobalTracker(t *testing.T) {
	auth := makeAuthWithRPM("test-records-tracker-v2", 1000)
	authID := auth.EnsureIndex()

	before := cliproxyauth.GlobalRPMTracker.CurrentRPM(authID)
	_ = checkClaudeRateLimit(auth)
	after := cliproxyauth.GlobalRPMTracker.CurrentRPM(authID)

	if after <= before {
		t.Fatalf("expected RPM to increase after request, before=%d after=%d", before, after)
	}
}

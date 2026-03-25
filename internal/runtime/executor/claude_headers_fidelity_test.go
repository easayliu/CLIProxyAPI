package executor

// Tests in this file are derived from real MITM captures of Claude Code CLI v2.1.83.
// Capture: /private/tmp/proxy_captures/20260325_230810
// Each test references the specific capture sequence number it validates against.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	"github.com/tidwall/gjson"
)

// ---------------------------------------------------------------------------
// Reference data: exact values from MITM capture 20260325_230810
// ---------------------------------------------------------------------------

// captureMainHeaders are the exact headers from capture #010 (opus-4-6 main
// conversation, streaming, with tools + effort).
var captureMainHeaders = map[string]string{
	"Accept":                                   "application/json",
	"User-Agent":                               "claude-cli/2.1.83 (external, cli)",
	"X-Stainless-Arch":                         "arm64",
	"X-Stainless-Lang":                         "js",
	"X-Stainless-OS":                           "MacOS",
	"X-Stainless-Package-Version":              "0.74.0",
	"X-Stainless-Retry-Count":                  "0",
	"X-Stainless-Runtime":                      "node",
	"X-Stainless-Runtime-Version":              "v23.7.0",
	"X-Stainless-Timeout":                      "600",
	"accept-encoding":                          "br, gzip, deflate",
	"accept-language":                           "*",
	"anthropic-dangerous-direct-browser-access": "true",
	"anthropic-version":                         "2023-06-01",
	"connection":                                "keep-alive",
	"content-type":                              "application/json",
	"sec-fetch-mode":                            "cors",
	"x-app":                                     "cli",
}

// captureMainBetas is the exact anthropic-beta value from capture #010.
// opus-4-6 main conversation with tools + effort (no structured-outputs, no context-management).
var captureMainBetas = "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20,effort-2025-11-24"

// captureQuotaBetas is from capture #007 (haiku quota check, no tools).
var captureQuotaBetas = "oauth-2025-04-20,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05"

// captureTitleBetas is from capture #009 (haiku title gen, with structured-outputs).
var captureTitleBetas = "oauth-2025-04-20,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05,structured-outputs-2025-12-15"

// captureBillingHeader is from capture #010 system[0].
const captureBillingHeader = "x-anthropic-billing-header: cc_version=2.1.83.c50; cc_entrypoint=cli; cch=00000;"

// captureAgentBlock is from capture #010 system[1].
const captureAgentBlock = "You are Claude Code, Anthropic's official CLI for Claude."

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// capturedRequest stores headers + body from a fake upstream server.
type capturedRequest struct {
	Headers http.Header
	Body    []byte
}

func newCaptureServer(t *testing.T, streaming bool) (*httptest.Server, *capturedRequest) {
	t.Helper()
	cap := &capturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.Headers = r.Header.Clone()
		cap.Body, _ = io.ReadAll(r.Body)
		if streaming {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-4-6\",\"content\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n"))
			w.Write([]byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"))
			w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n"))
			w.Write([]byte("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"))
			w.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n"))
			w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
		}
	}))
	return server, cap
}

func newTestAuth(serverURL string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": serverURL,
	}}
}

func drainStream(t *testing.T, result *cliproxyexecutor.StreamResult) {
	t.Helper()
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
	}
}

func assertHeader(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

func assertBetasExact(t *testing.T, got, want string) {
	t.Helper()
	gotParts := strings.Split(got, ",")
	wantParts := strings.Split(want, ",")
	for i, w := range wantParts {
		if i >= len(gotParts) {
			t.Errorf("anthropic-beta missing [%d]: want %q\n  full: %s", i, w, got)
			continue
		}
		if strings.TrimSpace(gotParts[i]) != strings.TrimSpace(w) {
			t.Errorf("anthropic-beta[%d] = %q, want %q\n  got:  %s\n  want: %s", i, gotParts[i], w, got, want)
		}
	}
	if len(gotParts) > len(wantParts) {
		t.Errorf("anthropic-beta has %d extra betas: %s", len(gotParts)-len(wantParts), got)
	}
}

// ---------------------------------------------------------------------------
// Tests: Main conversation request headers (capture #010)
// ---------------------------------------------------------------------------

// TestCapture010_StreamingHeaders verifies that a streaming opus-4-6 request
// produces headers matching capture #010 exactly.
func TestCapture010_StreamingHeaders(t *testing.T) {
	server, cap := newCaptureServer(t, true)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	// opus-4-6 with tools + effort, matching capture #010
	payload := []byte(`{
		"model":"claude-opus-4-6",
		"stream":true,
		"max_tokens":64000,
		"messages":[{"role":"user","content":[{"type":"text","text":"nihao"}]}],
		"output_config":{"effort":"medium"},
		"tools":[{"name":"ToolSearch","input_schema":{"type":"object"}}]
	}`)

	result, err := executor.ExecuteStream(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	drainStream(t, result)

	// Verify each header from capture #010
	for name, want := range captureMainHeaders {
		got := cap.Headers.Get(name)
		if got == "" {
			// Try lowercase lookup for raw headers set via r.Header["key"]
			if vals, ok := cap.Headers[name]; ok && len(vals) > 0 {
				got = vals[0]
			}
		}
		assertHeader(t, name, got, want)
	}

	// Verify betas match capture #010 exactly
	beta := cap.Headers.Get("Anthropic-Beta")
	if beta == "" {
		if vals, ok := cap.Headers["anthropic-beta"]; ok && len(vals) > 0 {
			beta = vals[0]
		}
	}
	assertBetasExact(t, beta, captureMainBetas)
}

// TestCapture010_NonStreamingHeaders verifies non-streaming produces identical
// headers (Accept-Encoding, User-Agent etc. should not differ).
func TestCapture010_NonStreamingHeaders(t *testing.T) {
	server, cap := newCaptureServer(t, false)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	payload := []byte(`{
		"model":"claude-opus-4-6",
		"max_tokens":64000,
		"messages":[{"role":"user","content":[{"type":"text","text":"nihao"}]}],
		"output_config":{"effort":"medium"},
		"tools":[{"name":"ToolSearch","input_schema":{"type":"object"}}]
	}`)

	_, err := executor.Execute(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	assertHeader(t, "Accept", cap.Headers.Get("Accept"), "application/json")

	enc := cap.Headers.Get("Accept-Encoding")
	if enc == "" {
		if vals, ok := cap.Headers["accept-encoding"]; ok && len(vals) > 0 {
			enc = vals[0]
		}
	}
	assertHeader(t, "accept-encoding", enc, "br, gzip, deflate")
}

// TestCapture010_StreamNonStreamIdentical verifies stream and non-stream
// produce identical Accept/Accept-Encoding (real CLI does not vary these).
func TestCapture010_StreamNonStreamIdentical(t *testing.T) {
	var streamEnc, nonStreamEnc string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc := r.Header.Get("Accept-Encoding")
		if enc == "" {
			if vals, ok := r.Header["accept-encoding"]; ok && len(vals) > 0 {
				enc = vals[0]
			}
		}
		body, _ := io.ReadAll(r.Body)
		if gjson.GetBytes(body, "stream").Bool() {
			streamEnc = enc
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		} else {
			nonStreamEnc = enc
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
		}
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := newTestAuth(server.URL)

	// Non-streaming
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Streaming
	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	drainStream(t, result)

	if streamEnc != nonStreamEnc {
		t.Errorf("Accept-Encoding differs: stream=%q non-stream=%q", streamEnc, nonStreamEnc)
	}
}

// ---------------------------------------------------------------------------
// Tests: Body structure (captures #010, #007)
// ---------------------------------------------------------------------------

// TestCapture010_SystemArray verifies system prompt structure matches capture #010:
//   system[0]: billing header (no cache_control)
//   system[1]: agent block (cache_control: ephemeral)
//   system[2+]: user content (cache_control: ephemeral)
func TestCapture010_SystemArray(t *testing.T) {
	server, cap := newCaptureServer(t, false)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	payload := []byte(`{
		"model":"claude-opus-4-6",
		"max_tokens":64000,
		"messages":[{"role":"user","content":[{"type":"text","text":"nihao"}]}]
	}`)

	_, err := executor.Execute(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// system[0]: billing header
	sys0 := gjson.GetBytes(cap.Body, "system.0.text").String()
	if !strings.HasPrefix(sys0, "x-anthropic-billing-header:") {
		t.Fatalf("system[0] not billing header: %s", sys0)
	}
	if !strings.Contains(sys0, "cc_version=2.1.83.") {
		t.Errorf("billing header missing cc_version=2.1.83: %s", sys0)
	}
	if !strings.Contains(sys0, "cc_entrypoint=cli") {
		t.Errorf("billing header missing cc_entrypoint=cli: %s", sys0)
	}
	if !strings.Contains(sys0, "cch=00000") {
		t.Errorf("billing header should have cch=00000: %s", sys0)
	}
	// Capture #010: system[0] has NO cache_control
	if gjson.GetBytes(cap.Body, "system.0.cache_control").Exists() {
		t.Error("system[0] should not have cache_control (matches capture #010)")
	}

	// system[1]: agent block
	sys1 := gjson.GetBytes(cap.Body, "system.1.text").String()
	if sys1 != captureAgentBlock {
		t.Errorf("system[1] = %q, want %q", sys1, captureAgentBlock)
	}
	// Capture #010: system[1] has cache_control: ephemeral
	sys1CC := gjson.GetBytes(cap.Body, "system.1.cache_control.type").String()
	if sys1CC != "ephemeral" {
		t.Errorf("system[1].cache_control.type = %q, want \"ephemeral\"", sys1CC)
	}
}

// TestCapture010_Temperature verifies temperature is always set to 1
// (matching capture #010 body).
func TestCapture010_Temperature(t *testing.T) {
	server, cap := newCaptureServer(t, false)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	// Client sends temperature:0.5 — proxy should override to 1
	payload := []byte(`{
		"model":"claude-opus-4-6",
		"max_tokens":1024,
		"temperature":0.5,
		"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]
	}`)

	_, err := executor.Execute(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	temp := gjson.GetBytes(cap.Body, "temperature").Float()
	if temp != 1.0 {
		t.Errorf("temperature = %v, want 1 (capture #010)", temp)
	}
}

// TestCapture010_UserIDFormat verifies metadata.user_id is JSON with
// device_id, account_uuid, session_id (matching capture #010 body).
func TestCapture010_UserIDFormat(t *testing.T) {
	server, cap := newCaptureServer(t, false)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	payload := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	userIDStr := gjson.GetBytes(cap.Body, "metadata.user_id").String()
	if userIDStr == "" {
		t.Fatal("metadata.user_id is empty")
	}

	var uid userIDPayload
	if err := json.Unmarshal([]byte(userIDStr), &uid); err != nil {
		t.Fatalf("user_id not valid JSON: %v\nraw: %s", err, userIDStr)
	}
	if len(uid.DeviceID) != 64 {
		t.Errorf("device_id length = %d, want 64", len(uid.DeviceID))
	}
	if !strings.Contains(uid.AccountUUID, "-") || len(uid.AccountUUID) != 36 {
		t.Errorf("account_uuid not UUID format: %s", uid.AccountUUID)
	}
	if !strings.Contains(uid.SessionID, "-") || len(uid.SessionID) != 36 {
		t.Errorf("session_id not UUID format: %s", uid.SessionID)
	}
}

// ---------------------------------------------------------------------------
// Tests: Beta variations per model (captures #007, #009, #010)
// ---------------------------------------------------------------------------

// TestCapture010_OpusBetas verifies opus-4-6 betas match capture #010 exactly.
// Key: opus always includes context-1m-2025-08-07.
func TestCapture010_OpusBetas(t *testing.T) {
	server, cap := newCaptureServer(t, false)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	payload := []byte(`{
		"model":"claude-opus-4-6",
		"max_tokens":64000,
		"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
		"output_config":{"effort":"medium"},
		"tools":[{"name":"ToolSearch","input_schema":{"type":"object"}}]
	}`)

	_, err := executor.Execute(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	beta := cap.Headers.Get("Anthropic-Beta")
	if beta == "" {
		if vals, ok := cap.Headers["anthropic-beta"]; ok && len(vals) > 0 {
			beta = vals[0]
		}
	}
	assertBetasExact(t, beta, captureMainBetas)

	if !strings.Contains(beta, "context-1m-2025-08-07") {
		t.Errorf("opus-4-6 must include context-1m (capture #010), got: %s", beta)
	}
}

// TestCapture_SonnetNoBetas verifies sonnet-4-6 does NOT include context-1m
// (not an opus model).
func TestCapture_SonnetNoBetas(t *testing.T) {
	server, cap := newCaptureServer(t, false)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	payload := []byte(`{
		"model":"claude-sonnet-4-6",
		"max_tokens":1024,
		"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
		"output_config":{"effort":"medium"},
		"tools":[{"name":"ToolSearch","input_schema":{"type":"object"}}]
	}`)

	_, err := executor.Execute(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	beta := cap.Headers.Get("Anthropic-Beta")
	if beta == "" {
		if vals, ok := cap.Headers["anthropic-beta"]; ok && len(vals) > 0 {
			beta = vals[0]
		}
	}
	if strings.Contains(beta, "context-1m") {
		t.Errorf("sonnet should not have context-1m, got: %s", beta)
	}
}

// TestCapture_Opus1MSuffix verifies opus-4-6[1m] also includes context-1m.
func TestCapture_Opus1MSuffix(t *testing.T) {
	server, cap := newCaptureServer(t, false)
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	payload := []byte(`{
		"model":"claude-opus-4-6[1m]",
		"max_tokens":64000,
		"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
		"output_config":{"effort":"medium"},
		"tools":[{"name":"ToolSearch","input_schema":{"type":"object"}}]
	}`)

	_, err := executor.Execute(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-opus-4-6[1m]",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	beta := cap.Headers.Get("Anthropic-Beta")
	if beta == "" {
		if vals, ok := cap.Headers["anthropic-beta"]; ok && len(vals) > 0 {
			beta = vals[0]
		}
	}
	if !strings.Contains(beta, "context-1m-2025-08-07") {
		t.Errorf("opus-4-6[1m] must include context-1m, got: %s", beta)
	}
}

// TestCapture007_QuotaCheckBetas verifies that a minimal haiku request
// (no tools, no effort, no structured-outputs) produces only the base betas,
// matching capture #007.
func TestCapture007_QuotaCheckBetas(t *testing.T) {
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-haiku-4-5-20251001","role":"assistant","content":[{"type":"text","text":"#"}],"usage":{"input_tokens":8,"output_tokens":1}}`))
	}))
	defer server.Close()

	// Test the session init quota check directly (not through executor pipeline).
	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireQuotaCheck(client, "sk-ant-oat01-test", true, "session-123", "device-abc", "account-xyz")

	beta := gotHeaders.Get("Anthropic-Beta")
	assertBetasExact(t, beta, captureQuotaBetas)
}

// ---------------------------------------------------------------------------
// Tests: Session init request headers (captures #001-#006, #011)
// ---------------------------------------------------------------------------

// TestCapture001_AccountSettings verifies fireAccountSettings headers match capture #001.
func TestCapture001_AccountSettings(t *testing.T) {
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireAccountSettings(client, "sk-ant-oat01-test", true)

	assertHeader(t, "Accept", gotHeaders.Get("Accept"), "application/json, text/plain, */*")
	assertHeader(t, "Accept-Encoding", gotHeaders.Get("Accept-Encoding"), "gzip, compress, deflate, br")
	assertHeader(t, "Connection", gotHeaders.Get("Connection"), "close")
	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "claude-code/2.1.83")
	// anthropic-beta set via raw header (lowercase key in Go map)
	beta := gotHeaders.Get("Anthropic-Beta")
	if beta == "" {
		if vals, ok := gotHeaders["anthropic-beta"]; ok && len(vals) > 0 {
			beta = vals[0]
		}
	}
	assertHeader(t, "anthropic-beta", beta, "oauth-2025-04-20")
	assertHeader(t, "Authorization", gotHeaders.Get("Authorization"), "Bearer sk-ant-oat01-test")
}

// TestCapture002_Grove verifies fireGrove headers match capture #002.
func TestCapture002_Grove(t *testing.T) {
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireGrove(client, "sk-ant-oat01-test", true, "cli")

	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "claude-cli/2.1.83 (external, cli)")
	assertHeader(t, "Accept", gotHeaders.Get("Accept"), "application/json, text/plain, */*")
	assertHeader(t, "Accept-Encoding", gotHeaders.Get("Accept-Encoding"), "gzip, compress, deflate, br")
	assertHeader(t, "Connection", gotHeaders.Get("Connection"), "close")
}

// TestCapture003_Bootstrap verifies fireBootstrap headers match capture #003.
func TestCapture003_Bootstrap(t *testing.T) {
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireBootstrap(client, "sk-ant-oat01-test", true)

	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "claude-code/2.1.83")
	assertHeader(t, "Content-Type", gotHeaders.Get("Content-Type"), "application/json")
	assertHeader(t, "Connection", gotHeaders.Get("Connection"), "close")
}

// TestCapture004_PenguinMode verifies firePenguinMode headers match capture #004.
func TestCapture004_PenguinMode(t *testing.T) {
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.firePenguinMode(client, "sk-ant-oat01-test", true)

	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "axios/1.13.6")
	assertHeader(t, "Accept-Encoding", gotHeaders.Get("Accept-Encoding"), "gzip, compress, deflate, br")
	assertHeader(t, "Connection", gotHeaders.Get("Connection"), "close")
}

// TestCapture005_MCPServers verifies fireMCPServers headers match capture #005.
func TestCapture005_MCPServers(t *testing.T) {
	var gotHeaders http.Header
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[],"next_page":null}`))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireMCPServers(client, "sk-ant-oat01-test", true)

	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "axios/1.13.6")
	assertHeader(t, "Content-Type", gotHeaders.Get("Content-Type"), "application/json")
	assertHeader(t, "Connection", gotHeaders.Get("Connection"), "close")
	// anthropic-beta should be mcp-servers-2025-12-04 (not oauth)
	beta := gotHeaders.Get("Anthropic-Beta")
	if beta == "" {
		if vals, ok := gotHeaders["anthropic-beta"]; ok && len(vals) > 0 {
			beta = vals[0]
		}
	}
	assertHeader(t, "anthropic-beta", beta, "mcp-servers-2025-12-04")
	ver := gotHeaders.Get("Anthropic-Version")
	if ver == "" {
		if vals, ok := gotHeaders["anthropic-version"]; ok && len(vals) > 0 {
			ver = vals[0]
		}
	}
	assertHeader(t, "anthropic-version", ver, "2023-06-01")
	if gotURL != "/v1/mcp_servers?limit=1000" {
		t.Errorf("URL = %q, want /v1/mcp_servers?limit=1000", gotURL)
	}
}

// TestCapture006_MCPRegistry verifies fireMCPRegistry headers match capture #006.
func TestCapture006_MCPRegistry(t *testing.T) {
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireMCPRegistry(client)

	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "axios/1.13.6")
	assertHeader(t, "Accept-Encoding", gotHeaders.Get("Accept-Encoding"), "gzip, compress, deflate, br")
	assertHeader(t, "Connection", gotHeaders.Get("Connection"), "close")
	// No auth header for mcp-registry (capture #006 has no Authorization)
	if gotHeaders.Get("Authorization") != "" {
		t.Error("mcp-registry should not have Authorization header (capture #006)")
	}
}

// TestCapture007_QuotaCheckHeaders verifies fireQuotaCheck headers match capture #007.
func TestCapture007_QuotaCheckHeaders(t *testing.T) {
	var gotHeaders http.Header
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-haiku-4-5-20251001","role":"assistant","content":[{"type":"text","text":"#"}],"usage":{"input_tokens":8,"output_tokens":1}}`))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireQuotaCheck(client, "sk-ant-oat01-test", true, "session-123", "device-abc", "account-xyz")

	// Stainless SDK style headers (capture #007)
	assertHeader(t, "Accept", gotHeaders.Get("Accept"), "application/json")
	assertHeader(t, "Accept-Encoding", gotHeaders.Get("Accept-Encoding"), "br, gzip, deflate")
	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "claude-cli/2.1.83 (external, cli)")
	assertHeader(t, "X-Stainless-Lang", gotHeaders.Get("X-Stainless-Lang"), "js")
	assertHeader(t, "X-Stainless-Runtime", gotHeaders.Get("X-Stainless-Runtime"), "node")
	assertHeader(t, "X-Stainless-Runtime-Version", gotHeaders.Get("X-Stainless-Runtime-Version"), "v23.7.0")
	assertHeader(t, "X-App", gotHeaders.Get("X-App"), "cli")
	assertHeader(t, "Connection", gotHeaders.Get("Connection"), "keep-alive")

	// Body: model=haiku, max_tokens=1
	model := gjson.GetBytes(gotBody, "model").String()
	if model != "claude-haiku-4-5-20251001" {
		t.Errorf("quota check model = %q, want claude-haiku-4-5-20251001", model)
	}
	maxTokens := gjson.GetBytes(gotBody, "max_tokens").Int()
	if maxTokens != 1 {
		t.Errorf("quota check max_tokens = %d, want 1", maxTokens)
	}
}

// TestCapture009_TitleGenHeaders verifies fireTitleGeneration headers match capture #009.
func TestCapture009_TitleGenHeaders(t *testing.T) {
	var gotHeaders http.Header
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	si := &SessionInitEmitter{upstream: server.URL, sessions: make(map[string]*initSession)}
	client := &http.Client{}
	si.fireTitleGeneration(client, "sk-ant-oat01-test", true, "session-123", "device-abc", "account-xyz")

	// Stainless SDK style headers (capture #009)
	assertHeader(t, "Accept", gotHeaders.Get("Accept"), "application/json")
	assertHeader(t, "Accept-Encoding", gotHeaders.Get("Accept-Encoding"), "br, gzip, deflate")
	assertHeader(t, "User-Agent", gotHeaders.Get("User-Agent"), "claude-cli/2.1.83 (external, cli)")
	assertHeader(t, "X-Stainless-Runtime-Version", gotHeaders.Get("X-Stainless-Runtime-Version"), "v23.7.0")

	// Beta must include structured-outputs (capture #009)
	beta := gotHeaders.Get("Anthropic-Beta")
	assertBetasExact(t, beta, captureTitleBetas)

	// Body structure
	model := gjson.GetBytes(gotBody, "model").String()
	if model != "claude-haiku-4-5-20251001" {
		t.Errorf("title gen model = %q, want claude-haiku-4-5-20251001", model)
	}
	if !gjson.GetBytes(gotBody, "stream").Bool() {
		t.Error("title gen should be streaming")
	}
	if gjson.GetBytes(gotBody, "max_tokens").Int() != 32000 {
		t.Errorf("title gen max_tokens = %d, want 32000", gjson.GetBytes(gotBody, "max_tokens").Int())
	}
	// system[0] billing header with .be2 build hash (capture #009)
	sys0 := gjson.GetBytes(gotBody, "system.0.text").String()
	if !strings.Contains(sys0, "cc_version=2.1.83.be2") {
		t.Errorf("title gen billing header should use .be2 build hash: %s", sys0)
	}
	// output_config.format.type = json_schema
	formatType := gjson.GetBytes(gotBody, "output_config.format.type").String()
	if formatType != "json_schema" {
		t.Errorf("title gen output_config.format.type = %q, want json_schema", formatType)
	}
}

// ---------------------------------------------------------------------------
// Tests: Gzip decompression (functional)
// ---------------------------------------------------------------------------

// TestCapture_GzipCompressedSSEStream verifies the proxy correctly handles
// gzip-compressed SSE from upstream (real scenario with Accept-Encoding: br, gzip, deflate).
func TestCapture_GzipCompressedSSEStream(t *testing.T) {
	ssePayload := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"usage":{"input_tokens":10,"output_tokens":0}}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello world"}}`,
		"",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`,
		"",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}, "\n")

	var compressed bytes.Buffer
	gzw := gzip.NewWriter(&compressed)
	gzw.Write([]byte(ssePayload))
	gzw.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressed.Bytes())
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	result, err := executor.ExecuteStream(context.Background(), newTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"say hi"}]}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}

	var allChunks []byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
		allChunks = append(allChunks, chunk.Payload...)
	}

	combined := string(allChunks)
	if !strings.Contains(combined, "message_start") {
		t.Error("missing message_start in decompressed stream")
	}
	if !strings.Contains(combined, "hello world") {
		t.Error("missing 'hello world' text_delta in decompressed stream")
	}
	if !strings.Contains(combined, "message_stop") {
		t.Error("missing message_stop in decompressed stream")
	}
}

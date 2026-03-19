package executor

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

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/tidwall/gjson"
)

// capturedHeaders stores all headers received by a fake upstream server.
type capturedHeaders struct {
	Accept         string
	AcceptEncoding string
	AnthropicBeta  string
	UserAgent      string
	ContentType    string
	XApp           string
	Version        string
	DangerousDBA   string
	StainlessLang  string
	StainlessRT    string
}

func captureFromRequest(r *http.Request) capturedHeaders {
	return capturedHeaders{
		Accept:         r.Header.Get("Accept"),
		AcceptEncoding: r.Header.Get("Accept-Encoding"),
		AnthropicBeta:  r.Header.Get("Anthropic-Beta"),
		UserAgent:      r.Header.Get("User-Agent"),
		ContentType:    r.Header.Get("Content-Type"),
		XApp:           r.Header.Get("X-App"),
		Version:        r.Header.Get("Anthropic-Version"),
		DangerousDBA:   r.Header.Get("Anthropic-Dangerous-Direct-Browser-Access"),
		StainlessLang:  r.Header.Get("X-Stainless-Lang"),
		StainlessRT:    r.Header.Get("X-Stainless-Runtime"),
	}
}

// realCLIHeaders returns the expected header values from real Claude Code CLI 2.1.79.
var realCLIHeaders = capturedHeaders{
	Accept:         "application/json",
	AcceptEncoding: "gzip, deflate, br, zstd",
	UserAgent:      "claude-cli/2.1.79 (external, cli)",
	XApp:           "cli",
	Version:        "2023-06-01",
	DangerousDBA:   "true",
	StainlessLang:  "js",
	StainlessRT:    "node",
}

// realCLIBetas lists the betas for non-1M models (e.g. sonnet).
var realCLIBetas = []string{
	"claude-code-20250219",
	"oauth-2025-04-20",
	"interleaved-thinking-2025-05-14",
	"context-management-2025-06-27",
	"prompt-caching-scope-2026-01-05",
	"effort-2025-11-24",
}

// realCLIBetas1M lists the betas for 1M-capable models (e.g. opus-4-6).
var realCLIBetas1M = []string{
	"claude-code-20250219",
	"oauth-2025-04-20",
	"context-1m-2025-08-07",
	"interleaved-thinking-2025-05-14",
	"context-management-2025-06-27",
	"prompt-caching-scope-2026-01-05",
	"effort-2025-11-24",
}

// TestHeaderFidelity_StreamingMatchesRealCLI verifies that a streaming request
// through ClaudeExecutor sends headers identical to the real Claude Code CLI 2.1.79.
func TestHeaderFidelity_StreamingMatchesRealCLI(t *testing.T) {
	var captured capturedHeaders
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = captureFromRequest(r)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"))
		_, _ = w.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n"))
		_, _ = w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": server.URL,
	}}
	payload := []byte(`{"model":"claude-sonnet-4-6","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"say hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	// Drain chunks
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
	}

	// Verify headers match real CLI
	assertHeader(t, "Accept", captured.Accept, realCLIHeaders.Accept)
	assertHeader(t, "Accept-Encoding", captured.AcceptEncoding, realCLIHeaders.AcceptEncoding)
	assertHeader(t, "User-Agent", captured.UserAgent, realCLIHeaders.UserAgent)
	assertHeader(t, "X-App", captured.XApp, realCLIHeaders.XApp)
	assertHeader(t, "Anthropic-Version", captured.Version, realCLIHeaders.Version)
	assertHeader(t, "Anthropic-Dangerous-Direct-Browser-Access", captured.DangerousDBA, realCLIHeaders.DangerousDBA)
	assertHeader(t, "X-Stainless-Lang", captured.StainlessLang, realCLIHeaders.StainlessLang)
	assertHeader(t, "X-Stainless-Runtime", captured.StainlessRT, realCLIHeaders.StainlessRT)

	// Verify Anthropic-Beta contains all required betas in correct order
	assertBetasInOrder(t, captured.AnthropicBeta, realCLIBetas)
}

// TestHeaderFidelity_NonStreamingMatchesRealCLI verifies non-streaming requests
// also match the real CLI headers.
func TestHeaderFidelity_NonStreamingMatchesRealCLI(t *testing.T) {
	var captured capturedHeaders
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = captureFromRequest(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":10,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": server.URL,
	}}
	payload := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"say hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Non-streaming should use the same Accept and Accept-Encoding
	assertHeader(t, "Accept", captured.Accept, "application/json")
	assertHeader(t, "Accept-Encoding", captured.AcceptEncoding, "gzip, deflate, br, zstd")
	assertBetasInOrder(t, captured.AnthropicBeta, realCLIBetas)
}

// TestHeaderFidelity_StreamingAndNonStreamingHeadersIdentical verifies that
// streaming and non-streaming requests send identical Accept/Accept-Encoding,
// matching the real Claude Code CLI behaviour.
func TestHeaderFidelity_StreamingAndNonStreamingHeadersIdentical(t *testing.T) {
	var streamHeaders, nonStreamHeaders capturedHeaders

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		isStream := gjson.GetBytes(body, "stream").Bool()
		if isStream {
			streamHeaders = captureFromRequest(r)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		} else {
			nonStreamHeaders = captureFromRequest(r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
		}
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": server.URL,
	}}

	// Non-streaming request
	nonStreamPayload := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model: "claude-sonnet-4-6", Payload: nonStreamPayload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Streaming request
	streamPayload := []byte(`{"model":"claude-sonnet-4-6","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)
	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model: "claude-sonnet-4-6", Payload: streamPayload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("chunk error: %v", chunk.Err)
		}
	}

	if streamHeaders.Accept != nonStreamHeaders.Accept {
		t.Errorf("Accept differs: stream=%q non-stream=%q", streamHeaders.Accept, nonStreamHeaders.Accept)
	}
	if streamHeaders.AcceptEncoding != nonStreamHeaders.AcceptEncoding {
		t.Errorf("Accept-Encoding differs: stream=%q non-stream=%q", streamHeaders.AcceptEncoding, nonStreamHeaders.AcceptEncoding)
	}
}

// TestHeaderFidelity_GzipCompressedSSEStream verifies that the proxy correctly
// handles a gzip-compressed SSE stream from upstream — the real scenario when
// Accept-Encoding includes gzip.
func TestHeaderFidelity_GzipCompressedSSEStream(t *testing.T) {
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

	// Gzip compress the SSE payload
	var compressed bytes.Buffer
	gzw := gzip.NewWriter(&compressed)
	_, _ = gzw.Write([]byte(ssePayload))
	_ = gzw.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream responds with gzip-compressed SSE
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": server.URL,
	}}
	payload := []byte(`{"model":"claude-sonnet-4-6","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"say hi"}]}]}`)

	result, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
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
	t.Logf("gzip SSE stream decompressed successfully, %d bytes received", len(allChunks))
}

// TestHeaderFidelity_UserIDNewJSONFormat verifies that the injected user_id
// matches the new Claude Code 2.1.79 JSON format.
func TestHeaderFidelity_UserIDNewJSONFormat(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": server.URL,
	}}
	// No metadata.user_id in the payload — the proxy should inject one
	payload := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	userIDStr := gjson.GetBytes(receivedBody, "metadata.user_id").String()
	if userIDStr == "" {
		t.Fatal("metadata.user_id is empty")
	}

	// Verify it's valid JSON with the expected fields
	var uid userIDPayload
	if err := json.Unmarshal([]byte(userIDStr), &uid); err != nil {
		t.Fatalf("user_id is not valid JSON: %v\nraw: %s", err, userIDStr)
	}
	if len(uid.DeviceID) != 64 {
		t.Errorf("device_id length = %d, want 64", len(uid.DeviceID))
	}
	if uid.AccountUUID == "" {
		t.Error("account_uuid is empty")
	}
	if uid.SessionID == "" {
		t.Error("session_id is empty")
	}
	// Verify it looks like a valid UUID format
	if !strings.Contains(uid.AccountUUID, "-") || len(uid.AccountUUID) != 36 {
		t.Errorf("account_uuid doesn't look like a UUID: %s", uid.AccountUUID)
	}
	if !strings.Contains(uid.SessionID, "-") || len(uid.SessionID) != 36 {
		t.Errorf("session_id doesn't look like a UUID: %s", uid.SessionID)
	}

	t.Logf("user_id format verified: device_id=%s... account=%s session=%s",
		uid.DeviceID[:12], uid.AccountUUID, uid.SessionID)
}

// TestHeaderFidelity_BillingHeaderFormat verifies the billing header matches
// Claude Code 2.1.79 format with dynamic cch.
func TestHeaderFidelity_BillingHeaderFormat(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": server.URL,
	}}
	payload := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"say hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	system0Text := gjson.GetBytes(receivedBody, "system.0.text").String()
	if !strings.HasPrefix(system0Text, "x-anthropic-billing-header:") {
		t.Fatalf("system[0] is not billing header: %s", system0Text)
	}

	// Verify format: cc_version=2.1.79.XXX; cc_entrypoint=cli; cch=XXXXX;
	if !strings.Contains(system0Text, "cc_version=2.1.79.") {
		t.Errorf("billing header missing cc_version=2.1.79: %s", system0Text)
	}
	if !strings.Contains(system0Text, "cc_entrypoint=cli") {
		t.Errorf("billing header missing cc_entrypoint=cli: %s", system0Text)
	}
	if !strings.Contains(system0Text, "cch=") {
		t.Errorf("billing header missing cch=: %s", system0Text)
	}
	// cch should NOT be 00000 (old hardcoded value)
	if strings.Contains(system0Text, "cch=00000") {
		t.Errorf("billing header still has hardcoded cch=00000: %s", system0Text)
	}

	// Verify system[1] is the agent block
	system1Text := gjson.GetBytes(receivedBody, "system.1.text").String()
	if system1Text != "You are a Claude agent, built on Anthropic's Claude Agent SDK." {
		t.Errorf("system[1] agent block mismatch: %s", system1Text)
	}

	t.Logf("billing header: %s", system0Text)
}

// TestHeaderFidelity_OpusIncludes1MBeta verifies that opus-4-6 models include
// the context-1m beta, while non-opus models do not.
func TestHeaderFidelity_OpusIncludes1MBeta(t *testing.T) {
	var captured capturedHeaders
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = captureFromRequest(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": server.URL,
	}}
	payload := []byte(`{"model":"claude-opus-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Opus should include context-1m beta
	assertBetasInOrder(t, captured.AnthropicBeta, realCLIBetas1M)

	// Verify sonnet does NOT include context-1m
	var capturedSonnet capturedHeaders
	serverSonnet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSonnet = captureFromRequest(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer serverSonnet.Close()

	authSonnet := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "sk-ant-api03-test-key",
		"base_url": serverSonnet.URL,
	}}
	payloadSonnet := []byte(`{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err = executor.Execute(context.Background(), authSonnet, cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: payloadSonnet,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Sonnet should NOT include context-1m beta
	assertBetasInOrder(t, capturedSonnet.AnthropicBeta, realCLIBetas)
	if strings.Contains(capturedSonnet.AnthropicBeta, "context-1m") {
		t.Errorf("sonnet should not have context-1m beta, got: %s", capturedSonnet.AnthropicBeta)
	}
}

// --- Helpers ---

func assertHeader(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

func assertBetasInOrder(t *testing.T, betaHeader string, expected []string) {
	t.Helper()
	parts := strings.Split(betaHeader, ",")
	for i, want := range expected {
		if i >= len(parts) {
			t.Errorf("Anthropic-Beta missing beta at position %d: want %q", i, want)
			continue
		}
		got := strings.TrimSpace(parts[i])
		if got != want {
			t.Errorf("Anthropic-Beta[%d] = %q, want %q\n  full: %s", i, got, want, betaHeader)
		}
	}
}

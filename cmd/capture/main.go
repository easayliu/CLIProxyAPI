package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

func main() {
	mode := "proxy"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	switch mode {
	case "proxy":
		runProxyCapture()
	case "server":
		runCaptureServer()
	default:
		fmt.Println("Usage: capture [proxy|server]")
		fmt.Println("  proxy  - capture what the proxy sends upstream (default)")
		fmt.Println("  server - start a local capture server for real Claude Code requests")
		os.Exit(1)
	}
}

// runProxyCapture simulates proxy requests and captures what gets sent upstream.
func runProxyCapture() {
	for _, model := range []string{"claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"} {
		fmt.Printf("\n========== Model: %s ==========\n", model)

		var capturedHeaders http.Header
		var capturedBody []byte

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeaders = r.Header.Clone()
			capturedBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			resp := fmt.Sprintf(`{"id":"msg_1","type":"message","model":"%s","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`, model)
			_, _ = w.Write([]byte(resp))
		}))

		exec := executor.NewClaudeExecutor(&config.Config{})
		auth := &cliproxyauth.Auth{Attributes: map[string]string{
			"api_key":  "sk-ant-api03-test-key",
			"base_url": server.URL,
		}}
		payload := fmt.Sprintf(`{"model":"%s","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"say hi"}]}]}`, model)

		_, err := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{
			Model: model, Payload: []byte(payload),
		}, cliproxyexecutor.Options{
			SourceFormat: sdktranslator.FromString("claude"),
		})
		server.Close()
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			continue
		}

		printCapturedRequest(capturedHeaders, capturedBody)
	}
}

// runCaptureServer starts a local HTTP server that captures real Claude Code requests.
// Usage: ANTHROPIC_BASE_URL=http://127.0.0.1:19876 claude -p "say hi"
func runCaptureServer() {
	addr := "127.0.0.1:19876"
	fmt.Printf("Capture server running on http://%s\n", addr)
	fmt.Println("Point Claude Code to it:")
	fmt.Printf("  ANTHROPIC_BASE_URL=http://%s claude -p \"say hi\"\n", addr)
	fmt.Println("Press Ctrl+C to stop\n")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		length := r.ContentLength
		var body []byte
		if length > 0 {
			body, _ = io.ReadAll(r.Body)
		}

		// Decompress gzip if needed
		if r.Header.Get("Content-Encoding") == "gzip" || isGzip(body) {
			if decompressed, err := decompressGzip(body); err == nil {
				body = decompressed
			}
		}

		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("REAL CLAUDE CODE REQUEST: %s %s\n", r.Method, r.URL.Path)
		fmt.Printf("%s\n", strings.Repeat("=", 60))

		printCapturedRequest(r.Header, body)

		// Return a valid SSE response
		w.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_capture\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n",
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"captured\"}}\n\n",
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		}
		for _, e := range events {
			_, _ = w.Write([]byte(e))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		fmt.Println("\n>>> Response sent, waiting for next request...")
	})

	server := &http.Server{Addr: addr, Handler: handler}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// printCapturedRequest prints headers and body in a readable format.
func printCapturedRequest(headers http.Header, body []byte) {
	// Print headers
	fmt.Println("\n--- Headers ---")
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := strings.Join(headers[k], ", ")
		// Mask auth tokens
		kl := strings.ToLower(k)
		if kl == "authorization" || kl == "x-api-key" {
			if len(val) > 20 {
				val = val[:20] + "..."
			}
		}
		fmt.Printf("  %s: %s\n", k, val)
	}

	// Print body
	fmt.Println("\n--- Body ---")
	var d map[string]interface{}
	if err := json.Unmarshal(body, &d); err != nil {
		fmt.Printf("  (raw, %d bytes) %s\n", len(body), string(body[:min(len(body), 500)]))
		return
	}

	fmt.Printf("  model: %v\n", d["model"])
	fmt.Printf("  stream: %v\n", d["stream"])
	fmt.Printf("  max_tokens: %v\n", d["max_tokens"])

	// System prompts
	if sys, ok := d["system"]; ok {
		fmt.Println("  system:")
		if arr, ok := sys.([]interface{}); ok {
			for i, item := range arr {
				if m, ok := item.(map[string]interface{}); ok {
					b, _ := json.MarshalIndent(m, "      ", "  ")
					fmt.Printf("    [%d] %s\n", i, string(b))
				}
			}
		} else if s, ok := sys.(string); ok {
			fmt.Printf("    (string) %s\n", s)
		}
	}

	// Metadata
	if meta, ok := d["metadata"]; ok {
		b, _ := json.MarshalIndent(meta, "    ", "  ")
		fmt.Printf("  metadata: %s\n", string(b))
	}

	// Messages summary
	if msgs, ok := d["messages"].([]interface{}); ok {
		fmt.Printf("  messages count: %d\n", len(msgs))
	}

	// Tools summary
	if tools, ok := d["tools"].([]interface{}); ok {
		fmt.Printf("  tools count: %d\n", len(tools))
	}
}

func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

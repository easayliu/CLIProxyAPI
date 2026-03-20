package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

const (
	defaultUpstream = "https://api.anthropic.com"
	captureDir      = "/tmp/capture_dumps"
	listenAddr      = "127.0.0.1:19876"
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
	case "mitm":
		runMITMProxy()
	case "httpproxy":
		runHTTPProxy()
	default:
		fmt.Println("Usage: capture [proxy|server|mitm|httpproxy]")
		fmt.Println("  proxy     - capture what the proxy sends upstream (default)")
		fmt.Println("  server    - start a local capture server (mock response)")
		fmt.Println("  mitm      - transparent proxy via ANTHROPIC_BASE_URL")
		fmt.Println("  httpproxy - HTTP/HTTPS forward proxy via HTTP_PROXY/HTTPS_PROXY (captures ALL requests)")
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

		printHeaders(capturedHeaders)
		printBodySummary(capturedBody)
	}
}

// runCaptureServer starts a local HTTP server that captures real Claude Code requests (mock response).
func runCaptureServer() {
	fmt.Printf("Capture server (mock) running on http://%s\n", listenAddr)
	fmt.Printf("  ANTHROPIC_BASE_URL=http://%s claude -p \"say hi\"\n\n", listenAddr)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAndDecompress(r)

		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("REQUEST: %s %s\n", r.Method, r.URL.Path)
		fmt.Printf("%s\n", strings.Repeat("=", 60))
		printHeaders(r.Header)
		printBodySummary(body)

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
	})

	server := &http.Server{Addr: listenAddr, Handler: handler}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// runMITMProxy starts a transparent MITM proxy that captures ALL requests
// and forwards them to the real Anthropic API, returning real responses.
func runMITMProxy() {
	upstream := defaultUpstream
	if env := os.Getenv("CAPTURE_UPSTREAM"); env != "" {
		upstream = env
	}

	// Create dump directory
	if err := os.MkdirAll(captureDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create dump dir: %v\n", err)
		os.Exit(1)
	}

	var reqCounter atomic.Int64

	fmt.Printf("MITM Capture Proxy running on http://%s\n", listenAddr)
	fmt.Printf("Upstream: %s\n", upstream)
	fmt.Printf("Dumps:    ./%s/\n", captureDir)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  ANTHROPIC_BASE_URL=http://%s claude\n", listenAddr)
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// HTTP client for upstream with keep-alive
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // keep original encoding
		MaxIdleConnsPerHost: 5,
	}
	client := &http.Client{Transport: transport}

	var mu sync.Mutex // protect console output

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq := reqCounter.Add(1)
		ts := time.Now()

		// Read request body
		reqBody := readAndDecompress(r)

		// Log request
		mu.Lock()
		fmt.Printf("\n%s\n", strings.Repeat("=", 70))
		fmt.Printf("[#%d] %s  %s %s  (%d bytes)\n", seq, ts.Format("15:04:05.000"), r.Method, r.URL.Path, len(reqBody))
		fmt.Printf("%s\n", strings.Repeat("=", 70))
		printHeaders(r.Header)
		printBodySummary(reqBody)
		mu.Unlock()

		// Build upstream request
		upstreamURL := upstream + r.URL.RequestURI()
		upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(reqBody))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create upstream request: %v", err), http.StatusBadGateway)
			return
		}

		// Copy all headers
		for k, vv := range r.Header {
			for _, v := range vv {
				upReq.Header.Add(k, v)
			}
		}
		// Remove hop-by-hop headers
		upReq.Header.Del("Connection")
		upReq.Header.Del("Accept-Encoding") // let us read the response raw

		// Send to upstream
		upResp, err := client.Do(upReq)
		if err != nil {
			mu.Lock()
			fmt.Printf("[#%d] UPSTREAM ERROR: %v\n", seq, err)
			mu.Unlock()
			http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
			return
		}
		defer upResp.Body.Close()

		// Copy response headers
		for k, vv := range upResp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		// Check if streaming
		isStreaming := strings.Contains(upResp.Header.Get("Content-Type"), "text/event-stream")

		if isStreaming {
			// Stream response: flush each chunk and capture
			w.WriteHeader(upResp.StatusCode)
			flusher, canFlush := w.(http.Flusher)

			var respBuf bytes.Buffer
			buf := make([]byte, 4096)
			for {
				n, readErr := upResp.Body.Read(buf)
				if n > 0 {
					respBuf.Write(buf[:n])
					_, _ = w.Write(buf[:n])
					if canFlush {
						flusher.Flush()
					}
				}
				if readErr != nil {
					break
				}
			}

			respBody := respBuf.Bytes()

			mu.Lock()
			fmt.Printf("\n[#%d] RESPONSE: %d (streaming, %d bytes)\n", seq, upResp.StatusCode, len(respBody))
			printResponseHeaders(upResp.Header)
			printStreamingSummary(respBody)
			mu.Unlock()

			// Save dump
			saveDump(seq, ts, r, reqBody, upResp, respBody)
		} else {
			// Non-streaming: read full response
			respBody, _ := io.ReadAll(upResp.Body)
			w.WriteHeader(upResp.StatusCode)
			_, _ = w.Write(respBody)

			// Decompress for logging if needed
			logBody := decompressIfNeeded(upResp.Header.Get("Content-Encoding"), respBody)

			mu.Lock()
			fmt.Printf("\n[#%d] RESPONSE: %d (%d bytes)\n", seq, upResp.StatusCode, len(respBody))
			printResponseHeaders(upResp.Header)
			printBodySummary(logBody)
			mu.Unlock()

			// Save dump
			saveDump(seq, ts, r, reqBody, upResp, logBody)
		}
	})

	server := &http.Server{Addr: listenAddr, Handler: handler}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// saveDump saves the captured request+response to a JSON file.
func saveDump(seq int64, ts time.Time, r *http.Request, reqBody []byte, resp *http.Response, respBody []byte) {
	dump := map[string]interface{}{
		"seq":       seq,
		"timestamp": ts.Format(time.RFC3339Nano),
		"request": map[string]interface{}{
			"method":  r.Method,
			"path":    r.URL.RequestURI(),
			"headers": headerMap(r.Header),
		},
		"response": map[string]interface{}{
			"status":  resp.StatusCode,
			"headers": headerMap(resp.Header),
		},
	}

	// Parse request body as JSON
	var reqJSON interface{}
	if err := json.Unmarshal(reqBody, &reqJSON); err == nil {
		dump["request"].(map[string]interface{})["body"] = reqJSON
	} else if len(reqBody) > 0 {
		dump["request"].(map[string]interface{})["body_raw"] = string(reqBody)
	}

	// Parse response body as JSON
	var respJSON interface{}
	if err := json.Unmarshal(respBody, &respJSON); err == nil {
		dump["response"].(map[string]interface{})["body"] = respJSON
	} else if len(respBody) > 0 {
		// For SSE, save as raw string
		dump["response"].(map[string]interface{})["body_raw"] = string(respBody)
	}

	filename := filepath.Join(captureDir, fmt.Sprintf("%03d_%s_%s.json",
		seq, ts.Format("150405"), sanitizePath(r.URL.Path)))
	data, _ := json.MarshalIndent(dump, "", "  ")
	if err := os.WriteFile(filename, data, 0o644); err == nil {
		fmt.Printf("[#%d] Saved: %s\n", seq, filename)
	}
}

// --- Helper functions ---

func readAndDecompress(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	body, _ := io.ReadAll(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" || isGzip(body) {
		if d, err := decompressGzip(body); err == nil {
			return d
		}
	}
	return body
}

func decompressIfNeeded(encoding string, data []byte) []byte {
	switch strings.ToLower(encoding) {
	case "gzip":
		if d, err := decompressGzip(data); err == nil {
			return d
		}
	}
	return data
}

func printHeaders(headers http.Header) {
	fmt.Println("  --- Request Headers ---")
	keys := sortedKeys(headers)
	for _, k := range keys {
		val := strings.Join(headers[k], ", ")
		kl := strings.ToLower(k)
		if kl == "authorization" || kl == "x-api-key" {
			if len(val) > 20 {
				val = val[:20] + "..."
			}
		}
		fmt.Printf("    %s: %s\n", k, val)
	}
}

func printResponseHeaders(headers http.Header) {
	fmt.Println("  --- Response Headers ---")
	keys := sortedKeys(headers)
	for _, k := range keys {
		val := strings.Join(headers[k], ", ")
		fmt.Printf("    %s: %s\n", k, val)
	}
}

func printBodySummary(body []byte) {
	if len(body) == 0 {
		fmt.Println("  (no body)")
		return
	}

	var d map[string]interface{}
	if err := json.Unmarshal(body, &d); err != nil {
		// Not JSON
		s := string(body)
		if len(s) > 500 {
			s = s[:500] + "..."
		}
		fmt.Printf("  --- Body (raw, %d bytes) ---\n    %s\n", len(body), s)
		return
	}

	fmt.Printf("  --- Body (%d bytes) ---\n", len(body))

	// Top-level keys
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := d[k]
		switch k {
		case "model", "stream", "max_tokens", "type", "id", "stop_reason":
			fmt.Printf("    %s: %v\n", k, v)
		case "system":
			if arr, ok := v.([]interface{}); ok {
				fmt.Printf("    system: [%d blocks]\n", len(arr))
				for i, item := range arr {
					if m, ok := item.(map[string]interface{}); ok {
						text, _ := m["text"].(string)
						if len(text) > 120 {
							text = text[:120] + "..."
						}
						fmt.Printf("      [%d] %s\n", i, text)
					}
				}
			}
		case "messages":
			if arr, ok := v.([]interface{}); ok {
				fmt.Printf("    messages: %d\n", len(arr))
				for i, msg := range arr {
					if m, ok := msg.(map[string]interface{}); ok {
						role, _ := m["role"].(string)
						if content, ok := m["content"].([]interface{}); ok {
							fmt.Printf("      [%d] role=%s, %d content blocks\n", i, role, len(content))
						} else if content, ok := m["content"].(string); ok {
							s := content
							if len(s) > 80 {
								s = s[:80] + "..."
							}
							fmt.Printf("      [%d] role=%s: %s\n", i, role, s)
						}
					}
				}
			}
		case "tools":
			if arr, ok := v.([]interface{}); ok {
				fmt.Printf("    tools: %d\n", len(arr))
				for _, t := range arr {
					if m, ok := t.(map[string]interface{}); ok {
						name, _ := m["name"].(string)
						fmt.Printf("      - %s\n", name)
					}
				}
			}
		case "metadata":
			b, _ := json.Marshal(v)
			fmt.Printf("    metadata: %s\n", string(b))
		case "thinking", "context_management", "output_config":
			b, _ := json.Marshal(v)
			fmt.Printf("    %s: %s\n", k, string(b))
		case "content":
			if arr, ok := v.([]interface{}); ok {
				fmt.Printf("    content: [%d blocks]\n", len(arr))
				for i, item := range arr {
					if m, ok := item.(map[string]interface{}); ok {
						t, _ := m["type"].(string)
						text, _ := m["text"].(string)
						if len(text) > 120 {
							text = text[:120] + "..."
						}
						fmt.Printf("      [%d] type=%s: %s\n", i, t, text)
					}
				}
			}
		case "usage":
			b, _ := json.Marshal(v)
			fmt.Printf("    usage: %s\n", string(b))
		default:
			b, _ := json.Marshal(v)
			s := string(b)
			if len(s) > 200 {
				s = s[:200] + "..."
			}
			fmt.Printf("    %s: %s\n", k, s)
		}
	}
}

func printStreamingSummary(data []byte) {
	lines := strings.Split(string(data), "\n")
	eventCount := 0
	var events []string
	for _, line := range lines {
		if strings.HasPrefix(line, "event: ") {
			eventCount++
			eventType := strings.TrimPrefix(line, "event: ")
			events = append(events, eventType)
		}
	}
	fmt.Printf("  --- Streaming Response (%d events) ---\n", eventCount)
	// Show event types summary
	counts := make(map[string]int)
	for _, e := range events {
		counts[e]++
	}
	for _, e := range sortedMapKeys(counts) {
		fmt.Printf("    %s: %d\n", e, counts[e])
	}

	// Extract final usage from message_delta
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "message_delta") {
			dataStr := strings.TrimPrefix(line, "data: ")
			var msg map[string]interface{}
			if json.Unmarshal([]byte(dataStr), &msg) == nil {
				if usage, ok := msg["usage"]; ok {
					b, _ := json.Marshal(usage)
					fmt.Printf("    final_usage: %s\n", string(b))
				}
			}
		}
	}

	// Extract message_start usage
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "message_start") {
			dataStr := strings.TrimPrefix(line, "data: ")
			var msg map[string]interface{}
			if json.Unmarshal([]byte(dataStr), &msg) == nil {
				if m, ok := msg["message"].(map[string]interface{}); ok {
					if usage, ok := m["usage"]; ok {
						b, _ := json.Marshal(usage)
						fmt.Printf("    input_usage: %s\n", string(b))
					}
					if model, ok := m["model"]; ok {
						fmt.Printf("    model: %v\n", model)
					}
				}
			}
		}
	}
}

func headerMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vv := range h {
		kl := strings.ToLower(k)
		if kl == "authorization" || kl == "x-api-key" {
			v := strings.Join(vv, ", ")
			if len(v) > 20 {
				v = v[:20] + "..."
			}
			m[k] = v
		} else {
			m[k] = strings.Join(vv, ", ")
		}
	}
	return m
}

func sortedKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedMapKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sanitizePath(path string) string {
	path = strings.ReplaceAll(path, "/", "_")
	path = strings.TrimLeft(path, "_")
	if len(path) > 40 {
		path = path[:40]
	}
	if path == "" {
		path = "root"
	}
	return path
}

func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	proxyAddr = "127.0.0.1:19877"
)

var proxyDumpDir string

// runHTTPProxy starts an HTTP/HTTPS forward proxy with MITM for TLS.
// Usage:
//
//	HTTP_PROXY=http://127.0.0.1:19877 HTTPS_PROXY=http://127.0.0.1:19877 \
//	NODE_TLS_REJECT_UNAUTHORIZED=0 claude -p "say hi"
func runHTTPProxy() {
	// Use timestamped subdirectory
	proxyDumpDir = filepath.Join("/tmp/proxy_captures", time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(proxyDumpDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create dump dir: %v\n", err)
		os.Exit(1)
	}

	// Generate CA for MITM
	ca, caKey, err := generateCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate CA: %v\n", err)
		os.Exit(1)
	}

	var counter atomic.Int64
	var mu sync.Mutex

	// Build HTTP client, optionally with upstream proxy
	upstreamTransport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if envProxy := os.Getenv("CAPTURE_UPSTREAM_PROXY"); envProxy != "" {
		proxyURL, err := url.Parse(envProxy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid CAPTURE_UPSTREAM_PROXY %q: %v\n", envProxy, err)
			os.Exit(1)
		}
		upstreamTransport.Proxy = http.ProxyURL(proxyURL)
		fmt.Printf("Upstream proxy: %s\n", envProxy)
	}
	upstreamClient := &http.Client{Transport: upstreamTransport}

	proxy := &httpProxy{
		ca:      ca,
		caKey:   caKey,
		counter: &counter,
		mu:      &mu,
		client:  upstreamClient,
	}

	fmt.Printf("HTTP/HTTPS Capture Proxy running on %s\n", proxyAddr)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  HTTP_PROXY=http://%s HTTPS_PROXY=http://%s \\\n", proxyAddr, proxyAddr)
	fmt.Println("  NODE_TLS_REJECT_UNAUTHORIZED=0 \\")
	fmt.Println("  claude -p \"say hi\"")
	fmt.Println()
	fmt.Println("Optional: set CAPTURE_UPSTREAM_PROXY to chain through another proxy, e.g.:")
	fmt.Println("  CAPTURE_UPSTREAM_PROXY=http://127.0.0.1:6152 go run ./cmd/capture httpproxy")
	fmt.Println()
	fmt.Printf("Dumps: %s/\n", proxyDumpDir)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	server := &http.Server{
		Addr:    proxyAddr,
		Handler: proxy,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Proxy error: %v\n", err)
		os.Exit(1)
	}
}

type httpProxy struct {
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	counter  *atomic.Int64
	mu       *sync.Mutex
	client   *http.Client
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleHTTP proxies plain HTTP requests.
func (p *httpProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	seq := p.counter.Add(1)
	ts := time.Now()

	// Read request body
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
	}

	p.logRequest(seq, ts, r.Method, r.URL.String(), r.Header, reqBody)

	// Forward request
	outReq, _ := http.NewRequest(r.Method, r.URL.String(), strings.NewReader(string(reqBody)))
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Del("Proxy-Connection")

	resp, err := p.client.Do(outReq)
	if err != nil {
		p.logError(seq, "upstream error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Copy response
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	p.logResponse(seq, ts, r.Method, r.URL.String(), r.Header, reqBody, resp, respBody)
}

// handleConnect handles HTTPS CONNECT with MITM.
func (p *httpProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	hostname := strings.Split(host, ":")[0]

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 Connection Established
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Generate cert for the target host
	tlsCert, err := p.generateCertForHost(hostname)
	if err != nil {
		p.logError(0, "cert generation failed for %s: %v", hostname, err)
		clientConn.Close()
		return
	}

	// TLS handshake with client (MITM)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.logError(0, "TLS handshake failed for %s: %v", hostname, err)
		clientConn.Close()
		return
	}
	defer tlsConn.Close()

	// Read the actual HTTPS request from the client.
	// Wrap with rawCapture to record raw bytes before Go's HTTP parser
	// canonicalizes header names (e.g. "accept" → "Accept").
	rawBuf := &rawCapture{}
	teeReader := io.TeeReader(tlsConn, rawBuf)
	clientReader := bufio.NewReader(teeReader)

	for {
		rawBuf.Reset()
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				p.logError(0, "read request from TLS: %v", err)
			}
			return
		}

		// Capture raw header bytes BEFORE body is read.
		rawHeaderBytes := rawBuf.Bytes()

		seq := p.counter.Add(1)
		ts := time.Now()

		// Read request body
		var reqBody []byte
		if req.Body != nil {
			reqBody, _ = io.ReadAll(req.Body)
		}

		// Extract raw headers from the captured bytes (preserving original casing)
		rawHeaders := extractRawHeaders(rawHeaderBytes)

		fullURL := fmt.Sprintf("https://%s%s", host, req.URL.RequestURI())
		p.logRequestWithRaw(seq, ts, req.Method, fullURL, req.Header, rawHeaders, reqBody)

		// Forward to real server
		outReq, _ := http.NewRequest(req.Method, fullURL, strings.NewReader(string(reqBody)))
		for k, vv := range req.Header {
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
		outReq.Header.Del("Proxy-Connection")
		outReq.Header.Set("Accept-Encoding", "identity") // force uncompressed responses for capture

		resp, err := p.client.Do(outReq)
		if err != nil {
			p.logError(seq, "upstream HTTPS error: %v", err)
			errResp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\n\r\n%s",
				len(err.Error()), err.Error())
			_, _ = tlsConn.Write([]byte(errResp))
			continue
		}

		// Read full response
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Write response back to client through TLS
		var respBuf strings.Builder
		respBuf.WriteString(fmt.Sprintf("HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status))
		// Write headers, skip hop-by-hop and length headers we override
		for k, vv := range resp.Header {
			kl := strings.ToLower(k)
			if kl == "transfer-encoding" || kl == "content-length" || kl == "content-encoding" {
				continue
			}
			for _, v := range vv {
				respBuf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
		}
		// Set actual body size
		respBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(respBody)))
		respBuf.WriteString("\r\n")
		_, _ = tlsConn.Write([]byte(respBuf.String()))
		_, _ = tlsConn.Write(respBody)

		p.logResponseWithRaw(seq, ts, req.Method, fullURL, req.Header, rawHeaders, reqBody, resp, respBody)
	}
}

// rawCapture accumulates bytes written via TeeReader.
type rawCapture struct {
	buf []byte
}

func (r *rawCapture) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	return len(p), nil
}

func (r *rawCapture) Bytes() []byte { return r.buf }
func (r *rawCapture) Reset()        { r.buf = r.buf[:0] }

// extractRawHeaders parses raw HTTP/1.x bytes and returns header lines
// with their original casing preserved (before Go's canonical formatting).
func extractRawHeaders(raw []byte) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(string(raw), "\r\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip request line (GET /path HTTP/1.1)
		}
		if line == "" {
			break // end of headers
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		headers[key] = val
	}
	return headers
}

func (p *httpProxy) logRequest(seq int64, ts time.Time, method, url string, headers http.Header, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("[#%d] %s  %s %s  (%d bytes)\n", seq, ts.Format("15:04:05.000"), method, url, len(body))
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	// Print headers
	fmt.Println("  --- Headers ---")
	for _, k := range sortedKeys(headers) {
		val := strings.Join(headers[k], ", ")
		kl := strings.ToLower(k)
		if kl == "authorization" || kl == "x-api-key" {
			if len(val) > 20 {
				val = val[:20] + "..."
			}
		}
		fmt.Printf("    %s: %s\n", k, val)
	}

	// Print body summary
	if len(body) > 0 {
		var d map[string]interface{}
		if json.Unmarshal(body, &d) == nil {
			fmt.Printf("  --- Body (%d bytes, JSON) ---\n", len(body))
			if m, ok := d["model"]; ok {
				fmt.Printf("    model: %v\n", m)
			}
			if msgs, ok := d["messages"].([]interface{}); ok {
				fmt.Printf("    messages: %d\n", len(msgs))
			}
			if tools, ok := d["tools"].([]interface{}); ok {
				fmt.Printf("    tools: %d\n", len(tools))
			}
		} else {
			s := string(body)
			if len(s) > 200 {
				s = s[:200] + "..."
			}
			fmt.Printf("  --- Body (%d bytes) ---\n    %s\n", len(body), s)
		}
	}
}

// logRequestWithRaw prints request with raw (original casing) headers.
func (p *httpProxy) logRequestWithRaw(seq int64, ts time.Time, method, url string, _ http.Header, rawHeaders map[string]string, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("[#%d] %s  %s %s  (%d bytes)\n", seq, ts.Format("15:04:05.000"), method, url, len(body))
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	fmt.Println("  --- Raw Headers (original casing) ---")
	for k, v := range rawHeaders {
		kl := strings.ToLower(k)
		display := v
		if kl == "authorization" || kl == "x-api-key" {
			if len(display) > 20 {
				display = display[:20] + "..."
			}
		}
		fmt.Printf("    %s: %s\n", k, display)
	}

	if len(body) > 0 {
		var d map[string]interface{}
		if json.Unmarshal(body, &d) == nil {
			fmt.Printf("  --- Body (%d bytes, JSON) ---\n", len(body))
			if m, ok := d["model"]; ok {
				fmt.Printf("    model: %v\n", m)
			}
		}
	}
}

// logResponse saves response with canonical (Go-formatted) headers for HTTP path.
func (p *httpProxy) logResponse(seq int64, ts time.Time, method, url string, reqHeaders http.Header, reqBody []byte, resp *http.Response, respBody []byte) {
	p.logResponseWithRaw(seq, ts, method, url, reqHeaders, headerMap(reqHeaders), reqBody, resp, respBody)
}

// logResponseWithRaw saves response with raw request headers preserved.
func (p *httpProxy) logResponseWithRaw(seq int64, ts time.Time, method, url string, _ http.Header, rawHeaders map[string]string, reqBody []byte, resp *http.Response, respBody []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(ts)
	fmt.Printf("[#%d] RESPONSE: %d (%d bytes, %.1fs)\n", seq, resp.StatusCode, len(respBody), elapsed.Seconds())

	// Redact auth tokens in raw headers for file output
	safeRaw := make(map[string]string, len(rawHeaders))
	for k, v := range rawHeaders {
		kl := strings.ToLower(k)
		if kl == "authorization" || kl == "x-api-key" {
			if len(v) > 20 {
				v = v[:20] + "..."
			}
		}
		safeRaw[k] = v
	}

	// Save to file with raw headers (original casing)
	dump := map[string]interface{}{
		"seq":       seq,
		"timestamp": ts.Format(time.RFC3339Nano),
		"elapsed":   elapsed.String(),
		"request": map[string]interface{}{
			"method":  method,
			"url":     url,
			"headers": safeRaw,
		},
		"response": map[string]interface{}{
			"status":  resp.StatusCode,
			"headers": headerMap(resp.Header),
		},
	}

	// Parse request body
	var reqJSON interface{}
	if json.Unmarshal(reqBody, &reqJSON) == nil {
		dump["request"].(map[string]interface{})["body"] = reqJSON
	} else if len(reqBody) > 0 {
		dump["request"].(map[string]interface{})["body_raw"] = string(reqBody)
	}

	// Decompress response body if gzip-encoded
	logBody := respBody
	if isGzip(respBody) {
		if d, err := decompressGzip(respBody); err == nil {
			logBody = d
		}
	}

	// Parse response body
	var respJSON interface{}
	if json.Unmarshal(logBody, &respJSON) == nil {
		dump["response"].(map[string]interface{})["body"] = respJSON
	} else if len(logBody) > 0 {
		s := string(logBody)
		if len(s) > 100000 {
			s = s[:100000] + "...(truncated)"
		}
		dump["response"].(map[string]interface{})["body_raw"] = s
	}

	// Determine filename from URL
	urlPath := url
	if idx := strings.Index(urlPath, "://"); idx >= 0 {
		urlPath = urlPath[idx+3:]
	}
	safePath := strings.ReplaceAll(urlPath, "/", "_")
	if len(safePath) > 60 {
		safePath = safePath[:60]
	}

	filename := filepath.Join(proxyDumpDir, fmt.Sprintf("%03d_%s_%s.json",
		seq, ts.Format("150405"), safePath))
	data, _ := json.MarshalIndent(dump, "", "  ")
	if err := os.WriteFile(filename, data, 0o644); err == nil {
		fmt.Printf("[#%d] Saved: %s\n", seq, filename)
	}
}

func (p *httpProxy) logError(seq int64, format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	if seq > 0 {
		fmt.Printf("[#%d] ERROR: %s\n", seq, msg)
	} else {
		fmt.Printf("[PROXY] ERROR: %s\n", msg)
	}
}

// generateCA creates a self-signed CA certificate for MITM.
func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Capture Proxy CA", Organization: []string{"Capture"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// generateCertForHost creates a TLS certificate signed by our CA for the given hostname.
func (p *httpProxy) generateCertForHost(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add SAN
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return tlsCert, nil
}

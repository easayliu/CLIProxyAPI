// Package claude provides authentication functionality for Anthropic's Claude API.
// This file implements a custom HTTP transport using utls to mimic Bun's BoringSSL
// TLS fingerprint, matching the real Claude Code CLI.
package claude

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	tls "github.com/refraction-networking/utls"
)

// claudeHeaderOrder defines the canonical header order AND casing matching the
// real Bun + @anthropic-ai/sdk (Stainless) wire format, captured via MITM of
// Claude Code CLI 2.1.87.
//
// Real CLI uses mixed casing:
//   - Standard HTTP headers + X-Stainless-* + X-Claude-Code-Session-Id: Title-Case
//   - anthropic-*, x-app, x-client-request-id: lowercase
//
// This matches Bun's behavior: HTTP standard headers follow Title-Case convention,
// custom headers preserve the casing set in SDK source code.
var claudeHeaderOrder = []string{
	"Accept",
	"User-Agent",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"X-Stainless-Timeout",
	"X-Claude-Code-Session-Id",
	"Accept-Encoding",
	"Accept-Language",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"Authorization",
	"x-api-key",
	"Connection",
	"Content-Length",
	"Content-Type",
	"Host",
	"sec-fetch-mode",
	"x-app",
	"x-client-request-id",
}

// claudeHeaderRank maps lowercase header name to its position in claudeHeaderOrder.
// Built once at init time for O(1) lookups during reordering.
var claudeHeaderRank map[string]int

// claudeHeaderCasing maps lowercase header name to the real wire casing from
// the Claude Code CLI. Used to rewrite header names to match real CLI output.
var claudeHeaderCasing map[string]string

func init() {
	claudeHeaderRank = make(map[string]int, len(claudeHeaderOrder))
	claudeHeaderCasing = make(map[string]string, len(claudeHeaderOrder))
	for i, h := range claudeHeaderOrder {
		lower := strings.ToLower(h)
		claudeHeaderRank[lower] = i
		claudeHeaderCasing[lower] = h
	}
}

const (
	// connIdleTimeout matches Bun's 5-minute keep-alive timeout for pooled sockets.
	connIdleTimeout = 5 * time.Minute
	// maxPoolSize matches Bun's 64-socket pool limit.
	maxPoolSize = 64
)

// poolEntry holds an idle connection along with its buffered reader and timestamp.
type poolEntry struct {
	conn      net.Conn
	br        *bufio.Reader
	idleSince time.Time
}

// connPool is a simple per-host idle connection pool matching Bun's keep-alive behavior.
type connPool struct {
	mu   sync.Mutex
	idle map[string][]*poolEntry // keyed by host:port
}

// get returns a healthy idle connection for addr, or nil if none available.
// Stale or errored connections are closed and discarded (matching Bun's
// isClosed/isShutdown/getError checks before reuse).
func (p *connPool) get(addr string) *poolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()

	entries := p.idle[addr]
	now := time.Now()
	for len(entries) > 0 {
		e := entries[len(entries)-1]
		entries = entries[:len(entries)-1]
		if now.Sub(e.idleSince) > connIdleTimeout {
			e.conn.Close()
			continue
		}
		// Bun checks isClosed/isShutdown/getError before reuse.
		// In Go, use bufio.Reader.Peek with a short read deadline to detect
		// if the server has sent FIN/RST. A healthy idle connection will
		// timeout (no data to read), while a closed one returns EOF or error.
		e.conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		_, err := e.br.Peek(1)
		e.conn.SetReadDeadline(time.Time{})
		if err == nil {
			// Got data unexpectedly — server sent something (shouldn't happen on idle).
			// Still usable, return it.
			p.idle[addr] = entries
			return e
		}
		if isTimeoutError(err) {
			// Timeout = no data and no close signal = connection is healthy.
			p.idle[addr] = entries
			return e
		}
		// EOF, connection reset, or other error — connection is dead.
		e.conn.Close()
		continue
	}
	p.idle[addr] = entries
	return nil
}

// put returns a connection to the pool. If the pool is full, the connection is closed.
func (p *connPool) put(addr string, e *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.idle == nil {
		p.idle = make(map[string][]*poolEntry)
	}
	total := 0
	for _, v := range p.idle {
		total += len(v)
	}
	if total >= maxPoolSize {
		e.conn.Close()
		return
	}
	e.idleSince = time.Now()
	p.idle[addr] = append(p.idle[addr], e)
}

// isTimeoutError checks if an error is a timeout (expected for healthy idle connections).
func isTimeoutError(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// utlsRoundTripper implements http.RoundTripper using utls with Bun BoringSSL
// fingerprint to match the real Claude Code CLI's TLS characteristics.
//
// It uses HTTP/1.1 (Bun's ALPN only offers http/1.1) and writes raw HTTP
// with correct header casing to match Node.js/Bun wire format.
//
// Connections are pooled with 5-minute idle timeout and health checks before
// reuse, matching Bun's keep-alive behavior. Stale connections are transparently
// retried with a fresh connection (Bun's allow_retry logic).
type utlsRoundTripper struct {
	dialer *ProxyDialer
	pool   connPool
}

// NewAnthropicTransport creates a new http.RoundTripper with Bun BoringSSL TLS
// fingerprint. Unlike NewAnthropicHttpClient, this returns a fresh transport
// (not cached), so callers can wrap it in their own http.Client with custom
// settings (e.g. Timeout) without affecting the shared cached client.
func NewAnthropicTransport(proxyURL string) http.RoundTripper {
	return newUtlsRoundTripper(proxyURL)
}

// newUtlsRoundTripper creates a new utls-based round tripper with optional proxy support.
func newUtlsRoundTripper(proxyURL string) *utlsRoundTripper {
	return &utlsRoundTripper{
		dialer: NewProxyDialer(proxyURL),
		pool:   connPool{idle: make(map[string][]*poolEntry)},
	}
}

// dialTLS establishes a TLS connection using utls with the Bun BoringSSL spec.
// It delegates raw TCP dialing (including proxy tunneling) to ProxyDialer,
// then performs the utls handshake on the resulting connection.
func (t *utlsRoundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Step 1: Establish raw TCP connection (proxy tunneling handled internally).
	conn, err := t.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Step 2: Propagate context deadline to TLS handshake to prevent indefinite hangs.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	// Step 3: TLS handshake with Bun BoringSSL fingerprint.
	tlsConfig := &tls.Config{ServerName: host}
	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloCustom)
	if err := tlsConn.ApplyPreset(BunBoringSSLSpec()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("apply Bun TLS spec: %w", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// dial creates a fresh connection (TLS for https, plain TCP for http).
func (t *utlsRoundTripper) dial(req *http.Request, addr string) (net.Conn, *bufio.Reader, error) {
	var conn net.Conn
	var err error
	if req.URL.Scheme == "http" {
		conn, err = t.dialer.DialContext(req.Context(), "tcp", addr)
	} else {
		conn, err = t.dialTLS(req.Context(), "tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}
	return conn, bufio.NewReader(conn), nil
}

// RoundTrip implements http.RoundTripper. It serializes the request with Go's
// standard req.Write, then reorders headers to match the real Bun/Stainless SDK
// order and recases header names to match Node.js/Bun wire format.
//
// Connections are pooled and reused with health checks. If a pooled connection
// fails, the request is transparently retried on a fresh connection (matching
// Bun's allow_retry behavior for keep-alive sockets).
func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Step 1: Serialize the full HTTP/1.1 request into a buffer.
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, fmt.Errorf("serialize request: %w", err)
	}

	// Step 2: Reorder and recase headers to match real Bun/Stainless SDK wire format.
	reordered := reorderAndLowercaseHeaders(buf.Bytes())

	// Debug: log actual wire-format headers.
	if log.IsLevelEnabled(log.DebugLevel) {
		if hdrEnd := bytes.Index(reordered, []byte("\r\n\r\n")); hdrEnd > 0 {
			log.Debugf("[wire-debug] %s", string(reordered[:hdrEnd]))
		}
	}

	// Step 3: Resolve target address.
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := "443"
		if req.URL.Scheme == "http" {
			port = "80"
		}
		addr = net.JoinHostPort(addr, port)
	}

	// Step 4: Try pooled connection first, then fresh connection.
	// Matching Bun's behavior: pooled sockets get allow_retry=true.
	allowRetry := false
	var conn net.Conn
	var br *bufio.Reader
	var err error

	if pe := t.pool.get(addr); pe != nil {
		conn, br = pe.conn, pe.br
		allowRetry = true // Bun: allow_retry=true for pooled sockets
	} else {
		conn, br, err = t.dial(req, addr)
		if err != nil {
			return nil, err
		}
		// Bun: allow_retry=false for new connections
	}

	// Step 5: Watch for context cancellation.
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-req.Context().Done():
			conn.Close()
		case <-cancelDone:
		}
	}()

	// Step 6: Write + Read. If pooled connection fails, retry once with fresh connection.
	resp, err := t.writeAndRead(conn, br, reordered, req)
	if err != nil && allowRetry {
		// Bun's onClose retry: pooled socket failed, retry with a new connection.
		close(cancelDone)
		conn.Close()

		conn, br, err = t.dial(req, addr)
		if err != nil {
			return nil, err
		}
		cancelDone = make(chan struct{})
		go func() {
			select {
			case <-req.Context().Done():
				conn.Close()
			case <-cancelDone:
			}
		}()
		resp, err = t.writeAndRead(conn, br, reordered, req)
	}
	if err != nil {
		close(cancelDone)
		conn.Close()
		return nil, err
	}

	// Step 7: Wrap body to return connection to pool when done reading.
	// If server sends "Connection: close", don't pool.
	resp.Body = &connPoolBody{
		ReadCloser: resp.Body,
		conn:       conn,
		br:         br,
		addr:       addr,
		pool:       &t.pool,
		cancel:     cancelDone,
		noReuse:    resp.Close,
	}

	return resp, nil
}

// writeAndRead writes the request and reads the response on a connection.
func (t *utlsRoundTripper) writeAndRead(conn net.Conn, br *bufio.Reader, data []byte, req *http.Request) (*http.Response, error) {
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	return http.ReadResponse(br, req)
}

// connPoolBody wraps a response body. When fully read (EOF) and the server
// allows keep-alive, the connection is returned to the pool. Otherwise closed.
type connPoolBody struct {
	io.ReadCloser
	conn    net.Conn
	br      *bufio.Reader
	addr    string
	pool    *connPool
	cancel  chan struct{}
	once    sync.Once
	hitEOF  bool
	noReuse bool
}

func (r *connPoolBody) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err == io.EOF {
		r.hitEOF = true
	}
	return n, err
}

func (r *connPoolBody) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() {
		close(r.cancel)
		if r.hitEOF && !r.noReuse {
			r.pool.put(r.addr, &poolEntry{conn: r.conn, br: r.br})
		} else {
			r.conn.Close()
		}
	})
	return err
}

// headerLine holds a parsed header with its lowercase name and the value portion.
type headerLine struct {
	lowerName string // lowercase header name (for ordering/casing lookup)
	value     []byte // everything after the colon, e.g. ": application/json"
}

// reorderAndRecaseHeaders parses the raw HTTP/1.1 request bytes, reorders
// headers to match the real Bun + Stainless SDK order (claudeHeaderOrder), and
// rewrites header names to match the real CLI's mixed casing (Title-Case for
// standard/SDK headers, lowercase for anthropic-*/x-app/x-client-request-id).
//
// The request line and body are preserved as-is.
// Returns a new byte slice with the rewritten request.
func reorderAndLowercaseHeaders(raw []byte) []byte {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return raw
	}

	// Split request line.
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd < 0 || lineEnd >= headerEnd {
		return raw
	}
	requestLine := raw[:lineEnd] // e.g. "POST /v1/messages HTTP/1.1"
	body := raw[headerEnd+2:]    // skip one \r\n; result.Write adds the other

	// Parse all header lines.
	pos := lineEnd + 2
	var headers []headerLine
	for pos < headerEnd {
		nextCRLF := bytes.Index(raw[pos:], []byte("\r\n"))
		if nextCRLF < 0 {
			break
		}
		line := raw[pos : pos+nextCRLF]
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx > 0 {
			// Lowercase the name for lookup only.
			lowerName := strings.ToLower(string(line[:colonIdx]))
			headers = append(headers, headerLine{
				lowerName: lowerName,
				value:     line[colonIdx:], // ": value"
			})
		}
		pos += nextCRLF + 2
	}

	// Reorder and recase: emit headers in claudeHeaderOrder with correct casing,
	// then append any remaining headers preserving their original name.
	used := make([]bool, len(headers))
	var result bytes.Buffer
	result.Grow(len(raw) + 64)
	result.Write(requestLine)
	result.WriteString("\r\n")

	for _, canonicalName := range claudeHeaderOrder {
		lowerOrdered := strings.ToLower(canonicalName)
		for i, h := range headers {
			if !used[i] && h.lowerName == lowerOrdered {
				// Use the casing from claudeHeaderCasing (real CLI wire format).
				result.WriteString(canonicalName)
				result.Write(h.value)
				result.WriteString("\r\n")
				used[i] = true
				break
			}
		}
	}
	// Append any headers not in the canonical order, using claudeHeaderCasing
	// if known, otherwise lowercase (safe default for unknown custom headers).
	for i, h := range headers {
		if !used[i] {
			if cased, ok := claudeHeaderCasing[h.lowerName]; ok {
				result.WriteString(cased)
			} else {
				result.WriteString(h.lowerName)
			}
			result.Write(h.value)
			result.WriteString("\r\n")
		}
	}

	result.Write(body)
	return result.Bytes()
}

// anthropicClients caches *http.Client instances keyed by proxyURL string.
// Each unique proxyURL gets a single shared client whose utlsRoundTripper
// reuses the same TLS dialer configuration — this avoids recreating the
// dialer per request. The number of unique proxy URLs is typically very
// small (1-3), so entries are never evicted.
var anthropicClients sync.Map // map[string]*http.Client

// NewAnthropicHttpClient returns a cached HTTP client that uses Bun BoringSSL TLS
// fingerprint for all connections, matching real Claude Code CLI behavior.
//
// Clients are cached per proxyURL so that the underlying utlsRoundTripper
// reuses the same proxy dialer configuration across requests.
//
// The proxyURL parameter is the pre-resolved proxy URL (e.g. from ResolveProxyURL).
// Pass an empty string to inherit proxy from environment variables.
func NewAnthropicHttpClient(proxyURL string) *http.Client {
	if cached, ok := anthropicClients.Load(proxyURL); ok {
		return cached.(*http.Client)
	}
	client := &http.Client{
		Transport: newUtlsRoundTripper(proxyURL),
	}
	actual, _ := anthropicClients.LoadOrStore(proxyURL, client)
	return actual.(*http.Client)
}

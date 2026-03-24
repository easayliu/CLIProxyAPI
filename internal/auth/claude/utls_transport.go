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
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
)

// claudeHeaderOrder defines the canonical header order matching the real
// Bun + @anthropic-ai/sdk (Stainless) wire format. Headers not in this
// list are appended at the end in their original order.
var claudeHeaderOrder = []string{
	"host",
	"authorization",
	"x-api-key",
	"content-type",
	"content-length",
	"transfer-encoding",
	"anthropic-version",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"x-app",
	"x-stainless-retry-count",
	"x-stainless-runtime-version",
	"x-stainless-package-version",
	"x-stainless-runtime",
	"x-stainless-lang",
	"x-stainless-arch",
	"x-stainless-os",
	"x-stainless-timeout",
	"user-agent",
	"accept",
	"accept-encoding",
	"connection",
}

// claudeHeaderRank maps lowercase header name to its position in claudeHeaderOrder.
// Built once at init time for O(1) lookups during reordering.
var claudeHeaderRank map[string]int

func init() {
	claudeHeaderRank = make(map[string]int, len(claudeHeaderOrder))
	for i, h := range claudeHeaderOrder {
		claudeHeaderRank[h] = i
	}
}

const (
	// connIdleTimeout is how long an idle pooled connection is kept before eviction.
	connIdleTimeout = 90 * time.Second
	// maxIdlePerHost is the maximum number of idle connections kept per host:port.
	maxIdlePerHost = 3
)

// poolEntry holds an idle connection along with its buffered reader and timestamp.
type poolEntry struct {
	conn      net.Conn
	br        *bufio.Reader
	idleSince time.Time
}

// connPool is a simple per-host idle connection pool for keep-alive reuse.
type connPool struct {
	mu   sync.Mutex
	idle map[string][]*poolEntry // keyed by host:port
}

// get returns an idle connection for addr, or nil if none available.
// Expired entries are closed and discarded.
func (p *connPool) get(addr string) *poolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()

	entries := p.idle[addr]
	now := time.Now()
	for len(entries) > 0 {
		// Pop from the end (LIFO — most recently used).
		e := entries[len(entries)-1]
		entries = entries[:len(entries)-1]
		if now.Sub(e.idleSince) > connIdleTimeout {
			e.conn.Close()
			continue
		}
		p.idle[addr] = entries
		return e
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
	entries := p.idle[addr]
	if len(entries) >= maxIdlePerHost {
		e.conn.Close()
		return
	}
	e.idleSince = time.Now()
	p.idle[addr] = append(entries, e)
}

// utlsRoundTripper implements http.RoundTripper using utls with Bun BoringSSL
// fingerprint to match the real Claude Code CLI's TLS characteristics.
//
// It uses HTTP/1.1 (Bun's ALPN only offers http/1.1) and writes raw HTTP
// with lowercase header names to match Node.js/Bun wire format.
//
// Connections are pooled for keep-alive reuse, matching real CLI behavior.
//
// Proxy support is handled by ProxyDialer (see proxy_dial.go), which establishes
// raw TCP connections through SOCKS5 or HTTP/HTTPS CONNECT proxies before this
// layer applies the utls TLS handshake.
type utlsRoundTripper struct {
	dialer *ProxyDialer // handles proxy tunneling for raw TCP connections
	pool   connPool     // idle connection pool for keep-alive reuse
}

// newUtlsRoundTripper creates a new utls-based round tripper with optional proxy support.
// The proxyURL parameter is the pre-resolved proxy URL string; an empty string means
// inherit proxy from environment variables (HTTPS_PROXY, HTTP_PROXY, ALL_PROXY).
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

// getOrDial returns a pooled connection if available, otherwise dials a new one.
func (t *utlsRoundTripper) getOrDial(req *http.Request, addr string) (net.Conn, *bufio.Reader, error) {
	if pe := t.pool.get(addr); pe != nil {
		return pe.conn, pe.br, nil
	}
	return t.dial(req, addr)
}

// RoundTrip implements http.RoundTripper. It serializes the request with Go's
// standard req.Write, then reorders headers to match the real Bun/Stainless SDK
// order and lowercases header names to match Node.js/Bun wire format.
// The modified payload is sent over a utls connection (pooled when possible).
func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Step 1: Serialize the full HTTP/1.1 request into a buffer.
	// req.Write handles Content-Length, Transfer-Encoding, chunking, etc.
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, fmt.Errorf("serialize request: %w", err)
	}

	// Step 2: Reorder headers to match real Bun/Stainless SDK order and lowercase names.
	reordered := reorderAndLowercaseHeaders(buf.Bytes())

	// Step 3: Resolve target address.
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := "443"
		if req.URL.Scheme == "http" {
			port = "80"
		}
		addr = net.JoinHostPort(addr, port)
	}

	// Step 4-7: Send request and read response. If a pooled connection fails
	// on write or read, retry once with a fresh connection (matching
	// http.Transport's stale-connection retry behavior).
	resp, err := t.roundTripAttempt(req, addr, reordered, true)
	if err != nil {
		// Retry with a fresh connection — the pooled one was likely stale.
		resp, err = t.roundTripAttempt(req, addr, reordered, false)
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// roundTripAttempt performs one send-receive cycle on a connection.
// If allowPool is true, it tries the pool first; otherwise it always dials fresh.
func (t *utlsRoundTripper) roundTripAttempt(req *http.Request, addr string, payload []byte, allowPool bool) (*http.Response, error) {
	var conn net.Conn
	var br *bufio.Reader
	var err error
	if allowPool {
		conn, br, err = t.getOrDial(req, addr)
	} else {
		conn, br, err = t.dial(req, addr)
	}
	if err != nil {
		return nil, err
	}

	// Watch for context cancellation to abort in-flight I/O.
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-req.Context().Done():
			conn.Close()
		case <-cancelDone:
		}
	}()

	// Write request.
	if _, err := conn.Write(payload); err != nil {
		close(cancelDone)
		conn.Close()
		return nil, err
	}

	// Read response headers.
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		close(cancelDone)
		conn.Close()
		return nil, err
	}

	// Wrap the body so the connection is returned to the pool (or closed)
	// when the caller finishes reading the response body.
	// Do not reuse if the server sent "Connection: close".
	resp.Body = &connPoolReader{
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

// connPoolReader wraps a response body. When the body is fully read (io.EOF)
// and the server did not send "Connection: close", the connection is returned
// to the pool for reuse. Otherwise the connection is closed.
type connPoolReader struct {
	io.ReadCloser
	conn    net.Conn
	br      *bufio.Reader
	addr    string
	pool    *connPool
	cancel  chan struct{}
	once    sync.Once
	hitEOF  bool // true when Read returned io.EOF
	noReuse bool // true when resp.Close is set (Connection: close)
}

func (r *connPoolReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err == io.EOF {
		r.hitEOF = true
	}
	return n, err
}

func (r *connPoolReader) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() {
		close(r.cancel)
		if r.hitEOF && !r.noReuse {
			// Body fully consumed and server allows keep-alive — pool the connection.
			r.pool.put(r.addr, &poolEntry{
				conn: r.conn,
				br:   r.br,
			})
		} else {
			// Body not fully read or server sent Connection: close — discard.
			r.conn.Close()
		}
	})
	return err
}

// headerLine holds a parsed header with its lowercase name and original full line bytes.
type headerLine struct {
	lowerName string // lowercase header name (for ordering lookup)
	line      []byte // full original line bytes (e.g. "Content-Type: application/json")
}

// reorderAndLowercaseHeaders parses the raw HTTP/1.1 request bytes, reorders
// headers to match the real Bun + Stainless SDK order (claudeHeaderOrder), and
// lowercases all header names. The request line and body are preserved as-is.
//
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
			// Lowercase the header name portion.
			nameBuf := make([]byte, colonIdx)
			for i := 0; i < colonIdx; i++ {
				c := line[i]
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				nameBuf[i] = c
			}
			// Build the lowercased line: "name" + original ": value" part.
			newLine := make([]byte, 0, len(line))
			newLine = append(newLine, nameBuf...)
			newLine = append(newLine, line[colonIdx:]...)
			headers = append(headers, headerLine{
				lowerName: string(nameBuf),
				line:      newLine,
			})
		}
		pos += nextCRLF + 2
	}

	// Reorder: first emit headers that appear in claudeHeaderOrder (in that order),
	// then append any remaining headers in their original order.
	used := make([]bool, len(headers))
	var result bytes.Buffer
	result.Grow(len(raw) + 64) // slightly over-allocate to avoid realloc
	result.Write(requestLine)
	result.WriteString("\r\n")

	for _, orderedName := range claudeHeaderOrder {
		for i, h := range headers {
			if !used[i] && h.lowerName == orderedName {
				result.Write(h.line)
				result.WriteString("\r\n")
				used[i] = true
				break // only first match per ordered name
			}
		}
	}
	// Append any headers not in the canonical order.
	for i, h := range headers {
		if !used[i] {
			result.Write(h.line)
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

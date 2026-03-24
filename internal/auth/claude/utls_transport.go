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

// utlsRoundTripper implements http.RoundTripper using utls with Bun BoringSSL
// fingerprint to match the real Claude Code CLI's TLS characteristics.
//
// It uses HTTP/1.1 (Bun's ALPN only offers http/1.1) and writes raw HTTP
// with lowercase header names to match Node.js/Bun wire format.
//
// Proxy support is handled by ProxyDialer (see proxy_dial.go), which establishes
// raw TCP connections through SOCKS5 or HTTP/HTTPS CONNECT proxies before this
// layer applies the utls TLS handshake.
type utlsRoundTripper struct {
	dialer *ProxyDialer // handles proxy tunneling for raw TCP connections
}

// newUtlsRoundTripper creates a new utls-based round tripper with optional proxy support.
// The proxyURL parameter is the pre-resolved proxy URL string; an empty string means
// inherit proxy from environment variables (HTTPS_PROXY, HTTP_PROXY, ALL_PROXY).
func newUtlsRoundTripper(proxyURL string) *utlsRoundTripper {
	return &utlsRoundTripper{dialer: NewProxyDialer(proxyURL)}
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

// RoundTrip implements http.RoundTripper. It serializes the request with Go's
// standard req.Write, then converts all header names to lowercase in-place to
// match the wire format of Node.js / Bun HTTP clients. The modified payload is
// sent over a raw utls connection, and the response is read with http.ReadResponse.
//
// Each call dials a fresh TLS connection (no keep-alive pooling). This is
// acceptable for Claude API traffic: streaming calls hold the connection for
// the full response duration anyway, and non-streaming calls are infrequent.
func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Step 1: Serialize the full HTTP/1.1 request into a buffer.
	// req.Write handles Content-Length, Transfer-Encoding, chunking, etc.
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, fmt.Errorf("serialize request: %w", err)
	}

	// Step 2: Lowercase all header names in-place.
	// ASCII case conversion preserves byte length — no reallocation needed.
	lowercaseRequestHeaders(buf.Bytes())

	// Step 3: Resolve target address.
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := "443"
		if req.URL.Scheme == "http" {
			port = "80"
		}
		addr = net.JoinHostPort(addr, port)
	}

	// Step 4: Dial connection (TLS for https, plain TCP for http).
	var conn net.Conn
	var dialErr error
	if req.URL.Scheme == "http" {
		conn, dialErr = t.dialer.DialContext(req.Context(), "tcp", addr)
	} else {
		conn, dialErr = t.dialTLS(req.Context(), "tcp", addr)
	}
	if dialErr != nil {
		return nil, dialErr
	}

	// Step 5: Watch for context cancellation to abort in-flight I/O.
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-req.Context().Done():
			conn.Close()
		case <-cancelDone:
		}
	}()

	// Step 6: Write the request with lowercase headers.
	if _, err := conn.Write(buf.Bytes()); err != nil {
		close(cancelDone)
		conn.Close()
		return nil, err
	}

	// Step 7: Read the response.
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		close(cancelDone)
		conn.Close()
		return nil, err
	}

	// Wrap the body so the connection and cancel goroutine are cleaned up
	// when the caller finishes reading (or closes) the response body.
	resp.Body = &connClosingReader{
		ReadCloser: resp.Body,
		conn:       conn,
		cancel:     cancelDone,
	}

	return resp, nil
}

// connClosingReader wraps a response body and closes the underlying connection
// (and stops the context-cancellation goroutine) when Close is called.
type connClosingReader struct {
	io.ReadCloser
	conn   net.Conn
	cancel chan struct{}
	once   sync.Once
}

func (r *connClosingReader) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() {
		close(r.cancel)
		r.conn.Close()
	})
	return err
}

// lowercaseRequestHeaders converts HTTP/1.1 header names from Go's Title-Case
// to lowercase in-place within the raw request bytes. The request line (first
// line) is left unchanged. Processing stops at the header/body boundary (\r\n\r\n).
//
// Since ASCII uppercase→lowercase is a single-byte operation (A-Z → a-z),
// the conversion is size-preserving and does not affect Content-Length or framing.
func lowercaseRequestHeaders(raw []byte) {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return
	}

	// Skip request line (e.g. "POST /v1/messages HTTP/1.1\r\n").
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd < 0 || lineEnd >= headerEnd {
		return
	}
	pos := lineEnd + 2

	// Process each header line: lowercase everything before the first ':'.
	for pos < headerEnd {
		nextCRLF := bytes.Index(raw[pos:], []byte("\r\n"))
		if nextCRLF < 0 {
			break
		}
		line := raw[pos : pos+nextCRLF]
		if colonIdx := bytes.IndexByte(line, ':'); colonIdx > 0 {
			for i := 0; i < colonIdx; i++ {
				if line[i] >= 'A' && line[i] <= 'Z' {
					line[i] += 32
				}
			}
		}
		pos += nextCRLF + 2
	}
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

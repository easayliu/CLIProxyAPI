package executor

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// fingerprintTransport implements http.RoundTripper with uTLS fingerprint
// spoofing to match Node.js/Chrome TLS and HTTP/2 characteristics.
//
// Go's default crypto/tls produces a distinct JA3/JA4 fingerprint that is
// trivially detectable by upstream servers. This transport uses uTLS to
// present a Chrome-like ClientHello, and golang.org/x/net/http2 for proper
// HTTP/2 framing that matches Chrome/Node.js behaviour.
type fingerprintTransport struct {
	profile   utls.ClientHelloID
	proxyFunc func(*http.Request) (*url.URL, error) // nil = direct connection

	// HTTP/2 connection pool keyed by host:port.
	mu     sync.Mutex
	h2Pool map[string]*http2.ClientConn
}

// newFingerprintTransport creates a transport that spoofs TLS fingerprints.
// If proxyFn is non-nil, connections are tunneled through the proxy via CONNECT.
func newFingerprintTransport(profile utls.ClientHelloID, proxyFn func(*http.Request) (*url.URL, error)) *fingerprintTransport {
	return &fingerprintTransport{
		profile:   profile,
		proxyFunc: proxyFn,
		h2Pool:    make(map[string]*http2.ClientConn),
	}
}

func (t *fingerprintTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		return http.DefaultTransport.RoundTrip(req)
	}

	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	// Try cached HTTP/2 connection first.
	if cc := t.getH2(addr); cc != nil {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// Stale connection; remove and redial below.
		t.removeH2(addr)
	}

	// Dial TCP (direct or via proxy).
	rawConn, err := t.dialRaw(req.Context(), addr, req)
	if err != nil {
		return nil, fmt.Errorf("fingerprint transport: dial: %w", err)
	}

	// uTLS handshake.
	host, _, _ := net.SplitHostPort(addr)
	uConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, t.profile)
	if err := uConn.HandshakeContext(req.Context()); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("fingerprint transport: tls handshake: %w", err)
	}

	alpn := uConn.ConnectionState().NegotiatedProtocol

	if alpn == "h2" {
		return t.roundTripH2(addr, uConn, req)
	}
	return t.roundTripH1(uConn, req)
}

// dialRaw establishes a raw TCP connection, optionally through a CONNECT proxy.
func (t *fingerprintTransport) dialRaw(ctx context.Context, addr string, req *http.Request) (net.Conn, error) {
	dialer := &net.Dialer{}

	if t.proxyFunc == nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}

	proxyURL, err := t.proxyFunc(req)
	if err != nil || proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}

	// SOCKS5 proxy
	if proxyURL.Scheme == "socks5" {
		return t.dialSOCKS5(ctx, proxyURL, addr)
	}

	// HTTP/HTTPS CONNECT proxy
	proxyAddr := proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		if proxyURL.Scheme == "https" {
			proxyAddr += ":443"
		} else {
			proxyAddr += ":80"
		}
	}

	var proxyConn net.Conn
	if proxyURL.Scheme == "https" {
		proxyConn, err = tls.DialWithDialer(dialer, "tcp", proxyAddr, &tls.Config{
			ServerName: proxyURL.Hostname(),
		})
	} else {
		proxyConn, err = dialer.DialContext(ctx, "tcp", proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("proxy dial %s: %w", proxyAddr, err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if proxyURL.User != nil {
		// Basic auth for proxy — not uTLS-relevant, just tunneling.
		connectReq += "Proxy-Authorization: Basic " + basicAuth(proxyURL.User) + "\r\n"
	}
	connectReq += "\r\n"

	if _, writeErr := proxyConn.Write([]byte(connectReq)); writeErr != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", writeErr)
	}

	br := bufio.NewReader(proxyConn)
	resp, readErr := http.ReadResponse(br, nil)
	if readErr != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT read: %w", readErr)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT status %d", resp.StatusCode)
	}

	return proxyConn, nil
}

func (t *fingerprintTransport) dialSOCKS5(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	socks5Addr := proxyURL.Host
	if !strings.Contains(socks5Addr, ":") {
		socks5Addr += ":1080"
	}

	conn, err := dialer.DialContext(ctx, "tcp", socks5Addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial: %w", err)
	}

	// SOCKS5 handshake
	destHost, destPort, _ := net.SplitHostPort(addr)

	// Greeting: version 5, 1 auth method
	hasAuth := proxyURL.User != nil
	if hasAuth {
		_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x02}) // NO AUTH + USER/PASS
	} else {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // NO AUTH
	}

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}

	if buf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: unexpected version %d", buf[0])
	}

	// Handle auth if server selected method 0x02
	if buf[1] == 0x02 && hasAuth {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		authReq := []byte{0x01, byte(len(username))}
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, []byte(password)...)
		if _, err := conn.Write(authReq); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth write: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := conn.Read(authResp); err != nil || authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth failed")
		}
	} else if buf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: unsupported auth method %d", buf[1])
	}

	// CONNECT request
	port := 443
	if destPort != "" {
		fmt.Sscanf(destPort, "%d", &port)
	}
	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}
	connectReq = append(connectReq, []byte(destHost)...)
	connectReq = append(connectReq, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect write: %w", err)
	}

	// Read response (minimum 10 bytes for IPv4)
	respBuf := make([]byte, 10)
	if _, err := conn.Read(respBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect read: %w", err)
	}
	if respBuf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: status %d", respBuf[1])
	}

	return conn, nil
}

// roundTripH2 creates or reuses an HTTP/2 client connection.
func (t *fingerprintTransport) roundTripH2(addr string, conn net.Conn, req *http.Request) (*http.Response, error) {
	h2t := &http2.Transport{
		// DisableCompression matches the request's Accept-Encoding handling;
		// the caller controls compression via headers.
		DisableCompression: true,
	}
	cc, err := h2t.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("fingerprint transport: h2 client conn: %w", err)
	}

	t.mu.Lock()
	t.h2Pool[addr] = cc
	t.mu.Unlock()

	return cc.RoundTrip(req)
}

// roundTripH1 performs HTTP/1.1 request on a pre-established TLS connection.
func (t *fingerprintTransport) roundTripH1(conn net.Conn, req *http.Request) (*http.Response, error) {
	// Write HTTP/1.1 request manually.
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("fingerprint transport: h1 write: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("fingerprint transport: h1 read: %w", err)
	}
	// Wrap the body so that Close also closes the underlying connection
	// when the caller is done reading.
	resp.Body = &connCloseBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// connCloseBody wraps a response body and closes the underlying connection
// when the body is closed (HTTP/1.1 one-shot connection pattern).
type connCloseBody struct {
	ReadCloser interface {
		Read([]byte) (int, error)
		Close() error
	}
	conn net.Conn
}

func (b *connCloseBody) Read(p []byte) (int, error) { return b.ReadCloser.Read(p) }

func (b *connCloseBody) Close() error {
	err1 := b.ReadCloser.Close()
	err2 := b.conn.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (t *fingerprintTransport) getH2(addr string) *http2.ClientConn {
	t.mu.Lock()
	defer t.mu.Unlock()
	cc, ok := t.h2Pool[addr]
	if !ok {
		return nil
	}
	if cc.CanTakeNewRequest() {
		return cc
	}
	delete(t.h2Pool, addr)
	return nil
}

func (t *fingerprintTransport) removeH2(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.h2Pool, addr)
}

func basicAuth(u *url.Userinfo) string {
	if u == nil {
		return ""
	}
	username := u.Username()
	password, _ := u.Password()
	return base64Encode(username + ":" + password)
}

func base64Encode(s string) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(s)+2)/3*4)
	for i := 0; i < len(s); i += 3 {
		var n int
		var pad int
		switch {
		case i+2 < len(s):
			n = int(s[i])<<16 | int(s[i+1])<<8 | int(s[i+2])
		case i+1 < len(s):
			n = int(s[i])<<16 | int(s[i+1])<<8
			pad = 1
		default:
			n = int(s[i]) << 16
			pad = 2
		}
		result = append(result, base64Chars[(n>>18)&0x3f], base64Chars[(n>>12)&0x3f])
		if pad < 2 {
			result = append(result, base64Chars[(n>>6)&0x3f])
		} else {
			result = append(result, '=')
		}
		if pad < 1 {
			result = append(result, base64Chars[n&0x3f])
		} else {
			result = append(result, '=')
		}
	}
	return string(result)
}

// defaultFingerprintProfile is the uTLS profile used when fingerprint spoofing
// is enabled. Chrome_Auto tracks the latest Chrome release which uses BoringSSL —
// the same TLS library that Bun (Claude Code runtime) uses.
var defaultFingerprintProfile = utls.HelloChrome_Auto

// wrapTransportWithFingerprint wraps an existing proxy-aware transport's
// proxy function into a fingerprintTransport. If the base transport is nil,
// a direct (no-proxy) fingerprint transport is returned.
func wrapTransportWithFingerprint(base *http.Transport) http.RoundTripper {
	var proxyFn func(*http.Request) (*url.URL, error)
	if base != nil && base.Proxy != nil {
		proxyFn = base.Proxy
	}
	if base != nil && base.DialContext != nil && base.Proxy == nil {
		// SOCKS5 proxy: the current proxyutil encodes SOCKS5 via DialContext.
		// Wrap the raw dialer into our SOCKS5 tunneling.
		// For SOCKS5, we handle it inside fingerprintTransport.dialSOCKS5.
		// Since proxyutil doesn't expose the parsed URL here, fall back to
		// using the base transport directly but log a warning.
		log.Debug("fingerprint transport: SOCKS5 via DialContext detected, fingerprint may not apply")
		return base
	}
	return newFingerprintTransport(defaultFingerprintProfile, proxyFn)
}

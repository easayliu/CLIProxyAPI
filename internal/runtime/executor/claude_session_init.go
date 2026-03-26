package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	log "github.com/sirupsen/logrus"
)

// SessionInitEmitter sends the blocking "startup" requests that the real
// Claude Code CLI makes when a new interactive session begins. These include
// feature-flag evaluation, MCP server listing, penguin-mode check, account
// settings fetch, grove check, quota probe, title generation, and version check.
//
// Requests are sent once per client session (keyed by session_id from the
// client's metadata.user_id, or from the session pool for non-Claude clients).
// They re-fire after a randomized TTL (1-3 hours) to mimic new terminal windows.
type SessionInitEmitter struct {
	upstream string

	mu       sync.Mutex
	sessions map[string]*initSession
}

type initSession struct {
	createdAt time.Time
	expireAt  time.Time
}

const (
	initSessionBaseTTL = 1 * time.Hour
	initSessionJitter  = 2 * time.Hour // total range: 1-3 hours
	initCliVersion     = "2.1.84"
)

// NewSessionInitEmitter creates a new emitter using the Bun BoringSSL
// TLS-fingerprinted HTTP client for consistent JA3/JA4 fingerprint.
func NewSessionInitEmitter() *SessionInitEmitter {
	si := &SessionInitEmitter{
		upstream: "https://api.anthropic.com",
		sessions: make(map[string]*initSession),
	}
	// Periodically purge expired sessions to prevent memory leak.
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			si.mu.Lock()
			for k, v := range si.sessions {
				if now.After(v.expireAt) {
					delete(si.sessions, k)
				}
			}
			si.mu.Unlock()
		}
	}()
	return si
}

// EmitSessionInit sends all startup requests in parallel and blocks until
// they complete. This must be called BEFORE the actual proxy request to
// match real Claude Code CLI behavior where init requests precede the
// first v1/messages call.
//
// The sessionID (extracted from the client's metadata.user_id) is used as
// the session key. Each unique sessionID triggers init exactly once.
// The apiKey is the current OAuth access_token used for Authorization headers.
func (si *SessionInitEmitter) EmitSessionInit(sessionID, apiKey string, isOAuth bool, deviceID, accountUUID string, proxyURL string) {
	if sessionID == "" {
		return
	}
	if !si.needsInit(sessionID) {
		return
	}
	// Create a per-account HTTP client so session init requests use the same
	// outbound proxy (and therefore the same exit IP) as the main API requests.
	// Use a separate client to avoid mutating the cached shared client's Timeout.
	shared := claudeauth.NewAnthropicHttpClient(proxyURL)
	client := &http.Client{
		Transport: shared.Transport,
		Timeout:   10 * time.Second,
	}
	si.fireAll(client, sessionID, apiKey, isOAuth, deviceID, accountUUID)
}

// needsInit checks whether a session init is needed for the given session ID.
// Returns true if no session exists or the existing one has expired.
func (si *SessionInitEmitter) needsInit(sessionID string) bool {
	si.mu.Lock()
	defer si.mu.Unlock()

	now := time.Now()
	sess, ok := si.sessions[sessionID]
	if ok && now.Before(sess.expireAt) {
		return false
	}

	si.sessions[sessionID] = &initSession{
		createdAt: now,
		expireAt:  now.Add(initSessionBaseTTL + time.Duration(rand.Int64N(int64(initSessionJitter)))),
	}
	return true
}

// fireAll sends all init requests in parallel.
func (si *SessionInitEmitter) fireAll(client *http.Client, sessionID, apiKey string, isOAuth bool, deviceID, accountUUID string) {
	var wg sync.WaitGroup

	// Determine entrypoint style for User-Agent
	entrypoint := "cli" // interactive mode

	// Matches real CLI 2.1.84 startup requests (MITM capture 20260326_091714).
	// Sequence: grove, account_settings, bootstrap, penguin_mode, mcp_servers,
	// mcp_registry, quota_check, cli_version_check all fire in parallel.
	// Then after quota_check completes: mcp_servers (2nd), title_generation.
	reqs := []func(){
		func() { si.fireGrove(client, apiKey, isOAuth, entrypoint) },
		func() { si.fireAccountSettings(client, apiKey, isOAuth) },
		func() { si.firePenguinMode(client, apiKey, isOAuth) },
		func() { si.fireBootstrap(client, apiKey, isOAuth) },
		func() { si.fireMCPServers(client, apiKey, isOAuth) },
		func() { si.fireMCPRegistry(client) },
		func() { si.fireQuotaCheck(client, apiKey, isOAuth, sessionID, deviceID, accountUUID) },
		func() { si.fireCLIVersionCheck(client) },
	}

	for _, fn := range reqs {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}

	wg.Wait()

	// Second wave: fires after quota_check completes (matches real CLI timing).
	// These are less critical — fire in parallel and don't block the main request.
	var wg2 sync.WaitGroup
	reqs2 := []func(){
		func() { si.fireMCPServers(client, apiKey, isOAuth) },
		func() { si.fireTitleGeneration(client, apiKey, isOAuth, sessionID, deviceID, accountUUID) },
	}
	for _, fn := range reqs2 {
		wg2.Add(1)
		go func(f func()) {
			defer wg2.Done()
			f()
		}(fn)
	}
	wg2.Wait()
	log.Debug("[session-init] all startup requests completed")
}

// --- Individual request senders ---

// All init requests use Connection: close and axios-style headers
// matching real CLI 2.1.84 MITM capture (DISABLE_TELEMETRY=1).

func (si *SessionInitEmitter) fireGrove(client *http.Client, apiKey string, isOAuth bool, entrypoint string) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/claude_code_grove", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", fmt.Sprintf("claude-cli/%s (external, %s)", initCliVersion, entrypoint))
	req.Header["anthropic-beta"] = []string{"oauth-2025-04-20"}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "grove")
}

func (si *SessionInitEmitter) fireAccountSettings(client *http.Client, apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/oauth/account/settings", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "claude-code/"+initCliVersion)
	req.Header["anthropic-beta"] = []string{"oauth-2025-04-20"}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "account_settings")
}

func (si *SessionInitEmitter) firePenguinMode(client *http.Client, apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/claude_code_penguin_mode", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "axios/1.13.6")
	req.Header["anthropic-beta"] = []string{"oauth-2025-04-20"}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "penguin_mode")
}

func (si *SessionInitEmitter) fireBootstrap(client *http.Client, apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/claude_cli/bootstrap", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "claude-code/"+initCliVersion)
	req.Header["anthropic-beta"] = []string{"oauth-2025-04-20"}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "bootstrap")
}

func (si *SessionInitEmitter) fireMCPServers(client *http.Client, apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/v1/mcp_servers?limit=1000", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "axios/1.13.6")
	req.Header["anthropic-beta"] = []string{"mcp-servers-2025-12-04"}
	req.Header["anthropic-version"] = []string{"2023-06-01"}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "mcp_servers")
}

func (si *SessionInitEmitter) fireMCPRegistry(client *http.Client) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/mcp-registry/v0/servers?version=latest&visibility=commercial", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "axios/1.13.6")
	si.doRequest(client, req, "mcp_registry")
}

// fireCLIVersionCheck matches MITM capture 20260326_091714 #008.
// Real CLI checks latest version from GCS bucket in first wave.
func (si *SessionInitEmitter) fireCLIVersionCheck(client *http.Client) {
	req, _ := http.NewRequest(http.MethodGet,
		"https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/latest", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "axios/1.13.6")
	si.doRequest(client, req, "cli_version_check")
}

func (si *SessionInitEmitter) fireQuotaCheck(client *http.Client, apiKey string, isOAuth bool, sessionID, deviceID, accountUUID string) {
	userID := buildInitUserID(sessionID, deviceID, accountUUID)
	body := map[string]any{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 1,
		"messages":   []map[string]string{{"role": "user", "content": "quota"}},
		"metadata":   map[string]string{"user_id": userID},
	}
	data, _ := json.Marshal(body)

	// Headers match MITM capture 20260326_091714 #007 (Stainless SDK style).
	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/v1/messages?beta=true", bytes.NewReader(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05")
	req.Header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", fmt.Sprintf("claude-cli/%s (external, cli)", initCliVersion))
	req.Header.Set("X-App", "cli")
	req.Header.Set("X-Stainless-Arch", "arm64")
	req.Header.Set("X-Stainless-Lang", "js")
	req.Header.Set("X-Stainless-Os", "MacOS")
	req.Header.Set("X-Stainless-Package-Version", "0.74.0")
	req.Header.Set("X-Stainless-Retry-Count", "0")
	req.Header.Set("X-Stainless-Runtime", "node")
	req.Header.Set("X-Stainless-Runtime-Version", "v24.3.0")
	req.Header.Set("X-Stainless-Timeout", "600")
	req.Header["x-client-request-id"] = []string{uuid.New().String()}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "quota_check")
}

func (si *SessionInitEmitter) fireTitleGeneration(client *http.Client, apiKey string, isOAuth bool, sessionID, deviceID, accountUUID string) {
	userID := buildInitUserID(sessionID, deviceID, accountUUID)
	// Body matches MITM capture 20260325_230810 #009.
	body := map[string]any{
		"model":       "claude-haiku-4-5-20251001",
		"max_tokens":  32000,
		"stream":      true,
		"temperature": 1,
		"tools":       []any{},
		"messages":    []map[string]any{{"role": "user", "content": []map[string]string{{"type": "text", "text": "hello"}}}},
		"metadata":    map[string]string{"user_id": userID},
		"system": []map[string]string{
			{"type": "text", "text": "x-anthropic-billing-header: cc_version=" + initCliVersion + "." + initBuildHash("hello") + "; cc_entrypoint=cli; cch=00000;"},
			{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."},
			{"type": "text", "text": "Generate a concise, sentence-case title (3-7 words) that captures the main topic or goal of this coding session. The title should be clear enough that the user recognizes the session in a list. Use sentence case: capitalize only the first word and proper nouns.\n\nReturn JSON with a single \"title\" field.\n\nGood examples:\n{\"title\": \"Fix login button on mobile\"}\n{\"title\": \"Add OAuth authentication\"}\n{\"title\": \"Debug failing CI tests\"}\n{\"title\": \"Refactor API client error handling\"}\n\nBad (too vague): {\"title\": \"Code changes\"}\nBad (too long): {\"title\": \"Investigate and fix the issue where the login button does not respond on mobile devices\"}\nBad (wrong case): {\"title\": \"Fix Login Button On Mobile\"}"},
		},
		"output_config": map[string]any{
			"format": map[string]any{
				"type": "json_schema",
				"schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"title": map[string]string{"type": "string"},
					},
					"required":             []string{"title"},
					"additionalProperties": false,
				},
			},
		},
	}
	data, _ := json.Marshal(body)

	// Headers match MITM capture 20260326_091714 (Stainless SDK style).
	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/v1/messages?beta=true", bytes.NewReader(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,structured-outputs-2025-12-15")
	req.Header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", fmt.Sprintf("claude-cli/%s (external, cli)", initCliVersion))
	req.Header.Set("X-App", "cli")
	req.Header.Set("X-Stainless-Arch", "arm64")
	req.Header.Set("X-Stainless-Lang", "js")
	req.Header.Set("X-Stainless-Os", "MacOS")
	req.Header.Set("X-Stainless-Package-Version", "0.74.0")
	req.Header.Set("X-Stainless-Retry-Count", "0")
	req.Header.Set("X-Stainless-Runtime", "node")
	req.Header.Set("X-Stainless-Runtime-Version", "v24.3.0")
	req.Header.Set("X-Stainless-Timeout", "600")
	req.Header["x-client-request-id"] = []string{uuid.New().String()}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "title_generation")
}

// --- Helpers ---

func (si *SessionInitEmitter) setAuth(req *http.Request, apiKey string, isOAuth bool) {
	if isOAuth {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		req.Header.Set("x-api-key", apiKey)
	}
}

func (si *SessionInitEmitter) doRequest(client *http.Client, req *http.Request, label string) {
	resp, err := client.Do(req)
	if err != nil {
		log.Debugf("[session-init] %s failed: %v", label, err)
		return
	}
	// Drain body to allow connection reuse, then close.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Debugf("[session-init] %s returned status %d", label, resp.StatusCode)
	}
}

// initBuildHash computes the 3-char build hash for session init billing headers.
// Uses the same algorithm as the main executor (cli.js _0T):
// SHA256(salt + chars_at_4_7_20 + version).slice(0,3).
func initBuildHash(userText string) string {
	chars := make([]byte, 3)
	indices := [3]int{4, 7, 20}
	for i, idx := range indices {
		if idx < len(userText) {
			chars[i] = userText[idx]
		} else {
			chars[i] = '0'
		}
	}
	input := billingBuildHashSalt + string(chars) + billingCLIVersion
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])[:3]
}

// buildInitUserID builds the JSON user_id for init requests (quota check,
// title generation). Uses the same session_id passed to the emitter so
// all requests within a session share a consistent identity.
func buildInitUserID(sessionID, deviceID, accountUUID string) string {
	uid := userIDPayload{
		DeviceID:    deviceID,
		AccountUUID: accountUUID,
		SessionID:   sessionID,
	}
	data, _ := json.Marshal(uid)
	return string(data)
}

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
	initSessionBaseTTL = 6 * time.Hour
	initSessionJitter  = 6 * time.Hour // total range: 6-12 hours
	initCliVersion     = "2.1.85"
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
// EmitSessionInit sends startup requests for the given sessionID.
// Returns true if init was actually executed, false if skipped (already done or empty ID).
func (si *SessionInitEmitter) EmitSessionInit(sessionID, apiKey string, isOAuth bool, deviceID, accountUUID string, proxyURL string) bool {
	if sessionID == "" {
		return false
	}
	if !si.needsInit(sessionID) {
		log.Infof("[session-init] skipped (already initialized) sessionID=%s", sessionID)
		return false
	}
	log.Infof("[session-init] triggering for sessionID=%s", sessionID)
	// Create a per-account HTTP client so session init requests use the same
	// outbound proxy (and therefore the same exit IP) as the main API requests.
	// Use a separate client to avoid mutating the cached shared client's Timeout.
	shared := claudeauth.NewAnthropicHttpClient(proxyURL)
	client := &http.Client{
		Transport: shared.Transport,
		Timeout:   10 * time.Second,
	}
	if si.fireAll(client, sessionID, apiKey, isOAuth, deviceID, accountUUID) {
		return true
	}
	// Init failed — remove session record so it can be retried next request.
	si.mu.Lock()
	delete(si.sessions, sessionID)
	si.mu.Unlock()
	return false
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

// fireAll sends init requests matching the real CLI default mode (no
// DISABLE_NONESSENTIAL_TRAFFIC). This includes bootstrap, feature flags,
// account settings, grove, penguin mode, MCP servers, plugins, version
// check, and title generation — matching the full startup request set.
// Returns true only if the critical title_generation request succeeded.
func (si *SessionInitEmitter) fireAll(client *http.Client, sessionID, apiKey string, isOAuth bool, deviceID, accountUUID string) bool {
	var wg sync.WaitGroup

	// Wave 1: all startup requests fire in parallel, matching real CLI
	// MITM capture 20260327_153339 (#001-#009).
	wave1 := []func(){
		func() { si.fireGrowthBookEval(client, apiKey, isOAuth, sessionID, deviceID, accountUUID) }, // #001 POST /api/eval/
		func() { si.fireAccountSettings(client, apiKey, isOAuth) },                                  // #002
		func() { si.fireGrove(client, apiKey, isOAuth, "cli") },                                     // #003
		func() { si.fireBootstrap(client, apiKey, isOAuth) },                                        // #004
		func() { si.firePenguinMode(client, apiKey, isOAuth) },                                      // #005
		func() { si.fireMCPServers(client, apiKey, isOAuth) },                                       // #006
		func() { si.fireMCPRegistry(client) },                                                       // #007 (no auth)
		func() { si.fireQuotaCheck(client, apiKey, isOAuth, sessionID, deviceID, accountUUID) },     // #008
		func() { si.fireCLIVersionCheck(client) },                                                   // #009 (no auth)
	}

	for _, fn := range wave1 {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}
	wg.Wait()

	// Wave 2: mcp_servers (2nd fetch, #010) + title_generation.
	// title_generation is the critical request — its success determines init status.
	var titleOK bool
	var wg2 sync.WaitGroup
	wg2.Add(2)
	go func() {
		defer wg2.Done()
		si.fireMCPServers(client, apiKey, isOAuth) // #010
	}()
	go func() {
		defer wg2.Done()
		titleOK = si.fireTitleGeneration(client, apiKey, isOAuth, sessionID, deviceID, accountUUID)
	}()
	wg2.Wait()

	if titleOK {
		log.Infof("[session-init] all startup requests completed (full default mode)")
	} else {
		log.Warnf("[session-init] title_generation failed, sessionID=%s will not be marked initialized", sessionID)
	}
	return titleOK
}

// fireGrowthBookEval sends a POST to Anthropic's GrowthBook remoteEval
// endpoint, matching MITM capture 20260327_153339 #001.
// Uses Bun/1.3.11 User-Agent and sends user attributes for experiment bucketing.
func (si *SessionInitEmitter) fireGrowthBookEval(client *http.Client, apiKey string, isOAuth bool, sessionID, deviceID, accountUUID string) {
	const clientKey = "sdk-zAZezfDKGoZuXXKe"

	body := map[string]any{
		"attributes": map[string]any{
			"id":               deviceID,
			"deviceID":         deviceID,
			"accountUUID":      accountUUID,
			"organizationUUID": "", // filled from auth if available
			"sessionId":        sessionID,
			"platform":         "darwin",
			"userType":         "external",
			"subscriptionType": "max",
			"rateLimitTier":    "default_claude_max_20x",
			"appVersion":       initCliVersion,
			"firstTokenTime":   time.Now().UnixMilli(),
		},
		"forcedFeatures":   []any{},
		"forcedVariations": map[string]any{},
		"url":              "",
	}
	data, _ := json.Marshal(body)

	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/api/eval/"+clientKey, bytes.NewReader(data))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Bun/1.3.11")
	req.Header["anthropic-beta"] = []string{"oauth-2025-04-20"}
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(client, req, "growthbook_eval")
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

// firePluginsCheck matches MITM capture 20260327_104953 #002.
// Real CLI checks plugin security advisories from GitHub.
func (si *SessionInitEmitter) firePluginsCheck(client *http.Client) {
	req, _ := http.NewRequest(http.MethodGet,
		"https://raw.githubusercontent.com/anthropics/claude-plugins-official/refs/heads/security/security.json", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "axios/1.13.6")
	si.doRequest(client, req, "plugins_check")
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

	// Headers match MITM capture 20260327_153339 #008 (Stainless SDK style).
	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/v1/messages?beta=true", bytes.NewReader(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05")
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

func (si *SessionInitEmitter) fireTitleGeneration(client *http.Client, apiKey string, isOAuth bool, sessionID, deviceID, accountUUID string) bool {
	userID := buildInitUserID(sessionID, deviceID, accountUUID)
	buildHash := initBuildHash("hello")
	cch := randomCCH()
	billingHeader := fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; cch=%s;", initCliVersion, buildHash, cch)
	log.Infof("[session-init] title_generation billing: %s", billingHeader)

	// Body matches MITM capture 20260327_091842 #027.
	body := map[string]any{
		"model":       "claude-haiku-4-5-20251001",
		"max_tokens":  32000,
		"stream":      true,
		"temperature": 1,
		"tools":       []any{},
		"messages":    []map[string]any{{"role": "user", "content": []map[string]string{{"type": "text", "text": "hello"}}}},
		"metadata":    map[string]string{"user_id": userID},
		"system": []map[string]string{
			{"type": "text", "text": billingHeader},
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

	// Headers match MITM capture 20260327_153339 (Stainless SDK style).
	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/v1/messages?beta=true", bytes.NewReader(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05,structured-outputs-2025-12-15")
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
	return si.doRequest(client, req, "title_generation")
}

// --- Helpers ---

func (si *SessionInitEmitter) setAuth(req *http.Request, apiKey string, isOAuth bool) {
	if isOAuth {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		req.Header.Set("x-api-key", apiKey)
	}
}

func (si *SessionInitEmitter) doRequest(client *http.Client, req *http.Request, label string) bool {
	log.Infof("[session-init] %s %s %s User-Agent=%s", label, req.Method, req.URL.String(), req.Header.Get("User-Agent"))
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("[session-init] %s failed: %v", label, err)
		return false
	}
	// Drain body to allow connection reuse, then close.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	log.Infof("[session-init] %s status=%d", label, resp.StatusCode)
	return resp.StatusCode < 400
}

// initBuildHash computes the 3-char build hash for session init billing headers.
// Uses the same algorithm as the main executor (cli.js _0T):
// SHA256(salt + chars_at_4_7_20 + version).slice(0,3).
func initBuildHash(userText string) string {
	runes := []rune(userText)
	chars := make([]rune, 3)
	indices := [3]int{4, 7, 20}
	for i, idx := range indices {
		if idx < len(runes) {
			chars[i] = runes[idx]
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

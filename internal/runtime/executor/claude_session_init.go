package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

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
	client   *http.Client
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
	initCliVersion     = "2.1.81"
)

// NewSessionInitEmitter creates a new emitter using the Bun BoringSSL
// TLS-fingerprinted HTTP client for consistent JA3/JA4 fingerprint.
func NewSessionInitEmitter() *SessionInitEmitter {
	client := claudeauth.NewAnthropicHttpClient("")
	client.Timeout = 10 * time.Second
	si := &SessionInitEmitter{
		client:   client,
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
func (si *SessionInitEmitter) EmitSessionInit(sessionID, apiKey string, isOAuth bool, deviceID, accountUUID, orgUUID, email string) {
	if sessionID == "" {
		return
	}
	if !si.needsInit(sessionID) {
		return
	}
	si.fireAll(sessionID, apiKey, isOAuth, deviceID, accountUUID, orgUUID, email)
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
func (si *SessionInitEmitter) fireAll(sessionID, apiKey string, isOAuth bool, deviceID, accountUUID, orgUUID, email string) {
	var wg sync.WaitGroup

	// Determine entrypoint style for User-Agent
	entrypoint := "cli" // interactive mode

	reqs := []func(){
		func() { si.fireGrove(apiKey, isOAuth, entrypoint) },
		func() { si.fireAccountSettings(apiKey, isOAuth) },
		func() { si.firePenguinMode(apiKey, isOAuth) },
		func() { si.fireClientData(apiKey, isOAuth) },
		func() { si.fireMCPServers(apiKey, isOAuth) },
		func() { si.fireVersionCheck() },
		func() { si.fireQuotaCheck(apiKey, isOAuth, sessionID, deviceID, accountUUID) },
		func() { si.fireGrowthBookEval(apiKey, isOAuth, sessionID, deviceID, accountUUID, orgUUID, email) },
		func() { si.fireTitleGeneration(apiKey, isOAuth, sessionID, deviceID, accountUUID) },
	}

	for _, fn := range reqs {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}

	wg.Wait()
	log.Debug("[session-init] all startup requests completed")
}

// --- Individual request senders ---

func (si *SessionInitEmitter) fireGrove(apiKey string, isOAuth bool, entrypoint string) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/claude_code_grove", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	req.Header.Set("User-Agent", fmt.Sprintf("claude-cli/%s (external, %s)", initCliVersion, entrypoint))
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "grove")
}

func (si *SessionInitEmitter) fireAccountSettings(apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/oauth/account/settings", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	req.Header.Set("User-Agent", "claude-code/"+initCliVersion)
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "account_settings")
}

func (si *SessionInitEmitter) firePenguinMode(apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/claude_code_penguin_mode", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	req.Header.Set("User-Agent", "axios/1.13.6")
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "penguin_mode")
}

func (si *SessionInitEmitter) fireClientData(apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/api/oauth/claude_cli/client_data", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "claude-code/"+initCliVersion)
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "client_data")
}

func (si *SessionInitEmitter) fireMCPServers(apiKey string, isOAuth bool) {
	req, _ := http.NewRequest(http.MethodGet, si.upstream+"/v1/mcp_servers?limit=1000", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Anthropic-Beta", "mcp-servers-2025-12-04")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "axios/1.13.6")
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "mcp_servers")
}

func (si *SessionInitEmitter) fireVersionCheck() {
	req, _ := http.NewRequest(http.MethodGet,
		"https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases/latest", nil)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("User-Agent", "axios/1.13.6")
	si.doRequest(req, "version_check")
}

func (si *SessionInitEmitter) fireQuotaCheck(apiKey string, isOAuth bool, sessionID, deviceID, accountUUID string) {
	userID := buildInitUserID(sessionID, deviceID, accountUUID)
	body := map[string]any{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 1,
		"messages":   []map[string]string{{"role": "user", "content": "quota"}},
		"metadata":   map[string]string{"user_id": userID},
	}
	data, _ := json.Marshal(body)

	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/v1/messages?beta=true", bytes.NewReader(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05")
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
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "quota_check")
}

func (si *SessionInitEmitter) fireGrowthBookEval(apiKey string, isOAuth bool, sessionID, deviceID, accountUUID, orgUUID, email string) {
	body := map[string]any{
		"attributes": map[string]any{
			"accountUUID":      accountUUID,
			"appVersion":       initCliVersion,
			"deviceID":         deviceID,
			"email":            email,
			"firstTokenTime":   time.Now().UnixMilli(),
			"id":               deviceID,
			"organizationUUID": orgUUID,
			"platform":         "darwin",
			"rateLimitTier":    "default_claude_max_20x",
			"sessionId":        sessionID,
			"subscriptionType": "max",
			"userType":         "external",
		},
		"forcedFeatures":   []any{},
		"forcedVariations": map[string]any{},
		"url":              "",
	}
	data, _ := json.Marshal(body)

	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/api/eval/sdk-zAZezfDKGoZuXXKe", bytes.NewReader(data))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "Bun/1.3.11")
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "growthbook_eval")
}

func (si *SessionInitEmitter) fireTitleGeneration(apiKey string, isOAuth bool, sessionID, deviceID, accountUUID string) {
	userID := buildInitUserID(sessionID, deviceID, accountUUID)
	body := map[string]any{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 32000,
		"stream":     true,
		"temperature": 1,
		"tools":      []any{},
		"messages":   []map[string]any{{"role": "user", "content": []map[string]string{{"type": "text", "text": "hello"}}}},
		"metadata":   map[string]string{"user_id": userID},
		"system": []map[string]string{
			{"type": "text", "text": "x-anthropic-billing-header: cc_version=" + initCliVersion + ".c43; cc_entrypoint=cli; cch=d74fc;"},
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

	req, _ := http.NewRequest(http.MethodPost, si.upstream+"/v1/messages?beta=true", bytes.NewReader(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05,structured-outputs-2025-12-15")
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
	si.setAuth(req, apiKey, isOAuth)
	si.doRequest(req, "title_generation")
}

// --- Helpers ---

func (si *SessionInitEmitter) setAuth(req *http.Request, apiKey string, isOAuth bool) {
	if isOAuth {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		req.Header.Set("x-api-key", apiKey)
	}
}

func (si *SessionInitEmitter) doRequest(req *http.Request, label string) {
	resp, err := si.client.Do(req)
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

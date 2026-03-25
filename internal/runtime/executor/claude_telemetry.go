package executor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	log "github.com/sirupsen/logrus"
)

// TelemetryEmitter generates and sends CLI telemetry events to Anthropic
// alongside v1/messages requests, using the same upstream auth identity.
// Event structure and timing are derived from real Claude Code CLI 2.1.83
// MITM captures (see /tmp/proxy_captures/).
type TelemetryEmitter struct {
	client   *http.Client
	upstream string // "https://api.anthropic.com"

	// Track per-auth session state
	mu       sync.Mutex
	sessions map[string]*telemetrySession // keyed by upstream API key
}

type telemetrySession struct {
	deviceID    string
	accountUUID string
	orgUUID     string
	sessionID   string
	rh          string
	email       string
	model       string
	initialized bool      // whether init events have been sent
	msgCount    int       // messages sent in this session
	createdAt   time.Time
	expireAt    time.Time // randomized TTL, matching session pool range

	// firstTokenTime is the epoch millis when session was created,
	// used in GrowthbookExperimentEvent user_attributes.
	firstTokenTime int64
}

const (
	// telemetrySessionTTL matches the session pool TTL range (1-3h) at the midpoint.
	telemetrySessionBaseTTL = 1 * time.Hour
	telemetrySessionJitter  = 2 * time.Hour // total range: 1-3 hours

	// Header constants from real CLI 2.1.83 MITM capture.
	telemetryServiceName = "claude-code"
	telemetryBetaHeader  = "oauth-2025-04-20"
	telemetryCliVersion  = "2.1.83"

	// Event body betas from real CLI capture — includes redact-thinking.
	telemetryEventBetas = "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05"
)

// NewTelemetryEmitter creates a new TelemetryEmitter using the same Bun BoringSSL
// TLS-fingerprinted HTTP client as the main API requests.
func NewTelemetryEmitter() *TelemetryEmitter {
	client := claudeauth.NewAnthropicHttpClient("")
	client.Timeout = 5 * time.Second
	return &TelemetryEmitter{
		client:   client,
		upstream: "https://api.anthropic.com",
		sessions: make(map[string]*telemetrySession),
	}
}

// randomTelemetryTTL generates a random TTL in the same range as session pool slots (1-3h).
func randomTelemetryTTL() time.Duration {
	return telemetrySessionBaseTTL + time.Duration(rand.Int64N(int64(telemetrySessionJitter)))
}

// TelemetryIdentity carries real identity fields from the auth metadata.
type TelemetryIdentity struct {
	DeviceID         string
	AccountUUID      string
	OrganizationUUID string
}

// EmitForMessage is called after each successful v1/messages forwarding.
// It generates appropriate telemetry events and sends them to Anthropic.
func (te *TelemetryEmitter) EmitForMessage(apiKey, authToken string, isOAuth bool, model, email string, identity TelemetryIdentity) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("[telemetry-emitter] panic recovered: %v", r)
			}
		}()

		session := te.getOrCreateSession(apiKey, model, email, identity)

		if !session.initialized {
			events := session.emitSessionInit()
			te.sendEventBatch(authToken, isOAuth, events)
			te.mu.Lock()
			session.initialized = true
			te.mu.Unlock()
		}

		msgEvents := session.emitMessageEvents()
		te.sendEventBatch(authToken, isOAuth, msgEvents)

		te.mu.Lock()
		session.msgCount++
		te.mu.Unlock()
	}()
}

// getOrCreateSession looks up or creates a telemetry session for the given API key.
func (te *TelemetryEmitter) getOrCreateSession(apiKey, model, email string, identity TelemetryIdentity) *telemetrySession {
	te.mu.Lock()
	defer te.mu.Unlock()

	session, ok := te.sessions[apiKey]
	now := time.Now()

	if ok && now.After(session.expireAt) {
		ok = false
	}

	if !ok {
		deviceID := DeriveDeviceID(apiKey)
		if identity.DeviceID != "" {
			deviceID = identity.DeviceID
		}
		accountUUID := DeriveAccountUUID(apiKey)
		if identity.AccountUUID != "" {
			accountUUID = identity.AccountUUID
		}
		orgUUID := DeriveOrganizationUUID(apiKey)
		if identity.OrganizationUUID != "" {
			orgUUID = identity.OrganizationUUID
		}
		session = &telemetrySession{
			deviceID:       deviceID,
			accountUUID:    accountUUID,
			orgUUID:        orgUUID,
			sessionID:      PickSessionID(apiKey),
			rh:             DeriveRH(apiKey),
			email:          email,
			model:          model,
			initialized:    false,
			msgCount:       0,
			createdAt:      now,
			expireAt:       now.Add(randomTelemetryTTL()),
			firstTokenTime: now.UnixMilli(),
		}
		te.sessions[apiKey] = session
	}

	if model != "" {
		session.model = model
	}
	if email != "" {
		session.email = email
	}

	return session
}

// --- Session Init Batch ---
// Matches real CLI 2.1.83 first telemetry batch pattern.

func (s *telemetrySession) emitSessionInit() []map[string]any {
	events := make([]map[string]any, 0, 24)
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339Nano)

	// tengu_shell_set_cwd
	events = append(events, s.buildEvent("tengu_shell_set_cwd", ts, map[string]any{
		"rh": s.rh, "success": true,
	}))

	// tengu_claude_in_chrome_setup
	events = append(events, s.buildEvent("tengu_claude_in_chrome_setup", ts, map[string]any{
		"rh": s.rh, "platform": "macos",
	}))

	// tengu_started
	events = append(events, s.buildEvent("tengu_started", ts, map[string]any{
		"rh": s.rh,
	}))

	// tengu_exit (previous session stats)
	events = append(events, s.buildEvent("tengu_exit", ts, s.fakeExitMetadata()))

	// tengu_dir_search (agents)
	events = append(events, s.buildEvent("tengu_dir_search", ts, map[string]any{
		"rh": s.rh, "durationMs": 1, "managedFilesFound": 0, "userFilesFound": 0,
		"projectFilesFound": 0, "projectDirsSearched": 0, "subdir": "agents",
	}))

	// tengu_version_lock_failed
	events = append(events, s.buildEvent("tengu_version_lock_failed", ts, map[string]any{
		"rh": s.rh, "is_pid_based": true, "is_lifetime_lock": true,
	}))

	// tengu_dir_search (commands)
	ts2 := now.Add(8 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_dir_search", ts2, map[string]any{
		"rh": s.rh, "durationMs": 23, "managedFilesFound": 0, "userFilesFound": 1,
		"projectFilesFound": 0, "projectDirsSearched": 0, "subdir": "commands",
	}))

	// tengu_timer
	events = append(events, s.buildEvent("tengu_timer", ts2, map[string]any{
		"rh": s.rh, "name": "config_load", "durationMs": rand.IntN(30) + 10,
	}))

	// tengu_claudemd__initial_load
	events = append(events, s.buildEvent("tengu_claudemd__initial_load", ts2, map[string]any{
		"rh": s.rh, "loadedPaths": 2, "totalChars": rand.IntN(5000) + 1000,
	}))

	// tengu_prompt_suggestion_init
	events = append(events, s.buildEvent("tengu_prompt_suggestion_init", ts2, map[string]any{
		"rh": s.rh,
	}))

	// GrowthbookExperimentEvent (tengu_desktop_upsell_tip)
	events = append(events, s.buildGrowthbookEvent("tengu_desktop_upsell_tip", "{\"feature_id\":\"tengu_desktop_upsell\"}", 0, now))

	// tengu_init
	events = append(events, s.buildEvent("tengu_init", now.Add(time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "entrypoint": "claude", "hasInitialPrompt": false, "hasStdin": false,
		"verbose": false, "debug": false, "debugToStderr": false, "print": false,
		"outputFormat": "text", "inputFormat": "text",
		"numAllowedTools": 18, "numDisallowedTools": 0, "mcpClientCount": 2,
		"worktree": false, "dangerouslySkipPermissionsPassed": false,
		"permissionMode": "default", "modeIsBypass": false,
		"allowDangerouslySkipPermissionsPassed": false,
		"thinkingType": "adaptive", "appendSystemPromptFlag": "flag",
		"autoUpdatesChannel": "latest",
	}))

	// tengu_startup_manual_model_config
	events = append(events, s.buildEvent("tengu_startup_manual_model_config", now.Add(time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "hasModelFlag": false, "hasModelConfig": false,
		"hasProviderConfig": false, "configuredModel": "",
	}))

	// tengu_prompt_suggestion_init (2nd)
	events = append(events, s.buildEvent("tengu_prompt_suggestion_init", now.Add(time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh,
	}))

	// tengu_mcp_server_connection_succeeded
	events = append(events, s.buildEvent("tengu_mcp_server_connection_succeeded", now.Add(2*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "connectionDurationMs": rand.IntN(2000) + 500,
		"totalServers": 2, "stdioCount": 1, "sseCount": 0, "httpCount": 0,
		"sseIdeCount": 0, "wsIdeCount": 0, "transportType": "stdio",
	}))

	// tengu_native_auto_updater_start
	events = append(events, s.buildEvent("tengu_native_auto_updater_start", now.Add(2*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh,
	}))

	// tengu_repo_text_file_size
	events = append(events, s.buildEvent("tengu_repo_text_file_size", now.Add(2*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "sizeBytes": rand.IntN(5000000) + 1000000,
		"filesCount": rand.IntN(500) + 100,
	}))

	// tengu_concurrent_sessions
	events = append(events, s.buildEvent("tengu_concurrent_sessions", now.Add(2*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "count": 1,
	}))

	// tengu_ripgrep_availability
	events = append(events, s.buildEvent("tengu_ripgrep_availability", now.Add(2*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "available": true,
	}))

	// tengu_startup_telemetry
	events = append(events, s.buildEvent("tengu_startup_telemetry", now.Add(2*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "is_git": true, "worktree_count": 1,
		"repo_text_file_size_bytes": rand.IntN(5000000) + 1000000,
		"gh_auth_status": "authenticated", "sandbox_enabled": false,
		"are_unsandboxed_commands_allowed": true,
		"is_auto_bash_allowed_if_sandbox_enabled": true,
		"auto_updater_disabled": false, "prefers_reduced_motion": false,
	}))

	// tengu_mcp_servers
	events = append(events, s.buildEvent("tengu_mcp_servers", now.Add(3*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "configuredCount": 2, "connectedCount": 1,
	}))

	// tengu_ext_installed
	events = append(events, s.buildEvent("tengu_ext_installed", now.Add(3*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh,
	}))

	// tengu_version_check_success
	events = append(events, s.buildEvent("tengu_version_check_success", now.Add(4*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "latency_ms": 400 + rand.IntN(600),
	}))

	// tengu_claudeai_limits_status_changed
	events = append(events, s.buildEvent("tengu_claudeai_limits_status_changed", now.Add(4*time.Second).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "status": "allowed",
		"unifiedRateLimitFallbackAvailable": true,
		"hoursTillReset":                    1 + rand.IntN(4),
	}))

	return events
}

// --- Per-Message Batch ---
// Matches real CLI 2.1.83 second telemetry batch pattern.

func (s *telemetrySession) emitMessageEvents() []map[string]any {
	events := make([]map[string]any, 0, 10)
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339Nano)

	// GrowthbookExperimentEvent (tengu_defer_all_v3)
	events = append(events, s.buildGrowthbookEvent("tengu_defer_all_v3", "{\"feature_id\":\"tengu_defer_all_bn4\"}", 1, now))

	// tengu_input_prompt
	events = append(events, s.buildEvent("tengu_input_prompt", ts, map[string]any{
		"rh": s.rh, "is_negative": false, "is_keep_going": false,
	}))

	// tengu_attachment_compute_duration
	events = append(events, s.buildEvent("tengu_attachment_compute_duration", ts, map[string]any{
		"rh": s.rh, "durationMs": rand.IntN(50) + 5,
	}))

	// tengu_api_before_normalize
	events = append(events, s.buildEvent("tengu_api_before_normalize", ts, map[string]any{
		"rh": s.rh,
	}))

	// tengu_api_after_normalize
	events = append(events, s.buildEvent("tengu_api_after_normalize", ts, map[string]any{
		"rh": s.rh,
	}))

	// tengu_api_cache_breakpoints
	events = append(events, s.buildEvent("tengu_api_cache_breakpoints", ts, map[string]any{
		"rh": s.rh,
	}))

	// tengu_api_query
	durationMs := 2000 + rand.IntN(8000)
	events = append(events, s.buildEvent("tengu_api_query", ts, map[string]any{
		"rh": s.rh, "model": s.model, "messagesLength": 1 + s.msgCount*2,
		"temperature": 1, "provider": "firstParty",
		"buildAgeMins": rand.IntN(500) + 100,
		"betas":          telemetryEventBetas + ",advanced-tool-use-2025-11-20,effort-2025-11-24",
		"permissionMode": "default", "querySource": "repl_main_thread",
		"queryChainId": uuid.New().String(), "queryDepth": 0,
		"thinkingType": "adaptive", "effortValue": "medium", "fastMode": false,
	}))

	// tengu_api_success
	inputTokens := rand.IntN(50000) + 1000
	outputTokens := rand.IntN(5000) + 100
	events = append(events, s.buildEvent("tengu_api_success", now.Add(time.Duration(durationMs)*time.Millisecond).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "model": s.model,
		"betas":          telemetryEventBetas + ",advanced-tool-use-2025-11-20,effort-2025-11-24",
		"messageCount":   1 + s.msgCount*2,
		"messageTokens":  0,
		"inputTokens":    inputTokens,
		"outputTokens":   outputTokens,
		"cachedInputTokens":   rand.IntN(inputTokens),
		"uncachedInputTokens": rand.IntN(inputTokens / 2),
		"durationMs":                durationMs,
		"durationMsIncludingRetries": durationMs + rand.IntN(50),
		"attempt":    1,
		"ttftMs":     durationMs - rand.IntN(100),
		"buildAgeMins": rand.IntN(500) + 100,
		"provider":     "firstParty",
		"requestId":    fmt.Sprintf("req_%s", uuid.New().String()[:24]),
		"stop_reason":  "end_turn",
		"costUSD":      float64(inputTokens*3+outputTokens*15) / 1000000.0,
		"didFallBackToNonStreaming": false,
		"isNonInteractiveSession":  false,
		"print":                    false,
		"isTTY":                    true,
		"querySource":              "repl_main_thread",
		"permissionMode":           "default",
		"globalCacheStrategy":      "none",
		"textContentLength":        rand.IntN(5000) + 50,
		"fastMode":                 false,
	}))

	// tengu_claudeai_limits_status_changed
	events = append(events, s.buildEvent("tengu_claudeai_limits_status_changed", now.Add(time.Duration(durationMs)*time.Millisecond).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "status": "allowed",
		"unifiedRateLimitFallbackAvailable": true,
		"hoursTillReset":                    1 + rand.IntN(4),
	}))

	return events
}

// --- Event Builders ---

// buildEvent constructs a ClaudeCodeInternalEvent matching real CLI 2.1.83 format.
func (s *telemetrySession) buildEvent(eventName, timestamp string, extraMetadata map[string]any) map[string]any {
	metaMap := make(map[string]any)
	for k, v := range extraMetadata {
		metaMap[k] = v
	}
	if _, ok := metaMap["rh"]; !ok {
		metaMap["rh"] = s.rh
	}
	metaJSON, _ := json.Marshal(metaMap)
	additionalMetadata := base64.StdEncoding.EncodeToString(metaJSON)

	processInfo := s.buildProcessInfo()
	processJSON, _ := json.Marshal(processInfo)
	processB64 := base64.StdEncoding.EncodeToString(processJSON)

	// Build time: use session creation date with fixed hour offset.
	buildTime := s.createdAt.UTC().Add(-5 * time.Hour).Format("2006-01-02T15:04:05Z")

	eventData := map[string]any{
		"additional_metadata": additionalMetadata,
		"betas":               telemetryEventBetas,
		"client_timestamp":    timestamp,
		"client_type":         "cli",
		"device_id":           s.deviceID,
		"entrypoint":          "cli",
		"env": map[string]any{
			"arch":                   "arm64",
			"build_time":             buildTime,
			"deployment_environment": "unknown-darwin",
			"is_ci":                  false,
			"is_claubbit":            false,
			"is_claude_ai_auth":      true,
			"is_claude_code_action":  false,
			"is_claude_code_remote":  false,
			"is_conductor":           false,
			"is_github_action":       false,
			"is_local_agent_mode":    false,
			"is_running_with_bun":    true,
			"node_version":           "v24.3.0",
			"package_managers":       "npm,pnpm",
			"platform":              "darwin",
			"platform_raw":          "darwin",
			"runtimes":              "node",
			"terminal":              "vscode",
			"vcs":                   "git",
			"version":               telemetryCliVersion,
			"version_base":          telemetryCliVersion,
		},
		"event_id":      uuid.New().String(),
		"event_name":    eventName,
		"is_interactive": true,
		"model":          s.model,
		"process":        processB64,
		"session_id":     s.sessionID,
		"user_type":      "external",
	}

	// Add auth fields for initialized sessions or always for init batch
	if s.email != "" {
		eventData["email"] = s.email
	}
	if s.accountUUID != "" || s.orgUUID != "" {
		eventData["auth"] = map[string]any{
			"account_uuid":      s.accountUUID,
			"organization_uuid": s.orgUUID,
		}
	}

	return map[string]any{
		"event_type": "ClaudeCodeInternalEvent",
		"event_data": eventData,
	}
}

// buildGrowthbookEvent constructs a GrowthbookExperimentEvent matching real CLI format.
func (s *telemetrySession) buildGrowthbookEvent(experimentID, experimentMetadata string, variationID int, ts time.Time) map[string]any {
	userAttrs := map[string]any{
		"id":               s.deviceID,
		"sessionId":        s.sessionID,
		"deviceID":         s.deviceID,
		"platform":         "darwin",
		"organizationUUID": s.orgUUID,
		"accountUUID":      s.accountUUID,
		"userType":         "external",
		"subscriptionType": "max",
		"rateLimitTier":    "default_claude_max_20x",
		"firstTokenTime":   s.firstTokenTime,
		"email":            s.email,
		"appVersion":       telemetryCliVersion,
	}
	userAttrsJSON, _ := json.Marshal(userAttrs)

	eventData := map[string]any{
		"auth": map[string]any{
			"account_uuid":      s.accountUUID,
			"organization_uuid": s.orgUUID,
		},
		"device_id":           s.deviceID,
		"environment":         "production",
		"event_id":            uuid.New().String(),
		"experiment_id":       experimentID,
		"experiment_metadata": experimentMetadata,
		"session_id":          s.sessionID,
		"timestamp":           ts.UTC().Format(time.RFC3339Nano),
		"user_attributes":     string(userAttrsJSON),
		"variation_id":        variationID,
	}

	return map[string]any{
		"event_type": "GrowthbookExperimentEvent",
		"event_data": eventData,
	}
}

// buildProcessInfo generates realistic Node.js process info matching real CLI format.
func (s *telemetrySession) buildProcessInfo() map[string]any {
	uptimeSec := time.Since(s.createdAt).Seconds()
	if uptimeSec < 0.1 {
		uptimeSec = 0.2 + rand.Float64()*0.1
	}

	rss := (250 + rand.IntN(150)) * 1024 * 1024         // 250-400MB
	heapTotal := (30 + rand.IntN(20)) * 1024 * 1024      // 30-50MB
	heapUsed := (25 + rand.IntN(25)) * 1024 * 1024       // 25-50MB
	external := (20 + rand.IntN(60)) * 1024 * 1024       // 20-80MB
	arrayBuffers := (15 + rand.IntN(10)) * 1024 * 1024   // 15-25MB

	info := map[string]any{
		"uptime":             uptimeSec,
		"rss":                rss,
		"heapTotal":          heapTotal,
		"heapUsed":           heapUsed,
		"external":           external,
		"arrayBuffers":       arrayBuffers,
		"constrainedMemory":  34359738368, // 32GB, consistent across captures
		"cpuUsage": map[string]any{
			"user":   rand.IntN(2000000) + 100000,
			"system": rand.IntN(400000) + 30000,
		},
	}

	// Add cpuPercent for non-startup events (real CLI adds it after first few events)
	if time.Since(s.createdAt) > 5*time.Second {
		info["cpuPercent"] = rand.Float64()*5 + 0.5
	}

	return info
}

// fakeExitMetadata generates realistic tengu_exit additional_metadata for "previous session".
func (s *telemetrySession) fakeExitMetadata() map[string]any {
	return map[string]any{
		"rh": s.rh,
		"last_session_cost":                           float64(rand.IntN(200)) + 10.0,
		"last_session_api_duration":                   rand.IntN(10000000) + 1000000,
		"last_session_tool_duration":                  rand.IntN(500000) + 50000,
		"last_session_duration":                       rand.IntN(20000000) + 2000000,
		"last_session_lines_added":                    rand.IntN(1000) + 50,
		"last_session_lines_removed":                  rand.IntN(500) + 10,
		"last_session_total_input_tokens":             rand.IntN(50000) + 5000,
		"last_session_total_output_tokens":            rand.IntN(200000) + 10000,
		"last_session_total_cache_creation_input_tokens": rand.IntN(20000000) + 1000000,
		"last_session_total_cache_read_input_tokens":  rand.IntN(50000000) + 5000000,
		"last_session_id":                             uuid.New().String(),
	}
}

// --- HTTP Sender ---

// sendEventBatch sends a batch of telemetry events to the Anthropic event logging endpoint.
// Headers match real CLI 2.1.83 MITM capture exactly.
func (te *TelemetryEmitter) sendEventBatch(authToken string, isOAuth bool, events []map[string]any) {
	if len(events) == 0 {
		return
	}

	payload := map[string]any{
		"events": events,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("[telemetry-emitter] failed to marshal event batch: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/event_logging/v2/batch", te.upstream)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Errorf("[telemetry-emitter] failed to create request: %v", err)
		return
	}

	// Headers match real CLI 2.1.83 capture exactly:
	//   Accept: application/json, text/plain, */*
	//   Accept-Encoding: gzip, compress, deflate, br
	//   Content-Type: application/json
	//   User-Agent: claude-code/2.1.83
	//   anthropic-beta: oauth-2025-04-20
	//   x-service-name: claude-code
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "claude-code/"+telemetryCliVersion)
	req.Header["anthropic-beta"] = []string{telemetryBetaHeader}
	req.Header["x-service-name"] = []string{telemetryServiceName}

	if isOAuth {
		req.Header.Set("Authorization", "Bearer "+authToken)
	} else {
		req.Header.Set("x-api-key", authToken)
	}

	resp, err := te.client.Do(req)
	if err != nil {
		log.Debugf("[telemetry-emitter] failed to send event batch: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Debugf("[telemetry-emitter] event batch returned status %d", resp.StatusCode)
	}
}

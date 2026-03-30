package executor

import (
	"bytes"
	"crypto/sha256"
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
// using a buffered flush model matching the real CLI's OTLP BatchLogRecordProcessor.
//
// Real CLI behavior (from MITM capture 20260327_153339):
//   - Events are buffered, flushed every ~10 seconds (scheduledDelayMillis=10000)
//   - Init batch (#011) fires ~10s after startup requests (#001-#010)
//   - Post-init batch (#013) fires ~31s after startup
//   - Per-message events are batched across multiple API calls
//   - Periodic standalone batches (version_cleanup, notification) fire independently
type TelemetryEmitter struct {
	client   *http.Client
	upstream string // "https://api.anthropic.com"

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
	authToken   string // cached for flush goroutine
	isOAuth     bool

	initialized     bool      // whether init events have been queued
	postInitSent    bool      // whether post-init batch has been sent
	msgCount        int       // messages sent in this session
	createdAt       time.Time
	expireAt        time.Time // randomized TTL, matching session pool range
	firstTokenTime  int64     // epoch millis for GrowthBook user_attributes
	lastCleanupAt   time.Time // last periodic cleanup batch time

	// Buffered events waiting for the next flush cycle.
	pendingEvents []map[string]any
	flushTimer    *time.Timer // 10-second flush timer
}

const (
	// telemetrySessionTTL matches the session pool TTL range (1-3h) at the midpoint.
	telemetrySessionBaseTTL = 1 * time.Hour
	telemetrySessionJitter  = 2 * time.Hour // total range: 1-3 hours

	// Header constants from real CLI 2.1.84 MITM capture.
	telemetryServiceName = "claude-code"
	telemetryBetaHeader  = "oauth-2025-04-20"
	telemetryCliVersion  = "2.1.85"

	// Event body betas from real CLI capture — includes redact-thinking.
	telemetryEventBetas = "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05"
)

// NewTelemetryEmitter creates a new TelemetryEmitter using a dedicated HTTP client
// with Bun BoringSSL TLS fingerprint and a short timeout suitable for telemetry.
//
// IMPORTANT: This intentionally creates a separate http.Client instead of reusing
// the cached one from NewAnthropicHttpClient, because setting Timeout on the shared
// cached client would affect all API requests (Execute/ExecuteStream) that share
// the same pointer.
func NewTelemetryEmitter() *TelemetryEmitter {
	client := &http.Client{
		Transport: claudeauth.NewAnthropicTransport(""),
		Timeout:   5 * time.Second,
	}
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
// SessionID should be set to the same slot sessionID used for the API request
// to keep telemetry consistent with the request body's device/session identity.
type TelemetryIdentity struct {
	DeviceID         string
	AccountUUID      string
	OrganizationUUID string
	SessionID        string
}

// EmitForMessage is called after each successful v1/messages forwarding.
// Events are buffered and flushed on a 10-second timer matching the real
// CLI's OTLP BatchLogRecordProcessor (scheduledDelayMillis=10000).
func (te *TelemetryEmitter) EmitForMessage(apiKey, authToken string, isOAuth bool, model, email string, identity TelemetryIdentity) {
	te.mu.Lock()
	session := te.getOrCreateSessionLocked(apiKey, model, email, identity)
	session.authToken = authToken
	session.isOAuth = isOAuth

	if !session.initialized {
		// Queue init events — they will be flushed ~10s later,
		// matching real CLI timing where init batch (#011) arrives
		// ~10s after startup requests (#001-#010).
		initEvents := session.emitSessionInit()
		session.pendingEvents = append(session.pendingEvents, initEvents...)
		session.initialized = true

		// Schedule post-init batch ~20s later (real CLI #013 at t+31s,
		// but init flush is at t+10s, so post-init is ~20s after that).
		go te.schedulePostInit(apiKey, 20*time.Second+time.Duration(rand.IntN(5000))*time.Millisecond)

		// Schedule periodic cleanup batch (~9 min, then ~30 min)
		go te.schedulePeriodicCleanup(apiKey, 9*time.Minute+time.Duration(rand.IntN(60000))*time.Millisecond)
	}

	// Queue per-message events into the buffer.
	msgEvents := session.emitMessageEvents()
	session.pendingEvents = append(session.pendingEvents, msgEvents...)
	session.msgCount++

	// Start or reset the 10-second flush timer.
	te.ensureFlushTimerLocked(apiKey, session)
	te.mu.Unlock()
}

// ensureFlushTimerLocked starts a 10-second flush timer if not already running.
// Must be called with te.mu held.
func (te *TelemetryEmitter) ensureFlushTimerLocked(apiKey string, session *telemetrySession) {
	if session.flushTimer != nil {
		return // timer already running, events will be flushed on next tick
	}
	delay := 9*time.Second + time.Duration(rand.IntN(2000))*time.Millisecond // 9-11s jitter
	session.flushTimer = time.AfterFunc(delay, func() {
		te.flushSession(apiKey)
	})
}

// flushSession sends all pending events for a session and resets the buffer.
func (te *TelemetryEmitter) flushSession(apiKey string) {
	te.mu.Lock()
	session, ok := te.sessions[apiKey]
	if !ok || len(session.pendingEvents) == 0 {
		if ok {
			session.flushTimer = nil
		}
		te.mu.Unlock()
		return
	}

	events := session.pendingEvents
	session.pendingEvents = nil
	session.flushTimer = nil
	authToken := session.authToken
	isOAuth := session.isOAuth
	te.mu.Unlock()

	log.Infof("[telemetry-emitter] flushing %d events for session", len(events))
	te.sendEventBatch(authToken, isOAuth, events)
}

// schedulePostInit sends the post-init batch (#013) after a delay.
// Contains MCP completion events: mcp_tools_commands_loaded, context_size, etc.
func (te *TelemetryEmitter) schedulePostInit(apiKey string, delay time.Duration) {
	time.Sleep(delay)
	te.mu.Lock()
	session, ok := te.sessions[apiKey]
	if !ok || session.postInitSent {
		te.mu.Unlock()
		return
	}
	session.postInitSent = true
	authToken := session.authToken
	isOAuth := session.isOAuth
	te.mu.Unlock()

	events := session.emitPostInit()
	if len(events) > 0 {
		log.Infof("[telemetry-emitter] sending post-init batch (%d events)", len(events))
		te.sendEventBatch(authToken, isOAuth, events)
	}
}

// schedulePeriodicCleanup sends standalone periodic batches
// (native_version_cleanup at ~9min, then every ~30min).
func (te *TelemetryEmitter) schedulePeriodicCleanup(apiKey string, initialDelay time.Duration) {
	time.Sleep(initialDelay)
	for {
		te.mu.Lock()
		session, ok := te.sessions[apiKey]
		if !ok || time.Now().After(session.expireAt) {
			te.mu.Unlock()
			return
		}
		authToken := session.authToken
		isOAuth := session.isOAuth
		session.lastCleanupAt = time.Now()
		te.mu.Unlock()

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		events := []map[string]any{
			session.buildEvent("tengu_native_version_cleanup", ts, map[string]any{
				"rh": session.rh, "total_count": 3, "deleted_count": 0,
				"protected_count": 1, "retained_count": 2,
				"lock_failed_count": 0, "error_count": 0,
			}),
		}
		log.Infof("[telemetry-emitter] sending periodic cleanup batch")
		te.sendEventBatch(authToken, isOAuth, events)

		// Next cleanup in ~30 min (matching real CLI pattern)
		time.Sleep(30*time.Minute + time.Duration(rand.IntN(120000))*time.Millisecond)
	}
}

// getOrCreateSessionLocked looks up or creates a telemetry session for the given API key.
// Must be called with te.mu held.
func (te *TelemetryEmitter) getOrCreateSessionLocked(apiKey, model, email string, identity TelemetryIdentity) *telemetrySession {
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
		// Use the sessionID from the caller (executor) so telemetry identity
		// matches the API request body. Generate a random one as fallback
		// (should not happen in normal flow).
		sessionID := identity.SessionID
		if sessionID == "" {
			sessionID = uuid.New().String()
		}
		session = &telemetrySession{
			deviceID:       deviceID,
			accountUUID:    accountUUID,
			orgUUID:        orgUUID,
			sessionID:      sessionID,
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
// Matches real CLI 2.1.85 MITM capture 20260327_153339 #011 (58 events).

func (s *telemetrySession) emitSessionInit() []map[string]any {
	events := make([]map[string]any, 0, 60)
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339Nano)

	// #0 tengu_dir_search (agents)
	events = append(events, s.buildEvent("tengu_dir_search", ts, map[string]any{
		"rh": s.rh, "durationMs": 1, "managedFilesFound": 0, "userFilesFound": 0,
		"projectFilesFound": 0, "projectDirsSearched": 0, "subdir": "agents",
	}))
	// #1 tengu_started
	events = append(events, s.buildEvent("tengu_started", ts, map[string]any{"rh": s.rh}))
	// #2 tengu_shell_set_cwd
	events = append(events, s.buildEvent("tengu_shell_set_cwd", ts, map[string]any{
		"rh": s.rh, "success": true,
	}))
	// #3 tengu_claude_in_chrome_setup
	events = append(events, s.buildEvent("tengu_claude_in_chrome_setup", ts, map[string]any{
		"rh": s.rh, "platform": "macos",
	}))

	// #4 tengu_version_lock_failed (+7ms)
	ts4 := now.Add(7 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_version_lock_failed", ts4, map[string]any{
		"rh": s.rh, "is_pid_based": true, "is_lifetime_lock": true,
	}))
	// #5 tengu_exit (+8ms)
	ts5 := now.Add(8 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_exit", ts5, s.fakeExitMetadata()))

	// #6 tengu_dir_search (commands) (+14ms)
	ts6 := now.Add(14 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_dir_search", ts6, map[string]any{
		"rh": s.rh, "durationMs": 20, "managedFilesFound": 0, "userFilesFound": 1,
		"projectFilesFound": 0, "projectDirsSearched": 0, "subdir": "commands",
	}))
	// #7 tengu_timer (+28ms)
	ts7 := now.Add(28 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_timer", ts7, map[string]any{
		"rh": s.rh, "event": "startup", "durationMs": 200 + rand.IntN(100),
	}))
	// #8 tengu_claudemd__initial_load (+39ms)
	ts8 := now.Add(39 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_claudemd__initial_load", ts8, map[string]any{
		"rh": s.rh, "file_count": 2, "total_content_length": 1500 + rand.IntN(1000),
		"user_count": 0, "project_count": 1, "local_count": 0,
		"managed_count": 0, "automem_count": 1, "teammem_count": 0,
		"duration_ms": 3 + rand.IntN(8),
	}))
	// #9 tengu_prompt_suggestion_init (+42ms)
	ts9 := now.Add(42 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_prompt_suggestion_init", ts9, map[string]any{
		"rh": s.rh, "enabled": false, "source": "growthbook",
	}))

	// #10 GrowthbookExperimentEvent (tengu_desktop_upsell_tip) (~+1s)
	events = append(events, s.buildGrowthbookEvent("tengu_desktop_upsell_tip", "{\"feature_id\":\"tengu_desktop_upsell\"}", 0, now.Add(time.Second)))

	// #11 tengu_init (+1.015s)
	ts11 := now.Add(1015 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_init", ts11, map[string]any{
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
	// #12 tengu_startup_manual_model_config
	events = append(events, s.buildEvent("tengu_startup_manual_model_config", ts11, map[string]any{
		"rh": s.rh, "subscriptionType": "max",
	}))
	// #13 tengu_prompt_suggestion_init (2nd)
	events = append(events, s.buildEvent("tengu_prompt_suggestion_init", ts11, map[string]any{
		"rh": s.rh, "enabled": false, "source": "growthbook",
	}))

	// #14-35 tengu_skill_loaded (22 skills, +1.016s, all same ms)
	tsSkills := now.Add(1016 * time.Millisecond).Format(time.RFC3339Nano)
	skills := []struct{ name, source, loadedFrom string }{
		{"update-config", "bundled", "bundled"},
		{"keybindings-help", "bundled", "bundled"},
		{"simplify", "bundled", "bundled"},
		{"loop", "bundled", "bundled"},
		{"schedule", "bundled", "bundled"},
		{"claude-api", "bundled", "bundled"},
		{"ui-ux-pro-max", "userSettings", "skills"},
		{"ts-style", "userSettings", "skills"},
		{"restful-style", "userSettings", "skills"},
		{"orris-responsive", "userSettings", "skills"},
		{"ffuf-skill", "userSettings", "skills"},
		{"go-style", "userSettings", "skills"},
		{"implement", "userSettings", "skills"},
		{"subagent-driven-development", "userSettings", "skills"},
		{"commit", "userSettings", "commands_DEPRECATED"},
		{"interface-design:status", "plugin", ""},
		{"interface-design:extract", "plugin", ""},
		{"interface-design:critique", "plugin", ""},
		{"interface-design:audit", "plugin", ""},
		{"interface-design:init", "plugin", ""},
		{"frontend-design:frontend-design", "plugin", "plugin"},
		{"interface-design:interface-design", "plugin", "plugin"},
	}
	for _, sk := range skills {
		meta := map[string]any{
			"rh": s.rh, "skill_budget": 80000,
		}
		ev := s.buildEvent("tengu_skill_loaded", tsSkills, meta)
		// skill_name and skill_source are top-level event_data fields
		ev["event_data"].(map[string]any)["skill_name"] = sk.name
		ev["event_data"].(map[string]any)["skill_source"] = sk.source
		if sk.loadedFrom != "" {
			ev["event_data"].(map[string]any)["skill_loaded_from"] = sk.loadedFrom
		}
		events = append(events, ev)
	}

	// #36 tengu_dir_search (output-styles) (+1.018s)
	ts36 := now.Add(1018 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_dir_search", ts36, map[string]any{
		"rh": s.rh, "durationMs": 51, "managedFilesFound": 0, "userFilesFound": 0,
		"projectFilesFound": 0, "projectDirsSearched": 0, "subdir": "output-styles",
	}))
	// #37 tengu_dir_search (workflows)
	events = append(events, s.buildEvent("tengu_dir_search", ts36, map[string]any{
		"rh": s.rh, "durationMs": 51, "managedFilesFound": 0, "userFilesFound": 0,
		"projectFilesFound": 0, "projectDirsSearched": 0, "subdir": "workflows",
	}))
	// #38 tengu_mcp_server_connection_succeeded (+1.022s)
	ts38 := now.Add(1022 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_mcp_server_connection_succeeded", ts38, map[string]any{
		"rh": s.rh, "connectionDurationMs": 50 + rand.IntN(100),
		"transportType": "stdio", "totalServers": 2, "stdioCount": 1,
		"sseCount": 0, "httpCount": 0, "sseIdeCount": 0, "wsIdeCount": 0,
	}))
	// #39 tengu_native_auto_updater_start (+1.035s)
	ts39 := now.Add(1035 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_native_auto_updater_start", ts39, map[string]any{"rh": s.rh}))

	// #40 tengu_file_suggestions_git_ls_files (+1.042s)
	ts40 := now.Add(1042 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_file_suggestions_git_ls_files", ts40, map[string]any{
		"rh": s.rh, "file_count": 400 + rand.IntN(200), "tracked_count": 400 + rand.IntN(200),
		"untracked_count": 0, "duration_ms": 50 + rand.IntN(80),
	}))
	// #41 tengu_concurrent_sessions (+1.044s)
	ts41 := now.Add(1044 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_concurrent_sessions", ts41, map[string]any{
		"rh": s.rh, "num_sessions": 1 + rand.IntN(3),
	}))
	// #42 tengu_plugin_remote_fetch (+1.060s)
	ts42 := now.Add(1060 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_plugin_remote_fetch", ts42, map[string]any{
		"rh": s.rh, "source": "blocklist", "host": "raw.githubusercontent.com",
		"is_official": true, "outcome": "cache_hit", "duration_ms": 0,
	}))
	// #43 tengu_plugins_loaded (+1.078s)
	ts43 := now.Add(1078 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_plugins_loaded", ts43, map[string]any{
		"rh": s.rh, "enabled_count": 3, "disabled_count": 0, "inline_count": 0,
		"marketplace_count": 3, "error_count": 0, "skill_count": 5,
		"agent_count": 0, "hook_count": 0, "mcp_count": 1, "lsp_count": 0,
		"has_custom_plugin_cache_dir": false,
	}))
	// #44 tengu_dir_search (skills) (+1.080s)
	ts44 := now.Add(1080 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_dir_search", ts44, map[string]any{
		"rh": s.rh, "durationMs": 113, "managedFilesFound": 0, "userFilesFound": 10,
		"projectFilesFound": 0, "projectDirsSearched": 0, "subdir": "skills",
	}))
	// #45 tengu_ripgrep_availability (+1.083s)
	ts45 := now.Add(1083 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_ripgrep_availability", ts45, map[string]any{
		"rh": s.rh, "working": 1, "using_system": 0,
	}))
	// #46 tengu_startup_telemetry (+1.114s)
	ts46 := now.Add(1114 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_startup_telemetry", ts46, map[string]any{
		"rh": s.rh, "is_git": true, "worktree_count": 1,
		"gh_auth_status": "authenticated", "sandbox_enabled": false,
		"are_unsandboxed_commands_allowed":        true,
		"is_auto_bash_allowed_if_sandbox_enabled": true,
		"auto_updater_disabled": false, "prefers_reduced_motion": false,
	}))

	// #47 tengu_claudeai_mcp_eligibility (+1.554s)
	ts47 := now.Add(1554 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_claudeai_mcp_eligibility", ts47, map[string]any{
		"rh": s.rh, "state": "eligible",
	}))
	// #48 tengu_mcp_servers
	events = append(events, s.buildEvent("tengu_mcp_servers", ts47, map[string]any{
		"rh": s.rh, "enterprise": 0, "global": 0, "project": 0,
		"user": 0, "plugin": 3, "claudeai": 0,
	}))
	// #49 tengu_mcp_ide_server_connection_failed (+1.556s)
	ts49 := now.Add(1556 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_mcp_ide_server_connection_failed", ts49, map[string]any{
		"rh": s.rh, "connectionDurationMs": 3,
	}))
	// #50 tengu_mcp_server_connection_failed
	events = append(events, s.buildEvent("tengu_mcp_server_connection_failed", ts49, map[string]any{
		"rh": s.rh, "connectionDurationMs": 3, "totalServers": 3, "stdioCount": 1,
		"sseCount": 0, "httpCount": 0, "sseIdeCount": 0, "wsIdeCount": 1,
		"transportType": "ws-ide", "mcpServerBaseUrl": "ws://127.0.0.1:34952",
	}))

	// #51 tengu_ext_installed (+1.593s)
	ts51 := now.Add(1593 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_ext_installed", ts51, map[string]any{"rh": s.rh}))

	// #52 tengu_claudeai_mcp_eligibility (+1.673s)
	ts52 := now.Add(1673 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_claudeai_mcp_eligibility", ts52, map[string]any{
		"rh": s.rh, "state": "eligible",
	}))

	// #53 tengu_version_check_success (+2.126s)
	versionLatencyMs := 800 + rand.IntN(500)
	ts53 := now.Add(2126 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_version_check_success", ts53, map[string]any{
		"rh": s.rh, "latency_ms": versionLatencyMs,
	}))
	// #54 tengu_native_update_complete
	events = append(events, s.buildEvent("tengu_native_update_complete", ts53, map[string]any{
		"rh": s.rh, "latency_ms": versionLatencyMs + 1,
		"was_new_install": false, "was_force_reinstall": false, "was_already_running": true,
	}))
	// #55 tengu_native_auto_updater_success
	events = append(events, s.buildEvent("tengu_native_auto_updater_success", ts53, map[string]any{
		"rh": s.rh, "latency_ms": versionLatencyMs + 2,
	}))
	// #56 tengu_claudeai_limits_status_changed (+2.132s)
	ts56 := now.Add(2132 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_claudeai_limits_status_changed", ts56, map[string]any{
		"rh": s.rh, "status": "allowed_warning",
		"unifiedRateLimitFallbackAvailable": false,
		"hoursTillReset":                    20 + rand.IntN(30),
	}))
	// #57 tengu_native_version_cleanup (+2.148s)
	ts57 := now.Add(2148 * time.Millisecond).Format(time.RFC3339Nano)
	events = append(events, s.buildEvent("tengu_native_version_cleanup", ts57, map[string]any{
		"rh": s.rh, "total_count": 3, "deleted_count": 0, "protected_count": 1,
		"retained_count": 2, "lock_failed_count": 0, "error_count": 0,
	}))

	return events
}

// --- Post-Init Batch ---
// Matches real CLI 2.1.85 MITM capture 20260327_153339 #013 (6 events at t+31s).
// Fires after MCP connections complete / time out.

func (s *telemetrySession) emitPostInit() []map[string]any {
	events := make([]map[string]any, 0, 8)
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339Nano)

	// tengu_mcp_server_connection_failed x2 (MCP timeout after ~30s)
	events = append(events, s.buildEvent("tengu_mcp_server_connection_failed", ts, map[string]any{
		"rh": s.rh, "connectionDurationMs": 30000 + rand.IntN(100),
		"totalServers": 2, "stdioCount": 1, "sseCount": 0, "httpCount": 0,
		"sseIdeCount": 0, "wsIdeCount": 0, "transportType": "stdio",
	}))
	events = append(events, s.buildEvent("tengu_mcp_server_connection_failed", now.Add(591*time.Millisecond).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "connectionDurationMs": 30000 + rand.IntN(100),
		"totalServers": 3, "stdioCount": 1, "sseCount": 0, "httpCount": 0,
		"sseIdeCount": 0, "wsIdeCount": 1, "transportType": "stdio",
	}))

	// tengu_mcp_tools_commands_loaded x2
	events = append(events, s.buildEvent("tengu_mcp_tools_commands_loaded", ts, map[string]any{
		"rh": s.rh, "tools_count": 18, "commands_count": 0, "commands_metadata_length": 0,
	}))
	events = append(events, s.buildEvent("tengu_mcp_tools_commands_loaded", ts, map[string]any{
		"rh": s.rh, "tools_count": 18, "commands_count": 0, "commands_metadata_length": 0,
	}))

	// tengu_context_size
	events = append(events, s.buildEvent("tengu_context_size", ts, map[string]any{
		"rh": s.rh, "git_status_size": 800 + rand.IntN(500),
		"claude_md_size": 2000 + rand.IntN(1000), "total_context_size": 3000 + rand.IntN(1000),
		"project_file_count_rounded": 2000, "mcp_tools_count": 18, "mcp_servers_count": 1,
		"mcp_tools_tokens": 3000 + rand.IntN(500), "non_mcp_tools_count": 27,
		"non_mcp_tools_tokens": 4500 + rand.IntN(500),
	}))

	// tengu_file_suggestions_git_ls_files
	events = append(events, s.buildEvent("tengu_file_suggestions_git_ls_files", now.Add(634*time.Millisecond).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "file_count": 400 + rand.IntN(200), "tracked_count": 400 + rand.IntN(200),
		"untracked_count": 0, "duration_ms": 15 + rand.IntN(30),
	}))

	return events
}

// --- Per-Message Batch ---
// Matches real CLI 2.1.85 MITM capture 20260327_153339 #040+#041 pattern.
// First message (#017) has extra events (deferred_tools, title_gen, etc.)
// that are omitted here for simplicity — subsequent messages are the norm.

func (s *telemetrySession) emitMessageEvents() []map[string]any {
	events := make([]map[string]any, 0, 20)
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339Nano)
	msgLen := 1 + s.msgCount*2 // messagesLength grows per turn
	buildAge := 600 + rand.IntN(200)
	mainBetas := telemetryEventBetas + ",advanced-tool-use-2025-11-20,effort-2025-11-24"
	queryChainID := uuid.New().String()

	// Periodic: version check events (~every hour, piggyback on msg batch)
	if s.msgCount > 0 && s.msgCount%5 == 0 {
		vLatency := 800 + rand.IntN(500)
		events = append(events, s.buildEvent("tengu_native_auto_updater_start", ts, map[string]any{"rh": s.rh}))
		events = append(events, s.buildEvent("tengu_version_check_success", ts, map[string]any{
			"rh": s.rh, "latency_ms": vLatency,
		}))
		events = append(events, s.buildEvent("tengu_native_update_complete", ts, map[string]any{
			"rh": s.rh, "latency_ms": vLatency + 1,
			"was_new_install": false, "was_force_reinstall": false, "was_already_running": true,
		}))
		events = append(events, s.buildEvent("tengu_native_auto_updater_success", ts, map[string]any{
			"rh": s.rh, "latency_ms": vLatency + 1,
		}))
		events = append(events, s.buildEvent("tengu_native_version_cleanup", ts, map[string]any{
			"rh": s.rh, "total_count": 3, "deleted_count": 0, "protected_count": 1,
			"retained_count": 2, "lock_failed_count": 0, "error_count": 0,
		}))
	}

	// tengu_paste_text (always present)
	events = append(events, s.buildEvent("tengu_paste_text", ts, map[string]any{
		"rh": s.rh, "pastedTextCount": 0, "pastedTextBytes": 0,
	}))

	// tengu_attachment_compute_duration (x2 for subsequent messages)
	if s.msgCount > 0 {
		events = append(events, s.buildEvent("tengu_attachment_compute_duration", ts, map[string]any{
			"rh": s.rh, "label": "agent_pending_messages", "duration_ms": 0,
			"attachment_size_bytes": 0, "attachment_count": 0,
		}))
		events = append(events, s.buildEvent("tengu_attachment_compute_duration", ts, map[string]any{
			"rh": s.rh, "label": "unified_tasks", "duration_ms": 0,
			"attachment_size_bytes": 0, "attachment_count": 0,
		}))
	}

	// tengu_input_prompt
	events = append(events, s.buildEvent("tengu_input_prompt", ts, map[string]any{
		"rh": s.rh, "is_negative": false, "is_keep_going": false,
	}))

	// tengu_file_history_snapshot_success
	events = append(events, s.buildEvent("tengu_file_history_snapshot_success", ts, map[string]any{
		"rh": s.rh, "trackedFilesCount": 0, "snapshotCount": 1 + s.msgCount,
	}))

	// tengu_tool_search_mode_decision
	events = append(events, s.buildEvent("tengu_tool_search_mode_decision", ts, map[string]any{
		"rh": s.rh, "enabled": true, "mode": "tst", "reason": "tst_enabled",
		"checkedModel": s.model, "mcpToolCount": 18, "userType": "external",
	}))

	// tengu_api_before_normalize
	events = append(events, s.buildEvent("tengu_api_before_normalize", ts, map[string]any{
		"rh": s.rh, "preNormalizedMessageCount": msgLen + 2,
	}))
	// tengu_api_after_normalize
	events = append(events, s.buildEvent("tengu_api_after_normalize", ts, map[string]any{
		"rh": s.rh, "postNormalizedMessageCount": msgLen,
	}))

	// tengu_sysprompt_boundary_found (x2)
	events = append(events, s.buildEvent("tengu_sysprompt_boundary_found", ts, map[string]any{
		"rh": s.rh, "blockCount": 4, "staticBlockLength": 13132,
		"dynamicBlockLength": 15000 + rand.IntN(5000),
	}))
	// tengu_sysprompt_block
	events = append(events, s.buildEvent("tengu_sysprompt_block", ts, map[string]any{
		"rh": s.rh, "snippet": "x-anthropic-billing-", "length": 80,
		"hash": fmt.Sprintf("%x", sha256.Sum256([]byte(s.sessionID+ts))),
	}))
	// tengu_sysprompt_boundary_found (2nd)
	events = append(events, s.buildEvent("tengu_sysprompt_boundary_found", ts, map[string]any{
		"rh": s.rh, "blockCount": 4, "staticBlockLength": 13132,
		"dynamicBlockLength": 15000 + rand.IntN(5000),
	}))

	// tengu_api_cache_breakpoints
	events = append(events, s.buildEvent("tengu_api_cache_breakpoints", ts, map[string]any{
		"rh": s.rh, "totalMessageCount": msgLen, "cachingEnabled": true, "skipCacheWrite": false,
	}))

	// tengu_api_query
	durationMs := 2000 + rand.IntN(8000)
	events = append(events, s.buildEvent("tengu_api_query", ts, map[string]any{
		"rh": s.rh, "model": s.model, "messagesLength": msgLen,
		"temperature": 1, "provider": "firstParty",
		"buildAgeMins": buildAge, "betas": mainBetas,
		"permissionMode": "default", "querySource": "repl_main_thread",
		"queryChainId": queryChainID, "queryDepth": 0,
		"thinkingType": "adaptive", "effortValue": "medium", "fastMode": false,
	}))

	// tengu_api_cache_breakpoints (2nd, after query sent)
	events = append(events, s.buildEvent("tengu_api_cache_breakpoints", now.Add(time.Duration(durationMs)*time.Millisecond).Format(time.RFC3339Nano), map[string]any{
		"rh": s.rh, "totalMessageCount": msgLen, "cachingEnabled": true, "skipCacheWrite": false,
	}))

	// tengu_api_success (arrives after durationMs)
	tsSuccess := now.Add(time.Duration(durationMs) * time.Millisecond).Format(time.RFC3339Nano)
	inputTokens := rand.IntN(50000) + 1000
	outputTokens := rand.IntN(5000) + 100
	cachedInput := 10000 + rand.IntN(5000)
	uncachedInput := 5000 + rand.IntN(5000)
	events = append(events, s.buildEvent("tengu_api_success", tsSuccess, map[string]any{
		"rh": s.rh, "model": s.model, "preNormalizedModel": s.model,
		"betas": mainBetas, "messageCount": msgLen, "messageTokens": 0,
		"inputTokens": inputTokens, "outputTokens": outputTokens,
		"cachedInputTokens": cachedInput, "uncachedInputTokens": uncachedInput,
		"durationMs": durationMs, "durationMsIncludingRetries": durationMs + rand.IntN(50),
		"attempt": 1, "ttftMs": durationMs - rand.IntN(100),
		"buildAgeMins": buildAge, "provider": "firstParty",
		"requestId":    fmt.Sprintf("req_%s", uuid.New().String()[:24]),
		"stop_reason":  "end_turn",
		"costUSD":      float64(inputTokens*3+outputTokens*15) / 1000000.0,
		"didFallBackToNonStreaming": false, "isNonInteractiveSession": false,
		"print": false, "isTTY": true,
		"querySource": "repl_main_thread", "queryChainId": queryChainID,
		"queryDepth": 0, "permissionMode": "default",
		"globalCacheStrategy": "system_prompt", "textContentLength": rand.IntN(5000) + 50,
		"fastMode": false,
	}))

	// tengu_prompt_suggestion
	events = append(events, s.buildEvent("tengu_prompt_suggestion", tsSuccess, map[string]any{
		"rh": s.rh, "source": "cli", "outcome": "suppressed",
		"reason": "disabled", "prompt_id": "user_intent",
	}))

	return events
}

// --- Event Builders ---

// buildEvent constructs a ClaudeCodeInternalEvent matching real CLI 2.1.84 format.
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
// Headers match real CLI 2.1.84 MITM capture exactly.
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

	// Headers match real CLI 2.1.84 capture exactly:
	//   Accept: application/json, text/plain, */*
	//   Accept-Encoding: gzip, compress, deflate, br
	//   Content-Type: application/json
	//   User-Agent: claude-code/2.1.84
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

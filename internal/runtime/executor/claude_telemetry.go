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
	log "github.com/sirupsen/logrus"
)

// TelemetryEmitter generates and sends CLI telemetry events to Anthropic
// alongside v1/messages requests, using the same upstream auth identity.
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
}

const (
	telemetrySessionTTL   = 2 * time.Hour
	telemetryUserAgent    = "claude-code/2.1.81"
	telemetryServiceName  = "claude-code"
	telemetryBetaHeader   = "oauth-2025-04-20"
	telemetryBetas        = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,prompt-caching-scope-2026-01-05"
	telemetryVersion      = "2.1.81"
	telemetryBuildTime    = "2026-03-20T21:26:18Z"
	telemetryNodeVersion  = "v24.3.0"
)

// NewTelemetryEmitter creates a new TelemetryEmitter with a 5s timeout HTTP client.
func NewTelemetryEmitter() *TelemetryEmitter {
	return &TelemetryEmitter{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		upstream: "https://api.anthropic.com",
		sessions: make(map[string]*telemetrySession),
	}
}

// EmitForMessage is called after each successful v1/messages forwarding.
// It generates appropriate telemetry events and sends them to Anthropic.
// Parameters:
//   - apiKey: the upstream auth's API key (used for identity derivation)
//   - authToken: the token to use in Authorization header (Bearer or x-api-key)
//   - isOAuth: whether authToken is an OAuth token (use Bearer) or API key (use x-api-key)
//   - model: the model used in the request
//   - email: email from auth metadata (can be empty)
func (te *TelemetryEmitter) EmitForMessage(apiKey, authToken string, isOAuth bool, model, email string) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("[telemetry-emitter] panic recovered: %v", r)
			}
		}()

		session := te.getOrCreateSession(apiKey, model, email)

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
// Sessions expire after 2 hours to simulate new terminal windows.
func (te *TelemetryEmitter) getOrCreateSession(apiKey, model, email string) *telemetrySession {
	te.mu.Lock()
	defer te.mu.Unlock()

	session, ok := te.sessions[apiKey]
	now := time.Now()

	// Expire sessions older than 2 hours
	if ok && now.Sub(session.createdAt) > telemetrySessionTTL {
		ok = false
	}

	if !ok {
		session = &telemetrySession{
			deviceID:    DeriveDeviceID(apiKey),
			accountUUID: DeriveAccountUUID(apiKey),
			orgUUID:     DeriveOrganizationUUID(apiKey),
			sessionID:   PickSessionID(apiKey),
			rh:          DeriveRH(apiKey),
			email:       email,
			model:       model,
			initialized: false,
			msgCount:    0,
			createdAt:   now,
		}
		te.sessions[apiKey] = session
	}

	// Update model if changed
	if model != "" {
		session.model = model
	}
	if email != "" {
		session.email = email
	}

	return session
}

// emitSessionInit generates the initialization event batch.
func (s *telemetrySession) emitSessionInit() []map[string]any {
	events := make([]map[string]any, 0, 4)

	// 1. tengu_started
	events = append(events, s.buildEvent("tengu_started", map[string]any{
		"rh": s.rh,
	}))

	// 2. tengu_init
	events = append(events, s.buildEvent("tengu_init", map[string]any{
		"rh":                   s.rh,
		"entrypoint":           "cli",
		"hasInitialPrompt":     false,
		"permissionMode":       "default",
		"thinkingType":         "adaptive",
		"autoUpdatesChannel":   "latest",
		"hasCustomSystemPrompt": false,
		"hasCustomInstructions": true,
		"hasProjectConfig":     true,
		"isDefaultModel":       true,
		"numMCPServers":        0,
		"numAllowedTools":      0,
		"numDeniedTools":       0,
	}))

	// 3. tengu_version_check_success
	events = append(events, s.buildEvent("tengu_version_check_success", map[string]any{
		"rh":         s.rh,
		"latency_ms": 400 + rand.IntN(300), // 400-699ms
	}))

	// 4. tengu_startup_telemetry
	events = append(events, s.buildEvent("tengu_startup_telemetry", map[string]any{
		"rh":                      s.rh,
		"is_git":                  true,
		"sandbox_enabled":         false,
		"project_file_count":      rand.IntN(500) + 100,
		"project_claudemd_count":  1,
		"user_claudemd_count":     1,
		"startup_time_ms":         800 + rand.IntN(400),
		"hasTenguDir":             true,
		"hasTenguProjectDir":      true,
	}))

	return events
}

// emitMessageEvents generates per-message telemetry events.
func (s *telemetrySession) emitMessageEvents() []map[string]any {
	events := make([]map[string]any, 0, 1)

	// tengu_claudeai_limits_status_changed
	events = append(events, s.buildEvent("tengu_claudeai_limits_status_changed", map[string]any{
		"rh":                                   s.rh,
		"status":                               "allowed",
		"unifiedRateLimitFallbackAvailable":     false,
		"hoursTillReset":                        4,
	}))

	return events
}

// buildEvent constructs a single telemetry event with all standard fields.
func (s *telemetrySession) buildEvent(eventName string, extraMetadata map[string]any) map[string]any {
	now := time.Now().UTC()

	// Build additional_metadata: merge extraMetadata with rh, then base64 encode
	metaMap := make(map[string]any)
	for k, v := range extraMetadata {
		metaMap[k] = v
	}
	metaMap["rh"] = s.rh
	metaJSON, _ := json.Marshal(metaMap)
	additionalMetadata := base64.StdEncoding.EncodeToString(metaJSON)

	// Build process info (randomized but realistic)
	processInfo := map[string]any{
		"uptime":             100 + rand.IntN(3500),
		"rss":                (200 + rand.IntN(200)) * 1024 * 1024, // 200-400MB
		"heapTotal":          (30 + rand.IntN(20)) * 1024 * 1024,   // 30-50MB
		"heapUsed":           (25 + rand.IntN(20)) * 1024 * 1024,   // 25-45MB
		"external":           (20 + rand.IntN(20)) * 1024 * 1024,   // 20-40MB
		"arrayBuffers":       (10 + rand.IntN(10)) * 1024 * 1024,   // 10-20MB
		"constrainedMemory":  34359738368,
		"cpuUsage": map[string]any{
			"user":   rand.IntN(5000000) + 1000000,
			"system": rand.IntN(1000000) + 200000,
		},
	}
	processJSON, _ := json.Marshal(processInfo)
	processB64 := base64.StdEncoding.EncodeToString(processJSON)

	eventData := map[string]any{
		"betas":                telemetryBetas,
		"client_timestamp":    now.Format(time.RFC3339Nano),
		"client_type":         "cli",
		"device_id":           s.deviceID,
		"entrypoint":          "cli",
		"event_id":            uuid.New().String(),
		"event_name":          eventName,
		"is_interactive":      true,
		"model":               s.model,
		"session_id":          s.sessionID,
		"user_type":           "external",
		"additional_metadata": additionalMetadata,
		"process":             processB64,
		"env": map[string]any{
			"arch":                    "arm64",
			"build_time":             telemetryBuildTime,
			"deployment_environment":  "unknown-darwin",
			"is_ci":                  false,
			"is_claubbit":            false,
			"is_claude_ai_auth":      false,
			"is_claude_code_action":  false,
			"is_claude_code_remote":  false,
			"is_conductor":           false,
			"is_github_action":       false,
			"is_local_agent_mode":    false,
			"is_running_with_bun":    true,
			"node_version":           telemetryNodeVersion,
			"package_managers":       "npm,pnpm",
			"platform":              "darwin",
			"platform_raw":          "darwin",
			"runtimes":              "node",
			"terminal":              "vscode",
			"vcs":                   "git",
			"version":               telemetryVersion,
			"version_base":          telemetryVersion,
		},
	}

	// Add auth/email fields for initialized sessions
	if s.initialized && s.email != "" {
		eventData["email"] = s.email
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

// sendEventBatch sends a batch of telemetry events to the Anthropic event logging endpoint.
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

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", telemetryUserAgent)
	req.Header.Set("X-Service-Name", telemetryServiceName)
	req.Header.Set("Anthropic-Beta", telemetryBetaHeader)

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

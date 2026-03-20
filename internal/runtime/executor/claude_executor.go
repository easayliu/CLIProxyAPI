package executor

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"runtime"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/gin-gonic/gin"
)

// ClaudeExecutor is a stateless executor for Anthropic Claude over the messages API.
// If api_key is unavailable on auth, it falls back to legacy via ClientAdapter.
type ClaudeExecutor struct {
	cfg *config.Config
}

// claudeToolPrefix is empty to match real Claude Code behavior (no tool name prefix).
// Previously "proxy_" was used but this is a detectable fingerprint difference.
const claudeToolPrefix = ""

func NewClaudeExecutor(cfg *config.Config) *ClaudeExecutor { return &ClaudeExecutor{cfg: cfg} }

func (e *ClaudeExecutor) Identifier() string { return "claude" }

// PrepareRequest injects Claude credentials into the outgoing HTTP request.
func (e *ClaudeExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	apiKey, _ := claudeCreds(auth)
	if strings.TrimSpace(apiKey) == "" {
		return nil
	}
	useAPIKey := auth != nil && auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != ""
	isAnthropicBase := req.URL != nil && strings.EqualFold(req.URL.Scheme, "https") && strings.EqualFold(req.URL.Host, "api.anthropic.com")
	if isAnthropicBase && useAPIKey {
		req.Header.Del("Authorization")
		req.Header.Set("x-api-key", apiKey)
	} else {
		req.Header.Del("x-api-key")
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects Claude credentials into the request and executes it.
func (e *ClaudeExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("claude executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := newClaudeHTTPClient(e.cfg, auth)
	return httpClient.Do(httpReq)
}

func (e *ClaudeExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	if opts.Alt == "responses/compact" {
		return resp, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}

	// Enforce per-auth RPM limit before proceeding
	if err := checkClaudeRateLimit(auth); err != nil {
		return resp, err
	}

	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := claudeCreds(auth)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.trackFailure(ctx, &err)
	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")
	// Use streaming translation to preserve function calling, except for claude.
	stream := from != to
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, stream)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, stream)
	body, _ = sjson.SetBytes(body, "model", baseModel)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	// Always regenerate system[0] (billing header) and system[1] (agent block)
	// to ensure version consistency with our template, regardless of cloaking.
	// This prevents version mismatch when a real Claude Code CLI with a different
	// version connects through an upstream proxy like NewAPI.
	if !strings.HasPrefix(baseModel, "claude-3-5-haiku") {
		oauthMode := isClaudeOAuthToken(apiKey)
		body = checkSystemInstructionsWithMode(body, false, oauthMode)
	}

	// Apply cloaking (fake user ID, field sanitization, sensitive word obfuscation)
	// based on client type and configuration.
	body = applyCloaking(ctx, e.cfg, auth, body, baseModel, apiKey)

	requestedModel := payloadRequestedModel(opts, req.Model)
	body = applyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel)

	// Disable thinking if tool_choice forces tool use (Anthropic API constraint)
	body = disableThinkingIfToolChoiceForced(body)

	// Auto-inject cache_control if missing (optimization for ClawdBot/clients without caching support)
	if countCacheControls(body) == 0 {
		body = ensureCacheControl(body)
	}

	// Enforce Anthropic's cache_control block limit (max 4 breakpoints per request).
	// Cloaking and ensureCacheControl may push the total over 4 when the client
	// (e.g. Amp CLI) already sends multiple cache_control blocks.
	body = enforceCacheControlLimit(body, 4)

	// Normalize TTL values to prevent ordering violations under prompt-caching-scope-2026-01-05.
	// A 1h-TTL block must not appear after a 5m-TTL block in evaluation order (tools→system→messages).
	body = normalizeCacheControlTTL(body)

	// Extract betas from body and convert to header
	var extraBetas []string
	extraBetas, body = extractAndRemoveBetas(body)
	bodyForTranslation := body
	bodyForUpstream := body
	if isClaudeOAuthToken(apiKey) && !auth.ToolPrefixDisabled() {
		bodyForUpstream = applyClaudeToolPrefix(body, claudeToolPrefix)
	}

	url := fmt.Sprintf("%s/v1/messages?beta=true", baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyForUpstream))
	if err != nil {
		return resp, err
	}
	applyClaudeHeaders(httpReq, auth, apiKey, false, extraBetas, e.cfg, baseModel)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      bodyForUpstream,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := newClaudeHTTPClient(e.cfg, auth)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		// Decompress error responses — pass the Content-Encoding value (may be empty)
		// and let decodeResponseBody handle both header-declared and magic-byte-detected
		// compression.  This keeps error-path behaviour consistent with the success path.
		errBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			recordAPIResponseError(ctx, e.cfg, decErr)
			msg := fmt.Sprintf("failed to decode error response body: %v", decErr)
			logWithRequestID(ctx).Warn(msg)
			return resp, statusErr{code: httpResp.StatusCode, msg: msg}
		}
		b, readErr := io.ReadAll(errBody)
		if readErr != nil {
			recordAPIResponseError(ctx, e.cfg, readErr)
			msg := fmt.Sprintf("failed to read error response body: %v", readErr)
			logWithRequestID(ctx).Warn(msg)
			b = []byte(msg)
		}
		appendAPIResponseChunk(ctx, e.cfg, b)
		logWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, summarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		if errClose := errBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return resp, err
	}
	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return resp, err
	}
	defer func() {
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	appendAPIResponseChunk(ctx, e.cfg, data)
	if stream {
		lines := bytes.Split(data, []byte("\n"))
		for _, line := range lines {
			if detail, ok := parseClaudeStreamUsage(line); ok {
				reporter.publish(ctx, detail)
			}
		}
	} else {
		reporter.publish(ctx, parseClaudeUsage(data))
	}
	if isClaudeOAuthToken(apiKey) && !auth.ToolPrefixDisabled() {
		data = stripClaudeToolPrefixFromResponse(data, claudeToolPrefix)
	}
	var param any
	out := sdktranslator.TranslateNonStream(
		ctx,
		to,
		from,
		req.Model,
		opts.OriginalRequest,
		bodyForTranslation,
		data,
		&param,
	)
	resp = cliproxyexecutor.Response{Payload: []byte(out), Headers: httpResp.Header.Clone()}
	return resp, nil
}

func (e *ClaudeExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}

	// Enforce per-auth RPM limit before proceeding
	if err := checkClaudeRateLimit(auth); err != nil {
		return nil, err
	}

	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := claudeCreds(auth)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.trackFailure(ctx, &err)
	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, true)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, true)
	body, _ = sjson.SetBytes(body, "model", baseModel)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}

	// Always regenerate system[0] (billing header) and system[1] (agent block)
	// to ensure version consistency with our template, regardless of cloaking.
	if !strings.HasPrefix(baseModel, "claude-3-5-haiku") {
		oauthMode := isClaudeOAuthToken(apiKey)
		body = checkSystemInstructionsWithMode(body, false, oauthMode)
	}

	// Apply cloaking (fake user ID, field sanitization, sensitive word obfuscation)
	// based on client type and configuration.
	body = applyCloaking(ctx, e.cfg, auth, body, baseModel, apiKey)

	requestedModel := payloadRequestedModel(opts, req.Model)
	body = applyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel)

	// Disable thinking if tool_choice forces tool use (Anthropic API constraint)
	body = disableThinkingIfToolChoiceForced(body)

	// Auto-inject cache_control if missing (optimization for ClawdBot/clients without caching support)
	if countCacheControls(body) == 0 {
		body = ensureCacheControl(body)
	}

	// Enforce Anthropic's cache_control block limit (max 4 breakpoints per request).
	body = enforceCacheControlLimit(body, 4)

	// Normalize TTL values to prevent ordering violations under prompt-caching-scope-2026-01-05.
	body = normalizeCacheControlTTL(body)

	// Extract betas from body and convert to header
	var extraBetas []string
	extraBetas, body = extractAndRemoveBetas(body)
	bodyForTranslation := body
	bodyForUpstream := body
	if isClaudeOAuthToken(apiKey) && !auth.ToolPrefixDisabled() {
		bodyForUpstream = applyClaudeToolPrefix(body, claudeToolPrefix)
	}

	url := fmt.Sprintf("%s/v1/messages?beta=true", baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyForUpstream))
	if err != nil {
		return nil, err
	}
	applyClaudeHeaders(httpReq, auth, apiKey, true, extraBetas, e.cfg, baseModel)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      bodyForUpstream,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := newClaudeHTTPClient(e.cfg, auth)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		// Decompress error responses — pass the Content-Encoding value (may be empty)
		// and let decodeResponseBody handle both header-declared and magic-byte-detected
		// compression.  This keeps error-path behaviour consistent with the success path.
		errBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			recordAPIResponseError(ctx, e.cfg, decErr)
			msg := fmt.Sprintf("failed to decode error response body: %v", decErr)
			logWithRequestID(ctx).Warn(msg)
			return nil, statusErr{code: httpResp.StatusCode, msg: msg}
		}
		b, readErr := io.ReadAll(errBody)
		if readErr != nil {
			recordAPIResponseError(ctx, e.cfg, readErr)
			msg := fmt.Sprintf("failed to read error response body: %v", readErr)
			logWithRequestID(ctx).Warn(msg)
			b = []byte(msg)
		}
		appendAPIResponseChunk(ctx, e.cfg, b)
		logWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, summarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		if errClose := errBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		err = statusErr{code: httpResp.StatusCode, msg: string(b)}
		return nil, err
	}
	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return nil, err
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := decodedBody.Close(); errClose != nil {
				log.Errorf("response body close error: %v", errClose)
			}
		}()

		// If from == to (Claude → Claude), directly forward the SSE stream without translation
		if from == to {
			scanner := bufio.NewScanner(decodedBody)
			scanner.Buffer(nil, 52_428_800) // 50MB
			for scanner.Scan() {
				line := scanner.Bytes()
				appendAPIResponseChunk(ctx, e.cfg, line)
				if detail, ok := parseClaudeStreamUsage(line); ok {
					reporter.publish(ctx, detail)
				}
				if isClaudeOAuthToken(apiKey) && !auth.ToolPrefixDisabled() {
					line = stripClaudeToolPrefixFromStreamLine(line, claudeToolPrefix)
				}
				// Forward the line as-is to preserve SSE format
				cloned := make([]byte, len(line)+1)
				copy(cloned, line)
				cloned[len(line)] = '\n'
				out <- cliproxyexecutor.StreamChunk{Payload: cloned}
			}
			if errScan := scanner.Err(); errScan != nil {
				recordAPIResponseError(ctx, e.cfg, errScan)
				reporter.publishFailure(ctx)
				out <- cliproxyexecutor.StreamChunk{Err: errScan}
			}
			return
		}

		// For other formats, use translation
		scanner := bufio.NewScanner(decodedBody)
		scanner.Buffer(nil, 52_428_800) // 50MB
		var param any
		for scanner.Scan() {
			line := scanner.Bytes()
			appendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := parseClaudeStreamUsage(line); ok {
				reporter.publish(ctx, detail)
			}
			if isClaudeOAuthToken(apiKey) && !auth.ToolPrefixDisabled() {
				line = stripClaudeToolPrefixFromStreamLine(line, claudeToolPrefix)
			}
			chunks := sdktranslator.TranslateStream(
				ctx,
				to,
				from,
				req.Model,
				opts.OriginalRequest,
				bodyForTranslation,
				bytes.Clone(line),
				&param,
			)
			for i := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: []byte(chunks[i])}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			recordAPIResponseError(ctx, e.cfg, errScan)
			reporter.publishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errScan}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *ClaudeExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := claudeCreds(auth)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")
	// Use streaming translation to preserve function calling, except for claude.
	stream := from != to
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, stream)
	body, _ = sjson.SetBytes(body, "model", baseModel)

	if !strings.HasPrefix(baseModel, "claude-3-5-haiku") {
		body = checkSystemInstructions(body)
	}

	// Keep count_tokens requests compatible with Anthropic cache-control constraints too.
	body = enforceCacheControlLimit(body, 4)
	body = normalizeCacheControlTTL(body)

	// Extract betas from body and convert to header (for count_tokens too)
	var extraBetas []string
	extraBetas, body = extractAndRemoveBetas(body)
	if isClaudeOAuthToken(apiKey) && !auth.ToolPrefixDisabled() {
		body = applyClaudeToolPrefix(body, claudeToolPrefix)
	}

	url := fmt.Sprintf("%s/v1/messages/count_tokens?beta=true", baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	applyClaudeHeaders(httpReq, auth, apiKey, false, extraBetas, e.cfg, baseModel)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := newClaudeHTTPClient(e.cfg, auth)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, resp.StatusCode, resp.Header.Clone())
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Decompress error responses — pass the Content-Encoding value (may be empty)
		// and let decodeResponseBody handle both header-declared and magic-byte-detected
		// compression.  This keeps error-path behaviour consistent with the success path.
		errBody, decErr := decodeResponseBody(resp.Body, resp.Header.Get("Content-Encoding"))
		if decErr != nil {
			recordAPIResponseError(ctx, e.cfg, decErr)
			msg := fmt.Sprintf("failed to decode error response body: %v", decErr)
			logWithRequestID(ctx).Warn(msg)
			return cliproxyexecutor.Response{}, statusErr{code: resp.StatusCode, msg: msg}
		}
		b, readErr := io.ReadAll(errBody)
		if readErr != nil {
			recordAPIResponseError(ctx, e.cfg, readErr)
			msg := fmt.Sprintf("failed to read error response body: %v", readErr)
			logWithRequestID(ctx).Warn(msg)
			b = []byte(msg)
		}
		appendAPIResponseChunk(ctx, e.cfg, b)
		if errClose := errBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return cliproxyexecutor.Response{}, statusErr{code: resp.StatusCode, msg: string(b)}
	}
	decodedBody, err := decodeResponseBody(resp.Body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return cliproxyexecutor.Response{}, err
	}
	defer func() {
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	appendAPIResponseChunk(ctx, e.cfg, data)
	count := gjson.GetBytes(data, "input_tokens").Int()
	out := sdktranslator.TranslateTokenCount(ctx, to, from, count, data)
	return cliproxyexecutor.Response{Payload: []byte(out), Headers: resp.Header.Clone()}, nil
}

func (e *ClaudeExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("claude executor: refresh called")
	if auth == nil {
		return nil, fmt.Errorf("claude executor: auth is nil")
	}
	var refreshToken string
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["refresh_token"].(string); ok && v != "" {
			refreshToken = v
		}
	}
	if refreshToken == "" {
		return auth, nil
	}
	// Use per-account proxy_url for token refresh, matching the priority in
	// proxy_helpers.go: auth.ProxyURL > cfg.ProxyURL > env vars.
	proxyURL := ResolveProxyURL(e.cfg, auth)
	svc := claudeauth.NewClaudeAuth(e.cfg, proxyURL)
	td, err := svc.RefreshTokens(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = td.AccessToken
	if td.RefreshToken != "" {
		auth.Metadata["refresh_token"] = td.RefreshToken
	}
	auth.Metadata["email"] = td.Email
	auth.Metadata["expired"] = td.Expire
	auth.Metadata["type"] = "claude"
	now := time.Now().Format(time.RFC3339)
	auth.Metadata["last_refresh"] = now
	return auth, nil
}

// extractAndRemoveBetas extracts the "betas" array from the body and removes it.
// Returns the extracted betas as a string slice and the modified body.
func extractAndRemoveBetas(body []byte) ([]string, []byte) {
	betasResult := gjson.GetBytes(body, "betas")
	if !betasResult.Exists() {
		return nil, body
	}
	var betas []string
	if betasResult.IsArray() {
		for _, item := range betasResult.Array() {
			if s := strings.TrimSpace(item.String()); s != "" {
				betas = append(betas, s)
			}
		}
	} else if s := strings.TrimSpace(betasResult.String()); s != "" {
		betas = append(betas, s)
	}
	body, _ = sjson.DeleteBytes(body, "betas")
	return betas, body
}

// disableThinkingIfToolChoiceForced checks if tool_choice forces tool use and disables thinking.
// Anthropic API does not allow thinking when tool_choice is set to "any" or a specific tool.
// See: https://docs.anthropic.com/en/docs/build-with-claude/extended-thinking#important-considerations
func disableThinkingIfToolChoiceForced(body []byte) []byte {
	toolChoiceType := gjson.GetBytes(body, "tool_choice.type").String()
	// "auto" is allowed with thinking, but "any" or "tool" (specific tool) are not
	if toolChoiceType == "any" || toolChoiceType == "tool" {
		// Remove thinking configuration entirely to avoid API error
		body, _ = sjson.DeleteBytes(body, "thinking")
		// Adaptive thinking may also set output_config.effort; remove it to avoid
		// leaking thinking controls when tool_choice forces tool use.
		body, _ = sjson.DeleteBytes(body, "output_config.effort")
		if oc := gjson.GetBytes(body, "output_config"); oc.Exists() && oc.IsObject() && len(oc.Map()) == 0 {
			body, _ = sjson.DeleteBytes(body, "output_config")
		}
	}
	return body
}

type compositeReadCloser struct {
	io.Reader
	closers []func() error
}

func (c *compositeReadCloser) Close() error {
	var firstErr error
	for i := range c.closers {
		if c.closers[i] == nil {
			continue
		}
		if err := c.closers[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// peekableBody wraps a bufio.Reader around the original ReadCloser so that
// magic bytes can be inspected without consuming them from the stream.
type peekableBody struct {
	*bufio.Reader
	closer io.Closer
}

func (p *peekableBody) Close() error {
	return p.closer.Close()
}

func decodeResponseBody(body io.ReadCloser, contentEncoding string) (io.ReadCloser, error) {
	if body == nil {
		return nil, fmt.Errorf("response body is nil")
	}
	if contentEncoding == "" {
		// No Content-Encoding header.  Attempt best-effort magic-byte detection to
		// handle misbehaving upstreams that compress without setting the header.
		// Only gzip (1f 8b) and zstd (28 b5 2f fd) have reliable magic sequences;
		// br and deflate have none and are left as-is.
		// The bufio wrapper preserves unread bytes so callers always see the full
		// stream regardless of whether decompression was applied.
		pb := &peekableBody{Reader: bufio.NewReader(body), closer: body}
		magic, peekErr := pb.Peek(4)
		if peekErr == nil || (peekErr == io.EOF && len(magic) >= 2) {
			switch {
			case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
				gzipReader, gzErr := gzip.NewReader(pb)
				if gzErr != nil {
					_ = pb.Close()
					return nil, fmt.Errorf("magic-byte gzip: failed to create reader: %w", gzErr)
				}
				return &compositeReadCloser{
					Reader: gzipReader,
					closers: []func() error{
						gzipReader.Close,
						pb.Close,
					},
				}, nil
			case len(magic) >= 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
				decoder, zdErr := zstd.NewReader(pb)
				if zdErr != nil {
					_ = pb.Close()
					return nil, fmt.Errorf("magic-byte zstd: failed to create reader: %w", zdErr)
				}
				return &compositeReadCloser{
					Reader: decoder,
					closers: []func() error{
						func() error { decoder.Close(); return nil },
						pb.Close,
					},
				}, nil
			}
		}
		return pb, nil
	}
	encodings := strings.Split(contentEncoding, ",")
	for _, raw := range encodings {
		encoding := strings.TrimSpace(strings.ToLower(raw))
		switch encoding {
		case "", "identity":
			continue
		case "gzip":
			gzipReader, err := gzip.NewReader(body)
			if err != nil {
				_ = body.Close()
				return nil, fmt.Errorf("failed to create gzip reader: %w", err)
			}
			return &compositeReadCloser{
				Reader: gzipReader,
				closers: []func() error{
					gzipReader.Close,
					func() error { return body.Close() },
				},
			}, nil
		case "deflate":
			deflateReader := flate.NewReader(body)
			return &compositeReadCloser{
				Reader: deflateReader,
				closers: []func() error{
					deflateReader.Close,
					func() error { return body.Close() },
				},
			}, nil
		case "br":
			return &compositeReadCloser{
				Reader: brotli.NewReader(body),
				closers: []func() error{
					func() error { return body.Close() },
				},
			}, nil
		case "zstd":
			decoder, err := zstd.NewReader(body)
			if err != nil {
				_ = body.Close()
				return nil, fmt.Errorf("failed to create zstd reader: %w", err)
			}
			return &compositeReadCloser{
				Reader: decoder,
				closers: []func() error{
					func() error { decoder.Close(); return nil },
					func() error { return body.Close() },
				},
			}, nil
		default:
			continue
		}
	}
	return body, nil
}

// mapStainlessOS maps runtime.GOOS to Stainless SDK OS names.
func mapStainlessOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "MacOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "freebsd":
		return "FreeBSD"
	default:
		return "Other::" + runtime.GOOS
	}
}

// mapStainlessArch maps runtime.GOARCH to Stainless SDK architecture names.
func mapStainlessArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "386":
		return "x86"
	default:
		return "other::" + runtime.GOARCH
	}
}

// modelSupports1MContext returns true if the model supports the context-1m beta.
// Currently only claude-opus-4-6 variants support 1M context.
func modelSupports1MContext(model string) bool {
	return strings.Contains(model, "opus-4-6") || strings.Contains(model, "opus-4-6")
}

func applyClaudeHeaders(r *http.Request, auth *cliproxyauth.Auth, apiKey string, _ bool, extraBetas []string, cfg *config.Config, model string) {
	hdrDefault := func(cfgVal, fallback string) string {
		if cfgVal != "" {
			return cfgVal
		}
		return fallback
	}

	var hd config.ClaudeHeaderDefaults
	if cfg != nil {
		hd = cfg.ClaudeHeaderDefaults
	}

	useAPIKey := auth != nil && auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != ""
	isAnthropicBase := r.URL != nil && strings.EqualFold(r.URL.Scheme, "https") && strings.EqualFold(r.URL.Host, "api.anthropic.com")
	if isAnthropicBase && useAPIKey {
		r.Header.Del("Authorization")
		r.Header.Set("x-api-key", apiKey)
	} else {
		r.Header.Set("Authorization", "Bearer "+apiKey)
	}
	r.Header.Set("Content-Type", "application/json")

	var ginHeaders http.Header
	if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header
	}

	baseBetas := "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,effort-2025-11-24"
	if modelSupports1MContext(model) {
		baseBetas = "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,effort-2025-11-24"
	}

	hasClaude1MHeader := false
	if ginHeaders != nil {
		if _, ok := ginHeaders[textproto.CanonicalMIMEHeaderKey("X-CPA-CLAUDE-1M")]; ok {
			hasClaude1MHeader = true
		}
	}

	// Merge extra betas from request body and request flags.
	if len(extraBetas) > 0 || hasClaude1MHeader {
		existingSet := make(map[string]bool)
		for _, b := range strings.Split(baseBetas, ",") {
			betaName := strings.TrimSpace(b)
			if betaName != "" {
				existingSet[betaName] = true
			}
		}
		for _, beta := range extraBetas {
			beta = strings.TrimSpace(beta)
			if beta != "" && !existingSet[beta] {
				baseBetas += "," + beta
				existingSet[beta] = true
			}
		}
		if hasClaude1MHeader && !existingSet["context-1m-2025-08-07"] {
			baseBetas += ",context-1m-2025-08-07"
		}
	}
	r.Header.Set("Anthropic-Beta", baseBetas)

	// Always use CLIProxyAPI's own template values for all identity-sensitive headers.
	// Client-forwarded headers (e.g. from NewAPI pass_headers) are intentionally ignored
	// to prevent version mismatches or non-standard values from leaking as fingerprints.
	r.Header.Set("Anthropic-Version", "2023-06-01")
	r.Header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
	r.Header.Set("X-App", "cli")
	// Values below match Claude Code 2.1.79 / @anthropic-ai/sdk 0.74.0 (updated 2026-03-19).
	r.Header.Set("X-Stainless-Retry-Count", "0")
	r.Header.Set("X-Stainless-Runtime-Version", hdrDefault(hd.RuntimeVersion, "v24.3.0"))
	r.Header.Set("X-Stainless-Package-Version", hdrDefault(hd.PackageVersion, "0.74.0"))
	r.Header.Set("X-Stainless-Runtime", "node")
	r.Header.Set("X-Stainless-Lang", "js")
	r.Header.Set("X-Stainless-Arch", mapStainlessArch())
	r.Header.Set("X-Stainless-Os", mapStainlessOS())
	r.Header.Set("X-Stainless-Timeout", hdrDefault(hd.Timeout, "600"))
	r.Header.Set("User-Agent", hdrDefault(hd.UserAgent, "claude-cli/2.1.79 (external, cli)"))
	r.Header.Set("Connection", "keep-alive")
	// Real Claude Code CLI 2.1.79 sends the same Accept and Accept-Encoding
	// for both streaming and non-streaming requests.  The stream mode is
	// controlled by the "stream" field in the JSON body, not by the Accept header.
	// The response body is decompressed by decodeResponseBody before the SSE
	// line scanner reads it, so compressed responses are handled correctly.
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	// Keep OS/Arch mapping dynamic (not configurable).
	// They intentionally continue to derive from runtime.GOOS/runtime.GOARCH.
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs)
}

func claudeCreds(a *cliproxyauth.Auth) (apiKey, baseURL string) {
	if a == nil {
		return "", ""
	}
	if a.Attributes != nil {
		apiKey = a.Attributes["api_key"]
		baseURL = a.Attributes["base_url"]
	}
	if apiKey == "" && a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok {
			apiKey = v
		}
	}
	return
}

func checkSystemInstructions(payload []byte) []byte {
	return checkSystemInstructionsWithMode(payload, false, false)
}

func isClaudeOAuthToken(apiKey string) bool {
	return strings.Contains(apiKey, "sk-ant-oat")
}

func applyClaudeToolPrefix(body []byte, prefix string) []byte {
	if prefix == "" {
		return body
	}

	// Collect built-in tool names (those with a non-empty "type" field) so we can
	// skip them consistently in both tools and message history.
	builtinTools := map[string]bool{}
	for _, name := range []string{"web_search", "code_execution", "text_editor", "computer"} {
		builtinTools[name] = true
	}

	if tools := gjson.GetBytes(body, "tools"); tools.Exists() && tools.IsArray() {
		tools.ForEach(func(index, tool gjson.Result) bool {
			// Skip built-in tools (web_search, code_execution, etc.) which have
			// a "type" field and require their name to remain unchanged.
			if tool.Get("type").Exists() && tool.Get("type").String() != "" {
				if n := tool.Get("name").String(); n != "" {
					builtinTools[n] = true
				}
				return true
			}
			name := tool.Get("name").String()
			if name == "" || strings.HasPrefix(name, prefix) {
				return true
			}
			path := fmt.Sprintf("tools.%d.name", index.Int())
			body, _ = sjson.SetBytes(body, path, prefix+name)
			return true
		})
	}

	if gjson.GetBytes(body, "tool_choice.type").String() == "tool" {
		name := gjson.GetBytes(body, "tool_choice.name").String()
		if name != "" && !strings.HasPrefix(name, prefix) && !builtinTools[name] {
			body, _ = sjson.SetBytes(body, "tool_choice.name", prefix+name)
		}
	}

	if messages := gjson.GetBytes(body, "messages"); messages.Exists() && messages.IsArray() {
		messages.ForEach(func(msgIndex, msg gjson.Result) bool {
			content := msg.Get("content")
			if !content.Exists() || !content.IsArray() {
				return true
			}
			content.ForEach(func(contentIndex, part gjson.Result) bool {
				partType := part.Get("type").String()
				switch partType {
				case "tool_use":
					name := part.Get("name").String()
					if name == "" || strings.HasPrefix(name, prefix) || builtinTools[name] {
						return true
					}
					path := fmt.Sprintf("messages.%d.content.%d.name", msgIndex.Int(), contentIndex.Int())
					body, _ = sjson.SetBytes(body, path, prefix+name)
				case "tool_reference":
					toolName := part.Get("tool_name").String()
					if toolName == "" || strings.HasPrefix(toolName, prefix) || builtinTools[toolName] {
						return true
					}
					path := fmt.Sprintf("messages.%d.content.%d.tool_name", msgIndex.Int(), contentIndex.Int())
					body, _ = sjson.SetBytes(body, path, prefix+toolName)
				case "tool_result":
					// Handle nested tool_reference blocks inside tool_result.content[]
					nestedContent := part.Get("content")
					if nestedContent.Exists() && nestedContent.IsArray() {
						nestedContent.ForEach(func(nestedIndex, nestedPart gjson.Result) bool {
							if nestedPart.Get("type").String() == "tool_reference" {
								nestedToolName := nestedPart.Get("tool_name").String()
								if nestedToolName != "" && !strings.HasPrefix(nestedToolName, prefix) && !builtinTools[nestedToolName] {
									nestedPath := fmt.Sprintf("messages.%d.content.%d.content.%d.tool_name", msgIndex.Int(), contentIndex.Int(), nestedIndex.Int())
									body, _ = sjson.SetBytes(body, nestedPath, prefix+nestedToolName)
								}
							}
							return true
						})
					}
				}
				return true
			})
			return true
		})
	}

	return body
}

func stripClaudeToolPrefixFromResponse(body []byte, prefix string) []byte {
	if prefix == "" {
		return body
	}
	content := gjson.GetBytes(body, "content")
	if !content.Exists() || !content.IsArray() {
		return body
	}
	content.ForEach(func(index, part gjson.Result) bool {
		partType := part.Get("type").String()
		switch partType {
		case "tool_use":
			name := part.Get("name").String()
			if !strings.HasPrefix(name, prefix) {
				return true
			}
			path := fmt.Sprintf("content.%d.name", index.Int())
			body, _ = sjson.SetBytes(body, path, strings.TrimPrefix(name, prefix))
		case "tool_reference":
			toolName := part.Get("tool_name").String()
			if !strings.HasPrefix(toolName, prefix) {
				return true
			}
			path := fmt.Sprintf("content.%d.tool_name", index.Int())
			body, _ = sjson.SetBytes(body, path, strings.TrimPrefix(toolName, prefix))
		case "tool_result":
			// Handle nested tool_reference blocks inside tool_result.content[]
			nestedContent := part.Get("content")
			if nestedContent.Exists() && nestedContent.IsArray() {
				nestedContent.ForEach(func(nestedIndex, nestedPart gjson.Result) bool {
					if nestedPart.Get("type").String() == "tool_reference" {
						nestedToolName := nestedPart.Get("tool_name").String()
						if strings.HasPrefix(nestedToolName, prefix) {
							nestedPath := fmt.Sprintf("content.%d.content.%d.tool_name", index.Int(), nestedIndex.Int())
							body, _ = sjson.SetBytes(body, nestedPath, strings.TrimPrefix(nestedToolName, prefix))
						}
					}
					return true
				})
			}
		}
		return true
	})
	return body
}

func stripClaudeToolPrefixFromStreamLine(line []byte, prefix string) []byte {
	if prefix == "" {
		return line
	}
	payload := jsonPayload(line)
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return line
	}
	contentBlock := gjson.GetBytes(payload, "content_block")
	if !contentBlock.Exists() {
		return line
	}

	blockType := contentBlock.Get("type").String()
	var updated []byte
	var err error

	switch blockType {
	case "tool_use":
		name := contentBlock.Get("name").String()
		if !strings.HasPrefix(name, prefix) {
			return line
		}
		updated, err = sjson.SetBytes(payload, "content_block.name", strings.TrimPrefix(name, prefix))
		if err != nil {
			return line
		}
	case "tool_reference":
		toolName := contentBlock.Get("tool_name").String()
		if !strings.HasPrefix(toolName, prefix) {
			return line
		}
		updated, err = sjson.SetBytes(payload, "content_block.tool_name", strings.TrimPrefix(toolName, prefix))
		if err != nil {
			return line
		}
	default:
		return line
	}

	trimmed := bytes.TrimSpace(line)
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		return append([]byte("data: "), updated...)
	}
	return updated
}

// getClientUserAgent extracts the client User-Agent from the gin context.
func getClientUserAgent(ctx context.Context) string {
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		return ginCtx.GetHeader("User-Agent")
	}
	return ""
}

// getCloakConfigFromAuth extracts cloak configuration from auth attributes.
// Returns (cloakMode, strictMode, sensitiveWords, cacheUserID).
func getCloakConfigFromAuth(auth *cliproxyauth.Auth) (string, bool, []string, bool) {
	if auth == nil || auth.Attributes == nil {
		return "auto", false, nil, true
	}

	cloakMode := auth.Attributes["cloak_mode"]
	if cloakMode == "" {
		cloakMode = "auto"
	}

	strictMode := strings.ToLower(auth.Attributes["cloak_strict_mode"]) == "true"

	var sensitiveWords []string
	if wordsStr := auth.Attributes["cloak_sensitive_words"]; wordsStr != "" {
		sensitiveWords = strings.Split(wordsStr, ",")
		for i := range sensitiveWords {
			sensitiveWords[i] = strings.TrimSpace(sensitiveWords[i])
		}
	}

	// Default to true: real Claude Code CLI reuses the same user_id across requests.
	// Only disable if explicitly set to "false".
	cacheUserID := true
	if v, ok := auth.Attributes["cloak_cache_user_id"]; ok && strings.EqualFold(strings.TrimSpace(v), "false") {
		cacheUserID = false
	}

	return cloakMode, strictMode, sensitiveWords, cacheUserID
}

// resolveClaudeKeyCloakConfig finds the matching ClaudeKey config and returns its CloakConfig.
func resolveClaudeKeyCloakConfig(cfg *config.Config, auth *cliproxyauth.Auth) *config.CloakConfig {
	if cfg == nil || auth == nil {
		return nil
	}

	apiKey, baseURL := claudeCreds(auth)
	if apiKey == "" {
		return nil
	}

	for i := range cfg.ClaudeKey {
		entry := &cfg.ClaudeKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)

		// Match by API key
		if strings.EqualFold(cfgKey, apiKey) {
			// If baseURL is specified, also check it
			if baseURL != "" && cfgBase != "" && !strings.EqualFold(cfgBase, baseURL) {
				continue
			}
			return entry.Cloak
		}
	}

	return nil
}

// injectFakeUserID generates and injects a fake user ID into the request metadata.
// When useCache is false, a new user ID is generated for every call.
func injectFakeUserID(payload []byte, apiKey string, useCache bool) []byte {
	generateID := func() string {
		if useCache {
			return cachedUserID(apiKey)
		}
		return generateFakeUserID()
	}

	metadata := gjson.GetBytes(payload, "metadata")
	if !metadata.Exists() {
		payload, _ = sjson.SetBytes(payload, "metadata.user_id", generateID())
		return payload
	}

	existingUserID := gjson.GetBytes(payload, "metadata.user_id").String()
	if existingUserID == "" || !isValidUserID(existingUserID) {
		payload, _ = sjson.SetBytes(payload, "metadata.user_id", generateID())
	}
	return payload
}

// generateBillingHeader creates the x-anthropic-billing-header text block that
// real Claude Code prepends to every system prompt array.
// Format: x-anthropic-billing-header: cc_version=<ver>.<build>; cc_entrypoint=cli; cch=<hash>;
//
// cc_version build hash (3-char) is derived from the first user message:
//  1. Extract text of the first "user" role message (first text block if array)
//  2. Take runes at positions 4, 7, 20 (default "0" if out of range)
//  3. SHA-256(salt + chars + version), take first 3 hex chars
//
// cch is a 5-char hex hash derived from session-specific data (updated in v2.1.79).
func generateBillingHeader(payload []byte) string {
	const salt = "59cf53e54c78"
	const version = "2.1.79"

	// Extract text of the first user message from the messages array.
	var firstUserText string
	messages := gjson.GetBytes(payload, "messages")
	if messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			if msg.Get("role").String() != "user" {
				return true
			}
			content := msg.Get("content")
			if content.Type == gjson.String {
				firstUserText = content.String()
			} else if content.IsArray() {
				content.ForEach(func(_, block gjson.Result) bool {
					if block.Get("type").String() == "text" {
						firstUserText = block.Get("text").String()
						return false
					}
					return true
				})
			}
			return false // stop at first user message
		})
	}

	// Take runes at positions 4, 7, 20 (default "0" if missing).
	runes := []rune(firstUserText)
	charAt := func(i int) string {
		if i < len(runes) {
			return string(runes[i])
		}
		return "0"
	}
	chars := charAt(4) + charAt(7) + charAt(20)

	h := sha256.Sum256([]byte(salt + chars + version))
	buildHash := hex.EncodeToString(h[:])[:3]

	cch := generateCCH()
	return fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; cch=%s;", version, buildHash, cch)
}

// checkSystemInstructionsWithMode injects Claude Code-style system blocks:
//
//	system[0]: billing header (no cache_control)
//	system[1]: agent identifier (cache_control: ephemeral, +ttl if oauthMode)
//	system[2..]: user system messages (cache_control added when missing)
//
// When oauthMode is true, cache_control blocks include ttl:"1h" to match the
// real Claude Code CLI behaviour under OAuth + active quota (fQ/aFK logic).
func checkSystemInstructionsWithMode(payload []byte, strictMode, oauthMode bool) []byte {
	system := gjson.GetBytes(payload, "system")

	billingText := generateBillingHeader(payload)
	billingBlock := fmt.Sprintf(`{"type":"text","text":"%s"}`, billingText)

	// Agent block matches real Claude Code v2.1.79 interactive mode system[1].
	// In OAuth mode the real CLI adds ttl:"1h" via fQ when quota conditions are met.
	agentBlock := `{"type":"text","text":"You are a Claude agent, built on Anthropic\u0027s Claude Agent SDK.","cache_control":{"type":"ephemeral"}}`
	if oauthMode {
		agentBlock = `{"type":"text","text":"You are a Claude agent, built on Anthropic\u0027s Claude Agent SDK.","cache_control":{"type":"ephemeral","ttl":"1h"}}`
	}

	if strictMode {
		// Strict mode: billing header + agent identifier only
		result := "[" + billingBlock + "," + agentBlock + "]"
		payload, _ = sjson.SetRawBytes(payload, "system", []byte(result))
		return payload
	}

	// Non-strict mode: billing header + agent identifier + user system messages
	// Always regenerate to ensure version consistency with our template (2.1.79).
	// If the client already injected a billing header (e.g. real Claude Code CLI
	// with a different version), strip it to prevent version mismatch fingerprints.
	result := "[" + billingBlock + "," + agentBlock
	if system.IsArray() {
		system.ForEach(func(_, part gjson.Result) bool {
			if part.Get("type").String() == "text" {
				text := part.Get("text").String()
				// Skip existing billing header or agent block from upstream client
				// to avoid duplication when regenerating.
				if strings.HasPrefix(text, "x-anthropic-billing-header:") {
					return true
				}
				if strings.HasPrefix(text, "You are a Claude agent") {
					return true
				}
				partJSON := part.Raw
				if !part.Get("cache_control").Exists() {
					partJSON, _ = sjson.Set(partJSON, "cache_control.type", "ephemeral")
					if oauthMode {
						partJSON, _ = sjson.Set(partJSON, "cache_control.ttl", "1h")
					}
				}
				result += "," + partJSON
			}
			return true
		})
	} else if system.Type == gjson.String && system.String() != "" {
		partJSON := `{"type":"text","cache_control":{"type":"ephemeral"}}`
		if oauthMode {
			partJSON = `{"type":"text","cache_control":{"type":"ephemeral","ttl":"1h"}}`
		}
		partJSON, _ = sjson.Set(partJSON, "text", system.String())
		result += "," + partJSON
	}
	result += "]"

	payload, _ = sjson.SetRawBytes(payload, "system", []byte(result))
	return payload
}

// claudeAPIAllowedFields is the whitelist of top-level fields accepted by the Claude
// Messages API. Any field not in this set is non-standard and will be stripped during
// cloaking to prevent upstream proxies (e.g. NewAPI) from injecting identifiable fields.
var claudeAPIAllowedFields = map[string]bool{
	"model":          true,
	"messages":       true,
	"system":         true,
	"max_tokens":     true,
	"metadata":       true,
	"stop_sequences": true,
	"stream":         true,
	"temperature":    true,
	"top_p":          true,
	"top_k":          true,
	"tools":          true,
	"tool_choice":    true,
	"thinking":       true,
	"output_config":  true,
	// Internal fields used by CLIProxyAPI pipeline (added after translation).
	"betas": true,
}

// stripNonStandardFields removes any top-level fields from the payload that are not
// part of the Claude Messages API specification. This prevents upstream proxies from
// injecting non-standard fields (e.g. custom tracking, request IDs) that could serve
// as fingerprints distinguishing proxied requests from real Claude Code CLI requests.
// Additionally, metadata is sanitized to only keep user_id.
func stripNonStandardFields(payload []byte) []byte {
	root := gjson.ParseBytes(payload)
	if !root.IsObject() {
		return payload
	}
	var toDelete []string
	root.ForEach(func(key, _ gjson.Result) bool {
		if !claudeAPIAllowedFields[key.String()] {
			toDelete = append(toDelete, key.String())
		}
		return true
	})
	result := payload
	for _, key := range toDelete {
		result, _ = sjson.DeleteBytes(result, key)
	}
	// Sanitize metadata: only keep user_id, remove any extra fields injected by upstream.
	metadata := gjson.GetBytes(result, "metadata")
	if metadata.Exists() && metadata.IsObject() {
		userID := gjson.GetBytes(result, "metadata.user_id").String()
		result, _ = sjson.DeleteBytes(result, "metadata")
		if userID != "" {
			result, _ = sjson.SetBytes(result, "metadata.user_id", userID)
		}
	}
	return result
}

// normalizeMaxTokensForCloaking ensures max_tokens matches the model's default value
// when cloaking is active. Real Claude Code CLI always sends model-appropriate max_tokens
// (e.g. 128000 for Opus 4.6, 64000 for Sonnet 4.6). A fixed value like 8192 across all
// models is a detectable fingerprint. This function replaces missing or non-matching
// max_tokens with the model's max_completion_tokens from the registry.
func normalizeMaxTokensForCloaking(payload []byte, model string) []byte {
	modelInfo := registry.LookupModelInfo(model, "claude")
	if modelInfo == nil || modelInfo.MaxCompletionTokens <= 0 {
		return payload
	}
	expected := modelInfo.MaxCompletionTokens
	current := gjson.GetBytes(payload, "max_tokens")
	if current.Exists() && int(current.Int()) == expected {
		return payload
	}
	result, err := sjson.SetBytes(payload, "max_tokens", expected)
	if err != nil {
		return payload
	}
	return result
}

// applyCloaking applies cloaking transformations to the payload based on config and client.
// Cloaking includes: system prompt injection, fake user ID, and sensitive word obfuscation.
func applyCloaking(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, payload []byte, model string, apiKey string) []byte {
	clientUserAgent := getClientUserAgent(ctx)

	// Get cloak config from ClaudeKey configuration
	cloakCfg := resolveClaudeKeyCloakConfig(cfg, auth)

	// Determine cloak settings
	var cloakMode string
	var strictMode bool
	var sensitiveWords []string
	cacheUserID := true

	if cloakCfg != nil {
		cloakMode = cloakCfg.Mode
		strictMode = cloakCfg.StrictMode
		sensitiveWords = cloakCfg.SensitiveWords
		if cloakCfg.CacheUserID != nil {
			cacheUserID = *cloakCfg.CacheUserID
		}
	}

	// Fallback to auth attributes if no config found
	if cloakMode == "" {
		attrMode, attrStrict, attrWords, attrCache := getCloakConfigFromAuth(auth)
		cloakMode = attrMode
		if !strictMode {
			strictMode = attrStrict
		}
		if len(sensitiveWords) == 0 {
			sensitiveWords = attrWords
		}
		if cloakCfg == nil || cloakCfg.CacheUserID == nil {
			cacheUserID = attrCache
		}
	} else if cloakCfg == nil || cloakCfg.CacheUserID == nil {
		_, _, _, attrCache := getCloakConfigFromAuth(auth)
		cacheUserID = attrCache
	}

	// Determine if cloaking should be applied
	if !shouldCloak(cloakMode, clientUserAgent) {
		return payload
	}

	// Strip non-standard top-level fields and sanitize metadata to prevent
	// upstream proxies from injecting identifiable fields into the request body.
	payload = stripNonStandardFields(payload)

	// Normalize max_tokens to match the model's default when cloaking is active.
	// Non-Claude-Code clients (e.g. NewAPI, OpenAI SDKs) may send a fixed default
	// (like 8192) for all models, which is a detectable fingerprint since real
	// Claude Code CLI sends model-appropriate values (e.g. 128000 for Opus 4.6).
	payload = normalizeMaxTokensForCloaking(payload, model)

	// Note: system[0]/[1] injection is now handled in Execute/ExecuteStream
	// before applyCloaking, so it applies to all requests regardless of cloaking.
	// In strict mode, strip user system messages and keep only billing + agent blocks.
	if strictMode && !strings.HasPrefix(model, "claude-3-5-haiku") {
		payload = checkSystemInstructionsWithMode(payload, true, true)
	}

	// Inject fake user ID
	payload = injectFakeUserID(payload, apiKey, cacheUserID)

	// Apply sensitive word obfuscation
	if len(sensitiveWords) > 0 {
		matcher := buildSensitiveWordMatcher(sensitiveWords)
		payload = obfuscateSensitiveWords(payload, matcher)
	}

	return payload
}

// ensureCacheControl injects cache_control breakpoints into the payload for optimal prompt caching.
// According to Anthropic's documentation, cache prefixes are created in order: tools -> system -> messages.
// This function adds cache_control to:
// 1. The LAST tool in the tools array (caches all tool definitions)
// 2. The LAST element in the system array (caches system prompt)
// 3. The SECOND-TO-LAST user turn (caches conversation history for multi-turn)
//
// Up to 4 cache breakpoints are allowed per request. Tools, System, and Messages are INDEPENDENT breakpoints.
// This enables up to 90% cost reduction on cached tokens (cache read = 0.1x base price).
// See: https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
func ensureCacheControl(payload []byte) []byte {
	// 1. Inject cache_control into the LAST tool (caches all tool definitions)
	// Tools are cached first in the hierarchy, so this is the most important breakpoint.
	payload = injectToolsCacheControl(payload)

	// 2. Inject cache_control into the LAST system prompt element
	// System is the second level in the cache hierarchy.
	payload = injectSystemCacheControl(payload)

	// 3. Inject cache_control into messages for multi-turn conversation caching
	// This caches the conversation history up to the second-to-last user turn.
	payload = injectMessagesCacheControl(payload)

	return payload
}

func countCacheControls(payload []byte) int {
	count := 0

	// Check system
	system := gjson.GetBytes(payload, "system")
	if system.IsArray() {
		system.ForEach(func(_, item gjson.Result) bool {
			if item.Get("cache_control").Exists() {
				count++
			}
			return true
		})
	}

	// Check tools
	tools := gjson.GetBytes(payload, "tools")
	if tools.IsArray() {
		tools.ForEach(func(_, item gjson.Result) bool {
			if item.Get("cache_control").Exists() {
				count++
			}
			return true
		})
	}

	// Check messages
	messages := gjson.GetBytes(payload, "messages")
	if messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			content := msg.Get("content")
			if content.IsArray() {
				content.ForEach(func(_, item gjson.Result) bool {
					if item.Get("cache_control").Exists() {
						count++
					}
					return true
				})
			}
			return true
		})
	}

	return count
}

func parsePayloadObject(payload []byte) (map[string]any, bool) {
	if len(payload) == 0 {
		return nil, false
	}
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil, false
	}
	return root, true
}

func marshalPayloadObject(original []byte, root map[string]any) []byte {
	if root == nil {
		return original
	}
	out, err := json.Marshal(root)
	if err != nil {
		return original
	}
	return out
}

func asObject(v any) (map[string]any, bool) {
	obj, ok := v.(map[string]any)
	return obj, ok
}

func asArray(v any) ([]any, bool) {
	arr, ok := v.([]any)
	return arr, ok
}

func countCacheControlsMap(root map[string]any) int {
	count := 0

	if system, ok := asArray(root["system"]); ok {
		for _, item := range system {
			if obj, ok := asObject(item); ok {
				if _, exists := obj["cache_control"]; exists {
					count++
				}
			}
		}
	}

	if tools, ok := asArray(root["tools"]); ok {
		for _, item := range tools {
			if obj, ok := asObject(item); ok {
				if _, exists := obj["cache_control"]; exists {
					count++
				}
			}
		}
	}

	if messages, ok := asArray(root["messages"]); ok {
		for _, msg := range messages {
			msgObj, ok := asObject(msg)
			if !ok {
				continue
			}
			content, ok := asArray(msgObj["content"])
			if !ok {
				continue
			}
			for _, item := range content {
				if obj, ok := asObject(item); ok {
					if _, exists := obj["cache_control"]; exists {
						count++
					}
				}
			}
		}
	}

	return count
}

func normalizeTTLForBlock(obj map[string]any, seen5m *bool) bool {
	ccRaw, exists := obj["cache_control"]
	if !exists {
		return false
	}
	cc, ok := asObject(ccRaw)
	if !ok {
		*seen5m = true
		return false
	}
	ttlRaw, ttlExists := cc["ttl"]
	ttl, ttlIsString := ttlRaw.(string)
	if !ttlExists || !ttlIsString || ttl != "1h" {
		*seen5m = true
		return false
	}
	if *seen5m {
		delete(cc, "ttl")
		return true
	}
	return false
}

func findLastCacheControlIndex(arr []any) int {
	last := -1
	for idx, item := range arr {
		obj, ok := asObject(item)
		if !ok {
			continue
		}
		if _, exists := obj["cache_control"]; exists {
			last = idx
		}
	}
	return last
}

func stripCacheControlExceptIndex(arr []any, preserveIdx int, excess *int) {
	for idx, item := range arr {
		if *excess <= 0 {
			return
		}
		obj, ok := asObject(item)
		if !ok {
			continue
		}
		if _, exists := obj["cache_control"]; exists && idx != preserveIdx {
			delete(obj, "cache_control")
			*excess--
		}
	}
}

func stripAllCacheControl(arr []any, excess *int) {
	for _, item := range arr {
		if *excess <= 0 {
			return
		}
		obj, ok := asObject(item)
		if !ok {
			continue
		}
		if _, exists := obj["cache_control"]; exists {
			delete(obj, "cache_control")
			*excess--
		}
	}
}

func stripMessageCacheControl(messages []any, excess *int) {
	for _, msg := range messages {
		if *excess <= 0 {
			return
		}
		msgObj, ok := asObject(msg)
		if !ok {
			continue
		}
		content, ok := asArray(msgObj["content"])
		if !ok {
			continue
		}
		for _, item := range content {
			if *excess <= 0 {
				return
			}
			obj, ok := asObject(item)
			if !ok {
				continue
			}
			if _, exists := obj["cache_control"]; exists {
				delete(obj, "cache_control")
				*excess--
			}
		}
	}
}

// normalizeCacheControlTTL ensures cache_control TTL values don't violate the
// prompt-caching-scope-2026-01-05 ordering constraint: a 1h-TTL block must not
// appear after a 5m-TTL block anywhere in the evaluation order.
//
// Anthropic evaluates blocks in order: tools → system (index 0..N) → messages.
// Within each section, blocks are evaluated in array order. A 5m (default) block
// followed by a 1h block at ANY later position is an error — including within
// the same section (e.g. system[1]=5m then system[3]=1h).
//
// Strategy: walk all cache_control blocks in evaluation order. Once a 5m block
// is seen, strip ttl from ALL subsequent 1h blocks (downgrading them to 5m).
func normalizeCacheControlTTL(payload []byte) []byte {
	root, ok := parsePayloadObject(payload)
	if !ok {
		return payload
	}

	seen5m := false
	modified := false

	if tools, ok := asArray(root["tools"]); ok {
		for _, tool := range tools {
			if obj, ok := asObject(tool); ok {
				if normalizeTTLForBlock(obj, &seen5m) {
					modified = true
				}
			}
		}
	}

	if system, ok := asArray(root["system"]); ok {
		for _, item := range system {
			if obj, ok := asObject(item); ok {
				if normalizeTTLForBlock(obj, &seen5m) {
					modified = true
				}
			}
		}
	}

	if messages, ok := asArray(root["messages"]); ok {
		for _, msg := range messages {
			msgObj, ok := asObject(msg)
			if !ok {
				continue
			}
			content, ok := asArray(msgObj["content"])
			if !ok {
				continue
			}
			for _, item := range content {
				if obj, ok := asObject(item); ok {
					if normalizeTTLForBlock(obj, &seen5m) {
						modified = true
					}
				}
			}
		}
	}

	if !modified {
		return payload
	}
	return marshalPayloadObject(payload, root)
}

// enforceCacheControlLimit removes excess cache_control blocks from a payload
// so the total does not exceed the Anthropic API limit (currently 4).
//
// Anthropic evaluates cache breakpoints in order: tools → system → messages.
// The most valuable breakpoints are:
//  1. Last tool         — caches ALL tool definitions
//  2. Last system block — caches ALL system content
//  3. Recent messages   — cache conversation context
//
// Removal priority (strip lowest-value first):
//
//	Phase 1: system blocks earliest-first, preserving the last one.
//	Phase 2: tool blocks earliest-first, preserving the last one.
//	Phase 3: message content blocks earliest-first.
//	Phase 4: remaining system blocks (last system).
//	Phase 5: remaining tool blocks (last tool).
func enforceCacheControlLimit(payload []byte, maxBlocks int) []byte {
	root, ok := parsePayloadObject(payload)
	if !ok {
		return payload
	}

	total := countCacheControlsMap(root)
	if total <= maxBlocks {
		return payload
	}

	excess := total - maxBlocks

	var system []any
	if arr, ok := asArray(root["system"]); ok {
		system = arr
	}
	var tools []any
	if arr, ok := asArray(root["tools"]); ok {
		tools = arr
	}
	var messages []any
	if arr, ok := asArray(root["messages"]); ok {
		messages = arr
	}

	if len(system) > 0 {
		stripCacheControlExceptIndex(system, findLastCacheControlIndex(system), &excess)
	}
	if excess <= 0 {
		return marshalPayloadObject(payload, root)
	}

	if len(tools) > 0 {
		stripCacheControlExceptIndex(tools, findLastCacheControlIndex(tools), &excess)
	}
	if excess <= 0 {
		return marshalPayloadObject(payload, root)
	}

	if len(messages) > 0 {
		stripMessageCacheControl(messages, &excess)
	}
	if excess <= 0 {
		return marshalPayloadObject(payload, root)
	}

	if len(system) > 0 {
		stripAllCacheControl(system, &excess)
	}
	if excess <= 0 {
		return marshalPayloadObject(payload, root)
	}

	if len(tools) > 0 {
		stripAllCacheControl(tools, &excess)
	}

	return marshalPayloadObject(payload, root)
}

// injectMessagesCacheControl adds cache_control to the second-to-last user turn for multi-turn caching.
// Per Anthropic docs: "Place cache_control on the second-to-last User message to let the model reuse the earlier cache."
// This enables caching of conversation history, which is especially beneficial for long multi-turn conversations.
// Only adds cache_control if:
// - There are at least 2 user turns in the conversation
// - No message content already has cache_control
func injectMessagesCacheControl(payload []byte) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	// Check if ANY message content already has cache_control
	hasCacheControlInMessages := false
	messages.ForEach(func(_, msg gjson.Result) bool {
		content := msg.Get("content")
		if content.IsArray() {
			content.ForEach(func(_, item gjson.Result) bool {
				if item.Get("cache_control").Exists() {
					hasCacheControlInMessages = true
					return false
				}
				return true
			})
		}
		return !hasCacheControlInMessages
	})
	if hasCacheControlInMessages {
		return payload
	}

	// Find all user message indices
	var userMsgIndices []int
	messages.ForEach(func(index gjson.Result, msg gjson.Result) bool {
		if msg.Get("role").String() == "user" {
			userMsgIndices = append(userMsgIndices, int(index.Int()))
		}
		return true
	})

	// Need at least 2 user turns to cache the second-to-last
	if len(userMsgIndices) < 2 {
		return payload
	}

	// Get the second-to-last user message index
	secondToLastUserIdx := userMsgIndices[len(userMsgIndices)-2]

	// Get the content of this message
	contentPath := fmt.Sprintf("messages.%d.content", secondToLastUserIdx)
	content := gjson.GetBytes(payload, contentPath)

	if content.IsArray() {
		// Add cache_control to the last content block of this message
		contentCount := int(content.Get("#").Int())
		if contentCount > 0 {
			cacheControlPath := fmt.Sprintf("messages.%d.content.%d.cache_control", secondToLastUserIdx, contentCount-1)
			result, err := sjson.SetBytes(payload, cacheControlPath, map[string]string{"type": "ephemeral"})
			if err != nil {
				log.Warnf("failed to inject cache_control into messages: %v", err)
				return payload
			}
			payload = result
		}
	} else if content.Type == gjson.String {
		// Convert string content to array with cache_control
		text := content.String()
		newContent := []map[string]interface{}{
			{
				"type": "text",
				"text": text,
				"cache_control": map[string]string{
					"type": "ephemeral",
				},
			},
		}
		result, err := sjson.SetBytes(payload, contentPath, newContent)
		if err != nil {
			log.Warnf("failed to inject cache_control into message string content: %v", err)
			return payload
		}
		payload = result
	}

	return payload
}

// injectToolsCacheControl adds cache_control to the last tool in the tools array.
// Per Anthropic docs: "The cache_control parameter on the last tool definition caches all tool definitions."
// This only adds cache_control if NO tool in the array already has it.
func injectToolsCacheControl(payload []byte) []byte {
	tools := gjson.GetBytes(payload, "tools")
	if !tools.Exists() || !tools.IsArray() {
		return payload
	}

	toolCount := int(tools.Get("#").Int())
	if toolCount == 0 {
		return payload
	}

	// Check if ANY tool already has cache_control - if so, don't modify tools
	hasCacheControlInTools := false
	tools.ForEach(func(_, tool gjson.Result) bool {
		if tool.Get("cache_control").Exists() {
			hasCacheControlInTools = true
			return false
		}
		return true
	})
	if hasCacheControlInTools {
		return payload
	}

	// Add cache_control to the last tool
	lastToolPath := fmt.Sprintf("tools.%d.cache_control", toolCount-1)
	result, err := sjson.SetBytes(payload, lastToolPath, map[string]string{"type": "ephemeral"})
	if err != nil {
		log.Warnf("failed to inject cache_control into tools array: %v", err)
		return payload
	}

	return result
}

// injectSystemCacheControl adds cache_control to the last element in the system prompt.
// Converts string system prompts to array format if needed.
// This only adds cache_control if NO system element already has it.
func injectSystemCacheControl(payload []byte) []byte {
	system := gjson.GetBytes(payload, "system")
	if !system.Exists() {
		return payload
	}

	if system.IsArray() {
		count := int(system.Get("#").Int())
		if count == 0 {
			return payload
		}

		// Check if ANY system element already has cache_control
		hasCacheControlInSystem := false
		system.ForEach(func(_, item gjson.Result) bool {
			if item.Get("cache_control").Exists() {
				hasCacheControlInSystem = true
				return false
			}
			return true
		})
		if hasCacheControlInSystem {
			return payload
		}

		// Add cache_control to the last system element
		lastSystemPath := fmt.Sprintf("system.%d.cache_control", count-1)
		result, err := sjson.SetBytes(payload, lastSystemPath, map[string]string{"type": "ephemeral"})
		if err != nil {
			log.Warnf("failed to inject cache_control into system array: %v", err)
			return payload
		}
		payload = result
	} else if system.Type == gjson.String {
		// Convert string system prompt to array with cache_control
		// "system": "text" -> "system": [{"type": "text", "text": "text", "cache_control": {"type": "ephemeral"}}]
		text := system.String()
		newSystem := []map[string]interface{}{
			{
				"type": "text",
				"text": text,
				"cache_control": map[string]string{
					"type": "ephemeral",
				},
			},
		}
		result, err := sjson.SetBytes(payload, "system", newSystem)
		if err != nil {
			log.Warnf("failed to inject cache_control into system string: %v", err)
			return payload
		}
		payload = result
	}

	return payload
}

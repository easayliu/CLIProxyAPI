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
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
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
	cfg              *config.Config
	telemetryEmitter *TelemetryEmitter
}

// claudeToolPrefix is empty to match real Claude Code behavior (no tool name prefix).
// Previously "proxy_" was used but this is a detectable fingerprint difference.
const claudeToolPrefix = ""

func NewClaudeExecutor(cfg *config.Config) *ClaudeExecutor {
	return &ClaudeExecutor{
		cfg:              cfg,
		telemetryEmitter: NewTelemetryEmitter(),
	}
}

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
	if isClaudeOAuthToken(apiKey) {
		req.Header.Del("x-api-key")
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else if apiKey != "" {
		req.Header.Del("Authorization")
		req.Header.Set("x-api-key", apiKey)
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
	t0 := time.Now()
	resp, err := httpClient.Do(httpReq)
	elapsed := time.Since(t0)
	if err != nil {
		logWithRequestID(ctx).Warnf("[timing] HttpRequest upstream failed after %s: %v", elapsed, err)
	} else {
		logWithRequestID(ctx).Infof("[timing] HttpRequest upstream responded %d in %s", resp.StatusCode, elapsed)
	}
	return resp, err
}

// upstreamPrepResult holds the prepared request and related metadata produced by prepareUpstream.
type upstreamPrepResult struct {
	httpReq            *http.Request
	apiKey             string
	bodyForTranslation []byte
	from               sdktranslator.Format
	to                 sdktranslator.Format
	reporter           *usageReporter
	prepDuration       time.Duration
	sessionRelease     func() // must be called when request completes
}

// prepareUpstream contains the shared preparation logic for Execute and ExecuteStream.
// It performs rate limiting, body sanitization, cloaking, header injection, and builds
// the upstream HTTP request. The caller is responsible for sending the request.
func (e *ClaudeExecutor) prepareUpstream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, streaming bool, callerTag string) (*upstreamPrepResult, error) {
	tEntry := time.Now()

	// Enforce per-auth RPM limit before proceeding.
	t0 := time.Now()
	if err := checkClaudeRateLimit(auth); err != nil {
		return nil, err
	}
	if d := time.Since(t0); d > 50*time.Millisecond {
		logWithRequestID(ctx).Warnf("[timing] %s checkClaudeRateLimit took %s", callerTag, d)
	}

	baseModel := req.Model
	apiKey, baseURL := claudeCreds(auth)
	if baseURL == "" {
		baseURL = "https://api.anthropic.com"
	}

	// Log identity on every request for auditing.
	extractAuthIdentity(auth, apiKey)

	poolKey := stablePoolKey(auth, apiKey)
	isCliClient := isClaudeCodeClient(getClientUserAgent(ctx))

	// Acquire a rotating session for CLI clients.
	// All concurrent requests (including subagents) share the same session_id,
	// matching real Claude Code behavior. Session rotates every 30–45 min.
	var mappedSessionID string
	sessionRelease := noopRelease
	if isCliClient {
		clientSID := extractClientSessionID(req.Payload)
		if clientSID != "" {
			mappedSessionID, sessionRelease = AcquireCLISession(poolKey)
		}
	}

	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")

	body := req.Payload

	// Sanitize context_management.edits: remove edits without server-issued signatures.
	body = sanitizeContextManagementEdits(body)

	// For non-CLI clients only: repair malformed body structures.
	if !isCliClient {
		body = repairToolUsePairing(body)
		body = sanitizeEmptyTextBlocks(body)
	}

	// Apply cloaking (fake user ID, field sanitization, sensitive word obfuscation).
	t0 = time.Now()
	body, _, err := applyCloaking(ctx, e.cfg, auth, body, baseModel, apiKey, "")
	if err != nil {
		return nil, err
	}
	if d := time.Since(t0); d > 50*time.Millisecond {
		logWithRequestID(ctx).Warnf("[timing] %s applyCloaking took %s", callerTag, d)
	}

	// Replace metadata.user_id with auth's real identity.
	body = replaceMetadataUserID(body, auth, poolKey, mappedSessionID)

	// Extract betas from body and convert to header.
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
	applyClaudeHeaders(httpReq, auth, apiKey, streaming, extraBetas, e.cfg, baseModel, bodyForUpstream, mappedSessionID)

	if log.IsLevelEnabled(log.DebugLevel) {
		hdrs, _ := json.Marshal(httpReq.Header)
		log.Debugf("[upstream-debug] url=%s headers=%s", url, string(hdrs))
		log.Debugf("[upstream-debug] body=%s", string(bodyForUpstream))
	}

	recordAPIRequest(ctx, e.cfg, buildUpstreamLog(url, bodyForUpstream, httpReq.Header, e.Identifier(), auth))

	return &upstreamPrepResult{
		httpReq:            httpReq,
		apiKey:             apiKey,
		bodyForTranslation: bodyForTranslation,
		from:               from,
		to:                 to,
		reporter:           reporter,
		prepDuration:       time.Since(tEntry),
		sessionRelease:     sessionRelease,
	}, nil
}

// buildUpstreamLog constructs an upstreamRequestLog from auth info.
func buildUpstreamLog(url string, body []byte, headers http.Header, provider string, auth *cliproxyauth.Auth) upstreamRequestLog {
	info := upstreamRequestLog{
		URL:      url,
		Method:   http.MethodPost,
		Headers:  headers.Clone(),
		Body:     body,
		Provider: provider,
	}
	if auth != nil {
		info.AuthID = auth.ID
		info.AuthLabel = auth.Label
		info.AuthType, info.AuthValue = auth.AccountInfo()
	}
	return info
}

// handleUpstreamError handles non-2xx responses from upstream, decompressing and logging
// the error body. Returns a statusErr with the upstream status code.
func (e *ClaudeExecutor) handleUpstreamError(ctx context.Context, httpResp *http.Response) error {
	errBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if decErr != nil {
		recordAPIResponseError(ctx, e.cfg, decErr)
		msg := fmt.Sprintf("failed to decode error response body: %v", decErr)
		logWithRequestID(ctx).Warn(msg)
		return statusErr{code: httpResp.StatusCode, msg: msg}
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
	return statusErr{code: httpResp.StatusCode, msg: string(b)}
}

func (e *ClaudeExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	if opts.Alt == "responses/compact" {
		return resp, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}

	prep, err := e.prepareUpstream(ctx, auth, req, opts, false, "Execute")
	if err != nil {
		return resp, err
	}
	defer prep.sessionRelease()
	reporter := prep.reporter
	defer reporter.trackFailure(ctx, &err)

	httpClient := newClaudeHTTPClient(e.cfg, auth)
	t0 := time.Now()
	httpResp, err := httpClient.Do(prep.httpReq)
	upstreamDuration := time.Since(t0)
	if err != nil {
		logWithRequestID(ctx).Warnf("[timing] Execute upstream failed after %s (prep=%s): %v", upstreamDuration, prep.prepDuration, err)
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	logWithRequestID(ctx).Infof("[timing] Execute upstream responded %d in %s (prep=%s)", httpResp.StatusCode, upstreamDuration, prep.prepDuration)
	recordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	updateAuthRateLimit(auth, httpResp.Header)

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return resp, e.handleUpstreamError(ctx, httpResp)
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

	stream := prep.from != prep.to
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

	if isClaudeOAuthToken(prep.apiKey) && !auth.ToolPrefixDisabled() {
		data = stripClaudeToolPrefixFromResponse(data, claudeToolPrefix)
	}

	var param any
	out := sdktranslator.TranslateNonStream(
		ctx,
		prep.to,
		prep.from,
		req.Model,
		opts.OriginalRequest,
		prep.bodyForTranslation,
		data,
		&param,
	)
	return cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}, nil
}

func (e *ClaudeExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}

	prep, err := e.prepareUpstream(ctx, auth, req, opts, true, "ExecuteStream")
	if err != nil {
		return nil, err
	}
	reporter := prep.reporter
	defer reporter.trackFailure(ctx, &err)

	httpClient := newClaudeHTTPClient(e.cfg, auth)
	t0 := time.Now()
	httpResp, err := httpClient.Do(prep.httpReq)
	upstreamDuration := time.Since(t0)
	if err != nil {
		logWithRequestID(ctx).Warnf("[timing] ExecuteStream upstream failed after %s (prep=%s): %v", upstreamDuration, prep.prepDuration, err)
		recordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	logWithRequestID(ctx).Infof("[timing] ExecuteStream upstream responded %d in %s (prep=%s)", httpResp.StatusCode, upstreamDuration, prep.prepDuration)
	recordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	updateAuthRateLimit(auth, httpResp.Header)

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, e.handleUpstreamError(ctx, httpResp)
	}

	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return nil, err
	}

	apiKey := prep.apiKey
	needStripPrefix := isClaudeOAuthToken(apiKey) && !auth.ToolPrefixDisabled()

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer prep.sessionRelease() // release session after stream fully consumed
		defer func() {
			if errClose := decodedBody.Close(); errClose != nil {
				log.Debugf("response body close error: %v", errClose)
			}
		}()

		// If from == to (Claude -> Claude), directly forward the SSE stream without translation.
		if prep.from == prep.to {
			scanner := bufio.NewScanner(decodedBody)
			scanner.Buffer(nil, 52_428_800) // 50MB
			for scanner.Scan() {
				line := scanner.Bytes()
				appendAPIResponseChunk(ctx, e.cfg, line)
				if detail, ok := parseClaudeStreamUsage(line); ok {
					reporter.publish(ctx, detail)
				}
				if needStripPrefix {
					line = stripClaudeToolPrefixFromStreamLine(line, claudeToolPrefix)
				}
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

		// For other formats, use translation.
		scanner := bufio.NewScanner(decodedBody)
		scanner.Buffer(nil, 52_428_800) // 50MB
		var param any
		for scanner.Scan() {
			line := scanner.Bytes()
			appendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := parseClaudeStreamUsage(line); ok {
				reporter.publish(ctx, detail)
			}
			if needStripPrefix {
				line = stripClaudeToolPrefixFromStreamLine(line, claudeToolPrefix)
			}
			chunks := sdktranslator.TranslateStream(
				ctx,
				prep.to,
				prep.from,
				req.Model,
				opts.OriginalRequest,
				prep.bodyForTranslation,
				bytes.Clone(line),
				&param,
			)
			for i := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}
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
	baseModel := req.Model

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

	body = checkSystemInstructions(body)
	body = finalizeBillingHeader(body)

	// Extract betas from body and convert to header.
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
	applyClaudeHeaders(httpReq, auth, apiKey, false, extraBetas, e.cfg, baseModel, body)
	recordAPIRequest(ctx, e.cfg, buildUpstreamLog(url, body, httpReq.Header, e.Identifier(), auth))

	httpClient := newClaudeHTTPClient(e.cfg, auth)
	tCountTokens := time.Now()
	resp, err := httpClient.Do(httpReq)
	countTokensDuration := time.Since(tCountTokens)
	if err != nil {
		logWithRequestID(ctx).Warnf("[timing] CountTokens upstream failed after %s: %v", countTokensDuration, err)
		recordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	logWithRequestID(ctx).Infof("[timing] CountTokens upstream responded %d in %s", resp.StatusCode, countTokensDuration)
	recordAPIResponseMetadata(ctx, e.cfg, resp.StatusCode, resp.Header.Clone())
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return cliproxyexecutor.Response{}, e.handleUpstreamError(ctx, resp)
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
	return cliproxyexecutor.Response{Payload: out, Headers: resp.Header.Clone()}, nil
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
	// Keep account_uuid and organization_uuid up-to-date from refresh response
	// so cloaking and telemetry use the real values.
	if td.AccountUUID != "" {
		auth.Metadata["account_uuid"] = td.AccountUUID
	}
	if td.OrganizationUUID != "" {
		auth.Metadata["organization_uuid"] = td.OrganizationUUID
	}
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

// buildAnthropicBeta builds the anthropic-beta header value dynamically based on
// upstream auth type, model, request body content, and extra betas.
// Matches real Claude CLI 2.1.87 behavior observed via MITM capture.
func buildAnthropicBeta(apiKey, model string, body []byte, extraBetas []string, ginHeaders http.Header) string {
	betaSet := make(map[string]bool)
	addBeta := func(b string) { betaSet[b] = true }

	// Always present in real CLI with OAuth tokens.
	if isClaudeOAuthToken(apiKey) {
		addBeta("oauth-2025-04-20")
	}
	addBeta("interleaved-thinking-2025-05-14")
	addBeta("redact-thinking-2026-02-12")
	addBeta("prompt-caching-scope-2026-01-05")

	// Conditional betas based on body features.
	hasTools := gjson.GetBytes(body, "tools").IsArray() && len(gjson.GetBytes(body, "tools").Array()) > 0
	if hasTools {
		addBeta("claude-code-20250219")
		addBeta("advanced-tool-use-2025-11-20")
	}
	if gjson.GetBytes(body, "thinking").Exists() || gjson.GetBytes(body, "output_config.effort").Exists() {
		addBeta("effort-2025-11-24")
	}
	if gjson.GetBytes(body, "output_config.format.type").String() == "json_schema" {
		addBeta("structured-outputs-2025-12-15")
	}
	if gjson.GetBytes(body, "context_management").Exists() || !isHaikuModel(model) {
		addBeta("context-management-2025-06-27")
	}
	if modelSupports1MContext(model) || strings.Contains(model, "opus-4-6") {
		addBeta("context-1m-2025-08-07")
	}

	if ginHeaders != nil {
		if _, ok := ginHeaders[textproto.CanonicalMIMEHeaderKey("X-CPA-CLAUDE-1M")]; ok {
			addBeta("context-1m-2025-08-07")
		}
		// Preserve client betas not in our predefined set (e.g. redact-thinking).
		if clientBeta := ginHeaders.Get("anthropic-beta"); clientBeta != "" {
			for _, b := range strings.Split(clientBeta, ",") {
				b = strings.TrimSpace(b)
				if b != "" {
					addBeta(b)
				}
			}
		}
	}

	for _, beta := range extraBetas {
		beta = strings.TrimSpace(beta)
		if beta != "" {
			addBeta(beta)
		}
	}

	// Assemble in a stable order matching real CLI output.
	betaOrder := []string{
		"claude-code-20250219",
		"oauth-2025-04-20",
		"context-1m-2025-08-07",
		"interleaved-thinking-2025-05-14",
		"redact-thinking-2026-02-12",
		"context-management-2025-06-27",
		"prompt-caching-scope-2026-01-05",
		"advanced-tool-use-2025-11-20",
		"effort-2025-11-24",
		"structured-outputs-2025-12-15",
	}
	var betas []string
	for _, b := range betaOrder {
		if betaSet[b] {
			betas = append(betas, b)
			delete(betaSet, b)
		}
	}
	for b := range betaSet {
		betas = append(betas, b)
	}
	return strings.Join(betas, ",")
}

// isHaikuModel returns true for all Haiku model variants (3.5 and 4.5).
// Real CLI sends full system prompt for Haiku but skips deferred-tools,
// adaptive thinking, and effort injection.
func isHaikuModel(model string) bool {
	return strings.HasPrefix(model, "claude-3-5-haiku") || strings.HasPrefix(model, "claude-haiku-4-5")
}

// modelSupports1MContext returns true if the model name explicitly requests 1M context.
// Real Claude CLI only adds context-1m-2025-08-07 beta when the model name contains "[1m]"
// suffix (e.g. "claude-opus-4-6[1m]"). Without this suffix, even Opus 4.6 uses 200K context.
func modelSupports1MContext(model string) bool {
	return strings.Contains(strings.ToLower(model), "[1m]")
}

func applyClaudeHeaders(r *http.Request, auth *cliproxyauth.Auth, apiKey string, _ bool, extraBetas []string, cfg *config.Config, model string, body []byte, mappedSessionID ...string) {
	var ginHeaders http.Header
	if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header
	}

	// CLI clients: passthrough original headers, only replace auth credentials
	// and rebuild anthropic-beta (client generates betas based on proxy key/domain,
	// which may differ from the actual upstream OAuth context).
	if ginHeaders != nil && isClaudeCodeClient(ginHeaders.Get("User-Agent")) {
		for k, v := range ginHeaders {
			r.Header[k] = v
		}
		// Remove proxy-specific headers that must not leak to upstream.
		r.Header.Del("Host")
		r.Header.Del("Content-Length") // recalculated by http.Client
		// Replace auth with proxy's credentials.
		if isClaudeOAuthToken(apiKey) {
			r.Header.Del("x-api-key")
			r.Header.Set("Authorization", "Bearer "+apiKey)
		} else if apiKey != "" {
			r.Header.Del("Authorization")
			r.Header.Set("x-api-key", apiKey)
		}
		// Ensure x-client-request-id is present (real CLI sends it to
		// api.anthropic.com but may omit it when targeting a proxy domain).
		if r.Header.Get("x-client-request-id") == "" {
			r.Header.Set("x-client-request-id", uuid.New().String())
		}
		// Replace X-Claude-Code-Session-Id with mapped pool session to
		// bound the number of visible sessions per auth.
		if len(mappedSessionID) > 0 && mappedSessionID[0] != "" {
			r.Header.Set("X-Claude-Code-Session-Id", mappedSessionID[0])
		}
		// Rebuild anthropic-beta: start from client's betas, then supplement
		// any missing betas that the proxy's upstream auth/model context requires.
		r.Header.Del("anthropic-beta")
		r.Header.Del("Anthropic-Beta")
		betaStr := buildAnthropicBeta(apiKey, model, body, extraBetas, ginHeaders)
		r.Header["anthropic-beta"] = []string{betaStr}
		return
	}

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

	// Real CLI uses Authorization: Bearer for OAuth tokens, x-api-key for API keys.
	// Determine auth style by token prefix, not by which field it was configured in.
	if isClaudeOAuthToken(apiKey) {
		r.Header.Del("x-api-key")
		r.Header.Set("Authorization", "Bearer "+apiKey)
	} else if apiKey != "" {
		r.Header.Del("Authorization")
		r.Header.Set("x-api-key", apiKey)
	}
	r.Header.Set("Content-Type", "application/json")


	betaStr := buildAnthropicBeta(apiKey, model, body, extraBetas, ginHeaders)
	betas := strings.Split(betaStr, ",")
	// Use exact header casing from real CLI MITM capture (2.1.84).
	// Go's r.Header.Set() canonicalizes keys (e.g. "anthropic-beta" → "Anthropic-Beta"),
	// so we bypass it with direct map assignment r.Header["key"] = []string{val}.
	// For HTTP/2 this doesn't matter (all keys lowercased on wire), but for HTTP/1.1
	// proxies the original casing is preserved and can be a fingerprint.
	setRaw := func(key, val string) {
		r.Header[key] = []string{val}
	}

	// Anthropic headers: all lowercase in real CLI
	setRaw("anthropic-beta", strings.Join(betas, ","))
	setRaw("anthropic-version", "2023-06-01")
	setRaw("anthropic-dangerous-direct-browser-access", "true")
	setRaw("x-app", "cli")

	// Stainless SDK headers: Title-Case, except OS which is all-caps
	setRaw("X-Stainless-Retry-Count", "0")
	setRaw("X-Stainless-Runtime-Version", hdrDefault(hd.RuntimeVersion, "v24.11.1"))
	setRaw("X-Stainless-Package-Version", hdrDefault(hd.PackageVersion, "0.74.0"))
	setRaw("X-Stainless-Runtime", "node")
	setRaw("X-Stainless-Lang", "js")
	setRaw("X-Stainless-Arch", hdrDefault(hd.Arch, mapStainlessArch()))
	setRaw("X-Stainless-OS", hdrDefault(hd.Os, mapStainlessOS()))
	setRaw("X-Stainless-Timeout", hdrDefault(hd.Timeout, "600"))

	// Standard HTTP headers matching real CLI 2.1.84 MITM capture.
	// Accept is Title-Case; the rest are lowercase in real Bun wire format.
	userAgent := hdrDefault(hd.UserAgent, "claude-cli/2.1.90 (external, cli)")
	clientReqID := uuid.New().String()
	r.Header.Set("User-Agent", userAgent)
	r.Header.Set("Accept", "application/json")
	setRaw("accept-encoding", "br, gzip, deflate")
	setRaw("accept-language", "*")
	setRaw("sec-fetch-mode", "cors")
	setRaw("connection", "keep-alive")
	// Real CLI 2.1.84 sends x-client-request-id (UUID v4) with every /v1/messages request.
	setRaw("x-client-request-id", clientReqID)
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs)

	log.Infof("[cloaking] headers: User-Agent=%s anthropic-beta=%s x-client-request-id=%s X-Stainless-Package-Version=%s X-Stainless-Runtime-Version=%s X-Stainless-OS=%s X-Stainless-Arch=%s",
		userAgent, strings.Join(betas, ","), clientReqID,
		r.Header["X-Stainless-Package-Version"], r.Header["X-Stainless-Runtime-Version"],
		r.Header["X-Stainless-OS"], r.Header["X-Stainless-Arch"])
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

// extractClientSessionID extracts the session_id from the client's
// metadata.user_id JSON field. Returns empty string if not present.
func extractClientSessionID(payload []byte) string {
	userIDStr := gjson.GetBytes(payload, "metadata.user_id").String()
	if userIDStr == "" {
		return ""
	}
	// user_id is a JSON string: {"device_id":"...","account_uuid":"...","session_id":"..."}
	sid := gjson.Get(userIDStr, "session_id").String()
	return sid
}

// stablePoolKey returns a stable key for the session pool. For OAuth tokens,
// auth.ID survives token refreshes. Falls back to apiKey for non-OAuth or
// when auth is nil.
func stablePoolKey(auth *cliproxyauth.Auth, apiKey string) string {
	if auth != nil && auth.ID != "" {
		return auth.ID
	}
	return apiKey
}

// extractAuthIdentity extracts identity fields from auth metadata,
// falling back to hash-derived values from the API key.
func extractAuthIdentity(auth *cliproxyauth.Auth, apiKey string) (deviceID, accountUUID, orgUUID, email string) {
	deviceID = DeriveDeviceID(apiKey)
	accountUUID = DeriveAccountUUID(apiKey)
	orgUUID = DeriveOrganizationUUID(apiKey)
	fromMeta := false
	if auth != nil && auth.Metadata != nil {
		if v, ok := auth.Metadata["device_id"].(string); ok && v != "" {
			deviceID = v
			fromMeta = true
		}
		if v, ok := auth.Metadata["account_uuid"].(string); ok && v != "" {
			accountUUID = v
		}
		if v, ok := auth.Metadata["organization_uuid"].(string); ok && v != "" {
			orgUUID = v
		}
		if v, ok := auth.Metadata["email"].(string); ok && v != "" {
			email = v
		}
	}
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	if fromMeta {
		log.Infof("[claude-identity] auth=%s device_id=%s account_uuid=%s org_uuid=%s (from auth metadata)", authID, deviceID, accountUUID, orgUUID)
	} else {
		log.Warnf("[claude-identity] auth=%s device_id=%s account_uuid=%s org_uuid=%s (derived from key — consider setting device_id/account_uuid in auth config)", authID, deviceID, accountUUID, orgUUID)
	}
	return
}

func checkSystemInstructions(payload []byte) []byte {
	return checkSystemInstructionsWithMode(payload, false, false, "")
}

// replaceMetadataUserID replaces metadata.user_id in the request body with
// the auth's real device_id/account_uuid. When overrideSessionID is non-empty,
// it replaces the client's session_id with the given value; otherwise preserves
// the client's original session_id.
//
// Uses bytes.Replace on the raw JSON to avoid sjson re-serializing the entire
// body, which corrupts payloads containing redacted thinking content.
func replaceMetadataUserID(body []byte, auth *cliproxyauth.Auth, poolKey string, overrideSessionID ...string) []byte {
	// Extract the original user_id raw JSON value (the escaped string).
	oldUserID := gjson.GetBytes(body, "metadata.user_id")
	if !oldUserID.Exists() {
		return body
	}

	// Get real identity from auth metadata.
	realDeviceID := ""
	realAccountUUID := ""
	if auth != nil && auth.Metadata != nil {
		if v, ok := auth.Metadata["device_id"].(string); ok {
			realDeviceID = v
		}
		if v, ok := auth.Metadata["account_uuid"].(string); ok {
			realAccountUUID = v
		}
	}

	// Use override session_id if provided (e.g. from CLI session pool mapping),
	// otherwise preserve client's original session_id for conversation continuity.
	var clientSessionID string
	if len(overrideSessionID) > 0 && overrideSessionID[0] != "" {
		clientSessionID = overrideSessionID[0]
	} else {
		clientSessionID = extractFieldFromUserID(oldUserID.String(), "session_id")
	}
	if clientSessionID == "" {
		clientSessionID = uuid.New().String()
	}

	// Fallback: use cached random identity per pool key so the same auth
	// always gets the same device_id/account_uuid across requests.
	if realDeviceID == "" || realAccountUUID == "" {
		cachedDeviceID, cachedAccountUUID := CachedRandomIdentity(poolKey)
		if realDeviceID == "" {
			realDeviceID = cachedDeviceID
		}
		if realAccountUUID == "" {
			realAccountUUID = cachedAccountUUID
		}
	}

	newPayload, _ := json.Marshal(userIDPayload{
		DeviceID:    realDeviceID,
		AccountUUID: realAccountUUID,
		SessionID:   clientSessionID,
	})

	// Build the new JSON string value (what appears after "user_id":).
	// oldUserID.Raw is the raw JSON token including quotes, e.g. "{\"device_id\":...}"
	newRaw, _ := json.Marshal(string(newPayload))

	result := bytes.Replace(body, []byte(oldUserID.Raw), newRaw, 1)
	log.Infof("[claude-identity] metadata.user_id=%s", string(newPayload))
	return result
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


// billingBuildHashSalt is the fixed salt used by real Claude Code CLI
// to compute the per-request build hash in the billing header.
// Extracted from cli.js: KM7 = "59cf53e54c78".
const billingBuildHashSalt = "59cf53e54c78"

// billingCLIVersion is the CLI version embedded in the billing header.
const billingCLIVersion = "2.1.90"

// computeBuildHash computes the 3-char build hash for the billing header.
// Algorithm (from cli.js _0T): extract chars at positions [4,7,20] from the
// first user message text, concatenate salt + chars + version, SHA-256 hash,
// take first 3 hex chars.
func computeBuildHash(payload []byte) string {
	text := firstUserMessageText(payload)
	// JS string indexing operates on UTF-16 code units. For BMP characters
	// (which covers CJK and most text) this is equivalent to rune indexing.
	runes := []rune(text)
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
	hash := hex.EncodeToString(h[:])[:3]
	log.Infof("[billing-debug] firstUserText(runes=%d): %.80s", len(runes), text)
	log.Infof("[billing-debug] chars=[%c,%c,%c] hash=%s", chars[0], chars[1], chars[2], hash)
	return hash
}

// firstUserMessageText extracts the text content of the first non-deferred-tools
// user message from a Claude API request payload. Matches cli.js OM7 function
// behavior: the deferred-tools message (messages[0] with <available-deferred-tools>)
// is skipped; the build hash is computed from the next user message's first text block.
func firstUserMessageText(payload []byte) string {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.IsArray() {
		return ""
	}
	for _, msg := range messages.Array() {
		if msg.Get("role").String() != "user" {
			continue
		}
		content := msg.Get("content")
		// String content
		if content.Type == gjson.String {
			text := content.String()
			if strings.Contains(text, "<available-deferred-tools>") {
				continue // skip deferred-tools message
			}
			return text
		}
		// Array content: find first text block
		if content.IsArray() {
			first := ""
			for _, block := range content.Array() {
				if block.Get("type").String() == "text" {
					first = block.Get("text").String()
					break
				}
			}
			if strings.Contains(first, "<available-deferred-tools>") {
				continue // skip deferred-tools message
			}
			return first
		}
		return ""
	}
	return ""
}

// generateCCH returns the cch field for the billing header.
// Node runtime always sends cch=00000; non-zero values seen in MITM captures
// come from Bun's native layer. We target Node behavior.
func generateCCH(_ []byte) string {
	return "00000"
}

// Billing header placeholder tokens, replaced by finalizeBillingHeader after
// all message injections (system-reminder, deferred-tools) are complete.
const (
	billingBuildHashPlaceholder = "__BH__"
	billingCCHPlaceholder      = "__CCH__"
)

// generateBillingHeader creates an x-anthropic-billing-header with placeholder
// tokens for the build hash and cch. These placeholders are replaced by
// finalizeBillingHeader once the full payload (including injected system-reminder
// and deferred-tools) is available.
func generateBillingHeader() string {
	return fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; cch=%s;",
		billingCLIVersion, billingBuildHashPlaceholder, billingCCHPlaceholder)
}

// finalizeBillingHeader replaces the placeholder tokens in system[0] with the
// real build hash and cch computed from the final payload. Must be called AFTER
// all message injections (injectCLISystemPrompt, injectCLIDeferredTools, etc.)
// so that the first user message text matches what the real CLI computes from.
func finalizeBillingHeader(payload []byte) []byte {
	buildHash := computeBuildHash(payload)
	cch := generateCCH(payload)
	// Replace placeholders in the raw JSON bytes.
	result := bytes.ReplaceAll(payload, []byte(billingBuildHashPlaceholder), []byte(buildHash))
	result = bytes.ReplaceAll(result, []byte(billingCCHPlaceholder), []byte(cch))
	log.Infof("[billing-header] cc_version=%s.%s; cc_entrypoint=cli; cch=%s;", billingCLIVersion, buildHash, cch)
	return result
}

// checkSystemInstructionsWithMode injects Claude Code-style system blocks:
//
//	system[0]: billing header (no cache_control)
//	system[1]: agent identifier (cache_control: ephemeral)
//	system[2..]: user system messages (cache_control added when missing)
//
// MITM capture (2.1.84) shows cache_control is {"type":"ephemeral"} without
// ttl for main conversation. The oauthMode param is kept for future use.
func checkSystemInstructionsWithMode(payload []byte, strictMode, oauthMode bool, poolKey string) []byte {
	system := gjson.GetBytes(payload, "system")

	billingText := generateBillingHeader()
	billingBlock := fmt.Sprintf(`{"type":"text","text":"%s"}`, billingText)

	agentBlock := `{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude."}`
	if strictMode {
		// Strict mode: billing header + agent block only
		result := "[" + billingBlock + "," + agentBlock + "]"
		payload, _ = sjson.SetRawBytes(payload, "system", []byte(result))
		return payload
	}

	// Non-strict mode: billing header + agent block + user system messages.
	// Always regenerate billing + agent to ensure version consistency.
	// Matches Node CLI 2.1.90 MITM capture structure:
	//   system[0]: billing header (no cache_control)
	//   system[1]: agent identifier (no cache_control)
	//   system[2]: first user system message (cache_control: scope=global, ttl=1h, ephemeral)
	//   system[3..]: remaining user system messages (no cache_control)
	result := "[" + billingBlock + "," + agentBlock
	firstUserBlock := true
	if system.IsArray() {
		system.ForEach(func(_, part gjson.Result) bool {
			if part.Get("type").String() == "text" {
				text := part.Get("text").String()
				// Skip existing billing header or agent block from upstream client
				// to avoid duplication when regenerating.
				if strings.HasPrefix(text, "x-anthropic-billing-header:") {
					return true
				}
				if strings.HasPrefix(text, "You are a Claude agent") || strings.HasPrefix(text, "You are Claude Code") {
					return true
				}
				partJSON := part.Raw
				// Only the first user system block gets cache_control (matches CLI 2.1.90).
				if firstUserBlock && !part.Get("cache_control").Exists() {
					updated, _ := sjson.SetRawBytes([]byte(partJSON), "cache_control", []byte(`{"scope":"global","ttl":"1h","type":"ephemeral"}`))
					partJSON = string(updated)
				}
				firstUserBlock = false
				result += "," + partJSON
			}
			return true
		})
	} else if system.Type == gjson.String && system.String() != "" {
		partJSON := `{"type":"text","cache_control":{"scope":"global","ttl":"1h","type":"ephemeral"}}`
		updated, _ := sjson.SetBytes([]byte(partJSON), "text", system.String())
		partJSON = string(updated)
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
	"model":              true,
	"messages":           true,
	"system":             true,
	"max_tokens":         true,
	"metadata":           true,
	"stop_sequences":     true,
	"stream":             true,
	"temperature":        true,
	"top_p":              true,
	"top_k":              true,
	"tools":              true,
	"tool_choice":        true,
	"thinking":           true,
	"output_config":      true,
	"context_management": true,
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
	// Sanitize metadata: keep only user_id. Real Claude Code CLI sends ONLY
	// metadata.user_id in the request body — no organization_uuid or other fields.
	// Verified via packet capture of real CLI traffic.
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

// sanitizeContextManagementEdits validates context_management.edits entries.
// Each edit requires a server-issued "signature" field; entries without a valid
// signature will be rejected with 400 by the Claude API. Edits with unsupported
// type tags are also removed. If no valid edits remain, the entire
// context_management field is deleted.
func sanitizeContextManagementEdits(payload []byte) []byte {
	cm := gjson.GetBytes(payload, "context_management")
	if !cm.Exists() {
		return payload
	}

	edits := cm.Get("edits")
	if !edits.Exists() || !edits.IsArray() {
		return payload
	}

	var kept []interface{}
	edits.ForEach(func(_, val gjson.Result) bool {
		// Each edit must have a signature from the server
		if val.Get("signature").String() == "" {
			return true // skip: missing signature → API will reject
		}
		kept = append(kept, json.RawMessage(val.Raw))
		return true
	})

	if len(kept) == len(edits.Array()) {
		return payload // nothing filtered
	}

	if len(kept) == 0 {
		// Remove context_management entirely if no valid edits remain.
		// Use bytes-level removal to avoid sjson corrupting large payloads
		// with redacted thinking content.
		cmRaw := cm.Raw // e.g. {"edits":[{"keep":"all","type":"clear_thinking_20251015"}]}
		// Try removing "context_management":{...}, (with trailing comma)
		target := []byte(`"context_management":` + cmRaw + ",")
		result := bytes.Replace(payload, target, nil, 1)
		if len(result) == len(payload) {
			// Try with leading comma instead (field is last in object)
			target = []byte(`,"context_management":` + cmRaw)
			result = bytes.Replace(payload, target, nil, 1)
		}
		if len(result) < len(payload) {
			return result
		}
		// Fallback to sjson if bytes.Replace didn't match
		result, _ = sjson.DeleteBytes(payload, "context_management")
		return result
	}

	// Replace edits array with only the valid ones.
	newEdits, _ := json.Marshal(kept)
	oldEdits := []byte(edits.Raw)
	result := bytes.Replace(payload, oldEdits, newEdits, 1)
	if len(result) != len(payload) {
		return result
	}
	// Fallback to sjson if bytes.Replace didn't match
	result, _ = sjson.SetBytes(payload, "context_management.edits", kept)
	return result
}

// cloakingContextManagementWithThinking includes clear_thinking for requests
// that have thinking enabled/adaptive.
var cloakingContextManagementWithThinking = []byte(`{"edits":[{"keep":"all","type":"clear_thinking_20251015"}]}`)

// cloakingContextManagementNoThinking is an empty edits list for requests
// without thinking. Anthropic rejects clear_thinking_20251015 when thinking
// is not enabled.
var cloakingContextManagementNoThinking = []byte(`{"edits":[]}`)

// replaceContextManagementForCloaking replaces context_management with the standard
// CLI value ONLY when the original request already contains context_management.
// Server-signed edits from the original client are discarded because their
// signatures are session-bound and invalid when forwarded through a proxy.
// The clear_thinking edit is only included when the request has thinking enabled,
// as Anthropic rejects it otherwise with "clear_thinking_20251015 strategy requires
// thinking to be enabled or adaptive".
// Real CLI 2.1.84 does NOT send context_management in early/short conversations;
// injecting it unconditionally would be a fingerprint difference.
func replaceContextManagementForCloaking(payload []byte) []byte {
	if !gjson.GetBytes(payload, "context_management").Exists() {
		return payload
	}
	thinking := gjson.GetBytes(payload, "thinking")
	hasThinking := thinking.Exists() && thinking.Get("type").String() != "disabled"
	cm := cloakingContextManagementNoThinking
	if hasThinking {
		cm = cloakingContextManagementWithThinking
	}
	result, _ := sjson.SetRawBytes(payload, "context_management", cm)
	return result
}

// sanitizeEmptyTextBlocks removes text content blocks that contain only whitespace
// from messages. Anthropic rejects requests with "text content blocks must contain
// non-whitespace text". This can happen when clients send truncated conversations
// or when cloaking/translation strips content but leaves empty text blocks.
func sanitizeEmptyTextBlocks(payload []byte) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	modified := false
	result := payload
	msgArr := messages.Array()

	for i, msg := range msgArr {
		content := msg.Get("content")
		if !content.Exists() || !content.IsArray() {
			// String content — check for whitespace-only.
			if content.Type == gjson.String {
				text := strings.TrimSpace(content.String())
				if text == "" {
					path := fmt.Sprintf("messages.%d.content", i)
					result, _ = sjson.SetBytes(result, path, ".")
					modified = true
				}
			}
			continue
		}

		blocks := content.Array()
		var kept []json.RawMessage
		changed := false

		for _, block := range blocks {
			if block.Get("type").String() == "text" {
				text := strings.TrimSpace(block.Get("text").String())
				if text == "" {
					changed = true
					continue // drop this empty text block
				}
			}
			kept = append(kept, json.RawMessage(block.Raw))
		}

		if !changed {
			continue
		}

		// If all blocks were empty text, keep a minimal placeholder.
		if len(kept) == 0 {
			kept = append(kept, json.RawMessage(`{"type":"text","text":"."}`))
		}

		path := fmt.Sprintf("messages.%d.content", i)
		result, _ = sjson.SetBytes(result, path, kept)
		modified = true
	}

	if !modified {
		return payload
	}
	return result
}

// repairToolUsePairing ensures every tool_use block in an assistant message has
// a corresponding tool_result in the immediately following user message.
// The Claude API requires strict pairing: each tool_use must be answered by a
// tool_result with the same id. Clients may forward truncated conversations
// (e.g. context window management) that break this invariant, causing 400 errors.
// This function injects stub tool_result blocks for any orphaned tool_use ids.
func repairToolUsePairing(payload []byte) []byte {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return payload
	}

	msgArr := messages.Array()
	modified := false
	result := payload

	for i := 0; i < len(msgArr); i++ {
		msg := msgArr[i]
		if msg.Get("role").String() != "assistant" {
			continue
		}

		// Collect tool_use ids from this assistant message
		content := msg.Get("content")
		if !content.Exists() || !content.IsArray() {
			continue
		}

		var toolUseIDs []string
		for _, block := range content.Array() {
			if block.Get("type").String() == "tool_use" {
				if id := block.Get("id").String(); id != "" {
					toolUseIDs = append(toolUseIDs, id)
				}
			}
		}
		if len(toolUseIDs) == 0 {
			continue
		}

		// Check the next message for matching tool_result blocks
		nextIdx := i + 1
		if nextIdx >= len(msgArr) {
			// No next message at all: remove orphaned tool_use blocks from
			// the assistant message (last message in conversation).
			var kept []interface{}
			for _, block := range content.Array() {
				if block.Get("type").String() == "tool_use" {
					continue
				}
				kept = append(kept, json.RawMessage(block.Raw))
			}
			if len(kept) == 0 {
				// If the entire assistant message was tool_use blocks, replace with
				// a minimal text block to avoid an empty content array.
				// Use a single dot — Anthropic rejects whitespace-only text blocks.
				kept = append(kept, json.RawMessage(`{"type":"text","text":"."}`))
			}
			modified = true
			path := fmt.Sprintf("messages.%d.content", i)
			result, _ = sjson.SetBytes(result, path, kept)
			// Re-parse messages after modification
			msgArr = gjson.GetBytes(result, "messages").Array()
			continue
		}

		nextMsg := msgArr[nextIdx]

		// Build set of tool_result ids in the next message
		answeredIDs := make(map[string]bool)
		nextContent := nextMsg.Get("content")
		if nextContent.Exists() && nextContent.IsArray() {
			for _, block := range nextContent.Array() {
				if block.Get("type").String() == "tool_result" {
					if id := block.Get("tool_use_id").String(); id != "" {
						answeredIDs[id] = true
					}
				}
			}
		}

		// Find orphaned tool_use ids
		var orphanIDs []string
		for _, id := range toolUseIDs {
			if !answeredIDs[id] {
				orphanIDs = append(orphanIDs, id)
			}
		}
		if len(orphanIDs) == 0 {
			continue
		}

		// If the next message is not a user message, or we need to inject
		// tool_results, add stub tool_result blocks.
		if nextMsg.Get("role").String() == "user" {
			// Inject into existing user message
			for _, id := range orphanIDs {
				stub := fmt.Sprintf(`{"type":"tool_result","tool_use_id":"%s","content":""}`, id)
				path := fmt.Sprintf("messages.%d.content.-1", nextIdx)
				result, _ = sjson.SetRawBytes(result, path, []byte(stub))
			}
		} else {
			// Next message is not user role: insert a new user message with tool_results
			var stubs []string
			for _, id := range orphanIDs {
				stubs = append(stubs, fmt.Sprintf(`{"type":"tool_result","tool_use_id":"%s","content":""}`, id))
			}
			newMsg := fmt.Sprintf(`{"role":"user","content":[%s]}`, strings.Join(stubs, ","))
			// sjson doesn't support array insert, so we rebuild
			var newMessages []interface{}
			for j, m := range msgArr {
				newMessages = append(newMessages, json.RawMessage(m.Raw))
				if j == i {
					newMessages = append(newMessages, json.RawMessage(newMsg))
				}
			}
			result, _ = sjson.SetBytes(result, "messages", newMessages)
		}

		modified = true
		// Re-parse messages after modification
		msgArr = gjson.GetBytes(result, "messages").Array()
	}

	if !modified {
		return payload
	}
	return result
}

// cliMaxTokens maps model IDs to the max_tokens values that real Claude Code CLI
// sends. These are hardcoded to match observed MITM captures and must be updated
// when real CLI behavior changes. Using the registry is unreliable because models
// may have multiple entries with different providers/values.
var cliMaxTokens = map[string]int{
	"claude-opus-4-6":           64000,
	"claude-sonnet-4-6":         32000,
	"claude-sonnet-4-20250514":  16000,
	"claude-haiku-4-5-20251001": 32000,
}

// normalizeMaxTokensForCloaking ensures max_tokens matches the value that real
// Claude Code CLI sends for each model. A mismatched value (e.g. 8192 for all
// models) is a detectable fingerprint.
func normalizeMaxTokensForCloaking(payload []byte, model string) []byte {
	expected, ok := cliMaxTokens[model]
	if !ok {
		// Unknown model: fall back to registry
		modelInfo := registry.LookupModelInfo(model, "claude")
		if modelInfo == nil || modelInfo.MaxCompletionTokens <= 0 {
			return payload
		}
		expected = modelInfo.MaxCompletionTokens
	}
	current := gjson.GetBytes(payload, "max_tokens")
	if current.Exists() && int(current.Int()) == expected {
		return payload
	}
	log.Infof("[cloaking] max_tokens: %v -> %d", current.Value(), expected)
	result, err := sjson.SetBytes(payload, "max_tokens", expected)
	if err != nil {
		return payload
	}
	return result
}

// applyCloaking applies cloaking transformations to the payload based on config and client.
// Cloaking includes: system prompt injection, fake user ID, and sensitive word obfuscation.
// applyCloaking returns the cloaked payload, the pool sessionID to release, and an error on timeout.
func applyCloaking(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, payload []byte, model string, apiKey string, sessionID string) ([]byte, string, error) {
	clientUserAgent := getClientUserAgent(ctx)

	// Get cloak config from ClaudeKey configuration
	cloakCfg := resolveClaudeKeyCloakConfig(cfg, auth)

	// Determine cloak settings
	var cloakMode string
	var strictMode bool
	var sensitiveWords []string

	if cloakCfg != nil {
		cloakMode = cloakCfg.Mode
		strictMode = cloakCfg.StrictMode
		sensitiveWords = cloakCfg.SensitiveWords
	}

	// Fallback to auth attributes if no config found
	if cloakMode == "" {
		attrMode, attrStrict, attrWords, _ := getCloakConfigFromAuth(auth)
		cloakMode = attrMode
		if !strictMode {
			strictMode = attrStrict
		}
		if len(sensitiveWords) == 0 {
			sensitiveWords = attrWords
		}
	}

	// OAuth tokens default to no cloaking. Set cloak_mode to "always" or
	// "auto" in auth attributes or config to re-enable cloaking for OAuth.
	if cloakMode == "auto" && isClaudeOAuthToken(apiKey) && !isClaudeCodeClient(clientUserAgent) {
		cloakMode = "always"
	}

	// Determine if cloaking should be applied
	if !shouldCloak(cloakMode, clientUserAgent) {
		// Even without cloaking, billing header placeholders must be resolved
		// since checkSystemInstructionsWithMode already injected them.
		payload = finalizeBillingHeader(payload)
		return payload, "", nil
	}

	// Strip non-standard top-level fields and sanitize metadata to prevent
	// upstream proxies from injecting identifiable fields into the request body.
	payload = stripNonStandardFields(payload)

	// Real Claude Code CLI never sends temperature, top_p, or top_k in main
	// conversation requests (confirmed via MITM captures). Strip them to match.
	payload, _ = sjson.DeleteBytes(payload, "temperature")
	payload, _ = sjson.DeleteBytes(payload, "top_p")
	payload, _ = sjson.DeleteBytes(payload, "top_k")

	// Normalize max_tokens to match the model's default when cloaking is active.
	// Non-Claude-Code clients (e.g. NewAPI, OpenAI SDKs) may send a fixed default
	// (like 8192) for all models, which is a detectable fingerprint since real
	// Claude Code CLI sends model-appropriate values (e.g. 128000 for Opus 4.6).
	payload = normalizeMaxTokensForCloaking(payload, model)

	// Inject system[0] (billing header) and system[1] (agent block) for non-CLI clients.
	// Non-strict: prepend billing + agent, keep client system messages.
	// Strict: replace all system with billing + agent only.
	oauthMode := isClaudeOAuthToken(apiKey)
	payload = checkSystemInstructionsWithMode(payload, strictMode, oauthMode, stablePoolKey(auth, apiKey))

	// Prepend default system-reminders to first user message for consistent
	// build hash. Real CLI always has these as the first text block, producing
	// a fixed build hash regardless of client content.
	payload = migrateSystemToUserMessage(payload, defaultSystemReminders())

	// Match real CLI 2.1.90 (Node) behavior: send both thinking:{"type":"adaptive"}
	// and output_config:{"effort":"medium"}. Ensure both fields are present.
	if supportsAdaptiveThinking(model) {
		effortInjected := false
		thinkingInjected := false
		// Ensure thinking is set to adaptive
		if !gjson.GetBytes(payload, "thinking").Exists() {
			payload, _ = sjson.SetRawBytes(payload, "thinking", []byte(`{"type":"adaptive"}`))
			thinkingInjected = true
		}
		// Ensure output_config.effort is set
		if !gjson.GetBytes(payload, "output_config").Exists() {
			effort := thinkingToEffort(payload)
			payload, _ = sjson.SetRawBytes(payload, "output_config", []byte(`{"effort":"`+effort+`"}`))
			effortInjected = true
		}
		log.Infof("[cloaking] thinking: type=%s (injected=%t) output_config: effort=%s (injected=%t)",
			gjson.GetBytes(payload, "thinking.type").String(), thinkingInjected,
			gjson.GetBytes(payload, "output_config.effort").String(), effortInjected)
	}

	// context_management replacement removed: clients manage their own context.
	// payload = replaceContextManagementForCloaking(payload)

	// Inject fake user_id for non-CLI clients to prevent the client's original
	// identity from leaking to upstream. Uses auth's real device_id/account_uuid
	// and a pooled session_id to keep the number of visible sessions bounded.
	poolKey := stablePoolKey(auth, apiKey)
	realDeviceID, realAccountUUID := "", ""
	if auth != nil && auth.Metadata != nil {
		if v, ok := auth.Metadata["device_id"].(string); ok {
			realDeviceID = v
		}
		if v, ok := auth.Metadata["account_uuid"].(string); ok {
			realAccountUUID = v
		}
	}
	if realDeviceID == "" {
		realDeviceID = DeriveDeviceID(poolKey)
	}
	if realAccountUUID == "" {
		realAccountUUID = DeriveAccountUUID(poolKey)
	}
	// Use a stable session_id from the CLI session pool. For non-CLI clients
	// without a real session_id, derive one from the pool key so the mapping
	// is deterministic per auth.
	fakeSessionID := MapCLISessionID(poolKey, DeriveDeviceID(poolKey+":non-cli"), 0)
	fakeUID, _ := json.Marshal(userIDPayload{
		DeviceID:    realDeviceID,
		AccountUUID: realAccountUUID,
		SessionID:   fakeSessionID,
	})
	payload, _ = sjson.SetBytes(payload, "metadata.user_id", string(fakeUID))
	log.Infof("[cloaking] metadata.user_id=%s", string(fakeUID))

	// Apply sensitive word obfuscation
	if len(sensitiveWords) > 0 {
		matcher := buildSensitiveWordMatcher(sensitiveWords)
		payload = obfuscateSensitiveWords(payload, matcher)
	}

	// Replace billing header placeholders with real build hash and cch now
	// that all injections (system-reminder, deferred-tools, etc.) are done.
	payload = finalizeBillingHeader(payload)

	return payload, "", nil
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

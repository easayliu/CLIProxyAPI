// Package claude provides OAuth2 authentication functionality for Anthropic's Claude API.
// This package implements the complete OAuth2 flow with PKCE (Proof Key for Code Exchange)
// for secure authentication with Claude API, including token exchange, refresh, and storage.
package claude

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
	log "github.com/sirupsen/logrus"
)

// OAuth configuration constants for Claude/Anthropic
const (
	AuthURL     = "https://platform.claude.com/oauth/authorize"
	TokenURL    = "https://platform.claude.com/v1/oauth/token"
	ClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	RedirectURI = "http://localhost:54545/oauth/callback"
)

// tokenResponse represents the response structure from Anthropic's OAuth token endpoint.
// It contains access token, refresh token, and associated user/organization information.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Organization struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
	} `json:"organization"`
	Account struct {
		UUID         string `json:"uuid"`
		EmailAddress string `json:"email_address"`
	} `json:"account"`
}

// ClaudeAuth handles Anthropic OAuth2 authentication flow.
// It provides methods for generating authorization URLs, exchanging codes for tokens,
// and refreshing expired tokens using PKCE for enhanced security.
type ClaudeAuth struct {
	httpClient *http.Client
}

// NewClaudeAuth creates a new Anthropic authentication service.
// It initializes the HTTP client with a custom TLS transport that uses Firefox
// fingerprint to bypass Cloudflare's TLS fingerprinting on Anthropic domains.
//
// Parameters:
//   - cfg: The application configuration containing proxy settings
//
// Returns:
//   - *ClaudeAuth: A new Claude authentication service instance
func NewClaudeAuth(cfg *config.Config) *ClaudeAuth {
	// Use custom HTTP client with Firefox TLS fingerprint to bypass
	// Cloudflare's bot detection on Anthropic domains
	return &ClaudeAuth{
		httpClient: NewAnthropicHttpClient(&cfg.SDKConfig),
	}
}

// GenerateAuthURL creates the OAuth authorization URL with PKCE.
// This method generates a secure authorization URL including PKCE challenge codes
// for the OAuth2 flow with Anthropic's API.
//
// Parameters:
//   - state: A random state parameter for CSRF protection
//   - pkceCodes: The PKCE codes for secure code exchange
//
// Returns:
//   - string: The complete authorization URL
//   - string: The state parameter for verification
//   - error: An error if PKCE codes are missing or URL generation fails
func (o *ClaudeAuth) GenerateAuthURL(state string, pkceCodes *PKCECodes) (string, string, error) {
	if pkceCodes == nil {
		return "", "", fmt.Errorf("PKCE codes are required")
	}

	params := url.Values{
		"code":                  {"true"},
		"client_id":             {ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {RedirectURI},
		"scope":                 {"org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"},
		"code_challenge":        {pkceCodes.CodeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}

	authURL := fmt.Sprintf("%s?%s", AuthURL, params.Encode())
	return authURL, state, nil
}

// parseCodeAndState extracts the authorization code and state from the callback response.
// It handles the parsing of the code parameter which may contain additional fragments.
//
// Parameters:
//   - code: The raw code parameter from the OAuth callback
//
// Returns:
//   - parsedCode: The extracted authorization code
//   - parsedState: The extracted state parameter if present
func (c *ClaudeAuth) parseCodeAndState(code string) (parsedCode, parsedState string) {
	splits := strings.Split(code, "#")
	parsedCode = splits[0]
	if len(splits) > 1 {
		parsedState = splits[1]
	}
	return
}

// ExchangeCodeForTokens exchanges authorization code for access tokens.
// This method implements the OAuth2 token exchange flow using PKCE for security.
// It sends the authorization code along with PKCE verifier to get access and refresh tokens.
//
// Parameters:
//   - ctx: The context for the request
//   - code: The authorization code received from OAuth callback
//   - state: The state parameter for verification
//   - pkceCodes: The PKCE codes for secure verification
//
// Returns:
//   - *ClaudeAuthBundle: The complete authentication bundle with tokens
//   - error: An error if token exchange fails
func (o *ClaudeAuth) ExchangeCodeForTokens(ctx context.Context, code, state string, pkceCodes *PKCECodes) (*ClaudeAuthBundle, error) {
	if pkceCodes == nil {
		return nil, fmt.Errorf("PKCE codes are required for token exchange")
	}
	newCode, newState := o.parseCodeAndState(code)

	// Prepare token exchange request
	reqBody := map[string]interface{}{
		"code":          newCode,
		"state":         state,
		"grant_type":    "authorization_code",
		"client_id":     ClientID,
		"redirect_uri":  RedirectURI,
		"code_verifier": pkceCodes.CodeVerifier,
	}

	// Include state if present
	if newState != "" {
		reqBody["state"] = newState
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// log.Debugf("Token exchange request: %s", string(jsonBody))

	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("failed to close response body: %v", errClose)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}
	// log.Debugf("Token response: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}
	// log.Debugf("Token response: %s", string(body))

	var tokenResp tokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Create token data
	tokenData := ClaudeTokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		Email:        tokenResp.Account.EmailAddress,
		Expire:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}

	// Create auth bundle
	bundle := &ClaudeAuthBundle{
		TokenData:   tokenData,
		LastRefresh: time.Now().Format(time.RFC3339),
	}

	return bundle, nil
}

// RefreshTokens refreshes the access token using the refresh token.
// This method exchanges a valid refresh token for a new access token,
// extending the user's authenticated session.
//
// Parameters:
//   - ctx: The context for the request
//   - refreshToken: The refresh token to use for getting new access token
//
// Returns:
//   - *ClaudeTokenData: The new token data with updated access token
//   - error: An error if token refresh fails
func (o *ClaudeAuth) RefreshTokens(ctx context.Context, refreshToken string) (*ClaudeTokenData, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	reqBody := map[string]interface{}{
		"client_id":     ClientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	// log.Debugf("Token response: %s", string(body))

	var tokenResp tokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Create token data
	return &ClaudeTokenData{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		Email:        tokenResp.Account.EmailAddress,
		Expire:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}, nil
}

// CreateTokenStorage creates a new ClaudeTokenStorage from auth bundle and user info.
// This method converts the authentication bundle into a token storage structure
// suitable for persistence and later use.
//
// Parameters:
//   - bundle: The authentication bundle containing token data
//
// Returns:
//   - *ClaudeTokenStorage: A new token storage instance
func (o *ClaudeAuth) CreateTokenStorage(bundle *ClaudeAuthBundle) *ClaudeTokenStorage {
	storage := &ClaudeTokenStorage{
		AccessToken:  bundle.TokenData.AccessToken,
		RefreshToken: bundle.TokenData.RefreshToken,
		LastRefresh:  bundle.LastRefresh,
		Email:        bundle.TokenData.Email,
		Expire:       bundle.TokenData.Expire,
	}

	return storage
}

// RefreshTokensWithRetry refreshes tokens with automatic retry logic.
// This method implements exponential backoff retry logic for token refresh operations,
// providing resilience against temporary network or service issues.
//
// Parameters:
//   - ctx: The context for the request
//   - refreshToken: The refresh token to use
//   - maxRetries: The maximum number of retry attempts
//
// Returns:
//   - *ClaudeTokenData: The refreshed token data
//   - error: An error if all retry attempts fail
func (o *ClaudeAuth) RefreshTokensWithRetry(ctx context.Context, refreshToken string, maxRetries int) (*ClaudeTokenData, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		tokenData, err := o.RefreshTokens(ctx, refreshToken)
		if err == nil {
			return tokenData, nil
		}

		lastErr = err
		log.Warnf("Token refresh attempt %d failed: %v", attempt+1, err)
	}

	return nil, fmt.Errorf("token refresh failed after %d attempts: %w", maxRetries, lastErr)
}

// UpdateTokenStorage updates an existing token storage with new token data.
// This method refreshes the token storage with newly obtained access and refresh tokens,
// updating timestamps and expiration information.
//
// Parameters:
//   - storage: The existing token storage to update
//   - tokenData: The new token data to apply
func (o *ClaudeAuth) UpdateTokenStorage(storage *ClaudeTokenStorage, tokenData *ClaudeTokenData) {
	storage.AccessToken = tokenData.AccessToken
	storage.RefreshToken = tokenData.RefreshToken
	storage.LastRefresh = time.Now().Format(time.RFC3339)
	storage.Email = tokenData.Email
	storage.Expire = tokenData.Expire
}

// ExchangeSessionKeyForTokens uses a browser session key to programmatically
// complete the OAuth authorization flow and obtain OAuth tokens.
// Flow: session key → get org UUID → POST /v1/oauth/{org}/authorize → get code → exchange for tokens.
func (o *ClaudeAuth) ExchangeSessionKeyForTokens(ctx context.Context, sessionKey string) (*ClaudeAuthBundle, error) {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return nil, NewAuthenticationError(ErrInvalidSessionKey, fmt.Errorf("session key is empty"))
	}

	// Step 1: Get account info to find the org UUID
	orgUUID, err := o.getOrgUUID(ctx, sessionKey)
	if err != nil {
		return nil, err
	}

	// Step 2: Generate PKCE codes and state
	pkceCodes, err := GeneratePKCECodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE codes: %w", err)
	}

	state, err := misc.GenerateRandomState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Step 3: POST to /v1/oauth/{org}/authorize to approve and get authorization code
	code, err := o.approveOAuthAuthorization(ctx, sessionKey, orgUUID, state, pkceCodes)
	if err != nil {
		return nil, err
	}

	// Step 4: Exchange authorization code for tokens
	bundle, err := o.ExchangeCodeForTokens(ctx, code, state, pkceCodes)
	if err != nil {
		return nil, NewAuthenticationError(ErrCodeExchangeFailed, err)
	}

	return bundle, nil
}

// accountMembership holds parsed membership info including organization capabilities.
type accountMembership struct {
	Role         string
	OrgUUID      string
	OrgName      string
	Capabilities []string
}

// hasCapability checks whether the membership's organization has the given capability.
func (m *accountMembership) hasCapability(cap string) bool {
	for _, c := range m.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// fetchMemberships retrieves all organization memberships for the session key holder.
func (o *ClaudeAuth) fetchMemberships(ctx context.Context, sessionKey string) ([]accountMembership, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://claude.ai/api/account?statsig_hashing_algorithm=djb2", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create account request: %w", err)
	}
	req.Header.Set("Cookie", "sessionKey="+sessionKey)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, NewAuthenticationError(ErrInvalidSessionKey, fmt.Errorf("account request failed: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, NewAuthenticationError(ErrInvalidSessionKey, fmt.Errorf("account request returned %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read account response: %w", err)
	}

	var account struct {
		Memberships []struct {
			Role         string `json:"role"`
			Organization struct {
				UUID         string   `json:"uuid"`
				Name         string   `json:"name"`
				Capabilities []string `json:"capabilities"`
			} `json:"organization"`
		} `json:"memberships"`
	}
	if err = json.Unmarshal(body, &account); err != nil {
		return nil, fmt.Errorf("failed to parse account response: %w", err)
	}

	if len(account.Memberships) == 0 {
		return nil, NewAuthenticationError(ErrSessionKeyExchangeFailed, fmt.Errorf("no organization memberships found"))
	}

	result := make([]accountMembership, len(account.Memberships))
	for i, m := range account.Memberships {
		result[i] = accountMembership{
			Role:         m.Role,
			OrgUUID:      m.Organization.UUID,
			OrgName:      m.Organization.Name,
			Capabilities: m.Organization.Capabilities,
		}
	}
	return result, nil
}

// getOrgUUID fetches the account info using the session key and returns the best org UUID.
func (o *ClaudeAuth) getOrgUUID(ctx context.Context, sessionKey string) (string, error) {
	memberships, err := o.fetchMemberships(ctx, sessionKey)
	if err != nil {
		return "", err
	}
	return selectOrgUUID(memberships), nil
}

// selectOrgUUID picks the best organization UUID from the memberships list.
// Priority order:
//  1. Enterprise orgs (raven_enterprise) with admin-level roles
//  2. Enterprise orgs (raven_enterprise) with any role
//  3. Orgs with raven capability and admin-level roles
//  4. Any org with admin-level roles
//  5. First org as fallback
func selectOrgUUID(memberships []accountMembership) string {
	isAdminRole := func(role string) bool {
		switch role {
		case "admin", "developer", "owner", "primary_owner", "claude_code_user":
			return true
		}
		return false
	}

	// Pass 1: enterprise org with admin role
	for _, m := range memberships {
		if m.hasCapability("raven_enterprise") && isAdminRole(m.Role) {
			return m.OrgUUID
		}
	}
	// Pass 2: enterprise org with any role
	for _, m := range memberships {
		if m.hasCapability("raven_enterprise") {
			return m.OrgUUID
		}
	}
	// Pass 3: raven-capable org with admin role
	for _, m := range memberships {
		if m.hasCapability("raven") && isAdminRole(m.Role) {
			return m.OrgUUID
		}
	}
	// Pass 4: any org with admin role
	for _, m := range memberships {
		if isAdminRole(m.Role) {
			return m.OrgUUID
		}
	}
	// Pass 5: fallback to first org
	return memberships[0].OrgUUID
}

// approveOAuthAuthorization posts to the OAuth authorize endpoint to approve the authorization.
func (o *ClaudeAuth) approveOAuthAuthorization(ctx context.Context, sessionKey, orgUUID, state string, pkceCodes *PKCECodes) (string, error) {
	approveURL := fmt.Sprintf("https://claude.ai/v1/oauth/%s/authorize", orgUUID)

	reqBody := map[string]string{
		"response_type":         "code",
		"client_id":             ClientID,
		"organization_uuid":     orgUUID,
		"redirect_uri":          RedirectURI,
		"scope":                 "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload",
		"state":                 state,
		"code_challenge":        pkceCodes.CodeChallenge,
		"code_challenge_method": "S256",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorize request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, approveURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", fmt.Errorf("failed to create authorize request: %w", err)
	}
	req.Header.Set("Cookie", "sessionKey="+sessionKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", NewAuthenticationError(ErrSessionKeyExchangeFailed, fmt.Errorf("authorize request failed: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read authorize response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", NewAuthenticationError(ErrSessionKeyExchangeFailed,
			fmt.Errorf("authorize returned %d: %s", resp.StatusCode, truncateBody(body, 200)))
	}

	// Response: {"redirect_uri": "http://localhost:54545/oauth/callback?code=xxx&state=yyy"}
	var result struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return "", NewAuthenticationError(ErrSessionKeyExchangeFailed, fmt.Errorf("failed to parse authorize response: %w", err))
	}

	if result.RedirectURI == "" {
		return "", NewAuthenticationError(ErrSessionKeyExchangeFailed, fmt.Errorf("no redirect_uri in authorize response"))
	}

	parsed, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", NewAuthenticationError(ErrSessionKeyExchangeFailed, fmt.Errorf("failed to parse redirect URI: %w", err))
	}

	code := parsed.Query().Get("code")
	if code == "" {
		return "", NewAuthenticationError(ErrSessionKeyExchangeFailed, fmt.Errorf("no code in redirect URI"))
	}

	return code, nil
}

// ExchangeSessionKeyViaOAuthPage uses a browser session key to complete the OAuth
// flow by navigating the standard authorize page with the session key cookie,
// following redirects through the consent/confirmation flow until reaching the
// callback URL with the authorization code.
//
// Flow: GET authorize page (with session key cookie) → follow redirects → if consent
// page is returned (200 HTML), fall back to programmatic approval via POST API.
func (o *ClaudeAuth) ExchangeSessionKeyViaOAuthPage(ctx context.Context, sessionKey string) (*ClaudeAuthBundle, error) {
	sessionKey = strings.TrimSpace(sessionKey)
	if sessionKey == "" {
		return nil, NewAuthenticationError(ErrInvalidSessionKey, fmt.Errorf("session key is empty"))
	}

	// Step 1: Generate PKCE codes and state
	pkceCodes, err := GeneratePKCECodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE codes: %w", err)
	}

	state, err := misc.GenerateRandomState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Step 2: Build the standard OAuth authorize URL
	authURL, _, err := o.GenerateAuthURL(state, pkceCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth URL: %w", err)
	}

	// Step 3: Navigate the OAuth flow by following redirects with session key cookie.
	// If the authorize page returns a consent page (200 HTML), the redirect flow returns
	// errConsentPageReceived and we fall back to programmatic approval.
	code, err := o.navigateOAuthFlow(ctx, sessionKey, authURL)
	if err != nil && !isConsentPageError(err) {
		return nil, err
	}

	// Step 4: If redirect flow did not yield a code (consent page returned),
	// approve programmatically via POST to the OAuth authorize API.
	if code == "" {
		log.Debug("Consent page received, falling back to programmatic approval via POST API")
		orgUUID, orgErr := o.getOrgUUID(ctx, sessionKey)
		if orgErr != nil {
			return nil, orgErr
		}
		code, err = o.approveOAuthAuthorization(ctx, sessionKey, orgUUID, state, pkceCodes)
		if err != nil {
			return nil, err
		}
	}

	// Step 5: Exchange authorization code for tokens
	bundle, err := o.ExchangeCodeForTokens(ctx, code, state, pkceCodes)
	if err != nil {
		return nil, NewAuthenticationError(ErrCodeExchangeFailed, err)
	}

	return bundle, nil
}

// errConsentPage is a sentinel error indicating the authorize page returned a
// consent page (HTTP 200 HTML) instead of a redirect, so programmatic approval is needed.
var errConsentPage = fmt.Errorf("consent page received")

// isConsentPageError checks whether the error indicates a consent page was returned.
func isConsentPageError(err error) bool {
	return err != nil && err.Error() == errConsentPage.Error()
}

// navigateOAuthFlow follows the OAuth authorize page redirects with session key cookie
// until reaching the callback URL, then extracts the authorization code.
// Returns errConsentPage if the authorize endpoint returns an HTML consent page (200).
func (o *ClaudeAuth) navigateOAuthFlow(ctx context.Context, sessionKey, startURL string) (string, error) {
	noRedirectClient := &http.Client{
		Transport: o.httpClient.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	currentURL := startURL
	const maxRedirects = 15

	for i := 0; i < maxRedirects; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create request for %s: %w", currentURL, err)
		}
		// Only add session key cookie for claude.ai requests
		if strings.Contains(currentURL, "claude.ai") {
			req.Header.Set("Cookie", "sessionKey="+sessionKey)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			return "", NewAuthenticationError(ErrSessionKeyExchangeFailed, fmt.Errorf("request failed at step %d: %w", i, err))
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		log.Debugf("OAuth page flow step %d: GET %s -> status %d", i, currentURL, resp.StatusCode)

		// Handle redirect responses (3xx)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				return "", NewAuthenticationError(ErrSessionKeyExchangeFailed,
					fmt.Errorf("redirect without Location header at step %d", i))
			}

			// Resolve relative URLs
			resolved := resolveRedirectURL(currentURL, location)

			// Check if redirect target is the callback URL
			if strings.HasPrefix(resolved, RedirectURI) || strings.HasPrefix(resolved, "http://localhost") {
				parsed, parseErr := url.Parse(resolved)
				if parseErr != nil {
					return "", fmt.Errorf("failed to parse callback URL: %w", parseErr)
				}

				code := parsed.Query().Get("code")
				if code == "" {
					errParam := parsed.Query().Get("error")
					if errParam != "" {
						return "", NewAuthenticationError(ErrSessionKeyExchangeFailed,
							fmt.Errorf("OAuth error in callback: %s", errParam))
					}
					return "", NewAuthenticationError(ErrSessionKeyExchangeFailed,
						fmt.Errorf("no authorization code in callback URL"))
				}
				log.Debugf("OAuth page flow completed: obtained authorization code at step %d", i)
				return code, nil
			}

			currentURL = resolved
			continue
		}

		// HTTP 200 from the authorize endpoint means the consent page was returned (React SPA).
		// Signal the caller to fall back to programmatic approval.
		if resp.StatusCode == http.StatusOK {
			log.Debugf("OAuth authorize page returned 200 (consent page HTML, %d bytes)", len(body))
			return "", errConsentPage
		}

		// Other non-redirect responses are unexpected errors
		return "", NewAuthenticationError(ErrSessionKeyExchangeFailed,
			fmt.Errorf("unexpected response status %d at %s: %s", resp.StatusCode, currentURL, truncateBody(body, 200)))
	}

	return "", NewAuthenticationError(ErrSessionKeyExchangeFailed,
		fmt.Errorf("exceeded maximum redirects (%d)", maxRedirects))
}

// resolveRedirectURL resolves a potentially relative redirect URL against the base URL.
func resolveRedirectURL(base, location string) string {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return location
	}
	refURL, err := url.Parse(location)
	if err != nil {
		return location
	}
	return baseURL.ResolveReference(refURL).String()
}

func truncateBody(b []byte, maxLen int) string {
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "..."
}

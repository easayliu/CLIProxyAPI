// Auto-generated from Go management API handlers
// Source: internal/api/handlers/management/

// ============================================================
// Common Types
// ============================================================

export interface ApiResponse<T = unknown> {
  data: T;
  status: number;
}

export interface ErrorResponse {
  error: string;
  message?: string;
}

export interface StatusResponse {
  status: "ok" | "error";
  error?: string;
}

export interface ValueRequest<T> {
  value: T;
}

// ============================================================
// Usage Statistics
// ============================================================

export interface TokenStats {
  input_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  cached_tokens: number;
  total_tokens: number;
}

export interface RequestDetail {
  timestamp: string;
  source: string;
  auth_index: string;
  tokens: TokenStats;
  failed: boolean;
}

export interface ModelSnapshot {
  total_requests: number;
  total_tokens: number;
  details: RequestDetail[];
}

export interface APISnapshot {
  total_requests: number;
  total_tokens: number;
  models: Record<string, ModelSnapshot>;
}

export interface StatisticsSnapshot {
  total_requests: number;
  success_count: number;
  failure_count: number;
  total_tokens: number;
  apis: Record<string, APISnapshot>;
  requests_by_day: Record<string, number>;
  requests_by_hour: Record<string, number>;
  tokens_by_day: Record<string, number>;
  tokens_by_hour: Record<string, number>;
}

export interface UsageResponse {
  usage: StatisticsSnapshot;
  failed_requests: number;
  by_auth: Record<string, APISnapshot>;
}

export interface UsageExportPayload {
  version: number;
  exported_at: string;
  usage: StatisticsSnapshot;
}

export interface UsageImportPayload {
  version: number;
  usage: StatisticsSnapshot;
}

export interface UsageImportResponse {
  added: number;
  skipped: number;
  total_requests: number;
  failed_requests: number;
}

// ============================================================
// Auth Files
// ============================================================

export interface QuotaInfo {
  exceeded: boolean;
  reason: string;
  next_recover_at?: string;
  backoff_level?: number;
}

export interface LastError {
  message: string;
  code: string;
  http_status: number;
}

export interface AuthFile {
  id: string;
  auth_index: string;
  name: string;
  type: string;
  provider: string;
  label: string;
  status: string;
  status_message: string;
  disabled: boolean;
  unavailable: boolean;
  runtime_only: boolean;
  source: string;
  size: number;
  email?: string;
  account_type?: string;
  account?: string;
  created_at?: string;
  modtime?: string;
  updated_at?: string;
  last_refresh?: string;
  next_retry_after?: string;
  request_count: number;
  total_tokens: number;
  path?: string;
  id_token?: Record<string, unknown>;
  quota?: QuotaInfo;
  last_error?: LastError;
  model_states?: Record<string, Record<string, unknown>>;
}

export interface AuthFilesResponse {
  files: AuthFile[];
}

export interface AuthFileModel {
  id: string;
  display_name?: string;
  type?: string;
  owned_by?: string;
}

export interface AuthFileModelsResponse {
  models: AuthFileModel[];
}

export interface PatchAuthFileStatusRequest {
  name: string;
  disabled: boolean;
}

export interface PatchAuthFileStatusResponse {
  status: "ok";
  disabled: boolean;
}

export interface PatchAuthFileFieldsRequest {
  name: string;
  prefix?: string;
  proxy_url?: string;
  priority?: number;
}

// ============================================================
// OAuth
// ============================================================

export interface OAuthCallbackRequest {
  provider: string;
  redirect_url?: string;
  code?: string;
  state?: string;
  error?: string;
}

export interface OAuthAuthUrlResponse {
  url: string;
  state: string;
  callback_url?: string;
}

export interface AuthStatusResponse {
  status: string;
  completed?: boolean;
  error?: string;
}

export interface AnthropicSessionKeyRequest {
  session_key: string;
}

export interface AnthropicSessionKeyConsentRequest {
  session_key: string;
  consent_token: string;
}

export interface AnthropicSessionKeyBatchRequest {
  session_keys: string[];
}

export interface IFlowCookieRequest {
  cookie: string;
}

// ============================================================
// API Call
// ============================================================

export interface ApiCallRequest {
  auth_index?: string;
  authIndex?: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  url: string;
  header?: Record<string, string>;
  data?: string;
}

export interface ApiCallResponse {
  status_code: number;
  header: Record<string, string[]>;
  body: string;
}

// ============================================================
// Config Lists - API Keys
// ============================================================

export interface GeminiKey {
  "api-key": string;
  prefix?: string;
  "base-url"?: string;
  "proxy-url"?: string;
  headers?: Record<string, string>;
  "excluded-models"?: string[];
}

export interface ClaudeModel {
  name: string;
  alias?: string;
}

export interface ClaudeKey {
  "api-key": string;
  prefix?: string;
  "base-url"?: string;
  "proxy-url"?: string;
  models?: ClaudeModel[];
  headers?: Record<string, string>;
  "excluded-models"?: string[];
}

export interface CodexModel {
  name: string;
  alias?: string;
}

export interface CodexKey {
  "api-key": string;
  prefix?: string;
  "base-url"?: string;
  "proxy-url"?: string;
  models?: CodexModel[];
  headers?: Record<string, string>;
  "excluded-models"?: string[];
}

export interface OpenAICompatibilityAPIKey {
  key: string;
  prefix?: string;
}

export interface OpenAICompatibilityModel {
  name: string;
  alias?: string;
}

export interface OpenAICompatibility {
  name: string;
  prefix?: string;
  "base-url"?: string;
  "api-key-entries"?: OpenAICompatibilityAPIKey[];
  models?: OpenAICompatibilityModel[];
  headers?: Record<string, string>;
}

export interface VertexCompatModel {
  name: string;
  alias?: string;
}

export interface VertexCompatKey {
  "api-key": string;
  prefix?: string;
  "base-url"?: string;
  "proxy-url"?: string;
  headers?: Record<string, string>;
  models?: VertexCompatModel[];
  "excluded-models"?: string[];
}

export interface OAuthModelAlias {
  from: string;
  to: string;
}

export interface ListPatchByIndex<T> {
  index: number;
  value: T;
}

export interface ListPatchByMatch<T> {
  match: string;
  value: T;
}

// ============================================================
// AmpCode
// ============================================================

export interface AmpModelMapping {
  from: string;
  to: string;
}

export interface AmpUpstreamAPIKeyEntry {
  "upstream-api-key": string;
  "api-keys": string[];
}

export interface AmpCodeConfig {
  "upstream-url": string;
  "upstream-api-key": string;
  "restrict-management-to-localhost": boolean;
  "model-mappings": AmpModelMapping[];
  "force-model-mappings": boolean;
  "upstream-api-keys": AmpUpstreamAPIKeyEntry[];
}

// ============================================================
// Logs
// ============================================================

export interface LogsResponse {
  lines: string[];
  "line-count": number;
  "latest-timestamp": number;
}

export interface LogsDeleteResponse {
  success: boolean;
  message: string;
  removed: number;
}

export interface ErrorLogEntry {
  name: string;
  size: number;
  modified: number;
}

export interface ErrorLogsResponse {
  files: ErrorLogEntry[];
}

// ============================================================
// Config (full)
// ============================================================

export interface ConfigChangedResponse {
  ok: boolean;
  changed: string[];
}

export interface LatestVersionResponse {
  "latest-version": string;
}

// ============================================================
// Model Definitions
// ============================================================

export interface ModelDefinition {
  id: string;
  display_name?: string;
  type?: string;
  owned_by?: string;
}

export interface ModelDefinitionsResponse {
  channel: string;
  models: ModelDefinition[];
}

// ============================================================
// Vertex Import
// ============================================================

export interface VertexImportResponse {
  status: "ok";
  "auth-file": string;
  project_id: string;
  email: string;
  location: string;
}

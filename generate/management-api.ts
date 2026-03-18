// Auto-generated from Go management API handlers
// Source: internal/api/server.go → registerManagementRoutes()

import type {
  AmpCodeConfig,
  AmpModelMapping,
  AmpUpstreamAPIKeyEntry,
  AnthropicSessionKeyBatchRequest,
  AnthropicSessionKeyConsentRequest,
  AnthropicSessionKeyRequest,
  ApiCallRequest,
  ApiCallResponse,
  AuthFileModelsResponse,
  AuthFilesResponse,
  AuthStatusResponse,
  ClaudeKey,
  CodexKey,
  ConfigChangedResponse,
  ErrorLogsResponse,
  GeminiKey,
  IFlowCookieRequest,
  LatestVersionResponse,
  ListPatchByIndex,
  ListPatchByMatch,
  LogsDeleteResponse,
  LogsResponse,
  ModelDefinitionsResponse,
  OAuthAuthUrlResponse,
  OAuthCallbackRequest,
  OAuthModelAlias,
  OpenAICompatibility,
  PatchAuthFileFieldsRequest,
  PatchAuthFileStatusRequest,
  PatchAuthFileStatusResponse,
  StatusResponse,
  UsageExportPayload,
  UsageImportPayload,
  UsageImportResponse,
  UsageResponse,
  ValueRequest,
  VertexCompatKey,
  VertexImportResponse,
} from "./types";

// ============================================================
// HTTP Client
// ============================================================

interface RequestOptions {
  headers?: Record<string, string>;
  params?: Record<string, string>;
  responseType?: "json" | "blob" | "text";
}

const BASE_PATH = "/v0/management";

let _managementKey = "";

export function setManagementKey(key: string) {
  _managementKey = key;
}

function buildUrl(path: string, params?: Record<string, string>): string {
  const url = `${BASE_PATH}${path}`;
  if (!params) return url;
  const qs = new URLSearchParams(params).toString();
  return qs ? `${url}?${qs}` : url;
}

function defaultHeaders(): Record<string, string> {
  const h: Record<string, string> = {};
  if (_managementKey) {
    h["X-Management-Key"] = _managementKey;
  }
  return h;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  opts?: RequestOptions,
): Promise<T> {
  const url = buildUrl(path, opts?.params);
  const headers: Record<string, string> = {
    ...defaultHeaders(),
    ...opts?.headers,
  };

  const init: RequestInit = { method, headers };

  if (body !== undefined && body !== null) {
    if (body instanceof FormData) {
      init.body = body;
    } else {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
  }

  const resp = await fetch(url, init);

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }

  if (opts?.responseType === "blob") {
    return (await resp.blob()) as T;
  }
  if (opts?.responseType === "text") {
    return (await resp.text()) as T;
  }
  return (await resp.json()) as T;
}

function get<T>(path: string, opts?: RequestOptions): Promise<T> {
  return request<T>("GET", path, undefined, opts);
}

function post<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
  return request<T>("POST", path, body, opts);
}

function put<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
  return request<T>("PUT", path, body, opts);
}

function patch<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
  return request<T>("PATCH", path, body, opts);
}

function del<T>(path: string, opts?: RequestOptions): Promise<T> {
  return request<T>("DELETE", path, undefined, opts);
}

// ============================================================
// Usage Statistics
// ============================================================

export const usage = {
  get: () => get<UsageResponse>("/usage"),

  export: () => get<UsageExportPayload>("/usage/export"),

  import: (payload: UsageImportPayload) =>
    post<UsageImportResponse>("/usage/import", payload),
};

// ============================================================
// Config - Basic Settings
// ============================================================

export const config = {
  get: () => get<Record<string, unknown>>("/config"),

  getYaml: () => get<string>("/config.yaml", { responseType: "text" }),

  putYaml: (yaml: string) =>
    put<ConfigChangedResponse>("/config.yaml", yaml, {
      headers: { "Content-Type": "application/yaml" },
    }),

  getLatestVersion: () => get<LatestVersionResponse>("/latest-version"),
};

// ============================================================
// Config - Toggle Settings (GET/PUT/PATCH pattern)
// ============================================================

function createToggleSetting<T>(path: string, key: string) {
  return {
    get: () => get<Record<string, T>>(path).then((r) => r[key] as T),
    set: (value: T) => put<StatusResponse>(path, { value } as ValueRequest<T>),
  };
}

export const debug = createToggleSetting<boolean>("/debug", "debug");

export const loggingToFile = createToggleSetting<boolean>(
  "/logging-to-file",
  "logging-to-file",
);

export const logsMaxTotalSizeMB = createToggleSetting<number>(
  "/logs-max-total-size-mb",
  "logs-max-total-size-mb",
);

export const errorLogsMaxFiles = createToggleSetting<number>(
  "/error-logs-max-files",
  "error-logs-max-files",
);

export const usageStatisticsEnabled = createToggleSetting<boolean>(
  "/usage-statistics-enabled",
  "usage-statistics-enabled",
);

export const requestRetry = createToggleSetting<number>(
  "/request-retry",
  "request-retry",
);

export const maxRetryInterval = createToggleSetting<number>(
  "/max-retry-interval",
  "max-retry-interval",
);

export const forceModelPrefix = createToggleSetting<boolean>(
  "/force-model-prefix",
  "force-model-prefix",
);

export const routingStrategy = createToggleSetting<string>(
  "/routing/strategy",
  "strategy",
);

export const requestLog = createToggleSetting<boolean>(
  "/request-log",
  "request-log",
);

export const wsAuth = createToggleSetting<boolean>("/ws-auth", "ws-auth");

export const switchProject = createToggleSetting<boolean>(
  "/quota-exceeded/switch-project",
  "switch-project",
);

export const switchPreviewModel = createToggleSetting<boolean>(
  "/quota-exceeded/switch-preview-model",
  "switch-preview-model",
);

// ============================================================
// Config - Proxy URL
// ============================================================

export const proxyUrl = {
  get: () =>
    get<Record<string, string>>("/proxy-url").then((r) => r["proxy-url"]),
  set: (value: string) =>
    put<StatusResponse>("/proxy-url", { value } as ValueRequest<string>),
  delete: () => del<StatusResponse>("/proxy-url"),
};

// ============================================================
// Config Lists - API Keys
// ============================================================

export const apiKeys = {
  get: () =>
    get<Record<string, string[]>>("/api-keys").then((r) => r["api-keys"]),
  set: (keys: string[]) => put<StatusResponse>("/api-keys", keys),
  patch: (body: ListPatchByIndex<string> | ListPatchByMatch<string>) =>
    patch<StatusResponse>("/api-keys", body),
  delete: (params: { index?: string; value?: string }) =>
    del<StatusResponse>("/api-keys", { params }),
};

// ============================================================
// Config Lists - Gemini API Keys
// ============================================================

export const geminiApiKey = {
  get: () =>
    get<Record<string, GeminiKey[]>>("/gemini-api-key").then(
      (r) => r["gemini-api-key"],
    ),
  set: (keys: GeminiKey[]) => put<StatusResponse>("/gemini-api-key", keys),
  patch: (body: ListPatchByIndex<GeminiKey> | ListPatchByMatch<GeminiKey>) =>
    patch<StatusResponse>("/gemini-api-key", body),
  delete: (params: { index?: string; value?: string }) =>
    del<StatusResponse>("/gemini-api-key", { params }),
};

// ============================================================
// Config Lists - Claude API Keys
// ============================================================

export const claudeApiKey = {
  get: () =>
    get<Record<string, ClaudeKey[]>>("/claude-api-key").then(
      (r) => r["claude-api-key"],
    ),
  set: (keys: ClaudeKey[]) => put<StatusResponse>("/claude-api-key", keys),
  patch: (body: ListPatchByIndex<ClaudeKey> | ListPatchByMatch<ClaudeKey>) =>
    patch<StatusResponse>("/claude-api-key", body),
  delete: (params: { index?: string; value?: string }) =>
    del<StatusResponse>("/claude-api-key", { params }),
};

// ============================================================
// Config Lists - Codex API Keys
// ============================================================

export const codexApiKey = {
  get: () =>
    get<Record<string, CodexKey[]>>("/codex-api-key").then(
      (r) => r["codex-api-key"],
    ),
  set: (keys: CodexKey[]) => put<StatusResponse>("/codex-api-key", keys),
  patch: (body: ListPatchByIndex<CodexKey> | ListPatchByMatch<CodexKey>) =>
    patch<StatusResponse>("/codex-api-key", body),
  delete: (params: { index?: string; value?: string }) =>
    del<StatusResponse>("/codex-api-key", { params }),
};

// ============================================================
// Config Lists - OpenAI Compatibility
// ============================================================

export const openaiCompatibility = {
  get: () =>
    get<Record<string, OpenAICompatibility[]>>("/openai-compatibility").then(
      (r) => r["openai-compatibility"],
    ),
  set: (items: OpenAICompatibility[]) =>
    put<StatusResponse>("/openai-compatibility", items),
  patch: (
    body:
      | ListPatchByIndex<OpenAICompatibility>
      | ListPatchByMatch<OpenAICompatibility>,
  ) => patch<StatusResponse>("/openai-compatibility", body),
  delete: (params: { index?: string; value?: string }) =>
    del<StatusResponse>("/openai-compatibility", { params }),
};

// ============================================================
// Config Lists - Vertex Compat API Keys
// ============================================================

export const vertexApiKey = {
  get: () =>
    get<Record<string, VertexCompatKey[]>>("/vertex-api-key").then(
      (r) => r["vertex-api-key"],
    ),
  set: (keys: VertexCompatKey[]) =>
    put<StatusResponse>("/vertex-api-key", keys),
  patch: (
    body: ListPatchByIndex<VertexCompatKey> | ListPatchByMatch<VertexCompatKey>,
  ) => patch<StatusResponse>("/vertex-api-key", body),
  delete: (params: { index?: string; value?: string }) =>
    del<StatusResponse>("/vertex-api-key", { params }),
};

// ============================================================
// Config Lists - OAuth Excluded Models
// ============================================================

export const oauthExcludedModels = {
  get: () =>
    get<Record<string, Record<string, string[]>>>(
      "/oauth-excluded-models",
    ).then((r) => r["oauth-excluded-models"]),
  set: (models: Record<string, string[]>) =>
    put<StatusResponse>("/oauth-excluded-models", models),
  patch: (body: { provider: string; models: string[] }) =>
    patch<StatusResponse>("/oauth-excluded-models", body),
  delete: (params: { provider?: string }) =>
    del<StatusResponse>("/oauth-excluded-models", { params }),
};

// ============================================================
// Config Lists - OAuth Model Alias
// ============================================================

export const oauthModelAlias = {
  get: () =>
    get<Record<string, Record<string, OAuthModelAlias[]>>>(
      "/oauth-model-alias",
    ).then((r) => r["oauth-model-alias"]),
  set: (aliases: Record<string, OAuthModelAlias[]>) =>
    put<StatusResponse>("/oauth-model-alias", aliases),
  patch: (body: { provider: string; aliases: OAuthModelAlias[] }) =>
    patch<StatusResponse>("/oauth-model-alias", body),
  delete: (params: { provider?: string }) =>
    del<StatusResponse>("/oauth-model-alias", { params }),
};

// ============================================================
// Auth Files
// ============================================================

export const authFiles = {
  list: () => get<AuthFilesResponse>("/auth-files"),

  getModels: (name: string) =>
    get<AuthFileModelsResponse>("/auth-files/models", {
      params: { name },
    }),

  download: (name: string) =>
    get<Blob>("/auth-files/download", {
      params: { name },
      responseType: "blob",
    }),

  upload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return post<StatusResponse>("/auth-files", form);
  },

  uploadRaw: (name: string, data: unknown) =>
    post<StatusResponse>("/auth-files", data, { params: { name } }),

  delete: (name: string) =>
    del<StatusResponse>("/auth-files", { params: { name } }),

  deleteAll: () =>
    del<{ status: string; deleted: number }>("/auth-files", {
      params: { all: "true" },
    }),

  patchStatus: (body: PatchAuthFileStatusRequest) =>
    patch<PatchAuthFileStatusResponse>("/auth-files/status", body),

  patchFields: (body: PatchAuthFileFieldsRequest) =>
    patch<StatusResponse>("/auth-files/fields", body),
};

// ============================================================
// Model Definitions
// ============================================================

export const modelDefinitions = {
  get: (channel: string) =>
    get<ModelDefinitionsResponse>(`/model-definitions/${channel}`),
};

// ============================================================
// Vertex Import
// ============================================================

export const vertexImport = {
  import: (file: File, location?: string) => {
    const form = new FormData();
    form.append("file", file);
    if (location) form.append("location", location);
    return post<VertexImportResponse>("/vertex/import", form);
  },
};

// ============================================================
// OAuth Token Requests
// ============================================================

export const oauth = {
  anthropicAuthUrl: (params?: { is_webui?: string }) =>
    get<OAuthAuthUrlResponse>("/anthropic-auth-url", { params }),

  anthropicSessionKey: (body: AnthropicSessionKeyRequest) =>
    post<StatusResponse>("/anthropic-session-key", body),

  anthropicSessionKeyConsent: (body: AnthropicSessionKeyConsentRequest) =>
    post<StatusResponse>("/anthropic-session-key-consent", body),

  anthropicSessionKeyBatch: (body: AnthropicSessionKeyBatchRequest) =>
    post<StatusResponse>("/anthropic-session-key-batch", body),

  codexAuthUrl: (params?: { is_webui?: string }) =>
    get<OAuthAuthUrlResponse>("/codex-auth-url", { params }),

  geminiAuthUrl: (params?: { is_webui?: string }) =>
    get<OAuthAuthUrlResponse>("/gemini-cli-auth-url", { params }),

  antigravityAuthUrl: (params?: { is_webui?: string }) =>
    get<OAuthAuthUrlResponse>("/antigravity-auth-url", { params }),

  qwenAuthUrl: () => get<OAuthAuthUrlResponse>("/qwen-auth-url"),

  kimiAuthUrl: () => get<OAuthAuthUrlResponse>("/kimi-auth-url"),

  iflowAuthUrl: () => get<OAuthAuthUrlResponse>("/iflow-auth-url"),

  iflowCookie: (body: IFlowCookieRequest) =>
    post<StatusResponse>("/iflow-auth-url", body),

  callback: (body: OAuthCallbackRequest) =>
    post<StatusResponse>("/oauth-callback", body),

  getAuthStatus: (state: string) =>
    get<AuthStatusResponse>("/get-auth-status", { params: { state } }),
};

// ============================================================
// Logs
// ============================================================

export const logs = {
  get: (params?: { limit?: string; after?: string }) =>
    get<LogsResponse>("/logs", { params }),

  delete: () => del<LogsDeleteResponse>("/logs"),

  getErrorLogs: () => get<ErrorLogsResponse>("/request-error-logs"),

  downloadErrorLog: (name: string) =>
    get<Blob>(`/request-error-logs/${name}`, { responseType: "blob" }),

  getRequestLogById: (id: string) =>
    get<Blob>(`/request-log-by-id/${id}`, { responseType: "blob" }),
};

// ============================================================
// API Call
// ============================================================

export const apiCall = {
  execute: (body: ApiCallRequest) =>
    post<ApiCallResponse>("/api-call", body),
};

// ============================================================
// AmpCode
// ============================================================

export const ampCode = {
  get: () => get<AmpCodeConfig>("/ampcode"),

  upstreamUrl: {
    get: () =>
      get<Record<string, string>>("/ampcode/upstream-url").then(
        (r) => r["upstream-url"],
      ),
    set: (value: string) =>
      put<StatusResponse>(
        "/ampcode/upstream-url",
        { value } as ValueRequest<string>,
      ),
    delete: () => del<StatusResponse>("/ampcode/upstream-url"),
  },

  upstreamApiKey: {
    get: () =>
      get<Record<string, string>>("/ampcode/upstream-api-key").then(
        (r) => r["upstream-api-key"],
      ),
    set: (value: string) =>
      put<StatusResponse>(
        "/ampcode/upstream-api-key",
        { value } as ValueRequest<string>,
      ),
    delete: () => del<StatusResponse>("/ampcode/upstream-api-key"),
  },

  restrictManagementToLocalhost: {
    get: () =>
      get<Record<string, boolean>>(
        "/ampcode/restrict-management-to-localhost",
      ).then((r) => r["restrict-management-to-localhost"]),
    set: (value: boolean) =>
      put<StatusResponse>(
        "/ampcode/restrict-management-to-localhost",
        { value } as ValueRequest<boolean>,
      ),
  },

  modelMappings: {
    get: () =>
      get<Record<string, AmpModelMapping[]>>("/ampcode/model-mappings").then(
        (r) => r["model-mappings"],
      ),
    set: (value: AmpModelMapping[]) =>
      put<StatusResponse>("/ampcode/model-mappings", { value }),
    patch: (value: AmpModelMapping[]) =>
      patch<StatusResponse>("/ampcode/model-mappings", { value }),
    delete: (value: string[]) =>
      request<StatusResponse>("DELETE", "/ampcode/model-mappings", { value }),
  },

  forceModelMappings: {
    get: () =>
      get<Record<string, boolean>>("/ampcode/force-model-mappings").then(
        (r) => r["force-model-mappings"],
      ),
    set: (value: boolean) =>
      put<StatusResponse>(
        "/ampcode/force-model-mappings",
        { value } as ValueRequest<boolean>,
      ),
  },

  upstreamApiKeys: {
    get: () =>
      get<Record<string, AmpUpstreamAPIKeyEntry[]>>(
        "/ampcode/upstream-api-keys",
      ).then((r) => r["upstream-api-keys"]),
    set: (value: AmpUpstreamAPIKeyEntry[]) =>
      put<StatusResponse>("/ampcode/upstream-api-keys", { value }),
    patch: (value: AmpUpstreamAPIKeyEntry[]) =>
      patch<StatusResponse>("/ampcode/upstream-api-keys", { value }),
    delete: (value: string[]) =>
      request<StatusResponse>("DELETE", "/ampcode/upstream-api-keys", {
        value,
      }),
  },
};

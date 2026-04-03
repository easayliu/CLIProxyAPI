#!/usr/bin/env bun
// Replay a proxy capture JSON file in a loop with optional concurrency
// Usage: bun replay_request.ts <capture_file.json> [interval_seconds] [loop_count] [concurrency]
export {};

const [captureFile, intervalArg, loopCountArg, concurrencyArg] = process.argv.slice(2);

if (!captureFile) {
  console.log("Usage: bun replay_request.ts <capture_file.json> [interval_seconds] [loop_count] [concurrency]");
  console.log("  interval_seconds: seconds between rounds (default: 2)");
  console.log("  loop_count:       number of rounds, 0 = infinite (default: 0)");
  console.log("  concurrency:      parallel requests per round (default: 1)");
  process.exit(1);
}

const file = Bun.file(captureFile);
if (!(await file.exists())) {
  console.error(`Error: file not found: ${captureFile}`);
  process.exit(1);
}

const INTERVAL = parseFloat(intervalArg ?? "2");
const LOOP_COUNT = parseInt(loopCountArg ?? "0", 10);
const CONCURRENCY = parseInt(concurrencyArg ?? "1", 10);

// ── Parse capture file ───────────────────────────────────────────────────────
// Format A: { "request": { "method", "url", "headers": {...}, "body": "..." } }
// Format B: { "method", "url", "headers": [...], "body": "..." }

const capture = await file.json();

let method: string;
let url: string;
let headersRaw: Record<string, string> | { name?: string; key?: string; value: string }[];
let body: string | undefined;

if (capture.request) {
  method = capture.request.method;
  url = capture.request.url;
  headersRaw = capture.request.headers ?? {};
  body = capture.request.body ?? undefined;
} else {
  method = capture.method;
  url = capture.url;
  headersRaw = capture.headers ?? {};
  body = capture.body ?? undefined;
}

// Normalize headers to a plain Record<string, string>
const headers: Record<string, string> = {};
if (Array.isArray(headersRaw)) {
  for (const h of headersRaw) {
    const key = (h as any).name ?? (h as any).key;
    if (key) headers[key] = h.value;
  }
} else {
  Object.assign(headers, headersRaw);
}

// Normalize body to plain object (keep as object for per-request mutation)
let bodyTemplate: unknown | undefined;
if (body !== undefined && body !== null) {
  bodyTemplate = typeof body === "string" ? JSON.parse(body) : body;
}

// Header keys to randomize per request (exact match, case-insensitive lookup at parse time)
const SESSION_HEADER_KEYS = new Set(["x-claude-code-session-id", "x-session-id", "session-id"]);
const REQUEST_HEADER_KEYS = new Set(["x-client-request-id", "x-request-id", "request-id"]);

const sessionHeaderKey = Object.keys(headers).find(k => SESSION_HEADER_KEYS.has(k.toLowerCase()));
const requestHeaderKey = Object.keys(headers).find(k => REQUEST_HEADER_KEYS.has(k.toLowerCase()));


interface RequestParts {
  headers: Record<string, string>;
  body: string | undefined;
  sessionId: string | undefined;   // value set in X-Claude-Code-Session-Id (or equivalent)
  bodySessionId: string | undefined; // value set in body session_id field(s)
}

// Collect replaced session_id values while traversing
function replaceSessionIdsTracked(val: unknown, collected: string[]): unknown {
  if (typeof val === "string") {
    if (val.startsWith("{") || val.startsWith("[")) {
      try {
        const inner = JSON.parse(val);
        return JSON.stringify(replaceSessionIdsTracked(inner, collected));
      } catch { /* not JSON */ }
    }
    return val;
  }
  if (Array.isArray(val)) return val.map(v => replaceSessionIdsTracked(v, collected));
  if (val !== null && typeof val === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (k === "session_id") {
        const newId = crypto.randomUUID();
        collected.push(newId);
        out[k] = newId;
      } else {
        out[k] = replaceSessionIdsTracked(v, collected);
      }
    }
    return out;
  }
  return val;
}

function buildRequest(): RequestParts {
  const h = { ...headers };
  let sessionId: string | undefined;
  if (sessionHeaderKey) {
    sessionId = crypto.randomUUID();
    h[sessionHeaderKey] = sessionId;
  }
  if (requestHeaderKey) h[requestHeaderKey] = crypto.randomUUID();

  let body: string | undefined;
  let bodySessionId: string | undefined;
  if (bodyTemplate !== undefined) {
    const collected: string[] = [];
    body = JSON.stringify(replaceSessionIdsTracked(bodyTemplate, collected));
    bodySessionId = collected[0]; // first (usually only) session_id in body
  }

  return { headers: h, body, sessionId, bodySessionId };
}

console.log("==========================================");
console.log(`Replay: ${method} ${url}`);
console.log(`Interval: ${INTERVAL}s  Loop: ${LOOP_COUNT === 0 ? "infinite" : LOOP_COUNT}  Concurrency: ${CONCURRENCY}`);
if (sessionHeaderKey) console.log(`  randomize header : ${sessionHeaderKey}`);
if (requestHeaderKey) console.log(`  randomize header : ${requestHeaderKey}`);
if (bodyTemplate) console.log(`  randomize body   : session_id (recursive, incl. JSON-encoded strings)`);
console.log("==========================================");

async function doRequest(reqId: number): Promise<void> {
  const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19);
  try {
    const req = buildRequest();
    const resp = await fetch(url, {
      method,
      headers: req.headers,
      body: req.body,
    });
    const idInfo = [
      req.sessionId     ? `${sessionHeaderKey}=${req.sessionId}`     : "",
      req.bodySessionId ? `session_id=${req.bodySessionId}`           : "",
    ].filter(Boolean).join(" ");
    console.log(`[${timestamp}] #${reqId} → HTTP ${resp.status}${idInfo ? `  [${idInfo}]` : ""}`);
    // Drain response body to free connection
    await resp.arrayBuffer();
  } catch (err) {
    console.error(`[${timestamp}] #${reqId} → ERROR: ${(err as Error).message}`);
  }
}

// ── Loop ─────────────────────────────────────────────────────────────────────
let round = 0;
let total = 0;

while (true) {
  round++;
  const promises: Promise<void>[] = [];

  for (let i = 0; i < CONCURRENCY; i++) {
    total++;
    promises.push(doRequest(total));
  }

  await Promise.all(promises);

  if (LOOP_COUNT > 0 && round >= LOOP_COUNT) {
    console.log(`Done. Sent ${total} requests in ${round} rounds.`);
    break;
  }

  await Bun.sleep(INTERVAL * 1000);
}

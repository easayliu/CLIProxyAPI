#!/usr/bin/env bash
# Replay a proxy capture JSON file in a loop with optional concurrency
# Supports daemon mode (start/stop/status/log)
#
# Usage:
#   ./replay_request.sh start <capture_file.json> [interval] [loop_count] [concurrency]
#   ./replay_request.sh stop
#   ./replay_request.sh status
#   ./replay_request.sh log [-f]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.replay_request.pid"
LOG_FILE="$SCRIPT_DIR/.replay_request.log"

CMD="${1:-}"

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  start <capture_file.json> [interval_seconds] [loop_count] [concurrency]"
    echo "        Start daemon. interval default 2s, loop_count 0=infinite, concurrency default 1"
    echo "  stop  Stop the running daemon"
    echo "  status Show daemon status"
    echo "  log [-f] Print log (use -f to follow)"
    echo ""
    echo "Examples:"
    echo "  $0 start /tmp/captures/012_xxx.json 2 0 1"
    echo "  $0 stop"
    echo "  $0 log -f"
    exit 1
}

# ── Parse capture file ───────────────────────────────────────────────────────
# Format A: { "request": { "method", "url", "headers": {...}, "body": "..." } }
# Format B: { "method", "url", "headers": [...], "body": "..." }

parse_capture() {
    local capture_file="$1"

    if jq -e '.request' "$capture_file" &>/dev/null; then
        METHOD=$(jq -r '.request.method' "$capture_file")
        URL=$(jq -r '.request.url' "$capture_file")
        HEADERS_JSON=$(jq -c '.request.headers // {}' "$capture_file")
        BODY=$(jq -c '.request.body // empty' "$capture_file" 2>/dev/null || echo "")
    else
        METHOD=$(jq -r '.method' "$capture_file")
        URL=$(jq -r '.url' "$capture_file")
        HEADERS_JSON=$(jq -c '.headers // {}' "$capture_file")
        BODY=$(jq -c '.body // empty' "$capture_file" 2>/dev/null || echo "")
    fi

    # Build curl header args
    HEADER_ARGS=()
    while IFS=$'\t' read -r key value; do
        HEADER_ARGS+=("-H" "${key}: ${value}")
    done < <(
        if jq -e 'type == "array"' <<<"$HEADERS_JSON" &>/dev/null; then
            jq -r '.[] | "\(.name // .key)\t\(.value)"' <<<"$HEADERS_JSON"
        else
            jq -r 'to_entries[] | "\(.key)\t\(.value)"' <<<"$HEADERS_JSON"
        fi
    )
}

# Generate a random UUID (v4)
random_uuid() {
    if command -v uuidgen &>/dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# Replace X-Claude-Code-Session-Id header and session_id in body per request
build_request_ids() {
    SESSION_UUID=$(random_uuid)

    PATCHED_HEADER_ARGS=()
    for ((i = 0; i < ${#HEADER_ARGS[@]}; i++)); do
        if [[ "${HEADER_ARGS[$i]}" == "-H" ]]; then
            local hdr="${HEADER_ARGS[$((i+1))]}"
            local hdr_lower
            hdr_lower=$(echo "${hdr%%:*}" | tr '[:upper:]' '[:lower:]')
            if [[ "$hdr_lower" == "x-claude-code-session-id" ]]; then
                PATCHED_HEADER_ARGS+=("-H" "${hdr%%:*}: ${SESSION_UUID}")
            else
                PATCHED_HEADER_ARGS+=("-H" "$hdr")
            fi
            ((i++))
        else
            PATCHED_HEADER_ARGS+=("${HEADER_ARGS[$i]}")
        fi
    done

    if [[ -n "$BODY" ]]; then
        PATCHED_BODY=$(jq --arg id "$SESSION_UUID" '
          walk(
            if type == "object" and has("session_id") then .session_id = $id
            elif type == "string" and test("\"session_id\"") then
              gsub("\"session_id\":\"[^\"]*\""; "\"session_id\":\"" + $id + "\"")
            else . end
          )
        ' -c <<<"$BODY")
    else
        PATCHED_BODY=""
    fi
}

do_request() {
    local req_id="$1"
    local log="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    local resp
    resp=$(mktemp)

    build_request_ids

    local http_code
    if [[ -n "$PATCHED_BODY" ]]; then
        http_code=$(curl -s -o "$resp" -w "%{http_code}" \
            -X "$METHOD" \
            "${PATCHED_HEADER_ARGS[@]}" \
            --data-raw "$PATCHED_BODY" \
            "$URL")
    else
        http_code=$(curl -s -o "$resp" -w "%{http_code}" \
            -X "$METHOD" \
            "${PATCHED_HEADER_ARGS[@]}" \
            "$URL")
    fi

    local id_info=""
    [[ -n "$SESSION_UUID" ]]   && id_info+=" X-Claude-Code-Session-Id=${SESSION_UUID}"
    [[ -n "$PATCHED_BODY" ]]   && id_info+=" session_id=${SESSION_UUID}"

    echo "[$timestamp] #${req_id} → HTTP ${http_code}${id_info:+  [${id_info# }]}" >> "$log"
    rm -f "$resp"
}

run_loop() {
    local capture_file="$1"
    local interval="$2"
    local loop_count="$3"
    local concurrency="$4"
    local log="$5"

    parse_capture "$capture_file"

    {
        echo "=========================================="
        echo "Replay: $METHOD $URL"
        echo "Interval: ${interval}s  Loop: $([ "$loop_count" -eq 0 ] && echo infinite || echo "$loop_count")  Concurrency: ${concurrency}"
        echo "=========================================="
    } >> "$log"

    local round=0 total=0
    while true; do
        round=$((round + 1))
        local pids=()

        for ((i = 1; i <= concurrency; i++)); do
            total=$((total + 1))
            do_request "$total" "$log" &
            pids+=($!)
        done

        for pid in "${pids[@]}"; do
            wait "$pid"
        done

        if [[ "$loop_count" -gt 0 && "$round" -ge "$loop_count" ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Done. Sent $total requests in $round rounds." >> "$log"
            rm -f "$PID_FILE"
            break
        fi

        sleep "$interval"
    done
}

case "$CMD" in
start)
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Already running (pid $PID). Run '$0 stop' first."
            exit 1
        fi
        rm -f "$PID_FILE"
    fi

    CAPTURE_FILE="${2:-}"
    if [[ -z "$CAPTURE_FILE" ]]; then usage; fi
    if [[ ! -f "$CAPTURE_FILE" ]]; then
        echo "Error: file not found: $CAPTURE_FILE"
        exit 1
    fi
    if ! command -v jq &>/dev/null; then
        echo "Error: jq is required. Install with: apt-get install jq"
        exit 1
    fi

    INTERVAL="${3:-2}"
    LOOP_COUNT="${4:-0}"
    CONCURRENCY="${5:-1}"

    nohup bash -c "$(declare -f parse_capture random_uuid build_request_ids do_request run_loop)
        run_loop $(printf '%q' "$CAPTURE_FILE") $INTERVAL $LOOP_COUNT $CONCURRENCY $(printf '%q' "$LOG_FILE")" \
        >> "$LOG_FILE" 2>&1 &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$PID_FILE"
    echo "Started (pid $DAEMON_PID). Log: $LOG_FILE"
    echo "  tail -f $LOG_FILE"
    ;;

stop)
    if [[ ! -f "$PID_FILE" ]]; then
        echo "Not running."
        exit 0
    fi
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        kill -- -"$(ps -o pgid= -p "$PID" | tr -d ' ')" 2>/dev/null || kill "$PID"
        echo "Stopped (pid $PID)."
    else
        echo "Process $PID not found (already dead)."
    fi
    rm -f "$PID_FILE"
    ;;

status)
    if [[ ! -f "$PID_FILE" ]]; then
        echo "Status: stopped"
        exit 0
    fi
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Status: running (pid $PID)"
        echo "Log:    $LOG_FILE"
        echo "--- last 5 lines ---"
        tail -5 "$LOG_FILE" 2>/dev/null || true
    else
        echo "Status: dead (stale pid $PID)"
        rm -f "$PID_FILE"
    fi
    ;;

log)
    if [[ "${2:-}" == "-f" ]]; then
        tail -f "$LOG_FILE"
    else
        cat "$LOG_FILE" 2>/dev/null || echo "(no log yet)"
    fi
    ;;

*)
    usage
    ;;
esac
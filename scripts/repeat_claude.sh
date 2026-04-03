#!/usr/bin/env bash
# Send a repeated prompt to claude CLI in a loop with optional concurrency
# Supports daemon mode (start/stop/status/log)
#
# Usage:
#   ./repeat_claude.sh start <prompt> [interval] [loop_count] [concurrency]
#   ./repeat_claude.sh stop
#   ./repeat_claude.sh status
#   ./repeat_claude.sh log [-f]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.repeat_claude.pid"
LOG_FILE="$SCRIPT_DIR/.repeat_claude.log"

CMD="${1:-}"

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  start <prompt> [interval_seconds] [loop_count] [concurrency]"
    echo "        Start daemon. interval default 2s, loop_count 0=infinite, concurrency default 1"
    echo "  stop  Stop the running daemon"
    echo "  status Show daemon status"
    echo "  log [-f] Print log (use -f to follow)"
    echo ""
    echo "Examples:"
    echo "  $0 start 'hello' 1 0 3"
    echo "  $0 stop"
    echo "  $0 log -f"
    exit 1
}

do_request() {
    local req_id="$1"
    local prompt="$2"
    local log="$3"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    local exit_code=0
    claude --print "$prompt" &>/dev/null || exit_code=$?

    if [[ "$exit_code" -eq 0 ]]; then
        echo "[$timestamp] #${req_id} → OK" >> "$log"
    else
        echo "[$timestamp] #${req_id} → FAILED (exit $exit_code)" >> "$log"
    fi
}

export -f do_request

run_loop() {
    local prompt="$1"
    local interval="$2"
    local loop_count="$3"
    local concurrency="$4"
    local log="$5"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Started. prompt='$prompt' interval=${interval}s loop=${loop_count} concurrency=${concurrency}" >> "$log"

    local round=0 total=0
    while true; do
        round=$((round + 1))
        local pids=()

        for ((i = 1; i <= concurrency; i++)); do
            total=$((total + 1))
            do_request "$total" "$prompt" "$log" &
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

    PROMPT="${2:-}"
    if [[ -z "$PROMPT" ]]; then usage; fi
    INTERVAL="${3:-2}"
    LOOP_COUNT="${4:-0}"
    CONCURRENCY="${5:-1}"

    if ! command -v claude &>/dev/null; then
        echo "Error: claude CLI not found in PATH"
        exit 1
    fi

    nohup bash -c "$(declare -f do_request run_loop); run_loop $(printf '%q' "$PROMPT") $INTERVAL $LOOP_COUNT $CONCURRENCY $(printf '%q' "$LOG_FILE")" \
        >> "$LOG_FILE" 2>&1 &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$PID_FILE"
    echo "Started (pid $DAEMON_PID). Log: $LOG_FILE"
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

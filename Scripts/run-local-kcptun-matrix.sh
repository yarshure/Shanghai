#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${KCPTUN_SERVER_BIN:-/Users/apple/github/kcptun/build/server_darwin_arm64}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-6152}"
PASSWORD="${KCPTUN_PASSWORD:-Xifeng2026}"
SWIFT_TEST_FILTER="${SWIFT_TEST_FILTER:-integrationHTTPOverLocalKcptunCase}"
LOG_DIR="${ROOT_DIR}/.tmp/kcptun-matrix"
CASE_FILTER="${CASE_FILTER:-}"
PROXY_REQUEST_URL="${PROXY_REQUEST_URL:-http://example.com/}"
PROXY_REQUEST_HOST="${PROXY_REQUEST_HOST:-example.com}"
PROXY_REQUEST_METHOD="${PROXY_REQUEST_METHOD:-GET}"
EXPECT_RESPONSE_MARKER="${EXPECT_RESPONSE_MARKER:-HTTP/}"
USE_EXISTING_TARGET="${USE_EXISTING_TARGET:-1}"

mkdir -p "${LOG_DIR}"

if [[ ! -x "${SERVER_BIN}" ]]; then
  echo "kcptun server binary not found or not executable: ${SERVER_BIN}" >&2
  exit 1
fi

HTTP_PID=""
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  SERVER_PID=""

  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi
  HTTP_PID=""
}

trap cleanup EXIT

start_http_server() {
  if [[ "${USE_EXISTING_TARGET}" == "1" ]]; then
    return
  fi
  local http_log="${LOG_DIR}/http-server.log"
  python3 -u - <<'PY' >"${http_log}" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer

import os

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
PORT = int(os.environ.get("TARGET_PORT", "6152"))
BODY = b"Shanghai local kcptun test server\n"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        print("[http]", fmt % args, flush=True)

HTTPServer((HOST, PORT), Handler).serve_forever()
PY
  HTTP_PID=$!
  sleep 1
}

start_kcptun_server() {
  local name="$1"
  local port="$2"
  local smuxver="$3"
  local crypt="$4"
  local nocomp="$5"
  local datashard="${6:-0}"
  local parityshard="${7:-0}"
  local server_log="${LOG_DIR}/${name}.server.log"

  local args=(
    "${SERVER_BIN}"
    -t "${TARGET_HOST}:${TARGET_PORT}"
    -l ":${port}"
    -mode fast
    --ds "${datashard}"
    --ps "${parityshard}"
    --smuxver "${smuxver}"
    --crypt "${crypt}"
    --key "${PASSWORD}"
  )

  if [[ "${nocomp}" == "1" ]]; then
    args+=(--nocomp)
  fi

  "${args[@]}" >"${server_log}" 2>&1 &
  SERVER_PID=$!
  sleep 1
}

run_case() {
  local name="$1"
  local port="$2"
  local smuxver="$3"
  local crypt="$4"
  local nocomp="$5"
  local datashard="${6:-0}"
  local parityshard="${7:-0}"
  local test_log="${LOG_DIR}/${name}.test.log"

  echo
  echo "==> ${name} port=${port} smux=${smuxver} crypt=${crypt} nocomp=${nocomp} ds=${datashard} ps=${parityshard}"

  start_kcptun_server "${name}" "${port}" "${smuxver}" "${crypt}" "${nocomp}" "${datashard}" "${parityshard}"

  (
    cd "${ROOT_DIR}"
    TARGET_HOST="${TARGET_HOST}" \
    TARGET_PORT="${TARGET_PORT}" \
    SHANGHAI_RUN_LOCAL_KCPTUN_CASE=1 \
    SHANGHAI_KCPTUN_CASE_NAME="${name}" \
    SHANGHAI_KCPTUN_HOST="${TARGET_HOST}" \
    SHANGHAI_KCPTUN_PORT="${port}" \
    SHANGHAI_KCPTUN_SMUXVER="${smuxver}" \
    SHANGHAI_KCPTUN_CRYPT="${crypt}" \
    SHANGHAI_KCPTUN_NOCOMP="${nocomp}" \
    SHANGHAI_KCPTUN_DATASHARD="${datashard}" \
    SHANGHAI_KCPTUN_PARITYSHARD="${parityshard}" \
    SHANGHAI_KCPTUN_PASSWORD="${PASSWORD}" \
    SHANGHAI_TARGET_HOST="${TARGET_HOST}" \
    SHANGHAI_TARGET_PORT="${TARGET_PORT}" \
    SHANGHAI_PROXY_REQUEST_METHOD="${PROXY_REQUEST_METHOD}" \
    SHANGHAI_PROXY_REQUEST_URL="${PROXY_REQUEST_URL}" \
    SHANGHAI_PROXY_REQUEST_HOST="${PROXY_REQUEST_HOST}" \
    SHANGHAI_EXPECT_RESPONSE_MARKER="${EXPECT_RESPONSE_MARKER}" \
    swift test --filter "${SWIFT_TEST_FILTER}"
  ) >"${test_log}" 2>&1
}

start_http_server

CASES=(
  # name|port|smuxver|crypt|nocomp|datashard|parityshard
  "v2-none-nocomp|63201|2|none|1|0|0"
  "v2-none-comp|63202|2|none|0|0|0"
  "v2-aes-nocomp|63203|2|aes|1|0|0"
  "v2-aes-comp|63204|2|aes|0|0|0"
  "v1-none-nocomp|63211|1|none|1|0|0"
  "v1-none-comp|63212|1|none|0|0|0"
  "v1-aes-nocomp|63213|1|aes|1|0|0"
  "v1-aes-comp|63214|1|aes|0|0|0"
  # FEC-enabled cases — exercise the kcptun-go default 10+3 RS
  # group on both v1 and v2 with default crypt + compression off.
  # These cases verify the wire-compatibility of Shanghai's
  # KcpFECEncoder/Decoder with klauspost/reedsolomon at the server.
  "v2-aes-fec103|63221|2|aes|1|10|3"
  "v1-aes-fec103|63231|1|aes|1|10|3"
)

FAILED=()

for item in "${CASES[@]}"; do
  IFS='|' read -r name port smuxver crypt nocomp datashard parityshard <<<"${item}"

  if [[ -n "${CASE_FILTER}" && "${name}" != "${CASE_FILTER}" ]]; then
    continue
  fi

  if run_case "${name}" "${port}" "${smuxver}" "${crypt}" "${nocomp}" "${datashard}" "${parityshard}"; then
    echo "PASS ${name}"
  else
    echo "FAIL ${name}"
    FAILED+=("${name}")
  fi

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  SERVER_PID=""
done

echo
echo "Logs: ${LOG_DIR}"

if [[ "${#FAILED[@]}" -gt 0 ]]; then
  echo "Failed cases:"
  for item in "${FAILED[@]}"; do
    echo "  - ${item}"
  done
  exit 1
fi

echo "All cases passed."

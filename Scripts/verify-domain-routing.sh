#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${KCPTUN_SERVER_BIN:-/Users/apple/github/kcptun/build/server_darwin_arm64}"
PROXY_PORT="${PROXY_PORT:-13059}"
SERVER_PORT="${SERVER_PORT:-63201}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-6152}"
PASSWORD="${KCPTUN_PASSWORD:-Xifeng2026}"
SMUXVER="${SMUXVER:-2}"

TMP_DIR="${ROOT_DIR}/.tmp/domain-routing"
SERVER_LOG="${TMP_DIR}/server.log"
PROXY_LOG="${TMP_DIR}/proxy.log"
mkdir -p "${TMP_DIR}"
rm -f "${SERVER_LOG}" "${PROXY_LOG}"

cleanup() {
  [[ -n "${PROXY_PID:-}" ]] && kill "${PROXY_PID}" >/dev/null 2>&1 || true
  [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

kill_listener_on_port() {
  local proto="$1"
  local port="$2"
  local pids
  pids="$(lsof -ti "${proto}:${port}" 2>/dev/null || true)"
  if [[ -n "${pids}" ]]; then
    kill ${pids} >/dev/null 2>&1 || true
    sleep 1
  fi
}

kill_listener_on_port tcp "${PROXY_PORT}"
kill_listener_on_port udp "${SERVER_PORT}"

echo "Starting kcptun server on udp:${SERVER_PORT}"
"${SERVER_BIN}" \
  -t "${TARGET_HOST}:${TARGET_PORT}" \
  -l ":${SERVER_PORT}" \
  -mode fast \
  --smuxver "${SMUXVER}" \
  --crypt none \
  --nocomp \
  --key "${PASSWORD}" \
  >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

sleep 1

echo "Starting ShanghaiProxy on tcp:${PROXY_PORT}"
(
  cd "${ROOT_DIR}"
  SHANGHAI_KCPTUN_HOST=127.0.0.1 \
  SHANGHAI_KCPTUN_PORT="${SERVER_PORT}" \
  SHANGHAI_LOCAL_PROXY_PORT="${PROXY_PORT}" \
  SHANGHAI_KCPTUN_PASSWORD="${PASSWORD}" \
  SHANGHAI_KCPTUN_SMUXVER="${SMUXVER}" \
  SHANGHAI_KCPTUN_CRYPT=none \
  SHANGHAI_KCPTUN_NOCOMP=1 \
  SHANGHAI_PROXY_ROUTE_TABLE="proxy1|www.x.com|127.0.0.1|${SERVER_PORT}|${SMUXVER}|none|1|${PASSWORD};proxy2|ifconfig.co|127.0.0.1|${SERVER_PORT}|${SMUXVER}|none|1|${PASSWORD};proxy3|www.google.com|127.0.0.1|${SERVER_PORT}|${SMUXVER}|none|1|${PASSWORD}" \
  SHANGHAI_LOG_LEVEL=info \
  swift run ShanghaiProxy
) >"${PROXY_LOG}" 2>&1 &
PROXY_PID=$!

sleep 3

echo "HTTP route: www.x.com"
curl -L --max-time 20 -I -x "http://127.0.0.1:${PROXY_PORT}" "http://www.x.com" >/dev/null

echo "HTTPS route: ifconfig.co"
curl -L --max-time 20 -I -x "http://127.0.0.1:${PROXY_PORT}" "https://ifconfig.co" >/dev/null

echo "HTTP route: www.google.com"
curl -L --max-time 20 -I -x "http://127.0.0.1:${PROXY_PORT}" "http://www.google.com" >/dev/null

sleep 1

echo "Recent runtime log:"
tail -n 20 "${PROXY_LOG}"

if ! grep -q "route=proxy1" "${PROXY_LOG}"; then
  echo "Missing proxy1 route hit" >&2
  exit 1
fi
if ! grep -q "route=proxy2" "${PROXY_LOG}"; then
  echo "Missing proxy2 route hit" >&2
  exit 1
fi
if ! grep -q "route=proxy3" "${PROXY_LOG}"; then
  echo "Missing proxy3 route hit" >&2
  exit 1
fi
if ! grep -q "active=0" "${PROXY_LOG}"; then
  echo "Runtime registry did not return to zero" >&2
  exit 1
fi

echo "Domain routing verification passed."

#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${ROOT_DIR}/.tmp/large-file-verify-swift"
SERVER_BIN="${KCPTUN_SERVER_BIN:-/Users/apple/github/kcptun/build/server_darwin_arm64}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-6152}"
SERVER_PORT="${SERVER_PORT:-63201}"
PROXY_PORT="${PROXY_PORT:-13059}"
PASSWORD="${KCPTUN_PASSWORD:-Xifeng2026}"
SMUXVER="${SMUXVER:-2}"
DOWNLOAD_URL="${DOWNLOAD_URL:-https://repo.unilake.net/unilake/ubuntu/noble/lake-agent.26.03.22868.deb}"
EXPECTED_MD5="${EXPECTED_MD5:-29347fd3017ef3b5bfc00ac8a777ff72}"
OUTPUT_FILE="${OUTPUT_FILE:-${TMP_DIR}/lake-agent.26.03.22868.deb}"
SERVER_LOG="${TMP_DIR}/server.log"
PROXY_LOG="${TMP_DIR}/proxy.log"

mkdir -p "${TMP_DIR}"

if [[ ! -x "${SERVER_BIN}" ]]; then
  echo "kcptun server binary not found or not executable: ${SERVER_BIN}" >&2
  exit 1
fi

SERVER_PID=""
PROXY_PID=""

cleanup() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  PROXY_PID=""

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  SERVER_PID=""
}

trap cleanup EXIT

wait_for_tcp_listen() {
  local port="$1"
  for _ in $(seq 1 80); do
    if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_udp_listen() {
  local port="$1"
  for _ in $(seq 1 40); do
    if lsof -nP -iUDP:"${port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

compute_md5() {
  local file="$1"
  if command -v md5 >/dev/null 2>&1; then
    md5 -q "${file}"
  else
    md5sum "${file}" | awk '{print $1}'
  fi
}

echo "Starting kcptun server on udp:${SERVER_PORT}"
"${SERVER_BIN}" \
  -t "${TARGET_HOST}:${TARGET_PORT}" \
  -l ":${SERVER_PORT}" \
  -mode fast \
  --nocomp \
  --crypt none \
  --key "${PASSWORD}" \
  --smuxver "${SMUXVER}" \
  --ds 0 \
  --ps 0 >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

wait_for_udp_listen "${SERVER_PORT}" || {
  echo "kcptun server failed to listen on udp:${SERVER_PORT}" >&2
  tail -n 60 "${SERVER_LOG}" >&2 || true
  exit 1
}

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
  swift run ShanghaiProxy
) >"${PROXY_LOG}" 2>&1 &
PROXY_PID=$!

wait_for_tcp_listen "${PROXY_PORT}" || {
  echo "ShanghaiProxy failed to listen on tcp:${PROXY_PORT}" >&2
  tail -n 80 "${PROXY_LOG}" >&2 || true
  exit 1
}

rm -f "${OUTPUT_FILE}"

echo "Downloading file through proxy http://127.0.0.1:${PROXY_PORT}"
curl -fL --proxy "http://127.0.0.1:${PROXY_PORT}" -o "${OUTPUT_FILE}" "${DOWNLOAD_URL}"

ACTUAL_MD5="$(compute_md5 "${OUTPUT_FILE}")"
FILE_SIZE="$(wc -c <"${OUTPUT_FILE}" | tr -d ' ')"

echo "Downloaded: ${OUTPUT_FILE}"
echo "Size: ${FILE_SIZE} bytes"
echo "MD5:  ${ACTUAL_MD5}"
echo "Want: ${EXPECTED_MD5}"

if [[ "${ACTUAL_MD5}" != "${EXPECTED_MD5}" ]]; then
  echo "MD5 mismatch" >&2
  exit 1
fi

echo "MD5 verified successfully."

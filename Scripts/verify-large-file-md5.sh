#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${ROOT_DIR}/.tmp/large-file-verify"
SERVER_BIN="${KCPTUN_SERVER_BIN:-/Users/apple/github/kcptun/build/server_darwin_arm64}"
CLIENT_BIN="${KCPTUN_CLIENT_BIN:-/Users/apple/github/kcptun/client_darwin_arm64}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-6152}"
SERVER_PORT="${SERVER_PORT:-63231}"
CLIENT_PORT="${CLIENT_PORT:-12959}"
PASSWORD="${KCPTUN_PASSWORD:-Xifeng2026}"
SMUXVER="${SMUXVER:-2}"
DOWNLOAD_URL="${DOWNLOAD_URL:-https://repo.unilake.net/unilake/ubuntu/noble/lake-agent.26.03.22868.deb}"
EXPECTED_MD5="${EXPECTED_MD5:-29347fd3017ef3b5bfc00ac8a777ff72}"
OUTPUT_FILE="${OUTPUT_FILE:-${TMP_DIR}/lake-agent.26.03.22868.deb}"
SERVER_LOG="${TMP_DIR}/server.log"
CLIENT_LOG="${TMP_DIR}/client.log"

mkdir -p "${TMP_DIR}"

if [[ ! -x "${SERVER_BIN}" ]]; then
  echo "kcptun server binary not found or not executable: ${SERVER_BIN}" >&2
  exit 1
fi

if [[ ! -x "${CLIENT_BIN}" ]]; then
  echo "kcptun client binary not found or not executable: ${CLIENT_BIN}" >&2
  exit 1
fi

SERVER_PID=""
CLIENT_PID=""

cleanup() {
  if [[ -n "${CLIENT_PID}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  CLIENT_PID=""

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  SERVER_PID=""
}

trap cleanup EXIT

wait_for_listen() {
  local proto="$1"
  local port="$2"

  for _ in $(seq 1 50); do
    if [[ "${proto}" == "tcp" ]]; then
      if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
        return 0
      fi
    else
      if lsof -nP -iUDP:"${port}" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.2
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

wait_for_listen udp "${SERVER_PORT}" || {
  echo "kcptun server failed to listen on udp:${SERVER_PORT}" >&2
  tail -n 60 "${SERVER_LOG}" >&2 || true
  exit 1
}

echo "Starting kcptun client on tcp:${CLIENT_PORT}"
"${CLIENT_BIN}" \
  -r "127.0.0.1:${SERVER_PORT}" \
  -l ":${CLIENT_PORT}" \
  -mode fast \
  --nocomp \
  --crypt none \
  --key "${PASSWORD}" \
  --smuxver "${SMUXVER}" \
  --ds 0 \
  --ps 0 >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

wait_for_listen tcp "${CLIENT_PORT}" || {
  echo "kcptun client failed to listen on tcp:${CLIENT_PORT}" >&2
  tail -n 60 "${CLIENT_LOG}" >&2 || true
  exit 1
}

rm -f "${OUTPUT_FILE}"

echo "Downloading file through proxy http://127.0.0.1:${CLIENT_PORT}"
curl -fL --proxy "http://127.0.0.1:${CLIENT_PORT}" -o "${OUTPUT_FILE}" "${DOWNLOAD_URL}"

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

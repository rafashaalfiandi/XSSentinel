#!/usr/bin/env bash
set -euo pipefail

APP_NAME="xssentinel"
INSTALL_DIR="${HOME}/.local/share/${APP_NAME}"
BIN_PATH="${HOME}/.local/bin/${APP_NAME}"

rm -f "${BIN_PATH}"
rm -rf "${INSTALL_DIR}"

echo "Uninstalled ${APP_NAME}"

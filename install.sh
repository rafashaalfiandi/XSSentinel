#!/usr/bin/env bash
set -euo pipefail

APP_NAME="xssentinel"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/share/${APP_NAME}"
BIN_DIR="${HOME}/.local/bin"
BIN_PATH="${BIN_DIR}/${APP_NAME}"

mkdir -p "${INSTALL_DIR}" "${BIN_DIR}"
rm -f "${INSTALL_DIR}/xss_fuzz_scanner.py"

cp -f "${SOURCE_DIR}/main.py" "${INSTALL_DIR}/main.py"
cp -f "${SOURCE_DIR}/xss-payloads.txt" "${INSTALL_DIR}/xss-payloads.txt"
cp -f "${SOURCE_DIR}/smart-selected-180-payloads.txt" "${INSTALL_DIR}/smart-selected-180-payloads.txt"
cp -f "${SOURCE_DIR}/useragents.txt" "${INSTALL_DIR}/useragents.txt"
printf '%s\n' "${SOURCE_DIR}" > "${INSTALL_DIR}/.source-dir"
if [[ -d "${SOURCE_DIR}/xssentinel_core" ]]; then
  rm -rf "${INSTALL_DIR}/xssentinel_core"
  cp -a "${SOURCE_DIR}/xssentinel_core" "${INSTALL_DIR}/xssentinel_core"
fi
chmod +x "${INSTALL_DIR}/main.py"

rm -f "${BIN_PATH}"
cat > "${BIN_PATH}" <<EOF
#!/usr/bin/env bash
exec -a "${APP_NAME}" "${INSTALL_DIR}/main.py" "\$@"
EOF
chmod +x "${BIN_PATH}"

echo "Installed ${APP_NAME} -> ${BIN_PATH}"
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo "Add this to your shell config: export PATH=\"${BIN_DIR}:\$PATH\""
fi
echo "Run: ${APP_NAME}"

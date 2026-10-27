#!/usr/bin/env bash
# CertPilot 卸载脚本（独立可用，不依赖 install.sh）
#
#   sudo ./uninstall.sh           卸载，保留 /etc/certpilot
#   sudo ./uninstall.sh --purge   卸载并删除数据（证书不可恢复）
set -euo pipefail

DATA_DIR="${CERTPILOT_DATA:-/etc/certpilot}"
BIN_PATH="/usr/local/bin/certpilot"
UNIT_PATH="/etc/systemd/system/certpilot.service"
SERVICE="certpilot"

[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo $0" >&2; exit 1; }

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

echo "停止并移除 CertPilot 服务..."
systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
rm -f "$UNIT_PATH"
systemctl daemon-reload
rm -f "$BIN_PATH"

if [ "$PURGE" = "1" ]; then
  rm -rf "$DATA_DIR"
  echo "已删除数据目录 $DATA_DIR"
else
  echo "已卸载。数据目录保留在 $DATA_DIR（如需彻底删除：sudo $0 --purge）"
fi

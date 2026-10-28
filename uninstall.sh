#!/usr/bin/env bash
# CertPilot 卸载脚本（独立可用，不依赖 install.sh）
#
#   sudo ./uninstall.sh           卸载，保留 /etc/certpilot
#   sudo ./uninstall.sh --purge   卸载并删除数据（证书不可恢复）
#
# 必须清理全部四个单元：按需模式（默认）下服务由 socket 激活、续期由 timer 驱动，
# 只删 certpilot.service 会留下 socket 继续监听端口、timer 继续每天唤醒进程。
set -euo pipefail

DATA_DIR="${CERTPILOT_DATA:-/etc/certpilot}"
BIN_PATH="/usr/local/bin/certpilot"
UNIT_DIR="/etc/systemd/system"
SERVICE="certpilot"
UNITS=("certpilot.service" "certpilot.socket" "certpilot-renew.service" "certpilot-renew.timer")

[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo $0" >&2; exit 1; }

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

echo "停止并移除 CertPilot 服务..."
# 先停 timer，再停 socket（BindsTo 会连带停掉 service），最后兜底停一次 service
systemctl disable --now certpilot-renew.timer >/dev/null 2>&1 || true
systemctl stop certpilot-renew.service >/dev/null 2>&1 || true
systemctl disable --now certpilot.socket >/dev/null 2>&1 || true
systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true

for u in "${UNITS[@]}"; do
  rm -f "$UNIT_DIR/$u"
done
systemctl daemon-reload
rm -f "$BIN_PATH"
echo "已停止服务并移除程序与 systemd 单元"

# 自检：确认没有残留，避免"看起来卸了其实还在"
leftover=0
for u in "${UNITS[@]}"; do
  if systemctl list-unit-files "$u" --no-legend 2>/dev/null | grep -q "^$u"; then
    echo "警告：单元 $u 仍然存在" >&2
    leftover=1
  fi
done
if pgrep -x certpilot >/dev/null 2>&1; then
  echo "警告：certpilot 进程仍在运行（pid: $(pgrep -x certpilot | tr '\n' ' ')）" >&2
  leftover=1
fi
if [ -x "$BIN_PATH" ]; then
  echo "警告：$BIN_PATH 仍然存在" >&2
  leftover=1
fi

if [ "$PURGE" = "1" ]; then
  rm -rf "$DATA_DIR"
  echo "已删除数据目录 $DATA_DIR"
else
  echo "已卸载。数据目录保留在 $DATA_DIR（如需彻底删除：sudo $0 --purge）"
fi

if [ "$leftover" = "0" ]; then
  echo "自检通过：无残留单元、进程或二进制"
fi

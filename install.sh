#!/usr/bin/env bash
# CertPilot 安装 / 升级 / 卸载脚本
#
# 在线安装：
#   curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | sudo bash
#
# 离线安装（把本脚本和 certpilot 二进制放同一目录）：
#   sudo ./install.sh
#
# 卸载（保留数据）：
#   sudo ./install.sh --uninstall
# 彻底卸载（连证书和配置一起删）：
#   sudo ./install.sh --purge
set -euo pipefail

# ---------------- 可覆盖的默认值 ----------------
REPO="${CERTPILOT_REPO:-__REPO_SLUG__}"      # CI 会替换成 owner/repo
VERSION="${CERTPILOT_VERSION:-latest}"
PORT="${CERTPILOT_PORT:-9443}"
DATA_DIR="${CERTPILOT_DATA:-/etc/certpilot}"
BIN_PATH="/usr/local/bin/certpilot"
UNIT_PATH="/etc/systemd/system/certpilot.service"
SERVICE="certpilot"
ADMIN_PASSWORD=""
ACME_EMAIL=""
TLS_CERT=""
TLS_KEY=""
NO_START=0
MODE=""            # ondemand | always；留空则升级时沿用原模式，新装默认 ondemand
IDLE_TIMEOUT="10m"

ACTION="install"

# ---------------- 输出helpers ----------------
if [ -t 1 ]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; DIM=""; BOLD=""; NC=""
fi
ok()   { printf '%s\n' "${GREEN}✔${NC} $*"; }
warn() { printf '%s\n' "${YELLOW}!${NC} $*"; }
die()  { printf '%s\n' "${RED}✘${NC} $*" >&2; exit 1; }
step() { printf '\n%s\n' "${BOLD}$*${NC}"; }

usage() {
  cat <<EOF
CertPilot 安装脚本

用法:
  ./install.sh [选项]

选项:
  --port N           面板端口（默认 9443）
  --data DIR         数据目录（默认 /etc/certpilot）
  --password PASS    安装完成后自动设置管理员密码
  --email ADDR       预设 ACME 联系邮箱
  --tls-cert PATH    面板证书路径（可选，多个用逗号分隔）
  --tls-key PATH     面板私钥路径（与证书一一对应）
  --version VER      安装指定版本（默认 latest）
  --repo OWNER/REPO  GitHub 仓库（离线安装时忽略）
  --mode MODE        ondemand（按需启动，默认）或 always（常驻）
  --idle DURATION    按需模式下空闲多久退出，默认 10m
  --no-start         只安装，不启动服务
  --uninstall        卸载，保留 ${DATA_DIR}
  --purge            卸载并删除 ${DATA_DIR}（证书将不可恢复）
  -h, --help         显示帮助

示例:
  curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | sudo bash
  sudo ./install.sh --port 8080 --password 'MyPass123'
EOF
}

# ---------------- 参数解析 ----------------
while [ $# -gt 0 ]; do
  case "$1" in
    --port)     PORT="${2:?}"; shift 2 ;;
    --data)     DATA_DIR="${2:?}"; shift 2 ;;
    --password) ADMIN_PASSWORD="${2:?}"; shift 2 ;;
    --email)    ACME_EMAIL="${2:?}"; shift 2 ;;
    --tls-cert) TLS_CERT="${2:?}"; shift 2 ;;
    --tls-key)  TLS_KEY="${2:?}"; shift 2 ;;
    --version)  VERSION="${2:?}"; shift 2 ;;
    --repo)     REPO="${2:?}"; shift 2 ;;
    --mode)     MODE="${2:?}"; shift 2 ;;
    --idle)     IDLE_TIMEOUT="${2:?}"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    --purge)     ACTION="purge"; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) die "未知参数: $1（用 --help 查看用法）" ;;
  esac
done

# ---------------- 基础检查 ----------------
[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo $0"

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if ! command -v systemctl >/dev/null 2>&1; then
  die "未检测到 systemd。本脚本仅支持 systemd 发行版（Debian/Ubuntu/CentOS/Alpine 需 OpenRC 请手动部署）"
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "不支持的架构: $(uname -m)（目前提供 amd64 / arm64）" ;;
esac

# ---------------- 卸载 ----------------
stop_service() {
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
}

do_uninstall() {
  local purge="$1"
  step "卸载 CertPilot"
  systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
  systemctl disable --now certpilot.socket >/dev/null 2>&1 || true
  systemctl disable --now certpilot-renew.timer >/dev/null 2>&1 || true
  systemctl stop certpilot-renew.service >/dev/null 2>&1 || true
  rm -f "$UNIT_PATH" /etc/systemd/system/certpilot.socket \
        /etc/systemd/system/certpilot-renew.service \
        /etc/systemd/system/certpilot-renew.timer
  systemctl daemon-reload
  rm -f "$BIN_PATH"
  ok "已停止服务并移除程序与 systemd 单元"

  if [ "$purge" = "1" ]; then
    rm -rf "$DATA_DIR"
    ok "已删除数据目录 $DATA_DIR"
  else
    ok "数据目录已保留：$DATA_DIR"
    printf '%s\n' "${DIM}  如需彻底删除：sudo $0 --purge${NC}"
  fi
}

if [ "$ACTION" = "uninstall" ] || [ "$ACTION" = "purge" ]; then
  do_uninstall "$([ "$ACTION" = "purge" ] && echo 1 || echo 0)"
  exit 0
fi

# ---------------- 获取二进制 ----------------
fetch_binary() {
  local tmpdir="$1"

  # 1) 本地同目录已有二进制（离线安装）
  for cand in "$SCRIPT_DIR/certpilot" "$SCRIPT_DIR/certpilot-linux-$ARCH"; do
    if [ -n "$SCRIPT_DIR" ] && [ -f "$cand" ]; then
      ok "使用本地二进制: $cand"
      install -m 0755 "$cand" "$tmpdir/certpilot"
      return 0
    fi
  done

  # 2) 从 GitHub Release 下载
  # 用"是否包含斜杠"来判断，避免哨兵字符串被 CI 替换后把判断逻辑改坏
  case "$REPO" in
    */*) : ;;
    *) die "尚未配置仓库地址。请用 --repo owner/repo 指定，或把二进制放在脚本同目录离线安装" ;;
  esac

  local base url
  if [ "$VERSION" = "latest" ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION"
  fi
  url="$base/certpilot-linux-$ARCH.tar.gz"

  step "下载 $VERSION ($ARCH)"
  printf '%s\n' "${DIM}  $url${NC}"

  local dl=""
  if command -v curl >/dev/null 2>&1; then
    dl="curl -fsSL --retry 3 --connect-timeout 15 -o"
  elif command -v wget >/dev/null 2>&1; then
    dl="wget -q -T 30 -O"
  else
    die "缺少 curl 或 wget，无法下载"
  fi

  if ! $dl "$tmpdir/pkg.tar.gz" "$url"; then
    die "下载失败。请检查网络，或用离线方式：把 certpilot 二进制放到脚本同目录再执行"
  fi

  tar -xzf "$tmpdir/pkg.tar.gz" -C "$tmpdir" || die "解压失败，包可能损坏"
  [ -f "$tmpdir/certpilot" ] || die "压缩包内未找到 certpilot"
  chmod +x "$tmpdir/certpilot"
  ok "下载完成"
}

# ---------------- 安装 ----------------
TMPDIR_INSTALL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_INSTALL"' EXIT

step "CertPilot 安装程序"
printf '%s\n' "  系统    : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s)"
printf '%s\n' "  架构    : $ARCH"
printf '%s\n' "  端口    : $PORT"
printf '%s\n' "  数据目录: $DATA_DIR"

fetch_binary "$TMPDIR_INSTALL"

step "安装文件"
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
  warn "检测到已安装，执行升级"
  stop_service
fi
install -m 0755 "$TMPDIR_INSTALL/certpilot" "$BIN_PATH"
mkdir -p "$DATA_DIR"
chmod 0750 "$DATA_DIR"
ok "二进制: $BIN_PATH"
ok "数据目录: $DATA_DIR"

# ---------------- systemd ----------------
step "配置 systemd 服务"

EXTRA_ARGS=""
if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
  EXTRA_ARGS=" -tls-cert $TLS_CERT -tls-key $TLS_KEY"
fi

# 没指定 --mode 时：已装按需模式就沿用，否则新装默认按需
if [ -z "$MODE" ]; then
  if [ -f /etc/systemd/system/certpilot.socket ]; then
    MODE="ondemand"
  elif [ -f "$UNIT_PATH" ]; then
    MODE="always"
  else
    MODE="ondemand"
  fi
fi

case "$MODE" in
  ondemand|always) ;;
  *) die "--mode 只能是 ondemand 或 always" ;;
esac

if [ "$MODE" = "ondemand" ]; then
  # 先停掉可能存在的常驻服务，避免它继续占用端口
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  systemctl disable "$SERVICE" >/dev/null 2>&1 || true

  cat > /etc/systemd/system/certpilot.socket <<EOF
[Unit]
Description=CertPilot socket (on-demand activation)

[Socket]
ListenStream=$PORT
Accept=no
NoDelay=true
Backlog=128

[Install]
WantedBy=sockets.target
EOF

  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=CertPilot certificate manager (on-demand)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 证书管理需要绑定 80/443、写入 /root/cert、执行 x-ui restart，因此以 root 运行
User=root
ExecStart=$BIN_PATH serve -data $DATA_DIR -listen :$PORT -idle-timeout $IDLE_TIMEOUT -scheduler=false$EXTRA_ARGS
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535
PrivateTmp=true
# 空闲正常退出后不要被反复拉起，等下一个连接由 socket 唤醒
RestartPreventExitStatus=0

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/certpilot-renew.service <<EOF
[Unit]
Description=CertPilot renewal check
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=$BIN_PATH renew -data $DATA_DIR
EOF

  cat > /etc/systemd/system/certpilot-renew.timer <<EOF
[Unit]
Description=CertPilot renewal timer

[Timer]
OnCalendar=*-*-* 00,06,12,18:17:00
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now certpilot.socket >/dev/null 2>&1
  systemctl enable --now certpilot-renew.timer >/dev/null 2>&1
  ok "按需模式：socket 已监听 $PORT，空闲 ${IDLE_TIMEOUT} 后自动退出"
  ok "续期定时器已启用（每天 4 次，进程只运行几秒）"
else
  # 常驻模式：清掉按需模式的单元，避免端口被 socket 占用
  systemctl disable --now certpilot.socket >/dev/null 2>&1 || true
  systemctl disable --now certpilot-renew.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/certpilot.socket \
        /etc/systemd/system/certpilot-renew.service \
        /etc/systemd/system/certpilot-renew.timer

  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=CertPilot certificate manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 证书管理需要绑定 80/443、写入 /root/cert、执行 x-ui restart，因此以 root 运行
User=root
ExecStart=$BIN_PATH serve -data $DATA_DIR -listen :$PORT$EXTRA_ARGS
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1
  ok "常驻模式：服务已注册并设为开机自启"
fi

if [ "$NO_START" = "1" ]; then
  warn "--no-start 已指定，跳过启动"
elif [ "$MODE" = "always" ]; then
  systemctl restart "$SERVICE"
  sleep 2
  systemctl is-active --quiet "$SERVICE" || {
    printf '%s\n' "${RED}服务启动失败，最近日志：${NC}"
    journalctl -u "$SERVICE" -n 20 --no-pager || true
    exit 1
  }
  ok "服务已启动"
else
  # 按需模式不主动常驻，交给 socket 在首次访问时拉起
  sleep 1
  systemctl is-active --quiet certpilot.socket || {
    printf '%s\n' "${RED}socket 启动失败，最近日志：${NC}"
    journalctl -u certpilot.socket -n 20 --no-pager || true
    exit 1
  }
fi

# ---------------- 健康检查 ----------------
SCHEME="http"
CURL_EXTRA=""
if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
  SCHEME="https"
  CURL_EXTRA="-k"
fi

if [ "$NO_START" != "1" ] && command -v curl >/dev/null 2>&1; then
  for i in $(seq 1 10); do
    if curl -fsS $CURL_EXTRA "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 \
       || curl -fsS $CURL_EXTRA "$SCHEME://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
      ok "健康检查通过"
      break
    fi
    sleep 1
  done
fi

# ---------------- 自动设置密码 ----------------
if [ -n "$ADMIN_PASSWORD" ] && [ "$NO_START" != "1" ]; then
  step "初始化管理员"
  BODY=$(printf '{"password":"%s","email":"%s"}' "$ADMIN_PASSWORD" "$ACME_EMAIL")
  RESP=$(curl -s $CURL_EXTRA -X POST \
    -H "Content-Type: application/json" -H "X-Requested-With: certpilot" \
    -d "$BODY" "$SCHEME://127.0.0.1:$PORT/api/setup" 2>/dev/null || true)
  case "$RESP" in
    *'"ok":true'*) ok "管理员密码已设置" ;;
    *) warn "自动设置密码未成功（可能已初始化过），请打开网页手动设置：$RESP" ;;
  esac
fi

# ---------------- 完成 ----------------
# 优先公网 IP，取不到再退回本机第一个地址
IP=$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || true)
case "$IP" in
  *[!0-9.]*|"") IP=$(hostname -I 2>/dev/null | awk '{print $1}') ;;
esac
[ -n "$IP" ] || IP="<服务器IP>"

step "安装完成"
printf '%s\n' "  访问地址: ${BOLD}$SCHEME://$IP:$PORT${NC}"
printf '%s\n' "  数据目录: $DATA_DIR"
if [ "$MODE" = "ondemand" ]; then
  printf '%s\n' "  运行模式: 按需启动（空闲 ${IDLE_TIMEOUT} 后退出，待机零内存占用）"
  printf '%s\n' "  服务管理: systemctl {status|restart|stop} certpilot.socket"
  printf '%s\n' "  续期检查: systemctl list-timers certpilot-renew.timer"
else
  printf '%s\n' "  运行模式: 常驻"
  printf '%s\n' "  服务管理: systemctl {status|restart|stop} $SERVICE"
fi
printf '%s\n' "  查看日志: journalctl -u $SERVICE -f"
# 管道执行时 $0 是 bash，直接用它拼命令会得到无效的 "sudo bash --uninstall"
if [ -n "$SCRIPT_DIR" ]; then
  SELF="sudo $SCRIPT_DIR/install.sh"
else
  SELF="curl -fsSL https://github.com/$REPO/releases/latest/download/install.sh | sudo bash -s --"
fi
printf '%s\n' "  卸载    : $SELF --uninstall   ${DIM}(保留数据)${NC}"
printf '%s\n' "            $SELF --purge       ${DIM}(连数据一起删)${NC}"
NEED_SETUP=0
if [ "$NO_START" != "1" ] && command -v curl >/dev/null 2>&1; then
  SESS=$(curl -s $CURL_EXTRA "$SCHEME://127.0.0.1:$PORT/api/session" 2>/dev/null || true)
  case "$SESS" in *'"needSetup":true'*) NEED_SETUP=1 ;; esac
fi
if [ "$NEED_SETUP" = "1" ]; then
  printf '%s\n' "${DIM}  首次访问会让你设置管理员密码。${NC}"
else
  printf '%s\n' "${DIM}  数据目录已存在，用原有管理员密码登录。${NC}"
fi
printf '%s\n' "${DIM}  如果打不开，请检查防火墙/安全组是否放行 $PORT 端口。${NC}"

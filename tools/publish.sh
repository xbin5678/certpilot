#!/usr/bin/env bash
# 一键把本地仓库发布到 GitHub
#
#   GITHUB_TOKEN=ghp_xxx ./tools/publish.sh [仓库名] [private|public]
#
# 会做四件事：查用户名 → 建仓库（已存在则跳过）→ 推送 main → 打 v1.0.0 标签推送（触发 CI）
set -euo pipefail

TOKEN="${GITHUB_TOKEN:?请先设置 GITHUB_TOKEN 环境变量}"
NAME="${1:-certpilot}"
VIS="${2:-private}"
DESC="多域名多 CA 证书管理、自动续期，兼容 3x-ui"

API="https://api.github.com"
AUTH=(-H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")

echo "→ 校验令牌"
USER=$(curl -fsSL "${AUTH[@]}" "$API/user" | sed -n 's/.*"login": *"\([^"]*\)".*/\1/p' | head -1)
[ -n "$USER" ] || { echo "✘ 令牌无效或权限不足" >&2; exit 1; }
echo "  账号: $USER"

echo "→ 检查仓库 $USER/$NAME"
if curl -fsSL "${AUTH[@]}" "$API/repos/$USER/$NAME" >/dev/null 2>&1; then
  echo "  已存在，直接推送"
else
  PRIVATE=false
  [ "$VIS" = "private" ] && PRIVATE=true
  curl -fsSL -X POST "${AUTH[@]}" "$API/user/repos" \
    -d "{\"name\":\"$NAME\",\"private\":$PRIVATE,\"description\":\"$DESC\",\"has_issues\":true,\"has_wiki\":false,\"auto_init\":false}" >/dev/null
  echo "  已创建 https://github.com/$USER/$NAME"
fi

echo "→ 推送代码"
BRANCH=$(git rev-parse --abbrev-ref HEAD)
[ "$BRANCH" = "main" ] || git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin "https://x-access-token:$TOKEN@github.com/$USER/$NAME.git"
git push -u origin main
git remote set-url origin "https://github.com/$USER/$NAME.git"

echo "→ 打标签触发自动构建"
git tag -f v1.0.0
git push -f origin v1.0.0

echo
echo "✔ 完成"
echo "  仓库: https://github.com/$USER/$NAME"
echo "  动作: https://github.com/$USER/$NAME/actions"
echo "  安装: curl -fsSL https://github.com/$USER/$NAME/releases/latest/download/install.sh | sudo bash"

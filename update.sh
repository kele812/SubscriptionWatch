#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ $EUID -eq 0 ]] || { echo '请使用 root 执行。'; exit 1; }
cd "$ROOT"
[[ -z "$(git status --porcelain)" ]] || { echo '项目存在本地修改，请先备份并处理修改，再更新。'; exit 1; }
[[ "$(git branch --show-current)" == main ]] || { echo '请在 main 分支执行更新。'; exit 1; }
echo '下载 GitHub 最新版本；不会覆盖本地修改。'
git remote set-url origin https://github.com/kele812/SubscriptionWatch.git
git pull --ff-only origin main
exec bash "$ROOT/deploy.sh"

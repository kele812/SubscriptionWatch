#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ $EUID -eq 0 ]] || { echo '请使用 root 执行。'; exit 1; }
command -v docker >/dev/null || { echo '请先安装 Docker。'; exit 1; }
command -v flock >/dev/null || { echo '请先安装 util-linux。'; exit 1; }
exec 9>/var/lock/subscriptionwatch-deploy.lock
flock -n 9 || { echo '另一个部署或更新正在运行。'; exit 1; }
docker info >/dev/null
docker compose version >/dev/null
cd "$ROOT/SubscriptionWatch"
COMPOSE=(docker compose -p subscriptionwatch-v2 -f "$ROOT/SubscriptionWatch/compose.yaml")
"${COMPOSE[@]}" config --quiet
echo '构建镜像，现有服务在构建期间继续运行……'
"${COMPOSE[@]}" build --pull watch
CID="$("${COMPOSE[@]}" ps -a -q watch)"
STOPPED=0
BACKUP=''
on_error() {
  echo "操作失败。数据卷未删除。备份目录：${BACKUP:-尚未创建}"
  if [[ $STOPPED == 1 ]]; then docker start "$CID" || true; fi
}
trap on_error ERR
if [[ -n "$CID" ]]; then
  BACKUP="$(mktemp -d /opt/SubscriptionWatch-backup-$(date +%Y%m%d-%H%M%S)-XXXXXX)"
  docker inspect "$CID" > "$BACKUP/container.json"
  echo "暂停服务并完整备份 /data 到 $BACKUP ……"
  docker stop "$CID" >/dev/null
  STOPPED=1
  docker cp -a "$CID:/data" "$BACKUP/data"
  [[ -d "$BACKUP/data" ]] || { echo '备份失败'; false; }
  # Resume the old container if replacement fails before it is removed.
fi
echo '启动服务……'
"${COMPOSE[@]}" up -d --no-build watch
STOPPED=0
CID="$("${COMPOSE[@]}" ps -a -q watch)"
for ((attempt=0; attempt<60; attempt++)); do
  STATE="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CID")"
  if [[ "$STATE" == healthy ]]; then
    echo '部署完成。宝塔反向代理目标：http://127.0.0.1:18080，请通过 HTTPS 域名访问。'
    [[ -z "$BACKUP" ]] || echo "更新前完整备份：$BACKUP（包含密钥，请妥善保存）"
    exit 0
  fi
  sleep 2
done
echo '服务未通过健康检查，请查看以下日志。不要删除数据卷，也不要直接降级数据库。'
"${COMPOSE[@]}" logs --tail=80 watch
false

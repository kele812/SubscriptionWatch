# Ubuntu 一键部署和更新

使用 root，预先安装 Git、Docker 和 Docker Compose 插件。仓库已公开，任何人都可以通过 HTTPS 下载，不需要 GitHub 账号、Token 或 SSH 密钥。

首次部署（目录必须尚不存在）：

```bash
git clone https://github.com/kele812/SubscriptionWatch.git /opt/SubscriptionWatch-repo && bash /opt/SubscriptionWatch-repo/deploy.sh
```

以后更新：

```bash
bash /opt/SubscriptionWatch-repo/update.sh
```

如果以前通过 SSH 下载且尚未获得新版更新脚本，先切换下载地址并更新：

```bash
git -C /opt/SubscriptionWatch-repo remote set-url origin https://github.com/kele812/SubscriptionWatch.git && bash /opt/SubscriptionWatch-repo/update.sh
```

已通过旧压缩包部署的机器也可以执行首次部署命令迁移到 GitHub 更新方式。脚本使用原有 Compose 项目 subscriptionwatch-v2 和数据卷 subscriptionwatch-v2_watch-data；必须在原机器、同一个 Docker daemon 上运行。不同项目名或自定义卷需要先人工迁移。首次下载失败时不要删除旧安装目录或数据卷。

脚本先构建镜像，再暂停原容器备份 /data，随后重建并检查健康状态。备份目录为 /opt/SubscriptionWatch-backup-时间-随机字符，权限仅 root 可读，包含数据库和密钥。备份不会自动删除，请注意磁盘空间。失败不会自动恢复旧数据库；保留备份并排查日志，避免降级损坏数据。

宝塔配置 HTTPS 网站并反向代理到 http://127.0.0.1:18080。脚本不修改宝塔配置。首次访问创建账号密码，旧安装继续使用原账号。Xboard 采集插件需在 Xboard 机器上单独更新，此命令只部署风控面板。
